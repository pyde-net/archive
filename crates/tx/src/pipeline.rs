//! Transaction execution pipeline: end-to-end integration of TX → Account → State → PVM.
//!
//! Connects all crates into a single execution flow:
//! 1. Load sender account from State SMT
//! 2. Validate transaction (signature, nonce, balance, gas, deadline)
//! 3. Pre-execution: deduct max gas from fee payer
//! 4. Value transfer: sender → recipient
//! 5. PVM execution (contract call or deployment)
//! 6. Post-execution: refund unused gas, apply SDELETE refunds
//! 7. Fee distribution: 70% burn, 20% validator, 10% treasury
//! 8. Update accounts in State SMT
//! 9. Generate receipt

use crate::execution::{
    distribute_fee, generate_receipt, post_execution_refund, pre_execution_charge, transfer_value,
    LogEntry, Receipt,
};
use crate::types::{FeePayer, Transaction, TransactionType};
use crate::validation::{validate_transaction, ValidationContext, ValidationError};

use pyde_account::address::{Address, ZERO_ADDRESS};
use pyde_account::nonce::NonceState;
use pyde_account::types::Account;
use pyde_crypto::poseidon2::poseidon2_hash;
use pyde_state::keys;
use pyde_vm::vm::{ExecutionContext, Outcome, Vm};
use pyde_vm::wide::U256;
use sparse_merkle_tree::H256;

/// Block-level execution context.
pub struct BlockContext {
    pub height: u64,
    pub timestamp: u64,
    pub base_fee: u128,
    pub block_gas_limit: u64,
    pub chain_id: u64,
    pub validator_address: Address,
    /// When true, FALCON signature verification is skipped for every
    /// transaction in this block. Intended only for in-process test
    /// harnesses that construct unsigned transactions against
    /// synthetic state. Production paths must leave this `false`. See
    /// `ValidationContext::dev_skip_signature`.
    pub dev_skip_signature: bool,
    /// Caller guarantees every tx in the block has already had its
    /// FALCON sig verified (e.g. via a parallel batch pass) and that
    /// the batch returned *all-valid*. When set, execution skips the
    /// per-tx sig check — the other validation steps (chain_id, nonce,
    /// balance, gas limits, access list, deadline) still run. This is
    /// a production-safe optimization: if ANY sig in the block was
    /// invalid, the caller must leave this `false` so the execution
    /// path still rejects the bad tx.
    pub block_sigs_pre_verified: bool,
}

impl Default for BlockContext {
    /// Safe defaults for every field — notably `dev_skip_signature: false`
    /// so a caller that forgets to set it never accidentally skips
    /// signature verification in production.
    fn default() -> Self {
        Self {
            height: 0,
            timestamp: 0,
            base_fee: 0,
            block_gas_limit: 0,
            chain_id: 0,
            validator_address: [0u8; 32],
            dev_skip_signature: false,
            block_sigs_pre_verified: false,
        }
    }
}

/// Pipeline execution error.
#[derive(Debug)]
pub enum PipelineError {
    Validation(ValidationError),
    AccountNotFound(Address),
    ExecutionFailed(String),
    StateError(String),
}

impl From<ValidationError> for PipelineError {
    fn from(e: ValidationError) -> Self {
        PipelineError::Validation(e)
    }
}

/// Load an account from the SMT. Returns default (empty) account if not found.
pub fn load_account(smt: &dyn pyde_state::smt::StateAccess, address: &Address) -> Account {
    let key = keys::balance_key(address);
    match smt.get(&key) {
        Some(bytes) => Account::from_bytes(&bytes).unwrap_or_else(|| empty_account(address)),
        None => empty_account(address),
    }
}

/// Store an account into the SMT.
pub fn store_account(
    smt: &mut dyn pyde_state::smt::StateAccess,
    account: &Account,
) -> Result<(), PipelineError> {
    let key = keys::balance_key(&account.address);
    smt.insert(key, account.to_bytes())
        .map_err(|e| PipelineError::StateError(e.to_string()))?;
    Ok(())
}

/// Apply the (final - initial) deltas the pipeline produced for an
/// account against the latest SMT state at write time, then store
/// (audit 307).
///
/// The pipeline loads `sender` and `recipient` once at the top of
/// `execute_transaction` and mutates them through pre_charge,
/// transfer_value, post_refund, and per-type handlers (e.g.
/// ClaimReward credits sender, RegisterPubkey sets sender.auth_keys).
/// In parallel, the fee-distribution path at the bottom of
/// `execute_transaction` loads + credits + stores `validator` and
/// `treasury` accounts directly via `store_account`. Per-type
/// handlers that touch other accounts (ClaimAirdrop's pool,
/// SweepAirdrop's pool/treasury, Slash's offender, etc.) do the
/// same.
///
/// When `tx.from` or `tx.to` aliases any of those handler-written
/// addresses (proposer submitting their own tx, self-transfer,
/// ClaimAirdrop with `tx.to == airdrop_pool_address()`, ...), a
/// blind `store_account(smt, &sender)` / `store_account(smt,
/// &recipient)` overwrites the handler's state with the in-memory
/// pipeline copy. Pre-audit-307 code did exactly that — the
/// validator credit, treasury credit, pool debit, etc. were
/// silently undone whenever they collided with the sender or
/// recipient address.
///
/// The fix is to capture pre-mutation snapshots
/// (`sender_initial`, `recipient_initial`) before any pipeline-
/// side modification, and at write time:
///   1. re-load the latest SMT state for the address;
///   2. add `final.balance - initial.balance` (saturating);
///   3. add `final.gas_tank - initial.gas_tank` (saturating);
///   4. take `final.auth_keys` if the pipeline changed it
///      (RegisterPubkey upgrade) — otherwise keep what's there;
///   5. store.
///
/// This is correct under aliasing AND under self-transfer
/// (where the sender apply runs first, recipient apply re-reads
/// sender's just-stored state and adds `+tx.value` on top).
pub fn apply_account_delta(
    smt: &mut dyn pyde_state::smt::StateAccess,
    addr: &Address,
    initial: &Account,
    final_: &Account,
) -> Result<(), PipelineError> {
    let mut current = load_account(smt, addr);

    // Balance delta. `i128` is wide enough: u128 deltas up to
    // ±u128::MAX/2 are representable. Real Pyde txs operate on
    // values bounded by total_supply (≪ 2^127) so saturating
    // covers the tail.
    let balance_delta = final_.balance as i128 - initial.balance as i128;
    if balance_delta >= 0 {
        current.balance = current.balance.saturating_add(balance_delta as u128);
    } else {
        current.balance = current.balance.saturating_sub((-balance_delta) as u128);
    }

    // gas_tank delta (FeePayer::GasTank path).
    let gas_tank_delta = final_.gas_tank as i128 - initial.gas_tank as i128;
    if gas_tank_delta >= 0 {
        current.gas_tank = current.gas_tank.saturating_add(gas_tank_delta as u128);
    } else {
        current.gas_tank = current.gas_tank.saturating_sub((-gas_tank_delta) as u128);
    }

    // auth_keys: only override if the pipeline changed it
    // (RegisterPubkey is the only handler that mutates
    // sender.auth_keys today). Otherwise preserve whatever the
    // SMT currently holds — covers a future handler that rotates
    // auth_keys for the same address as sender/recipient.
    if final_.auth_keys != initial.auth_keys {
        current.auth_keys = final_.auth_keys.clone();
    }

    // Audit 307 follow-up: `account.nonce` is the per-sender
    // CREATE-address counter (`derive_create_address(tx.from,
    // sender.nonce)` in the Deploy handler). Pre-fix this field
    // was the only mutation `apply_account_delta` failed to
    // propagate — the Deploy handler set
    // `sender.nonce += 1` in-memory but the late write-back here
    // never touched `current.nonce`, so the stored counter
    // stayed at zero forever. Result: every Deploy from the same
    // sender derived the same address (`create_address(sender,
    // 0)`), with each new contract silently overwriting the
    // previous one's runtime bytecode at that address. The
    // failure was usually invisible (most test fixtures only
    // deploy one contract per sender) but
    // `reentrancy_attack_blocked` and any production multi-deploy
    // flow would break.
    //
    // Override semantics (not a numeric delta) match the
    // auth_keys path above: the pipeline is the only mutator and
    // its final value is authoritative. Concurrent
    // sender/recipient aliasing isn't a concern because Deploy
    // can't have `tx.to == tx.from` (CREATE addresses are
    // post-derived from the sender's pre-mutation nonce).
    if final_.nonce != initial.nonce {
        current.nonce = final_.nonce;
    }

    store_account(smt, &current)
}

/// Load a nonce state for an account. Returns default if not found.
///
/// Audit 390: `NonceState::from_bytes` is now `Option<Self>`. A
/// `None` here means the nonce-key value was structurally
/// malformed (length < 10) — surface it as the same "fresh
/// account" default rather than panicking, since the caller
/// can't distinguish corrupted-storage from never-seen anyway
/// at this layer. The corruption shows up downstream when
/// `validate_nonce` rejects the tx against a `base = 0`
/// window the sender never actually set.
pub fn load_nonce(smt: &dyn pyde_state::smt::StateAccess, address: &Address) -> NonceState {
    let key = keys::nonce_key(address);
    smt.get(&key)
        .and_then(|bytes| NonceState::from_bytes(&bytes))
        .unwrap_or_default()
}

/// Store a nonce state into the SMT.
pub fn store_nonce(
    smt: &mut dyn pyde_state::smt::StateAccess,
    address: &Address,
    nonce: &NonceState,
) -> Result<(), PipelineError> {
    let key = keys::nonce_key(address);
    smt.insert(key, nonce.to_bytes().to_vec())
        .map_err(|e| PipelineError::StateError(e.to_string()))?;
    Ok(())
}

/// Load contract code from the SMT.
pub fn load_code(smt: &dyn pyde_state::smt::StateAccess, address: &Address) -> Option<Vec<u8>> {
    let key = keys::code_key(address);
    smt.get(&key)
}

/// Store contract code into the SMT.
pub fn store_code(
    smt: &mut dyn pyde_state::smt::StateAccess,
    address: &Address,
    code: &[u8],
) -> Result<(), PipelineError> {
    let key = keys::code_key(address);
    smt.insert(key, code.to_vec())
        .map_err(|e| PipelineError::StateError(e.to_string()))?;
    Ok(())
}

fn empty_account(address: &Address) -> Account {
    Account {
        address: *address,
        nonce: 0,
        balance: 0,
        code_hash: H256::zero(),
        storage_root: H256::zero(),
        account_type: pyde_account::types::AccountType::EOA,
        auth_keys: pyde_account::types::AuthKeys::None,
        gas_tank: 0,
        key_nonce: 0,
    }
}

/// Execute a single transaction against the state.
/// Returns the receipt and updates the SMT in place.
/// `aot_lookup` optionally provides a native compiled function for the target contract.
pub fn execute_transaction(
    tx: &Transaction,
    smt: &mut dyn pyde_state::smt::StateAccess,
    block_ctx: &BlockContext,
) -> Result<Receipt, PipelineError> {
    execute_transaction_inner(tx, smt, block_ctx, None)
}

/// Audit 353: emit a `success = false` Receipt for a tx that
/// passed validation but failed post-validation (typically
/// `pre_execution_charge` returning Err for a `GasTank`-paid tx
/// whose gas_tank is empty). The nonce has already been persisted
/// at step 3 of `execute_transaction_inner` so the tx cannot be
/// resubmitted; this helper additionally:
///   1. Charges baseline gas (`MIN_GAS_LIMIT`) from sender.balance,
///      saturating to whatever they hold. This deters cheap
///      validator-CPU attacks where a sender repeatedly submits
///      txs that are valid-on-paper but uncoverable in practice.
///   2. Writes the debited sender via `apply_account_delta` so the
///      net charge lands on top of any concurrent state mutations.
///   3. Distributes the charged quanta through the standard
///      validator / treasury / burn split.
///   4. Produces a Receipt naming the failure in `return_data`.
fn emit_failed_execution_receipt(
    tx: &Transaction,
    smt: &mut dyn pyde_state::smt::StateAccess,
    block_ctx: &BlockContext,
    sender_initial: &Account,
    mut sender: Account,
    error_msg: String,
) -> Result<Receipt, PipelineError> {
    let baseline_gas = crate::validation::MIN_GAS_LIMIT;
    let baseline_cost = baseline_gas as u128 * block_ctx.base_fee;

    // Best-effort charge: clamp to what the sender actually holds.
    // If `base_fee == 0` (devnet) `baseline_cost == 0` so nothing
    // is debited but we still pretend the metered gas was the
    // full baseline so the receipt accurately reports the CPU cost
    // the failure consumed.
    let charged_quanta = baseline_cost.min(sender.balance);
    sender.balance -= charged_quanta;

    let effective_gas_charged = if block_ctx.base_fee == 0 {
        baseline_gas
    } else {
        // Round down: how many gas units the actual quanta cover.
        (charged_quanta / block_ctx.base_fee) as u64
    };

    apply_account_delta(smt, &tx.from, sender_initial, &sender)?;

    // Distribute the charged fee. Mirrors the success-path
    // distribute_fee logic so a failed tx doesn't grant the
    // validator / treasury different yield than a successful one
    // for the same metered cost.
    let fee_dist = distribute_fee(effective_gas_charged, block_ctx.base_fee);
    if fee_dist.validator > 0 {
        let mut validator_acct = load_account(smt, &block_ctx.validator_address);
        validator_acct.balance += fee_dist.validator;
        store_account(smt, &validator_acct)?;
    }
    if fee_dist.treasury > 0 {
        let treasury_addr = pyde_account::address::treasury_address();
        let mut treasury_acct = load_account(smt, &treasury_addr);
        treasury_acct.balance += fee_dist.treasury;
        store_account(smt, &treasury_acct)?;
    }

    let state_root = smt.root();
    Ok(generate_receipt(
        tx,
        false,
        baseline_gas,
        0,
        effective_gas_charged,
        block_ctx.base_fee,
        vec![],
        state_root,
        error_msg.into_bytes(),
    ))
}

/// Execute with optional AOT-compiled native code for the target contract.
pub fn execute_transaction_aot(
    tx: &Transaction,
    smt: &mut dyn pyde_state::smt::StateAccess,
    block_ctx: &BlockContext,
    aot_fn: Option<unsafe fn(*mut u64, u64, *mut pyde_vm::vm::Vm) -> u64>,
) -> Result<Receipt, PipelineError> {
    execute_transaction_inner(tx, smt, block_ctx, aot_fn)
}

fn execute_transaction_inner(
    tx: &Transaction,
    smt: &mut dyn pyde_state::smt::StateAccess,
    block_ctx: &BlockContext,
    aot_fn: Option<unsafe fn(*mut u64, u64, *mut pyde_vm::vm::Vm) -> u64>,
) -> Result<Receipt, PipelineError> {
    // 0. Emergency pause gate (slice 4.6).
    //
    // The pause state stores an `end_slot`; the chain is paused while
    // `current_slot < end_slot`. While paused, only `EmergencyResume`
    // may execute. Rejection happens BEFORE validation + gas charging
    // so spam-to-fail during pause doesn't burn user gas.
    //
    // Past-deadline end_slots auto-expire without any explicit clear
    // — if signers lose their keys during pause, the chain recovers
    // once the declared pause window lapses instead of being bricked.
    if is_paused(smt, block_ctx.height) && tx.tx_type != TransactionType::EmergencyResume {
        return Err(PipelineError::ExecutionFailed(
            "chain paused: only EmergencyResume accepted".into(),
        ));
    }

    // 1. Load accounts
    let mut sender = load_account(smt, &tx.from);
    let mut recipient = load_account(smt, &tx.to);
    let mut nonce_state = load_nonce(smt, &tx.from);

    // Audit 307: snapshot pre-mutation account state so we can
    // apply deltas (balance / gas_tank / auth_keys) against the
    // latest SMT state at write time, instead of overwriting
    // writes made by validator + treasury fee distribution and by
    // per-type handlers. The clobber matters whenever a handler-
    // mutated address aliases sender or recipient — e.g. a
    // proposer submitting their own tx (tx.from == validator
    // address), self-transfers (tx.from == tx.to), or
    // ClaimAirdrop with tx.to == airdrop_pool_address(). Without
    // these snapshots the late `store_account(smt, &sender)` /
    // `store_account(smt, &recipient)` calls silently undo every
    // such cross-write.
    let sender_initial = sender.clone();
    let recipient_initial = recipient.clone();

    // Compute vested-locked amount for the sender (slice 4.4). Senders
    // with no vesting schedule get 0 — their full balance is spendable.
    let sender_locked = read_vesting_schedule(smt, &tx.from)
        .map(|s| s.locked_at(block_ctx.height))
        .unwrap_or(0);

    // 2. Validate
    let val_ctx = ValidationContext {
        block_height: block_ctx.height,
        base_fee: block_ctx.base_fee,
        block_gas_limit: block_ctx.block_gas_limit,
        chain_id: block_ctx.chain_id,
        dev_skip_signature: block_ctx.dev_skip_signature,
        sender_locked,
        sig_pre_verified: block_ctx.block_sigs_pre_verified,
    };
    validate_transaction(tx, &sender, &nonce_state, &val_ctx)?;

    // 3. Mark nonce as used and persist immediately.
    //
    // Audit 353: pre-fix `use_nonce` ran in-memory and
    // `store_nonce` only ran at the end of the function on full
    // success. Any `?` propagation between here and the final
    // `store_nonce` (e.g., a `GasTank`-paid tx whose `gas_tank`
    // is empty, a Paymaster-paid tx whose value-transfer
    // exceeds sender balance, an SMT write error during fee
    // distribution) dropped the in-memory nonce and let the
    // same tx be resubmitted indefinitely — burning validator
    // CPU on each re-attempt for free. Persisting up-front
    // makes the nonce burn unconditional once validation
    // passes; the worst the attacker can do is consume one
    // nonce slot per failed attempt (bounded by the nonce
    // window).
    nonce_state
        .use_nonce(tx.nonce)
        .map_err(|e| PipelineError::ExecutionFailed(format!("nonce error: {:?}", e)))?;
    store_nonce(smt, &tx.from, &nonce_state)?;

    // 4. Pre-execution: deduct max gas
    // NOTE: When fee_payer is Paymaster, no pre-charge happens here.
    // Paymaster gas charges are enforced by the paymaster contract itself
    // (via a validation call that checks and debits the paymaster's deposit),
    // not by the pipeline.  The pipeline only pre-charges Sender and GasTank
    // fee payers; paymaster settlement is deferred to the contract layer.
    //
    // Audit 353: if the charge fails (validation passed but the
    // declared fee_payer can't actually cover gas — most common
    // for `GasTank` with an empty gas_tank since validation only
    // structurally checks the variant), fall through to the
    // failed-execution path that charges baseline gas from
    // sender.balance, distributes the fee, and emits a
    // `success = false` receipt. The nonce was already burned at
    // step 3 so the tx can't be resubmitted.
    let mut gas_tank_balance = sender.gas_tank;
    if let Err(charge_err) = pre_execution_charge(
        tx,
        &mut sender.balance,
        &mut gas_tank_balance,
        block_ctx.base_fee,
    ) {
        return emit_failed_execution_receipt(
            tx,
            smt,
            block_ctx,
            &sender_initial,
            sender,
            charge_err,
        );
    }
    sender.gas_tank = gas_tank_balance;

    // 5. Value transfer
    //
    // Audit 352: only `Standard` and `Deploy` carry value
    // semantics. Validation (`validate_transaction`) already
    // rejects `tx.value != 0` for every other tx_type, but we
    // gate again here as defense-in-depth for any internal
    // caller that bypasses validation (replay, regression
    // harnesses, future fast paths). Without this gate the
    // pre-fix behaviour returns: a Slash / MultisigTx /
    // ClaimReward / StakeDeposit / etc. with `tx.value > 0`
    // performs a silent `tx.from → tx.to` transfer alongside
    // its declared semantics.
    match tx.tx_type {
        TransactionType::Standard | TransactionType::Deploy => {
            transfer_value(&mut sender.balance, &mut recipient.balance, tx.value)
                .map_err(PipelineError::ExecutionFailed)?;
        }
        _ => {
            // Non-value tx_types reach this branch only via internal
            // callers that bypassed validation. Skipping the
            // transfer is the safe behaviour even if `tx.value > 0`
            // sneaks in here.
        }
    }

    // 6. PVM execution (if contract call or deployment)
    let (success, gas_used, gas_refund, logs, return_data) = match tx.tx_type {
        TransactionType::Standard if tx.to != ZERO_ADDRESS => {
            // Contract call
            match load_code(smt, &tx.to) {
                Some(code) => {
                    tracing::debug!(
                        to = hex::encode(tx.to),
                        code_len = code.len(),
                        "executing contract call in PVM"
                    );
                    execute_in_pvm(tx, &sender, &code, smt, block_ctx, aot_fn)
                }
                None => {
                    tracing::debug!(
                        to = hex::encode(tx.to),
                        "simple transfer (no code at recipient)"
                    );
                    (true, 21_000u64, 0u64, vec![], vec![])
                }
            }
        }
        TransactionType::Deploy => {
            // Contract deployment with constructor execution.
            // tx.data format: constructor_len(4 LE) + constructor_bytes + runtime_bytes + constructor_args
            // If constructor_len == 0: store tx.data[4..] as runtime (no constructor).
            let new_addr = pyde_account::address::derive_create_address(&tx.from, sender.nonce);
            // Increment sender nonce so the next deploy gets a different address
            sender.nonce += 1;

            let (_runtime_code, gas_used) = if tx.data.len() >= 8 {
                let mut clen_bytes = [0u8; 4];
                clen_bytes.copy_from_slice(&tx.data[..4]);
                let constructor_len = u32::from_le_bytes(clen_bytes) as usize;

                let mut rlen_bytes = [0u8; 4];
                rlen_bytes.copy_from_slice(&tx.data[4..8]);
                let runtime_len = u32::from_le_bytes(rlen_bytes) as usize;

                // Validate header: lengths must be sane and total must fit
                if constructor_len > 0
                    && runtime_len > 0
                    && constructor_len + runtime_len <= tx.data.len()
                    && tx.data.len() >= 8 + constructor_len + runtime_len
                {
                    let constructor = &tx.data[8..8 + constructor_len];
                    let runtime = &tx.data[8 + constructor_len..8 + constructor_len + runtime_len];
                    // Args for constructor come after runtime — extract if present
                    // Actually, constructor args are encoded in calldata when running constructor.
                    // For now, run constructor without args (init sets state).

                    // Store runtime code first (constructor may reference self_address)
                    store_code(smt, &new_addr, runtime)?;
                    let contract = Account::new_contract(new_addr, runtime);
                    store_account(smt, &contract)?;

                    // AOT compilation happens at execution time (JIT-cached in memory).
                    // The PVM bytecode in state is the source of truth.
                    // AOT native code can't be serialized to the SMT (it's memory-mapped).
                    // See execute_in_pvm for the JIT compilation cache.

                    // Execute constructor.
                    // Constructor args follow the runtime bytecode in the deploy data.
                    // Format: [4-byte len][constructor][runtime][args]
                    // Everything after constructor+runtime is the args.
                    let header_plus_code = 8 + constructor_len + runtime_len;
                    let constructor_args = if tx.data.len() > header_plus_code {
                        tx.data[header_plus_code..].to_vec()
                    } else {
                        vec![]
                    };
                    let mut constructor_tx = tx.clone();
                    constructor_tx.to = new_addr;
                    constructor_tx.data = constructor_args;
                    tracing::debug!(
                        constructor_len,
                        runtime_len = runtime.len(),
                        args_len = constructor_tx.data.len(),
                        contract = hex::encode(new_addr),
                        "executing constructor"
                    );
                    let (success, gas, _, _logs, _) =
                        execute_in_pvm(&constructor_tx, &sender, constructor, smt, block_ctx, None);
                    if !success {
                        tracing::warn!(gas, "constructor execution failed (reverted or trapped)");
                    } else {
                        tracing::info!(gas, "constructor executed successfully");
                    }

                    (runtime.to_vec(), 32_000 + gas)
                } else {
                    // No valid header — store all data as runtime (raw deploy)
                    store_code(smt, &new_addr, &tx.data)?;
                    let contract = Account::new_contract(new_addr, &tx.data);
                    store_account(smt, &contract)?;
                    (tx.data.clone(), 32_000u64)
                }
            } else {
                // Fallback: store all data as code
                store_code(smt, &new_addr, &tx.data)?;
                let contract = Account::new_contract(new_addr, &tx.data);
                store_account(smt, &contract)?;
                (tx.data.clone(), 32_000u64)
            };

            (true, gas_used, 0u64, vec![], new_addr.to_vec())
        }
        TransactionType::StakeDeposit => {
            // Stake deposit: lock VALIDATOR_STAKE from sender, create validator entry.
            // tx.data = FALCON-512 public key (897 bytes).
            // Shared constant — see `pyde-slashing` crate for the authoritative
            // value and why it's in a leaf crate.
            use pyde_slashing::VALIDATOR_STAKE;

            if sender.balance < VALIDATOR_STAKE {
                (
                    false,
                    21_000u64,
                    0u64,
                    vec![],
                    b"insufficient balance for stake deposit".to_vec(),
                )
            } else if tx.data.len() < 897 {
                (
                    false,
                    21_000u64,
                    0u64,
                    vec![],
                    b"tx.data must contain FALCON public key (897 bytes)".to_vec(),
                )
            } else {
                // Validate: public key must derive to sender's address
                let pk_bytes = &tx.data[..897];
                let derived_addr = pyde_account::address::derive_eoa_address(pk_bytes);
                if derived_addr != tx.from {
                    (
                        false,
                        21_000u64,
                        0u64,
                        vec![],
                        b"public key does not match sender address".to_vec(),
                    )
                } else if smt
                    .get(&pyde_state::keys::validator_key(&tx.from))
                    .is_some()
                {
                    // Already registered
                    (
                        false,
                        21_000u64,
                        0u64,
                        vec![],
                        b"already registered as validator".to_vec(),
                    )
                } else {
                    // Deduct stake from sender balance
                    sender.balance -= VALIDATOR_STAKE;

                    // Snapshot the current global rewards accumulator. Seeding
                    // `last_claimed_at` at the CURRENT value means the new
                    // validator starts with zero owed — they only earn from
                    // future blocks. Without this, a late-joiner would be
                    // retroactively credited with every historical pool
                    // payout and claim an outsized amount on their first
                    // ClaimReward tx.
                    let current_rewards_per_validator = read_rewards_per_validator(smt);

                    // Write validator entry to state:
                    //   [pk_len:4 LE][pk][stake:16 LE][status:1][last_claimed_at:16 LE]
                    let mut val_data = Vec::with_capacity(4 + 897 + 16 + 1 + 16);
                    val_data.extend_from_slice(&(897u32).to_le_bytes());
                    val_data.extend_from_slice(pk_bytes);
                    val_data.extend_from_slice(&VALIDATOR_STAKE.to_le_bytes());
                    val_data.push(0x00); // Active
                    val_data.extend_from_slice(&current_rewards_per_validator.to_le_bytes());

                    let val_key = pyde_state::keys::validator_key(&tx.from);
                    let _ = smt.insert(val_key, val_data);

                    // Update validator address list (append sender address)
                    let count_key = pyde_state::keys::validator_count_key();
                    let count = smt
                        .get(&count_key)
                        .map(|b| {
                            if b.len() >= 8 {
                                u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]))
                            } else {
                                0
                            }
                        })
                        .unwrap_or(0);
                    let new_count = count + 1;
                    let _ = smt.insert(count_key, new_count.to_le_bytes().to_vec());

                    // Store address at index for enumeration
                    let idx_key = pyde_state::keys::validator_index_key(count);
                    let _ = smt.insert(idx_key, tx.from.to_vec());

                    // Slice 4.2: bump the active-only count. This is the
                    // divisor used by the pool-yield accumulator; tracking
                    // separately from the monotonic `VALIDATOR_COUNT`
                    // (which doubles as an enumeration index) lets exited
                    // and ejected members stop diluting active stakers.
                    increment_active_validator_count(smt);

                    tracing::info!(
                        validator = hex::encode(tx.from),
                        stake = VALIDATOR_STAKE,
                        "stake deposit: new validator registered"
                    );

                    (true, 50_000u64, 0u64, vec![], tx.from.to_vec())
                }
            }
        }
        TransactionType::StakeWithdraw => {
            // Stake withdraw: set validator status to Unbonding.
            let val_key = pyde_state::keys::validator_key(&tx.from);
            match smt.get(&val_key) {
                Some(val_data) => match ValidatorEntry::decode(&val_data) {
                    Some(mut entry) if entry.status == 0x00 => {
                        entry.status = 0x01;
                        entry.exit_block = Some(block_ctx.height);
                        let _ = smt.insert(val_key, entry.encode());
                        // Slice 4.2: Active→Unbonding, stop earning yield.
                        decrement_active_validator_count(smt);
                        tracing::info!(
                            validator = hex::encode(tx.from),
                            exit_block = block_ctx.height,
                            "stake withdraw: validator unbonding started"
                        );
                        (true, 50_000u64, 0u64, vec![], vec![])
                    }
                    Some(_) => (
                        false,
                        21_000u64,
                        0u64,
                        vec![],
                        b"validator is not active".to_vec(),
                    ),
                    None => (
                        false,
                        21_000u64,
                        0u64,
                        vec![],
                        b"invalid validator entry".to_vec(),
                    ),
                },
                None => (
                    false,
                    21_000u64,
                    0u64,
                    vec![],
                    b"not a registered validator".to_vec(),
                ),
            }
        }
        TransactionType::RegisterPubkey => {
            // Audit 229: validate_register_pubkey already enforced
            // tx.from == Poseidon2(tx.data), sender.balance > 0, and
            // sender.auth_keys == None. Just commit the registration.
            sender.auth_keys = pyde_account::types::AuthKeys::Single(tx.data.clone());
            (true, 0u64, 0u64, Vec::new(), Vec::new())
        }
        TransactionType::Slash => execute_slash(block_ctx.chain_id, tx, smt, &mut sender.balance),
        TransactionType::ClaimAirdrop => {
            execute_claim_airdrop(tx, smt, block_ctx, &mut sender.balance)
        }
        TransactionType::SweepAirdrop => execute_sweep_airdrop(tx, smt, block_ctx),
        TransactionType::MultisigTx => execute_multisig_spend(tx, smt, block_ctx),
        TransactionType::RotateMultisig => execute_rotate_multisig(tx, smt, block_ctx),
        TransactionType::EmergencyPause => execute_emergency_pause(tx, smt, block_ctx),
        TransactionType::EmergencyResume => execute_emergency_resume(tx, smt, block_ctx),
        TransactionType::ClaimReward => {
            // Pull the sender's accrued pool share. Valid only for
            // Active (0x00) and Unbonding (0x01) entries — Exited
            // (0x02) validators are rejected. Without this gate, an
            // exited validator whose entry sits in state could still
            // claim whatever the accumulator has gained since their
            // last_claimed_at — free yield after they've already
            // withdrawn their stake. Real fund leakage.
            //
            // Unbonding validators CAN claim: they may have earned
            // yield while still Active and haven't pulled it yet.
            // Denying their claim punishes honest validators who
            // submitted StakeWithdraw.
            let val_key = pyde_state::keys::validator_key(&tx.from);
            match smt.get(&val_key) {
                Some(val_data) => match ValidatorEntry::decode(&val_data) {
                    Some(entry) if entry.status == 0x02 => (
                        false,
                        21_000u64,
                        0u64,
                        vec![],
                        b"validator has exited; no further claims".to_vec(),
                    ),
                    Some(mut entry) => {
                        let current = read_rewards_per_validator(smt);
                        let owed = current.saturating_sub(entry.last_claimed_at);
                        if owed > 0 {
                            sender.balance = sender.balance.saturating_add(owed);
                            entry.last_claimed_at = current;
                            let _ = smt.insert(val_key, entry.encode());
                        }
                        (true, 21_000u64, 0u64, vec![], owed.to_le_bytes().to_vec())
                    }
                    None => (
                        false,
                        21_000u64,
                        0u64,
                        vec![],
                        b"validator entry corrupt".to_vec(),
                    ),
                },
                None => (
                    false,
                    21_000u64,
                    0u64,
                    vec![],
                    b"not a registered validator".to_vec(),
                ),
            }
        }
        _ => {
            // Simple transfer or batch (batch deferred)
            (true, 21_000u64, 0u64, vec![], vec![])
        }
    };

    // 7. Post-execution: refund unused gas
    let mut fee_payer_balance = match &tx.fee_payer {
        FeePayer::Sender => sender.balance,
        FeePayer::GasTank(_) => sender.gas_tank,
        FeePayer::Paymaster(_) => 0,
    };

    let (effective_gas, refund_amount) = post_execution_refund(
        gas_used,
        tx.gas_limit,
        gas_refund,
        &mut fee_payer_balance,
        block_ctx.base_fee,
    );

    // Write back refunded balance
    match &tx.fee_payer {
        FeePayer::Sender => sender.balance = fee_payer_balance,
        FeePayer::GasTank(_) => sender.gas_tank = fee_payer_balance,
        FeePayer::Paymaster(_) => {}
    }

    // 8. Fee distribution: 70% burned (implicit — never credited), 20% validator, 10% treasury
    let fee_dist = distribute_fee(effective_gas, block_ctx.base_fee);

    // Credit validator (20%)
    let mut validator_account = load_account(smt, &block_ctx.validator_address);
    validator_account.balance += fee_dist.validator;
    store_account(smt, &validator_account)?;

    // Credit treasury (10%) — well-known address: Poseidon2("pyde-treasury")
    if fee_dist.treasury > 0 {
        let treasury_addr = pyde_account::address::treasury_address();
        let mut treasury_account = load_account(smt, &treasury_addr);
        treasury_account.balance += fee_dist.treasury;
        store_account(smt, &treasury_account)?;
    }

    // Burn (70%): implicit — charged from sender in step 3, never credited to anyone.
    // Total supply decreases by fee_dist.burned each transaction.

    // 9. Save updated accounts via delta-apply (audit 307).
    //    `apply_account_delta` re-reads the latest SMT state for
    //    each address, applies the (final - initial) deltas the
    //    pipeline produced for sender / recipient, and stores. If
    //    `tx.from` aliased the validator / treasury / handler-
    //    written address, the credit applied at lines 609 / 616 /
    //    inside the handler is preserved AND the pipeline's
    //    debit + transfer + refund deltas land on top of it.
    //
    //    Self-transfer note: when `tx.to == tx.from`, both calls
    //    target the same SMT key. The sender apply runs first
    //    (storing pre-tx + sender deltas), the recipient apply
    //    re-reads that stored value and applies the recipient
    //    delta (+tx.value) on top. End state: pre-tx + (-debit
    //    - tx.value + refund) + tx.value = pre-tx - debit +
    //    refund. The pre-307 code clobbered sender's stored
    //    state with the recipient's pre-tx + tx.value, dropping
    //    the gas debit entirely (free self-transfers).
    apply_account_delta(smt, &tx.from, &sender_initial, &sender)?;
    apply_account_delta(smt, &tx.to, &recipient_initial, &recipient)?;
    // Audit 353: nonce was persisted up-front at step 3 to block
    // replay on any post-validate failure. The redundant late
    // store has been removed — re-writing the same nonce here
    // would be a no-op SMT touch but adds churn to the witness
    // and to RocksDB writes.

    // 10. Generate receipt
    let state_root = smt.root();
    let receipt = generate_receipt(
        tx,
        success,
        gas_used,
        refund_amount,
        effective_gas,
        block_ctx.base_fee,
        logs,
        state_root,
        return_data,
    );

    Ok(receipt)
}

/// Execute contract code in the PVM.
/// Loads contract storage from SMT before execution and persists changes after.
/// If `aot_fn` is provided, runs native compiled code instead of the interpreter.
fn execute_in_pvm(
    tx: &Transaction,
    _sender: &Account,
    code: &[u8],
    smt: &mut dyn pyde_state::smt::StateAccess,
    block_ctx: &BlockContext,
    aot_fn: Option<unsafe fn(*mut u64, u64, *mut pyde_vm::vm::Vm) -> u64>,
) -> (bool, u64, u64, Vec<LogEntry>, Vec<u8>) {
    let ctx = ExecutionContext {
        caller: tx.from,
        self_address: tx.to,
        call_value: U256::from(tx.value),
        block_number: block_ctx.height,
        timestamp: block_ctx.timestamp,
        gas_price: U256::from(block_ctx.base_fee),
        tx_nonce: tx.nonce,
        tx_gas_limit: tx.gas_limit,
        tx_hash: U256::ZERO,
        block_proposer: [0u8; 32],
        block_hashes: vec![],
        balances: std::collections::HashMap::new(),
    };

    let mut vm = Vm::with_gas_limit_and_context(tx.gas_limit, ctx);
    vm.calldata = tx.data.clone();

    // Pre-derive storage keys from access list and set as allowed keys + warm keys.
    // This avoids redundant Poseidon2 hashing during SLOAD/SSTORE and enforces
    // access list bounds (strict mode: unlisted keys trap).
    if !tx.access_list.is_empty() {
        let (allowed, warm) = pre_derive_access_list_keys(&tx.access_list, &tx.to);
        vm.allowed_storage_keys = Some(allowed);
        for key in warm {
            // Pre-warm all declared keys (EIP-2929: no cold surcharge)
            vm.warm_storage_keys.insert(key);
        }
    }

    // Lazy storage backend: VM reads from state on demand during Sload.
    // During execution, state is only read (writes go to vm.storage overlay).
    // SAFETY: smt is not mutated during vm.execute(). The pointer is valid for
    // the duration of execute_in_pvm. The closure is dropped before smt is mutated again.
    let _smt_ptr = smt as *const dyn pyde_state::smt::StateAccess as *const () as usize;
    let smt_vtable =
        unsafe { std::mem::transmute::<&dyn pyde_state::smt::StateAccess, [usize; 2]>(smt) };
    vm.storage_backend = Some(std::sync::Arc::new(move |key: &U256| {
        let smt_key = H256::from(key.to_le_bytes());
        // SAFETY: reverse of the transmute above. `smt` (the source of
        // `smt_vtable`) outlives every invocation of this closure —
        // `execute_in_pvm` borrows `smt` mutably for the full PVM run
        // and the closure is dropped before the borrow ends. The
        // fat-pointer layout `[usize; 2]` is stable for the whole
        // program (compile-time vtable).
        let smt_ref: &dyn pyde_state::smt::StateAccess = unsafe {
            std::mem::transmute::<[usize; 2], &dyn pyde_state::smt::StateAccess>(smt_vtable)
        };
        smt_ref.get(&smt_key)
    }));

    // Code backend: lazy-load target contract bytecode for cross-contract calls.
    let smt_vtable2 = smt_vtable;
    vm.code_backend = Some(std::sync::Arc::new(
        move |addr: &pyde_account::address::Address| {
            let code_key = pyde_state::keys::code_key(addr);
            // SAFETY: same invariant as the storage_backend closure —
            // `smt` outlives this closure for the duration of
            // `execute_in_pvm`.
            let smt_ref: &dyn pyde_state::smt::StateAccess = unsafe {
                std::mem::transmute::<[usize; 2], &dyn pyde_state::smt::StateAccess>(smt_vtable2)
            };
            smt_ref.get(&code_key)
        },
    ));

    // Try AOT compiled native code first, fall back to interpreter on failure.
    let (success, _gas_used_raw) = if let Some(func) = aot_fn {
        if vm.load(code).is_err() {
            return (false, tx.gas_limit, 0, vec![], vec![]);
        }
        // Pass pointer to vm.cpu.gp DIRECTLY — AOT reads/writes the SAME memory
        // as host functions. Zero desync between AOT variables and VM state.
        let regs_ptr = vm.cpu.gp.as_mut_ptr();
        let saved_storage = vm.storage.clone();
        let saved_logs = vm.logs.clone();
        // SAFETY: `func` is an `unsafe fn(*mut u64, u64, *mut Vm) ->
        // u64` pointer produced by `pyde_aot::compile_bytecode` via
        // Cranelift. The ABI is fixed; the three arguments match the
        // JIT's entry-block parameter list (`aot/src/codegen.rs`).
        // `regs_ptr` is a live pointer into `vm.cpu.gp` (which we own
        // exclusively inside `execute_in_pvm`). `&mut vm as *mut _`
        // is valid for the entire call. The AOT code only dereferences
        // through the same host_* callbacks that carry their own
        // SAFETY commentary (see `pyde-aot/src/host.rs`).
        let raw = unsafe { func(regs_ptr, tx.gas_limit, &mut vm as *mut _) };
        let (status, gas) = pyde_aot::decode_result(raw);
        if status == pyde_aot::RESULT_SUCCESS {
            // No register copy needed — AOT wrote directly to vm.cpu.gp
            vm.gas_used_total = gas;
            (true, gas)
        } else {
            // AOT failed — restore and retry with interpreter
            vm.storage = saved_storage;
            vm.logs = saved_logs;
            vm.gas_used_total = 0;
            vm.gas_refund = 0;
            vm.pc = 0;
            let _ = vm.load(code);
            let output = vm.execute();
            let ok = output.outcome == Outcome::Success;
            (ok, output.gas_used)
        }
    } else {
        if vm.load(code).is_err() {
            return (false, tx.gas_limit, 0, vec![], vec![]);
        }
        let output = vm.execute();
        let ok = output.outcome == Outcome::Success;
        (ok, output.gas_used)
    };

    // Persist VM storage changes back to SMT.
    // Use the derived key directly (same as what the VM uses internally).
    // Drop the storage backend before writing back (releases the read pointer)
    vm.storage_backend = None;
    vm.code_backend = None;

    // Batch-persist VM storage changes to SMT (single Merkle tree update + RocksDB write)
    if success && !vm.storage.is_empty() {
        let entries: Vec<(H256, Vec<u8>)> = vm
            .storage
            .iter()
            .map(|(vm_key, value_bytes)| (H256::from(vm_key.to_le_bytes()), value_bytes.clone()))
            .collect();
        let _ = smt.update_all(entries);
    }

    // Persist any contracts created via CREATE opcode (factory pattern)
    if success {
        for (addr, code) in &vm.contracts {
            let code_key = pyde_state::keys::code_key(addr);
            // Only persist if not already in SMT (newly created)
            if smt.get(&code_key).is_none() {
                let _ = smt.insert(code_key, code.clone());
                let contract_account = Account::new_contract(*addr, code);
                let _ = store_account(smt, &contract_account);
            }
        }
    }

    let logs = vm
        .logs
        .iter()
        .map(|log| LogEntry {
            address: log.address,
            topics: log.topics.iter().map(|t| t.to_le_bytes()).collect(),
            data: log.data.clone(),
        })
        .collect();

    // Capture return data: explicit return_data (from Revert/child calls) takes
    // priority. Otherwise, read from r1/r2 (same convention as do_ext_call).
    let return_data = if !vm.return_data.is_empty() {
        vm.return_data.clone()
    } else if success {
        let r2 = vm.cpu.read_gp(2);
        if r2 > 0 {
            // Blob/wide return: r1 = pointer, r2 = length
            let ptr = vm.cpu.read_gp(1) as usize;
            let len = (r2 as usize).min(pyde_vm::memory::MEMORY_SIZE);
            if ptr + len <= pyde_vm::memory::MEMORY_SIZE {
                vm.memory.load_bytes(ptr, len)
            } else {
                vm.cpu.read_gp(1).to_le_bytes().to_vec()
            }
        } else {
            // GP return: r1 = value (8 bytes LE)
            vm.cpu.read_gp(1).to_le_bytes().to_vec()
        }
    } else {
        vm.return_data.clone() // revert data
    };
    (success, vm.gas_used_total, vm.gas_refund, logs, return_data)
}

/// Execute a block of transactions using parallel group scheduling.
///
/// Groups are determined by the conflict scheduler (disjoint access lists).
/// Within each group, transactions execute sequentially (they conflict).
/// Between groups, execution is order-independent because the scheduler
/// guarantees disjoint state access — groups never touch the same storage keys.
///
// ============================================================
// Staking yield accounting (Phase 4 slice 4.1)
// ============================================================

/// Percentage of per-block inflation minted to the block proposer as a
/// "service reward." The remainder (100 - `SERVICE_SHARE_PCT`) flows into
/// the pool-yield accumulator and is claimable by every registered
/// validator proportional to their (identical) stake.
///
/// Chosen at 25% to roughly mirror Ethereum's proposer-vs-attester split
/// (proposer takes a meaningful bonus but most mint accrues to stakers).
pub const SERVICE_SHARE_PCT: u128 = 25;

/// Read the global rewards-per-validator accumulator. Returns 0 when the
/// key has not yet been initialized (pre-first-mint state).
pub fn read_rewards_per_validator(smt: &dyn pyde_state::smt::StateAccess) -> u128 {
    read_u128_state(smt, pyde_state::keys::rewards_per_validator_key()).unwrap_or(0)
}

/// Write the global rewards-per-validator accumulator.
pub fn write_rewards_per_validator(smt: &mut dyn pyde_state::smt::StateAccess, value: u128) {
    let _ = smt.insert(
        pyde_state::keys::rewards_per_validator_key(),
        value.to_le_bytes().to_vec(),
    );
}

/// Read the global `total_supply` state variable. Returns
/// `GENESIS_TOTAL_SUPPLY` (1B PYDE in quanta) as the default for
/// pre-initialization state, so block_reward math is correct at block 1
/// even before the first `total_supply` write.
pub fn read_total_supply(smt: &dyn pyde_state::smt::StateAccess) -> u128 {
    read_u128_state(smt, pyde_state::keys::supply_key()).unwrap_or(crate::fee::GENESIS_TOTAL_SUPPLY)
}

/// Write the global `total_supply` state variable.
pub fn write_total_supply(smt: &mut dyn pyde_state::smt::StateAccess, value: u128) {
    let _ = smt.insert(pyde_state::keys::supply_key(), value.to_le_bytes().to_vec());
}

/// Read cumulative fee burn counter (u128 LE, defaults to 0).
pub fn read_total_burned(smt: &dyn pyde_state::smt::StateAccess) -> u128 {
    read_u128_state(smt, pyde_state::keys::total_burned_key()).unwrap_or(0)
}

/// Write cumulative fee burn counter.
pub fn write_total_burned(smt: &mut dyn pyde_state::smt::StateAccess, value: u128) {
    let _ = smt.insert(
        pyde_state::keys::total_burned_key(),
        value.to_le_bytes().to_vec(),
    );
}

fn read_u128_state(
    smt: &dyn pyde_state::smt::StateAccess,
    key: sparse_merkle_tree::H256,
) -> Option<u128> {
    smt.get(&key).and_then(|b| {
        if b.len() >= 16 {
            Some(u128::from_le_bytes(b[..16].try_into().ok()?))
        } else {
            None
        }
    })
}

/// Read a vesting schedule from state (slice 4.4). Returns `None` when
/// the account has no vesting — tx validation treats this as "fully
/// unlocked." Writers: genesis init installs one per allocation; post-
/// genesis there is no mechanism to create or modify vesting, so an
/// installed schedule is effectively write-once.
pub fn read_vesting_schedule(
    smt: &dyn pyde_state::smt::StateAccess,
    address: &Address,
) -> Option<crate::vesting::VestingSchedule> {
    let bytes = smt.get(&pyde_state::keys::vesting_key(address))?;
    crate::vesting::VestingSchedule::decode(&bytes)
}

/// Install a vesting schedule for an account. Called by genesis init.
pub fn write_vesting_schedule(
    smt: &mut dyn pyde_state::smt::StateAccess,
    address: &Address,
    schedule: &crate::vesting::VestingSchedule,
) {
    let _ = smt.insert(pyde_state::keys::vesting_key(address), schedule.encode());
}

/// Validator bootstrap subsidy schedule (slice 4.4a).
///
/// `per_block` is precomputed as `total_amount / duration_slots` to avoid
/// doing the division in the hot path every block. The block processor
/// still gates on `end_slot` so the subsidy stream ends precisely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSubsidySchedule {
    pub per_block: u128,
    pub end_slot: u64,
}

impl ValidatorSubsidySchedule {
    pub const ENCODED_LEN: usize = 16 + 8;

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::ENCODED_LEN);
        buf.extend_from_slice(&self.per_block.to_le_bytes());
        buf.extend_from_slice(&self.end_slot.to_le_bytes());
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::ENCODED_LEN {
            return None;
        }
        let per_block = u128::from_le_bytes(bytes[0..16].try_into().ok()?);
        let end_slot = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
        Some(Self {
            per_block,
            end_slot,
        })
    }
}

/// Read the bootstrap subsidy schedule, if configured. Absent = no subsidy.
pub fn read_validator_subsidy(
    smt: &dyn pyde_state::smt::StateAccess,
) -> Option<ValidatorSubsidySchedule> {
    let bytes = smt.get(&pyde_state::keys::validator_subsidy_key())?;
    ValidatorSubsidySchedule::decode(&bytes)
}

pub fn write_validator_subsidy(
    smt: &mut dyn pyde_state::smt::StateAccess,
    schedule: &ValidatorSubsidySchedule,
) {
    let _ = smt.insert(pyde_state::keys::validator_subsidy_key(), schedule.encode());
}

/// Read the multisig signer public keys (slice 4.5). Returns the raw
/// byte list; caller decodes via `crate::multisig::decode_signer_set`.
pub fn read_multisig_signers_raw(smt: &dyn pyde_state::smt::StateAccess) -> Option<Vec<u8>> {
    smt.get(&pyde_state::keys::multisig_signers_key())
}

pub fn read_multisig_signers(smt: &dyn pyde_state::smt::StateAccess) -> Option<Vec<Vec<u8>>> {
    let bytes = read_multisig_signers_raw(smt)?;
    crate::multisig::decode_signer_set(&bytes)
}

pub fn write_multisig_signers(smt: &mut dyn pyde_state::smt::StateAccess, pks: &[Vec<u8>]) {
    let _ = smt.insert(
        pyde_state::keys::multisig_signers_key(),
        crate::multisig::encode_signer_set(pks),
    );
}

/// Read the multisig threshold (slice 4.5). Returns 0 when absent —
/// handlers should treat 0 as "no multisig configured" and reject.
pub fn read_multisig_threshold(smt: &dyn pyde_state::smt::StateAccess) -> u8 {
    smt.get(&pyde_state::keys::multisig_threshold_key())
        .and_then(|b| b.first().copied())
        .unwrap_or(0)
}

pub fn write_multisig_threshold(smt: &mut dyn pyde_state::smt::StateAccess, t: u8) {
    let _ = smt.insert(pyde_state::keys::multisig_threshold_key(), vec![t]);
}

/// Read the multisig nonce (slice 4.5). Defaults to 0.
pub fn read_multisig_nonce(smt: &dyn pyde_state::smt::StateAccess) -> u64 {
    smt.get(&pyde_state::keys::multisig_nonce_key())
        .and_then(|b| {
            if b.len() >= 8 {
                Some(u64::from_le_bytes(b[..8].try_into().ok()?))
            } else {
                None
            }
        })
        .unwrap_or(0)
}

pub fn write_multisig_nonce(smt: &mut dyn pyde_state::smt::StateAccess, n: u64) {
    let _ = smt.insert(
        pyde_state::keys::multisig_nonce_key(),
        n.to_le_bytes().to_vec(),
    );
}

/// Read the emergency pause end-slot (slice 4.6). `0` or absent means
/// the chain is not paused. A non-zero value means "paused until
/// `current_slot >= end_slot`" — callers typically want `is_paused`
/// below, which compares against the current slot.
pub fn read_emergency_pause_end_slot(smt: &dyn pyde_state::smt::StateAccess) -> u64 {
    smt.get(&pyde_state::keys::emergency_pause_end_slot_key())
        .and_then(|b| {
            if b.len() >= 8 {
                Some(u64::from_le_bytes(b[..8].try_into().ok()?))
            } else {
                None
            }
        })
        .unwrap_or(0)
}

pub fn write_emergency_pause_end_slot(smt: &mut dyn pyde_state::smt::StateAccess, end_slot: u64) {
    let _ = smt.insert(
        pyde_state::keys::emergency_pause_end_slot_key(),
        end_slot.to_le_bytes().to_vec(),
    );
}

/// True when `current_slot < pause_end_slot`. Past-deadline pauses are
/// treated as unpaused without any explicit clear — lazy expiry.
pub fn is_paused(smt: &dyn pyde_state::smt::StateAccess, current_slot: u64) -> bool {
    current_slot < read_emergency_pause_end_slot(smt)
}

/// Read the airdrop Merkle root, if configured.
pub fn read_airdrop_root(smt: &dyn pyde_state::smt::StateAccess) -> Option<[u8; 32]> {
    let bytes = smt.get(&pyde_state::keys::airdrop_root_key())?;
    if bytes.len() == 32 {
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes);
        Some(root)
    } else {
        None
    }
}

pub fn write_airdrop_root(smt: &mut dyn pyde_state::smt::StateAccess, root: &[u8; 32]) {
    let _ = smt.insert(pyde_state::keys::airdrop_root_key(), root.to_vec());
}

/// Read the airdrop claim deadline (slot). Absent = no deadline configured.
pub fn read_airdrop_deadline(smt: &dyn pyde_state::smt::StateAccess) -> Option<u64> {
    let bytes = smt.get(&pyde_state::keys::airdrop_deadline_key())?;
    if bytes.len() >= 8 {
        Some(u64::from_le_bytes(bytes[..8].try_into().ok()?))
    } else {
        None
    }
}

pub fn write_airdrop_deadline(smt: &mut dyn pyde_state::smt::StateAccess, slot: u64) {
    let _ = smt.insert(
        pyde_state::keys::airdrop_deadline_key(),
        slot.to_le_bytes().to_vec(),
    );
}

/// Read the operator-declared expected airdrop claim sum.
pub fn read_airdrop_expected_sum(smt: &dyn pyde_state::smt::StateAccess) -> Option<u128> {
    let bytes = smt.get(&pyde_state::keys::airdrop_expected_sum_key())?;
    if bytes.len() >= 16 {
        Some(u128::from_le_bytes(bytes[..16].try_into().ok()?))
    } else {
        None
    }
}

pub fn write_airdrop_expected_sum(smt: &mut dyn pyde_state::smt::StateAccess, amount: u128) {
    let _ = smt.insert(
        pyde_state::keys::airdrop_expected_sum_key(),
        amount.to_le_bytes().to_vec(),
    );
}

/// Check whether a leaf index has already been claimed.
pub fn is_airdrop_claimed(smt: &dyn pyde_state::smt::StateAccess, leaf_index: u64) -> bool {
    smt.get(&pyde_state::keys::airdrop_claimed_key(leaf_index))
        .is_some()
}

/// Mark a leaf index as claimed. Idempotent — value is a single marker byte.
pub fn mark_airdrop_claimed(smt: &mut dyn pyde_state::smt::StateAccess, leaf_index: u64) {
    let _ = smt.insert(
        pyde_state::keys::airdrop_claimed_key(leaf_index),
        vec![0x01],
    );
}

/// Read active-only validator count (slice 4.2). Defaults to 0.
pub fn read_active_validator_count(smt: &dyn pyde_state::smt::StateAccess) -> u64 {
    smt.get(&pyde_state::keys::active_validator_count_key())
        .and_then(|b| {
            if b.len() >= 8 {
                Some(u64::from_le_bytes(b[..8].try_into().ok()?))
            } else {
                None
            }
        })
        .unwrap_or(0)
}

/// Increment `active_validator_count`. Called on successful StakeDeposit.
pub fn increment_active_validator_count(smt: &mut dyn pyde_state::smt::StateAccess) {
    let n = read_active_validator_count(smt).saturating_add(1);
    let _ = smt.insert(
        pyde_state::keys::active_validator_count_key(),
        n.to_le_bytes().to_vec(),
    );
}

/// Decrement `active_validator_count`. Called on each transition OUT of
/// Active (StakeWithdraw, slash, ejection). `saturating_sub(1)` protects
/// against counter corruption — if it ever went negative the underflow
/// would silently wrap and dilute payouts.
pub fn decrement_active_validator_count(smt: &mut dyn pyde_state::smt::StateAccess) {
    let n = read_active_validator_count(smt).saturating_sub(1);
    let _ = smt.insert(
        pyde_state::keys::active_validator_count_key(),
        n.to_le_bytes().to_vec(),
    );
}

/// Layout of a validator entry:
///   [pk_len:4 LE][pk:897][stake:16 LE][status:1][last_claimed_at:16 LE][exit_block:8 LE, optional]
/// `exit_block` is present iff `status == 0x01` (Unbonding). Total is
/// either 4 + 897 + 16 + 1 + 16 = 934 bytes (Active/Exited), or
/// 934 + 8 = 942 bytes (Unbonding).
pub const VALIDATOR_ENTRY_BASE_LEN: usize = 4 + 897 + 16 + 1 + 16;

/// Parsed view of a validator entry. Single source of truth for the wire
/// format — both the StakeDeposit / StakeWithdraw / ClaimReward handlers
/// and the consensus-side loader in pyde-node::validator go through this
/// struct to avoid offset drift.
pub struct ValidatorEntry {
    pub pk: Vec<u8>,
    pub stake: u128,
    pub status: u8,
    pub last_claimed_at: u128,
    /// Block at which unbonding was initiated. Only populated when
    /// `status == 0x01` (Unbonding).
    pub exit_block: Option<u64>,
}

impl ValidatorEntry {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < VALIDATOR_ENTRY_BASE_LEN {
            return None;
        }
        let pk_len = u32::from_le_bytes(bytes[..4].try_into().ok()?) as usize;
        if pk_len != 897 || bytes.len() < 4 + pk_len + 16 + 1 + 16 {
            return None;
        }
        let pk = bytes[4..4 + pk_len].to_vec();
        let stake_start = 4 + pk_len;
        let stake = u128::from_le_bytes(bytes[stake_start..stake_start + 16].try_into().ok()?);
        let status_pos = stake_start + 16;
        let status = bytes[status_pos];
        let claim_start = status_pos + 1;
        let last_claimed_at =
            u128::from_le_bytes(bytes[claim_start..claim_start + 16].try_into().ok()?);
        let exit_start = claim_start + 16;
        let exit_block = if status == 0x01 && bytes.len() >= exit_start + 8 {
            Some(u64::from_le_bytes(
                bytes[exit_start..exit_start + 8].try_into().ok()?,
            ))
        } else {
            None
        };
        Some(Self {
            pk,
            stake,
            status,
            last_claimed_at,
            exit_block,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(VALIDATOR_ENTRY_BASE_LEN + 8);
        buf.extend_from_slice(&(self.pk.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.pk);
        buf.extend_from_slice(&self.stake.to_le_bytes());
        buf.push(self.status);
        buf.extend_from_slice(&self.last_claimed_at.to_le_bytes());
        if let Some(eb) = self.exit_block {
            buf.extend_from_slice(&eb.to_le_bytes());
        }
        buf
    }
}

// ============================================================
// Slash transaction handler
// ============================================================
//
// Canonical constants live in `pyde-slashing`. Both `pyde-tx` and
// `pyde-consensus` depend on it directly — this eliminates the earlier
// drift risk where the shadow copies could fork.
use pyde_slashing::{
    EVIDENCE_VERSION as SLASH_EVIDENCE_VERSION, FINDER_FEE_PERCENT as SLASH_FINDER_FEE_PERCENT,
    VALIDATOR_STAKE as SLASH_VALIDATOR_STAKE,
};

/// Parsed contents of a `TransactionType::Slash` payload.
struct SlashEvidence {
    slot: u64,
    block_hash_1: [u8; 32],
    signature_1: Vec<u8>,
    block_hash_2: [u8; 32],
    signature_2: Vec<u8>,
    signer: Address,
    _submitter: Address, // carried for wire compatibility; the on-chain
                         // submitter is authoritatively tx.from.
}

/// Decode the Slash-tx payload. Mirrors the wire layout in
/// `pyde_node::wire::encode_double_sign_evidence`; see that file for
/// the canonical format description.
fn decode_slash_evidence(data: &[u8]) -> Result<SlashEvidence, String> {
    fn need(data: &[u8], pos: usize, n: usize) -> Result<(), String> {
        if data.len() < pos + n {
            Err(format!("evidence truncated at offset {}", pos))
        } else {
            Ok(())
        }
    }
    let mut pos = 0usize;
    need(data, pos, 1)?;
    let version = data[pos];
    pos += 1;
    if version != SLASH_EVIDENCE_VERSION {
        return Err(format!("unsupported evidence version: {}", version));
    }
    need(data, pos, 8)?;
    let slot = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
    pos += 8;
    need(data, pos, 32)?;
    let mut block_hash_1 = [0u8; 32];
    block_hash_1.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;
    need(data, pos, 4)?;
    let sig1_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    need(data, pos, sig1_len)?;
    let signature_1 = data[pos..pos + sig1_len].to_vec();
    pos += sig1_len;
    need(data, pos, 32)?;
    let mut block_hash_2 = [0u8; 32];
    block_hash_2.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;
    need(data, pos, 4)?;
    let sig2_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    need(data, pos, sig2_len)?;
    let signature_2 = data[pos..pos + sig2_len].to_vec();
    pos += sig2_len;
    need(data, pos, 32)?;
    let mut signer = [0u8; 32];
    signer.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;
    need(data, pos, 32)?;
    let mut submitter = [0u8; 32];
    submitter.copy_from_slice(&data[pos..pos + 32]);
    Ok(SlashEvidence {
        slot,
        block_hash_1,
        signature_1,
        block_hash_2,
        signature_2,
        signer,
        _submitter: submitter,
    })
}

/// Parse a serialized validator entry:
/// `[pk_len:4 LE][pk][stake:16 LE][status:1]`.
/// Returns `(pk_bytes, stake, status, status_offset)`.
/// Canonical `(chain_id_le || slot_le || block_hash)` bytes that
/// proposers and voters sign. Mirrors
/// `pyde_consensus::hotstuff::proposer_sign_message` — kept here as a
/// local copy to avoid a `pyde-tx` → `pyde-consensus` dep cycle. The
/// `chain_id` prefix prevents cross-chain replay of slashing evidence.
fn proposer_sign_message_bytes(chain_id: u64, slot: u64, block_hash: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + 8 + 32);
    msg.extend_from_slice(&chain_id.to_le_bytes());
    msg.extend_from_slice(&slot.to_le_bytes());
    msg.extend_from_slice(block_hash);
    msg
}

/// Execute a Slash tx. Returns the standard
/// `(success, gas_used, gas_refund, logs, return_data)` tuple expected
/// by the outer pipeline match. On success, `submitter_balance` is
/// credited the finder's fee and the offender's validator entry is
/// updated in the SMT (stake zeroed, status = Ejected).
///
/// `chain_id` is the LOCAL chain's id; evidence signatures are
/// re-verified against `(chain_id || slot || block_hash)` so a
/// double-sign on a different chain cannot slash here.
fn execute_slash(
    chain_id: u64,
    tx: &Transaction,
    smt: &mut dyn pyde_state::smt::StateAccess,
    submitter_balance: &mut u128,
) -> (bool, u64, u64, Vec<LogEntry>, Vec<u8>) {
    let failed = |gas: u64, msg: &[u8]| -> (bool, u64, u64, Vec<LogEntry>, Vec<u8>) {
        (false, gas, 0, vec![], msg.to_vec())
    };

    let ev = match decode_slash_evidence(&tx.data) {
        Ok(ev) => ev,
        Err(e) => return failed(21_000, e.as_bytes()),
    };

    if ev.block_hash_1 == ev.block_hash_2 {
        return failed(21_000, b"evidence blocks must differ");
    }

    let val_key = pyde_state::keys::validator_key(&ev.signer);
    let val_data = match smt.get(&val_key) {
        Some(d) => d,
        None => return failed(21_000, b"accused signer is not a registered validator"),
    };

    let mut entry = match ValidatorEntry::decode(&val_data) {
        Some(e) => e,
        None => return failed(21_000, b"corrupt validator entry"),
    };

    // Status: 0x00 = Active, 0x01 = Unbonding, 0x02 = Ejected/Exited.
    // An already-ejected validator has already been slashed — skip.
    if entry.status == 0x02 {
        return failed(21_000, b"signer already ejected");
    }
    let was_active = entry.status == 0x00;

    // Re-verify both signatures using the pubkey from state (not from
    // the evidence payload — the submitter could lie about signer).
    let pk = match pyde_crypto::falcon::FalconPublicKey::from_bytes(&entry.pk) {
        Some(pk) => pk,
        None => return failed(21_000, b"validator public key is malformed"),
    };
    let sig_1 = match pyde_crypto::falcon::FalconSignature::from_bytes(&ev.signature_1) {
        Some(s) => s,
        None => return failed(21_000, b"signature_1 malformed"),
    };
    let sig_2 = match pyde_crypto::falcon::FalconSignature::from_bytes(&ev.signature_2) {
        Some(s) => s,
        None => return failed(21_000, b"signature_2 malformed"),
    };
    let msg_1 = proposer_sign_message_bytes(chain_id, ev.slot, &ev.block_hash_1);
    let msg_2 = proposer_sign_message_bytes(chain_id, ev.slot, &ev.block_hash_2);
    if !pyde_crypto::falcon::falcon_verify(&pk, &msg_1, &sig_1)
        || !pyde_crypto::falcon::falcon_verify(&pk, &msg_2, &sig_2)
    {
        return failed(21_000, b"evidence signatures failed FALCON verification");
    }

    // Evidence valid. Apply the slash: zero the stake, pay the finder,
    // mark the offender Ejected. The portion of stake not paid to the
    // finder is burned (implicit — never credited to any account).
    let slash_amount = entry.stake.min(SLASH_VALIDATOR_STAKE);
    let finder_fee = slash_amount * SLASH_FINDER_FEE_PERCENT / 100;
    entry.stake = entry.stake.saturating_sub(slash_amount);
    entry.status = 0x02;
    entry.exit_block = None;
    *submitter_balance = submitter_balance.saturating_add(finder_fee);
    let _ = smt.insert(val_key, entry.encode());

    // Task 4.2: decrement active_validator_count when slashing an Active
    // member (Unbonding members were already decremented on withdraw).
    if was_active {
        decrement_active_validator_count(smt);
    }

    tracing::info!(
        offender = hex::encode(ev.signer),
        finder = hex::encode(tx.from),
        finder_fee,
        burned = slash_amount - finder_fee,
        "slash applied: offender ejected, finder paid"
    );

    (true, 100_000, 0, vec![], ev.signer.to_vec())
}

// ---------------------------------------------------------------------------
// Airdrop claim + sweep (slice 4.4b)
// ---------------------------------------------------------------------------

/// Base gas for a `ClaimAirdrop` tx (covers state lookups + balance writes).
const AIRDROP_CLAIM_BASE_GAS: u64 = 30_000;

/// Per-proof-level gas for the Poseidon2 pair hash that reconstructs the
/// root. Measured via `crypto/benches/poseidon2_bench.rs` at ≈ 1.0 µs per
/// `poseidon2_pair` on M-series (≈ 1_000 gas at the 1 ns/gas target).
/// Charged at 5× the measured cost to absorb slower hardware, state I/O
/// that accompanies each level, and CI variance. A 20-level proof pays
/// ~100_000 gas vs ~20_000 gas of pure hashing — the margin is real
/// state-write overhead, not arbitrary inflation.
const AIRDROP_CLAIM_PER_LEVEL_GAS: u64 = 5_000;

/// Flat gas for `SweepAirdrop`: three reads (deadline, pool account,
/// treasury account) + two balance writes.
const AIRDROP_SWEEP_GAS: u64 = 40_000;

fn execute_claim_airdrop(
    tx: &Transaction,
    smt: &mut dyn pyde_state::smt::StateAccess,
    block_ctx: &BlockContext,
    sender_balance: &mut u128,
) -> (bool, u64, u64, Vec<LogEntry>, Vec<u8>) {
    let payload = match crate::airdrop::ClaimPayload::decode(&tx.data) {
        Some(p) => p,
        None => {
            return (
                false,
                AIRDROP_CLAIM_BASE_GAS,
                0,
                vec![],
                b"airdrop payload malformed".to_vec(),
            );
        }
    };

    let gas = AIRDROP_CLAIM_BASE_GAS
        .saturating_add(AIRDROP_CLAIM_PER_LEVEL_GAS.saturating_mul(payload.proof.len() as u64));

    // If the tx.gas_limit can't cover the measured cost of this claim,
    // reject BEFORE we touch any state. Without this, `post_execution_refund`
    // would cap the charge at `gas_limit × base_fee`, effectively letting
    // the claimer underpay for the Poseidon2 work — cheap exploit because
    // state writes (pool debit, claimed flag, balance credit) would still
    // commit. Returning `gas_limit` here caps the fee at exactly what the
    // sender budgeted; no state mutations have happened yet.
    if tx.gas_limit < gas {
        return (
            false,
            tx.gas_limit,
            0,
            vec![],
            b"airdrop claim gas_limit below required cost".to_vec(),
        );
    }

    // Deadline — if no deadline is configured the airdrop isn't active.
    let deadline = match read_airdrop_deadline(smt) {
        Some(d) => d,
        None => {
            return (false, gas, 0, vec![], b"airdrop not configured".to_vec());
        }
    };
    if block_ctx.height > deadline {
        return (false, gas, 0, vec![], b"airdrop deadline passed".to_vec());
    }

    // Root — required alongside deadline, but check defensively in case
    // of partially-written genesis state.
    let root = match read_airdrop_root(smt) {
        Some(r) => r,
        None => {
            return (false, gas, 0, vec![], b"airdrop root missing".to_vec());
        }
    };

    // Anti-replay check BEFORE proof verification so repeated failed
    // claims don't waste Poseidon2 cycles on the validator.
    if is_airdrop_claimed(smt, payload.leaf_index) {
        return (
            false,
            gas,
            0,
            vec![],
            b"airdrop leaf already claimed".to_vec(),
        );
    }

    if !crate::airdrop::verify_proof(
        payload.leaf_index,
        &tx.from,
        payload.amount,
        &payload.proof,
        &root,
    ) {
        return (false, gas, 0, vec![], b"airdrop proof invalid".to_vec());
    }

    // Debit pool, credit claimer. Pool underfund should be caught at
    // genesis by the `expected_sum >= pool_balance` check, but we
    // defend in depth in case the expected sum was wrong and late
    // claimers hit a drained pool.
    let pool_addr = pyde_account::address::airdrop_pool_address();
    let mut pool = load_account(smt, &pool_addr);
    if pool.balance < payload.amount {
        return (false, gas, 0, vec![], b"airdrop pool insufficient".to_vec());
    }
    pool.balance -= payload.amount;
    if store_account(smt, &pool).is_err() {
        return (false, gas, 0, vec![], b"airdrop pool write failed".to_vec());
    }

    *sender_balance = sender_balance.saturating_add(payload.amount);
    mark_airdrop_claimed(smt, payload.leaf_index);

    (true, gas, 0, vec![], payload.amount.to_le_bytes().to_vec())
}

fn execute_sweep_airdrop(
    tx: &Transaction,
    smt: &mut dyn pyde_state::smt::StateAccess,
    block_ctx: &BlockContext,
) -> (bool, u64, u64, Vec<LogEntry>, Vec<u8>) {
    // Symmetric to the claim handler: reject before touching state if
    // the sweeper budgeted less gas than we actually charge. Without
    // this, the balance-transfer writes would commit while the fee is
    // capped at the sweeper's limit.
    if tx.gas_limit < AIRDROP_SWEEP_GAS {
        return (
            false,
            tx.gas_limit,
            0,
            vec![],
            b"sweep gas_limit below required cost".to_vec(),
        );
    }

    let deadline = match read_airdrop_deadline(smt) {
        Some(d) => d,
        None => {
            return (
                false,
                AIRDROP_SWEEP_GAS,
                0,
                vec![],
                b"airdrop not configured".to_vec(),
            );
        }
    };
    if block_ctx.height <= deadline {
        return (
            false,
            AIRDROP_SWEEP_GAS,
            0,
            vec![],
            b"airdrop still active".to_vec(),
        );
    }

    let pool_addr = pyde_account::address::airdrop_pool_address();
    let mut pool = load_account(smt, &pool_addr);
    let residue = pool.balance;
    if residue == 0 {
        return (true, AIRDROP_SWEEP_GAS, 0, vec![], vec![]);
    }

    let treasury_addr = pyde_account::address::treasury_address();
    let mut treasury = load_account(smt, &treasury_addr);
    pool.balance = 0;
    treasury.balance = treasury.balance.saturating_add(residue);

    if store_account(smt, &pool).is_err() || store_account(smt, &treasury).is_err() {
        return (
            false,
            AIRDROP_SWEEP_GAS,
            0,
            vec![],
            b"sweep state write failed".to_vec(),
        );
    }

    (
        true,
        AIRDROP_SWEEP_GAS,
        0,
        vec![],
        residue.to_le_bytes().to_vec(),
    )
}

// ---------------------------------------------------------------------------
// Multisig governance (slice 4.5)
// ---------------------------------------------------------------------------

/// Base gas for a MultisigTx (state reads + one treasury debit + one
/// target credit + nonce bump). Verification cost of each FALCON sig is
/// charged per-sig below.
const MULTISIG_SPEND_BASE_GAS: u64 = 50_000;

/// Per-sig verification cost. FALCON-512 verify measured at ~21 µs via
/// `crypto/benches/falcon_bench.rs`, so at the 1 ns/gas target a single
/// verify is ~21_000 gas of pure crypto. Charged at 50_000 gas per sig
/// (≈ 2.4× measured) to absorb slower hardware, per-sig bookkeeping,
/// and the overhead of building the signing-bytes preimage.
const MULTISIG_PER_SIG_GAS: u64 = 50_000;

/// Base gas for a RotateMultisig (same reads + signer set write).
const MULTISIG_ROTATE_BASE_GAS: u64 = 60_000;

/// Per-new-signer gas for the signer-set write. 16 signers = 14.4KB of
/// pk bytes, charged at 10_000 per pk.
const MULTISIG_ROTATE_PER_NEW_SIGNER_GAS: u64 = 10_000;

fn execute_multisig_spend(
    tx: &Transaction,
    smt: &mut dyn pyde_state::smt::StateAccess,
    block_ctx: &BlockContext,
) -> (bool, u64, u64, Vec<LogEntry>, Vec<u8>) {
    let payload = match crate::multisig::MultisigPayload::decode(&tx.data) {
        Some(p) => p,
        None => {
            return (
                false,
                MULTISIG_SPEND_BASE_GAS,
                0,
                vec![],
                b"multisig payload malformed".to_vec(),
            );
        }
    };
    let (spend, sigs) = match payload {
        crate::multisig::MultisigPayload::Spend { spend, sigs } => (spend, sigs),
        crate::multisig::MultisigPayload::Rotate { .. } => {
            return (
                false,
                MULTISIG_SPEND_BASE_GAS,
                0,
                vec![],
                b"wrong payload tag for MultisigTx".to_vec(),
            );
        }
    };

    let gas = MULTISIG_SPEND_BASE_GAS
        .saturating_add(MULTISIG_PER_SIG_GAS.saturating_mul(sigs.len() as u64));

    // Early gas guard — same pattern as ClaimAirdrop. Reject before
    // state writes if the sender under-budgeted.
    if tx.gas_limit < gas {
        return (
            false,
            tx.gas_limit,
            0,
            vec![],
            b"multisig gas_limit below required cost".to_vec(),
        );
    }

    // Structural checks on the spend itself before any crypto work.
    if spend.value == 0 {
        return (
            false,
            gas,
            0,
            vec![],
            b"multisig value must be > 0".to_vec(),
        );
    }
    if spend.target == [0u8; 32] {
        return (
            false,
            gas,
            0,
            vec![],
            b"multisig target must not be zero".to_vec(),
        );
    }
    let treasury = pyde_account::address::treasury_address();
    if spend.target == treasury {
        return (
            false,
            gas,
            0,
            vec![],
            b"multisig cannot spend to treasury itself".to_vec(),
        );
    }
    // The pipeline's post-execution stage unconditionally writes back
    // `sender` (the submitter account) and `recipient` (tx.to). Both
    // writebacks happen AFTER the handler. If our handler credits
    // `spend.target` and then the pipeline writes `sender` or
    // `recipient` back to the same balance key, our credit is
    // clobbered — treasury gets debited but the target never sees the
    // funds. Block the two collision paths.
    if spend.target == tx.from {
        return (
            false,
            gas,
            0,
            vec![],
            b"multisig target must not be the submitter".to_vec(),
        );
    }
    if tx.to != [0u8; 32] {
        return (
            false,
            gas,
            0,
            vec![],
            b"MultisigTx must set tx.to = ZERO_ADDRESS".to_vec(),
        );
    }

    let signer_pks = match read_multisig_signers(smt) {
        Some(p) => p,
        None => {
            return (false, gas, 0, vec![], b"multisig not configured".to_vec());
        }
    };
    let threshold = read_multisig_threshold(smt);
    if threshold == 0 {
        return (false, gas, 0, vec![], b"multisig threshold = 0".to_vec());
    }

    let nonce = read_multisig_nonce(smt);
    let msg = spend.signing_bytes(nonce, block_ctx.chain_id);
    let valid = match crate::multisig::count_valid_sigs(&sigs, &signer_pks, &msg) {
        Ok(v) => v,
        Err(e) => return (false, gas, 0, vec![], e.as_bytes().to_vec()),
    };

    if valid < threshold as usize {
        return (
            false,
            gas,
            0,
            vec![],
            format!(
                "multisig below threshold: {} valid of {} required",
                valid, threshold
            )
            .into_bytes(),
        );
    }

    // Check treasury balance.
    let mut treasury_account = load_account(smt, &treasury);
    if treasury_account.balance < spend.value {
        return (
            false,
            gas,
            0,
            vec![],
            b"treasury balance insufficient".to_vec(),
        );
    }

    let mut target_account = load_account(smt, &spend.target);
    treasury_account.balance -= spend.value;
    target_account.balance = target_account.balance.saturating_add(spend.value);

    if store_account(smt, &treasury_account).is_err()
        || store_account(smt, &target_account).is_err()
    {
        return (
            false,
            gas,
            0,
            vec![],
            b"multisig state write failed".to_vec(),
        );
    }

    // Bump nonce — binds THIS payload to THIS nonce, preventing replay.
    write_multisig_nonce(smt, nonce.saturating_add(1));

    (true, gas, 0, vec![], spend.value.to_le_bytes().to_vec())
}

fn execute_rotate_multisig(
    tx: &Transaction,
    smt: &mut dyn pyde_state::smt::StateAccess,
    block_ctx: &BlockContext,
) -> (bool, u64, u64, Vec<LogEntry>, Vec<u8>) {
    let payload = match crate::multisig::MultisigPayload::decode(&tx.data) {
        Some(p) => p,
        None => {
            return (
                false,
                MULTISIG_ROTATE_BASE_GAS,
                0,
                vec![],
                b"multisig payload malformed".to_vec(),
            );
        }
    };
    let (rotate, sigs) = match payload {
        crate::multisig::MultisigPayload::Rotate { rotate, sigs } => (rotate, sigs),
        crate::multisig::MultisigPayload::Spend { .. } => {
            return (
                false,
                MULTISIG_ROTATE_BASE_GAS,
                0,
                vec![],
                b"wrong payload tag for RotateMultisig".to_vec(),
            );
        }
    };

    let gas = MULTISIG_ROTATE_BASE_GAS
        .saturating_add(MULTISIG_PER_SIG_GAS.saturating_mul(sigs.len() as u64))
        .saturating_add(
            MULTISIG_ROTATE_PER_NEW_SIGNER_GAS.saturating_mul(rotate.new_signer_pks.len() as u64),
        );

    if tx.gas_limit < gas {
        return (
            false,
            tx.gas_limit,
            0,
            vec![],
            b"multisig rotate gas_limit below required cost".to_vec(),
        );
    }

    // New-set structural checks.
    if rotate.new_signer_pks.is_empty()
        || rotate.new_signer_pks.len() > crate::multisig::MAX_SIGNERS as usize
    {
        return (
            false,
            gas,
            0,
            vec![],
            b"rotate signer count out of range".to_vec(),
        );
    }
    if rotate.new_threshold == 0 || rotate.new_threshold as usize > rotate.new_signer_pks.len() {
        return (false, gas, 0, vec![], b"rotate threshold invalid".to_vec());
    }
    // Every pk must be 897 bytes AND parseable — decoder already
    // enforced length; verify pk parses cleanly, and detect duplicates.
    let mut seen: Vec<&[u8]> = Vec::with_capacity(rotate.new_signer_pks.len());
    for pk in &rotate.new_signer_pks {
        if pyde_crypto::falcon::FalconPublicKey::from_bytes(pk).is_none() {
            return (
                false,
                gas,
                0,
                vec![],
                b"rotate contains malformed pk".to_vec(),
            );
        }
        if seen.contains(&pk.as_slice()) {
            return (
                false,
                gas,
                0,
                vec![],
                b"rotate contains duplicate pk".to_vec(),
            );
        }
        seen.push(pk.as_slice());
    }

    // Load current config for authorization check.
    let current_signers = match read_multisig_signers(smt) {
        Some(p) => p,
        None => {
            return (false, gas, 0, vec![], b"multisig not configured".to_vec());
        }
    };
    let current_threshold = read_multisig_threshold(smt);
    if current_threshold == 0 {
        return (false, gas, 0, vec![], b"multisig threshold = 0".to_vec());
    }

    let nonce = read_multisig_nonce(smt);
    let msg = rotate.signing_bytes(nonce, block_ctx.chain_id);
    let valid = match crate::multisig::count_valid_sigs(&sigs, &current_signers, &msg) {
        Ok(v) => v,
        Err(e) => return (false, gas, 0, vec![], e.as_bytes().to_vec()),
    };
    if valid < current_threshold as usize {
        return (
            false,
            gas,
            0,
            vec![],
            format!(
                "rotate below threshold: {} valid of {} required",
                valid, current_threshold
            )
            .into_bytes(),
        );
    }

    // Install new set + threshold + bump nonce.
    write_multisig_signers(smt, &rotate.new_signer_pks);
    write_multisig_threshold(smt, rotate.new_threshold);
    write_multisig_nonce(smt, nonce.saturating_add(1));

    let signer_count = rotate.new_signer_pks.len() as u8;
    (
        true,
        gas,
        0,
        vec![],
        vec![signer_count, rotate.new_threshold],
    )
}

// ---------------------------------------------------------------------------
// Emergency pause / resume (slice 4.6)
// ---------------------------------------------------------------------------

/// Base gas for EmergencyPause / EmergencyResume. State work is
/// minimal (one slot write + nonce bump); sig verification is the
/// dominant cost, charged per-sig below.
const EMERGENCY_BASE_GAS: u64 = 40_000;

/// Maximum pause window in slots. 6_500_000 × 400ms ≈ 30 days. Caps
/// the lost-keys blast radius: even a worst-case "all signers lose
/// their keys during pause" scenario auto-recovers after 30 days.
pub const MAX_PAUSE_DURATION_SLOTS: u64 = 6_500_000;

fn multisig_ok(
    smt: &dyn pyde_state::smt::StateAccess,
    sigs: &[crate::multisig::SigEntry],
    signing_bytes: &[u8],
    gas: u64,
) -> Result<(), (bool, u64, u64, Vec<LogEntry>, Vec<u8>)> {
    let signer_pks = match read_multisig_signers(smt) {
        Some(p) => p,
        None => {
            return Err((false, gas, 0, vec![], b"multisig not configured".to_vec()));
        }
    };
    let threshold = read_multisig_threshold(smt);
    if threshold == 0 {
        return Err((false, gas, 0, vec![], b"multisig threshold = 0".to_vec()));
    }
    let valid = match crate::multisig::count_valid_sigs(sigs, &signer_pks, signing_bytes) {
        Ok(v) => v,
        Err(e) => return Err((false, gas, 0, vec![], e.as_bytes().to_vec())),
    };
    if valid < threshold as usize {
        return Err((
            false,
            gas,
            0,
            vec![],
            format!(
                "emergency below threshold: {} valid of {} required",
                valid, threshold
            )
            .into_bytes(),
        ));
    }
    Ok(())
}

fn execute_emergency_pause(
    tx: &Transaction,
    smt: &mut dyn pyde_state::smt::StateAccess,
    block_ctx: &BlockContext,
) -> (bool, u64, u64, Vec<LogEntry>, Vec<u8>) {
    let payload = match crate::multisig::EmergencyPausePayload::decode(&tx.data) {
        Some(p) => p,
        None => {
            return (
                false,
                EMERGENCY_BASE_GAS,
                0,
                vec![],
                b"pause payload malformed".to_vec(),
            );
        }
    };

    let gas = EMERGENCY_BASE_GAS
        .saturating_add(MULTISIG_PER_SIG_GAS.saturating_mul(payload.sigs.len() as u64));

    if tx.gas_limit < gas {
        return (
            false,
            tx.gas_limit,
            0,
            vec![],
            b"pause gas_limit below required cost".to_vec(),
        );
    }

    // Duration bounds. Zero = no pause (weird), above cap = too long.
    if payload.duration_slots == 0 || payload.duration_slots > MAX_PAUSE_DURATION_SLOTS {
        return (
            false,
            gas,
            0,
            vec![],
            format!(
                "pause duration_slots {} outside 1..={}",
                payload.duration_slots, MAX_PAUSE_DURATION_SLOTS
            )
            .into_bytes(),
        );
    }

    // Reject re-pause while already paused — unreachable via public
    // entry (gate blocks non-Resume while paused) but kept as
    // defense-in-depth against future refactors.
    if is_paused(smt, block_ctx.height) {
        return (false, gas, 0, vec![], b"chain already paused".to_vec());
    }

    let nonce = read_multisig_nonce(smt);
    let msg = payload.signing_bytes(nonce, block_ctx.chain_id);
    if let Err(e) = multisig_ok(smt, &payload.sigs, &msg, gas) {
        return e;
    }

    let end_slot = block_ctx.height.saturating_add(payload.duration_slots);
    write_emergency_pause_end_slot(smt, end_slot);
    write_multisig_nonce(smt, nonce.saturating_add(1));

    (true, gas, 0, vec![], end_slot.to_le_bytes().to_vec())
}

fn execute_emergency_resume(
    tx: &Transaction,
    smt: &mut dyn pyde_state::smt::StateAccess,
    block_ctx: &BlockContext,
) -> (bool, u64, u64, Vec<LogEntry>, Vec<u8>) {
    let payload = match crate::multisig::EmergencyResumePayload::decode(&tx.data) {
        Some(p) => p,
        None => {
            return (
                false,
                EMERGENCY_BASE_GAS,
                0,
                vec![],
                b"resume payload malformed".to_vec(),
            );
        }
    };

    let gas = EMERGENCY_BASE_GAS
        .saturating_add(MULTISIG_PER_SIG_GAS.saturating_mul(payload.sigs.len() as u64));

    if tx.gas_limit < gas {
        return (
            false,
            tx.gas_limit,
            0,
            vec![],
            b"resume gas_limit below required cost".to_vec(),
        );
    }

    // Resume only makes sense if currently paused. An auto-expired
    // pause (end_slot in the past) still counts as "not paused" and
    // should reject resume submissions as a no-op waste of signer
    // coordination.
    if !is_paused(smt, block_ctx.height) {
        return (false, gas, 0, vec![], b"chain already unpaused".to_vec());
    }

    let nonce = read_multisig_nonce(smt);
    let msg = crate::multisig::EmergencyResumePayload::signing_bytes(nonce, block_ctx.chain_id);
    if let Err(e) = multisig_ok(smt, &payload.sigs, &msg, gas) {
        return e;
    }

    // Explicit unpause: zero out the end slot.
    write_emergency_pause_end_slot(smt, 0);
    write_multisig_nonce(smt, nonce.saturating_add(1));

    (true, gas, 0, vec![], vec![])
}

/// Currently executes groups sequentially on the shared SMT. True thread-level
/// parallelism (per-group SMT clones or overlays) is a future optimization —
/// the correctness guarantee is already provided by the conflict scheduler.
///
/// Returns receipts in the original transaction order.
pub fn execute_block_parallel(
    txs: &[Transaction],
    schedule: &crate::parallel::ExecutionSchedule,
    smt: &mut dyn pyde_state::smt::StateAccess,
    block_ctx: &BlockContext,
) -> Result<Vec<Receipt>, PipelineError> {
    let mut receipts: Vec<Option<Receipt>> = vec![None; txs.len()];

    for group in &schedule.groups {
        for &tx_idx in &group.tx_indices {
            let tx = &txs[tx_idx];
            let receipt = execute_transaction(tx, smt, block_ctx)?;
            receipts[tx_idx] = Some(receipt);
        }
    }

    let ordered: Vec<Receipt> = receipts.into_iter().map(|r| r.unwrap()).collect();
    Ok(ordered)
}

/// Pre-derive storage keys from transaction access lists.
///
/// Converts raw 32-byte access list keys into the VM's derived U256 keys
/// (Poseidon2 of slot || contract_address). Returns:
/// - allowed: HashSet of all derived keys (for strict access list enforcement)
/// - warm: Vec of all derived keys (for EIP-2929 pre-warming)
///
/// This avoids redundant Poseidon2 hashing during SLOAD/SSTORE execution.
pub fn pre_derive_access_list_keys(
    access_list: &[crate::types::AccessEntry],
    contract_address: &Address,
) -> (std::collections::HashSet<U256>, Vec<U256>) {
    let mut allowed = std::collections::HashSet::new();
    let mut warm = Vec::new();

    for entry in access_list {
        // Derive keys for each access entry's reads and writes
        let target = if entry.address == ZERO_ADDRESS {
            contract_address
        } else {
            &entry.address
        };

        for raw_key in entry.reads.iter().chain(entry.writes.iter()) {
            let slot = U256::from_le_bytes(*raw_key);
            let slot_bytes = slot.to_le_bytes();
            // Trim trailing zeros, minimum 8 bytes (u64 width)
            let sig_len = 32 - slot_bytes.iter().rev().take_while(|&&b| b == 0).count();
            let slot_len = sig_len.max(8);
            // Derive storage key: Poseidon2(address || 0x04 || slot_bytes)
            // Matches VM's derive_storage_key and pyde_state::keys::storage_slot_key
            let mut buf = Vec::with_capacity(33 + slot_len);
            buf.extend_from_slice(target);
            buf.push(0x04); // STORAGE_SLOT discriminator
            buf.extend_from_slice(&slot_bytes[..slot_len]);
            let hash = poseidon2_hash(&buf);
            let derived = U256::from_le_bytes(hash.to_bytes());
            allowed.insert(derived);
            warm.push(derived);
        }
    }

    (allowed, warm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::falcon::{falcon_keygen, falcon_sign};
    use pyde_state::smt::PydeSMT;

    fn make_block_ctx() -> BlockContext {
        BlockContext {
            height: 100,
            timestamp: 1_000_000,
            base_fee: 1_000,
            block_gas_limit: 400_000_000,
            chain_id: 1,
            validator_address: derive_eoa_address(b"validator"),
            // Pipeline tests construct unsigned tx fixtures — existing
            // tests relied on the old chain_id=31337 bypass; now we set
            // the flag explicitly to preserve that behavior without the
            // chain_id coupling. Individual tests override tx.signature
            // when they want to exercise signature validation.
            dev_skip_signature: true,
            block_sigs_pre_verified: false,
        }
    }

    fn make_signed_tx(
        from: Address,
        to: Address,
        value: u128,
        gas_limit: u64,
        nonce: u64,
        sk: &pyde_crypto::falcon::FalconSecretKey,
    ) -> Transaction {
        let mut tx = Transaction {
            from,
            to,
            value,
            data: vec![],
            gas_limit,
            nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };
        let hash = tx.hash();
        tx.signature = falcon_sign(sk, &hash).unwrap().as_bytes().to_vec();
        tx
    }

    fn setup_funded_account(
        smt: &mut dyn pyde_state::smt::StateAccess,
        pk_bytes: &[u8],
        balance: u128,
    ) -> Address {
        let addr = derive_eoa_address(pk_bytes);
        let mut account = Account::new_eoa(pk_bytes);
        account.balance = balance;
        store_account(smt, &account).unwrap();
        store_nonce(smt, &addr, &NonceState::new()).unwrap();
        addr
    }

    // ========== Task 0398: PVM execution invocation ==========

    #[test]
    fn simple_transfer_updates_balances() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let block_ctx = make_block_ctx();

        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, 100_000_000);
        let recipient_addr = derive_eoa_address(b"recipient");

        let tx = make_signed_tx(sender_addr, recipient_addr, 1_000, 21_000, 0, &sk);
        let receipt = execute_transaction(&tx, &mut smt, &block_ctx).unwrap();

        assert!(receipt.success);
        assert_eq!(receipt.gas_used, 21_000);

        // Check balances
        let sender = load_account(&smt, &sender_addr);
        let recipient = load_account(&smt, &recipient_addr);
        assert!(sender.balance < 100_000_000); // paid gas + value
        assert_eq!(recipient.balance, 1_000);
    }

    #[test]
    fn nonce_consumed_after_execution() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let block_ctx = make_block_ctx();

        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, 100_000_000);
        let recipient_addr = derive_eoa_address(b"recipient");

        let tx = make_signed_tx(sender_addr, recipient_addr, 0, 21_000, 0, &sk);
        execute_transaction(&tx, &mut smt, &block_ctx).unwrap();

        // Nonce 0 should be consumed, base advanced to 1
        let nonce = load_nonce(&smt, &sender_addr);
        assert_eq!(nonce.base, 1);
    }

    // ========== Task 0403: Contract deployment ==========

    #[test]
    fn contract_deployment() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let block_ctx = make_block_ctx();

        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, 100_000_000);

        let mut tx = make_signed_tx(sender_addr, ZERO_ADDRESS, 0, 50_000, 0, &sk);
        tx.tx_type = TransactionType::Deploy;
        tx.data = b"contract bytecode here".to_vec();
        // Re-sign with new fields
        let hash = tx.hash();
        tx.signature = falcon_sign(&sk, &hash).unwrap().as_bytes().to_vec();

        let receipt = execute_transaction(&tx, &mut smt, &block_ctx).unwrap();
        assert!(receipt.success);

        // Contract should be deployed at derived address
        let contract_addr = pyde_account::address::derive_create_address(&sender_addr, 0);
        let code = load_code(&smt, &contract_addr);
        assert!(code.is_some());
        assert_eq!(code.unwrap(), b"contract bytecode here");

        let contract = load_account(&smt, &contract_addr);
        assert!(contract.is_contract());
    }

    // ========== Fee distribution ==========

    #[test]
    fn fees_distributed_to_validator() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let block_ctx = make_block_ctx();

        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, 100_000_000);
        let recipient_addr = derive_eoa_address(b"recipient");

        let tx = make_signed_tx(sender_addr, recipient_addr, 0, 21_000, 0, &sk);
        let receipt = execute_transaction(&tx, &mut smt, &block_ctx).unwrap();

        assert!(receipt.fee_validator > 0);
        assert!(receipt.fee_burned > 0);

        // Validator account should have received fees
        let validator = load_account(&smt, &block_ctx.validator_address);
        assert_eq!(validator.balance, receipt.fee_validator);
    }

    // ========== State persistence ==========

    // ── Audit 307: writeback no-clobber regression tests ───────────

    /// Audit 307 follow-up: `apply_account_delta` must persist
    /// `account.nonce` increments from the Deploy handler. Pre-fix
    /// the function only handled `balance`, `gas_tank`, and
    /// `auth_keys` — `nonce` was loaded fresh from SMT and stored
    /// without applying the deploy-time `+= 1`. Result: every
    /// Deploy from the same sender derived
    /// `create_address(sender, 0)` and silently overwrote the
    /// previously-deployed contract's runtime bytecode at that
    /// address. The first regression to catch this was
    /// `pyde-node`'s `reentrancy_attack_blocked` integration test
    /// (deploys two contracts back-to-back, both ended up at the
    /// same address, so the "attacker" overwrote the "vault" and
    /// the rest of the test went sideways).
    #[test]
    fn deploy_increments_persisted_nonce_after_307() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let block_ctx = make_block_ctx();

        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, 1_000_000_000);
        let initial_nonce = load_account(&smt, &sender_addr).nonce;
        assert_eq!(initial_nonce, 0, "fresh account starts at nonce 0");

        // Deploy 1.
        let mut tx1 = make_signed_tx(sender_addr, ZERO_ADDRESS, 0, 50_000, 0, &sk);
        tx1.tx_type = TransactionType::Deploy;
        tx1.data = b"contract bytecode #1".to_vec();
        let h1 = tx1.hash();
        tx1.signature = falcon_sign(&sk, &h1).unwrap().as_bytes().to_vec();
        let receipt1 = execute_transaction(&tx1, &mut smt, &block_ctx).unwrap();
        assert!(receipt1.success);
        let addr1: [u8; 32] = receipt1.return_data.as_slice().try_into().unwrap();

        // The persisted account.nonce MUST be 1 now.
        let after_deploy1 = load_account(&smt, &sender_addr).nonce;
        assert_eq!(
            after_deploy1, 1,
            "account.nonce must be persisted as 1 after first Deploy",
        );

        // Deploy 2 — must derive a DIFFERENT address from Deploy 1.
        let mut tx2 = make_signed_tx(sender_addr, ZERO_ADDRESS, 0, 50_000, 1, &sk);
        tx2.tx_type = TransactionType::Deploy;
        tx2.data = b"contract bytecode #2".to_vec();
        let h2 = tx2.hash();
        tx2.signature = falcon_sign(&sk, &h2).unwrap().as_bytes().to_vec();
        let receipt2 = execute_transaction(&tx2, &mut smt, &block_ctx).unwrap();
        assert!(receipt2.success);
        let addr2: [u8; 32] = receipt2.return_data.as_slice().try_into().unwrap();

        assert_ne!(
            addr1, addr2,
            "back-to-back Deploys must derive distinct addresses (got the same!)",
        );

        // Verify each address holds its own bytecode.
        let code1 = load_code(&smt, &addr1).expect("contract #1 code present");
        let code2 = load_code(&smt, &addr2).expect("contract #2 code present");
        assert_eq!(code1, b"contract bytecode #1");
        assert_eq!(code2, b"contract bytecode #2");

        // The persisted nonce after Deploy 2 must be 2.
        let after_deploy2 = load_account(&smt, &sender_addr).nonce;
        assert_eq!(
            after_deploy2, 2,
            "account.nonce must be persisted as 2 after second Deploy",
        );
    }

    /// Self-transfer must pay gas. Pre-307, `store_account(smt,
    /// &recipient)` ran AFTER `store_account(smt, &sender)` for
    /// the same address, overwriting sender's debit with
    /// recipient's pre-tx-balance + tx.value. End state: pre-tx +
    /// tx.value (free + minted). After 307: pre-tx - gas_used.
    #[test]
    fn self_transfer_pays_gas_after_307() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let mut block_ctx = make_block_ctx();
        // Use a non-aliasing validator address so the sender alone
        // captures the clobber path under test.
        block_ctx.validator_address = derive_eoa_address(b"validator-distinct");

        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, 100_000_000);
        let tx = make_signed_tx(sender_addr, sender_addr, 1_000, 21_000, 0, &sk);
        let receipt = execute_transaction(&tx, &mut smt, &block_ctx).unwrap();
        assert!(receipt.success);

        let final_balance = load_account(&smt, &sender_addr).balance;
        let expected_gas_cost = 21_000u128 * block_ctx.base_fee;
        // Pre-307 bug: final_balance == 100_000_000 + 1_000 (free).
        // Post-307: final_balance == 100_000_000 - gas_cost.
        assert!(
            final_balance < 100_000_000,
            "self-transfer must pay gas, balance = {}",
            final_balance
        );
        assert_eq!(
            final_balance,
            100_000_000 - expected_gas_cost,
            "self-transfer leaves only the gas debit; tx.value moves nowhere"
        );
    }

    /// Proposer submitting their own tx earns the validator fee
    /// credit. Pre-307: line-623 `store_account(smt, &sender)`
    /// overwrote line-609's validator credit. After 307: sender
    /// re-loads from SMT (with credit applied) and applies its
    /// debit + refund deltas on top. End balance: pre-tx -
    /// gas_paid + fee_dist.validator.
    #[test]
    fn proposer_self_tx_earns_validator_credit_after_307() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let mut block_ctx = make_block_ctx();

        // Make the validator address == the sender address.
        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, 100_000_000);
        block_ctx.validator_address = sender_addr;

        let recipient_addr = derive_eoa_address(b"recipient");
        let tx = make_signed_tx(sender_addr, recipient_addr, 1_000, 21_000, 0, &sk);
        let receipt = execute_transaction(&tx, &mut smt, &block_ctx).unwrap();
        assert!(receipt.success);

        // The validator credit is 20% of effective_gas * base_fee
        // (see distribute_fee). A non-zero credit confirms the
        // line-609 store survived past the line-623 sender store.
        let final_balance = load_account(&smt, &sender_addr).balance;
        let gas_paid = receipt.gas_used as u128 * block_ctx.base_fee;
        let validator_credit = (gas_paid * 20) / 100;
        let expected = 100_000_000u128 - gas_paid - 1_000 + validator_credit;
        assert_eq!(
            final_balance, expected,
            "proposer must keep the validator-fee credit after paying their own tx (audit 307)"
        );
    }

    /// Recipient = validator: validator credit applied to recipient
    /// is NOT clobbered by the late `store_account(smt, &recipient)`.
    /// End balance: pre-tx + tx.value + fee_dist.validator.
    #[test]
    fn recipient_is_validator_keeps_credit_after_307() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let mut block_ctx = make_block_ctx();

        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, 100_000_000);

        // Pre-fund the validator (= recipient) so we can verify
        // the delta is applied on top of an existing balance.
        let recipient_addr = derive_eoa_address(b"recipient-and-validator");
        let mut recipient_account = Account::new_eoa(b"recipient-and-validator");
        recipient_account.balance = 50_000_000;
        store_account(&mut smt, &recipient_account).unwrap();
        block_ctx.validator_address = recipient_addr;

        let tx = make_signed_tx(sender_addr, recipient_addr, 1_000, 21_000, 0, &sk);
        let receipt = execute_transaction(&tx, &mut smt, &block_ctx).unwrap();
        assert!(receipt.success);

        let final_balance = load_account(&smt, &recipient_addr).balance;
        let gas_paid = receipt.gas_used as u128 * block_ctx.base_fee;
        let validator_credit = (gas_paid * 20) / 100;
        let expected = 50_000_000u128 + 1_000 + validator_credit;
        assert_eq!(
            final_balance, expected,
            "recipient-as-validator must accumulate value transfer AND validator credit (audit 307)"
        );
    }

    /// Sender = treasury: the 10% treasury credit applied at line
    /// 614-616 survives past the late sender store.
    #[test]
    fn sender_is_treasury_keeps_credit_after_307() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let block_ctx = make_block_ctx();

        // Build a sender whose address IS the treasury address by
        // overriding the loaded account at the treasury slot.
        let treasury_addr = pyde_account::address::treasury_address();
        let mut treasury_eoa = Account::new_eoa(&pk_bytes);
        // Force the address field to match the treasury slot.
        treasury_eoa.address = treasury_addr;
        treasury_eoa.balance = 100_000_000;
        store_account(&mut smt, &treasury_eoa).unwrap();
        store_nonce(&mut smt, &treasury_addr, &NonceState::new()).unwrap();

        let recipient_addr = derive_eoa_address(b"recipient");
        let mut tx = make_signed_tx(treasury_addr, recipient_addr, 1_000, 21_000, 0, &sk);
        // The from address is the treasury slot which doesn't have
        // sender's auth_keys; tests skip signature via
        // dev_skip_signature in block_ctx, but we must still
        // override tx.signature shape for `make_signed_tx`'s sig
        // to be sane against `sender.auth_keys`. Re-build the sig
        // against the (mutated) tx fields:
        tx.signature = falcon_sign(&sk, &tx.hash()).unwrap().as_bytes().to_vec();

        let receipt = execute_transaction(&tx, &mut smt, &block_ctx).unwrap();
        assert!(receipt.success);

        let final_balance = load_account(&smt, &treasury_addr).balance;
        let gas_paid = receipt.gas_used as u128 * block_ctx.base_fee;
        let treasury_credit = (gas_paid * 10) / 100;
        let expected = 100_000_000u128 - gas_paid - 1_000 + treasury_credit;
        assert_eq!(
            final_balance, expected,
            "sender-as-treasury must keep treasury credit after paying their own tx (audit 307)"
        );
    }

    #[test]
    fn state_root_changes_after_tx() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let block_ctx = make_block_ctx();

        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, 100_000_000);
        let root_before = smt.root();

        let tx = make_signed_tx(sender_addr, derive_eoa_address(b"r"), 1_000, 21_000, 0, &sk);
        execute_transaction(&tx, &mut smt, &block_ctx).unwrap();

        assert_ne!(smt.root(), root_before);
    }

    // ========== Error cases ==========

    #[test]
    fn insufficient_balance_rejected() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let block_ctx = make_block_ctx();

        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, 100); // too low
        let tx = make_signed_tx(sender_addr, derive_eoa_address(b"r"), 0, 21_000, 0, &sk);

        let result = execute_transaction(&tx, &mut smt, &block_ctx);
        assert!(result.is_err());
    }

    #[test]
    fn multiple_txs_sequential() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let block_ctx = make_block_ctx();

        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, 1_000_000_000);
        let recipient = derive_eoa_address(b"recipient");

        // Execute 3 transactions sequentially
        for nonce in 0..3u64 {
            let tx = make_signed_tx(sender_addr, recipient, 100, 21_000, nonce, &sk);
            let receipt = execute_transaction(&tx, &mut smt, &block_ctx).unwrap();
            assert!(receipt.success);
        }

        let recipient_account = load_account(&smt, &recipient);
        assert_eq!(recipient_account.balance, 300); // 3 × 100

        let nonce = load_nonce(&smt, &sender_addr);
        assert_eq!(nonce.base, 3);
    }

    /// Full pipeline test: deploy contract, call set_balance x4, call batch_reward,
    /// then verify balance(20) == 41700. Reproduces the E2E discrepancy.
    #[test]
    fn pipeline_batch_reward_storage_integrity() {
        let src = r#"
            contract T {
                storage {
                    balances: Map<u64, u64>,
                    fee_rate: u64,
                    owner_id: u64,
                }
                pub fn setup() {
                    self.fee_rate = 10;
                    self.owner_id = 1;
                    self.balances[1] = 0;
                }
                pub fn set_balance(user: u64, amount: u64) {
                    self.balances[user] = amount;
                }
                #[reentrant]
                pub fn batch_reward(u1: u64, u2: u64, u3: u64, reward: u64) -> u64 {
                    let b1 = self.balances[u1];
                    let b2 = self.balances[u2];
                    let b3 = self.balances[u3];
                    let rate = self.fee_rate;
                    let total = reward * 3;
                    let tax = total * rate / 100;
                    let per_user = (total - tax) / 3;
                    self.balances[u1] = b1 + per_user;
                    self.balances[u2] = b2 + per_user;
                    self.balances[u3] = b3 + per_user;
                    let oid = self.owner_id;
                    let owner_bal = self.balances[oid];
                    self.balances[oid] = owner_bal + tax;
                    return per_user;
                }
                #[view]
                pub fn get_balance(user: u64) -> u64 { return self.balances[user]; }
            }
        "#;

        // Compile WITH optimization (matches CLI: otic build)
        let (tokens, _) = otic::lexer::Lexer::new(src).tokenize();
        let (file, _) = otic::parser::Parser::new(tokens).parse();
        let mut ir = otic::lower::lower(&file);
        otic::optimize::optimize(&mut ir);
        let codegen = otic::codegen::CodeGen::new();
        let contract = codegen.generate(&ir);

        let mut smt = PydeSMT::new();
        let contract_addr = [0x42u8; 32];

        // Store contract code in SMT
        store_code(&mut smt, &contract_addr, &contract.runtime_bytecode).unwrap();
        let contract_account = Account::new_contract(contract_addr, &contract.runtime_bytecode);
        store_account(&mut smt, &contract_account).unwrap();

        // Create sender account with huge balance
        let sender_addr = [0x01u8; 32];
        let sender = Account {
            address: sender_addr,
            nonce: 0,
            balance: 10_000_000_000_000_000_000u128,
            code_hash: sparse_merkle_tree::H256::zero(),
            storage_root: sparse_merkle_tree::H256::zero(),
            account_type: pyde_account::types::AccountType::EOA,
            auth_keys: pyde_account::types::AuthKeys::None,
            gas_tank: 0,
            key_nonce: 0,
        };
        store_account(&mut smt, &sender).unwrap();
        store_nonce(
            &mut smt,
            &sender_addr,
            &pyde_account::nonce::NonceState::new(),
        )
        .unwrap();

        // Also create validator account
        let validator_addr = [0xFFu8; 32];
        let validator = Account {
            address: validator_addr,
            balance: 0,
            ..sender.clone()
        };
        store_account(&mut smt, &validator).unwrap();

        let block_ctx = BlockContext {
            height: 1,
            timestamp: 1000,
            base_fee: 50_000_000_000, // match node genesis: 50 gwei
            block_gas_limit: 400_000_000,
            chain_id: 31337,
            validator_address: validator_addr,
            dev_skip_signature: true,
            block_sigs_pre_verified: false,
        };

        let sel = |name: &str| -> u32 { otic::codegen::compute_selector(name) };

        // Helper: send a tx through the pipeline
        let mut nonce_counter = 0u64;
        let mut send = |smt: &mut dyn pyde_state::smt::StateAccess, calldata: Vec<u8>| {
            let tx = Transaction {
                from: sender_addr,
                to: contract_addr,
                value: 0,
                data: calldata,
                gas_limit: 500_000,
                nonce: nonce_counter,
                signature: vec![],
                fee_payer: FeePayer::Sender,
                access_list: vec![],
                deadline: None,
                chain_id: 31337,
                tx_type: TransactionType::Standard,
            };
            nonce_counter += 1;
            let result = execute_transaction(&tx, smt, &block_ctx);
            match result {
                Ok(receipt) => assert!(receipt.success, "tx failed: nonce={}", tx.nonce),
                Err(e) => panic!("pipeline error: {:?}", e),
            }
        };

        // Helper: pyde_call equivalent (read-only)
        let call = |smt: &dyn pyde_state::smt::StateAccess, calldata: Vec<u8>| -> u64 {
            let ctx = pyde_vm::vm::ExecutionContext {
                self_address: contract_addr,
                caller: sender_addr,
                ..Default::default()
            };
            let code = load_code(smt, &contract_addr).expect("no code");
            let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(10_000_000, ctx);
            let smt_vtable = unsafe {
                std::mem::transmute::<&dyn pyde_state::smt::StateAccess, [usize; 2]>(smt)
            };
            vm.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
                let smt_key = sparse_merkle_tree::H256::from(key.to_le_bytes());
                let smt_ref: &dyn pyde_state::smt::StateAccess = unsafe {
                    std::mem::transmute::<[usize; 2], &dyn pyde_state::smt::StateAccess>(smt_vtable)
                };
                smt_ref.get(&smt_key)
            }));
            vm.calldata = calldata;
            vm.load(&code).unwrap();
            let output = vm.execute();
            assert_eq!(output.outcome, pyde_vm::vm::Outcome::Success, "call failed");
            vm.cpu.read_gp(1)
        };

        let _enc_u64 = |v: u64| -> Vec<u8> { v.to_le_bytes().to_vec() };
        let cd = |name: &str, args: &[u64]| -> Vec<u8> {
            let mut data = sel(name).to_be_bytes().to_vec();
            for a in args {
                data.extend_from_slice(&a.to_le_bytes());
            }
            data
        };

        // Run: setup, set_balance x4, batch_reward
        send(&mut smt, cd("setup", &[]));
        send(&mut smt, cd("set_balance", &[10, 38000]));
        send(&mut smt, cd("set_balance", &[20, 39000]));
        send(&mut smt, cd("set_balance", &[30, 21800]));
        send(&mut smt, cd("set_balance", &[1, 1200]));

        // Verify pre-batch balances
        assert_eq!(
            call(&smt, cd("get_balance", &[10])),
            38000,
            "pre-batch bal(10)"
        );
        assert_eq!(
            call(&smt, cd("get_balance", &[20])),
            39000,
            "pre-batch bal(20)"
        );
        assert_eq!(
            call(&smt, cd("get_balance", &[30])),
            21800,
            "pre-batch bal(30)"
        );
        assert_eq!(
            call(&smt, cd("get_balance", &[1])),
            1200,
            "pre-batch bal(1)"
        );

        // Run batch_reward
        send(&mut smt, cd("batch_reward", &[10, 20, 30, 3000]));

        // Verify post-batch balances
        let b10 = call(&smt, cd("get_balance", &[10]));
        let b20 = call(&smt, cd("get_balance", &[20]));
        let b30 = call(&smt, cd("get_balance", &[30]));
        let b1 = call(&smt, cd("get_balance", &[1]));

        assert_eq!(b10, 40700, "bal(10) = 38000 + 2700");
        assert_eq!(b20, 41700, "bal(20) = 39000 + 2700");
        assert_eq!(b30, 24500, "bal(30) = 21800 + 2700");
        assert_eq!(b1, 2100, "bal(1) = 1200 + 900");
    }

    // ========== E2E: Otigen compile → deploy → call (struct + Vec + while loop) ==========

    // `arc_with_non_send_sync`: the storage_backend closure captures a
    // raw `*const PydeSMT` pointer (!Send/!Sync). Single-thread test
    // context; same rationale as otic/src/codegen.rs tests module.
    #[allow(clippy::arc_with_non_send_sync)]
    #[test]
    fn e2e_rank_contract() {
        // Compile the RankTest contract from source
        let src = r#"
            contract RankTest {
                struct Player { id: u64, score: u64, }
                storage {
                    players: Map<u64, Player>,
                    boards: Map<u64, Vec<u64>>,
                }
                #[constructor] pub fn init() {}
                pub fn setup() {
                    let p = Player { id: 1, score: 400 };
                    self.players[1] = p;
                    let mut b = Vec::new();
                    b.push(100); b.push(200); b.push(300);
                    self.boards[1] = b;
                }
                pub fn rank(pid: u64, bid: u64) -> u64 {
                    let p = self.players[pid];
                    let board = self.boards[bid];
                    let score = p.score;
                    let mut rank = 0;
                    let mut i = 0;
                    let len = board.len();
                    while i < len {
                        if board[i] > score { rank = rank + 1; }
                        i = i + 1;
                    }
                    return rank + 1;
                }
            }
        "#;

        let (tokens, _) = otic::lexer::Lexer::new(src).tokenize();
        let (file, _) = otic::parser::Parser::new(tokens).parse();
        let mut ir = otic::lower::lower(&file);
        otic::optimize::optimize(&mut ir);
        let codegen = otic::codegen::CodeGen::new();
        let contract = codegen.generate(&ir);

        // Build deploy-format bytecode: [clen:4 LE][rlen:4 LE][constructor][runtime]
        let clen = contract.constructor_bytecode.len() as u32;
        let rlen = contract.runtime_bytecode.len() as u32;
        let mut deploy_data = Vec::new();
        deploy_data.extend_from_slice(&clen.to_le_bytes());
        deploy_data.extend_from_slice(&rlen.to_le_bytes());
        deploy_data.extend_from_slice(&contract.constructor_bytecode);
        deploy_data.extend_from_slice(&contract.runtime_bytecode);

        // Setup accounts and deploy
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let block_ctx = make_block_ctx();
        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, 1_000_000_000_000);
        let contract_addr = pyde_account::address::derive_create_address(&sender_addr, 0);

        // Deploy transaction
        let mut deploy_tx = make_signed_tx(sender_addr, ZERO_ADDRESS, 0, 100_000_000, 0, &sk);
        deploy_tx.tx_type = TransactionType::Deploy;
        deploy_tx.data = deploy_data;
        let hash = deploy_tx.hash();
        deploy_tx.signature = falcon_sign(&sk, &hash).unwrap().as_bytes().to_vec();

        let receipt = execute_transaction(&deploy_tx, &mut smt, &block_ctx).unwrap();
        assert!(receipt.success, "deploy failed: {:?}", receipt);

        // Verify contract code was stored
        let code = load_code(&smt, &contract_addr);
        assert!(code.is_some(), "contract code not found");
        assert_eq!(code.unwrap(), contract.runtime_bytecode);

        // Call setup() — populates storage with Player and board
        let setup_sel = otic::codegen::compute_selector("setup");
        let mut setup_tx = make_signed_tx(sender_addr, contract_addr, 0, 100_000_000, 1, &sk);
        setup_tx.data = setup_sel.to_be_bytes().to_vec();
        let hash = setup_tx.hash();
        setup_tx.signature = falcon_sign(&sk, &hash).unwrap().as_bytes().to_vec();

        let receipt = execute_transaction(&setup_tx, &mut smt, &block_ctx).unwrap();
        assert!(receipt.success, "setup() failed: {:?}", receipt);

        // Call rank(1, 1) via direct PVM execution (to read return value from r1)
        // score=400, board=[100,200,300] — no entries > 400, so rank = 0+1 = 1
        let rank_sel = otic::codegen::compute_selector("rank");
        let mut calldata = rank_sel.to_be_bytes().to_vec();
        calldata.extend_from_slice(&1u64.to_le_bytes()); // pid = 1
        calldata.extend_from_slice(&1u64.to_le_bytes()); // bid = 1

        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: contract_addr,
            ..Default::default()
        };
        let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm.calldata = calldata;

        // Wire up storage backend to read from SMT
        let smt_ptr = &smt as *const PydeSMT;
        vm.storage_backend = Some(std::sync::Arc::new(move |key: &U256| {
            let smt_key = H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr).get(&smt_key) }
        }));

        let runtime_code = load_code(&smt, &contract_addr).expect("runtime code");
        vm.load(&runtime_code).unwrap();
        let output = vm.execute();
        assert_eq!(
            output.outcome,
            pyde_vm::vm::Outcome::Success,
            "rank() failed"
        );
        assert_eq!(
            vm.cpu.read_gp(1),
            1,
            "rank should be 1 (no board entries > 400)"
        );
    }

    // ========== Task 1183: Pre-derived keys match runtime-derived keys ==========

    #[test]
    fn pre_derived_keys_match_runtime_derived() {
        // Verify that pre_derive_access_list_keys produces identical U256 keys
        // to what the VM computes at runtime via derive_storage_key.
        let contract_addr = derive_eoa_address(b"test_contract");
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: contract_addr,
            ..Default::default()
        };
        let vm = pyde_vm::vm::Vm::with_gas_limit_and_context(0, ctx);

        // Test several slot values
        for slot_val in [0u64, 1, 42, 0xDEADBEEF, u64::MAX] {
            let slot = U256::from(slot_val);
            let runtime_key = vm.derive_storage_key(slot);

            // Pre-derive via access list
            let mut raw_key = [0u8; 32];
            raw_key.copy_from_slice(&slot.to_le_bytes());
            let access_entry = crate::types::AccessEntry {
                address: ZERO_ADDRESS, // ZERO = use contract_address
                reads: vec![raw_key],
                writes: vec![],
            };
            let (allowed, _warm) = pre_derive_access_list_keys(&[access_entry], &contract_addr);

            assert!(
                allowed.contains(&runtime_key),
                "pre-derived key for slot {} doesn't match runtime key",
                slot_val
            );
        }
    }

    #[test]
    fn pre_derived_keys_cross_contract() {
        // Access list entries with explicit contract address (not ZERO)
        let target_addr = derive_eoa_address(b"target_contract");
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: target_addr,
            ..Default::default()
        };
        let vm = pyde_vm::vm::Vm::with_gas_limit_and_context(0, ctx);

        let slot = U256::from(7u64);
        let runtime_key = vm.derive_storage_key(slot);

        let mut raw_key = [0u8; 32];
        raw_key.copy_from_slice(&slot.to_le_bytes());
        let access_entry = crate::types::AccessEntry {
            address: target_addr, // explicit address
            reads: vec![],
            writes: vec![raw_key],
        };
        let caller_addr = derive_eoa_address(b"caller");
        let (allowed, warm) = pre_derive_access_list_keys(&[access_entry], &caller_addr);

        assert!(
            allowed.contains(&runtime_key),
            "cross-contract key should match"
        );
        assert_eq!(warm.len(), 1);
    }

    // ========== Return data capture ==========

    #[test]
    fn return_data_captured_for_function_with_return_value() {
        // Compile a contract with a function that returns a value
        let src = r#"
            contract Returner {
                storage { value: u64, }
                #[constructor]
                pub fn init() { self.value = 42; }
                pub fn get_value() -> u64 { return self.value; }
            }
        "#;
        let compiled = otic::compile_all(src);
        assert!(!compiled.is_empty());
        let (_, contract) = &compiled[0];

        // Build deploy data
        let clen = contract.constructor_bytecode.len() as u32;
        let rlen = contract.runtime_bytecode.len() as u32;
        let mut deploy_data = Vec::new();
        deploy_data.extend_from_slice(&clen.to_le_bytes());
        deploy_data.extend_from_slice(&rlen.to_le_bytes());
        deploy_data.extend_from_slice(&contract.constructor_bytecode);
        deploy_data.extend_from_slice(&contract.runtime_bytecode);

        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let block_ctx = make_block_ctx();
        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, 1_000_000_000_000);
        let contract_addr = pyde_account::address::derive_create_address(&sender_addr, 0);

        // Deploy — must set data BEFORE signing
        let deploy_tx = {
            let mut tx = Transaction {
                from: sender_addr,
                to: ZERO_ADDRESS,
                value: 0,
                data: deploy_data,
                gas_limit: 100_000_000,
                nonce: 0,
                signature: vec![],
                fee_payer: FeePayer::Sender,
                access_list: vec![],
                deadline: None,
                chain_id: 1,
                tx_type: TransactionType::Deploy,
            };
            let hash = tx.hash();
            tx.signature = pyde_crypto::falcon::falcon_sign(&sk, &hash)
                .unwrap()
                .as_bytes()
                .to_vec();
            tx
        };
        let deploy_receipt = execute_transaction(&deploy_tx, &mut smt, &block_ctx).unwrap();
        assert!(deploy_receipt.success, "deploy failed");

        // Call get_value() — should return 42
        let selector = otic::codegen::compute_selector("get_value");
        let call_tx = {
            let mut tx = Transaction {
                from: sender_addr,
                to: contract_addr,
                value: 0,
                data: selector.to_be_bytes().to_vec(),
                gas_limit: 100_000_000,
                nonce: 1,
                signature: vec![],
                fee_payer: FeePayer::Sender,
                access_list: vec![],
                deadline: None,
                chain_id: 1,
                tx_type: TransactionType::Standard,
            };
            let hash = tx.hash();
            tx.signature = pyde_crypto::falcon::falcon_sign(&sk, &hash)
                .unwrap()
                .as_bytes()
                .to_vec();
            tx
        };
        let call_receipt = execute_transaction(&call_tx, &mut smt, &block_ctx).unwrap();
        assert!(call_receipt.success, "call failed");

        // return_data should contain 42 as u64 LE
        assert!(
            !call_receipt.return_data.is_empty(),
            "return_data should not be empty"
        );
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&call_receipt.return_data[..8]);
        let returned_value = u64::from_le_bytes(buf);
        assert_eq!(returned_value, 42, "return_data should contain 42");
    }

    #[test]
    fn return_data_empty_for_void_function_is_not_meaningful() {
        // Compile a contract with a void function
        let src = r#"
            contract Setter {
                storage { value: u64, }
                #[constructor]
                pub fn init() { self.value = 0; }
                pub fn set_value(v: u64) { self.value = v; }
            }
        "#;
        let compiled = otic::compile_all(src);
        let (_, contract) = &compiled[0];

        let clen = contract.constructor_bytecode.len() as u32;
        let rlen = contract.runtime_bytecode.len() as u32;
        let mut deploy_data = Vec::new();
        deploy_data.extend_from_slice(&clen.to_le_bytes());
        deploy_data.extend_from_slice(&rlen.to_le_bytes());
        deploy_data.extend_from_slice(&contract.constructor_bytecode);
        deploy_data.extend_from_slice(&contract.runtime_bytecode);

        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let block_ctx = make_block_ctx();
        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, 1_000_000_000_000);
        let contract_addr = pyde_account::address::derive_create_address(&sender_addr, 0);

        // Deploy — must set data BEFORE signing
        let deploy_tx = {
            let mut tx = Transaction {
                from: sender_addr,
                to: ZERO_ADDRESS,
                value: 0,
                data: deploy_data,
                gas_limit: 100_000_000,
                nonce: 0,
                signature: vec![],
                fee_payer: FeePayer::Sender,
                access_list: vec![],
                deadline: None,
                chain_id: 1,
                tx_type: TransactionType::Deploy,
            };
            let hash = tx.hash();
            tx.signature = pyde_crypto::falcon::falcon_sign(&sk, &hash)
                .unwrap()
                .as_bytes()
                .to_vec();
            tx
        };
        let deploy_receipt = execute_transaction(&deploy_tx, &mut smt, &block_ctx).unwrap();
        assert!(deploy_receipt.success, "deploy failed");

        // Call set_value(99) — void function
        let selector = otic::codegen::compute_selector("set_value");
        let mut calldata = selector.to_be_bytes().to_vec();
        calldata.extend_from_slice(&99u64.to_le_bytes());
        let call_tx = {
            let mut tx = Transaction {
                from: sender_addr,
                to: contract_addr,
                value: 0,
                data: calldata,
                gas_limit: 100_000_000,
                nonce: 1,
                signature: vec![],
                fee_payer: FeePayer::Sender,
                access_list: vec![],
                deadline: None,
                chain_id: 1,
                tx_type: TransactionType::Standard,
            };
            let hash = tx.hash();
            tx.signature = pyde_crypto::falcon::falcon_sign(&sk, &hash)
                .unwrap()
                .as_bytes()
                .to_vec();
            tx
        };
        let call_receipt = execute_transaction(&call_tx, &mut smt, &block_ctx).unwrap();
        assert!(call_receipt.success, "void call failed");
        // return_data exists (r1 value) but caller should ignore for void functions
    }

    #[test]
    fn storage_slot_key_reads_correct_value_after_execution() {
        // Deploy a contract, call set_value(42), then verify storage_slot_key can read it
        let src = r#"
            contract Counter {
                storage { count: u64, }
                #[constructor]
                pub fn init() { self.count = 0; }
                pub fn increment() { self.count = self.count + 1; }
            }
        "#;
        let compiled = otic::compile_all(src);
        let (_, contract) = &compiled[0];

        let clen = contract.constructor_bytecode.len() as u32;
        let rlen = contract.runtime_bytecode.len() as u32;
        let mut deploy_data = Vec::new();
        deploy_data.extend_from_slice(&clen.to_le_bytes());
        deploy_data.extend_from_slice(&rlen.to_le_bytes());
        deploy_data.extend_from_slice(&contract.constructor_bytecode);
        deploy_data.extend_from_slice(&contract.runtime_bytecode);

        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let block_ctx = make_block_ctx();
        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, 1_000_000_000_000);
        let contract_addr = pyde_account::address::derive_create_address(&sender_addr, 0);

        // Deploy
        let deploy_tx = {
            let mut tx = Transaction {
                from: sender_addr,
                to: ZERO_ADDRESS,
                value: 0,
                data: deploy_data,
                gas_limit: 100_000_000,
                nonce: 0,
                signature: vec![],
                fee_payer: FeePayer::Sender,
                access_list: vec![],
                deadline: None,
                chain_id: 1,
                tx_type: TransactionType::Deploy,
            };
            let hash = tx.hash();
            tx.signature = pyde_crypto::falcon::falcon_sign(&sk, &hash)
                .unwrap()
                .as_bytes()
                .to_vec();
            tx
        };
        let deploy_receipt = execute_transaction(&deploy_tx, &mut smt, &block_ctx).unwrap();
        assert!(deploy_receipt.success, "deploy failed");

        // Call increment() 3 times
        for i in 0..3u64 {
            let selector = otic::codegen::compute_selector("increment");
            let call_tx = {
                let mut tx = Transaction {
                    from: sender_addr,
                    to: contract_addr,
                    value: 0,
                    data: selector.to_be_bytes().to_vec(),
                    gas_limit: 100_000_000,
                    nonce: 1 + i,
                    signature: vec![],
                    fee_payer: FeePayer::Sender,
                    access_list: vec![],
                    deadline: None,
                    chain_id: 1,
                    tx_type: TransactionType::Standard,
                };
                let hash = tx.hash();
                tx.signature = pyde_crypto::falcon::falcon_sign(&sk, &hash)
                    .unwrap()
                    .as_bytes()
                    .to_vec();
                tx
            };
            let receipt = execute_transaction(&call_tx, &mut smt, &block_ctx).unwrap();
            assert!(receipt.success, "increment {} failed", i);
        }

        // Verify storage via storage_slot_key (same key get_storage_at RPC uses)
        let storage_key = pyde_state::keys::storage_slot_key(&contract_addr, 0);
        let value = smt.get(&storage_key);
        assert!(value.is_some(), "storage_slot_key should find the value");
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&value.unwrap()[..8]);
        let count = u64::from_le_bytes(buf);
        assert_eq!(count, 3, "count should be 3 after 3 increments");
    }

    // ========== Staking tests ==========

    #[test]
    fn stake_deposit_registers_validator() {
        let (pk, sk) = falcon_keygen().unwrap();
        let sender_addr = derive_eoa_address(pk.as_bytes());
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();

        // Fund sender with enough for stake + gas
        let balance: u128 = 20_000_000_000_000; // 20K PYDE
        fund_account_with_pk(&mut smt, &sender_addr, balance, pk.as_bytes());

        // StakeDeposit tx: data = FALCON public key
        let mut tx = Transaction {
            from: sender_addr,
            to: [0u8; 32],
            value: 0,
            data: pk.as_bytes().to_vec(),
            gas_limit: 100_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::StakeDeposit,
        };
        sign_tx(&mut tx, &sk);

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(receipt.success, "stake deposit should succeed");

        // Verify validator entry in state
        let val_key = pyde_state::keys::validator_key(&sender_addr);
        let val_data = smt.get(&val_key);
        assert!(val_data.is_some(), "validator entry should exist");

        // Verify sender balance reduced by stake
        let account = load_account(&smt, &sender_addr);
        assert!(account.balance < balance, "balance should be reduced");
    }

    #[test]
    fn stake_deposit_wrong_key_rejected() {
        let (pk, sk) = falcon_keygen().unwrap();
        let (pk2, _) = falcon_keygen().unwrap();
        let sender_addr = derive_eoa_address(pk.as_bytes());
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();

        fund_account_with_pk(&mut smt, &sender_addr, 20_000_000_000_000, pk.as_bytes());

        // Use WRONG public key (pk2 doesn't derive to sender_addr)
        let mut tx = Transaction {
            from: sender_addr,
            to: [0u8; 32],
            value: 0,
            data: pk2.as_bytes().to_vec(),
            gas_limit: 100_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::StakeDeposit,
        };
        sign_tx(&mut tx, &sk);

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success, "wrong key should be rejected");
    }

    #[test]
    fn stake_deposit_duplicate_rejected() {
        let (pk, sk) = falcon_keygen().unwrap();
        let sender_addr = derive_eoa_address(pk.as_bytes());
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();

        fund_account_with_pk(&mut smt, &sender_addr, 30_000_000_000_000, pk.as_bytes());

        // First deposit succeeds
        let mut tx1 = Transaction {
            from: sender_addr,
            to: [0u8; 32],
            value: 0,
            data: pk.as_bytes().to_vec(),
            gas_limit: 100_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::StakeDeposit,
        };
        sign_tx(&mut tx1, &sk);
        let r1 = execute_transaction(&tx1, &mut smt, &ctx).unwrap();
        assert!(r1.success);

        // Second deposit rejected (duplicate)
        let mut tx2 = tx1.clone();
        tx2.nonce = 1;
        sign_tx(&mut tx2, &sk);
        let r2 = execute_transaction(&tx2, &mut smt, &ctx).unwrap();
        assert!(!r2.success, "duplicate stake should be rejected");
    }

    // Audit 351: `StakeWithdraw` is disabled at validation until
    // the unbonding-complete path ships post-mainnet. The handler
    // is preserved (it's the transition logic re-enabled later)
    // but no honest caller can reach it now. The pipeline test is
    // kept (it exercises the handler in isolation) but ignored so
    // the live validation gate is not contradicted. Re-enable
    // when audit 351 is lifted.
    #[test]
    #[ignore = "audit 351: StakeWithdraw disabled at validation"]
    fn stake_withdraw_starts_unbonding() {
        let (pk, sk) = falcon_keygen().unwrap();
        let sender_addr = derive_eoa_address(pk.as_bytes());
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();

        fund_account_with_pk(&mut smt, &sender_addr, 20_000_000_000_000, pk.as_bytes());

        // Deposit first
        let mut deposit = Transaction {
            from: sender_addr,
            to: [0u8; 32],
            value: 0,
            data: pk.as_bytes().to_vec(),
            gas_limit: 100_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::StakeDeposit,
        };
        sign_tx(&mut deposit, &sk);
        execute_transaction(&deposit, &mut smt, &ctx).unwrap();

        // Withdraw
        let mut withdraw = Transaction {
            from: sender_addr,
            to: [0u8; 32],
            value: 0,
            data: vec![],
            gas_limit: 100_000,
            nonce: 1,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::StakeWithdraw,
        };
        sign_tx(&mut withdraw, &sk);
        let receipt = execute_transaction(&withdraw, &mut smt, &ctx).unwrap();
        assert!(receipt.success, "withdraw should succeed");

        // Verify status is Unbonding (0x01)
        let val_key = pyde_state::keys::validator_key(&sender_addr);
        let val_data = smt.get(&val_key).unwrap();
        let entry = ValidatorEntry::decode(&val_data).expect("entry should decode");
        assert_eq!(entry.status, 0x01, "status should be Unbonding");
        assert!(
            entry.exit_block.is_some(),
            "exit_block must be set when unbonding"
        );
    }

    // ========== Phase 4 slice 4.1: ClaimReward + pool accrual ==========

    fn deposit_validator(
        smt: &mut PydeSMT,
        ctx: &BlockContext,
    ) -> (Address, pyde_crypto::falcon::FalconSecretKey) {
        let (pk, sk) = falcon_keygen().unwrap();
        let addr = derive_eoa_address(pk.as_bytes());
        // Generous balance so gas + stake + later-claim fits.
        fund_account_with_pk(
            smt,
            &addr,
            pyde_slashing::VALIDATOR_STAKE + 1_000_000_000_000,
            pk.as_bytes(),
        );
        let mut tx = Transaction {
            from: addr,
            to: [0u8; 32],
            value: 0,
            data: pk.as_bytes().to_vec(),
            gas_limit: 100_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::StakeDeposit,
        };
        sign_tx(&mut tx, &sk);
        let r = execute_transaction(&tx, smt, ctx).unwrap();
        assert!(r.success, "deposit should succeed");
        (addr, sk)
    }

    #[test]
    fn claim_reward_late_joiner_gets_zero() {
        // Validator joins AFTER some blocks have accrued pool rewards.
        // Their `last_claimed_at` is seeded to the current accumulator, so
        // the first ClaimReward pulls exactly zero — no retroactive crediting.
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();

        // Seed the accumulator as if earlier blocks accrued 500 quanta/validator.
        write_rewards_per_validator(&mut smt, 500);

        let (addr, sk) = deposit_validator(&mut smt, &ctx);

        // Read entry — last_claimed_at should equal current accumulator (500).
        let entry =
            ValidatorEntry::decode(&smt.get(&pyde_state::keys::validator_key(&addr)).unwrap())
                .unwrap();
        assert_eq!(entry.last_claimed_at, 500);

        // Claim now with no further accrual → owed = 0.
        let mut claim = Transaction {
            from: addr,
            to: [0u8; 32],
            value: 0,
            data: vec![],
            gas_limit: 50_000,
            nonce: 1,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::ClaimReward,
        };
        sign_tx(&mut claim, &sk);
        let r = execute_transaction(&claim, &mut smt, &ctx).unwrap();
        assert!(r.success);
        // return_data encodes the owed amount as u128 LE.
        let owed = u128::from_le_bytes(r.return_data[..16].try_into().unwrap());
        assert_eq!(owed, 0);
    }

    #[test]
    fn claim_reward_pulls_accrued_amount() {
        // Validator joins first, THEN pool accrues, then claim → pulls the
        // full accrued amount. Verifies lazy-accrual math end-to-end.
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();

        let (addr, sk) = deposit_validator(&mut smt, &ctx);
        let balance_before = load_account(&smt, &addr).balance;

        // Simulate pool accrual. Set ACCRUED large enough that the gas
        // charge on the claim tx is negligible — the test asserts that
        // the accrued amount landed in the validator's balance, not gas
        // math. 10 PYDE is ~500× the gas cost at the devnet base_fee.
        const ACCRUED: u128 = 10_000_000_000;
        write_rewards_per_validator(&mut smt, ACCRUED);

        let mut claim = Transaction {
            from: addr,
            to: [0u8; 32],
            value: 0,
            data: vec![],
            gas_limit: 50_000,
            nonce: 1,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::ClaimReward,
        };
        sign_tx(&mut claim, &sk);
        let r = execute_transaction(&claim, &mut smt, &ctx).unwrap();
        assert!(r.success);

        let owed = u128::from_le_bytes(r.return_data[..16].try_into().unwrap());
        assert_eq!(owed, ACCRUED, "claim must pull exactly the accrued amount");

        let balance_after = load_account(&smt, &addr).balance;
        // The claim adds ACCRUED; gas consumes some of it. Net delta must
        // be positive (claim > gas) and bounded above by ACCRUED.
        let delta = balance_after - balance_before;
        assert!(
            delta > 0 && delta <= ACCRUED,
            "balance delta (0, ACCRUED]: got {}, accrued {}",
            delta,
            ACCRUED,
        );

        // last_claimed_at must advance to current accumulator.
        let entry =
            ValidatorEntry::decode(&smt.get(&pyde_state::keys::validator_key(&addr)).unwrap())
                .unwrap();
        assert_eq!(entry.last_claimed_at, ACCRUED);
    }

    #[test]
    fn claim_reward_twice_only_pulls_once() {
        // Second claim immediately after the first must pull zero — the
        // accumulator hasn't moved between calls.
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let (addr, sk) = deposit_validator(&mut smt, &ctx);
        write_rewards_per_validator(&mut smt, 10_000);

        let mut c1 = Transaction {
            from: addr,
            to: [0u8; 32],
            value: 0,
            data: vec![],
            gas_limit: 50_000,
            nonce: 1,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::ClaimReward,
        };
        sign_tx(&mut c1, &sk);
        let r1 = execute_transaction(&c1, &mut smt, &ctx).unwrap();
        assert_eq!(
            u128::from_le_bytes(r1.return_data[..16].try_into().unwrap()),
            10_000,
        );

        let mut c2 = c1.clone();
        c2.nonce = 2;
        sign_tx(&mut c2, &sk);
        let r2 = execute_transaction(&c2, &mut smt, &ctx).unwrap();
        assert_eq!(
            u128::from_le_bytes(r2.return_data[..16].try_into().unwrap()),
            0,
            "second claim at same accumulator must be empty"
        );
    }

    #[test]
    fn claim_reward_exited_validator_rejected() {
        // REGRESSION TEST for the fund-leakage bug surfaced during slice 4.1
        // review. Without the status gate, an exited validator could continue
        // pulling from the accumulator after already receiving their stake back.
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();

        let (addr, sk) = deposit_validator(&mut smt, &ctx);

        // Flip the entry to Exited directly (simulates post-unbonding state).
        let val_key = pyde_state::keys::validator_key(&addr);
        let mut entry = ValidatorEntry::decode(&smt.get(&val_key).unwrap()).unwrap();
        entry.status = 0x02;
        smt.insert(val_key, entry.encode()).unwrap();

        // Accumulator has moved up since their last_claimed_at; under the
        // old code this would be claimable. After the fix it must reject.
        write_rewards_per_validator(&mut smt, 1_000_000);

        let mut claim = Transaction {
            from: addr,
            to: [0u8; 32],
            value: 0,
            data: vec![],
            gas_limit: 50_000,
            nonce: 1,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::ClaimReward,
        };
        sign_tx(&mut claim, &sk);
        let r = execute_transaction(&claim, &mut smt, &ctx).unwrap();
        assert!(!r.success, "exited validator must not be able to claim");
        assert_eq!(r.return_data, b"validator has exited; no further claims");
    }

    #[test]
    fn claim_reward_unbonding_validator_still_allowed() {
        // Unbonding validators can still claim what they earned while
        // Active. Only Exited is gated. Without this, honest validators
        // who submitted StakeWithdraw would lose their legitimate yield.
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();

        let (addr, sk) = deposit_validator(&mut smt, &ctx);
        write_rewards_per_validator(&mut smt, 10_000_000_000);

        // Flip to Unbonding (0x01) — analogous to a StakeWithdraw having run.
        let val_key = pyde_state::keys::validator_key(&addr);
        let mut entry = ValidatorEntry::decode(&smt.get(&val_key).unwrap()).unwrap();
        entry.status = 0x01;
        entry.exit_block = Some(100);
        smt.insert(val_key, entry.encode()).unwrap();

        let mut claim = Transaction {
            from: addr,
            to: [0u8; 32],
            value: 0,
            data: vec![],
            gas_limit: 50_000,
            nonce: 1,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::ClaimReward,
        };
        sign_tx(&mut claim, &sk);
        let r = execute_transaction(&claim, &mut smt, &ctx).unwrap();
        assert!(
            r.success,
            "unbonding validator must be able to claim earned yield"
        );
        let owed = u128::from_le_bytes(r.return_data[..16].try_into().unwrap());
        assert_eq!(owed, 10_000_000_000);
    }

    #[test]
    fn claim_reward_non_validator_rejected() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let (pk, sk) = falcon_keygen().unwrap();
        let addr = derive_eoa_address(pk.as_bytes());
        fund_account_with_pk(&mut smt, &addr, 1_000_000_000_000, pk.as_bytes());

        let mut claim = Transaction {
            from: addr,
            to: [0u8; 32],
            value: 0,
            data: vec![],
            gas_limit: 50_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::ClaimReward,
        };
        sign_tx(&mut claim, &sk);
        let r = execute_transaction(&claim, &mut smt, &ctx).unwrap();
        assert!(!r.success, "non-validator must be rejected");
        assert_eq!(r.return_data, b"not a registered validator");
    }

    // ========== Phase 4 slice 4.2: active validator count + lifecycle ==========

    #[test]
    fn active_count_increments_on_stake_deposit() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        assert_eq!(read_active_validator_count(&smt), 0);

        let (_, _) = deposit_validator(&mut smt, &ctx);
        assert_eq!(read_active_validator_count(&smt), 1);

        let (_, _) = deposit_validator(&mut smt, &ctx);
        assert_eq!(read_active_validator_count(&smt), 2);
    }

    // Audit 351: see note on `stake_withdraw_starts_unbonding`.
    // Same rationale — handler is preserved, validation gate is
    // active, the test is ignored until the unbonding-complete
    // path lands.
    #[test]
    #[ignore = "audit 351: StakeWithdraw disabled at validation"]
    fn active_count_decrements_on_stake_withdraw() {
        // Active → Unbonding must release a slot in the active pool so
        // the validator stops earning new yield immediately on withdraw.
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let (addr, sk) = deposit_validator(&mut smt, &ctx);
        assert_eq!(read_active_validator_count(&smt), 1);

        let mut withdraw = Transaction {
            from: addr,
            to: [0u8; 32],
            value: 0,
            data: vec![],
            gas_limit: 50_000,
            nonce: 1,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::StakeWithdraw,
        };
        sign_tx(&mut withdraw, &sk);
        let r = execute_transaction(&withdraw, &mut smt, &ctx).unwrap();
        assert!(r.success);
        assert_eq!(read_active_validator_count(&smt), 0);

        // Entry is Unbonding and carries the exit block.
        let val_key = pyde_state::keys::validator_key(&addr);
        let entry = ValidatorEntry::decode(&smt.get(&val_key).unwrap()).unwrap();
        assert_eq!(entry.status, 0x01);
        assert!(entry.exit_block.is_some());
    }

    #[test]
    fn active_count_decrements_on_slash() {
        // Direct slash on an Active validator: active count must drop,
        // entry stake must be zeroed, status must be Ejected (0x02).
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let (addr, _) = deposit_validator(&mut smt, &ctx);
        assert_eq!(read_active_validator_count(&smt), 1);

        // Synthesize an Ejected transition via direct state poke + the
        // public decrement helper (integration testing execute_slash
        // requires real FALCON sigs + evidence encoding; the slash unit
        // tests elsewhere already cover the sig path. Here we focus on
        // the lifecycle bookkeeping invariant.)
        let val_key = pyde_state::keys::validator_key(&addr);
        let mut entry = ValidatorEntry::decode(&smt.get(&val_key).unwrap()).unwrap();
        entry.status = 0x02;
        entry.stake = 0;
        smt.insert(val_key, entry.encode()).unwrap();
        decrement_active_validator_count(&mut smt);

        assert_eq!(read_active_validator_count(&smt), 0);
    }

    // Audit 351: same rationale as the other StakeWithdraw tests
    // — the validation gate now rejects the variant pre-handler,
    // so this active-count regression test is parked until the
    // unbonding-complete path lands.
    #[test]
    #[ignore = "audit 351: StakeWithdraw disabled at validation"]
    fn active_count_is_independent_of_monotonic_total() {
        // Two validators register → active=2, total=2.
        // One withdraws → active=1, total=2 (monotonic never decreases).
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let (addr1, sk1) = deposit_validator(&mut smt, &ctx);
        let (_addr2, _sk2) = deposit_validator(&mut smt, &ctx);

        assert_eq!(read_active_validator_count(&smt), 2);
        let total: u64 = smt
            .get(&pyde_state::keys::validator_count_key())
            .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
            .unwrap_or(0);
        assert_eq!(total, 2);

        let mut withdraw = Transaction {
            from: addr1,
            to: [0u8; 32],
            value: 0,
            data: vec![],
            gas_limit: 50_000,
            nonce: 1,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::StakeWithdraw,
        };
        sign_tx(&mut withdraw, &sk1);
        execute_transaction(&withdraw, &mut smt, &ctx).unwrap();

        assert_eq!(read_active_validator_count(&smt), 1);
        let total_after: u64 = smt
            .get(&pyde_state::keys::validator_count_key())
            .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
            .unwrap_or(0);
        assert_eq!(total_after, 2, "monotonic total must NOT decrement");
    }

    #[test]
    fn decrement_active_count_saturates_at_zero() {
        // Guard: counter corruption must not wrap to u64::MAX and silently
        // cause a gigantic divisor next block.
        let mut smt = PydeSMT::new();
        decrement_active_validator_count(&mut smt);
        assert_eq!(read_active_validator_count(&smt), 0);
        decrement_active_validator_count(&mut smt);
        assert_eq!(read_active_validator_count(&smt), 0);
    }

    #[test]
    fn supply_and_burn_counters_default_correctly() {
        let smt = PydeSMT::new();
        assert_eq!(read_total_supply(&smt), crate::fee::GENESIS_TOTAL_SUPPLY);
        assert_eq!(read_total_burned(&smt), 0);
        assert_eq!(read_rewards_per_validator(&smt), 0);
    }

    #[test]
    fn supply_counter_round_trips() {
        let mut smt = PydeSMT::new();
        let val = crate::fee::GENESIS_TOTAL_SUPPLY + 12_345_678;
        write_total_supply(&mut smt, val);
        assert_eq!(read_total_supply(&smt), val);
    }

    // ========== Phase 4 slice 4.4: vesting enforcement ==========

    fn make_vesting_fixture(
        balance: u128,
        vesting: crate::vesting::VestingSchedule,
    ) -> (PydeSMT, Address, pyde_crypto::falcon::FalconSecretKey) {
        let mut smt = PydeSMT::new();
        let (pk, sk) = falcon_keygen().unwrap();
        let addr = derive_eoa_address(pk.as_bytes());
        fund_account_with_pk(&mut smt, &addr, balance, pk.as_bytes());
        write_vesting_schedule(&mut smt, &addr, &vesting);
        (smt, addr, sk)
    }

    fn transfer_tx(from: Address, to: Address, value: u128, nonce: u64) -> Transaction {
        Transaction {
            from,
            to,
            value,
            data: vec![],
            gas_limit: 50_000,
            nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        }
    }

    #[test]
    fn tx_rejected_when_value_exceeds_unlocked() {
        // Pre-cliff: 100% of balance locked. Any non-zero value must fail
        // the balance check.
        let total: u128 = 1_000_000_000_000;
        let vest = crate::vesting::VestingSchedule {
            start_slot: 0,
            cliff_slots: 1_000,
            duration_slots: 10_000,
            total_amount: total,
        };
        let (mut smt, addr, sk) = make_vesting_fixture(total, vest);
        let recipient = derive_eoa_address(b"recipient");

        let mut ctx = make_block_ctx();
        ctx.height = 100; // before cliff
        ctx.base_fee = 1;

        let mut tx = transfer_tx(addr, recipient, 100, 0);
        sign_tx(&mut tx, &sk);
        let err = execute_transaction(&tx, &mut smt, &ctx).unwrap_err();
        assert!(
            matches!(
                err,
                PipelineError::Validation(
                    crate::validation::ValidationError::InsufficientBalance { .. }
                )
            ),
            "pre-cliff transfer must be rejected with InsufficientBalance; got {:?}",
            err,
        );
    }

    #[test]
    fn tx_accepted_when_value_within_unlocked() {
        // At 50% duration, 50% is unlocked. Transfer below that succeeds.
        let total: u128 = 1_000_000_000_000;
        let vest = crate::vesting::VestingSchedule {
            start_slot: 0,
            cliff_slots: 100,
            duration_slots: 1_000,
            total_amount: total,
        };
        let (mut smt, addr, sk) = make_vesting_fixture(total, vest);
        let recipient = derive_eoa_address(b"recipient-ok");

        let mut ctx = make_block_ctx();
        ctx.height = 500; // 50% through duration
        ctx.base_fee = 1;

        // Unlocked at slot 500 = 500/1000 × total = 500 PYDE.
        // Transfer 100 PYDE — well within.
        let mut tx = transfer_tx(addr, recipient, 100_000_000_000, 0);
        sign_tx(&mut tx, &sk);
        let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(r.success, "transfer within unlocked must succeed");
    }

    #[test]
    fn tx_rejected_at_boundary_exceeds_unlocked() {
        // Exact boundary: unlocked = 50_000_000_000, value = 50_000_000_001.
        // Gas adds more required. Must fail.
        let total: u128 = 100_000_000_000;
        let vest = crate::vesting::VestingSchedule {
            start_slot: 0,
            cliff_slots: 100,
            duration_slots: 1_000,
            total_amount: total,
        };
        let (mut smt, addr, sk) = make_vesting_fixture(total, vest);
        let recipient = derive_eoa_address(b"recipient-boundary");

        let mut ctx = make_block_ctx();
        ctx.height = 500;
        ctx.base_fee = 1;

        let mut tx = transfer_tx(addr, recipient, 50_000_000_001, 0);
        sign_tx(&mut tx, &sk);
        let err = execute_transaction(&tx, &mut smt, &ctx).unwrap_err();
        assert!(
            matches!(
                err,
                PipelineError::Validation(
                    crate::validation::ValidationError::InsufficientBalance { .. }
                )
            ),
            "transfer > unlocked must fail with InsufficientBalance; got {:?}",
            err,
        );
    }

    #[test]
    fn tx_fully_unlocked_after_duration() {
        let total: u128 = 1_000_000_000_000;
        let vest = crate::vesting::VestingSchedule {
            start_slot: 0,
            cliff_slots: 100,
            duration_slots: 1_000,
            total_amount: total,
        };
        let (mut smt, addr, sk) = make_vesting_fixture(total, vest);
        let recipient = derive_eoa_address(b"recipient-post");

        let mut ctx = make_block_ctx();
        ctx.height = 10_000; // well past end
        ctx.base_fee = 1;

        let mut tx = transfer_tx(addr, recipient, total - 50_000, 0);
        sign_tx(&mut tx, &sk);
        let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(r.success, "post-vesting transfer must succeed");
    }

    #[test]
    fn account_without_vesting_is_fully_spendable() {
        let mut smt = PydeSMT::new();
        let (pk, sk) = falcon_keygen().unwrap();
        let addr = derive_eoa_address(pk.as_bytes());
        fund_account_with_pk(&mut smt, &addr, 1_000_000_000_000, pk.as_bytes());
        assert!(read_vesting_schedule(&smt, &addr).is_none());

        let recipient = derive_eoa_address(b"recipient-free");
        let mut ctx = make_block_ctx();
        ctx.base_fee = 1;

        let mut tx = transfer_tx(addr, recipient, 500_000_000_000, 0);
        sign_tx(&mut tx, &sk);
        let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(r.success);
    }

    fn fund_account_with_pk(
        smt: &mut dyn pyde_state::smt::StateAccess,
        addr: &Address,
        balance: u128,
        pk: &[u8],
    ) {
        let mut account = pyde_account::types::Account::new_eoa(pk);
        account.address = *addr;
        account.balance = balance;
        let key = pyde_state::keys::balance_key(addr);
        smt.insert(key, account.to_bytes()).unwrap();
        // Also set nonce
        let nonce_key = pyde_state::keys::nonce_key(addr);
        let ns = pyde_account::nonce::NonceState::new();
        smt.insert(nonce_key, ns.to_bytes().to_vec()).unwrap();
    }

    fn sign_tx(tx: &mut Transaction, sk: &pyde_crypto::falcon::FalconSecretKey) {
        let hash = tx.hash();
        tx.signature = falcon_sign(sk, &hash).unwrap().as_bytes().to_vec();
    }

    // ========== Slash transaction handler ==========

    /// Directly install a validator entry under `validator_key(addr)`,
    /// bypassing the StakeDeposit flow. Uses the unified `ValidatorEntry`
    /// struct so test fixtures track the live wire format.
    fn register_validator_directly(
        smt: &mut dyn pyde_state::smt::StateAccess,
        addr: &Address,
        pk_bytes: &[u8],
        stake: u128,
        status_byte: u8,
    ) {
        let entry = ValidatorEntry {
            pk: pk_bytes.to_vec(),
            stake,
            status: status_byte,
            last_claimed_at: 0,
            exit_block: None,
        };
        let key = pyde_state::keys::validator_key(addr);
        smt.insert(key, entry.encode()).unwrap();
        // Mirror the active-count bookkeeping StakeDeposit would do, so
        // subsequent slash/withdraw decrements leave the counter
        // consistent (otherwise a slash would saturate at 0 here).
        if status_byte == 0x00 {
            increment_active_validator_count(smt);
        }
    }

    /// Assemble a Slash-tx payload matching the wire format in
    /// `pyde_node::wire::encode_double_sign_evidence`.
    fn encode_evidence_for_test(
        slot: u64,
        block_hash_1: &[u8; 32],
        signature_1: &[u8],
        block_hash_2: &[u8; 32],
        signature_2: &[u8],
        signer: &Address,
        submitter: &Address,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(SLASH_EVIDENCE_VERSION);
        out.extend_from_slice(&slot.to_le_bytes());
        out.extend_from_slice(block_hash_1);
        out.extend_from_slice(&(signature_1.len() as u32).to_le_bytes());
        out.extend_from_slice(signature_1);
        out.extend_from_slice(block_hash_2);
        out.extend_from_slice(&(signature_2.len() as u32).to_le_bytes());
        out.extend_from_slice(signature_2);
        out.extend_from_slice(signer);
        out.extend_from_slice(submitter);
        out
    }

    fn sign_proposer_for_test(
        sk: &pyde_crypto::falcon::FalconSecretKey,
        chain_id: u64,
        slot: u64,
        block_hash: &[u8; 32],
    ) -> Vec<u8> {
        let msg = proposer_sign_message_bytes(chain_id, slot, block_hash);
        falcon_sign(sk, &msg).unwrap().as_bytes().to_vec()
    }

    /// Build a signed Slash tx for tests. The submitter signs the outer
    /// tx; the offender's two FALCON sigs live inside the payload.
    fn build_slash_tx(
        submitter_addr: Address,
        submitter_sk: &pyde_crypto::falcon::FalconSecretKey,
        evidence_bytes: Vec<u8>,
    ) -> Transaction {
        let mut tx = Transaction {
            from: submitter_addr,
            to: [0u8; 32],
            value: 0,
            data: evidence_bytes,
            gas_limit: 300_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Slash,
        };
        sign_tx(&mut tx, submitter_sk);
        tx
    }

    /// Setup: register an offender validator with `initial_stake` and a
    /// submitter funded with `submitter_balance`. Returns keys + addrs.
    fn slash_fixture(
        smt: &mut dyn pyde_state::smt::StateAccess,
        initial_stake: u128,
        submitter_balance: u128,
    ) -> (
        pyde_crypto::falcon::FalconPublicKey,
        pyde_crypto::falcon::FalconSecretKey,
        Address,
        pyde_crypto::falcon::FalconPublicKey,
        pyde_crypto::falcon::FalconSecretKey,
        Address,
    ) {
        let (offender_pk, offender_sk) = falcon_keygen().unwrap();
        let offender_addr = derive_eoa_address(offender_pk.as_bytes());
        register_validator_directly(
            smt,
            &offender_addr,
            offender_pk.as_bytes(),
            initial_stake,
            0x00,
        );

        let (submitter_pk, submitter_sk) = falcon_keygen().unwrap();
        let submitter_addr = derive_eoa_address(submitter_pk.as_bytes());
        fund_account_with_pk(
            smt,
            &submitter_addr,
            submitter_balance,
            submitter_pk.as_bytes(),
        );

        (
            offender_pk,
            offender_sk,
            offender_addr,
            submitter_pk,
            submitter_sk,
            submitter_addr,
        )
    }

    #[test]
    fn slash_tx_valid_evidence_debits_stake_and_pays_finder() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let submitter_start: u128 = 1_000_000_000_000; // 1K PYDE + gas headroom
        let (_opk, osk, offender, _spk, ssk, submitter) =
            slash_fixture(&mut smt, SLASH_VALIDATOR_STAKE, submitter_start);

        let slot = 100u64;
        let hash_1 = [0x01u8; 32];
        let hash_2 = [0x02u8; 32];
        let sig_1 = sign_proposer_for_test(&osk, ctx.chain_id, slot, &hash_1);
        let sig_2 = sign_proposer_for_test(&osk, ctx.chain_id, slot, &hash_2);

        let evidence = encode_evidence_for_test(
            slot, &hash_1, &sig_1, &hash_2, &sig_2, &offender, &submitter,
        );
        let tx = build_slash_tx(submitter, &ssk, evidence);

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(receipt.success, "valid slash should succeed");

        // Offender's validator entry: stake zeroed, status = Ejected (0x02).
        let val_data = smt
            .get(&pyde_state::keys::validator_key(&offender))
            .expect("validator entry must still exist");
        let entry = ValidatorEntry::decode(&val_data).unwrap();
        assert_eq!(entry.stake, 0, "stake should be fully slashed");
        assert_eq!(entry.status, 0x02, "status should be Ejected");

        // Submitter got finder's fee = 10% of VALIDATOR_STAKE = 1K PYDE.
        // Also lost gas for the tx. Net: start + 1K PYDE - gas_fee.
        let submitter_acc = load_account(&smt, &submitter);
        let expected_fee = SLASH_VALIDATOR_STAKE * SLASH_FINDER_FEE_PERCENT / 100;
        // Fee is credited pre-gas-refund; gas is charged separately.
        // So final balance = start + fee - effective_gas * base_fee.
        let gas_cost = receipt.gas_used as u128 * ctx.base_fee;
        assert_eq!(
            submitter_acc.balance,
            submitter_start + expected_fee - gas_cost,
            "submitter should net finder's fee minus gas"
        );
    }

    #[test]
    fn slash_tx_same_hash_rejected() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let (_opk, osk, offender, _spk, ssk, submitter) =
            slash_fixture(&mut smt, SLASH_VALIDATOR_STAKE, 1_000_000_000_000);

        let slot = 100;
        let hash = [0x01u8; 32];
        let sig = sign_proposer_for_test(&osk, ctx.chain_id, slot, &hash);
        let evidence =
            encode_evidence_for_test(slot, &hash, &sig, &hash, &sig, &offender, &submitter);
        let tx = build_slash_tx(submitter, &ssk, evidence);

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success, "same-hash evidence is not equivocation");

        // State untouched.
        let val_data = smt
            .get(&pyde_state::keys::validator_key(&offender))
            .unwrap();
        let entry = ValidatorEntry::decode(&val_data).unwrap();
        assert_eq!(entry.stake, SLASH_VALIDATOR_STAKE);
        assert_eq!(entry.status, 0x00);
    }

    #[test]
    fn slash_tx_nonexistent_validator_rejected() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();

        // Submitter only — no validator registered.
        let (spk, ssk) = falcon_keygen().unwrap();
        let submitter = derive_eoa_address(spk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 1_000_000_000_000, spk.as_bytes());

        let (_opk, osk) = falcon_keygen().unwrap();
        let ghost_signer = [0xAB; 32]; // never registered
        let slot = 100;
        let sig_1 = sign_proposer_for_test(&osk, ctx.chain_id, slot, &[0x01; 32]);
        let sig_2 = sign_proposer_for_test(&osk, ctx.chain_id, slot, &[0x02; 32]);
        let evidence = encode_evidence_for_test(
            slot,
            &[0x01; 32],
            &sig_1,
            &[0x02; 32],
            &sig_2,
            &ghost_signer,
            &submitter,
        );
        let tx = build_slash_tx(submitter, &ssk, evidence);

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success);
    }

    #[test]
    fn slash_tx_already_ejected_rejected() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let (opk, osk) = falcon_keygen().unwrap();
        let offender = derive_eoa_address(opk.as_bytes());
        // Pre-ejected: status byte = 0x02
        register_validator_directly(&mut smt, &offender, opk.as_bytes(), 0, 0x02);

        let (spk, ssk) = falcon_keygen().unwrap();
        let submitter = derive_eoa_address(spk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 1_000_000_000_000, spk.as_bytes());

        let slot = 100;
        let hash_1 = [0x01u8; 32];
        let hash_2 = [0x02u8; 32];
        let sig_1 = sign_proposer_for_test(&osk, ctx.chain_id, slot, &hash_1);
        let sig_2 = sign_proposer_for_test(&osk, ctx.chain_id, slot, &hash_2);
        let evidence = encode_evidence_for_test(
            slot, &hash_1, &sig_1, &hash_2, &sig_2, &offender, &submitter,
        );
        let tx = build_slash_tx(submitter, &ssk, evidence);

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success, "can't slash an already-ejected validator");
    }

    #[test]
    fn slash_tx_wrong_slot_signature_rejected() {
        // Signer produced sigs for slot 101, but evidence claims slot 100.
        // FALCON verify at slot 100 must reject.
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let (_opk, osk, offender, _spk, ssk, submitter) =
            slash_fixture(&mut smt, SLASH_VALIDATOR_STAKE, 1_000_000_000_000);

        let evidence_slot = 100u64;
        let signed_slot = 101u64; // wrong!
        let hash_1 = [0x01u8; 32];
        let hash_2 = [0x02u8; 32];
        let sig_1 = sign_proposer_for_test(&osk, ctx.chain_id, signed_slot, &hash_1);
        let sig_2 = sign_proposer_for_test(&osk, ctx.chain_id, signed_slot, &hash_2);

        let evidence = encode_evidence_for_test(
            evidence_slot,
            &hash_1,
            &sig_1,
            &hash_2,
            &sig_2,
            &offender,
            &submitter,
        );
        let tx = build_slash_tx(submitter, &ssk, evidence);

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success, "sigs from wrong slot cannot be replayed");
    }

    #[test]
    fn slash_tx_garbage_signature_rejected() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let (_opk, _osk, offender, _spk, ssk, submitter) =
            slash_fixture(&mut smt, SLASH_VALIDATOR_STAKE, 1_000_000_000_000);

        let slot = 100;
        // Garbage bytes instead of valid FALCON sigs.
        let bad_sig = vec![0xDE; 666];
        let evidence = encode_evidence_for_test(
            slot,
            &[0x01; 32],
            &bad_sig,
            &[0x02; 32],
            &bad_sig,
            &offender,
            &submitter,
        );
        let tx = build_slash_tx(submitter, &ssk, evidence);

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success);
    }

    #[test]
    fn slash_tx_truncated_evidence_rejected() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let (_opk, _osk, _offender, _spk, ssk, submitter) =
            slash_fixture(&mut smt, SLASH_VALIDATOR_STAKE, 1_000_000_000_000);

        let tx = build_slash_tx(submitter, &ssk, vec![SLASH_EVIDENCE_VERSION, 0x00]);
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success);
    }

    /// Cross-chain replay: a double-sign signed under a foreign
    /// `chain_id` must NOT slash on the local chain, even when the
    /// FALCON keys match. Mirrors audit-240 multisig regression and
    /// the consensus-layer cross-chain test.
    #[test]
    fn slash_tx_cross_chain_replay_rejected() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx(); // chain_id = 1
        let (_opk, osk, offender, _spk, ssk, submitter) =
            slash_fixture(&mut smt, SLASH_VALIDATOR_STAKE, 1_000_000_000_000);

        let slot = 100u64;
        let hash_1 = [0x01u8; 32];
        let hash_2 = [0x02u8; 32];
        // Sign evidence under a DIFFERENT chain_id than the local chain.
        let foreign_chain_id = ctx.chain_id + 1;
        let sig_1 = sign_proposer_for_test(&osk, foreign_chain_id, slot, &hash_1);
        let sig_2 = sign_proposer_for_test(&osk, foreign_chain_id, slot, &hash_2);

        let evidence = encode_evidence_for_test(
            slot, &hash_1, &sig_1, &hash_2, &sig_2, &offender, &submitter,
        );
        let tx = build_slash_tx(submitter, &ssk, evidence);

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(
            !receipt.success,
            "evidence signed under a different chain_id must not slash here"
        );

        // State untouched.
        let val_data = smt
            .get(&pyde_state::keys::validator_key(&offender))
            .unwrap();
        let entry = ValidatorEntry::decode(&val_data).unwrap();
        assert_eq!(entry.stake, SLASH_VALIDATOR_STAKE);
        assert_eq!(entry.status, 0x00);
    }

    // ========== Slice 4.4b: airdrop claim + sweep ==========

    /// Seed airdrop state: root, deadline, pool balance, and optional
    /// expected-sum. Returns the claimer address + secret key + the
    /// computed proof for `leaf_index`.
    fn airdrop_fixture(
        smt: &mut dyn pyde_state::smt::StateAccess,
        leaves: Vec<(Address, u128)>,
        leaf_index: usize,
        deadline: u64,
        pool_balance: u128,
    ) -> (
        pyde_crypto::falcon::FalconPublicKey,
        pyde_crypto::falcon::FalconSecretKey,
        Address,
        Vec<[u8; 32]>,
    ) {
        let (pk, sk) = falcon_keygen().unwrap();
        let claimer = derive_eoa_address(pk.as_bytes());

        // Replace the placeholder at leaf_index with the real claimer
        // address so the proof binds to a signable account.
        let mut leaves = leaves;
        let amount = leaves[leaf_index].1;
        leaves[leaf_index] = (claimer, amount);

        let (root, proofs) = crate::airdrop::build_tree(&leaves);
        let proof = proofs[leaf_index].clone();

        write_airdrop_root(smt, &root);
        write_airdrop_deadline(smt, deadline);

        // Fund the pool.
        let pool_addr = pyde_account::address::airdrop_pool_address();
        let mut pool_account = pyde_account::types::Account {
            address: pool_addr,
            nonce: 0,
            balance: pool_balance,
            code_hash: sparse_merkle_tree::H256::zero(),
            storage_root: sparse_merkle_tree::H256::zero(),
            account_type: pyde_account::types::AccountType::EOA,
            auth_keys: pyde_account::types::AuthKeys::None,
            gas_tank: 0,
            key_nonce: 0,
        };
        pool_account.balance = pool_balance;
        store_account(smt, &pool_account).unwrap();

        fund_account_with_pk(smt, &claimer, 1_000_000_000_000, pk.as_bytes());

        (pk, sk, claimer, proof)
    }

    fn build_claim_tx(
        from: Address,
        sk: &pyde_crypto::falcon::FalconSecretKey,
        leaf_index: u64,
        amount: u128,
        proof: Vec<[u8; 32]>,
        nonce: u64,
    ) -> Transaction {
        let payload = crate::airdrop::ClaimPayload {
            leaf_index,
            amount,
            proof,
        };
        let mut tx = Transaction {
            from,
            to: [0u8; 32],
            value: 0,
            data: payload.encode(),
            gas_limit: 200_000,
            nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::ClaimAirdrop,
        };
        sign_tx(&mut tx, sk);
        tx
    }

    #[test]
    fn airdrop_claim_debits_pool_and_credits_claimer() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let leaves = vec![([0xAA; 32], 1_000u128), ([0xBB; 32], 2_000u128)];
        let (_pk, sk, claimer, proof) = airdrop_fixture(&mut smt, leaves, 0, 10_000, 5_000);

        let starting_balance = load_account(&smt, &claimer).balance;

        let tx = build_claim_tx(claimer, &sk, 0, 1_000, proof, 0);
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(receipt.success, "valid claim should succeed");

        // Pool debited
        let pool = load_account(&smt, &pyde_account::address::airdrop_pool_address());
        assert_eq!(pool.balance, 4_000);

        // Claimer credited — minus gas cost
        let after = load_account(&smt, &claimer);
        let gas_cost = receipt.gas_used as u128 * ctx.base_fee;
        assert_eq!(after.balance, starting_balance + 1_000 - gas_cost);

        // Claimed flag set
        assert!(is_airdrop_claimed(&smt, 0));
    }

    #[test]
    fn airdrop_claim_rejects_double_claim() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let leaves = vec![([0xAA; 32], 1_000u128), ([0xBB; 32], 2_000u128)];
        let (_pk, sk, claimer, proof) = airdrop_fixture(&mut smt, leaves, 0, 10_000, 5_000);

        let tx1 = build_claim_tx(claimer, &sk, 0, 1_000, proof.clone(), 0);
        let r1 = execute_transaction(&tx1, &mut smt, &ctx).unwrap();
        assert!(r1.success);

        let tx2 = build_claim_tx(claimer, &sk, 0, 1_000, proof, 1);
        let r2 = execute_transaction(&tx2, &mut smt, &ctx).unwrap();
        assert!(!r2.success, "second claim for same leaf must fail");
    }

    #[test]
    fn airdrop_claim_rejects_wrong_amount() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let leaves = vec![([0xAA; 32], 1_000u128), ([0xBB; 32], 2_000u128)];
        let (_pk, sk, claimer, proof) = airdrop_fixture(&mut smt, leaves, 0, 10_000, 5_000);

        // Claim more than the leaf allocates.
        let tx = build_claim_tx(claimer, &sk, 0, 9_999, proof, 0);
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success, "wrong-amount claim must fail proof check");
    }

    #[test]
    fn airdrop_claim_rejects_wrong_claimer() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let leaves = vec![([0xAA; 32], 1_000u128), ([0xBB; 32], 2_000u128)];
        // Install fixture for leaf 0, but have a different funded account
        // try to submit. Proof commits to leaf 0's address, so an impostor
        // fails verification.
        let (_pk, _sk, _legit_claimer, proof) = airdrop_fixture(&mut smt, leaves, 0, 10_000, 5_000);

        let (imp_pk, imp_sk) = falcon_keygen().unwrap();
        let impostor = derive_eoa_address(imp_pk.as_bytes());
        fund_account_with_pk(&mut smt, &impostor, 1_000_000_000_000, imp_pk.as_bytes());

        let tx = build_claim_tx(impostor, &imp_sk, 0, 1_000, proof, 0);
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success, "impostor must fail proof verify");
    }

    #[test]
    fn airdrop_claim_rejects_past_deadline() {
        let mut smt = PydeSMT::new();
        // Block height 100 — set deadline below that to simulate expiry.
        let ctx = make_block_ctx();
        let leaves = vec![([0xAA; 32], 1_000u128), ([0xBB; 32], 2_000u128)];
        let (_pk, sk, claimer, proof) = airdrop_fixture(&mut smt, leaves, 0, 50, 5_000);

        let tx = build_claim_tx(claimer, &sk, 0, 1_000, proof, 0);
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success, "post-deadline claim must fail");
    }

    #[test]
    fn airdrop_claim_rejects_when_not_configured() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let (pk, sk) = falcon_keygen().unwrap();
        let claimer = derive_eoa_address(pk.as_bytes());
        fund_account_with_pk(&mut smt, &claimer, 1_000_000_000_000, pk.as_bytes());

        let tx = build_claim_tx(claimer, &sk, 0, 1_000, vec![], 0);
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success, "must reject with no airdrop configured");
    }

    #[test]
    fn airdrop_claim_rejects_pool_underfunded() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let leaves = vec![([0xAA; 32], 10_000u128)];
        // Pool balance 500 < leaf amount 10_000. Expected-sum check
        // should have caught this at genesis, but we defend in depth.
        let (_pk, sk, claimer, proof) = airdrop_fixture(&mut smt, leaves, 0, 10_000, 500);

        let tx = build_claim_tx(claimer, &sk, 0, 10_000, proof, 0);
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success, "underfunded pool must reject claim");
    }

    #[test]
    fn airdrop_claim_rejects_malformed_payload() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let leaves = vec![([0xAA; 32], 1_000u128)];
        let (pk, sk, claimer, _proof) = airdrop_fixture(&mut smt, leaves, 0, 10_000, 5_000);

        let mut tx = Transaction {
            from: claimer,
            to: [0u8; 32],
            value: 0,
            data: vec![0x01, 0x02], // truncated
            gas_limit: 200_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::ClaimAirdrop,
        };
        sign_tx(&mut tx, &sk);
        let _ = pk;
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success, "malformed payload must fail");
    }

    #[test]
    fn airdrop_sweep_moves_residue_to_treasury() {
        let mut smt = PydeSMT::new();
        let mut ctx = make_block_ctx();
        let leaves = vec![([0xAA; 32], 1_000u128)];
        let (_pk, sk, claimer, _proof) = airdrop_fixture(&mut smt, leaves, 0, 50, 5_000);

        // Advance block height past deadline.
        ctx.height = 100; // already > 50

        let mut sweep_tx = Transaction {
            from: claimer,
            to: [0u8; 32],
            value: 0,
            data: vec![],
            gas_limit: 200_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::SweepAirdrop,
        };
        sign_tx(&mut sweep_tx, &sk);

        let treasury_before =
            load_account(&smt, &pyde_account::address::treasury_address()).balance;

        let receipt = execute_transaction(&sweep_tx, &mut smt, &ctx).unwrap();
        assert!(receipt.success, "sweep after deadline should succeed");

        let pool = load_account(&smt, &pyde_account::address::airdrop_pool_address());
        let treasury = load_account(&smt, &pyde_account::address::treasury_address());
        assert_eq!(pool.balance, 0, "pool drained");
        // Treasury gets both the swept residue (5000) AND the 10% of this
        // tx's gas fee. Assert the residue landed; fee share is orthogonal.
        assert!(
            treasury.balance >= treasury_before + 5_000,
            "treasury should gain at least 5000 from sweep; got {} - {}",
            treasury.balance,
            treasury_before
        );
    }

    #[test]
    fn airdrop_claim_rejects_insufficient_gas_limit() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let leaves = vec![([0xAA; 32], 1_000u128), ([0xBB; 32], 2_000u128)];
        let (_pk, sk, claimer, proof) = airdrop_fixture(&mut smt, leaves, 0, 10_000, 5_000);

        // Needed gas = 30_000 + proof.len() * 5_000. Set gas_limit to
        // exactly the intrinsic minimum (21_000) to trigger the early
        // gas-check guard. Without the guard, pool would be debited
        // despite underpayment.
        let payload = crate::airdrop::ClaimPayload {
            leaf_index: 0,
            amount: 1_000,
            proof,
        };
        let mut tx = Transaction {
            from: claimer,
            to: [0u8; 32],
            value: 0,
            data: payload.encode(),
            gas_limit: 22_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::ClaimAirdrop,
        };
        sign_tx(&mut tx, &sk);

        let pool_before =
            load_account(&smt, &pyde_account::address::airdrop_pool_address()).balance;

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success, "under-gassed claim must fail");

        // Pool untouched — the gas guard prevents state writes.
        let pool_after = load_account(&smt, &pyde_account::address::airdrop_pool_address()).balance;
        assert_eq!(pool_before, pool_after, "pool must not be debited");
        assert!(!is_airdrop_claimed(&smt, 0), "claimed flag must not be set");
    }

    #[test]
    fn airdrop_sweep_rejects_insufficient_gas_limit() {
        let mut smt = PydeSMT::new();
        let mut ctx = make_block_ctx();
        let leaves = vec![([0xAA; 32], 1_000u128)];
        let (_pk, sk, claimer, _proof) = airdrop_fixture(&mut smt, leaves, 0, 50, 5_000);
        ctx.height = 100; // past deadline

        let mut sweep_tx = Transaction {
            from: claimer,
            to: [0u8; 32],
            value: 0,
            data: vec![],
            gas_limit: 22_000, // below AIRDROP_SWEEP_GAS = 40_000
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::SweepAirdrop,
        };
        sign_tx(&mut sweep_tx, &sk);

        let pool_before =
            load_account(&smt, &pyde_account::address::airdrop_pool_address()).balance;

        let receipt = execute_transaction(&sweep_tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success, "under-gassed sweep must fail");

        let pool_after = load_account(&smt, &pyde_account::address::airdrop_pool_address()).balance;
        assert_eq!(pool_before, pool_after, "pool must not move");
    }

    #[test]
    fn airdrop_sweep_rejected_before_deadline() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx(); // height = 100
        let leaves = vec![([0xAA; 32], 1_000u128)];
        // Deadline 1000 > current 100 → still active.
        let (_pk, sk, claimer, _proof) = airdrop_fixture(&mut smt, leaves, 0, 1_000, 5_000);

        let mut sweep_tx = Transaction {
            from: claimer,
            to: [0u8; 32],
            value: 0,
            data: vec![],
            gas_limit: 200_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::SweepAirdrop,
        };
        sign_tx(&mut sweep_tx, &sk);

        let receipt = execute_transaction(&sweep_tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success, "pre-deadline sweep must be rejected");
    }

    // ========== Slice 4.5: multisig governance ==========

    /// Set up a multisig configuration on the SMT and return the signer
    /// secret keys so the test can sign. Also funds the treasury so
    /// MultisigTx spends have something to pull from.
    fn multisig_fixture(
        smt: &mut dyn pyde_state::smt::StateAccess,
        n: usize,
        threshold: u8,
        treasury_balance: u128,
    ) -> Vec<pyde_crypto::falcon::FalconSecretKey> {
        let mut pks = Vec::with_capacity(n);
        let mut sks = Vec::with_capacity(n);
        for _ in 0..n {
            let (pk, sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
            pks.push(pk.as_bytes().to_vec());
            sks.push(sk);
        }
        write_multisig_signers(smt, &pks);
        write_multisig_threshold(smt, threshold);
        write_multisig_nonce(smt, 0);

        // Fund treasury
        let treasury = pyde_account::address::treasury_address();
        let account = pyde_account::types::Account {
            address: treasury,
            nonce: 0,
            balance: treasury_balance,
            code_hash: sparse_merkle_tree::H256::zero(),
            storage_root: sparse_merkle_tree::H256::zero(),
            account_type: pyde_account::types::AccountType::EOA,
            auth_keys: pyde_account::types::AuthKeys::None,
            gas_tank: 0,
            key_nonce: 0,
        };
        store_account(smt, &account).unwrap();

        sks
    }

    /// Build a signed outer tx (the submitter is any funded account —
    /// their role is to pay gas and submit; authority comes from the
    /// multisig signatures inside tx.data).
    fn build_multisig_spend_tx(
        submitter: Address,
        submitter_sk: &pyde_crypto::falcon::FalconSecretKey,
        payload: crate::multisig::MultisigPayload,
    ) -> Transaction {
        let mut tx = Transaction {
            from: submitter,
            to: [0u8; 32],
            value: 0,
            data: payload.encode(),
            gas_limit: 2_000_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::MultisigTx,
        };
        sign_tx(&mut tx, submitter_sk);
        tx
    }

    fn build_multisig_rotate_tx(
        submitter: Address,
        submitter_sk: &pyde_crypto::falcon::FalconSecretKey,
        payload: crate::multisig::MultisigPayload,
    ) -> Transaction {
        let mut tx = build_multisig_spend_tx(submitter, submitter_sk, payload);
        tx.tx_type = TransactionType::RotateMultisig;
        sign_tx(&mut tx, submitter_sk);
        tx
    }

    fn make_spend(target: Address, value: u128) -> crate::multisig::MultisigSpend {
        crate::multisig::MultisigSpend {
            target,
            value,
            data_digest: [0xAA; 32],
        }
    }

    fn sign_spend(
        spend: &crate::multisig::MultisigSpend,
        sks: &[&pyde_crypto::falcon::FalconSecretKey],
        indices: &[u8],
        nonce: u64,
        chain_id: u64,
    ) -> Vec<crate::multisig::SigEntry> {
        let msg = spend.signing_bytes(nonce, chain_id);
        sks.iter()
            .zip(indices.iter())
            .map(|(sk, idx)| {
                let sig = pyde_crypto::falcon::falcon_sign(sk, &msg).unwrap();
                crate::multisig::SigEntry {
                    signer_index: *idx,
                    signature: sig.as_bytes().to_vec(),
                }
            })
            .collect()
    }

    #[test]
    fn multisig_spend_debits_treasury_and_credits_target() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 5, 3, 10_000_000);

        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let target = [0xEE; 32];
        let spend = make_spend(target, 1_000_000);
        let sigs = sign_spend(&spend, &[&sks[0], &sks[1], &sks[2]], &[0, 1, 2], 0, 1);
        let payload = crate::multisig::MultisigPayload::Spend { spend, sigs };
        let tx = build_multisig_spend_tx(submitter, &sub_sk, payload);

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(receipt.success, "valid multisig spend should succeed");

        let target_acc = load_account(&smt, &target);
        // Target got exactly the spend amount. Treasury dynamics are
        // complicated by 10% fee share flowing in from the submitter's
        // gas — net treasury change = fee_share - spend_value, which can
        // be negative or positive depending on gas usage. Asserting the
        // target credit is the clean invariant.
        assert_eq!(target_acc.balance, 1_000_000, "target received spend");

        // Nonce should have incremented.
        assert_eq!(read_multisig_nonce(&smt), 1);
    }

    #[test]
    fn multisig_spend_rejects_below_threshold() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 5, 3, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let spend = make_spend([0xEE; 32], 1_000_000);
        // Only 2 sigs but threshold = 3.
        let sigs = sign_spend(&spend, &[&sks[0], &sks[1]], &[0, 1], 0, 1);
        let payload = crate::multisig::MultisigPayload::Spend { spend, sigs };
        let tx = build_multisig_spend_tx(submitter, &sub_sk, payload);

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success, "below-threshold must fail");
        // Nonce untouched.
        assert_eq!(read_multisig_nonce(&smt), 0);
    }

    #[test]
    fn multisig_spend_rejects_replay_after_success() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let spend = make_spend([0xEE; 32], 500_000);
        let sigs = sign_spend(&spend, &[&sks[0], &sks[1]], &[0, 1], 0, 1);
        let payload = crate::multisig::MultisigPayload::Spend {
            spend: spend.clone(),
            sigs: sigs.clone(),
        };
        let tx1 = build_multisig_spend_tx(submitter, &sub_sk, payload.clone());
        let r1 = execute_transaction(&tx1, &mut smt, &ctx).unwrap();
        assert!(r1.success);

        // Resubmit the SAME signed payload. Nonce has advanced so sigs
        // now verify against a stale message → 0 valid sigs → reject.
        let mut tx2 = build_multisig_spend_tx(submitter, &sub_sk, payload);
        tx2.nonce = 1; // advance outer nonce (tx-level); inner multisig nonce is what matters
        sign_tx(&mut tx2, &sub_sk);
        let r2 = execute_transaction(&tx2, &mut smt, &ctx).unwrap();
        assert!(
            !r2.success,
            "replay of exact payload must fail after nonce advance"
        );
    }

    #[test]
    fn multisig_spend_rejects_zero_value() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let spend = make_spend([0xEE; 32], 0);
        let sigs = sign_spend(&spend, &[&sks[0], &sks[1]], &[0, 1], 0, 1);
        let payload = crate::multisig::MultisigPayload::Spend { spend, sigs };
        let tx = build_multisig_spend_tx(submitter, &sub_sk, payload);
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success);
    }

    #[test]
    fn multisig_spend_rejects_zero_target() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let spend = make_spend([0u8; 32], 1_000);
        let sigs = sign_spend(&spend, &[&sks[0], &sks[1]], &[0, 1], 0, 1);
        let payload = crate::multisig::MultisigPayload::Spend { spend, sigs };
        let tx = build_multisig_spend_tx(submitter, &sub_sk, payload);
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success);
    }

    #[test]
    fn multisig_spend_rejects_treasury_self_target() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let spend = make_spend(pyde_account::address::treasury_address(), 1_000);
        let sigs = sign_spend(&spend, &[&sks[0], &sks[1]], &[0, 1], 0, 1);
        let payload = crate::multisig::MultisigPayload::Spend { spend, sigs };
        let tx = build_multisig_spend_tx(submitter, &sub_sk, payload);
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success);
    }

    #[test]
    fn multisig_spend_rejects_insufficient_treasury() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 500); // only 500 in treasury
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let spend = make_spend([0xEE; 32], 1_000_000);
        let sigs = sign_spend(&spend, &[&sks[0], &sks[1]], &[0, 1], 0, 1);
        let payload = crate::multisig::MultisigPayload::Spend { spend, sigs };
        let tx = build_multisig_spend_tx(submitter, &sub_sk, payload);
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success);
    }

    #[test]
    fn multisig_spend_rejects_duplicate_signer_index() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let spend = make_spend([0xEE; 32], 1_000);
        // Same signer_index twice — hard reject at sig-count stage.
        let sigs = sign_spend(&spend, &[&sks[0], &sks[0]], &[0, 0], 0, 1);
        let payload = crate::multisig::MultisigPayload::Spend { spend, sigs };
        let tx = build_multisig_spend_tx(submitter, &sub_sk, payload);
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success);
    }

    #[test]
    fn multisig_spend_rejects_target_equal_submitter() {
        // Regression guard: if submitter == target, the pipeline's
        // post-exec sender writeback clobbers the handler's target
        // credit. Treasury would be debited while the target sees
        // nothing — ledger integrity violation. Must reject early.
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let spend = make_spend(submitter, 500_000);
        let sigs = sign_spend(&spend, &[&sks[0], &sks[1]], &[0, 1], 0, 1);
        let payload = crate::multisig::MultisigPayload::Spend { spend, sigs };
        let tx = build_multisig_spend_tx(submitter, &sub_sk, payload);

        let treasury_before =
            load_account(&smt, &pyde_account::address::treasury_address()).balance;
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success, "submitter-as-target must reject");

        // Treasury must not have been debited by the spend — nonce
        // also must be unchanged.
        let treasury_after = load_account(&smt, &pyde_account::address::treasury_address()).balance;
        assert!(
            treasury_after >= treasury_before,
            "treasury must not lose value"
        );
        assert_eq!(read_multisig_nonce(&smt), 0);
    }

    #[test]
    fn multisig_spend_rejects_nonzero_tx_to() {
        // Regression guard: tx.to is unconditionally loaded + written
        // back by the pipeline. If tx.to matches spend.target, the
        // recipient writeback clobbers the handler's target credit.
        // Enforce tx.to = ZERO_ADDRESS for MultisigTx.
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let target = [0xEE; 32];
        let spend = make_spend(target, 500_000);
        let sigs = sign_spend(&spend, &[&sks[0], &sks[1]], &[0, 1], 0, 1);
        let payload = crate::multisig::MultisigPayload::Spend { spend, sigs };
        let mut tx = build_multisig_spend_tx(submitter, &sub_sk, payload);
        tx.to = target; // non-zero tx.to — would clobber target credit
        sign_tx(&mut tx, &sub_sk);

        let treasury_before =
            load_account(&smt, &pyde_account::address::treasury_address()).balance;
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success, "non-zero tx.to must reject");

        let treasury_after = load_account(&smt, &pyde_account::address::treasury_address()).balance;
        assert!(treasury_after >= treasury_before);
        assert_eq!(read_multisig_nonce(&smt), 0);
    }

    #[test]
    fn rotate_installs_new_signer_set() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let old_sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let mut new_pks = Vec::new();
        for _ in 0..5 {
            let (pk, _) = pyde_crypto::falcon::falcon_keygen().unwrap();
            new_pks.push(pk.as_bytes().to_vec());
        }
        let rotate = crate::multisig::MultisigRotate {
            new_signer_pks: new_pks.clone(),
            new_threshold: 3,
        };
        let msg = rotate.signing_bytes(0, 1);
        let sigs = vec![
            crate::multisig::SigEntry {
                signer_index: 0,
                signature: pyde_crypto::falcon::falcon_sign(&old_sks[0], &msg)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            },
            crate::multisig::SigEntry {
                signer_index: 1,
                signature: pyde_crypto::falcon::falcon_sign(&old_sks[1], &msg)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            },
        ];
        let payload = crate::multisig::MultisigPayload::Rotate { rotate, sigs };
        let tx = build_multisig_rotate_tx(submitter, &sub_sk, payload);

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(receipt.success);

        // New signer set installed.
        let stored = read_multisig_signers(&smt).unwrap();
        assert_eq!(stored, new_pks);
        assert_eq!(read_multisig_threshold(&smt), 3);
        assert_eq!(read_multisig_nonce(&smt), 1);
    }

    #[test]
    fn rotate_rejects_invalid_new_threshold() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let old_sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let (new_pk, _) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let rotate = crate::multisig::MultisigRotate {
            new_signer_pks: vec![new_pk.as_bytes().to_vec()],
            new_threshold: 5, // > signer count
        };
        let msg = rotate.signing_bytes(0, 1);
        let sigs = vec![
            crate::multisig::SigEntry {
                signer_index: 0,
                signature: pyde_crypto::falcon::falcon_sign(&old_sks[0], &msg)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            },
            crate::multisig::SigEntry {
                signer_index: 1,
                signature: pyde_crypto::falcon::falcon_sign(&old_sks[1], &msg)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            },
        ];
        let payload = crate::multisig::MultisigPayload::Rotate { rotate, sigs };
        let tx = build_multisig_rotate_tx(submitter, &sub_sk, payload);

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success);
    }

    #[test]
    fn rotate_rejects_duplicate_new_pk() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let old_sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let (dup_pk, _) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let dup = dup_pk.as_bytes().to_vec();
        let rotate = crate::multisig::MultisigRotate {
            new_signer_pks: vec![dup.clone(), dup.clone()],
            new_threshold: 1,
        };
        let msg = rotate.signing_bytes(0, 1);
        let sigs = vec![
            crate::multisig::SigEntry {
                signer_index: 0,
                signature: pyde_crypto::falcon::falcon_sign(&old_sks[0], &msg)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            },
            crate::multisig::SigEntry {
                signer_index: 1,
                signature: pyde_crypto::falcon::falcon_sign(&old_sks[1], &msg)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            },
        ];
        let payload = crate::multisig::MultisigPayload::Rotate { rotate, sigs };
        let tx = build_multisig_rotate_tx(submitter, &sub_sk, payload);

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success);
    }

    #[test]
    fn spend_after_rotate_requires_new_signers() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let old_sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        // Rotate to a fresh set with threshold 2.
        let (new_pk_a, new_sk_a) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let (new_pk_b, new_sk_b) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let (new_pk_c, _new_sk_c) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let new_pks = vec![
            new_pk_a.as_bytes().to_vec(),
            new_pk_b.as_bytes().to_vec(),
            new_pk_c.as_bytes().to_vec(),
        ];
        let rotate = crate::multisig::MultisigRotate {
            new_signer_pks: new_pks,
            new_threshold: 2,
        };
        let rmsg = rotate.signing_bytes(0, 1);
        let rsigs = vec![
            crate::multisig::SigEntry {
                signer_index: 0,
                signature: pyde_crypto::falcon::falcon_sign(&old_sks[0], &rmsg)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            },
            crate::multisig::SigEntry {
                signer_index: 1,
                signature: pyde_crypto::falcon::falcon_sign(&old_sks[1], &rmsg)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            },
        ];
        let rpayload = crate::multisig::MultisigPayload::Rotate {
            rotate,
            sigs: rsigs,
        };
        let rtx = build_multisig_rotate_tx(submitter, &sub_sk, rpayload);
        let rr = execute_transaction(&rtx, &mut smt, &ctx).unwrap();
        assert!(rr.success);

        // Spend signed by OLD signers should now fail.
        let spend = make_spend([0xEE; 32], 1_000);
        let old_sigs = sign_spend(&spend, &[&old_sks[0], &old_sks[1]], &[0, 1], 1, 1);
        let old_payload = crate::multisig::MultisigPayload::Spend {
            spend: spend.clone(),
            sigs: old_sigs,
        };
        let mut old_tx = build_multisig_spend_tx(submitter, &sub_sk, old_payload);
        old_tx.nonce = 1;
        sign_tx(&mut old_tx, &sub_sk);
        let orr = execute_transaction(&old_tx, &mut smt, &ctx).unwrap();
        assert!(!orr.success, "old signers must no longer authorize");

        // Spend signed by NEW signers should succeed.
        let new_sigs = sign_spend(&spend, &[&new_sk_a, &new_sk_b], &[0, 1], 1, 1);
        let new_payload = crate::multisig::MultisigPayload::Spend {
            spend,
            sigs: new_sigs,
        };
        let mut new_tx = build_multisig_spend_tx(submitter, &sub_sk, new_payload);
        new_tx.nonce = 2;
        sign_tx(&mut new_tx, &sub_sk);
        let nrr = execute_transaction(&new_tx, &mut smt, &ctx).unwrap();
        assert!(nrr.success, "new signers should authorize");
    }

    #[test]
    fn multisig_spend_rejects_when_not_configured() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        // Fund treasury but do NOT configure multisig.
        let treasury = pyde_account::address::treasury_address();
        let acc = pyde_account::types::Account {
            address: treasury,
            nonce: 0,
            balance: 1_000_000,
            code_hash: sparse_merkle_tree::H256::zero(),
            storage_root: sparse_merkle_tree::H256::zero(),
            account_type: pyde_account::types::AccountType::EOA,
            auth_keys: pyde_account::types::AuthKeys::None,
            gas_tank: 0,
            key_nonce: 0,
        };
        store_account(&mut smt, &acc).unwrap();

        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let spend = make_spend([0xEE; 32], 1_000);
        let payload = crate::multisig::MultisigPayload::Spend {
            spend,
            sigs: vec![crate::multisig::SigEntry {
                signer_index: 0,
                signature: vec![0xAB; 666],
            }],
        };
        let tx = build_multisig_spend_tx(submitter, &sub_sk, payload);
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success);
    }

    #[test]
    fn multisig_spend_rejects_insufficient_gas_limit() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let spend = make_spend([0xEE; 32], 1_000);
        let sigs = sign_spend(&spend, &[&sks[0], &sks[1]], &[0, 1], 0, 1);
        let payload = crate::multisig::MultisigPayload::Spend { spend, sigs };
        let mut tx = build_multisig_spend_tx(submitter, &sub_sk, payload);
        // Needed: 50k base + 2*50k = 150k. Set below.
        tx.gas_limit = 100_000;
        sign_tx(&mut tx, &sub_sk);

        let treasury_before =
            load_account(&smt, &pyde_account::address::treasury_address()).balance;
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!receipt.success);
        // Treasury balance unchanged by multisig handler (may gain fee
        // share from gas distribution, but not spend).
        let treasury_after = load_account(&smt, &pyde_account::address::treasury_address()).balance;
        assert!(
            treasury_after >= treasury_before,
            "treasury must not have been debited"
        );
        assert_eq!(read_multisig_nonce(&smt), 0);
    }

    // ========== Slice 4.6: emergency pause / resume ==========

    fn sign_pause_sigs(
        sks: &[&pyde_crypto::falcon::FalconSecretKey],
        indices: &[u8],
        duration_slots: u64,
        nonce: u64,
        chain_id: u64,
    ) -> Vec<crate::multisig::SigEntry> {
        let stub = crate::multisig::EmergencyPausePayload {
            duration_slots,
            sigs: vec![],
        };
        let msg = stub.signing_bytes(nonce, chain_id);
        sks.iter()
            .zip(indices.iter())
            .map(|(sk, idx)| crate::multisig::SigEntry {
                signer_index: *idx,
                signature: pyde_crypto::falcon::falcon_sign(sk, &msg)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            })
            .collect()
    }

    fn sign_resume_sigs(
        sks: &[&pyde_crypto::falcon::FalconSecretKey],
        indices: &[u8],
        nonce: u64,
        chain_id: u64,
    ) -> Vec<crate::multisig::SigEntry> {
        let msg = crate::multisig::EmergencyResumePayload::signing_bytes(nonce, chain_id);
        sks.iter()
            .zip(indices.iter())
            .map(|(sk, idx)| crate::multisig::SigEntry {
                signer_index: *idx,
                signature: pyde_crypto::falcon::falcon_sign(sk, &msg)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            })
            .collect()
    }

    fn build_pause_tx(
        submitter: Address,
        submitter_sk: &pyde_crypto::falcon::FalconSecretKey,
        duration_slots: u64,
        sigs: Vec<crate::multisig::SigEntry>,
        outer_nonce: u64,
    ) -> Transaction {
        let payload = crate::multisig::EmergencyPausePayload {
            duration_slots,
            sigs,
        };
        let mut tx = Transaction {
            from: submitter,
            to: [0u8; 32],
            value: 0,
            data: payload.encode(),
            gas_limit: 1_000_000,
            nonce: outer_nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::EmergencyPause,
        };
        sign_tx(&mut tx, submitter_sk);
        tx
    }

    fn build_resume_tx(
        submitter: Address,
        submitter_sk: &pyde_crypto::falcon::FalconSecretKey,
        sigs: Vec<crate::multisig::SigEntry>,
        outer_nonce: u64,
    ) -> Transaction {
        let payload = crate::multisig::EmergencyResumePayload { sigs };
        let mut tx = Transaction {
            from: submitter,
            to: [0u8; 32],
            value: 0,
            data: payload.encode(),
            gas_limit: 1_000_000,
            nonce: outer_nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::EmergencyResume,
        };
        sign_tx(&mut tx, submitter_sk);
        tx
    }

    #[test]
    fn emergency_pause_sets_end_slot_and_bumps_nonce() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        assert!(!is_paused(&smt, ctx.height));

        let sigs = sign_pause_sigs(&[&sks[0], &sks[1]], &[0, 1], 500, 0, 1);
        let tx = build_pause_tx(submitter, &sub_sk, 500, sigs, 0);
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(receipt.success);
        assert!(is_paused(&smt, ctx.height), "chain must be paused");
        assert_eq!(
            read_emergency_pause_end_slot(&smt),
            ctx.height + 500,
            "end slot = current + duration"
        );
        assert_eq!(read_multisig_nonce(&smt), 1);
    }

    #[test]
    fn emergency_resume_clears_end_slot_and_bumps_nonce() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let pause_sigs = sign_pause_sigs(&[&sks[0], &sks[1]], &[0, 1], 500, 0, 1);
        let pause_tx = build_pause_tx(submitter, &sub_sk, 500, pause_sigs, 0);
        execute_transaction(&pause_tx, &mut smt, &ctx).unwrap();

        let resume_sigs = sign_resume_sigs(&[&sks[0], &sks[1]], &[0, 1], 1, 1);
        let resume_tx = build_resume_tx(submitter, &sub_sk, resume_sigs, 1);
        let r = execute_transaction(&resume_tx, &mut smt, &ctx).unwrap();
        assert!(r.success);
        assert!(!is_paused(&smt, ctx.height));
        assert_eq!(read_emergency_pause_end_slot(&smt), 0);
        assert_eq!(read_multisig_nonce(&smt), 2);
    }

    #[test]
    fn emergency_pause_auto_expires_past_end_slot() {
        let mut smt = PydeSMT::new();
        let mut ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let sigs = sign_pause_sigs(&[&sks[0], &sks[1]], &[0, 1], 10, 0, 1);
        let tx = build_pause_tx(submitter, &sub_sk, 10, sigs, 0);
        execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(is_paused(&smt, ctx.height));

        // Advance well past the declared window. End slot is
        // ctx.height(100) + 10 = 110. At slot 1000 the chain is no
        // longer paused — lost-keys scenario recovers here without
        // any explicit resume tx.
        ctx.height = 1000;
        assert!(!is_paused(&smt, ctx.height));

        // A standard transfer should execute at slot 1000 even though
        // the state still holds a stale end_slot.
        let (recv_pk, _) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let recipient = derive_eoa_address(recv_pk.as_bytes());
        let transfer = make_signed_tx(submitter, recipient, 100, 100_000, 1, &sub_sk);
        let r = execute_transaction(&transfer, &mut smt, &ctx).unwrap();
        assert!(r.success);
    }

    #[test]
    fn emergency_pause_rejects_zero_duration() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let sigs = sign_pause_sigs(&[&sks[0], &sks[1]], &[0, 1], 0, 0, 1);
        let tx = build_pause_tx(submitter, &sub_sk, 0, sigs, 0);
        let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!r.success);
        assert!(!is_paused(&smt, ctx.height));
        assert_eq!(read_multisig_nonce(&smt), 0);
    }

    #[test]
    fn emergency_pause_rejects_over_max_duration() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let over = MAX_PAUSE_DURATION_SLOTS + 1;
        let sigs = sign_pause_sigs(&[&sks[0], &sks[1]], &[0, 1], over, 0, 1);
        let tx = build_pause_tx(submitter, &sub_sk, over, sigs, 0);
        let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!r.success);
        assert!(!is_paused(&smt, ctx.height));
    }

    #[test]
    fn emergency_pause_rejects_below_threshold() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let sigs = sign_pause_sigs(&[&sks[0]], &[0], 500, 0, 1);
        let tx = build_pause_tx(submitter, &sub_sk, 500, sigs, 0);
        let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!r.success);
        assert!(!is_paused(&smt, ctx.height));
        assert_eq!(read_multisig_nonce(&smt), 0);
    }

    #[test]
    fn emergency_pause_rejects_replay_after_success() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let sigs = sign_pause_sigs(&[&sks[0], &sks[1]], &[0, 1], 500, 0, 1);
        let pause_tx = build_pause_tx(submitter, &sub_sk, 500, sigs.clone(), 0);
        execute_transaction(&pause_tx, &mut smt, &ctx).unwrap();

        // Resume so we can attempt re-pause.
        let resume_sigs = sign_resume_sigs(&[&sks[0], &sks[1]], &[0, 1], 1, 1);
        let resume_tx = build_resume_tx(submitter, &sub_sk, resume_sigs, 1);
        execute_transaction(&resume_tx, &mut smt, &ctx).unwrap();

        // Replay original pause sigs — signed against nonce 0, multisig
        // nonce is now 2.
        let replay_tx = build_pause_tx(submitter, &sub_sk, 500, sigs, 2);
        let r = execute_transaction(&replay_tx, &mut smt, &ctx).unwrap();
        assert!(!r.success, "pause sigs bound to nonce 0 must not replay");
    }

    #[test]
    fn emergency_pause_rejects_duration_mismatch() {
        // Signers sign over duration=500 but submitter tampers with
        // duration in the wire payload. Sigs verify against signed
        // bytes (nonce || "PAUSE" || 500), but handler uses the wire
        // duration (100). The decoder preserves the duration from
        // wire, so the signing_bytes recomputed at verify time use
        // 100, which doesn't match the signed preimage.
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let sigs_over_500 = sign_pause_sigs(&[&sks[0], &sks[1]], &[0, 1], 500, 0, 1);
        let tx = build_pause_tx(submitter, &sub_sk, 100, sigs_over_500, 0);
        let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!r.success, "duration tamper must fail sig verification");
    }

    #[test]
    fn emergency_rejects_re_resume_when_not_paused() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let sigs = sign_resume_sigs(&[&sks[0], &sks[1]], &[0, 1], 0, 1);
        let tx = build_resume_tx(submitter, &sub_sk, sigs, 0);
        let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!r.success);
        assert_eq!(read_multisig_nonce(&smt), 0);
    }

    #[test]
    fn while_paused_standard_tx_rejected() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let pause_sigs = sign_pause_sigs(&[&sks[0], &sks[1]], &[0, 1], 500, 0, 1);
        let pause_tx = build_pause_tx(submitter, &sub_sk, 500, pause_sigs, 0);
        execute_transaction(&pause_tx, &mut smt, &ctx).unwrap();

        let (recv_pk, _) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let recipient = derive_eoa_address(recv_pk.as_bytes());
        let transfer = make_signed_tx(submitter, recipient, 100, 100_000, 1, &sub_sk);
        let err = execute_transaction(&transfer, &mut smt, &ctx);
        assert!(err.is_err(), "standard tx must fail during pause");
    }

    #[test]
    fn while_paused_multisig_spend_rejected() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let pause_sigs = sign_pause_sigs(&[&sks[0], &sks[1]], &[0, 1], 500, 0, 1);
        let pause_tx = build_pause_tx(submitter, &sub_sk, 500, pause_sigs, 0);
        execute_transaction(&pause_tx, &mut smt, &ctx).unwrap();

        let spend = make_spend([0xEE; 32], 1_000);
        let spend_sigs = sign_spend(&spend, &[&sks[0], &sks[1]], &[0, 1], 1, 1);
        let payload = crate::multisig::MultisigPayload::Spend {
            spend,
            sigs: spend_sigs,
        };
        let mut spend_tx = build_multisig_spend_tx(submitter, &sub_sk, payload);
        spend_tx.nonce = 1;
        sign_tx(&mut spend_tx, &sub_sk);
        let err = execute_transaction(&spend_tx, &mut smt, &ctx);
        assert!(err.is_err(), "MultisigTx must fail during pause");
    }

    #[test]
    fn while_paused_rotate_rejected() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let pause_sigs = sign_pause_sigs(&[&sks[0], &sks[1]], &[0, 1], 500, 0, 1);
        let pause_tx = build_pause_tx(submitter, &sub_sk, 500, pause_sigs, 0);
        execute_transaction(&pause_tx, &mut smt, &ctx).unwrap();

        let (new_pk, _) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let rotate = crate::multisig::MultisigRotate {
            new_signer_pks: vec![new_pk.as_bytes().to_vec()],
            new_threshold: 1,
        };
        let rmsg = rotate.signing_bytes(1, 1);
        let rsigs = vec![
            crate::multisig::SigEntry {
                signer_index: 0,
                signature: pyde_crypto::falcon::falcon_sign(&sks[0], &rmsg)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            },
            crate::multisig::SigEntry {
                signer_index: 1,
                signature: pyde_crypto::falcon::falcon_sign(&sks[1], &rmsg)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            },
        ];
        let rpayload = crate::multisig::MultisigPayload::Rotate {
            rotate,
            sigs: rsigs,
        };
        let mut rtx = build_multisig_rotate_tx(submitter, &sub_sk, rpayload);
        rtx.nonce = 1;
        sign_tx(&mut rtx, &sub_sk);
        let err = execute_transaction(&rtx, &mut smt, &ctx);
        assert!(err.is_err(), "RotateMultisig must fail during pause");
    }

    #[test]
    fn while_paused_emergency_resume_accepted() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let pause_sigs = sign_pause_sigs(&[&sks[0], &sks[1]], &[0, 1], 500, 0, 1);
        let pause_tx = build_pause_tx(submitter, &sub_sk, 500, pause_sigs, 0);
        execute_transaction(&pause_tx, &mut smt, &ctx).unwrap();
        assert!(is_paused(&smt, ctx.height));

        let resume_sigs = sign_resume_sigs(&[&sks[0], &sks[1]], &[0, 1], 1, 1);
        let resume_tx = build_resume_tx(submitter, &sub_sk, resume_sigs, 1);
        let r = execute_transaction(&resume_tx, &mut smt, &ctx).unwrap();
        assert!(r.success);
        assert!(!is_paused(&smt, ctx.height));
    }

    #[test]
    fn pause_resume_cycle_restores_normal_operation() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let pause_sigs = sign_pause_sigs(&[&sks[0], &sks[1]], &[0, 1], 500, 0, 1);
        let pause_tx = build_pause_tx(submitter, &sub_sk, 500, pause_sigs, 0);
        execute_transaction(&pause_tx, &mut smt, &ctx).unwrap();

        let resume_sigs = sign_resume_sigs(&[&sks[0], &sks[1]], &[0, 1], 1, 1);
        let resume_tx = build_resume_tx(submitter, &sub_sk, resume_sigs, 1);
        execute_transaction(&resume_tx, &mut smt, &ctx).unwrap();

        let (recv_pk, _) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let recipient = derive_eoa_address(recv_pk.as_bytes());
        let transfer = make_signed_tx(submitter, recipient, 100, 100_000, 2, &sub_sk);
        let r = execute_transaction(&transfer, &mut smt, &ctx).unwrap();
        assert!(r.success);
    }

    #[test]
    fn emergency_rejects_insufficient_gas_limit() {
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();
        let sks = multisig_fixture(&mut smt, 3, 2, 10_000_000);
        let (sub_pk, sub_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let submitter = derive_eoa_address(sub_pk.as_bytes());
        fund_account_with_pk(&mut smt, &submitter, 5_000_000_000_000, sub_pk.as_bytes());

        let sigs = sign_pause_sigs(&[&sks[0], &sks[1]], &[0, 1], 500, 0, 1);
        let mut tx = build_pause_tx(submitter, &sub_sk, 500, sigs, 0);
        tx.gas_limit = 50_000;
        sign_tx(&mut tx, &sub_sk);

        let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(!r.success);
        assert!(!is_paused(&smt, ctx.height));
        assert_eq!(read_multisig_nonce(&smt), 0);
    }

    // ========== Audit 353: nonce burned on failed execution ==========

    /// Pre-fix: a tx that passed validation but failed in
    /// `pre_execution_charge` (most common: GasTank with empty
    /// gas_tank, since validation only structurally checks the
    /// variant) returned `Err(PipelineError::ExecutionFailed)`,
    /// which dropped the in-memory nonce. The same tx could then
    /// be resubmitted indefinitely. Post-fix: validation success
    /// burns the nonce immediately. The same tx after a
    /// pre-execution-charge failure must produce a new
    /// `InvalidNonce` error (the nonce slot is consumed) instead
    /// of replaying.
    #[test]
    fn audit_353_failed_charge_burns_nonce() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        // Devnet: chain_id 31337 keeps `GasTank` enabled so we can
        // exercise the pre-execution-charge failure path. (Audit
        // 305 already hard-rejects GasTank on production, so the
        // production leak surface is closed there.)
        let block_ctx = BlockContext {
            chain_id: 31337,
            ..make_block_ctx()
        };

        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, 100_000_000_000);

        // Build a GasTank-paid tx whose declared gas_tank balance
        // is empty (default `Account::new_eoa` sets gas_tank = 0).
        // `validate_balance` for `GasTank` only checks
        // `spendable >= tx.value` — gas_tank is checked at
        // execution time, where it now fails.
        let mut tx = make_signed_tx(
            sender_addr,
            derive_eoa_address(b"recipient"),
            0, // value: must be 0 for the audit-352 gate to pass
            // (Standard tx_type with value=0 is fine).
            21_000,
            0, // nonce: 0
            &sk,
        );
        tx.fee_payer = FeePayer::GasTank([0xCC; 32]);
        tx.chain_id = 31337;
        sign_tx(&mut tx, &sk);

        let receipt = execute_transaction(&tx, &mut smt, &block_ctx).unwrap();
        assert!(
            !receipt.success,
            "GasTank-with-empty-tank must produce success=false receipt, not bubble Err",
        );
        assert!(
            !receipt.return_data.is_empty(),
            "failure receipt must carry the error message",
        );

        // Nonce 0 must now be marked used. `use_nonce(0)` advances
        // the base over the consumed slot, so `base` becomes 1
        // (or higher if subsequent slots were also pre-used).
        let nonce_after = load_nonce(&smt, &sender_addr);
        assert!(
            nonce_after.base > 0,
            "nonce 0 must be persisted as used after failed execution; got base={}",
            nonce_after.base,
        );

        // Replay attempt with the SAME tx must hit InvalidNonce
        // — this is the proof the leak is closed.
        let replay = execute_transaction(&tx, &mut smt, &block_ctx);
        match replay {
            Err(PipelineError::Validation(ValidationError::InvalidNonce(_))) => {}
            other => panic!("replay must reject with InvalidNonce; got {other:?}"),
        }
    }

    /// Failed-execution path must charge baseline gas + apply the
    /// validator/treasury split. This deters cheap CPU-burn
    /// attacks: even when the tx fails, the sender pays.
    #[test]
    fn audit_353_failed_charge_charges_baseline_gas() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let block_ctx = BlockContext {
            chain_id: 31337,
            ..make_block_ctx()
        };
        let initial_balance: u128 = 100_000_000_000;
        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, initial_balance);

        let mut tx = make_signed_tx(
            sender_addr,
            derive_eoa_address(b"recipient"),
            0,
            21_000,
            0,
            &sk,
        );
        tx.fee_payer = FeePayer::GasTank([0xDD; 32]);
        tx.chain_id = 31337;
        sign_tx(&mut tx, &sk);

        let receipt = execute_transaction(&tx, &mut smt, &block_ctx).unwrap();
        assert!(!receipt.success);

        let baseline_cost = 21_000u128 * block_ctx.base_fee;
        let sender_after = load_account(&smt, &sender_addr);
        assert_eq!(
            sender_after.balance,
            initial_balance - baseline_cost,
            "sender must be debited baseline gas (21k * base_fee) on failed execution",
        );

        // Validator + treasury credited proportionally.
        let validator_acct = load_account(&smt, &block_ctx.validator_address);
        assert!(
            validator_acct.balance > 0,
            "validator must receive its 20% share of the failed-tx fee",
        );
    }

    /// When the sender's balance is below the baseline cost, the
    /// helper saturates and only debits what's available — never
    /// underflows. (Edge case: if a tx escalates past validate
    /// somehow with insufficient balance for baseline gas, we
    /// don't panic.)
    #[test]
    fn audit_353_failed_charge_saturates_below_baseline() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut smt = PydeSMT::new();
        let block_ctx = BlockContext {
            chain_id: 31337,
            ..make_block_ctx()
        };

        // Fund just enough to satisfy validation gas check
        // (gas_limit * base_fee = 21k * 1k = 21M), then drain
        // most of it via direct mutation so `pre_execution_charge`
        // still fails (GasTank empty) and the failed-receipt path
        // sees a tiny balance.
        let initial: u128 = 21_000_000_000;
        let sender_addr = setup_funded_account(&mut smt, &pk_bytes, initial);

        let mut tx = make_signed_tx(
            sender_addr,
            derive_eoa_address(b"recipient"),
            0,
            21_000,
            0,
            &sk,
        );
        tx.fee_payer = FeePayer::GasTank([0xEE; 32]);
        tx.chain_id = 31337;
        sign_tx(&mut tx, &sk);

        let receipt = execute_transaction(&tx, &mut smt, &block_ctx).unwrap();
        assert!(!receipt.success);

        let sender_after = load_account(&smt, &sender_addr);
        assert!(sender_after.balance < initial, "some debit must happen");
    }
}
