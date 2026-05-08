//! Transaction validation: check all preconditions before execution.
//!
//! Validates: signature, nonce window, balance, gas limits, deadline,
//! access list format, and transaction size.

use crate::types::Transaction;
use pyde_account::nonce::NonceState;
use pyde_account::types::Account;

/// Minimum gas limit for any transaction (simple transfer baseline).
pub const MIN_GAS_LIMIT: u64 = 21_000;

/// Maximum transaction size in bytes (wire format).
pub const MAX_TX_SIZE: usize = 128 * 1024; // 128 KB

/// Maximum calldata (tx.data) size in bytes (Phase 5 slice 5.3).
///
/// Separate from `MAX_TX_SIZE` because calldata dominates a tx's
/// size budget. Without a dedicated cap, a malicious tx with a
/// near-`MAX_TX_SIZE` data field (e.g. 120 KB of worthless bytes)
/// still passes validation and burns validator cycles during
/// execution + witness propagation. 64 KB is the standard cap used
/// by comparable EVM-family chains — large enough for legitimate
/// contract-deploy bytecode, small enough to bound DoS surface.
pub const MAX_CALLDATA: usize = 64 * 1024;

/// Block gas limit (target). Elastic blocks can go up to 4x.
pub const BLOCK_GAS_TARGET: u64 = 400_000_000;
pub const BLOCK_GAS_MAX: u64 = 1_600_000_000; // 4x elastic

/// Validation context: block-level info needed for checks.
pub struct ValidationContext {
    /// Current block height.
    pub block_height: u64,
    /// Current base fee (per gas unit, in quanta).
    pub base_fee: u128,
    /// Maximum gas allowed in this block.
    pub block_gas_limit: u64,
    /// Expected chain ID.
    pub chain_id: u64,
    /// When true, FALCON signature verification is skipped. Intended
    /// only for in-process devnet tests that construct transactions
    /// without real FALCON keys. Production must keep this `false`
    /// regardless of `chain_id` — the previous check was "skip sigs
    /// if chain_id == 31337" which let a misconfigured mainnet node
    /// with a devnet chain_id accept forged transactions.
    pub dev_skip_signature: bool,
    /// Sender's currently-locked vesting balance (Phase 4 slice 4.4).
    /// Computed by the caller from the sender's `VestingSchedule`
    /// before validation. Deducted from `sender.balance` when checking
    /// that `gas_cost + value` fits. Zero for accounts with no vesting.
    pub sender_locked: u128,
    /// Caller has already verified this tx's FALCON signature (e.g. in
    /// a parallel batch pass over the whole block). Skipping the
    /// per-tx verify is only safe when the caller guarantees the sig
    /// was actually checked and passed. Unlike `dev_skip_signature`,
    /// this is production-safe when correctly set by the block path.
    pub sig_pre_verified: bool,
}

/// Validation error with specific reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// FALCON signature doesn't match sender's public key.
    InvalidSignature,
    /// Nonce not within sender's nonce window.
    InvalidNonce(String),
    /// Insufficient balance to cover gas + value.
    InsufficientBalance { required: u128, available: u128 },
    /// Gas limit below minimum (21,000).
    GasLimitTooLow { limit: u64, min: u64 },
    /// Gas limit exceeds block gas limit.
    GasLimitTooHigh { limit: u64, max: u64 },
    /// Transaction deadline has passed.
    DeadlineExpired { deadline: u64, current: u64 },
    /// Transaction is too large.
    TxTooLarge { size: usize, max: usize },
    /// Calldata (`tx.data`) exceeds `MAX_CALLDATA` (slice 5.3).
    CalldataTooLarge { size: usize, max: usize },
    /// Access list malformed.
    InvalidAccessList(String),
    /// Wrong chain ID.
    WrongChainId { expected: u64, got: u64 },
    /// Paymaster address is invalid (zero address).
    InvalidPaymaster,
    /// `tx.value != 0` on a tx_type that has no value semantics
    /// (audit 352). Only `Standard` and `Deploy` carry a value
    /// transfer; every other variant (Slash, MultisigTx,
    /// ClaimReward, StakeDeposit, ...) used to silently move
    /// `tx.value` quanta from `tx.from` to `tx.to` because
    /// `transfer_value` ran before the per-type dispatch in
    /// `execute_transaction_inner`. The handlers had no idea this
    /// transfer happened, so a Slash tx with `value = 1_000` would
    /// move 1k PYDE to the offender's address (or anyone else)
    /// alongside the slashing logic — a side-channel transfer the
    /// declared tx type implies nothing about. Now rejected at
    /// validation so the malformed tx never reaches the pipeline.
    UnexpectedValue { tx_type: u8, value: u128 },
    /// `tx.tx_type` is non-`Standard`/non-`Deploy` but `tx.to` is
    /// not `ZERO_ADDRESS` (TPL-408). Pre-fix the pipeline always
    /// called `apply_account_delta(smt, &tx.to, ...)` regardless of
    /// tx_type. For variants that don't carry a destination
    /// (`Slash`, `ClaimReward`, multisig types, etc.), `tx.to` was
    /// effectively unconstrained — a malicious proposer could set
    /// it to any unused address, run the tx, and have the SMT
    /// permanently store an empty `Account` record at that address.
    /// Repeated at scale this fills the trie with junk entries at
    /// only the cost of the per-tx gas (no per-write storage gas
    /// because `apply_account_delta` writes a zero-balance shell).
    /// Now rejected at validation so the malformed tx can't enter
    /// the mempool or land in a block.
    UnexpectedTo { tx_type: u8 },
    /// `tx.tx_type` is currently disabled at the protocol level
    /// (audit 351). `StakeWithdraw` flips a validator entry to
    /// `Unbonding` but there is no `CompleteUnbonding` tx type —
    /// the locked stake is never returned to the operator's
    /// balance. Operators experimenting with the variant lose
    /// `VALIDATOR_STAKE` PYDE silently. Pre-mainnet path is to
    /// hard-reject the variant at validation; post-mainnet we
    /// implement `CompleteUnbonding` (or fold the stake-return
    /// logic into a slot-driven sweep) and lift this gate.
    DisabledTxType(u8),
}

/// Validate a transaction against the sender's account and block context.
/// Returns Ok(()) if all checks pass, or the first error found.
pub fn validate_transaction(
    tx: &Transaction,
    sender: &Account,
    nonce_state: &NonceState,
    ctx: &ValidationContext,
) -> Result<(), ValidationError> {
    // 1. Chain ID
    validate_chain_id(tx, ctx)?;

    // RegisterPubkey (audit 229) takes a separate validation path:
    // no signature, no gas, no balance check, AuthKeys::None is the
    // pre-condition (not a rejection). Routing it here keeps the
    // 226 gate, signature check, and balance check below from
    // tripping on its intentionally-unsigned shape.
    if tx.tx_type == crate::types::TransactionType::RegisterPubkey {
        return validate_register_pubkey(tx, sender, nonce_state);
    }

    // 1.5 Audit 226 — reject AuthKeys::None senders on non-devnet
    // chain_id. `validate_signature` short-circuits FALCON
    // verification when the sender has `AuthKeys::None`, and
    // `pyde_tx::pipeline::load_account` returns a default EOA with
    // `AuthKeys::None` for any address never seen on chain. The gap
    // lets an attacker submit a tx with `from = victim_fresh_address`
    // that bypasses the signature check entirely. Balance gates
    // direct fund-loss but a Paymaster fee_payer slips past balance
    // and the tx pollutes the mempool / can land in a block.
    //
    // Gating here (not just at the RPC ingress in `rpc.rs`) makes the
    // check a defense-in-depth invariant: any caller of
    // `validate_transaction` — RPC, block validation, gossip — sees
    // the same enforcement. Devnet (chain_id == 31337) keeps the
    // relaxed behaviour for the faucet / bootstrap UX.
    if ctx.chain_id != 31337 && matches!(sender.auth_keys, pyde_account::types::AuthKeys::None) {
        return Err(ValidationError::InvalidSignature);
    }

    // 1.6 Audit 304 — reject `AuthKeys::MultiSig` senders on
    // non-devnet chain_id. `validate_signature` currently
    // short-circuits MultiSig with a "// For now, skip" arm —
    // any tx from a MultiSig-keyed account is accepted with no
    // auth check at all. Reachable today only via genesis
    // allocations that pre-set MultiSig (no production tx flow
    // rotates an EOA to MultiSig yet), but the gate ships
    // unenforced so it's a footgun. Mirror the audit-226 None
    // gate: hard-reject on production, devnet keeps the relaxed
    // shape so test infra that exercises the variant still works.
    if ctx.chain_id != 31337
        && matches!(
            sender.auth_keys,
            pyde_account::types::AuthKeys::MultiSig { .. }
        )
    {
        return Err(ValidationError::InvalidSignature);
    }

    // 1.7 Audit 305 — reject `FeePayer::Paymaster` and
    // `FeePayer::GasTank` on non-devnet chain_id. `Paymaster`
    // currently mints fees out of thin air (`pre_execution_charge`
    // returns Ok(0), then post-execution distribution credits
    // validator + treasury anyway). `GasTank` ignores the encoded
    // contract address entirely and silently debits the sender's
    // own per-account gas_tank — the sponsorship UX is decorative.
    // Both paths are unsafe to expose on production until the
    // paymaster contract integration ships and the GasTank wiring
    // honours its address parameter. Devnet keeps both for dev /
    // test ergonomics.
    if ctx.chain_id != 31337 {
        match &tx.fee_payer {
            crate::types::FeePayer::Sender => {}
            crate::types::FeePayer::Paymaster(_) | crate::types::FeePayer::GasTank(_) => {
                return Err(ValidationError::InvalidPaymaster);
            }
        }
    }

    // 1.8 Audit 352 — only `Standard` and `Deploy` carry value
    // semantics. Pre-fix `execute_transaction_inner` ran
    // `transfer_value(sender, recipient, tx.value)` before the
    // per-type dispatch, so a Slash / MultisigTx / ClaimReward /
    // StakeDeposit / etc. with `tx.value > 0` performed an
    // undeclared `tx.from → tx.to` transfer alongside its
    // declared semantics. The shape was unreachable from honest
    // tooling but a hand-crafted tx exploited it as a free
    // side-channel transfer that bypassed all per-type intent
    // analysis (paymaster billing, gas-tank accounting,
    // mempool / explorer summaries, etc.).
    //
    // Reject the malformed input at the earliest gate so the
    // pipeline only ever sees value-bearing txs of types that
    // know what to do with `tx.value`. `RegisterPubkey` is
    // already rejected in its dedicated path (`tx.value == 0` is
    // a hard precondition).
    match tx.tx_type {
        crate::types::TransactionType::Standard | crate::types::TransactionType::Deploy => {}
        _ => {
            if tx.value != 0 {
                return Err(ValidationError::UnexpectedValue {
                    tx_type: tx.tx_type as u8,
                    value: tx.value,
                });
            }
        }
    }

    // TPL-408: same shape as the value gate above for `tx.to`.
    // `Standard` and `Deploy` are the only types whose pipeline
    // semantics actually consume `tx.to`. For every other variant
    // the pipeline still calls `apply_account_delta(smt, &tx.to,
    // ...)` at write-back, which always ends in
    // `store_account` — even when initial == final the SMT gets a
    // fresh `Account` shell at the target address. A malicious
    // proposer (or a loose RPC client) setting `tx.to` to an
    // unused address per non-Standard tx writes one empty record
    // per tx into the trie at no storage-gas cost, growing the
    // SMT and the witness without bound.
    //
    // Reject at validation so the malformed input can't enter
    // the mempool or land in a block. `RegisterPubkey` already
    // routed away above; honest tooling for the gated variants
    // (Slash, ClaimReward, multisig types, …) sets
    // `tx.to = ZERO_ADDRESS`.
    match tx.tx_type {
        crate::types::TransactionType::Standard | crate::types::TransactionType::Deploy => {}
        _ => {
            if tx.to != pyde_account::address::ZERO_ADDRESS {
                return Err(ValidationError::UnexpectedTo {
                    tx_type: tx.tx_type as u8,
                });
            }
        }
    }

    // 1.9 Audit 351 — `StakeWithdraw` is disabled at the protocol
    // level until `CompleteUnbonding` ships. The `StakeWithdraw`
    // handler in `execute_transaction_inner` flips the validator
    // entry to `Unbonding` and records `exit_block`, but no other
    // code path ever returns the locked `VALIDATOR_STAKE` to the
    // operator's balance. Operators who experiment with the
    // variant on testnet would silently lose 10k PYDE — exactly
    // the kind of footgun that erodes trust in the chain.
    //
    // Hard-reject at validation (the earliest gate) so the tx
    // can't enter the mempool and can't land in a block. Lifting
    // this gate is paired with shipping the unbonding-complete
    // path post-mainnet (either as a new tx type or as a
    // slot-driven sweep that re-credits stake once
    // `block_height >= exit_block + UNBONDING_DELAY`).
    if matches!(tx.tx_type, crate::types::TransactionType::StakeWithdraw) {
        return Err(ValidationError::DisabledTxType(tx.tx_type as u8));
    }

    // 2. Signature. Skipping is allowed only when the caller explicitly
    // sets `dev_skip_signature` (test-only) or `sig_pre_verified`
    // (production fast path where the block processor already ran a
    // parallel batch verify). chain_id is NOT consulted here so a
    // misconfigured mainnet validator with chain_id = 31337 cannot
    // accidentally accept forged transactions.
    if !ctx.dev_skip_signature && !ctx.sig_pre_verified {
        validate_signature(tx, sender)?;
    }

    // 3. Nonce
    validate_nonce(tx, nonce_state)?;

    // 4. Balance
    validate_balance(tx, sender, ctx)?;

    // 5. Gas limits
    validate_gas_limit(tx, ctx)?;

    // 6. Deadline
    validate_deadline(tx, ctx)?;

    // 7. Access list
    validate_access_list(tx)?;

    // 8. Size
    validate_size(tx)?;

    Ok(())
}

/// Validate a `TransactionType::RegisterPubkey` (audit 229).
///
/// Rules:
///   - `tx.signature` is empty (the address-derivation check is
///     the proof of pubkey ownership, no FALCON sig needed).
///   - `tx.value == 0`, `tx.gas_limit == 0`: no transfer, no gas.
///   - `tx.data.len() == FALCON_PUBLIC_KEY_LEN` (897 bytes).
///   - `tx.from == Poseidon2(tx.data)`: the address derives from
///     this pubkey, so only the keypair holder can produce it.
///   - `sender.balance > 0`: account must have been funded already.
///     Without this, an attacker can spam-register from millions of
///     locally-generated keypairs and bloat state without spending
///     anything.
///   - `sender.auth_keys == AuthKeys::None`: one-time registration.
///     Re-registration (or upgrading auth) goes through
///     `pyde_account::auth::rotate` with a current-key signature.
///   - Nonce check still applies — `tx.nonce` must be valid.
fn validate_register_pubkey(
    tx: &Transaction,
    sender: &Account,
    nonce_state: &NonceState,
) -> Result<(), ValidationError> {
    if !tx.signature.is_empty() {
        return Err(ValidationError::InvalidSignature);
    }
    if tx.value != 0 {
        return Err(ValidationError::InvalidPaymaster); // misuse — register tx must not transfer
    }
    if tx.gas_limit != 0 {
        return Err(ValidationError::GasLimitTooHigh {
            limit: tx.gas_limit,
            max: 0,
        });
    }
    if tx.data.len() != pyde_crypto::falcon::FalconPublicKey::SIZE {
        return Err(ValidationError::InvalidSignature);
    }
    let derived = pyde_crypto::poseidon2::poseidon2_hash(&tx.data).to_bytes();
    if derived != tx.from {
        return Err(ValidationError::InvalidSignature);
    }
    if sender.balance == 0 {
        return Err(ValidationError::InsufficientBalance {
            required: 1,
            available: 0,
        });
    }
    if !matches!(sender.auth_keys, pyde_account::types::AuthKeys::None) {
        // Already registered — refuse to re-register. Use the
        // key-rotation flow (`pyde_account::auth::rotate`) instead.
        return Err(ValidationError::InvalidSignature);
    }
    validate_nonce(tx, nonce_state)?;
    validate_size(tx)?;
    Ok(())
}

fn validate_chain_id(tx: &Transaction, ctx: &ValidationContext) -> Result<(), ValidationError> {
    if tx.chain_id != ctx.chain_id {
        return Err(ValidationError::WrongChainId {
            expected: ctx.chain_id,
            got: tx.chain_id,
        });
    }
    Ok(())
}

fn validate_signature(tx: &Transaction, sender: &Account) -> Result<(), ValidationError> {
    match &sender.auth_keys {
        pyde_account::types::AuthKeys::Single(pk) => {
            if !tx.verify_signature(pk) {
                return Err(ValidationError::InvalidSignature);
            }
        }
        pyde_account::types::AuthKeys::None => {
            // System/contract accounts — no signature check at this level
        }
        pyde_account::types::AuthKeys::MultiSig { .. } => {
            // Multi-sig validation is handled by the auth module
            // For now, skip (requires multiple signatures in tx)
        }
    }
    Ok(())
}

fn validate_nonce(tx: &Transaction, nonce_state: &NonceState) -> Result<(), ValidationError> {
    match nonce_state.validate(tx.nonce) {
        Ok(_) => Ok(()),
        Err(e) => {
            // Enrich the error with the lowest unused nonce in the
            // current window so wallets can tell the user "you're
            // waiting on nonce N to fill" instead of "your nonce is
            // out of range, figure it out yourself." (MAINNET_PLAN M5.)
            //
            // The lowest unused nonce is `base` itself — every used
            // bit at position 0 would have already advanced `base`.
            // So `base` is always the next-needed slot if the window
            // has any gaps. We also include `base + WINDOW_SIZE - 1`
            // as the current upper bound so AboveWindow errors say
            // exactly which range is acceptable.
            let next_needed = nonce_state.base;
            let window_max = nonce_state.max_nonce();
            let msg = format!(
                "{:?} (got {}, window [{}..{}], next usable {})",
                e, tx.nonce, nonce_state.base, window_max, next_needed
            );
            Err(ValidationError::InvalidNonce(msg))
        }
    }
}

fn validate_balance(
    tx: &Transaction,
    sender: &Account,
    ctx: &ValidationContext,
) -> Result<(), ValidationError> {
    // TPL-206: bare `*` and `+` on attacker-controlled
    // `(gas_limit, base_fee, value)` overflow `u128` and either panic
    // in debug or wrap in release. With `panic = "abort"` workspace-
    // wide, the panic is SIGABRT — a remote validator-kill from a
    // single ingress tx in any base-fee-elevated regime. Reject with
    // an `InsufficientBalance { required: u128::MAX, available }`
    // result so operator logs surface "required = 2^128 - 1" as the
    // overflow tell; no balance can satisfy that demand.
    let overflow = || ValidationError::InsufficientBalance {
        required: u128::MAX,
        available: sender.balance.saturating_sub(ctx.sender_locked),
    };
    let gas_cost = (tx.gas_limit as u128)
        .checked_mul(ctx.base_fee)
        .ok_or_else(overflow)?;
    let total_required = gas_cost.checked_add(tx.value).ok_or_else(overflow)?;

    // Vested / locked balance (slice 4.4) is subtracted from the raw
    // account balance before any solvency check. `saturating_sub`
    // handles the edge case where a slash reduces balance below the
    // lock amount — the account is effectively frozen until vesting
    // progresses further (or the lock ends).
    let spendable = sender.balance.saturating_sub(ctx.sender_locked);

    // Check the fee payer's balance
    let available = match &tx.fee_payer {
        crate::types::FeePayer::Sender => spendable,
        crate::types::FeePayer::GasTank(_) => {
            // Gas tank pays gas, sender pays value only.
            // Gas tank balance check happens at execution time.
            if spendable < tx.value {
                return Err(ValidationError::InsufficientBalance {
                    required: tx.value,
                    available: spendable,
                });
            }
            return Ok(());
        }
        crate::types::FeePayer::Paymaster(paymaster_addr) => {
            // Paymaster pays everything — but verify the paymaster address is non-zero.
            // Full paymaster balance/existence check happens at execution time when
            // state is available. This structural check catches obvious misconfiguration.
            if *paymaster_addr == [0u8; 32] {
                return Err(ValidationError::InvalidPaymaster);
            }
            return Ok(());
        }
    };

    if available < total_required {
        return Err(ValidationError::InsufficientBalance {
            required: total_required,
            available,
        });
    }
    Ok(())
}

fn validate_gas_limit(tx: &Transaction, ctx: &ValidationContext) -> Result<(), ValidationError> {
    if tx.gas_limit < MIN_GAS_LIMIT {
        return Err(ValidationError::GasLimitTooLow {
            limit: tx.gas_limit,
            min: MIN_GAS_LIMIT,
        });
    }
    if tx.gas_limit > ctx.block_gas_limit {
        return Err(ValidationError::GasLimitTooHigh {
            limit: tx.gas_limit,
            max: ctx.block_gas_limit,
        });
    }
    Ok(())
}

fn validate_deadline(tx: &Transaction, ctx: &ValidationContext) -> Result<(), ValidationError> {
    if let Some(deadline) = tx.deadline {
        if ctx.block_height >= deadline {
            return Err(ValidationError::DeadlineExpired {
                deadline,
                current: ctx.block_height,
            });
        }
    }
    Ok(())
}

fn validate_access_list(tx: &Transaction) -> Result<(), ValidationError> {
    for (i, entry) in tx.access_list.iter().enumerate() {
        // Each storage key must be 32 bytes (enforced by type system)
        // Check for duplicate addresses
        for j in (i + 1)..tx.access_list.len() {
            if entry.address == tx.access_list[j].address {
                return Err(ValidationError::InvalidAccessList(format!(
                    "duplicate address at entries {} and {}",
                    i, j
                )));
            }
        }
    }
    Ok(())
}

fn validate_size(tx: &Transaction) -> Result<(), ValidationError> {
    // Calldata cap runs BEFORE the wire-encode size check so a pathological
    // tx with 1 GB of data can't force a 1 GB allocation inside
    // `to_bytes()` just to then reject.
    if tx.data.len() > MAX_CALLDATA {
        return Err(ValidationError::CalldataTooLarge {
            size: tx.data.len(),
            max: MAX_CALLDATA,
        });
    }
    let size = tx.to_bytes().len();
    if size > MAX_TX_SIZE {
        return Err(ValidationError::TxTooLarge {
            size,
            max: MAX_TX_SIZE,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AccessEntry, FeePayer, TransactionType};
    use pyde_account::address::{derive_eoa_address, ZERO_ADDRESS};
    use pyde_account::types::Account;
    use pyde_crypto::falcon::{falcon_keygen, falcon_sign};

    fn make_valid_tx_and_account() -> (Transaction, Account, NonceState) {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let account = Account {
            balance: 1_000_000_000_000, // plenty
            ..Account::new_eoa(&pk_bytes)
        };
        let nonce_state = NonceState::new();

        let mut tx = Transaction {
            from: account.address,
            to: derive_eoa_address(&[0xBB; 897]),
            value: 1_000,
            data: vec![],
            gas_limit: 21_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };

        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).unwrap().as_bytes().to_vec();

        (tx, account, nonce_state)
    }

    fn default_ctx() -> ValidationContext {
        ValidationContext {
            block_height: 100,
            base_fee: 1_000,
            block_gas_limit: BLOCK_GAS_TARGET,
            chain_id: 1,
            // validation.rs unit tests exercise each rule in isolation;
            // individual tests pass signed txs when they want to exercise
            // signature validation, and the module's signature test
            // overrides this field.
            dev_skip_signature: true,
            sender_locked: 0,
            sig_pre_verified: false,
        }
    }

    // ========== Task 0393: Each validation rule ==========

    #[test]
    fn valid_transaction_passes() {
        let (tx, account, nonce) = make_valid_tx_and_account();
        let ctx = default_ctx();
        assert!(validate_transaction(&tx, &account, &nonce, &ctx).is_ok());
    }

    #[test]
    fn wrong_chain_id_rejected() {
        let (tx, account, nonce) = make_valid_tx_and_account();
        let mut ctx = default_ctx();
        ctx.chain_id = 999;
        let err = validate_transaction(&tx, &account, &nonce, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::WrongChainId { .. }));
    }

    #[test]
    fn invalid_signature_rejected() {
        let (mut tx, account, nonce) = make_valid_tx_and_account();
        tx.signature = vec![0xFF; 666]; // garbage sig
                                        // Override default_ctx()'s dev_skip_signature so the sig check
                                        // actually runs — the whole point of this test.
        let ctx = ValidationContext {
            dev_skip_signature: false,
            ..default_ctx()
        };
        let err = validate_transaction(&tx, &account, &nonce, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidSignature));
    }

    // ========== Task 0396: Nonce outside window rejected ==========

    #[test]
    fn nonce_outside_window_rejected() {
        let (mut tx, _account, nonce) = make_valid_tx_and_account();
        tx.nonce = 100; // way outside [0, 15]
                        // Re-sign with correct hash
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let account = Account {
            balance: 1_000_000_000_000,
            ..Account::new_eoa(&pk_bytes)
        };
        tx.from = account.address;
        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).unwrap().as_bytes().to_vec();

        let ctx = default_ctx();
        let err = validate_transaction(&tx, &account, &nonce, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidNonce(_)));
    }

    // ========== Task 0395: Insufficient balance rejected ==========

    #[test]
    fn insufficient_balance_rejected() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let account = Account {
            balance: 100, // way too low
            ..Account::new_eoa(&pk_bytes)
        };
        let nonce = NonceState::new();

        let mut tx = Transaction {
            from: account.address,
            to: ZERO_ADDRESS,
            value: 0,
            data: vec![],
            gas_limit: 21_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };
        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).unwrap().as_bytes().to_vec();

        let ctx = default_ctx(); // base_fee = 1000, so 21000 * 1000 = 21M > 100
        let err = validate_transaction(&tx, &account, &nonce, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::InsufficientBalance { .. }));
    }

    /// TPL-206 regression — `gas_cost + value` (and `gas_limit *
    /// base_fee` upstream) must not overflow `u128`. Pre-fix the
    /// bare `+` and `*` would either panic in debug or wrap in
    /// release; with workspace `panic = "abort"` either was a
    /// remote-killable validator process. Post-fix every overflow
    /// path returns `InsufficientBalance { required: u128::MAX, ..
    /// }` so the rejection is clean and the operator log shows
    /// `required = 2^128 - 1` as the unmistakable overflow tell.
    #[test]
    fn fee_overflow_rejected_as_insufficient_balance() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        // Balance is irrelevant — overflow makes `required = u128::MAX`,
        // which exceeds any possible spendable balance regardless.
        let account = Account {
            balance: u128::MAX,
            ..Account::new_eoa(&pk_bytes)
        };
        let nonce = NonceState::new();

        // Adversarial shape: `value = u128::MAX` plus any non-zero
        // `gas_cost` overflows on the `gas_cost + value` add.
        let mut tx = Transaction {
            from: account.address,
            to: ZERO_ADDRESS,
            value: u128::MAX,
            data: vec![],
            gas_limit: 21_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };
        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).unwrap().as_bytes().to_vec();

        let ctx = default_ctx();
        let err = validate_transaction(&tx, &account, &nonce, &ctx).unwrap_err();
        assert!(
            matches!(
                err,
                ValidationError::InsufficientBalance { required, .. } if required == u128::MAX
            ),
            "expected fee-overflow → InsufficientBalance{{required: u128::MAX, ..}}, got {:?}",
            err
        );
    }

    #[test]
    fn paymaster_skips_balance_check() {
        // Audit 305 hard-rejects Paymaster on production; this test
        // exercises the same balance-check skip on devnet, where the
        // variant is still permitted for dev / test ergonomics.
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let account = Account {
            balance: 0, // zero balance
            ..Account::new_eoa(&pk_bytes)
        };
        let nonce = NonceState::new();

        let mut tx = Transaction {
            from: account.address,
            to: ZERO_ADDRESS,
            value: 0,
            data: vec![],
            gas_limit: 21_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Paymaster([0xFF; 32]),
            access_list: vec![],
            deadline: None,
            chain_id: 31337,
            tx_type: TransactionType::Standard,
        };
        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).unwrap().as_bytes().to_vec();

        let mut ctx = default_ctx();
        ctx.chain_id = 31337;
        assert!(validate_transaction(&tx, &account, &nonce, &ctx).is_ok());
    }

    // ========== Task 0394: Expired deadline rejected ==========

    #[test]
    fn expired_deadline_rejected() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let account = Account {
            balance: 1_000_000_000_000,
            ..Account::new_eoa(&pk_bytes)
        };
        let nonce = NonceState::new();

        let mut tx = Transaction {
            from: account.address,
            to: ZERO_ADDRESS,
            value: 0,
            data: vec![],
            gas_limit: 21_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: Some(50), // deadline at block 50
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };
        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).unwrap().as_bytes().to_vec();

        let ctx = default_ctx(); // block_height = 100 > deadline 50
        let err = validate_transaction(&tx, &account, &nonce, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::DeadlineExpired { .. }));
    }

    #[test]
    fn future_deadline_passes() {
        let (tx, _account, _nonce) = make_valid_tx_and_account();
        let mut tx = tx;
        // Need to re-sign with deadline
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let account = Account {
            balance: 1_000_000_000_000,
            ..Account::new_eoa(&pk_bytes)
        };
        tx.from = account.address;
        tx.deadline = Some(999); // future
        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).unwrap().as_bytes().to_vec();

        let ctx = default_ctx();
        assert!(validate_transaction(&tx, &account, &NonceState::new(), &ctx).is_ok());
    }

    // ========== Gas limits ==========

    #[test]
    fn gas_limit_too_low_rejected() {
        let (mut tx, _account, _nonce) = make_valid_tx_and_account();
        tx.gas_limit = 1_000; // below 21,000 minimum
        let ctx = default_ctx();
        // Skip sig check — gas limit is checked before execution
        let err = validate_gas_limit(&tx, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::GasLimitTooLow { .. }));
    }

    #[test]
    fn gas_limit_too_high_rejected() {
        let (mut tx, _, _) = make_valid_tx_and_account();
        tx.gas_limit = BLOCK_GAS_MAX + 1;
        let ctx = ValidationContext {
            block_gas_limit: BLOCK_GAS_MAX,
            ..default_ctx()
        };
        let err = validate_gas_limit(&tx, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::GasLimitTooHigh { .. }));
    }

    // ========== Access list ==========

    #[test]
    fn duplicate_access_list_address_rejected() {
        let (mut tx, _, _) = make_valid_tx_and_account();
        tx.access_list = vec![
            AccessEntry {
                address: [0xAA; 32],
                reads: vec![],
                writes: vec![],
            },
            AccessEntry {
                address: [0xAA; 32],
                reads: vec![],
                writes: vec![],
            }, // duplicate
        ];
        let err = validate_access_list(&tx).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidAccessList(_)));
    }

    #[test]
    fn valid_access_list_passes() {
        let (mut tx, _, _) = make_valid_tx_and_account();
        tx.access_list = vec![
            AccessEntry {
                address: [0xAA; 32],
                reads: vec![[0x11; 32]],
                writes: vec![],
            },
            AccessEntry {
                address: [0xBB; 32],
                reads: vec![],
                writes: vec![],
            },
        ];
        assert!(validate_access_list(&tx).is_ok());
    }

    // ========== Slice 5.3: MAX_CALLDATA ==========

    #[test]
    fn calldata_at_max_accepted() {
        let (mut tx, account, nonce_state) = make_valid_tx_and_account();
        tx.data = vec![0u8; MAX_CALLDATA];
        // Re-sign after mutating the body.
        let (_pk, sk) = falcon_keygen().unwrap();
        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).unwrap().as_bytes().to_vec();
        // Calldata check is size-only; signature check is bypassed under
        // dev_skip_signature = true in default_ctx.
        assert!(validate_size(&tx).is_ok());

        // Also run through full validation — signature is skipped by ctx,
        // account has headroom balance.
        let ctx = default_ctx();
        let _ = validate_transaction(&tx, &account, &nonce_state, &ctx);
    }

    #[test]
    fn calldata_over_max_rejected_by_size() {
        let (mut tx, _, _) = make_valid_tx_and_account();
        tx.data = vec![0u8; MAX_CALLDATA + 1];
        let err = validate_size(&tx).unwrap_err();
        match err {
            ValidationError::CalldataTooLarge { size, max } => {
                assert_eq!(size, MAX_CALLDATA + 1);
                assert_eq!(max, MAX_CALLDATA);
            }
            other => panic!("wrong error: {:?}", other),
        }
    }

    #[test]
    fn calldata_check_runs_before_tx_size_check() {
        // A tx with ridiculously oversized calldata should hit the
        // calldata cap first, not the tx-size cap — guards against
        // a future refactor reordering the checks and forcing the
        // pipeline to allocate MAX_TX_SIZE + K bytes via to_bytes()
        // before rejecting.
        let (mut tx, _, _) = make_valid_tx_and_account();
        tx.data = vec![0u8; MAX_CALLDATA * 10];
        let err = validate_size(&tx).unwrap_err();
        assert!(matches!(err, ValidationError::CalldataTooLarge { .. }));
    }

    // ========== Audit 226: AuthKeys::None production reject ==========

    #[test]
    fn validate_transaction_rejects_authkeys_none_on_production() {
        // A fresh (or contract / system) account has AuthKeys::None.
        // On non-devnet chain_id this should be rejected at
        // validate_transaction time so it can't slip past the
        // signature short-circuit ("System/contract accounts — no
        // signature check at this level"). Defense-in-depth alongside
        // the rpc.rs ingress gate (audit 226).
        let (tx, _, nonce_state) = make_valid_tx_and_account();
        let mut victim_account = Account::new_eoa(&[]);
        victim_account.address = tx.from;
        victim_account.auth_keys = pyde_account::types::AuthKeys::None;
        victim_account.balance = 1_000_000_000_000;
        let ctx = ValidationContext {
            chain_id: 1, // production
            dev_skip_signature: false,
            ..default_ctx()
        };
        let err = validate_transaction(&tx, &victim_account, &nonce_state, &ctx).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidSignature),
            "expected InvalidSignature for AuthKeys::None on production, got {err:?}"
        );
    }

    #[test]
    fn validate_transaction_allows_authkeys_none_on_devnet() {
        // chain_id == 31337 keeps the relaxed faucet/bootstrap UX:
        // an unregistered account can still send unsigned txs.
        let (mut tx, _, nonce_state) = make_valid_tx_and_account();
        tx.chain_id = 31337;
        let mut victim_account = Account::new_eoa(&[]);
        victim_account.address = tx.from;
        victim_account.auth_keys = pyde_account::types::AuthKeys::None;
        victim_account.balance = 1_000_000_000_000;
        let ctx = ValidationContext {
            chain_id: 31337,
            dev_skip_signature: true,
            ..default_ctx()
        };
        // Should pass all the audit-226-related checks. Other rules
        // may still apply (this just asserts 226 doesn't reject).
        validate_transaction(&tx, &victim_account, &nonce_state, &ctx)
            .expect("devnet must allow AuthKeys::None senders");
    }

    // ========== Audit 304: AuthKeys::MultiSig production reject ==========

    #[test]
    fn validate_transaction_rejects_multisig_on_production() {
        // `validate_signature` short-circuits MultiSig with a "// For
        // now, skip" arm — any tx from a MultiSig sender passes
        // without an auth check. Until threshold-check + multi-sig
        // wire format ship, hard-reject on every non-devnet chain_id.
        let (mut tx, _, nonce_state) = make_valid_tx_and_account();
        let mut victim = Account::new_eoa(&[]);
        victim.address = tx.from;
        victim.auth_keys = pyde_account::types::AuthKeys::MultiSig {
            keys: vec![vec![0xAA; 897]],
            threshold: 1,
        };
        victim.balance = 1_000_000_000_000;
        for chain_id in [1u64, 7, 7331, 1_000_000] {
            tx.chain_id = chain_id;
            let mut ctx = default_ctx();
            ctx.chain_id = chain_id;
            ctx.dev_skip_signature = false;
            let err = validate_transaction(&tx, &victim, &nonce_state, &ctx).unwrap_err();
            assert!(
                matches!(err, ValidationError::InvalidSignature),
                "chain_id {chain_id} must reject MultiSig, got {err:?}"
            );
        }
    }

    // ========== Audit 305: FeePayer::Paymaster / GasTank reject ==========

    #[test]
    fn validate_transaction_rejects_paymaster_on_production() {
        // FeePayer::Paymaster currently mints fees out of thin air
        // (pre_execution_charge returns Ok(0); post-execution
        // distribution still credits validator + treasury). Reject
        // until the paymaster contract integration ships.
        let (mut tx, account, nonce_state) = make_valid_tx_and_account();
        tx.fee_payer = FeePayer::Paymaster([0xAA; 32]);
        for chain_id in [1u64, 7, 7331, 1_000_000] {
            tx.chain_id = chain_id;
            let mut ctx = default_ctx();
            ctx.chain_id = chain_id;
            let err = validate_transaction(&tx, &account, &nonce_state, &ctx).unwrap_err();
            assert!(
                matches!(err, ValidationError::InvalidPaymaster),
                "chain_id {chain_id} must reject FeePayer::Paymaster, got {err:?}"
            );
        }
    }

    #[test]
    fn validate_transaction_rejects_gas_tank_on_production() {
        // FeePayer::GasTank's encoded address is currently ignored;
        // the debit always comes from sender.gas_tank, making the
        // sponsorship UX decorative. Reject on production until the
        // GasTank wiring honours its address.
        let (mut tx, account, nonce_state) = make_valid_tx_and_account();
        tx.fee_payer = FeePayer::GasTank([0xBB; 32]);
        for chain_id in [1u64, 7, 7331, 1_000_000] {
            tx.chain_id = chain_id;
            let mut ctx = default_ctx();
            ctx.chain_id = chain_id;
            let err = validate_transaction(&tx, &account, &nonce_state, &ctx).unwrap_err();
            assert!(
                matches!(err, ValidationError::InvalidPaymaster),
                "chain_id {chain_id} must reject FeePayer::GasTank, got {err:?}"
            );
        }
    }

    #[test]
    fn validate_transaction_allows_paymaster_and_gas_tank_on_devnet() {
        // Devnet (chain_id == 31337) keeps both fee_payer variants
        // for dev / test ergonomics — they're broken-by-design but
        // harmless inside a single-machine devnet.
        let (mut tx, account, nonce_state) = make_valid_tx_and_account();
        tx.chain_id = 31337;
        let mut ctx = default_ctx();
        ctx.chain_id = 31337;

        tx.fee_payer = FeePayer::Paymaster([0xAA; 32]);
        validate_transaction(&tx, &account, &nonce_state, &ctx)
            .expect("devnet must allow Paymaster");

        tx.fee_payer = FeePayer::GasTank([0xBB; 32]);
        validate_transaction(&tx, &account, &nonce_state, &ctx).expect("devnet must allow GasTank");
    }

    // ========== Audit 229: RegisterPubkey tx type ==========

    fn make_register_pubkey_tx_and_account() -> (Transaction, Account, NonceState) {
        let (pk, _sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let address = derive_eoa_address(&pk_bytes);
        // Build an account in the "funded but unregistered" state.
        // Account::new_eoa(&[]) would set auth_keys = Single(empty),
        // not None — start from the empty_account default instead.
        let account = Account {
            address,
            nonce: 0,
            balance: 1_000_000,
            code_hash: sparse_merkle_tree::H256::zero(),
            storage_root: sparse_merkle_tree::H256::zero(),
            account_type: pyde_account::types::AccountType::EOA,
            auth_keys: pyde_account::types::AuthKeys::None,
            gas_tank: 0,
            key_nonce: 0,
        };
        let tx = Transaction {
            from: address,
            to: ZERO_ADDRESS,
            value: 0,
            data: pk_bytes,
            gas_limit: 0,
            nonce: 0,
            signature: vec![], // unsigned
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::RegisterPubkey,
        };
        (tx, account, NonceState::new())
    }

    #[test]
    fn register_pubkey_happy_path_accepted() {
        let (tx, account, nonce_state) = make_register_pubkey_tx_and_account();
        let ctx = ValidationContext {
            chain_id: 1,
            dev_skip_signature: false,
            ..default_ctx()
        };
        validate_transaction(&tx, &account, &nonce_state, &ctx)
            .expect("happy-path RegisterPubkey must pass validation");
    }

    #[test]
    fn register_pubkey_with_signature_rejected() {
        // The whole point is the address-derivation check is the proof
        // — no FALCON sig is needed. A non-empty signature signals
        // confused intent; reject so we don't accidentally let an
        // alternative auth flow slip in.
        let (mut tx, account, nonce_state) = make_register_pubkey_tx_and_account();
        tx.signature = vec![0xAB; 666];
        let ctx = ValidationContext {
            chain_id: 1,
            dev_skip_signature: false,
            ..default_ctx()
        };
        let err = validate_transaction(&tx, &account, &nonce_state, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidSignature));
    }

    #[test]
    fn register_pubkey_with_value_or_gas_rejected() {
        let (mut tx, account, nonce_state) = make_register_pubkey_tx_and_account();
        tx.value = 100;
        let ctx = ValidationContext {
            chain_id: 1,
            dev_skip_signature: false,
            ..default_ctx()
        };
        assert!(validate_transaction(&tx, &account, &nonce_state, &ctx).is_err());

        tx.value = 0;
        tx.gas_limit = 21_000;
        let err = validate_transaction(&tx, &account, &nonce_state, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::GasLimitTooHigh { .. }));
    }

    #[test]
    fn register_pubkey_wrong_pubkey_for_address_rejected() {
        // Attacker tries to register a pubkey that does NOT hash to
        // tx.from. Address-derivation check rejects.
        let (mut tx, account, nonce_state) = make_register_pubkey_tx_and_account();
        let (other_pk, _) = falcon_keygen().unwrap();
        tx.data = other_pk.as_bytes().to_vec();
        // tx.from is still the original address (Poseidon2 of the original pk)
        let ctx = ValidationContext {
            chain_id: 1,
            dev_skip_signature: false,
            ..default_ctx()
        };
        let err = validate_transaction(&tx, &account, &nonce_state, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidSignature));
    }

    #[test]
    fn register_pubkey_wrong_data_size_rejected() {
        let (mut tx, account, nonce_state) = make_register_pubkey_tx_and_account();
        tx.data = vec![0xAB; 100]; // not 897 bytes
        let ctx = ValidationContext {
            chain_id: 1,
            dev_skip_signature: false,
            ..default_ctx()
        };
        let err = validate_transaction(&tx, &account, &nonce_state, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidSignature));
    }

    #[test]
    fn register_pubkey_zero_balance_rejected() {
        // Account must have been funded already — otherwise an
        // attacker can spam-register from millions of locally-generated
        // keypairs and bloat state without spending anything.
        let (tx, mut account, nonce_state) = make_register_pubkey_tx_and_account();
        account.balance = 0;
        let ctx = ValidationContext {
            chain_id: 1,
            dev_skip_signature: false,
            ..default_ctx()
        };
        let err = validate_transaction(&tx, &account, &nonce_state, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::InsufficientBalance { .. }));
    }

    #[test]
    fn register_pubkey_already_registered_rejected() {
        // One-time only. Re-registration goes through the
        // key-rotation flow (`pyde_account::auth::rotate`) which
        // requires a sig from the current key.
        let (tx, mut account, nonce_state) = make_register_pubkey_tx_and_account();
        account.auth_keys = pyde_account::types::AuthKeys::Single(vec![0xCD; 897]);
        let ctx = ValidationContext {
            chain_id: 1,
            dev_skip_signature: false,
            ..default_ctx()
        };
        let err = validate_transaction(&tx, &account, &nonce_state, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidSignature));
    }

    // ========== Audit 352: tx.value rejected on non-Standard/Deploy types ==========

    /// `Standard` is the only happy-path that carries value
    /// semantics for the simple-transfer / contract-call shape; it
    /// must continue to accept `tx.value > 0`.
    #[test]
    fn audit_352_standard_with_value_accepted() {
        let (tx, account, nonce_state) = make_valid_tx_and_account();
        assert_eq!(tx.tx_type, TransactionType::Standard);
        assert!(tx.value > 0, "fixture has nonzero value");
        let ctx = default_ctx();
        validate_transaction(&tx, &account, &nonce_state, &ctx)
            .expect("Standard with value must remain valid");
    }

    /// `Deploy` is the only other variant that carries value
    /// semantics (CREATE-with-value).
    #[test]
    fn audit_352_deploy_with_value_accepted() {
        let (mut tx, account, nonce_state) = make_valid_tx_and_account();
        tx.tx_type = TransactionType::Deploy;
        tx.to = ZERO_ADDRESS;
        tx.value = 5_000;
        let ctx = default_ctx();
        validate_transaction(&tx, &account, &nonce_state, &ctx)
            .expect("Deploy with value must remain valid");
    }

    /// Every non-Standard / non-Deploy variant with `tx.value > 0`
    /// must be rejected. Pre-fix `transfer_value` ran
    /// unconditionally before the per-type dispatch so a Slash tx
    /// with `value = 1_000` quietly transferred 1k PYDE alongside
    /// the slashing semantics — a side-channel transfer the
    /// declared tx_type implied nothing about.
    #[test]
    fn audit_352_non_value_types_with_value_rejected() {
        // Skip RegisterPubkey: it has its own pre-existing
        // value-must-be-zero check inside `validate_register_pubkey`
        // (returns `InvalidPaymaster` when `tx.value != 0`, see
        // line ~223). The new gate runs ahead of that branch but
        // RegisterPubkey is filtered before reaching it via the
        // early routing on line ~104. This test exercises the
        // remaining variants that flow through the new gate.
        let non_value_types = [
            TransactionType::StakeDeposit,
            TransactionType::StakeWithdraw,
            TransactionType::Slash,
            TransactionType::ClaimReward,
            TransactionType::ClaimAirdrop,
            TransactionType::SweepAirdrop,
            TransactionType::MultisigTx,
            TransactionType::RotateMultisig,
            TransactionType::EmergencyPause,
            TransactionType::EmergencyResume,
        ];
        for ty in non_value_types {
            let (mut tx, account, nonce_state) = make_valid_tx_and_account();
            tx.tx_type = ty;
            tx.value = 1_000;
            let ctx = default_ctx();
            let err = validate_transaction(&tx, &account, &nonce_state, &ctx)
                .expect_err(&format!("{ty:?} with value=1000 must reject"));
            match err {
                ValidationError::UnexpectedValue {
                    tx_type,
                    value: 1_000,
                } => assert_eq!(tx_type, ty as u8),
                other => panic!("{ty:?}: expected UnexpectedValue, got {other:?}"),
            }
        }
    }

    /// TPL-408: every non-Standard / non-Deploy variant with
    /// `tx.to != ZERO_ADDRESS` must be rejected. Pre-fix the
    /// pipeline's blanket `apply_account_delta(smt, &tx.to, ...)`
    /// wrote an empty Account record at the supplied address
    /// regardless of tx_type, growing the SMT for free.
    #[test]
    fn tpl_408_non_to_types_with_nonzero_to_rejected() {
        let stranger = derive_eoa_address(b"tpl-408-junk-bloat");
        // Skip RegisterPubkey (routed earlier) and StakeWithdraw
        // (audit-351 disables it) so the new gate is what we're
        // exercising rather than an earlier reject path.
        let non_to_types = [
            TransactionType::StakeDeposit,
            TransactionType::Slash,
            TransactionType::ClaimReward,
            TransactionType::ClaimAirdrop,
            TransactionType::SweepAirdrop,
            TransactionType::MultisigTx,
            TransactionType::RotateMultisig,
            TransactionType::EmergencyPause,
            TransactionType::EmergencyResume,
        ];
        for ty in non_to_types {
            let (mut tx, account, nonce_state) = make_valid_tx_and_account();
            tx.tx_type = ty;
            tx.value = 0; // 352 gate must not trip
            tx.to = stranger;
            let ctx = default_ctx();
            let err = validate_transaction(&tx, &account, &nonce_state, &ctx)
                .expect_err(&format!("{ty:?} with non-zero tx.to must reject"));
            match err {
                ValidationError::UnexpectedTo { tx_type } => assert_eq!(tx_type, ty as u8),
                other => panic!("{ty:?}: expected UnexpectedTo, got {other:?}"),
            }
        }
    }

    /// TPL-408 positive control: every non-`Standard`/`Deploy` variant
    /// with `tx.to == ZERO_ADDRESS` reaches at least past the new
    /// gate (later validation checks may still reject it for
    /// other reasons — we only verify the gate doesn't trip here).
    #[test]
    fn tpl_408_non_to_types_with_zero_to_pass_gate() {
        let non_to_types = [
            TransactionType::StakeDeposit,
            TransactionType::Slash,
            TransactionType::ClaimReward,
            TransactionType::ClaimAirdrop,
            TransactionType::SweepAirdrop,
            TransactionType::MultisigTx,
            TransactionType::RotateMultisig,
            TransactionType::EmergencyPause,
            TransactionType::EmergencyResume,
        ];
        for ty in non_to_types {
            let (mut tx, account, nonce_state) = make_valid_tx_and_account();
            tx.tx_type = ty;
            tx.value = 0;
            tx.to = ZERO_ADDRESS;
            let ctx = default_ctx();
            let res = validate_transaction(&tx, &account, &nonce_state, &ctx);
            // Either Ok or any error other than UnexpectedTo.
            if let Err(ValidationError::UnexpectedTo { .. }) = res {
                panic!("{ty:?}: ZERO_ADDRESS must clear the new gate");
            }
        }
    }

    // ========== Audit 351: StakeWithdraw disabled at validation ==========

    /// `StakeWithdraw` flips a validator entry to `Unbonding` but
    /// no other code path returns the locked stake to the
    /// operator. Pre-fix, an operator submitting `StakeWithdraw`
    /// silently lost their `VALIDATOR_STAKE` PYDE. The validation
    /// gate must hard-reject the variant on every chain_id (devnet
    /// included) until `CompleteUnbonding` ships.
    #[test]
    fn audit_351_stake_withdraw_rejected() {
        let (mut tx, account, nonce_state) = make_valid_tx_and_account();
        tx.tx_type = TransactionType::StakeWithdraw;
        tx.value = 0; // 352 gate must not trip
        tx.to = ZERO_ADDRESS; // TPL-408 gate must not trip

        for chain_id in [1u64, 7331, 31337] {
            tx.chain_id = chain_id;
            let mut ctx = default_ctx();
            ctx.chain_id = chain_id;
            let err = validate_transaction(&tx, &account, &nonce_state, &ctx)
                .expect_err(&format!("chain_id {chain_id} must reject StakeWithdraw"));
            match err {
                ValidationError::DisabledTxType(t) => {
                    assert_eq!(t, TransactionType::StakeWithdraw as u8)
                }
                other => panic!("chain_id {chain_id}: expected DisabledTxType, got {other:?}"),
            }
        }
    }

    /// `StakeDeposit` must continue to work — only `StakeWithdraw`
    /// is gated. Confirms the audit-351 gate is precise (doesn't
    /// over-reach to the deposit side).
    #[test]
    fn audit_351_stake_deposit_still_accepted() {
        let (mut tx, account, nonce_state) = make_valid_tx_and_account();
        tx.tx_type = TransactionType::StakeDeposit;
        tx.value = 0;
        let ctx = default_ctx();
        // Validation may still fail for other reasons (payload
        // shape, etc.), but must not trip on DisabledTxType.
        if let Err(e) = validate_transaction(&tx, &account, &nonce_state, &ctx) {
            assert!(
                !matches!(e, ValidationError::DisabledTxType(_)),
                "StakeDeposit must not be gated, got {e:?}",
            );
        }
    }

    /// Same set with `tx.value == 0` must continue to validate
    /// (the gate is value-conditional, not type-conditional).
    #[test]
    fn audit_352_non_value_types_with_zero_value_accepted() {
        let non_value_types = [
            TransactionType::StakeDeposit,
            TransactionType::StakeWithdraw,
            TransactionType::Slash,
            TransactionType::ClaimReward,
            TransactionType::ClaimAirdrop,
            TransactionType::SweepAirdrop,
            TransactionType::MultisigTx,
            TransactionType::RotateMultisig,
            TransactionType::EmergencyPause,
            TransactionType::EmergencyResume,
        ];
        for ty in non_value_types {
            let (mut tx, account, nonce_state) = make_valid_tx_and_account();
            tx.tx_type = ty;
            tx.value = 0;
            let ctx = default_ctx();
            // Some types may still fail later checks (e.g. payload
            // shape) — we only assert that the audit-352 gate
            // does not fire.
            if let Err(e) = validate_transaction(&tx, &account, &nonce_state, &ctx) {
                assert!(
                    !matches!(e, ValidationError::UnexpectedValue { .. }),
                    "{ty:?} with value=0 must not trip UnexpectedValue, got {e:?}",
                );
            }
        }
    }
}
