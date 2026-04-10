//! Transaction execution pipeline: end-to-end integration of TX → Account → State → PVM.
//!
//! Connects all crates into a single execution flow:
//! 1. Load sender account from State SMT
//! 2. Validate transaction (signature, nonce, balance, gas, deadline)
//! 3. Pre-execution: deduct max gas from fee payer
//! 4. Value transfer: sender → recipient
//! 5. PVM execution (contract call or deployment)
//! 6. Post-execution: refund unused gas, apply SDELETE refunds
//! 7. Fee distribution: 80% burn, 20% validator
//! 8. Update accounts in State SMT
//! 9. Generate receipt

use crate::execution::{
    distribute_fee, generate_receipt, post_execution_refund, pre_execution_charge,
    transfer_value, LogEntry, Receipt,
};
use crate::fee::adjust_base_fee;
use crate::types::{FeePayer, Transaction, TransactionType};
use crate::validation::{validate_transaction, ValidationContext, ValidationError};

use pyde_account::address::{Address, ZERO_ADDRESS};
use pyde_account::nonce::NonceState;
use pyde_account::types::Account;
use pyde_crypto::poseidon2::poseidon2_hash;
use pyde_state::keys;
use pyde_state::smt::{Key, PydeSMT};
use pyde_vm::vm::{ExecutionContext, ExecResult, Outcome, Vm};
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
pub fn store_account(smt: &mut dyn pyde_state::smt::StateAccess, account: &Account) -> Result<(), PipelineError> {
    let key = keys::balance_key(&account.address);
    smt.insert(key, account.to_bytes())
        .map_err(|e| PipelineError::StateError(e.to_string()))?;
    Ok(())
}

/// Load a nonce state for an account. Returns default if not found.
pub fn load_nonce(smt: &dyn pyde_state::smt::StateAccess, address: &Address) -> NonceState {
    let key = keys::nonce_key(address);
    match smt.get(&key) {
        Some(bytes) if bytes.len() >= 10 => {
            let mut nonce_bytes = [0u8; 10];
            nonce_bytes.copy_from_slice(&bytes[..10]);
            NonceState::from_bytes(&nonce_bytes)
        }
        _ => NonceState::new(),
    }
}

/// Store a nonce state into the SMT.
pub fn store_nonce(smt: &mut dyn pyde_state::smt::StateAccess, address: &Address, nonce: &NonceState) -> Result<(), PipelineError> {
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
pub fn store_code(smt: &mut dyn pyde_state::smt::StateAccess, address: &Address, code: &[u8]) -> Result<(), PipelineError> {
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
pub fn execute_transaction(
    tx: &Transaction,
    smt: &mut dyn pyde_state::smt::StateAccess,
    block_ctx: &BlockContext,
) -> Result<Receipt, PipelineError> {
    // 1. Load accounts
    let mut sender = load_account(smt, &tx.from);
    let mut recipient = load_account(smt, &tx.to);
    let mut nonce_state = load_nonce(smt, &tx.from);

    // 2. Validate
    let val_ctx = ValidationContext {
        block_height: block_ctx.height,
        base_fee: block_ctx.base_fee,
        block_gas_limit: block_ctx.block_gas_limit,
        chain_id: block_ctx.chain_id,
    };
    validate_transaction(tx, &sender, &nonce_state, &val_ctx)?;

    // 3. Mark nonce as used
    nonce_state
        .use_nonce(tx.nonce)
        .map_err(|e| PipelineError::ExecutionFailed(format!("nonce error: {:?}", e)))?;

    // 4. Pre-execution: deduct max gas
    // NOTE: When fee_payer is Paymaster, no pre-charge happens here.
    // Paymaster gas charges are enforced by the paymaster contract itself
    // (via a validation call that checks and debits the paymaster's deposit),
    // not by the pipeline.  The pipeline only pre-charges Sender and GasTank
    // fee payers; paymaster settlement is deferred to the contract layer.
    let mut gas_tank_balance = sender.gas_tank;
    pre_execution_charge(tx, &mut sender.balance, &mut gas_tank_balance, block_ctx.base_fee)
        .map_err(|e| PipelineError::ExecutionFailed(e))?;
    sender.gas_tank = gas_tank_balance;

    // 5. Value transfer
    transfer_value(&mut sender.balance, &mut recipient.balance, tx.value)
        .map_err(|e| PipelineError::ExecutionFailed(e))?;

    // 6. PVM execution (if contract call or deployment)
    let (success, gas_used, gas_refund, logs, return_data) = match tx.tx_type {
        TransactionType::Standard if tx.to != ZERO_ADDRESS => {
            // Contract call
            match load_code(smt, &tx.to) {
                Some(code) => {
                    tracing::debug!(to = hex::encode(tx.to), code_len = code.len(), "executing contract call in PVM");
                    execute_in_pvm(tx, &sender, &code, smt, block_ctx)
                }
                None => {
                    tracing::debug!(to = hex::encode(tx.to), "simple transfer (no code at recipient)");
                    (true, 21_000u64, 0u64, vec![], vec![])
                }
            }
        }
        TransactionType::Deploy => {
            // Contract deployment with constructor execution.
            // tx.data format: constructor_len(4 LE) + constructor_bytes + runtime_bytes + constructor_args
            // If constructor_len == 0: store tx.data[4..] as runtime (no constructor).
            let new_addr = pyde_account::address::derive_create_address(
                &tx.from,
                sender.nonce,
            );
            // Increment sender nonce so the next deploy gets a different address
            sender.nonce += 1;

            let (runtime_code, gas_used) = if tx.data.len() >= 8 {
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
                    let (success, gas, _, logs, _) = execute_in_pvm(
                        &constructor_tx, &sender, constructor, smt, block_ctx,
                    );
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
            // 10,000 PYDE = 10_000_000_000_000 quanta (matches consensus::validator::VALIDATOR_STAKE)
            const VALIDATOR_STAKE: u128 = 10_000_000_000_000;

            if sender.balance < VALIDATOR_STAKE {
                (false, 21_000u64, 0u64, vec![], b"insufficient balance for stake deposit".to_vec())
            } else if tx.data.len() < 897 {
                (false, 21_000u64, 0u64, vec![], b"tx.data must contain FALCON public key (897 bytes)".to_vec())
            } else {
                // Validate: public key must derive to sender's address
                let pk_bytes = &tx.data[..897];
                let derived_addr = pyde_account::address::derive_eoa_address(pk_bytes);
                if derived_addr != tx.from {
                    (false, 21_000u64, 0u64, vec![], b"public key does not match sender address".to_vec())
                } else if smt.get(&pyde_state::keys::validator_key(&tx.from)).is_some() {
                    // Already registered
                    (false, 21_000u64, 0u64, vec![], b"already registered as validator".to_vec())
                } else {

                // Deduct stake from sender balance
                sender.balance -= VALIDATOR_STAKE;

                // Write validator entry to state: [pk_len:4 LE][pk][stake:16 LE][status:1]
                let mut val_data = Vec::with_capacity(4 + 897 + 16 + 1);
                val_data.extend_from_slice(&(897u32).to_le_bytes());
                val_data.extend_from_slice(pk_bytes);
                val_data.extend_from_slice(&VALIDATOR_STAKE.to_le_bytes());
                val_data.push(0x00); // Active

                let val_key = pyde_state::keys::validator_key(&tx.from);
                let _ = smt.insert(val_key, val_data);

                // Update validator address list (append sender address)
                let count_key = pyde_state::keys::validator_count_key();
                let count = smt.get(&count_key)
                    .map(|b| {
                        if b.len() >= 8 {
                            u64::from_le_bytes(b[..8].try_into().unwrap_or([0;8]))
                        } else { 0 }
                    })
                    .unwrap_or(0);
                let new_count = count + 1;
                let _ = smt.insert(count_key, new_count.to_le_bytes().to_vec());

                // Store address at index for enumeration
                let idx_key = pyde_state::keys::validator_index_key(count);
                let _ = smt.insert(idx_key, tx.from.to_vec());

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
                Some(mut val_data) => {
                    if val_data.len() < 5 {
                        (false, 21_000u64, 0u64, vec![], b"invalid validator entry".to_vec())
                    } else {
                        let pk_len = u32::from_le_bytes([val_data[0], val_data[1], val_data[2], val_data[3]]) as usize;
                        let status_offset = 4 + pk_len + 16;
                        if val_data.len() <= status_offset {
                            (false, 21_000u64, 0u64, vec![], b"invalid validator entry".to_vec())
                        } else if val_data[status_offset] != 0x00 {
                            // Not Active
                            (false, 21_000u64, 0u64, vec![], b"validator is not active".to_vec())
                        } else {
                            // Set status to Unbonding (0x01) + store exit block
                            val_data[status_offset] = 0x01;
                            // Append exit block (8 bytes LE) for unbonding period tracking
                            val_data.extend_from_slice(&block_ctx.height.to_le_bytes());
                            let _ = smt.insert(val_key, val_data);

                            tracing::info!(
                                validator = hex::encode(tx.from),
                                exit_block = block_ctx.height,
                                "stake withdraw: validator unbonding started"
                            );

                            (true, 50_000u64, 0u64, vec![], vec![])
                        }
                    }
                }
                None => {
                    (false, 21_000u64, 0u64, vec![], b"not a registered validator".to_vec())
                }
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

    // 9. Save updated accounts
    store_account(smt, &sender)?;
    store_account(smt, &recipient)?;
    store_nonce(smt, &tx.from, &nonce_state)?;

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
fn execute_in_pvm(
    tx: &Transaction,
    sender: &Account,
    code: &[u8],
    smt: &mut dyn pyde_state::smt::StateAccess,
    block_ctx: &BlockContext,
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
    let smt_ptr = smt as *const dyn pyde_state::smt::StateAccess as *const () as usize;
    let smt_vtable = unsafe {
        std::mem::transmute::<&dyn pyde_state::smt::StateAccess, [usize; 2]>(smt)
    };
    vm.storage_backend = Some(std::sync::Arc::new(move |key: &U256| {
        let smt_key = H256::from(key.to_le_bytes());
        let smt_ref: &dyn pyde_state::smt::StateAccess = unsafe {
            std::mem::transmute::<[usize; 2], &dyn pyde_state::smt::StateAccess>(smt_vtable)
        };
        smt_ref.get(&smt_key)
    }));

    // Code backend: lazy-load target contract bytecode for cross-contract calls.
    let smt_vtable2 = smt_vtable;
    vm.code_backend = Some(std::sync::Arc::new(move |addr: &pyde_account::address::Address| {
        let code_key = pyde_state::keys::code_key(addr);
        let smt_ref: &dyn pyde_state::smt::StateAccess = unsafe {
            std::mem::transmute::<[usize; 2], &dyn pyde_state::smt::StateAccess>(smt_vtable2)
        };
        smt_ref.get(&code_key)
    }));

    if vm.load(code).is_err() {
        return (false, tx.gas_limit, 0, vec![], vec![]);
    }

    let output = vm.execute();
    let success = output.outcome == Outcome::Success;

    tracing::debug!(
        success,
        gas = output.gas_used,
        storage_entries = vm.storage.len(),
        "execute_in_pvm completed"
    );

    // Persist VM storage changes back to SMT.
    // Use the derived key directly (same as what the VM uses internally).
    // Drop the storage backend before writing back (releases the read pointer)
    vm.storage_backend = None;
    vm.code_backend = None;

    // Persist VM storage changes to SMT
    if success && !vm.storage.is_empty() {
        for (vm_key, value_bytes) in &vm.storage {
            let smt_key = H256::from(vm_key.to_le_bytes());
            let _ = smt.insert(smt_key, value_bytes.clone());
        }
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

    let logs = output
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
    (success, output.gas_used as u64, output.gas_refund, logs, return_data)
}

/// Execute a block of transactions using parallel group scheduling.
///
/// Groups are determined by the conflict scheduler (disjoint access lists).
/// Within each group, transactions execute sequentially (they conflict).
/// Between groups, execution is order-independent because the scheduler
/// guarantees disjoint state access — groups never touch the same storage keys.
///
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

    fn make_block_ctx() -> BlockContext {
        BlockContext {
            height: 100,
            timestamp: 1_000_000,
            base_fee: 1_000,
            block_gas_limit: 400_000_000,
            chain_id: 1,
            validator_address: derive_eoa_address(b"validator"),
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

    fn setup_funded_account(smt: &mut dyn pyde_state::smt::StateAccess, pk_bytes: &[u8], balance: u128) -> Address {
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
        let mut sender = Account {
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
        store_nonce(&mut smt, &sender_addr, &pyde_account::nonce::NonceState::new()).unwrap();

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
            let smt_ptr = smt as *const PydeSMT;
            vm.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
                let smt_key = sparse_merkle_tree::H256::from(key.to_le_bytes());
                unsafe { (*smt_ptr).get(&smt_key) }
            }));
            vm.calldata = calldata;
            vm.load(&code).unwrap();
            let output = vm.execute();
            assert_eq!(output.outcome, pyde_vm::vm::Outcome::Success, "call failed");
            vm.cpu.read_gp(1)
        };

        let enc_u64 = |v: u64| -> Vec<u8> { v.to_le_bytes().to_vec() };
        let mut cd = |name: &str, args: &[u64]| -> Vec<u8> {
            let mut data = sel(name).to_be_bytes().to_vec();
            for a in args { data.extend_from_slice(&a.to_le_bytes()); }
            data
        };

        // Run: setup, set_balance x4, batch_reward
        send(&mut smt, cd("setup", &[]));
        send(&mut smt, cd("set_balance", &[10, 38000]));
        send(&mut smt, cd("set_balance", &[20, 39000]));
        send(&mut smt, cd("set_balance", &[30, 21800]));
        send(&mut smt, cd("set_balance", &[1, 1200]));

        // Verify pre-batch balances
        assert_eq!(call(&smt, cd("get_balance", &[10])), 38000, "pre-batch bal(10)");
        assert_eq!(call(&smt, cd("get_balance", &[20])), 39000, "pre-batch bal(20)");
        assert_eq!(call(&smt, cd("get_balance", &[30])), 21800, "pre-batch bal(30)");
        assert_eq!(call(&smt, cd("get_balance", &[1])), 1200, "pre-batch bal(1)");

        // Run batch_reward
        send(&mut smt, cd("batch_reward", &[10, 20, 30, 3000]));

        // Verify post-batch balances
        let b10 = call(&smt, cd("get_balance", &[10]));
        let b20 = call(&smt, cd("get_balance", &[20]));
        let b30 = call(&smt, cd("get_balance", &[30]));
        let b1 = call(&smt, cd("get_balance", &[1]));

        eprintln!("bal(10)={b10} (want 40700)");
        eprintln!("bal(20)={b20} (want 41700)");
        eprintln!("bal(30)={b30} (want 24500)");
        eprintln!("bal(1)={b1} (want 2100)");

        assert_eq!(b10, 40700, "bal(10) = 38000 + 2700");
        assert_eq!(b20, 41700, "bal(20) = 39000 + 2700");
        assert_eq!(b30, 24500, "bal(30) = 21800 + 2700");
        assert_eq!(b1, 2100, "bal(1) = 1200 + 900");
    }

    // ========== E2E: Otigen compile → deploy → call (struct + Vec + while loop) ==========

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
            self_address: contract_addr.into(),
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
        assert_eq!(output.outcome, pyde_vm::vm::Outcome::Success, "rank() failed");
        assert_eq!(vm.cpu.read_gp(1), 1, "rank should be 1 (no board entries > 400)");
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
                "pre-derived key for slot {} doesn't match runtime key", slot_val
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

        assert!(allowed.contains(&runtime_key), "cross-contract key should match");
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
                from: sender_addr, to: ZERO_ADDRESS, value: 0,
                data: deploy_data, gas_limit: 100_000_000, nonce: 0,
                signature: vec![], fee_payer: FeePayer::Sender,
                access_list: vec![], deadline: None, chain_id: 1,
                tx_type: TransactionType::Deploy,
            };
            let hash = tx.hash();
            tx.signature = pyde_crypto::falcon::falcon_sign(&sk, &hash).unwrap().as_bytes().to_vec();
            tx
        };
        let deploy_receipt = execute_transaction(&deploy_tx, &mut smt, &block_ctx).unwrap();
        assert!(deploy_receipt.success, "deploy failed");

        // Call get_value() — should return 42
        let selector = otic::codegen::compute_selector("get_value");
        let call_tx = {
            let mut tx = Transaction {
                from: sender_addr, to: contract_addr, value: 0,
                data: selector.to_be_bytes().to_vec(), gas_limit: 100_000_000, nonce: 1,
                signature: vec![], fee_payer: FeePayer::Sender,
                access_list: vec![], deadline: None, chain_id: 1,
                tx_type: TransactionType::Standard,
            };
            let hash = tx.hash();
            tx.signature = pyde_crypto::falcon::falcon_sign(&sk, &hash).unwrap().as_bytes().to_vec();
            tx
        };
        let call_receipt = execute_transaction(&call_tx, &mut smt, &block_ctx).unwrap();
        assert!(call_receipt.success, "call failed");

        // return_data should contain 42 as u64 LE
        assert!(!call_receipt.return_data.is_empty(), "return_data should not be empty");
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
                from: sender_addr, to: ZERO_ADDRESS, value: 0,
                data: deploy_data, gas_limit: 100_000_000, nonce: 0,
                signature: vec![], fee_payer: FeePayer::Sender,
                access_list: vec![], deadline: None, chain_id: 1,
                tx_type: TransactionType::Deploy,
            };
            let hash = tx.hash();
            tx.signature = pyde_crypto::falcon::falcon_sign(&sk, &hash).unwrap().as_bytes().to_vec();
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
                from: sender_addr, to: contract_addr, value: 0,
                data: calldata, gas_limit: 100_000_000, nonce: 1,
                signature: vec![], fee_payer: FeePayer::Sender,
                access_list: vec![], deadline: None, chain_id: 1,
                tx_type: TransactionType::Standard,
            };
            let hash = tx.hash();
            tx.signature = pyde_crypto::falcon::falcon_sign(&sk, &hash).unwrap().as_bytes().to_vec();
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
                from: sender_addr, to: ZERO_ADDRESS, value: 0,
                data: deploy_data, gas_limit: 100_000_000, nonce: 0,
                signature: vec![], fee_payer: FeePayer::Sender,
                access_list: vec![], deadline: None, chain_id: 1,
                tx_type: TransactionType::Deploy,
            };
            let hash = tx.hash();
            tx.signature = pyde_crypto::falcon::falcon_sign(&sk, &hash).unwrap().as_bytes().to_vec();
            tx
        };
        let deploy_receipt = execute_transaction(&deploy_tx, &mut smt, &block_ctx).unwrap();
        assert!(deploy_receipt.success, "deploy failed");

        // Call increment() 3 times
        for i in 0..3u64 {
            let selector = otic::codegen::compute_selector("increment");
            let call_tx = {
                let mut tx = Transaction {
                    from: sender_addr, to: contract_addr, value: 0,
                    data: selector.to_be_bytes().to_vec(), gas_limit: 100_000_000, nonce: 1 + i,
                    signature: vec![], fee_payer: FeePayer::Sender,
                    access_list: vec![], deadline: None, chain_id: 1,
                    tx_type: TransactionType::Standard,
                };
                let hash = tx.hash();
                tx.signature = pyde_crypto::falcon::falcon_sign(&sk, &hash).unwrap().as_bytes().to_vec();
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
            from: sender_addr, to: [0u8;32], value: 0,
            data: pk.as_bytes().to_vec(), gas_limit: 100_000, nonce: 0,
            signature: vec![], fee_payer: FeePayer::Sender,
            access_list: vec![], deadline: None, chain_id: 1,
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

    #[test]
    fn stake_withdraw_starts_unbonding() {
        let (pk, sk) = falcon_keygen().unwrap();
        let sender_addr = derive_eoa_address(pk.as_bytes());
        let mut smt = PydeSMT::new();
        let ctx = make_block_ctx();

        fund_account_with_pk(&mut smt, &sender_addr, 20_000_000_000_000, pk.as_bytes());

        // Deposit first
        let mut deposit = Transaction {
            from: sender_addr, to: [0u8;32], value: 0,
            data: pk.as_bytes().to_vec(), gas_limit: 100_000, nonce: 0,
            signature: vec![], fee_payer: FeePayer::Sender,
            access_list: vec![], deadline: None, chain_id: 1,
            tx_type: TransactionType::StakeDeposit,
        };
        sign_tx(&mut deposit, &sk);
        execute_transaction(&deposit, &mut smt, &ctx).unwrap();

        // Withdraw
        let mut withdraw = Transaction {
            from: sender_addr, to: [0u8;32], value: 0,
            data: vec![], gas_limit: 100_000, nonce: 1,
            signature: vec![], fee_payer: FeePayer::Sender,
            access_list: vec![], deadline: None, chain_id: 1,
            tx_type: TransactionType::StakeWithdraw,
        };
        sign_tx(&mut withdraw, &sk);
        let receipt = execute_transaction(&withdraw, &mut smt, &ctx).unwrap();
        assert!(receipt.success, "withdraw should succeed");

        // Verify status is Unbonding (0x01)
        let val_key = pyde_state::keys::validator_key(&sender_addr);
        let val_data = smt.get(&val_key).unwrap();
        let pk_len = u32::from_le_bytes([val_data[0],val_data[1],val_data[2],val_data[3]]) as usize;
        assert_eq!(val_data[4 + pk_len + 16], 0x01, "status should be Unbonding");
    }

    fn fund_account_with_pk(smt: &mut dyn pyde_state::smt::StateAccess, addr: &Address, balance: u128, pk: &[u8]) {
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
}
