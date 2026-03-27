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
pub fn load_account(smt: &PydeSMT, address: &Address) -> Account {
    let key = keys::balance_key(address);
    match smt.get(&key) {
        Some(bytes) => Account::from_bytes(&bytes).unwrap_or_else(|| empty_account(address)),
        None => empty_account(address),
    }
}

/// Store an account into the SMT.
pub fn store_account(smt: &mut PydeSMT, account: &Account) -> Result<(), PipelineError> {
    let key = keys::balance_key(&account.address);
    smt.insert(key, account.to_bytes())
        .map_err(|e| PipelineError::StateError(e.to_string()))?;
    Ok(())
}

/// Load a nonce state for an account. Returns default if not found.
pub fn load_nonce(smt: &PydeSMT, address: &Address) -> NonceState {
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
pub fn store_nonce(smt: &mut PydeSMT, address: &Address, nonce: &NonceState) -> Result<(), PipelineError> {
    let key = keys::nonce_key(address);
    smt.insert(key, nonce.to_bytes().to_vec())
        .map_err(|e| PipelineError::StateError(e.to_string()))?;
    Ok(())
}

/// Load contract code from the SMT.
pub fn load_code(smt: &PydeSMT, address: &Address) -> Option<Vec<u8>> {
    let key = keys::code_key(address);
    smt.get(&key)
}

/// Store contract code into the SMT.
pub fn store_code(smt: &mut PydeSMT, address: &Address, code: &[u8]) -> Result<(), PipelineError> {
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
    smt: &mut PydeSMT,
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
    let (success, gas_used, gas_refund, logs) = match tx.tx_type {
        TransactionType::Standard if tx.to != ZERO_ADDRESS => {
            // Contract call
            match load_code(smt, &tx.to) {
                Some(code) => {
                    let result = execute_in_pvm(tx, &sender, &code, smt, block_ctx);
                    result
                }
                None => {
                    // Simple transfer (no code at recipient)
                    (true, 21_000u64, 0u64, vec![])
                }
            }
        }
        TransactionType::Deploy => {
            // Contract deployment
            let new_addr = pyde_account::address::derive_create_address(
                &tx.from,
                sender.nonce,
            );
            store_code(smt, &new_addr, &tx.data)?;

            let contract = Account::new_contract(new_addr, &tx.data);
            store_account(smt, &contract)?;

            (true, 32_000u64, 0u64, vec![])
        }
        _ => {
            // Simple transfer or batch (batch deferred)
            (true, 21_000u64, 0u64, vec![])
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

    // 8. Fee distribution
    let fee_dist = distribute_fee(effective_gas, block_ctx.base_fee);

    // Credit validator
    let mut validator_account = load_account(smt, &block_ctx.validator_address);
    validator_account.balance += fee_dist.validator;
    store_account(smt, &validator_account)?;

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
    );

    Ok(receipt)
}

/// Execute contract code in the PVM.
fn execute_in_pvm(
    tx: &Transaction,
    sender: &Account,
    code: &[u8],
    smt: &PydeSMT,
    block_ctx: &BlockContext,
) -> (bool, u64, u64, Vec<LogEntry>) {
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

    if vm.load(code).is_err() {
        return (false, tx.gas_limit, 0, vec![]);
    }

    let output = vm.execute();

    let success = output.outcome == Outcome::Success;
    let logs = output
        .logs
        .iter()
        .map(|log| LogEntry {
            address: log.address,
            topics: log.topics.iter().map(|t| t.to_le_bytes()).collect(),
            data: log.data.clone(),
        })
        .collect();

    (success, output.gas_used as u64, output.gas_refund, logs)
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

    fn setup_funded_account(smt: &mut PydeSMT, pk_bytes: &[u8], balance: u128) -> Address {
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
}
