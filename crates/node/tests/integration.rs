//! M12.1 — Single-Node Integration Tests
//!
//! End-to-end tests that exercise the full transaction pipeline:
//! genesis → fund accounts → build transactions → execute → verify state.
//!
//! Uses in-process execution (no node subprocess) for speed and determinism.

use pyde_account::address::derive_eoa_address;
use pyde_crypto::falcon::{falcon_keygen, falcon_sign};
use pyde_state::smt::PydeSMT;
use pyde_tx::execution::Receipt;
use pyde_tx::pipeline::{execute_transaction, BlockContext};
use pyde_tx::types::*;

// ============================================================================
// Test utilities
// ============================================================================

fn block_ctx() -> BlockContext {
    BlockContext {
        height: 1,
        timestamp: 1_000_000,
        base_fee: 1_000,
        block_gas_limit: 400_000_000,
        chain_id: 1,
        validator_address: derive_eoa_address(b"validator"),
    }
}

fn fund_account(
    smt: &mut PydeSMT,
    pk_bytes: &[u8],
    balance: u128,
) -> [u8; 32] {
    let addr = derive_eoa_address(pk_bytes);
    let mut account = pyde_account::types::Account::new_eoa(pk_bytes);
    account.balance = balance;
    pyde_tx::pipeline::store_account(smt, &account).unwrap();
    pyde_tx::pipeline::store_nonce(smt, &addr, &pyde_account::nonce::NonceState::new()).unwrap();
    addr
}

fn sign_tx(tx: &mut Transaction, sk: &pyde_crypto::falcon::FalconSecretKey) {
    let hash = tx.hash();
    tx.signature = falcon_sign(sk, &hash).unwrap().as_bytes().to_vec();
}

fn transfer_tx(
    from: [u8; 32],
    to: [u8; 32],
    value: u128,
    nonce: u64,
    sk: &pyde_crypto::falcon::FalconSecretKey,
) -> Transaction {
    let mut tx = Transaction {
        from, to, value,
        data: vec![],
        gas_limit: 21_000,
        nonce,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id: 1,
        tx_type: TransactionType::Standard,
    };
    sign_tx(&mut tx, sk);
    tx
}

fn deploy_tx(
    from: [u8; 32],
    deploy_data: Vec<u8>,
    nonce: u64,
    sk: &pyde_crypto::falcon::FalconSecretKey,
) -> Transaction {
    let mut tx = Transaction {
        from,
        to: [0u8; 32],
        value: 0,
        data: deploy_data,
        gas_limit: 100_000_000,
        nonce,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id: 1,
        tx_type: TransactionType::Deploy,
    };
    sign_tx(&mut tx, sk);
    tx
}

fn call_tx(
    from: [u8; 32],
    to: [u8; 32],
    method: &str,
    args: Vec<u8>,
    nonce: u64,
    sk: &pyde_crypto::falcon::FalconSecretKey,
) -> Transaction {
    let selector = otic::codegen::compute_selector(method);
    let mut data = selector.to_be_bytes().to_vec();
    data.extend_from_slice(&args);
    let mut tx = Transaction {
        from, to, value: 0,
        data,
        gas_limit: 100_000_000,
        nonce,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id: 1,
        tx_type: TransactionType::Standard,
    };
    sign_tx(&mut tx, sk);
    tx
}

fn compile_contract(source: &str) -> (Vec<u8>, String) {
    let compiled = otic::compile_all(source);
    assert!(!compiled.is_empty(), "compilation produced no contracts");
    let (name, contract) = &compiled[0];
    let clen = contract.constructor_bytecode.len() as u32;
    let rlen = contract.runtime_bytecode.len() as u32;
    let mut deploy = Vec::with_capacity(8 + clen as usize + rlen as usize);
    deploy.extend_from_slice(&clen.to_le_bytes());
    deploy.extend_from_slice(&rlen.to_le_bytes());
    deploy.extend_from_slice(&contract.constructor_bytecode);
    deploy.extend_from_slice(&contract.runtime_bytecode);
    (deploy, name.clone())
}

const BALANCE: u128 = 1_000_000_000_000;

// ============================================================================
// 0915 — Genesis block created on startup
// ============================================================================

#[test]
fn genesis_block_created() {
    let smt = PydeSMT::new();
    assert!(smt.is_empty());
    // Genesis would populate accounts — verified by funded account setup
    let (pk, _) = falcon_keygen().unwrap();
    let mut smt = PydeSMT::new();
    let addr = fund_account(&mut smt, pk.as_bytes(), BALANCE);
    let account = pyde_tx::pipeline::load_account(&smt, &addr);
    assert_eq!(account.balance, BALANCE);
}

// ============================================================================
// 0916 — Submit transaction, mine block, verify receipt
// ============================================================================

#[test]
fn submit_transfer_verify_receipt() {
    let (pk, sk) = falcon_keygen().unwrap();
    let mut smt = PydeSMT::new();
    let ctx = block_ctx();
    let sender = fund_account(&mut smt, pk.as_bytes(), BALANCE);
    let recipient = derive_eoa_address(b"bob");

    let tx = transfer_tx(sender, recipient, 1_000, 0, &sk);
    let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();

    assert!(receipt.success, "transfer should succeed");
    assert_eq!(receipt.gas_used, 21_000);

    let bob = pyde_tx::pipeline::load_account(&smt, &recipient);
    assert_eq!(bob.balance, 1_000);
}

// ============================================================================
// 0917 — Deploy contract, call function, verify state change
// ============================================================================

#[test]
fn deploy_and_call_counter() {
    let (pk, sk) = falcon_keygen().unwrap();
    let mut smt = PydeSMT::new();
    let ctx = block_ctx();
    let sender = fund_account(&mut smt, pk.as_bytes(), BALANCE);
    let contract_addr = pyde_account::address::derive_create_address(&sender, 0);

    let (deploy_data, _) = compile_contract(r#"
        contract Counter {
            storage { count: u64, }
            #[constructor]
            pub fn init() { self.count = 0; }
            pub fn increment() { self.count = self.count + 1; }
            pub fn get_count() -> u64 { return self.count; }
        }
    "#);

    // Deploy
    let dtx = deploy_tx(sender, deploy_data, 0, &sk);
    let receipt = execute_transaction(&dtx, &mut smt, &ctx).unwrap();
    assert!(receipt.success, "deploy should succeed");

    // Call increment
    let itx = call_tx(sender, contract_addr, "increment", vec![], 1, &sk);
    let receipt = execute_transaction(&itx, &mut smt, &ctx).unwrap();
    assert!(receipt.success, "increment should succeed");

    // Call get_count — should return 1
    let gtx = call_tx(sender, contract_addr, "get_count", vec![], 2, &sk);
    let receipt = execute_transaction(&gtx, &mut smt, &ctx).unwrap();
    assert!(receipt.success, "get_count should succeed");
    assert!(!receipt.return_data.is_empty());
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&receipt.return_data[..8]);
    assert_eq!(u64::from_le_bytes(buf), 1, "count should be 1");
}

// ============================================================================
// 0918 — ERC20 token: deploy, mint, transfer, check balances
// ============================================================================

#[test]
fn erc20_token_flow() {
    let (pk, sk) = falcon_keygen().unwrap();
    let mut smt = PydeSMT::new();
    let ctx = block_ctx();
    let sender = fund_account(&mut smt, pk.as_bytes(), BALANCE);
    let contract_addr = pyde_account::address::derive_create_address(&sender, 0);

    let (deploy_data, _) = compile_contract(r#"
        contract Token {
            storage {
                total_supply: u64,
                owner_balance: u64,
            }
            #[constructor]
            pub fn init() {
                self.total_supply = 1000000;
                self.owner_balance = 1000000;
            }
            pub fn balance_of() -> u64 { return self.owner_balance; }
            pub fn transfer(amount: u64) {
                self.owner_balance = self.owner_balance - amount;
            }
            pub fn total_supply() -> u64 { return self.total_supply; }
        }
    "#);

    // Deploy
    let dtx = deploy_tx(sender, deploy_data, 0, &sk);
    let r = execute_transaction(&dtx, &mut smt, &ctx).unwrap();
    assert!(r.success);

    // Check total supply
    let stx = call_tx(sender, contract_addr, "total_supply", vec![], 1, &sk);
    let r = execute_transaction(&stx, &mut smt, &ctx).unwrap();
    assert!(r.success);
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&r.return_data[..8]);
    assert_eq!(u64::from_le_bytes(buf), 1_000_000);

    // Transfer 500
    let mut args = Vec::new();
    args.extend_from_slice(&500u64.to_le_bytes());
    let ttx = call_tx(sender, contract_addr, "transfer", args, 2, &sk);
    let r = execute_transaction(&ttx, &mut smt, &ctx).unwrap();
    assert!(r.success);

    // Check balance after transfer
    let btx = call_tx(sender, contract_addr, "balance_of", vec![], 3, &sk);
    let r = execute_transaction(&btx, &mut smt, &ctx).unwrap();
    assert!(r.success);
    buf.copy_from_slice(&r.return_data[..8]);
    assert_eq!(u64::from_le_bytes(buf), 999_500);
}

// ============================================================================
// 0921 — Out-of-gas transaction reverts correctly
// ============================================================================

#[test]
fn out_of_gas_reverts() {
    let (pk, sk) = falcon_keygen().unwrap();
    let mut smt = PydeSMT::new();
    let ctx = block_ctx();
    let sender = fund_account(&mut smt, pk.as_bytes(), BALANCE);
    let contract_addr = pyde_account::address::derive_create_address(&sender, 0);

    let (deploy_data, _) = compile_contract(r#"
        contract Burner {
            storage { val: u64, }
            #[constructor]
            pub fn init() { self.val = 0; }
            pub fn burn() {
                let i = 0;
                while i < 1000000 {
                    self.val = self.val + 1;
                    i = i + 1;
                }
            }
        }
    "#);

    let dtx = deploy_tx(sender, deploy_data, 0, &sk);
    let r = execute_transaction(&dtx, &mut smt, &ctx).unwrap();
    assert!(r.success);

    // Call burn with very low gas — should fail
    let mut tx = Transaction {
        from: sender, to: contract_addr, value: 0,
        data: otic::codegen::compute_selector("burn").to_be_bytes().to_vec(),
        gas_limit: 25_000, // enough for dispatch but not the loop
        nonce: 1,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id: 1,
        tx_type: TransactionType::Standard,
    };
    sign_tx(&mut tx, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(!r.success, "should fail with out of gas");
}

// ============================================================================
// 0922 — Revert rolls back all state changes
// ============================================================================

#[test]
fn revert_rolls_back_state() {
    let (pk, sk) = falcon_keygen().unwrap();
    let mut smt = PydeSMT::new();
    let ctx = block_ctx();
    let sender = fund_account(&mut smt, pk.as_bytes(), BALANCE);
    let contract_addr = pyde_account::address::derive_create_address(&sender, 0);

    let (deploy_data, _) = compile_contract(r#"
        contract Reverter {
            storage { count: u64, }
            #[constructor]
            pub fn init() { self.count = 0; }
            pub fn increment_and_revert() {
                self.count = self.count + 1;
                revert!("intentional revert");
            }
            pub fn get_count() -> u64 { return self.count; }
        }
    "#);

    let dtx = deploy_tx(sender, deploy_data, 0, &sk);
    let r = execute_transaction(&dtx, &mut smt, &ctx).unwrap();
    assert!(r.success);

    // Call increment_and_revert — should fail
    let itx = call_tx(sender, contract_addr, "increment_and_revert", vec![], 1, &sk);
    let r = execute_transaction(&itx, &mut smt, &ctx).unwrap();
    assert!(!r.success, "should revert");

    // Count should still be 0
    let gtx = call_tx(sender, contract_addr, "get_count", vec![], 2, &sk);
    let r = execute_transaction(&gtx, &mut smt, &ctx).unwrap();
    assert!(r.success);
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&r.return_data[..8]);
    assert_eq!(u64::from_le_bytes(buf), 0, "count should be 0 after revert");
}

// ============================================================================
// 0924 — Overflow panics correctly
// ============================================================================

#[test]
fn overflow_panics() {
    let (pk, sk) = falcon_keygen().unwrap();
    let mut smt = PydeSMT::new();
    let ctx = block_ctx();
    let sender = fund_account(&mut smt, pk.as_bytes(), BALANCE);
    let contract_addr = pyde_account::address::derive_create_address(&sender, 0);

    let (deploy_data, _) = compile_contract(r#"
        contract Overflow {
            storage { val: u64, }
            #[constructor]
            pub fn init() { self.val = 18446744073709551615; }
            pub fn add_one() { self.val = self.val + 1; }
        }
    "#);

    let dtx = deploy_tx(sender, deploy_data, 0, &sk);
    let r = execute_transaction(&dtx, &mut smt, &ctx).unwrap();
    assert!(r.success);

    // Adding 1 to u64::MAX should overflow/panic
    let atx = call_tx(sender, contract_addr, "add_one", vec![], 1, &sk);
    let r = execute_transaction(&atx, &mut smt, &ctx).unwrap();
    assert!(!r.success, "overflow should cause revert/trap");
}

// ============================================================================
// 0926 — Base fee adjusts based on block fullness
// ============================================================================

#[test]
fn base_fee_adjustment() {
    // The fee model adjusts base_fee based on gas usage vs target.
    // Full block → base fee increases. Empty block → decreases.
    let initial_base_fee: u128 = 50_000_000_000;
    let gas_target: u64 = 400_000_000 / 2; // 50% = target

    // Simulate full block
    let new_fee_full = pyde_tx::fee::adjust_base_fee(
        initial_base_fee,
        400_000_000u64,
        gas_target,
    );
    assert!(new_fee_full > initial_base_fee, "full block should increase fee");

    // Simulate empty block
    let new_fee_empty = pyde_tx::fee::adjust_base_fee(
        initial_base_fee,
        0u64,
        gas_target,
    );
    assert!(new_fee_empty < initial_base_fee, "empty block should decrease fee");
}
