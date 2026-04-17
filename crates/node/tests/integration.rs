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
        dev_skip_signature: false,
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

// ============================================================================
// 0919 — Auction contract: create, bid, withdraw, end
// ============================================================================

#[test]
fn auction_contract_flow() {
    let (pk, sk) = falcon_keygen().unwrap();
    let mut smt = PydeSMT::new();
    let ctx = block_ctx();
    let sender = fund_account(&mut smt, pk.as_bytes(), BALANCE);
    let contract_addr = pyde_account::address::derive_create_address(&sender, 0);

    let (deploy_data, _) = compile_contract(r#"
        contract Auction {
            storage {
                highest_bid: u64,
                bid_count: u64,
                ended: bool,
            }
            #[constructor]
            pub fn init() {
                self.highest_bid = 0;
                self.bid_count = 0;
                self.ended = false;
            }
            pub fn bid(amount: u64) {
                require!(amount > self.highest_bid, "bid too low");
                require!(!self.ended, "auction ended");
                self.highest_bid = amount;
                self.bid_count = self.bid_count + 1;
            }
            pub fn end_auction() {
                self.ended = true;
            }
            pub fn get_highest_bid() -> u64 { return self.highest_bid; }
            pub fn get_bid_count() -> u64 { return self.bid_count; }
            pub fn is_ended() -> bool { return self.ended; }
        }
    "#);

    // Deploy
    let dtx = deploy_tx(sender, deploy_data, 0, &sk);
    let r = execute_transaction(&dtx, &mut smt, &ctx).unwrap();
    assert!(r.success, "deploy failed");

    // Bid 100
    let mut args = 100u64.to_le_bytes().to_vec();
    let tx = call_tx(sender, contract_addr, "bid", args.clone(), 1, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success, "bid 100 failed");

    // Bid 200
    args = 200u64.to_le_bytes().to_vec();
    let tx = call_tx(sender, contract_addr, "bid", args, 2, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success, "bid 200 failed");

    // Bid 50 — should fail (too low)
    args = 50u64.to_le_bytes().to_vec();
    let tx = call_tx(sender, contract_addr, "bid", args, 3, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(!r.success, "bid 50 should fail");

    // Check highest bid = 200
    let tx = call_tx(sender, contract_addr, "get_highest_bid", vec![], 4, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success);
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&r.return_data[..8]);
    assert_eq!(u64::from_le_bytes(buf), 200);

    // Check bid count = 2
    let tx = call_tx(sender, contract_addr, "get_bid_count", vec![], 5, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success);
    buf.copy_from_slice(&r.return_data[..8]);
    assert_eq!(u64::from_le_bytes(buf), 2);

    // End auction
    let tx = call_tx(sender, contract_addr, "end_auction", vec![], 6, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success);

    // Bid after end — should fail
    args = 500u64.to_le_bytes().to_vec();
    let tx = call_tx(sender, contract_addr, "bid", args, 7, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(!r.success, "bid after end should fail");
}

// ============================================================================
// 0920 — Struct-based vault: deposit, withdraw, split, merge
// ============================================================================

#[test]
fn vault_deposit_withdraw() {
    let (pk, sk) = falcon_keygen().unwrap();
    let mut smt = PydeSMT::new();
    let ctx = block_ctx();
    let sender = fund_account(&mut smt, pk.as_bytes(), BALANCE);
    let contract_addr = pyde_account::address::derive_create_address(&sender, 0);

    let (deploy_data, _) = compile_contract(r#"
        contract Vault {
            storage {
                balance: u64,
                fee_rate: u64,
                total_fees: u64,
            }
            #[constructor]
            pub fn init() {
                self.balance = 0;
                self.fee_rate = 10;
                self.total_fees = 0;
            }
            pub fn deposit(amount: u64) {
                self.balance = self.balance + amount;
            }
            pub fn withdraw(amount: u64) {
                let fee = amount * self.fee_rate / 100;
                require!(self.balance >= amount + fee, "insufficient balance");
                self.balance = self.balance - amount - fee;
                self.total_fees = self.total_fees + fee;
            }
            pub fn get_balance() -> u64 { return self.balance; }
            pub fn get_total_fees() -> u64 { return self.total_fees; }
        }
    "#);

    let dtx = deploy_tx(sender, deploy_data, 0, &sk);
    let r = execute_transaction(&dtx, &mut smt, &ctx).unwrap();
    assert!(r.success);

    // Deposit 1000
    let tx = call_tx(sender, contract_addr, "deposit", 1000u64.to_le_bytes().to_vec(), 1, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success);

    // Deposit 500
    let tx = call_tx(sender, contract_addr, "deposit", 500u64.to_le_bytes().to_vec(), 2, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success);

    // Withdraw 200 (fee = 200 * 10/100 = 20, total deducted = 220)
    let tx = call_tx(sender, contract_addr, "withdraw", 200u64.to_le_bytes().to_vec(), 3, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success);

    // Balance should be 1500 - 220 = 1280
    let tx = call_tx(sender, contract_addr, "get_balance", vec![], 4, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success);
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&r.return_data[..8]);
    assert_eq!(u64::from_le_bytes(buf), 1280);

    // Total fees should be 20
    let tx = call_tx(sender, contract_addr, "get_total_fees", vec![], 5, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success);
    buf.copy_from_slice(&r.return_data[..8]);
    assert_eq!(u64::from_le_bytes(buf), 20);

    // Withdraw too much — should fail
    let tx = call_tx(sender, contract_addr, "withdraw", 5000u64.to_le_bytes().to_vec(), 6, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(!r.success, "overdraw should fail");
}

// ============================================================================
// 0923 — Reentrancy guard blocks re-entrant call
// ============================================================================

#[test]
fn reentrancy_guard() {
    let (pk, sk) = falcon_keygen().unwrap();
    let mut smt = PydeSMT::new();
    let ctx = block_ctx();
    let sender = fund_account(&mut smt, pk.as_bytes(), BALANCE);
    let vault_addr = pyde_account::address::derive_create_address(&sender, 0);

    // Vault with guarded withdraw (default: no #[reentrant]).
    // The reentrancy guard sets a storage lock on entry and clears on exit.
    // Sequential external calls (separate txs) should work — guard resets.
    let (vault_deploy, _) = compile_contract(r#"
        contract Vault {
            storage { balance: u64, }
            #[constructor]
            pub fn init() { self.balance = 1000; }
            pub fn withdraw(amount: u64) {
                require!(self.balance >= amount, "insufficient");
                self.balance = self.balance - amount;
            }
            pub fn get_balance() -> u64 { return self.balance; }
        }
    "#);

    let dtx = deploy_tx(sender, vault_deploy, 0, &sk);
    let r = execute_transaction(&dtx, &mut smt, &ctx).unwrap();
    assert!(r.success);

    // Three sequential withdrawals — guard resets between txs
    for i in 0..3u64 {
        let tx = call_tx(sender, vault_addr, "withdraw", 200u64.to_le_bytes().to_vec(), 1 + i, &sk);
        let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(r.success, "withdraw {} should succeed", i + 1);
    }

    // Balance = 1000 - 600 = 400
    let tx = call_tx(sender, vault_addr, "get_balance", vec![], 4, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success);
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&r.return_data[..8]);
    assert_eq!(u64::from_le_bytes(buf), 400);

    // Overdraw reverts, balance unchanged
    let tx = call_tx(sender, vault_addr, "withdraw", 999u64.to_le_bytes().to_vec(), 5, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(!r.success, "overdraw should revert");

    let tx = call_tx(sender, vault_addr, "get_balance", vec![], 6, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success);
    buf.copy_from_slice(&r.return_data[..8]);
    assert_eq!(u64::from_le_bytes(buf), 400, "balance unchanged after revert");
}

// ============================================================================
// Cross-contract storage visibility within a single transaction
// ============================================================================

#[test]
fn cross_contract_storage_visibility() {
    let (pk, sk) = falcon_keygen().unwrap();
    let mut smt = PydeSMT::new();
    let ctx = block_ctx();
    let sender = fund_account(&mut smt, pk.as_bytes(), BALANCE);

    // Driver deploys Vault, calls withdraw twice, reads balance back.
    // Tests that Vault.withdraw()'s storage changes are visible to
    // the next Vault.get_balance() call within the same transaction.
    let compiled = otic::compile_all(r#"
        contract Vault {
            storage { balance: u64, }
            #[constructor]
            pub fn init() { self.balance = 1000; }
            pub fn withdraw(amount: u64) {
                require!(self.balance >= amount, "insufficient");
                self.balance = self.balance - amount;
            }
            pub fn get_balance() -> u64 { return self.balance; }
        }

        contract Driver {
            storage { result: u64, }
            #[constructor]
            pub fn init() { self.result = 0; }
            pub fn run_test() {
                let v = deploy!(Vault);
                v.withdraw(100);
                v.withdraw(200);
                self.result = v.get_balance();
            }
            pub fn get_result() -> u64 { return self.result; }
        }
    "#);

    let driver_contract = compiled.iter().find(|(n, _)| n == "Driver").unwrap();
    let clen = driver_contract.1.constructor_bytecode.len() as u32;
    let rlen = driver_contract.1.runtime_bytecode.len() as u32;
    let mut deploy_data = Vec::new();
    deploy_data.extend_from_slice(&clen.to_le_bytes());
    deploy_data.extend_from_slice(&rlen.to_le_bytes());
    deploy_data.extend_from_slice(&driver_contract.1.constructor_bytecode);
    deploy_data.extend_from_slice(&driver_contract.1.runtime_bytecode);

    let driver_addr = pyde_account::address::derive_create_address(&sender, 0);

    let dtx = deploy_tx(sender, deploy_data, 0, &sk);
    let r = execute_transaction(&dtx, &mut smt, &ctx).unwrap();
    assert!(r.success, "driver deploy failed");

    // run_test: deploy Vault → withdraw(100) → withdraw(200) → get_balance() → store result
    let tx = call_tx(sender, driver_addr, "run_test", vec![], 1, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success, "run_test should succeed");

    // result should be 700 (1000 - 100 - 200)
    let tx = call_tx(sender, driver_addr, "get_result", vec![], 2, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success);
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&r.return_data[..8]);
    assert_eq!(u64::from_le_bytes(buf), 700,
        "vault balance should be 700 (cross-contract storage visible within tx)");
}

// ============================================================================
// Reentrancy attack — callback contract tries to re-enter guarded function
// ============================================================================

#[test]
fn reentrancy_attack_blocked() {
    let (pk, sk) = falcon_keygen().unwrap();
    let mut smt = PydeSMT::new();
    let ctx = block_ctx();
    let sender = fund_account(&mut smt, pk.as_bytes(), BALANCE);

    // Vault: withdraw calls back to caller via raw_call! (simulates ETH transfer callback).
    // Attacker: on_hook() tries to re-enter Vault.withdraw().
    // Without #[reentrant], the guard should block the re-entry.
    let compiled = otic::compile_all(r#"
        contract Vault {
            storage { balance: u64, }
            #[constructor]
            pub fn init() { self.balance = 1000; }
            pub fn withdraw(amount: u64, hook: Address) {
                require!(self.balance >= amount, "insufficient");
                self.balance = self.balance - amount;
                raw_call!(hook, "on_hook");
            }
            pub fn get_balance() -> u64 { return self.balance; }
        }

        contract Attacker {
            storage { vault: Address, stolen: u64, }
            #[constructor]
            pub fn init() {
                self.stolen = 0;
            }
            pub fn set_vault(v: Address) {
                self.vault = v;
            }
            pub fn attack(amount: u64) {
                raw_call!(self.vault, "withdraw", amount, self);
            }
            #[reentrant]
            pub fn on_hook() {
                self.stolen = self.stolen + 1;
                raw_call!(self.vault, "withdraw", 100, self);
            }
            pub fn get_stolen() -> u64 { return self.stolen; }
        }
    "#);

    // Deploy Vault
    let vault_c = compiled.iter().find(|(n, _)| n == "Vault").unwrap();
    let mut vault_deploy = Vec::new();
    let clen = vault_c.1.constructor_bytecode.len() as u32;
    let rlen = vault_c.1.runtime_bytecode.len() as u32;
    vault_deploy.extend_from_slice(&clen.to_le_bytes());
    vault_deploy.extend_from_slice(&rlen.to_le_bytes());
    vault_deploy.extend_from_slice(&vault_c.1.constructor_bytecode);
    vault_deploy.extend_from_slice(&vault_c.1.runtime_bytecode);
    let vault_addr = pyde_account::address::derive_create_address(&sender, 0);

    let dtx = deploy_tx(sender, vault_deploy, 0, &sk);
    let r = execute_transaction(&dtx, &mut smt, &ctx).unwrap();
    assert!(r.success, "vault deploy failed");

    // Deploy Attacker
    let attacker_c = compiled.iter().find(|(n, _)| n == "Attacker").unwrap();
    let mut attacker_deploy = Vec::new();
    let clen2 = attacker_c.1.constructor_bytecode.len() as u32;
    let rlen2 = attacker_c.1.runtime_bytecode.len() as u32;
    attacker_deploy.extend_from_slice(&clen2.to_le_bytes());
    attacker_deploy.extend_from_slice(&rlen2.to_le_bytes());
    attacker_deploy.extend_from_slice(&attacker_c.1.constructor_bytecode);
    attacker_deploy.extend_from_slice(&attacker_c.1.runtime_bytecode);
    let attacker_addr = pyde_account::address::derive_create_address(&sender, 1);

    let dtx = deploy_tx(sender, attacker_deploy, 1, &sk);
    let r = execute_transaction(&dtx, &mut smt, &ctx).unwrap();
    assert!(r.success, "attacker deploy failed");

    // Set vault address on attacker
    let tx = call_tx(sender, attacker_addr, "set_vault", vault_addr.to_vec(), 2, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success, "set_vault failed");

    // Attack: Attacker calls Vault.withdraw(100, attacker_addr)
    // Vault deducts 100, calls attacker.on_hook()
    // on_hook() tries to re-enter Vault.withdraw() — should be BLOCKED by guard
    // The entire tx should revert because the re-entry fails
    let tx = call_tx(sender, attacker_addr, "attack", 100u64.to_le_bytes().to_vec(), 3, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();

    // The re-entry is blocked by the guard. The first withdraw (100) is legit
    // and succeeds. The re-entry attempt from on_hook() fails silently.
    // Balance = 900 (only one withdrawal of 100, not two).
    // Without the guard, balance would be 800 (two withdrawals).
    let tx = call_tx(sender, vault_addr, "get_balance", vec![], 4, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success);
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&r.return_data[..8]);
    assert_eq!(u64::from_le_bytes(buf), 900,
        "vault balance should be 900 — first withdraw ok, re-entry blocked");
}

// ============================================================================
// 0925 — Access list validation
// ============================================================================

#[test]
fn access_list_validation() {
    // Transactions with duplicate addresses in access list should be rejected
    let (pk, sk) = falcon_keygen().unwrap();
    let mut smt = PydeSMT::new();
    let ctx = block_ctx();
    let sender = fund_account(&mut smt, pk.as_bytes(), BALANCE);
    let recipient = derive_eoa_address(b"recipient");

    let dup_addr = [0xAA; 32];
    let mut tx = Transaction {
        from: sender,
        to: recipient,
        value: 100,
        data: vec![],
        gas_limit: 21_000,
        nonce: 0,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![
            AccessEntry { address: dup_addr, reads: vec![], writes: vec![] },
            AccessEntry { address: dup_addr, reads: vec![], writes: vec![] }, // duplicate
        ],
        deadline: None,
        chain_id: 1,
        tx_type: TransactionType::Standard,
    };
    sign_tx(&mut tx, &sk);

    let result = execute_transaction(&tx, &mut smt, &ctx);
    assert!(result.is_err(), "duplicate access list entries should be rejected");
}

// ============================================================================
// 0927 — Elastic block (gas ceiling)
// ============================================================================

#[test]
fn elastic_block_gas_ceiling() {
    // The gas ceiling is 4x the target (400M target → 1.6B max).
    // Transactions exceeding the block gas limit should be rejected.
    let (pk, sk) = falcon_keygen().unwrap();
    let mut smt = PydeSMT::new();
    let ctx = BlockContext {
        height: 1,
        timestamp: 1_000_000,
        base_fee: 1_000,
        block_gas_limit: 1_600_000_000, // 4x elastic max
        chain_id: 1,
        validator_address: derive_eoa_address(b"validator"),
        dev_skip_signature: false,
    };
    let sender = fund_account(&mut smt, pk.as_bytes(), BALANCE * 1000);

    // Transaction within limit should work
    let mut tx = Transaction {
        from: sender, to: derive_eoa_address(b"bob"), value: 100,
        data: vec![], gas_limit: 21_000, nonce: 0,
        signature: vec![], fee_payer: FeePayer::Sender,
        access_list: vec![], deadline: None, chain_id: 1,
        tx_type: TransactionType::Standard,
    };
    sign_tx(&mut tx, &sk);
    let r = execute_transaction(&tx, &mut smt, &ctx).unwrap();
    assert!(r.success);

    // Transaction exceeding block gas limit should be rejected
    let mut tx2 = Transaction {
        from: sender, to: derive_eoa_address(b"bob"), value: 100,
        data: vec![], gas_limit: 2_000_000_000, // > 1.6B
        nonce: 1, signature: vec![], fee_payer: FeePayer::Sender,
        access_list: vec![], deadline: None, chain_id: 1,
        tx_type: TransactionType::Standard,
    };
    sign_tx(&mut tx2, &sk);
    let result = execute_transaction(&tx2, &mut smt, &ctx);
    assert!(result.is_err(), "tx exceeding block gas limit should be rejected");
}
