//! Full lifecycle test with chain_id=1 (production mode).
//! FALCON-512 signature verification ON for every transaction.
//! Tests: fund accounts, deploy contracts, call functions, transfers — all signed.

use pyde_account::address::derive_eoa_address;
use pyde_crypto::falcon::{falcon_keygen, falcon_sign};
use pyde_crypto::poseidon2::poseidon2_hash;
use pyde_state::smt::PersistentSMT;
use pyde_tx::pipeline::{execute_transaction, BlockContext};
use pyde_tx::types::*;
use std::time::Instant;

struct Acct {
    pk: pyde_crypto::falcon::FalconPublicKey,
    sk: pyde_crypto::falcon::FalconSecretKey,
    address: [u8; 32],
    nonce: u64,
}

fn sign(tx: &mut Transaction, sk: &pyde_crypto::falcon::FalconSecretKey) {
    tx.signature = falcon_sign(sk, &tx.hash()).unwrap().as_bytes().to_vec();
}

fn compile(src: &str) -> Vec<u8> {
    let c = otic::compile_all(src);
    let (_, cc) = &c[0];
    let mut d = Vec::new();
    d.extend_from_slice(&(cc.constructor_bytecode.len() as u32).to_le_bytes());
    d.extend_from_slice(&(cc.runtime_bytecode.len() as u32).to_le_bytes());
    d.extend_from_slice(&cc.constructor_bytecode);
    d.extend_from_slice(&cc.runtime_bytecode);
    d
}

fn sync_nonces(accounts: &mut [Acct], smt: &dyn pyde_state::smt::StateAccess) {
    for acc in accounts.iter_mut() {
        if let Some(data) = smt.get(&pyde_state::keys::nonce_key(&acc.address)) {
            // Audit 390: from_bytes is Option<Self>; canonical
            // store payloads always parse.
            let ns = pyde_account::nonce::NonceState::from_bytes(&data)
                .expect("nonce-key value must be a 10-byte NonceState");
            acc.nonce = ns.base + ns.used.trailing_ones() as u64;
        }
    }
}

#[test]
fn production_chain_id_1_full_lifecycle() {
    let tmp = tempfile::tempdir().unwrap();
    let mut smt = PersistentSMT::open(tmp.path().join("state").to_str().unwrap()).unwrap();

    // Production context: chain_id=1, sig verification ON
    let validator = derive_eoa_address(b"validator");
    let ctx = BlockContext {
        height: 1,
        timestamp: 1_700_000_000,
        base_fee: 100,
        block_gas_limit: 4_000_000_000,
        chain_id: 1,
        validator_address: validator,
        dev_skip_signature: false,
        block_sigs_pre_verified: false,
    };

    // Generate 10 accounts with FALCON keys
    let t0 = Instant::now();
    let mut accounts: Vec<Acct> = (0..10)
        .map(|_| {
            let (pk, sk) = falcon_keygen().unwrap();
            let address = derive_eoa_address(pk.as_bytes());
            Acct {
                pk,
                sk,
                address,
                nonce: 0,
            }
        })
        .collect();
    println!(
        "  Keygen (10 accounts): {:.0}ms",
        t0.elapsed().as_secs_f64() * 1000.0
    );

    // Fund accounts with AuthKeys::Single (enables sig verification)
    for acc in &accounts {
        let account = pyde_account::types::Account {
            address: acc.address,
            nonce: 0,
            balance: 10_000_000_000_000,
            code_hash: sparse_merkle_tree::H256::zero(),
            storage_root: sparse_merkle_tree::H256::zero(),
            account_type: pyde_account::types::AccountType::EOA,
            auth_keys: pyde_account::types::AuthKeys::Single(acc.pk.as_bytes().to_vec()),
            gas_tank: 0,
            key_nonce: 0,
        };
        smt.insert(
            pyde_state::keys::balance_key(&acc.address),
            account.to_bytes(),
        )
        .unwrap();
        smt.insert(
            pyde_state::keys::nonce_key(&acc.address),
            pyde_account::nonce::NonceState::new().to_bytes().to_vec(),
        )
        .unwrap();
    }

    let mut ok = 0;
    let fail = 0;

    // ── 1. Native transfer (chain_id=1, FALCON sig verified) ─────
    println!("\n  1. Native transfer (chain_id=1, FALCON verified)");
    {
        let to = accounts[1].address;
        let acc = &mut accounts[0];
        let from_slot = poseidon2_hash(&{
            let mut b = Vec::with_capacity(33);
            b.extend_from_slice(&acc.address);
            b.push(0x04);
            b
        })
        .to_bytes();
        let to_slot = poseidon2_hash(&{
            let mut b = Vec::with_capacity(33);
            b.extend_from_slice(&to);
            b.push(0x04);
            b
        })
        .to_bytes();
        let mut tx = Transaction {
            from: acc.address,
            to,
            value: 1_000_000,
            data: vec![],
            gas_limit: 21_000,
            nonce: acc.nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![
                AccessEntry {
                    address: acc.address,
                    reads: vec![],
                    writes: vec![from_slot],
                },
                AccessEntry {
                    address: to,
                    reads: vec![],
                    writes: vec![to_slot],
                },
            ],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };
        sign(&mut tx, &acc.sk);
        acc.nonce += 1;

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(
            receipt.success,
            "transfer should succeed with valid FALCON sig"
        );
        println!("    OK — gas={}", receipt.gas_used);
        ok += 1;
    }

    // ── 2. Deploy contract (chain_id=1, FALCON sig verified) ─────
    println!("  2. Deploy counter (chain_id=1, FALCON verified)");
    let counter_addr;
    {
        sync_nonces(&mut accounts, &smt);
        let acc = &mut accounts[2];
        let bin = compile(
            r#"
            contract Counter {
                storage { count: u64, }
                #[constructor] pub fn init() { self.count = 0; }
                pub fn increment() { self.count = self.count + 1; }
                pub fn set_count(n: u64) { self.count = n; }
                #[view] pub fn get_count() -> u64 { return self.count; }
            }
        "#,
        );
        let mut tx = Transaction {
            from: acc.address,
            to: [0u8; 32],
            value: 0,
            data: bin,
            gas_limit: 200_000_000,
            nonce: acc.nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Deploy,
        };
        sign(&mut tx, &acc.sk);
        acc.nonce += 1;

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(receipt.success, "deploy should succeed");
        assert_eq!(
            receipt.return_data.len(),
            32,
            "should return contract address"
        );
        counter_addr = {
            let mut a = [0u8; 32];
            a.copy_from_slice(&receipt.return_data);
            a
        };
        println!("    OK — addr={}", hex::encode(&counter_addr[..4]));
        ok += 1;
    }

    // ── 3. Contract call: increment (chain_id=1, FALCON verified) ──
    println!("  3. Contract call: increment (chain_id=1, FALCON verified)");
    {
        sync_nonces(&mut accounts, &smt);
        let acc = &mut accounts[3];
        let sel = otic::codegen::compute_selector("increment");
        let mut tx = Transaction {
            from: acc.address,
            to: counter_addr,
            value: 0,
            data: sel.to_be_bytes().to_vec(),
            gas_limit: 50_000_000,
            nonce: acc.nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![], // empty = no strict mode
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };
        sign(&mut tx, &acc.sk);
        acc.nonce += 1;

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(receipt.success, "increment should succeed");
        println!("    OK — gas={}", receipt.gas_used);
        ok += 1;
    }

    // ── 4. Contract call with args: set_count(42) ────────────────
    println!("  4. Contract call: set_count(42) (chain_id=1, FALCON verified)");
    {
        sync_nonces(&mut accounts, &smt);
        let acc = &mut accounts[4];
        let sel = otic::codegen::compute_selector("set_count");
        let mut data = sel.to_be_bytes().to_vec();
        data.extend_from_slice(&42u64.to_le_bytes());
        let mut tx = Transaction {
            from: acc.address,
            to: counter_addr,
            value: 0,
            data,
            gas_limit: 50_000_000,
            nonce: acc.nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };
        sign(&mut tx, &acc.sk);
        acc.nonce += 1;

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(receipt.success, "set_count(42) should succeed");
        println!("    OK — gas={}", receipt.gas_used);
        ok += 1;
    }

    // ── 5. Deploy vault (payable, events, u256, maps) ────────────
    println!("  5. Deploy vault (chain_id=1, FALCON verified)");
    let vault_addr;
    {
        sync_nonces(&mut accounts, &smt);
        let acc = &mut accounts[5];
        let bin = compile(
            r#"
            contract Vault {
                storage { total: u256, balances: Map<Address, u256>, }
                event Deposit { #[indexed] sender: Address, amount: u256, }
                #[constructor] pub fn init() { self.total = 0u256; }
                #[payable] pub fn deposit() {
                    self.balances[msg.sender] = self.balances[msg.sender] + msg.value;
                    self.total = self.total + msg.value;
                    emit Deposit { sender: msg.sender, amount: msg.value };
                }
                #[view] pub fn get_total() -> u256 { return self.total; }
            }
        "#,
        );
        let mut tx = Transaction {
            from: acc.address,
            to: [0u8; 32],
            value: 0,
            data: bin,
            gas_limit: 200_000_000,
            nonce: acc.nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Deploy,
        };
        sign(&mut tx, &acc.sk);
        acc.nonce += 1;

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(receipt.success, "vault deploy should succeed");
        vault_addr = {
            let mut a = [0u8; 32];
            a.copy_from_slice(&receipt.return_data);
            a
        };
        println!("    OK — addr={}", hex::encode(&vault_addr[..4]));
        ok += 1;
    }

    // ── 6. Payable call: deposit with value ──────────────────────
    println!("  6. Vault deposit with value (chain_id=1, FALCON verified)");
    {
        sync_nonces(&mut accounts, &smt);
        let acc = &mut accounts[6];
        let sel = otic::codegen::compute_selector("deposit");
        let mut tx = Transaction {
            from: acc.address,
            to: vault_addr,
            value: 500_000,
            data: sel.to_be_bytes().to_vec(),
            gas_limit: 50_000_000,
            nonce: acc.nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };
        sign(&mut tx, &acc.sk);
        acc.nonce += 1;

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        assert!(receipt.success, "vault deposit should succeed");
        assert!(!receipt.logs.is_empty(), "should emit Deposit event");
        println!(
            "    OK — gas={}, events={}",
            receipt.gas_used,
            receipt.logs.len()
        );
        ok += 1;
    }

    // ── 7. Invalid sig should FAIL ───────────────────────────────
    println!("  7. Invalid signature (should fail validation)");
    {
        sync_nonces(&mut accounts, &smt);
        let to = accounts[8].address;
        let acc = &mut accounts[7];
        let tx = Transaction {
            from: acc.address,
            to,
            value: 1_000,
            data: vec![],
            gas_limit: 21_000,
            nonce: acc.nonce,
            signature: vec![0xDE; 666], // garbage sig
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };
        // DON'T sign properly — use garbage sig

        let result = execute_transaction(&tx, &mut smt, &ctx);
        assert!(result.is_err(), "garbage sig should fail validation");
        println!("    OK — rejected as expected");
        ok += 1;
    }

    // ── 8. Wrong chain_id should FAIL ────────────────────────────
    println!("  8. Wrong chain_id (should fail validation)");
    {
        sync_nonces(&mut accounts, &smt);
        let to = accounts[9].address;
        let acc = &mut accounts[8];
        let mut tx = Transaction {
            from: acc.address,
            to,
            value: 1_000,
            data: vec![],
            gas_limit: 21_000,
            nonce: acc.nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 999, // WRONG chain_id
            tx_type: TransactionType::Standard,
        };
        sign(&mut tx, &acc.sk);

        let result = execute_transaction(&tx, &mut smt, &ctx);
        assert!(result.is_err(), "wrong chain_id should fail");
        println!("    OK — rejected as expected");
        ok += 1;
    }

    // ── 9. Multiple txs from same sender (nonce sequence) ────────
    println!("  9. Nonce sequence: 3 txs from same sender");
    {
        sync_nonces(&mut accounts, &smt);
        let to = accounts[1].address;
        for i in 0..3 {
            let acc = &mut accounts[0];
            let mut tx = Transaction {
                from: acc.address,
                to,
                value: 100,
                data: vec![],
                gas_limit: 21_000,
                nonce: acc.nonce,
                signature: vec![],
                fee_payer: FeePayer::Sender,
                access_list: vec![],
                deadline: None,
                chain_id: 1,
                tx_type: TransactionType::Standard,
            };
            sign(&mut tx, &acc.sk);
            acc.nonce += 1;
            let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
            assert!(receipt.success, "nonce {} should succeed", i);
        }
        println!("    OK — 3/3 nonce-sequenced txs succeeded");
        ok += 3;
    }

    println!("\n  RESULTS: {}/{} passed, {} failed", ok, ok + fail, fail);
    assert_eq!(fail, 0, "all tests must pass");
    println!("  chain_id=1 production signatures: VERIFIED\n");
}
