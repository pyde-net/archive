//! Comprehensive throughput benchmark — measures REAL TPS with diverse workloads.

use pyde_account::address::derive_eoa_address;
use pyde_crypto::falcon::falcon_keygen;
use pyde_tx::parallel::schedule;
use pyde_tx::pipeline::{execute_transaction, BlockContext};
use pyde_tx::types::*;
use std::time::Instant;

fn block_ctx() -> BlockContext {
    BlockContext {
        height: 100, timestamp: 1_000_000,
        base_fee: 1, // minimal for benchmark
        block_gas_limit: 4_000_000_000,
        chain_id: 31337, // devnet — skips sig verification
        validator_address: derive_eoa_address(b"validator"),
    }
}

fn fund_account(smt: &mut pyde_state::smt::PydeSMT, idx: u64) -> ([u8; 32], u64) {
    let seed = idx.to_le_bytes();
    let mut pk_bytes = vec![0u8; 897];
    pk_bytes[..8].copy_from_slice(&seed);
    let address = derive_eoa_address(&pk_bytes);
    let mut account = pyde_account::types::Account {
        address, nonce: 0, balance: 1_000_000_000_000_000,
        code_hash: sparse_merkle_tree::H256::zero(),
        storage_root: sparse_merkle_tree::H256::zero(),
        account_type: pyde_account::types::AccountType::EOA,
        auth_keys: pyde_account::types::AuthKeys::None,
        gas_tank: 0, key_nonce: 0,
    };
    let key = pyde_state::keys::balance_key(&address);
    smt.insert(key, account.to_bytes()).unwrap();
    let nonce_key = pyde_state::keys::nonce_key(&address);
    smt.insert(nonce_key, pyde_account::nonce::NonceState::new().to_bytes().to_vec()).unwrap();
    (address, 0)
}

fn make_transfer(from: [u8; 32], to: [u8; 32], nonce: u64) -> Transaction {
    Transaction {
        from, to, value: 1_000, data: vec![],
        gas_limit: 21_000, nonce, signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![
            AccessEntry { address: from, reads: vec![], writes: vec![[0x00; 32]] },
            AccessEntry { address: to, reads: vec![], writes: vec![[0x00; 32]] },
        ],
        deadline: None, chain_id: 31337, tx_type: TransactionType::Standard,
    }
}

fn compile(source: &str) -> Vec<u8> {
    let compiled = otic::compile_all(source);
    let (_, c) = &compiled[0];
    let mut data = Vec::new();
    data.extend_from_slice(&(c.constructor_bytecode.len() as u32).to_le_bytes());
    data.extend_from_slice(&(c.runtime_bytecode.len() as u32).to_le_bytes());
    data.extend_from_slice(&c.constructor_bytecode);
    data.extend_from_slice(&c.runtime_bytecode);
    data
}

fn make_deploy(from: [u8; 32], deploy_data: Vec<u8>, nonce: u64) -> Transaction {
    Transaction {
        from, to: [0u8; 32], value: 0, data: deploy_data,
        gas_limit: 100_000_000, nonce, signature: vec![],
        fee_payer: FeePayer::Sender, access_list: vec![],
        deadline: None, chain_id: 31337, tx_type: TransactionType::Deploy,
    }
}

fn make_call(from: [u8; 32], to: [u8; 32], method: &str, args: Vec<u8>, nonce: u64) -> Transaction {
    let selector = otic::codegen::compute_selector(method);
    let mut data = selector.to_be_bytes().to_vec();
    data.extend_from_slice(&args);
    Transaction {
        from, to, value: 0, data, gas_limit: 10_000_000, nonce,
        signature: vec![], fee_payer: FeePayer::Sender,
        access_list: vec![
            AccessEntry { address: to, reads: vec![[0x01; 32]], writes: vec![[0x01; 32]] },
        ],
        deadline: None, chain_id: 31337, tx_type: TransactionType::Standard,
    }
}

fn run_benchmark(label: &str, txs: &[Transaction], smt: &mut pyde_state::smt::PydeSMT, ctx: &BlockContext) {
    let sched = schedule(txs);
    let start = Instant::now();
    for tx in txs {
        let _ = execute_transaction(tx, smt, ctx);
    }
    let elapsed = start.elapsed();
    let tps = txs.len() as f64 / elapsed.as_secs_f64();
    println!("  {}: {} txs, {} groups, {:.1}ms, {:.0} TPS",
        label, txs.len(), sched.group_count(), elapsed.as_secs_f64() * 1000.0, tps);
}

#[test]
fn benchmark_throughput() {
    let mut smt = pyde_state::smt::PydeSMT::new();
    let ctx = block_ctx();

    // Fund 100 accounts (to spread nonces across senders)
    let mut accounts: Vec<([u8; 32], u64)> = Vec::new();
    for i in 0..100 {
        accounts.push(fund_account(&mut smt, i));
    }

    println!("\n========== PYDE THROUGHPUT BENCHMARK ==========\n");

    // --- 1. Pure transfers (different senders = parallel potential) ---
    {
        let mut txs = Vec::new();
        for i in 0..500 {
            let (from, _) = accounts[i % 100];
            let (to, _) = accounts[(i + 1) % 100];
            let nonce = (i / 100) as u64;
            txs.push(make_transfer(from, to, nonce));
        }
        run_benchmark("Pure transfers (500)", &txs, &mut smt, &ctx);
    }

    // --- 2. Contract deployments ---
    let counter_deploy = compile(r#"
        contract Counter {
            storage { count: u64, }
            #[constructor] pub fn init() { self.count = 0; }
            pub fn increment() { self.count = self.count + 1; }
            pub fn get_count() -> u64 { return self.count; }
        }
    "#);
    {
        let mut txs = Vec::new();
        for i in 0..20 {
            let (from, _) = accounts[i % 100];
            txs.push(make_deploy(from, counter_deploy.clone(), (i / 100 + 5) as u64));
        }
        run_benchmark("Deploys (20)", &txs, &mut smt, &ctx);
    }

    // --- 3. Contract calls ---
    {
        // Deploy one contract first
        let (deployer, _) = accounts[0];
        let dtx = make_deploy(deployer, counter_deploy.clone(), 10);
        let receipt = execute_transaction(&dtx, &mut smt, &ctx).unwrap();
        let contract = {
            let mut a = [0u8; 32];
            if receipt.return_data.len() == 32 { a.copy_from_slice(&receipt.return_data); }
            a
        };

        let mut txs = Vec::new();
        for i in 0..200 {
            let (from, _) = accounts[i % 100];
            txs.push(make_call(from, contract, "increment", vec![], (i / 100 + 11) as u64));
        }
        run_benchmark("Contract calls (200)", &txs, &mut smt, &ctx);
    }

    // --- 4. Math-heavy ---
    let math_deploy = compile(r#"
        contract MathHeavy {
            storage { result: u64, }
            #[constructor] pub fn init() { self.result = 0; }
            pub fn compute(n: u64) {
                let mut sum: u64 = 0;
                for i in 0..n { sum = sum + i * i; }
                self.result = sum;
            }
        }
    "#);
    {
        let (deployer, _) = accounts[1];
        let dtx = make_deploy(deployer, math_deploy.clone(), 13);
        let receipt = execute_transaction(&dtx, &mut smt, &ctx).unwrap();
        let math_addr = {
            let mut a = [0u8; 32];
            if receipt.return_data.len() == 32 { a.copy_from_slice(&receipt.return_data); }
            a
        };

        let mut txs = Vec::new();
        for i in 0..50 {
            let (from, _) = accounts[i % 100];
            txs.push(make_call(from, math_addr, "compute", 100u64.to_le_bytes().to_vec(), (i / 100 + 14) as u64));
        }
        run_benchmark("Math-heavy (50, n=100)", &txs, &mut smt, &ctx);
    }

    // --- 5. Mixed realistic block ---
    {
        let (deployer, _) = accounts[2];
        let dtx = make_deploy(deployer, counter_deploy.clone(), 15);
        let receipt = execute_transaction(&dtx, &mut smt, &ctx).unwrap();
        let caddr = {
            let mut a = [0u8; 32];
            if receipt.return_data.len() == 32 { a.copy_from_slice(&receipt.return_data); }
            a
        };

        let mut txs = Vec::new();
        // 300 transfers from different senders
        for i in 0..300 {
            let (from, _) = accounts[i % 100];
            let (to, _) = accounts[(i + 50) % 100];
            txs.push(make_transfer(from, to, (i / 100 + 16) as u64));
        }
        // 150 contract calls from different senders
        for i in 0..150 {
            let (from, _) = accounts[i % 100];
            txs.push(make_call(from, caddr, "increment", vec![], (i / 100 + 19) as u64));
        }
        // 50 deploys
        for i in 0..50 {
            let (from, _) = accounts[i % 100];
            txs.push(make_deploy(from, counter_deploy.clone(), (i / 100 + 22) as u64));
        }
        run_benchmark("Mixed (300 xfer + 150 call + 50 deploy)", &txs, &mut smt, &ctx);
    }

    println!("\n========== BENCHMARK COMPLETE ==========\n");
}
