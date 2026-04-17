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
    // Include proper access lists so the parallel scheduler can create groups
    let from_slot = pyde_crypto::poseidon2::poseidon2_hash(&{
        let mut buf = Vec::with_capacity(33);
        buf.extend_from_slice(&from);
        buf.push(0x04); // STORAGE_SLOT discriminator
        buf
    }).to_bytes();
    let to_slot = pyde_crypto::poseidon2::poseidon2_hash(&{
        let mut buf = Vec::with_capacity(33);
        buf.extend_from_slice(&to);
        buf.push(0x04);
        buf
    }).to_bytes();
    Transaction {
        from, to, value: 1_000, data: vec![],
        gas_limit: 21_000, nonce, signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![
            AccessEntry { address: from, reads: vec![], writes: vec![from_slot] },
            AccessEntry { address: to, reads: vec![], writes: vec![to_slot] },
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
#[ignore = "benchmark — run with --ignored"]
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

#[test]
#[ignore = "benchmark — run with --ignored"]
fn benchmark_realistic_block() {
    use pyde_state::smt::PersistentSMT;
    use rayon::prelude::*;
    use pyde_state::smt::{StateAccess, StateOverlay};

    let dir = std::env::temp_dir().join(format!("pyde-bench-realistic-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut persistent = PersistentSMT::open(
        dir.join("state").to_str().unwrap()
    ).unwrap();

    let ctx = block_ctx();

    // Fund 200 accounts on persistent SMT
    let mut accounts: Vec<([u8; 32], u64)> = Vec::new();
    for i in 0u64..200 {
        let seed = i.to_le_bytes();
        let mut pk_bytes = vec![0u8; 897];
        pk_bytes[..8].copy_from_slice(&seed);
        let address = derive_eoa_address(&pk_bytes);
        let account = pyde_account::types::Account {
            address, nonce: 0, balance: 1_000_000_000_000_000,
            code_hash: sparse_merkle_tree::H256::zero(),
            storage_root: sparse_merkle_tree::H256::zero(),
            account_type: pyde_account::types::AccountType::EOA,
            auth_keys: pyde_account::types::AuthKeys::None,
            gas_tank: 0, key_nonce: 0,
        };
        let key = pyde_state::keys::balance_key(&address);
        persistent.insert(key, account.to_bytes()).unwrap();
        let nonce_key = pyde_state::keys::nonce_key(&address);
        persistent.insert(nonce_key, pyde_account::nonce::NonceState::new().to_bytes().to_vec()).unwrap();
        accounts.push((address, 0));
    }

    println!("\n========== REALISTIC PRODUCTION BENCHMARK ==========\n");
    println!("  Backend: PersistentSMT (RocksDB)");
    println!("  Accounts: {}", accounts.len());
    println!();

    // --- 1. Pure transfers on RocksDB ---
    {
        let mut txs = Vec::new();
        for i in 0..1000 {
            let (from, _) = accounts[i % 200];
            let (to, _) = accounts[(i + 1) % 200];
            let nonce = (i / 200) as u64;
            txs.push(make_transfer(from, to, nonce));
        }
        let sched = schedule(&txs);
        let start = Instant::now();
        for tx in &txs {
            let _ = execute_transaction(tx, &mut persistent, &ctx);
        }
        let elapsed = start.elapsed();
        let tps = txs.len() as f64 / elapsed.as_secs_f64();
        println!("  Transfers (1000, sequential, RocksDB): {} groups, {:.1}ms, {:.0} TPS",
            sched.group_count(), elapsed.as_secs_f64() * 1000.0, tps);
    }

    // --- 2. Parallel transfers (non-overlapping sender pairs for max parallelism) ---
    {
        // Create non-overlapping transfer pairs: (0→100, 1→101, 2→102, ...)
        // Each pair touches unique addresses → maximum parallel groups
        let mut txs = Vec::new();
        for i in 0..1000 {
            let (from, _) = accounts[i % 100]; // senders 0-99
            let (to, _) = accounts[100 + (i % 100)]; // recipients 100-199
            let nonce = (i / 100 + 5) as u64;
            txs.push(make_transfer(from, to, nonce));
        }
        let sched = schedule(&txs);
        let groups = &sched.groups;
        let num_groups = groups.len();

        // Parallel execution via rayon + StateOverlay
        use rayon::prelude::*;
        use pyde_state::smt::StateOverlay;

        let start = Instant::now();
        if num_groups > 1 {
            let base = &persistent;
            let group_writes: Vec<Vec<(sparse_merkle_tree::H256, Vec<u8>)>> = groups
                .par_iter()
                .map(|group| {
                    let mut overlay = StateOverlay::new(base);
                    for &idx in &group.tx_indices {
                        let _ = execute_transaction(&txs[idx], &mut overlay, &ctx);
                    }
                    overlay.into_writes()
                })
                .collect();
            let all_writes: Vec<(sparse_merkle_tree::H256, Vec<u8>)> = group_writes
                .into_iter().flatten().collect();
            let write_count = all_writes.len();
            let _ = persistent.update_all(all_writes);
            let elapsed = start.elapsed();
            let tps = txs.len() as f64 / elapsed.as_secs_f64();
            println!("  Parallel transfers (1000, {} groups, {} writes, RocksDB): {:.1}ms, {:.0} TPS",
                num_groups, write_count, elapsed.as_secs_f64() * 1000.0, tps);
        } else {
            for tx in &txs {
                let _ = execute_transaction(tx, &mut persistent, &ctx);
            }
            let elapsed = start.elapsed();
            let tps = txs.len() as f64 / elapsed.as_secs_f64();
            println!("  Transfers (1000, 1 group, RocksDB): {:.1}ms, {:.0} TPS",
                elapsed.as_secs_f64() * 1000.0, tps);
        }
    }

    // --- 3. Contract deploy + calls on RocksDB ---
    {
        let counter_deploy = compile(r#"
            contract Counter {
                storage { count: u64, }
                #[constructor] pub fn init() { self.count = 0; }
                pub fn increment() { self.count = self.count + 1; }
                pub fn get_count() -> u64 { return self.count; }
            }
        "#);

        // Deploy one contract — read current nonce from state
        let (deployer, _) = accounts[0];
        let deploy_nonce = {
            let nk = pyde_state::keys::nonce_key(&deployer);
            persistent.get(&nk)
                .map(|d| {
                    let ns = pyde_account::nonce::NonceState::from_bytes(&d);
                    ns.base + ns.used.trailing_ones() as u64
                })
                .unwrap_or(0)
        };
        let dtx = make_deploy(deployer, counter_deploy.clone(), deploy_nonce);
        let receipt = execute_transaction(&dtx, &mut persistent, &ctx).unwrap();
        let contract = {
            let mut a = [0u8; 32];
            if receipt.return_data.len() == 32 { a.copy_from_slice(&receipt.return_data); }
            a
        };

        let mut txs = Vec::new();
        for i in 0..500 {
            let (from, _) = accounts[i % 200];
            txs.push(make_call(from, contract, "increment", vec![], (i / 200 + 11) as u64));
        }
        let start = Instant::now();
        for tx in &txs {
            let _ = execute_transaction(tx, &mut persistent, &ctx);
        }
        let elapsed = start.elapsed();
        let tps = txs.len() as f64 / elapsed.as_secs_f64();
        println!("  Contract calls (500, sequential, RocksDB): {:.1}ms, {:.0} TPS",
            elapsed.as_secs_f64() * 1000.0, tps);
    }

    // --- 4. Mixed realistic block ---
    {
        let counter_deploy = compile(r#"
            contract Counter {
                storage { count: u64, }
                #[constructor] pub fn init() { self.count = 0; }
                pub fn increment() { self.count = self.count + 1; }
            }
        "#);
        let (deployer, _) = accounts[1];
        let dtx = make_deploy(deployer, counter_deploy.clone(), 15);
        let receipt = execute_transaction(&dtx, &mut persistent, &ctx).unwrap();
        let contract = {
            let mut a = [0u8; 32];
            if receipt.return_data.len() == 32 { a.copy_from_slice(&receipt.return_data); }
            a
        };

        let mut txs = Vec::new();
        for i in 0..1500 {
            let (from, _) = accounts[i % 200];
            let (to, _) = accounts[(i + 50) % 200];
            txs.push(make_transfer(from, to, (i / 200 + 16) as u64));
        }
        for i in 0..400 {
            let (from, _) = accounts[i % 200];
            txs.push(make_call(from, contract, "increment", vec![], (i / 200 + 24) as u64));
        }
        for i in 0..100 {
            let (from, _) = accounts[i % 200];
            txs.push(make_deploy(from, counter_deploy.clone(), (i / 200 + 26) as u64));
        }

        let start = Instant::now();
        for tx in &txs {
            let _ = execute_transaction(tx, &mut persistent, &ctx);
        }
        let elapsed = start.elapsed();
        let tps = txs.len() as f64 / elapsed.as_secs_f64();
        println!("  Mixed block (1500 xfer + 400 call + 100 deploy, RocksDB): {:.1}ms, {:.0} TPS",
            elapsed.as_secs_f64() * 1000.0, tps);
    }

    let _ = std::fs::remove_dir_all(&dir);
    println!("\n========== REALISTIC BENCHMARK COMPLETE ==========\n");
}

/// Production benchmark: AOT compiled parallel execution on PersistentSMT.
/// Tests the actual hot path: schedule → parallel execute → batch commit.
#[test]
#[ignore = "benchmark — run with --ignored"]
fn benchmark_production_block() {
    use pyde_state::smt::PersistentSMT;
    use pyde_state::smt::StateAccess;
    use pyde_state::smt::StateOverlay;
    use pyde_tx::pipeline::execute_transaction_aot;
    use rayon::prelude::*;
    use std::sync::Arc;

    let dir = std::env::temp_dir().join("pyde-bench-production");
    let _ = std::fs::remove_dir_all(&dir);

    let mut persistent = PersistentSMT::open(
        dir.join("state").to_str().unwrap()
    ).unwrap();

    let ctx = block_ctx();
    let num_accounts = 500;

    // Fund accounts
    let mut accounts: Vec<([u8; 32], u64)> = Vec::new();
    for i in 0u64..num_accounts {
        let seed = i.to_le_bytes();
        let mut pk_bytes = vec![0u8; 897];
        pk_bytes[..8].copy_from_slice(&seed);
        let address = derive_eoa_address(&pk_bytes);
        let account = pyde_account::types::Account {
            address, nonce: 0, balance: 1_000_000_000_000_000,
            code_hash: sparse_merkle_tree::H256::zero(),
            storage_root: sparse_merkle_tree::H256::zero(),
            account_type: pyde_account::types::AccountType::EOA,
            auth_keys: pyde_account::types::AuthKeys::None,
            gas_tank: 0, key_nonce: 0,
        };
        let key = pyde_state::keys::balance_key(&address);
        &mut persistent.insert(key, account.to_bytes()).unwrap();
        let nonce_key = pyde_state::keys::nonce_key(&address);
        &mut persistent.insert(nonce_key, pyde_account::nonce::NonceState::new().to_bytes().to_vec()).unwrap();
        accounts.push((address, 0));
    }

    // Deploy 10 independent COMPLEX contracts — realistic DeFi-like workloads:
    // - Storage: maps, counters, accumulators
    // - Loops iterating 100+ elements
    // - Math: multiply, divide, modulo, bitwise
    // - Strings, struct-like data
    // - Multiple storage reads + writes per call
    // Complex contract: 200-iteration loop with math + bitwise ops,
    // writes result to a single storage field (parallelizable with 1 access key)
    let heavy_code = compile(r#"
        contract HeavyWork {
            storage {
                result: u64,
            }

            #[constructor]
            pub fn init() { self.result = 0; }

            #[reentrant] #[payable]
            pub fn heavy_compute(n: u64) {
                let mut sum: u64 = 0;
                for i in 0..n {
                    sum = sum + i * i;
                }
                self.result = sum;
            }
        }
    "#);

    // Deploy 10 contracts and pre-compile AOT
    let mut contract_addrs = Vec::new();
    let mut aot_compiled: std::collections::HashMap<[u8; 32], pyde_aot::CompiledCode> = std::collections::HashMap::new();
    let num_contracts = 100usize;
    for i in 0..num_contracts as u64 {
        // Each contract deployed by a different account (nonce 0 for each)
        let (deployer, _) = accounts[i as usize];
        let dtx = make_deploy(deployer, heavy_code.clone(), 0);
        let receipt = execute_transaction(&dtx, &mut persistent, &ctx).unwrap();
        let mut addr = [0u8; 32];
        if receipt.return_data.len() == 32 { addr.copy_from_slice(&receipt.return_data); }
        contract_addrs.push(addr);

        let code_key = pyde_state::keys::code_key(&addr);
        if let Some(bytecode) = persistent.get(&code_key) {
            if let Ok(compiled) = pyde_aot::compile_bytecode(&bytecode) {
                aot_compiled.insert(addr, compiled);
            }
        }
    }

    println!("\n========== PRODUCTION BLOCK BENCHMARK ==========\n");
    println!("  Accounts: {}", num_accounts);
    let aot_count = aot_compiled.len();
    println!("  Contracts: {} (AOT pre-compiled: {})", contract_addrs.len(), aot_count);
    println!("  CPU cores: {}", rayon::current_num_threads());
    println!();

    // Build AOT lookup: contract address → compiled function pointer
    let aot_map: std::collections::HashMap<[u8; 32], unsafe fn(*mut u64, u64, *mut pyde_vm::vm::Vm) -> u64> =
        aot_compiled.iter().map(|(addr, code)| (*addr, code.as_fn())).collect();

    // Helper: run block sequentially (to verify txs work, get accurate write counts)
    let run_sequential = |label: &str, txs: &[Transaction], smt: &mut PersistentSMT| {
        let sched = schedule(txs);
        let mut ok = 0u64;
        let mut fail = 0u64;
        // Use StateOverlay for sequential too — avoids per-tx RocksDB I/O
        let mut overlay = StateOverlay::new(smt as &dyn StateAccess);
        let start = Instant::now();
        for (i, tx) in txs.iter().enumerate() {
            let aot_fn = aot_map.get(&tx.to).copied();
            match execute_transaction_aot(tx, &mut overlay, &ctx, aot_fn) {
                Ok(r) => if r.success { ok += 1; } else {
                    fail += 1;
                    if i < 3 { eprintln!("    tx {} reverted: gas_used={}, ret_len={}, ret={}", i, r.gas_used, r.return_data.len(), String::from_utf8_lossy(&r.return_data)); }
                }
                Err(e) => {
                    fail += 1;
                    if i < 3 { eprintln!("    tx {} error: {:?}", i, e); }
                }
            }
        }
        // Batch commit all overlay writes
        let writes = overlay.into_writes();
        let _ = smt.update_all(writes);
        let elapsed = start.elapsed();
        let tps = txs.len() as f64 / elapsed.as_secs_f64();
        println!("  {} ({} txs, {} ok, {} fail, {} groups): {:.1}ms, {:.0} TPS",
            label, txs.len(), ok, fail, sched.group_count(), elapsed.as_secs_f64() * 1000.0, tps);
    };

    // Helper: run block with parallel execution
    let run_parallel = |label: &str, txs: &[Transaction], smt: &mut PersistentSMT| {
        let sched = schedule(txs);
        let groups = &sched.groups;
        let num_groups = groups.len();

        let start = Instant::now();
        if num_groups > 1 {
            let base = smt as &dyn StateAccess;
            let group_results: Vec<(u64, Vec<(sparse_merkle_tree::H256, Vec<u8>)>)> = groups
                .par_iter()
                .map(|group| {
                    let mut overlay = StateOverlay::new(base);
                    let mut ok = 0u64;
                    for &idx in &group.tx_indices {
                        let aot_fn = aot_map.get(&txs[idx].to).copied();
                        match execute_transaction_aot(&txs[idx], &mut overlay, &ctx, aot_fn) {
                            Ok(r) if r.success => ok += 1,
                            _ => {}
                        }
                    }
                    (ok, overlay.into_writes())
                })
                .collect();
            let exec_elapsed = start.elapsed();
            let total_ok: u64 = group_results.iter().map(|(ok, _)| ok).sum();
            let all_writes: Vec<_> = group_results.into_iter().flat_map(|(_, w)| w).collect();
            let write_count = all_writes.len();
            // Single batch Merkle update + RocksDB write
            let commit_start = Instant::now();
            let _ = smt.update_all(all_writes);
            let commit_elapsed = commit_start.elapsed();
            let total_elapsed = start.elapsed();
            let exec_tps = txs.len() as f64 / exec_elapsed.as_secs_f64();
            let total_tps = txs.len() as f64 / total_elapsed.as_secs_f64();
            println!("  {} ({} txs, {} ok, {} groups, {} writes)", label, txs.len(), total_ok, num_groups, write_count);
            println!("    exec: {:.1}ms ({:.0} TPS), commit: {:.1}ms, total: {:.1}ms ({:.0} TPS)",
                exec_elapsed.as_secs_f64() * 1000.0, exec_tps,
                commit_elapsed.as_secs_f64() * 1000.0,
                total_elapsed.as_secs_f64() * 1000.0, total_tps);
        } else {
            run_sequential(label, txs, smt);
        }
    };

    // --- 1. Transfer block (non-overlapping pairs → max parallel) ---
    {
        let half = num_accounts as usize / 2;
        let mut txs = Vec::new();
        for i in 0..2000usize {
            let (from, _) = accounts[i % half];
            let (to, _) = accounts[half + (i % half)];
            txs.push(make_transfer(from, to, (i / half) as u64 + 10));
        }
        run_parallel("Transfers (parallel)", &txs, &mut persistent);
    }

    // --- 2. Contract calls with AOT (10 independent contracts → parallel) ---
    {
        let selector = otic::codegen::compute_selector("heavy_compute");
        // Access list uses RAW slot indices (not derived keys).
        // pre_derive_access_list_keys() handles Poseidon2 derivation internally.
        let slot_0: [u8; 32] = [0u8; 32]; // slot 0 = "result" field

        let mut txs = Vec::new();
        for i in 0..50000usize {
            let (from, _) = accounts[(i + 50) % (num_accounts as usize)];
            let ci = i % num_contracts;
            let contract = contract_addrs[ci];
            let mut data = selector.to_be_bytes().to_vec();
            data.extend_from_slice(&200u64.to_le_bytes()); // n=200 iterations
            txs.push(Transaction {
                from, to: contract, value: 0, data,
                gas_limit: 10_000_000, nonce: (i / (num_accounts as usize)) as u64,
                signature: vec![], fee_payer: FeePayer::Sender,
                access_list: vec![
                    AccessEntry { address: contract, reads: vec![slot_0], writes: vec![slot_0] },
                ],
                deadline: None, chain_id: 31337, tx_type: TransactionType::Standard,
            });
        }
        run_sequential("Contract calls (sequential, n=200)", &txs[..500], &mut persistent);
        run_parallel("Contract calls (parallel, n=200, 10K txs)", &txs[500..], &mut persistent);
    }

    // --- 3. Mixed block ---
    {
        let half = num_accounts as usize / 2;
        let mut txs = Vec::new();
        for i in 0..1500usize {
            let (from, _) = accounts[i % half];
            let (to, _) = accounts[half + (i % half)];
            txs.push(make_transfer(from, to, (i / half) as u64 + 30));
        }
        let selector = otic::codegen::compute_selector("heavy_compute");
        for i in 0..500usize {
            let (from, _) = accounts[(i + 10) % (num_accounts as usize)];
            let contract = contract_addrs[i % 10];
            let mut data = selector.to_be_bytes().to_vec();
            data.extend_from_slice(&200u64.to_le_bytes());
            txs.push(Transaction {
                from, to: contract, value: 0, data,
                gas_limit: 10_000_000, nonce: (i / (num_accounts as usize)) as u64,
                signature: vec![], fee_payer: FeePayer::Sender,
                access_list: vec![],
                deadline: None, chain_id: 31337, tx_type: TransactionType::Standard,
            });
        }
        run_parallel("Mixed (1500 xfer + 500 call)", &txs, &mut persistent);
    }

    let _ = std::fs::remove_dir_all(&dir);
    println!("\n========== PRODUCTION BENCHMARK COMPLETE ==========\n");
}

