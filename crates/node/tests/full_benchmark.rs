//! PYDE FULL-STACK PRODUCTION BENCHMARK
//!
//! Tests the entire chain pipeline with 30+ contracts, FALCON-512 sigs,
//! parallel execution, AOT compilation, consensus voting, and diverse workloads.
//!
//! Outputs Prometheus-compatible metrics to a file for Grafana visualization.

mod contracts;

use contracts::*;
use pyde_account::address::derive_eoa_address;
use pyde_consensus::block::{BlockHeader, QuorumCert};
use pyde_consensus::hotstuff::{ConsensusState, create_vote, verify_vote, try_form_qc};
use pyde_crypto::falcon::{falcon_keygen, falcon_sign};
use pyde_crypto::poseidon2::poseidon2_hash;
use pyde_state::smt::{PersistentSMT, StateAccess, StateOverlay};
use pyde_tx::parallel::schedule;
use pyde_tx::pipeline::{execute_transaction, BlockContext};
use pyde_tx::types::*;
use rayon::prelude::*;
use std::collections::HashMap;
use std::time::Instant;

// ═══════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════

struct Account {
    pk: pyde_crypto::falcon::FalconPublicKey,
    sk: pyde_crypto::falcon::FalconSecretKey,
    address: [u8; 32],
    nonce: u64,
}

struct ValidatorKeys {
    pk: pyde_crypto::falcon::FalconPublicKey,
    sk: pyde_crypto::falcon::FalconSecretKey,
    address: [u8; 32],
}

struct BlockMetrics {
    label: String,
    tx_count: usize,
    ok_count: usize,
    fail_count: usize,
    exec_ms: f64,
    commit_ms: f64,
    sign_ms: f64,
    events: usize,
    gas_used: u64,
    parallel_groups: usize,
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

fn compile_single(source: &str) -> Vec<u8> {
    let compiled = otic::compile_all(source);
    let (_, c) = &compiled[0];
    let mut data = Vec::new();
    data.extend_from_slice(&(c.constructor_bytecode.len() as u32).to_le_bytes());
    data.extend_from_slice(&(c.runtime_bytecode.len() as u32).to_le_bytes());
    data.extend_from_slice(&c.constructor_bytecode);
    data.extend_from_slice(&c.runtime_bytecode);
    data
}

fn compile_last(source: &str) -> Vec<u8> {
    let compiled = otic::compile_all(source);
    let (_, c) = compiled.last().unwrap();
    let mut data = Vec::new();
    data.extend_from_slice(&(c.constructor_bytecode.len() as u32).to_le_bytes());
    data.extend_from_slice(&(c.runtime_bytecode.len() as u32).to_le_bytes());
    data.extend_from_slice(&c.constructor_bytecode);
    data.extend_from_slice(&c.runtime_bytecode);
    data
}

fn sign_tx(tx: &mut Transaction, sk: &pyde_crypto::falcon::FalconSecretKey) {
    let hash = tx.hash();
    tx.signature = falcon_sign(sk, &hash).unwrap().as_bytes().to_vec();
}

fn make_transfer(from: &Account, to: &[u8; 32], value: u128) -> Transaction {
    let from_slot = poseidon2_hash(&{
        let mut buf = Vec::with_capacity(33); buf.extend_from_slice(&from.address); buf.push(0x04); buf
    }).to_bytes();
    let to_slot = poseidon2_hash(&{
        let mut buf = Vec::with_capacity(33); buf.extend_from_slice(to); buf.push(0x04); buf
    }).to_bytes();
    Transaction {
        from: from.address, to: *to, value, data: vec![],
        gas_limit: 21_000, nonce: from.nonce, signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![
            AccessEntry { address: from.address, reads: vec![], writes: vec![from_slot] },
            AccessEntry { address: *to, reads: vec![], writes: vec![to_slot] },
        ],
        deadline: None, chain_id: 31337, tx_type: TransactionType::Standard,
    }
}

fn make_deploy(from: &Account, data: Vec<u8>) -> Transaction {
    Transaction {
        from: from.address, to: [0u8; 32], value: 0, data,
        gas_limit: 200_000_000, nonce: from.nonce, signature: vec![],
        fee_payer: FeePayer::Sender, access_list: vec![],
        deadline: None, chain_id: 31337, tx_type: TransactionType::Deploy,
    }
}

fn make_call(from: &Account, to: [u8; 32], method: &str, args: Vec<u8>) -> Transaction {
    let selector = otic::codegen::compute_selector(method);
    let mut data = selector.to_be_bytes().to_vec();
    data.extend_from_slice(&args);
    Transaction {
        from: from.address, to, value: 0, data, gas_limit: 50_000_000, nonce: from.nonce,
        signature: vec![], fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None, chain_id: 31337, tx_type: TransactionType::Standard,
    }
}

fn make_payable_call(from: &Account, to: [u8; 32], method: &str, value: u128) -> Transaction {
    let selector = otic::codegen::compute_selector(method);
    Transaction {
        from: from.address, to, value, data: selector.to_be_bytes().to_vec(),
        gas_limit: 50_000_000, nonce: from.nonce,
        signature: vec![], fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None, chain_id: 31337, tx_type: TransactionType::Standard,
    }
}

fn sync_nonces(accounts: &mut [Account], smt: &dyn StateAccess) {
    for acc in accounts.iter_mut() {
        let nonce_key = pyde_state::keys::nonce_key(&acc.address);
        if let Some(data) = smt.get(&nonce_key) {
            let ns = pyde_account::nonce::NonceState::from_bytes(&data);
            acc.nonce = ns.base + ns.used.trailing_ones() as u64;
        }
    }
}

fn execute_block_parallel(
    txs: &[Transaction],
    smt: &mut PersistentSMT,
    ctx: &BlockContext,
) -> (f64, f64, usize, usize, usize, u64, usize) {
    let sched = schedule(txs);
    let groups = &sched.groups;
    let num_groups = groups.len();

    // Phase A: execution (in-memory)
    let t_exec = Instant::now();
    let group_results: Vec<(Vec<(sparse_merkle_tree::H256, Vec<u8>)>, usize, usize, u64, usize)> = groups
        .par_iter()
        .map(|group| {
            let mut overlay = StateOverlay::new(smt as &dyn StateAccess);
            let mut ok = 0usize;
            let mut fail = 0usize;
            let mut gas = 0u64;
            let mut events = 0usize;
            for &idx in &group.tx_indices {
                match execute_transaction(&txs[idx], &mut overlay, ctx) {
                    Ok(r) if r.success => { ok += 1; gas += r.gas_used; events += r.logs.len(); }
                    _ => { fail += 1; }
                }
            }
            (overlay.into_writes(), ok, fail, gas, events)
        })
        .collect();
    let exec_ms = t_exec.elapsed().as_secs_f64() * 1000.0;

    let mut total_ok = 0;
    let mut total_fail = 0;
    let mut total_gas = 0u64;
    let mut total_events = 0;
    let mut all_writes = Vec::new();
    for (writes, ok, fail, gas, events) in group_results {
        total_ok += ok;
        total_fail += fail;
        total_gas += gas;
        total_events += events;
        all_writes.extend(writes);
    }

    // Phase B: commit
    let t_commit = Instant::now();
    let _ = smt.update_all(all_writes);
    let commit_ms = t_commit.elapsed().as_secs_f64() * 1000.0;

    (exec_ms, commit_ms, total_ok, total_fail, num_groups, total_gas, total_events)
}

fn execute_block_sequential(
    txs: &[Transaction],
    smt: &mut PersistentSMT,
    ctx: &BlockContext,
) -> (usize, usize, u64, usize) {
    let mut ok = 0;
    let mut fail = 0;
    let mut gas = 0u64;
    let mut events = 0;
    for tx in txs {
        match execute_transaction(tx, smt, ctx) {
            Ok(r) if r.success => { ok += 1; gas += r.gas_used; events += r.logs.len(); }
            _ => { fail += 1; }
        }
    }
    (ok, fail, gas, events)
}

fn run_consensus(
    slot: u64,
    parent_hash: [u8; 32],
    prev_qc: QuorumCert,
    validators: &[ValidatorKeys],
    states: &mut [ConsensusState],
) -> ([u8; 32], QuorumCert) {
    let header = BlockHeader {
        slot, epoch: slot / 128,
        parent_hash,
        proposer: validators[(slot as usize) % validators.len()].address,
        vrf_proof: vec![],
        qc_previous: prev_qc,
        tx_root: poseidon2_hash(&slot.to_le_bytes()).to_bytes(),
        state_root: [0u8; 32],
        timestamp: 1_700_000_000 + slot * 400,
    };
    let block_hash = header.hash();
    let committee_keys: Vec<Vec<u8>> = validators.iter().map(|v| v.pk.as_bytes().to_vec()).collect();
    let mut votes = Vec::new();
    for (i, v) in validators.iter().enumerate() {
        if let Ok(Some(vote)) = create_vote(&mut states[i], &header, i as u8, v.address, &v.sk) {
            assert!(verify_vote(&vote, v.pk.as_bytes()));
            votes.push(vote);
        }
    }
    let qc = try_form_qc(slot, block_hash, &votes, &committee_keys).expect("QC must form");
    (block_hash, qc)
}

// ═══════════════════════════════════════════════════════════════════
// MAIN BENCHMARK
// ═══════════════════════════════════════════════════════════════════

#[test]
fn full_production_benchmark() {
    let bench_start = Instant::now();

    let dir = std::env::temp_dir().join("pyde-full-benchmark");
    let _ = std::fs::remove_dir_all(&dir);
    let mut smt = PersistentSMT::open(dir.join("state").to_str().unwrap()).unwrap();

    println!("\n{}", "=".repeat(80));
    println!("  PYDE FULL-STACK PRODUCTION BENCHMARK");
    println!("  30+ contracts | FALCON-512 | Parallel exec | Consensus | RocksDB");
    println!("{}\n", "=".repeat(80));

    // ── Setup: validators + accounts ─────────────────────────────
    let t0 = Instant::now();
    let validators: Vec<ValidatorKeys> = (0..4).map(|_| {
        let (pk, sk) = falcon_keygen().unwrap();
        let address = derive_eoa_address(pk.as_bytes());
        ValidatorKeys { pk, sk, address }
    }).collect();
    let mut consensus_states: Vec<ConsensusState> = (0..4).map(|_| ConsensusState::new()).collect();
    println!("  [SETUP] 4 validators: {:.0}ms", t0.elapsed().as_secs_f64() * 1000.0);

    let t0 = Instant::now();
    let mut accounts: Vec<Account> = (0..500).into_par_iter().map(|_| {
        let (pk, sk) = falcon_keygen().unwrap();
        let address = derive_eoa_address(pk.as_bytes());
        Account { pk, sk, address, nonce: 0 }
    }).collect();
    println!("  [SETUP] 500 accounts (parallel keygen): {:.0}ms", t0.elapsed().as_secs_f64() * 1000.0);

    let t0 = Instant::now();
    for acc in &accounts {
        let account = pyde_account::types::Account {
            address: acc.address, nonce: 0, balance: 100_000_000_000_000_000,
            code_hash: sparse_merkle_tree::H256::zero(),
            storage_root: sparse_merkle_tree::H256::zero(),
            account_type: pyde_account::types::AccountType::EOA,
            auth_keys: pyde_account::types::AuthKeys::Single(acc.pk.as_bytes().to_vec()),
            gas_tank: 0, key_nonce: 0,
        };
        smt.insert(pyde_state::keys::balance_key(&acc.address), account.to_bytes()).unwrap();
        smt.insert(pyde_state::keys::nonce_key(&acc.address),
            pyde_account::nonce::NonceState::new().to_bytes().to_vec()).unwrap();
    }
    println!("  [SETUP] Funded 500 accounts: {:.0}ms", t0.elapsed().as_secs_f64() * 1000.0);

    let ctx = BlockContext {
        height: 1, timestamp: 1_700_000_000, base_fee: 1,
        block_gas_limit: 4_000_000_000, chain_id: 31337,
        validator_address: validators[0].address,
    };

    // ── Compile all contracts ────────────────────────────────────
    let t0 = Instant::now();
    let specs = all_contracts();
    let mut compiled: HashMap<String, Vec<u8>> = HashMap::new();
    for spec in &specs {
        let bin = if spec.is_multi { compile_last(spec.source) } else { compile_single(spec.source) };
        compiled.insert(spec.name.to_string(), bin);
    }
    println!("  [SETUP] Compiled {} contracts: {:.0}ms\n", specs.len(), t0.elapsed().as_secs_f64() * 1000.0);

    let mut all_metrics: Vec<BlockMetrics> = Vec::new();
    let mut block_hash = [0u8; 32];
    let mut qc = QuorumCert::empty();
    let mut slot = 0u64;
    let mut deployed: HashMap<String, [u8; 32]> = HashMap::new();

    // ═══════════════════════════════════════════════════════════════
    // BLOCK 1: Deploy all 23 contracts
    // ═══════════════════════════════════════════════════════════════
    slot += 1;
    println!("  -- BLOCK {}: Deploy {} contracts --", slot, specs.len());
    let t_sign = Instant::now();
    let mut deploy_txs = Vec::new();
    for (i, spec) in specs.iter().enumerate() {
        let acc = &mut accounts[i];
        let mut tx = make_deploy(acc, compiled[spec.name].clone());
        sign_tx(&mut tx, &acc.sk);
        acc.nonce += 1;
        deploy_txs.push((spec.name.to_string(), tx));
    }
    let sign_ms = t_sign.elapsed().as_secs_f64() * 1000.0;

    let t_exec = Instant::now();
    let mut ok = 0; let mut fail = 0; let mut gas = 0u64;
    for (name, tx) in &deploy_txs {
        match execute_transaction(tx, &mut smt, &ctx) {
            Ok(r) if r.success && r.return_data.len() == 32 => {
                let mut addr = [0u8; 32];
                addr.copy_from_slice(&r.return_data);
                deployed.insert(name.clone(), addr);
                ok += 1; gas += r.gas_used;
            }
            _ => { fail += 1; }
        }
    }
    let exec_ms = t_exec.elapsed().as_secs_f64() * 1000.0;
    println!("    Sign: {:.0}ms | Exec: {:.0}ms | {}/{} ok | {:.0} TPS",
        sign_ms, exec_ms, ok, deploy_txs.len(), ok as f64 / (exec_ms / 1000.0));
    all_metrics.push(BlockMetrics {
        label: format!("Deploy {} contracts", specs.len()),
        tx_count: deploy_txs.len(), ok_count: ok, fail_count: fail,
        exec_ms, commit_ms: 0.0, sign_ms, events: 0, gas_used: gas,
        parallel_groups: 1,
    });

    let (bh, q) = run_consensus(slot, block_hash, qc, &validators, &mut consensus_states);
    block_hash = bh; qc = q;

    // ═══════════════════════════════════════════════════════════════
    // BLOCK 2: 3000 native transfers (parallel)
    // ═══════════════════════════════════════════════════════════════
    slot += 1;
    sync_nonces(&mut accounts, &smt);
    println!("\n  -- BLOCK {}: 3000 native transfers (parallel) --", slot);

    let t_sign = Instant::now();
    let mut txs = Vec::new();
    for i in 0..3000 {
        let to = accounts[250 + (i % 250)].address;
        let acc = &mut accounts[i % 250];
        let mut tx = make_transfer(acc, &to, 1_000);
        sign_tx(&mut tx, &acc.sk);
        acc.nonce += 1;
        txs.push(tx);
    }
    let sign_ms = t_sign.elapsed().as_secs_f64() * 1000.0;

    let (exec_ms, commit_ms, ok, fail, groups, gas, events) =
        execute_block_parallel(&txs, &mut smt, &ctx);
    let total_ms = exec_ms + commit_ms;
    println!("    Sign: {:.0}ms | Exec: {:.1}ms | Commit: {:.0}ms | Total: {:.0}ms",
        sign_ms, exec_ms, commit_ms, total_ms);
    println!("    {}/{} ok | {} groups | EXEC TPS: {:.0} | TOTAL TPS: {:.0}",
        ok, txs.len(), groups, 3000.0 / (exec_ms / 1000.0), 3000.0 / (total_ms / 1000.0));
    all_metrics.push(BlockMetrics {
        label: "3000 transfers (parallel)".into(),
        tx_count: txs.len(), ok_count: ok, fail_count: fail,
        exec_ms, commit_ms, sign_ms, events, gas_used: gas, parallel_groups: groups,
    });

    let (bh, q) = run_consensus(slot, block_hash, qc, &validators, &mut consensus_states);
    block_hash = bh; qc = q;

    // ═══════════════════════════════════════════════════════════════
    // BLOCK 3: 200 counter increments (simple state mutation)
    // ═══════════════════════════════════════════════════════════════
    slot += 1;
    sync_nonces(&mut accounts, &smt);
    println!("\n  -- BLOCK {}: 200 counter increments --", slot);

    let counter_addr = *deployed.get("Counter").unwrap();
    let t_sign = Instant::now();
    let mut txs = Vec::new();
    for i in 0..200 {
        let acc = &mut accounts[i % 200];
        let mut tx = make_call(acc, counter_addr, "increment", vec![]);
        sign_tx(&mut tx, &acc.sk);
        acc.nonce += 1;
        txs.push(tx);
    }
    let sign_ms = t_sign.elapsed().as_secs_f64() * 1000.0;

    let t_exec = Instant::now();
    let (ok, fail, gas, events) = execute_block_sequential(&txs, &mut smt, &ctx);
    let exec_ms = t_exec.elapsed().as_secs_f64() * 1000.0;
    println!("    Sign: {:.0}ms | Exec: {:.0}ms | {}/{} ok | {:.0} TPS",
        sign_ms, exec_ms, ok, txs.len(), ok as f64 / (exec_ms / 1000.0));
    all_metrics.push(BlockMetrics {
        label: "200 counter increments".into(),
        tx_count: txs.len(), ok_count: ok, fail_count: fail,
        exec_ms, commit_ms: 0.0, sign_ms, events, gas_used: gas, parallel_groups: 1,
    });

    let (bh, q) = run_consensus(slot, block_hash, qc, &validators, &mut consensus_states);
    block_hash = bh; qc = q;

    // ═══════════════════════════════════════════════════════════════
    // BLOCK 4: 200 vault deposits (payable + events + u256 + maps)
    // ═══════════════════════════════════════════════════════════════
    slot += 1;
    sync_nonces(&mut accounts, &smt);
    println!("\n  -- BLOCK {}: 200 vault deposits (payable + events + u256) --", slot);

    let vault_addr = *deployed.get("Vault").unwrap();
    let t_sign = Instant::now();
    let mut txs = Vec::new();
    for i in 0..200 {
        let acc = &mut accounts[i % 200];
        let mut tx = make_payable_call(acc, vault_addr, "deposit", 50_000);
        sign_tx(&mut tx, &acc.sk);
        acc.nonce += 1;
        txs.push(tx);
    }
    let sign_ms = t_sign.elapsed().as_secs_f64() * 1000.0;

    let t_exec = Instant::now();
    let (ok, fail, gas, events) = execute_block_sequential(&txs, &mut smt, &ctx);
    let exec_ms = t_exec.elapsed().as_secs_f64() * 1000.0;
    println!("    Sign: {:.0}ms | Exec: {:.0}ms | {}/{} ok | Events: {} | {:.0} TPS",
        sign_ms, exec_ms, ok, txs.len(), events, ok as f64 / (exec_ms / 1000.0));
    all_metrics.push(BlockMetrics {
        label: "200 vault deposits".into(),
        tx_count: txs.len(), ok_count: ok, fail_count: fail,
        exec_ms, commit_ms: 0.0, sign_ms, events, gas_used: gas, parallel_groups: 1,
    });

    let (bh, q) = run_consensus(slot, block_hash, qc, &validators, &mut consensus_states);
    block_hash = bh; qc = q;

    // ═══════════════════════════════════════════════════════════════
    // BLOCK 5: 100 math-heavy computations (loops + bitwise + fibonacci)
    // ═══════════════════════════════════════════════════════════════
    slot += 1;
    sync_nonces(&mut accounts, &smt);
    println!("\n  -- BLOCK {}: 100 math-heavy computations --", slot);

    let math_addr = *deployed.get("MathHeavy").unwrap();
    let t_sign = Instant::now();
    let mut txs = Vec::new();
    for i in 0..34 {
        let acc = &mut accounts[i % 100];
        let mut tx = make_call(acc, math_addr, "compute_sum_squares", 100u64.to_le_bytes().to_vec());
        sign_tx(&mut tx, &acc.sk); acc.nonce += 1; txs.push(tx);
    }
    for i in 0..33 {
        let acc = &mut accounts[34 + (i % 100)];
        let mut tx = make_call(acc, math_addr, "compute_fibonacci", 80u64.to_le_bytes().to_vec());
        sign_tx(&mut tx, &acc.sk); acc.nonce += 1; txs.push(tx);
    }
    for i in 0..33 {
        let acc = &mut accounts[67 + (i % 100)];
        let mut tx = make_call(acc, math_addr, "compute_bitwise", 100u64.to_le_bytes().to_vec());
        sign_tx(&mut tx, &acc.sk); acc.nonce += 1; txs.push(tx);
    }
    let sign_ms = t_sign.elapsed().as_secs_f64() * 1000.0;

    let t_exec = Instant::now();
    let (ok, fail, gas, events) = execute_block_sequential(&txs, &mut smt, &ctx);
    let exec_ms = t_exec.elapsed().as_secs_f64() * 1000.0;
    println!("    Sign: {:.0}ms | Exec: {:.0}ms | {}/{} ok | {:.0} TPS",
        sign_ms, exec_ms, ok, txs.len(), ok as f64 / (exec_ms / 1000.0));
    all_metrics.push(BlockMetrics {
        label: "100 math-heavy".into(),
        tx_count: txs.len(), ok_count: ok, fail_count: fail,
        exec_ms, commit_ms: 0.0, sign_ms, events, gas_used: gas, parallel_groups: 1,
    });

    let (bh, q) = run_consensus(slot, block_hash, qc, &validators, &mut consensus_states);
    block_hash = bh; qc = q;

    // ═══════════════════════════════════════════════════════════════
    // BLOCK 6: 100 lottery entries (payable + PRNG + events)
    // ═══════════════════════════════════════════════════════════════
    slot += 1;
    sync_nonces(&mut accounts, &smt);
    println!("\n  -- BLOCK {}: 100 lottery entries --", slot);

    let lottery_addr = *deployed.get("Lottery").unwrap();
    let t_sign = Instant::now();
    let mut txs = Vec::new();
    for i in 0..100 {
        let acc = &mut accounts[i % 100];
        let mut tx = make_payable_call(acc, lottery_addr, "enter", 5_000);
        sign_tx(&mut tx, &acc.sk); acc.nonce += 1; txs.push(tx);
    }
    let sign_ms = t_sign.elapsed().as_secs_f64() * 1000.0;

    let t_exec = Instant::now();
    let (ok, fail, gas, events) = execute_block_sequential(&txs, &mut smt, &ctx);
    let exec_ms = t_exec.elapsed().as_secs_f64() * 1000.0;
    println!("    Sign: {:.0}ms | Exec: {:.0}ms | {}/{} ok | Events: {} | {:.0} TPS",
        sign_ms, exec_ms, ok, txs.len(), events, ok as f64 / (exec_ms / 1000.0));
    all_metrics.push(BlockMetrics {
        label: "100 lottery entries".into(),
        tx_count: txs.len(), ok_count: ok, fail_count: fail,
        exec_ms, commit_ms: 0.0, sign_ms, events, gas_used: gas, parallel_groups: 1,
    });

    let (bh, q) = run_consensus(slot, block_hash, qc, &validators, &mut consensus_states);
    block_hash = bh; qc = q;

    // ═══════════════════════════════════════════════════════════════
    // BLOCK 7: 100 stack/heap stress (deep recursion + loops)
    // ═══════════════════════════════════════════════════════════════
    slot += 1;
    sync_nonces(&mut accounts, &smt);
    println!("\n  -- BLOCK {}: 100 stack/heap stress --", slot);

    let stress_addr = *deployed.get("StackHeapStress").unwrap();
    let t_sign = Instant::now();
    let mut txs = Vec::new();
    for i in 0..50 {
        let acc = &mut accounts[i % 100];
        let mut tx = make_call(acc, stress_addr, "loop_heavy", 200u64.to_le_bytes().to_vec());
        sign_tx(&mut tx, &acc.sk); acc.nonce += 1; txs.push(tx);
    }
    for i in 0..50 {
        let acc = &mut accounts[50 + (i % 100)];
        let mut tx = make_call(acc, stress_addr, "deep_call", 20u64.to_le_bytes().to_vec());
        sign_tx(&mut tx, &acc.sk); acc.nonce += 1; txs.push(tx);
    }
    let sign_ms = t_sign.elapsed().as_secs_f64() * 1000.0;

    let t_exec = Instant::now();
    let (ok, fail, gas, events) = execute_block_sequential(&txs, &mut smt, &ctx);
    let exec_ms = t_exec.elapsed().as_secs_f64() * 1000.0;
    println!("    Sign: {:.0}ms | Exec: {:.0}ms | {}/{} ok | {:.0} TPS",
        sign_ms, exec_ms, ok, txs.len(), ok as f64 / (exec_ms / 1000.0));
    all_metrics.push(BlockMetrics {
        label: "100 stack/heap stress".into(),
        tx_count: txs.len(), ok_count: ok, fail_count: fail,
        exec_ms, commit_ms: 0.0, sign_ms, events, gas_used: gas, parallel_groups: 1,
    });

    let (bh, q) = run_consensus(slot, block_hash, qc, &validators, &mut consensus_states);
    block_hash = bh; qc = q;

    // ═══════════════════════════════════════════════════════════════
    // BLOCK 8: 200 AMM swaps (u256 multiply + divide + events)
    // ═══════════════════════════════════════════════════════════════
    slot += 1;
    sync_nonces(&mut accounts, &smt);
    println!("\n  -- BLOCK {}: 200 AMM swaps --", slot);

    let amm_addr = *deployed.get("AmmPool").unwrap();
    // First add liquidity
    {
        let acc = &mut accounts[0];
        let mut args = Vec::new();
        let mut x = [0u8; 32]; x[..8].copy_from_slice(&1_000_000u64.to_le_bytes());
        let mut y = [0u8; 32]; y[..8].copy_from_slice(&2_000_000u64.to_le_bytes());
        args.extend_from_slice(&x);
        args.extend_from_slice(&y);
        let mut tx = make_call(acc, amm_addr, "add_liquidity", args);
        sign_tx(&mut tx, &acc.sk); acc.nonce += 1;
        let _ = execute_transaction(&tx, &mut smt, &ctx);
    }
    sync_nonces(&mut accounts, &smt);

    let t_sign = Instant::now();
    let mut txs = Vec::new();
    for i in 0..200 {
        let acc = &mut accounts[i % 200];
        let mut amount = [0u8; 32];
        amount[..8].copy_from_slice(&((i as u64 + 1) * 100).to_le_bytes());
        let mut tx = make_call(acc, amm_addr, "swap_x_for_y", amount.to_vec());
        sign_tx(&mut tx, &acc.sk); acc.nonce += 1; txs.push(tx);
    }
    let sign_ms = t_sign.elapsed().as_secs_f64() * 1000.0;

    let t_exec = Instant::now();
    let (ok, fail, gas, events) = execute_block_sequential(&txs, &mut smt, &ctx);
    let exec_ms = t_exec.elapsed().as_secs_f64() * 1000.0;
    println!("    Sign: {:.0}ms | Exec: {:.0}ms | {}/{} ok | Events: {} | {:.0} TPS",
        sign_ms, exec_ms, ok, txs.len(), events, ok as f64 / (exec_ms / 1000.0));
    all_metrics.push(BlockMetrics {
        label: "200 AMM swaps".into(),
        tx_count: txs.len(), ok_count: ok, fail_count: fail,
        exec_ms, commit_ms: 0.0, sign_ms, events, gas_used: gas, parallel_groups: 1,
    });

    let (bh, q) = run_consensus(slot, block_hash, qc, &validators, &mut consensus_states);
    block_hash = bh; qc = q;

    // ═══════════════════════════════════════════════════════════════
    // BLOCK 9: 200 bitmap ops (bitwise heavy)
    // ═══════════════════════════════════════════════════════════════
    slot += 1;
    sync_nonces(&mut accounts, &smt);
    println!("\n  -- BLOCK {}: 200 bitmap ops (bitwise) --", slot);

    let bitmap_addr = *deployed.get("Bitmap").unwrap();
    let t_sign = Instant::now();
    let mut txs = Vec::new();
    for i in 0..200 {
        let acc = &mut accounts[i % 200];
        let bit = (i % 63) as u64;
        let mut tx = make_call(acc, bitmap_addr, "set_bit", bit.to_le_bytes().to_vec());
        sign_tx(&mut tx, &acc.sk); acc.nonce += 1; txs.push(tx);
    }
    let sign_ms = t_sign.elapsed().as_secs_f64() * 1000.0;

    let t_exec = Instant::now();
    let (ok, fail, gas, events) = execute_block_sequential(&txs, &mut smt, &ctx);
    let exec_ms = t_exec.elapsed().as_secs_f64() * 1000.0;
    println!("    Sign: {:.0}ms | Exec: {:.0}ms | {}/{} ok | {:.0} TPS",
        sign_ms, exec_ms, ok, txs.len(), ok as f64 / (exec_ms / 1000.0));
    all_metrics.push(BlockMetrics {
        label: "200 bitmap ops".into(),
        tx_count: txs.len(), ok_count: ok, fail_count: fail,
        exec_ms, commit_ms: 0.0, sign_ms, events, gas_used: gas, parallel_groups: 1,
    });

    let (bh, q) = run_consensus(slot, block_hash, qc, &validators, &mut consensus_states);
    block_hash = bh; qc = q;

    // ═══════════════════════════════════════════════════════════════
    // BLOCK 10: 200 multi-slot writes (8 storage writes per call)
    // ═══════════════════════════════════════════════════════════════
    slot += 1;
    sync_nonces(&mut accounts, &smt);
    println!("\n  -- BLOCK {}: 200 multi-slot writes (8 sstores each) --", slot);

    let multislot_addr = *deployed.get("MultiSlot").unwrap();
    let t_sign = Instant::now();
    let mut txs = Vec::new();
    for i in 0..200 {
        let acc = &mut accounts[i % 200];
        let mut tx = make_call(acc, multislot_addr, "write_all", (i as u64).to_le_bytes().to_vec());
        sign_tx(&mut tx, &acc.sk); acc.nonce += 1; txs.push(tx);
    }
    let sign_ms = t_sign.elapsed().as_secs_f64() * 1000.0;

    let t_exec = Instant::now();
    let (ok, fail, gas, events) = execute_block_sequential(&txs, &mut smt, &ctx);
    let exec_ms = t_exec.elapsed().as_secs_f64() * 1000.0;
    println!("    Sign: {:.0}ms | Exec: {:.0}ms | {}/{} ok | {:.0} TPS",
        sign_ms, exec_ms, ok, txs.len(), ok as f64 / (exec_ms / 1000.0));
    all_metrics.push(BlockMetrics {
        label: "200 multi-slot writes".into(),
        tx_count: txs.len(), ok_count: ok, fail_count: fail,
        exec_ms, commit_ms: 0.0, sign_ms, events, gas_used: gas, parallel_groups: 1,
    });

    let (_bh, _q) = run_consensus(slot, block_hash, qc, &validators, &mut consensus_states);

    // ═══════════════════════════════════════════════════════════════
    // FINAL SUMMARY
    // ═══════════════════════════════════════════════════════════════
    let total_elapsed = bench_start.elapsed();
    let total_txs: usize = all_metrics.iter().map(|m| m.ok_count).sum();
    let total_events: usize = all_metrics.iter().map(|m| m.events).sum();
    let total_gas: u64 = all_metrics.iter().map(|m| m.gas_used).sum();
    let total_fails: usize = all_metrics.iter().map(|m| m.fail_count).sum();

    println!("\n{}", "=".repeat(80));
    println!("  BENCHMARK RESULTS");
    println!("{}", "=".repeat(80));
    println!();
    println!("  {:40} {:>6} {:>6} {:>8} {:>8} {:>10}", "Workload", "OK", "Fail", "Exec ms", "Sign ms", "TPS");
    println!("  {}", "-".repeat(78));
    for m in &all_metrics {
        let tps = if m.exec_ms > 0.0 { m.ok_count as f64 / (m.exec_ms / 1000.0) } else { 0.0 };
        println!("  {:40} {:>6} {:>6} {:>8.1} {:>8.0} {:>10.0}",
            m.label, m.ok_count, m.fail_count, m.exec_ms, m.sign_ms, tps);
    }
    println!("  {}", "-".repeat(78));
    println!();
    println!("  Total transactions:   {}", total_txs);
    println!("  Total failures:       {}", total_fails);
    println!("  Total events:         {}", total_events);
    println!("  Total gas:            {}", total_gas);
    println!("  Contracts deployed:   {}", deployed.len());
    println!("  Consensus rounds:     {} (4 validators, QC each)", slot);
    println!("  FALCON-512 sigs:      {}", all_metrics.iter().map(|m| m.tx_count).sum::<usize>() * 2);
    println!("  Wall clock time:      {:.1}s", total_elapsed.as_secs_f64());
    println!("  Backend:              RocksDB (PersistentSMT)");
    println!();

    // Write metrics file for Prometheus/Grafana
    let metrics_path = dir.join("metrics.txt");
    let mut metrics_out = String::new();
    for m in &all_metrics {
        let label = m.label.replace(' ', "_").replace('(', "").replace(')', "");
        let tps = if m.exec_ms > 0.0 { m.ok_count as f64 / (m.exec_ms / 1000.0) } else { 0.0 };
        metrics_out += &format!("pyde_bench_tps{{workload=\"{}\"}} {:.0}\n", label, tps);
        metrics_out += &format!("pyde_bench_exec_ms{{workload=\"{}\"}} {:.1}\n", label, m.exec_ms);
        metrics_out += &format!("pyde_bench_ok{{workload=\"{}\"}} {}\n", label, m.ok_count);
        metrics_out += &format!("pyde_bench_events{{workload=\"{}\"}} {}\n", label, m.events);
        metrics_out += &format!("pyde_bench_gas{{workload=\"{}\"}} {}\n", label, m.gas_used);
        metrics_out += &format!("pyde_bench_groups{{workload=\"{}\"}} {}\n", label, m.parallel_groups);
    }
    metrics_out += &format!("pyde_bench_total_txs {}\n", total_txs);
    metrics_out += &format!("pyde_bench_total_time_s {:.1}\n", total_elapsed.as_secs_f64());
    metrics_out += &format!("pyde_bench_contracts_deployed {}\n", deployed.len());
    std::fs::write(&metrics_path, &metrics_out).unwrap();
    println!("  Metrics written to: {}", metrics_path.display());

    println!("{}\n", "=".repeat(80));

    assert_eq!(total_fails, 0, "All transactions must succeed");
}
