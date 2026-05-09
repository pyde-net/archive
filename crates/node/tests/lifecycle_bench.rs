//! VALIDATOR BLOCK LIFECYCLE BENCHMARK — REALISTIC WORKLOAD
//! Mixed transactions with REAL conflicts: same contracts, same DEX pool,
//! same token, overlapping senders. Measures what mainnet actually sees.

mod contracts;
use contracts::*;

use pyde_account::address::derive_eoa_address;
use pyde_consensus::block::{BlockHeader, QuorumCert};
use pyde_consensus::hotstuff::{create_vote, try_form_qc, verify_vote, ConsensusState};
use pyde_consensus::proposer::compute_candidacy;
use pyde_crypto::falcon::{falcon_keygen, falcon_sign};
use pyde_crypto::poseidon2::poseidon2_hash;
use pyde_state::smt::{PersistentSMT, StateAccess, StateOverlay};
use pyde_tx::parallel::schedule;
use pyde_tx::pipeline::execute_transaction;
use pyde_tx::types::*;
use rayon::prelude::*;
use std::time::Instant;

struct Acct {
    pk: pyde_crypto::falcon::FalconPublicKey,
    sk: pyde_crypto::falcon::FalconSecretKey,
    address: [u8; 32],
    nonce: u64,
}
struct Val {
    pk: pyde_crypto::falcon::FalconPublicKey,
    sk: pyde_crypto::falcon::FalconSecretKey,
    address: [u8; 32],
}

fn sign(tx: &mut Transaction, sk: &pyde_crypto::falcon::FalconSecretKey) {
    tx.signature = falcon_sign(sk, &tx.hash()).unwrap().as_bytes().to_vec();
}
fn compile(src: &str) -> Vec<u8> {
    let c = otic::__compile_all_unchecked(src);
    let (_, cc) = &c[0];
    let mut d = Vec::new();
    d.extend_from_slice(&(cc.constructor_bytecode.len() as u32).to_le_bytes());
    d.extend_from_slice(&(cc.runtime_bytecode.len() as u32).to_le_bytes());
    d.extend_from_slice(&cc.constructor_bytecode);
    d.extend_from_slice(&cc.runtime_bytecode);
    d
}
fn sync_nonces(accounts: &mut [Acct], smt: &dyn StateAccess) {
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
#[ignore = "benchmark — run with --ignored"]
fn validator_block_lifecycle() {
    let dir = std::env::temp_dir().join("pyde-lifecycle-real");
    let _ = std::fs::remove_dir_all(&dir);
    let mut smt = PersistentSMT::open(dir.join("state").to_str().unwrap()).unwrap();

    // ── SETUP ────────────────────────────────────────────────────
    let validators: Vec<Val> = (0..4)
        .map(|_| {
            let (pk, sk) = falcon_keygen().unwrap();
            let address = derive_eoa_address(pk.as_bytes());
            Val { pk, sk, address }
        })
        .collect();
    let ckeys: Vec<Vec<u8>> = validators
        .iter()
        .map(|v| v.pk.as_bytes().to_vec())
        .collect();
    let mut cstates: Vec<ConsensusState> = (0..4).map(|_| ConsensusState::new()).collect();

    let mut accounts: Vec<Acct> = (0..2000)
        .into_par_iter()
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
    for acc in &accounts {
        let a = pyde_account::types::Account {
            address: acc.address,
            nonce: 0,
            balance: 100_000_000_000_000_000,
            code_hash: sparse_merkle_tree::H256::zero(),
            storage_root: sparse_merkle_tree::H256::zero(),
            account_type: pyde_account::types::AccountType::EOA,
            auth_keys: pyde_account::types::AuthKeys::Single(acc.pk.as_bytes().to_vec()),
            gas_tank: 0,
            key_nonce: 0,
        };
        smt.insert(pyde_state::keys::balance_key(&acc.address), a.to_bytes())
            .unwrap();
        smt.insert(
            pyde_state::keys::nonce_key(&acc.address),
            pyde_account::nonce::NonceState::new().to_bytes().to_vec(),
        )
        .unwrap();
    }

    let ctx = pyde_tx::pipeline::BlockContext {
        height: 1,
        timestamp: 1_700_000_000,
        base_fee: 1,
        block_gas_limit: 4_000_000_000,
        chain_id: 31337,
        validator_address: validators[0].address,
        dev_skip_signature: true,
        block_sigs_pre_verified: false,
    };

    // Deploy contracts (not timed)
    let deploy_and_get = |acc: &mut Acct, bin: Vec<u8>, smt: &mut PersistentSMT| -> [u8; 32] {
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
            chain_id: 31337,
            tx_type: TransactionType::Deploy,
        };
        sign(&mut tx, &acc.sk);
        acc.nonce += 1;
        let r = execute_transaction(&tx, smt, &ctx).unwrap();
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&r.return_data);
        addr
    };

    let counter_addr = deploy_and_get(&mut accounts[0], compile(COUNTER), &mut smt);
    let vault_addr = deploy_and_get(&mut accounts[1], compile(VAULT), &mut smt);
    let math_addr = deploy_and_get(&mut accounts[2], compile(MATH_HEAVY), &mut smt);
    let amm_addr = deploy_and_get(&mut accounts[3], compile(AMM_POOL), &mut smt);

    // Seed AMM with liquidity
    {
        let acc = &mut accounts[4];
        let sel = otic::codegen::compute_selector("add_liquidity");
        let mut data = sel.to_be_bytes().to_vec();
        let mut x = [0u8; 32];
        x[..8].copy_from_slice(&10_000_000u64.to_le_bytes());
        let mut y = [0u8; 32];
        y[..8].copy_from_slice(&20_000_000u64.to_le_bytes());
        data.extend_from_slice(&x);
        data.extend_from_slice(&y);
        let mut tx = Transaction {
            from: acc.address,
            to: amm_addr,
            value: 0,
            data,
            gas_limit: 50_000_000,
            nonce: acc.nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 31337,
            tx_type: TransactionType::Standard,
        };
        sign(&mut tx, &acc.sk);
        acc.nonce += 1;
        execute_transaction(&tx, &mut smt, &ctx).unwrap();
    }
    sync_nonces(&mut accounts, &smt);

    // ═══════════════════════════════════════════════════════════
    // BUILD REALISTIC MEMPOOL (conflicts everywhere)
    // ═══════════════════════════════════════════════════════════
    // Real-world mix:
    //   40% transfers (partially conflicting — some senders overlap)
    //   25% counter increments (ALL conflict — same contract)
    //   15% vault deposits (ALL conflict — same contract)
    //   10% AMM swaps (ALL conflict — same pool)
    //   10% math-heavy (ALL conflict — same contract)

    let total = 10_000usize;
    let n_transfers = total * 40 / 100; // 4000
    let n_counter = total * 25 / 100; // 2500
    let n_vault = total * 15 / 100; // 1500
    let n_amm = total * 10 / 100; // 1000
    let n_math = total - n_transfers - n_counter - n_vault - n_amm; // 1000

    let t_presign = Instant::now();
    let mut mempool: Vec<Transaction> = Vec::with_capacity(total);

    // Transfers (some senders overlap → partial conflicts)
    for i in 0..n_transfers {
        let from_idx = i % 500;
        let to = accounts[500 + (i % 500)].address;
        let acc = &mut accounts[from_idx];
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
            value: 1_000,
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
            chain_id: 31337,
            tx_type: TransactionType::Standard,
        };
        sign(&mut tx, &acc.sk);
        acc.nonce += 1;
        mempool.push(tx);
    }

    // Counter increments — ALL hit same contract (sequential group)
    sync_nonces(&mut accounts, &smt);
    for i in 0..n_counter {
        let acc = &mut accounts[1000 + (i % 500)];
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
            access_list: vec![],
            deadline: None,
            chain_id: 31337,
            tx_type: TransactionType::Standard,
        };
        sign(&mut tx, &acc.sk);
        acc.nonce += 1;
        mempool.push(tx);
    }

    // Vault deposits — ALL hit same contract
    sync_nonces(&mut accounts, &smt);
    for i in 0..n_vault {
        let acc = &mut accounts[1500 + (i % 500)];
        let sel = otic::codegen::compute_selector("deposit");
        let mut tx = Transaction {
            from: acc.address,
            to: vault_addr,
            value: 5_000,
            data: sel.to_be_bytes().to_vec(),
            gas_limit: 50_000_000,
            nonce: acc.nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 31337,
            tx_type: TransactionType::Standard,
        };
        sign(&mut tx, &acc.sk);
        acc.nonce += 1;
        mempool.push(tx);
    }

    // AMM swaps — ALL hit same pool
    sync_nonces(&mut accounts, &smt);
    for i in 0..n_amm {
        let acc = &mut accounts[i % 1000];
        let sel = otic::codegen::compute_selector("swap_x_for_y");
        let mut data = sel.to_be_bytes().to_vec();
        let mut amt = [0u8; 32];
        amt[..8].copy_from_slice(&100u64.to_le_bytes());
        data.extend_from_slice(&amt);
        let mut tx = Transaction {
            from: acc.address,
            to: amm_addr,
            value: 0,
            data,
            gas_limit: 50_000_000,
            nonce: acc.nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 31337,
            tx_type: TransactionType::Standard,
        };
        sign(&mut tx, &acc.sk);
        acc.nonce += 1;
        mempool.push(tx);
    }

    // Math heavy — ALL hit same contract
    sync_nonces(&mut accounts, &smt);
    for i in 0..n_math {
        let acc = &mut accounts[500 + (i % 500)];
        let sel = otic::codegen::compute_selector("compute_sum_squares");
        let mut data = sel.to_be_bytes().to_vec();
        data.extend_from_slice(&50u64.to_le_bytes());
        let mut tx = Transaction {
            from: acc.address,
            to: math_addr,
            value: 0,
            data,
            gas_limit: 50_000_000,
            nonce: acc.nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 31337,
            tx_type: TransactionType::Standard,
        };
        sign(&mut tx, &acc.sk);
        acc.nonce += 1;
        mempool.push(tx);
    }

    let presign_ms = t_presign.elapsed().as_secs_f64() * 1000.0;

    // Gas-limit the block: 4B gas, transfers = 21K, calls = 50M
    // 4000 transfers * 21K = 84M gas
    // 6000 calls * 50M = 300B gas → WAY over 4B limit
    // So we can fit: 4000 transfers (84M) + ~78 calls (78 * 50M = 3.9B) ≈ 4082 txs
    // Use fair ordering to select
    let t = Instant::now();
    let mut by_sender: std::collections::BTreeMap<[u8; 32], Vec<Transaction>> =
        std::collections::BTreeMap::new();
    for tx in mempool {
        by_sender.entry(tx.from).or_default().push(tx);
    }
    let mut queues: Vec<std::collections::VecDeque<Transaction>> = Vec::new();
    for (_, mut txs) in by_sender {
        txs.sort_by_key(|t| t.nonce);
        queues.push(std::collections::VecDeque::from(txs));
    }
    let mut selected: Vec<Transaction> = Vec::new();
    let mut gas = 0u64;
    loop {
        let mut any = false;
        for q in queues.iter_mut() {
            if let Some(tx) = q.front() {
                if gas + tx.gas_limit > 4_000_000_000 {
                    continue;
                }
                let tx = q.pop_front().unwrap();
                gas += tx.gas_limit;
                selected.push(tx);
                any = true;
                if gas >= 4_000_000_000 {
                    break;
                }
            }
        }
        if !any || gas >= 4_000_000_000 {
            break;
        }
    }
    let ordering_ms = t.elapsed().as_secs_f64() * 1000.0;

    // Count by type
    let n_sel_transfers = selected.iter().filter(|t| t.data.is_empty()).count();
    let n_sel_calls = selected.len() - n_sel_transfers;

    println!();
    println!("  PYDE VALIDATOR LIFECYCLE — REALISTIC WORKLOAD");
    println!(
        "  {} txs in mempool | {} selected for block (gas limit)",
        total,
        selected.len()
    );
    println!(
        "  {} transfers + {} contract calls",
        n_sel_transfers, n_sel_calls
    );
    println!("  Conflicts: counter/vault/amm/math ALL share state (sequential)");
    println!("  Pre-signing: {:.0}ms (user cost, excluded)", presign_ms);
    println!();

    // ── Phase 1: VRF ─────────────────────────────────────────
    let t = Instant::now();
    let epoch_rand = poseidon2_hash(b"epoch-0").to_bytes();
    let _ = compute_candidacy(
        &validators[0].pk,
        &validators[0].sk,
        &epoch_rand,
        1,
        validators[0].address,
    )
    .unwrap();
    let vrf_ms = t.elapsed().as_secs_f64() * 1000.0;

    // ── Phase 2: Scheduling (inverted index, O(n*k)) ──────
    let t = Instant::now();
    let sched = schedule(&selected);
    let sched_ms = t.elapsed().as_secs_f64() * 1000.0;
    let n_groups = sched.group_count();

    // ── Phase 3: Batch sig verify ────────────────────────────
    let t = Instant::now();
    let _: Vec<bool> = selected
        .par_iter()
        .map(|tx| {
            let key = pyde_state::keys::balance_key(&tx.from);
            if let Some(ab) = smt.get(&key) {
                if let Some(a) = pyde_account::types::Account::from_bytes(&ab) {
                    if let pyde_account::types::AuthKeys::Single(ref pk) = a.auth_keys {
                        return tx.verify_signature(pk);
                    }
                }
            }
            true
        })
        .collect();
    let verify_ms = t.elapsed().as_secs_f64() * 1000.0;

    // ── Phase 4: Parallel execution ──────────────────────────
    let t = Instant::now();
    let results: Vec<(
        Vec<(sparse_merkle_tree::H256, Vec<u8>)>,
        usize,
        usize,
        u64,
        usize,
    )> = sched
        .groups
        .par_iter()
        .map(|group| {
            let mut ov = StateOverlay::new(&smt as &dyn StateAccess);
            let (mut ok, mut fail, mut g, mut ev) = (0, 0, 0u64, 0);
            for &idx in &group.tx_indices {
                match execute_transaction(&selected[idx], &mut ov, &ctx) {
                    Ok(r) if r.success => {
                        ok += 1;
                        g += r.gas_used;
                        ev += r.logs.len();
                    }
                    _ => {
                        fail += 1;
                    }
                }
            }
            (ov.into_writes(), ok, fail, g, ev)
        })
        .collect();
    let exec_ms = t.elapsed().as_secs_f64() * 1000.0;

    let (mut ok, mut fail, mut total_gas, mut total_events) = (0, 0, 0u64, 0);
    let mut writes = Vec::new();
    for (w, o, f, g, e) in &results {
        ok += o;
        fail += f;
        total_gas += g;
        total_events += e;
        writes.extend(w.iter().cloned());
    }

    // ── Phase 5: State commit ────────────────────────────────
    let t = Instant::now();
    let wc = writes.len();
    let _ = smt.update_all(writes);
    let commit_ms = t.elapsed().as_secs_f64() * 1000.0;

    // ── Phase 6: Consensus ───────────────────────────────────
    let t = Instant::now();
    let hdr = BlockHeader {
        slot: 1,
        epoch: 0,
        parent_hash: [0u8; 32],
        proposer: validators[0].address,
        vrf_proof: vec![],
        qc_previous: QuorumCert::empty(),
        tx_root: poseidon2_hash(b"tx").to_bytes(),
        state_root: poseidon2_hash(b"st").to_bytes(),
        timestamp: 1_700_000_000,
    };
    let bh = hdr.hash();
    let mut votes = Vec::new();
    const CHAIN_ID: u64 = 31337;
    for (i, v) in validators.iter().enumerate() {
        if let Ok(Some(vote)) = create_vote(
            CHAIN_ID,
            &mut cstates[i],
            &hdr,
            i as u8,
            v.address,
            &v.sk,
            &ckeys,
        ) {
            assert!(verify_vote(CHAIN_ID, &vote, v.pk.as_bytes()));
            votes.push(vote);
        }
    }
    let _ = try_form_qc(CHAIN_ID, 1, bh, &votes, &ckeys).unwrap();
    let consensus_ms = t.elapsed().as_secs_f64() * 1000.0;

    // ── RESULTS ──────────────────────────────────────────────
    let critical = vrf_ms + ordering_ms + sched_ms + verify_ms + exec_ms + consensus_ms;

    println!("  Phase                            Time");
    println!("  ─────────────────────────────────────────────");
    println!("  VRF proposer check            {:>10.2}ms", vrf_ms);
    println!("  Fair ordering                 {:>10.2}ms", ordering_ms);
    println!(
        "  Scheduling                    {:>10.2}ms  ({} groups)",
        sched_ms, n_groups
    );
    println!(
        "  Batch sig verify              {:>10.2}ms  ({} sigs)",
        verify_ms,
        selected.len()
    );
    println!(
        "  Parallel execution            {:>10.2}ms  ({}/{} ok, {} events)",
        exec_ms,
        ok,
        ok + fail,
        total_events
    );
    println!(
        "  State commit (background)     {:>10.2}ms  ({} writes)",
        commit_ms, wc
    );
    println!("  Consensus (4 votes + QC)      {:>10.2}ms", consensus_ms);
    println!("  ─────────────────────────────────────────────");
    println!("  CRITICAL PATH:                {:>10.2}ms", critical);
    println!();
    println!(
        "  TPS (commit in background):   {:>10.0}",
        ok as f64 / (critical / 1000.0)
    );
    println!();
    let headroom = 400.0 - critical;
    if headroom > 0.0 {
        let scale = 400.0 / critical;
        println!(
            "  400ms slot: {:.0}ms critical + {:.0}ms headroom",
            critical, headroom
        );
        println!(
            "  MAINNET TPS:                  {:>10.0}",
            ok as f64 * scale / 0.4
        );
    } else {
        // Block takes longer than 400ms — need to reduce txs
        let fits = (ok as f64 * 400.0 / critical) as usize;
        println!("  Block exceeds 400ms slot — would fit ~{} txs", fits);
        println!(
            "  MAINNET TPS:                  {:>10.0}",
            fits as f64 / 0.4
        );
    }
    println!();
    println!("  Gas used:  {} / 4,000,000,000", total_gas);
    println!();
}
