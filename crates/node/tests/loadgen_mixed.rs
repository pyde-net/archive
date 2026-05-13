//! Mixed-workload sustained loadgen — exercises the full mainnet
//! transaction shape on a 4-validator network.
//!
//! Where the existing `loadgen_sustained` runs plaintext transfers
//! only, this test fires a weighted mix of the three real production
//! transaction shapes against the same chain instance:
//!
//!   - **plaintext transfer** (default 60%): Alice → Bob, signed
//!     FALCON, 50 K gas. Same as `loadgen_sustained`.
//!   - **plaintext contract call** (default 30%):
//!     `Counter.increment()` — exercises AOT cache (warm after
//!     first call), parallel-exec scheduler, PVM execution path.
//!   - **encrypted value tx** (default 10%): Kyber-768 encrypted
//!     transfer via `pyde_sendRawEncryptedTransaction` —
//!     exercises threshold encryption + cooperative decrypt-share
//!     gossip + post-QC seal-then-execute. The MEV-protected path
//!     real DeFi traffic uses.
//!
//! The intended 60/30/10 mix matches what most L1 production
//! traffic looks like in practice (most txs are simple value
//! movement; a large minority is contract activity; a small slice
//! is the MEV-target DeFi/swap traffic that self-selects
//! encrypted). While the MEV-protection pipeline is disabled at
//! compile time (see `MEV_PROTECTION_ENABLED` in
//! `crates/node/src/main.rs`), the default falls back to 70/30/0
//! — encrypted txs would be rejected at the RPC layer. Tunable
//! via `PYDE_LOADGEN_MIX=transfer:60,call:30,encrypted:10` once
//! the encrypted-tx path is re-enabled.
//!
//! Output: per-type submit/inclusion counts plus aggregate. The
//! aggregate is the headline number quotable at testnet launch —
//! "this hardware sustains X TPS of mainnet-shaped traffic".
//!
//! # Run
//!
//!   cargo test -p pyde-node --test loadgen_mixed --release -- \
//!     --ignored --nocapture
//!
//! # Knobs (env vars)
//!
//!   PYDE_LOADGEN_TPS         — target submit rate (default 1000)
//!   PYDE_LOADGEN_DURATION    — measurement duration in seconds (default 300)
//!   PYDE_LOADGEN_WARMUP      — warm-up in seconds (default 30)
//!   PYDE_LOADGEN_SENDERS     — funded sender count (default 200)
//!   PYDE_LOADGEN_MIX         — weight string (default "transfer:70,call:30,encrypted:0" while MEV is off; intended mix once re-enabled is "transfer:60,call:30,encrypted:10")
//!   PYDE_LOADGEN_FUND        — per-sender fund override
//!
//! # On sender count
//!
//! The mempool enforces a per-sender nonce window of 16. With ~400 ms
//! slots that's ~2.5 successful txs/sender/s before `InvalidNonce`
//! starts rejecting. So `num_senders ≥ target_TPS / 2.5`. The default
//! 200 senders gives ~500 TPS of headroom before the loadgen — not
//! the system — becomes the bottleneck.
//!
//! Beyond that, the loadgen makes no assumptions about validator
//! internals. Proposer selection, scheduler grouping, AOT cache
//! warm-up, JMT commit cadence — all happen inside the validators.
//! The loadgen just bombards; whatever throughput falls out is the
//! real number.

mod common;

use common::TestNetwork;
use pyde_account::address::derive_eoa_address;
use pyde_crypto::falcon::{
    falcon_keygen, falcon_sign, FalconPublicKey, FalconSecretKey, FalconSignature,
};
use pyde_tx::types::{AccessEntry, FeePayer, Transaction, TransactionType};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// audit 383: `pyde testnet` refuses chain_id=1 (mainnet). 7331 is the
// canonical public testnet id and still triggers production-mode sig
// verification — `dev_skip_signature` only fires at 31337.
const CHAIN_ID: u64 = 7331;
const RECIPIENT: [u8; 32] = [0x42u8; 32];
const TX_VALUE: u128 = 1;
// 1 PYDE = 10^9 quanta. Each sender gets enough headroom to cover
// gas at the genesis base-fee (50 gwei × 100 K gas ≈ 5 K PYDE upper
// bound per-tx) over a 5-minute run at the per-sender rate. Default
// fund matches the plaintext loadgen.
const FUND_PER_SENDER: u128 = 1_000_000_000_000_000_000;

/// Counter contract source — same one used across the multi-node
/// test suite. Tiny ctor, single u64 storage slot, `increment()`
/// is one storage read + add + write — minimal compute, but
/// exercises the full AOT cache + PVM execution path.
const COUNTER_SRC: &str = r#"
contract Counter {
    storage { count: u64, }
    #[constructor] pub fn init() { self.count = 0; }
    pub fn increment() { self.count = self.count + 1; }
    #[view] pub fn get_count() -> u64 { return self.count; }
}
"#;

/// Compile the Counter source into the on-chain deploy envelope
/// shape `pyde_tx::pipeline` expects (4-byte LE constructor length +
/// 4-byte LE runtime length + constructor bytes + runtime bytes).
fn compile_deploy_payload(src: &str) -> Vec<u8> {
    let c = otic::__compile_all_unchecked(src);
    let (_, cc) = &c[0];
    let mut out = Vec::with_capacity(8 + cc.constructor_bytecode.len() + cc.runtime_bytecode.len());
    out.extend_from_slice(&(cc.constructor_bytecode.len() as u32).to_le_bytes());
    out.extend_from_slice(&(cc.runtime_bytecode.len() as u32).to_le_bytes());
    out.extend_from_slice(&cc.constructor_bytecode);
    out.extend_from_slice(&cc.runtime_bytecode);
    out
}

struct Wallet {
    address: [u8; 32],
    pk_bytes: Vec<u8>,
    sk: FalconSecretKey,
}

#[derive(Clone, Copy, Debug)]
struct MixWeights {
    transfer: u32,
    call: u32,
    encrypted: u32,
}

impl MixWeights {
    fn parse(s: &str) -> Self {
        // "transfer:70,call:30,encrypted:0" → MixWeights{70,30,0}
        // Default encrypted=0 while MEV protection is disabled in
        // the build (see `MEV_PROTECTION_ENABLED` in
        // `crates/node/src/main.rs`). Override the mix string once
        // the encrypted path is wired back in.
        let mut transfer = 70u32;
        let mut call = 30u32;
        let mut encrypted = 0u32;
        for part in s.split(',') {
            if let Some((k, v)) = part.split_once(':') {
                let val = v.trim().parse::<u32>().unwrap_or(0);
                match k.trim() {
                    "transfer" => transfer = val,
                    "call" => call = val,
                    "encrypted" => encrypted = val,
                    _ => {}
                }
            }
        }
        Self {
            transfer,
            call,
            encrypted,
        }
    }

    fn total(&self) -> u32 {
        self.transfer + self.call + self.encrypted
    }

    /// Pick a tx type for this submit slot via `(slot_idx % total)`
    /// against cumulative weights. Deterministic + uniform across
    /// the run; no RNG needed (which would also block easy
    /// reproduction).
    fn pick(&self, idx: u64) -> TxKind {
        let r = (idx % self.total() as u64) as u32;
        if r < self.transfer {
            TxKind::Transfer
        } else if r < self.transfer + self.call {
            TxKind::Call
        } else {
            TxKind::Encrypted
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum TxKind {
    Transfer,
    Call,
    Encrypted,
}

#[test]
#[ignore = "Mixed-workload load test — spawns 4-node subprocess testnet, run with --ignored"]
fn mixed_workload_load_test() {
    let target_tps: u64 = env_var_u64("PYDE_LOADGEN_TPS", 1000);
    let duration_s: u64 = env_var_u64("PYDE_LOADGEN_DURATION", 300);
    let warmup_s: u64 = env_var_u64("PYDE_LOADGEN_WARMUP", 30);
    let num_senders: usize = env_var_u64("PYDE_LOADGEN_SENDERS", 200) as usize;
    let fund_per_sender: u128 = env_var_u64("PYDE_LOADGEN_FUND", FUND_PER_SENDER as u64) as u128;
    let mix = MixWeights::parse(
        &std::env::var("PYDE_LOADGEN_MIX")
            .unwrap_or_else(|_| "transfer:60,call:30,encrypted:10".into()),
    );

    let per_acct_rate = target_tps as f64 / num_senders as f64;
    let inflight_per_slot = per_acct_rate * 0.4;
    assert!(
        inflight_per_slot < 12.0,
        "num_senders ({}) too low for target {} TPS — per-account rate {:.1}/s, in-flight/slot {:.1} near nonce window 16",
        num_senders, target_tps, per_acct_rate, inflight_per_slot
    );

    println!("╔══════════════════════════════════════════════════════╗");
    println!("║  Pyde Mixed-Workload Load Test                      ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!("  Target TPS:   {}", target_tps);
    println!(
        "  Duration:     {} s  (+ {} s warm-up, not measured)",
        duration_s, warmup_s
    );
    println!(
        "  Senders:      {} (per-account rate: {:.1} tx/s)",
        num_senders, per_acct_rate
    );
    println!(
        "  Mix:          transfer:{}, call:{}, encrypted:{} (sum {})",
        mix.transfer,
        mix.call,
        mix.encrypted,
        mix.total()
    );
    println!("  chain_id:     {} (FALCON sig verification ON)", CHAIN_ID);
    println!("╚══════════════════════════════════════════════════════╝");

    // ── Phase 0: spawn 4-validator testnet ──────────────────────
    println!("\n[0/4] Spawning 4-validator native testnet at chain_id = {CHAIN_ID}…");
    let net = TestNetwork::spawn_with_chain_id(4, CHAIN_ID)
        .unwrap_or_else(|e| panic!("spawn 4v@chain_id={CHAIN_ID}: {}", e));
    net.wait_for_slot(3, Duration::from_secs(30))
        .unwrap_or_else(|e| panic!("chain warm-up: {}", e));

    let (faucet_pk_bytes, faucet_sk_bytes) = net
        .load_faucet_key()
        .unwrap_or_else(|e| panic!("load faucet.key: {}", e));
    let faucet_sk =
        FalconSecretKey::from_bytes(&faucet_sk_bytes).expect("invalid FALCON secret key");
    let faucet_addr = derive_eoa_address(&faucet_pk_bytes);
    println!("  faucet: 0x{}", hex::encode(faucet_addr));

    let rpc_urls: Vec<String> = net.nodes.iter().map(|n| n.rpc_url()).collect();

    // ── Phase 1: fund + register pubkeys for N senders ──────────
    println!(
        "\n[1/4] Funding + registering {} sender wallets…",
        num_senders
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let client = reqwest::Client::builder()
        .tcp_keepalive(Duration::from_secs(60))
        .pool_idle_timeout(Duration::from_secs(60))
        .build()
        .expect("reqwest client");

    let setup_start = Instant::now();
    let wallets: Vec<Arc<Wallet>> = runtime.block_on(async {
        let mut wallets = Vec::with_capacity(num_senders);
        for _ in 0..num_senders {
            let (pk, sk) = falcon_keygen().expect("keygen");
            let address = derive_eoa_address(pk.as_bytes());
            wallets.push(Arc::new(Wallet {
                address,
                pk_bytes: pk.as_bytes().to_vec(),
                sk,
            }));
        }

        // 1a. Fund each wallet from faucet.
        let mut faucet_nonce = fetch_nonce(&client, &rpc_urls[0], &faucet_addr)
            .await
            .expect("faucet nonce");
        let mut signed_hex: Vec<String> = Vec::with_capacity(num_senders);
        for w in &wallets {
            let mut tx = Transaction {
                from: faucet_addr,
                to: w.address,
                value: fund_per_sender,
                data: vec![],
                gas_limit: 50_000,
                nonce: faucet_nonce,
                signature: vec![],
                fee_payer: FeePayer::Sender,
                access_list: vec![],
                deadline: None,
                chain_id: CHAIN_ID,
                tx_type: TransactionType::Standard,
            };
            tx.signature = falcon_sign(&faucet_sk, &tx.hash())
                .expect("fund sig")
                .as_bytes()
                .to_vec();
            signed_hex.push(hex::encode(tx.to_bytes()));
            faucet_nonce += 1;
        }
        // Stream funding in nonce-window-friendly chunks.
        let mut chunk_idx = 0usize;
        for chunk in signed_hex.chunks(15) {
            for hex_tx in chunk {
                let _ = rpc_send_raw(&client, &rpc_urls[0], hex_tx).await;
            }
            chunk_idx += 1;
            tokio::time::sleep(Duration::from_millis(800)).await;
        }
        // Wait for all funded.
        let poll_deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let mut funded = 0usize;
            for w in &wallets {
                if fetch_balance(&client, &rpc_urls[0], &w.address)
                    .await
                    .unwrap_or(0)
                    > 0
                {
                    funded += 1;
                }
            }
            if funded == wallets.len() {
                break;
            }
            if Instant::now() >= poll_deadline {
                panic!("funding timed out: {}/{}", funded, wallets.len());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let _ = chunk_idx;

        // 1b. RegisterPubkey for each wallet (audit 226 / 229).
        let mut signed_register: Vec<String> = Vec::with_capacity(wallets.len());
        for w in &wallets {
            let tx = Transaction {
                from: w.address,
                to: [0u8; 32],
                value: 0,
                data: w.pk_bytes.clone(),
                gas_limit: 0,
                nonce: 0,
                signature: vec![],
                fee_payer: FeePayer::Sender,
                access_list: vec![],
                deadline: None,
                chain_id: CHAIN_ID,
                tx_type: TransactionType::RegisterPubkey,
            };
            signed_register.push(hex::encode(tx.to_bytes()));
        }
        use futures_util::stream::{iter, StreamExt};
        let mut futs = Vec::new();
        for (i, hex_tx) in signed_register.iter().enumerate() {
            let url = rpc_urls[i % rpc_urls.len()].clone();
            let cli = client.clone();
            let hex_tx = hex_tx.clone();
            futs.push(async move {
                let _ = rpc_send_raw(&cli, &url, &hex_tx).await;
            });
        }
        iter(futs).buffer_unordered(32).collect::<Vec<()>>().await;

        let poll_deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let mut registered = 0usize;
            for w in &wallets {
                if fetch_nonce(&client, &rpc_urls[0], &w.address)
                    .await
                    .unwrap_or(0)
                    >= 1
                {
                    registered += 1;
                }
            }
            if registered == wallets.len() {
                break;
            }
            if Instant::now() >= poll_deadline {
                panic!("RegisterPubkey timed out: {}/{}", registered, wallets.len());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        wallets
    });
    println!(
        "  ✓ {} wallets funded + registered in {:.1} s",
        wallets.len(),
        setup_start.elapsed().as_secs_f64()
    );

    // ── Phase 2: deploy Counter contract from faucet ────────────
    let mut counter_addr: [u8; 32] = [0u8; 32];
    if mix.call > 0 {
        println!("\n[2/4] Deploying Counter contract from faucet…");
        let deploy_start = Instant::now();
        let payload = compile_deploy_payload(COUNTER_SRC);
        let faucet_nonce = runtime
            .block_on(fetch_nonce(&client, &rpc_urls[0], &faucet_addr))
            .unwrap_or(0);
        let mut deploy_tx = Transaction {
            from: faucet_addr,
            to: [0u8; 32],
            value: 0,
            data: payload,
            gas_limit: 100_000_000,
            nonce: faucet_nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: CHAIN_ID,
            tx_type: TransactionType::Deploy,
        };
        deploy_tx.signature = falcon_sign(&faucet_sk, &deploy_tx.hash())
            .expect("deploy sig")
            .as_bytes()
            .to_vec();
        let deploy_hash = net
            .submit_raw_tx(0, &deploy_tx.to_bytes())
            .unwrap_or_else(|e| panic!("submit deploy: {}", e));
        let receipts = net
            .wait_for_receipt_on_all(&deploy_hash, Duration::from_secs(60))
            .unwrap_or_else(|e| panic!("deploy receipt: {}", e));
        assert!(receipts[0].success, "deploy failed: {}", receipts[0].raw);
        let return_bytes = TestNetwork::decode_return_data(&receipts[0].raw)
            .unwrap_or_else(|e| panic!("decode deploy returnData: {}", e));
        counter_addr.copy_from_slice(&return_bytes);
        println!(
            "  ✓ Counter at 0x{} (deploy in {:.1}s)",
            hex::encode(counter_addr),
            deploy_start.elapsed().as_secs_f64()
        );
    } else {
        println!("\n[2/4] Skipping Counter deploy (mix.call=0)");
    }

    // ── Phase 3: fetch threshold pubkey for encrypted-tx path ───
    let threshold_pk_bytes: Option<Vec<u8>> = if mix.encrypted > 0 {
        println!("\n[3/4] Fetching threshold pubkey for encrypted-tx path…");
        let pk = runtime
            .block_on(fetch_threshold_pubkey(&client, &rpc_urls[0]))
            .unwrap_or_else(|e| panic!("threshold pubkey: {}", e));
        println!("  ✓ threshold pk fetched ({} bytes)", pk.len());
        Some(pk)
    } else {
        println!("\n[3/4] Skipping threshold-pk fetch (mix.encrypted=0)");
        None
    };

    // ── Phase 4: sustained mixed-rate submission ────────────────
    let rate_per_acct = target_tps as f64 / num_senders as f64;
    let per_acct_interval = Duration::from_secs_f64(1.0 / rate_per_acct);
    let total_run_s = warmup_s + duration_s;

    println!(
        "\n[4/4] Mixed-load run: {} s total ({} warm-up + {} measured)",
        total_run_s, warmup_s, duration_s
    );

    let counts = Arc::new(MixCounts::new());
    let submitted_hashes = Arc::new(SubmittedHashes::default());
    let run_start = Instant::now();
    let measurement_start_at = run_start + Duration::from_secs(warmup_s);
    let run_deadline = run_start + Duration::from_secs(total_run_s);

    runtime.block_on(async {
        let mut tasks = Vec::with_capacity(num_senders);
        for (i, w) in wallets.iter().enumerate() {
            let wallet = w.clone();
            let cli = client.clone();
            let url = rpc_urls[i % rpc_urls.len()].clone();
            let counts = counts.clone();
            let submitted_hashes = submitted_hashes.clone();
            let interval = per_acct_interval;
            let measure_at = measurement_start_at;
            let deadline = run_deadline;
            let cnt_addr = counter_addr;
            let tpk_bytes = threshold_pk_bytes.clone();

            tasks.push(tokio::spawn(async move {
                let mut nonce = 1u64; // nonce 0 was RegisterPubkey
                let mut next_submit = Instant::now();
                let mut submit_idx: u64 = (i as u64) * 7919; // staggered seed so senders don't all pick the same kind in lockstep
                loop {
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    if now < next_submit {
                        tokio::time::sleep(next_submit - now).await;
                    }
                    next_submit += interval;

                    let kind = mix.pick(submit_idx);
                    submit_idx += 1;

                    let result: Result<Option<[u8; 32]>, ()> = match kind {
                        TxKind::Transfer => submit_transfer(&cli, &url, &wallet, nonce)
                            .await
                            .map(Some),
                        TxKind::Call => {
                            if cnt_addr == [0u8; 32] {
                                Ok(None) // skipped; treat as no-op
                            } else {
                                submit_counter_call(&cli, &url, &wallet, nonce, &cnt_addr)
                                    .await
                                    .map(Some)
                            }
                        }
                        TxKind::Encrypted => {
                            if let Some(ref tpk) = tpk_bytes {
                                submit_encrypted(&cli, &url, &wallet, nonce, tpk)
                                    .await
                                    .map(Some)
                            } else {
                                Ok(None)
                            }
                        }
                    };

                    let in_measure = Instant::now() >= measure_at;
                    match result {
                        Ok(maybe_hash) => {
                            counts.record_ok(kind, in_measure);
                            if in_measure {
                                if let Some(hash) = maybe_hash {
                                    submitted_hashes.record(kind, hash);
                                }
                            }
                            nonce += 1;
                        }
                        Err(_) => {
                            counts.record_err(kind, in_measure);
                            // The chain may have committed the tx
                            // even though the HTTP response failed
                            // (3 s timeout) — resync the nonce from
                            // chain state before retrying, otherwise
                            // we burn this sender's slot forever on
                            // `InvalidNonce(BelowWindow)`.
                            if let Some(chain_nonce) =
                                fetch_nonce(&cli, &url, &wallet.address).await
                            {
                                if chain_nonce > nonce {
                                    nonce = chain_nonce;
                                }
                            }
                            tokio::time::sleep(Duration::from_millis(400)).await;
                            next_submit = Instant::now();
                        }
                    }
                }
            }));
        }

        // Progress reporter — per-type.
        let progress_counts = counts.clone();
        let progress_end = run_deadline;
        let progress_measure_at = measurement_start_at;
        let progress_task = tokio::spawn(async move {
            let mut last = MixSnapshot::default();
            while Instant::now() < progress_end {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let now = Instant::now();
                let cur = progress_counts.snapshot();
                let delta = cur.minus(&last);
                let phase = if now < progress_measure_at {
                    "warmup"
                } else {
                    "measure"
                };
                println!(
                    "  [{:>7}] +T{}/C{}/E{} in 10s ({}+{}+{} ok / {}+{}+{} err total)",
                    phase,
                    delta.transfer_ok,
                    delta.call_ok,
                    delta.encrypted_ok,
                    cur.transfer_ok,
                    cur.call_ok,
                    cur.encrypted_ok,
                    cur.transfer_err,
                    cur.call_err,
                    cur.encrypted_err,
                );
                last = cur;
            }
        });

        for t in tasks {
            let _ = t.await;
        }
        let _ = progress_task.await;
    });

    // ── Settle + report ─────────────────────────────────────────
    println!("\n  Settling 20 s for final inclusion…");
    runtime.block_on(async {
        tokio::time::sleep(Duration::from_secs(20)).await;
    });

    let snap = counts.snapshot();
    let total_submitted = snap.transfer_ok + snap.call_ok + snap.encrypted_ok;
    let measure_submitted =
        snap.transfer_ok_measure + snap.call_ok_measure + snap.encrypted_ok_measure;
    let total_errors = snap.transfer_err + snap.call_err + snap.encrypted_err;

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║  RESULTS                                             ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!(
        "  Target:                 {} TPS for {} s",
        target_tps, duration_s
    );
    println!(
        "  Mix:                    transfer:{}, call:{}, encrypted:{}",
        mix.transfer, mix.call, mix.encrypted
    );
    println!("  ─ submitted (measured) ─");
    println!("    transfer:    {}", snap.transfer_ok_measure);
    println!("    call:        {}", snap.call_ok_measure);
    println!("    encrypted:   {}", snap.encrypted_ok_measure);
    println!(
        "    AGGREGATE:   {} ({} TPS)",
        measure_submitted,
        measure_submitted / duration_s.max(1)
    );
    println!("  ─ submitted (total over warmup+measure) ─");
    println!("    transfer:    {}", snap.transfer_ok);
    println!("    call:        {}", snap.call_ok);
    println!("    encrypted:   {}", snap.encrypted_ok);
    println!("    AGGREGATE:   {}", total_submitted);
    println!("  ─ errors ─");
    println!("    transfer:    {}", snap.transfer_err);
    println!("    call:        {}", snap.call_err);
    println!("    encrypted:   {}", snap.encrypted_err);
    println!("    AGGREGATE:   {}", total_errors);
    println!("╚══════════════════════════════════════════════════════╝");
    dump_err_pattern_top(10);

    // ── Verification phase ──────────────────────────────────────
    // Submit-OK rate (above) only proves RPC accepted the tx into
    // its mempool. The 5 checks below verify the txs actually
    // landed in committed blocks AND executed correctly:
    //   (1) include-rate via receipt lookups (cheaper + more accurate
    //       than the per-slot transactionHashes walk, which is subject
    //       to a pre-existing chain bug where slot_txs is overwritten
    //       on re-apply paths)
    //   (2) receipts: sample submitted hashes, count success=true
    //   (3) sender balances: spot-check expected debits
    //   (4) Counter.value(): contract storage matches included calls
    //   (5) RECIPIENT balance: matches (transfer + encrypted) * value
    //
    // RPC nodes rate-limit at 100 req/s sustained per connection
    // (-32429). We route across all 4 nodes to multiply the
    // effective budget, and add a short pacing delay between calls.
    runtime.block_on(async {
        run_verifications(
            &client,
            &rpc_urls,
            &wallets,
            &submitted_hashes,
            &snap,
            counter_addr,
            fund_per_sender,
        )
        .await;
    });

    // Per-node validator output: full log to /tmp + last 60 lines to
    // stderr. The on-disk file captures the measurement-phase window
    // (the stderr tail alone is always settle-phase empty blocks).
    for n in &net.nodes {
        let snap = n.output_snapshot();
        let path = format!("/tmp/pyde-loadgen-mixed-node-{}.log", n.index);
        if let Err(e) = std::fs::write(&path, &snap) {
            eprintln!("failed to write {}: {}", path, e);
        } else {
            eprintln!(
                "\n=== node-{} (rpc {}) full log → {} ({} bytes) ===",
                n.index,
                n.rpc_port,
                path,
                snap.len()
            );
        }
        let last: Vec<&str> = snap.lines().rev().take(60).collect();
        for line in last.into_iter().rev() {
            eprintln!("{}", line);
        }
    }

    // We don't fail the test on TPS — this is a measurement
    // instrument, not a regression gate. Operators inspect the
    // aggregate number and decide.
}

// ════════════════════════════════════════════════════════════════════
// Per-tx-kind submitters
// ════════════════════════════════════════════════════════════════════

async fn submit_transfer(
    client: &reqwest::Client,
    url: &str,
    wallet: &Wallet,
    nonce: u64,
) -> Result<[u8; 32], ()> {
    let mut tx = Transaction {
        from: wallet.address,
        to: RECIPIENT,
        value: TX_VALUE,
        data: vec![],
        gas_limit: 50_000,
        nonce,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id: CHAIN_ID,
        tx_type: TransactionType::Standard,
    };
    let tx_hash = tx.hash();
    let sig = falcon_sign(&wallet.sk, &tx_hash).map_err(|_| ())?;
    tx.signature = sig.as_bytes().to_vec();
    rpc_send_raw_fast(client, url, &hex::encode(tx.to_bytes())).await?;
    Ok(tx_hash)
}

async fn submit_counter_call(
    client: &reqwest::Client,
    url: &str,
    wallet: &Wallet,
    nonce: u64,
    counter_addr: &[u8; 32],
) -> Result<[u8; 32], ()> {
    let selector = otic::codegen::compute_selector("increment");
    let calldata = selector.to_be_bytes().to_vec();
    let mut tx = Transaction {
        from: wallet.address,
        to: *counter_addr,
        value: 0,
        data: calldata,
        gas_limit: 200_000,
        nonce,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id: CHAIN_ID,
        tx_type: TransactionType::Standard,
    };
    let tx_hash = tx.hash();
    let sig = falcon_sign(&wallet.sk, &tx_hash).map_err(|_| ())?;
    tx.signature = sig.as_bytes().to_vec();
    rpc_send_raw_fast(client, url, &hex::encode(tx.to_bytes())).await?;
    Ok(tx_hash)
}

/// Submit an encrypted value tx via `pyde_sendRawEncryptedTransaction`.
///
/// Mirrors `TestNetwork::submit_encrypted_transfer_inner` but takes
/// the threshold pubkey + chain_id as parameters so the caller can
/// cache the pk (avoids one extra RPC per submit) and use the
/// production chain_id (the helper hardcodes 31337).
async fn submit_encrypted(
    client: &reqwest::Client,
    url: &str,
    wallet: &Wallet,
    nonce: u64,
    threshold_pk_bytes: &[u8],
) -> Result<[u8; 32], ()> {
    let tpk =
        pyde_crypto::threshold::ThresholdPublicKey::from_bytes(threshold_pk_bytes).ok_or(())?;
    // Same structural scaffolding as the
    // `submit_encrypted_transfer_inner` helper: minimal access list
    // (mempool requires non-empty), 100K gas, sign AFTER encryption
    // because the hash covers the ciphertext.
    let access_list = vec![AccessEntry {
        address: RECIPIENT,
        reads: Vec::new(),
        writes: Vec::new(),
    }];
    let mut enc_tx = pyde_mempool::encrypted::encrypt_transaction(
        wallet.address,
        nonce,
        100_000,
        access_list,
        None,
        CHAIN_ID,
        Vec::new(),
        &RECIPIENT,
        TX_VALUE,
        &[],
        &tpk,
    )
    .map_err(|_| ())?;
    let tx_hash = enc_tx.hash();
    let sig = falcon_sign(&wallet.sk, &tx_hash).map_err(|_| ())?;
    enc_tx.signature = sig.as_bytes().to_vec();
    let wire = enc_tx.to_bytes();
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"pyde_sendRawEncryptedTransaction","params":["0x{}"]}}"#,
        hex::encode(wire)
    );
    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body)
        .timeout(Duration::from_secs(3))
        .send()
        .await
        .map_err(|_| ())?;
    if !resp.status().is_success() {
        return Err(());
    }
    let text = resp.text().await.map_err(|_| ())?;
    if text.contains(r#""error""#) {
        return Err(());
    }
    // Self-verify so a bad sig surfaces here, not as a server-side
    // rejection that's harder to interpret in the loadgen output.
    let pk = FalconPublicKey::from_bytes(&wallet.pk_bytes).ok_or(())?;
    let sig_obj = FalconSignature::from_bytes(&enc_tx.signature).ok_or(())?;
    if !pyde_crypto::falcon::falcon_verify(&pk, &enc_tx.hash(), &sig_obj) {
        return Err(());
    }
    Ok(tx_hash)
}

// ════════════════════════════════════════════════════════════════════
// Inclusion + execution verification
// ════════════════════════════════════════════════════════════════════

/// Tx hashes successfully submitted (RPC-accepted) during the
/// measurement window. Stored under a Mutex per kind so the
/// post-run verifier can sample receipts, walk the chain, and
/// compare submit-count vs include-count.
#[derive(Default)]
struct SubmittedHashes {
    transfer: std::sync::Mutex<Vec<[u8; 32]>>,
    call: std::sync::Mutex<Vec<[u8; 32]>>,
    encrypted: std::sync::Mutex<Vec<[u8; 32]>>,
}

impl SubmittedHashes {
    fn record(&self, kind: TxKind, hash: [u8; 32]) {
        let target = match kind {
            TxKind::Transfer => &self.transfer,
            TxKind::Call => &self.call,
            TxKind::Encrypted => &self.encrypted,
        };
        if let Ok(mut v) = target.lock() {
            v.push(hash);
        }
    }

    fn snapshot(&self, kind: TxKind) -> Vec<[u8; 32]> {
        let src = match kind {
            TxKind::Transfer => &self.transfer,
            TxKind::Call => &self.call,
            TxKind::Encrypted => &self.encrypted,
        };
        src.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

// ════════════════════════════════════════════════════════════════════
// Counters
// ════════════════════════════════════════════════════════════════════

#[derive(Default)]
struct MixCounts {
    transfer_ok: AtomicU64,
    call_ok: AtomicU64,
    encrypted_ok: AtomicU64,
    transfer_ok_measure: AtomicU64,
    call_ok_measure: AtomicU64,
    encrypted_ok_measure: AtomicU64,
    transfer_err: AtomicU64,
    call_err: AtomicU64,
    encrypted_err: AtomicU64,
}

impl MixCounts {
    fn new() -> Self {
        Self::default()
    }

    fn record_ok(&self, kind: TxKind, in_measure: bool) {
        match kind {
            TxKind::Transfer => {
                self.transfer_ok.fetch_add(1, Ordering::Relaxed);
                if in_measure {
                    self.transfer_ok_measure.fetch_add(1, Ordering::Relaxed);
                }
            }
            TxKind::Call => {
                self.call_ok.fetch_add(1, Ordering::Relaxed);
                if in_measure {
                    self.call_ok_measure.fetch_add(1, Ordering::Relaxed);
                }
            }
            TxKind::Encrypted => {
                self.encrypted_ok.fetch_add(1, Ordering::Relaxed);
                if in_measure {
                    self.encrypted_ok_measure.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    fn record_err(&self, kind: TxKind, _in_measure: bool) {
        match kind {
            TxKind::Transfer => self.transfer_err.fetch_add(1, Ordering::Relaxed),
            TxKind::Call => self.call_err.fetch_add(1, Ordering::Relaxed),
            TxKind::Encrypted => self.encrypted_err.fetch_add(1, Ordering::Relaxed),
        };
    }

    fn snapshot(&self) -> MixSnapshot {
        MixSnapshot {
            transfer_ok: self.transfer_ok.load(Ordering::Relaxed),
            call_ok: self.call_ok.load(Ordering::Relaxed),
            encrypted_ok: self.encrypted_ok.load(Ordering::Relaxed),
            transfer_ok_measure: self.transfer_ok_measure.load(Ordering::Relaxed),
            call_ok_measure: self.call_ok_measure.load(Ordering::Relaxed),
            encrypted_ok_measure: self.encrypted_ok_measure.load(Ordering::Relaxed),
            transfer_err: self.transfer_err.load(Ordering::Relaxed),
            call_err: self.call_err.load(Ordering::Relaxed),
            encrypted_err: self.encrypted_err.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default, Clone, Copy)]
struct MixSnapshot {
    transfer_ok: u64,
    call_ok: u64,
    encrypted_ok: u64,
    transfer_ok_measure: u64,
    call_ok_measure: u64,
    encrypted_ok_measure: u64,
    transfer_err: u64,
    call_err: u64,
    encrypted_err: u64,
}

impl MixSnapshot {
    fn minus(&self, other: &Self) -> Self {
        Self {
            transfer_ok: self.transfer_ok - other.transfer_ok,
            call_ok: self.call_ok - other.call_ok,
            encrypted_ok: self.encrypted_ok - other.encrypted_ok,
            transfer_ok_measure: self.transfer_ok_measure - other.transfer_ok_measure,
            call_ok_measure: self.call_ok_measure - other.call_ok_measure,
            encrypted_ok_measure: self.encrypted_ok_measure - other.encrypted_ok_measure,
            transfer_err: self.transfer_err - other.transfer_err,
            call_err: self.call_err - other.call_err,
            encrypted_err: self.encrypted_err - other.encrypted_err,
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// Verification: did the chain actually execute these txs?
// ════════════════════════════════════════════════════════════════════

const BALANCE_SAMPLE_SIZE: usize = 10;
/// Per-connection sustained budget is 100 req/s (-32429 kicks in
/// above), so 11 ms between calls gives ~90 req/s/conn — under the
/// limit even if one of the 4 nodes is briefly slow.
const RPC_PACING_MS: u64 = 11;

/// Round-robin URL picker so consecutive verification calls hit
/// different RPC endpoints and each conn stays under its own
/// sustained budget.
struct UrlPool<'a> {
    urls: &'a [String],
    cursor: std::sync::atomic::AtomicUsize,
}

impl<'a> UrlPool<'a> {
    fn new(urls: &'a [String]) -> Self {
        Self {
            urls,
            cursor: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn next(&self) -> &str {
        let i = self
            .cursor
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        &self.urls[i % self.urls.len()]
    }
}

/// Look up every submitted hash via `pyde_getTransactionReceipt` and
/// classify (success / failed / missing). Reliable because it queries
/// the per-hash receipt map directly — unaffected by the slot_txs
/// overwrite bug on re-apply paths.
async fn full_receipt_audit(
    client: &reqwest::Client,
    pool: &UrlPool<'_>,
    hashes: &[[u8; 32]],
) -> (u64, u64, u64) {
    let mut ok = 0u64;
    let mut failed = 0u64;
    let mut missing = 0u64;
    for h in hashes {
        let resp = rpc_call(
            client,
            pool.next(),
            "pyde_getTransactionReceipt",
            &format!("\"0x{}\"", hex::encode(h)),
        )
        .await;
        match resp.get("result") {
            Some(v) if v.is_null() => missing += 1,
            Some(v) => match v.get("success").and_then(|s| s.as_bool()) {
                Some(true) => ok += 1,
                Some(false) => failed += 1,
                None => missing += 1,
            },
            None => missing += 1,
        }
        tokio::time::sleep(Duration::from_millis(RPC_PACING_MS)).await;
    }
    (ok, failed, missing)
}

/// Run all 5 post-soak verification checks and print a VERIFICATION
/// block analogous to RESULTS. We don't panic on failure here — the
/// numbers go to stdout/stderr and the operator decides whether the
/// chain executed the load correctly.
async fn run_verifications(
    client: &reqwest::Client,
    urls: &[String],
    wallets: &[Arc<Wallet>],
    submitted: &SubmittedHashes,
    submit_snap: &MixSnapshot,
    counter_addr: [u8; 32],
    fund_per_sender: u128,
) {
    let pool = UrlPool::new(urls);
    let transfer_hashes = submitted.snapshot(TxKind::Transfer);
    let call_hashes = submitted.snapshot(TxKind::Call);

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║  VERIFICATION                                        ║");
    println!("╠══════════════════════════════════════════════════════╣");

    let head_slot = fetch_block_number(client, pool.next()).await.unwrap_or(0);
    tokio::time::sleep(Duration::from_millis(RPC_PACING_MS)).await;

    // ── (1) Include-rate via full receipt audit ─────────────────
    // Look up every measurement-window hash. Definitive count of
    // which txs actually executed (success or failure).
    println!(
        "  (1) include-rate (full receipt audit, head_slot={})",
        head_slot
    );
    let (t_ok, t_fail, t_miss) = full_receipt_audit(client, &pool, &transfer_hashes).await;
    let (c_ok, c_fail, c_miss) = full_receipt_audit(client, &pool, &call_hashes).await;
    let t_landed = t_ok + t_fail;
    let c_landed = c_ok + c_fail;
    let submitted_measure =
        submit_snap.transfer_ok_measure + submit_snap.call_ok_measure;
    println!(
        "      transfer landed:  {} / {} submitted ({}%)",
        t_landed,
        transfer_hashes.len(),
        if transfer_hashes.is_empty() {
            0
        } else {
            t_landed as usize * 100 / transfer_hashes.len()
        }
    );
    println!(
        "      call landed:      {} / {} submitted ({}%)",
        c_landed,
        call_hashes.len(),
        if call_hashes.is_empty() {
            0
        } else {
            c_landed as usize * 100 / call_hashes.len()
        }
    );
    println!(
        "      aggregate landed: {} / {} measurement-window submits",
        t_landed + c_landed,
        submitted_measure
    );
    println!("  (2) execution success vs. failure");
    println!(
        "      transfer:  success={} failed={} missing={}",
        t_ok, t_fail, t_miss
    );
    println!(
        "      call:      success={} failed={} missing={}",
        c_ok, c_fail, c_miss
    );
    println!(
        "      encrypted: skipped — encrypted-wrapper hash != inner-receipt hash; \
         covered by RECIPIENT balance below"
    );

    // ── (3) Sender balance spot-check ───────────────────────────
    println!(
        "  (3) sender balances (sampled, {} of {})",
        BALANCE_SAMPLE_SIZE,
        wallets.len()
    );
    let step = (wallets.len() / BALANCE_SAMPLE_SIZE).max(1);
    let mut sample_count = 0usize;
    let mut debited = 0usize;
    for w in wallets.iter().step_by(step) {
        if sample_count >= BALANCE_SAMPLE_SIZE {
            break;
        }
        sample_count += 1;
        let bal = fetch_balance(client, pool.next(), &w.address).await.unwrap_or(0);
        tokio::time::sleep(Duration::from_millis(RPC_PACING_MS)).await;
        let nonce = fetch_nonce(client, pool.next(), &w.address).await.unwrap_or(0);
        tokio::time::sleep(Duration::from_millis(RPC_PACING_MS)).await;
        // After register (nonce 0) + any successful sends, nonce on chain ≥ 2.
        // Any included tx debits ≥ 1 quanta + base_fee*gas → balance drops.
        if nonce >= 2 && bal < fund_per_sender {
            debited += 1;
        }
        if sample_count <= 3 {
            println!(
                "      0x{}…: nonce={}, balance={}",
                hex::encode(&w.address[..6]),
                nonce,
                bal
            );
        }
    }
    println!(
        "      {} of {} sampled senders show post-tx state (nonce≥2 AND balance<fund)",
        debited, sample_count
    );

    // ── (4) Counter contract value ──────────────────────────────
    // Counter exposes `get_count()` as its view function (see
    // `COUNTER_SRC` near the top of this file). Selector mismatch
    // would surface as a `Revert` since `compute_selector("value")`
    // wouldn't match any function in the contract dispatch table.
    let value_selector = otic::codegen::compute_selector("get_count");
    let calldata = value_selector.to_be_bytes();
    let counter_value =
        fetch_call_u64(client, pool.next(), &counter_addr, &hex::encode(calldata)).await;
    tokio::time::sleep(Duration::from_millis(RPC_PACING_MS)).await;
    println!("  (4) Counter contract storage");
    println!(
        "      counter.value():      {}",
        counter_value
            .map(|v| v.to_string())
            .unwrap_or_else(|| "<call failed>".to_string())
    );
    println!("      execution-success calls (chain-side, measurement window):  {}", c_ok);
    println!("      submitted calls (RPC-accepted, total): {}", submit_snap.call_ok);

    // ── (5) RECIPIENT balance ───────────────────────────────────
    let recipient_balance = fetch_balance(client, pool.next(), &RECIPIENT)
        .await
        .unwrap_or(0);
    let expected_max = (submit_snap.transfer_ok as u128 + submit_snap.encrypted_ok as u128)
        * TX_VALUE;
    println!("  (5) RECIPIENT (0x42…42) balance");
    println!(
        "      observed balance: {} (= {} txs of value {})",
        recipient_balance,
        if TX_VALUE > 0 {
            recipient_balance / TX_VALUE
        } else {
            0
        },
        TX_VALUE
    );
    println!(
        "      expected ≤ {} (transfer+encrypted submitted × {})",
        expected_max, TX_VALUE
    );
    println!("╚══════════════════════════════════════════════════════╝");
}

/// Query `pyde_blockNumber`. Returns the current head slot.
async fn fetch_block_number(client: &reqwest::Client, url: &str) -> Option<u64> {
    let resp = rpc_call(client, url, "pyde_blockNumber", "").await;
    let raw = resp.get("result")?.as_str()?;
    u64::from_str_radix(raw.strip_prefix("0x").unwrap_or(raw), 16).ok()
}

/// Query `pyde_getBlockByNumber(slot)` and return:
///   (plaintext_tx_hashes, encrypted_tx_count)
#[allow(dead_code)]
async fn fetch_block_tx_hashes(
    client: &reqwest::Client,
    url: &str,
    slot: u64,
) -> Option<(Vec<[u8; 32]>, u64)> {
    let resp = rpc_call(
        client,
        url,
        "pyde_getBlockByNumber",
        &format!("{},true", slot),
    )
    .await;
    let block = resp.get("result")?;
    if block.is_null() {
        return None;
    }
    let mut hashes = Vec::new();
    if let Some(hs) = block.get("transactionHashes").and_then(|v| v.as_array()) {
        for h in hs {
            if let Some(s) = h.as_str() {
                if let Ok(bytes) = hex::decode(s.strip_prefix("0x").unwrap_or(s)) {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        hashes.push(arr);
                    }
                }
            }
        }
    }
    // Encrypted txs aren't in transactionHashes (those are the
    // INNER decrypted-tx hashes, which get receipts separately).
    // We use the block's `transactions` field — but the wrapper
    // shape may include encrypted entries; for now we approximate
    // by treating encrypted count as 0 here and relying on check
    // (5) to verify recipient balance. A future improvement: add
    // an `encrypted_count` field to `pyde_getBlockByNumber`.
    Some((hashes, 0))
}

/// Sample up to `n` hashes evenly across the input, query each
/// receipt, and return (success_count, failed_count, missing_count).
#[allow(dead_code)]
async fn sample_receipts(
    client: &reqwest::Client,
    url: &str,
    hashes: &[[u8; 32]],
    n: usize,
) -> (u64, u64, u64) {
    if hashes.is_empty() {
        return (0, 0, 0);
    }
    let step = (hashes.len() / n.max(1)).max(1);
    let mut ok = 0u64;
    let mut failed = 0u64;
    let mut missing = 0u64;
    let mut sampled = 0usize;
    for h in hashes.iter().step_by(step) {
        if sampled >= n {
            break;
        }
        sampled += 1;
        let resp = rpc_call(
            client,
            url,
            "pyde_getTransactionReceipt",
            &format!("\"0x{}\"", hex::encode(h)),
        )
        .await;
        match resp.get("result") {
            Some(v) if v.is_null() => missing += 1,
            Some(v) => match v.get("success").and_then(|s| s.as_bool()) {
                Some(true) => ok += 1,
                Some(false) => failed += 1,
                None => missing += 1,
            },
            None => missing += 1,
        }
    }
    (ok, failed, missing)
}

/// Call a view-function and decode the result as u64 (last 8 bytes
/// of the returned u256, big-endian). For Counter.value(), the
/// return data is a 32-byte big-endian u256.
async fn fetch_call_u64(
    client: &reqwest::Client,
    url: &str,
    to: &[u8; 32],
    data_hex: &str,
) -> Option<u64> {
    let params = format!(
        r#"{{"to":"0x{}","data":"0x{}"}}"#,
        hex::encode(to),
        data_hex
    );
    let resp = rpc_call(client, url, "pyde_call", &params).await;
    // Diagnostic: surface the raw response so a `<call failed>`
    // result tells us *why* — rate-limit, no-code, revert, etc.
    let raw_opt = resp.get("result").and_then(|v| v.as_str());
    if raw_opt.is_none() {
        eprintln!("DEBUG counter pyde_call result-missing: {}", resp);
        return None;
    }
    let raw = raw_opt.unwrap();
    let bytes = match hex::decode(raw.strip_prefix("0x").unwrap_or(raw)) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "DEBUG counter pyde_call hex decode failed: {} (raw={:?})",
                e, raw
            );
            return None;
        }
    };
    if bytes.len() < 8 {
        eprintln!(
            "DEBUG counter pyde_call short return: {} bytes (raw={:?})",
            bytes.len(),
            raw
        );
        return None;
    }
    let start = bytes.len() - 8;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[start..]);
    Some(u64::from_be_bytes(buf))
}

// ════════════════════════════════════════════════════════════════════
// HTTP helpers
// ════════════════════════════════════════════════════════════════════

async fn rpc_call(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: &str,
) -> serde_json::Value {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"{}","params":[{}],"id":1}}"#,
        method, params
    );
    match client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body)
        .timeout(Duration::from_secs(3))
        .send()
        .await
    {
        Ok(resp) => resp.json().await.unwrap_or_default(),
        Err(_) => serde_json::Value::Null,
    }
}

async fn rpc_send_raw(client: &reqwest::Client, url: &str, tx_hex: &str) -> serde_json::Value {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"pyde_sendRawTransaction","params":["0x{}"]}}"#,
        tx_hex
    );
    match client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body)
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => resp.json().await.unwrap_or_default(),
        Err(_) => serde_json::Value::Null,
    }
}

/// Global histogram of `rpc_send_raw_fast` error patterns so the
/// final report shows what's actually failing across the run. The
/// counters reset between processes, so each test run starts clean.
fn err_pattern_map() -> &'static std::sync::Mutex<std::collections::HashMap<String, u64>> {
    use std::sync::OnceLock;
    static MAP: OnceLock<std::sync::Mutex<std::collections::HashMap<String, u64>>> =
        OnceLock::new();
    MAP.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn record_err_pattern(msg: &str) {
    if let Ok(mut m) = err_pattern_map().lock() {
        *m.entry(msg.to_string()).or_insert(0) += 1;
    }
}

fn dump_err_pattern_top(n: usize) {
    let m = match err_pattern_map().lock() {
        Ok(m) => m,
        Err(_) => return,
    };
    let mut v: Vec<(String, u64)> = m.iter().map(|(k, v)| (k.clone(), *v)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    eprintln!("  ─ top {} error patterns ─", n);
    for (k, count) in v.iter().take(n) {
        eprintln!("    {:>6}  {}", count, k);
    }
}

async fn rpc_send_raw_fast(client: &reqwest::Client, url: &str, tx_hex: &str) -> Result<(), ()> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"pyde_sendRawTransaction","params":["0x{}"]}}"#,
        tx_hex
    );
    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body)
        .timeout(Duration::from_secs(3))
        .send()
        .await
        .map_err(|e| {
            record_err_pattern(&format!("transport:{}", e));
        })?;
    if !resp.status().is_success() {
        record_err_pattern(&format!("http:{}", resp.status()));
        return Err(());
    }
    let text = resp.text().await.map_err(|_| ())?;
    if text.contains(r#""error""#) {
        // Extract the error message (between `"message":"` and `"`).
        if let Some(start) = text.find(r#""message":""#) {
            let after = &text[start + r#""message":""#.len()..];
            if let Some(end) = after.find('"') {
                // Capture enough to distinguish InvalidNonce variants
                // (BelowWindow vs TooFarInFuture) plus the window/got
                // values that pin down whether we're behind or ahead.
                let msg = &after[..end.min(200)];
                record_err_pattern(msg);
            }
        }
        return Err(());
    }
    Ok(())
}

async fn fetch_nonce(client: &reqwest::Client, url: &str, addr: &[u8; 32]) -> Option<u64> {
    let resp = rpc_call(
        client,
        url,
        "pyde_getTransactionCount",
        &format!("\"0x{}\"", hex::encode(addr)),
    )
    .await;
    let raw = resp.get("result")?.as_str()?;
    if let Some(stripped) = raw.strip_prefix("0x") {
        u64::from_str_radix(stripped, 16).ok()
    } else {
        raw.parse().ok()
    }
}

async fn fetch_balance(client: &reqwest::Client, url: &str, addr: &[u8; 32]) -> Option<u128> {
    let resp = rpc_call(
        client,
        url,
        "pyde_getBalance",
        &format!("\"0x{}\"", hex::encode(addr)),
    )
    .await;
    let raw = resp.get("result")?.as_str()?;
    raw.parse().ok()
}

async fn fetch_threshold_pubkey(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let resp = rpc_call(client, url, "pyde_getThresholdPublicKey", "").await;
    let raw = resp
        .get("result")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("threshold pk missing in response: {}", resp))?;
    hex::decode(raw.strip_prefix("0x").unwrap_or(raw))
        .map_err(|e| format!("decode threshold pk hex: {}", e))
}

fn env_var_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}
