//! Sustained-rate load generator — Phase 7 task 073 measurement
//! instrument.
//!
//! Spawns its own 4-validator network via `common::TestNetwork` (native
//! subprocess `pyde` binaries at `chain_id = 1`, FALCON sig verification
//! ON), funds N senders from the faucet, then holds a target submit
//! rate for a configurable duration and records steady-state throughput
//! + inclusion. Native subprocesses (not Docker) — removes the Linux-VM
//! hop on macOS.
//!
//! # Current state (2026-04-22, after this commit's two fixes)
//!
//! Task 073 (1 K TPS sustained 10 min) is **NOT YET MET**. Two real
//! bottlenecks have been fixed as part of landing this test:
//!
//!   - `pending_txs` was a `Vec<Transaction>`; post-block `retain`
//!     recomputed a full Poseidon2 per entry (`tx.hash()` uncached).
//!     That was quadratic under load — at ~100 k mempool entries and
//!     20 block txs, retain scanned 2 M Poseidon2 hashes (several
//!     seconds per 400 ms slot). Fixed by switching to
//!     `HashMap<TxHash, Transaction>`; retain is now O(|block|).
//!   - Proposer `drain`-ed the full mempool to build its candidate
//!     block. In Pyde's multi-proposer VRF scheme, every validator
//!     proposes every slot and one wins the lottery; if our proposal
//!     lost, the drained txs vanished (neither in pending nor in the
//!     committed block). Under concentrated RPC load (e.g. this test)
//!     gossip couldn't re-seed them fast enough within the 400 ms
//!     slot, so every lost proposal = permanently lost txs. Fixed by
//!     cloning (`pending.values().cloned()`) rather than draining;
//!     the block-commit retain path already removes committed tx
//!     hashes, so the mempool correctly retains non-committed txs
//!     across slots.
//!
//! A remaining finding surfaces with these fixes in place: at 50 TPS
//! × 30 s, every sender commits exactly SENDER_CAP (16) txs and then
//! stops advancing. So one full round of block-packing works and the
//! next round(s) apparently re-propose already-committed nonces but
//! don't advance further. Likely interaction between the test's
//! locally-tracked submit-nonce and the chain's nonce-state update
//! path, or a stale-duplicate situation where pending still carries
//! committed txs a slot after they landed. Tracked as follow-up perf
//! work.
//!
//! # Run
//!
//!   cargo test -p pyde-node --test loadgen_sustained --release -- \
//!     --ignored --nocapture
//!
//! # Knobs (env vars)
//!
//!   PYDE_LOADGEN_TPS       — target submit rate (default 100)
//!   PYDE_LOADGEN_DURATION  — measurement duration in seconds (default 600)
//!   PYDE_LOADGEN_WARMUP    — warm-up in seconds, not measured (default 30)
//!   PYDE_LOADGEN_SENDERS   — funded sender count (default 50)
//!   PYDE_LOADGEN_ENCRYPTED — when "1"/"true", drives the encrypted-tx
//!                            path (Kyber-768 encrypt + threshold-decrypt)
//!                            instead of the plaintext path. Per-sender
//!                            rate is capped at the audit-027 limit
//!                            (10 enc-tx/s/sender); aggregate ceiling
//!                            with default settings is 50 senders × 10
//!                            = 500 enc-tx/s. Default: "0".

mod common;

use common::TestNetwork;
use pyde_account::address::derive_eoa_address;
use pyde_crypto::falcon::{falcon_keygen, falcon_sign, FalconSecretKey};
use pyde_tx::types::{FeePayer, Transaction, TransactionType};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CHAIN_ID: u64 = 1;
const RECIPIENT: [u8; 32] = [0x42u8; 32];
const TX_VALUE: u128 = 1;
// 1 000 000 000 PYDE (= 10^18 base units). Fee per tx is gas_limit * base_fee,
// and early blocks start at GENESIS_BASE_FEE = 50 gwei (5e10) until EIP-1559
// adjusts downward. At 50k gas_limit that's ~2 500 PYDE upfront per tx; a
// 10-minute run at 1 000 TPS / 50 senders = 12 000 txs/sender, so funding
// has to cover ~30M PYDE of worst-case base-fee spend with headroom.
const FUND_PER_SENDER: u128 = 1_000_000_000_000_000_000;

struct Wallet {
    address: [u8; 32],
    /// FALCON public key bytes — held to construct the
    /// `RegisterPubkey` setup tx (audit 229) that audit 226 now
    /// requires before any signed tx from this address is accepted
    /// at the rpc ingress.
    pk_bytes: Vec<u8>,
    sk: FalconSecretKey,
}

#[test]
#[ignore = "Phase 7 load test — spawns 4-node subprocess testnet, run with --ignored"]
fn sustained_rate_load_test() {
    let target_tps: u64 = env_var_u64("PYDE_LOADGEN_TPS", 100);
    let duration_s: u64 = env_var_u64("PYDE_LOADGEN_DURATION", 600);
    let warmup_s: u64 = env_var_u64("PYDE_LOADGEN_WARMUP", 30);
    let num_senders: usize = env_var_u64("PYDE_LOADGEN_SENDERS", 50) as usize;
    // Per-sender fund override for workloads (like burst tests with many
    // senders) where the default FUND_PER_SENDER×num_senders exceeds
    // the faucet's genesis balance. Defaults to FUND_PER_SENDER.
    let fund_per_sender: u128 = env_var_u64("PYDE_LOADGEN_FUND", FUND_PER_SENDER as u64) as u128;
    // Encrypted-path toggle: when set, switch tx submission from
    // `pyde_sendRawTransaction` (plaintext) to `pyde_sendRawEncryptedTransaction`
    // (Kyber-768 + threshold-decrypt). The wallets, funding, and
    // RegisterPubkey path are reused — encrypted ingress requires a
    // registered FALCON pubkey on the sender (`AuthKeys::Single`)
    // and our faucet-funded wallets satisfy that after Phase 1.
    let encrypted_path: bool = env_var_bool("PYDE_LOADGEN_ENCRYPTED", false);

    let per_acct_rate = target_tps as f64 / num_senders as f64;
    let inflight_per_slot = per_acct_rate * 0.4;
    assert!(
        inflight_per_slot < 12.0,
        "num_senders ({}) too low for target {} TPS — per-account rate {:.1}/s, in-flight/slot {:.1} near nonce window 16",
        num_senders, target_tps, per_acct_rate, inflight_per_slot
    );

    // Audit-027 enforces a per-sender rate cap on the encrypted
    // mempool (`DEFAULT_MAX_TX_PER_WINDOW_PER_SENDER = 10` enc-tx/s).
    // Above this, the RPC ingress rejects with rate-limited errors
    // and the measurement becomes meaningless. Hard-fail early so
    // the operator picks a sensible (target_tps, num_senders) pair.
    if encrypted_path {
        assert!(
            per_acct_rate <= 10.0,
            "encrypted path: per-account rate {:.1}/s exceeds audit-027 cap of 10 enc-tx/s/sender. \
             Either lower PYDE_LOADGEN_TPS to ≤ {} or raise PYDE_LOADGEN_SENDERS to ≥ {}.",
            per_acct_rate,
            num_senders * 10,
            (target_tps as f64 / 10.0).ceil() as u64,
        );
    }

    let path_label = if encrypted_path {
        "ENCRYPTED (Kyber-768 + threshold decrypt)"
    } else {
        "plaintext (pyde_sendRawTransaction)"
    };
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║  Pyde Phase 7 — Sustained-Rate Load Test            ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!("  Path:         {}", path_label);
    println!("  Target TPS:   {}", target_tps);
    println!(
        "  Duration:     {} s  (+ {} s warm-up, not measured)",
        duration_s, warmup_s
    );
    println!(
        "  Senders:      {} (per-account rate: {:.1} tx/s)",
        num_senders, per_acct_rate
    );
    println!("  chain_id:     {} (FALCON sig verification ON)", CHAIN_ID);
    println!("  Recipient:    0x{}", hex::encode(RECIPIENT));
    println!("╚══════════════════════════════════════════════════════╝");

    // --- Phase 0: spawn 4-validator testnet ---
    println!("\n[0/3] Spawning 4-validator native testnet at chain_id = 1…");
    let net = TestNetwork::spawn_with_chain_id(4, CHAIN_ID)
        .unwrap_or_else(|e| panic!("spawn 4v@chain_id=1: {}", e));

    // Wait for chain to warm up.
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
    println!("  nodes:  {:?}", rpc_urls);

    // --- Phase 1: fund N sender wallets from faucet ---
    println!(
        "\n[1/3] Funding {} sender wallets from faucet…",
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

        async fn current_block(client: &reqwest::Client, url: &str) -> u64 {
            let resp = rpc_call(client, url, "pyde_blockNumber", "[]").await;
            resp.get("result")
                .and_then(|v| v.as_str())
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0)
        }

        // Nonce window is 16; stream in chunks of 15.
        let mut chunk_idx = 0usize;
        let stream_t0 = Instant::now();
        let start_block = current_block(&client, &rpc_urls[0]).await;
        for chunk in signed_hex.chunks(15) {
            let submit_t = Instant::now();
            let mut ok = 0usize;
            let mut err_samples: Vec<String> = Vec::new();
            for hex_tx in chunk {
                let resp = rpc_send_raw(&client, &rpc_urls[0], hex_tx).await;
                if resp.get("error").is_some() {
                    if err_samples.len() < 2 {
                        err_samples.push(resp.to_string());
                    }
                } else {
                    ok += 1;
                }
            }
            let submit_elapsed = submit_t.elapsed();
            let faucet_nonce_now = fetch_nonce(&client, &rpc_urls[0], &faucet_addr)
                .await
                .unwrap_or(0);
            let block_now = current_block(&client, &rpc_urls[0]).await;
            println!(
                "    chunk {}: {}/{} submitted ok in {:.0}ms (chain block={}, +{}, faucet nonce={}, t+{:.1}s)",
                chunk_idx,
                ok,
                chunk.len(),
                submit_elapsed.as_secs_f64() * 1000.0,
                block_now,
                block_now - start_block,
                faucet_nonce_now,
                stream_t0.elapsed().as_secs_f64()
            );
            for e in &err_samples {
                println!("      sample error: {}", e);
            }
            chunk_idx += 1;
            tokio::time::sleep(Duration::from_millis(800)).await;
        }

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
                for (i, node) in net.nodes.iter().enumerate() {
                    let snap = node.output_snapshot();
                    let lines: Vec<&str> = snap.lines().collect();
                    let tail = lines.iter().rev().take(120).rev().copied().collect::<Vec<_>>();
                    eprintln!("\n=== node {} last 120 lines ===\n{}\n", i, tail.join("\n"));
                }
                panic!("funding timed out: {}/{}", funded, wallets.len());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        // Audit 226: production chain (chain_id != 31337) rejects
        // signed plaintext txs from senders with `AuthKeys::None`.
        // Fresh keypairs are exactly that. Send the gas-free
        // `RegisterPubkey` (audit 229) for each wallet at nonce 0
        // before the load run; this binds the FALCON pubkey on
        // chain so subsequent Standard txs pass the ingress gate.
        let register_t0 = Instant::now();
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
        // Stream registrations in parallel — they're independent
        // (each is signed by address-derivation, not by sequence
        // number across senders), so we can fire chunks concurrently
        // across the 4 RPC nodes.
        let mut futs = Vec::new();
        for (i, hex_tx) in signed_register.iter().enumerate() {
            let url = rpc_urls[i % rpc_urls.len()].clone();
            let cli = client.clone();
            let hex_tx = hex_tx.clone();
            futs.push(async move {
                let _ = rpc_send_raw(&cli, &url, &hex_tx).await;
            });
        }
        // Buffered concurrency cap to avoid socket churn.
        use futures_util::stream::{iter, StreamExt};
        iter(futs).buffer_unordered(32).collect::<Vec<()>>().await;

        let poll_deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let mut registered = 0usize;
            for w in &wallets {
                // After RegisterPubkey commits, sender's nonce
                // base advances from 0 to 1. Use that as the
                // confirmation signal.
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
                panic!(
                    "RegisterPubkey timed out: {}/{} confirmed",
                    registered,
                    wallets.len()
                );
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        println!(
            "  ✓ {} pubkeys registered in {:.1} s",
            wallets.len(),
            register_t0.elapsed().as_secs_f64()
        );
        wallets
    });
    println!(
        "  ✓ {} wallets funded in {:.1} s",
        wallets.len(),
        setup_start.elapsed().as_secs_f64()
    );

    // --- Phase 2: sustained-rate submission ---
    let rate_per_acct = target_tps as f64 / num_senders as f64;
    let per_acct_interval = Duration::from_secs_f64(1.0 / rate_per_acct);
    let total_run_s = warmup_s + duration_s;

    println!(
        "\n[2/3] Load run: {} s total ({} warm-up + {} measured)",
        total_run_s, warmup_s, duration_s
    );

    let pre_recipient_balance = runtime
        .block_on(async { fetch_balance(&client, &rpc_urls[0], &RECIPIENT).await })
        .unwrap_or(0);
    println!("  pre-run recipient balance: {}", pre_recipient_balance);

    // Fetch the committee threshold pubkey ONCE up-front when
    // running the encrypted path. Per-tx fetches add one RPC
    // round-trip per submission and would dominate latency at
    // anything above a few tx/s.
    let threshold_pk: Option<Arc<pyde_crypto::threshold::ThresholdPublicKey>> = if encrypted_path {
        let bytes = runtime
            .block_on(fetch_threshold_pk_bytes(&client, &rpc_urls[0]))
            .unwrap_or_else(|| panic!("could not fetch threshold pubkey from {}", rpc_urls[0]));
        let tpk =
            pyde_crypto::threshold::ThresholdPublicKey::from_bytes(&bytes).unwrap_or_else(|| {
                panic!(
                    "threshold pubkey bytes ({} bytes) failed to decode",
                    bytes.len()
                )
            });
        println!(
            "  cached threshold pubkey: {} bytes (encrypted path)",
            bytes.len()
        );
        Some(Arc::new(tpk))
    } else {
        None
    };

    let submitted = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let run_start = Instant::now();
    let measurement_start_at = run_start + Duration::from_secs(warmup_s);
    let run_deadline = run_start + Duration::from_secs(total_run_s);
    let submitted_during_measure = Arc::new(AtomicU64::new(0));

    runtime.block_on(async {
        let mut tasks = Vec::with_capacity(num_senders);
        for (i, w) in wallets.iter().enumerate() {
            let wallet = w.clone();
            let cli = client.clone();
            let url = rpc_urls[i % rpc_urls.len()].clone();
            let sub_total = submitted.clone();
            let sub_measure = submitted_during_measure.clone();
            let err = errors.clone();
            let interval = per_acct_interval;
            let measure_at = measurement_start_at;
            let deadline = run_deadline;
            let tpk = threshold_pk.clone();

            tasks.push(tokio::spawn(async move {
                // Nonce 0 was consumed by `RegisterPubkey` during
                // setup (audit 229). First payload tx is nonce 1.
                let mut nonce = 1u64;
                let mut next_submit = Instant::now();
                loop {
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    if now < next_submit {
                        tokio::time::sleep(next_submit - now).await;
                    }
                    next_submit += interval;

                    // Build + sign the tx (encrypted or plaintext) on
                    // a blocking thread — both paths involve
                    // FALCON-sign (~1 ms) and the encrypted path
                    // additionally runs a Kyber-768 encap. Off-loading
                    // keeps the tokio runtime free for reqwest I/O.
                    let wallet_for_build = wallet.clone();
                    let tpk_for_build = tpk.clone();
                    let build = tokio::task::spawn_blocking(move || {
                        if let Some(tpk) = tpk_for_build {
                            build_encrypted_tx_hex(
                                &wallet_for_build,
                                nonce,
                                &RECIPIENT,
                                TX_VALUE,
                                CHAIN_ID,
                                &tpk,
                            )
                        } else {
                            build_plaintext_tx_hex(&wallet_for_build, nonce)
                        }
                    })
                    .await;
                    let hex_tx = match build {
                        Ok(Ok(s)) => s,
                        _ => {
                            err.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };

                    let result = if tpk.is_some() {
                        rpc_send_raw_encrypted_fast(&cli, &url, &hex_tx).await
                    } else {
                        rpc_send_raw_fast(&cli, &url, &hex_tx).await
                    };

                    match result {
                        Ok(()) => {
                            sub_total.fetch_add(1, Ordering::Relaxed);
                            if Instant::now() >= measure_at {
                                sub_measure.fetch_add(1, Ordering::Relaxed);
                            }
                            nonce += 1;
                        }
                        Err(_) => {
                            let prev_err = err.fetch_add(1, Ordering::Relaxed);
                            // Sample the first few rejections with the
                            // full response body — gives us the actual
                            // error reason (InvalidNonce, rate-limited,
                            // InsufficientBalance, …) instead of a
                            // generic "submit errors N" count.
                            if i == 0 && prev_err < 3 {
                                let resp = if tpk.is_some() {
                                    rpc_send_raw_encrypted(&cli, &url, &hex_tx).await
                                } else {
                                    rpc_send_raw(&cli, &url, &hex_tx).await
                                };
                                eprintln!(
                                    "  [sender 0] nonce={} rejection #{}: {}",
                                    nonce, prev_err, resp
                                );
                            }
                            // Back off a full slot on rejection. Usually
                            // an InvalidNonce "too far ahead" or a
                            // per-sender rate-limit hit on the
                            // encrypted path — waiting a slot lets the
                            // chain commit a block (or two), advancing
                            // the window so the same tx validates on
                            // retry.
                            tokio::time::sleep(Duration::from_millis(400)).await;
                            next_submit = Instant::now();
                        }
                    }
                }
            }));
        }

        // Progress reporter
        let progress_sub = submitted.clone();
        let progress_err = errors.clone();
        let progress_end = run_deadline;
        let progress_measure_at = measurement_start_at;
        let progress_task = tokio::spawn(async move {
            let mut last_count = 0u64;
            let mut last_time = Instant::now();
            while Instant::now() < progress_end {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let now = Instant::now();
                let cur = progress_sub.load(Ordering::Relaxed);
                let dt = (now - last_time).as_secs_f64();
                let rate = (cur - last_count) as f64 / dt;
                let phase = if now < progress_measure_at {
                    "warmup"
                } else {
                    "measure"
                };
                println!(
                    "  [{:>7}] +{} submits in {:.1}s → {:.0} tx/s (total: {}, errors: {})",
                    phase,
                    cur - last_count,
                    dt,
                    rate,
                    cur,
                    progress_err.load(Ordering::Relaxed),
                );
                last_count = cur;
                last_time = now;
            }
        });

        for t in tasks {
            let _ = t.await;
        }
        let _ = progress_task.await;
    });

    let total_submits = submitted.load(Ordering::Relaxed);
    let measure_submits = submitted_during_measure.load(Ordering::Relaxed);
    let err_count = errors.load(Ordering::Relaxed);
    let submit_tps_measure = measure_submits as f64 / duration_s as f64;
    println!(
        "\n  submit totals: {} total, {} during measurement ({:.0} tx/s), {} errors",
        total_submits, measure_submits, submit_tps_measure, err_count
    );

    // --- Phase 3: settle + measure inclusion ---
    let end_of_submit_balance = runtime
        .block_on(async { fetch_balance(&client, &rpc_urls[0], &RECIPIENT).await })
        .unwrap_or(0);

    println!("\n[3/3] Settling 20 s for final inclusion…");
    runtime.block_on(async {
        tokio::time::sleep(Duration::from_secs(20)).await;
    });

    let post_recipient_balance = runtime
        .block_on(async { fetch_balance(&client, &rpc_urls[0], &RECIPIENT).await })
        .unwrap_or(0);
    let confirmed_at_end_of_submit =
        end_of_submit_balance.saturating_sub(pre_recipient_balance) / TX_VALUE;
    let confirmed_after_settle =
        post_recipient_balance.saturating_sub(pre_recipient_balance) / TX_VALUE;

    let measurement_elapsed = duration_s as f64;
    let total_submit_elapsed = total_run_s as f64;
    let submit_tps_overall = total_submits as f64 / total_submit_elapsed;
    let warmup_submits = total_submits.saturating_sub(measure_submits);
    let confirmed_measurement = confirmed_after_settle.saturating_sub(warmup_submits as u128);
    let inclusion_tps_steady = confirmed_measurement as f64 / measurement_elapsed;
    let inclusion_efficiency = if measure_submits > 0 {
        confirmed_measurement as f64 / measure_submits as f64
    } else {
        0.0
    };

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║  RESULTS                                             ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!(
        "  Target:                 {} TPS for {} s",
        target_tps, duration_s
    );
    println!(
        "  Submitted (total):      {} txs over {:.0} s",
        total_submits, total_submit_elapsed
    );
    println!(
        "  Submitted (measured):   {} txs over {} s ({:.0} tx/s)",
        measure_submits, duration_s, submit_tps_measure
    );
    println!("  Submit errors:          {}", err_count);
    println!(
        "  Confirmed @ submit-end: {} txs",
        confirmed_at_end_of_submit
    );
    println!("  Confirmed @ +20 s:      {} txs", confirmed_after_settle);
    println!(
        "  Inclusion TPS steady:   {:.0} (measured window only)",
        inclusion_tps_steady
    );
    println!(
        "  Inclusion efficiency:   {:.1}%",
        inclusion_efficiency * 100.0
    );
    println!("  Submit TPS overall:     {:.0}", submit_tps_overall);
    println!("╚══════════════════════════════════════════════════════╝");

    let pass_submit_threshold = (target_tps as f64 * 0.9) as u64;
    let pass_inclusion_threshold = (target_tps as f64 * 0.9) as u64;

    // Diagnostics: if the test is about to fail, dump node-0's
    // stdout/stderr so we can see whether blocks are being produced,
    // whether txs are landing, and any warnings from block_processor.
    // Diagnostics on failure: nonces on chain tell us how many txs
    // of each sender actually committed even if recipient-balance
    // sampling timed out against an overloaded RPC.
    if (submit_tps_measure as u64) < pass_submit_threshold || inclusion_efficiency < 0.9 {
        let nonces: Vec<u64> = runtime.block_on(async {
            let mut out = Vec::with_capacity(wallets.len());
            for w in &wallets {
                out.push(
                    fetch_nonce(&client, &rpc_urls[0], &w.address)
                        .await
                        .unwrap_or(0),
                );
            }
            out
        });
        let total_confirmed: u64 = nonces.iter().sum();
        eprintln!(
            "\n  diagnostic: {} txs committed across {} senders (min nonce {}, max {})",
            total_confirmed,
            wallets.len(),
            nonces.iter().min().copied().unwrap_or(0),
            nonces.iter().max().copied().unwrap_or(0),
        );
    }

    // Always dump diagnostic views of node 0's log.
    {
        let snap = net.nodes[0].output_snapshot();

        // (a) Peak-load proposer timing — pick slots with real
        // work (pending > 100) from the middle of the run so we
        // see the steady-state cost, not the drain-down tail.
        // Path A renamed the log line: "proposed and processed"
        // (single-step) → "proposed block (awaiting QC for
        // canonical apply)" (two-step). Match either so this
        // diagnostic keeps working before/after Path A.
        let timing_lines: Vec<&str> = snap
            .lines()
            .filter(|l| {
                (l.contains("proposed and processed") || l.contains("proposed block (awaiting QC"))
                    && !l.contains("pending=0 ")
                    && !l.contains("pending=0\n")
            })
            .collect();
        let n = timing_lines.len();
        let start = n.saturating_sub(30).max(n / 2);
        let sample: Vec<&str> = timing_lines[start..].iter().copied().take(20).collect();
        eprintln!(
            "\n=== node 0 peak-load timing (mid-run sample, {}) ===\n{}\n",
            sample.len(),
            sample.join("\n")
        );

        // gas=0 diagnostics: count blocks by whether they executed
        // successfully. If most blocks show txs>0 but gas=0, the
        // block_processor is failing every tx (the symptom we saw
        // under the old self-proposal bug).
        let mut with_gas = 0usize;
        let mut gas_zero_with_txs = 0usize;
        let mut empty = 0usize;
        for l in &timing_lines {
            let has_txs = !l.contains("txs=0");
            let has_gas = !l.contains("gas=0");
            if !has_txs {
                empty += 1;
            } else if has_gas {
                with_gas += 1;
            } else {
                gas_zero_with_txs += 1;
            }
        }
        eprintln!(
            "  block stats (node 0): empty={}, txs-with-gas={}, txs-but-gas=0={}",
            empty, with_gas, gas_zero_with_txs
        );

        // (b) Any WARN/ERROR produced during the run. If blocks are
        // committing with `gas=0`, the block_processor is either
        // rejecting txs silently or logging `tx execution failed`
        // here — this pass surfaces which.
        let warn_lines: Vec<&str> = snap
            .lines()
            .filter(|l| l.contains(" WARN ") || l.contains(" ERROR "))
            .collect();
        let warn_tail: Vec<&str> = warn_lines.iter().rev().take(30).rev().copied().collect();
        eprintln!(
            "=== node 0 WARN/ERROR (last {}) ===\n{}\n",
            warn_tail.len(),
            warn_tail.join("\n")
        );
    }

    assert!(
        submit_tps_measure as u64 >= pass_submit_threshold,
        "FAIL: submit rate {:.0} TPS < 90% of target {}",
        submit_tps_measure,
        target_tps
    );
    assert!(
        inclusion_efficiency >= 0.9,
        "FAIL: only {:.1}% of submitted txs confirmed",
        inclusion_efficiency * 100.0
    );
    assert!(
        inclusion_tps_steady as u64 >= pass_inclusion_threshold,
        "FAIL: inclusion TPS {:.0} < 90% of target {}",
        inclusion_tps_steady,
        target_tps
    );
    println!(
        "\n  ✓ PASS — target {} TPS, sustained submit {:.0}, sustained inclusion {:.0}",
        target_tps, submit_tps_measure, inclusion_tps_steady
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn env_var_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

async fn rpc_call(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: &str,
) -> serde_json::Value {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":[{}]}}"#,
        method, params
    );
    match client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body)
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        Ok(r) => r.json().await.unwrap_or(serde_json::Value::Null),
        Err(_) => serde_json::Value::Null,
    }
}

async fn rpc_send_raw(client: &reqwest::Client, url: &str, tx_hex: &str) -> serde_json::Value {
    rpc_call(
        client,
        url,
        "pyde_sendRawTransaction",
        &format!("\"0x{}\"", tx_hex),
    )
    .await
}

async fn rpc_send_raw_encrypted(
    client: &reqwest::Client,
    url: &str,
    tx_hex: &str,
) -> serde_json::Value {
    rpc_call(
        client,
        url,
        "pyde_sendRawEncryptedTransaction",
        &format!("\"0x{}\"", tx_hex),
    )
    .await
}

/// Same fast-path as `rpc_send_raw_fast` but targets the encrypted-tx
/// ingress endpoint. Used by the encrypted variant of the load run.
async fn rpc_send_raw_encrypted_fast(
    client: &reqwest::Client,
    url: &str,
    tx_hex: &str,
) -> Result<(), ()> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"pyde_sendRawEncryptedTransaction","params":["0x{}"]}}"#,
        tx_hex
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
    Ok(())
}

/// Fetch the committee threshold pubkey via
/// `pyde_getThresholdPublicKey`. The encrypted path needs this to
/// build `EncryptedTx` ciphertexts; we cache it once at start-up
/// rather than re-fetching per submission.
async fn fetch_threshold_pk_bytes(client: &reqwest::Client, url: &str) -> Option<Vec<u8>> {
    let resp = rpc_call(client, url, "pyde_getThresholdPublicKey", "[]").await;
    let s = resp.get("result")?.as_str()?.to_string();
    let stripped = s.strip_prefix("0x").unwrap_or(&s);
    hex::decode(stripped).ok()
}

/// Encode a signed plaintext transfer at `nonce` from `wallet` to
/// `RECIPIENT`. Mirrors the inline build that the load loop did
/// before; pulled out so the encrypted variant can share the same
/// spawn_blocking shape.
fn build_plaintext_tx_hex(wallet: &Wallet, nonce: u64) -> Result<String, ()> {
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
    let sig = falcon_sign(&wallet.sk, &tx.hash()).map_err(|_| ())?;
    tx.signature = sig.as_bytes().to_vec();
    Ok(hex::encode(tx.to_bytes()))
}

/// Build a signed encrypted transfer (Kyber-768 + threshold) at
/// `nonce` from `wallet` to `recipient` for `value` quanta. Returns
/// the wire-encoded `EncryptedTx` as hex, ready for
/// `pyde_sendRawEncryptedTransaction`.
///
/// Mirrors `common::TestNetwork::submit_encrypted_transfer_inner`
/// but inlined here so we can stay within the loadgen file's
/// async/spawn_blocking model and reuse the cached threshold pubkey
/// instead of refetching per call.
fn build_encrypted_tx_hex(
    wallet: &Wallet,
    nonce: u64,
    recipient: &[u8; 32],
    value: u128,
    chain_id: u64,
    tpk: &pyde_crypto::threshold::ThresholdPublicKey,
) -> Result<String, ()> {
    // `Mempool::check_core_validity` rejects encrypted txs with an
    // empty access_list. Add a single-entry list for the recipient.
    let access_list = vec![pyde_tx::types::AccessEntry {
        address: *recipient,
        reads: Vec::new(),
        writes: Vec::new(),
    }];
    let mut enc_tx = pyde_mempool::encrypted::encrypt_transaction(
        wallet.address,
        nonce,
        /* gas_limit */ 100_000,
        access_list,
        /* deadline */ None,
        chain_id,
        /* signature */ Vec::new(),
        recipient,
        value,
        /* calldata */ &[],
        tpk,
    )
    .map_err(|_| ())?;
    let tx_hash = enc_tx.hash();
    let sig = falcon_sign(&wallet.sk, &tx_hash).map_err(|_| ())?;
    enc_tx.signature = sig.as_bytes().to_vec();
    Ok(hex::encode(enc_tx.to_bytes()))
}

/// Read a boolean env var. Truthy: "1", "true", "yes" (case-insensitive).
/// Anything else (including unset) returns `default`.
fn env_var_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => default,
    }
}

/// Returns `Ok` only when HTTP 200 AND the JSON-RPC body has no
/// `"error"`. jsonrpsee returns HTTP 200 with an error body for
/// nonce-too-high, mempool-full, invalid-sig — a bare status check
/// would overcount successful submits.
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
        .map_err(|_| ())?;
    if !resp.status().is_success() {
        return Err(());
    }
    let text = resp.text().await.map_err(|_| ())?;
    if text.contains(r#""error""#) {
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
    let s = resp.get("result")?.as_str()?.to_string();
    if let Some(h) = s.strip_prefix("0x") {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
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
    let s = resp.get("result")?.as_str()?.to_string();
    if let Some(h) = s.strip_prefix("0x") {
        u128::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
    }
}
