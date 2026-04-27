//! Encrypted-path burst stress test (audit task 074b sustained).
//!
//! Goal: empirically answer "how many encrypted txs can a 4-validator
//! testnet commit under realistic concurrent load, and at what rate".
//!
//! Single-sender bursts hit the audit-027 per-sender rate cap
//! (`DEFAULT_MAX_TX_PER_WINDOW_PER_SENDER = 10` enc-tx / second / sender),
//! which is intentional spam defense — not a flow bug. To exercise
//! the actual gossip + decrypt pipeline we fan out across all four
//! validator keys, each at the per-sender limit, so the aggregate
//! load through the encrypted-share path is well past what a single
//! sender could ever push.
//!
//! Methodology:
//!
//!   1. Spawn 4-node testnet, warm up to slot 15 (matches the
//!      lifecycle-test warm-up — gossipsub mesh has fully published
//!      subscriber lists by then).
//!   2. From each of the 4 validators, submit BURST_PER_SENDER
//!      encrypted transfers to a single recipient with sequential
//!      nonces. RPC node rotates per tx so no single mempool is the
//!      bottleneck.
//!   3. Wait DEADLINE for all submitted txs to land in the
//!      recipient's balance. Inclusion is `(observed_balance -
//!      pre_balance) / transfer_value`; partial increases mean
//!      partial inclusion, cleanly distinguishable from "stuck".
//!   4. Report: submitted, committed, inclusion-rate, latency,
//!      throughput.
//!
//! Marked `#[ignore]` because it spawns subprocesses — run via
//! `cargo test --ignored encrypted_burst -- --nocapture`.

mod common;

use common::TestNetwork;
use std::time::{Duration, Instant};

/// Per-sender burst. Stays at the audit-027 per-window cap of 10 so
/// no submission gets rejected as rate-limited — we want to measure
/// the post-mempool path, not the rate-limit gate. Override via
/// `PYDE_ENC_BURST_PER_SENDER` for stress runs.
fn burst_per_sender() -> u64 {
    std::env::var("PYDE_ENC_BURST_PER_SENDER")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10)
}

const TRANSFER_VALUE: u128 = 1_000_000;
const INCLUSION_DEADLINE: Duration = Duration::from_secs(180);
const PASS_INCLUSION_PCT: f64 = 70.0;

#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn encrypted_burst_inclusion_rate() {
    let per_sender = burst_per_sender();
    let net =
        TestNetwork::spawn(4, true).unwrap_or_else(|e| panic!("spawn 4-node testnet: {}", e));

    net.wait_for_slot(15, Duration::from_secs(45))
        .unwrap_or_else(|e| panic!("warm-up to slot 15: {}", e));

    // Load all 4 validator keypairs as the sender pool. Rate limit
    // is per-sender, so 4 senders × 10 = 40-tx aggregate burst at
    // the cap.
    let mut senders: Vec<(Vec<u8>, Vec<u8>, [u8; 32], u64)> = Vec::with_capacity(4);
    for v in 0..net.nodes.len() {
        let (pk, sk) = net
            .load_validator_key(v)
            .unwrap_or_else(|e| panic!("load validator {v} key: {e}"));
        let addr = pyde_account::address::derive_eoa_address(&pk);
        let nonce = net
            .get_nonce(0, &addr)
            .unwrap_or_else(|e| panic!("get_nonce v={v}: {e}"));
        senders.push((pk, sk, addr, nonce));
    }

    let funded = net
        .funded_addresses()
        .unwrap_or_else(|e| panic!("funded_addresses: {}", e));
    assert!(funded.len() > 4, "expected >4 funded addresses");
    let recipient = funded[4];

    let pre_balance = net
        .get_balance(0, &recipient)
        .unwrap_or_else(|e| panic!("get_balance pre: {}", e));

    let total_target = (senders.len() as u64) * per_sender;
    eprintln!(
        "burst plan: senders={} per_sender={} total_target={total_target} recipient={}",
        senders.len(),
        per_sender,
        hex::encode(recipient),
    );

    // Submit. Two-level loop (per-sender outer, per-tx inner) keeps
    // each sender's nonces sequential. Rotating the RPC node across
    // submissions spreads ingress load.
    let submit_start = Instant::now();
    let mut submitted = 0u64;
    let mut submit_errors: Vec<String> = Vec::new();
    let mut tx_counter = 0u64;
    for (s_idx, (pk, sk, _addr, start_nonce)) in senders.iter().enumerate() {
        for i in 0..per_sender {
            let nonce = start_nonce + i;
            let rpc_idx = (tx_counter as usize) % net.nodes.len();
            tx_counter += 1;
            match net.submit_encrypted_transfer_with_nonce(
                rpc_idx,
                pk,
                sk,
                &recipient,
                TRANSFER_VALUE,
                nonce,
            ) {
                Ok(_) => submitted += 1,
                Err(e) => {
                    eprintln!("submit sender={s_idx} nonce={nonce} rpc={rpc_idx} FAILED: {e}");
                    submit_errors.push(format!("sender={s_idx} nonce={nonce}: {e}"));
                }
            }
        }
    }
    let submit_duration = submit_start.elapsed();
    eprintln!(
        "submission phase: {submitted}/{total_target} accepted in {:?}",
        submit_duration
    );

    if submitted == 0 {
        panic!(
            "no encrypted txs accepted — flow broken before consensus.\nerrors: {:#?}",
            submit_errors
        );
    }

    // Poll for inclusion via balance delta.
    let target_balance = pre_balance + (submitted as u128) * TRANSFER_VALUE;
    let deadline = Instant::now() + INCLUSION_DEADLINE;
    let mut last_balance = pre_balance;
    let mut last_committed = 0u64;
    let mut hit_full = false;

    while Instant::now() < deadline {
        let cur = net.get_balance(0, &recipient).unwrap_or(0);
        last_balance = cur;
        let committed = ((cur.saturating_sub(pre_balance)) / TRANSFER_VALUE) as u64;
        if committed != last_committed {
            eprintln!(
                "committed {committed}/{submitted} ({:.1}s)",
                Instant::now().duration_since(submit_start).as_secs_f64()
            );
            last_committed = committed;
        }
        if cur >= target_balance {
            hit_full = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    let total_elapsed = submit_start.elapsed();
    let final_committed = ((last_balance.saturating_sub(pre_balance)) / TRANSFER_VALUE) as u64;
    let inclusion_pct = if submitted == 0 {
        0.0
    } else {
        100.0 * final_committed as f64 / submitted as f64
    };
    let throughput_tps = if total_elapsed.as_secs_f64() > 0.0 {
        final_committed as f64 / total_elapsed.as_secs_f64()
    } else {
        0.0
    };

    eprintln!(
        "\n=== encrypted burst result ===\n\
         senders:      {}\n\
         per_sender:   {per_sender}\n\
         submitted:    {submitted}/{total_target}\n\
         committed:    {final_committed}\n\
         inclusion:    {inclusion_pct:.1}%\n\
         elapsed:      {:?}\n\
         throughput:   {throughput_tps:.2} encrypted-tx/s aggregate\n\
         hit_full:     {hit_full}\n\
         submit_errors: {}\n",
        senders.len(),
        total_elapsed,
        submit_errors.len(),
    );

    // Cross-node convergence: every node must see the same
    // post-burst balance. Otherwise some node missed the decryption
    // path even though the canonical chain accepted the txs.
    if final_committed > 0 {
        let n0 = net.get_balance(0, &recipient).unwrap_or(0);
        for n in &net.nodes[1..] {
            let nb = net.get_balance(n.index, &recipient).unwrap_or(0);
            assert_eq!(
                nb, n0,
                "balance divergence: node-0={n0}, node-{}={nb}",
                n.index
            );
        }
    }

    if inclusion_pct < PASS_INCLUSION_PCT {
        let dumps = net
            .nodes
            .iter()
            .map(|n| {
                format!(
                    "\n=== node-{} (rpc {}) ===\n{}",
                    n.index,
                    n.rpc_port,
                    n.output_snapshot()
                )
            })
            .collect::<Vec<_>>()
            .join("");
        panic!(
            "encrypted burst inclusion {inclusion_pct:.1}% < pass threshold {PASS_INCLUSION_PCT:.1}%\n\
             submitted={submitted} committed={final_committed}\n\
             submit_errors first 5: {:#?}{dumps}",
            submit_errors.iter().take(5).collect::<Vec<_>>()
        );
    }
}
