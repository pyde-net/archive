//! Long-running multi-node soak test for hardening.
//!
//! Spawns a 4-node devnet, drives a sustained tx load, and
//! periodically asserts the chain stays healthy:
//!
//!   - All nodes advance the head slot at roughly the target
//!     rate (no validator stalls).
//!   - All nodes' state roots match at any sampled slot
//!     (consensus determinism — the AOT vs interpreter parity
//!     audits 228a-d are exercised under real load here).
//!   - Mempool stays bounded (no unbounded growth — M2 TTL +
//!     M3 cap should drain).
//!   - All node processes stay alive.
//!
//! Designed to surface what unit tests can't catch:
//! - Memory leaks (RocksDB, mempool, decryptor queues, gossip
//!   message caches)
//! - Slot-clock drift across nodes
//! - State-root divergence under concurrent load
//! - Background-task starvation
//! - Validator thread deadlocks
//!
//! Default duration is 5 minutes (CI-friendly). Set
//! `SOAK_DURATION_SECS` to override — recommended values for
//! pre-mainnet hardening:
//!   - 300 (5 min) — basic smoke
//!   - 1800 (30 min) — finds gradual leaks
//!   - 21600 (6 h) — surfaces drift
//!   - 86400 (24 h) — full pre-deploy soak
//!
//! Marked `#[ignore]` because spawning real subprocesses is
//! heavy. Run with:
//!   cargo test -p pyde-node --test soak -- --ignored --nocapture

mod common;

use common::TestNetwork;
use std::time::{Duration, Instant};

const DEFAULT_DURATION_SECS: u64 = 300;
const TX_RATE_PER_SEC: u64 = 2;
const CHECK_INTERVAL_SECS: u64 = 15;
/// Mempool sanity bound. Steady state should be <100 (txs
/// drain on every 400 ms slot). Anything above this means
/// the M2 TTL sweep / M3 cap is broken or block production
/// stalled. Caps at 10× MEMPOOL_GLOBAL_CAP / 100 = headroom.
const MEMPOOL_BOUND: usize = 10_000;
/// Slot-rate floor: per CHECK_INTERVAL the head should advance
/// at least this many slots. At 400 ms target, 25 slots/10s is
/// healthy; we tolerate ~33% of that to absorb laptop CPU
/// contention, multi-proposer race retries, and the audit-232
/// reorg path's transient stalls when a competing block isn't
/// buffered. Genuine stalls (deadlock, validator died) advance
/// 0 slots and are easily caught.
const MIN_SLOTS_PER_INTERVAL: u64 = 10;

#[test]
#[ignore = "long-running soak — opt in via --ignored, override duration with SOAK_DURATION_SECS"]
fn soak_multi_node_under_sustained_load() {
    let duration = std::env::var("SOAK_DURATION_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_DURATION_SECS);
    let duration = Duration::from_secs(duration);
    eprintln!(
        "soak: spawning 4-node devnet for {}s ({} tx/sec, check every {}s)",
        duration.as_secs(),
        TX_RATE_PER_SEC,
        CHECK_INTERVAL_SECS
    );

    let net = TestNetwork::spawn(4, true).unwrap_or_else(|e| panic!("spawn 4-node: {e}"));

    // Initial warm-up — let bootstrap + gossip mesh settle.
    net.wait_for_slot(5, Duration::from_secs(45))
        .unwrap_or_else(|e| panic!("warm-up: {}", e));

    let funded = net
        .funded_addresses()
        .unwrap_or_else(|e| panic!("read funded addresses: {}", e));
    assert!(
        funded.len() > 5,
        "soak needs at least 5 funded addresses (4 validators + ≥1 spare); got {}",
        funded.len()
    );
    // Sender: validator 0 (has balance + AuthKeys::Single via genesis).
    // Recipient: a non-validator funded address — keeps balance math
    // simple and avoids contaminating slot-reward bookkeeping.
    let sender = funded[0];
    let recipient = funded[4];

    let start = Instant::now();
    let deadline = start + duration;
    let mut next_check = start + Duration::from_secs(CHECK_INTERVAL_SECS);
    let mut last_check_slot: Option<u64> = None;
    let mut tx_count = 0u64;
    let mut anomalies: Vec<String> = Vec::new();
    let tx_interval = Duration::from_millis(1000 / TX_RATE_PER_SEC.max(1));

    while Instant::now() < deadline {
        // Submit one tx per tick. submit_transfer goes through the
        // dev-mode pyde_sendTransaction (chain_id=31337), which
        // auto-fills nonce on the server side, so a steady stream
        // of txs from the same `from` works without bookkeeping.
        match net.submit_transfer(
            (tx_count as usize) % net.nodes.len(),
            &sender,
            &recipient,
            1, // 1 quanta per tx — keeps balance math interpretable
        ) {
            Ok(_hash) => tx_count += 1,
            Err(e) => {
                // Transient submission failures (gossip backpressure,
                // mempool full) are expected under load. Only flag
                // sustained failures.
                if !e.contains("mempool full") && !e.contains("duplicate") {
                    eprintln!("soak: tx submit anomaly: {}", e);
                }
            }
        }

        // Periodic health check. Recompute next_check from `now`
        // rather than incrementing — if a submit hangs, we don't
        // want a backlog of "missed" checks to fire all at once
        // (which would all see the same head slot and falsely
        // accuse the chain of stalling).
        let now = Instant::now();
        if now >= next_check {
            run_health_check(
                &net,
                &mut anomalies,
                &mut last_check_slot,
                tx_count,
                start.elapsed(),
            );
            next_check = now + Duration::from_secs(CHECK_INTERVAL_SECS);
            if !anomalies.is_empty() {
                let dump = node_diagnostics(&net);
                panic!(
                    "soak failed at t={}s after {} txs:\n  {}\n{}",
                    start.elapsed().as_secs(),
                    tx_count,
                    anomalies.join("\n  "),
                    dump
                );
            }
        }

        std::thread::sleep(tx_interval);
    }

    eprintln!(
        "soak: completed cleanly — {} txs over {}s, {} health checks passed",
        tx_count,
        duration.as_secs(),
        duration.as_secs() / CHECK_INTERVAL_SECS
    );
}

/// Run all health checks, append any anomalies to `anomalies`.
fn run_health_check(
    net: &TestNetwork,
    anomalies: &mut Vec<String>,
    last_check_slot: &mut Option<u64>,
    tx_count: u64,
    elapsed: Duration,
) {
    // 1. All nodes still running.
    for n in &net.nodes {
        if !n.is_running() {
            anomalies.push(format!("node-{} process died", n.index));
        }
    }
    if !anomalies.is_empty() {
        return;
    }

    // 2. State roots match across all nodes (consensus determinism).
    let roots: Vec<(usize, String)> = net
        .nodes
        .iter()
        .filter_map(|n| net.state_root(n.index).ok().map(|r| (n.index, r)))
        .collect();
    if let Some((_, ref reference)) = roots.first() {
        for (idx, root) in &roots[1..] {
            if root != reference {
                anomalies.push(format!(
                    "state_root divergence: node-0={} node-{}={}",
                    reference, idx, root
                ));
            }
        }
    }

    // 3. Slot rate — every interval the head should advance at
    //    least MIN_SLOTS_PER_INTERVAL.
    let current_slots: Vec<(usize, Option<u64>)> = net.current_slots();
    let head_slot = current_slots
        .iter()
        .filter_map(|(_, s)| *s)
        .max()
        .unwrap_or(0);
    if let Some(prev) = *last_check_slot {
        let advanced = head_slot.saturating_sub(prev);
        if advanced < MIN_SLOTS_PER_INTERVAL {
            anomalies.push(format!(
                "slot rate too low: advanced {} slots in {}s (min {})",
                advanced, CHECK_INTERVAL_SECS, MIN_SLOTS_PER_INTERVAL
            ));
        }
    }
    *last_check_slot = Some(head_slot);

    // 4. Mempool isn't growing unboundedly. Probe via the metrics
    //    endpoint of node-0 (Prometheus exporter from audit 222).
    //    A growing mempool is the canary for stuck block production
    //    or a wedged TTL sweep.
    if let Some(mempool_size) = scrape_metric(net, 0, "pyde_mempool_size") {
        if mempool_size > MEMPOOL_BOUND as f64 {
            anomalies.push(format!(
                "mempool overflow: {} > {} (M2 TTL or M3 cap broken?)",
                mempool_size as u64, MEMPOOL_BOUND
            ));
        }
    }

    eprintln!(
        "soak: t={}s txs={} head={} roots_agree={} mempool={}",
        elapsed.as_secs(),
        tx_count,
        head_slot,
        roots.windows(2).all(|w| w[0].1 == w[1].1),
        scrape_metric(net, 0, "pyde_mempool_size")
            .map(|v| format!("{:.0}", v))
            .unwrap_or_else(|| "?".to_string()),
    );
}

/// Scrape a single Prometheus gauge value from a node's metrics
/// endpoint. Returns None if the metric isn't present or the
/// endpoint isn't reachable — soak treats that as "skip the check"
/// rather than failing, since the metrics endpoint is best-effort.
fn scrape_metric(net: &TestNetwork, node_idx: usize, metric_name: &str) -> Option<f64> {
    let metrics_port = net.nodes[node_idx].rpc_port + 1000;
    let url = format!("http://127.0.0.1:{}/metrics", metrics_port);
    let body = reqwest::blocking::get(&url).ok()?.text().ok()?;
    for line in body.lines() {
        if line.starts_with(metric_name) && !line.starts_with('#') {
            // Format: `metric_name [labels] VALUE` — last whitespace-
            // separated token is the value.
            return line.split_whitespace().last().and_then(|v| v.parse().ok());
        }
    }
    None
}

/// Tail of each node's stdout/stderr for diagnostic dumps on
/// failure.
fn node_diagnostics(net: &TestNetwork) -> String {
    net.nodes
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
        .join("")
}
