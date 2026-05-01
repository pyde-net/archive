//! Validator churn at the 4-of-4 boundary.
//!
//! Rotates EVERY validator in a 4-node committee — the last
//! rotation kills the only never-restarted node. Pre-fix this
//! reliably stalled the chain because of two compounding issues:
//!
//! 1. Gossipsub publish for the consensus topic returned
//!    `InsufficientPeers` after restart cycles (libp2p
//!    subscription state didn't re-sync), so view-change
//!    messages silently dropped.
//! 2. Even with delivery fixed, alive validators ended up in
//!    inconsistent states: some voted on stale buffered
//!    proposals from the dead proposer (proposal_received
//!    suppresses their primary timeout), others timed out and
//!    sent view-change. Neither vote-QC nor view-change-QC
//!    reached quorum.
//!
//! Audit 234 part 3 ships the full fix:
//! - RR fallback for consensus broadcasts when gossip publish
//!   fails (delivery half).
//! - "Vote-but-no-progress" secondary timeout: if a validator
//!   voted but no QC for the slot is observed within
//!   `PROGRESS_TIMEOUT_MS`, the validator triggers view-change
//!   anyway — the protocol-level liveness fallback (consistency
//!   half).
//!
//! Marked `#[ignore]` because subprocess-based.

mod common;

use common::TestNetwork;
use std::time::{Duration, Instant};

const WARMUP_SLOT: u64 = 30;
const DOWNTIME_SECS: u64 = 8;
const MIN_SLOTS_DURING_DOWNTIME: u64 = 5;
const CATCHUP_TIMEOUT_SECS: u64 = 60;
const STEADY_STATE_SLOTS: u64 = 10;

fn max_live_head(net: &TestNetwork, exclude: Option<usize>) -> u64 {
    net.current_slots()
        .into_iter()
        .filter(|(idx, _)| Some(*idx) != exclude)
        .filter_map(|(_, s)| s)
        .max()
        .unwrap_or(0)
}

fn wait_for_convergence(
    net: &TestNetwork,
    tolerance: u64,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let slots: Vec<u64> = net
            .current_slots()
            .into_iter()
            .filter_map(|(_, s)| s)
            .collect();
        if slots.len() == net.nodes.len() {
            let max = *slots.iter().max().unwrap();
            let min = *slots.iter().min().unwrap();
            if max.saturating_sub(min) <= tolerance {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(format!("did not converge: {slots:?}"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn wait_for_steady_state(net: &TestNetwork, slots: u64, timeout: Duration) -> Result<(), String> {
    let baseline = max_live_head(net, None);
    let target = baseline + slots;
    let deadline = Instant::now() + timeout;
    loop {
        if max_live_head(net, None) >= target {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "stall: head {} target {target}",
                max_live_head(net, None)
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn wait_for_node_slot(
    net: &TestNetwork,
    node_idx: usize,
    target_slot: u64,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let cur = net
            .current_slots()
            .into_iter()
            .find(|(i, _)| *i == node_idx)
            .and_then(|(_, s)| s)
            .unwrap_or(0);
        if cur >= target_slot {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "node-{node_idx} stuck at {cur}, target {target_slot}"
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn rolling_restart_4_of_4() {
    let mut net = TestNetwork::spawn(4, true).unwrap_or_else(|e| panic!("spawn: {e}"));
    net.wait_for_slot(WARMUP_SLOT, Duration::from_secs(60))
        .unwrap_or_else(|e| panic!("warmup: {e}"));
    eprintln!("churn4: warmed up to slot {WARMUP_SLOT}");

    let initial_root = net.state_root(0).unwrap();
    for n in &net.nodes[1..] {
        let r = net.state_root(n.index).unwrap();
        assert_eq!(r, initial_root, "pre-test root divergence node-{}", n.index);
    }

    for victim in 0..4 {
        eprintln!("churn4: --- rotating node-{victim} ---");
        let pre = max_live_head(&net, Some(victim));
        net.kill_node(victim).unwrap();
        std::thread::sleep(Duration::from_secs(DOWNTIME_SECS));
        let post = max_live_head(&net, Some(victim));
        let advanced = post.saturating_sub(pre);
        if advanced < MIN_SLOTS_DURING_DOWNTIME {
            for n in &net.nodes {
                let snap = n.output_snapshot();
                let tail: Vec<&str> = snap.lines().rev().take(80).collect();
                eprintln!("\n=== node-{} (last 80) ===", n.index);
                for l in tail.into_iter().rev() {
                    eprintln!("  {l}");
                }
            }
            panic!("churn4: chain stalled while node-{victim} down — advanced {advanced} slots in {DOWNTIME_SECS}s (min {MIN_SLOTS_DURING_DOWNTIME})");
        }
        eprintln!("churn4: node-{victim} down {DOWNTIME_SECS}s, chain advanced {advanced} ({pre}->{post})");

        net.restart_node(victim).unwrap();
        let target = max_live_head(&net, None) + 3;
        wait_for_node_slot(
            &net,
            victim,
            target,
            Duration::from_secs(CATCHUP_TIMEOUT_SECS),
        )
        .unwrap();
        wait_for_convergence(&net, 2, Duration::from_secs(CATCHUP_TIMEOUT_SECS)).unwrap();
        wait_for_steady_state(
            &net,
            STEADY_STATE_SLOTS,
            Duration::from_secs(CATCHUP_TIMEOUT_SECS),
        )
        .unwrap();
        eprintln!("churn4: node-{victim} caught up + steady");

        let r0 = net.state_root(victim).unwrap();
        for n in &net.nodes {
            if n.index == victim {
                continue;
            }
            let r = net.state_root(n.index).unwrap();
            assert_eq!(r, r0, "post-rotation root divergence on node-{}", n.index);
        }
    }

    for n in &net.nodes {
        assert!(
            n.is_running(),
            "node-{} died during 4-of-4 rotation",
            n.index
        );
    }
    eprintln!(
        "churn4: passed — rotated 4 of 4 validators, final head {}, all roots agree",
        max_live_head(&net, None)
    );
}
