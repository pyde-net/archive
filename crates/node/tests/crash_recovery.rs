//! Crash recovery: kill -9 a validator mid-operation, restart,
//! assert the chain stays consistent and the restarted node
//! catches back up via gossip + sync.
//!
//! Why this matters. Real operators get power outages, OOM
//! kills, kernel panics, and Docker restarts. None of these
//! are graceful shutdowns — there's no chance to flush an
//! in-flight Merkle commit, drain the mempool, or persist
//! "I was about to do X" state. The node must be designed so
//! its on-disk state at any kill point is recoverable.
//!
//! Test scenario:
//!   1. Spawn 4-node devnet, let it produce ~30 slots of blocks.
//!   2. SIGKILL node-0 (the equivalent of `kill -9`).
//!   3. Other 3 validators continue producing blocks (3-of-4 ≥
//!      2/3 honest, so QCs still form).
//!   4. Wait until the 3-node majority advances 30+ slots past
//!      where node-0 died.
//!   5. Restart node-0 with the same datadir.
//!   6. Assert node-0 catches up — `head_slot` reaches the
//!      majority's tip and `state_root` matches.
//!
//! Marked `#[ignore]` because it spawns real subprocesses.

mod common;

use common::TestNetwork;
use std::time::Duration;

#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn validator_recovers_from_kill_minus_9() {
    let mut net = TestNetwork::spawn(4, true).unwrap_or_else(|e| panic!("spawn 4-node: {e}"));

    // 1. Let the chain warm up so all validators are committee-active
    //    and have built persistent state.
    net.wait_for_slot(30, Duration::from_secs(60))
        .unwrap_or_else(|e| panic!("warm-up to slot 30: {e}"));

    let pre_crash_root = net
        .state_root(0)
        .unwrap_or_else(|e| panic!("pre-crash state_root node-0: {e}"));
    eprintln!(
        "crash_recovery: pre-crash node-0 state_root = {}",
        pre_crash_root
    );

    // Sanity: all 4 nodes agree on root before the kill.
    for n in &net.nodes[1..] {
        let r = net
            .state_root(n.index)
            .unwrap_or_else(|e| panic!("pre-crash state_root node-{}: {e}", n.index));
        assert_eq!(
            r, pre_crash_root,
            "pre-crash state_root divergence on node-{}",
            n.index
        );
    }

    // 2. SIGKILL node-0. No graceful shutdown — simulates power
    //    loss, OOM kill, kernel panic.
    net.kill_node(0)
        .unwrap_or_else(|e| panic!("kill node-0: {e}"));
    eprintln!("crash_recovery: SIGKILL'd node-0");

    // 3. The remaining 3 validators are 3/4 = 75% of the committee
    //    — well above the 2/3 HotStuff QC threshold — so block
    //    production must continue. Wait for the majority to
    //    advance 30 slots past the kill point.
    let advance_target = {
        // Find the highest head_slot among the still-running nodes.
        let live_heads: Vec<u64> = net
            .nodes
            .iter()
            .filter(|n| n.index != 0)
            .filter_map(|n| net.current_slots().into_iter().find(|(i, _)| *i == n.index))
            .filter_map(|(_, s)| s)
            .collect();
        let highest = live_heads.iter().max().copied().unwrap_or(0);
        highest + 30
    };
    eprintln!(
        "crash_recovery: waiting for live nodes to advance to slot {}",
        advance_target
    );
    // wait_for_slot waits for ALL nodes; node-0 is dead so its
    // slot is None forever. Inline-poll the live nodes only.
    {
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        loop {
            let live_min: Option<u64> = net
                .nodes
                .iter()
                .filter(|n| n.index != 0)
                .filter_map(|n| net.current_slots().into_iter().find(|(i, _)| *i == n.index))
                .filter_map(|(_, s)| s)
                .min();
            if live_min.map(|v| v >= advance_target).unwrap_or(false) {
                break;
            }
            if std::time::Instant::now() >= deadline {
                panic!(
                    "post-kill chain advance to {advance_target} timed out — live mins {:?}",
                    live_min
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    // 4. Restart node-0 — picks up persisted RocksDB state, sync
    //    fills the gap.
    net.restart_node(0)
        .unwrap_or_else(|e| panic!("restart node-0: {e}"));
    eprintln!("crash_recovery: restarted node-0");

    // 5. Give node-0 time to sync. The existing
    //    `multi_node_partition_heal` exercises the same path
    //    (linear block sync from a peer ahead), so the
    //    convergence behavior is well-trodden — we just need
    //    a generous timeout to absorb startup + sync.
    let post_restart_target = advance_target + 5;
    net.wait_for_slot(post_restart_target, Duration::from_secs(120))
        .unwrap_or_else(|e| panic!("node-0 catch-up to {post_restart_target}: {e}"));

    // 6. Sample the post-recovery state root on every node;
    //    they must all agree, and node-0 must have caught up
    //    to the same head as the others.
    let post_root = net
        .state_root(0)
        .unwrap_or_else(|e| panic!("post-recovery state_root node-0: {e}"));
    for n in &net.nodes[1..] {
        let r = net
            .state_root(n.index)
            .unwrap_or_else(|e| panic!("post-recovery state_root node-{}: {e}", n.index));
        assert_eq!(
            r, post_root,
            "post-recovery state_root divergence on node-{} (node-0={}, node-{}={})",
            n.index, post_root, n.index, r
        );
    }

    // 7. Assert node-0's head slot caught up to the network tip.
    //    Use head_slot rather than state_root for the
    //    "chain advanced" check — devnet empty blocks (no txs,
    //    no validator subsidy configured) legitimately produce
    //    identical state roots, so a root-equality test would
    //    misfire. The roots-agree check above already catches
    //    "node-0 sees a divergent state", which is the real
    //    failure mode.
    let post_head = net
        .nodes
        .iter()
        .filter_map(|n| net.current_slots().into_iter().find(|(i, _)| *i == n.index))
        .filter_map(|(_, s)| s)
        .min()
        .unwrap_or(0);
    assert!(
        post_head >= post_restart_target,
        "post-recovery head {} < target {}",
        post_head,
        post_restart_target
    );

    eprintln!(
        "crash_recovery: passed — all 4 nodes at head ≥{} with state_root={} after restart",
        post_restart_target, post_root
    );
}
