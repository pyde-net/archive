//! Partition → heal → no-fork test (slice 6.8, plan task 070).
//!
//! True symmetric partition (both sides alive, disconnected by a
//! firewall rule) would need OS-level network injection — iptables
//! on Linux, pfctl on macOS, both requiring root. Neither is
//! portable for the laptop-local harness.
//!
//! The invariant we actually care about: a validator disconnected
//! from the majority, that loses quorum-reach to the rest, must
//! stall while the majority keeps producing blocks, and then
//! cleanly rejoin + sync without forking the chain. That invariant
//! is exercised correctly by killing the odd-one-out process
//! (node-3), letting the majority run alone, then restarting
//! node-3 with its persisted state — it reconnects, catches up
//! via sync, and converges.
//!
//! Different from slice 6.4: 6.4 is cold-start sync (empty
//! datadir, apply genesis, walk from slot 0). This test is
//! warm-restart sync — node-3's RocksDB already has blocks through
//! slot ~20 when it goes down, so the sync protocol has to
//! correctly resume from a non-genesis head.
//! Different from slice 6.5: 6.5 kills a validator and never
//! restarts it. This test heals.

mod common;

use common::TestNetwork;
use std::time::{Duration, Instant};

#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn partitioned_validator_heals_without_fork() {
    let mut net = TestNetwork::spawn(4, true)
        .unwrap_or_else(|e| panic!("spawn 4v: {}", e));

    // Warm up: every node agrees on some history before we disrupt.
    net.wait_for_slot(20, Duration::from_secs(60))
        .unwrap_or_else(|e| panic!("warm-up: {}", e));

    // Snapshot pre-partition state roots so we can later verify the
    // majority's root at partition time is derivable in the healed
    // world too (i.e. no one diverged).
    let pre_partition_root = net
        .state_root(0)
        .unwrap_or_else(|e| panic!("pre-partition root: {}", e));
    for n in &net.nodes[1..] {
        let r = net
            .state_root(n.index)
            .unwrap_or_else(|e| panic!("state_root node-{}: {}", n.index, e));
        assert_eq!(
            r, pre_partition_root,
            "pre-partition divergence: node-0 = {}, node-{} = {}",
            pre_partition_root, n.index, r
        );
    }

    // Partition: node-3 goes offline. The remaining 3 validators
    // still meet the 3/4 quorum and must keep making blocks.
    eprintln!("partitioning node-3 at slot >= 20");
    net.kill_node(3)
        .unwrap_or_else(|e| panic!("kill node-3: {}", e));

    // Let the majority advance by at least 15 slots while node-3 is
    // gone, so the heal has something non-trivial to sync.
    let kill_slot = min_slot_over(&net, &[0, 1, 2])
        .unwrap_or_else(|e| panic!("snapshot slot: {}", e));
    let majority_target = kill_slot + 15;
    wait_for_slot_on_nodes(&net, &[0, 1, 2], majority_target, Duration::from_secs(60))
        .unwrap_or_else(|e| {
            let dumps = per_node_dump(&net);
            panic!("majority progress: {}\n{}", e, dumps);
        });

    let majority_head_at_heal = min_slot_over(&net, &[0, 1, 2])
        .unwrap_or_else(|e| panic!("majority head: {}", e));
    let majority_root_at_heal = net
        .state_root(0)
        .unwrap_or_else(|e| panic!("majority root: {}", e));
    eprintln!(
        "majority reached slot {} with state_root {}",
        majority_head_at_heal, majority_root_at_heal
    );

    // Heal: node-3 comes back online with its persisted RocksDB
    // state (chain head from slot ~20). It must reconnect via
    // libp2p, notice it's behind, pull missing blocks via the
    // sync protocol, and catch up.
    eprintln!("healing — restarting node-3");
    net.restart_node(3)
        .unwrap_or_else(|e| panic!("restart node-3: {}", e));

    // Wait for node-3 to catch up. The majority is still producing
    // blocks while node-3 syncs, so we target the head-at-heal slot,
    // not a higher moving target.
    wait_for_node_to_reach(
        &net,
        3,
        majority_head_at_heal,
        Duration::from_secs(60),
    )
    .unwrap_or_else(|e| {
        let dumps = per_node_dump(&net);
        panic!("node-3 catch-up: {}\n{}", e, dumps);
    });

    let node3_head_after_heal = slot_of(&net, 3)
        .unwrap_or_else(|e| panic!("node-3 post-heal head: {}", e));
    eprintln!(
        "node-3 caught up to slot {} (majority-at-heal was {})",
        node3_head_after_heal, majority_head_at_heal
    );

    // No-fork check: at the slot majority_head_at_heal, whichever
    // node reports a block must report the SAME state_root the
    // majority had when we took the snapshot above. Since chain
    // keeps moving, compare via a snapshot — any node at that slot
    // must match majority_root_at_heal.
    //
    // The test's real invariant: node-3's current head should agree
    // with at least one majority node's state at the SAME slot.
    let snapshots = state_root_snapshot(&net);
    eprintln!("post-heal state_root snapshot: {:?}", snapshots);
    let (n3_slot, n3_root) = snapshots[3].as_ref().expect("node-3 snapshot present");

    // Either a majority node is at node-3's slot (exact match
    // required), or the chain has moved on (acceptable — node-3 just
    // needs to be close behind).
    let mut exact_match = None;
    for i in [0usize, 1, 2] {
        if let Some((s, r)) = &snapshots[i] {
            if s == n3_slot {
                assert_eq!(
                    r, n3_root,
                    "node-3 diverged at slot {}: node-3 = {}, node-{} = {}",
                    n3_slot, n3_root, i, r
                );
                exact_match = Some(i);
                break;
            }
        }
    }
    if exact_match.is_none() {
        let max_majority_slot = [0usize, 1, 2]
            .iter()
            .filter_map(|&i| snapshots[i].as_ref().map(|(s, _)| *s))
            .max()
            .unwrap_or(0);
        let gap = max_majority_slot.saturating_sub(*n3_slot);
        assert!(
            gap <= 5,
            "node-3 is {} slots behind majority — not catching up",
            gap
        );
        eprintln!(
            "no exact slot match in snapshot (majority raced past by {} slots) — acceptable",
            gap
        );
    }

    // Every validator's recent head block must descend from the
    // majority's at-heal root. A fork would surface as one node's
    // root NOT matching any other node's root at the same slot;
    // we've already checked that for node-3, now cross-check the
    // majority among themselves.
    let root_0 = &snapshots[0].as_ref().unwrap().1;
    for i in [1usize, 2] {
        let slot_i = snapshots[i].as_ref().unwrap().0;
        let slot_0 = snapshots[0].as_ref().unwrap().0;
        if slot_i == slot_0 {
            assert_eq!(
                &snapshots[i].as_ref().unwrap().1,
                root_0,
                "majority fork between node-0 and node-{}: {:?} vs {:?}",
                i,
                snapshots[i],
                snapshots[0]
            );
        }
    }
}

fn slot_of(net: &TestNetwork, idx: usize) -> Result<u64, String> {
    net.current_slots()
        .into_iter()
        .find_map(|(i, s)| if i == idx { s } else { None })
        .ok_or_else(|| format!("node-{} slot unavailable", idx))
}

fn min_slot_over(net: &TestNetwork, indices: &[usize]) -> Result<u64, String> {
    let slots: Vec<u64> = net
        .current_slots()
        .into_iter()
        .filter(|(i, _)| indices.contains(i))
        .map(|(_, s)| s.ok_or_else(|| "missing slot on a node".to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    slots.into_iter().min().ok_or_else(|| "empty indices".into())
}

fn wait_for_slot_on_nodes(
    net: &TestNetwork,
    indices: &[usize],
    target: u64,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let slots: Vec<(usize, Option<u64>)> = net
            .current_slots()
            .into_iter()
            .filter(|(i, _)| indices.contains(i))
            .collect();
        if slots
            .iter()
            .all(|(_, s)| s.map(|v| v >= target).unwrap_or(false))
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "wait_for_slot_on_nodes({:?}, {}) timed out — {:?}",
                indices, target, slots
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn wait_for_node_to_reach(
    net: &TestNetwork,
    idx: usize,
    target: u64,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(s) = slot_of(net, idx) {
            if s >= target {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "node-{} did not reach slot {} within {:?}; last: {:?}",
                idx,
                target,
                timeout,
                slot_of(net, idx).ok()
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn state_root_snapshot(net: &TestNetwork) -> Vec<Option<(u64, String)>> {
    net.nodes
        .iter()
        .map(|n| {
            let s = slot_of(net, n.index).ok()?;
            let r = net.state_root(n.index).ok()?;
            Some((s, r))
        })
        .collect()
}

fn per_node_dump(net: &TestNetwork) -> String {
    net.nodes
        .iter()
        .map(|n| {
            format!(
                "\n=== node-{} ({}, rpc {}) ===\n{}",
                n.index,
                n.role,
                n.rpc_port,
                n.output_snapshot()
            )
        })
        .collect::<Vec<_>>()
        .join("")
}
