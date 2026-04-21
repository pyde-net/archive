//! Leader-failure / view-change test (slice 6.5, plan task 067).
//!
//! 4 validators. Chain advances to slot 20. Node-0 is killed. The
//! remaining 3 validators must continue producing blocks (quorum is
//! still satisfied — 3/4 > 2/3) and converge on a consistent
//! state_root. No block in the post-kill window can name node-0 as
//! proposer.
//!
//! Pyde uses multi-proposer VRF selection: each validator that
//! qualifies for a slot proposes, lowest-VRF wins, QC is formed
//! over the winning proposal. A validator going offline mid-epoch
//! removes it from the proposer pool and (if it was the previous
//! proposer pattern) triggers the view-change path on the slots it
//! would have owned. Here we test the observable outcome — the
//! chain continues — rather than poking at the view-change state
//! machine directly.

mod common;

use common::TestNetwork;
use std::time::{Duration, Instant};

#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn validator_failure_keeps_chain_live() {
    let mut net = TestNetwork::spawn(4, true)
        .unwrap_or_else(|e| panic!("spawn 4-validator testnet: {}", e));

    // Let consensus warm up to a healthy depth. Generous timeout
    // because this test often runs concurrently with other
    // multi-node binaries; each spins up 4 validators, and the host
    // slot rate drops under contention.
    net.wait_for_slot(20, Duration::from_secs(90))
        .unwrap_or_else(|e| panic!("warm-up: {}", e));

    // Snapshot state just before the kill.
    let funded = net
        .funded_addresses()
        .unwrap_or_else(|e| panic!("funded: {}", e));
    assert!(
        funded.len() >= 4,
        "expected >= 4 funded addresses, got {}",
        funded.len()
    );
    // First 4 funded addresses are the 4 validators (allocations
    // section comes before validators section in genesis.toml, and
    // funded_addresses dedupes). Node-i's validator key produces
    // address `funded[i]`.
    let killed_addr = funded[0];
    let kill_slot = min_slot_over(&net, &[1, 2, 3])
        .unwrap_or_else(|e| panic!("snapshot slot: {}", e));
    eprintln!(
        "about to kill node-0 (addr 0x{}) at slot {}",
        hex::encode(killed_addr),
        kill_slot
    );

    net.kill_node(0).unwrap_or_else(|e| panic!("kill node-0: {}", e));

    // Give the survivors a fresh 15 s to make progress. At 400 ms
    // block time, that's ~35 slots of headroom; we only require
    // slot to grow by >= 10 to call it "live".
    let target_slot = kill_slot + 10;
    wait_for_slot_on_nodes(&net, &[1, 2, 3], target_slot, Duration::from_secs(60))
        .unwrap_or_else(|e| {
            let dumps = per_node_dump(&net);
            panic!("{}\n{}", e, dumps);
        });

    // State roots must agree across the 3 survivors.
    let mut roots: Vec<(usize, String)> = Vec::new();
    for i in [1, 2, 3] {
        let r = net
            .state_root(i)
            .unwrap_or_else(|e| panic!("state_root node-{}: {}", i, e));
        roots.push((i, r));
    }
    let reference = roots[0].1.clone();
    for (i, r) in roots.iter().skip(1) {
        assert_eq!(
            r, &reference,
            "state_root divergence among survivors: node-1 = {}, node-{} = {}",
            reference, i, r
        );
    }

    // No block in the post-kill window should report node-0 as
    // proposer. We check slots [kill_slot+3, target_slot] — the
    // +3 buffer lets any in-flight proposal from node-0 that was
    // already propagating commit before the kill takes effect.
    // Read headers from node-1 (any survivor works).
    let window_start = kill_slot + 3;
    let window_end = target_slot;
    let mut inspected = 0usize;
    for slot in window_start..=window_end {
        match net.proposer_of(1, slot) {
            Ok(Some(p)) => {
                inspected += 1;
                assert_ne!(
                    p, killed_addr,
                    "slot {} proposer is the killed node-0 (0x{})",
                    slot,
                    hex::encode(p)
                );
            }
            Ok(None) => { /* node-1 hadn't committed this slot yet */ }
            Err(e) => eprintln!("getBlockByNumber({}) failed: {}", slot, e),
        }
    }
    assert!(
        inspected >= 3,
        "expected to inspect >= 3 post-kill blocks, only got {}",
        inspected
    );
    eprintln!(
        "verified {} blocks in slots {}..={} — none proposed by killed node-0",
        inspected, window_start, window_end
    );
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
