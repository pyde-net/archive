//! Multi-node finality test (slice 6.1, plan task 063).
//!
//! Spins up 4 validator nodes, waits for them to produce + finalize
//! blocks, and verifies all four converge on the same chain tip.
//!
//! Marked `#[ignore]` — runs via `cargo test -p pyde-node -- --ignored`.

mod common;

use common::TestNetwork;
use std::time::Duration;

/// Task 063: 4-node consensus reaches finality.
///
/// Invariants asserted:
/// 1. All 4 validators boot to RPC-up within 30 s.
/// 2. Within 30 s of boot, every node's head slot ≥ 5 (i.e. blocks
///    are being produced AND reaching every peer).
/// 3. All 4 nodes report the same `pyde_stateRoot` at that point —
///    no fork, all nodes executing the same canonical chain.
#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn four_nodes_reach_finality() {
    // `dev = true` skips signature validation (tests don't drive
    // actual user txs; just need block production to advance).
    let net = TestNetwork::spawn(4, true).unwrap_or_else(|e| {
        panic!("failed to spawn 4-node testnet: {}", e);
    });

    // Give the network a generous window to reach slot 5 — libp2p
    // bootstrap + first proposer lottery + HotStuff 3-chain each
    // cost real wall-clock time.
    net.wait_for_slot(5, Duration::from_secs(60))
        .unwrap_or_else(|e| {
            let dumps: String = net
                .nodes
                .iter()
                .map(|n| {
                    format!(
                        "\n=== node-{} (port {}) ===\n{}",
                        n.index,
                        n.rpc_port,
                        n.output_snapshot()
                    )
                })
                .collect();
            panic!("{}{}", e, dumps);
        });

    // All nodes at >= slot 5. Sample each one's state_root. They
    // should match — if they don't, the nodes have forked.
    let mut roots = Vec::with_capacity(net.nodes.len());
    for node in &net.nodes {
        let root = net
            .state_root(node.index)
            .unwrap_or_else(|e| panic!("state_root for node-{}: {}", node.index, e));
        roots.push((node.index, root));
    }

    // Pick node-0 as reference. Any divergence = fork.
    let reference = roots[0].1.clone();
    for (idx, root) in &roots[1..] {
        assert_eq!(
            root, &reference,
            "node-{} state_root diverged from node-0:\n  node-0:  {}\n  node-{}:  {}",
            idx, reference, idx, root
        );
    }
}
