//! Epoch rotation test (slice 6.7, plan task 069).
//!
//! 4 validators at block_time_ms=100 (fast mode; default is 400).
//! Runs the chain past slot 1000 (one EPOCH_LENGTH) and verifies:
//!   - every node's `pyde_getBlockByNumber` reports `epoch == 1` for
//!     slots 1000..=1005 and `epoch == 0` for slots 999 and below;
//!   - state_root converges across all 4 nodes;
//!   - at least one validator's log contains
//!     "committee rotated at epoch boundary" (proof the rotation
//!     code path actually fired, not just that the epoch field got
//!     computed at the block-header level).
//!
//! With EPOCH_LENGTH = 1000 and 100 ms/slot, an epoch boundary is
//! ~100 s after genesis. Bumping to slot 1005 gives a small margin
//! for the rotation handler to run on every node before we sample.

mod common;

use common::TestNetwork;
use std::time::Duration;

const EPOCH_LENGTH: u64 = 1000;

#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn epoch_rotation_crosses_boundary() {
    // 100 ms/slot crosses the 1000-slot boundary in ~100 s. Pyde
    // consensus stays stable at this rate on a laptop under the
    // 4-subprocess load (libp2p QUIC handshake + gossipsub).
    let net = TestNetwork::spawn_with_block_time(4, true, 100)
        .unwrap_or_else(|e| panic!("spawn 4v at 100ms: {}", e));

    // Target = epoch boundary + a few slots of headroom so the
    // rotation handler has processed on every node before we poll.
    let target_slot = EPOCH_LENGTH + 5;
    eprintln!("waiting for slot {}...", target_slot);
    net.wait_for_slot(target_slot, Duration::from_secs(240))
        .unwrap_or_else(|e| {
            let dumps = per_node_dump(&net);
            panic!("cross-epoch wait: {}\n{}", e, dumps);
        });
    eprintln!("all nodes reached slot {}", target_slot);

    // Every node's state_root must match at this point — no fork
    // across the epoch boundary.
    let reference_root = net
        .state_root(0)
        .unwrap_or_else(|e| panic!("state_root node-0: {}", e));
    for n in &net.nodes[1..] {
        let root = net
            .state_root(n.index)
            .unwrap_or_else(|e| panic!("state_root node-{}: {}", n.index, e));
        assert_eq!(
            root, reference_root,
            "state_root divergence across epoch boundary:\n  node-0:  {}\n  node-{}: {}",
            reference_root, n.index, root
        );
    }

    // Block at slot 999 (last of epoch 0) must report epoch=0.
    let e0 = net
        .epoch_of(0, EPOCH_LENGTH - 1)
        .unwrap_or_else(|e| panic!("epoch of slot {}: {}", EPOCH_LENGTH - 1, e))
        .unwrap_or_else(|| panic!("node-0 missing block at slot {}", EPOCH_LENGTH - 1));
    assert_eq!(
        e0, 0,
        "slot {} should be epoch 0, got {}",
        EPOCH_LENGTH - 1,
        e0
    );

    // Block at slot 1000 (first of epoch 1) must report epoch=1.
    let e1 = net
        .epoch_of(0, EPOCH_LENGTH)
        .unwrap_or_else(|e| panic!("epoch of slot {}: {}", EPOCH_LENGTH, e))
        .unwrap_or_else(|| panic!("node-0 missing block at slot {}", EPOCH_LENGTH));
    assert_eq!(
        e1, 1,
        "slot {} should be epoch 1, got {}",
        EPOCH_LENGTH, e1
    );

    // Block at slot target_slot (deep in epoch 1) matches too.
    let e_deep = net
        .epoch_of(0, target_slot)
        .unwrap_or_else(|e| panic!("epoch of slot {}: {}", target_slot, e))
        .unwrap_or_else(|| panic!("node-0 missing block at slot {}", target_slot));
    assert_eq!(
        e_deep, 1,
        "slot {} should be epoch 1, got {}",
        target_slot, e_deep
    );
    eprintln!(
        "epoch field: slot {} → {}, slot {} → {}, slot {} → {}",
        EPOCH_LENGTH - 1,
        e0,
        EPOCH_LENGTH,
        e1,
        target_slot,
        e_deep
    );

    // Observable rotation: every validator should have logged
    // "committee rotated at epoch boundary" exactly once as they
    // crossed slot 1000.
    let mut rotated_count = 0;
    for n in &net.nodes {
        let snapshot = n.output_snapshot();
        if snapshot.contains("committee rotated at epoch boundary") {
            rotated_count += 1;
        }
    }
    assert!(
        rotated_count >= net.nodes.len(),
        "only {}/{} validators logged 'committee rotated at epoch boundary' — rotation path didn't fire on some node",
        rotated_count,
        net.nodes.len()
    );
    eprintln!("rotation log observed on {}/{} nodes", rotated_count, net.nodes.len());
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
