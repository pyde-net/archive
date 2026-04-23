//! Cold-start sync test (slice 6.4, plan task 066).
//!
//! Spins up 3 validators and lets them advance the chain past slot 10.
//! Then a 4th node (a full node with an empty datadir — never seen
//! the network before) is started, and must:
//!   - discover peers via the bootstrap list,
//!   - pull blocks over the sync protocol,
//!   - converge to the same head slot and state root as the
//!     validators within a reasonable deadline.
//!
//! This is the only Phase 6 test where a node genuinely starts cold
//! and has to catch up, so it's the smoke test for `sync.rs` +
//! `pyde_net::sync_protocol`.

mod common;

use common::TestNetwork;
use std::time::{Duration, Instant};

#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn new_node_syncs_from_network() {
    // 3 running validators + 1 cold full node. The full node's dir
    // and config are generated, but its process is NOT started yet.
    let mut net = TestNetwork::spawn_with_deferred_full_nodes(3, 1, 1, true)
        .unwrap_or_else(|e| panic!("spawn 3v+1 deferred: {}", e));

    let fulls = net.full_node_indices();
    assert_eq!(
        fulls.len(),
        1,
        "expected exactly 1 full node, got {}",
        fulls.len()
    );
    let late_joiner = fulls[0];

    // Confirm the deferred node really is cold — no process attached.
    assert!(
        !net.nodes[late_joiner].is_running(),
        "late joiner should not be running yet"
    );

    // Let the validators build some chain. Target ≥ slot 10 so the
    // late joiner has something substantive to catch up on; a
    // validator-only wait_for_slot is needed because the deferred
    // node would make the default `wait_for_slot` wait forever.
    wait_for_slot_on_validators(&net, 10, Duration::from_secs(60))
        .unwrap_or_else(|e| panic!("validator warm-up: {}", e));

    // Grab the validators' head before starting the joiner. The
    // joiner should at least reach this slot; it will likely go
    // further since blocks keep being produced.
    let validator_head_at_join =
        min_validator_slot(&net).unwrap_or_else(|e| panic!("read validator head: {}", e));
    eprintln!(
        "validator head at join: slot {} — starting node-{}",
        validator_head_at_join, late_joiner
    );

    // Bring the cold node online.
    net.start_deferred(late_joiner)
        .unwrap_or_else(|e| panic!("start_deferred node-{}: {}", late_joiner, e));

    // Wait for the late joiner to reach at least the validator head
    // captured above. 60s is generous — validators make ~2 blocks/s
    // and block-sync requests are batched.
    wait_for_node_to_reach(
        &net,
        late_joiner,
        validator_head_at_join,
        Duration::from_secs(60),
    )
    .unwrap_or_else(|e| {
        let dumps = per_node_dump(&net);
        panic!("{}\n{}", e, dumps);
    });

    // Catch-up done. Validate consistency at whatever slot the
    // joiner is now at. State root must match at least one validator
    // at the joiner's current head slot (the validators may be a few
    // slots ahead because the chain keeps moving).
    let joiner_head =
        slot_of(&net, late_joiner).unwrap_or_else(|e| panic!("read joiner head: {}", e));
    eprintln!("joiner caught up to slot {}", joiner_head);
    assert!(
        joiner_head >= validator_head_at_join,
        "joiner slot {} < validator head at join {}",
        joiner_head,
        validator_head_at_join
    );

    // At least one validator must report the same state_root as the
    // joiner. We can't require ALL validators match the joiner
    // instantly because the chain keeps advancing; comparing at the
    // joiner's current head would race. The invariant is: if the
    // joiner is at slot S, then whichever node produced that block
    // committed a particular state_root for slot S, and consensus
    // means every node agrees on that root for that slot.
    //
    // The cheapest way to test: snapshot every node's state_root +
    // slot atomically. Any node whose head matches the joiner's
    // head must have the same root.
    let snapshots = state_root_snapshot(&net);
    eprintln!("state_root snapshot: {:?}", snapshots);
    let (joiner_slot, joiner_root) = snapshots[late_joiner]
        .as_ref()
        .expect("joiner snapshot present");

    // If any validator is sitting at the same slot as the joiner in
    // the snapshot, their state_root MUST match. A mismatch here
    // would mean the joiner synced a different chain than the
    // validators — a hard fork.
    let mut matching_validator: Option<usize> = None;
    for v in net.validator_indices() {
        if let Some((v_slot, v_root)) = &snapshots[v] {
            if v_slot == joiner_slot {
                assert_eq!(
                    v_root, joiner_root,
                    "state_root divergence at slot {}: joiner {} vs validator-{} {}",
                    joiner_slot, joiner_root, v, v_root
                );
                matching_validator = Some(v);
                break;
            }
        }
    }
    if matching_validator.is_none() {
        // Validators raced past the joiner between the two RPC calls.
        // Accept as long as the gap is small — the joiner was
        // demonstrably caught up a moment ago.
        let max_val_slot = net
            .validator_indices()
            .iter()
            .filter_map(|&i| snapshots[i].as_ref().map(|(s, _)| *s))
            .max()
            .unwrap_or(0);
        let gap = max_val_slot.saturating_sub(*joiner_slot);
        assert!(
            gap <= 5,
            "validators raced too far past joiner: joiner slot {}, max validator slot {}, gap {}",
            joiner_slot,
            max_val_slot,
            gap
        );
        eprintln!(
            "no exact slot match (validators raced ahead by {} slots) — acceptable",
            gap
        );
    }
}

/// Wait until every VALIDATOR node's head >= `target_slot`.
fn wait_for_slot_on_validators(
    net: &TestNetwork,
    target_slot: u64,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let vids = net.validator_indices();
    loop {
        let all_ok = vids
            .iter()
            .all(|&i| slot_of(net, i).map(|s| s >= target_slot).unwrap_or(false));
        if all_ok {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let per_node: Vec<(usize, Option<u64>)> =
                vids.iter().map(|&i| (i, slot_of(net, i).ok())).collect();
            return Err(format!(
                "wait_for_slot_on_validators({}) timed out: {:?}",
                target_slot, per_node
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Wait for a specific node to reach `target_slot`.
fn wait_for_node_to_reach(
    net: &TestNetwork,
    idx: usize,
    target_slot: u64,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match slot_of(net, idx) {
            Ok(s) if s >= target_slot => return Ok(()),
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "node-{} did not reach slot {} within {:?}; last slot seen: {:?}",
                idx,
                target_slot,
                timeout,
                slot_of(net, idx).ok()
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn slot_of(net: &TestNetwork, idx: usize) -> Result<u64, String> {
    net.current_slots()
        .into_iter()
        .find_map(|(i, s)| if i == idx { s } else { None })
        .ok_or_else(|| format!("node-{} slot unavailable", idx))
}

fn min_validator_slot(net: &TestNetwork) -> Result<u64, String> {
    net.validator_indices()
        .iter()
        .map(|&i| slot_of(net, i))
        .collect::<Result<Vec<u64>, _>>()?
        .into_iter()
        .min()
        .ok_or_else(|| "no validators".into())
}

/// Read (slot, state_root) from every node. `None` if either RPC
/// fails (deferred nodes report None).
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
