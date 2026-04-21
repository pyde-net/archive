//! End-to-end transaction lifecycle test (slice 6.2, plan task 064).
//!
//! Submits a real transfer to node-0's RPC and verifies every node
//! observes the resulting state change: same receipt, same sender
//! debit, same recipient credit. This is the first test that
//! exercises the tx propagation path end-to-end — slice 6.1 only
//! covered block production + state-root convergence on otherwise
//! empty blocks.

mod common;

use common::TestNetwork;
use std::time::Duration;

/// Task 064: tx submitted to node-0 propagates to every node and
/// produces identical state on every node.
#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn transfer_propagates_and_balances_match() {
    let net = TestNetwork::spawn(4, true).unwrap_or_else(|e| {
        panic!("spawn 4-node testnet: {}", e);
    });

    // Pick sender + recipient from genesis allocations. `funded_addresses()`
    // dedupes validators listed in both `[[allocations]]` and
    // `[[validators]]`. Slots 0..4 are validator addresses; slots 4+
    // are the 5 test-only accounts `generate_testnet` creates.
    let funded = net
        .funded_addresses()
        .unwrap_or_else(|e| panic!("read funded: {}", e));
    assert!(
        funded.len() >= 6,
        "expected >= 6 funded addresses from genesis (4 validators + 5 test + faucet), got {}",
        funded.len()
    );
    // Use two test-only accounts (not validators) to avoid interaction
    // with validator fee crediting and to keep the expected delta clean.
    let sender = funded[4];
    let recipient = funded[5];
    let transfer_value: u128 = 1_000_000_000; // 1 PYDE

    // Wait for chain to advance — submitting before nodes finish
    // bootstrap can flake.
    net.wait_for_slot(3, Duration::from_secs(30))
        .unwrap_or_else(|e| panic!("initial warm-up: {}", e));

    // Snapshot pre-tx balances on every node — they must all agree.
    let pre_balances = sample_balances(&net, &sender, &recipient);
    assert_convergent(&pre_balances, "pre-transfer balance divergence");

    // Submit via node-0.
    let tx_hash = net
        .submit_transfer(0, &sender, &recipient, transfer_value)
        .unwrap_or_else(|e| panic!("submit_transfer: {}", e));
    eprintln!(
        "tx_hash returned by submit_transfer: bytes={:?} string={}",
        tx_hash.as_bytes(),
        tx_hash
    );

    // Wait for every node to see the receipt. 60s is generous — one
    // block at 400ms + gossip + execution should be well under 10s.
    let receipts = net
        .wait_for_receipt_on_all(&tx_hash, Duration::from_secs(60))
        .unwrap_or_else(|e| {
            let dumps = per_node_dump(&net);
            panic!("{}\n{}", e, dumps);
        });

    // Every receipt must report success.
    for (i, r) in receipts.iter().enumerate() {
        // Print raw JSON for debugging — helpful when the receipt
        // parser logic disagrees with reality.
        eprintln!("node-{} receipt: {}", i, r.raw);
        assert!(
            r.success,
            "node-{} reported a failed receipt:\nraw: {}",
            i, r.raw
        );
    }

    // Every receipt must reference the same block slot.
    let block_slot = receipts[0].block_slot;
    for (i, r) in receipts.iter().enumerate().skip(1) {
        assert_eq!(
            r.block_slot, block_slot,
            "node-{} saw tx in slot {:?} but node-0 saw slot {:?}",
            i, r.block_slot, block_slot
        );
    }

    // Every node's state_root must match — no fork.
    let reference_root = net
        .state_root(0)
        .unwrap_or_else(|e| panic!("state_root node-0: {}", e));
    for n in &net.nodes[1..] {
        let root = net
            .state_root(n.index)
            .unwrap_or_else(|e| panic!("state_root node-{}: {}", n.index, e));
        assert_eq!(
            root, reference_root,
            "state_root divergence after tx:\n  node-0:  {}\n  node-{}: {}",
            reference_root, n.index, root
        );
    }

    // Final balance check: sender down by at least `transfer_value`
    // (plus gas), recipient up by exactly `transfer_value`.
    let post_balances = sample_balances(&net, &sender, &recipient);
    assert_convergent(&post_balances, "post-transfer balance divergence");

    let pre_sender = pre_balances[0].0;
    let post_sender = post_balances[0].0;
    let pre_recipient = pre_balances[0].1;
    let post_recipient = post_balances[0].1;

    assert!(
        post_sender < pre_sender,
        "sender balance did not decrease: pre {} post {}",
        pre_sender,
        post_sender
    );
    let sender_debit = pre_sender - post_sender;
    assert!(
        sender_debit >= transfer_value,
        "sender debit {} is less than transfer_value {} (should include gas)",
        sender_debit,
        transfer_value
    );

    assert_eq!(
        post_recipient, pre_recipient + transfer_value,
        "recipient should receive exactly transfer_value; pre {} post {}",
        pre_recipient, post_recipient
    );
}

/// Read (sender, recipient) balances from every node.
fn sample_balances(
    net: &TestNetwork,
    sender: &[u8; 32],
    recipient: &[u8; 32],
) -> Vec<(u128, u128)> {
    net.nodes
        .iter()
        .map(|n| {
            let s = net.get_balance(n.index, sender).unwrap_or(u128::MAX);
            let r = net.get_balance(n.index, recipient).unwrap_or(u128::MAX);
            (s, r)
        })
        .collect()
}

/// Assert every node reports the same (sender, recipient) balance.
/// Fails with a readable message showing per-node divergence.
fn assert_convergent(balances: &[(u128, u128)], context: &str) {
    let first = balances[0];
    for (i, b) in balances.iter().enumerate().skip(1) {
        assert_eq!(
            *b, first,
            "{}: node-0 = {:?}, node-{} = {:?}",
            context, first, i, b
        );
    }
}

fn per_node_dump(net: &TestNetwork) -> String {
    net.nodes
        .iter()
        .map(|n| {
            format!(
                "\n=== node-{} (rpc port {}) ===\n{}",
                n.index,
                n.rpc_port,
                n.output_snapshot()
            )
        })
        .collect::<Vec<_>>()
        .join("")
}
