//! Full-node tx relay test (slice 6.3, plan task 065).
//!
//! Spins up 3 validators + 1 full node. Submits a transfer via the
//! full node's RPC (NOT a validator), and verifies:
//!   - a validator includes the tx in a block,
//!   - every validator + the full node reports the same success
//!     receipt, same block slot, matching state roots, and
//!     convergent balances.
//!
//! This exercises the tx-gossip path from full node to validator and
//! the block-gossip path back to the full node — the key thing that
//! separates 6.3 from 6.2 (which submitted directly to a validator).

mod common;

use common::TestNetwork;
use std::time::Duration;

#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn tx_via_full_node_reaches_validator() {
    let net = TestNetwork::spawn_mixed(3, 1, true)
        .unwrap_or_else(|e| panic!("spawn 3v+1f testnet: {}", e));

    // Sanity: we got exactly one full node and it's indexed after the
    // validators.
    let fulls = net.full_node_indices();
    assert_eq!(fulls.len(), 1, "expected 1 full node, got {}", fulls.len());
    let full_idx = fulls[0];
    assert_eq!(
        full_idx, 3,
        "full node should be at index 3 (after 3 validators)"
    );
    let validators = net.validator_indices();
    assert_eq!(validators.len(), 3);

    // Wait for the network to advance so we know gossip is live and
    // the proposer lottery is producing blocks.
    net.wait_for_slot(3, Duration::from_secs(30))
        .unwrap_or_else(|e| panic!("initial warm-up: {}", e));

    // Pick sender + recipient from genesis test accounts (slots 3..8
    // are the 5 non-validator test accounts since we have 3 validators).
    let funded = net
        .funded_addresses()
        .unwrap_or_else(|e| panic!("read funded: {}", e));
    assert!(
        funded.len() >= 3 + 5 + 1,
        "expected >= 9 funded addresses (3 validators + 5 test + faucet), got {}",
        funded.len()
    );
    let sender = funded[3];
    let recipient = funded[4];
    let transfer_value: u128 = 1_000_000_000;

    // Pre-tx balance snapshot must agree across every node, including
    // the full node.
    let pre_balances = sample_balances(&net, &sender, &recipient);
    assert_convergent(&pre_balances, "pre-transfer balance divergence");

    // Submit via the FULL NODE, not a validator. This is the feature
    // under test: the full node has no stake, doesn't propose, yet its
    // RPC must accept the tx, gossip it, and the validators must
    // include it in a block.
    let tx_hash = net
        .submit_transfer(full_idx, &sender, &recipient, transfer_value)
        .unwrap_or_else(|e| panic!("submit_transfer via full node: {}", e));
    eprintln!("tx_hash (submitted via node-{}): {}", full_idx, tx_hash);

    // Wait for the receipt to land on every node.
    let receipts = net
        .wait_for_receipt_on_all(&tx_hash, Duration::from_secs(60))
        .unwrap_or_else(|e| {
            let dumps = per_node_dump(&net);
            panic!("{}\n{}", e, dumps);
        });

    for (i, r) in receipts.iter().enumerate() {
        let role = net.nodes[i].role;
        eprintln!("node-{} ({}) receipt: {}", i, role, r.raw);
        assert!(
            r.success,
            "node-{} ({}) reported a failed receipt:\nraw: {}",
            i, role, r.raw
        );
    }

    // Every receipt must point at the same block slot — the tx can't
    // land in two different blocks on two different nodes.
    let block_slot = receipts[0].block_slot;
    for (i, r) in receipts.iter().enumerate().skip(1) {
        assert_eq!(
            r.block_slot, block_slot,
            "node-{} saw tx in slot {:?}; node-0 saw slot {:?}",
            i, r.block_slot, block_slot
        );
    }

    // State roots must match across validators AND the full node.
    // Divergence here would mean the full node is executing a
    // different chain than the validators.
    let reference_root = net
        .state_root(0)
        .unwrap_or_else(|e| panic!("state_root node-0: {}", e));
    for n in &net.nodes[1..] {
        let root = net
            .state_root(n.index)
            .unwrap_or_else(|e| panic!("state_root node-{}: {}", n.index, e));
        assert_eq!(
            root, reference_root,
            "state_root divergence after tx:\n  node-0:  {}\n  node-{} ({}): {}",
            reference_root, n.index, n.role, root
        );
    }

    // Balance deltas: sender debit ≥ transfer_value (gas added on top);
    // recipient credit == transfer_value exactly.
    let post_balances = sample_balances(&net, &sender, &recipient);
    assert_convergent(&post_balances, "post-transfer balance divergence");

    let pre_sender = pre_balances[0].0;
    let post_sender = post_balances[0].0;
    let pre_recipient = pre_balances[0].1;
    let post_recipient = post_balances[0].1;

    assert!(
        post_sender < pre_sender,
        "sender balance did not decrease: pre {} post {}",
        pre_sender, post_sender
    );
    let sender_debit = pre_sender - post_sender;
    assert!(
        sender_debit >= transfer_value,
        "sender debit {} < transfer_value {} (should include gas)",
        sender_debit, transfer_value
    );
    assert_eq!(
        post_recipient,
        pre_recipient + transfer_value,
        "recipient should receive exactly transfer_value; pre {} post {}",
        pre_recipient, post_recipient
    );
}

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
