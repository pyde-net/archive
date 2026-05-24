//! Encrypted-tx flow across an epoch boundary (PSS share-refresh coverage).
//!
//! Closes the integration gap that `multi_node_encrypted_lifecycle`
//! (one tx, no rotation) and `multi_node_epoch_rotation` (rotation,
//! no encrypted txs) leave: prove that the committee's threshold
//! key shares stay coherent across the epoch boundary, so an
//! encrypted tx submitted *after* PSS refresh still decrypts under
//! the rotated shares.
//!
//! Flow:
//!
//!   1. Spawn 4-validator testnet at `block_time_ms=100` (epoch
//!      boundary at slot 1000 = ~100 s wall clock — the same
//!      test-acceleration cadence `multi_node_epoch_rotation` uses).
//!   2. Warm-up to slot 30 — bootstrap + gossipsub mesh settled,
//!      genesis-key DKG complete. A few extra slots vs. the
//!      lifecycle test buys margin for the encrypted-tx submission
//!      to land before the proposer-selection window of slot 30
//!      closes at this faster cadence.
//!   3. Snapshot the threshold pubkey via `pyde_getThresholdPublicKey`
//!      on every node. Assert all 4 nodes agree.
//!   4. Submit encrypted tx #1 (recipient = funded test acct).
//!      Wait for the recipient's balance to credit on all 4 nodes
//!      (proves decryption-share path works under epoch-0 shares).
//!   5. Wait for slot 1005 — past `EPOCH_LENGTH = 1000`, plus 5
//!      slots so every node has processed `rotate_to_epoch` +
//!      broadcast its `start_pss_refresh` contribution.
//!   6. Assert "committee rotated at epoch boundary" appears in
//!      every validator's log (the same proof multi_node_epoch_rotation
//!      uses).
//!   7. Re-snapshot the threshold pubkey on every node. PSS refresh
//!      preserves the secret `s` and therefore the pubkey `Y = g^s`,
//!      so post-rotation bytes must equal pre-rotation bytes on
//!      every node (if they don't, the test caught a coherence bug
//!      and the second encrypted tx would have failed silently
//!      anyway).
//!   8. Submit encrypted tx #2. Wait for credit on all 4 nodes.
//!      This is the actual proof: validators are using the
//!      refreshed shares (the unit tests in
//!      `pyde_crypto::threshold::tests::pss_*` guarantee old
//!      shares can't decrypt post-refresh, so a successful
//!      cooperative decrypt here means the new shares are wired
//!      end-to-end through the validator dispatch path).
//!   9. State-root convergence on all 4 nodes — fork-free.
//!
//! At 100 ms/slot this completes in ~150 s on a laptop. Marked
//! `#[ignore]` so it doesn't run on every `cargo test`.

mod common;

use common::TestNetwork;
use std::time::{Duration, Instant};

const EPOCH_LENGTH: u64 = 1000;
const TRANSFER_VALUE: u128 = 1_000_000_000; // 1 PYDE

#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn encrypted_tx_decrypts_after_pss_refresh() {
    // 100 ms/slot test acceleration — same cadence
    // `multi_node_epoch_rotation` uses. Epoch boundary at slot 1000
    // = ~100 s wall clock.
    let net = TestNetwork::spawn_with_block_time(4, true, 100)
        .unwrap_or_else(|e| panic!("spawn 4v at 100ms: {}", e));

    // Warm-up to slot 30 (vs. the lifecycle test's 15 at 400 ms):
    // gives the encrypted-tx submission a little more margin at
    // this faster slot cadence for the mesh to converge.
    net.wait_for_slot(30, Duration::from_secs(60))
        .unwrap_or_else(|e| panic!("warm-up to slot 30: {}", e));

    // Sender: validator-0's FALCON keypair (has AuthKeys::Single
    // installed at genesis — required for try_decrypt_and_execute).
    let (sender_pk, sender_sk) = net
        .load_validator_key(0)
        .unwrap_or_else(|e| panic!("load validator 0 key: {}", e));

    // Recipient: a non-validator funded test acct (avoids
    // validator-fee-credit accumulation muddling the assertion).
    let funded = net
        .funded_addresses()
        .unwrap_or_else(|e| panic!("read funded: {}", e));
    assert!(
        funded.len() > 4,
        "expected >4 funded addresses, got {}",
        funded.len()
    );
    let recipient = funded[4];

    // ── Pre-rotation snapshot ──────────────────────────────────────
    let tpk_pre: Vec<Vec<u8>> = (0..net.nodes.len())
        .map(|i| {
            net.get_threshold_pubkey(i)
                .unwrap_or_else(|e| panic!("pre tpk node-{}: {}", i, e))
        })
        .collect();
    for (i, pk) in tpk_pre.iter().enumerate().skip(1) {
        assert_eq!(
            *pk, tpk_pre[0],
            "pre-rotation threshold pubkey divergence: node-0 vs node-{}",
            i
        );
    }
    eprintln!("pre-rotation threshold pubkey ({} bytes)", tpk_pre[0].len());

    // ── Pre-rotation encrypted tx ──────────────────────────────────
    let pre_balances: Vec<u128> = (0..net.nodes.len())
        .map(|i| {
            net.get_balance(i, &recipient)
                .unwrap_or_else(|e| panic!("pre balance node-{}: {}", i, e))
        })
        .collect();

    let tx1_hash = net
        .submit_encrypted_transfer(0, &sender_pk, &sender_sk, &recipient, TRANSFER_VALUE)
        .unwrap_or_else(|e| panic!("submit encrypted tx #1: {}", e));
    eprintln!("encrypted tx #1 submitted: {}", tx1_hash);

    wait_for_recipient_credit(
        &net,
        &recipient,
        &pre_balances,
        TRANSFER_VALUE,
        Duration::from_secs(60),
        "tx#1 (pre-rotation)",
    );
    eprintln!("encrypted tx #1 credited on all 4 nodes");

    // ── Cross the epoch boundary ───────────────────────────────────
    let target_slot = EPOCH_LENGTH + 5;
    eprintln!("waiting for slot {} (past epoch boundary)…", target_slot);
    // At 100 ms/slot, slot 1005 ≈ 100 s nominal. 240 s ceiling
    // gives ~2× headroom for laptop CPU contention — matches
    // `multi_node_epoch_rotation`.
    net.wait_for_slot(target_slot, Duration::from_secs(240))
        .unwrap_or_else(|e| panic!("cross-epoch wait: {}\n{}", e, per_node_dump(&net)));
    eprintln!("all 4 nodes past slot {}", target_slot);

    // Epoch field sanity (mirrors multi_node_epoch_rotation).
    let e0 = net
        .epoch_of(0, EPOCH_LENGTH - 1)
        .unwrap_or_else(|e| panic!("epoch_of {}: {}", EPOCH_LENGTH - 1, e))
        .unwrap_or_else(|| panic!("missing block at slot {}", EPOCH_LENGTH - 1));
    let e1 = net
        .epoch_of(0, EPOCH_LENGTH)
        .unwrap_or_else(|e| panic!("epoch_of {}: {}", EPOCH_LENGTH, e))
        .unwrap_or_else(|| panic!("missing block at slot {}", EPOCH_LENGTH));
    assert_eq!(
        e0,
        0,
        "slot {} should be epoch 0, got {}",
        EPOCH_LENGTH - 1,
        e0
    );
    assert_eq!(e1, 1, "slot {} should be epoch 1, got {}", EPOCH_LENGTH, e1);

    // Rotation log on every validator — proof the rotate_to_epoch +
    // PSS refresh path actually fired (not just that the epoch
    // number got computed at the block-header level).
    let mut rotated = 0;
    for n in &net.nodes {
        if n.output_snapshot()
            .contains("committee rotated at epoch boundary")
        {
            rotated += 1;
        }
    }
    assert!(
        rotated >= net.nodes.len(),
        "only {}/{} validators logged 'committee rotated at epoch boundary'",
        rotated,
        net.nodes.len()
    );
    eprintln!(
        "rotation log observed on {}/{} nodes",
        rotated,
        net.nodes.len()
    );

    // ── Post-rotation pubkey snapshot ──────────────────────────────
    let tpk_post: Vec<Vec<u8>> = (0..net.nodes.len())
        .map(|i| {
            net.get_threshold_pubkey(i)
                .unwrap_or_else(|e| panic!("post tpk node-{}: {}", i, e))
        })
        .collect();
    for (i, pk) in tpk_post.iter().enumerate().skip(1) {
        assert_eq!(
            *pk, tpk_post[0],
            "post-rotation threshold pubkey divergence: node-0 vs node-{}",
            i
        );
    }
    // PSS refresh preserves the secret `s` and therefore the pubkey
    // `Y = g^s` — only the share representation rotates. A change
    // here would mean either the on-chain pubkey advertisement
    // raced with the refresh (validator coherence bug) or the
    // protocol implementation regressed.
    assert_eq!(
        tpk_post[0],
        tpk_pre[0],
        "threshold pubkey changed across epoch boundary — \
         PSS refresh should preserve Y = g^s (pre len={}, post len={})",
        tpk_pre[0].len(),
        tpk_post[0].len()
    );

    // ── Post-rotation encrypted tx ─────────────────────────────────
    // submit_encrypted_transfer re-fetches the threshold pk before
    // each submission, so this tx is encrypted under the same Y
    // but will be decrypted using the *refreshed* shares.
    let mid_balances: Vec<u128> = (0..net.nodes.len())
        .map(|i| {
            net.get_balance(i, &recipient)
                .unwrap_or_else(|e| panic!("mid balance node-{}: {}", i, e))
        })
        .collect();

    let tx2_hash = net
        .submit_encrypted_transfer(0, &sender_pk, &sender_sk, &recipient, TRANSFER_VALUE)
        .unwrap_or_else(|e| panic!("submit encrypted tx #2: {}", e));
    eprintln!("encrypted tx #2 submitted: {}", tx2_hash);

    wait_for_recipient_credit(
        &net,
        &recipient,
        &mid_balances,
        TRANSFER_VALUE,
        Duration::from_secs(60),
        "tx#2 (post-rotation)",
    );
    eprintln!("encrypted tx #2 credited on all 4 nodes — refreshed shares decrypt correctly");

    // ── State-root convergence ─────────────────────────────────────
    let reference_root = net
        .state_root(0)
        .unwrap_or_else(|e| panic!("state_root node-0: {}", e));
    for n in &net.nodes[1..] {
        let root = net
            .state_root(n.index)
            .unwrap_or_else(|e| panic!("state_root node-{}: {}", n.index, e));
        assert_eq!(
            root, reference_root,
            "state_root divergence after post-rotation encrypted tx:\n  node-0:  {}\n  node-{}: {}",
            reference_root, n.index, root
        );
    }
    eprintln!("state_root convergence: 4/4 nodes match");
}

fn wait_for_recipient_credit(
    net: &TestNetwork,
    recipient: &[u8; 32],
    pre_balances: &[u128],
    expected_delta: u128,
    timeout: Duration,
    label: &str,
) {
    let deadline = Instant::now() + timeout;
    let mut last: Vec<u128> = pre_balances.to_vec();
    while Instant::now() < deadline {
        let current: Vec<u128> = (0..net.nodes.len())
            .map(|i| net.get_balance(i, recipient).unwrap_or(0))
            .collect();
        last = current.clone();
        let all_credited = current
            .iter()
            .enumerate()
            .all(|(i, b)| *b == pre_balances[i] + expected_delta);
        if all_credited {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!(
        "{}: recipient not credited on all nodes within {:?}\n  pre:  {:?}\n  last: {:?}\n  expected delta: {}\n{}",
        label,
        timeout,
        pre_balances,
        last,
        expected_delta,
        per_node_dump(net)
    );
}

fn per_node_dump(net: &TestNetwork) -> String {
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
