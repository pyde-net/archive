//! End-to-end lifecycle test for the MEV-protected encrypted-tx flow
//! (audit items 207 + 227 step 4/4 — also unblocks 074b).
//!
//! Exercises the full client-side flow against a 4-node testnet:
//!
//!   1. Client fetches the committee threshold pubkey via
//!      `pyde_getThresholdPublicKey` (item 227 step 1/4).
//!   2. Client encrypts `(to, value, calldata)` locally and signs
//!      `EncryptedTx::hash()` with the sender's FALCON key
//!      (item 227 step 3/4).
//!   3. Client submits via `pyde_sendRawEncryptedTransaction`
//!      (item 227 step 2/4).
//!   4. Proposer includes the encrypted tx, publishes a compact
//!      block + an `EncryptedTxBundle` on the Blocks channel
//!      (item 207 steps 1+2/3).
//!   5. Non-proposer validators pull the encrypted_txs out of the
//!      bundle, reconstruct the full block, run the
//!      decryption-share protocol, execute the decrypted tx, and
//!      credit the recipient.
//!
//! Assertion: the recipient's on-chain balance increases by exactly
//! `transfer_value` on every node. If the encrypted-tx flow is
//! wired correctly, the balance change is identical across all
//! nodes (because every validator decrypted + executed the same
//! tx). If any piece of the chain is broken (bundle not
//! propagating, shares orphaned, decryption failing, sig rejected),
//! the balance doesn't change and the test fails loudly.
//!
//! Uses a validator account as the sender because
//! `try_decrypt_and_execute` drops encrypted txs from senders
//! without `AuthKeys::Single` on-chain (see `block_processor.rs`
//! ~L801); validators satisfy this at genesis.

mod common;

use common::TestNetwork;
use std::time::Duration;

/// Multi-node encrypted-tx lifecycle. Marked `#[ignore]` because
/// it spawns real subprocesses — run with `cargo test --ignored`.
#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn encrypted_tx_decrypts_and_credits_recipient_on_all_nodes() {
    let net = TestNetwork::spawn(4, true).unwrap_or_else(|e| panic!("spawn 4-node testnet: {}", e));

    // Let bootstrap + gossip mesh converge. Submitting before the
    // encrypted-share path is fully warm tends to drop shares.
    net.wait_for_slot(5, Duration::from_secs(45))
        .unwrap_or_else(|e| panic!("initial warm-up: {}", e));

    // Sender: validator 0's FALCON keypair. Has AuthKeys::Single
    // registered at genesis + has balance. Clean for encrypted-tx
    // since try_decrypt_and_execute requires a registered key.
    let (sender_pk, sender_sk) = net
        .load_validator_key(0)
        .unwrap_or_else(|e| panic!("load validator 0 key: {}", e));

    // Recipient: a test account (not a validator — keeps balance
    // math clean, no fee-credit accumulation to worry about).
    let funded = net
        .funded_addresses()
        .unwrap_or_else(|e| panic!("read funded: {}", e));
    assert!(
        funded.len() > 4,
        "expected >4 funded addresses (4 validators + >=1 test acct), got {}",
        funded.len()
    );
    let recipient = funded[4];

    let transfer_value: u128 = 1_000_000_000; // 1 PYDE

    // Snapshot recipient balance pre-tx on every node.
    let pre_balances: Vec<u128> = net
        .nodes
        .iter()
        .map(|n| {
            net.get_balance(n.index, &recipient)
                .unwrap_or_else(|e| panic!("get_balance pre node-{}: {}", n.index, e))
        })
        .collect();
    let first_pre = pre_balances[0];
    for (i, b) in pre_balances.iter().enumerate().skip(1) {
        assert_eq!(
            *b, first_pre,
            "pre-balance divergence: node-0 = {}, node-{} = {}",
            first_pre, i, b
        );
    }

    // Submit encrypted tx via node-0.
    let tx_hash = net
        .submit_encrypted_transfer(
            /* rpc_node_idx */ 0,
            &sender_pk,
            &sender_sk,
            &recipient,
            transfer_value,
        )
        .unwrap_or_else(|e| panic!("submit_encrypted_transfer: {}", e));
    eprintln!("submitted encrypted tx hash = {}", tx_hash);

    // Wait for the full flow to complete:
    //   * block inclusion (~1 slot = 400ms after submission window)
    //   * compact block + bundle gossip to all non-proposer nodes
    //   * QC formation (2f+1 votes)
    //   * decryption-share exchange
    //   * threshold decryption + execution
    //   * state root commit + propagation
    // 60s is generous; a healthy flow typically commits in <10s.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let mut last_balances: Vec<u128> = pre_balances.clone();
    let mut committed_on_all = false;
    while std::time::Instant::now() < deadline {
        let current: Vec<u128> = net
            .nodes
            .iter()
            .map(|n| net.get_balance(n.index, &recipient).unwrap_or(0))
            .collect();
        last_balances = current.clone();

        let all_updated = current
            .iter()
            .enumerate()
            .all(|(i, b)| *b == pre_balances[i] + transfer_value);
        if all_updated {
            committed_on_all = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    if !committed_on_all {
        // Dump per-node tail output to help diagnose.
        let dumps = net
            .nodes
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
            .join("");
        panic!(
            "encrypted tx did not commit on all nodes within 60s\n\
             pre_balances:  {:?}\n\
             last_balances: {:?}\n\
             expected per-node increase: {}\n{}",
            pre_balances, last_balances, transfer_value, dumps
        );
    }

    // State root convergence: every validator executed the same
    // decrypted tx, so roots must match.
    let reference_root = net
        .state_root(0)
        .unwrap_or_else(|e| panic!("state_root node-0: {}", e));
    for n in &net.nodes[1..] {
        let root = net
            .state_root(n.index)
            .unwrap_or_else(|e| panic!("state_root node-{}: {}", n.index, e));
        assert_eq!(
            root, reference_root,
            "state_root divergence after encrypted tx:\n  node-0:  {}\n  node-{}: {}",
            reference_root, n.index, root
        );
    }
}
