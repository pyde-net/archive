//! Audit-408 regression: every node — proposer or not — runs
//! multi-group blocks through the parallel-exec branch in
//! `block_processor` AND every node converges on the same state
//! root after each multi-group block. Pre-fix the receiver
//! hardcoded a single sequential group when reconstructing a
//! compact block (see `crates/node/src/node.rs:2008`), throwing
//! away the proposer's parallel schedule and forcing every
//! non-proposer onto the slow `groups.len() <= 1` path.
//!
//! The fix wires `cb.group_ids` (a per-tx group-label vector) into
//! the compact-block wire format so receivers reconstruct the same
//! `ExecutionSchedule` the proposer built. This test is the
//! end-to-end witness:
//!
//!   1. Submit 3 bursts of 4 independently-scheduled txs, each from
//!      a distinct signer with a non-overlapping access list.
//!   2. After every burst, fetch `pyde_stateRoot` from all 4 nodes
//!      and assert they're identical — a divergent root would mean
//!      receivers applied a different partition than the proposer.
//!   3. Assert all 4 nodes logged the parallel-exec line at least
//!      once after the run completes.
//!
//! Why distinct AL keys per signer:
//!   The scheduler in `crates/tx/src/parallel.rs` short-circuits to
//!   a single sequential group when no tx in a block declares
//!   informative `(address, key)` pairs (TPL-001). Loadgen workloads
//!   use the uninformative `[{addr, [], []}]` shape and therefore
//!   never exercise the parallel branch — see the comment in
//!   `parallel.rs::access_list_is_uninformative`. We sidestep that
//!   here by populating `writes` with a distinct key per signer,
//!   yielding a 4-group schedule when the proposer batches all
//!   4 txs into one block.

mod common;

use common::TestNetwork;
use pyde_account::address::derive_eoa_address;
use pyde_crypto::falcon::{falcon_sign, FalconSecretKey};
use pyde_tx::types::{AccessEntry, FeePayer, Transaction, TransactionType};
use std::time::Duration;

const NUM_BURSTS: u64 = 3;

#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn parallel_exec_fires_on_non_proposers() {
    // 4-node devnet (chain_id=31337). The audit-408 fix is independent
    // of chain_id / sig-verification — the wire format and receiver
    // schedule reconstruction are the same on devnet, testnet, and
    // mainnet. We use devnet here for the same reasons every other
    // multi-node test does: localhost binds, faster setup, no
    // additional bootstrap-pubkey-pin gymnastics.
    let net = TestNetwork::spawn(4, true).unwrap_or_else(|e| panic!("spawn 4v devnet: {}", e));

    // 60s warm-up — 4-validator boot + FALCON keygen + libp2p mesh
    // formation + first-slot block production occasionally exceeds
    // 30s on a loaded machine.
    net.wait_for_slot(3, Duration::from_secs(60))
        .unwrap_or_else(|e| panic!("warm-up: {}", e));

    // Sanity: pre-test state_root must be identical on every node.
    // If they diverge here we have a problem unrelated to audit-408
    // and the rest of the test would be measuring noise.
    let pre_roots: Vec<String> = (0..4)
        .map(|i| {
            net.state_root(i)
                .unwrap_or_else(|e| panic!("pre-test state_root node-{}: {}", i, e))
        })
        .collect();
    assert!(
        pre_roots.windows(2).all(|w| w[0] == w[1]),
        "pre-test state-root divergence (test setup is broken):\n{:?}",
        pre_roots
    );

    // Load each validator's FALCON keypair. Validators are also EOAs
    // funded at genesis with stake-bonded balances + a registered
    // `AuthKeys::Single` pubkey, which is everything we need to
    // build + sign a transfer from each one.
    let mut signers: Vec<(FalconSecretKey, [u8; 32])> = Vec::with_capacity(4);
    for i in 0..4 {
        let (pk, sk_bytes) = net
            .load_validator_key(i)
            .unwrap_or_else(|e| panic!("load validator-{} key: {}", i, e));
        let sk = FalconSecretKey::from_bytes(&sk_bytes)
            .expect("invalid FALCON secret key in validator.key");
        let addr = derive_eoa_address(&pk);
        signers.push((sk, addr));
    }

    // One distinct recipient per signer. Same recipient across bursts
    // so post-test convergence is `value * NUM_BURSTS` per recipient.
    // Sharing a single recipient address across multiple txs in the
    // same block would require the access list to declare that
    // recipient's balance key as a shared write — otherwise the
    // scheduler partitions the txs into independent groups and the
    // parallel branches all race on `recipient.balance` (read-old,
    // write-new, last-write-wins → silent value loss). That race is
    // well-defined behavior for misdeclared ALs and not what we're
    // here to test; per-signer recipients sidestep it.
    let recipients: Vec<[u8; 32]> = (0..signers.len() as u8)
        .map(|i| {
            let mut a = [0u8; 32];
            a[0] = 0x42;
            a[31] = i + 1;
            a
        })
        .collect();
    let chain_id = 31337u64;
    let value: u128 = 1_000_000;

    // For each burst, construct 4 independent transfers with distinct
    // AL write keys (one per signer × per burst) and submit. Wait
    // for receipts on every node, then check state-root convergence.
    for burst in 0..NUM_BURSTS {
        let nonce = burst;
        let mut tx_hashes: Vec<String> = Vec::with_capacity(signers.len());
        for (i, (sk, sender_addr)) in signers.iter().enumerate() {
            let mut write_key = [0u8; 32];
            // distinct (signer × burst) → distinct keys across the
            // whole run, so the scheduler never accidentally unions
            // two txs across bursts.
            write_key[0] = (i + 1) as u8;
            write_key[1] = (burst + 1) as u8;
            let access_list = vec![AccessEntry {
                address: *sender_addr,
                reads: vec![],
                writes: vec![write_key],
            }];
            let mut tx = Transaction {
                from: *sender_addr,
                to: recipients[i],
                value,
                data: vec![],
                gas_limit: 100_000,
                nonce,
                signature: vec![],
                fee_payer: FeePayer::Sender,
                access_list,
                deadline: None,
                chain_id,
                tx_type: TransactionType::Standard,
            };
            let sig = falcon_sign(sk, &tx.hash()).expect("sign tx");
            tx.signature = sig.as_bytes().to_vec();
            let h = net
                .submit_raw_tx(0, &tx.to_bytes())
                .unwrap_or_else(|e| panic!("burst {} tx-{}: {}", burst, i, e));
            tx_hashes.push(h);
        }

        // Wait for every tx in this burst to land on every node and
        // assert success. A failed tx (insufficient balance, sig
        // rejection, etc.) doesn't credit the recipient and would
        // silently throw off the convergence check below.
        for (i, h) in tx_hashes.iter().enumerate() {
            let receipts = net
                .wait_for_receipt_on_all(h, Duration::from_secs(60))
                .unwrap_or_else(|e| panic!("burst {} tx-{} receipt: {}", burst, i, e));
            for (n, r) in receipts.iter().enumerate() {
                assert!(
                    r.success,
                    "burst {} tx-{} failed on node-{}: {}",
                    burst, i, n, r.raw
                );
            }
        }

        // State convergence: audit-408 wires the proposer's
        // partition to every receiver, so every node MUST commit the
        // same post-state after applying a multi-group block. Pre-fix
        // failure mode: non-proposers ran the txs sequentially while
        // the proposer ran them in parallel; for these access-list-
        // disjoint transfers the final balances *happened* to be
        // identical (the writes are commutative on disjoint keys),
        // but the test exists to catch the future case where the
        // partition disagrees and the writes don't commute.
        //
        // We probe convergence on three different observables — any
        // single one would catch divergence; together they triangulate:
        //
        //   1. Recipient balance: `value * 4 * (burst + 1)` total.
        //      A non-proposer that applied a different subset of txs
        //      lands on a different sum.
        //   2. Per-sender nonce (`pyde_getTransactionCount`). After
        //      the burst lands every sender's nonce should advance
        //      to `burst + 1`. A non-proposer that dropped or
        //      double-applied a tx lands elsewhere.
        //   3. `pyde_stateRoot`. Even pre-finality this should be
        //      consistent across nodes (chain.state_root is the
        //      most recently advanced header's state_root, set in
        //      `chain::ChainState::advance`).
        // Each recipient should have received `value * (burst + 1)`
        // PYDE total — one transfer per burst. All 4 nodes must
        // report the same balance for each recipient (audit-408
        // convergence: the proposer's parallel-exec partition is
        // applied identically on every receiver).
        let expected_per_recipient = value * (burst + 1) as u128;
        for (i, recipient_addr) in recipients.iter().enumerate() {
            let balances: Vec<u128> = (0..4)
                .map(|n| {
                    net.get_balance(n, recipient_addr).unwrap_or_else(|e| {
                        panic!("burst {} recipient-{} balance node-{}: {}", burst, i, n, e)
                    })
                })
                .collect();
            assert!(
                balances.windows(2).all(|w| w[0] == w[1]),
                "burst {} recipient-{} balance divergence: {:?}",
                burst,
                i,
                balances
            );
            assert_eq!(
                balances[0], expected_per_recipient,
                "burst {} recipient-{} balance wrong: got {}, expected {}",
                burst, i, balances[0], expected_per_recipient
            );
        }

        let expected_nonce = burst + 1;
        for (sidx, (_sk, sender_addr)) in signers.iter().enumerate() {
            let nonces: Vec<u64> = (0..4)
                .map(|n| {
                    net.get_nonce(n, sender_addr).unwrap_or_else(|e| {
                        panic!("burst {} signer-{} nonce node-{}: {}", burst, sidx, n, e)
                    })
                })
                .collect();
            assert!(
                nonces.windows(2).all(|w| w[0] == w[1]),
                "burst {} signer-{} nonce divergence: {:?}",
                burst,
                sidx,
                nonces
            );
            assert_eq!(
                nonces[0], expected_nonce,
                "burst {} signer-{} nonce wrong: got {}, expected {}",
                burst, sidx, nonces[0], expected_nonce
            );
        }

        let post_roots: Vec<String> = (0..4)
            .map(|i| {
                net.state_root(i)
                    .unwrap_or_else(|e| panic!("burst {} post state_root node-{}: {}", burst, i, e))
            })
            .collect();
        assert!(
            post_roots.windows(2).all(|w| w[0] == w[1]),
            "burst {} state-root divergence:\n{:#?}",
            burst,
            post_roots
        );
        eprintln!(
            "burst {} ok — per-recipient balance={}, state_root={}",
            burst, expected_per_recipient, post_roots[0]
        );
    }

    // Audit-408 assertion. Each node's block_processor logs
    // `"parallel execution: N groups on rayon threads"` whenever a
    // multi-group block applies and produces writes — see
    // `crates/node/src/block_processor.rs:444`. Pre-fix only the
    // proposer would hit this line because non-proposers
    // reconstructed the schedule as a single sequential group.
    // Post-fix every node sees the same `groups.len() > 1` and
    // takes the rayon-parallel branch.
    //
    // Three bursts of 4-group txs typically produce 1-3 multi-group
    // blocks (depending on whether the proposer batches a burst's
    // txs into one block or fragments across slots). We assert >= 1
    // per node, which is the load-bearing invariant — that the
    // parallel branch fires at all on every receiver.
    for i in 0..4 {
        let snapshot = net.nodes[i].output_snapshot();
        let count = snapshot.matches("parallel execution:").count();
        assert!(
            count >= 1,
            "node-{} never hit the parallel-exec branch: \
             expected >= 1 'parallel execution:' log line, got {}. \
             This is an audit-408 regression — non-proposers are \
             running the single-group fallback path despite the \
             proposer scheduling multiple independent groups",
            i,
            count
        );
        eprintln!("node-{}: parallel-exec lines = {}", i, count);
    }
}
