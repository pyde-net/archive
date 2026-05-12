//! Task #94 regression: every node in a 4-validator testnet MUST
//! hold the same SMT root after each applied slot.
//!
//! Witness motivating the test (soak v15 against clean main):
//! - Slot 1: deterministic VC fallback proposer (node-2 in that run)
//!   builds + broadcasts its empty block but never seeds it into
//!   `pending_block_bodies` or `buffered_proposals`. The QC-formed
//!   apply path looks up neither, the synthesize-empty-body fallback
//!   gives up, and the proposer silently skips applying its own
//!   slot.
//! - Slot 2 onward: node-2's pre-apply state is one slot behind the
//!   rest of the cluster, so even when it applies the same block
//!   the resulting SMT root differs. Cascades for the rest of the
//!   run.
//!
//! Why a dedicated test (not just a soak):
//! - `multi_node_parallel_exec` reads `pyde_stateRoot` (header field,
//!   `[0u8; 32]` for current-codebase blocks) — it can't see the
//!   divergence the soak logs prove. `pyde_smtRoot` (added for
//!   #94) returns the live SMT root the `block_processor` logs as
//!   `state_root` after each apply.
//! - Soak runs are long, flaky on contended boxes, and mix many
//!   failure modes. This test isolates the convergence invariant:
//!   spawn → light traffic → check SMT root parity. ~10s.
//!
//! Why CHAIN_ID 7331 instead of devnet (31337):
//! - 7331 is the canonical public-testnet id. Slot 1 there always
//!   takes the fallback path (no view-0 happy-path proposer in the
//!   first slot), exercising the bug. Devnet has the same code
//!   path but FALCON-skip side-channels mask other failure modes
//!   under load.

use std::time::Duration;

mod common;
use common::TestNetwork;

const CHAIN_ID: u64 = 7331;

#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn smt_root_converges_across_4_validators() {
    // ── Spawn a 4-validator testnet ──────────────────────────────
    let net = TestNetwork::spawn_with_chain_id(4, CHAIN_ID)
        .unwrap_or_else(|e| panic!("spawn 4v@chain_id={}: {}", CHAIN_ID, e));

    // Warm-up: let the chain reach slot 5. Slot 1 is the
    // diagnostic-critical one — it's where the fallback-proposer
    // self-buffer bug surfaces — but on a healthy chain we should
    // see at least 5 slots applied within a few seconds. Anything
    // longer than 30s is a separate stall problem (covered by
    // `multi_node_finality`).
    net.wait_for_slot(5, Duration::from_secs(30))
        .unwrap_or_else(|e| panic!("warm-up to slot 5: {}", e));

    // ── Sample SMT roots from every node ─────────────────────────
    let roots: Vec<String> = (0..4)
        .map(|i| {
            net.smt_root(i)
                .unwrap_or_else(|e| panic!("smt_root node-{}: {}", i, e))
        })
        .collect();

    // Defensive: roots should be 0x-prefixed hex of length 66.
    for (i, r) in roots.iter().enumerate() {
        assert!(
            r.starts_with("0x") && r.len() == 66,
            "node-{} smt_root malformed: {:?}",
            i,
            r
        );
    }

    // ── The invariant ────────────────────────────────────────────
    // Every node ran the same sequence of canonical blocks against
    // the same genesis state, so every node must hold the same
    // SMT root. Anything else means at least one node skipped or
    // applied-out-of-order. The error message dumps every node's
    // root so a single failure run shows which node is the odd one
    // out.
    let same = roots.windows(2).all(|w| w[0] == w[1]);
    assert!(
        same,
        "smt_root divergence after warm-up — task #94 regression:\n\
         node-0: {}\nnode-1: {}\nnode-2: {}\nnode-3: {}",
        roots[0], roots[1], roots[2], roots[3]
    );

    // ── Sample again after a few more slots to catch the cascade ─
    // Even when slot 1 applies cleanly, the under-load body-
    // propagation bug surfaces around slots 19+ on multi-tx blocks.
    // For this minimal test we don't generate load (the soak does
    // that), so converging at slot 10 is a reasonable bar — just
    // long enough that any slot-1 cascade would be visible.
    net.wait_for_slot(10, Duration::from_secs(15))
        .unwrap_or_else(|e| panic!("warm-up to slot 10: {}", e));

    let roots2: Vec<String> = (0..4)
        .map(|i| {
            net.smt_root(i)
                .unwrap_or_else(|e| panic!("smt_root node-{} @ slot10: {}", i, e))
        })
        .collect();

    let same2 = roots2.windows(2).all(|w| w[0] == w[1]);
    assert!(
        same2,
        "smt_root divergence at ~slot 10 — task #94 regression:\n\
         node-0: {}\nnode-1: {}\nnode-2: {}\nnode-3: {}",
        roots2[0], roots2[1], roots2[2], roots2[3]
    );

    eprintln!(
        "smt root converged across all 4 nodes — slot5={} slot10={}",
        roots[0], roots2[0]
    );
}
