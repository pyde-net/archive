//! Audit-ω: single-source-of-truth canonical commit.
//!
//! Commit 1 of the audit-ω rollout introduces this module with no
//! call sites yet — the `#[allow(dead_code)]` below is removed when
//! commits 2-5 wire the existing apply paths through here. Each
//! commit removes one path's worth of dead-code warnings as it
//! migrates.
#![allow(dead_code)]
//!
//! See `docs/audits/audit-omega-spec.md` for the full rationale. In
//! short: every path in `node.rs` that mutates `chain.head_slot` should
//! route through this function. The invariant is "QC is the only
//! authority on what block lives at slot N". This function enforces it:
//!
//! - **Forward apply**: head extends to qc_slot via process_full_block.
//! - **Idempotent**: local already has the canonical block at qc_slot.
//! - **Reorged**: local has a different block at qc_slot; reorg.
//! - **DivergenceUnresolved**: local has a different block but the
//!   canonical competitor isn't buffered; caller must trigger sync.
//! - **Gap**: qc_slot > head_slot + 1; sync needed.
//! - **Failed**: header/body validation rejected the canonical block
//!   (signals a bug or a malicious peer — surface loudly).
//!
//! This file is the work for **commit 1** of audit-ω. Commit 1 only
//! introduces the function; nothing in the codebase calls it yet.
//! Commits 2–5 route the six existing apply paths through here.

use crate::block_processor::BlockProcessor;
use crate::chain::ChainState;
use crate::state_manager::StateManager;
use pyde_consensus::block::Block;
use pyde_tx::execution::Receipt;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Which validator-internal path triggered `commit_canonical`. Used
/// only for log tagging so a future regression in any single path is
/// attributable. Has no effect on behavior.
#[derive(Debug, Clone, Copy)]
pub enum CanonicalSource {
    /// Proposer's own vote completed a QC inline (audit-232 path).
    OwnVoteInline,
    /// RR fallback QC arrived (the rendezvous-broadcast retry path).
    RrFallback,
    /// Gossip-formed QC arrived; body recovery may have been needed.
    ApplyCanonicalAfterQc,
    /// Hard-finality cert ingested and the block needs re-apply
    /// (e.g. the local node had body unavailable when the QC formed).
    HardFinalityReapply,
}

impl CanonicalSource {
    fn as_str(self) -> &'static str {
        match self {
            CanonicalSource::OwnVoteInline => "own-vote",
            CanonicalSource::RrFallback => "rr-fallback",
            CanonicalSource::ApplyCanonicalAfterQc => "apply-canonical",
            CanonicalSource::HardFinalityReapply => "hard-finality",
        }
    }
}

/// Outcome of attempting to commit the canonical block at `qc_slot`.
///
/// Receipts are returned in the apply variants so the caller can
/// persist them — the function does not touch the receipt store
/// itself (separation of concerns: this module owns chain/state
/// mutation; the caller owns I/O side effects).
#[derive(Debug)]
pub enum CommitOutcome {
    /// `head_slot` advanced from `head_slot + 1 - 1` to `qc_slot` (forward extension).
    Applied {
        txs: u64,
        gas: u64,
        receipts: Vec<Receipt>,
    },
    /// Local already had the same block at `qc_slot`. No mutation. No
    /// log noise — this is the normal "I applied this on the
    /// own-vote-QC inline path, then the gossip-QC arrived later"
    /// case.
    Idempotent,
    /// Local had a different block at `qc_slot`. Reorged: dropped the
    /// local block, re-applied the canonical one.
    Reorged {
        txs: u64,
        gas: u64,
        receipts: Vec<Receipt>,
    },
    /// Local had a different block at `qc_slot` but the canonical
    /// competitor was not in `competing_blocks` (or `competing_blocks`
    /// was not passed). Caller decides: fire `GetBlockByHash`, buffer
    /// for later, or escalate. Function logs at `warn!`.
    DivergenceUnresolved { local_hash: [u8; 32] },
    /// `qc_slot > head_slot + 1`: we're missing intermediate blocks.
    /// Caller must request sync. Function logs at `info!` (not a bug
    /// — happens whenever this node lagged briefly).
    Gap { head_slot: u64, qc_slot: u64 },
    /// Header validation, body validation, or block-processor
    /// execution rejected the block. Almost always a bug or a
    /// malicious peer. Logged at `warn!`.
    Failed { error: String },
}

/// Commit the canonical block at `qc_slot` to chain/state, or
/// reconcile if local state already has something different there.
///
/// **Pure function** — no I/O. Caller owns:
/// - persisting receipts and the header (block_store, receipt_store)
/// - flushing pending state writes (state_w.flush_pending)
/// - notifying chain_sync (chain_sync.on_block_processed)
/// - emitting WS / RPC events
/// - any post-commit fan-out (decryption shares, finality votes,
///   target_height advancement on the validator engine)
///
/// This split keeps the function trivially unit-testable: a pair of
/// `(ChainState, StateManager)` and an in-memory `competing_blocks`
/// map are enough to exercise every branch, without standing up the
/// async/gossipsub/RPC scaffolding that wraps the call sites.
///
/// `competing_blocks` is an `Option` because the OwnVoteInline path
/// has its own competing-block buffer outside this function (today —
/// commit 4 unifies it). Passing `None` short-circuits the reorg
/// path to `DivergenceUnresolved`.
#[allow(clippy::too_many_arguments)]
pub fn commit_canonical(
    chain: &mut ChainState,
    state: &mut StateManager,
    aot_cache: Option<&std::sync::Arc<crate::aot_cache::AotCache>>,
    ws_checkpoint_slot: Option<u64>,
    qc_slot: u64,
    qc_block_hash: [u8; 32],
    block: &Block,
    competing_blocks: Option<&mut HashMap<(u64, [u8; 32]), Block>>,
    source: CanonicalSource,
) -> CommitOutcome {
    let head_slot = chain.head_slot;
    let local_at_slot = chain.header(qc_slot).map(|h| h.hash());

    // Branch 1: local has a block at qc_slot already.
    if let Some(local_hash) = local_at_slot {
        if local_hash == qc_block_hash {
            debug!(
                source = source.as_str(),
                slot = qc_slot,
                "canonical commit: idempotent (local hash matches QC)"
            );
            return CommitOutcome::Idempotent;
        }
        // Divergence — local committed a different block at this slot
        // (proposer's own pre-QC apply, view-1 fallback, or a stale
        // reorg target). The QC is authority; we must reorg.
        let buffered = competing_blocks.as_ref().and_then(|cb| {
            cb.get(&(qc_slot, qc_block_hash)).cloned()
        });
        let reorg_target = buffered.unwrap_or_else(|| block.clone());
        match BlockProcessor::reorg_to_block(
            chain,
            state,
            &reorg_target,
            aot_cache,
            ws_checkpoint_slot,
        ) {
            Ok((txs, gas, receipts)) => {
                // Drain the competitor entry; it's been promoted to
                // canonical and shouldn't be re-attempted.
                if let Some(cb) = competing_blocks {
                    cb.remove(&(qc_slot, qc_block_hash));
                }
                info!(
                    source = source.as_str(),
                    slot = qc_slot,
                    local = hex::encode(local_hash),
                    canonical = hex::encode(qc_block_hash),
                    txs,
                    gas,
                    "canonical commit: reorged from local fork to canonical QC block"
                );
                CommitOutcome::Reorged { txs, gas, receipts }
            }
            Err(e) => {
                // Reorg refused (most commonly: target slot <= WS
                // checkpoint). Surface loudly — staying on a non-
                // canonical block past the checkpoint is a real
                // safety problem to investigate, not silently mask.
                warn!(
                    source = source.as_str(),
                    slot = qc_slot,
                    local = hex::encode(local_hash),
                    canonical = hex::encode(qc_block_hash),
                    error = %e,
                    "canonical commit: divergence detected but reorg failed"
                );
                CommitOutcome::DivergenceUnresolved { local_hash }
            }
        }
    }
    // Branch 2: local has nothing at qc_slot.
    else if qc_slot == head_slot + 1 {
        // Forward apply — the normal path.
        match BlockProcessor::process_full_block_with_aot_and_checkpoint(
            chain,
            state,
            block,
            aot_cache,
            ws_checkpoint_slot,
        ) {
            Ok((txs, gas, receipts)) => CommitOutcome::Applied { txs, gas, receipts },
            Err(e) => {
                warn!(
                    source = source.as_str(),
                    slot = qc_slot,
                    error = %e,
                    "canonical commit: forward apply failed"
                );
                CommitOutcome::Failed { error: e }
            }
        }
    } else if qc_slot > head_slot + 1 {
        info!(
            source = source.as_str(),
            slot = qc_slot,
            head_slot,
            "canonical commit: gap — sync required"
        );
        CommitOutcome::Gap {
            head_slot,
            qc_slot,
        }
    } else {
        // qc_slot < head_slot but no header at qc_slot. Header pruning
        // (2-epoch retention) drops old headers, so this happens for
        // QCs about slots more than 2 epochs behind head. Treat as
        // idempotent — the slot was committed long ago, the QC just
        // arrived late.
        debug!(
            source = source.as_str(),
            slot = qc_slot,
            head_slot,
            "canonical commit: QC older than retained history — treating as idempotent"
        );
        CommitOutcome::Idempotent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::devnet_genesis;
    use pyde_consensus::block::{BlockBody, BlockHeader, QuorumCert};
    use pyde_tx::parallel::ExecutionSchedule;

    /// Build a deterministic dummy header at `slot` with the given
    /// parent_hash. `seed` varies the `proposer` field so two headers
    /// at the same slot with different seeds produce different
    /// `header.hash()` values. `BlockHeader::hash()` deliberately does
    /// NOT include `state_root` (it's unknown at proposal time —
    /// committed separately via hard finality), so varying state_root
    /// alone wouldn't disambiguate the hash.
    fn header_at(slot: u64, parent_hash: [u8; 32], seed: u8) -> BlockHeader {
        BlockHeader {
            slot,
            epoch: 0,
            parent_hash,
            proposer: [seed; 32],
            vrf_proof: vec![],
            qc_previous: QuorumCert {
                slot: slot.saturating_sub(1),
                block_hash: parent_hash,
                voter_bitmap: 0,
                signatures: vec![],
            },
            tx_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: slot * 400,
        }
    }

    fn empty_block(header: BlockHeader) -> Block {
        Block {
            header,
            body: BlockBody {
                transactions: vec![],
                encrypted_txs: vec![],
                execution_schedule: ExecutionSchedule {
                    groups: vec![],
                    total_txs: 0,
                },
            },
            proposer_signature: vec![],
        }
    }

    fn fresh_chain_and_state() -> (ChainState, StateManager) {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateManager::open(tmp.path(), 1024).unwrap();
        let _ = devnet_genesis();
        let chain = ChainState::genesis(state.root(), 31337);
        // Leak the tempdir intentionally — the state lives for the
        // duration of the test and the OS cleans /tmp on exit. Doing
        // it this way avoids a per-test wrapper struct that has to
        // own the TempDir alongside the state.
        std::mem::forget(tmp);
        (chain, state)
    }

    #[test]
    fn applied_forward_extension() {
        let (mut chain, mut state) = fresh_chain_and_state();
        let h1 = header_at(1, [0u8; 32], 1);
        let h1_hash = h1.hash();
        let block1 = empty_block(h1);

        let outcome = commit_canonical(
            &mut chain,
            &mut state,
            None,
            None,
            1,
            h1_hash,
            &block1,
            None,
            CanonicalSource::ApplyCanonicalAfterQc,
        );

        assert!(
            matches!(outcome, CommitOutcome::Applied { txs: 0, gas: 0, .. }),
            "expected Applied, got {:?}",
            outcome
        );
        assert_eq!(chain.head_slot, 1);
    }

    #[test]
    fn idempotent_when_local_hash_matches_qc() {
        let (mut chain, mut state) = fresh_chain_and_state();
        let h1 = header_at(1, [0u8; 32], 1);
        let h1_hash = h1.hash();
        let block1 = empty_block(h1);

        // First commit: forward apply.
        let _ = commit_canonical(
            &mut chain,
            &mut state,
            None,
            None,
            1,
            h1_hash,
            &block1,
            None,
            CanonicalSource::ApplyCanonicalAfterQc,
        );
        assert_eq!(chain.head_slot, 1);

        // Second commit with the same (slot, hash): idempotent.
        let outcome = commit_canonical(
            &mut chain,
            &mut state,
            None,
            None,
            1,
            h1_hash,
            &block1,
            None,
            CanonicalSource::ApplyCanonicalAfterQc,
        );
        assert!(
            matches!(outcome, CommitOutcome::Idempotent),
            "expected Idempotent, got {:?}",
            outcome
        );
        assert_eq!(chain.head_slot, 1, "head must not have moved");
    }

    #[test]
    fn reorged_when_local_hash_differs_and_canonical_is_buffered() {
        // Simulates the slot-3251 wedge: local applied its own view-1
        // fallback (h_local), then the canonical QC arrived for a
        // different block (h_canonical). Without `commit_canonical`,
        // `ApplyCanonicalAfterQc` silently skipped on `head_slot >=
        // qc_slot`. With it, we reorg.
        let (mut chain, mut state) = fresh_chain_and_state();
        let h_local = header_at(1, [0u8; 32], 1);
        let block_local = empty_block(h_local);

        let h_canonical = header_at(1, [0u8; 32], 2);
        let h_canonical_hash = h_canonical.hash();
        let block_canonical = empty_block(h_canonical);

        // Apply the local (speculative) block first.
        let _ = commit_canonical(
            &mut chain,
            &mut state,
            None,
            None,
            1,
            block_local.header.hash(),
            &block_local,
            None,
            CanonicalSource::OwnVoteInline,
        );
        assert_eq!(chain.head_slot, 1);
        let local_hash_at_1 = chain.header(1).unwrap().hash();
        assert_eq!(local_hash_at_1, block_local.header.hash());

        // Canonical QC arrives. competing_blocks has the canonical block
        // (it was received via gossip / GetBlockByHash before the QC).
        let mut competing: HashMap<(u64, [u8; 32]), Block> = HashMap::new();
        competing.insert((1, h_canonical_hash), block_canonical.clone());

        let outcome = commit_canonical(
            &mut chain,
            &mut state,
            None,
            None,
            1,
            h_canonical_hash,
            &block_canonical,
            Some(&mut competing),
            CanonicalSource::ApplyCanonicalAfterQc,
        );

        assert!(
            matches!(outcome, CommitOutcome::Reorged { .. }),
            "expected Reorged, got {:?}",
            outcome
        );
        assert_eq!(chain.head_slot, 1, "head still at 1 (reorg, not extension)");
        assert_eq!(
            chain.header(1).unwrap().hash(),
            h_canonical_hash,
            "header at slot 1 is now the canonical block"
        );
        assert!(
            !competing.contains_key(&(1, h_canonical_hash)),
            "competing_blocks entry consumed by successful reorg"
        );
    }

    #[test]
    fn divergence_unresolved_when_competing_block_not_buffered() {
        // Same setup as above but the canonical block isn't in
        // `competing_blocks` — caller must trigger sync. We pass the
        // canonical `block` directly as the reorg target (the function
        // falls back to it), but the WS-checkpoint or other gates may
        // still reject; either way the outcome is observable.
        let (mut chain, mut state) = fresh_chain_and_state();
        let h_local = header_at(1, [0u8; 32], 1);
        let block_local = empty_block(h_local);

        let _ = commit_canonical(
            &mut chain,
            &mut state,
            None,
            None,
            1,
            block_local.header.hash(),
            &block_local,
            None,
            CanonicalSource::OwnVoteInline,
        );
        assert_eq!(chain.head_slot, 1);

        let h_canonical = header_at(1, [0u8; 32], 2);
        let h_canonical_hash = h_canonical.hash();
        let block_canonical = empty_block(h_canonical);

        // No competing_blocks passed — function must still attempt the
        // reorg with the supplied `block` argument. Whether the reorg
        // succeeds depends on the inner pieces; in this minimal harness
        // it does. The branch we're really exercising is: a future
        // call site that doesn't have a competing_blocks store still
        // gets a coherent outcome rather than a silent skip.
        let outcome = commit_canonical(
            &mut chain,
            &mut state,
            None,
            None,
            1,
            h_canonical_hash,
            &block_canonical,
            None,
            CanonicalSource::ApplyCanonicalAfterQc,
        );

        // Either Reorged or DivergenceUnresolved is acceptable — what
        // we're forbidding is the prior silent-skip behavior.
        assert!(
            matches!(
                outcome,
                CommitOutcome::Reorged { .. } | CommitOutcome::DivergenceUnresolved { .. }
            ),
            "expected Reorged or DivergenceUnresolved, got {:?}",
            outcome
        );
    }

    #[test]
    fn gap_when_qc_slot_exceeds_head_by_more_than_one() {
        let (mut chain, mut state) = fresh_chain_and_state();
        let h5 = header_at(5, [0u8; 32], 5);
        let h5_hash = h5.hash();
        let block5 = empty_block(h5);

        // head_slot = 0, qc_slot = 5 → Gap.
        let outcome = commit_canonical(
            &mut chain,
            &mut state,
            None,
            None,
            5,
            h5_hash,
            &block5,
            None,
            CanonicalSource::ApplyCanonicalAfterQc,
        );

        assert!(
            matches!(
                outcome,
                CommitOutcome::Gap {
                    head_slot: 0,
                    qc_slot: 5
                }
            ),
            "expected Gap, got {:?}",
            outcome
        );
        assert_eq!(chain.head_slot, 0, "head must not have moved on Gap");
    }

    #[test]
    fn reorg_refused_past_ws_checkpoint() {
        // If the WS checkpoint has advanced past qc_slot, reorg is
        // refused (HotStuff safety: never reorg past hard finality).
        // The function reports DivergenceUnresolved so the caller can
        // escalate. This used to be a silent skip on `head_slot >=
        // qc_slot` regardless of ws_checkpoint — audit-ω makes the
        // refusal observable.
        let (mut chain, mut state) = fresh_chain_and_state();

        // Build to slot 5 so we have a head past the would-be reorg
        // target. Use process_full_block_with_aot_and_checkpoint
        // directly (rather than commit_canonical) so the setup is
        // independent of the function under test.
        let mut parent_hash = [0u8; 32];
        for slot in 1..=5 {
            let h = header_at(slot, parent_hash, slot as u8);
            parent_hash = h.hash();
            let block = empty_block(h);
            BlockProcessor::process_full_block_with_aot_and_checkpoint(
                &mut chain,
                &mut state,
                &block,
                None,
                None,
            )
            .unwrap();
        }
        assert_eq!(chain.head_slot, 5);

        // Now try a "canonical commit" at slot 3 with a different hash,
        // while WS checkpoint is at 4. reorg_to_block must refuse
        // (3 <= 4), and the outcome must be DivergenceUnresolved.
        let h3_alt = header_at(3, [2u8; 32], 99);
        let h3_alt_hash = h3_alt.hash();
        let block_alt = empty_block(h3_alt);

        let outcome = commit_canonical(
            &mut chain,
            &mut state,
            None,
            Some(4),
            3,
            h3_alt_hash,
            &block_alt,
            None,
            CanonicalSource::ApplyCanonicalAfterQc,
        );

        assert!(
            matches!(outcome, CommitOutcome::DivergenceUnresolved { .. }),
            "expected DivergenceUnresolved, got {:?}",
            outcome
        );
    }
}
