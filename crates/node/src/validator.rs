use pyde_account::address::Address;
use pyde_consensus::block::quorum_for_committee;
use pyde_consensus::block::{Block, BlockBody, BlockHeader, QuorumCert, EPOCH_LENGTH};
use pyde_consensus::epoch_randomness::{
    generate_share, verify_share, RandomnessCollector, RandomnessShare,
};
use pyde_consensus::finality::{
    create_finality_vote, try_form_hard_finality, FinalityTracker, FinalityVote,
};
use pyde_consensus::hotstuff::{
    create_vote, proposer_sign_message, try_form_qc, verify_vote, ConsensusMessage, ConsensusState,
};
use pyde_consensus::proposer::{compute_candidacy, ProposerCandidate};
use pyde_consensus::slashing::{verify_double_sign, DoubleSignEvidence};
use pyde_consensus::validator::VALIDATOR_STAKE;
use pyde_consensus::view_change::{
    create_view_change, try_form_view_change_qc, TimeoutTracker, ViewChangeMessage,
};
use pyde_crypto::falcon::{FalconPublicKey, FalconSecretKey};
use pyde_crypto::threshold::{
    aggregate_new_share, canonical_resharing_subset, generate_refresh_contribution,
    generate_resharing_contribution, verify_refresh_contribution, verify_resharing_contribution,
    RefreshContribution, ResharingContribution,
};
use pyde_crypto::threshold::{generate_decryption_share, DecryptionShare, KeyShare};
use pyde_crypto::vrf::VrfProof;
use pyde_mempool::decryption::BlockDecryptor;
use pyde_mempool::encrypted::EncryptedTx;
use pyde_tx::parallel::ExecutionSchedule;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::consensus_store::ConsensusStateStore;

/// Validator keypair and identity.
pub struct ValidatorIdentity {
    pub address: Address,
    pub public_key: FalconPublicKey,
    pub secret_key: FalconSecretKey,
    pub committee_index: u8,
    /// Threshold decryption key share for MEV-protected mempool.
    pub key_share: Option<KeyShare>,
    /// Task #95: long-lived per-validator KEM keypair used for
    /// receiving encrypted shares during DKG. Other committee members
    /// encrypt this validator's `delta[v]` row to `kem_public_key`
    /// using Kyber-KEM + AEAD; only the holder of `kem_secret_key`
    /// can decrypt their share. Persisted at `<datadir>/kem.key`,
    /// pk is published on-chain as part of the validator's
    /// `ValidatorEntry` so peers can discover it.
    ///
    /// Long-lived rather than per-epoch: simpler bookkeeping at the
    /// cost of forward secrecy — a stolen `kem_secret_key` lets the
    /// attacker decrypt every past DKG share addressed to this
    /// validator. Forward-secret per-epoch ephemeral KEM keys are a
    /// follow-up once the long-lived path is stable.
    pub kem_public_key: pyde_crypto::kyber::KyberPublicKey,
    pub kem_secret_key: pyde_crypto::kyber::KyberSecretKey,
}

/// Verify that a validator has sufficient stake on-chain.
/// Returns Ok(balance) if staked, Err if insufficient.
pub fn verify_stake(balance: u128) -> Result<u128, String> {
    if balance < VALIDATOR_STAKE {
        Err(format!(
            "insufficient stake: have {} quanta, need {} (10,000 PYDE)",
            balance, VALIDATOR_STAKE,
        ))
    } else {
        Ok(balance)
    }
}

/// Load the validator set from on-chain state.
/// Reads ALL validator entries via the index (genesis + dynamically staked).
/// Returns a ValidatorSet that can be used for committee selection.
pub fn load_validator_set_from_state(
    state: &crate::state_manager::StateManager,
    _genesis_config: &crate::genesis::GenesisConfig,
) -> pyde_consensus::validator::ValidatorSet {
    use pyde_consensus::validator::{Validator, ValidatorSet, ValidatorStatus};

    let mut set = ValidatorSet::new();

    // Read validator count from state
    let count_key = pyde_state::keys::validator_count_key();
    let count = state
        .get(&count_key)
        .map(|b| {
            if b.len() >= 8 {
                u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]))
            } else {
                0
            }
        })
        .unwrap_or(0);

    // Read each validator by index
    for i in 0..count {
        let idx_key = pyde_state::keys::validator_index_key(i);
        let address = match state.get(&idx_key) {
            Some(addr_bytes) if addr_bytes.len() == 32 => {
                let mut addr = [0u8; 32];
                addr.copy_from_slice(&addr_bytes);
                addr
            }
            _ => continue,
        };

        let val_key = pyde_state::keys::validator_key(&address);
        if let Some(val_data) = state.get(&val_key) {
            let entry = match pyde_tx::pipeline::ValidatorEntry::decode(&val_data) {
                Some(e) => e,
                None => continue,
            };
            let status = match entry.status {
                0x00 => ValidatorStatus::Active,
                0x01 => ValidatorStatus::Unbonding {
                    exit_block: entry.exit_block.unwrap_or(0),
                },
                _ => ValidatorStatus::Exited,
            };

            set.validators.push(Validator {
                address,
                public_key: entry.pk,
                stake: entry.stake,
                status,
                registered_epoch: 0,
                kem_pk: entry.kem_pk,
            });
        }
    }

    set
}

/// Process unbonding validators: return stake for those whose unbonding period expired.
/// Called at each epoch boundary.
pub fn process_unbonding(state: &mut crate::state_manager::StateManager, current_slot: u64) {
    use pyde_consensus::validator::{UNBONDING_PERIOD, VALIDATOR_STAKE};

    let count_key = pyde_state::keys::validator_count_key();
    let count = state
        .get(&count_key)
        .map(|b| {
            if b.len() >= 8 {
                u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]))
            } else {
                0
            }
        })
        .unwrap_or(0);

    for i in 0..count {
        let idx_key = pyde_state::keys::validator_index_key(i);
        let address = match state.get(&idx_key) {
            Some(addr_bytes) if addr_bytes.len() == 32 => {
                let mut addr = [0u8; 32];
                addr.copy_from_slice(&addr_bytes);
                addr
            }
            _ => continue,
        };

        let val_key = pyde_state::keys::validator_key(&address);
        if let Some(val_data) = state.get(&val_key) {
            let mut entry = match pyde_tx::pipeline::ValidatorEntry::decode(&val_data) {
                Some(e) => e,
                None => continue,
            };

            // Unbonding period elapsed? Transition to Exited + return stake.
            // Auto-claim any pending pool yield BEFORE transitioning to
            // Exited — the ClaimReward handler rejects Exited entries, so
            // without this step the validator's legitimate pre-exit
            // accrual would be stranded in the accumulator forever.
            if entry.status == 0x01 {
                if let Some(exit_block) = entry.exit_block {
                    if current_slot >= exit_block + UNBONDING_PERIOD {
                        let current_acc = pyde_tx::pipeline::read_rewards_per_validator(state);
                        let owed = current_acc.saturating_sub(entry.last_claimed_at);

                        entry.status = 0x02;
                        entry.exit_block = None;
                        entry.last_claimed_at = current_acc;
                        let _ = state.insert(val_key, entry.encode());

                        let balance_key = pyde_state::keys::balance_key(&address);
                        if let Some(account_bytes) = state.get(&balance_key) {
                            if let Some(mut account) =
                                pyde_account::types::Account::from_bytes(&account_bytes)
                            {
                                account.balance = account.balance.saturating_add(VALIDATOR_STAKE);
                                account.balance = account.balance.saturating_add(owed);
                                let _ = state.insert(balance_key, account.to_bytes());
                                tracing::info!(
                                    validator = hex::encode(address),
                                    stake_returned = VALIDATOR_STAKE,
                                    reward_claimed = owed,
                                    "unbonding complete: stake + pending reward returned"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Collected votes for a slot, used to form QCs.
struct SlotVotes {
    #[allow(dead_code)]
    block_hash: [u8; 32],
    votes: Vec<ConsensusMessage>,
}

/// A buffered proposal with verified VRF score.
struct BufferedProposal {
    header: BlockHeader,
    #[allow(dead_code)]
    proposer_signature: Vec<u8>,
    vrf_score: u64,
}

/// The validator consensus engine.
/// Manages the HotStuff protocol state, VRF proposer selection,
/// voting, QC formation, and finality tracking.
pub struct ValidatorEngine {
    /// Local chain id. Bound into every consensus signing preimage
    /// (proposer headers, votes, view-change votes, slashing evidence)
    /// so a signature created on one chain cannot be replayed on
    /// another even when FALCON keys match. See
    /// `pyde_consensus::hotstuff::proposer_sign_message`.
    pub chain_id: u64,
    /// HotStuff consensus state (current slot, highest QC, etc.).
    pub consensus: ConsensusState,
    /// Finality tracker (soft/hard finality, checkpoints).
    pub finality: FinalityTracker,
    /// Timeout tracker for the current slot.
    pub timeout: TimeoutTracker,
    /// Audit 408: wall-clock anchor for converting slot numbers into
    /// the moment that slot actually begins. The
    /// `PROPOSAL_TIMEOUT_MS` window for slot N is measured from
    /// `genesis_timestamp_ms + N * block_time_ms`, NOT from the
    /// instant the prior slot's QC happened to form. Pre-fix,
    /// `advance_target_height` reset the tracker to wall-clock
    /// `now`, so a slot whose QC formed early (e.g. slot 26 QC at
    /// 100 ms into the slot) started counting timeout for slot 27
    /// from that same moment — 200 ms later it would fire a view-
    /// change for slot 27 even though slot 27's wall-clock window
    /// hadn't begun yet (slot 27 starts at slot 26 + 400 ms). The
    /// 3-min soak observed 50 % of slots view-changing under this
    /// bug. Both fields default to 0 until `set_slot_anchor()` is
    /// called after the runtime constructs the slot clock; while
    /// they're 0 the engine falls back to the wall-clock-now
    /// behavior so unit tests that don't wire a slot clock
    /// continue to pass.
    pub genesis_timestamp_ms: u64,
    /// Block-time interval in milliseconds. Paired with
    /// `genesis_timestamp_ms` for the timeout-anchor computation
    /// described above.
    pub block_time_ms: u64,
    /// Committee public keys for the current epoch (index → key bytes).
    pub committee_keys: Vec<Vec<u8>>,
    /// Epoch randomness seed (for VRF proposer selection).
    pub epoch_randomness: [u8; 32],
    /// Audit 402: committee public keys for the IMMEDIATELY-PRIOR
    /// epoch. Pre-fix, when the chain crossed an epoch boundary
    /// `set_committee` overwrote `committee_keys` with the new
    /// committee. The first block of the new epoch (slot N where
    /// `N % EPOCH_LENGTH == 0`) carries `qc_previous = QC(slot
    /// N-1)` — signed by the OLD committee. Verifying that QC
    /// against the NEW committee keys fails, no validator votes,
    /// and the chain wedges forever. By keeping the prior epoch's
    /// keys around for one slot past the boundary, the
    /// `committee_keys_for_slot()` helper returns the right key
    /// set for any QC whose slot fell in either the current or
    /// the prior epoch. Caught by the 1-hour soak test
    /// (`loadgen_soak.rs`); reproduces deterministically at slot
    /// 1000 (= 1 × EPOCH_LENGTH).
    pub prev_committee_keys: Vec<Vec<u8>>,
    /// Audit 402: epoch randomness for the IMMEDIATELY-PRIOR
    /// epoch. Same problem as `prev_committee_keys` but for VRF
    /// verification — the proposer at the first slot of a new
    /// epoch generated its VRF proof against the value of
    /// `epoch_randomness` AT proposal time, but by the time the
    /// validator verifies it, `epoch_randomness` has been
    /// overwritten with the next epoch's randomness during the
    /// boundary handler. The verifier looks up the right
    /// randomness via `epoch_randomness_for_slot()`.
    pub prev_epoch_randomness: [u8; 32],
    /// Audit 402: which epoch this engine is currently aligned
    /// with. The boundary handlers in `node.rs` advance this when
    /// `set_committee` runs. Verification helpers compare
    /// `slot / EPOCH_LENGTH` against this to decide whether to
    /// use current or prior epoch's keys / randomness.
    pub current_epoch: u64,
    /// Audit 402: BUFFERED randomness for the next epoch. Pre-fix,
    /// `on_randomness_share` directly overwrote
    /// `self.epoch_randomness` whenever a randomness collector
    /// finalized — typically a few slots after the rotation that
    /// kicked off collection. That meant `self.epoch_randomness`
    /// could mutate MID-EPOCH (between proposer's VRF generation
    /// and verifier's VRF verification of the same slot's
    /// proposal), so the same node would generate a VRF with one
    /// value and verify it against another. Post-fix the share
    /// finalize writes here; the swap into `self.epoch_randomness`
    /// happens atomically inside `rotate_to_epoch` at the next
    /// boundary, so any given epoch's slots all see the same
    /// stable randomness.
    pub next_epoch_randomness: Option<[u8; 32]>,
    /// Votes collected per slot.
    votes: HashMap<u64, SlotVotes>,
    /// View change messages collected per slot.
    view_changes: HashMap<u64, Vec<ViewChangeMessage>>,
    /// Finality votes collected per slot.
    finality_votes: HashMap<u64, Vec<FinalityVote>>,
    /// Buffered proposals per slot (collected during proposal phase, voted after selection).
    buffered_proposals: HashMap<u64, Vec<BufferedProposal>>,
    /// Highest view at which we've voted on each slot (audit-94).
    /// Voting at `(slot, view=0)` does NOT lock out voting at
    /// `(slot, view=1)` on the deterministic recovery proposal —
    /// that's the case the view change exists to recover from.
    /// Sentinel `u64::MAX` means inclusion-violated: voting on
    /// this slot is permanently disabled regardless of view.
    voted_view_per_slot: std::collections::HashMap<u64, u64>,
    /// audit-94: highest view at which this validator has built a
    /// fallback proposal for each slot. Prevents the double-build
    /// race where both the gossip and RR view-change-QC paths
    /// trigger `try_build_fallback_proposal` for the same
    /// `(slot, view)`. Each build re-stamps `timestamp = now_ms()`
    /// → different `block_hash` → peers split their fallback votes
    /// across the two versions → vote-QC never forms → chain
    /// wedges at the slot the fallback was supposed to recover.
    /// The companion `buffered_proposals`-based dedup at the top
    /// of `try_build_fallback_proposal` doesn't catch this: the
    /// proposer deliberately omits its own fallback from
    /// `buffered_proposals` (Phase 2 — preserves the
    /// min-by-`vrf_score` tie-break for cluster-wide vote
    /// dynamics). This map IS the proposer-side dedup.
    last_built_fallback_view_per_slot: std::collections::HashMap<u64, u64>,
    /// Seen proposals per slot: (slot, proposer_address) → (header, signature).
    /// Used to detect double-proposing.
    seen_proposals: HashMap<(u64, Address), (BlockHeader, Vec<u8>)>,
    /// Seen votes per slot: (slot, voter_index) → (block_hash, signature).
    /// Used to detect double-voting (equivocation).
    seen_votes: HashMap<(u64, u8), ([u8; 32], Vec<u8>)>,
    /// Audit 327: dedup map for incoming view-change messages,
    /// keyed on `(slot, voter_index)` with value
    /// `(highest_qc_hash, signature)`. `on_view_change` checks
    /// the key set BEFORE pushing to `view_changes` so a peer
    /// that re-broadcasts the same VC message (legitimate gossip
    /// reflood) or floods adversarial repeats cannot inflate the
    /// per-slot Vec — `try_form_view_change_qc` runs FALCON
    /// verification once per entry, so an unbounded Vec means
    /// unbounded FALCON cost per QC-formation attempt.
    /// Pruned alongside `view_changes` in the slot-prune loop.
    ///
    /// TPL-502: the *value* (`(qc_hash, sig)`) is stored so that
    /// when a second VC arrives at the same `(slot,
    /// voter_index)` with a DIFFERENT `highest_qc.hash()`, we
    /// can construct `DoubleViewChangeEvidence` from the cached
    /// first signature + the incoming second one and route it
    /// through the slashing pipeline.
    seen_view_changes: HashMap<(u64, u8), ([u8; 32], Vec<u8>)>,
    /// TPL-501: self-VC equivocation guard. Records every
    /// view-change message THIS validator signed, keyed by
    /// `slot` (target_height at sign time) with value
    /// `(highest_qc_hash, signature)`. Persisted via
    /// `ConsensusStateStore::save_seen_view_change_self`
    /// BEFORE `on_timeout` returns the signed message — without
    /// that ordering, a crash between sign + persist could let
    /// the validator sign a different VC at the same slot post-
    /// restart (different `highest_qc` survives the reboot,
    /// FALCON sig over a different message → equivocation,
    /// slashable).
    ///
    /// Pruned alongside `seen_proposals` / `seen_votes` in the
    /// `advance_slot` retention loop and on disk via
    /// `prune_evidence_before`.
    seen_view_changes_self: std::collections::HashMap<u64, ([u8; 32], Vec<u8>)>,
    /// Audit 327: dedup set for incoming finality votes, keyed
    /// on `(slot, voter_index)`. Same rationale as
    /// `seen_view_changes` — `try_form_hard_finality` re-verifies
    /// every vote in the per-slot Vec, so a duplicate flood
    /// re-pays FALCON cost per duplicate.
    seen_finality_votes: std::collections::HashSet<(u64, u8)>,
    /// Collected double-sign evidence awaiting inclusion in a Slash tx.
    /// Drained by `drain_pending_evidence` when the block builder wants
    /// to construct slashing transactions. We hold the raw evidence here
    /// rather than the computed SlashResult because the slashing handler
    /// on the receiving node will re-verify signatures from state —
    /// SlashResult is just a local convenience.
    pub pending_evidence: Vec<DoubleSignEvidence>,
    /// TPL-502: queue for VC equivocation evidence detected by
    /// `on_view_change`. Held separately from `pending_evidence`
    /// to keep wire compatibility with the existing Slash-tx
    /// payload (which expects `DoubleSignEvidence` shape) while
    /// the on-chain handler integration is staged. Drained by
    /// `drain_pending_vc_evidence`. Dedup is the same `(slot,
    /// signer)` pair keyed off `seen_evidence`, so a piece of
    /// evidence is queued at most once.
    pub pending_vc_evidence: Vec<pyde_consensus::slashing::DoubleViewChangeEvidence>,
    /// Epoch randomness collector (gathers VRF shares at epoch boundary).
    randomness_collector: Option<RandomnessCollector>,
    /// Audit 403: slot at which `try_finalize_randomness_on_slot` is
    /// allowed to combine the buffered shares. Set to
    /// `current_slot + RANDOMNESS_AGGREGATION_DELAY_SLOTS` by
    /// `start_epoch_randomness`. The delay closes the same race that
    /// the resharing trigger closes: under async gossip, different
    /// validators see different "first 3-of-4" arrival sets and used
    /// to finalize on whichever set hit threshold first — producing
    /// non-deterministic randomness across the committee. Waiting
    /// for this trigger lets gossipsub deliver every member's share
    /// to every node before we run the canonical-subset combine, so
    /// all nodes agree on the same epoch randomness.
    randomness_aggregation_trigger_slot: u64,
    /// PSS refresh contributions collected at epoch boundary.
    pss_contributions: Vec<RefreshContribution>,
    /// Target epoch for PSS refresh.
    pss_target_epoch: u64,
    /// Audit 406: slot at which `try_apply_pss_on_slot` is allowed to
    /// combine the buffered PSS contributions. Mirror of
    /// `reshare_aggregation_trigger_slot` for cross-committee
    /// resharing and `randomness_aggregation_trigger_slot` for epoch
    /// randomness — under async gossip every node sees a different
    /// "first `threshold`-of-N" arrival order, so eagerly applying
    /// the first `threshold` contributions caused different nodes
    /// to apply different delta subsets, breaking the PSS invariant
    /// that all refreshed shares interpolate to the same secret.
    /// Set to `current_slot + RESHARE_AGGREGATION_DELAY_SLOTS` by
    /// `start_pss_refresh`; the slot tick fires
    /// `try_apply_pss_on_slot` once `current_slot` crosses it.
    pss_aggregation_trigger_slot: u64,
    /// `true` once `try_apply_pss_on_slot` has fired for the current
    /// target epoch. Prevents re-applying when additional late
    /// contributions arrive after the canonical apply.
    pss_aggregated: bool,
    /// Audit 406: own PSS contribution bytes stashed for periodic
    /// re-broadcast, mirror of `pending_reshare_rebroadcast`. Without
    /// this a single dropped gossip message means the missing-contrib
    /// validator's pool stays at `n - 1`, the all-N guard in
    /// `try_apply_pss_on_slot` blocks the apply, and PSS silently
    /// skips the epoch. With the rebroadcast loop a missed message
    /// recovers within `PSS_REBROADCAST_INTERVAL_SLOTS` slots.
    /// Layout: `(target_epoch, contribution_bytes)`.
    pending_pss_rebroadcast: Option<(u64, Vec<u8>)>,
    /// Slot at which `start_pss_refresh` published our contribution.
    /// `maybe_rebroadcast_pss` uses this + `current_slot` to scope
    /// the rebroadcast window.
    pss_broadcast_start_slot: u64,
    /// Cross-committee resharing contributions collected at epoch boundary
    /// (task 034). Keyed by target epoch so late contributions from
    /// previous epochs are ignored.
    reshare_contributions: Vec<ResharingContribution>,
    /// Target epoch for active resharing (the epoch whose incoming committee
    /// the contributions are addressed to).
    reshare_target_epoch: u64,
    /// Committee key pubkeys of the NEW committee for the active reshare.
    /// Used to compute new_n, new_threshold, and our own 1-based index in
    /// the incoming committee (0 if we're not a member).
    reshare_new_committee: Vec<Vec<u8>>,
    /// Our 1-based index in the incoming committee for the active reshare.
    /// Zero when we're not on the new committee (no aggregation to perform).
    reshare_new_index: usize,
    /// Our own resharing contribution (if we're outgoing) stashed for
    /// periodic re-broadcast. Gossipsub's message cache only retains a few
    /// heartbeats, so a validator that comes online a few slots after the
    /// epoch-boundary broadcast could miss contributions. Re-broadcasting
    /// for the first `RESHARE_REBROADCAST_SLOTS` slots of the target epoch
    /// lets stragglers catch up without a dedicated sync protocol.
    /// Layout: `(target_epoch, contribution_bytes)`.
    pending_reshare_rebroadcast: Option<(u64, Vec<u8>)>,
    /// Slot at which `start_committee_reshare` published our contribution.
    /// `maybe_rebroadcast_reshare` uses this + `current_slot` to decide
    /// whether we're still inside the re-broadcast window.
    reshare_broadcast_start_slot: u64,
    /// Slot at which the next aggregation attempt should fire. Set by
    /// `prepare_for_reshare_reception` to
    /// `current_slot + RESHARE_AGGREGATION_DELAY_SLOTS`. The delay gives
    /// gossipsub enough time to deliver every old member's contribution
    /// to every new member, so all new members see the same pool and
    /// derive identical canonical subsets. Aggregating eagerly on first
    /// threshold — as we did before — is unsafe under async gossip,
    /// because different new members can hit threshold with different
    /// pool subsets and end up on different polynomials.
    reshare_aggregation_trigger_slot: u64,
    /// `true` once aggregation has fired for the current target epoch.
    /// Prevents re-aggregating when additional late contributions arrive.
    reshare_aggregated: bool,
    /// Set to true when key share was refreshed and needs saving to disk.
    pub key_share_dirty: bool,
    /// Optional persistent store for ConsensusState. When set, the engine
    /// writes to disk on every safety-critical mutation and reloads on startup.
    /// Crash-safe property: never regress last_voted_slot or highest_qc.
    consensus_store: Option<Arc<ConsensusStateStore>>,
    /// Evidence staged for P2P broadcast. Populated by local detection
    /// (and by ingest_evidence on first-seen gossip items); drained by
    /// the node loop after each proposal it processes, so new
    /// equivocations reach every validator even if only one directly
    /// witnessed them.
    broadcast_evidence: Vec<DoubleSignEvidence>,
    /// (slot, signer) pairs we've already ingested. Dedups both local
    /// re-detection (same validator conflicting across >2 blocks at the
    /// same slot) and gossip arrivals — each pair is broadcast at most
    /// once and stored in pending_evidence at most once.
    seen_evidence: std::collections::HashSet<(u64, Address)>,
    /// Slots flagged by the inclusion audit (task 026). When a compact
    /// block is received, validators compare its encrypted_txs against
    /// their local mempool view; if a tx older than the grace window is
    /// absent while gas budget remains, the slot is flagged and this
    /// validator will not vote on the selected proposal for that slot.
    /// Soft enforcement — a 1/128 false positive just costs one vote.
    inclusion_violated_slots: std::collections::HashSet<u64>,
    /// Audit 234 part 3: wall-clock timestamp (Unix ms) of the
    /// most recent forward movement of `consensus.highest_qc.slot`,
    /// AND the slot value at that moment. `is_timed_out` lazily
    /// detects QC progress (current `highest_qc.slot` > the cached
    /// one), updates both fields, then checks the
    /// `PROGRESS_TIMEOUT_MS` deadline. Powers the
    /// "no-progress" liveness fallback: if the chain hasn't
    /// produced a new QC for `PROGRESS_TIMEOUT_MS`, the validator
    /// triggers view-change regardless of whether a proposal was
    /// received for the current slot. Without this, gossip-mesh
    /// degradation can wedge the chain indefinitely — validators
    /// that received the proposal vote and don't time out,
    /// validators that didn't time out and view-change, and
    /// neither path reaches quorum.
    last_qc_progress_ms: u64,
    last_seen_qc_slot: u64,
    /// TPL-405: graceful-shutdown handle. When set, fatal-persist
    /// branches that previously called `panic!` instead trigger
    /// this signal so the main loop can drain in-flight work and
    /// exit cleanly. Tests leave this `None`, preserving the
    /// existing `panic!` behaviour for failure-mode assertions.
    shutdown_signal: Option<crate::shutdown::ShutdownSignal>,
}

impl ValidatorEngine {
    /// Create a new validator engine at genesis bound to a specific
    /// `chain_id`. The `chain_id` is bound into every consensus signing
    /// preimage so signatures cannot be replayed across chains even
    /// when FALCON keys match.
    pub fn new(chain_id: u64, epoch_randomness: [u8; 32]) -> Self {
        let now_ms = current_time_ms();
        let consensus = ConsensusState::new();
        // audit-234 part 4: TimeoutTracker is keyed on `target_height`,
        // not the wall-clock slot. ConsensusState::new() initializes
        // target_height to 1 (the first slot we want to commit).
        let initial_target = consensus.target_height;
        Self {
            chain_id,
            consensus,
            finality: FinalityTracker::new(),
            timeout: TimeoutTracker::new(initial_target, now_ms),
            // Audit 408: anchor stays 0 until the runtime calls
            // `set_slot_anchor()` post-slot-clock-construction.
            // While 0, `slot_start_ms_for_target()` falls back to
            // wall-clock — preserving prior behavior for tests
            // that exercise the engine without wiring a clock.
            genesis_timestamp_ms: 0,
            block_time_ms: 0,
            committee_keys: Vec::new(),
            epoch_randomness,
            // Audit 402: prior-epoch caches start empty; populated
            // by `rotate_to_epoch` at every boundary.
            prev_committee_keys: Vec::new(),
            prev_epoch_randomness: [0u8; 32],
            current_epoch: 0,
            next_epoch_randomness: None,
            votes: HashMap::new(),
            view_changes: HashMap::new(),
            finality_votes: HashMap::new(),
            buffered_proposals: HashMap::new(),
            voted_view_per_slot: std::collections::HashMap::new(),
            last_built_fallback_view_per_slot: std::collections::HashMap::new(),
            seen_proposals: HashMap::new(),
            seen_votes: HashMap::new(),
            seen_view_changes: HashMap::new(),
            seen_view_changes_self: std::collections::HashMap::new(),
            seen_finality_votes: std::collections::HashSet::new(),
            pending_evidence: Vec::new(),
            pending_vc_evidence: Vec::new(),
            broadcast_evidence: Vec::new(),
            seen_evidence: std::collections::HashSet::new(),
            inclusion_violated_slots: std::collections::HashSet::new(),
            last_qc_progress_ms: now_ms,
            last_seen_qc_slot: 0,
            randomness_collector: None,
            randomness_aggregation_trigger_slot: 0,
            pss_contributions: Vec::new(),
            pss_target_epoch: 0,
            pss_aggregation_trigger_slot: 0,
            pss_aggregated: false,
            pending_pss_rebroadcast: None,
            pss_broadcast_start_slot: 0,
            reshare_contributions: Vec::new(),
            reshare_target_epoch: 0,
            reshare_new_committee: Vec::new(),
            reshare_new_index: 0,
            pending_reshare_rebroadcast: None,
            reshare_broadcast_start_slot: 0,
            reshare_aggregation_trigger_slot: 0,
            reshare_aggregated: false,
            key_share_dirty: false,
            consensus_store: None,
            shutdown_signal: None,
        }
    }

    /// TPL-405: register a shutdown signal so persist failures can
    /// trigger drain-then-exit instead of `panic!`. Production
    /// callers wire this to the same `ShutdownSignal` the SIGTERM
    /// handler triggers; the main loop then drives the drain.
    pub fn attach_shutdown_signal(&mut self, signal: crate::shutdown::ShutdownSignal) {
        self.shutdown_signal = Some(signal);
    }

    /// TPL-405: log a fatal-persist diagnostic and either trigger
    /// graceful shutdown (production) or panic (tests / no signal
    /// configured). Used by the consensus / evidence / reshare
    /// persist paths whose pre-fix branches called `panic!`
    /// directly. Continuing after a failed safety-critical write
    /// would silently degrade BFT guarantees on the next restart;
    /// the function returns rather than swallowing the error so
    /// callers stop issuing new actions while the loop drains.
    fn signal_persist_failure(&self, what: &str, err: &str) {
        error!(
            error = %err,
            what,
            "FATAL: safety-critical persist failed — halting validator"
        );
        match &self.shutdown_signal {
            Some(sig) => sig.trigger(),
            None => panic!("{what} persist failed: {err}"),
        }
    }

    /// Attach a persistent ConsensusState store.
    ///
    /// If the store already contains a prior state (from a previous run),
    /// it is loaded into `self.consensus`, preserving `last_voted_slot` and
    /// `highest_qc` across restarts — the safety guarantee that prevents
    /// double-voting after a crash.
    pub fn attach_consensus_store(&mut self, store: Arc<ConsensusStateStore>) {
        match store.load() {
            Ok(Some(prior)) => {
                info!(
                    slot = prior.current_slot,
                    last_voted = prior.last_voted_slot,
                    highest_qc = prior.highest_qc.slot,
                    "restoring consensus state from disk"
                );
                self.consensus = prior;
            }
            Ok(None) => {
                info!("no prior consensus state found; starting fresh");
            }
            Err(e) => {
                // A corrupt store is a hard failure — we refuse to start
                // with possibly-regressed safety state rather than silently
                // continue with a fresh state that could double-vote.
                error!(error = %e, "failed to load consensus state; aborting attach");
                return;
            }
        }

        // Restore equivocation evidence index. Missing or corrupt entries are
        // skipped by the store loader; we take whatever comes back.
        let proposals = store.load_all_seen_proposals();
        let votes = store.load_all_seen_votes();
        // TPL-501: also restore self-VC records so on_timeout
        // post-restart re-broadcasts the persisted signature
        // (when highest_qc still hashes the same) instead of
        // signing a fresh — potentially divergent — VC.
        let view_changes_self = store.load_all_seen_view_changes_self();
        if !proposals.is_empty() || !votes.is_empty() || !view_changes_self.is_empty() {
            info!(
                proposals = proposals.len(),
                votes = votes.len(),
                view_changes_self = view_changes_self.len(),
                "restoring equivocation evidence from disk"
            );
        }
        for (key, value) in proposals {
            self.seen_proposals.insert(key, value);
        }
        for (key, value) in votes {
            self.seen_votes.insert(key, value);
        }
        for (slot, qc_hash_and_sig) in view_changes_self {
            self.seen_view_changes_self.insert(slot, qc_hash_and_sig);
        }

        // Restore the ingest queues. Without this, a validator that
        // detected equivocation and crashed before draining would lose
        // the evidence — the seen_proposals/seen_votes indexes would
        // still know about the conflict but the ready-to-slash queue
        // would be empty, and if the offender never equivocated again
        // they'd escape punishment.
        match store.load_evidence_state() {
            Ok(Some(ev_state)) => {
                info!(
                    pending = ev_state.pending.len(),
                    broadcast = ev_state.broadcast.len(),
                    seen = ev_state.seen.len(),
                    "restoring evidence ingest queues from disk"
                );
                self.pending_evidence = ev_state.pending;
                self.broadcast_evidence = ev_state.broadcast;
                self.seen_evidence = ev_state.seen.into_iter().collect();
            }
            Ok(None) => {}
            Err(e) => {
                // Non-fatal: we can continue with empty queues. The
                // dedup HashSet being empty means we might re-ingest
                // duplicate gossip, but duplicates are caught by the
                // on-chain slash handler (already-ejected rejection).
                warn!(error = %e, "failed to load evidence state; starting empty");
            }
        }

        // Reshare state restore (task 034 crash safety). Contribution pool
        // is intentionally NOT persisted — it rebuilds from rebroadcasts
        // during the window. All other fields ARE persisted so an in-
        // progress rotation resumes cleanly: the same target epoch, the
        // same new-committee index, the same aggregation trigger slot, and
        // the same `aggregated` flag that prevents double-aggregation.
        match store.load_reshare_state() {
            Ok(Some(rs)) => {
                info!(
                    target_epoch = rs.target_epoch,
                    new_index = rs.new_index,
                    aggregated = rs.aggregated,
                    "restoring reshare state from disk"
                );
                self.restore_reshare_state(rs);
            }
            Ok(None) => {}
            Err(e) => {
                warn!(error = %e, "failed to load reshare state; starting empty");
            }
        }

        // Slice 4.3: restore WS checkpoint so a restart preserves the
        // hard-final anchor. Without this, a node coming back online
        // would validate any chain from slot 0 and potentially accept
        // a long-range-attack fork.
        match store.load_finality_checkpoint() {
            Ok(Some(cp)) => {
                info!(slot = cp.slot, "restoring weak-subjectivity checkpoint");
                self.finality.latest_checkpoint = Some(cp);
            }
            Ok(None) => {}
            Err(e) => {
                // A corrupt checkpoint is a HARD failure — without it we
                // can't enforce WS, so refusing to start is safer than
                // silently running without the guard.
                self.signal_persist_failure("finality checkpoint load", &e.to_string());
                return;
            }
        }

        self.consensus_store = Some(store);
    }

    /// Snapshot the current evidence ingest queues into an
    /// `EvidenceState` for persistence. Called after any mutation
    /// that changes pending_evidence, broadcast_evidence, or
    /// seen_evidence.
    fn evidence_snapshot(&self) -> crate::wire::EvidenceState {
        crate::wire::EvidenceState {
            pending: self.pending_evidence.clone(),
            broadcast: self.broadcast_evidence.clone(),
            seen: self.seen_evidence.iter().copied().collect(),
        }
    }

    /// Persist the current evidence state. No-op without a store.
    /// Panics on failure for the same reason as `persist_consensus`:
    /// a silent revert to in-memory-only mode loses safety
    /// guarantees on the next crash.
    fn persist_evidence_state(&self) {
        if let Some(store) = &self.consensus_store {
            if let Err(e) = store.save_evidence_state(&self.evidence_snapshot()) {
                self.signal_persist_failure("evidence state", &e.to_string());
            }
        }
    }

    /// Persist consensus state to disk. No-op when no store is attached.
    ///
    /// Safety-critical: must be called after any mutation of
    /// `last_voted_slot`, `highest_qc`, or `current_slot`.
    ///
    /// **Panics on persist failure.** Continuing after a failed write would
    /// silently degrade the validator to in-memory-only mode: the next
    /// crash or restart would reload stale state from disk, potentially
    /// regressing `last_voted_slot` and allowing a double-vote — a BFT
    /// safety violation. We'd rather abort the process loudly and let
    /// the operator restart from a clean (last known-good) disk state
    /// after resolving the underlying I/O issue. In release builds the
    /// workspace uses `panic = "abort"`, so this unwinds to an immediate
    /// SIGABRT; in tests it surfaces as a test failure.
    fn persist_consensus(&self) {
        if let Some(store) = &self.consensus_store {
            if let Err(e) = store.save(&self.consensus) {
                self.signal_persist_failure("consensus state", &e.to_string());
            }
        }
    }

    /// Set the committee keys for the current epoch.
    ///
    /// Audit 402: when called at an epoch boundary (i.e., the new
    /// keys differ from the current set), the prior keys must be
    /// preserved so QCs that signed the LAST slot of the prior
    /// epoch can still be verified by the new committee. The
    /// boundary handler in `node.rs` should call
    /// `rotate_to_epoch(new_epoch, new_keys, new_randomness)`
    /// instead of `set_committee` for the cleanest transition;
    /// `set_committee` itself is kept for the genesis-bootstrap
    /// path where `prev_committee_keys` stays empty.
    pub fn set_committee(&mut self, keys: Vec<Vec<u8>>) {
        info!(members = keys.len(), "committee keys loaded");
        self.committee_keys = keys;
    }

    /// Audit 402: atomic epoch-boundary rotation. Three things move
    /// in lock-step:
    ///
    ///   1. Outgoing committee keys → `prev_committee_keys` so
    ///      `qc_previous` (which signs the prior epoch's last slot)
    ///      can still be verified against the right keys.
    ///   2. Outgoing `epoch_randomness` → `prev_epoch_randomness`
    ///      for the same reason on the VRF side.
    ///   3. If `next_epoch_randomness` was buffered (from
    ///      `on_randomness_share` finalizing during the prior
    ///      epoch), it gets swapped into `epoch_randomness`. If no
    ///      buffer is available, `epoch_randomness` keeps its prior
    ///      value — degenerate but consistent: every node will use
    ///      the same fallback so VRF still verifies, the chain just
    ///      reuses entropy until the next collection finishes.
    pub fn rotate_to_epoch(&mut self, new_epoch: u64, new_keys: Vec<Vec<u8>>) {
        info!(
            new_epoch,
            members = new_keys.len(),
            randomness_swapped = self.next_epoch_randomness.is_some(),
            "epoch rotation: prior keys + randomness preserved for boundary verification"
        );
        self.prev_committee_keys = std::mem::take(&mut self.committee_keys);
        self.prev_epoch_randomness = self.epoch_randomness;
        self.committee_keys = new_keys;
        if let Some(next) = self.next_epoch_randomness.take() {
            self.epoch_randomness = next;
        }
        self.current_epoch = new_epoch;
    }

    /// Audit 402: return the committee keys that were active during
    /// `slot`'s epoch. For `slot >= current_epoch * EPOCH_LENGTH`
    /// returns the current committee. For slots in the immediately-
    /// prior epoch (i.e., `current_epoch - 1`), returns the cached
    /// prior keys. Slots older than that fall back to the current
    /// committee — that's a degenerate case (we'd never legitimately
    /// vote on a QC that old) but keeps the function total.
    pub fn committee_keys_for_slot(&self, slot: u64) -> &[Vec<u8>] {
        let slot_epoch = slot / pyde_consensus::block::EPOCH_LENGTH;
        if slot_epoch + 1 == self.current_epoch && !self.prev_committee_keys.is_empty() {
            &self.prev_committee_keys
        } else {
            &self.committee_keys
        }
    }

    /// Audit 402: same boundary-aware lookup for VRF input
    /// randomness. The proposer at slot N generated its VRF
    /// against the randomness valid at slot N's epoch; the verifier
    /// must use the same value or VRF verification fails.
    pub fn epoch_randomness_for_slot(&self, slot: u64) -> [u8; 32] {
        let slot_epoch = slot / pyde_consensus::block::EPOCH_LENGTH;
        if slot_epoch + 1 == self.current_epoch && self.prev_epoch_randomness != [0u8; 32] {
            self.prev_epoch_randomness
        } else {
            self.epoch_randomness
        }
    }

    /// Start collecting epoch randomness shares for the next epoch.
    /// Called at epoch boundary. Generates and returns our own share to broadcast.
    /// Generate a PSS refresh contribution and start collecting others'.
    /// Returns our contribution to broadcast.
    pub fn start_pss_refresh(
        &mut self,
        epoch: u64,
        identity: &ValidatorIdentity,
    ) -> Option<RefreshContribution> {
        let key_share = identity.key_share.as_ref()?;
        let n = self.committee_keys.len();
        let threshold = quorum_for_committee(n);

        // Use PRIVATE entropy: hash of secret key + epoch randomness.
        // This ensures each validator's contribution is unpredictable to others.
        // Public epoch_randomness alone would let attackers derive all contributions.
        let mut private_entropy = Vec::with_capacity(64);
        private_entropy.extend_from_slice(identity.secret_key.as_bytes());
        private_entropy.extend_from_slice(&self.epoch_randomness);
        let entropy = pyde_crypto::poseidon2::poseidon2_hash(&private_entropy);

        // TPL-303: sign the contribution with the validator's
        // consensus FALCON sk so peers can authenticate the
        // claimed `from_index` and reject cross-epoch replays.
        let contribution = match generate_refresh_contribution(
            key_share.index,
            n,
            threshold,
            epoch,
            entropy.as_bytes(),
            &identity.secret_key,
        ) {
            Ok(c) => c,
            Err(e) => {
                warn!(epoch, error = %e, "PSS refresh sig generation failed");
                return None;
            }
        };

        self.pss_contributions = vec![contribution.clone()];
        self.pss_target_epoch = epoch;
        // Audit 406: arm the canonical-subset apply gate. The slot
        // tick fires `try_apply_pss_on_slot` once `current_slot`
        // crosses this trigger; until then, contributions just pool.
        // Mirrors `RESHARE_AGGREGATION_DELAY_SLOTS` for cross-
        // committee resharing so PSS, randomness, and reshare all
        // resolve their first-N-wins races identically.
        self.pss_aggregation_trigger_slot =
            self.consensus.current_slot + Self::RESHARE_AGGREGATION_DELAY_SLOTS;
        self.pss_aggregated = false;
        // Audit 406: stash bytes + window start for the rebroadcast
        // loop. Mirror of `pending_reshare_rebroadcast` —
        // `maybe_rebroadcast_pss` re-publishes every
        // `RESHARE_REBROADCAST_INTERVAL_SLOTS` slots for
        // `RESHARE_REBROADCAST_SLOTS` slots after the initial publish
        // so a single dropped gossip message doesn't strand a
        // validator's pool at n-1.
        self.pending_pss_rebroadcast = Some((epoch, contribution.to_bytes()));
        self.pss_broadcast_start_slot = self.consensus.current_slot;
        info!(epoch, "started PSS key share refresh");
        Some(contribution)
    }

    /// Audit 406: return our own PSS contribution bytes for a
    /// rebroadcast on this slot tick, or `None` if we're outside the
    /// rebroadcast window or it isn't a rebroadcast slot. Caller
    /// publishes the returned bytes on the consensus topic. Mirror
    /// of `maybe_rebroadcast_reshare`.
    pub fn maybe_rebroadcast_pss(&mut self) -> Option<(u64, Vec<u8>)> {
        let (target_epoch, bytes) = self.pending_pss_rebroadcast.as_ref()?;
        let now = self.consensus.current_slot;
        let elapsed = now.saturating_sub(self.pss_broadcast_start_slot);
        if elapsed > Self::RESHARE_REBROADCAST_SLOTS {
            self.pending_pss_rebroadcast = None;
            return None;
        }
        if elapsed == 0 {
            return None;
        }
        if elapsed % Self::RESHARE_REBROADCAST_INTERVAL_SLOTS != 0 {
            return None;
        }
        Some((*target_epoch, bytes.clone()))
    }

    /// Add a received PSS refresh contribution. Pools it for the
    /// canonical-subset apply that fires on slot tick. Returns
    /// `true` when the contribution was new (not a duplicate index)
    /// and structurally valid; the boolean is informational only —
    /// the actual apply lives in `try_apply_pss_on_slot`.
    pub fn on_pss_contribution(
        &mut self,
        contribution: RefreshContribution,
        _identity: &mut ValidatorIdentity,
    ) -> bool {
        let threshold = quorum_for_committee(self.committee_keys.len());

        // Audit 406: drop late contributions for an already-applied
        // refresh. Pre-fix the eager-apply bucket was cleared on
        // first-threshold and any `from_index` could refill it;
        // post-fix `pss_aggregated` gates this explicitly.
        if self.pss_aggregated {
            return false;
        }

        // TPL-303: resolve the claimed issuer's FALCON pk from the
        // committee table. `from_index` is 1-based, so subtract 1
        // before indexing. An out-of-range `from_index` is rejected
        // here without spending a Lagrange/structural verify cycle.
        let from_idx0 = match contribution.from_index.checked_sub(1) {
            Some(i) if i < self.committee_keys.len() => i,
            _ => {
                warn!(
                    from = contribution.from_index,
                    "PSS contribution from_index out of committee range"
                );
                return false;
            }
        };
        let issuer_pk =
            match pyde_crypto::falcon::FalconPublicKey::from_bytes(&self.committee_keys[from_idx0])
            {
                Some(pk) => pk,
                None => {
                    warn!(
                        from = contribution.from_index,
                        "committee FALCON pk decode failed for PSS contribution"
                    );
                    return false;
                }
            };

        // Verify the contribution: TPL-303 epoch + sig, plus the
        // existing structural zero-secret + polynomial-consistency
        // checks. `pss_target_epoch` is set by `start_pss_refresh`
        // and matches the epoch every honest contribution claims.
        if !verify_refresh_contribution(
            &contribution,
            threshold,
            self.pss_target_epoch,
            &issuer_pk,
        ) {
            warn!(
                from = contribution.from_index,
                "invalid PSS refresh contribution"
            );
            return false;
        }

        // Check for duplicate
        if self
            .pss_contributions
            .iter()
            .any(|c| c.from_index == contribution.from_index)
        {
            return false;
        }

        self.pss_contributions.push(contribution);
        // Audit 406: NO eager apply here. The canonical-subset
        // apply runs on slot tick via `try_apply_pss_on_slot`,
        // after gossip has had time to fan every member's
        // contribution out to every node, so all validators see
        // the same pool and converge on the same canonical subset.
        true
    }

    /// Audit 406: canonical-subset PSS apply, fired by the slot tick
    /// once `current_slot` crosses the aggregation trigger. Mirror of
    /// `try_aggregate_reshare_on_slot` for cross-committee resharing
    /// — picks the canonical lowest-`threshold` subset (sorted by
    /// `from_index`) and adds those zero-secret deltas to our share.
    ///
    /// Pre-fix `on_pss_contribution` applied refresh eagerly the
    /// moment the pool reached `threshold` items, which under async
    /// gossip gave every node a different "first-3-of-4" arrival set
    /// and diverged the post-PSS shares onto different polynomials.
    /// The fix mirrors cross-committee resharing exactly:
    /// `start_pss_refresh` arms a deadline + seeds the pool with our
    /// own contribution + stashes bytes for `maybe_rebroadcast_pss`,
    /// the gossip handler just buffers, and this method commits the
    /// canonical apply on the slot tick when the deadline has passed
    /// AND the pool has reached `threshold` (the rebroadcast loop
    /// fills the pool to `n` for honest committees, so all members
    /// converge on the SAME `lowest-threshold` subset).
    ///
    /// Late contributions arriving after the apply are dropped (the
    /// `pss_aggregated` gate in `on_pss_contribution`).
    pub fn try_apply_pss_on_slot(
        &mut self,
        current_slot: u64,
        identity: &mut ValidatorIdentity,
    ) -> bool {
        if self.pss_aggregated || self.pss_aggregation_trigger_slot == 0 {
            return false;
        }
        if current_slot < self.pss_aggregation_trigger_slot {
            return false;
        }
        let threshold = quorum_for_committee(self.committee_keys.len());
        if threshold == 0 {
            return false;
        }
        let canonical = match pyde_crypto::threshold::canonical_refresh_subset(
            &self.pss_contributions,
            threshold,
        ) {
            Some(c) => c,
            None => {
                warn!(
                    target_epoch = self.pss_target_epoch,
                    received = self.pss_contributions.len(),
                    threshold,
                    "PSS aggregation trigger fired but below threshold — waiting"
                );
                return false;
            }
        };
        if let Some(ref old_share) = identity.key_share {
            let pre_idx = old_share.index;
            let canon_indices: Vec<usize> = canonical.iter().map(|c| c.from_index).collect();
            let new_share = pyde_crypto::threshold::apply_refresh_canonical(old_share, &canonical);
            identity.key_share = Some(new_share);
            self.pss_contributions.clear();
            self.pss_aggregated = true;
            self.key_share_dirty = true;
            info!(
                target_epoch = self.pss_target_epoch,
                contributions = threshold,
                pre_index = pre_idx,
                canon_indices = ?canon_indices,
                "PSS key share refreshed (canonical) — genesis trust dissolved"
            );
            return true;
        }
        false
    }

    // ==================================================================
    // Task 034 — cross-committee resharing at epoch boundary
    // ==================================================================
    //
    // Flow (see `pyde_crypto::threshold` for the math):
    //
    // * `start_committee_reshare` is called by any OLD committee member
    //   (those leaving or staying) when the epoch boundary announces the
    //   new committee. Returns a contribution addressed to every new
    //   member. The node layer broadcasts it on the consensus channel.
    //
    // * `prepare_for_reshare_reception` is called by any NEW committee
    //   member when they learn the incoming committee roster. Sets
    //   `reshare_new_index` and clears the prior bucket so stale epochs
    //   don't leak.
    //
    // * `on_reshare_contribution` accepts contributions from the old
    //   committee and, once the OLD threshold is reached, Lagrange-
    //   interpolates the new member's share using the canonical subset
    //   rule. Returns `true` the first time a new share is derived.

    /// How long (in slots) an outgoing member keeps re-broadcasting their
    /// resharing contribution after the initial epoch-boundary publish.
    /// Wide enough that late-joining validators within the first few slots
    /// of the target epoch can still catch up, narrow enough to not spam
    /// the consensus channel. Re-broadcasts fire every
    /// `RESHARE_REBROADCAST_INTERVAL_SLOTS` slots.
    pub const RESHARE_REBROADCAST_SLOTS: u64 = 10;
    pub const RESHARE_REBROADCAST_INTERVAL_SLOTS: u64 = 2;

    /// Slots each new committee member waits past the epoch boundary
    /// before aggregating received contributions. During this window
    /// gossipsub delivers contributions to everyone, so all new members
    /// observe the same pool and derive identical canonical subsets.
    /// MUST be ≤ `RESHARE_REBROADCAST_SLOTS` so late joiners still get
    /// contributions during the window.
    pub const RESHARE_AGGREGATION_DELAY_SLOTS: u64 = 5;

    /// Audit 403: slots to wait between starting epoch-randomness
    /// collection and combining the buffered shares. Same idea as
    /// `RESHARE_AGGREGATION_DELAY_SLOTS` for resharing — under async
    /// gossip the order in which 4-of-N shares arrive varies per
    /// node, and finalizing on first threshold gave different nodes
    /// different "first 3" subsets, producing non-deterministic
    /// epoch randomness. Waiting this many slots lets gossipsub
    /// fan out every share to every node, so the canonical-subset
    /// combine resolves to identical bytes everywhere. 20 slots ≈ 8s
    /// at 400ms/slot — orders of magnitude over realistic 4-node
    /// localhost gossip latency, and still ~2% of an epoch so
    /// randomness lands well before the next boundary needs it.
    pub const RANDOMNESS_AGGREGATION_DELAY_SLOTS: u64 = 20;

    /// Snapshot the resharing state for disk persistence (task 034 crash
    /// safety). Returns `None` when nothing needs to be saved (engine is
    /// idle between rotations). Excludes the contribution pool — on
    /// restart within the rebroadcast window the pool rebuilds from
    /// gossip; after the window, the node stays locked out of this
    /// epoch's decryption and resumes normally on the next rotation.
    pub fn reshare_state_snapshot(&self) -> Option<crate::wire::ReshareState> {
        if self.reshare_target_epoch == 0 && self.pending_reshare_rebroadcast.is_none() {
            return None;
        }
        Some(crate::wire::ReshareState {
            target_epoch: self.reshare_target_epoch,
            new_index: self.reshare_new_index as u64,
            aggregation_trigger_slot: self.reshare_aggregation_trigger_slot,
            aggregated: self.reshare_aggregated,
            broadcast_start_slot: self.reshare_broadcast_start_slot,
            pending_rebroadcast: self.pending_reshare_rebroadcast.clone(),
            new_committee_keys: self.reshare_new_committee.clone(),
        })
    }

    /// Restore the persistent resharing fields from a disk snapshot. The
    /// contribution pool starts empty and refills from gossip rebroadcasts.
    pub fn restore_reshare_state(&mut self, s: crate::wire::ReshareState) {
        self.reshare_target_epoch = s.target_epoch;
        self.reshare_new_index = s.new_index as usize;
        self.reshare_aggregation_trigger_slot = s.aggregation_trigger_slot;
        self.reshare_aggregated = s.aggregated;
        self.reshare_broadcast_start_slot = s.broadcast_start_slot;
        self.pending_reshare_rebroadcast = s.pending_rebroadcast;
        self.reshare_new_committee = s.new_committee_keys;
        self.reshare_contributions.clear();
    }

    /// Generate a share-transfer contribution for the incoming committee.
    /// Caller is an OLD committee member. Returns `None` if we don't have
    /// a key share (e.g. not a previous committee member) or if the new
    /// committee is empty.
    pub fn start_committee_reshare(
        &mut self,
        target_epoch: u64,
        new_committee_keys: &[Vec<u8>],
        identity: &ValidatorIdentity,
    ) -> Option<ResharingContribution> {
        let key_share = identity.key_share.as_ref()?;
        let new_n = new_committee_keys.len();
        if new_n == 0 {
            return None;
        }
        let new_threshold = quorum_for_committee(new_n);

        // Private entropy: combines validator secret key with the target
        // epoch so each old member picks an independent polynomial, even
        // if two old members briefly share the same `from_old_index`
        // (shouldn't happen, but defense-in-depth).
        let mut private = Vec::with_capacity(64 + 8);
        private.extend_from_slice(identity.secret_key.as_bytes());
        private.extend_from_slice(&self.epoch_randomness);
        private.extend_from_slice(&target_epoch.to_le_bytes());
        let entropy = pyde_crypto::poseidon2::poseidon2_hash(&private);

        let contribution = generate_resharing_contribution(
            key_share,
            new_n,
            new_threshold,
            target_epoch,
            entropy.as_bytes(),
        );
        // Audit 406: seed our own reshare pool with our own
        // contribution. Pre-fix the local pool was filled SOLELY by
        // gossip arrivals from peers, so each old member's own
        // contribution never landed in its own pool. With 4-validator
        // committees and `old_threshold = 3`, that left every node
        // looking at a 3-of-4 pool — and `canonical_resharing_subset`
        // (lowest-`old_threshold` `from_old_index`) picked a DIFFERENT
        // subset on each node (each was missing the contribution from
        // its own OLD position). The aggregated new shares ended up on
        // different polynomials and threshold decryption failed every
        // time. Adding own here mirrors `start_pss_refresh` and lets
        // every old member's pool converge on the same canonical
        // {lowest old_threshold from_old_index} once gossip finishes
        // delivering the n-1 peer contributions.
        if self
            .reshare_contributions
            .iter()
            .all(|c| c.from_old_index != contribution.from_old_index)
        {
            self.reshare_contributions.push(contribution.clone());
        }
        // Stash bytes + target epoch so `maybe_rebroadcast_reshare` can
        // re-publish during the early target-epoch slot window.
        self.pending_reshare_rebroadcast = Some((target_epoch, contribution.to_bytes()));
        self.reshare_broadcast_start_slot = self.consensus.current_slot;
        self.persist_reshare_state();
        info!(
            target_epoch,
            new_n,
            new_threshold,
            from_old_index = contribution.from_old_index,
            "broadcasting cross-committee resharing contribution"
        );
        Some(contribution)
    }

    /// Install a synthetic weak-subjectivity anchor at `slot` (Phase 4
    /// slice 4.3 gap 2). Used at startup when no on-disk checkpoint
    /// exists and the operator has configured a bootstrap anchor via
    /// `config.consensus.initial_ws_checkpoint_slot`.
    ///
    /// The anchor carries empty state_root / block_hash / cert fields
    /// because they're not used by the `can_reorg` check — only the
    /// slot matters. If the operator later observes a real hard
    /// finality, the real checkpoint overwrites this synthetic one.
    ///
    /// Persisted to disk immediately so a restart after bootstrap
    /// reuses the anchor without requiring the operator to re-inject
    /// it via config.
    pub fn install_bootstrap_ws_anchor(&mut self, slot: u64) {
        use pyde_consensus::finality::{FinalityCheckpoint, HardFinalityCert};
        // Audit item 207a: persist BEFORE mutating in-memory state.
        // If the store is attached and the write fails, persist
        // panics — and we never touch `self.finality`, keeping the
        // invariant that in-memory >= on-disk.
        let cp = FinalityCheckpoint {
            slot,
            block_hash: [0u8; 32],
            state_root: [0u8; 32],
            cert: HardFinalityCert {
                slot,
                block_hash: [0u8; 32],
                state_root: [0u8; 32],
                voter_bitmap: 0,
                signatures: Vec::new(),
            },
        };
        self.persist_finality_checkpoint_direct(&cp);
        self.finality.latest_checkpoint = Some(cp);
        if self.finality.highest_hard_slot < slot {
            self.finality.highest_hard_slot = slot;
        }
    }

    /// Persist an explicit checkpoint to disk. Used by the three
    /// call sites that advance the WS anchor (bootstrap install,
    /// hard-finality vote, gossip ingest). Audit item 207a: the
    /// previous `persist_finality_checkpoint()` read from
    /// `self.finality.latest_checkpoint`, which forced callers to
    /// mutate in-memory state BEFORE disk — opening a crash window
    /// where memory said "slot N is finalized" but disk still said
    /// "slot N-1". On restart the WS anchor would revert to N-1,
    /// re-admitting long-range reorgs of N. Callers now pass the
    /// cert they're about to install and invoke this FIRST, only
    /// flipping in-memory state if the persist succeeds (panic on
    /// failure aborts before the memory mutation).
    fn persist_finality_checkpoint_direct(
        &self,
        cp: &pyde_consensus::finality::FinalityCheckpoint,
    ) {
        let Some(store) = self.consensus_store.as_ref() else {
            return;
        };
        if let Err(e) = store.save_finality_checkpoint(cp) {
            self.signal_persist_failure("finality checkpoint", &e.to_string());
        }
    }

    /// Persist whatever checkpoint is currently on `self.finality`.
    /// Kept as a convenience wrapper for non-ordering-sensitive
    /// callers (tests, and the `install_bootstrap_ws_anchor` dev-mode
    /// path which is a bootstrap-only helper). New code on the hot
    /// consensus path should use
    /// `persist_finality_checkpoint_direct` and pass the cert
    /// explicitly so the persist-before-memory invariant is visible
    /// at the call site.
    #[allow(dead_code)]
    fn persist_finality_checkpoint(&self) {
        if let Some(cp) = self.finality.latest_checkpoint.as_ref() {
            self.persist_finality_checkpoint_direct(cp);
        }
    }

    /// Fsync the reshare snapshot to the ConsensusStateStore when one is
    /// attached. No-op when there's no store (devnet/tests) or when
    /// snapshot is empty. Panics on write failure — same safety-critical
    /// contract as other consensus-state persistence.
    fn persist_reshare_state(&self) {
        let (Some(store), Some(snap)) =
            (self.consensus_store.as_ref(), self.reshare_state_snapshot())
        else {
            return;
        };
        if let Err(e) = store.save_reshare_state(&snap) {
            self.signal_persist_failure("reshare state", &e.to_string());
        }
    }

    /// Called by the node-layer slot tick. Returns the stashed resharing
    /// contribution to re-broadcast, or `None` if we're not in the window.
    /// Re-publishes every `RESHARE_REBROADCAST_INTERVAL_SLOTS` slots for up
    /// to `RESHARE_REBROADCAST_SLOTS` slots after the initial broadcast.
    /// Self-clears after the window expires.
    pub fn maybe_rebroadcast_reshare(&mut self) -> Option<(u64, Vec<u8>)> {
        let (target_epoch, bytes) = self.pending_reshare_rebroadcast.as_ref()?;
        let now = self.consensus.current_slot;
        let elapsed = now.saturating_sub(self.reshare_broadcast_start_slot);
        if elapsed > Self::RESHARE_REBROADCAST_SLOTS {
            // Window closed — purge so we don't re-broadcast a stale epoch.
            self.pending_reshare_rebroadcast = None;
            return None;
        }
        if elapsed == 0 {
            // Initial publish already happened this slot; don't re-broadcast
            // immediately (gossipsub dedupes but we avoid the extra traffic).
            return None;
        }
        if elapsed % Self::RESHARE_REBROADCAST_INTERVAL_SLOTS != 0 {
            return None;
        }
        Some((*target_epoch, bytes.clone()))
    }

    /// Install the incoming committee roster + our 1-based index in it so
    /// future resharing contributions can be collected. Safe to call even
    /// if we're not in the new committee (`our_new_index` = 0) — we'll
    /// ignore received contributions in that case.
    ///
    /// Sets the aggregation trigger to fire `RESHARE_AGGREGATION_DELAY_SLOTS`
    /// slots after the current slot. Aggregation itself happens in
    /// `try_aggregate_reshare_on_slot`, which the node slot tick drives.
    pub fn prepare_for_reshare_reception(
        &mut self,
        target_epoch: u64,
        new_committee_keys: Vec<Vec<u8>>,
        our_new_index: usize,
    ) {
        self.reshare_target_epoch = target_epoch;
        self.reshare_new_committee = new_committee_keys;
        self.reshare_new_index = our_new_index;
        self.reshare_contributions.clear();
        self.reshare_aggregation_trigger_slot =
            self.consensus.current_slot + Self::RESHARE_AGGREGATION_DELAY_SLOTS;
        self.reshare_aggregated = false;
        self.persist_reshare_state();
        debug!(
            target_epoch,
            our_new_index,
            trigger_slot = self.reshare_aggregation_trigger_slot,
            "prepared resharing reception bucket"
        );
    }

    /// Store an incoming resharing contribution in the pool. Does NOT
    /// aggregate — that's `try_aggregate_reshare_on_slot`'s job, fired at
    /// a deterministic trigger slot so all new members see the same
    /// contribution pool before combining.
    ///
    /// Returns `true` if the contribution was newly accepted (not a
    /// duplicate, not stale, not malformed). Return value is for
    /// telemetry; the caller can ignore it.
    pub fn on_reshare_contribution(
        &mut self,
        contribution: ResharingContribution,
        _old_committee_size: usize,
        _identity: &mut ValidatorIdentity,
    ) -> bool {
        // Silently drop: not a new committee member.
        if self.reshare_new_index == 0 || self.reshare_new_committee.is_empty() {
            return false;
        }
        if self.reshare_aggregated {
            // Already aggregated this epoch; late arrivals are ignored.
            return false;
        }
        let new_n = self.reshare_new_committee.len();
        let new_threshold = quorum_for_committee(new_n);

        // Verify structural consistency of the contribution.
        if !verify_resharing_contribution(&contribution, new_threshold, new_n) {
            warn!(
                from_old_index = contribution.from_old_index,
                "invalid resharing contribution (failed polynomial check)"
            );
            return false;
        }

        // Dedupe by old-index so a re-broadcast doesn't inflate our pool.
        if self
            .reshare_contributions
            .iter()
            .any(|c| c.from_old_index == contribution.from_old_index)
        {
            return false;
        }
        self.reshare_contributions.push(contribution);
        true
    }

    /// Called from the node slot tick. If the current slot is at or past
    /// the aggregation trigger and we haven't aggregated yet, attempt to
    /// derive our new share from the canonical subset of the contribution
    /// pool. Returns `true` when a new `KeyShare` is derived and installed.
    ///
    /// Failure modes:
    /// - Not a new committee member → returns false silently.
    /// - Not enough contributions (< `old_threshold`) by the trigger →
    ///   logs a warning and returns false. The engine stays "unaggregated"
    ///   so subsequent slots will retry, which accommodates genuinely
    ///   delayed contributions; but if too many old members went dark,
    ///   this node is effectively locked out of threshold decryption for
    ///   this epoch until they can resync.
    pub fn try_aggregate_reshare_on_slot(
        &mut self,
        current_slot: u64,
        old_committee_size: usize,
        identity: &mut ValidatorIdentity,
    ) -> bool {
        if self.reshare_aggregated
            || self.reshare_new_index == 0
            || self.reshare_new_committee.is_empty()
            || self.reshare_aggregation_trigger_slot == 0
        {
            return false;
        }
        if current_slot < self.reshare_aggregation_trigger_slot {
            return false;
        }
        let old_threshold = quorum_for_committee(old_committee_size);
        if old_threshold == 0 {
            return false;
        }
        if self.reshare_contributions.len() < old_threshold {
            warn!(
                target_epoch = self.reshare_target_epoch,
                received = self.reshare_contributions.len(),
                old_threshold,
                "resharing aggregation trigger fired but below threshold — waiting"
            );
            return false;
        }
        let canonical = match canonical_resharing_subset(&self.reshare_contributions, old_threshold)
        {
            Some(c) => c,
            None => return false,
        };
        let new_share = match aggregate_new_share(self.reshare_new_index, &canonical) {
            Some(s) => s,
            None => return false,
        };

        let post_idx = new_share.index;
        let canon_old_indices: Vec<usize> = canonical.iter().map(|c| c.from_old_index).collect();
        identity.key_share = Some(new_share);
        self.key_share_dirty = true;
        self.reshare_aggregated = true;
        self.reshare_contributions.clear();
        self.persist_reshare_state();
        info!(
            target_epoch = self.reshare_target_epoch,
            new_index = self.reshare_new_index,
            old_threshold,
            post_index = post_idx,
            canon_old_indices = ?canon_old_indices,
            "committee handoff complete — new key share derived from resharing"
        );
        true
    }

    /// Expose the target epoch of any pending resharing (for node-layer
    /// stale-message filtering).
    pub fn reshare_target(&self) -> u64 {
        self.reshare_target_epoch
    }

    /// Audit 406: expose the target epoch of any pending PSS refresh
    /// for node-layer stale-message filtering. Mirror of
    /// `reshare_target` — drops gossip from old epochs that would
    /// otherwise pollute the canonical-subset apply.
    pub fn pss_target(&self) -> u64 {
        self.pss_target_epoch
    }

    pub fn start_epoch_randomness(
        &mut self,
        next_epoch: u64,
        identity: &ValidatorIdentity,
    ) -> Option<RandomnessShare> {
        let share = generate_share(
            &identity.public_key,
            &identity.secret_key,
            next_epoch,
            identity.committee_index,
            identity.address,
        )
        .ok()?;

        // Audit 322: pass the active committee size so the
        // collector's threshold is `randomness_threshold_for(N)`
        // instead of the hardcoded 85. Without this, devnet /
        // testnet committees < 85 could never finalize epoch
        // randomness.
        let mut collector = RandomnessCollector::new(next_epoch, self.committee_keys.len());
        collector.add_share(share.clone());
        self.randomness_collector = Some(collector);

        // Audit 403: arm the deadline gate. `try_finalize_randomness_on_slot`
        // will refuse to combine until the slot tick crosses this trigger,
        // giving gossipsub time to deliver every member's share to every
        // node before any node finalizes. Without this delay, finalize-
        // on-first-threshold raced gossip and produced split-brain
        // randomness across the committee.
        self.randomness_aggregation_trigger_slot =
            self.consensus.current_slot + Self::RANDOMNESS_AGGREGATION_DELAY_SLOTS;

        info!(epoch = next_epoch, "started epoch randomness collection");
        Some(share)
    }

    /// Audit 403: receive a randomness share. Buffers it in the
    /// collector after verifying the FALCON proof — does NOT finalize.
    /// Finalization happens deterministically in
    /// `try_finalize_randomness_on_slot` once the deadline arrives.
    /// Returns `true` if the share was new and accepted.
    pub fn on_randomness_share(&mut self, share: RandomnessShare) -> bool {
        let collector = match self.randomness_collector.as_mut() {
            Some(c) => c,
            None => return false,
        };

        // Verify share against committee key
        let idx = share.validator_index as usize;
        if idx >= self.committee_keys.len() {
            return false;
        }
        let pk = match pyde_crypto::falcon::FalconPublicKey::from_bytes(&self.committee_keys[idx]) {
            Some(pk) => pk,
            None => return false,
        };
        if !verify_share(&share, &pk, collector.epoch) {
            warn!(
                epoch = collector.epoch,
                validator = idx,
                "invalid randomness share"
            );
            return false;
        }

        collector.add_share(share)
    }

    /// Audit 403: deterministically finalize the buffered randomness.
    /// Driven by the node slot tick. Two firing conditions:
    ///
    ///   (a) we've collected a share from EVERY committee member —
    ///       gossip has converged, no need to wait further.
    ///   (b) the slot tick has crossed the deadline trigger AND we
    ///       have at least the dynamic threshold — gossip may not
    ///       have fully converged but we have enough to combine,
    ///       and waiting longer risks the next boundary overtaking
    ///       this one.
    ///
    /// Both paths run the canonical-subset combine
    /// (`combine_shares_with_threshold`), which selects the lowest
    /// `threshold` shares by `validator_index`. So provided every
    /// honest node has the canonical members' shares (case (a) is
    /// trivially this; case (b) requires gossip convergence by the
    /// trigger slot, which is the design contract), every node
    /// produces identical bytes.
    ///
    /// Returns `Some(randomness)` exactly once per collector — once
    /// finalized, the collector is cleared.
    pub fn try_finalize_randomness_on_slot(&mut self, current_slot: u64) -> Option<[u8; 32]> {
        let collector = self.randomness_collector.as_ref()?;
        let n = self.committee_keys.len();
        let threshold = quorum_for_committee(n);

        let ready = collector.has_full_set()
            || (current_slot >= self.randomness_aggregation_trigger_slot
                && collector.share_count() >= threshold);
        if !ready {
            return None;
        }

        let result = collector.finalize()?;
        info!(
            epoch = result.epoch,
            shares = result.share_count,
            "epoch randomness combined (audit 403)"
        );

        // Audit 402: buffer for the NEXT epoch boundary — the swap
        // into `self.epoch_randomness` happens atomically inside
        // `rotate_to_epoch` so any single epoch's VRF inputs stay
        // constant from first slot to last.
        self.next_epoch_randomness = Some(result.randomness);
        self.randomness_collector = None;
        Some(result.randomness)
    }

    /// Compute VRF candidacy for the current slot.
    /// Only propose if VRF score is below threshold (targets ~1 proposer per slot).
    /// Threshold = U64::MAX / committee_size. With N validators, on average 1 score
    /// falls below this threshold per slot. If 0 qualify → timeout/view change.
    /// If 2+ qualify → proposal buffering picks the lowest score.
    pub fn check_proposer(&self, identity: &ValidatorIdentity) -> Option<ProposerCandidate> {
        let slot = self.consensus.current_slot;
        let committee_size = self.committee_keys.len();

        // Audit 402: same boundary-aware lookup as the verify path.
        // Pre-fix this used `self.epoch_randomness` directly, which
        // could be a stale value (the buffered next-epoch randomness
        // hadn't been swapped in yet) or the wrong epoch's value.
        // Result: proposers generated VRF proofs against a different
        // randomness than verifiers used → every VRF check failed
        // → view-change fallback fired every 20-50 slots → chain
        // ran at ~25% throughput post-boundary. Routing through
        // `epoch_randomness_for_slot(slot)` makes generator and
        // verifier agree on the same input.
        let randomness = self.epoch_randomness_for_slot(slot);
        match compute_candidacy(
            &identity.public_key,
            &identity.secret_key,
            &randomness,
            slot,
            identity.address,
        ) {
            Ok(candidate) => {
                // VRF threshold: only propose if score < threshold.
                // Audit 323: shared formula in
                // `pyde_consensus::proposer::vrf_proposer_threshold`
                // so the receive path (`validate_network_block`)
                // applies the same gate.
                let threshold = pyde_consensus::proposer::vrf_proposer_threshold(committee_size);

                if candidate.score > threshold {
                    debug!(
                        slot,
                        score = candidate.score,
                        threshold,
                        "VRF score above threshold, not proposing"
                    );
                    return None;
                }

                debug!(
                    slot,
                    score = candidate.score,
                    threshold,
                    "proposing (below VRF threshold)"
                );
                Some(candidate)
            }
            Err(e) => {
                warn!(slot, error = e, "VRF candidacy failed");
                None
            }
        }
    }

    /// Buffer a received proposal. Verifies the VRF proof against the proposer's
    /// committee key. Invalid proofs are rejected.
    ///
    /// The header.vrf_proof field is encoded as [vrf_output:32 || vrf_proof:N].
    pub fn buffer_proposal(&mut self, header: &BlockHeader, proposer_signature: &[u8]) -> bool {
        let slot = header.slot;

        // View-aware late-proposal dedup (audit-94). Voting at view 0
        // (happy path) does not block buffering a fallback recovery
        // proposal at view ≥1 — splitting view-0 votes across the
        // committee is exactly the case the recovery exists for.
        let proposal_view = pyde_consensus::view_change::decode_fallback_proof(&header.vrf_proof)
            .map(|(_, v)| v)
            .unwrap_or(0);
        if let Some(&voted_view) = self.voted_view_per_slot.get(&slot) {
            if proposal_view <= voted_view {
                debug!(
                    slot,
                    proposal_view,
                    voted_view,
                    "ignoring late proposal (already voted at this or higher view)"
                );
                return false;
            }
        }

        // Audit 234 part 3: fallback proposals (built by the
        // deterministic fallback proposer after a view-change-QC
        // forms) carry a marker in vrf_proof instead of VRF data.
        // Validate the proposer against our local view-change-QC
        // rather than running VRF verification.
        if pyde_consensus::view_change::is_fallback_proof(&header.vrf_proof) {
            return self.buffer_fallback_proposal(header, proposer_signature);
        }

        // VRF data must be at least 32 bytes (output) + some proof bytes
        if header.vrf_proof.len() < 33 {
            warn!(slot, "proposal has missing or truncated VRF data");
            return false;
        }

        // Split [output:32 || proof:N]
        let vrf_output_bytes = &header.vrf_proof[..32];
        let vrf_proof_bytes = &header.vrf_proof[32..];

        // Find proposer's committee index by matching address
        let proposer_idx = self.committee_keys.iter().position(|k| {
            let addr = pyde_account::address::derive_eoa_address(k);
            addr == header.proposer
        });
        let proposer_idx = match proposer_idx {
            Some(idx) => idx,
            None => {
                warn!(
                    slot,
                    proposer = hex::encode(header.proposer),
                    "proposal from non-committee member"
                );
                return false;
            }
        };

        // Reconstruct proposer's public key
        let pk = match pyde_crypto::falcon::FalconPublicKey::from_bytes(
            &self.committee_keys[proposer_idx],
        ) {
            Some(pk) => pk,
            None => {
                warn!(slot, "invalid committee public key");
                return false;
            }
        };

        // Verify proposer signature on block header.
        // Proposers sign `slot || block_hash` (same canonical layout as
        // votes) so a sig at slot N cannot be replayed for a block at slot M.
        if !proposer_signature.is_empty() {
            let block_hash = header.hash();
            let sig = match pyde_crypto::falcon::FalconSignature::from_bytes(proposer_signature) {
                Some(s) => s,
                None => {
                    warn!(slot, "invalid proposer signature format");
                    return false;
                }
            };
            let sign_msg = proposer_sign_message(self.chain_id, slot, &block_hash);
            if !pyde_crypto::falcon::falcon_verify(&pk, &sign_msg, &sig) {
                warn!(slot, "proposer signature verification failed");
                return false;
            }
        } else {
            warn!(slot, "proposal missing proposer signature");
            return false;
        }
        // TPL-306: `from_hash_bytes` is Option-returning. The
        // `vrf_output_bytes` slice is taken from
        // `&header.vrf_proof[..32]` after a `len() >= 33` gate
        // higher up, so the input is always exactly 32 bytes —
        // `None` here would indicate a refactor that loosened
        // the gate without updating this site, which we'd rather
        // notice loudly.
        let vrf_output = match pyde_crypto::vrf::VrfOutput::from_hash_bytes(vrf_output_bytes) {
            Some(o) => o,
            None => {
                warn!(slot, "vrf output bytes are not 32 bytes");
                return false;
            }
        };
        let vrf_proof = VrfProof::from_bytes(vrf_proof_bytes);

        // Build VRF input: epoch_randomness || slot.
        //
        // Audit 402: use the randomness that was active at THIS
        // slot's epoch, not the validator's `self.epoch_randomness`
        // (which may have been overwritten by the boundary handler
        // between proposal generation and proposal verification on
        // the same node). At an epoch boundary this returns the
        // prior epoch's randomness for the last slot of that epoch
        // and the new epoch's randomness for the first slot of the
        // new epoch — same lookup the proposer makes.
        let slot_randomness = self.epoch_randomness_for_slot(slot);
        let mut vrf_input = Vec::with_capacity(40);
        vrf_input.extend_from_slice(&slot_randomness);
        vrf_input.extend_from_slice(&slot.to_le_bytes());

        // Verify VRF proof
        if !pyde_crypto::vrf::vrf_verify(&pk, &vrf_input, &vrf_output, &vrf_proof) {
            warn!(slot, "invalid VRF proof from proposer");
            return false;
        }

        // Score = first 8 bytes of VRF output (LE u64)
        let vrf_score = {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&vrf_output_bytes[..8]);
            u64::from_le_bytes(buf)
        };

        // --- Double-propose detection ---
        let proposal_key = (slot, header.proposer);
        if let Some((prev_header, prev_sig)) = self.seen_proposals.get(&proposal_key) {
            // Same proposer for same slot — check if it's a different block
            if prev_header.hash() != header.hash() {
                warn!(
                    slot,
                    proposer = hex::encode(header.proposer),
                    "DOUBLE PROPOSE DETECTED — slashing"
                );
                let evidence = DoubleSignEvidence {
                    slot,
                    block_hash_1: prev_header.hash(),
                    signature_1: prev_sig.clone(),
                    block_hash_2: header.hash(),
                    signature_2: proposer_signature.to_vec(),
                    signer: header.proposer,
                    // submitter is filled in by whoever actually broadcasts
                    // the Slash tx — typically the next block proposer.
                    submitter: [0u8; 32],
                };
                // Route through ingest_evidence: validates both sigs,
                // dedupes on (slot, signer), and also stages the entry
                // for P2P broadcast so other validators can slash even
                // if they never directly observed the equivocation.
                if self.ingest_evidence(evidence) {
                    info!(
                        slot,
                        offender = hex::encode(header.proposer),
                        "double-propose evidence queued for slashing"
                    );
                }
            }
        } else {
            // Persist BEFORE the in-memory insert so a crash between the two
            // leaves the in-memory state recoverable from disk.
            //
            // Panics on persist failure: losing the seen-proposal index
            // silently disables equivocation detection for this slot,
            // and a validator that cannot detect its own double-proposes
            // is worse than one that halts visibly.
            if let Some(store) = &self.consensus_store {
                if let Err(e) =
                    store.save_seen_proposal(slot, &header.proposer, header, proposer_signature)
                {
                    self.signal_persist_failure("seen-proposal", &e.to_string());
                }
            }
            self.seen_proposals
                .insert(proposal_key, (header.clone(), proposer_signature.to_vec()));
        }

        // Mark proposal received for timeout tracker
        if slot == self.timeout.slot {
            self.timeout.receive_proposal();
        }

        let entry = self.buffered_proposals.entry(slot).or_default();
        entry.push(BufferedProposal {
            header: header.clone(),
            proposer_signature: proposer_signature.to_vec(),
            vrf_score,
        });

        debug!(
            slot,
            vrf_score,
            proposals = entry.len(),
            "proposal buffered"
        );
        true
    }

    /// Audit 234 part 4 step 7n: lookup the buffered proposal whose
    /// header hashes to `block_hash`. Used by the slot tick after a
    /// vote-QC forms locally — peer needs to APPLY the block, but
    /// the body comes via gossip on the Blocks topic which is the
    /// degraded path under churn. For empty blocks (fallback or no
    /// txs), the caller can synthesize the body locally and apply
    /// without waiting for the gossip-delivered full block.
    pub fn buffered_proposal_for(
        &self,
        slot: u64,
        block_hash: &[u8; 32],
    ) -> Option<(BlockHeader, Vec<u8>)> {
        self.buffered_proposals
            .get(&slot)?
            .iter()
            .find(|p| p.header.hash() == *block_hash)
            .map(|p| (p.header.clone(), p.proposer_signature.clone()))
    }

    /// audit-94: resolve the view a buffered proposal was produced
    /// at by decoding `vrf_proof`. Used by `on_vote`'s equivocation
    /// detection to distinguish a legit cross-view re-vote (view
    /// 0 happy-path → view 1 fallback recovery) from a genuine
    /// same-view double-vote that warrants slashing.
    ///
    /// Returns `None` when no buffered proposal at this slot
    /// matches the hash — caller defensively treats unknown views
    /// as the same view, preserving the safety property of the
    /// pre-audit-94 slashing path under partial buffer state.
    fn view_for_block_hash(&self, slot: u64, block_hash: &[u8; 32]) -> Option<u64> {
        self.buffered_proposals
            .get(&slot)?
            .iter()
            .find(|p| p.header.hash() == *block_hash)
            .map(|p| {
                pyde_consensus::view_change::decode_fallback_proof(&p.header.vrf_proof)
                    .map(|(_, v)| v)
                    .unwrap_or(0)
            })
    }

    /// Flag a slot as having failed the mandatory-inclusion audit (task 026).
    /// Caller is the compact-block reception path in node.rs. A flagged slot
    /// causes `select_and_vote` to skip its vote for this proposal, whatever
    /// the VRF selection picks.
    pub fn flag_inclusion_violation(&mut self, slot: u64) {
        self.inclusion_violated_slots.insert(slot);
    }

    /// True when a slot was flagged via `flag_inclusion_violation`.
    /// Exposed for tests.
    #[allow(dead_code)]
    pub fn is_inclusion_violated(&self, slot: u64) -> bool {
        self.inclusion_violated_slots.contains(&slot)
    }

    /// Select the best proposal (lowest VRF score) and vote for it.
    /// Called after the proposal collection window (100ms into the slot).
    /// Returns the vote to broadcast, or None if no proposals were buffered.
    ///
    /// audit-234 part 4 (CONSENSUS_INVARIANTS.md L1, O3): the slot used
    /// to look up buffered proposals is `target_height`, NOT
    /// `current_slot`. Both `try_build_fallback_proposal` and
    /// `buffer_fallback_proposal` key on the proposer's
    /// `target_height` (fallback header.slot = target_height), so a
    /// receiver whose wall-clock advanced past `target_height`
    /// during recovery (recovery > SLOT_DURATION_MS) would otherwise
    /// look for proposals at `current_slot` and never find the
    /// fallback that was buffered at `target_height`. The validator
    /// then refused to vote on every fallback proposal until the
    /// chain unstuck itself, prolonging the wedge. The two
    /// `advance_target_height` callers (vote-QC apply path,
    /// `advance_target_height_after_sync` from chain-sync) keep
    /// `target_height` correctly aligned with the height we are
    /// actively trying to commit.
    pub fn select_and_vote(&mut self, identity: &ValidatorIdentity) -> Option<ConsensusMessage> {
        let slot = self.consensus.target_height;
        let current_view = self.consensus.current_view;

        // View-aware double-vote dedup (audit-94). Re-open the gate
        // when a view-change-QC has bumped current_view past what we
        // last voted at, so the fallback recovery proposal becomes
        // votable.
        if let Some(&voted_view) = self.voted_view_per_slot.get(&slot) {
            if voted_view >= current_view {
                return None;
            }
        }

        // Task 026 — skip vote if the local inclusion audit flagged this slot.
        // The flag is set by the compact-block reception path when encrypted
        // txs the validator has held past the grace window are missing from
        // the proposal while gas budget remained.
        if self.inclusion_violated_slots.contains(&slot) {
            warn!(slot, "skipping vote: mandatory-inclusion audit failed");
            // Mark voted at MAX view so a later arriving compact block that
            // clears the flag — even at a higher view — doesn't cause us to
            // belatedly cast a vote. The decision is final for this slot.
            self.voted_view_per_slot.insert(slot, u64::MAX);
            return None;
        }

        // View-aware proposal selection. After a VC QC bumps
        // current_view, only proposals at the current view are
        // legitimate candidates: a stale view-0 happy-path proposal
        // sitting in the buffer would otherwise win min-by-vrf-score
        // (raw VRF bytes can be smaller than fallback's
        // committee_index) and pull us back into voting on the
        // wrong view. Filter buffered proposals to those whose
        // encoded view matches `current_view`.
        let proposals = self.buffered_proposals.get(&slot)?;
        if proposals.is_empty() {
            return None;
        }
        let best = proposals
            .iter()
            .filter(|p| {
                let v = pyde_consensus::view_change::decode_fallback_proof(&p.header.vrf_proof)
                    .map(|(_, v)| v)
                    .unwrap_or(0);
                v == current_view
            })
            .min_by_key(|p| p.vrf_score)?;
        let best_header = best.header.clone();
        let best_score = best.vrf_score;
        let best_proposer = best.header.proposer;

        info!(
            slot,
            current_view,
            vrf_score = best_score,
            proposer = hex::encode(best_proposer),
            "selected best proposal"
        );

        // Vote for the best proposal. The view we record matches
        // the proposal's encoded view (= current_view, by filter).
        let vote = self.on_proposal(&best_header, identity);
        if vote.is_some() {
            self.voted_view_per_slot
                .entry(slot)
                .and_modify(|v| {
                    if current_view > *v {
                        *v = current_view;
                    }
                })
                .or_insert(current_view);
        }
        vote
    }

    /// Validate + buffer a fallback proposal (audit 234 part 3).
    /// Uses the local view-change-QC rather than VRF for proposer
    /// authority. Returns true iff the proposal was buffered.
    fn buffer_fallback_proposal(
        &mut self,
        header: &BlockHeader,
        proposer_signature: &[u8],
    ) -> bool {
        let slot = header.slot;

        // Local view-change-QC for this slot is required to
        // recognize the legitimate fallback proposer. Without it,
        // we have no way to validate the proposal; reject and let
        // our own view-change-QC formation catch up.
        if self.timeout.slot != slot || self.timeout.view_change_qc.is_none() {
            debug!(
                slot,
                "fallback proposal received without local view-change-QC; deferring"
            );
            return false;
        }
        let vc_qc = self.timeout.view_change_qc.as_ref().unwrap();

        // Verify the proposer is a committee member.
        let proposer_idx = match self
            .committee_keys
            .iter()
            .position(|k| pyde_account::address::derive_eoa_address(k) == header.proposer)
        {
            Some(i) => i,
            None => {
                warn!(
                    slot,
                    proposer = hex::encode(header.proposer),
                    "fallback proposal from non-committee member"
                );
                return false;
            }
        };
        let _ = vc_qc;

        // audit-234 part 4 (CONSENSUS_INVARIANTS.md L2): the proposer
        // MUST be the deterministic leader for the view encoded in
        // the proposal's fallback proof. The view comes from the
        // proof, not from the receiver's local `current_view`,
        // because honest validators may be ahead/behind on view
        // bumps under partial connectivity. Computing the leader
        // against the proposer-asserted view lets a receiver accept
        // a valid fallback for a view it hasn't installed yet
        // (it'll catch up when more VC messages arrive); rejecting
        // mismatches still blocks attacker-built proposals at the
        // wrong index.
        let (proof_slot, proof_view) =
            match pyde_consensus::view_change::decode_fallback_proof(&header.vrf_proof) {
                Some(decoded) => decoded,
                None => {
                    warn!(slot, "fallback proposal has malformed fallback proof");
                    return false;
                }
            };
        if proof_slot != slot {
            warn!(
                slot,
                proof_slot, "fallback proposal: proof slot does not match header slot"
            );
            return false;
        }
        let expected_leader = pyde_consensus::view_change::fallback_leader_index(
            slot,
            proof_view,
            self.committee_keys.len(),
        );
        if proposer_idx != expected_leader {
            warn!(
                slot,
                view = proof_view,
                proposer = proposer_idx,
                expected = expected_leader,
                "fallback proposal: proposer is not the deterministic leader for this view"
            );
            return false;
        }

        // Verify proposer signature on the block header (same
        // canonical message format as the regular path).
        if proposer_signature.is_empty() {
            warn!(slot, "fallback proposal missing proposer signature");
            return false;
        }
        let pk = match pyde_crypto::falcon::FalconPublicKey::from_bytes(
            &self.committee_keys[proposer_idx],
        ) {
            Some(pk) => pk,
            None => {
                warn!(slot, "fallback proposer pk decode failed");
                return false;
            }
        };
        let sig = match pyde_crypto::falcon::FalconSignature::from_bytes(proposer_signature) {
            Some(s) => s,
            None => {
                warn!(slot, "fallback proposer signature decode failed");
                return false;
            }
        };
        let block_hash = header.hash();
        let sign_msg = proposer_sign_message(self.chain_id, slot, &block_hash);
        if !pyde_crypto::falcon::falcon_verify(&pk, &sign_msg, &sig) {
            warn!(slot, "fallback proposer signature verification failed");
            return false;
        }

        // Buffer with vrf_score = committee_index. When multiple
        // alive validators each broadcast a fallback proposal,
        // receivers' existing min-by-vrf_score selection picks the
        // lowest committee_index — deterministic across all
        // receivers without requiring identical view-change-QC
        // bitmaps. Real proposals (if they arrive) have full
        // 64-bit VRF scores from a hash, so a u8 committee_index
        // never beats a real proposal in the rare race.
        let entry = self.buffered_proposals.entry(slot).or_default();
        entry.push(BufferedProposal {
            header: header.clone(),
            proposer_signature: proposer_signature.to_vec(),
            vrf_score: proposer_idx as u64,
        });
        info!(slot, proposer_idx, "buffered fallback proposal");
        true
    }

    /// If a view-change-QC has formed for the current slot AND we
    /// are the deterministic fallback proposer (audit 234 part 3),
    /// build the empty fallback block and return it for broadcast.
    /// Otherwise returns None.
    pub fn try_build_fallback_proposal(
        &mut self,
        identity: &ValidatorIdentity,
        parent_hash: [u8; 32],
        state_root: [u8; 32],
    ) -> Option<Block> {
        // audit-234 part 4 (CONSENSUS_INVARIANTS.md L1, O3): fallback
        // proposals target `target_height`, not `current_slot`.
        // Wall-clock drift during recovery would otherwise cause the
        // fallback to be built for a slot the chain has already moved
        // past.
        let slot = self.consensus.target_height;
        info!(
            mine = identity.committee_index,
            target_height = slot,
            current_slot = self.consensus.current_slot,
            "DBG try_build_fallback_proposal entered"
        );
        // NOTE: previously voting for slot does NOT disqualify us from
        // being the fallback proposer (audit 234 part 3). The whole
        // reason a view-change-QC exists at this slot is that the
        // earlier vote-QC failed to reach quorum — we need a fresh
        // proposal to break the wedge. The voted-slot dedup matters
        // only against double-voting on the SAME proposal, which is
        // enforced by HotStuff safety in `create_vote`.
        if self.timeout.slot != slot {
            info!(
                slot,
                timeout_slot = self.timeout.slot,
                "DBG fallback skip: timeout.slot != target_height"
            );
            return None;
        }
        self.timeout.view_change_qc.as_ref()?;
        // audit-234 part 4 (CONSENSUS_INVARIANTS.md L2): only the
        // deterministic leader for `(target_height, current_view)`
        // builds a fallback. Other validators return None. This
        // collapses the multi-proposer fallback that was splitting
        // votes under asymmetric gossip delivery — every honest
        // receiver computes the same `fallback_leader_index`
        // independently of which view-change messages it observed,
        // so the only candidate proposal carries a single committee
        // index that all receivers agree on.
        let view = self.consensus.current_view;
        let leader_idx = pyde_consensus::view_change::fallback_leader_index(
            slot,
            view,
            self.committee_keys.len(),
        );
        if (identity.committee_index as usize) != leader_idx {
            debug!(
                slot,
                view,
                mine = identity.committee_index,
                leader = leader_idx,
                "fallback skip: not the deterministic leader for this view"
            );
            return None;
        }
        info!(
            slot,
            view,
            mine = identity.committee_index,
            "DBG fallback: I am the deterministic leader for (target_height, current_view); building"
        );
        // audit-94: proposer-side build dedup. Both the gossip-VC and
        // the RR-VC paths can independently trigger this builder
        // within the same view-change-QC formation window — without
        // this gate, we build TWO fallback proposals at the same
        // `(slot, view)`. Each carries `timestamp = now_ms()` so
        // their `block_hash`es differ. Peers receive both, vote-split
        // 1+1+1 across the two block_hashes, and the vote-QC never
        // reaches quorum even though three legitimate votes were
        // cast. The chain wedges at the very slot the fallback was
        // supposed to recover. Witness: diag stall, slot 1, two
        // back-to-back "built fallback proposal" logs ~1.4ms apart,
        // zero subsequent "QC formed" until the test panics.
        //
        // The `buffered_proposals`-based dedup just below is a
        // separate guard against happy-path proposal interference;
        // it can't catch this one because the proposer deliberately
        // omits its own fallback from `buffered_proposals`.
        if let Some(&built_view) = self.last_built_fallback_view_per_slot.get(&slot) {
            if built_view >= view {
                info!(
                    slot,
                    view,
                    built_view,
                    "fallback skip: already built fallback at this view"
                );
                return None;
            }
        }
        // Don't double-build at the SAME (slot, view) via the
        // buffered-proposals path either: a happy-path (view-0)
        // proposal from this node MUST NOT block building a
        // higher-view fallback recovery proposal — that's exactly
        // the case the view change exists to recover from. Only skip
        // if a fallback proposal from this node at THIS exact view
        // is already buffered (e.g. via a gossip-echo round-trip).
        if self.buffered_proposals.get(&slot).is_some_and(|v| {
            v.iter().any(|p| {
                p.header.proposer == identity.address
                    && pyde_consensus::view_change::decode_fallback_proof(&p.header.vrf_proof)
                        .is_some_and(|(_, v)| v == view)
            })
        }) {
            return None;
        }

        let vrf_proof = pyde_consensus::view_change::encode_fallback_proof(slot, view);
        let header = BlockHeader {
            slot,
            epoch: slot / EPOCH_LENGTH,
            parent_hash,
            proposer: identity.address,
            vrf_proof,
            qc_previous: self.consensus.highest_qc.clone(),
            tx_root: [0u8; 32],
            state_root,
            timestamp: current_time_ms(),
        };

        let block_hash = header.hash();
        let sign_msg = proposer_sign_message(self.chain_id, slot, &block_hash);
        let proposer_signature =
            match pyde_crypto::falcon::falcon_sign(&identity.secret_key, &sign_msg) {
                Ok(sig) => sig.to_vec(),
                Err(_) => {
                    warn!(slot, "failed to sign fallback proposal");
                    return None;
                }
            };

        info!(
            slot,
            view,
            "built fallback proposal as deterministic view-change fallback proposer"
        );
        // Record the (slot, view) build so the second trigger from
        // the dual gossip+RR view-change-QC path bails out instead
        // of producing a second timestamped block_hash.
        self.last_built_fallback_view_per_slot
            .entry(slot)
            .and_modify(|v| {
                if view > *v {
                    *v = view;
                }
            })
            .or_insert(view);
        Some(Block {
            header,
            body: BlockBody {
                transactions: vec![],
                encrypted_txs: vec![],
                execution_schedule: ExecutionSchedule {
                    groups: vec![],
                    total_txs: 0,
                },
            },
            proposer_signature,
        })
    }

    /// Build a block proposal for the current slot.
    /// Called when this validator is the proposer.
    pub fn build_proposal(
        &self,
        identity: &ValidatorIdentity,
        parent_hash: [u8; 32],
        state_root: [u8; 32],
        tx_root: [u8; 32],
        vrf_proof: Vec<u8>,
        transactions: Vec<pyde_tx::types::Transaction>,
        encrypted_txs: Vec<Vec<u8>>,
        execution_schedule: ExecutionSchedule,
    ) -> Block {
        let slot = self.consensus.current_slot;
        let epoch = slot / EPOCH_LENGTH;

        let header = BlockHeader {
            slot,
            epoch,
            parent_hash,
            proposer: identity.address,
            vrf_proof,
            qc_previous: self.consensus.highest_qc.clone(),
            tx_root,
            state_root,
            timestamp: current_time_ms(),
        };

        // Sign the canonical (chain_id || slot || block_hash) message
        // with the proposer's FALCON key. See proposer_sign_message
        // for the format.
        let block_hash = header.hash();
        let sign_msg = proposer_sign_message(self.chain_id, header.slot, &block_hash);
        let proposer_signature =
            match pyde_crypto::falcon::falcon_sign(&identity.secret_key, &sign_msg) {
                Ok(sig) => sig.to_vec(),
                Err(_) => {
                    warn!(slot, "failed to sign block header");
                    vec![]
                }
            };

        Block {
            header,
            body: BlockBody {
                transactions,
                encrypted_txs,
                execution_schedule,
            },
            proposer_signature,
        }
    }

    /// Handle an incoming proposal: validate and vote if valid.
    /// Returns the vote message to broadcast, or None.
    pub fn on_proposal(
        &mut self,
        header: &BlockHeader,
        identity: &ValidatorIdentity,
    ) -> Option<ConsensusMessage> {
        let slot = header.slot;

        // Mark proposal received for timeout tracker
        if slot == self.timeout.slot {
            self.timeout.receive_proposal();
        }

        // Create vote (HotStuff safety rules enforced inside create_vote).
        // Audit 311: pass committee_keys so create_vote can verify the
        // FALCON signatures inside `header.qc_previous` before
        // promoting it into our HotStuff `highest_qc`.
        //
        // Audit 402: at an epoch boundary the qc_previous in this
        // proposal was signed by the OUTGOING committee (whose last
        // slot it covers). Look up the keys that were active at
        // `qc_previous.slot`'s epoch — the prior-epoch cache holds
        // them for one slot past the rotation, exactly the window
        // we need for the boundary block. Clone to break the
        // simultaneous immutable-borrow-of-self + mutable-borrow-
        // of-self.consensus that `create_vote` requires.
        let qc_keys: Vec<Vec<u8>> = self
            .committee_keys_for_slot(header.qc_previous.slot)
            .to_vec();
        match create_vote(
            self.chain_id,
            &mut self.consensus,
            header,
            identity.committee_index,
            identity.address,
            &identity.secret_key,
            &qc_keys,
        ) {
            Ok(Some(vote)) => {
                // create_vote mutated last_voted_slot and possibly highest_qc.
                // Persist BEFORE returning the vote so a crash between this line
                // and the network broadcast cannot produce a double-vote on restart.
                self.persist_consensus();
                info!(slot, "voted for block");
                Some(vote)
            }
            Ok(None) => {
                debug!(slot, "declined to vote (safety rule)");
                None
            }
            Err(e) => {
                warn!(slot, error = e, "failed to create vote");
                None
            }
        }
    }

    /// Handle an incoming vote: collect and try to form QC.
    /// Returns the QC if quorum is reached.
    pub fn on_vote(&mut self, vote: ConsensusMessage) -> Option<QuorumCert> {
        // Extract every field we'll need below so we don't have to
        // re-match the variant later (and so `voter_address` is
        // available for evidence construction in the double-vote
        // detection branch).
        let (slot, block_hash, voter_index, voter_address, vote_sig) = match &vote {
            ConsensusMessage::Vote {
                slot,
                block_hash,
                voter_index,
                voter_address,
                signature,
            } => (
                *slot,
                *block_hash,
                *voter_index as usize,
                *voter_address,
                signature.clone(),
            ),
            _ => return None,
        };

        // Audit 327: dedup BEFORE FALCON verify. A re-broadcast of
        // an already-accepted vote (legitimate gossip reflood OR
        // adversarial replay) used to incur a fresh FALCON-verify
        // each time the message arrived; with this gate the cost
        // is paid only on the first delivery.
        //
        // Only short-circuit when the prior seen-vote has the
        // SAME `block_hash` — a different hash from the same
        // voter is a double-vote and must continue down the
        // verify + evidence path below so it can be reported
        // for slashing. The post-verify branch later in this
        // function still handles that case.
        let vote_key = (slot, voter_index as u8);
        if let Some((prev_hash, _)) = self.seen_votes.get(&vote_key) {
            if *prev_hash == block_hash {
                debug!(slot, voter_index, "dedup: replayed vote dropped pre-FALCON",);
                return None;
            }
        }

        // Verify vote signature
        if voter_index < self.committee_keys.len()
            && !verify_vote(self.chain_id, &vote, &self.committee_keys[voter_index])
        {
            warn!(slot, voter_index, "invalid vote signature");
            return None;
        }

        // --- Double-vote (equivocation) detection ---
        // audit-94: equivocation is defined within a single
        // `(slot, view)` window. A validator that votes at view 0
        // (happy-path) and again at view 1 (deterministic recovery
        // after the view-change-QC) signs two different block_hashes
        // for the same `(slot, voter_index)` — but those are
        // legitimate, non-equivocating votes. Pre-audit-94 the check
        // here was view-blind and would slash honest validators
        // wedged into recovery. We resolve each block_hash's view
        // via `view_for_block_hash` (which inspects buffered
        // proposals) and only slash when both votes were cast at
        // the same view.
        //
        // Defensive default: when a view is unknown (proposal not
        // buffered locally), treat it as the same view as the other
        // — preserves the original slashing behaviour under partial
        // buffer state, accepting some false-positive risk over
        // missing a real equivocation.
        if let Some((prev_hash, prev_sig)) = self.seen_votes.get(&vote_key).cloned() {
            if prev_hash != block_hash {
                let prev_view = self.view_for_block_hash(slot, &prev_hash);
                let cur_view = self.view_for_block_hash(slot, &block_hash);
                // Only slash when we KNOW both votes were cast at the
                // SAME view. Unknown view = vote arrived before its
                // proposal was buffered (legitimate race under load) —
                // treat as cross-view and track the new vote rather
                // than risk slashing an honest validator. This loses
                // some real-equivocation detection coverage; a
                // malicious slasher could still construct evidence
                // and submit it as a Slash tx, and the chain-side
                // `verify_double_sign` would still accept it. Mainnet
                // hardening requires committing `view` to the vote
                // signature so the on-chain verifier can refuse
                // cross-view evidence.
                let confirmed_same_view = matches!(
                    (prev_view, cur_view),
                    (Some(p), Some(c)) if p == c
                );
                if confirmed_same_view {
                    warn!(
                        slot,
                        voter_index,
                        offender = hex::encode(voter_address),
                        "DOUBLE VOTE DETECTED — equivocation"
                    );
                    // Construct evidence from both votes and route through
                    // `ingest_evidence`, mirroring the double-propose path.
                    // ingest_evidence re-verifies both signatures, dedups on
                    // (slot, signer), pushes to pending + broadcast queues,
                    // and persists to disk before returning — a crash between
                    // detection and the next slot can no longer drop the
                    // evidence (finder's-fee + slashing preserved).
                    let evidence = DoubleSignEvidence {
                        slot,
                        block_hash_1: prev_hash,
                        signature_1: prev_sig,
                        block_hash_2: block_hash,
                        signature_2: vote_sig.clone(),
                        signer: voter_address,
                        // Filled in by whichever validator broadcasts the
                        // Slash tx — typically the next block proposer.
                        submitter: [0u8; 32],
                    };
                    if self.ingest_evidence(evidence) {
                        info!(
                            slot,
                            offender = hex::encode(voter_address),
                            "double-vote evidence queued for slashing"
                        );
                    }
                } else {
                    debug!(
                        slot,
                        voter_index,
                        prev_view = ?prev_view,
                        cur_view = ?cur_view,
                        "cross-view re-vote — not equivocation, tracking new vote"
                    );
                    // Track the latest vote so future same-view re-votes
                    // from this voter are still detected.
                    if let Some(store) = &self.consensus_store {
                        if let Err(e) = store.save_seen_vote(
                            slot,
                            voter_index as u8,
                            &block_hash,
                            &vote_sig,
                        ) {
                            self.signal_persist_failure("seen-vote", &e.to_string());
                        }
                    }
                    self.seen_votes
                        .insert(vote_key, (block_hash, vote_sig.clone()));
                }
            }
        } else {
            // Persist BEFORE the in-memory insert. Panics on failure for
            // the same reason as the seen-proposal site above.
            if let Some(store) = &self.consensus_store {
                if let Err(e) =
                    store.save_seen_vote(slot, voter_index as u8, &block_hash, &vote_sig)
                {
                    self.signal_persist_failure("seen-vote", &e.to_string());
                }
            }
            self.seen_votes.insert(vote_key, (block_hash, vote_sig));
        }

        // Collect vote
        let entry = self.votes.entry(slot).or_insert_with(|| SlotVotes {
            block_hash,
            votes: Vec::new(),
        });
        entry.votes.push(vote);

        // Try to form QC (dynamic quorum based on actual committee size)
        let threshold = quorum_for_committee(self.committee_keys.len());
        if entry.votes.len() >= threshold {
            let qc = try_form_qc(
                self.chain_id,
                slot,
                block_hash,
                &entry.votes,
                &self.committee_keys,
            );
            if let Some(ref qc) = qc {
                info!(slot, votes = qc.vote_count(), "QC formed");
                // Update consensus state
                let mut mutated = false;
                if slot > self.consensus.highest_qc.slot {
                    self.consensus.highest_qc = qc.clone();
                    mutated = true;
                }
                if mutated {
                    self.persist_consensus();
                }
                // audit-234 part 4 (CONSENSUS_INVARIANTS.md O2): a QC
                // for slot `slot` certifies the block at that height.
                // Advance `target_height` to `slot + 1` so subsequent
                // recovery (view-change, fallback) targets the next
                // height we need to commit, not the one we just
                // certified. `advance_target_height` is monotonic
                // (no-op if a later QC already advanced past us) and
                // resets the timeout tracker for the new target.
                self.advance_target_height(slot + 1);
                // Record soft finality. Pass the active committee
                // size so devnet/testnet committees (smaller than the
                // production 128) compute the correct quorum threshold.
                self.finality.record_soft_finality(
                    slot,
                    block_hash,
                    qc.clone(),
                    self.committee_keys.len(),
                );
            }
            qc
        } else {
            None
        }
    }

    /// Handle a slot timeout: create view change message.
    /// Returns the message to broadcast.
    pub fn on_timeout(&mut self, identity: &ValidatorIdentity) -> Option<ViewChangeMessage> {
        // audit-234 part 4 (CONSENSUS_INVARIANTS.md L1, O3): the
        // view-change message MUST target `target_height` — the
        // oldest height we still need to commit — not the
        // wall-clock `current_slot`. When recovery takes longer
        // than `SLOT_DURATION_MS`, `current_slot` drifts and a
        // VC msg keyed on it would target a slot the chain has
        // already moved past, leaving the original failed slot
        // permanently uncommitted.
        let slot = self.consensus.target_height;
        let highest_qc_hash = self.consensus.highest_qc.hash();

        // TPL-501: equivocation guard. If we already signed a
        // VC at this slot, we MUST NOT sign a different one — a
        // FALCON sig over `(slot=N, highest_qc=Q1)` paired with
        // a sig over `(slot=N, highest_qc=Q2)` is the textbook
        // double-VC slashable pattern. Branches:
        //
        // - persisted hash matches current highest_qc.hash() →
        //   the message we'd sign is identical to one we
        //   already signed; rebuild it from cached signature
        //   bytes and return it (idempotent re-broadcast covers
        //   crash-after-sign-before-broadcast).
        // - persisted hash differs from current highest_qc.hash()
        //   → highest_qc has advanced (or otherwise changed) at
        //   the same target_height between sign and the
        //   re-fire; signing a fresh VC would equivocate.
        //   Return None — better to forfeit our VC contribution
        //   for this round than self-slash.
        if let Some((persisted_hash, persisted_sig)) = self.seen_view_changes_self.get(&slot) {
            if *persisted_hash == highest_qc_hash {
                debug!(slot, "TPL-501: re-broadcasting persisted view-change signature");
                return Some(ViewChangeMessage {
                    slot,
                    highest_qc: self.consensus.highest_qc.clone(),
                    voter_index: identity.committee_index,
                    voter_address: identity.address,
                    signature: persisted_sig.clone(),
                });
            } else {
                warn!(
                    slot,
                    "TPL-501: refusing to sign new VC at slot we already signed for — would equivocate"
                );
                return None;
            }
        }

        match create_view_change(
            self.chain_id,
            slot,
            &self.consensus.highest_qc,
            identity.committee_index,
            identity.address,
            &identity.secret_key,
        ) {
            Ok(msg) => {
                // TPL-501: persist BEFORE returning the signed
                // message — same pattern as `seen_proposals` /
                // `seen_votes`. A crash between this fsync and
                // the broadcast leaves the seen-VC record on
                // disk; on restart, the equivocation guard
                // above triggers and we re-broadcast the same
                // signature instead of signing a divergent one.
                if let Some(store) = &self.consensus_store {
                    if let Err(e) =
                        store.save_seen_view_change_self(slot, &highest_qc_hash, &msg.signature)
                    {
                        self.signal_persist_failure("seen-view-change-self", &e.to_string());
                    }
                }
                self.seen_view_changes_self
                    .insert(slot, (highest_qc_hash, msg.signature.clone()));
                info!(slot, "created view change message");
                Some(msg)
            }
            Err(e) => {
                warn!(slot, error = e, "failed to create view change");
                None
            }
        }
    }

    /// Handle an incoming view change message.
    /// Returns true when a view-change-QC is installed in `self.timeout`.
    ///
    /// audit-234 part 4 (CONSENSUS_INVARIANTS.md L3): on the first
    /// formation of a VC-QC for the current view, bump
    /// `consensus.current_view`. The deterministic leader for the
    /// new view (V+1) is then `fallback_leader_index(target_height,
    /// current_view, n)`. The timeout tracker is reset so the new
    /// view's leader gets a fresh proposal window — the VC-QC is
    /// preserved on the new tracker so receivers know recovery is
    /// in progress.
    pub fn on_view_change(&mut self, msg: ViewChangeMessage) -> bool {
        let slot = msg.slot;

        // audit-234 part 4: ignore late VC messages for slots the
        // chain has already moved past. Without this guard, a VC
        // msg arriving after target_height advanced would re-form
        // a VC-QC for the stale slot and clobber the current
        // target's timeout tracker (since the first-formation
        // check sees vc_qc=None and would install a fresh tracker
        // keyed on the stale slot). target_height monotonicity
        // means msg.slot < target_height is always stale; equal
        // is the current target; greater is future and we accept
        // it (the chain hasn't reached it yet but we'll need the
        // VC state by the time it does).
        if slot < self.consensus.target_height {
            debug!(
                slot,
                target_height = self.consensus.target_height,
                "ignoring stale view-change message"
            );
            return false;
        }

        // Audit 327: dedup BEFORE pushing into the per-slot Vec.
        // `try_form_view_change_qc` runs FALCON verification on
        // every entry in the Vec, so a peer that floods repeats
        // of the same `(slot, voter_index)` would inflate the
        // per-QC-attempt FALCON cost linearly. The dedup map's
        // entry is removed alongside the Vec in the slot-prune
        // loop.
        //
        // TPL-502: the dedup map stores `(qc_hash, sig)` so a
        // SECOND VC from the same `(slot, voter_index)` with a
        // DIFFERENT `highest_qc.hash()` is detected here as
        // equivocation. Honest validators sign at most one
        // (slot, qc) pair via TPL-501; observing two distinct
        // `qc_hash`es from the same voter at the same target
        // slot is the slashable double-VC pattern.
        let dedup_key = (slot, msg.voter_index);
        let incoming_qc_hash = msg.highest_qc.hash();
        if let Some((prev_qc_hash, prev_sig)) = self.seen_view_changes.get(&dedup_key).cloned() {
            if prev_qc_hash == incoming_qc_hash {
                debug!(
                    slot,
                    voter_index = msg.voter_index,
                    "dedup: replayed view-change dropped",
                );
                return false;
            }
            // Different qc_hash from the same voter at the same
            // slot — equivocation. Verify the INCOMING sig (the
            // first one's validity is implied by it having
            // landed in the dedup map) before constructing
            // evidence; a peer-injected forgery shouldn't be
            // mistaken for an honest validator's equivocation.
            //
            // The verifier only proves `prev_sig` is well-formed
            // FALCON-signed bytes against the prior preimage —
            // we trusted it on first arrival. We re-verify
            // `signature_2` here (the new arrival) to make sure
            // we're not framing the offender on a corrupt sig.
            let voter_idx = msg.voter_index as usize;
            if voter_idx >= self.committee_keys.len() {
                warn!(
                    slot,
                    voter_index = msg.voter_index,
                    "VC voter_index outside committee — drop without ingesting evidence"
                );
                return false;
            }
            if !pyde_consensus::view_change::verify_view_change(
                self.chain_id,
                &msg,
                &self.committee_keys[voter_idx],
            ) {
                warn!(
                    slot,
                    voter_index = msg.voter_index,
                    "second VC's signature failed FALCON verify; not equivocation"
                );
                return false;
            }
            warn!(
                slot,
                voter_index = msg.voter_index,
                offender = hex::encode(msg.voter_address),
                "DOUBLE VIEW-CHANGE DETECTED — equivocation"
            );
            let evidence = pyde_consensus::slashing::DoubleViewChangeEvidence {
                slot,
                qc_hash_1: prev_qc_hash,
                signature_1: prev_sig,
                qc_hash_2: incoming_qc_hash,
                signature_2: msg.signature.clone(),
                signer: msg.voter_address,
                // Filled in on-chain by whichever validator
                // broadcasts the Slash tx. The on-chain handler
                // for double-VC evidence is a follow-up; for now
                // the evidence is queued in
                // `pending_vc_evidence` for the runtime to drain.
                submitter: [0u8; 32],
            };
            if self.ingest_view_change_evidence(evidence) {
                info!(
                    slot,
                    offender = hex::encode(msg.voter_address),
                    "double-VC evidence queued for slashing"
                );
            }
            return false;
        }
        self.seen_view_changes
            .insert(dedup_key, (incoming_qc_hash, msg.signature.clone()));

        let entry = self.view_changes.entry(slot).or_default();
        entry.push(msg);

        // Try to form view change QC
        if let Some(vc_qc) =
            try_form_view_change_qc(self.chain_id, slot, entry, &self.committee_keys)
        {
            let first_formation = self.timeout.view_change_qc.is_none();
            if first_formation {
                self.consensus.bump_view();
                self.persist_consensus();
                info!(
                    slot,
                    votes = vc_qc.vote_count,
                    new_view = self.consensus.current_view,
                    "view change QC formed; bumped to view {}",
                    self.consensus.current_view
                );
                // Fresh tracker for the new view so the leader has a
                // full proposal window. Preserve the VC-QC so the
                // receive-side gate in `buffer_fallback_proposal`
                // and the build-side gate in
                // `try_build_fallback_proposal` recognize that
                // recovery is in progress.
                //
                // Audit 408: anchor the new tracker on the slot's
                // wall-clock start (same fix as `advance_target_height`).
                // After a VC-QC the fallback leader gets a fresh
                // `PROPOSAL_TIMEOUT_MS` window measured from the
                // slot's actual start, not "now".
                let slot_start_ms = self.slot_start_ms_for_target(slot);
                let mut new_tracker = TimeoutTracker::new(slot, slot_start_ms);
                new_tracker.view_change_qc = Some(vc_qc);
                self.timeout = new_tracker;
            } else {
                // VC-QC already installed — idempotent late-arriving
                // VC messages just refresh the QC contents.
                self.timeout.view_change_qc = Some(vc_qc);
            }
            true
        } else {
            false
        }
    }

    /// Handle a finality vote. Returns `true` when a new hard-finality
    /// certificate was formed this call — the caller should then drain
    /// `take_checkpoint_to_broadcast()` and publish on the consensus
    /// channel so non-validator peers can update their WS anchor
    /// (slice 4.3 gap 1).
    pub fn on_finality_vote(&mut self, vote: FinalityVote) -> bool {
        let slot = vote.slot;
        let block_hash = vote.block_hash;
        let state_root = vote.state_root;
        let voter_index = vote.voter_index;

        // Audit 327: dedup BEFORE pushing into the per-slot Vec.
        // `try_form_hard_finality` runs FALCON verification on
        // every entry of the Vec, so a peer flooding the same
        // `(slot, voter_index)` would force a fresh FALCON-verify
        // round per duplicate.
        let dedup_key = (slot, voter_index);
        if !self.seen_finality_votes.insert(dedup_key) {
            debug!(slot, voter_index, "dedup: replayed finality vote dropped",);
            return false;
        }

        let entry = self.finality_votes.entry(slot).or_default();
        entry.push(vote);

        // Try to form hard finality cert (dynamic quorum)
        let threshold = quorum_for_committee(self.committee_keys.len());
        if entry.len() >= threshold {
            if let Some(cert) = try_form_hard_finality(
                self.chain_id,
                slot,
                block_hash,
                state_root,
                entry,
                &self.committee_keys,
            ) {
                info!(slot, "hard finality achieved");
                // Audit item 207a: persist BEFORE in-memory mutation.
                // Construct the checkpoint explicitly here so we can
                // fsync it first; if the write fails, panic aborts
                // the process before `record_hard_finality` moves
                // `self.finality` to a state that disk won't confirm
                // on restart. Reverted-on-restart state was the
                // long-range-attack re-opening the audit flagged.
                let cp = pyde_consensus::finality::FinalityCheckpoint {
                    slot: cert.slot,
                    block_hash: cert.block_hash,
                    state_root: cert.state_root,
                    cert: cert.clone(),
                };
                self.persist_finality_checkpoint_direct(&cp);
                self.finality.record_hard_finality(cert);
                return true;
            }
        }
        false
    }

    /// Borrow the latest checkpoint for external broadcasting. Used by
    /// the node runtime after `on_finality_vote` returns true. Validators
    /// publish the full checkpoint on the consensus topic so non-
    /// validator peers (and any validator that missed votes due to
    /// temporary network issues) can catch up on the WS anchor.
    pub fn latest_finality_checkpoint(
        &self,
    ) -> Option<&pyde_consensus::finality::FinalityCheckpoint> {
        self.finality.latest_checkpoint.as_ref()
    }

    /// Ingest a finality checkpoint received via gossip (slice 4.3 gap 1).
    ///
    /// Semantics:
    /// - Refuse if the checkpoint's slot is not strictly greater than our
    ///   current WS anchor (monotonic progress only).
    /// - Validators cross-verify the cert's FALCON signatures against
    ///   their own `committee_keys`. A cert with fewer than the current
    ///   committee's quorum is rejected.
    /// - Non-validators (empty committee_keys) accept the cert without
    ///   re-verification — they trust the consensus-topic filter to
    ///   gate publication to validators only.
    ///
    /// On acceptance, updates `latest_checkpoint` + persists to disk.
    pub fn ingest_finality_checkpoint(
        &mut self,
        cp: pyde_consensus::finality::FinalityCheckpoint,
    ) -> bool {
        if let Some(existing) = &self.finality.latest_checkpoint {
            if cp.slot <= existing.slot {
                debug!(
                    incoming = cp.slot,
                    current = existing.slot,
                    "ignoring non-monotonic finality checkpoint"
                );
                return false;
            }
        }

        // Validator cross-verification: we know the current committee, so
        // we can re-check the cert's signatures. Mismatched quorum means
        // either the cert is for a prior epoch (committee rotated) or
        // it's forged — either way, don't trust it.
        if !self.committee_keys.is_empty() {
            let quorum = quorum_for_committee(self.committee_keys.len());
            if cp.cert.vote_count() < quorum as u32 {
                warn!(
                    slot = cp.slot,
                    votes = cp.cert.vote_count(),
                    quorum,
                    "rejecting finality checkpoint: below current-committee quorum"
                );
                return false;
            }
        }

        // Audit item 207a: persist BEFORE mutating in-memory state
        // so a crash in the window can't leave in-memory ahead of
        // disk. If the write fails, panic aborts before `latest_
        // checkpoint` takes the new value.
        self.persist_finality_checkpoint_direct(&cp);
        self.finality.latest_checkpoint = Some(cp);
        true
    }

    /// Take ownership of all queued double-sign evidence, clearing the
    /// internal queue. Called by the block builder when constructing a
    /// proposal so each piece of evidence can be wrapped into a
    /// `TransactionType::Slash` and submitted on-chain.
    ///
    /// If the caller fails to produce the block (e.g. view change), they
    /// are responsible for re-queueing the evidence via `push_evidence`
    /// — otherwise it is lost along with the unbuilt proposal.
    pub fn drain_pending_evidence(&mut self) -> Vec<DoubleSignEvidence> {
        let out = std::mem::take(&mut self.pending_evidence);
        if !out.is_empty() {
            self.persist_evidence_state();
        }
        out
    }

    /// Re-queue previously drained evidence, e.g. after a failed block
    /// build. No-op if `evidence` is empty. Preserves insertion order by
    /// appending at the tail.
    #[allow(dead_code)]
    pub fn push_evidence(&mut self, evidence: Vec<DoubleSignEvidence>) {
        if evidence.is_empty() {
            return;
        }
        self.pending_evidence.extend(evidence);
        self.persist_evidence_state();
    }

    /// Ingest a piece of equivocation evidence — shared entry point for
    /// both local detection and gossip reception. The flow is:
    ///
    /// 1. Deduplicate on `(slot, signer)`. A validator that has already
    ///    queued evidence against the same offender at the same slot
    ///    ignores repeats.
    /// 2. Verify that `signer` is a current committee member. Evidence
    ///    naming a non-validator is meaningless and wastes block space.
    /// 3. Verify both FALCON signatures against the signer's committee
    ///    key (delegated to `slash_double_sign`, which re-runs the
    ///    canonical verification used by the on-chain handler).
    /// 4. If all three pass, push to `pending_evidence` (for block
    ///    inclusion) and `broadcast_evidence` (for P2P relay).
    ///
    /// Returns `true` if the evidence was newly accepted; `false` means
    /// it was a duplicate or failed verification. Callers relying on
    /// the return value: gossip path should only relay on `true` to
    /// avoid amplification storms.
    pub fn ingest_evidence(&mut self, evidence: DoubleSignEvidence) -> bool {
        let key = (evidence.slot, evidence.signer);
        if self.seen_evidence.contains(&key) {
            return false;
        }

        // Resolve the accused signer to their committee index. A signer
        // not in the active committee cannot be slashed — drop.
        let signer_pk = self
            .committee_keys
            .iter()
            .find(|pk| pyde_account::address::derive_eoa_address(pk) == evidence.signer);
        let pk_bytes = match signer_pk {
            Some(pk) => pk.clone(),
            None => {
                debug!(
                    slot = evidence.slot,
                    signer = hex::encode(evidence.signer),
                    "rejecting evidence: signer not in committee"
                );
                return false;
            }
        };

        // Audit 328: switch to `verify_double_sign` here — the
        // ingest path only cares whether the FALCON signatures
        // verify under the local chain_id. The on-chain handler
        // (`pyde_tx::pipeline::execute_slash`) re-runs verification
        // and computes the slash amount from the live validator
        // entry's `stake` (so the burned + finder_fee numbers
        // honour the offender's actual stake, not the constant
        // `VALIDATOR_STAKE`). Calling `slash_double_sign` here
        // would force us to invent a stake parameter just to throw
        // away the result.
        if !verify_double_sign(self.chain_id, &evidence, &pk_bytes) {
            debug!(
                slot = evidence.slot,
                signer = hex::encode(evidence.signer),
                "rejecting evidence: signature verification failed"
            );
            return false;
        }

        self.seen_evidence.insert(key);
        self.pending_evidence.push(evidence.clone());
        self.broadcast_evidence.push(evidence);
        // Persist BEFORE returning so a crash between ingest and the
        // next drain_* call cannot lose the evidence.
        self.persist_evidence_state();
        true
    }

    /// TPL-502: ingest VC equivocation evidence (mirror of
    /// `ingest_evidence` for proposer/vote double-sign). The
    /// flow is the same: dedup on `(slot, signer)`, reject if
    /// the signer isn't in the current committee, FALCON-verify
    /// both signatures under the local `chain_id`, queue.
    ///
    /// Returns `true` if the evidence was newly accepted. The
    /// `seen_evidence` dedup key is shared with the proposer/
    /// vote pipeline so a validator that's already been queued
    /// for slashing once at a given slot doesn't double-queue.
    /// (Slot-level slashing is unique per `(slot, signer)` —
    /// the on-chain handler will reject the second instance
    /// anyway, but pre-pipeline dedup keeps the queues lean.)
    ///
    /// Caveat: the on-chain Slash-tx handler currently only
    /// understands `DoubleSignEvidence` (the proposer/vote
    /// shape). Until the Slash payload's discriminator is
    /// extended to cover VC equivocation, evidence queued here
    /// stays in `pending_vc_evidence` for runtime drainage —
    /// it isn't yet wrapped into an on-chain Slash tx. The
    /// detection side (this method) is the security primitive;
    /// the on-chain integration is staged separately so the
    /// wire-format change can land in its own commit.
    pub fn ingest_view_change_evidence(
        &mut self,
        evidence: pyde_consensus::slashing::DoubleViewChangeEvidence,
    ) -> bool {
        let key = (evidence.slot, evidence.signer);
        if self.seen_evidence.contains(&key) {
            return false;
        }
        let signer_pk = self
            .committee_keys
            .iter()
            .find(|pk| pyde_account::address::derive_eoa_address(pk) == evidence.signer);
        let pk_bytes = match signer_pk {
            Some(pk) => pk.clone(),
            None => {
                debug!(
                    slot = evidence.slot,
                    signer = hex::encode(evidence.signer),
                    "rejecting VC evidence: signer not in committee"
                );
                return false;
            }
        };
        if !pyde_consensus::slashing::verify_double_view_change(
            self.chain_id,
            &evidence,
            &pk_bytes,
        ) {
            debug!(
                slot = evidence.slot,
                signer = hex::encode(evidence.signer),
                "rejecting VC evidence: signature verification failed"
            );
            return false;
        }
        self.seen_evidence.insert(key);
        self.pending_vc_evidence.push(evidence);
        // Persist `seen_evidence` so a crash between detection and
        // drainage doesn't lose the dedup record (matches the
        // proposer/vote ingest path's persistence).
        self.persist_evidence_state();
        true
    }

    /// TPL-502: take ownership of all queued VC equivocation
    /// evidence, clearing the internal queue. Counterpart to
    /// `drain_pending_evidence` for the double-sign queue.
    /// Caller must re-queue if they fail to consume (e.g.
    /// failed block build). Dead-code warning is expected
    /// pre on-chain integration: this is the consumer API the
    /// follow-up Slash-tx pipeline will call.
    #[allow(dead_code)]
    pub fn drain_pending_vc_evidence(
        &mut self,
    ) -> Vec<pyde_consensus::slashing::DoubleViewChangeEvidence> {
        std::mem::take(&mut self.pending_vc_evidence)
    }

    /// Drain the broadcast staging queue. Returns every piece of
    /// evidence that has been newly ingested (either locally detected
    /// or received via gossip) since the last call. The caller is
    /// responsible for publishing each entry on the consensus channel.
    pub fn drain_broadcast_evidence(&mut self) -> Vec<DoubleSignEvidence> {
        let out = std::mem::take(&mut self.broadcast_evidence);
        if !out.is_empty() {
            self.persist_evidence_state();
        }
        out
    }

    /// Drain `pending_evidence` and turn each entry into a signed
    /// `TransactionType::Slash` transaction, authored by `identity`.
    ///
    /// Slash txs are added to `out` in the order they were queued, each
    /// with a sequential nonce starting at `start_nonce`. The
    /// submitter's address (`identity.address`) is also stamped into
    /// the evidence's `submitter` field so `execute_slash` can pay the
    /// finder's fee to the correct account — this is the point where
    /// the "filled by caller" stub at the detection site is resolved.
    ///
    /// Returns the next nonce the caller should use for any additional
    /// txs from this address within the same block.
    pub fn drain_evidence_into_slash_txs(
        &mut self,
        identity: &ValidatorIdentity,
        start_nonce: u64,
        chain_id: u64,
        out: &mut Vec<pyde_tx::types::Transaction>,
    ) -> u64 {
        use pyde_tx::types::{FeePayer, Transaction, TransactionType};

        let mut next_nonce = start_nonce;
        for mut evidence in self.drain_pending_evidence() {
            evidence.submitter = identity.address;
            let data = crate::wire::encode_double_sign_evidence(&evidence);

            let mut tx = Transaction {
                from: identity.address,
                to: [0u8; 32],
                value: 0,
                data,
                // Handler charges 100_000 on success; give ~3× headroom for
                // safety against any future gas-model adjustment.
                gas_limit: 300_000,
                nonce: next_nonce,
                signature: vec![],
                fee_payer: FeePayer::Sender,
                access_list: vec![],
                deadline: None,
                chain_id,
                tx_type: TransactionType::Slash,
            };

            let tx_hash = tx.hash();
            match pyde_crypto::falcon::falcon_sign(&identity.secret_key, &tx_hash) {
                Ok(sig) => tx.signature = sig.as_bytes().to_vec(),
                Err(e) => {
                    error!(error = ?e, "failed to sign slash tx; dropping evidence");
                    continue;
                }
            }

            info!(
                offender = hex::encode(evidence.signer),
                slot = evidence.slot,
                nonce = next_nonce,
                "slash tx built for block inclusion"
            );
            out.push(tx);
            next_nonce = next_nonce.saturating_add(1);
        }
        next_nonce
    }

    /// Advance to the next wall-clock slot. Returns the new slot number.
    ///
    /// audit-234 part 4 (CONSENSUS_INVARIANTS.md O3): wall-clock tick
    /// does NOT reset `self.timeout`. The tracker is keyed on
    /// `target_height` and only resets when the chain progresses
    /// (`advance_target_height`) or a view-change-QC bumps the view
    /// (deferred to step 3). This way, an in-flight recovery for an
    /// old failed slot is preserved across multiple wall-clock ticks
    /// instead of being silently discarded each tick.
    pub fn advance_slot(&mut self) -> u64 {
        self.consensus.advance_slot();
        // current_slot changed + pending_votes/timeouts cleared.
        self.persist_consensus();
        let new_slot = self.consensus.current_slot;

        // Clean up old vote/view-change data (keep last 10 slots).
        // audit-94: NEVER prune `target_height` itself, regardless of
        // how far wall-clock has raced ahead. Pre-fix, a wedged
        // target_height + 10+-slot wall-clock drift erased the
        // recovery data for the wedged slot, making the wedge
        // permanent. The `prune_floor = min(prune_before, target)`
        // clamp keeps target_height (and everything above) intact
        // on the wedged path while preserving the original 10-slot
        // window on the healthy path. Equivocation-detection state
        // (`seen_votes`, `seen_proposals`, `seen_view_changes`)
        // still anchors on the original wall-clock window so its
        // gossip-replay protection isn't affected by wedges.
        if new_slot > 10 {
            let prune_before = new_slot - 10;
            let prune_floor = std::cmp::min(prune_before, self.consensus.target_height);
            self.votes.retain(|s, _| *s >= prune_floor);
            self.view_changes.retain(|s, _| *s >= prune_floor);
            self.finality_votes.retain(|s, _| *s >= prune_floor);
            self.buffered_proposals
                .retain(|s, _| *s >= prune_floor);
            self.voted_view_per_slot
                .retain(|s, _| *s >= prune_floor);
            self.last_built_fallback_view_per_slot
                .retain(|s, _| *s >= prune_floor);
            self.seen_proposals.retain(|(s, _), _| *s >= prune_before);
            self.seen_votes.retain(|(s, _), _| *s >= prune_before);
            // Audit 327: prune the dedup sets in lockstep with their
            // backing per-slot Vecs so the sets don't grow unbounded
            // for long-running validators.
            self.seen_view_changes.retain(|(s, _), _| *s >= prune_before);
            // TPL-501: prune the self-VC equivocation record
            // alongside its peers. The on-disk copy is pruned
            // by `store.prune_evidence_before` below.
            self.seen_view_changes_self.retain(|s, _| *s >= prune_before);
            self.seen_finality_votes.retain(|(s, _)| *s >= prune_before);
            // Audit 326: `seen_evidence` is keyed on
            // `(slot, signer)` and gates evidence ingestion to
            // dedup local re-detection + gossip arrivals. Pre-fix
            // it grew for the entire lifetime of the validator —
            // a long-running testnet validator with thousands of
            // slashing events would accumulate one entry per
            // distinct (slot, signer) pair indefinitely. Prune
            // mirrors `seen_proposals` / `seen_votes`: drop
            // entries older than the 10-slot retention window.
            //
            // Re-broadcast risk: if a peer resurfaces evidence
            // for `slot < prune_before`, the dedup gate misses
            // and the evidence enters `pending_evidence` +
            // `broadcast_evidence` again. That's a one-shot
            // amplification per stale evidence — gossip's own
            // de-dup handles the second hop, and the on-disk
            // evidence store (pruned via `prune_evidence_before`)
            // is the durability anchor. Acceptable trade.
            self.seen_evidence.retain(|(s, _)| *s >= prune_before);
            // Mirror the same pruning on disk so the evidence index does not
            // grow unbounded. Best-effort: a failure here just delays cleanup.
            if let Some(store) = &self.consensus_store {
                if let Err(e) = store.prune_evidence_before(prune_before) {
                    warn!(error = %e, "failed to prune evidence on disk");
                }
            }
        }

        debug!(slot = new_slot, "advanced to next slot");
        new_slot
    }

    /// Audit 408: set the slot-clock anchor on the engine. Called by
    /// the runtime after the `SlotClock` is constructed (which
    /// happens later in node startup than `ValidatorEngine::new`).
    /// Once set, `advance_target_height` resets the timeout tracker
    /// to the slot's actual wall-clock start instead of "now".
    pub fn set_slot_anchor(&mut self, genesis_timestamp_ms: u64, block_time_ms: u64) {
        self.genesis_timestamp_ms = genesis_timestamp_ms;
        self.block_time_ms = block_time_ms;

        // Audit-94: re-anchor the *initial* TimeoutTracker now that
        // the slot clock is known. The tracker created in `new()`
        // was anchored to engine-creation-time because the genesis
        // timestamp wasn't available yet — and engine creation
        // typically runs 100–300 ms before slot 1's wall-clock
        // window begins. Without this re-anchor, the 200 ms
        // `PROPOSAL_TIMEOUT_MS` expires before slot 1 even starts,
        // firing a spurious view-change. That early VC cascades:
        // peers form a VC-QC at slot 1, then every subsequent
        // wall-clock tick layers a happy-path proposal on top of
        // a chain still in recovery, splitting votes between
        // forward progress and the fallback candidate and wedging
        // the chain permanently at startup.
        //
        // Only the initial tracker needs this fix; `advance_target_
        // height` (audit 408) already anchors to the new slot's
        // wall-clock start once the chain is moving.
        if !self.timeout.proposal_received && self.timeout.view_change_qc.is_none() {
            let slot_start_ms = self.slot_start_ms_for_target(self.timeout.slot);
            self.timeout.slot_start_ms = slot_start_ms;
        }
    }

    /// Wall-clock instant (Unix ms) when slot `target` begins.
    /// Falls back to `current_time_ms()` if the slot anchor hasn't
    /// been wired yet (test paths). See `set_slot_anchor`.
    fn slot_start_ms_for_target(&self, target: u64) -> u64 {
        if self.block_time_ms == 0 {
            current_time_ms()
        } else {
            self.genesis_timestamp_ms
                .saturating_add(target.saturating_mul(self.block_time_ms))
        }
    }

    /// Advance `target_height` to `new_height` and reset the timeout
    /// tracker for the new height. No-op if `new_height` doesn't
    /// advance the target. Persists the consensus state.
    ///
    /// audit-234 part 4 (CONSENSUS_INVARIANTS.md O2): called when a
    /// vote-QC for the current target forms — the chain has moved
    /// on, recovery state for the old height is no longer needed.
    ///
    /// Audit 408: the new tracker's `slot_start_ms` is the wall-
    /// clock start of `new_height` per `slot_start_ms_for_target`,
    /// not `now`. The prior code used `now` and fired view-change
    /// 200 ms after the *previous* slot's QC — typically before the
    /// new slot's wall-clock window even started.
    fn advance_target_height(&mut self, new_height: u64) {
        if self.consensus.advance_target_height(new_height) {
            let slot_start_ms = self.slot_start_ms_for_target(new_height);
            self.timeout = TimeoutTracker::new(new_height, slot_start_ms);
            self.persist_consensus();
            debug!(target_height = new_height, "advanced target_height");
        }
    }

    /// Audit 399: same monotonic advance as `advance_target_height`,
    /// callable from outside the engine. Used by the sync-apply
    /// path so a restarted validator's `target_height` follows the
    /// chain head it just synced — without this, the engine keeps
    /// voting on the slot it was at before the crash even after
    /// the chain has moved on, and a 4-of-4 cluster with one node
    /// down + one node effectively muted falls below quorum.
    pub fn advance_target_height_after_sync(&mut self, new_height: u64) {
        self.advance_target_height(new_height);
    }

    /// Check if the current slot has timed out.
    ///
    /// Two timeout paths (audit 234 part 3 added the second):
    /// 1. **Primary**: no proposal received within
    ///    `PROPOSAL_TIMEOUT_MS` of slot start. Standard HotStuff
    ///    leader-failure path.
    /// 2. **Secondary (progress)**: chain hasn't advanced — i.e.
    ///    `consensus.highest_qc.slot` hasn't moved forward in
    ///    `PROGRESS_TIMEOUT_MS`. Gossip-mesh degradation means
    ///    some validators received the proposal and voted (their
    ///    primary timer is suppressed) while others didn't,
    ///    leaving neither path with quorum. Engine-level deadline
    ///    that survives slot advances — only resets when the
    ///    chain genuinely moves.
    ///
    /// In both cases the runtime's response is the same: build a
    /// view-change message, broadcast it, await a view-change-QC
    /// to install the fallback proposer.
    ///
    /// Takes `&mut self` because the secondary path lazily
    /// refreshes `last_qc_progress_ms` whenever it observes
    /// `highest_qc.slot` having advanced — keeps the bookkeeping
    /// in one place rather than scattering across every QC-update
    /// site.
    pub fn is_timed_out(&mut self) -> bool {
        let now_ms = current_time_ms();
        // Refresh the engine-level progress timestamp lazily.
        if self.consensus.highest_qc.slot > self.last_seen_qc_slot {
            self.last_seen_qc_slot = self.consensus.highest_qc.slot;
            self.last_qc_progress_ms = now_ms;
        }
        if self.timeout.is_expired(now_ms) {
            return true;
        }
        let progressed = self.consensus.highest_qc.slot >= self.consensus.current_slot;
        let already_view_changed = self.timeout.view_change_qc.is_some();
        let elapsed = now_ms.saturating_sub(self.last_qc_progress_ms);
        if !progressed
            && !already_view_changed
            && elapsed >= pyde_consensus::view_change::PROGRESS_TIMEOUT_MS
        {
            tracing::info!(
                slot = self.consensus.current_slot,
                highest_qc = self.consensus.highest_qc.slot,
                elapsed_ms = elapsed,
                "DBG: progress timeout firing"
            );
            return true;
        }
        false
    }

    // ========== Threshold Decryption (MEV Protection) ==========

    /// Generate decryption shares for a block's encrypted transactions.
    /// Called after ordering is locked (QC formed) and before execution.
    /// Returns the shares to broadcast to other committee members.
    pub fn generate_decryption_shares(
        &self,
        identity: &ValidatorIdentity,
        encrypted_txs: &[EncryptedTx],
    ) -> Option<Vec<DecryptionShare>> {
        let key_share = identity.key_share.as_ref()?;

        // TPL-301: each share carries a FALCON sig over
        // (ct_hash || index || blinded_shares_hash) signed by the
        // validator's consensus FALCON sk. `combine_shares` verifies
        // the sig against the committee's public-key vector before
        // accepting the share into Lagrange interpolation.
        let shares: Vec<DecryptionShare> = encrypted_txs
            .iter()
            .filter_map(|tx| {
                generate_decryption_share(key_share, &tx.ciphertext, &identity.secret_key).ok()
            })
            .collect();
        // Defensive: if any share generation failed, abandon the
        // whole round so we don't broadcast a partial set with
        // mismatched ciphertext indices.
        if shares.len() != encrypted_txs.len() {
            warn!(
                txs = encrypted_txs.len(),
                produced = shares.len(),
                "decryption-share generation produced partial set; aborting"
            );
            return None;
        }

        info!(
            slot = self.consensus.current_slot,
            txs = encrypted_txs.len(),
            "generated decryption shares"
        );
        Some(shares)
    }

    /// Create a BlockDecryptor and seed it with our own shares.
    /// Other committee members' shares are added as they arrive via gossipsub.
    #[allow(dead_code)]
    pub fn start_decryption(
        &self,
        identity: &ValidatorIdentity,
        encrypted_txs: Vec<EncryptedTx>,
        threshold: usize,
        committee_keys: Vec<FalconPublicKey>,
    ) -> Result<BlockDecryptor, String> {
        let mut decryptor = BlockDecryptor::new(encrypted_txs, threshold, committee_keys)?;

        // Add our own shares immediately
        if let Some(key_share) = &identity.key_share {
            decryptor.add_member_shares(key_share, &identity.secret_key);
            debug!(
                slot = self.consensus.current_slot,
                "added own decryption shares"
            );
        }

        Ok(decryptor)
    }

    /// Create a finality vote for a block we've seen finalized with QC.
    pub fn create_finality_vote(
        &self,
        slot: u64,
        block_hash: [u8; 32],
        state_root: [u8; 32],
        identity: &ValidatorIdentity,
    ) -> Option<FinalityVote> {
        match create_finality_vote(
            self.chain_id,
            slot,
            block_hash,
            state_root,
            identity.committee_index,
            identity.address,
            &identity.secret_key,
        ) {
            Ok(vote) => Some(vote),
            Err(e) => {
                warn!(slot, error = e, "failed to create finality vote");
                None
            }
        }
    }
}

/// Get current time in milliseconds.
fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::falcon::falcon_keygen;

    /// Arbitrary non-mainnet, non-devnet chain_id used by every test
    /// in this module so cross-chain replay regressions surface here
    /// rather than slipping past with hardcoded chain_id=0.
    const TEST_CHAIN_ID: u64 = 7;

    fn make_identity(index: u8) -> ValidatorIdentity {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let address = derive_eoa_address(&pk_bytes);
        let (kem_pk, kem_sk) = pyde_crypto::kyber::kyber_keygen().unwrap();
        ValidatorIdentity {
            address,
            public_key: pk,
            secret_key: sk,
            committee_index: index,
            key_share: None,
            kem_public_key: kem_pk,
            kem_secret_key: kem_sk,
        }
    }

    fn make_engine_with_committee(n: usize) -> (ValidatorEngine, Vec<ValidatorIdentity>) {
        let mut identities = Vec::new();
        let mut keys = Vec::new();

        for i in 0..n {
            let id = make_identity(i as u8);
            keys.push(id.public_key.as_bytes().to_vec());
            identities.push(id);
        }

        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        engine.set_committee(keys);
        (engine, identities)
    }

    /// TPL-405: when a `ShutdownSignal` is attached, a fatal-
    /// persist branch triggers the signal (no panic). Subscribers
    /// observe the trigger so the main loop can begin draining.
    #[tokio::test]
    async fn tpl_405_persist_failure_triggers_shutdown_when_signal_attached() {
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        let signal = crate::shutdown::ShutdownSignal::new();
        let mut rx = signal.subscribe();
        engine.attach_shutdown_signal(signal);

        // Direct invocation of the dispatch helper. Production
        // call sites (persist_consensus, persist_evidence_state,
        // persist_finality_checkpoint_direct, persist_reshare_state,
        // seen-proposal save, seen-vote save) all funnel through it.
        engine.signal_persist_failure("test", "synthetic-io-error");

        // Subscribers must receive within a tight bound — the
        // broadcast send is in-process and non-blocking.
        let recv = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;
        assert!(
            matches!(recv, Ok(Ok(()))),
            "shutdown signal must fire on attached-signal persist failure; got {:?}",
            recv
        );
    }

    /// TPL-405: with no signal attached, the engine still panics
    /// — preserves the existing failure-mode contract for the unit
    /// tests that assert it. Production paths always attach a
    /// signal via `attach_shutdown_signal`.
    #[test]
    #[should_panic(expected = "test persist failed: synthetic-io-error")]
    fn tpl_405_persist_failure_panics_when_no_signal_attached() {
        let engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        engine.signal_persist_failure("test", "synthetic-io-error");
    }

    #[test]
    fn engine_starts_at_genesis() {
        let engine = ValidatorEngine::new(TEST_CHAIN_ID, [0; 32]);
        assert_eq!(engine.consensus.current_slot, 0);
    }

    #[test]
    fn advance_slot_increments() {
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0; 32]);
        let new_slot = engine.advance_slot();
        assert_eq!(new_slot, 1);
        assert_eq!(engine.consensus.current_slot, 1);
    }

    #[test]
    fn check_proposer_respects_vrf_threshold() {
        // With 3 validators, threshold = (U64::MAX / 3) * 3 / 2 ≈ U64::MAX / 2.
        // Try multiple slots — at least one should qualify (probabilistic but reliable).
        let (mut engine, identities) = make_engine_with_committee(3);
        let mut found_proposer = false;
        for _ in 0..20 {
            engine.advance_slot();
            if let Some(candidate) = engine.check_proposer(&identities[0]) {
                assert_eq!(candidate.address, identities[0].address);
                found_proposer = true;
                break;
            }
        }
        assert!(
            found_proposer,
            "should find at least 1 slot to propose in 20 tries"
        );
    }

    #[test]
    fn single_validator_always_proposes() {
        let (engine, identities) = make_engine_with_committee(1);
        // Single validator: threshold = U64::MAX, always qualifies
        let candidate = engine.check_proposer(&identities[0]);
        assert!(candidate.is_some());
    }

    #[test]
    fn vote_on_proposal() {
        let (mut engine, identities) = make_engine_with_committee(3);

        // Advance to slot 1 so we can vote
        engine.advance_slot();

        let header = BlockHeader {
            slot: 1,
            epoch: 0,
            parent_hash: [0u8; 32],
            proposer: identities[0].address,
            vrf_proof: vec![],
            qc_previous: QuorumCert::empty(),
            tx_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 0,
        };

        let vote = engine.on_proposal(&header, &identities[1]);
        assert!(vote.is_some());
    }

    // ========== Task 026: mandatory-inclusion vote-skip ==========

    #[test]
    fn select_and_vote_skips_when_inclusion_flag_set() {
        // End-to-end enforcement test for the mandatory-inclusion path.
        // Directly exercises the vote-skip mechanism that node.rs's compact-
        // block handler triggers via flag_inclusion_violation.
        let (mut engine, identities) = make_engine_with_committee(3);
        engine.advance_slot();
        let slot = engine.consensus.current_slot;

        // Seed a buffered proposal so select_and_vote has something to act on.
        // Without this the function returns None for an unrelated reason
        // (nothing to vote for), which would mask whether the inclusion
        // check actually fires.
        let header = BlockHeader {
            slot,
            epoch: 0,
            parent_hash: [0u8; 32],
            proposer: identities[0].address,
            vrf_proof: vec![],
            qc_previous: QuorumCert::empty(),
            tx_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 0,
        };
        engine
            .buffered_proposals
            .entry(slot)
            .or_default()
            .push(BufferedProposal {
                header,
                proposer_signature: vec![],
                vrf_score: 0,
            });

        // Baseline: without the flag, select_and_vote produces a vote.
        let baseline_engine_clone_check = {
            // Clone-the-flag by using a fresh engine snapshot — we instead
            // assert by the positive path in vote_on_proposal (already
            // covered). Here, flag then assert None.
            engine.flag_inclusion_violation(slot);
            assert!(engine.is_inclusion_violated(slot));
            engine.select_and_vote(&identities[1])
        };
        assert!(
            baseline_engine_clone_check.is_none(),
            "inclusion-flagged slot must not produce a vote"
        );

        // Post-skip invariant: subsequent calls still return None. The
        // engine should treat the slot as "voted" for this round, so that
        // a compact block that clears the flag late cannot cause a
        // belated vote.
        assert!(engine.voted_view_per_slot.contains_key(&slot));
        assert!(engine.select_and_vote(&identities[1]).is_none());
    }

    #[test]
    fn select_and_vote_produces_vote_without_inclusion_flag() {
        // Positive case: no inclusion flag → normal vote path runs.
        // Pairs with the skip test above so we know the flag is what
        // caused the skip, not some unrelated issue.
        let (mut engine, identities) = make_engine_with_committee(3);
        engine.advance_slot();
        let slot = engine.consensus.current_slot;

        let header = BlockHeader {
            slot,
            epoch: 0,
            parent_hash: [0u8; 32],
            proposer: identities[0].address,
            vrf_proof: vec![],
            qc_previous: QuorumCert::empty(),
            tx_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 0,
        };
        engine
            .buffered_proposals
            .entry(slot)
            .or_default()
            .push(BufferedProposal {
                header,
                proposer_signature: vec![],
                vrf_score: 0,
            });

        assert!(!engine.is_inclusion_violated(slot));
        let vote = engine.select_and_vote(&identities[1]);
        assert!(vote.is_some(), "un-flagged slot should produce a vote");
    }

    /// TPL-203 / audit-234 part 4 (CONSENSUS_INVARIANTS.md L1, O3):
    /// when recovery for a slot takes longer than `SLOT_DURATION_MS`,
    /// a validator's wall-clock `current_slot` drifts past
    /// `target_height`. Fallback proposals are buffered at
    /// `header.slot = target_height` (the proposer wrote it that
    /// way). Pre-fix, `select_and_vote` looked up
    /// `buffered_proposals[current_slot]`, missed the fallback at
    /// `target_height`, and silently returned None on every tick of
    /// the recovery window. Post-fix it reads `target_height` and
    /// finds the buffered proposal.
    #[test]
    fn select_and_vote_uses_target_height_not_current_slot() {
        let (mut engine, identities) = make_engine_with_committee(3);
        // Drift wall-clock past target_height: target_height stays at
        // 1 (no QC formed), current_slot walks forward to 5. This is
        // the exact shape of a recovery > SLOT_DURATION_MS — three
        // wall-clock ticks fired after the recovery began but no
        // vote-QC has formed at target_height yet.
        for _ in 0..5 {
            engine.advance_slot();
        }
        assert_eq!(engine.consensus.current_slot, 5);
        assert_eq!(engine.consensus.target_height, 1);

        // Buffer a proposal at target_height (where a fallback
        // proposer would have placed it). vrf_score 0 so it wins
        // min-by-vrf_score selection.
        let header = BlockHeader {
            slot: engine.consensus.target_height,
            epoch: 0,
            parent_hash: [0u8; 32],
            proposer: identities[0].address,
            vrf_proof: vec![],
            qc_previous: QuorumCert::empty(),
            tx_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 0,
        };
        engine
            .buffered_proposals
            .entry(engine.consensus.target_height)
            .or_default()
            .push(BufferedProposal {
                header,
                proposer_signature: vec![],
                vrf_score: 0,
            });

        // Pre-fix: returned None because lookup was at current_slot=5
        // but the proposal lives at target_height=1.
        let vote = engine.select_and_vote(&identities[1]);
        assert!(
            vote.is_some(),
            "select_and_vote must find the proposal at target_height even when current_slot has drifted past"
        );
    }

    // ========== Task 034: cross-committee resharing ==========

    use pyde_crypto::threshold::{
        combine_shares, generate_decryption_share, threshold_encrypt, threshold_keygen,
    };

    /// Outfit a validator identity with a specific key share — lets tests
    /// simulate membership in a particular committee without running full
    /// DKG through ValidatorEngine.
    fn identity_with_share(
        index: u8,
        key_share: pyde_crypto::threshold::KeyShare,
    ) -> ValidatorIdentity {
        let mut id = make_identity(index);
        id.key_share = Some(key_share);
        id
    }

    #[test]
    fn reshare_full_rotation_preserves_decryption() {
        // End-to-end: encrypt under the committee's public key, rotate to a
        // completely fresh committee via ValidatorEngine resharing, and
        // verify the new committee decrypts the pre-rotation ciphertext.
        // Every new member ingests all contributions, waits past the
        // aggregation trigger, fires aggregation from the slot tick.
        let (tpk, old_shares) = threshold_keygen(5, 3).unwrap();
        let msg = b"rotation survives";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        let (mut outgoing, old_ids) = make_engine_with_committee(5);
        let mut outgoing_ids: Vec<ValidatorIdentity> = old_ids
            .into_iter()
            .zip(old_shares.iter())
            .enumerate()
            .map(|(i, (id, ks))| {
                let mut with_share = id;
                with_share.key_share = Some(ks.clone());
                with_share.committee_index = i as u8;
                with_share
            })
            .collect();

        let (mut incoming, new_ids) = make_engine_with_committee(6);
        let new_committee_keys: Vec<Vec<u8>> = new_ids
            .iter()
            .map(|id| id.public_key.as_bytes().to_vec())
            .collect();
        let mut new_identities: Vec<ValidatorIdentity> = new_ids;

        let contribs: Vec<ResharingContribution> = outgoing_ids
            .iter_mut()
            .filter_map(|id| outgoing.start_committee_reshare(1, &new_committee_keys, id))
            .collect();
        assert_eq!(contribs.len(), 5);

        for (new_idx, identity) in new_identities.iter_mut().enumerate() {
            incoming.prepare_for_reshare_reception(
                /* target */ 1,
                new_committee_keys.clone(),
                /* our 1-based new index */ new_idx + 1,
            );
            // Ingest all contributions — storage only, no aggregation.
            for c in &contribs {
                incoming.on_reshare_contribution(c.clone(), 5, identity);
            }
            // Before the trigger fires, no share should be derived.
            let trigger = incoming.reshare_aggregation_trigger_slot;
            assert!(incoming.consensus.current_slot < trigger);
            assert!(!incoming.try_aggregate_reshare_on_slot(
                incoming.consensus.current_slot,
                5,
                identity
            ));
            // Advance past the trigger; aggregation fires.
            let fire_at = trigger + 1;
            assert!(incoming.try_aggregate_reshare_on_slot(fire_at, 5, identity));
            // Second call after aggregation: no-op.
            assert!(!incoming.try_aggregate_reshare_on_slot(fire_at + 1, 5, identity));
        }

        // TPL-301: combine_shares verifies each share's FALCON sig
        // against the committee's pk vector, so deserialize the
        // pk-bytes the engine already tracks.
        let committee_falcon_pks: Vec<pyde_crypto::falcon::FalconPublicKey> = new_committee_keys
            .iter()
            .map(|b| pyde_crypto::falcon::FalconPublicKey::from_bytes(b).unwrap())
            .collect();
        let dec_shares: Vec<_> = new_identities
            .iter()
            .take(4)
            .map(|id| {
                generate_decryption_share(id.key_share.as_ref().unwrap(), &ct, &id.secret_key)
                    .unwrap()
            })
            .collect();
        let plaintext = combine_shares(&dec_shares, 4, &ct, &committee_falcon_pks).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn reshare_async_arrival_converges_on_same_polynomial() {
        // CORRECTNESS REGRESSION TEST.
        // Simulates the asymmetric-gossip scenario that motivated the
        // deterministic-trigger design: two new members receive
        // contributions in different orders, and one hits the old-
        // threshold with a different subset than the other. Under the
        // old "aggregate on first threshold reached" rule, they'd derive
        // shares on different polynomials and threshold decryption in
        // the new committee would silently fail. With the trigger-
        // based rule, they wait until the pool has converged and then
        // both pick the canonical lowest-indexed subset.
        let (tpk, old_shares) = threshold_keygen(5, 3).unwrap();
        let msg = b"async arrival convergence";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        let new_committee_keys = vec![vec![0xAA; 897]; 6];

        // Two new members, independent engines — model separate nodes.
        let mut engine_a = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        engine_a.set_committee(new_committee_keys.clone());
        let mut engine_b = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        engine_b.set_committee(new_committee_keys.clone());

        engine_a.prepare_for_reshare_reception(1, new_committee_keys.clone(), 1);
        engine_b.prepare_for_reshare_reception(1, new_committee_keys.clone(), 2);

        let contribs: Vec<ResharingContribution> = old_shares
            .iter()
            .map(|s| generate_resharing_contribution(s, 6, 4, 1, b"conv"))
            .collect();

        let mut id_a = make_identity(0);
        let mut id_b = make_identity(1);

        // Asymmetric arrival:
        // A receives {2, 3, 4} first (contributions 1 and 5 delayed).
        for c in [&contribs[1], &contribs[2], &contribs[3]] {
            engine_a.on_reshare_contribution(c.clone(), 5, &mut id_a);
        }
        // B receives {1, 2, 3} first.
        for c in [&contribs[0], &contribs[1], &contribs[2]] {
            engine_b.on_reshare_contribution(c.clone(), 5, &mut id_b);
        }

        // Under the OLD first-threshold rule this is where they'd
        // diverge. Under the new rule, they haven't aggregated yet —
        // the trigger hasn't fired.
        let trigger = engine_a.reshare_aggregation_trigger_slot;
        assert!(!engine_a.try_aggregate_reshare_on_slot(trigger - 1, 5, &mut id_a));
        assert!(!engine_b.try_aggregate_reshare_on_slot(trigger - 1, 5, &mut id_b));

        // Gossip converges: both engines now have the full set.
        engine_a.on_reshare_contribution(contribs[0].clone(), 5, &mut id_a);
        engine_a.on_reshare_contribution(contribs[4].clone(), 5, &mut id_a);
        engine_b.on_reshare_contribution(contribs[3].clone(), 5, &mut id_b);
        engine_b.on_reshare_contribution(contribs[4].clone(), 5, &mut id_b);

        // Trigger fires on both.
        assert!(engine_a.try_aggregate_reshare_on_slot(trigger, 5, &mut id_a));
        assert!(engine_b.try_aggregate_reshare_on_slot(trigger, 5, &mut id_b));

        // THE KEY CHECK: A's and B's shares must combine to decrypt.
        // If they were on different polynomials, `combine_shares` would
        // produce garbage.
        let shares = vec![
            generate_decryption_share(id_a.key_share.as_ref().unwrap(), &ct, &id_a.secret_key)
                .unwrap(),
            generate_decryption_share(id_b.key_share.as_ref().unwrap(), &ct, &id_b.secret_key)
                .unwrap(),
        ];
        // Can't combine with only 2 of 4 required — add more honest shares.
        let mut helpers: Vec<ValidatorEngine> = (3..=6)
            .map(|_| {
                let mut e = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
                e.set_committee(new_committee_keys.clone());
                e
            })
            .collect();
        let mut helper_ids: Vec<ValidatorIdentity> = (3..=6).map(make_identity).collect();
        for (i, (engine, id)) in helpers.iter_mut().zip(helper_ids.iter_mut()).enumerate() {
            engine.prepare_for_reshare_reception(1, new_committee_keys.clone(), i + 3);
            for c in &contribs {
                engine.on_reshare_contribution(c.clone(), 5, id);
            }
            assert!(engine.try_aggregate_reshare_on_slot(trigger, 5, id));
        }
        let mut all_shares = shares;
        for id in &helper_ids[..2] {
            all_shares.push(
                generate_decryption_share(id.key_share.as_ref().unwrap(), &ct, &id.secret_key)
                    .unwrap(),
            );
        }
        // TPL-301: build the FALCON-pk vector that combine_shares
        // verifies against, ordered by share-index. Indices 1, 2 are
        // id_a, id_b; indices 3..=6 come from helper_ids.
        let mut committee_falcon_pks =
            Vec::<pyde_crypto::falcon::FalconPublicKey>::with_capacity(6);
        committee_falcon_pks.push(id_a.public_key.clone());
        committee_falcon_pks.push(id_b.public_key.clone());
        for h in &helper_ids {
            committee_falcon_pks.push(h.public_key.clone());
        }
        let plaintext = combine_shares(&all_shares, 4, &ct, &committee_falcon_pks).unwrap();
        assert_eq!(
            plaintext, msg,
            "shares must be on same polynomial — canonical subset divergence would break this"
        );
    }

    #[test]
    fn reshare_aggregation_waits_for_trigger() {
        let (_, old_shares) = threshold_keygen(4, 3).unwrap();
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        let new_committee = vec![vec![0xAA; 897]; 4];
        engine.prepare_for_reshare_reception(1, new_committee.clone(), 1);
        let mut id = make_identity(0);

        // Submit ALL 4 contributions.
        for s in &old_shares {
            let c = generate_resharing_contribution(s, 4, 3, 1, b"e");
            engine.on_reshare_contribution(c, 4, &mut id);
        }
        // Pool is full, but trigger hasn't fired.
        let trigger = engine.reshare_aggregation_trigger_slot;
        assert!(trigger > 0);
        assert!(!engine.try_aggregate_reshare_on_slot(trigger - 1, 4, &mut id));
        assert!(id.key_share.is_none());

        // At trigger: fires.
        assert!(engine.try_aggregate_reshare_on_slot(trigger, 4, &mut id));
        assert!(id.key_share.is_some());
    }

    #[test]
    fn reshare_aggregation_below_threshold_retries() {
        // If only 2 of 4 contributions arrive by trigger time, aggregation
        // doesn't fire — and `reshare_aggregated` stays false so a
        // subsequent slot tick with a fuller pool can succeed.
        let (_, old_shares) = threshold_keygen(4, 3).unwrap();
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        engine.prepare_for_reshare_reception(1, vec![vec![0xAA; 897]; 4], 1);
        let mut id = make_identity(0);

        // Only 2 contributions (below old_threshold of 3).
        for s in old_shares.iter().take(2) {
            let c = generate_resharing_contribution(s, 4, 3, 1, b"e");
            engine.on_reshare_contribution(c, 4, &mut id);
        }
        let trigger = engine.reshare_aggregation_trigger_slot;
        assert!(!engine.try_aggregate_reshare_on_slot(trigger, 4, &mut id));
        // Third contribution arrives late.
        let late = generate_resharing_contribution(&old_shares[2], 4, 3, 1, b"e");
        engine.on_reshare_contribution(late, 4, &mut id);
        // Later slot: now we have enough → fires.
        assert!(engine.try_aggregate_reshare_on_slot(trigger + 3, 4, &mut id));
        assert!(id.key_share.is_some());
    }

    // ========== Task 034: reshare crash-safety ==========

    #[test]
    fn reshare_state_wire_roundtrip() {
        let s = crate::wire::ReshareState {
            target_epoch: 42,
            new_index: 7,
            aggregation_trigger_slot: 123,
            aggregated: false,
            broadcast_start_slot: 100,
            pending_rebroadcast: Some((42, vec![0xAA; 16])),
            new_committee_keys: vec![vec![0x11; 50], vec![0x22; 50], vec![0x33; 50]],
        };
        let bytes = crate::wire::encode_reshare_state(&s);
        let decoded = crate::wire::decode_reshare_state(&bytes).unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn reshare_state_wire_none_rebroadcast() {
        let s = crate::wire::ReshareState {
            target_epoch: 0,
            new_index: 0,
            aggregation_trigger_slot: 0,
            aggregated: true,
            broadcast_start_slot: 0,
            pending_rebroadcast: None,
            new_committee_keys: vec![],
        };
        let bytes = crate::wire::encode_reshare_state(&s);
        let decoded = crate::wire::decode_reshare_state(&bytes).unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn reshare_state_restores_across_engine_restart() {
        // Full crash-restart roundtrip: attach a store, advance through a
        // rotation preparation, "crash" (drop engine), reattach the store
        // to a fresh engine, and verify the reshare state came back.
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let new_committee = vec![
            vec![0x11; 897],
            vec![0x22; 897],
            vec![0x33; 897],
            vec![0x44; 897],
        ];

        let trigger_slot;
        {
            let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
            engine.set_committee(vec![vec![0x01; 897]; 4]);
            let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
            engine.attach_consensus_store(store);
            engine.prepare_for_reshare_reception(7, new_committee.clone(), 2);
            trigger_slot = engine.reshare_aggregation_trigger_slot;
            assert!(trigger_slot > 0);
            // engine dropped here — simulates crash.
        }

        // Reopen store, reattach.
        let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        engine.attach_consensus_store(store);

        // Post-restore invariants.
        assert_eq!(engine.reshare_target_epoch, 7);
        assert_eq!(engine.reshare_new_index, 2);
        assert_eq!(engine.reshare_aggregation_trigger_slot, trigger_slot);
        assert_eq!(engine.reshare_new_committee, new_committee);
        assert!(!engine.reshare_aggregated);
        // Contribution pool is NOT persisted (rebuilds from rebroadcasts).
        assert_eq!(engine.reshare_contributions.len(), 0);
    }

    #[test]
    fn reshare_state_restores_aggregated_flag() {
        // If aggregation fired before the crash, the aggregated flag must
        // persist — otherwise the restarted node could double-aggregate
        // when late contributions arrive and overwrite its now-correct
        // key share with garbage derived from a different canonical set.
        use tempfile::tempdir;

        let dir = tempdir().unwrap();

        {
            let (_, old_shares) = threshold_keygen(4, 3).unwrap();
            let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
            let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
            engine.attach_consensus_store(store);
            engine.prepare_for_reshare_reception(1, vec![vec![0xAA; 897]; 4], 1);
            let mut id = make_identity(0);
            for s in &old_shares {
                let c = generate_resharing_contribution(s, 4, 3, 1, b"e");
                engine.on_reshare_contribution(c, 4, &mut id);
            }
            let trigger = engine.reshare_aggregation_trigger_slot;
            assert!(engine.try_aggregate_reshare_on_slot(trigger, 4, &mut id));
            assert!(engine.reshare_aggregated);
        }

        let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        engine.attach_consensus_store(store);
        assert!(
            engine.reshare_aggregated,
            "aggregated flag must survive restart"
        );
    }

    #[test]
    fn reshare_state_pending_rebroadcast_survives_restart() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let (_, old_shares) = threshold_keygen(3, 2).unwrap();

        {
            let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
            engine.set_committee(vec![vec![0x01; 897]; 3]);
            let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
            engine.attach_consensus_store(store);
            let id = identity_with_share(0, old_shares[0].clone());
            engine
                .start_committee_reshare(5, &vec![vec![0xBB; 897]; 3], &id)
                .unwrap();
            assert!(engine.pending_reshare_rebroadcast.is_some());
        }

        let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        engine.attach_consensus_store(store);
        assert!(
            engine.pending_reshare_rebroadcast.is_some(),
            "outgoing member must continue rebroadcasting after restart"
        );
    }

    #[test]
    fn reshare_ignores_when_not_on_new_committee() {
        // Departing member (not on new committee): prepare_for_reshare_reception
        // with index 0 → contributions get silently dropped, no share derived.
        let (_, old_shares) = threshold_keygen(4, 3).unwrap();
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        engine.prepare_for_reshare_reception(1, vec![vec![0xAA; 897]], /* our_new_index */ 0);
        let mut leaving = identity_with_share(0, old_shares[0].clone());

        let sample_contrib = generate_resharing_contribution(&old_shares[0], 4, 3, 1, b"e");
        let derived = engine.on_reshare_contribution(sample_contrib, 4, &mut leaving);
        assert!(!derived);
    }

    #[test]
    fn reshare_rejects_invalid_contribution() {
        // Tampered contribution: must fail internal consistency check and
        // NOT be counted toward threshold.
        let (_, old_shares) = threshold_keygen(4, 3).unwrap();
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        let new_committee = vec![vec![0xAA; 897]; 4];
        engine.prepare_for_reshare_reception(1, new_committee, 1);
        let mut new_id = make_identity(0);

        let bad = generate_resharing_contribution(&old_shares[0], 4, 3, 1, b"e");
        // Flip one sub-share to break the polynomial.
        bad.to_bytes(); // sanity
                        // Expose a mutation path: rebuild via from_bytes after a byte flip.
        let mut bytes = bad.to_bytes();
        // Corrupt a payload byte well past the 16-byte header.
        let corrupt_at = bytes.len() - 4;
        bytes[corrupt_at] ^= 0xFF;
        let corrupted = ResharingContribution::from_bytes(&bytes).unwrap();
        assert!(!engine.on_reshare_contribution(corrupted, 4, &mut new_id));
    }

    #[test]
    fn reshare_deduplicates_same_old_index() {
        // Same old member re-broadcasts (gossip retry). The pool must not
        // double-count duplicates; subsequent calls with the same
        // `from_old_index` return false.
        let (_, old_shares) = threshold_keygen(4, 3).unwrap();
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        let new_committee = vec![vec![0xAA; 897]; 4];
        engine.prepare_for_reshare_reception(1, new_committee, 1);
        let mut new_id = make_identity(0);

        let c = generate_resharing_contribution(&old_shares[0], 4, 3, 1, b"e");
        // First call: newly stored → returns true.
        assert!(engine.on_reshare_contribution(c.clone(), 4, &mut new_id));
        // Duplicate: rejected → returns false. Pool still at size 1.
        assert!(!engine.on_reshare_contribution(c, 4, &mut new_id));
        assert_eq!(engine.reshare_contributions.len(), 1);
    }

    #[test]
    fn reshare_rebroadcast_fires_within_window() {
        // Outgoing member stashes a contribution and re-broadcasts every
        // RESHARE_REBROADCAST_INTERVAL_SLOTS slots for RESHARE_REBROADCAST_SLOTS.
        let (_, old_shares) = threshold_keygen(3, 2).unwrap();
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        engine.set_committee(vec![vec![0xAA; 897]; 3]);
        let mut id = identity_with_share(0, old_shares[0].clone());

        // Initial broadcast at slot 0.
        engine
            .start_committee_reshare(7, &vec![vec![0xBB; 897]; 3], &id)
            .unwrap();

        // Same slot: should NOT re-broadcast (already-publishing slot).
        assert!(engine.maybe_rebroadcast_reshare().is_none());

        // Slot 2 (interval hit) → re-broadcast.
        engine.advance_slot();
        engine.advance_slot();
        let r = engine.maybe_rebroadcast_reshare();
        assert!(r.is_some(), "expected rebroadcast at slot 2");
        assert_eq!(r.unwrap().0, 7);

        // Slot 3 (off-interval) → skip.
        engine.advance_slot();
        assert!(engine.maybe_rebroadcast_reshare().is_none());

        // Slot 4 (interval hit) → re-broadcast.
        engine.advance_slot();
        assert!(engine.maybe_rebroadcast_reshare().is_some());

        // Push past the window (RESHARE_REBROADCAST_SLOTS = 10). Clears
        // the pending bytes so no stale epoch leaks out later.
        for _ in 0..20 {
            engine.advance_slot();
        }
        assert!(engine.maybe_rebroadcast_reshare().is_none());
        // Second call after window: still None — the purge is sticky.
        assert!(engine.maybe_rebroadcast_reshare().is_none());

        // Suppress unused-variable warning on id in branches that don't touch it.
        let _ = &mut id;
    }

    #[test]
    fn reshare_rebroadcast_none_without_prior_start() {
        // maybe_rebroadcast with no stashed contribution → always None.
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        assert!(engine.maybe_rebroadcast_reshare().is_none());
        for _ in 0..20 {
            engine.advance_slot();
            assert!(engine.maybe_rebroadcast_reshare().is_none());
        }
    }

    // ========== Phase 4 slice 4.3: WS anchor bootstrap + gossip ==========

    #[test]
    fn install_bootstrap_ws_anchor_sets_checkpoint_slot() {
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        assert!(engine.finality.latest_checkpoint.is_none());

        engine.install_bootstrap_ws_anchor(500);
        let cp = engine.finality.latest_checkpoint.as_ref().unwrap();
        assert_eq!(cp.slot, 500);
    }

    #[test]
    fn install_bootstrap_ws_anchor_survives_restart() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();

        {
            let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
            engine.attach_consensus_store(Arc::new(ConsensusStateStore::open(dir.path()).unwrap()));
            engine.install_bootstrap_ws_anchor(777);
        }
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        engine.attach_consensus_store(Arc::new(ConsensusStateStore::open(dir.path()).unwrap()));
        let cp = engine.finality.latest_checkpoint.as_ref().unwrap();
        assert_eq!(cp.slot, 777);
    }

    #[test]
    fn ingest_finality_checkpoint_rejects_non_monotonic() {
        // Anchor must only move forward. A checkpoint at a lower slot
        // than the current anchor could be a replay of an old message,
        // or a malicious peer trying to rewind the WS guard.
        use pyde_consensus::finality::{FinalityCheckpoint, HardFinalityCert};
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        engine.install_bootstrap_ws_anchor(100);

        let stale = FinalityCheckpoint {
            slot: 50,
            block_hash: [0u8; 32],
            state_root: [0u8; 32],
            cert: HardFinalityCert {
                slot: 50,
                block_hash: [0u8; 32],
                state_root: [0u8; 32],
                voter_bitmap: 0,
                signatures: Vec::new(),
            },
        };
        assert!(!engine.ingest_finality_checkpoint(stale));
        assert_eq!(
            engine.finality.latest_checkpoint.as_ref().unwrap().slot,
            100
        );
    }

    #[test]
    fn ingest_finality_checkpoint_rejects_below_quorum_when_committee_known() {
        // A validator cross-verifies sigs against their own committee.
        // A cert with fewer sigs than quorum must be rejected.
        use pyde_consensus::finality::{FinalityCheckpoint, HardFinalityCert};
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        engine.set_committee(vec![vec![0xAA; 897]; 4]); // 4-member committee → quorum 3
        engine.install_bootstrap_ws_anchor(10);

        let under_quorum = FinalityCheckpoint {
            slot: 100,
            block_hash: [0u8; 32],
            state_root: [0u8; 32],
            cert: HardFinalityCert {
                slot: 100,
                block_hash: [0u8; 32],
                state_root: [0u8; 32],
                voter_bitmap: 0b11, // only 2 votes, below quorum of 3
                signatures: vec![vec![0x01; 600]; 2],
            },
        };
        assert!(!engine.ingest_finality_checkpoint(under_quorum));
    }

    #[test]
    fn ingest_finality_checkpoint_accepts_valid_cert_and_persists() {
        use pyde_consensus::finality::{FinalityCheckpoint, HardFinalityCert};
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        engine.set_committee(vec![vec![0xAA; 897]; 4]);
        engine.attach_consensus_store(Arc::new(ConsensusStateStore::open(dir.path()).unwrap()));

        let valid = FinalityCheckpoint {
            slot: 500,
            block_hash: [0xCC; 32],
            state_root: [0xDD; 32],
            cert: HardFinalityCert {
                slot: 500,
                block_hash: [0xCC; 32],
                state_root: [0xDD; 32],
                voter_bitmap: 0b1111, // 4 votes, meets quorum
                signatures: vec![vec![0x02; 600]; 4],
            },
        };
        assert!(engine.ingest_finality_checkpoint(valid));
        assert_eq!(
            engine.finality.latest_checkpoint.as_ref().unwrap().slot,
            500
        );

        // Survives restart.
        drop(engine);
        let mut fresh = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        fresh.attach_consensus_store(Arc::new(ConsensusStateStore::open(dir.path()).unwrap()));
        assert_eq!(fresh.finality.latest_checkpoint.as_ref().unwrap().slot, 500);
    }

    #[test]
    fn ingest_finality_checkpoint_non_validator_accepts_without_verify() {
        // Non-validator path: committee_keys empty → no quorum check.
        // Caller (non-validator full node) trusts the consensus-topic
        // filter (slice 3.4) to gate publication.
        use pyde_consensus::finality::{FinalityCheckpoint, HardFinalityCert};
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0u8; 32]);
        // Do NOT set_committee → empty → non-validator mode.
        assert!(engine.committee_keys.is_empty());

        let cp = FinalityCheckpoint {
            slot: 200,
            block_hash: [0u8; 32],
            state_root: [0u8; 32],
            cert: HardFinalityCert {
                slot: 200,
                block_hash: [0u8; 32],
                state_root: [0u8; 32],
                voter_bitmap: 0, // no votes — non-validator can't verify
                signatures: Vec::new(),
            },
        };
        assert!(engine.ingest_finality_checkpoint(cp));
        assert_eq!(
            engine.finality.latest_checkpoint.as_ref().unwrap().slot,
            200
        );
    }

    // ========== Crash-restart safety tests ==========

    #[test]
    fn crash_restart_preserves_last_voted_slot() {
        // Safety-critical test: if a validator crashes after voting, on restart
        // it MUST remember it already voted for that slot, or BFT safety breaks.
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let committee_keys: Vec<Vec<u8>>;
        let voter: ValidatorIdentity;

        // --- Pre-crash: vote for slot 1 ---
        {
            let (mut engine, identities) = make_engine_with_committee(3);
            committee_keys = identities
                .iter()
                .map(|id| id.public_key.as_bytes().to_vec())
                .collect();
            voter = make_identity(1);

            let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
            engine.attach_consensus_store(store);
            engine.advance_slot(); // → slot 1

            let header = BlockHeader {
                slot: 1,
                epoch: 0,
                parent_hash: [0u8; 32],
                proposer: identities[0].address,
                vrf_proof: vec![],
                qc_previous: QuorumCert::empty(),
                tx_root: [0u8; 32],
                state_root: [0u8; 32],
                timestamp: 0,
            };

            let vote = engine.on_proposal(&header, &voter);
            assert!(vote.is_some(), "first vote must succeed");
            assert_eq!(engine.consensus.last_voted_slot, 1);
            // engine drops here, simulating a crash
        }

        // --- Post-crash: reopen and attempt to vote for slot 1 again ---
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        engine.set_committee(committee_keys);
        let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
        engine.attach_consensus_store(store);

        assert_eq!(
            engine.consensus.last_voted_slot, 1,
            "last_voted_slot must survive restart"
        );
        assert_eq!(
            engine.consensus.current_slot, 1,
            "current_slot must survive restart"
        );

        // Attempt to vote again for slot 1 — create_vote's safety rule must reject it.
        let header = BlockHeader {
            slot: 1,
            epoch: 0,
            parent_hash: [0u8; 32],
            proposer: voter.address,
            vrf_proof: vec![],
            qc_previous: QuorumCert::empty(),
            tx_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 0,
        };
        let vote = engine.on_proposal(&header, &voter);
        assert!(
            vote.is_none(),
            "double-vote after crash must be blocked by safety rule"
        );
    }

    #[test]
    fn crash_restart_preserves_highest_qc() {
        // A formed QC updates highest_qc. After a crash, the restarted validator
        // must not vote for a proposal that doesn't extend that QC.
        use tempfile::tempdir;

        let dir = tempdir().unwrap();

        // Pre-crash: form a QC at slot 5, which becomes highest_qc.
        {
            let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
            let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
            engine.attach_consensus_store(store);

            engine.consensus.highest_qc = QuorumCert {
                slot: 5,
                block_hash: [0xAB; 32],
                voter_bitmap: (1u128 << 86) - 1,
                signatures: vec![vec![0xCC; 600]],
            };
            engine.consensus.current_slot = 5;
            engine.consensus.last_voted_slot = 5;
            // Force a persist via advance_slot (which calls persist_consensus).
            engine.advance_slot();
        }

        // Post-crash: reopen.
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
        engine.attach_consensus_store(store);

        assert_eq!(engine.consensus.highest_qc.slot, 5);
        assert_eq!(engine.consensus.highest_qc.block_hash, [0xAB; 32]);
        assert_eq!(engine.consensus.last_voted_slot, 5);
    }

    #[test]
    fn fresh_store_starts_at_genesis() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
        engine.attach_consensus_store(store);

        assert_eq!(engine.consensus.current_slot, 0);
        assert_eq!(engine.consensus.last_voted_slot, 0);
        assert_eq!(engine.consensus.highest_qc.slot, 0);
    }

    #[test]
    fn advance_slot_persists_across_restart() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();

        {
            let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
            let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
            engine.attach_consensus_store(store);
            for _ in 0..7 {
                engine.advance_slot();
            }
            assert_eq!(engine.consensus.current_slot, 7);
        }

        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
        engine.attach_consensus_store(store);
        assert_eq!(engine.consensus.current_slot, 7);
    }

    // ========== Equivocation evidence crash-restart tests ==========

    fn evidence_header(slot: u64, state_root: [u8; 32]) -> BlockHeader {
        BlockHeader {
            slot,
            epoch: slot / 1000,
            parent_hash: [0x11; 32],
            proposer: [0xAA; 32],
            vrf_proof: vec![0xCC; 100],
            qc_previous: QuorumCert::empty(),
            tx_root: [0x22; 32],
            state_root,
            timestamp: slot * 400,
        }
    }

    #[test]
    fn seen_proposals_restored_on_attach() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let proposer: Address = [0xAB; 32];
        let header = evidence_header(5, [0x33; 32]);
        let sig = vec![0xEE; 600];

        // Write evidence via an isolated store (simulating pre-crash state).
        {
            let store = ConsensusStateStore::open(dir.path()).unwrap();
            store
                .save_seen_proposal(5, &proposer, &header, &sig)
                .unwrap();
        }

        // Fresh engine attaches the same store and must restore the index.
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
        engine.attach_consensus_store(store);

        let entry = engine
            .seen_proposals
            .get(&(5u64, proposer))
            .expect("proposal must be reloaded");
        assert_eq!(entry.0.slot, 5);
        assert_eq!(entry.0.state_root, [0x33; 32]);
        assert_eq!(entry.1, sig);
    }

    #[test]
    fn seen_votes_restored_on_attach() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let block_hash = [0x99; 32];
        let sig = vec![0xFF; 600];

        {
            let store = ConsensusStateStore::open(dir.path()).unwrap();
            store.save_seen_vote(12, 4, &block_hash, &sig).unwrap();
        }

        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
        engine.attach_consensus_store(store);

        let entry = engine
            .seen_votes
            .get(&(12u64, 4u8))
            .expect("vote must be reloaded");
        assert_eq!(entry.0, block_hash);
        assert_eq!(entry.1, sig);
    }

    #[test]
    fn advance_slot_prunes_evidence_on_disk() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();

        // Seed 15 slots of evidence via the store directly.
        {
            let store = ConsensusStateStore::open(dir.path()).unwrap();
            for slot in 1..=15u64 {
                store
                    .save_seen_proposal(
                        slot,
                        &[0xAA; 32],
                        &evidence_header(slot, [0x33; 32]),
                        &[0x11; 10],
                    )
                    .unwrap();
                store
                    .save_seen_vote(slot, 0, &[0x99; 32], &[0x22; 10])
                    .unwrap();
            }
        }

        // Attach, jump forward to slot 15, advancing triggers prune.
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
        engine.attach_consensus_store(Arc::clone(&store));
        // Sanity: reload pulled them all in.
        assert_eq!(engine.seen_proposals.len(), 15);
        assert_eq!(engine.seen_votes.len(), 15);

        // Jump to slot 15 (prune removes slot < new_slot - 10 = 5).
        engine.consensus.current_slot = 14;
        engine.advance_slot(); // new_slot = 15, prune_before = 5

        // Memory pruned in lockstep.
        assert!(engine.seen_proposals.iter().all(|((s, _), _)| *s >= 5));
        assert!(engine.seen_votes.iter().all(|((s, _), _)| *s >= 5));

        // Disk pruned too.
        let on_disk_props = store.load_all_seen_proposals();
        let on_disk_votes = store.load_all_seen_votes();
        assert!(on_disk_props.iter().all(|((s, _), _)| *s >= 5));
        assert!(on_disk_votes.iter().all(|((s, _), _)| *s >= 5));
    }

    // ========== Pending evidence drain/push ==========

    fn evidence_fixture(slot: u64, signer: Address) -> DoubleSignEvidence {
        DoubleSignEvidence {
            slot,
            block_hash_1: [0x01; 32],
            signature_1: vec![0xAA; 600],
            block_hash_2: [0x02; 32],
            signature_2: vec![0xBB; 600],
            signer,
            submitter: [0u8; 32],
        }
    }

    #[test]
    fn drain_pending_evidence_empties_queue() {
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        engine
            .pending_evidence
            .push(evidence_fixture(1, [0xAB; 32]));
        engine
            .pending_evidence
            .push(evidence_fixture(2, [0xCD; 32]));

        let drained = engine.drain_pending_evidence();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].slot, 1);
        assert_eq!(drained[1].slot, 2);
        assert!(engine.pending_evidence.is_empty());

        // Second drain returns empty — ownership was already transferred.
        assert!(engine.drain_pending_evidence().is_empty());
    }

    #[test]
    fn push_evidence_restores_queue() {
        // Simulates the failed-block-build recovery path: drain, fail to
        // build, push back, drain again.
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        engine
            .pending_evidence
            .push(evidence_fixture(7, [0x99; 32]));

        let drained = engine.drain_pending_evidence();
        assert_eq!(drained.len(), 1);
        assert!(engine.pending_evidence.is_empty());

        engine.push_evidence(drained);
        assert_eq!(engine.pending_evidence.len(), 1);
        assert_eq!(engine.pending_evidence[0].slot, 7);
    }

    #[test]
    fn push_evidence_appends_preserving_order() {
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        engine
            .pending_evidence
            .push(evidence_fixture(1, [0x01; 32]));

        engine.push_evidence(vec![
            evidence_fixture(2, [0x02; 32]),
            evidence_fixture(3, [0x03; 32]),
        ]);

        let slots: Vec<u64> = engine.pending_evidence.iter().map(|e| e.slot).collect();
        assert_eq!(slots, vec![1, 2, 3]);
    }

    // ========== Evidence gossip ingest + dedup ==========

    /// Build valid evidence signed by a real FALCON key. Registers
    /// `pk` as committee index 0 so ingest_evidence passes the
    /// signer-in-committee check.
    fn valid_evidence_and_engine() -> (
        ValidatorEngine,
        pyde_crypto::falcon::FalconSecretKey,
        DoubleSignEvidence,
        Address,
    ) {
        use pyde_crypto::falcon::falcon_keygen;

        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let signer = pyde_account::address::derive_eoa_address(&pk_bytes);

        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        engine.set_committee(vec![pk_bytes]);

        let slot = 42u64;
        let hash_1 = [0x01u8; 32];
        let hash_2 = [0x02u8; 32];
        // Build the canonical (chain_id || slot || block_hash) preimage —
        // must match what `verify_double_sign` reconstructs for the
        // engine's chain_id, otherwise FALCON verify rejects.
        let sign_1 = pyde_consensus::hotstuff::proposer_sign_message(TEST_CHAIN_ID, slot, &hash_1);
        let sign_2 = pyde_consensus::hotstuff::proposer_sign_message(TEST_CHAIN_ID, slot, &hash_2);
        let sig_1 = pyde_crypto::falcon::falcon_sign(&sk, &sign_1)
            .unwrap()
            .as_bytes()
            .to_vec();
        let sig_2 = pyde_crypto::falcon::falcon_sign(&sk, &sign_2)
            .unwrap()
            .as_bytes()
            .to_vec();

        let evidence = DoubleSignEvidence {
            slot,
            block_hash_1: hash_1,
            signature_1: sig_1,
            block_hash_2: hash_2,
            signature_2: sig_2,
            signer,
            submitter: [0u8; 32],
        };
        (engine, sk, evidence, signer)
    }

    #[test]
    fn ingest_evidence_accepts_valid_and_stages_for_broadcast() {
        let (mut engine, _sk, evidence, signer) = valid_evidence_and_engine();
        assert!(engine.ingest_evidence(evidence.clone()));

        // Pending queue populated (block builder will drain it).
        assert_eq!(engine.pending_evidence.len(), 1);
        assert_eq!(engine.pending_evidence[0].signer, signer);

        // Broadcast queue populated (node loop will drain it).
        let broadcast = engine.drain_broadcast_evidence();
        assert_eq!(broadcast.len(), 1);
        assert_eq!(broadcast[0].signer, signer);

        // Second drain is empty — ownership transferred.
        assert!(engine.drain_broadcast_evidence().is_empty());
    }

    #[test]
    fn ingest_evidence_dedups_on_slot_signer_pair() {
        let (mut engine, _sk, evidence, _signer) = valid_evidence_and_engine();
        assert!(engine.ingest_evidence(evidence.clone()));
        // Second call with the same (slot, signer) is dropped — returns
        // false, doesn't re-push to either queue.
        assert!(!engine.ingest_evidence(evidence.clone()));
        assert_eq!(engine.pending_evidence.len(), 1);

        let broadcast = engine.drain_broadcast_evidence();
        assert_eq!(broadcast.len(), 1, "duplicates must not double-broadcast");
    }

    #[test]
    fn ingest_evidence_rejects_non_committee_signer() {
        let (mut engine, _sk, mut evidence, _signer) = valid_evidence_and_engine();
        // Replace the signer with an address that isn't in committee_keys.
        evidence.signer = [0xEE; 32];
        assert!(!engine.ingest_evidence(evidence));
        assert!(engine.pending_evidence.is_empty());
        assert!(engine.drain_broadcast_evidence().is_empty());
    }

    #[test]
    fn ingest_evidence_rejects_forged_signatures() {
        let (mut engine, _sk, mut evidence, _signer) = valid_evidence_and_engine();
        // Replace sig_2 with random bytes — FALCON verify will fail.
        evidence.signature_2 = vec![0xFFu8; evidence.signature_2.len()];
        assert!(!engine.ingest_evidence(evidence));
        assert!(engine.pending_evidence.is_empty());
    }

    #[test]
    fn ingest_evidence_rejects_same_hash() {
        // `block_hash_1 == block_hash_2` isn't equivocation; verify_double_sign
        // returns false, so ingest_evidence should drop it.
        let (mut engine, sk, mut evidence, _signer) = valid_evidence_and_engine();
        // Sign the SAME hash twice so both signatures are individually valid.
        let h = [0x77u8; 32];
        let sign_msg = {
            let mut m = Vec::with_capacity(40);
            m.extend_from_slice(&evidence.slot.to_le_bytes());
            m.extend_from_slice(&h);
            m
        };
        let sig = pyde_crypto::falcon::falcon_sign(&sk, &sign_msg)
            .unwrap()
            .as_bytes()
            .to_vec();
        evidence.block_hash_1 = h;
        evidence.block_hash_2 = h;
        evidence.signature_1 = sig.clone();
        evidence.signature_2 = sig;
        assert!(!engine.ingest_evidence(evidence));
    }

    #[test]
    fn on_vote_detects_double_vote_and_queues_evidence() {
        // Regression test for audit item 205: two Vote messages at the
        // same slot from the same voter on different block hashes must
        // produce DoubleSignEvidence in `pending_evidence` instead of
        // just a log line. Before this fix, a validator that crashed
        // between detection and the next slot lost the slashing signal.
        //
        // Audit-94 update: equivocation slashing is now view-aware to
        // avoid false-positives on honest cross-view re-votes. The
        // detector requires KNOWN same-view for both votes (via the
        // proposals buffered for those hashes); construct two real
        // headers at view 0 and buffer them so the lookup resolves.
        use pyde_consensus::hotstuff::{proposer_sign_message, ConsensusMessage};
        use pyde_consensus::block::{BlockHeader, QuorumCert};
        use pyde_crypto::falcon::{falcon_keygen, falcon_sign};

        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let signer = pyde_account::address::derive_eoa_address(&pk_bytes);

        const TEST_CHAIN_ID: u64 = 7;
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        engine.set_committee(vec![pk_bytes]);

        let slot = 7u64;

        // Build two distinct headers at view 0 (vrf_proof omitted →
        // decode_fallback_proof returns None → view defaults to 0).
        let mut header_a = BlockHeader {
            slot,
            epoch: 0,
            parent_hash: [0u8; 32],
            proposer: signer,
            vrf_proof: vec![],
            qc_previous: QuorumCert::empty(),
            tx_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 100,
        };
        let mut header_b = header_a.clone();
        header_b.timestamp = 200; // differ in one byte → different hash
        let hash_a = header_a.hash();
        let hash_b = header_b.hash();
        assert_ne!(hash_a, hash_b);

        engine.buffered_proposals.entry(slot).or_default().push(
            BufferedProposal { header: header_a, proposer_signature: vec![], vrf_score: 0 },
        );
        engine.buffered_proposals.entry(slot).or_default().push(
            BufferedProposal { header: header_b, proposer_signature: vec![], vrf_score: 0 },
        );

        let sign_vote = |h: &[u8; 32]| -> Vec<u8> {
            falcon_sign(&sk, &proposer_sign_message(TEST_CHAIN_ID, slot, h))
                .unwrap()
                .as_bytes()
                .to_vec()
        };

        let vote_a = ConsensusMessage::Vote {
            slot,
            block_hash: hash_a,
            voter_index: 0,
            voter_address: signer,
            signature: sign_vote(&hash_a),
        };
        let vote_b = ConsensusMessage::Vote {
            slot,
            block_hash: hash_b,
            voter_index: 0,
            voter_address: signer,
            signature: sign_vote(&hash_b),
        };

        // First vote: stored in seen_votes, no evidence.
        let _ = engine.on_vote(vote_a);
        assert!(engine.pending_evidence.is_empty());

        // Second vote (same voter, different hash): equivocation.
        let _ = engine.on_vote(vote_b);
        assert_eq!(engine.pending_evidence.len(), 1);
        let ev = &engine.pending_evidence[0];
        assert_eq!(ev.slot, slot);
        assert_eq!(ev.signer, signer);
        assert_eq!(ev.block_hash_1, hash_a);
        assert_eq!(ev.block_hash_2, hash_b);
        assert!(!ev.signature_1.is_empty());
        assert!(!ev.signature_2.is_empty());
        assert_ne!(ev.signature_1, ev.signature_2);

        // Also staged for P2P broadcast so other validators can slash.
        assert_eq!(engine.drain_broadcast_evidence().len(), 1);
    }

    #[test]
    fn evidence_queues_survive_restart() {
        // Hardening task 014c: a validator that ingests evidence and
        // then crashes must still have the evidence available on
        // restart. Without this, detected-but-un-drained equivocations
        // are silently lost if the observing validator crashes before
        // producing its next block.
        use pyde_crypto::falcon::falcon_keygen;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let committee_pk: Vec<u8>;
        let signer_addr: Address;

        // --- Run 1: ingest evidence, then "crash" (drop engine) ---
        {
            let (pk, sk) = falcon_keygen().unwrap();
            committee_pk = pk.as_bytes().to_vec();
            signer_addr = pyde_account::address::derive_eoa_address(&committee_pk);

            let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
            engine.set_committee(vec![committee_pk.clone()]);
            let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
            engine.attach_consensus_store(store);

            let slot = 50u64;
            let hash_1 = [0x01u8; 32];
            let hash_2 = [0x02u8; 32];
            // Bind chain_id into the preimage so the engine's
            // `ingest_evidence` (which rebuilds with self.chain_id =
            // TEST_CHAIN_ID) actually verifies the sigs.
            let sign_1 =
                pyde_consensus::hotstuff::proposer_sign_message(TEST_CHAIN_ID, slot, &hash_1);
            let sign_2 =
                pyde_consensus::hotstuff::proposer_sign_message(TEST_CHAIN_ID, slot, &hash_2);
            let sig_1 = pyde_crypto::falcon::falcon_sign(&sk, &sign_1)
                .unwrap()
                .as_bytes()
                .to_vec();
            let sig_2 = pyde_crypto::falcon::falcon_sign(&sk, &sign_2)
                .unwrap()
                .as_bytes()
                .to_vec();

            let evidence = DoubleSignEvidence {
                slot,
                block_hash_1: hash_1,
                signature_1: sig_1,
                block_hash_2: hash_2,
                signature_2: sig_2,
                signer: signer_addr,
                submitter: [0u8; 32],
            };
            assert!(engine.ingest_evidence(evidence));
            assert_eq!(engine.pending_evidence.len(), 1);
            assert_eq!(engine.broadcast_evidence.len(), 1);
            // engine drops here — disk is the only source of truth now.
        }

        // --- Run 2: reopen, attach, evidence must still be there ---
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        engine.set_committee(vec![committee_pk.clone()]);
        let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
        engine.attach_consensus_store(store);

        assert_eq!(
            engine.pending_evidence.len(),
            1,
            "pending queue must survive restart"
        );
        assert_eq!(
            engine.broadcast_evidence.len(),
            1,
            "broadcast queue must survive restart"
        );
        assert_eq!(engine.pending_evidence[0].slot, 50);
        assert_eq!(engine.pending_evidence[0].signer, signer_addr);

        // Dedup set is also restored — a repeat gossip would be dropped.
        assert!(engine.seen_evidence.contains(&(50, signer_addr)));
    }

    // ========== End-to-end: drain evidence → Slash tx → state mutation ==========

    #[test]
    fn drain_evidence_builds_signed_slash_tx() {
        use pyde_crypto::falcon::falcon_keygen;

        // Set up a validator (the submitter) with a real FALCON key. This
        // is the validator that will build the block and submit evidence.
        let (pk, sk) = falcon_keygen().unwrap();
        let submitter_addr = pyde_account::address::derive_eoa_address(pk.as_bytes());
        let (kem_pk, kem_sk) = pyde_crypto::kyber::kyber_keygen().unwrap();
        let identity = ValidatorIdentity {
            address: submitter_addr,
            public_key: pk.clone(),
            secret_key: sk,
            committee_index: 0,
            key_share: None,
            kem_public_key: kem_pk,
            kem_secret_key: kem_sk,
        };

        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        engine
            .pending_evidence
            .push(evidence_fixture(42, [0xFF; 32]));

        let mut out = Vec::new();
        let next = engine.drain_evidence_into_slash_txs(&identity, 7, 1, &mut out);

        assert_eq!(out.len(), 1);
        assert_eq!(next, 8);
        let tx = &out[0];
        assert_eq!(tx.from, submitter_addr);
        assert_eq!(tx.nonce, 7);
        assert_eq!(tx.chain_id, 1);
        assert!(matches!(tx.tx_type, pyde_tx::types::TransactionType::Slash));
        assert!(!tx.signature.is_empty(), "tx must be signed");
        // submitter field was rewritten from [0; 32] → submitter_addr during drain
        assert!(engine.pending_evidence.is_empty());
    }

    #[test]
    fn end_to_end_detection_to_on_chain_slash() {
        // This exercises the full slice B pipeline without driving VRF/
        // proposal verification: craft real evidence, push it, drain into
        // a signed Slash tx, execute against an SMT, assert state
        // mutations. It's what a validator would do on every block
        // proposal when its pending_evidence queue is non-empty.
        use pyde_crypto::falcon::{falcon_keygen, falcon_sign};
        use pyde_slashing::VALIDATOR_STAKE;
        use pyde_state::smt::PydeSMT;
        use pyde_tx::pipeline::{execute_transaction, BlockContext};

        // Offender: produces the two conflicting signatures.
        let (offender_pk, offender_sk) = falcon_keygen().unwrap();
        let offender_addr = pyde_account::address::derive_eoa_address(offender_pk.as_bytes());

        // Submitter: the validator building the block (and receiving the fee).
        let (submitter_pk, submitter_sk) = falcon_keygen().unwrap();
        let submitter_addr = pyde_account::address::derive_eoa_address(submitter_pk.as_bytes());

        // Stand up an SMT with the offender registered as an Active
        // validator (status 0x00) and the submitter funded. Uses the
        // unified ValidatorEntry encoder so the fixture tracks the
        // live wire format.
        let mut smt = PydeSMT::new();
        let entry = pyde_tx::pipeline::ValidatorEntry {
            pk: offender_pk.as_bytes().to_vec(),
            stake: VALIDATOR_STAKE,
            status: 0x00,
            last_claimed_at: 0,
            exit_block: None,
            kem_pk: None,
        };
        smt.insert(
            pyde_state::keys::validator_key(&offender_addr),
            entry.encode(),
        )
        .unwrap();
        // Mirror the active-count bookkeeping the real StakeDeposit path
        // would have done, so the slash decrement leaves the counter
        // non-negative.
        pyde_tx::pipeline::increment_active_validator_count(&mut smt);

        let mut submitter_account = pyde_account::types::Account::new_eoa(submitter_pk.as_bytes());
        submitter_account.address = submitter_addr;
        submitter_account.balance = 1_000_000_000_000; // 1K PYDE, plenty for gas
        smt.insert(
            pyde_state::keys::balance_key(&submitter_addr),
            submitter_account.to_bytes(),
        )
        .unwrap();
        smt.insert(
            pyde_state::keys::nonce_key(&submitter_addr),
            pyde_account::nonce::NonceState::new().to_bytes().to_vec(),
        )
        .unwrap();

        // Craft two real FALCON-signed attestations for the same slot —
        // exactly what an equivocating proposer would produce. Use the
        // chain_id we'll execute against (set on `ctx` below) so the
        // pipeline's verifier rebuild matches.
        let chain_id = 1u64;
        let slot = 100u64;
        let hash_1 = [0xA1u8; 32];
        let hash_2 = [0xA2u8; 32];
        let sign_msg_1 = pyde_consensus::hotstuff::proposer_sign_message(chain_id, slot, &hash_1);
        let sign_msg_2 = pyde_consensus::hotstuff::proposer_sign_message(chain_id, slot, &hash_2);
        let sig_1 = falcon_sign(&offender_sk, &sign_msg_1)
            .unwrap()
            .as_bytes()
            .to_vec();
        let sig_2 = falcon_sign(&offender_sk, &sign_msg_2)
            .unwrap()
            .as_bytes()
            .to_vec();

        // Push into the engine's queue, exactly as the detection site does.
        let (sub_kem_pk, sub_kem_sk) = pyde_crypto::kyber::kyber_keygen().unwrap();
        let identity = ValidatorIdentity {
            address: submitter_addr,
            public_key: submitter_pk,
            secret_key: submitter_sk,
            committee_index: 0,
            key_share: None,
            kem_public_key: sub_kem_pk,
            kem_secret_key: sub_kem_sk,
        };
        // Engine is bound to the same chain_id as the block context so
        // its `ingest_evidence` (when used) and on-chain handler agree.
        let mut engine = ValidatorEngine::new(chain_id, [0xAA; 32]);
        engine.pending_evidence.push(DoubleSignEvidence {
            slot,
            block_hash_1: hash_1,
            signature_1: sig_1,
            block_hash_2: hash_2,
            signature_2: sig_2,
            signer: offender_addr,
            submitter: [0u8; 32], // filled by drain
        });

        // Drain into Slash txs.
        let mut slash_txs = Vec::new();
        engine.drain_evidence_into_slash_txs(&identity, 0, chain_id, &mut slash_txs);
        assert_eq!(slash_txs.len(), 1);

        // Execute on the SMT.
        let ctx = BlockContext {
            height: 101,
            timestamp: 1_000_000,
            base_fee: 1_000,
            block_gas_limit: 400_000_000,
            chain_id,
            validator_address: [0xEE; 32],
            dev_skip_signature: false,
            block_sigs_pre_verified: false,
        };
        let receipt = execute_transaction(&slash_txs[0], &mut smt, &ctx).unwrap();
        assert!(
            receipt.success,
            "on-chain slash must succeed with real evidence"
        );

        // Offender: stake 0, status Ejected.
        let val_data = smt
            .get(&pyde_state::keys::validator_key(&offender_addr))
            .expect("validator entry still present");
        let entry = pyde_tx::pipeline::ValidatorEntry::decode(&val_data).unwrap();
        assert_eq!(entry.stake, 0, "offender stake must be fully slashed");
        assert_eq!(entry.status, 0x02, "offender must be marked Ejected");

        // Submitter: balance increased by finder's fee (10% of stake) minus gas.
        let raw = smt
            .get(&pyde_state::keys::balance_key(&submitter_addr))
            .unwrap();
        let acc = pyde_account::types::Account::from_bytes(&raw).unwrap();
        let expected_fee = VALIDATOR_STAKE / 10;
        let gas_cost = receipt.gas_used as u128 * ctx.base_fee;
        assert_eq!(
            acc.balance,
            1_000_000_000_000 + expected_fee - gas_cost,
            "submitter must net finder's fee minus gas"
        );

        // Queue is drained.
        assert!(engine.pending_evidence.is_empty());
    }

    #[test]
    fn qc_forms_with_dynamic_quorum() {
        // 3-member committee: quorum_for_committee(3) = 2
        // Simulate multi-node: each validator has its own engine for voting,
        // but votes are collected in one engine for QC formation.
        let (_, identities) = make_engine_with_committee(3);
        let committee_keys: Vec<Vec<u8>> = identities
            .iter()
            .map(|id| id.public_key.as_bytes().to_vec())
            .collect();

        let header = BlockHeader {
            slot: 1,
            epoch: 0,
            parent_hash: [0u8; 32],
            proposer: identities[0].address,
            vrf_proof: vec![],
            qc_previous: QuorumCert::empty(),
            tx_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 0,
        };

        // Each validator creates their vote using their own engine
        let mut votes = Vec::new();
        for id in &identities {
            let mut voter_engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
            voter_engine.set_committee(committee_keys.clone());
            voter_engine.advance_slot();
            if let Some(vote) = voter_engine.on_proposal(&header, id) {
                votes.push(vote);
            }
        }
        assert_eq!(votes.len(), 3);

        // Collect votes in a single engine (simulates the proposer node)
        let mut collector = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        collector.set_committee(committee_keys);
        collector.advance_slot();

        let mut qc_formed = false;
        for vote in votes {
            if let Some(qc) = collector.on_vote(vote) {
                qc_formed = true;
                assert!(qc.vote_count() >= 2);
            }
        }

        assert!(
            qc_formed,
            "QC should form with 3 votes in 3-member committee (quorum=2)"
        );
    }

    #[test]
    fn two_node_qc_requires_both_votes() {
        // 2-member committee: quorum_for_committee(2) = 2
        let (_, identities) = make_engine_with_committee(2);
        let committee_keys: Vec<Vec<u8>> = identities
            .iter()
            .map(|id| id.public_key.as_bytes().to_vec())
            .collect();

        let header = BlockHeader {
            slot: 1,
            epoch: 0,
            parent_hash: [0u8; 32],
            proposer: identities[0].address,
            vrf_proof: vec![],
            qc_previous: QuorumCert::empty(),
            tx_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 0,
        };

        // Each validator votes using their own engine
        let mut votes = Vec::new();
        for id in &identities {
            let mut voter_engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
            voter_engine.set_committee(committee_keys.clone());
            voter_engine.advance_slot();
            if let Some(vote) = voter_engine.on_proposal(&header, id) {
                votes.push(vote);
            }
        }
        assert_eq!(votes.len(), 2);

        // Collector engine
        let mut collector = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        collector.set_committee(committee_keys);
        collector.advance_slot();

        // First vote — not enough
        assert!(
            collector.on_vote(votes[0].clone()).is_none(),
            "1/2 votes should not form QC"
        );

        // Second vote — QC forms
        let qc = collector.on_vote(votes[1].clone());
        assert!(qc.is_some(), "2/2 votes should form QC");
        assert_eq!(qc.unwrap().vote_count(), 2);
    }

    #[test]
    fn old_votes_pruned() {
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0; 32]);
        engine.votes.insert(
            1,
            SlotVotes {
                block_hash: [0; 32],
                votes: vec![],
            },
        );
        engine.votes.insert(
            5,
            SlotVotes {
                block_hash: [0; 32],
                votes: vec![],
            },
        );

        // Audit-94: prune_floor = min(slot - 10, target_height). To
        // exercise the steady-state pruning path (not the wedged-
        // chain protective clamp), advance target_height beyond
        // the prune_before cutoff so the floor is `slot - 10`.
        engine.consensus.target_height = 10;
        // Advance past slot 15 to trigger pruning (prune < slot - 10 = 5)
        engine.consensus.current_slot = 14;
        engine.advance_slot(); // now at 15

        assert!(!engine.votes.contains_key(&1)); // pruned
        assert!(engine.votes.contains_key(&5)); // kept (>= 5)
    }

    #[test]
    fn build_proposal_creates_block() {
        let (engine, identities) = make_engine_with_committee(1);

        let block = engine.build_proposal(
            &identities[0],
            [0u8; 32],
            [0xBB; 32],
            [0xCC; 32],
            vec![0xDD; 100],
            vec![],
            vec![],
            ExecutionSchedule {
                groups: vec![],
                total_txs: 0,
            },
        );

        assert_eq!(block.slot(), 0);
        assert_eq!(block.header.proposer, identities[0].address);
        assert_eq!(block.header.state_root, [0xBB; 32]);
        assert_eq!(block.header.tx_root, [0xCC; 32]);
    }

    // ========== Stake verification ==========

    #[test]
    fn sufficient_stake_accepted() {
        assert!(verify_stake(VALIDATOR_STAKE).is_ok());
        assert!(verify_stake(VALIDATOR_STAKE + 1).is_ok());
    }

    #[test]
    fn insufficient_stake_rejected() {
        assert!(verify_stake(VALIDATOR_STAKE - 1).is_err());
        assert!(verify_stake(0).is_err());
    }

    // ========== Threshold decryption ==========

    #[test]
    fn generate_shares_without_key_share_returns_none() {
        let (engine, identities) = make_engine_with_committee(1);
        // identity has key_share = None
        let shares = engine.generate_decryption_shares(&identities[0], &[]);
        assert!(shares.is_none());
    }

    #[test]
    fn generate_shares_with_key_share() {
        let (engine, _) = make_engine_with_committee(1);
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let address = derive_eoa_address(&pk_bytes);

        // Create threshold keys and assign one share
        let (tpk, key_shares) = pyde_crypto::threshold::threshold_keygen(3, 2).unwrap();
        let (kem_pk_a, kem_sk_a) = pyde_crypto::kyber::kyber_keygen().unwrap();

        let identity = ValidatorIdentity {
            address,
            public_key: pk,
            secret_key: sk,
            committee_index: 0,
            key_share: Some(key_shares[0].clone()),
            kem_public_key: kem_pk_a,
            kem_secret_key: kem_sk_a,
        };

        // Create an encrypted tx to generate shares for
        let to = derive_eoa_address(b"to");
        let enc_tx = pyde_mempool::encrypted::encrypt_transaction(
            address,
            0,
            50_000,
            vec![pyde_tx::types::AccessEntry {
                address: derive_eoa_address(b"contract"),
                reads: vec![[0x01; 32]],
                writes: vec![],
            }],
            None,
            1,
            vec![0xAA; 666],
            &to,
            0,
            b"",
            &tpk,
        )
        .unwrap();

        let shares = engine.generate_decryption_shares(&identity, &[enc_tx]);
        assert!(shares.is_some());
        assert_eq!(shares.unwrap().len(), 1);
    }

    #[test]
    fn start_decryption_creates_decryptor() {
        let (engine, _) = make_engine_with_committee(1);
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let address = derive_eoa_address(&pk_bytes);

        let (tpk, key_shares) = pyde_crypto::threshold::threshold_keygen(3, 2).unwrap();
        let (kem_pk_b, kem_sk_b) = pyde_crypto::kyber::kyber_keygen().unwrap();

        let identity = ValidatorIdentity {
            address,
            public_key: pk,
            secret_key: sk,
            committee_index: 0,
            key_share: Some(key_shares[0].clone()),
            kem_public_key: kem_pk_b,
            kem_secret_key: kem_sk_b,
        };

        let to = derive_eoa_address(b"to");
        let enc_tx = pyde_mempool::encrypted::encrypt_transaction(
            address,
            0,
            50_000,
            vec![pyde_tx::types::AccessEntry {
                address: derive_eoa_address(b"contract"),
                reads: vec![[0x01; 32]],
                writes: vec![],
            }],
            None,
            1,
            vec![0xAA; 666],
            &to,
            0,
            b"",
            &tpk,
        )
        .unwrap();

        // TPL-301: BlockDecryptor needs the committee's FALCON pks;
        // for this single-node smoke test the only validator IS our
        // identity, holding share-index 1.
        let committee_pks = vec![identity.public_key.clone()];
        let decryptor = engine
            .start_decryption(&identity, vec![enc_tx], 2, committee_pks)
            .unwrap();
        assert_eq!(decryptor.tx_count(), 1);
        assert_eq!(decryptor.share_count(0), 1); // our own share added
    }

    // ==========================================================================
    // Task 031 + 032: multi-node MEV lifecycle + frontrun rejection
    // ==========================================================================
    //
    // These tests orchestrate three simulated validators through the full MEV
    // pipeline: submit encrypted tx → block build → body validation → plaintext
    // execution → threshold decryption → decrypted execution → state root
    // convergence. Networking is stubbed (direct function calls between
    // engines) so the tests are deterministic and fast — real libp2p transport
    // is exercised separately by `auth_handshake.rs` + `reshare_handshake.rs`.

    use crate::block_processor::{try_decrypt_and_execute, BlockProcessor, DecryptOutcome};
    use crate::block_store::BlockStore;
    use crate::chain::ChainState;
    use crate::state_manager::StateManager;
    use crate::wire;
    use pyde_consensus::block::{Block, BlockBody};
    use pyde_mempool::decryption::BlockDecryptor;
    use pyde_mempool::encrypted::{encrypt_transaction, EncryptedTx};
    use pyde_tx::parallel::ExecutionSchedule;
    use pyde_tx::types::AccessEntry;
    use tempfile::TempDir;

    /// Per-node test rig for the MEV e2e scenarios.
    struct E2ENode {
        state: StateManager,
        chain: ChainState,
        block_store: BlockStore,
        key_share: pyde_crypto::threshold::KeyShare,
        _tmp: TempDir,
    }

    impl E2ENode {
        fn new(key_share: pyde_crypto::threshold::KeyShare, chain_id: u64) -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let state = StateManager::open(tmp.path(), 1024).unwrap();
            let block_store = BlockStore::open(tmp.path()).unwrap();
            let chain = ChainState::genesis(state.root(), chain_id);
            Self {
                state,
                chain,
                block_store,
                key_share,
                _tmp: tmp,
            }
        }
    }

    fn e2e_header(
        slot: u64,
        parent_hash: [u8; 32],
        state_root: [u8; 32],
        tx_root: [u8; 32],
    ) -> BlockHeader {
        BlockHeader {
            slot,
            epoch: 0,
            parent_hash,
            proposer: [0u8; 32],
            vrf_proof: vec![],
            qc_previous: QuorumCert::empty(),
            tx_root,
            state_root,
            timestamp: slot * 400,
        }
    }

    fn e2e_access_list() -> Vec<AccessEntry> {
        vec![AccessEntry {
            address: [0x01; 32],
            reads: vec![[0x01; 32]],
            writes: vec![],
        }]
    }

    fn e2e_signed_encrypted(
        tpk: &pyde_crypto::threshold::ThresholdPublicKey,
        sender_keys: &(
            pyde_crypto::falcon::FalconPublicKey,
            pyde_crypto::falcon::FalconSecretKey,
        ),
        recipient: Address,
        value: u128,
        nonce: u64,
    ) -> EncryptedTx {
        let (pk, sk) = sender_keys;
        let sender = pyde_account::address::derive_eoa_address(pk.as_bytes());
        let template = encrypt_transaction(
            sender,
            nonce,
            100_000,
            e2e_access_list(),
            None,
            31337,
            vec![0u8; 666],
            &recipient,
            value,
            b"",
            tpk,
        )
        .unwrap();
        let hash = template.hash();
        let sig = pyde_crypto::falcon::falcon_sign(sk, &hash)
            .unwrap()
            .to_vec();
        EncryptedTx {
            sender,
            nonce,
            gas_limit: 100_000,
            access_list: template.access_list.clone(),
            deadline: None,
            chain_id: 31337,
            signature: sig,
            ciphertext: template.ciphertext.clone(),
        }
    }

    #[test]
    fn e2e_encrypted_tx_lifecycle_three_validators() {
        // TASK 031: submit encrypted tx → commit → decrypt → seal.
        //
        // Three validators with a 2-of-3 threshold. A transfer from Alice
        // (funded at genesis) to Bob gets encrypted, committed to a block,
        // threshold-decrypted, and applied. Final state root matches across
        // all three validators — the strongest property we can assert
        // about MEV-protected txs in one test.
        use pyde_crypto::falcon::falcon_keygen;
        use pyde_crypto::threshold::threshold_keygen;

        let (tpk, key_shares) = threshold_keygen(3, 2).unwrap();
        let alice_keys = falcon_keygen().unwrap();
        let alice = pyde_account::address::derive_eoa_address(alice_keys.0.as_bytes());
        let bob = pyde_account::address::derive_eoa_address(b"bob-recipient");

        // TPL-301: each validator gets a FALCON keypair for signing
        // its decryption shares; the public-key vector is used by
        // combine_shares to verify each share.
        let mut committee_falcon_pks =
            Vec::<pyde_crypto::falcon::FalconPublicKey>::with_capacity(3);
        let mut committee_falcon_sks =
            Vec::<pyde_crypto::falcon::FalconSecretKey>::with_capacity(3);
        for _ in 0..3 {
            let (pk, sk) = falcon_keygen().unwrap();
            committee_falcon_pks.push(pk);
            committee_falcon_sks.push(sk);
        }

        let mut nodes: Vec<E2ENode> = key_shares
            .iter()
            .take(3)
            .map(|ks| E2ENode::new(ks.clone(), 31337))
            .collect();

        // Fund Alice with an on-chain account (balance + FALCON pubkey
        // for signature verification during decrypted-tx execution).
        // Bypasses real genesis config to keep the test narrow.
        let starting_balance: u128 = 10_000_000_000_000_000_000_u128; // plenty for gas + transfer
        let mut alice_account = pyde_account::types::Account::new_eoa(alice_keys.0.as_bytes());
        alice_account.balance = starting_balance;
        let account_bytes = alice_account.to_bytes();
        for node in &mut nodes {
            let key = pyde_state::keys::balance_key(&alice);
            node.state.insert(key, account_bytes.clone()).unwrap();
            node.state.refresh_root();
            node.chain = ChainState::genesis(node.state.root(), 31337);
        }
        assert_eq!(nodes[0].state.root(), nodes[1].state.root());
        assert_eq!(nodes[1].state.root(), nodes[2].state.root());

        // Alice encrypts a 100-quanta transfer to Bob.
        let enc_tx = e2e_signed_encrypted(&tpk, &alice_keys, bob, 100, 0);
        let encrypted_body: Vec<Vec<u8>> = vec![enc_tx.to_bytes()];
        let tx_root = pyde_consensus::block::compute_tx_root(&[], &[enc_tx.hash()]);

        let starting_root = nodes[0].state.root();
        let header = e2e_header(1, [0u8; 32], starting_root, tx_root);
        let block = Block {
            header: header.clone(),
            body: BlockBody {
                transactions: vec![],
                encrypted_txs: encrypted_body.clone(),
                execution_schedule: ExecutionSchedule {
                    groups: vec![],
                    total_txs: 0,
                },
            },
            proposer_signature: vec![],
        };

        // Every validator processes the block. Body validation runs the
        // tx_root check from slice 3.1; execution advances chain state.
        // Storing the raw block lets the decrypt path fetch it later.
        let raw = wire::encode_block(&block);
        for node in &mut nodes {
            BlockProcessor::validate_block_body(&block, &node.state, 31337)
                .expect("honest block must pass body validation");
            node.block_store.put_block(&header, &raw).unwrap();
            BlockProcessor::process_full_block(&mut node.chain, &mut node.state, &block)
                .expect("honest block must process");
        }
        for n in &nodes {
            assert_eq!(n.chain.head_slot, 1);
        }

        // Each validator produces a decryption share. In production these
        // ride the consensus gossip topic post-QC; we collect them directly.
        let shares: Vec<_> = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| {
                pyde_crypto::threshold::generate_decryption_share(
                    &n.key_share,
                    &enc_tx.ciphertext,
                    &committee_falcon_sks[i],
                )
                .unwrap()
            })
            .collect();

        // Every validator then runs the decrypt+execute path. Uses the
        // same `try_decrypt_and_execute` helper the production node loop
        // calls — so the MEV invariant check (slice 3.1's second-chance
        // tx_root verify) fires on every node.
        for node in &mut nodes {
            let mut decryptor =
                BlockDecryptor::new(vec![enc_tx.clone()], 2, committee_falcon_pks.clone()).unwrap();
            decryptor.add_share(0, shares[0].clone());
            decryptor.add_share(0, shares[1].clone());
            assert!(decryptor.all_ready());
            let outcome = try_decrypt_and_execute(
                &node.block_store,
                1,
                &mut decryptor,
                &mut node.state,
                400_000_000,
                1_000_000_000,
                31337,
                [0u8; 32],
            );
            assert!(
                matches!(outcome, DecryptOutcome::Executed { tx_count: 1, .. }),
                "decrypt+execute must succeed on every validator; got {:?}",
                outcome
            );
        }

        // All three validators converged on the same post-decryption
        // state root, AND the root actually changed — the decrypted
        // transfer produced a real write. Both properties together are
        // the end-to-end MEV guarantee: every validator applied the
        // committed ordering and ended up with the same correct state.
        let final_root = nodes[0].state.root();
        assert_eq!(nodes[1].state.root(), final_root);
        assert_eq!(nodes[2].state.root(), final_root);
        assert_ne!(final_root, starting_root);

        // Bob got his transfer, Alice's balance dropped (ignoring gas).
        let bob_key = pyde_state::keys::balance_key(&bob);
        let bob_raw = nodes[0].state.get(&bob_key).expect("bob should exist");
        // Account format: parse as Account if it decodes, else u128 LE.
        let bob_balance = pyde_account::types::Account::from_bytes(&bob_raw)
            .map(|a| a.balance)
            .unwrap_or_else(|| {
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&bob_raw[..16]);
                u128::from_le_bytes(buf)
            });
        assert_eq!(bob_balance, 100, "bob received the 100-quanta transfer");
    }

    #[test]
    fn e2e_frontrun_by_reorder_is_rejected() {
        // TASK 032: any attempt to reorder encrypted_txs after QC breaks
        // the tx_root → header hash → proposer-signature chain. Body
        // validation rejects the tampered block before decryption.
        use pyde_crypto::threshold::threshold_keygen;
        let (tpk, _) = threshold_keygen(3, 2).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let state = StateManager::open(tmp.path(), 1024).unwrap();

        let tx_a = encrypt_transaction(
            [0xAA; 32],
            0,
            100_000,
            e2e_access_list(),
            None,
            31337,
            vec![0xAA; 666],
            &[0x11; 32],
            100,
            b"swap-a",
            &tpk,
        )
        .unwrap();
        let tx_b = encrypt_transaction(
            [0xBB; 32],
            1,
            100_000,
            e2e_access_list(),
            None,
            31337,
            vec![0xBB; 666],
            &[0x22; 32],
            200,
            b"swap-b",
            &tpk,
        )
        .unwrap();

        // Honest tx_root commits to [A, B]; tampered body ships [B, A].
        let honest_tx_root =
            pyde_consensus::block::compute_tx_root(&[], &[tx_a.hash(), tx_b.hash()]);
        let header = e2e_header(1, [0u8; 32], state.root(), honest_tx_root);
        let tampered = Block {
            header,
            body: BlockBody {
                transactions: vec![],
                encrypted_txs: vec![tx_b.to_bytes(), tx_a.to_bytes()],
                execution_schedule: ExecutionSchedule {
                    groups: vec![],
                    total_txs: 0,
                },
            },
            proposer_signature: vec![],
        };

        let err = BlockProcessor::validate_block_body(&tampered, &state, 31337)
            .expect_err("tampered block must be rejected");
        assert!(
            err.contains("tx_root mismatch"),
            "expected tx_root mismatch, got: {}",
            err
        );
    }

    #[test]
    fn e2e_frontrun_by_injection_is_rejected() {
        // Injection variant of 032: attacker prepends a sandwich-front tx
        // hoping to execute before the victim. tx_root committed to just
        // the victim, so the injected tx breaks validation.
        use pyde_crypto::threshold::threshold_keygen;
        let (tpk, _) = threshold_keygen(3, 2).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let state = StateManager::open(tmp.path(), 1024).unwrap();

        let victim = encrypt_transaction(
            [0xAA; 32],
            0,
            100_000,
            e2e_access_list(),
            None,
            31337,
            vec![0xAA; 666],
            &[0x11; 32],
            100,
            b"victim-swap",
            &tpk,
        )
        .unwrap();
        let sandwich_front = encrypt_transaction(
            [0xEE; 32],
            0,
            100_000,
            e2e_access_list(),
            None,
            31337,
            vec![0xEE; 666],
            &[0x22; 32],
            50_000,
            b"front",
            &tpk,
        )
        .unwrap();

        let honest_tx_root = pyde_consensus::block::compute_tx_root(&[], &[victim.hash()]);
        let header = e2e_header(1, [0u8; 32], state.root(), honest_tx_root);
        let tampered = Block {
            header,
            body: BlockBody {
                transactions: vec![],
                encrypted_txs: vec![sandwich_front.to_bytes(), victim.to_bytes()],
                execution_schedule: ExecutionSchedule {
                    groups: vec![],
                    total_txs: 0,
                },
            },
            proposer_signature: vec![],
        };

        let err = BlockProcessor::validate_block_body(&tampered, &state, 31337)
            .expect_err("injection must be rejected");
        assert!(err.contains("tx_root mismatch"), "got: {}", err);
    }

    #[test]
    fn e2e_byzantine_proposer_forged_encrypted_tx_rejected_at_execute() {
        // REGRESSION TEST for the malicious-proposer hole surfaced during
        // slice 3.6. A byzantine proposer includes an EncryptedTx with a
        // forged sender (bypasses mempool admission entirely). The
        // committee decrypts it (crypto works), but execution must reject
        // because the FALCON signature doesn't verify against Alice's
        // on-chain auth key.
        use pyde_crypto::falcon::falcon_keygen;
        use pyde_crypto::threshold::threshold_keygen;

        let (tpk, key_shares) = threshold_keygen(3, 2).unwrap();
        let alice_keys = falcon_keygen().unwrap();
        let alice = pyde_account::address::derive_eoa_address(alice_keys.0.as_bytes());
        let attacker = pyde_account::address::derive_eoa_address(b"attacker");

        // TPL-301: committee FALCON keypairs for share signing /
        // verification.
        let mut committee_falcon_pks =
            Vec::<pyde_crypto::falcon::FalconPublicKey>::with_capacity(3);
        let mut committee_falcon_sks =
            Vec::<pyde_crypto::falcon::FalconSecretKey>::with_capacity(3);
        for _ in 0..3 {
            let (pk, sk) = falcon_keygen().unwrap();
            committee_falcon_pks.push(pk);
            committee_falcon_sks.push(sk);
        }

        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let bs = BlockStore::open(tmp.path()).unwrap();

        // Alice funded with proper on-chain auth key.
        let mut alice_account = pyde_account::types::Account::new_eoa(alice_keys.0.as_bytes());
        alice_account.balance = 10_000_000_000_000_000_000_u128;
        state
            .insert(
                pyde_state::keys::balance_key(&alice),
                alice_account.to_bytes(),
            )
            .unwrap();
        state.refresh_root();

        // Byzantine proposer forges: sender=alice, garbage sig, but the
        // transfer ciphertext actually moves Alice's funds to attacker.
        // (In a real attack the sig would be something plausible-looking,
        // but a 666-byte garbage blob is indistinguishable at mempool
        // structural check.)
        let template = encrypt_transaction(
            alice,
            0,
            100_000,
            e2e_access_list(),
            None,
            31337,
            vec![0xFF; 666],
            &attacker,
            1_000,
            b"",
            &tpk,
        )
        .unwrap();
        let forged = EncryptedTx {
            sender: alice, // plaintext — attacker claims to be alice
            nonce: 0,
            gas_limit: 100_000,
            access_list: template.access_list,
            deadline: None,
            chain_id: 31337,
            signature: vec![0xFF; 666], // garbage — NOT signed by alice
            ciphertext: template.ciphertext,
        };
        let forged_hash = forged.hash();

        // Proposer puts it in a block with the correct tx_root (they're
        // building the block, so they can commit to whatever they're
        // shipping — slice 3.1's ordering commitment doesn't help here,
        // this is a different attack).
        let tx_root = pyde_consensus::block::compute_tx_root(&[], &[forged_hash]);
        let header = e2e_header(1, [0u8; 32], state.root(), tx_root);
        let block = Block {
            header: header.clone(),
            body: BlockBody {
                transactions: vec![],
                encrypted_txs: vec![forged.to_bytes()],
                execution_schedule: ExecutionSchedule {
                    groups: vec![],
                    total_txs: 0,
                },
            },
            proposer_signature: vec![],
        };
        bs.put_block(&header, &wire::encode_block(&block)).unwrap();

        // Body validation passes (tx_root matches) — this is NOT what
        // catches the attack.
        BlockProcessor::validate_block_body(&block, &state, 31337).unwrap();

        let before_root = state.root();
        let before_balance = 10_000_000_000_000_000_000_u128;

        // Run decryption + execution. The FALCON sig won't verify against
        // Alice's on-chain pubkey over EncryptedTx::hash(), so the tx is
        // dropped BEFORE it can move her funds.
        let shares: Vec<_> = key_shares
            .iter()
            .enumerate()
            .take(2)
            .map(|(i, ks)| {
                pyde_crypto::threshold::generate_decryption_share(
                    ks,
                    &forged.ciphertext,
                    &committee_falcon_sks[i],
                )
                .unwrap()
            })
            .collect();
        let mut decryptor =
            BlockDecryptor::new(vec![forged], 2, committee_falcon_pks.clone()).unwrap();
        decryptor.add_share(0, shares[0].clone());
        decryptor.add_share(0, shares[1].clone());
        let outcome = try_decrypt_and_execute(
            &bs,
            1,
            &mut decryptor,
            &mut state,
            400_000_000,
            1_000_000_000,
            31337,
            [0u8; 32],
        );

        // Outcome reports zero verified txs executed (the forged one
        // was dropped).
        match outcome {
            DecryptOutcome::Executed { tx_count, .. } => {
                assert_eq!(tx_count, 0, "forged tx must NOT be counted as executed");
            }
            other => panic!("unexpected outcome: {:?}", other),
        }

        // Alice's balance is untouched. Root may change due to SMT
        // bookkeeping, but the balance key must still hold her original
        // funds.
        let alice_raw = state.get(&pyde_state::keys::balance_key(&alice)).unwrap();
        let alice_acct = pyde_account::types::Account::from_bytes(&alice_raw).unwrap();
        assert_eq!(
            alice_acct.balance, before_balance,
            "alice's funds must be untouched by the forged tx"
        );
        let _ = before_root;
    }

    #[test]
    fn e2e_decrypted_ordering_matches_committed_ordering() {
        // Completes the "committed → executed" chain: if a block commits
        // to encrypted order [A, B], the decrypted txs must execute in
        // THAT order, not whatever a malicious validator might prefer.
        // A tampered decryptor (one that reorders encrypted_txs) is
        // rejected by try_decrypt_and_execute's secondary tx_root check.
        use pyde_crypto::falcon::falcon_keygen;
        use pyde_crypto::threshold::threshold_keygen;
        let (tpk, shares) = threshold_keygen(3, 2).unwrap();

        // TPL-301: committee FALCON keypairs for share signing /
        // verification.
        let mut committee_falcon_pks =
            Vec::<pyde_crypto::falcon::FalconPublicKey>::with_capacity(3);
        let mut committee_falcon_sks =
            Vec::<pyde_crypto::falcon::FalconSecretKey>::with_capacity(3);
        for _ in 0..3 {
            let (pk, sk) = falcon_keygen().unwrap();
            committee_falcon_pks.push(pk);
            committee_falcon_sks.push(sk);
        }

        // Both senders get FALCON-backed accounts so execute-time auth
        // verification accepts the honest txs. (Proves the ordering
        // invariant independently of the byzantine-proposer auth hole.)
        let sender_a_keys = falcon_keygen().unwrap();
        let sender_b_keys = falcon_keygen().unwrap();
        let tx_a = e2e_signed_encrypted(&tpk, &sender_a_keys, [0x11; 32], 100, 0);
        let tx_b = e2e_signed_encrypted(&tpk, &sender_b_keys, [0x22; 32], 200, 0);

        let committed_root =
            pyde_consensus::block::compute_tx_root(&[], &[tx_a.hash(), tx_b.hash()]);
        let header = e2e_header(1, [0u8; 32], [0u8; 32], committed_root);
        let block = Block {
            header: header.clone(),
            body: BlockBody {
                transactions: vec![],
                encrypted_txs: vec![tx_a.to_bytes(), tx_b.to_bytes()],
                execution_schedule: ExecutionSchedule {
                    groups: vec![],
                    total_txs: 0,
                },
            },
            proposer_signature: vec![],
        };
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let bs = BlockStore::open(tmp.path()).unwrap();
        bs.put_block(&header, &wire::encode_block(&block)).unwrap();

        // Fund each sender account so the honest-path auth check passes.
        // Balances are ample for the transfer + gas.
        for keys in [&sender_a_keys, &sender_b_keys] {
            let addr = pyde_account::address::derive_eoa_address(keys.0.as_bytes());
            let mut acct = pyde_account::types::Account::new_eoa(keys.0.as_bytes());
            acct.balance = 10_000_000_000_000_000_000_u128;
            state
                .insert(pyde_state::keys::balance_key(&addr), acct.to_bytes())
                .unwrap();
        }
        state.refresh_root();

        // Honest decryptor, committed order [A, B].
        let mut honest =
            BlockDecryptor::new(vec![tx_a.clone(), tx_b.clone()], 2, committee_falcon_pks.clone())
                .unwrap();
        honest.add_share(
            0,
            pyde_crypto::threshold::generate_decryption_share(
                &shares[0],
                &tx_a.ciphertext,
                &committee_falcon_sks[0],
            )
            .unwrap(),
        );
        honest.add_share(
            0,
            pyde_crypto::threshold::generate_decryption_share(
                &shares[1],
                &tx_a.ciphertext,
                &committee_falcon_sks[1],
            )
            .unwrap(),
        );
        honest.add_share(
            1,
            pyde_crypto::threshold::generate_decryption_share(
                &shares[0],
                &tx_b.ciphertext,
                &committee_falcon_sks[0],
            )
            .unwrap(),
        );
        honest.add_share(
            1,
            pyde_crypto::threshold::generate_decryption_share(
                &shares[1],
                &tx_b.ciphertext,
                &committee_falcon_sks[1],
            )
            .unwrap(),
        );
        let honest_outcome = try_decrypt_and_execute(
            &bs,
            1,
            &mut honest,
            &mut state,
            400_000_000,
            1_000_000_000,
            31337,
            [0u8; 32],
        );
        assert!(
            matches!(honest_outcome, DecryptOutcome::Executed { tx_count: 2, .. }),
            "honest-order decrypt must run; got {:?}",
            honest_outcome
        );

        // Tampered decryptor flipping to [B, A] is rejected by the
        // second-chance tx_root check in try_decrypt_and_execute.
        let mut tampered = BlockDecryptor::new(vec![tx_b, tx_a], 2, committee_falcon_pks).unwrap();
        let tampered_outcome = try_decrypt_and_execute(
            &bs,
            1,
            &mut tampered,
            &mut state,
            400_000_000,
            1_000_000_000,
            31337,
            [0u8; 32],
        );
        assert!(
            matches!(tampered_outcome, DecryptOutcome::TxRootMismatch),
            "reordered decryptor must be rejected; got {:?}",
            tampered_outcome
        );
    }

    // ========================================================================
    // audit-234 part 4: characterization tests for the (height, view) refactor.
    //
    // These tests express the post-fix behavior described in
    // crates/consensus/CONSENSUS_INVARIANTS.md. They MUST FAIL on the current
    // (audit-234 in-flight) state machine, which uses `current_slot` as the
    // recovery target and permits multiple fallback proposers per slot.
    //
    // They turn green as steps 2-3 of the audit-234 fix sequence land:
    //   - step 2: decouple `target_height` from `current_slot`
    //   - step 3: single deterministic leader per (H, V)
    //
    // Marked `#[ignore]` so the workspace test suite stays green during the
    // refactor; remove the ignore (or re-flip to active) when the
    // corresponding step ships.
    // ========================================================================

    /// Invariant L1 (oldest-unresolved-height): when the wall-clock slot
    /// has drifted past the slot we're trying to commit, view-change must
    /// still target the FAILED slot, not the current wall-clock slot.
    ///
    /// CURRENT behavior: `on_timeout` reads `self.consensus.current_slot`,
    /// so the view-change message targets the wrong slot whenever recovery
    /// takes longer than `SLOT_DURATION_MS`. This is failure mode (1) in
    /// the audit-234 part-4 diagnosis.
    ///
    /// POST-FIX behavior: `on_timeout` should target
    /// `self.consensus.last_committed_slot + 1` — the oldest unresolved
    /// height — regardless of how far `current_slot` has drifted.
    #[test]
    fn slot_drift_does_not_advance_target_height() {
        let (mut engine, identities) = make_engine_with_committee(4);

        // Bootstrap: pretend the chain has committed up through slot 144,
        // and we are now trying to commit slot 145.
        engine.consensus.last_committed_slot = 144;
        engine.consensus.target_height = 145;
        engine.consensus.current_view = 0;
        engine.consensus.current_slot = 145;
        engine.timeout = TimeoutTracker::new(145, current_time_ms());
        let target_height = engine.consensus.target_height;
        assert_eq!(target_height, 145);

        // Wall-clock slot drifts during the recovery delay (gossip, RR
        // delivery, view-change-QC formation). In a real run this is
        // PROGRESS_TIMEOUT_MS / SLOT_DURATION_MS = 5 slot ticks.
        for _ in 0..5 {
            engine.advance_slot();
        }
        let drifted = engine.consensus.current_slot;
        assert_eq!(drifted, 150, "wall-clock slot should have drifted");

        // last_committed_slot is unchanged because no block at 145 has
        // committed yet.
        assert_eq!(
            engine.consensus.last_committed_slot, 144,
            "no block committed during the recovery window"
        );

        // Trigger view-change. Per L1, the resulting message MUST target
        // the oldest unresolved height (145), not the drifted current
        // slot (150). Today this assertion fails — vc_msg.slot == 150.
        let vc_msg = engine
            .on_timeout(&identities[0])
            .expect("on_timeout should produce a view-change message");

        assert_eq!(
            vc_msg.slot, target_height,
            "view-change must target the oldest unresolved height ({target_height}), \
             not the drifted current_slot ({drifted}). \
             See CONSENSUS_INVARIANTS.md L1."
        );
    }

    /// TPL-501: `on_timeout` MUST cache the signed VC's
    /// `(highest_qc.hash(), signature)` into
    /// `seen_view_changes_self` BEFORE returning. The cache is
    /// what the equivocation guard checks on a re-fire (post-
    /// crash restart, retry within the same window, etc.) — if
    /// it's missing, the guard's protective branch never trips
    /// and the validator can sign a divergent VC at the same
    /// target_height for slashing.
    #[test]
    fn tpl_501_on_timeout_caches_seen_vc_record_before_returning() {
        let (mut engine, identities) = make_engine_with_committee(4);
        engine.consensus.target_height = 42;

        let pre_count = engine.seen_view_changes_self.len();
        let msg = engine
            .on_timeout(&identities[0])
            .expect("on_timeout should sign a fresh VC");

        // Cache populated.
        let cached = engine
            .seen_view_changes_self
            .get(&42)
            .expect("seen_view_changes_self must contain the slot we just signed");
        let qc_hash = engine.consensus.highest_qc.hash();
        assert_eq!(cached.0, qc_hash, "cached qc_hash must match current");
        assert_eq!(
            cached.1, msg.signature,
            "cached signature must match the returned VC's signature"
        );
        assert_eq!(engine.seen_view_changes_self.len(), pre_count + 1);
    }

    /// TPL-501: a second `on_timeout` call at the same slot
    /// with the same `highest_qc` is idempotent — returns the
    /// SAME signature bytes. This is the post-restart re-
    /// broadcast branch: a crash between sign and broadcast
    /// preserves the persisted record on disk; on restart we
    /// re-derive the same VC instead of signing a fresh
    /// (potentially-divergent) one.
    #[test]
    fn tpl_501_on_timeout_idempotent_when_highest_qc_unchanged() {
        let (mut engine, identities) = make_engine_with_committee(4);
        engine.consensus.target_height = 42;

        let first = engine.on_timeout(&identities[0]).unwrap();
        let second = engine
            .on_timeout(&identities[0])
            .expect("re-fire should still return the cached signature");

        assert_eq!(first.signature, second.signature);
        assert_eq!(first.slot, second.slot);
        assert_eq!(first.highest_qc.hash(), second.highest_qc.hash());
    }

    /// TPL-501: if `highest_qc` advances at the same
    /// `target_height` between the first sign and a re-fire,
    /// `on_timeout` MUST refuse to sign — signing a fresh VC
    /// over the new (higher) QC at the same slot would
    /// equivocate against the originally-signed message. Pre-
    /// fix this returned `Some(...)` with a divergent
    /// signature; post-fix it returns `None`.
    #[test]
    fn tpl_501_on_timeout_refuses_to_sign_when_highest_qc_advanced() {
        let (mut engine, identities) = make_engine_with_committee(4);
        engine.consensus.target_height = 42;

        let _first = engine
            .on_timeout(&identities[0])
            .expect("first sign should succeed");

        // Mutate `highest_qc` to a different value at the same
        // target_height — simulates a peer-vote QC arriving
        // post-restart but pre-VC-broadcast that advances our
        // local highest_qc to a new shape.
        engine.consensus.highest_qc.slot = 41;
        engine.consensus.highest_qc.block_hash = [0xCC; 32];
        engine.consensus.highest_qc.voter_bitmap = 0b1011;
        engine.consensus.highest_qc.signatures = vec![vec![0xAA; 666]; 3];

        let second = engine.on_timeout(&identities[0]);
        assert!(
            second.is_none(),
            "TPL-501: a different highest_qc at the same target_height MUST trip the equivocation guard, got {:?}",
            second.map(|m| m.signature.len())
        );
    }

    /// TPL-502: when a peer sends two view-change messages from
    /// the same `(slot, voter_index)` covering different
    /// `highest_qc.hash()`es, `on_view_change` constructs
    /// `DoubleViewChangeEvidence` and routes it through
    /// `ingest_view_change_evidence` — same slashing-pipeline
    /// pattern as the proposer/vote double-sign path. Without
    /// the equivocation guard the second VC was just dropped
    /// at the dedup gate and the offender escaped slashing.
    #[test]
    fn tpl_502_on_view_change_detects_equivocation_at_same_slot() {
        let (mut engine, identities) = make_engine_with_committee(4);

        // Two distinct QCs to sign over — same slot, different
        // highest_qc.hash().
        let qc_1 = pyde_consensus::block::QuorumCert::empty();
        let mut qc_2 = pyde_consensus::block::QuorumCert::empty();
        qc_2.slot = 1;
        qc_2.block_hash = [0xCC; 32];
        qc_2.voter_bitmap = 0b011;
        qc_2.signatures = vec![vec![0xAA; 666]; 2];
        // Sanity: hashes really are distinct.
        assert_ne!(qc_1.hash(), qc_2.hash());

        let target_slot = 42;
        let attacker = &identities[1];
        let vc_1 = pyde_consensus::view_change::create_view_change(
            engine.chain_id,
            target_slot,
            &qc_1,
            attacker.committee_index,
            attacker.address,
            &attacker.secret_key,
        )
        .unwrap();
        let vc_2 = pyde_consensus::view_change::create_view_change(
            engine.chain_id,
            target_slot,
            &qc_2,
            attacker.committee_index,
            attacker.address,
            &attacker.secret_key,
        )
        .unwrap();
        // VC's preimage is `view_change || chain_id || slot ||
        // qc_hash`, so different qc → different sig.
        assert_ne!(vc_1.signature, vc_2.signature);

        // Bootstrap engine state so on_view_change accepts the
        // VC at target_slot (target_height must be ≤ slot).
        engine.consensus.target_height = target_slot;

        // First VC: lands clean, populates dedup map, no
        // evidence yet.
        engine.on_view_change(vc_1.clone());
        assert!(engine.pending_vc_evidence.is_empty());

        // Second VC at the same (slot, voter) with a DIFFERENT
        // qc_hash: equivocation. Evidence is constructed and
        // ingested.
        engine.on_view_change(vc_2.clone());

        let queued = &engine.pending_vc_evidence;
        assert_eq!(
            queued.len(),
            1,
            "double-VC must produce exactly one queued evidence"
        );
        let ev = &queued[0];
        assert_eq!(ev.slot, target_slot);
        assert_eq!(ev.signer, attacker.address);
        // The two qc_hashes carried by the evidence must match
        // what the attacker signed, in either order.
        let pair = (qc_1.hash(), qc_2.hash());
        let evidence_pair_a = (ev.qc_hash_1, ev.qc_hash_2);
        let evidence_pair_b = (ev.qc_hash_2, ev.qc_hash_1);
        assert!(
            evidence_pair_a == pair || evidence_pair_b == pair,
            "evidence qc_hashes must be the two distinct values the attacker signed"
        );

        // The slot's `seen_evidence` dedup record is set so a
        // re-arrival of either VC doesn't double-queue.
        assert!(engine.seen_evidence.contains(&(target_slot, attacker.address)));
    }

    /// TPL-502 control: a benign re-broadcast of the SAME VC
    /// (same qc_hash) is dropped at the dedup gate without
    /// queuing evidence. Without this the equivocation
    /// detector could be fooled by gossip refloods into
    /// reporting honest validators.
    #[test]
    fn tpl_502_on_view_change_does_not_flag_dedup_replay() {
        let (mut engine, identities) = make_engine_with_committee(4);

        let qc_1 = pyde_consensus::block::QuorumCert::empty();
        let target_slot = 42;
        let voter = &identities[1];
        let vc = pyde_consensus::view_change::create_view_change(
            engine.chain_id,
            target_slot,
            &qc_1,
            voter.committee_index,
            voter.address,
            &voter.secret_key,
        )
        .unwrap();
        engine.consensus.target_height = target_slot;

        engine.on_view_change(vc.clone());
        engine.on_view_change(vc.clone()); // gossip reflood
        engine.on_view_change(vc); // and again

        assert!(
            engine.pending_vc_evidence.is_empty(),
            "same-qc replay must not be flagged as equivocation"
        );
    }

    /// Invariant L2 (single deterministic leader per (H, V)): when a
    /// view-change-QC has formed for height H view V, exactly ONE
    /// committee member produces a fallback proposal — the deterministic
    /// leader `committee[fallback_index(H, V, n)]`. All other validators'
    /// `try_build_fallback_proposal` returns None.
    ///
    /// CURRENT behavior: any validator with a local view-change-QC builds
    /// a fallback proposal (the "any-validator" loosening documented in
    /// `try_build_fallback_proposal` line 1491). With 4 validators each
    /// holding a VC-QC, all 4 produce competing proposals. Under
    /// asymmetric gossip delivery, votes split across the candidates and
    /// no proposal reaches quorum. This is failure mode (2) in the
    /// audit-234 part-4 diagnosis.
    ///
    /// POST-FIX behavior: only one validator (the deterministic leader
    /// for (H, V)) produces Some(block); the other three return None.
    #[test]
    fn single_fallback_leader_per_view() {
        let n = 4;

        // Build n engines, each representing one validator's local state,
        // all sharing the same committee.
        let mut identities = Vec::new();
        let mut keys = Vec::new();
        for i in 0..n {
            let id = make_identity(i as u8);
            keys.push(id.public_key.as_bytes().to_vec());
            identities.push(id);
        }
        const TEST_CHAIN_ID: u64 = 7;
        let mut engines = Vec::new();
        for _ in 0..n {
            let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
            engine.set_committee(keys.clone());
            engine.advance_slot(); // → slot 1
            engines.push(engine);
        }
        let target_slot = engines[0].consensus.current_slot;

        // Every validator sends a view-change message for the target slot.
        let vc_messages: Vec<_> = identities
            .iter()
            .map(|id| {
                pyde_consensus::view_change::create_view_change(
                    TEST_CHAIN_ID,
                    target_slot,
                    &pyde_consensus::block::QuorumCert::empty(),
                    id.committee_index,
                    id.address,
                    &id.secret_key,
                )
                .unwrap()
            })
            .collect();

        // Each engine ingests every VC message → installs a VC-QC.
        for engine in &mut engines {
            for msg in &vc_messages {
                engine.on_view_change(msg.clone());
            }
            assert!(
                engine.timeout.view_change_qc.is_some(),
                "each engine should have a view-change-QC for slot {target_slot}"
            );
        }

        // Every engine tries to build a fallback proposal. Per L2, exactly
        // ONE engine (the deterministic leader for (target_slot, V=1))
        // should produce Some(block); the other three return None.
        let proposals: Vec<_> = engines
            .iter_mut()
            .enumerate()
            .map(|(i, engine)| {
                engine.try_build_fallback_proposal(&identities[i], [0u8; 32], [0u8; 32])
            })
            .collect();

        let proposal_count = proposals.iter().filter(|p| p.is_some()).count();
        assert_eq!(
            proposal_count, 1,
            "exactly ONE validator should build a fallback per (H, V); got {proposal_count}. \
             Today every validator with a local VC-QC builds, leading to vote splits under \
             asymmetric gossip delivery. See CONSENSUS_INVARIANTS.md L2."
        );
    }

    // ========== Audit 327: dedup before FALCON-verify cost is paid ==========

    /// A vote that's been accepted once must not push a second
    /// entry into `votes[slot]` when re-broadcast (legitimate
    /// gossip reflood) or replayed by an adversary. Pre-fix the
    /// FALCON verify ran first, then the vote was pushed
    /// unconditionally — every duplicate inflated the per-slot
    /// Vec and the next QC-formation pass paid the FALCON cost
    /// for each entry.
    #[test]
    fn audit_327_replayed_vote_dropped_pre_verify() {
        use pyde_consensus::hotstuff::{proposer_sign_message, ConsensusMessage};
        use pyde_crypto::falcon::{falcon_keygen, falcon_sign};

        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let signer = pyde_account::address::derive_eoa_address(&pk_bytes);

        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        engine.set_committee(vec![pk_bytes.clone()]);

        let slot = 9u64;
        let hash = [0x42u8; 32];
        let sig = falcon_sign(&sk, &proposer_sign_message(TEST_CHAIN_ID, slot, &hash))
            .unwrap()
            .as_bytes()
            .to_vec();
        let make_vote = || ConsensusMessage::Vote {
            slot,
            block_hash: hash,
            voter_index: 0,
            voter_address: signer,
            signature: sig.clone(),
        };

        // First delivery: accepted, pushed.
        let _ = engine.on_vote(make_vote());
        let entry = engine.votes.get(&slot).expect("vote stored");
        assert_eq!(entry.votes.len(), 1);

        // 100 replays of the byte-identical vote: dropped pre-verify.
        for _ in 0..100 {
            let _ = engine.on_vote(make_vote());
        }
        let entry = engine.votes.get(&slot).expect("still stored");
        assert_eq!(
            entry.votes.len(),
            1,
            "replays must NOT inflate the per-slot vote vec",
        );
    }

    /// View-change message dedup: a peer flooding repeats of the
    /// same `(slot, voter_index)` view-change must not inflate
    /// `view_changes[slot]`. `try_form_view_change_qc` runs FALCON
    /// verify on every entry, so the bound matters.
    #[test]
    fn audit_327_replayed_view_change_dropped() {
        use pyde_crypto::falcon::falcon_keygen;

        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let signer = pyde_account::address::derive_eoa_address(&pk_bytes);

        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        engine.set_committee(vec![pk_bytes]);
        // Set target_height so `slot >= target_height` passes.
        engine.consensus.target_height = 5;

        let slot = 5u64;
        let qc = pyde_consensus::block::QuorumCert::empty();
        let msg = pyde_consensus::view_change::create_view_change(
            TEST_CHAIN_ID,
            slot,
            &qc,
            0,
            signer,
            &sk,
        )
        .unwrap();

        // First delivery: accepted.
        engine.on_view_change(msg.clone());
        assert_eq!(engine.view_changes.get(&slot).unwrap().len(), 1);

        // 100 replays: dropped on dedup, vec stays at length 1.
        for _ in 0..100 {
            engine.on_view_change(msg.clone());
        }
        assert_eq!(
            engine.view_changes.get(&slot).unwrap().len(),
            1,
            "replays must NOT inflate the per-slot view-change vec",
        );
    }

    /// Finality-vote dedup: same rationale as view-change above,
    /// applied to `finality_votes[slot]` which is the input to
    /// `try_form_hard_finality`.
    /// Audit 326: `seen_evidence` is pruned in the slot-prune
    /// loop. Pre-fix it grew unbounded for the entire validator
    /// lifetime — a long-running testnet validator with
    /// thousands of slashing events would accumulate one entry
    /// per distinct (slot, signer) indefinitely.
    #[test]
    fn audit_326_seen_evidence_pruned_in_slot_loop() {
        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);

        // Seed seen_evidence at slots 1..=20 directly (bypasses
        // the verify path so we don't depend on FALCON keys).
        for slot in 1..=20u64 {
            let signer: Address = {
                let mut a = [0u8; 32];
                a[0] = slot as u8;
                a
            };
            engine.seen_evidence.insert((slot, signer));
        }
        assert_eq!(engine.seen_evidence.len(), 20);

        // Jump to slot 25 — prune_before = 15. Entries at slots
        // 1..=14 must drop; 15..=20 must remain.
        engine.consensus.current_slot = 24;
        engine.advance_slot(); // new_slot = 25

        assert!(
            engine.seen_evidence.iter().all(|(s, _)| *s >= 15),
            "seen_evidence retained entries older than prune_before",
        );
        assert_eq!(engine.seen_evidence.len(), 6, "slots 15..=20");
    }

    #[test]
    fn audit_327_replayed_finality_vote_dropped() {
        use pyde_consensus::finality::FinalityVote;
        use pyde_crypto::falcon::falcon_keygen;

        let (pk, _sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let signer = pyde_account::address::derive_eoa_address(&pk_bytes);

        let mut engine = ValidatorEngine::new(TEST_CHAIN_ID, [0xAA; 32]);
        engine.set_committee(vec![pk_bytes]);

        let slot = 11u64;
        // The dedup gate runs BEFORE any FALCON verify, so the
        // signature contents don't matter for this test — only the
        // (slot, voter_index) tuple. A garbage signature lets us
        // exercise the dedup path without depending on
        // `finality_sign_message` (which is private to
        // pyde_consensus::finality).
        let vote = FinalityVote {
            slot,
            block_hash: [0x33u8; 32],
            state_root: [0x44u8; 32],
            voter_index: 0,
            voter_address: signer,
            signature: vec![0xEE; 666],
        };

        engine.on_finality_vote(vote.clone());
        assert_eq!(engine.finality_votes.get(&slot).unwrap().len(), 1);

        for _ in 0..100 {
            engine.on_finality_vote(vote.clone());
        }
        assert_eq!(
            engine.finality_votes.get(&slot).unwrap().len(),
            1,
            "replays must NOT inflate the per-slot finality vote vec",
        );
    }
}
