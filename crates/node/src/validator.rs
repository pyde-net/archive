use pyde_account::address::Address;
use pyde_consensus::block::{
    Block, BlockBody, BlockHeader, QuorumCert, EPOCH_LENGTH,
};
use pyde_consensus::finality::{FinalityTracker, FinalityVote, create_finality_vote, try_form_hard_finality};
use pyde_consensus::hotstuff::{
    ConsensusMessage, ConsensusState, create_vote, proposer_sign_message, try_form_qc, verify_vote,
};
use pyde_consensus::proposer::{compute_candidacy, ProposerCandidate};
use pyde_crypto::vrf::VrfProof;
use pyde_consensus::block::quorum_for_committee;
use pyde_consensus::epoch_randomness::{
    RandomnessCollector, RandomnessShare, generate_share, verify_share,
    combine_shares_dynamic,
};
use pyde_crypto::threshold::{
    RefreshContribution, ResharingContribution, aggregate_new_share, apply_refresh,
    canonical_resharing_subset, generate_refresh_contribution, generate_resharing_contribution,
    verify_refresh_contribution, verify_resharing_contribution,
};
use pyde_consensus::slashing::{
    DoubleSignEvidence, slash_double_sign, verify_double_sign,
};
use pyde_consensus::validator::VALIDATOR_STAKE;
use pyde_consensus::view_change::{
    TimeoutTracker, ViewChangeMessage, create_view_change, try_form_view_change_qc,
};
use pyde_crypto::falcon::{FalconPublicKey, FalconSecretKey};
use pyde_crypto::threshold::{generate_decryption_share, DecryptionShare, KeyShare};
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
    let count = state.get(&count_key)
        .map(|b| {
            if b.len() >= 8 {
                u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]))
            } else { 0 }
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
            // Parse: [pk_len:4 LE][pk_bytes][stake:16 LE][status:1][exit_block:8 LE optional]
            if val_data.len() < 5 {
                continue;
            }
            let pk_len = u32::from_le_bytes([val_data[0], val_data[1], val_data[2], val_data[3]]) as usize;
            if val_data.len() < 4 + pk_len + 16 + 1 {
                continue;
            }
            let pk_bytes = val_data[4..4 + pk_len].to_vec();
            let mut stake_buf = [0u8; 16];
            stake_buf.copy_from_slice(&val_data[4 + pk_len..4 + pk_len + 16]);
            let stake = u128::from_le_bytes(stake_buf);
            let status_byte = val_data[4 + pk_len + 16];
            let status = match status_byte {
                0x00 => ValidatorStatus::Active,
                0x01 => {
                    // Unbonding — read exit block if available
                    let exit_block = if val_data.len() >= 4 + pk_len + 16 + 1 + 8 {
                        let off = 4 + pk_len + 16 + 1;
                        u64::from_le_bytes(val_data[off..off+8].try_into().unwrap_or([0;8]))
                    } else { 0 };
                    ValidatorStatus::Unbonding { exit_block }
                }
                _ => ValidatorStatus::Exited,
            };

            set.validators.push(Validator {
                address,
                public_key: pk_bytes,
                stake,
                status,
                registered_epoch: 0,
            });
        }
    }

    set
}

/// Process unbonding validators: return stake for those whose unbonding period expired.
/// Called at each epoch boundary.
pub fn process_unbonding(
    state: &mut crate::state_manager::StateManager,
    current_slot: u64,
) {
    use pyde_consensus::validator::{UNBONDING_PERIOD, VALIDATOR_STAKE};

    let count_key = pyde_state::keys::validator_count_key();
    let count = state.get(&count_key)
        .map(|b| {
            if b.len() >= 8 { u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8])) } else { 0 }
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
        if let Some(mut val_data) = state.get(&val_key) {
            if val_data.len() < 5 { continue; }
            let pk_len = u32::from_le_bytes([val_data[0], val_data[1], val_data[2], val_data[3]]) as usize;
            let status_offset = 4 + pk_len + 16;
            if val_data.len() <= status_offset { continue; }

            // Check if Unbonding (0x01) with expired period
            if val_data[status_offset] == 0x01 && val_data.len() >= status_offset + 1 + 8 {
                let exit_off = status_offset + 1;
                let exit_block = u64::from_le_bytes(
                    val_data[exit_off..exit_off + 8].try_into().unwrap_or([0; 8])
                );

                if current_slot >= exit_block + UNBONDING_PERIOD {
                    // Unbonding expired: return stake to balance, set status to Exited (0x02)
                    val_data[status_offset] = 0x02; // Exited
                    let _ = state.insert(val_key, val_data);

                    // Credit stake back to validator's balance
                    let balance_key = pyde_state::keys::balance_key(&address);
                    if let Some(account_bytes) = state.get(&balance_key) {
                        if let Some(mut account) = pyde_account::types::Account::from_bytes(&account_bytes) {
                            account.balance += VALIDATOR_STAKE;
                            let _ = state.insert(balance_key, account.to_bytes());
                            tracing::info!(
                                validator = hex::encode(address),
                                "unbonding complete: stake returned"
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Collected votes for a slot, used to form QCs.
struct SlotVotes {
    block_hash: [u8; 32],
    votes: Vec<ConsensusMessage>,
}

/// A buffered proposal with verified VRF score.
struct BufferedProposal {
    header: BlockHeader,
    proposer_signature: Vec<u8>,
    vrf_score: u64,
}

/// The validator consensus engine.
/// Manages the HotStuff protocol state, VRF proposer selection,
/// voting, QC formation, and finality tracking.
pub struct ValidatorEngine {
    /// HotStuff consensus state (current slot, highest QC, etc.).
    pub consensus: ConsensusState,
    /// Finality tracker (soft/hard finality, checkpoints).
    pub finality: FinalityTracker,
    /// Timeout tracker for the current slot.
    pub timeout: TimeoutTracker,
    /// Committee public keys for the current epoch (index → key bytes).
    pub committee_keys: Vec<Vec<u8>>,
    /// Epoch randomness seed (for VRF proposer selection).
    pub epoch_randomness: [u8; 32],
    /// Votes collected per slot.
    votes: HashMap<u64, SlotVotes>,
    /// View change messages collected per slot.
    view_changes: HashMap<u64, Vec<ViewChangeMessage>>,
    /// Finality votes collected per slot.
    finality_votes: HashMap<u64, Vec<FinalityVote>>,
    /// Buffered proposals per slot (collected during proposal phase, voted after selection).
    buffered_proposals: HashMap<u64, Vec<BufferedProposal>>,
    /// Whether we've already voted for a given slot (after proposal selection).
    voted_slots: std::collections::HashSet<u64>,
    /// Seen proposals per slot: (slot, proposer_address) → (header, signature).
    /// Used to detect double-proposing.
    seen_proposals: HashMap<(u64, Address), (BlockHeader, Vec<u8>)>,
    /// Seen votes per slot: (slot, voter_index) → (block_hash, signature).
    /// Used to detect double-voting (equivocation).
    seen_votes: HashMap<(u64, u8), ([u8; 32], Vec<u8>)>,
    /// Collected double-sign evidence awaiting inclusion in a Slash tx.
    /// Drained by `drain_pending_evidence` when the block builder wants
    /// to construct slashing transactions. We hold the raw evidence here
    /// rather than the computed SlashResult because the slashing handler
    /// on the receiving node will re-verify signatures from state —
    /// SlashResult is just a local convenience.
    pub pending_evidence: Vec<DoubleSignEvidence>,
    /// Epoch randomness collector (gathers VRF shares at epoch boundary).
    randomness_collector: Option<RandomnessCollector>,
    /// PSS refresh contributions collected at epoch boundary.
    pss_contributions: Vec<RefreshContribution>,
    /// Target epoch for PSS refresh.
    pss_target_epoch: u64,
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
}

impl ValidatorEngine {
    /// Create a new validator engine at genesis.
    pub fn new(epoch_randomness: [u8; 32]) -> Self {
        let now_ms = current_time_ms();
        Self {
            consensus: ConsensusState::new(),
            finality: FinalityTracker::new(),
            timeout: TimeoutTracker::new(0, now_ms),
            committee_keys: Vec::new(),
            epoch_randomness,
            votes: HashMap::new(),
            view_changes: HashMap::new(),
            finality_votes: HashMap::new(),
            buffered_proposals: HashMap::new(),
            voted_slots: std::collections::HashSet::new(),
            seen_proposals: HashMap::new(),
            seen_votes: HashMap::new(),
            pending_evidence: Vec::new(),
            broadcast_evidence: Vec::new(),
            seen_evidence: std::collections::HashSet::new(),
            inclusion_violated_slots: std::collections::HashSet::new(),
            randomness_collector: None,
            pss_contributions: Vec::new(),
            pss_target_epoch: 0,
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
        if !proposals.is_empty() || !votes.is_empty() {
            info!(
                proposals = proposals.len(),
                votes = votes.len(),
                "restoring equivocation evidence from disk"
            );
        }
        for (key, value) in proposals {
            self.seen_proposals.insert(key, value);
        }
        for (key, value) in votes {
            self.seen_votes.insert(key, value);
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
                error!(
                    error = %e,
                    "FATAL: failed to persist evidence state — halting validator"
                );
                panic!("evidence state persist failed: {}", e);
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
                error!(
                    error = %e,
                    "FATAL: failed to persist consensus state — halting validator to preserve BFT safety"
                );
                panic!("consensus state persist failed: {}", e);
            }
        }
    }

    /// Set the committee keys for the current epoch.
    pub fn set_committee(&mut self, keys: Vec<Vec<u8>>) {
        info!(members = keys.len(), "committee keys loaded");
        self.committee_keys = keys;
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

        let contribution = generate_refresh_contribution(
            key_share.index,
            n,
            threshold,
            epoch,
            entropy.as_bytes(),
        );

        self.pss_contributions = vec![contribution.clone()];
        self.pss_target_epoch = epoch;
        info!(epoch, "started PSS key share refresh");
        Some(contribution)
    }

    /// Add a received PSS refresh contribution. Returns the new KeyShare if threshold reached.
    pub fn on_pss_contribution(
        &mut self,
        contribution: RefreshContribution,
        identity: &mut ValidatorIdentity,
    ) -> bool {
        let threshold = quorum_for_committee(self.committee_keys.len());

        // Verify the contribution (zero-secret reconstruction check)
        if !verify_refresh_contribution(&contribution, threshold) {
            warn!(from = contribution.from_index, "invalid PSS refresh contribution");
            return false;
        }

        // Check for duplicate
        if self.pss_contributions.iter().any(|c| c.from_index == contribution.from_index) {
            return false;
        }

        self.pss_contributions.push(contribution);

        // If threshold reached, apply all contributions to our key share
        if self.pss_contributions.len() >= threshold {
            if let Some(ref old_share) = identity.key_share {
                let new_share = apply_refresh(old_share, &self.pss_contributions);
                identity.key_share = Some(new_share);
                self.pss_contributions.clear();
                self.key_share_dirty = true;
                info!(
                    epoch = self.pss_target_epoch,
                    contributions = threshold,
                    "PSS key share refreshed — genesis trust dissolved"
                );
                return true;
            }
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

    /// Snapshot the resharing state for disk persistence (task 034 crash
    /// safety). Returns `None` when nothing needs to be saved (engine is
    /// idle between rotations). Excludes the contribution pool — on
    /// restart within the rebroadcast window the pool rebuilds from
    /// gossip; after the window, the node stays locked out of this
    /// epoch's decryption and resumes normally on the next rotation.
    pub fn reshare_state_snapshot(&self) -> Option<crate::wire::ReshareState> {
        if self.reshare_target_epoch == 0
            && self.pending_reshare_rebroadcast.is_none()
        {
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

    /// Fsync the reshare snapshot to the ConsensusStateStore when one is
    /// attached. No-op when there's no store (devnet/tests) or when
    /// snapshot is empty. Panics on write failure — same safety-critical
    /// contract as other consensus-state persistence.
    fn persist_reshare_state(&self) {
        let (Some(store), Some(snap)) = (self.consensus_store.as_ref(), self.reshare_state_snapshot()) else {
            return;
        };
        if let Err(e) = store.save_reshare_state(&snap) {
            panic!("CRITICAL: reshare state persistence failed — {}", e);
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
        if self.reshare_contributions.iter().any(|c| c.from_old_index == contribution.from_old_index) {
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
        let canonical = match canonical_resharing_subset(&self.reshare_contributions, old_threshold) {
            Some(c) => c,
            None => return false,
        };
        let new_share = match aggregate_new_share(self.reshare_new_index, &canonical) {
            Some(s) => s,
            None => return false,
        };

        identity.key_share = Some(new_share);
        self.key_share_dirty = true;
        self.reshare_aggregated = true;
        self.reshare_contributions.clear();
        self.persist_reshare_state();
        info!(
            target_epoch = self.reshare_target_epoch,
            new_index = self.reshare_new_index,
            old_threshold,
            "committee handoff complete — new key share derived from resharing"
        );
        true
    }

    /// Expose the target epoch of any pending resharing (for node-layer
    /// stale-message filtering).
    pub fn reshare_target(&self) -> u64 {
        self.reshare_target_epoch
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
        ).ok()?;

        let mut collector = RandomnessCollector::new(next_epoch);
        collector.add_share(share.clone());
        self.randomness_collector = Some(collector);

        info!(epoch = next_epoch, "started epoch randomness collection");
        Some(share)
    }

    /// Add a received randomness share from another committee member.
    /// Returns the new epoch randomness if threshold reached.
    pub fn on_randomness_share(
        &mut self,
        share: RandomnessShare,
    ) -> Option<[u8; 32]> {
        let collector = self.randomness_collector.as_mut()?;

        // Verify share against committee key
        let idx = share.validator_index as usize;
        if idx >= self.committee_keys.len() {
            return None;
        }
        let pk = match pyde_crypto::falcon::FalconPublicKey::from_bytes(&self.committee_keys[idx]) {
            Some(pk) => pk,
            None => return None,
        };
        if !verify_share(&share, &pk, collector.epoch) {
            warn!(epoch = collector.epoch, validator = idx, "invalid randomness share");
            return None;
        }

        collector.add_share(share);

        // Check with dynamic threshold based on committee size
        let threshold = quorum_for_committee(self.committee_keys.len());
        if collector.share_count() >= threshold {
            if let Some(result) = collector.finalize() {
                info!(
                    epoch = result.epoch,
                    shares = result.share_count,
                    "epoch randomness combined"
                );
                self.epoch_randomness = result.randomness;
                self.randomness_collector = None;
                return Some(result.randomness);
            }
        }

        None
    }

    /// Compute VRF candidacy for the current slot.
    /// Only propose if VRF score is below threshold (targets ~1 proposer per slot).
    /// Threshold = U64::MAX / committee_size. With N validators, on average 1 score
    /// falls below this threshold per slot. If 0 qualify → timeout/view change.
    /// If 2+ qualify → proposal buffering picks the lowest score.
    pub fn check_proposer(&self, identity: &ValidatorIdentity) -> Option<ProposerCandidate> {
        let slot = self.consensus.current_slot;
        let committee_size = self.committee_keys.len();

        match compute_candidacy(
            &identity.public_key,
            &identity.secret_key,
            &self.epoch_randomness,
            slot,
            identity.address,
        ) {
            Ok(candidate) => {
                // VRF threshold: only propose if score < threshold.
                // Target ~5 expected proposers per slot for reliability:
                //   threshold = min(U64::MAX, 5 * U64::MAX / committee_size)
                //   P(0 proposers) ≈ e^(-5) ≈ 0.67% (virtually no empty slots)
                //   Proposal buffering picks the lowest VRF score from candidates.
                //
                // For small committees (≤5), everyone proposes (threshold = MAX).
                const TARGET_PROPOSERS: u64 = 5;
                let threshold = if committee_size as u64 <= TARGET_PROPOSERS {
                    u64::MAX // small committee: everyone proposes
                } else {
                    (u64::MAX / committee_size as u64).saturating_mul(TARGET_PROPOSERS)
                };

                if candidate.score > threshold {
                    debug!(
                        slot,
                        score = candidate.score,
                        threshold,
                        "VRF score above threshold, not proposing"
                    );
                    return None;
                }

                debug!(slot, score = candidate.score, threshold, "proposing (below VRF threshold)");
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
    pub fn buffer_proposal(
        &mut self,
        header: &BlockHeader,
        proposer_signature: &[u8],
    ) -> bool {
        let slot = header.slot;

        // Don't buffer if we've already voted for this slot
        if self.voted_slots.contains(&slot) {
            debug!(slot, "ignoring late proposal (already voted)");
            return false;
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
                warn!(slot, proposer = hex::encode(header.proposer), "proposal from non-committee member");
                return false;
            }
        };

        // Reconstruct proposer's public key
        let pk = match pyde_crypto::falcon::FalconPublicKey::from_bytes(&self.committee_keys[proposer_idx]) {
            Some(pk) => pk,
            None => { warn!(slot, "invalid committee public key"); return false; }
        };

        // Verify proposer signature on block header.
        // Proposers sign `slot || block_hash` (same canonical layout as
        // votes) so a sig at slot N cannot be replayed for a block at slot M.
        if !proposer_signature.is_empty() {
            let block_hash = header.hash();
            let sig = match pyde_crypto::falcon::FalconSignature::from_bytes(proposer_signature) {
                Some(s) => s,
                None => { warn!(slot, "invalid proposer signature format"); return false; }
            };
            let sign_msg = proposer_sign_message(slot, &block_hash);
            if !pyde_crypto::falcon::falcon_verify(&pk, &sign_msg, &sig) {
                warn!(slot, "proposer signature verification failed");
                return false;
            }
        } else {
            warn!(slot, "proposal missing proposer signature");
            return false;
        }
        let vrf_output = pyde_crypto::vrf::VrfOutput::from_hash_bytes(vrf_output_bytes);
        let vrf_proof = VrfProof::from_bytes(vrf_proof_bytes);

        // Build VRF input: epoch_randomness || slot
        let mut vrf_input = Vec::with_capacity(40);
        vrf_input.extend_from_slice(&self.epoch_randomness);
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
                if let Err(e) = store.save_seen_proposal(slot, &header.proposer, header, proposer_signature) {
                    error!(
                        error = %e,
                        slot,
                        "FATAL: failed to persist seen proposal — halting validator"
                    );
                    panic!("seen-proposal persist failed: {}", e);
                }
            }
            self.seen_proposals.insert(proposal_key, (header.clone(), proposer_signature.to_vec()));
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

        debug!(slot, vrf_score, proposals = entry.len(), "proposal buffered");
        true
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
    pub fn is_inclusion_violated(&self, slot: u64) -> bool {
        self.inclusion_violated_slots.contains(&slot)
    }

    /// Select the best proposal (lowest VRF score) and vote for it.
    /// Called after the proposal collection window (100ms into the slot).
    /// Returns the vote to broadcast, or None if no proposals were buffered.
    pub fn select_and_vote(
        &mut self,
        identity: &ValidatorIdentity,
    ) -> Option<ConsensusMessage> {
        let slot = self.consensus.current_slot;

        // Don't double-vote
        if self.voted_slots.contains(&slot) {
            return None;
        }

        // Task 026 — skip vote if the local inclusion audit flagged this slot.
        // The flag is set by the compact-block reception path when encrypted
        // txs the validator has held past the grace window are missing from
        // the proposal while gas budget remained.
        if self.inclusion_violated_slots.contains(&slot) {
            warn!(slot, "skipping vote: mandatory-inclusion audit failed");
            // Mark voted so a later arriving compact block that clears the
            // flag doesn't cause us to belatedly cast a vote. The decision
            // is final for this slot.
            self.voted_slots.insert(slot);
            return None;
        }

        let proposals = self.buffered_proposals.get(&slot)?;
        if proposals.is_empty() {
            return None;
        }

        // Pick the proposal with the lowest VRF score (clone to release borrow)
        let best = proposals.iter().min_by_key(|p| p.vrf_score)?;
        let best_header = best.header.clone();
        let best_score = best.vrf_score;
        let best_proposer = best.header.proposer;

        info!(
            slot,
            vrf_score = best_score,
            proposer = hex::encode(best_proposer),
            "selected best proposal"
        );

        // Vote for the best proposal
        let vote = self.on_proposal(&best_header, identity);
        if vote.is_some() {
            self.voted_slots.insert(slot);
        }
        vote
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

        // Sign the canonical (slot || block_hash) message with the
        // proposer's FALCON key. See proposer_sign_message for the format.
        let block_hash = header.hash();
        let sign_msg = proposer_sign_message(header.slot, &block_hash);
        let proposer_signature = match pyde_crypto::falcon::falcon_sign(
            &identity.secret_key,
            &sign_msg,
        ) {
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

        // Create vote (HotStuff safety rules enforced inside create_vote)
        match create_vote(
            &mut self.consensus,
            header,
            identity.committee_index,
            identity.address,
            &identity.secret_key,
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
        // Extract slot and block_hash from vote
        let (slot, block_hash, voter_index) = match &vote {
            ConsensusMessage::Vote {
                slot,
                block_hash,
                voter_index,
                ..
            } => (*slot, *block_hash, *voter_index as usize),
            _ => return None,
        };

        // Verify vote signature
        if voter_index < self.committee_keys.len() {
            if !verify_vote(&vote, &self.committee_keys[voter_index]) {
                warn!(slot, voter_index, "invalid vote signature");
                return None;
            }
        }

        // --- Double-vote (equivocation) detection ---
        let vote_key = (slot, voter_index as u8);
        let vote_sig = match &vote {
            ConsensusMessage::Vote { signature, .. } => signature.clone(),
            _ => vec![],
        };
        if let Some((prev_hash, _prev_sig)) = self.seen_votes.get(&vote_key) {
            if *prev_hash != block_hash {
                warn!(
                    slot,
                    voter_index,
                    "DOUBLE VOTE DETECTED — equivocation"
                );
                // Note: full evidence creation requires both vote messages.
                // For now, log and flag. Full evidence submission (with both signatures)
                // can be implemented when the slashing transaction type is added.
            }
        } else {
            // Persist BEFORE the in-memory insert. Panics on failure for
            // the same reason as the seen-proposal site above.
            if let Some(store) = &self.consensus_store {
                if let Err(e) = store.save_seen_vote(slot, voter_index as u8, &block_hash, &vote_sig) {
                    error!(
                        error = %e,
                        slot,
                        voter_index,
                        "FATAL: failed to persist seen vote — halting validator"
                    );
                    panic!("seen-vote persist failed: {}", e);
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
            let qc = try_form_qc(slot, block_hash, &entry.votes, &self.committee_keys);
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
                // Record soft finality
                self.finality.record_soft_finality(slot, block_hash, qc.clone());
            }
            qc
        } else {
            None
        }
    }

    /// Handle a slot timeout: create view change message.
    /// Returns the message to broadcast.
    pub fn on_timeout(&mut self, identity: &ValidatorIdentity) -> Option<ViewChangeMessage> {
        let slot = self.consensus.current_slot;
        match create_view_change(
            slot,
            &self.consensus.highest_qc,
            identity.committee_index,
            identity.address,
            &identity.secret_key,
        ) {
            Ok(msg) => {
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
    /// Returns the ViewChangeQC if quorum is reached.
    pub fn on_view_change(&mut self, msg: ViewChangeMessage) -> bool {
        let slot = msg.slot;
        let entry = self.view_changes.entry(slot).or_default();
        entry.push(msg);

        // Try to form view change QC
        if let Some(vc_qc) = try_form_view_change_qc(slot, entry, &self.committee_keys) {
            info!(slot, votes = vc_qc.vote_count, "view change QC formed");
            self.timeout.view_change_qc = Some(vc_qc);
            true
        } else {
            false
        }
    }

    /// Handle a finality vote.
    pub fn on_finality_vote(&mut self, vote: FinalityVote) {
        let slot = vote.slot;
        let block_hash = vote.block_hash;
        let state_root = vote.state_root;

        let entry = self.finality_votes.entry(slot).or_default();
        entry.push(vote);

        // Try to form hard finality cert (dynamic quorum)
        let threshold = quorum_for_committee(self.committee_keys.len());
        if entry.len() >= threshold {
            if let Some(cert) = try_form_hard_finality(
                slot,
                block_hash,
                state_root,
                entry,
                &self.committee_keys,
            ) {
                info!(slot, "hard finality achieved");
                self.finality.record_hard_finality(cert);
            }
        }
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
        let signer_pk = self.committee_keys.iter().find(|pk| {
            pyde_account::address::derive_eoa_address(pk) == evidence.signer
        });
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

        // slash_double_sign returns None if the sig/format verification
        // fails. We discard the SlashResult — only verification matters;
        // the on-chain handler re-computes it from state.
        if slash_double_sign(&evidence, &pk_bytes).is_none() {
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

    /// Advance to the next slot. Returns the new slot number.
    pub fn advance_slot(&mut self) -> u64 {
        self.consensus.advance_slot();
        // current_slot changed + pending_votes/timeouts cleared.
        self.persist_consensus();
        let new_slot = self.consensus.current_slot;
        let now_ms = current_time_ms();
        self.timeout = TimeoutTracker::new(new_slot, now_ms);

        // Clean up old vote/view-change data (keep last 10 slots)
        if new_slot > 10 {
            let prune_before = new_slot - 10;
            self.votes.retain(|s, _| *s >= prune_before);
            self.view_changes.retain(|s, _| *s >= prune_before);
            self.finality_votes.retain(|s, _| *s >= prune_before);
            self.buffered_proposals.retain(|s, _| *s >= prune_before);
            self.voted_slots.retain(|s| *s >= prune_before);
            self.seen_proposals.retain(|(s, _), _| *s >= prune_before);
            self.seen_votes.retain(|(s, _), _| *s >= prune_before);
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

    /// Check if the current slot has timed out.
    pub fn is_timed_out(&self) -> bool {
        let now_ms = current_time_ms();
        self.timeout.is_expired(now_ms)
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

        let shares: Vec<DecryptionShare> = encrypted_txs
            .iter()
            .map(|tx| generate_decryption_share(key_share, &tx.ciphertext))
            .collect();

        info!(
            slot = self.consensus.current_slot,
            txs = encrypted_txs.len(),
            "generated decryption shares"
        );
        Some(shares)
    }

    /// Create a BlockDecryptor and seed it with our own shares.
    /// Other committee members' shares are added as they arrive via gossipsub.
    pub fn start_decryption(
        &self,
        identity: &ValidatorIdentity,
        encrypted_txs: Vec<EncryptedTx>,
        threshold: usize,
    ) -> Result<BlockDecryptor, String> {
        let mut decryptor = BlockDecryptor::new(encrypted_txs, threshold)?;

        // Add our own shares immediately
        if let Some(key_share) = &identity.key_share {
            decryptor.add_member_shares(key_share);
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

    fn make_identity(index: u8) -> ValidatorIdentity {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let address = derive_eoa_address(&pk_bytes);
        ValidatorIdentity {
            address,
            public_key: pk,
            secret_key: sk,
            committee_index: index,
            key_share: None,
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

        let mut engine = ValidatorEngine::new([0xAA; 32]);
        engine.set_committee(keys);
        (engine, identities)
    }

    #[test]
    fn engine_starts_at_genesis() {
        let engine = ValidatorEngine::new([0; 32]);
        assert_eq!(engine.consensus.current_slot, 0);
    }

    #[test]
    fn advance_slot_increments() {
        let mut engine = ValidatorEngine::new([0; 32]);
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
        assert!(found_proposer, "should find at least 1 slot to propose in 20 tries");
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
        engine.buffered_proposals.entry(slot).or_default().push(BufferedProposal {
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
        assert!(engine.voted_slots.contains(&slot));
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
        engine.buffered_proposals.entry(slot).or_default().push(BufferedProposal {
            header,
            proposer_signature: vec![],
            vrf_score: 0,
        });

        assert!(!engine.is_inclusion_violated(slot));
        let vote = engine.select_and_vote(&identities[1]);
        assert!(vote.is_some(), "un-flagged slot should produce a vote");
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
                incoming.consensus.current_slot, 5, identity
            ));
            // Advance past the trigger; aggregation fires.
            let fire_at = trigger + 1;
            assert!(incoming.try_aggregate_reshare_on_slot(fire_at, 5, identity));
            // Second call after aggregation: no-op.
            assert!(!incoming.try_aggregate_reshare_on_slot(fire_at + 1, 5, identity));
        }

        let dec_shares: Vec<_> = new_identities
            .iter()
            .take(4)
            .map(|id| generate_decryption_share(id.key_share.as_ref().unwrap(), &ct))
            .collect();
        let plaintext = combine_shares(&dec_shares, 4, &ct).unwrap();
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
        let mut engine_a = ValidatorEngine::new([0u8; 32]);
        engine_a.set_committee(new_committee_keys.clone());
        let mut engine_b = ValidatorEngine::new([0u8; 32]);
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
            generate_decryption_share(id_a.key_share.as_ref().unwrap(), &ct),
            generate_decryption_share(id_b.key_share.as_ref().unwrap(), &ct),
        ];
        // Can't combine with only 2 of 4 required — add more honest shares.
        let mut helpers: Vec<ValidatorEngine> = (3..=6)
            .map(|_| {
                let mut e = ValidatorEngine::new([0u8; 32]);
                e.set_committee(new_committee_keys.clone());
                e
            })
            .collect();
        let mut helper_ids: Vec<ValidatorIdentity> =
            (3..=6).map(|i| make_identity(i)).collect();
        for (i, (engine, id)) in helpers.iter_mut().zip(helper_ids.iter_mut()).enumerate() {
            engine.prepare_for_reshare_reception(1, new_committee_keys.clone(), i + 3);
            for c in &contribs {
                engine.on_reshare_contribution(c.clone(), 5, id);
            }
            assert!(engine.try_aggregate_reshare_on_slot(trigger, 5, id));
        }
        let mut all_shares = shares;
        for id in &helper_ids[..2] {
            all_shares.push(generate_decryption_share(id.key_share.as_ref().unwrap(), &ct));
        }
        let plaintext = combine_shares(&all_shares, 4, &ct).unwrap();
        assert_eq!(
            plaintext, msg,
            "shares must be on same polynomial — canonical subset divergence would break this"
        );
    }

    #[test]
    fn reshare_aggregation_waits_for_trigger() {
        let (_, old_shares) = threshold_keygen(4, 3).unwrap();
        let mut engine = ValidatorEngine::new([0u8; 32]);
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
        let mut engine = ValidatorEngine::new([0u8; 32]);
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
        let new_committee = vec![vec![0x11; 897], vec![0x22; 897], vec![0x33; 897], vec![0x44; 897]];

        let trigger_slot;
        {
            let mut engine = ValidatorEngine::new([0xAA; 32]);
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
        let mut engine = ValidatorEngine::new([0xAA; 32]);
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
            let mut engine = ValidatorEngine::new([0u8; 32]);
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
        let mut engine = ValidatorEngine::new([0u8; 32]);
        engine.attach_consensus_store(store);
        assert!(engine.reshare_aggregated, "aggregated flag must survive restart");
    }

    #[test]
    fn reshare_state_pending_rebroadcast_survives_restart() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let (_, old_shares) = threshold_keygen(3, 2).unwrap();

        {
            let mut engine = ValidatorEngine::new([0u8; 32]);
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
        let mut engine = ValidatorEngine::new([0u8; 32]);
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
        let mut engine = ValidatorEngine::new([0u8; 32]);
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
        let mut engine = ValidatorEngine::new([0u8; 32]);
        let new_committee = vec![vec![0xAA; 897]; 4];
        engine.prepare_for_reshare_reception(1, new_committee, 1);
        let mut new_id = make_identity(0);

        let mut bad = generate_resharing_contribution(&old_shares[0], 4, 3, 1, b"e");
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
        let mut engine = ValidatorEngine::new([0u8; 32]);
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
        let mut engine = ValidatorEngine::new([0u8; 32]);
        engine.set_committee(vec![vec![0xAA; 897]; 3]);
        let mut id = identity_with_share(0, old_shares[0].clone());

        // Initial broadcast at slot 0.
        engine.start_committee_reshare(7, &vec![vec![0xBB; 897]; 3], &id).unwrap();

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
        let mut engine = ValidatorEngine::new([0u8; 32]);
        assert!(engine.maybe_rebroadcast_reshare().is_none());
        for _ in 0..20 {
            engine.advance_slot();
            assert!(engine.maybe_rebroadcast_reshare().is_none());
        }
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
            committee_keys = identities.iter().map(|id| id.public_key.as_bytes().to_vec()).collect();
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
        let mut engine = ValidatorEngine::new([0xAA; 32]);
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
            let mut engine = ValidatorEngine::new([0xAA; 32]);
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
        let mut engine = ValidatorEngine::new([0xAA; 32]);
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
        let mut engine = ValidatorEngine::new([0xAA; 32]);
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
            let mut engine = ValidatorEngine::new([0xAA; 32]);
            let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
            engine.attach_consensus_store(store);
            for _ in 0..7 {
                engine.advance_slot();
            }
            assert_eq!(engine.consensus.current_slot, 7);
        }

        let mut engine = ValidatorEngine::new([0xAA; 32]);
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
            store.save_seen_proposal(5, &proposer, &header, &sig).unwrap();
        }

        // Fresh engine attaches the same store and must restore the index.
        let mut engine = ValidatorEngine::new([0xAA; 32]);
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

        let mut engine = ValidatorEngine::new([0xAA; 32]);
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
                    .save_seen_proposal(slot, &[0xAA; 32], &evidence_header(slot, [0x33; 32]), &vec![0x11; 10])
                    .unwrap();
                store.save_seen_vote(slot, 0, &[0x99; 32], &vec![0x22; 10]).unwrap();
            }
        }

        // Attach, jump forward to slot 15, advancing triggers prune.
        let mut engine = ValidatorEngine::new([0xAA; 32]);
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
        let mut engine = ValidatorEngine::new([0xAA; 32]);
        engine.pending_evidence.push(evidence_fixture(1, [0xAB; 32]));
        engine.pending_evidence.push(evidence_fixture(2, [0xCD; 32]));

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
        let mut engine = ValidatorEngine::new([0xAA; 32]);
        engine.pending_evidence.push(evidence_fixture(7, [0x99; 32]));

        let drained = engine.drain_pending_evidence();
        assert_eq!(drained.len(), 1);
        assert!(engine.pending_evidence.is_empty());

        engine.push_evidence(drained);
        assert_eq!(engine.pending_evidence.len(), 1);
        assert_eq!(engine.pending_evidence[0].slot, 7);
    }

    #[test]
    fn push_evidence_appends_preserving_order() {
        let mut engine = ValidatorEngine::new([0xAA; 32]);
        engine.pending_evidence.push(evidence_fixture(1, [0x01; 32]));

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
    fn valid_evidence_and_engine()
        -> (ValidatorEngine, pyde_crypto::falcon::FalconSecretKey, DoubleSignEvidence, Address)
    {
        use pyde_crypto::falcon::falcon_keygen;

        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let signer = pyde_account::address::derive_eoa_address(&pk_bytes);

        let mut engine = ValidatorEngine::new([0xAA; 32]);
        engine.set_committee(vec![pk_bytes]);

        let slot = 42u64;
        let hash_1 = [0x01u8; 32];
        let hash_2 = [0x02u8; 32];
        let sign_1 = {
            let mut m = Vec::with_capacity(40);
            m.extend_from_slice(&slot.to_le_bytes());
            m.extend_from_slice(&hash_1);
            m
        };
        let sign_2 = {
            let mut m = Vec::with_capacity(40);
            m.extend_from_slice(&slot.to_le_bytes());
            m.extend_from_slice(&hash_2);
            m
        };
        let sig_1 = pyde_crypto::falcon::falcon_sign(&sk, &sign_1).unwrap().as_bytes().to_vec();
        let sig_2 = pyde_crypto::falcon::falcon_sign(&sk, &sign_2).unwrap().as_bytes().to_vec();

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
        let sig = pyde_crypto::falcon::falcon_sign(&sk, &sign_msg).unwrap().as_bytes().to_vec();
        evidence.block_hash_1 = h;
        evidence.block_hash_2 = h;
        evidence.signature_1 = sig.clone();
        evidence.signature_2 = sig;
        assert!(!engine.ingest_evidence(evidence));
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

            let mut engine = ValidatorEngine::new([0xAA; 32]);
            engine.set_committee(vec![committee_pk.clone()]);
            let store = Arc::new(ConsensusStateStore::open(dir.path()).unwrap());
            engine.attach_consensus_store(store);

            let slot = 50u64;
            let hash_1 = [0x01u8; 32];
            let hash_2 = [0x02u8; 32];
            let sign_1 = {
                let mut m = Vec::with_capacity(40);
                m.extend_from_slice(&slot.to_le_bytes());
                m.extend_from_slice(&hash_1);
                m
            };
            let sign_2 = {
                let mut m = Vec::with_capacity(40);
                m.extend_from_slice(&slot.to_le_bytes());
                m.extend_from_slice(&hash_2);
                m
            };
            let sig_1 = pyde_crypto::falcon::falcon_sign(&sk, &sign_1).unwrap().as_bytes().to_vec();
            let sig_2 = pyde_crypto::falcon::falcon_sign(&sk, &sign_2).unwrap().as_bytes().to_vec();

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
        let mut engine = ValidatorEngine::new([0xAA; 32]);
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
        let identity = ValidatorIdentity {
            address: submitter_addr,
            public_key: pk.clone(),
            secret_key: sk,
            committee_index: 0,
            key_share: None,
        };

        let mut engine = ValidatorEngine::new([0xAA; 32]);
        engine.pending_evidence.push(evidence_fixture(42, [0xFF; 32]));

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
        use pyde_state::smt::PydeSMT;
        use pyde_tx::pipeline::{execute_transaction, BlockContext};

        const VALIDATOR_STAKE: u128 = 10_000_000_000_000;

        // Offender: produces the two conflicting signatures.
        let (offender_pk, offender_sk) = falcon_keygen().unwrap();
        let offender_addr =
            pyde_account::address::derive_eoa_address(offender_pk.as_bytes());

        // Submitter: the validator building the block (and receiving the fee).
        let (submitter_pk, submitter_sk) = falcon_keygen().unwrap();
        let submitter_addr =
            pyde_account::address::derive_eoa_address(submitter_pk.as_bytes());

        // Stand up an SMT with the offender registered as an Active
        // validator (status 0x00) and the submitter funded.
        let mut smt = PydeSMT::new();
        let pk_len = offender_pk.as_bytes().len() as u32;
        let mut val_data = Vec::new();
        val_data.extend_from_slice(&pk_len.to_le_bytes());
        val_data.extend_from_slice(offender_pk.as_bytes());
        val_data.extend_from_slice(&VALIDATOR_STAKE.to_le_bytes());
        val_data.push(0x00); // Active
        smt.insert(pyde_state::keys::validator_key(&offender_addr), val_data)
            .unwrap();

        let mut submitter_account =
            pyde_account::types::Account::new_eoa(submitter_pk.as_bytes());
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
        // exactly what an equivocating proposer would produce.
        let slot = 100u64;
        let hash_1 = [0xA1u8; 32];
        let hash_2 = [0xA2u8; 32];
        let sign_msg_1 = {
            let mut m = Vec::with_capacity(40);
            m.extend_from_slice(&slot.to_le_bytes());
            m.extend_from_slice(&hash_1);
            m
        };
        let sign_msg_2 = {
            let mut m = Vec::with_capacity(40);
            m.extend_from_slice(&slot.to_le_bytes());
            m.extend_from_slice(&hash_2);
            m
        };
        let sig_1 = falcon_sign(&offender_sk, &sign_msg_1)
            .unwrap()
            .as_bytes()
            .to_vec();
        let sig_2 = falcon_sign(&offender_sk, &sign_msg_2)
            .unwrap()
            .as_bytes()
            .to_vec();

        // Push into the engine's queue, exactly as the detection site does.
        let identity = ValidatorIdentity {
            address: submitter_addr,
            public_key: submitter_pk,
            secret_key: submitter_sk,
            committee_index: 0,
            key_share: None,
        };
        let mut engine = ValidatorEngine::new([0xAA; 32]);
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
        engine.drain_evidence_into_slash_txs(&identity, 0, 1, &mut slash_txs);
        assert_eq!(slash_txs.len(), 1);

        // Execute on the SMT.
        let ctx = BlockContext {
            height: 101,
            timestamp: 1_000_000,
            base_fee: 1_000,
            block_gas_limit: 400_000_000,
            chain_id: 1,
            validator_address: [0xEE; 32],
            dev_skip_signature: false,
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
        // Layout: [pk_len:4 LE][pk][stake:16 LE][status:1].
        let pk_len =
            u32::from_le_bytes(val_data[0..4].try_into().unwrap()) as usize;
        let stake_offset = 4 + pk_len;
        let stake = u128::from_le_bytes(
            val_data[stake_offset..stake_offset + 16].try_into().unwrap(),
        );
        let status = val_data[stake_offset + 16];
        assert_eq!(stake, 0, "offender stake must be fully slashed");
        assert_eq!(status, 0x02, "offender must be marked Ejected");

        // Submitter: balance increased by finder's fee (10% of stake) minus gas.
        let raw = smt.get(&pyde_state::keys::balance_key(&submitter_addr)).unwrap();
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
        let committee_keys: Vec<Vec<u8>> = identities.iter()
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
            let mut voter_engine = ValidatorEngine::new([0xAA; 32]);
            voter_engine.set_committee(committee_keys.clone());
            voter_engine.advance_slot();
            if let Some(vote) = voter_engine.on_proposal(&header, id) {
                votes.push(vote);
            }
        }
        assert_eq!(votes.len(), 3);

        // Collect votes in a single engine (simulates the proposer node)
        let mut collector = ValidatorEngine::new([0xAA; 32]);
        collector.set_committee(committee_keys);
        collector.advance_slot();

        let mut qc_formed = false;
        for vote in votes {
            if let Some(qc) = collector.on_vote(vote) {
                qc_formed = true;
                assert!(qc.vote_count() >= 2);
            }
        }

        assert!(qc_formed, "QC should form with 3 votes in 3-member committee (quorum=2)");
    }

    #[test]
    fn two_node_qc_requires_both_votes() {
        // 2-member committee: quorum_for_committee(2) = 2
        let (_, identities) = make_engine_with_committee(2);
        let committee_keys: Vec<Vec<u8>> = identities.iter()
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
            let mut voter_engine = ValidatorEngine::new([0xAA; 32]);
            voter_engine.set_committee(committee_keys.clone());
            voter_engine.advance_slot();
            if let Some(vote) = voter_engine.on_proposal(&header, id) {
                votes.push(vote);
            }
        }
        assert_eq!(votes.len(), 2);

        // Collector engine
        let mut collector = ValidatorEngine::new([0xAA; 32]);
        collector.set_committee(committee_keys);
        collector.advance_slot();

        // First vote — not enough
        assert!(collector.on_vote(votes[0].clone()).is_none(), "1/2 votes should not form QC");

        // Second vote — QC forms
        let qc = collector.on_vote(votes[1].clone());
        assert!(qc.is_some(), "2/2 votes should form QC");
        assert_eq!(qc.unwrap().vote_count(), 2);
    }

    #[test]
    fn old_votes_pruned() {
        let mut engine = ValidatorEngine::new([0; 32]);
        engine.votes.insert(1, SlotVotes {
            block_hash: [0; 32],
            votes: vec![],
        });
        engine.votes.insert(5, SlotVotes {
            block_hash: [0; 32],
            votes: vec![],
        });

        // Advance past slot 15 to trigger pruning (prune < slot - 10 = 5)
        engine.consensus.current_slot = 14;
        engine.advance_slot(); // now at 15

        assert!(engine.votes.get(&1).is_none()); // pruned
        assert!(engine.votes.get(&5).is_some()); // kept (>= 5)
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
            ExecutionSchedule { groups: vec![], total_txs: 0 },
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

        let identity = ValidatorIdentity {
            address,
            public_key: pk,
            secret_key: sk,
            committee_index: 0,
            key_share: Some(key_shares[0].clone()),
        };

        // Create an encrypted tx to generate shares for
        let to = derive_eoa_address(b"to");
        let enc_tx = pyde_mempool::encrypted::encrypt_transaction(
            address, 0, 50_000,
            vec![pyde_tx::types::AccessEntry {
                address: derive_eoa_address(b"contract"),
                reads: vec![[0x01; 32]],
                writes: vec![],
            }],
            None, 1, vec![0xAA; 666], &to, 0, b"", &tpk,
        ).unwrap();

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

        let identity = ValidatorIdentity {
            address,
            public_key: pk,
            secret_key: sk,
            committee_index: 0,
            key_share: Some(key_shares[0].clone()),
        };

        let to = derive_eoa_address(b"to");
        let enc_tx = pyde_mempool::encrypted::encrypt_transaction(
            address, 0, 50_000,
            vec![pyde_tx::types::AccessEntry {
                address: derive_eoa_address(b"contract"),
                reads: vec![[0x01; 32]],
                writes: vec![],
            }],
            None, 1, vec![0xAA; 666], &to, 0, b"", &tpk,
        ).unwrap();

        let decryptor = engine.start_decryption(&identity, vec![enc_tx], 2).unwrap();
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
            Self { state, chain, block_store, key_share, _tmp: tmp }
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
        sender_keys: &(pyde_crypto::falcon::FalconPublicKey, pyde_crypto::falcon::FalconSecretKey),
        recipient: Address,
        value: u128,
        nonce: u64,
    ) -> EncryptedTx {
        let (pk, sk) = sender_keys;
        let sender = pyde_account::address::derive_eoa_address(pk.as_bytes());
        let template = encrypt_transaction(
            sender, nonce, 100_000,
            e2e_access_list(), None, 31337,
            vec![0u8; 666], &recipient, value, b"",
            tpk,
        ).unwrap();
        let hash = template.hash();
        let sig = pyde_crypto::falcon::falcon_sign(sk, &hash).unwrap().to_vec();
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
                execution_schedule: ExecutionSchedule { groups: vec![], total_txs: 0 },
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
            .map(|n| pyde_crypto::threshold::generate_decryption_share(&n.key_share, &enc_tx.ciphertext))
            .collect();

        // Every validator then runs the decrypt+execute path. Uses the
        // same `try_decrypt_and_execute` helper the production node loop
        // calls — so the MEV invariant check (slice 3.1's second-chance
        // tx_root verify) fires on every node.
        for node in &mut nodes {
            let mut decryptor = BlockDecryptor::new(vec![enc_tx.clone()], 2).unwrap();
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
            [0xAA; 32], 0, 100_000,
            e2e_access_list(), None, 31337,
            vec![0xAA; 666], &[0x11; 32], 100, b"swap-a",
            &tpk,
        ).unwrap();
        let tx_b = encrypt_transaction(
            [0xBB; 32], 1, 100_000,
            e2e_access_list(), None, 31337,
            vec![0xBB; 666], &[0x22; 32], 200, b"swap-b",
            &tpk,
        ).unwrap();

        // Honest tx_root commits to [A, B]; tampered body ships [B, A].
        let honest_tx_root = pyde_consensus::block::compute_tx_root(
            &[], &[tx_a.hash(), tx_b.hash()],
        );
        let header = e2e_header(1, [0u8; 32], state.root(), honest_tx_root);
        let tampered = Block {
            header,
            body: BlockBody {
                transactions: vec![],
                encrypted_txs: vec![tx_b.to_bytes(), tx_a.to_bytes()],
                execution_schedule: ExecutionSchedule { groups: vec![], total_txs: 0 },
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
            [0xAA; 32], 0, 100_000,
            e2e_access_list(), None, 31337,
            vec![0xAA; 666], &[0x11; 32], 100, b"victim-swap",
            &tpk,
        ).unwrap();
        let sandwich_front = encrypt_transaction(
            [0xEE; 32], 0, 100_000,
            e2e_access_list(), None, 31337,
            vec![0xEE; 666], &[0x22; 32], 50_000, b"front",
            &tpk,
        ).unwrap();

        let honest_tx_root = pyde_consensus::block::compute_tx_root(&[], &[victim.hash()]);
        let header = e2e_header(1, [0u8; 32], state.root(), honest_tx_root);
        let tampered = Block {
            header,
            body: BlockBody {
                transactions: vec![],
                encrypted_txs: vec![sandwich_front.to_bytes(), victim.to_bytes()],
                execution_schedule: ExecutionSchedule { groups: vec![], total_txs: 0 },
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

        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let bs = BlockStore::open(tmp.path()).unwrap();

        // Alice funded with proper on-chain auth key.
        let mut alice_account = pyde_account::types::Account::new_eoa(alice_keys.0.as_bytes());
        alice_account.balance = 10_000_000_000_000_000_000_u128;
        state.insert(
            pyde_state::keys::balance_key(&alice),
            alice_account.to_bytes(),
        ).unwrap();
        state.refresh_root();

        // Byzantine proposer forges: sender=alice, garbage sig, but the
        // transfer ciphertext actually moves Alice's funds to attacker.
        // (In a real attack the sig would be something plausible-looking,
        // but a 666-byte garbage blob is indistinguishable at mempool
        // structural check.)
        let template = encrypt_transaction(
            alice, 0, 100_000,
            e2e_access_list(), None, 31337,
            vec![0xFF; 666], &attacker, 1_000, b"",
            &tpk,
        ).unwrap();
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
                execution_schedule: ExecutionSchedule { groups: vec![], total_txs: 0 },
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
            .take(2)
            .map(|ks| pyde_crypto::threshold::generate_decryption_share(ks, &forged.ciphertext))
            .collect();
        let mut decryptor = BlockDecryptor::new(vec![forged], 2).unwrap();
        decryptor.add_share(0, shares[0].clone());
        decryptor.add_share(0, shares[1].clone());
        let outcome = try_decrypt_and_execute(
            &bs, 1, &mut decryptor, &mut state,
            400_000_000, 1_000_000_000, 31337, [0u8; 32],
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

        // Both senders get FALCON-backed accounts so execute-time auth
        // verification accepts the honest txs. (Proves the ordering
        // invariant independently of the byzantine-proposer auth hole.)
        let sender_a_keys = falcon_keygen().unwrap();
        let sender_b_keys = falcon_keygen().unwrap();
        let tx_a = e2e_signed_encrypted(&tpk, &sender_a_keys, [0x11; 32], 100, 0);
        let tx_b = e2e_signed_encrypted(&tpk, &sender_b_keys, [0x22; 32], 200, 0);

        let committed_root = pyde_consensus::block::compute_tx_root(
            &[], &[tx_a.hash(), tx_b.hash()],
        );
        let header = e2e_header(1, [0u8; 32], [0u8; 32], committed_root);
        let block = Block {
            header: header.clone(),
            body: BlockBody {
                transactions: vec![],
                encrypted_txs: vec![tx_a.to_bytes(), tx_b.to_bytes()],
                execution_schedule: ExecutionSchedule { groups: vec![], total_txs: 0 },
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
            state.insert(
                pyde_state::keys::balance_key(&addr),
                acct.to_bytes(),
            ).unwrap();
        }
        state.refresh_root();

        // Honest decryptor, committed order [A, B].
        let mut honest = BlockDecryptor::new(vec![tx_a.clone(), tx_b.clone()], 2).unwrap();
        honest.add_share(0, pyde_crypto::threshold::generate_decryption_share(&shares[0], &tx_a.ciphertext));
        honest.add_share(0, pyde_crypto::threshold::generate_decryption_share(&shares[1], &tx_a.ciphertext));
        honest.add_share(1, pyde_crypto::threshold::generate_decryption_share(&shares[0], &tx_b.ciphertext));
        honest.add_share(1, pyde_crypto::threshold::generate_decryption_share(&shares[1], &tx_b.ciphertext));
        let honest_outcome = try_decrypt_and_execute(
            &bs, 1, &mut honest, &mut state,
            400_000_000, 1_000_000_000, 31337, [0u8; 32],
        );
        assert!(
            matches!(honest_outcome, DecryptOutcome::Executed { tx_count: 2, .. }),
            "honest-order decrypt must run; got {:?}",
            honest_outcome
        );

        // Tampered decryptor flipping to [B, A] is rejected by the
        // second-chance tx_root check in try_decrypt_and_execute.
        let mut tampered = BlockDecryptor::new(vec![tx_b, tx_a], 2).unwrap();
        let tampered_outcome = try_decrypt_and_execute(
            &bs, 1, &mut tampered, &mut state,
            400_000_000, 1_000_000_000, 31337, [0u8; 32],
        );
        assert!(
            matches!(tampered_outcome, DecryptOutcome::TxRootMismatch),
            "reordered decryptor must be rejected; got {:?}",
            tampered_outcome
        );
    }
}
