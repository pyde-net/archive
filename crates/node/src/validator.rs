use pyde_account::address::Address;
use pyde_consensus::block::{
    Block, BlockBody, BlockHeader, QuorumCert, EPOCH_LENGTH,
};
use pyde_consensus::finality::{FinalityTracker, FinalityVote, create_finality_vote, try_form_hard_finality};
use pyde_consensus::hotstuff::{
    ConsensusMessage, ConsensusState, create_vote, try_form_qc, verify_vote,
};
use pyde_consensus::proposer::{compute_candidacy, ProposerCandidate};
use pyde_crypto::vrf::VrfProof;
use pyde_consensus::block::quorum_for_committee;
use pyde_consensus::slashing::{
    DoubleSignEvidence, SlashResult, slash_double_sign, verify_double_sign,
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
use tracing::{debug, info, warn};

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
    /// Collected slashing evidence to broadcast.
    pub pending_slashes: Vec<SlashResult>,
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
            pending_slashes: Vec::new(),
        }
    }

    /// Set the committee keys for the current epoch.
    pub fn set_committee(&mut self, keys: Vec<Vec<u8>>) {
        info!(members = keys.len(), "committee keys loaded");
        self.committee_keys = keys;
    }

    /// Compute VRF candidacy for the current slot.
    /// All validators compute their candidacy and propose. The best proposal
    /// (lowest VRF score) is selected during the proposal phase via `select_and_vote`.
    pub fn check_proposer(&self, identity: &ValidatorIdentity) -> Option<ProposerCandidate> {
        let slot = self.consensus.current_slot;
        match compute_candidacy(
            &identity.public_key,
            &identity.secret_key,
            &self.epoch_randomness,
            slot,
            identity.address,
        ) {
            Ok(candidate) => {
                debug!(slot, score = candidate.score, "computed VRF candidacy");
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

        // Verify proposer signature on block header
        if !proposer_signature.is_empty() {
            let block_hash = header.hash();
            let sig = match pyde_crypto::falcon::FalconSignature::from_bytes(proposer_signature) {
                Some(s) => s,
                None => { warn!(slot, "invalid proposer signature format"); return false; }
            };
            if !pyde_crypto::falcon::falcon_verify(&pk, &block_hash, &sig) {
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
                    block_1: prev_header.clone(),
                    signature_1: prev_sig.clone(),
                    block_2: header.clone(),
                    signature_2: proposer_signature.to_vec(),
                    signer: header.proposer,
                    submitter: [0u8; 32], // self — filled by caller
                };
                if let Some(result) = slash_double_sign(&evidence, &self.committee_keys[proposer_idx]) {
                    info!(
                        slot,
                        offender = hex::encode(result.offender),
                        burned = result.amount_burned,
                        "slash evidence created for double-propose"
                    );
                    self.pending_slashes.push(result);
                }
            }
        } else {
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

        // Sign the block header hash with the proposer's FALCON key
        let block_hash = header.hash();
        let proposer_signature = match pyde_crypto::falcon::falcon_sign(
            &identity.secret_key,
            &block_hash,
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
                if slot > self.consensus.highest_qc.slot {
                    self.consensus.highest_qc = qc.clone();
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

    /// Advance to the next slot. Returns the new slot number.
    pub fn advance_slot(&mut self) -> u64 {
        self.consensus.advance_slot();
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
    fn check_proposer_returns_candidate() {
        let (engine, identities) = make_engine_with_committee(3);
        let candidate = engine.check_proposer(&identities[0]);
        assert!(candidate.is_some());
        assert_eq!(candidate.unwrap().address, identities[0].address);
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
}
