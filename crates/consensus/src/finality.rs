//! Soft and hard finality per Chapter 6, Sections 6.5-6.6.
//!
//! **Soft finality (~400ms)**: block has a valid QC (86+ votes).
//! - Content finality: transactions and ordering locked.
//! - No rollback under honest majority (<1/3 malicious).
//! - Full nodes execute optimistically — state changes applied here.
//! - Use cases: payments, DEX orders, game state, social.
//!
//! **Hard finality (~2.5s)**: soft finality + 86+ finality signatures.
//! - Execution correctness: validators attest to the committed state root.
//! - Irreversibility: cannot revert without breaking BFT assumptions.
//! - Use cases: bridge transfers, large settlements, governance.

use crate::block::{QuorumCert, QUORUM_THRESHOLD};
use pyde_account::address::Address;
use pyde_crypto::falcon::{
    falcon_sign, falcon_verify, FalconPublicKey, FalconSecretKey, FalconSignature,
};

/// Finality level for a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FinalityLevel {
    /// Not finalized — pending votes.
    None,
    /// Soft finality: QC with 86+ votes exists.
    Soft,
    /// Hard finality: soft + 86+ finality signatures.
    Hard,
}

/// Finality status for a specific block.
#[derive(Clone, Debug)]
pub struct FinalityStatus {
    /// Slot of the block.
    pub slot: u64,
    /// Block hash.
    pub block_hash: [u8; 32],
    /// Current finality level.
    pub level: FinalityLevel,
    /// QC for this block (if soft-finalized).
    pub qc: Option<QuorumCert>,
    /// Hard finality certificate (if hard-finalized).
    pub hard_cert: Option<HardFinalityCert>,
}

/// Hard finality certificate: validators attest to the block's state transition.
#[derive(Clone, Debug)]
pub struct HardFinalityCert {
    /// Slot of the block.
    pub slot: u64,
    /// Block hash.
    pub block_hash: [u8; 32],
    /// State root after execution.
    pub state_root: [u8; 32],
    /// 128-bit bitmap of which validators signed the finality cert.
    pub voter_bitmap: u128,
    /// FALCON signatures from validators who attested to finality.
    pub signatures: Vec<Vec<u8>>,
}

impl HardFinalityCert {
    pub fn vote_count(&self) -> u32 {
        self.voter_bitmap.count_ones()
    }

    pub fn has_quorum(&self) -> bool {
        self.vote_count() >= QUORUM_THRESHOLD as u32
    }
}

/// A finality vote: validator attests to a block's state transition.
#[derive(Clone, Debug)]
pub struct FinalityVote {
    pub slot: u64,
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub voter_index: u8,
    pub voter_address: Address,
    pub signature: Vec<u8>,
}

/// Build the message validators sign for hard finality.
fn finality_sign_message(slot: u64, block_hash: &[u8; 32], state_root: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(85); // "hard_finality"(13) + slot(8) + 2×hash(64)
    msg.extend_from_slice(b"hard_finality");
    msg.extend_from_slice(&slot.to_le_bytes());
    msg.extend_from_slice(block_hash);
    msg.extend_from_slice(state_root);
    msg
}

// ========== Soft Finality ==========

/// Check if a block has reached soft finality (QC with 86+ votes).
pub fn check_soft_finality(qc: &QuorumCert) -> bool {
    qc.has_quorum()
}

/// Detect soft finality and return status.
pub fn soft_finality_status(slot: u64, block_hash: [u8; 32], qc: &QuorumCert) -> FinalityStatus {
    let level = if check_soft_finality(qc) {
        FinalityLevel::Soft
    } else {
        FinalityLevel::None
    };

    FinalityStatus {
        slot,
        block_hash,
        level,
        qc: Some(qc.clone()),
        hard_cert: None,
    }
}

// ========== Hard Finality ==========

/// Create a finality vote attesting to a block's state transition.
pub fn create_finality_vote(
    slot: u64,
    block_hash: [u8; 32],
    state_root: [u8; 32],
    voter_index: u8,
    voter_address: Address,
    voter_sk: &FalconSecretKey,
) -> Result<FinalityVote, &'static str> {
    let msg = finality_sign_message(slot, &block_hash, &state_root);
    let sig = falcon_sign(voter_sk, &msg).map_err(|_| "finality vote signing failed")?;

    Ok(FinalityVote {
        slot,
        block_hash,
        state_root,
        voter_index,
        voter_address,
        signature: sig.as_bytes().to_vec(),
    })
}

/// Verify a finality vote.
pub fn verify_finality_vote(vote: &FinalityVote, public_key: &[u8]) -> bool {
    let pk = match FalconPublicKey::from_bytes(public_key) {
        Some(pk) => pk,
        None => return false,
    };
    let msg = finality_sign_message(vote.slot, &vote.block_hash, &vote.state_root);
    let sig = match FalconSignature::from_bytes(&vote.signature) {
        Some(s) => s,
        None => return false,
    };
    falcon_verify(&pk, &msg, &sig)
}

/// Try to form a hard finality certificate from collected finality votes.
pub fn try_form_hard_finality(
    slot: u64,
    block_hash: [u8; 32],
    state_root: [u8; 32],
    votes: &[FinalityVote],
    committee_keys: &[Vec<u8>],
) -> Option<HardFinalityCert> {
    let mut voter_bitmap: u128 = 0;
    let mut signatures = Vec::new();
    let mut valid_count = 0u32;

    for vote in votes {
        if vote.slot != slot || vote.block_hash != block_hash {
            continue;
        }
        if vote.state_root != state_root {
            continue;
        }

        let idx = vote.voter_index as usize;
        if idx >= committee_keys.len() {
            continue;
        }

        // Skip duplicates
        if voter_bitmap & (1u128 << idx) != 0 {
            continue;
        }

        if verify_finality_vote(vote, &committee_keys[idx]) {
            voter_bitmap |= 1u128 << idx;
            signatures.push(vote.signature.clone());
            valid_count += 1;
        }
    }

    if valid_count >= QUORUM_THRESHOLD as u32 {
        Some(HardFinalityCert {
            slot,
            block_hash,
            state_root,
            voter_bitmap,
            signatures,
        })
    } else {
        None
    }
}

// ========== Finality Checkpoint ==========

/// A finality checkpoint: a hard-finalized block that anchors the chain.
/// Blocks at or before a checkpoint cannot be reorganized.
#[derive(Clone, Debug)]
pub struct FinalityCheckpoint {
    pub slot: u64,
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub cert: HardFinalityCert,
}

/// Finality tracker: manages finality state for the chain.
#[derive(Clone, Debug, Default)]
pub struct FinalityTracker {
    /// Latest hard-finalized checkpoint.
    pub latest_checkpoint: Option<FinalityCheckpoint>,
    /// Pending finality statuses for recent blocks.
    pub pending: Vec<FinalityStatus>,
    /// Highest soft-finalized slot.
    pub highest_soft_slot: u64,
    /// Highest hard-finalized slot.
    pub highest_hard_slot: u64,
}

impl FinalityTracker {
    pub fn new() -> Self {
        Self {
            latest_checkpoint: None,
            pending: Vec::new(),
            highest_soft_slot: 0,
            highest_hard_slot: 0,
        }
    }

    /// Number of blocks with soft finality but no hard finality yet.
    pub fn unconfirmed_count(&self) -> u64 {
        self.highest_soft_slot
            .saturating_sub(self.highest_hard_slot)
    }

    /// Record soft finality for a block.
    pub fn record_soft_finality(&mut self, slot: u64, block_hash: [u8; 32], qc: QuorumCert) {
        let status = soft_finality_status(slot, block_hash, &qc);
        if status.level == FinalityLevel::Soft {
            if slot > self.highest_soft_slot {
                self.highest_soft_slot = slot;
            }
            self.pending.push(status);
        }
    }

    /// Record hard finality and create a checkpoint.
    pub fn record_hard_finality(&mut self, cert: HardFinalityCert) {
        if cert.slot > self.highest_hard_slot {
            self.highest_hard_slot = cert.slot;
        }
        let checkpoint = FinalityCheckpoint {
            slot: cert.slot,
            block_hash: cert.block_hash,
            state_root: cert.state_root,
            cert,
        };

        // Update pending status
        for status in &mut self.pending {
            if status.slot == checkpoint.slot && status.block_hash == checkpoint.block_hash {
                status.level = FinalityLevel::Hard;
                status.hard_cert = Some(checkpoint.cert.clone());
            }
        }

        let checkpoint_slot = checkpoint.slot;
        self.latest_checkpoint = Some(checkpoint);

        // Prune pending entries at or before the checkpoint
        self.pending.retain(|s| s.slot > checkpoint_slot);
    }

    /// Check if a block can be reorganized (only if before latest checkpoint).
    pub fn can_reorg(&self, slot: u64) -> bool {
        match &self.latest_checkpoint {
            Some(cp) => slot > cp.slot,
            None => true, // no checkpoint yet, everything can reorg
        }
    }

    /// Get the finality level for a specific block.
    pub fn finality_level(&self, slot: u64, block_hash: &[u8; 32]) -> FinalityLevel {
        // Check if it's at or before the checkpoint
        if let Some(cp) = &self.latest_checkpoint {
            if slot == cp.slot && *block_hash == cp.block_hash {
                return FinalityLevel::Hard;
            }
            if slot < cp.slot {
                return FinalityLevel::Hard; // implicitly finalized by later checkpoint
            }
        }

        // Check pending
        for status in &self.pending {
            if status.slot == slot && status.block_hash == *block_hash {
                return status.level;
            }
        }

        FinalityLevel::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::falcon::falcon_keygen;

    fn make_qc(slot: u64, votes: u32) -> QuorumCert {
        QuorumCert {
            slot,
            block_hash: [0xAA; 32],
            voter_bitmap: if votes >= 128 {
                u128::MAX
            } else {
                (1u128 << votes) - 1
            },
            signatures: vec![],
        }
    }

    // ========== Task 0498: Soft finality at 86/128 ==========

    #[test]
    fn soft_finality_at_86_votes() {
        let qc = make_qc(5, 86);
        assert!(check_soft_finality(&qc));
    }

    #[test]
    fn no_soft_finality_at_85_votes() {
        let qc = make_qc(5, 85);
        assert!(!check_soft_finality(&qc));
    }

    #[test]
    fn soft_finality_status_detected() {
        let qc = make_qc(5, 100);
        let status = soft_finality_status(5, [0xAA; 32], &qc);
        assert_eq!(status.level, FinalityLevel::Soft);
    }

    // ========== Task 0499: Soft finality timing ==========

    #[test]
    fn soft_finality_is_immediate_with_qc() {
        // Soft finality is a property check, not time-based.
        // It's reached the moment the QC has 86+ votes.
        let qc = make_qc(5, 86);
        assert!(check_soft_finality(&qc)); // instant
    }

    // ========== Task 0503: Hard finality with quorum ==========

    #[test]
    fn hard_finality_with_86_votes() {
        let mut votes = Vec::new();
        let mut keys = Vec::new();

        let block_hash = [0xAA; 32];
        let state_root = [0xCC; 32];

        for i in 0..86u8 {
            let (pk, sk) = falcon_keygen().unwrap();
            let pk_bytes = pk.as_bytes().to_vec();
            let addr = derive_eoa_address(&pk_bytes);

            let vote = create_finality_vote(5, block_hash, state_root, i, addr, &sk).unwrap();
            votes.push(vote);
            keys.push(pk_bytes);
        }

        while keys.len() < 128 {
            keys.push(vec![0; 897]);
        }

        let cert = try_form_hard_finality(5, block_hash, state_root, &votes, &keys);
        assert!(cert.is_some());
        assert!(cert.unwrap().has_quorum());
    }

    #[test]
    fn no_hard_finality_with_85_votes() {
        let mut votes = Vec::new();
        let mut keys = Vec::new();

        for i in 0..85u8 {
            let (pk, sk) = falcon_keygen().unwrap();
            let pk_bytes = pk.as_bytes().to_vec();
            let addr = derive_eoa_address(&pk_bytes);

            let vote = create_finality_vote(5, [0xAA; 32], [0xCC; 32], i, addr, &sk).unwrap();
            votes.push(vote);
            keys.push(pk_bytes);
        }

        while keys.len() < 128 {
            keys.push(vec![0; 897]);
        }

        let cert = try_form_hard_finality(5, [0xAA; 32], [0xCC; 32], &votes, &keys);
        assert!(cert.is_none());
    }

    #[test]
    fn finality_vote_verified() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let addr = derive_eoa_address(&pk_bytes);

        let vote = create_finality_vote(5, [0xAA; 32], [0xCC; 32], 0, addr, &sk).unwrap();
        assert!(verify_finality_vote(&vote, &pk_bytes));
    }

    #[test]
    fn finality_vote_wrong_key_rejected() {
        let (pk1, sk1) = falcon_keygen().unwrap();
        let (pk2, _sk2) = falcon_keygen().unwrap();
        let addr = derive_eoa_address(pk1.as_bytes());

        let vote = create_finality_vote(5, [0xAA; 32], [0xCC; 32], 0, addr, &sk1).unwrap();
        assert!(!verify_finality_vote(&vote, pk2.as_bytes()));
    }

    // ========== Task 0504: Before hard finality can reorg ==========

    #[test]
    fn blocks_before_checkpoint_cannot_reorg() {
        let mut tracker = FinalityTracker::new();

        // No checkpoint → everything can reorg
        assert!(tracker.can_reorg(10));

        // Create checkpoint at slot 50
        let cert = HardFinalityCert {
            slot: 50,
            block_hash: [0xAA; 32],
            state_root: [0xCC; 32],
            voter_bitmap: (1u128 << 86) - 1,
            signatures: vec![],
        };
        tracker.record_hard_finality(cert);

        // Slot 50 and before: cannot reorg
        assert!(!tracker.can_reorg(50));
        assert!(!tracker.can_reorg(30));

        // Slot 51 and after: can reorg (not yet finalized)
        assert!(tracker.can_reorg(51));
    }

    // ========== Task 0505: After hard finality cannot reorg ==========

    #[test]
    fn hard_finalized_block_is_irreversible() {
        let mut tracker = FinalityTracker::new();

        let cert = HardFinalityCert {
            slot: 100,
            block_hash: [0xAA; 32],
            state_root: [0xCC; 32],
            voter_bitmap: (1u128 << 86) - 1,
            signatures: vec![],
        };
        tracker.record_hard_finality(cert);

        assert_eq!(
            tracker.finality_level(100, &[0xAA; 32]),
            FinalityLevel::Hard
        );
        assert!(!tracker.can_reorg(100));
    }

    // ========== Finality tracker ==========

    #[test]
    fn tracker_records_soft_then_hard() {
        let mut tracker = FinalityTracker::new();

        // Soft finality
        let qc = make_qc(10, 90);
        tracker.record_soft_finality(10, [0xAA; 32], qc);
        assert_eq!(tracker.finality_level(10, &[0xAA; 32]), FinalityLevel::Soft);

        // Hard finality
        let cert = HardFinalityCert {
            slot: 10,
            block_hash: [0xAA; 32],
            state_root: [0xCC; 32],
            voter_bitmap: (1u128 << 86) - 1,
            signatures: vec![],
        };
        tracker.record_hard_finality(cert);
        assert_eq!(tracker.finality_level(10, &[0xAA; 32]), FinalityLevel::Hard);
    }

    #[test]
    fn finality_levels_ordered() {
        assert!(FinalityLevel::None < FinalityLevel::Soft);
        assert!(FinalityLevel::Soft < FinalityLevel::Hard);
    }

    #[test]
    fn checkpoint_prunes_old_pending() {
        let mut tracker = FinalityTracker::new();

        // Add soft finality for slots 5, 10, 15
        for slot in [5, 10, 15] {
            tracker.record_soft_finality(slot, [slot as u8; 32], make_qc(slot, 90));
        }
        assert_eq!(tracker.pending.len(), 3);

        // Hard finality at slot 10 prunes slots <= 10
        let cert = HardFinalityCert {
            slot: 10,
            block_hash: [10; 32],
            state_root: [0xCC; 32],
            voter_bitmap: (1u128 << 86) - 1,
            signatures: vec![],
        };
        tracker.record_hard_finality(cert);

        // Only slot 15 remains pending
        assert_eq!(tracker.pending.len(), 1);
        assert_eq!(tracker.pending[0].slot, 15);
    }

    // ========== Unconfirmed count ==========

    #[test]
    fn unconfirmed_count_tracks_gap() {
        let mut tracker = FinalityTracker::new();

        // Soft finality for slots 1-50
        for slot in 1..=50 {
            tracker.record_soft_finality(slot, [slot as u8; 32], make_qc(slot, 90));
        }
        assert_eq!(tracker.unconfirmed_count(), 50);

        // Hard finality for slot 20
        let cert = HardFinalityCert {
            slot: 20,
            block_hash: [20; 32],
            state_root: [0xCC; 32],
            voter_bitmap: (1u128 << 86) - 1,
            signatures: vec![],
        };
        tracker.record_hard_finality(cert);
        assert_eq!(tracker.unconfirmed_count(), 30); // 50 - 20
    }

    #[test]
    fn tracker_hard_finality_catches_up() {
        let mut tracker = FinalityTracker::new();

        // Soft finality races ahead
        for slot in 1..=150 {
            tracker.record_soft_finality(slot, [slot as u8; 32], make_qc(slot, 90));
        }
        assert_eq!(tracker.unconfirmed_count(), 150);

        // Hard finality catches up
        let cert = HardFinalityCert {
            slot: 100,
            block_hash: [100; 32],
            state_root: [0xCC; 32],
            voter_bitmap: (1u128 << 86) - 1,
            signatures: vec![],
        };
        tracker.record_hard_finality(cert);
        assert_eq!(tracker.unconfirmed_count(), 50); // 150 - 100
    }
}
