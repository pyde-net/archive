//! View change protocol: leader failure recovery per Chapter 6, Section 6.9.
//!
//! When the proposer fails to produce a block within 200ms:
//! 1. Validators broadcast ViewChange messages with their highest QC
//! 2. Upon collecting 86+ ViewChange messages → form ViewChangeQC
//! 3. Fallback proposer (2nd lowest VRF score) takes over
//! 4. If fallback also fails → empty block, advance to next slot
//!
//! Liveness: guaranteed if 86+ of 128 validators are honest and online.

use crate::block::{BlockHeader, QuorumCert, COMMITTEE_SIZE, QUORUM_THRESHOLD};
use pyde_account::address::Address;
use pyde_crypto::falcon::{falcon_sign, falcon_verify, FalconPublicKey, FalconSecretKey, FalconSignature};

/// Timeout duration before declaring proposer failure (milliseconds).
pub const PROPOSAL_TIMEOUT_MS: u64 = 200;

/// Slot duration (milliseconds).
pub const SLOT_DURATION_MS: u64 = 400;

/// A view change message broadcast when a proposer fails.
#[derive(Clone, Debug)]
pub struct ViewChangeMessage {
    /// The slot that timed out.
    pub slot: u64,
    /// The highest QC this validator has seen.
    pub highest_qc: QuorumCert,
    /// Validator's committee index.
    pub voter_index: u8,
    /// Validator's address.
    pub voter_address: Address,
    /// FALCON signature over (slot || "view_change").
    pub signature: Vec<u8>,
}

/// A ViewChange QC: proof that 86+ validators reported timeout.
#[derive(Clone, Debug)]
pub struct ViewChangeQC {
    /// The slot that timed out.
    pub slot: u64,
    /// The highest QC from all view change messages (the one with max slot).
    pub highest_qc: QuorumCert,
    /// Bitmap of which validators sent view change messages.
    pub voter_bitmap: u128,
    /// Number of valid view change messages.
    pub vote_count: u32,
}

impl ViewChangeQC {
    /// Whether enough validators reported timeout.
    pub fn has_quorum(&self) -> bool {
        self.vote_count >= QUORUM_THRESHOLD as u32
    }
}

/// Timeout state tracker for a single slot.
#[derive(Clone, Debug)]
pub struct TimeoutTracker {
    /// Slot being tracked.
    pub slot: u64,
    /// Collected view change messages.
    pub messages: Vec<ViewChangeMessage>,
    /// Whether a valid proposal was received (cancels timeout).
    pub proposal_received: bool,
    /// Whether view change QC has been formed.
    pub view_change_qc: Option<ViewChangeQC>,
}

impl TimeoutTracker {
    pub fn new(slot: u64) -> Self {
        Self {
            slot,
            messages: Vec::new(),
            proposal_received: false,
            view_change_qc: None,
        }
    }

    /// Mark that a valid proposal was received (cancels timeout).
    pub fn receive_proposal(&mut self) {
        self.proposal_received = true;
    }

    /// Whether this slot has timed out (no proposal and no QC yet).
    pub fn is_timed_out(&self) -> bool {
        !self.proposal_received && self.view_change_qc.is_none()
    }
}

/// Build the message that validators sign for view change.
fn view_change_sign_message(slot: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(16);
    msg.extend_from_slice(b"view_change");
    msg.extend_from_slice(&slot.to_le_bytes());
    msg
}

/// Create a view change message when timeout is detected.
pub fn create_view_change(
    slot: u64,
    highest_qc: &QuorumCert,
    voter_index: u8,
    voter_address: Address,
    voter_sk: &FalconSecretKey,
) -> ViewChangeMessage {
    let msg = view_change_sign_message(slot);
    let sig = falcon_sign(voter_sk, &msg);

    ViewChangeMessage {
        slot,
        highest_qc: highest_qc.clone(),
        voter_index,
        voter_address,
        signature: sig.as_bytes().to_vec(),
    }
}

/// Verify a view change message.
pub fn verify_view_change(msg: &ViewChangeMessage, public_key: &[u8]) -> bool {
    let pk = match FalconPublicKey::from_bytes(public_key) {
        Some(pk) => pk,
        None => return false,
    };
    let sign_msg = view_change_sign_message(msg.slot);
    let sig = FalconSignature::from_bytes(&msg.signature);
    falcon_verify(&pk, &sign_msg, &sig)
}

/// Try to form a ViewChangeQC from collected messages.
/// Returns Some(ViewChangeQC) if 86+ valid messages for the same slot.
pub fn try_form_view_change_qc(
    slot: u64,
    messages: &[ViewChangeMessage],
    committee_keys: &[Vec<u8>],
) -> Option<ViewChangeQC> {
    let mut voter_bitmap: u128 = 0;
    let mut valid_count = 0u32;
    let mut highest_qc = QuorumCert::empty();

    for msg in messages {
        if msg.slot != slot {
            continue;
        }

        let idx = msg.voter_index as usize;
        if idx >= committee_keys.len() {
            continue;
        }

        // Skip duplicates
        if voter_bitmap & (1u128 << idx) != 0 {
            continue;
        }

        if verify_view_change(msg, &committee_keys[idx]) {
            voter_bitmap |= 1u128 << idx;
            valid_count += 1;

            // Track highest QC across all messages
            if msg.highest_qc.slot > highest_qc.slot {
                highest_qc = msg.highest_qc.clone();
            }
        }
    }

    if valid_count >= QUORUM_THRESHOLD as u32 {
        Some(ViewChangeQC {
            slot,
            highest_qc,
            voter_bitmap,
            vote_count: valid_count,
        })
    } else {
        None
    }
}

/// Determine the fallback proposer for a slot.
/// The fallback is the committee member with the 2nd lowest VRF score.
/// `sorted_scores` should be (address, score) sorted by score ascending.
pub fn fallback_proposer(sorted_scores: &[(Address, u64)]) -> Option<Address> {
    sorted_scores.get(1).map(|(addr, _)| *addr)
}

/// Create an empty block header for when both primary and fallback fail.
pub fn empty_block_header(
    slot: u64,
    epoch: u64,
    parent_hash: [u8; 32],
    qc_previous: QuorumCert,
    state_root: [u8; 32],
    timestamp: u64,
) -> BlockHeader {
    BlockHeader {
        slot,
        epoch,
        parent_hash,
        proposer: [0u8; 32], // no proposer
        vrf_proof: vec![],
        qc_previous,
        tx_root: [0u8; 32], // no transactions
        state_root,
        timestamp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::falcon::falcon_keygen;

    // ========== Task 0493: Leader timeout → view change → new leader ==========

    #[test]
    fn view_change_message_created_and_verified() {
        let (pk, sk) = falcon_keygen();
        let pk_bytes = pk.as_bytes().to_vec();
        let addr = derive_eoa_address(&pk_bytes);
        let qc = QuorumCert::empty();

        let msg = create_view_change(5, &qc, 0, addr, &sk);
        assert_eq!(msg.slot, 5);
        assert!(verify_view_change(&msg, &pk_bytes));
    }

    #[test]
    fn view_change_wrong_key_rejected() {
        let (pk1, sk1) = falcon_keygen();
        let (pk2, _sk2) = falcon_keygen();
        let addr = derive_eoa_address(pk1.as_bytes());
        let qc = QuorumCert::empty();

        let msg = create_view_change(5, &qc, 0, addr, &sk1);
        assert!(!verify_view_change(&msg, pk2.as_bytes()));
    }

    #[test]
    fn view_change_qc_formed_with_86_messages() {
        let mut messages = Vec::new();
        let mut keys = Vec::new();

        for i in 0..86u8 {
            let (pk, sk) = falcon_keygen();
            let pk_bytes = pk.as_bytes().to_vec();
            let addr = derive_eoa_address(&pk_bytes);
            let qc = QuorumCert::empty();

            let msg = create_view_change(10, &qc, i, addr, &sk);
            messages.push(msg);
            keys.push(pk_bytes);
        }

        while keys.len() < 128 {
            keys.push(vec![0; 897]);
        }

        let vc_qc = try_form_view_change_qc(10, &messages, &keys);
        assert!(vc_qc.is_some());
        assert!(vc_qc.unwrap().has_quorum());
    }

    #[test]
    fn view_change_qc_not_formed_with_85() {
        let mut messages = Vec::new();
        let mut keys = Vec::new();

        for i in 0..85u8 {
            let (pk, sk) = falcon_keygen();
            let pk_bytes = pk.as_bytes().to_vec();
            let addr = derive_eoa_address(&pk_bytes);

            let msg = create_view_change(10, &QuorumCert::empty(), i, addr, &sk);
            messages.push(msg);
            keys.push(pk_bytes);
        }

        while keys.len() < 128 {
            keys.push(vec![0; 897]);
        }

        let vc_qc = try_form_view_change_qc(10, &messages, &keys);
        assert!(vc_qc.is_none());
    }

    // ========== Task 0494: Multiple consecutive failures ==========

    #[test]
    fn fallback_proposer_is_second_lowest() {
        let scores = vec![
            ([0x01; 32], 100),
            ([0x02; 32], 200),
            ([0x03; 32], 300),
        ];
        let fallback = fallback_proposer(&scores).unwrap();
        assert_eq!(fallback, [0x02; 32]); // 2nd lowest
    }

    #[test]
    fn empty_block_when_all_fail() {
        let header = empty_block_header(
            42,
            0,
            [0xAA; 32],
            QuorumCert::empty(),
            [0xBB; 32],
            1_000_000,
        );
        assert_eq!(header.slot, 42);
        assert_eq!(header.proposer, [0u8; 32]); // no proposer
        assert_eq!(header.tx_root, [0u8; 32]); // no txs
    }

    // ========== Task 0495: Safety preserved ==========

    #[test]
    fn view_change_qc_tracks_highest_qc() {
        let mut messages = Vec::new();
        let mut keys = Vec::new();

        for i in 0..86u8 {
            let (pk, sk) = falcon_keygen();
            let pk_bytes = pk.as_bytes().to_vec();
            let addr = derive_eoa_address(&pk_bytes);

            // Validators report different highest QCs
            let qc = QuorumCert {
                slot: i as u64, // different QC slots
                block_hash: [i; 32],
                voter_bitmap: (1u128 << 86) - 1,
                signatures: vec![],
            };

            let msg = create_view_change(100, &qc, i, addr, &sk);
            messages.push(msg);
            keys.push(pk_bytes);
        }

        while keys.len() < 128 {
            keys.push(vec![0; 897]);
        }

        let vc_qc = try_form_view_change_qc(100, &messages, &keys).unwrap();
        // Should pick the highest QC (slot 85)
        assert_eq!(vc_qc.highest_qc.slot, 85);
    }

    // ========== Timeout tracker ==========

    #[test]
    fn timeout_tracker_basic() {
        let mut tracker = TimeoutTracker::new(5);
        assert!(tracker.is_timed_out());

        tracker.receive_proposal();
        assert!(!tracker.is_timed_out());
    }

    #[test]
    fn timeout_cancelled_by_proposal() {
        let mut tracker = TimeoutTracker::new(5);
        assert!(tracker.is_timed_out());
        tracker.receive_proposal();
        assert!(!tracker.is_timed_out());
    }
}
