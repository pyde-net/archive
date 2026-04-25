//! Property-based safety invariants for HotStuff consensus.
//!
//! These tests use proptest to generate arbitrary message sequences
//! and assert global safety properties hold for all of them. Each
//! invariant maps to a specific HotStuff safety guarantee:
//!
//! 1. No double-voting per validator per slot (vote uniqueness)
//! 2. No two distinct blocks reach quorum at the same slot when
//!    byzantine count ≤ ⌊N/3⌋ (the central HotStuff safety property)
//! 3. `highest_qc.slot` never regresses across legitimate proposals
//! 4. `try_form_qc` returns Some iff distinct valid voters ≥ quorum
//! 5. `FinalityTracker.latest_checkpoint.slot` is non-decreasing
//!    across out-of-order hard-finality cert delivery
//!
//! Falcon keygen is expensive (~10ms each) so a 128-key fixture is
//! shared across all property cases via OnceLock.

use proptest::prelude::*;
use pyde_account::address::derive_eoa_address;
use pyde_consensus::block::{quorum_for_committee, BlockHeader, QuorumCert, COMMITTEE_SIZE};
use pyde_consensus::finality::{FinalityTracker, HardFinalityCert};
use pyde_consensus::hotstuff::{
    create_vote, proposer_sign_message, try_form_qc, ConsensusMessage, ConsensusState,
};
use pyde_crypto::falcon::{falcon_keygen, falcon_sign, FalconPublicKey, FalconSecretKey};
use std::sync::OnceLock;

fn keys() -> &'static Vec<(FalconPublicKey, FalconSecretKey, Vec<u8>)> {
    static KEYS: OnceLock<Vec<(FalconPublicKey, FalconSecretKey, Vec<u8>)>> = OnceLock::new();
    KEYS.get_or_init(|| {
        (0..COMMITTEE_SIZE)
            .map(|_| {
                let (pk, sk) = falcon_keygen().expect("keygen");
                let bytes = pk.as_bytes().to_vec();
                (pk, sk, bytes)
            })
            .collect()
    })
}

fn committee_keys() -> Vec<Vec<u8>> {
    keys().iter().map(|(_, _, b)| b.clone()).collect()
}

fn make_header(slot: u64, qc: QuorumCert, tx_root_seed: u8) -> BlockHeader {
    BlockHeader {
        slot,
        epoch: slot / 1000,
        parent_hash: [0xAA; 32],
        proposer: derive_eoa_address(&keys()[0].2),
        vrf_proof: vec![],
        qc_previous: qc,
        tx_root: [tx_root_seed; 32],
        state_root: [0; 32],
        timestamp: 1_000_000,
    }
}

fn build_votes_for(slot: u64, block_hash: [u8; 32], voter_indices: &[u8]) -> Vec<ConsensusMessage> {
    voter_indices
        .iter()
        .map(|&i| {
            let (_, sk, pk) = &keys()[i as usize];
            let addr = derive_eoa_address(pk);
            let msg = proposer_sign_message(slot, &block_hash);
            let sig = falcon_sign(sk, &msg).unwrap();
            ConsensusMessage::Vote {
                slot,
                block_hash,
                voter_index: i,
                voter_address: addr,
                signature: sig.as_bytes().to_vec(),
            }
        })
        .collect()
}

// =============================================================
// Invariant 1: A validator never double-votes within a slot.
// =============================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// For any sequence of slot numbers, after iteratively calling
    /// `create_vote`, `state.last_voted_slot` is non-decreasing and
    /// no vote is emitted for a slot ≤ the previous voted slot.
    #[test]
    fn no_double_vote(slots in prop::collection::vec(1u64..1000, 1..50)) {
        let (_, sk, pk) = &keys()[0];
        let addr = derive_eoa_address(pk);
        let mut state = ConsensusState::new();

        let mut last_voted = 0u64;
        for s in slots {
            let header = make_header(s, QuorumCert::empty(), 0);
            let vote = create_vote(&mut state, &header, 0, addr, sk).unwrap();
            if s > last_voted {
                prop_assert!(vote.is_some(), "should vote for new slot {}", s);
                prop_assert_eq!(state.last_voted_slot, s);
                last_voted = s;
            } else {
                prop_assert!(
                    vote.is_none(),
                    "must not double-vote for slot {} (last={})",
                    s,
                    last_voted
                );
                prop_assert_eq!(state.last_voted_slot, last_voted);
            }
        }
    }
}

// =============================================================
// Invariant 2: Byzantine equivocation cannot produce two QCs
// for distinct blocks at the same slot when |byzantine| ≤ ⌊N/3⌋.
// This is the central HotStuff safety property.
// =============================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// Setup: split the committee into honest (size H) and byzantine
    /// (size B) where B ≤ ⌊N/3⌋. Honest validators all vote for
    /// block_a. Byzantine validators equivocate — vote for both
    /// block_a AND a competing block_b. Block A trivially gets a QC
    /// (H+B = N votes); block B must NEVER reach quorum because only
    /// the byzantine subset votes for it (B ≤ ⌊N/3⌋ < ⌈2N/3⌉).
    #[test]
    fn no_two_qcs_with_honest_majority(
        // N=128, ⌊N/3⌋ = 42 byzantine validators max.
        byzantine_count in 0u8..=42,
    ) {
        let n = COMMITTEE_SIZE as u8;
        let h = n - byzantine_count;
        let honest: Vec<u8> = (0..h).collect();
        let byzantine: Vec<u8> = (h..n).collect();

        let block_a = [0xAA_u8; 32];
        let block_b = [0xBB_u8; 32];

        let mut votes_a = build_votes_for(7, block_a, &honest);
        votes_a.extend(build_votes_for(7, block_a, &byzantine));
        let votes_b = build_votes_for(7, block_b, &byzantine);

        let keys_v = committee_keys();
        let qc_a = try_form_qc(7, block_a, &votes_a, &keys_v);
        let qc_b = try_form_qc(7, block_b, &votes_b, &keys_v);

        prop_assert!(qc_a.is_some(), "block_a should reach quorum (H={} + B={})", h, byzantine_count);
        prop_assert!(
            qc_b.is_none(),
            "block_b reached quorum with only {} byzantine voters (threshold {})",
            byzantine_count,
            quorum_for_committee(COMMITTEE_SIZE),
        );
    }
}

// =============================================================
// Invariant 3: highest_qc.slot is monotonically non-decreasing.
// =============================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// As a validator processes proposals, its highest_qc.slot must
    /// never regress, even when proposals arrive carrying QCs with
    /// arbitrary (older or newer) slot numbers.
    #[test]
    fn highest_qc_monotonic(
        steps in prop::collection::vec((1u64..1000, 0u64..1000), 1..30),
    ) {
        let (_, sk, pk) = &keys()[0];
        let addr = derive_eoa_address(pk);
        let mut state = ConsensusState::new();

        let mut prev_highest = state.highest_qc.slot;
        for (slot, qc_slot) in steps {
            let qc = QuorumCert {
                slot: qc_slot,
                block_hash: [0xCC; 32],
                voter_bitmap: (1u128 << 86) - 1,
                signatures: vec![],
            };
            let header = make_header(slot, qc, slot as u8);
            let _ = create_vote(&mut state, &header, 0, addr, sk).unwrap();

            prop_assert!(
                state.highest_qc.slot >= prev_highest,
                "highest_qc.slot regressed: {} -> {}",
                prev_highest,
                state.highest_qc.slot
            );
            prev_highest = state.highest_qc.slot;
        }
    }
}

// =============================================================
// Invariant 4: try_form_qc returns Some iff voters >= threshold.
// =============================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// For any voter subset, try_form_qc returns Some iff the
    /// distinct valid voter count meets the BFT threshold.
    #[test]
    fn qc_threshold_exact(voter_count in 0usize..=COMMITTEE_SIZE) {
        let voters: Vec<u8> = (0..voter_count as u8).collect();
        let block_hash = [0xDD; 32];
        let votes = build_votes_for(11, block_hash, &voters);
        let keys_v = committee_keys();
        let threshold = quorum_for_committee(COMMITTEE_SIZE);
        let qc = try_form_qc(11, block_hash, &votes, &keys_v);
        if voter_count >= threshold {
            prop_assert!(
                qc.is_some(),
                "{} voters should form QC (threshold {})",
                voter_count,
                threshold
            );
        } else {
            prop_assert!(
                qc.is_none(),
                "{} voters must NOT form QC (threshold {})",
                voter_count,
                threshold
            );
        }
    }
}

// =============================================================
// Invariant 5: FinalityTracker.latest_checkpoint.slot is non-
// decreasing across out-of-order delivery. A late-arriving cert
// for an older slot must NOT regress the checkpoint.
// =============================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Feed hard-finality certs in arbitrary slot order. After every
    /// insertion, latest_checkpoint.slot must equal the maximum slot
    /// observed so far — i.e. an out-of-order cert can update the
    /// hash/state_root only if it is for a later slot.
    #[test]
    fn finality_checkpoint_monotonic(slots in prop::collection::vec(1u64..1000, 1..20)) {
        let mut tracker = FinalityTracker::new();
        let mut max_seen = 0u64;
        let mut prev = 0u64;
        for slot in slots {
            let cert = HardFinalityCert {
                slot,
                block_hash: [(slot & 0xff) as u8; 32],
                state_root: [0; 32],
                voter_bitmap: u128::MAX,
                signatures: vec![],
            };
            tracker.record_hard_finality(cert);
            max_seen = max_seen.max(slot);
            let cp_slot = tracker.latest_checkpoint.as_ref().map(|c| c.slot).unwrap_or(0);
            prop_assert!(
                cp_slot >= prev,
                "latest_checkpoint.slot regressed: {} -> {} (cert slot={})",
                prev,
                cp_slot,
                slot
            );
            prop_assert_eq!(
                cp_slot,
                max_seen,
                "latest_checkpoint should reflect max slot seen ({}), got {}",
                max_seen,
                cp_slot
            );
            prev = cp_slot;
        }
    }
}
