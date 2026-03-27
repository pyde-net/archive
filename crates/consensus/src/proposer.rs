//! VRF-based proposer selection per Chapter 6, Section 6.4.
//!
//! Each slot has exactly one proposer. Every committee member computes:
//!   (output, proof) = VRF(secret_key, epoch_randomness || slot)
//!   score = output mod 2^64
//!
//! The validator with the lowest score is the proposer.
//! The proposer reveals their VRF proof in the block header.
//! Other validators verify the proof and check it's the lowest score.
//!
//! ## Epoch Randomness (TODO: Phase 7)
//!
//! `epoch_randomness` is currently passed in by the caller. In production,
//! it must be generated via **threshold randomness** to prevent the last
//! block proposer from biasing the next epoch's committee selection.
//!
//! The planned approach: at each epoch boundary, committee members produce
//! randomness shares via threshold signatures (85-of-128). The combined
//! output is unpredictable to any coalition of <86 validators. This reuses
//! the existing threshold Kyber infrastructure from the crypto crate.
//!
//! Implementation requires the networking layer (Phase 7) for validators
//! to exchange randomness shares over P2P.

use crate::validator::Committee;
use pyde_account::address::Address;
use pyde_crypto::falcon::FalconPublicKey;
use pyde_crypto::vrf::{vrf_prove, vrf_verify, VrfOutput, VrfProof};
use pyde_crypto::falcon::FalconSecretKey;

/// Build the VRF input for a given slot: epoch_randomness || slot_bytes.
fn vrf_input(epoch_randomness: &[u8; 32], slot: u64) -> Vec<u8> {
    let mut input = Vec::with_capacity(40);
    input.extend_from_slice(epoch_randomness);
    input.extend_from_slice(&slot.to_le_bytes());
    input
}

/// Extract a u64 score from a VRF output (first 8 bytes, little-endian).
fn score_from_output(output: &VrfOutput) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&output.as_bytes()[..8]);
    u64::from_le_bytes(buf)
}

/// A proposer candidate: validator address + VRF output + proof.
#[derive(Clone, Debug)]
pub struct ProposerCandidate {
    /// Validator address.
    pub address: Address,
    /// VRF output (32 bytes).
    pub vrf_output: VrfOutput,
    /// VRF proof (FALCON signature).
    pub vrf_proof: VrfProof,
    /// Score derived from VRF output (lower = wins).
    pub score: u64,
}

/// Compute a validator's proposer candidacy for a given slot.
///
/// Each validator calls this locally with their keypair.
/// Returns their candidate (output, proof, score).
pub fn compute_candidacy(
    public_key: &FalconPublicKey,
    secret_key: &FalconSecretKey,
    epoch_randomness: &[u8; 32],
    slot: u64,
    address: Address,
) -> Result<ProposerCandidate, &'static str> {
    let input = vrf_input(epoch_randomness, slot);
    let (output, proof) = vrf_prove(public_key, secret_key, &input)
        .map_err(|_| "VRF prove failed — invalid keypair")?;
    let score = score_from_output(&output);

    Ok(ProposerCandidate {
        address,
        vrf_output: output,
        vrf_proof: proof,
        score,
    })
}

/// Verify a proposer candidate's VRF proof.
///
/// Other validators call this to check:
/// 1. The VRF proof is valid for the public key and input
/// 2. The score matches the VRF output
pub fn verify_candidacy(
    candidate: &ProposerCandidate,
    public_key: &[u8],
    epoch_randomness: &[u8; 32],
    slot: u64,
) -> bool {
    let pk = match FalconPublicKey::from_bytes(public_key) {
        Some(pk) => pk,
        None => return false,
    };

    let input = vrf_input(epoch_randomness, slot);

    // Verify VRF proof
    if !vrf_verify(&pk, &input, &candidate.vrf_output, &candidate.vrf_proof) {
        return false;
    }

    // Verify score matches output
    let expected_score = score_from_output(&candidate.vrf_output);
    candidate.score == expected_score
}

/// Determine the proposer from a list of candidates.
/// The candidate with the lowest score wins.
pub fn select_proposer(candidates: &[ProposerCandidate]) -> Option<&ProposerCandidate> {
    candidates.iter().min_by_key(|c| c.score)
}

/// Verify that a claimed proposer actually has the lowest score in the committee.
///
/// In practice, each validator computes their own score and checks if the
/// claimed proposer's score is lower. This function simulates that by
/// checking a candidate against a set of other known scores.
pub fn is_lowest_score(candidate: &ProposerCandidate, other_scores: &[u64]) -> bool {
    other_scores.iter().all(|&s| candidate.score <= s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::falcon::falcon_keygen;

    fn make_candidate(slot: u64, randomness: &[u8; 32]) -> (ProposerCandidate, Vec<u8>) {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let addr = derive_eoa_address(&pk_bytes);
        let candidate = compute_candidacy(&pk, &sk, randomness, slot, addr).unwrap();
        (candidate, pk_bytes)
    }

    // ========== Task 0473: Deterministic for same key + slot ==========

    #[test]
    fn proposer_selection_deterministic() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let addr = derive_eoa_address(&pk_bytes);
        let randomness = [0xAA; 32];

        let c1 = compute_candidacy(&pk, &sk, &randomness, 100, addr).unwrap();
        let c2 = compute_candidacy(&pk, &sk, &randomness, 100, addr).unwrap();

        assert_eq!(c1.score, c2.score);
        assert_eq!(c1.vrf_output.as_bytes(), c2.vrf_output.as_bytes());
    }

    // ========== Task 0474: Different slots → different proposers ==========

    #[test]
    fn different_slots_different_scores() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let addr = derive_eoa_address(&pk_bytes);
        let randomness = [0xAA; 32];

        let c1 = compute_candidacy(&pk, &sk, &randomness, 100, addr).unwrap();
        let c2 = compute_candidacy(&pk, &sk, &randomness, 101, addr).unwrap();

        // Scores should differ (with overwhelming probability)
        assert_ne!(c1.score, c2.score);
    }

    #[test]
    fn different_randomness_different_scores() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let addr = derive_eoa_address(&pk_bytes);

        let c1 = compute_candidacy(&pk, &sk, &[0xAA; 32], 100, addr).unwrap();
        let c2 = compute_candidacy(&pk, &sk, &[0xBB; 32], 100, addr).unwrap();

        assert_ne!(c1.score, c2.score);
    }

    // ========== Task 0475: Invalid VRF proof rejected ==========

    #[test]
    fn valid_proof_accepted() {
        let (candidate, pk_bytes) = make_candidate(100, &[0xAA; 32]);
        assert!(verify_candidacy(&candidate, &pk_bytes, &[0xAA; 32], 100));
    }

    #[test]
    fn wrong_slot_rejected() {
        let (candidate, pk_bytes) = make_candidate(100, &[0xAA; 32]);
        // Verify with wrong slot
        assert!(!verify_candidacy(&candidate, &pk_bytes, &[0xAA; 32], 101));
    }

    #[test]
    fn wrong_key_rejected() {
        let (candidate, _pk_bytes) = make_candidate(100, &[0xAA; 32]);
        let (pk2, _sk2) = falcon_keygen().unwrap();
        // Verify with wrong public key
        assert!(!verify_candidacy(&candidate, pk2.as_bytes(), &[0xAA; 32], 100));
    }

    #[test]
    fn wrong_randomness_rejected() {
        let (candidate, pk_bytes) = make_candidate(100, &[0xAA; 32]);
        assert!(!verify_candidacy(&candidate, &pk_bytes, &[0xBB; 32], 100));
    }

    #[test]
    fn tampered_score_rejected() {
        let (mut candidate, pk_bytes) = make_candidate(100, &[0xAA; 32]);
        candidate.score = 0; // tamper
        assert!(!verify_candidacy(&candidate, &pk_bytes, &[0xAA; 32], 100));
    }

    // ========== Proposer selection ==========

    #[test]
    fn lowest_score_wins() {
        let randomness = [0xAA; 32];
        let mut candidates = Vec::new();

        for i in 0..10 {
            let (c, _) = make_candidate(100 + i, &randomness);
            // Use different slots to get different scores from same randomness
            candidates.push(c);
        }

        let proposer = select_proposer(&candidates).unwrap();
        let min_score = candidates.iter().map(|c| c.score).min().unwrap();
        assert_eq!(proposer.score, min_score);
    }

    #[test]
    fn is_lowest_score_check() {
        let (candidate, _) = make_candidate(100, &[0xAA; 32]);
        let higher_scores = vec![candidate.score + 1, candidate.score + 100, u64::MAX];
        assert!(is_lowest_score(&candidate, &higher_scores));

        let lower_scores = vec![candidate.score.saturating_sub(1)];
        if candidate.score > 0 {
            assert!(!is_lowest_score(&candidate, &lower_scores));
        }
    }

    #[test]
    fn empty_candidates_returns_none() {
        assert!(select_proposer(&[]).is_none());
    }
}
