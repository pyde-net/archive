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
//! ## Epoch Randomness
//!
//! At each epoch boundary, committee members produce randomness shares
//! via threshold signatures (85-of-128). The combined output is unpredictable
//! to any coalition of <86 validators. Wired in:
//! - `validator.rs:start_epoch_randomness()` — generate + broadcast share
//! - `validator.rs:on_randomness_share()` — collect + combine at threshold
//! - `node.rs:769` — triggered at epoch boundary
//! - `node.rs:1406` — share collection via gossipsub

use pyde_account::address::Address;
use pyde_crypto::falcon::FalconPublicKey;
use pyde_crypto::falcon::FalconSecretKey;
use pyde_crypto::vrf::{vrf_prove, vrf_verify, VrfOutput, VrfProof};

/// Build the VRF input for a given slot: epoch_randomness || slot_bytes.
fn vrf_input(epoch_randomness: &[u8; 32], slot: u64) -> Vec<u8> {
    let mut input = Vec::with_capacity(40);
    input.extend_from_slice(epoch_randomness);
    input.extend_from_slice(&slot.to_le_bytes());
    input
}

/// Extract a u64 score from a VRF output (first 8 bytes, little-endian).
/// Public so receivers (block_processor::validate_network_block) can
/// recompute the score from a verified VRF output and check it
/// against `vrf_proposer_threshold` (audit 323).
pub fn score_from_output(output: &VrfOutput) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&output.as_bytes()[..8]);
    u64::from_le_bytes(buf)
}

/// Eligibility threshold for a proposer's VRF score given a
/// committee size. Historically this targeted ~5 expected proposers
/// per slot via `5 * u64::MAX / N`. Audit-410-extended (universal
/// round-robin, see `is_view0_proposer`) makes view-0 leader
/// selection a deterministic single-proposer rotation for ALL
/// committee sizes, so the VRF score-vs-threshold gate has nothing
/// to filter — the round-robin already picks exactly one leader per
/// slot. The threshold is now `u64::MAX` unconditionally; the VRF
/// proof itself is still computed and verified to bind the
/// proposer's randomness commitment to this slot (anti-grinding /
/// epoch-randomness liveness), but the score check is a no-op pass.
///
/// Kept as a function (rather than removed) because both sender
/// (`validator::check_proposer`) and receiver
/// (`block_processor::validate_network_block`) call it, and a future
/// design that re-introduces a probabilistic eligibility layer
/// (e.g. for an opt-in fast-path on very large committees) would
/// flow through here.
pub fn vrf_proposer_threshold(_committee_size: usize) -> u64 {
    u64::MAX
}

/// Audit 410 (and audit-410-extended): deterministic single-leader
/// gate for the view-0 happy path.
///
/// Returns whether the validator at `committee_index` is the sole
/// eligible proposer for `slot`. Universal round-robin:
///   `(slot % committee_size) == committee_index`
///
/// Pre-410, view-0 used VRF multi-leader selection: every committee
/// member with a low-enough VRF score (`≤ vrf_proposer_threshold(N)`)
/// could propose, targeting ~5 eligible proposers per slot. Under
/// sustained mixed load, gossip delivery of competing proposals
/// slipped past the 100 ms vote deadline, so different honest
/// validators voted on different "best of buffered" subsets,
/// scattering votes across competing block hashes and wedging
/// consensus. Audit-410 first introduced the round-robin gate for
/// committees ≤ 5 (where fan-out is too small for the
/// gossip-convergence race to settle in time). A subsequent
/// 6-validator soak proved the same race re-emerges above the
/// cutoff, so the gate is now universal: every committee size uses
/// the single deterministic leader per `(slot, view=0)`.
///
/// Tradeoff: an offline view-0 leader stalls one slot per N until
/// view-change kicks in (~200 ms baseline timeout, exponential
/// backoff per attempt). The original multi-leader design hid
/// single-validator outages behind redundancy; with universal
/// round-robin, view-change is the sole recovery mechanism — which
/// is what it was designed for. Vote-coherence under load wins over
/// latency-hiding under churn.
///
/// View-1+ fallbacks remain governed by `fallback_leader_index`
/// (slot + view rotation) — this gate only governs the view-0
/// happy path. Used in:
/// - `validator::check_proposer` to suppress non-leader proposals
/// - `block_processor::validate_network_block` to reject any
///   view-0 block whose proposer index is not the round-robin leader.
pub fn is_view0_proposer(slot: u64, committee_index: usize, committee_size: usize) -> bool {
    if committee_size == 0 {
        return false;
    }
    (slot % committee_size as u64) as usize == committee_index
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
        assert!(!verify_candidacy(
            &candidate,
            pk2.as_bytes(),
            &[0xAA; 32],
            100
        ));
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

    // ── vrf_proposer_threshold helper ─────────────────────────────────

    #[test]
    fn vrf_proposer_threshold_is_universally_permissive() {
        // Audit-410-extended: universal round-robin makes the score
        // gate a no-op. The threshold must be u64::MAX for every N
        // so the round-robin-chosen leader is never additionally
        // filtered by VRF score.
        for n in [1usize, 4, 5, 6, 7, 8, 32, 128, 256] {
            assert_eq!(
                vrf_proposer_threshold(n),
                u64::MAX,
                "threshold must be u64::MAX for n={n} (universal round-robin)"
            );
        }
    }

    #[test]
    fn is_view0_proposer_universal_round_robin() {
        // Audit-410-extended: for every committee size, exactly one
        // index is eligible per slot, and it cycles `slot % N`.
        for n in [1usize, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 128] {
            for slot in 0u64..(n as u64 * 3) {
                let expected = (slot % n as u64) as usize;
                for idx in 0..n {
                    assert_eq!(
                        is_view0_proposer(slot, idx, n),
                        idx == expected,
                        "n={n} slot={slot} idx={idx}"
                    );
                }
            }
        }
    }

    #[test]
    fn is_view0_proposer_zero_committee_safe() {
        // Defensive: a zero-size committee is never a valid state,
        // but the helper must not panic with `% 0`.
        assert!(!is_view0_proposer(0, 0, 0));
        assert!(!is_view0_proposer(99, 3, 0));
    }

    #[test]
    fn score_from_output_is_first_8_bytes_le() {
        // The score must be the little-endian decoding of the first
        // 8 bytes of the VRF output. Receivers (block_processor) and
        // the local check_proposer derive the same value from the
        // same VrfOutput.
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&0xCAFEBABE_u64.to_le_bytes());
        let output = VrfOutput::from_hash_bytes(&bytes).expect("32-byte input");
        assert_eq!(score_from_output(&output), 0xCAFEBABE);
    }
}
