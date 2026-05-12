//! VRF-driven committee selection primitives.
//!
//! The current `select_committee` in `pyde-consensus` shuffles
//! eligible validators by a hash of `(randomness, epoch, address)`,
//! which is deterministic but lets anyone who knows `randomness`
//! compute every validator's score — there is no unforgeable
//! binding between a score and the validator's secret key, and the
//! `randomness` seed itself becomes a single grinding target.
//!
//! This module replaces that with an Algorand-style VRF selection:
//! every eligible validator self-computes
//! `score = VRF(sk, COMMITTEE_VRF_DOMAIN || epoch || epoch_seed)`
//! using the existing Falcon + Poseidon2 VRF from
//! [`crate::vrf`]. Each reveal carries a Falcon-signed proof that
//! the score was honestly derived from the validator's secret key.
//! Top-k by score (lowest score wins, ties broken by index) =
//! committee.
//!
//! Properties:
//! - **Unforgeable.** Only the holder of `sk_i` can produce a valid
//!   `(output_i, proof_i)` for `pk_i`. An attacker can't pre-grind
//!   a winning score for a key they don't control.
//! - **Verifiable.** Anyone with the validator's `pk_i`, the epoch
//!   seed, and the published `(output_i, proof_i)` can re-check the
//!   reveal.
//! - **Equal voting.** Every eligible validator runs exactly one
//!   VRF per epoch and gets exactly one score; the score
//!   distribution is uniform over the VRF output space, so each
//!   validator has equal probability of winning a committee seat.
//!   Stake influences eligibility (validators below the minimum
//!   stake threshold don't reveal at all) but does NOT weight the
//!   score, matching Pyde's equal-voting design.
//! - **Deterministic.** Given the same set of valid reveals plus
//!   the same `(epoch, epoch_seed)`, every observer derives the
//!   same committee.

use alloc::vec::Vec;

use crate::falcon::{FalconPublicKey, FalconSecretKey};
use crate::vrf::{vrf_prove, vrf_verify, VrfOutput, VrfProof};

/// Domain separator for the VRF input used in committee selection.
/// Distinct from any other VRF use in the system (block proposer,
/// epoch randomness, etc.) so a reveal here can't be mistaken for
/// a reveal in another role.
pub const COMMITTEE_VRF_DOMAIN: &[u8] = b"PYDE_COMMITTEE_VRF_V1\0";

/// Build the VRF input for committee selection. Binds the score
/// to a specific `(epoch, epoch_seed)` so a reveal from one epoch
/// can't be replayed in another.
fn committee_vrf_input(epoch: u64, epoch_seed: &[u8; 32]) -> Vec<u8> {
    let mut input = Vec::with_capacity(COMMITTEE_VRF_DOMAIN.len() + 8 + 32);
    input.extend_from_slice(COMMITTEE_VRF_DOMAIN);
    input.extend_from_slice(&epoch.to_le_bytes());
    input.extend_from_slice(epoch_seed);
    input
}

/// Compute the validator's committee score for `epoch`. Only the
/// holder of `vrf_sk` can produce a `(VrfOutput, VrfProof)` that
/// verifies under `vrf_pk` — there is no way to forge a winning
/// reveal for someone else's key.
pub fn compute_committee_score(
    vrf_pk: &FalconPublicKey,
    vrf_sk: &FalconSecretKey,
    epoch: u64,
    epoch_seed: &[u8; 32],
) -> Result<(VrfOutput, VrfProof), &'static str> {
    let input = committee_vrf_input(epoch, epoch_seed);
    vrf_prove(vrf_pk, vrf_sk, &input)
}

/// Verify a validator's committee score against their public key
/// and the epoch seed. Returns `false` on any mismatch (malformed
/// proof, wrong key, tampered output, wrong epoch, wrong seed).
pub fn verify_committee_score(
    vrf_pk: &FalconPublicKey,
    epoch: u64,
    epoch_seed: &[u8; 32],
    output: &VrfOutput,
    proof: &VrfProof,
) -> bool {
    let input = committee_vrf_input(epoch, epoch_seed);
    vrf_verify(vrf_pk, &input, output, proof)
}

/// Convert a VRF output to a sortable `u64` score. The first 8
/// bytes of the 32-byte output interpreted little-endian — since
/// Poseidon2 produces uniformly distributed bytes, the resulting
/// `u64` is uniform on `[0, 2^64)`. Two independent VRFs collide
/// at the `u64` level with probability `~2^-64`, which is
/// negligible at any realistic committee size.
pub fn vrf_output_to_score(output: &VrfOutput) -> u64 {
    let bytes = output.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// One validator's VRF reveal for the epoch's committee.
#[derive(Clone, Debug)]
pub struct CommitteeReveal {
    /// 1-based committee position from the eligible-validator set.
    /// The selection's tiebreaker — when two reveals score equal,
    /// the lower index wins — uses this field, so it must match
    /// the canonical ordering observers use for the eligible set.
    pub validator_index: usize,
    /// The validator's Falcon (VRF) public key.
    pub vrf_pk: FalconPublicKey,
    pub output: VrfOutput,
    pub proof: VrfProof,
}

/// Verify every reveal and return the top-`k` validator indices
/// by VRF score (lowest scores win — matching the existing
/// `select_committee` ordering). Reveals that fail VRF
/// verification are silently dropped; this matches the
/// "non-respondents excluded from the committee" model and keeps
/// the function pure on the set of *valid* reveals.
///
/// Ties (same `u64` score) are broken by `validator_index`, lower
/// index wins, so the output is fully deterministic given the
/// input reveal set.
///
/// `k` is capped at the number of valid reveals — asking for more
/// than the eligible pool simply returns every valid reveal.
pub fn select_top_k_by_vrf(
    reveals: &[CommitteeReveal],
    epoch: u64,
    epoch_seed: &[u8; 32],
    k: usize,
) -> Vec<usize> {
    let mut scored: Vec<(u64, usize)> = reveals
        .iter()
        .filter(|r| verify_committee_score(&r.vrf_pk, epoch, epoch_seed, &r.output, &r.proof))
        .map(|r| (vrf_output_to_score(&r.output), r.validator_index))
        .collect();
    scored.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    scored.into_iter().take(k).map(|(_, i)| i).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::falcon::falcon_keygen;
    use alloc::vec;

    fn make_seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn compute_then_verify_roundtrip() {
        let (pk, sk) = falcon_keygen().expect("falcon");
        let seed = make_seed(7);
        let (output, proof) = compute_committee_score(&pk, &sk, 11, &seed).expect("score");
        assert!(verify_committee_score(&pk, 11, &seed, &output, &proof));
    }

    #[test]
    fn score_is_deterministic_in_inputs() {
        let (pk, sk) = falcon_keygen().expect("falcon");
        let seed = make_seed(3);
        let (out1, _) = compute_committee_score(&pk, &sk, 5, &seed).expect("s1");
        let (out2, _) = compute_committee_score(&pk, &sk, 5, &seed).expect("s2");
        assert_eq!(out1, out2);
    }

    #[test]
    fn different_epoch_gives_different_score() {
        let (pk, sk) = falcon_keygen().expect("falcon");
        let seed = make_seed(3);
        let (out_a, _) = compute_committee_score(&pk, &sk, 1, &seed).expect("a");
        let (out_b, _) = compute_committee_score(&pk, &sk, 2, &seed).expect("b");
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn different_seed_gives_different_score() {
        let (pk, sk) = falcon_keygen().expect("falcon");
        let (out_a, _) = compute_committee_score(&pk, &sk, 1, &make_seed(1)).expect("a");
        let (out_b, _) = compute_committee_score(&pk, &sk, 1, &make_seed(2)).expect("b");
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn verify_rejects_wrong_public_key() {
        let (pk_a, sk_a) = falcon_keygen().expect("a");
        let (pk_b, _sk_b) = falcon_keygen().expect("b");
        let seed = make_seed(5);
        let (output, proof) = compute_committee_score(&pk_a, &sk_a, 1, &seed).expect("score");
        assert!(!verify_committee_score(&pk_b, 1, &seed, &output, &proof));
    }

    #[test]
    fn verify_rejects_tampered_output() {
        let (pk, sk) = falcon_keygen().expect("falcon");
        let seed = make_seed(4);
        let (output, proof) = compute_committee_score(&pk, &sk, 1, &seed).expect("score");
        // Flip a bit in the output hash.
        let mut bytes = *output.as_bytes();
        bytes[0] ^= 0x01;
        let tampered = VrfOutput::from_hash_bytes(&bytes).expect("ctor");
        assert!(!verify_committee_score(&pk, 1, &seed, &tampered, &proof));
    }

    #[test]
    fn verify_rejects_wrong_epoch_or_seed() {
        let (pk, sk) = falcon_keygen().expect("falcon");
        let seed = make_seed(6);
        let (output, proof) = compute_committee_score(&pk, &sk, 10, &seed).expect("score");
        assert!(!verify_committee_score(&pk, 11, &seed, &output, &proof));
        assert!(!verify_committee_score(&pk, 10, &make_seed(99), &output, &proof));
    }

    #[test]
    fn vrf_output_to_score_is_deterministic() {
        let (pk, sk) = falcon_keygen().expect("falcon");
        let seed = make_seed(8);
        let (output, _) = compute_committee_score(&pk, &sk, 1, &seed).expect("score");
        assert_eq!(
            vrf_output_to_score(&output),
            vrf_output_to_score(&output)
        );
    }

    fn fresh_reveal(index: usize, epoch: u64, seed: &[u8; 32]) -> CommitteeReveal {
        let (pk, sk) = falcon_keygen().expect("falcon");
        let (output, proof) = compute_committee_score(&pk, &sk, epoch, seed).expect("score");
        CommitteeReveal {
            validator_index: index,
            vrf_pk: pk,
            output,
            proof,
        }
    }

    #[test]
    fn select_top_k_picks_lowest_scores() {
        let seed = make_seed(11);
        let epoch = 3;
        let reveals: Vec<CommitteeReveal> =
            (1..=20).map(|i| fresh_reveal(i, epoch, &seed)).collect();
        let committee = select_top_k_by_vrf(&reveals, epoch, &seed, 5);
        assert_eq!(committee.len(), 5);

        // Independently sort: take the 5 lowest-scoring indices.
        let mut scored: Vec<(u64, usize)> = reveals
            .iter()
            .map(|r| (vrf_output_to_score(&r.output), r.validator_index))
            .collect();
        scored.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        let expected: Vec<usize> = scored.iter().take(5).map(|(_, i)| *i).collect();
        assert_eq!(committee, expected);
    }

    #[test]
    fn select_top_k_dedups_via_tie_break_on_index() {
        // Two reveals manufactured to share a score: same output
        // value is permitted, but the validator_index breaks the
        // tie. Build two distinct keys and copy one's output/proof
        // onto a CommitteeReveal struct under a different index —
        // this fails verification (proof is bound to the original
        // key), so the duplicate is dropped by select_top_k. The
        // verified entry's index wins.
        let seed = make_seed(13);
        let epoch = 4;
        let a = fresh_reveal(7, epoch, &seed);
        let stolen = CommitteeReveal {
            validator_index: 3,
            vrf_pk: fresh_reveal(99, epoch, &seed).vrf_pk, // a different pk
            output: a.output.clone(),                       // copy a's output
            proof: a.proof.clone(),                         // copy a's proof
        };
        let committee = select_top_k_by_vrf(&[a, stolen], epoch, &seed, 5);
        // The "stolen" reveal can't verify under the swapped pk, so
        // only `a` (validator_index = 7) survives.
        assert_eq!(committee, vec![7]);
    }

    #[test]
    fn select_top_k_drops_invalid_reveals() {
        let seed = make_seed(17);
        let epoch = 5;
        let good_a = fresh_reveal(1, epoch, &seed);
        let good_b = fresh_reveal(2, epoch, &seed);
        let mut tampered = fresh_reveal(3, epoch, &seed);
        // Sabotage the proof so verification fails.
        tampered.proof = VrfProof::from_bytes(&[0u8; 666]);

        let committee = select_top_k_by_vrf(
            &[good_a.clone(), good_b.clone(), tampered],
            epoch,
            &seed,
            10,
        );
        assert_eq!(committee.len(), 2);
        // Both surviving indices appear, in score order.
        let mut expected_indices = [good_a.validator_index, good_b.validator_index];
        let mut expected_scores = [
            vrf_output_to_score(&good_a.output),
            vrf_output_to_score(&good_b.output),
        ];
        if expected_scores[0] > expected_scores[1] {
            expected_indices.swap(0, 1);
            expected_scores.swap(0, 1);
        }
        assert_eq!(committee, expected_indices.to_vec());
    }

    #[test]
    fn select_top_k_handles_k_greater_than_pool() {
        let seed = make_seed(21);
        let epoch = 6;
        let reveals: Vec<CommitteeReveal> =
            (1..=4).map(|i| fresh_reveal(i, epoch, &seed)).collect();
        let committee = select_top_k_by_vrf(&reveals, epoch, &seed, 100);
        assert_eq!(committee.len(), 4);
    }

    #[test]
    fn select_top_k_zero_returns_empty() {
        let seed = make_seed(23);
        let epoch = 7;
        let reveals: Vec<CommitteeReveal> =
            (1..=4).map(|i| fresh_reveal(i, epoch, &seed)).collect();
        assert!(select_top_k_by_vrf(&reveals, epoch, &seed, 0).is_empty());
    }

    #[test]
    fn select_top_k_at_committee_scale() {
        // 200 candidates → 128-member committee. Verifies that the
        // function is sane at the production target.
        let seed = make_seed(31);
        let epoch = 50;
        let reveals: Vec<CommitteeReveal> =
            (1..=200).map(|i| fresh_reveal(i, epoch, &seed)).collect();
        let committee = select_top_k_by_vrf(&reveals, epoch, &seed, 128);
        assert_eq!(committee.len(), 128);
        // Sanity: all indices unique.
        let mut sorted = committee.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 128);
    }

    #[test]
    fn epoch_seed_rerolls_committee() {
        // A different epoch_seed should produce a substantially
        // different committee — i.e. the selection isn't dominated
        // by validator index.
        let epoch = 9;
        let seed_a = make_seed(41);
        let seed_b = make_seed(43);
        let reveals_a: Vec<CommitteeReveal> =
            (1..=50).map(|i| fresh_reveal(i, epoch, &seed_a)).collect();
        let reveals_b: Vec<CommitteeReveal> = reveals_a
            .iter()
            .map(|r| {
                // Build a fresh reveal for the same validator (we
                // need their secret key, which `fresh_reveal`
                // discarded — so just make a new key per slot for
                // seed_b. The point of the test is that DIFFERENT
                // randomness picks DIFFERENT committees, not that
                // the same identities re-roll.)
                fresh_reveal(r.validator_index, epoch, &seed_b)
            })
            .collect();
        let comm_a = select_top_k_by_vrf(&reveals_a, epoch, &seed_a, 10);
        let comm_b = select_top_k_by_vrf(&reveals_b, epoch, &seed_b, 10);
        assert_ne!(comm_a, comm_b);
    }
}
