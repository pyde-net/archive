//! Threshold epoch randomness: unpredictable, unbiasable randomness for
//! proposer selection via 85-of-128 threshold VRF shares.
//!
//! Protocol:
//! 1. At epoch boundary, each committee member produces a randomness share:
//!    (share, proof) = VRF(sk, "epoch_randomness" || epoch_number)
//! 2. Shares are broadcast via the consensus P2P channel.
//! 3. Once 85+ valid shares are collected, they are combined:
//!    epoch_randomness = Poseidon2(sorted_shares[0] || sorted_shares[1] || ... || sorted_shares[N])
//! 4. The combined output is unpredictable to any coalition of <85 validators.
//!
//! Security properties:
//! - **Unpredictability**: No coalition of <85 validators can predict the output
//!   (each share requires the validator's secret key via VRF).
//! - **Unbiasability**: The last validator to submit cannot bias the output
//!   because shares are sorted before combining (order-independent).
//! - **Availability**: Only 85 of 128 needed — tolerates 43 offline validators.

use pyde_account::address::Address;
use pyde_crypto::falcon::{FalconPublicKey, FalconSecretKey};
use pyde_crypto::hash::Hash256;
use pyde_crypto::poseidon2::poseidon2_many;
use pyde_crypto::vrf::{vrf_prove, vrf_verify, VrfOutput, VrfProof};

use crate::block::COMMITTEE_SIZE;

/// Domain separator for epoch randomness VRF input.
const DOMAIN: &[u8] = b"pyde-epoch-randomness-v1";

/// Minimum shares required for production (2/3 + 1 of 128).
pub const RANDOMNESS_THRESHOLD: usize = 85;

/// Compute dynamic randomness threshold for a given committee size.
/// Uses ceil(2/3 * size), same as consensus quorum.
pub fn randomness_threshold_for(committee_size: usize) -> usize {
    crate::block::quorum_for_committee(committee_size)
}

/// A randomness share from one committee member.
#[derive(Clone, Debug)]
pub struct RandomnessShare {
    /// Validator index in the committee (0-based).
    pub validator_index: u8,
    /// Validator address.
    pub address: Address,
    /// VRF output (the share value).
    pub vrf_output: VrfOutput,
    /// VRF proof (FALCON signature, verifiable by anyone).
    pub vrf_proof: VrfProof,
}

/// Combined epoch randomness output.
#[derive(Clone, Debug)]
pub struct EpochRandomness {
    /// The epoch this randomness is for.
    pub epoch: u64,
    /// The combined 32-byte randomness value.
    pub randomness: [u8; 32],
    /// Number of shares that were combined.
    pub share_count: usize,
}

/// Build the VRF input for epoch randomness: domain || epoch_bytes.
fn randomness_vrf_input(epoch: u64) -> Vec<u8> {
    let mut input = Vec::with_capacity(DOMAIN.len() + 8);
    input.extend_from_slice(DOMAIN);
    input.extend_from_slice(&epoch.to_le_bytes());
    input
}

/// Generate a randomness share for the given epoch.
///
/// Each committee member calls this with their keypair at the epoch boundary.
pub fn generate_share(
    public_key: &FalconPublicKey,
    secret_key: &FalconSecretKey,
    epoch: u64,
    validator_index: u8,
    address: Address,
) -> Result<RandomnessShare, &'static str> {
    let input = randomness_vrf_input(epoch);
    let (output, proof) = vrf_prove(public_key, secret_key, &input)?;

    Ok(RandomnessShare {
        validator_index,
        address,
        vrf_output: output,
        vrf_proof: proof,
    })
}

/// Verify a randomness share from another validator.
///
/// Returns true if the share is a valid VRF output for the given epoch.
pub fn verify_share(share: &RandomnessShare, public_key: &FalconPublicKey, epoch: u64) -> bool {
    let input = randomness_vrf_input(epoch);
    vrf_verify(public_key, &input, &share.vrf_output, &share.vrf_proof)
}

/// Combine 85+ verified shares into a single epoch randomness value.
///
/// Shares are sorted by their output bytes before combining to ensure
/// the result is order-independent (prevents last-revealer bias).
///
/// Returns None if fewer than RANDOMNESS_THRESHOLD shares provided.
/// Combine shares with dynamic threshold based on committee size.
pub fn combine_shares_dynamic(
    shares: &[RandomnessShare],
    epoch: u64,
    committee_size: usize,
) -> Option<EpochRandomness> {
    let threshold = randomness_threshold_for(committee_size);
    combine_shares_with_threshold(shares, epoch, threshold)
}

pub fn combine_shares(shares: &[RandomnessShare], epoch: u64) -> Option<EpochRandomness> {
    combine_shares_with_threshold(shares, epoch, RANDOMNESS_THRESHOLD)
}

fn combine_shares_with_threshold(
    shares: &[RandomnessShare],
    epoch: u64,
    threshold: usize,
) -> Option<EpochRandomness> {
    if shares.len() < threshold {
        return None;
    }

    // Audit 403: take the canonical subset — the `threshold` shares
    // with the LOWEST `validator_index` values. Pre-fix, every share
    // was combined regardless of count, so two validators with
    // different gossip-arrival sets (e.g. {0,1,2} vs {0,1,3})
    // produced different randomness for the same epoch — split-brain.
    // Sorting by validator_index and truncating to threshold gives
    // every node the SAME canonical set, provided each one has
    // received the canonical members' shares. The
    // `try_finalize_randomness_on_slot` deadline gate at the
    // validator layer ensures gossip has converged before this
    // function runs, so the canonical members' shares are present
    // on every honest node.
    let mut by_index: std::collections::BTreeMap<u8, &RandomnessShare> =
        std::collections::BTreeMap::new();
    for share in shares {
        by_index.entry(share.validator_index).or_insert(share);
    }
    if by_index.len() < threshold {
        return None;
    }

    // Lowest `threshold` indices, in index order.
    let canonical: Vec<&RandomnessShare> = by_index.values().take(threshold).copied().collect();

    // Sort by VRF output bytes for last-revealer protection within
    // the canonical subset (the input set is already deterministic;
    // this just removes any in-set ordering signal).
    let mut sorted_outputs: Vec<Hash256> =
        canonical.iter().map(|s| s.vrf_output.to_hash()).collect();
    sorted_outputs.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    let combined = poseidon2_many(&sorted_outputs);

    Some(EpochRandomness {
        epoch,
        randomness: combined.to_bytes(),
        share_count: canonical.len(),
    })
}

/// Collector for gathering shares during an epoch transition.
#[derive(Clone, Debug)]
pub struct RandomnessCollector {
    /// Target epoch.
    pub epoch: u64,
    /// Active committee size — drives the dynamic randomness
    /// threshold (audit 322). Must equal the active committee size
    /// for `epoch`. Pre-322 the threshold was hardcoded to
    /// `RANDOMNESS_THRESHOLD = 85`, which made epoch randomness
    /// impossible to advance on any committee smaller than 85
    /// (every devnet + testnet pre-launch).
    committee_size: usize,
    /// Collected shares (validated).
    shares: Vec<RandomnessShare>,
    /// Track which validators have submitted (by index).
    seen: std::collections::HashSet<u8>,
}

impl RandomnessCollector {
    /// Build a collector for `epoch` with the active committee size.
    /// Audit 322: `is_complete` / `finalize` use
    /// `randomness_threshold_for(committee_size)` so a 4-validator
    /// devnet completes at 3-of-4, mirroring how
    /// `try_form_qc` / `try_form_hard_finality` use the dynamic
    /// quorum after audits 234/235.
    pub fn new(epoch: u64, committee_size: usize) -> Self {
        Self {
            epoch,
            committee_size,
            shares: Vec::with_capacity(committee_size.max(COMMITTEE_SIZE)),
            seen: std::collections::HashSet::new(),
        }
    }

    /// Add a verified share. Returns false if duplicate or wrong epoch.
    pub fn add_share(&mut self, share: RandomnessShare) -> bool {
        if self.seen.contains(&share.validator_index) {
            return false; // duplicate
        }
        self.seen.insert(share.validator_index);
        self.shares.push(share);
        true
    }

    /// Whether enough shares have been collected (uses the
    /// committee-size-derived threshold from audit 322).
    pub fn is_complete(&self) -> bool {
        self.shares.len() >= randomness_threshold_for(self.committee_size)
    }

    /// Number of shares collected so far.
    pub fn share_count(&self) -> usize {
        self.shares.len()
    }

    /// Whether we've collected a share from EVERY committee member.
    /// When true, `finalize` is guaranteed deterministic across nodes
    /// because the canonical-subset rule (lowest `threshold` indices)
    /// resolves to the same set on every node.
    pub fn has_full_set(&self) -> bool {
        self.shares.len() >= self.committee_size
    }

    /// Active committee size for this collector. Drives the dynamic
    /// threshold and the canonical-subset rule.
    pub fn committee_size(&self) -> usize {
        self.committee_size
    }

    /// Finalize: combine shares into epoch randomness using the
    /// dynamic threshold. Returns None if not enough shares.
    pub fn finalize(&self) -> Option<EpochRandomness> {
        combine_shares_dynamic(&self.shares, self.epoch, self.committee_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_crypto::falcon::falcon_keygen;

    fn make_committee(n: usize) -> Vec<(FalconPublicKey, FalconSecretKey, Address)> {
        (0..n)
            .map(|i| {
                let (pk, sk) = falcon_keygen().unwrap();
                let mut addr = [0u8; 32];
                addr[0] = i as u8;
                (pk, sk, addr)
            })
            .collect()
    }

    // ========== Task 1200: Threshold epoch randomness protocol ==========

    #[test]
    fn generate_and_verify_share() {
        let (pk, sk, addr) = &make_committee(1)[0];
        let share = generate_share(pk, sk, 42, 0, *addr).unwrap();
        assert!(verify_share(&share, pk, 42));
    }

    #[test]
    fn share_invalid_for_wrong_epoch() {
        let (pk, sk, addr) = &make_committee(1)[0];
        let share = generate_share(pk, sk, 42, 0, *addr).unwrap();
        assert!(!verify_share(&share, pk, 43)); // wrong epoch
    }

    #[test]
    fn share_invalid_for_wrong_key() {
        let committee = make_committee(2);
        let (pk0, sk0, addr0) = &committee[0];
        let (pk1, _, _) = &committee[1];
        let share = generate_share(pk0, sk0, 42, 0, *addr0).unwrap();
        assert!(!verify_share(&share, pk1, 42)); // wrong key
    }

    // ========== Task 1201: 85-of-128 threshold combine ==========

    #[test]
    fn combine_with_exact_threshold() {
        let committee = make_committee(RANDOMNESS_THRESHOLD);
        let epoch = 1;

        let shares: Vec<RandomnessShare> = committee
            .iter()
            .enumerate()
            .map(|(i, (pk, sk, addr))| generate_share(pk, sk, epoch, i as u8, *addr).unwrap())
            .collect();

        let result = combine_shares(&shares, epoch);
        assert!(result.is_some());
        let randomness = result.unwrap();
        assert_eq!(randomness.epoch, epoch);
        assert_eq!(randomness.share_count, RANDOMNESS_THRESHOLD);
        assert_ne!(randomness.randomness, [0u8; 32]);
    }

    #[test]
    fn combine_below_threshold_fails() {
        let committee = make_committee(RANDOMNESS_THRESHOLD - 1);
        let epoch = 1;

        let shares: Vec<RandomnessShare> = committee
            .iter()
            .enumerate()
            .map(|(i, (pk, sk, addr))| generate_share(pk, sk, epoch, i as u8, *addr).unwrap())
            .collect();

        assert!(combine_shares(&shares, epoch).is_none());
    }

    #[test]
    fn combine_is_deterministic() {
        let committee = make_committee(RANDOMNESS_THRESHOLD);
        let epoch = 5;

        let shares: Vec<RandomnessShare> = committee
            .iter()
            .enumerate()
            .map(|(i, (pk, sk, addr))| generate_share(pk, sk, epoch, i as u8, *addr).unwrap())
            .collect();

        let r1 = combine_shares(&shares, epoch).unwrap();
        let r2 = combine_shares(&shares, epoch).unwrap();
        assert_eq!(r1.randomness, r2.randomness);
    }

    #[test]
    fn combine_rejects_duplicates() {
        let committee = make_committee(RANDOMNESS_THRESHOLD - 1);
        let epoch = 1;

        let mut shares: Vec<RandomnessShare> = committee
            .iter()
            .enumerate()
            .map(|(i, (pk, sk, addr))| generate_share(pk, sk, epoch, i as u8, *addr).unwrap())
            .collect();

        // Duplicate the last share — shouldn't count as an extra
        shares.push(shares.last().unwrap().clone());
        assert!(combine_shares(&shares, epoch).is_none());
    }

    // ========== Task 1202: Unpredictable to <86 validators ==========

    #[test]
    fn different_subsets_produce_different_randomness() {
        // With 86 validators, two different 85-member subsets should produce
        // different randomness (because each subset has a different share).
        let committee = make_committee(86);
        let epoch = 10;

        let all_shares: Vec<RandomnessShare> = committee
            .iter()
            .enumerate()
            .map(|(i, (pk, sk, addr))| generate_share(pk, sk, epoch, i as u8, *addr).unwrap())
            .collect();

        // Subset A: first 85
        let r_a = combine_shares(&all_shares[..85], epoch).unwrap();
        // Subset B: last 85
        let r_b = combine_shares(&all_shares[1..86], epoch).unwrap();

        assert_ne!(
            r_a.randomness, r_b.randomness,
            "different subsets should produce different randomness"
        );
    }

    // ========== Task 1203: Withholding doesn't bias randomness ==========

    #[test]
    fn order_independent_combining() {
        // Shares are sorted before combining, so the order of submission
        // doesn't affect the result. A validator withholding and then
        // submitting late gets the same result.
        let committee = make_committee(RANDOMNESS_THRESHOLD);
        let epoch = 20;

        let shares: Vec<RandomnessShare> = committee
            .iter()
            .enumerate()
            .map(|(i, (pk, sk, addr))| generate_share(pk, sk, epoch, i as u8, *addr).unwrap())
            .collect();

        // Forward order
        let r_forward = combine_shares(&shares, epoch).unwrap();

        // Reverse order
        let mut reversed = shares.clone();
        reversed.reverse();
        let r_reverse = combine_shares(&reversed, epoch).unwrap();

        assert_eq!(
            r_forward.randomness, r_reverse.randomness,
            "combining order should not affect result"
        );
    }

    #[test]
    fn collector_workflow() {
        // Audit 322: collector now uses
        // `randomness_threshold_for(committee_size)` instead of
        // the hardcoded `RANDOMNESS_THRESHOLD`. For
        // committee_size=128 the threshold is
        // `ceil(2*128/3) = 86` (the legacy `RANDOMNESS_THRESHOLD =
        // 85` constant was off-by-one vs `quorum_for_committee`).
        let threshold = randomness_threshold_for(COMMITTEE_SIZE);
        let committee = make_committee(threshold);
        let epoch = 30;

        let mut collector = RandomnessCollector::new(epoch, COMMITTEE_SIZE);
        assert!(!collector.is_complete());

        for (i, (pk, sk, addr)) in committee.iter().enumerate() {
            let share = generate_share(pk, sk, epoch, i as u8, *addr).unwrap();
            assert!(collector.add_share(share));
        }

        assert!(collector.is_complete());
        assert_eq!(collector.share_count(), threshold);

        let randomness = collector.finalize().unwrap();
        assert_eq!(randomness.epoch, epoch);
        assert_ne!(randomness.randomness, [0u8; 32]);
    }

    #[test]
    fn collector_rejects_duplicate_share() {
        let (pk, sk, addr) = &make_committee(1)[0];
        let epoch = 1;

        let mut collector = RandomnessCollector::new(epoch, COMMITTEE_SIZE);
        let share = generate_share(pk, sk, epoch, 0, *addr).unwrap();
        assert!(collector.add_share(share.clone()));
        assert!(!collector.add_share(share)); // duplicate rejected
        assert_eq!(collector.share_count(), 1);
    }

    /// Audit 322: a 4-validator testnet committee must be able to
    /// finalize epoch randomness at 3-of-4 (the dynamic quorum).
    /// Pre-fix, RandomnessCollector used the hardcoded
    /// `RANDOMNESS_THRESHOLD = 85`, so the 16-validator testnet
    /// (and every smaller dev / staging committee) silently
    /// stalled at the first epoch boundary forever.
    #[test]
    fn collector_completes_on_small_committee_audit_322() {
        let committee = make_committee(4);
        let epoch = 100;
        let mut collector = RandomnessCollector::new(epoch, 4);
        assert!(!collector.is_complete());

        // 3-of-4 is the BFT quorum (= randomness_threshold_for(4)).
        for (i, (pk, sk, addr)) in committee.iter().take(3).enumerate() {
            let share = generate_share(pk, sk, epoch, i as u8, *addr).unwrap();
            assert!(collector.add_share(share));
        }
        assert!(
            collector.is_complete(),
            "4-validator committee must complete at 3 shares (audit 322)"
        );
        let randomness = collector
            .finalize()
            .expect("finalize must produce randomness on a 4-validator committee (audit 322)");
        assert_eq!(randomness.epoch, epoch);
        assert_eq!(randomness.share_count, 3);
        assert_ne!(randomness.randomness, [0u8; 32]);
    }

    #[test]
    fn collector_below_dynamic_threshold_stays_incomplete() {
        let committee = make_committee(7);
        let epoch = 200;
        let mut collector = RandomnessCollector::new(epoch, 7);
        // randomness_threshold_for(7) = ceil(2/3 * 7) = 5.
        // Submit only 4 shares — collector stays incomplete.
        for (i, (pk, sk, addr)) in committee.iter().take(4).enumerate() {
            let share = generate_share(pk, sk, epoch, i as u8, *addr).unwrap();
            collector.add_share(share);
        }
        assert!(!collector.is_complete());
        assert!(collector.finalize().is_none());
    }
}
