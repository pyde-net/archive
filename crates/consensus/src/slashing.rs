//! Slashing conditions per Chapter 6, Section 6.10.
//!
//! | Offense               | Slash Amount        | Description                               |
//! |-----------------------|---------------------|-------------------------------------------|
//! | Double signing        | 100% (10,000 PYDE)  | Two different blocks for same slot         |
//! | Equivocation          | 100% (10,000 PYDE)  | Conflicting votes in same round            |
//! | Liveness < 90%        | 1% of stake         | Missed > 10% of slots in epoch             |
//! | Liveness < 50%        | 5% of stake + eject | Missed > 50% of slots in epoch             |
//! | Liveness == 0%        | 10% + forced unbond  | Completely absent for entire epoch          |
//! | Invalid block proposal| 50% (5,000 PYDE)    | Proposing block with invalid structure     |
//! | Decryption withholding| 2% per offense      | Failing to provide decryption shares       |
//!
//! Evidence submitter receives 10% finder's fee from slashed stake.
//! No time limit on evidence — previous epoch evidence is still valid.

use crate::block::BlockHeader;
use crate::validator::{Validator, ValidatorSet, ValidatorStatus, VALIDATOR_STAKE};
use pyde_account::address::Address;
use pyde_crypto::falcon::{falcon_verify, FalconPublicKey, FalconSignature};

/// Finder's fee percentage (10% of slashed amount).
pub const FINDER_FEE_PERCENT: u128 = 10;

/// Slash percentages for liveness tiers.
pub const LIVENESS_SLASH_MINOR: u128 = 1;   // 1% — participation < 90%
pub const LIVENESS_SLASH_MAJOR: u128 = 5;   // 5% — participation < 50%
pub const LIVENESS_SLASH_ABSENT: u128 = 10;  // 10% — participation == 0%

/// Slash percentage for invalid block proposal.
pub const INVALID_PROPOSAL_SLASH: u128 = 50; // 50%

/// Slash percentage for decryption withholding.
pub const DECRYPTION_WITHHOLD_SLASH: u128 = 2; // 2% per offense

/// Slashing offense type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlashingOffense {
    DoubleSigning,
    Equivocation,
    LivenessMinor,    // < 90% participation
    LivenessMajor,    // < 50% participation
    LivenessAbsent,   // 0% participation
    InvalidProposal,
    DecryptionWithholding,
}

/// The result of processing a slashing event.
#[derive(Clone, Debug)]
pub struct SlashResult {
    /// Address of the slashed validator.
    pub offender: Address,
    /// Amount burned.
    pub amount_burned: u128,
    /// Finder's fee paid to evidence submitter.
    pub finder_fee: u128,
    /// Whether the offender is ejected from the validator set.
    pub ejected: bool,
    /// Whether forced unbonding is triggered.
    pub forced_unbonding: bool,
    /// The offense type.
    pub offense: SlashingOffense,
}

/// Double-signing evidence: two different blocks signed for the same slot.
///
/// Carries block *hashes* rather than full `BlockHeader`s because both
/// the proposer signature and vote signature formats bind (slot || hash)
/// directly — verifying the evidence requires nothing more than the
/// hashes, the two FALCON signatures, and the signer's public key. This
/// keeps the on-chain payload (`TransactionType::Slash` data field)
/// small and lets the tx pipeline verify the evidence without depending
/// on `BlockHeader` internals.
#[derive(Clone, Debug)]
pub struct DoubleSignEvidence {
    /// The slot where double-signing occurred.
    pub slot: u64,
    /// Hash of the first block the signer signed for this slot.
    pub block_hash_1: [u8; 32],
    /// FALCON signature over `proposer_sign_message(slot, block_hash_1)`.
    pub signature_1: Vec<u8>,
    /// Hash of the second block — must differ from `block_hash_1`.
    pub block_hash_2: [u8; 32],
    /// FALCON signature over `proposer_sign_message(slot, block_hash_2)`.
    pub signature_2: Vec<u8>,
    /// Address of the signer being accused.
    pub signer: Address,
    /// Address of the evidence submitter (receives the finder's fee).
    pub submitter: Address,
}

/// Liveness report for a validator over an epoch.
#[derive(Clone, Debug)]
pub struct LivenessReport {
    pub validator: Address,
    /// Number of slots the validator participated in.
    pub slots_participated: u64,
    /// Total slots in the epoch.
    pub total_slots: u64,
}

impl LivenessReport {
    /// Participation rate as a percentage (0-100).
    pub fn participation_percent(&self) -> u64 {
        if self.total_slots == 0 {
            return 100;
        }
        (self.slots_participated * 100) / self.total_slots
    }
}

// ========== Verification ==========

/// Verify double-sign evidence.
///
/// Checks:
/// 1. The two block hashes are different (otherwise it's not equivocation).
/// 2. Both signatures verify over `(slot || block_hash)` against the
///    accused signer's public key.
///
/// The slot binding lives inside the signed message, so a sig for slot
/// N cannot be replayed as evidence of equivocation at slot M.
pub fn verify_double_sign(evidence: &DoubleSignEvidence, public_key: &[u8]) -> bool {
    // Two distinct blocks (empty-or-equal hashes = not evidence).
    if evidence.block_hash_1 == evidence.block_hash_2 {
        return false;
    }

    let pk = match FalconPublicKey::from_bytes(public_key) {
        Some(pk) => pk,
        None => return false,
    };
    let sig_1 = match FalconSignature::from_bytes(&evidence.signature_1) {
        Some(s) => s,
        None => return false,
    };
    let sig_2 = match FalconSignature::from_bytes(&evidence.signature_2) {
        Some(s) => s,
        None => return false,
    };

    let msg_1 = crate::hotstuff::proposer_sign_message(evidence.slot, &evidence.block_hash_1);
    let msg_2 = crate::hotstuff::proposer_sign_message(evidence.slot, &evidence.block_hash_2);
    falcon_verify(&pk, &msg_1, &sig_1) && falcon_verify(&pk, &msg_2, &sig_2)
}

// ========== Slash Computation ==========

/// Compute the slash amount and finder's fee for a given offense.
fn compute_slash(stake: u128, offense: &SlashingOffense) -> (u128, u128) {
    let slash_percent = match offense {
        SlashingOffense::DoubleSigning => 100,
        SlashingOffense::Equivocation => 100,
        SlashingOffense::LivenessMinor => LIVENESS_SLASH_MINOR,
        SlashingOffense::LivenessMajor => LIVENESS_SLASH_MAJOR,
        SlashingOffense::LivenessAbsent => LIVENESS_SLASH_ABSENT,
        SlashingOffense::InvalidProposal => INVALID_PROPOSAL_SLASH,
        SlashingOffense::DecryptionWithholding => DECRYPTION_WITHHOLD_SLASH,
    };

    let slash_amount = stake * slash_percent / 100;
    let finder_fee = slash_amount * FINDER_FEE_PERCENT / 100;
    let burned = slash_amount - finder_fee;

    (burned, finder_fee)
}

/// Process a double-sign slashing event.
pub fn slash_double_sign(evidence: &DoubleSignEvidence, public_key: &[u8]) -> Option<SlashResult> {
    if !verify_double_sign(evidence, public_key) {
        return None;
    }

    let (burned, finder_fee) = compute_slash(VALIDATOR_STAKE, &SlashingOffense::DoubleSigning);

    Some(SlashResult {
        offender: evidence.signer,
        amount_burned: burned,
        finder_fee,
        ejected: true,
        forced_unbonding: true,
        offense: SlashingOffense::DoubleSigning,
    })
}

/// Process liveness slashing based on participation rate.
pub fn slash_liveness(report: &LivenessReport) -> Option<SlashResult> {
    let pct = report.participation_percent();

    let offense = if pct == 0 {
        SlashingOffense::LivenessAbsent
    } else if pct < 50 {
        SlashingOffense::LivenessMajor
    } else if pct < 90 {
        SlashingOffense::LivenessMinor
    } else {
        return None; // >= 90% participation, no slash
    };

    let (burned, finder_fee) = compute_slash(VALIDATOR_STAKE, &offense);
    let ejected = matches!(offense, SlashingOffense::LivenessMajor | SlashingOffense::LivenessAbsent);
    let forced_unbonding = matches!(offense, SlashingOffense::LivenessAbsent);

    Some(SlashResult {
        offender: report.validator,
        amount_burned: burned,
        finder_fee,
        ejected,
        forced_unbonding,
        offense,
    })
}

/// Apply a slash result to the validator set.
///
/// This actually modifies the validator's state:
/// 1. Reduces the validator's stake by the slashed amount
/// 2. Ejects the validator if required (status → Exited or Unbonding)
/// 3. Returns the amounts for the caller to credit/burn
///
/// Note: balance transfers (finder's fee, burn) must be handled by the
/// caller via the state/account layer, since this module only manages
/// the validator set.
pub fn apply_slash(
    validator_set: &mut ValidatorSet,
    result: &SlashResult,
    current_block: u64,
) -> bool {
    let total_slash = result.amount_burned + result.finder_fee;

    let validator = match validator_set
        .validators
        .iter_mut()
        .find(|v| v.address == result.offender)
    {
        Some(v) => v,
        None => return false,
    };

    // Reduce stake
    if validator.stake >= total_slash {
        validator.stake -= total_slash;
    } else {
        validator.stake = 0;
    }

    // Eject if required
    if result.forced_unbonding {
        validator.status = ValidatorStatus::Unbonding {
            exit_block: current_block,
        };
    } else if result.ejected {
        validator.status = ValidatorStatus::Exited;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::QuorumCert;
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::falcon::{falcon_keygen, falcon_sign};

    fn make_validator(seed: u8) -> (Address, Vec<u8>) {
        let pk = vec![seed; 897];
        let addr = derive_eoa_address(&pk);
        (addr, pk)
    }

    fn make_header(slot: u64, timestamp: u64) -> BlockHeader {
        BlockHeader {
            slot,
            epoch: slot / 1000,
            parent_hash: [0xAA; 32],
            proposer: derive_eoa_address(&[0x01; 897]),
            vrf_proof: vec![],
            qc_previous: QuorumCert::empty(),
            tx_root: [0; 32],
            state_root: [0; 32],
            timestamp,
        }
    }

    /// Helper: produce a proposer signature over the canonical
    /// `(slot || block_hash)` message layout the production code uses.
    fn sign_proposer(
        sk: &pyde_crypto::falcon::FalconSecretKey,
        slot: u64,
        block_hash: &[u8; 32],
    ) -> Vec<u8> {
        let msg = crate::hotstuff::proposer_sign_message(slot, block_hash);
        falcon_sign(sk, &msg).unwrap().as_bytes().to_vec()
    }

    // ========== Task 0512: Double-sign slashes validator ==========

    #[test]
    fn double_sign_detected_and_slashed() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let addr = derive_eoa_address(&pk_bytes);

        let hash_1 = make_header(100, 1_000_000).hash();
        let hash_2 = make_header(100, 2_000_000).hash(); // different timestamp → different hash

        let evidence = DoubleSignEvidence {
            slot: 100,
            block_hash_1: hash_1,
            signature_1: sign_proposer(&sk, 100, &hash_1),
            block_hash_2: hash_2,
            signature_2: sign_proposer(&sk, 100, &hash_2),
            signer: addr,
            submitter: derive_eoa_address(b"submitter"),
        };

        assert!(verify_double_sign(&evidence, &pk_bytes));

        let result = slash_double_sign(&evidence, &pk_bytes).unwrap();
        assert_eq!(result.offender, addr);
        assert_eq!(result.offense, SlashingOffense::DoubleSigning);
        assert!(result.ejected);
        assert!(result.forced_unbonding);
        // 100% slashed: 90% burned, 10% finder fee
        assert_eq!(result.amount_burned + result.finder_fee, VALIDATOR_STAKE);
        assert_eq!(result.finder_fee, VALIDATOR_STAKE / 10);
    }

    // ========== Task 0515: False evidence rejected ==========

    #[test]
    fn same_block_twice_rejected() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let addr = derive_eoa_address(&pk_bytes);

        let hash = make_header(100, 1_000_000).hash();
        let sig = sign_proposer(&sk, 100, &hash);

        let evidence = DoubleSignEvidence {
            slot: 100,
            block_hash_1: hash,
            signature_1: sig.clone(),
            block_hash_2: hash, // same hash!
            signature_2: sig,
            signer: addr,
            submitter: derive_eoa_address(b"submitter"),
        };

        assert!(!verify_double_sign(&evidence, &pk_bytes));
        assert!(slash_double_sign(&evidence, &pk_bytes).is_none());
    }

    #[test]
    fn wrong_signer_key_rejected() {
        let (pk1, sk1) = falcon_keygen().unwrap();
        let (pk2, _sk2) = falcon_keygen().unwrap();
        let addr = derive_eoa_address(pk1.as_bytes());

        let hash_1 = make_header(100, 1_000_000).hash();
        let hash_2 = make_header(100, 2_000_000).hash();

        let evidence = DoubleSignEvidence {
            slot: 100,
            block_hash_1: hash_1,
            signature_1: sign_proposer(&sk1, 100, &hash_1),
            block_hash_2: hash_2,
            signature_2: sign_proposer(&sk1, 100, &hash_2),
            signer: addr,
            submitter: derive_eoa_address(b"submitter"),
        };

        // Wrong key → reject
        assert!(!verify_double_sign(&evidence, pk2.as_bytes()));
    }

    #[test]
    fn wrong_slot_rejected() {
        // Signatures are bound to (slot || hash). If the signer attested
        // to slot 101 but the evidence claims slot 100, the FALCON
        // verify at slot 100 fails — no cross-slot replay possible.
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let addr = derive_eoa_address(&pk_bytes);

        let hash_1 = make_header(100, 1_000_000).hash();
        let hash_2 = make_header(100, 2_000_000).hash();

        let evidence = DoubleSignEvidence {
            slot: 100,
            block_hash_1: hash_1,
            // Signed at the wrong slot (101) — verify at slot 100 rejects.
            signature_1: sign_proposer(&sk, 101, &hash_1),
            block_hash_2: hash_2,
            signature_2: sign_proposer(&sk, 100, &hash_2),
            signer: addr,
            submitter: derive_eoa_address(b"submitter"),
        };

        assert!(!verify_double_sign(&evidence, &pk_bytes));
    }

    // ========== Task 0513: Liveness slashes proportionally ==========

    #[test]
    fn liveness_90_percent_no_slash() {
        let report = LivenessReport {
            validator: derive_eoa_address(b"val"),
            slots_participated: 900,
            total_slots: 1000,
        };
        assert!(slash_liveness(&report).is_none());
    }

    #[test]
    fn liveness_89_percent_minor_slash() {
        let report = LivenessReport {
            validator: derive_eoa_address(b"val"),
            slots_participated: 890,
            total_slots: 1000,
        };
        let result = slash_liveness(&report).unwrap();
        assert_eq!(result.offense, SlashingOffense::LivenessMinor);
        assert!(!result.ejected);
        // 1% of 10K PYDE
        let expected_total = VALIDATOR_STAKE / 100;
        assert_eq!(result.amount_burned + result.finder_fee, expected_total);
    }

    #[test]
    fn liveness_49_percent_major_slash_and_eject() {
        let report = LivenessReport {
            validator: derive_eoa_address(b"val"),
            slots_participated: 490,
            total_slots: 1000,
        };
        let result = slash_liveness(&report).unwrap();
        assert_eq!(result.offense, SlashingOffense::LivenessMajor);
        assert!(result.ejected);
        assert!(!result.forced_unbonding);
        // 5% of 10K PYDE
        let expected_total = VALIDATOR_STAKE * 5 / 100;
        assert_eq!(result.amount_burned + result.finder_fee, expected_total);
    }

    #[test]
    fn liveness_zero_absent_slash_and_forced_unbonding() {
        let report = LivenessReport {
            validator: derive_eoa_address(b"val"),
            slots_participated: 0,
            total_slots: 1000,
        };
        let result = slash_liveness(&report).unwrap();
        assert_eq!(result.offense, SlashingOffense::LivenessAbsent);
        assert!(result.ejected);
        assert!(result.forced_unbonding);
        // 10% of 10K PYDE
        let expected_total = VALIDATOR_STAKE / 10;
        assert_eq!(result.amount_burned + result.finder_fee, expected_total);
    }

    // ========== Finder's fee ==========

    #[test]
    fn finder_fee_is_10_percent() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let addr = derive_eoa_address(&pk_bytes);

        let hash_1 = make_header(100, 1_000_000).hash();
        let hash_2 = make_header(100, 2_000_000).hash();

        let evidence = DoubleSignEvidence {
            slot: 100,
            block_hash_1: hash_1,
            signature_1: sign_proposer(&sk, 100, &hash_1),
            block_hash_2: hash_2,
            signature_2: sign_proposer(&sk, 100, &hash_2),
            signer: addr,
            submitter: derive_eoa_address(b"finder"),
        };

        let result = slash_double_sign(&evidence, &pk_bytes).unwrap();
        assert_eq!(result.finder_fee, VALIDATOR_STAKE * 10 / 100);
        assert_eq!(result.amount_burned, VALIDATOR_STAKE * 90 / 100);
    }

    // ========== apply_slash ==========

    #[test]
    fn apply_double_sign_slash_reduces_stake_and_ejects() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let addr = derive_eoa_address(&pk_bytes);

        let mut set = ValidatorSet::new();
        set.register(addr, pk_bytes.clone(), VALIDATOR_STAKE, 0).unwrap();
        assert_eq!(set.validators[0].stake, VALIDATOR_STAKE);

        let hash_1 = make_header(100, 1_000_000).hash();
        let hash_2 = make_header(100, 2_000_000).hash();

        let evidence = DoubleSignEvidence {
            slot: 100,
            block_hash_1: hash_1,
            signature_1: sign_proposer(&sk, 100, &hash_1),
            block_hash_2: hash_2,
            signature_2: sign_proposer(&sk, 100, &hash_2),
            signer: addr,
            submitter: derive_eoa_address(b"finder"),
        };

        let result = slash_double_sign(&evidence, &pk_bytes).unwrap();
        assert!(apply_slash(&mut set, &result, 500));

        // Stake reduced to 0 (100% slashed)
        assert_eq!(set.validators[0].stake, 0);
        // Forced unbonding
        assert!(matches!(
            set.validators[0].status,
            ValidatorStatus::Unbonding { exit_block: 500 }
        ));
    }

    #[test]
    fn apply_liveness_slash_reduces_stake_partially() {
        let mut set = ValidatorSet::new();
        let (addr, pk) = make_validator(1);
        set.register(addr, pk, VALIDATOR_STAKE, 0).unwrap();

        let report = LivenessReport {
            validator: addr,
            slots_participated: 890,
            total_slots: 1000,
        };

        let result = slash_liveness(&report).unwrap();
        assert!(apply_slash(&mut set, &result, 1000));

        // 1% slashed, 99% remains
        let expected_remaining = VALIDATOR_STAKE - (VALIDATOR_STAKE / 100);
        assert_eq!(set.validators[0].stake, expected_remaining);
        // Not ejected for minor liveness
        assert_eq!(set.validators[0].status, ValidatorStatus::Active);
    }

    #[test]
    fn apply_slash_nonexistent_validator_returns_false() {
        let mut set = ValidatorSet::new();
        let result = SlashResult {
            offender: derive_eoa_address(b"nobody"),
            amount_burned: 1000,
            finder_fee: 100,
            ejected: true,
            forced_unbonding: false,
            offense: SlashingOffense::DoubleSigning,
        };
        assert!(!apply_slash(&mut set, &result, 0));
    }
}
