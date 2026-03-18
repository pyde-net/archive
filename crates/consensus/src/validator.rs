//! Validator set management per Chapter 6 and Chapter 14 spec.
//!
//! - Fixed stake: 10,000 PYDE per validator (equal votes)
//! - Committee: 128 validators per epoch, VRF-selected
//! - Epoch rotation every 1,000 blocks
//! - 14-day unbonding period on deregistration

use crate::block::{COMMITTEE_SIZE, EPOCH_LENGTH};
use pyde_account::address::Address;
use pyde_crypto::poseidon2::poseidon2_hash;

/// Required stake to register as a validator (in quanta, 10^9 quanta = 1 PYDE).
pub const VALIDATOR_STAKE: u128 = 10_000_000_000_000; // 10,000 PYDE

/// Unbonding period in blocks (~14 days at 400ms blocks).
/// 14 days × 24 hours × 60 min × 60 sec / 0.4 sec = 3,024,000 blocks.
pub const UNBONDING_PERIOD: u64 = 3_024_000;

/// Validator status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidatorStatus {
    /// Registered and eligible for committee selection.
    Active,
    /// Initiated exit, stake locked during unbonding period.
    Unbonding { exit_block: u64 },
    /// Unbonding complete, stake returned.
    Exited,
}

/// A registered validator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validator {
    /// Validator's address (32 bytes).
    pub address: Address,
    /// FALCON-512 public key for signing.
    pub public_key: Vec<u8>,
    /// Staked amount (must be exactly VALIDATOR_STAKE).
    pub stake: u128,
    /// Current status.
    pub status: ValidatorStatus,
    /// Epoch when registered.
    pub registered_epoch: u64,
}

/// The active committee for an epoch.
#[derive(Clone, Debug)]
pub struct Committee {
    /// Epoch this committee is active for.
    pub epoch: u64,
    /// The 128 selected validators.
    pub members: Vec<Validator>,
    /// Threshold public key for this epoch's threshold decryption.
    pub threshold_public_key: Vec<u8>,
}

impl Committee {
    /// Number of members.
    pub fn size(&self) -> usize {
        self.members.len()
    }

    /// Check if an address is in this committee.
    pub fn contains(&self, address: &Address) -> bool {
        self.members.iter().any(|v| v.address == *address)
    }

    /// Get a member by index.
    pub fn member(&self, index: usize) -> Option<&Validator> {
        self.members.get(index)
    }
}

/// The full validator set (all registered validators across all statuses).
#[derive(Clone, Debug, Default)]
pub struct ValidatorSet {
    pub validators: Vec<Validator>,
}

/// Registration error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidatorError {
    InsufficientStake { required: u128, provided: u128 },
    AlreadyRegistered(Address),
    NotFound(Address),
    AlreadyUnbonding(Address),
    NotEnoughValidators { needed: usize, available: usize },
}

impl ValidatorSet {
    pub fn new() -> Self {
        Self {
            validators: Vec::new(),
        }
    }

    /// Register a new validator with exactly VALIDATOR_STAKE.
    pub fn register(
        &mut self,
        address: Address,
        public_key: Vec<u8>,
        stake: u128,
        current_epoch: u64,
    ) -> Result<(), ValidatorError> {
        if stake < VALIDATOR_STAKE {
            return Err(ValidatorError::InsufficientStake {
                required: VALIDATOR_STAKE,
                provided: stake,
            });
        }

        if self.validators.iter().any(|v| v.address == address && v.status == ValidatorStatus::Active) {
            return Err(ValidatorError::AlreadyRegistered(address));
        }

        self.validators.push(Validator {
            address,
            public_key,
            stake: VALIDATOR_STAKE, // exactly 10K, excess returned
            status: ValidatorStatus::Active,
            registered_epoch: current_epoch,
        });

        Ok(())
    }

    /// Initiate deregistration (begin unbonding).
    pub fn deregister(
        &mut self,
        address: &Address,
        current_block: u64,
    ) -> Result<(), ValidatorError> {
        let validator = self
            .validators
            .iter_mut()
            .find(|v| v.address == *address && v.status == ValidatorStatus::Active)
            .ok_or(ValidatorError::NotFound(*address))?;

        if matches!(validator.status, ValidatorStatus::Unbonding { .. }) {
            return Err(ValidatorError::AlreadyUnbonding(*address));
        }

        validator.status = ValidatorStatus::Unbonding {
            exit_block: current_block,
        };

        Ok(())
    }

    /// Process unbonding: release validators whose unbonding period has elapsed.
    pub fn process_unbonding(&mut self, current_block: u64) {
        for v in &mut self.validators {
            if let ValidatorStatus::Unbonding { exit_block } = v.status {
                if current_block >= exit_block + UNBONDING_PERIOD {
                    v.status = ValidatorStatus::Exited;
                }
            }
        }
    }

    /// Get all active (eligible) validators with sufficient stake.
    pub fn active_validators(&self) -> Vec<&Validator> {
        self.validators
            .iter()
            .filter(|v| v.status == ValidatorStatus::Active && v.stake >= VALIDATOR_STAKE)
            .collect()
    }

    /// Get active validators with stake below the required minimum.
    /// These validators should top up before the next epoch or be excluded.
    pub fn underfunded_validators(&self) -> Vec<&Validator> {
        self.validators
            .iter()
            .filter(|v| v.status == ValidatorStatus::Active && v.stake < VALIDATOR_STAKE)
            .collect()
    }

    /// Top up a validator's stake (e.g., after partial slash).
    pub fn top_up_stake(&mut self, address: &Address, amount: u128) -> Result<(), ValidatorError> {
        let validator = self
            .validators
            .iter_mut()
            .find(|v| v.address == *address)
            .ok_or(ValidatorError::NotFound(*address))?;
        validator.stake += amount;
        Ok(())
    }

    /// Select a committee of 128 validators for the given epoch.
    /// Only validators with Active status AND sufficient stake are eligible.
    /// Uses VRF-seeded randomness for deterministic, unpredictable selection.
    pub fn select_committee(
        &self,
        epoch: u64,
        randomness: &[u8; 32],
        threshold_public_key: Vec<u8>,
    ) -> Result<Committee, ValidatorError> {
        let eligible: Vec<Validator> = self
            .validators
            .iter()
            .filter(|v| v.status == ValidatorStatus::Active && v.stake >= VALIDATOR_STAKE)
            .cloned()
            .collect();

        if eligible.len() < COMMITTEE_SIZE {
            return Err(ValidatorError::NotEnoughValidators {
                needed: COMMITTEE_SIZE,
                available: eligible.len(),
            });
        }

        // Deterministic shuffle using randomness seed
        let mut scored: Vec<(u64, Validator)> = eligible
            .into_iter()
            .map(|v| {
                let mut buf = Vec::with_capacity(32 + 8 + 32);
                buf.extend_from_slice(randomness);
                buf.extend_from_slice(&epoch.to_le_bytes());
                buf.extend_from_slice(&v.address);
                let hash = poseidon2_hash(&buf).to_bytes();
                let score = u64::from_le_bytes(hash[..8].try_into().unwrap());
                (score, v)
            })
            .collect();

        // Sort by score (deterministic ordering from randomness)
        scored.sort_by_key(|(score, _)| *score);

        // Take first 128
        let members: Vec<Validator> = scored
            .into_iter()
            .take(COMMITTEE_SIZE)
            .map(|(_, v)| v)
            .collect();

        Ok(Committee {
            epoch,
            members,
            threshold_public_key,
        })
    }

    /// Total number of registered validators (all statuses).
    pub fn total_count(&self) -> usize {
        self.validators.len()
    }

    /// Number of active validators.
    pub fn active_count(&self) -> usize {
        self.active_validators().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::derive_eoa_address;

    fn make_validator(seed: u8) -> (Address, Vec<u8>) {
        let pk = vec![seed; 897];
        let addr = derive_eoa_address(&pk);
        (addr, pk)
    }

    fn register_n(set: &mut ValidatorSet, n: usize) {
        for i in 0..n {
            let (addr, pk) = make_validator(i as u8);
            set.register(addr, pk, VALIDATOR_STAKE, 0).unwrap();
        }
    }

    // ========== Task 0464: Register with sufficient stake ==========

    #[test]
    fn register_validator() {
        let mut set = ValidatorSet::new();
        let (addr, pk) = make_validator(1);
        set.register(addr, pk, VALIDATOR_STAKE, 0).unwrap();
        assert_eq!(set.active_count(), 1);
    }

    #[test]
    fn register_sets_correct_fields() {
        let mut set = ValidatorSet::new();
        let (addr, pk) = make_validator(1);
        set.register(addr, pk.clone(), VALIDATOR_STAKE, 5).unwrap();

        let v = &set.validators[0];
        assert_eq!(v.address, addr);
        assert_eq!(v.public_key, pk);
        assert_eq!(v.stake, VALIDATOR_STAKE);
        assert_eq!(v.status, ValidatorStatus::Active);
        assert_eq!(v.registered_epoch, 5);
    }

    // ========== Task 0465: Reject insufficient stake ==========

    #[test]
    fn reject_insufficient_stake() {
        let mut set = ValidatorSet::new();
        let (addr, pk) = make_validator(1);
        let err = set.register(addr, pk, VALIDATOR_STAKE - 1, 0).unwrap_err();
        assert!(matches!(err, ValidatorError::InsufficientStake { .. }));
    }

    #[test]
    fn reject_duplicate_registration() {
        let mut set = ValidatorSet::new();
        let (addr, pk) = make_validator(1);
        set.register(addr, pk.clone(), VALIDATOR_STAKE, 0).unwrap();
        let err = set.register(addr, pk, VALIDATOR_STAKE, 0).unwrap_err();
        assert!(matches!(err, ValidatorError::AlreadyRegistered(_)));
    }

    // ========== Task 0466: Committee has exactly 128 members ==========

    #[test]
    fn committee_has_128_members() {
        let mut set = ValidatorSet::new();
        register_n(&mut set, 200);

        let committee = set
            .select_committee(0, &[0xAA; 32], vec![0xFF; 100])
            .unwrap();
        assert_eq!(committee.size(), COMMITTEE_SIZE);
        assert_eq!(committee.epoch, 0);
    }

    #[test]
    fn committee_selection_deterministic() {
        let mut set = ValidatorSet::new();
        register_n(&mut set, 200);

        let c1 = set.select_committee(0, &[0xAA; 32], vec![]).unwrap();
        let c2 = set.select_committee(0, &[0xAA; 32], vec![]).unwrap();

        let addrs1: Vec<Address> = c1.members.iter().map(|v| v.address).collect();
        let addrs2: Vec<Address> = c2.members.iter().map(|v| v.address).collect();
        assert_eq!(addrs1, addrs2);
    }

    #[test]
    fn different_randomness_different_committee() {
        let mut set = ValidatorSet::new();
        register_n(&mut set, 200);

        let c1 = set.select_committee(0, &[0xAA; 32], vec![]).unwrap();
        let c2 = set.select_committee(0, &[0xBB; 32], vec![]).unwrap();

        let addrs1: Vec<Address> = c1.members.iter().map(|v| v.address).collect();
        let addrs2: Vec<Address> = c2.members.iter().map(|v| v.address).collect();
        assert_ne!(addrs1, addrs2);
    }

    #[test]
    fn not_enough_validators_rejected() {
        let mut set = ValidatorSet::new();
        register_n(&mut set, 100); // only 100, need 128

        let err = set
            .select_committee(0, &[0xAA; 32], vec![])
            .unwrap_err();
        assert!(matches!(err, ValidatorError::NotEnoughValidators { .. }));
    }

    // ========== Task 0467: Committee rotates at epoch boundary ==========

    #[test]
    fn different_epoch_different_committee() {
        let mut set = ValidatorSet::new();
        register_n(&mut set, 200);

        let c1 = set.select_committee(0, &[0xAA; 32], vec![]).unwrap();
        let c2 = set.select_committee(1, &[0xAA; 32], vec![]).unwrap();

        let addrs1: Vec<Address> = c1.members.iter().map(|v| v.address).collect();
        let addrs2: Vec<Address> = c2.members.iter().map(|v| v.address).collect();
        // Different epochs with same randomness → different selection (epoch in hash)
        assert_ne!(addrs1, addrs2);
    }

    // ========== Task 0468: Deregistered excluded ==========

    #[test]
    fn deregistered_excluded_from_committee() {
        let mut set = ValidatorSet::new();
        register_n(&mut set, 130);

        let target = set.validators[0].address;
        set.deregister(&target, 100).unwrap();

        let committee = set
            .select_committee(1, &[0xAA; 32], vec![])
            .unwrap();
        assert!(!committee.contains(&target));
    }

    #[test]
    fn deregister_begins_unbonding() {
        let mut set = ValidatorSet::new();
        let (addr, pk) = make_validator(1);
        set.register(addr, pk, VALIDATOR_STAKE, 0).unwrap();

        set.deregister(&addr, 1000).unwrap();
        assert!(matches!(
            set.validators[0].status,
            ValidatorStatus::Unbonding { exit_block: 1000 }
        ));
    }

    #[test]
    fn unbonding_completes_after_period() {
        let mut set = ValidatorSet::new();
        let (addr, pk) = make_validator(1);
        set.register(addr, pk, VALIDATOR_STAKE, 0).unwrap();
        set.deregister(&addr, 1000).unwrap();

        // Before period
        set.process_unbonding(1000 + UNBONDING_PERIOD - 1);
        assert!(matches!(
            set.validators[0].status,
            ValidatorStatus::Unbonding { .. }
        ));

        // After period
        set.process_unbonding(1000 + UNBONDING_PERIOD);
        assert_eq!(set.validators[0].status, ValidatorStatus::Exited);
    }

    #[test]
    fn deregister_nonexistent_fails() {
        let mut set = ValidatorSet::new();
        let addr = derive_eoa_address(b"nobody");
        assert!(matches!(
            set.deregister(&addr, 0),
            Err(ValidatorError::NotFound(_))
        ));
    }

    // ========== Contains ==========

    #[test]
    fn committee_contains() {
        let mut set = ValidatorSet::new();
        register_n(&mut set, 128);

        let committee = set.select_committee(0, &[0xAA; 32], vec![]).unwrap();
        // All members should be found
        for m in &committee.members {
            assert!(committee.contains(&m.address));
        }
    }

    // ========== Underfunded after slash ==========

    #[test]
    fn underfunded_validator_excluded_from_committee() {
        let mut set = ValidatorSet::new();
        register_n(&mut set, 130);

        // Slash one validator's stake below minimum
        set.validators[0].stake = VALIDATOR_STAKE - 1;

        // Underfunded detected
        assert_eq!(set.underfunded_validators().len(), 1);

        // Excluded from committee selection
        let committee = set.select_committee(0, &[0xAA; 32], vec![]).unwrap();
        assert!(!committee.contains(&set.validators[0].address));
    }

    #[test]
    fn top_up_restores_eligibility() {
        let mut set = ValidatorSet::new();
        register_n(&mut set, 130);

        // Slash below minimum
        set.validators[0].stake = VALIDATOR_STAKE - 100;
        assert_eq!(set.underfunded_validators().len(), 1);

        // Top up
        set.top_up_stake(&set.validators[0].address.clone(), 100).unwrap();
        assert_eq!(set.underfunded_validators().len(), 0);
        assert_eq!(set.validators[0].stake, VALIDATOR_STAKE);
    }
}
