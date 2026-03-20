//! Prover registry: bond management for ZK provers.
//!
//! Provers post a 1,000 PYDE bond (not stake). The bond is slashable
//! for submitting invalid proofs. Registration, unbonding, and slash
//! execution are handled here.

use pyde_account::address::Address;

/// Required bond to register as a prover (in quanta, 1,000 PYDE).
pub const PROVER_BOND: u128 = 1_000_000_000_000;

/// Minimum prover committee size.
pub const MIN_PROVER_COMMITTEE: usize = 4;

/// Maximum prover committee size (coordination overhead cap).
pub const MAX_PROVER_COMMITTEE: usize = 32;

/// Unbonding period in blocks (~7 days at 400ms blocks).
pub const PROVER_UNBONDING_PERIOD: u64 = 1_512_000;

/// Prover status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProverStatus {
    /// Active and eligible to submit proofs.
    Active,
    /// Initiated exit, bond locked during unbonding.
    Unbonding { exit_block: u64 },
    /// Unbonding complete, bond returned.
    Exited,
    /// Slashed — bond partially or fully burned.
    Slashed,
}

/// A registered prover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prover {
    /// Prover's address.
    pub address: Address,
    /// Public key for proof verification.
    pub public_key: Vec<u8>,
    /// Bond amount (starts at PROVER_BOND, reduced by slashing).
    pub bond: u128,
    /// Current status.
    pub status: ProverStatus,
    /// Total proofs submitted.
    pub proofs_submitted: u64,
    /// Total invalid proofs (for reputation).
    pub invalid_proofs: u64,
}

/// Prover registry error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProverError {
    InsufficientBond { required: u128, provided: u128 },
    AlreadyRegistered(Address),
    NotFound(Address),
    AlreadyUnbonding(Address),
    NotActive(Address),
}

/// The prover registry.
#[derive(Clone, Debug, Default)]
pub struct ProverRegistry {
    pub provers: Vec<Prover>,
}

impl ProverRegistry {
    pub fn new() -> Self {
        Self {
            provers: Vec::new(),
        }
    }

    /// Register a new prover with the required bond.
    pub fn register(
        &mut self,
        address: Address,
        public_key: Vec<u8>,
        bond: u128,
    ) -> Result<(), ProverError> {
        if bond < PROVER_BOND {
            return Err(ProverError::InsufficientBond {
                required: PROVER_BOND,
                provided: bond,
            });
        }

        if self.provers.iter().any(|p| p.address == address && p.status == ProverStatus::Active) {
            return Err(ProverError::AlreadyRegistered(address));
        }

        self.provers.push(Prover {
            address,
            public_key,
            bond: PROVER_BOND,
            status: ProverStatus::Active,
            proofs_submitted: 0,
            invalid_proofs: 0,
        });

        Ok(())
    }

    /// Initiate unbonding (exit).
    pub fn unbond(&mut self, address: &Address, current_block: u64) -> Result<(), ProverError> {
        let prover = self
            .provers
            .iter_mut()
            .find(|p| p.address == *address && p.status == ProverStatus::Active)
            .ok_or(ProverError::NotFound(*address))?;

        prover.status = ProverStatus::Unbonding {
            exit_block: current_block,
        };
        Ok(())
    }

    /// Process unbonding: release provers whose period has elapsed.
    /// Returns list of (address, bond_to_return).
    pub fn process_unbonding(&mut self, current_block: u64) -> Vec<(Address, u128)> {
        let mut released = Vec::new();
        for p in &mut self.provers {
            if let ProverStatus::Unbonding { exit_block } = p.status {
                if current_block >= exit_block + PROVER_UNBONDING_PERIOD {
                    released.push((p.address, p.bond));
                    p.status = ProverStatus::Exited;
                }
            }
        }
        released
    }

    /// Slash a prover's bond. Returns (amount_burned, finder_fee).
    pub fn slash(
        &mut self,
        address: &Address,
        slash_percent: u128,
    ) -> Result<(u128, u128), ProverError> {
        let prover = self
            .provers
            .iter_mut()
            .find(|p| p.address == *address)
            .ok_or(ProverError::NotFound(*address))?;

        let slash_amount = prover.bond * slash_percent / 100;
        let finder_fee = slash_amount * 10 / 100; // 10% finder's fee
        let burned = slash_amount - finder_fee;

        prover.bond -= slash_amount;
        prover.invalid_proofs += 1;

        if prover.bond == 0 {
            prover.status = ProverStatus::Slashed;
        }

        Ok((burned, finder_fee))
    }

    /// Record a successful proof submission.
    pub fn record_proof(&mut self, address: &Address) -> Result<(), ProverError> {
        let prover = self
            .provers
            .iter_mut()
            .find(|p| p.address == *address && p.status == ProverStatus::Active)
            .ok_or(ProverError::NotActive(*address))?;

        prover.proofs_submitted += 1;
        Ok(())
    }

    /// Get active provers.
    pub fn active_provers(&self) -> Vec<&Prover> {
        self.provers.iter().filter(|p| p.status == ProverStatus::Active).collect()
    }

    /// Number of active provers.
    pub fn active_count(&self) -> usize {
        self.active_provers().len()
    }

    /// Get a prover by address.
    pub fn get(&self, address: &Address) -> Option<&Prover> {
        self.provers.iter().find(|p| p.address == *address)
    }

    /// Compute the prover committee size based on active provers and backlog.
    ///
    /// - Base: half of active provers (rest are backup)
    /// - Scale up 1.5x if unproven backlog > 50
    /// - Clamped to [MIN_PROVER_COMMITTEE, MAX_PROVER_COMMITTEE]
    pub fn committee_size(&self, unproven_backlog: u64) -> usize {
        compute_committee_size(self.active_count(), unproven_backlog)
    }

    /// Select a prover committee for an epoch.
    ///
    /// Uses all active provers up to MAX_PROVER_COMMITTEE (minimum viable).
    /// Sorted by highest proof count (most reliable get priority if capped).
    /// Overflow provers serve as backup (pick up unclaimed groups on failure).
    pub fn select_committee(
        &self,
        unproven_backlog: u64,
    ) -> ProverCommittee {
        let size = self.committee_size(unproven_backlog);

        let mut candidates: Vec<&Prover> = self.active_provers();
        // Sort by most proofs submitted (most reliable first)
        candidates.sort_by(|a, b| b.proofs_submitted.cmp(&a.proofs_submitted));

        let members: Vec<Prover> = candidates
            .iter()
            .take(size)
            .map(|p| (*p).clone())
            .collect();

        // Only overflow beyond MAX becomes backup
        let backups: Vec<Prover> = candidates
            .iter()
            .skip(size)
            .map(|p| (*p).clone())
            .collect();

        ProverCommittee {
            members,
            backups,
        }
    }
}

/// Compute committee size from active prover count and backlog.
///
/// Strategy: use all available provers (minimum viable), capped at MAX.
/// Don't bench provers unnecessarily — more provers = faster proving.
/// Backlog doesn't increase size (we use everyone already), it's a signal
/// for the market to attract more prover registrations.
pub fn compute_committee_size(active_provers: usize, _unproven_backlog: u64) -> usize {
    active_provers.clamp(MIN_PROVER_COMMITTEE, MAX_PROVER_COMMITTEE)
}

/// A prover committee for an epoch.
#[derive(Clone, Debug)]
pub struct ProverCommittee {
    /// Active committee members (assigned groups).
    pub members: Vec<Prover>,
    /// Backup provers (pick up unclaimed groups on failure).
    pub backups: Vec<Prover>,
}

impl ProverCommittee {
    /// Number of committee members.
    pub fn size(&self) -> usize {
        self.members.len()
    }

    /// Get the aggregator for a given slot (rotating).
    pub fn aggregator(&self, slot: u64) -> Option<&Prover> {
        if self.members.is_empty() {
            return None;
        }
        Some(&self.members[slot as usize % self.members.len()])
    }

    /// Assign parallel groups to committee members (round-robin).
    pub fn assign_groups(&self, num_groups: usize) -> Vec<Vec<usize>> {
        let mut assignments = vec![vec![]; self.members.len()];
        if self.members.is_empty() {
            return assignments;
        }
        for group_idx in 0..num_groups {
            assignments[group_idx % self.members.len()].push(group_idx);
        }
        assignments
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::derive_eoa_address;

    fn prover_addr(seed: u8) -> (Address, Vec<u8>) {
        let pk = vec![seed; 897];
        let addr = derive_eoa_address(&pk);
        (addr, pk)
    }

    // ========== Task 1210-1211: Prover registration ==========

    #[test]
    fn register_prover() {
        let mut reg = ProverRegistry::new();
        let (addr, pk) = prover_addr(1);
        reg.register(addr, pk, PROVER_BOND).unwrap();
        assert_eq!(reg.active_count(), 1);
        assert_eq!(reg.get(&addr).unwrap().bond, PROVER_BOND);
    }

    #[test]
    fn reject_insufficient_bond() {
        let mut reg = ProverRegistry::new();
        let (addr, pk) = prover_addr(1);
        let err = reg.register(addr, pk, PROVER_BOND - 1).unwrap_err();
        assert!(matches!(err, ProverError::InsufficientBond { .. }));
    }

    #[test]
    fn reject_duplicate_registration() {
        let mut reg = ProverRegistry::new();
        let (addr, pk) = prover_addr(1);
        reg.register(addr, pk.clone(), PROVER_BOND).unwrap();
        let err = reg.register(addr, pk, PROVER_BOND).unwrap_err();
        assert!(matches!(err, ProverError::AlreadyRegistered(_)));
    }

    // ========== Task 1212: Slash reduces bond ==========

    #[test]
    fn slash_reduces_bond() {
        let mut reg = ProverRegistry::new();
        let (addr, pk) = prover_addr(1);
        reg.register(addr, pk, PROVER_BOND).unwrap();

        let (burned, fee) = reg.slash(&addr, 100).unwrap(); // 100% slash
        assert_eq!(burned + fee, PROVER_BOND);
        assert_eq!(fee, PROVER_BOND / 10); // 10% finder's fee

        let prover = reg.get(&addr).unwrap();
        assert_eq!(prover.bond, 0);
        assert_eq!(prover.status, ProverStatus::Slashed);
        assert_eq!(prover.invalid_proofs, 1);
    }

    #[test]
    fn partial_slash() {
        let mut reg = ProverRegistry::new();
        let (addr, pk) = prover_addr(1);
        reg.register(addr, pk, PROVER_BOND).unwrap();

        reg.slash(&addr, 50).unwrap(); // 50% slash
        let prover = reg.get(&addr).unwrap();
        assert_eq!(prover.bond, PROVER_BOND / 2);
        assert_eq!(prover.status, ProverStatus::Active); // still active, has remaining bond
    }

    // ========== Task 1213: Unbond returns bond ==========

    #[test]
    fn unbond_and_release() {
        let mut reg = ProverRegistry::new();
        let (addr, pk) = prover_addr(1);
        reg.register(addr, pk, PROVER_BOND).unwrap();

        reg.unbond(&addr, 1000).unwrap();
        assert!(matches!(
            reg.get(&addr).unwrap().status,
            ProverStatus::Unbonding { exit_block: 1000 }
        ));

        // Before period
        let released = reg.process_unbonding(1000 + PROVER_UNBONDING_PERIOD - 1);
        assert!(released.is_empty());

        // After period
        let released = reg.process_unbonding(1000 + PROVER_UNBONDING_PERIOD);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0], (addr, PROVER_BOND));
        assert_eq!(reg.get(&addr).unwrap().status, ProverStatus::Exited);
    }

    // ========== Proof tracking ==========

    #[test]
    fn record_proof() {
        let mut reg = ProverRegistry::new();
        let (addr, pk) = prover_addr(1);
        reg.register(addr, pk, PROVER_BOND).unwrap();

        reg.record_proof(&addr).unwrap();
        reg.record_proof(&addr).unwrap();
        assert_eq!(reg.get(&addr).unwrap().proofs_submitted, 2);
    }

    #[test]
    fn inactive_prover_cannot_submit() {
        let mut reg = ProverRegistry::new();
        let (addr, pk) = prover_addr(1);
        reg.register(addr, pk, PROVER_BOND).unwrap();
        reg.unbond(&addr, 0).unwrap();

        assert!(reg.record_proof(&addr).is_err());
    }

    // ========== Committee sizing ==========

    fn register_n_provers(reg: &mut ProverRegistry, n: usize) {
        for i in 0..n {
            let (addr, pk) = prover_addr(i as u8);
            reg.register(addr, pk, PROVER_BOND).unwrap();
        }
    }

    #[test]
    fn committee_size_minimum() {
        // 2 provers → clamped to MIN = 4 (use all available anyway)
        assert_eq!(compute_committee_size(2, 0), MIN_PROVER_COMMITTEE);
        assert_eq!(compute_committee_size(4, 0), MIN_PROVER_COMMITTEE);
    }

    #[test]
    fn committee_size_uses_all_provers() {
        // 20 provers → all 20 in committee
        assert_eq!(compute_committee_size(20, 0), 20);
    }

    #[test]
    fn committee_size_backlog_doesnt_change_size() {
        // All provers already in committee, backlog is market signal
        assert_eq!(compute_committee_size(20, 0), 20);
        assert_eq!(compute_committee_size(20, 100), 20);
    }

    #[test]
    fn committee_size_maximum() {
        // 100 provers → capped at MAX = 32
        assert_eq!(compute_committee_size(100, 0), MAX_PROVER_COMMITTEE);
    }

    #[test]
    fn committee_size_from_registry() {
        let mut reg = ProverRegistry::new();
        register_n_provers(&mut reg, 20);
        assert_eq!(reg.committee_size(0), 20); // all 20
    }

    // ========== Committee selection ==========

    #[test]
    fn select_committee_uses_all_provers() {
        let mut reg = ProverRegistry::new();
        register_n_provers(&mut reg, 20);

        let committee = reg.select_committee(0);
        assert_eq!(committee.size(), 20);       // all provers in committee
        assert_eq!(committee.backups.len(), 0);  // no overflow
    }

    #[test]
    fn select_committee_overflow_becomes_backup() {
        let mut reg = ProverRegistry::new();
        register_n_provers(&mut reg, 40); // exceeds MAX_PROVER_COMMITTEE (32)

        let committee = reg.select_committee(0);
        assert_eq!(committee.size(), MAX_PROVER_COMMITTEE); // capped at 32
        assert_eq!(committee.backups.len(), 8);               // overflow as backup
    }

    #[test]
    fn select_committee_sorted_by_reputation() {
        let mut reg = ProverRegistry::new();
        register_n_provers(&mut reg, 10);

        // Give prover 5 the most proofs
        let addr5 = reg.provers[5].address;
        for _ in 0..100 {
            reg.record_proof(&addr5).unwrap();
        }

        let committee = reg.select_committee(0);
        // Most prolific prover should be first member
        assert_eq!(committee.members[0].address, addr5);
    }

    // ========== Group assignment ==========

    #[test]
    fn assign_groups_round_robin() {
        let mut reg = ProverRegistry::new();
        register_n_provers(&mut reg, 8);
        let committee = reg.select_committee(0);

        let assignments = committee.assign_groups(10);
        assert_eq!(assignments.len(), committee.size());

        // All groups assigned
        let total: usize = assignments.iter().map(|a| a.len()).sum();
        assert_eq!(total, 10);

        // Roughly equal distribution
        for a in &assignments {
            assert!(a.len() >= 1 && a.len() <= 3);
        }
    }

    #[test]
    fn assign_groups_fewer_than_members() {
        let mut reg = ProverRegistry::new();
        register_n_provers(&mut reg, 20);
        let committee = reg.select_committee(0); // 10 members

        let assignments = committee.assign_groups(3); // only 3 groups
        let assigned_members = assignments.iter().filter(|a| !a.is_empty()).count();
        assert_eq!(assigned_members, 3); // only 3 members get work
    }

    // ========== Aggregator ==========

    #[test]
    fn aggregator_rotates() {
        let mut reg = ProverRegistry::new();
        register_n_provers(&mut reg, 10);
        let committee = reg.select_committee(0);

        let agg0 = committee.aggregator(0).unwrap().address;
        let agg1 = committee.aggregator(1).unwrap().address;
        assert_ne!(agg0, agg1); // different aggregators per slot

        // Wraps around
        let agg_wrap = committee.aggregator(committee.size() as u64).unwrap().address;
        assert_eq!(agg_wrap, agg0); // back to first
    }
}
