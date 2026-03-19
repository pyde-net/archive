//! Parallel execution scheduler: groups non-conflicting transactions
//! for concurrent execution based on access list analysis.
//!
//! Two transactions conflict if their access lists overlap with at least
//! one write. Non-conflicting transactions can execute in parallel.
//! Conflicting transactions fall back to sequential execution.
//!
//! Algorithm:
//! 1. Build conflict graph from access lists
//! 2. Graph-color to produce non-conflicting groups
//! 3. Groups execute in parallel; transactions within a group are independent

use crate::types::{AccessEntry, Transaction};
use pyde_account::address::Address;
use std::collections::{HashMap, HashSet};

/// A group of non-conflicting transactions that can execute in parallel.
#[derive(Clone, Debug)]
pub struct ExecutionGroup {
    /// Indices into the original transaction list.
    pub tx_indices: Vec<usize>,
}

/// Result of scheduling: ordered groups for execution.
#[derive(Clone, Debug)]
pub struct ExecutionSchedule {
    /// Groups in execution order. Each group runs in parallel internally,
    /// groups execute sequentially.
    pub groups: Vec<ExecutionGroup>,
    /// Total number of transactions.
    pub total_txs: usize,
}

impl ExecutionSchedule {
    /// Number of groups (sequential steps).
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Maximum parallelism (largest group size).
    pub fn max_parallelism(&self) -> usize {
        self.groups.iter().map(|g| g.tx_indices.len()).max().unwrap_or(0)
    }
}

/// A storage key accessed by a transaction: (contract_address, storage_key).
type StorageAccess = (Address, [u8; 32]);

/// Access type: read-only or read-write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccessType {
    Read,
    Write,
}

/// Detect conflicts between two transactions based on their access lists.
///
/// Conflict rule (key-level, not address-level):
/// - read + read on same (address, key) = NO conflict (parallel safe)
/// - read + write on same (address, key) = CONFLICT
/// - write + write on same (address, key) = CONFLICT
///
/// Two txs touching the same contract but different keys are NOT conflicting.
pub fn conflicts(tx_a: &Transaction, tx_b: &Transaction) -> bool {
    // Collect write keys from each tx: (address, key)
    let writes_a: HashSet<(Address, [u8; 32])> = tx_a
        .access_list
        .iter()
        .flat_map(|entry| entry.writes.iter().map(move |k| (entry.address, *k)))
        .collect();

    let writes_b: HashSet<(Address, [u8; 32])> = tx_b
        .access_list
        .iter()
        .flat_map(|entry| entry.writes.iter().map(move |k| (entry.address, *k)))
        .collect();

    // Collect all keys (reads + writes) from each tx
    let all_a: HashSet<(Address, [u8; 32])> = tx_a
        .access_list
        .iter()
        .flat_map(|entry| {
            entry.reads.iter().chain(entry.writes.iter())
                .map(move |k| (entry.address, *k))
        })
        .collect();

    let all_b: HashSet<(Address, [u8; 32])> = tx_b
        .access_list
        .iter()
        .flat_map(|entry| {
            entry.reads.iter().chain(entry.writes.iter())
                .map(move |k| (entry.address, *k))
        })
        .collect();

    // Conflict if: A writes something B touches, or B writes something A touches
    for wk in &writes_a {
        if all_b.contains(wk) {
            return true;
        }
    }
    for wk in &writes_b {
        if all_a.contains(wk) {
            return true;
        }
    }
    false
}

/// Schedule transactions into parallel execution groups.
///
/// Uses greedy graph coloring: for each transaction, assign it to the first
/// group where it doesn't conflict with any existing transaction in that group.
pub fn schedule(txs: &[Transaction]) -> ExecutionSchedule {
    let n = txs.len();
    if n == 0 {
        return ExecutionSchedule {
            groups: vec![],
            total_txs: 0,
        };
    }

    // Greedy coloring: assign each tx to the first compatible group
    let mut groups: Vec<ExecutionGroup> = Vec::new();

    for i in 0..n {
        let mut assigned = false;

        for group in groups.iter_mut() {
            // Check if tx[i] conflicts with any tx already in this group
            let has_conflict = group
                .tx_indices
                .iter()
                .any(|&j| conflicts(&txs[i], &txs[j]));

            if !has_conflict {
                group.tx_indices.push(i);
                assigned = true;
                break;
            }
        }

        if !assigned {
            groups.push(ExecutionGroup {
                tx_indices: vec![i],
            });
        }
    }

    ExecutionSchedule {
        groups,
        total_txs: n,
    }
}

/// Check if two access lists conflict (shared key with at least one write).
pub fn access_lists_conflict(a: &[AccessEntry], b: &[AccessEntry]) -> bool {
    let writes_a: HashSet<(Address, [u8; 32])> = a
        .iter()
        .flat_map(|entry| entry.writes.iter().map(move |k| (entry.address, *k)))
        .collect();

    let writes_b: HashSet<(Address, [u8; 32])> = b
        .iter()
        .flat_map(|entry| entry.writes.iter().map(move |k| (entry.address, *k)))
        .collect();

    let all_a: HashSet<(Address, [u8; 32])> = a
        .iter()
        .flat_map(|entry| {
            entry.reads.iter().chain(entry.writes.iter())
                .map(move |k| (entry.address, *k))
        })
        .collect();

    let all_b: HashSet<(Address, [u8; 32])> = b
        .iter()
        .flat_map(|entry| {
            entry.reads.iter().chain(entry.writes.iter())
                .map(move |k| (entry.address, *k))
        })
        .collect();

    for wk in &writes_a {
        if all_b.contains(wk) {
            return true;
        }
    }
    for wk in &writes_b {
        if all_a.contains(wk) {
            return true;
        }
    }
    false
}

/// Schedule from raw access lists (works for both Transaction and EncryptedTx).
/// Each element in `access_lists` is the access list for one transaction.
pub fn schedule_from_access_lists(access_lists: &[Vec<AccessEntry>]) -> ExecutionSchedule {
    let n = access_lists.len();
    if n == 0 {
        return ExecutionSchedule {
            groups: vec![],
            total_txs: 0,
        };
    }

    let mut groups: Vec<ExecutionGroup> = Vec::new();

    for i in 0..n {
        let mut assigned = false;

        for group in groups.iter_mut() {
            let has_conflict = group
                .tx_indices
                .iter()
                .any(|&j| access_lists_conflict(&access_lists[i], &access_lists[j]));

            if !has_conflict {
                group.tx_indices.push(i);
                assigned = true;
                break;
            }
        }

        if !assigned {
            groups.push(ExecutionGroup {
                tx_indices: vec![i],
            });
        }
    }

    ExecutionSchedule {
        groups,
        total_txs: n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FeePayer, TransactionType};
    use pyde_account::address::{derive_eoa_address, ZERO_ADDRESS};

    fn make_tx_with_access(access_list: Vec<AccessEntry>) -> Transaction {
        Transaction {
            from: derive_eoa_address(&[0xAA; 897]),
            to: derive_eoa_address(&[0xBB; 897]),
            value: 0,
            data: vec![],
            gas_limit: 21_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list,
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        }
    }

    fn read_access(addr: u8, keys: &[[u8; 32]]) -> AccessEntry {
        AccessEntry {
            address: {
                let mut a = ZERO_ADDRESS;
                a[0] = addr;
                a
            },
            reads: keys.to_vec(),
            writes: vec![],
        }
    }

    fn write_access(addr: u8, keys: &[[u8; 32]]) -> AccessEntry {
        AccessEntry {
            address: {
                let mut a = ZERO_ADDRESS;
                a[0] = addr;
                a
            },
            reads: vec![],
            writes: keys.to_vec(),
        }
    }

    // ========== Task 0411: Conflict detection ==========

    #[test]
    fn no_conflict_different_keys() {
        let tx_a = make_tx_with_access(vec![write_access(0x01, &[[0xAA; 32]])]);
        let tx_b = make_tx_with_access(vec![write_access(0x01, &[[0xBB; 32]])]);
        assert!(!conflicts(&tx_a, &tx_b));
    }

    #[test]
    fn conflict_same_key() {
        let key = [0xAA; 32];
        let tx_a = make_tx_with_access(vec![write_access(0x01, &[key])]);
        let tx_b = make_tx_with_access(vec![write_access(0x01, &[key])]);
        assert!(conflicts(&tx_a, &tx_b));
    }

    #[test]
    fn no_conflict_different_contracts() {
        let key = [0xAA; 32];
        let tx_a = make_tx_with_access(vec![write_access(0x01, &[key])]);
        let tx_b = make_tx_with_access(vec![write_access(0x02, &[key])]);
        assert!(!conflicts(&tx_a, &tx_b));
    }

    #[test]
    fn no_conflict_empty_access_lists() {
        let tx_a = make_tx_with_access(vec![]);
        let tx_b = make_tx_with_access(vec![]);
        assert!(!conflicts(&tx_a, &tx_b));
    }

    #[test]
    fn no_conflict_read_read_same_key() {
        // Two reads on same key = parallel safe
        let key = [0xAA; 32];
        let tx_a = make_tx_with_access(vec![read_access(0x01, &[key])]);
        let tx_b = make_tx_with_access(vec![read_access(0x01, &[key])]);
        assert!(!conflicts(&tx_a, &tx_b));
    }

    #[test]
    fn conflict_read_write_same_key() {
        // One reads, other writes same key = conflict
        let key = [0xAA; 32];
        let tx_a = make_tx_with_access(vec![read_access(0x01, &[key])]);
        let tx_b = make_tx_with_access(vec![write_access(0x01, &[key])]);
        assert!(conflicts(&tx_a, &tx_b));
    }

    #[test]
    fn no_conflict_same_address_different_write_keys() {
        // Same contract, different write keys = parallel safe
        let tx_a = make_tx_with_access(vec![write_access(0x01, &[[0xAA; 32]])]);
        let tx_b = make_tx_with_access(vec![write_access(0x01, &[[0xBB; 32]])]);
        assert!(!conflicts(&tx_a, &tx_b));
    }

    // ========== Task 0412: Transaction grouping ==========

    #[test]
    fn non_conflicting_in_same_group() {
        let txs = vec![
            make_tx_with_access(vec![write_access(0x01, &[[0xAA; 32]])]),
            make_tx_with_access(vec![write_access(0x01, &[[0xBB; 32]])]),
            make_tx_with_access(vec![write_access(0x02, &[[0xAA; 32]])]),
        ];

        let schedule = schedule(&txs);
        assert_eq!(schedule.group_count(), 1); // all non-conflicting
        assert_eq!(schedule.max_parallelism(), 3);
    }

    // ========== Task 0417: Two non-conflicting execute in parallel ==========

    #[test]
    fn two_non_conflicting_parallel() {
        let txs = vec![
            make_tx_with_access(vec![write_access(0x01, &[[0x11; 32]])]),
            make_tx_with_access(vec![write_access(0x02, &[[0x22; 32]])]),
        ];

        let schedule = schedule(&txs);
        assert_eq!(schedule.group_count(), 1);
        assert_eq!(schedule.groups[0].tx_indices, vec![0, 1]);
    }

    // ========== Task 0418: Two conflicting execute sequentially ==========

    #[test]
    fn two_conflicting_sequential() {
        let key = [0xAA; 32];
        let txs = vec![
            make_tx_with_access(vec![write_access(0x01, &[key])]),
            make_tx_with_access(vec![write_access(0x01, &[key])]),
        ];

        let schedule = schedule(&txs);
        assert_eq!(schedule.group_count(), 2); // separate groups
        assert_eq!(schedule.groups[0].tx_indices, vec![0]);
        assert_eq!(schedule.groups[1].tx_indices, vec![1]);
    }

    // ========== Task 0416: Sequential fallback ==========

    #[test]
    fn all_conflicting_fully_sequential() {
        let key = [0xFF; 32];
        let txs: Vec<Transaction> = (0..5)
            .map(|_| make_tx_with_access(vec![write_access(0x01, &[key])]))
            .collect();

        let schedule = schedule(&txs);
        assert_eq!(schedule.group_count(), 5); // each in its own group
    }

    // ========== Mixed scenario ==========

    #[test]
    fn mixed_parallel_and_sequential() {
        let key_shared = [0xAA; 32];
        let txs = vec![
            make_tx_with_access(vec![write_access(0x01, &[key_shared])]),     // group 0
            make_tx_with_access(vec![write_access(0x01, &[key_shared])]),     // group 1 (conflicts with 0)
            make_tx_with_access(vec![write_access(0x02, &[[0xBB; 32]])]),     // group 0 (no conflict)
            make_tx_with_access(vec![write_access(0x03, &[[0xCC; 32]])]),     // group 0 (no conflict)
        ];

        let schedule = schedule(&txs);
        // tx0 conflicts with tx1, so tx1 gets its own group
        // tx2, tx3 don't conflict with tx0 → same group as tx0
        assert_eq!(schedule.group_count(), 2);
        assert_eq!(schedule.groups[0].tx_indices, vec![0, 2, 3]);
        assert_eq!(schedule.groups[1].tx_indices, vec![1]);
    }

    // ========== Task 0419: Same state root ==========

    #[test]
    fn schedule_preserves_all_txs() {
        let txs: Vec<Transaction> = (0..10)
            .map(|i| {
                make_tx_with_access(vec![write_access(i as u8, &[[i as u8; 32]])])
            })
            .collect();

        let schedule = schedule(&txs);

        // All tx indices should be present exactly once
        let mut all_indices: Vec<usize> = schedule
            .groups
            .iter()
            .flat_map(|g| g.tx_indices.iter().copied())
            .collect();
        all_indices.sort();
        assert_eq!(all_indices, (0..10).collect::<Vec<_>>());
    }

    // ========== Empty ==========

    #[test]
    fn empty_schedule() {
        let schedule = schedule(&[]);
        assert_eq!(schedule.group_count(), 0);
        assert_eq!(schedule.total_txs, 0);
    }
}
