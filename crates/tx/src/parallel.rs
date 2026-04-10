//! Conflict-based execution scheduler: groups conflicting transactions
//! for sequential execution, enabling parallel proving between groups.
//!
//! Two transactions conflict if their access lists overlap with at least
//! one write. Transitively conflicting transactions are grouped together
//! (connected components in the conflict graph).
//!
//! ## Execution Model
//!
//! - Within a group: transactions execute SEQUENTIALLY (they conflict)
//! - Between groups: fully PARALLEL (disjoint access lists)
//! - All groups start from the SAME pre_state_root
//!
//! ## Algorithm
//!
//! 1. Build conflict graph from access lists (pairwise conflict detection)
//! 2. Find connected components via union-find (O(n * alpha(n)))
//! 3. Each component = one group of transitively conflicting transactions

use crate::types::{AccessEntry, Transaction};
use pyde_account::address::Address;
use std::collections::{HashMap, HashSet};

/// A group of conflicting transactions that must execute sequentially.
/// Different groups are independent and can be proven in parallel.
#[derive(Clone, Debug)]
pub struct ExecutionGroup {
    /// Indices into the original transaction list.
    pub tx_indices: Vec<usize>,
}

/// Result of scheduling: conflict groups for parallel proving.
#[derive(Clone, Debug)]
pub struct ExecutionSchedule {
    /// Conflict groups. Each group executes sequentially internally.
    /// Groups are independent and can execute/prove in parallel.
    /// All groups start from the same pre_state_root.
    pub groups: Vec<ExecutionGroup>,
    /// Total number of transactions.
    pub total_txs: usize,
}

impl ExecutionSchedule {
    /// Number of groups (parallel proving units).
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Largest group size (bottleneck for sequential execution within a group).
    pub fn max_group_size(&self) -> usize {
        self.groups.iter().map(|g| g.tx_indices.len()).max().unwrap_or(0)
    }
}

/// Union-Find data structure for connected components.
struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<usize>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            rank: vec![0; n],
        }
    }

    fn find(&mut self, x: usize) -> usize {
        if self.parent[x] != x {
            self.parent[x] = self.find(self.parent[x]); // path compression
        }
        self.parent[x]
    }

    fn union(&mut self, a: usize, b: usize) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return;
        }
        // union by rank
        if self.rank[ra] < self.rank[rb] {
            self.parent[ra] = rb;
        } else if self.rank[ra] > self.rank[rb] {
            self.parent[rb] = ra;
        } else {
            self.parent[rb] = ra;
            self.rank[ra] += 1;
        }
    }
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
    // Transactions with empty access lists are treated as touching EVERYTHING.
    // They must be sequential with all other txs (can't parallelize safely).
    if tx_a.access_list.is_empty() || tx_b.access_list.is_empty() {
        return true;
    }

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

/// Schedule transactions into conflict groups via connected components.
///
/// Finds connected components in the conflict graph using union-find.
/// Each component = one group of transitively conflicting transactions
/// that must execute sequentially. Groups are independent and can be
/// proven in parallel from the same pre_state_root.
pub fn schedule(txs: &[Transaction]) -> ExecutionSchedule {
    let n = txs.len();
    if n == 0 {
        return ExecutionSchedule {
            groups: vec![],
            total_txs: 0,
        };
    }

    // Build connected components via union-find
    let mut uf = UnionFind::new(n);

    for i in 0..n {
        for j in (i + 1)..n {
            if conflicts(&txs[i], &txs[j]) {
                uf.union(i, j);
            }
        }
    }

    // Collect components: root → tx indices
    let mut components: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..n {
        components.entry(uf.find(i)).or_default().push(i);
    }

    // Convert to groups (sorted by first tx index for deterministic order)
    let mut groups: Vec<ExecutionGroup> = components
        .into_values()
        .map(|tx_indices| ExecutionGroup { tx_indices })
        .collect();
    groups.sort_by_key(|g| g.tx_indices[0]);

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
/// Uses connected components — same algorithm as `schedule()`.
pub fn schedule_from_access_lists(access_lists: &[Vec<AccessEntry>]) -> ExecutionSchedule {
    let n = access_lists.len();
    if n == 0 {
        return ExecutionSchedule {
            groups: vec![],
            total_txs: 0,
        };
    }

    let mut uf = UnionFind::new(n);

    for i in 0..n {
        for j in (i + 1)..n {
            if access_lists_conflict(&access_lists[i], &access_lists[j]) {
                uf.union(i, j);
            }
        }
    }

    let mut components: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..n {
        components.entry(uf.find(i)).or_default().push(i);
    }

    let mut groups: Vec<ExecutionGroup> = components
        .into_values()
        .map(|tx_indices| ExecutionGroup { tx_indices })
        .collect();
    groups.sort_by_key(|g| g.tx_indices[0]);

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

    // ========== Conflict detection ==========

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
    fn empty_access_lists_always_conflict() {
        // Txs without access lists are conservatively treated as conflicting
        // because they could access any key at runtime.
        let tx_a = make_tx_with_access(vec![]);
        let tx_b = make_tx_with_access(vec![]);
        assert!(conflicts(&tx_a, &tx_b));
    }

    #[test]
    fn no_conflict_read_read_same_key() {
        let key = [0xAA; 32];
        let tx_a = make_tx_with_access(vec![read_access(0x01, &[key])]);
        let tx_b = make_tx_with_access(vec![read_access(0x01, &[key])]);
        assert!(!conflicts(&tx_a, &tx_b));
    }

    #[test]
    fn conflict_read_write_same_key() {
        let key = [0xAA; 32];
        let tx_a = make_tx_with_access(vec![read_access(0x01, &[key])]);
        let tx_b = make_tx_with_access(vec![write_access(0x01, &[key])]);
        assert!(conflicts(&tx_a, &tx_b));
    }

    #[test]
    fn no_conflict_same_address_different_write_keys() {
        let tx_a = make_tx_with_access(vec![write_access(0x01, &[[0xAA; 32]])]);
        let tx_b = make_tx_with_access(vec![write_access(0x01, &[[0xBB; 32]])]);
        assert!(!conflicts(&tx_a, &tx_b));
    }

    // ========== Connected components grouping ==========

    #[test]
    fn non_conflicting_each_in_own_group() {
        // Non-conflicting txs are independent → each in its own group
        let txs = vec![
            make_tx_with_access(vec![write_access(0x01, &[[0xAA; 32]])]),
            make_tx_with_access(vec![write_access(0x01, &[[0xBB; 32]])]),
            make_tx_with_access(vec![write_access(0x02, &[[0xAA; 32]])]),
        ];

        let schedule = schedule(&txs);
        // Each tx is independent → 3 separate groups (provable in parallel)
        assert_eq!(schedule.group_count(), 3);
    }

    #[test]
    fn two_non_conflicting_separate_groups() {
        let txs = vec![
            make_tx_with_access(vec![write_access(0x01, &[[0x11; 32]])]),
            make_tx_with_access(vec![write_access(0x02, &[[0x22; 32]])]),
        ];

        let schedule = schedule(&txs);
        // Independent → 2 groups (parallel provable)
        assert_eq!(schedule.group_count(), 2);
    }

    #[test]
    fn two_conflicting_same_group() {
        let key = [0xAA; 32];
        let txs = vec![
            make_tx_with_access(vec![write_access(0x01, &[key])]),
            make_tx_with_access(vec![write_access(0x01, &[key])]),
        ];

        let schedule = schedule(&txs);
        // Conflicting → same group (sequential execution)
        assert_eq!(schedule.group_count(), 1);
        assert_eq!(schedule.groups[0].tx_indices, vec![0, 1]);
    }

    #[test]
    fn all_conflicting_single_group() {
        let key = [0xFF; 32];
        let txs: Vec<Transaction> = (0..5)
            .map(|_| make_tx_with_access(vec![write_access(0x01, &[key])]))
            .collect();

        let schedule = schedule(&txs);
        // All conflict on same key → one group (all sequential)
        assert_eq!(schedule.group_count(), 1);
        assert_eq!(schedule.groups[0].tx_indices, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn transitive_conflict_merged() {
        // TX0 conflicts with TX1 (key A)
        // TX1 conflicts with TX2 (key B)
        // TX0 does NOT conflict with TX2 directly
        // But transitively: TX0-TX1-TX2 are all in one component
        let key_a = [0xAA; 32];
        let key_b = [0xBB; 32];
        let txs = vec![
            make_tx_with_access(vec![write_access(0x01, &[key_a])]),         // TX0: writes A
            make_tx_with_access(vec![write_access(0x01, &[key_a, key_b])]),  // TX1: writes A, B
            make_tx_with_access(vec![write_access(0x01, &[key_b])]),         // TX2: writes B
        ];

        let schedule = schedule(&txs);
        // All transitively connected → one group
        assert_eq!(schedule.group_count(), 1);
        assert_eq!(schedule.groups[0].tx_indices, vec![0, 1, 2]);
    }

    #[test]
    fn mixed_conflict_and_independent() {
        let key_shared = [0xAA; 32];
        let txs = vec![
            make_tx_with_access(vec![write_access(0x01, &[key_shared])]),     // TX0: conflicts with TX1
            make_tx_with_access(vec![write_access(0x01, &[key_shared])]),     // TX1: conflicts with TX0
            make_tx_with_access(vec![write_access(0x02, &[[0xBB; 32]])]),     // TX2: independent
            make_tx_with_access(vec![write_access(0x03, &[[0xCC; 32]])]),     // TX3: independent
        ];

        let schedule = schedule(&txs);
        // TX0+TX1 = one group, TX2 = own group, TX3 = own group → 3 groups
        assert_eq!(schedule.group_count(), 3);
        assert_eq!(schedule.groups[0].tx_indices, vec![0, 1]); // conflict group
        assert_eq!(schedule.groups[1].tx_indices, vec![2]);     // independent
        assert_eq!(schedule.groups[2].tx_indices, vec![3]);     // independent
    }

    #[test]
    fn two_separate_conflict_clusters() {
        // Cluster 1: TX0, TX1 conflict on key A
        // Cluster 2: TX2, TX3 conflict on key B
        // Clusters are independent
        let key_a = [0xAA; 32];
        let key_b = [0xBB; 32];
        let txs = vec![
            make_tx_with_access(vec![write_access(0x01, &[key_a])]),  // cluster 1
            make_tx_with_access(vec![write_access(0x01, &[key_a])]),  // cluster 1
            make_tx_with_access(vec![write_access(0x02, &[key_b])]),  // cluster 2
            make_tx_with_access(vec![write_access(0x02, &[key_b])]),  // cluster 2
        ];

        let schedule = schedule(&txs);
        // 2 independent clusters → 2 groups (provable in parallel)
        assert_eq!(schedule.group_count(), 2);
        assert_eq!(schedule.groups[0].tx_indices, vec![0, 1]);
        assert_eq!(schedule.groups[1].tx_indices, vec![2, 3]);
    }

    // ========== Invariants ==========

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

    #[test]
    fn groups_are_disjoint() {
        let key = [0xAA; 32];
        let txs = vec![
            make_tx_with_access(vec![write_access(0x01, &[key])]),
            make_tx_with_access(vec![write_access(0x01, &[key])]),
            make_tx_with_access(vec![write_access(0x02, &[[0xBB; 32]])]),
            make_tx_with_access(vec![write_access(0x03, &[[0xCC; 32]])]),
        ];

        let schedule = schedule(&txs);

        // Verify no cross-group conflicts
        for (i, g1) in schedule.groups.iter().enumerate() {
            for g2 in schedule.groups.iter().skip(i + 1) {
                for &a in &g1.tx_indices {
                    for &b in &g2.tx_indices {
                        assert!(!conflicts(&txs[a], &txs[b]),
                            "tx {} and tx {} conflict but are in different groups", a, b);
                    }
                }
            }
        }
    }

    #[test]
    fn empty_schedule() {
        let schedule = schedule(&[]);
        assert_eq!(schedule.group_count(), 0);
        assert_eq!(schedule.total_txs, 0);
    }

    #[test]
    fn single_tx() {
        let txs = vec![
            make_tx_with_access(vec![write_access(0x01, &[[0xAA; 32]])]),
        ];
        let schedule = schedule(&txs);
        assert_eq!(schedule.group_count(), 1);
        assert_eq!(schedule.groups[0].tx_indices, vec![0]);
    }

    #[test]
    fn empty_access_lists_all_in_one_group() {
        // Txs without access lists conflict with everything → all in one group
        let txs = vec![
            make_tx_with_access(vec![]),
            make_tx_with_access(vec![]),
            make_tx_with_access(vec![]),
        ];
        let schedule = schedule(&txs);
        assert_eq!(schedule.group_count(), 1);
        assert_eq!(schedule.groups[0].tx_indices.len(), 3);
    }
}
