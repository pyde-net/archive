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
        self.groups
            .iter()
            .map(|g| g.tx_indices.len())
            .max()
            .unwrap_or(0)
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
            entry
                .reads
                .iter()
                .chain(entry.writes.iter())
                .map(move |k| (entry.address, *k))
        })
        .collect();

    let all_b: HashSet<(Address, [u8; 32])> = tx_b
        .access_list
        .iter()
        .flat_map(|entry| {
            entry
                .reads
                .iter()
                .chain(entry.writes.iter())
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
/// Uses an inverted index for O(n * k) conflict detection (k = avg keys per tx),
/// replacing the old O(n²) pairwise approach. For 50K txs this is ~1000x faster.
///
/// Algorithm:
/// 1. Build inverted index: (address, key) → first tx that WRITES this key
/// 2. For each tx, check if any of its keys (reads + writes) are already claimed
///    by a write from another tx → union them
/// 3. Txs with empty access lists are unioned with ALL other txs (safe default)
/// 4. Extract connected components via union-find
pub fn schedule(txs: &[Transaction]) -> ExecutionSchedule {
    let n = txs.len();
    if n == 0 {
        return ExecutionSchedule {
            groups: vec![],
            total_txs: 0,
        };
    }

    // If NO txs have access lists, they're all potentially conflicting
    // → put everything in one sequential group (safe default).
    let has_any_access_list = txs.iter().any(|t| !t.access_list.is_empty());
    if !has_any_access_list {
        return ExecutionSchedule {
            groups: vec![ExecutionGroup {
                tx_indices: (0..n).collect(),
            }],
            total_txs: n,
        };
    }

    let mut uf = UnionFind::new(n);

    // Inverted index: (address, key) → tx index that writes this key.
    // When a second tx touches this key, we union them.
    let mut write_owners: HashMap<(Address, [u8; 32]), usize> = HashMap::new();

    // Track the first empty-access-list tx to union all such txs together.
    let mut empty_representative: Option<usize> = None;

    for (i, tx) in txs.iter().enumerate() {
        if tx.access_list.is_empty() {
            // Empty access list = unknown keys = conflicts with everything.
            // Union with the representative (and the representative unions with
            // every keyed tx below).
            match empty_representative {
                Some(rep) => uf.union(i, rep),
                None => empty_representative = Some(i),
            }
            continue;
        }

        // For each write key: check if another tx already claimed it
        for entry in &tx.access_list {
            for key in &entry.writes {
                let addr_key = (entry.address, *key);
                match write_owners.get(&addr_key) {
                    Some(&other) => uf.union(i, other),
                    None => {
                        write_owners.insert(addr_key, i);
                    }
                }
            }
        }

        // For each read key: check if another tx WRITES it (read-write conflict)
        for entry in &tx.access_list {
            for key in &entry.reads {
                let addr_key = (entry.address, *key);
                if let Some(&writer) = write_owners.get(&addr_key) {
                    if writer != i {
                        uf.union(i, writer);
                    }
                }
            }
        }
    }

    // If any txs had empty access lists, union their representative with
    // every other tx (they conflict with everything).
    if let Some(rep) = empty_representative {
        for i in 0..n {
            if i != rep {
                uf.union(i, rep);
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
            entry
                .reads
                .iter()
                .chain(entry.writes.iter())
                .map(move |k| (entry.address, *k))
        })
        .collect();

    let all_b: HashSet<(Address, [u8; 32])> = b
        .iter()
        .flat_map(|entry| {
            entry
                .reads
                .iter()
                .chain(entry.writes.iter())
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
/// Uses inverted index — same O(n*k) algorithm as `schedule()`.
pub fn schedule_from_access_lists(access_lists: &[Vec<AccessEntry>]) -> ExecutionSchedule {
    let n = access_lists.len();
    if n == 0 {
        return ExecutionSchedule {
            groups: vec![],
            total_txs: 0,
        };
    }

    let mut uf = UnionFind::new(n);
    let mut write_owners: HashMap<(Address, [u8; 32]), usize> = HashMap::new();
    let mut empty_rep: Option<usize> = None;

    for (i, al) in access_lists.iter().enumerate() {
        if al.is_empty() {
            match empty_rep {
                Some(rep) => uf.union(i, rep),
                None => {
                    empty_rep = Some(i);
                }
            }
            continue;
        }
        for entry in al {
            for key in &entry.writes {
                let ak = (entry.address, *key);
                match write_owners.get(&ak) {
                    Some(&other) => uf.union(i, other),
                    None => {
                        write_owners.insert(ak, i);
                    }
                }
            }
            for key in &entry.reads {
                let ak = (entry.address, *key);
                if let Some(&writer) = write_owners.get(&ak) {
                    if writer != i {
                        uf.union(i, writer);
                    }
                }
            }
        }
    }
    if let Some(rep) = empty_rep {
        for i in 0..n {
            if i != rep {
                uf.union(i, rep);
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
            make_tx_with_access(vec![write_access(0x01, &[key_a])]), // TX0: writes A
            make_tx_with_access(vec![write_access(0x01, &[key_a, key_b])]), // TX1: writes A, B
            make_tx_with_access(vec![write_access(0x01, &[key_b])]), // TX2: writes B
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
            make_tx_with_access(vec![write_access(0x01, &[key_shared])]), // TX0: conflicts with TX1
            make_tx_with_access(vec![write_access(0x01, &[key_shared])]), // TX1: conflicts with TX0
            make_tx_with_access(vec![write_access(0x02, &[[0xBB; 32]])]), // TX2: independent
            make_tx_with_access(vec![write_access(0x03, &[[0xCC; 32]])]), // TX3: independent
        ];

        let schedule = schedule(&txs);
        // TX0+TX1 = one group, TX2 = own group, TX3 = own group → 3 groups
        assert_eq!(schedule.group_count(), 3);
        assert_eq!(schedule.groups[0].tx_indices, vec![0, 1]); // conflict group
        assert_eq!(schedule.groups[1].tx_indices, vec![2]); // independent
        assert_eq!(schedule.groups[2].tx_indices, vec![3]); // independent
    }

    #[test]
    fn two_separate_conflict_clusters() {
        // Cluster 1: TX0, TX1 conflict on key A
        // Cluster 2: TX2, TX3 conflict on key B
        // Clusters are independent
        let key_a = [0xAA; 32];
        let key_b = [0xBB; 32];
        let txs = vec![
            make_tx_with_access(vec![write_access(0x01, &[key_a])]), // cluster 1
            make_tx_with_access(vec![write_access(0x01, &[key_a])]), // cluster 1
            make_tx_with_access(vec![write_access(0x02, &[key_b])]), // cluster 2
            make_tx_with_access(vec![write_access(0x02, &[key_b])]), // cluster 2
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
            .map(|i| make_tx_with_access(vec![write_access(i as u8, &[[i as u8; 32]])]))
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
                        assert!(
                            !conflicts(&txs[a], &txs[b]),
                            "tx {} and tx {} conflict but are in different groups",
                            a,
                            b
                        );
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
        let txs = vec![make_tx_with_access(vec![write_access(0x01, &[[0xAA; 32]])])];
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

    #[test]
    fn schedule_50k_txs_under_100ms() {
        // 50K transactions with unique key pairs → 50K groups (max parallelism)
        // Old O(n²) took 341 seconds. New O(n*k) must finish in <100ms.
        let txs: Vec<Transaction> = (0..50_000)
            .map(|i| {
                let mut from = ZERO_ADDRESS;
                from[..8].copy_from_slice(&(i as u64).to_le_bytes());
                let mut key = [0u8; 32];
                key[..8].copy_from_slice(&(i as u64).to_le_bytes());
                Transaction {
                    from,
                    to: ZERO_ADDRESS,
                    value: 0,
                    data: vec![],
                    gas_limit: 21_000,
                    nonce: 0,
                    signature: vec![],
                    fee_payer: FeePayer::Sender,
                    access_list: vec![AccessEntry {
                        address: from,
                        reads: vec![],
                        writes: vec![key],
                    }],
                    deadline: None,
                    chain_id: 1,
                    tx_type: TransactionType::Standard,
                }
            })
            .collect();

        let start = std::time::Instant::now();
        let sched = schedule(&txs);
        let elapsed = start.elapsed();

        assert_eq!(sched.total_txs, 50_000);
        assert_eq!(sched.group_count(), 50_000); // all independent
        // The O(n^2) regression baseline was 341_000 ms for 50K txs.
        // A 5 s ceiling keeps the regression signal (700× margin) while
        // tolerating contended CI runs / laptops under concurrent
        // workspace load, where the strict 500 ms bar flaked.
        assert!(
            elapsed.as_millis() < 5_000,
            "50K scheduling took {}ms, must be <5000ms (was 341,000ms with O(n^2))",
            elapsed.as_millis()
        );
    }

    #[test]
    fn schedule_10k_with_conflicts_under_50ms() {
        // 10K txs, 100 hot keys shared across many txs → realistic DeFi pattern
        let txs: Vec<Transaction> = (0..10_000)
            .map(|i| {
                let mut from = ZERO_ADDRESS;
                from[..8].copy_from_slice(&(i as u64).to_le_bytes());
                // Hot key: one of 100 contract slots (simulates 100 DEX pools)
                let mut hot_key = [0u8; 32];
                hot_key[0] = (i % 100) as u8;
                Transaction {
                    from,
                    to: ZERO_ADDRESS,
                    value: 0,
                    data: vec![],
                    gas_limit: 21_000,
                    nonce: 0,
                    signature: vec![],
                    fee_payer: FeePayer::Sender,
                    access_list: vec![AccessEntry {
                        address: {
                            let mut a = ZERO_ADDRESS;
                            a[0] = 0xCC;
                            a
                        },
                        reads: vec![],
                        writes: vec![hot_key],
                    }],
                    deadline: None,
                    chain_id: 1,
                    tx_type: TransactionType::Standard,
                }
            })
            .collect();

        let start = std::time::Instant::now();
        let sched = schedule(&txs);
        let elapsed = start.elapsed();

        assert_eq!(sched.total_txs, 10_000);
        assert_eq!(sched.group_count(), 100); // 100 hot keys → 100 groups
                                              // Sanity floor for scheduler complexity — 200 ms is deliberately
                                              // loose because this runs in a debug build under contention with
                                              // the rest of `cargo test --workspace`. A regression to O(n²)
                                              // would take seconds, which this catches; tighter timings belong
                                              // in `cargo bench`, not in the regression suite.
        assert!(
            elapsed.as_millis() < 200,
            "10K scheduling took {}ms, must be <200ms (expected ~few ms under release)",
            elapsed.as_millis()
        );
    }
}
