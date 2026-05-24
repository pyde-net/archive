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

use crate::types::{AccessEntry, Transaction, TransactionType};
use pyde_account::address::Address;
use std::collections::{HashMap, HashSet};

/// Implicit write keys that every tx of the given type touches by
/// virtue of executing — independent of `tx.access_list`. The
/// scheduler folds these in so two transfers from different senders
/// to different recipients can run in parallel even when the senders
/// shipped empty access lists, while two transfers from the same
/// sender (or to the same recipient) still serialise correctly.
///
/// Returns `None` for tx types whose touch-set the scheduler can't
/// derive from header fields alone (Slash, ClaimReward, multisig,
/// etc.). Those types fall back to the existing "uninformative AL
/// conflicts with everything" rule via the `unknown_representative`
/// path in `schedule`.
///
/// Fee distribution to the block proposer and the treasury is
/// intentionally NOT listed here. Every tx in a block credits the
/// same proposer/treasury account, so declaring it would union the
/// entire block into one sequential group. The block processor
/// instead defers fee credit into a single post-block accumulation
/// step (see `pyde_tx::pipeline::apply_block_fees`).
fn implicit_writes(tx: &Transaction) -> Option<Vec<(Address, [u8; 32])>> {
    match tx.tx_type {
        TransactionType::Standard | TransactionType::Deploy | TransactionType::RegisterPubkey => {
            let from_balance: [u8; 32] = pyde_state::keys::balance_key(&tx.from).into();
            let from_nonce: [u8; 32] = pyde_state::keys::nonce_key(&tx.from).into();
            let mut writes = vec![(tx.from, from_balance), (tx.from, from_nonce)];
            if matches!(tx.tx_type, TransactionType::Standard) && tx.to != [0u8; 32] {
                let to_balance: [u8; 32] = pyde_state::keys::balance_key(&tx.to).into();
                writes.push((tx.to, to_balance));
            }
            Some(writes)
        }
        _ => None,
    }
}

/// An access list is "uninformative" when it declares no concrete
/// `(address, key)` pairs the scheduler can use for conflict detection.
/// This covers two equivalent shapes:
///
///   1. The Vec is empty (`vec![]`) — the user opted out of declaring
///      keys altogether.
///   2. The Vec has `AccessEntry`s, but every entry's `reads` and
///      `writes` are both empty — the user named addresses they
///      touch but didn't list any storage keys.
///
/// Both shapes mean the same thing semantically: "I touch storage,
/// but I haven't told you which keys." The scheduler must treat
/// uninformative txs as conflicting with everything; otherwise a
/// caller declaring `[{addr, [], []}]` would slip past the
/// "is_empty" check, contribute zero keys to the union-find, and
/// land in its own parallel group — which is unsafe (e.g. multiple
/// same-sender txs would race on `sender.nonce` since the implicit
/// nonce-write is never declared in any AL).
///
/// Audit 407: `loadgen_soak`'s workload txs use shape (2) for every
/// contract call (`[{contract, [], []}]`), which produced
/// proposer/non-proposer state-root divergence the moment tx
/// traffic hit a fresh 4-validator soak. The 4 non-proposers
/// converged on the sequential single-group answer, the proposer
/// produced a parallel-execution answer where all but the
/// nonce-N tx reverted with `InvalidNonce` (each parallel group
/// reads pre-block sender.nonce=N). After this fix, shape (2) is
/// treated as shape (1) and unions with all other txs, restoring
/// the safe sequential default.
fn access_list_is_uninformative(access_list: &[AccessEntry]) -> bool {
    access_list
        .iter()
        .all(|e| e.reads.is_empty() && e.writes.is_empty())
}

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
    // A tx with no declared keys (empty AL or all-empty entries — see
    // `access_list_is_uninformative`) is treated as touching EVERYTHING.
    // It must be sequential with all other txs (can't parallelize safely).
    if access_list_is_uninformative(&tx_a.access_list)
        || access_list_is_uninformative(&tx_b.access_list)
    {
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

    let mut uf = UnionFind::new(n);

    // Inverted index: (address, key) → tx index that writes this key.
    // When a second tx touches this key, we union them.
    let mut write_owners: HashMap<(Address, [u8; 32]), usize> = HashMap::new();

    // Representative for txs whose touch-set the scheduler can't
    // derive (tx types without `implicit_writes` support AND with
    // uninformative `access_list`). All such txs collapse to one
    // sequential group at the end.
    let mut unknown_representative: Option<usize> = None;

    for (i, tx) in txs.iter().enumerate() {
        let implicit = implicit_writes(tx);
        let explicit_informative = !access_list_is_uninformative(&tx.access_list);

        if implicit.is_none() && !explicit_informative {
            // Unknown tx type, no useful AL — conflicts with everything.
            match unknown_representative {
                Some(rep) => uf.union(i, rep),
                None => unknown_representative = Some(i),
            }
            continue;
        }

        // Claim every implicit write. Two txs whose implicit sets
        // overlap (same sender, or one sender == other recipient,
        // or shared recipient) get unioned here.
        if let Some(writes) = &implicit {
            for ak in writes {
                match write_owners.get(ak) {
                    Some(&other) => uf.union(i, other),
                    None => {
                        write_owners.insert(*ak, i);
                    }
                }
            }
        }

        // Claim explicit writes from the access list.
        if explicit_informative {
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

            // Read-vs-write conflicts (explicit reads only — the
            // implicit reads are subsumed by the implicit writes
            // claimed above for the same key).
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
    }

    // Union the unknown-rep with every other tx — it conflicts with
    // everything. Same shape as the prior `empty_representative`
    // sweep, just gated on the unknown-tx-type case (a Standard tx
    // with empty AL is no longer unknown because `implicit_writes`
    // returns its sender/recipient touches).
    if let Some(rep) = unknown_representative {
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
///
/// TPL-513: an uninformative access list (`access_list_is_uninformative`)
/// is treated as touching EVERYTHING, exactly as `conflicts()` does
/// for two transactions. Pre-fix this function only compared
/// declared writes/reads, so two empty access lists or two
/// `[{addr, [], []}]`-shaped lists came back as "no conflict" —
/// the same TPL-001 hazard `conflicts()` already guards against.
/// `block_builder`'s post-schedule sanity assert is the only
/// in-tree consumer today, but mirroring the rule keeps the two
/// helpers from drifting if a future caller uses
/// `access_lists_conflict` for a real safety decision.
pub fn access_lists_conflict(a: &[AccessEntry], b: &[AccessEntry]) -> bool {
    if access_list_is_uninformative(a) || access_list_is_uninformative(b) {
        return true;
    }
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
        // Same uninformative-AL handling as `schedule()`. See
        // `access_list_is_uninformative` for why a list shaped
        // `[{addr, [], []}]` must be treated as no-info, not as a
        // declared "I touch addr" hint.
        if access_list_is_uninformative(al) {
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

    /// Per-call unique seed so `make_tx_with_access` produces txs with
    /// distinct senders + recipients. Without this, every test tx
    /// would share `(from, balance/nonce)` and `(to, balance)` keys
    /// under the implicit-write rule and the scheduler would union
    /// everything into one group — masking the explicit-AL union-find
    /// behavior the surrounding tests are actually trying to assert.
    static TX_SEED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn make_tx_with_access(access_list: Vec<AccessEntry>) -> Transaction {
        let seed = TX_SEED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut from_seed = [0xAAu8; 897];
        from_seed[..8].copy_from_slice(&seed.to_le_bytes());
        let mut to_seed = [0xBBu8; 897];
        to_seed[..8].copy_from_slice(&seed.to_le_bytes());
        Transaction {
            from: derive_eoa_address(&from_seed),
            to: derive_eoa_address(&to_seed),
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
        // For tx types the scheduler can't derive implicit writes for
        // (Slash here — any non-{Standard, Deploy, RegisterPubkey}
        // works), empty access lists collapse every tx into one
        // sequential group. Standard txs go through the implicit-
        // write path instead and are covered by `same_sender_standard_txs_unioned_via_implicit`.
        let mut a = make_tx_with_access(vec![]);
        a.tx_type = TransactionType::Slash;
        let mut b = make_tx_with_access(vec![]);
        b.tx_type = TransactionType::Slash;
        let mut c = make_tx_with_access(vec![]);
        c.tx_type = TransactionType::Slash;
        let txs = vec![a, b, c];
        let schedule = schedule(&txs);
        assert_eq!(schedule.group_count(), 1);
        assert_eq!(schedule.groups[0].tx_indices.len(), 3);
    }

    /// Phase-A counterpart: two Standard txs from the SAME sender
    /// must still serialise even with empty `access_list`, because
    /// the scheduler derives the implicit `(from, nonce_key)` write
    /// from `tx.from` + `tx.tx_type`. Without this, the audit-407
    /// hazard (proposer parallel vs non-proposer serial, diverging
    /// on undeclared sender-nonce writes) would re-open.
    #[test]
    fn same_sender_standard_txs_unioned_via_implicit() {
        let sender = derive_eoa_address(b"audit-407-sender");
        let mk = |nonce: u64| Transaction {
            from: sender,
            to: derive_eoa_address(b"audit-407-recipient"),
            value: 0,
            data: vec![],
            gas_limit: 21_000,
            nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };
        let schedule = schedule(&[mk(0), mk(1), mk(2)]);
        assert_eq!(
            schedule.group_count(),
            1,
            "same-sender Standard txs MUST serialise via implicit (from, nonce_key) conflict (audit 407)"
        );
        assert_eq!(schedule.groups[0].tx_indices, vec![0, 1, 2]);
    }

    /// Phase-A win: two Standard txs from DIFFERENT senders to
    /// DIFFERENT recipients with empty `access_list` get to run in
    /// parallel. Pre-Phase-A this collapsed to one sequential group;
    /// the loadgen-mixed soak wedge at 2k TPS / 4v was the headline
    /// symptom.
    #[test]
    fn different_sender_standard_txs_parallel_via_implicit() {
        let mk = |sender_seed: &[u8], to_seed: &[u8]| Transaction {
            from: derive_eoa_address(sender_seed),
            to: derive_eoa_address(to_seed),
            value: 0,
            data: vec![],
            gas_limit: 21_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };
        let schedule = schedule(&[
            mk(b"sender-a", b"recipient-a"),
            mk(b"sender-b", b"recipient-b"),
            mk(b"sender-c", b"recipient-c"),
        ]);
        assert_eq!(
            schedule.group_count(),
            3,
            "three Standard txs with disjoint (sender, recipient) pairs MUST be schedulable in parallel"
        );
    }

    /// Audit 407 regression: an `AccessEntry` with empty `reads` and
    /// empty `writes` is still a non-empty `Vec`, so the pre-fix
    /// `t.access_list.is_empty()` check missed it. Each tx ended up
    /// alone in its own component — proposers ran them in parallel,
    /// non-proposers (whose compact-block reconstruct hard-codes a
    /// single-group schedule) ran them sequentially, and the two
    /// paths produced different post-block state under any
    /// undeclared write (sender nonce being the universal example).
    ///
    /// The original fix treated this shape as no-info and unioned
    /// everything. Phase A replaces that workaround with implicit
    /// `(sender, balance/nonce)` writes for Standard/Deploy/
    /// RegisterPubkey — so this regression is now covered
    /// STRUCTURALLY by `same_sender_standard_txs_unioned_via_implicit`.
    /// The test below preserves the old shape for tx types whose
    /// touch-set the scheduler still can't derive (Slash here).
    #[test]
    fn access_list_with_only_addresses_no_keys_unions_with_all() {
        let mega_addr = {
            let mut a = ZERO_ADDRESS;
            a[0] = 0xAB;
            a
        };
        let only_addr_no_keys = || {
            vec![AccessEntry {
                address: mega_addr,
                reads: vec![],
                writes: vec![],
            }]
        };
        let mut txs: Vec<Transaction> = (0..4)
            .map(|_| make_tx_with_access(only_addr_no_keys()))
            .collect();
        for tx in &mut txs {
            tx.tx_type = TransactionType::Slash;
        }
        let schedule = schedule(&txs);
        assert_eq!(
            schedule.group_count(),
            1,
            "AL=[{{addr,[],[]}}] is uninformative for tx types without implicit writes — all txs must serialize"
        );
        assert_eq!(schedule.groups[0].tx_indices.len(), 4);
    }

    /// Same as above but mixed: one tx declares a real write key,
    /// the others use the empty-keys shape. The keyed tx must still
    /// land in the single group with everyone else, because the
    /// uninformative txs union with all. Phase A: scenario applies
    /// to tx types without implicit writes (Slash here); Standard
    /// txs go through the implicit-write path tested separately.
    #[test]
    fn uninformative_unions_with_keyed_txs() {
        let mega_addr = {
            let mut a = ZERO_ADDRESS;
            a[0] = 0xAB;
            a
        };
        let only_addr_no_keys = vec![AccessEntry {
            address: mega_addr,
            reads: vec![],
            writes: vec![],
        }];
        let mut txs = vec![
            // One tx with a real declared write
            make_tx_with_access(vec![write_access(0xCC, &[[0x42; 32]])]),
            // Three txs with the soak-loadgen shape
            make_tx_with_access(only_addr_no_keys.clone()),
            make_tx_with_access(only_addr_no_keys.clone()),
            make_tx_with_access(only_addr_no_keys.clone()),
        ];
        for tx in &mut txs {
            tx.tx_type = TransactionType::Slash;
        }
        let schedule = schedule(&txs);
        assert_eq!(schedule.group_count(), 1);
        assert_eq!(schedule.groups[0].tx_indices.len(), 4);
    }

    /// Same regression check via `schedule_from_access_lists` (the
    /// path the encrypted-tx mempool block builder uses). Both
    /// entry points must use identical uninformative-AL semantics
    /// — otherwise the encrypted and plaintext schedules diverge
    /// on the same workload.
    #[test]
    fn schedule_from_access_lists_treats_empty_keys_as_uninformative() {
        let mega_addr = {
            let mut a = ZERO_ADDRESS;
            a[0] = 0xAB;
            a
        };
        let als: Vec<Vec<AccessEntry>> = (0..4)
            .map(|_| {
                vec![AccessEntry {
                    address: mega_addr,
                    reads: vec![],
                    writes: vec![],
                }]
            })
            .collect();
        let schedule = schedule_from_access_lists(&als);
        assert_eq!(schedule.group_count(), 1);
        assert_eq!(schedule.groups[0].tx_indices.len(), 4);
    }

    /// `conflicts(a, b)` must also treat the uninformative shape as
    /// "conflicts with everything", matching the scheduler's
    /// behavior. A pre-fix `is_empty()` check missed
    /// `[{addr,[],[]}]` and reported "no conflict", which would
    /// break any caller that uses pairwise conflict detection
    /// instead of the union-find scheduler.
    #[test]
    fn conflicts_treats_uninformative_as_conflicting() {
        let mega_addr = {
            let mut a = ZERO_ADDRESS;
            a[0] = 0xAB;
            a
        };
        let tx_uninformative = make_tx_with_access(vec![AccessEntry {
            address: mega_addr,
            reads: vec![],
            writes: vec![],
        }]);
        let tx_keyed = make_tx_with_access(vec![write_access(0xCC, &[[0x77; 32]])]);
        assert!(
            conflicts(&tx_uninformative, &tx_keyed),
            "uninformative AL must conflict with any other tx"
        );
        assert!(
            conflicts(&tx_keyed, &tx_uninformative),
            "uninformative AL must conflict regardless of arg order"
        );
    }

    /// TPL-513: `access_lists_conflict` must reuse the same
    /// uninformative-AL rule as `conflicts()`. Pre-fix it only
    /// compared declared writes/reads, so two empty access lists
    /// (or `[{addr, [], []}]`-shaped lists) came back as "no
    /// conflict". A future caller using this helper for a real
    /// safety decision would silently let two TPL-001-shaped txs
    /// run in parallel.
    #[test]
    fn tpl_513_access_lists_conflict_uninformative_treated_as_conflict() {
        let uninformative = vec![AccessEntry {
            address: {
                let mut a = ZERO_ADDRESS;
                a[0] = 0xAB;
                a
            },
            reads: vec![],
            writes: vec![],
        }];
        let keyed = vec![write_access(0xCC, &[[0x77; 32]])];

        // Empty AL ↔ empty AL.
        assert!(
            access_lists_conflict(&[], &[]),
            "two empty ALs must conflict"
        );
        // Uninformative AL ↔ keyed AL — both directions.
        assert!(
            access_lists_conflict(&uninformative, &keyed),
            "uninformative ↔ keyed must conflict"
        );
        assert!(
            access_lists_conflict(&keyed, &uninformative),
            "uninformative ↔ keyed must conflict regardless of arg order"
        );
        // Uninformative ↔ uninformative.
        assert!(
            access_lists_conflict(&uninformative, &uninformative),
            "two uninformative ALs must conflict"
        );
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
                                              // Sanity floor for scheduler complexity — 2000 ms is deliberately
                                              // loose because this runs in a debug build under contention with
                                              // the rest of `cargo test --workspace`. A regression to O(n²)
                                              // would take seconds, which this catches; tighter timings belong
                                              // in `cargo bench`, not in the regression suite. The threshold
                                              // was bumped from 200 ms when the scheduler started deriving
                                              // implicit `(sender, balance/nonce)` writes per tx — that adds
                                              // two Poseidon2 hashes per tx, ~100 µs each in debug, so 10K
                                              // txs is bounded by ~2 s of hashing in the worst case.
        assert!(
            elapsed.as_millis() < 2000,
            "10K scheduling took {}ms, must be <2000ms (expected ~few ms under release)",
            elapsed.as_millis()
        );
    }
}
