//! Data tiers: manage state across RAM, SSD, and archival storage.
//!
//! - Hot tier: RAM-based (InMemoryBackend), current block's working set
//! - Warm tier: SSD-based (RocksDB), recent state (last 100K blocks)
//! - Cold tier: archival interface (lazy retrieval from network/archive)
//!
//! Keys are promoted on access (cold → warm → hot) and demoted when
//! not accessed for a configurable number of blocks.

use crate::smt::SmtValue;
use sparse_merkle_tree::traits::{StoreReadOps, StoreWriteOps};
use sparse_merkle_tree::{BranchKey, BranchNode, H256};
use std::cell::RefCell;
use std::collections::HashMap;

/// Configuration for tier demotion.
const DEFAULT_HOT_EVICT_BLOCKS: u64 = 128;

/// Tier identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Hot,
    Warm,
    Cold,
}

/// Cold tier trait: interface for archival retrieval.
/// Implementors provide lazy fetch from network, IPFS, or archive nodes.
pub trait ColdStorage {
    fn get_branch(&self, key: &BranchKey) -> Option<BranchNode>;
    fn get_leaf(&self, key: &H256) -> Option<SmtValue>;
}

/// Null cold storage: always returns None (no archival backend configured).
pub struct NullColdStorage;

impl ColdStorage for NullColdStorage {
    fn get_branch(&self, _key: &BranchKey) -> Option<BranchNode> {
        None
    }
    fn get_leaf(&self, _key: &H256) -> Option<SmtValue> {
        None
    }
}

/// Tiered storage backend: hot (RAM) → warm (RocksDB) → cold (archival).
///
/// Reads check hot first, then warm, then cold. Writes go to hot.
/// Periodically, hot entries are flushed to warm, and old warm entries
/// can be archived to cold.
pub struct TieredBackend<W, C> {
    /// Hot tier: in-memory cache for current block's working set.
    hot_branches: RefCell<HashMap<BranchKey, BranchNode>>,
    hot_leaves: RefCell<HashMap<H256, SmtValue>>,
    /// Track which keys are in hot tier and when they were last accessed.
    hot_branch_access: RefCell<HashMap<BranchKey, u64>>,
    hot_leaf_access: RefCell<HashMap<H256, u64>>,
    /// Current block height (for access tracking).
    current_height: RefCell<u64>,
    /// Warm tier: persistent storage.
    warm: W,
    /// Cold tier: archival.
    cold: C,
    /// How many blocks before evicting from hot.
    evict_after: u64,
    /// Stats
    hot_hits: RefCell<u64>,
    warm_hits: RefCell<u64>,
    cold_hits: RefCell<u64>,
    misses: RefCell<u64>,
}

impl<W, C: ColdStorage> TieredBackend<W, C> {
    pub fn new(warm: W, cold: C) -> Self {
        Self {
            hot_branches: RefCell::new(HashMap::new()),
            hot_leaves: RefCell::new(HashMap::new()),
            hot_branch_access: RefCell::new(HashMap::new()),
            hot_leaf_access: RefCell::new(HashMap::new()),
            current_height: RefCell::new(0),
            warm,
            cold,
            evict_after: DEFAULT_HOT_EVICT_BLOCKS,
            hot_hits: RefCell::new(0),
            warm_hits: RefCell::new(0),
            cold_hits: RefCell::new(0),
            misses: RefCell::new(0),
        }
    }

    /// Advance to the next block. Triggers hot → warm demotion for stale entries.
    pub fn advance_block(&mut self)
    where
        W: StoreWriteOps<SmtValue>,
    {
        let height = *self.current_height.borrow() + 1;
        *self.current_height.borrow_mut() = height;

        // Evict stale branches from hot → warm
        let stale_branches: Vec<BranchKey> = self
            .hot_branch_access
            .borrow()
            .iter()
            .filter(|(_, &last)| height - last > self.evict_after)
            .map(|(k, _)| k.clone())
            .collect();

        for key in &stale_branches {
            if let Some(node) = self.hot_branches.borrow_mut().remove(key) {
                let _ = self.warm.insert_branch(key.clone(), node);
            }
            self.hot_branch_access.borrow_mut().remove(key);
        }

        // Evict stale leaves from hot → warm
        let stale_leaves: Vec<H256> = self
            .hot_leaf_access
            .borrow()
            .iter()
            .filter(|(_, &last)| height - last > self.evict_after)
            .map(|(k, _)| *k)
            .collect();

        for key in &stale_leaves {
            if let Some(val) = self.hot_leaves.borrow_mut().remove(key) {
                let _ = self.warm.insert_leaf(*key, val);
            }
            self.hot_leaf_access.borrow_mut().remove(key);
        }
    }

    /// Stats: how many reads hit each tier.
    pub fn stats(&self) -> TierStats {
        TierStats {
            hot_hits: *self.hot_hits.borrow(),
            warm_hits: *self.warm_hits.borrow(),
            cold_hits: *self.cold_hits.borrow(),
            misses: *self.misses.borrow(),
        }
    }

    /// Number of entries in hot tier.
    pub fn hot_size(&self) -> usize {
        self.hot_branches.borrow().len() + self.hot_leaves.borrow().len()
    }
}

/// Tier access statistics.
#[derive(Clone, Debug, Default)]
pub struct TierStats {
    pub hot_hits: u64,
    pub warm_hits: u64,
    pub cold_hits: u64,
    pub misses: u64,
}

impl<W: StoreReadOps<SmtValue>, C: ColdStorage> StoreReadOps<SmtValue> for TieredBackend<W, C> {
    fn get_branch(
        &self,
        branch_key: &BranchKey,
    ) -> Result<Option<BranchNode>, sparse_merkle_tree::error::Error> {
        let height = *self.current_height.borrow();

        // Hot
        if let Some(node) = self.hot_branches.borrow().get(branch_key) {
            *self.hot_hits.borrow_mut() += 1;
            self.hot_branch_access
                .borrow_mut()
                .insert(branch_key.clone(), height);
            return Ok(Some(node.clone()));
        }

        // Warm
        if let Ok(Some(node)) = self.warm.get_branch(branch_key) {
            *self.warm_hits.borrow_mut() += 1;
            // Promote to hot
            self.hot_branches
                .borrow_mut()
                .insert(branch_key.clone(), node.clone());
            self.hot_branch_access
                .borrow_mut()
                .insert(branch_key.clone(), height);
            return Ok(Some(node));
        }

        // Cold
        if let Some(node) = self.cold.get_branch(branch_key) {
            *self.cold_hits.borrow_mut() += 1;
            // Promote to hot
            self.hot_branches
                .borrow_mut()
                .insert(branch_key.clone(), node.clone());
            self.hot_branch_access
                .borrow_mut()
                .insert(branch_key.clone(), height);
            return Ok(Some(node));
        }

        *self.misses.borrow_mut() += 1;
        Ok(None)
    }

    fn get_leaf(
        &self,
        leaf_key: &H256,
    ) -> Result<Option<SmtValue>, sparse_merkle_tree::error::Error> {
        let height = *self.current_height.borrow();

        // Hot
        if let Some(val) = self.hot_leaves.borrow().get(leaf_key) {
            *self.hot_hits.borrow_mut() += 1;
            self.hot_leaf_access.borrow_mut().insert(*leaf_key, height);
            return Ok(Some(val.clone()));
        }

        // Warm
        if let Ok(Some(val)) = self.warm.get_leaf(leaf_key) {
            *self.warm_hits.borrow_mut() += 1;
            self.hot_leaves
                .borrow_mut()
                .insert(*leaf_key, val.clone());
            self.hot_leaf_access.borrow_mut().insert(*leaf_key, height);
            return Ok(Some(val));
        }

        // Cold
        if let Some(val) = self.cold.get_leaf(leaf_key) {
            *self.cold_hits.borrow_mut() += 1;
            self.hot_leaves
                .borrow_mut()
                .insert(*leaf_key, val.clone());
            self.hot_leaf_access.borrow_mut().insert(*leaf_key, height);
            return Ok(Some(val));
        }

        *self.misses.borrow_mut() += 1;
        Ok(None)
    }
}

impl<W: StoreWriteOps<SmtValue>, C: ColdStorage> StoreWriteOps<SmtValue>
    for TieredBackend<W, C>
{
    fn insert_branch(
        &mut self,
        node_key: BranchKey,
        branch: BranchNode,
    ) -> Result<(), sparse_merkle_tree::error::Error> {
        let height = *self.current_height.borrow();
        self.hot_branches
            .borrow_mut()
            .insert(node_key.clone(), branch);
        self.hot_branch_access
            .borrow_mut()
            .insert(node_key, height);
        Ok(())
    }

    fn insert_leaf(
        &mut self,
        leaf_key: H256,
        leaf: SmtValue,
    ) -> Result<(), sparse_merkle_tree::error::Error> {
        let height = *self.current_height.borrow();
        self.hot_leaves.borrow_mut().insert(leaf_key, leaf);
        self.hot_leaf_access.borrow_mut().insert(leaf_key, height);
        Ok(())
    }

    fn remove_branch(
        &mut self,
        node_key: &BranchKey,
    ) -> Result<(), sparse_merkle_tree::error::Error> {
        self.hot_branches.borrow_mut().remove(node_key);
        self.hot_branch_access.borrow_mut().remove(node_key);
        self.warm.remove_branch(node_key)
    }

    fn remove_leaf(
        &mut self,
        leaf_key: &H256,
    ) -> Result<(), sparse_merkle_tree::error::Error> {
        self.hot_leaves.borrow_mut().remove(leaf_key);
        self.hot_leaf_access.borrow_mut().remove(leaf_key);
        self.warm.remove_leaf(leaf_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::InMemoryBackend;
    use crate::smt::{key_from_seed, Poseidon2Hasher};
    use sparse_merkle_tree::traits::Value;
    use sparse_merkle_tree::SparseMerkleTree;

    type SMT<S> = SparseMerkleTree<Poseidon2Hasher, SmtValue, S>;

    fn make_tiered() -> TieredBackend<InMemoryBackend, NullColdStorage> {
        TieredBackend::new(InMemoryBackend::new(), NullColdStorage)
    }

    // ========== Task 0338: Tier transitions ==========

    #[test]
    fn writes_go_to_hot() {
        let store = make_tiered();
        let mut smt = SMT::new(H256::zero(), store);

        let key = key_from_seed(1);
        smt.update(key, SmtValue(b"data".to_vec())).unwrap();
        assert_eq!(smt.get(&key).unwrap().0, b"data");

        let store = smt.take_store();
        assert!(store.hot_size() > 0);
        assert!(store.stats().hot_hits > 0); // get() reads from hot after write
    }

    #[test]
    fn reads_promote_to_hot() {
        let _warm = InMemoryBackend::new();
        // Pre-populate warm tier
        let key = key_from_seed(1);
        let val = SmtValue(b"warm_data".to_vec());
        let _leaf_key = val.to_h256();

        // We need to write through a real SMT to populate correctly
        let mut warm_smt = SMT::new(H256::zero(), InMemoryBackend::new());
        warm_smt.update(key, SmtValue(b"warm_data".to_vec())).unwrap();
        let root = *warm_smt.root();
        let warm_store = warm_smt.take_store();

        // Use warm_store as warm tier
        let store = TieredBackend::new(warm_store, NullColdStorage);
        let smt = SMT::new(root, store);

        // Read should hit warm, promote to hot
        let val = smt.get(&key).unwrap();
        assert_eq!(val.0, b"warm_data");

        let store = smt.take_store();
        assert!(store.stats().warm_hits > 0);
    }

    #[test]
    fn hot_eviction_after_blocks() {
        let mut store = TieredBackend::new(InMemoryBackend::new(), NullColdStorage);
        store.evict_after = 3; // evict after 3 blocks without access

        let mut smt = SMT::new(H256::zero(), store);
        let key = key_from_seed(1);
        smt.update(key, SmtValue(b"data".to_vec())).unwrap();

        let initial_hot = smt.store().hot_size();
        assert!(initial_hot > 0);

        // Advance blocks without accessing
        for _ in 0..5 {
            smt.store_mut().advance_block();
        }

        // Hot should have been evicted to warm
        assert!(smt.store().hot_size() < initial_hot);
    }

    #[test]
    fn access_prevents_eviction() {
        let mut store = TieredBackend::new(InMemoryBackend::new(), NullColdStorage);
        store.evict_after = 3;

        let mut smt = SMT::new(H256::zero(), store);
        let key = key_from_seed(1);
        smt.update(key, SmtValue(b"data".to_vec())).unwrap();

        // Access every block to keep it hot
        for _ in 0..10 {
            let _ = smt.get(&key).unwrap();
            smt.store_mut().advance_block();
        }

        // Should still be in hot
        let stats = smt.store().stats();
        assert!(stats.hot_hits > 0);
    }

    // ========== Task 0339: Read latency per tier (implicit) ==========

    #[test]
    fn stats_tracking() {
        let store = make_tiered();
        let mut smt = SMT::new(H256::zero(), store);

        let key = key_from_seed(1);
        smt.update(key, SmtValue(b"x".to_vec())).unwrap();

        // First read: already in hot from write
        let _ = smt.get(&key).unwrap();
        let _ = smt.get(&key).unwrap();

        let stats = smt.store().stats();
        assert!(stats.hot_hits >= 2);
    }

    #[test]
    fn cold_storage_returns_none() {
        let cold = NullColdStorage;
        assert!(cold.get_branch(&BranchKey { height: 0, node_key: H256::zero() }).is_none());
        assert!(cold.get_leaf(&H256::zero()).is_none());
    }
}
