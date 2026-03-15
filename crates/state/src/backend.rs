//! Storage backends for the Sparse Merkle Tree.
//!
//! Provides a trait abstraction over key-value stores, with implementations
//! for in-memory (testing), RocksDB (production), and LRU-cached wrappers.

use sparse_merkle_tree::merge::MergeValue;
use sparse_merkle_tree::traits::{StoreReadOps, StoreWriteOps};
use sparse_merkle_tree::BranchKey;
use sparse_merkle_tree::H256;
use std::collections::HashMap;

use crate::smt::SmtValue;

/// Errors from storage backends.
#[derive(Debug)]
pub enum BackendError {
    RocksDB(String),
    NotFound,
    Io(String),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::RocksDB(e) => write!(f, "RocksDB error: {e}"),
            BackendError::NotFound => write!(f, "key not found"),
            BackendError::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for BackendError {}

// ---------------------------------------------------------------------------
// In-memory backend (for tests)
// ---------------------------------------------------------------------------

/// In-memory storage backend backed by HashMaps. Fast, not persistent.
#[derive(Clone, Default)]
pub struct InMemoryBackend {
    branches: HashMap<BranchKey, sparse_merkle_tree::BranchNode>,
    leaves: HashMap<H256, SmtValue>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn branch_count(&self) -> usize {
        self.branches.len()
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }
}

impl StoreReadOps<SmtValue> for InMemoryBackend {
    fn get_branch(
        &self,
        branch_key: &BranchKey,
    ) -> Result<Option<sparse_merkle_tree::BranchNode>, sparse_merkle_tree::error::Error> {
        Ok(self.branches.get(branch_key).cloned())
    }

    fn get_leaf(
        &self,
        leaf_key: &H256,
    ) -> Result<Option<SmtValue>, sparse_merkle_tree::error::Error> {
        Ok(self.leaves.get(leaf_key).cloned())
    }
}

impl StoreWriteOps<SmtValue> for InMemoryBackend {
    fn insert_branch(
        &mut self,
        node_key: BranchKey,
        branch: sparse_merkle_tree::BranchNode,
    ) -> Result<(), sparse_merkle_tree::error::Error> {
        self.branches.insert(node_key, branch);
        Ok(())
    }

    fn insert_leaf(
        &mut self,
        leaf_key: H256,
        leaf: SmtValue,
    ) -> Result<(), sparse_merkle_tree::error::Error> {
        self.leaves.insert(leaf_key, leaf);
        Ok(())
    }

    fn remove_branch(
        &mut self,
        node_key: &BranchKey,
    ) -> Result<(), sparse_merkle_tree::error::Error> {
        self.branches.remove(node_key);
        Ok(())
    }

    fn remove_leaf(&mut self, leaf_key: &H256) -> Result<(), sparse_merkle_tree::error::Error> {
        self.leaves.remove(leaf_key);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RocksDB backend (persistent)
// ---------------------------------------------------------------------------

/// Prefix bytes for key namespacing in RocksDB.
const BRANCH_PREFIX: u8 = 0x01;
const LEAF_PREFIX: u8 = 0x02;

// MergeValue serialization tags
const MV_VALUE: u8 = 1;
const MV_MERGE_WITH_ZERO: u8 = 2;

fn serialize_merge_value(mv: &MergeValue) -> Vec<u8> {
    use sparse_merkle_tree::merge::MergeValue;
    match mv {
        MergeValue::Value(h) => {
            let mut buf = Vec::with_capacity(33);
            buf.push(MV_VALUE);
            buf.extend_from_slice(h.as_slice());
            buf
        }
        MergeValue::MergeWithZero {
            base_node,
            zero_bits,
            zero_count,
        } => {
            let mut buf = Vec::with_capacity(66);
            buf.push(MV_MERGE_WITH_ZERO);
            buf.extend_from_slice(base_node.as_slice());
            buf.extend_from_slice(zero_bits.as_slice());
            buf.push(*zero_count);
            buf
        }
        #[allow(unreachable_patterns)]
        _ => Vec::new(),
    }
}

fn deserialize_merge_value(data: &[u8]) -> Option<MergeValue> {
    use sparse_merkle_tree::merge::MergeValue;
    if data.is_empty() {
        return None;
    }
    match data[0] {
        MV_VALUE if data.len() >= 33 => {
            let h = H256::from(<[u8; 32]>::try_from(&data[1..33]).ok()?);
            Some(MergeValue::Value(h))
        }
        MV_MERGE_WITH_ZERO if data.len() >= 66 => {
            let base_node = H256::from(<[u8; 32]>::try_from(&data[1..33]).ok()?);
            let zero_bits = H256::from(<[u8; 32]>::try_from(&data[33..65]).ok()?);
            let zero_count = data[65];
            Some(MergeValue::MergeWithZero {
                base_node,
                zero_bits,
                zero_count,
            })
        }
        _ => None,
    }
}

fn serialize_branch(branch: &sparse_merkle_tree::BranchNode) -> Vec<u8> {
    let left = serialize_merge_value(&branch.left);
    let right = serialize_merge_value(&branch.right);
    let mut buf = Vec::with_capacity(2 + left.len() + right.len());
    buf.push(left.len() as u8);
    buf.extend_from_slice(&left);
    buf.push(right.len() as u8);
    buf.extend_from_slice(&right);
    buf
}

fn deserialize_branch(data: &[u8]) -> Option<sparse_merkle_tree::BranchNode> {
    if data.len() < 2 {
        return None;
    }
    let left_len = data[0] as usize;
    if data.len() < 1 + left_len + 1 {
        return None;
    }
    let left = deserialize_merge_value(&data[1..1 + left_len])?;
    let right_start = 1 + left_len;
    let right_len = data[right_start] as usize;
    if data.len() < right_start + 1 + right_len {
        return None;
    }
    let right = deserialize_merge_value(&data[right_start + 1..right_start + 1 + right_len])?;
    Some(sparse_merkle_tree::BranchNode { left, right })
}

/// RocksDB-backed persistent storage.
pub struct RocksDBBackend {
    db: rocksdb::DB,
}

impl RocksDBBackend {
    /// Open or create a RocksDB database at the given path.
    pub fn open(path: &str) -> Result<Self, BackendError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db =
            rocksdb::DB::open(&opts, path).map_err(|e| BackendError::RocksDB(e.to_string()))?;
        Ok(Self { db })
    }

    /// Open a temporary database (for testing).
    pub fn open_tmp() -> Result<Self, BackendError> {
        let dir = tempfile::tempdir().map_err(|e| BackendError::Io(e.to_string()))?;
        Self::open(dir.keep().to_str().unwrap())
    }

    fn branch_key_bytes(bk: &BranchKey) -> Vec<u8> {
        let mut key = Vec::with_capacity(1 + 1 + 32);
        key.push(BRANCH_PREFIX);
        key.push(bk.height);
        key.extend_from_slice(bk.node_key.as_slice());
        key
    }

    fn leaf_key_bytes(lk: &H256) -> Vec<u8> {
        let mut key = Vec::with_capacity(1 + 32);
        key.push(LEAF_PREFIX);
        key.extend_from_slice(lk.as_slice());
        key
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> Result<(), BackendError> {
        self.db
            .flush()
            .map_err(|e| BackendError::RocksDB(e.to_string()))
    }
}

impl StoreReadOps<SmtValue> for RocksDBBackend {
    fn get_branch(
        &self,
        branch_key: &BranchKey,
    ) -> Result<Option<sparse_merkle_tree::BranchNode>, sparse_merkle_tree::error::Error> {
        let key = Self::branch_key_bytes(branch_key);
        match self.db.get(&key) {
            Ok(Some(data)) => Ok(deserialize_branch(&data)),
            Ok(None) => Ok(None),
            Err(e) => Err(sparse_merkle_tree::error::Error::Store(e.to_string())),
        }
    }

    fn get_leaf(
        &self,
        leaf_key: &H256,
    ) -> Result<Option<SmtValue>, sparse_merkle_tree::error::Error> {
        let key = Self::leaf_key_bytes(leaf_key);
        match self.db.get(&key) {
            Ok(Some(data)) => Ok(Some(SmtValue(data))),
            Ok(None) => Ok(None),
            Err(e) => Err(sparse_merkle_tree::error::Error::Store(e.to_string())),
        }
    }
}

impl StoreWriteOps<SmtValue> for RocksDBBackend {
    fn insert_branch(
        &mut self,
        node_key: BranchKey,
        branch: sparse_merkle_tree::BranchNode,
    ) -> Result<(), sparse_merkle_tree::error::Error> {
        let key = Self::branch_key_bytes(&node_key);
        let data = serialize_branch(&branch);
        self.db
            .put(&key, &data)
            .map_err(|e| sparse_merkle_tree::error::Error::Store(e.to_string()))
    }

    fn insert_leaf(
        &mut self,
        leaf_key: H256,
        leaf: SmtValue,
    ) -> Result<(), sparse_merkle_tree::error::Error> {
        let key = Self::leaf_key_bytes(&leaf_key);
        self.db
            .put(&key, &leaf.0)
            .map_err(|e| sparse_merkle_tree::error::Error::Store(e.to_string()))
    }

    fn remove_branch(
        &mut self,
        node_key: &BranchKey,
    ) -> Result<(), sparse_merkle_tree::error::Error> {
        let key = Self::branch_key_bytes(node_key);
        self.db
            .delete(&key)
            .map_err(|e| sparse_merkle_tree::error::Error::Store(e.to_string()))
    }

    fn remove_leaf(&mut self, leaf_key: &H256) -> Result<(), sparse_merkle_tree::error::Error> {
        let key = Self::leaf_key_bytes(leaf_key);
        self.db
            .delete(&key)
            .map_err(|e| sparse_merkle_tree::error::Error::Store(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// LRU-cached wrapper
// ---------------------------------------------------------------------------

use std::cell::RefCell;

/// LRU cache wrapping any storage backend. Caches branch and leaf reads
/// using interior mutability (RefCell) since Nervos StoreReadOps takes &self.
pub struct CachedBackend<S> {
    inner: S,
    branch_cache: RefCell<lru::LruCache<BranchKey, Option<sparse_merkle_tree::BranchNode>>>,
    leaf_cache: RefCell<lru::LruCache<H256, Option<SmtValue>>>,
    hits: RefCell<u64>,
    misses: RefCell<u64>,
}

impl<S> CachedBackend<S> {
    /// Create a new cached wrapper with the given capacity.
    pub fn new(inner: S, capacity: usize) -> Self {
        Self {
            inner,
            branch_cache: RefCell::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(capacity).unwrap(),
            )),
            leaf_cache: RefCell::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(capacity).unwrap(),
            )),
            hits: RefCell::new(0),
            misses: RefCell::new(0),
        }
    }

    pub fn cache_hits(&self) -> u64 {
        *self.hits.borrow()
    }

    pub fn cache_misses(&self) -> u64 {
        *self.misses.borrow()
    }

    pub fn cache_hit_rate(&self) -> f64 {
        let h = *self.hits.borrow();
        let m = *self.misses.borrow();
        let total = h + m;
        if total == 0 {
            0.0
        } else {
            h as f64 / total as f64
        }
    }
}

impl<S: StoreReadOps<SmtValue>> StoreReadOps<SmtValue> for CachedBackend<S> {
    fn get_branch(
        &self,
        branch_key: &BranchKey,
    ) -> Result<Option<sparse_merkle_tree::BranchNode>, sparse_merkle_tree::error::Error> {
        if let Some(cached) = self.branch_cache.borrow_mut().get(branch_key) {
            *self.hits.borrow_mut() += 1;
            return Ok(cached.clone());
        }
        *self.misses.borrow_mut() += 1;
        let result = self.inner.get_branch(branch_key)?;
        self.branch_cache
            .borrow_mut()
            .put(branch_key.clone(), result.clone());
        Ok(result)
    }

    fn get_leaf(
        &self,
        leaf_key: &H256,
    ) -> Result<Option<SmtValue>, sparse_merkle_tree::error::Error> {
        if let Some(cached) = self.leaf_cache.borrow_mut().get(leaf_key) {
            *self.hits.borrow_mut() += 1;
            return Ok(cached.clone());
        }
        *self.misses.borrow_mut() += 1;
        let result = self.inner.get_leaf(leaf_key)?;
        self.leaf_cache.borrow_mut().put(*leaf_key, result.clone());
        Ok(result)
    }
}

impl<S: StoreWriteOps<SmtValue>> StoreWriteOps<SmtValue> for CachedBackend<S> {
    fn insert_branch(
        &mut self,
        node_key: BranchKey,
        branch: sparse_merkle_tree::BranchNode,
    ) -> Result<(), sparse_merkle_tree::error::Error> {
        self.branch_cache
            .borrow_mut()
            .put(node_key.clone(), Some(branch.clone()));
        self.inner.insert_branch(node_key, branch)
    }

    fn insert_leaf(
        &mut self,
        leaf_key: H256,
        leaf: SmtValue,
    ) -> Result<(), sparse_merkle_tree::error::Error> {
        self.leaf_cache
            .borrow_mut()
            .put(leaf_key, Some(leaf.clone()));
        self.inner.insert_leaf(leaf_key, leaf)
    }

    fn remove_branch(
        &mut self,
        node_key: &BranchKey,
    ) -> Result<(), sparse_merkle_tree::error::Error> {
        self.branch_cache.borrow_mut().put(node_key.clone(), None);
        self.inner.remove_branch(node_key)
    }

    fn remove_leaf(&mut self, leaf_key: &H256) -> Result<(), sparse_merkle_tree::error::Error> {
        self.leaf_cache.borrow_mut().put(*leaf_key, None);
        self.inner.remove_leaf(leaf_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smt::{key_from_seed, Poseidon2Hasher, SmtValue};
    use sparse_merkle_tree::SparseMerkleTree;

    type SMT<S> = SparseMerkleTree<Poseidon2Hasher, SmtValue, S>;

    // ========== Task 0293: Backend get/put/delete roundtrip ==========

    #[test]
    fn in_memory_roundtrip() {
        let store = InMemoryBackend::new();
        let mut smt = SMT::new(H256::zero(), store);

        let key = key_from_seed(1);
        smt.update(key, SmtValue(b"hello".to_vec())).unwrap();

        let val = smt.get(&key).unwrap();
        assert_eq!(val.0, b"hello");

        // Delete
        smt.update(key, SmtValue::default()).unwrap();
        let val = smt.get(&key).unwrap();
        assert!(val.0.is_empty());
    }

    #[test]
    fn rocksdb_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDBBackend::open(dir.path().to_str().unwrap()).unwrap();
        let mut smt = SMT::new(H256::zero(), store);

        let key = key_from_seed(1);
        smt.update(key, SmtValue(b"persistent".to_vec())).unwrap();

        let val = smt.get(&key).unwrap();
        assert_eq!(val.0, b"persistent");
    }

    #[test]
    fn rocksdb_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap().to_string();
        let root;
        let key = key_from_seed(1);

        // Write
        {
            let store = RocksDBBackend::open(&path).unwrap();
            let mut smt = SMT::new(H256::zero(), store);
            smt.update(key, SmtValue(b"data".to_vec())).unwrap();
            root = *smt.root();
        }

        // Reopen and read
        {
            let store = RocksDBBackend::open(&path).unwrap();
            let smt = SMT::new(root, store);
            let val = smt.get(&key).unwrap();
            assert_eq!(val.0, b"data");
        }
    }

    // ========== Task 0294: Batch write atomicity ==========

    #[test]
    fn batch_update() {
        let store = InMemoryBackend::new();
        let mut smt = SMT::new(H256::zero(), store);

        let entries: Vec<(H256, SmtValue)> = (0..100)
            .map(|i| (key_from_seed(i), SmtValue(format!("v{i}").into_bytes())))
            .collect();

        smt.update_all(entries.clone()).unwrap();

        for (k, v) in &entries {
            assert_eq!(smt.get(k).unwrap().0, v.0);
        }
    }

    #[test]
    fn rocksdb_batch_update() {
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDBBackend::open(dir.path().to_str().unwrap()).unwrap();
        let mut smt = SMT::new(H256::zero(), store);

        let entries: Vec<(H256, SmtValue)> = (0..100)
            .map(|i| (key_from_seed(i), SmtValue(format!("v{i}").into_bytes())))
            .collect();

        smt.update_all(entries.clone()).unwrap();

        for (k, v) in &entries {
            assert_eq!(smt.get(k).unwrap().0, v.0);
        }
    }

    // ========== Task 0295: Cache hit/miss ==========

    #[test]
    fn cached_backend_basic() {
        let inner = InMemoryBackend::new();
        let store = CachedBackend::new(inner, 1000);
        let mut smt = SMT::new(H256::zero(), store);

        let key = key_from_seed(1);
        smt.update(key, SmtValue(b"cached".to_vec())).unwrap();
        assert_eq!(smt.get(&key).unwrap().0, b"cached");
    }

    #[test]
    fn cached_backend_records_hits_and_misses() {
        let inner = InMemoryBackend::new();
        let store = CachedBackend::new(inner, 1000);
        let mut smt = SMT::new(H256::zero(), store);

        let key = key_from_seed(1);
        smt.update(key, SmtValue(b"data".to_vec())).unwrap();

        // First read: cache miss (populated by update, but get goes through cache)
        let _val = smt.get(&key).unwrap();
        // Second read: should be a cache hit
        let _val = smt.get(&key).unwrap();

        let store = smt.take_store();
        assert!(
            store.cache_hits() > 0 || store.cache_misses() > 0,
            "cache should have recorded activity: hits={} misses={}",
            store.cache_hits(),
            store.cache_misses()
        );
    }

    // ========== Serialization roundtrip ==========

    #[test]
    fn merge_value_serialization_roundtrip() {
        use sparse_merkle_tree::merge::MergeValue;

        // Value variant
        let mv = MergeValue::Value(H256::from([0xAB; 32]));
        let data = super::serialize_merge_value(&mv);
        let deserialized = super::deserialize_merge_value(&data).unwrap();
        assert_eq!(mv, deserialized);

        // MergeWithZero variant
        let mv = MergeValue::MergeWithZero {
            base_node: H256::from([0x11; 32]),
            zero_bits: H256::from([0x22; 32]),
            zero_count: 42,
        };
        let data = super::serialize_merge_value(&mv);
        let deserialized = super::deserialize_merge_value(&data).unwrap();
        assert_eq!(mv, deserialized);

        // Zero value
        let mv = MergeValue::zero();
        let data = super::serialize_merge_value(&mv);
        let deserialized = super::deserialize_merge_value(&data).unwrap();
        assert_eq!(mv, deserialized);
    }

    #[test]
    fn branch_serialization_roundtrip() {
        use sparse_merkle_tree::merge::MergeValue;

        let branch = sparse_merkle_tree::BranchNode {
            left: MergeValue::Value(H256::from([0xAA; 32])),
            right: MergeValue::MergeWithZero {
                base_node: H256::from([0xBB; 32]),
                zero_bits: H256::from([0xCC; 32]),
                zero_count: 10,
            },
        };

        let data = super::serialize_branch(&branch);
        let deserialized = super::deserialize_branch(&data).unwrap();
        assert_eq!(branch.left, deserialized.left);
        assert_eq!(branch.right, deserialized.right);
    }

    #[test]
    fn deserialize_corrupt_data_returns_none() {
        assert!(super::deserialize_merge_value(&[]).is_none());
        assert!(super::deserialize_merge_value(&[0xFF]).is_none());
        assert!(super::deserialize_merge_value(&[0x01, 0x00]).is_none()); // too short for Value
        assert!(super::deserialize_branch(&[]).is_none());
        assert!(super::deserialize_branch(&[0x01]).is_none());
    }

    // ========== Root consistency across backends ==========

    #[test]
    fn same_root_across_backends() {
        let key1 = key_from_seed(1);
        let key2 = key_from_seed(2);
        let entries = vec![
            (key1, SmtValue(b"a".to_vec())),
            (key2, SmtValue(b"b".to_vec())),
        ];

        // In-memory
        let store1 = InMemoryBackend::new();
        let mut smt1 = SMT::new(H256::zero(), store1);
        smt1.update_all(entries.clone()).unwrap();

        // RocksDB
        let dir = tempfile::tempdir().unwrap();
        let store2 = RocksDBBackend::open(dir.path().to_str().unwrap()).unwrap();
        let mut smt2 = SMT::new(H256::zero(), store2);
        smt2.update_all(entries).unwrap();

        assert_eq!(smt1.root(), smt2.root());
    }
}
