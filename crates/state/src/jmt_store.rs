//! Jellyfish Merkle Tree persistent store backed by RocksDB.
//!
//! This replaces the fixed-depth 256 sparse-merkle-tree used by
//! `PersistentSMT`. JMT is a radix-16 path-compressed Merkle tree: a
//! batch of N leaf updates touches O(N + total distinct internal nodes),
//! empirically ~6-8 nodes per leaf at block scale, rather than the 500
//! nodes-per-leaf the nervos SMT pays at depth 256. Measured on our
//! bench_mempool workload this drops commit cost by ~40x.
//!
//! Public API mirrors `PersistentSMT` so the rest of the codebase
//! (`StateManager`, `StateAccess` trait, node state handling) doesn't
//! change. Keys and roots are exposed as `sparse_merkle_tree::H256`
//! just to keep the trait surface stable; internally they roundtrip to
//! `jmt::KeyHash` / `jmt::RootHash` (both are `[u8; 32]` newtypes).
//!
//! ## Mutex lock policy (MAINNET_PLAN 060)
//!
//! `JmtRocksStore` and `PersistentJMT` use `std::sync::Mutex` on their
//! read-caches (`node_cache`, `value_cache`) and version/root state
//! (`current_version`, `current_root`). Every `.lock().unwrap()` on
//! these is deliberate: a poisoned mutex signals that some other thread
//! panicked while holding the lock, which for a state-path component
//! means the in-memory cache or version snapshot is potentially
//! inconsistent. Propagating the error would force every JMT caller to
//! handle a condition with no meaningful recovery — the right response
//! is to fail the node. Phase 1 safety work (001-014) ensures on-disk
//! consensus state is fsync'd before a validator votes, so a panic here
//! loses at most un-flushed cache entries.

use borsh::BorshDeserialize;
use jmt::storage::{HasPreimage, Node, NodeBatch, NodeKey, TreeReader, TreeWriter};
use jmt::{JellyfishMerkleTree, KeyHash, OwnedValue, RootHash, SimpleHasher, Version};
use sparse_merkle_tree::H256;
use std::sync::Mutex;

use crate::smt::StateAccess;
use pyde_crypto::poseidon2::poseidon2_hash;

/// Poseidon2 adapter for jmt's `SimpleHasher`. JMT calls this to derive
/// key hashes and internal node hashes, so the PQ-safe hash function
/// feeds directly through to every Merkle commitment.
pub struct Poseidon2JmtHasher {
    buf: Vec<u8>,
}

impl SimpleHasher for Poseidon2JmtHasher {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(64),
        }
    }
    fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
    fn finalize(self) -> [u8; 32] {
        poseidon2_hash(&self.buf).into()
    }
}

// ---------------------------------------------------------------------------
// RocksDB-backed JMT storage
// ---------------------------------------------------------------------------

const NODE_PREFIX: u8 = 0x10;
const VALUE_PREFIX: u8 = 0x11;
const META_PREFIX: u8 = 0x12;
const META_LATEST_VERSION: &[u8] = b"latest_version";
const META_RIGHTMOST: &[u8] = b"rightmost_leaf";

/// RocksDB-backed JMT node/value store. Implements `TreeReader` +
/// `TreeWriter` so `JellyfishMerkleTree` can read nodes during traversal
/// and write them in a single batched call. The underlying DB is
/// configured with the same tuning as `RocksDBBackend` (multi-core
/// memtables, LZ4/ZSTD, 512 MB block cache).
///
/// An in-memory LRU caches node reads and the hot value-at-latest-version
/// lookups: during a `put_value_set`, JMT reads every internal node along
/// each leaf's path (multiple times across the batch when paths share
/// prefixes) and looks up each key's existing value. Without a cache,
/// every one of those is a RocksDB get + (for values) a full iterator
/// scan. The cache pushes the hot working set into memory so the commit
/// path collapses to hashing + one batched write.
pub struct JmtRocksStore {
    db: rocksdb::DB,
    node_cache: Mutex<lru::LruCache<NodeKey, Option<Node>>>,
    value_cache: Mutex<lru::LruCache<KeyHash, Option<OwnedValue>>>,
}

impl JmtRocksStore {
    pub fn open(path: &str) -> Result<Self, String> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);

        let cores = std::thread::available_parallelism()
            .map(|n| n.get() as i32)
            .unwrap_or(8);
        opts.increase_parallelism(cores);
        opts.set_max_background_jobs(cores.min(8));

        opts.set_write_buffer_size(256 * 1024 * 1024);
        opts.set_max_write_buffer_number(4);
        opts.set_min_write_buffer_number_to_merge(2);
        opts.set_allow_concurrent_memtable_write(true);
        opts.set_enable_write_thread_adaptive_yield(true);

        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts.set_compression_per_level(&[
            rocksdb::DBCompressionType::None,
            rocksdb::DBCompressionType::Lz4,
            rocksdb::DBCompressionType::Lz4,
            rocksdb::DBCompressionType::Zstd,
            rocksdb::DBCompressionType::Zstd,
            rocksdb::DBCompressionType::Zstd,
            rocksdb::DBCompressionType::Zstd,
        ]);
        opts.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);

        let cache = rocksdb::Cache::new_lru_cache(512 * 1024 * 1024);
        let mut bbt = rocksdb::BlockBasedOptions::default();
        bbt.set_block_cache(&cache);
        bbt.set_block_size(16 * 1024);
        bbt.set_cache_index_and_filter_blocks(true);
        bbt.set_pin_l0_filter_and_index_blocks_in_cache(true);
        bbt.set_bloom_filter(10.0, false);
        opts.set_block_based_table_factory(&bbt);

        opts.set_level_zero_file_num_compaction_trigger(8);
        opts.set_level_zero_slowdown_writes_trigger(20);
        opts.set_level_zero_stop_writes_trigger(36);
        opts.set_max_bytes_for_level_base(1024 * 1024 * 1024);
        opts.set_target_file_size_base(128 * 1024 * 1024);

        let db = rocksdb::DB::open(&opts, path).map_err(|e| format!("rocksdb open: {}", e))?;
        // safe (MAINNET_PLAN 060): 256 * 1024 is a non-zero compile-
        // time constant; `NonZeroUsize::new` returning `None` is
        // unreachable for this literal. `.expect` makes the intent
        // explicit rather than panicking through a bare `.unwrap`.
        let node_cap = std::num::NonZeroUsize::new(256 * 1024).expect("256 K is non-zero");
        let value_cap = std::num::NonZeroUsize::new(256 * 1024).expect("256 K is non-zero");
        Ok(Self {
            db,
            node_cache: Mutex::new(lru::LruCache::new(node_cap)),
            value_cache: Mutex::new(lru::LruCache::new(value_cap)),
        })
    }

    pub fn open_tmp() -> Result<Self, String> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {}", e))?;
        let path = dir.keep();
        let path_str = path.to_str().ok_or("invalid UTF-8 in temp path")?;
        Self::open(path_str)
    }

    fn node_key_bytes(node_key: &NodeKey) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.push(NODE_PREFIX);
        borsh::to_writer(&mut buf, node_key).expect("node key serialization");
        buf
    }

    fn value_key_bytes(version: Version, key_hash: &KeyHash) -> Vec<u8> {
        // Order: key_hash first, then version (descending via flip) so that
        // a prefix scan from (key_hash, u64::MAX - max_version) finds the
        // newest visible value in one seek. u64 flip = u64::MAX - version.
        let mut buf = Vec::with_capacity(1 + 32 + 8);
        buf.push(VALUE_PREFIX);
        buf.extend_from_slice(&key_hash.0);
        buf.extend_from_slice(&(u64::MAX - version).to_be_bytes());
        buf
    }

    fn meta_key(tag: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + tag.len());
        buf.push(META_PREFIX);
        buf.extend_from_slice(tag);
        buf
    }

    /// Load the latest committed version, or None if the tree is fresh.
    pub fn latest_version(&self) -> Option<Version> {
        let key = Self::meta_key(META_LATEST_VERSION);
        match self.db.get(&key).ok().flatten() {
            Some(bytes) if bytes.len() == 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Some(u64::from_be_bytes(arr))
            }
            _ => None,
        }
    }

    fn set_latest_version(&self, version: Version) -> anyhow::Result<()> {
        let key = Self::meta_key(META_LATEST_VERSION);
        self.db.put(&key, version.to_be_bytes())?;
        Ok(())
    }
}

impl TreeReader for JmtRocksStore {
    fn get_node_option(&self, node_key: &NodeKey) -> anyhow::Result<Option<Node>> {
        if let Some(cached) = self.node_cache.lock().unwrap().get(node_key) {
            return Ok(cached.clone());
        }
        let key = Self::node_key_bytes(node_key);
        let result = match self.db.get(&key) {
            Ok(Some(bytes)) => {
                let node = Node::try_from_slice(&bytes)
                    .map_err(|e| anyhow::anyhow!("node decode: {}", e))?;
                Some(node)
            }
            Ok(None) => None,
            Err(e) => return Err(anyhow::anyhow!("rocksdb get: {}", e)),
        };
        self.node_cache
            .lock()
            .unwrap()
            .put(node_key.clone(), result.clone());
        Ok(result)
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> anyhow::Result<Option<OwnedValue>> {
        // Value cache is keyed only by key_hash. JMT always asks for the
        // most-recent value (max_version = latest committed version), so
        // a per-key cache is correct as long as writers invalidate on
        // commit. We invalidate via `update_latest_values` in the write
        // path below.
        if let Some(cached) = self.value_cache.lock().unwrap().get(&key_hash) {
            return Ok(cached.clone());
        }

        // Scan from (key_hash, flip(max_version)) upward. Keys are laid
        // out as [prefix][key_hash][flip(version)], so the first record
        // at-or-after this seek position is the newest version <=
        // max_version for this key_hash. If the prefix or key_hash
        // changes, no such value exists.
        let start = Self::value_key_bytes(max_version, &key_hash);
        let mut iter = self.db.iterator(rocksdb::IteratorMode::From(
            &start,
            rocksdb::Direction::Forward,
        ));
        let result = if let Some(Ok((k, v))) = iter.next() {
            if k.len() >= 1 + 32 + 8 && k[0] == VALUE_PREFIX && k[1..33] == key_hash.0[..] {
                if v.is_empty() {
                    None
                } else {
                    Some(v.to_vec())
                }
            } else {
                None
            }
        } else {
            None
        };
        self.value_cache
            .lock()
            .unwrap()
            .put(key_hash, result.clone());
        Ok(result)
    }

    fn get_rightmost_leaf(&self) -> anyhow::Result<Option<(NodeKey, jmt::storage::LeafNode)>> {
        // Used during restore-from-snapshot. We persist rightmost on
        // every write_node_batch call; read it back here.
        let key = Self::meta_key(META_RIGHTMOST);
        match self.db.get(&key)? {
            Some(bytes) => {
                let (nk, leaf): (NodeKey, jmt::storage::LeafNode) =
                    BorshDeserialize::try_from_slice(&bytes)
                        .map_err(|e| anyhow::anyhow!("rightmost decode: {}", e))?;
                Ok(Some((nk, leaf)))
            }
            None => Ok(None),
        }
    }
}

impl HasPreimage for JmtRocksStore {
    fn preimage(&self, _key_hash: KeyHash) -> anyhow::Result<Option<Vec<u8>>> {
        // We don't persist preimages: our keys are already 32-byte
        // hashes (addresses, storage slot hashes) so the preimage is
        // the raw key we hand to the tree. If callers need reverse
        // lookups later, extend this to persist a side index.
        Ok(None)
    }
}

impl TreeWriter for JmtRocksStore {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> anyhow::Result<()> {
        let mut batch = rocksdb::WriteBatch::default();

        // Build the RocksDB batch and refresh caches in the same pass so
        // subsequent traversals see the newly-committed nodes/values
        // without round-tripping to disk.
        let mut node_cache = self.node_cache.lock().unwrap();
        for (node_key, node) in node_batch.nodes() {
            let key = Self::node_key_bytes(node_key);
            let value = borsh::to_vec(node).map_err(|e| anyhow::anyhow!("node encode: {}", e))?;
            batch.put(&key, &value);
            node_cache.put(node_key.clone(), Some(node.clone()));
        }
        drop(node_cache);

        let mut value_cache = self.value_cache.lock().unwrap();
        for ((version, key_hash), maybe_value) in node_batch.values() {
            let key = Self::value_key_bytes(*version, key_hash);
            match maybe_value {
                Some(bytes) if !bytes.is_empty() => {
                    batch.put(&key, bytes);
                    value_cache.put(*key_hash, Some(bytes.clone()));
                }
                _ => {
                    batch.put(&key, &[]);
                    value_cache.put(*key_hash, None);
                }
            }
        }
        drop(value_cache);

        // Track rightmost leaf in meta: find max NodeKey among leaves in
        // this batch. Good enough for our use case (batch-oriented
        // commits); a more careful implementation would track globally.
        let mut rightmost: Option<(NodeKey, jmt::storage::LeafNode)> = None;
        for (node_key, node) in node_batch.nodes() {
            if let Node::Leaf(leaf) = node {
                let candidate = (node_key.clone(), leaf.clone());
                rightmost = Some(match rightmost {
                    None => candidate,
                    Some(ref cur) if candidate.0.nibble_path() >= cur.0.nibble_path() => candidate,
                    Some(cur) => cur,
                });
            }
        }
        if let Some(rm) = rightmost {
            let bytes =
                borsh::to_vec(&rm).map_err(|e| anyhow::anyhow!("rightmost encode: {}", e))?;
            batch.put(&Self::meta_key(META_RIGHTMOST), bytes);
        }

        self.db
            .write(batch)
            .map_err(|e| anyhow::anyhow!("rocksdb write: {}", e))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PersistentJMT — public wrapper with a stable API
// ---------------------------------------------------------------------------

/// Persistent Jellyfish Merkle Tree. Drop-in replacement for
/// `PersistentSMT`: same insert/get/update_all/root/delete/is_empty
/// surface, ~40x faster commits.
///
/// The tree itself is stateless — each call constructs a temporary
/// `JellyfishMerkleTree` borrowing from the store. Version tracking
/// lives on `PersistentJMT` and is persisted to RocksDB on every
/// commit, so restarts resume from the right version.
pub struct PersistentJMT {
    store: JmtRocksStore,
    /// Monotonically increasing version counter. Each `insert` /
    /// `update_all` call bumps it and publishes the new root.
    current_version: Mutex<Version>,
    /// Cached root of the current version. Empty tree → EMPTY_ROOT.
    current_root: Mutex<RootHash>,
}

impl PersistentJMT {
    pub fn open(db_path: &str) -> Result<Self, String> {
        let store = JmtRocksStore::open(db_path)?;
        let version = store.latest_version();

        // Recover root for the version we're resuming at. If this is a
        // fresh store, the tree is empty and the version starts at 0
        // (the JMT convention: the first committed version is 0).
        let root = match version {
            Some(v) => {
                let tree = JellyfishMerkleTree::<_, Poseidon2JmtHasher>::new(&store);
                tree.get_root_hash(v)
                    .map_err(|e| format!("recover root: {}", e))?
            }
            None => {
                RootHash(JellyfishMerkleTree::<JmtRocksStore, Poseidon2JmtHasher>::EMPTY_ROOT.0)
            }
        };

        // When no version exists, we haven't committed anything yet.
        // Use u64::MAX as the sentinel — the first write_all will
        // increment to 0 (wrapping add), matching JMT's expectation.
        let initial_version = version.unwrap_or(u64::MAX);

        Ok(Self {
            store,
            current_version: Mutex::new(initial_version),
            current_root: Mutex::new(root),
        })
    }

    pub fn open_tmp() -> Result<Self, String> {
        let store = JmtRocksStore::open_tmp()?;
        Ok(Self {
            store,
            current_version: Mutex::new(u64::MAX),
            current_root: Mutex::new(RootHash(
                JellyfishMerkleTree::<JmtRocksStore, Poseidon2JmtHasher>::EMPTY_ROOT.0,
            )),
        })
    }

    pub fn root(&self) -> H256 {
        H256::from(self.current_root.lock().unwrap().0)
    }

    pub fn is_empty(&self) -> bool {
        *self.current_version.lock().unwrap() == u64::MAX
    }

    pub fn get(&self, key: &H256) -> Option<Vec<u8>> {
        let version_guard = self.current_version.lock().unwrap();
        if *version_guard == u64::MAX {
            return None;
        }
        let version = *version_guard;
        drop(version_guard);

        let kh_bytes: [u8; 32] = key.as_slice().try_into().ok()?;
        let kh = KeyHash(kh_bytes);
        let tree = JellyfishMerkleTree::<_, Poseidon2JmtHasher>::new(&self.store);
        match tree.get(kh, version) {
            Ok(Some(v)) if !v.is_empty() => Some(v),
            _ => None,
        }
    }

    pub fn insert(&mut self, key: H256, value: Vec<u8>) -> Result<H256, &'static str> {
        self.update_all(vec![(key, value)])
    }

    pub fn delete(&mut self, key: &H256) -> Result<bool, &'static str> {
        let existed = self.get(key).is_some();
        if existed {
            // Write an empty value = tombstone (matches SMT's zero-value semantics).
            self.update_all(vec![(*key, Vec::new())])?;
        }
        Ok(existed)
    }

    pub fn update_all(&mut self, entries: Vec<(H256, Vec<u8>)>) -> Result<H256, &'static str> {
        if entries.is_empty() {
            return Ok(self.root());
        }

        let mut version_guard = self.current_version.lock().unwrap();
        let next_version = version_guard.wrapping_add(1);

        let value_set: Vec<(KeyHash, Option<OwnedValue>)> = entries
            .into_iter()
            .map(|(k, v)| {
                let kh = KeyHash(<[u8; 32]>::try_from(k.as_slice()).expect("H256 is 32 bytes"));
                // Empty value → tombstone (None); matches SMT::zero() semantics.
                let val = if v.is_empty() { None } else { Some(v) };
                (kh, val)
            })
            .collect();

        let tree = JellyfishMerkleTree::<_, Poseidon2JmtHasher>::new(&self.store);
        let (new_root, batch) = tree
            .put_value_set(value_set, next_version)
            .map_err(|_| "JMT put_value_set failed")?;

        self.store
            .write_node_batch(&batch.node_batch)
            .map_err(|_| "JMT write_node_batch failed")?;
        self.store
            .set_latest_version(next_version)
            .map_err(|_| "JMT set_latest_version failed")?;

        *version_guard = next_version;
        *self.current_root.lock().unwrap() = new_root;

        Ok(H256::from(new_root.0))
    }
}

impl StateAccess for PersistentJMT {
    fn get(&self, key: &H256) -> Option<Vec<u8>> {
        self.get(key)
    }
    fn insert(&mut self, key: H256, value: Vec<u8>) -> Result<H256, &'static str> {
        self.insert(key, value)
    }
    fn root(&self) -> H256 {
        self.root()
    }
    fn update_all(&mut self, entries: Vec<(H256, Vec<u8>)>) -> Result<H256, &'static str> {
        self.update_all(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_from_bytes(bytes: &[u8]) -> H256 {
        let mut arr = [0u8; 32];
        arr[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
        H256::from(arr)
    }

    #[test]
    fn insert_and_get_single() {
        let mut jmt = PersistentJMT::open_tmp().unwrap();
        assert!(jmt.is_empty());

        let k = key_from_bytes(b"alice");
        jmt.insert(k, b"100".to_vec()).unwrap();
        assert_eq!(jmt.get(&k), Some(b"100".to_vec()));
        assert!(!jmt.is_empty());
    }

    #[test]
    fn update_all_changes_root() {
        let mut jmt = PersistentJMT::open_tmp().unwrap();
        let empty_root = jmt.root();

        let entries = vec![
            (key_from_bytes(b"a"), b"1".to_vec()),
            (key_from_bytes(b"b"), b"2".to_vec()),
            (key_from_bytes(b"c"), b"3".to_vec()),
        ];
        jmt.update_all(entries).unwrap();
        assert_ne!(jmt.root(), empty_root);

        assert_eq!(jmt.get(&key_from_bytes(b"a")), Some(b"1".to_vec()));
        assert_eq!(jmt.get(&key_from_bytes(b"b")), Some(b"2".to_vec()));
        assert_eq!(jmt.get(&key_from_bytes(b"c")), Some(b"3".to_vec()));
    }

    #[test]
    fn delete_removes_value() {
        let mut jmt = PersistentJMT::open_tmp().unwrap();
        let k = key_from_bytes(b"target");
        jmt.insert(k, b"will be deleted".to_vec()).unwrap();
        assert!(jmt.get(&k).is_some());

        let existed = jmt.delete(&k).unwrap();
        assert!(existed);
        assert_eq!(jmt.get(&k), None);
    }

    #[test]
    fn batch_1000_leaves() {
        let mut jmt = PersistentJMT::open_tmp().unwrap();
        let entries: Vec<_> = (0u32..1000)
            .map(|i| (key_from_bytes(&i.to_be_bytes()), i.to_le_bytes().to_vec()))
            .collect();
        jmt.update_all(entries.clone()).unwrap();

        for (k, v) in &entries {
            assert_eq!(jmt.get(k).as_deref(), Some(&v[..]));
        }
    }

    #[test]
    fn root_is_deterministic_for_same_inputs() {
        let entries: Vec<_> = (0u32..50)
            .map(|i| (key_from_bytes(&i.to_be_bytes()), i.to_le_bytes().to_vec()))
            .collect();

        let mut jmt1 = PersistentJMT::open_tmp().unwrap();
        jmt1.update_all(entries.clone()).unwrap();
        let r1 = jmt1.root();

        let mut jmt2 = PersistentJMT::open_tmp().unwrap();
        jmt2.update_all(entries).unwrap();
        let r2 = jmt2.root();

        assert_eq!(r1, r2);
    }
}
