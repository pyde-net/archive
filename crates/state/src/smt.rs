//! Sparse Merkle Tree backed by the Nervos `sparse-merkle-tree` crate
//! with Poseidon2 hashing (Goldilocks field, efficient for Merkle trees).
//!
//! The tree has a fixed depth of 256 levels. Keys are 256-bit hashes used
//! as paths through the tree. Empty subtrees use precomputed constant hashes.

use pyde_crypto::poseidon2::{poseidon2_hash, poseidon2_pair};
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::traits::{Hasher, Value};
use sparse_merkle_tree::{SparseMerkleTree as NervosSMT, H256};

use crate::backend::RocksDBBackend;

// ---------------------------------------------------------------------------
// Poseidon2 hasher adapter for the Nervos SMT
// ---------------------------------------------------------------------------

/// Poseidon2-based hasher for the Nervos SMT.
/// Accumulates bytes written via `write_h256` / `write_byte`, then hashes on `finish`.
pub struct Poseidon2Hasher {
    buf: Vec<u8>,
}

impl Default for Poseidon2Hasher {
    fn default() -> Self {
        Self {
            buf: Vec::with_capacity(64),
        }
    }
}

impl Hasher for Poseidon2Hasher {
    fn write_h256(&mut self, h: &H256) {
        self.buf.extend_from_slice(h.as_slice());
    }

    fn write_byte(&mut self, b: u8) {
        self.buf.push(b);
    }

    fn finish(self) -> H256 {
        // For internal nodes (exactly two H256 children = 64 bytes),
        // use poseidon2_pair for efficient two-to-one Merkle hashing.
        if self.buf.len() == 64 {
            let mut left_bytes = [0u8; 32];
            left_bytes.copy_from_slice(&self.buf[..32]);
            let left = pyde_crypto::hash::Hash256::new(left_bytes);
            let mut right_bytes = [0u8; 32];
            right_bytes.copy_from_slice(&self.buf[32..]);
            let right = pyde_crypto::hash::Hash256::new(right_bytes);
            let hash = poseidon2_pair(left, right);
            return H256::from(hash.to_bytes());
        }
        let hash = poseidon2_hash(&self.buf);
        H256::from(hash.to_bytes())
    }
}

// ---------------------------------------------------------------------------
// Value adapter
// ---------------------------------------------------------------------------

/// A variable-length byte value stored in the SMT.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SmtValue(pub Vec<u8>);

impl From<Vec<u8>> for SmtValue {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl Value for SmtValue {
    fn to_h256(&self) -> H256 {
        if self.0.is_empty() {
            return H256::zero();
        }
        let hash = poseidon2_hash(&self.0);
        H256::from(hash.to_bytes())
    }

    fn zero() -> Self {
        Self(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Public API wrapping the Nervos SMT
// ---------------------------------------------------------------------------

/// 256-bit key type.
pub type Key = H256;

/// Pyde's Sparse Merkle Tree: Nervos SMT with Poseidon2 hashing.
pub struct PydeSMT {
    inner: NervosSMT<Poseidon2Hasher, SmtValue, DefaultStore<SmtValue>>,
}

impl PydeSMT {
    /// Create a new empty tree.
    pub fn new() -> Self {
        Self {
            inner: NervosSMT::default(),
        }
    }

    /// Get the current Merkle root.
    pub fn root(&self) -> H256 {
        *self.inner.root()
    }

    /// Look up a value by key. Returns None if key is absent (zero value).
    pub fn get(&self, key: &Key) -> Option<Vec<u8>> {
        match self.inner.get(key) {
            Ok(v) if v.0.is_empty() => None,
            Ok(v) => Some(v.0),
            Err(_) => None,
        }
    }

    /// Insert or update a key-value pair. Returns the new root.
    pub fn insert(&mut self, key: Key, value: Vec<u8>) -> Result<H256, &'static str> {
        self.inner
            .update(key, SmtValue(value))
            .map_err(|_| "SMT update failed")?;
        Ok(self.root())
    }

    /// Delete a key (set value to zero). Returns true if key existed.
    pub fn delete(&mut self, key: &Key) -> Result<bool, &'static str> {
        let existed = self.get(key).is_some();
        if existed {
            self.inner
                .update(*key, SmtValue::zero())
                .map_err(|_| "SMT delete failed")?;
        }
        Ok(existed)
    }

    /// Batch insert/update multiple key-value pairs. Returns the new root.
    pub fn update_all(&mut self, entries: Vec<(Key, Vec<u8>)>) -> Result<H256, &'static str> {
        let leaves: Vec<(Key, SmtValue)> = entries
            .into_iter()
            .map(|(k, v)| (k, SmtValue(v)))
            .collect();
        self.inner
            .update_all(leaves)
            .map_err(|_| "SMT batch update failed")?;
        Ok(self.root())
    }

    /// Generate a Merkle proof for one or more keys.
    pub fn prove(&self, keys: Vec<Key>) -> Result<MerkleProof, &'static str> {
        let proof = self
            .inner
            .merkle_proof(keys.clone())
            .map_err(|_| "SMT proof generation failed")?;
        Ok(MerkleProof { inner: proof })
    }

    /// Whether the tree is empty (root == zero).
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Trait for state access — implemented by both PydeSMT and StateOverlay.
/// Allows the tx pipeline to work with either direct SMT or per-group overlays.
pub trait StateAccess {
    fn get(&self, key: &Key) -> Option<Vec<u8>>;
    fn insert(&mut self, key: Key, value: Vec<u8>) -> Result<H256, &'static str>;
    fn root(&self) -> H256;
    /// Batch insert: default falls back to individual inserts.
    /// PersistentSMT overrides with a single Merkle tree update + RocksDB batch write.
    fn update_all(&mut self, entries: Vec<(Key, Vec<u8>)>) -> Result<H256, &'static str> {
        let mut root = self.root();
        for (k, v) in entries {
            root = self.insert(k, v)?;
        }
        Ok(root)
    }
}

impl StateAccess for PydeSMT {
    fn get(&self, key: &Key) -> Option<Vec<u8>> {
        self.get(key)
    }
    fn insert(&mut self, key: Key, value: Vec<u8>) -> Result<H256, &'static str> {
        self.insert(key, value)
    }
    fn root(&self) -> H256 {
        self.root()
    }
    fn update_all(&mut self, entries: Vec<(Key, Vec<u8>)>) -> Result<H256, &'static str> {
        self.update_all(entries)
    }
}

/// Lightweight state overlay for parallel execution.
/// Reads from a shared base SMT (immutable), writes to a local HashMap.
/// After execution, the writes are collected and batch-inserted into the real SMT.
pub struct StateOverlay<'a> {
    base: &'a dyn StateAccess,
    writes: std::collections::HashMap<Key, Vec<u8>>,
}

impl<'a> StateOverlay<'a> {
    pub fn new(base: &'a dyn StateAccess) -> Self {
        Self {
            base,
            writes: std::collections::HashMap::new(),
        }
    }

    /// Collect all writes (for merging into the main SMT after parallel execution).
    pub fn into_writes(self) -> Vec<(Key, Vec<u8>)> {
        self.writes.into_iter().collect()
    }

    /// Number of write operations captured.
    pub fn write_count(&self) -> usize {
        self.writes.len()
    }
}

impl<'a> StateAccess for StateOverlay<'a> {
    fn get(&self, key: &Key) -> Option<Vec<u8>> {
        // Check overlay first (local writes), then base SMT
        if let Some(v) = self.writes.get(key) {
            if v.is_empty() { None } else { Some(v.clone()) }
        } else {
            self.base.get(key)
        }
    }

    fn insert(&mut self, key: Key, value: Vec<u8>) -> Result<H256, &'static str> {
        self.writes.insert(key, value);
        // Return a dummy root — real root is computed after merge
        Ok(H256::zero())
    }

    fn root(&self) -> H256 {
        // Overlay doesn't track root — use base root as approximation
        self.base.root()
    }
}

/// Persistent PydeSMT backed by RocksDB.
/// State survives node restarts.
pub struct PersistentSMT {
    inner: NervosSMT<Poseidon2Hasher, SmtValue, RocksDBBackend>,
}

impl PersistentSMT {
    /// Open a persistent SMT backed by RocksDB at the given path.
    pub fn open(db_path: &str) -> Result<Self, String> {
        let backend = RocksDBBackend::open(db_path)
            .map_err(|e| format!("failed to open RocksDB: {}", e))?;
        let smt = NervosSMT::new_with_store(backend)
            .map_err(|e| format!("failed to create SMT: {}", e))?;
        Ok(Self { inner: smt })
    }

    pub fn root(&self) -> H256 {
        *self.inner.root()
    }

    pub fn get(&self, key: &Key) -> Option<Vec<u8>> {
        match self.inner.get(key) {
            Ok(v) if v.0.is_empty() => None,
            Ok(v) => Some(v.0),
            Err(_) => None,
        }
    }

    pub fn insert(&mut self, key: Key, value: Vec<u8>) -> Result<H256, &'static str> {
        self.inner
            .update(key, SmtValue(value))
            .map_err(|_| "SMT update failed")?;
        Ok(self.root())
    }

    pub fn delete(&mut self, key: &Key) -> Result<bool, &'static str> {
        let existed = self.get(key).is_some();
        if existed {
            self.inner
                .update(*key, SmtValue::zero())
                .map_err(|_| "SMT delete failed")?;
        }
        Ok(existed)
    }

    pub fn update_all(&mut self, entries: Vec<(Key, Vec<u8>)>) -> Result<H256, &'static str> {
        let leaves: Vec<(Key, SmtValue)> = entries
            .into_iter()
            .map(|(k, v)| (k, SmtValue(v)))
            .collect();
        self.inner
            .update_all(leaves)
            .map_err(|_| "SMT batch update failed")?;
        Ok(self.root())
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl StateAccess for PersistentSMT {
    fn get(&self, key: &Key) -> Option<Vec<u8>> {
        self.get(key)
    }
    fn insert(&mut self, key: Key, value: Vec<u8>) -> Result<H256, &'static str> {
        self.insert(key, value)
    }
    fn root(&self) -> H256 {
        self.root()
    }
    fn update_all(&mut self, entries: Vec<(Key, Vec<u8>)>) -> Result<H256, &'static str> {
        self.update_all(entries)
    }
}

impl Default for PydeSMT {
    fn default() -> Self {
        Self::new()
    }
}

/// A Merkle proof wrapping the Nervos proof type.
pub struct MerkleProof {
    inner: sparse_merkle_tree::MerkleProof,
}

impl MerkleProof {
    /// Compile this proof into a more compact representation for serialization.
    pub fn compile(self, keys: Vec<Key>) -> Result<CompiledProof, &'static str> {
        let compiled = self
            .inner
            .compile(keys)
            .map_err(|_| "proof compilation failed")?;
        Ok(CompiledProof { inner: compiled })
    }

    /// Verify this proof against a root hash and expected leaves.
    /// `leaves` is a list of (key, value) pairs. Use empty vec for non-existence.
    pub fn verify(
        &self,
        root: H256,
        leaves: Vec<(Key, Vec<u8>)>,
    ) -> bool {
        let smt_leaves: Vec<(Key, H256)> = leaves
            .iter()
            .map(|(k, v)| {
                let val = SmtValue(v.clone());
                (*k, val.to_h256())
            })
            .collect();
        self.inner
            .clone()
            .verify::<Poseidon2Hasher>(&root, smt_leaves)
            .unwrap_or(false)
    }

    /// Verify non-existence of keys against a root hash.
    pub fn verify_absence(&self, root: H256, keys: Vec<Key>) -> bool {
        let smt_leaves: Vec<(Key, H256)> = keys
            .iter()
            .map(|k| (*k, H256::zero()))
            .collect();
        self.inner
            .clone()
            .verify::<Poseidon2Hasher>(&root, smt_leaves)
            .unwrap_or(false)
    }
}

/// A compiled Merkle proof — more compact, better for serialization and wire transfer.
pub struct CompiledProof {
    inner: sparse_merkle_tree::CompiledMerkleProof,
}

impl CompiledProof {
    /// Verify this compiled proof against a root and leaves.
    pub fn verify(&self, root: H256, leaves: Vec<(Key, Vec<u8>)>) -> bool {
        let smt_leaves: Vec<(Key, H256)> = leaves
            .iter()
            .map(|(k, v)| {
                let val = SmtValue(v.clone());
                (*k, val.to_h256())
            })
            .collect();
        self.inner
            .clone()
            .verify::<Poseidon2Hasher>(&root, smt_leaves)
            .unwrap_or(false)
    }

    /// Serialize to bytes for wire transfer.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.clone().into()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self {
            inner: sparse_merkle_tree::CompiledMerkleProof(data),
        }
    }
}

/// Helper: create a Key from a u64 seed (for testing).
pub fn key_from_seed(seed: u64) -> Key {
    let hash = poseidon2_hash(&seed.to_le_bytes());
    H256::from(hash.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Task 0276: Insert and retrieve single value ==========

    #[test]
    fn insert_and_get_single() {
        let mut smt = PydeSMT::new();
        let key = key_from_seed(1);
        smt.insert(key, b"hello".to_vec()).unwrap();
        assert_eq!(smt.get(&key), Some(b"hello".to_vec()));
    }

    #[test]
    fn get_missing_returns_none() {
        let smt = PydeSMT::new();
        assert_eq!(smt.get(&key_from_seed(1)), None);
    }

    // ========== Task 0277: Insert 1000 random pairs ==========

    #[test]
    fn insert_1000_and_verify_all() {
        let mut smt = PydeSMT::new();
        let pairs: Vec<(Key, Vec<u8>)> = (0..1000)
            .map(|i| (key_from_seed(i), format!("value_{i}").into_bytes()))
            .collect();

        for (k, v) in &pairs {
            smt.insert(*k, v.clone()).unwrap();
        }

        for (k, v) in &pairs {
            assert_eq!(smt.get(k), Some(v.clone()));
        }
    }

    // ========== Task 0278: Delete key and verify absence ==========

    #[test]
    fn delete_key_removes_it() {
        let mut smt = PydeSMT::new();
        let key = key_from_seed(42);
        smt.insert(key, b"data".to_vec()).unwrap();
        assert!(smt.delete(&key).unwrap());
        assert_eq!(smt.get(&key), None);
    }

    #[test]
    fn delete_nonexistent_returns_false() {
        let mut smt = PydeSMT::new();
        assert!(!smt.delete(&key_from_seed(99)).unwrap());
    }

    // ========== Task 0279: Root changes after insert ==========

    #[test]
    fn root_changes_after_insert() {
        let mut smt = PydeSMT::new();
        let root_before = smt.root();
        smt.insert(key_from_seed(1), b"test".to_vec()).unwrap();
        assert_ne!(root_before, smt.root());
    }

    #[test]
    fn different_values_different_roots() {
        let key = key_from_seed(1);

        let mut smt1 = PydeSMT::new();
        smt1.insert(key, b"aaa".to_vec()).unwrap();

        let mut smt2 = PydeSMT::new();
        smt2.insert(key, b"bbb".to_vec()).unwrap();

        assert_ne!(smt1.root(), smt2.root());
    }

    // ========== Task 0280: Root reverts after insert + delete ==========

    #[test]
    fn root_reverts_after_insert_delete() {
        let mut smt = PydeSMT::new();
        let empty_root = smt.root();

        let key = key_from_seed(1);
        smt.insert(key, b"temp".to_vec()).unwrap();
        assert_ne!(smt.root(), empty_root);

        smt.delete(&key).unwrap();
        assert_eq!(smt.root(), empty_root);
    }

    // ========== Task 0281: Merkle proof for existing key ==========

    #[test]
    fn merkle_proof_existing_key() {
        let mut smt = PydeSMT::new();
        let key = key_from_seed(1);
        let value = b"value".to_vec();
        smt.insert(key, value.clone()).unwrap();

        let root = smt.root();
        let proof = smt.prove(vec![key]).unwrap();
        assert!(proof.verify(root, vec![(key, value)]));
    }

    #[test]
    fn merkle_proof_multiple_keys() {
        let mut smt = PydeSMT::new();
        let entries: Vec<(Key, Vec<u8>)> = (0..10)
            .map(|i| (key_from_seed(i), format!("val_{i}").into_bytes()))
            .collect();

        for (k, v) in &entries {
            smt.insert(*k, v.clone()).unwrap();
        }

        let root = smt.root();
        let keys: Vec<Key> = entries.iter().map(|(k, _)| *k).collect();
        let proof = smt.prove(keys).unwrap();
        assert!(proof.verify(root, entries));
    }

    // ========== Task 0282: Non-existence proof ==========

    #[test]
    fn merkle_proof_nonexistence() {
        let mut smt = PydeSMT::new();
        smt.insert(key_from_seed(1), b"exists".to_vec()).unwrap();

        let root = smt.root();
        let missing = key_from_seed(999);
        let proof = smt.prove(vec![missing]).unwrap();
        assert!(proof.verify_absence(root, vec![missing]));
    }

    // ========== Task 0283: Tampered proof fails ==========

    #[test]
    fn tampered_value_produces_different_root() {
        // Verify integrity: same key with different values → different roots
        let key = key_from_seed(1);

        let mut smt1 = PydeSMT::new();
        smt1.insert(key, b"real".to_vec()).unwrap();

        let mut smt2 = PydeSMT::new();
        smt2.insert(key, b"fake".to_vec()).unwrap();

        assert_ne!(smt1.root(), smt2.root());

        // The correct proof verifies against the correct root
        let proof = smt1.prove(vec![key]).unwrap();
        assert!(proof.verify(smt1.root(), vec![(key, b"real".to_vec())]));
    }

    #[test]
    fn different_roots_for_different_states() {
        let key = key_from_seed(1);
        let value = b"data".to_vec();

        let mut smt = PydeSMT::new();
        smt.insert(key, value.clone()).unwrap();
        let root = smt.root();

        // Proof verifies against correct root
        let proof = smt.prove(vec![key]).unwrap();
        assert!(proof.verify(root, vec![(key, value.clone())]));

        // Mutating the tree changes the root
        smt.insert(key, b"changed".to_vec()).unwrap();
        assert_ne!(root, smt.root());
    }

    // ========== Additional tests ==========

    #[test]
    fn insert_overwrite() {
        let mut smt = PydeSMT::new();
        let key = key_from_seed(1);
        smt.insert(key, b"first".to_vec()).unwrap();
        smt.insert(key, b"second".to_vec()).unwrap();
        assert_eq!(smt.get(&key), Some(b"second".to_vec()));
    }

    #[test]
    fn root_deterministic_regardless_of_order() {
        let k1 = key_from_seed(1);
        let k2 = key_from_seed(2);

        let mut smt1 = PydeSMT::new();
        smt1.insert(k1, b"a".to_vec()).unwrap();
        smt1.insert(k2, b"b".to_vec()).unwrap();

        let mut smt2 = PydeSMT::new();
        smt2.insert(k2, b"b".to_vec()).unwrap();
        smt2.insert(k1, b"a".to_vec()).unwrap();

        assert_eq!(smt1.root(), smt2.root());
    }

    #[test]
    fn batch_update() {
        let mut smt = PydeSMT::new();
        let entries: Vec<(Key, Vec<u8>)> = (0..100)
            .map(|i| (key_from_seed(i), format!("v{i}").into_bytes()))
            .collect();

        smt.update_all(entries.clone()).unwrap();

        for (k, v) in &entries {
            assert_eq!(smt.get(k), Some(v.clone()));
        }
    }

    #[test]
    fn empty_tree_is_empty() {
        let smt = PydeSMT::new();
        assert!(smt.is_empty());
    }

    #[test]
    fn verify_rejects_tampered_value() {
        let mut smt = PydeSMT::new();
        let key = key_from_seed(1);
        smt.insert(key, b"real".to_vec()).unwrap();

        let root = smt.root();
        let proof = smt.prove(vec![key]).unwrap();

        // Correct value passes
        assert!(proof.verify(root, vec![(key, b"real".to_vec())]));
        // Tampered value fails
        assert!(!proof.verify(root, vec![(key, b"fake".to_vec())]));
    }

    #[test]
    fn verify_rejects_wrong_root() {
        let mut smt = PydeSMT::new();
        let key = key_from_seed(1);
        let value = b"data".to_vec();
        smt.insert(key, value.clone()).unwrap();

        let root = smt.root();
        let proof = smt.prove(vec![key]).unwrap();

        // Correct root passes
        assert!(proof.verify(root, vec![(key, value.clone())]));
        // Wrong root fails
        let fake_root = H256::from(poseidon2_hash(b"wrong").to_bytes());
        assert!(!proof.verify(fake_root, vec![(key, value)]));
    }

    // ========== Compiled proof ==========

    #[test]
    fn compiled_proof_verifies() {
        let mut smt = PydeSMT::new();
        let key = key_from_seed(1);
        let value = b"value".to_vec();
        smt.insert(key, value.clone()).unwrap();

        let root = smt.root();
        let proof = smt.prove(vec![key]).unwrap();
        let compiled = proof.compile(vec![key]).unwrap();

        assert!(compiled.verify(root, vec![(key, value.clone())]));
        assert!(!compiled.verify(root, vec![(key, b"wrong".to_vec())]));
    }

}
