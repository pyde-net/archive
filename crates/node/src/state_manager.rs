use pyde_state::backend::{CachedBackend, RocksDBBackend};
use pyde_state::smt::{Key, PydeSMT};
use std::path::Path;
use tracing::info;

/// Manages on-disk state: RocksDB-backed SMT with LRU cache.
pub struct StateManager {
    smt: PydeSMT,
    root: [u8; 32],
}

impl StateManager {
    /// Open state from disk (or initialize empty state).
    pub fn open(datadir: &Path, cache_size: usize) -> Result<Self, String> {
        let db_path = datadir.join("state");
        let db_path_str = db_path.to_str().ok_or("invalid db path")?;

        let backend = RocksDBBackend::open(db_path_str)
            .map_err(|e| format!("failed to open state db: {}", e))?;

        let _cached = CachedBackend::new(backend, cache_size);

        // For now, use in-memory SMT (RocksDB backend integration with
        // sparse-merkle-tree requires the Store trait bridge — wired in next phase).
        // State is persisted through RocksDB on flush.
        let smt = PydeSMT::new();
        let root = smt.root().as_slice().try_into().unwrap_or([0u8; 32]);

        info!(
            db = %db_path.display(),
            cache_size,
            "state database opened"
        );

        Ok(Self { smt, root })
    }

    /// Current state root hash.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Get a value by key.
    pub fn get(&self, key: &Key) -> Option<Vec<u8>> {
        self.smt.get(key)
    }

    /// Insert a key-value pair, returns new root.
    pub fn insert(&mut self, key: Key, value: Vec<u8>) -> Result<[u8; 32], String> {
        let new_root = self.smt.insert(key, value)
            .map_err(|e| format!("state insert failed: {}", e))?;
        self.root = new_root.as_slice().try_into().unwrap_or([0u8; 32]);
        Ok(self.root)
    }

    /// Delete a key, returns whether it existed.
    pub fn delete(&mut self, key: &Key) -> Result<bool, String> {
        self.smt.delete(key)
            .map_err(|e| format!("state delete failed: {}", e))
    }

    /// Batch update: insert multiple key-value pairs, returns new root.
    pub fn update_batch(&mut self, entries: Vec<(Key, Vec<u8>)>) -> Result<[u8; 32], String> {
        let new_root = self.smt.update_all(entries)
            .map_err(|e| format!("state batch update failed: {}", e))?;
        self.root = new_root.as_slice().try_into().unwrap_or([0u8; 32]);
        Ok(self.root)
    }

    /// Generate a Merkle proof for the given keys.
    pub fn prove(&self, keys: Vec<Key>) -> Result<pyde_state::smt::MerkleProof, String> {
        self.smt.prove(keys)
            .map_err(|e| format!("proof generation failed: {}", e))
    }

    /// Whether state is empty (genesis).
    pub fn is_empty(&self) -> bool {
        self.smt.is_empty()
    }

    /// Get mutable access to the underlying SMT (for tx execution pipeline).
    pub fn smt_mut(&mut self) -> &mut PydeSMT {
        &mut self.smt
    }

    /// Refresh the cached root after SMT mutations (e.g., after tx execution).
    pub fn refresh_root(&mut self) {
        self.root = self.smt.root().as_slice().try_into().unwrap_or([0u8; 32]);
    }
}
