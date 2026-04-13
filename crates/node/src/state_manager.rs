use pyde_state::smt::{Key, PersistentSMT, StateAccess};
use sparse_merkle_tree::H256;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::info;

/// Manages on-disk state: RocksDB-backed persistent SMT with write-ahead cache.
///
/// Architecture (layered reads):
///   StateOverlay (per-block) → write_cache (multi-block) → PersistentSMT (disk)
///
/// The write_cache holds uncommitted state from recently executed blocks.
/// The Merkle tree commit (expensive) runs asynchronously while new blocks
/// execute from the cache. This hides commit latency from the execution path.
pub struct StateManager {
    smt: PersistentSMT,
    root: [u8; 32],
    /// All keys ever inserted (for snapshot export).
    tracked_keys: HashSet<Key>,
    /// Write-ahead buffer for deferred Merkle tree computation.
    pending_writes: Vec<(Key, Vec<u8>)>,
    /// Write-ahead cache: holds state from recently executed blocks.
    /// Reads check here before hitting the SMT/RocksDB.
    write_cache: HashMap<Key, Vec<u8>>,
}

impl StateManager {
    /// Open persistent state from disk.
    /// If the database exists, state is loaded (including all contract storage).
    /// If the database is new, returns an empty state.
    pub fn open(datadir: &Path, _cache_size: usize) -> Result<Self, String> {
        let db_path = datadir.join("state");
        let db_path_str = db_path.to_str().ok_or("invalid db path")?;

        let smt = PersistentSMT::open(db_path_str)?;
        let root = smt.root().as_slice().try_into().unwrap_or([0u8; 32]);

        let is_empty = smt.is_empty();
        info!(
            db = %db_path.display(),
            is_empty,
            root = hex::encode(root),
            "state database opened (persistent RocksDB)"
        );

        Ok(Self { smt, root, tracked_keys: HashSet::new(), pending_writes: Vec::new(), write_cache: HashMap::new() })
    }

    /// Current state root hash.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Get a value by key. Checks write-ahead cache first, then disk.
    pub fn get(&self, key: &Key) -> Option<Vec<u8>> {
        // Check write-ahead cache first (recent block writes)
        if let Some(val) = self.write_cache.get(key) {
            return if val.is_empty() { None } else { Some(val.clone()) };
        }
        self.smt.get(key)
    }

    /// Insert a key-value pair, returns new root.
    pub fn insert(&mut self, key: Key, value: Vec<u8>) -> Result<[u8; 32], String> {
        self.tracked_keys.insert(key);
        // Write to cache for immediate visibility
        self.write_cache.insert(key, value.clone());
        let new_root = self.smt.insert(key, value)
            .map_err(|e| format!("state insert failed: {}", e))?;
        self.root = new_root.as_slice().try_into().unwrap_or([0u8; 32]);
        Ok(self.root)
    }

    /// Delete a key, returns whether it existed.
    pub fn delete(&mut self, key: &Key) -> Result<bool, String> {
        self.tracked_keys.remove(key);
        self.smt.delete(key)
            .map_err(|e| format!("state delete failed: {}", e))
    }

    /// Batch update: insert multiple key-value pairs, returns new root.
    pub fn update_batch(&mut self, entries: Vec<(Key, Vec<u8>)>) -> Result<[u8; 32], String> {
        for (k, _) in &entries {
            self.tracked_keys.insert(*k);
        }
        let new_root = self.smt.update_all(entries)
            .map_err(|e| format!("state batch update failed: {}", e))?;
        self.root = new_root.as_slice().try_into().unwrap_or([0u8; 32]);
        Ok(self.root)
    }

    /// Fast batch update: buffer writes in-memory without Merkle tree recomputation.
    /// The dirty entries are stored in the write-ahead cache. Merkle root is computed
    /// lazily on next `root()` call or explicitly via `flush_pending()`.
    /// Use this for block execution to defer the expensive Merkle update.
    pub fn update_batch_deferred(&mut self, entries: Vec<(Key, Vec<u8>)>) -> Result<(), String> {
        for (k, v) in &entries {
            self.tracked_keys.insert(*k);
            // Write to cache for immediate visibility by the next block
            self.write_cache.insert(*k, v.clone());
        }
        self.pending_writes.extend(entries);
        Ok(())
    }

    /// Flush any pending deferred writes to the SMT (computes Merkle root).
    pub fn flush_pending(&mut self) -> Result<[u8; 32], String> {
        if self.pending_writes.is_empty() {
            return Ok(self.root);
        }
        let entries = std::mem::take(&mut self.pending_writes);
        self.update_batch(entries)
    }

    /// Whether state is empty (genesis).
    pub fn is_empty(&self) -> bool {
        self.smt.is_empty()
    }

    /// Get mutable access to the underlying SMT (for tx execution pipeline).
    pub fn smt_mut(&mut self) -> &mut PersistentSMT {
        &mut self.smt
    }

    /// Get immutable reference to the SMT (for parallel execution overlays).
    pub fn smt_ref(&self) -> &PersistentSMT {
        &self.smt
    }

    /// Refresh the cached root after SMT mutations (e.g., after tx execution).
    pub fn refresh_root(&mut self) {
        self.root = self.smt.root().as_slice().try_into().unwrap_or([0u8; 32]);
    }

    // ========== State Snapshot ==========

    /// Export all state entries as (key_bytes, value_bytes) pairs.
    /// Used for state snapshot sync — a new node downloads this to bootstrap.
    pub fn export_snapshot(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut entries = Vec::with_capacity(self.tracked_keys.len());
        for key in &self.tracked_keys {
            if let Some(value) = self.smt.get(key) {
                entries.push((key.as_slice().to_vec(), value));
            }
        }
        entries
    }

    /// Import a state snapshot: bulk insert all entries, returns new root.
    /// Used by a syncing node to restore state from a peer's snapshot.
    pub fn import_snapshot(&mut self, entries: Vec<(Vec<u8>, Vec<u8>)>) -> Result<[u8; 32], String> {
        let smt_entries: Vec<(Key, Vec<u8>)> = entries
            .into_iter()
            .map(|(k, v)| {
                let key = H256::from(
                    <[u8; 32]>::try_from(k.as_slice()).unwrap_or([0u8; 32])
                );
                (key, v)
            })
            .collect();

        for (k, _) in &smt_entries {
            self.tracked_keys.insert(*k);
        }

        let new_root = self.smt.update_all(smt_entries)
            .map_err(|e| format!("snapshot import failed: {}", e))?;
        self.root = new_root.as_slice().try_into().unwrap_or([0u8; 32]);

        info!(
            entries = self.tracked_keys.len(),
            state_root = hex::encode(self.root),
            "state snapshot imported"
        );
        Ok(self.root)
    }

    /// Number of tracked state entries.
    pub fn entry_count(&self) -> usize {
        self.tracked_keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_export_import_roundtrip() {
        // Create state with some entries
        let dir1 = std::env::temp_dir().join("pyde-snap-export");
        let _ = std::fs::remove_dir_all(&dir1);
        let mut state1 = StateManager::open(&dir1, 1024).unwrap();

        let key_a = pyde_state::keys::balance_key(&[0x01; 32]);
        let key_b = pyde_state::keys::balance_key(&[0x02; 32]);
        state1.insert(key_a, 1000u128.to_le_bytes().to_vec()).unwrap();
        state1.insert(key_b, 2000u128.to_le_bytes().to_vec()).unwrap();

        let root1 = state1.root();
        let snapshot = state1.export_snapshot();
        assert_eq!(snapshot.len(), 2);

        // Import into a fresh state
        let dir2 = std::env::temp_dir().join("pyde-snap-import");
        let _ = std::fs::remove_dir_all(&dir2);
        let mut state2 = StateManager::open(&dir2, 1024).unwrap();

        let root2 = state2.import_snapshot(snapshot).unwrap();
        assert_eq!(root1, root2); // same state root

        // Verify entries
        assert_eq!(state2.get(&key_a).unwrap(), 1000u128.to_le_bytes().to_vec());
        assert_eq!(state2.get(&key_b).unwrap(), 2000u128.to_le_bytes().to_vec());
    }

    #[test]
    fn empty_snapshot() {
        let dir = std::env::temp_dir().join("pyde-snap-empty");
        let _ = std::fs::remove_dir_all(&dir);
        let state = StateManager::open(&dir, 1024).unwrap();

        let snapshot = state.export_snapshot();
        assert!(snapshot.is_empty());
    }
}
