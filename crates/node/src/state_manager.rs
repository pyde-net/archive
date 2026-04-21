use pyde_state::smt::{Key, PersistentSMT, StateAccess};
use sparse_merkle_tree::H256;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock as StdRwLock};
use tracing::info;

/// Pipelined state manager: separates read cache from Merkle commit.
///
/// Architecture:
///   StateOverlay (per-block) → cache (Arc<RwLock>) → PersistentSMT (Mutex)
///
/// - Execution: reads from cache (shared, fast), writes to overlay → cache
/// - Background commit: takes SMT mutex, writes Merkle tree (slow, exclusive)
/// - No contention: execution reads cache while commit writes SMT
pub struct StateManager {
    /// Shared read cache: holds ALL recent state. Checked before SMT.
    /// Protected by std::sync::RwLock for concurrent reads during execution.
    cache: Arc<StdRwLock<HashMap<Key, Vec<u8>>>>,
    /// Persistent SMT: Merkle tree + RocksDB. Only touched during commit.
    /// Protected by Mutex so commit can run on a background thread.
    smt: Arc<Mutex<PersistentSMT>>,
    root: [u8; 32],
    tracked_keys: HashSet<Key>,
    pending_writes: Vec<(Key, Vec<u8>)>,
}

// StateManager is Send (for Arc<RwLock>/Arc<Mutex>)
unsafe impl Send for StateManager {}

impl StateManager {
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

        Ok(Self {
            cache: Arc::new(StdRwLock::new(HashMap::new())),
            smt: Arc::new(Mutex::new(smt)),
            root,
            tracked_keys: HashSet::new(),
            pending_writes: Vec::new(),
        })
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Get a value. Checks cache first (fast), then SMT/RocksDB (slow).
    pub fn get(&self, key: &Key) -> Option<Vec<u8>> {
        if let Ok(cache) = self.cache.read() {
            if let Some(val) = cache.get(key) {
                return if val.is_empty() {
                    None
                } else {
                    Some(val.clone())
                };
            }
        }
        if let Ok(smt) = self.smt.lock() {
            smt.get(key)
        } else {
            None
        }
    }

    /// Take a read-consistent snapshot of the cache + SMT for static calls.
    /// Returns a closure that reads from the frozen snapshot, immune to
    /// concurrent cache writes from the block processor or Merkle commit.
    pub fn snapshot_reader(&self) -> impl Fn(&Key) -> Option<Vec<u8>> + Send + Sync {
        // Clone the entire cache — this is O(n) but pyde_call is infrequent.
        let cache_snap: HashMap<Key, Vec<u8>> =
            self.cache.read().map(|c| c.clone()).unwrap_or_default();
        let smt = Arc::clone(&self.smt);
        move |key: &Key| -> Option<Vec<u8>> {
            if let Some(val) = cache_snap.get(key) {
                return if val.is_empty() {
                    None
                } else {
                    Some(val.clone())
                };
            }
            if let Ok(smt) = smt.lock() {
                smt.get(key)
            } else {
                None
            }
        }
    }

    /// Insert directly (used during genesis, bypasses deferred path).
    pub fn insert(&mut self, key: Key, value: Vec<u8>) -> Result<[u8; 32], String> {
        self.tracked_keys.insert(key);
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(key, value.clone());
        }
        let mut smt = self.smt.lock().map_err(|e| format!("smt lock: {}", e))?;
        let new_root = smt
            .insert(key, value)
            .map_err(|e| format!("state insert failed: {}", e))?;
        self.root = new_root.as_slice().try_into().unwrap_or([0u8; 32]);
        Ok(self.root)
    }

    #[allow(dead_code)]
    pub fn delete(&mut self, key: &Key) -> Result<bool, String> {
        self.tracked_keys.remove(key);
        let mut smt = self.smt.lock().map_err(|e| format!("smt lock: {}", e))?;
        smt.delete(key)
            .map_err(|e| format!("state delete failed: {}", e))
    }

    pub fn update_batch(&mut self, entries: Vec<(Key, Vec<u8>)>) -> Result<[u8; 32], String> {
        for (k, _) in &entries {
            self.tracked_keys.insert(*k);
        }
        let mut smt = self.smt.lock().map_err(|e| format!("smt lock: {}", e))?;
        let new_root = smt
            .update_all(entries)
            .map_err(|e| format!("state batch update failed: {}", e))?;
        self.root = new_root.as_slice().try_into().unwrap_or([0u8; 32]);
        Ok(self.root)
    }

    /// Buffer writes in cache (instant). Merkle commit deferred.
    pub fn update_batch_deferred(&mut self, entries: Vec<(Key, Vec<u8>)>) -> Result<(), String> {
        if let Ok(mut cache) = self.cache.write() {
            for (k, v) in &entries {
                self.tracked_keys.insert(*k);
                cache.insert(*k, v.clone());
            }
        }
        self.pending_writes.extend(entries);
        Ok(())
    }

    /// Flush pending writes synchronously.
    pub fn flush_pending(&mut self) -> Result<[u8; 32], String> {
        if self.pending_writes.is_empty() {
            return Ok(self.root);
        }
        let entries = std::mem::take(&mut self.pending_writes);
        self.update_batch(entries)
    }

    /// Extract pending writes for async commit.
    pub fn take_pending_writes(&mut self) -> Vec<(Key, Vec<u8>)> {
        std::mem::take(&mut self.pending_writes)
    }

    /// Get a clone of the SMT Arc for background commit.
    pub fn smt_handle(&self) -> Arc<Mutex<PersistentSMT>> {
        self.smt.clone()
    }

    /// Commit writes to SMT on the current thread (called from background task).
    pub fn commit_writes_to_smt(
        smt: &Arc<Mutex<PersistentSMT>>,
        entries: Vec<(Key, Vec<u8>)>,
    ) -> Result<[u8; 32], String> {
        let mut smt = smt.lock().map_err(|e| format!("smt lock: {}", e))?;
        let root = smt
            .update_all(entries)
            .map_err(|e| format!("commit failed: {}", e))?;
        Ok(root.as_slice().try_into().unwrap_or([0u8; 32]))
    }

    /// Update root after background commit.
    pub fn set_root(&mut self, root: [u8; 32]) {
        self.root = root;
    }

    pub fn is_empty(&self) -> bool {
        if let Ok(smt) = self.smt.lock() {
            smt.is_empty()
        } else {
            true
        }
    }

    /// Get mutable SMT access. Returns MutexGuard (deref to PersistentSMT).
    /// Only used during genesis/startup — not during pipelined execution.
    pub fn smt_mut(&self) -> std::sync::MutexGuard<'_, PersistentSMT> {
        self.smt.lock().expect("smt lock poisoned")
    }

    /// Get immutable SMT access. Returns MutexGuard.
    #[allow(dead_code)]
    pub fn smt_ref(&self) -> std::sync::MutexGuard<'_, PersistentSMT> {
        self.smt.lock().expect("smt lock poisoned")
    }

    pub fn refresh_root(&mut self) {
        if let Ok(smt) = self.smt.lock() {
            self.root = smt.root().as_slice().try_into().unwrap_or([0u8; 32]);
        }
    }

    pub fn export_snapshot(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let smt = self.smt.lock().unwrap();
        let mut entries = Vec::with_capacity(self.tracked_keys.len());
        for key in &self.tracked_keys {
            if let Some(value) = smt.get(key) {
                entries.push((key.as_slice().to_vec(), value));
            }
        }
        entries
    }

    pub fn import_snapshot(
        &mut self,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<[u8; 32], String> {
        let smt_entries: Vec<(Key, Vec<u8>)> = entries
            .into_iter()
            .map(|(k, v)| {
                let key = H256::from(<[u8; 32]>::try_from(k.as_slice()).unwrap_or([0u8; 32]));
                (key, v)
            })
            .collect();
        for (k, _) in &smt_entries {
            self.tracked_keys.insert(*k);
        }
        let mut smt = self.smt.lock().map_err(|e| format!("smt lock: {}", e))?;
        let new_root = smt
            .update_all(smt_entries)
            .map_err(|e| format!("snapshot import failed: {}", e))?;
        self.root = new_root.as_slice().try_into().unwrap_or([0u8; 32]);
        info!(
            entries = self.tracked_keys.len(),
            state_root = hex::encode(self.root),
            "state snapshot imported"
        );
        Ok(self.root)
    }

    #[allow(dead_code)]
    pub fn entry_count(&self) -> usize {
        self.tracked_keys.len()
    }
}

/// StateAccess impl so StateOverlay can use StateManager as its base.
/// Reads go through the write-ahead cache first, then SMT.
impl StateAccess for StateManager {
    fn get(&self, key: &Key) -> Option<Vec<u8>> {
        self.get(key)
    }
    fn insert(&mut self, key: Key, value: Vec<u8>) -> Result<H256, &'static str> {
        // Write to cache only (deferred). Returns dummy root.
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(key, value.clone());
        }
        self.tracked_keys.insert(key);
        self.pending_writes.push((key, value));
        Ok(H256::zero())
    }
    fn root(&self) -> H256 {
        H256::from(self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_export_import_roundtrip() {
        let dir1 = tempfile::tempdir().unwrap();
        let mut state1 = StateManager::open(dir1.path(), 1024).unwrap();
        let key_a = pyde_state::keys::balance_key(&[0x01; 32]);
        let key_b = pyde_state::keys::balance_key(&[0x02; 32]);
        state1
            .insert(key_a, 1000u128.to_le_bytes().to_vec())
            .unwrap();
        state1
            .insert(key_b, 2000u128.to_le_bytes().to_vec())
            .unwrap();
        let root1 = state1.root();
        let snapshot = state1.export_snapshot();
        assert_eq!(snapshot.len(), 2);

        let dir2 = tempfile::tempdir().unwrap();
        let mut state2 = StateManager::open(dir2.path(), 1024).unwrap();
        let root2 = state2.import_snapshot(snapshot).unwrap();
        assert_eq!(root1, root2);
        assert_eq!(state2.get(&key_a).unwrap(), 1000u128.to_le_bytes().to_vec());
        assert_eq!(state2.get(&key_b).unwrap(), 2000u128.to_le_bytes().to_vec());
    }

    #[test]
    fn empty_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateManager::open(dir.path(), 1024).unwrap();
        assert!(state.export_snapshot().is_empty());
    }
}
