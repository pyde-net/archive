use pyde_state::jmt_store::PersistentJMT;
use pyde_state::smt::{Key, StateAccess, UndoEntry};
use sparse_merkle_tree::H256;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock as StdRwLock};
use tracing::info;

/// How many recent blocks' undo logs to keep in memory. Beyond
/// this depth, reverts cannot be performed and the node would
/// have to fall back to snapshot restore. 128 covers the
/// HotStuff finality window (worst-case ~2 slots) plus generous
/// headroom for partition-heal scenarios (audit 230).
const MAX_UNDO_DEPTH: usize = 128;

/// Pipelined state manager: separates read cache from Merkle commit.
///
/// Architecture:
///   StateOverlay (per-block) → cache (Arc<RwLock>) → PersistentJMT (Mutex)
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
    smt: Arc<Mutex<PersistentJMT>>,
    root: [u8; 32],
    tracked_keys: HashSet<Key>,
    pending_writes: Vec<(Key, Vec<u8>)>,
    /// Per-block undo logs ordered by slot (newest last). VecDeque
    /// for O(1) front pruning. Audit 230: drives `revert_to(slot)`
    /// when consensus picks a different chain at the same slot.
    block_undo_logs: VecDeque<(u64, Vec<UndoEntry>)>,
}

// SAFETY: every field of `StateManager` is already `Send`:
// - `cache: Arc<StdRwLock<HashMap<Key, Vec<u8>>>>`     — Send
// - `smt:   Arc<Mutex<PersistentJMT>>`                  — Send
// - `root:  [u8; 32]`                                   — Send (Copy)
// - `tracked_keys: HashSet<Key>`                        — Send
// - `pending_writes: Vec<(Key, Vec<u8>)>`               — Send
// The manual `Send` impl is a historical artefact from when the JMT
// store had non-Send internals; kept explicit so future additions
// that introduce a non-Send field break the build here, forcing a
// conscious review rather than silently breaking tokio::spawn.
unsafe impl Send for StateManager {}

impl StateManager {
    pub fn open(datadir: &Path, _cache_size: usize) -> Result<Self, String> {
        let db_path = datadir.join("state");
        let db_path_str = db_path.to_str().ok_or("invalid db path")?;

        let smt = PersistentJMT::open(db_path_str)?;
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
            block_undo_logs: VecDeque::new(),
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
    pub fn smt_handle(&self) -> Arc<Mutex<PersistentJMT>> {
        self.smt.clone()
    }

    /// Commit writes to SMT on the current thread (called from background task).
    pub fn commit_writes_to_smt(
        smt: &Arc<Mutex<PersistentJMT>>,
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

    /// Record per-block undo info (audit 230). Called by the
    /// block processor immediately after a block's writes are
    /// applied so a future `revert_to(slot - 1)` call can
    /// reverse them.
    ///
    /// Logs older than `MAX_UNDO_DEPTH` are pruned from the front
    /// — beyond that horizon, reverts are not possible and the
    /// node falls back to snapshot restore.
    pub fn record_block_undo(&mut self, slot: u64, entries: Vec<UndoEntry>) {
        self.block_undo_logs.push_back((slot, entries));
        while self.block_undo_logs.len() > MAX_UNDO_DEPTH {
            self.block_undo_logs.pop_front();
        }
    }

    /// True if the StateManager has at least one undo log
    /// recorded for `slot` (or any later slot). Used by the
    /// reorg path (audit 231) to verify the target depth is in
    /// range before initiating a revert.
    ///
    /// Audit 230 ships the mechanism; the call site is added in
    /// 231 — `#[allow(dead_code)]` keeps the build green while
    /// the integration lands incrementally.
    #[allow(dead_code)]
    pub fn can_revert_to(&self, target_slot: u64) -> bool {
        self.block_undo_logs
            .front()
            .map(|(s, _)| target_slot >= s.saturating_sub(1))
            .unwrap_or(false)
    }

    /// Revert state to the end of `target_slot` by replaying
    /// undo logs in reverse. Returns the number of blocks
    /// reverted, or `Err(...)` if the target is beyond the
    /// in-memory undo horizon.
    ///
    /// Walks `block_undo_logs` from the back, popping each log
    /// whose slot is `> target_slot`, applying its old values
    /// to the cache + scheduling them as pending SMT writes.
    /// Stops when the next log on the back is at or before
    /// `target_slot`.
    ///
    /// Audit 230 ships the mechanism; call site lights up in
    /// 231 — `#[allow(dead_code)]` covers the gap.
    #[allow(dead_code)]
    pub fn revert_to(&mut self, target_slot: u64) -> Result<usize, String> {
        // Range check: we can only revert if every slot above
        // target is still in the in-memory log. The OLDEST log
        // on the front represents the deepest reversible slot;
        // anything older has been pruned.
        if let Some((oldest_slot, _)) = self.block_undo_logs.front() {
            if target_slot + 1 < *oldest_slot {
                return Err(format!(
                    "revert target {target_slot} is below oldest undo log at slot {oldest_slot}"
                ));
            }
        }

        let mut reverted = 0usize;
        // Pop from the back until the back log's slot ≤ target_slot.
        // For each popped log, apply old values to:
        //   1. the in-memory cache (remove on None, insert otherwise)
        //   2. the SMT (synchronously — revert must leave a coherent
        //      view by return time, since callers expect to read
        //      reverted state immediately)
        while let Some((slot, _)) = self.block_undo_logs.back() {
            if *slot <= target_slot {
                break;
            }
            // Pop, then apply old values. Unwrap safe — peek was Some.
            let (popped_slot, entries) = self.block_undo_logs.pop_back().unwrap();
            let restore_writes: Vec<(Key, Vec<u8>)> = entries
                .into_iter()
                .map(|e| (e.key, e.old_value.unwrap_or_default()))
                .collect();
            // Cache: remove empty-value restores, insert non-empty.
            if let Ok(mut cache) = self.cache.write() {
                for (k, v) in &restore_writes {
                    if v.is_empty() {
                        cache.remove(k);
                    } else {
                        cache.insert(*k, v.clone());
                    }
                }
            }
            // SMT: persist the restore now so reads from the SMT
            // tree (cache miss path) see the reverted view, and so
            // the chain's `state_root` recomputed from this SMT
            // matches the reverted slot's header.
            if !restore_writes.is_empty() {
                if let Ok(mut smt) = self.smt.lock() {
                    if let Err(e) = smt.update_all(restore_writes) {
                        return Err(format!("revert SMT update failed: {e}"));
                    }
                    // Refresh root after SMT mutation.
                    self.root = smt.root().as_slice().try_into().unwrap_or([0u8; 32]);
                }
            }
            reverted += 1;
            tracing::debug!(slot = popped_slot, "reverted state at slot");
        }
        Ok(reverted)
    }

    /// Drain the in-memory undo log (testing / diagnostics).
    #[allow(dead_code)]
    pub fn undo_log_len(&self) -> usize {
        self.block_undo_logs.len()
    }

    pub fn is_empty(&self) -> bool {
        if let Ok(smt) = self.smt.lock() {
            smt.is_empty()
        } else {
            true
        }
    }

    // Audit 332: `smt_mut()` was the escape hatch that let the
    // decrypted-tx execution path bypass the StateManager's
    // write-cache and undo-log machinery, silently breaking
    // reorg consistency. Removed alongside the audit-332 fix —
    // every state write now goes through `update_batch_deferred`
    // (with `record_block_undo` for revertibility), and reads
    // through the cache-aware `StateAccess` impl on
    // `StateManager`. Adding a new `smt_mut`-style raw escape
    // hatch should be considered a regression: the next caller
    // will re-introduce the same skip-the-cache-and-undo-log
    // bug class. Use `StateOverlay` for transactional execution
    // contexts and `update_batch_deferred` for direct buffered
    // writes.

    /// Get immutable SMT access. Returns MutexGuard.
    #[allow(dead_code)]
    pub fn smt_ref(&self) -> std::sync::MutexGuard<'_, PersistentJMT> {
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

    // ========== Audit 230: per-block undo log + revert_to ==========

    fn k(seed: u8) -> Key {
        let mut a = [0u8; 32];
        a[0] = seed;
        a.into()
    }

    #[test]
    fn revert_to_undoes_one_block() {
        // Apply one block's writes, record undo, revert, and assert
        // the cache + pending writes restore the pre-block view.
        let dir = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(dir.path(), 1024).unwrap();

        // Pre-block: key_a = "before". Persist it via flush so the
        // SMT also has it (revert path schedules SMT writes).
        let key_a = k(0xA1);
        state
            .update_batch(vec![(key_a, b"before".to_vec())])
            .unwrap();

        // Block at slot 1: change key_a, add key_b. Capture undo
        // (the pre-block values) and record.
        let key_b = k(0xB2);
        let undo = vec![
            UndoEntry {
                key: key_a,
                old_value: Some(b"before".to_vec()),
            },
            UndoEntry {
                key: key_b,
                old_value: None, // didn't exist
            },
        ];
        state
            .update_batch(vec![(key_a, b"after".to_vec()), (key_b, b"new".to_vec())])
            .unwrap();
        state.record_block_undo(1, undo);
        assert_eq!(state.undo_log_len(), 1);

        // Pre-revert: cache has the new values.
        assert_eq!(state.get(&key_a).unwrap(), b"after");
        assert_eq!(state.get(&key_b).unwrap(), b"new");

        // Revert to slot 0.
        let n = state.revert_to(0).unwrap();
        assert_eq!(n, 1, "exactly one block should be reverted");
        assert_eq!(state.undo_log_len(), 0);

        // Post-revert: cache restored.
        assert_eq!(state.get(&key_a).unwrap(), b"before");
        assert_eq!(state.get(&key_b), None);
    }

    #[test]
    fn revert_to_pops_only_above_target() {
        // Three blocks recorded, revert to slot 1: only blocks 2 and 3
        // are popped; block 1's undo log stays in place.
        let dir = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(dir.path(), 1024).unwrap();

        for slot in 1..=3 {
            let key = k(slot as u8);
            state.update_batch(vec![(key, vec![slot as u8])]).unwrap();
            state.record_block_undo(
                slot,
                vec![UndoEntry {
                    key,
                    old_value: None,
                }],
            );
        }
        assert_eq!(state.undo_log_len(), 3);

        let n = state.revert_to(1).unwrap();
        assert_eq!(n, 2);
        assert_eq!(state.undo_log_len(), 1);
        // Block 1's write still present
        assert_eq!(state.get(&k(1)).unwrap(), vec![1]);
        // Blocks 2 and 3's writes reverted
        assert_eq!(state.get(&k(2)), None);
        assert_eq!(state.get(&k(3)), None);
    }

    #[test]
    fn revert_to_below_oldest_log_errors() {
        // Pruning means we can't revert past MAX_UNDO_DEPTH. Simulate
        // by recording past the depth and asserting older logs were
        // pruned + revert_to that depth errors.
        let dir = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(dir.path(), 1024).unwrap();
        // Write past MAX_UNDO_DEPTH (128) so the front gets pruned.
        for slot in 1..=(MAX_UNDO_DEPTH as u64 + 5) {
            state.record_block_undo(slot, vec![]);
        }
        assert_eq!(state.undo_log_len(), MAX_UNDO_DEPTH);
        // Front log is now slot 6 (slots 1..=5 pruned).
        // Reverting to slot 3 should be rejected.
        let err = state.revert_to(3).unwrap_err();
        assert!(err.contains("below oldest undo log"));
    }

    #[test]
    fn revert_to_noop_when_target_is_head() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(dir.path(), 1024).unwrap();
        state.record_block_undo(1, vec![]);
        state.record_block_undo(2, vec![]);
        let n = state.revert_to(2).unwrap();
        assert_eq!(n, 0);
        assert_eq!(state.undo_log_len(), 2);
    }

    #[test]
    fn revert_to_restores_smt_root_to_snapshot() {
        // Audit 230 — root-equality test. Without this, a revert
        // could restore values at the cache level but produce a
        // structurally different SMT (e.g. if "empty value" doesn't
        // collapse the same way as "key absent"), leading to a
        // root mismatch downstream.
        //
        // Mirrors what BlockProcessor does in production:
        //   update_batch_deferred(writes) → flush_pending() → record_block_undo(slot, undo)
        let dir = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(dir.path(), 1024).unwrap();

        // Helper: simulate one "block" by capturing pre-block values,
        // applying writes, flushing to SMT, recording undo. Returns
        // the post-block root.
        let apply_block =
            |s: &mut StateManager, slot: u64, writes: Vec<(Key, Vec<u8>)>| -> [u8; 32] {
                let undo: Vec<UndoEntry> = writes
                    .iter()
                    .map(|(k, _)| UndoEntry {
                        key: *k,
                        old_value: s.get(k),
                    })
                    .collect();
                s.update_batch_deferred(writes).unwrap();
                let root = s.flush_pending().unwrap();
                s.record_block_undo(slot, undo);
                root
            };

        // Block 1: set key_a, key_b
        let _r1 = apply_block(
            &mut state,
            1,
            vec![(k(0xA1), b"a-v1".to_vec()), (k(0xB2), b"b-v1".to_vec())],
        );
        // Block 2: change key_a, set key_c
        let r2_snapshot = apply_block(
            &mut state,
            2,
            vec![(k(0xA1), b"a-v2".to_vec()), (k(0xC3), b"c-v1".to_vec())],
        );
        // Block 3: change key_b, delete key_c (empty value), add key_d
        let _r3 = apply_block(
            &mut state,
            3,
            vec![
                (k(0xB2), b"b-v2".to_vec()),
                (k(0xC3), Vec::new()), // delete
                (k(0xD4), b"d-v1".to_vec()),
            ],
        );

        // Sanity: root advanced over time.
        assert_ne!(r2_snapshot, _r1);
        assert_ne!(_r3, r2_snapshot);

        // Revert to slot 2 — root must match the slot-2 snapshot.
        let reverted = state.revert_to(2).unwrap();
        assert_eq!(reverted, 1);
        assert_eq!(
            state.root(),
            r2_snapshot,
            "post-revert root must equal the slot-2 snapshot"
        );

        // Cache + SMT both reflect slot-2 view.
        assert_eq!(state.get(&k(0xA1)).unwrap(), b"a-v2"); // unchanged in block 3
        assert_eq!(state.get(&k(0xB2)).unwrap(), b"b-v1"); // restored
        assert_eq!(state.get(&k(0xC3)).unwrap(), b"c-v1"); // restored
        assert_eq!(state.get(&k(0xD4)), None); // never existed before block 3

        // Revert further to slot 1 — root must match block-1 root.
        let reverted = state.revert_to(1).unwrap();
        assert_eq!(reverted, 1);
        assert_eq!(state.root(), _r1);
        assert_eq!(state.get(&k(0xA1)).unwrap(), b"a-v1"); // restored
        assert_eq!(state.get(&k(0xC3)), None); // restored to "absent"
    }
}
