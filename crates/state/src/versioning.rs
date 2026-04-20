//! State versioning: undo logs for reorgs and historical state queries.
//!
//! Each block application records an undo log (the old values before changes).
//! To revert a block, the undo log is replayed in reverse. Historical state
//! queries walk backward through undo logs from the current state.

use crate::smt::{Key, PydeSMT};
use sparse_merkle_tree::H256;
use std::collections::VecDeque;

/// Maximum number of undo logs to keep (oldest pruned beyond this).
const DEFAULT_MAX_UNDO_DEPTH: usize = 128;

/// A single state change: old value before the block was applied.
#[derive(Clone, Debug)]
pub struct UndoEntry {
    pub key: Key,
    /// The value before the block. `None` = key didn't exist.
    pub old_value: Option<Vec<u8>>,
}

/// Undo log for a single block: everything needed to revert it.
#[derive(Clone, Debug)]
pub struct UndoLog {
    /// Block height this log belongs to.
    pub height: u64,
    /// State root before this block was applied.
    pub pre_root: H256,
    /// State root after this block was applied.
    pub post_root: H256,
    /// Old values for every key modified by this block.
    pub entries: Vec<UndoEntry>,
}

/// Versioned state manager: wraps a PydeSMT with undo log history.
pub struct VersionedState {
    /// The current state tree.
    pub smt: PydeSMT,
    /// Current block height.
    pub height: u64,
    /// Undo logs ordered by height (newest last). VecDeque for O(1) front pruning.
    undo_logs: VecDeque<UndoLog>,
    /// Maximum undo logs to keep.
    max_depth: usize,
}

impl VersionedState {
    /// Create a new versioned state at height 0.
    pub fn new() -> Self {
        Self {
            smt: PydeSMT::new(),
            height: 0,
            undo_logs: VecDeque::new(),
            max_depth: DEFAULT_MAX_UNDO_DEPTH,
        }
    }

    /// Create with a custom max undo depth.
    pub fn with_max_depth(max_depth: usize) -> Self {
        Self {
            max_depth,
            ..Self::new()
        }
    }

    /// Current state root.
    pub fn root(&self) -> H256 {
        self.smt.root()
    }

    /// Get a value from current state.
    pub fn get(&self, key: &Key) -> Option<Vec<u8>> {
        self.smt.get(key)
    }

    /// Apply a block: record undo log, then apply diffs.
    /// `diffs` is a list of (key, new_value). Empty value = deletion.
    /// Returns the new state root.
    pub fn apply_block(&mut self, diffs: Vec<(Key, Vec<u8>)>) -> Result<H256, &'static str> {
        let pre_root = self.smt.root();

        // Record old values for undo
        let entries: Vec<UndoEntry> = diffs
            .iter()
            .map(|(k, _)| UndoEntry {
                key: *k,
                old_value: self.smt.get(k),
            })
            .collect();

        // Apply diffs
        let post_root = self.smt.update_all(diffs)?;

        self.height += 1;

        self.undo_logs.push_back(UndoLog {
            height: self.height,
            pre_root,
            post_root,
            entries,
        });

        // Prune old logs
        self.prune();

        Ok(post_root)
    }

    /// Undo the last block: revert state to before it was applied.
    /// Returns the restored root, or None if no blocks to undo.
    pub fn undo_block(&mut self) -> Result<Option<H256>, &'static str> {
        let log = match self.undo_logs.pop_back() {
            Some(log) => log,
            None => return Ok(None),
        };

        // Replay old values
        let restore_diffs: Vec<(Key, Vec<u8>)> = log
            .entries
            .iter()
            .map(|e| (e.key, e.old_value.clone().unwrap_or_default()))
            .collect();

        self.smt.update_all(restore_diffs)?;
        self.height -= 1;

        Ok(Some(log.pre_root))
    }

    /// Undo multiple blocks (for reorgs).
    /// Returns the root after undoing `count` blocks, or None if not enough history.
    pub fn undo_blocks(&mut self, count: usize) -> Result<Option<H256>, &'static str> {
        if count > self.undo_logs.len() {
            return Ok(None);
        }
        let mut root = H256::zero();
        for _ in 0..count {
            match self.undo_block()? {
                Some(r) => root = r,
                None => return Ok(None),
            }
        }
        Ok(Some(root))
    }

    /// Query the state value at a specific historical height.
    /// Walks backward through undo logs from current state.
    /// Returns None if the height is beyond undo history or has been pruned.
    pub fn get_at_height(&self, key: &Key, target_height: u64) -> Option<Vec<u8>> {
        if target_height > self.height {
            return None;
        }
        if target_height == self.height {
            return self.get(key);
        }

        // Reject queries for heights that have been pruned away
        if target_height < self.oldest_available_height() {
            return None;
        }

        // Walk undo logs backward
        let mut value = self.get(key);
        for log in self.undo_logs.iter().rev() {
            if log.height <= target_height {
                break;
            }
            // If this block modified the key, use the old value
            for entry in &log.entries {
                if entry.key == *key {
                    value = entry.old_value.clone();
                }
            }
        }
        value
    }

    /// The oldest height we can query (limited by undo log pruning).
    pub fn oldest_available_height(&self) -> u64 {
        self.undo_logs
            .front()
            .map(|log| log.height - 1)
            .unwrap_or(self.height)
    }

    /// Number of undo logs currently stored.
    pub fn undo_depth(&self) -> usize {
        self.undo_logs.len()
    }

    /// Prune undo logs beyond max_depth.
    fn prune(&mut self) {
        while self.undo_logs.len() > self.max_depth {
            self.undo_logs.pop_front();
        }
    }
}

impl Default for VersionedState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smt::key_from_seed;

    // ========== Task 0330: Apply block, undo block ==========

    #[test]
    fn apply_and_undo_single_block() {
        let mut vs = VersionedState::new();
        let key = key_from_seed(1);

        let empty_root = vs.root();
        vs.apply_block(vec![(key, b"hello".to_vec())]).unwrap();
        assert_eq!(vs.get(&key), Some(b"hello".to_vec()));
        assert_ne!(vs.root(), empty_root);
        assert_eq!(vs.height, 1);

        // Undo
        let restored = vs.undo_block().unwrap().unwrap();
        assert_eq!(restored, empty_root);
        assert_eq!(vs.get(&key), None);
        assert_eq!(vs.height, 0);
    }

    #[test]
    fn apply_modify_undo_restores_old_value() {
        let mut vs = VersionedState::new();
        let key = key_from_seed(1);

        vs.apply_block(vec![(key, b"first".to_vec())]).unwrap();
        let root_after_first = vs.root();

        vs.apply_block(vec![(key, b"second".to_vec())]).unwrap();
        assert_eq!(vs.get(&key), Some(b"second".to_vec()));

        vs.undo_block().unwrap();
        assert_eq!(vs.get(&key), Some(b"first".to_vec()));
        assert_eq!(vs.root(), root_after_first);
    }

    #[test]
    fn undo_with_no_blocks_returns_none() {
        let mut vs = VersionedState::new();
        assert_eq!(vs.undo_block().unwrap(), None);
    }

    // ========== Task 0331: Multi-block undo (reorg) ==========

    #[test]
    fn multi_block_undo() {
        let mut vs = VersionedState::new();
        let k1 = key_from_seed(1);
        let k2 = key_from_seed(2);

        let root0 = vs.root();
        vs.apply_block(vec![(k1, b"a".to_vec())]).unwrap();
        vs.apply_block(vec![(k2, b"b".to_vec())]).unwrap();
        vs.apply_block(vec![(k1, b"c".to_vec())]).unwrap();
        assert_eq!(vs.height, 3);

        // Undo 2 blocks
        let _root = vs.undo_blocks(2).unwrap().unwrap();
        assert_eq!(vs.height, 1);
        assert_eq!(vs.get(&k1), Some(b"a".to_vec()));
        assert_eq!(vs.get(&k2), None);

        // Undo last block
        vs.undo_block().unwrap();
        assert_eq!(vs.root(), root0);
    }

    #[test]
    fn undo_blocks_too_many_returns_none() {
        let mut vs = VersionedState::new();
        vs.apply_block(vec![(key_from_seed(1), b"x".to_vec())]).unwrap();
        assert_eq!(vs.undo_blocks(5).unwrap(), None);
    }

    // ========== Task 0332: Historical state query ==========

    #[test]
    fn get_at_height_current() {
        let mut vs = VersionedState::new();
        let key = key_from_seed(1);
        vs.apply_block(vec![(key, b"val".to_vec())]).unwrap();

        assert_eq!(vs.get_at_height(&key, 1), Some(b"val".to_vec()));
    }

    #[test]
    fn get_at_height_historical() {
        let mut vs = VersionedState::new();
        let key = key_from_seed(1);

        vs.apply_block(vec![(key, b"v1".to_vec())]).unwrap();
        vs.apply_block(vec![(key, b"v2".to_vec())]).unwrap();
        vs.apply_block(vec![(key, b"v3".to_vec())]).unwrap();

        assert_eq!(vs.get_at_height(&key, 3), Some(b"v3".to_vec()));
        assert_eq!(vs.get_at_height(&key, 2), Some(b"v2".to_vec()));
        assert_eq!(vs.get_at_height(&key, 1), Some(b"v1".to_vec()));
        assert_eq!(vs.get_at_height(&key, 0), None); // didn't exist before block 1
    }

    #[test]
    fn get_at_height_future_returns_none() {
        let mut vs = VersionedState::new();
        vs.apply_block(vec![(key_from_seed(1), b"x".to_vec())]).unwrap();
        assert_eq!(vs.get_at_height(&key_from_seed(1), 999), None);
    }

    // ========== Pruning ==========

    #[test]
    fn pruning_limits_undo_depth() {
        let mut vs = VersionedState::with_max_depth(5);
        let key = key_from_seed(1);

        for i in 0..10u64 {
            vs.apply_block(vec![(key, format!("v{i}").into_bytes())]).unwrap();
        }

        assert_eq!(vs.undo_depth(), 5);
        assert_eq!(vs.height, 10);
        assert!(vs.oldest_available_height() > 0);
    }

    #[test]
    fn cannot_undo_beyond_pruned() {
        let mut vs = VersionedState::with_max_depth(3);
        let key = key_from_seed(1);

        for i in 0..10u64 {
            vs.apply_block(vec![(key, format!("v{i}").into_bytes())]).unwrap();
        }

        // Can only undo 3 blocks
        assert!(vs.undo_blocks(3).unwrap().is_some());
        assert_eq!(vs.height, 7);
        // No more undo available
        assert_eq!(vs.undo_blocks(5).unwrap(), None);
    }

    // ========== Multiple keys per block ==========

    #[test]
    fn block_with_multiple_diffs() {
        let mut vs = VersionedState::new();
        let k1 = key_from_seed(1);
        let k2 = key_from_seed(2);
        let k3 = key_from_seed(3);

        vs.apply_block(vec![
            (k1, b"a".to_vec()),
            (k2, b"b".to_vec()),
            (k3, b"c".to_vec()),
        ]).unwrap();
        assert_eq!(vs.get(&k1), Some(b"a".to_vec()));
        assert_eq!(vs.get(&k2), Some(b"b".to_vec()));
        assert_eq!(vs.get(&k3), Some(b"c".to_vec()));

        vs.undo_block().unwrap();
        assert_eq!(vs.get(&k1), None);
        assert_eq!(vs.get(&k2), None);
        assert_eq!(vs.get(&k3), None);
    }

    #[test]
    fn undo_restores_deleted_key() {
        let mut vs = VersionedState::new();
        let key = key_from_seed(1);

        // Block 1: create key
        vs.apply_block(vec![(key, b"exists".to_vec())]).unwrap();
        assert_eq!(vs.get(&key), Some(b"exists".to_vec()));

        // Block 2: delete key (empty value)
        vs.apply_block(vec![(key, vec![])]).unwrap();
        assert_eq!(vs.get(&key), None);

        // Undo block 2: key should be restored
        vs.undo_block().unwrap();
        assert_eq!(vs.get(&key), Some(b"exists".to_vec()));
    }
}
