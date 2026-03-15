//! State snapshots: serialize/deserialize the full SMT for node sync.
//!
//! - Full snapshot: all key-value pairs + root hash
//! - Incremental snapshot: only keys changed since a previous root
//! - Chunking: split snapshot into fixed-size chunks for network transfer
//! - Verification: reconstruct root from chunks to verify integrity

use crate::smt::{Key, PydeSMT, SmtValue};
use pyde_crypto::poseidon2::poseidon2_hash;
use sparse_merkle_tree::H256;

/// A full state snapshot: all key-value pairs at a point in time.
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// The state root this snapshot represents.
    pub root: H256,
    /// All key-value pairs in the state.
    pub entries: Vec<(Key, Vec<u8>)>,
}

/// A chunk of a snapshot for network transfer.
#[derive(Clone, Debug)]
pub struct SnapshotChunk {
    /// Chunk index (0-based).
    pub index: u32,
    /// Total number of chunks.
    pub total: u32,
    /// Entries in this chunk.
    pub entries: Vec<(Key, Vec<u8>)>,
    /// Hash of this chunk's data (for integrity).
    pub chunk_hash: H256,
}

/// An incremental snapshot: only keys that changed between two roots.
#[derive(Clone, Debug)]
pub struct IncrementalSnapshot {
    /// The root before changes.
    pub from_root: H256,
    /// The root after changes.
    pub to_root: H256,
    /// Changed key-value pairs (new values). Empty value = deleted.
    pub diffs: Vec<(Key, Vec<u8>)>,
}

/// Create a full snapshot of the SMT.
pub fn create_snapshot(smt: &PydeSMT, all_keys: &[Key]) -> Snapshot {
    let root = smt.root();
    let entries: Vec<(Key, Vec<u8>)> = all_keys
        .iter()
        .filter_map(|k| smt.get(k).map(|v| (*k, v)))
        .collect();

    Snapshot { root, entries }
}

/// Restore a full SMT from a snapshot.
pub fn restore_snapshot(snapshot: &Snapshot) -> PydeSMT {
    let mut smt = PydeSMT::new();
    if !snapshot.entries.is_empty() {
        smt.update_all(snapshot.entries.clone());
    }
    smt
}

/// Verify that a restored snapshot produces the expected root.
pub fn verify_snapshot(snapshot: &Snapshot) -> bool {
    let smt = restore_snapshot(snapshot);
    smt.root() == snapshot.root
}

/// Create an incremental snapshot: diff between old state and new state.
pub fn create_incremental(
    old_keys: &[Key],
    old_smt: &PydeSMT,
    new_smt: &PydeSMT,
    new_keys: &[Key],
) -> IncrementalSnapshot {
    let from_root = old_smt.root();
    let to_root = new_smt.root();

    let mut diffs = Vec::new();

    // Find keys that changed or were added
    for k in new_keys {
        let old_val = old_smt.get(k);
        let new_val = new_smt.get(k);
        if old_val != new_val {
            diffs.push((*k, new_val.unwrap_or_default()));
        }
    }

    // Find keys that were deleted (in old but not in new)
    for k in old_keys {
        if new_smt.get(k).is_none() && old_smt.get(k).is_some() {
            diffs.push((*k, Vec::new())); // empty = deleted
        }
    }

    IncrementalSnapshot {
        from_root,
        to_root,
        diffs,
    }
}

/// Apply an incremental snapshot to an SMT.
pub fn apply_incremental(smt: &mut PydeSMT, inc: &IncrementalSnapshot) -> H256 {
    smt.update_all(inc.diffs.clone())
}

/// Split a snapshot into chunks of `chunk_size` entries each.
pub fn chunk_snapshot(snapshot: &Snapshot, chunk_size: usize) -> Vec<SnapshotChunk> {
    let total_chunks = (snapshot.entries.len() + chunk_size - 1) / chunk_size;
    let total = total_chunks.max(1) as u32;

    snapshot
        .entries
        .chunks(chunk_size)
        .enumerate()
        .map(|(i, entries)| {
            let chunk_entries: Vec<(Key, Vec<u8>)> = entries.to_vec();
            let chunk_hash = hash_chunk(&chunk_entries);
            SnapshotChunk {
                index: i as u32,
                total,
                entries: chunk_entries,
                chunk_hash,
            }
        })
        .collect()
}

/// Reconstruct a snapshot from chunks and verify the root.
pub fn verify_chunks(chunks: &[SnapshotChunk], expected_root: H256) -> bool {
    // Verify chunk hashes
    for chunk in chunks {
        let computed = hash_chunk(&chunk.entries);
        if computed != chunk.chunk_hash {
            return false;
        }
    }

    // Reconstruct full entry list
    let mut all_entries: Vec<(Key, Vec<u8>)> = Vec::new();
    let mut sorted_chunks: Vec<&SnapshotChunk> = chunks.iter().collect();
    sorted_chunks.sort_by_key(|c| c.index);

    for chunk in sorted_chunks {
        all_entries.extend(chunk.entries.clone());
    }

    // Rebuild SMT and verify root
    let snapshot = Snapshot {
        root: expected_root,
        entries: all_entries,
    };
    verify_snapshot(&snapshot)
}

/// Hash a chunk's entries for integrity verification.
fn hash_chunk(entries: &[(Key, Vec<u8>)]) -> H256 {
    let mut buf = Vec::new();
    for (k, v) in entries {
        buf.extend_from_slice(k.as_slice());
        buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
        buf.extend_from_slice(v);
    }
    H256::from(poseidon2_hash(&buf).to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smt::key_from_seed;

    fn populate_smt(count: u64) -> (PydeSMT, Vec<Key>) {
        let mut smt = PydeSMT::new();
        let keys: Vec<Key> = (0..count).map(|i| key_from_seed(i)).collect();
        for (i, k) in keys.iter().enumerate() {
            smt.insert(*k, format!("val_{i}").into_bytes());
        }
        (smt, keys)
    }

    // ========== Task 0323: Snapshot/restore roundtrip ==========

    #[test]
    fn snapshot_restore_roundtrip() {
        let (smt, keys) = populate_smt(100);
        let original_root = smt.root();

        let snapshot = create_snapshot(&smt, &keys);
        assert_eq!(snapshot.root, original_root);
        assert_eq!(snapshot.entries.len(), 100);

        let restored = restore_snapshot(&snapshot);
        assert_eq!(restored.root(), original_root);

        // Verify all values match
        for (k, v) in &snapshot.entries {
            assert_eq!(restored.get(k), Some(v.clone()));
        }
    }

    #[test]
    fn snapshot_verify_passes() {
        let (smt, keys) = populate_smt(50);
        let snapshot = create_snapshot(&smt, &keys);
        assert!(verify_snapshot(&snapshot));
    }

    #[test]
    fn snapshot_verify_fails_with_tampered_root() {
        let (smt, keys) = populate_smt(50);
        let mut snapshot = create_snapshot(&smt, &keys);
        snapshot.root = H256::from([0xFFu8; 32]);
        assert!(!verify_snapshot(&snapshot));
    }

    // ========== Task 0324: Incremental snapshot correctness ==========

    #[test]
    fn incremental_captures_changes() {
        let (mut old_smt, old_keys) = populate_smt(10);
        let old_root = old_smt.root();

        // Clone and modify
        let mut new_smt = PydeSMT::new();
        for (i, k) in old_keys.iter().enumerate() {
            new_smt.insert(*k, format!("val_{i}").into_bytes());
        }
        // Change one key
        let changed_key = old_keys[0];
        new_smt.insert(changed_key, b"new_value".to_vec());
        // Add one key
        let new_key = key_from_seed(999);
        new_smt.insert(new_key, b"added".to_vec());

        let mut all_new_keys = old_keys.clone();
        all_new_keys.push(new_key);

        let inc = create_incremental(&old_keys, &old_smt, &new_smt, &all_new_keys);
        assert_eq!(inc.from_root, old_root);
        assert_eq!(inc.to_root, new_smt.root());
        assert!(!inc.diffs.is_empty());

        // Apply incremental to old SMT
        let result_root = apply_incremental(&mut old_smt, &inc);
        assert_eq!(result_root, new_smt.root());
    }

    #[test]
    fn incremental_captures_deletion() {
        let (old_smt, old_keys) = populate_smt(5);

        let mut new_smt = PydeSMT::new();
        // Copy all except key[0]
        for (i, k) in old_keys.iter().enumerate().skip(1) {
            new_smt.insert(*k, format!("val_{i}").into_bytes());
        }

        let new_keys: Vec<Key> = old_keys[1..].to_vec();
        let inc = create_incremental(&old_keys, &old_smt, &new_smt, &new_keys);

        // Should have a deletion entry for key[0]
        let deleted = inc.diffs.iter().find(|(k, _)| *k == old_keys[0]);
        assert!(deleted.is_some());
        assert!(deleted.unwrap().1.is_empty()); // empty = deleted
    }

    // ========== Chunking ==========

    #[test]
    fn chunk_and_verify() {
        let (smt, keys) = populate_smt(100);
        let snapshot = create_snapshot(&smt, &keys);

        let chunks = chunk_snapshot(&snapshot, 25);
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].total, 4);
        assert_eq!(chunks[0].index, 0);
        assert_eq!(chunks[3].index, 3);

        // Total entries across all chunks = 100
        let total: usize = chunks.iter().map(|c| c.entries.len()).sum();
        assert_eq!(total, 100);

        // Verify chunks reconstruct to correct root
        assert!(verify_chunks(&chunks, smt.root()));
    }

    #[test]
    fn tampered_chunk_fails_verification() {
        let (smt, keys) = populate_smt(50);
        let snapshot = create_snapshot(&smt, &keys);
        let mut chunks = chunk_snapshot(&snapshot, 25);

        // Tamper with a chunk's data
        if let Some(entry) = chunks[0].entries.first_mut() {
            entry.1 = b"tampered".to_vec();
        }

        assert!(!verify_chunks(&chunks, smt.root()));
    }

    #[test]
    fn single_chunk_for_small_state() {
        let (smt, keys) = populate_smt(5);
        let snapshot = create_snapshot(&smt, &keys);
        let chunks = chunk_snapshot(&snapshot, 1000);
        assert_eq!(chunks.len(), 1);
        assert!(verify_chunks(&chunks, smt.root()));
    }

    #[test]
    fn empty_snapshot() {
        let smt = PydeSMT::new();
        let snapshot = create_snapshot(&smt, &[]);
        assert!(snapshot.entries.is_empty());
        assert!(verify_snapshot(&snapshot));
    }
}
