//! Persistent block header storage backed by RocksDB.
//!
//! Key layout:
//!   b"h:{slot_le_bytes}" → serialized header
//!   b"i:{block_hash}"    → slot (8 bytes LE)
//!   b"meta:head"         → head slot (8 bytes LE)

use crate::wire;
use pyde_consensus::block::BlockHeader;
use rocksdb::{DB, Options};
use std::path::Path;
use tracing::info;

/// Persistent block header store.
pub struct BlockStore {
    db: DB,
}

impl BlockStore {
    /// Open or create the block store.
    pub fn open(datadir: &Path) -> Result<Self, String> {
        let db_path = datadir.join("blocks");
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, &db_path)
            .map_err(|e| format!("failed to open block store: {}", e))?;
        info!(path = %db_path.display(), "block store opened");
        Ok(Self { db })
    }

    /// Store a block header.
    pub fn put_header(&self, header: &BlockHeader) -> Result<(), String> {
        let slot = header.slot;
        let block_hash = header.hash();
        let header_bytes = wire::encode_block_header(header);

        // slot → header
        let mut slot_key = Vec::with_capacity(2 + 8);
        slot_key.extend_from_slice(b"h:");
        slot_key.extend_from_slice(&slot.to_le_bytes());
        self.db.put(&slot_key, &header_bytes)
            .map_err(|e| format!("failed to store header: {}", e))?;

        // hash → slot
        let mut hash_key = Vec::with_capacity(2 + 32);
        hash_key.extend_from_slice(b"i:");
        hash_key.extend_from_slice(&block_hash);
        self.db.put(&hash_key, &slot.to_le_bytes())
            .map_err(|e| format!("failed to store hash index: {}", e))?;

        Ok(())
    }

    /// Load a block header by slot.
    pub fn get_header(&self, slot: u64) -> Option<BlockHeader> {
        let mut key = Vec::with_capacity(10);
        key.extend_from_slice(b"h:");
        key.extend_from_slice(&slot.to_le_bytes());
        self.db.get(&key).ok()?.and_then(|bytes| wire::decode_block_header(&bytes).ok())
    }

    /// Look up a slot by block hash.
    pub fn get_slot_by_hash(&self, hash: &[u8; 32]) -> Option<u64> {
        let mut key = Vec::with_capacity(34);
        key.extend_from_slice(b"i:");
        key.extend_from_slice(hash);
        self.db.get(&key).ok()?.map(|bytes| {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[..8]);
            u64::from_le_bytes(buf)
        })
    }

    /// Get a header by block hash.
    pub fn get_header_by_hash(&self, hash: &[u8; 32]) -> Option<BlockHeader> {
        let slot = self.get_slot_by_hash(hash)?;
        self.get_header(slot)
    }

    /// Save the current head slot.
    pub fn put_head(&self, slot: u64) -> Result<(), String> {
        self.db.put(b"meta:head", slot.to_le_bytes())
            .map_err(|e| format!("failed to store head: {}", e))
    }

    /// Load the saved head slot.
    pub fn get_head(&self) -> u64 {
        self.db.get(b"meta:head").ok()
            .flatten()
            .map(|bytes| {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[..8]);
                u64::from_le_bytes(buf)
            })
            .unwrap_or(0)
    }

    // ========================================================================
    // Block body storage (task 1311 + 1313)
    // ========================================================================

    /// Store a full block (header + wire-encoded body) for the given slot.
    /// The raw_bytes contain the full wire-encoded block for replay/sync.
    pub fn put_block(&self, header: &BlockHeader, raw_bytes: &[u8]) -> Result<(), String> {
        self.put_header(header)?;
        // Full wire-encoded block at "b:{slot}" (for sync and replay)
        let mut key = Vec::with_capacity(2 + 8);
        key.extend_from_slice(b"b:");
        key.extend_from_slice(&header.slot.to_le_bytes());
        self.db.put(&key, raw_bytes)
            .map_err(|e| format!("failed to store block data: {}", e))
    }

    /// Load the full wire-encoded block by slot.
    /// Returns the raw bytes that can be decoded via wire::decode_block().
    pub fn get_block_raw(&self, slot: u64) -> Option<Vec<u8>> {
        let mut key = Vec::with_capacity(2 + 8);
        key.extend_from_slice(b"b:");
        key.extend_from_slice(&slot.to_le_bytes());
        self.db.get(&key).ok()?.map(|bytes| bytes.to_vec())
    }

    /// Check if full block data exists for this slot.
    pub fn has_block_data(&self, slot: u64) -> bool {
        self.get_block_raw(slot).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::ZERO_ADDRESS;
    use pyde_consensus::block::QuorumCert;

    fn dummy_header(slot: u64) -> BlockHeader {
        BlockHeader {
            slot,
            epoch: 0,
            parent_hash: [0u8; 32],
            proposer: ZERO_ADDRESS,
            vrf_proof: vec![0xAA; 50],
            qc_previous: QuorumCert::empty(),
            tx_root: [slot as u8; 32],
            state_root: [slot as u8; 32],
            timestamp: slot * 400,
        }
    }

    // Each test uses a `tempfile::tempdir()` instead of a shared path
    // under `std::env::temp_dir()`. The prior `pyde-bstore-N` paths
    // collided between concurrent `cargo test --workspace` invocations
    // (e.g. two CI jobs, or one job plus a developer's local run),
    // producing flaky assertion failures as tests observed each other's
    // state through the shared RocksDB directory.

    #[test]
    fn store_and_load_header() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let header = dummy_header(5);
        store.put_header(&header).unwrap();

        let loaded = store.get_header(5).unwrap();
        assert_eq!(loaded.slot, 5);
        assert_eq!(loaded.tx_root, [5u8; 32]);
    }

    #[test]
    fn lookup_by_hash() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let header = dummy_header(10);
        let hash = header.hash();
        store.put_header(&header).unwrap();

        let loaded = store.get_header_by_hash(&hash).unwrap();
        assert_eq!(loaded.slot, 10);
    }

    #[test]
    fn missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        assert!(store.get_header(999).is_none());
        assert!(store.get_header_by_hash(&[0xFF; 32]).is_none());
    }

    #[test]
    fn head_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        assert_eq!(store.get_head(), 0);
        store.put_head(42).unwrap();
        assert_eq!(store.get_head(), 42);
    }
}
