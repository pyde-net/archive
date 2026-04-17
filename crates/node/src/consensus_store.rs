//! Persistent storage for HotStuff consensus state.
//!
//! Safety property: on validator restart, we must never regress
//! `last_voted_slot` or `highest_qc`. A double-vote after a crash
//! would be a BFT safety violation.
//!
//! Key layout:
//!   b"consensus:state" → serialized ConsensusState (see wire::encode_consensus_state)

use crate::wire;
use pyde_consensus::hotstuff::ConsensusState;
use rocksdb::{DB, Options};
use std::path::Path;
use tracing::{debug, info};

const STATE_KEY: &[u8] = b"consensus:state";

/// RocksDB-backed store for a validator's `ConsensusState`.
///
/// There is exactly one persisted state per node, so the store is
/// effectively a single-key KV. RocksDB gives us atomic writes,
/// crash recovery, and fsync guarantees at the filesystem layer.
pub struct ConsensusStateStore {
    db: DB,
}

impl ConsensusStateStore {
    /// Open (or create) the consensus state store under `datadir/consensus`.
    pub fn open(datadir: &Path) -> Result<Self, String> {
        let db_path = datadir.join("consensus");
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, &db_path)
            .map_err(|e| format!("failed to open consensus state store: {}", e))?;
        info!(path = %db_path.display(), "consensus state store opened");
        Ok(Self { db })
    }

    /// Persist the current consensus state. Overwrites any prior value.
    pub fn save(&self, state: &ConsensusState) -> Result<(), String> {
        let bytes = wire::encode_consensus_state(state);
        self.db
            .put(STATE_KEY, &bytes)
            .map_err(|e| format!("failed to save consensus state: {}", e))?;
        debug!(
            slot = state.current_slot,
            epoch = state.current_epoch,
            last_voted = state.last_voted_slot,
            highest_qc = state.highest_qc.slot,
            bytes = bytes.len(),
            "consensus state persisted"
        );
        Ok(())
    }

    /// Load the previously-persisted state, if any.
    pub fn load(&self) -> Result<Option<ConsensusState>, String> {
        match self.db.get(STATE_KEY) {
            Ok(Some(bytes)) => {
                let state = wire::decode_consensus_state(&bytes)
                    .map_err(|e| format!("failed to decode consensus state: {}", e))?;
                info!(
                    slot = state.current_slot,
                    epoch = state.current_epoch,
                    last_voted = state.last_voted_slot,
                    highest_qc = state.highest_qc.slot,
                    "consensus state restored from disk"
                );
                Ok(Some(state))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("failed to read consensus state: {}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_consensus::block::QuorumCert;
    use tempfile::tempdir;

    fn populated_state() -> ConsensusState {
        ConsensusState {
            current_slot: 100,
            current_epoch: 1,
            highest_qc: QuorumCert {
                slot: 99,
                block_hash: [0xAB; 32],
                voter_bitmap: (1u128 << 86) - 1,
                signatures: vec![vec![0x11; 600], vec![0x22; 600]],
            },
            last_voted_slot: 100,
            last_committed_hash: [0xCD; 32],
            last_committed_slot: 98,
            pending_votes: Vec::new(),
            pending_timeouts: Vec::new(),
        }
    }

    #[test]
    fn load_empty_returns_none() {
        let dir = tempdir().unwrap();
        let store = ConsensusStateStore::open(dir.path()).unwrap();
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempdir().unwrap();
        let store = ConsensusStateStore::open(dir.path()).unwrap();
        let state = populated_state();
        store.save(&state).unwrap();

        let loaded = store.load().unwrap().expect("state must be present");
        assert_eq!(loaded.current_slot, state.current_slot);
        assert_eq!(loaded.current_epoch, state.current_epoch);
        assert_eq!(loaded.highest_qc.slot, state.highest_qc.slot);
        assert_eq!(loaded.highest_qc.block_hash, state.highest_qc.block_hash);
        assert_eq!(loaded.last_voted_slot, state.last_voted_slot);
        assert_eq!(loaded.last_committed_hash, state.last_committed_hash);
        assert_eq!(loaded.last_committed_slot, state.last_committed_slot);
    }

    #[test]
    fn save_overwrites_prior_value() {
        let dir = tempdir().unwrap();
        let store = ConsensusStateStore::open(dir.path()).unwrap();

        let mut state = populated_state();
        store.save(&state).unwrap();

        state.current_slot = 200;
        state.last_voted_slot = 200;
        store.save(&state).unwrap();

        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.current_slot, 200);
        assert_eq!(loaded.last_voted_slot, 200);
    }

    #[test]
    fn state_survives_reopen() {
        let dir = tempdir().unwrap();
        let state = populated_state();

        {
            let store = ConsensusStateStore::open(dir.path()).unwrap();
            store.save(&state).unwrap();
            // store is dropped here, simulating node shutdown
        }

        // Reopen — this is the crash-restart case
        let store = ConsensusStateStore::open(dir.path()).unwrap();
        let loaded = store.load().unwrap().expect("state must persist across reopen");
        assert_eq!(loaded.current_slot, 100);
        assert_eq!(loaded.last_voted_slot, 100);
        assert_eq!(loaded.highest_qc.slot, 99);
    }
}
