//! Persistent storage for HotStuff consensus state + equivocation evidence.
//!
//! Safety property 1 (consensus state): on validator restart, we must never
//! regress `last_voted_slot` or `highest_qc`. A double-vote after a crash
//! would be a BFT safety violation.
//!
//! Safety property 2 (seen proposals/votes): equivocation detection requires
//! remembering every distinct (slot, proposer) proposal and (slot, voter)
//! vote that crossed this node. Losing that index across a crash means a
//! Byzantine validator can equivocate either side of the crash undetected.
//!
//! Key layout:
//!   b"consensus:state"              → serialized ConsensusState
//!   b"p:" || slot_be8 || addr[32]   → (encoded BlockHeader, signature)
//!   b"v:" || slot_be8 || voter_idx  → (block_hash[32], signature)

use crate::wire;
use pyde_account::address::Address;
use pyde_consensus::block::BlockHeader;
use pyde_consensus::hotstuff::ConsensusState;
use rocksdb::{DB, IteratorMode, Options, WriteBatch, WriteOptions};
use std::path::Path;
use tracing::{debug, info, warn};

const STATE_KEY: &[u8] = b"consensus:state";
const PROPOSAL_PREFIX: &[u8] = b"p:";
const VOTE_PREFIX: &[u8] = b"v:";

/// A proposal seen from a proposer at a given slot (for double-propose detection).
pub type SeenProposal = ((u64, Address), (BlockHeader, Vec<u8>));

/// A vote seen from a voter at a given slot (for double-vote detection).
pub type SeenVote = ((u64, u8), ([u8; 32], Vec<u8>));

/// RocksDB-backed store for a validator's `ConsensusState`.
///
/// There is exactly one persisted state per node, so the store is
/// effectively a single-key KV. RocksDB gives us atomic writes,
/// crash recovery, and fsync guarantees at the filesystem layer.
///
/// All mutating writes go through `sync_opts` (`set_sync(true)`), which
/// forces an fsync before the `put` returns. Without this, a vote
/// "committed" to the WAL page cache could be lost in a power-loss
/// window — the entire crash-safety guarantee of the store depends on
/// the data actually being on disk when we return Ok.
pub struct ConsensusStateStore {
    db: DB,
    sync_opts: WriteOptions,
}

impl ConsensusStateStore {
    /// Open (or create) the consensus state store under `datadir/consensus`.
    pub fn open(datadir: &Path) -> Result<Self, String> {
        let db_path = datadir.join("consensus");
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, &db_path)
            .map_err(|e| format!("failed to open consensus state store: {}", e))?;
        let mut sync_opts = WriteOptions::default();
        sync_opts.set_sync(true);
        info!(path = %db_path.display(), "consensus state store opened (fsync on every write)");
        Ok(Self { db, sync_opts })
    }

    /// Persist the current consensus state. Overwrites any prior value.
    /// Blocks until the write is fsync'd to disk.
    pub fn save(&self, state: &ConsensusState) -> Result<(), String> {
        let bytes = wire::encode_consensus_state(state);
        self.db
            .put_opt(STATE_KEY, &bytes, &self.sync_opts)
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

    // ============================================================
    // Seen proposals / votes (equivocation evidence index)
    // ============================================================

    /// Persist a seen proposal entry. Idempotent on repeat writes.
    /// fsync'd before return (see struct docstring).
    pub fn save_seen_proposal(
        &self,
        slot: u64,
        proposer: &Address,
        header: &BlockHeader,
        signature: &[u8],
    ) -> Result<(), String> {
        let key = encode_proposal_key(slot, proposer);
        let value = encode_seen_proposal(header, signature);
        self.db
            .put_opt(&key, &value, &self.sync_opts)
            .map_err(|e| format!("failed to save seen proposal: {}", e))
    }

    /// Persist a seen vote entry. Idempotent on repeat writes.
    /// fsync'd before return (see struct docstring).
    pub fn save_seen_vote(
        &self,
        slot: u64,
        voter_index: u8,
        block_hash: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), String> {
        let key = encode_vote_key(slot, voter_index);
        let value = encode_seen_vote(block_hash, signature);
        self.db
            .put_opt(&key, &value, &self.sync_opts)
            .map_err(|e| format!("failed to save seen vote: {}", e))
    }

    /// Load all persisted seen proposals. Corrupt entries are skipped + logged.
    pub fn load_all_seen_proposals(&self) -> Vec<SeenProposal> {
        let mut out = Vec::new();
        for item in self.db.prefix_iterator(PROPOSAL_PREFIX) {
            let (k, v) = match item {
                Ok(kv) => kv,
                Err(e) => {
                    warn!(error = %e, "iterator error on seen proposals");
                    continue;
                }
            };
            if !k.starts_with(PROPOSAL_PREFIX) {
                break;
            }
            let (slot, addr) = match decode_proposal_key(&k) {
                Ok(parsed) => parsed,
                Err(e) => {
                    warn!(error = e, "skipping corrupt proposal key");
                    continue;
                }
            };
            match decode_seen_proposal(&v) {
                Ok((header, sig)) => out.push(((slot, addr), (header, sig))),
                Err(e) => warn!(slot, error = e, "skipping corrupt proposal value"),
            }
        }
        out
    }

    /// Load all persisted seen votes. Corrupt entries are skipped + logged.
    pub fn load_all_seen_votes(&self) -> Vec<SeenVote> {
        let mut out = Vec::new();
        for item in self.db.prefix_iterator(VOTE_PREFIX) {
            let (k, v) = match item {
                Ok(kv) => kv,
                Err(e) => {
                    warn!(error = %e, "iterator error on seen votes");
                    continue;
                }
            };
            if !k.starts_with(VOTE_PREFIX) {
                break;
            }
            let (slot, voter_index) = match decode_vote_key(&k) {
                Ok(parsed) => parsed,
                Err(e) => {
                    warn!(error = e, "skipping corrupt vote key");
                    continue;
                }
            };
            match decode_seen_vote(&v) {
                Ok((block_hash, sig)) => out.push(((slot, voter_index), (block_hash, sig))),
                Err(e) => warn!(slot, error = e, "skipping corrupt vote value"),
            }
        }
        out
    }

    /// Delete all seen-proposal and seen-vote entries with slot < prune_before.
    /// Mirrors the in-memory pruning in `ValidatorEngine::advance_slot`.
    pub fn prune_evidence_before(&self, prune_before: u64) -> Result<usize, String> {
        let mut batch = WriteBatch::default();
        let mut count = 0usize;

        for prefix in [PROPOSAL_PREFIX, VOTE_PREFIX] {
            for item in self.db.iterator(IteratorMode::From(prefix, rocksdb::Direction::Forward)) {
                let (k, _v) = match item {
                    Ok(kv) => kv,
                    Err(_) => continue,
                };
                if !k.starts_with(prefix) {
                    break;
                }
                let slot_bytes: &[u8] = match k.get(prefix.len()..prefix.len() + 8) {
                    Some(b) => b,
                    None => continue,
                };
                let mut buf = [0u8; 8];
                buf.copy_from_slice(slot_bytes);
                let slot = u64::from_be_bytes(buf);
                if slot < prune_before {
                    batch.delete(&k);
                    count += 1;
                }
            }
        }

        if count > 0 {
            // Prune writes also fsync. Loss of a prune doesn't violate
            // safety (stale disk entries are benign — in-memory state is
            // source of truth for active slots), but fsync-consistent
            // pruning keeps the disk size predictable and simplifies
            // reasoning about what the next cold-start will reload.
            self.db
                .write_opt(batch, &self.sync_opts)
                .map_err(|e| format!("failed to prune evidence: {}", e))?;
            debug!(pruned = count, prune_before, "evidence pruned");
        }
        Ok(count)
    }
}

// ============================================================
// Key + value encoding helpers
// ============================================================

fn encode_proposal_key(slot: u64, proposer: &Address) -> Vec<u8> {
    let mut k = Vec::with_capacity(PROPOSAL_PREFIX.len() + 8 + 32);
    k.extend_from_slice(PROPOSAL_PREFIX);
    k.extend_from_slice(&slot.to_be_bytes());
    k.extend_from_slice(proposer);
    k
}

fn decode_proposal_key(key: &[u8]) -> Result<(u64, Address), &'static str> {
    if key.len() != PROPOSAL_PREFIX.len() + 8 + 32 {
        return Err("unexpected proposal key length");
    }
    if !key.starts_with(PROPOSAL_PREFIX) {
        return Err("missing proposal prefix");
    }
    let mut slot_buf = [0u8; 8];
    slot_buf.copy_from_slice(&key[PROPOSAL_PREFIX.len()..PROPOSAL_PREFIX.len() + 8]);
    let slot = u64::from_be_bytes(slot_buf);
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&key[PROPOSAL_PREFIX.len() + 8..]);
    Ok((slot, addr))
}

fn encode_vote_key(slot: u64, voter_index: u8) -> Vec<u8> {
    let mut k = Vec::with_capacity(VOTE_PREFIX.len() + 8 + 1);
    k.extend_from_slice(VOTE_PREFIX);
    k.extend_from_slice(&slot.to_be_bytes());
    k.push(voter_index);
    k
}

fn decode_vote_key(key: &[u8]) -> Result<(u64, u8), &'static str> {
    if key.len() != VOTE_PREFIX.len() + 8 + 1 {
        return Err("unexpected vote key length");
    }
    if !key.starts_with(VOTE_PREFIX) {
        return Err("missing vote prefix");
    }
    let mut slot_buf = [0u8; 8];
    slot_buf.copy_from_slice(&key[VOTE_PREFIX.len()..VOTE_PREFIX.len() + 8]);
    let slot = u64::from_be_bytes(slot_buf);
    let voter_index = key[VOTE_PREFIX.len() + 8];
    Ok((slot, voter_index))
}

fn encode_seen_proposal(header: &BlockHeader, signature: &[u8]) -> Vec<u8> {
    let header_bytes = wire::encode_block_header(header);
    let mut out = Vec::with_capacity(8 + header_bytes.len() + signature.len());
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&(signature.len() as u32).to_le_bytes());
    out.extend_from_slice(signature);
    out
}

fn decode_seen_proposal(bytes: &[u8]) -> Result<(BlockHeader, Vec<u8>), &'static str> {
    if bytes.len() < 4 {
        return Err("seen proposal value too short");
    }
    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&bytes[..4]);
    let header_len = u32::from_le_bytes(len_buf) as usize;
    if bytes.len() < 4 + header_len + 4 {
        return Err("seen proposal header truncated");
    }
    let header = wire::decode_block_header(&bytes[4..4 + header_len])?;
    let sig_start = 4 + header_len;
    len_buf.copy_from_slice(&bytes[sig_start..sig_start + 4]);
    let sig_len = u32::from_le_bytes(len_buf) as usize;
    if bytes.len() < sig_start + 4 + sig_len {
        return Err("seen proposal signature truncated");
    }
    let sig = bytes[sig_start + 4..sig_start + 4 + sig_len].to_vec();
    Ok((header, sig))
}

fn encode_seen_vote(block_hash: &[u8; 32], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 4 + signature.len());
    out.extend_from_slice(block_hash);
    out.extend_from_slice(&(signature.len() as u32).to_le_bytes());
    out.extend_from_slice(signature);
    out
}

fn decode_seen_vote(bytes: &[u8]) -> Result<([u8; 32], Vec<u8>), &'static str> {
    if bytes.len() < 32 + 4 {
        return Err("seen vote value too short");
    }
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&bytes[..32]);
    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&bytes[32..36]);
    let sig_len = u32::from_le_bytes(len_buf) as usize;
    if bytes.len() < 36 + sig_len {
        return Err("seen vote signature truncated");
    }
    let sig = bytes[36..36 + sig_len].to_vec();
    Ok((block_hash, sig))
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

    // ========== Seen proposals / votes ==========

    fn dummy_header(slot: u64) -> BlockHeader {
        BlockHeader {
            slot,
            epoch: slot / 1000,
            parent_hash: [0x11; 32],
            proposer: [0xAA; 32],
            vrf_proof: vec![0xCC; 100],
            qc_previous: QuorumCert {
                slot: slot.saturating_sub(1),
                block_hash: [0xBB; 32],
                voter_bitmap: 0,
                signatures: vec![],
            },
            tx_root: [0x22; 32],
            state_root: [0x33; 32],
            timestamp: slot * 400,
        }
    }

    #[test]
    fn seen_proposal_roundtrip() {
        let dir = tempdir().unwrap();
        let store = ConsensusStateStore::open(dir.path()).unwrap();

        let proposer = [0xAA; 32];
        let header = dummy_header(10);
        let sig = vec![0xEE; 600];

        store.save_seen_proposal(10, &proposer, &header, &sig).unwrap();

        let all = store.load_all_seen_proposals();
        assert_eq!(all.len(), 1);
        let ((slot, addr), (loaded_header, loaded_sig)) = &all[0];
        assert_eq!(*slot, 10);
        assert_eq!(*addr, proposer);
        assert_eq!(loaded_header.slot, 10);
        assert_eq!(loaded_header.timestamp, 4000);
        assert_eq!(*loaded_sig, sig);
    }

    #[test]
    fn seen_vote_roundtrip() {
        let dir = tempdir().unwrap();
        let store = ConsensusStateStore::open(dir.path()).unwrap();

        let block_hash = [0x77; 32];
        let sig = vec![0xFF; 600];
        store.save_seen_vote(42, 7, &block_hash, &sig).unwrap();

        let all = store.load_all_seen_votes();
        assert_eq!(all.len(), 1);
        let ((slot, voter_idx), (loaded_hash, loaded_sig)) = &all[0];
        assert_eq!(*slot, 42);
        assert_eq!(*voter_idx, 7);
        assert_eq!(*loaded_hash, block_hash);
        assert_eq!(*loaded_sig, sig);
    }

    #[test]
    fn multiple_proposals_same_slot_different_proposers() {
        let dir = tempdir().unwrap();
        let store = ConsensusStateStore::open(dir.path()).unwrap();

        let a = [0xAA; 32];
        let b = [0xBB; 32];
        store.save_seen_proposal(5, &a, &dummy_header(5), &vec![0x11; 10]).unwrap();
        store.save_seen_proposal(5, &b, &dummy_header(5), &vec![0x22; 10]).unwrap();

        let all = store.load_all_seen_proposals();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn prune_removes_old_entries_only() {
        let dir = tempdir().unwrap();
        let store = ConsensusStateStore::open(dir.path()).unwrap();

        for slot in 1..=15u64 {
            store.save_seen_proposal(slot, &[0xAA; 32], &dummy_header(slot), &vec![0x11; 10]).unwrap();
            store.save_seen_vote(slot, 0, &[0x77; 32], &vec![0x22; 10]).unwrap();
        }

        assert_eq!(store.load_all_seen_proposals().len(), 15);
        assert_eq!(store.load_all_seen_votes().len(), 15);

        // Keep last 10 slots: slots < 6 should be pruned.
        let pruned = store.prune_evidence_before(6).unwrap();
        assert_eq!(pruned, 10); // 5 proposals + 5 votes

        let props = store.load_all_seen_proposals();
        let votes = store.load_all_seen_votes();
        assert_eq!(props.len(), 10);
        assert_eq!(votes.len(), 10);
        assert!(props.iter().all(|((slot, _), _)| *slot >= 6));
        assert!(votes.iter().all(|((slot, _), _)| *slot >= 6));
    }

    #[test]
    fn evidence_survives_reopen() {
        let dir = tempdir().unwrap();
        let proposer = [0xAA; 32];
        let header = dummy_header(7);
        let sig = vec![0xEE; 600];

        {
            let store = ConsensusStateStore::open(dir.path()).unwrap();
            store.save_seen_proposal(7, &proposer, &header, &sig).unwrap();
            store.save_seen_vote(7, 3, &[0x99; 32], &vec![0xFF; 600]).unwrap();
        }

        let store = ConsensusStateStore::open(dir.path()).unwrap();
        assert_eq!(store.load_all_seen_proposals().len(), 1);
        assert_eq!(store.load_all_seen_votes().len(), 1);
    }

    #[test]
    fn consensus_state_and_evidence_coexist() {
        // Belt-and-braces: saving state + evidence in the same DB must not
        // stomp each other (shared RocksDB with distinct key prefixes).
        let dir = tempdir().unwrap();
        let store = ConsensusStateStore::open(dir.path()).unwrap();

        store.save(&populated_state()).unwrap();
        store.save_seen_proposal(50, &[0xAA; 32], &dummy_header(50), &vec![0x11; 10]).unwrap();
        store.save_seen_vote(50, 1, &[0x99; 32], &vec![0x22; 10]).unwrap();

        assert!(store.load().unwrap().is_some());
        assert_eq!(store.load_all_seen_proposals().len(), 1);
        assert_eq!(store.load_all_seen_votes().len(), 1);
    }
}
