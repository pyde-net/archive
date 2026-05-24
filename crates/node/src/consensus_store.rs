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
//!   b"evidence:state"               → serialized EvidenceState (pending +
//!                                     broadcast queues + seen dedup set)
//!   b"p:" || slot_be8 || addr[32]   → (encoded BlockHeader, signature)
//!   b"v:" || slot_be8 || voter_idx  → (block_hash[32], signature)
//!   b"vcs:" || slot_be8             → (highest_qc_hash[32], signature)
//!     [TPL-501: self-VC equivocation guard. Persisted before
//!      `on_timeout` returns the signed VC, restored on restart.
//!      Re-attempting a VC at the same slot reuses the persisted
//!      signature when the highest_qc still matches; refuses to
//!      sign a different VC at that slot otherwise.]

use crate::wire;
use pyde_account::address::Address;
use pyde_consensus::block::BlockHeader;
use pyde_consensus::hotstuff::ConsensusState;
use rocksdb::{IteratorMode, Options, WriteBatch, WriteOptions, DB};
use std::path::Path;
use tracing::{debug, info, warn};

const STATE_KEY: &[u8] = b"consensus:state";
const EVIDENCE_STATE_KEY: &[u8] = b"evidence:state";
const RESHARE_STATE_KEY: &[u8] = b"reshare:state";
const FINALITY_CHECKPOINT_KEY: &[u8] = b"finality:checkpoint";
const PROPOSAL_PREFIX: &[u8] = b"p:";
const VOTE_PREFIX: &[u8] = b"v:";
/// TPL-501: self-VC equivocation guard. Stored once per (slot)
/// since voter_index is always this validator's own committee
/// index — encoding it would add nothing.
const VC_SELF_PREFIX: &[u8] = b"vcs:";

/// A proposal seen from a proposer at a given slot (for double-propose detection).
pub type SeenProposal = ((u64, Address), (BlockHeader, Vec<u8>));

/// A vote seen from a voter at a given slot (for double-vote detection).
pub type SeenVote = ((u64, u8), ([u8; 32], Vec<u8>));

/// A view-change message we ourselves signed at a given slot.
/// `(highest_qc_hash, signature)` is enough to (a) reject a
/// different-content VC at the same slot post-restart and
/// (b) idempotently re-broadcast the original signature when the
/// current `highest_qc` still hashes to the same value.
pub type SeenViewChangeSelf = (u64, ([u8; 32], Vec<u8>));

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

    /// Persist the ingest queues (pending, broadcast, seen) as one
    /// atomic blob. Rewrites the whole blob on each call — fine
    /// because equivocations are rare and the blob is small
    /// (~1 KB per evidence × 10 entries max, pruned per slot).
    pub fn save_evidence_state(&self, state: &wire::EvidenceState) -> Result<(), String> {
        let bytes = wire::encode_evidence_state(state);
        self.db
            .put_opt(EVIDENCE_STATE_KEY, &bytes, &self.sync_opts)
            .map_err(|e| format!("failed to save evidence state: {}", e))?;
        debug!(
            pending = state.pending.len(),
            broadcast = state.broadcast.len(),
            seen = state.seen.len(),
            bytes = bytes.len(),
            "evidence state persisted"
        );
        Ok(())
    }

    /// Load the previously-persisted evidence state, if any.
    pub fn load_evidence_state(&self) -> Result<Option<wire::EvidenceState>, String> {
        match self.db.get(EVIDENCE_STATE_KEY) {
            Ok(Some(bytes)) => {
                let state = wire::decode_evidence_state(&bytes)
                    .map_err(|e| format!("failed to decode evidence state: {}", e))?;
                info!(
                    pending = state.pending.len(),
                    broadcast = state.broadcast.len(),
                    seen = state.seen.len(),
                    "evidence state restored from disk"
                );
                Ok(Some(state))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("failed to read evidence state: {}", e)),
        }
    }

    /// Persist resharing runtime state (task 034 crash safety). Written
    /// on each state transition: `prepare_for_reshare_reception`,
    /// `start_committee_reshare`, `try_aggregate_reshare_on_slot` when it
    /// fires. Small blob (committee keys + scalars, tens of KB), so
    /// fsync cost per transition is bounded.
    pub fn save_reshare_state(&self, state: &wire::ReshareState) -> Result<(), String> {
        let bytes = wire::encode_reshare_state(state);
        self.db
            .put_opt(RESHARE_STATE_KEY, &bytes, &self.sync_opts)
            .map_err(|e| format!("failed to save reshare state: {}", e))?;
        debug!(
            target_epoch = state.target_epoch,
            new_index = state.new_index,
            aggregated = state.aggregated,
            bytes = bytes.len(),
            "reshare state persisted"
        );
        Ok(())
    }

    /// Load the previously-persisted reshare state, if any.
    pub fn load_reshare_state(&self) -> Result<Option<wire::ReshareState>, String> {
        match self.db.get(RESHARE_STATE_KEY) {
            Ok(Some(bytes)) => {
                let state = wire::decode_reshare_state(&bytes)
                    .map_err(|e| format!("failed to decode reshare state: {}", e))?;
                info!(
                    target_epoch = state.target_epoch,
                    new_index = state.new_index,
                    aggregated = state.aggregated,
                    "reshare state restored from disk"
                );
                Ok(Some(state))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("failed to read reshare state: {}", e)),
        }
    }

    /// Remove any persisted reshare state. Used when an epoch's rotation
    /// completes successfully; keeping stale state around causes confused
    /// behavior on a subsequent restart.
    #[allow(dead_code)]
    pub fn clear_reshare_state(&self) -> Result<(), String> {
        self.db
            .delete_opt(RESHARE_STATE_KEY, &self.sync_opts)
            .map_err(|e| format!("failed to clear reshare state: {}", e))?;
        debug!("reshare state cleared");
        Ok(())
    }

    /// Persist the current weak-subjectivity finality checkpoint (slice 4.3).
    /// Called every time `FinalityTracker::record_hard_finality` produces a
    /// new checkpoint. fsync'd per the store's safety contract so a crash
    /// between finality and the next restart doesn't silently reset the
    /// WS anchor and let a long-range-attack chain through.
    pub fn save_finality_checkpoint(
        &self,
        cp: &pyde_consensus::finality::FinalityCheckpoint,
    ) -> Result<(), String> {
        let bytes = wire::encode_finality_checkpoint(cp);
        self.db
            .put_opt(FINALITY_CHECKPOINT_KEY, &bytes, &self.sync_opts)
            .map_err(|e| format!("failed to save finality checkpoint: {}", e))?;
        debug!(
            slot = cp.slot,
            bytes = bytes.len(),
            "finality checkpoint persisted"
        );
        Ok(())
    }

    /// Load the persisted WS checkpoint, if any. Returns `Ok(None)` on a
    /// fresh store or one that has never seen hard finality yet.
    pub fn load_finality_checkpoint(
        &self,
    ) -> Result<Option<pyde_consensus::finality::FinalityCheckpoint>, String> {
        match self.db.get(FINALITY_CHECKPOINT_KEY) {
            Ok(Some(bytes)) => {
                let cp = wire::decode_finality_checkpoint(&bytes)
                    .map_err(|e| format!("failed to decode finality checkpoint: {}", e))?;
                info!(
                    slot = cp.slot,
                    "weak-subjectivity checkpoint restored from disk"
                );
                Ok(Some(cp))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("failed to read finality checkpoint: {}", e)),
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

    /// TPL-501: persist the view-change message THIS validator
    /// signed at `slot` together with the `highest_qc_hash` it
    /// was signed over. Called BEFORE `on_timeout` returns the
    /// signed message — without that ordering a crash between
    /// signing and persisting could let the validator sign a
    /// different VC at the same slot post-restart, equivocating
    /// itself for a slashable offense.
    /// fsync'd before return (see struct docstring).
    pub fn save_seen_view_change_self(
        &self,
        slot: u64,
        highest_qc_hash: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), String> {
        let mut key = Vec::with_capacity(VC_SELF_PREFIX.len() + 8);
        key.extend_from_slice(VC_SELF_PREFIX);
        key.extend_from_slice(&slot.to_be_bytes());
        let mut value = Vec::with_capacity(32 + signature.len());
        value.extend_from_slice(highest_qc_hash);
        value.extend_from_slice(signature);
        self.db
            .put_opt(&key, &value, &self.sync_opts)
            .map_err(|e| format!("failed to save seen view-change: {}", e))
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

    /// TPL-501: load all persisted self-VC records. Corrupt
    /// entries (wrong key length, value too short to fit the
    /// 32-byte qc_hash prefix) are skipped + logged. Called
    /// from `attach_consensus_store` to seed the in-memory
    /// `seen_view_changes_self` map post-restart.
    pub fn load_all_seen_view_changes_self(&self) -> Vec<SeenViewChangeSelf> {
        let mut out = Vec::new();
        for item in self.db.prefix_iterator(VC_SELF_PREFIX) {
            let (k, v) = match item {
                Ok(kv) => kv,
                Err(e) => {
                    warn!(error = %e, "iterator error on self-VC records");
                    continue;
                }
            };
            if !k.starts_with(VC_SELF_PREFIX) {
                break;
            }
            let slot_bytes = match k.get(VC_SELF_PREFIX.len()..VC_SELF_PREFIX.len() + 8) {
                Some(b) => b,
                None => {
                    warn!("skipping self-VC key shorter than VC_SELF_PREFIX + 8");
                    continue;
                }
            };
            let mut buf = [0u8; 8];
            buf.copy_from_slice(slot_bytes);
            let slot = u64::from_be_bytes(buf);
            if v.len() < 32 {
                warn!(slot, "skipping self-VC value shorter than 32 bytes");
                continue;
            }
            let mut qc_hash = [0u8; 32];
            qc_hash.copy_from_slice(&v[..32]);
            let signature = v[32..].to_vec();
            out.push((slot, (qc_hash, signature)));
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

    /// Delete on-disk evidence-index entries below the per-bucket
    /// floors. Mirrors the in-memory pruning in
    /// `ValidatorEngine::advance_slot`.
    ///
    /// `proposal_floor` governs `PROPOSAL_PREFIX` entries. It MUST
    /// match the in-memory `seen_proposals` clamp
    /// (`prune_floor = min(wall-clock-window, target_height)`).
    /// Without that match, a crash-during-wedge → restart erases
    /// the self-dedup entry for the stuck `target_height` on disk;
    /// the post-restart proposer then rebuilds the same
    /// `(target_height, view=0)` with a fresh `timestamp` (different
    /// `block_hash`), which is a proposer-equivocation signature
    /// honest peers slash on.
    ///
    /// `vote_vc_floor` governs `VOTE_PREFIX` and `VC_SELF_PREFIX`
    /// entries. The strict wall-clock window
    /// (`current_slot - 10`) is the right floor for these — they
    /// are read by inbound-message handlers only, not by our own
    /// build path, so wedges don't alter their correctness window.
    pub fn prune_evidence_before(
        &self,
        proposal_floor: u64,
        vote_vc_floor: u64,
    ) -> Result<usize, String> {
        let mut batch = WriteBatch::default();
        let mut count = 0usize;

        for (prefix, floor) in [
            (PROPOSAL_PREFIX, proposal_floor),
            (VOTE_PREFIX, vote_vc_floor),
            (VC_SELF_PREFIX, vote_vc_floor),
        ] {
            for item in self
                .db
                .iterator(IteratorMode::From(prefix, rocksdb::Direction::Forward))
            {
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
                if slot < floor {
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
            debug!(
                pruned = count,
                proposal_floor, vote_vc_floor, "evidence pruned"
            );
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
            last_voted_view: 0,
            last_committed_hash: [0xCD; 32],
            last_committed_slot: 98,
            target_height: 100,
            current_view: 0,
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
        let loaded = store
            .load()
            .unwrap()
            .expect("state must persist across reopen");
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

        store
            .save_seen_proposal(10, &proposer, &header, &sig)
            .unwrap();

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
        store
            .save_seen_proposal(5, &a, &dummy_header(5), &[0x11; 10])
            .unwrap();
        store
            .save_seen_proposal(5, &b, &dummy_header(5), &[0x22; 10])
            .unwrap();

        let all = store.load_all_seen_proposals();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn prune_removes_old_entries_only() {
        let dir = tempdir().unwrap();
        let store = ConsensusStateStore::open(dir.path()).unwrap();

        for slot in 1..=15u64 {
            store
                .save_seen_proposal(slot, &[0xAA; 32], &dummy_header(slot), &[0x11; 10])
                .unwrap();
            store
                .save_seen_vote(slot, 0, &[0x77; 32], &[0x22; 10])
                .unwrap();
        }

        assert_eq!(store.load_all_seen_proposals().len(), 15);
        assert_eq!(store.load_all_seen_votes().len(), 15);

        // Steady-state pruning (both floors at 6): slots < 6 pruned
        // across PROPOSAL + VOTE prefixes.
        let pruned = store.prune_evidence_before(6, 6).unwrap();
        assert_eq!(pruned, 10); // 5 proposals + 5 votes

        let props = store.load_all_seen_proposals();
        let votes = store.load_all_seen_votes();
        assert_eq!(props.len(), 10);
        assert_eq!(votes.len(), 10);
        assert!(props.iter().all(|((slot, _), _)| *slot >= 6));
        assert!(votes.iter().all(|((slot, _), _)| *slot >= 6));
    }

    /// Wedge-protection on disk: when `target_height` is stuck
    /// below the wall-clock window, `proposal_floor` clamps to
    /// `target_height` while `vote_vc_floor` keeps the wall-clock
    /// window. Verifies that PROPOSAL_PREFIX entries survive while
    /// VOTE_PREFIX prunes normally.
    #[test]
    fn prune_keeps_proposals_for_wedged_target_height() {
        let dir = tempdir().unwrap();
        let store = ConsensusStateStore::open(dir.path()).unwrap();

        for slot in 1..=15u64 {
            store
                .save_seen_proposal(slot, &[0xAA; 32], &dummy_header(slot), &[0x11; 10])
                .unwrap();
            store
                .save_seen_vote(slot, 0, &[0x77; 32], &[0x22; 10])
                .unwrap();
        }

        // proposal_floor = 4 (target_height stuck at 4), vote_vc_floor = 6
        // (wall-clock - 10). Proposals 4-15 survive (12); votes 6-15
        // survive (10). Pruned = 3 + 5 = 8.
        let pruned = store.prune_evidence_before(4, 6).unwrap();
        assert_eq!(pruned, 8);

        let props = store.load_all_seen_proposals();
        let votes = store.load_all_seen_votes();
        assert_eq!(props.len(), 12);
        assert_eq!(votes.len(), 10);
        assert!(props.iter().all(|((slot, _), _)| *slot >= 4));
        assert!(votes.iter().all(|((slot, _), _)| *slot >= 6));
        // The wedge-anchor entry survives.
        assert!(props.iter().any(|((slot, _), _)| *slot == 4));
    }

    #[test]
    fn evidence_survives_reopen() {
        let dir = tempdir().unwrap();
        let proposer = [0xAA; 32];
        let header = dummy_header(7);
        let sig = vec![0xEE; 600];

        {
            let store = ConsensusStateStore::open(dir.path()).unwrap();
            store
                .save_seen_proposal(7, &proposer, &header, &sig)
                .unwrap();
            store
                .save_seen_vote(7, 3, &[0x99; 32], &vec![0xFF; 600])
                .unwrap();
        }

        let store = ConsensusStateStore::open(dir.path()).unwrap();
        assert_eq!(store.load_all_seen_proposals().len(), 1);
        assert_eq!(store.load_all_seen_votes().len(), 1);
    }

    #[test]
    fn finality_checkpoint_empty_load_returns_none() {
        let dir = tempdir().unwrap();
        let store = ConsensusStateStore::open(dir.path()).unwrap();
        assert!(store.load_finality_checkpoint().unwrap().is_none());
    }

    #[test]
    fn finality_checkpoint_roundtrips() {
        use pyde_consensus::finality::{FinalityCheckpoint, HardFinalityCert};
        let dir = tempdir().unwrap();
        let store = ConsensusStateStore::open(dir.path()).unwrap();
        let cp = FinalityCheckpoint {
            slot: 1_234,
            block_hash: [0xAB; 32],
            state_root: [0xCD; 32],
            cert: HardFinalityCert {
                slot: 1_234,
                block_hash: [0xAB; 32],
                state_root: [0xCD; 32],
                voter_bitmap: (1u128 << 86) - 1,
                signatures: vec![vec![0x11; 600], vec![0x22; 600], vec![0x33; 600]],
            },
        };
        store.save_finality_checkpoint(&cp).unwrap();
        let loaded = store.load_finality_checkpoint().unwrap().unwrap();
        assert_eq!(loaded.slot, cp.slot);
        assert_eq!(loaded.block_hash, cp.block_hash);
        assert_eq!(loaded.state_root, cp.state_root);
        assert_eq!(loaded.cert.slot, cp.cert.slot);
        assert_eq!(loaded.cert.voter_bitmap, cp.cert.voter_bitmap);
        assert_eq!(loaded.cert.signatures.len(), cp.cert.signatures.len());
        for (a, b) in loaded.cert.signatures.iter().zip(cp.cert.signatures.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn finality_checkpoint_msg_wire_roundtrip() {
        use pyde_consensus::finality::{FinalityCheckpoint, HardFinalityCert};
        let cp = FinalityCheckpoint {
            slot: 42,
            block_hash: [0xAA; 32],
            state_root: [0xBB; 32],
            cert: HardFinalityCert {
                slot: 42,
                block_hash: [0xAA; 32],
                state_root: [0xBB; 32],
                voter_bitmap: 0x00FF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
                signatures: vec![vec![0x11; 600]; 86],
            },
        };
        let bytes = wire::encode_finality_checkpoint_msg(&cp);
        assert_eq!(bytes[0], wire::tag::CONSENSUS_FINALITY_CHECKPOINT);
        let decoded = wire::decode_finality_checkpoint_msg(&bytes).unwrap();
        assert_eq!(decoded.slot, cp.slot);
        assert_eq!(decoded.cert.signatures.len(), cp.cert.signatures.len());
    }

    #[test]
    fn finality_checkpoint_msg_rejects_wrong_tag() {
        // Payload missing the envelope tag — must not be silently treated
        // as a checkpoint (that would let a blocked peer smuggle WS
        // updates through via a mis-tagged topic).
        let bytes = vec![0xFF; 100];
        assert!(wire::decode_finality_checkpoint_msg(&bytes).is_err());
    }

    #[test]
    fn finality_checkpoint_survives_reopen() {
        use pyde_consensus::finality::{FinalityCheckpoint, HardFinalityCert};
        let dir = tempdir().unwrap();
        let cp = FinalityCheckpoint {
            slot: 7,
            block_hash: [0xFF; 32],
            state_root: [0x01; 32],
            cert: HardFinalityCert {
                slot: 7,
                block_hash: [0xFF; 32],
                state_root: [0x01; 32],
                voter_bitmap: 0,
                signatures: vec![],
            },
        };
        {
            let store = ConsensusStateStore::open(dir.path()).unwrap();
            store.save_finality_checkpoint(&cp).unwrap();
        }
        // Simulated restart.
        let store = ConsensusStateStore::open(dir.path()).unwrap();
        let loaded = store.load_finality_checkpoint().unwrap().unwrap();
        assert_eq!(loaded.slot, 7);
        assert_eq!(loaded.block_hash, cp.block_hash);
    }

    #[test]
    fn consensus_state_and_evidence_coexist() {
        // Belt-and-braces: saving state + evidence in the same DB must not
        // stomp each other (shared RocksDB with distinct key prefixes).
        let dir = tempdir().unwrap();
        let store = ConsensusStateStore::open(dir.path()).unwrap();

        store.save(&populated_state()).unwrap();
        store
            .save_seen_proposal(50, &[0xAA; 32], &dummy_header(50), &[0x11; 10])
            .unwrap();
        store
            .save_seen_vote(50, 1, &[0x99; 32], &[0x22; 10])
            .unwrap();

        assert!(store.load().unwrap().is_some());
        assert_eq!(store.load_all_seen_proposals().len(), 1);
        assert_eq!(store.load_all_seen_votes().len(), 1);
    }

    /// Hardening task 014f: measure fsync overhead on consensus-state
    /// writes so we know whether per-vote `set_sync(true)` caps us
    /// below the 12,500 TPS target at 400 ms slots.
    ///
    /// Gated as `#[ignore]` — it's informational + sensitive to the
    /// host filesystem (SSD vs HDD, ext4 vs APFS vs NTFS). Run with:
    ///
    /// ```text
    /// cargo test -p pyde-node --bin pyde --release -- --ignored \
    ///     consensus_store::tests::fsync_cost_bench --nocapture
    /// ```
    ///
    /// Reports per-write latency and derived max TPS. If sync mode
    /// shows > 10× latency and drops TPS below 1000, switch to batched
    /// writes or slot-end sync before mainnet.
    #[test]
    #[ignore = "benchmark — run with --ignored"]
    fn fsync_cost_bench() {
        use std::time::Instant;

        const ITERATIONS: u32 = 500;

        // Baseline: sync=false (WAL to OS page cache, no fsync).
        let dir_async = tempdir().unwrap();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db_async = DB::open(&opts, dir_async.path().join("async")).unwrap();
        let async_opts = WriteOptions::default();
        let state = populated_state();
        let bytes = wire::encode_consensus_state(&state);

        let t0 = Instant::now();
        for i in 0..ITERATIONS {
            let mut key = b"x:".to_vec();
            key.extend_from_slice(&i.to_le_bytes());
            db_async.put_opt(&key, &bytes, &async_opts).unwrap();
        }
        let async_total = t0.elapsed();
        let async_per = async_total.as_secs_f64() / ITERATIONS as f64 * 1_000_000.0;
        let async_tps = 1.0 / (async_total.as_secs_f64() / ITERATIONS as f64);

        // Production: sync=true (fsync on every write).
        let dir_sync = tempdir().unwrap();
        let db_sync = DB::open(&opts, dir_sync.path().join("sync")).unwrap();
        let mut sync_opts = WriteOptions::default();
        sync_opts.set_sync(true);

        let t0 = Instant::now();
        for i in 0..ITERATIONS {
            let mut key = b"x:".to_vec();
            key.extend_from_slice(&i.to_le_bytes());
            db_sync.put_opt(&key, &bytes, &sync_opts).unwrap();
        }
        let sync_total = t0.elapsed();
        let sync_per = sync_total.as_secs_f64() / ITERATIONS as f64 * 1_000_000.0;
        let sync_tps = 1.0 / (sync_total.as_secs_f64() / ITERATIONS as f64);

        eprintln!();
        eprintln!(
            "=== ConsensusStateStore fsync cost ({} writes, {}-byte payload) ===",
            ITERATIONS,
            bytes.len()
        );
        eprintln!(
            "async (page cache): {:>8.1} µs/write  →  {:>9.0} writes/sec",
            async_per, async_tps
        );
        eprintln!(
            "sync  (fsync)    : {:>8.1} µs/write  →  {:>9.0} writes/sec",
            sync_per, sync_tps
        );
        eprintln!(
            "overhead: {:.1}× slower",
            sync_total.as_secs_f64() / async_total.as_secs_f64()
        );
        eprintln!();

        // Sanity: both paths produced durable writes. We don't assert a
        // hard TPS threshold — the number is environment-dependent. The
        // operator reads the output and decides whether to re-tune.
    }
}
