//! Chain sync: full block sync over libp2p request-response.
//!
//! When a new node connects, it discovers the network tip and downloads
//! full blocks (header + body) in batches. Each block is executed against
//! state via BlockProcessor, building up the full chain from genesis.
//!
//! For nodes very far behind (>1000 slots), state snapshot sync is available
//! as an optimization (download state trie directly, skip replay).

use crate::block_processor::BlockProcessor;
use crate::block_store::BlockStore;
use crate::chain::ChainState;
use crate::state_manager::StateManager;
use libp2p::request_response::OutboundRequestId;
use libp2p::{PeerId, Swarm};
use pyde_net::node::PydeBehaviour;
use pyde_net::sync::SyncManager;
use pyde_net::sync_protocol::{SyncReq, SyncResp};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Chain sync coordinator.
/// Manages the sync state machine and dispatches requests to peers.
/// Default chunk size for snapshot transfers (entries per chunk).
pub const SNAPSHOT_CHUNK_SIZE: u32 = 5000;
/// Max retries per chunk before giving up.
const CHUNK_MAX_RETRIES: u32 = 3;

pub struct ChainSync {
    /// Sync state tracker from the net crate.
    pub manager: SyncManager,
    /// Outstanding outbound requests: request_id → peer.
    pending: HashMap<OutboundRequestId, PeerId>,
    /// Whether initial sync has completed at least once.
    pub initial_sync_done: bool,
    /// Chunked snapshot receiver state.
    snapshot_chunks: Vec<(u32, Vec<(Vec<u8>, Vec<u8>)>, [u8; 32])>,
    snapshot_expected_root: Option<[u8; 32]>,
    snapshot_total_chunks: u32,
    snapshot_head_slot: u64,
    snapshot_retry_count: u32,
}

/// Pinned snapshot cache for serving chunked requests.
/// Created on first chunk request, reused for all subsequent chunks
/// so the state root stays consistent across the entire transfer.
pub struct PinnedSnapshot {
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
    pub state_root: [u8; 32],
    pub head_slot: u64,
    /// Slot at which this snapshot was pinned (stale after N slots).
    pub pinned_at_slot: u64,
}

impl ChainSync {
    pub fn new() -> Self {
        Self {
            manager: SyncManager::new(),
            pending: HashMap::new(),
            initial_sync_done: false,
            snapshot_chunks: Vec::new(),
            snapshot_expected_root: None,
            snapshot_total_chunks: 0,
            snapshot_head_slot: 0,
            snapshot_retry_count: 0,
        }
    }

    /// Called when we learn a peer's chain tip (from ChainTip response or identify).
    #[allow(dead_code)]
    pub fn on_peer_tip(&mut self, peer: PeerId, tip_slot: u64) {
        let old_tip = self.manager.network_tip;
        self.manager.update_network_tip(tip_slot);
        if tip_slot > old_tip {
            info!(
                %peer,
                network_tip = tip_slot,
                local_tip = self.manager.local_tip,
                behind = self.manager.slots_behind(),
                "network tip updated"
            );
        }
    }

    /// Called after we process a block. Advances our local tip.
    pub fn on_block_processed(&mut self, slot: u64) {
        self.manager.advance_local_tip(slot);
        if !self.manager.needs_sync() && !self.initial_sync_done {
            self.initial_sync_done = true;
            info!(slot, "initial chain sync complete");
        }
    }

    /// Try to request the next batch of blocks from a peer.
    /// Returns true if a request was sent.
    pub fn request_next_batch(
        &mut self,
        swarm: &mut Swarm<PydeBehaviour>,
    ) -> bool {
        if !self.manager.needs_sync() {
            return false;
        }

        // Don't send multiple concurrent requests
        if !self.pending.is_empty() {
            return false;
        }

        // Pick a connected peer
        let peer = match swarm.connected_peers().next() {
            Some(p) => *p,
            None => {
                debug!("no peers to sync from");
                return false;
            }
        };

        if let Some(req) = self.manager.next_request() {
            let (start, count) = match &req {
                pyde_net::sync::SyncRequest::GetBlocks { start_slot, count } => (*start_slot, *count),
                _ => return false,
            };

            let request_id = swarm
                .behaviour_mut()
                .sync
                .send_request(&peer, SyncReq::GetBlocks { start_slot: start, count });

            self.pending.insert(request_id, peer);
            info!(
                %peer,
                start_slot = start,
                count,
                "requested blocks for sync"
            );
            true
        } else {
            false
        }
    }

    /// Ask a newly connected peer for their chain tip.
    pub fn request_chain_tip(
        &mut self,
        swarm: &mut Swarm<PydeBehaviour>,
        peer: PeerId,
    ) {
        let _id = swarm
            .behaviour_mut()
            .sync
            .send_request(&peer, SyncReq::GetChainTip);
        debug!(%peer, "requested chain tip");
    }

    /// Request a state snapshot from a peer (for fast sync when far behind).
    /// Uses chunked transfer for production, falls back to bulk for small states.
    #[allow(dead_code)]
    pub fn request_state_snapshot(
        &mut self,
        swarm: &mut Swarm<PydeBehaviour>,
    ) -> bool {
        let peer = match swarm.connected_peers().next() {
            Some(p) => *p,
            None => return false,
        };
        // Start chunked download from chunk 0
        self.snapshot_chunks.clear();
        self.snapshot_expected_root = None;
        self.snapshot_total_chunks = 0;
        let request_id = swarm
            .behaviour_mut()
            .sync
            .send_request(&peer, SyncReq::GetStateSnapshotChunk {
                chunk_index: 0,
                chunk_size: SNAPSHOT_CHUNK_SIZE,
            });
        self.pending.insert(request_id, peer);
        info!(%peer, chunk_size = SNAPSHOT_CHUNK_SIZE, "requested state snapshot (chunked)");
        true
    }

    /// Request the next chunk of an in-progress snapshot download.
    pub fn request_next_chunk(
        &mut self,
        swarm: &mut Swarm<PydeBehaviour>,
        peer: PeerId,
        next_index: u32,
    ) {
        let request_id = swarm
            .behaviour_mut()
            .sync
            .send_request(&peer, SyncReq::GetStateSnapshotChunk {
                chunk_index: next_index,
                chunk_size: SNAPSHOT_CHUNK_SIZE,
            });
        self.pending.insert(request_id, peer);
        debug!(chunk = next_index, "requesting next snapshot chunk");
    }

    /// Threshold: if behind by more than this many slots, use snapshot sync.
    #[allow(dead_code)]
    pub const SNAPSHOT_THRESHOLD: u64 = 1000;

    /// Handle a sync response from a peer.
    /// Returns the number of blocks processed.
    ///
    /// `ws_checkpoint_slot` (slice 4.3) is the caller's live
    /// weak-subjectivity anchor — `Some(cp_slot)` during normal
    /// operation, `None` during first-time bootstrap. Blocks at or
    /// before `cp_slot` are rejected even via sync to defend against
    /// long-range attacks delivered through a compromised peer.
    pub fn on_response(
        &mut self,
        request_id: OutboundRequestId,
        response: SyncResp,
        chain: &mut ChainState,
        state: &mut StateManager,
        block_store: &BlockStore,
        ws_checkpoint_slot: Option<u64>,
    ) -> u64 {
        self.pending.remove(&request_id);

        match response {
            SyncResp::ChainTip { slot, block_hash } => {
                self.manager.update_network_tip(slot);
                info!(slot, hash = hex::encode(block_hash), "received chain tip");
                0
            }
            SyncResp::Blocks(block_data) => {
                let count = block_data.len();
                let mut processed = 0u64;

                for data in &block_data {
                    // Decode full block (header + body + signature)
                    match crate::wire::decode_block(data) {
                        Ok(block) => {
                            let slot = block.header.slot;
                            // Validate synced block body (includes signature verification)
                            if let Err(e) = BlockProcessor::validate_synced_block_body(
                                &block, state, chain.chain_id,
                            ) {
                                warn!(slot, error = %e, "synced block body validation failed");
                                break;
                            }
                            match BlockProcessor::process_full_block_with_aot_and_checkpoint(
                                chain, state, &block, None, ws_checkpoint_slot,
                            ) {
                                Ok((tx_count, gas_used, _receipts)) => {
                                    // Persist to disk for future sync serving
                                    let _ = block_store.put_block(&block.header, data);
                                    let _ = block_store.put_head(slot);
                                    self.manager.advance_local_tip(slot);
                                    processed += 1;
                                    debug!(slot, tx_count, gas_used, "synced block");
                                }
                                Err(e) => {
                                    warn!(slot, error = %e, "failed to process synced block");
                                    break;
                                }
                            }
                        }
                        Err(_) => {
                            // Fallback: try header-only decode for backwards compat
                            if let Ok(header) = crate::wire::decode_block_header(data) {
                                match BlockProcessor::process_block_with_checkpoint(
                                    chain, state, header, &[], ws_checkpoint_slot,
                                ) {
                                    Ok(_) => {
                                        self.manager.advance_local_tip(chain.head_slot);
                                        processed += 1;
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "failed to process synced header");
                                        break;
                                    }
                                }
                            } else {
                                warn!(len = data.len(), "failed to decode synced block");
                                break;
                            }
                        }
                    }
                }

                info!(
                    received = count,
                    processed,
                    head = chain.head_slot,
                    "sync batch processed"
                );
                processed
            }
            SyncResp::Headers(_) => {
                debug!("received headers (not used in block sync)");
                0
            }
            SyncResp::StateSnapshot { state_root, head_slot, entries } => {
                let count = entries.len();
                info!(
                    entries = count,
                    head_slot,
                    state_root = hex::encode(state_root),
                    "received state snapshot"
                );

                match state.import_snapshot(entries) {
                    Ok(imported_root) => {
                        if imported_root == state_root {
                            self.manager.advance_local_tip(head_slot);
                            if !self.initial_sync_done {
                                self.initial_sync_done = true;
                            }
                            info!(
                                head_slot,
                                entries = count,
                                "state snapshot applied — node synced"
                            );
                        } else {
                            warn!(
                                expected = hex::encode(state_root),
                                got = hex::encode(imported_root),
                                "state root mismatch after snapshot import"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to import state snapshot");
                    }
                }
                0
            }
            SyncResp::StateSnapshotChunk {
                state_root, head_slot, chunk_index, total_chunks, chunk_hash, entries,
            } => {
                // Verify chunk hash
                let mut hash_buf = Vec::new();
                for (k, v) in &entries {
                    hash_buf.extend_from_slice(k);
                    hash_buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
                    hash_buf.extend_from_slice(v);
                }
                let computed = pyde_crypto::poseidon2::poseidon2_hash(&hash_buf).to_bytes();
                if computed != chunk_hash {
                    self.snapshot_retry_count += 1;
                    if self.snapshot_retry_count > CHUNK_MAX_RETRIES {
                        warn!(chunk = chunk_index, retries = self.snapshot_retry_count,
                            "snapshot chunk hash mismatch — max retries exceeded, aborting sync");
                        self.snapshot_chunks.clear();
                        self.snapshot_expected_root = None;
                        self.snapshot_total_chunks = 0;
                        self.snapshot_retry_count = 0;
                    } else {
                        warn!(chunk = chunk_index, retry = self.snapshot_retry_count,
                            "snapshot chunk hash mismatch — will retry");
                        // Don't store the bad chunk — needs_next_chunk() will re-request it
                    }
                    return 0;
                }
                self.snapshot_retry_count = 0; // reset on success

                // Store chunk
                if self.snapshot_expected_root.is_none() {
                    self.snapshot_expected_root = Some(state_root);
                    self.snapshot_total_chunks = total_chunks;
                    self.snapshot_head_slot = head_slot;
                }
                self.snapshot_chunks.push((chunk_index, entries, chunk_hash));

                info!(
                    chunk = chunk_index,
                    total = total_chunks,
                    collected = self.snapshot_chunks.len(),
                    "received snapshot chunk"
                );

                // If all chunks received, assemble and import
                if self.snapshot_chunks.len() as u32 >= total_chunks {
                    // Sort by index, flatten entries
                    self.snapshot_chunks.sort_by_key(|(idx, _, _)| *idx);
                    let all_entries: Vec<(Vec<u8>, Vec<u8>)> = self.snapshot_chunks
                        .drain(..)
                        .flat_map(|(_, entries, _)| entries)
                        .collect();

                    let root = self.snapshot_expected_root.take().unwrap_or([0u8; 32]);
                    let slot = self.snapshot_head_slot;

                    info!(entries = all_entries.len(), head_slot = slot, "all chunks received — importing snapshot");

                    match state.import_snapshot(all_entries) {
                        Ok(imported_root) => {
                            if imported_root == root {
                                self.manager.advance_local_tip(slot);
                                if !self.initial_sync_done {
                                    self.initial_sync_done = true;
                                }
                                info!(head_slot = slot, "chunked snapshot applied — node synced");
                            } else {
                                warn!(
                                    expected = hex::encode(root),
                                    got = hex::encode(imported_root),
                                    "state root mismatch after chunked snapshot"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to import chunked snapshot");
                        }
                    }
                }
                0
            }
            SyncResp::NotFound => {
                // If we're mid-chunk-sync, abort — peer can't serve the snapshot
                if self.snapshot_total_chunks > 0 {
                    warn!("peer returned NotFound during chunked snapshot — aborting");
                    self.snapshot_chunks.clear();
                    self.snapshot_expected_root = None;
                    self.snapshot_total_chunks = 0;
                    self.snapshot_retry_count = 0;
                } else {
                    warn!("peer doesn't have requested data");
                }
                0
            }
        }
    }

    /// Handle an inbound sync request from a peer.
    /// `pinned_snapshot` is used for chunked requests — the caller pins the snapshot
    /// on first chunk request and reuses it for all subsequent chunks.
    pub fn handle_inbound_request(
        req: &SyncReq,
        chain: &ChainState,
        state: &StateManager,
        block_store: &BlockStore,
        pinned_snapshot: &mut Option<PinnedSnapshot>,
    ) -> SyncResp {
        match req {
            SyncReq::GetChainTip => {
                SyncResp::ChainTip {
                    slot: chain.head_slot,
                    block_hash: chain.state_root,
                }
            }
            SyncReq::GetBlocks { start_slot, count } => {
                // Serve full wire-encoded blocks (header + body + signature).
                // Skips empty slots (sparse block history — not every slot has a block).
                let mut blocks = Vec::new();
                let end_slot = *start_slot + *count as u64;
                // Scan up to end_slot or chain head, whichever is higher
                let scan_end = end_slot.max(chain.head_slot + 1);
                for slot in *start_slot..scan_end {
                    if let Some(raw) = block_store.get_block_raw(slot) {
                        blocks.push(raw);
                    } else if let Some(header) = chain.header(slot) {
                        blocks.push(crate::wire::encode_block_header(header));
                    }
                    // Don't break on missing slots — blocks are sparse
                    if blocks.len() >= *count as usize {
                        break;
                    }
                }
                if blocks.is_empty() {
                    SyncResp::NotFound
                } else {
                    SyncResp::Blocks(blocks)
                }
            }
            SyncReq::GetHeaders { start_slot, count } => {
                let mut headers = Vec::new();
                for slot in *start_slot..(*start_slot + *count as u64) {
                    if let Some(header) = chain.header(slot) {
                        headers.push(crate::wire::encode_block_header(header));
                    } else {
                        break;
                    }
                }
                if headers.is_empty() {
                    SyncResp::NotFound
                } else {
                    SyncResp::Headers(headers)
                }
            }
            SyncReq::GetStateSnapshot => {
                let entries = state.export_snapshot();
                if entries.is_empty() {
                    SyncResp::NotFound
                } else {
                    SyncResp::StateSnapshot {
                        state_root: state.root(),
                        head_slot: chain.head_slot,
                        entries,
                    }
                }
            }
            SyncReq::GetStateSnapshotChunk { chunk_index, chunk_size } => {
                // Pin snapshot on first chunk request (reuse for all subsequent chunks)
                let snap = pinned_snapshot.get_or_insert_with(|| {
                    let entries = state.export_snapshot();
                    PinnedSnapshot {
                        state_root: state.root(),
                        head_slot: chain.head_slot,
                        pinned_at_slot: chain.head_slot,
                        entries,
                    }
                });

                // Expire stale pins (if state advanced >100 slots since pin)
                if chain.head_slot > snap.pinned_at_slot + 100 {
                    *pinned_snapshot = Some(PinnedSnapshot {
                        entries: state.export_snapshot(),
                        state_root: state.root(),
                        head_slot: chain.head_slot,
                        pinned_at_slot: chain.head_slot,
                    });
                }
                let snap = pinned_snapshot.as_ref().unwrap();

                if snap.entries.is_empty() {
                    return SyncResp::NotFound;
                }

                let cs = (*chunk_size as usize).max(1);
                let total_chunks = snap.entries.len().div_ceil(cs).max(1) as u32;
                let start = (*chunk_index as usize) * cs;

                if start >= snap.entries.len() {
                    return SyncResp::NotFound;
                }
                let end = (start + cs).min(snap.entries.len());
                let chunk_entries: Vec<(Vec<u8>, Vec<u8>)> = snap.entries[start..end].to_vec();

                let mut hash_buf = Vec::new();
                for (k, v) in &chunk_entries {
                    hash_buf.extend_from_slice(k);
                    hash_buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
                    hash_buf.extend_from_slice(v);
                }
                let chunk_hash = pyde_crypto::poseidon2::poseidon2_hash(&hash_buf).to_bytes();

                SyncResp::StateSnapshotChunk {
                    state_root: snap.state_root,
                    head_slot: snap.head_slot,
                    chunk_index: *chunk_index,
                    total_chunks,
                    chunk_hash,
                    entries: chunk_entries,
                }
            }
        }
    }

    /// Whether sync is in progress.
    pub fn is_syncing(&self) -> bool {
        self.manager.needs_sync()
    }

    /// Whether a chunked snapshot download is in progress and needs more chunks.
    /// Returns the next chunk index to request, or None if complete.
    pub fn needs_next_chunk(&self) -> Option<u32> {
        if self.snapshot_total_chunks == 0 { return None; }
        let collected = self.snapshot_chunks.len() as u32;
        if collected < self.snapshot_total_chunks {
            Some(collected)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::ZERO_ADDRESS;
    use pyde_consensus::block::{BlockHeader, QuorumCert};

    fn dummy_header(slot: u64) -> BlockHeader {
        BlockHeader {
            slot,
            epoch: 0,
            parent_hash: [0u8; 32],
            proposer: ZERO_ADDRESS,
            vrf_proof: vec![],
            qc_previous: QuorumCert::empty(),
            tx_root: [slot as u8; 32],
            state_root: [slot as u8; 32],
            timestamp: slot * 400,
        }
    }

    #[test]
    fn header_wire_roundtrip() {
        let header = dummy_header(42);
        let bytes = crate::wire::encode_block_header(&header);
        let restored = crate::wire::decode_block_header(&bytes).unwrap();

        assert_eq!(restored.slot, 42);
        assert_eq!(restored.epoch, 0);
        assert_eq!(restored.state_root, [42u8; 32]);
        assert_eq!(restored.tx_root, [42u8; 32]);
        assert_eq!(restored.timestamp, 42 * 400);
    }

    #[test]
    fn decode_too_short_returns_err() {
        assert!(crate::wire::decode_block_header(&[0u8; 5]).is_err());
    }

    #[test]
    fn sync_manager_tracks_tips() {
        let mut sync = ChainSync::new();
        let peer = PeerId::random();

        sync.on_peer_tip(peer, 100);
        assert_eq!(sync.manager.network_tip, 100);
        assert!(sync.manager.needs_sync());
        assert_eq!(sync.manager.slots_behind(), 100);
    }

    #[test]
    fn sync_completes_when_caught_up() {
        let mut sync = ChainSync::new();
        let peer = PeerId::random();

        sync.on_peer_tip(peer, 5);
        assert!(!sync.initial_sync_done);

        for slot in 1..=5 {
            sync.on_block_processed(slot);
        }

        assert!(!sync.manager.needs_sync());
        assert!(sync.initial_sync_done);
    }

    /// Return a `(StateManager, TempDir)` pair. Callers must hold the
    /// `TempDir` in scope for the life of the manager; dropping it
    /// removes the underlying directory. Using `tempfile::tempdir()`
    /// gives unique-per-invocation paths, which sidesteps the parallel
    /// RocksDB races that plague fixed `/tmp/pyde-*` tests.
    fn make_state() -> (StateManager, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let sm = StateManager::open(tmp.path(), 1024).unwrap();
        (sm, tmp)
    }

    fn make_block_store() -> (BlockStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let bs = BlockStore::open(tmp.path()).unwrap();
        (bs, tmp)
    }

    #[test]
    fn handle_chain_tip_request() {
        let mut chain = ChainState::genesis([0u8; 32], 1);
        chain.advance(dummy_header(10));
        let (state, _sd) = make_state();
        let (bs, _bd) = make_block_store();

        let resp = ChainSync::handle_inbound_request(&SyncReq::GetChainTip, &chain, &state, &bs, &mut None::<PinnedSnapshot>);
        match resp {
            SyncResp::ChainTip { slot, .. } => assert_eq!(slot, 10),
            _ => panic!("expected ChainTip response"),
        }
    }

    #[test]
    fn handle_get_blocks_request() {
        let mut chain = ChainState::genesis([0u8; 32], 1);
        for slot in 1..=5 {
            chain.advance(dummy_header(slot));
        }
        let (state, _sd) = make_state();
        let (bs, _bd) = make_block_store();

        let resp = ChainSync::handle_inbound_request(
            &SyncReq::GetBlocks { start_slot: 1, count: 3 },
            &chain, &state, &bs, &mut None::<PinnedSnapshot>,
        );
        match resp {
            SyncResp::Blocks(blocks) => {
                assert_eq!(blocks.len(), 3);
                // Falls back to header-only since no block bodies stored
                let h = crate::wire::decode_block_header(&blocks[0]).unwrap();
                assert_eq!(h.slot, 1);
            }
            _ => panic!("expected Blocks response"),
        }
    }

    #[test]
    fn handle_get_blocks_not_found() {
        let chain = ChainState::genesis([0u8; 32], 1);
        let (state, _sd) = make_state();
        let (bs, _bd) = make_block_store();

        let resp = ChainSync::handle_inbound_request(
            &SyncReq::GetBlocks { start_slot: 100, count: 10 },
            &chain, &state, &bs, &mut None::<PinnedSnapshot>,
        );
        match resp {
            SyncResp::NotFound => {}
            _ => panic!("expected NotFound"),
        }
    }

    #[test]
    fn handle_state_snapshot_request() {
        let mut chain = ChainState::genesis([0u8; 32], 1);
        chain.advance(dummy_header(5));
        let (mut state, _sd) = make_state();

        // Insert some state
        let key = pyde_state::keys::balance_key(&[0x01; 32]);
        state.insert(key, 42u128.to_le_bytes().to_vec()).unwrap();

        let (bs, _bd) = make_block_store();
        let resp = ChainSync::handle_inbound_request(
            &SyncReq::GetStateSnapshot,
            &chain, &state, &bs, &mut None::<PinnedSnapshot>,
        );
        match resp {
            SyncResp::StateSnapshot { state_root, head_slot, entries } => {
                assert_eq!(head_slot, 5);
                assert_eq!(entries.len(), 1);
                assert_eq!(state_root, state.root());
            }
            _ => panic!("expected StateSnapshot"),
        }
    }
}
