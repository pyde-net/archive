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
    ///
    /// Audit 220: when the node is more than `SNAPSHOT_THRESHOLD`
    /// slots behind the network tip and we haven't yet completed
    /// initial sync, delegate to `request_state_snapshot` instead
    /// of doing block-by-block catch-up. Cold-syncing 1M+ slots
    /// one batch at a time is impractical at scale; the snapshot
    /// path streams the SMT state in fixed-size chunks and lets
    /// the node skip directly to recent slots.
    pub fn request_next_batch(&mut self, swarm: &mut Swarm<PydeBehaviour>) -> bool {
        if !self.manager.needs_sync() {
            return false;
        }

        // Don't send multiple concurrent requests
        if !self.pending.is_empty() {
            return false;
        }

        // Audit 220: prefer snapshot sync when we're far behind and
        // haven't yet done initial sync. After initial sync finishes
        // the node stays caught up via gossip + small block-by-block
        // catch-up, so the threshold only fires for fresh nodes
        // joining a long-running chain.
        if self.should_use_snapshot_sync() {
            info!(
                slots_behind = self.manager.slots_behind(),
                threshold = Self::SNAPSHOT_THRESHOLD,
                "switching to snapshot sync for fast catch-up"
            );
            return self.request_state_snapshot(swarm);
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
                pyde_net::sync::SyncRequest::GetBlocks { start_slot, count } => {
                    (*start_slot, *count)
                }
                _ => return false,
            };

            let request_id = swarm.behaviour_mut().sync.send_request(
                &peer,
                SyncReq::GetBlocks {
                    start_slot: start,
                    count,
                },
            );

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
    pub fn request_chain_tip(&mut self, swarm: &mut Swarm<PydeBehaviour>, peer: PeerId) {
        let _id = swarm
            .behaviour_mut()
            .sync
            .send_request(&peer, SyncReq::GetChainTip);
        debug!(%peer, "requested chain tip");
    }

    /// Request a state snapshot from a peer (for fast sync when far behind).
    /// Uses chunked transfer for production, falls back to bulk for small states.
    /// Auto-invoked from `request_next_batch` when far behind (audit 220).
    pub fn request_state_snapshot(&mut self, swarm: &mut Swarm<PydeBehaviour>) -> bool {
        let peer = match swarm.connected_peers().next() {
            Some(p) => *p,
            None => return false,
        };
        // Start chunked download from chunk 0
        self.snapshot_chunks.clear();
        self.snapshot_expected_root = None;
        self.snapshot_total_chunks = 0;
        let request_id = swarm.behaviour_mut().sync.send_request(
            &peer,
            SyncReq::GetStateSnapshotChunk {
                chunk_index: 0,
                chunk_size: SNAPSHOT_CHUNK_SIZE,
            },
        );
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
        let request_id = swarm.behaviour_mut().sync.send_request(
            &peer,
            SyncReq::GetStateSnapshotChunk {
                chunk_index: next_index,
                chunk_size: SNAPSHOT_CHUNK_SIZE,
            },
        );
        self.pending.insert(request_id, peer);
        debug!(chunk = next_index, "requesting next snapshot chunk");
    }

    /// Threshold: if behind by more than this many slots, use snapshot
    /// sync (audit 220). 1000 slots = ~6.7 minutes at 400 ms/slot, well
    /// past the point where block-by-block catch-up becomes wasteful.
    pub const SNAPSHOT_THRESHOLD: u64 = 1000;

    /// True if the next sync request should use snapshot mode rather
    /// than block-by-block. Pure predicate over the manager's local
    /// state — extracted from `request_next_batch` so the threshold
    /// logic is unit-testable without a live `Swarm`.
    pub fn should_use_snapshot_sync(&self) -> bool {
        !self.initial_sync_done
            && self.snapshot_chunks.is_empty()
            && self.snapshot_expected_root.is_none()
            && self.manager.slots_behind() > Self::SNAPSHOT_THRESHOLD
    }

    /// Audit 241: WS-anchor admission check for snapshots. Returns
    /// `Err(reason)` if the announced `(head_slot, state_root)` would
    /// violate the weak-subjectivity anchor; `Ok(())` otherwise.
    ///
    /// `None` ws_checkpoint means first-time bootstrap — accept any
    /// snapshot. With a checkpoint set, two cases reject:
    /// - `head_slot < cp_slot`: snapshot would regress past the
    ///   finalized anchor.
    /// - `head_slot == cp_slot && state_root != cp_state_root`:
    ///   snapshot's anchor-slot state diverges from canonical
    ///   (long-range fork).
    ///
    /// Snapshots strictly beyond the anchor (`head_slot > cp_slot`)
    /// pass this check; deeper root-vs-canonical-block matching for
    /// post-anchor snapshots is a follow-up — would need per-slot
    /// state-root tracking that the chain doesn't expose today.
    fn check_snapshot_ws_anchor(
        head_slot: u64,
        state_root: &[u8; 32],
        ws_checkpoint: Option<(u64, [u8; 32])>,
    ) -> Result<(), &'static str> {
        if let Some((cp_slot, cp_root)) = ws_checkpoint {
            if head_slot < cp_slot {
                return Err("snapshot head_slot is before WS checkpoint");
            }
            if head_slot == cp_slot && *state_root != cp_root {
                return Err("snapshot state_root at WS checkpoint slot does not match");
            }
        }
        Ok(())
    }

    /// Handle a sync response from a peer.
    /// Returns the number of blocks processed.
    ///
    /// `ws_checkpoint` (slice 4.3) is the caller's live
    /// weak-subjectivity anchor — `Some((cp_slot, cp_state_root))`
    /// during normal operation, `None` during first-time bootstrap.
    ///
    /// Block-sync paths (Blocks/Headers): blocks at or before
    /// `cp_slot` are rejected to defend against long-range attacks
    /// delivered through a compromised peer.
    ///
    /// Audit 241: snapshot paths apply the same anchor rule:
    /// snapshots whose `head_slot < cp_slot` are rejected outright
    /// (would regress us past a finalized checkpoint), and snapshots
    /// at exactly `head_slot == cp_slot` must announce a `state_root`
    /// matching the checkpoint's root (otherwise they're a long-range
    /// fork from the anchor). Without these guards, a malicious peer
    /// can deliver a crypto-internally-valid snapshot from a divergent
    /// chain and have it silently overwrite our state.
    pub fn on_response(
        &mut self,
        request_id: OutboundRequestId,
        response: SyncResp,
        chain: &mut ChainState,
        state: &mut StateManager,
        block_store: &BlockStore,
        ws_checkpoint: Option<(u64, [u8; 32])>,
    ) -> u64 {
        let ws_checkpoint_slot = ws_checkpoint.map(|(s, _)| s);
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
                                &block,
                                state,
                                chain.chain_id,
                            ) {
                                warn!(slot, error = %e, "synced block body validation failed");
                                break;
                            }
                            match BlockProcessor::process_full_block_with_aot_and_checkpoint(
                                chain,
                                state,
                                &block,
                                None,
                                ws_checkpoint_slot,
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
                                    chain,
                                    state,
                                    header,
                                    &[],
                                    ws_checkpoint_slot,
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
            SyncResp::StateSnapshot {
                state_root,
                head_slot,
                entries,
            } => {
                let count = entries.len();
                info!(
                    entries = count,
                    head_slot,
                    state_root = hex::encode(state_root),
                    "received state snapshot"
                );

                // Audit 241: WS-anchor guard. Reject snapshots that
                // would regress us past the finalized checkpoint, or
                // that announce a divergent state_root at exactly the
                // anchor slot (long-range fork).
                if let Err(reason) =
                    Self::check_snapshot_ws_anchor(head_slot, &state_root, ws_checkpoint)
                {
                    warn!(
                        head_slot,
                        announced_root = hex::encode(state_root),
                        ws = ?ws_checkpoint.map(|(s, _)| s),
                        reason,
                        "rejecting state snapshot"
                    );
                    return 0;
                }

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
                state_root,
                head_slot,
                chunk_index,
                total_chunks,
                chunk_hash,
                entries,
            } => {
                // Audit 241: WS-anchor guard for the chunked path.
                // Same admission rule as the single-shot path, applied
                // on every chunk so a peer that flips the announced
                // root mid-stream can't slip through. Reject also
                // clears any partial state so a retry starts clean.
                if let Err(reason) =
                    Self::check_snapshot_ws_anchor(head_slot, &state_root, ws_checkpoint)
                {
                    warn!(
                        head_slot,
                        announced_root = hex::encode(state_root),
                        ws = ?ws_checkpoint.map(|(s, _)| s),
                        reason,
                        "rejecting snapshot chunk"
                    );
                    self.snapshot_chunks.clear();
                    self.snapshot_expected_root = None;
                    self.snapshot_total_chunks = 0;
                    self.snapshot_retry_count = 0;
                    return 0;
                }

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
                        warn!(
                            chunk = chunk_index,
                            retries = self.snapshot_retry_count,
                            "snapshot chunk hash mismatch — max retries exceeded, aborting sync"
                        );
                        self.snapshot_chunks.clear();
                        self.snapshot_expected_root = None;
                        self.snapshot_total_chunks = 0;
                        self.snapshot_retry_count = 0;
                    } else {
                        warn!(
                            chunk = chunk_index,
                            retry = self.snapshot_retry_count,
                            "snapshot chunk hash mismatch — will retry"
                        );
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
                self.snapshot_chunks
                    .push((chunk_index, entries, chunk_hash));

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
                    let all_entries: Vec<(Vec<u8>, Vec<u8>)> = self
                        .snapshot_chunks
                        .drain(..)
                        .flat_map(|(_, entries, _)| entries)
                        .collect();

                    let root = self.snapshot_expected_root.take().unwrap_or([0u8; 32]);
                    let slot = self.snapshot_head_slot;

                    info!(
                        entries = all_entries.len(),
                        head_slot = slot,
                        "all chunks received — importing snapshot"
                    );

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
            SyncReq::GetChainTip => SyncResp::ChainTip {
                slot: chain.head_slot,
                block_hash: chain.state_root,
            },
            SyncReq::GetBlocks { start_slot, count } => {
                // Audit 337: clamp the peer-supplied count before
                // any iteration. Pre-fix, count was used directly
                // (`as u64`) so a peer passing u32::MAX iterated
                // ~4 billion slots, hammering RocksDB + chain
                // header lookups before returning. Cap at
                // MAX_GET_BLOCKS_COUNT = 256 — large enough for
                // healthy bulk sync, small enough that a malicious
                // request burns ≤ a few ms of server CPU.
                const MAX_GET_BLOCKS_COUNT: u32 = 256;
                let count = (*count).min(MAX_GET_BLOCKS_COUNT);
                let mut blocks = Vec::new();
                let end_slot = *start_slot + count as u64;
                let scan_end = end_slot.max(chain.head_slot + 1);
                for slot in *start_slot..scan_end {
                    if let Some(raw) = block_store.get_block_raw(slot) {
                        blocks.push(raw);
                    } else if let Some(header) = chain.header(slot) {
                        blocks.push(crate::wire::encode_block_header(header));
                    }
                    // Don't break on missing slots — blocks are sparse
                    if blocks.len() >= count as usize {
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
                // Audit 337: same clamp shape as GetBlocks above.
                // Pre-fix `*start_slot..(*start_slot + *count as
                // u64)` could iterate u32::MAX slots on a malformed
                // request.
                const MAX_GET_HEADERS_COUNT: u32 = 1024;
                let count = (*count).min(MAX_GET_HEADERS_COUNT);
                let mut headers = Vec::new();
                for slot in *start_slot..(*start_slot + count as u64) {
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
            SyncReq::GetStateSnapshotChunk {
                chunk_index,
                chunk_size,
            } => {
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

                // Audit 338: clamp peer-supplied chunk_size. Pre-fix
                // `(*chunk_size as usize).max(1)` accepted any u32
                // including u32::MAX, which sliced the entire
                // `snap.entries` Vec into one response (defeats
                // chunked transfer's whole purpose AND lets a
                // peer trigger a full snapshot allocation per
                // request). Cap at MAX_SNAPSHOT_CHUNK_SIZE = 50_000
                // entries — well above the SNAPSHOT_CHUNK_SIZE
                // operators actually use, but bounded.
                const MAX_SNAPSHOT_CHUNK_SIZE: usize = 50_000;
                let cs = (*chunk_size as usize).clamp(1, MAX_SNAPSHOT_CHUNK_SIZE);
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
        if self.snapshot_total_chunks == 0 {
            return None;
        }
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

    // ========== Audit 220: snapshot-sync threshold trigger ==========

    #[test]
    fn snapshot_sync_triggers_when_far_behind() {
        // Fresh node sees a peer at slot SNAPSHOT_THRESHOLD + 100 →
        // should_use_snapshot_sync = true. Block-by-block sync would
        // take ~SNAPSHOT_THRESHOLD requests, snapshot sync is one
        // chunked transfer.
        let mut sync = ChainSync::new();
        sync.on_peer_tip(PeerId::random(), ChainSync::SNAPSHOT_THRESHOLD + 100);
        assert!(
            sync.should_use_snapshot_sync(),
            "should switch to snapshot sync when slots_behind > threshold"
        );
    }

    #[test]
    fn snapshot_sync_skipped_when_close_enough() {
        // Same node but only behind by half the threshold — block-by-
        // block is fine.
        let mut sync = ChainSync::new();
        sync.on_peer_tip(PeerId::random(), ChainSync::SNAPSHOT_THRESHOLD / 2);
        assert!(
            !sync.should_use_snapshot_sync(),
            "no snapshot sync when slots_behind ≤ threshold"
        );
    }

    #[test]
    fn snapshot_sync_skipped_after_initial_sync_done() {
        // Once initial sync is done, even a far-behind situation
        // (e.g. operator restored from backup) doesn't re-trigger
        // snapshot sync — only fresh nodes use it. This guards
        // against bouncing into snapshot mode mid-operation.
        let mut sync = ChainSync::new();
        sync.on_peer_tip(PeerId::random(), 5);
        for slot in 1..=5 {
            sync.on_block_processed(slot);
        }
        assert!(sync.initial_sync_done);
        // Now suddenly see a peer way ahead.
        sync.on_peer_tip(PeerId::random(), ChainSync::SNAPSHOT_THRESHOLD + 1000);
        assert!(
            !sync.should_use_snapshot_sync(),
            "post-initial-sync nodes use block sync regardless of distance"
        );
    }

    #[test]
    fn snapshot_sync_skipped_when_already_in_progress() {
        // If a snapshot download is in progress, don't re-request.
        let mut sync = ChainSync::new();
        sync.on_peer_tip(PeerId::random(), ChainSync::SNAPSHOT_THRESHOLD + 100);
        sync.snapshot_expected_root = Some([0u8; 32]); // simulate in-flight
        assert!(
            !sync.should_use_snapshot_sync(),
            "no double-request while snapshot is in flight"
        );
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

    // ========== Audit 241: snapshot WS-anchor admission ==========

    #[test]
    fn snapshot_ws_anchor_no_checkpoint_accepts_anything() {
        // Bootstrap path: no checkpoint set, so nothing is rejected.
        assert!(ChainSync::check_snapshot_ws_anchor(0, &[0u8; 32], None).is_ok());
        assert!(ChainSync::check_snapshot_ws_anchor(1_000_000, &[0xAA; 32], None).is_ok());
    }

    #[test]
    fn snapshot_ws_anchor_rejects_pre_checkpoint_slot() {
        let cp = (500u64, [0xAA; 32]);
        // Long-range fork: snapshot's head is BEFORE the WS anchor —
        // applying it would regress past a finalized point.
        let err = ChainSync::check_snapshot_ws_anchor(499, &[0xBB; 32], Some(cp)).unwrap_err();
        assert!(err.contains("before WS checkpoint"));
        // Even with a state_root that happens to match, slot wins.
        let err = ChainSync::check_snapshot_ws_anchor(0, &[0xAA; 32], Some(cp)).unwrap_err();
        assert!(err.contains("before WS checkpoint"));
    }

    #[test]
    fn snapshot_ws_anchor_rejects_wrong_root_at_checkpoint_slot() {
        let cp = (500u64, [0xAA; 32]);
        // Same slot as the anchor but a divergent state_root: this is
        // the long-range fork delivered as a snapshot — reject.
        let err = ChainSync::check_snapshot_ws_anchor(500, &[0xBB; 32], Some(cp)).unwrap_err();
        assert!(err.contains("does not match"));
    }

    #[test]
    fn snapshot_ws_anchor_accepts_at_checkpoint_with_matching_root() {
        let cp = (500u64, [0xAA; 32]);
        assert!(ChainSync::check_snapshot_ws_anchor(500, &[0xAA; 32], Some(cp)).is_ok());
    }

    #[test]
    fn snapshot_ws_anchor_accepts_post_checkpoint() {
        let cp = (500u64, [0xAA; 32]);
        // Strictly past the anchor: any state_root passes the slot
        // guard — deeper root verification against canonical block at
        // head_slot is a follow-up (needs per-slot root tracking).
        assert!(ChainSync::check_snapshot_ws_anchor(501, &[0xBB; 32], Some(cp)).is_ok());
        assert!(ChainSync::check_snapshot_ws_anchor(10_000, &[0xCC; 32], Some(cp)).is_ok());
    }

    #[test]
    fn handle_chain_tip_request() {
        let mut chain = ChainState::genesis([0u8; 32], 1);
        chain.advance(dummy_header(10));
        let (state, _sd) = make_state();
        let (bs, _bd) = make_block_store();

        let resp = ChainSync::handle_inbound_request(
            &SyncReq::GetChainTip,
            &chain,
            &state,
            &bs,
            &mut None::<PinnedSnapshot>,
        );
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
            &SyncReq::GetBlocks {
                start_slot: 1,
                count: 3,
            },
            &chain,
            &state,
            &bs,
            &mut None::<PinnedSnapshot>,
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
            &SyncReq::GetBlocks {
                start_slot: 100,
                count: 10,
            },
            &chain,
            &state,
            &bs,
            &mut None::<PinnedSnapshot>,
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
            &chain,
            &state,
            &bs,
            &mut None::<PinnedSnapshot>,
        );
        match resp {
            SyncResp::StateSnapshot {
                state_root,
                head_slot,
                entries,
            } => {
                assert_eq!(head_slot, 5);
                assert_eq!(entries.len(), 1);
                assert_eq!(state_root, state.root());
            }
            _ => panic!("expected StateSnapshot"),
        }
    }
}
