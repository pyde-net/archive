//! Chain sync: header-first sync over libp2p request-response.
//!
//! ## Current Limitations
//!
//! This is a header-only sync skeleton. A fully synced node currently has:
//! - Chain head tracking (slot, epoch, parent hashes)
//! - Block header history for finality verification
//!
//! What's NOT synced yet (requires block wire format + tx execution):
//! - Block bodies (transactions, execution schedules)
//! - State trie (account balances, storage, contract code)
//! - Transaction execution / state replay from genesis
//!
//! ## TODO: Full Sync
//!
//! 1. Block serialization format (header + body + signatures)
//! 2. Download full blocks (not just headers) during sync
//! 3. Execute transactions per block to rebuild state from genesis
//! 4. State snapshot sync (download trie at checkpoint, replay recent blocks)
//! 5. Parallel block download with sequential execution

use crate::block_processor::BlockProcessor;
use crate::chain::ChainState;
use crate::state_manager::StateManager;
use libp2p::request_response::{self, OutboundRequestId, ResponseChannel};
use libp2p::{PeerId, Swarm};
use pyde_net::node::PydeBehaviour;
use pyde_net::sync::SyncManager;
use pyde_net::sync_protocol::{SyncReq, SyncResp};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Chain sync coordinator.
/// Manages the sync state machine and dispatches requests to peers.
pub struct ChainSync {
    /// Sync state tracker from the net crate.
    pub manager: SyncManager,
    /// Outstanding outbound requests: request_id → peer.
    pending: HashMap<OutboundRequestId, PeerId>,
    /// Whether initial sync has completed at least once.
    pub initial_sync_done: bool,
}

impl ChainSync {
    pub fn new() -> Self {
        Self {
            manager: SyncManager::new(),
            pending: HashMap::new(),
            initial_sync_done: false,
        }
    }

    /// Called when we learn a peer's chain tip (from ChainTip response or identify).
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

    /// Handle a sync response from a peer.
    /// Returns the number of blocks processed.
    pub fn on_response(
        &mut self,
        request_id: OutboundRequestId,
        response: SyncResp,
        chain: &mut ChainState,
        state: &mut StateManager,
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
                    // Deserialize block header from the data.
                    // For now, we use a minimal format: slot(8) || parent_hash(32) || state_root(32) || tx_root(32)
                    // Full serialization will be expanded later.
                    if let Some(header) = deserialize_block_header(data) {
                        match BlockProcessor::process_block(chain, state, header, &[]) {
                            Ok(_) => {
                                self.manager.advance_local_tip(chain.head_slot);
                                processed += 1;
                            }
                            Err(e) => {
                                warn!(error = %e, "failed to process synced block");
                                break;
                            }
                        }
                    } else {
                        warn!(len = data.len(), "failed to deserialize synced block");
                        break;
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
            SyncResp::NotFound => {
                warn!("peer doesn't have requested blocks");
                0
            }
        }
    }

    /// Handle an inbound sync request from a peer.
    /// Returns the response to send back.
    pub fn handle_inbound_request(
        req: &SyncReq,
        chain: &ChainState,
    ) -> SyncResp {
        match req {
            SyncReq::GetChainTip => {
                SyncResp::ChainTip {
                    slot: chain.head_slot,
                    block_hash: chain.state_root, // simplified: use state_root as block identifier
                }
            }
            SyncReq::GetBlocks { start_slot, count } => {
                // Serialize block headers from our chain state.
                // We serve what we have in our header cache.
                let mut blocks = Vec::new();
                for slot in *start_slot..(*start_slot + *count as u64) {
                    if let Some(header) = chain.header(slot) {
                        blocks.push(serialize_block_header(header));
                    } else {
                        break; // stop at first missing slot
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
                        headers.push(serialize_block_header(header));
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
        }
    }

    /// Whether sync is in progress.
    pub fn is_syncing(&self) -> bool {
        self.manager.needs_sync()
    }
}

/// Minimal block header serialization.
/// Format: slot(8) || epoch(8) || parent_hash(32) || state_root(32) || tx_root(32) || timestamp(8)
fn serialize_block_header(header: &pyde_consensus::block::BlockHeader) -> Vec<u8> {
    let mut buf = Vec::with_capacity(120);
    buf.extend_from_slice(&header.slot.to_le_bytes());
    buf.extend_from_slice(&header.epoch.to_le_bytes());
    buf.extend_from_slice(&header.parent_hash);
    buf.extend_from_slice(&header.state_root);
    buf.extend_from_slice(&header.tx_root);
    buf.extend_from_slice(&header.timestamp.to_le_bytes());
    buf
}

/// Minimal block header deserialization.
fn deserialize_block_header(data: &[u8]) -> Option<pyde_consensus::block::BlockHeader> {
    if data.len() < 120 {
        return None;
    }

    let mut slot_bytes = [0u8; 8];
    slot_bytes.copy_from_slice(&data[0..8]);
    let slot = u64::from_le_bytes(slot_bytes);

    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&data[8..16]);
    let epoch = u64::from_le_bytes(epoch_bytes);

    let mut parent_hash = [0u8; 32];
    parent_hash.copy_from_slice(&data[16..48]);

    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(&data[48..80]);

    let mut tx_root = [0u8; 32];
    tx_root.copy_from_slice(&data[80..112]);

    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&data[112..120]);
    let timestamp = u64::from_le_bytes(ts_bytes);

    Some(pyde_consensus::block::BlockHeader {
        slot,
        epoch,
        parent_hash,
        state_root,
        tx_root,
        timestamp,
        proposer: pyde_account::address::ZERO_ADDRESS,
        vrf_proof: vec![],
        qc_previous: pyde_consensus::block::QuorumCert::empty(),
    })
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
    fn header_serialization_roundtrip() {
        let header = dummy_header(42);
        let bytes = serialize_block_header(&header);
        let restored = deserialize_block_header(&bytes).unwrap();

        assert_eq!(restored.slot, 42);
        assert_eq!(restored.epoch, 0);
        assert_eq!(restored.state_root, [42u8; 32]);
        assert_eq!(restored.tx_root, [42u8; 32]);
        assert_eq!(restored.timestamp, 42 * 400);
    }

    #[test]
    fn deserialize_too_short_returns_none() {
        assert!(deserialize_block_header(&[0u8; 50]).is_none());
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

    #[test]
    fn handle_chain_tip_request() {
        let mut chain = ChainState::genesis([0u8; 32]);
        chain.advance(dummy_header(10));

        let resp = ChainSync::handle_inbound_request(&SyncReq::GetChainTip, &chain);
        match resp {
            SyncResp::ChainTip { slot, .. } => assert_eq!(slot, 10),
            _ => panic!("expected ChainTip response"),
        }
    }

    #[test]
    fn handle_get_blocks_request() {
        let mut chain = ChainState::genesis([0u8; 32]);
        for slot in 1..=5 {
            chain.advance(dummy_header(slot));
        }

        let resp = ChainSync::handle_inbound_request(
            &SyncReq::GetBlocks { start_slot: 1, count: 3 },
            &chain,
        );
        match resp {
            SyncResp::Blocks(blocks) => {
                assert_eq!(blocks.len(), 3);
                // Verify first block deserializes to slot 1
                let h = deserialize_block_header(&blocks[0]).unwrap();
                assert_eq!(h.slot, 1);
            }
            _ => panic!("expected Blocks response"),
        }
    }

    #[test]
    fn handle_get_blocks_not_found() {
        let chain = ChainState::genesis([0u8; 32]);

        let resp = ChainSync::handle_inbound_request(
            &SyncReq::GetBlocks { start_slot: 100, count: 10 },
            &chain,
        );
        match resp {
            SyncResp::NotFound => {}
            _ => panic!("expected NotFound"),
        }
    }
}
