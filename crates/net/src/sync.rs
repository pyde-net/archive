//! Sync protocol: state sync, chain sync, witness delivery.
//!
//! Pull-based request/response protocol per Chapter 12:
//! - Chain sync: header-first, download blocks in ranges
//! - State sync: snapshot download + Merkle verification
//! - Witness sync: deliver state witnesses for verification
//! - Epoch data: validator set transitions

/// Sync request types (node → peer).
#[derive(Clone, Debug)]
pub enum SyncRequest {
    /// Request block headers in a range.
    GetHeaders { start_slot: u64, count: u32 },
    /// Request full blocks in a range.
    GetBlocks { start_slot: u64, count: u32 },
    /// Request state witnesses for a block.
    GetStateWitnesses { block_hash: [u8; 32] },
    /// Request a chunk of the state trie for snapshot sync.
    GetStateChunk {
        state_root: [u8; 32],
        path_prefix: Vec<u8>,
    },
    /// Request the validator set for an epoch.
    GetEpochData { epoch: u64 },
    /// Request proof of a historical state entry.
    GetHistoricalProof { slot: u64, key: [u8; 32] },
}

/// Sync response types (peer → node).
#[derive(Clone, Debug)]
pub enum SyncResponse {
    /// Block headers.
    Headers(Vec<Vec<u8>>),
    /// Full block bodies.
    Blocks(Vec<Vec<u8>>),
    /// State witnesses: (key, value, merkle_path) per storage slot.
    StateWitnesses(Vec<SlotWitness>),
    /// A chunk of the state trie.
    StateChunk {
        path_prefix: Vec<u8>,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// Epoch data (serialized validator set, committee).
    EpochData(Vec<u8>),
    /// Historical Merkle proof.
    HistoricalProof {
        key: [u8; 32],
        value: Vec<u8>,
        proof: Vec<Vec<u8>>,
    },
    /// Request not fulfilled (peer doesn't have the data).
    NotFound,
    /// Rate limited (too many requests).
    RateLimited,
}

/// A state witness for a single storage slot.
#[derive(Clone, Debug)]
pub struct SlotWitness {
    /// Storage key.
    pub key: [u8; 32],
    /// Storage value.
    pub value: Vec<u8>,
    /// Merkle proof path from the key to the state root.
    pub proof: Vec<Vec<u8>>,
}

/// Sync state for a node catching up to chain tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncState {
    /// Fully synced with the chain tip.
    Synced,
    /// Downloading headers.
    SyncingHeaders { current: u64, target: u64 },
    /// Downloading block bodies.
    SyncingBlocks { current: u64, target: u64 },
    /// Downloading state snapshot.
    SyncingState {
        chunks_received: u32,
        chunks_total: u32,
    },
}

impl SyncState {
    /// Progress as a percentage (0-100).
    pub fn progress_percent(&self) -> u32 {
        match self {
            SyncState::Synced => 100,
            SyncState::SyncingHeaders { current, target } => {
                if *target == 0 {
                    100
                } else {
                    (current * 100 / target) as u32
                }
            }
            SyncState::SyncingBlocks { current, target } => {
                if *target == 0 {
                    100
                } else {
                    (current * 100 / target) as u32
                }
            }
            SyncState::SyncingState {
                chunks_received,
                chunks_total,
            } => {
                if *chunks_total == 0 {
                    100
                } else {
                    chunks_received * 100 / chunks_total
                }
            }
        }
    }
}

/// Sync manager: tracks sync progress and manages requests.
#[derive(Debug)]
pub struct SyncManager {
    /// Current sync state.
    pub state: SyncState,
    /// Our highest known slot.
    pub local_tip: u64,
    /// The network's highest known slot.
    pub network_tip: u64,
    /// Maximum blocks to request per batch.
    pub batch_size: u32,
    /// Pending requests (request_id → SyncRequest).
    pending_requests: Vec<(u64, SyncRequest)>,
    /// Next request ID.
    next_request_id: u64,
}

impl SyncManager {
    pub fn new() -> Self {
        Self {
            state: SyncState::Synced,
            local_tip: 0,
            network_tip: 0,
            batch_size: 100,
            pending_requests: Vec::new(),
            next_request_id: 0,
        }
    }

    /// Update the network tip (from peer announcements).
    pub fn update_network_tip(&mut self, tip: u64) {
        if tip > self.network_tip {
            self.network_tip = tip;
        }
    }

    /// Update the local tip (after processing a block).
    pub fn advance_local_tip(&mut self, slot: u64) {
        if slot > self.local_tip {
            self.local_tip = slot;
        }
        if self.local_tip >= self.network_tip {
            self.state = SyncState::Synced;
        }
    }

    /// Check if we need to sync.
    pub fn needs_sync(&self) -> bool {
        self.local_tip < self.network_tip
    }

    /// How many slots behind we are.
    pub fn slots_behind(&self) -> u64 {
        self.network_tip.saturating_sub(self.local_tip)
    }

    /// Generate the next sync request (if needed).
    pub fn next_request(&mut self) -> Option<SyncRequest> {
        if !self.needs_sync() {
            return None;
        }

        let start = self.local_tip + 1;
        let count = self.batch_size.min(self.slots_behind() as u32);

        self.state = SyncState::SyncingBlocks {
            current: self.local_tip,
            target: self.network_tip,
        };

        let req = SyncRequest::GetBlocks {
            start_slot: start,
            count,
        };

        let id = self.next_request_id;
        self.next_request_id += 1;
        self.pending_requests.push((id, req.clone()));

        Some(req)
    }

    /// Number of pending requests.
    pub fn pending_count(&self) -> usize {
        self.pending_requests.len()
    }

    /// Clear a pending request (after receiving response).
    pub fn complete_request(&mut self, request_id: u64) {
        self.pending_requests.retain(|(id, _)| *id != request_id);
    }
}

impl Default for SyncManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Task 0579: New node syncs chain ==========

    #[test]
    fn new_node_needs_sync() {
        let mut mgr = SyncManager::new();
        mgr.update_network_tip(1000);
        assert!(mgr.needs_sync());
        assert_eq!(mgr.slots_behind(), 1000);
    }

    #[test]
    fn synced_node_no_sync() {
        let mut mgr = SyncManager::new();
        mgr.local_tip = 1000;
        mgr.network_tip = 1000;
        assert!(!mgr.needs_sync());
        assert_eq!(mgr.state, SyncState::Synced);
    }

    #[test]
    fn next_request_generates_block_request() {
        let mut mgr = SyncManager::new();
        mgr.update_network_tip(500);

        let req = mgr.next_request().unwrap();
        match req {
            SyncRequest::GetBlocks { start_slot, count } => {
                assert_eq!(start_slot, 1);
                assert_eq!(count, 100); // batch_size
            }
            _ => panic!("expected GetBlocks"),
        }
        assert_eq!(mgr.pending_count(), 1);
    }

    #[test]
    fn advance_tip_completes_sync() {
        let mut mgr = SyncManager::new();
        mgr.update_network_tip(100);

        assert!(mgr.needs_sync());

        // Simulate receiving all blocks
        mgr.advance_local_tip(100);
        assert!(!mgr.needs_sync());
        assert_eq!(mgr.state, SyncState::Synced);
    }

    #[test]
    fn batch_size_capped_by_slots_behind() {
        let mut mgr = SyncManager::new();
        mgr.update_network_tip(10); // only 10 slots behind

        let req = mgr.next_request().unwrap();
        match req {
            SyncRequest::GetBlocks { count, .. } => {
                assert_eq!(count, 10); // capped to slots_behind
            }
            _ => panic!("expected GetBlocks"),
        }
    }

    // ========== Task 0580: Sync from snapshot ==========

    #[test]
    fn state_sync_progress() {
        let state = SyncState::SyncingState {
            chunks_received: 50,
            chunks_total: 100,
        };
        assert_eq!(state.progress_percent(), 50);
    }

    #[test]
    fn header_sync_progress() {
        let state = SyncState::SyncingHeaders {
            current: 750,
            target: 1000,
        };
        assert_eq!(state.progress_percent(), 75);
    }

    // ========== Request management ==========

    #[test]
    fn complete_request_removes_pending() {
        let mut mgr = SyncManager::new();
        mgr.update_network_tip(500);

        mgr.next_request();
        assert_eq!(mgr.pending_count(), 1);

        mgr.complete_request(0);
        assert_eq!(mgr.pending_count(), 0);
    }

    // ========== Witness request ==========

    #[test]
    fn witness_request_construction() {
        let req = SyncRequest::GetStateWitnesses {
            block_hash: [0xAA; 32],
        };
        match req {
            SyncRequest::GetStateWitnesses { block_hash } => {
                assert_eq!(block_hash, [0xAA; 32]);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ========== Slot witness ==========

    #[test]
    fn slot_witness_construction() {
        let witness = SlotWitness {
            key: [0x01; 32],
            value: vec![0xAA; 64],
            proof: vec![vec![0xBB; 32], vec![0xCC; 32]],
        };
        assert_eq!(witness.key, [0x01; 32]);
        assert_eq!(witness.proof.len(), 2);
    }
}
