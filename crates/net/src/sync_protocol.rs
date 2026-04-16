//! Sync request-response protocol over libp2p.
//!
//! Uses CBOR encoding over the `/pyde/sync/1` protocol.
//! Peers exchange block headers, block bodies, and chain tip info.

use libp2p::request_response;
use libp2p::StreamProtocol;
use serde::{Deserialize, Serialize};

/// Protocol name for sync requests.
pub const SYNC_PROTOCOL: StreamProtocol = StreamProtocol::new("/pyde/sync/1");

/// Sync request sent from syncing node to a peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncReq {
    /// Ask the peer for their chain tip (highest slot).
    GetChainTip,
    /// Request block data for a range of slots.
    GetBlocks {
        start_slot: u64,
        count: u32,
    },
    /// Request block headers only for a range of slots.
    GetHeaders {
        start_slot: u64,
        count: u32,
    },
    /// Request a full state snapshot at the peer's current state root.
    GetStateSnapshot,
    /// Request a single chunk of a state snapshot (for large states).
    GetStateSnapshotChunk {
        chunk_index: u32,
        chunk_size: u32,
    },
}

/// Sync response from peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncResp {
    /// Peer's chain tip.
    ChainTip {
        slot: u64,
        block_hash: [u8; 32],
    },
    /// Block data (serialized blocks).
    Blocks(Vec<Vec<u8>>),
    /// Block headers only.
    Headers(Vec<Vec<u8>>),
    /// Full state snapshot: Vec<(key_bytes, value_bytes)>.
    StateSnapshot {
        state_root: [u8; 32],
        head_slot: u64,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// A single chunk of a state snapshot.
    StateSnapshotChunk {
        state_root: [u8; 32],
        head_slot: u64,
        chunk_index: u32,
        total_chunks: u32,
        chunk_hash: [u8; 32],
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// Peer doesn't have the requested data.
    NotFound,
}

/// Create the request-response behaviour for sync.
pub fn sync_behaviour() -> request_response::cbor::Behaviour<SyncReq, SyncResp> {
    request_response::cbor::Behaviour::new(
        [(SYNC_PROTOCOL, request_response::ProtocolSupport::Full)],
        request_response::Config::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_req_serializes() {
        let req = SyncReq::GetBlocks { start_slot: 100, count: 50 };
        let bytes = serde_json::to_vec(&req).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn sync_resp_serializes() {
        let resp = SyncResp::ChainTip { slot: 42, block_hash: [0xAA; 32] };
        let bytes = serde_json::to_vec(&resp).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn not_found_serializes() {
        let resp = SyncResp::NotFound;
        let bytes = serde_json::to_vec(&resp).unwrap();
        assert!(!bytes.is_empty());
    }
}
