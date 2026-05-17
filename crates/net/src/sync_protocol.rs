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
    GetBlocks { start_slot: u64, count: u32 },
    /// Request block headers only for a range of slots.
    GetHeaders { start_slot: u64, count: u32 },
    /// Request a full state snapshot at the peer's current state root.
    GetStateSnapshot,
    /// Request a single chunk of a state snapshot (for large states).
    GetStateSnapshotChunk { chunk_index: u32, chunk_size: u32 },
    /// Task #94: request a single block by its block_hash. Used by
    /// the QC-apply body-unavailable recovery path: we have the QC
    /// (so we know the canonical block_hash) but no body — slot-
    /// based GetBlocks is useless here because every peer at the
    /// same head reports "I'm at slot N too" without distinguishing
    /// who actually has the body. The proposer always does, and
    /// will respond. Other peers respond with `BlockByHash(None)`.
    GetBlockByHash([u8; 32]),
}

/// Sync response from peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncResp {
    /// Peer's chain tip.
    ChainTip { slot: u64, block_hash: [u8; 32] },
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
    /// Task #94: response to `GetBlockByHash`. `Some(bytes)` is the
    /// wire-encoded full block (header + body + proposer_signature)
    /// keyed by the requested block_hash; `None` means the peer
    /// doesn't have it. Distinct from top-level `NotFound` so the
    /// caller can tell "peer doesn't have THIS block" (try another
    /// peer) from "peer didn't understand the request" (protocol
    /// error).
    BlockByHash(Option<Vec<u8>>),
    /// Peer doesn't have the requested data.
    NotFound,
}

/// Create the request-response behaviour for sync.
///
/// `request_timeout` is operator-configurable via
/// `NetworkConfig::sync_request_timeout`. Sync carries heavier
/// payloads than the consensus/blocks/block_txs RR protocols
/// (block batches with full tx bodies), so it gets its own
/// configurable budget separate from the small-message
/// `NetworkConfig::request_timeout`. Default 10s matches libp2p's
/// pre-refactor implicit default; cross-region operators typically
/// scale this to `block_time_ms * 10`.
pub fn sync_behaviour(
    request_timeout: std::time::Duration,
) -> request_response::cbor::Behaviour<SyncReq, SyncResp> {
    let cfg = request_response::Config::default().with_request_timeout(request_timeout);
    request_response::cbor::Behaviour::new(
        [(SYNC_PROTOCOL, request_response::ProtocolSupport::Full)],
        cfg,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_req_serializes() {
        let req = SyncReq::GetBlocks {
            start_slot: 100,
            count: 50,
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn sync_resp_serializes() {
        let resp = SyncResp::ChainTip {
            slot: 42,
            block_hash: [0xAA; 32],
        };
        let bytes = serde_json::to_vec(&resp).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn not_found_serializes() {
        let resp = SyncResp::NotFound;
        let bytes = serde_json::to_vec(&resp).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn get_block_by_hash_roundtrip() {
        // Task #94: GetBlockByHash carries a 32-byte hash and the
        // response is `Option<Vec<u8>>` so receivers can distinguish
        // "I don't have this block" from "I don't understand this
        // request". Cover both cases.
        let req = SyncReq::GetBlockByHash([0xAB; 32]);
        let req_bytes = serde_json::to_vec(&req).unwrap();
        let req_back: SyncReq = serde_json::from_slice(&req_bytes).unwrap();
        match req_back {
            SyncReq::GetBlockByHash(h) => assert_eq!(h, [0xAB; 32]),
            _ => panic!("wrong variant after roundtrip"),
        }

        let resp_some = SyncResp::BlockByHash(Some(b"block-bytes".to_vec()));
        let bytes = serde_json::to_vec(&resp_some).unwrap();
        let back: SyncResp = serde_json::from_slice(&bytes).unwrap();
        match back {
            SyncResp::BlockByHash(Some(b)) => assert_eq!(b, b"block-bytes"),
            other => panic!("wrong variant: {:?}", other),
        }

        let resp_none = SyncResp::BlockByHash(None);
        let bytes = serde_json::to_vec(&resp_none).unwrap();
        let back: SyncResp = serde_json::from_slice(&bytes).unwrap();
        match back {
            SyncResp::BlockByHash(None) => {}
            other => panic!("wrong variant: {:?}", other),
        }
    }
}
