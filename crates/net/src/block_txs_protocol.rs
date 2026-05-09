//! Direct request-response delivery for missing-tx fetch.
//!
//! When a non-proposer receives a CompactBlock and can't fully
//! reconstruct the body because some short_ids don't match its
//! local plaintext mempool / encrypted-tx relay, this protocol
//! fetches just the missing tx bodies from a peer instead of
//! falling back to whole-block sync. The pre-fix code path bumped
//! `network_tip` to the unfinalized slot and fired `GetBlocks` —
//! peers responded `NotFound` (the slot has no QC yet, so it isn't
//! in `block_store`), and the tight retry loop starved the
//! consensus message handler. That was the audit-396 failure mode
//! at a sibling code site (`node.rs::ReconstructCompactBlock`
//! missing-txs branch).
//!
//! Design notes:
//! - `nonce` is part of the request so any peer with the txs can
//!   recompute the short IDs over its own mempool — the responder
//!   does NOT need to have buffered the compact block itself.
//!   Without this, the only useful responder would be a peer who
//!   has already received and parsed the same compact block, which
//!   defeats the point on a degraded mesh.
//! - `block_hash` is included for context: rate-limiting,
//!   per-block deduplication on the responder side, and operator
//!   logs. It does not gate the response.
//! - The response uses `Option<Vec<u8>>` per slot so the requester
//!   can distinguish "peer doesn't have this short id" from "tx
//!   bytes are zero-length" (which would otherwise alias).

use libp2p::request_response;
use libp2p::StreamProtocol;
use serde::{Deserialize, Serialize};

use crate::propagation::ShortId;

/// Protocol name. Versioned so a future schema change can ship
/// alongside the old one during migration.
pub const BLOCK_TXS_PROTOCOL: StreamProtocol = StreamProtocol::new("/pyde/block-txs/1");

/// Request: the missing short IDs from a known compact block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockTxsReq {
    /// Compact block hash. Echoed in the response so the caller can
    /// match a response to the right pending reconstruction; also
    /// used by the responder for logging and per-block rate limits.
    pub block_hash: [u8; 32],
    /// Compact block short-ID nonce. Lets any peer with the txs
    /// recompute matching short IDs from its local mempool view —
    /// without this, only peers that already buffered the compact
    /// block could answer.
    pub nonce: u64,
    /// Short IDs the requester is missing. Order is preserved in
    /// the response.
    pub short_ids: Vec<ShortId>,
}

/// Response: tx bytes for each requested short ID, in order. `None`
/// at index `i` means the responder didn't have a tx whose
/// short ID matches `req.short_ids[i]` under `req.nonce`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockTxsResp {
    pub block_hash: [u8; 32],
    pub txs: Vec<Option<Vec<u8>>>,
}

/// Request-response behaviour for fine-grained missing-tx fetch.
///
/// Same 1500ms timeout pattern as `blocks_protocol` — we want fast
/// `OutboundFailure` so the caller can move on to a different peer
/// rather than holding the slot open while a stale connection
/// times out.
pub fn block_txs_behaviour() -> request_response::cbor::Behaviour<BlockTxsReq, BlockTxsResp> {
    let cfg = request_response::Config::default()
        .with_request_timeout(std::time::Duration::from_millis(1500));
    request_response::cbor::Behaviour::new(
        [(BLOCK_TXS_PROTOCOL, request_response::ProtocolSupport::Full)],
        cfg,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_roundtrip() {
        let req = BlockTxsReq {
            block_hash: [0xAA; 32],
            nonce: 0xdead_beef_cafe_babe,
            short_ids: vec![[0x01; 8], [0x02; 8], [0x03; 8]],
        };
        let ser = serde_json::to_vec(&req).unwrap();
        let de: BlockTxsReq = serde_json::from_slice(&ser).unwrap();
        assert_eq!(de.block_hash, req.block_hash);
        assert_eq!(de.nonce, req.nonce);
        assert_eq!(de.short_ids, req.short_ids);
    }

    #[test]
    fn resp_roundtrip_with_holes() {
        let resp = BlockTxsResp {
            block_hash: [0xBB; 32],
            txs: vec![Some(vec![1, 2, 3]), None, Some(vec![4, 5])],
        };
        let ser = serde_json::to_vec(&resp).unwrap();
        let de: BlockTxsResp = serde_json::from_slice(&ser).unwrap();
        assert_eq!(de.block_hash, resp.block_hash);
        assert_eq!(de.txs.len(), 3);
        assert_eq!(de.txs[0], Some(vec![1, 2, 3]));
        assert_eq!(de.txs[1], None);
        assert_eq!(de.txs[2], Some(vec![4, 5]));
    }
}
