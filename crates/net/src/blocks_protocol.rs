//! Direct request-response delivery for Blocks-topic messages.
//!
//! Audit 234 part 4 (follow-up to consensus_protocol.rs): the same
//! gossipsub mesh degradation that drops consensus messages after
//! restart cycles also drops Blocks-topic broadcasts. The proposer's
//! compact block + encrypted-tx bundle silently disappear into a
//! gossipsub mesh whose `topic_peers[blocks]` is empty —
//! `gossipsub.publish` returns Ok with no recipients, votes never
//! form a QC against an unseen block, and the chain stalls.
//!
//! This protocol mirrors `consensus_protocol.rs`: opaque
//! wire-encoded payload, receiver dispatches by the existing tag
//! byte (`wire::tag::COMPACT_BLOCK`, `wire::tag::ENCRYPTED_TX_BUNDLE`,
//! or full-block fallback) through the SAME handlers as the gossipsub
//! receive arm. The deterministic delivery semantics of
//! request-response — message reaches the peer or returns an explicit
//! error — close the silent-drop window for liveness-critical block
//! propagation, just as consensus_protocol does for the consensus
//! topic.

use libp2p::request_response;
use libp2p::StreamProtocol;
use serde::{Deserialize, Serialize};

/// Protocol name for direct block delivery.
pub const BLOCKS_PROTOCOL: StreamProtocol = StreamProtocol::new("/pyde/blocks/1");

/// Request: a wire-encoded block-channel payload (compact block,
/// encrypted-tx bundle, or full block fallback). Receiver decodes by
/// the first byte's tag and routes through the same handlers as the
/// gossipsub Blocks-topic receive arm.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlocksReq {
    /// Wire-encoded block-channel payload (same encoding used on the
    /// gossipsub Blocks topic).
    pub bytes: Vec<u8>,
}

/// Response: best-effort ack. A successful `Ack` only confirms
/// receipt — the receiver may still drop the payload at validation
/// time (e.g., bad signature, wrong slot, malformed body).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BlocksResp {
    Ack,
    /// Receiver couldn't decode the request bytes. Caller can drop
    /// the response without retrying — the payload itself was
    /// malformed.
    DecodeError,
}

/// Create the request-response behaviour for direct block delivery.
///
/// `request_timeout` is operator-configurable via
/// `NetworkConfig::request_timeout`. The legacy default of 1500ms
/// (audit 234 part 4 step 7) is tuned for fast OutboundFailure under
/// post-restart stale-connection conditions on same-region clusters;
/// cross-region operators should scale this up (typically
/// `slot_duration_ms * 3`).
pub fn blocks_behaviour(
    request_timeout: std::time::Duration,
) -> request_response::cbor::Behaviour<BlocksReq, BlocksResp> {
    let cfg = request_response::Config::default().with_request_timeout(request_timeout);
    request_response::cbor::Behaviour::new(
        [(BLOCKS_PROTOCOL, request_response::ProtocolSupport::Full)],
        cfg,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_roundtrip() {
        let req = BlocksReq {
            bytes: vec![0xCB, 1, 2, 3, 4, 5],
        };
        let ser = serde_json::to_vec(&req).unwrap();
        let de: BlocksReq = serde_json::from_slice(&ser).unwrap();
        assert_eq!(de.bytes, req.bytes);
    }

    #[test]
    fn resp_roundtrip() {
        let r = BlocksResp::Ack;
        let ser = serde_json::to_vec(&r).unwrap();
        let de: BlocksResp = serde_json::from_slice(&ser).unwrap();
        assert!(matches!(de, BlocksResp::Ack));
    }
}
