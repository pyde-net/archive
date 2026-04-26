//! Direct request-response delivery for consensus messages.
//!
//! Audit 234 part 3: gossipsub publish for the consensus topic
//! returns `InsufficientPeers` after restart cycles because peer
//! subscription state (gossipsub `topic_peers`) doesn't reliably
//! re-sync on reconnect — the libp2p `on_connection_established`
//! handler only re-broadcasts SUBSCRIBE on the FIRST connection
//! to a peer (`other_established == 0` guard), and there's no
//! reciprocal SUBSCRIBE send when one side receives a SUBSCRIBE.
//! The result: view-change messages silently drop, the chain
//! stalls when the assigned proposer is offline.
//!
//! View-change is liveness-critical and must not depend on
//! best-effort gossip. This protocol delivers consensus messages
//! point-to-point over libp2p request-response, which has
//! deterministic delivery semantics — the message either reaches
//! the peer or returns an explicit error to the caller. The
//! existing gossipsub path stays primary; this RR path is only
//! used as a fallback when gossipsub fails.

use libp2p::request_response;
use libp2p::StreamProtocol;
use serde::{Deserialize, Serialize};

/// Protocol name for direct consensus message delivery.
pub const CONSENSUS_PROTOCOL: StreamProtocol = StreamProtocol::new("/pyde/consensus/1");

/// Request: a wire-encoded `pyde_consensus::hotstuff::ConsensusMessage`.
/// The receiver decodes and routes through the same handler as
/// the gossipsub path, so callers don't need to special-case
/// fallback receipts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusReq {
    /// Wire-encoded ConsensusMessage (same encoding used on the
    /// gossipsub consensus topic).
    pub bytes: Vec<u8>,
}

/// Response: best-effort ack. A successful `Ack` only confirms
/// receipt — the receiver may still drop the message at
/// validation time (e.g., wrong slot, unknown signer).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConsensusResp {
    Ack,
    /// Receiver couldn't decode the request bytes as a
    /// ConsensusMessage. Caller can drop the response without
    /// retrying — the message itself was malformed.
    DecodeError,
}

/// Create the request-response behaviour for consensus messages.
pub fn consensus_behaviour() -> request_response::cbor::Behaviour<ConsensusReq, ConsensusResp> {
    request_response::cbor::Behaviour::new(
        [(CONSENSUS_PROTOCOL, request_response::ProtocolSupport::Full)],
        request_response::Config::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_roundtrip() {
        let req = ConsensusReq {
            bytes: vec![1, 2, 3, 4, 5],
        };
        let ser = serde_json::to_vec(&req).unwrap();
        let de: ConsensusReq = serde_json::from_slice(&ser).unwrap();
        assert_eq!(de.bytes, req.bytes);
    }

    #[test]
    fn resp_roundtrip() {
        let r = ConsensusResp::Ack;
        let ser = serde_json::to_vec(&r).unwrap();
        let de: ConsensusResp = serde_json::from_slice(&ser).unwrap();
        assert!(matches!(de, ConsensusResp::Ack));
    }
}
