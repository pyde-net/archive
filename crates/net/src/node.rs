//! Pyde P2P node: libp2p swarm with QUIC transport.
//!
//! Transport uses Ed25519 identity (libp2p requirement). All consensus-critical
//! operations are FALCON-512 signed at the application layer — the Ed25519
//! identity has no authority over consensus, blocks, or transactions.

use crate::auth::{self, PydeAuthReq, PydeAuthResp};
use crate::blocks_protocol::{self, BlocksReq, BlocksResp};
use crate::config::NetworkConfig;
use crate::consensus_protocol::{self, ConsensusReq, ConsensusResp};
use crate::sync_protocol::{self, SyncReq, SyncResp};
use libp2p::{
    gossipsub, identify, identity,
    kad::{self, store::MemoryStore},
    request_response,
    swarm::NetworkBehaviour,
    Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use std::time::Duration;

/// The combined network behaviour for Pyde nodes.
#[derive(NetworkBehaviour)]
pub struct PydeBehaviour {
    /// Gossipsub for message propagation (4 channels).
    pub gossipsub: gossipsub::Behaviour,
    /// Kademlia DHT for peer discovery.
    pub kademlia: kad::Behaviour<MemoryStore>,
    /// Identify protocol (exchange peer info on connect).
    pub identify: identify::Behaviour,
    /// Request-response for sync protocol (block download, chain tip queries).
    pub sync: request_response::cbor::Behaviour<SyncReq, SyncResp>,
    /// Request-response for FALCON peer attestation (tasks 029/030).
    pub auth: request_response::cbor::Behaviour<PydeAuthReq, PydeAuthResp>,
    /// Request-response for direct consensus message delivery — used as
    /// a fallback when gossipsub publish fails (audit 234 part 3).
    pub consensus_rr: request_response::cbor::Behaviour<ConsensusReq, ConsensusResp>,
    /// Request-response for direct Blocks-topic delivery — same
    /// silent-drop failure mode as consensus_rr (audit 234 part 4
    /// follow-up).
    pub blocks_rr: request_response::cbor::Behaviour<BlocksReq, BlocksResp>,
}

/// Generate a new node keypair. Call once on first run, then persist.
pub fn generate_keypair() -> identity::Keypair {
    identity::Keypair::generate_ed25519()
}

/// Serialize a keypair to bytes for disk persistence.
pub fn keypair_to_bytes(keypair: &identity::Keypair) -> Result<Vec<u8>, String> {
    keypair
        .to_protobuf_encoding()
        .map_err(|e| format!("keypair serialize error: {e}"))
}

/// Deserialize a keypair from bytes (loaded from disk).
pub fn keypair_from_bytes(bytes: &[u8]) -> Result<identity::Keypair, String> {
    identity::Keypair::from_protobuf_encoding(bytes)
        .map_err(|e| format!("keypair deserialize error: {e}"))
}

/// Create a new Pyde P2P node with an existing keypair.
///
/// The keypair should be loaded from disk for identity persistence.
/// Use `generate_keypair()` on first run, persist with `keypair_to_bytes()`,
/// and reload with `keypair_from_bytes()` on subsequent runs.
///
/// Returns the Swarm and the local PeerId.
pub fn create_node(
    config: &NetworkConfig,
    local_key: identity::Keypair,
) -> Result<(Swarm<PydeBehaviour>, PeerId), String> {
    let local_peer_id = PeerId::from(local_key.public());

    // Build swarm
    //
    // Audit 234 part 4 step 7r: hybrid TCP + QUIC transport, Lighthouse
    // pattern. TCP is the primary stack — explicit FIN/RST gives
    // RTT-grade dead-peer detection on validator restart, important
    // for churn recovery. QUIC is composed alongside via libp2p's
    // builder so peers that prefer it (lower-latency 0-RTT handshake,
    // multiplexing without HOL blocking) can negotiate it on the
    // multiaddr. Bootstrap addresses default to TCP — operators can
    // override with `/udp/PORT/quic-v1` multiaddrs to opt into QUIC
    // for same-client peer pairs. Ethereum consensus clients
    // (Lighthouse, Prysm) ship the same hybrid; ethlambda picked QUIC
    // primary but their devnet hasn't been stress-tested under the
    // SIGKILL-style churn pattern that surfaces QUIC's connection-
    // state lag.
    let swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default().nodelay(true),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|e| format!("tcp transport error: {e}"))?
        .with_quic()
        .with_behaviour(|key| {
            // Gossipsub
            // Gossipsub config tuned for throughput under sustained
            // loadgen (task 074: 5K TPS × 10 min). Key knobs:
            //
            // - `ValidationMode::Permissive`: auto-accept+forward. In
            //   Strict mode the application must call
            //   `report_message_validation_result` for every inbound
            //   message before it's re-gossiped to the rest of the
            //   mesh. We don't call it, so Strict was effectively
            //   disabling multi-hop propagation — each tx only reached
            //   the direct peers of the first publisher, leaving other
            //   proposers' mempools starved.
            // - `mesh_n{,_low,_high}` pushed up so small committees
            //   (4–8 validators) keep a full mesh instead of falling
            //   back to lazy-gossip between churn events.
            // - Heartbeat stays at the slot time so mesh stabilizes
            //   once per slot.
            // - Larger `max_transmit_size` for our compact-block relays.
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_millis(400))
                .validation_mode(gossipsub::ValidationMode::Permissive)
                .max_transmit_size(1024 * 1024) // 1 MB max message
                .mesh_n(8)
                .mesh_n_low(4)
                .mesh_n_high(12)
                .mesh_outbound_min(2)
                .gossip_lazy(8)
                .history_length(6)
                .history_gossip(3)
                .duplicate_cache_time(Duration::from_secs(60))
                .flood_publish(true)
                // Audit 234 part 4 step 7p: match ethlambda's
                // `allow_self_origin = true`. Proposer's own block
                // is delivered back to its own gossipsub handler,
                // giving a uniform "block arrived from gossip" code
                // path on both proposer and peers.
                .allow_self_origin(true)
                .build()
                .map_err(|e| format!("gossipsub config error: {e}"))?;

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .map_err(|e| format!("gossipsub error: {e}"))?;

            // Kademlia
            let kademlia = kad::Behaviour::new(
                PeerId::from(key.public()),
                MemoryStore::new(PeerId::from(key.public())),
            );

            // Identify
            let identify = identify::Behaviour::new(identify::Config::new(
                "/pyde/1.0.0".to_string(),
                key.public(),
            ));

            // Sync request-response protocol
            let sync = sync_protocol::sync_behaviour();

            // FALCON peer-attestation protocol (tasks 029/030).
            let auth = auth::auth_behaviour();

            // Direct consensus message delivery (audit 234 part 3).
            let consensus_rr = consensus_protocol::consensus_behaviour();

            // Direct Blocks-topic delivery (audit 234 part 4 follow-up).
            let blocks_rr = blocks_protocol::blocks_behaviour();

            Ok(PydeBehaviour {
                gossipsub,
                kademlia,
                identify,
                sync,
                auth,
                consensus_rr,
                blocks_rr,
            })
        })
        .map_err(|e| format!("behaviour error: {e}"))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(config.idle_timeout))
        .build();

    Ok((swarm, local_peer_id))
}

/// The 4 gossipsub topic names for Pyde's message channels.
pub mod topics {
    use libp2p::gossipsub::IdentTopic;

    /// Consensus messages (votes, view changes) — validators only.
    pub fn consensus() -> IdentTopic {
        IdentTopic::new("pyde/consensus/1")
    }

    /// Plaintext transactions from users.
    pub fn transactions() -> IdentTopic {
        IdentTopic::new("pyde/transactions/1")
    }

    /// Threshold-encrypted (MEV-protected) transactions. Separate
    /// from plaintext transactions so the receive dispatcher can
    /// decode the right wire format without probing. Audit item
    /// 227 step 4 / option E.
    pub fn encrypted_transactions() -> IdentTopic {
        IdentTopic::new("pyde/encrypted_tx/1")
    }

    /// Proposed blocks and scheduled blocks.
    pub fn blocks() -> IdentTopic {
        IdentTopic::new("pyde/blocks/1")
    }

    /// State sync and witness delivery.
    pub fn sync() -> IdentTopic {
        IdentTopic::new("pyde/sync/1")
    }

    /// All topic names.
    pub fn all() -> Vec<IdentTopic> {
        vec![
            consensus(),
            transactions(),
            encrypted_transactions(),
            blocks(),
            sync(),
        ]
    }
}

/// Dial bootstrap peers and add them to Kademlia.
pub fn dial_bootstrap_peers(swarm: &mut Swarm<PydeBehaviour>, bootstrap_peers: &[String]) {
    for addr_str in bootstrap_peers {
        if let Ok(addr) = addr_str.parse::<Multiaddr>() {
            // Extract PeerId from the multiaddr
            let peer_id = addr.iter().find_map(|proto| {
                if let libp2p::multiaddr::Protocol::P2p(id) = proto {
                    Some(id)
                } else {
                    None
                }
            });

            if let Some(peer_id) = peer_id {
                // Add to Kademlia routing table
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, addr.clone());
                // Dial the peer
                if let Err(e) = swarm.dial(addr) {
                    tracing::warn!(%peer_id, error = %e, "failed to dial bootstrap peer");
                } else {
                    tracing::info!(%peer_id, "dialing bootstrap peer");
                }
            }
        }
    }
}

/// Subscribe a swarm to the appropriate topics based on node role.
pub fn subscribe_topics(
    swarm: &mut Swarm<PydeBehaviour>,
    is_validator: bool,
) -> Result<(), String> {
    // All nodes subscribe to transactions (plaintext + encrypted), blocks, sync
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&topics::transactions())
        .map_err(|e| format!("subscribe error: {e}"))?;
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&topics::encrypted_transactions())
        .map_err(|e| format!("subscribe error: {e}"))?;
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&topics::blocks())
        .map_err(|e| format!("subscribe error: {e}"))?;
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&topics::sync())
        .map_err(|e| format!("subscribe error: {e}"))?;

    // Validators also subscribe to consensus
    if is_validator {
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topics::consensus())
            .map_err(|e| format!("subscribe error: {e}"))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_names_unique() {
        let topics = topics::all();
        let mut names: Vec<String> = topics.iter().map(|t| t.hash().to_string()).collect();
        let len = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), len); // all unique
    }

    #[test]
    fn topic_count() {
        assert_eq!(topics::all().len(), 4);
    }

    #[tokio::test]
    async fn create_node_succeeds() {
        let config = NetworkConfig::default();
        let key = generate_keypair();
        let (swarm, peer_id) = create_node(&config, key).unwrap();
        assert!(!peer_id.to_string().is_empty());
        drop(swarm);
    }

    #[tokio::test]
    async fn create_validator_node() {
        let config = NetworkConfig::validator(30303);
        let (mut swarm, _) = create_node(&config, generate_keypair()).unwrap();
        subscribe_topics(&mut swarm, true).unwrap();
    }

    #[tokio::test]
    async fn create_full_node() {
        let config = NetworkConfig::full_node(30304);
        let (mut swarm, _) = create_node(&config, generate_keypair()).unwrap();
        subscribe_topics(&mut swarm, false).unwrap();
    }

    #[tokio::test]
    async fn keypair_persistence_roundtrip() {
        let key = generate_keypair();
        let peer_id = PeerId::from(key.public());

        // Serialize → deserialize
        let bytes = keypair_to_bytes(&key).unwrap();
        let restored = keypair_from_bytes(&bytes).unwrap();
        let restored_id = PeerId::from(restored.public());

        // Same PeerId after restore
        assert_eq!(peer_id, restored_id);
    }

    #[tokio::test]
    async fn persistent_identity_across_restarts() {
        let key = generate_keypair();
        let bytes = keypair_to_bytes(&key).unwrap();

        // "First run"
        let config = NetworkConfig::default();
        let (_, id1) = create_node(&config, keypair_from_bytes(&bytes).unwrap()).unwrap();

        // "Second run" (same keypair bytes)
        let (_, id2) = create_node(&config, keypair_from_bytes(&bytes).unwrap()).unwrap();

        assert_eq!(id1, id2); // same identity
    }
}
