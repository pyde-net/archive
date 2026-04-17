//! Pyde P2P node: libp2p swarm with QUIC transport.
//!
//! Transport uses Ed25519 identity (libp2p requirement). All consensus-critical
//! operations are FALCON-512 signed at the application layer — the Ed25519
//! identity has no authority over consensus, blocks, or transactions.

use crate::config::NetworkConfig;
use crate::sync_protocol::{self, SyncReq, SyncResp};
use libp2p::{
    gossipsub, identify, identity,
    kad::{self, store::MemoryStore},
    noise, request_response,
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
}

/// Generate a new node keypair. Call once on first run, then persist.
pub fn generate_keypair() -> identity::Keypair {
    identity::Keypair::generate_ed25519()
}

/// Serialize a keypair to bytes for disk persistence.
pub fn keypair_to_bytes(keypair: &identity::Keypair) -> Result<Vec<u8>, String> {
    keypair.to_protobuf_encoding().map_err(|e| format!("keypair serialize error: {e}"))
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
pub fn create_node(config: &NetworkConfig, local_key: identity::Keypair) -> Result<(Swarm<PydeBehaviour>, PeerId), String> {
    let local_peer_id = PeerId::from(local_key.public());

    // Build swarm
    let swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_quic()
        .with_behaviour(|key| {
            // Gossipsub
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_millis(400)) // match block time
                .validation_mode(gossipsub::ValidationMode::Strict)
                .max_transmit_size(256 * 1024) // 256KB max message
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

            Ok(PydeBehaviour {
                gossipsub,
                kademlia,
                identify,
                sync,
            })
        })
        .map_err(|e| format!("behaviour error: {e}"))?
        .with_swarm_config(|cfg| {
            cfg.with_idle_connection_timeout(config.idle_timeout)
        })
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

    /// Encrypted transactions from users.
    pub fn transactions() -> IdentTopic {
        IdentTopic::new("pyde/transactions/1")
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
        vec![consensus(), transactions(), blocks(), sync()]
    }
}

/// Dial bootstrap peers and add them to Kademlia.
pub fn dial_bootstrap_peers(
    swarm: &mut Swarm<PydeBehaviour>,
    bootstrap_peers: &[String],
) {
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
                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
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
    // All nodes subscribe to transactions, blocks, sync
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&topics::transactions())
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
