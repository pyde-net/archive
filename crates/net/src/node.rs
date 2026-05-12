//! Pyde P2P node: libp2p swarm with QUIC transport.
//!
//! Transport uses Ed25519 identity (libp2p requirement). All consensus-critical
//! operations are FALCON-512 signed at the application layer — the Ed25519
//! identity has no authority over consensus, blocks, or transactions.

use crate::auth::{self, PydeAuthReq, PydeAuthResp};
use crate::block_txs_protocol::{self, BlockTxsReq, BlockTxsResp};
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
    /// Request-response for fine-grained missing-tx fetch when a
    /// compact block can't be reconstructed from the local mempool.
    /// Replaces the audit-396-style storm of `GetBlocks(slot)` for
    /// unfinalized slots — see `block_txs_protocol.rs` for the full
    /// rationale.
    pub block_txs_rr: request_response::cbor::Behaviour<BlockTxsReq, BlockTxsResp>,
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
                // Audit 333: match the Blocks-channel logical cap
                // (4 MB per `crates/net/src/channels.rs` +
                // `ddos.rs`). Pre-fix this knob was 1 MB, so a
                // proposer publishing a compact block + a heavy
                // `EncryptedTxBundle` near the per-channel ceiling
                // had its publish silently fail at the gossipsub
                // layer — non-proposer mempools never received the
                // bundle and the chain stalled on the encrypted-tx
                // pipeline (see audit P1 #319 for the user-facing
                // burst-test shape). Lifting to 4 MB closes the
                // mismatch.
                .max_transmit_size(4 * 1024 * 1024) // 4 MB max message
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

            let mut gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .map_err(|e| format!("gossipsub error: {e}"))?;

            // Audit 334: install peer scoring so misbehaving peers
            // get demoted from the mesh and (eventually) graylisted.
            // Pre-fix `with_peer_score` was never called, so every
            // peer received the same priority forever — a single
            // hostile peer that re-grafted faster than the prune
            // backoff or failed IWANT lookups silently degraded the
            // gossipsub mesh for everyone, with no recovery path.
            //
            // Parameter rationale:
            // - **`behaviour_penalty_weight: -10.0`** (default) +
            //   threshold 6.0 → tolerate up to 6 misbehaviours
            //   (graft-floods, dropped IWANT) before scoring kicks
            //   in; squared penalty above that.
            // - **`behaviour_penalty_decay: 0.5`** → after a peer
            //   stops misbehaving, their score recovers to ~0 over
            //   a few decay intervals (1 s each). Lenient enough
            //   for transient flaps, strict enough that a sustained
            //   attacker drops below `graylist_threshold (-80)`.
            // - **`ip_colocation_factor_threshold: 10.0`** → up to
            //   10 peers per IP is fine. Cluster-test setups (4-8
            //   localhost validators) stay below the line; a
            //   real-world Sybil farm hosting many peers behind
            //   one IP gets scored down.
            // - **`app_specific_weight: 0.0`** → we don't yet plumb
            //   app-side scores back into gossipsub; weight 0
            //   neutralizes the unused dimension. Hook is in place
            //   for future audit-suite reputation feedback.
            // - Default `PeerScoreThresholds`:
            //   gossip = -10, publish = -50, graylist = -80,
            //   accept_px = 10, opportunistic_graft = 20. Standard
            //   Ethereum-2 / IPFS-style envelope.
            //
            // No per-topic params yet — testnet operators will tune
            // mesh delivery / invalid-message weights from real
            // observation. Global behavioural penalty is the
            // floor that closes the most-exploitable hole.
            let score_params = gossipsub::PeerScoreParams {
                topics: std::collections::HashMap::new(),
                topic_score_cap: 3600.0,
                app_specific_weight: 0.0,
                ip_colocation_factor_weight: -5.0,
                ip_colocation_factor_threshold: 10.0,
                ip_colocation_factor_whitelist: std::collections::HashSet::new(),
                behaviour_penalty_weight: -10.0,
                behaviour_penalty_threshold: 6.0,
                behaviour_penalty_decay: 0.5,
                decay_interval: Duration::from_secs(1),
                decay_to_zero: 0.01,
                retain_score: Duration::from_secs(3600),
            };
            let score_thresholds = gossipsub::PeerScoreThresholds::default();
            gossipsub
                .with_peer_score(score_params, score_thresholds)
                .map_err(|e| format!("gossipsub peer-score init: {e}"))?;

            // Kademlia
            let kademlia = kad::Behaviour::new(
                PeerId::from(key.public()),
                MemoryStore::new(PeerId::from(key.public())),
            );

            // Audit 340: bind chain_id into the identify
            // protocol-version string so peers from a different
            // chain are visible at handshake time. The
            // ConnectionEstablished arm in the application loop
            // disconnects on `IdentifyEvent::Received` whose
            // `protocol_version` doesn't match. Without this a
            // chain-7331 node and a chain-12345 node could
            // happily handshake at the libp2p layer and only
            // diverge later at application-message time, after
            // they'd already swapped Kademlia entries +
            // gossipsub subscriptions.
            let proto_ver = format!("/pyde/1.0.0/{}", config.chain_id);
            let identify = identify::Behaviour::new(identify::Config::new(proto_ver, key.public()));

            // Sync request-response protocol
            let sync = sync_protocol::sync_behaviour();

            // FALCON peer-attestation protocol (tasks 029/030).
            let auth = auth::auth_behaviour();

            // Direct consensus message delivery (audit 234 part 3).
            let consensus_rr = consensus_protocol::consensus_behaviour();

            // Direct Blocks-topic delivery (audit 234 part 4 follow-up).
            let blocks_rr = blocks_protocol::blocks_behaviour();

            // Fine-grained missing-tx fetch — replaces the audit-396
            // storm of GetBlocks for unfinalized slots when a compact
            // block can't be reconstructed from the local mempool.
            let block_txs_rr = block_txs_protocol::block_txs_behaviour();

            Ok(PydeBehaviour {
                gossipsub,
                kademlia,
                identify,
                sync,
                auth,
                consensus_rr,
                blocks_rr,
                block_txs_rr,
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
    ///
    /// The literal string MUST match the arm in
    /// `crate::channels::Channel::from_topic`. Pre-fix this returned
    /// `pyde/encrypted_tx/1` while `Channel::from_topic` only knew
    /// `pyde/encrypted_transactions/1`, so every received encrypted-
    /// tx gossip message fell into the catch-all "unknown topic"
    /// branch and the encrypted mempool was a no-op over the network.
    /// `topics_round_trip_through_channel_from_topic` below locks
    /// the alignment in.
    pub fn encrypted_transactions() -> IdentTopic {
        IdentTopic::new("pyde/encrypted_transactions/1")
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
///
/// Avoids two libp2p flap sources that wreck consensus on a
/// fully-meshed bootstrap config:
///
/// 1. **Simultaneous open.** With every node listing every other
///    node, both peers in a pair dial each other concurrently;
///    libp2p establishes both connections, then dedupes one with
///    cause `None` (local close) or `ApplicationClosed`. On a 4-node
///    localhost devnet that produced ~4 flaps/sec/peer and dropped
///    ~33% of gossipsub block proposals, leaving each validator's
///    `buffered_proposals` set holding only its own block at vote
///    time — every node then voted for itself, formed a self-QC
///    over a synth empty-body block, and the chain forked into N
///    independent local chains. Mitigation: per-pair, only the
///    LOWER peer-id dials; the higher accepts the inbound. Symmetric
///    tie-break — both ends agree without coordination.
///
/// 2. **Re-dialing connected peers.** This function is called on a
///    2-second tick to recover from post-restart mesh degradation,
///    but firing the dial unconditionally has the same effect as #1
///    on every tick — libp2p sees a connected peer being dialed,
///    races the new connection against the live one, and dedupes.
///    Mitigation: skip peers we already have a connection to. The
///    earlier audit-234 comment said this gating "regressed" chain
///    advancement, but that regression was specific to SIGKILL-style
///    restarts where libp2p still considers a TCP-half-closed peer
///    "connected"; the steady-state cost of re-dialing every tick
///    is far worse than that edge case, which is better handled by
///    explicit disconnect-then-redial.
pub fn dial_bootstrap_peers(swarm: &mut Swarm<PydeBehaviour>, bootstrap_peers: &[String]) {
    let local_peer_id = *swarm.local_peer_id();
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
                // Always seed Kademlia — even when we don't dial, the
                // routing entry lets us answer DHT queries about this
                // peer and lets discovery promote the address if
                // we end up dialing later.
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, addr.clone());
                // Skip dialing peers with peer-ids higher than ours —
                // they will dial us instead. This breaks the dial
                // race symmetrically.
                if local_peer_id >= peer_id {
                    tracing::debug!(
                        %peer_id,
                        "skipping bootstrap dial (waiting for higher peer to dial us)"
                    );
                    continue;
                }
                // Skip dialing peers we already have a live
                // connection to — re-dial only if the connection
                // dropped.
                if swarm.is_connected(&peer_id) {
                    continue;
                }
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
    mev_protection_enabled: bool,
) -> Result<(), String> {
    // All nodes subscribe to transactions (plaintext), blocks, sync
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&topics::transactions())
        .map_err(|e| format!("subscribe error: {e}"))?;
    if mev_protection_enabled {
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topics::encrypted_transactions())
            .map_err(|e| format!("subscribe error: {e}"))?;
    }
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
        // consensus + transactions + encrypted_transactions + blocks + sync.
        // Last bumped when `encrypted_transactions` shipped with the
        // MEV-protected encrypted-tx flow (item 227).
        assert_eq!(topics::all().len(), 5);
    }

    /// TPL-201: every subscribed topic name must round-trip through
    /// `Channel::from_topic`. The pre-existing
    /// `channel_from_topic_roundtrip` in `channels.rs` only checks
    /// `Channel::topic()` against `Channel::from_topic` — both
    /// internal to that file — so it can't notice when a `topics::*`
    /// function in this file drifts away from the dispatcher's
    /// table. The bug it would have caught: pre-fix
    /// `topics::encrypted_transactions()` returned
    /// `pyde/encrypted_tx/1`, the dispatcher only knew
    /// `pyde/encrypted_transactions/1`, and every received
    /// encrypted-tx gossip silently fell into the catch-all
    /// "unknown topic" branch — the encrypted mempool was a no-op
    /// over the network.
    #[test]
    fn topics_round_trip_through_channel_from_topic() {
        use crate::channels::Channel;

        let pairs = [
            (topics::consensus(), Channel::Consensus),
            (topics::transactions(), Channel::Transactions),
            (
                topics::encrypted_transactions(),
                Channel::EncryptedTransactions,
            ),
            (topics::blocks(), Channel::Blocks),
            (topics::sync(), Channel::Sync),
        ];
        for (topic, expected) in pairs {
            let name = topic.hash().to_string();
            assert_eq!(
                Channel::from_topic(&name),
                Some(expected),
                "subscribed topic {:?} (name {:?}) did not round-trip \
                 through Channel::from_topic — receive-side dispatch \
                 will silently drop messages on this topic",
                expected,
                name,
            );
        }
    }

    #[tokio::test]
    async fn create_node_succeeds() {
        let config = NetworkConfig::default();
        let key = generate_keypair();
        let (swarm, peer_id) = create_node(&config, key).unwrap();
        assert!(!peer_id.to_string().is_empty());
        drop(swarm);
    }

    /// Audit 334: every newly-created Pyde swarm must have peer
    /// scoring enabled. Pre-fix `with_peer_score(...)` was never
    /// called, so misbehaving peers couldn't be demoted from the
    /// gossipsub mesh and a single hostile peer could degrade
    /// delivery for every other validator. We can't read the
    /// installed `PeerScoreParams` back out (the gossipsub
    /// crate doesn't expose getters), but we CAN attempt to
    /// install the scoring system again — the second call must
    /// fail with "Peer score set twice", proving the first one
    /// took effect during `create_node`.
    #[tokio::test]
    async fn audit_334_peer_scoring_is_installed_on_create() {
        let config = NetworkConfig::default();
        let key = generate_keypair();
        let (mut swarm, _peer_id) = create_node(&config, key).unwrap();

        // Try to install scoring AGAIN. If `create_node` already
        // wired peer scoring, this fails with the "Peer score set
        // twice" error from the gossipsub crate. If `create_node`
        // forgot to install it (the audit-334 regression), this
        // would silently succeed.
        let params = gossipsub::PeerScoreParams::default();
        let thresholds = gossipsub::PeerScoreThresholds::default();
        let res = swarm
            .behaviour_mut()
            .gossipsub
            .with_peer_score(params, thresholds);
        assert!(
            res.is_err() && res.as_ref().unwrap_err().contains("twice"),
            "audit 334: peer scoring must be installed by create_node, but got {:?}",
            res
        );
    }

    #[tokio::test]
    async fn create_validator_node() {
        let config = NetworkConfig::validator(30303);
        let (mut swarm, _) = create_node(&config, generate_keypair()).unwrap();
        subscribe_topics(&mut swarm, true, true).unwrap();
    }

    #[tokio::test]
    async fn create_full_node() {
        let config = NetworkConfig::full_node(30304);
        let (mut swarm, _) = create_node(&config, generate_keypair()).unwrap();
        subscribe_topics(&mut swarm, false, true).unwrap();
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
