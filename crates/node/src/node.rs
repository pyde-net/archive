use crate::block_processor::BlockProcessor;
use crate::chain::ChainState;
use crate::config::NodeConfig;
use crate::shutdown::ShutdownSignal;
use crate::state_manager::StateManager;
use crate::tx_relay::TxRelay;
use crate::validator::{ValidatorEngine, ValidatorIdentity, verify_stake};
use libp2p::futures::StreamExt;
use libp2p::gossipsub;
use libp2p::swarm::SwarmEvent;
use pyde_net::channels::Channel;
use pyde_net::config::NetworkConfig;
use pyde_net::node::{
    create_node, generate_keypair, keypair_from_bytes, keypair_to_bytes, subscribe_topics,
    PydeBehaviourEvent,
};
use std::path::Path;
use tracing::{debug, info, warn};

/// The main Pyde node. Owns all subsystems.
pub struct PydeNode {
    config: NodeConfig,
    shutdown: ShutdownSignal,
}

impl PydeNode {
    pub fn new(config: NodeConfig, shutdown: ShutdownSignal) -> Self {
        Self { config, shutdown }
    }

    /// Run the node until shutdown.
    pub async fn run(&self) -> Result<(), String> {
        let is_validator = self.config.node.role == "validator";
        let role_str = if is_validator {
            "validator"
        } else {
            "full node"
        };

        info!(
            role = role_str,
            chain_id = self.config.node.chain_id,
            "starting pyde node"
        );

        // Ensure data directory exists
        let datadir = &self.config.node.datadir;
        std::fs::create_dir_all(datadir)
            .map_err(|e| format!("failed to create datadir {}: {}", datadir.display(), e))?;

        // --- Initialize subsystems ---

        // 1. State storage (RocksDB + SMT)
        let mut state = StateManager::open(datadir, self.config.storage.cache_size)?;
        info!(
            state_root = hex::encode(state.root()),
            empty = state.is_empty(),
            "state loaded"
        );

        // 2. Chain state tracker
        let mut chain = ChainState::genesis(state.root());
        info!(head_slot = chain.head_slot, "chain initialized");

        // 3. Transaction relay / mempool
        let mut tx_relay = TxRelay::new();

        // 4. Validator engine (only for validator role)
        let mut validator_engine: Option<ValidatorEngine> = if is_validator {
            let mut engine = ValidatorEngine::new([0u8; 32]); // epoch randomness set at epoch boundary
            // Validator key loading is deferred until the validator registers on-chain
            // and receives their committee assignment. For now, initialize the engine.
            info!("validator consensus engine initialized");
            Some(engine)
        } else {
            None
        };

        // 5. Load or generate node identity (persistent across restarts)
        let keypair = load_or_generate_identity(datadir)?;
        let peer_id = libp2p::PeerId::from(keypair.public());
        info!(%peer_id, "node identity loaded");

        // 5. Build network config from node config
        let net_config = NetworkConfig {
            port: self.config.network.port,
            max_peers: self.config.network.max_peers,
            max_inbound: self.config.network.max_inbound,
            max_outbound: self.config.network.max_outbound,
            idle_timeout: std::time::Duration::from_secs(60),
            rate_limit_per_ip: self.config.network.rate_limit_per_ip,
            bootstrap_peers: self.config.network.bootstrap_peers.clone(),
            is_validator,
        };

        // 6. Create libp2p swarm
        let (mut swarm, local_peer_id) = create_node(&net_config, keypair)?;
        info!(%local_peer_id, port = self.config.network.port, "P2P transport ready");

        // 7. Subscribe to gossipsub topics
        subscribe_topics(&mut swarm, is_validator)?;
        info!("gossipsub topics subscribed");

        // 8. Listen on all interfaces
        let listen_addr: libp2p::Multiaddr =
            format!("/ip4/0.0.0.0/udp/{}/quic-v1", self.config.network.port)
                .parse()
                .map_err(|e| format!("invalid listen addr: {}", e))?;
        swarm
            .listen_on(listen_addr)
            .map_err(|e| format!("failed to listen: {}", e))?;

        // 9. Start metrics if enabled
        if self.config.metrics.enabled {
            match crate::metrics::init(self.config.metrics.port) {
                Ok(addr) => info!(%addr, "prometheus metrics server started"),
                Err(e) => warn!("metrics disabled: {}", e),
            }
        }

        info!(
            role = role_str,
            port = self.config.network.port,
            "node started — waiting for peers"
        );

        // --- Main event loop ---
        let mut shutdown_rx = self.shutdown.subscribe();

        // Periodic maintenance timer (every 10 seconds)
        let mut maintenance_interval = tokio::time::interval(std::time::Duration::from_secs(10));

        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    handle_swarm_event(
                        event,
                        &mut chain,
                        &mut state,
                        &mut tx_relay,
                        &mut validator_engine,
                    );
                }
                _ = maintenance_interval.tick() => {
                    // Periodic maintenance
                    tx_relay.prune_expired();
                    crate::metrics::record_mempool(tx_relay.mempool_size());
                    let peer_count = swarm.connected_peers().count();
                    crate::metrics::record_peers(peer_count);
                    debug!(
                        peers = peer_count,
                        mempool = tx_relay.mempool_size(),
                        head = chain.head_slot,
                        "maintenance tick"
                    );
                }
                _ = shutdown_rx.recv() => {
                    info!("shutdown signal received, stopping node...");
                    break;
                }
            }
        }

        info!(
            head_slot = chain.head_slot,
            state_root = hex::encode(chain.state_root),
            "node stopped cleanly"
        );
        Ok(())
    }
}

/// Handle a libp2p swarm event.
fn handle_swarm_event(
    event: SwarmEvent<PydeBehaviourEvent>,
    chain: &mut ChainState,
    state: &mut StateManager,
    tx_relay: &mut TxRelay,
    validator_engine: &mut Option<ValidatorEngine>,
) {
    match event {
        // --- Gossipsub message received ---
        SwarmEvent::Behaviour(PydeBehaviourEvent::Gossipsub(
            gossipsub::Event::Message { message, .. },
        )) => {
            let topic = message.topic.to_string();
            let channel = Channel::from_topic(&topic);

            match channel {
                Some(Channel::Transactions) => {
                    debug!(bytes = message.data.len(), "received tx gossip");
                    // Tx deserialization will be wired when we have a wire format
                    // for EncryptedTx. For now, log receipt.
                }
                Some(Channel::Blocks) => {
                    debug!(bytes = message.data.len(), "received block gossip");
                    // Block deserialization and processing will be wired when we have
                    // a wire format for blocks.
                }
                Some(Channel::Consensus) => {
                    if let Some(engine) = validator_engine.as_mut() {
                        debug!(bytes = message.data.len(), "received consensus message");
                        // Consensus message deserialization and dispatch:
                        // - Proposal → engine.on_proposal()
                        // - Vote → engine.on_vote()
                        // - ViewChange → engine.on_view_change()
                        // - FinalityVote → engine.on_finality_vote()
                        // Wire format serialization is a Phase 10 integration task.
                    }
                }
                Some(Channel::Sync) => {
                    debug!(bytes = message.data.len(), "received sync message");
                }
                None => {
                    debug!(topic, "received message on unknown topic");
                }
            }
        }

        // --- Peer connected ---
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            info!(
                %peer_id,
                addr = %endpoint.get_remote_address(),
                "peer connected"
            );
        }

        // --- Peer disconnected ---
        SwarmEvent::ConnectionClosed {
            peer_id, cause, ..
        } => {
            info!(
                %peer_id,
                cause = ?cause,
                "peer disconnected"
            );
        }

        // --- Listening on address ---
        SwarmEvent::NewListenAddr { address, .. } => {
            info!(%address, "listening on");
        }

        // All other events
        _ => {}
    }
}

/// Load node identity from disk, or generate and persist a new one.
fn load_or_generate_identity(datadir: &Path) -> Result<libp2p::identity::Keypair, String> {
    let key_path = datadir.join("node.key");

    if key_path.exists() {
        let bytes = std::fs::read(&key_path)
            .map_err(|e| format!("failed to read {}: {}", key_path.display(), e))?;
        let keypair = keypair_from_bytes(&bytes)?;
        Ok(keypair)
    } else {
        let keypair = generate_keypair();
        let bytes = keypair_to_bytes(&keypair)?;
        std::fs::write(&key_path, &bytes)
            .map_err(|e| format!("failed to write {}: {}", key_path.display(), e))?;
        info!(path = %key_path.display(), "generated new node identity");
        Ok(keypair)
    }
}
