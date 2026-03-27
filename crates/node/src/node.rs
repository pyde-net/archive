use crate::block_processor::BlockProcessor;
use crate::chain::ChainState;
use crate::config::NodeConfig;
use crate::rpc::{self, RpcState};
use crate::shutdown::ShutdownSignal;
use crate::state_manager::StateManager;
use crate::sync::ChainSync;
use crate::tx_relay::TxRelay;
use crate::validator::{ValidatorEngine, ValidatorIdentity, verify_stake};
use libp2p::futures::StreamExt;
use libp2p::gossipsub;
use libp2p::request_response;
use libp2p::swarm::SwarmEvent;
use libp2p::PeerId;
use pyde_net::channels::Channel;
use pyde_net::config::NetworkConfig;
use pyde_net::node::{
    create_node, generate_keypair, keypair_from_bytes, keypair_to_bytes, subscribe_topics,
    PydeBehaviour, PydeBehaviourEvent,
};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
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

        // 2. Apply genesis if state is empty (first start)
        if state.is_empty() {
            let genesis_path = datadir.join("genesis.toml");
            let genesis_config = if genesis_path.exists() {
                crate::genesis::GenesisConfig::load(&genesis_path)?
            } else {
                info!("no genesis.toml found, using devnet defaults");
                let config = crate::genesis::devnet_genesis();
                // Write default genesis for reference
                let _ = std::fs::write(&genesis_path, config.to_toml());
                config
            };
            let genesis_block = crate::genesis::initialize_genesis(&mut state, &genesis_config)?;
            info!(
                state_root = hex::encode(state.root()),
                slot = genesis_block.slot(),
                "genesis block created"
            );
        } else {
            info!(
                state_root = hex::encode(state.root()),
                "state loaded from disk"
            );
        }

        // 3. Chain state tracker
        let chain = ChainState::genesis(state.root());
        info!(head_slot = chain.head_slot, "chain initialized");

        // Wrap in Arc<RwLock> for RPC sharing
        let chain = Arc::new(RwLock::new(chain));
        let state = Arc::new(RwLock::new(state));

        // 3. Transaction relay / mempool
        let mut tx_relay = TxRelay::new();

        // 4. Chain sync
        let mut chain_sync = ChainSync::new();
        chain_sync.manager.local_tip = chain.read().await.head_slot;

        // 5. Validator engine (only for validator role)
        let mut validator_engine: Option<ValidatorEngine> = if is_validator {
            // Load validator FALCON signing key (required for validator role)
            let identity = load_validator_identity(datadir)?;
            info!(
                address = hex::encode(identity.address),
                "validator identity loaded"
            );

            // Check stake if state is available (non-genesis)
            {
                let state_guard = state.read().await;
                if !state_guard.is_empty() {
                    let balance_key = pyde_state::keys::balance_key(&identity.address);
                    let balance = state_guard.get(&balance_key)
                        .map(|b| {
                            if b.len() >= 16 {
                                let mut buf = [0u8; 16];
                                buf.copy_from_slice(&b[..16]);
                                u128::from_le_bytes(buf)
                            } else {
                                0u128
                            }
                        })
                        .unwrap_or(0);

                    verify_stake(balance).map_err(|e| {
                        format!("cannot start as validator: {}", e)
                    })?;
                    info!(balance, "validator stake verified");
                } else {
                    warn!("state is empty (genesis) — stake verification deferred until chain syncs");
                }
            }

            let mut engine = ValidatorEngine::new([0u8; 32]);
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

        // 10. Start RPC server if enabled
        if self.config.rpc.enabled {
            let rpc_state = Arc::new(RpcState {
                chain: chain.clone(),
                state: state.clone(),
            });
            match rpc::start_rpc_server(
                &self.config.rpc.listen,
                self.config.rpc.port,
                rpc_state,
                self.config.node.chain_id,
            ).await {
                Ok(addr) => info!(%addr, "JSON-RPC server started"),
                Err(e) => warn!("RPC server disabled: {}", e),
            }
        }

        info!(
            role = role_str,
            port = self.config.network.port,
            "node started — waiting for peers"
        );

        // --- Main event loop ---
        let mut shutdown_rx = self.shutdown.subscribe();

        // Periodic timers
        let mut maintenance_interval = tokio::time::interval(std::time::Duration::from_secs(10));
        let mut sync_interval = tokio::time::interval(std::time::Duration::from_secs(2));

        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    // Process event, collecting any actions that need the swarm
                    let action = {
                        let mut chain_w = chain.write().await;
                        let mut state_w = state.write().await;
                        handle_swarm_event(
                            event,
                            &mut chain_w,
                            &mut state_w,
                            &mut tx_relay,
                            &mut chain_sync,
                            &mut validator_engine,
                        )
                    };

                    // Execute post-event actions that need swarm access
                    match action {
                        PostEventAction::None => {}
                        PostEventAction::RequestChainTip(peer) => {
                            chain_sync.request_chain_tip(&mut swarm, peer);
                        }
                        PostEventAction::SendSyncResponse(channel, response) => {
                            let _ = swarm.behaviour_mut().sync.send_response(channel, response);
                        }
                        PostEventAction::ContinueSync => {
                            chain_sync.request_next_batch(&mut swarm);
                        }
                    }
                }
                _ = sync_interval.tick() => {
                    // Try to sync if we're behind
                    if chain_sync.is_syncing() {
                        chain_sync.request_next_batch(&mut swarm);
                    }
                }
                _ = maintenance_interval.tick() => {
                    // Periodic maintenance
                    tx_relay.prune_expired();
                    crate::metrics::record_mempool(tx_relay.mempool_size());
                    let peer_count = swarm.connected_peers().count();
                    crate::metrics::record_peers(peer_count);
                    let head = chain.read().await.head_slot;
                    debug!(
                        peers = peer_count,
                        mempool = tx_relay.mempool_size(),
                        head,
                        syncing = chain_sync.is_syncing(),
                        behind = chain_sync.manager.slots_behind(),
                        "maintenance tick"
                    );
                }
                _ = shutdown_rx.recv() => {
                    info!("shutdown signal received, stopping node...");
                    break;
                }
            }
        }

        {
            let chain_r = chain.read().await;
            info!(
                head_slot = chain_r.head_slot,
                state_root = hex::encode(chain_r.state_root),
                "node stopped cleanly"
            );
        }
        Ok(())
    }
}

use pyde_net::sync_protocol::{SyncReq, SyncResp};

/// Action to take after processing a swarm event (avoids borrow conflicts with swarm).
enum PostEventAction {
    None,
    RequestChainTip(PeerId),
    SendSyncResponse(request_response::ResponseChannel<SyncResp>, SyncResp),
    ContinueSync,
}

/// Handle a libp2p swarm event. Returns an action that may need swarm access.
fn handle_swarm_event(
    event: SwarmEvent<PydeBehaviourEvent>,
    chain: &mut ChainState,
    state: &mut StateManager,
    tx_relay: &mut TxRelay,
    chain_sync: &mut ChainSync,
    validator_engine: &mut Option<ValidatorEngine>,
) -> PostEventAction {
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
                }
                Some(Channel::Blocks) => {
                    debug!(bytes = message.data.len(), "received block gossip");
                }
                Some(Channel::Consensus) => {
                    if let Some(_engine) = validator_engine.as_mut() {
                        debug!(bytes = message.data.len(), "received consensus message");
                    }
                }
                Some(Channel::Sync) => {
                    debug!(bytes = message.data.len(), "received sync message");
                }
                None => {
                    debug!(topic, "received message on unknown topic");
                }
            }
            PostEventAction::None
        }

        // --- Sync: inbound request from peer ---
        SwarmEvent::Behaviour(PydeBehaviourEvent::Sync(
            request_response::Event::Message {
                message: request_response::Message::Request { request, channel, .. },
                peer,
            },
        )) => {
            debug!(%peer, "inbound sync request");
            let response = ChainSync::handle_inbound_request(&request, chain);
            PostEventAction::SendSyncResponse(channel, response)
        }

        // --- Sync: response to our outbound request ---
        SwarmEvent::Behaviour(PydeBehaviourEvent::Sync(
            request_response::Event::Message {
                message: request_response::Message::Response { request_id, response },
                ..
            },
        )) => {
            chain_sync.on_response(request_id, response, chain, state);
            if chain_sync.is_syncing() {
                PostEventAction::ContinueSync
            } else {
                PostEventAction::None
            }
        }

        // --- Sync request failed ---
        SwarmEvent::Behaviour(PydeBehaviourEvent::Sync(
            request_response::Event::OutboundFailure { peer, error, .. },
        )) => {
            warn!(%peer, ?error, "sync request failed");
            PostEventAction::None
        }

        // --- Peer connected: ask for their chain tip ---
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            info!(
                %peer_id,
                addr = %endpoint.get_remote_address(),
                "peer connected"
            );
            PostEventAction::RequestChainTip(peer_id)
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
            PostEventAction::None
        }

        // --- Listening on address ---
        SwarmEvent::NewListenAddr { address, .. } => {
            info!(%address, "listening on");
            PostEventAction::None
        }

        // All other events
        _ => PostEventAction::None,
    }
}

/// Load validator FALCON signing key from disk.
/// Requires `validator.key` to exist in the data directory.
/// Use `pyde keygen` to generate one (TODO: add keygen subcommand).
/// For now, generates on first run if missing.
fn load_validator_identity(datadir: &Path) -> Result<ValidatorIdentity, String> {
    let key_path = datadir.join("validator.key");

    let (pk, sk) = if key_path.exists() {
        let bytes = std::fs::read(&key_path)
            .map_err(|e| format!("failed to read {}: {}", key_path.display(), e))?;

        // Format: pk_len(4 bytes LE) || pk_bytes || sk_bytes
        if bytes.len() < 4 {
            return Err("validator.key is corrupted (too short)".into());
        }
        let pk_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if bytes.len() < 4 + pk_len {
            return Err("validator.key is corrupted (pk truncated)".into());
        }
        let pk = pyde_crypto::falcon::FalconPublicKey::from_bytes(&bytes[4..4 + pk_len])
            .ok_or("validator.key has invalid public key")?;
        let sk = pyde_crypto::falcon::FalconSecretKey::from_bytes(&bytes[4 + pk_len..])
            .ok_or("validator.key has invalid secret key")?;
        info!(path = %key_path.display(), "loaded validator signing key");
        (pk, sk)
    } else {
        // Generate new validator key
        let (pk, sk) = pyde_crypto::falcon::falcon_keygen()
            .map_err(|e| format!("failed to generate validator key: {}", e))?;

        // Serialize: pk_len || pk || sk
        let pk_bytes = pk.as_bytes();
        let sk_bytes = sk.as_bytes();
        let mut buf = Vec::with_capacity(4 + pk_bytes.len() + sk_bytes.len());
        buf.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(pk_bytes);
        buf.extend_from_slice(sk_bytes);

        std::fs::write(&key_path, &buf)
            .map_err(|e| format!("failed to write {}: {}", key_path.display(), e))?;
        info!(path = %key_path.display(), "generated new validator signing key");
        (pk, sk)
    };

    let pk_bytes = pk.as_bytes().to_vec();
    let address = pyde_account::address::derive_eoa_address(&pk_bytes);

    Ok(ValidatorIdentity {
        address,
        public_key: pk,
        secret_key: sk,
        committee_index: 0, // assigned when joining committee
        key_share: None,    // assigned at epoch boundary
    })
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
