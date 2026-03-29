use crate::block_processor::BlockProcessor;
use crate::block_store::BlockStore;
use crate::chain::ChainState;
use crate::config::NodeConfig;
use crate::receipt_store::ReceiptStore;
use crate::rpc::{self, RpcState};
use crate::shutdown::ShutdownSignal;
use crate::slot_clock::SlotClock;
use crate::state_manager::StateManager;
use crate::sync::ChainSync;
use crate::tx_relay::TxRelay;
use crate::validator::{ValidatorEngine, ValidatorIdentity, verify_stake};
use crate::wire;
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

        // 1. Load validator identity early (needed for genesis funding)
        let early_validator_identity = if is_validator {
            Some(load_validator_identity(datadir)?)
        } else {
            None
        };

        // 2. State storage (RocksDB + SMT)
        let mut state = StateManager::open(datadir, self.config.storage.cache_size)?;

        // 3. Apply genesis if state is empty (first start)
        if state.is_empty() {
            let genesis_path = datadir.join("genesis.toml");
            let mut genesis_config = if genesis_path.exists() {
                crate::genesis::GenesisConfig::load(&genesis_path)?
            } else {
                info!("no genesis.toml found, using devnet defaults");
                crate::genesis::devnet_genesis()
            };

            // Auto-fund validator address with required stake for devnet
            if let Some(ref identity) = early_validator_identity {
                let val_addr = hex::encode(identity.address);
                let already_funded = genesis_config.allocations.iter()
                    .any(|a| a.address == val_addr);
                if !already_funded {
                    genesis_config.allocations.push(crate::genesis::GenesisAllocation {
                        address: val_addr.clone(),
                        balance: pyde_consensus::validator::VALIDATOR_STAKE.to_string(),
                        public_key: Some(hex::encode(identity.public_key.as_bytes())),
                    });
                    info!(address = val_addr, "auto-funded validator in genesis with 10,000 PYDE");
                }
            }

            // Write genesis for reference
            let _ = std::fs::write(&genesis_path, genesis_config.to_toml());

            // Print funded accounts (Anvil-style)
            info!("");
            info!("Available Accounts");
            info!("==================");
            for (i, alloc) in genesis_config.allocations.iter().enumerate() {
                let bal = alloc.balance_u128().unwrap_or(0);
                let pyde = bal / 1_000_000_000; // quanta to PYDE (approx)
                info!("  ({}) 0x{} ({} PYDE)", i, alloc.address, pyde);
            }
            info!("");
            info!("Chain ID: {}", genesis_config.chain_id);
            info!("Base Fee: {} quanta/gas", pyde_tx::fee::GENESIS_BASE_FEE);
            info!("");

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

        // 3. Block store (persistent headers on disk)
        let block_store = BlockStore::open(datadir)?;
        let saved_head = block_store.get_head();

        // 4. Chain state tracker (resume from saved head if available)
        let mut chain = ChainState::genesis(state.root(), self.config.node.chain_id);
        if saved_head > 0 {
            // Restore headers from disk into chain state
            for slot in 1..=saved_head {
                if let Some(header) = block_store.get_header(slot) {
                    chain.advance(header);
                }
            }
            info!(head_slot = chain.head_slot, "chain restored from disk");
        } else {
            info!(head_slot = chain.head_slot, "chain initialized at genesis");
        }

        // Wrap in Arc<RwLock> for RPC sharing
        let chain = Arc::new(RwLock::new(chain));
        let state = Arc::new(RwLock::new(state));

        // 3. Transaction relay / mempool + receipt store + pending tx queue
        let tx_relay = Arc::new(RwLock::new(TxRelay::new()));
        let receipts = Arc::new(RwLock::new(ReceiptStore::new()));
        let pending_txs: Arc<RwLock<Vec<pyde_tx::types::Transaction>>> = Arc::new(RwLock::new(Vec::new()));

        // 4. Chain sync
        let mut chain_sync = ChainSync::new();
        chain_sync.manager.local_tip = chain.read().await.head_slot;

        // 5. Validator engine + identity (only for validator role)
        let mut validator_identity: Option<ValidatorIdentity> = None;
        let mut validator_engine: Option<ValidatorEngine> = if is_validator {
            let identity = early_validator_identity.expect("validator identity loaded earlier");
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
                        .and_then(|b| {
                            // Try to parse as full Account first, fall back to raw u128
                            if let Some(account) = pyde_account::types::Account::from_bytes(&b) {
                                Some(account.balance)
                            } else if b.len() >= 16 {
                                let mut buf = [0u8; 16];
                                buf.copy_from_slice(&b[..16]);
                                Some(u128::from_le_bytes(buf))
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);

                    match verify_stake(balance) {
                        Ok(_) => info!(balance, "validator stake verified"),
                        Err(e) => warn!("{} — proceeding in devnet mode", e),
                    }
                } else {
                    warn!("state is empty (genesis) — stake verification deferred until chain syncs");
                }
            }

            let mut engine = ValidatorEngine::new([0xAA; 32]); // devnet epoch randomness

            // For devnet: this validator is the sole committee member (index 0).
            // In production, committee is formed from on-chain validator set at epoch boundary.
            let pk_bytes = identity.public_key.as_bytes().to_vec();
            engine.set_committee(vec![pk_bytes]);

            info!(
                committee_size = 1,
                "validator consensus engine initialized (devnet single-validator mode)"
            );
            validator_identity = Some(identity);
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

        // 8. Dial bootstrap peers
        if !self.config.network.bootstrap_peers.is_empty() {
            pyde_net::node::dial_bootstrap_peers(&mut swarm, &self.config.network.bootstrap_peers);
        }

        // 9. Listen on all interfaces
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
                tx_relay: tx_relay.clone(),
                receipts: receipts.clone(),
                pending_txs: pending_txs.clone(),
                threshold_pk: None, // Set at epoch boundary when committee is formed
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
            %local_peer_id,
            rpc = format!("http://{}:{}", self.config.rpc.listen, self.config.rpc.port),
            "node started"
        );
        info!(
            "connect with: --bootstrap \"/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}\"",
            self.config.network.port, local_peer_id
        );

        // --- Main event loop ---
        let mut shutdown_rx = self.shutdown.subscribe();

        // Slot clock for block timing
        let slot_clock = SlotClock::new(0); // genesis timestamp 0 = start now
        let mut last_slot = slot_clock.current_slot();

        // Periodic timers
        let mut slot_interval = tokio::time::interval(std::time::Duration::from_millis(100)); // check slot every 100ms
        let mut maintenance_interval = tokio::time::interval(std::time::Duration::from_secs(10));
        let mut sync_interval = tokio::time::interval(std::time::Duration::from_secs(2));

        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    // Process event, collecting any actions that need the swarm
                    let action = {
                        let mut chain_w = chain.write().await;
                        let mut state_w = state.write().await;
                        let mut tx_relay_w = tx_relay.write().await;
                        handle_swarm_event(
                            event,
                            &mut chain_w,
                            &mut state_w,
                            &mut tx_relay_w,
                            &mut chain_sync,
                            &mut validator_engine,
                            &validator_identity,
                            &block_store,
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
                        PostEventAction::BroadcastConsensus(data) => {
                            let topic = pyde_net::node::topics::consensus();
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, data) {
                                warn!(error = %e, "failed to broadcast consensus message");
                            }
                        }
                    }
                }
                _ = slot_interval.tick() => {
                    let current_slot = slot_clock.current_slot();
                    if current_slot > last_slot {
                        last_slot = current_slot;

                        // New slot — validator block production
                        if let Some(engine) = validator_engine.as_mut() {
                            // Sync engine slot to clock (not just +1)
                            while engine.consensus.current_slot < current_slot {
                                engine.advance_slot();
                            }

                            // Skip if chain head is already at or past this slot
                            let chain_head = chain.read().await.head_slot;
                            if current_slot <= chain_head {
                                // Already processed this slot
                            } else if let Some(identity) = validator_identity.as_ref() {
                                // Check if we're the proposer
                                if let Some(candidate) = engine.check_proposer(identity) {
                                    // Drain pending transactions from the queue
                                    let mut pending_w = pending_txs.write().await;
                                    let txs: Vec<pyde_tx::types::Transaction> = pending_w.drain(..).collect();
                                    drop(pending_w);

                                    // Only produce a block if there are pending transactions
                                    if txs.is_empty() {
                                        debug!(slot = current_slot, "skipping empty slot (no pending txs)");
                                    } else {
                                    let tx_count = txs.len();

                                    // Build block with transactions
                                    let chain_r = chain.read().await;
                                    let parent_hash = chain_r.state_root;
                                    let head = chain_r.head_slot;
                                    drop(chain_r);

                                    // Build execution schedule (single group for devnet)
                                    let exec_schedule = pyde_tx::parallel::ExecutionSchedule {
                                        groups: vec![pyde_tx::parallel::ExecutionGroup {
                                            tx_indices: (0..tx_count).collect(),
                                        }],
                                        total_txs: tx_count,
                                    };

                                    // Compute tx root
                                    let tx_root = pyde_consensus::block::compute_tx_root(&txs);

                                    let block = engine.build_proposal(
                                        identity,
                                        parent_hash,
                                        parent_hash, // pre-state root (post-state computed after execution)
                                        tx_root,
                                        candidate.vrf_proof.as_bytes().to_vec(),
                                        txs,
                                        exec_schedule,
                                    );

                                    // Process our own block locally
                                    {
                                        let mut chain_w = chain.write().await;
                                        let mut state_w = state.write().await;
                                        match BlockProcessor::process_full_block(&mut chain_w, &mut state_w, &block) {
                                            Ok((tc, gas, ref receipts_list)) => {
                                                let _ = block_store.put_header(&block.header);
                                                let _ = block_store.put_head(current_slot);
                                                chain_sync.on_block_processed(current_slot);
                                                // Store receipts
                                                let mut receipts_w = receipts.write().await;
                                                receipts_w.insert_block_receipts(current_slot, receipts_list.clone());
                                                info!(
                                                    slot = current_slot,
                                                    txs = tc,
                                                    gas,
                                                    mempool_pending = tx_count,
                                                    "proposed and processed block"
                                                );
                                            }
                                            Err(e) => {
                                                warn!(slot = current_slot, error = %e, "failed to process own block");
                                            }
                                        }
                                    }

                                    // Broadcast via gossipsub
                                    let block_bytes = wire::encode_block(&block);
                                    let topic = pyde_net::node::topics::blocks();
                                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, block_bytes) {
                                        // Expected when no peers subscribe — single node devnet
                                        debug!(slot = current_slot, error = %e, "no gossipsub subscribers for block");
                                    }

                                    // Also broadcast proposal as consensus message
                                    let proposal = pyde_consensus::hotstuff::ConsensusMessage::Proposal {
                                        header: block.header.clone(),
                                        proposer_signature: block.proposer_signature.clone(),
                                    };
                                    let proposal_bytes = wire::encode_consensus_message(&proposal);
                                    let cons_topic = pyde_net::node::topics::consensus();
                                    let _ = swarm.behaviour_mut().gossipsub.publish(cons_topic, proposal_bytes);
                                } // end if mempool_size > 0
                                }
                            }

                            // Check for timeout (no proposal received within 200ms)
                            if engine.is_timed_out() {
                                if let Some(identity) = validator_identity.as_ref() {
                                    if let Some(vc_msg) = engine.on_timeout(identity) {
                                        let vc_bytes = wire::encode_consensus_message(
                                            &pyde_consensus::hotstuff::ConsensusMessage::Timeout {
                                                slot: current_slot,
                                                voter_index: identity.committee_index,
                                                voter_address: identity.address,
                                                highest_qc: engine.consensus.highest_qc.clone(),
                                                signature: vec![], // signed inside on_timeout
                                            }
                                        );
                                        let topic = pyde_net::node::topics::consensus();
                                        let _ = swarm.behaviour_mut().gossipsub.publish(topic, vc_bytes);
                                    }
                                }
                            }

                            debug!(slot = current_slot, "slot tick");
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
                    let mut tx_relay_w = tx_relay.write().await;
                    tx_relay_w.prune_expired();
                    let mempool_size = tx_relay_w.mempool_size();
                    drop(tx_relay_w);
                    crate::metrics::record_mempool(mempool_size);
                    let peer_count = swarm.connected_peers().count();
                    crate::metrics::record_peers(peer_count);
                    let head = chain.read().await.head_slot;
                    debug!(
                        peers = peer_count,
                        mempool = mempool_size,
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
    BroadcastConsensus(Vec<u8>),
}

/// Handle a libp2p swarm event. Returns an action that may need swarm access.
fn handle_swarm_event(
    event: SwarmEvent<PydeBehaviourEvent>,
    chain: &mut ChainState,
    state: &mut StateManager,
    tx_relay: &mut TxRelay,
    chain_sync: &mut ChainSync,
    validator_engine: &mut Option<ValidatorEngine>,
    validator_identity: &Option<ValidatorIdentity>,
    block_store: &BlockStore,
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
                    // Decode transaction and add to mempool
                    // Encrypted txs come as raw EncryptedTx bytes.
                    // Plain txs (for devnet) are wire-encoded Transaction bytes.
                    // For now, log receipt — full decode requires choosing a tx format.
                }
                Some(Channel::Blocks) => {
                    debug!(bytes = message.data.len(), "received block gossip");
                    // Decode and process the block
                    match wire::decode_block(&message.data) {
                        Ok(block) => {
                            let slot = block.header.slot;
                            match BlockProcessor::process_full_block(chain, state, &block) {
                                Ok((tx_count, gas_used, _receipts)) => {
                                    chain_sync.on_block_processed(slot);
                                    // Persist header to disk
                                    let _ = block_store.put_header(&block.header);
                                    let _ = block_store.put_head(slot);
                                    info!(slot, tx_count, gas_used, "block received and processed");
                                }
                                Err(e) => {
                                    debug!(slot, error = %e, "block rejected");
                                }
                            }
                        }
                        Err(e) => {
                            warn!(error = e, "failed to decode block from gossip");
                        }
                    }
                }
                Some(Channel::Consensus) => {
                    if let Some(engine) = validator_engine.as_mut() {
                        match wire::decode_consensus_message(&message.data) {
                            Ok(msg) => {
                                use pyde_consensus::hotstuff::ConsensusMessage;
                                match msg {
                                    ConsensusMessage::Proposal { ref header, .. } => {
                                        info!(slot = header.slot, "received proposal");
                                        // Vote on the proposal if we have an identity
                                        if let Some(identity) = validator_identity.as_ref() {
                                            if let Some(vote) = engine.on_proposal(header, identity) {
                                                // Broadcast vote via gossipsub
                                                let vote_bytes = wire::encode_consensus_message(&vote);
                                                return PostEventAction::BroadcastConsensus(vote_bytes);
                                            }
                                        }
                                    }
                                    ConsensusMessage::Vote { slot, voter_index, .. } => {
                                        debug!(slot, voter_index, "received vote");
                                        if let Some(qc) = engine.on_vote(msg) {
                                            info!(slot, votes = qc.vote_count(), "QC formed");
                                        }
                                    }
                                    ConsensusMessage::Timeout { slot, .. } => {
                                        debug!(slot, "received timeout");
                                    }
                                    ConsensusMessage::NewView { slot, .. } => {
                                        debug!(slot, "received new view");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(error = e, "failed to decode consensus message");
                            }
                        }
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
            let response = ChainSync::handle_inbound_request(&request, chain, state);
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
