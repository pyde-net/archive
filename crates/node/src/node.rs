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
use libp2p::identify;
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
        let genesis_path = datadir.join("genesis.toml");
        let genesis_config = if state.is_empty() {
            let mut genesis_config = if genesis_path.exists() {
                crate::genesis::GenesisConfig::load(&genesis_path)?
            } else {
                info!("no genesis.toml found, using devnet defaults");
                let (config, devnet_accounts) = crate::genesis::devnet_genesis();

                // Print Anvil-style account info with private keys
                info!("");
                info!("==========================================");
                info!("  Pyde Devnet");
                info!("==========================================");
                info!("");
                info!("Available Accounts");
                info!("==================");
                for (i, acc) in devnet_accounts.iter().enumerate() {
                    let pyde = acc.balance / 1_000_000_000;
                    info!("  ({}) {} ({} PYDE)", i, acc.address_hex(), pyde);
                }
                info!("");
                info!("Private Keys");
                info!("==================");
                for (i, acc) in devnet_accounts.iter().enumerate() {
                    info!("  ({}) {}", i, acc.private_key_hex());
                }
                info!("");

                // Save devnet keys for SDK usage
                let keys_path = datadir.join("devnet-keys.json");
                let keys_json: Vec<serde_json::Value> = devnet_accounts.iter().map(|acc| {
                    serde_json::json!({
                        "address": acc.address_hex(),
                        "privateKey": acc.private_key_hex(),
                        "balance": acc.balance.to_string(),
                    })
                }).collect();
                let _ = std::fs::write(&keys_path, serde_json::to_string_pretty(&keys_json).unwrap_or_default());

                config
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

            info!("Chain ID: {}", genesis_config.chain_id);
            info!("Base Fee: {} quanta/gas", pyde_tx::fee::GENESIS_BASE_FEE);
            info!("==========================================");
            info!("");

            let genesis_block = crate::genesis::initialize_genesis(&mut state, &genesis_config)?;
            info!(
                state_root = hex::encode(state.root()),
                slot = genesis_block.slot(),
                "genesis block created"
            );
            genesis_config
        } else {
            info!(
                state_root = hex::encode(state.root()),
                "state loaded from disk"
            );
            // Reload genesis config for committee formation
            if genesis_path.exists() {
                crate::genesis::GenesisConfig::load(&genesis_path)?
            } else {
                crate::genesis::GenesisConfig::default()
            }
        };

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

        // Mempool tx index for compact block reconstruction: tx_hash → wire-encoded bytes
        let mempool_index: Arc<RwLock<std::collections::HashMap<[u8; 32], Vec<u8>>>> =
            Arc::new(RwLock::new(std::collections::HashMap::new()));

        // 4. Chain sync
        let mut chain_sync = ChainSync::new();
        chain_sync.manager.local_tip = chain.read().await.head_slot;

        // 5. Validator engine + identity (only for validator role)
        let mut validator_identity: Option<ValidatorIdentity> = None;
        let mut validator_engine: Option<ValidatorEngine> = if is_validator {
            let mut identity = early_validator_identity.expect("validator identity loaded earlier");
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

            // Build committee from genesis validators (if any).
            // If genesis has validators, use them all as the committee.
            // Otherwise fall back to single-validator mode (just self).
            let mut committee_keys: Vec<Vec<u8>> = Vec::new();
            let mut my_index: u8 = 0;
            let my_pk_hex = hex::encode(identity.public_key.as_bytes());

            if !genesis_config.validators.is_empty() {
                for (i, val) in genesis_config.validators.iter().enumerate() {
                    let pk_bytes = hex::decode(val.public_key.strip_prefix("0x").unwrap_or(&val.public_key))
                        .map_err(|e| format!("invalid validator public key in genesis: {}", e))?;
                    if val.public_key == my_pk_hex || val.public_key == format!("0x{}", my_pk_hex) {
                        my_index = i as u8;
                    }
                    committee_keys.push(pk_bytes);
                }
                info!(
                    committee_size = committee_keys.len(),
                    my_index,
                    "committee formed from genesis validators"
                );
            } else {
                // Fallback: single-validator devnet mode
                committee_keys.push(identity.public_key.as_bytes().to_vec());
                info!(
                    committee_size = 1,
                    "validator consensus engine initialized (devnet single-validator mode)"
                );
            }

            engine.set_committee(committee_keys);
            identity.committee_index = my_index;
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
        let (tx_gossip_tx, mut tx_gossip_rx) = tokio::sync::mpsc::channel::<pyde_tx::types::Transaction>(1024);
        if self.config.rpc.enabled {
            let (new_heads_tx, _) = tokio::sync::broadcast::channel(256);
            let (pending_tx_tx, _) = tokio::sync::broadcast::channel(4096);
            let (logs_tx, _) = tokio::sync::broadcast::channel(1024);
            let rpc_state = Arc::new(RpcState {
                chain: chain.clone(),
                state: state.clone(),
                tx_relay: tx_relay.clone(),
                receipts: receipts.clone(),
                pending_txs: pending_txs.clone(),
                threshold_pk: None, // Set at epoch boundary when committee is formed
                new_heads_tx,
                pending_tx_tx,
                logs_tx,
                dev_mode: self.config.node.dev_mode,
                tx_gossip_tx,
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
                        PostEventAction::AcceptTransaction(tx) => {
                            let tx_hash = tx.hash();
                            // Index for compact block reconstruction
                            let tx_bytes = wire::encode_transaction(&tx);
                            mempool_index.write().await.insert(tx_hash, tx_bytes);
                            let mut pending = pending_txs.write().await;
                            pending.push(tx);
                            debug!(tx_hash = hex::encode(tx_hash), pending = pending.len(), "tx accepted from gossip");
                        }
                        PostEventAction::AddPeerToKademlia(peer_id, addrs) => {
                            for addr in &addrs {
                                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                            }
                            // Proactively dial peers we learn about through Identify.
                            // This builds a mesh so nodes survive bootstrap node failure.
                            if !swarm.is_connected(&peer_id) {
                                for addr in addrs {
                                    if let Err(e) = swarm.dial(addr) {
                                        debug!(error = %e, "failed to dial discovered peer");
                                    }
                                }
                            }
                            let _ = swarm.behaviour_mut().kademlia.bootstrap();
                        }
                        PostEventAction::StoreReceipts(slot, receipts_list) => {
                            let mut receipts_w = receipts.write().await;
                            receipts_w.insert_block_receipts(slot, receipts_list);
                        }
                        PostEventAction::ReconstructCompactBlock(cb) => {
                            // Reconstruct full block from compact block + mempool index
                            let header = match wire::decode_block_header(&cb.header) {
                                Ok(h) => h,
                                Err(e) => { warn!(error = e, "invalid compact block header"); continue; }
                            };
                            let slot = header.slot;

                            // Build mempool snapshot for reconstruction
                            let idx = mempool_index.read().await;
                            let mempool_txs: Vec<([u8; 32], Vec<u8>)> = idx.iter()
                                .map(|(h, b)| (*h, b.clone()))
                                .collect();
                            drop(idx);

                            let (matched, missing) = cb.reconstruct(&mempool_txs);

                            if !missing.is_empty() {
                                // TODO: request missing txs from peers via GetBlockTxs
                                warn!(slot, missing = missing.len(), "compact block has missing txs — requesting not yet implemented, skipping");
                                continue;
                            }

                            // All txs found — decode them and build the full block
                            let mut transactions = Vec::with_capacity(matched.len());
                            for (i, tx_bytes_opt) in matched.iter().enumerate() {
                                let tx_bytes = tx_bytes_opt.as_ref().unwrap();
                                match wire::decode_transaction(tx_bytes) {
                                    Ok(tx) => transactions.push(tx),
                                    Err(e) => {
                                        warn!(slot, tx_idx = i, error = e, "failed to decode reconstructed tx");
                                        continue;
                                    }
                                }
                            }

                            let tx_count = transactions.len();
                            let exec_schedule = pyde_tx::parallel::ExecutionSchedule {
                                groups: vec![pyde_tx::parallel::ExecutionGroup {
                                    tx_indices: (0..tx_count).collect(),
                                }],
                                total_txs: tx_count,
                            };
                            let block = pyde_consensus::block::Block {
                                header: header.clone(),
                                body: pyde_consensus::block::BlockBody {
                                    transactions,
                                    execution_schedule: exec_schedule,
                                },
                                proposer_signature: vec![], // not in compact block, validated via proposal
                            };

                            // Validate and process
                            {
                                let mut chain_w = chain.write().await;
                                let mut state_w = state.write().await;
                                match BlockProcessor::process_full_block(&mut chain_w, &mut state_w, &block) {
                                    Ok((tc, gas, ref receipts_list)) => {
                                        // Store full block for future sync
                                        let full_bytes = wire::encode_block(&block);
                                        let _ = block_store.put_block(&block.header, &full_bytes);
                                        let _ = block_store.put_head(slot);
                                        chain_sync.on_block_processed(slot);
                                        if !receipts_list.is_empty() {
                                            let mut receipts_w = receipts.write().await;
                                            receipts_w.insert_block_receipts(slot, receipts_list.clone());
                                        }
                                        // Remove processed txs from mempool index + pending
                                        let tx_hashes: Vec<[u8; 32]> = block.body.transactions.iter()
                                            .map(|tx| tx.hash()).collect();
                                        {
                                            let mut idx = mempool_index.write().await;
                                            for h in &tx_hashes { idx.remove(h); }
                                        }
                                        {
                                            let mut pending_w = pending_txs.write().await;
                                            pending_w.retain(|tx| !tx_hashes.contains(&tx.hash()));
                                        }
                                        info!(slot, txs = tc, gas, "compact block reconstructed and processed");
                                    }
                                    Err(e) => {
                                        debug!(slot, error = %e, "compact block rejected");
                                    }
                                }
                            }
                        }
                        PostEventAction::BlockProcessed { slot, receipts: receipts_list, tx_hashes } => {
                            // Store receipts
                            if !receipts_list.is_empty() {
                                let mut receipts_w = receipts.write().await;
                                receipts_w.insert_block_receipts(slot, receipts_list);
                            }
                            // Remove processed txs from pending queue (dedup)
                            if !tx_hashes.is_empty() {
                                let mut pending_w = pending_txs.write().await;
                                pending_w.retain(|tx| !tx_hashes.contains(&tx.hash()));
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
                                    // Build fair transaction list: nonce-ordered, interleaved, per-sender capped
                                    let mut pending_w = pending_txs.write().await;
                                    let all_pending: Vec<pyde_tx::types::Transaction> = pending_w.drain(..).collect();
                                    let gas_ceiling = self.config.consensus.gas_ceiling;
                                    let (txs, remaining) = crate::block_builder::build_tx_list(all_pending, gas_ceiling);
                                    // Return overflow txs to pending queue
                                    if !remaining.is_empty() {
                                        pending_w.extend(remaining);
                                    }
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

                                    // Encode VRF data as [output:32 || proof:N] so verifiers
                                    // can check both the score and the proof validity.
                                    let mut vrf_data = Vec::with_capacity(32 + candidate.vrf_proof.as_bytes().len());
                                    vrf_data.extend_from_slice(candidate.vrf_output.as_bytes());
                                    vrf_data.extend_from_slice(candidate.vrf_proof.as_bytes());

                                    let block = engine.build_proposal(
                                        identity,
                                        parent_hash,
                                        parent_hash, // pre-state root (post-state computed after execution)
                                        tx_root,
                                        vrf_data,
                                        txs,
                                        exec_schedule,
                                    );

                                    // Process our own block immediately.
                                    // VRF selection ensures only one proposal wins votes, so
                                    // speculative execution is safe: our block either wins (QC forms)
                                    // or nobody's block wins (timeout). In the rare case another
                                    // proposer's block wins for the same slot, our state diverges
                                    // but the gossip block handler rejects duplicate slots.
                                    {
                                        let mut chain_w = chain.write().await;
                                        let mut state_w = state.write().await;
                                        match BlockProcessor::process_full_block(&mut chain_w, &mut state_w, &block) {
                                            Ok((tc, gas, ref receipts_list)) => {
                                                let _ = block_store.put_header(&block.header);
                                                let _ = block_store.put_head(current_slot);
                                                chain_sync.on_block_processed(current_slot);
                                                let mut receipts_w = receipts.write().await;
                                                receipts_w.insert_block_receipts(current_slot, receipts_list.clone());
                                                info!(
                                                    slot = current_slot, txs = tc, gas,
                                                    "proposed and processed block"
                                                );
                                            }
                                            Err(e) => {
                                                warn!(slot = current_slot, error = %e, "failed to process own block");
                                            }
                                        }
                                    }

                                    // Store full block for sync serving + missing tx requests
                                    let full_block_bytes = wire::encode_block(&block);
                                    let _ = block_store.put_block(&block.header, &full_block_bytes);

                                    // Broadcast COMPACT block (header + 8-byte short IDs) instead of full block.
                                    // Receivers reconstruct from their mempool.
                                    let header_bytes = wire::encode_block_header(&block.header);
                                    let tx_hashes: Vec<[u8; 32]> = block.body.transactions.iter()
                                        .map(|tx| tx.hash()).collect();
                                    let compact = pyde_net::propagation::CompactBlock::from_block(
                                        header_bytes,
                                        &tx_hashes,
                                        &[], // no prefilled txs for now
                                        &[],
                                    );
                                    let compact_bytes = wire::encode_compact_block(&compact);
                                    let topic = pyde_net::node::topics::blocks();
                                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, compact_bytes) {
                                        debug!(slot = current_slot, error = %e, "no gossipsub subscribers for block");
                                    }

                                    // Broadcast proposal as consensus message
                                    let proposal = pyde_consensus::hotstuff::ConsensusMessage::Proposal {
                                        header: block.header.clone(),
                                        proposer_signature: block.proposer_signature.clone(),
                                    };
                                    let proposal_bytes = wire::encode_consensus_message(&proposal);
                                    let cons_topic = pyde_net::node::topics::consensus();
                                    let _ = swarm.behaviour_mut().gossipsub.publish(cons_topic, proposal_bytes);

                                    // Buffer our own proposal for VRF selection.
                                    // Voting happens after the proposal collection window.
                                    engine.buffer_proposal(&block.header, &block.proposer_signature);
                                } // end if mempool_size > 0
                                }
                            }

                            debug!(slot = current_slot, "slot tick (new)");
                        }
                    }

                    // --- Per-tick consensus actions (run every 100ms, not just on new slots) ---
                    if let Some(engine) = validator_engine.as_mut() {
                        let current_slot = slot_clock.current_slot();
                        let ms_in_slot = slot_clock.ms_into_slot();

                        // Proposal selection phase: 100ms into the slot, select the
                        // best proposal (lowest VRF score) and vote for it.
                        if ms_in_slot >= 100 {
                            if let Some(identity) = validator_identity.as_ref() {
                                if let Some(vote) = engine.select_and_vote(identity) {
                                    // Add own vote to collection
                                    let qc_formed = if let Some(qc) = engine.on_vote(vote.clone()) {
                                        info!(slot = current_slot, votes = qc.vote_count(), "QC formed after VRF selection");
                                        true
                                    } else {
                                        false
                                    };
                                    // Broadcast vote
                                    let vote_bytes = wire::encode_consensus_message(&vote);
                                    let topic = pyde_net::node::topics::consensus();
                                    let _ = swarm.behaviour_mut().gossipsub.publish(topic, vote_bytes);

                                    // If QC formed: broadcast hard finality vote
                                    if qc_formed {
                                        let state_root = chain.read().await.state_root;
                                        if let Some(fv) = engine.create_finality_vote(
                                            current_slot,
                                            engine.consensus.highest_qc.block_hash,
                                            state_root,
                                            identity,
                                        ) {
                                            engine.on_finality_vote(fv.clone());
                                            let fv_bytes = wire::encode_finality_vote(&fv);
                                            let topic = pyde_net::node::topics::consensus();
                                            let _ = swarm.behaviour_mut().gossipsub.publish(topic, fv_bytes);
                                        }
                                    }
                                }
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
                                            signature: vec![],
                                        }
                                    );
                                    let topic = pyde_net::node::topics::consensus();
                                    let _ = swarm.behaviour_mut().gossipsub.publish(topic, vc_bytes);
                                }
                            }
                        }
                    }
                }
                Some(tx) = tx_gossip_rx.recv() => {
                    // Index for compact block reconstruction
                    let tx_bytes = wire::encode_transaction(&tx);
                    mempool_index.write().await.insert(tx.hash(), tx_bytes.clone());
                    // Gossip to P2P network
                    let topic = pyde_net::node::topics::transactions();
                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, tx_bytes) {
                        debug!(error = %e, "failed to gossip tx (no subscribers)");
                    } else {
                        debug!(tx_hash = hex::encode(tx.hash()), "gossiped tx to network");
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
                    // Periodically trigger Kademlia bootstrap to discover + connect to new peers.
                    // Critical for mesh resilience: ensures nodes connect to each other,
                    // not just the bootstrap node.
                    let _ = swarm.behaviour_mut().kademlia.bootstrap();
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
    AcceptTransaction(pyde_tx::types::Transaction),
    StoreReceipts(u64, Vec<pyde_tx::execution::Receipt>),
    AddPeerToKademlia(PeerId, Vec<libp2p::Multiaddr>),
    BlockProcessed {
        slot: u64,
        receipts: Vec<pyde_tx::execution::Receipt>,
        tx_hashes: Vec<[u8; 32]>,
    },
    ReconstructCompactBlock(pyde_net::propagation::CompactBlock),
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
                    // Decode wire-encoded transaction and add to pending queue
                    match wire::decode_transaction(&message.data) {
                        Ok(tx) => {
                            let tx_hash = tx.hash();
                            debug!(tx_hash = hex::encode(tx_hash), "decoded tx from gossip");
                            return PostEventAction::AcceptTransaction(tx);
                        }
                        Err(e) => {
                            debug!(error = e, "failed to decode tx from gossip");
                        }
                    }
                }
                Some(Channel::Blocks) => {
                    debug!(bytes = message.data.len(), "received block gossip");

                    // Try compact block first (primary format)
                    if !message.data.is_empty() && message.data[0] == wire::tag::COMPACT_BLOCK {
                        match wire::decode_compact_block(&message.data) {
                            Ok(cb) => {
                                return PostEventAction::ReconstructCompactBlock(cb);
                            }
                            Err(e) => {
                                debug!(error = e, "failed to decode compact block");
                            }
                        }
                        return PostEventAction::None;
                    }

                    // Fallback: full block (from sync or older nodes)
                    match wire::decode_block(&message.data) {
                        Ok(block) => {
                            let slot = block.header.slot;

                            // Validate block against committee (signature, VRF, proposer, QC)
                            if let Some(ref engine) = validator_engine {
                                if let Err(e) = BlockProcessor::validate_network_block(
                                    &block.header,
                                    &block.proposer_signature,
                                    &engine.committee_keys,
                                    &engine.epoch_randomness,
                                ) {
                                    warn!(slot, error = %e, "block validation failed");
                                    return PostEventAction::None;
                                }
                            }

                            match BlockProcessor::process_full_block(chain, state, &block) {
                                Ok((tx_count, gas_used, receipts_list)) => {
                                    chain_sync.on_block_processed(slot);
                                    // Persist full block (header + body) to disk
                                    let _ = block_store.put_block(&block.header, &message.data);
                                    let _ = block_store.put_head(slot);
                                    info!(slot, tx_count, gas_used, "block received and processed");
                                    // Collect tx hashes to deduplicate from pending queue
                                    let tx_hashes: Vec<[u8; 32]> = block.body.transactions.iter()
                                        .map(|tx| tx.hash()).collect();
                                    // Store receipts + deduplicate txs
                                    return PostEventAction::BlockProcessed {
                                        slot,
                                        receipts: receipts_list,
                                        tx_hashes,
                                    };
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
                        // Check if it's a finality vote (different wire tag)
                        if !message.data.is_empty() && message.data[0] == wire::tag::CONSENSUS_FINALITY_VOTE {
                            match wire::decode_finality_vote(&message.data) {
                                Ok(fv) => {
                                    debug!(slot = fv.slot, voter = fv.voter_index, "received finality vote");
                                    engine.on_finality_vote(fv);
                                }
                                Err(e) => {
                                    debug!(error = e, "failed to decode finality vote");
                                }
                            }
                            return PostEventAction::None;
                        }

                        match wire::decode_consensus_message(&message.data) {
                            Ok(msg) => {
                                use pyde_consensus::hotstuff::ConsensusMessage;
                                match msg {
                                    ConsensusMessage::Proposal { ref header, ref proposer_signature } => {
                                        info!(slot = header.slot, "received proposal");
                                        // Buffer the proposal for VRF-based selection.
                                        // Voting happens after the proposal collection window
                                        // via select_and_vote (triggered by slot timer).
                                        engine.buffer_proposal(header, proposer_signature);
                                    }
                                    ConsensusMessage::Vote { slot, voter_index, .. } => {
                                        debug!(slot, voter_index, "received vote");
                                        if let Some(qc) = engine.on_vote(msg) {
                                            info!(slot, votes = qc.vote_count(), "QC formed");
                                        }
                                    }
                                    ConsensusMessage::Timeout {
                                        slot, voter_index, voter_address, highest_qc, signature
                                    } => {
                                        debug!(slot, voter_index, "received timeout");
                                        // Convert to ViewChangeMessage and process
                                        let vc_msg = pyde_consensus::view_change::ViewChangeMessage {
                                            slot,
                                            highest_qc,
                                            voter_index,
                                            voter_address,
                                            signature,
                                        };
                                        if engine.on_view_change(vc_msg) {
                                            info!(slot, "view change QC formed — fallback proposer can proceed");
                                        }
                                    }
                                    ConsensusMessage::NewView { slot, highest_qc, voter_address, signature } => {
                                        debug!(slot, "received new view");
                                        // NewView carries the highest QC from a validator after view change.
                                        // Update our highest QC if theirs is higher.
                                        if highest_qc.slot > engine.consensus.highest_qc.slot {
                                            engine.consensus.highest_qc = highest_qc;
                                            debug!(slot, "updated highest QC from NewView");
                                        }
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
            let response = ChainSync::handle_inbound_request(&request, chain, state, block_store);
            PostEventAction::SendSyncResponse(channel, response)
        }

        // --- Sync: response to our outbound request ---
        SwarmEvent::Behaviour(PydeBehaviourEvent::Sync(
            request_response::Event::Message {
                message: request_response::Message::Response { request_id, response },
                ..
            },
        )) => {
            chain_sync.on_response(request_id, response, chain, state, block_store);
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

        // --- Identify: peer shared their listen addresses ---
        SwarmEvent::Behaviour(PydeBehaviourEvent::Identify(
            identify::Event::Received { peer_id, info, .. },
        )) => {
            debug!(%peer_id, addrs = info.listen_addrs.len(), "identify received");
            if !info.listen_addrs.is_empty() {
                PostEventAction::AddPeerToKademlia(peer_id, info.listen_addrs)
            } else {
                PostEventAction::None
            }
        }

        // --- Kademlia: routing table updated (discovered a new peer) ---
        SwarmEvent::Behaviour(PydeBehaviourEvent::Kademlia(
            libp2p::kad::Event::RoutingUpdated { peer, addresses, .. },
        )) => {
            let addrs: Vec<libp2p::Multiaddr> = addresses.into_vec();
            if !addrs.is_empty() {
                debug!(%peer, addrs = addrs.len(), "kademlia discovered peer");
                PostEventAction::AddPeerToKademlia(peer, addrs)
            } else {
                PostEventAction::None
            }
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
