use crate::block_processor::BlockProcessor;
use crate::block_store::BlockStore;
use crate::chain::ChainState;
use crate::config::NodeConfig;
use crate::consensus_store::ConsensusStateStore;
use crate::receipt_store::ReceiptStore;
use crate::rpc::{self, RpcState};
use crate::shutdown::ShutdownSignal;
use crate::slot_clock::SlotClock;
use crate::state_manager::StateManager;
use crate::sync::ChainSync;
use crate::tx_relay::TxRelay;
use crate::validator::{verify_stake, ValidatorEngine, ValidatorIdentity};
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
    PydeBehaviourEvent,
};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Grace window (in slots) for the task-026 mandatory-inclusion audit.
/// An encrypted_tx must sit in local mempool for at least this many slots
/// before its absence from a proposal counts as censorship. Mainnet ships
/// with 2 slots (~800ms at 400ms block time) — long enough for libp2p
/// gossip to reach the whole 128-validator committee, short enough that
/// a censoring proposer can't hide behind latency.
const MEV_INCLUSION_GRACE_SLOTS: u64 = 2;

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
                let keys_json: Vec<serde_json::Value> = devnet_accounts
                    .iter()
                    .map(|acc| {
                        serde_json::json!({
                            "address": acc.address_hex(),
                            "privateKey": acc.private_key_hex(),
                            "balance": acc.balance.to_string(),
                        })
                    })
                    .collect();
                let _ = std::fs::write(
                    &keys_path,
                    serde_json::to_string_pretty(&keys_json).unwrap_or_default(),
                );

                config
            };

            // Auto-fund validator address with required stake for devnet
            if let Some(ref identity) = early_validator_identity {
                let val_addr = hex::encode(identity.address);
                let already_funded = genesis_config
                    .allocations
                    .iter()
                    .any(|a| a.address == val_addr);
                if !already_funded {
                    genesis_config
                        .allocations
                        .push(crate::genesis::GenesisAllocation {
                            address: val_addr.clone(),
                            balance: pyde_consensus::validator::VALIDATOR_STAKE.to_string(),
                            public_key: Some(hex::encode(identity.public_key.as_bytes())),
                            bucket: None,
                            vesting: None,
                        });
                    info!(
                        address = val_addr,
                        "auto-funded validator in genesis with 10,000 PYDE"
                    );
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

        // AOT JIT compilation cache (background Cranelift compilation)
        let aot_cache = Arc::new(crate::aot_cache::AotCache::new());

        // 3. Transaction relay / mempool + receipt store + pending tx queue
        let tx_relay = Arc::new(RwLock::new(TxRelay::new()));
        let receipts = Arc::new(RwLock::new(ReceiptStore::new()));
        // HashMap keyed by tx hash so `retain(|tx| !tx_hashes.contains(&tx.hash()))`
        // — which recomputed a Poseidon2 per entry per block-commit and
        // was quadratic under load — becomes O(|block|) remove loop.
        let pending_txs: Arc<
            RwLock<std::collections::HashMap<[u8; 32], pyde_tx::types::Transaction>>,
        > = Arc::new(RwLock::new(std::collections::HashMap::new()));

        // Parallel timestamp map for mempool TTL (MAINNET_PLAN M2).
        // Maintained alongside `pending_txs` on insert / remove; swept
        // periodically by the maintenance tick so a tx that never
        // commits (under sustained overload) doesn't live in memory
        // forever.
        let pending_tx_times: Arc<RwLock<std::collections::HashMap<[u8; 32], std::time::Instant>>> =
            Arc::new(RwLock::new(std::collections::HashMap::new()));

        // Mempool tx index for compact block reconstruction: tx_hash → wire-encoded bytes
        let mempool_index: Arc<RwLock<std::collections::HashMap<[u8; 32], Vec<u8>>>> =
            Arc::new(RwLock::new(std::collections::HashMap::new()));

        // Pending block decryptors: slot → BlockDecryptor (collecting shares for threshold decryption)
        let pending_decryptors: Arc<
            RwLock<std::collections::HashMap<u64, pyde_mempool::decryption::BlockDecryptor>>,
        > = Arc::new(RwLock::new(std::collections::HashMap::new()));

        // Queued decryption shares that arrived before the BlockDecryptor was created.
        // When a decryptor is created for a slot, queued shares are replayed into it.
        let queued_shares: Arc<
            RwLock<std::collections::HashMap<u64, Vec<wire::DecryptionShareMsg>>>,
        > = Arc::new(RwLock::new(std::collections::HashMap::new()));

        // Queued encrypted-tx bundles (audit item 207). Proposers publish an
        // EncryptedTxBundle alongside the compact block to deliver the
        // block's encrypted_txs to validators that don't already have them
        // in their local tx_relay. Keyed by (slot, block_hash) so the
        // matching compact block can find its bundle on arrival
        // regardless of which message reaches a given peer first.
        // Pruned in the maintenance tick alongside queued_shares.
        let queued_encrypted_bundles: Arc<
            RwLock<std::collections::HashMap<(u64, [u8; 32]), Vec<Vec<u8>>>>,
        > = Arc::new(RwLock::new(std::collections::HashMap::new()));

        // 4. Chain sync
        let mut chain_sync = ChainSync::new();
        chain_sync.manager.local_tip = chain.read().await.head_slot;
        let mut pinned_snapshot: Option<crate::sync::PinnedSnapshot> = None;

        // Peer tracking for task 029/030 FALCON attestation + consensus filter.
        // Sized generously — the mempool pool is 500K, validator mesh is 128
        // with gossipsub fan-out reaching ~30 peers in practice.
        let mut peer_manager = pyde_net::peer::PeerManager::new(
            /* max_peers */ 200, /* max_inbound */ 150, /* max_outbound */ 150,
            /* rate_limit_per_ip */ 10,
        );
        // Nonces we've sent out in outbound auth requests, keyed by peer.
        // Populated in `SendAuthRequest`, consumed when the matching
        // `PydeAuthResp` arrives.
        let mut pending_auth_nonces: std::collections::HashMap<libp2p::PeerId, [u8; 32]> =
            std::collections::HashMap::new();

        // Size of the committee that was in power at the last epoch boundary.
        // Feeds the `old_threshold` passed to `on_reshare_contribution` after
        // `engine.set_committee` has already advanced `engine.committee_keys`
        // to the incoming set. Initialized to 0 (no prior committee); the
        // first epoch boundary sets it.
        let mut last_outgoing_committee_size: usize = 0;

        // Audit 232: buffer for competing blocks at slots we've already
        // processed. Populated when a gossiped block fails the
        // `slot > head_slot` check but its hash differs from the block
        // we already committed at that slot — i.e. it's a competing
        // proposal under a multi-proposer race. When a QC later forms
        // for the competing hash (line ~2716 ConsensusMessage::Vote),
        // we look it up here and call `BlockProcessor::reorg_to_block`
        // to switch chains.
        //
        // Bounded to 64 entries (~64 slots × ~one competing block each).
        // The HotStuff multi-proposer race window is 100ms, so the
        // buffer typically holds at most 2-3 entries at any time.
        const COMPETING_BLOCK_CAP: usize = 64;
        let mut competing_blocks: std::collections::HashMap<
            (u64, [u8; 32]),
            pyde_consensus::block::Block,
        > = std::collections::HashMap::new();

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
                    let balance = state_guard
                        .get(&balance_key)
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
                    warn!(
                        "state is empty (genesis) — stake verification deferred until chain syncs"
                    );
                }
            }

            let mut engine = ValidatorEngine::new([0xAA; 32]); // devnet epoch randomness

            // Attach persistent ConsensusState store. If a prior state exists,
            // it is loaded here — this is what prevents last_voted_slot or
            // highest_qc from regressing after a validator crash/restart.
            match ConsensusStateStore::open(datadir) {
                Ok(store) => engine.attach_consensus_store(Arc::new(store)),
                Err(e) => warn!(
                    error = %e,
                    "failed to open consensus state store; running without crash-safe vote persistence"
                ),
            }

            // Slice 4.3 gap 2: install config-provided WS bootstrap anchor
            // if no on-disk checkpoint is present yet. Operators use this
            // to close the long-range-attack window for validators joining
            // an established network (genesis validators self-observe).
            if engine.finality.latest_checkpoint.is_none() {
                if let Some(bootstrap_slot) = self.config.consensus.initial_ws_checkpoint_slot {
                    engine.install_bootstrap_ws_anchor(bootstrap_slot);
                    info!(
                        bootstrap_slot,
                        "installed config-provided weak-subjectivity bootstrap anchor"
                    );
                }
            }

            // Build committee from genesis validators (if any).
            // If genesis has validators, use them all as the committee.
            // Otherwise fall back to single-validator mode (just self).
            let mut committee_keys: Vec<Vec<u8>> = Vec::new();
            let mut my_index: u8 = 0;
            let my_pk_hex = hex::encode(identity.public_key.as_bytes());

            if !genesis_config.validators.is_empty() {
                for (i, val) in genesis_config.validators.iter().enumerate() {
                    let pk_bytes = hex::decode(
                        val.public_key.strip_prefix("0x").unwrap_or(&val.public_key),
                    )
                    .map_err(|e| format!("invalid validator public key in genesis: {}", e))?;
                    if val.public_key == my_pk_hex || val.public_key == format!("0x{}", my_pk_hex) {
                        my_index = i as u8;
                    }
                    committee_keys.push(pk_bytes);
                }
                info!(
                    committee_size = committee_keys.len(),
                    my_index, "committee formed from genesis validators"
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

        // 8. Dial bootstrap peers. Empty on anything other than a single
        // isolated devnet node is almost certainly misconfiguration —
        // without peers the node produces a fork of one and can never
        // sync. Warn loudly so operators catch this before genesis
        // rather than after.
        if self.config.network.bootstrap_peers.is_empty() {
            if self.config.node.chain_id != 31337 {
                warn!(
                    chain_id = self.config.node.chain_id,
                    "no bootstrap_peers configured for a non-devnet chain — this node will not \
                     discover peers and cannot sync. Set network.bootstrap_peers in config.toml \
                     before launch."
                );
            }
        } else {
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
        let (tx_gossip_tx, mut tx_gossip_rx) =
            tokio::sync::mpsc::channel::<pyde_tx::types::Transaction>(1024);
        // Audit item 227 step 4 / option E: RPC ingress side of the
        // encrypted-tx gossip channel. After pyde_sendRawEncryptedTransaction
        // accepts a tx into the local tx_relay, the RPC handler also
        // pushes it here. The main loop forwards it to gossipsub on the
        // encrypted-tx topic so every validator's tx_relay ends up with
        // a copy — otherwise only the RPC-receiving node's proposer
        // could ever include the tx in a block.
        let (encrypted_tx_gossip_tx, mut encrypted_tx_gossip_rx) =
            tokio::sync::mpsc::channel::<pyde_mempool::encrypted::EncryptedTx>(1024);
        // WebSocket subscription broadcast channels (created even if RPC disabled — cheap no-op)
        let (new_heads_tx, _) = tokio::sync::broadcast::channel::<serde_json::Value>(256);
        let (pending_tx_tx, _) = tokio::sync::broadcast::channel::<String>(4096);
        let (logs_tx, _) = tokio::sync::broadcast::channel::<serde_json::Value>(1024);
        let ws_heads = new_heads_tx.clone();
        let ws_logs = logs_tx.clone();
        let ws_sub_heads = new_heads_tx.clone();
        let ws_sub_logs = logs_tx.clone();
        if self.config.rpc.enabled {
            let rpc_state = Arc::new(RpcState {
                chain: chain.clone(),
                state: state.clone(),
                tx_relay: tx_relay.clone(),
                receipts: receipts.clone(),
                pending_txs: pending_txs.clone(),
                pending_tx_times: pending_tx_times.clone(),
                threshold_pk: {
                    // Load threshold public key from disk (generated by testnet command)
                    let tpk_path = self.config.node.datadir.join("threshold.pk");
                    if tpk_path.exists() {
                        let tpk_bytes = std::fs::read(&tpk_path).ok();
                        tpk_bytes.and_then(|b| {
                            pyde_crypto::threshold::ThresholdPublicKey::from_bytes(&b)
                        })
                    } else {
                        None
                    }
                },
                new_heads_tx,
                pending_tx_tx,
                logs_tx,
                dev_mode: self.config.node.dev_mode,
                tx_gossip_tx: tx_gossip_tx.clone(),
                encrypted_tx_gossip_tx: encrypted_tx_gossip_tx.clone(),
            });
            match rpc::start_rpc_server(
                &self.config.rpc.listen,
                self.config.rpc.port,
                rpc_state,
                self.config.node.chain_id,
            )
            .await
            {
                Ok(addr) => info!(%addr, "JSON-RPC server started"),
                Err(e) => warn!("RPC server disabled: {}", e),
            }
        }

        // 11. Start dedicated WebSocket subscription server (port 8546)
        // Uses tokio-tungstenite directly for reliable subscription delivery.
        if self.config.rpc.enabled {
            let ws_port = self.config.rpc.port + 1; // 8546
            match crate::ws_sub::start_ws_server(
                &self.config.rpc.listen,
                ws_port,
                ws_sub_heads,
                ws_sub_logs,
            )
            .await
            {
                Ok(addr) => info!(%addr, "WebSocket subscription server started"),
                Err(e) => warn!("WS subscription server disabled: {}", e),
            }
        }

        // 12. Start fast binary TX endpoint (high-throughput alternative to HTTP RPC)
        if self.config.fast_tx.enabled {
            match crate::fast_tx::start_fast_tx_listener(
                &self.config.fast_tx.listen,
                self.config.fast_tx.port,
                pending_txs.clone(),
                pending_tx_times.clone(),
                tx_gossip_tx.clone(),
            )
            .await
            {
                Ok(addr) => info!(%addr, "fast binary TX endpoint started"),
                Err(e) => warn!("fast TX endpoint disabled: {}", e),
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

        // Slot clock for block timing. If resuming from persisted head,
        // backdate genesis so current_slot() picks up where we left off.
        // Block time comes from `[consensus].block_time_ms` (default
        // 400); `with_block_time` clamps out-of-range values.
        let block_time_ms = self.config.consensus.block_time_ms;
        let slot_clock = if saved_head > 0 {
            let backdate_ms = saved_head * block_time_ms;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            SlotClock::with_block_time(now_ms.saturating_sub(backdate_ms), block_time_ms)
        } else {
            SlotClock::with_block_time(0, block_time_ms)
        };
        let mut last_slot = slot_clock.current_slot();

        // Periodic timers
        let mut slot_interval = tokio::time::interval(std::time::Duration::from_millis(100)); // check slot every 100ms
        let mut maintenance_interval = tokio::time::interval(std::time::Duration::from_secs(10));
        let mut sync_interval = tokio::time::interval(std::time::Duration::from_secs(2));
        // Gossip retry: re-publish uncommitted pending txs every 2 slots.
        // Closes the window where gossipsub NoSubscribers / mesh churn /
        // subscription timing dropped the initial broadcast — without this,
        // a tx could sit in a single node's pending forever if its first
        // publish missed all peers. Capped to avoid re-publish bursts.
        let mut gossip_retry_interval =
            tokio::time::interval(std::time::Duration::from_millis(800));
        const GOSSIP_RETRY_MAX_TXS: usize = 1000;

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
                            &mut validator_identity,
                            &block_store,
                            &mut pinned_snapshot,
                            &mut peer_manager,
                            &mut pending_auth_nonces,
                            last_outgoing_committee_size,
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
                        PostEventAction::SendAuthRequest(peer) => {
                            // Generate a fresh nonce, record it, send the request.
                            // We only authenticate to peers once; if a response is
                            // already pending we skip to avoid stacking nonces.
                            if let std::collections::hash_map::Entry::Vacant(e) = pending_auth_nonces.entry(peer) {
                                let nonce = pyde_net::auth::generate_nonce();
                                e.insert(nonce);
                                let req = pyde_net::auth::PydeAuthReq { nonce };
                                let _ = swarm.behaviour_mut().auth.send_request(&peer, req);
                            }
                        }
                        PostEventAction::SendAuthResponse(channel, resp) => {
                            let _ = swarm.behaviour_mut().auth.send_response(channel, resp);
                        }
                        PostEventAction::ContinueSync => {
                            // If chunked snapshot in progress, request next chunk
                            if let Some(next_idx) = chain_sync.needs_next_chunk() {
                                let peer = swarm.connected_peers().next().copied();
                                if let Some(p) = peer {
                                    chain_sync.request_next_chunk(&mut swarm, p, next_idx);
                                }
                            } else {
                                chain_sync.request_next_batch(&mut swarm);
                            }
                        }
                        PostEventAction::BroadcastConsensus(data) => {
                            // Audit 218: publish-time guard. The
                            // consensus topic is validator-only on
                            // ingress (`Channel::Consensus.validator_only()`
                            // gates inbound at the libp2p layer). Add a
                            // matching egress check here so a future
                            // non-validator code path that constructs a
                            // BroadcastConsensus action can't slip a
                            // message onto the wire — belt-and-suspenders.
                            if !is_validator {
                                warn!(
                                    "non-validator attempted BroadcastConsensus; dropped (audit 218)"
                                );
                            } else {
                                let topic = pyde_net::node::topics::consensus();
                                if let Err(e) =
                                    swarm.behaviour_mut().gossipsub.publish(topic, data)
                                {
                                    warn!(error = %e, "failed to broadcast consensus message");
                                }
                            }
                        }
                        PostEventAction::BroadcastConsensusMany(messages) => {
                            if !is_validator {
                                warn!(
                                    count = messages.len(),
                                    "non-validator attempted BroadcastConsensusMany; dropped (audit 218)"
                                );
                            } else {
                                let topic = pyde_net::node::topics::consensus();
                                for data in messages {
                                    if let Err(e) = swarm
                                        .behaviour_mut()
                                        .gossipsub
                                        .publish(topic.clone(), data)
                                    {
                                        warn!(error = %e, "failed to broadcast consensus message");
                                    }
                                }
                            }
                        }
                        PostEventAction::AcceptTransaction(tx) => {
                            let tx_hash = tx.hash();
                            // Global cap (M3) + (sender, nonce) dedup (M6)
                            // on the gossip path too. Without these, a
                            // busy gossip mesh can push this node past
                            // its mempool budget or land a second-write
                            // variant for an already-pending (sender,
                            // nonce). Constants match rpc.rs — keep in
                            // sync if those change.
                            const GOSSIP_MEMPOOL_GLOBAL_CAP: usize = 100_000;
                            let mut pending = pending_txs.write().await;
                            if pending.len() >= GOSSIP_MEMPOOL_GLOBAL_CAP {
                                debug!(
                                    tx_hash = hex::encode(tx_hash),
                                    cap = GOSSIP_MEMPOOL_GLOBAL_CAP,
                                    "gossip tx dropped: mempool full"
                                );
                            } else if pending
                                .values()
                                .any(|t| t.from == tx.from && t.nonce == tx.nonce)
                            {
                                debug!(
                                    tx_hash = hex::encode(tx_hash),
                                    "gossip tx dropped: duplicate (sender, nonce)"
                                );
                            } else {
                                let tx_bytes = wire::encode_transaction(&tx);
                                mempool_index.write().await.insert(tx_hash, tx_bytes);
                                pending.insert(tx_hash, tx);
                                debug!(tx_hash = hex::encode(tx_hash), pending = pending.len(), "tx accepted from gossip");
                                drop(pending);
                                pending_tx_times
                                    .write()
                                    .await
                                    .insert(tx_hash, std::time::Instant::now());
                            }
                        }
                        PostEventAction::QcFormedFromGossip { slot } => {
                            // Audit item 227 step 4: QC just formed for
                            // `slot` via an incoming gossip vote — the
                            // original decrypt path at `select_and_vote`
                            // only triggered when our OWN vote closed the
                            // QC, which is rare in a 4+-node committee.
                            // Mirror that logic here so the decrypt flow
                            // starts regardless of which validator's vote
                            // was the one.
                            if !validator_identity
                                .as_ref()
                                .map(|id| id.key_share.is_some())
                                .unwrap_or(false)
                            {
                                continue;
                            }
                            // Already started decryption for this slot? Skip.
                            if pending_decryptors.read().await.contains_key(&slot) {
                                continue;
                            }
                            let block = match block_store.get_block_raw(slot)
                                .and_then(|b| wire::decode_block(&b).ok())
                            {
                                Some(b) => b,
                                None => continue,
                            };
                            if block.body.encrypted_txs.is_empty() {
                                continue;
                            }
                            let enc_txs: Vec<pyde_mempool::encrypted::EncryptedTx> = block
                                .body
                                .encrypted_txs
                                .iter()
                                .filter_map(|b| pyde_mempool::encrypted::EncryptedTx::from_bytes(b))
                                .collect();
                            let tx_root_ok = crate::block_processor::verify_decryptor_against_committed_root(
                                &block.header.tx_root,
                                &block.body.transactions,
                                &enc_txs,
                            );
                            if !tx_root_ok {
                                error!(slot, "decrypt-time tx_root mismatch");
                                continue;
                            }
                            let engine = match validator_engine.as_mut() {
                                Some(e) => e,
                                None => continue,
                            };
                            let threshold = pyde_consensus::block::quorum_for_committee(
                                engine.committee_keys.len(),
                            );
                            let identity = validator_identity.as_ref().unwrap();
                            if let Ok(mut decryptor) =
                                pyde_mempool::decryption::BlockDecryptor::new(
                                    enc_txs.clone(),
                                    threshold,
                                )
                            {
                                if let Some(ks) = &identity.key_share {
                                    decryptor.add_member_shares(ks);
                                }
                                // Replay any shares that arrived before
                                // the decryptor existed.
                                {
                                    let mut q = queued_shares.write().await;
                                    if let Some(queued) = q.remove(&slot) {
                                        for qmsg in &queued {
                                            for (i, sb) in qmsg.shares.iter().enumerate() {
                                                if let Some(s) = pyde_crypto::threshold::DecryptionShare::from_bytes(sb) {
                                                    decryptor.add_share(i, s);
                                                }
                                            }
                                        }
                                    }
                                }
                                pending_decryptors
                                    .write()
                                    .await
                                    .insert(slot, decryptor);
                            }
                            // Broadcast our own decryption shares on the
                            // consensus topic.
                            if let Some(shares) =
                                engine.generate_decryption_shares(identity, &enc_txs)
                            {
                                let msg = wire::DecryptionShareMsg {
                                    slot,
                                    member_index: identity.committee_index,
                                    shares: shares.iter().map(|s| s.to_bytes()).collect(),
                                };
                                let share_bytes = wire::encode_decryption_shares(&msg);
                                let topic = pyde_net::node::topics::consensus();
                                let _ = swarm
                                    .behaviour_mut()
                                    .gossipsub
                                    .publish(topic, share_bytes);
                                info!(
                                    slot,
                                    enc_txs = enc_txs.len(),
                                    "broadcast decryption shares (gossip-QC)"
                                );
                            }
                        }
                        PostEventAction::BufferCompetingBlock(block) => {
                            // Audit 232: a competing block at our head slot
                            // was just received. Buffer it keyed by
                            // (slot, block_hash) so a later QC for that
                            // hash can pull it out and trigger reorg.
                            let key = (block.header.slot, block.header.hash());
                            // Cap eviction: HashMap-iteration-order victim.
                            // Acceptable because (a) cap is small, (b) the
                            // only blocks that matter are ones a future QC
                            // will pull, and a QC for a long-evicted block
                            // is recoverable via sync. Deterministic LRU
                            // would be nicer but adds dependencies.
                            if competing_blocks.len() >= COMPETING_BLOCK_CAP
                                && !competing_blocks.contains_key(&key)
                            {
                                if let Some(victim_key) = competing_blocks.keys().next().copied() {
                                    competing_blocks.remove(&victim_key);
                                }
                            }
                            competing_blocks.insert(key, block);
                        }
                        PostEventAction::TryReorgToQc {
                            qc_slot,
                            qc_block_hash,
                        } => {
                            // Audit 232: a QC formed for `qc_block_hash` at
                            // `qc_slot`, but our local view at that slot is
                            // a different block. Try to reorg via the
                            // buffered-competing-block path. Whether or not
                            // the reorg fires, we still need to trigger the
                            // existing post-QC decrypt pipeline (audit 227)
                            // — so this handler does BOTH reorg + decrypt
                            // dispatch, by re-emitting QcFormedFromGossip
                            // at the end via the channel-style fallthrough
                            // inside the match.
                            let key = (qc_slot, qc_block_hash);
                            if let Some(target) = competing_blocks.remove(&key) {
                                let mut chain_w = chain.write().await;
                                let mut state_w = state.write().await;
                                let ws_slot = validator_engine.as_ref().and_then(|e| {
                                    e.finality.latest_checkpoint.as_ref().map(|cp| cp.slot)
                                });
                                match BlockProcessor::reorg_to_block(
                                    &mut chain_w,
                                    &mut state_w,
                                    &target,
                                    Some(&aot_cache),
                                    ws_slot,
                                ) {
                                    Ok((tx_count, gas_used, _)) => {
                                        let _ = state_w.flush_pending();
                                        state_w.refresh_root();
                                        crate::metrics::record_reorg(
                                            crate::metrics::ReorgOutcome::Succeeded,
                                        );
                                        info!(
                                            qc_slot,
                                            tx_count,
                                            gas_used,
                                            "reorg succeeded — chain now matches QC"
                                        );
                                    }
                                    Err(e) => {
                                        crate::metrics::record_reorg(
                                            crate::metrics::ReorgOutcome::Failed,
                                        );
                                        warn!(qc_slot, error = %e, "reorg failed");
                                    }
                                }
                            } else {
                                // No buffered block. Sync will recover the
                                // canonical block on its next pass; the
                                // local view stays inconsistent until then.
                                // Still proceed to decrypt below — if our
                                // local block at qc_slot has different
                                // encrypted_txs from the QC'd block, the
                                // tx_root check inside the decrypt path
                                // will fail and we'll skip safely.
                                crate::metrics::record_reorg(
                                    crate::metrics::ReorgOutcome::TargetNotBuffered,
                                );
                                warn!(
                                    qc_slot,
                                    qc_hash = hex::encode(qc_block_hash),
                                    "QC mismatch but competing block not buffered — sync will recover"
                                );
                            }
                            // Re-dispatch as QcFormedFromGossip so the
                            // existing decrypt pipeline still fires for
                            // qc_slot (audit 227 dependency).
                            // Manually run the same logic since we can't
                            // re-invoke the match arm directly.
                            let slot = qc_slot;
                            // BEGIN copy of QcFormedFromGossip body
                            // (kept inline rather than extracted because
                            // the body captures many local mutable refs;
                            // refactor to a closure after both call sites
                            // settle).
                            if !validator_identity
                                .as_ref()
                                .map(|id| id.key_share.is_some())
                                .unwrap_or(false)
                            {
                                continue;
                            }
                            if pending_decryptors.read().await.contains_key(&slot) {
                                continue;
                            }
                            let block = match block_store
                                .get_block_raw(slot)
                                .and_then(|b| wire::decode_block(&b).ok())
                            {
                                Some(b) => b,
                                None => continue,
                            };
                            if block.body.encrypted_txs.is_empty() {
                                continue;
                            }
                            let enc_txs: Vec<pyde_mempool::encrypted::EncryptedTx> = block
                                .body
                                .encrypted_txs
                                .iter()
                                .filter_map(|b| pyde_mempool::encrypted::EncryptedTx::from_bytes(b))
                                .collect();
                            let tx_root_ok =
                                crate::block_processor::verify_decryptor_against_committed_root(
                                    &block.header.tx_root,
                                    &block.body.transactions,
                                    &enc_txs,
                                );
                            if !tx_root_ok {
                                error!(slot, "decrypt-time tx_root mismatch (post-reorg)");
                                continue;
                            }
                            let engine = match validator_engine.as_mut() {
                                Some(e) => e,
                                None => continue,
                            };
                            let threshold = pyde_consensus::block::quorum_for_committee(
                                engine.committee_keys.len(),
                            );
                            let identity = validator_identity.as_ref().unwrap();
                            if let Ok(mut decryptor) = pyde_mempool::decryption::BlockDecryptor::new(
                                enc_txs.clone(),
                                threshold,
                            ) {
                                if let Some(ks) = &identity.key_share {
                                    decryptor.add_member_shares(ks);
                                }
                                {
                                    let mut q = queued_shares.write().await;
                                    if let Some(queued) = q.remove(&slot) {
                                        for qmsg in &queued {
                                            for (i, sb) in qmsg.shares.iter().enumerate() {
                                                if let Some(s) = pyde_crypto::threshold::DecryptionShare::from_bytes(sb) {
                                                    decryptor.add_share(i, s);
                                                }
                                            }
                                        }
                                    }
                                }
                                pending_decryptors.write().await.insert(slot, decryptor);
                            }
                            if let Some(shares) =
                                engine.generate_decryption_shares(identity, &enc_txs)
                            {
                                let msg = wire::DecryptionShareMsg {
                                    slot,
                                    member_index: identity.committee_index,
                                    shares: shares.iter().map(|s| s.to_bytes()).collect(),
                                };
                                let share_bytes = wire::encode_decryption_shares(&msg);
                                let topic = pyde_net::node::topics::consensus();
                                let _ = swarm
                                    .behaviour_mut()
                                    .gossipsub
                                    .publish(topic, share_bytes);
                                info!(
                                    slot,
                                    enc_txs = enc_txs.len(),
                                    "broadcast decryption shares (post-reorg-QC)"
                                );
                            }
                            // END copy of QcFormedFromGossip body
                        }
                        PostEventAction::AcceptEncryptedTransaction(enc_tx) => {
                            // Audit item 227 step 4 / option E: inbound
                            // from the encrypted-transactions gossip topic.
                            // Route through the same ingress policy as the
                            // RPC path so mainnet still enforces registered
                            // auth_keys while devnet keeps the structural-
                            // only fall-through.
                            let from = enc_tx.sender;
                            let tx_hash = enc_tx.hash();
                            let sender_pk_opt = {
                                let state_r = state.read().await;
                                let sender_key = pyde_state::keys::balance_key(&from);
                                state_r
                                    .get(&sender_key)
                                    .and_then(|b| pyde_account::types::Account::from_bytes(&b))
                                    .and_then(|acct| match acct.auth_keys {
                                        pyde_account::types::AuthKeys::Single(pk) => Some(pk),
                                        _ => None,
                                    })
                            };
                            let chain_id = chain.read().await.chain_id;
                            let mut relay = tx_relay.write().await;
                            let accepted = match (sender_pk_opt, chain_id) {
                                (Some(pk), _) => relay.receive_tx_verified(enc_tx, &pk),
                                (None, 31337) => relay.receive_tx(enc_tx),
                                (None, _) => {
                                    debug!(
                                        tx_hash = hex::encode(tx_hash),
                                        "dropped encrypted gossip tx: sender has no registered auth_key"
                                    );
                                    false
                                }
                            };
                            if accepted {
                                debug!(
                                    tx_hash = hex::encode(tx_hash),
                                    "encrypted tx accepted from gossip"
                                );
                            }
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
                            let block_hash = header.hash();

                            // Build mempool snapshot for reconstruction (plaintext + encrypted)
                            let idx = mempool_index.read().await;
                            let mut mempool_txs: Vec<([u8; 32], Vec<u8>)> = idx.iter()
                                .map(|(h, b)| (*h, b.clone()))
                                .collect();
                            drop(idx);

                            // Also include encrypted txs from TxRelay
                            {
                                let relay_r = tx_relay.read().await;
                                for etx in relay_r.mempool().iter_txs() {
                                    let hash = etx.hash();
                                    let bytes = etx.to_bytes();
                                    mempool_txs.push((hash, bytes));
                                }
                            }

                            // Audit item 207: pull encrypted_txs from any
                            // queued bundle for this (slot, block_hash). The
                            // proposer published the bundle alongside the
                            // compact block exactly so non-proposer validators
                            // that don't have the txs in local tx_relay can
                            // still reconstruct. Remove the entry (single-use)
                            // to keep the queue bounded. Integrity is checked
                            // downstream by `verify_tx_root` inside
                            // `BlockProcessor::process_full_block_with_aot_and_checkpoint`
                            // (block_processor.rs:622), so a bundle whose
                            // entries don't match the block header's tx_root
                            // will fail block validation without extra logic
                            // here.
                            {
                                let mut qb = queued_encrypted_bundles.write().await;
                                if let Some(bundle_txs) = qb.remove(&(slot, block_hash)) {
                                    for bytes in bundle_txs {
                                        if let Some(etx) = pyde_mempool::encrypted::EncryptedTx::from_bytes(&bytes) {
                                            mempool_txs.push((etx.hash(), bytes));
                                        }
                                    }
                                    debug!(
                                        slot,
                                        "reassembled compact block using queued encrypted-tx bundle"
                                    );
                                }
                            }

                            let (matched, missing) = cb.reconstruct(&mempool_txs);

                            if !missing.is_empty() {
                                // Can't fully reconstruct — request full block via sync.
                                // Update network tip so sync manager knows to fetch this slot.
                                debug!(
                                    slot,
                                    missing = missing.len(),
                                    "compact block missing txs — triggering sync for full block"
                                );
                                chain_sync.manager.update_network_tip(slot);
                                chain_sync.request_next_batch(&mut swarm);
                                continue;
                            }

                            // All txs found — separate into plaintext and encrypted
                            let mut transactions = Vec::new();
                            let mut encrypted_txs = Vec::new();
                            for (i, tx_bytes_opt) in matched.iter().enumerate() {
                                let tx_bytes = tx_bytes_opt.as_ref().unwrap();
                                // Try plaintext first, then encrypted
                                if let Ok(tx) = wire::decode_transaction(tx_bytes) {
                                    transactions.push(tx);
                                } else if pyde_mempool::encrypted::EncryptedTx::from_bytes(tx_bytes).is_some() {
                                    encrypted_txs.push(tx_bytes.clone());
                                } else {
                                    warn!(slot, tx_idx = i, "failed to decode reconstructed tx");
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
                                    encrypted_txs,
                                    execution_schedule: exec_schedule,
                                },
                                proposer_signature: vec![], // not in compact block, validated via proposal
                            };

                            // Task 026: mandatory-inclusion audit. Compare the block's
                            // encrypted_tx set against our local mempool view. If the
                            // proposer skipped a tx we've held past the grace window
                            // while gas budget remained, flag the slot so the later
                            // select_and_vote call abstains. Enforcement is soft —
                            // HotStuff tolerates 1/128 dissent; false positives under
                            // network jitter only cost liveness on the affected slot.
                            if let Some(engine) = validator_engine.as_mut() {
                                let relay_r = tx_relay.read().await;
                                let audit = pyde_mempool::inclusion::audit_block_inclusion(
                                    &block.body.encrypted_txs,
                                    relay_r.mempool().view_with_slots(),
                                    slot,
                                    MEV_INCLUSION_GRACE_SLOTS,
                                    self.config.consensus.gas_ceiling,
                                );
                                drop(relay_r);
                                if !audit.is_clean() {
                                    warn!(
                                        slot,
                                        missing = audit.missing_older_than_grace.len(),
                                        gas_remaining = audit.gas_remaining,
                                        "mandatory-inclusion audit failed — skipping vote for this slot"
                                    );
                                    engine.flag_inclusion_violation(slot);
                                }
                            }

                            // Validate and process with WS checkpoint (slice 4.3).
                            {
                                let mut chain_w = chain.write().await;
                                let mut state_w = state.write().await;
                                let ws_slot = validator_engine
                                    .as_ref()
                                    .and_then(|e| e.finality.latest_checkpoint.as_ref().map(|cp| cp.slot));
                                match BlockProcessor::process_full_block_with_aot_and_checkpoint(&mut chain_w, &mut state_w, &block, Some(&aot_cache), ws_slot) {
                                    Ok((tc, gas, ref receipts_list)) => {
                                        // PIPELINED: extract writes + SMT handle, release lock
                                        let pending = state_w.take_pending_writes();
                                        let smt_handle = state_w.smt_handle();
                                        drop(state_w);
                                        drop(chain_w);

                                        // Spawn background Merkle commit — doesn't hold state lock
                                        if !pending.is_empty() {
                                            let state_for_root = state.clone();
                                            tokio::spawn(async move {
                                                // SMT mutex is separate from the state RwLock.
                                                // Audit 222: time the commit so operators can
                                                // alert on SMT/RocksDB pressure independent of
                                                // pyde_block_processing_ms.
                                                let commit_start = std::time::Instant::now();
                                                if let Ok(root) = crate::state_manager::StateManager::commit_writes_to_smt(&smt_handle, pending) {
                                                    crate::metrics::record_state_commit_ms(
                                                        commit_start.elapsed().as_millis() as u64,
                                                    );
                                                    // Update cached root (brief write lock)
                                                    if let Ok(mut sw) = state_for_root.try_write() {
                                                        sw.set_root(root);
                                                    }
                                                }
                                            });
                                        }

                                        let full_bytes = wire::encode_block(&block);
                                        let _ = block_store.put_block(&block.header, &full_bytes);
                                        let _ = block_store.put_head(slot);
                                        chain_sync.on_block_processed(slot);
                                        if !receipts_list.is_empty() {
                                            let mut receipts_w = receipts.write().await;
                                            receipts_w.insert_block_receipts(slot, receipts_list.clone());
                                        }
                                        let tx_hashes: Vec<[u8; 32]> = block.body.transactions.iter()
                                            .map(|tx| tx.hash()).collect();
                                        {
                                            let mut idx = mempool_index.write().await;
                                            for h in &tx_hashes { idx.remove(h); }
                                        }
                                        {
                                            let mut pending_w = pending_txs.write().await;
                                            for h in &tx_hashes {
                                                pending_w.remove(h);
                                            }
                                        }
                                        {
                                            let mut times_w = pending_tx_times.write().await;
                                            for h in &tx_hashes {
                                                times_w.remove(h);
                                            }
                                        }
                                        // Audit item 227 step 4: clear encrypted txs from
                                        // the local tx_relay once the block committing
                                        // them has been fully processed. The self-propose
                                        // path deliberately does NOT do this — self-proposals
                                        // can lose the multi-proposer VRF lottery, and
                                        // removing on self-propose would permanently drop
                                        // the tx even when a different validator's block
                                        // wins the slot. Doing it here, after the block
                                        // has actually been QC'd and processed, matches
                                        // the P7a-2 plaintext fix.
                                        if !block.body.encrypted_txs.is_empty() {
                                            let enc_hashes: Vec<[u8; 32]> = block.body.encrypted_txs.iter()
                                                .filter_map(|b| pyde_mempool::encrypted::EncryptedTx::from_bytes(b))
                                                .map(|etx| etx.hash())
                                                .collect();
                                            if !enc_hashes.is_empty() {
                                                let mut relay_w = tx_relay.write().await;
                                                relay_w.remove_included(&enc_hashes);
                                            }
                                        }
                                        info!(
                                            slot,
                                            txs = tc,
                                            encrypted = block.body.encrypted_txs.len(),
                                            gas,
                                            "compact block reconstructed and processed"
                                        );
                                    }
                                    Err(e) => {
                                        debug!(slot, error = %e, "compact block rejected");
                                    }
                                }
                            }
                        }
                        PostEventAction::BlockProcessed { slot, receipts: receipts_list, tx_hashes } => {
                            if !receipts_list.is_empty() {
                                let mut receipts_w = receipts.write().await;
                                receipts_w.insert_block_receipts(slot, receipts_list);
                            }
                            if !tx_hashes.is_empty() {
                                let mut pending_w = pending_txs.write().await;
                                for h in &tx_hashes {
                                    pending_w.remove(h);
                                }
                                drop(pending_w);
                                let mut times_w = pending_tx_times.write().await;
                                for h in &tx_hashes {
                                    times_w.remove(h);
                                }
                            }
                        }
                        PostEventAction::BufferEncryptedBundle(bundle) => {
                            // Drop stale bundles so the queue can't grow
                            // unboundedly under adversarial / noisy gossip.
                            // 100 slots matches the queued_shares window.
                            let head = chain.read().await.head_slot;
                            if bundle.slot + 100 < head {
                                debug!(
                                    slot = bundle.slot,
                                    head,
                                    "dropping stale encrypted-tx bundle"
                                );
                                continue;
                            }
                            let key = (bundle.slot, bundle.block_hash);
                            let txs_count = bundle.encrypted_txs.len();
                            let mut qb = queued_encrypted_bundles.write().await;
                            qb.insert(key, bundle.encrypted_txs);
                            debug!(
                                slot = bundle.slot,
                                encrypted_txs = txs_count,
                                "buffered encrypted-tx bundle"
                            );
                        }
                        PostEventAction::AddDecryptionShares(msg) => {
                            let slot = msg.slot;
                            let mut dec_w = pending_decryptors.write().await;
                            if let Some(decryptor) = dec_w.get_mut(&slot) {
                                // Decryptor exists — feed shares directly
                                // Feed each share to the decryptor
                                for (i, share_bytes) in msg.shares.iter().enumerate() {
                                    if let Some(share) = pyde_crypto::threshold::DecryptionShare::from_bytes(share_bytes) {
                                        decryptor.add_share(i, share);
                                    }
                                }

                                // Check if threshold reached → decrypt + execute
                                if decryptor.all_ready() {
                                    let chain_w = chain.read().await;
                                    let base_fee = chain_w.base_fee;
                                    let chain_id = chain_w.chain_id;
                                    drop(chain_w);
                                    let proposer = block_store.get_header(slot)
                                        .map(|h| h.proposer).unwrap_or([0u8; 32]);
                                    let mut state_w = state.write().await;
                                    let outcome = crate::block_processor::try_decrypt_and_execute(
                                        &block_store,
                                        slot,
                                        decryptor,
                                        &mut state_w,
                                        self.config.consensus.gas_ceiling,
                                        base_fee,
                                        chain_id,
                                        proposer,
                                    );
                                    drop(state_w);
                                    match outcome {
                                        crate::block_processor::DecryptOutcome::Executed { tx_count, receipts: slot_receipts } => {
                                            info!(slot, txs = tx_count, "threshold reached — decrypted + executed");
                                            if !slot_receipts.is_empty() {
                                                let mut receipts_w = receipts.write().await;
                                                receipts_w.insert_block_receipts(slot, slot_receipts);
                                            }
                                        }
                                        crate::block_processor::DecryptOutcome::TxRootMismatch => {
                                            error!(slot, "decrypt-time tx_root mismatch — dropped decryptor without executing");
                                        }
                                        crate::block_processor::DecryptOutcome::HeaderMissing => {
                                            warn!(slot, "block header missing at decrypt time");
                                        }
                                        crate::block_processor::DecryptOutcome::DecryptFailed(e) => {
                                            warn!(slot, error = %e, "decryption failed");
                                        }
                                    }
                                    dec_w.remove(&slot);
                                }
                            } else {
                                // No decryptor yet — queue shares for later replay
                                drop(dec_w);
                                let mut q = queued_shares.write().await;
                                q.entry(slot).or_default().push(msg);
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
                            let prev_epoch = engine.consensus.current_slot / pyde_consensus::block::EPOCH_LENGTH;
                            // Sync engine slot to clock (not just +1)
                            while engine.consensus.current_slot < current_slot {
                                engine.advance_slot();
                            }

                            // Task 034: re-broadcast our resharing contribution
                            // while we're inside the `RESHARE_REBROADCAST_SLOTS`
                            // window. Gossipsub's own message cache covers only
                            // a few heartbeats; this helps validators that come
                            // online a few slots into the target epoch catch up
                            // without needing a dedicated sync protocol.
                            if let Some((target_epoch, bytes)) = engine.maybe_rebroadcast_reshare() {
                                if !is_validator {
                                    warn!(
                                        "non-validator attempted reshare rebroadcast; dropped (audit 218)"
                                    );
                                } else {
                                    let msg = wire::encode_resharing(target_epoch, &bytes);
                                    let topic = pyde_net::node::topics::consensus();
                                    let _ = swarm.behaviour_mut().gossipsub.publish(topic, msg);
                                    debug!(target_epoch, "re-broadcast resharing contribution");
                                }
                            }

                            // Task 034: deterministic aggregation trigger. We
                            // deliberately DON'T aggregate on first-threshold
                            // arrival because async gossip can deliver a
                            // different pool subset to different new members,
                            // causing them to derive shares on divergent
                            // polynomials. Instead, every new member waits
                            // `RESHARE_AGGREGATION_DELAY_SLOTS` past the
                            // epoch boundary and aggregates from whatever is
                            // in the pool — by then gossipsub has converged.
                            if let Some(identity) = validator_identity.as_mut() {
                                engine.try_aggregate_reshare_on_slot(
                                    current_slot,
                                    last_outgoing_committee_size,
                                    identity,
                                );
                            }

                            // Epoch boundary: rotate committee
                            let new_epoch = current_slot / pyde_consensus::block::EPOCH_LENGTH;
                            if new_epoch > prev_epoch && new_epoch > 0 {
                                // Process unbonding: return stake for validators whose
                                // unbonding period has expired (14 days / 3,024,000 blocks)
                                {
                                    let mut state_w = state.write().await;
                                    crate::validator::process_unbonding(
                                        &mut state_w, current_slot,
                                    );
                                }

                                let state_r = state.read().await;
                                let val_set = crate::validator::load_validator_set_from_state(
                                    &state_r, &genesis_config,
                                );
                                drop(state_r);

                                match val_set.select_committee(
                                    new_epoch,
                                    &engine.epoch_randomness,
                                    vec![], // no threshold PK yet
                                ) {
                                    Ok(committee) => {
                                        let new_keys: Vec<Vec<u8>> = committee.members.iter()
                                            .map(|v| v.public_key.clone()).collect();

                                        // Snapshot the OLD committee BEFORE any rotation — task
                                        // 034 resharing needs to know who's outgoing to compute
                                        // the old_threshold we accept contributions against.
                                        let old_committee_keys = engine.committee_keys.clone();
                                        let was_in_old_committee =
                                            if let Some(identity) = validator_identity.as_ref() {
                                                old_committee_keys
                                                    .iter()
                                                    .any(|k| k.as_slice() == identity.public_key.as_bytes())
                                            } else { false };

                                        // Find our own index in the new committee. Zero means
                                        // we're leaving; non-zero means we'll aggregate
                                        // incoming resharing contributions.
                                        let mut our_new_index: usize = 0;
                                        if let Some(identity) = validator_identity.as_mut() {
                                            let my_pk = hex::encode(identity.public_key.as_bytes());
                                            for (i, member) in committee.members.iter().enumerate() {
                                                if hex::encode(&member.public_key) == my_pk {
                                                    identity.committee_index = i as u8;
                                                    our_new_index = i + 1; // 1-based for KeyShare
                                                    break;
                                                }
                                            }
                                        }
                                        engine.set_committee(new_keys.clone());
                                        info!(
                                            epoch = new_epoch,
                                            committee_size = committee.size(),
                                            "committee rotated at epoch boundary"
                                        );

                                        // Prepare to aggregate resharing contributions when we're
                                        // on the incoming committee. Safe to call even with
                                        // our_new_index = 0 — the engine will drop contributions.
                                        engine.prepare_for_reshare_reception(
                                            new_epoch,
                                            new_keys.clone(),
                                            our_new_index,
                                        );

                                        if let Some(identity) = validator_identity.as_ref() {
                                            // Generate and broadcast epoch randomness share
                                            if let Some(share) = engine.start_epoch_randomness(new_epoch + 1, identity) {
                                                let share_bytes = wire::encode_randomness_share(new_epoch + 1, &share);
                                                let topic = pyde_net::node::topics::consensus();
                                                let _ = swarm.behaviour_mut().gossipsub.publish(topic, share_bytes);
                                            }

                                            // Generate and broadcast PSS refresh contribution
                                            // (rotates threshold key shares so genesis trust dissolves)
                                            if let Some(contrib) = engine.start_pss_refresh(new_epoch + 1, identity) {
                                                let contrib_bytes = wire::encode_pss_refresh(new_epoch + 1, &contrib.to_bytes());
                                                let topic = pyde_net::node::topics::consensus();
                                                let _ = swarm.behaviour_mut().gossipsub.publish(topic, contrib_bytes);
                                            }

                                            // Task 034: if we were in the outgoing committee and
                                            // actually hold a key share, broadcast a resharing
                                            // contribution so the incoming committee can derive
                                            // its shares of the invariant threshold secret.
                                            // Same-committee-continuation also runs through this
                                            // path so the bookkeeping stays uniform.
                                            if was_in_old_committee && identity.key_share.is_some() {
                                                if let Some(contrib) = engine.start_committee_reshare(
                                                    new_epoch, &new_keys, identity,
                                                ) {
                                                    let contrib_bytes = wire::encode_resharing(
                                                        new_epoch, &contrib.to_bytes(),
                                                    );
                                                    let topic = pyde_net::node::topics::consensus();
                                                    let _ = swarm.behaviour_mut().gossipsub.publish(topic, contrib_bytes);
                                                }
                                            }
                                        }

                                        // Stash old committee size for inbound resharing
                                        // handlers — ingestion needs old_threshold to decide
                                        // when the canonical subset is reachable.
                                        last_outgoing_committee_size = old_committee_keys.len();
                                    }
                                    Err(e) => {
                                        warn!(epoch = new_epoch, error = ?e, "committee selection failed, keeping current");
                                    }
                                }
                            }

                            // Skip if chain head is already at or past this slot
                            let chain_head = chain.read().await.head_slot;
                            if current_slot <= chain_head {
                                // Already processed this slot
                            } else if let Some(identity) = validator_identity.as_ref() {
                                // Check if we're the proposer
                                if let Some(candidate) = engine.check_proposer(identity) {
                                    // Build fair transaction list by CLONING from the mempool,
                                    // NOT draining. Previously the proposer did `pending.drain()`
                                    // — if our proposal lost the multi-proposer VRF lottery,
                                    // the drained txs were neither in `pending` nor in the
                                    // committed block, so they vanished until re-gossipped.
                                    // Under concentrated RPC load (e.g. loadgen hitting one
                                    // node), gossip can't spread the tx fast enough across
                                    // the 400 ms slot, so the tx would be lost permanently.
                                    // Cloning is cheap relative to the block-assembly work
                                    // it feeds, and the block-commit retain path already
                                    // removes committed tx hashes from the mempool, so the
                                    // only txs kept are the ones that didn't make this
                                    // block.
                                    let slot_t0 = std::time::Instant::now();
                                    let t_clone = std::time::Instant::now();
                                    let pending_r = pending_txs.read().await;
                                    let all_pending: Vec<pyde_tx::types::Transaction> =
                                        pending_r.values().cloned().collect();
                                    let pending_len = pending_r.len();
                                    drop(pending_r);
                                    let clone_ms = t_clone.elapsed().as_secs_f64() * 1000.0;

                                    let t_build = std::time::Instant::now();
                                    let gas_ceiling = self.config.consensus.gas_ceiling;
                                    let (mut txs, _remaining) =
                                        crate::block_builder::build_tx_list(all_pending, gas_ceiling);
                                    let build_ms = t_build.elapsed().as_secs_f64() * 1000.0;

                                    // Drain any queued double-sign evidence into Slash txs and
                                    // prepend them to the block. This is the detection → punishment
                                    // link: without it, `pending_evidence` would accumulate forever
                                    // with no on-chain effect.
                                    if !engine.pending_evidence.is_empty() {
                                        let state_r = state.read().await;
                                        let base_nonce = pyde_tx::pipeline::load_nonce(
                                            &*state_r,
                                            &identity.address,
                                        ).base;
                                        drop(state_r);
                                        let mut slash_txs: Vec<pyde_tx::types::Transaction> = Vec::new();
                                        let _ = engine.drain_evidence_into_slash_txs(
                                            identity,
                                            base_nonce,
                                            self.config.node.chain_id,
                                            &mut slash_txs,
                                        );
                                        if !slash_txs.is_empty() {
                                            tracing::info!(
                                                count = slash_txs.len(),
                                                "prepending slash txs to block proposal"
                                            );
                                            // Slash txs go first so they execute before any
                                            // tx that might depend on the offender's stake
                                            // (e.g. a self-Withdraw racing the slash).
                                            slash_txs.extend(txs);
                                            txs = slash_txs;
                                        }
                                    }

                                    // Also collect encrypted txs from the threshold-encrypted mempool
                                    let encrypted_blobs = {
                                        let relay_r = tx_relay.read().await;
                                        let selected = relay_r.mempool().select_for_block(
                                            gas_ceiling, current_slot,
                                        );
                                        // Serialize each EncryptedTx to bytes for block inclusion
                                        selected.iter().map(|etx| etx.to_bytes()).collect::<Vec<Vec<u8>>>()
                                    };

                                    // Always produce blocks to advance the chain.
                                    // Empty blocks are needed for QC chain progression.
                                    {
                                    let _tx_count = txs.len();

                                    // Build block with transactions
                                    let chain_r = chain.read().await;
                                    let parent_hash = chain_r.state_root;
                                    let _head = chain_r.head_slot;
                                    drop(chain_r);

                                    // Auto-infer access lists for parallel scheduling.
                                    // Only run when there are enough txs to benefit from parallelism
                                    // AND enough CPU headroom (infer cost = ~1 simulation per contract call).
                                    // On small blocks or resource-constrained nodes, the sequential path
                                    // is faster than infer + parallel.
                                    if txs.len() >= 100 {
                                        let state_r = state.read().await;
                                        let infer_ctx = pyde_tx::pipeline::BlockContext {
                                            height: current_slot,
                                            timestamp: slot_clock.slot_timestamp(current_slot),
                                            base_fee: chain.read().await.base_fee,
                                            block_gas_limit: gas_ceiling,
                                            chain_id: self.config.node.chain_id,
                                            validator_address: identity.address,
                                            dev_skip_signature: false,
                                            block_sigs_pre_verified: false,
                                        };
                                        pyde_tx::access_infer::infer_access_lists_batch(
                                            &mut txs, &*state_r, &infer_ctx,
                                        );
                                    }

                                    // Build execution schedule: group non-conflicting txs
                                    // for parallel execution (Sealevel-style).
                                    let exec_schedule = pyde_tx::parallel::schedule(&txs);

                                    // Compute tx root over BOTH plaintext and encrypted txs.
                                    // Including encrypted tx hashes is what closes proposer
                                    // front-running: without it, a proposer could reorder
                                    // encrypted_txs after decryption without changing the
                                    // block hash. See `compute_tx_root` for the rationale.
                                    let encrypted_tx_hashes: Vec<[u8; 32]> = encrypted_blobs
                                        .iter()
                                        .filter_map(|b| pyde_mempool::encrypted::EncryptedTx::from_bytes(b))
                                        .map(|etx| etx.hash())
                                        .collect();
                                    let tx_root = pyde_consensus::block::compute_tx_root(
                                        &txs,
                                        &encrypted_tx_hashes,
                                    );

                                    // Encode VRF data as [output:32 || proof:N] so verifiers
                                    // can check both the score and the proof validity.
                                    let mut vrf_data = Vec::with_capacity(32 + candidate.vrf_proof.as_bytes().len());
                                    vrf_data.extend_from_slice(candidate.vrf_output.as_bytes());
                                    vrf_data.extend_from_slice(candidate.vrf_proof.as_bytes());

                                    let block = engine.build_proposal(
                                        identity,
                                        parent_hash,
                                        parent_hash,
                                        tx_root,
                                        vrf_data,
                                        txs,
                                        encrypted_blobs,
                                        exec_schedule,
                                    );

                                    // Process our own block immediately.
                                    // VRF selection ensures only one proposal wins votes, so
                                    // speculative execution is safe: our block either wins (QC forms)
                                    // or nobody's block wins (timeout). In the rare case another
                                    // proposer's block wins for the same slot, our state diverges
                                    // but the gossip block handler rejects duplicate slots.
                                    let t_exec = std::time::Instant::now();
                                    {
                                        let mut chain_w = chain.write().await;
                                        let mut state_w = state.write().await;
                                        let ws_slot = engine
                                            .finality
                                            .latest_checkpoint
                                            .as_ref()
                                            .map(|cp| cp.slot);
                                        match BlockProcessor::process_full_block_with_aot_and_checkpoint(&mut chain_w, &mut state_w, &block, Some(&aot_cache), ws_slot) {
                                            Ok((tc, gas, ref receipts_list)) => {
                                                // PIPELINED: background Merkle commit
                                                let pending = state_w.take_pending_writes();
                                                let smt_handle = state_w.smt_handle();
                                                drop(state_w);
                                                drop(chain_w);
                                                if !pending.is_empty() {
                                                    let state_for_root = state.clone();
                                                    tokio::spawn(async move {
                                                        if let Ok(root) = crate::state_manager::StateManager::commit_writes_to_smt(&smt_handle, pending) {
                                                            if let Ok(mut sw) = state_for_root.try_write() {
                                                                sw.set_root(root);
                                                            }
                                                        }
                                                    });
                                                }
                                                let _ = block_store.put_header(&block.header);
                                                let _ = block_store.put_head(current_slot);
                                                chain_sync.on_block_processed(current_slot);
                                                let mut receipts_w = receipts.write().await;
                                                receipts_w.insert_block_receipts(current_slot, receipts_list.clone());
                                                // Broadcast to WS subscribers
                                                let _ = ws_heads.send(serde_json::json!({
                                                    "slot": format!("0x{:x}", current_slot),
                                                    "timestamp": format!("0x{:x}", block.header.timestamp),
                                                    "proposer": format!("0x{}", hex::encode(block.header.proposer)),
                                                    "txCount": format!("0x{:x}", tc),
                                                }));
                                                for r in receipts_list.iter() {
                                                    for log in &r.logs {
                                                        let _ = ws_logs.send(serde_json::json!({
                                                            "address": format!("0x{}", hex::encode(log.address)),
                                                            "topics": log.topics.iter().map(|t| format!("0x{}", hex::encode(t))).collect::<Vec<_>>(),
                                                            "data": format!("0x{}", hex::encode(&log.data)),
                                                        }));
                                                    }
                                                }
                                                let exec_ms = t_exec.elapsed().as_secs_f64() * 1000.0;
                                                let slot_ms = slot_t0.elapsed().as_secs_f64() * 1000.0;
                                                info!(
                                                    slot = current_slot,
                                                    txs = tc,
                                                    gas,
                                                    pending = pending_len,
                                                    clone_ms,
                                                    build_ms,
                                                    exec_ms,
                                                    slot_ms,
                                                    "proposed and processed block"
                                                );

                                                // Remove plaintext tx hashes from the local
                                                // pending queue and mempool_index. Without this,
                                                // self-proposed blocks leave their txs in
                                                // pending forever — the next slot's builder
                                                // keeps re-selecting them, execution fails
                                                // `BelowWindow` (nonce already consumed), and
                                                // the block's 16-tx slot never fills with
                                                // fresh txs. BlockProcessed in the gossip
                                                // path handles the same cleanup for blocks
                                                // received from peers; the self-proposal
                                                // path must do it here too.
                                                let committed_tx_hashes: Vec<[u8; 32]> = block
                                                    .body
                                                    .transactions
                                                    .iter()
                                                    .map(|tx| tx.hash())
                                                    .collect();
                                                if !committed_tx_hashes.is_empty() {
                                                    {
                                                        let mut pending_w = pending_txs.write().await;
                                                        for h in &committed_tx_hashes {
                                                            pending_w.remove(h);
                                                        }
                                                    }
                                                    {
                                                        let mut times_w = pending_tx_times.write().await;
                                                        for h in &committed_tx_hashes {
                                                            times_w.remove(h);
                                                        }
                                                    }
                                                    {
                                                        let mut idx = mempool_index.write().await;
                                                        for h in &committed_tx_hashes {
                                                            idx.remove(h);
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                warn!(slot = current_slot, error = %e, "failed to process own block");
                                            }
                                        }
                                    }

                                    // Audit item 227 step 4: do NOT remove encrypted txs
                                    // from tx_relay here. Self-proposals can lose the
                                    // multi-proposer VRF lottery, and removing at self-
                                    // propose time would permanently orphan the tx when
                                    // a different validator's block wins the slot. The
                                    // removal happens in the `ReconstructCompactBlock`
                                    // handler once the committed block has been processed
                                    // — if our block ends up being the winner, it arrives
                                    // back to us via gossip like any other block and the
                                    // cleanup fires there. If it loses, the tx stays in
                                    // the mempool for future slots.

                                    // Store full block for sync serving + missing tx requests
                                    let full_block_bytes = wire::encode_block(&block);
                                    let _ = block_store.put_block(&block.header, &full_block_bytes);

                                    // Broadcast block to peers.
                                    // If block has encrypted txs, send FULL block (encrypted blobs
                                    // can't be compacted — they're opaque, not matchable against mempool).
                                    // Always use compact blocks for bandwidth efficiency.
                                    // Both plaintext and encrypted tx hashes are included as short IDs.
                                    // Receivers reconstruct from their respective mempools.
                                    let header_bytes = wire::encode_block_header(&block.header);
                                    let mut all_tx_hashes: Vec<[u8; 32]> = block.body.transactions.iter()
                                        .map(|tx| tx.hash()).collect();
                                    // Include encrypted tx hashes (receivers match against TxRelay mempool)
                                    for etx_bytes in &block.body.encrypted_txs {
                                        if let Some(etx) = pyde_mempool::encrypted::EncryptedTx::from_bytes(etx_bytes) {
                                            all_tx_hashes.push(etx.hash());
                                        }
                                    }
                                    let compact = pyde_net::propagation::CompactBlock::from_block(
                                        header_bytes,
                                        &all_tx_hashes,
                                        &[],
                                        &[],
                                    );
                                    let compact_bytes = wire::encode_compact_block(&compact);
                                    let topic = pyde_net::node::topics::blocks();
                                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), compact_bytes) {
                                        debug!(slot = current_slot, error = %e, "no gossipsub subscribers for block");
                                    }

                                    // Audit item 207: publish the encrypted_txs
                                    // bundle alongside the compact block so
                                    // non-proposer validators that don't have
                                    // them in their local tx_relay can still
                                    // reconstruct the block. Integrity is
                                    // anchored by BlockHeader::tx_root on the
                                    // receiver (see process_full_block_...).
                                    if !block.body.encrypted_txs.is_empty() {
                                        let bundle = pyde_net::propagation::EncryptedTxBundle {
                                            slot: block.header.slot,
                                            block_hash: block.header.hash(),
                                            encrypted_txs: block.body.encrypted_txs.clone(),
                                        };
                                        let bundle_bytes = wire::encode_encrypted_tx_bundle(&bundle);
                                        match swarm
                                            .behaviour_mut()
                                            .gossipsub
                                            .publish(topic, bundle_bytes)
                                        {
                                            Ok(_) => debug!(
                                                slot = current_slot,
                                                entries = block.body.encrypted_txs.len(),
                                                "published encrypted-tx bundle"
                                            ),
                                            Err(e) => debug!(
                                                slot = current_slot,
                                                error = %e,
                                                "no gossipsub subscribers for encrypted-tx bundle"
                                            ),
                                        }
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

                                    // If buffering triggered local detection of an
                                    // equivocation, relay the evidence on the consensus
                                    // channel so peers can slash even if they never
                                    // directly witnessed the double-propose.
                                    for ev in engine.drain_broadcast_evidence() {
                                        let bytes = wire::encode_slash_evidence_msg(&ev);
                                        let topic = pyde_net::node::topics::consensus();
                                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, bytes) {
                                            warn!(error = ?e, "failed to publish slash evidence");
                                        }
                                    }
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

                                    // Audit 232: own-vote QC mismatch check.
                                    // Same logic as the gossip-vote path at
                                    // ConsensusMessage::Vote — if the QC formed
                                    // here points at a hash that doesn't match
                                    // what we committed at this slot, trigger
                                    // a reorg via the same buffer pathway.
                                    if qc_formed {
                                        let qc_hash = engine.consensus.highest_qc.block_hash;
                                        let local_hash = chain
                                            .read()
                                            .await
                                            .header(current_slot)
                                            .map(|h| h.hash());
                                        if let Some(local) = local_hash {
                                            if local != qc_hash {
                                                if let Some(target) =
                                                    competing_blocks.remove(&(current_slot, qc_hash))
                                                {
                                                    // We're already inside `engine` mut-borrow,
                                                    // so capture ws_slot directly via that —
                                                    // can't re-borrow validator_engine.
                                                    let ws_slot = engine
                                                        .finality
                                                        .latest_checkpoint
                                                        .as_ref()
                                                        .map(|cp| cp.slot);
                                                    let mut chain_w = chain.write().await;
                                                    let mut state_w = state.write().await;
                                                    match BlockProcessor::reorg_to_block(
                                                        &mut chain_w,
                                                        &mut state_w,
                                                        &target,
                                                        Some(&aot_cache),
                                                        ws_slot,
                                                    ) {
                                                        Ok((tx_count, gas_used, _)) => {
                                                            let _ = state_w.flush_pending();
                                                            state_w.refresh_root();
                                                            crate::metrics::record_reorg(
                                                                crate::metrics::ReorgOutcome::Succeeded,
                                                            );
                                                            info!(
                                                                slot = current_slot,
                                                                tx_count,
                                                                gas_used,
                                                                "reorg succeeded (own-vote QC)"
                                                            );
                                                        }
                                                        Err(e) => {
                                                            crate::metrics::record_reorg(
                                                                crate::metrics::ReorgOutcome::Failed,
                                                            );
                                                            warn!(slot = current_slot, error = %e, "reorg failed (own-vote QC)");
                                                        }
                                                    }
                                                } else {
                                                    crate::metrics::record_reorg(
                                                        crate::metrics::ReorgOutcome::TargetNotBuffered,
                                                    );
                                                    warn!(
                                                        slot = current_slot,
                                                        local = hex::encode(local),
                                                        qc = hex::encode(qc_hash),
                                                        "QC mismatch on own-vote path but competing block not buffered"
                                                    );
                                                }
                                            }
                                        }
                                    }

                                    // If QC formed: broadcast hard finality vote
                                    if qc_formed {
                                        let state_root = chain.read().await.state_root;
                                        if let Some(fv) = engine.create_finality_vote(
                                            current_slot,
                                            engine.consensus.highest_qc.block_hash,
                                            state_root,
                                            identity,
                                        ) {
                                            let cert_formed = engine.on_finality_vote(fv.clone());
                                            let fv_bytes = wire::encode_finality_vote(&fv);
                                            let topic = pyde_net::node::topics::consensus();
                                            let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), fv_bytes);
                                            if cert_formed {
                                                if let Some(cp) = engine.latest_finality_checkpoint() {
                                                    let cp_bytes =
                                                        wire::encode_finality_checkpoint_msg(cp);
                                                    let _ = swarm.behaviour_mut().gossipsub.publish(topic, cp_bytes);
                                                }
                                            }
                                        }

                                        // After QC: if block has encrypted txs, create a
                                        // BlockDecryptor, generate + broadcast our shares,
                                        // and start collecting shares from other validators.
                                        if identity.key_share.is_some() {
                                            if let Some(block_raw) = block_store.get_block_raw(current_slot) {
                                                if let Ok(block) = wire::decode_block(&block_raw) {
                                                    if !block.body.encrypted_txs.is_empty() {
                                                        let enc_txs: Vec<pyde_mempool::encrypted::EncryptedTx> =
                                                            block.body.encrypted_txs.iter()
                                                                .filter_map(|b| pyde_mempool::encrypted::EncryptedTx::from_bytes(b))
                                                                .collect();

                                                        let tx_root_ok = crate::block_processor::verify_decryptor_against_committed_root(
                                                            &block.header.tx_root,
                                                            &block.body.transactions,
                                                            &enc_txs,
                                                        );
                                                        if !tx_root_ok {
                                                            error!(
                                                                slot = current_slot,
                                                                "decrypt-time tx_root mismatch — \
                                                                 refusing to decrypt tampered block"
                                                            );
                                                        }

                                                        if tx_root_ok && !enc_txs.is_empty() {
                                                            let threshold = pyde_consensus::block::quorum_for_committee(
                                                                engine.committee_keys.len()
                                                            );
                                                            // Create decryptor and seed with our own shares
                                                            if let Ok(mut decryptor) = pyde_mempool::decryption::BlockDecryptor::new(
                                                                enc_txs.clone(), threshold,
                                                            ) {
                                                                if let Some(ks) = &identity.key_share {
                                                                    decryptor.add_member_shares(ks);
                                                                }
                                                                // Store decryptor for share collection
                                                                // Replay any queued shares that arrived before the decryptor
                                                                {
                                                                    let mut q = queued_shares.write().await;
                                                                    if let Some(queued) = q.remove(&current_slot) {
                                                                        for qmsg in &queued {
                                                                            for (i, sb) in qmsg.shares.iter().enumerate() {
                                                                                if let Some(s) = pyde_crypto::threshold::DecryptionShare::from_bytes(sb) {
                                                                                    decryptor.add_share(i, s);
                                                                                }
                                                                            }
                                                                        }
                                                                        debug!(
                                                                            slot = current_slot,
                                                                            replayed = queued.len(),
                                                                            "replayed queued decryption shares"
                                                                        );
                                                                    }
                                                                }
                                                                pending_decryptors.write().await.insert(current_slot, decryptor);
                                                            }

                                                            // Broadcast our shares
                                                            if let Some(shares) = engine.generate_decryption_shares(identity, &enc_txs) {
                                                                let msg = wire::DecryptionShareMsg {
                                                                    slot: current_slot,
                                                                    member_index: identity.committee_index,
                                                                    shares: shares.iter().map(|s| s.to_bytes()).collect(),
                                                                };
                                                                let share_bytes = wire::encode_decryption_shares(&msg);
                                                                let topic = pyde_net::node::topics::consensus();
                                                                let _ = swarm.behaviour_mut().gossipsub.publish(topic, share_bytes);
                                                                info!(
                                                                    slot = current_slot,
                                                                    enc_txs = enc_txs.len(),
                                                                    "broadcast decryption shares"
                                                                );
                                                            }

                                                            // Check if already at threshold (e.g. single node)
                                                            let mut dec_w = pending_decryptors.write().await;
                                                            if let Some(decryptor) = dec_w.get_mut(&current_slot) {
                                                                if decryptor.all_ready() {
                                                                    match decryptor.decrypt_all() {
                                                                        Ok(decrypted_txs) => {
                                                                            info!(
                                                                                slot = current_slot,
                                                                                txs = decrypted_txs.len(),
                                                                                "encrypted txs decrypted — executing"
                                                                            );
                                                                            // Execute decrypted txs
                                                                            let chain_w = chain.write().await;
                                                                            let mut state_w = state.write().await;
                                                                            let proposer = block_store.get_header(current_slot)
                                                                                .map(|h| h.proposer).unwrap_or(identity.address);
                                                                            let block_ctx = pyde_tx::pipeline::BlockContext {
                                                                                height: current_slot,
                                                                                timestamp: 0,
                                                                                base_fee: chain_w.base_fee,
                                                                                block_gas_limit: self.config.consensus.gas_ceiling,
                                                                                chain_id: chain_w.chain_id,
                                                                                validator_address: proposer,
                                                                                dev_skip_signature: false,
                                                                                block_sigs_pre_verified: false,
                                                                            };
                                                                            for dtx in &decrypted_txs {
                                                                                // Bind the execute_transaction result BEFORE the
                                                                                // match so the `state_w.smt_mut()` MutexGuard
                                                                                // temporary is dropped at this semicolon. Without
                                                                                // this binding the guard lives through the match
                                                                                // body, which includes `receipts.write().await` —
                                                                                // the tokio scheduler could move the future to
                                                                                // another thread holding a std Mutex guard, a
                                                                                // well-known deadlock / UB pattern. Surfaced by
                                                                                // slice 5.5 clippy sweep.
                                                                                let exec_result = pyde_tx::pipeline::execute_transaction(
                                                                                    dtx,
                                                                                    &mut *state_w.smt_mut(),
                                                                                    &block_ctx,
                                                                                );
                                                                                match exec_result {
                                                                                    Ok(receipt) => {
                                                                                        let mut receipts_w = receipts.write().await;
                                                                                        receipts_w.insert_block_receipts(current_slot, vec![receipt]);
                                                                                    }
                                                                                    Err(e) => {
                                                                                        warn!(error = ?e, "failed to execute decrypted tx");
                                                                                    }
                                                                                }
                                                                            }
                                                                            state_w.refresh_root();
                                                                        }
                                                                        Err(e) => warn!(error = %e, "decryption failed"),
                                                                    }
                                                                    dec_w.remove(&current_slot);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Check for timeout (no proposal received within 200ms)
                        if engine.is_timed_out() {
                            if let Some(identity) = validator_identity.as_ref() {
                                // audit 234: forward the signed view-change
                                // message returned by `on_timeout`. Earlier
                                // code constructed a fresh Timeout with
                                // `signature: vec![]`, which receivers
                                // rejected at signature verification — so
                                // `try_form_view_change_qc` never reached
                                // quorum and the chain stalled on any slot
                                // where the assigned proposer was offline.
                                if let Some(vc_msg) = engine.on_timeout(identity) {
                                    let vc_bytes = wire::encode_consensus_message(
                                        &pyde_consensus::hotstuff::ConsensusMessage::Timeout {
                                            slot: vc_msg.slot,
                                            voter_index: vc_msg.voter_index,
                                            voter_address: vc_msg.voter_address,
                                            highest_qc: vc_msg.highest_qc,
                                            signature: vc_msg.signature,
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
                Some(enc_tx) = encrypted_tx_gossip_rx.recv() => {
                    // Audit item 227 step 4 / option E: fan out the
                    // encrypted tx to other validators. Without this,
                    // only the RPC-receiving node has it and only its
                    // own proposals can include it — under multi-proposer
                    // VRF the tx would be permanently orphaned.
                    let tx_hash = enc_tx.hash();
                    let tx_bytes = enc_tx.to_bytes();
                    let topic = pyde_net::node::topics::encrypted_transactions();
                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, tx_bytes) {
                        debug!(error = %e, "failed to gossip encrypted tx");
                    } else {
                        debug!(tx_hash = hex::encode(tx_hash), "gossiped encrypted tx to network");
                    }
                }
                _ = sync_interval.tick() => {
                    // Try to sync if we're behind
                    if chain_sync.is_syncing() {
                        chain_sync.request_next_batch(&mut swarm);
                    }
                }
                _ = gossip_retry_interval.tick() => {
                    // Re-publish uncommitted pending txs. The initial
                    // gossipsub publish at RPC-ingress time is
                    // best-effort: it can silently fail with
                    // NoSubscribers if the mesh hasn't converged yet,
                    // and there's no retry path in libp2p's gossipsub.
                    // Without this, a tx submitted during startup /
                    // mesh churn / subscription re-binding can sit in
                    // exactly one node's pending forever, orphaning
                    // that sender's nonce window — the root cause of
                    // the "stuck at nonce N" stalls we saw under
                    // loadgen. Cap to avoid re-publish bursts.
                    let pending_r = pending_txs.read().await;
                    let to_retry: Vec<pyde_tx::types::Transaction> = pending_r
                        .values()
                        .take(GOSSIP_RETRY_MAX_TXS)
                        .cloned()
                        .collect();
                    drop(pending_r);
                    if !to_retry.is_empty() {
                        let topic = pyde_net::node::topics::transactions();
                        let mut ok = 0;
                        let mut nosub = 0;
                        for tx in &to_retry {
                            let bytes = wire::encode_transaction(tx);
                            match swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes) {
                                Ok(_) => ok += 1,
                                Err(_) => nosub += 1,
                            }
                        }
                        debug!(
                            total = to_retry.len(),
                            ok,
                            nosub,
                            "gossip retry"
                        );
                    }
                }
                _ = maintenance_interval.tick() => {
                    // Periodic maintenance
                    let mut tx_relay_w = tx_relay.write().await;
                    tx_relay_w.prune_expired();
                    let plain_mempool_size = pending_txs.read().await.len();
                    let mempool_size = tx_relay_w.mempool_size();
                    drop(tx_relay_w);
                    crate::metrics::record_mempool(plain_mempool_size);
                    crate::metrics::record_encrypted_mempool(mempool_size);
                    let peer_count = swarm.connected_peers().count();
                    crate::metrics::record_peers(peer_count);

                    // Audit 222: operator-actionable lag gauges.
                    // block_lag = how far behind the gossip-observed
                    // network tip; finality_lag = how far behind the
                    // last hard-finality checkpoint. Stable values
                    // for finality_lag are ~2 slots in steady state.
                    let local_head = chain.read().await.head_slot;
                    let network_tip = chain_sync.manager.network_tip;
                    crate::metrics::record_block_lag(local_head, network_tip);
                    let last_cp = validator_engine
                        .as_ref()
                        .and_then(|e| e.finality.latest_checkpoint.as_ref().map(|cp| cp.slot))
                        .unwrap_or(0);
                    crate::metrics::record_finality_lag(local_head, last_cp);

                    // Plaintext mempool TTL sweep (MAINNET_PLAN M2).
                    // Any tx that's been pending for more than
                    // `MEMPOOL_TX_TTL` is evicted — under sustained
                    // overload the mempool would otherwise grow
                    // without bound. The eviction is driven by the
                    // parallel `pending_tx_times` map to avoid
                    // changing the mempool value type. 4-minute
                    // default chosen to span ~600 slots at 400 ms —
                    // well past the point where a legitimate tx
                    // would have its nonce window slide past it.
                    const MEMPOOL_TX_TTL: std::time::Duration =
                        std::time::Duration::from_secs(240);
                    {
                        let now = std::time::Instant::now();
                        let stale: Vec<[u8; 32]> = pending_tx_times
                            .read()
                            .await
                            .iter()
                            .filter_map(|(h, t)| {
                                if now.duration_since(*t) > MEMPOOL_TX_TTL {
                                    Some(*h)
                                } else {
                                    None
                                }
                            })
                            .collect();
                        if !stale.is_empty() {
                            {
                                let mut pending_w = pending_txs.write().await;
                                for h in &stale {
                                    pending_w.remove(h);
                                }
                            }
                            {
                                let mut times_w = pending_tx_times.write().await;
                                for h in &stale {
                                    times_w.remove(h);
                                }
                            }
                            {
                                let mut idx = mempool_index.write().await;
                                for h in &stale {
                                    idx.remove(h);
                                }
                            }
                            info!(
                                evicted = stale.len(),
                                "mempool TTL sweep"
                            );
                        }
                    }
                    // Periodically trigger Kademlia bootstrap to discover + connect to new peers.
                    // Critical for mesh resilience: ensures nodes connect to each other,
                    // not just the bootstrap node.
                    let _ = swarm.behaviour_mut().kademlia.bootstrap();
                    // Clean up stale decryptors and queued shares (older than 100 slots)
                    {
                        let head = chain.read().await.head_slot;
                        let mut dec_w = pending_decryptors.write().await;
                        dec_w.retain(|slot, _| *slot + 100 > head);
                        let mut q = queued_shares.write().await;
                        q.retain(|slot, _| *slot + 100 > head);
                        // Audit item 207: prune queued encrypted-tx bundles
                        // that never paired with a compact block (proposer
                        // failure, gossip drop, or an adversarial orphan).
                        let mut qb = queued_encrypted_bundles.write().await;
                        qb.retain(|(slot, _), _| *slot + 100 > head);
                    }
                    let head = chain.read().await.head_slot;
                    debug!(
                        peers = peer_count,
                        mempool = mempool_size,
                        head,
                        syncing = chain_sync.is_syncing(),
                        behind = chain_sync.manager.slots_behind(),
                        "maintenance tick"
                    );
                    // Persist refreshed key share to disk if dirty
                    if let Some(engine) = validator_engine.as_mut() {
                        if engine.key_share_dirty {
                            if let Some(identity) = validator_identity.as_ref() {
                                if let Some(ref ks) = identity.key_share {
                                    let share_path = self.config.node.datadir.join("threshold.share");
                                    if std::fs::write(&share_path, ks.to_bytes()).is_ok() {
                                        engine.key_share_dirty = false;
                                        info!("PSS: refreshed key share saved to disk");
                                    }
                                }
                            }
                        }
                    }
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

use pyde_net::sync_protocol::SyncResp;

/// Action to take after processing a swarm event (avoids borrow conflicts with swarm).
enum PostEventAction {
    None,
    #[allow(dead_code)]
    RequestChainTip(PeerId),
    SendSyncResponse(request_response::ResponseChannel<SyncResp>, SyncResp),
    ContinueSync,
    BroadcastConsensus(Vec<u8>),
    /// Batch-publish multiple consensus messages in one post-event
    /// action. Used for slashing evidence: a single received proposal
    /// can cause the engine to queue several messages at once (e.g. if
    /// gossip and local detection arrive in the same tick).
    BroadcastConsensusMany(Vec<Vec<u8>>),
    AcceptTransaction(pyde_tx::types::Transaction),
    /// Ingress from the encrypted-transactions gossip topic
    /// (audit item 227 step 4 / option E). Main loop routes it
    /// through `tx_relay.receive_tx_verified` or
    /// `receive_tx` depending on whether the sender has a
    /// registered `AuthKeys::Single` on-chain.
    AcceptEncryptedTransaction(pyde_mempool::encrypted::EncryptedTx),
    #[allow(dead_code)]
    StoreReceipts(u64, Vec<pyde_tx::execution::Receipt>),
    AddPeerToKademlia(PeerId, Vec<libp2p::Multiaddr>),
    BlockProcessed {
        slot: u64,
        receipts: Vec<pyde_tx::execution::Receipt>,
        tx_hashes: Vec<[u8; 32]>,
    },
    ReconstructCompactBlock(pyde_net::propagation::CompactBlock),
    AddDecryptionShares(wire::DecryptionShareMsg),
    /// Buffered encrypted-tx bundle from a proposer. The main loop
    /// stores it keyed by (slot, block_hash) so the matching compact
    /// block can pull encrypted_txs out of it on arrival, regardless
    /// of gossipsub ordering. Audit item 207.
    BufferEncryptedBundle(pyde_net::propagation::EncryptedTxBundle),
    /// A fresh QC just formed via an incoming gossip vote. Main loop
    /// uses this to trigger the post-QC decryption flow — previously
    /// that flow was only attached to `select_and_vote`'s local-QC
    /// path, which in a 4+-node committee rarely fires (our vote is
    /// typically not the 3rd/Nth that closes the QC; another
    /// validator's is). Without this action the encrypted-tx
    /// decryption never started on real multi-node networks.
    /// Audit item 227 step 4 / option E.
    QcFormedFromGossip {
        slot: u64,
    },
    /// Send a `PydeAuthReq` to a newly connected peer. The main loop
    /// generates a fresh nonce, records it in `pending_auth_nonces`, and
    /// dispatches via the swarm.
    SendAuthRequest(PeerId),
    /// Reply to an inbound `PydeAuthReq` with a signed attestation over
    /// `(nonce, our_peer_id)`. The response channel holds the pending
    /// outbound stream to the requester.
    SendAuthResponse(
        request_response::ResponseChannel<pyde_net::auth::PydeAuthResp>,
        pyde_net::auth::PydeAuthResp,
    ),
    /// Audit 232: a gossiped block is at the same slot as our current
    /// head but with a different hash — i.e. a competing proposal
    /// under a multi-proposer race. Main loop inserts it into
    /// `competing_blocks` so a later QC for that hash can trigger
    /// `reorg_to_block`.
    BufferCompetingBlock(pyde_consensus::block::Block),
    /// Audit 232: a QC formed for a block whose hash doesn't match
    /// what we committed at that slot. Main loop looks up the QC'd
    /// block in `competing_blocks` and, if present, calls
    /// `BlockProcessor::reorg_to_block` to switch chains. If
    /// absent, schedules a sync request for the missing block.
    TryReorgToQc {
        qc_slot: u64,
        qc_block_hash: [u8; 32],
    },
}

/// Handle a libp2p swarm event. Returns an action that may need swarm access.
fn handle_swarm_event(
    event: SwarmEvent<PydeBehaviourEvent>,
    chain: &mut ChainState,
    state: &mut StateManager,
    _tx_relay: &mut TxRelay,
    chain_sync: &mut ChainSync,
    validator_engine: &mut Option<ValidatorEngine>,
    validator_identity: &mut Option<ValidatorIdentity>,
    block_store: &BlockStore,
    pinned_snapshot: &mut Option<crate::sync::PinnedSnapshot>,
    peer_manager: &mut pyde_net::peer::PeerManager,
    pending_auth_nonces: &mut std::collections::HashMap<PeerId, [u8; 32]>,
    last_outgoing_committee_size: usize,
) -> PostEventAction {
    match event {
        // --- Gossipsub message received ---
        SwarmEvent::Behaviour(PydeBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            message,
            propagation_source,
            ..
        })) => {
            let topic = message.topic.to_string();
            let channel = Channel::from_topic(&topic);

            match channel {
                Some(Channel::Transactions) => {
                    debug!(bytes = message.data.len(), "received tx gossip");
                    // Decode wire-encoded transaction, verify signature, add to pending queue
                    match wire::decode_transaction(&message.data) {
                        Ok(tx) => {
                            let tx_hash = tx.hash();
                            // Verify signature at mempool entry (not devnet)
                            if chain.chain_id != 31337 && !tx.signature.is_empty() {
                                let sender_key = pyde_state::keys::balance_key(&tx.from);
                                if let Some(acct_bytes) = state.get(&sender_key) {
                                    if let Some(acct) =
                                        pyde_account::types::Account::from_bytes(&acct_bytes)
                                    {
                                        if let pyde_account::types::AuthKeys::Single(ref pk) =
                                            acct.auth_keys
                                        {
                                            if !tx.verify_signature(pk) {
                                                debug!(
                                                    tx_hash = hex::encode(tx_hash),
                                                    "rejected gossip tx: invalid signature"
                                                );
                                                return PostEventAction::None;
                                            }
                                        }
                                    }
                                }
                            }
                            debug!(tx_hash = hex::encode(tx_hash), "decoded tx from gossip");
                            return PostEventAction::AcceptTransaction(tx);
                        }
                        Err(e) => {
                            debug!(error = e, "failed to decode tx from gossip");
                        }
                    }
                }
                Some(Channel::EncryptedTransactions) => {
                    debug!(bytes = message.data.len(), "received encrypted tx gossip");
                    // Audit item 227 step 4 / option E: decode the
                    // EncryptedTx wire frame and route it to the main
                    // loop's action handler, which drops it into the
                    // local tx_relay. The local tx_relay is what the
                    // block builder pulls from when this node is the
                    // winning proposer — without this path, only the
                    // RPC-ingress node ever has the tx in its relay.
                    match pyde_mempool::encrypted::EncryptedTx::from_bytes(&message.data) {
                        Some(enc_tx) => {
                            return PostEventAction::AcceptEncryptedTransaction(enc_tx);
                        }
                        None => {
                            debug!("failed to decode encrypted tx from gossip");
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

                    // Encrypted-tx bundle (audit item 207): proposer delivers
                    // the block's encrypted_txs to validators that don't
                    // already have them in their local tx_relay. Buffered
                    // until the matching compact block arrives.
                    if !message.data.is_empty() && message.data[0] == wire::tag::ENCRYPTED_TX_BUNDLE
                    {
                        match wire::decode_encrypted_tx_bundle(&message.data) {
                            Ok(bundle) => {
                                return PostEventAction::BufferEncryptedBundle(bundle);
                            }
                            Err(e) => {
                                debug!(error = e, "failed to decode encrypted-tx bundle");
                            }
                        }
                        return PostEventAction::None;
                    }

                    // Fallback: full block (from sync or older nodes)
                    match wire::decode_block(&message.data) {
                        Ok(block) => {
                            let slot = block.header.slot;

                            // Validate block header (signature, VRF, proposer, QC)
                            if let Some(ref engine) = validator_engine {
                                if let Err(e) = BlockProcessor::validate_network_block(
                                    &block.header,
                                    &block.proposer_signature,
                                    &engine.committee_keys,
                                    &engine.epoch_randomness,
                                ) {
                                    warn!(slot, error = %e, "block header validation failed");
                                    return PostEventAction::None;
                                }
                            }

                            // Validate block body (tx signatures, gas, no duplicates)
                            if let Err(e) =
                                BlockProcessor::validate_block_body(&block, state, chain.chain_id)
                            {
                                warn!(slot, error = %e, "block body validation failed");
                                return PostEventAction::None;
                            }

                            let ws_slot = validator_engine.as_ref().and_then(|e| {
                                e.finality.latest_checkpoint.as_ref().map(|cp| cp.slot)
                            });
                            match BlockProcessor::process_full_block_with_aot_and_checkpoint(
                                chain, state, &block, None, ws_slot,
                            ) {
                                Ok((tx_count, gas_used, receipts_list)) => {
                                    // Sync flush for gossip-received blocks (no Arc access here)
                                    let _ = state.flush_pending();
                                    state.refresh_root();
                                    chain_sync.on_block_processed(slot);
                                    // Persist full block (header + body) to disk
                                    let _ = block_store.put_block(&block.header, &message.data);
                                    let _ = block_store.put_head(slot);
                                    info!(slot, tx_count, gas_used, "block received and processed");
                                    // Collect tx hashes to deduplicate from pending queue
                                    let tx_hashes: Vec<[u8; 32]> = block
                                        .body
                                        .transactions
                                        .iter()
                                        .map(|tx| tx.hash())
                                        .collect();
                                    // Store receipts + deduplicate txs
                                    return PostEventAction::BlockProcessed {
                                        slot,
                                        receipts: receipts_list,
                                        tx_hashes,
                                    };
                                }
                                Err(e) => {
                                    // Audit 232: if rejection is "slot at our head but
                                    // different hash" (multi-proposer race), buffer the
                                    // block so a later QC can trigger reorg via
                                    // `BlockProcessor::reorg_to_block`. The block
                                    // already passed signature + body validation above,
                                    // so trust is bounded — only the canonical chain's
                                    // QC'd block ever gets reapplied from this buffer.
                                    let incoming_hash = block.header.hash();
                                    let is_same_slot_competitor = slot == chain.head_slot
                                        && chain
                                            .header(slot)
                                            .map(|h| h.hash() != incoming_hash)
                                            .unwrap_or(false);
                                    if is_same_slot_competitor {
                                        debug!(
                                            slot,
                                            incoming_hash = hex::encode(incoming_hash),
                                            "buffering competing block for potential reorg"
                                        );
                                        return PostEventAction::BufferCompetingBlock(block);
                                    }
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
                    // Task 030: block non-validator relays of consensus
                    // gossip. Two layered checks:
                    //
                    // 1. `propagation_source` — the DIRECT peer that
                    //    forwarded this message to us. Every in-mesh peer
                    //    has attempted our FALCON handshake, so an
                    //    attested-non-committee propagator is a solid
                    //    signal of a non-validator spamming the mesh.
                    //    Drop hard.
                    // 2. `message.source` — the ORIGINATOR. We may or may
                    //    not have shaken hands with them (they might not
                    //    be in our mesh at all). When we have, applying
                    //    the same committee check blocks originator-level
                    //    impersonation too.
                    //
                    // Unattested peers in either slot fall through to
                    // app-layer FALCON sig verification — which catches
                    // forgeries but pays the decode + verify cost.
                    if let Some(engine) = validator_engine.as_ref() {
                        // Primary: immediate forwarder.
                        let prop_attested = peer_manager
                            .peer_falcon_pubkey(&propagation_source)
                            .is_some();
                        let prop_authorized = peer_manager
                            .is_consensus_authorized(&propagation_source, &engine.committee_keys);
                        if prop_attested && !prop_authorized {
                            debug!(
                                forwarder = %propagation_source,
                                "dropping consensus gossip relayed by non-committee attested peer"
                            );
                            if let Some(info) = peer_manager.get_peer_mut(&propagation_source) {
                                info.invalid_messages = info.invalid_messages.saturating_add(1);
                            }
                            return PostEventAction::None;
                        }
                        // Secondary: originator, when known.
                        if let Some(source) = message.source.as_ref() {
                            let src_attested = peer_manager.peer_falcon_pubkey(source).is_some();
                            let src_authorized = peer_manager
                                .is_consensus_authorized(source, &engine.committee_keys);
                            if src_attested && !src_authorized {
                                debug!(
                                    %source,
                                    "dropping consensus gossip originated by non-committee attested peer"
                                );
                                if let Some(info) = peer_manager.get_peer_mut(source) {
                                    info.invalid_messages = info.invalid_messages.saturating_add(1);
                                }
                                return PostEventAction::None;
                            }
                        }
                    }
                    if let Some(engine) = validator_engine.as_mut() {
                        // Check if it's a finality vote (different wire tag)
                        if !message.data.is_empty()
                            && message.data[0] == wire::tag::CONSENSUS_FINALITY_VOTE
                        {
                            match wire::decode_finality_vote(&message.data) {
                                Ok(fv) => {
                                    debug!(
                                        slot = fv.slot,
                                        voter = fv.voter_index,
                                        "received finality vote"
                                    );
                                    if engine.on_finality_vote(fv) {
                                        // Slice 4.3 gap 1: freshly formed cert →
                                        // broadcast so non-validator peers can
                                        // advance their WS anchor.
                                        if let Some(cp) = engine.latest_finality_checkpoint() {
                                            let msg = wire::encode_finality_checkpoint_msg(cp);
                                            return PostEventAction::BroadcastConsensus(msg);
                                        }
                                    }
                                }
                                Err(e) => {
                                    debug!(error = e, "failed to decode finality vote");
                                }
                            }
                            return PostEventAction::None;
                        }

                        // Slice 4.3 gap 1: received a finality checkpoint from another peer.
                        if !message.data.is_empty()
                            && message.data[0] == wire::tag::CONSENSUS_FINALITY_CHECKPOINT
                        {
                            match wire::decode_finality_checkpoint_msg(&message.data) {
                                Ok(cp) => {
                                    let slot = cp.slot;
                                    if engine.ingest_finality_checkpoint(cp) {
                                        info!(slot, "WS anchor advanced from peer checkpoint");
                                    }
                                }
                                Err(e) => {
                                    debug!(error = e, "failed to decode finality checkpoint");
                                }
                            }
                            return PostEventAction::None;
                        }

                        // Check if it's an epoch randomness share
                        if !message.data.is_empty()
                            && message.data[0] == wire::tag::RANDOMNESS_SHARE
                        {
                            match wire::decode_randomness_share(&message.data) {
                                Ok((epoch, share)) => {
                                    debug!(
                                        epoch,
                                        validator = share.validator_index,
                                        "received randomness share"
                                    );
                                    if let Some(new_randomness) = engine.on_randomness_share(share)
                                    {
                                        info!(
                                            epoch,
                                            randomness = hex::encode(new_randomness),
                                            "epoch randomness updated"
                                        );
                                    }
                                }
                                Err(e) => {
                                    debug!(error = e, "failed to decode randomness share");
                                }
                            }
                            return PostEventAction::None;
                        }

                        // Check if it's a slashing-evidence gossip message.
                        // Validators relay these so that even a validator
                        // that never directly witnessed the equivocation
                        // can include a Slash tx in its next proposal.
                        if !message.data.is_empty()
                            && message.data[0] == wire::tag::CONSENSUS_SLASH_EVIDENCE
                        {
                            // Task 014d: rate-limit evidence ingest by peer score.
                            // Evidence verification costs ~60µs of FALCON verify.
                            // A spammer that has already produced
                            // `EVIDENCE_SPAM_THRESHOLD` rejected messages gets
                            // dropped without decode+verify. Honest validators
                            // producing legitimate evidence stay well under
                            // the threshold because `ingest_evidence` dedupes
                            // by (slot, signer) and silently ignores repeats.
                            const EVIDENCE_SPAM_THRESHOLD: u64 = 5;
                            let propagator_invalid = peer_manager
                                .get_peer(&propagation_source)
                                .map(|p| p.invalid_messages)
                                .unwrap_or(0);
                            if propagator_invalid >= EVIDENCE_SPAM_THRESHOLD {
                                debug!(
                                    forwarder = %propagation_source,
                                    invalid = propagator_invalid,
                                    "dropping evidence from peer over spam threshold"
                                );
                                return PostEventAction::None;
                            }
                            match wire::decode_slash_evidence_msg(&message.data) {
                                Ok(evidence) => {
                                    let slot = evidence.slot;
                                    let signer = evidence.signer;
                                    if engine.ingest_evidence(evidence) {
                                        info!(
                                            slot,
                                            signer = hex::encode(signer),
                                            "ingested slash evidence from gossip"
                                        );
                                    } else {
                                        // Failed verification or dedupe — bump
                                        // the peer's invalid counter so repeat
                                        // offenders cross the spam threshold
                                        // and get dropped without further verify.
                                        if let Some(info) =
                                            peer_manager.get_peer_mut(&propagation_source)
                                        {
                                            info.invalid_messages =
                                                info.invalid_messages.saturating_add(1);
                                        }
                                    }
                                    // Note: no immediate re-publish here.
                                    // gossipsub already propagates the
                                    // message across the mesh; re-emitting
                                    // would cause an amplification storm.
                                }
                                Err(e) => {
                                    debug!(error = e, "failed to decode slash evidence gossip");
                                    if let Some(info) =
                                        peer_manager.get_peer_mut(&propagation_source)
                                    {
                                        info.invalid_messages =
                                            info.invalid_messages.saturating_add(1);
                                    }
                                }
                            }
                            return PostEventAction::None;
                        }

                        // Check if it's a PSS refresh contribution
                        if !message.data.is_empty() && message.data[0] == wire::tag::PSS_REFRESH {
                            match wire::decode_pss_refresh(&message.data) {
                                Ok((epoch, contrib_bytes)) => {
                                    if let Some(contrib) =
                                        pyde_crypto::threshold::RefreshContribution::from_bytes(
                                            &contrib_bytes,
                                        )
                                    {
                                        debug!(
                                            epoch,
                                            from = contrib.from_index,
                                            "received PSS refresh contribution"
                                        );
                                        if let Some(identity) = validator_identity.as_mut() {
                                            engine.on_pss_contribution(contrib, identity);
                                        }
                                    }
                                }
                                Err(e) => {
                                    debug!(error = e, "failed to decode PSS contribution");
                                }
                            }
                            return PostEventAction::None;
                        }

                        // Check if it's a committee resharing contribution (task 034)
                        if !message.data.is_empty()
                            && message.data[0] == wire::tag::COMMITTEE_RESHARING
                        {
                            match wire::decode_resharing(&message.data) {
                                Ok((target_epoch, contrib_bytes)) => {
                                    // Drop stale contributions targeted at epochs other
                                    // than the one we're currently receiving for.
                                    if target_epoch != engine.reshare_target() {
                                        debug!(
                                            target_epoch,
                                            active = engine.reshare_target(),
                                            "ignoring stale resharing contribution"
                                        );
                                        return PostEventAction::None;
                                    }
                                    match pyde_crypto::threshold::ResharingContribution::from_bytes(
                                        &contrib_bytes,
                                    ) {
                                        Some(contrib) => {
                                            debug!(
                                                target_epoch,
                                                from_old_index = contrib.from_old_index,
                                                "received resharing contribution"
                                            );
                                            if let Some(identity) = validator_identity.as_mut() {
                                                engine.on_reshare_contribution(
                                                    contrib,
                                                    last_outgoing_committee_size,
                                                    identity,
                                                );
                                            }
                                        }
                                        None => {
                                            debug!("malformed resharing contribution bytes");
                                        }
                                    }
                                }
                                Err(e) => {
                                    debug!(error = e, "failed to decode resharing message");
                                }
                            }
                            return PostEventAction::None;
                        }

                        // Check if it's a decryption share
                        if !message.data.is_empty()
                            && message.data[0] == wire::tag::DECRYPTION_SHARES
                        {
                            // Audit item 214: rate-limit decryption share ingest
                            // by peer-invalid-message score, same pattern as
                            // evidence (014d). Every share costs a decode +
                            // several DecryptionShare::from_bytes parses; a
                            // peer that has already crossed the invalid-
                            // message threshold on prior gossip gets dropped
                            // here without further CPU cost. Honest committee
                            // members stay well under the threshold because
                            // their shares decode cleanly and bump nothing.
                            const DECRYPT_SHARE_SPAM_THRESHOLD: u64 = 5;
                            let propagator_invalid = peer_manager
                                .get_peer(&propagation_source)
                                .map(|p| p.invalid_messages)
                                .unwrap_or(0);
                            if propagator_invalid >= DECRYPT_SHARE_SPAM_THRESHOLD {
                                debug!(
                                    forwarder = %propagation_source,
                                    invalid = propagator_invalid,
                                    "dropping decryption shares from peer over spam threshold"
                                );
                                return PostEventAction::None;
                            }
                            match wire::decode_decryption_shares(&message.data) {
                                Ok(msg) => {
                                    debug!(
                                        slot = msg.slot,
                                        member = msg.member_index,
                                        shares = msg.shares.len(),
                                        "received decryption shares"
                                    );
                                    // Feed shares to the BlockDecryptor for this slot
                                    return PostEventAction::AddDecryptionShares(msg);
                                }
                                Err(e) => {
                                    // Bump peer invalid counter — repeat
                                    // offenders cross the threshold and
                                    // get dropped without decode next time.
                                    if let Some(info) =
                                        peer_manager.get_peer_mut(&propagation_source)
                                    {
                                        info.invalid_messages =
                                            info.invalid_messages.saturating_add(1);
                                    }
                                    debug!(error = e, "failed to decode decryption shares");
                                }
                            }
                            return PostEventAction::None;
                        }

                        match wire::decode_consensus_message(&message.data) {
                            Ok(msg) => {
                                use pyde_consensus::hotstuff::ConsensusMessage;
                                match msg {
                                    ConsensusMessage::Proposal {
                                        ref header,
                                        ref proposer_signature,
                                    } => {
                                        info!(slot = header.slot, "received proposal");
                                        // Buffer the proposal for VRF-based selection.
                                        // Voting happens after the proposal collection window
                                        // via select_and_vote (triggered by slot timer).
                                        engine.buffer_proposal(header, proposer_signature);
                                        // Same detection-then-relay pattern as when we
                                        // produce our own proposal: buffering a received
                                        // proposal can reveal it conflicts with one we
                                        // already saw from the same proposer. Hand the
                                        // encoded envelopes back to the outer loop to
                                        // publish — swarm isn't accessible from here.
                                        let new_evidence: Vec<Vec<u8>> = engine
                                            .drain_broadcast_evidence()
                                            .iter()
                                            .map(wire::encode_slash_evidence_msg)
                                            .collect();
                                        if !new_evidence.is_empty() {
                                            return PostEventAction::BroadcastConsensusMany(
                                                new_evidence,
                                            );
                                        }
                                    }
                                    ConsensusMessage::Vote {
                                        slot, voter_index, ..
                                    } => {
                                        debug!(slot, voter_index, "received vote");
                                        if let Some(qc) = engine.on_vote(msg) {
                                            info!(slot, votes = qc.vote_count(), "QC formed");
                                            // Audit 232: detect QC-vs-local-head
                                            // mismatch (multi-proposer race where we
                                            // committed block A but consensus picked
                                            // B). Local view says block at `slot` has
                                            // hash `local_hash`; the QC carries
                                            // `qc.block_hash`. If they differ AND we
                                            // have B buffered (or can sync it),
                                            // reorg_to_block will switch chains.
                                            let local_hash = chain.header(slot).map(|h| h.hash());
                                            if let Some(local) = local_hash {
                                                if local != qc.block_hash {
                                                    warn!(
                                                        slot,
                                                        local = hex::encode(local),
                                                        qc = hex::encode(qc.block_hash),
                                                        "QC-vs-local-head mismatch — triggering reorg"
                                                    );
                                                    return PostEventAction::TryReorgToQc {
                                                        qc_slot: slot,
                                                        qc_block_hash: qc.block_hash,
                                                    };
                                                }
                                            }
                                            // Audit item 227 step 4: notify main loop so
                                            // the decrypt pipeline starts even when OUR
                                            // own vote isn't the one that closes the QC.
                                            return PostEventAction::QcFormedFromGossip { slot };
                                        }
                                    }
                                    ConsensusMessage::Timeout {
                                        slot,
                                        voter_index,
                                        voter_address,
                                        highest_qc,
                                        signature,
                                    } => {
                                        debug!(slot, voter_index, "received timeout");
                                        // Convert to ViewChangeMessage and process
                                        let vc_msg =
                                            pyde_consensus::view_change::ViewChangeMessage {
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
                                    ConsensusMessage::NewView {
                                        slot,
                                        highest_qc,
                                        voter_address: _,
                                        signature: _,
                                    } => {
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
        SwarmEvent::Behaviour(PydeBehaviourEvent::Sync(request_response::Event::Message {
            message:
                request_response::Message::Request {
                    request, channel, ..
                },
            peer,
        })) => {
            debug!(%peer, "inbound sync request");
            let response = ChainSync::handle_inbound_request(
                &request,
                chain,
                state,
                block_store,
                pinned_snapshot,
            );
            PostEventAction::SendSyncResponse(channel, response)
        }

        // --- Sync: response to our outbound request ---
        SwarmEvent::Behaviour(PydeBehaviourEvent::Sync(request_response::Event::Message {
            message:
                request_response::Message::Response {
                    request_id,
                    response,
                },
            ..
        })) => {
            let ws_slot = validator_engine
                .as_ref()
                .and_then(|e| e.finality.latest_checkpoint.as_ref().map(|cp| cp.slot));
            chain_sync.on_response(request_id, response, chain, state, block_store, ws_slot);
            // Signal the event loop to continue if chunked snapshot needs
            // more chunks OR we're otherwise still syncing. Both branches
            // produced the same ContinueSync return — collapsed into a
            // single `||` expression (spotted by slice 5.5 clippy sweep).
            if chain_sync.needs_next_chunk().is_some() || chain_sync.is_syncing() {
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

        // --- Auth: inbound PydeAuthReq from a peer ---
        SwarmEvent::Behaviour(PydeBehaviourEvent::Auth(request_response::Event::Message {
            message:
                request_response::Message::Request {
                    request, channel, ..
                },
            peer,
        })) => {
            // Only validators can answer auth challenges — they're the only
            // ones with a FALCON keypair. Full nodes stay silent; the
            // requester will simply have no attestation to record for
            // this peer, which is fine (they'll be treated as a
            // non-validator by the consensus filter).
            match validator_identity.as_ref() {
                Some(id) => {
                    let our_peer_bytes = id.address; // 32-byte EOA derived from FALCON pk
                    match pyde_net::auth::build_auth_resp(
                        &request,
                        &our_peer_bytes,
                        &id.secret_key,
                        &id.public_key,
                    ) {
                        Ok(resp) => {
                            debug!(%peer, "sending auth attestation");
                            PostEventAction::SendAuthResponse(channel, resp)
                        }
                        Err(e) => {
                            warn!(%peer, error = %e, "failed to build auth response");
                            PostEventAction::None
                        }
                    }
                }
                None => {
                    debug!(%peer, "ignoring auth request — no validator identity");
                    PostEventAction::None
                }
            }
        }

        // --- Auth: response to our outbound PydeAuthReq ---
        SwarmEvent::Behaviour(PydeBehaviourEvent::Auth(request_response::Event::Message {
            message: request_response::Message::Response { response, .. },
            peer,
        })) => {
            // All handshake logic lives in `apply_auth_response` so this
            // arm stays purely the swarm-event adapter. Keeps the state
            // transitions testable without a live libp2p swarm.
            let committee_keys = validator_engine
                .as_ref()
                .map(|e| e.committee_keys.clone())
                .unwrap_or_default();
            let outcome = pyde_net::auth::apply_auth_response(
                peer,
                &response,
                pending_auth_nonces,
                peer_manager,
                &committee_keys,
            );
            use pyde_net::auth::AuthOutcome;
            match outcome {
                AuthOutcome::StoredAsValidator => {
                    info!(%peer, "peer attested as committee validator");
                }
                AuthOutcome::StoredAsNonValidator => {
                    debug!(%peer, "peer attested as non-validator");
                }
                AuthOutcome::NoPendingNonce => {
                    debug!(%peer, "unexpected auth response (no pending nonce)");
                }
                AuthOutcome::VerifyFailed => {
                    warn!(%peer, "FALCON attestation failed verification");
                }
                AuthOutcome::RebindRejected => {
                    warn!(%peer, "peer attempted to rebind FALCON pubkey — ignoring");
                }
            }
            PostEventAction::None
        }

        // --- Auth failures ---
        SwarmEvent::Behaviour(PydeBehaviourEvent::Auth(
            request_response::Event::OutboundFailure { peer, error, .. },
        )) => {
            debug!(%peer, ?error, "auth request failed");
            pending_auth_nonces.remove(&peer);
            PostEventAction::None
        }
        SwarmEvent::Behaviour(PydeBehaviourEvent::Auth(
            request_response::Event::InboundFailure { peer, error, .. },
        )) => {
            debug!(%peer, ?error, "auth inbound failed");
            PostEventAction::None
        }
        SwarmEvent::Behaviour(PydeBehaviourEvent::Auth(
            request_response::Event::ResponseSent { .. },
        )) => PostEventAction::None,

        // --- Peer connected: register + ask for chain tip + trigger auth handshake ---
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            info!(
                %peer_id,
                addr = %endpoint.get_remote_address(),
                "peer connected"
            );
            // Track the peer so attested pubkeys can later be stored.
            // Direction + IP are best-effort; we don't enforce inbound
            // limits here because libp2p already handled transport.
            let direction = match &endpoint {
                libp2p::core::ConnectedPoint::Dialer { .. } => pyde_net::peer::Direction::Outbound,
                libp2p::core::ConnectedPoint::Listener { .. } => pyde_net::peer::Direction::Inbound,
            };
            let info = pyde_net::peer::PeerInfo::new(peer_id, direction);
            peer_manager.add_peer(info);

            // Task 029: kick off the FALCON attestation handshake so the
            // consensus filter (task 030) has a pubkey to check.
            PostEventAction::SendAuthRequest(peer_id)
        }

        // --- Peer disconnected ---
        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            info!(
                %peer_id,
                cause = ?cause,
                "peer disconnected"
            );
            peer_manager.remove_peer(&peer_id);
            pending_auth_nonces.remove(&peer_id);
            PostEventAction::None
        }

        // --- Listening on address ---
        SwarmEvent::NewListenAddr { address, .. } => {
            info!(%address, "listening on");
            PostEventAction::None
        }

        // --- Identify: peer shared their listen addresses ---
        SwarmEvent::Behaviour(PydeBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            debug!(%peer_id, addrs = info.listen_addrs.len(), "identify received");
            if !info.listen_addrs.is_empty() {
                PostEventAction::AddPeerToKademlia(peer_id, info.listen_addrs)
            } else {
                PostEventAction::None
            }
        }

        // --- Kademlia: routing table updated (discovered a new peer) ---
        SwarmEvent::Behaviour(PydeBehaviourEvent::Kademlia(
            libp2p::kad::Event::RoutingUpdated {
                peer, addresses, ..
            },
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
///
/// Two on-disk formats are supported (audit 221):
///
///   1. **Encrypted keystore** (preferred for any non-devnet
///      deployment): JSON file matching `keystore::ValidatorKeystore`.
///      Decrypted via the passphrase in the
///      `PYDE_VALIDATOR_PASSPHRASE` env var.
///   2. **Legacy raw bytes** `[pk_len:4 LE][pk_bytes][sk_bytes]`.
///      Still accepted because devnet test infra writes this
///      format and migrating that infra is out of scope. Logs
///      a warning so operators see the deprecation path.
///
/// If `validator.key` doesn't exist, generates a new keypair.
/// The new key is saved encrypted iff `PYDE_VALIDATOR_PASSPHRASE`
/// is set; otherwise it falls back to the legacy raw format
/// (preserving devnet ergonomics).
fn load_validator_identity(datadir: &Path) -> Result<ValidatorIdentity, String> {
    let key_path = datadir.join("validator.key");
    let passphrase = std::env::var("PYDE_VALIDATOR_PASSPHRASE").ok();

    let (pk, sk) = if key_path.exists() {
        let bytes = std::fs::read(&key_path)
            .map_err(|e| format!("failed to read {}: {}", key_path.display(), e))?;

        // Try encrypted-keystore format first. JSON parse acts
        // as the format-discriminator — raw-bytes always begins
        // with a u32 LE for pk_len (FALCON-512 = 0x0381, first
        // byte 0x81), so it cannot be confused with `{`-prefixed
        // JSON.
        if let Some(keystore) = crate::keystore::try_parse_keystore(&bytes) {
            let pass = passphrase.clone().ok_or_else(|| {
                "validator.key is encrypted but PYDE_VALIDATOR_PASSPHRASE is not set".to_string()
            })?;
            let (pk, sk) = crate::keystore::decrypt(&keystore, &pass)?;
            info!(path = %key_path.display(), "loaded encrypted validator signing key");
            (pk, sk)
        } else {
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
            tracing::warn!(
                path = %key_path.display(),
                "loaded validator signing key in legacy raw-bytes format — \
                 set PYDE_VALIDATOR_PASSPHRASE and re-save to enable encryption \
                 (audit 221)"
            );
            (pk, sk)
        }
    } else {
        // Generate new validator key
        let (pk, sk) = pyde_crypto::falcon::falcon_keygen()
            .map_err(|e| format!("failed to generate validator key: {}", e))?;

        // Save in encrypted format if a passphrase is available;
        // otherwise fall back to legacy raw bytes for devnet
        // ergonomics (existing test infra doesn't set the env
        // var and shouldn't have to).
        if let Some(pass) = passphrase.as_deref().filter(|p| !p.is_empty()) {
            let keystore = crate::keystore::encrypt(&pk, &sk, pass)?;
            let json = serde_json::to_vec_pretty(&keystore)
                .map_err(|e| format!("failed to serialize keystore: {e}"))?;
            std::fs::write(&key_path, &json)
                .map_err(|e| format!("failed to write {}: {}", key_path.display(), e))?;
            info!(
                path = %key_path.display(),
                "generated and encrypted new validator signing key"
            );
        } else {
            let pk_bytes = pk.as_bytes();
            let sk_bytes = sk.as_bytes();
            let mut buf = Vec::with_capacity(4 + pk_bytes.len() + sk_bytes.len());
            buf.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(pk_bytes);
            buf.extend_from_slice(sk_bytes);
            std::fs::write(&key_path, &buf)
                .map_err(|e| format!("failed to write {}: {}", key_path.display(), e))?;
            info!(
                path = %key_path.display(),
                "generated new validator signing key (unencrypted — set \
                 PYDE_VALIDATOR_PASSPHRASE for encryption)"
            );
        }

        // Tighten permissions on the key file regardless of
        // format — readable only by the owning user.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        }

        (pk, sk)
    };

    let pk_bytes = pk.as_bytes().to_vec();
    let address = pyde_account::address::derive_eoa_address(&pk_bytes);

    // Load threshold key share if available
    let share_path = datadir.join("threshold.share");
    let key_share = if share_path.exists() {
        let share_bytes = std::fs::read(&share_path)
            .map_err(|e| format!("failed to read {}: {}", share_path.display(), e))?;
        match pyde_crypto::threshold::KeyShare::from_bytes(&share_bytes) {
            Some(share) => {
                info!("loaded threshold key share for MEV protection");
                Some(share)
            }
            None => {
                warn!("invalid threshold.share file, MEV protection disabled");
                None
            }
        }
    } else {
        None
    };

    Ok(ValidatorIdentity {
        address,
        public_key: pk,
        secret_key: sk,
        committee_index: 0, // assigned when joining committee
        key_share,
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
