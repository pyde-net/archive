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

/// Audit 319: minimum committee size at which the mandatory-inclusion
/// audit (task 026) is allowed to flip the validator into "abstain
/// from voting" mode. Below this, an abstention costs more than 1/128
/// — on a 4-validator devnet/testnet committee a single abstainer
/// is 25% of the committee, well above the (committee_size −
/// quorum_threshold) dissent slack. Two abstainers stall the QC
/// entirely, so under sustained encrypted-tx load the audit's
/// false-positive rate (mempool divergence between proposer and
/// validators) deterministically blocks liveness.
///
/// 32 is calibrated so the dissent slack at the smallest enforced
/// committee is `33 - quorum_for_committee(33) = 33 - 22 = 11`
/// validators — large enough that the audit can flip ~1/3 of votes
/// and still leave the chain liveness-safe. Below 32 we degrade to
/// log-only (the warn! still fires for operator visibility, and
/// the slot-flagging helper isn't called so `select_and_vote`
/// proceeds normally).
///
/// Pre-launch testnet sweep showed sustained 40-tx/s encrypted load
/// produced 3445 audit-fail warnings over a 181 s run on a 4-node
/// committee — 0/4 votes per slot for every encrypted slot. With
/// this gate, the audit is observational only for the testnet
/// committee size; mainnet's 128-validator committee continues to
/// enforce.
const MEV_INCLUSION_MIN_ENFORCEMENT_COMMITTEE: usize = 32;

/// Audit 219 + Tier 2.4: validate `(chain_id, bootstrap_peers)` at startup.
///
/// Returns `Err` for any non-devnet chain that would launch as an
/// isolated "fork of one": no peers configured ⇒ no discovery ⇒ no
/// sync. Mainnet (`chain_id == 1`) was the original audit-219 case;
/// Tier 2.4 extends the gate to cover testnet and custom chains too,
/// because the failure mode is identical the moment outsiders are
/// expected to join — operators consistently miss `warn!`s and the
/// resulting forks are reputational disasters during testnet rollout.
///
/// Devnet (`chain_id == 31337`) is silent: laptop-local single-node
/// devnets are an explicit, intentional configuration.
///
/// Operators bringing up a brand-new testnet's first node MUST set
/// `network.bootstrap_peers = []` via a non-empty placeholder list
/// (e.g., their own multiaddr) so the gate is satisfied. This mirrors
/// the operational reality — a network with no peers and no bootstrap
/// is never a real network.
pub fn check_bootstrap_config(chain_id: u64, bootstrap_peers: &[String]) -> Result<(), String> {
    if !bootstrap_peers.is_empty() {
        return Ok(());
    }
    if chain_id == pyde_net::discovery::DEVNET_CHAIN_ID {
        return Ok(());
    }
    let label = if chain_id == pyde_net::discovery::MAINNET_CHAIN_ID {
        "mainnet"
    } else if chain_id == pyde_net::discovery::TESTNET_CHAIN_ID {
        "public testnet"
    } else {
        "non-devnet chain"
    };
    Err(format!(
        "refusing to start {} (chain_id={}) with no bootstrap peers — \
         set network.bootstrap_peers in config.toml before launch. \
         A node with no peers on a public chain produces an isolated \
         fork that cannot sync to the canonical chain. \
         For a fresh testnet bring-up, set bootstrap_peers to your \
         genesis-node multiaddr(s) before starting any peer.",
        label, chain_id
    ))
}

/// Audit 343: refuse startup when `config.toml [node].chain_id`
/// disagrees with `genesis.toml`'s chain_id. Pre-fix, the runtime
/// chain_id came from config.toml while the genesis state came
/// from genesis.toml, with no consistency check. An operator who
/// edits config.toml to set `chain_id = 7331` while genesis.toml
/// still says 31337 would run with chain_id=7331 (binding
/// signatures to that domain) against state computed for 31337 —
/// confusing self-isolation. Worse, a forged genesis.toml
/// claiming chain_id=1 would silently propagate onto mainnet's
/// domain. The helper is split out so the comparison can be
/// unit-tested without spinning up `PydeNode::run()`.
pub fn check_config_genesis_chain_id_match(
    config_chain_id: u64,
    genesis_chain_id: u64,
) -> Result<(), String> {
    if config_chain_id != genesis_chain_id {
        return Err(format!(
            "chain_id mismatch (audit 343): config.toml says {} but genesis.toml says {} — \
             refusing to start. Either update config.toml to match the genesis chain_id, \
             or regenerate the genesis bundle with `pyde testnet --chain-id {}`.",
            config_chain_id, genesis_chain_id, config_chain_id,
        ));
    }
    Ok(())
}

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

        // Audit 219: hard-refuse to start a mainnet node with no
        // bootstrap peers configured. Run this BEFORE any subsystem
        // init so a misconfigured launch fails loudly at the first
        // line of node startup, not after datadir/keystore/swarm
        // setup partially completes.
        check_bootstrap_config(
            self.config.node.chain_id,
            &self.config.network.bootstrap_peers,
        )?;

        // Ensure data directory exists
        let datadir = &self.config.node.datadir;
        std::fs::create_dir_all(datadir)
            .map_err(|e| format!("failed to create datadir {}: {}", datadir.display(), e))?;

        // --- Initialize subsystems ---

        // 1. Load validator identity early (needed for genesis funding)
        let early_validator_identity = if is_validator {
            Some(load_validator_identity(datadir, self.config.node.chain_id)?)
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

        // Audit 343: refuse to start if config.toml's chain_id
        // disagrees with genesis.toml's.
        check_config_genesis_chain_id_match(self.config.node.chain_id, genesis_config.chain_id)?;

        // 3. Block store (persistent headers on disk). Arc'd so the
        // RPC layer can read full block bodies without a second open.
        let block_store = Arc::new(BlockStore::open(datadir)?);
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

        // Reconstructed full blocks awaiting QC, keyed by block hash.
        //
        // HotStuff QC-gated apply: a peer's compact block is
        // reassembled into a full Block on receipt, but apply is
        // deferred until the slot's vote-QC forms. Without this,
        // non-proposer validators applied the proposer's block
        // eagerly on gossip — chain_head advanced past current_slot
        // before their own slot tick fired, hitting the
        // `current_slot <= chain_head` skip in the proposer-build
        // loop and collapsing the cluster into single-leader chains
        // (one validator wins 100%, never rotates). The proposer's
        // own self-apply path remains at the slot tick (it needs
        // the post-execution state_root for its own header) — for
        // the proposer-loses-VRF case, the QC-formed handler
        // detects a chain/QC mismatch and rolls back via
        // chain.revert + state.revert_to before applying the
        // canonical block. The map is keyed by block_hash so the
        // QC handler can look up the real body that matches the
        // QC's hash; falls back to the audit-234 synthesized
        // empty-body path when the body hasn't arrived yet
        // (e.g., RR fallback delivered the QC vote before the
        // gossip block body).
        //
        // Bounded by a slot-window prune in the maintenance tick
        // so a stalled gossip peer can't pile up bodies forever.
        let pending_block_bodies: Arc<
            RwLock<std::collections::HashMap<[u8; 32], pyde_consensus::block::Block>>,
        > = Arc::new(RwLock::new(std::collections::HashMap::new()));

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

        // Audit 234 follow-up: persistent peer book. Loaded at
        // startup (used to seed the dial list below); populated
        // on every `ConnectionEstablished`; persisted on a 30 s
        // tick + at shutdown so a future restart can re-dial the
        // exact peer set without relying on bootstrap+DHT to
        // re-discover every edge.
        let mut peer_book = crate::peer_book::PeerBook::load(&self.config.node.datadir);

        // Audit 234 follow-up: gossip-publish cache. Stashes
        // consensus / Blocks topic messages whose `gossipsub.publish`
        // returned `InsufficientPeers` (the post-restart
        // SUBSCRIBE-arrival race documented in rust-libp2p #5097).
        // Replayed when a `gossipsub::Event::Subscribed` for the
        // matching topic arrives — i.e. when the race finally
        // resolves itself via heartbeat-driven re-subscription.
        // Mirrors Lighthouse (Eth2 consensus client)'s
        // `GossipCache` pattern.
        let mut gossip_cache = crate::gossip_cache::GossipCache::new();

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

            let mut engine = ValidatorEngine::new(self.config.node.chain_id, [0xAA; 32]); // devnet epoch randomness

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

        // Audit 341: full-node header validation requires committee
        // keys + epoch randomness too. Pre-fix only validators ran
        // `validate_network_block`, so a non-validator full node
        // accepted any block whose header signature was bytes-shaped
        // — a Byzantine peer could feed it a block with a bogus
        // proposer (FALCON-signed by a stranger key, VRF-faked, QC
        // empty) and the full node would persist + relay it. The
        // audit fix is "always validate"; for that we need
        // committee_keys + epoch_randomness on every node, not just
        // validators. Recompute the committee from `genesis_config`
        // — same logic the validator branch above runs. Devnet uses
        // a fixed epoch_randomness of `[0xAA; 32]`; production
        // networks rotate it via threshold randomness shares
        // (audit 320/322 finalize the binding). For testnet we
        // anchor to the genesis committee; full nodes that need
        // post-rotation accuracy will rebuild the committee on
        // epoch boundary just like validators.
        let mut committee_keys_for_validation: Vec<Vec<u8>> = Vec::new();
        if !genesis_config.validators.is_empty() {
            for val in genesis_config.validators.iter() {
                let pk_bytes =
                    hex::decode(val.public_key.strip_prefix("0x").unwrap_or(&val.public_key))
                        .map_err(|e| format!("invalid validator pk in genesis: {}", e))?;
                committee_keys_for_validation.push(pk_bytes);
            }
        }
        let epoch_randomness_for_validation: [u8; 32] = [0xAA; 32];

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
            // Audit 234 part 4 step 7: defer to the crate-default
            // (5s post-step-7) instead of the prior hardcoded 60s.
            // The hardcode kept stale post-restart QUIC connections
            // alive long enough to block 4-of-4 churn recovery.
            idle_timeout: pyde_net::config::DEFAULT_IDLE_TIMEOUT,
            rate_limit_per_ip: self.config.network.rate_limit_per_ip,
            bootstrap_peers: self.config.network.bootstrap_peers.clone(),
            is_validator,
            // Audit 340: bake chain_id into the identify
            // protocol-version so cross-chain peers can be
            // detected at handshake time.
            chain_id: self.config.node.chain_id,
        };

        // 6. Create libp2p swarm
        let (mut swarm, local_peer_id) = create_node(&net_config, keypair)?;
        info!(%local_peer_id, port = self.config.network.port, "P2P transport ready");

        // 7. Subscribe to gossipsub topics
        subscribe_topics(&mut swarm, is_validator)?;
        info!("gossipsub topics subscribed");

        // 8. Dial bootstrap peers. Audit 219: the
        // `check_bootstrap_config` call earlier in `run()` already
        // hard-refused mainnet starts with no peers and warned for
        // other non-devnet chains, so by the time we reach this
        // point an empty list means devnet — which is fine for a
        // single-node local devnet.
        if !self.config.network.bootstrap_peers.is_empty() {
            pyde_net::node::dial_bootstrap_peers(&mut swarm, &self.config.network.bootstrap_peers);
        }

        // 8b. Audit 234 follow-up: also dial every peer the previous
        // run ended up connected to. Bootstrap is the seed list (a
        // few well-known validators); the peer book is the *full*
        // set of edges the previous run had — including peers we
        // discovered via DHT and might not be in the static
        // bootstrap config. Without this, a restarted small-
        // committee node can come back missing one or two edges,
        // which is invisible until a different node dies.
        // Skip-if-already-connected is handled inside
        // `redial_saved_peers` so a peer in BOTH bootstrap and the
        // book isn't dialed twice.
        if !peer_book.is_empty() {
            redial_saved_peers(&mut swarm, &peer_book);
        }

        // 9. Listen on all interfaces — hybrid TCP + QUIC (audit 234
        // part 4 step 7r). TCP is the default for bootstrap-multiaddr
        // resolution; QUIC is available so peers that prefer it can
        // negotiate it from a `/udp/PORT/quic-v1` address.
        //
        // In dev mode, bind only to loopback and skip QUIC entirely.
        // Two reasons:
        //  - 0.0.0.0 binds advertise every reachable interface
        //    (loopback + LAN + others) via Identify. With every node
        //    running on the same host, peers learn 2-3 addresses for
        //    each other, then libp2p races dials across all of them
        //    and dedupes the losers — producing ~4 connection flaps
        //    per second on a fully meshed 4-node localhost devnet,
        //    enough to keep gossipsub mesh formation in constant
        //    churn and drop ~33% of consensus messages.
        //  - QUIC + TCP simultaneously is the same problem one
        //    layer down: same peer reachable via two transports,
        //    libp2p tries both. Single-transport dev mode dodges
        //    that race.
        // Production binds remain on 0.0.0.0 with both transports
        // because real peers come from different hosts and the
        // multi-address advertising is what makes connectivity work
        // through NAT/firewall paths.
        let bind_ip = if self.config.node.dev_mode {
            "127.0.0.1"
        } else {
            "0.0.0.0"
        };
        let tcp_listen_addr: libp2p::Multiaddr =
            format!("/ip4/{}/tcp/{}", bind_ip, self.config.network.port)
                .parse()
                .map_err(|e| format!("invalid tcp listen addr: {}", e))?;
        swarm
            .listen_on(tcp_listen_addr)
            .map_err(|e| format!("failed to listen on tcp: {}", e))?;

        if !self.config.node.dev_mode {
            let quic_listen_addr: libp2p::Multiaddr =
                format!("/ip4/0.0.0.0/udp/{}/quic-v1", self.config.network.port)
                    .parse()
                    .map_err(|e| format!("invalid quic listen addr: {}", e))?;
            if let Err(e) = swarm.listen_on(quic_listen_addr) {
                // QUIC bind failure is non-fatal — TCP is the primary
                // transport. Log so operators know but keep going.
                warn!(error = %e, port = self.config.network.port, "QUIC listen failed; running TCP-only");
            }
        }

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
                block_store: block_store.clone(),
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
            "connect with: --bootstrap \"/ip4/127.0.0.1/tcp/{}/p2p/{}\"",
            self.config.network.port, local_peer_id
        );

        // --- Main event loop ---
        let mut shutdown_rx = self.shutdown.subscribe();

        // Slot clock for block timing. If resuming from persisted head,
        // Audit 399: derive the slot_clock anchor from the most
        // recent block's `header.timestamp` minus
        // `head_slot * block_time_ms`. block.timestamp is set by
        // the proposer to `current_time_ms()` at proposal time, so
        // it's a real Unix-ms wall-clock; subtracting
        // `head_slot * block_time_ms` recovers the original
        // genesis_instant. All validators that observed the same
        // chain land on the same anchor.
        //
        // Pre-fix the slot_clock was backdated from `saved_head *
        // block_time_ms` against `now`, anchoring slot 0 to "now -
        // saved_head*400ms". After a restart, the backdated
        // anchor sat further forward in wall-clock than the
        // continuously-running validators' anchor (their
        // genesis_instant had been "their startup wall-clock"),
        // so a restarted node-0's `current_slot()` returned
        // `saved_head` even when the live network was many slots
        // ahead. `select_and_vote` keys off
        // `consensus.current_slot` (which tracks the slot_clock),
        // so the restarted validator kept voting on stale slots —
        // a 4-of-4 cluster with one node down + one node muted by
        // this clock skew dropped below 3-of-4 quorum and stalled.
        //
        // Audit 400: anchor the slot_clock to the genesis timestamp
        // for BOTH fresh-start and resume paths. The previous
        // fresh-start branch returned `0`, which made
        // `SlotClock::with_block_time` fall back to anchoring slot 0
        // at the per-node `Instant::now()` — a stagger between
        // operators (4 minutes is enough) became hundreds of slots
        // of permanent skew because each node's `current_slot()`
        // walked from a different wall-clock origin. With genesis
        // now stamped at bundle-generation time (see
        // `generate_testnet`), every node can anchor its
        // slot_clock at the SAME absolute Unix-ms regardless of
        // when its host booted.
        //
        // Resume: prefer the head block's `header.timestamp` minus
        // `head_slot * block_time_ms` (audit-399); fall back to
        // `now - head_slot * block_time_ms` if the header was
        // unstamped. Fresh start: read `genesis_config.timestamp`
        // (`chain.header(0)` returns None because the genesis block
        // isn't inserted into the chain's `headers` map). Final
        // fallback ("anchor at now") only fires for legacy bundles
        // with an unstamped genesis AND no saved head — i.e., the
        // dev-loop / in-process-test case.
        let block_time_ms = self.config.consensus.block_time_ms;
        let now_ms_for_anchor = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let head_block_ts = if saved_head > 0 {
            chain
                .read()
                .await
                .header(saved_head)
                .map(|h| h.timestamp)
                .unwrap_or(0)
        } else {
            genesis_config.timestamp
        };
        let slot_clock_anchor_ms = if head_block_ts > 0 {
            head_block_ts.saturating_sub(saved_head * block_time_ms)
        } else if saved_head > 0 {
            now_ms_for_anchor.saturating_sub(saved_head * block_time_ms)
        } else {
            0
        };
        let slot_clock = SlotClock::with_block_time(slot_clock_anchor_ms, block_time_ms);
        info!(
            saved_head,
            head_block_ts,
            slot_clock_anchor_ms,
            now_ms = now_ms_for_anchor,
            initial_slot = slot_clock.current_slot(),
            "slot_clock initialized"
        );
        // Audit 408: hand the validator engine the same wall-clock
        // anchor the slot clock uses, so its `advance_target_height`
        // resets the proposal-timeout tracker to the new slot's
        // actual start (genesis_ts + N * block_time) rather than
        // wall-clock "now". Without this, the timer for slot N
        // begins counting at the moment slot N-1's QC formed —
        // which is typically 50–150 ms into slot N-1, so the 200 ms
        // PROPOSAL_TIMEOUT fires ~50 ms BEFORE slot N starts and
        // every other slot view-changes spuriously. See the
        // `slot_start_ms_for_target` helper in validator.rs.
        if let Some(engine) = validator_engine.as_mut() {
            engine.set_slot_anchor(slot_clock_anchor_ms, block_time_ms);
        }
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
        // Audit 234 follow-up: snapshot the peer book to disk every
        // 5 s. Aggressive enough that a node killed soon after
        // startup (validator-churn tests warm up in ~12 s, then
        // start killing) still has the freshly-observed peer set
        // persisted; coarse enough that I/O cost is negligible
        // (one small JSON write per 5 s = nothing). `kill -9` loses
        // at most 5 s of new observations.
        let mut peer_book_snapshot_interval =
            tokio::time::interval(std::time::Duration::from_secs(5));
        // First tick fires immediately on `interval()`; consume it
        // here so the next firing is 5 s later, not on the very
        // first poll of the select loop. (Without this we'd save
        // an empty book at t=0 and then an immediate save at t=5
        // — harmless but wasteful.)
        peer_book_snapshot_interval.tick().await;

        // Audit 234 follow-up: prune expired entries from the
        // gossip cache. Catches the case where a topic never gets
        // re-subscribed (e.g. all peers permanently disconnected)
        // — without periodic pruning, those entries would pin
        // memory until the next `drain_topic` walked past them.
        let mut gossip_cache_prune_interval =
            tokio::time::interval(std::time::Duration::from_secs(15));
        gossip_cache_prune_interval.tick().await; // skip immediate first firing

        // Audit 319 follow-up: rebroadcast our decryption shares for
        // pending decryptors that haven't reached threshold yet.
        // Pre-fix the share broadcast was a single best-effort
        // gossipsub publish at decryptor-bootstrap time; a
        // gossipsub mesh that drops 1-3% of messages occasionally
        // leaves a validator's decryptor with < threshold shares
        // and no recovery path — encrypted_txs in that block silently
        // never decrypt for that validator, producing the cross-node
        // state divergence the audit flags.
        //
        // 250 ms (≈ 0.6 slot at 400 ms block time) tunes for the
        // tension between (a) collapsing divergence fast enough that
        // the loadgen test's eager-exit-on-node-0-full polling loop
        // sees every node converged, and (b) not flooding the
        // consensus topic. Each retry sends ~50 KB for a full
        // 40-tx block (1 share per tx × 1280 B per share); at 4
        // hz that's 200 KB/s sustained worst-case per validator
        // with stuck decryptors, which is well inside gossipsub's
        // headroom. The retry self-heals: once a decryptor reaches
        // threshold, it's removed from `pending_decryptors` and the
        // tick stops emitting for that slot. Shares are deterministic
        // from `(key_share, ciphertext)` so regeneration is cheap
        // and `BlockDecryptor::add_share` is idempotent (set-insert)
        // on the receiver side.
        let mut decryption_share_retry_interval =
            tokio::time::interval(std::time::Duration::from_millis(100));
        decryption_share_retry_interval.tick().await; // skip immediate first firing

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
                            &committee_keys_for_validation,
                            &epoch_randomness_for_validation,
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
                        PostEventAction::ReplayCachedGossip(topic) => {
                            // Audit 234 follow-up: race-resolution
                            // replay. Drain every cached message
                            // for this topic and re-publish via the
                            // standard fan-out (gossipsub + RR).
                            // If the second publish ALSO hits
                            // `InsufficientPeers`, the helpers
                            // re-stash — bounded by the per-message
                            // TTL, so a permanent topic-empty
                            // condition can't loop forever.
                            let entries = gossip_cache.drain_topic(&topic);
                            if !entries.is_empty() {
                                debug!(
                                    %topic,
                                    count = entries.len(),
                                    "replaying cached gossip after Subscribed event"
                                );
                                for data in entries {
                                    // Reconstruct an IdentTopic from the
                                    // hash by trying each known channel —
                                    // gossipsub identifies topics via hash
                                    // but `publish` wants a typed topic.
                                    // This is the same pattern used at
                                    // the Message-arm receive site.
                                    let consensus_topic = pyde_net::node::topics::consensus();
                                    let blocks_topic = pyde_net::node::topics::blocks();
                                    if topic == consensus_topic.hash() {
                                        broadcast_consensus_with_rr_fallback(
                                            &mut swarm,
                                            consensus_topic,
                                            data,
                                            &peer_manager,
                                            &mut gossip_cache,
                                        );
                                    } else if topic == blocks_topic.hash() {
                                        broadcast_blocks_with_rr_fallback(
                                            &mut swarm,
                                            blocks_topic,
                                            data,
                                            &mut gossip_cache,
                                        );
                                    }
                                    // Other topics (transactions, sync)
                                    // aren't cached — txs have their own
                                    // gossip-retry path; sync is RR-only.
                                }
                            }
                        }
                        PostEventAction::AddExplicitGossipPeer(peer_id) => {
                            // Audit 234 follow-up: pin a FALCON-
                            // attested validator into gossipsub's
                            // mesh. Explicit peers bypass scoring +
                            // heartbeat-based pruning and stay in the
                            // mesh as long as the connection is up.
                            // `add_explicit_peer` immediately emits a
                            // GRAFT control frame on every subscribed
                            // topic, so messages start flowing without
                            // waiting for a fresh SUBSCRIBE handshake.
                            // Symmetric: when we attest to *them*,
                            // their AddExplicitGossipPeer fires and
                            // they pin us back.
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            debug!(%peer_id, "pinned validator into gossipsub mesh (explicit peer)");
                        }
                        PostEventAction::RecordPeerAndAuth { peer_id, multiaddr } => {
                            // Audit 234 follow-up: persist the (peer, addr)
                            // pair so a future restart re-dials it directly.
                            // The book is snapshot to disk on a 30 s tick +
                            // at shutdown.
                            peer_book.record(peer_id, multiaddr);
                            // Same auth-handshake kick that the original
                            // ConnectionEstablished arm did before the
                            // peer-book promotion was added.
                            if let std::collections::hash_map::Entry::Vacant(e) = pending_auth_nonces.entry(peer_id) {
                                let nonce = pyde_net::auth::generate_nonce();
                                e.insert(nonce);
                                let req = pyde_net::auth::PydeAuthReq { nonce };
                                let _ = swarm.behaviour_mut().auth.send_request(&peer_id, req);
                            }
                            // Audit 396: also poll this peer for their
                            // chain tip. Without this kick, a fresh full
                            // node connects, never learns the network is
                            // ahead, sync_manager.network_tip stays at 0
                            // (`is_behind` returns false), no GetBlocks
                            // is ever sent — the node sits at slot 0
                            // forever even though peers have a long
                            // chain to share. The PostEventAction
                            // variant existed for this purpose but was
                            // never produced anywhere, so the cold-sync
                            // path was dead from day one.
                            chain_sync.request_chain_tip(&mut swarm, peer_id);
                        }
                        PostEventAction::SendAuthResponse(channel, resp) => {
                            let _ = swarm.behaviour_mut().auth.send_response(channel, resp);
                        }
                        PostEventAction::SendConsensusRrResponse(channel, resp) => {
                            let _ = swarm.behaviour_mut().consensus_rr.send_response(channel, resp);
                        }
                        PostEventAction::SendConsensusRrResponseAndBroadcast(channel, resp, data) => {
                            let _ = swarm.behaviour_mut().consensus_rr.send_response(channel, resp);
                            let topic = pyde_net::node::topics::consensus();
                            broadcast_consensus_with_rr_fallback(
                                &mut swarm,
                                topic,
                                data,
                                &peer_manager,
                            &mut gossip_cache,
                            );
                        }
                        PostEventAction::SendConsensusRrResponseAndApplyQcd(
                            channel,
                            resp,
                            qc_slot,
                            qc_block_hash,
                        ) => {
                            // Path A: RR-receive of a Vote closed the soft
                            // QC. Ack the RR sender, then run the same
                            // canonical-apply orchestration as the
                            // gossipsub `ApplyCanonicalAfterQc` handler at
                            // line ~1190. The shared sub-helpers take a
                            // `log_tag` to distinguish call sites in
                            // operator logs.
                            let _ = swarm.behaviour_mut().consensus_rr.send_response(channel, resp);
                            // Audit 408: mirror the own-vote-QC path's
                            // synthesize-empty-body fallback so QC
                            // application is deterministic across all
                            // nodes regardless of which node's own vote
                            // closed the QC. The fallback is gated on
                            // `header.tx_root == EMPTY_TX_ROOT` so it
                            // only applies for blocks the proposer
                            // committed to as empty (view-change empty
                            // blocks, idle slots) — `compute_tx_root`
                            // returns `[0u8; 32]` exactly when both
                            // plaintext txs and encrypted-tx hashes are
                            // empty (`pyde_consensus::block::compute_tx_root`).
                            // For non-empty bodies we MUST wait on the
                            // gossip-delivered body: pre-fix the
                            // synthesize fallback applied an empty body
                            // for any block the body buffer didn't hold,
                            // and `process_full_block_…` doesn't verify
                            // tx_root, so non-empty payloads silently
                            // committed wrong state on the fallback path.
                            const EMPTY_TX_ROOT: [u8; 32] = [0u8; 32];
                            let block = {
                                let pbb = pending_block_bodies.read().await;
                                pbb.get(&qc_block_hash).cloned()
                            }
                            .or_else(|| {
                                let engine = validator_engine.as_ref()?;
                                let (header, sig) =
                                    engine.buffered_proposal_for(qc_slot, &qc_block_hash)?;
                                if header.tx_root != EMPTY_TX_ROOT {
                                    return None;
                                }
                                Some(pyde_consensus::block::Block {
                                    header,
                                    body: pyde_consensus::block::BlockBody {
                                        transactions: vec![],
                                        encrypted_txs: vec![],
                                        execution_schedule:
                                            pyde_tx::parallel::ExecutionSchedule {
                                                groups: vec![],
                                                total_txs: 0,
                                            },
                                    },
                                    proposer_signature: sig,
                                })
                            });
                            let block = match block {
                                Some(b) => b,
                                None => {
                                    debug!(
                                        qc_slot,
                                        "RR-QC canonical apply: body unavailable (sync will recover)"
                                    );
                                    continue;
                                }
                            };
                            let mut chain_w = chain.write().await;
                            let mut state_w = state.write().await;
                            if chain_w.head_slot >= qc_slot {
                                drop(state_w);
                                drop(chain_w);
                                continue;
                            }
                            let ws_slot = validator_engine
                                .as_ref()
                                .and_then(|e| e.finality.latest_checkpoint.as_ref().map(|c| c.slot));
                            match BlockProcessor::process_full_block_with_aot_and_checkpoint(
                                &mut chain_w,
                                &mut state_w,
                                &block,
                                Some(&aot_cache),
                                ws_slot,
                            ) {
                                Ok((tc, gas, ref receipts_list)) => {
                                    let pending_writes = state_w.take_pending_writes();
                                    let smt_handle = state_w.smt_handle();
                                    drop(state_w);
                                    drop(chain_w);
                                    commit_jmt_writes(&state, smt_handle, pending_writes).await;
                                    persist_block_and_receipts(
                                        &block_store,
                                        &mut chain_sync,
                                        &receipts,
                                        &block,
                                        qc_slot,
                                        receipts_list,
                                    )
                                    .await;
                                    emit_ws_events(
                                        &ws_heads,
                                        &ws_logs,
                                        &block,
                                        qc_slot,
                                        tc,
                                        receipts_list,
                                    );
                                    prune_committed_txs(
                                        &mempool_index,
                                        &pending_txs,
                                        &pending_tx_times,
                                        &tx_relay,
                                        &block,
                                    )
                                    .await;
                                    {
                                        let mut pbb = pending_block_bodies.write().await;
                                        pbb.remove(&qc_block_hash);
                                    }
                                    info!(
                                        slot = qc_slot,
                                        txs = tc,
                                        gas,
                                        proposer = hex::encode(block.header.proposer),
                                        "applied block from QC (canonical, RR path)"
                                    );
                                    cast_finality_vote_and_persist(
                                        &mut validator_engine,
                                        &validator_identity,
                                        &state,
                                        &block_store,
                                        &mut swarm,
                                        &peer_manager,
                                        &mut gossip_cache,
                                        qc_slot,
                                        qc_block_hash,
                                        " (RR path)",
                                    )
                                    .await;
                                    maybe_kick_decryption_pipeline(
                                        &mut validator_engine,
                                        &validator_identity,
                                        &queued_shares,
                                        &pending_decryptors,
                                        &mut swarm,
                                        &peer_manager,
                                        &mut gossip_cache,
                                        &block,
                                        qc_slot,
                                        " (RR path)",
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    drop(state_w);
                                    drop(chain_w);
                                    debug!(
                                        slot = qc_slot,
                                        error = %e,
                                        "RR canonical apply failed"
                                    );
                                }
                            }
                        }
                        PostEventAction::SendConsensusRrResponseAndAddShares(
                            channel,
                            resp,
                            share_msg,
                        ) => {
                            // Phase 1 hardening (audit 074b): ack the
                            // RR sender, then re-enter the same
                            // AddDecryptionShares path the gossip arm
                            // uses. Re-issuing as a PostEventAction
                            // would require a self-pump; cleaner to
                            // inline the same logic directly here. The
                            // matched bodies are kept in sync — if the
                            // gossip arm grows new behaviour, mirror it.
                            let _ = swarm.behaviour_mut().consensus_rr.send_response(channel, resp);
                            let slot = share_msg.slot;
                            let mut dec_w = pending_decryptors.write().await;
                            if let Some(decryptor) = dec_w.get_mut(&slot) {
                                for (i, share_bytes) in share_msg.shares.iter().enumerate() {
                                    if let Some(share) = pyde_crypto::threshold::DecryptionShare::from_bytes(share_bytes) {
                                        decryptor.add_share(i, share);
                                    }
                                }
                                if decryptor.all_ready() {
                                    let chain_w = chain.read().await;
                                    let base_fee = chain_w.base_fee;
                                    let chain_id = chain_w.chain_id;
                                    drop(chain_w);
                                    let proposer = block_store
                                        .get_header(slot)
                                        .map(|h| h.proposer)
                                        .unwrap_or([0u8; 32]);
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
                                    if let crate::block_processor::DecryptOutcome::Executed {
                                        tx_count,
                                        receipts: slot_receipts,
                                    } = outcome
                                    {
                                        info!(slot, txs = tx_count, "threshold reached via RR — decrypted + executed");
                                        if !slot_receipts.is_empty() {
                                            let mut receipts_w = receipts.write().await;
                                            receipts_w.insert_block_receipts(slot, slot_receipts);
                                        }
                                    }
                                    dec_w.remove(&slot);
                                }
                            } else {
                                drop(dec_w);
                                let mut q = queued_shares.write().await;
                                q.entry(slot).or_default().push(share_msg);
                            }
                        }
                        PostEventAction::SendBlocksRrResponse(channel, resp) => {
                            let _ = swarm.behaviour_mut().blocks_rr.send_response(channel, resp);
                        }
                        PostEventAction::DisconnectStalePeer(peer) => {
                            // Audit 234 part 4 step 7: force-drop the
                            // half-broken connection so the next dial is
                            // treated as "first connection" by gossipsub
                            // (which re-sends SUBSCRIBE only on first
                            // connection). Without this, the stale
                            // connection persists until QUIC keepalive
                            // fires (now 5s; was 60s pre-step-7), blocking
                            // every RR send to that peer in the meantime.
                            let _ = swarm.disconnect_peer_id(peer);
                            debug!(%peer, "force-disconnected stale peer");
                        }
                        PostEventAction::SyncedBlocksApplied {
                            receipts_batch,
                            continue_sync,
                            encrypted_blocks_to_decrypt,
                        } => {
                            // Persist receipts produced by sync-applied
                            // blocks. Held briefly under one lock — same
                            // pattern as the QC-apply branch at line ~3470.
                            if !receipts_batch.is_empty() {
                                let mut receipts_w = receipts.write().await;
                                for (slot, slot_receipts) in receipts_batch {
                                    receipts_w.insert_block_receipts(slot, slot_receipts);
                                }
                            }
                            // Audit 319: bootstrap threshold-decryption
                            // for each sync-applied block that carries
                            // encrypted txs. Pre-fix the sync path
                            // stopped at plaintext execution and never
                            // started the decryptor / share broadcast
                            // on this validator. The helper is
                            // idempotent — if the gossip path already
                            // bootstrapped the same slot first, it
                            // returns early on the
                            // `pending_decryptors.contains_key`
                            // guard — so calling it from the sync
                            // path is safe even when both paths
                            // converge on the same slot.
                            for block in encrypted_blocks_to_decrypt {
                                let qc_slot = block.header.slot;
                                maybe_kick_decryption_pipeline(
                                    &mut validator_engine,
                                    &validator_identity,
                                    &queued_shares,
                                    &pending_decryptors,
                                    &mut swarm,
                                    &peer_manager,
                                    &mut gossip_cache,
                                    &block,
                                    qc_slot,
                                    " (sync path)",
                                )
                                .await;
                            }
                            if continue_sync {
                                if let Some(next_idx) = chain_sync.needs_next_chunk() {
                                    let peer = swarm.connected_peers().next().copied();
                                    if let Some(p) = peer {
                                        chain_sync.request_next_chunk(&mut swarm, p, next_idx);
                                    }
                                } else {
                                    chain_sync.request_next_batch(&mut swarm);
                                }
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
                                broadcast_consensus_with_rr_fallback(
                                    &mut swarm,
                                    topic,
                                    data,
                                    &peer_manager,
                                &mut gossip_cache,
                                );
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
                                    broadcast_consensus_with_rr_fallback(
                                        &mut swarm,
                                        topic.clone(),
                                        data,
                                        &peer_manager,
                                    &mut gossip_cache,
                                    );
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
                        PostEventAction::ApplyCanonicalAfterQc {
                            qc_slot,
                            qc_block_hash,
                        } => {
                            // Path A canonical apply. The body is split
                            // into focused sub-helpers (commit_jmt_writes,
                            // persist_block_and_receipts, emit_ws_events,
                            // prune_committed_txs, cast_finality_vote_and_persist,
                            // maybe_kick_decryption_pipeline) so this
                            // handler reads as the orchestration layer
                            // it is. Same body runs from the
                            // RR-fallback handler at line ~780 with a
                            // different log_tag.
                            // Audit 408: same `EMPTY_TX_ROOT`-gated
                            // synthesize fallback as the RR-QC path
                            // above. Both paths must apply view-change
                            // empty blocks identically. Non-empty bodies
                            // still wait on gossip — see the rationale
                            // attached to the RR-QC version.
                            const EMPTY_TX_ROOT: [u8; 32] = [0u8; 32];
                            let block = {
                                let pbb = pending_block_bodies.read().await;
                                pbb.get(&qc_block_hash).cloned()
                            }
                            .or_else(|| {
                                let engine = validator_engine.as_ref()?;
                                let (header, sig) =
                                    engine.buffered_proposal_for(qc_slot, &qc_block_hash)?;
                                if header.tx_root != EMPTY_TX_ROOT {
                                    return None;
                                }
                                Some(pyde_consensus::block::Block {
                                    header,
                                    body: pyde_consensus::block::BlockBody {
                                        transactions: vec![],
                                        encrypted_txs: vec![],
                                        execution_schedule:
                                            pyde_tx::parallel::ExecutionSchedule {
                                                groups: vec![],
                                                total_txs: 0,
                                            },
                                    },
                                    proposer_signature: sig,
                                })
                            });
                            let block = match block {
                                Some(b) => b,
                                None => {
                                    debug!(
                                        qc_slot,
                                        "ApplyCanonicalAfterQc: body unavailable (sync will recover)"
                                    );
                                    continue;
                                }
                            };
                            let mut chain_w = chain.write().await;
                            let mut state_w = state.write().await;
                            // Skip if we've already applied this slot
                            // (e.g. the own-vote-QC inline path got there
                            // first this turn).
                            if chain_w.head_slot >= qc_slot {
                                drop(state_w);
                                drop(chain_w);
                                continue;
                            }
                            let ws_slot = validator_engine
                                .as_ref()
                                .and_then(|e| e.finality.latest_checkpoint.as_ref().map(|c| c.slot));
                            match BlockProcessor::process_full_block_with_aot_and_checkpoint(
                                &mut chain_w,
                                &mut state_w,
                                &block,
                                Some(&aot_cache),
                                ws_slot,
                            ) {
                                Ok((tc, gas, ref receipts_list)) => {
                                    let pending_writes = state_w.take_pending_writes();
                                    let smt_handle = state_w.smt_handle();
                                    drop(state_w);
                                    drop(chain_w);
                                    commit_jmt_writes(&state, smt_handle, pending_writes).await;
                                    persist_block_and_receipts(
                                        &block_store,
                                        &mut chain_sync,
                                        &receipts,
                                        &block,
                                        qc_slot,
                                        receipts_list,
                                    )
                                    .await;
                                    emit_ws_events(
                                        &ws_heads,
                                        &ws_logs,
                                        &block,
                                        qc_slot,
                                        tc,
                                        receipts_list,
                                    );
                                    prune_committed_txs(
                                        &mempool_index,
                                        &pending_txs,
                                        &pending_tx_times,
                                        &tx_relay,
                                        &block,
                                    )
                                    .await;
                                    {
                                        let mut pbb = pending_block_bodies.write().await;
                                        pbb.remove(&qc_block_hash);
                                    }
                                    info!(
                                        slot = qc_slot,
                                        txs = tc,
                                        gas,
                                        proposer = hex::encode(block.header.proposer),
                                        "applied block from QC (canonical)"
                                    );
                                    cast_finality_vote_and_persist(
                                        &mut validator_engine,
                                        &validator_identity,
                                        &state,
                                        &block_store,
                                        &mut swarm,
                                        &peer_manager,
                                        &mut gossip_cache,
                                        qc_slot,
                                        qc_block_hash,
                                        "",
                                    )
                                    .await;
                                    maybe_kick_decryption_pipeline(
                                        &mut validator_engine,
                                        &validator_identity,
                                        &queued_shares,
                                        &pending_decryptors,
                                        &mut swarm,
                                        &peer_manager,
                                        &mut gossip_cache,
                                        &block,
                                        qc_slot,
                                        "",
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    drop(state_w);
                                    drop(chain_w);
                                    debug!(
                                        slot = qc_slot,
                                        error = %e,
                                        "canonical apply failed"
                                    );
                                }
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
                            // Audit 384: route through the same
                            // `encrypted_tx_ingest_policy` as the RPC
                            // ingress so the devnet/production split
                            // can't drift between the three call
                            // sites. On any non-devnet chain_id this
                            // function maps `None` sender_pk to
                            // `Reject`, so the structural-only path
                            // is unreachable on mainnet.
                            let accepted = match crate::rpc::encrypted_tx_ingest_policy(
                                sender_pk_opt,
                                chain_id,
                            ) {
                                crate::rpc::EncryptedTxIngestPolicy::Verify(pk) => {
                                    relay.receive_tx_verified(enc_tx, &pk)
                                }
                                crate::rpc::EncryptedTxIngestPolicy::StructuralOnly => {
                                    relay.receive_tx(enc_tx)
                                }
                                crate::rpc::EncryptedTxIngestPolicy::Reject => {
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
                            //
                            // We must dial only ONE address per peer. Identify
                            // commonly returns multiple paths to the same node
                            // (loopback + LAN + WAN), and parallel-dialing all
                            // of them races libp2p's connection-deduplication:
                            // both dials succeed, the second is force-closed
                            // with `ApplicationClosed`, both ends log
                            // "peer disconnected", and gossipsub re-meshes.
                            // On a 4-node localhost devnet this produced ~1.5
                            // connect/disconnect cycles per second per peer
                            // and dropped ~80% of consensus messages, since
                            // the mesh was never stable for a full slot.
                            //
                            // libp2p maintains the rest of the address list in
                            // Kademlia (lines above), and on dial-failure it
                            // walks alternatives via `DialOpts::addresses`
                            // automatically, so dropping addresses here costs
                            // nothing.
                            //
                            // Loopback is preferred for same-host peers — when
                            // a peer announces `/ip4/127.0.0.1/...` alongside
                            // a LAN address, the loopback path always wins on
                            // latency and avoids NAT/firewall variability.
                            if !swarm.is_connected(&peer_id) {
                                // Same peer-id ordering as
                                // `dial_bootstrap_peers`: only the
                                // lower peer-id dials, the higher
                                // accepts inbound. Identify-driven
                                // discovery can race with bootstrap on
                                // a fresh devnet (peer learns of us
                                // via DHT before our outbound from
                                // bootstrap completes), and a parallel
                                // dial in either direction triggers
                                // the same dedupe-and-flap problem.
                                let local = *swarm.local_peer_id();
                                if local < peer_id {
                                    let dial_addr = addrs
                                        .iter()
                                        .find(|a| {
                                            a.iter().any(|p| {
                                                matches!(
                                                    p,
                                                    libp2p::multiaddr::Protocol::Ip4(ip)
                                                        if ip.is_loopback()
                                                )
                                            })
                                        })
                                        .cloned()
                                        .or_else(|| addrs.first().cloned());
                                    if let Some(addr) = dial_addr {
                                        if let Err(e) = swarm.dial(addr) {
                                            debug!(error = %e, "failed to dial discovered peer");
                                        }
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
                            // Audit 396: a compact block far ahead of
                            // our current head is a "we missed
                            // something" signal, but it's a PROPOSAL
                            // (not a finalized block) so we can't
                            // bump `network_tip` to its slot directly
                            // — `network_tip` should track finalized
                            // heads, not proposed-but-not-QC'd slots.
                            // Pre-fix the direct `update_network_tip`
                            // here triggered GetBlocks for the
                            // proposed slot, sync server returned
                            // NotFound (full block doesn't exist
                            // anywhere until QC + apply), and the
                            // tight retry loop starved the consensus
                            // message handler — a 4-of-4 committee
                            // with one dead node stalled because the
                            // live validators couldn't drain their
                            // vote queues.
                            //
                            // Instead: re-poll a peer for their
                            // canonical chain tip. The response
                            // (`SyncResp::ChainTip`) reports
                            // `chain.head_slot` — the peer's highest
                            // applied block — which is what
                            // `network_tip` should reflect. If the
                            // peer is genuinely ahead, sync engages
                            // for the right slots; if the peer is at
                            // the same head as us (we just got a
                            // proposal-in-flight), `is_behind`
                            // returns false and sync stays idle.
                            // The "head + 1" exclusion catches the
                            // common natural-next-slot proposal
                            // without an extra round-trip.
                            let local_head = chain.read().await.head_slot;
                            if slot > local_head.saturating_add(1) {
                                let first_peer: Option<libp2p::PeerId> =
                                    swarm.connected_peers().next().copied();
                                if let Some(peer) = first_peer {
                                    chain_sync.request_chain_tip(&mut swarm, peer);
                                }
                            }

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
                            //
                            // Audit 319: gate the abstention on
                            // committee size. The "soft" framing
                            // assumes a 128-validator committee
                            // where a 1-validator abstain costs
                            // ~0.78%. On the 4-node testnet commit-
                            // tee, 1 abstainer is 25% (already
                            // close to the 33% slack) and 2 stall
                            // the QC entirely. Sustained 40-tx/s
                            // encrypted load produces enough mem-
                            // pool divergence between proposer and
                            // validators that 3445 audit-fail
                            // warnings fired in a 181 s run, with
                            // every encrypted-tx slot blocked by
                            // unanimous abstention — chain advanced
                            // on plaintext only and inclusion
                            // dropped to 0%. Below
                            // `MEV_INCLUSION_MIN_ENFORCEMENT_COMMITTEE`
                            // we keep the audit observational only
                            // (log + metric) so the testnet stays
                            // live; mainnet's 128-validator commit-
                            // tee continues to abstain on flagged
                            // slots.
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
                                    let committee_size = engine.committee_keys.len();
                                    let enforce = committee_size
                                        >= MEV_INCLUSION_MIN_ENFORCEMENT_COMMITTEE;
                                    if enforce {
                                        warn!(
                                            slot,
                                            missing = audit.missing_older_than_grace.len(),
                                            gas_remaining = audit.gas_remaining,
                                            committee_size,
                                            "mandatory-inclusion audit failed — skipping vote for this slot"
                                        );
                                        engine.flag_inclusion_violation(slot);
                                    } else {
                                        debug!(
                                            slot,
                                            missing = audit.missing_older_than_grace.len(),
                                            gas_remaining = audit.gas_remaining,
                                            committee_size,
                                            min_enforce = MEV_INCLUSION_MIN_ENFORCEMENT_COMMITTEE,
                                            "mandatory-inclusion audit failed — observational only on small committee (audit 319)"
                                        );
                                    }
                                }
                            }

                            // QC-gated apply: buffer the reconstructed
                            // block, don't mutate chain or state yet.
                            // The slot's vote-QC formation handler
                            // (`select_and_vote` + the QC-formed branch
                            // below) is responsible for applying
                            // whichever block_hash the committee voted
                            // for. Eager-applying here would race the
                            // proposer-selection loop on every other
                            // validator and collapse the cluster into a
                            // leader-takes-all chain (see the
                            // `pending_block_bodies` declaration up top
                            // for the failure mode this replaces).
                            //
                            // We still need the inclusion-audit logic
                            // ABOVE this point (it sets `inclusion_violated`
                            // on the engine so the vote phase abstains
                            // for slots that skipped mandatory txs) —
                            // that part doesn't depend on apply.
                            //
                            // mempool / tx-relay cleanup that previously
                            // ran on this branch is now done in the
                            // QC-formed apply path so it fires once,
                            // for the canonical block, regardless of
                            // who proposed.
                            {
                                let mut pbb = pending_block_bodies.write().await;
                                pbb.insert(block_hash, block.clone());
                            }
                            debug!(
                                slot,
                                block_hash = hex::encode(block_hash),
                                txs = block.body.transactions.len(),
                                encrypted = block.body.encrypted_txs.len(),
                                "compact block reconstructed and buffered (awaiting QC)"
                            );
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
                                    broadcast_consensus_with_rr_fallback(
                                        &mut swarm,
                                        topic,
                                        msg,
                                        &peer_manager,
                                    &mut gossip_cache,
                                    );
                                    debug!(target_epoch, "re-broadcast resharing contribution");
                                }
                            }

                            // Audit 406: re-broadcast our PSS contribution
                            // during the same window. Without this a
                            // dropped gossip message strands a peer's pool
                            // at n-1 and the all-N apply guard blocks
                            // PSS for the epoch — the share stays valid
                            // (resharing already produced it) but the
                            // genesis-trust-dissolution intent of PSS
                            // doesn't fire. The rebroadcast loop here
                            // closes that gap with the same window cross-
                            // committee resharing already uses.
                            if let Some((target_epoch, bytes)) = engine.maybe_rebroadcast_pss() {
                                if is_validator {
                                    let msg = wire::encode_pss_refresh(target_epoch, &bytes);
                                    let topic = pyde_net::node::topics::consensus();
                                    broadcast_consensus_with_rr_fallback(
                                        &mut swarm,
                                        topic,
                                        msg,
                                        &peer_manager,
                                        &mut gossip_cache,
                                    );
                                    debug!(target_epoch, "re-broadcast PSS contribution");
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

                            // Audit 406: deterministic PSS apply trigger.
                            // Same first-N-wins race that audit 403 fixed for
                            // randomness and `try_aggregate_reshare_on_slot`
                            // fixes for cross-committee resharing — eagerly
                            // applying the first `threshold` PSS contributions
                            // produced different "first 3-of-4" subsets across
                            // nodes under async gossip, leaving each
                            // validator's share on a different polynomial and
                            // breaking threshold decryption (every block of
                            // encrypted txs failed to combine, even with all
                            // 4 shares present). Waiting through the same
                            // RESHARE_AGGREGATION_DELAY_SLOTS lets gossipsub
                            // deliver every contribution to every node before
                            // we run the canonical-subset apply.
                            if let Some(identity) = validator_identity.as_mut() {
                                engine.try_apply_pss_on_slot(current_slot, identity);
                            }

                            // Audit 403: deterministically finalize the
                            // buffered epoch-randomness shares once gossip
                            // has had time to converge. Without this, every
                            // node finalized on the FIRST 3-of-N shares it
                            // saw — and gossipsub delivered those in
                            // different orders to different validators,
                            // producing split-brain randomness. The
                            // canonical-subset combine inside the engine
                            // makes this fire identically on every node.
                            if let Some(new_randomness) =
                                engine.try_finalize_randomness_on_slot(current_slot)
                            {
                                info!(
                                    randomness = hex::encode(new_randomness),
                                    "epoch randomness updated"
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
                                        // Audit 402: rotate atomically — the engine
                                        // (a) saves the outgoing committee keys +
                                        //     epoch_randomness into prior-epoch
                                        //     caches so the boundary block's
                                        //     `qc_previous` (signed by the prior
                                        //     committee) still verifies, and
                                        // (b) swaps the buffered `next_epoch_randomness`
                                        //     (written by `on_randomness_share`
                                        //     during the prior epoch) into
                                        //     `epoch_randomness` so the new epoch
                                        //     starts with stable, agreed-upon VRF
                                        //     input — eliminating the proposer/
                                        //     verifier randomness drift that wedged
                                        //     the chain at slot 1000 in the soak.
                                        engine.rotate_to_epoch(new_epoch, new_keys.clone());
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
                                            // Generate and broadcast epoch randomness share.
                                            // audit-234 part 4 step 4: RR fallback
                                            // applied uniformly to every consensus-topic
                                            // publish so epoch transitions don't stall
                                            // on mesh degradation.
                                            if let Some(share) = engine.start_epoch_randomness(new_epoch + 1, identity) {
                                                let share_bytes = wire::encode_randomness_share(new_epoch + 1, &share);
                                                let topic = pyde_net::node::topics::consensus();
                                                broadcast_consensus_with_rr_fallback(
                                                    &mut swarm,
                                                    topic,
                                                    share_bytes,
                                                    &peer_manager,
                                                &mut gossip_cache,
                                                );
                                            }

                                            // Generate and broadcast PSS refresh contribution
                                            // (rotates threshold key shares so genesis trust dissolves)
                                            if let Some(contrib) = engine.start_pss_refresh(new_epoch + 1, identity) {
                                                let contrib_bytes = wire::encode_pss_refresh(new_epoch + 1, &contrib.to_bytes());
                                                let topic = pyde_net::node::topics::consensus();
                                                broadcast_consensus_with_rr_fallback(
                                                    &mut swarm,
                                                    topic,
                                                    contrib_bytes,
                                                    &peer_manager,
                                                &mut gossip_cache,
                                                );
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
                                                    broadcast_consensus_with_rr_fallback(
                                                        &mut swarm,
                                                        topic,
                                                        contrib_bytes,
                                                        &peer_manager,
                                                    &mut gossip_cache,
                                                    );
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

                                    // Also collect encrypted txs from the threshold-encrypted mempool.
                                    //
                                    // The MAX_ENCRYPTED_TXS_PER_BLOCK cap is what stops the
                                    // chain from wedging above the per-validator decrypt-apply
                                    // throughput: without it, gas-only selection greedily
                                    // fills up to ~16 K encrypted-tx-equivalents per block,
                                    // but receive-side decrypt+apply takes ~3-5 ms per tx
                                    // and can't keep up with the proposer. `prune_committed_
                                    // txs` then never fires for the in-flight set, so the
                                    // proposer keeps re-selecting the same set every slot
                                    // and the chain falls indefinitely behind. See the
                                    // const's doc-comment in `pyde-mempool::pool` for the
                                    // measurement that motivates the value.
                                    let encrypted_blobs = {
                                        let relay_r = tx_relay.read().await;
                                        let selected = relay_r.mempool().select_for_block(
                                            gas_ceiling,
                                            pyde_mempool::pool::MAX_ENCRYPTED_TXS_PER_BLOCK,
                                            current_slot,
                                        );
                                        // Serialize each EncryptedTx to bytes for block inclusion
                                        selected.iter().map(|etx| etx.to_bytes()).collect::<Vec<Vec<u8>>>()
                                    };

                                    // Always produce blocks to advance the chain.
                                    // Empty blocks are needed for QC chain progression.
                                    {
                                    let _tx_count = txs.len();

                                    // Build block with transactions
                                    //
                                    // `parent_hash` is the Poseidon2 hash of the
                                    // parent BLOCK HEADER (per BlockHeader's doc and
                                    // the chain-linking safety check in
                                    // `pyde_consensus::hotstuff` line 342:
                                    // `next_header.parent_hash == qc_for_block.block_hash`).
                                    // The earlier code passed `chain_r.state_root`
                                    // here, which never matched the parent's block
                                    // hash — that silently broke HotStuff's
                                    // chain-linking invariant on every consecutive
                                    // block pair (the safety check was vacuously
                                    // unsatisfiable, so the protocol was
                                    // load-bearing on the audit-234 fallback paths
                                    // for liveness). Genesis falls back to all-zeros
                                    // per `Block::is_genesis`.
                                    let chain_r = chain.read().await;
                                    let parent_hash = chain_r
                                        .header(chain_r.head_slot)
                                        .map(|h| h.hash())
                                        .unwrap_or([0u8; 32]);
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

                                    // `state_root` is intentionally [0u8;32] at
                                    // proposal time — per BlockHeader's doc, the
                                    // post-execution root is set after optimistic
                                    // execution at soft finality, then verified on
                                    // re-execution and committed in the
                                    // HardFinalityCert (so the header's state_root
                                    // can't be a forged claim by the proposer).
                                    // The earlier code passed `parent_hash` (which
                                    // was already misset to parent's state_root)
                                    // here too, doubling the bug.
                                    let block = engine.build_proposal(
                                        identity,
                                        parent_hash,
                                        [0u8; 32],
                                        tx_root,
                                        vrf_data,
                                        txs,
                                        encrypted_blobs,
                                        exec_schedule,
                                    );

                                    // Path A: do NOT execute the block here.
                                    //
                                    // Per BlockHeader's design (state_root = 0
                                    // at proposal, set after optimistic
                                    // execution at soft finality, verified in
                                    // HardFinalityCert): the proposer's only
                                    // pre-soft-QC work is to schedule the
                                    // (possibly encrypted) txs and broadcast
                                    // header + commitments. Execution moves
                                    // to the post-QC canonical-apply site,
                                    // run by every validator against the
                                    // single canonical block.
                                    //
                                    // Removing the speculative self-apply:
                                    //   - eliminates the per-slot reorg
                                    //     ceremony (audit-230/231/232) for
                                    //     the steady state, since losing-VRF
                                    //     validators no longer commit a block
                                    //     that needs reverting
                                    //   - is the only structurally correct
                                    //     path for encrypted txs in mainnet
                                    //     (the proposer doesn't have the
                                    //     decryption shares yet, so it
                                    //     cannot execute the block)
                                    //   - centralizes block-side-effects
                                    //     (mempool cleanup, receipts, ws
                                    //     emits, block_store put) at the
                                    //     canonical-apply hook so they fire
                                    //     once for the canonical block,
                                    //     never for a discarded
                                    //     speculation
                                    //
                                    // We still buffer our own block in
                                    // `pending_block_bodies` so the
                                    // QC-formed apply path can find it when
                                    // we win the VRF (peers populate the
                                    // same buffer via gossip-receive).
                                    {
                                        let mut pbb = pending_block_bodies.write().await;
                                        pbb.insert(block.header.hash(), block.clone());
                                    }
                                    let slot_ms = slot_t0.elapsed().as_secs_f64() * 1000.0;
                                    info!(
                                        slot = current_slot,
                                        txs = block.body.transactions.len(),
                                        encrypted = block.body.encrypted_txs.len(),
                                        pending = pending_len,
                                        clone_ms,
                                        build_ms,
                                        slot_ms,
                                        "proposed block (awaiting QC for canonical apply)"
                                    );

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
                                    // audit-234 part 4 follow-up: compact-block
                                    // delivery via RR fallback. Without this,
                                    // post-restart mesh degradation drops the
                                    // block silently — non-proposer validators
                                    // never see the header, no QC forms.
                                    broadcast_blocks_with_rr_fallback(
                                        &mut swarm,
                                        topic.clone(),
                                        compact_bytes,
                                    &mut gossip_cache,
                                    );

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
                                        // Same RR-fallback rationale as the
                                        // compact block above.
                                        broadcast_blocks_with_rr_fallback(
                                            &mut swarm,
                                            topic,
                                            bundle_bytes,
                                        &mut gossip_cache,
                                        );
                                    }

                                    // Broadcast proposal as consensus message
                                    let proposal = pyde_consensus::hotstuff::ConsensusMessage::Proposal {
                                        header: block.header.clone(),
                                        proposer_signature: block.proposer_signature.clone(),
                                    };
                                    let proposal_bytes = wire::encode_consensus_message(&proposal);
                                    let cons_topic = pyde_net::node::topics::consensus();
                                    // audit-234 part 4 step 4: own-proposal is
                                    // liveness-critical. Gossipsub publish on a
                                    // degraded mesh (post-restart cycles)
                                    // returns InsufficientPeers and the proposal
                                    // never reaches voters → no QC forms. Route
                                    // through the RR-fallback helper so a
                                    // gossip miss falls back to direct
                                    // request-response delivery to every known
                                    // validator peer.
                                    broadcast_consensus_with_rr_fallback(
                                        &mut swarm,
                                        cons_topic,
                                        proposal_bytes,
                                        &peer_manager,
                                    &mut gossip_cache,
                                    );

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
                                        // audit-234 part 4 step 4: same RR
                                        // fallback as own-proposal — slash
                                        // evidence missing from peers under
                                        // mesh degradation lets the offender
                                        // escape unpunished if they crash
                                        // before the next gossip retry.
                                        broadcast_consensus_with_rr_fallback(
                                            &mut swarm,
                                            topic,
                                            bytes,
                                            &peer_manager,
                                        &mut gossip_cache,
                                        );
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
                                    let (qc_formed, qc_slot_hash) = if let Some(qc) = engine.on_vote(vote.clone()) {
                                        info!(slot = current_slot, votes = qc.vote_count(), "QC formed after VRF selection");
                                        (true, Some((qc.slot, qc.block_hash)))
                                    } else {
                                        (false, None)
                                    };

                                    // Audit 234 part 4 step 7n: when a peer's
                                    // own-vote forms a QC, the proposer applies
                                    // its block locally elsewhere — but
                                    // non-proposer peers that form the same QC
                                    // never apply the block because the body
                                    // arrives via the Blocks-topic gossip path,
                                    // which is the degraded path under churn.
                                    // For blocks with empty bodies (all blocks
                                    // in this load-free test path; also any
                                    // fallback) the receiver can synthesize the
                                    // body locally and apply without waiting on
                                    // gossip. Validation inside
                                    // process_full_block_with_aot_and_checkpoint
                                    // will reject the synthesized block if the
                                    // header's tx_root doesn't commit to the
                                    // empty body — so this is safe under load
                                    // (real-tx blocks just won't apply via this
                                    // path; they wait for the compact-block
                                    // gossip/RR path as before).
                                    if let Some((qc_slot, qc_hash)) = qc_slot_hash {
                                        if let Some((header, sig)) = engine.buffered_proposal_for(qc_slot, &qc_hash) {
                                            // Prefer the real body buffered at gossip
                                            // receipt; fall back to a synthesized
                                            // empty body ONLY when the header
                                            // commits to an empty tx_root (audit
                                            // 408). `process_full_block_…` does NOT
                                            // verify tx_root, so the prior
                                            // unconditional synthesize would
                                            // silently apply an empty body for any
                                            // non-empty-tx block whose body hadn't
                                            // arrived yet — diverging state across
                                            // peers. Gate on
                                            // `compute_tx_root([], []) == [0u8; 32]`
                                            // so the fallback only fires for blocks
                                            // the proposer truly committed to as
                                            // empty (view-change empties, idle
                                            // slots).
                                            const EMPTY_TX_ROOT: [u8; 32] = [0u8; 32];
                                            let buffered_block = {
                                                let pbb = pending_block_bodies.read().await;
                                                pbb.get(&qc_hash).cloned()
                                            };
                                            let block = match buffered_block {
                                                Some(b) => b,
                                                None if header.tx_root == EMPTY_TX_ROOT => {
                                                    pyde_consensus::block::Block {
                                                        header: header.clone(),
                                                        body: pyde_consensus::block::BlockBody {
                                                            transactions: vec![],
                                                            encrypted_txs: vec![],
                                                            execution_schedule: pyde_tx::parallel::ExecutionSchedule {
                                                                groups: vec![],
                                                                total_txs: 0,
                                                            },
                                                        },
                                                        proposer_signature: sig,
                                                    }
                                                }
                                                None => {
                                                    debug!(
                                                        slot = qc_slot,
                                                        "own-vote-QC inline apply: body unavailable for non-empty block (sync will recover)"
                                                    );
                                                    continue;
                                                }
                                            };
                                            let mut chain_w = chain.write().await;
                                            let mut state_w = state.write().await;

                                            // Three cases at QC time:
                                            //   1. chain head < qc_slot — we never applied
                                            //      anything for this slot; apply forward.
                                            //   2. chain head == qc_slot && hashes match —
                                            //      we ARE the winning proposer and self-
                                            //      applied earlier in the tick (line ~2002,
                                            //      needed for our header's state_root). The
                                            //      block is already canonical; skip apply.
                                            //   3. chain head == qc_slot && hashes differ —
                                            //      we self-applied a block but lost the VRF
                                            //      tournament. Roll back the speculative
                                            //      slot via the audit-230 revert/revert_to
                                            //      pair, then apply the canonical block.
                                            //   4. chain head > qc_slot — multi-slot reorg
                                            //      territory; defer to the sync path
                                            //      instead of trying here.
                                            let need_apply = if chain_w.head_slot == qc_slot {
                                                let our_block_hash = chain_w
                                                    .header(qc_slot)
                                                    .map(|h| h.hash());
                                                if our_block_hash == Some(qc_hash) {
                                                    debug!(slot = qc_slot, "QC matches our self-applied block — already canonical");
                                                    false
                                                } else {
                                                    let target = qc_slot.saturating_sub(1);
                                                    if let Err(e) = chain_w.revert(target) {
                                                        warn!(slot = qc_slot, error = %e, "chain revert before QC apply failed");
                                                    }
                                                    match state_w.revert_to(target) {
                                                        Ok(_) => {
                                                            info!(
                                                                slot = qc_slot,
                                                                from = hex::encode(our_block_hash.unwrap_or([0u8; 32])),
                                                                to = hex::encode(qc_hash),
                                                                "rolled back speculative self-proposal — applying canonical block"
                                                            );
                                                            true
                                                        }
                                                        Err(e) => {
                                                            warn!(slot = qc_slot, error = %e, "state revert before QC apply failed");
                                                            false
                                                        }
                                                    }
                                                }
                                            } else if chain_w.head_slot < qc_slot {
                                                true
                                            } else {
                                                debug!(
                                                    qc_slot,
                                                    head = chain_w.head_slot,
                                                    "QC behind our chain head — skipping (handled by reorg path)"
                                                );
                                                false
                                            };

                                            if !need_apply {
                                                drop(state_w);
                                                drop(chain_w);
                                                // Drop buffered body even when we skip apply
                                                // (winner case: we already have the canonical
                                                // copy via self-apply; the buffered copy is
                                                // a duplicate from gossip).
                                                let mut pbb = pending_block_bodies.write().await;
                                                pbb.remove(&qc_hash);
                                                continue;
                                            }

                                            let ws_slot = engine
                                                .finality
                                                .latest_checkpoint
                                                .as_ref()
                                                .map(|cp| cp.slot);
                                            match BlockProcessor::process_full_block_with_aot_and_checkpoint(
                                                &mut chain_w,
                                                &mut state_w,
                                                &block,
                                                Some(&aot_cache),
                                                ws_slot,
                                            ) {
                                                Ok((tc, gas, ref receipts_list)) => {
                                                    let pending_writes = state_w.take_pending_writes();
                                                    let smt_handle = state_w.smt_handle();
                                                    drop(state_w);
                                                    drop(chain_w);
                                                    commit_jmt_writes(&state, smt_handle, pending_writes).await;
                                                    persist_block_and_receipts(
                                                        &block_store,
                                                        &mut chain_sync,
                                                        &receipts,
                                                        &block,
                                                        qc_slot,
                                                        receipts_list,
                                                    )
                                                    .await;
                                                    emit_ws_events(
                                                        &ws_heads,
                                                        &ws_logs,
                                                        &block,
                                                        qc_slot,
                                                        tc,
                                                        receipts_list,
                                                    );
                                                    prune_committed_txs(
                                                        &mempool_index,
                                                        &pending_txs,
                                                        &pending_tx_times,
                                                        &tx_relay,
                                                        &block,
                                                    )
                                                    .await;
                                                    {
                                                        let mut pbb = pending_block_bodies.write().await;
                                                        pbb.remove(&qc_hash);
                                                    }
                                                    info!(
                                                        slot = qc_slot,
                                                        txs = tc,
                                                        gas,
                                                        proposer = hex::encode(block.header.proposer),
                                                        "applied block from QC"
                                                    );
                                                }
                                                Err(e) => {
                                                    drop(state_w);
                                                    drop(chain_w);
                                                    debug!(slot = qc_slot, error = %e, "QC-gated apply failed");
                                                }
                                            }
                                        }
                                    }
                                    // Broadcast vote.
                                    // audit-234 part 4 step 4: own-vote is
                                    // liveness-critical (no QC without it).
                                    // Use the RR fallback helper so a gossip
                                    // miss on a degraded mesh still reaches
                                    // the next proposer.
                                    let vote_bytes = wire::encode_consensus_message(&vote);
                                    let topic = pyde_net::node::topics::consensus();
                                    broadcast_consensus_with_rr_fallback(
                                        &mut swarm,
                                        topic,
                                        vote_bytes,
                                        &peer_manager,
                                    &mut gossip_cache,
                                    );

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
                                        // The finality vote's state_root must be
                                        // this validator's ACTUAL post-execution
                                        // root, not chain.state_root. After the
                                        // proposer-header fix, chain.state_root is
                                        // 0x00…00 (per BlockHeader's "empty at
                                        // proposal" semantics), so all validators
                                        // would otherwise sign a zero state_root,
                                        // making `try_form_hard_finality`'s
                                        // state-root agreement check vacuous and
                                        // letting any validator's divergent state
                                        // be included in the cert. Reading
                                        // `state.root()` is the canonical
                                        // post-commit SMT root — every honest
                                        // validator that executed the block
                                        // deterministically produces the same
                                        // value; honest-but-divergent validators
                                        // have their votes correctly excluded
                                        // from the cert.
                                        let state_root = state.read().await.root();
                                        if let Some(fv) = engine.create_finality_vote(
                                            current_slot,
                                            engine.consensus.highest_qc.block_hash,
                                            state_root,
                                            identity,
                                        ) {
                                            let cert_formed = engine.on_finality_vote(fv.clone());
                                            let fv_bytes = wire::encode_finality_vote(&fv);
                                            let topic = pyde_net::node::topics::consensus();
                                            // audit-234 part 4 step 4: finality
                                            // vote/cert via RR fallback. Hard
                                            // finality progress is what
                                            // anchors the WS checkpoint;
                                            // dropping these on a degraded
                                            // mesh leaves nodes unable to
                                            // advance past their last anchor.
                                            broadcast_consensus_with_rr_fallback(
                                                &mut swarm,
                                                topic.clone(),
                                                fv_bytes,
                                                &peer_manager,
                                            &mut gossip_cache,
                                            );
                                            if cert_formed {
                                                if let Some(cp) = engine.latest_finality_checkpoint() {
                                                    let _ = block_store.put_finality_cert(cp);
                                                    let cp_bytes =
                                                        wire::encode_finality_checkpoint_msg(cp);
                                                    broadcast_consensus_with_rr_fallback(
                                                        &mut swarm,
                                                        topic,
                                                        cp_bytes,
                                                        &peer_manager,
                                                    &mut gossip_cache,
                                                    );
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

                                                            // Broadcast our shares.
                                                            // audit-234 part 4 step 4: RR
                                                            // fallback for decryption shares
                                                            // — without these reaching the
                                                            // committee, encrypted txs never
                                                            // decrypt and the MEV path stalls.
                                                            if let Some(shares) = engine.generate_decryption_shares(identity, &enc_txs) {
                                                                let msg = wire::DecryptionShareMsg {
                                                                    slot: current_slot,
                                                                    member_index: identity.committee_index,
                                                                    shares: shares.iter().map(|s| s.to_bytes()).collect(),
                                                                };
                                                                let share_bytes = wire::encode_decryption_shares(&msg);
                                                                let topic = pyde_net::node::topics::consensus();
                                                                broadcast_consensus_with_rr_fallback(
                                                                    &mut swarm,
                                                                    topic,
                                                                    share_bytes,
                                                                    &peer_manager,
                                                                &mut gossip_cache,
                                                                );
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
                                                                            // Audit 332: same overlay+undo
                                                                            // discipline as the block_processor
                                                                            // path. Pre-fix this loop wrote each
                                                                            // decrypted tx directly into
                                                                            // `state_w.smt_mut()`, bypassing the
                                                                            // StateManager write-cache and
                                                                            // skipping `record_block_undo`. A
                                                                            // reorg via `revert_to(slot - 1)`
                                                                            // would leave decrypted-tx state
                                                                            // applied even after rolling the
                                                                            // surrounding block back, producing
                                                                            // a divergent state.
                                                                            use pyde_state::smt::StateAccess;
                                                                            let mut overlay =
                                                                                pyde_state::smt::StateOverlay::new(
                                                                                    &*state_w as &dyn StateAccess,
                                                                                );
                                                                            let mut tx_receipts = Vec::with_capacity(
                                                                                decrypted_txs.len(),
                                                                            );
                                                                            for dtx in &decrypted_txs {
                                                                                let exec_result = pyde_tx::pipeline::execute_transaction(
                                                                                    dtx,
                                                                                    &mut overlay,
                                                                                    &block_ctx,
                                                                                );
                                                                                match exec_result {
                                                                                    Ok(receipt) => tx_receipts.push(receipt),
                                                                                    Err(e) => {
                                                                                        warn!(error = ?e, "failed to execute decrypted tx");
                                                                                    }
                                                                                }
                                                                            }
                                                                            let (writes, undo) =
                                                                                overlay.into_writes_with_undo();
                                                                            if !writes.is_empty() {
                                                                                let _ = state_w
                                                                                    .update_batch_deferred(writes);
                                                                            }
                                                                            if !undo.is_empty() {
                                                                                state_w.record_block_undo(
                                                                                    current_slot, undo,
                                                                                );
                                                                            }
                                                                            // Persist receipts after the overlay
                                                                            // commit so the caller sees them
                                                                            // alongside the new state.
                                                                            if !tx_receipts.is_empty() {
                                                                                let mut receipts_w =
                                                                                    receipts.write().await;
                                                                                receipts_w.insert_block_receipts(
                                                                                    current_slot,
                                                                                    tx_receipts,
                                                                                );
                                                                            }
                                                                            // Flush deferred writes before
                                                                            // recomputing root; the overlay
                                                                            // path buffers via
                                                                            // `update_batch_deferred` so the
                                                                            // SMT/JMT root only reflects them
                                                                            // after `flush_pending`.
                                                                            let _ = state_w.flush_pending();
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
                                            highest_qc: vc_msg.highest_qc.clone(),
                                            signature: vc_msg.signature.clone(),
                                        }
                                    );
                                    let topic = pyde_net::node::topics::consensus();
                                    broadcast_consensus_with_rr_fallback(
                                        &mut swarm,
                                        topic,
                                        vc_bytes,
                                        &peer_manager,
                                    &mut gossip_cache,
                                    );
                                    // audit 234 part 3: also process our own
                                    // view-change message locally — gossipsub
                                    // doesn't echo published messages back to
                                    // us, so without this our own vote is
                                    // missing from the local view-change-QC
                                    // formation, leaving us short of quorum
                                    // by one. With small committees this is
                                    // the difference between QC forming and
                                    // not.
                                    engine.on_view_change(vc_msg);
                                }
                                // audit 234 part 3: regardless of whether we
                                // just timed out, attempt to build a fallback
                                // proposal if the conditions are met (we have
                                // a view-change-QC for the current slot AND
                                // we are the deterministic fallback proposer).
                                // Catches the case where QC formed asynchronously
                                // via a previous receive event but the build
                                // didn't fire from there for any reason.
                                if let Some(identity) = validator_identity.as_ref() {
                                    let parent_hash = chain
                                        .read()
                                        .await
                                        .headers
                                        .get(&chain.read().await.head_slot)
                                        .map(|h| h.hash())
                                        .unwrap_or([0u8; 32]);
                                    let state_root = chain.read().await.state_root;
                                    if let Some(block) = engine.try_build_fallback_proposal(
                                        identity,
                                        parent_hash,
                                        state_root,
                                    ) {
                                        let header = block.header.clone();
                                        let header_bytes = wire::encode_block_header(&header);
                                        let proposer_sig = block.proposer_signature.clone();
                                        let fallback_slot = header.slot;

                                        // 1) Broadcast Proposal (header + sig) on
                                        //    consensus topic so peers can vote on
                                        //    the (slot, view) — same as before.
                                        let bytes = wire::encode_consensus_message(
                                            &pyde_consensus::hotstuff::ConsensusMessage::Proposal {
                                                header: header.clone(),
                                                proposer_signature: proposer_sig.clone(),
                                            },
                                        );
                                        let cons_topic = pyde_net::node::topics::consensus();
                                        broadcast_consensus_with_rr_fallback(
                                            &mut swarm,
                                            cons_topic,
                                            bytes,
                                            &peer_manager,
                                        &mut gossip_cache,
                                        );

                                        // 2) Audit 234 part 4 step 7m: ALSO
                                        //    broadcast the full block as a
                                        //    CompactBlock on the Blocks topic.
                                        //    Without this, peers can vote on the
                                        //    fallback header but never APPLY the
                                        //    block to chain.head — vote-QCs were
                                        //    forming on peers (29 in best run)
                                        //    but chain didn't advance because no
                                        //    block was ever broadcast for them
                                        //    to apply. Empty-body fallback is
                                        //    representable as a CompactBlock
                                        //    with 0 short_tx_ids.
                                        let compact = pyde_net::propagation::CompactBlock::from_block(
                                            header_bytes,
                                            &[], // no tx hashes (empty fallback)
                                            &[],
                                            &[],
                                        );
                                        let compact_bytes = wire::encode_compact_block(&compact);
                                        let blocks_topic = pyde_net::node::topics::blocks();
                                        broadcast_blocks_with_rr_fallback(
                                            &mut swarm,
                                            blocks_topic,
                                            compact_bytes,
                                        &mut gossip_cache,
                                        );

                                        // 3) Apply the block locally so the
                                        //    proposer's chain.head advances.
                                        //    Mirrors the regular self-proposal
                                        //    path at the slot tick — fallback
                                        //    needs the same so chain progress
                                        //    isn't predicated on receiving the
                                        //    block back via gossip.
                                        let mut chain_w = chain.write().await;
                                        let mut state_w = state.write().await;
                                        let ws_slot = engine
                                            .finality
                                            .latest_checkpoint
                                            .as_ref()
                                            .map(|cp| cp.slot);
                                        if let Err(e) = BlockProcessor::process_full_block_with_aot_and_checkpoint(
                                            &mut chain_w,
                                            &mut state_w,
                                            &block,
                                            Some(&aot_cache),
                                            ws_slot,
                                        ) {
                                            warn!(slot = fallback_slot, error = %e, "failed to process own fallback block");
                                        } else {
                                            let _ = state_w.flush_pending();
                                            state_w.refresh_root();
                                            let _ = block_store.put_header(&header);
                                            let _ = block_store.put_head(fallback_slot);
                                            chain_sync.on_block_processed(fallback_slot);
                                            info!(slot = fallback_slot, "applied own fallback block");
                                        }
                                        drop(state_w);
                                        drop(chain_w);
                                    }
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
                    // Audit 234 part 4 step 7: re-dial bootstrap peers
                    // every 2s, unconditional. Earlier "skip if
                    // already connected" version regressed (chain
                    // advancement 1→0, VC-QC formation 6→0). Reason:
                    // libp2p still considers stale post-restart
                    // connections "connected" even when their
                    // substreams can't carry traffic, so the skip
                    // hid them from the redial path. Re-dialing an
                    // already-connected peer triggers libp2p's own
                    // connection-state reconciliation — the resulting
                    // churn is what actually repairs the mesh.
                    pyde_net::node::dial_bootstrap_peers(
                        &mut swarm,
                        &self.config.network.bootstrap_peers,
                    );

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
                        // Prune QC-gated apply buffer. Same window — a body
                        // that hasn't been QC'd within 100 slots is from a
                        // losing/stale proposal that no future QC will pull.
                        let mut pbb = pending_block_bodies.write().await;
                        pbb.retain(|_, block| block.header.slot + 100 > head);
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
                _ = gossip_cache_prune_interval.tick() => {
                    // Drop expired entries so a topic with no live
                    // subscribers doesn't pin stale messages.
                    let before = gossip_cache.len();
                    gossip_cache.prune_expired();
                    let after = gossip_cache.len();
                    if before != after {
                        debug!(
                            pruned = before - after,
                            remaining = after,
                            "gossip cache pruned"
                        );
                    }
                }
                _ = peer_book_snapshot_interval.tick() => {
                    // Audit 234 follow-up: persist the (peer_id,
                    // multiaddr) set so a future restart redials the
                    // exact peer set instead of waiting for
                    // bootstrap+DHT to re-discover every edge. Errors
                    // logged but non-fatal — the previous snapshot on
                    // disk remains valid; we'll retry on the next tick.
                    if let Err(e) = peer_book.save(&self.config.node.datadir) {
                        warn!(error = %e, "peer book snapshot failed");
                    }
                }
                _ = decryption_share_retry_interval.tick() => {
                    // Audit 319 follow-up: re-broadcast our decryption
                    // shares for any pending decryptor that hasn't
                    // reached threshold yet. Closes the gossipsub
                    // 1-3% loss window where a single share-broadcast
                    // miss leaves the cluster's per-slot share count
                    // below threshold and the encrypted_txs in that
                    // block silently never decrypt for the affected
                    // validator(s) — the cross-node state divergence
                    // the audit flags. Shares are deterministic from
                    // (key_share, ciphertext) so regeneration is
                    // cheap; rebroadcast is idempotent on the receiver
                    // side because `BlockDecryptor::add_share` is a
                    // set-insert (duplicate adds are no-ops).
                    let Some(identity) = validator_identity.as_ref() else {
                        continue;
                    };
                    if identity.key_share.is_none() {
                        continue;
                    }
                    let stuck_slots: Vec<u64> = {
                        let dec_r = pending_decryptors.read().await;
                        dec_r
                            .iter()
                            .filter(|(_, d)| !d.all_ready())
                            .map(|(slot, _)| *slot)
                            .collect()
                    };
                    if stuck_slots.is_empty() {
                        continue;
                    }
                    if let Some(engine) = validator_engine.as_ref() {
                        for slot in stuck_slots {
                            // Pull encrypted_txs out of the live
                            // decryptor (the canonical source — same
                            // ordering as the one passed to
                            // BlockDecryptor::new at bootstrap).
                            let enc_txs: Vec<pyde_mempool::encrypted::EncryptedTx> = {
                                let dec_r = pending_decryptors.read().await;
                                match dec_r.get(&slot) {
                                    Some(d) => d.encrypted_txs.clone(),
                                    None => continue,
                                }
                            };
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
                                broadcast_consensus_with_rr_fallback(
                                    &mut swarm,
                                    topic,
                                    share_bytes,
                                    &peer_manager,
                                    &mut gossip_cache,
                                );
                                debug!(
                                    slot,
                                    enc_txs = enc_txs.len(),
                                    "rebroadcast decryption shares (audit 319 retry)"
                                );
                            }
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("shutdown signal received, stopping node...");
                    // Final peer-book snapshot on the way out so the
                    // most-recent observations land on disk even if
                    // we're between regular ticks. Best-effort —
                    // shutdown proceeds either way.
                    if let Err(e) = peer_book.save(&self.config.node.datadir) {
                        warn!(error = %e, "peer book final snapshot failed");
                    }
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
    /// Audit 396: emitted after a Sync RR response has been applied.
    /// Carries the per-slot receipts batch produced by sync-applied
    /// blocks so the action handler can persist them in the same
    /// ReceiptStore the QC-apply path uses, and a flag indicating
    /// whether sync should keep pulling more batches/chunks. Pre-fix
    /// the receipts were silently dropped at the on_response call
    /// site; full nodes that reached their head purely via sync had
    /// no receipts to serve over `pyde_getTransactionReceipt`.
    SyncedBlocksApplied {
        receipts_batch: Vec<(u64, Vec<pyde_tx::execution::Receipt>)>,
        continue_sync: bool,
        /// Audit 319: synced blocks whose `body.encrypted_txs` is
        /// non-empty. The action handler bootstraps the threshold-
        /// decryption pipeline for each via
        /// `maybe_kick_decryption_pipeline`. Pre-fix the sync path
        /// stopped at plaintext-tx execution and never started the
        /// decryptor / share broadcast on this validator, so the
        /// threshold across the committee stalled and the encrypted
        /// txs never decrypted. Carrying the blocks via the post-
        /// event action keeps the inner closure free of the swarm /
        /// peer-manager / gossip-cache borrows that the bootstrap
        /// helper needs.
        encrypted_blocks_to_decrypt: Vec<pyde_consensus::block::Block>,
    },
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
    /// Path A: a soft-QC just formed (via gossip Vote, RR-fallback Vote,
    /// or our own Vote closing it) and the block whose hash equals
    /// `qc_block_hash` is sitting in `pending_block_bodies`. The main
    /// loop picks it up, runs the canonical apply (validate + execute
    /// + cleanup + ws emit + finality-vote cast + audit-227 decryption
    /// share broadcast for blocks with encrypted_txs). Replaces the
    /// per-validator speculative self-apply path that used to do this
    /// at proposal time. Triggered from any QC-formation site so
    /// canonical execution happens exactly once per slot per node.
    ApplyCanonicalAfterQc {
        qc_slot: u64,
        qc_block_hash: [u8; 32],
    },
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
    /// Audit 234 part 3: ack for an inbound consensus RR request.
    /// Main loop dispatches via the swarm's ConsensusRr behaviour.
    SendConsensusRrResponse(
        request_response::ResponseChannel<pyde_net::consensus_protocol::ConsensusResp>,
        pyde_net::consensus_protocol::ConsensusResp,
    ),
    /// Audit 234 part 3: an RR-receive of a Timeout caused a
    /// view-change-QC to form, AND we are the deterministic
    /// fallback proposer. The runtime acks the RR request and
    /// broadcasts the fallback proposal in the same dispatch.
    SendConsensusRrResponseAndBroadcast(
        request_response::ResponseChannel<pyde_net::consensus_protocol::ConsensusResp>,
        pyde_net::consensus_protocol::ConsensusResp,
        Vec<u8>,
    ),
    /// Path A: an RR-receive of a Vote closed the soft QC. The
    /// runtime acks the RR request and triggers the canonical apply
    /// (process_full_block + side effects + finality vote) for
    /// `(qc_slot, qc_block_hash)`. Same body as
    /// `ApplyCanonicalAfterQc`, just sent alongside the RR ack so
    /// the requester sees the response without us having to drop
    /// the channel.
    SendConsensusRrResponseAndApplyQcd(
        request_response::ResponseChannel<pyde_net::consensus_protocol::ConsensusResp>,
        pyde_net::consensus_protocol::ConsensusResp,
        u64,
        [u8; 32],
    ),
    /// Phase 1 hardening (audit 074b): decryption shares delivered
    /// via RR fallback. The runtime acks the RR request and routes
    /// the decoded `DecryptionShareMsg` through the same handler
    /// the gossip path uses so dedup + threshold + decrypt-execute
    /// all run identically.
    SendConsensusRrResponseAndAddShares(
        request_response::ResponseChannel<pyde_net::consensus_protocol::ConsensusResp>,
        pyde_net::consensus_protocol::ConsensusResp,
        wire::DecryptionShareMsg,
    ),
    /// Audit 234 part 4 step 7: drop a peer's connection so libp2p
    /// will redial fresh. Triggered when a request-response message
    /// fails (timeout / connection-closed / etc.) — the peer is
    /// in the post-restart half-broken state where `connected_peers()`
    /// still lists them but substreams can't carry traffic. Dropping
    /// the connection makes the subsequent reconnect a "first
    /// connection" so gossipsub re-broadcasts SUBSCRIBE control
    /// messages to repair the mesh.
    DisconnectStalePeer(PeerId),
    /// Audit 234 part 4 follow-up: BlocksRr ack-only path. Used when
    /// the request had a decode error — the receive arm for valid
    /// payloads drops the channel and returns the existing
    /// ReconstructCompactBlock / BufferEncryptedBundle actions
    /// directly (they reuse the heavy gossipsub-receive handlers).
    /// Sacrificing the ack on valid payloads is acceptable because
    /// libp2p RR's per-stream timeout handles the dropped channel,
    /// and the receive-side processing has already happened by the
    /// time the requester sees the OutboundFailure.
    SendBlocksRrResponse(
        request_response::ResponseChannel<pyde_net::blocks_protocol::BlocksResp>,
        pyde_net::blocks_protocol::BlocksResp,
    ),
    /// Audit 234 follow-up: record a `(PeerId, Multiaddr)` pair into the
    /// persistent peer book AND fire the FALCON auth handshake (task
    /// 029). Both are side-effects of `SwarmEvent::ConnectionEstablished`;
    /// the runtime executes them as a unit so the auth-gated peer-book
    /// promotion in `OnPeerAuthenticated` can correlate the freshly-
    /// recorded `peer_id` with the authentication outcome.
    ///
    /// The book is persisted on a coarse cadence + at shutdown and
    /// re-dialed at next startup, so a restarted validator restores
    /// all its connections instead of relying on bootstrap+DHT to
    /// re-discover every peer (which can leave one edge missing in
    /// small committees and stall consensus when a different node
    /// dies).
    RecordPeerAndAuth {
        peer_id: PeerId,
        multiaddr: libp2p::Multiaddr,
    },
    /// Audit 234 follow-up: promote a FALCON-attested validator to
    /// gossipsub's `explicit_peers` list. Explicit peers are pinned
    /// into the topic mesh regardless of scoring, heartbeat-based
    /// pruning, or transient SUBSCRIBE-control-frame loss after
    /// restart. `add_explicit_peer` immediately emits a GRAFT on
    /// every subscribed topic, so messages start flowing without
    /// waiting for the next gossipsub heartbeat.
    ///
    /// Modelled on the validator-mesh-stability pattern Lighthouse
    /// (Eth2 consensus client) and the other Eth2 clients use:
    /// validators always pin each other into mesh, restart
    /// recovery is automatic.
    AddExplicitGossipPeer(PeerId),
    /// Audit 234 follow-up: a peer just subscribed to `topic`. Drain
    /// any messages we previously stashed for this topic (because
    /// `gossipsub.publish` returned `InsufficientPeers` at the time)
    /// and re-publish them. Closes the post-restart SUBSCRIBE-arrival
    /// race by absorbing the window: we hold messages until we know
    /// someone is listening, then send.
    ReplayCachedGossip(libp2p::gossipsub::TopicHash),
}

/// Publish a consensus message via gossipsub; on `InsufficientPeers`
/// (audit 234 part 3 — peer subscription state hasn't re-synced after
/// restart cycles), fall back to direct point-to-point delivery via
/// the consensus_rr request-response protocol to every authenticated
/// validator peer. Without this fallback, view-change and proposal
/// gossip can silently drop in the small window after restarts where
/// libp2p gossipsub's `topic_peers[consensus]` map is empty even
/// though TCP-level connections to validators are live.
/// Audit 234 part 3: when a view-change-QC just formed, build the
/// empty fallback block (if we are the deterministic fallback
/// proposer) and return its wire-encoded `ConsensusMessage::
/// Proposal` ready for broadcast. Returns None if we're not the
/// fallback or we've already proposed.
fn build_and_encode_fallback_proposal(
    engine: &mut ValidatorEngine,
    identity: Option<&ValidatorIdentity>,
    chain: &ChainState,
) -> Option<Vec<u8>> {
    let identity = identity?;
    let parent_hash = chain
        .headers
        .get(&chain.head_slot)
        .map(|h| h.hash())
        .unwrap_or([0u8; 32]);
    // state_root is intentionally [0u8;32] at proposal time — see the
    // primary `build_proposal` call site for the rationale.
    let block = engine.try_build_fallback_proposal(identity, parent_hash, [0u8; 32])?;
    let msg = pyde_consensus::hotstuff::ConsensusMessage::Proposal {
        header: block.header,
        proposer_signature: block.proposer_signature,
    };
    Some(wire::encode_consensus_message(&msg))
}

/// Path A canonical-apply sub-helper: synchronously commit the
/// `take_pending_writes()` batch returned by `process_full_block` to
/// the JMT, refresh the cached state root.
///
/// Sync (not spawned) to close the race against any subsequent
/// rollback path — see `audit-230` rollback notes in the
/// `state_manager` module.
async fn commit_jmt_writes(
    state: &std::sync::Arc<tokio::sync::RwLock<crate::state_manager::StateManager>>,
    smt_handle: std::sync::Arc<std::sync::Mutex<pyde_state::jmt_store::PersistentJMT>>,
    pending_writes: Vec<(pyde_state::smt::Key, Vec<u8>)>,
) {
    if pending_writes.is_empty() {
        return;
    }
    let commit_start = std::time::Instant::now();
    if let Ok(root) =
        crate::state_manager::StateManager::commit_writes_to_smt(&smt_handle, pending_writes)
    {
        crate::metrics::record_state_commit_ms(commit_start.elapsed().as_millis() as u64);
        let mut sw = state.write().await;
        sw.set_root(root);
    }
}

/// Path A canonical-apply sub-helper: persist the canonical block and
/// its receipts. Updates `chain_sync` so the sync manager knows this
/// slot is committed.
async fn persist_block_and_receipts(
    block_store: &crate::block_store::BlockStore,
    chain_sync: &mut crate::sync::ChainSync,
    receipts: &std::sync::Arc<tokio::sync::RwLock<crate::receipt_store::ReceiptStore>>,
    block: &pyde_consensus::block::Block,
    qc_slot: u64,
    receipts_list: &[pyde_tx::execution::Receipt],
) {
    let full_bytes = wire::encode_block(block);
    let _ = block_store.put_block(&block.header, &full_bytes);
    let _ = block_store.put_head(qc_slot);
    chain_sync.on_block_processed(qc_slot);
    if !receipts_list.is_empty() {
        let mut receipts_w = receipts.write().await;
        receipts_w.insert_block_receipts(qc_slot, receipts_list.to_vec());
    }
}

/// Path A canonical-apply sub-helper: emit the per-block WS events
/// (head + per-receipt log entries). Sync — `broadcast::Sender::send`
/// doesn't block.
fn emit_ws_events(
    ws_heads: &tokio::sync::broadcast::Sender<serde_json::Value>,
    ws_logs: &tokio::sync::broadcast::Sender<serde_json::Value>,
    block: &pyde_consensus::block::Block,
    qc_slot: u64,
    tc: u64,
    receipts_list: &[pyde_tx::execution::Receipt],
) {
    let _ = ws_heads.send(serde_json::json!({
        "slot": format!("0x{:x}", qc_slot),
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
}

/// Path A canonical-apply sub-helper: drop committed tx hashes from the
/// plaintext mempool indices and the encrypted-tx relay. Without this,
/// committed txs would re-appear in the next block's selection set and
/// fail with `BelowWindow` (nonce already consumed).
async fn prune_committed_txs(
    mempool_index: &std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<[u8; 32], Vec<u8>>>,
    >,
    pending_txs: &std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<[u8; 32], pyde_tx::types::Transaction>>,
    >,
    pending_tx_times: &std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<[u8; 32], std::time::Instant>>,
    >,
    tx_relay: &std::sync::Arc<tokio::sync::RwLock<crate::tx_relay::TxRelay>>,
    block: &pyde_consensus::block::Block,
) {
    let tx_hashes: Vec<[u8; 32]> = block.body.transactions.iter().map(|tx| tx.hash()).collect();
    if !tx_hashes.is_empty() {
        let mut idx = mempool_index.write().await;
        for h in &tx_hashes {
            idx.remove(h);
        }
        drop(idx);
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
    if !block.body.encrypted_txs.is_empty() {
        let enc_hashes: Vec<[u8; 32]> = block
            .body
            .encrypted_txs
            .iter()
            .filter_map(|b| pyde_mempool::encrypted::EncryptedTx::from_bytes(b))
            .map(|etx| etx.hash())
            .collect();
        if !enc_hashes.is_empty() {
            let mut relay_w = tx_relay.write().await;
            relay_w.remove_included(&enc_hashes);
        }
    }
}

/// Path A canonical-apply sub-helper: cast this validator's hard-
/// finality vote with the post-canonical-apply `state.root()`,
/// broadcast it, locally aggregate via `on_finality_vote`, and on
/// cert formation persist the cert + broadcast the checkpoint to
/// non-validator peers so they advance their WS anchor.
///
/// `log_tag` distinguishes call-site origin in operator logs (e.g.
/// "" for the primary canonical-apply path, " (RR path)" for the
/// RR-fallback path).
async fn cast_finality_vote_and_persist(
    validator_engine: &mut Option<crate::validator::ValidatorEngine>,
    validator_identity: &Option<crate::validator::ValidatorIdentity>,
    state: &std::sync::Arc<tokio::sync::RwLock<crate::state_manager::StateManager>>,
    block_store: &crate::block_store::BlockStore,
    swarm: &mut libp2p::Swarm<pyde_net::node::PydeBehaviour>,
    peer_manager: &pyde_net::peer::PeerManager,
    gossip_cache: &mut crate::gossip_cache::GossipCache,
    qc_slot: u64,
    qc_block_hash: [u8; 32],
    log_tag: &str,
) {
    let (Some(engine), Some(identity)) = (validator_engine.as_mut(), validator_identity.as_ref())
    else {
        return;
    };
    let state_root = state.read().await.root();
    let Some(fv) = engine.create_finality_vote(qc_slot, qc_block_hash, state_root, identity) else {
        return;
    };
    let cert_formed = engine.on_finality_vote(fv.clone());
    let fv_bytes = wire::encode_finality_vote(&fv);
    let topic = pyde_net::node::topics::consensus();
    broadcast_consensus_with_rr_fallback(
        swarm,
        topic.clone(),
        fv_bytes,
        peer_manager,
        gossip_cache,
    );
    if !cert_formed {
        return;
    }
    let Some(cp) = engine.latest_finality_checkpoint() else {
        return;
    };
    let _ = block_store.put_finality_cert(cp);
    let cp_bytes = wire::encode_finality_checkpoint_msg(cp);
    broadcast_consensus_with_rr_fallback(swarm, topic, cp_bytes, peer_manager, gossip_cache);
    info!(
        slot = qc_slot,
        "hard finality cert formed (canonical-apply path{})", log_tag
    );
}

/// Path A canonical-apply sub-helper: kick off audit-227 threshold
/// decryption for the canonical block's encrypted_txs. No-op for
/// blocks with no encrypted txs (most testnet load) or for non-
/// committee validators that don't hold a key share.
async fn maybe_kick_decryption_pipeline(
    validator_engine: &mut Option<crate::validator::ValidatorEngine>,
    validator_identity: &Option<crate::validator::ValidatorIdentity>,
    queued_shares: &std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<u64, Vec<wire::DecryptionShareMsg>>>,
    >,
    pending_decryptors: &std::sync::Arc<
        tokio::sync::RwLock<
            std::collections::HashMap<u64, pyde_mempool::decryption::BlockDecryptor>,
        >,
    >,
    swarm: &mut libp2p::Swarm<pyde_net::node::PydeBehaviour>,
    peer_manager: &pyde_net::peer::PeerManager,
    gossip_cache: &mut crate::gossip_cache::GossipCache,
    block: &pyde_consensus::block::Block,
    qc_slot: u64,
    log_tag: &str,
) {
    if block.body.encrypted_txs.is_empty() {
        return;
    }
    if validator_identity
        .as_ref()
        .and_then(|id| id.key_share.as_ref())
        .is_none()
    {
        return;
    }
    if pending_decryptors.read().await.contains_key(&qc_slot) {
        return;
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
        error!(
            slot = qc_slot,
            "decrypt-time tx_root mismatch (canonical-apply{})", log_tag
        );
        return;
    }
    let Some(engine) = validator_engine.as_mut() else {
        return;
    };
    let identity = validator_identity.as_ref().unwrap();
    let threshold = pyde_consensus::block::quorum_for_committee(engine.committee_keys.len());
    if let Ok(mut decryptor) =
        pyde_mempool::decryption::BlockDecryptor::new(enc_txs.clone(), threshold)
    {
        if let Some(ks) = &identity.key_share {
            decryptor.add_member_shares(ks);
        }
        let mut q = queued_shares.write().await;
        if let Some(queued) = q.remove(&qc_slot) {
            for qmsg in &queued {
                for (i, sb) in qmsg.shares.iter().enumerate() {
                    if let Some(s) = pyde_crypto::threshold::DecryptionShare::from_bytes(sb) {
                        decryptor.add_share(i, s);
                    }
                }
            }
        }
        drop(q);
        pending_decryptors.write().await.insert(qc_slot, decryptor);
    }
    if let Some(shares) = engine.generate_decryption_shares(identity, &enc_txs) {
        let msg = wire::DecryptionShareMsg {
            slot: qc_slot,
            member_index: identity.committee_index,
            shares: shares.iter().map(|s| s.to_bytes()).collect(),
        };
        let share_bytes = wire::encode_decryption_shares(&msg);
        let topic = pyde_net::node::topics::consensus();
        broadcast_consensus_with_rr_fallback(swarm, topic, share_bytes, peer_manager, gossip_cache);
        info!(
            slot = qc_slot,
            enc_txs = enc_txs.len(),
            "broadcast decryption shares (canonical-apply{})",
            log_tag
        );
    }
}

fn broadcast_consensus_with_rr_fallback(
    swarm: &mut libp2p::Swarm<pyde_net::node::PydeBehaviour>,
    topic: gossipsub::IdentTopic,
    data: Vec<u8>,
    _peer_manager: &pyde_net::peer::PeerManager,
    gossip_cache: &mut crate::gossip_cache::GossipCache,
) {
    // Best-effort gossip publish (cheap fan-out via mesh). On
    // `InsufficientPeers` the message is stashed for replay when
    // a peer subscribes to the topic — see the
    // `gossipsub::Event::Subscribed` arm in `handle_swarm_event`.
    let topic_hash = topic.hash();
    if let Err(libp2p::gossipsub::PublishError::InsufficientPeers) = swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic.clone(), data.clone())
    {
        debug!(topic = %topic_hash, bytes = data.len(), "consensus publish: InsufficientPeers; stashed for replay");
        gossip_cache.stash(topic_hash, data.clone());
    }

    // audit-234 part 4 step 5 — RR fanout is **unconditional + to all
    // connected peers**, not a fallback gated on gossip publish
    // returning Err and not filtered by attested-validator role.
    //
    // Two failure modes the conservative version missed:
    //
    //   1. `gossipsub.publish` returns Ok even when `topic_peers` is
    //      empty (message accepted into the internal buffer but goes
    //      nowhere). Mesh degradation after restart cycles drops
    //      `topic_peers` to zero without raising an error → silent
    //      message loss. Fix: don't gate on Err.
    //
    //   2. On peer disconnect, `PeerManager::remove_peer` wipes the
    //      attested validator role; on reconnect the new entry
    //      defaults back to the unattested state until the FALCON
    //      auth handshake re-completes (~tens of ms, longer if
    //      QUIC connections keep timing out). Filtering by
    //      `peer_manager.validators()` during that gap returns empty
    //      → RR fan-out sends to no one. The 4-of-4 churn test
    //      reproduced exactly this: peers reconnecting with QUIC
    //      `TimedOut` errors mid-rotation, validator role transiently
    //      absent on every restart cycle, RR fan-out empty.
    //
    // Fix: send to every connected peer. The consensus message is
    // FALCON-signed and verified inside the engine (`try_form_view_
    // change_qc`, `verify_vote`), so spam from unattested peers
    // can't forge state — at worst it costs a verify per message.
    // Non-committee peers (full nodes, light clients) will decode
    // and either bail (no validator_engine) or no-op (msg from a
    // non-committee voter index). The receive handler at the
    // ConsensusRr arm already documents this: peer-level auth gating
    // would race with the auth handshake re-completion after restart
    // cycles — exactly the failure mode this fan-out exists to fix.
    //
    // Cost: at committee size N + F full nodes, each consensus
    // message is (N+F-1) RR send_requests on top of one gossip
    // publish. At N=4 (devnet) ≈3 extra messages. At N=128 (mainnet)
    // ≈127, well under 100KB per slot at FALCON sig sizes —
    // negligible against the gossip mesh's own per-message cost.
    let connected_peers: Vec<libp2p::PeerId> = swarm.connected_peers().copied().collect();
    debug!(
        n_peers = connected_peers.len(),
        "consensus broadcast: RR fanout to connected peers"
    );
    for peer in connected_peers {
        swarm.behaviour_mut().consensus_rr.send_request(
            &peer,
            pyde_net::consensus_protocol::ConsensusReq {
                bytes: data.clone(),
            },
        );
    }
}

/// Broadcast a Blocks-topic payload via gossipsub AND direct
/// request-response to every connected peer.
///
/// audit-234 part 4 follow-up: same silent-drop failure mode as the
/// consensus topic. After restart cycles, gossipsub's
/// `topic_peers[blocks]` empties without raising an error — the
/// proposer's compact block + encrypted-tx bundle vanish into a
/// no-recipient publish, the rest of the committee never sees the
/// block, votes can't form a QC against an unseen header, and the
/// chain stalls.
///
/// The gossip path stays primary for happy-path latency. The RR
/// path provides the deterministic delivery guarantee — message
/// reaches the peer or returns an explicit error to the caller. The
/// receive arm dispatches by the existing tag byte
/// (`wire::tag::COMPACT_BLOCK`, `wire::tag::ENCRYPTED_TX_BUNDLE`,
/// or full-block fallback) through the same handlers as the
/// gossipsub Blocks-topic receive arm, so callers don't need to
/// special-case fallback receipts.
///
/// Cost: at committee size N + F full nodes, each block becomes
/// (N+F-1) RR send_requests on top of one gossip publish. CompactBlock
/// is ~200 bytes per tx hash; EncryptedTxBundle is the size of the
/// encrypted_txs section. At 4-validator devnet, ≈3 extra messages
/// per block. At 128-validator mainnet, ≈127 — non-trivial bandwidth
/// at high tx counts; this can be tightened later (mesh-health
/// detection, pull-based block fetch on miss) once the silent-drop
/// failure mode is closed end-to-end.
fn broadcast_blocks_with_rr_fallback(
    swarm: &mut libp2p::Swarm<pyde_net::node::PydeBehaviour>,
    topic: gossipsub::IdentTopic,
    data: Vec<u8>,
    gossip_cache: &mut crate::gossip_cache::GossipCache,
) {
    // Best-effort gossip publish (cheap fan-out via mesh). Same
    // stash-on-InsufficientPeers pattern as the consensus
    // broadcast — without it, compact blocks silently dropped
    // post-restart never get retried even though the RR fanout
    // already ensures eventual delivery.
    let topic_hash = topic.hash();
    if let Err(libp2p::gossipsub::PublishError::InsufficientPeers) = swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic.clone(), data.clone())
    {
        debug!(topic = %topic_hash, bytes = data.len(), "blocks publish: InsufficientPeers; stashed for replay");
        gossip_cache.stash(topic_hash, data.clone());
    }

    // Unconditional RR fanout — gossipsub.publish returns Ok with
    // empty topic_peers under mesh degradation, silently dropping
    // the block. Sending to every connected peer (not just attested
    // validators) avoids racing the auth handshake on
    // disconnect/reconnect; receivers FALCON-verify the block
    // header inside `validate_network_block` before applying.
    let connected_peers: Vec<libp2p::PeerId> = swarm.connected_peers().copied().collect();
    debug!(
        n_peers = connected_peers.len(),
        bytes = data.len(),
        "blocks broadcast: RR fanout to connected peers"
    );
    for peer in connected_peers {
        swarm.behaviour_mut().blocks_rr.send_request(
            &peer,
            pyde_net::blocks_protocol::BlocksReq {
                bytes: data.clone(),
            },
        );
    }
}

/// Audit 234 follow-up: dial every peer the previous run was
/// connected to. Run once at startup, AFTER `dial_bootstrap_peers`
/// so peers in both lists aren't double-dialed (the
/// `is_connected` check below catches the duplicate).
///
/// Deliberately drops the `local_peer_id >= peer_id` dial-race
/// guard that `dial_bootstrap_peers` carries. The guard exists to
/// stop *sustained* symmetric dialing (each side periodically
/// retrying bootstrap → both sides dialing each other on every
/// retry → libp2p reaps the duplicate). This call is a one-shot
/// at startup; the worst-case race is two TCP setups for the same
/// peer, libp2p picks one, the other gets reaped — no sustained
/// flap. Skipping the guard is what fixes the
/// validator-churn-4-of-4 stall: with the guard in place,
/// whichever side has the higher PeerId waits for the other to
/// dial, but the other side isn't actively dialing us at startup
/// either, so the connection never reforms and quorum can't
/// reach 3-of-4.
fn redial_saved_peers(
    swarm: &mut libp2p::Swarm<pyde_net::node::PydeBehaviour>,
    peer_book: &crate::peer_book::PeerBook,
) {
    let local_peer_id = *swarm.local_peer_id();
    let mut dialed = 0usize;
    for (peer_id, addr) in peer_book.iter() {
        if local_peer_id == *peer_id {
            continue; // self
        }
        if swarm.is_connected(peer_id) {
            continue;
        }
        // Seed Kademlia even if dial fails — DHT can use it later.
        swarm
            .behaviour_mut()
            .kademlia
            .add_address(peer_id, addr.clone());
        match swarm.dial(addr.clone()) {
            Ok(_) => {
                dialed += 1;
                debug!(%peer_id, %addr, "redialing saved peer");
            }
            Err(e) => {
                debug!(%peer_id, %addr, error = %e, "saved-peer dial failed; bootstrap+DHT will retry");
            }
        }
    }
    info!(
        saved = peer_book.len(),
        dialed, "redialed saved peers from peer book"
    );
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
    // Audit 341: full-node validation fallback. Validators
    // override these via their engine; non-validator full nodes
    // use them to validate gossip block headers without skipping
    // the check.
    committee_keys_for_validation: &[Vec<u8>],
    epoch_randomness_for_validation: &[u8; 32],
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

                            // Validate block header (signature, VRF, proposer, QC).
                            // Audit 321: pass the expected parent_hash so the
                            // header's chain-linking invariant is enforced.
                            // For slot=1 use genesis_hash; for slot>1 use the
                            // hash of the canonical block at head_slot. None
                            // for the bootstrap case where we have no parent
                            // yet (skips the check).
                            // Audit 325: also pull the parent's timestamp
                            // (slot>1 only — the genesis header isn't kept in
                            // `chain.headers`, so slot=1 falls back to drift-
                            // only checking).
                            let (expected_parent, parent_timestamp) = if slot == 1 {
                                (Some(chain.genesis_hash), None)
                            } else if let Some(parent) = chain.header(slot - 1) {
                                (Some(parent.hash()), Some(parent.timestamp))
                            } else {
                                (None, None)
                            };
                            let now_ms = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64;
                            // Audit 341: validate the header on
                            // EVERY node, not just validators.
                            // Validators use their engine's live
                            // committee/epoch state; full nodes
                            // fall back to the
                            // genesis-derived committee +
                            // epoch_randomness loaded at startup.
                            // Skipping validation on the full-node
                            // path used to let a Byzantine peer
                            // ship a block with a bogus proposer
                            // signature past the chain head, and
                            // the full node would persist + relay
                            // it without checking.
                            let (committee_keys_ref, epoch_rand_ref): (&[Vec<u8>], &[u8; 32]) =
                                if let Some(ref engine) = validator_engine {
                                    (engine.committee_keys.as_slice(), &engine.epoch_randomness)
                                } else {
                                    (
                                        committee_keys_for_validation,
                                        epoch_randomness_for_validation,
                                    )
                                };
                            if !committee_keys_ref.is_empty() {
                                if let Err(e) = BlockProcessor::validate_network_block(
                                    chain.chain_id,
                                    &block.header,
                                    &block.proposer_signature,
                                    committee_keys_ref,
                                    epoch_rand_ref,
                                    expected_parent.as_ref(),
                                    parent_timestamp,
                                    now_ms,
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
                                            let _ = block_store.put_finality_cert(cp);
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
                                    let validator_idx = share.validator_index;
                                    debug!(
                                        epoch,
                                        validator = validator_idx,
                                        "received randomness share"
                                    );
                                    // Audit 403: receiving a share only buffers it.
                                    // Finalization is driven by the slot tick via
                                    // `try_finalize_randomness_on_slot` so all nodes
                                    // combine the same canonical set deterministically.
                                    let _accepted = engine.on_randomness_share(share);
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
                                    // Audit 406: drop stale contributions
                                    // targeted at epochs other than the
                                    // currently-active PSS refresh.
                                    // Without this an old-epoch contribution
                                    // could pass the polynomial verify
                                    // (zero-secret check is structural and
                                    // epoch-agnostic) and pollute the
                                    // canonical-subset pool, which
                                    // `try_apply_pss_on_slot` then folds
                                    // into the new share — silently breaking
                                    // decryption for every block that
                                    // follows.
                                    if epoch != engine.pss_target() {
                                        debug!(
                                            epoch,
                                            active = engine.pss_target(),
                                            "ignoring stale PSS refresh contribution"
                                        );
                                        return PostEventAction::None;
                                    }
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
                                            // Path A: under no-speculative-apply,
                                            // chain.head_slot < qc.slot at this point
                                            // (we haven't applied yet). The audit-232
                                            // mismatch path was for the speculative-
                                            // apply era; with Path A there's no
                                            // already-committed block at this slot
                                            // to mismatch. Go straight to the
                                            // canonical-apply trigger which the main
                                            // loop fulfills against the buffered
                                            // block. The audit-232 reorg machinery
                                            // remains for adversarial fork cases
                                            // where some node DID speculatively
                                            // commit (e.g. an older client) — kept
                                            // wired but no longer the steady-state
                                            // path.
                                            return PostEventAction::ApplyCanonicalAfterQc {
                                                qc_slot: slot,
                                                qc_block_hash: qc.block_hash,
                                            };
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
                                            if let Some(bytes) = build_and_encode_fallback_proposal(
                                                engine,
                                                validator_identity.as_ref(),
                                                chain,
                                            ) {
                                                return PostEventAction::BroadcastConsensus(bytes);
                                            }
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

        // --- Gossipsub: a peer subscribed to a topic ---
        SwarmEvent::Behaviour(PydeBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed {
            peer_id,
            topic,
        })) => {
            // Audit 234 follow-up: this is the moment the post-
            // restart SUBSCRIBE-arrival race resolves. Replay any
            // gossip messages we previously stashed for this topic
            // — they returned `InsufficientPeers` at publish time
            // because the peer's `topic_peers["consensus"]` entry
            // was missing on our side. Now it's there.
            debug!(%peer_id, %topic, "peer subscribed; replaying any cached gossip for topic");
            PostEventAction::ReplayCachedGossip(topic)
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
            // Audit 241: hand the snapshot path the full WS anchor
            // (slot + state_root) so it can reject snapshots that
            // either regress past the checkpoint or land on a
            // long-range fork at the anchor slot. Block-sync paths
            // still derive just the slot internally.
            let ws_checkpoint = validator_engine
                .as_ref()
                .and_then(|e| e.finality.latest_checkpoint.as_ref())
                .map(|cp| (cp.slot, cp.state_root));
            // Audit 396: on_response now returns the receipts produced
            // by sync-applied blocks. Pre-fix the `_receipts` were
            // dropped at the inner call site, so a node that reached
            // its head purely via sync (cold-start joiner, full node
            // catching up after start-up race) had no receipts to
            // serve over RPC. Returned here so the action handler can
            // persist them via the same ReceiptStore the QC-apply
            // path uses.
            // Audit 319: `on_response` now also returns the synced
            // blocks whose body has non-empty `encrypted_txs`. The
            // sync path applies plaintext txs but does NOT bootstrap
            // the threshold-decryption pipeline (BlockDecryptor +
            // share broadcast); the gossip-arrival path does that
            // in `maybe_kick_decryption_pipeline`. Without this
            // bootstrap, a validator that reaches a block via sync
            // never broadcasts decryption shares, the per-slot
            // threshold stalls, and encrypted_txs in that block
            // never decrypt — proposer keeps re-including the same
            // 40 txs at successive slots; chain advances on
            // plaintext only; balance divergence appears in
            // cross-node convergence checks. The bootstrap loop
            // below mirrors the gossip-arrival call sites (line
            // 1127, 1434) so all three apply paths now leave the
            // decryption state machine in the same shape.
            let (_processed, receipts_batch, encrypted_blocks) = chain_sync.on_response(
                request_id,
                response,
                chain,
                state,
                block_store,
                ws_checkpoint,
            );
            // Audit 399: advance the validator engine's
            // `target_height` to chain head + 1 so a restarted
            // validator that just sync-applied blocks doesn't keep
            // voting on the slot it was at before the crash. The
            // QC-apply path already advances target_height inside
            // `on_vote`'s success branch; the sync-apply path
            // bypassed that, leaving target_height pinned at the
            // pre-restart slot. Net effect: the restarted node
            // received proposals for the live network's current
            // slot but refused to vote (`select_and_vote` targets
            // `target_height`, not the wall-clock slot). With one
            // node killed AND one node effectively muted only 2 of
            // 4 validators voted, so no QC formed and the chain
            // stalled. `advance_target_height` is monotonic — it
            // no-ops if the engine already advanced past us.
            if let Some(engine) = validator_engine.as_mut() {
                let next_target = chain.head_slot.saturating_add(1);
                engine.advance_target_height_after_sync(next_target);
            }
            // Signal the event loop to continue if chunked snapshot needs
            // more chunks OR we're otherwise still syncing. Both branches
            // produced the same ContinueSync return — collapsed into a
            // single `||` expression (spotted by slice 5.5 clippy sweep).
            // Now also carries the receipts to persist alongside the
            // continue signal.
            let continue_sync = chain_sync.needs_next_chunk().is_some() || chain_sync.is_syncing();
            if !receipts_batch.is_empty() || continue_sync || !encrypted_blocks.is_empty() {
                PostEventAction::SyncedBlocksApplied {
                    receipts_batch,
                    continue_sync,
                    encrypted_blocks_to_decrypt: encrypted_blocks,
                }
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
                    // Audit 234 follow-up: pin attested validators
                    // into gossipsub's mesh so consensus messages
                    // flow even after a restart cycle leaves the
                    // peer's `topic_peers["consensus"]` state stale
                    // on the remote side.
                    return PostEventAction::AddExplicitGossipPeer(peer);
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

        // --- ConsensusRr: inbound consensus message via RR fallback ---
        // (audit 234 part 3) Restarted nodes whose gossipsub mesh state
        // hasn't fully re-synced still receive view-change messages this
        // way. The bytes are the same wire encoding as on the gossipsub
        // consensus topic so the receive logic decodes + processes
        // identically.
        SwarmEvent::Behaviour(PydeBehaviourEvent::ConsensusRr(
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            },
        )) => {
            // No peer-level auth check here — unlike the gossipsub
            // consensus topic (audit 218), the message itself is
            // FALCON-signed and verified inside `try_form_view_change_qc`
            // against the on-chain committee_keys. Spam from unattested
            // peers is bounded by libp2p RR's per-stream concurrency
            // limits + the dedup logic in `engine.on_view_change`.
            // Gating here on `is_consensus_authorized` would race with
            // the auth handshake re-completion after restart cycles —
            // exactly the failure mode this RR fallback exists to fix.
            let mut pending_fallback_broadcast: Option<Vec<u8>> = None;
            let mut pending_share_msg: Option<wire::DecryptionShareMsg> = None;
            // Path A: when an RR-fallback Vote closes the soft QC, the
            // bottom-of-arm dispatch emits a combo action that acks the
            // RR sender AND triggers canonical apply against the QC'd
            // block_hash. Mutually exclusive with the other two pending
            // slots because only one ConsensusMessage variant fires per
            // RR message.
            let mut pending_apply_qcd: Option<(u64, [u8; 32])> = None;
            let resp = {
                // Tag-byte routing: the consensus topic carries
                // FinalityVote alongside the ConsensusMessage variants
                // (Proposal/Vote/Timeout/NewView). Gossipsub-receive at
                // line ~3706 routes these via the explicit tag byte
                // because `decode_consensus_message` doesn't handle
                // CONSENSUS_FINALITY_VOTE — the same routing has to
                // happen here, otherwise finality votes broadcast via
                // RR fallback are silently dropped on the receiver side
                // and hard-finality cert formation never gathers a
                // quorum of votes.
                if !request.bytes.is_empty()
                    && request.bytes[0] == wire::tag::CONSENSUS_FINALITY_VOTE
                {
                    if let Some(engine) = validator_engine.as_mut() {
                        match wire::decode_finality_vote(&request.bytes) {
                            Ok(fv) => {
                                debug!(
                                    slot = fv.slot,
                                    voter = fv.voter_index,
                                    "received finality vote via RR fallback"
                                );
                                if engine.on_finality_vote(fv) {
                                    if let Some(cp) = engine.latest_finality_checkpoint() {
                                        let _ = block_store.put_finality_cert(cp);
                                        info!(
                                            slot = cp.slot,
                                            "hard finality cert formed (RR-receive)"
                                        );
                                        // Re-broadcast the checkpoint so
                                        // non-validator peers can advance
                                        // their WS anchor (mirrors the
                                        // gossipsub-receive handler at
                                        // line ~3720).
                                        pending_fallback_broadcast =
                                            Some(wire::encode_finality_checkpoint_msg(cp));
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(error = e, "RR-fallback finality vote decode failed");
                            }
                        }
                    }
                    pyde_net::consensus_protocol::ConsensusResp::Ack
                } else if let Ok(msg) = wire::decode_consensus_message(&request.bytes) {
                    use pyde_consensus::hotstuff::ConsensusMessage;
                    if let Some(engine) = validator_engine.as_mut() {
                        match msg {
                            ConsensusMessage::Timeout {
                                slot,
                                voter_index,
                                voter_address,
                                highest_qc,
                                signature,
                            } => {
                                debug!(slot, voter_index, "received timeout via RR fallback");
                                let vc_msg = pyde_consensus::view_change::ViewChangeMessage {
                                    slot,
                                    highest_qc,
                                    voter_index,
                                    voter_address,
                                    signature,
                                };
                                if engine.on_view_change(vc_msg) {
                                    info!(slot, "view change QC formed (via RR fallback) — fallback proposer can proceed");
                                    if let Some(bytes) = build_and_encode_fallback_proposal(
                                        engine,
                                        validator_identity.as_ref(),
                                        chain,
                                    ) {
                                        pending_fallback_broadcast = Some(bytes);
                                    }
                                }
                            }
                            ConsensusMessage::Vote {
                                slot, voter_index, ..
                            } => {
                                // Audit 234 part 3: votes that fell back
                                // to RR (gossip publish failed) need to
                                // route through the same `on_vote` path
                                // as the gossip-receive arm. Otherwise
                                // vote-QCs for fallback proposals never
                                // form because votes are silently dropped
                                // here.
                                debug!(slot, voter_index, "received vote via RR fallback");
                                if let Some(qc) = engine.on_vote(msg) {
                                    info!(
                                        slot,
                                        votes = qc.vote_count(),
                                        "QC formed (via RR fallback)"
                                    );
                                    pending_apply_qcd = Some((slot, qc.block_hash));
                                }
                            }
                            ConsensusMessage::Proposal {
                                ref header,
                                ref proposer_signature,
                            } => {
                                debug!(slot = header.slot, "received proposal via RR fallback");
                                engine.buffer_proposal(header, proposer_signature);
                            }
                            ConsensusMessage::NewView {
                                slot, highest_qc, ..
                            } => {
                                debug!(slot, "received new view via RR fallback");
                                if highest_qc.slot > engine.consensus.highest_qc.slot {
                                    engine.consensus.highest_qc = highest_qc;
                                }
                            }
                        }
                    }
                    pyde_net::consensus_protocol::ConsensusResp::Ack
                } else if let Ok(share_msg) = wire::decode_decryption_shares(&request.bytes) {
                    // Phase 1 hardening (audit 074b): decryption shares
                    // also fall back to RR. The bytes are the same wire
                    // encoding as on the gossipsub consensus topic; we
                    // hand the decoded message off to the same
                    // `AddDecryptionShares` handler the gossip path
                    // uses, so dedup + threshold + decrypt-execute all
                    // run identically. Without this branch, the new
                    // RR fan-out at the broadcast sites would land
                    // here as DecodeError on every peer — silent loss.
                    debug!(
                        slot = share_msg.slot,
                        member = share_msg.member_index,
                        "received decryption shares via RR fallback"
                    );
                    pending_share_msg = Some(share_msg);
                    pyde_net::consensus_protocol::ConsensusResp::Ack
                } else {
                    debug!(%peer, "failed to decode consensus RR request as either ConsensusMessage or DecryptionShareMsg");
                    pyde_net::consensus_protocol::ConsensusResp::DecodeError
                }
            };
            // Four-way dispatch: ack the RR sender, then route the
            // decoded payload through the same PostEventAction queue
            // as the gossip-receive arm. The four pending_* slots
            // are mutually exclusive because the decode branches are.
            if let Some(share_msg) = pending_share_msg {
                PostEventAction::SendConsensusRrResponseAndAddShares(channel, resp, share_msg)
            } else if let Some((qc_slot, qc_hash)) = pending_apply_qcd {
                PostEventAction::SendConsensusRrResponseAndApplyQcd(channel, resp, qc_slot, qc_hash)
            } else {
                match pending_fallback_broadcast {
                    Some(bytes) => {
                        PostEventAction::SendConsensusRrResponseAndBroadcast(channel, resp, bytes)
                    }
                    None => PostEventAction::SendConsensusRrResponse(channel, resp),
                }
            }
        }
        SwarmEvent::Behaviour(PydeBehaviourEvent::ConsensusRr(
            request_response::Event::Message {
                message: request_response::Message::Response { .. },
                ..
            },
        )) => {
            // Acks are best-effort confirmation; nothing to do.
            PostEventAction::None
        }
        SwarmEvent::Behaviour(PydeBehaviourEvent::ConsensusRr(
            request_response::Event::OutboundFailure { peer, error, .. },
        )) => {
            // Audit 234 part 4 step 7 originally disconnected the
            // peer here on the theory that a failed RR send is the
            // canonical signal of a half-broken QUIC connection.
            // That works for the "real stale peer" case it targeted
            // (post-restart QUIC half-open), but on a healthy mesh
            // it creates a feedback loop: every slot tick the
            // proposer fans out RR consensus messages, a few fail
            // (substream not ready, peer momentarily busy, gossipsub
            // heartbeat racing), each failure disconnects the peer,
            // bootstrap re-dials 2s later, and the mesh never
            // converges. On a 4-node localhost devnet that produced
            // ~4 connect/disconnect cycles per second per peer.
            //
            // Only disconnect on `Timeout` — a 30-second-no-response
            // failure is a real signal of a wedged connection. The
            // common transient failures (`DialFailure`, `Io`,
            // substream-closed-during-send) don't warrant disconnect;
            // libp2p's own keep-alive will reap genuinely-dead
            // connections.
            let is_timeout = matches!(error, request_response::OutboundFailure::Timeout);
            if is_timeout {
                debug!(%peer, ?error, "consensus RR timeout; dropping stale connection");
                PostEventAction::DisconnectStalePeer(peer)
            } else {
                debug!(%peer, ?error, "consensus RR transient failure; keeping connection");
                PostEventAction::None
            }
        }
        SwarmEvent::Behaviour(PydeBehaviourEvent::ConsensusRr(
            request_response::Event::InboundFailure { peer, error, .. },
        )) => {
            debug!(%peer, ?error, "consensus RR inbound failed");
            PostEventAction::None
        }
        SwarmEvent::Behaviour(PydeBehaviourEvent::ConsensusRr(
            request_response::Event::ResponseSent { .. },
        )) => PostEventAction::None,

        // --- BlocksRr: inbound block via RR fallback (audit 234 part 4 follow-up) ---
        SwarmEvent::Behaviour(PydeBehaviourEvent::BlocksRr(request_response::Event::Message {
            peer,
            message:
                request_response::Message::Request {
                    request, channel, ..
                },
            ..
        })) => {
            // Per-peer spam threshold, mirroring audit item 214's
            // pattern for decryption-share gossip. A peer that has
            // already crossed the invalid-message threshold on prior
            // gossip / RR delivery gets dropped here BEFORE the
            // decode + reconstruct work — closes the "open 20 outbound
            // connections, spam BlocksReq with bogus bytes" CPU-burn
            // amplification vector. Honest proposers stay at 0
            // because their compact blocks and bundles decode
            // cleanly.
            const BLOCKS_RR_SPAM_THRESHOLD: u64 = 5;
            let invalid = peer_manager
                .get_peer(&peer)
                .map(|p| p.invalid_messages)
                .unwrap_or(0);
            if invalid >= BLOCKS_RR_SPAM_THRESHOLD {
                debug!(
                    %peer,
                    invalid,
                    "dropping BlocksRr from peer over spam threshold"
                );
                return PostEventAction::SendBlocksRrResponse(
                    channel,
                    pyde_net::blocks_protocol::BlocksResp::DecodeError,
                );
            }

            // Dispatch by tag byte through the SAME PostEventActions
            // the gossipsub Blocks-topic receive arm uses
            // (ReconstructCompactBlock / BufferEncryptedBundle).
            //
            // The RR ResponseChannel is dropped on the valid-payload
            // paths — the receiver-side processing has already been
            // handed off to the action loop, and ack-then-process
            // would require either (a) ~226 lines of duplicated
            // ReconstructCompactBlock body inside this arm, or (b)
            // a substantial refactor to hoist that body into a helper
            // both paths can call. Both deferred — libp2p's per-stream
            // timeout cleans up the channel; the requester sees an
            // OutboundFailure (logged at debug) but the message has
            // already reached our consensus state. The decode-error
            // arm DOES ack so the requester can stop retrying.
            //
            // Bumps `invalid_messages` on every malformed payload so
            // repeat offenders cross BLOCKS_RR_SPAM_THRESHOLD and get
            // dropped on subsequent requests without decode cost.
            if request.bytes.is_empty() {
                debug!(%peer, "BlocksRr: empty payload");
                if let Some(info) = peer_manager.get_peer_mut(&peer) {
                    info.invalid_messages = info.invalid_messages.saturating_add(1);
                }
                return PostEventAction::SendBlocksRrResponse(
                    channel,
                    pyde_net::blocks_protocol::BlocksResp::DecodeError,
                );
            }
            let tag = request.bytes[0];
            if tag == wire::tag::COMPACT_BLOCK {
                match wire::decode_compact_block(&request.bytes) {
                    Ok(cb) => {
                        debug!(%peer, short_ids = cb.short_tx_ids.len(), "BlocksRr: compact block");
                        return PostEventAction::ReconstructCompactBlock(cb);
                    }
                    Err(e) => {
                        debug!(%peer, error = e, "BlocksRr: decode compact block failed");
                        if let Some(info) = peer_manager.get_peer_mut(&peer) {
                            info.invalid_messages = info.invalid_messages.saturating_add(1);
                        }
                        return PostEventAction::SendBlocksRrResponse(
                            channel,
                            pyde_net::blocks_protocol::BlocksResp::DecodeError,
                        );
                    }
                }
            }
            if tag == wire::tag::ENCRYPTED_TX_BUNDLE {
                match wire::decode_encrypted_tx_bundle(&request.bytes) {
                    Ok(bundle) => {
                        debug!(%peer, slot = bundle.slot, "BlocksRr: encrypted-tx bundle");
                        return PostEventAction::BufferEncryptedBundle(bundle);
                    }
                    Err(e) => {
                        debug!(%peer, error = e, "BlocksRr: decode bundle failed");
                        if let Some(info) = peer_manager.get_peer_mut(&peer) {
                            info.invalid_messages = info.invalid_messages.saturating_add(1);
                        }
                        return PostEventAction::SendBlocksRrResponse(
                            channel,
                            pyde_net::blocks_protocol::BlocksResp::DecodeError,
                        );
                    }
                }
            }
            // Full block fallback isn't routed through PostEventAction
            // (the gossip arm processes inline) — for RR delivery,
            // reject as not-yet-supported. Compact-block + bundle
            // cover every steady-state proposer broadcast.
            debug!(%peer, tag = format!("0x{tag:02x}"), "BlocksRr: unsupported tag");
            if let Some(info) = peer_manager.get_peer_mut(&peer) {
                info.invalid_messages = info.invalid_messages.saturating_add(1);
            }
            PostEventAction::SendBlocksRrResponse(
                channel,
                pyde_net::blocks_protocol::BlocksResp::DecodeError,
            )
        }
        SwarmEvent::Behaviour(PydeBehaviourEvent::BlocksRr(request_response::Event::Message {
            message: request_response::Message::Response { .. },
            ..
        })) => {
            // Acks (or DecodeError responses) from peers — best-effort
            // confirmation, nothing to do.
            PostEventAction::None
        }
        SwarmEvent::Behaviour(PydeBehaviourEvent::BlocksRr(
            request_response::Event::OutboundFailure { peer, error, .. },
        )) => {
            // Same rationale as ConsensusRr OutboundFailure: only
            // disconnect on `Timeout`. Transient failures during slot-
            // tick fanout would otherwise trigger a feedback loop on
            // the bootstrap re-dial cycle.
            let is_timeout = matches!(error, request_response::OutboundFailure::Timeout);
            if is_timeout {
                debug!(%peer, ?error, "blocks RR timeout; dropping stale connection");
                PostEventAction::DisconnectStalePeer(peer)
            } else {
                debug!(%peer, ?error, "blocks RR transient failure; keeping connection");
                PostEventAction::None
            }
        }
        SwarmEvent::Behaviour(PydeBehaviourEvent::BlocksRr(
            request_response::Event::InboundFailure { peer, error, .. },
        )) => {
            debug!(%peer, ?error, "blocks RR inbound failed");
            PostEventAction::None
        }
        SwarmEvent::Behaviour(PydeBehaviourEvent::BlocksRr(
            request_response::Event::ResponseSent { .. },
        )) => PostEventAction::None,

        // --- Peer connected: register + ask for chain tip + trigger auth handshake ---
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            let remote_addr = endpoint.get_remote_address().clone();
            info!(
                %peer_id,
                addr = %remote_addr,
                "peer connected"
            );
            // Track the peer so attested pubkeys can later be stored.
            // Direction + IP are best-effort; we don't enforce inbound
            // limits here because libp2p already handled transport.
            let direction = match &endpoint {
                libp2p::core::ConnectedPoint::Dialer { .. } => pyde_net::peer::Direction::Outbound,
                libp2p::core::ConnectedPoint::Listener { .. } => pyde_net::peer::Direction::Inbound,
            };
            // Audit 336: populate `info.ip` from the multiaddr so
            // PeerManager's per-IP rate limiter actually fires.
            // Pre-fix this field was always None and
            // `is_rate_limited` silently returned false on every
            // connection.
            let mut info = pyde_net::peer::PeerInfo::new(peer_id, direction);
            if let Some(ip) = pyde_net::peer::ip_from_multiaddr(&remote_addr) {
                info = info.with_ip(ip);
            }
            peer_manager.add_peer(info);

            // Audit 234 follow-up: snapshot the (peer_id, multiaddr)
            // for the persistent peer book AND kick off the FALCON
            // attestation handshake (task 029). The runtime handles
            // both as a unit; auth-gating for the book happens
            // downstream so a malicious peer that fails attestation
            // doesn't end up in the persisted set.
            PostEventAction::RecordPeerAndAuth {
                peer_id,
                multiaddr: remote_addr,
            }
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
            // Audit 340: chain_id is baked into the identify
            // protocol-version string (`/pyde/1.0.0/<chain_id>`).
            // A peer from a different chain is benign at the
            // libp2p layer (their FALCON peer-attestation also
            // fails downstream) but takes up Kademlia + gossipsub
            // resources until that downstream check fires. Drop
            // the connection here to keep the routing table
            // chain-clean.
            let expected_proto_prefix = format!("/pyde/1.0.0/{}", chain.chain_id);
            if info.protocol_version != expected_proto_prefix {
                warn!(
                    %peer_id,
                    got = %info.protocol_version,
                    expected = %expected_proto_prefix,
                    "peer protocol/chain mismatch — disconnecting"
                );
                return PostEventAction::DisconnectStalePeer(peer_id);
            }
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
///
/// Audit 395: silent regeneration on non-devnet chain_ids was an
/// operator footgun. If a validator's `validator.key` got deleted,
/// moved during a backup restore, or never made it into a fresh
/// VM image, the node would silently mint a NEW keypair and
/// rejoin under a different identity. From the chain's perspective
/// this is a different validator (new pubkey → new
/// derived address) — it can't sign on behalf of the original
/// stake position, so the original validator stops voting and the
/// chain quietly degrades to N-1 effective validators with no log
/// signal that something is wrong. We now refuse to silently
/// generate on non-devnet chain_ids and require the operator to
/// explicitly opt in via `PYDE_INIT_VALIDATOR_KEY=1`. Devnet
/// (`chain_id == 31337`) keeps the silent-generate ergonomics so
/// laptop test infra doesn't have to set the env var.
fn load_validator_identity(datadir: &Path, chain_id: u64) -> Result<ValidatorIdentity, String> {
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
        // Audit 395: refuse to mint a fresh keypair on non-devnet
        // chains unless the operator explicitly opted in. Devnet
        // (`chain_id == 31337`) preserves the silent-generate
        // ergonomics for laptop test infra.
        let is_devnet = chain_id == pyde_net::discovery::DEVNET_CHAIN_ID;
        let opted_in = std::env::var("PYDE_INIT_VALIDATOR_KEY")
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false);
        if !is_devnet && !opted_in {
            return Err(format!(
                "validator.key missing at {} on chain_id={} — refusing \
                 to silently generate a NEW validator identity (audit 395). \
                 If this is a fresh validator that should mint a new key, \
                 re-run with PYDE_INIT_VALIDATOR_KEY=1. If this is an \
                 existing validator whose key was lost or moved, restore \
                 the original `validator.key` from backup before starting \
                 — silently regenerating produces a new pubkey/address \
                 the chain doesn't recognize as your stake position, \
                 quietly degrading the network to N-1 effective \
                 validators.",
                key_path.display(),
                chain_id
            ));
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Audit 219 + Tier 2.4: bootstrap config startup guard ==========

    #[test]
    fn bootstrap_guard_rejects_empty_mainnet() {
        let err = check_bootstrap_config(1, &[]).unwrap_err();
        assert!(
            err.contains("mainnet"),
            "error must name mainnet so the operator knows what tripped, got: {err}"
        );
        assert!(err.contains("bootstrap_peers"));
    }

    #[test]
    fn bootstrap_guard_accepts_mainnet_with_peers() {
        let peers = vec!["/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWfoo".to_string()];
        assert!(check_bootstrap_config(1, &peers).is_ok());
    }

    #[test]
    fn bootstrap_guard_accepts_devnet_with_no_peers() {
        // Single-node local devnet is the one legitimate "no peers" case.
        assert!(check_bootstrap_config(31337, &[]).is_ok());
    }

    /// Tier 2.4: testnet and other non-devnet chains MUST hard-refuse
    /// startup with empty bootstrap_peers, mirroring audit-219's
    /// mainnet gate. Outsiders running validators against a public
    /// testnet expect a real network, not a silent fork-of-one — the
    /// failure mode is identical to mainnet's.
    #[test]
    fn bootstrap_guard_rejects_empty_testnet_and_custom_chains() {
        for chain_id in [2u64, 7, 1_000_000] {
            let err = check_bootstrap_config(chain_id, &[]).unwrap_err();
            assert!(
                err.contains(&format!("chain_id={chain_id}")),
                "error must name the chain_id, got: {err}"
            );
            assert!(
                err.contains("bootstrap_peers"),
                "error must name the missing config, got: {err}"
            );
        }
    }

    /// Tier 2.4: the error message must point operators bringing up a
    /// fresh testnet at the right escape hatch — set bootstrap_peers
    /// to their own genesis multiaddr(s) before starting any peer.
    #[test]
    fn bootstrap_guard_error_mentions_testnet_bringup_path() {
        let err = check_bootstrap_config(2, &[]).unwrap_err();
        assert!(
            err.contains("testnet bring-up") || err.contains("genesis-node"),
            "error must guide testnet operators to the escape hatch, got: {err}"
        );
    }

    /// Tier 2.3: the canonical public testnet chain_id (7331)
    /// produces an error that names "public testnet" specifically —
    /// not the generic "non-devnet chain" fallback. Operators
    /// reading the log line should recognize their network at a
    /// glance.
    #[test]
    fn bootstrap_guard_labels_canonical_testnet_chain_id() {
        let err = check_bootstrap_config(pyde_net::discovery::TESTNET_CHAIN_ID, &[]).unwrap_err();
        assert!(
            err.contains("public testnet"),
            "error must label canonical testnet (7331) as 'public testnet', got: {err}"
        );
        assert!(err.contains("chain_id=7331"));
    }

    #[test]
    fn bootstrap_guard_accepts_any_chain_with_peers() {
        let peers = vec!["/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWfoo".to_string()];
        for chain_id in [1u64, 2, 7, 31337, 1_000_000] {
            assert!(
                check_bootstrap_config(chain_id, &peers).is_ok(),
                "chain_id {chain_id} with peers should pass"
            );
        }
    }

    // ── Audit 343: config.toml ↔ genesis.toml chain_id consistency ──

    #[test]
    fn config_genesis_chain_id_match_accepts_equal() {
        for id in [1u64, 7, 7331, 31337, 1_000_000] {
            assert!(
                check_config_genesis_chain_id_match(id, id).is_ok(),
                "matching chain_id {id} must pass"
            );
        }
    }

    #[test]
    fn config_genesis_chain_id_mismatch_rejects() {
        // Common mishap shapes: operator edited config.toml without
        // regenerating genesis.toml, or pulled a forged genesis.toml
        // claiming a different chain than the runtime.
        for (config_id, genesis_id) in [
            (1u64, 31337),
            (7331, 31337),
            (7331, 1),
            (31337, 7331),
            (1, 7331),
        ] {
            let err = check_config_genesis_chain_id_match(config_id, genesis_id).unwrap_err();
            assert!(err.contains("audit 343"));
            assert!(err.contains(&format!("config.toml says {}", config_id)));
            assert!(err.contains(&format!("genesis.toml says {}", genesis_id)));
        }
    }
}
