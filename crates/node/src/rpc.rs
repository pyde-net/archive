//! JSON-RPC server for Pyde node.
//!
//! Exposes chain state queries and transaction submission over HTTP.

use crate::block_store::BlockStore;
use crate::chain::ChainState;
use crate::receipt_store::ReceiptStore;
use crate::state_manager::StateManager;
use crate::tx_relay::TxRelay;
use crate::wire;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObjectOwned;
use pyde_tx::execution::Receipt;
use pyde_tx::pipeline::BlockContext;
use pyde_tx::types::Transaction;
use pyde_tx::validation::{validate_transaction, ValidationContext, ValidationError};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Maximum number of pending txs any single sender can have in the
/// mempool (MAINNET_PLAN M1). Blocks one-account spam from filling a
/// node's memory and starving honest traffic. Chosen well above the
/// nonce-window size (16) so legitimate wallets doing batched
/// replacements or fee bumps don't run into it in practice, but low
/// enough that 100k mempool cap ÷ 128 = 782 distinct senders can still
/// max out the mempool — matching typical pending-account counts.
const MEMPOOL_SENDER_CAP: usize = 128;

/// Hard cap on total mempool size per node (MAINNET_PLAN M3). Under
/// sustained overload the M2 TTL sweep drains the mempool, but a
/// large burst can still push it past reasonable memory bounds
/// before the 4-minute TTL kicks in. Rejecting at this cap bounds
/// worst-case memory to roughly:
///   100_000 tx × ~1.8 KB avg (FALCON sig dominates) = ~180 MB.
/// Well inside a server budget; a laptop can also absorb this before
/// swap pressure kicks in. We chose hard-reject over fee-priority
/// eviction because our fee model has no per-tx priority signal —
/// every tx at a given base_fee pays the same per gas unit. When the
/// protocol grows a priority-fee field, M3 can upgrade to lowest-fee
/// eviction.
const MEMPOOL_GLOBAL_CAP: usize = 100_000;

/// Shared node state accessible by RPC handlers.
pub struct RpcState {
    pub chain: Arc<RwLock<ChainState>>,
    pub state: Arc<RwLock<StateManager>>,
    pub tx_relay: Arc<RwLock<TxRelay>>,
    pub receipts: Arc<RwLock<ReceiptStore>>,
    /// Persistent block store. Used by `getBlockByNumber` to decode
    /// the wire-encoded block body and surface full transaction
    /// fields (from, to, value, nonce, tx_type) — the in-memory
    /// `ChainState::header` only carries the merkle commitments.
    pub block_store: Arc<BlockStore>,
    /// Plain transaction queue (devnet mode — no threshold encryption).
    /// Proposer drains this to build blocks. Keyed by `tx.hash()` so
    /// block-commit retains are O(|block|) instead of O(|mempool| ×
    /// Poseidon2); under sustained load `Vec` grew into a quadratic
    /// hotspot because every `retain` had to recompute a full tx
    /// hash for every entry in the mempool.
    pub pending_txs: Arc<RwLock<std::collections::HashMap<[u8; 32], pyde_tx::types::Transaction>>>,
    /// Insertion timestamp for each tx in `pending_txs`, used for the
    /// mempool TTL sweep (MAINNET_PLAN M2). Parallel to `pending_txs`
    /// rather than inlined in its value type so existing call sites
    /// (block builder, gossip handler, fast_tx ingress) don't have
    /// to change. Drift is tolerated — an entry missing from one map
    /// is just skipped by the eviction loop, not a correctness bug.
    pub pending_tx_times: Arc<RwLock<std::collections::HashMap<[u8; 32], std::time::Instant>>>,
    /// Committee threshold public key for encrypting transactions (MEV protection).
    pub threshold_pk: Option<pyde_crypto::threshold::ThresholdPublicKey>,
    /// Broadcast channel for new block headers (WebSocket subscriptions).
    pub new_heads_tx: tokio::sync::broadcast::Sender<serde_json::Value>,
    /// Broadcast channel for pending transaction hashes.
    pub pending_tx_tx: tokio::sync::broadcast::Sender<String>,
    /// Broadcast channel for event logs.
    pub logs_tx: tokio::sync::broadcast::Sender<serde_json::Value>,
    /// Dev mode: allows unsigned pyde_sendTransaction.
    pub dev_mode: bool,
    /// Channel to gossip submitted transactions to the P2P network.
    pub tx_gossip_tx: tokio::sync::mpsc::Sender<pyde_tx::types::Transaction>,
    /// Audit item 227 step 4 / option E: encrypted-tx gossip side
    /// channel. After `send_raw_encrypted_transaction` accepts a tx
    /// into the local tx_relay, push a clone here so the node's
    /// main loop can publish it on the encrypted-transactions
    /// gossipsub topic — otherwise only this node's proposals can
    /// ever include it.
    pub encrypted_tx_gossip_tx: tokio::sync::mpsc::Sender<pyde_mempool::encrypted::EncryptedTx>,
    /// TPL-404: concurrency cap on simulator-backed RPCs
    /// (`pyde_call`, `pyde_estimateGas`, `pyde_createAccessList`).
    /// Each acquires one permit and holds it for the duration of
    /// the call. Without the cap a single peer could spam the
    /// public RPC node with concurrent simulator requests; each
    /// one calls `StateManager::snapshot_reader`, which clones the
    /// entire write-cache HashMap. Memory usage scales linearly
    /// with concurrent requests and was unbounded pre-fix.
    pub call_concurrency: Arc<tokio::sync::Semaphore>,
}

/// TPL-404: cap on concurrent in-flight `pyde_call` /
/// `pyde_estimateGas` / `pyde_createAccessList` requests. Each
/// holds a snapshot of the StateManager cache for its duration; 8
/// is enough for legitimate dapp UX (RPCs are bursty but
/// short-lived) and small enough to bound the worst-case memory
/// footprint at 8 × cache_size during a flood.
pub const CALL_CONCURRENCY_LIMIT: usize = 8;

/// Define the Pyde JSON-RPC API.
#[rpc(server)]
pub trait PydeApi {
    #[method(name = "pyde_getBalance")]
    async fn get_balance(&self, address: String) -> Result<String, ErrorObjectOwned>;

    #[method(name = "pyde_getTransactionCount")]
    async fn get_transaction_count(&self, address: String) -> Result<String, ErrorObjectOwned>;

    #[method(name = "pyde_getCode")]
    async fn get_code(&self, address: String) -> Result<String, ErrorObjectOwned>;

    #[method(name = "pyde_getStorageAt")]
    async fn get_storage_at(&self, address: String, slot: u64) -> Result<String, ErrorObjectOwned>;

    #[method(name = "pyde_gasPrice")]
    async fn gas_price(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "pyde_chainId")]
    async fn chain_id(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "pyde_blockNumber")]
    async fn block_number(&self) -> Result<String, ErrorObjectOwned>;

    /// `pyde_getBlockByNumber(slot, full_tx?)`. The second parameter
    /// is accepted for compatibility with Ethereum-style 2-arg
    /// callers (e.g. `eth_getBlockByNumber(slot, true)`); both the
    /// `transactions` and `transactionHashes` arrays are always
    /// included in the response so the flag is currently informational.
    #[method(name = "pyde_getBlockByNumber")]
    async fn get_block_by_number(
        &self,
        slot: u64,
        full_tx: Option<bool>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get block info by block hash.
    #[method(name = "pyde_getBlockByHash")]
    async fn get_block_by_hash(&self, hash: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "pyde_stateRoot")]
    async fn state_root(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "pyde_syncing")]
    async fn syncing(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get all registered validators with their status and stake.
    #[method(name = "pyde_getValidators")]
    async fn get_validators(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Submit a transaction as JSON object. Returns tx hash.
    /// Fields: from, to, value (decimal string), data (hex), gas (number), nonce (number).
    #[method(name = "pyde_sendTransaction")]
    async fn send_transaction(&self, tx_obj: serde_json::Value)
        -> Result<String, ErrorObjectOwned>;

    /// Submit a raw wire-encoded transaction (hex string). Returns tx hash.
    #[method(name = "pyde_sendRawTransaction")]
    async fn send_raw_transaction(&self, tx_hex: String) -> Result<String, ErrorObjectOwned>;

    /// Simulate a call without committing (read-only execution). Returns result hex.
    #[method(name = "pyde_call")]
    async fn call(&self, call_obj: serde_json::Value) -> Result<String, ErrorObjectOwned>;

    /// Estimate gas for a transaction.
    #[method(name = "pyde_estimateGas")]
    async fn estimate_gas(&self, call_obj: serde_json::Value) -> Result<String, ErrorObjectOwned>;

    /// Simulate a call and return the access list (storage keys touched).
    /// Used by SDKs to attach access lists for parallel scheduling.
    #[method(name = "pyde_createAccessList")]
    async fn create_access_list(
        &self,
        call_obj: serde_json::Value,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get a transaction receipt by tx hash.
    #[method(name = "pyde_getTransactionReceipt")]
    async fn get_transaction_receipt(
        &self,
        tx_hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get a user-facing status for a tx: "not_found", "pending" (with
    /// age), or "included" (with slot + success + gas). Complements
    /// `getTransactionReceipt`, which only answers after commit —
    /// this lets wallets show "still in mempool, submitted N seconds ago"
    /// instead of "unknown". MAINNET_PLAN M4.
    #[method(name = "pyde_getTransactionStatus")]
    async fn get_transaction_status(
        &self,
        tx_hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get logs matching a filter.
    #[method(name = "pyde_getLogs")]
    async fn get_logs(
        &self,
        filter: serde_json::Value,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get the mempool size.
    #[method(name = "pyde_mempoolSize")]
    async fn mempool_size(&self) -> Result<String, ErrorObjectOwned>;

    /// Return the committee's threshold public key (hex-encoded
    /// wire bytes). Clients encrypt the private fields of an
    /// `EncryptedTx` with this key locally before submitting via
    /// `pyde_sendRawEncryptedTransaction`. Errors if the node has
    /// no threshold committee configured (e.g. a dev node without
    /// MEV protection wired up).
    #[method(name = "pyde_getThresholdPublicKey")]
    async fn get_threshold_public_key(&self) -> Result<String, ErrorObjectOwned>;

    /// Submit a transaction for threshold encryption and mempool inclusion.
    /// Accepts a JSON object with: from, to, value, data, gas, nonce, signature.
    /// The node encrypts it with the committee's threshold public key before adding to mempool.
    ///
    /// NOTE: server-side encryption means the RPC node sees the
    /// plaintext (defeats MEV protection against a curious operator)
    /// and the client's signature can't bind to the ciphertext (the
    /// server chose the randomness). Dev / fallback path only. Real
    /// clients should use `pyde_sendRawEncryptedTransaction` below.
    #[method(name = "pyde_sendEncryptedTransaction")]
    async fn send_encrypted_transaction(
        &self,
        tx_obj: serde_json::Value,
    ) -> Result<String, ErrorObjectOwned>;

    /// Canonical MEV-protected submission path. Accepts a fully
    /// client-built + client-signed `EncryptedTx` as hex-encoded
    /// wire bytes (`EncryptedTx::to_bytes`).
    ///
    /// The client is expected to:
    ///   1. Fetch the committee pubkey via
    ///      `pyde_getThresholdPublicKey`.
    ///   2. Call `threshold_encrypt` on `(to, value, calldata)`
    ///      locally (so the node never sees plaintext).
    ///   3. Sign `EncryptedTx::hash()` with the sender's FALCON
    ///      secret key. Because the client chose the ciphertext's
    ///      randomness, the signature binds to a hash the client
    ///      actually knows — unlike the server-side path above.
    ///   4. Serialize via `to_bytes` and hex-encode.
    ///
    /// Returns the EncryptedTx hash on success.
    #[method(name = "pyde_sendRawEncryptedTransaction")]
    async fn send_raw_encrypted_transaction(
        &self,
        tx_hex: String,
    ) -> Result<String, ErrorObjectOwned>;

    // ========================================================================
    // WebSocket Subscriptions
    // ========================================================================

    /// Subscribe to new block headers. Fires each time a new block is committed.
    #[subscription(name = "pyde_subscribe" => "pyde_subscription", item = serde_json::Value, unsubscribe = "pyde_unsubscribe")]
    async fn subscribe_new_heads(&self) -> jsonrpsee::core::SubscriptionResult;

    /// Subscribe to new pending transactions in the mempool.
    #[subscription(name = "pyde_subscribePending" => "pyde_pendingSubscription", item = String, unsubscribe = "pyde_unsubscribePending")]
    async fn subscribe_pending_transactions(&self) -> jsonrpsee::core::SubscriptionResult;

    /// Subscribe to contract event logs matching a filter.
    #[subscription(name = "pyde_subscribeLogs" => "pyde_logSubscription", item = serde_json::Value, unsubscribe = "pyde_unsubscribeLogs")]
    async fn subscribe_logs(
        &self,
        filter: serde_json::Value,
    ) -> jsonrpsee::core::SubscriptionResult;
}

/// RPC server implementation.
pub struct RpcServer {
    pub state: Arc<RpcState>,
    pub chain_id: u64,
}

#[async_trait]
impl PydeApiServer for RpcServer {
    async fn get_balance(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let key = pyde_state::keys::balance_key(&addr);
        let state = self.state.state.read().await;
        let balance = state
            .get(&key)
            .and_then(|b| read_account_balance(&b))
            .unwrap_or(0);
        Ok(balance.to_string())
    }

    async fn get_transaction_count(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        // Nonce is stored separately at nonce_key (NonceState: base u64 + bitmap u16)
        let key = pyde_state::keys::nonce_key(&addr);
        let state = self.state.state.read().await;
        // Audit 390: `from_bytes` is `Option<Self>`. Missing or
        // structurally-invalid bytes both produce `None`, which
        // we collapse to `base = 0` (the never-seen-EOA case).
        let nonce = state
            .get(&key)
            .and_then(|b| pyde_account::nonce::NonceState::from_bytes(&b))
            .map(|ns| ns.base)
            .unwrap_or(0);
        Ok(nonce.to_string())
    }

    async fn get_code(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let key = pyde_state::keys::code_key(&addr);
        let state = self.state.state.read().await;
        let code = state.get(&key).unwrap_or_default();
        Ok(format!("0x{}", hex::encode(&code)))
    }

    async fn get_storage_at(&self, address: String, slot: u64) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let key = pyde_state::keys::storage_slot_key(&addr, slot);
        let state = self.state.state.read().await;
        let value = state.get(&key).unwrap_or_default();
        Ok(format!("0x{}", hex::encode(&value)))
    }

    async fn gas_price(&self) -> Result<String, ErrorObjectOwned> {
        let chain = self.state.chain.read().await;
        Ok(chain.base_fee.to_string())
    }

    async fn chain_id(&self) -> Result<String, ErrorObjectOwned> {
        Ok(format!("0x{:x}", self.chain_id))
    }

    async fn block_number(&self) -> Result<String, ErrorObjectOwned> {
        let chain = self.state.chain.read().await;
        Ok(format!("0x{:x}", chain.head_slot))
    }

    async fn get_block_by_number(
        &self,
        slot: u64,
        _full_tx: Option<bool>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        // `_full_tx` is currently ignored — the response always
        // includes both `transactions` and `transactionHashes` so any
        // caller (Ethereum-style with `true`, terse with no arg) gets
        // the data they wanted. Kept on the signature so jsonrpsee
        // accepts the 2-positional-arg form without "Invalid params".
        // ChainState only keeps the last ~2 epochs of headers in
        // memory; for older slots fall back to the persistent
        // BlockStore so block-explorer-style range queries don't go
        // dark past the in-memory window.
        let header = {
            let chain = self.state.chain.read().await;
            match chain.header(slot) {
                Some(h) => h.clone(),
                None => match self.state.block_store.get_header(slot) {
                    Some(h) => h,
                    None => return Ok(serde_json::Value::Null),
                },
            }
        };
        let tx_hashes = self
            .state
            .receipts
            .read()
            .await
            .tx_hashes_at_slot(slot)
            .unwrap_or_default();
        let block_hash = header.hash();
        let transactions = decode_block_transactions(&self.state.block_store, slot);
        Ok(serde_json::json!({
            "slot": header.slot,
            "epoch": header.epoch,
            "blockHash": format!("0x{}", hex::encode(block_hash)),
            "parentHash": format!("0x{}", hex::encode(header.parent_hash)),
            "stateRoot": format!("0x{}", hex::encode(header.state_root)),
            "txRoot": format!("0x{}", hex::encode(header.tx_root)),
            "timestamp": format!("0x{:x}", header.timestamp),
            "proposer": format!("0x{}", hex::encode(header.proposer)),
            "transactionHashes": tx_hashes
                .iter()
                .map(|h| format!("0x{}", hex::encode(h)))
                .collect::<Vec<_>>(),
            "transactions": transactions,
        }))
    }

    async fn get_block_by_hash(&self, hash: String) -> Result<serde_json::Value, ErrorObjectOwned> {
        let block_hash = parse_hash(&hash)?;
        let chain = self.state.chain.read().await;
        let header = match chain.header_by_hash(&block_hash) {
            Some(h) => h.clone(),
            None => return Err(rpc_err(-32602, "block not found for hash".to_string())),
        };
        drop(chain);
        let slot = header.slot;
        let tx_hashes = self
            .state
            .receipts
            .read()
            .await
            .tx_hashes_at_slot(slot)
            .unwrap_or_default();
        let transactions = decode_block_transactions(&self.state.block_store, slot);
        Ok(serde_json::json!({
            "slot": header.slot,
            "epoch": header.epoch,
            "blockHash": format!("0x{}", hex::encode(block_hash)),
            "parentHash": format!("0x{}", hex::encode(header.parent_hash)),
            "stateRoot": format!("0x{}", hex::encode(header.state_root)),
            "txRoot": format!("0x{}", hex::encode(header.tx_root)),
            "timestamp": format!("0x{:x}", header.timestamp),
            "proposer": format!("0x{}", hex::encode(header.proposer)),
            "hash": format!("0x{}", hex::encode(block_hash)),
            "transactionHashes": tx_hashes
                .iter()
                .map(|h| format!("0x{}", hex::encode(h)))
                .collect::<Vec<_>>(),
            "transactions": transactions,
        }))
    }

    async fn state_root(&self) -> Result<String, ErrorObjectOwned> {
        let chain = self.state.chain.read().await;
        Ok(format!("0x{}", hex::encode(chain.state_root)))
    }

    async fn syncing(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let chain = self.state.chain.read().await;
        Ok(serde_json::json!({
            "headSlot": chain.head_slot,
            "epoch": chain.epoch,
            "stateRoot": format!("0x{}", hex::encode(chain.state_root)),
        }))
    }

    async fn get_validators(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let state = self.state.state.read().await;

        // Read validator count
        let count_key = pyde_state::keys::validator_count_key();
        let count = state
            .get(&count_key)
            .map(|b| {
                if b.len() >= 8 {
                    u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]))
                } else {
                    0
                }
            })
            .unwrap_or(0);

        let mut validators = Vec::new();
        for i in 0..count {
            let idx_key = pyde_state::keys::validator_index_key(i);
            let address = match state.get(&idx_key) {
                Some(b) if b.len() == 32 => {
                    let mut addr = [0u8; 32];
                    addr.copy_from_slice(&b);
                    addr
                }
                _ => continue,
            };

            let val_key = pyde_state::keys::validator_key(&address);
            if let Some(val_data) = state.get(&val_key) {
                let entry = match pyde_tx::pipeline::ValidatorEntry::decode(&val_data) {
                    Some(e) => e,
                    None => continue,
                };
                let status = match entry.status {
                    0x00 => "active",
                    0x01 => "unbonding",
                    0x02 => "exited",
                    _ => "unknown",
                };

                validators.push(serde_json::json!({
                    "address": format!("0x{}", hex::encode(address)),
                    "stake": entry.stake.to_string(),
                    "status": status,
                    "index": i,
                }));
            }
        }

        Ok(serde_json::json!({
            "count": count,
            "validators": validators,
        }))
    }

    async fn send_transaction(
        &self,
        tx_obj: serde_json::Value,
    ) -> Result<String, ErrorObjectOwned> {
        if !self.state.dev_mode {
            return Err(rpc_err(-32601, "pyde_sendTransaction is only available in dev mode (--dev). Use pyde_sendRawTransaction with a signed transaction.".into()));
        }
        let from = tx_obj
            .get("from")
            .and_then(|v| v.as_str())
            .map(parse_address)
            .transpose()?
            .ok_or_else(|| rpc_err(-32602, "missing 'from' field".into()))?;
        let to = tx_obj
            .get("to")
            .and_then(|v| v.as_str())
            .map(parse_address)
            .transpose()?
            .unwrap_or([0u8; 32]);
        let value: u128 = tx_obj
            .get("value")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let data_hex = tx_obj.get("data").and_then(|v| v.as_str()).unwrap_or("");
        let data = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex)).unwrap_or_default();
        let gas_limit: u64 = tx_obj.get("gas").and_then(|v| v.as_u64()).unwrap_or(21_000);
        let chain_r = self.state.chain.read().await;
        let chain_id = chain_r.chain_id;
        drop(chain_r);

        let explicit_nonce = tx_obj.get("nonce").and_then(|v| v.as_u64());

        let tx_type = match tx_obj.get("txType").and_then(|v| v.as_str()) {
            Some("stakeDeposit") => pyde_tx::types::TransactionType::StakeDeposit,
            Some("stakeWithdraw") => pyde_tx::types::TransactionType::StakeWithdraw,
            Some("deploy") => pyde_tx::types::TransactionType::Deploy,
            // Slash txs carry double-sign evidence in the `data` field;
            // the pipeline re-verifies both FALCON signatures against the
            // accused validator's on-chain pubkey before debiting stake.
            // Dev mode exposes this path so multi-node harness tests can
            // submit forged evidence without routing through a proposer.
            Some("slash") => pyde_tx::types::TransactionType::Slash,
            _ => {
                if to == [0u8; 32] {
                    pyde_tx::types::TransactionType::Deploy
                } else {
                    pyde_tx::types::TransactionType::Standard
                }
            }
        };

        // For deploy txs: data should already be in pipeline format:
        // [clen:4 LE][rlen:4 LE][constructor][runtime][args]
        // Pass through as-is. The SDK/CLI constructs this format.
        let deploy_data = data;

        // TPL-927: auto-fetch nonce, ingress validation, mempool dedup,
        // and insert all happen under one `pending_txs.write()`. Pre-fix
        // the auto-fetch read on-chain state with no awareness of
        // in-flight pending txs from the same sender, so two concurrent
        // dev-mode `send_transaction` calls would both pick the same N
        // and the second one fell through to a duplicate-nonce error
        // from the dedup pass. `ingress_validate` and the on-chain
        // nonce read use independent locks (state, chain) and never
        // touch `pending_txs`, so holding `pending` through them is
        // deadlock-free given the codebase-wide convention that
        // pending_txs is the outer lock.
        let mut pending = self.state.pending_txs.write().await;

        let nonce: u64 = if let Some(n) = explicit_nonce {
            n
        } else {
            let on_chain = {
                let state_r = self.state.state.read().await;
                let nonce_key = pyde_state::keys::nonce_key(&from);
                // Audit 390: from_bytes is Option<Self>; missing /
                // malformed both collapse to `base = 0`.
                state_r
                    .get(&nonce_key)
                    .and_then(|bytes| pyde_account::nonce::NonceState::from_bytes(&bytes))
                    .map(|ns| ns.base)
                    .unwrap_or(0)
            };
            // Walk pending txs from this sender so concurrent auto-fetch
            // submissions don't both land on the same nonce. This is the
            // same O(N) scan the dedup pass below already does; we just
            // fold "max nonce for sender" into the same thinking.
            let max_pending = pending
                .values()
                .filter(|t| t.from == from)
                .map(|t| t.nonce)
                .max();
            match max_pending {
                Some(p) => p.saturating_add(1).max(on_chain),
                None => on_chain,
            }
        };

        let tx = pyde_tx::types::Transaction {
            from,
            to,
            value,
            data: deploy_data,
            gas_limit,
            nonce,
            signature: vec![],
            fee_payer: pyde_tx::types::FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id,
            tx_type,
        };

        // Ingress validation — same canonical validator as `send_raw_transaction`.
        // Dev-mode unsigned txs pass because `dev_skip_signature` is driven
        // by chain_id == 31337 inside `ingress_validate`.
        ingress_validate(&self.state.state, &self.state.chain, &tx).await?;

        // Compute tx hash (must match tx.hash() used in receipt generation)
        let tx_hash = tx.hash();

        // Global cap (M3) + per-sender cap (M1) + (sender, nonce) dedup
        // (M6), all atomic with the insert under one write lock.
        if pending.len() >= MEMPOOL_GLOBAL_CAP {
            return Err(rpc_err(
                -32011,
                format!(
                    "mempool full: {} txs pending (cap {})",
                    pending.len(),
                    MEMPOOL_GLOBAL_CAP
                ),
            ));
        }
        let mut sender_count: usize = 0;
        let mut duplicate_nonce = false;
        for t in pending.values() {
            if t.from == tx.from {
                sender_count += 1;
                if t.nonce == tx.nonce {
                    duplicate_nonce = true;
                    break;
                }
            }
        }
        if duplicate_nonce {
            return Err(rpc_err(
                -32010,
                format!(
                    "duplicate (sender, nonce)={} in mempool; cancel or wait for the existing tx to commit/expire",
                    tx.nonce
                ),
            ));
        }
        if sender_count >= MEMPOOL_SENDER_CAP {
            return Err(rpc_err(
                -32009,
                format!(
                    "mempool sender cap reached: {} pending txs from this sender (max {})",
                    sender_count, MEMPOOL_SENDER_CAP
                ),
            ));
        }
        pending.insert(tx_hash, tx.clone());
        let queue_size = pending.len();
        drop(pending);
        self.state
            .pending_tx_times
            .write()
            .await
            .insert(tx_hash, std::time::Instant::now());

        // Gossip to P2P network so all nodes can include it
        let _ = self.state.tx_gossip_tx.send(tx).await;

        let tx_hash_hex = format!("0x{}", hex::encode(tx_hash));
        info!(
            tx_hash = %tx_hash_hex,
            queue_size,
            "transaction accepted into pending queue"
        );

        // Return tx hash only. For deploys, the contract address is in the
        // receipt's returnData (authoritative, computed at execution time).
        Ok(serde_json::json!({
            "txHash": tx_hash_hex,
        })
        .to_string())
    }

    async fn send_raw_transaction(&self, tx_hex: String) -> Result<String, ErrorObjectOwned> {
        // Audit 222: record the RPC outcome via Prometheus. Wrapping
        // the body in an async block lets `?` propagate through to
        // `res`, then the counter fires regardless of success/failure
        // before the result is returned.
        let res: Result<String, ErrorObjectOwned> = async {
            let hex_str = tx_hex.strip_prefix("0x").unwrap_or(&tx_hex);
            let tx_bytes = hex::decode(hex_str)
                .map_err(|e| rpc_err(-32602, format!("invalid tx hex: {}", e)))?;
            // Try wire format first, then Transaction::from_bytes (used by wallet CLI)
            let tx = crate::wire::decode_transaction(&tx_bytes)
                .or_else(|_| {
                    pyde_tx::types::Transaction::from_bytes(&tx_bytes).ok_or("invalid tx encoding")
                })
                .map_err(|e| rpc_err(-32602, format!("invalid tx encoding: {}", e)))?;

            // Ingress validation — reject invalid txs BEFORE polluting the
            // mempool + gossip network. See `ingress_validate` docs.
            ingress_validate(&self.state.state, &self.state.chain, &tx).await?;

            let tx_hash = tx.hash();

            // Global cap + per-sender cap + dedup — same atomic check as
            // send_transaction. See that handler for rationale.
            let mut pending = self.state.pending_txs.write().await;
            if pending.len() >= MEMPOOL_GLOBAL_CAP {
                return Err(rpc_err(
                    -32011,
                    format!(
                        "mempool full: {} txs pending (cap {})",
                        pending.len(),
                        MEMPOOL_GLOBAL_CAP
                    ),
                ));
            }
            let mut sender_count: usize = 0;
            let mut duplicate_nonce = false;
            for t in pending.values() {
                if t.from == tx.from {
                    sender_count += 1;
                    if t.nonce == tx.nonce {
                        duplicate_nonce = true;
                        break;
                    }
                }
            }
            if duplicate_nonce {
                return Err(rpc_err(
                    -32010,
                    format!(
                        "duplicate (sender, nonce)={} in mempool; cancel or wait for the existing tx to commit/expire",
                        tx.nonce
                    ),
                ));
            }
            if sender_count >= MEMPOOL_SENDER_CAP {
                return Err(rpc_err(
                    -32009,
                    format!(
                        "mempool sender cap reached: {} pending txs from this sender (max {})",
                        sender_count, MEMPOOL_SENDER_CAP
                    ),
                ));
            }
            pending.insert(tx_hash, tx.clone());
            drop(pending);
            self.state
                .pending_tx_times
                .write()
                .await
                .insert(tx_hash, std::time::Instant::now());

            // Gossip to P2P network
            let _ = self.state.tx_gossip_tx.send(tx).await;

            Ok(format!("0x{}", hex::encode(tx_hash)))
        }
        .await;
        crate::metrics::record_rpc_request("pyde_sendRawTransaction", res.is_ok());
        res
    }

    async fn call(&self, call_obj: serde_json::Value) -> Result<String, ErrorObjectOwned> {
        // TPL-404: cap concurrent simulator-backed RPCs. Without
        // this gate a peer can flood `pyde_call` and force the
        // public RPC node to clone the StateManager cache once
        // per request — unbounded memory growth under load.
        let _permit = self
            .state
            .call_concurrency
            .clone()
            .try_acquire_owned()
            .map_err(|_| rpc_err(-32000, "server busy: too many concurrent calls".into()))?;
        let from = call_obj
            .get("from")
            .and_then(|v| v.as_str())
            .map(parse_address)
            .transpose()?
            .unwrap_or([0u8; 32]);
        let to = call_obj
            .get("to")
            .and_then(|v| v.as_str())
            .map(parse_address)
            .transpose()?
            .ok_or_else(|| rpc_err(-32602, "missing 'to' for call".into()))?;
        let data_hex = call_obj.get("data").and_then(|v| v.as_str()).unwrap_or("");
        let calldata =
            hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex)).unwrap_or_default();
        // Cap user-supplied gas at the block-level GAS_TARGET (400M).
        // `pyde_call` runs synchronously on the public RPC node's CPU
        // (never proposed into a block), so without an upper bound a
        // malicious caller can pass `gas: u64::MAX` and burn CPU until
        // the request times out. 400M leaves ample headroom over the
        // 100M default for any legitimate view function — full block
        // gas budgets are bounded by the same target.
        let gas_limit: u64 = clamp_call_gas(call_obj.get("gas").and_then(|v| v.as_u64()));

        // Take a read-consistent snapshot of state for the entire call.
        // This prevents the background Merkle commit or block processor from
        // modifying the cache mid-execution (which caused stale reads where
        // the same key returned different values within one pyde_call).
        let state_r = self.state.state.read().await;
        let code_key = pyde_state::keys::code_key(&to);
        let code = state_r
            .get(&code_key)
            .ok_or_else(|| rpc_err(-32000, "no code at address".into()))?;
        let storage_snapshot = state_r.snapshot_reader();
        let code_snapshot = state_r.snapshot_reader();
        drop(state_r); // release tokio lock — snapshot is self-contained

        // Audit 349: hydrate block-context from the chain head so
        // view functions reading block.number / block.timestamp /
        // block.proposer / BLOCKHASH return live data instead of
        // zeros. Read the chain lock briefly here; the snapshot
        // copy means no lock is held during PVM execution.
        let (block_number, timestamp, block_proposer, block_hashes) = {
            let chain_r = self.state.chain.read().await;
            build_call_block_context(&chain_r, &self.state.block_store)
        };
        let base_fee = {
            let chain_r = self.state.chain.read().await;
            chain_r.base_fee
        };

        // Run PVM directly — no validation, no nonce/balance checks
        let ctx = pyde_vm::vm::ExecutionContext {
            caller: from,
            self_address: to,
            call_value: ethnum::U256::ZERO,
            block_number,
            timestamp,
            gas_price: ethnum::U256::from(base_fee),
            tx_nonce: 0,
            tx_gas_limit: gas_limit,
            tx_hash: ethnum::U256::ZERO,
            block_proposer,
            block_hashes,
            balances: std::collections::HashMap::new(),
        };

        let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(gas_limit, ctx);
        vm.calldata = calldata;

        if let Err(e) = vm.load(&code) {
            return Err(rpc_err(-32000, format!("failed to load code: {:?}", e)));
        }

        // Storage backend reads from frozen snapshot (no stale reads)
        vm.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let smt_key = sparse_merkle_tree::H256::from(key.to_le_bytes());
            storage_snapshot(&smt_key)
        }));
        // Code backend for cross-contract calls (CallExt)
        vm.code_backend = Some(std::sync::Arc::new(move |addr: &[u8; 32]| {
            let ck = pyde_state::keys::code_key(addr);
            code_snapshot(&ck)
        }));

        let output = vm.execute();
        let success = output.outcome == pyde_vm::vm::Outcome::Success;

        if success {
            // Return value convention:
            // - GP return (u64, bool): r1 = value, r2 = 0
            // - Wide return (u256, Address): stored at heap, r1 = ptr, r2 = 32
            // - Blob return (String, Vec, Struct): r1 = ptr, r2 = len
            // Format: numeric values as BE hex (matches Ethereum convention).
            let r2 = vm.cpu.read_gp(2);
            let r1 = vm.cpu.read_gp(1);
            if r2 > 0 {
                // Blob return (String, Vec, Struct): raw serialized bytes
                let blob = vm.memory.load_bytes(r1 as usize, r2 as usize);
                Ok(format!("0x{}", hex::encode(blob)))
            } else {
                // GP return: r1 as u64 — encode as 8 bytes LE hex (consistent with ABI)
                Ok(format!("0x{}", hex::encode(r1.to_le_bytes())))
            }
        } else {
            Err(rpc_err(
                -32000,
                format!("execution failed: {:?}", output.outcome),
            ))
        }
    }

    async fn estimate_gas(&self, call_obj: serde_json::Value) -> Result<String, ErrorObjectOwned> {
        // TPL-404: same concurrency cap as `pyde_call`. Both run
        // through the simulator path with a snapshot-cloned cache.
        let _permit = self
            .state
            .call_concurrency
            .clone()
            .try_acquire_owned()
            .map_err(|_| rpc_err(-32000, "server busy: too many concurrent calls".into()))?;
        // Run the same as call but return gas used
        let from = call_obj
            .get("from")
            .and_then(|v| v.as_str())
            .map(parse_address)
            .transpose()?
            .unwrap_or([0u8; 32]);
        let to = call_obj
            .get("to")
            .and_then(|v| v.as_str())
            .map(parse_address)
            .transpose()?
            .unwrap_or([0u8; 32]);
        let data_hex = call_obj.get("data").and_then(|v| v.as_str()).unwrap_or("");
        let calldata =
            hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex)).unwrap_or_default();
        // Audit 342: cap caller-supplied gas at CALL_GAS_CAP — same DoS
        // mitigation that audit-735bcef applied to `pyde_call`. Without
        // this gate, a single estimateGas request with `gas: u64::MAX`
        // spins the public RPC node's CPU until the request times out.
        let gas_limit: u64 = clamp_call_gas(call_obj.get("gas").and_then(|v| v.as_u64()));

        if to == [0u8; 32] {
            // Deploy estimation
            return Ok(format!("0x{:x}", 32_000 + calldata.len() as u64 * 16));
        }

        let state_r = self.state.state.read().await;
        let code_key = pyde_state::keys::code_key(&to);
        let code = match state_r.get(&code_key) {
            Some(c) => c,
            None => return Ok(format!("0x{:x}", 21_000)), // simple transfer
        };
        let storage_snapshot = state_r.snapshot_reader();
        drop(state_r);

        // Audit 349: same block-context hydration as `pyde_call`.
        // estimateGas runs the same simulator path so divergent
        // block context produces divergent gas estimates for any
        // view function that reads block.number / timestamp /
        // proposer / BLOCKHASH.
        let (block_number, timestamp, block_proposer, block_hashes) = {
            let chain_r = self.state.chain.read().await;
            build_call_block_context(&chain_r, &self.state.block_store)
        };
        let base_fee = {
            let chain_r = self.state.chain.read().await;
            chain_r.base_fee
        };

        let ctx = pyde_vm::vm::ExecutionContext {
            caller: from,
            self_address: to,
            call_value: ethnum::U256::ZERO,
            block_number,
            timestamp,
            gas_price: ethnum::U256::from(base_fee),
            tx_nonce: 0,
            tx_gas_limit: gas_limit,
            tx_hash: ethnum::U256::ZERO,
            block_proposer,
            block_hashes,
            balances: std::collections::HashMap::new(),
        };

        let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(gas_limit, ctx);
        vm.calldata = calldata;
        let _ = vm.load(&code);
        vm.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let smt_key = sparse_merkle_tree::H256::from(key.to_le_bytes());
            storage_snapshot(&smt_key)
        }));
        let _output = vm.execute();

        // Return gas used + 10% margin for real execution overhead (nonce check, balance deduct, etc.)
        // The VM simulation already includes all cold storage surcharges.
        let gas_used = vm.gas_used_total;
        let base_tx_cost = 21_000u64;
        let estimate = if gas_used == 0 {
            base_tx_cost
        } else {
            base_tx_cost + gas_used + gas_used / 10
        };
        Ok(format!("0x{:x}", estimate))
    }

    async fn create_access_list(
        &self,
        call_obj: serde_json::Value,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        // TPL-404: same concurrency cap as `pyde_call`. Both run
        // through the simulator path with a snapshot-cloned cache.
        let _permit = self
            .state
            .call_concurrency
            .clone()
            .try_acquire_owned()
            .map_err(|_| rpc_err(-32000, "server busy: too many concurrent calls".into()))?;
        let from = call_obj
            .get("from")
            .and_then(|v| v.as_str())
            .map(parse_address)
            .transpose()?
            .unwrap_or([0u8; 32]);
        let to = call_obj
            .get("to")
            .and_then(|v| v.as_str())
            .map(parse_address)
            .transpose()?
            .unwrap_or([0u8; 32]);
        let data_hex = call_obj.get("data").and_then(|v| v.as_str()).unwrap_or("");
        let calldata =
            hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex)).unwrap_or_default();
        let value: u128 = call_obj
            .get("value")
            .and_then(|v| v.as_str())
            .and_then(|s| u128::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok())
            .unwrap_or(0);
        // Audit 342: same gas-cap mitigation as estimateGas + pyde_call.
        // createAccessList runs the same simulator path so an
        // unbounded `gas` parameter is the same DoS vector.
        let gas_limit: u64 = clamp_call_gas(call_obj.get("gas").and_then(|v| v.as_u64()));

        if to == [0u8; 32] {
            // Deploy — no meaningful access list
            return Ok(serde_json::json!({
                "accessList": [],
                "gasUsed": format!("0x{:x}", 32_000 + calldata.len() as u64 * 16)
            }));
        }

        let state_r = self.state.state.read().await;
        let code_key = pyde_state::keys::code_key(&to);
        let code = match state_r.get(&code_key) {
            Some(c) => c,
            None => {
                // Simple transfer — access list is just the sender and receiver balance keys
                let from_slot = pyde_crypto::poseidon2::poseidon2_hash(&{
                    let mut buf = Vec::with_capacity(33);
                    buf.extend_from_slice(&from);
                    buf.push(0x04);
                    buf
                })
                .to_bytes();
                let to_slot = pyde_crypto::poseidon2::poseidon2_hash(&{
                    let mut buf = Vec::with_capacity(33);
                    buf.extend_from_slice(&to);
                    buf.push(0x04);
                    buf
                })
                .to_bytes();
                return Ok(serde_json::json!({
                    "accessList": [
                        { "address": format!("0x{}", hex::encode(from)), "reads": [], "writes": [format!("0x{}", hex::encode(from_slot))] },
                        { "address": format!("0x{}", hex::encode(to)), "reads": [], "writes": [format!("0x{}", hex::encode(to_slot))] }
                    ],
                    "gasUsed": "0x5208"
                }));
            }
        };
        let storage_snapshot = state_r.snapshot_reader();
        drop(state_r);

        // Audit 349: same block-context hydration. createAccessList
        // simulates the call to discover the touched storage keys;
        // a contract that branches on block.number / timestamp /
        // BLOCKHASH would otherwise produce a wrong access list
        // (under-listing slots that the live tx will actually
        // touch — strict-mode access lists then trap on those
        // unlisted SLOAD/SSTOREs at execution time).
        let (block_number, timestamp, block_proposer, block_hashes) = {
            let chain_r = self.state.chain.read().await;
            build_call_block_context(&chain_r, &self.state.block_store)
        };
        let base_fee = {
            let chain_r = self.state.chain.read().await;
            chain_r.base_fee
        };

        let ctx = pyde_vm::vm::ExecutionContext {
            caller: from,
            self_address: to,
            call_value: ethnum::U256::from(value),
            block_number,
            timestamp,
            gas_price: ethnum::U256::from(base_fee),
            tx_nonce: 0,
            tx_gas_limit: gas_limit,
            tx_hash: ethnum::U256::ZERO,
            block_proposer,
            block_hashes,
            balances: std::collections::HashMap::new(),
        };

        let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(gas_limit, ctx);
        vm.calldata = calldata;
        let _ = vm.load(&code);
        vm.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let smt_key = sparse_merkle_tree::H256::from(key.to_le_bytes());
            storage_snapshot(&smt_key)
        }));
        let _output = vm.execute();

        // Build access list from VM's tracked RAW slots (pre-derivation).
        // The pipeline's pre_derive_access_list_keys will derive them,
        // so we must return raw slots, not already-derived keys.
        let write_keys: Vec<String> = vm
            .written_raw_slots
            .iter()
            .map(|k| format!("0x{}", hex::encode(k.to_le_bytes())))
            .collect();
        let read_keys: Vec<String> = vm
            .accessed_raw_slots
            .iter()
            .filter(|k| !vm.written_raw_slots.contains(k))
            .map(|k| format!("0x{}", hex::encode(k.to_le_bytes())))
            .collect();

        let gas_used = vm.gas_used_total;

        Ok(serde_json::json!({
            "accessList": [{
                "address": format!("0x{}", hex::encode(to)),
                "reads": read_keys,
                "writes": write_keys,
            }],
            "gasUsed": format!("0x{:x}", gas_used)
        }))
    }

    async fn get_transaction_receipt(
        &self,
        tx_hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let hash = parse_hash(&tx_hash)?;
        let store = self.state.receipts.read().await;

        match store.get(&hash) {
            Some(receipt) => Ok(receipt_to_json(receipt)),
            None => Ok(serde_json::Value::Null),
        }
    }

    async fn get_transaction_status(
        &self,
        tx_hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let hash = parse_hash(&tx_hash)?;

        // 1. Committed? Return the receipt highlights.
        if let Some(receipt) = self.state.receipts.read().await.get(&hash) {
            return Ok(serde_json::json!({
                "status": "included",
                "success": receipt.success,
                "gasUsed": format!("0x{:x}", receipt.gas_used),
                "effectiveGas": format!("0x{:x}", receipt.effective_gas),
            }));
        }

        // 2. Pending? Report age so wallets can render "X seconds ago".
        if self.state.pending_txs.read().await.contains_key(&hash) {
            let age_secs = self
                .state
                .pending_tx_times
                .read()
                .await
                .get(&hash)
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0);
            return Ok(serde_json::json!({
                "status": "pending",
                "ageSecs": age_secs,
            }));
        }

        // 3. Neither — never seen, or evicted by TTL sweep.
        Ok(serde_json::json!({ "status": "not_found" }))
    }

    async fn get_logs(
        &self,
        filter: serde_json::Value,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let from_slot = filter
            .get("fromBlock")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let to_slot = filter
            .get("toBlock")
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::MAX);
        let address_filter = filter
            .get("address")
            .and_then(|v| v.as_str())
            .map(|s| parse_address(s))
            .transpose()?;

        // Topic filters: array of arrays. topics[i] matches log.topics[i].
        // null/empty at position i means "any". Multiple values at position i means "OR".
        let topic_filters: Vec<Vec<Vec<u8>>> = filter
            .get("topics")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|entry| {
                        if entry.is_null() {
                            vec![] // match any
                        } else if let Some(s) = entry.as_str() {
                            // Single topic
                            hex::decode(s.trim_start_matches("0x"))
                                .unwrap_or_default()
                                .chunks(32)
                                .map(|c| c.to_vec())
                                .collect::<Vec<_>>()
                                .into_iter()
                                .take(1)
                                .flat_map(|v| vec![v])
                                .collect()
                        } else if let Some(arr) = entry.as_array() {
                            // OR list of topics
                            arr.iter()
                                .filter_map(|t| {
                                    t.as_str().map(|s| {
                                        hex::decode(s.trim_start_matches("0x")).unwrap_or_default()
                                    })
                                })
                                .collect()
                        } else {
                            vec![]
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let store = self.state.receipts.read().await;
        let logs = store.get_logs(from_slot, to_slot, address_filter.as_ref());

        let result: Vec<serde_json::Value> = logs.iter()
            .filter(|(_, log)| {
                // Apply topic filters
                for (i, filter_topics) in topic_filters.iter().enumerate() {
                    if filter_topics.is_empty() { continue; } // null = match any
                    if i >= log.topics.len() { return false; } // log has fewer topics
                    let log_topic = &log.topics[i];
                    if !filter_topics.iter().any(|ft| ft == log_topic) {
                        return false; // no match at this position
                    }
                }
                true
            })
            .map(|(slot, log)| {
                serde_json::json!({
                    "slot": slot,
                    "address": format!("0x{}", hex::encode(log.address)),
                    "topics": log.topics.iter().map(|t| format!("0x{}", hex::encode(t))).collect::<Vec<_>>(),
                    "data": format!("0x{}", hex::encode(&log.data)),
                })
            }).collect();

        Ok(serde_json::json!(result))
    }

    async fn mempool_size(&self) -> Result<String, ErrorObjectOwned> {
        let relay = self.state.tx_relay.read().await;
        Ok(relay.mempool_size().to_string())
    }

    async fn get_threshold_public_key(&self) -> Result<String, ErrorObjectOwned> {
        let pk =
            self.state.threshold_pk.as_ref().ok_or_else(|| {
                rpc_err(-32000, "threshold encryption not configured".to_string())
            })?;
        Ok(format!("0x{}", hex::encode(pk.to_bytes())))
    }

    async fn send_encrypted_transaction(
        &self,
        tx_obj: serde_json::Value,
    ) -> Result<String, ErrorObjectOwned> {
        let tpk =
            self.state.threshold_pk.as_ref().ok_or_else(|| {
                rpc_err(-32000, "threshold encryption not configured".to_string())
            })?;

        // Parse tx fields
        let from = tx_obj
            .get("from")
            .and_then(|v| v.as_str())
            .map(parse_address)
            .transpose()?
            .unwrap_or([0u8; 32]);
        let to = tx_obj
            .get("to")
            .and_then(|v| v.as_str())
            .map(parse_address)
            .transpose()?
            .unwrap_or([0u8; 32]);
        let value: u128 = tx_obj
            .get("value")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let data_hex = tx_obj.get("data").and_then(|v| v.as_str()).unwrap_or("");
        let data = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex)).unwrap_or_default();
        let gas_limit: u64 = tx_obj
            .get("gas")
            .and_then(|v| v.as_u64())
            .unwrap_or(100_000);
        let nonce: u64 = tx_obj.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0);
        let signature_hex = tx_obj
            .get("signature")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let signature = hex::decode(signature_hex.strip_prefix("0x").unwrap_or(signature_hex))
            .unwrap_or_default();
        // Audit 302: never default `chainId` to mainnet. A wallet that
        // omits the field gets the node's running chain_id; a wallet
        // that supplies a different chain_id gets a clean -32602 so
        // the misconfiguration surfaces immediately instead of
        // producing a tx that fails verification on the target chain
        // AND replays the moment any chain with the same id launches.
        let chain_id = resolve_request_chain_id(
            tx_obj.get("chainId").and_then(|v| v.as_u64()),
            self.chain_id,
        )
        .map_err(|m| rpc_err(-32602, m))?;

        // Build access list (simplified: just the target contract)
        let access_list = if to != [0u8; 32] {
            vec![pyde_tx::types::AccessEntry {
                address: to,
                reads: vec![],
                writes: vec![],
            }]
        } else {
            vec![pyde_tx::types::AccessEntry {
                address: from,
                reads: vec![],
                writes: vec![],
            }]
        };

        // Threshold-encrypt the transaction
        let enc_tx = pyde_mempool::encrypted::encrypt_transaction(
            from,
            nonce,
            gas_limit,
            access_list,
            None,
            chain_id,
            signature,
            &to,
            value,
            &data,
            tpk,
        )
        .map_err(|e| rpc_err(-32000, format!("encryption failed: {}", e)))?;

        let tx_hash = enc_tx.hash();

        // Task 028: bind ciphertext to sender's on-chain FALCON pubkey.
        // Look up the sender's account; if a Single auth_key is registered,
        // enforce full FALCON verification (receive_tx_verified).
        //
        // Audit item 206: on production chain_ids the fall-through to the
        // structural-only path is closed — accounts with no registered
        // auth_key are REJECTED, because structural-only accepts any
        // 500-1000 byte blob as a "signature" and lets an attacker spoof
        // `sender = victim_address` for every fresh address. Devnet
        // (chain_id == 31337) keeps the fall-through so faucet / bootstrap
        // accounts can transact before their first key registration.
        let sender_pk_opt = {
            let state_r = self.state.state.read().await;
            let sender_key = pyde_state::keys::balance_key(&from);
            state_r
                .get(&sender_key)
                .and_then(|bytes| pyde_account::types::Account::from_bytes(&bytes))
                .and_then(|acct| match acct.auth_keys {
                    pyde_account::types::AuthKeys::Single(pk) => Some(pk),
                    _ => None,
                })
        };

        let mut relay = self.state.tx_relay.write().await;
        let accepted = match encrypted_tx_ingest_policy(sender_pk_opt, self.chain_id) {
            EncryptedTxIngestPolicy::Verify(sender_pk) => {
                relay.receive_tx_verified(enc_tx, &sender_pk)
            }
            EncryptedTxIngestPolicy::StructuralOnly => relay.receive_tx(enc_tx),
            EncryptedTxIngestPolicy::Reject => {
                return Err(rpc_err(
                    -32001,
                    "encrypted-tx sender has no registered auth_key; register one before submitting"
                        .to_string(),
                ));
            }
        };
        if !accepted {
            return Err(rpc_err(
                -32000,
                "tx rejected (duplicate, rate-limited, or signature failed verification)"
                    .to_string(),
            ));
        }

        info!(
            tx_hash = hex::encode(tx_hash),
            "encrypted tx accepted into mempool"
        );
        Ok(format!("0x{}", hex::encode(tx_hash)))
    }

    async fn send_raw_encrypted_transaction(
        &self,
        tx_hex: String,
    ) -> Result<String, ErrorObjectOwned> {
        // Decode hex-encoded EncryptedTx wire frame produced by the
        // client via `EncryptedTx::to_bytes`.
        let tx_bytes = hex::decode(tx_hex.strip_prefix("0x").unwrap_or(&tx_hex))
            .map_err(|e| rpc_err(-32602, format!("invalid hex: {}", e)))?;
        let enc_tx = pyde_mempool::encrypted::EncryptedTx::from_bytes(&tx_bytes)
            .ok_or_else(|| rpc_err(-32602, "invalid EncryptedTx wire format".to_string()))?;

        let from = enc_tx.sender;
        let tx_hash = enc_tx.hash();
        // Clone for the gossip fan-out below. We gossip only after
        // local acceptance so the ingress policy (auth_key lookup,
        // sig verify, nonce-window) gates what the network sees.
        let tx_for_gossip = enc_tx.clone();

        // Same ingest policy as the server-side path (audit item 206):
        // mainnet requires the sender to have a registered auth_key,
        // devnet falls through to structural-only for faucet UX. The
        // key win over the server-side path is that the signature
        // actually binds to a ciphertext the client knows about — so
        // on mainnet the FALCON verify inside `receive_tx_verified`
        // is meaningful, not a no-op length check.
        //
        // While we have the read-lock open, also fetch the sender's
        // current nonce state for the ingress window check below —
        // saves a second state read on the hot path.
        let (sender_pk_opt, nonce_state_opt) = {
            let state_r = self.state.state.read().await;
            let sender_key = pyde_state::keys::balance_key(&from);
            let pk_opt = state_r
                .get(&sender_key)
                .and_then(|bytes| pyde_account::types::Account::from_bytes(&bytes))
                .and_then(|acct| match acct.auth_keys {
                    pyde_account::types::AuthKeys::Single(pk) => Some(pk),
                    _ => None,
                });
            // Audit 390: from_bytes is Option<Self>. Flatten via
            // and_then so a malformed nonce-key value collapses
            // into the same `None` shape as a missing key — the
            // ingress check below treats both as "no upstream
            // window known" and skips the upper-bound rejection.
            let ns_opt = state_r
                .get(&pyde_state::keys::nonce_key(&from))
                .and_then(|bytes| pyde_account::nonce::NonceState::from_bytes(&bytes));
            (pk_opt, ns_opt)
        };

        // Pre-check the nonce window at ingress. Without this, a
        // submitter who can encrypt + FALCON-sign faster than the
        // chain can decrypt + apply (true on any laptop the moment
        // submit-rate exceeds chain-commit-rate) piles arbitrary
        // future nonces into the encrypted mempool, where they sit
        // unprocessable until their parent nonces commit. The mempool
        // grows past the per-sender concurrent cap, submission
        // collapses to errors, and from the operator's view the
        // encrypted path appears to "stall under load" even though
        // the chain is committing what it can.
        //
        // Rejecting above-window submissions at ingress flips the
        // failure shape from "silent backlog → submitter sees
        // TooManyConcurrent later" to "submitter gets a clean
        // -32008 immediately and can back off". Also keeps mempool
        // depth proportional to the actual in-flight window
        // (`WINDOW_SIZE = 16` per sender) instead of the wall-clock
        // submission rate.
        if let Some(ns) = &nonce_state_opt {
            // Audit 386: `ns.base + WINDOW_SIZE` panics in debug and
            // wraps in release once `base` is within `WINDOW_SIZE` of
            // `u64::MAX`. `checked_add` returning `None` means the
            // window naturally extends to `u64::MAX`, so every nonce
            // `>= base` is in-window and we skip the upper-bound
            // rejection.
            if let Some(window_end) = ns.base.checked_add(pyde_account::nonce::WINDOW_SIZE) {
                if enc_tx.nonce >= window_end {
                    return Err(rpc_err(
                        -32008,
                        format!(
                            "encrypted-tx nonce {} is past the in-flight window [{}, {}); submit when prior nonces commit",
                            enc_tx.nonce,
                            ns.base,
                            window_end,
                        ),
                    ));
                }
            }
            if enc_tx.nonce < ns.base {
                return Err(rpc_err(
                    -32008,
                    format!(
                        "encrypted-tx nonce {} is below the chain's committed nonce {}",
                        enc_tx.nonce, ns.base
                    ),
                ));
            }
        }

        let mut relay = self.state.tx_relay.write().await;
        let accepted = match encrypted_tx_ingest_policy(sender_pk_opt, self.chain_id) {
            EncryptedTxIngestPolicy::Verify(sender_pk) => {
                relay.receive_tx_verified(enc_tx, &sender_pk)
            }
            EncryptedTxIngestPolicy::StructuralOnly => relay.receive_tx(enc_tx),
            EncryptedTxIngestPolicy::Reject => {
                return Err(rpc_err(
                    -32001,
                    "encrypted-tx sender has no registered auth_key; register one before submitting"
                        .to_string(),
                ));
            }
        };
        if !accepted {
            return Err(rpc_err(
                -32000,
                "tx rejected (duplicate, rate-limited, or signature failed verification)"
                    .to_string(),
            ));
        }

        info!(
            tx_hash = hex::encode(tx_hash),
            "raw encrypted tx accepted into mempool"
        );

        // Audit item 227 step 4 / option E: fan out to validator
        // peers so their tx_relays also have the tx — without this,
        // only our own proposals can include it.
        if self
            .state
            .encrypted_tx_gossip_tx
            .send(tx_for_gossip)
            .await
            .is_err()
        {
            debug!(
                tx_hash = hex::encode(tx_hash),
                "encrypted-tx gossip channel closed — skipping fan-out"
            );
        }

        Ok(format!("0x{}", hex::encode(tx_hash)))
    }

    // ========================================================================
    // WebSocket Subscription Implementations
    // ========================================================================

    async fn subscribe_new_heads(
        &self,
        subscription_sink: jsonrpsee::PendingSubscriptionSink,
    ) -> jsonrpsee::core::SubscriptionResult {
        let mut sink = subscription_sink.accept().await?;
        let mut rx = self.state.new_heads_tx.subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(header) => {
                        // Use try_send to avoid blocking — if the WS buffer is full, skip this header.
                        // Block headers arrive every 400ms; missing one is acceptable.
                        // The JSON serialization is infallible for `header` (a
                        // `serde_json::Value` we constructed ourselves), but we
                        // handle the Err arm explicitly instead of `.unwrap()`
                        // so a tokio::spawn task can never panic on malformed
                        // input. (MAINNET_PLAN 060.)
                        if let Ok(msg) = jsonrpsee::SubscriptionMessage::from_json(&header) {
                            let _ = sink.try_send(msg);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        });
        Ok(())
    }

    async fn subscribe_pending_transactions(
        &self,
        subscription_sink: jsonrpsee::PendingSubscriptionSink,
    ) -> jsonrpsee::core::SubscriptionResult {
        let sink = subscription_sink.accept().await?;
        let mut rx = self.state.pending_tx_tx.subscribe();
        tokio::spawn(async move {
            while let Ok(tx_hash) = rx.recv().await {
                // MAINNET_PLAN 060: graceful Err arm instead of `.unwrap()` so
                // a malformed tx_hash (unreachable for our code paths) can't
                // panic the spawned task.
                let msg = match jsonrpsee::SubscriptionMessage::from_json(&tx_hash) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if sink.send(msg).await.is_err() {
                    break;
                }
            }
        });
        Ok(())
    }

    async fn subscribe_logs(
        &self,
        subscription_sink: jsonrpsee::PendingSubscriptionSink,
        filter: serde_json::Value,
    ) -> jsonrpsee::core::SubscriptionResult {
        let sink = subscription_sink.accept().await?;
        let mut rx = self.state.logs_tx.subscribe();
        let filter_addr = filter
            .get("address")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase());
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(log) => {
                        if let Some(ref addr) = filter_addr {
                            let log_addr = log
                                .get("address")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_lowercase());
                            if log_addr.as_deref() != Some(addr.as_str()) {
                                continue;
                            }
                        }
                        // MAINNET_PLAN 060: graceful Err arm instead of
                        // `.unwrap()` so a malformed log (unreachable for our
                        // code paths) can't panic the spawned task.
                        let msg = match jsonrpsee::SubscriptionMessage::from_json(&log) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };
                        if sink.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        });
        Ok(())
    }
}

/// Start the JSON-RPC HTTP server.
pub async fn start_rpc_server(
    listen: &str,
    port: u16,
    rpc_state: Arc<RpcState>,
    chain_id: u64,
) -> Result<SocketAddr, String> {
    let addr: SocketAddr = format!("{}:{}", listen, port)
        .parse()
        .map_err(|e| format!("invalid RPC address: {}", e))?;

    // Audit 345: explicit body / batch caps on the jsonrpsee
    // server. Pre-fix the server used jsonrpsee's defaults
    // (~10 MB request body, no batch cap), so a single connection
    // could send back-to-back 10 MB requests until the RPC
    // process saturated. The numbers are chosen for `pyde_call` /
    // `pyde_estimateGas` / `pyde_createAccessList` shapes —
    // calldata + ABI args at typical contract sizes — plus
    // headroom for `pyde_getLogs` / `pyde_getBlockByNumber(slot,
    // full_tx)` response payloads.
    const MAX_REQUEST_BODY_BYTES: u32 = 1_048_576; // 1 MB
    const MAX_RESPONSE_BODY_BYTES: u32 = 16_777_216; // 16 MB
    const MAX_CONNECTIONS: u32 = 1024;
    const MAX_REQUESTS_PER_BATCH: u32 = 32;
    let server = Server::builder()
        .max_request_body_size(MAX_REQUEST_BODY_BYTES)
        .max_response_body_size(MAX_RESPONSE_BODY_BYTES)
        .max_connections(MAX_CONNECTIONS)
        .set_batch_request_config(jsonrpsee::server::BatchRequestConfig::Limit(
            MAX_REQUESTS_PER_BATCH,
        ))
        .build(addr)
        .await
        .map_err(|e| format!("failed to start RPC server: {}", e))?;

    let bound_addr = server
        .local_addr()
        .map_err(|e| format!("failed to get RPC server address: {}", e))?;

    let rpc = RpcServer {
        state: rpc_state,
        chain_id,
    };
    let handle = server.start(rpc.into_rpc());
    tokio::spawn(handle.stopped());

    info!(%bound_addr, "JSON-RPC server started");
    Ok(bound_addr)
}

// ============================================================
// Helpers
// ============================================================

/// Validate a transaction at RPC ingress using the canonical
/// `pyde_tx::validation` pipeline. Reads the sender's on-chain
/// account + nonce + vesting lock + current chain state, feeds them
/// to `validate_transaction`. Reject here = no pollution of the
/// local mempool, no wasted gossip, no wasted proposer slot-budget.
///
/// The only intentional relaxation vs block-execution validation is
/// the sig-skip rule: on chain_id==31337 (devnet) we skip FALCON
/// verification so the `--dev` `pyde_sendTransaction` path (unsigned
/// txs from pre-funded accounts) still works. Any other chain_id
/// enforces sigs.
async fn ingress_validate(
    state: &Arc<RwLock<StateManager>>,
    chain: &Arc<RwLock<ChainState>>,
    tx: &Transaction,
) -> Result<(), ErrorObjectOwned> {
    let chain_r = chain.read().await;
    let chain_id = chain_r.chain_id;
    let base_fee = chain_r.base_fee;
    let head_slot = chain_r.head_slot;
    drop(chain_r);

    let state_r = state.read().await;
    let sender = pyde_tx::pipeline::load_account(&*state_r, &tx.from);
    let nonce_state = pyde_tx::pipeline::load_nonce(&*state_r, &tx.from);
    let sender_locked = pyde_tx::pipeline::read_vesting_schedule(&*state_r, &tx.from)
        .map(|s| s.locked_at(head_slot))
        .unwrap_or(0);
    drop(state_r);

    // Audit 226 / 304: gate the sender's auth_keys at ingress. Skip
    // for RegisterPubkey (audit 229) — the whole point of that tx
    // type is to upgrade `AuthKeys::None` accounts to `Single(pk)`.
    // `validate_register_pubkey` enforces its own stricter shape
    // checks (data == FALCON pk, from == Poseidon2(data), funded,
    // not already registered).
    if tx.tx_type != pyde_tx::types::TransactionType::RegisterPubkey {
        if let Err(msg) = plaintext_tx_ingest_policy(&sender.auth_keys, chain_id) {
            return Err(rpc_err(-32001, format!("ingress validation: {msg}")));
        }
    }

    // Audit 305: gate fee_payer at ingress so Paymaster / GasTank
    // never reach validation on production. Both paths are
    // currently broken (Paymaster mints fees, GasTank ignores its
    // encoded address) and would otherwise sit in the mempool
    // until block-time validation rejected them.
    if let Err(msg) = fee_payer_ingest_policy(&tx.fee_payer, chain_id) {
        return Err(rpc_err(-32001, format!("ingress validation: {msg}")));
    }

    let ctx = ValidationContext {
        block_height: head_slot,
        base_fee,
        block_gas_limit: pyde_tx::fee::GAS_CEILING,
        chain_id,
        dev_skip_signature: chain_id == 31337,
        sender_locked,
        // Ingress path verifies sigs itself; nothing pre-verified them.
        sig_pre_verified: false,
    };

    validate_transaction(tx, &sender, &nonce_state, &ctx).map_err(|e| {
        let code = match e {
            ValidationError::InvalidSignature => -32001,
            ValidationError::InvalidNonce(_) => -32002,
            ValidationError::InsufficientBalance { .. } => -32003,
            ValidationError::WrongChainId { .. } => -32004,
            ValidationError::GasLimitTooLow { .. } | ValidationError::GasLimitTooHigh { .. } => {
                -32005
            }
            ValidationError::DeadlineExpired { .. } => -32006,
            ValidationError::TxTooLarge { .. } | ValidationError::CalldataTooLarge { .. } => -32007,
            ValidationError::InvalidAccessList(_) => -32008,
            _ => -32000,
        };
        rpc_err(code, format!("ingress validation: {:?}", e))
    })
}

fn rpc_err(code: i32, msg: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(code, msg, None::<()>)
}

/// Default gas limit for `pyde_call` when the caller omits one. 100M
/// covers Vec deserialization + loop-heavy view functions seen in
/// real otic contracts.
const CALL_GAS_DEFAULT: u64 = 100_000_000;

/// Hard cap on `pyde_call` gas. `pyde_call` runs on the public RPC
/// node's CPU and never reaches a block, so an unbounded
/// caller-supplied gas value is a free CPU-burn DoS — a single
/// `gas: u64::MAX` request would spin until the request timed out.
/// 400M matches `pyde_tx::fee::GAS_TARGET`, the per-block target, so
/// any view function shape that fits in a block fits in a call.
const CALL_GAS_CAP: u64 = pyde_tx::fee::GAS_TARGET;

/// Clamp a caller-supplied `gas` parameter for `pyde_call`. None → use
/// the default; Some(g) → at most `CALL_GAS_CAP`.
fn clamp_call_gas(supplied: Option<u64>) -> u64 {
    match supplied {
        None => CALL_GAS_DEFAULT,
        Some(g) => g.min(CALL_GAS_CAP),
    }
}

/// Audit 349: assemble block-context fields for the RPC simulator
/// path (`pyde_call` / `pyde_estimateGas` / `pyde_createAccessList`)
/// from the live chain head. Pre-fix the simulators constructed a
/// zero-filled `ExecutionContext` so any view function that read
/// `block.number` / `block.timestamp` / the proposer address / a
/// recent block hash got `0`. Wallets relying on the simulator to
/// preview a function got results that diverged from on-chain
/// execution — most painfully on time-locked or block-height-gated
/// view functions, which always returned the "before genesis"
/// branch.
///
/// We treat the simulator as executing AT the current head:
///   * `block_number` = `head_slot`
///   * `timestamp` = head header timestamp
///   * `block_proposer` = head header proposer
/// Recent block hashes for the `BLOCKHASH` opcode are loaded from
/// the in-memory header cache (current + previous epoch) plus the
/// persistent `BlockStore` for older slots, indexed so that
/// `block_hashes[0]` is the most recent prior block (`head - 1`).
/// The PVM clamps lookups to 256 blocks so we cap the vec at that.
///
/// At genesis (no blocks processed yet) the helper returns
/// `(0, 0, [0; 32], vec![])` — semantically the same as pre-fix,
/// but only at genesis where there's no head to read from.
fn build_call_block_context(
    chain: &crate::chain::ChainState,
    block_store: &crate::block_store::BlockStore,
) -> (u64, u64, [u8; 32], Vec<ethnum::U256>) {
    if chain.is_genesis() {
        return (0, 0, [0u8; 32], Vec::new());
    }
    let head_slot = chain.head_slot;
    let (timestamp, proposer) = match chain.header(head_slot) {
        Some(h) => (h.timestamp, h.proposer),
        // Defensive fallback: head_slot was advanced but header
        // hasn't landed yet (only possible during a brief window
        // inside `advance`; ChainState writes are atomic from
        // outside but in-process readers might race). Fall back
        // to the persistent store.
        None => match block_store.get_header(head_slot) {
            Some(h) => (h.timestamp, h.proposer),
            None => (0, [0u8; 32]),
        },
    };

    // Build BLOCKHASH window: index 0 = head-1, index 1 = head-2,
    // ... up to 256 entries. Skip slots we can't resolve (genesis,
    // pruned, missing) by leaving them as zero — matches the PVM's
    // "unknown → 0" convention on the dispatch side.
    const BLOCKHASH_WINDOW: u64 = 256;
    let mut block_hashes = Vec::with_capacity(BLOCKHASH_WINDOW as usize);
    if head_slot > 0 {
        let n = head_slot.min(BLOCKHASH_WINDOW);
        for i in 1..=n {
            let slot = head_slot - i;
            let hash_bytes = chain
                .header(slot)
                .map(|h| h.hash())
                .or_else(|| block_store.get_header(slot).map(|h| h.hash()))
                .unwrap_or([0u8; 32]);
            block_hashes.push(ethnum::U256::from_le_bytes(hash_bytes));
        }
    }

    (head_slot, timestamp, proposer, block_hashes)
}

/// Resolve a caller-supplied `chainId` against the node's running
/// chain_id. None → the node's chain_id (sane default for omitted
/// fields). Some(v) where v == node.chain_id → accepted. Some(v)
/// where v ≠ node.chain_id → an `Err` the caller should surface as
/// JSON-RPC -32602.
///
/// Audit 302: the prior behavior defaulted missing `chainId` to 1
/// (mainnet), so a wallet that omitted the field on testnet signed a
/// tx bound to mainnet — the tx would fail verification on the local
/// chain AND replay the moment a chain with id 1 launched.
fn resolve_request_chain_id(supplied: Option<u64>, node_chain_id: u64) -> Result<u64, String> {
    match supplied {
        None => Ok(node_chain_id),
        Some(v) if v == node_chain_id => Ok(v),
        Some(v) => Err(format!(
            "chainId mismatch: tx claims {} but node is on {}",
            v, node_chain_id
        )),
    }
}

/// Policy choice for how to gate encrypted-tx RPC ingress against
/// `send_encrypted_transaction`'s sender-FALCON binding (audit item
/// 206). Split out as a pure function so the devnet/production
/// branch is unit-testable without spinning up an `RpcServer`.
///
/// Audit 384: this enum is the single source of truth for the
/// devnet-vs-production routing of encrypted-tx ingress. Three
/// callers (RPC `send_encrypted_transaction`, RPC
/// `send_raw_encrypted_transaction`, gossip ingress in `node.rs`)
/// MUST go through `encrypted_tx_ingest_policy` rather than
/// open-coding the match. Pre-fix the gossip path duplicated the
/// match inline, so any future change to the structural-only
/// devnet rule would need to be mirrored in three places — drift
/// would silently re-open the length-only ingress on mainnet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EncryptedTxIngestPolicy {
    /// Sender has an on-chain `Single` auth_key; route through full
    /// FALCON verification against it.
    Verify(Vec<u8>),
    /// Devnet-only: sender has no registered key yet (faucet /
    /// bootstrap account). Accept via structural-only — signature
    /// length is sanity-checked, FALCON is not.
    StructuralOnly,
    /// Production: sender has no registered key. Reject so attackers
    /// can't spoof `from = victim_fresh_address` through the
    /// length-only path.
    Reject,
}

/// See `EncryptedTxIngestPolicy`. `sender_pk` comes from the
/// sender's on-chain account (`None` means either no account or an
/// account with `AuthKeys::None`). `chain_id == 31337` identifies
/// devnet; any other chain_id is treated as production.
pub(crate) fn encrypted_tx_ingest_policy(
    sender_pk: Option<Vec<u8>>,
    chain_id: u64,
) -> EncryptedTxIngestPolicy {
    match sender_pk {
        Some(pk) => EncryptedTxIngestPolicy::Verify(pk),
        None if chain_id == 31337 => EncryptedTxIngestPolicy::StructuralOnly,
        None => EncryptedTxIngestPolicy::Reject,
    }
}

/// Plaintext-tx ingress policy (audit 206 / 226 / 304).
///
/// `pyde_tx::validation::validate_signature` short-circuits FALCON
/// verification when the sender account has `AuthKeys::None`
/// ("System/contract accounts — no signature check at this level"),
/// and `pyde_tx::pipeline::load_account` returns a default EOA with
/// `AuthKeys::None` for any address that has never been seen on chain.
/// The combination lets an attacker spoof `from = victim_fresh_address`
/// past the signature check; balance gates fund-loss but a Paymaster
/// fee_payer slips past balance too, polluting the mempool.
///
/// `validate_signature` ALSO short-circuits `AuthKeys::MultiSig`
/// ("Multi-sig validation is handled by the auth module / For now,
/// skip"). Until the multi-sig wire format and threshold-check
/// path land, any tx from a MultiSig-keyed account is accepted
/// with no auth at all — the same footgun shape as the None case.
///
/// Policy:
///   - Single: allow (validate_signature does the FALCON check).
///   - None on devnet (chain_id == 31337): allow — the faucet /
///     bootstrap UX needs unsigned txs from unregistered accounts.
///   - MultiSig on devnet: allow — keeps test infra that exercises
///     the variant working.
///   - None / MultiSig on any other chain_id: reject at ingress
///     (audits 226, 304).
fn plaintext_tx_ingest_policy(
    auth_keys: &pyde_account::types::AuthKeys,
    chain_id: u64,
) -> Result<(), &'static str> {
    match auth_keys {
        pyde_account::types::AuthKeys::Single(_) => Ok(()),
        pyde_account::types::AuthKeys::None if chain_id == 31337 => Ok(()),
        pyde_account::types::AuthKeys::MultiSig { .. } if chain_id == 31337 => Ok(()),
        pyde_account::types::AuthKeys::None => Err("sender has no registered auth_key (audit 226)"),
        pyde_account::types::AuthKeys::MultiSig { .. } => {
            Err("MultiSig auth_keys not yet enforced; rejecting on production (audit 304)")
        }
    }
}

/// Fee-payer ingress policy (audit 305). `FeePayer::Paymaster`
/// currently mints fees out of thin air — `pre_execution_charge`
/// returns Ok(0) for it ("settlement deferred to contract layer"),
/// then post-execution distribution credits validator and treasury
/// from a 0 placeholder. `FeePayer::GasTank` ignores the encoded
/// contract address entirely; it silently debits the sender's own
/// per-account `gas_tank` field, so the sponsorship UX is
/// decorative. Both paths are unsafe to expose on production
/// until the paymaster contract integration ships and the GasTank
/// wiring honours its address parameter. Devnet keeps both for
/// dev / test ergonomics.
fn fee_payer_ingest_policy(
    fee_payer: &pyde_tx::types::FeePayer,
    chain_id: u64,
) -> Result<(), &'static str> {
    match fee_payer {
        pyde_tx::types::FeePayer::Sender => Ok(()),
        _ if chain_id == 31337 => Ok(()),
        pyde_tx::types::FeePayer::Paymaster(_) => {
            Err("FeePayer::Paymaster not yet wired; rejecting on production (audit 305)")
        }
        pyde_tx::types::FeePayer::GasTank(_) => {
            Err("FeePayer::GasTank not yet wired; rejecting on production (audit 305)")
        }
    }
}

fn parse_address(input: &str) -> Result<[u8; 32], ErrorObjectOwned> {
    let hex_str = input.strip_prefix("0x").unwrap_or(input);
    let bytes =
        hex::decode(hex_str).map_err(|e| rpc_err(-32602, format!("invalid address: {}", e)))?;
    if bytes.len() != 32 {
        return Err(rpc_err(
            -32602,
            format!("address must be 32 bytes, got {}", bytes.len()),
        ));
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

fn parse_hash(input: &str) -> Result<[u8; 32], ErrorObjectOwned> {
    let hex_str = input.strip_prefix("0x").unwrap_or(input);
    let bytes =
        hex::decode(hex_str).map_err(|e| rpc_err(-32602, format!("invalid hash: {}", e)))?;
    if bytes.len() != 32 {
        return Err(rpc_err(
            -32602,
            format!("hash must be 32 bytes, got {}", bytes.len()),
        ));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

/// Parse a JSON call object into a Transaction + BlockContext for simulation.
#[allow(dead_code)]
async fn parse_call_object(
    obj: &serde_json::Value,
    rpc_state: &RpcState,
) -> Result<(pyde_tx::types::Transaction, BlockContext), ErrorObjectOwned> {
    let from = obj
        .get("from")
        .and_then(|v| v.as_str())
        .map(parse_address)
        .transpose()?
        .unwrap_or([0u8; 32]);
    let to = obj
        .get("to")
        .and_then(|v| v.as_str())
        .map(parse_address)
        .transpose()?
        .unwrap_or([0u8; 32]);
    let data = obj
        .get("data")
        .and_then(|v| v.as_str())
        .map(|s| {
            let s = s.strip_prefix("0x").unwrap_or(s);
            hex::decode(s).unwrap_or_default()
        })
        .unwrap_or_default();
    let value: u128 = obj
        .get("value")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let gas_limit: u64 = obj.get("gas").and_then(|v| v.as_u64()).unwrap_or(1_000_000);

    let chain = rpc_state.chain.read().await;
    let tx = pyde_tx::types::Transaction {
        from,
        to,
        value,
        data,
        gas_limit,
        nonce: 0,
        signature: vec![],
        fee_payer: pyde_tx::types::FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id: chain.chain_id,
        tx_type: pyde_tx::types::TransactionType::Standard,
    };
    let block_ctx = BlockContext {
        height: chain.head_slot,
        timestamp: chain.head_slot * 400,
        base_fee: chain.base_fee,
        block_gas_limit: pyde_tx::fee::GAS_CEILING,
        chain_id: chain.chain_id,
        validator_address: [0u8; 32],
        dev_skip_signature: false,
        block_sigs_pre_verified: false,
    };
    Ok((tx, block_ctx))
}

/// Decode the wire-encoded block at `slot` and emit one JSON object
/// per transaction with the fields an indexer/explorer needs to
/// render a tx without a second `getTransactionByHash` round-trip:
/// hash, sender, recipient, value, nonce, gas_limit, tx_type. Falls
/// back to an empty array if the block isn't on disk yet (genesis,
/// or a slot that this node only saw a header for during sync).
fn decode_block_transactions(block_store: &BlockStore, slot: u64) -> Vec<serde_json::Value> {
    let raw = match block_store.get_block_raw(slot) {
        Some(r) => r,
        None => return Vec::new(),
    };
    let block = match wire::decode_block(&raw) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    block
        .body
        .transactions
        .iter()
        .enumerate()
        .map(|(idx, tx)| {
            serde_json::json!({
                "hash": format!("0x{}", hex::encode(tx.hash())),
                "from": format!("0x{}", hex::encode(tx.from)),
                "to": format!("0x{}", hex::encode(tx.to)),
                "value": tx.value.to_string(),
                "nonce": tx.nonce,
                "gasLimit": tx.gas_limit,
                "txType": tx.tx_type as u8,
                "indexInBlock": idx,
            })
        })
        .collect()
}

fn receipt_to_json(receipt: &Receipt) -> serde_json::Value {
    let mut json = serde_json::json!({
        "txHash": format!("0x{}", hex::encode(receipt.tx_hash)),
        "success": receipt.success,
        "gasUsed": format!("0x{:x}", receipt.gas_used),
        "effectiveGas": format!("0x{:x}", receipt.effective_gas),
        "feePaid": receipt.fee_paid.to_string(),
        "feeBurned": receipt.fee_burned.to_string(),
        "feeValidator": receipt.fee_validator.to_string(),
        "feeTreasury": receipt.fee_treasury.to_string(),
        "logs": receipt.logs.iter().map(|l| serde_json::json!({
            "address": format!("0x{}", hex::encode(l.address)),
            "topics": l.topics.iter().map(|t| format!("0x{}", hex::encode(t))).collect::<Vec<_>>(),
            "data": format!("0x{}", hex::encode(&l.data)),
        })).collect::<Vec<_>>(),
    });
    // Include return_data if non-empty (ephemeral — not persisted to disk)
    if !receipt.return_data.is_empty() {
        json["returnData"] =
            serde_json::Value::String(format!("0x{}", hex::encode(&receipt.return_data)));
    }
    json
}

/// Read balance from Account bytes (try Account::from_bytes, fall back to raw u128).
fn read_account_balance(data: &[u8]) -> Option<u128> {
    if let Some(account) = pyde_account::types::Account::from_bytes(data) {
        Some(account.balance)
    } else if data.len() >= 16 {
        Some(decode_u128(data))
    } else {
        None
    }
}

fn decode_u128(data: &[u8]) -> u128 {
    if data.len() >= 16 {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&data[..16]);
        u128::from_le_bytes(buf)
    } else {
        0
    }
}

#[allow(dead_code)]
fn decode_u64(data: &[u8]) -> u64 {
    if data.len() >= 8 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[..8]);
        u64::from_le_bytes(buf)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_address() {
        let hex_addr = format!("0x{}", hex::encode([0xAA; 32]));
        let addr = parse_address(&hex_addr).unwrap();
        assert_eq!(addr, [0xAA; 32]);
    }

    #[test]
    fn parse_address_no_prefix() {
        let hex_addr = hex::encode([0xBB; 32]);
        let addr = parse_address(&hex_addr).unwrap();
        assert_eq!(addr, [0xBB; 32]);
    }

    #[test]
    fn parse_invalid_address_length() {
        assert!(parse_address("0xdeadbeef").is_err());
    }

    #[test]
    fn parse_invalid_hex() {
        assert!(parse_address("0xnothex").is_err());
    }

    #[test]
    fn parse_valid_hash() {
        let hex_hash = format!("0x{}", hex::encode([0xCC; 32]));
        let hash = parse_hash(&hex_hash).unwrap();
        assert_eq!(hash, [0xCC; 32]);
    }

    #[test]
    fn decode_u128_from_bytes() {
        let val: u128 = 10_000_000_000_000;
        assert_eq!(decode_u128(&val.to_le_bytes()), val);
    }

    #[test]
    fn decode_u128_short_returns_zero() {
        assert_eq!(decode_u128(&[1, 2, 3]), 0);
    }

    #[test]
    fn clamp_call_gas_default_when_omitted() {
        assert_eq!(clamp_call_gas(None), CALL_GAS_DEFAULT);
    }

    #[test]
    fn clamp_call_gas_passes_through_below_cap() {
        // Default sits below the cap, so it's preserved as-is.
        assert_eq!(clamp_call_gas(Some(50_000_000)), 50_000_000);
        assert_eq!(clamp_call_gas(Some(CALL_GAS_DEFAULT)), CALL_GAS_DEFAULT);
        // Exact cap is allowed.
        assert_eq!(clamp_call_gas(Some(CALL_GAS_CAP)), CALL_GAS_CAP);
    }

    #[test]
    fn clamp_call_gas_caps_oversized_request() {
        // The DoS vector: u64::MAX or any value above CALL_GAS_CAP must
        // be clamped to CALL_GAS_CAP, otherwise a single call ties up
        // the RPC node's CPU until the request times out.
        assert_eq!(clamp_call_gas(Some(CALL_GAS_CAP + 1)), CALL_GAS_CAP);
        assert_eq!(clamp_call_gas(Some(u64::MAX)), CALL_GAS_CAP);
        assert_eq!(clamp_call_gas(Some(2 * CALL_GAS_CAP)), CALL_GAS_CAP);
    }

    #[test]
    fn resolve_chain_id_defaults_to_node_when_missing() {
        // Audit 302: a wallet that omits `chainId` gets the node's
        // running chain_id, NOT a hardcoded mainnet=1 fallback.
        for node_chain in [1u64, 7, 7331, 31337, 1_000_000] {
            assert_eq!(
                resolve_request_chain_id(None, node_chain).unwrap(),
                node_chain,
                "node {} should default to itself",
                node_chain
            );
        }
    }

    #[test]
    fn resolve_chain_id_accepts_matching_value() {
        for chain in [1u64, 7331, 31337] {
            assert_eq!(resolve_request_chain_id(Some(chain), chain).unwrap(), chain);
        }
    }

    #[test]
    fn resolve_chain_id_rejects_mismatch() {
        // Cross-chain replay surface: testnet 7331 must reject a
        // mainnet=1 claim, and vice versa. Pre-fix this defaulted to
        // 1, so the mismatch was masked.
        assert!(resolve_request_chain_id(Some(1), 7331).is_err());
        assert!(resolve_request_chain_id(Some(7331), 1).is_err());
        assert!(resolve_request_chain_id(Some(31337), 7331).is_err());
        assert!(resolve_request_chain_id(Some(7331), 31337).is_err());
    }

    #[test]
    fn ingest_policy_verifies_when_auth_key_registered() {
        let pk = vec![0x11u8; 900];
        assert_eq!(
            encrypted_tx_ingest_policy(Some(pk.clone()), 1),
            EncryptedTxIngestPolicy::Verify(pk.clone())
        );
        // Devnet with a registered key still verifies — the
        // structural-only branch is only for the no-key case.
        assert_eq!(
            encrypted_tx_ingest_policy(Some(pk.clone()), 31337),
            EncryptedTxIngestPolicy::Verify(pk)
        );
    }

    #[test]
    fn ingest_policy_devnet_falls_through_without_key() {
        assert_eq!(
            encrypted_tx_ingest_policy(None, 31337),
            EncryptedTxIngestPolicy::StructuralOnly
        );
    }

    #[test]
    fn ingest_policy_production_rejects_without_key() {
        // Mainnet and any non-devnet chain_id must reject — otherwise
        // an attacker can spoof `from = victim_fresh_address` through
        // the length-only path.
        for chain_id in [1u64, 2, 7, 1337, 1_000_000] {
            assert_eq!(
                encrypted_tx_ingest_policy(None, chain_id),
                EncryptedTxIngestPolicy::Reject,
                "chain_id {} must reject no-key encrypted tx",
                chain_id
            );
        }
    }

    /// Audit 384: the `StructuralOnly` variant must NEVER appear on
    /// any chain_id other than the devnet sentinel (31337). Sweep a
    /// dense range of plausible chain_ids — including testnet (7331)
    /// and the canonical mainnet candidates — to guard against any
    /// future change widening the structural-only window. Pre-fix
    /// the gossip path in `node.rs` open-coded the match, so a drift
    /// between the RPC and gossip routing was the realistic failure
    /// mode this test is designed to catch.
    #[test]
    fn ingest_policy_structural_only_is_devnet_exclusive() {
        for chain_id in 0u64..=10_000 {
            let policy = encrypted_tx_ingest_policy(None, chain_id);
            if chain_id == 31337 {
                continue; // not in range, but explicit for clarity
            }
            assert_ne!(
                policy,
                EncryptedTxIngestPolicy::StructuralOnly,
                "chain_id {} must not produce StructuralOnly without auth_key",
                chain_id,
            );
        }
        // Spot-check the canonical chain_ids we actually care about.
        for chain_id in [1u64, 7331, 100_000, 1_000_000, u64::MAX] {
            assert_ne!(
                encrypted_tx_ingest_policy(None, chain_id),
                EncryptedTxIngestPolicy::StructuralOnly,
                "chain_id {} must not produce StructuralOnly without auth_key",
                chain_id,
            );
        }
        // And confirm devnet IS the only chain that returns it.
        assert_eq!(
            encrypted_tx_ingest_policy(None, 31337),
            EncryptedTxIngestPolicy::StructuralOnly,
        );
    }

    #[test]
    fn plaintext_ingest_policy_allows_single_on_every_chain() {
        // Single auth_key — the only universally-OK shape — allowed
        // on every chain_id.
        let pk = vec![0x11u8; 900];
        for chain_id in [1u64, 7, 31337, 1_000_000] {
            assert!(plaintext_tx_ingest_policy(
                &pyde_account::types::AuthKeys::Single(pk.clone()),
                chain_id,
            )
            .is_ok());
        }
    }

    /// Audit 304 — MultiSig is allowed on devnet for test infra
    /// but REJECTED on every other chain_id. The validation path
    /// silently passes any tx from a MultiSig sender; until the
    /// multi-sig wire format + threshold check ship, that's an
    /// open footgun.
    #[test]
    fn plaintext_ingest_policy_multisig_devnet_only() {
        let pk = vec![0x11u8; 900];
        let multi = pyde_account::types::AuthKeys::MultiSig {
            keys: vec![pk.clone()],
            threshold: 1,
        };
        // Devnet: allowed (test ergonomics).
        assert!(plaintext_tx_ingest_policy(&multi, 31337).is_ok());
        // Every other chain_id: rejected.
        for chain_id in [1u64, 2, 7, 7331, 1_000_000] {
            let err = plaintext_tx_ingest_policy(&multi, chain_id);
            assert!(
                err.is_err(),
                "chain_id {chain_id} must reject AuthKeys::MultiSig"
            );
            assert!(err.err().unwrap().contains("audit 304"));
        }
    }

    #[test]
    fn plaintext_ingest_policy_devnet_allows_no_auth_key() {
        // chain_id == 31337 keeps the relaxed faucet/bootstrap UX.
        assert!(plaintext_tx_ingest_policy(&pyde_account::types::AuthKeys::None, 31337).is_ok());
    }

    #[test]
    fn plaintext_ingest_policy_production_rejects_no_auth_key() {
        // Every non-devnet chain_id must reject so an attacker
        // can't spoof `from = victim_fresh_address` past the
        // sig-skip in validate_signature.
        for chain_id in [1u64, 2, 7, 1337, 1_000_000] {
            let err = plaintext_tx_ingest_policy(&pyde_account::types::AuthKeys::None, chain_id);
            assert!(
                err.is_err(),
                "chain_id {chain_id} must reject AuthKeys::None"
            );
        }
    }

    // ── Audit 305: fee_payer ingress gate ───────────────────────────

    #[test]
    fn fee_payer_ingest_policy_sender_always_ok() {
        for chain_id in [1u64, 7, 7331, 31337, 1_000_000] {
            assert!(
                fee_payer_ingest_policy(&pyde_tx::types::FeePayer::Sender, chain_id).is_ok(),
                "Sender must always pass at chain_id {chain_id}"
            );
        }
    }

    #[test]
    fn fee_payer_ingest_policy_paymaster_devnet_only() {
        let paymaster = pyde_tx::types::FeePayer::Paymaster([0xAA; 32]);
        assert!(fee_payer_ingest_policy(&paymaster, 31337).is_ok());
        for chain_id in [1u64, 2, 7, 7331, 1_000_000] {
            let err = fee_payer_ingest_policy(&paymaster, chain_id);
            assert!(
                err.is_err(),
                "chain_id {chain_id} must reject FeePayer::Paymaster"
            );
            assert!(err.err().unwrap().contains("audit 305"));
        }
    }

    #[test]
    fn fee_payer_ingest_policy_gas_tank_devnet_only() {
        let gas_tank = pyde_tx::types::FeePayer::GasTank([0xBB; 32]);
        assert!(fee_payer_ingest_policy(&gas_tank, 31337).is_ok());
        for chain_id in [1u64, 2, 7, 7331, 1_000_000] {
            let err = fee_payer_ingest_policy(&gas_tank, chain_id);
            assert!(
                err.is_err(),
                "chain_id {chain_id} must reject FeePayer::GasTank"
            );
            assert!(err.err().unwrap().contains("audit 305"));
        }
    }

    #[test]
    fn receipt_json_format() {
        let receipt = Receipt {
            tx_hash: [0xAA; 32],
            success: true,
            gas_used: 21000,
            gas_refund: 0,
            effective_gas: 21000,
            fee_paid: 1050000,
            fee_burned: 735000,    // 70%
            fee_validator: 210000, // 20%
            fee_treasury: 105000,  // 10%
            logs: vec![],
            state_root: sparse_merkle_tree::H256::zero(),
            return_data: vec![],
        };
        let json = receipt_to_json(&receipt);
        assert_eq!(json["success"], true);
        assert_eq!(json["gasUsed"], "0x5208");
    }

    // ========== Audit 349: build_call_block_context hydrates from chain head ==========

    fn dummy_header_with(
        slot: u64,
        timestamp: u64,
        proposer: pyde_account::address::Address,
    ) -> pyde_consensus::block::BlockHeader {
        pyde_consensus::block::BlockHeader {
            slot,
            epoch: 0,
            parent_hash: [0u8; 32],
            proposer,
            vrf_proof: vec![0xAA; 50],
            qc_previous: pyde_consensus::block::QuorumCert::empty(),
            tx_root: [slot as u8; 32],
            state_root: [slot as u8; 32],
            timestamp,
        }
    }

    /// At genesis (no headers landed yet) the helper returns
    /// zero-defaults — semantically the same as pre-fix, but
    /// scoped to the actual genesis case where there's no head
    /// to read from.
    #[test]
    fn audit_349_genesis_returns_zero_context() {
        let chain = crate::chain::ChainState::genesis([0xAA; 32], 7331);
        let dir = tempfile::tempdir().unwrap();
        let block_store = crate::block_store::BlockStore::open(dir.path()).unwrap();

        let (block_number, timestamp, proposer, hashes) =
            build_call_block_context(&chain, &block_store);

        assert_eq!(block_number, 0);
        assert_eq!(timestamp, 0);
        assert_eq!(proposer, [0u8; 32]);
        assert!(hashes.is_empty());
    }

    /// After advancing the head, `block_number`, `timestamp`, and
    /// `block_proposer` come straight from the head header.
    #[test]
    fn audit_349_head_fields_match_chain_head() {
        let mut chain = crate::chain::ChainState::genesis([0u8; 32], 7331);
        let dir = tempfile::tempdir().unwrap();
        let block_store = crate::block_store::BlockStore::open(dir.path()).unwrap();

        let head_proposer = [0xCC; 32];
        let head_timestamp = 1_715_000_000_000;
        let head_slot = 42;
        chain.advance(dummy_header_with(head_slot, head_timestamp, head_proposer));

        let (block_number, timestamp, proposer, _) = build_call_block_context(&chain, &block_store);
        assert_eq!(block_number, head_slot);
        assert_eq!(timestamp, head_timestamp);
        assert_eq!(proposer, head_proposer);
    }

    /// `block_hashes` is filled in newest-first order so
    /// `block_hashes[0]` is the hash of `head - 1`. The PVM's
    /// `BLOCKHASH` opcode at line ~810 of `crates/pvm/src/vm.rs`
    /// indexes via `idx = current - height - 1`, so the producer
    /// (this helper) must agree with the consumer (the PVM).
    #[test]
    fn audit_349_block_hashes_indexed_newest_first() {
        let mut chain = crate::chain::ChainState::genesis([0u8; 32], 7331);
        let dir = tempfile::tempdir().unwrap();
        let block_store = crate::block_store::BlockStore::open(dir.path()).unwrap();

        // Advance through slots 1..=5 with distinct timestamps so
        // each header.hash() differs.
        let mut slot_hashes: std::collections::HashMap<u64, [u8; 32]> =
            std::collections::HashMap::new();
        for slot in 1..=5u64 {
            let h = dummy_header_with(slot, slot * 1000, [(slot * 17) as u8; 32]);
            slot_hashes.insert(slot, h.hash());
            chain.advance(h);
        }

        let (head_slot, _, _, hashes) = build_call_block_context(&chain, &block_store);
        assert_eq!(head_slot, 5);

        // Window has 5 entries: head-1=4, head-2=3, head-3=2,
        // head-4=1, head-5=0 (genesis — no header, so zero).
        assert_eq!(hashes.len(), 5);

        let expect = |slot: u64| ethnum::U256::from_le_bytes(*slot_hashes.get(&slot).unwrap());
        assert_eq!(hashes[0], expect(4), "block_hashes[0] must be hash(head-1)");
        assert_eq!(hashes[1], expect(3));
        assert_eq!(hashes[2], expect(2));
        assert_eq!(hashes[3], expect(1));
        assert_eq!(
            hashes[4],
            ethnum::U256::ZERO,
            "slot 0 (genesis, no header recorded) → zero",
        );
    }

    /// The window is capped at 256 — past that, older block
    /// hashes are not surfaced (and the PVM's BLOCKHASH opcode
    /// rejects them anyway).
    #[test]
    fn audit_349_block_hashes_capped_at_256() {
        let mut chain = crate::chain::ChainState::genesis([0u8; 32], 7331);
        let dir = tempfile::tempdir().unwrap();
        let block_store = crate::block_store::BlockStore::open(dir.path()).unwrap();

        // Advance past 256 to confirm the cap fires.
        for slot in 1..=300u64 {
            chain.advance(dummy_header_with(slot, slot * 1000, [slot as u8; 32]));
        }

        let (_, _, _, hashes) = build_call_block_context(&chain, &block_store);
        assert_eq!(hashes.len(), 256, "BLOCKHASH window must cap at 256");
    }
}
