//! JSON-RPC server for Pyde node.
//!
//! Exposes chain state queries and transaction submission over HTTP.

use crate::chain::ChainState;
use crate::receipt_store::ReceiptStore;
use crate::state_manager::StateManager;
use crate::tx_relay::TxRelay;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObjectOwned;
use pyde_tx::execution::Receipt;
use pyde_tx::pipeline::{execute_transaction, BlockContext};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Shared node state accessible by RPC handlers.
pub struct RpcState {
    pub chain: Arc<RwLock<ChainState>>,
    pub state: Arc<RwLock<StateManager>>,
    pub tx_relay: Arc<RwLock<TxRelay>>,
    pub receipts: Arc<RwLock<ReceiptStore>>,
    /// Plain transaction queue (devnet mode — no threshold encryption).
    /// Proposer drains this to build blocks.
    pub pending_txs: Arc<RwLock<Vec<pyde_tx::types::Transaction>>>,
    /// Committee threshold public key for encrypting transactions (MEV protection).
    pub threshold_pk: Option<pyde_crypto::threshold::ThresholdPublicKey>,
    /// Broadcast channel for new block headers (WebSocket subscriptions).
    pub new_heads_tx: tokio::sync::broadcast::Sender<serde_json::Value>,
    /// Broadcast channel for pending transaction hashes.
    pub pending_tx_tx: tokio::sync::broadcast::Sender<String>,
    /// Broadcast channel for event logs.
    pub logs_tx: tokio::sync::broadcast::Sender<serde_json::Value>,
}

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

    #[method(name = "pyde_getBlockByNumber")]
    async fn get_block_by_number(&self, slot: u64) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get block info by block hash.
    #[method(name = "pyde_getBlockByHash")]
    async fn get_block_by_hash(&self, hash: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "pyde_stateRoot")]
    async fn state_root(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "pyde_syncing")]
    async fn syncing(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Submit a transaction as JSON object. Returns tx hash.
    /// Fields: from, to, value (decimal string), data (hex), gas (number), nonce (number).
    #[method(name = "pyde_sendTransaction")]
    async fn send_transaction(&self, tx_obj: serde_json::Value) -> Result<String, ErrorObjectOwned>;

    /// Submit a raw wire-encoded transaction (hex string). Returns tx hash.
    #[method(name = "pyde_sendRawTransaction")]
    async fn send_raw_transaction(&self, tx_hex: String) -> Result<String, ErrorObjectOwned>;

    /// Simulate a call without committing (read-only execution). Returns result hex.
    #[method(name = "pyde_call")]
    async fn call(&self, call_obj: serde_json::Value) -> Result<String, ErrorObjectOwned>;

    /// Estimate gas for a transaction.
    #[method(name = "pyde_estimateGas")]
    async fn estimate_gas(&self, call_obj: serde_json::Value) -> Result<String, ErrorObjectOwned>;

    /// Get a transaction receipt by tx hash.
    #[method(name = "pyde_getTransactionReceipt")]
    async fn get_transaction_receipt(&self, tx_hash: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get logs matching a filter.
    #[method(name = "pyde_getLogs")]
    async fn get_logs(&self, filter: serde_json::Value) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get the mempool size.
    #[method(name = "pyde_mempoolSize")]
    async fn mempool_size(&self) -> Result<String, ErrorObjectOwned>;

    /// Submit a transaction for threshold encryption and mempool inclusion.
    /// Accepts a JSON object with: from, to, value, data, gas, nonce, signature.
    /// The node encrypts it with the committee's threshold public key before adding to mempool.
    #[method(name = "pyde_sendEncryptedTransaction")]
    async fn send_encrypted_transaction(&self, tx_obj: serde_json::Value) -> Result<String, ErrorObjectOwned>;

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
    async fn subscribe_logs(&self, filter: serde_json::Value) -> jsonrpsee::core::SubscriptionResult;
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
        let balance = state.get(&key)
            .and_then(|b| read_account_balance(&b))
            .unwrap_or(0);
        Ok(balance.to_string())
    }

    async fn get_transaction_count(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        // Nonce is stored separately at nonce_key (NonceState: base u64 + bitmap u16)
        let key = pyde_state::keys::nonce_key(&addr);
        let state = self.state.state.read().await;
        let nonce = state.get(&key)
            .map(|b| {
                if b.len() >= 10 {
                    let ns = pyde_account::nonce::NonceState::from_bytes(
                        &<[u8; 10]>::try_from(&b[..10]).unwrap_or([0u8; 10])
                    );
                    ns.base
                } else {
                    0
                }
            })
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

    async fn get_block_by_number(&self, slot: u64) -> Result<serde_json::Value, ErrorObjectOwned> {
        let chain = self.state.chain.read().await;
        match chain.header(slot) {
            Some(header) => Ok(serde_json::json!({
                "slot": header.slot,
                "epoch": header.epoch,
                "parentHash": format!("0x{}", hex::encode(header.parent_hash)),
                "stateRoot": format!("0x{}", hex::encode(header.state_root)),
                "txRoot": format!("0x{}", hex::encode(header.tx_root)),
                "timestamp": format!("0x{:x}", header.timestamp),
                "proposer": format!("0x{}", hex::encode(header.proposer)),
            })),
            None => Err(rpc_err(-32602, format!("block not found at slot {}", slot))),
        }
    }

    async fn get_block_by_hash(&self, hash: String) -> Result<serde_json::Value, ErrorObjectOwned> {
        let block_hash = parse_hash(&hash)?;
        let chain = self.state.chain.read().await;
        match chain.header_by_hash(&block_hash) {
            Some(header) => Ok(serde_json::json!({
                "slot": header.slot,
                "epoch": header.epoch,
                "parentHash": format!("0x{}", hex::encode(header.parent_hash)),
                "stateRoot": format!("0x{}", hex::encode(header.state_root)),
                "txRoot": format!("0x{}", hex::encode(header.tx_root)),
                "timestamp": format!("0x{:x}", header.timestamp),
                "proposer": format!("0x{}", hex::encode(header.proposer)),
                "hash": format!("0x{}", hex::encode(block_hash)),
            })),
            None => Err(rpc_err(-32602, "block not found for hash".to_string())),
        }
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

    async fn send_transaction(&self, tx_obj: serde_json::Value) -> Result<String, ErrorObjectOwned> {
        let from = tx_obj.get("from").and_then(|v| v.as_str())
            .map(parse_address).transpose()?
            .ok_or_else(|| rpc_err(-32602, "missing 'from' field".into()))?;
        let to = tx_obj.get("to").and_then(|v| v.as_str())
            .map(parse_address).transpose()?
            .unwrap_or([0u8; 32]);
        let value: u128 = tx_obj.get("value").and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let data_hex = tx_obj.get("data").and_then(|v| v.as_str()).unwrap_or("");
        let data = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex))
            .unwrap_or_default();
        let gas_limit: u64 = tx_obj.get("gas").and_then(|v| v.as_u64())
            .unwrap_or(21_000);
        let nonce: u64 = tx_obj.get("nonce").and_then(|v| v.as_u64())
            .unwrap_or(0);

        let chain_r = self.state.chain.read().await;
        let chain_id = chain_r.chain_id;
        drop(chain_r);

        let tx_type = if to == [0u8; 32] {
            pyde_tx::types::TransactionType::Deploy
        } else {
            pyde_tx::types::TransactionType::Standard
        };

        // For deploy txs: encode constructor length prefix so pipeline can split.
        // Format: constructor_len(4 LE) + constructor_bytes + runtime_bytes + constructor_args
        let deploy_data = if tx_type == pyde_tx::types::TransactionType::Deploy {
            let constructor_len = tx_obj.get("constructorLen")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let constructor_args_hex = tx_obj.get("constructorArgs")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let constructor_args = hex::decode(
                constructor_args_hex.strip_prefix("0x").unwrap_or(constructor_args_hex)
            ).unwrap_or_default();

            // Compute runtime length (data = full bytecode = constructor + runtime)
            let runtime_len = if constructor_len > 0 && data.len() > constructor_len as usize {
                (data.len() - constructor_len as usize) as u32
            } else {
                data.len() as u32
            };

            // Format: constructor_len(4 LE) + runtime_len(4 LE) + constructor + runtime + args
            let mut encoded = Vec::with_capacity(8 + data.len() + constructor_args.len());
            encoded.extend_from_slice(&constructor_len.to_le_bytes());
            encoded.extend_from_slice(&runtime_len.to_le_bytes());
            encoded.extend_from_slice(&data);
            encoded.extend_from_slice(&constructor_args);
            encoded
        } else {
            data
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

        // Compute tx hash
        let tx_bytes = crate::wire::encode_transaction(&tx);
        let tx_hash = pyde_crypto::poseidon2::poseidon2_hash(&tx_bytes).to_bytes();

        // For deploy txs, compute the contract address.
        // Use Account.nonce (always 0 in devnet since pipeline doesn't increment Account.nonce).
        // This matches what the pipeline uses: derive_create_address(&from, sender.nonce).
        let contract_address = if tx_type == pyde_tx::types::TransactionType::Deploy {
            // Read the account nonce from state (matches pipeline's sender.nonce)
            let state = self.state.state.read().await;
            let balance_key = pyde_state::keys::balance_key(&from);
            let account_nonce = state.get(&balance_key)
                .and_then(|b| pyde_account::types::Account::from_bytes(&b))
                .map(|a| a.nonce)
                .unwrap_or(0);
            drop(state);
            let addr = pyde_account::address::derive_create_address(&from, account_nonce);
            Some(format!("0x{}", hex::encode(addr)))
        } else {
            None
        };

        // Add to pending tx queue
        let mut pending = self.state.pending_txs.write().await;
        pending.push(tx);
        let queue_size = pending.len();
        drop(pending);

        info!(
            tx_hash = hex::encode(tx_hash),
            queue_size,
            contract = ?contract_address,
            "transaction accepted into pending queue"
        );

        // Return tx hash + contract address for deploys
        if let Some(addr) = contract_address {
            Ok(serde_json::json!({
                "txHash": format!("0x{}", hex::encode(tx_hash)),
                "contractAddress": addr,
            }).to_string())
        } else {
            Ok(format!("0x{}", hex::encode(tx_hash)))
        }
    }

    async fn send_raw_transaction(&self, tx_hex: String) -> Result<String, ErrorObjectOwned> {
        let hex_str = tx_hex.strip_prefix("0x").unwrap_or(&tx_hex);
        let tx_bytes = hex::decode(hex_str)
            .map_err(|e| rpc_err(-32602, format!("invalid tx hex: {}", e)))?;
        let tx = crate::wire::decode_transaction(&tx_bytes)
            .map_err(|e| rpc_err(-32602, format!("invalid tx encoding: {}", e)))?;
        let tx_hash = pyde_crypto::poseidon2::poseidon2_hash(&tx_bytes).to_bytes();

        let mut pending = self.state.pending_txs.write().await;
        pending.push(tx);
        drop(pending);

        Ok(format!("0x{}", hex::encode(tx_hash)))
    }

    async fn call(&self, call_obj: serde_json::Value) -> Result<String, ErrorObjectOwned> {
        let from = call_obj.get("from").and_then(|v| v.as_str())
            .map(parse_address).transpose()?.unwrap_or([0u8; 32]);
        let to = call_obj.get("to").and_then(|v| v.as_str())
            .map(parse_address).transpose()?
            .ok_or_else(|| rpc_err(-32602, "missing 'to' for call".into()))?;
        let data_hex = call_obj.get("data").and_then(|v| v.as_str()).unwrap_or("");
        let calldata = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex))
            .unwrap_or_default();
        let gas_limit: u64 = call_obj.get("gas").and_then(|v| v.as_u64())
            .unwrap_or(100_000_000); // 100M default — Vec deserialization + loops need headroom

        // Acquire an OWNED read lock that lives for the entire call execution.
        // This prevents the block processor from modifying state mid-read.
        // Previously, we dropped the lock before PVM execution and used try_read()
        // per Sload, which could fail if the block processor held a write lock,
        // causing stale zero values to be cached in the VM overlay.
        let state_guard = Arc::clone(&self.state.state).read_owned().await;

        let code_key = pyde_state::keys::code_key(&to);
        let code = state_guard.get(&code_key)
            .ok_or_else(|| rpc_err(-32000, "no code at address".into()))?;

        // Acquire second read guard for code backend BEFORE creating VM
        // (both guards must be obtained before any non-Send value exists across await)
        let code_guard = Arc::clone(&self.state.state).read_owned().await;

        // Run PVM directly — no validation, no nonce/balance checks
        let ctx = pyde_vm::vm::ExecutionContext {
            caller: from,
            self_address: to,
            call_value: ethnum::U256::ZERO,
            block_number: 0,
            timestamp: 0,
            gas_price: ethnum::U256::ZERO,
            tx_nonce: 0,
            tx_gas_limit: gas_limit,
            tx_hash: ethnum::U256::ZERO,
            block_proposer: [0u8; 32],
            block_hashes: vec![],
            balances: std::collections::HashMap::new(),
        };

        let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(gas_limit, ctx);
        vm.calldata = calldata;

        if let Err(e) = vm.load(&code) {
            return Err(rpc_err(-32000, format!("failed to load code: {:?}", e)));
        }

        // Lazy storage backend (owned guard — no stale reads)
        vm.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let smt_key = sparse_merkle_tree::H256::from(key.to_le_bytes());
            state_guard.get(&smt_key)
        }));
        // Code backend for cross-contract calls (CallExt)
        vm.code_backend = Some(std::sync::Arc::new(move |addr: &[u8; 32]| {
            let ck = pyde_state::keys::code_key(addr);
            code_guard.get(&ck)
        }));

        let output = vm.execute();
        let success = output.outcome == pyde_vm::vm::Outcome::Success;

        if success {
            // Check r2 for blob return (Struct/Vec/String): r1=pointer, r2=byte_length
            let r2 = vm.cpu.read_gp(2);
            if r2 > 0 {
                let r1 = vm.cpu.read_gp(1) as usize;
                let len = r2 as usize;
                // Read serialized blob from VM memory
                let blob = vm.memory.load_bytes(r1, len);
                Ok(format!("0x{}", hex::encode(blob)))
            } else {
                // Check wide register w0 for Address/u256 returns
                let w0 = vm.cpu.read_wide(0);
                if w0 != ethnum::U256::ZERO {
                    // Wide return: format as full 32-byte hex
                    let bytes = w0.to_le_bytes();
                    Ok(format!("0x{}", hex::encode(bytes)))
                } else {
                    // GP return: r1
                    let return_value = vm.cpu.read_gp(1);
                    Ok(format!("0x{:x}", return_value))
                }
            }
        } else {
            Err(rpc_err(-32000, format!("execution failed: {:?}", output.outcome)))
        }
    }

    async fn estimate_gas(&self, call_obj: serde_json::Value) -> Result<String, ErrorObjectOwned> {
        // Run the same as call but return gas used
        let from = call_obj.get("from").and_then(|v| v.as_str())
            .map(parse_address).transpose()?.unwrap_or([0u8; 32]);
        let to = call_obj.get("to").and_then(|v| v.as_str())
            .map(parse_address).transpose()?.unwrap_or([0u8; 32]);
        let data_hex = call_obj.get("data").and_then(|v| v.as_str()).unwrap_or("");
        let calldata = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex))
            .unwrap_or_default();
        let gas_limit: u64 = call_obj.get("gas").and_then(|v| v.as_u64())
            .unwrap_or(1_000_000);

        if to == [0u8; 32] {
            // Deploy estimation
            return Ok(format!("0x{:x}", 32_000 + calldata.len() as u64 * 16));
        }

        let state_guard = Arc::clone(&self.state.state).read_owned().await;
        let code_key = pyde_state::keys::code_key(&to);
        let code = match state_guard.get(&code_key) {
            Some(c) => c,
            None => return Ok(format!("0x{:x}", 21_000)), // simple transfer
        };

        let ctx = pyde_vm::vm::ExecutionContext {
            caller: from,
            self_address: to,
            call_value: ethnum::U256::ZERO,
            block_number: 0,
            timestamp: 0,
            gas_price: ethnum::U256::ZERO,
            tx_nonce: 0,
            tx_gas_limit: gas_limit,
            tx_hash: ethnum::U256::ZERO,
            block_proposer: [0u8; 32],
            block_hashes: vec![],
            balances: std::collections::HashMap::new(),
        };

        let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(gas_limit, ctx);
        vm.calldata = calldata;
        let _ = vm.load(&code);
        // Hold read lock for entire execution via owned guard
        vm.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let smt_key = sparse_merkle_tree::H256::from(key.to_le_bytes());
            state_guard.get(&smt_key)
        }));
        let output = vm.execute();
        Ok(format!("0x{:x}", output.gas_used))
    }

    async fn get_transaction_receipt(&self, tx_hash: String) -> Result<serde_json::Value, ErrorObjectOwned> {
        let hash = parse_hash(&tx_hash)?;
        let store = self.state.receipts.read().await;

        match store.get(&hash) {
            Some(receipt) => Ok(receipt_to_json(receipt)),
            None => Err(rpc_err(-32602, "receipt not found".to_string())),
        }
    }

    async fn get_logs(&self, filter: serde_json::Value) -> Result<serde_json::Value, ErrorObjectOwned> {
        let from_slot = filter.get("fromBlock")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let to_slot = filter.get("toBlock")
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::MAX);
        let address_filter = filter.get("address")
            .and_then(|v| v.as_str())
            .map(|s| parse_address(s))
            .transpose()?;

        let store = self.state.receipts.read().await;
        let logs = store.get_logs(from_slot, to_slot, address_filter.as_ref());

        let result: Vec<serde_json::Value> = logs.iter().map(|(slot, log)| {
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

    async fn send_encrypted_transaction(&self, tx_obj: serde_json::Value) -> Result<String, ErrorObjectOwned> {
        let tpk = self.state.threshold_pk.as_ref()
            .ok_or_else(|| rpc_err(-32000, "threshold encryption not configured".to_string()))?;

        // Parse tx fields
        let from = tx_obj.get("from").and_then(|v| v.as_str())
            .map(parse_address).transpose()?.unwrap_or([0u8; 32]);
        let to = tx_obj.get("to").and_then(|v| v.as_str())
            .map(parse_address).transpose()?.unwrap_or([0u8; 32]);
        let value: u128 = tx_obj.get("value").and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok()).unwrap_or(0);
        let data_hex = tx_obj.get("data").and_then(|v| v.as_str()).unwrap_or("");
        let data = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex))
            .unwrap_or_default();
        let gas_limit: u64 = tx_obj.get("gas").and_then(|v| v.as_u64()).unwrap_or(100_000);
        let nonce: u64 = tx_obj.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0);
        let signature_hex = tx_obj.get("signature").and_then(|v| v.as_str()).unwrap_or("");
        let signature = hex::decode(signature_hex.strip_prefix("0x").unwrap_or(signature_hex))
            .unwrap_or_default();
        let chain_id: u64 = tx_obj.get("chainId").and_then(|v| v.as_u64()).unwrap_or(1);

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
            from, nonce, gas_limit, access_list, None, chain_id,
            signature, &to, value, &data, tpk,
        ).map_err(|e| rpc_err(-32000, format!("encryption failed: {}", e)))?;

        let tx_hash = enc_tx.hash();

        // Add to encrypted mempool
        let mut relay = self.state.tx_relay.write().await;
        relay.receive_tx(enc_tx);

        info!(tx_hash = hex::encode(tx_hash), "encrypted tx accepted into mempool");
        Ok(format!("0x{}", hex::encode(tx_hash)))
    }

    // ========================================================================
    // WebSocket Subscription Implementations
    // ========================================================================

    async fn subscribe_new_heads(
        &self,
        subscription_sink: jsonrpsee::PendingSubscriptionSink,
    ) -> jsonrpsee::core::SubscriptionResult {
        let sink = subscription_sink.accept().await?;
        let mut rx = self.state.new_heads_tx.subscribe();
        tokio::spawn(async move {
            while let Ok(header) = rx.recv().await {
                if sink.send(jsonrpsee::SubscriptionMessage::from_json(&header).unwrap()).await.is_err() {
                    break; // client disconnected
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
                if sink.send(jsonrpsee::SubscriptionMessage::from_json(&tx_hash).unwrap()).await.is_err() {
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
        // Parse filter for address and topic matching
        let filter_addr = filter.get("address")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase());
        tokio::spawn(async move {
            while let Ok(log) = rx.recv().await {
                // Apply filter: if address specified, only send matching logs
                if let Some(ref addr) = filter_addr {
                    let log_addr = log.get("address")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_lowercase());
                    if log_addr.as_deref() != Some(addr.as_str()) {
                        continue;
                    }
                }
                if sink.send(jsonrpsee::SubscriptionMessage::from_json(&log).unwrap()).await.is_err() {
                    break;
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

    let server = Server::builder()
        .build(addr)
        .await
        .map_err(|e| format!("failed to start RPC server: {}", e))?;

    let bound_addr = server.local_addr()
        .map_err(|e| format!("failed to get RPC server address: {}", e))?;

    let rpc = RpcServer { state: rpc_state, chain_id };
    let handle = server.start(rpc.into_rpc());
    tokio::spawn(handle.stopped());

    info!(%bound_addr, "JSON-RPC server started");
    Ok(bound_addr)
}

// ============================================================
// Helpers
// ============================================================

fn rpc_err(code: i32, msg: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(code, msg, None::<()>)
}

fn parse_address(input: &str) -> Result<[u8; 32], ErrorObjectOwned> {
    let hex_str = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(hex_str)
        .map_err(|e| rpc_err(-32602, format!("invalid address: {}", e)))?;
    if bytes.len() != 32 {
        return Err(rpc_err(-32602, format!("address must be 32 bytes, got {}", bytes.len())));
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

fn parse_hash(input: &str) -> Result<[u8; 32], ErrorObjectOwned> {
    let hex_str = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(hex_str)
        .map_err(|e| rpc_err(-32602, format!("invalid hash: {}", e)))?;
    if bytes.len() != 32 {
        return Err(rpc_err(-32602, format!("hash must be 32 bytes, got {}", bytes.len())));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

/// Parse a JSON call object into a Transaction + BlockContext for simulation.
async fn parse_call_object(
    obj: &serde_json::Value,
    rpc_state: &RpcState,
) -> Result<(pyde_tx::types::Transaction, BlockContext), ErrorObjectOwned> {
    let from = obj.get("from").and_then(|v| v.as_str())
        .map(parse_address).transpose()?.unwrap_or([0u8; 32]);
    let to = obj.get("to").and_then(|v| v.as_str())
        .map(parse_address).transpose()?.unwrap_or([0u8; 32]);
    let data = obj.get("data").and_then(|v| v.as_str())
        .map(|s| {
            let s = s.strip_prefix("0x").unwrap_or(s);
            hex::decode(s).unwrap_or_default()
        })
        .unwrap_or_default();
    let value: u128 = obj.get("value").and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let gas_limit: u64 = obj.get("gas").and_then(|v| v.as_u64())
        .unwrap_or(1_000_000);

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
        block_gas_limit: pyde_tx::fee::GAS_CEILING as u64,
        chain_id: chain.chain_id,
        validator_address: [0u8; 32],
    };
    Ok((tx, block_ctx))
}

fn receipt_to_json(receipt: &Receipt) -> serde_json::Value {
    serde_json::json!({
        "txHash": format!("0x{}", hex::encode(receipt.tx_hash)),
        "success": receipt.success,
        "gasUsed": format!("0x{:x}", receipt.gas_used),
        "effectiveGas": format!("0x{:x}", receipt.effective_gas),
        "feePaid": receipt.fee_paid.to_string(),
        "feeBurned": receipt.fee_burned.to_string(),
        "feeValidator": receipt.fee_validator.to_string(),
        "logs": receipt.logs.iter().map(|l| serde_json::json!({
            "address": format!("0x{}", hex::encode(l.address)),
            "topics": l.topics.iter().map(|t| format!("0x{}", hex::encode(t))).collect::<Vec<_>>(),
            "data": format!("0x{}", hex::encode(&l.data)),
        })).collect::<Vec<_>>(),
    })
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
    } else { 0 }
}

fn decode_u64(data: &[u8]) -> u64 {
    if data.len() >= 8 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[..8]);
        u64::from_le_bytes(buf)
    } else { 0 }
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
    fn receipt_json_format() {
        let receipt = Receipt {
            tx_hash: [0xAA; 32],
            success: true,
            gas_used: 21000,
            gas_refund: 0,
            effective_gas: 21000,
            fee_paid: 1050000,
            fee_burned: 840000,
            fee_validator: 210000,
            logs: vec![],
            state_root: sparse_merkle_tree::H256::zero(),
        };
        let json = receipt_to_json(&receipt);
        assert_eq!(json["success"], true);
        assert_eq!(json["gasUsed"], "0x5208");
    }
}
