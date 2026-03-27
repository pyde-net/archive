//! JSON-RPC server for Pyde node.
//!
//! Exposes chain state queries over HTTP.
//! Methods follow a similar pattern to Ethereum's JSON-RPC but with Pyde-specific naming.

use crate::chain::ChainState;
use crate::state_manager::StateManager;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObjectOwned;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Shared node state accessible by RPC handlers.
pub struct RpcState {
    pub chain: Arc<RwLock<ChainState>>,
    pub state: Arc<RwLock<StateManager>>,
}

/// Define the Pyde JSON-RPC API.
#[rpc(server)]
pub trait PydeApi {
    /// Get the balance of an address (hex-encoded, returns decimal string).
    #[method(name = "pyde_getBalance")]
    async fn get_balance(&self, address: String) -> Result<String, ErrorObjectOwned>;

    /// Get the transaction count (nonce) of an address.
    #[method(name = "pyde_getTransactionCount")]
    async fn get_transaction_count(&self, address: String) -> Result<String, ErrorObjectOwned>;

    /// Get the deployed code at an address (hex-encoded).
    #[method(name = "pyde_getCode")]
    async fn get_code(&self, address: String) -> Result<String, ErrorObjectOwned>;

    /// Get a storage value at an address and slot index.
    #[method(name = "pyde_getStorageAt")]
    async fn get_storage_at(&self, address: String, slot: u64) -> Result<String, ErrorObjectOwned>;

    /// Get the current base fee (gas price).
    #[method(name = "pyde_gasPrice")]
    async fn gas_price(&self) -> Result<String, ErrorObjectOwned>;

    /// Get the chain ID.
    #[method(name = "pyde_chainId")]
    async fn chain_id(&self) -> Result<String, ErrorObjectOwned>;

    /// Get the latest block number (slot).
    #[method(name = "pyde_blockNumber")]
    async fn block_number(&self) -> Result<String, ErrorObjectOwned>;

    /// Get block info by slot number.
    #[method(name = "pyde_getBlockByNumber")]
    async fn get_block_by_number(&self, slot: u64) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get the state root at the chain tip.
    #[method(name = "pyde_stateRoot")]
    async fn state_root(&self) -> Result<String, ErrorObjectOwned>;

    /// Get sync status.
    #[method(name = "pyde_syncing")]
    async fn syncing(&self) -> Result<serde_json::Value, ErrorObjectOwned>;
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
            .map(|b| decode_u128(&b))
            .unwrap_or(0);
        Ok(balance.to_string())
    }

    async fn get_transaction_count(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let key = pyde_state::keys::nonce_key(&addr);
        let state = self.state.state.read().await;
        let nonce = state.get(&key)
            .map(|b| decode_u64(&b))
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
            None => Err(ErrorObjectOwned::owned(
                -32602,
                format!("block not found at slot {}", slot),
                None::<()>,
            )),
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

    let rpc = RpcServer {
        state: rpc_state,
        chain_id,
    };

    let handle = server.start(rpc.into_rpc());
    // Keep the server running in the background
    tokio::spawn(handle.stopped());

    info!(%bound_addr, "JSON-RPC server started");
    Ok(bound_addr)
}

/// Parse a hex address string to 32-byte address.
fn parse_address(input: &str) -> Result<[u8; 32], ErrorObjectOwned> {
    let hex_str = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(hex_str).map_err(|e| {
        ErrorObjectOwned::owned(-32602, format!("invalid address: {}", e), None::<()>)
    })?;
    if bytes.len() != 32 {
        return Err(ErrorObjectOwned::owned(
            -32602,
            format!("address must be 32 bytes, got {}", bytes.len()),
            None::<()>,
        ));
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

/// Decode a u128 from LE bytes (balance).
fn decode_u128(data: &[u8]) -> u128 {
    if data.len() >= 16 {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&data[..16]);
        u128::from_le_bytes(buf)
    } else {
        0
    }
}

/// Decode a u64 from LE bytes (nonce).
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
        let result = parse_address("0xdeadbeef");
        assert!(result.is_err());
    }

    #[test]
    fn parse_invalid_hex() {
        let result = parse_address("0xnothex");
        assert!(result.is_err());
    }

    #[test]
    fn decode_u128_from_bytes() {
        let val: u128 = 10_000_000_000_000;
        let bytes = val.to_le_bytes();
        assert_eq!(decode_u128(&bytes), val);
    }

    #[test]
    fn decode_u128_short_returns_zero() {
        assert_eq!(decode_u128(&[1, 2, 3]), 0);
    }

    #[test]
    fn decode_u64_from_bytes() {
        let val: u64 = 42;
        let bytes = val.to_le_bytes();
        assert_eq!(decode_u64(&bytes), val);
    }
}
