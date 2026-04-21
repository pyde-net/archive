use crate::error::{Result, SdkError};
use crate::types::{BlockHeader, Log, LogFilter};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, oneshot, Mutex};

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// WebSocket JSON-RPC provider with subscription support.
///
/// ```rust,ignore
/// let ws = WsProvider::connect("ws://127.0.0.1:8546").await?;
///
/// // Subscribe to new blocks
/// let mut blocks = ws.subscribe_new_heads().await?;
/// tokio::spawn(async move {
///     while let Ok(header) = blocks.recv().await {
///         println!("New block: {}", header.slot);
///     }
/// });
///
/// // Standard queries also work
/// let balance = ws.get_balance(&addr).await?;
///
/// ws.close().await;
/// ```
pub struct WsProvider {
    sender: Arc<
        Mutex<futures_util::stream::SplitSink<WsStream, tokio_tungstenite::tungstenite::Message>>,
    >,
    rpc_id: Arc<Mutex<u64>>,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<serde_json::Value>>>>,
    new_heads_tx: broadcast::Sender<BlockHeader>,
    pending_tx_tx: broadcast::Sender<String>,
    logs_tx: broadcast::Sender<Log>,
    _handle: tokio::task::JoinHandle<()>,
}

impl WsProvider {
    /// Connect to a WebSocket JSON-RPC endpoint.
    pub async fn connect(url: &str) -> Result<Self> {
        let (ws, _) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| SdkError::Connection(format!("WebSocket connect: {}", e)))?;

        let (sink, mut stream) = ws.split();
        let sender = Arc::new(Mutex::new(sink));
        let pending: Arc<Mutex<HashMap<u64, oneshot::Sender<serde_json::Value>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (new_heads_tx, _) = broadcast::channel(64);
        let (pending_tx_tx, _) = broadcast::channel(64);
        let (logs_tx, _) = broadcast::channel(256);

        let pending_clone = pending.clone();
        let heads_tx = new_heads_tx.clone();
        let ptx_tx = pending_tx_tx.clone();
        let ltx = logs_tx.clone();

        let handle = tokio::spawn(async move {
            while let Some(msg) = stream.next().await {
                let msg = match msg {
                    Ok(tokio_tungstenite::tungstenite::Message::Text(t)) => t,
                    _ => continue,
                };
                let data: serde_json::Value = match serde_json::from_str(&msg) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                // Subscription notification
                if data.get("method").is_some() {
                    let result = data.get("params").and_then(|p| p.get("result"));
                    let method = data["method"].as_str().unwrap_or("");

                    if let Some(result) = result {
                        if method.contains("subscription") {
                            // Try as block header
                            if let Ok(header) =
                                serde_json::from_value::<BlockHeader>(result.clone())
                            {
                                let _ = heads_tx.send(header);
                            }
                            // Try as log
                            else if let Ok(log) = serde_json::from_value::<Log>(result.clone()) {
                                let _ = ltx.send(log);
                            }
                            // Try as pending tx hash
                            else if let Some(hash) = result.as_str() {
                                let _ = ptx_tx.send(hash.to_string());
                            }
                        }
                    }
                    continue;
                }

                // RPC response
                if let Some(id) = data.get("id").and_then(|v| v.as_u64()) {
                    let mut map = pending_clone.lock().await;
                    if let Some(tx) = map.remove(&id) {
                        let _ = tx.send(data);
                    }
                }
            }
        });

        Ok(Self {
            sender,
            rpc_id: Arc::new(Mutex::new(0)),
            pending,
            new_heads_tx,
            pending_tx_tx,
            logs_tx,
            _handle: handle,
        })
    }

    // ========================================================================
    // Subscriptions
    // ========================================================================

    /// Subscribe to new block headers.
    pub async fn subscribe_new_heads(&self) -> Result<broadcast::Receiver<BlockHeader>> {
        self.rpc("pyde_subscribe", &[serde_json::json!("newHeads")])
            .await?;
        Ok(self.new_heads_tx.subscribe())
    }

    /// Subscribe to pending transactions.
    pub async fn subscribe_pending_transactions(&self) -> Result<broadcast::Receiver<String>> {
        self.rpc("pyde_subscribePending", &[]).await?;
        Ok(self.pending_tx_tx.subscribe())
    }

    /// Subscribe to contract event logs matching a filter.
    pub async fn subscribe_logs(&self, filter: &LogFilter) -> Result<broadcast::Receiver<Log>> {
        self.rpc(
            "pyde_subscribeLogs",
            &[serde_json::to_value(filter).unwrap_or_default()],
        )
        .await?;
        Ok(self.logs_tx.subscribe())
    }

    // ========================================================================
    // Standard queries (same as HTTP Provider)
    // ========================================================================

    pub async fn get_balance(&self, address: &[u8; 32]) -> Result<u128> {
        let result = self
            .rpc(
                "pyde_getBalance",
                &[serde_json::json!(format!("0x{}", hex::encode(address)))],
            )
            .await?;
        let s = result.as_str().unwrap_or("0x0");
        u128::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| SdkError::InvalidResponse(format!("bad balance: {}", e)))
    }

    pub async fn get_block_number(&self) -> Result<u64> {
        let result = self.rpc("pyde_blockNumber", &[]).await?;
        let s = result.as_str().unwrap_or("0x0");
        u64::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| SdkError::InvalidResponse(format!("bad block number: {}", e)))
    }

    pub async fn get_chain_id(&self) -> Result<u64> {
        let result = self.rpc("pyde_chainId", &[]).await?;
        let s = result.as_str().unwrap_or("0x0");
        u64::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| SdkError::InvalidResponse(format!("bad chain id: {}", e)))
    }

    // ========================================================================
    // Cleanup
    // ========================================================================

    /// Close the WebSocket connection.
    pub async fn close(&self) {
        let mut sink = self.sender.lock().await;
        let _ = sink.close().await;
    }

    // ========================================================================
    // Internal
    // ========================================================================

    async fn rpc(&self, method: &str, params: &[serde_json::Value]) -> Result<serde_json::Value> {
        let id = {
            let mut id = self.rpc_id.lock().await;
            *id += 1;
            *id
        };

        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);

        {
            let mut sink = self.sender.lock().await;
            sink.send(tokio_tungstenite::tungstenite::Message::Text(
                msg.to_string(),
            ))
            .await
            .map_err(|e| SdkError::Connection(format!("WS send: {}", e)))?;
        }

        let result = rx
            .await
            .map_err(|_| SdkError::Connection("WS response channel closed".into()))?;
        if let Some(err) = result.get("error") {
            return Err(SdkError::Rpc(err.to_string()));
        }
        Ok(result
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }
}
