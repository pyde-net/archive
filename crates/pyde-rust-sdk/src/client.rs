use crate::error::{Result, SdkError};
use crate::types::*;

/// Provider options for configuring HTTP behavior.
pub struct ProviderOptions {
    /// Request timeout (default: 30s).
    pub timeout: std::time::Duration,
    /// Number of retry attempts (default: 0).
    pub retries: u32,
}

impl Default for ProviderOptions {
    fn default() -> Self {
        Self { timeout: std::time::Duration::from_secs(30), retries: 0 }
    }
}

/// RPC client for interacting with a Pyde node.
pub struct Provider {
    rpc_url: String,
    client: reqwest::Client,
    retries: u32,
}

impl Provider {
    pub fn new(rpc_url: &str) -> Self {
        Self::with_options(rpc_url, ProviderOptions::default())
    }

    pub fn with_options(rpc_url: &str, options: ProviderOptions) -> Self {
        let client = reqwest::Client::builder()
            .timeout(options.timeout)
            .build()
            .unwrap_or_default();
        Self { rpc_url: rpc_url.to_string(), client, retries: options.retries }
    }

    // ========================================================================
    // Queries
    // ========================================================================

    pub async fn get_balance(&self, addr: &Address) -> Result<u128> {
        let result = self.rpc("pyde_getBalance", &[json_str(&format_address(addr))]).await?;
        parse_u128_str(&result)
    }

    pub async fn get_nonce(&self, addr: &Address) -> Result<u64> {
        let result = self.rpc("pyde_getTransactionCount", &[json_str(&format_address(addr))]).await?;
        parse_u64_str(&result)
    }

    pub async fn get_code(&self, addr: &Address) -> Result<Vec<u8>> {
        let result = self.rpc("pyde_getCode", &[json_str(&format_address(addr))]).await?;
        let hex = result.as_str().unwrap_or("0x").trim_start_matches("0x");
        hex::decode(hex).map_err(|e| SdkError::InvalidResponse(format!("bad code hex: {}", e)))
    }

    pub async fn get_chain_id(&self) -> Result<u64> {
        let result = self.rpc("pyde_chainId", &[]).await?;
        parse_hex_u64(&result)
    }

    pub async fn get_block_number(&self) -> Result<u64> {
        let result = self.rpc("pyde_blockNumber", &[]).await?;
        parse_hex_u64(&result)
    }

    pub async fn get_gas_price(&self) -> Result<u128> {
        let result = self.rpc("pyde_gasPrice", &[]).await?;
        parse_u128_str(&result)
    }

    pub async fn get_storage_at(&self, addr: &Address, slot: u64) -> Result<Vec<u8>> {
        let result = self.rpc("pyde_getStorageAt", &[
            json_str(&format_address(addr)),
            serde_json::Value::Number(slot.into()),
        ]).await?;
        let hex = result.as_str().unwrap_or("0x").trim_start_matches("0x");
        hex::decode(hex).map_err(|e| SdkError::InvalidResponse(format!("bad storage hex: {}", e)))
    }

    pub async fn get_block_by_number(&self, slot: u64) -> Result<Option<BlockHeader>> {
        let result = self.rpc("pyde_getBlockByNumber", &[
            serde_json::Value::Number(slot.into()),
        ]).await?;
        if result.is_null() {
            return Ok(None);
        }
        serde_json::from_value(result)
            .map(Some)
            .map_err(|e| SdkError::InvalidResponse(format!("bad block: {}", e)))
    }

    // ========================================================================
    // Static calls & gas estimation
    // ========================================================================

    pub async fn call(&self, to: &Address, data: &[u8]) -> Result<Vec<u8>> {
        self.call_with(to, data, None).await
    }

    /// Static call with overrides (from, value, gas).
    pub async fn call_with(&self, to: &Address, data: &[u8], overrides: Option<&CallOverrides>) -> Result<Vec<u8>> {
        let mut params = serde_json::json!({
            "from": overrides.and_then(|o| o.from.as_ref()).map(|a| format_address(a))
                .unwrap_or_else(|| "0x".to_string() + &"00".repeat(32)),
            "to": format_address(to),
            "data": format!("0x{}", hex::encode(data)),
        });
        if let Some(o) = overrides {
            if let Some(v) = o.value { params["value"] = serde_json::json!(format!("0x{:x}", v)); }
            if let Some(g) = o.gas_limit { params["gas"] = serde_json::json!(format!("0x{:x}", g)); }
        }
        let result = self.rpc("pyde_call", &[params]).await?;
        let hex = result.as_str().unwrap_or("0x").trim_start_matches("0x");
        hex::decode(hex).map_err(|e| SdkError::InvalidResponse(format!("bad call result: {}", e)))
    }

    pub async fn estimate_gas(&self, to: &Address, data: &[u8]) -> Result<u64> {
        self.estimate_gas_with(to, data, None).await
    }

    /// Estimate gas with overrides (from, value, gas).
    pub async fn estimate_gas_with(&self, to: &Address, data: &[u8], overrides: Option<&CallOverrides>) -> Result<u64> {
        let mut params = serde_json::json!({
            "from": overrides.and_then(|o| o.from.as_ref()).map(|a| format_address(a))
                .unwrap_or_else(|| "0x".to_string() + &"00".repeat(32)),
            "to": format_address(to),
            "data": format!("0x{}", hex::encode(data)),
        });
        if let Some(o) = overrides {
            if let Some(v) = o.value { params["value"] = serde_json::json!(format!("0x{:x}", v)); }
            if let Some(g) = o.gas_limit { params["gas"] = serde_json::json!(format!("0x{:x}", g)); }
        }
        let result = self.rpc("pyde_estimateGas", &[params]).await?;
        parse_hex_u64(&result)
    }

    /// Look up a transaction by its hash. Returns None if not found.
    pub async fn get_transaction(&self, tx_hash: &[u8; 32]) -> Result<Option<serde_json::Value>> {
        let result = self.rpc("pyde_getTransactionByHash", &[
            json_str(&format!("0x{}", hex::encode(tx_hash))),
        ]).await?;
        if result.is_null() { Ok(None) } else { Ok(Some(result)) }
    }

    /// Get current fee data (base fee = gas price in Pyde's EIP-1559 model).
    pub async fn get_fee_data(&self) -> Result<FeeData> {
        let gas_price = self.get_gas_price().await?;
        Ok(FeeData { gas_price, base_fee: gas_price })
    }

    // ========================================================================
    // Transaction submission
    // ========================================================================

    /// Send a signed transaction. Returns a TransactionResponse with hash and wait().
    pub async fn send_transaction(&self, tx: &Transaction) -> Result<TransactionResponse<'_>> {
        let tx_bytes = tx.to_bytes();
        let result = self.rpc("pyde_sendRawTransaction", &[
            json_str(&format!("0x{}", hex::encode(&tx_bytes))),
        ]).await?;
        let hash = parse_tx_hash(&result)?;
        Ok(TransactionResponse { hash, provider: self })
    }

    /// Send a signed transaction and wait for the receipt.
    pub async fn send_and_wait(&self, tx: &Transaction, timeout_ms: u64) -> Result<Receipt> {
        let tx_resp = self.send_transaction(tx).await?;
        tx_resp.wait(timeout_ms).await
    }

    // ========================================================================
    // Receipts
    // ========================================================================

    pub async fn get_receipt(&self, tx_hash: &[u8; 32]) -> Result<Option<Receipt>> {
        let result = self.rpc("pyde_getTransactionReceipt", &[
            json_str(&format!("0x{}", hex::encode(tx_hash))),
        ]).await?;
        if result.is_null() {
            return Ok(None);
        }
        serde_json::from_value(result)
            .map(Some)
            .map_err(|e| SdkError::InvalidResponse(format!("bad receipt: {}", e)))
    }

    /// Poll for a receipt until available or timeout.
    pub async fn wait_for_receipt(&self, tx_hash: &[u8; 32], timeout_ms: u64) -> Result<Receipt> {
        let start = std::time::Instant::now();
        loop {
            if let Some(receipt) = self.get_receipt(tx_hash).await? {
                return Ok(receipt);
            }
            if start.elapsed().as_millis() as u64 > timeout_ms {
                return Err(SdkError::Timeout(format!(
                    "receipt not available after {}ms for tx 0x{}",
                    timeout_ms,
                    hex::encode(tx_hash)
                )));
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    // ========================================================================
    // Events
    // ========================================================================

    pub async fn get_logs(&self, filter: &LogFilter) -> Result<Vec<Log>> {
        let params = serde_json::to_value(filter)
            .map_err(|e| SdkError::InvalidResponse(format!("bad filter: {}", e)))?;
        let result = self.rpc("pyde_getLogs", &[params]).await?;
        serde_json::from_value(result)
            .map_err(|e| SdkError::InvalidResponse(format!("bad logs: {}", e)))
    }

    // ========================================================================
    // Internal RPC helper
    // ========================================================================

    // ========================================================================
    // Batch RPC
    // ========================================================================

    /// Send multiple RPC calls in a single HTTP request.
    pub async fn batch(&self, calls: &[(&str, &[serde_json::Value])]) -> Result<Vec<serde_json::Value>> {
        let bodies: Vec<_> = calls.iter().enumerate().map(|(i, (method, params))| {
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": i + 1,
                "method": method,
                "params": params,
            })
        }).collect();

        let resp = self.client
            .post(&self.rpc_url)
            .json(&bodies)
            .send()
            .await
            .map_err(|e| SdkError::Connection(e.to_string()))?;

        let results: Vec<serde_json::Value> = resp
            .json()
            .await
            .map_err(|e| SdkError::InvalidResponse(e.to_string()))?;

        results.into_iter().map(|r| {
            if let Some(err) = r.get("error") {
                Err(SdkError::Rpc(err.to_string()))
            } else {
                Ok(r.get("result").cloned().unwrap_or(serde_json::Value::Null))
            }
        }).collect()
    }

    // ========================================================================
    // Internal RPC helper
    // ========================================================================

    async fn rpc(&self, method: &str, params: &[serde_json::Value]) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let mut last_err = SdkError::Connection("no attempts".into());
        for attempt in 0..=self.retries {
            match self.do_rpc(&body).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    last_err = e;
                    if attempt < self.retries {
                        tokio::time::sleep(std::time::Duration::from_millis(100 * (attempt as u64 + 1))).await;
                    }
                }
            }
        }
        Err(last_err)
    }

    async fn do_rpc(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        let resp = self.client
            .post(&self.rpc_url)
            .json(body)
            .send()
            .await
            .map_err(|e| SdkError::Connection(e.to_string()))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SdkError::InvalidResponse(e.to_string()))?;

        if let Some(err) = json.get("error") {
            return Err(SdkError::Rpc(err.to_string()));
        }

        Ok(json.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }
}

// ============================================================================
// Parsing helpers
// ============================================================================

/// Pending transaction handle returned by send_transaction().
pub struct TransactionResponse<'a> {
    /// Transaction hash.
    pub hash: [u8; 32],
    provider: &'a Provider,
}

impl<'a> TransactionResponse<'a> {
    /// Transaction hash as 0x-prefixed hex string.
    pub fn hash_hex(&self) -> String {
        format!("0x{}", hex::encode(self.hash))
    }

    /// Wait for the transaction to be included in a block.
    pub async fn wait(&self, timeout_ms: u64) -> Result<Receipt> {
        self.provider.wait_for_receipt(&self.hash, timeout_ms).await
    }
}

fn json_str(s: &str) -> serde_json::Value {
    serde_json::Value::String(s.to_string())
}

fn parse_hex_u64(val: &serde_json::Value) -> Result<u64> {
    let s = val.as_str().unwrap_or("0x0");
    let hex = s.trim_start_matches("0x");
    u64::from_str_radix(hex, 16)
        .map_err(|_| SdkError::InvalidResponse(format!("bad hex u64: {}", s)))
}

fn parse_u64_str(val: &serde_json::Value) -> Result<u64> {
    let s = val.as_str().unwrap_or("0");
    // Try hex first, then decimal
    if s.starts_with("0x") {
        parse_hex_u64(val)
    } else {
        s.parse::<u64>()
            .map_err(|_| SdkError::InvalidResponse(format!("bad u64: {}", s)))
    }
}

fn parse_u128_str(val: &serde_json::Value) -> Result<u128> {
    let s = val.as_str().unwrap_or("0");
    if s.starts_with("0x") {
        let hex = s.trim_start_matches("0x");
        u128::from_str_radix(hex, 16)
            .map_err(|_| SdkError::InvalidResponse(format!("bad hex u128: {}", s)))
    } else {
        s.parse::<u128>()
            .map_err(|_| SdkError::InvalidResponse(format!("bad u128: {}", s)))
    }
}

fn parse_tx_hash(val: &serde_json::Value) -> Result<[u8; 32]> {
    // Response may be a JSON string containing a nested JSON object
    let s = val.as_str().unwrap_or("");
    let hash_hex = if let Ok(inner) = serde_json::from_str::<serde_json::Value>(s) {
        inner.get("txHash").and_then(|v| v.as_str())
            .unwrap_or(s).to_string()
    } else {
        s.to_string()
    };
    let hex = hash_hex.trim_start_matches("0x");
    if hex.len() != 64 {
        return Err(SdkError::InvalidResponse(format!("bad tx hash: {}", hash_hex)));
    }
    let bytes = hex::decode(hex)
        .map_err(|e| SdkError::InvalidResponse(format!("bad tx hash hex: {}", e)))?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}
