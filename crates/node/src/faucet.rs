//! Public faucet: dispenses test PYDE to requesting addresses.
//!
//! Usage: `pyde faucet --rpc http://127.0.0.1:8545 --from 0x... --port 8080`
//!
//! Endpoints:
//!   GET /faucet?address=0x...  → sends PYDE, returns tx hash
//!   GET /health                → {"status":"ok"}

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

pub struct FaucetConfig {
    pub rpc_url: String,
    pub port: u16,
    pub amount_pyde: u64,
    pub from_address: String,
    pub cooldown_secs: u64,
    /// Path to faucet's private key file (FALCON keypair).
    /// If provided, signs transactions via pyde_sendRawTransaction.
    /// If None, uses unsigned pyde_sendTransaction (dev mode only).
    pub private_key_path: Option<String>,
}

struct RateLimiter {
    last_request: Mutex<HashMap<String, Instant>>,
    cooldown: Duration,
}

impl RateLimiter {
    fn new(cooldown_secs: u64) -> Self {
        Self {
            last_request: Mutex::new(HashMap::new()),
            cooldown: Duration::from_secs(cooldown_secs),
        }
    }

    fn check(&self, address: &str) -> Result<(), u64> {
        let mut map = self.last_request.lock().unwrap();
        let addr = address.to_lowercase();
        if let Some(last) = map.get(&addr) {
            let elapsed = last.elapsed();
            if elapsed < self.cooldown {
                return Err((self.cooldown - elapsed).as_secs());
            }
        }
        map.insert(addr, Instant::now());
        Ok(())
    }
}

/// Faucet signing key (loaded once at startup).
pub struct FaucetSigner {
    pub address: [u8; 32],
    #[allow(dead_code)]
    pub public_key: pyde_crypto::falcon::FalconPublicKey,
    pub secret_key: pyde_crypto::falcon::FalconSecretKey,
}

impl FaucetSigner {
    /// Load from private key file (same format as validator.key: pk_len || pk || sk).
    pub fn load(path: &str) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("failed to read faucet key {}: {}", path, e))?;
        if bytes.len() < 4 { return Err("faucet key too short".into()); }
        let pk_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if bytes.len() < 4 + pk_len { return Err("faucet key truncated".into()); }
        let pk = pyde_crypto::falcon::FalconPublicKey::from_bytes(&bytes[4..4 + pk_len])
            .ok_or("invalid faucet public key")?;
        let sk = pyde_crypto::falcon::FalconSecretKey::from_bytes(&bytes[4 + pk_len..])
            .ok_or("invalid faucet secret key")?;
        let address = pyde_account::address::derive_eoa_address(pk.as_bytes());
        Ok(Self { address, public_key: pk, secret_key: sk })
    }

    /// Build and sign a transfer transaction.
    fn sign_transfer(&self, to: &[u8; 32], value: u128, nonce: u64, chain_id: u64) -> Vec<u8> {
        let mut tx = pyde_tx::types::Transaction {
            from: self.address,
            to: *to,
            value,
            data: vec![],
            gas_limit: 21_000,
            nonce,
            signature: vec![],
            fee_payer: pyde_tx::types::FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id,
            tx_type: pyde_tx::types::TransactionType::Standard,
        };
        let hash = tx.hash();
        tx.signature = pyde_crypto::falcon::falcon_sign(&self.secret_key, &hash)
            .map(|s| s.to_vec())
            .unwrap_or_default();
        tx.to_bytes()
    }
}

async fn send_faucet_tx(
    rpc_url: &str,
    from: &str,
    to: &str,
    amount_pyde: u64,
    signer: Option<&FaucetSigner>,
) -> Result<String, String> {
    let quanta = (amount_pyde as u128) * 1_000_000_000;

    let body = if let Some(signer) = signer {
        // Signed path: fetch nonce, build + sign tx, send raw
        let nonce = fetch_nonce(rpc_url, from).await?;
        let to_addr = parse_hex_addr(to)?;
        let chain_id = fetch_chain_id(rpc_url).await.unwrap_or(31337);
        let tx_bytes = signer.sign_transfer(&to_addr, quanta, nonce, chain_id);
        let tx_hex = format!("0x{}", hex::encode(&tx_bytes));
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "pyde_sendRawTransaction",
            "params": [tx_hex]
        })
    } else {
        // Unsigned path (dev mode)
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "pyde_sendTransaction",
            "params": [{"from": from, "to": to, "value": quanta.to_string(), "gas": 21000}]
        })
    };
    let body_str = serde_json::to_string(&body).unwrap();
    let json = rpc_call(rpc_url, &body_str).await?;

    if let Some(err) = json.get("error") {
        return Err(format!("{}", err));
    }

    let result = json.get("result").and_then(|v| v.as_str()).unwrap_or("");
    if let Ok(inner) = serde_json::from_str::<serde_json::Value>(result) {
        Ok(inner.get("txHash").and_then(|v| v.as_str()).unwrap_or(result).to_string())
    } else {
        Ok(result.to_string())
    }
}

async fn rpc_call(rpc_url: &str, body_str: &str) -> Result<serde_json::Value, String> {
    let url = rpc_url.strip_prefix("http://").unwrap_or(rpc_url);
    let mut stream = tokio::net::TcpStream::connect(url).await
        .map_err(|e| format!("connect failed: {}", e))?;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        url, body_str.len(), body_str
    );
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(request.as_bytes()).await.map_err(|e| format!("write: {}", e))?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await.map_err(|e| format!("read: {}", e))?;
    let json_body = response.split("\r\n\r\n").nth(1).ok_or("no body")?;
    serde_json::from_str(json_body).map_err(|e| format!("json: {}", e))
}

async fn fetch_nonce(rpc_url: &str, address: &str) -> Result<u64, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "pyde_getTransactionCount",
        "params": [address]
    });
    let json = rpc_call(rpc_url, &serde_json::to_string(&body).unwrap()).await?;
    let nonce_str = json.get("result").and_then(|v| v.as_str()).unwrap_or("0");
    nonce_str.parse::<u64>().map_err(|_| format!("invalid nonce: {}", nonce_str))
}

async fn fetch_chain_id(rpc_url: &str) -> Result<u64, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "pyde_chainId", "params": []
    });
    let json = rpc_call(rpc_url, &serde_json::to_string(&body).unwrap()).await?;
    let hex = json.get("result").and_then(|v| v.as_str()).unwrap_or("0x7a69");
    u64::from_str_radix(hex.strip_prefix("0x").unwrap_or(hex), 16)
        .map_err(|_| format!("invalid chain_id: {}", hex))
}

fn parse_hex_addr(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 32 { return Err(format!("address must be 32 bytes, got {}", bytes.len())); }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

fn json_response(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
        status,
        match status { 200 => "OK", 400 => "Bad Request", 429 => "Too Many Requests", 404 => "Not Found", _ => "Error" },
        body.len(),
        body
    )
}

pub async fn run_faucet(config: FaucetConfig) -> Result<(), String> {
    let limiter = Arc::new(RateLimiter::new(config.cooldown_secs));
    let rpc_url = Arc::new(config.rpc_url);
    let from = Arc::new(config.from_address);
    let amount = config.amount_pyde;

    // Load signing key if provided (production mode)
    let signer: Arc<Option<FaucetSigner>> = Arc::new(match &config.private_key_path {
        Some(path) => {
            let s = FaucetSigner::load(path)?;
            tracing::info!(
                address = hex::encode(s.address),
                "faucet signer loaded (signed transactions)"
            );
            Some(s)
        }
        None => {
            tracing::warn!("no private key — using unsigned dev mode transactions");
            None
        }
    });

    let addr = format!("0.0.0.0:{}", config.port);
    let listener = TcpListener::bind(&addr).await
        .map_err(|e| format!("failed to bind {}: {}", addr, e))?;

    tracing::info!("faucet started on http://{}", addr);
    tracing::info!("  GET /faucet?address=0x... → {} PYDE", amount);
    tracing::info!("  rate limit: {} seconds per address", config.cooldown_secs);

    loop {
        let (stream, _) = listener.accept().await
            .map_err(|e| format!("accept: {}", e))?;

        let limiter = limiter.clone();
        let rpc = rpc_url.clone();
        let from = from.clone();
        let signer = signer.clone();

        tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(stream);
            let mut buf_reader = BufReader::new(reader);
            let mut request_line = String::new();
            if buf_reader.read_line(&mut request_line).await.is_err() {
                return;
            }

            // Parse: "GET /path?query HTTP/1.1"
            let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
            if parts.len() < 2 {
                let _ = writer.write_all(json_response(400, r#"{"error":"bad request"}"#).as_bytes()).await;
                return;
            }

            let full_path = parts[1];
            let (path, query) = if let Some(idx) = full_path.find('?') {
                (&full_path[..idx], &full_path[idx + 1..])
            } else {
                (full_path, "")
            };

            let response = match path {
                "/health" => json_response(200, r#"{"status":"ok"}"#),
                "/faucet" => {
                    let address = query.split('&')
                        .find_map(|p| {
                            let mut kv = p.splitn(2, '=');
                            let k = kv.next()?;
                            let v = kv.next()?;
                            if k == "address" { Some(v.to_string()) } else { None }
                        });

                    match address {
                        Some(addr) if addr.len() >= 64 => {
                            match limiter.check(&addr) {
                                Err(secs) => {
                                    json_response(429, &format!(
                                        r#"{{"error":"rate limited","retryAfter":{}}}"#, secs
                                    ))
                                }
                                Ok(()) => {
                                    match send_faucet_tx(&rpc, &from, &addr, amount, signer.as_ref().as_ref()).await {
                                        Ok(tx_hash) => {
                                            tracing::info!(to = %addr, amount, tx_hash = %tx_hash, "faucet dispensed");
                                            json_response(200, &format!(
                                                r#"{{"txHash":"{}","amount":"{}","to":"{}"}}"#,
                                                tx_hash, amount, addr
                                            ))
                                        }
                                        Err(e) => {
                                            json_response(500, &format!(r#"{{"error":"{}"}}"#, e))
                                        }
                                    }
                                }
                            }
                        }
                        _ => json_response(400, r#"{"error":"missing or invalid address"}"#),
                    }
                }
                _ => json_response(404, r#"{"error":"not found"}"#),
            };

            let _ = writer.write_all(response.as_bytes()).await;
        });
    }
}
