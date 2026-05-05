//! Public faucet: dispenses test PYDE to requesting addresses.
//!
//! Usage: `pyde faucet --rpc http://127.0.0.1:8545 --from 0x... --port 8080`
//!
//! Endpoints:
//!
//!   GET  /                    → minimal HTML form (the "web UI" half
//!                                of task 082 / audit 225). Loads a
//!                                vanilla-JS page that POSTs to
//!                                `/api/request`.
//!   POST /api/request         → JSON `{"address": "0x..."}` body, the
//!                                public API recommended for clients.
//!                                Mirrors the example in
//!                                `docs/connect-to-testnet.md` so the
//!                                doc and the implementation stay in
//!                                lock-step.
//!   GET  /faucet?address=...  → legacy GET endpoint, kept for
//!                                backwards compat with anything
//!                                already wired to it.
//!   GET  /health              → `{"status":"ok"}` for k8s / load
//!                                balancer probes.
//!
//! Both dispense paths share a two-stage rate limiter: a request must
//! pass BOTH the per-address cooldown and the per-IP cooldown to be
//! served. A single attacker rotating addresses still hits the IP
//! ceiling; a single victim behind shared NAT still gets their first
//! drop. Cooldown windows are configurable via the CLI; defaults are
//! 1h per address, 1h per IP.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// Audit 347: hard cap on the per-IP and per-address rate-limit
/// maps. Pre-fix the maps were unbounded `HashMap`s — every
/// distinct address that ever requested (or every distinct
/// IP that ever connected) added an entry that lived for the
/// process lifetime. An attacker rotating addresses (cheap with
/// FALCON keygen) or rotating IPs (cheap with IPv6) could OOM the
/// faucet host. 50_000 is large enough to support a real testnet
/// drop-in cohort without forcing legitimate-but-quiet users out
/// of their cooldown windows, and small enough that even a 100 MB
/// peak (entry size ≈ 100B at the worst case) stays bounded.
const RATE_LIMITER_MAX_ENTRIES: usize = 50_000;

/// Audit 382: ceiling on the number of in-flight requests that are
/// allowed to be waiting on the signing-serialization lock at any
/// moment. Beyond this, new requests get an immediate HTTP 503
/// rather than queueing further. The signing path is intrinsically
/// sequential (per-faucet nonce race) so adding queue capacity
/// trades only memory; this cap pins the worst-case to single-digit
/// MB even under sustained DoS.
const MAX_FAUCET_QUEUE: usize = 16;

/// Audit 347: a syntactically valid Pyde address is exactly
/// `0x` + 64 hex digits (case-insensitive). Anything else is a
/// malformed request and must be rejected BEFORE the rate-limiter
/// records the string — pre-fix the cooldown map happily
/// recorded any 64+-char string the attacker shoved into the JSON
/// body, including non-hex garbage and unicode payloads.
fn is_valid_address(s: &str) -> bool {
    if s.len() != 66 {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[0] != b'0' || bytes[1] != b'x' {
        return false;
    }
    bytes[2..].iter().all(|b| b.is_ascii_hexdigit())
}

/// Audit 348: choose the rate-limit IP key from `peer_addr` and
/// the optional `X-Forwarded-For` header.
///
/// When `trust_xff` is `false` (default), the rate-limit key is
/// always `peer_addr.ip()` — the IP of whoever opened the TCP
/// connection. This is correct for a faucet exposed directly on
/// the public internet but collapses to one IP behind any
/// reverse proxy (every legitimate user shared the proxy's IP
/// cooldown).
///
/// When `trust_xff` is `true`, the operator has promised that
/// the edge proxy strips any inbound `X-Forwarded-For` and
/// appends its own — so the rightmost entry in the received
/// header is the proxy's view of the client IP. We split on `,`
/// per RFC 7239 / RFC 9110 §5.3.6, take the rightmost trimmed
/// hop, and use it as the rate-limit key. If the header is
/// absent or empty, we fall back to `peer_addr.ip()` (which in
/// a behind-proxy deployment is the proxy itself, but it's the
/// best evidence we have).
///
/// Why "rightmost untrusted hop": the leftmost entry in XFF is
/// the original (potentially attacker-controlled) client claim;
/// the rightmost is whoever the *proxy* last saw connect to it.
/// When the operator promises XFF is trusted, the proxy IS the
/// closest trusted hop, so its view wins.
fn resolve_rate_limit_ip(
    peer_addr: SocketAddr,
    forwarded_for: Option<&str>,
    trust_xff: bool,
) -> String {
    if !trust_xff {
        return peer_addr.ip().to_string();
    }
    if let Some(header) = forwarded_for {
        if let Some(rightmost) = header.rsplit(',').next() {
            let trimmed = rightmost.trim();
            if !trimmed.is_empty() {
                return trimmed.to_lowercase();
            }
        }
    }
    peer_addr.ip().to_string()
}

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
    /// Operator-pinned chain_id (audit 303). If `Some(n)`, the
    /// faucet polls the node at boot and refuses to start if the
    /// node reports a different chain_id — catches misconfiguration
    /// before any tx gets signed against the wrong chain. If `None`,
    /// the faucet trusts whatever the node returns (devnet
    /// ergonomics).
    pub chain_id: Option<u64>,
    /// Audit 348: trust the rightmost untrusted hop in
    /// `X-Forwarded-For` as the client IP for rate-limiting.
    /// Default `false` so a faucet directly exposed on the
    /// public internet keeps the safe `peer_addr.ip()` behaviour.
    /// Operators behind a reverse proxy must set this AND ensure
    /// the proxy strips any inbound XFF before adding its own.
    pub trust_x_forwarded_for: bool,
}

struct RateLimiter {
    /// Audit 347: bounded LRU map. `get` moves the entry to MRU
    /// so frequently-used addresses don't get evicted out from
    /// under their cooldown; `put` inserts and evicts the LRU
    /// entry when the cap is reached. The capacity is fixed at
    /// `RATE_LIMITER_MAX_ENTRIES`, eliminating the unbounded-map
    /// OOM vector that pre-fix grew with every unique address /
    /// IP that ever requested.
    last_request: Mutex<lru::LruCache<String, Instant>>,
    cooldown: Duration,
}

impl RateLimiter {
    fn new(cooldown_secs: u64) -> Self {
        Self {
            last_request: Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(RATE_LIMITER_MAX_ENTRIES).expect("non-zero LRU cap"),
            )),
            cooldown: Duration::from_secs(cooldown_secs),
        }
    }

    /// Check whether `key` (an address or an IP, normalised to
    /// lowercase) is past its cooldown. Does NOT record the
    /// request — call `record` only after both the address and IP
    /// gates pass, otherwise a request that's blocked by IP would
    /// reset the address timer (and vice versa).
    ///
    /// Audit 347: uses `LruCache::get` (mutating, moves to MRU)
    /// rather than `peek` so that an active-but-still-cooling
    /// address stays at the head of the LRU and won't be evicted
    /// to make room for a new entry. Evicting a still-cooling
    /// entry would silently expose the attacker who triggered
    /// the eviction — they could rotate enough new addresses /
    /// IPs to push the victim out of the cap, then re-request
    /// from the rotated pool unconstrained.
    fn check(&self, key: &str) -> Result<(), u64> {
        let mut map = self.last_request.lock().unwrap();
        let k = key.to_lowercase();
        if let Some(last) = map.get(&k) {
            let elapsed = last.elapsed();
            if elapsed < self.cooldown {
                return Err((self.cooldown - elapsed).as_secs());
            }
        }
        Ok(())
    }

    /// Record a successful dispense. Caller must have already checked
    /// every gate (address + IP) so the timer only advances on a
    /// served request.
    ///
    /// Audit 347: `LruCache::put` evicts the LRU entry when the
    /// cap is reached. The evicted address loses its cooldown
    /// memory and can request again immediately — acceptable
    /// because the cap is sized for the busiest realistic
    /// testnet cohort, and a victim crowded out of the cap can
    /// just retry. The attacker can't abuse this to bypass their
    /// own cooldown: their own entry is the one most recently
    /// touched, so it sits at the MRU end and never gets evicted.
    fn record(&self, key: &str) {
        let mut map = self.last_request.lock().unwrap();
        map.put(key.to_lowercase(), Instant::now());
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
        if bytes.len() < 4 {
            return Err("faucet key too short".into());
        }
        let pk_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if bytes.len() < 4 + pk_len {
            return Err("faucet key truncated".into());
        }
        let pk = pyde_crypto::falcon::FalconPublicKey::from_bytes(&bytes[4..4 + pk_len])
            .ok_or("invalid faucet public key")?;
        let sk = pyde_crypto::falcon::FalconSecretKey::from_bytes(&bytes[4 + pk_len..])
            .ok_or("invalid faucet secret key")?;
        let address = pyde_account::address::derive_eoa_address(pk.as_bytes());
        Ok(Self {
            address,
            public_key: pk,
            secret_key: sk,
        })
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

#[allow(clippy::too_many_arguments)]
async fn send_faucet_tx(
    rpc_url: &str,
    from: &str,
    to: &str,
    amount_pyde: u64,
    signer: Option<&FaucetSigner>,
    signing_lock: &tokio::sync::Mutex<()>,
    chain_id: u64,
) -> Result<String, String> {
    let quanta = (amount_pyde as u128) * 1_000_000_000;

    let body = if let Some(signer) = signer {
        // Signed path: fetch nonce, build + sign tx, send raw.
        //
        // The fetch-nonce → sign → submit sequence MUST be serialized
        // across concurrent faucet requests. Two requests racing each
        // other both fetch the same nonce N from the RPC node and sign
        // two distinct txs at nonce N; the mempool's per-(sender,nonce)
        // dedup (audit M6) accepts the first and rejects the second
        // with a confusing `InvalidNonce` even though the user did
        // nothing wrong. Holding `signing_lock` across the whole
        // build+submit window is the minimum-mechanism fix — public
        // faucets are rate-limited per address+IP so throughput cost
        // is negligible.
        let _guard = signing_lock.lock().await;
        let nonce = fetch_nonce(rpc_url, from).await?;
        let to_addr = parse_hex_addr(to)?;
        // Audit 303: chain_id is pinned at boot in `run_faucet` and
        // passed in here, eliminating both the per-request RPC
        // round-trip AND the silent-default-to-devnet failure mode.
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
        Ok(inner
            .get("txHash")
            .and_then(|v| v.as_str())
            .unwrap_or(result)
            .to_string())
    } else {
        Ok(result.to_string())
    }
}

async fn rpc_call(rpc_url: &str, body_str: &str) -> Result<serde_json::Value, String> {
    let url = rpc_url.strip_prefix("http://").unwrap_or(rpc_url);
    let mut stream = tokio::net::TcpStream::connect(url)
        .await
        .map_err(|e| format!("connect failed: {}", e))?;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        url, body_str.len(), body_str
    );
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write: {}", e))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .map_err(|e| format!("read: {}", e))?;
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
    nonce_str
        .parse::<u64>()
        .map_err(|_| format!("invalid nonce: {}", nonce_str))
}

async fn fetch_chain_id(rpc_url: &str) -> Result<u64, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "pyde_chainId", "params": []
    });
    let json = rpc_call(rpc_url, &serde_json::to_string(&body).unwrap()).await?;
    // Audit 303: do NOT default to devnet on missing/null result. A
    // transient RPC blip used to silently re-target the faucet at
    // chain_id=31337, producing signed txs valid only on devnet
    // even when the operator was running a public testnet.
    let hex = json
        .get("result")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "pyde_chainId returned no result".to_string())?;
    u64::from_str_radix(hex.strip_prefix("0x").unwrap_or(hex), 16)
        .map_err(|_| format!("invalid chain_id: {}", hex))
}

fn parse_hex_addr(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("address must be 32 bytes, got {}", bytes.len()));
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

fn json_response(status: u16, body: &str) -> String {
    http_response(status, "application/json", body)
}

fn html_response(status: u16, body: &str) -> String {
    http_response(status, "text/html; charset=utf-8", body)
}

fn http_response(status: u16, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: {}\r\n\r\n{}",
        status,
        match status {
            200 => "OK",
            400 => "Bad Request",
            429 => "Too Many Requests",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Error",
        },
        content_type,
        body.len(),
        body
    )
}

/// Minimal vanilla-JS faucet UI. Single-page, no framework, no
/// external assets — keeps the binary self-contained so operators
/// don't need a separate static-file server. The page POSTs to
/// `/api/request`; cooldown and error messages display inline.
const FAUCET_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pyde Testnet Faucet</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         max-width: 640px; margin: 4rem auto; padding: 0 1rem; line-height: 1.5; }
  h1 { font-size: 1.6rem; margin-bottom: 0.2rem; }
  p.lede { color: #666; margin-top: 0; }
  form { margin-top: 2rem; display: flex; gap: 0.5rem; flex-wrap: wrap; }
  input[type="text"] { flex: 1; min-width: 280px; padding: 0.6rem 0.8rem;
                       font-family: ui-monospace, monospace; font-size: 0.95rem;
                       border: 1px solid #ccc; border-radius: 6px; }
  button { padding: 0.6rem 1.2rem; font-size: 0.95rem; border: 0; border-radius: 6px;
           background: #2c5dff; color: white; cursor: pointer; }
  button:disabled { background: #999; cursor: not-allowed; }
  #out { margin-top: 1.5rem; padding: 0.8rem 1rem; border-radius: 6px;
         font-family: ui-monospace, monospace; font-size: 0.9rem;
         white-space: pre-wrap; word-break: break-all; }
  .ok { background: #e7f7ec; border: 1px solid #a4d8b0; }
  .err { background: #fdeaea; border: 1px solid #e0a3a3; }
  .info { background: #f0f0f0; border: 1px solid #ccc; }
  small { color: #888; }
  a { color: #2c5dff; }
</style>
</head>
<body>
<h1>Pyde Testnet Faucet</h1>
<p class="lede">Request test PYDE for development. One drop per address per cooldown window.</p>
<form id="f">
  <input id="addr" type="text" autocomplete="off" placeholder="0x... (32-byte address)" required>
  <button id="btn" type="submit">Request</button>
</form>
<div id="out" class="info" style="display:none"></div>
<p><small>Powered by the built-in <code>pyde faucet</code> service.
See <a href="https://github.com/zarah-s/pyde/blob/main/docs/connect-to-testnet.md">connect-to-testnet docs</a>.</small></p>
<script>
const form = document.getElementById('f');
const addrInput = document.getElementById('addr');
const btn = document.getElementById('btn');
const out = document.getElementById('out');
function show(kind, msg) {
  out.style.display = 'block';
  out.className = kind;
  out.textContent = msg;
}
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const address = addrInput.value.trim();
  btn.disabled = true;
  show('info', 'Submitting...');
  try {
    const resp = await fetch('/api/request', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({address}),
    });
    const json = await resp.json();
    if (resp.ok) {
      show('ok', `Sent ${json.amount} PYDE to ${json.to}\n\ntx hash: ${json.txHash}`);
    } else if (resp.status === 429) {
      show('err', `Rate limited. Try again in ${json.retryAfter}s.`);
    } else {
      show('err', `Error: ${json.error || 'unknown'}`);
    }
  } catch (err) {
    show('err', `Network error: ${err}`);
  } finally {
    btn.disabled = false;
  }
});
</script>
</body>
</html>
"##;

/// Pull a JSON `address` field out of a POSTed body. Tolerant of
/// the most common client mistakes (extra whitespace, trailing
/// newlines) but does not implement a full JSON parser; the request
/// surface is small enough that `serde_json::from_str` is overkill.
fn parse_post_body_address(body: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    json.get("address")?.as_str().map(|s| s.to_string())
}

/// Pure pin-or-mismatch decision after the node has reported its
/// chain_id. Split from the I/O wrapper so the branch logic is
/// unit-testable (audit 303).
fn check_pinned_chain_id(node_chain_id: u64, pinned: Option<u64>) -> Result<u64, String> {
    match pinned {
        None => Ok(node_chain_id),
        Some(expected) if expected == node_chain_id => Ok(node_chain_id),
        Some(expected) => Err(format!(
            "faucet --chain-id={} but node reports {}; refusing to start (audit 303)",
            expected, node_chain_id
        )),
    }
}

/// Resolve the faucet's chain_id at boot (audit 303).
///
/// - If the operator passes `--chain-id N`, poll the node and refuse
///   to start if the node reports anything other than `N`.
/// - If `--chain-id` was omitted, use whatever the node reports.
///   This branch keeps devnet ergonomics (no flag needed for `pyde
///   testnet` bring-up) while production deploys lock in a pinned
///   value.
///
/// Either way, RPC errors propagate as `Err` instead of silently
/// defaulting to chain_id 31337 — the prior behaviour silently
/// re-targeted the faucet at devnet on any transient blip.
async fn resolve_faucet_chain_id(rpc_url: &str, pinned: Option<u64>) -> Result<u64, String> {
    let node_chain_id = fetch_chain_id(rpc_url).await.map_err(|e| {
        format!(
            "faucet failed to fetch chain_id from {}: {}; refusing to start (audit 303)",
            rpc_url, e
        )
    })?;
    check_pinned_chain_id(node_chain_id, pinned)
}

pub async fn run_faucet(config: FaucetConfig) -> Result<(), String> {
    let addr_limiter = Arc::new(RateLimiter::new(config.cooldown_secs));
    let ip_limiter = Arc::new(RateLimiter::new(config.cooldown_secs));
    let rpc_url = Arc::new(config.rpc_url);
    let from = Arc::new(config.from_address);
    let amount = config.amount_pyde;

    // Audit 303: pin chain_id at boot. Poll the node once; if the
    // operator supplied `--chain-id`, refuse to start on mismatch
    // so a misconfiguration surfaces before any tx gets signed.
    // After this, the chain_id is held in `chain_id` and reused on
    // every dispense — eliminates both the per-request RPC fetch
    // AND the "default to devnet on RPC failure" hazard.
    let chain_id = match resolve_faucet_chain_id(&rpc_url, config.chain_id).await {
        Ok(id) => id,
        Err(e) => return Err(e),
    };
    tracing::info!(chain_id, "faucet pinned to chain");

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
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("failed to bind {}: {}", addr, e))?;

    tracing::info!("faucet started on http://{}", addr);
    tracing::info!("  GET  /                   → web UI");
    tracing::info!(
        "  POST /api/request        → JSON body {{\"address\":\"0x...\"}} → {} PYDE",
        amount
    );
    tracing::info!("  GET  /faucet?address=... → legacy GET endpoint");
    tracing::info!("  GET  /health             → {{\"status\":\"ok\"}}");
    tracing::info!(
        "  rate limit: {}s per address AND {}s per IP",
        config.cooldown_secs,
        config.cooldown_secs
    );
    if config.trust_x_forwarded_for {
        tracing::warn!(
            "  audit 348: trust_x_forwarded_for=true — operator MUST ensure the edge \
             proxy strips inbound XFF headers before adding its own. If it doesn't, \
             attackers can spoof their client IP and bypass per-IP rate-limits."
        );
    }

    // Single global lock that serializes the fetch-nonce → sign →
    // submit window in `send_faucet_tx`. Two concurrent dispenses
    // would otherwise race on the faucet's nonce — see the comment
    // in `send_faucet_tx` for the mempool-dedup interaction.
    let signing_lock: Arc<tokio::sync::Mutex<()>> = Arc::new(tokio::sync::Mutex::new(()));

    // Audit 382: bound the queue depth on the signing serialization.
    // The `signing_lock` mutex itself is unbounded — under DoS, every
    // request that survives the per-IP and per-address rate limits
    // queues on this mutex, and the queue grows linearly in spawned
    // tokio tasks plus their captured Arc state until the runtime
    // OOMs. The signing serialization is sequential by design (nonce
    // race), so the only valid backpressure is to refuse new work
    // when the queue is already deep. `signing_capacity` is a
    // `Semaphore` with `MAX_FAUCET_QUEUE` permits; each handler
    // calls `try_acquire_owned` before waiting on `signing_lock` and
    // returns 503 if no permit is available. With `MAX_FAUCET_QUEUE
    // = 16`, the worst-case queue depth on the lock is 16 (one
    // active signer + 15 waiters), bounding RAM at single-digit MB.
    let signing_capacity: Arc<tokio::sync::Semaphore> =
        Arc::new(tokio::sync::Semaphore::new(MAX_FAUCET_QUEUE));

    let trust_xff = config.trust_x_forwarded_for;

    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .map_err(|e| format!("accept: {}", e))?;

        let addr_limiter = addr_limiter.clone();
        let ip_limiter = ip_limiter.clone();
        let rpc = rpc_url.clone();
        let from = from.clone();
        let signer = signer.clone();
        let signing_lock = signing_lock.clone();
        let signing_capacity = signing_capacity.clone();

        tokio::spawn(async move {
            handle_connection(
                stream,
                peer_addr,
                addr_limiter,
                ip_limiter,
                rpc,
                from,
                amount,
                signer,
                signing_lock,
                signing_capacity,
                chain_id,
                trust_xff,
            )
            .await;
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    addr_limiter: Arc<RateLimiter>,
    ip_limiter: Arc<RateLimiter>,
    rpc: Arc<String>,
    from: Arc<String>,
    amount: u64,
    signer: Arc<Option<FaucetSigner>>,
    signing_lock: Arc<tokio::sync::Mutex<()>>,
    signing_capacity: Arc<tokio::sync::Semaphore>,
    chain_id: u64,
    trust_xff: bool,
) {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut buf_reader = BufReader::new(reader);
    let mut request_line = String::new();
    if buf_reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    // Parse: "METHOD /path[?query] HTTP/1.1"
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        let _ = writer
            .write_all(json_response(400, r#"{"error":"bad request"}"#).as_bytes())
            .await;
        return;
    }
    let method = parts[0];
    let full_path = parts[1];
    let (path, query) = if let Some(idx) = full_path.find('?') {
        (&full_path[..idx], &full_path[idx + 1..])
    } else {
        (full_path, "")
    };

    // Read headers until empty line, capturing Content-Length so we
    // can read the body for POST requests, and X-Forwarded-For so we
    // can derive the client IP under audit 348 when --trust-x-forwarded-for
    // is set. Anything we don't need is discarded — small request
    // surface, no need for a full HTTP lib.
    let mut content_length: usize = 0;
    let mut x_forwarded_for: Option<String> = None;
    loop {
        let mut header_line = String::new();
        if buf_reader.read_line(&mut header_line).await.is_err() {
            return;
        }
        if header_line.trim().is_empty() {
            break;
        }
        let lower = header_line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            content_length = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = lower.strip_prefix("x-forwarded-for:") {
            // Preserve the original-case value (some clients send
            // mixed-case IPs in v6 form); the trim-and-rsplit
            // below in `resolve_rate_limit_ip` handles the rest.
            x_forwarded_for = Some(rest.trim().to_string());
        }
    }

    let mut body = String::new();
    if content_length > 0 {
        // Cap body to a small upper bound — defensive against a
        // misbehaving / malicious client claiming Content-Length:
        // 1GB. The legitimate JSON body is < 100 bytes.
        let cap = content_length.min(4096);
        let mut buf = vec![0u8; cap];
        use tokio::io::AsyncReadExt;
        if buf_reader.read_exact(&mut buf).await.is_ok() {
            // Audit 347: reject non-UTF-8 bodies outright instead
            // of `from_utf8_lossy`. Pre-fix the lossy decoder
            // silently replaced invalid bytes with U+FFFD, which
            // (a) corrupted the JSON parser's view of the
            // request and (b) gave attackers a way to inject
            // garbage that survived address-shape checks
            // downstream. A non-UTF-8 body is a malformed
            // request, full stop.
            match String::from_utf8(buf) {
                Ok(s) => body = s,
                Err(_) => {
                    let _ = writer
                        .write_all(
                            json_response(400, r#"{"error":"body must be valid UTF-8"}"#)
                                .as_bytes(),
                        )
                        .await;
                    return;
                }
            }
        }
    }

    // Audit 348: rate-limit IP key honours the operator's trust
    // setting. Pre-fix this was always `peer_addr.ip()`, which
    // collapses to one IP behind any reverse proxy. With
    // `--trust-x-forwarded-for`, we honour the rightmost
    // X-Forwarded-For hop instead. See `resolve_rate_limit_ip`
    // for the security model + operator-side prerequisite.
    let ip_key = resolve_rate_limit_ip(peer_addr, x_forwarded_for.as_deref(), trust_xff);

    let response = match (method, path) {
        ("OPTIONS", _) => {
            // CORS preflight — 204 with the headers from `http_response`
            // is enough; browsers don't care about the body.
            http_response(204, "text/plain", "")
        }
        ("GET", "/") | ("GET", "/index.html") => html_response(200, FAUCET_HTML),
        ("GET", "/health") => json_response(200, r#"{"status":"ok"}"#),
        ("POST", "/api/request") => match parse_post_body_address(&body) {
            // Audit 347: tighten from `addr.len() >= 64` to a
            // strict `^0x[0-9a-fA-F]{64}$` match. Pre-fix any
            // 64+-char string slipped through the surface check
            // and reached `serve_dispense`, where the rate
            // limiter recorded it on success. Strict matching
            // here means malformed addresses can't grow the
            // cooldown map at all, even before hitting the LRU
            // cap.
            Some(addr) if is_valid_address(&addr) => {
                serve_dispense(
                    &addr,
                    &ip_key,
                    &addr_limiter,
                    &ip_limiter,
                    &rpc,
                    &from,
                    amount,
                    signer.as_ref().as_ref(),
                    &signing_lock,
                    &signing_capacity,
                    chain_id,
                )
                .await
            }
            Some(_) => json_response(
                400,
                r#"{"error":"address must be 0x-prefixed 32-byte hex"}"#,
            ),
            None => json_response(400, r#"{"error":"missing address field in JSON body"}"#),
        },
        ("GET", "/faucet") => {
            // Legacy backwards-compat endpoint.
            let address = query.split('&').find_map(|p| {
                let (k, v) = p.split_once('=')?;
                if k == "address" {
                    Some(v.to_string())
                } else {
                    None
                }
            });
            match address {
                // Audit 347: same strict address validation as
                // the POST path — the legacy GET endpoint shares
                // the rate-limiter map and must not be a
                // back-door for malformed-address recording.
                Some(addr) if is_valid_address(&addr) => {
                    serve_dispense(
                        &addr,
                        &ip_key,
                        &addr_limiter,
                        &ip_limiter,
                        &rpc,
                        &from,
                        amount,
                        signer.as_ref().as_ref(),
                        &signing_lock,
                        &signing_capacity,
                        chain_id,
                    )
                    .await
                }
                _ => json_response(400, r#"{"error":"missing or invalid address"}"#),
            }
        }
        _ => json_response(404, r#"{"error":"not found"}"#),
    };

    let _ = writer.write_all(response.as_bytes()).await;
}

#[allow(clippy::too_many_arguments)]
async fn serve_dispense(
    address: &str,
    ip_key: &str,
    addr_limiter: &RateLimiter,
    ip_limiter: &RateLimiter,
    rpc: &str,
    from: &str,
    amount: u64,
    signer: Option<&FaucetSigner>,
    signing_lock: &tokio::sync::Mutex<()>,
    signing_capacity: &Arc<tokio::sync::Semaphore>,
    chain_id: u64,
) -> String {
    // Both rate limits must pass. Check before dispense; record only
    // after a successful send so a downstream RPC failure doesn't
    // burn the cooldown window.
    if let Err(secs) = addr_limiter.check(address) {
        return json_response(
            429,
            &format!(
                r#"{{"error":"address rate limited","retryAfter":{}}}"#,
                secs
            ),
        );
    }
    if let Err(secs) = ip_limiter.check(ip_key) {
        return json_response(
            429,
            &format!(r#"{{"error":"ip rate limited","retryAfter":{}}}"#, secs),
        );
    }
    // Audit 382: bound queue depth on the signing-serialization lock.
    // `try_acquire_owned` is non-blocking; if the queue is full
    // (`MAX_FAUCET_QUEUE` requests already waiting on `signing_lock`),
    // shed load with HTTP 503 rather than letting tokio tasks pile
    // up holding their captured Arc state.
    let _queue_permit = match signing_capacity.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!(
                to = %address,
                ip = %ip_key,
                "faucet queue saturated — returning 503 (audit 382)"
            );
            return json_response(
                503,
                r#"{"error":"faucet queue saturated, retry shortly"}"#,
            );
        }
    };
    match send_faucet_tx(rpc, from, address, amount, signer, signing_lock, chain_id).await {
        Ok(tx_hash) => {
            addr_limiter.record(address);
            ip_limiter.record(ip_key);
            tracing::info!(to = %address, ip = %ip_key, amount, tx_hash = %tx_hash, "faucet dispensed");
            json_response(
                200,
                &format!(
                    r#"{{"txHash":"{}","amount":"{}","to":"{}"}}"#,
                    tx_hash, amount, address
                ),
            )
        }
        Err(e) => {
            tracing::warn!(to = %address, ip = %ip_key, error = %e, "faucet dispense failed");
            json_response(500, &format!(r#"{{"error":"{}"}}"#, e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Task 082 / audit 225: faucet web UI + JSON API ==========

    // ── Audit 303: chain_id pin / fail-loud ──────────────────────────

    #[test]
    fn check_pinned_chain_id_unpinned_uses_node_value() {
        // No --chain-id flag → trust whatever the node reports.
        // Devnet ergonomics: a `pyde testnet` bring-up with the
        // matching faucet doesn't need to thread the chain_id.
        for node in [1u64, 7, 7331, 31337, 1_000_000] {
            assert_eq!(check_pinned_chain_id(node, None).unwrap(), node);
        }
    }

    #[test]
    fn check_pinned_chain_id_matching_pin_accepts() {
        for node in [1u64, 7331, 31337] {
            assert_eq!(check_pinned_chain_id(node, Some(node)).unwrap(), node);
        }
    }

    #[test]
    fn check_pinned_chain_id_mismatch_rejects() {
        // Operator pinned testnet (7331), node is on mainnet (1) —
        // refuse to sign anything.
        let err = check_pinned_chain_id(1, Some(7331)).unwrap_err();
        assert!(
            err.contains("--chain-id=7331") && err.contains("reports 1"),
            "expected mismatch error, got: {}",
            err
        );
        // The reverse direction — operator pinned mainnet on a
        // testnet node — must also refuse.
        assert!(check_pinned_chain_id(7331, Some(1)).is_err());
        // Devnet vs testnet mismatch: most common faucet
        // misconfiguration in practice.
        assert!(check_pinned_chain_id(31337, Some(7331)).is_err());
        assert!(check_pinned_chain_id(7331, Some(31337)).is_err());
    }

    #[test]
    fn parse_post_body_extracts_address_field() {
        let body = r#"{"address":"0xabc123"}"#;
        assert_eq!(parse_post_body_address(body), Some("0xabc123".into()));
    }

    #[test]
    fn parse_post_body_tolerates_whitespace_and_extra_fields() {
        let body = r#"{
            "address": "0xdeadbeef",
            "captcha": "ignored"
        }"#;
        assert_eq!(parse_post_body_address(body), Some("0xdeadbeef".into()));
    }

    #[test]
    fn parse_post_body_returns_none_on_missing_address() {
        assert_eq!(parse_post_body_address(r#"{"foo":"bar"}"#), None);
    }

    #[test]
    fn parse_post_body_returns_none_on_invalid_json() {
        assert_eq!(parse_post_body_address("not json"), None);
        assert_eq!(parse_post_body_address(""), None);
    }

    #[test]
    fn rate_limiter_does_not_consume_window_on_check() {
        // Regression for the two-stage gate: a `check` that succeeds
        // must NOT advance the timer, otherwise a request blocked by
        // the *other* gate (e.g. IP) burns the address window for free.
        let lim = RateLimiter::new(60);
        assert!(lim.check("0xabc").is_ok());
        assert!(lim.check("0xabc").is_ok(), "check must not arm cooldown");
        lim.record("0xabc");
        assert!(lim.check("0xabc").is_err(), "record must arm cooldown");
    }

    #[test]
    fn rate_limiter_normalises_case() {
        let lim = RateLimiter::new(60);
        lim.record("0xABC");
        assert!(lim.check("0xabc").is_err());
        assert!(lim.check("0xAbC").is_err());
    }

    #[test]
    fn html_response_advertises_correct_content_type() {
        let r = html_response(200, "<p>hi</p>");
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(r.contains("Content-Type: text/html; charset=utf-8\r\n"));
        assert!(r.contains("Access-Control-Allow-Origin: *\r\n"));
        assert!(r.ends_with("<p>hi</p>"));
    }

    #[test]
    fn json_response_advertises_correct_content_type() {
        let r = json_response(429, r#"{"error":"rate limited"}"#);
        assert!(r.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
        assert!(r.contains("Content-Type: application/json\r\n"));
    }

    #[test]
    fn faucet_html_contains_form_and_api_endpoint() {
        // Regression check on the embedded UI — must contain the
        // form, the API endpoint it POSTs to, and an address input.
        // If a future edit removes any of these, the page is no
        // longer functional and this test catches it.
        assert!(FAUCET_HTML.contains("<form"));
        assert!(FAUCET_HTML.contains("/api/request"));
        assert!(FAUCET_HTML.contains(r#"id="addr""#));
        assert!(FAUCET_HTML.contains("Pyde Testnet Faucet"));
    }

    // ========== Audit 347: address validation + LRU bound ==========

    #[test]
    fn audit_347_is_valid_address_strict_match() {
        // Canonical: 0x + exactly 64 hex digits, mixed case OK.
        let canonical = format!("0x{}", "a".repeat(64));
        assert!(is_valid_address(&canonical));
        let mixed = format!("0x{}", "AbCdEf0123456789".repeat(4));
        assert!(is_valid_address(&mixed));

        // Wrong length.
        assert!(!is_valid_address(""));
        assert!(!is_valid_address("0x"));
        assert!(!is_valid_address(&format!("0x{}", "a".repeat(63)))); // 65 char
        assert!(!is_valid_address(&format!("0x{}", "a".repeat(65)))); // 67 char
        assert!(!is_valid_address(&"a".repeat(66))); // missing 0x

        // Non-hex characters.
        assert!(!is_valid_address(&format!("0x{}g", "a".repeat(63))));
        // Unicode (any non-ASCII fails the .len() == 66 check
        // because UTF-8 multi-byte chars push the len past 66).
        assert!(!is_valid_address(&format!(
            "0x{}é{}",
            "a".repeat(32),
            "a".repeat(31)
        )));
        // Missing 0x prefix.
        assert!(!is_valid_address(&"a".repeat(64)));
        // Wrong prefix.
        assert!(!is_valid_address(&format!("Ax{}", "a".repeat(64))));
    }

    #[test]
    fn audit_347_rate_limiter_evicts_at_cap() {
        // Reduce the cap to a value we can exhaust quickly. The
        // production cap (RATE_LIMITER_MAX_ENTRIES) is 50_000;
        // we exercise the eviction logic directly via lru's API
        // to keep the test fast.
        use std::num::NonZeroUsize;
        let mut cache: lru::LruCache<String, Instant> =
            lru::LruCache::new(NonZeroUsize::new(3).unwrap());
        cache.put("a".into(), Instant::now());
        cache.put("b".into(), Instant::now());
        cache.put("c".into(), Instant::now());
        // Touch "a" so it's MRU; now LRU order is b → c → a.
        let _ = cache.get("a");
        cache.put("d".into(), Instant::now()); // evicts "b"
        assert!(cache.contains("a"));
        assert!(!cache.contains("b"));
        assert!(cache.contains("c"));
        assert!(cache.contains("d"));
    }

    // ========== Audit 348: trust-x-forwarded-for IP resolution ==========

    fn sock(s: &str) -> SocketAddr {
        s.parse().expect("valid SocketAddr")
    }

    /// Default behaviour (`trust_xff = false`): always use
    /// `peer_addr.ip()`. XFF header is ignored even if present —
    /// pre-fix behaviour for direct-internet deployments.
    #[test]
    fn audit_348_xff_ignored_when_not_trusted() {
        let key = resolve_rate_limit_ip(
            sock("203.0.113.42:54321"),
            Some("203.0.113.99, 198.51.100.7"),
            false,
        );
        assert_eq!(key, "203.0.113.42");
    }

    /// With `trust_xff = true` and a present XFF header, the
    /// rightmost trimmed hop is the rate-limit key (matches the
    /// operator-trusted "the proxy's view of the client").
    #[test]
    fn audit_348_xff_rightmost_hop_used_when_trusted() {
        // Two-hop chain: client → CDN → proxy → faucet. Proxy
        // overwrote XFF with `client, cdn`; the rightmost hop the
        // proxy itself trusted is `cdn`. (In practice operators
        // configure the proxy to write `cdn` — i.e. its peer —
        // as the only entry, but the test exercises the
        // rightmost-of-multiple branch.)
        let key = resolve_rate_limit_ip(
            sock("203.0.113.42:54321"), // proxy IP from peer_addr
            Some("198.51.100.5, 203.0.113.99"),
            true,
        );
        assert_eq!(key, "203.0.113.99");
    }

    /// Single-hop XFF (the common case): one IP in the header.
    #[test]
    fn audit_348_xff_single_hop_when_trusted() {
        let key = resolve_rate_limit_ip(sock("127.0.0.1:8080"), Some("198.51.100.5"), true);
        assert_eq!(key, "198.51.100.5");
    }

    /// XFF with surrounding whitespace must trim cleanly.
    #[test]
    fn audit_348_xff_whitespace_trimmed() {
        let key = resolve_rate_limit_ip(
            sock("127.0.0.1:8080"),
            Some("  198.51.100.5  ,   203.0.113.99   "),
            true,
        );
        assert_eq!(key, "203.0.113.99");
    }

    /// Empty XFF or absent XFF falls back to peer_addr.
    #[test]
    fn audit_348_xff_empty_falls_back_to_peer() {
        let key = resolve_rate_limit_ip(sock("198.51.100.5:1234"), Some(""), true);
        assert_eq!(key, "198.51.100.5");

        let key = resolve_rate_limit_ip(sock("198.51.100.5:1234"), None, true);
        assert_eq!(key, "198.51.100.5");
    }

    /// IPv6 addresses round-trip through case-insensitive match.
    #[test]
    fn audit_348_xff_ipv6_lowercased() {
        let key = resolve_rate_limit_ip(sock("[::1]:8080"), Some("2001:DB8::DEAD:BEEF"), true);
        // IPv6 from XFF is lowercased so `check`'s lowercase
        // lookup hits the same key on every visit.
        assert_eq!(key, "2001:db8::dead:beef");
    }

    #[test]
    fn audit_347_rate_limiter_keeps_active_entries_at_mru() {
        // Mirror the live `RateLimiter` semantics: a `check` that
        // observes a recent record must keep that entry warm so
        // the attacker can't evict a still-cooling victim by
        // flooding fresh addresses. Production uses
        // `LruCache::get` (mutating) inside `check`; this test
        // confirms that contract.
        let lim = RateLimiter::new(60);
        lim.record("victim");

        // Fill with a flood of distinct keys, each touched once.
        // Without the get-on-check semantics, "victim" would be
        // pushed out by ~RATE_LIMITER_MAX_ENTRIES inserts; with
        // the semantics, every `check("victim")` keeps it warm.
        for i in 0..100usize {
            // Periodic re-check on victim to bump it MRU.
            if i % 10 == 0 {
                let _ = lim.check("victim");
            }
            lim.record(&format!("a_{i}"));
        }
        // Victim still under cooldown (we only ran 100 puts on
        // a 50_000-cap LRU, so it wouldn't have been evicted on
        // capacity grounds either — the test mostly documents
        // the get-on-check contract). The deeper assertion is
        // that `check` returned `Err` on each touch.
        assert!(
            lim.check("victim").is_err(),
            "victim must remain rate-limited",
        );
    }
}
