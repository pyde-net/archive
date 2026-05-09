//! Dedicated WebSocket subscription server (port 8546).
//!
//! Uses tokio-tungstenite directly for reliable subscription delivery.
//! jsonrpsee's subscription sink has a bug where sink.send() returns Ok
//! but the WS frame isn't written to the client.

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, warn};

/// TPL-932: per-subscription event rate-limit. Sustained refill rate
/// of events the subscription is allowed to forward to the connection's
/// outgoing channel. At a 400 ms slot time the chain produces ~2.5
/// new heads / second, so 50/s gives 20× headroom for a `newHeads`
/// subscription while still capping a runaway `logs` subscription
/// that, on a busy contract slot, would otherwise be able to dump
/// hundreds of events into the connection's bounded mpsc and starve
/// other subscriptions on the same socket.
const SUB_RATE_PER_SEC: f64 = 50.0;

/// TPL-932: burst capacity per subscription. A subscription that has
/// been idle accumulates up to this many tokens, so a brief burst of
/// events (e.g., a backlog drain after a brief stall) clears without
/// throttling.
const SUB_BURST: f64 = 100.0;

/// Lazy token-bucket: refilled on each `try_consume` call from
/// `tokio::time::Instant` deltas, no background task. One per
/// spawned subscription task, so each subscription's rate is
/// isolated from siblings on the same WS connection.
struct SubRateLimiter {
    tokens: f64,
    last_refill: tokio::time::Instant,
}

impl SubRateLimiter {
    fn new() -> Self {
        Self {
            tokens: SUB_BURST,
            last_refill: tokio::time::Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = tokio::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * SUB_RATE_PER_SEC).min(SUB_BURST);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub async fn start_ws_server(
    listen: &str,
    port: u16,
    new_heads_tx: broadcast::Sender<serde_json::Value>,
    logs_tx: broadcast::Sender<serde_json::Value>,
) -> Result<std::net::SocketAddr, String> {
    let addr = format!("{}:{}", listen, port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("WS bind failed: {}", e))?;
    let bound = listener
        .local_addr()
        .map_err(|e| format!("WS addr: {}", e))?;

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let heads = new_heads_tx.clone();
                    let logs = logs_tx.clone();
                    tokio::spawn(handle_connection(stream, heads, logs));
                }
                Err(e) => warn!(error = %e, "WS accept failed"),
            }
        }
    });

    Ok(bound)
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    heads_tx: broadcast::Sender<serde_json::Value>,
    logs_tx: broadcast::Sender<serde_json::Value>,
) {
    let ws = match tokio_tungstenite::accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            debug!(error = %e, "WS handshake failed");
            return;
        }
    };

    let (mut ws_sink, mut ws_stream) = ws.split();

    // Audit 346: bounded mpsc + per-connection subscription cap.
    // Pre-fix the channel was `mpsc::unbounded_channel::<String>()`,
    // so a slow / disconnected WS client backed up arbitrarily
    // many queued strings in memory. Sub spawn count was also
    // unbounded — a single connection could call `pyde_subscribe`
    // thousands of times, spawning a tokio task per call. Bounded
    // (256-message) outgoing channel + 16-subscription cap close
    // both vectors.
    const OUT_CHANNEL_CAP: usize = 256;
    const MAX_SUBS_PER_CONN: usize = 16;
    let (out_tx, mut out_rx) = mpsc::channel::<String>(OUT_CHANNEL_CAP);

    // Spawn WS writer task
    let writer = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if ws_sink.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    let mut sub_counter = 0u64;
    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // Read incoming messages
    while let Some(Ok(msg)) = ws_stream.next().await {
        if let Message::Text(text) = msg {
            let data: serde_json::Value = match serde_json::from_str(&text) {
                Ok(d) => d,
                Err(_) => continue,
            };

            let id = data.get("id").cloned().unwrap_or(serde_json::Value::Null);
            let method = data.get("method").and_then(|m| m.as_str()).unwrap_or("");

            match method {
                "pyde_subscribe" => {
                    if tasks.len() >= MAX_SUBS_PER_CONN {
                        let resp = serde_json::json!({
                            "jsonrpc":"2.0","id":id,
                            "error":{"code":-32603,"message":format!("subscription cap reached ({MAX_SUBS_PER_CONN} per connection); audit 346")}
                        });
                        let _ = out_tx.try_send(resp.to_string());
                        continue;
                    }
                    sub_counter += 1;
                    let sub_id = sub_counter;
                    let mut rx = heads_tx.subscribe();
                    let tx = out_tx.clone();

                    // Response
                    let _ = out_tx.try_send(
                        serde_json::json!({"jsonrpc":"2.0","id":id,"result":sub_id}).to_string(),
                    );

                    tasks.push(tokio::spawn(async move {
                        let mut rl = SubRateLimiter::new();
                        loop {
                            match rx.recv().await {
                                Ok(header) => {
                                    // TPL-932: per-subscription rate-limit.
                                    // Drop events past the per-second cap so
                                    // one runaway sub can't monopolize the
                                    // connection's bounded outgoing channel.
                                    // newHeads at ~2.5/s never trips the
                                    // 50/s cap in practice.
                                    if !rl.try_consume() {
                                        debug!(sub_id, "newHeads sub rate-limit: dropped event (TPL-932)");
                                        continue;
                                    }
                                    let notif = serde_json::json!({
                                        "jsonrpc":"2.0",
                                        "method":"pyde_subscription",
                                        "params":{"subscription":sub_id,"result":header}
                                    });
                                    // Audit 346: bounded channel —
                                    // try_send drops if a slow client
                                    // can't keep up. Beats unbounded
                                    // memory growth on a stuck WS.
                                    if let Err(mpsc::error::TrySendError::Closed(_)) =
                                        tx.try_send(notif.to_string())
                                    {
                                        break;
                                    }
                                }
                                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                                Err(_) => break,
                            }
                        }
                    }));
                }

                "pyde_subscribeLogs" => {
                    if tasks.len() >= MAX_SUBS_PER_CONN {
                        let resp = serde_json::json!({
                            "jsonrpc":"2.0","id":id,
                            "error":{"code":-32603,"message":format!("subscription cap reached ({MAX_SUBS_PER_CONN} per connection); audit 346")}
                        });
                        let _ = out_tx.try_send(resp.to_string());
                        continue;
                    }
                    sub_counter += 1;
                    let sub_id = sub_counter;
                    let mut rx = logs_tx.subscribe();
                    let tx = out_tx.clone();

                    let filter_addr = data
                        .get("params")
                        .and_then(|p| p.as_array())
                        .and_then(|a| a.first())
                        .and_then(|f| f.get("address"))
                        .and_then(|a| a.as_str())
                        .map(|s| s.to_lowercase());

                    // Response
                    let _ = out_tx.try_send(
                        serde_json::json!({"jsonrpc":"2.0","id":id,"result":sub_id}).to_string(),
                    );

                    debug!(sub_id, "logs subscription created");

                    tasks.push(tokio::spawn(async move {
                        let mut rl = SubRateLimiter::new();
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
                                    // TPL-932: per-subscription rate-limit.
                                    // Caps how fast one logs sub can pump
                                    // events into the connection's outgoing
                                    // channel. Filter-pass is checked first
                                    // so dropped logs don't burn tokens.
                                    if !rl.try_consume() {
                                        debug!(sub_id, "logs sub rate-limit: dropped event (TPL-932)");
                                        continue;
                                    }
                                    let notif = serde_json::json!({
                                        "jsonrpc":"2.0",
                                        "method":"pyde_logSubscription",
                                        "params":{"subscription":sub_id,"result":log}
                                    });
                                    debug!("forwarding log to WS client");
                                    if let Err(mpsc::error::TrySendError::Closed(_)) =
                                        tx.try_send(notif.to_string())
                                    {
                                        break;
                                    }
                                }
                                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                                Err(_) => break,
                            }
                        }
                    }));
                }

                _ => {
                    let resp = serde_json::json!({
                        "jsonrpc":"2.0","id":id,
                        "error":{"code":-32601,"message":"use HTTP RPC for queries, WS for subscriptions"}
                    });
                    let _ = out_tx.try_send(resp.to_string());
                }
            }
        }
    }

    // Cleanup
    for t in tasks {
        t.abort();
    }
    writer.abort();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn tpl_932_sub_rate_limiter_allows_burst_then_throttles() {
        let mut rl = SubRateLimiter::new();
        let mut allowed = 0;
        for _ in 0..(SUB_BURST as usize + 50) {
            if rl.try_consume() {
                allowed += 1;
            }
        }
        // The tight loop is fast enough that real-time refill during
        // the loop contributes only sub-millisecond fractional tokens
        // (≪ 1), so allowed ~= BURST. Allow ±1 of slop for the
        // last_refill timestamp delta on slow CI machines.
        assert!(
            (SUB_BURST as usize..=SUB_BURST as usize + 1).contains(&allowed),
            "expected ~{} allowed in tight loop, got {}",
            SUB_BURST as usize,
            allowed
        );
    }

    #[test]
    fn tpl_932_sub_rate_limiter_refills_over_time() {
        let mut rl = SubRateLimiter::new();
        // Drain the bucket.
        for _ in 0..(SUB_BURST as usize) {
            assert!(rl.try_consume());
        }
        assert!(!rl.try_consume(), "bucket should be empty");
        // 100 ms at 50/s → ~5 tokens refilled.
        std::thread::sleep(Duration::from_millis(100));
        let mut after_refill = 0;
        for _ in 0..10 {
            if rl.try_consume() {
                after_refill += 1;
            }
        }
        assert!(
            (4..=7).contains(&after_refill),
            "100ms refill at {} req/s should yield ~5 tokens (got {})",
            SUB_RATE_PER_SEC as u32,
            after_refill
        );
    }
}
