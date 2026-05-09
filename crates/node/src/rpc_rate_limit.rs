//! Per-connection request rate-limit middleware for the JSON-RPC
//! server (TPL-931).
//!
//! Bounds how many RPC requests a single TCP connection can issue
//! per second. The existing connection cap (`MAX_CONNECTIONS = 1024`)
//! and per-request body cap (`1 MB`) leave room for one peer to
//! flood `pyde_call` / `pyde_getLogs` / `pyde_estimateGas` from a
//! single connection — every request consumes a handler future, and
//! back-to-back small requests can saturate the Tokio runtime well
//! before either of those caps kicks in.
//!
//! Algorithm: token bucket per `ConnectionId`. Each connection
//! starts with a full burst capacity and refills at a steady rate.
//! Requests consume one token; when the bucket is empty the call is
//! rejected with `-32429 "rate limit exceeded"`. Token-bucket lets
//! bursty-but-honest clients (block explorers paginating receipts,
//! wallets refreshing balance + nonce + logs in one tick) succeed
//! while still capping sustained throughput.

use futures_util::future::{ready, Either, Ready};
use jsonrpsee::core::server::MethodResponse;
use jsonrpsee::server::middleware::rpc::RpcServiceT;
use jsonrpsee::types::{ErrorObject, Request};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower::Layer;

/// Sustained refill rate per connection, requests/second.
const RATE_PER_SECOND: f64 = 100.0;

/// Burst capacity per connection. A single connection can issue up
/// to this many requests immediately before the per-second refill
/// kicks in. 200 ≈ ~2 s of sustained traffic — comfortably above
/// the typical "one tick of a wallet UI refresh" burst.
const BURST_CAPACITY: f64 = 200.0;

/// Soft ceiling on the per-connection state map. Beyond this, stale
/// entries (no traffic for ≥ 60 s) are pruned. Keeps memory bounded
/// across very long server uptimes — `ConnectionId` (a `usize`)
/// monotonically increases per accepted TCP connection, so without
/// pruning the map would grow forever.
const STATE_MAP_SOFT_CAP: usize = 4096;

/// Idle-eviction window. An entry whose `last_refill` is older than
/// this is dropped during the soft-cap sweep.
const STALE_ENTRY_AFTER: Duration = Duration::from_secs(60);

/// JSON-RPC error code for rate-limit. `-32429` mirrors HTTP `429`
/// semantically. jsonrpsee passes the error object through to the
/// client unchanged, so picking a code outside the standard
/// `-32000..-32099` range avoids collision with handler-level errors.
const RATE_LIMIT_ERROR_CODE: i32 = -32429;

#[derive(Clone, Copy, Debug)]
struct ConnState {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Default)]
struct InnerState {
    map: HashMap<usize, ConnState>,
}

#[derive(Clone, Default)]
pub struct RpcRateLimitState(Arc<Mutex<InnerState>>);

impl RpcRateLimitState {
    pub fn new() -> Self {
        Self::default()
    }

    fn try_consume(&self, conn_id: usize) -> bool {
        let now = Instant::now();
        let mut g = self.0.lock().expect("rate-limit state poisoned");
        if g.map.len() > STATE_MAP_SOFT_CAP {
            // Cheap idle sweep — only fires when the map is already
            // above the soft cap, so amortized cost is negligible.
            let cutoff = now - STALE_ENTRY_AFTER;
            g.map.retain(|_, s| s.last_refill >= cutoff);
        }
        let entry = g.map.entry(conn_id).or_insert(ConnState {
            tokens: BURST_CAPACITY,
            last_refill: now,
        });
        let elapsed_s = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed_s * RATE_PER_SECOND).min(BURST_CAPACITY);
        entry.last_refill = now;
        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Clone)]
pub struct RpcRateLimitLayer(RpcRateLimitState);

impl RpcRateLimitLayer {
    pub fn new(state: RpcRateLimitState) -> Self {
        Self(state)
    }
}

impl<S> Layer<S> for RpcRateLimitLayer {
    type Service = RpcRateLimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RpcRateLimit {
            inner,
            state: self.0.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RpcRateLimit<S> {
    inner: S,
    state: RpcRateLimitState,
}

impl<'a, S> RpcServiceT<'a> for RpcRateLimit<S>
where
    S: RpcServiceT<'a>,
{
    type Future = Either<S::Future, Ready<MethodResponse>>;

    fn call(&self, request: Request<'a>) -> Self::Future {
        let conn_id = request
            .extensions()
            .get::<jsonrpsee::core::server::ConnectionId>()
            .map(|c| c.0)
            .unwrap_or(0);
        if self.state.try_consume(conn_id) {
            Either::Left(self.inner.call(request))
        } else {
            let id = request.id().into_owned();
            let err = ErrorObject::owned(
                RATE_LIMIT_ERROR_CODE,
                format!(
                    "rate limit exceeded: {} req/s sustained per connection (burst {})",
                    RATE_PER_SECOND as u32, BURST_CAPACITY as u32
                ),
                None::<()>,
            );
            Either::Right(ready(MethodResponse::error(id, err)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_burst_then_throttles() {
        let state = RpcRateLimitState::new();
        let conn = 1usize;
        let mut allowed = 0;
        // BURST_CAPACITY is 200; the first ~200 should pass even
        // back-to-back. Use 250 to confirm a hard cut-off after the
        // initial burst, with the per-second refill contributing only
        // sub-millisecond fractional tokens during this loop.
        for _ in 0..250 {
            if state.try_consume(conn) {
                allowed += 1;
            }
        }
        assert!(
            (BURST_CAPACITY as usize..=BURST_CAPACITY as usize + 1).contains(&allowed),
            "expected ~{} allowed in tight loop, got {}",
            BURST_CAPACITY as usize,
            allowed
        );
    }

    #[test]
    fn token_bucket_isolates_connections() {
        let state = RpcRateLimitState::new();
        // Drain conn 1 to empty.
        for _ in 0..(BURST_CAPACITY as usize + 50) {
            state.try_consume(1);
        }
        // Conn 2 should still get its full burst.
        let mut allowed_2 = 0;
        for _ in 0..(BURST_CAPACITY as usize) {
            if state.try_consume(2) {
                allowed_2 += 1;
            }
        }
        assert!(
            allowed_2 >= BURST_CAPACITY as usize - 1,
            "conn 2 starved by conn 1's rate-limit state: {} / {}",
            allowed_2,
            BURST_CAPACITY as usize
        );
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let state = RpcRateLimitState::new();
        let conn = 7usize;
        // Drain.
        for _ in 0..(BURST_CAPACITY as usize + 10) {
            state.try_consume(conn);
        }
        assert!(!state.try_consume(conn), "bucket should be empty");
        // Sleep ~50 ms; at 100 req/s that refills ~5 tokens.
        std::thread::sleep(Duration::from_millis(50));
        let mut refilled_allowed = 0;
        for _ in 0..10 {
            if state.try_consume(conn) {
                refilled_allowed += 1;
            }
        }
        assert!(
            (3..=8).contains(&refilled_allowed),
            "expected ~5 tokens refilled in 50ms at 100 req/s, got {}",
            refilled_allowed
        );
    }
}
