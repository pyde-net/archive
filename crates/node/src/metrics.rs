//! Prometheus metrics for operator observability (audit 222).
//!
//! All metric names are prefixed `pyde_` and follow Prometheus
//! conventions: `_total` for counters, plain or `_seconds` /
//! `_ms` for histograms, plain for gauges.
//!
//! Operator alerting rules (suggested):
//!   - `pyde_block_lag` > 10 → node falling behind network tip
//!   - `pyde_finality_lag` > 100 → finality stalled (HotStuff
//!     liveness issue, partition, or coordination failure)
//!   - `pyde_reorgs_total` increasing on a single node → that
//!     node is on a fork
//!   - `pyde_validator_missed_proposals_total` increasing → this
//!     validator is missing its proposer slots (down or buggy)
//!   - `pyde_block_processing_ms` p99 > 200 → execution slow,
//!     check load / disk
//!   - `pyde_state_commit_ms` p99 > 500 → SMT/RocksDB write
//!     pressure
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

/// Bucket scheme for every `*_ms` histogram (TPL-102).
///
/// The exporter default emits summary metrics (no `_bucket` series),
/// but the operator dashboard at `deploy/grafana-pyde-testnet.json`
/// queries `histogram_quantile(...)` over `_bucket` series. Without
/// explicit buckets the p50/p95/p99 panels for
/// `pyde_block_processing_ms` and `pyde_state_commit_ms` rendered
/// blank — operator-blind during incidents.
///
/// Suffix-matching `_ms` rather than naming each histogram lets future
/// `*_ms` additions inherit the scheme automatically. The spread
/// covers happy-path block processing (~10–50 ms) through degraded
/// state-commit latency (~1–2 s); 10 buckets keeps cardinality
/// bounded for Prometheus storage.
const MS_BUCKETS: &[f64] = &[
    1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2500.0,
];

/// Start the Prometheus metrics exporter on the given port.
/// Returns the socket address it's bound to, or an error.
pub fn init(port: u16) -> Result<SocketAddr, String> {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();

    let builder = PrometheusBuilder::new()
        .with_http_listener(addr)
        .set_buckets_for_metric(Matcher::Suffix("_ms".to_string()), MS_BUCKETS)
        .map_err(|e| format!("set_buckets_for_metric: {}", e))?;
    builder
        .install()
        .map_err(|e| format!("failed to start metrics exporter on {}: {}", addr, e))?;

    Ok(addr)
}

/// Record common node metrics. Called from the main loop.
pub fn record_block(slot: u64, tx_count: u64, gas_used: u64, elapsed_ms: u64) {
    metrics::gauge!("pyde_chain_head_slot").set(slot as f64);
    metrics::counter!("pyde_blocks_processed_total").increment(1);
    metrics::counter!("pyde_transactions_processed_total").increment(tx_count);
    metrics::gauge!("pyde_block_gas_used").set(gas_used as f64);
    metrics::histogram!("pyde_block_processing_ms").record(elapsed_ms as f64);
    let snap = snapshot();
    snap.chain_head_slot.store(slot, Ordering::Relaxed);
    snap.blocks_processed_total.fetch_add(1, Ordering::Relaxed);
    snap.txs_committed_total
        .fetch_add(tx_count, Ordering::Relaxed);
    snap.last_block_slot.store(slot, Ordering::Relaxed);
    snap.last_block_txs.store(tx_count, Ordering::Relaxed);
    snap.last_block_gas.store(gas_used, Ordering::Relaxed);
    snap.last_block_ms.store(elapsed_ms, Ordering::Relaxed);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    snap.last_block_at_unix_ms.store(now_ms, Ordering::Relaxed);
}

pub fn record_peers(count: usize) {
    metrics::gauge!("pyde_peers_connected").set(count as f64);
    snapshot().peers.store(count, Ordering::Relaxed);
}

pub fn record_mempool(size: usize) {
    metrics::gauge!("pyde_mempool_size").set(size as f64);
    snapshot().mempool_plain.store(size, Ordering::Relaxed);
}

/// Encrypted-tx mempool depth, separate from the plaintext
/// `pyde_mempool_size` so alerts can target the MEV-protected
/// queue specifically (audit 222). When this stays elevated
/// while plaintext mempool drains, it signals the threshold-
/// decryption pipeline is wedged.
pub fn record_encrypted_mempool(size: usize) {
    metrics::gauge!("pyde_encrypted_mempool_size").set(size as f64);
    snapshot().mempool_encrypted.store(size, Ordering::Relaxed);
}

/// Block-lag: how many slots behind the observed network tip
/// the local chain head is. Operators alert on > 10. The
/// network tip comes from `chain_sync.network_tip` (max slot
/// seen on gossip), so this captures both "I'm catching up" and
/// "I've stalled while peers advance."
pub fn record_block_lag(local_slot: u64, network_tip_slot: u64) {
    let lag = network_tip_slot.saturating_sub(local_slot);
    metrics::gauge!("pyde_block_lag").set(lag as f64);
}

/// Finality-lag: how many slots have passed since the latest
/// hard-finality checkpoint. HotStuff finalizes after a 2-chain
/// (block N+1 confirms block N), so steady-state lag is ~2.
/// A growing lag means consensus liveness is degrading
/// (partition, missed view changes, validator outage).
pub fn record_finality_lag(local_slot: u64, latest_checkpoint_slot: u64) {
    let lag = local_slot.saturating_sub(latest_checkpoint_slot);
    metrics::gauge!("pyde_finality_lag").set(lag as f64);
}

/// Bumped on every reorg attempt (audit 232). Labelled by
/// outcome so operators can distinguish "QC mismatch fired but
/// we couldn't reorg" (alarm-worthy: sync is needed) from
/// "QC mismatch fired and we successfully switched chains"
/// (informational: the protocol is working).
pub fn record_reorg(outcome: ReorgOutcome) {
    let label = match outcome {
        ReorgOutcome::Succeeded => "succeeded",
        ReorgOutcome::TargetNotBuffered => "target_not_buffered",
        ReorgOutcome::Failed => "failed",
    };
    metrics::counter!("pyde_reorgs_total", "outcome" => label).increment(1);
}

#[derive(Clone, Copy, Debug)]
pub enum ReorgOutcome {
    Succeeded,
    TargetNotBuffered,
    Failed,
}

/// Bumped each time this validator was scheduled to propose a
/// block at slot N but didn't (because the slot wrapped, the
/// proposer was timed out, the local mempool was empty during
/// production-mode operation, etc.). Audit 222 — operators
/// alert on a non-zero rate.
///
/// `#[allow(dead_code)]` until the validator hook lands. The
/// proposer-skip detection lives in `crates/node/src/validator.rs`
/// where the multi-proposer VRF window expires without our
/// `select_and_vote` having produced a proposal; that's the
/// natural call site. Tracked as a 222 follow-up so this PR
/// stays focused on the gauge plumbing.
#[allow(dead_code)]
pub fn record_missed_proposal() {
    metrics::counter!("pyde_validator_missed_proposals_total").increment(1);
}

/// SMT/RocksDB commit latency. Spikes here drive
/// `pyde_block_processing_ms` p99 spikes; isolating the SMT
/// commit path makes it possible to root-cause without staring
/// at end-to-end histograms.
pub fn record_state_commit_ms(elapsed_ms: u64) {
    metrics::histogram!("pyde_state_commit_ms").record(elapsed_ms as f64);
}

/// RPC request observability. `method` is the JSON-RPC method
/// name (e.g. `pyde_sendRawTransaction`); `outcome` is one of
/// `ok` / `err`. Lets operators see request volume + error
/// rates per method.
pub fn record_rpc_request(method: &'static str, ok: bool) {
    let outcome = if ok { "ok" } else { "err" };
    metrics::counter!("pyde_rpc_requests_total", "method" => method, "outcome" => outcome)
        .increment(1);
    let snap = snapshot();
    if ok {
        snap.rpc_accepts_total.fetch_add(1, Ordering::Relaxed);
    } else {
        snap.rpc_rejects_total.fetch_add(1, Ordering::Relaxed);
    }
}

/// In-process metrics snapshot. Both the Prometheus exporter and
/// the optional TUI dashboard read from the same numbers — the
/// TUI just needs a non-HTTP, lock-free read path. Atomics for
/// counters/gauges; `RwLock` for the address fields where atomic
/// fixed-size byte arrays aren't a thing in std.
pub struct Snapshot {
    pub chain_head_slot: AtomicU64,
    pub chain_finalized_slot: AtomicU64,
    pub chain_base_fee: AtomicU64,
    pub epoch: AtomicU64,
    pub peers: AtomicUsize,
    pub committee_size: AtomicUsize,
    pub mempool_plain: AtomicUsize,
    pub mempool_encrypted: AtomicUsize,
    pub txs_committed_total: AtomicU64,
    pub blocks_processed_total: AtomicU64,
    pub rpc_accepts_total: AtomicU64,
    pub rpc_rejects_total: AtomicU64,
    pub last_block_slot: AtomicU64,
    pub last_block_txs: AtomicU64,
    pub last_block_gas: AtomicU64,
    pub last_block_ms: AtomicU64,
    pub last_block_at_unix_ms: AtomicU64,
    pub current_proposer: RwLock<[u8; 32]>,
    pub local_address: RwLock<[u8; 32]>,
    pub is_validator: std::sync::atomic::AtomicBool,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            chain_head_slot: AtomicU64::new(0),
            chain_finalized_slot: AtomicU64::new(0),
            chain_base_fee: AtomicU64::new(0),
            epoch: AtomicU64::new(0),
            peers: AtomicUsize::new(0),
            committee_size: AtomicUsize::new(0),
            mempool_plain: AtomicUsize::new(0),
            mempool_encrypted: AtomicUsize::new(0),
            txs_committed_total: AtomicU64::new(0),
            blocks_processed_total: AtomicU64::new(0),
            rpc_accepts_total: AtomicU64::new(0),
            rpc_rejects_total: AtomicU64::new(0),
            last_block_slot: AtomicU64::new(0),
            last_block_txs: AtomicU64::new(0),
            last_block_gas: AtomicU64::new(0),
            last_block_ms: AtomicU64::new(0),
            last_block_at_unix_ms: AtomicU64::new(0),
            current_proposer: RwLock::new([0u8; 32]),
            local_address: RwLock::new([0u8; 32]),
            is_validator: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

static SNAPSHOT: OnceLock<Arc<Snapshot>> = OnceLock::new();

/// Returns the process-wide metrics snapshot, initializing it on
/// first call. Cheap on the hot path: cloning the `Arc` is one
/// atomic increment.
pub fn snapshot() -> Arc<Snapshot> {
    SNAPSHOT
        .get_or_init(|| Arc::new(Snapshot::default()))
        .clone()
}

/// Setters the call sites that already publish to Prometheus also
/// invoke. Centralizes the snapshot writes so the
/// Prometheus-export-only fns above don't grow a parallel set of
/// `snapshot().X.store(...)` lines.
pub fn set_finalized_slot(slot: u64) {
    metrics::gauge!("pyde_chain_finalized_slot").set(slot as f64);
    snapshot()
        .chain_finalized_slot
        .store(slot, Ordering::Relaxed);
}

pub fn set_base_fee(fee: u64) {
    metrics::gauge!("pyde_chain_base_fee").set(fee as f64);
    snapshot().chain_base_fee.store(fee, Ordering::Relaxed);
}

pub fn set_epoch(epoch: u64) {
    metrics::gauge!("pyde_chain_epoch").set(epoch as f64);
    snapshot().epoch.store(epoch, Ordering::Relaxed);
}

pub fn set_committee_size(size: usize) {
    metrics::gauge!("pyde_committee_size").set(size as f64);
    snapshot().committee_size.store(size, Ordering::Relaxed);
}

pub fn set_current_proposer(addr: [u8; 32]) {
    if let Ok(mut w) = snapshot().current_proposer.write() {
        *w = addr;
    }
}

pub fn set_local_address(addr: [u8; 32]) {
    if let Ok(mut w) = snapshot().local_address.write() {
        *w = addr;
    }
}

pub fn set_is_validator(v: bool) {
    snapshot().is_validator.store(v, Ordering::Relaxed);
}
