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
}

pub fn record_peers(count: usize) {
    metrics::gauge!("pyde_peers_connected").set(count as f64);
}

pub fn record_mempool(size: usize) {
    metrics::gauge!("pyde_mempool_size").set(size as f64);
}

/// Encrypted-tx mempool depth, separate from the plaintext
/// `pyde_mempool_size` so alerts can target the MEV-protected
/// queue specifically (audit 222). When this stays elevated
/// while plaintext mempool drains, it signals the threshold-
/// decryption pipeline is wedged.
pub fn record_encrypted_mempool(size: usize) {
    metrics::gauge!("pyde_encrypted_mempool_size").set(size as f64);
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
}
