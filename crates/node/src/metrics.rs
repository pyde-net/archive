use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;

/// Start the Prometheus metrics exporter on the given port.
/// Returns the socket address it's bound to, or an error.
pub fn init(port: u16) -> Result<SocketAddr, String> {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();

    let builder = PrometheusBuilder::new().with_http_listener(addr);
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
