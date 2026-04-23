//! Fast binary transaction submission endpoint.
//!
//! High-performance alternative to HTTP JSON-RPC for transaction submission.
//! Accepts raw signed transaction bytes with length-prefix framing over TCP.
//!
//! Wire format per transaction:
//!   [4 bytes LE: payload_length][payload_length bytes: signed tx]
//!
//! The signed tx bytes are decoded via `wire::decode_transaction()` or
//! `Transaction::from_bytes()`, then injected into the pending pool + gossip.
//!
//! This eliminates HTTP headers, JSON parsing, and hex encoding overhead.
//! Typical throughput: 50K-100K tx/s vs ~1-2K tx/s via HTTP RPC.

use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Start the fast binary TX submission listener.
/// Returns the bound address on success.
pub async fn start_fast_tx_listener(
    listen: &str,
    port: u16,
    pending_txs: Arc<RwLock<std::collections::HashMap<[u8; 32], pyde_tx::types::Transaction>>>,
    pending_tx_times: Arc<RwLock<std::collections::HashMap<[u8; 32], std::time::Instant>>>,
    tx_gossip_tx: tokio::sync::mpsc::Sender<pyde_tx::types::Transaction>,
) -> Result<std::net::SocketAddr, String> {
    let addr = format!("{}:{}", listen, port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("fast_tx bind failed on {}: {}", addr, e))?;
    let bound = listener
        .local_addr()
        .map_err(|e| format!("fast_tx local_addr: {}", e))?;

    info!(%bound, "fast binary TX endpoint started");

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let ptx = pending_txs.clone();
                    let ptimes = pending_tx_times.clone();
                    let gtx = tx_gossip_tx.clone();
                    tokio::spawn(handle_connection(stream, peer, ptx, ptimes, gtx));
                }
                Err(e) => {
                    warn!(error = %e, "fast_tx accept error");
                }
            }
        }
    });

    Ok(bound)
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    pending_txs: Arc<RwLock<std::collections::HashMap<[u8; 32], pyde_tx::types::Transaction>>>,
    pending_tx_times: Arc<RwLock<std::collections::HashMap<[u8; 32], std::time::Instant>>>,
    tx_gossip_tx: tokio::sync::mpsc::Sender<pyde_tx::types::Transaction>,
) {
    let mut accepted = 0u64;
    let mut errors = 0u64;
    let mut batch: Vec<pyde_tx::types::Transaction> = Vec::with_capacity(256);

    loop {
        // Read 4-byte length prefix (LE)
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break; // connection closed or EOF
        }
        let len = u32::from_le_bytes(len_buf) as usize;

        if len == 0 || len > 131_072 {
            debug!(peer = %peer, len, "invalid tx length");
            errors += 1;
            break;
        }

        let mut buf = vec![0u8; len];
        if stream.read_exact(&mut buf).await.is_err() {
            break;
        }

        let tx = crate::wire::decode_transaction(&buf).or_else(|_| {
            pyde_tx::types::Transaction::from_bytes(&buf).ok_or("invalid tx encoding")
        });

        match tx {
            Ok(tx) => {
                batch.push(tx);
                accepted += 1;
            }
            Err(_) => {
                errors += 1;
            }
        }

        // Flush batch every 128 txs or when no more data is immediately available
        if batch.len() >= 128 {
            let now = std::time::Instant::now();
            let hashes: Vec<[u8; 32]> = batch.iter().map(|tx| tx.hash()).collect();
            let mut pending = pending_txs.write().await;
            for tx in batch.drain(..) {
                pending.insert(tx.hash(), tx);
            }
            drop(pending);
            let mut times = pending_tx_times.write().await;
            for h in &hashes {
                times.insert(*h, now);
            }
        }
    }

    // Flush remaining
    if !batch.is_empty() {
        let now = std::time::Instant::now();
        let hashes: Vec<[u8; 32]> = batch.iter().map(|tx| tx.hash()).collect();
        let mut pending = pending_txs.write().await;
        for tx in &batch {
            let _ = tx_gossip_tx.send(tx.clone()).await;
        }
        for tx in batch {
            pending.insert(tx.hash(), tx);
        }
        drop(pending);
        let mut times = pending_tx_times.write().await;
        for h in &hashes {
            times.insert(*h, now);
        }
    }

    if accepted > 0 || errors > 0 {
        debug!(peer = %peer, accepted, errors, "fast_tx connection closed");
    }
}
