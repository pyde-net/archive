//! Production-grade load generator: async HTTP, connection pooling, multi-node.
//! Measures real end-to-end TPS including consensus, networking, signatures.
//!
//! Usage:
//!   docker compose -f docker/docker-compose.production.yml up -d
//!   PYDE_ACCOUNTS_JSON=/path/to/accounts.json \
//!     cargo test -p pyde-node --test loadgen --release -- --nocapture

use pyde_account::address::derive_eoa_address;
use pyde_crypto::falcon::{falcon_sign, FalconPublicKey, FalconSecretKey};
use pyde_tx::types::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

struct Wallet {
    address: [u8; 32],
    _pk: FalconPublicKey,
    sk: FalconSecretKey,
}

async fn rpc_async(client: &reqwest::Client, url: &str, method: &str, params: &str) -> serde_json::Value {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"{}","params":[{}],"id":1}}"#,
        method, params
    );
    match client.post(url).header("Content-Type", "application/json").body(body).send().await {
        Ok(resp) => resp.json().await.unwrap_or_default(),
        Err(_) => serde_json::Value::Null,
    }
}

fn get_str(resp: &serde_json::Value) -> String {
    match resp.get("result") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => String::new(),
    }
}

#[test]
fn load_test_full_pipeline() {
    let accounts_path = match std::env::var("PYDE_ACCOUNTS_JSON") {
        Ok(p) => p,
        Err(_) => { println!("SKIP: PYDE_ACCOUNTS_JSON not set"); return; }
    };
    let rpc_urls: Vec<String> = vec![
        "http://localhost:8545".into(),
        "http://localhost:8546".into(),
        "http://localhost:8547".into(),
        "http://localhost:8548".into(),
    ];

    let accounts_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&accounts_path).unwrap()
    ).unwrap();
    let chain_id = accounts_json["chainId"].as_u64().unwrap();
    let accts = accounts_json["accounts"].as_array().unwrap();

    // Load wallets
    let mut wallets: Vec<Wallet> = Vec::new();
    for acc in accts {
        if acc.get("faucet").is_some() { continue; }
        let pk_hex = acc["privateKey"].as_str().unwrap().trim_start_matches("0x");
        let pk_bytes = hex::decode(pk_hex).unwrap();
        if pk_bytes.len() != 897 + 1281 { continue; }
        let pk = FalconPublicKey::from_bytes(&pk_bytes[..897]).unwrap();
        let sk = FalconSecretKey::from_bytes(&pk_bytes[897..]).unwrap();
        let address = derive_eoa_address(pk.as_bytes());
        wallets.push(Wallet { address, _pk: pk, sk });
    }

    // Each wallet sends 14 txs (nonce window = 16, leave margin)
    let txs_per_wallet: u64 = 14;
    let total_txs = wallets.len() as u64 * txs_per_wallet;
    let recipient = [0x42u8; 32];

    println!("\n========== PYDE PRODUCTION LOAD TEST ==========\n");
    println!("  RPC nodes:  {}", rpc_urls.len());
    println!("  Chain ID:   {}", chain_id);
    println!("  Wallets:    {}", wallets.len());
    println!("  Txs/wallet: {}", txs_per_wallet);
    println!("  Total txs:  {}", total_txs);
    println!();

    // Pre-sign ALL transactions
    println!("  Signing {} transactions...", total_txs);
    let sign_start = Instant::now();
    let mut signed_txs: Vec<String> = Vec::with_capacity(total_txs as usize);
    for i in 0..total_txs {
        let w = &wallets[(i as usize) % wallets.len()];
        let nonce = i / wallets.len() as u64;
        let mut tx = Transaction {
            from: w.address, to: recipient, value: 1, data: vec![],
            gas_limit: 50_000, nonce, signature: vec![],
            fee_payer: FeePayer::Sender, access_list: vec![],
            deadline: None, chain_id, tx_type: TransactionType::Standard,
        };
        let hash = tx.hash();
        tx.signature = falcon_sign(&w.sk, &hash).unwrap().as_bytes().to_vec();
        signed_txs.push(format!("0x{}", hex::encode(tx.to_bytes())));
    }
    let sign_elapsed = sign_start.elapsed();
    println!("  Signed in {:.2}s ({:.0} signs/s)\n",
        sign_elapsed.as_secs_f64(), total_txs as f64 / sign_elapsed.as_secs_f64());

    // Run async submission
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(20)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();

        // Check node
        let resp = rpc_async(&client, &rpc_urls[0], "pyde_blockNumber", "").await;
        let start_block_hex = get_str(&resp);
        let start_block = u64::from_str_radix(start_block_hex.trim_start_matches("0x"), 16).unwrap_or(0);
        println!("  Start block: {} (0x{:x})", start_block, start_block);

        // Submit txs across all 4 nodes in parallel
        let submitted = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));
        let send_start = Instant::now();

        // Split txs into chunks, one per async task, round-robin across RPC nodes
        let concurrency = 32usize;
        let chunk_size = (signed_txs.len() + concurrency - 1) / concurrency;
        let mut tasks = Vec::new();

        for c in 0..concurrency {
            let start = c * chunk_size;
            let end = (start + chunk_size).min(signed_txs.len());
            if start >= signed_txs.len() { break; }
            let chunk: Vec<String> = signed_txs[start..end].to_vec();
            let url = rpc_urls[c % rpc_urls.len()].clone();
            let cl = client.clone();
            let sub = submitted.clone();
            let err = errors.clone();

            tasks.push(tokio::spawn(async move {
                for tx_hex in chunk {
                    let params = format!("\"{}\"", tx_hex);
                    let resp = rpc_async(&cl, &url, "pyde_sendRawTransaction", &params).await;
                    if resp.get("error").is_some() || resp.is_null() {
                        err.fetch_add(1, Ordering::Relaxed);
                    } else {
                        sub.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }

        for t in tasks { let _ = t.await; }
        let send_elapsed = send_start.elapsed();
        let sub_count = submitted.load(Ordering::Relaxed);
        let err_count = errors.load(Ordering::Relaxed);
        let submit_tps = sub_count as f64 / send_elapsed.as_secs_f64();

        println!("  Submitted: {} ok, {} errors in {:.2}s ({:.0} submit/s)",
            sub_count, err_count, send_elapsed.as_secs_f64(), submit_tps);

        // Wait for inclusion
        println!("  Waiting 10s for block inclusion...");
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        // Measure results
        let resp = rpc_async(&client, &rpc_urls[0], "pyde_blockNumber", "").await;
        let end_block_hex = get_str(&resp);
        let end_block = u64::from_str_radix(end_block_hex.trim_start_matches("0x"), 16).unwrap_or(0);

        let resp = rpc_async(&client, &rpc_urls[0], "pyde_getBalance",
            &format!("\"0x{}\"", hex::encode(recipient))).await;
        let bal_str = get_str(&resp);
        let executed: u64 = if bal_str.starts_with("0x") {
            u64::from_str_radix(bal_str.trim_start_matches("0x"), 16).unwrap_or(0)
        } else {
            bal_str.parse().unwrap_or(0)
        };

        let blocks = end_block - start_block;
        let total_time = send_elapsed.as_secs_f64() + 10.0;
        let inclusion_tps = executed as f64 / total_time;
        // TPS during active submission period
        let active_tps = if send_elapsed.as_secs_f64() > 0.0 {
            executed as f64 / send_elapsed.as_secs_f64()
        } else { 0.0 };

        println!("\n  ========== RESULTS ==========");
        println!("  Blocks:       {} ({} → {})", blocks, start_block, end_block);
        println!("  Block time:   {:.2}s", total_time / blocks as f64);
        println!("  Submitted:    {}", sub_count);
        println!("  Executed:     {} ({:.1}% success)", executed, (executed as f64 / sub_count as f64) * 100.0);
        println!("  Submit rate:  {:.0} tx/s (async, {} concurrent, 4 nodes)", submit_tps, concurrency);
        println!("  Sign rate:    {:.0} tx/s (FALCON-512)", total_txs as f64 / sign_elapsed.as_secs_f64());
        println!("  Active TPS:   {:.0} (executed / submit time)", active_tps);
        println!("  Overall TPS:  {:.0} (executed / total time incl. wait)", inclusion_tps);
        println!("  ==============================\n");

        println!("  Grafana: http://localhost:3000 (dashboard: Pyde Devnet)");
        println!("  Prometheus: http://localhost:9999");
        println!();

        assert!(executed > 0, "no transactions executed");
        println!("========== LOAD TEST COMPLETE ==========\n");
    });
}
