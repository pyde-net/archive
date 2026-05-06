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

async fn rpc_async(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: &str,
) -> serde_json::Value {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"{}","params":[{}],"id":1}}"#,
        method, params
    );
    match client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
    {
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
#[ignore = "load generator — requires running node, run with --ignored"]
fn load_test_full_pipeline() {
    let accounts_path = match std::env::var("PYDE_ACCOUNTS_JSON") {
        Ok(p) => p,
        Err(_) => {
            println!("SKIP: PYDE_ACCOUNTS_JSON not set");
            return;
        }
    };
    let rpc_urls: Vec<String> = vec![
        "http://localhost:8545".into(),
        "http://localhost:8546".into(),
        "http://localhost:8547".into(),
        "http://localhost:8548".into(),
    ];

    let accounts_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&accounts_path).unwrap()).unwrap();
    let chain_id = accounts_json["chainId"].as_u64().unwrap();
    let accts = accounts_json["accounts"].as_array().unwrap();

    // Load wallets
    let mut wallets: Vec<Wallet> = Vec::new();
    for acc in accts {
        if acc.get("faucet").is_some() {
            continue;
        }
        let pk_hex = acc["privateKey"].as_str().unwrap().trim_start_matches("0x");
        let pk_bytes = hex::decode(pk_hex).unwrap();
        if pk_bytes.len() != 897 + 1281 {
            continue;
        }
        let pk = FalconPublicKey::from_bytes(&pk_bytes[..897]).unwrap();
        let sk = FalconSecretKey::from_bytes(&pk_bytes[897..]).unwrap();
        let address = derive_eoa_address(pk.as_bytes());
        wallets.push(Wallet {
            address,
            _pk: pk,
            sk,
        });
    }

    // Each wallet sends 60 txs (nonce window = 64, leave margin)
    let txs_per_wallet: u64 = 60;
    let total_txs = wallets.len() as u64 * txs_per_wallet;
    let recipient = [0x42u8; 32];

    println!("\n========== PYDE PRODUCTION LOAD TEST ==========\n");
    println!("  RPC nodes:  {}", rpc_urls.len());
    println!("  Chain ID:   {}", chain_id);
    println!("  Wallets:    {}", wallets.len());
    println!("  Txs/wallet: {}", txs_per_wallet);
    println!("  Total txs:  {}", total_txs);
    println!();

    // --- Phase 1: Deploy 20 complex contracts ---
    println!("  Deploying 20 complex contracts...");
    let num_contracts = 20usize;
    // Complex contract: 597 instructions. Exercises:
    // - Heap: Vec allocation + indexed access (370 memory instrs)
    // - Wide: u256 accumulation (11 wide ops)
    // - Math: Fibonacci, XOR, shifts, multiply (170 GP instrs)
    // - Stack: 16+ local variables, struct construction
    // - String: heap-allocated string processing
    // - Loops: 3 passes over n-element array
    let heavy_source = r#"
        struct Stats { sum: u256, count: u64, min: u64, max: u64 }

        contract HeavyWork {
            storage { result: u64, }
            #[constructor] pub fn init() { self.result = 0; }

            #[reentrant] #[payable]
            pub fn heavy_compute(n: u64) {
                let mut data = Vec::new();
                for i in 0..n { data.push(i * i + i * 37); }

                let mut wide_sum: u256 = 0 as u256;
                let mut wide_product: u256 = 1 as u256;
                let len = data.len();
                let mut idx: u64 = 0;
                while idx < len {
                    let val = data[idx];
                    wide_sum = wide_sum + (val as u256);
                    wide_product = wide_product + (val as u256) * (17 as u256);
                    idx = idx + 1;
                }

                let mut xor_acc: u64 = 0;
                let mut shift_acc: u64 = 0;
                idx = 0;
                while idx < len {
                    let val = data[idx];
                    xor_acc = xor_acc ^ (val * 31);
                    shift_acc = shift_acc + (val >> (idx % 8));
                    idx = idx + 1;
                }

                let stats = Stats { sum: wide_sum, count: len, min: data[0], max: data[len - 1] };
                let mut name = "pyde_benchmark_heavy";
                let name_len = name.len();

                let mut fib_sum: u64 = 0;
                idx = 2;
                while idx < len {
                    let prev1 = data[idx - 1];
                    let prev2 = data[idx - 2];
                    fib_sum = fib_sum + prev1 + prev2 + (xor_acc >> 3);
                    idx = idx + 1;
                }

                let a = stats.count * 3;
                let b = fib_sum ^ xor_acc;
                let c = shift_acc + name_len;
                let d = a + b + c;
                let e = d * 7 + a;
                let f = e ^ (b >> 2);
                let g = f + c * 13;
                let h = g ^ d;
                self.result = h ^ fib_sum;
            }
        }
    "#;
    let compiled = otic::compile_all_unchecked(heavy_source);
    let (_, cc) = &compiled[0];
    let mut deploy_data = Vec::new();
    deploy_data.extend_from_slice(&(cc.constructor_bytecode.len() as u32).to_le_bytes());
    deploy_data.extend_from_slice(&(cc.runtime_bytecode.len() as u32).to_le_bytes());
    deploy_data.extend_from_slice(&cc.constructor_bytecode);
    deploy_data.extend_from_slice(&cc.runtime_bytecode);

    // Sign deploy txs (one per deployer wallet, nonce 0)
    let mut deploy_txs: Vec<String> = Vec::new();
    for i in 0..num_contracts {
        let w = &wallets[i];
        let mut tx = Transaction {
            from: w.address,
            to: [0u8; 32],
            value: 0,
            data: deploy_data.clone(),
            gas_limit: 100_000_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id,
            tx_type: TransactionType::Deploy,
        };
        let hash = tx.hash();
        tx.signature = falcon_sign(&w.sk, &hash).unwrap().as_bytes().to_vec();
        deploy_txs.push(format!("0x{}", hex::encode(tx.to_bytes())));
    }

    // --- Phase 2: Build mixed workload (60% transfers + 40% contract calls) ---
    let call_selector = otic::codegen::compute_selector("heavy_compute");
    let mut call_data = call_selector.to_be_bytes().to_vec();
    call_data.extend_from_slice(&100u64.to_le_bytes()); // n=100 iterations

    // Pre-compute nonces and tx params, then parallel sign with rayon
    println!(
        "  Building {} mixed transactions (60% transfers, 40% contract calls)...",
        total_txs
    );
    let mut nonce_tracker: Vec<u64> = vec![0; wallets.len()];
    for i in 0..num_contracts {
        nonce_tracker[i] = 1;
    }

    // Build unsigned tx descriptors (fast, single-threaded)
    struct TxDesc {
        w_idx: usize,
        nonce: u64,
        is_call: bool,
        contract_idx: usize,
    }
    let mut descs: Vec<TxDesc> = Vec::with_capacity(total_txs as usize);
    for i in 0..total_txs {
        let w_idx = (i as usize) % wallets.len();
        let nonce = nonce_tracker[w_idx];
        nonce_tracker[w_idx] += 1;
        descs.push(TxDesc {
            w_idx,
            nonce,
            is_call: (i % 5) >= 3,
            contract_idx: (i as usize) % num_contracts,
        });
    }

    // Parallel signing with rayon (14 cores)
    use rayon::prelude::*;
    println!(
        "  Signing {} txs in parallel ({} cores)...",
        total_txs,
        rayon::current_num_threads()
    );
    let sign_start = Instant::now();

    // Pre-compute contract addresses
    let contract_addrs: Vec<[u8; 32]> = (0..num_contracts)
        .map(|i| pyde_account::address::derive_create_address(&wallets[i].address, 0))
        .collect();

    let signed_txs: Vec<Vec<u8>> = descs
        .par_iter()
        .map(|desc| {
            let w = &wallets[desc.w_idx];
            let mut tx = if desc.is_call {
                Transaction {
                    from: w.address,
                    to: contract_addrs[desc.contract_idx],
                    value: 0,
                    data: call_data.clone(),
                    gas_limit: 10_000_000,
                    nonce: desc.nonce,
                    signature: vec![],
                    fee_payer: FeePayer::Sender,
                    access_list: vec![],
                    deadline: None,
                    chain_id,
                    tx_type: TransactionType::Standard,
                }
            } else {
                Transaction {
                    from: w.address,
                    to: recipient,
                    value: 1,
                    data: vec![],
                    gas_limit: 50_000,
                    nonce: desc.nonce,
                    signature: vec![],
                    fee_payer: FeePayer::Sender,
                    access_list: vec![],
                    deadline: None,
                    chain_id,
                    tx_type: TransactionType::Standard,
                }
            };
            let hash = tx.hash();
            tx.signature = falcon_sign(&w.sk, &hash).unwrap().as_bytes().to_vec();
            tx.to_bytes()
        })
        .collect();

    let sign_elapsed = sign_start.elapsed();
    let transfer_count = descs.iter().filter(|d| !d.is_call).count();
    let call_count = descs.iter().filter(|d| d.is_call).count();
    println!(
        "  Signed in {:.2}s ({:.0} signs/s) — {} transfers + {} contract calls\n",
        sign_elapsed.as_secs_f64(),
        total_txs as f64 / sign_elapsed.as_secs_f64(),
        transfer_count,
        call_count
    );

    // Also keep hex versions for HTTP fallback
    let signed_txs_hex: Vec<String> = signed_txs
        .iter()
        .map(|b| format!("0x{}", hex::encode(b)))
        .collect();

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

        // Deploy contracts — submit to ALL nodes for fastest inclusion
        println!(
            "  Deploying {} contracts (to all 4 nodes)...",
            deploy_txs.len()
        );
        for dtx in deploy_txs.iter() {
            let params = format!("\"{}\"", dtx);
            // Submit to all 4 nodes simultaneously
            for url in &rpc_urls {
                let _ = rpc_async(&client, url, "pyde_sendRawTransaction", &params).await;
            }
        }

        // Poll until contracts are deployed (max 20s)
        let contract0 = pyde_account::address::derive_create_address(&wallets[0].address, 0);
        println!("  Waiting for contract deployment...");
        for attempt in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let resp = rpc_async(
                &client,
                &rpc_urls[0],
                "pyde_getCode",
                &format!("\"0x{}\"", hex::encode(contract0)),
            )
            .await;
            let code = get_str(&resp);
            if !code.is_empty() && code != "0x" {
                println!(
                    "  Contracts deployed after {:.1}s ({} bytes code)",
                    (attempt + 1) as f64 * 0.5,
                    code.len() / 2 - 1
                );
                break;
            }
            if attempt == 39 {
                println!("  WARNING: contracts still not deployed after 20s");
            }
        }

        // Check node
        let resp = rpc_async(&client, &rpc_urls[0], "pyde_blockNumber", "").await;
        let start_block_hex = get_str(&resp);
        let start_block =
            u64::from_str_radix(start_block_hex.trim_start_matches("0x"), 16).unwrap_or(0);
        println!("  Start block: {} (0x{:x})", start_block, start_block);

        // Submit via fast binary TCP endpoint (port 9545) if available,
        // otherwise fall back to HTTP RPC
        // Auto-detect which fast TX ports are available
        let mut fast_tx_addrs: Vec<String> = Vec::new();
        for port in [9545, 9546, 9547, 9548] {
            let addr = format!("127.0.0.1:{}", port);
            if std::net::TcpStream::connect_timeout(
                &addr.parse().unwrap(),
                std::time::Duration::from_millis(100),
            )
            .is_ok()
            {
                fast_tx_addrs.push(addr);
            }
        }
        if fast_tx_addrs.is_empty() {
            fast_tx_addrs.push("127.0.0.1:9545".into()); // fallback
        }
        println!("  Fast TX ports: {} available", fast_tx_addrs.len());

        // signed_txs is already raw bytes, signed_txs_hex is for HTTP fallback
        let raw_txs = &signed_txs;

        // Try binary endpoint first
        let use_binary = tokio::net::TcpStream::connect(&fast_tx_addrs[0])
            .await
            .is_ok();

        let submitted = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));
        let send_start = Instant::now();

        if use_binary {
            println!("  Using fast binary TX endpoint (port 9545-9548)");
            let concurrency = 32usize;
            let chunk_size = raw_txs.len().div_ceil(concurrency);
            let mut tasks = Vec::new();

            for c in 0..concurrency {
                let start_idx = c * chunk_size;
                let end_idx = (start_idx + chunk_size).min(raw_txs.len());
                if start_idx >= raw_txs.len() {
                    break;
                }
                let chunk: Vec<Vec<u8>> = raw_txs[start_idx..end_idx].to_vec();
                let addr = fast_tx_addrs[c % fast_tx_addrs.len()].clone();
                let sub = submitted.clone();
                let err = errors.clone();

                tasks.push(tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    match tokio::net::TcpStream::connect(&addr).await {
                        Ok(mut stream) => {
                            let _ = stream.set_nodelay(true);
                            // Send in micro-batches of 64 txs with small delays
                            // to match chain ingestion rate (~2K tx/s per node)
                            for micro in chunk.chunks(64) {
                                let total_size: usize = micro.iter().map(|t| 4 + t.len()).sum();
                                let mut buf = Vec::with_capacity(total_size);
                                for tx_bytes in micro {
                                    buf.extend_from_slice(&(tx_bytes.len() as u32).to_le_bytes());
                                    buf.extend_from_slice(tx_bytes);
                                }
                                if stream.write_all(&buf).await.is_err() {
                                    err.fetch_add(micro.len() as u64, Ordering::Relaxed);
                                    break;
                                }
                                sub.fetch_add(micro.len() as u64, Ordering::Relaxed);
                                // Pace submission: ~2K tx/s per connection = 64 txs every 32ms
                                tokio::time::sleep(std::time::Duration::from_millis(32)).await;
                            }
                        }
                        Err(_) => {
                            err.fetch_add(chunk.len() as u64, Ordering::Relaxed);
                        }
                    }
                }));
            }
            for t in tasks {
                let _ = t.await;
            }
        } else {
            println!("  Using HTTP RPC (fast TX endpoint not available)");
            let concurrency = 32usize;
            let chunk_size = signed_txs_hex.len().div_ceil(concurrency);
            let mut tasks = Vec::new();

            for c in 0..concurrency {
                let start_idx = c * chunk_size;
                let end_idx = (start_idx + chunk_size).min(signed_txs_hex.len());
                if start_idx >= signed_txs_hex.len() {
                    break;
                }
                let chunk: Vec<String> = signed_txs_hex[start_idx..end_idx].to_vec();
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
            for t in tasks {
                let _ = t.await;
            }
        }
        let send_elapsed = send_start.elapsed();
        let sub_count = submitted.load(Ordering::Relaxed);
        let err_count = errors.load(Ordering::Relaxed);
        let submit_tps = sub_count as f64 / send_elapsed.as_secs_f64();

        println!(
            "  Submitted: {} ok, {} errors in {:.2}s ({:.0} submit/s)",
            sub_count,
            err_count,
            send_elapsed.as_secs_f64(),
            submit_tps
        );

        // Wait for inclusion
        println!("  Waiting 10s for block inclusion...");
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        // Measure results
        let resp = rpc_async(&client, &rpc_urls[0], "pyde_blockNumber", "").await;
        let end_block_hex = get_str(&resp);
        let end_block =
            u64::from_str_radix(end_block_hex.trim_start_matches("0x"), 16).unwrap_or(0);

        let resp = rpc_async(
            &client,
            &rpc_urls[0],
            "pyde_getBalance",
            &format!("\"0x{}\"", hex::encode(recipient)),
        )
        .await;
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
        } else {
            0.0
        };

        println!("\n  ========== RESULTS ==========");
        println!(
            "  Blocks:       {} ({} → {})",
            blocks, start_block, end_block
        );
        println!("  Block time:   {:.2}s", total_time / blocks as f64);
        println!("  Submitted:    {}", sub_count);
        println!(
            "  Executed:     {} ({:.1}% success)",
            executed,
            (executed as f64 / sub_count as f64) * 100.0
        );
        println!(
            "  Submit rate:  {:.0} tx/s ({}, 32 concurrent, 4 nodes)",
            submit_tps,
            if use_binary { "binary TCP" } else { "HTTP RPC" }
        );
        println!(
            "  Sign rate:    {:.0} tx/s (FALCON-512)",
            total_txs as f64 / sign_elapsed.as_secs_f64()
        );
        println!("  Active TPS:   {:.0} (executed / submit time)", active_tps);
        println!(
            "  Overall TPS:  {:.0} (executed / total time incl. wait)",
            inclusion_tps
        );
        println!("  ==============================\n");

        println!("  Grafana: http://localhost:3000 (dashboard: Pyde Devnet)");
        println!("  Prometheus: http://localhost:9999");
        println!();

        assert!(executed > 0, "no transactions executed");
        println!("========== LOAD TEST COMPLETE ==========\n");
    });
}
