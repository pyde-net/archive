//! RPC throughput benchmark.
//!
//! Starts a node RPC server, sends N requests via HTTP, measures req/sec.
//! Run with: cargo bench -p pyde-node
//!
//! NOTE: Requires a running node on port 8545.
//! Start with: make run-full
//! Then run: cargo bench -p pyde-node

use std::time::Instant;

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let url = "http://127.0.0.1:8545";

    rt.block_on(async {
        let client = reqwest::Client::new();

        // Check connectivity
        match send_rpc(&client, url, "pyde_chainId", "[]").await {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "Cannot connect to RPC at {}. Start a node first: make run-full",
                    url
                );
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }

        println!("\n=== Pyde RPC Benchmark ({})\n", url);

        bench(&client, url, "pyde_blockNumber", "[]", 10_000).await;
        bench(&client, url, "pyde_chainId", "[]", 10_000).await;
        bench(&client, url, "pyde_gasPrice", "[]", 10_000).await;
        bench(&client, url, "pyde_stateRoot", "[]", 10_000).await;
        bench(&client, url, "pyde_syncing", "[]", 10_000).await;

        let addr = format!("\"{}\"", hex::encode([0x01; 32]));
        bench(
            &client,
            url,
            "pyde_getBalance",
            &format!("[{}]", addr),
            10_000,
        )
        .await;
        bench(
            &client,
            url,
            "pyde_getTransactionCount",
            &format!("[{}]", addr),
            10_000,
        )
        .await;
        bench(&client, url, "pyde_getCode", &format!("[{}]", addr), 10_000).await;
        bench(&client, url, "pyde_mempoolSize", "[]", 10_000).await;

        println!();
    });
}

async fn bench(client: &reqwest::Client, url: &str, method: &str, params: &str, iterations: usize) {
    // Warm up
    for _ in 0..100 {
        let _ = send_rpc(client, url, method, params).await;
    }

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = send_rpc(client, url, method, params).await;
    }
    let elapsed = start.elapsed();

    println!(
        "  {:<35} {:.0} req/sec  ({:.1}µs/req)",
        method,
        iterations as f64 / elapsed.as_secs_f64(),
        elapsed.as_micros() as f64 / iterations as f64,
    );
}

async fn send_rpc(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: &str,
) -> Result<String, String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"{}","params":{},"id":1}}"#,
        method, params
    );
    client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())
}
