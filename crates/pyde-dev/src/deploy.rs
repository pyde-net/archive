use crate::build;
use crate::project;
use std::fs;

pub fn run(network: &str, contract: Option<&str>, from: &str) -> Result<(), String> {
    let (config, root) = project::load_config()?;

    // Get network config
    let net = config
        .networks
        .get(network)
        .ok_or_else(|| {
            let available: Vec<&String> = config.networks.keys().collect();
            format!(
                "network '{}' not found in pyde.toml (available: {})",
                network,
                if available.is_empty() {
                    "none".to_string()
                } else {
                    available.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                }
            )
        })?
        .clone();

    // Build if needed
    let out_dir = root.join(&config.compiler.out);
    if !out_dir.exists() {
        println!("  Building contracts first...");
        build::build_project(&config, &root)?;
        println!();
    }

    // Find the artifact to deploy
    let artifact_path = if let Some(name) = contract {
        let p = out_dir.join(format!("{}.json", name));
        if !p.exists() {
            return Err(format!("artifact not found: {}", p.display()));
        }
        p
    } else {
        // Auto-detect: find the first .json artifact in out/
        let mut artifacts: Vec<_> = glob::glob(&format!("{}/*.json", out_dir.display()))
            .map_err(|e| format!("glob error: {}", e))?
            .filter_map(|r| r.ok())
            .filter(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy() != ".build-cache.json")
                    .unwrap_or(false)
            })
            .collect();

        if artifacts.is_empty() {
            return Err("no compiled artifacts found in out/ — run `pyde-dev build` first".into());
        }
        if artifacts.len() > 1 {
            let names: Vec<String> = artifacts
                .iter()
                .filter_map(|p| p.file_stem().map(|s| s.to_string_lossy().to_string()))
                .collect();
            return Err(format!(
                "multiple contracts found: {}. Use --contract <name> to specify which to deploy",
                names.join(", ")
            ));
        }
        artifacts.remove(0)
    };

    // Read artifact
    let json_str = fs::read_to_string(&artifact_path)
        .map_err(|e| format!("cannot read {}: {}", artifact_path.display(), e))?;
    let artifact: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| format!("invalid artifact JSON: {}", e))?;

    let contract_name = artifact
        .get("contractName")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let constructor_hex = artifact
        .get("constructorBytecode")
        .and_then(|v| v.as_str())
        .unwrap_or("0x")
        .trim_start_matches("0x");
    let runtime_hex = artifact
        .get("deployedBytecode")
        .and_then(|v| v.as_str())
        .unwrap_or("0x")
        .trim_start_matches("0x");

    let constructor_len = constructor_hex.len() / 2;
    let full_bytecode = format!("{}{}", constructor_hex, runtime_hex);

    println!("  Deploying {} to {} ({})", contract_name, network, net.rpc_url);
    println!("  Constructor: {} bytes", constructor_len);
    println!("  Runtime:     {} bytes", runtime_hex.len() / 2);
    println!("  From:        {}", from);

    // Send deploy transaction via JSON-RPC
    let zero_addr = "0x0000000000000000000000000000000000000000000000000000000000000000";
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "pyde_sendTransaction",
        "params": [{
            "from": from,
            "to": zero_addr,
            "data": format!("0x{}", full_bytecode),
            "constructorLen": constructor_len,
            "gas": 100_000_000,
            "nonce": get_nonce(&net.rpc_url, from)?,
            "value": "0"
        }]
    });

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&net.rpc_url)
        .json(&body)
        .send()
        .map_err(|e| format!("RPC request failed: {} — is the node running at {}?", e, net.rpc_url))?;

    let resp_json: serde_json::Value = resp
        .json()
        .map_err(|e| format!("invalid RPC response: {}", e))?;

    if let Some(err) = resp_json.get("error") {
        return Err(format!("deploy failed: {}", err));
    }

    let result_str = resp_json
        .get("result")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Extract tx hash from response
    let tx_hash = if let Ok(inner) = serde_json::from_str::<serde_json::Value>(result_str) {
        inner.get("txHash").and_then(|v| v.as_str())
            .unwrap_or(result_str).to_string()
    } else {
        result_str.to_string()
    };

    // Poll receipt for the authoritative contract address
    println!("  Waiting for receipt...");
    let receipt = poll_receipt(&client, &net.rpc_url, &tx_hash)?;
    let success = receipt.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        return Err("deploy transaction reverted".into());
    }
    let contract_addr = receipt.get("returnData")
        .and_then(|v| v.as_str())
        .map(|s| if s.starts_with("0x") { s.to_string() } else { format!("0x{}", s) })
        .unwrap_or_else(|| "unknown".to_string());

    println!();
    println!("  Deployed!");
    println!("  Contract: {}", contract_addr);
    println!("  Tx Hash:  {}", tx_hash);

    Ok(())
}

/// Poll `pyde_getTransactionReceipt` until the receipt is available.
fn poll_receipt(
    client: &reqwest::blocking::Client,
    rpc_url: &str,
    tx_hash: &str,
) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "pyde_getTransactionReceipt",
        "params": [tx_hash]
    });
    for attempt in 0..50 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let resp = client.post(rpc_url).json(&body).send()
            .map_err(|e| format!("RPC error polling receipt: {}", e))?;
        let json: serde_json::Value = resp.json()
            .map_err(|e| format!("invalid receipt response: {}", e))?;
        if json.get("error").is_none() {
            if let Some(result) = json.get("result") {
                if !result.is_null() {
                    return Ok(result.clone());
                }
            }
        }
    }
    Err(format!("receipt not available after 5s for tx {}", tx_hash))
}

/// Get the current nonce for an address via RPC.
fn get_nonce(rpc_url: &str, address: &str) -> Result<u64, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "pyde_getTransactionCount",
        "params": [address]
    });

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(rpc_url)
        .json(&body)
        .send()
        .map_err(|e| format!("cannot fetch nonce: {}", e))?;

    let resp_json: serde_json::Value = resp
        .json()
        .map_err(|e| format!("invalid nonce response: {}", e))?;

    let nonce_str = resp_json
        .get("result")
        .and_then(|v| v.as_str())
        .unwrap_or("0");

    nonce_str
        .parse::<u64>()
        .map_err(|_| format!("invalid nonce value: {}", nonce_str))
}
