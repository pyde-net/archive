use crate::build;
use crate::project;
use crate::signer::Signer;
use pyde_tx::types::*;
use std::fs;

pub fn run(network: &str, contract: Option<&str>, signer: &Signer, value: u128, verify: bool) -> Result<(), String> {
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

    // Build
    let out_dir = root.join(&config.compiler.out);
    println!("  Building...");
    build::build_project(&config, &root)?;
    println!();

    // Resolve artifact (supports path:ContractName or auto-detect)
    let (artifact_path, _) = project::resolve_artifact(&out_dir, contract)?;

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
    let full_bytecode = hex::decode(format!("{}{}", constructor_hex, runtime_hex))
        .map_err(|e| format!("invalid bytecode hex: {}", e))?;

    println!("  Deploying {} to {} ({})", contract_name, network, net.rpc_url);
    println!("  Constructor: {} bytes", constructor_len);
    println!("  Runtime:     {} bytes", runtime_hex.len() / 2);
    println!("  From:        {}", signer.address_hex());

    // Get nonce
    let nonce = get_nonce(&net.rpc_url, &signer.address_hex())?;

    // Build deploy transaction
    let mut tx = Transaction {
        from: signer.address,
        to: [0u8; 32], // zero address = deploy
        value,
        data: full_bytecode,
        gas_limit: 100_000_000,
        nonce,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id: net.chain_id,
        tx_type: TransactionType::Deploy,
    };

    // Sign with FALCON-512
    println!("  Signing transaction...");
    signer.sign_transaction(&mut tx)?;

    // Serialize to wire format and send via pyde_sendRawTransaction
    let tx_bytes = tx.to_bytes();
    let tx_hex = format!("0x{}", hex::encode(&tx_bytes));

    let client = reqwest::blocking::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "pyde_sendRawTransaction",
        "params": [tx_hex]
    });

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

    // Extract tx hash
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
    println!("  Signed:   ✓ (FALCON-512, verified by validator)");

    if verify {
        println!();
        crate::verify::run(&contract_addr, contract, network)?;
    }

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
