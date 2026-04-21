use crate::build;
use crate::project;
use std::fs;

/// Verify a deployed contract matches local source compilation.
pub fn run(address: &str, contract: Option<&str>, network: &str) -> Result<(), String> {
    let (config, root) = project::load_config()?;

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
                    available
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            )
        })?
        .clone();

    // Build to ensure artifacts are up to date
    println!("  Building...");
    build::build_project(&config, &root)?;
    println!();

    // Resolve artifact (supports path:ContractName or auto-detect)
    let out_dir = root.join(&config.compiler.out);
    let (artifact_path, _) = project::resolve_artifact(&out_dir, contract)?;

    // Read local runtime bytecode
    let json_str = fs::read_to_string(&artifact_path)
        .map_err(|e| format!("cannot read {}: {}", artifact_path.display(), e))?;
    let artifact: serde_json::Value =
        serde_json::from_str(&json_str).map_err(|e| format!("invalid artifact JSON: {}", e))?;

    let contract_name = artifact
        .get("contractName")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let local_hex = artifact
        .get("deployedBytecode")
        .and_then(|v| v.as_str())
        .unwrap_or("0x")
        .trim_start_matches("0x");

    if local_hex.is_empty() {
        return Err(format!(
            "no runtime bytecode in artifact for {}",
            contract_name
        ));
    }

    let local_bytes = hex::decode(local_hex).map_err(|e| format!("invalid bytecode hex: {}", e))?;

    // Fetch on-chain bytecode
    println!(
        "  Verifying {} at {} on {}",
        contract_name, address, network
    );

    let client = reqwest::blocking::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "pyde_getCode",
        "params": [address]
    });
    let resp = client
        .post(&net.rpc_url)
        .json(&body)
        .send()
        .map_err(|e| format!("RPC error: {} — is the node running?", e))?;
    let resp_json: serde_json::Value = resp
        .json()
        .map_err(|e| format!("invalid RPC response: {}", e))?;

    if let Some(err) = resp_json.get("error") {
        return Err(format!("RPC error: {}", err));
    }

    let onchain_hex = resp_json
        .get("result")
        .and_then(|v| v.as_str())
        .unwrap_or("0x")
        .trim_start_matches("0x");

    if onchain_hex.is_empty() {
        return Err(format!(
            "no code at {} — is the contract deployed?",
            address
        ));
    }

    let onchain_bytes =
        hex::decode(onchain_hex).map_err(|e| format!("invalid on-chain bytecode: {}", e))?;

    // Compare
    if local_bytes == onchain_bytes {
        println!("  {} VERIFIED", contract_name);
        println!("    Local:    {} bytes", local_bytes.len());
        println!("    On-chain: {} bytes", onchain_bytes.len());
        println!("    Match: exact");
    } else {
        println!("  {} MISMATCH", contract_name);
        println!("    Local:    {} bytes", local_bytes.len());
        println!("    On-chain: {} bytes", onchain_bytes.len());
        if local_bytes.len() != onchain_bytes.len() {
            println!(
                "    Size differs by {} bytes",
                (local_bytes.len() as isize - onchain_bytes.len() as isize).unsigned_abs()
            );
        } else if let Some(pos) = local_bytes
            .iter()
            .zip(onchain_bytes.iter())
            .position(|(a, b)| a != b)
        {
            println!("    First difference at byte {}", pos);
        }
        return Err("verification failed — bytecode does not match".into());
    }

    Ok(())
}
