use crate::project;
use std::io::{self, BufRead, Write};

/// Interactive REPL for interacting with contracts on a live network.
///
/// Commands:
///   call <address> <method>(<args>)        — read-only call (pyde_call)
///   send <address> <method>(<args>)        — state-changing tx (pyde_sendTransaction)
///   balance <address>                       — query balance
///   nonce <address>                         — query nonce
///   code <address>                          — check if code exists
///   receipt <tx_hash>                       — get transaction receipt
///   block                                   — current block number
///   exit / quit                             — exit console
///
/// Supported arg types: u64, hex (0x...), bool (true/false), strings ("...").
/// Complex types (structs, arrays, Vec) are not yet supported — use `pyde script`
/// for those. TODO: load contract ABI from artifacts for type-aware encoding.
pub fn run(network: &str, signer: &crate::signer::Signer) -> Result<(), String> {
    let from = &signer.address_hex();
    let (config, _) = project::load_config()?;

    let net = config
        .networks
        .get(network)
        .ok_or_else(|| {
            let available: Vec<&String> = config.networks.keys().collect();
            format!(
                "network '{}' not found in pyde.toml (available: {})",
                network,
                if available.is_empty() { "none".to_string() }
                else { available.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ") }
            )
        })?
        .clone();

    // Verify connection
    let client = reqwest::blocking::Client::new();
    let block = rpc_call(&client, &net.rpc_url, "pyde_blockNumber", &[])?;
    println!("  Connected to {} ({})", network, net.rpc_url);
    println!("  Block: {}", block);
    println!("  From:  {}", from);
    println!("  Type 'help' for commands, 'exit' to quit");
    println!();

    let stdin = io::stdin();
    let mut nonce = get_nonce(&client, &net.rpc_url, from);

    loop {
        print!("pyde> ");
        io::stdout().flush().unwrap();

        let mut line = String::new();
        if stdin.lock().read_line(&mut line).is_err() || line.is_empty() {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match handle_command(&client, &net.rpc_url, from, signer, &net, &mut nonce, line) {
            Ok(true) => break, // exit
            Ok(false) => {}
            Err(e) => eprintln!("  error: {}", e),
        }
    }

    Ok(())
}

/// Returns true if should exit.
fn handle_command(
    client: &reqwest::blocking::Client,
    rpc_url: &str,
    from: &str,
    signer: &crate::signer::Signer,
    net: &crate::project::NetworkConfig,
    nonce: &mut u64,
    line: &str,
) -> Result<bool, String> {
    let parts: Vec<&str> = line.splitn(2, ' ').collect();
    let cmd = parts[0];
    let args = parts.get(1).map(|s| s.trim()).unwrap_or("");

    match cmd {
        "exit" | "quit" | "q" => return Ok(true),

        "help" => {
            println!("  call <address> <method>(<args>)   — read-only call");
            println!("  send <address> <method>(<args>)   — state-changing tx");
            println!("  balance <address>                  — query balance");
            println!("  nonce <address>                    — query nonce");
            println!("  code <address>                     — check deployed code");
            println!("  receipt <tx_hash>                  — get tx receipt");
            println!("  block                              — current block number");
            println!("  exit                               — quit console");
        }

        "block" => {
            let result = rpc_call(client, rpc_url, "pyde_blockNumber", &[])?;
            println!("  {}", result);
        }

        "balance" => {
            if args.is_empty() {
                return Err("usage: balance <address>".into());
            }
            let result = rpc_call(client, rpc_url, "pyde_getBalance", &[json_str(args)])?;
            println!("  {}", result);
        }

        "nonce" => {
            if args.is_empty() {
                return Err("usage: nonce <address>".into());
            }
            let result = rpc_call(client, rpc_url, "pyde_getTransactionCount", &[json_str(args)])?;
            println!("  {}", result);
        }

        "code" => {
            if args.is_empty() {
                return Err("usage: code <address>".into());
            }
            let result = rpc_call(client, rpc_url, "pyde_getCode", &[json_str(args)])?;
            let hex = result.as_str().unwrap_or("0x").trim_start_matches("0x");
            if hex.is_empty() {
                println!("  no code (EOA or empty)");
            } else {
                println!("  {} bytes deployed", hex.len() / 2);
            }
        }

        "receipt" => {
            if args.is_empty() {
                return Err("usage: receipt <tx_hash>".into());
            }
            let result = rpc_call(client, rpc_url, "pyde_getTransactionReceipt", &[json_str(args)])?;
            println!("  {}", serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()));
        }

        "call" => {
            let (addr, method, method_args) = parse_call_args(args)?;
            let selector = compute_selector(&method);
            let mut calldata = selector.to_be_bytes().to_vec();
            for arg in &method_args {
                calldata.extend_from_slice(&encode_arg(arg));
            }
            let calldata_hex = format!("0x{}", hex::encode(&calldata));

            let params = serde_json::json!({
                "from": from,
                "to": addr,
                "data": calldata_hex,
            });
            let result = rpc_call(client, rpc_url, "pyde_call", &[params])?;
            let hex = result.as_str().unwrap_or("0x0");
            // Try to parse as integer
            let hex_clean = hex.trim_start_matches("0x");
            if let Ok(val) = u128::from_str_radix(hex_clean, 16) {
                println!("  {} (0x{})", val, hex_clean);
            } else {
                println!("  {}", hex);
            }
        }

        "send" => {
            let (addr, method, method_args) = parse_call_args(args)?;
            let to = parse_hex_address(&addr)?;
            let selector = compute_selector(&method);
            let mut calldata = selector.to_be_bytes().to_vec();
            for arg in &method_args {
                calldata.extend_from_slice(&encode_arg(arg));
            }

            // Build, sign, and send transaction
            let mut tx = pyde_tx::types::Transaction {
                from: signer.address,
                to,
                value: 0,
                data: calldata,
                gas_limit: 100_000_000,
                nonce: *nonce,
                signature: vec![],
                fee_payer: pyde_tx::types::FeePayer::Sender,
                access_list: vec![],
                deadline: None,
                chain_id: net.chain_id,
                tx_type: pyde_tx::types::TransactionType::Standard,
            };
            signer.sign_transaction(&mut tx)?;
            let tx_hex = format!("0x{}", hex::encode(tx.to_bytes()));
            let result = rpc_call(client, rpc_url, "pyde_sendRawTransaction", &[serde_json::json!(tx_hex)])?;
            let tx_hash = result.as_str().unwrap_or("").to_string();
            println!("  tx: {} (signed ✓)", tx_hash);
            *nonce += 1;
        }

        _ => {
            return Err(format!("unknown command '{}'. Type 'help' for usage.", cmd));
        }
    }

    Ok(false)
}

/// Parse `<address> <method>(<arg1>, <arg2>)` into components.
fn parse_hex_address(s: &str) -> Result<[u8; 32], String> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex).map_err(|e| format!("invalid address hex: {}", e))?;
    if bytes.len() != 32 { return Err(format!("address must be 32 bytes, got {}", bytes.len())); }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

fn parse_call_args(input: &str) -> Result<(String, String, Vec<String>), String> {
    let parts: Vec<&str> = input.splitn(2, ' ').collect();
    if parts.len() < 2 {
        return Err("usage: call/send <address> <method>(<args>)".into());
    }
    let addr = parts[0].to_string();
    let rest = parts[1].trim();

    // Parse method(args)
    if let Some(paren_start) = rest.find('(') {
        let method = rest[..paren_start].trim().to_string();
        let args_str = rest[paren_start + 1..].trim_end_matches(')').trim();
        let args = if args_str.is_empty() {
            vec![]
        } else {
            args_str.split(',').map(|s| s.trim().to_string()).collect()
        };
        Ok((addr, method, args))
    } else {
        // No parens — method with no args
        Ok((addr, rest.trim().to_string(), vec![]))
    }
}

/// Encode a CLI argument as 8 bytes LE (u64).
fn encode_arg(arg: &str) -> Vec<u8> {
    let arg = arg.trim();
    // Try as integer
    if let Ok(val) = arg.parse::<u64>() {
        return val.to_le_bytes().to_vec();
    }
    // Try as hex
    if let Some(hex) = arg.strip_prefix("0x") {
        if let Ok(val) = u64::from_str_radix(hex, 16) {
            return val.to_le_bytes().to_vec();
        }
    }
    // Try as bool
    match arg {
        "true" => return 1u64.to_le_bytes().to_vec(),
        "false" => return 0u64.to_le_bytes().to_vec(),
        _ => {}
    }
    // Fallback: treat as string bytes (length-prefixed)
    let bytes = arg.trim_matches('"').as_bytes();
    let mut encoded = (bytes.len() as u64).to_le_bytes().to_vec();
    encoded.extend_from_slice(bytes);
    // Pad to 8-byte alignment
    while encoded.len() % 8 != 0 {
        encoded.push(0);
    }
    encoded
}

/// FNV-1a selector (same as codegen).
fn compute_selector(name: &str) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in name.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

fn get_nonce(client: &reqwest::blocking::Client, rpc_url: &str, address: &str) -> u64 {
    rpc_call(client, rpc_url, "pyde_getTransactionCount", &[json_str(address)])
        .ok()
        .and_then(|v| v.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0)
}

fn json_str(s: &str) -> serde_json::Value {
    serde_json::Value::String(s.to_string())
}

fn rpc_call(
    client: &reqwest::blocking::Client,
    rpc_url: &str,
    method: &str,
    params: &[serde_json::Value],
) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let resp = client
        .post(rpc_url)
        .json(&body)
        .send()
        .map_err(|e| format!("RPC error: {}", e))?;
    let json: serde_json::Value = resp
        .json()
        .map_err(|e| format!("invalid response: {}", e))?;
    if let Some(err) = json.get("error") {
        return Err(format!("{}", err));
    }
    Ok(json.get("result").cloned().unwrap_or(serde_json::Value::Null))
}

// ============================================================================
// One-shot CLI commands (used by main.rs dispatch)
// ============================================================================

/// `pyde-dev call <address> <function>(<args>) --network devnet`
pub fn cmd_call(address: &str, function: &str, network: &str) -> Result<(), String> {
    let (config, _) = crate::project::load_config()?;
    let net = config.networks.get(network)
        .ok_or_else(|| format!("network '{}' not found in pyde.toml", network))?;

    let (method, method_args) = parse_function(function)?;
    let selector = compute_selector(&method);
    let mut calldata = selector.to_be_bytes().to_vec();
    for arg in &method_args {
        calldata.extend_from_slice(&encode_arg(arg));
    }

    let client = reqwest::blocking::Client::new();
    let params = serde_json::json!({
        "from": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "to": address,
        "data": format!("0x{}", hex::encode(&calldata)),
    });
    let result = rpc_call(&client, &net.rpc_url, "pyde_call", &[params])?;
    let hex = result.as_str().unwrap_or("0x0");
    let hex_clean = hex.trim_start_matches("0x");
    if let Ok(val) = u128::from_str_radix(hex_clean, 16) {
        println!("  {}", val);
    } else {
        println!("  {}", hex);
    }
    Ok(())
}

/// `pyde-dev send <address> <function> --network devnet`
/// Signed state-changing transaction.
pub fn cmd_send(address: &str, function: &str, network: &str, signer: &crate::signer::Signer, value: u128) -> Result<(), String> {
    let (config, _) = crate::project::load_config()?;
    let net = config.networks.get(network)
        .ok_or_else(|| format!("network '{}' not found in pyde.toml", network))?;

    let to = parse_hex_address(address)?;
    let (method, method_args) = parse_function(function)?;
    let selector = compute_selector(&method);
    let mut calldata = selector.to_be_bytes().to_vec();
    for arg in &method_args {
        calldata.extend_from_slice(&encode_arg(arg));
    }

    // Get nonce
    let client = reqwest::blocking::Client::new();
    let nonce_result = rpc_call(&client, &net.rpc_url, "pyde_getTransactionCount", &[serde_json::json!(signer.address_hex())])?;
    let nonce: u64 = nonce_result.as_str().unwrap_or("0").parse().unwrap_or(0);

    // Build and sign
    let mut tx = pyde_tx::types::Transaction {
        from: signer.address,
        to,
        value,
        data: calldata,
        gas_limit: 100_000_000,
        nonce,
        signature: vec![],
        fee_payer: pyde_tx::types::FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id: net.chain_id,
        tx_type: pyde_tx::types::TransactionType::Standard,
    };
    signer.sign_transaction(&mut tx)?;

    // Send signed tx
    let tx_hex = format!("0x{}", hex::encode(tx.to_bytes()));
    let result = rpc_call(&client, &net.rpc_url, "pyde_sendRawTransaction", &[serde_json::json!(tx_hex)])?;
    let tx_hash = result.as_str().unwrap_or("").to_string();

    println!("  Tx Hash: {} (signed ✓)", tx_hash);
    println!("  From:    {}", signer.address_hex());
    println!("  To:      {}", address);
    println!("  Method:  {}", method);

    // Wait for receipt
    let receipt_body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "pyde_getTransactionReceipt",
        "params": [tx_hash]
    });
    for attempt in 0..50 {
        if attempt > 0 { std::thread::sleep(std::time::Duration::from_millis(100)); }
        let resp = client.post(&net.rpc_url).json(&receipt_body).send()
            .map_err(|e| format!("RPC error: {}", e))?;
        let json: serde_json::Value = resp.json().map_err(|e| format!("invalid response: {}", e))?;
        if let Some(result) = json.get("result") {
            if !result.is_null() {
                let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
                println!("  Success: {}", success);
                let gas = result.get("gasUsed").and_then(|v| v.as_str()).unwrap_or("0");
                println!("  Gas:     {}", gas);
                return if success { Ok(()) } else { Err("transaction reverted".into()) };
            }
        }
    }
    Err("receipt not available after 5s".into())
}

/// `pyde-dev tx <hash> --network devnet`
pub fn cmd_tx(hash: &str, network: &str) -> Result<(), String> {
    let (config, _) = crate::project::load_config()?;
    let net = config.networks.get(network)
        .ok_or_else(|| format!("network '{}' not found in pyde.toml", network))?;

    let client = reqwest::blocking::Client::new();
    let result = rpc_call(&client, &net.rpc_url, "pyde_getTransactionReceipt", &[json_str(hash)])?;

    if result.is_null() {
        println!("  Receipt not found (tx may be pending or invalid)");
    } else {
        let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
        let gas = result.get("gasUsed").and_then(|v| v.as_str()).unwrap_or("0");
        let return_data = result.get("returnData").and_then(|v| v.as_str()).unwrap_or("");

        println!("  Status:     {}", if success { "Success" } else { "Reverted" });
        println!("  Gas Used:   {}", gas);
        if !return_data.is_empty() && return_data != "0x" {
            println!("  Return:     {}", return_data);
        }
        let fee_paid = result.get("feePaid").and_then(|v| v.as_str()).unwrap_or("0");
        println!("  Fee Paid:   {} quanta", fee_paid);
    }
    Ok(())
}

/// Parse `method(arg1, arg2)` into (method, [args]).
fn parse_function(input: &str) -> Result<(String, Vec<String>), String> {
    if let Some(paren_start) = input.find('(') {
        let method = input[..paren_start].trim().to_string();
        let args_str = input[paren_start + 1..].trim_end_matches(')').trim();
        let args = if args_str.is_empty() {
            vec![]
        } else {
            args_str.split(',').map(|s| s.trim().to_string()).collect()
        };
        Ok((method, args))
    } else {
        Ok((input.trim().to_string(), vec![]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_call_with_args() {
        let (addr, method, args) = parse_call_args("0xaabb get_count()").unwrap();
        assert_eq!(addr, "0xaabb");
        assert_eq!(method, "get_count");
        assert!(args.is_empty());
    }

    #[test]
    fn parse_call_with_params() {
        let (addr, method, args) = parse_call_args("0xaabb deposit(500, 10)").unwrap();
        assert_eq!(addr, "0xaabb");
        assert_eq!(method, "deposit");
        assert_eq!(args, vec!["500", "10"]);
    }

    #[test]
    fn parse_call_no_parens() {
        let (addr, method, args) = parse_call_args("0xaabb get_count").unwrap();
        assert_eq!(addr, "0xaabb");
        assert_eq!(method, "get_count");
        assert!(args.is_empty());
    }

    #[test]
    fn encode_u64_arg() {
        assert_eq!(encode_arg("42"), 42u64.to_le_bytes().to_vec());
    }

    #[test]
    fn encode_bool_arg() {
        assert_eq!(encode_arg("true"), 1u64.to_le_bytes().to_vec());
        assert_eq!(encode_arg("false"), 0u64.to_le_bytes().to_vec());
    }

    #[test]
    fn selector_matches_codegen() {
        // Same FNV-1a as otic::codegen::compute_selector
        assert_eq!(compute_selector("get_count"), 0xd9e32bf7);
        assert_eq!(compute_selector("increment"), 0x3812e73e);
    }
}
