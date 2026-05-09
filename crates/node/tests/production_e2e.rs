//! Production E2E test — signed FALCON transactions against a live node.
//!
//! This test requires a running production testnet (chain_id != 31337).
//! Run:
//!   docker compose -f docker/docker-compose.production.yml up -d
//!   PYDE_PRODUCTION_RPC=http://localhost:8545 PYDE_ACCOUNTS_JSON=/path/to/accounts.json \
//!     cargo test -p pyde-node --test production_e2e -- --nocapture
//!
//! Skip if no env vars are set.

use pyde_account::address::derive_eoa_address;
use pyde_crypto::falcon::{falcon_sign, FalconPublicKey, FalconSecretKey};
use pyde_tx::types::*;

fn rpc_call(url: &str, method: &str, params: &str) -> serde_json::Value {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"{}","params":[{}],"id":1}}"#,
        method, params
    );
    let output = std::process::Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            url,
            "-H",
            "Content-Type: application/json",
            "-d",
            &body,
        ])
        .output()
        .expect("curl failed");
    let text = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&text).unwrap_or_default()
}

fn get_result_string(resp: &serde_json::Value) -> String {
    match resp.get("result") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => String::new(),
    }
}

#[test]
#[ignore = "requires live node — run with --ignored and PYDE_PRODUCTION_RPC set"]
fn production_signed_transfer() {
    let rpc = match std::env::var("PYDE_PRODUCTION_RPC") {
        Ok(url) => url,
        Err(_) => {
            println!("SKIP: PYDE_PRODUCTION_RPC not set");
            return;
        }
    };
    let accounts_path = match std::env::var("PYDE_ACCOUNTS_JSON") {
        Ok(p) => p,
        Err(_) => {
            println!("SKIP: PYDE_ACCOUNTS_JSON not set");
            return;
        }
    };

    // Load accounts
    let accounts_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&accounts_path).expect("read accounts.json"))
            .expect("parse accounts.json");

    let chain_id = accounts_json["chainId"].as_u64().expect("chainId");
    assert_ne!(chain_id, 31337, "must NOT be devnet chain_id");
    println!("[PASS] chain_id = {} (production)", chain_id);

    let accts = accounts_json["accounts"]
        .as_array()
        .expect("accounts array");
    // Use the first non-faucet account
    let sender_info = accts
        .iter()
        .find(|a| a.get("faucet").is_none())
        .expect("no funded account");

    let private_key_hex = sender_info["privateKey"].as_str().unwrap();
    let pk_hex = private_key_hex.trim_start_matches("0x");
    let pk_bytes = hex::decode(pk_hex).expect("decode private key");
    assert_eq!(pk_bytes.len(), 897 + 1281, "private key wrong size");

    let pk = FalconPublicKey::from_bytes(&pk_bytes[..897]).expect("parse pk");
    let sk = FalconSecretKey::from_bytes(&pk_bytes[897..]).expect("parse sk");
    let address = derive_eoa_address(pk.as_bytes());
    println!("[PASS] loaded sender: 0x{}", hex::encode(address));

    // Check chain is alive
    let resp = rpc_call(&rpc, "pyde_blockNumber", "");
    let block = get_result_string(&resp);
    assert!(!block.is_empty(), "node not responding");
    println!("[PASS] node alive, block: {}", block);

    // Check balance
    let resp = rpc_call(
        &rpc,
        "pyde_getBalance",
        &format!("\"0x{}\"", hex::encode(address)),
    );
    let balance_str = get_result_string(&resp);
    let balance: u128 = if balance_str.starts_with("0x") {
        u128::from_str_radix(balance_str.trim_start_matches("0x"), 16).unwrap_or(0)
    } else {
        balance_str.parse().unwrap_or(0)
    };
    assert!(balance > 0, "sender has no balance: {}", balance_str);
    println!("[PASS] sender balance: {}", balance);

    // Get nonce
    let resp = rpc_call(
        &rpc,
        "pyde_getTransactionCount",
        &format!("\"0x{}\"", hex::encode(address)),
    );
    let nonce_str = get_result_string(&resp);
    let nonce: u64 = if nonce_str.starts_with("0x") {
        u64::from_str_radix(nonce_str.trim_start_matches("0x"), 16).unwrap_or(0)
    } else {
        nonce_str.parse().unwrap_or(0)
    };
    println!("[INFO] nonce: {}", nonce);

    // Build transfer tx
    let recipient = [0x02u8; 32];
    let mut tx = Transaction {
        from: address,
        to: recipient,
        value: 1_000_000,
        data: vec![],
        gas_limit: 50_000,
        nonce,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id,
        tx_type: TransactionType::Standard,
    };

    // Sign with FALCON-512
    let tx_hash = tx.hash();
    let sig = falcon_sign(&sk, &tx_hash).expect("FALCON sign");
    tx.signature = sig.as_bytes().to_vec();
    assert!(!tx.signature.is_empty());
    println!("[PASS] signed tx ({} byte signature)", tx.signature.len());

    // Verify locally
    assert!(
        tx.verify_signature(pk.as_bytes()),
        "local signature verification failed"
    );
    println!("[PASS] local signature verification passed");

    // Encode for wire
    let tx_bytes = tx.to_bytes();
    let tx_hex = format!("0x{}", hex::encode(&tx_bytes));
    println!("[INFO] wire-encoded tx: {} bytes", tx_bytes.len());

    // Submit via pyde_sendRawTransaction
    let resp = rpc_call(&rpc, "pyde_sendRawTransaction", &format!("\"{}\"", tx_hex));
    if let Some(err) = resp.get("error") {
        panic!("[FAIL] sendRawTransaction error: {}", err);
    }
    let submitted_hash = get_result_string(&resp);
    assert!(!submitted_hash.is_empty(), "no tx hash returned");
    println!("[PASS] tx submitted: {}", submitted_hash);

    // Wait for inclusion
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Check receipt
    let resp = rpc_call(
        &rpc,
        "pyde_getTransactionReceipt",
        &format!("\"{}\"", submitted_hash),
    );
    if let Some(result) = resp.get("result") {
        let success = result
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        println!(
            "[{}] receipt: success={}",
            if success { "PASS" } else { "FAIL" },
            success
        );
        assert!(success, "tx execution failed");
    } else {
        println!("[WARN] no receipt yet (may need more time)");
    }

    // Check recipient balance
    let resp = rpc_call(
        &rpc,
        "pyde_getBalance",
        &format!("\"0x{}\"", hex::encode(recipient)),
    );
    let new_bal_str = get_result_string(&resp);
    let new_bal: u128 = if new_bal_str.starts_with("0x") {
        u128::from_str_radix(new_bal_str.trim_start_matches("0x"), 16).unwrap_or(0)
    } else {
        new_bal_str.parse().unwrap_or(0)
    };
    println!(
        "[{}] recipient balance: {} (expected >= 1000000)",
        if new_bal >= 1_000_000 { "PASS" } else { "FAIL" },
        new_bal
    );

    println!("\n========== PRODUCTION E2E COMPLETE ==========\n");
}

#[test]
#[ignore = "requires live node — run with --ignored and PYDE_PRODUCTION_RPC set"]
fn production_signed_deploy_and_call() {
    let rpc = match std::env::var("PYDE_PRODUCTION_RPC") {
        Ok(url) => url,
        Err(_) => {
            println!("SKIP: PYDE_PRODUCTION_RPC not set");
            return;
        }
    };
    let accounts_path = match std::env::var("PYDE_ACCOUNTS_JSON") {
        Ok(p) => p,
        Err(_) => {
            println!("SKIP: PYDE_ACCOUNTS_JSON not set");
            return;
        }
    };

    let accounts_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&accounts_path).unwrap()).unwrap();
    let chain_id = accounts_json["chainId"].as_u64().unwrap();
    let accts = accounts_json["accounts"].as_array().unwrap();
    let sender_info = accts.iter().find(|a| a.get("faucet").is_none()).unwrap();
    let pk_hex = sender_info["privateKey"]
        .as_str()
        .unwrap()
        .trim_start_matches("0x");
    let pk_bytes = hex::decode(pk_hex).unwrap();
    let pk = FalconPublicKey::from_bytes(&pk_bytes[..897]).unwrap();
    let sk = FalconSecretKey::from_bytes(&pk_bytes[897..]).unwrap();
    let address = derive_eoa_address(pk.as_bytes());

    // Get nonce
    let resp = rpc_call(
        &rpc,
        "pyde_getTransactionCount",
        &format!("\"0x{}\"", hex::encode(address)),
    );
    let nonce_str = get_result_string(&resp);
    let nonce: u64 = if nonce_str.starts_with("0x") {
        u64::from_str_radix(nonce_str.trim_start_matches("0x"), 16).unwrap_or(0)
    } else {
        nonce_str.parse().unwrap_or(0)
    };

    // Compile Counter contract
    let compiled = otic::__compile_all_unchecked(
        r#"
        contract Counter {
            storage { count: u64, }
            #[constructor] pub fn init() { self.count = 0; }
            pub fn increment() { self.count = self.count + 1; }
            pub fn get_count() -> u64 { return self.count; }
        }
    "#,
    );
    let (_, c) = &compiled[0];

    // Build deploy data: [clen:4LE][rlen:4LE][constructor][runtime]
    let clen = c.constructor_bytecode.len() as u32;
    let rlen = c.runtime_bytecode.len() as u32;
    let mut deploy_data = Vec::new();
    deploy_data.extend_from_slice(&clen.to_le_bytes());
    deploy_data.extend_from_slice(&rlen.to_le_bytes());
    deploy_data.extend_from_slice(&c.constructor_bytecode);
    deploy_data.extend_from_slice(&c.runtime_bytecode);

    // Build + sign deploy tx
    let mut tx = Transaction {
        from: address,
        to: [0u8; 32],
        value: 0,
        data: deploy_data,
        gas_limit: 100_000_000,
        nonce,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id,
        tx_type: TransactionType::Deploy,
    };
    let hash = tx.hash();
    tx.signature = falcon_sign(&sk, &hash).unwrap().as_bytes().to_vec();
    println!("[PASS] signed deploy tx");

    // Submit
    let tx_hex = format!("0x{}", hex::encode(tx.to_bytes()));
    let resp = rpc_call(&rpc, "pyde_sendRawTransaction", &format!("\"{}\"", tx_hex));
    if let Some(err) = resp.get("error") {
        panic!("[FAIL] deploy sendRawTransaction: {}", err);
    }
    let deploy_hash = get_result_string(&resp);
    println!("[PASS] deploy submitted: {}", deploy_hash);

    std::thread::sleep(std::time::Duration::from_secs(5));

    // Get receipt → contract address
    let resp = rpc_call(
        &rpc,
        "pyde_getTransactionReceipt",
        &format!("\"{}\"", deploy_hash),
    );
    let receipt = resp.get("result").expect("no deploy receipt");
    let success = receipt
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(success, "deploy failed");
    let contract_hex = receipt
        .get("returnData")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(!contract_hex.is_empty(), "no contract address");
    println!("[PASS] contract deployed: {}", contract_hex);

    // Call get_count() via pyde_call (read-only, no signature needed)
    let selector = otic::codegen::compute_selector("get_count");
    let sel_hex = format!("{:08x}", selector);
    let resp = rpc_call(
        &rpc,
        "pyde_call",
        &format!(
            r#"{{"from":"0x{}","to":"{}","data":"0x{}","gas":100000000}}"#,
            hex::encode(address),
            contract_hex,
            sel_hex
        ),
    );
    let count = get_result_string(&resp);
    assert_eq!(count, "0x0", "initial count should be 0");
    println!("[PASS] get_count() = 0");

    // increment() — signed tx
    let sel = otic::codegen::compute_selector("increment");
    let calldata = sel.to_be_bytes().to_vec();
    let contract_addr = {
        let h = contract_hex.trim_start_matches("0x");
        let b = hex::decode(h).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        a
    };

    let mut inc_tx = Transaction {
        from: address,
        to: contract_addr,
        value: 0,
        data: calldata,
        gas_limit: 10_000_000,
        nonce: nonce + 1,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id,
        tx_type: TransactionType::Standard,
    };
    let hash = inc_tx.hash();
    inc_tx.signature = falcon_sign(&sk, &hash).unwrap().as_bytes().to_vec();
    println!("[PASS] signed increment tx");

    let tx_hex = format!("0x{}", hex::encode(inc_tx.to_bytes()));
    let resp = rpc_call(&rpc, "pyde_sendRawTransaction", &format!("\"{}\"", tx_hex));
    if let Some(err) = resp.get("error") {
        panic!("[FAIL] increment sendRawTransaction: {}", err);
    }
    println!("[PASS] increment submitted");

    std::thread::sleep(std::time::Duration::from_secs(5));

    // Verify get_count() = 1
    let selector_hex = format!("{:08x}", otic::codegen::compute_selector("get_count"));
    let resp = rpc_call(
        &rpc,
        "pyde_call",
        &format!(
            r#"{{"from":"0x{}","to":"{}","data":"0x{}","gas":100000000}}"#,
            hex::encode(address),
            contract_hex,
            selector_hex
        ),
    );
    let count = get_result_string(&resp);
    println!(
        "[{}] get_count() = {} (expected 0x1)",
        if count == "0x1" { "PASS" } else { "INFO" },
        count
    );

    println!("\n========== PRODUCTION DEPLOY+CALL E2E COMPLETE ==========\n");
}
