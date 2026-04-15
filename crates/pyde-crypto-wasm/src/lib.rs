use pyde_crypto::poseidon2::poseidon2_hash;
use wasm_bindgen::prelude::*;

// ============================================================================
// Key generation & address
// ============================================================================

/// Generate a FALCON-512 keypair.
/// Returns JSON: { "publicKey": "0x...", "secretKey": "0x...", "address": "0x..." }
#[wasm_bindgen(js_name = "generateKeypair")]
pub fn generate_keypair() -> Result<String, JsValue> {
    let (pk, sk) = pyde_crypto::falcon::falcon_keygen()
        .map_err(|e| JsValue::from_str(&format!("keygen failed: {}", e)))?;
    let address = poseidon2_hash(pk.as_bytes()).to_bytes();
    let result = serde_json::json!({
        "publicKey": format!("0x{}", hex::encode(pk.as_bytes())),
        "secretKey": format!("0x{}", hex::encode(sk.as_bytes())),
        "address": format!("0x{}", hex::encode(address)),
    });
    Ok(result.to_string())
}

/// Derive address from a FALCON-512 public key (hex).
/// address = Poseidon2(public_key_bytes)
#[wasm_bindgen(js_name = "deriveAddress")]
pub fn derive_address(pk_hex: &str) -> Result<String, JsValue> {
    let pk_bytes = decode_hex(pk_hex)?;
    let address = poseidon2_hash(&pk_bytes).to_bytes();
    Ok(format!("0x{}", hex::encode(address)))
}

// ============================================================================
// Signing & verification
// ============================================================================

/// Sign a message with a FALCON-512 secret key. Returns signature hex.
#[wasm_bindgen(js_name = "signMessage")]
pub fn sign_message(sk_hex: &str, message_hex: &str) -> Result<String, JsValue> {
    let sk_bytes = decode_hex(sk_hex)?;
    let msg_bytes = decode_hex(message_hex)?;
    let sk = pyde_crypto::falcon::FalconSecretKey::from_bytes(&sk_bytes)
        .ok_or_else(|| JsValue::from_str("invalid secret key"))?;
    let sig = pyde_crypto::falcon::falcon_sign(&sk, &msg_bytes)
        .map_err(|e| JsValue::from_str(&format!("sign failed: {}", e)))?;
    Ok(format!("0x{}", hex::encode(sig.as_bytes())))
}

/// Verify a FALCON-512 signature.
#[wasm_bindgen(js_name = "verifySignature")]
pub fn verify_signature(pk_hex: &str, message_hex: &str, sig_hex: &str) -> Result<bool, JsValue> {
    let pk_bytes = decode_hex(pk_hex)?;
    let msg_bytes = decode_hex(message_hex)?;
    let sig_bytes = decode_hex(sig_hex)?;
    let pk = pyde_crypto::falcon::FalconPublicKey::from_bytes(&pk_bytes)
        .ok_or_else(|| JsValue::from_str("invalid public key"))?;
    let sig = pyde_crypto::falcon::FalconSignature::from_bytes(&sig_bytes)
        .ok_or_else(|| JsValue::from_str("invalid signature"))?;
    Ok(pyde_crypto::falcon::falcon_verify(&pk, &msg_bytes, &sig))
}

// ============================================================================
// Hashing
// ============================================================================

/// Compute Poseidon2 hash of arbitrary bytes (hex).
#[wasm_bindgen(js_name = "poseidon2Hash")]
pub fn poseidon2_hash_wasm(data_hex: &str) -> Result<String, JsValue> {
    let data = decode_hex(data_hex)?;
    let hash = poseidon2_hash(&data);
    Ok(format!("0x{}", hex::encode(hash.to_bytes())))
}

/// Compute FNV-1a function selector (same as Otigen codegen).
#[wasm_bindgen(js_name = "computeSelector")]
pub fn compute_selector(name: &str) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in name.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

// ============================================================================
// Transaction hash & signing
// ============================================================================

/// Compute transaction hash from JSON fields.
/// Accepts: { from, to, value, data, gasLimit, nonce, chainId, txType }
/// Returns hash hex.
#[wasm_bindgen(js_name = "hashTransaction")]
pub fn hash_transaction(tx_json: &str) -> Result<String, JsValue> {
    let v: serde_json::Value = serde_json::from_str(tx_json)
        .map_err(|e| JsValue::from_str(&format!("bad JSON: {}", e)))?;
    let hash = compute_tx_hash(&v)?;
    Ok(format!("0x{}", hex::encode(hash)))
}

/// Sign a transaction. Returns the signed tx bytes as hex (wire format).
/// Accepts JSON tx fields + secretKey hex.
#[wasm_bindgen(js_name = "signTransaction")]
pub fn sign_transaction(tx_json: &str, sk_hex: &str) -> Result<String, JsValue> {
    let v: serde_json::Value = serde_json::from_str(tx_json)
        .map_err(|e| JsValue::from_str(&format!("bad JSON: {}", e)))?;

    let hash = compute_tx_hash(&v)?;

    let sk_bytes = decode_hex(sk_hex)?;
    let sk = pyde_crypto::falcon::FalconSecretKey::from_bytes(&sk_bytes)
        .ok_or_else(|| JsValue::from_str("invalid secret key"))?;
    let sig = pyde_crypto::falcon::falcon_sign(&sk, &hash)
        .map_err(|e| JsValue::from_str(&format!("sign failed: {}", e)))?;

    // Serialize transaction with signature
    let tx_bytes = serialize_tx(&v, sig.as_bytes())?;
    Ok(format!("0x{}", hex::encode(&tx_bytes)))
}

// ============================================================================
// Internal: tx hash (mirrors pyde_tx::types::Transaction::hash)
// ============================================================================

fn compute_tx_hash(v: &serde_json::Value) -> Result<[u8; 32], JsValue> {
    let from = parse_addr(v.get("from"))?;
    let to = parse_addr(v.get("to"))?;
    let value = parse_u128(v.get("value"));
    let data = parse_hex_bytes(v.get("data"));
    let gas_limit = v.get("gasLimit").and_then(|v| v.as_u64()).unwrap_or(21000);
    let nonce = v.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0);
    let chain_id = v.get("chainId").and_then(|v| v.as_u64()).unwrap_or(31337);
    let tx_type = v.get("txType").and_then(|v| v.as_u64()).unwrap_or(0) as u8;

    // Same hash algorithm as Transaction::hash() in pyde-tx
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(&chain_id.to_le_bytes());
    buf.extend_from_slice(&from);
    buf.extend_from_slice(&to);
    buf.extend_from_slice(&value.to_le_bytes());
    buf.extend_from_slice(&poseidon2_hash(&data).to_bytes());
    buf.extend_from_slice(&gas_limit.to_le_bytes());
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.push(0); // fee_payer tag: Sender
    buf.extend_from_slice(&hash_empty_access_list());
    // deadline: None → single 0 byte (matches Transaction::hash)
    buf.push(0);
    buf.push(tx_type);

    Ok(poseidon2_hash(&buf).to_bytes())
}

fn hash_empty_access_list() -> [u8; 32] {
    poseidon2_hash(&[]).to_bytes()
}

// ============================================================================
// Internal: tx serialization (mirrors Transaction::to_bytes)
// ============================================================================

fn serialize_tx(v: &serde_json::Value, signature: &[u8]) -> Result<Vec<u8>, JsValue> {
    let from = parse_addr(v.get("from"))?;
    let to = parse_addr(v.get("to"))?;
    let value = parse_u128(v.get("value"));
    let data = parse_hex_bytes(v.get("data"));
    let gas_limit = v.get("gasLimit").and_then(|v| v.as_u64()).unwrap_or(21000);
    let nonce = v.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0);
    let chain_id = v.get("chainId").and_then(|v| v.as_u64()).unwrap_or(31337);
    let tx_type = v.get("txType").and_then(|v| v.as_u64()).unwrap_or(0) as u8;

    let mut buf = Vec::new();
    buf.extend_from_slice(&from);                              // 32
    buf.extend_from_slice(&to);                                // 32
    buf.extend_from_slice(&value.to_le_bytes());               // 16
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes()); // 4
    buf.extend_from_slice(&data);                              // var
    buf.extend_from_slice(&gas_limit.to_le_bytes());           // 8
    buf.extend_from_slice(&nonce.to_le_bytes());               // 8
    buf.extend_from_slice(&(signature.len() as u16).to_le_bytes()); // 2
    buf.extend_from_slice(signature);                          // ~666
    buf.push(1); // fee_payer bytes len
    buf.push(0); // FeePayer::Sender tag
    // access_list: byte length of serialized data (4 bytes for the empty count prefix)
    buf.extend_from_slice(&4u32.to_le_bytes());               // access_list byte len = 4
    buf.extend_from_slice(&0u32.to_le_bytes());               // entry count = 0
    buf.push(0); // no deadline
    buf.extend_from_slice(&chain_id.to_le_bytes());           // 8
    buf.push(tx_type);                                         // 1
    Ok(buf)
}

// ============================================================================
// Hex helpers
// ============================================================================

fn decode_hex(s: &str) -> Result<Vec<u8>, JsValue> {
    hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| JsValue::from_str(&format!("bad hex: {}", e)))
}

fn parse_addr(val: Option<&serde_json::Value>) -> Result<[u8; 32], JsValue> {
    let s = val.and_then(|v| v.as_str()).unwrap_or(
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    let bytes = decode_hex(s)?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str(&format!("address must be 32 bytes, got {}", bytes.len())));
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

fn parse_u128(val: Option<&serde_json::Value>) -> u128 {
    val.and_then(|v| {
        v.as_u64().map(|n| n as u128)
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    }).unwrap_or(0)
}

fn parse_hex_bytes(val: Option<&serde_json::Value>) -> Vec<u8> {
    val.and_then(|v| v.as_str())
        .map(|s| hex::decode(s.trim_start_matches("0x")).unwrap_or_default())
        .unwrap_or_default()
}
