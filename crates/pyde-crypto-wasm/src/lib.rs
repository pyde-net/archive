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
    // Fields: chain_id(8) + from(32) + to(32) + value(16) + data_hash(32) +
    //         gas_limit(8) + nonce(8) + fee_payer(1) + access_hash(32) +
    //         deadline(1-9) + tx_type(1) = 171-179 bytes
    let mut buf = Vec::with_capacity(180);
    buf.extend_from_slice(&chain_id.to_le_bytes());
    buf.extend_from_slice(&from);
    buf.extend_from_slice(&to);
    buf.extend_from_slice(&value.to_le_bytes());
    buf.extend_from_slice(&poseidon2_hash(&data).to_bytes());
    buf.extend_from_slice(&gas_limit.to_le_bytes());
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.push(0); // fee_payer tag: Sender
    buf.extend_from_slice(&hash_access_list(v));
    // deadline: None → single 0 byte (matches Transaction::hash)
    buf.push(0);
    buf.push(tx_type);

    Ok(poseidon2_hash(&buf).to_bytes())
}

fn hash_access_list(v: &serde_json::Value) -> [u8; 32] {
    let entries = match v.get("accessList").and_then(|a| a.as_array()) {
        Some(arr) if !arr.is_empty() => arr,
        _ => return poseidon2_hash(&[]).to_bytes(), // empty = hash of empty bytes
    };
    // Must match Rust's hash_access_list format: NO count prefix, just entries
    let serialized = hash_serialize_access_list(entries);
    poseidon2_hash(&serialized).to_bytes()
}

/// Serialize for wire encoding (WITH count prefix — matches Rust serialize_access_list)
fn serialize_access_list_entries(entries: &[serde_json::Value]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        serialize_one_access_entry(entry, &mut buf);
    }
    buf
}

/// Serialize for HASHING (NO count prefix — matches Rust hash_access_list)
fn hash_serialize_access_list(entries: &[serde_json::Value]) -> Vec<u8> {
    let mut buf = Vec::new();
    for entry in entries {
        serialize_one_access_entry(entry, &mut buf);
    }
    buf
}

fn serialize_one_access_entry(entry: &serde_json::Value, buf: &mut Vec<u8>) {
    let addr = entry
        .get("address")
        .and_then(|v| v.as_str())
        .map(|s| decode_hex(s).unwrap_or_default())
        .unwrap_or_default();
    let mut addr32 = [0u8; 32];
    if addr.len() == 32 {
        addr32.copy_from_slice(&addr);
    }
    buf.extend_from_slice(&addr32);

    let parse_keys = |field: &str| -> Vec<[u8; 32]> {
        entry
            .get(field)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|k| {
                        let b = decode_hex(k.as_str().unwrap_or("")).unwrap_or_default();
                        if b.len() == 32 {
                            let mut k32 = [0u8; 32];
                            k32.copy_from_slice(&b);
                            Some(k32)
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    let reads = parse_keys("reads");
    buf.extend_from_slice(&(reads.len() as u32).to_le_bytes());
    for k in &reads {
        buf.extend_from_slice(k);
    }

    let writes = parse_keys("writes");
    buf.extend_from_slice(&(writes.len() as u32).to_le_bytes());
    for k in &writes {
        buf.extend_from_slice(k);
    }
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
    buf.extend_from_slice(&from); // 32
    buf.extend_from_slice(&to); // 32
    buf.extend_from_slice(&value.to_le_bytes()); // 16
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes()); // 4
    buf.extend_from_slice(&data); // var
    buf.extend_from_slice(&gas_limit.to_le_bytes()); // 8
    buf.extend_from_slice(&nonce.to_le_bytes()); // 8
    buf.extend_from_slice(&(signature.len() as u16).to_le_bytes()); // 2
    buf.extend_from_slice(signature); // ~666
    buf.push(1); // fee_payer bytes len
    buf.push(0); // FeePayer::Sender tag
                 // access_list serialization
    let al_entries = v.get("accessList").and_then(|a| a.as_array());
    let al_bytes = match al_entries {
        Some(entries) if !entries.is_empty() => serialize_access_list_entries(entries),
        _ => {
            let mut b = Vec::new();
            b.extend_from_slice(&0u32.to_le_bytes());
            b
        }
    };
    buf.extend_from_slice(&(al_bytes.len() as u32).to_le_bytes()); // byte len prefix
    buf.extend_from_slice(&al_bytes);
    buf.push(0); // no deadline
    buf.extend_from_slice(&chain_id.to_le_bytes()); // 8
    buf.push(tx_type); // 1
    Ok(buf)
}

// ============================================================================
// Threshold encryption (MEV-protected tx flow)
// ============================================================================

/// Threshold-encrypt a payload against the committee's public key.
/// `pk_hex` is the hex-encoded wire bytes from
/// `pyde_getThresholdPublicKey`. `payload_hex` is the bytes to
/// encrypt — typically `to (32) || value_le (16) || calldata`.
///
/// Returns hex of `ThresholdCiphertext::to_wire_bytes()` ready to
/// embed in an `EncryptedTx`.
#[wasm_bindgen(js_name = "thresholdEncrypt")]
pub fn threshold_encrypt_wasm(pk_hex: &str, payload_hex: &str) -> Result<String, JsValue> {
    let pk_bytes = decode_hex(pk_hex)?;
    let pk = pyde_crypto::threshold::ThresholdPublicKey::from_bytes(&pk_bytes)
        .ok_or_else(|| JsValue::from_str("invalid threshold public key"))?;
    let payload = decode_hex(payload_hex)?;
    let ct = pyde_crypto::threshold::threshold_encrypt(&pk, &payload)
        .map_err(|e| JsValue::from_str(&format!("threshold encryption failed: {}", e)))?;
    Ok(format!("0x{}", hex::encode(ct.to_wire_bytes())))
}

/// One-shot client-side EncryptedTx builder. Does everything a
/// wallet needs for the MEV-protected flow in a single call:
///
///   1. Threshold-encrypt `(to || value_le || calldata)` with the
///      committee pubkey.
///   2. Assemble the EncryptedTx wire frame with `signature = []`.
///   3. Compute `EncryptedTx::hash` (same formula the node uses).
///   4. FALCON-sign the hash with the sender's secret key.
///   5. Serialize the full wire frame.
///
/// `params_json` shape (all strings are `0x`-prefixed hex unless
/// noted):
/// ```ignore
/// {
///   "thresholdPk": "0x...",          // wire bytes from pyde_getThresholdPublicKey
///   "sender": "0x...",               // 32-byte address
///   "nonce": 0,                      // u64
///   "gasLimit": 100000,              // u64
///   "accessList": [                  // optional
///     { "address": "0x...",
///       "reads":  ["0x..."],
///       "writes": ["0x..."] }
///   ],
///   "deadline": null,                // optional u64
///   "chainId": 31337,                // u64
///   "to": "0x...",                   // 32-byte address
///   "value": "1000",                 // u128 decimal string
///   "calldata": "0x..."              // hex bytes
/// }
/// ```
///
/// Returns hex of the wire-encoded EncryptedTx, ready to submit via
/// `pyde_sendRawEncryptedTransaction`.
#[wasm_bindgen(js_name = "buildRawEncryptedTx")]
pub fn build_raw_encrypted_tx_wasm(params_json: &str, sk_hex: &str) -> Result<String, JsValue> {
    let v: serde_json::Value = serde_json::from_str(params_json)
        .map_err(|e| JsValue::from_str(&format!("bad JSON: {}", e)))?;

    // Parse fields.
    let tpk_bytes = decode_hex(
        v.get("thresholdPk")
            .and_then(|x| x.as_str())
            .ok_or_else(|| JsValue::from_str("missing thresholdPk"))?,
    )?;
    let tpk = pyde_crypto::threshold::ThresholdPublicKey::from_bytes(&tpk_bytes)
        .ok_or_else(|| JsValue::from_str("invalid threshold public key"))?;

    let sender = parse_addr(v.get("sender"))?;
    let nonce = v.get("nonce").and_then(|x| x.as_u64()).unwrap_or(0);
    let gas_limit = v
        .get("gasLimit")
        .and_then(|x| x.as_u64())
        .unwrap_or(100_000);
    let chain_id = v.get("chainId").and_then(|x| x.as_u64()).unwrap_or(31337);
    let deadline = v.get("deadline").and_then(|x| x.as_u64());
    let to = parse_addr(v.get("to"))?;
    let value = parse_u128(v.get("value"));
    let calldata = parse_hex_bytes(v.get("data").or_else(|| v.get("calldata")));

    // Encrypt (to || value_le || calldata) — same layout as Rust's
    // encrypt_transaction.
    let mut payload = Vec::with_capacity(48 + calldata.len());
    payload.extend_from_slice(&to);
    payload.extend_from_slice(&value.to_le_bytes());
    payload.extend_from_slice(&calldata);
    let ct = pyde_crypto::threshold::threshold_encrypt(&tpk, &payload)
        .map_err(|e| JsValue::from_str(&format!("threshold encryption failed: {}", e)))?;
    let ct_wire_bytes = ct.to_wire_bytes();

    // Access list — empty by default.
    let access_entries = v
        .get("accessList")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();

    // Compute EncryptedTx::hash — MUST match
    // `pyde-mempool::encrypted::EncryptedTx::hash`:
    //   poseidon2(sender || nonce_le || gas_le || chain_le || ct_hash)
    // where ct_hash = poseidon2(ciphertext::to_bytes()).
    let ct_for_hash = ct.to_bytes(); // no length prefixes — matches Rust
    let ct_hash = poseidon2_hash(&ct_for_hash);
    let mut hash_buf = Vec::with_capacity(32 + 8 + 8 + 8 + 32);
    hash_buf.extend_from_slice(&sender);
    hash_buf.extend_from_slice(&nonce.to_le_bytes());
    hash_buf.extend_from_slice(&gas_limit.to_le_bytes());
    hash_buf.extend_from_slice(&chain_id.to_le_bytes());
    hash_buf.extend_from_slice(&ct_hash.to_bytes());
    let enc_tx_hash = poseidon2_hash(&hash_buf).to_bytes();

    // FALCON-sign the hash.
    let sk_bytes = decode_hex(sk_hex)?;
    let sk = pyde_crypto::falcon::FalconSecretKey::from_bytes(&sk_bytes)
        .ok_or_else(|| JsValue::from_str("invalid secret key"))?;
    let sig = pyde_crypto::falcon::falcon_sign(&sk, &enc_tx_hash)
        .map_err(|e| JsValue::from_str(&format!("sign failed: {}", e)))?;
    let signature = sig.as_bytes().to_vec();

    // Serialize wire bytes. MUST match
    // `pyde-mempool::encrypted::EncryptedTx::to_bytes`.
    let mut buf = Vec::new();
    buf.extend_from_slice(&sender);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(&gas_limit.to_le_bytes());
    buf.extend_from_slice(&chain_id.to_le_bytes());
    buf.push(deadline.is_some() as u8);
    if let Some(d) = deadline {
        buf.extend_from_slice(&d.to_le_bytes());
    }
    // Access list (u32 count + entries).
    buf.extend_from_slice(&(access_entries.len() as u32).to_le_bytes());
    for entry in &access_entries {
        serialize_encrypted_tx_access_entry(entry, &mut buf)?;
    }
    // Signature (u32 len + bytes).
    buf.extend_from_slice(&(signature.len() as u32).to_le_bytes());
    buf.extend_from_slice(&signature);
    // Ciphertext (u32 len + wire bytes).
    buf.extend_from_slice(&(ct_wire_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&ct_wire_bytes);

    Ok(format!("0x{}", hex::encode(&buf)))
}

/// Serialize one access-list entry for an EncryptedTx. Layout mirrors
/// `pyde-mempool::encrypted::EncryptedTx::to_bytes` which uses u16
/// read/write counts (distinct from the Transaction wire format which
/// uses u32 here).
fn serialize_encrypted_tx_access_entry(
    entry: &serde_json::Value,
    buf: &mut Vec<u8>,
) -> Result<(), JsValue> {
    let addr_bytes = parse_addr(entry.get("address"))?;
    buf.extend_from_slice(&addr_bytes);

    let parse_keys = |field: &str| -> Result<Vec<[u8; 32]>, JsValue> {
        let arr = entry
            .get(field)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::with_capacity(arr.len());
        for k in arr {
            let s = k
                .as_str()
                .ok_or_else(|| JsValue::from_str("access list key must be string"))?;
            let b = decode_hex(s)?;
            if b.len() != 32 {
                return Err(JsValue::from_str("access list key must be 32 bytes"));
            }
            let mut k32 = [0u8; 32];
            k32.copy_from_slice(&b);
            out.push(k32);
        }
        Ok(out)
    };

    let reads = parse_keys("reads")?;
    buf.extend_from_slice(&(reads.len() as u16).to_le_bytes());
    for r in &reads {
        buf.extend_from_slice(r);
    }
    let writes = parse_keys("writes")?;
    buf.extend_from_slice(&(writes.len() as u16).to_le_bytes());
    for w in &writes {
        buf.extend_from_slice(w);
    }
    Ok(())
}

// ============================================================================
// Hex helpers
// ============================================================================

fn decode_hex(s: &str) -> Result<Vec<u8>, JsValue> {
    hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| JsValue::from_str(&format!("bad hex: {}", e)))
}

fn parse_addr(val: Option<&serde_json::Value>) -> Result<[u8; 32], JsValue> {
    let s = val
        .and_then(|v| v.as_str())
        .unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000");
    let bytes = decode_hex(s)?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "address must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

fn parse_u128(val: Option<&serde_json::Value>) -> u128 {
    val.and_then(|v| {
        v.as_u64()
            .map(|n| n as u128)
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    })
    .unwrap_or(0)
}

fn parse_hex_bytes(val: Option<&serde_json::Value>) -> Vec<u8> {
    val.and_then(|v| v.as_str())
        .map(|s| hex::decode(s.trim_start_matches("0x")).unwrap_or_default())
        .unwrap_or_default()
}

// ============================================================================
// Tests — format parity against the production EncryptedTx decoder.
// ============================================================================
//
// These run only on the native target (not in the wasm bundle). The
// assertion is: wire bytes produced by our inlined WASM builder must
// decode cleanly with `pyde-mempool`'s real `EncryptedTx::from_bytes`,
// with every field intact. This catches silent format drift between
// WASM and the node.
#[cfg(test)]
mod tests {
    use super::*;
    use pyde_crypto::falcon::{falcon_keygen, falcon_verify, FalconPublicKey, FalconSignature};
    use pyde_crypto::threshold::threshold_keygen;

    #[test]
    fn build_raw_encrypted_tx_decodes_with_production_decoder() {
        let (tpk, _shares) = threshold_keygen(4, 3).unwrap();
        let (pk, sk) = falcon_keygen().unwrap();
        let sender = poseidon2_hash(pk.as_bytes()).to_bytes();
        let to = [0xBBu8; 32];

        let params = serde_json::json!({
            "thresholdPk": format!("0x{}", hex::encode(tpk.to_bytes())),
            "sender":      format!("0x{}", hex::encode(sender)),
            "nonce":       7u64,
            "gasLimit":    42_000u64,
            "chainId":     31337u64,
            "deadline":    1000u64,
            "to":          format!("0x{}", hex::encode(to)),
            "value":       "99",
            "calldata":    format!("0x{}", hex::encode(b"hello encrypted")),
        });
        let sk_hex = format!("0x{}", hex::encode(sk.as_bytes()));

        let wire_hex = build_raw_encrypted_tx_wasm(&params.to_string(), &sk_hex).unwrap();
        let wire_bytes = hex::decode(wire_hex.trim_start_matches("0x")).unwrap();

        // Decode with the REAL decoder from pyde-mempool. If this
        // succeeds and every field matches, the WASM wire format
        // is byte-compatible with the node.
        let decoded = pyde_mempool::encrypted::EncryptedTx::from_bytes(&wire_bytes)
            .expect("production decoder must accept WASM-built bytes");

        assert_eq!(decoded.sender, sender);
        assert_eq!(decoded.nonce, 7);
        assert_eq!(decoded.gas_limit, 42_000);
        assert_eq!(decoded.chain_id, 31337);
        assert_eq!(decoded.deadline, Some(1000));
        assert!(
            !decoded.signature.is_empty(),
            "signature must be populated after build"
        );
        // FALCON verify against the sender's pubkey — exact check
        // the server's `receive_tx_verified` runs.
        let falcon_pk = FalconPublicKey::from_bytes(pk.as_bytes()).unwrap();
        let sig_obj = FalconSignature::from_bytes(&decoded.signature).unwrap();
        assert!(
            falcon_verify(&falcon_pk, &decoded.hash(), &sig_obj),
            "signature produced by WASM must verify against sender pubkey"
        );
    }

    #[test]
    fn threshold_encrypt_primitive_roundtrips() {
        // Encrypt via WASM primitive, decode via real
        // ThresholdCiphertext::from_wire_bytes.
        let (tpk, _) = threshold_keygen(4, 3).unwrap();
        let payload = b"plaintext for primitive test";

        let ct_hex = threshold_encrypt_wasm(
            &format!("0x{}", hex::encode(tpk.to_bytes())),
            &format!("0x{}", hex::encode(payload)),
        )
        .unwrap();
        let ct_bytes = hex::decode(ct_hex.trim_start_matches("0x")).unwrap();

        let decoded = pyde_crypto::threshold::ThresholdCiphertext::from_wire_bytes(&ct_bytes)
            .expect("real decoder must accept WASM threshold_encrypt output");
        assert_eq!(decoded.encrypted_len(), payload.len());
    }

    // Negative-path testing (invalid threshold pubkey, bad hex, etc.)
    // is not run natively here: the workspace profile uses
    // `panic = "abort"`, and `wasm_bindgen` functions cannot unwind a
    // `JsValue` error across the FFI boundary on non-wasm targets —
    // even for happy-path `Err(...)` returns the process aborts.
    // These paths are exercised end-to-end via the `pyde-ts-sdk` jest
    // suite once the wasm bundle is rebuilt.
}
