use pyde_crypto::falcon::FalconSecretKey;
use pyde_crypto::poseidon2::poseidon2_hash;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use wasm_bindgen::prelude::*;

// ============================================================================
// Audit 361: opaque-handle keystore
// ============================================================================
//
// `generate_keypair_handle` keeps the FALCON secret key inside this
// crate's WASM heap and returns only an opaque `u32` handle to JS.
// `sign_*_with_handle` look the key up by handle and sign in place;
// `drop_keypair` zeroes and removes the entry. The intent is that
// SK bytes never enter the JS heap at all — in particular, never
// land in `JSON.stringify(walletState)`, never appear in dev-tools
// memory snapshots, never survive in a crash dump as a recoverable
// hex string, and never get accidentally logged.
//
// `FalconSecretKey` already derives `ZeroizeOnDrop` (audit 358), so
// removing the entry from the map (via `HashMap::remove` →
// `Drop::drop`) actually zeroes the secret bytes in place.
//
// Why a process-global Mutex: wasm32 is currently single-threaded on
// every browser (no SharedArrayBuffer threads enabled here), so the
// Mutex is uncontended in practice. Keeping it as a Mutex (rather
// than a thread_local!) means we don't need wasm-bindgen's
// thread-local plumbing, and the API stays callable from any
// future worker context without additional setup.
//
// Handle exhaustion: u32 gives 4G distinct handles before wrap.
// The wallet UX is one keypair per browser tab, so 4G is effectively
// unlimited; if a long-running app does churn through that many
// handles, `drop_keypair` is the correct release path. We do NOT
// reuse handles after drop — each new keypair gets a fresh number,
// so a stale handle from a dropped keypair returns "key not found"
// instead of silently signing under a different key.
struct KeyTable {
    next_handle: u32,
    keys: HashMap<u32, FalconSecretKey>,
}

impl KeyTable {
    fn new() -> Self {
        Self {
            next_handle: 1, // 0 is reserved as "no handle"
            keys: HashMap::new(),
        }
    }
}

fn key_table() -> &'static Mutex<KeyTable> {
    static TABLE: OnceLock<Mutex<KeyTable>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(KeyTable::new()))
}

// ============================================================================
// Key generation & address
// ============================================================================

/// Generate a FALCON-512 keypair.
/// Returns JSON: { "publicKey": "0x...", "secretKey": "0x...", "address": "0x..." }
///
/// **Audit 361 — security warning**: this function returns the
/// secret key as a hex string into the JS heap. Once there, it is
/// reachable from:
///   - browser dev-tools console (`Object.values(walletState)`)
///   - browser extensions with content-script access to the page
///   - process crash dumps (the string survives until JS GC)
///   - accidental logging (`JSON.stringify(walletState)`)
///
/// For wallet UIs that need to hold the key in-process, prefer
/// `generateKeypairHandle` + `signMessageWithHandle` /
/// `signTransactionWithHandle` / `dropKeypair`. Those keep the SK
/// inside this crate's WASM heap and return only an opaque `u32`
/// handle to JS — the SK bytes never enter the JS heap at all. For
/// wallets that need to encrypt the SK to disk before discarding
/// the in-memory copy (the typical `pyde-ts-sdk` / `pyde-dev`
/// keystore flow), this hex-string return is unavoidable, but
/// callers MUST encrypt the value at the earliest opportunity and
/// must NEVER let it survive across renders or get serialized.
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

/// Audit 361: opaque-handle variant of `generateKeypair`. Generates
/// a FALCON-512 keypair, retains the secret key inside this crate's
/// WASM heap, and returns JSON with only the `publicKey`, `address`,
/// and an opaque `handle: u32` to JS. The SK bytes never enter the
/// JS heap. Use `signMessageWithHandle` / `signTransactionWithHandle`
/// to sign with the retained key, and `dropKeypair(handle)` when
/// done.
///
/// Returns JSON: `{ "publicKey": "0x...", "address": "0x...",
///                  "handle": 1 }`.
#[wasm_bindgen(js_name = "generateKeypairHandle")]
pub fn generate_keypair_handle() -> Result<String, JsValue> {
    let (pk, sk) = pyde_crypto::falcon::falcon_keygen()
        .map_err(|e| JsValue::from_str(&format!("keygen failed: {}", e)))?;
    let address = poseidon2_hash(pk.as_bytes()).to_bytes();

    let handle = {
        let mut table = key_table()
            .lock()
            .map_err(|_| JsValue::from_str("internal: key table mutex poisoned (audit 361)"))?;
        let h = table.next_handle;
        table.next_handle = table.next_handle.checked_add(1).ok_or_else(|| {
            JsValue::from_str("handle space exhausted (u32::MAX keypairs generated this session)")
        })?;
        table.keys.insert(h, sk);
        h
    };

    let result = serde_json::json!({
        "publicKey": format!("0x{}", hex::encode(pk.as_bytes())),
        "address": format!("0x{}", hex::encode(address)),
        "handle": handle,
    });
    Ok(result.to_string())
}

/// Audit 361: sign a message using a key retained by handle. The
/// SK bytes never leave this crate's WASM heap.
///
/// Returns the signature as a `0x`-prefixed hex string.
#[wasm_bindgen(js_name = "signMessageWithHandle")]
pub fn sign_message_with_handle(handle: u32, message_hex: &str) -> Result<String, JsValue> {
    let msg_bytes = decode_hex(message_hex)?;
    let table = key_table()
        .lock()
        .map_err(|_| JsValue::from_str("internal: key table mutex poisoned (audit 361)"))?;
    let sk = table.keys.get(&handle).ok_or_else(|| {
        JsValue::from_str("audit 361: handle not found (already dropped or never created)")
    })?;
    let sig = pyde_crypto::falcon::falcon_sign(sk, &msg_bytes)
        .map_err(|e| JsValue::from_str(&format!("sign failed: {}", e)))?;
    Ok(format!("0x{}", hex::encode(sig.as_bytes())))
}

/// Audit 361: sign a transaction (same JSON shape as
/// `signTransaction`) using a key retained by handle. Returns the
/// signed wire bytes as `0x`-prefixed hex.
#[wasm_bindgen(js_name = "signTransactionWithHandle")]
pub fn sign_transaction_with_handle(tx_json: &str, handle: u32) -> Result<String, JsValue> {
    let v: serde_json::Value = serde_json::from_str(tx_json)
        .map_err(|e| JsValue::from_str(&format!("bad JSON: {}", e)))?;
    let hash = compute_tx_hash(&v)?;

    let table = key_table()
        .lock()
        .map_err(|_| JsValue::from_str("internal: key table mutex poisoned (audit 361)"))?;
    let sk = table.keys.get(&handle).ok_or_else(|| {
        JsValue::from_str("audit 361: handle not found (already dropped or never created)")
    })?;
    let sig = pyde_crypto::falcon::falcon_sign(sk, &hash)
        .map_err(|e| JsValue::from_str(&format!("sign failed: {}", e)))?;

    let tx_bytes = serialize_tx(&v, sig.as_bytes())?;
    Ok(format!("0x{}", hex::encode(&tx_bytes)))
}

/// Audit 361: drop a retained keypair. The `FalconSecretKey`'s
/// `ZeroizeOnDrop` impl (audit 358) overwrites the secret bytes in
/// place when removed from the table. Returns `true` if a key was
/// actually removed, `false` if the handle was already dropped.
#[wasm_bindgen(js_name = "dropKeypair")]
pub fn drop_keypair(handle: u32) -> Result<bool, JsValue> {
    let mut table = key_table()
        .lock()
        .map_err(|_| JsValue::from_str("internal: key table mutex poisoned (audit 361)"))?;
    Ok(table.keys.remove(&handle).is_some())
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

/// Wire-encode a `TransactionType::RegisterPubkey` (audit 229) tx
/// without signing. The address-derivation check (`from ==
/// Poseidon2(data)`) IS the proof of pubkey ownership for this
/// tx type, so a FALCON sig is neither needed nor accepted.
/// Refuses to encode any other tx type — accidental misuse on a
/// signed-tx path would be a hard-to-debug protocol violation.
#[wasm_bindgen(js_name = "encodeRegisterPubkeyTx")]
pub fn encode_register_pubkey_tx(tx_json: &str) -> Result<String, JsValue> {
    let v: serde_json::Value = serde_json::from_str(tx_json)
        .map_err(|e| JsValue::from_str(&format!("bad JSON: {}", e)))?;
    let tx_type = v.get("txType").and_then(|v| v.as_u64()).unwrap_or(0);
    if tx_type != 13 {
        return Err(JsValue::from_str(
            "encodeRegisterPubkeyTx only accepts txType=13 (RegisterPubkey)",
        ));
    }
    let tx_bytes = serialize_tx(&v, &[])?;
    Ok(format!("0x{}", hex::encode(&tx_bytes)))
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
    // Audit 362: chainId is REQUIRED. Pre-fix `unwrap_or(31337)`
    // silently bound a missing-chainId tx to devnet, opening the
    // same cross-chain replay surface that audit 302/303 closed
    // on the RPC side: a wallet that omitted chainId on testnet
    // signed a tx targeted at devnet (or, after a chain_id 1
    // mainnet ships, at mainnet — where the same FALCON keypair
    // would replay onto whatever chain happened to share the
    // default). The fix mirrors audit 302's strict resolution:
    // missing → error, present → use as-is.
    let chain_id = v
        .get("chainId")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| JsValue::from_str("audit 362: chainId is required (use chainId: <u64>)"))?;
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
    // Audit 362: chainId required; see compute_tx_hash for rationale.
    let chain_id = v
        .get("chainId")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| JsValue::from_str("audit 362: chainId is required (use chainId: <u64>)"))?;
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
    // Audit 362: chainId required; see `compute_tx_hash` for the
    // cross-chain replay rationale. Encrypted-tx flows are higher-
    // value than plain tx flows (each carries a value transfer
    // alongside the calldata), so a default-on-31337 here was
    // strictly worse than the same gap on the plain-tx path.
    let chain_id = v
        .get("chainId")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| JsValue::from_str("audit 362: chainId is required (use chainId: <u64>)"))?;
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

    // ========== Audit 361: opaque-handle key retention ==========

    /// `generateKeypairHandle` returns a JSON object that does NOT
    /// expose the secret key — only `publicKey`, `address`, and the
    /// opaque `handle`. Pre-fix the only API was `generateKeypair`
    /// which serialized the SK as hex into the JS heap.
    #[test]
    fn audit_361_generate_keypair_handle_does_not_leak_sk() {
        let json = generate_keypair_handle().unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(v.get("publicKey").and_then(|x| x.as_str()).is_some());
        assert!(v.get("address").and_then(|x| x.as_str()).is_some());
        let handle = v.get("handle").and_then(|x| x.as_u64()).unwrap();
        assert!(handle > 0, "handle must be non-zero (0 reserved)");

        // The secret key must NOT appear under any plausible field
        // name — checks against a regression where a future
        // contributor adds an `sk` field for "convenience".
        assert!(v.get("secretKey").is_none());
        assert!(v.get("sk").is_none());
        assert!(v.get("privateKey").is_none());

        // Cleanup so the static table doesn't grow across tests.
        let _ = drop_keypair(handle as u32);
    }

    /// Signing through `signMessageWithHandle` must produce a
    /// FALCON signature that verifies against the publicKey
    /// returned by `generateKeypairHandle` — proves the key really
    /// is the one identified by the handle, end-to-end without the
    /// SK ever leaving the WASM heap.
    #[test]
    fn audit_361_sign_message_with_handle_verifies() {
        let json = generate_keypair_handle().unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let pk_hex = v.get("publicKey").and_then(|x| x.as_str()).unwrap();
        let handle = v.get("handle").and_then(|x| x.as_u64()).unwrap() as u32;

        let msg_hex = format!("0x{}", hex::encode(b"hello opaque-handle"));
        let sig_hex = sign_message_with_handle(handle, &msg_hex).unwrap();

        let pk_bytes = hex::decode(pk_hex.trim_start_matches("0x")).unwrap();
        let sig_bytes = hex::decode(sig_hex.trim_start_matches("0x")).unwrap();
        let pk = pyde_crypto::falcon::FalconPublicKey::from_bytes(&pk_bytes).unwrap();
        let sig = pyde_crypto::falcon::FalconSignature::from_bytes(&sig_bytes).unwrap();
        assert!(pyde_crypto::falcon::falcon_verify(
            &pk,
            b"hello opaque-handle",
            &sig
        ));

        let _ = drop_keypair(handle);
    }

    /// `dropKeypair` removes the entry; subsequent `dropKeypair`
    /// returns false for the same handle (already-dropped).
    #[test]
    fn audit_361_drop_keypair_idempotent() {
        let json = generate_keypair_handle().unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let handle = v.get("handle").and_then(|x| x.as_u64()).unwrap() as u32;

        assert!(drop_keypair(handle).unwrap(), "first drop removes entry");
        assert!(
            !drop_keypair(handle).unwrap(),
            "second drop of same handle returns false"
        );
    }

    /// Each call to `generateKeypairHandle` returns a fresh,
    /// independent handle; signing with one handle does not affect
    /// the other.
    #[test]
    fn audit_361_handles_are_independent() {
        let j_a = generate_keypair_handle().unwrap();
        let j_b = generate_keypair_handle().unwrap();
        let v_a: serde_json::Value = serde_json::from_str(&j_a).unwrap();
        let v_b: serde_json::Value = serde_json::from_str(&j_b).unwrap();
        let h_a = v_a.get("handle").and_then(|x| x.as_u64()).unwrap() as u32;
        let h_b = v_b.get("handle").and_then(|x| x.as_u64()).unwrap() as u32;
        assert_ne!(h_a, h_b);

        let msg = format!("0x{}", hex::encode(b"same message"));
        let sig_a = sign_message_with_handle(h_a, &msg).unwrap();
        let sig_b = sign_message_with_handle(h_b, &msg).unwrap();
        assert_ne!(sig_a, sig_b, "different keys must produce different sigs");

        // Drop A; signing with A now fails, but B still works.
        assert!(drop_keypair(h_a).unwrap());
        // Sign with B continues to work after A is dropped.
        let _ = sign_message_with_handle(h_b, &msg).unwrap();

        let _ = drop_keypair(h_b);
    }

    // ========== Audit 362: chainId is required ==========

    /// Happy-path regression: chainId provided → tx hash produced
    /// (the existing `build_raw_encrypted_tx_decodes_with_production_decoder`
    /// covers this for the encrypted path; this test pins the plain
    /// `hashTransaction` path).
    #[test]
    fn audit_362_chain_id_required_happy_path() {
        let tx = serde_json::json!({
            "from":     format!("0x{}", hex::encode([0xAAu8; 32])),
            "to":       format!("0x{}", hex::encode([0xBBu8; 32])),
            "value":    "1000",
            "data":     "0x",
            "gasLimit": 21_000u64,
            "nonce":    0u64,
            "chainId":  7331u64, // required
            "txType":   0u64,
        });
        let hash_hex = hash_transaction(&tx.to_string()).unwrap();
        assert!(hash_hex.starts_with("0x"));
        assert_eq!(hash_hex.len(), 2 + 64); // 0x + 32-byte hex

        // Different chainId must produce a different hash — this
        // is the actual cross-chain replay protection. Pre-fix
        // both calls would silently default to 31337 and produce
        // identical hashes.
        let mut tx2 = tx.clone();
        tx2["chainId"] = serde_json::json!(7332u64);
        let hash2 = hash_transaction(&tx2.to_string()).unwrap();
        assert_ne!(hash_hex, hash2, "chainId must be part of the tx digest",);
    }
}
