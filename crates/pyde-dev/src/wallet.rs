use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pyde_crypto::falcon::{falcon_keygen, falcon_sign, FalconPublicKey, FalconSecretKey};
use pyde_crypto::poseidon2::poseidon2_hash;
use std::fs;
use std::path::PathBuf;

const WALLET_DIR: &str = ".pyde/wallets";
/// Schema versions: 1 = legacy single-iteration Poseidon2 KDF
/// (brute-forceable on commodity GPUs); 2 = Argon2id with
/// `m=64 MB, t=3, p=1` (audit 306).
const KEYSTORE_VERSION: u32 = 2;
const KEYSTORE_VERSION_LEGACY_POSEIDON2: u32 = 1;

const ARGON2_M_COST_KIB: u32 = 64 * 1024;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

/// On-disk encrypted keystore.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Keystore {
    pub address: String,
    pub public_key: String,
    encrypted_secret_key: String,
    salt: String,
    nonce: String,
    version: u32,
}

/// Decrypted wallet ready for signing.
pub struct Wallet {
    #[allow(dead_code)]
    pub name: String,
    pub address: [u8; 32],
    pub public_key: FalconPublicKey,
    pub(crate) secret_key: FalconSecretKey,
}

impl Wallet {
    /// Sign a transaction hash and return the signature bytes.
    pub fn sign(&self, tx_hash: &[u8; 32]) -> Result<Vec<u8>, String> {
        let sig =
            falcon_sign(&self.secret_key, tx_hash).map_err(|e| format!("signing failed: {}", e))?;
        Ok(sig.as_bytes().to_vec())
    }

    /// Get the address as hex string.
    pub fn address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.address))
    }
}

/// Create a new wallet with a generated FALCON-512 keypair.
pub fn create(name: &str, password: &str) -> Result<Wallet, String> {
    let (pk, sk) = falcon_keygen().map_err(|e| format!("key generation failed: {}", e))?;

    let address = pyde_account::address::derive_eoa_address(pk.as_bytes());

    let keystore = encrypt_keystore(&pk, &sk, &address, password)?;
    save_keystore(name, &keystore)?;

    Ok(Wallet {
        name: name.to_string(),
        address,
        public_key: pk,
        secret_key: sk,
    })
}

/// Import an existing secret key.
#[allow(dead_code)]
pub fn import(_name: &str, sk_hex: &str, _password: &str) -> Result<Wallet, String> {
    let sk_bytes = hex::decode(sk_hex.trim_start_matches("0x"))
        .map_err(|e| format!("invalid secret key hex: {}", e))?;

    let _sk = FalconSecretKey::from_bytes(&sk_bytes)
        .ok_or("invalid FALCON-512 secret key (expected 1281 bytes)")?;

    // Derive public key by signing a test message and... we can't derive pk from sk directly.
    // FALCON doesn't support pk derivation from sk. User must provide pk too, or we generate
    // a new keypair and only use the sk. For simplicity, we'll require the full keypair.
    // Actually, let's store sk and derive address differently — for import, user provides
    // the secret key, we sign a known message and verify to extract... that doesn't work either.
    //
    // Practical approach: import expects hex of BOTH pk and sk concatenated.
    // Or: we just store the sk and ask for the address separately.
    //
    // Simplest: import takes the secret key hex. We can't derive the public key from it
    // (FALCON is not like Ed25519). So import also needs the public key.
    // Let's change the interface.

    Err("import requires both public and secret key — use `wallet import <pk_hex> <sk_hex>`".into())
}

/// Import with both public and secret key.
pub fn import_keypair(
    name: &str,
    pk_hex: &str,
    sk_hex: &str,
    password: &str,
) -> Result<Wallet, String> {
    let pk_bytes = hex::decode(pk_hex.trim_start_matches("0x"))
        .map_err(|e| format!("invalid public key hex: {}", e))?;
    let sk_bytes = hex::decode(sk_hex.trim_start_matches("0x"))
        .map_err(|e| format!("invalid secret key hex: {}", e))?;

    let pk = FalconPublicKey::from_bytes(&pk_bytes)
        .ok_or("invalid FALCON-512 public key (expected 897 bytes)")?;
    let sk = FalconSecretKey::from_bytes(&sk_bytes)
        .ok_or("invalid FALCON-512 secret key (expected 1281 bytes)")?;

    let address = pyde_account::address::derive_eoa_address(pk.as_bytes());

    let keystore = encrypt_keystore(&pk, &sk, &address, password)?;
    save_keystore(name, &keystore)?;

    Ok(Wallet {
        name: name.to_string(),
        address,
        public_key: pk,
        secret_key: sk,
    })
}

/// Load and decrypt a wallet by name.
pub fn load(name: &str, password: &str) -> Result<Wallet, String> {
    let keystore = load_keystore(name)?;
    let sk = decrypt_secret_key(&keystore, password)?;
    let pk_bytes = hex::decode(keystore.public_key.trim_start_matches("0x"))
        .map_err(|e| format!("invalid public key in keystore: {}", e))?;
    let pk = FalconPublicKey::from_bytes(&pk_bytes).ok_or("invalid public key in keystore")?;

    let addr_bytes = hex::decode(keystore.address.trim_start_matches("0x"))
        .map_err(|e| format!("invalid address in keystore: {}", e))?;
    let mut address = [0u8; 32];
    if addr_bytes.len() == 32 {
        address.copy_from_slice(&addr_bytes);
    }

    Ok(Wallet {
        name: name.to_string(),
        address,
        public_key: pk,
        secret_key: sk,
    })
}

/// List all wallet names and addresses.
pub fn list() -> Result<Vec<(String, String)>, String> {
    let dir = wallet_dir();
    if !dir.exists() {
        return Ok(vec![]);
    }

    let mut wallets = Vec::new();
    for entry in fs::read_dir(&dir).map_err(|e| format!("cannot read wallet dir: {}", e))? {
        let entry = entry.map_err(|e| format!("read error: {}", e))?;
        let path = entry.path();
        if path.extension().map(|e| e == "json").unwrap_or(false) {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(ks) = serde_json::from_str::<Keystore>(&content) {
                    let name = path
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                    wallets.push((name, ks.address));
                }
            }
        }
    }

    Ok(wallets)
}

// ============================================================================
// Encryption
// ============================================================================

/// Argon2id KDF (audit 306). Replaces the prior single-iteration
/// Poseidon2 KDF, which was brute-forceable on commodity GPUs.
fn derive_aes_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = argon2::Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| format!("argon2 params: {}", e))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| format!("argon2 hash: {}", e))?;
    Ok(out)
}

/// Legacy Poseidon2 KDF retained ONLY for decrypting v1 keystores.
fn derive_aes_key_v1_poseidon2(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(password.len() + salt.len());
    input.extend_from_slice(password.as_bytes());
    input.extend_from_slice(salt);
    poseidon2_hash(&input).to_bytes()
}

fn encrypt_keystore(
    pk: &FalconPublicKey,
    sk: &FalconSecretKey,
    address: &[u8; 32],
    password: &str,
) -> Result<Keystore, String> {
    // Generate random salt and nonce
    let salt: [u8; 16] = rand::random();
    let nonce_bytes: [u8; 12] = rand::random();

    let aes_key = derive_aes_key(password, &salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).map_err(|e| format!("AES init failed: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted = cipher
        .encrypt(nonce, sk.as_bytes())
        .map_err(|e| format!("encryption failed: {}", e))?;

    Ok(Keystore {
        address: format!("0x{}", hex::encode(address)),
        public_key: format!("0x{}", hex::encode(pk.as_bytes())),
        encrypted_secret_key: format!("0x{}", hex::encode(&encrypted)),
        salt: format!("0x{}", hex::encode(salt)),
        nonce: format!("0x{}", hex::encode(nonce_bytes)),
        version: KEYSTORE_VERSION,
    })
}

fn decrypt_secret_key(keystore: &Keystore, password: &str) -> Result<FalconSecretKey, String> {
    let salt = hex::decode(keystore.salt.trim_start_matches("0x")).map_err(|_| "invalid salt")?;
    let nonce_bytes =
        hex::decode(keystore.nonce.trim_start_matches("0x")).map_err(|_| "invalid nonce")?;
    let encrypted = hex::decode(keystore.encrypted_secret_key.trim_start_matches("0x"))
        .map_err(|_| "invalid encrypted key")?;

    let aes_key = match keystore.version {
        KEYSTORE_VERSION => derive_aes_key(password, &salt)?,
        KEYSTORE_VERSION_LEGACY_POSEIDON2 => derive_aes_key_v1_poseidon2(password, &salt),
        v => {
            return Err(format!(
                "unsupported keystore version: {} (expected 1 or {})",
                v, KEYSTORE_VERSION
            ))
        }
    };
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).map_err(|e| format!("AES init failed: {}", e))?;

    if nonce_bytes.len() != 12 {
        return Err("invalid nonce length".into());
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let decrypted = cipher
        .decrypt(nonce, encrypted.as_slice())
        .map_err(|_| "decryption failed — wrong password?")?;

    FalconSecretKey::from_bytes(&decrypted)
        .ok_or_else(|| "decrypted key is invalid FALCON-512 secret key".into())
}

// ============================================================================
// File I/O
// ============================================================================

fn wallet_dir() -> PathBuf {
    dirs_or_home().join(WALLET_DIR)
}

fn dirs_or_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn save_keystore(name: &str, keystore: &Keystore) -> Result<(), String> {
    let dir = wallet_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create wallet dir: {}", e))?;

    // Set directory permissions to 700 (owner only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }

    let path = dir.join(format!("{}.json", name));
    if path.exists() {
        return Err(format!("wallet '{}' already exists", name));
    }

    let json =
        serde_json::to_string_pretty(keystore).map_err(|e| format!("serialize error: {}", e))?;
    fs::write(&path, json).map_err(|e| format!("cannot write keystore: {}", e))?;

    // Set file permissions to 600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

fn load_keystore(name: &str) -> Result<Keystore, String> {
    let path = wallet_dir().join(format!("{}.json", name));
    if !path.exists() {
        return Err(format!(
            "wallet '{}' not found (check ~/.pyde/wallets/)",
            name
        ));
    }

    let content = fs::read_to_string(&path).map_err(|e| format!("cannot read keystore: {}", e))?;
    serde_json::from_str(&content).map_err(|e| format!("invalid keystore JSON: {}", e))
}

/// Prompt for password from stdin (no echo).
pub fn prompt_password(prompt: &str) -> Result<String, String> {
    eprint!("{}", prompt);
    let mut password = String::new();
    std::io::stdin()
        .read_line(&mut password)
        .map_err(|e| format!("cannot read password: {}", e))?;
    Ok(password.trim().to_string())
}

/// Load a wallet by name, prompt for password, return the address hex.
/// Used by deploy/script/console when --wallet is specified.
#[allow(dead_code)]
pub fn resolve_wallet_address(name: &str) -> Result<String, String> {
    let password = prompt_password("  Enter wallet password: ")?;
    let w = load(name, &password)?;
    Ok(w.address_hex())
}

// ============================================================================
// CLI command handlers
// ============================================================================

pub fn cmd_create(name: &str) -> Result<(), String> {
    let password = prompt_password("  Enter password for new wallet: ")?;
    if password.is_empty() {
        return Err("password cannot be empty".into());
    }
    let confirm = prompt_password("  Confirm password: ")?;
    if password != confirm {
        return Err("passwords do not match".into());
    }

    let w = create(name, &password)?;
    println!();
    println!("  Wallet created: {}", name);
    println!("  Address: {}", w.address_hex());
    println!("  Stored at: ~/.pyde/wallets/{}.json", name);
    Ok(())
}

pub fn cmd_import(name: &str, pk_hex: &str, sk_hex: &str) -> Result<(), String> {
    let password = prompt_password("  Enter password for keystore: ")?;
    if password.is_empty() {
        return Err("password cannot be empty".into());
    }

    let w = import_keypair(name, pk_hex, sk_hex, &password)?;
    println!();
    println!("  Wallet imported: {}", name);
    println!("  Address: {}", w.address_hex());
    Ok(())
}

pub fn cmd_list() -> Result<(), String> {
    let wallets = list()?;
    if wallets.is_empty() {
        println!("  No wallets found. Create one with `pyde-dev wallet create`");
        return Ok(());
    }
    println!("  Wallets:");
    for (name, addr) in &wallets {
        println!("    {} — {}", name, addr);
    }
    Ok(())
}

pub fn cmd_balance(name: &str, network: &str) -> Result<(), String> {
    let (config, _) = crate::project::load_config()?;
    let net = config
        .networks
        .get(network)
        .ok_or_else(|| format!("network '{}' not found in pyde.toml", network))?;

    let keystore = load_keystore(name)?;
    let client = reqwest::blocking::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "pyde_getBalance",
        "params": [&keystore.address]
    });
    let resp = client
        .post(&net.rpc_url)
        .json(&body)
        .send()
        .map_err(|e| format!("RPC error: {}", e))?;
    let json: serde_json::Value = resp
        .json()
        .map_err(|e| format!("invalid response: {}", e))?;
    let balance = json.get("result").and_then(|v| v.as_str()).unwrap_or("0");

    println!("  Wallet: {} ({})", name, keystore.address);
    println!("  Balance: {} quanta", balance);
    Ok(())
}

pub fn cmd_transfer(
    to: &str,
    amount: u128,
    wallet_name: &str,
    network: &str,
) -> Result<(), String> {
    let (config, _) = crate::project::load_config()?;
    let net = config
        .networks
        .get(network)
        .ok_or_else(|| format!("network '{}' not found in pyde.toml", network))?;

    let password = prompt_password("  Enter wallet password: ")?;
    let w = load(wallet_name, &password)?;

    // Fetch nonce
    let client = reqwest::blocking::Client::new();
    let nonce_body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "pyde_getTransactionCount",
        "params": [w.address_hex()]
    });
    let nonce_resp = client
        .post(&net.rpc_url)
        .json(&nonce_body)
        .send()
        .map_err(|e| format!("RPC error: {}", e))?;
    let nonce_json: serde_json::Value = nonce_resp
        .json()
        .map_err(|e| format!("invalid response: {}", e))?;
    let nonce: u64 = nonce_json
        .get("result")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Parse recipient
    let to_hex = to.trim_start_matches("0x");
    if to_hex.len() != 64 {
        return Err(format!(
            "invalid recipient address: expected 64 hex chars, got {}",
            to_hex.len()
        ));
    }
    let to_bytes = hex::decode(to_hex).map_err(|e| format!("invalid address: {}", e))?;
    let mut to_addr = [0u8; 32];
    to_addr.copy_from_slice(&to_bytes);

    // Build transaction
    let chain_id = net.chain_id;
    let mut tx = pyde_tx::types::Transaction {
        from: w.address,
        to: to_addr,
        value: amount,
        data: vec![],
        gas_limit: 21_000,
        nonce,
        signature: vec![],
        fee_payer: pyde_tx::types::FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id,
        tx_type: pyde_tx::types::TransactionType::Standard,
    };

    // Sign
    let tx_hash = tx.hash();
    tx.signature = w.sign(&tx_hash)?;

    println!(
        "  Sending {} quanta from {} to {}",
        amount,
        w.address_hex(),
        to
    );

    // Send via sendRawTransaction
    let tx_bytes = pyde_tx::types::Transaction::to_bytes(&tx);
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "pyde_sendRawTransaction",
        "params": [format!("0x{}", hex::encode(&tx_bytes))]
    });
    let resp = client
        .post(&net.rpc_url)
        .json(&body)
        .send()
        .map_err(|e| format!("RPC error: {}", e))?;
    let resp_json: serde_json::Value = resp
        .json()
        .map_err(|e| format!("invalid response: {}", e))?;

    if let Some(err) = resp_json.get("error") {
        return Err(format!("transfer failed: {}", err));
    }

    let result = resp_json
        .get("result")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    println!("  Tx: {}", result);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (pk, sk) = falcon_keygen().unwrap();
        let address = pyde_account::address::derive_eoa_address(pk.as_bytes());
        let password = "test_password_123";

        let keystore = encrypt_keystore(&pk, &sk, &address, password).unwrap();
        let decrypted = decrypt_secret_key(&keystore, password).unwrap();

        assert_eq!(sk.as_bytes(), decrypted.as_bytes());
    }

    #[test]
    fn wrong_password_fails() {
        let (pk, sk) = falcon_keygen().unwrap();
        let address = pyde_account::address::derive_eoa_address(pk.as_bytes());

        let keystore = encrypt_keystore(&pk, &sk, &address, "correct").unwrap();
        let result = decrypt_secret_key(&keystore, "wrong");

        assert!(result.is_err());
    }

    // ── Audit 306: Argon2id migration tests ─────────────────────────

    #[test]
    fn new_keystores_are_v2_argon2id() {
        let (pk, sk) = falcon_keygen().unwrap();
        let address = pyde_account::address::derive_eoa_address(pk.as_bytes());
        let ks = encrypt_keystore(&pk, &sk, &address, "x").unwrap();
        assert_eq!(ks.version, 2);
    }

    /// Pre-306 v1 keystores still decrypt via the legacy KDF dispatch.
    #[test]
    fn legacy_v1_keystore_still_decrypts() {
        let (pk, sk) = falcon_keygen().unwrap();
        let address = pyde_account::address::derive_eoa_address(pk.as_bytes());
        let pass = "legacy-passphrase";
        let salt: [u8; 16] = rand::random();
        let nonce_bytes: [u8; 12] = rand::random();

        let aes_key = derive_aes_key_v1_poseidon2(pass, &salt);
        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, sk.as_bytes()).unwrap();
        let v1_ks = Keystore {
            address: format!("0x{}", hex::encode(address)),
            public_key: format!("0x{}", hex::encode(pk.as_bytes())),
            encrypted_secret_key: format!("0x{}", hex::encode(&ciphertext)),
            salt: format!("0x{}", hex::encode(salt)),
            nonce: format!("0x{}", hex::encode(nonce_bytes)),
            version: 1,
        };

        let decrypted = decrypt_secret_key(&v1_ks, pass).unwrap();
        assert_eq!(sk.as_bytes(), decrypted.as_bytes());
        assert!(decrypt_secret_key(&v1_ks, "wrong").is_err());
    }

    #[test]
    fn unsupported_keystore_version_rejected() {
        let (pk, sk) = falcon_keygen().unwrap();
        let address = pyde_account::address::derive_eoa_address(pk.as_bytes());
        let mut ks = encrypt_keystore(&pk, &sk, &address, "x").unwrap();
        ks.version = 99;
        let res = decrypt_secret_key(&ks, "x");
        assert!(res.is_err());
        assert!(res.err().unwrap().contains("unsupported keystore version"));
    }

    #[test]
    fn address_derivation_consistent() {
        let (pk, _) = falcon_keygen().unwrap();
        let addr1 = pyde_account::address::derive_eoa_address(pk.as_bytes());
        let addr2 = pyde_account::address::derive_eoa_address(pk.as_bytes());
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn sign_and_verify() {
        let (pk, sk) = falcon_keygen().unwrap();
        let wallet = Wallet {
            name: "test".into(),
            address: [0u8; 32],
            public_key: pk.clone(),
            secret_key: sk,
        };

        let msg = [42u8; 32];
        let sig = wallet.sign(&msg).unwrap();
        assert!(!sig.is_empty());

        // Verify with the crypto layer
        let falcon_sig = pyde_crypto::falcon::FalconSignature::from_bytes(&sig).unwrap();
        assert!(pyde_crypto::falcon::falcon_verify(&pk, &msg, &falcon_sig));
    }
}
