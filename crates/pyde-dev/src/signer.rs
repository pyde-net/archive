//! Signer resolution for deploy/script/console commands.
//!
//! Resolution priority:
//! 1. --private-key <hex>  (explicit FALCON-512 private key)
//! 2. --wallet <name>      (load encrypted keystore from ~/.pyde/wallets/)
//! 3. Default: Account #0 from devnet-keys.json (localhost only!)
//!
//! Validations:
//! - --private-key and --wallet are mutually exclusive
//! - Devnet auto-keys only allowed when RPC is localhost/127.0.0.1
//! - Private key format validated (length, hex chars)

use pyde_account::address::derive_eoa_address;
use pyde_crypto::falcon::{falcon_sign, FalconPublicKey, FalconSecretKey};
use pyde_tx::types::Transaction;

pub struct Signer {
    pub address: [u8; 32],
    pub public_key: FalconPublicKey,
    pub secret_key: FalconSecretKey,
}

impl Signer {
    pub fn address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.address))
    }

    /// Sign a transaction in place.
    pub fn sign_transaction(&self, tx: &mut Transaction) -> Result<(), String> {
        let hash = tx.hash();
        let sig = falcon_sign(&self.secret_key, &hash)
            .map_err(|e| format!("signing failed: {}", e))?;
        tx.signature = sig.as_bytes().to_vec();
        Ok(())
    }

    /// Create from a combined private key hex (pk + sk, 2178 bytes).
    pub fn from_private_key(hex_str: &str) -> Result<Self, String> {
        let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);

        // Validate hex characters
        if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("private key contains non-hex characters".into());
        }

        // Validate length
        let expected_len = (897 + 1281) * 2; // 4356 hex chars
        if hex.len() != expected_len {
            return Err(format!(
                "invalid private key length: expected {} hex chars (2178 bytes = 897 pk + 1281 sk), got {}",
                expected_len, hex.len()
            ));
        }

        let bytes = hex::decode(hex)
            .map_err(|e| format!("invalid private key hex: {}", e))?;
        let pk = FalconPublicKey::from_bytes(&bytes[..897])
            .ok_or("invalid FALCON-512 public key bytes — key may be corrupted")?;
        let sk = FalconSecretKey::from_bytes(&bytes[897..])
            .ok_or("invalid FALCON-512 secret key bytes — key may be corrupted")?;
        let address = derive_eoa_address(pk.as_bytes());
        Ok(Self { address, public_key: pk, secret_key: sk })
    }
}

/// Resolve which signer to use.
///
/// `rpc_url` is required to validate that devnet auto-keys are only used on localhost.
pub fn resolve_signer(
    private_key: Option<&str>,
    wallet_name: Option<&str>,
    rpc_url: &str,
) -> Result<Signer, String> {
    // Validation: --private-key and --wallet are mutually exclusive
    if private_key.is_some() && wallet_name.is_some() {
        return Err(
            "cannot use both --private-key and --wallet. Choose one:\n\
             • --private-key <hex>  (raw FALCON-512 key)\n\
             • --wallet <name>     (encrypted keystore)"
                .into(),
        );
    }

    // 1. Explicit private key — works with any network
    if let Some(pk) = private_key {
        if pk.is_empty() {
            return Err("--private-key value cannot be empty".into());
        }
        return Signer::from_private_key(pk);
    }

    // 2. Named wallet — works with any network
    if let Some(name) = wallet_name {
        if name.is_empty() {
            return Err("--wallet name cannot be empty".into());
        }
        return load_wallet_signer(name);
    }

    // 3. Devnet auto-keys — ONLY allowed on localhost
    if !is_localhost(rpc_url) {
        return Err(format!(
            "no signer specified for non-local network '{}'.\n\
             Devnet auto-keys are only allowed on localhost to prevent\n\
             accidental use of shared keys on public networks.\n\n\
             Use one of:\n\
             • --private-key <hex>  (your FALCON-512 key)\n\
             • --wallet <name>     (encrypted keystore)",
            rpc_url
        ));
    }

    load_devnet_account(0)
}

/// Load Account #N from the devnet-keys.json file.
fn load_devnet_account(index: usize) -> Result<Signer, String> {
    let paths = [
        data_dir().join("devnet-keys.json"),
        std::path::PathBuf::from("./data/devnet-keys.json"),
        std::path::PathBuf::from("./devnet-keys.json"),
    ];

    for path in &paths {
        if path.exists() {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
            let keys: Vec<serde_json::Value> = serde_json::from_str(&content)
                .map_err(|e| format!("invalid devnet-keys.json: {}", e))?;

            if keys.is_empty() {
                return Err("devnet-keys.json is empty — no accounts available".into());
            }

            let account = keys.get(index).ok_or_else(|| format!(
                "devnet account #{} not found (only {} accounts available)",
                index, keys.len()
            ))?;

            let pk_hex = account.get("privateKey")
                .and_then(|v| v.as_str())
                .ok_or("missing 'privateKey' field in devnet-keys.json entry")?;

            return Signer::from_private_key(pk_hex);
        }
    }

    Err(
        "no devnet keys found. Start a devnet node first:\n\
         \n\
         $ pyde node --dev\n\
         \n\
         This generates FALCON-512 keypairs and saves them to devnet-keys.json.\n\
         Alternatively, pass --private-key or --wallet explicitly."
            .into(),
    )
}

/// Load a wallet from ~/.pyde/wallets/<name>.json
fn load_wallet_signer(name: &str) -> Result<Signer, String> {
    let password = std::env::var("PYDE_WALLET_PASSWORD")
        .or_else(|_| crate::wallet::prompt_password(&format!("Password for wallet '{}': ", name)))
        .map_err(|e| format!("cannot get wallet password: {}", e))?;

    let w = crate::wallet::load(name, &password)?;
    Ok(Signer {
        address: w.address,
        public_key: w.public_key.clone(),
        secret_key: w.secret_key.clone(),
    })
}

/// Check if an RPC URL points to localhost.
fn is_localhost(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.contains("localhost") ||
    lower.contains("127.0.0.1") ||
    lower.contains("0.0.0.0") ||
    lower.contains("[::1]")
}

fn home_dir() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

fn data_dir() -> std::path::PathBuf {
    home_dir().join(".pyde").join("data")
}
