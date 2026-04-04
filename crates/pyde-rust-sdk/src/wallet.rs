use crate::client::Provider;
use crate::error::{Result, SdkError};
use crate::types::*;
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use pyde_crypto::falcon::{falcon_keygen, falcon_sign, FalconSecretKey, FalconPublicKey};
use pyde_crypto::poseidon2::poseidon2_hash;

/// Encrypted keystore format (JSON file).
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Keystore {
    pub address: String,
    pub public_key: String,
    encrypted_secret_key: String,
    salt: String,
    nonce: String,
    version: u32,
}

/// FALCON-512 wallet for signing transactions.
pub struct Wallet {
    address: Address,
    public_key: FalconPublicKey,
    secret_key: FalconSecretKey,
}

impl Wallet {
    /// Generate a new random keypair (in-memory, not persisted).
    pub fn generate() -> Result<Self> {
        let (pk, sk) = falcon_keygen()
            .map_err(|e| SdkError::Signing(format!("keygen failed: {}", e)))?;
        let address = derive_eoa_address(pk.as_bytes());
        Ok(Self { address, public_key: pk, secret_key: sk })
    }

    /// Create from existing key objects.
    pub fn from_keys(pk: FalconPublicKey, sk: FalconSecretKey) -> Self {
        let address = derive_eoa_address(pk.as_bytes());
        Self { address, public_key: pk, secret_key: sk }
    }

    /// Create from a private key hex string.
    /// The hex contains both public key (897 bytes) and secret key (1281 bytes)
    /// concatenated = 2178 bytes total. This is what `secret_key_full_hex()` exports.
    pub fn from_private_key(hex: &str) -> Result<Self> {
        let hex = hex.trim_start_matches("0x");
        let bytes = ::hex::decode(hex)
            .map_err(|e| SdkError::InvalidAddress(format!("bad private key hex: {}", e)))?;
        if bytes.len() != 897 + 1281 {
            return Err(SdkError::Signing(format!(
                "private key must be {} bytes (897 pk + 1281 sk), got {}",
                897 + 1281, bytes.len()
            )));
        }
        let pk = FalconPublicKey::from_bytes(&bytes[..897])
            .ok_or_else(|| SdkError::Signing("invalid public key".into()))?;
        let sk = FalconSecretKey::from_bytes(&bytes[897..])
            .ok_or_else(|| SdkError::Signing("invalid secret key".into()))?;
        Ok(Self::from_keys(pk, sk))
    }

    /// Create from an encrypted Keystore struct (not file — for when you already have it in memory).
    pub fn from_encrypted(keystore: &Keystore, password: &str) -> Result<Self> {
        let sk = decrypt_key(keystore, password)?;
        let pk_bytes = ::hex::decode(keystore.public_key.trim_start_matches("0x"))
            .map_err(|_| SdkError::Signing("bad public key hex in keystore".into()))?;
        let pk = FalconPublicKey::from_bytes(&pk_bytes)
            .ok_or_else(|| SdkError::Signing("invalid public key in keystore".into()))?;
        let address = derive_eoa_address(pk.as_bytes());
        Ok(Self { address, public_key: pk, secret_key: sk })
    }

    /// Generate a new keypair and save encrypted to a file.
    pub fn create_encrypted(path: &std::path::Path, password: &str) -> Result<Self> {
        let wallet = Self::generate()?;
        let keystore = wallet.to_keystore(password)?;
        let json = serde_json::to_string_pretty(&keystore)
            .map_err(|e| SdkError::Signing(format!("serialize: {}", e)))?;
        std::fs::write(path, json)
            .map_err(|e| SdkError::Signing(format!("write: {}", e)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(wallet)
    }

    /// Load a wallet from an encrypted keystore file.
    pub fn from_keystore(path: &std::path::Path, password: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| SdkError::Signing(format!("read: {}", e)))?;
        let keystore: Keystore = serde_json::from_str(&content)
            .map_err(|e| SdkError::Signing(format!("parse: {}", e)))?;

        let sk = decrypt_key(&keystore, password)?;
        let pk_bytes = hex::decode(keystore.public_key.trim_start_matches("0x"))
            .map_err(|_| SdkError::Signing("bad public key hex".into()))?;
        let pk = FalconPublicKey::from_bytes(&pk_bytes)
            .ok_or_else(|| SdkError::Signing("invalid public key".into()))?;

        let address = derive_eoa_address(pk.as_bytes());
        Ok(Self { address, public_key: pk, secret_key: sk })
    }

    /// Export wallet as encrypted keystore struct.
    pub fn to_keystore(&self, password: &str) -> Result<Keystore> {
        encrypt_keystore(&self.public_key, &self.secret_key, &self.address, password)
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    pub fn address(&self) -> &Address { &self.address }

    pub fn address_hex(&self) -> String { format_address(&self.address) }

    pub fn public_key(&self) -> &FalconPublicKey { &self.public_key }

    pub fn public_key_hex(&self) -> String {
        format!("0x{}", hex::encode(self.public_key.as_bytes()))
    }

    pub fn secret_key_hex(&self) -> String {
        format!("0x{}", hex::encode(self.secret_key.as_bytes()))
    }

    /// Export the full private key (pk + sk concatenated) as hex.
    /// Use with `Wallet::from_private_key()` to restore.
    pub fn private_key_hex(&self) -> String {
        let mut bytes = Vec::with_capacity(897 + 1281);
        bytes.extend_from_slice(self.public_key.as_bytes());
        bytes.extend_from_slice(self.secret_key.as_bytes());
        format!("0x{}", hex::encode(&bytes))
    }

    // ========================================================================
    // Signing
    // ========================================================================

    /// Sign a transaction in place.
    pub fn sign_transaction(&self, tx: &mut Transaction) -> Result<()> {
        let hash = tx.hash();
        let sig = falcon_sign(&self.secret_key, &hash)
            .map_err(|e| SdkError::Signing(format!("sign: {}", e)))?;
        tx.signature = sig.as_bytes().to_vec();
        Ok(())
    }

    // ========================================================================
    // High-level helpers
    // ========================================================================

    /// Build, sign, send a native transfer. Returns receipt (errors on revert).
    pub async fn transfer(&self, provider: &Provider, to: &Address, amount: u128) -> Result<Receipt> {
        let nonce = provider.get_nonce(&self.address).await?;
        let chain_id = provider.get_chain_id().await?;

        let mut tx = Transaction {
            from: self.address, to: *to, value: amount, data: vec![],
            gas_limit: 21_000, nonce, signature: vec![],
            fee_payer: FeePayer::Sender, access_list: vec![],
            deadline: None, chain_id, tx_type: TransactionType::Standard,
        };
        self.sign_transaction(&mut tx)?;
        send_and_check(provider, &tx).await
    }

    /// Build, sign, send a contract call. Returns receipt (errors on revert).
    pub async fn send_call(
        &self, provider: &Provider, to: &Address, data: Vec<u8>, gas_limit: u64,
    ) -> Result<Receipt> {
        let nonce = provider.get_nonce(&self.address).await?;
        let chain_id = provider.get_chain_id().await?;

        let mut tx = Transaction {
            from: self.address, to: *to, value: 0, data,
            gas_limit, nonce, signature: vec![],
            fee_payer: FeePayer::Sender, access_list: vec![],
            deadline: None, chain_id, tx_type: TransactionType::Standard,
        };
        self.sign_transaction(&mut tx)?;
        send_and_check(provider, &tx).await
    }

    /// Build, sign, send a contract deploy. Returns receipt (errors on revert).
    pub async fn deploy(
        &self, provider: &Provider, deploy_data: Vec<u8>, gas_limit: u64,
    ) -> Result<Receipt> {
        let nonce = provider.get_nonce(&self.address).await?;
        let chain_id = provider.get_chain_id().await?;

        let mut tx = Transaction {
            from: self.address, to: [0u8; 32], value: 0, data: deploy_data,
            gas_limit, nonce, signature: vec![],
            fee_payer: FeePayer::Sender, access_list: vec![],
            deadline: None, chain_id, tx_type: TransactionType::Deploy,
        };
        self.sign_transaction(&mut tx)?;
        send_and_check(provider, &tx).await
    }
}

/// Bind a wallet to a provider for convenience.
pub struct SignerProvider<'a> {
    pub wallet: &'a Wallet,
    pub provider: &'a Provider,
}

impl<'a> SignerProvider<'a> {
    pub fn new(wallet: &'a Wallet, provider: &'a Provider) -> Self {
        Self { wallet, provider }
    }

    pub async fn transfer(&self, to: &Address, amount: u128) -> Result<Receipt> {
        self.wallet.transfer(self.provider, to, amount).await
    }

    pub async fn send_call(&self, to: &Address, data: Vec<u8>, gas_limit: u64) -> Result<Receipt> {
        self.wallet.send_call(self.provider, to, data, gas_limit).await
    }

    pub async fn deploy(&self, deploy_data: Vec<u8>, gas_limit: u64) -> Result<Receipt> {
        self.wallet.deploy(self.provider, deploy_data, gas_limit).await
    }

    pub async fn get_balance(&self) -> Result<u128> {
        self.provider.get_balance(self.wallet.address()).await
    }

    pub async fn get_nonce(&self) -> Result<u64> {
        self.provider.get_nonce(self.wallet.address()).await
    }

    pub async fn call(&self, to: &Address, data: &[u8]) -> Result<Vec<u8>> {
        self.provider.call(to, data).await
    }
}

// ============================================================================
// Internal: send + check revert
// ============================================================================

async fn send_and_check(provider: &Provider, tx: &Transaction) -> Result<Receipt> {
    let receipt = provider.send_and_wait(tx, 10_000).await?;
    if !receipt.success {
        return Err(SdkError::Reverted {
            gas_used: receipt.gas(),
            data: receipt.return_bytes(),
        });
    }
    Ok(receipt)
}

// ============================================================================
// Encryption (AES-256-GCM + Poseidon2 key derivation)
// ============================================================================

fn derive_aes_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(password.len() + salt.len());
    input.extend_from_slice(password.as_bytes());
    input.extend_from_slice(salt);
    poseidon2_hash(&input).to_bytes()
}

fn encrypt_keystore(
    pk: &FalconPublicKey, sk: &FalconSecretKey, address: &Address, password: &str,
) -> Result<Keystore> {
    let salt: [u8; 16] = rand::random();
    let nonce_bytes: [u8; 12] = rand::random();

    let aes_key = derive_aes_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| SdkError::Signing(format!("AES init: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted = cipher.encrypt(nonce, sk.as_bytes())
        .map_err(|e| SdkError::Signing(format!("encrypt: {}", e)))?;

    Ok(Keystore {
        address: format!("0x{}", hex::encode(address)),
        public_key: format!("0x{}", hex::encode(pk.as_bytes())),
        encrypted_secret_key: format!("0x{}", hex::encode(&encrypted)),
        salt: format!("0x{}", hex::encode(salt)),
        nonce: format!("0x{}", hex::encode(nonce_bytes)),
        version: 1,
    })
}

fn decrypt_key(keystore: &Keystore, password: &str) -> Result<FalconSecretKey> {
    let salt = hex::decode(keystore.salt.trim_start_matches("0x"))
        .map_err(|_| SdkError::Signing("bad salt".into()))?;
    let nonce_bytes = hex::decode(keystore.nonce.trim_start_matches("0x"))
        .map_err(|_| SdkError::Signing("bad nonce".into()))?;
    let encrypted = hex::decode(keystore.encrypted_secret_key.trim_start_matches("0x"))
        .map_err(|_| SdkError::Signing("bad encrypted key".into()))?;

    let aes_key = derive_aes_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| SdkError::Signing(format!("AES init: {}", e)))?;

    if nonce_bytes.len() != 12 {
        return Err(SdkError::Signing("bad nonce length".into()));
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let decrypted = cipher.decrypt(nonce, encrypted.as_slice())
        .map_err(|_| SdkError::Signing("decryption failed — wrong password?".into()))?;

    FalconSecretKey::from_bytes(&decrypted)
        .ok_or_else(|| SdkError::Signing("invalid secret key after decrypt".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_wallet() {
        let w = Wallet::generate().unwrap();
        assert_ne!(w.address(), &[0u8; 32]);
    }

    #[test]
    fn sign_and_verify() {
        let w = Wallet::generate().unwrap();
        let mut tx = Transaction {
            from: *w.address(), to: [0xBB; 32], value: 100, data: vec![],
            gas_limit: 21_000, nonce: 0, signature: vec![],
            fee_payer: FeePayer::Sender, access_list: vec![],
            deadline: None, chain_id: 1, tx_type: TransactionType::Standard,
        };
        w.sign_transaction(&mut tx).unwrap();
        assert!(!tx.signature.is_empty());
        assert!(tx.verify_signature(w.public_key().as_bytes()));
    }

    #[test]
    fn address_deterministic() {
        let (pk, sk) = falcon_keygen().unwrap();
        let w1 = Wallet::from_keys(pk.clone(), sk.clone());
        let w2 = Wallet::from_keys(pk, sk);
        assert_eq!(w1.address(), w2.address());
    }

    #[test]
    fn keystore_encrypt_decrypt() {
        let w = Wallet::generate().unwrap();
        let keystore = w.to_keystore("mypassword").unwrap();
        let sk = decrypt_key(&keystore, "mypassword").unwrap();
        assert_eq!(sk.as_bytes(), w.secret_key.as_bytes());
    }

    #[test]
    fn keystore_wrong_password() {
        let w = Wallet::generate().unwrap();
        let keystore = w.to_keystore("correct").unwrap();
        let result = decrypt_key(&keystore, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn keystore_file_roundtrip() {
        let dir = std::env::temp_dir().join("pyde-sdk-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test-wallet.json");
        let _ = std::fs::remove_file(&path);

        let w = Wallet::create_encrypted(&path, "pass123").unwrap();
        assert!(path.exists());

        let loaded = Wallet::from_keystore(&path, "pass123").unwrap();
        assert_eq!(w.address(), loaded.address());
        assert_eq!(w.public_key_hex(), loaded.public_key_hex());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn from_private_key_roundtrip() {
        let w = Wallet::generate().unwrap();
        let pk_hex = w.private_key_hex();
        let restored = Wallet::from_private_key(&pk_hex).unwrap();
        assert_eq!(w.address(), restored.address());
        assert_eq!(w.public_key_hex(), restored.public_key_hex());
    }

    #[test]
    fn from_encrypted_roundtrip() {
        let w = Wallet::generate().unwrap();
        let keystore = w.to_keystore("secret").unwrap();
        let restored = Wallet::from_encrypted(&keystore, "secret").unwrap();
        assert_eq!(w.address(), restored.address());
    }

    #[test]
    fn from_encrypted_wrong_password() {
        let w = Wallet::generate().unwrap();
        let keystore = w.to_keystore("correct").unwrap();
        assert!(Wallet::from_encrypted(&keystore, "wrong").is_err());
    }

    #[test]
    fn key_export_hex() {
        let w = Wallet::generate().unwrap();
        assert!(w.public_key_hex().starts_with("0x"));
        assert!(w.secret_key_hex().starts_with("0x"));
        assert_eq!(w.public_key_hex().len(), 2 + 897 * 2); // 0x + 897 bytes hex
        assert_eq!(w.secret_key_hex().len(), 2 + 1281 * 2); // 0x + 1281 bytes hex
    }
}
