use crate::client::Provider;
use crate::error::{Result, SdkError};
use crate::types::*;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pyde_crypto::falcon::{falcon_keygen, falcon_sign, FalconPublicKey, FalconSecretKey};
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
        let (pk, sk) =
            falcon_keygen().map_err(|e| SdkError::Signing(format!("keygen failed: {}", e)))?;
        let address = derive_eoa_address(pk.as_bytes());
        Ok(Self {
            address,
            public_key: pk,
            secret_key: sk,
        })
    }

    /// Create from existing key objects.
    pub fn from_keys(pk: FalconPublicKey, sk: FalconSecretKey) -> Self {
        let address = derive_eoa_address(pk.as_bytes());
        Self {
            address,
            public_key: pk,
            secret_key: sk,
        }
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
                897 + 1281,
                bytes.len()
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
        Ok(Self {
            address,
            public_key: pk,
            secret_key: sk,
        })
    }

    /// Generate a new keypair and save encrypted to a file.
    pub fn create_encrypted(path: &std::path::Path, password: &str) -> Result<Self> {
        let wallet = Self::generate()?;
        let keystore = wallet.to_keystore(password)?;
        let json = serde_json::to_string_pretty(&keystore)
            .map_err(|e| SdkError::Signing(format!("serialize: {}", e)))?;
        std::fs::write(path, json).map_err(|e| SdkError::Signing(format!("write: {}", e)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(wallet)
    }

    /// Load a wallet from an encrypted keystore file.
    pub fn from_keystore(path: &std::path::Path, password: &str) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).map_err(|e| SdkError::Signing(format!("read: {}", e)))?;
        let keystore: Keystore = serde_json::from_str(&content)
            .map_err(|e| SdkError::Signing(format!("parse: {}", e)))?;

        let sk = decrypt_key(&keystore, password)?;
        let pk_bytes = hex::decode(keystore.public_key.trim_start_matches("0x"))
            .map_err(|_| SdkError::Signing("bad public key hex".into()))?;
        let pk = FalconPublicKey::from_bytes(&pk_bytes)
            .ok_or_else(|| SdkError::Signing("invalid public key".into()))?;

        let address = derive_eoa_address(pk.as_bytes());
        Ok(Self {
            address,
            public_key: pk,
            secret_key: sk,
        })
    }

    /// Export wallet as encrypted keystore struct.
    pub fn to_keystore(&self, password: &str) -> Result<Keystore> {
        encrypt_keystore(&self.public_key, &self.secret_key, &self.address, password)
    }

    /// Save wallet as encrypted keystore to a file.
    pub fn save_keystore(&self, path: &std::path::Path, password: &str) -> Result<()> {
        let keystore = self.to_keystore(password)?;
        let json = serde_json::to_string_pretty(&keystore)
            .map_err(|e| SdkError::Signing(format!("serialize: {}", e)))?;
        std::fs::write(path, json).map_err(|e| SdkError::Signing(format!("write: {}", e)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn address_hex(&self) -> String {
        format_address(&self.address)
    }

    pub fn public_key(&self) -> &FalconPublicKey {
        &self.public_key
    }

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

    /// Sign an arbitrary 32-byte message. Returns signature bytes.
    pub fn sign(&self, message: &[u8; 32]) -> Result<Vec<u8>> {
        let sig = falcon_sign(&self.secret_key, message)
            .map_err(|e| SdkError::Signing(format!("sign: {}", e)))?;
        Ok(sig.as_bytes().to_vec())
    }

    // ========================================================================
    // High-level helpers
    // ========================================================================

    /// Register this wallet's FALCON public key on-chain (audit 229).
    ///
    /// Required ONCE per address before the wallet can submit any
    /// signed tx. Pyde uses post-quantum FALCON-512 signatures, which
    /// (unlike ECDSA) don't support pubkey recovery from a sig — so
    /// the chain needs to know each address's pubkey separately. The
    /// `RegisterPubkey` tx is unsigned and free; the address-derivation
    /// check (`from == Poseidon2(pubkey)`) is the proof of pubkey
    /// ownership.
    ///
    /// Pre-conditions enforced by the chain:
    ///   - This account must exist with `balance > 0` (someone has to
    ///     send you funds first).
    ///   - The account must not be already registered.
    ///
    /// Typical first-tx flow for a new user:
    ///   1. Generate wallet locally (`Wallet::generate()`).
    ///   2. Receive funds at `wallet.address()` from a faucet or
    ///      another user.
    ///   3. Call `wallet.register_pubkey(&provider).await?` once.
    ///   4. From now on, `transfer` / `send_call` etc. work normally.
    pub async fn register_pubkey(&self, provider: &Provider) -> Result<Receipt> {
        let (nonce, chain_id) = provider.get_nonce_and_chain_id(&self.address).await?;
        let tx = Transaction {
            from: self.address,
            to: pyde_account::address::ZERO_ADDRESS,
            value: 0,
            data: self.public_key.as_bytes().to_vec(),
            gas_limit: 0,
            nonce,
            signature: vec![], // unsigned by design — see audit 229
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id,
            tx_type: TransactionType::RegisterPubkey,
        };
        send_and_check(provider, &tx).await
    }

    /// Build, sign, send a native transfer. Returns receipt (errors on revert).
    pub async fn transfer(
        &self,
        provider: &Provider,
        to: &Address,
        amount: u128,
    ) -> Result<Receipt> {
        let (nonce, chain_id) = provider.get_nonce_and_chain_id(&self.address).await?;

        let mut tx = Transaction {
            from: self.address,
            to: *to,
            value: amount,
            data: vec![],
            gas_limit: 21_000,
            nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id,
            tx_type: TransactionType::Standard,
        };
        self.sign_transaction(&mut tx)?;
        send_and_check(provider, &tx).await
    }

    /// Generate a random FALCON-512 private key hex (pk + sk combined).
    /// Use with `Wallet::from_private_key()` to create a wallet later.
    pub fn generate_private_key() -> Result<String> {
        let wallet = Self::generate()?;
        Ok(wallet.private_key_hex())
    }

    /// Build, sign, send a contract call. Returns receipt (errors on revert).
    pub async fn send_call(
        &self,
        provider: &Provider,
        to: &Address,
        data: Vec<u8>,
        gas_limit: u64,
    ) -> Result<Receipt> {
        self.send_call_with_value(provider, to, data, 0, gas_limit)
            .await
    }

    /// Build, sign, send a contract call with native token value.
    /// Automatically fetches access list via simulation for parallel scheduling.
    pub async fn send_call_with_value(
        &self,
        provider: &Provider,
        to: &Address,
        data: Vec<u8>,
        value: u128,
        gas_limit: u64,
    ) -> Result<Receipt> {
        let (nonce, chain_id) = provider.get_nonce_and_chain_id(&self.address).await?;

        // Fetch access list via simulation (enables parallel scheduling)
        let val = if value > 0 { Some(value) } else { None };
        let access_list = provider
            .create_access_list(to, &data, Some(&self.address), val)
            .await
            .unwrap_or_default();

        let mut tx = Transaction {
            from: self.address,
            to: *to,
            value,
            data,
            gas_limit,
            nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list,
            deadline: None,
            chain_id,
            tx_type: TransactionType::Standard,
        };
        self.sign_transaction(&mut tx)?;
        send_and_check(provider, &tx).await
    }

    /// Bind a provider for convenience. Returns a SignerProvider with shorter method signatures.
    pub fn connect<'a>(&'a self, provider: &'a Provider) -> SignerProvider<'a> {
        SignerProvider::new(self, provider)
    }

    /// Validate a FALCON-512 private key hex string (pk + sk, 2178 bytes).
    pub fn is_valid_private_key(hex: &str) -> bool {
        crate::types::is_valid_private_key(hex)
    }

    /// Build, sign, send a contract deploy. Returns receipt (errors on revert).
    pub async fn deploy(
        &self,
        provider: &Provider,
        deploy_data: Vec<u8>,
        gas_limit: u64,
    ) -> Result<Receipt> {
        self.deploy_with_value(provider, deploy_data, 0, gas_limit)
            .await
    }

    /// Build, sign, send a contract deploy with native token value (payable constructor).
    pub async fn deploy_with_value(
        &self,
        provider: &Provider,
        deploy_data: Vec<u8>,
        value: u128,
        gas_limit: u64,
    ) -> Result<Receipt> {
        let (nonce, chain_id) = provider.get_nonce_and_chain_id(&self.address).await?;

        let mut tx = Transaction {
            from: self.address,
            to: [0u8; 32],
            value,
            data: deploy_data,
            gas_limit,
            nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id,
            tx_type: TransactionType::Deploy,
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
        self.wallet
            .send_call(self.provider, to, data, gas_limit)
            .await
    }

    pub async fn send_call_with_value(
        &self,
        to: &Address,
        data: Vec<u8>,
        value: u128,
        gas_limit: u64,
    ) -> Result<Receipt> {
        self.wallet
            .send_call_with_value(self.provider, to, data, value, gas_limit)
            .await
    }

    pub async fn deploy(&self, deploy_data: Vec<u8>, gas_limit: u64) -> Result<Receipt> {
        self.wallet
            .deploy(self.provider, deploy_data, gas_limit)
            .await
    }

    pub async fn deploy_with_value(
        &self,
        deploy_data: Vec<u8>,
        value: u128,
        gas_limit: u64,
    ) -> Result<Receipt> {
        self.wallet
            .deploy_with_value(self.provider, deploy_data, value, gas_limit)
            .await
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

impl crate::signer::Signer for Wallet {
    fn address(&self) -> &Address {
        &self.address
    }
    fn sign_transaction(&self, tx: &mut Transaction) -> Result<()> {
        self.sign_transaction(tx)
    }
    fn sign(&self, message: &[u8; 32]) -> Result<Vec<u8>> {
        self.sign(message)
    }
}

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
    pk: &FalconPublicKey,
    sk: &FalconSecretKey,
    address: &Address,
    password: &str,
) -> Result<Keystore> {
    let salt: [u8; 16] = rand::random();
    let nonce_bytes: [u8; 12] = rand::random();

    let aes_key = derive_aes_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| SdkError::Signing(format!("AES init: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted = cipher
        .encrypt(nonce, sk.as_bytes())
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

    let decrypted = cipher
        .decrypt(nonce, encrypted.as_slice())
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
            from: *w.address(),
            to: [0xBB; 32],
            value: 100,
            data: vec![],
            gas_limit: 21_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
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

    #[test]
    fn is_valid_private_key_check() {
        let w = Wallet::generate().unwrap();
        assert!(Wallet::is_valid_private_key(&w.private_key_hex()));
        assert!(!Wallet::is_valid_private_key("0xdeadbeef"));
        assert!(!Wallet::is_valid_private_key("not hex at all"));
    }

    #[test]
    fn connect_returns_signer() {
        let w = Wallet::generate().unwrap();
        let p = crate::Provider::new("http://localhost:0");
        let signer = w.connect(&p);
        assert_eq!(signer.wallet.address(), w.address());
    }

    #[test]
    fn address_utilities() {
        use crate::types::*;
        assert!(is_zero_address(&ZERO_ADDRESS));
        assert!(!is_zero_address(&[0xAA; 32]));
        let valid_addr = format!("0x{}", "ab".repeat(32));
        assert!(is_valid_address(&valid_addr));
        assert!(!is_valid_address("0xshort"));
        let bad_addr = format!("0x{}", "zz".repeat(32));
        assert!(!is_valid_address(&bad_addr));
        assert!(address_eq(&[0xAA; 32], &[0xAA; 32]));
        assert!(!address_eq(&[0xAA; 32], &[0xBB; 32]));
    }

    #[test]
    fn unit_formatting() {
        use crate::types::*;
        // parse_units
        assert_eq!(parse_units("100", 9).unwrap(), 100_000_000_000);
        assert_eq!(parse_units("1.5", 9).unwrap(), 1_500_000_000);
        assert_eq!(parse_units("0.001", 9).unwrap(), 1_000_000);
        assert_eq!(parse_units("0", 9).unwrap(), 0);
        assert!(parse_units("1.0000000001", 9).is_err()); // too many decimals
                                                          // format_units
        assert_eq!(format_units(1_500_000_000, 9), "1.5");
        assert_eq!(format_units(1_000_000, 9), "0.001");
        assert_eq!(format_units(0, 9), "0.0");
        assert_eq!(format_units(1_000_000_000, 9), "1.0");
        // quanta shortcuts
        assert_eq!(parse_quanta("2.5").unwrap(), 2_500_000_000);
        assert_eq!(format_quanta(2_500_000_000), "2.5");
        // custom decimals
        assert_eq!(parse_units("1.0", 18).unwrap(), 1_000_000_000_000_000_000);
        // roundtrip
        assert_eq!(
            format_units(parse_units("123.456789", 9).unwrap(), 9),
            "123.456789"
        );
    }
}
