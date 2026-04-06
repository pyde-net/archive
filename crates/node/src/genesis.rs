//! Genesis state initialization.
//!
//! On first startup (empty state), the node loads a genesis config that defines:
//! - Initial token allocations (address → balance)
//! - Initial validators (address → public key)
//! - Chain parameters (chain_id, initial base fee)
//!
//! These are written into the SMT to produce the genesis state root,
//! which is used to create the genesis block (slot 0).

use crate::state_manager::StateManager;
use pyde_account::address::Address;
use pyde_consensus::block::{genesis_block, Block};
use pyde_tx::fee::GENESIS_BASE_FEE;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, info};

/// Genesis configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct GenesisConfig {
    /// Chain ID.
    pub chain_id: u64,
    /// Genesis timestamp (Unix milliseconds).
    pub timestamp: u64,
    /// Initial token allocations: hex address → balance in quanta.
    pub allocations: Vec<GenesisAllocation>,
    /// Initial validators: hex address → public key hex.
    pub validators: Vec<GenesisValidator>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisAllocation {
    /// Hex-encoded 32-byte address.
    pub address: String,
    /// Balance in quanta as string (10^9 quanta = 1 PYDE). String to avoid TOML u128 limitation.
    pub balance: String,
    /// Optional hex-encoded FALCON-512 public key (sets auth_keys for tx signing).
    #[serde(default)]
    pub public_key: Option<String>,
}

impl GenesisAllocation {
    pub fn balance_u128(&self) -> Result<u128, String> {
        self.balance.parse::<u128>().map_err(|e| format!("invalid balance '{}': {}", self.balance, e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Hex-encoded 32-byte address.
    pub address: String,
    /// Hex-encoded FALCON-512 public key.
    pub public_key: String,
    /// Staked amount in quanta as string.
    pub stake: String,
}

impl GenesisValidator {
    pub fn stake_u128(&self) -> Result<u128, String> {
        self.stake.parse::<u128>().map_err(|e| format!("invalid stake '{}': {}", self.stake, e))
    }
}

/// Threshold encryption config for MEV protection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Number of committee members.
    pub n: usize,
    /// Threshold for decryption (85 of 128 in production).
    pub threshold: usize,
}

impl Default for GenesisConfig {
    fn default() -> Self {
        Self {
            chain_id: 1,
            timestamp: 0,
            allocations: Vec::new(),
            validators: Vec::new(),
        }
    }
}

impl GenesisConfig {
    /// Load genesis config from a TOML file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read genesis config {}: {}", path.display(), e))?;
        toml::from_str(&content)
            .map_err(|e| format!("failed to parse genesis config: {}", e))
    }

    /// Serialize to TOML string.
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }
}

/// Apply genesis state: write initial allocations into the SMT.
/// Returns the genesis block.
pub fn initialize_genesis(
    state: &mut StateManager,
    config: &GenesisConfig,
) -> Result<Block, String> {
    if !state.is_empty() {
        return Err("state is not empty — genesis already applied".into());
    }

    let mut entries = Vec::new();
    let mut total_supply: u128 = 0;

    // 1. Write initial allocations (balances)
    for alloc in &config.allocations {
        let address = parse_hex_address(&alloc.address)?;
        let balance = alloc.balance_u128()?;

        // Always store as full Account struct so the tx pipeline can read it correctly.
        let mut account = if let Some(pk_hex) = &alloc.public_key {
            let pk_bytes = hex::decode(pk_hex.strip_prefix("0x").unwrap_or(pk_hex))
                .map_err(|e| format!("invalid public key hex: {}", e))?;
            let mut a = pyde_account::types::Account::new_eoa(&pk_bytes);
            a.address = address;
            a
        } else {
            // No auth_keys — create a bare EOA (can receive, devnet can send with sig skip)
            pyde_account::types::Account {
                address,
                nonce: 0,
                balance: 0,
                code_hash: sparse_merkle_tree::H256::zero(),
                storage_root: sparse_merkle_tree::H256::zero(),
                account_type: pyde_account::types::AccountType::EOA,
                auth_keys: pyde_account::types::AuthKeys::None,
                gas_tank: 0,
                key_nonce: 0,
            }
        };
        account.balance = balance;

        let key = pyde_state::keys::balance_key(&address);
        entries.push((key, account.to_bytes()));
        debug!(
            address = alloc.address,
            balance,
            has_auth_keys = alloc.public_key.is_some(),
            "genesis allocation"
        );

        total_supply = total_supply.checked_add(balance)
            .ok_or("genesis total supply overflow")?;
    }

    // 2. Write validator stakes as balances (included in total supply)
    for val in &config.validators {
        let address = parse_hex_address(&val.address)?;
        let stake = val.stake_u128()?;

        let mut account = pyde_account::types::Account {
            address,
            nonce: 0,
            balance: stake,
            code_hash: sparse_merkle_tree::H256::zero(),
            storage_root: sparse_merkle_tree::H256::zero(),
            account_type: pyde_account::types::AccountType::EOA,
            auth_keys: pyde_account::types::AuthKeys::None,
            gas_tank: 0,
            key_nonce: 0,
        };
        let balance_key = pyde_state::keys::balance_key(&address);
        entries.push((balance_key, account.to_bytes()));
        total_supply = total_supply.checked_add(stake)
            .ok_or("genesis total supply overflow")?;

        debug!(
            address = val.address,
            stake,
            "genesis validator"
        );
    }

    // 3. Batch insert all entries
    let state_root = state.update_batch(entries)?;

    info!(
        allocations = config.allocations.len(),
        validators = config.validators.len(),
        total_supply,
        state_root = hex::encode(state_root),
        "genesis state initialized"
    );

    // 4. Create genesis block
    let block = genesis_block(state_root, config.timestamp);
    Ok(block)
}

/// A devnet account with full keypair (for printing private keys on startup).
pub struct DevnetAccount {
    pub address: Address,
    pub public_key: pyde_crypto::falcon::FalconPublicKey,
    pub secret_key: pyde_crypto::falcon::FalconSecretKey,
    pub balance: u128,
}

impl DevnetAccount {
    /// Export combined private key (pk + sk) as 0x-prefixed hex.
    /// Same format as Wallet.exportPrivateKey() in the SDKs.
    pub fn private_key_hex(&self) -> String {
        let mut bytes = Vec::with_capacity(897 + 1281);
        bytes.extend_from_slice(self.public_key.as_bytes());
        bytes.extend_from_slice(self.secret_key.as_bytes());
        format!("0x{}", hex::encode(&bytes))
    }

    /// Address as 0x-prefixed hex.
    pub fn address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.address))
    }
}

/// Create a default devnet genesis config with 10 pre-funded accounts.
/// Returns both the config AND the full keypairs (for printing private keys).
pub fn devnet_genesis() -> (GenesisConfig, Vec<DevnetAccount>) {
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::falcon::falcon_keygen;

    // 10M PYDE per account in quanta (10,000,000 × 10^9)
    let ten_million_pyde: u128 = 10_000_000 * 1_000_000_000;

    let mut allocations = Vec::new();
    let mut accounts = Vec::new();

    for _ in 0..10 {
        let (pk, sk) = falcon_keygen().expect("FALCON keygen failed");
        let address = derive_eoa_address(pk.as_bytes());

        allocations.push(GenesisAllocation {
            address: hex::encode(address),
            balance: ten_million_pyde.to_string(),
            public_key: Some(hex::encode(pk.as_bytes())),
        });

        accounts.push(DevnetAccount {
            address,
            public_key: pk,
            secret_key: sk,
            balance: ten_million_pyde,
        });
    }

    let config = GenesisConfig {
        chain_id: 31337,
        timestamp: 0,
        allocations,
        validators: Vec::new(),
    };

    (config, accounts)
}

fn parse_hex_address(hex_str: &str) -> Result<Address, String> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)
        .map_err(|e| format!("invalid hex address '{}': {}", hex_str, e))?;
    if bytes.len() != 32 {
        return Err(format!("address must be 32 bytes, got {}", bytes.len()));
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_genesis_has_10_accounts() {
        let (config, accounts) = devnet_genesis();
        assert_eq!(config.allocations.len(), 10);
        assert_eq!(accounts.len(), 10);
        assert_eq!(config.chain_id, 31337);
        // Each account should have a public key
        for alloc in &config.allocations {
            assert!(alloc.public_key.is_some());
        }
        // Private keys should be restorable
        for acc in &accounts {
            let pk_hex = acc.private_key_hex();
            assert!(pk_hex.starts_with("0x"));
            assert_eq!(pk_hex.len(), 2 + (897 + 1281) * 2); // 0x + 2178 bytes hex
        }
    }

    #[test]
    fn devnet_genesis_balance_correct() {
        let (_, accounts) = devnet_genesis();
        let ten_million_pyde: u128 = 10_000_000 * 1_000_000_000;
        for acc in &accounts {
            assert_eq!(acc.balance, ten_million_pyde);
        }
    }

    #[test]
    fn genesis_config_roundtrip() {
        let (config, _) = devnet_genesis();
        let toml_str = config.to_toml();
        let parsed: GenesisConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.allocations.len(), 10);
        assert_eq!(parsed.chain_id, 31337);
    }

    #[test]
    fn initialize_genesis_creates_state() {
        let mut state = StateManager::open(
            &std::env::temp_dir().join("pyde-test-genesis-init-v2"),
            1024,
        ).unwrap();

        let (config, _) = devnet_genesis();
        let block = initialize_genesis(&mut state, &config).unwrap();

        assert_eq!(block.slot(), 0);
        assert!(!state.is_empty());

        // Verify first account has balance
        let addr = parse_hex_address(&config.allocations[0].address).unwrap();
        let key = pyde_state::keys::balance_key(&addr);
        let account_bytes = state.get(&key).expect("account should exist");
        let account = pyde_account::types::Account::from_bytes(&account_bytes)
            .expect("should be a valid Account");
        let ten_million_pyde: u128 = 10_000_000 * 1_000_000_000;
        assert_eq!(account.balance, ten_million_pyde);
    }

    #[test]
    fn genesis_rejects_non_empty_state() {
        let mut state = StateManager::open(
            &std::env::temp_dir().join("pyde-test-genesis-reject-v2"),
            1024,
        ).unwrap();

        let (config, _) = devnet_genesis();
        initialize_genesis(&mut state, &config).unwrap();
        let result = initialize_genesis(&mut state, &config);
        assert!(result.is_err());
    }

    #[test]
    fn parse_hex_address_works() {
        let hex = hex::encode([0xAA; 32]);
        let addr = parse_hex_address(&hex).unwrap();
        assert_eq!(addr, [0xAA; 32]);
    }

    #[test]
    fn parse_hex_address_with_prefix() {
        let hex = format!("0x{}", hex::encode([0xBB; 32]));
        let addr = parse_hex_address(&hex).unwrap();
        assert_eq!(addr, [0xBB; 32]);
    }

    #[test]
    fn parse_hex_address_wrong_length() {
        assert!(parse_hex_address("deadbeef").is_err());
    }
}
