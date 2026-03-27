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
use tracing::info;

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
        let key = pyde_state::keys::balance_key(&address);
        entries.push((key, balance.to_le_bytes().to_vec()));
        total_supply = total_supply.checked_add(balance)
            .ok_or("genesis total supply overflow")?;

        info!(
            address = alloc.address,
            balance,
            "genesis allocation"
        );
    }

    // 2. Write validator stakes as balances (included in total supply)
    for val in &config.validators {
        let address = parse_hex_address(&val.address)?;
        let stake = val.stake_u128()?;

        let balance_key = pyde_state::keys::balance_key(&address);
        entries.push((balance_key, stake.to_le_bytes().to_vec()));
        total_supply = total_supply.checked_add(stake)
            .ok_or("genesis total supply overflow")?;

        info!(
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

/// Create a default devnet genesis config with pre-funded accounts.
pub fn devnet_genesis() -> GenesisConfig {
    // 10 pre-funded accounts for development (each gets 1M PYDE)
    let one_million_pyde = "1000000000000000"; // 1M PYDE in quanta (10^15)

    let mut allocations = Vec::new();
    for i in 0u8..10 {
        let address = hex::encode([i + 1; 32]);
        allocations.push(GenesisAllocation {
            address,
            balance: one_million_pyde.to_string(),
        });
    }

    GenesisConfig {
        chain_id: 31337, // devnet chain ID
        timestamp: 0,
        allocations,
        validators: Vec::new(),
    }
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
        let config = devnet_genesis();
        assert_eq!(config.allocations.len(), 10);
        assert_eq!(config.chain_id, 31337);
    }

    #[test]
    fn genesis_config_roundtrip() {
        let config = devnet_genesis();
        let toml_str = config.to_toml();
        let parsed: GenesisConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.allocations.len(), 10);
        assert_eq!(parsed.chain_id, 31337);
    }

    #[test]
    fn initialize_genesis_creates_state() {
        let mut state = StateManager::open(
            &std::env::temp_dir().join("pyde-test-genesis-init"),
            1024,
        ).unwrap();

        let config = devnet_genesis();
        let block = initialize_genesis(&mut state, &config).unwrap();

        assert_eq!(block.slot(), 0);
        assert!(!state.is_empty());

        // Verify first account has balance
        let addr = parse_hex_address(&config.allocations[0].address).unwrap();
        let key = pyde_state::keys::balance_key(&addr);
        let balance_bytes = state.get(&key).expect("balance should exist");
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&balance_bytes[..16]);
        let balance = u128::from_le_bytes(buf);
        assert_eq!(balance, 1_000_000_000_000_000); // 1M PYDE
    }

    #[test]
    fn genesis_rejects_non_empty_state() {
        let mut state = StateManager::open(
            &std::env::temp_dir().join("pyde-test-genesis-reject"),
            1024,
        ).unwrap();

        let config = devnet_genesis();
        initialize_genesis(&mut state, &config).unwrap(); // first time ok
        let result = initialize_genesis(&mut state, &config); // second time fails
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
