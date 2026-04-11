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

    // 2. Write validator stakes as balances (included in total supply).
    // Skip validators that already appear in allocations (they're already written with auth_keys).
    let alloc_addresses: std::collections::HashSet<String> = config.allocations.iter()
        .map(|a| a.address.strip_prefix("0x").unwrap_or(&a.address).to_lowercase())
        .collect();

    for val in &config.validators {
        let val_addr_normalized = val.address.strip_prefix("0x").unwrap_or(&val.address).to_lowercase();
        if alloc_addresses.contains(&val_addr_normalized) {
            debug!(address = val.address, "validator already in allocations, skipping duplicate");
            continue;
        }

        let address = parse_hex_address(&val.address)?;
        let stake = val.stake_u128()?;

        // Parse public key to set auth_keys (validators must be able to sign)
        let pk_hex = val.public_key.strip_prefix("0x").unwrap_or(&val.public_key);
        let pk_bytes = hex::decode(pk_hex)
            .map_err(|e| format!("invalid validator public key hex: {}", e))?;
        let mut account = pyde_account::types::Account::new_eoa(&pk_bytes);
        account.address = address;
        account.balance = stake;

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

    // 3. Write validator registry entries (for epoch committee selection).
    // Each validator stored at validator_key(address) with serialized public key + stake.
    // Format: [pk_len:4 LE][pk_bytes][stake:16 LE][status:1]
    let mut val_count: u64 = 0;
    for val in &config.validators {
        let address = parse_hex_address(&val.address)?;
        let pk_hex = val.public_key.strip_prefix("0x").unwrap_or(&val.public_key);
        let pk_bytes = hex::decode(pk_hex)
            .map_err(|e| format!("invalid validator pk for registry: {}", e))?;
        let stake = val.stake_u128()?;

        let mut val_data = Vec::with_capacity(4 + pk_bytes.len() + 16 + 1);
        val_data.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
        val_data.extend_from_slice(&pk_bytes);
        val_data.extend_from_slice(&stake.to_le_bytes());
        val_data.push(0x00); // 0x00 = Active status

        let key = pyde_state::keys::validator_key(&address);
        entries.push((key, val_data));

        // Store address at index for enumeration
        let idx_key = pyde_state::keys::validator_index_key(val_count);
        entries.push((idx_key, address.to_vec()));
        val_count += 1;
    }

    // Store validator count
    let count_key = pyde_state::keys::validator_count_key();
    entries.push((count_key, val_count.to_le_bytes().to_vec()));

    // 4. Batch insert all entries
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

    // 10B PYDE per account in quanta (10,000,000,000 × 10^9)
    // Must cover: gas_limit(100M) × base_fee(50 gwei) = 5B PYDE per tx
    let funding_per_account: u128 = 10_000_000_000 * 1_000_000_000;

    let mut allocations = Vec::new();
    let mut accounts = Vec::new();

    for _ in 0..10 {
        let (pk, sk) = falcon_keygen().expect("FALCON keygen failed");
        let address = derive_eoa_address(pk.as_bytes());

        allocations.push(GenesisAllocation {
            address: hex::encode(address),
            balance: funding_per_account.to_string(),
            public_key: Some(hex::encode(pk.as_bytes())),
        });

        accounts.push(DevnetAccount {
            address,
            public_key: pk,
            secret_key: sk,
            balance: funding_per_account,
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

/// Generate a multi-validator testnet directory.
/// Creates: shared genesis.toml, per-node validator.key files, per-node config.toml files.
pub fn generate_testnet(
    out_dir: &std::path::Path,
    num_validators: usize,
    base_port: u16,
    base_rpc_port: u16,
    dev_mode: bool,
) -> Result<(), String> {
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::falcon::falcon_keygen;
    use std::fs;

    if num_validators < 2 || num_validators > 128 {
        return Err("validators must be between 2 and 128".into());
    }

    fs::create_dir_all(out_dir)
        .map_err(|e| format!("failed to create {}: {}", out_dir.display(), e))?;

    // 10B PYDE per account
    let funding: u128 = 10_000_000_000 * 1_000_000_000;

    let mut allocations = Vec::new();
    let mut validators = Vec::new();
    let mut accounts = Vec::new();

    // Generate FALCON keypairs for each validator
    for _ in 0..num_validators {
        let (pk, sk) = falcon_keygen().map_err(|e| format!("keygen failed: {}", e))?;
        let address = derive_eoa_address(pk.as_bytes());

        allocations.push(GenesisAllocation {
            address: hex::encode(address),
            balance: funding.to_string(),
            public_key: Some(hex::encode(pk.as_bytes())),
        });

        validators.push(GenesisValidator {
            address: hex::encode(address),
            public_key: hex::encode(pk.as_bytes()),
            stake: funding.to_string(),
        });

        accounts.push(DevnetAccount {
            address,
            public_key: pk,
            secret_key: sk,
            balance: funding,
        });
    }

    // Also generate 5 non-validator funded accounts for testing
    for _ in 0..5 {
        let (pk, sk) = falcon_keygen().map_err(|e| format!("keygen failed: {}", e))?;
        let address = derive_eoa_address(pk.as_bytes());
        allocations.push(GenesisAllocation {
            address: hex::encode(address),
            balance: funding.to_string(),
            public_key: Some(hex::encode(pk.as_bytes())),
        });
    }

    // Generate dedicated faucet account (1 trillion PYDE for dispensing)
    let faucet_balance: u128 = 1_000_000_000_000 * 1_000_000_000; // 1T PYDE in quanta
    let (faucet_pk, faucet_sk) = falcon_keygen().map_err(|e| format!("faucet keygen failed: {}", e))?;
    let faucet_address = derive_eoa_address(faucet_pk.as_bytes());
    allocations.push(GenesisAllocation {
        address: hex::encode(faucet_address),
        balance: faucet_balance.to_string(),
        public_key: Some(hex::encode(faucet_pk.as_bytes())),
    });

    let genesis_config = GenesisConfig {
        chain_id: 31337,
        timestamp: 0,
        allocations,
        validators,
    };

    // Write shared genesis.toml
    let genesis_path = out_dir.join("genesis.toml");
    fs::write(&genesis_path, genesis_config.to_toml())
        .map_err(|e| format!("failed to write genesis.toml: {}", e))?;

    // Generate threshold encryption keys for MEV protection.
    //
    // SECURITY NOTE — CENTRALIZED KEYGEN (devnet only):
    // This generates ALL key shares in one process. The operator of `pyde testnet`
    // temporarily sees all shares. This is acceptable for devnet/testnet where the
    // operator is trusted, but NOT acceptable for mainnet.
    //
    // Production path (before mainnet):
    // 1. Multi-party ceremony: K operators each contribute randomness via MPC.
    //    Security: if ANY 1 of K operators is honest, the combined key is secure.
    // 2. Shares distributed to validators, combined secret DELETED.
    // 3. PSS (Proactive Secret Sharing) refresh at each epoch boundary rotates
    //    shares so the genesis ceremony trust dissolves after epoch 1.
    //    (PSS is implemented in crypto/threshold.rs: pss_refresh, apply_refresh)
    // 4. After first PSS refresh, even the original ceremony operator cannot
    //    reconstruct the secret key from the refreshed shares.
    //
    // TODO: Wire PSS refresh into epoch boundary (same P2P pattern as epoch randomness).
    // TODO: Implement `pyde ceremony` command for multi-party key generation.
    let threshold = pyde_consensus::block::quorum_for_committee(num_validators);
    let (threshold_pk, key_shares) = pyde_crypto::threshold::threshold_keygen(num_validators, threshold)
        .map_err(|e| format!("threshold keygen failed: {}", e))?;

    // Pre-generate node identity keys (Ed25519 for libp2p) so we know peer IDs
    // and can write full bootstrap multiaddrs in each config.
    let mut node_keypairs: Vec<(libp2p::identity::Keypair, libp2p::PeerId)> = Vec::new();
    for _ in 0..num_validators {
        let kp = pyde_net::node::generate_keypair();
        let peer_id = libp2p::PeerId::from(kp.public());
        node_keypairs.push((kp, peer_id));
    }

    // Write per-node directories
    for i in 0..num_validators {
        let node_dir = out_dir.join(format!("node-{}", i));
        fs::create_dir_all(&node_dir)
            .map_err(|e| format!("failed to create {}: {}", node_dir.display(), e))?;

        // Write validator.key (format: pk_len(4 LE) || pk || sk)
        let pk_bytes = accounts[i].public_key.as_bytes();
        let sk_bytes = accounts[i].secret_key.as_bytes();
        let mut key_buf = Vec::with_capacity(4 + pk_bytes.len() + sk_bytes.len());
        key_buf.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
        key_buf.extend_from_slice(pk_bytes);
        key_buf.extend_from_slice(sk_bytes);
        fs::write(node_dir.join("validator.key"), &key_buf)
            .map_err(|e| format!("failed to write validator.key: {}", e))?;

        // Write node.key (pre-generated so we know the peer ID for bootstrap addrs)
        let node_key_bytes = pyde_net::node::keypair_to_bytes(&node_keypairs[i].0)
            .map_err(|e| format!("failed to serialize node key: {}", e))?;
        fs::write(node_dir.join("node.key"), &node_key_bytes)
            .map_err(|e| format!("failed to write node.key: {}", e))?;

        // Write threshold key share (binary) for MEV-protected decryption
        fs::write(node_dir.join("threshold.share"), key_shares[i].to_bytes())
            .map_err(|e| format!("failed to write threshold.share: {}", e))?;

        // Write threshold public key (shared — same for all nodes)
        fs::write(node_dir.join("threshold.pk"), threshold_pk.to_bytes())
            .map_err(|e| format!("failed to write threshold.pk: {}", e))?;

        // Copy genesis.toml into each node's directory
        fs::write(node_dir.join("genesis.toml"), genesis_config.to_toml())
            .map_err(|e| format!("failed to write genesis.toml: {}", e))?;

        // Build bootstrap list: ALL other nodes (full mesh)
        let mut bootstrap_addrs: Vec<String> = Vec::new();
        for j in 0..num_validators {
            if j != i {
                let other_port = base_port + j as u16;
                let other_peer_id = &node_keypairs[j].1;
                bootstrap_addrs.push(format!(
                    "\"/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}\"",
                    other_port, other_peer_id
                ));
            }
        }
        let bootstrap = format!("[{}]", bootstrap_addrs.join(", "));

        // Write config.toml
        let p2p_port = base_port + i as u16;
        let rpc_port = base_rpc_port + i as u16;
        let metrics_port = 9090 + i as u16;

        let config_toml = format!(
            r#"[node]
role = "validator"
chain_id = 31337
datadir = "{datadir}"
dev_mode = {dev}

[network]
port = {p2p_port}
max_peers = 50
max_inbound = 30
max_outbound = 20
rate_limit_per_ip = 5
bootstrap_peers = {bootstrap}

[consensus]
block_time_ms = 400
gas_target = 400000000
gas_ceiling = 1600000000

[storage]
db_path = "state"
cache_size = 65536

[rpc]
enabled = true
listen = "127.0.0.1"
port = {rpc_port}

[metrics]
enabled = true
port = {metrics_port}

[logging]
level = "info"
json = false
"#,
            datadir = node_dir.display(),
            dev = dev_mode,
            p2p_port = p2p_port,
            rpc_port = rpc_port,
            metrics_port = metrics_port,
            bootstrap = bootstrap,
        );

        fs::write(node_dir.join("config.toml"), config_toml)
            .map_err(|e| format!("failed to write config.toml: {}", e))?;
    }

    // Write a run.sh convenience script
    let mut run_script = String::from("#!/bin/bash\n# Auto-generated testnet launch script\n\n");
    run_script.push_str("set -e\n\n");
    run_script.push_str(&format!("TESTNET_DIR=\"{}\"\n\n", out_dir.display()));

    for i in 0..num_validators {
        let p2p_port = base_port + i as u16;
        let rpc_port = base_rpc_port + i as u16;
        let node_dir = out_dir.join(format!("node-{}", i));

        if i == 0 {
            run_script.push_str(&format!(
                "echo \"Starting node-0 (port {p2p_port}, RPC {rpc_port})...\"\n\
                 pyde run --role validator --config \"{dir}/config.toml\" --datadir \"{dir}\"{dev} &\n\
                 NODE0_PID=$!\n\
                 sleep 2\n\n\
                 # Get node-0's peer ID from its log output\n\
                 echo \"Node-0 started (PID $NODE0_PID)\"\n\n",
                p2p_port = p2p_port,
                rpc_port = rpc_port,
                dir = node_dir.display(),
                dev = if dev_mode { " --dev" } else { "" },
            ));
        } else {
            // Subsequent nodes bootstrap to node-0
            // The actual multiaddr with peer ID must be provided at runtime
            run_script.push_str(&format!(
                "echo \"Starting node-{i} (port {p2p_port}, RPC {rpc_port})...\"\n\
                 echo \"NOTE: Copy the bootstrap multiaddr from node-0's output and pass it:\"\n\
                 echo \"  pyde run --role validator --config \\\"{dir}/config.toml\\\" --datadir \\\"{dir}\\\" --bootstrap \\\"<node-0-multiaddr>\\\"{dev}\"\n\n",
                i = i,
                p2p_port = p2p_port,
                rpc_port = rpc_port,
                dir = node_dir.display(),
                dev = if dev_mode { " --dev" } else { "" },
            ));
        }
    }

    run_script.push_str("wait\n");
    let script_path = out_dir.join("run.sh");
    fs::write(&script_path, run_script)
        .map_err(|e| format!("failed to write run.sh: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755));
    }

    // Write faucet key file
    let faucet_pk_bytes = faucet_pk.as_bytes();
    let faucet_sk_bytes = faucet_sk.as_bytes();
    let mut faucet_key_buf = Vec::with_capacity(4 + faucet_pk_bytes.len() + faucet_sk_bytes.len());
    faucet_key_buf.extend_from_slice(&(faucet_pk_bytes.len() as u32).to_le_bytes());
    faucet_key_buf.extend_from_slice(faucet_pk_bytes);
    faucet_key_buf.extend_from_slice(faucet_sk_bytes);
    fs::write(out_dir.join("faucet.key"), &faucet_key_buf)
        .map_err(|e| format!("failed to write faucet.key: {}", e))?;

    // Print summary
    println!("Testnet generated in {}", out_dir.display());
    println!();
    println!("Validators: {}", num_validators);
    println!("Chain ID:   31337");
    println!();
    println!("Validator Addresses:");
    for (i, acc) in accounts.iter().enumerate() {
        println!("  ({}) {}", i, acc.address_hex());
    }
    println!();
    println!("Private Keys:");
    for (i, acc) in accounts.iter().enumerate() {
        println!("  ({}) {}", i, acc.private_key_hex());
    }
    println!();
    println!("Faucet:");
    println!("  Address: 0x{}", hex::encode(faucet_address));
    println!("  Balance: 1,000,000,000,000 PYDE (1T)");
    println!("  Key:     {}/faucet.key", out_dir.display());
    println!();
    println!("Files:");
    println!("  genesis.toml        — shared genesis");
    println!("  faucet.key          — faucet signing key");
    for i in 0..num_validators {
        println!("  node-{}/config.toml  — node {} config (P2P:{}, RPC:{})",
            i, i, base_port + i as u16, base_rpc_port + i as u16);
        println!("  node-{}/validator.key — node {} signing key", i, i);
    }
    println!();
    println!("To start:");
    println!("  # Terminal 1 (node-0):");
    println!("  pyde run --role validator --config {}/node-0/config.toml --datadir {}/node-0{}",
        out_dir.display(), out_dir.display(), if dev_mode { " --dev" } else { "" });
    println!();
    println!("  # Terminal 2 (node-1 — copy bootstrap addr from node-0 output):");
    println!("  pyde run --role validator --config {}/node-1/config.toml --datadir {}/node-1 --bootstrap \"<node-0-multiaddr>\"{}",
        out_dir.display(), out_dir.display(), if dev_mode { " --dev" } else { "" });
    println!();
    println!("  # Faucet:");
    println!("  pyde faucet --rpc http://127.0.0.1:8545 --from 0x{} --private-key {}/faucet.key",
        hex::encode(faucet_address), out_dir.display());

    Ok(())
}

/// Parse a hex-encoded 32-byte address.
pub fn parse_hex_address_pub(hex_str: &str) -> Result<Address, String> {
    parse_hex_address(hex_str)
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
        let expected: u128 = 10_000_000_000 * 1_000_000_000;
        for acc in &accounts {
            assert_eq!(acc.balance, expected);
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
        let dir = std::env::temp_dir().join("pyde-test-genesis-init-v2");
        let _ = std::fs::remove_dir_all(&dir);
        let mut state = StateManager::open(&dir, 1024).unwrap();

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
        let expected: u128 = 10_000_000_000 * 1_000_000_000;
        assert_eq!(account.balance, expected);
    }

    #[test]
    fn genesis_rejects_non_empty_state() {
        let dir = std::env::temp_dir().join("pyde-test-genesis-reject-v2");
        let _ = std::fs::remove_dir_all(&dir);
        let mut state = StateManager::open(&dir, 1024).unwrap();

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
