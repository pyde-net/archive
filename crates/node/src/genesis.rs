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
    /// Expected total supply in quanta (slice 4.4a sanity check).
    /// Declared as a string to avoid TOML u128 limitation. When non-empty,
    /// `initialize_genesis` verifies that the sum of all allocations
    /// matches this value and rejects the config otherwise. Catches
    /// typos in large allocation tables before mainnet ceremony.
    /// Empty (default) → no check, matches pre-4.4a behaviour.
    #[serde(default)]
    pub initial_supply: String,
    /// Optional per-validator streaming subsidy (slice 4.4a).
    /// The 15% bootstrap allocation flows to active validators via the
    /// same lazy-accrual `rewards_per_validator` accumulator that
    /// handles inflation pool yield — one mechanism, uniform math.
    /// `None` means no subsidy configured (devnet).
    #[serde(default)]
    pub validator_subsidy: Option<ValidatorSubsidyConfig>,
    /// Per-bucket allocation ceilings (slice 4.4a).
    /// Map of bucket name → max percentage (integer 0..=100) of
    /// `initial_supply`. Enforced at startup: if the sum of
    /// allocations tagged with a given bucket exceeds its cap,
    /// `initialize_genesis` returns an error. Unset caps = no limit.
    /// Requires `initial_supply` to be non-empty (caps are
    /// percentages of declared supply).
    #[serde(default)]
    pub bucket_caps: std::collections::HashMap<String, u32>,
    /// Optional airdrop commitment (slice 4.4b). When present, genesis
    /// pre-mints the airdrop pool to `airdrop_pool_address()` and stores
    /// the Merkle root + deadline + expected-sum so `ClaimAirdrop` txs
    /// can verify proofs against the commitment.
    #[serde(default)]
    pub airdrop: Option<AirdropConfig>,
    /// Governance multisig (slice 4.5). Declares the initial signer
    /// set + threshold used by `MultisigTx` / `RotateMultisig`. When
    /// absent, the chain has no on-chain governance — treasury
    /// balance accumulates with no way to spend until a hard fork
    /// installs a multisig.
    #[serde(default)]
    pub multisig: Option<MultisigConfig>,
}

/// Genesis multisig configuration (slice 4.5).
///
/// `signer_public_keys` are hex-encoded FALCON-512 public keys (897
/// bytes each). The on-chain signer set is derived from these; the
/// EOA addresses `derive_eoa_address(pk)` are not stored separately
/// because they're derivable.
///
/// Note: these signers are the INITIAL set. After launch, `threshold`
/// sigs from the current set can install a new set via
/// `RotateMultisig`, enabling signer rotation (annual validator-rep
/// turnover, compromised-key replacement) without a hard fork.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultisigConfig {
    /// Hex-encoded FALCON-512 public keys (897 bytes each).
    pub signer_public_keys: Vec<String>,
    /// Required number of valid signatures. Must be 1..=signer count.
    pub threshold: u8,
}

impl MultisigConfig {
    pub fn decode_pks(&self) -> Result<Vec<Vec<u8>>, String> {
        let mut out = Vec::with_capacity(self.signer_public_keys.len());
        for (i, hex_pk) in self.signer_public_keys.iter().enumerate() {
            let s = hex_pk.strip_prefix("0x").unwrap_or(hex_pk);
            let bytes = hex::decode(s)
                .map_err(|e| format!("invalid multisig.signer_public_keys[{}] hex: {}", i, e))?;
            if bytes.len() != 897 {
                return Err(format!(
                    "multisig.signer_public_keys[{}] must be 897 bytes, got {}",
                    i,
                    bytes.len()
                ));
            }
            if pyde_crypto::falcon::FalconPublicKey::from_bytes(&bytes).is_none() {
                return Err(format!(
                    "multisig.signer_public_keys[{}] is not a valid FALCON pk",
                    i
                ));
            }
            out.push(bytes);
        }
        Ok(out)
    }
}

/// Genesis airdrop commitment (slice 4.4b).
///
/// The operator ships the Merkle root of the `(address, amount)` set
/// they're airdropping. At genesis:
///
/// 1. `pool_total_amount` quanta are minted to `airdrop_pool_address()`
///    (counts toward `initial_supply` like any other allocation).
/// 2. `root` and `deadline_slot` are stored so `ClaimAirdrop` handlers
///    can verify proofs and reject late claims.
/// 3. `expected_claim_sum` is enforced to be ≤ `pool_total_amount` so
///    underfunding is caught at boot, not at claim time.
///
/// Unclaimed residue after `deadline_slot` can be moved to the treasury
/// via a permissionless `SweepAirdrop` tx.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AirdropConfig {
    /// Hex-encoded 32-byte Merkle root.
    pub root: String,
    /// Slot after which `ClaimAirdrop` is rejected.
    pub deadline_slot: u64,
    /// Total quanta pre-minted to the airdrop pool as a string.
    pub pool_total_amount: String,
    /// Operator-declared sum of all claimable leaves as a string.
    /// Enforced: `expected_claim_sum <= pool_total_amount`. Must be set
    /// so that underfunding the pool fails genesis, not later claims.
    pub expected_claim_sum: String,
}

impl AirdropConfig {
    pub fn root_bytes(&self) -> Result<[u8; 32], String> {
        let hex = self.root.strip_prefix("0x").unwrap_or(&self.root);
        let bytes = hex::decode(hex).map_err(|e| format!("invalid airdrop root hex: {}", e))?;
        if bytes.len() != 32 {
            return Err(format!(
                "airdrop root must be 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    pub fn pool_total_u128(&self) -> Result<u128, String> {
        self.pool_total_amount.parse::<u128>().map_err(|e| {
            format!(
                "invalid airdrop.pool_total_amount '{}': {}",
                self.pool_total_amount, e
            )
        })
    }

    pub fn expected_sum_u128(&self) -> Result<u128, String> {
        self.expected_claim_sum.parse::<u128>().map_err(|e| {
            format!(
                "invalid airdrop.expected_claim_sum '{}': {}",
                self.expected_claim_sum, e
            )
        })
    }
}

/// Configuration for the validator bootstrap subsidy stream.
///
/// `total_amount` quanta are minted over `duration_slots` blocks
/// starting at genesis, distributed per-block to the ACTIVE validator
/// pool (identical share per validator). Operates as an add-on to
/// inflation — validators during the subsidy window earn
/// `inflation_share + subsidy_share` per block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSubsidyConfig {
    /// Total subsidy pool in quanta as string (to avoid TOML u128 limitation).
    pub total_amount: String,
    /// How many slots the subsidy streams for. After `genesis.timestamp +
    /// duration_slots × block_time`, the subsidy pool ends.
    pub duration_slots: u64,
}

impl ValidatorSubsidyConfig {
    pub fn total_u128(&self) -> Result<u128, String> {
        self.total_amount.parse::<u128>().map_err(|e| {
            format!(
                "invalid validator_subsidy.total_amount '{}': {}",
                self.total_amount, e
            )
        })
    }
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
    /// Optional allocation bucket label (Phase 4 slice 4.4). Pure
    /// metadata — not interpreted by the protocol, only useful for
    /// offline accounting ("did we actually put 30% in community?").
    /// Typical values: "team", "investors", "treasury", "community",
    /// "validator_subsidy", "liquidity".
    #[serde(default)]
    pub bucket: Option<String>,
    /// Optional vesting schedule. When present, the full `balance` is
    /// deposited but only the unlocked portion is spendable until the
    /// cliff is reached and linear vesting completes. See
    /// `pyde_tx::vesting::VestingSchedule` for the unlock curve.
    #[serde(default)]
    pub vesting: Option<GenesisVesting>,
}

/// Serialization-friendly vesting spec loaded from TOML.
///
/// Units are in SLOTS, not seconds. At 400ms slots the relationships:
///   1 day   = 216_000 slots
///   30 days = 6_480_000 slots
///   1 year  = 78_892_800 slots
/// Operators encode durations in slots to match the runtime.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisVesting {
    /// Slot at which vesting begins. Usually 0 (genesis).
    #[serde(default)]
    pub start_slot: u64,
    /// Slots from `start` during which nothing unlocks.
    pub cliff_slots: u64,
    /// Total vesting duration in slots (counted from `start`, not cliff).
    pub duration_slots: u64,
}

impl GenesisAllocation {
    pub fn balance_u128(&self) -> Result<u128, String> {
        self.balance
            .parse::<u128>()
            .map_err(|e| format!("invalid balance '{}': {}", self.balance, e))
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
        self.stake
            .parse::<u128>()
            .map_err(|e| format!("invalid stake '{}': {}", self.stake, e))
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
            initial_supply: String::new(),
            validator_subsidy: None,
            bucket_caps: std::collections::HashMap::new(),
            airdrop: None,
            multisig: None,
        }
    }
}

impl GenesisConfig {
    /// Load genesis config from a TOML file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read genesis config {}: {}", path.display(), e))?;
        toml::from_str(&content).map_err(|e| format!("failed to parse genesis config: {}", e))
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
    let mut bucket_totals: std::collections::HashMap<String, u128> =
        std::collections::HashMap::new();

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

        // Slice 4.4: install vesting schedule if the allocation specifies
        // one. The full `balance` is credited to the account immediately;
        // the protocol subtracts the locked portion from the spendable
        // balance during tx validation. Empty schedule is a no-op.
        if let Some(v) = &alloc.vesting {
            // `cliff > duration` is semantically nonsense (the cliff
            // would fall past the already-complete vesting window).
            // Reject at genesis so the config is sane by the time it
            // ships — a bug surfaced by slice 5.1 property tests.
            if v.cliff_slots > v.duration_slots {
                return Err(format!(
                    "vesting for {}: cliff_slots {} exceeds duration_slots {}",
                    alloc.address, v.cliff_slots, v.duration_slots
                ));
            }
            let schedule = pyde_tx::vesting::VestingSchedule {
                start_slot: v.start_slot,
                cliff_slots: v.cliff_slots,
                duration_slots: v.duration_slots,
                total_amount: balance,
            };
            entries.push((pyde_state::keys::vesting_key(&address), schedule.encode()));
        }

        debug!(
            address = alloc.address,
            balance,
            has_auth_keys = alloc.public_key.is_some(),
            bucket = alloc.bucket.as_deref().unwrap_or(""),
            vesting = alloc.vesting.is_some(),
            "genesis allocation"
        );

        total_supply = total_supply
            .checked_add(balance)
            .ok_or("genesis total supply overflow")?;

        // Slice 4.4a: accumulate per-bucket totals for cap enforcement.
        if let Some(name) = &alloc.bucket {
            let e = bucket_totals.entry(name.clone()).or_insert(0u128);
            *e = e.checked_add(balance).ok_or("bucket total overflow")?;
        }
    }

    // 2. Write validator stakes as balances (included in total supply).
    // Skip validators that already appear in allocations (they're already written with auth_keys).
    let alloc_addresses: std::collections::HashSet<String> = config
        .allocations
        .iter()
        .map(|a| {
            a.address
                .strip_prefix("0x")
                .unwrap_or(&a.address)
                .to_lowercase()
        })
        .collect();

    for val in &config.validators {
        let val_addr_normalized = val
            .address
            .strip_prefix("0x")
            .unwrap_or(&val.address)
            .to_lowercase();
        if alloc_addresses.contains(&val_addr_normalized) {
            debug!(
                address = val.address,
                "validator already in allocations, skipping duplicate"
            );
            continue;
        }

        let address = parse_hex_address(&val.address)?;
        let stake = val.stake_u128()?;

        // Parse public key to set auth_keys (validators must be able to sign)
        let pk_hex = val.public_key.strip_prefix("0x").unwrap_or(&val.public_key);
        let pk_bytes =
            hex::decode(pk_hex).map_err(|e| format!("invalid validator public key hex: {}", e))?;
        let mut account = pyde_account::types::Account::new_eoa(&pk_bytes);
        account.address = address;
        account.balance = stake;

        let balance_key = pyde_state::keys::balance_key(&address);
        entries.push((balance_key, account.to_bytes()));
        total_supply = total_supply
            .checked_add(stake)
            .ok_or("genesis total supply overflow")?;

        debug!(address = val.address, stake, "genesis validator");
    }

    // 3. Write validator registry entries (for epoch committee selection).
    // Use `ValidatorEntry::encode()` so the wire format stays aligned
    // with whatever `decode()` expects — the hand-rolled encoder here
    // previously omitted the `last_claimed_at` field, which meant
    // every decode() on a genesis entry returned None and the RPC
    // + slash + stake paths silently saw an empty validator set.
    let mut val_count: u64 = 0;
    for val in &config.validators {
        let address = parse_hex_address(&val.address)?;
        let pk_hex = val.public_key.strip_prefix("0x").unwrap_or(&val.public_key);
        let pk_bytes =
            hex::decode(pk_hex).map_err(|e| format!("invalid validator pk for registry: {}", e))?;
        let stake = val.stake_u128()?;

        let entry = pyde_tx::pipeline::ValidatorEntry {
            pk: pk_bytes,
            stake,
            status: 0x00, // Active
            last_claimed_at: 0,
            exit_block: None,
        };

        let key = pyde_state::keys::validator_key(&address);
        entries.push((key, entry.encode()));

        // Store address at index for enumeration
        let idx_key = pyde_state::keys::validator_index_key(val_count);
        entries.push((idx_key, address.to_vec()));
        val_count += 1;
    }

    // Store validator count
    let count_key = pyde_state::keys::validator_count_key();
    entries.push((count_key, val_count.to_le_bytes().to_vec()));

    // Slice 4.5: install governance multisig signer set + threshold.
    //
    // The signer set is used by MultisigTx (treasury spend) and
    // RotateMultisig (signer-set rotation). Nonce starts at 0 — each
    // successful multisig operation increments it so signatures bind
    // to a single execution.
    if let Some(ms) = &config.multisig {
        let pks = ms.decode_pks()?;
        if pks.is_empty() || pks.len() > pyde_tx::multisig::MAX_SIGNERS as usize {
            return Err(format!(
                "multisig.signer_public_keys count {} outside 1..={}",
                pks.len(),
                pyde_tx::multisig::MAX_SIGNERS
            ));
        }
        if ms.threshold == 0 || ms.threshold as usize > pks.len() {
            return Err(format!(
                "multisig.threshold {} must be in 1..={}",
                ms.threshold,
                pks.len()
            ));
        }
        // Duplicate-pk check.
        for i in 0..pks.len() {
            for j in (i + 1)..pks.len() {
                if pks[i] == pks[j] {
                    return Err(format!(
                        "multisig.signer_public_keys contains duplicate pk at indices {} and {}",
                        i, j
                    ));
                }
            }
        }
        entries.push((
            pyde_state::keys::multisig_signers_key(),
            pyde_tx::multisig::encode_signer_set(&pks),
        ));
        entries.push((
            pyde_state::keys::multisig_threshold_key(),
            vec![ms.threshold],
        ));
        entries.push((
            pyde_state::keys::multisig_nonce_key(),
            0u64.to_le_bytes().to_vec(),
        ));
    }

    // Slice 4.4b: pre-mint airdrop pool + install commitment.
    //
    // Pool is credited to the well-known `airdrop_pool_address()` so
    // `ClaimAirdrop` handlers debit it by exact leaf amount. The pool
    // amount is added to `total_supply` the same way any other
    // allocation is — so the 4.4a supply sanity check still holds.
    if let Some(air) = &config.airdrop {
        let root = air.root_bytes()?;
        let pool_total = air.pool_total_u128()?;
        let expected_sum = air.expected_sum_u128()?;

        if expected_sum > pool_total {
            return Err(format!(
                "airdrop underfunded: expected_claim_sum={} quanta but pool_total_amount={}",
                expected_sum, pool_total
            ));
        }

        let pool_addr = pyde_account::address::airdrop_pool_address();
        let pool_account = pyde_account::types::Account {
            address: pool_addr,
            nonce: 0,
            balance: pool_total,
            code_hash: sparse_merkle_tree::H256::zero(),
            storage_root: sparse_merkle_tree::H256::zero(),
            account_type: pyde_account::types::AccountType::EOA,
            auth_keys: pyde_account::types::AuthKeys::None,
            gas_tank: 0,
            key_nonce: 0,
        };
        entries.push((
            pyde_state::keys::balance_key(&pool_addr),
            pool_account.to_bytes(),
        ));

        entries.push((pyde_state::keys::airdrop_root_key(), root.to_vec()));
        entries.push((
            pyde_state::keys::airdrop_deadline_key(),
            air.deadline_slot.to_le_bytes().to_vec(),
        ));
        entries.push((
            pyde_state::keys::airdrop_expected_sum_key(),
            expected_sum.to_le_bytes().to_vec(),
        ));

        total_supply = total_supply
            .checked_add(pool_total)
            .ok_or("genesis total supply overflow")?;

        // Count the airdrop pool as its own bucket for per-bucket cap
        // enforcement. Operators who want to cap airdrop size pass
        // `bucket_caps["airdrop"] = N`.
        let e = bucket_totals.entry("airdrop".to_string()).or_insert(0u128);
        *e = e.checked_add(pool_total).ok_or("airdrop bucket overflow")?;
    }

    // Slice 4.4a: install validator bootstrap subsidy schedule.
    // `total_amount` was already included in `total_supply` if the
    // operator allocated it to the subsidy pool via a genesis
    // allocation; this record just instructs the block processor to
    // stream it to active validators.
    if let Some(vs) = &config.validator_subsidy {
        let total = vs.total_u128()?;
        if vs.duration_slots == 0 {
            return Err("validator_subsidy.duration_slots must be > 0".into());
        }
        let per_block = total / vs.duration_slots as u128;
        let schedule = pyde_tx::pipeline::ValidatorSubsidySchedule {
            per_block,
            end_slot: vs.duration_slots, // relative to slot 0 (genesis)
        };
        entries.push((pyde_state::keys::validator_subsidy_key(), schedule.encode()));
    }

    // Slice 4.4a: declared-vs-actual supply sanity check. When the
    // operator declares `initial_supply` in the config, verify the
    // sum of allocation balances matches. Catches fat-finger typos in
    // large allocation tables before the mainnet ceremony burns them
    // in. Empty string (default) preserves pre-4.4a behaviour.
    if !config.initial_supply.is_empty() {
        let declared = config
            .initial_supply
            .parse::<u128>()
            .map_err(|e| format!("invalid initial_supply '{}': {}", config.initial_supply, e))?;
        if declared != total_supply {
            return Err(format!(
                "genesis supply mismatch: config declares {} quanta but allocations sum to {}",
                declared, total_supply
            ));
        }
    }

    // Slice 4.4a: per-bucket cap enforcement. Each cap is integer
    // percent of `total_supply`. We use u128 arithmetic with explicit
    // multiplication to avoid float rounding and catch operators who
    // silently exceed their declared distribution targets. Caps only
    // apply when `initial_supply` was declared (otherwise percentages
    // have no reference point — we'd be dividing by the actual sum,
    // which is what the operator is trying to constrain in the first
    // place).
    if !config.bucket_caps.is_empty() {
        if config.initial_supply.is_empty() {
            return Err(
                "bucket_caps requires initial_supply to be declared (caps are percentages of supply)".into()
            );
        }
        for (bucket_name, cap_pct) in &config.bucket_caps {
            if *cap_pct > 100 {
                return Err(format!(
                    "bucket_caps['{}'] = {} is not a valid percentage",
                    bucket_name, cap_pct
                ));
            }
            let actual = bucket_totals.get(bucket_name).copied().unwrap_or(0);
            // actual * 100 > total * cap_pct  →  actual exceeds cap%
            let lhs = actual.checked_mul(100).ok_or("bucket cap math overflow")?;
            let rhs = total_supply
                .checked_mul(*cap_pct as u128)
                .ok_or("bucket cap math overflow")?;
            if lhs > rhs {
                return Err(format!(
                    "bucket '{}' exceeds cap: allocated {} quanta = {:.2}% of supply, cap is {}%",
                    bucket_name,
                    actual,
                    (actual as f64) * 100.0 / (total_supply as f64),
                    cap_pct,
                ));
            }
        }
    }

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
            bucket: None,
            vesting: None,
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
        initial_supply: String::new(),
        validator_subsidy: None,
        bucket_caps: std::collections::HashMap::new(),
        airdrop: None,
        multisig: None,
    };

    (config, accounts)
}

/// Generate a multi-validator testnet directory.
/// Creates: shared genesis.toml, per-node validator.key files, per-node config.toml files.
pub fn generate_testnet(
    out_dir: &std::path::Path,
    num_validators: usize,
    num_full_nodes: usize,
    base_port: u16,
    base_rpc_port: u16,
    dev_mode: bool,
    chain_id: u64,
    block_time_ms: u64,
) -> Result<(), String> {
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::falcon::falcon_keygen;
    use std::fs;

    if !(2..=128).contains(&num_validators) {
        return Err("validators must be between 2 and 128".into());
    }
    if num_full_nodes > 16 {
        return Err("full_nodes must be 0..=16".into());
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
            bucket: None,
            vesting: None,
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

    // Generate 5 non-validator funded accounts for testing
    for _ in 0..5 {
        let (pk, sk) = falcon_keygen().map_err(|e| format!("keygen failed: {}", e))?;
        let address = derive_eoa_address(pk.as_bytes());
        allocations.push(GenesisAllocation {
            address: hex::encode(address),
            balance: funding.to_string(),
            public_key: Some(hex::encode(pk.as_bytes())),
            bucket: None,
            vesting: None,
        });
        accounts.push(DevnetAccount {
            address,
            public_key: pk,
            secret_key: sk,
            balance: funding,
        });
    }

    // Generate dedicated faucet account (1 trillion PYDE for dispensing)
    let faucet_balance: u128 = 1_000_000_000_000 * 1_000_000_000; // 1T PYDE in quanta
    let (faucet_pk, faucet_sk) =
        falcon_keygen().map_err(|e| format!("faucet keygen failed: {}", e))?;
    let faucet_address = derive_eoa_address(faucet_pk.as_bytes());
    allocations.push(GenesisAllocation {
        address: hex::encode(faucet_address),
        balance: faucet_balance.to_string(),
        public_key: Some(hex::encode(faucet_pk.as_bytes())),
        bucket: None,
        vesting: None,
    });

    let genesis_config = GenesisConfig {
        chain_id,
        timestamp: 0,
        allocations,
        validators,
        initial_supply: String::new(),
        validator_subsidy: None,
        bucket_caps: std::collections::HashMap::new(),
        airdrop: None,
        multisig: None,
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
    // PSS refresh is wired into epoch boundary (node.rs:767, validator.rs:284).
    // Multi-party ceremony: use `pyde testnet` for distributed keygen.
    let threshold = pyde_consensus::block::quorum_for_committee(num_validators);
    let (threshold_pk, key_shares) =
        pyde_crypto::threshold::threshold_keygen(num_validators, threshold)
            .map_err(|e| format!("threshold keygen failed: {}", e))?;

    // Pre-generate node identity keys (Ed25519 for libp2p) so we know peer IDs
    // and can write full bootstrap multiaddrs in each config.
    //
    // Indexing convention: slots 0..num_validators hold validator keypairs;
    // slots num_validators..num_validators+num_full_nodes hold full-node
    // keypairs. Validator bootstrap lists include every OTHER validator;
    // full-node bootstrap lists include every validator (but no other full
    // nodes — they find each other via gossipsub once connected to a
    // validator).
    let total_nodes = num_validators + num_full_nodes;
    let mut node_keypairs: Vec<(libp2p::identity::Keypair, libp2p::PeerId)> =
        Vec::with_capacity(total_nodes);
    for _ in 0..total_nodes {
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
chain_id = {chain_id}
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
block_time_ms = {block_time_ms}
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
            block_time_ms = block_time_ms,
        );

        fs::write(node_dir.join("config.toml"), config_toml)
            .map_err(|e| format!("failed to write config.toml: {}", e))?;
    }

    // Write per-full-node directories. Full nodes share the same genesis
    // and threshold.pk as validators but have no validator.key, no
    // threshold.share, and a config with role = "full". Their bootstrap
    // list points to every validator.
    for f in 0..num_full_nodes {
        let i = num_validators + f;
        let node_dir = out_dir.join(format!("node-{}", i));
        fs::create_dir_all(&node_dir)
            .map_err(|e| format!("failed to create {}: {}", node_dir.display(), e))?;

        // node.key
        let node_key_bytes = pyde_net::node::keypair_to_bytes(&node_keypairs[i].0)
            .map_err(|e| format!("failed to serialize node key: {}", e))?;
        fs::write(node_dir.join("node.key"), &node_key_bytes)
            .map_err(|e| format!("failed to write node.key: {}", e))?;

        // threshold.pk (shared — same for every node).
        fs::write(node_dir.join("threshold.pk"), threshold_pk.to_bytes())
            .map_err(|e| format!("failed to write threshold.pk: {}", e))?;

        // Copy genesis.toml.
        fs::write(node_dir.join("genesis.toml"), genesis_config.to_toml())
            .map_err(|e| format!("failed to write genesis.toml: {}", e))?;

        // Bootstrap list: all validators.
        let mut bootstrap_addrs: Vec<String> = Vec::new();
        for j in 0..num_validators {
            let other_port = base_port + j as u16;
            let other_peer_id = &node_keypairs[j].1;
            bootstrap_addrs.push(format!(
                "\"/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}\"",
                other_port, other_peer_id
            ));
        }
        let bootstrap = format!("[{}]", bootstrap_addrs.join(", "));

        let p2p_port = base_port + i as u16;
        let rpc_port = base_rpc_port + i as u16;
        let metrics_port = 9090 + i as u16;

        let config_toml = format!(
            r#"[node]
role = "full"
chain_id = {chain_id}
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
block_time_ms = {block_time_ms}
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
            block_time_ms = block_time_ms,
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
    fs::write(&script_path, run_script).map_err(|e| format!("failed to write run.sh: {}", e))?;
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
    println!("Chain ID:   {}", chain_id);
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
    // Write accounts.json for E2E test scripts (addresses + private keys)
    {
        let mut accts = Vec::new();
        for acc in &accounts {
            accts.push(serde_json::json!({
                "address": acc.address_hex(),
                "privateKey": acc.private_key_hex(),
                "balance": acc.balance.to_string(),
            }));
        }
        accts.push(serde_json::json!({
            "address": format!("0x{}", hex::encode(faucet_address)),
            "privateKey": format!("0x{}", hex::encode(faucet_pk.as_bytes()) + &hex::encode(faucet_sk.as_bytes())),
            "balance": faucet_balance.to_string(),
            "faucet": true,
        }));
        let json = serde_json::json!({ "chainId": chain_id, "accounts": accts });
        let _ = fs::write(
            out_dir.join("accounts.json"),
            serde_json::to_string_pretty(&json).unwrap_or_default(),
        );
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
        println!(
            "  node-{}/config.toml  — node {} config (P2P:{}, RPC:{})",
            i,
            i,
            base_port + i as u16,
            base_rpc_port + i as u16
        );
        println!("  node-{}/validator.key — node {} signing key", i, i);
    }
    println!();
    println!("To start:");
    println!("  # Terminal 1 (node-0):");
    println!(
        "  pyde run --role validator --config {}/node-0/config.toml --datadir {}/node-0{}",
        out_dir.display(),
        out_dir.display(),
        if dev_mode { " --dev" } else { "" }
    );
    println!();
    println!("  # Terminal 2 (node-1 — copy bootstrap addr from node-0 output):");
    println!("  pyde run --role validator --config {}/node-1/config.toml --datadir {}/node-1 --bootstrap \"<node-0-multiaddr>\"{}",
        out_dir.display(), out_dir.display(), if dev_mode { " --dev" } else { "" });
    println!();
    println!("  # Faucet:");
    println!(
        "  pyde faucet --rpc http://127.0.0.1:8545 --from 0x{} --private-key {}/faucet.key",
        hex::encode(faucet_address),
        out_dir.display()
    );

    Ok(())
}

/// Parse a hex-encoded 32-byte address.
#[allow(dead_code)]
pub fn parse_hex_address_pub(hex_str: &str) -> Result<Address, String> {
    parse_hex_address(hex_str)
}

fn parse_hex_address(hex_str: &str) -> Result<Address, String> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes =
        hex::decode(hex_str).map_err(|e| format!("invalid hex address '{}': {}", hex_str, e))?;
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
        let dir = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(dir.path(), 1024).unwrap();

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
        let dir = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(dir.path(), 1024).unwrap();

        let (config, _) = devnet_genesis();
        initialize_genesis(&mut state, &config).unwrap();
        let result = initialize_genesis(&mut state, &config);
        assert!(result.is_err());
    }

    // ========== Slice 4.4a: sanity check + validator subsidy ==========

    fn tiny_alloc(addr: [u8; 32], balance: u128) -> GenesisAllocation {
        GenesisAllocation {
            address: hex::encode(addr),
            balance: balance.to_string(),
            public_key: None,
            bucket: None,
            vesting: None,
        }
    }

    #[test]
    fn genesis_supply_sanity_check_matches() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let config = GenesisConfig {
            chain_id: 31337,
            timestamp: 0,
            allocations: vec![
                tiny_alloc([0x01; 32], 100),
                tiny_alloc([0x02; 32], 200),
                tiny_alloc([0x03; 32], 700),
            ],
            validators: Vec::new(),
            initial_supply: "1000".to_string(),
            validator_subsidy: None,
            bucket_caps: std::collections::HashMap::new(),
            airdrop: None,
            multisig: None,
        };
        initialize_genesis(&mut state, &config).expect("matching sum should accept");
    }

    #[test]
    fn genesis_supply_sanity_check_rejects_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let config = GenesisConfig {
            chain_id: 31337,
            timestamp: 0,
            allocations: vec![tiny_alloc([0x01; 32], 100), tiny_alloc([0x02; 32], 200)],
            validators: Vec::new(),
            initial_supply: "500".to_string(), // allocations sum to 300 — mismatch
            validator_subsidy: None,
            bucket_caps: std::collections::HashMap::new(),
            airdrop: None,
            multisig: None,
        };
        let err = initialize_genesis(&mut state, &config).unwrap_err();
        assert!(err.contains("genesis supply mismatch"), "got: {}", err);
    }

    #[test]
    fn genesis_supply_sanity_check_empty_means_no_check() {
        // Default behaviour: no declared supply → no check, anything
        // allocations add up to is accepted. Preserves pre-4.4a devnet flows.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let config = GenesisConfig {
            chain_id: 31337,
            timestamp: 0,
            allocations: vec![tiny_alloc([0x01; 32], 999)],
            validators: Vec::new(),
            initial_supply: String::new(),
            validator_subsidy: None,
            bucket_caps: std::collections::HashMap::new(),
            airdrop: None,
            multisig: None,
        };
        initialize_genesis(&mut state, &config).unwrap();
    }

    #[test]
    fn genesis_writes_validator_subsidy_schedule() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let config = GenesisConfig {
            chain_id: 31337,
            timestamp: 0,
            allocations: vec![tiny_alloc([0x01; 32], 100_000_000)],
            validators: Vec::new(),
            initial_supply: String::new(),
            validator_subsidy: Some(ValidatorSubsidyConfig {
                total_amount: "100_000_000".replace("_", ""),
                duration_slots: 1_000,
            }),
            bucket_caps: std::collections::HashMap::new(),
            airdrop: None,
            multisig: None,
        };
        initialize_genesis(&mut state, &config).unwrap();

        let sched = pyde_tx::pipeline::read_validator_subsidy(&state)
            .expect("subsidy schedule must be installed");
        assert_eq!(sched.per_block, 100_000_000 / 1_000);
        assert_eq!(sched.end_slot, 1_000);
    }

    #[test]
    fn genesis_rejects_zero_duration_subsidy() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let config = GenesisConfig {
            chain_id: 31337,
            timestamp: 0,
            allocations: vec![tiny_alloc([0x01; 32], 100)],
            validators: Vec::new(),
            initial_supply: String::new(),
            validator_subsidy: Some(ValidatorSubsidyConfig {
                total_amount: "100".to_string(),
                duration_slots: 0,
            }),
            bucket_caps: std::collections::HashMap::new(),
            airdrop: None,
            multisig: None,
        };
        let err = initialize_genesis(&mut state, &config).unwrap_err();
        assert!(err.contains("duration_slots must be > 0"));
    }

    fn alloc_with_bucket(addr: [u8; 32], balance: u128, bucket: &str) -> GenesisAllocation {
        GenesisAllocation {
            address: hex::encode(addr),
            balance: balance.to_string(),
            public_key: None,
            bucket: Some(bucket.to_string()),
            vesting: None,
        }
    }

    #[test]
    fn bucket_caps_accept_under_limit() {
        // 15% of 1000 = 150; team bucket at 100 → within cap.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let mut caps = std::collections::HashMap::new();
        caps.insert("team".to_string(), 15);
        caps.insert("treasury".to_string(), 90);
        let config = GenesisConfig {
            chain_id: 31337,
            timestamp: 0,
            allocations: vec![
                alloc_with_bucket([0x01; 32], 100, "team"),
                alloc_with_bucket([0x02; 32], 900, "treasury"),
            ],
            validators: Vec::new(),
            initial_supply: "1000".to_string(),
            validator_subsidy: None,
            bucket_caps: caps,
            airdrop: None,
            multisig: None,
        };
        initialize_genesis(&mut state, &config).unwrap();
    }

    #[test]
    fn bucket_caps_reject_over_limit() {
        // team cap 15% of 1000 = 150, allocation gives 200 → rejected.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let mut caps = std::collections::HashMap::new();
        caps.insert("team".to_string(), 15);
        let config = GenesisConfig {
            chain_id: 31337,
            timestamp: 0,
            allocations: vec![
                alloc_with_bucket([0x01; 32], 200, "team"),
                alloc_with_bucket([0x02; 32], 800, "treasury"),
            ],
            validators: Vec::new(),
            initial_supply: "1000".to_string(),
            validator_subsidy: None,
            bucket_caps: caps,
            airdrop: None,
            multisig: None,
        };
        let err = initialize_genesis(&mut state, &config).unwrap_err();
        assert!(err.contains("bucket 'team' exceeds cap"), "got: {}", err);
    }

    #[test]
    fn bucket_caps_require_declared_supply() {
        // Caps are percentages; without `initial_supply` there's no
        // reference denominator → reject the config.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let mut caps = std::collections::HashMap::new();
        caps.insert("team".to_string(), 15);
        let config = GenesisConfig {
            chain_id: 31337,
            timestamp: 0,
            allocations: vec![alloc_with_bucket([0x01; 32], 100, "team")],
            validators: Vec::new(),
            initial_supply: String::new(),
            validator_subsidy: None,
            bucket_caps: caps,
            airdrop: None,
            multisig: None,
        };
        let err = initialize_genesis(&mut state, &config).unwrap_err();
        assert!(err.contains("requires initial_supply"), "got: {}", err);
    }

    #[test]
    fn bucket_caps_reject_invalid_percentage() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let mut caps = std::collections::HashMap::new();
        caps.insert("team".to_string(), 101); // > 100
        let config = GenesisConfig {
            chain_id: 31337,
            timestamp: 0,
            allocations: vec![alloc_with_bucket([0x01; 32], 100, "team")],
            validators: Vec::new(),
            initial_supply: "100".to_string(),
            validator_subsidy: None,
            bucket_caps: caps,
            airdrop: None,
            multisig: None,
        };
        let err = initialize_genesis(&mut state, &config).unwrap_err();
        assert!(err.contains("not a valid percentage"), "got: {}", err);
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

    // ========== Slice 4.4b: airdrop commitment ==========

    fn airdrop_cfg(root: [u8; 32], pool: u128, expected: u128, deadline: u64) -> AirdropConfig {
        AirdropConfig {
            root: hex::encode(root),
            deadline_slot: deadline,
            pool_total_amount: pool.to_string(),
            expected_claim_sum: expected.to_string(),
        }
    }

    #[test]
    fn genesis_writes_airdrop_root_and_funds_pool() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let (root, _) =
            pyde_tx::airdrop::build_tree(&[([0x11; 32], 500u128), ([0x22; 32], 500u128)]);

        let config = GenesisConfig {
            chain_id: 1,
            timestamp: 0,
            allocations: vec![tiny_alloc([0xAA; 32], 200)],
            validators: Vec::new(),
            initial_supply: "1200".to_string(), // 200 alloc + 1000 pool
            validator_subsidy: None,
            bucket_caps: std::collections::HashMap::new(),
            airdrop: Some(airdrop_cfg(root, 1000, 1000, 10_000)),
            multisig: None,
        };
        initialize_genesis(&mut state, &config).expect("airdrop genesis should accept");

        // Root stored
        let root_bytes = state.get(&pyde_state::keys::airdrop_root_key()).unwrap();
        assert_eq!(root_bytes.len(), 32);
        assert_eq!(&root_bytes[..], &root[..]);
        // Deadline stored
        let deadline_bytes = state
            .get(&pyde_state::keys::airdrop_deadline_key())
            .unwrap();
        let deadline = u64::from_le_bytes(deadline_bytes[..8].try_into().unwrap());
        assert_eq!(deadline, 10_000);
        // Pool funded to exactly pool_total_amount
        let pool_addr = pyde_account::address::airdrop_pool_address();
        let bytes = state
            .get(&pyde_state::keys::balance_key(&pool_addr))
            .unwrap();
        let account = pyde_account::types::Account::from_bytes(&bytes).unwrap();
        assert_eq!(account.balance, 1000);
    }

    #[test]
    fn genesis_rejects_underfunded_airdrop_pool() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let (root, _) = pyde_tx::airdrop::build_tree(&[([0x11; 32], 2000u128)]);

        let config = GenesisConfig {
            chain_id: 1,
            timestamp: 0,
            allocations: vec![],
            validators: Vec::new(),
            initial_supply: "1000".to_string(),
            validator_subsidy: None,
            bucket_caps: std::collections::HashMap::new(),
            // expected_claim_sum (2000) > pool_total (1000) → underfunded
            airdrop: Some(airdrop_cfg(root, 1000, 2000, 10_000)),
            multisig: None,
        };
        let err = initialize_genesis(&mut state, &config).unwrap_err();
        assert!(err.contains("airdrop underfunded"), "got: {}", err);
    }

    #[test]
    fn genesis_airdrop_pool_counts_toward_supply() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let (root, _) = pyde_tx::airdrop::build_tree(&[([0x11; 32], 500u128)]);

        let config = GenesisConfig {
            chain_id: 1,
            timestamp: 0,
            allocations: vec![tiny_alloc([0xAA; 32], 300)],
            validators: Vec::new(),
            // Declared supply 700 = 300 alloc + 400 pool. If the pool
            // weren't counted toward total_supply, the sanity check
            // would see 300 ≠ 700 and reject. Successful acceptance
            // proves pool balance flows into the total.
            initial_supply: "700".to_string(),
            validator_subsidy: None,
            bucket_caps: std::collections::HashMap::new(),
            airdrop: Some(airdrop_cfg(root, 400, 400, 10_000)),
            multisig: None,
        };
        // 300 + 400 = 700, matches declared → accepts.
        initialize_genesis(&mut state, &config).expect("declared supply includes pool");
    }

    #[test]
    fn genesis_rejects_invalid_airdrop_root_hex() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let mut config = GenesisConfig {
            chain_id: 1,
            timestamp: 0,
            allocations: vec![],
            validators: Vec::new(),
            initial_supply: "100".to_string(),
            validator_subsidy: None,
            bucket_caps: std::collections::HashMap::new(),
            airdrop: Some(AirdropConfig {
                root: "not-hex".to_string(),
                deadline_slot: 100,
                pool_total_amount: "100".to_string(),
                expected_claim_sum: "100".to_string(),
            }),
            multisig: None,
        };
        let err = initialize_genesis(&mut state, &config).unwrap_err();
        assert!(err.contains("invalid airdrop root hex"), "got: {}", err);

        // Wrong length (16 bytes instead of 32)
        config.airdrop.as_mut().unwrap().root = hex::encode([0xAB; 16]);
        let err = initialize_genesis(&mut state, &config).unwrap_err();
        assert!(
            err.contains("airdrop root must be 32 bytes"),
            "got: {}",
            err
        );
    }

    #[test]
    fn genesis_airdrop_honors_bucket_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let (root, _) = pyde_tx::airdrop::build_tree(&[([0x11; 32], 300u128)]);

        let mut caps = std::collections::HashMap::new();
        caps.insert("airdrop".to_string(), 20u32); // cap 20% of 1000 = 200

        let config = GenesisConfig {
            chain_id: 1,
            timestamp: 0,
            allocations: vec![tiny_alloc([0xAA; 32], 700)],
            validators: Vec::new(),
            initial_supply: "1000".to_string(),
            validator_subsidy: None,
            bucket_caps: caps,
            // Pool is 300 quanta = 30% of 1000 → exceeds 20% cap.
            airdrop: Some(airdrop_cfg(root, 300, 300, 10_000)),
            multisig: None,
        };
        let err = initialize_genesis(&mut state, &config).unwrap_err();
        assert!(err.contains("bucket 'airdrop' exceeds cap"), "got: {}", err);
    }

    // ========== Slice 4.5: multisig governance ==========

    fn multisig_cfg(
        n: usize,
        threshold: u8,
    ) -> (MultisigConfig, Vec<pyde_crypto::falcon::FalconSecretKey>) {
        use pyde_crypto::falcon::falcon_keygen;
        let mut pk_hexes = Vec::with_capacity(n);
        let mut sks = Vec::with_capacity(n);
        for _ in 0..n {
            let (pk, sk) = falcon_keygen().unwrap();
            pk_hexes.push(hex::encode(pk.as_bytes()));
            sks.push(sk);
        }
        (
            MultisigConfig {
                signer_public_keys: pk_hexes,
                threshold,
            },
            sks,
        )
    }

    #[test]
    fn genesis_installs_multisig() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let (ms_cfg, _) = multisig_cfg(5, 3);

        let config = GenesisConfig {
            chain_id: 1,
            timestamp: 0,
            allocations: vec![],
            validators: Vec::new(),
            initial_supply: String::new(),
            validator_subsidy: None,
            bucket_caps: std::collections::HashMap::new(),
            airdrop: None,
            multisig: Some(ms_cfg),
        };
        initialize_genesis(&mut state, &config).expect("multisig genesis should accept");

        // Threshold stored.
        let threshold_bytes = state
            .get(&pyde_state::keys::multisig_threshold_key())
            .unwrap();
        assert_eq!(threshold_bytes, vec![3u8]);

        // Nonce initialized to 0.
        let nonce_bytes = state.get(&pyde_state::keys::multisig_nonce_key()).unwrap();
        assert_eq!(nonce_bytes, 0u64.to_le_bytes().to_vec());

        // Signer set parseable.
        let set_bytes = state
            .get(&pyde_state::keys::multisig_signers_key())
            .unwrap();
        let decoded = pyde_tx::multisig::decode_signer_set(&set_bytes).unwrap();
        assert_eq!(decoded.len(), 5);
    }

    #[test]
    fn genesis_rejects_multisig_threshold_over_count() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let (mut ms_cfg, _) = multisig_cfg(3, 2);
        ms_cfg.threshold = 10; // > count

        let config = GenesisConfig {
            chain_id: 1,
            timestamp: 0,
            allocations: vec![],
            validators: Vec::new(),
            initial_supply: String::new(),
            validator_subsidy: None,
            bucket_caps: std::collections::HashMap::new(),
            airdrop: None,
            multisig: Some(ms_cfg),
        };
        let err = initialize_genesis(&mut state, &config).unwrap_err();
        assert!(err.contains("multisig.threshold"), "got: {}", err);
    }

    #[test]
    fn genesis_rejects_multisig_zero_threshold() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let (mut ms_cfg, _) = multisig_cfg(3, 2);
        ms_cfg.threshold = 0;

        let config = GenesisConfig {
            chain_id: 1,
            timestamp: 0,
            allocations: vec![],
            validators: Vec::new(),
            initial_supply: String::new(),
            validator_subsidy: None,
            bucket_caps: std::collections::HashMap::new(),
            airdrop: None,
            multisig: Some(ms_cfg),
        };
        let err = initialize_genesis(&mut state, &config).unwrap_err();
        assert!(err.contains("multisig.threshold"), "got: {}", err);
    }

    #[test]
    fn genesis_rejects_duplicate_multisig_pk() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let (mut ms_cfg, _) = multisig_cfg(3, 2);
        ms_cfg.signer_public_keys[1] = ms_cfg.signer_public_keys[0].clone();

        let config = GenesisConfig {
            chain_id: 1,
            timestamp: 0,
            allocations: vec![],
            validators: Vec::new(),
            initial_supply: String::new(),
            validator_subsidy: None,
            bucket_caps: std::collections::HashMap::new(),
            airdrop: None,
            multisig: Some(ms_cfg),
        };
        let err = initialize_genesis(&mut state, &config).unwrap_err();
        assert!(err.contains("duplicate pk"), "got: {}", err);
    }

    #[test]
    fn genesis_rejects_multisig_over_max_signers() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let (ms_cfg, _) = multisig_cfg(pyde_tx::multisig::MAX_SIGNERS as usize + 1, 2);

        let config = GenesisConfig {
            chain_id: 1,
            timestamp: 0,
            allocations: vec![],
            validators: Vec::new(),
            initial_supply: String::new(),
            validator_subsidy: None,
            bucket_caps: std::collections::HashMap::new(),
            airdrop: None,
            multisig: Some(ms_cfg),
        };
        let err = initialize_genesis(&mut state, &config).unwrap_err();
        assert!(err.contains("signer_public_keys count"), "got: {}", err);
    }

    // ========== Slice 5.1: surfaced vesting misconfig ==========

    #[test]
    fn genesis_rejects_vesting_cliff_exceeds_duration() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let alloc = GenesisAllocation {
            address: hex::encode([0xAB; 32]),
            balance: "1000".to_string(),
            public_key: None,
            bucket: None,
            vesting: Some(GenesisVesting {
                start_slot: 0,
                cliff_slots: 1000,
                duration_slots: 100, // cliff > duration: nonsense
            }),
        };
        let config = GenesisConfig {
            chain_id: 1,
            timestamp: 0,
            allocations: vec![alloc],
            validators: Vec::new(),
            initial_supply: String::new(),
            validator_subsidy: None,
            bucket_caps: std::collections::HashMap::new(),
            airdrop: None,
            multisig: None,
        };
        let err = initialize_genesis(&mut state, &config).unwrap_err();
        assert!(
            err.contains("cliff_slots") && err.contains("exceeds duration_slots"),
            "got: {}",
            err
        );
    }
}
