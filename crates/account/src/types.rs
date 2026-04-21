//! Account types and serialization per Chapter 11 spec.
//!
//! Every account has: address, nonce, balance, code_hash, storage_root,
//! account_type, auth_keys, gas_tank, key_nonce.

use pyde_crypto::poseidon2::poseidon2_hash;
use pyde_state::keys::Address;
use sparse_merkle_tree::H256;

/// Account type tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AccountType {
    /// Externally Owned Account — controlled by a private key, no code.
    EOA = 0,
    /// Smart contract — has deployed bytecode and storage.
    Contract = 1,
    /// System account — native protocol functions (staking, governance, etc.).
    System = 2,
}

impl AccountType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(AccountType::EOA),
            1 => Some(AccountType::Contract),
            2 => Some(AccountType::System),
            _ => None,
        }
    }
}

/// Authorization keys for the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthKeys {
    /// No keys (system accounts, contracts without admin).
    None,
    /// Single FALCON-512 public key (standard EOA).
    Single(Vec<u8>),
    /// Multi-sig: list of keys + threshold required to authorize.
    MultiSig { keys: Vec<Vec<u8>>, threshold: u32 },
}

impl AuthKeys {
    /// Serialize auth keys to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            AuthKeys::None => vec![0x00],
            AuthKeys::Single(pk) => {
                let mut buf = vec![0x01];
                buf.extend_from_slice(&(pk.len() as u32).to_le_bytes());
                buf.extend_from_slice(pk);
                buf
            }
            AuthKeys::MultiSig { keys, threshold } => {
                let mut buf = vec![0x02];
                buf.extend_from_slice(&threshold.to_le_bytes());
                buf.extend_from_slice(&(keys.len() as u32).to_le_bytes());
                for k in keys {
                    buf.extend_from_slice(&(k.len() as u32).to_le_bytes());
                    buf.extend_from_slice(k);
                }
                buf
            }
        }
    }

    /// Deserialize auth keys from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        match data[0] {
            0x00 => Some(AuthKeys::None),
            0x01 => {
                if data.len() < 5 {
                    return None;
                }
                let len = u32::from_le_bytes(data[1..5].try_into().ok()?) as usize;
                if data.len() < 5 + len {
                    return None;
                }
                Some(AuthKeys::Single(data[5..5 + len].to_vec()))
            }
            0x02 => {
                if data.len() < 9 {
                    return None;
                }
                let threshold = u32::from_le_bytes(data[1..5].try_into().ok()?);
                let num_keys = u32::from_le_bytes(data[5..9].try_into().ok()?) as usize;
                let mut keys = Vec::with_capacity(num_keys);
                let mut offset = 9;
                for _ in 0..num_keys {
                    if offset + 4 > data.len() {
                        return None;
                    }
                    let klen =
                        u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
                    offset += 4;
                    if offset + klen > data.len() {
                        return None;
                    }
                    keys.push(data[offset..offset + klen].to_vec());
                    offset += klen;
                }
                Some(AuthKeys::MultiSig { keys, threshold })
            }
            _ => None,
        }
    }
}

/// The core account structure per Chapter 11 spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    /// 32-byte address (Poseidon2 hash of FALCON public key).
    pub address: Address,
    /// Transaction sequence counter.
    pub nonce: u64,
    /// Spendable PYDE balance (in quanta, 10^9 quanta = 1 PYDE).
    pub balance: u128,
    /// Poseidon2 hash of deployed bytecode. Zero for EOAs.
    pub code_hash: H256,
    /// Root of account's storage Merkle trie. Zero for empty.
    pub storage_root: H256,
    /// Account type (EOA, Contract, System).
    pub account_type: AccountType,
    /// Public key(s) authorized to sign for this account.
    pub auth_keys: AuthKeys,
    /// Gas tank balance for sponsored transactions.
    pub gas_tank: u128,
    /// Key rotation nonce (increments on key change).
    pub key_nonce: u32,
}

impl Account {
    /// Create a new EOA with a FALCON public key.
    pub fn new_eoa(falcon_public_key: &[u8]) -> Self {
        let address = pyde_state::keys::derive_address(falcon_public_key);
        Self {
            address,
            nonce: 0,
            balance: 0,
            code_hash: H256::zero(),
            storage_root: H256::zero(),
            account_type: AccountType::EOA,
            auth_keys: AuthKeys::Single(falcon_public_key.to_vec()),
            gas_tank: 0,
            key_nonce: 0,
        }
    }

    /// Create a new contract account from deployment.
    pub fn new_contract(address: Address, code: &[u8]) -> Self {
        let code_hash = H256::from(poseidon2_hash(code).to_bytes());
        Self {
            address,
            nonce: 0,
            balance: 0,
            code_hash,
            storage_root: H256::zero(),
            account_type: AccountType::Contract,
            auth_keys: AuthKeys::None,
            gas_tank: 0,
            key_nonce: 0,
        }
    }

    /// Create a system account at a fixed address.
    pub fn new_system(address: Address) -> Self {
        Self {
            address,
            nonce: 0,
            balance: 0,
            code_hash: H256::zero(),
            storage_root: H256::zero(),
            account_type: AccountType::System,
            auth_keys: AuthKeys::None,
            gas_tank: 0,
            key_nonce: 0,
        }
    }

    /// Serialize account to bytes for storage in SMT leaf.
    pub fn to_bytes(&self) -> Vec<u8> {
        let auth_bytes = self.auth_keys.to_bytes();
        // Fixed fields: 32 (addr) + 8 (nonce) + 16 (balance) + 32 (code_hash)
        //   + 32 (storage_root) + 1 (type) + 16 (gas_tank) + 4 (key_nonce) = 141
        // Variable: 4 (auth_len) + auth_bytes
        let mut buf = Vec::with_capacity(141 + 4 + auth_bytes.len());
        buf.extend_from_slice(&self.address);
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&self.balance.to_le_bytes());
        buf.extend_from_slice(self.code_hash.as_slice());
        buf.extend_from_slice(self.storage_root.as_slice());
        buf.push(self.account_type as u8);
        buf.extend_from_slice(&self.gas_tank.to_le_bytes());
        buf.extend_from_slice(&self.key_nonce.to_le_bytes());
        buf.extend_from_slice(&(auth_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&auth_bytes);
        buf
    }

    /// Deserialize account from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 145 {
            // 141 fixed + 4 auth_len minimum
            return None;
        }
        let address: Address = data[0..32].try_into().ok()?;
        let nonce = u64::from_le_bytes(data[32..40].try_into().ok()?);
        let balance = u128::from_le_bytes(data[40..56].try_into().ok()?);
        let code_hash = H256::from(<[u8; 32]>::try_from(&data[56..88]).ok()?);
        let storage_root = H256::from(<[u8; 32]>::try_from(&data[88..120]).ok()?);
        let account_type = AccountType::from_u8(data[120])?;
        let gas_tank = u128::from_le_bytes(data[121..137].try_into().ok()?);
        let key_nonce = u32::from_le_bytes(data[137..141].try_into().ok()?);
        let auth_len = u32::from_le_bytes(data[141..145].try_into().ok()?) as usize;
        if data.len() < 145 + auth_len {
            return None;
        }
        let auth_keys = AuthKeys::from_bytes(&data[145..145 + auth_len])?;

        Some(Self {
            address,
            nonce,
            balance,
            code_hash,
            storage_root,
            account_type,
            auth_keys,
            gas_tank,
            key_nonce,
        })
    }

    /// Whether this is an EOA (no code).
    pub fn is_eoa(&self) -> bool {
        self.account_type == AccountType::EOA
    }

    /// Whether this is a contract.
    pub fn is_contract(&self) -> bool {
        self.account_type == AccountType::Contract
    }

    /// Whether this is a system account.
    pub fn is_system(&self) -> bool {
        self.account_type == AccountType::System
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Task 0348: EOA creation and balance update ==========

    #[test]
    fn eoa_creation() {
        let fake_pk = vec![0xABu8; 897]; // FALCON-512 public key size
        let account = Account::new_eoa(&fake_pk);

        assert!(account.is_eoa());
        assert!(!account.is_contract());
        assert_eq!(account.nonce, 0);
        assert_eq!(account.balance, 0);
        assert_eq!(account.code_hash, H256::zero());
        assert_eq!(account.storage_root, H256::zero());
        assert_eq!(account.gas_tank, 0);
        assert_ne!(account.address, [0u8; 32]);
    }

    #[test]
    fn eoa_balance_update() {
        let fake_pk = vec![0xABu8; 897];
        let mut account = Account::new_eoa(&fake_pk);
        account.balance = 1_000_000_000; // 1 PYDE
        assert_eq!(account.balance, 1_000_000_000);
    }

    // ========== Task 0349: Contract account creation ==========

    #[test]
    fn contract_creation() {
        let code = b"contract bytecode here";
        let addr = pyde_state::keys::derive_address(b"deployer");
        let account = Account::new_contract(addr, code);

        assert!(account.is_contract());
        assert!(!account.is_eoa());
        assert_ne!(account.code_hash, H256::zero());
        assert_eq!(account.auth_keys, AuthKeys::None);
    }

    #[test]
    fn system_account() {
        let addr = [0x01u8; 32];
        let account = Account::new_system(addr);
        assert!(account.is_system());
        assert_eq!(account.balance, 0);
    }

    // ========== Task 0350: Serialize/deserialize roundtrip ==========

    #[test]
    fn serialize_deserialize_eoa() {
        let fake_pk = vec![0xCDu8; 897];
        let mut account = Account::new_eoa(&fake_pk);
        account.nonce = 42;
        account.balance = 5_000_000_000;
        account.gas_tank = 1_000;
        account.key_nonce = 3;

        let bytes = account.to_bytes();
        let restored = Account::from_bytes(&bytes).unwrap();
        assert_eq!(account, restored);
    }

    #[test]
    fn serialize_deserialize_contract() {
        let addr = pyde_state::keys::derive_address(b"contract_deployer");
        let mut account = Account::new_contract(addr, b"code");
        account.balance = 100;
        account.storage_root = H256::from([0xAA; 32]);

        let bytes = account.to_bytes();
        let restored = Account::from_bytes(&bytes).unwrap();
        assert_eq!(account, restored);
    }

    #[test]
    fn serialize_deserialize_system() {
        let account = Account::new_system([0x02; 32]);
        let bytes = account.to_bytes();
        let restored = Account::from_bytes(&bytes).unwrap();
        assert_eq!(account, restored);
    }

    #[test]
    fn serialize_deserialize_multisig() {
        let mut account = Account::new_eoa(&[0xAA; 897]);
        account.auth_keys = AuthKeys::MultiSig {
            keys: vec![vec![0x11; 897], vec![0x22; 897], vec![0x33; 897]],
            threshold: 2,
        };

        let bytes = account.to_bytes();
        let restored = Account::from_bytes(&bytes).unwrap();
        assert_eq!(account, restored);
    }

    #[test]
    fn deserialize_corrupt_returns_none() {
        assert_eq!(Account::from_bytes(&[]), None);
        assert_eq!(Account::from_bytes(&[0; 10]), None);
        // Invalid account type
        let mut bytes = Account::new_eoa(&[0; 897]).to_bytes();
        bytes[120] = 0xFF; // corrupt type byte
        assert_eq!(Account::from_bytes(&bytes), None);
    }

    // ========== AuthKeys serialization ==========

    #[test]
    fn auth_keys_none_roundtrip() {
        let ak = AuthKeys::None;
        let bytes = ak.to_bytes();
        assert_eq!(AuthKeys::from_bytes(&bytes), Some(AuthKeys::None));
    }

    #[test]
    fn auth_keys_single_roundtrip() {
        let ak = AuthKeys::Single(vec![0xAB; 897]);
        let bytes = ak.to_bytes();
        let restored = AuthKeys::from_bytes(&bytes).unwrap();
        assert_eq!(ak, restored);
    }

    #[test]
    fn auth_keys_multisig_roundtrip() {
        let ak = AuthKeys::MultiSig {
            keys: vec![vec![0x11; 32], vec![0x22; 32]],
            threshold: 2,
        };
        let bytes = ak.to_bytes();
        let restored = AuthKeys::from_bytes(&bytes).unwrap();
        assert_eq!(ak, restored);
    }

    // ========== Address determinism ==========

    #[test]
    fn same_key_same_address() {
        let pk = vec![0xAB; 897];
        let a1 = Account::new_eoa(&pk);
        let a2 = Account::new_eoa(&pk);
        assert_eq!(a1.address, a2.address);
    }

    #[test]
    fn different_key_different_address() {
        let a1 = Account::new_eoa(&[0xAB; 897]);
        let a2 = Account::new_eoa(&[0xCD; 897]);
        assert_ne!(a1.address, a2.address);
    }
}
