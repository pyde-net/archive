//! State key derivation: deterministic, domain-separated Poseidon2 hashing
//! for mapping account addresses, storage slots, and map entries to SMT keys.
//!
//! Each domain has a unique tag to prevent collisions:
//! - Account:      Poseidon2(address || "account")
//! - Storage slot: Poseidon2(contract || "storage" || slot_index)
//! - Map entry:    Poseidon2(Poseidon2(contract || "storage" || slot) || map_key)
//! - Nested map:   Poseidon2(Poseidon2(Poseidon2(contract || "storage" || slot) || key1) || key2)

use pyde_crypto::poseidon2::poseidon2_hash;
use sparse_merkle_tree::H256;

/// 32-byte address type (matches PVM Address).
pub type Address = [u8; 32];

/// Domain tag for account keys.
const DOMAIN_ACCOUNT: &[u8] = b"account";
/// Domain tag for storage slot keys.
const DOMAIN_STORAGE: &[u8] = b"storage";

/// Derive the SMT key for an account's metadata (balance, nonce, code_hash).
///
/// `key = Poseidon2(address_bytes || "account")`
pub fn account_key(address: &Address) -> H256 {
    let mut input = Vec::with_capacity(32 + DOMAIN_ACCOUNT.len());
    input.extend_from_slice(address);
    input.extend_from_slice(DOMAIN_ACCOUNT);
    let hash = poseidon2_hash(&input);
    H256::from(hash.to_bytes())
}

/// Derive the SMT key for a contract's storage slot.
///
/// `key = Poseidon2(contract_address || "storage" || slot_index_bytes)`
pub fn storage_slot_key(contract: &Address, slot: u64) -> H256 {
    let mut input = Vec::with_capacity(32 + DOMAIN_STORAGE.len() + 8);
    input.extend_from_slice(contract);
    input.extend_from_slice(DOMAIN_STORAGE);
    input.extend_from_slice(&slot.to_le_bytes());
    let hash = poseidon2_hash(&input);
    H256::from(hash.to_bytes())
}

/// Derive the SMT key for a map entry within a contract's storage slot.
///
/// `key = Poseidon2(Poseidon2(contract || "storage" || slot) || map_key_bytes)`
pub fn map_entry_key(contract: &Address, slot: u64, map_key: &[u8]) -> H256 {
    let slot_key = storage_slot_key(contract, slot);
    let mut input = Vec::with_capacity(32 + map_key.len());
    input.extend_from_slice(slot_key.as_slice());
    input.extend_from_slice(map_key);
    let hash = poseidon2_hash(&input);
    H256::from(hash.to_bytes())
}

/// Derive the SMT key for a nested map entry (2-level deep).
///
/// `key = Poseidon2(Poseidon2(Poseidon2(contract || "storage" || slot) || key1) || key2)`
pub fn nested_map_key(contract: &Address, slot: u64, key1: &[u8], key2: &[u8]) -> H256 {
    let level1 = map_entry_key(contract, slot, key1);
    let mut input = Vec::with_capacity(32 + key2.len());
    input.extend_from_slice(level1.as_slice());
    input.extend_from_slice(key2);
    let hash = poseidon2_hash(&input);
    H256::from(hash.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(seed: u64) -> Address {
        let mut a = [0u8; 32];
        a[..8].copy_from_slice(&seed.to_le_bytes());
        a
    }

    #[test]
    fn account_key_deterministic() {
        let a = test_addr(0xAAAA);
        assert_eq!(account_key(&a), account_key(&a));
    }

    #[test]
    fn storage_slot_key_deterministic() {
        let a = test_addr(0xBBBB);
        assert_eq!(storage_slot_key(&a, 0), storage_slot_key(&a, 0));
    }

    #[test]
    fn map_entry_key_deterministic() {
        let a = test_addr(0xCCCC);
        assert_eq!(map_entry_key(&a, 1, b"alice"), map_entry_key(&a, 1, b"alice"));
    }

    #[test]
    fn nested_map_key_deterministic() {
        let a = test_addr(0xDDDD);
        assert_eq!(
            nested_map_key(&a, 2, b"alice", b"token_1"),
            nested_map_key(&a, 2, b"alice", b"token_1")
        );
    }

    #[test]
    fn different_contracts_different_account_keys() {
        assert_ne!(account_key(&test_addr(0xAAAA)), account_key(&test_addr(0xBBBB)));
    }

    #[test]
    fn different_contracts_same_slot_different_keys() {
        let a = test_addr(0xAAAA);
        let b = test_addr(0xBBBB);
        assert_ne!(storage_slot_key(&a, 0), storage_slot_key(&b, 0));
    }

    #[test]
    fn same_contract_different_slots() {
        let a = test_addr(0xAAAA);
        assert_ne!(storage_slot_key(&a, 0), storage_slot_key(&a, 1));
    }

    #[test]
    fn different_map_keys() {
        let a = test_addr(0xAAAA);
        assert_ne!(map_entry_key(&a, 0, b"alice"), map_entry_key(&a, 0, b"bob"));
    }

    #[test]
    fn different_slots_same_map_key() {
        let a = test_addr(0xAAAA);
        assert_ne!(map_entry_key(&a, 0, b"alice"), map_entry_key(&a, 1, b"alice"));
    }

    #[test]
    fn nested_map_different_key2() {
        let a = test_addr(0xAAAA);
        assert_ne!(
            nested_map_key(&a, 0, b"alice", b"token_1"),
            nested_map_key(&a, 0, b"alice", b"token_2")
        );
    }

    #[test]
    fn nested_map_different_key1() {
        let a = test_addr(0xAAAA);
        assert_ne!(
            nested_map_key(&a, 0, b"alice", b"token_1"),
            nested_map_key(&a, 0, b"bob", b"token_1")
        );
    }

    #[test]
    fn account_vs_storage_no_collision() {
        let a = test_addr(0xAAAA);
        assert_ne!(account_key(&a), storage_slot_key(&a, 0));
    }

    #[test]
    fn storage_vs_map_no_collision() {
        let a = test_addr(0xAAAA);
        assert_ne!(storage_slot_key(&a, 0), map_entry_key(&a, 0, &[]));
    }

    #[test]
    fn map_vs_nested_no_collision() {
        let a = test_addr(0xAAAA);
        assert_ne!(map_entry_key(&a, 0, b"key"), nested_map_key(&a, 0, b"key", b""));
    }

    #[test]
    fn all_domains_unique() {
        let a = test_addr(0x1234);
        let keys = vec![
            account_key(&a),
            storage_slot_key(&a, 0),
            map_entry_key(&a, 0, b"k"),
            nested_map_key(&a, 0, b"k", b"v"),
        ];
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "collision between domain {i} and {j}");
            }
        }
    }
}
