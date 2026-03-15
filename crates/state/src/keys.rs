//! State key derivation: deterministic, domain-separated Poseidon2 hashing
//! for mapping account addresses, storage slots, and map entries to SMT keys.
//!
//! Uses byte discriminators per spec (Chapter 4, Section 4.4):
//! - 0x00: Account balance
//! - 0x01: Account nonce
//! - 0x02: Contract code
//! - 0x03: Contract code hash
//! - 0x04: Storage slot
//! - 0x05: Named storage / map entry

use pyde_crypto::poseidon2::poseidon2_hash;
use sparse_merkle_tree::H256;

/// 32-byte address type (matches PVM Address).
pub type Address = [u8; 32];

/// Discriminator bytes for domain separation.
pub mod discriminator {
    pub const BALANCE: u8 = 0x00;
    pub const NONCE: u8 = 0x01;
    pub const CODE: u8 = 0x02;
    pub const CODE_HASH: u8 = 0x03;
    pub const STORAGE_SLOT: u8 = 0x04;
    pub const MAP_ENTRY: u8 = 0x05;
}

// ---------------------------------------------------------------------------
// Address derivation
// ---------------------------------------------------------------------------

/// Derive a 32-byte address from a FALCON-512 public key.
///
/// `address = Poseidon2(falcon_public_key_bytes)`
pub fn derive_address(falcon_public_key: &[u8]) -> Address {
    poseidon2_hash(falcon_public_key).to_bytes()
}

// ---------------------------------------------------------------------------
// Account metadata keys
// ---------------------------------------------------------------------------

/// Derive the SMT key for an account's balance.
///
/// `key = Poseidon2(address || 0x00)`
pub fn balance_key(address: &Address) -> H256 {
    let mut input = Vec::with_capacity(33);
    input.extend_from_slice(address);
    input.push(discriminator::BALANCE);
    H256::from(poseidon2_hash(&input).to_bytes())
}

/// Derive the SMT key for an account's nonce.
///
/// `key = Poseidon2(address || 0x01)`
pub fn nonce_key(address: &Address) -> H256 {
    let mut input = Vec::with_capacity(33);
    input.extend_from_slice(address);
    input.push(discriminator::NONCE);
    H256::from(poseidon2_hash(&input).to_bytes())
}

/// Derive the SMT key for a contract's deployed code.
///
/// `key = Poseidon2(address || 0x02)`
pub fn code_key(address: &Address) -> H256 {
    let mut input = Vec::with_capacity(33);
    input.extend_from_slice(address);
    input.push(discriminator::CODE);
    H256::from(poseidon2_hash(&input).to_bytes())
}

/// Derive the SMT key for a contract's code hash.
///
/// `key = Poseidon2(address || 0x03)`
pub fn code_hash_key(address: &Address) -> H256 {
    let mut input = Vec::with_capacity(33);
    input.extend_from_slice(address);
    input.push(discriminator::CODE_HASH);
    H256::from(poseidon2_hash(&input).to_bytes())
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

/// Derive the SMT key for a contract's storage slot.
///
/// `key = Poseidon2(contract_address || 0x04 || slot_index_bytes)`
pub fn storage_slot_key(contract: &Address, slot: u64) -> H256 {
    let mut input = Vec::with_capacity(41);
    input.extend_from_slice(contract);
    input.push(discriminator::STORAGE_SLOT);
    input.extend_from_slice(&slot.to_le_bytes());
    H256::from(poseidon2_hash(&input).to_bytes())
}

/// Derive the SMT key for a map entry within a contract's storage slot.
///
/// `key = Poseidon2(Poseidon2(contract || 0x04 || slot) || 0x05 || map_key_bytes)`
pub fn map_entry_key(contract: &Address, slot: u64, map_key: &[u8]) -> H256 {
    let slot_hash = storage_slot_key(contract, slot);
    let mut input = Vec::with_capacity(33 + map_key.len());
    input.extend_from_slice(slot_hash.as_slice());
    input.push(discriminator::MAP_ENTRY);
    input.extend_from_slice(map_key);
    H256::from(poseidon2_hash(&input).to_bytes())
}

/// Derive the SMT key for a nested map entry (2-level deep).
///
/// `key = Poseidon2(Poseidon2(slot_hash || 0x05 || key1) || 0x05 || key2)`
pub fn nested_map_key(contract: &Address, slot: u64, key1: &[u8], key2: &[u8]) -> H256 {
    let level1 = map_entry_key(contract, slot, key1);
    let mut input = Vec::with_capacity(33 + key2.len());
    input.extend_from_slice(level1.as_slice());
    input.push(discriminator::MAP_ENTRY);
    input.extend_from_slice(key2);
    H256::from(poseidon2_hash(&input).to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(seed: u64) -> Address {
        let mut a = [0u8; 32];
        a[..8].copy_from_slice(&seed.to_le_bytes());
        a
    }

    // ========== Address derivation ==========

    #[test]
    fn derive_address_deterministic() {
        let pk = [0xABu8; 897]; // fake FALCON public key
        let a1 = derive_address(&pk);
        let a2 = derive_address(&pk);
        assert_eq!(a1, a2);
        assert_ne!(a1, [0u8; 32]);
    }

    #[test]
    fn different_keys_different_addresses() {
        let pk1 = [0xABu8; 897];
        let pk2 = [0xCDu8; 897];
        assert_ne!(derive_address(&pk1), derive_address(&pk2));
    }

    // ========== Account metadata keys ==========

    #[test]
    fn account_keys_deterministic() {
        let a = test_addr(0xAAAA);
        assert_eq!(balance_key(&a), balance_key(&a));
        assert_eq!(nonce_key(&a), nonce_key(&a));
        assert_eq!(code_key(&a), code_key(&a));
        assert_eq!(code_hash_key(&a), code_hash_key(&a));
    }

    #[test]
    fn account_keys_all_different() {
        let a = test_addr(0xAAAA);
        let keys = vec![
            balance_key(&a),
            nonce_key(&a),
            code_key(&a),
            code_hash_key(&a),
        ];
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "collision between metadata {i} and {j}");
            }
        }
    }

    #[test]
    fn different_addresses_different_balance_keys() {
        let a = test_addr(0xAAAA);
        let b = test_addr(0xBBBB);
        assert_ne!(balance_key(&a), balance_key(&b));
    }

    // ========== Storage keys ==========

    #[test]
    fn storage_slot_key_deterministic() {
        let a = test_addr(0xBBBB);
        assert_eq!(storage_slot_key(&a, 0), storage_slot_key(&a, 0));
    }

    #[test]
    fn different_contracts_same_slot() {
        let a = test_addr(0xAAAA);
        let b = test_addr(0xBBBB);
        assert_ne!(storage_slot_key(&a, 0), storage_slot_key(&b, 0));
    }

    #[test]
    fn same_contract_different_slots() {
        let a = test_addr(0xAAAA);
        assert_ne!(storage_slot_key(&a, 0), storage_slot_key(&a, 1));
    }

    // ========== Map keys ==========

    #[test]
    fn different_map_keys() {
        let a = test_addr(0xAAAA);
        assert_ne!(map_entry_key(&a, 0, b"alice"), map_entry_key(&a, 0, b"bob"));
    }

    #[test]
    fn nested_map_different_key2() {
        let a = test_addr(0xAAAA);
        assert_ne!(
            nested_map_key(&a, 0, b"alice", b"token_1"),
            nested_map_key(&a, 0, b"alice", b"token_2")
        );
    }

    // ========== Cross-domain collision resistance ==========

    #[test]
    fn no_collision_across_all_domains() {
        let a = test_addr(0x1234);
        let keys = vec![
            balance_key(&a),
            nonce_key(&a),
            code_key(&a),
            code_hash_key(&a),
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

    #[test]
    fn balance_vs_storage_no_collision() {
        let a = test_addr(0xAAAA);
        assert_ne!(balance_key(&a), storage_slot_key(&a, 0));
    }

    #[test]
    fn storage_vs_map_no_collision() {
        let a = test_addr(0xAAAA);
        assert_ne!(storage_slot_key(&a, 0), map_entry_key(&a, 0, &[]));
    }
}
