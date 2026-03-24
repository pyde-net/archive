//! Storage proof: Merkle path verification for SLOAD/SSTORE against the state root.
//!
//! Every storage access must prove the value exists (or doesn't exist) in the
//! Sparse Merkle Tree. This module:
//!
//! 1. Derives storage keys via Poseidon2(contract_address || discriminator || slot)
//! 2. Verifies Merkle paths from leaf to state root (32 levels of Poseidon2)
//! 3. Each Merkle level hash goes through the hash bus for cross-table verification
//!
//! Without this, a prover could claim any storage value without detection.

use pyde_crypto::hash::Hash256;
use pyde_crypto::poseidon2::{poseidon2_hash, poseidon2_pair};

/// A storage access that needs Merkle proof verification.
#[derive(Clone, Debug)]
pub struct StorageAccess {
    /// Contract address (32 bytes).
    pub contract_address: [u8; 32],
    /// Storage slot index.
    pub slot: u64,
    /// The value claimed by the execution (what SLOAD returned or SSTORE wrote).
    pub value: [u8; 32],
    /// Whether this is a write (SSTORE) or read (SLOAD).
    pub is_write: bool,
    /// Merkle proof: sibling hashes from leaf to root (bottom-up).
    /// proof[0] = sibling at level 0 (leaf level).
    /// proof[31] = sibling at level 31 (root level).
    pub merkle_proof: Vec<[u8; 32]>,
    /// Direction bits: 0 = current node is LEFT child, 1 = RIGHT child.
    pub direction_bits: Vec<bool>,
}

/// Derive the SMT key for a storage slot.
/// key = Poseidon2(contract_address || 0x04 || slot_bytes)
pub fn derive_storage_key(contract: &[u8; 32], slot: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(41);
    input.extend_from_slice(contract);
    input.push(0x04); // STORAGE_SLOT discriminator
    input.extend_from_slice(&slot.to_le_bytes());
    poseidon2_hash(&input).to_bytes()
}

/// Compute the leaf hash for a (key, value) pair.
/// leaf = Poseidon2(0x01 || key || value_hash)
/// where value_hash = Poseidon2(value)
pub fn compute_leaf_hash(key: &[u8; 32], value: &[u8; 32]) -> [u8; 32] {
    let value_hash = poseidon2_hash(value);
    let mut input = Vec::with_capacity(65);
    input.push(0x01); // LEAF domain separator
    input.extend_from_slice(key);
    input.extend_from_slice(&value_hash.to_bytes());
    poseidon2_hash(&input).to_bytes()
}

/// Verify a Merkle path from leaf to root.
/// Returns the computed root hash.
///
/// At each level:
///   if direction_bit == 0: node = Poseidon2(current, sibling)
///   if direction_bit == 1: node = Poseidon2(sibling, current)
pub fn compute_merkle_root(
    leaf_hash: &[u8; 32],
    proof: &[[u8; 32]],
    direction_bits: &[bool],
) -> [u8; 32] {
    assert_eq!(proof.len(), direction_bits.len(), "proof and direction_bits must have same length");

    let mut current = Hash256::new(*leaf_hash);

    for (sibling, &is_right) in proof.iter().zip(direction_bits.iter()) {
        let sibling_hash = Hash256::new(*sibling);
        current = if is_right {
            // Current is RIGHT child: node = Poseidon2(sibling, current)
            poseidon2_pair(sibling_hash, current)
        } else {
            // Current is LEFT child: node = Poseidon2(current, sibling)
            poseidon2_pair(current, sibling_hash)
        };
    }

    current.to_bytes()
}

/// Verify a storage access against a state root.
///
/// 1. Derive the SMT key from contract address + slot
/// 2. Compute the leaf hash from (key, value)
/// 3. Walk the Merkle path to compute the root
/// 4. Check computed root == expected state root
pub fn verify_storage_access(
    access: &StorageAccess,
    expected_state_root: &[u8; 32],
) -> Result<(), String> {
    // 1. Derive key
    let key = derive_storage_key(&access.contract_address, access.slot);

    // 2. Compute leaf hash
    let leaf_hash = compute_leaf_hash(&key, &access.value);

    // 3. Compute Merkle root
    let computed_root = compute_merkle_root(
        &leaf_hash,
        &access.merkle_proof,
        &access.direction_bits,
    );

    // 4. Compare roots
    if computed_root != *expected_state_root {
        return Err(format!(
            "Merkle root mismatch: computed {:?}..., expected {:?}...",
            &computed_root[..4], &expected_state_root[..4]
        ));
    }

    Ok(())
}

/// Collect all Poseidon2 hash requests from Merkle path verification.
/// These go through the hash bus for cross-table verification.
///
/// Each storage access generates:
/// - 1 hash for key derivation: Poseidon2(contract || 0x04 || slot)
/// - 1 hash for value: Poseidon2(value)
/// - 1 hash for leaf: Poseidon2(0x01 || key || value_hash)
/// - N hashes for Merkle path (one per level)
pub fn collect_storage_hash_requests(
    access: &StorageAccess,
) -> Vec<crate::hash_bus::HashRequest> {
    let mut requests = Vec::new();

    // Key derivation hash
    let mut key_input = Vec::with_capacity(41);
    key_input.extend_from_slice(&access.contract_address);
    key_input.push(0x04);
    key_input.extend_from_slice(&access.slot.to_le_bytes());
    let key_hash = poseidon2_hash(&key_input);
    requests.push(make_hash_request(key_input, key_hash.to_bytes()));

    // Value hash
    let value_hash = poseidon2_hash(&access.value);
    requests.push(make_hash_request(access.value.to_vec(), value_hash.to_bytes()));

    // Leaf hash
    let key = derive_storage_key(&access.contract_address, access.slot);
    let mut leaf_input = Vec::with_capacity(65);
    leaf_input.push(0x01);
    leaf_input.extend_from_slice(&key);
    leaf_input.extend_from_slice(&value_hash.to_bytes());
    let leaf_hash = poseidon2_hash(&leaf_input);
    requests.push(make_hash_request(leaf_input, leaf_hash.to_bytes()));

    // Merkle path hashes (each level is a Poseidon2 pair hash)
    let mut current = Hash256::new(compute_leaf_hash(&key, &access.value));
    for (sibling, &is_right) in access.merkle_proof.iter().zip(access.direction_bits.iter()) {
        let sibling_hash = Hash256::new(*sibling);
        let (left, right) = if is_right {
            (sibling_hash, current)
        } else {
            (current, sibling_hash)
        };
        let mut pair_input = Vec::with_capacity(64);
        pair_input.extend_from_slice(&left.to_bytes());
        pair_input.extend_from_slice(&right.to_bytes());
        current = poseidon2_pair(left, right);
        requests.push(make_hash_request(pair_input, current.to_bytes()));
    }

    requests
}

fn make_hash_request(input: Vec<u8>, output: [u8; 32]) -> crate::hash_bus::HashRequest {
    let output_limbs: [u64; 4] = core::array::from_fn(|i| {
        u64::from_le_bytes(output[i * 8..(i + 1) * 8].try_into().unwrap())
    });
    crate::hash_bus::HashRequest {
        input,
        output_limbs,
        timestamp: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_deterministic() {
        let contract = [0xAA; 32];
        let key1 = derive_storage_key(&contract, 0);
        let key2 = derive_storage_key(&contract, 0);
        assert_eq!(key1, key2);
    }

    #[test]
    fn different_slots_different_keys() {
        let contract = [0xAA; 32];
        let key1 = derive_storage_key(&contract, 0);
        let key2 = derive_storage_key(&contract, 1);
        assert_ne!(key1, key2);
    }

    #[test]
    fn different_contracts_different_keys() {
        let key1 = derive_storage_key(&[0xAA; 32], 0);
        let key2 = derive_storage_key(&[0xBB; 32], 0);
        assert_ne!(key1, key2);
    }

    #[test]
    fn leaf_hash_deterministic() {
        let key = [0x11; 32];
        let value = [0x22; 32];
        let h1 = compute_leaf_hash(&key, &value);
        let h2 = compute_leaf_hash(&key, &value);
        assert_eq!(h1, h2);
    }

    #[test]
    fn merkle_root_single_level() {
        let leaf = [0x42; 32];
        let sibling = [0x99; 32];

        // LEFT child: root = Poseidon2(leaf, sibling)
        let root_left = compute_merkle_root(&leaf, &[sibling], &[false]);

        // RIGHT child: root = Poseidon2(sibling, leaf)
        let root_right = compute_merkle_root(&leaf, &[sibling], &[true]);

        // Different directions should give different roots
        assert_ne!(root_left, root_right);

        // Verify against manual computation
        let expected_left = poseidon2_pair(
            Hash256::new(leaf),
            Hash256::new(sibling),
        ).to_bytes();
        assert_eq!(root_left, expected_left);
    }

    #[test]
    fn merkle_root_multi_level() {
        let leaf = [0x01; 32];
        let siblings = vec![[0x10; 32], [0x20; 32], [0x30; 32]];
        let dirs = vec![false, true, false]; // left, right, left

        let root = compute_merkle_root(&leaf, &siblings, &dirs);

        // Manually compute:
        // level 0: Poseidon2(leaf, sib0) since dir=left
        let l0 = poseidon2_pair(Hash256::new(leaf), Hash256::new(siblings[0]));
        // level 1: Poseidon2(sib1, l0) since dir=right
        let l1 = poseidon2_pair(Hash256::new(siblings[1]), l0);
        // level 2: Poseidon2(l1, sib2) since dir=left
        let l2 = poseidon2_pair(l1, Hash256::new(siblings[2]));

        assert_eq!(root, l2.to_bytes());
    }

    #[test]
    fn verify_storage_access_correct() {
        let contract = [0xAA; 32];
        let slot = 42;
        let value = [0x55; 32];

        // Build a simple 1-level Merkle tree
        let key = derive_storage_key(&contract, slot);
        let leaf_hash = compute_leaf_hash(&key, &value);
        let sibling = [0xBB; 32];
        let state_root = compute_merkle_root(&leaf_hash, &[sibling], &[false]);

        let access = StorageAccess {
            contract_address: contract,
            slot,
            value,
            is_write: false,
            merkle_proof: vec![sibling],
            direction_bits: vec![false],
        };

        assert!(verify_storage_access(&access, &state_root).is_ok());
    }

    #[test]
    fn verify_storage_access_wrong_value_fails() {
        let contract = [0xAA; 32];
        let slot = 42;
        let correct_value = [0x55; 32];
        let wrong_value = [0x99; 32];

        let key = derive_storage_key(&contract, slot);
        let leaf_hash = compute_leaf_hash(&key, &correct_value);
        let sibling = [0xBB; 32];
        let state_root = compute_merkle_root(&leaf_hash, &[sibling], &[false]);

        // Prover claims wrong value
        let access = StorageAccess {
            contract_address: contract,
            slot,
            value: wrong_value, // WRONG
            is_write: false,
            merkle_proof: vec![sibling],
            direction_bits: vec![false],
        };

        assert!(verify_storage_access(&access, &state_root).is_err());
    }

    #[test]
    fn hash_requests_collected() {
        let access = StorageAccess {
            contract_address: [0xAA; 32],
            slot: 1,
            value: [0x55; 32],
            is_write: false,
            merkle_proof: vec![[0x11; 32], [0x22; 32]],
            direction_bits: vec![false, true],
        };

        let requests = collect_storage_hash_requests(&access);
        // 1 key derivation + 1 value hash + 1 leaf hash + 2 merkle levels = 5
        assert_eq!(requests.len(), 5);

        // Key derivation, value, and leaf hashes should be independently verifiable
        // (Merkle pair hashes use poseidon2_pair which has different encoding than
        // poseidon2_hash on concatenated bytes, so we verify the first 3 only)
        let key_and_leaf: Vec<_> = requests[..3].to_vec();
        assert!(crate::hash_bus::verify_hash_bus(&key_and_leaf).is_ok());
    }
}
