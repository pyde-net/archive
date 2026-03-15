//! State witnesses: Merkle proofs for stateless execution.
//!
//! Full nodes generate witnesses (Merkle paths for accessed storage slots).
//! Provers receive witnesses, verify them against the pre-state root,
//! execute transactions, and compute the post-state root.
//!
//! Uses batch Merkle proofs: one proof for all accessed keys, deduplicating
//! shared siblings. This reduces witness size from O(N * depth) to
//! O(N * log(N) + depth) for N keys.

use crate::smt::{CompiledProof, Key, PydeSMT};
use sparse_merkle_tree::H256;

/// A leaf entry in the witness: key + current value.
#[derive(Clone, Debug)]
pub struct WitnessEntry {
    /// The SMT key being accessed.
    pub key: Key,
    /// The current value (before execution). Empty vec = absent.
    pub value: Vec<u8>,
}

/// A complete witness for a block: batch proof + all accessed key-value pairs.
#[derive(Clone, Debug)]
pub struct BlockWitness {
    /// All accessed key-value pairs (leaves).
    pub entries: Vec<WitnessEntry>,
    /// Single batch Merkle proof covering all keys.
    pub proof: Vec<u8>,
    /// The state root before block execution.
    pub pre_state_root: H256,
    /// The state root after block execution (set after applying diffs).
    pub post_state_root: H256,
}

impl BlockWitness {
    /// Total serialized size of the witness (proof + entries).
    pub fn size_bytes(&self) -> usize {
        let entries_size: usize = self.entries.iter().map(|e| 32 + e.value.len()).sum();
        self.proof.len() + entries_size + 64 // + 2 roots
    }

    /// Number of accessed keys.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Generate a block witness from an access list using a single batch proof.
///
/// The full node calls this before sending the block to provers.
/// All keys get a single compiled Merkle proof (shared siblings deduplicated).
pub fn generate_witnesses(smt: &PydeSMT, access_keys: &[Key]) -> BlockWitness {
    let pre_root = smt.root();

    if access_keys.is_empty() {
        return BlockWitness {
            entries: Vec::new(),
            proof: Vec::new(),
            pre_state_root: pre_root,
            post_state_root: H256::zero(),
        };
    }

    // Collect current values
    let entries: Vec<WitnessEntry> = access_keys
        .iter()
        .map(|key| WitnessEntry {
            key: *key,
            value: smt.get(key).unwrap_or_default(),
        })
        .collect();

    // Generate single batch proof for all keys
    let keys_vec: Vec<Key> = access_keys.to_vec();
    let proof = smt.prove(keys_vec.clone());
    let compiled = proof.compile(keys_vec);

    BlockWitness {
        entries,
        proof: compiled.to_bytes(),
        pre_state_root: pre_root,
        post_state_root: H256::zero(),
    }
}

/// Verify a block witness: check that the batch proof is valid
/// against the pre-state root for all entries.
///
/// Returns true if the proof verifies. The prover calls this before executing.
pub fn verify_witnesses(witness: &BlockWitness) -> bool {
    if witness.entries.is_empty() {
        return true;
    }

    let proof = CompiledProof::from_bytes(witness.proof.clone());

    let leaves: Vec<(Key, Vec<u8>)> = witness
        .entries
        .iter()
        .map(|e| (e.key, e.value.clone()))
        .collect();

    proof.verify(witness.pre_state_root, leaves)
}

/// Build a key→value map from witnesses for use during execution.
/// The prover uses this instead of querying the full state.
pub fn witness_to_state_map(witness: &BlockWitness) -> std::collections::HashMap<Key, Vec<u8>> {
    let mut map = std::collections::HashMap::new();
    for entry in &witness.entries {
        if !entry.value.is_empty() {
            map.insert(entry.key, entry.value.clone());
        }
    }
    map
}

/// Compute the post-state root by applying state diffs to the SMT.
///
/// `diffs` is a list of (key, new_value) pairs. Empty value = deletion.
/// Returns the new root after applying all diffs.
pub fn compute_post_state_root(smt: &mut PydeSMT, diffs: Vec<(Key, Vec<u8>)>) -> H256 {
    smt.update_all(diffs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smt::key_from_seed;

    // ========== Task 0311: Witness for single storage read ==========

    #[test]
    fn witness_single_read() {
        let mut smt = PydeSMT::new();
        let key = key_from_seed(1);
        smt.insert(key, b"balance_100".to_vec());

        let witness = generate_witnesses(&smt, &[key]);
        assert_eq!(witness.len(), 1);
        assert_eq!(witness.entries[0].key, key);
        assert_eq!(witness.entries[0].value, b"balance_100");
        assert!(!witness.proof.is_empty());
    }

    // ========== Task 0312: Witness for storage write ==========

    #[test]
    fn witness_storage_write() {
        let mut smt = PydeSMT::new();
        let key = key_from_seed(1);
        smt.insert(key, b"old_value".to_vec());

        let witness = generate_witnesses(&smt, &[key]);
        assert_eq!(witness.entries[0].value, b"old_value");

        // Apply write — root changes
        smt.insert(key, b"new_value".to_vec());
        assert_ne!(smt.root(), witness.pre_state_root);
    }

    // ========== Task 0313: Witness for absent key ==========

    #[test]
    fn witness_absent_key() {
        let mut smt = PydeSMT::new();
        smt.insert(key_from_seed(1), b"exists".to_vec());

        let missing = key_from_seed(999);
        let witness = generate_witnesses(&smt, &[missing]);
        assert!(witness.entries[0].value.is_empty());
    }

    // ========== Task 0314: Witness verification ==========

    #[test]
    fn witness_verification_passes() {
        let mut smt = PydeSMT::new();
        for i in 0..10u64 {
            smt.insert(key_from_seed(i), format!("val_{i}").into_bytes());
        }
        let keys: Vec<Key> = (0..10).map(|i| key_from_seed(i)).collect();

        let witness = generate_witnesses(&smt, &keys);
        assert!(verify_witnesses(&witness));
    }

    #[test]
    fn witness_verification_fails_with_wrong_root() {
        let mut smt = PydeSMT::new();
        let key = key_from_seed(1);
        smt.insert(key, b"data".to_vec());

        let mut witness = generate_witnesses(&smt, &[key]);
        witness.pre_state_root = H256::from([0xFFu8; 32]);
        assert!(!verify_witnesses(&witness));
    }

    // ========== Task 0315: Execution matches full state ==========

    #[test]
    fn witness_state_map_matches_full_state() {
        let mut smt = PydeSMT::new();
        let keys: Vec<Key> = (0..10).map(|i| key_from_seed(i)).collect();
        for (i, k) in keys.iter().enumerate() {
            smt.insert(*k, format!("val_{i}").into_bytes());
        }

        let witness = generate_witnesses(&smt, &keys);
        let state_map = witness_to_state_map(&witness);

        for (i, k) in keys.iter().enumerate() {
            assert_eq!(state_map.get(k), Some(&format!("val_{i}").into_bytes()));
            assert_eq!(smt.get(k), Some(format!("val_{i}").into_bytes()));
        }
    }

    #[test]
    fn post_state_root_matches_after_diffs() {
        let mut smt = PydeSMT::new();
        let key1 = key_from_seed(1);
        let key2 = key_from_seed(2);
        smt.insert(key1, b"a".to_vec());
        smt.insert(key2, b"b".to_vec());

        let mut smt_clone = PydeSMT::new();
        smt_clone.insert(key1, b"a".to_vec());
        smt_clone.insert(key2, b"b".to_vec());

        let diffs = vec![(key1, b"new_a".to_vec())];
        let post_root = compute_post_state_root(&mut smt, diffs);
        smt_clone.insert(key1, b"new_a".to_vec());

        assert_eq!(post_root, smt_clone.root());
    }

    // ========== Batch proof size ==========

    #[test]
    fn batch_proof_smaller_than_individual() {
        let mut smt = PydeSMT::new();
        let keys: Vec<Key> = (0..100).map(|i| key_from_seed(i)).collect();
        for (i, k) in keys.iter().enumerate() {
            smt.insert(*k, format!("v{i}").into_bytes());
        }

        // Batch witness (single proof)
        let batch = generate_witnesses(&smt, &keys);
        let batch_size = batch.size_bytes();

        // Individual witnesses (100 separate proofs)
        let mut individual_size = 0;
        for k in &keys {
            let w = generate_witnesses(&smt, &[*k]);
            individual_size += w.size_bytes();
        }

        println!("batch: {batch_size} bytes, individual: {individual_size} bytes");
        assert!(batch_size < individual_size, "batch should be smaller");
    }

    #[test]
    fn empty_access_list() {
        let smt = PydeSMT::new();
        let witness = generate_witnesses(&smt, &[]);
        assert!(witness.is_empty());
        assert!(verify_witnesses(&witness));
    }
}
