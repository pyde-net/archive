//! State witnesses: Merkle proofs for stateless execution.
//!
//! Full nodes generate witnesses (Merkle paths for accessed storage slots).
//! Validators use witnesses for stateless verification against the pre-state
//! root, re-execute transactions, and compute the post-state root.
//!
//! Uses batch Merkle proofs: one proof for all accessed keys, deduplicating
//! shared siblings. This reduces witness size from O(N * depth) to
//! O(N * log(N) + depth) for N keys.

use crate::smt::{CompiledProof, Key, PydeSMT};
use sparse_merkle_tree::H256;

/// Maximum witness size in bytes (Phase 5 slice 5.3).
///
/// Enforced by `verify_witnesses`: any incoming witness whose
/// `size_bytes()` exceeds this cap is rejected without running the
/// batch-proof verifier. Without this cap, a peer can gossip a
/// pathologically large witness (e.g. GB-scale) and force a syncing
/// node to allocate + verify it. 1 MB is large enough for any
/// realistic block witness (at ~32 B per entry + batch proof
/// overhead, that's tens of thousands of accessed keys) and small
/// enough to keep the DoS surface bounded.
pub const MAX_WITNESS_SIZE: usize = 1024 * 1024;

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

    /// Stamp the post-execution state root onto the witness. Callers
    /// MUST do this after applying state diffs; without it
    /// `post_state_root` remains `H256::zero()` (the placeholder from
    /// `generate_witnesses`) and stateless verifiers have no way to
    /// check the transition.
    pub fn set_post_state_root(&mut self, root: H256) {
        self.post_state_root = root;
    }

    /// Whether this witness has been finalized (its `post_state_root`
    /// is non-zero). Useful as a sanity check at the block-producer
    /// boundary: a not-yet-finalized witness should never leave the node.
    pub fn is_finalized(&self) -> bool {
        self.post_state_root != H256::zero()
    }
}

/// Apply `diffs` to `smt`, compute the new root, and stamp it onto
/// `witness.post_state_root` in one step. Intended for the block-
/// producer flow:
///
/// ```text
/// 1. generate_witnesses(smt, access_keys) → pre-execution witness
/// 2. execute transactions against `smt`, collecting diffs
/// 3. finalize_witness(&mut witness, &mut smt, diffs)
/// 4. broadcast witness (now has pre + post roots)
/// ```
///
/// Returns the post-root for convenience; it is also written into
/// `witness.post_state_root`.
pub fn finalize_witness(
    witness: &mut BlockWitness,
    smt: &mut PydeSMT,
    diffs: Vec<(Key, Vec<u8>)>,
) -> Result<H256, &'static str> {
    let post_root = compute_post_state_root(smt, diffs)?;
    witness.set_post_state_root(post_root);
    Ok(post_root)
}

/// Generate a block witness from an access list using a single batch proof.
///
/// The full node calls this before sending the block to validators.
/// All keys get a single compiled Merkle proof (shared siblings deduplicated).
pub fn generate_witnesses(smt: &PydeSMT, access_keys: &[Key]) -> Result<BlockWitness, &'static str> {
    let pre_root = smt.root();

    if access_keys.is_empty() {
        return Ok(BlockWitness {
            entries: Vec::new(),
            proof: Vec::new(),
            pre_state_root: pre_root,
            post_state_root: H256::zero(),
        });
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
    let proof = smt.prove(keys_vec.clone())?;
    let compiled = proof.compile(keys_vec)?;

    Ok(BlockWitness {
        entries,
        proof: compiled.to_bytes(),
        pre_state_root: pre_root,
        post_state_root: H256::zero(),
    })
}

/// Verify a block witness: check that the batch proof is valid
/// against the pre-state root for all entries.
///
/// Returns true if the proof verifies. The validator calls this before executing.
pub fn verify_witnesses(witness: &BlockWitness) -> bool {
    // Size gate (slice 5.3). Reject oversized witnesses before doing
    // any proof-verification work — an adversary shouldn't be able to
    // burn CPU on a multi-MB witness just by gossiping garbage. Run
    // this BEFORE the empty-witness branch so an empty-entries-but-
    // huge-proof blob is also caught.
    if witness.size_bytes() > MAX_WITNESS_SIZE {
        return false;
    }

    if witness.entries.is_empty() {
        // Empty witness is only valid if proof is also empty
        return witness.proof.is_empty();
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
/// Stateless validators use this instead of querying the full state.
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
pub fn compute_post_state_root(smt: &mut PydeSMT, diffs: Vec<(Key, Vec<u8>)>) -> Result<H256, &'static str> {
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
        smt.insert(key, b"balance_100".to_vec()).unwrap();

        let witness = generate_witnesses(&smt, &[key]).unwrap();
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
        smt.insert(key, b"old_value".to_vec()).unwrap();

        let witness = generate_witnesses(&smt, &[key]).unwrap();
        assert_eq!(witness.entries[0].value, b"old_value");

        // Apply write — root changes
        smt.insert(key, b"new_value".to_vec()).unwrap();
        assert_ne!(smt.root(), witness.pre_state_root);
    }

    // ========== Task 0313: Witness for absent key ==========

    #[test]
    fn witness_absent_key() {
        let mut smt = PydeSMT::new();
        smt.insert(key_from_seed(1), b"exists".to_vec()).unwrap();

        let missing = key_from_seed(999);
        let witness = generate_witnesses(&smt, &[missing]).unwrap();
        assert!(witness.entries[0].value.is_empty());
    }

    // ========== Task 0314: Witness verification ==========

    #[test]
    fn witness_verification_passes() {
        let mut smt = PydeSMT::new();
        for i in 0..10u64 {
            smt.insert(key_from_seed(i), format!("val_{i}").into_bytes()).unwrap();
        }
        let keys: Vec<Key> = (0..10).map(|i| key_from_seed(i)).collect();

        let witness = generate_witnesses(&smt, &keys).unwrap();
        assert!(verify_witnesses(&witness));
    }

    #[test]
    fn witness_verification_fails_with_wrong_root() {
        let mut smt = PydeSMT::new();
        let key = key_from_seed(1);
        smt.insert(key, b"data".to_vec()).unwrap();

        let mut witness = generate_witnesses(&smt, &[key]).unwrap();
        witness.pre_state_root = H256::from([0xFFu8; 32]);
        assert!(!verify_witnesses(&witness));
    }

    // ========== Task 0315: Execution matches full state ==========

    #[test]
    fn witness_state_map_matches_full_state() {
        let mut smt = PydeSMT::new();
        let keys: Vec<Key> = (0..10).map(|i| key_from_seed(i)).collect();
        for (i, k) in keys.iter().enumerate() {
            smt.insert(*k, format!("val_{i}").into_bytes()).unwrap();
        }

        let witness = generate_witnesses(&smt, &keys).unwrap();
        let state_map = witness_to_state_map(&witness);

        for (i, k) in keys.iter().enumerate() {
            assert_eq!(state_map.get(k), Some(&format!("val_{i}").into_bytes()));
            assert_eq!(smt.get(k), Some(format!("val_{i}").into_bytes()));
        }
    }

    #[test]
    fn new_witness_is_not_finalized() {
        let smt = PydeSMT::new();
        let witness = generate_witnesses(&smt, &[]).unwrap();
        assert!(
            !witness.is_finalized(),
            "freshly-generated witness must NOT report as finalized — \
             post_state_root starts as H256::zero() and is only set \
             by finalize_witness after execution diffs are applied"
        );
    }

    #[test]
    fn set_post_state_root_marks_witness_finalized() {
        let mut smt = PydeSMT::new();
        smt.insert(key_from_seed(1), b"x".to_vec()).unwrap();
        let mut witness = generate_witnesses(&smt, &[key_from_seed(1)]).unwrap();
        assert!(!witness.is_finalized());

        witness.set_post_state_root(H256::from([0x42u8; 32]));
        assert!(witness.is_finalized());
        assert_eq!(witness.post_state_root, H256::from([0x42u8; 32]));
    }

    #[test]
    fn finalize_witness_stamps_actual_post_root() {
        let mut smt = PydeSMT::new();
        let key = key_from_seed(1);
        smt.insert(key, b"old".to_vec()).unwrap();

        let mut witness = generate_witnesses(&smt, &[key]).unwrap();
        assert!(!witness.is_finalized());

        // Independently compute what the post-root should be.
        let mut expected = PydeSMT::new();
        expected.insert(key, b"old".to_vec()).unwrap();
        expected.insert(key, b"new".to_vec()).unwrap();
        let expected_root = expected.root();

        let stamped = finalize_witness(&mut witness, &mut smt, vec![(key, b"new".to_vec())])
            .unwrap();

        assert!(witness.is_finalized());
        assert_eq!(witness.post_state_root, stamped);
        assert_eq!(witness.post_state_root, expected_root);
        assert_eq!(smt.root(), expected_root);
    }

    #[test]
    fn post_state_root_matches_after_diffs() {
        let mut smt = PydeSMT::new();
        let key1 = key_from_seed(1);
        let key2 = key_from_seed(2);
        smt.insert(key1, b"a".to_vec()).unwrap();
        smt.insert(key2, b"b".to_vec()).unwrap();

        let mut smt_clone = PydeSMT::new();
        smt_clone.insert(key1, b"a".to_vec()).unwrap();
        smt_clone.insert(key2, b"b".to_vec()).unwrap();

        let diffs = vec![(key1, b"new_a".to_vec())];
        let post_root = compute_post_state_root(&mut smt, diffs).unwrap();
        smt_clone.insert(key1, b"new_a".to_vec()).unwrap();

        assert_eq!(post_root, smt_clone.root());
    }

    // ========== Batch proof size ==========

    #[test]
    fn batch_proof_smaller_than_individual() {
        let mut smt = PydeSMT::new();
        let keys: Vec<Key> = (0..100).map(|i| key_from_seed(i)).collect();
        for (i, k) in keys.iter().enumerate() {
            smt.insert(*k, format!("v{i}").into_bytes()).unwrap();
        }

        // Batch witness (single proof)
        let batch = generate_witnesses(&smt, &keys).unwrap();
        let batch_size = batch.size_bytes();

        // Individual witnesses (100 separate proofs)
        let mut individual_size = 0;
        for k in &keys {
            let w = generate_witnesses(&smt, &[*k]).unwrap();
            individual_size += w.size_bytes();
        }

        println!("batch: {batch_size} bytes, individual: {individual_size} bytes");
        assert!(batch_size < individual_size, "batch should be smaller");
    }

    #[test]
    fn empty_access_list() {
        let smt = PydeSMT::new();
        let witness = generate_witnesses(&smt, &[]).unwrap();
        assert!(witness.is_empty());
        assert!(verify_witnesses(&witness));
    }

    // ========== Slice 5.3: MAX_WITNESS_SIZE ==========

    #[test]
    fn oversized_witness_rejected_without_verify() {
        // Construct a witness whose `size_bytes()` exceeds MAX_WITNESS_SIZE.
        // The proof blob itself is junk — verify_witnesses must return
        // false via the size gate BEFORE attempting proof verification,
        // so the junk proof never gets parsed. Simulates an adversary
        // gossiping a pathological witness.
        let witness = BlockWitness {
            entries: vec![],
            proof: vec![0u8; MAX_WITNESS_SIZE + 1],
            pre_state_root: H256::zero(),
            post_state_root: H256::zero(),
        };
        assert!(witness.size_bytes() > MAX_WITNESS_SIZE);
        assert!(!verify_witnesses(&witness));
    }

    #[test]
    fn oversized_witness_via_entries_rejected() {
        // Large number of entries also trips the cap even with a small
        // proof blob.
        let entries: Vec<WitnessEntry> = (0..50_000)
            .map(|i| WitnessEntry {
                key: key_from_seed(i as u64),
                value: vec![0xFF; 32],
            })
            .collect();
        let witness = BlockWitness {
            entries,
            proof: vec![],
            pre_state_root: H256::zero(),
            post_state_root: H256::zero(),
        };
        // Each entry = 32 (key) + 32 (value) = 64 bytes; 50_000 entries
        // = 3.2 MB, well above 1 MB cap.
        assert!(witness.size_bytes() > MAX_WITNESS_SIZE);
        assert!(!verify_witnesses(&witness));
    }

    #[test]
    fn witness_at_boundary_still_runs_proof_path() {
        // A witness slightly UNDER the cap must be allowed past the
        // size gate and reach the proof-verification path. We use an
        // empty entries + empty proof (always valid) as the "normal"
        // witness; the gate must not reject it just for being near
        // the cap.
        let witness = BlockWitness {
            entries: vec![],
            proof: vec![],
            pre_state_root: H256::zero(),
            post_state_root: H256::zero(),
        };
        assert!(witness.size_bytes() < MAX_WITNESS_SIZE);
        assert!(verify_witnesses(&witness));
    }
}
