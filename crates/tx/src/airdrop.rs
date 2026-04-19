//! Airdrop Merkle proof verification (slice 4.4b).
//!
//! Tree layout:
//! - Leaf:     `Poseidon2(0x00 || leaf_index_le_8 || address_32 || amount_le_16)`
//! - Internal: `poseidon2_pair(left, right)`
//!
//! The leading `0x00` byte in leaves domain-separates them from internal
//! nodes (which come out of `poseidon2_pair`, not `poseidon2_hash`, and
//! therefore have no freely-chosen preimage). This blocks the classic
//! sorted-pair second-preimage attack where an internal hash could be
//! presented as a leaf.
//!
//! Proof format carried in `ClaimAirdrop` `tx.data`:
//!
//! ```text
//! [leaf_index:8 LE][amount:16 LE][proof_len:1][sibling_0:32]...[sibling_{N-1}:32]
//! ```
//!
//! Direction at each level is taken from the index bits: bit `i` of
//! `leaf_index` = 0 → sibling sits to the right of the current hash at
//! level `i`; bit = 1 → sibling sits to the left.

use pyde_account::address::Address;
use pyde_crypto::poseidon2::{poseidon2_hash, poseidon2_pair};

/// 32-byte Merkle hash.
pub type MerkleHash = [u8; 32];

/// Domain-separation tag for leaves.
const LEAF_TAG: u8 = 0x00;

/// Maximum proof length carried in a single tx. 1-byte length field
/// caps depth at 255 — a tree that deep would hold `2^255` leaves, so
/// this ceiling is purely a serialization cap, not a protocol limit.
pub const MAX_PROOF_LEN: usize = 255;

/// Minimum encoded payload size: `index (8) + amount (16) + proof_len (1)`.
pub const MIN_CLAIM_DATA_LEN: usize = 25;

/// Decoded `ClaimAirdrop` payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimPayload {
    pub leaf_index: u64,
    pub amount: u128,
    pub proof: Vec<MerkleHash>,
}

impl ClaimPayload {
    /// Decode a `tx.data` payload into a structured claim. Returns `None`
    /// for any malformed or truncated input — the pipeline treats this as
    /// a rejected tx.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < MIN_CLAIM_DATA_LEN {
            return None;
        }
        let leaf_index = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let amount = u128::from_le_bytes(bytes[8..24].try_into().ok()?);
        let proof_len = bytes[24] as usize;
        let expected = MIN_CLAIM_DATA_LEN + proof_len * 32;
        if bytes.len() != expected {
            return None;
        }
        let mut proof = Vec::with_capacity(proof_len);
        for i in 0..proof_len {
            let off = MIN_CLAIM_DATA_LEN + i * 32;
            let mut sibling = [0u8; 32];
            sibling.copy_from_slice(&bytes[off..off + 32]);
            proof.push(sibling);
        }
        Some(Self {
            leaf_index,
            amount,
            proof,
        })
    }

    /// Serialize for tests and off-chain tooling. Inverse of `decode`.
    pub fn encode(&self) -> Vec<u8> {
        assert!(self.proof.len() <= MAX_PROOF_LEN, "proof too long");
        let mut out = Vec::with_capacity(MIN_CLAIM_DATA_LEN + self.proof.len() * 32);
        out.extend_from_slice(&self.leaf_index.to_le_bytes());
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.push(self.proof.len() as u8);
        for sibling in &self.proof {
            out.extend_from_slice(sibling);
        }
        out
    }
}

/// Compute the leaf hash for `(index, address, amount)`.
pub fn leaf_hash(index: u64, address: &Address, amount: u128) -> MerkleHash {
    let mut input = Vec::with_capacity(1 + 8 + 32 + 16);
    input.push(LEAF_TAG);
    input.extend_from_slice(&index.to_le_bytes());
    input.extend_from_slice(address);
    input.extend_from_slice(&amount.to_le_bytes());
    poseidon2_hash(&input).to_bytes()
}

/// Walk the proof from the leaf to compute a root. Returns the computed
/// 32-byte root — callers compare against the stored `airdrop_root`.
///
/// Order at each level is derived from the corresponding bit of
/// `leaf_index`. This ensures the proof commits to the leaf's position,
/// not just its content — without it, an attacker could swap two leaves'
/// proofs and claim either.
pub fn compute_root(
    leaf_index: u64,
    address: &Address,
    amount: u128,
    proof: &[MerkleHash],
) -> MerkleHash {
    let mut node = leaf_hash(leaf_index, address, amount);
    let mut index = leaf_index;
    for sibling in proof {
        let (left, right) = if index & 1 == 0 {
            (node, *sibling)
        } else {
            (*sibling, node)
        };
        node = poseidon2_pair(
            pyde_crypto::hash::Hash256::from(left),
            pyde_crypto::hash::Hash256::from(right),
        )
        .to_bytes();
        index >>= 1;
    }
    node
}

/// Verify that `(index, address, amount, proof)` is consistent with `root`.
pub fn verify_proof(
    leaf_index: u64,
    address: &Address,
    amount: u128,
    proof: &[MerkleHash],
    root: &MerkleHash,
) -> bool {
    &compute_root(leaf_index, address, amount, proof) == root
}

// ---------------------------------------------------------------------------
// Off-chain builder (test helper; operators run a separate tool in prod).
// ---------------------------------------------------------------------------

/// Build a full Merkle tree from a vector of `(address, amount)` pairs.
/// Leaves are indexed in the order provided. Returns `(root, proofs)`
/// where `proofs[i]` is the proof for leaf `i`.
///
/// Reference implementation — genesis tests, devnet tooling, and any
/// downstream CLI can share the same leaf/node formulation so the
/// off-chain tree matches what `verify_proof` expects on-chain.
pub fn build_tree(leaves: &[(Address, u128)]) -> (MerkleHash, Vec<Vec<MerkleHash>>) {
    assert!(!leaves.is_empty(), "cannot build a tree with zero leaves");

    // Pad leaf count to next power of two with all-zero hashes so every
    // internal level is full. Zero padding is safe because the off-chain
    // builder determines leaf index and no attacker can submit a claim
    // against a padded slot — its preimage has no valid (address,amount).
    let mut level: Vec<MerkleHash> = leaves
        .iter()
        .enumerate()
        .map(|(i, (addr, amt))| leaf_hash(i as u64, addr, *amt))
        .collect();

    let depth = if level.len() <= 1 {
        0
    } else {
        (level.len() - 1).ilog2() as usize + 1
    };
    let padded_width = 1usize << depth;
    while level.len() < padded_width {
        level.push([0u8; 32]);
    }

    let mut siblings_per_leaf: Vec<Vec<MerkleHash>> = vec![Vec::with_capacity(depth); leaves.len()];

    for _d in 0..depth {
        for leaf_i in 0..leaves.len() {
            let pos_at_level = leaf_i >> _d;
            let sibling_pos = pos_at_level ^ 1;
            siblings_per_leaf[leaf_i].push(level[sibling_pos]);
        }

        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let parent = poseidon2_pair(
                pyde_crypto::hash::Hash256::from(pair[0]),
                pyde_crypto::hash::Hash256::from(pair[1]),
            )
            .to_bytes();
            next.push(parent);
        }
        level = next;
    }

    (level[0], siblings_per_leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(seed: u64) -> Address {
        let mut a = [0u8; 32];
        a[..8].copy_from_slice(&seed.to_le_bytes());
        a
    }

    #[test]
    fn leaf_hash_deterministic() {
        let a = addr(1);
        assert_eq!(leaf_hash(0, &a, 100), leaf_hash(0, &a, 100));
    }

    #[test]
    fn leaf_hash_differs_on_index_address_amount() {
        let a = addr(1);
        let b = addr(2);
        assert_ne!(leaf_hash(0, &a, 100), leaf_hash(1, &a, 100));
        assert_ne!(leaf_hash(0, &a, 100), leaf_hash(0, &b, 100));
        assert_ne!(leaf_hash(0, &a, 100), leaf_hash(0, &a, 101));
    }

    #[test]
    fn single_leaf_tree() {
        let leaves = vec![(addr(1), 100u128)];
        let (root, proofs) = build_tree(&leaves);
        // Single-leaf tree: depth is 0, root == leaf hash, proof is empty.
        assert_eq!(proofs[0].len(), 0);
        assert_eq!(root, leaf_hash(0, &addr(1), 100));
        assert!(verify_proof(0, &addr(1), 100, &proofs[0], &root));
    }

    #[test]
    fn two_leaf_tree_proof_verifies() {
        let leaves = vec![(addr(1), 100u128), (addr(2), 200u128)];
        let (root, proofs) = build_tree(&leaves);
        assert!(verify_proof(0, &addr(1), 100, &proofs[0], &root));
        assert!(verify_proof(1, &addr(2), 200, &proofs[1], &root));
    }

    #[test]
    fn eight_leaf_tree_all_proofs_verify() {
        let leaves: Vec<_> = (0..8).map(|i| (addr(i), (i as u128) * 100)).collect();
        let (root, proofs) = build_tree(&leaves);
        for (i, (a, amt)) in leaves.iter().enumerate() {
            assert!(
                verify_proof(i as u64, a, *amt, &proofs[i], &root),
                "proof {i} failed"
            );
        }
    }

    #[test]
    fn proof_rejects_wrong_address() {
        let leaves = vec![(addr(1), 100u128), (addr(2), 200u128)];
        let (root, proofs) = build_tree(&leaves);
        assert!(!verify_proof(0, &addr(99), 100, &proofs[0], &root));
    }

    #[test]
    fn proof_rejects_wrong_amount() {
        let leaves = vec![(addr(1), 100u128), (addr(2), 200u128)];
        let (root, proofs) = build_tree(&leaves);
        assert!(!verify_proof(0, &addr(1), 999, &proofs[0], &root));
    }

    #[test]
    fn proof_rejects_wrong_index() {
        let leaves = vec![(addr(1), 100u128), (addr(2), 200u128)];
        let (root, proofs) = build_tree(&leaves);
        // Using leaf 1's proof but claiming it's for leaf 0.
        assert!(!verify_proof(0, &addr(2), 200, &proofs[1], &root));
    }

    #[test]
    fn proof_rejects_mutated_sibling() {
        let leaves = vec![(addr(1), 100u128), (addr(2), 200u128)];
        let (root, mut proofs) = build_tree(&leaves);
        proofs[0][0][0] ^= 0xFF;
        assert!(!verify_proof(0, &addr(1), 100, &proofs[0], &root));
    }

    #[test]
    fn claim_payload_roundtrip() {
        let payload = ClaimPayload {
            leaf_index: 42,
            amount: 1_000_000,
            proof: vec![[0xAB; 32], [0xCD; 32], [0xEF; 32]],
        };
        let bytes = payload.encode();
        let decoded = ClaimPayload::decode(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn claim_payload_rejects_truncated() {
        assert_eq!(ClaimPayload::decode(&[]), None);
        assert_eq!(ClaimPayload::decode(&[0u8; 20]), None);
    }

    #[test]
    fn claim_payload_rejects_length_mismatch() {
        let mut payload = ClaimPayload {
            leaf_index: 0,
            amount: 0,
            proof: vec![[0xAB; 32]],
        };
        let bytes = payload.encode();
        // Claim proof_len=1 but only supply empty siblings.
        let mut truncated = bytes.clone();
        truncated.truncate(MIN_CLAIM_DATA_LEN);
        assert_eq!(ClaimPayload::decode(&truncated), None);

        // Claim proof_len=0 but append extra bytes.
        payload.proof.clear();
        let mut extended = payload.encode();
        extended.extend_from_slice(&[0u8; 32]);
        assert_eq!(ClaimPayload::decode(&extended), None);
    }
}
