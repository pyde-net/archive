//! Property tests for airdrop claim + Merkle verification (slice 4.4b).

use proptest::prelude::*;
use pyde_tx::airdrop::{build_tree, leaf_hash, verify_proof, ClaimPayload, MAX_PROOF_LEN};

fn any_address() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

fn any_proof() -> impl Strategy<Value = Vec<[u8; 32]>> {
    prop::collection::vec(prop::array::uniform32(any::<u8>()), 0..=MAX_PROOF_LEN)
}

/// Arbitrary leaf set for tree construction. Bounded to 64 leaves so
/// tree building stays cheap (256 proptest cases × tree build).
fn any_leaves() -> impl Strategy<Value = Vec<([u8; 32], u128)>> {
    prop::collection::vec((any_address(), any::<u128>()), 1..=64)
}

proptest! {
    /// ClaimPayload encode→decode roundtrip for arbitrary inputs.
    #[test]
    fn claim_payload_roundtrip(
        leaf_index in any::<u64>(),
        amount in any::<u128>(),
        proof in any_proof(),
    ) {
        let payload = ClaimPayload { leaf_index, amount, proof };
        let bytes = payload.encode();
        let decoded = ClaimPayload::decode(&bytes).unwrap();
        prop_assert_eq!(payload, decoded);
    }

    /// Decoder must never panic on arbitrary bytes.
    #[test]
    fn claim_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..=16_000)) {
        let _ = ClaimPayload::decode(&bytes);
    }

    /// `leaf_hash` must differ whenever any of (index, address, amount)
    /// differ. Proves the hash domain separates each input field.
    #[test]
    fn leaf_hash_distinguishes_inputs(
        i1 in any::<u64>(),
        i2 in any::<u64>(),
        a1 in any_address(),
        a2 in any_address(),
        v1 in any::<u128>(),
        v2 in any::<u128>(),
    ) {
        prop_assume!((i1, a1, v1) != (i2, a2, v2));
        prop_assert_ne!(leaf_hash(i1, &a1, v1), leaf_hash(i2, &a2, v2));
    }

    /// For any tree built from a leaf set, every leaf's generated
    /// proof must verify against the tree's root. This is the
    /// fundamental soundness property of the airdrop commitment.
    #[test]
    fn every_generated_proof_verifies(leaves in any_leaves()) {
        let (root, proofs) = build_tree(&leaves);
        for (i, (addr, amt)) in leaves.iter().enumerate() {
            prop_assert!(
                verify_proof(i as u64, addr, *amt, &proofs[i], &root),
                "proof {} did not verify",
                i
            );
        }
    }

    /// Mutating any byte of a valid proof must cause verification
    /// to fail. This is the tamper-detection property: an attacker
    /// can't flip a single sibling bit and have the proof still
    /// verify for the same leaf.
    #[test]
    fn mutated_proof_bit_breaks_verify(
        leaves in any_leaves(),
        leaf_select in 0usize..64,
        sibling_select in 0usize..64,
        bit_select in 0usize..256,
    ) {
        let (root, proofs) = build_tree(&leaves);
        let leaf_idx = leaf_select % leaves.len();
        let proof = &proofs[leaf_idx];
        // Skip leaves whose proof is empty (single-leaf tree) — no
        // sibling to mutate.
        prop_assume!(!proof.is_empty());
        let sibling_idx = sibling_select % proof.len();
        let byte_idx = (bit_select / 8) % 32;
        let bit_idx = bit_select % 8;

        let mut mutated = proof.clone();
        mutated[sibling_idx][byte_idx] ^= 1 << bit_idx;

        let (addr, amt) = leaves[leaf_idx];
        prop_assert!(
            !verify_proof(leaf_idx as u64, &addr, amt, &mutated, &root),
            "mutated proof unexpectedly verified"
        );
    }

    /// Claiming with the wrong address must fail verification even if
    /// everything else is correct.
    #[test]
    fn wrong_address_breaks_verify(leaves in any_leaves(), imposter in any_address()) {
        let (root, proofs) = build_tree(&leaves);
        let idx = 0usize;
        let (legit_addr, amt) = leaves[idx];
        prop_assume!(imposter != legit_addr);
        prop_assert!(
            !verify_proof(idx as u64, &imposter, amt, &proofs[idx], &root),
            "imposter unexpectedly verified"
        );
    }

    /// Claiming the wrong amount must fail verification.
    #[test]
    fn wrong_amount_breaks_verify(leaves in any_leaves(), wrong_amt in any::<u128>()) {
        let (root, proofs) = build_tree(&leaves);
        let idx = 0usize;
        let (addr, legit_amt) = leaves[idx];
        prop_assume!(wrong_amt != legit_amt);
        prop_assert!(
            !verify_proof(idx as u64, &addr, wrong_amt, &proofs[idx], &root),
            "wrong-amount unexpectedly verified"
        );
    }
}
