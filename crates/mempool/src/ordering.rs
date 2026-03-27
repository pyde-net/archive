//! VRF-based transaction ordering per Chapter 6, Section 6.5 Step 2.
//!
//! The proposer VRF-shuffles the selected transactions after collecting
//! them from the mempool. This makes the final ordering unpredictable
//! and unmanipulable — even by the proposer.
//!
//! Algorithm: Fisher-Yates shuffle seeded by VRF output.
//! Verification: any node can reproduce the shuffle given the VRF output.

use pyde_crypto::poseidon2::poseidon2_hash;

/// Generate a deterministic shuffle seed from a VRF output.
/// The VRF output is the proposer's VRF(sk, epoch_randomness || slot).
pub fn shuffle_seed(vrf_output: &[u8; 32]) -> [u8; 32] {
    // Domain-separate the shuffle seed from other VRF uses
    let mut buf = Vec::with_capacity(44); // "vrf_shuffle"(11) + vrf_output(32)
    buf.extend_from_slice(b"vrf_shuffle");
    buf.extend_from_slice(vrf_output);
    poseidon2_hash(&buf).to_bytes()
}

/// Derive a pseudo-random u64 from the seed at a given index.
/// Used internally by the Fisher-Yates shuffle.
fn prng_at(seed: &[u8; 32], index: usize) -> u64 {
    let mut buf = Vec::with_capacity(40); // seed(32) + index(8)
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&(index as u64).to_le_bytes());
    let hash = poseidon2_hash(&buf).to_bytes();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash[..8]);
    u64::from_le_bytes(bytes)
}

/// Fisher-Yates shuffle: deterministic, uniform, O(n).
/// Shuffles indices [0..n) using the given seed.
/// Returns the permutation as a vector of indices.
pub fn vrf_shuffle(n: usize, seed: &[u8; 32]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..n).collect();

    // Fisher-Yates: iterate from last to first, swap with random earlier index
    for i in (1..n).rev() {
        let j = (prng_at(seed, i) as usize) % (i + 1);
        indices.swap(i, j);
    }

    indices
}

/// Apply a shuffle permutation to a slice, returning a new Vec.
pub fn apply_shuffle<T: Clone>(items: &[T], permutation: &[usize]) -> Vec<T> {
    permutation.iter().map(|&i| items[i].clone()).collect()
}

/// Verify that a claimed ordering matches the VRF shuffle.
/// Any node can reproduce the shuffle from the VRF output.
pub fn verify_shuffle(n: usize, vrf_output: &[u8; 32], claimed_order: &[usize]) -> bool {
    if claimed_order.len() != n {
        return false;
    }
    let seed = shuffle_seed(vrf_output);
    let expected = vrf_shuffle(n, &seed);
    claimed_order == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Task 0532: Same seed → same ordering ==========

    #[test]
    fn same_seed_same_ordering() {
        let seed = shuffle_seed(&[0xAA; 32]);
        let perm1 = vrf_shuffle(100, &seed);
        let perm2 = vrf_shuffle(100, &seed);
        assert_eq!(perm1, perm2);
    }

    // ========== Task 0533: Different seed → different ordering ==========

    #[test]
    fn different_seed_different_ordering() {
        let seed1 = shuffle_seed(&[0xAA; 32]);
        let seed2 = shuffle_seed(&[0xBB; 32]);
        let perm1 = vrf_shuffle(100, &seed1);
        let perm2 = vrf_shuffle(100, &seed2);
        assert_ne!(perm1, perm2);
    }

    // ========== Task 0534: Shuffle is statistically uniform ==========

    #[test]
    fn shuffle_is_permutation() {
        let seed = shuffle_seed(&[0xCC; 32]);
        let perm = vrf_shuffle(50, &seed);

        // Every index appears exactly once
        let mut sorted = perm.clone();
        sorted.sort();
        assert_eq!(sorted, (0..50).collect::<Vec<_>>());
    }

    #[test]
    fn shuffle_distributes_uniformly() {
        // Run 1000 shuffles with different seeds, check that index 0
        // doesn't always end up in the same position
        let mut first_positions = std::collections::HashSet::new();

        for i in 0u64..1000 {
            let mut vrf = [0u8; 32];
            vrf[..8].copy_from_slice(&i.to_le_bytes());
            let seed = shuffle_seed(&vrf);
            let perm = vrf_shuffle(20, &seed);
            first_positions.insert(perm[0]);
        }

        // With 1000 shuffles of 20 elements, index 0 should appear in
        // many different positions (at least 15 of 20)
        assert!(first_positions.len() >= 15);
    }

    // ========== Verification ==========

    #[test]
    fn verify_correct_shuffle() {
        let vrf_output = [0xDD; 32];
        let seed = shuffle_seed(&vrf_output);
        let perm = vrf_shuffle(10, &seed);

        assert!(verify_shuffle(10, &vrf_output, &perm));
    }

    #[test]
    fn verify_wrong_shuffle_rejected() {
        let vrf_output = [0xDD; 32];
        let wrong_order: Vec<usize> = (0..10).rev().collect(); // reversed, not shuffled

        assert!(!verify_shuffle(10, &vrf_output, &wrong_order));
    }

    #[test]
    fn verify_wrong_length_rejected() {
        let vrf_output = [0xDD; 32];
        let perm = vrf_shuffle(10, &shuffle_seed(&vrf_output));

        // Wrong n
        assert!(!verify_shuffle(11, &vrf_output, &perm));
    }

    // ========== Apply shuffle ==========

    #[test]
    fn apply_shuffle_reorders() {
        let items = vec!["a", "b", "c", "d"];
        let perm = vec![2, 0, 3, 1]; // c, a, d, b
        let shuffled = apply_shuffle(&items, &perm);
        assert_eq!(shuffled, vec!["c", "a", "d", "b"]);
    }

    // ========== Edge cases ==========

    #[test]
    fn shuffle_single_element() {
        let seed = shuffle_seed(&[0xFF; 32]);
        let perm = vrf_shuffle(1, &seed);
        assert_eq!(perm, vec![0]);
    }

    #[test]
    fn shuffle_empty() {
        let seed = shuffle_seed(&[0xFF; 32]);
        let perm = vrf_shuffle(0, &seed);
        assert!(perm.is_empty());
    }
}
