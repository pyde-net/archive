use alloc::vec;
use alloc::vec::Vec;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{
    Goldilocks, Poseidon2GoldilocksHL, HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
    HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS,
};
use p3_poseidon2::{ExternalLayerConstants, Poseidon2};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};

use crate::hash::Hash256;

/// Poseidon2 over Goldilocks field.
///
/// - State width: 8 field elements (512 bits)
/// - Rate: 4 field elements absorbed per permutation
/// - Output: 4 field elements (256 bits → Hash256)
/// - S-box degree: 7
/// - External rounds: 8, Internal rounds: 22
const WIDTH: usize = 8;
const RATE: usize = 4;
const OUT: usize = 4;

type Perm = Poseidon2GoldilocksHL<WIDTH>;
type Sponge = PaddingFreeSponge<Perm, WIDTH, RATE, OUT>;

fn make_perm() -> Perm {
    Poseidon2::new(
        ExternalLayerConstants::<Goldilocks, WIDTH>::new_from_saved_array(
            HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
            Goldilocks::new_array,
        ),
        Goldilocks::new_array(HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS).to_vec(),
    )
}

fn make_sponge() -> Sponge {
    PaddingFreeSponge::new(make_perm())
}

/// Convert 4 Goldilocks field elements to Hash256 (each element = 8 bytes LE).
fn elements_to_hash(elements: [Goldilocks; OUT]) -> Hash256 {
    let mut bytes = [0u8; 32];
    for (i, el) in elements.iter().enumerate() {
        let val = goldilocks_to_u64(*el);
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
    }
    Hash256::new(bytes)
}

fn goldilocks_to_u64(el: Goldilocks) -> u64 {
    el.as_canonical_u64()
}

fn u64_to_goldilocks(val: u64) -> Goldilocks {
    PrimeCharacteristicRing::from_u64(val)
}

/// Convert raw bytes to Goldilocks field elements.
/// Each 7-byte chunk is interpreted as a little-endian u64 (fits in Goldilocks).
/// We use 7 bytes per element to avoid exceeding the field modulus (2^64 - 2^32 + 1).
fn bytes_to_elements(data: &[u8]) -> Vec<Goldilocks> {
    const CHUNK: usize = 7;
    if data.is_empty() {
        return vec![Goldilocks::ZERO];
    }
    let mut elements = Vec::with_capacity((data.len() + CHUNK - 1) / CHUNK + 1);
    for chunk in data.chunks(CHUNK) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        elements.push(u64_to_goldilocks(u64::from_le_bytes(buf)));
    }
    // Append length as domain separator to prevent collisions
    elements.push(u64_to_goldilocks(data.len() as u64));
    elements
}

fn hash256_to_elements(hash: &Hash256) -> [Goldilocks; 4] {
    let b = hash.as_bytes();
    [
        u64_to_goldilocks(u64::from_le_bytes(b[0..8].try_into().unwrap())),
        u64_to_goldilocks(u64::from_le_bytes(b[8..16].try_into().unwrap())),
        u64_to_goldilocks(u64::from_le_bytes(b[16..24].try_into().unwrap())),
        u64_to_goldilocks(u64::from_le_bytes(b[24..32].try_into().unwrap())),
    ]
}

/// Hash arbitrary bytes → Hash256.
pub fn poseidon2_hash(data: &[u8]) -> Hash256 {
    let sponge = make_sponge();
    let elements = bytes_to_elements(data);
    let out = sponge.hash_iter(elements);
    elements_to_hash(out)
}

/// Hash two Hash256 values together (for Merkle trees).
pub fn poseidon2_pair(left: Hash256, right: Hash256) -> Hash256 {
    let sponge = make_sponge();
    let l = hash256_to_elements(&left);
    let r = hash256_to_elements(&right);
    let elements = l.iter().chain(r.iter()).copied().collect::<Vec<_>>();
    let out = sponge.hash_iter(elements);
    elements_to_hash(out)
}

/// Hash multiple Hash256 values together (variable-length sponge).
pub fn poseidon2_many(hashes: &[Hash256]) -> Hash256 {
    let sponge = make_sponge();
    let elements: Vec<Goldilocks> = hashes.iter().flat_map(|h| hash256_to_elements(h)).collect();
    let out = sponge.hash_iter(elements);
    elements_to_hash(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_empty() {
        let h = poseidon2_hash(&[]);
        assert_ne!(h, Hash256::ZERO);
    }

    #[test]
    fn hash_single_byte() {
        let h = poseidon2_hash(&[0x42]);
        assert_ne!(h, Hash256::ZERO);
    }

    #[test]
    fn hash_deterministic() {
        let a = poseidon2_hash(b"hello");
        let b = poseidon2_hash(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_different_inputs_differ() {
        let a = poseidon2_hash(b"hello");
        let b = poseidon2_hash(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_length_extension_safe() {
        let a = poseidon2_hash(b"ab");
        let b = poseidon2_hash(b"ab\x00");
        assert_ne!(a, b);
    }

    #[test]
    fn pair_deterministic() {
        let a = poseidon2_hash(b"left");
        let b = poseidon2_hash(b"right");
        let p1 = poseidon2_pair(a, b);
        let p2 = poseidon2_pair(a, b);
        assert_eq!(p1, p2);
    }

    #[test]
    fn pair_order_matters() {
        let a = poseidon2_hash(b"left");
        let b = poseidon2_hash(b"right");
        let p1 = poseidon2_pair(a, b);
        let p2 = poseidon2_pair(b, a);
        assert_ne!(p1, p2);
    }

    #[test]
    fn pair_differs_from_inputs() {
        let a = poseidon2_hash(b"a");
        let b = poseidon2_hash(b"b");
        let p = poseidon2_pair(a, b);
        assert_ne!(p, a);
        assert_ne!(p, b);
    }

    #[test]
    fn many_single_element() {
        let h = poseidon2_hash(b"test");
        let m = poseidon2_many(&[h]);
        assert_ne!(m, Hash256::ZERO);
    }

    #[test]
    fn many_deterministic() {
        let a = poseidon2_hash(b"a");
        let b = poseidon2_hash(b"b");
        let c = poseidon2_hash(b"c");
        let m1 = poseidon2_many(&[a, b, c]);
        let m2 = poseidon2_many(&[a, b, c]);
        assert_eq!(m1, m2);
    }

    #[test]
    fn many_order_matters() {
        let a = poseidon2_hash(b"a");
        let b = poseidon2_hash(b"b");
        let m1 = poseidon2_many(&[a, b]);
        let m2 = poseidon2_many(&[b, a]);
        assert_ne!(m1, m2);
    }

    #[test]
    fn many_different_lengths_differ() {
        let a = poseidon2_hash(b"a");
        let b = poseidon2_hash(b"b");
        let m1 = poseidon2_many(&[a]);
        let m2 = poseidon2_many(&[a, b]);
        assert_ne!(m1, m2);
    }

    #[test]
    fn pair_matches_many_two() {
        let a = poseidon2_hash(b"x");
        let b = poseidon2_hash(b"y");
        let p = poseidon2_pair(a, b);
        let m = poseidon2_many(&[a, b]);
        assert_eq!(p, m);
    }

    // --- Task 0011: Edge cases ---

    #[test]
    fn hash_max_single_chunk() {
        let h = poseidon2_hash(&[0xFF; 7]);
        assert_ne!(h, Hash256::ZERO);
    }

    #[test]
    fn hash_two_chunks() {
        let h = poseidon2_hash(&[0xAB; 8]);
        assert_ne!(h, Hash256::ZERO);
    }

    #[test]
    fn hash_large_input() {
        let data = vec![0x55u8; 1024];
        let h = poseidon2_hash(&data);
        assert_ne!(h, Hash256::ZERO);
    }

    #[test]
    fn hash_all_zeros() {
        let h = poseidon2_hash(&[0u8; 32]);
        assert_ne!(h, Hash256::ZERO);
    }

    #[test]
    fn hash_all_ones() {
        let h = poseidon2_hash(&[0xFF; 32]);
        assert_ne!(h, Hash256::ZERO);
    }

    #[test]
    fn hash_sequential_bytes() {
        let data: Vec<u8> = (0..=255).collect();
        let h = poseidon2_hash(&data);
        assert_ne!(h, Hash256::ZERO);
    }

    #[test]
    fn pair_with_zero_hash() {
        let a = Hash256::ZERO;
        let b = poseidon2_hash(b"nonzero");
        let p = poseidon2_pair(a, b);
        assert_ne!(p, Hash256::ZERO);
    }

    #[test]
    fn many_empty_slice() {
        let m = poseidon2_many(&[]);
        assert_eq!(m, m); // doesn't panic
    }

    // --- Task 0015: Verify algebraic degree matches expected security level ---

    #[test]
    fn sbox_degree_is_coprime_to_p_minus_1() {
        // Goldilocks: p = 2^64 - 2^32 + 1
        // p - 1 = 2^64 - 2^32 = 2^32 * (2^32 - 1) = 2^32 * 3 * 5 * 17 * 257 * 65537
        // S-box degree D = 7 must satisfy gcd(p-1, D) = 1
        // 7 is prime and doesn't divide any factor of p-1, so gcd = 1
        let p_minus_1: u64 = 0u64.wrapping_sub(1u64 << 32); // 2^64 - 2^32
        let d: u64 = 7;
        assert_eq!(gcd(p_minus_1, d), 1, "S-box degree must be coprime to p-1");
    }

    #[test]
    fn round_counts_match_128_bit_security() {
        // For Poseidon2 over Goldilocks with WIDTH=8, D=7:
        // External rounds (RF) = 8, Internal rounds (RI) = 22
        // This matches Plonky3's poseidon2_round_numbers_128 output
        let external_rounds = HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS[0].len()
            + HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS[1].len();
        let internal_rounds = HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS.len();

        assert_eq!(
            external_rounds, 8,
            "Expected 8 external rounds (4 initial + 4 terminal)"
        );
        assert_eq!(
            internal_rounds, 22,
            "Expected 22 internal rounds for 128-bit security"
        );
    }

    #[test]
    fn state_width_provides_sufficient_capacity() {
        // WIDTH=8, RATE=4, CAPACITY=4
        // Capacity = 4 Goldilocks elements = 4 * 64 = 256 bits
        // For 128-bit security, capacity >= 2 * security_level = 256 bits ✓
        let capacity = WIDTH - RATE;
        assert_eq!(capacity, 4);
        let capacity_bits = capacity * 64;
        assert!(
            capacity_bits >= 256,
            "Capacity must be >= 256 bits for 128-bit security"
        );
    }

    fn gcd(mut a: u64, mut b: u64) -> u64 {
        while b != 0 {
            let t = b;
            b = a % b;
            a = t;
        }
        a
    }
}
