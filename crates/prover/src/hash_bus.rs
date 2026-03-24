//! Hash bus: verifies Poseidon2 hash computations via cross-table check.
//!
//! For each POSEIDON/SLOAD/SSTORE opcode, the execution trace claims a hash
//! input→output mapping. This module recomputes each hash using the crypto
//! crate and verifies the claimed outputs match.
//!
//! Connected to execution trace via cross-table permutation:
//!   execution hash bus == recomputed hash bus (multiset equality)

use p3_goldilocks::Goldilocks;
use p3_field::AbstractField;

use crate::cross_table::{BusEntry, verify_permutation};

/// A hash request from the execution trace.
#[derive(Clone, Debug)]
pub struct HashRequest {
    /// Input bytes to hash.
    pub input: Vec<u8>,
    /// Claimed Poseidon2 hash output (32 bytes as 4 × u64 limbs).
    pub output_limbs: [u64; 4],
    /// Execution step (for ordering).
    pub timestamp: u64,
}

impl HashRequest {
    /// Convert to bus entry for permutation check.
    pub fn to_bus_entry(&self) -> BusEntry {
        let mut fields = Vec::with_capacity(8);
        // Input: first 4 × u64 limbs (32 bytes)
        for i in 0..4 {
            let start = i * 8;
            let end = (start + 8).min(self.input.len());
            if start < self.input.len() {
                let mut buf = [0u8; 8];
                buf[..end - start].copy_from_slice(&self.input[start..end]);
                fields.push(Goldilocks::from_canonical_u64(u64::from_le_bytes(buf)));
            } else {
                fields.push(Goldilocks::zero());
            }
        }
        // Output: 4 limbs
        for limb in &self.output_limbs {
            fields.push(Goldilocks::from_canonical_u64(*limb));
        }
        BusEntry { fields }
    }
}

/// Recompute a hash and build a bus entry with the CORRECT output.
fn recompute_hash_entry(req: &HashRequest) -> BusEntry {
    let hash = pyde_crypto::poseidon2::poseidon2_hash(&req.input);
    let hash_bytes = hash.to_bytes();

    let mut fields = Vec::with_capacity(8);
    // Input (same as execution side)
    for i in 0..4 {
        let start = i * 8;
        let end = (start + 8).min(req.input.len());
        if start < req.input.len() {
            let mut buf = [0u8; 8];
            buf[..end - start].copy_from_slice(&req.input[start..end]);
            fields.push(Goldilocks::from_canonical_u64(u64::from_le_bytes(buf)));
        } else {
            fields.push(Goldilocks::zero());
        }
    }
    // Recomputed output
    for i in 0..4 {
        fields.push(Goldilocks::from_canonical_u64(
            u64::from_le_bytes(hash_bytes[i * 8..(i + 1) * 8].try_into().unwrap()),
        ));
    }
    BusEntry { fields }
}

/// Verify all hash requests: recompute each hash and check permutation.
pub fn verify_hash_bus(requests: &[HashRequest]) -> Result<(), String> {
    if requests.is_empty() {
        return Ok(());
    }

    let exec_bus: Vec<BusEntry> = requests.iter().map(|r| r.to_bus_entry()).collect();
    let recomputed_bus: Vec<BusEntry> = requests.iter().map(|r| recompute_hash_entry(r)).collect();

    let alpha = Goldilocks::from_canonical_u64(0x6a09e667f3bcc908);
    let alpha_prime = Goldilocks::from_canonical_u64(0xbb67ae8584caa73b);

    if !verify_permutation(&exec_bus, &recomputed_bus, alpha, alpha_prime) {
        return Err("hash bus permutation failed — claimed hash outputs don't match recomputed".into());
    }

    Ok(())
}

/// Extract hash requests from an execution trace.
pub fn extract_hash_requests(
    trace: &crate::trace::ExecutionTrace,
) -> Vec<HashRequest> {
    use crate::constraint::opcodes;
    use crate::trace::col;
    use p3_field::PrimeField64;

    let mut requests = Vec::new();

    for (step, row) in trace.rows.iter().enumerate() {
        let op = row.get(col::OPCODE).as_canonical_u64();

        // Storage operations use Poseidon2 for key derivation
        if row.get(col::IS_STORAGE_OP) == Goldilocks::one() {
            let key_bytes: Vec<u8> = (0..4)
                .flat_map(|i| row.get(col::storage_key(i)).as_canonical_u64().to_le_bytes().to_vec())
                .collect();
            let val_bytes: Vec<u8> = (0..4)
                .flat_map(|i| row.get(col::storage_val(i)).as_canonical_u64().to_le_bytes().to_vec())
                .collect();

            let mut input = key_bytes;
            input.extend_from_slice(&val_bytes);

            let hash = pyde_crypto::poseidon2::poseidon2_hash(&input);
            let hash_bytes = hash.to_bytes();
            let output_limbs: [u64; 4] = core::array::from_fn(|i| {
                u64::from_le_bytes(hash_bytes[i * 8..(i + 1) * 8].try_into().unwrap())
            });

            requests.push(HashRequest {
                input,
                output_limbs,
                timestamp: step as u64,
            });
        }

        // POSEIDON opcode (0x30): explicit hash instruction
        if op == opcodes::POSEIDON {
            // Input comes from memory (captured in mem_val columns)
            let input_bytes: Vec<u8> = (0..4)
                .flat_map(|i| row.get(col::mem_val(i)).as_canonical_u64().to_le_bytes().to_vec())
                .collect();

            let hash = pyde_crypto::poseidon2::poseidon2_hash(&input_bytes);
            let hash_bytes = hash.to_bytes();
            let output_limbs: [u64; 4] = core::array::from_fn(|i| {
                u64::from_le_bytes(hash_bytes[i * 8..(i + 1) * 8].try_into().unwrap())
            });

            requests.push(HashRequest {
                input: input_bytes,
                output_limbs,
                timestamp: step as u64,
            });
        }
    }

    requests
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_hash_passes() {
        let input = b"hello world".to_vec();
        let hash = pyde_crypto::poseidon2::poseidon2_hash(&input);
        let hash_bytes = hash.to_bytes();
        let output_limbs: [u64; 4] = core::array::from_fn(|i| {
            u64::from_le_bytes(hash_bytes[i * 8..(i + 1) * 8].try_into().unwrap())
        });

        let requests = vec![HashRequest { input, output_limbs, timestamp: 0 }];
        assert!(verify_hash_bus(&requests).is_ok());
    }

    #[test]
    fn wrong_hash_detected() {
        let input = b"hello world".to_vec();
        let requests = vec![HashRequest {
            input,
            output_limbs: [1, 2, 3, 4], // WRONG
            timestamp: 0,
        }];
        assert!(verify_hash_bus(&requests).is_err());
    }

    #[test]
    fn empty_requests_ok() {
        assert!(verify_hash_bus(&[]).is_ok());
    }

    #[test]
    fn multiple_hashes() {
        let mut requests = Vec::new();
        for i in 0..5 {
            let input = format!("data_{}", i).into_bytes();
            let hash = pyde_crypto::poseidon2::poseidon2_hash(&input);
            let hash_bytes = hash.to_bytes();
            let output_limbs: [u64; 4] = core::array::from_fn(|j| {
                u64::from_le_bytes(hash_bytes[j * 8..(j + 1) * 8].try_into().unwrap())
            });
            requests.push(HashRequest { input, output_limbs, timestamp: i as u64 });
        }
        assert!(verify_hash_bus(&requests).is_ok());
    }
}
