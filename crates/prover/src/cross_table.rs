//! Cross-table permutation argument: connects execution, memory, and Poseidon2 AIRs.
//!
//! Architecture:
//!   Execution AIR ←→ Memory AIR ←→ Poseidon2 AIR
//!
//! Each cross-table connection uses a randomized multiset equality check:
//! 1. Both tables compute a "running product" column
//! 2. Running product = product over all rows of (alpha - row_fingerprint)
//! 3. If both tables have the same multiset of fingerprints, their products match
//! 4. The verifier checks: execution_product == memory_product (etc.)
//!
//! This ensures:
//! - Every memory access in the execution trace has a matching entry in memory AIR
//! - Every hash request in the execution trace has a matching entry in Poseidon2 AIR
//! - No fabricated entries exist in either sub-table

use p3_field::AbstractField;
use p3_goldilocks::Goldilocks;

/// A "bus" entry: a tuple of field elements that must appear in both tables.
#[derive(Clone, Debug)]
pub struct BusEntry {
    pub fields: Vec<Goldilocks>,
}

/// Compute the fingerprint of a bus entry using a random challenge alpha.
/// fingerprint = alpha^n * fields[0] + alpha^(n-1) * fields[1] + ... + fields[n-1]
/// (random linear combination for Schwartz-Zippel collision resistance)
pub fn fingerprint(entry: &BusEntry, alpha: Goldilocks) -> Goldilocks {
    let mut result = Goldilocks::zero();
    let mut power = Goldilocks::one();
    for f in &entry.fields {
        result = result + power * *f;
        power = power * alpha;
    }
    result
}

/// Compute the running product for a table.
/// product = Π (alpha_prime - fingerprint(row_i))
/// where alpha_prime is a second random challenge.
pub fn running_product(
    entries: &[BusEntry],
    alpha: Goldilocks,
    alpha_prime: Goldilocks,
) -> Goldilocks {
    let mut product = Goldilocks::one();
    for entry in entries {
        let fp = fingerprint(entry, alpha);
        product = product * (alpha_prime - fp);
    }
    product
}

/// Verify that two tables have the same multiset of entries.
/// Returns true if the running products match.
pub fn verify_permutation(
    table_a: &[BusEntry],
    table_b: &[BusEntry],
    alpha: Goldilocks,
    alpha_prime: Goldilocks,
) -> bool {
    let prod_a = running_product(table_a, alpha, alpha_prime);
    let prod_b = running_product(table_b, alpha, alpha_prime);
    prod_a == prod_b
}

/// Extract memory bus entries from the execution trace.
/// Each memory operation becomes a bus entry: (addr, value, is_write, timestamp).
pub fn extract_memory_bus(
    addrs: &[u64],
    values: &[u64],
    is_writes: &[bool],
    timestamps: &[u64],
) -> Vec<BusEntry> {
    addrs
        .iter()
        .zip(values.iter())
        .zip(is_writes.iter())
        .zip(timestamps.iter())
        .map(|(((a, v), w), t)| BusEntry {
            fields: vec![
                Goldilocks::from_canonical_u64(*a),
                Goldilocks::from_canonical_u64(*v),
                if *w { Goldilocks::one() } else { Goldilocks::zero() },
                Goldilocks::from_canonical_u64(*t),
            ],
        })
        .collect()
}

/// Extract hash bus entries from execution trace.
/// Each SLOAD/SSTORE with Merkle verification becomes a hash bus entry.
pub fn extract_hash_bus(
    inputs: &[[u64; 8]],
    outputs: &[[u64; 8]],
) -> Vec<BusEntry> {
    inputs
        .iter()
        .zip(outputs.iter())
        .map(|(inp, out)| {
            let mut fields = Vec::with_capacity(16);
            for v in inp {
                fields.push(Goldilocks::from_canonical_u64(*v));
            }
            for v in out {
                fields.push(Goldilocks::from_canonical_u64(*v));
            }
            BusEntry { fields }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(vals: &[u64]) -> BusEntry {
        BusEntry {
            fields: vals.iter().map(|v| Goldilocks::from_canonical_u64(*v)).collect(),
        }
    }

    #[test]
    fn same_multiset_matches() {
        let alpha = Goldilocks::from_canonical_u64(12345);
        let alpha_prime = Goldilocks::from_canonical_u64(67890);

        let table_a = vec![
            make_entry(&[1, 2, 3]),
            make_entry(&[4, 5, 6]),
            make_entry(&[7, 8, 9]),
        ];

        // Same entries, different order (permutation)
        let table_b = vec![
            make_entry(&[4, 5, 6]),
            make_entry(&[7, 8, 9]),
            make_entry(&[1, 2, 3]),
        ];

        assert!(verify_permutation(&table_a, &table_b, alpha, alpha_prime));
    }

    #[test]
    fn different_multiset_fails() {
        let alpha = Goldilocks::from_canonical_u64(12345);
        let alpha_prime = Goldilocks::from_canonical_u64(67890);

        let table_a = vec![make_entry(&[1, 2, 3])];
        let table_b = vec![make_entry(&[1, 2, 4])]; // different!

        assert!(!verify_permutation(&table_a, &table_b, alpha, alpha_prime));
    }

    #[test]
    fn empty_tables_match() {
        let alpha = Goldilocks::from_canonical_u64(12345);
        let alpha_prime = Goldilocks::from_canonical_u64(67890);

        assert!(verify_permutation(&[], &[], alpha, alpha_prime));
    }

    #[test]
    fn memory_bus_extraction() {
        let addrs = vec![100, 200, 100];
        let values = vec![42, 99, 42];
        let writes = vec![true, true, false];
        let timestamps = vec![0, 1, 2];

        let bus = extract_memory_bus(&addrs, &values, &writes, &timestamps);
        assert_eq!(bus.len(), 3);
        assert_eq!(bus[0].fields.len(), 4);
    }

    #[test]
    fn memory_permutation_with_sorted() {
        let alpha = Goldilocks::from_canonical_u64(99999);
        let alpha_prime = Goldilocks::from_canonical_u64(88888);

        // Execution order
        let exec_bus = vec![
            make_entry(&[200, 99, 1, 1]),  // write 99 to addr 200 at t=1
            make_entry(&[100, 42, 1, 0]),  // write 42 to addr 100 at t=0
            make_entry(&[100, 42, 0, 2]),  // read 42 from addr 100 at t=2
        ];

        // Memory AIR (sorted by addr, then time)
        let sorted_bus = vec![
            make_entry(&[100, 42, 1, 0]),  // addr 100, t=0
            make_entry(&[100, 42, 0, 2]),  // addr 100, t=2
            make_entry(&[200, 99, 1, 1]),  // addr 200, t=1
        ];

        // Same multiset → permutation matches
        assert!(verify_permutation(&exec_bus, &sorted_bus, alpha, alpha_prime));
    }

    #[test]
    fn fingerprint_deterministic() {
        let alpha = Goldilocks::from_canonical_u64(42);
        let entry = make_entry(&[1, 2, 3]);
        assert_eq!(fingerprint(&entry, alpha), fingerprint(&entry, alpha));
    }

    #[test]
    fn different_alpha_different_fingerprint() {
        let entry = make_entry(&[1, 2, 3]);
        let fp1 = fingerprint(&entry, Goldilocks::from_canonical_u64(42));
        let fp2 = fingerprint(&entry, Goldilocks::from_canonical_u64(43));
        assert_ne!(fp1, fp2);
    }
}
