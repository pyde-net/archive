//! Lookup table for bitwise operations (AND, OR, XOR, NOT).
//!
//! Instead of 64-bit bit-decomposition constraints (128 extra columns),
//! we verify bitwise ops via byte-level lookups against a precomputed table.
//!
//! For each 64-bit bitwise operation:
//!   1. Decompose op_a, op_b, result into 8 bytes each
//!   2. For each byte position: verify (a_byte, b_byte, result_byte, op_type)
//!      exists in the precomputed table
//!   3. Verify the bytes reconstruct to the original values
//!
//! The table is verified via cross-table permutation argument:
//!   execution_bus entries == lookup_table entries (multiset equality)
//!
//! Table size: 256 × 256 × 4 ops = 262,144 rows (precomputed, fixed)
//! Lookups per 64-bit op: 8 (one per byte)
//! Lookups per 256-bit wide op: 32 (4 limbs × 8 bytes)

use p3_goldilocks::Goldilocks;
use p3_field::AbstractField;

use crate::cross_table::{BusEntry, verify_permutation};

/// Bitwise operation type tag for the lookup table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitwiseOp {
    And = 0,
    Or = 1,
    Xor = 2,
    Not = 3,
}

/// A single lookup query: one byte position of a bitwise operation.
#[derive(Clone, Debug)]
pub struct LookupQuery {
    pub a_byte: u8,
    pub b_byte: u8,
    pub result_byte: u8,
    pub op_type: BitwiseOp,
}

impl LookupQuery {
    /// Convert to a bus entry for cross-table permutation.
    pub fn to_bus_entry(&self) -> BusEntry {
        BusEntry {
            fields: vec![
                Goldilocks::from_canonical_u64(self.a_byte as u64),
                Goldilocks::from_canonical_u64(self.b_byte as u64),
                Goldilocks::from_canonical_u64(self.result_byte as u64),
                Goldilocks::from_canonical_u64(self.op_type as u64),
            ],
        }
    }

    /// Verify this query is correct (the operation matches).
    pub fn is_valid(&self) -> bool {
        let expected = match self.op_type {
            BitwiseOp::And => self.a_byte & self.b_byte,
            BitwiseOp::Or => self.a_byte | self.b_byte,
            BitwiseOp::Xor => self.a_byte ^ self.b_byte,
            BitwiseOp::Not => !self.a_byte,
        };
        self.result_byte == expected
    }
}

/// Decompose a 64-bit bitwise operation into 8 byte-level lookup queries.
pub fn decompose_gp_bitwise(a: u64, b: u64, result: u64, op: BitwiseOp) -> Vec<LookupQuery> {
    let a_bytes = a.to_le_bytes();
    let b_bytes = b.to_le_bytes();
    let r_bytes = result.to_le_bytes();

    (0..8).map(|i| LookupQuery {
        a_byte: a_bytes[i],
        b_byte: if op == BitwiseOp::Not { 0 } else { b_bytes[i] },
        result_byte: r_bytes[i],
        op_type: op,
    }).collect()
}

/// Decompose a 256-bit wide bitwise operation into 32 byte-level lookup queries.
pub fn decompose_wide_bitwise(
    a_limbs: &[u64; 4],
    b_limbs: &[u64; 4],
    result_limbs: &[u64; 4],
    op: BitwiseOp,
) -> Vec<LookupQuery> {
    let mut queries = Vec::with_capacity(32);
    for limb in 0..4 {
        queries.extend(decompose_gp_bitwise(a_limbs[limb], b_limbs[limb], result_limbs[limb], op));
    }
    queries
}

/// Build the precomputed lookup table bus entries.
/// Contains ALL valid (a_byte, b_byte, result_byte, op_type) tuples.
/// Each entry appears exactly once in the table.
pub fn build_lookup_table() -> Vec<BusEntry> {
    let mut entries = Vec::with_capacity(256 * 256 * 4 + 256);

    // AND, OR, XOR: all 256×256 pairs
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            entries.push(LookupQuery { a_byte: a, b_byte: b, result_byte: a & b, op_type: BitwiseOp::And }.to_bus_entry());
            entries.push(LookupQuery { a_byte: a, b_byte: b, result_byte: a | b, op_type: BitwiseOp::Or }.to_bus_entry());
            entries.push(LookupQuery { a_byte: a, b_byte: b, result_byte: a ^ b, op_type: BitwiseOp::Xor }.to_bus_entry());
        }
    }

    // NOT: 256 entries (b_byte = 0)
    for a in 0..=255u8 {
        entries.push(LookupQuery { a_byte: a, b_byte: 0, result_byte: !a, op_type: BitwiseOp::Not }.to_bus_entry());
    }

    entries
}

/// Collect bitwise lookup queries from execution trace data.
/// Called by the multi-table prover to extract lookup bus entries.
pub fn collect_bitwise_queries(
    opcode: u64,
    op_a: u64,
    op_b: u64,
    result: u64,
) -> Option<Vec<LookupQuery>> {
    use crate::constraint::opcodes;
    let op = match opcode {
        opcodes::AND => BitwiseOp::And,
        opcodes::OR => BitwiseOp::Or,
        opcodes::XOR => BitwiseOp::Xor,
        opcodes::NOT => BitwiseOp::Not,
        _ => return None,
    };
    Some(decompose_gp_bitwise(op_a, op_b, result, op))
}

/// Verify bitwise operations via cross-table permutation.
/// The execution-side bus entries (from lookup queries) must match
/// a subset of the precomputed lookup table entries.
///
/// Note: this uses a simplified verification — it checks that each query
/// is individually valid. Full permutation proof is generated during
/// multi-table proving.
pub fn verify_bitwise_queries(queries: &[LookupQuery]) -> bool {
    queries.iter().all(|q| q.is_valid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn and_decomposition() {
        let a: u64 = 0xFF00_FF00_FF00_FF00;
        let b: u64 = 0x0F0F_0F0F_0F0F_0F0F;
        let result = a & b;
        let queries = decompose_gp_bitwise(a, b, result, BitwiseOp::And);
        assert_eq!(queries.len(), 8);
        assert!(queries.iter().all(|q| q.is_valid()));
    }

    #[test]
    fn or_decomposition() {
        let a: u64 = 0xAAAA_BBBB_CCCC_DDDD;
        let b: u64 = 0x1111_2222_3333_4444;
        let result = a | b;
        let queries = decompose_gp_bitwise(a, b, result, BitwiseOp::Or);
        assert!(queries.iter().all(|q| q.is_valid()));
    }

    #[test]
    fn xor_decomposition() {
        let a: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let b: u64 = 0x1234_5678_9ABC_DEF0;
        let result = a ^ b;
        let queries = decompose_gp_bitwise(a, b, result, BitwiseOp::Xor);
        assert!(queries.iter().all(|q| q.is_valid()));
    }

    #[test]
    fn not_decomposition() {
        let a: u64 = 0xFF00_FF00_FF00_FF00;
        let result = !a;
        let queries = decompose_gp_bitwise(a, 0, result, BitwiseOp::Not);
        assert!(queries.iter().all(|q| q.is_valid()));
    }

    #[test]
    fn invalid_query_detected() {
        let bad = LookupQuery {
            a_byte: 0xFF,
            b_byte: 0x0F,
            result_byte: 0x00, // wrong — AND should give 0x0F
            op_type: BitwiseOp::And,
        };
        assert!(!bad.is_valid());
    }

    #[test]
    fn wide_bitwise_decomposition() {
        let a = [0x1111_1111u64, 0x2222_2222, 0x3333_3333, 0x4444_4444];
        let b = [0xFFFF_FFFFu64, 0x0000_0000, 0xAAAA_AAAA, 0x5555_5555];
        let result: [u64; 4] = core::array::from_fn(|i| a[i] & b[i]);
        let queries = decompose_wide_bitwise(&a, &b, &result, BitwiseOp::And);
        assert_eq!(queries.len(), 32); // 4 limbs × 8 bytes
        assert!(queries.iter().all(|q| q.is_valid()));
    }

    #[test]
    fn lookup_table_size() {
        let table = build_lookup_table();
        // 256*256*3 (AND/OR/XOR) + 256 (NOT) = 196,608 + 256 = 196,864
        assert_eq!(table.len(), 256 * 256 * 3 + 256);
    }

    #[test]
    fn collect_queries_from_opcode() {
        use crate::constraint::opcodes;
        let queries = collect_bitwise_queries(opcodes::AND, 0xFF, 0x0F, 0x0F).unwrap();
        assert_eq!(queries.len(), 8);
        assert!(verify_bitwise_queries(&queries));
    }

    #[test]
    fn collect_queries_non_bitwise_returns_none() {
        use crate::constraint::opcodes;
        assert!(collect_bitwise_queries(opcodes::ADD, 1, 2, 3).is_none());
    }

    #[test]
    fn full_permutation_check() {
        // Simulate: execution trace has 1 AND operation
        let exec_queries = decompose_gp_bitwise(0xABCD, 0x1234, 0xABCD & 0x1234, BitwiseOp::And);
        let exec_bus: Vec<BusEntry> = exec_queries.iter().map(|q| q.to_bus_entry()).collect();

        // The lookup table side: for each exec query, find matching table entry
        // (in a real prover, the table has multiplicities; here we just verify the entries exist)
        let table = build_lookup_table();

        // Check each exec entry exists in the table
        let alpha = Goldilocks::from_canonical_u64(0x9e3779b97f4a7c15);
        for entry in &exec_bus {
            let fp = crate::cross_table::fingerprint(entry, alpha);
            let exists = table.iter().any(|t| crate::cross_table::fingerprint(t, alpha) == fp);
            assert!(exists, "lookup entry not found in table");
        }
    }
}
