//! Range-check: verifies values are valid u64 (fit in 64 bits).
//!
//! Used for comparison diffs (LT/GT) and shift remainders (SHR/SAR).
//! Decompose u64 into 4 × 16-bit limbs, verify each limb ∈ [0, 65535].
//!
//! Connected to execution trace via cross-table bus: the execution trace
//! emits values that need range-checking, and this table proves they're valid.

use p3_goldilocks::Goldilocks;
use p3_field::AbstractField;

use crate::cross_table::BusEntry;

/// A range-check request: verify this value is a valid u64.
#[derive(Clone, Debug)]
pub struct RangeCheckRequest {
    pub value: u64,
}

impl RangeCheckRequest {
    pub fn to_bus_entry(&self) -> BusEntry {
        BusEntry {
            fields: vec![Goldilocks::from_canonical_u64(self.value)],
        }
    }
}

/// Range-check table row: decomposes value into 4 × 16-bit limbs.
#[derive(Clone, Debug)]
pub struct RangeCheckRow {
    pub value: u64,
    pub limbs: [u16; 4],
}

impl RangeCheckRow {
    pub fn from_u64(val: u64) -> Self {
        Self {
            value: val,
            limbs: [
                (val & 0xFFFF) as u16,
                ((val >> 16) & 0xFFFF) as u16,
                ((val >> 32) & 0xFFFF) as u16,
                ((val >> 48) & 0xFFFF) as u16,
            ],
        }
    }

    /// Verify limbs reconstruct to value.
    pub fn is_valid(&self) -> bool {
        let reconstructed = self.limbs[0] as u64
            | (self.limbs[1] as u64) << 16
            | (self.limbs[2] as u64) << 32
            | (self.limbs[3] as u64) << 48;
        reconstructed == self.value
    }
}

/// Range-check trace: collection of values to verify.
#[derive(Clone, Debug, Default)]
pub struct RangeCheckTrace {
    pub rows: Vec<RangeCheckRow>,
}

impl RangeCheckTrace {
    pub fn new() -> Self {
        Self { rows: Vec::new() }
    }

    pub fn add(&mut self, val: u64) {
        self.rows.push(RangeCheckRow::from_u64(val));
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Verify all rows are valid decompositions.
    pub fn verify(&self) -> bool {
        self.rows.iter().all(|r| r.is_valid())
    }

    /// Build bus entries for cross-table permutation.
    pub fn to_bus_entries(&self) -> Vec<BusEntry> {
        self.rows
            .iter()
            .map(|r| BusEntry {
                fields: vec![Goldilocks::from_canonical_u64(r.value)],
            })
            .collect()
    }
}

/// Extract range-check requests from an execution trace.
/// Collects values that need u64 range verification:
/// - Comparison diffs (LT/GT op_aux)
/// - Shift results and remainders (SHR/SAR)
/// - Wide arithmetic carries
pub fn extract_range_check_requests(
    trace: &crate::trace::ExecutionTrace,
) -> Vec<RangeCheckRequest> {
    use crate::constraint::opcodes;
    use crate::trace::col;
    use p3_field::PrimeField64;

    let mut requests = Vec::new();

    for row in &trace.rows {
        let op = row.get(col::OPCODE).as_canonical_u64();

        // Comparison diffs
        if op == opcodes::LT || op == opcodes::GT || op == opcodes::SLT || op == opcodes::SGT {
            requests.push(RangeCheckRequest {
                value: row.get(col::OP_AUX).as_canonical_u64(),
            });
        }

        // SHR/SAR: verify shift result is valid u64
        // remainder = op_a - result * 2^shift, must be non-negative and < 2^shift
        if op == opcodes::SHR || op == opcodes::SAR {
            // Range-check the result (must be valid u64)
            requests.push(RangeCheckRequest {
                value: row.get(col::OP_RESULT).as_canonical_u64(),
            });
            // Range-check the implicit remainder: op_a - result * op_aux
            let op_a = row.get(col::OP_A).as_canonical_u64();
            let result_val = row.get(col::OP_RESULT).as_canonical_u64();
            let power = row.get(col::OP_AUX).as_canonical_u64();
            if power != 0 {
                let remainder = op_a.wrapping_sub(result_val.wrapping_mul(power));
                requests.push(RangeCheckRequest { value: remainder });
            }
        }

        // Wide arithmetic carries
        if op == opcodes::WADD || op == opcodes::WSUB || op == opcodes::WMUL
            || op == opcodes::WDIV || op == opcodes::WMOD
        {
            for i in 0..4 {
                requests.push(RangeCheckRequest {
                    value: row.get(col::wide_carry(i)).as_canonical_u64(),
                });
            }
        }
    }

    requests
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decomposition_correct() {
        let row = RangeCheckRow::from_u64(0x1234_5678_9ABC_DEF0);
        assert!(row.is_valid());
        assert_eq!(row.limbs[0], 0xDEF0);
        assert_eq!(row.limbs[1], 0x9ABC);
        assert_eq!(row.limbs[2], 0x5678);
        assert_eq!(row.limbs[3], 0x1234);
    }

    #[test]
    fn zero_valid() {
        let row = RangeCheckRow::from_u64(0);
        assert!(row.is_valid());
    }

    #[test]
    fn max_u64_valid() {
        let row = RangeCheckRow::from_u64(u64::MAX);
        assert!(row.is_valid());
        assert_eq!(row.limbs, [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF]);
    }

    #[test]
    fn tampered_row_detected() {
        let mut row = RangeCheckRow::from_u64(42);
        row.limbs[0] = 999; // tamper
        assert!(!row.is_valid());
    }

    #[test]
    fn trace_verify() {
        let mut trace = RangeCheckTrace::new();
        trace.add(42);
        trace.add(u64::MAX);
        trace.add(0);
        assert!(trace.verify());
    }
}
