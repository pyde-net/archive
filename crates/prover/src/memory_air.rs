//! Memory AIR: verifies read-after-write consistency.
//!
//! Every LOAD must return the value from the most recent STORE at that address.
//! Without this, a prover could fake any LOAD result.
//!
//! Approach:
//! 1. Collect all memory accesses (addr, value, is_write, timestamp) from execution trace
//! 2. Sort by (address, then timestamp)
//! 3. Verify: each READ returns the value from the last WRITE at that address
//! 4. Cross-table permutation proves execution trace and sorted table have same entries
//!
//! Columns (6 per row):
//!   addr, value, is_write, timestamp, addr_same, is_first

use p3_field::AbstractField;
use p3_goldilocks::Goldilocks;

use crate::cross_table::{BusEntry, verify_permutation};

/// A memory access from the execution trace.
#[derive(Clone, Debug)]
pub struct MemoryAccess {
    pub addr: u64,
    pub value: u64,
    pub is_write: bool,
    pub timestamp: u64,
}

impl MemoryAccess {
    /// Convert to bus entry for cross-table permutation.
    pub fn to_bus_entry(&self) -> BusEntry {
        BusEntry {
            fields: vec![
                Goldilocks::from_canonical_u64(self.addr),
                Goldilocks::from_canonical_u64(self.value),
                if self.is_write { Goldilocks::one() } else { Goldilocks::zero() },
                Goldilocks::from_canonical_u64(self.timestamp),
            ],
        }
    }
}

/// Sorted memory trace row (for the memory AIR).
#[derive(Clone, Debug)]
pub struct MemoryRow {
    pub addr: u64,
    pub value: u64,
    pub is_write: bool,
    pub timestamp: u64,
    /// 1 if same address as previous row.
    pub addr_same: bool,
    /// 1 if this is the first access to this address.
    pub is_first: bool,
}

/// The sorted memory trace.
#[derive(Clone, Debug, Default)]
pub struct MemoryTrace {
    pub rows: Vec<MemoryRow>,
}

impl MemoryTrace {
    pub fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// Build from unsorted memory accesses: sort by (addr, timestamp).
    pub fn from_accesses(accesses: &[MemoryAccess]) -> Self {
        let mut sorted: Vec<MemoryAccess> = accesses.to_vec();
        sorted.sort_by_key(|a| (a.addr, a.timestamp));

        let mut rows = Vec::with_capacity(sorted.len());
        let mut prev_addr: Option<u64> = None;

        for access in &sorted {
            let addr_same = prev_addr == Some(access.addr);
            let is_first = !addr_same;

            rows.push(MemoryRow {
                addr: access.addr,
                value: access.value,
                is_write: access.is_write,
                timestamp: access.timestamp,
                addr_same,
                is_first,
            });

            prev_addr = Some(access.addr);
        }

        Self { rows }
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Verify read-after-write consistency.
    /// For each READ at address A: value must equal the most recent WRITE to A.
    /// For first access to an address: if READ, value must be 0 (uninitialized).
    pub fn verify_consistency(&self) -> Result<(), String> {
        let mut last_write_value: Option<u64> = None;

        for (i, row) in self.rows.iter().enumerate() {
            if row.is_first {
                // New address: reset write tracker
                last_write_value = None;

                if !row.is_write && row.value != 0 {
                    return Err(format!(
                        "row {}: first access to addr {} is READ with value {} (expected 0)",
                        i, row.addr, row.value
                    ));
                }
            }

            if row.is_write {
                last_write_value = Some(row.value);
            } else {
                // READ: must match last write
                match last_write_value {
                    Some(expected) if expected != row.value => {
                        return Err(format!(
                            "row {}: READ at addr {} returned {} but last WRITE was {}",
                            i, row.addr, row.value, expected
                        ));
                    }
                    None if row.value != 0 => {
                        return Err(format!(
                            "row {}: READ at addr {} returned {} but no prior WRITE (expected 0)",
                            i, row.addr, row.value
                        ));
                    }
                    _ => {} // OK
                }
            }
        }

        Ok(())
    }

    /// Build bus entries for the sorted side of the permutation argument.
    pub fn to_bus_entries(&self) -> Vec<BusEntry> {
        self.rows
            .iter()
            .map(|row| {
                BusEntry {
                    fields: vec![
                        Goldilocks::from_canonical_u64(row.addr),
                        Goldilocks::from_canonical_u64(row.value),
                        if row.is_write { Goldilocks::one() } else { Goldilocks::zero() },
                        Goldilocks::from_canonical_u64(row.timestamp),
                    ],
                }
            })
            .collect()
    }
}

/// Verify memory consistency via cross-table permutation.
/// Checks:
/// 1. Execution-side memory accesses == sorted memory trace (permutation)
/// 2. Sorted trace satisfies read-after-write consistency
pub fn verify_memory(
    exec_accesses: &[MemoryAccess],
    memory_trace: &MemoryTrace,
) -> Result<(), String> {
    // 1. Verify read-after-write in sorted trace
    memory_trace.verify_consistency()?;

    // 2. Verify permutation: execution bus == sorted bus
    let exec_bus: Vec<BusEntry> = exec_accesses.iter().map(|a| a.to_bus_entry()).collect();
    let sorted_bus = memory_trace.to_bus_entries();

    let alpha = Goldilocks::from_canonical_u64(0x9e3779b97f4a7c15);
    let alpha_prime = Goldilocks::from_canonical_u64(0x517cc1b727220a95);

    if !verify_permutation(&exec_bus, &sorted_bus, alpha, alpha_prime) {
        return Err("memory permutation argument failed".to_string());
    }

    Ok(())
}

/// Extract memory accesses from an execution trace.
/// For 64-bit ops (LOAD/STORE/PUSH/POP): one access with value = mem_val[0].
/// For 256-bit ops (WLOAD/WSTORE): four accesses, one per limb.
pub fn extract_memory_accesses(
    trace: &crate::trace::ExecutionTrace,
) -> Vec<MemoryAccess> {
    use crate::constraint::opcodes;
    use crate::trace::col;
    use p3_field::PrimeField64;

    let mut accesses = Vec::new();

    for (step, row) in trace.rows.iter().enumerate() {
        if row.get(col::IS_MEMORY_OP) == Goldilocks::one() {
            let opcode = row.get(col::OPCODE).as_canonical_u64();
            let addr = row.get(col::MEM_ADDR).as_canonical_u64();
            let is_write = row.get(col::MEM_IS_WRITE) == Goldilocks::one();

            if opcode == opcodes::WLOAD || opcode == opcodes::WSTORE {
                // 256-bit: capture all 4 limbs as separate accesses
                for limb in 0..4 {
                    accesses.push(MemoryAccess {
                        addr: addr + (limb as u64 * 8), // each limb at 8-byte offset
                        value: row.get(col::mem_val(limb)).as_canonical_u64(),
                        is_write,
                        timestamp: step as u64 * 4 + limb as u64, // unique timestamp per limb
                    });
                }
            } else {
                // 64-bit: single access
                accesses.push(MemoryAccess {
                    addr,
                    value: row.get(col::mem_val(0)).as_canonical_u64(),
                    is_write,
                    timestamp: step as u64 * 4, // multiply by 4 to leave room for wide limbs
                });
            }
        }
    }

    accesses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_consistent() {
        let accesses = vec![
            MemoryAccess { addr: 100, value: 42, is_write: true, timestamp: 0 },
            MemoryAccess { addr: 100, value: 42, is_write: false, timestamp: 1 },
        ];
        let trace = MemoryTrace::from_accesses(&accesses);
        assert!(trace.verify_consistency().is_ok());
    }

    #[test]
    fn read_wrong_value_detected() {
        let accesses = vec![
            MemoryAccess { addr: 100, value: 42, is_write: true, timestamp: 0 },
            MemoryAccess { addr: 100, value: 99, is_write: false, timestamp: 1 }, // WRONG
        ];
        let trace = MemoryTrace::from_accesses(&accesses);
        assert!(trace.verify_consistency().is_err());
    }

    #[test]
    fn first_read_must_be_zero() {
        let accesses = vec![
            MemoryAccess { addr: 200, value: 42, is_write: false, timestamp: 0 }, // no prior write
        ];
        let trace = MemoryTrace::from_accesses(&accesses);
        assert!(trace.verify_consistency().is_err());
    }

    #[test]
    fn first_read_zero_ok() {
        let accesses = vec![
            MemoryAccess { addr: 200, value: 0, is_write: false, timestamp: 0 },
        ];
        let trace = MemoryTrace::from_accesses(&accesses);
        assert!(trace.verify_consistency().is_ok());
    }

    #[test]
    fn multiple_addresses_sorted() {
        let accesses = vec![
            MemoryAccess { addr: 200, value: 99, is_write: true, timestamp: 0 },
            MemoryAccess { addr: 100, value: 42, is_write: true, timestamp: 1 },
            MemoryAccess { addr: 100, value: 42, is_write: false, timestamp: 2 },
            MemoryAccess { addr: 200, value: 99, is_write: false, timestamp: 3 },
        ];
        let trace = MemoryTrace::from_accesses(&accesses);
        assert_eq!(trace.rows[0].addr, 100); // sorted by address
        assert_eq!(trace.rows[2].addr, 200);
        assert!(trace.verify_consistency().is_ok());
    }

    #[test]
    fn overwrite_then_read() {
        let accesses = vec![
            MemoryAccess { addr: 100, value: 42, is_write: true, timestamp: 0 },
            MemoryAccess { addr: 100, value: 99, is_write: true, timestamp: 1 }, // overwrite
            MemoryAccess { addr: 100, value: 99, is_write: false, timestamp: 2 }, // must read 99
        ];
        let trace = MemoryTrace::from_accesses(&accesses);
        assert!(trace.verify_consistency().is_ok());
    }

    #[test]
    fn overwrite_read_old_value_fails() {
        let accesses = vec![
            MemoryAccess { addr: 100, value: 42, is_write: true, timestamp: 0 },
            MemoryAccess { addr: 100, value: 99, is_write: true, timestamp: 1 },
            MemoryAccess { addr: 100, value: 42, is_write: false, timestamp: 2 }, // WRONG: should be 99
        ];
        let trace = MemoryTrace::from_accesses(&accesses);
        assert!(trace.verify_consistency().is_err());
    }

    #[test]
    fn permutation_check_passes() {
        let accesses = vec![
            MemoryAccess { addr: 100, value: 42, is_write: true, timestamp: 0 },
            MemoryAccess { addr: 100, value: 42, is_write: false, timestamp: 1 },
        ];
        let trace = MemoryTrace::from_accesses(&accesses);
        assert!(verify_memory(&accesses, &trace).is_ok());
    }

    #[test]
    fn permutation_check_detects_fabrication() {
        let exec_accesses = vec![
            MemoryAccess { addr: 100, value: 42, is_write: true, timestamp: 0 },
        ];
        // Fabricated sorted trace with different value
        let mut trace = MemoryTrace::new();
        trace.rows.push(MemoryRow {
            addr: 100,
            value: 999, // fabricated
            is_write: true,
            timestamp: 0,
            addr_same: false,
            is_first: true,
        });
        assert!(verify_memory(&exec_accesses, &trace).is_err());
    }

    #[test]
    fn end_to_end_with_recorder() {
        use pyde_vm::isa::{encode, encode_mem_immediate, MemWidth, Opcode};
        use pyde_vm::vm::Vm;

        let store_imm = encode_mem_immediate(0, MemWidth::W64);
        let load_imm = encode_mem_immediate(0, MemWidth::W64);

        let code: Vec<u8> = [
            &encode(Opcode::Addi, 1, 0, 0x010000).0.to_le_bytes(),
            &encode(Opcode::Addi, 2, 0, 42).0.to_le_bytes(),
            &encode(Opcode::Store, 2, 1, store_imm).0.to_le_bytes(),
            &encode(Opcode::Load, 3, 1, load_imm).0.to_le_bytes(),
            &encode(Opcode::Halt, 0, 0, 0).0.to_le_bytes(),
        ].iter().flat_map(|i| i.iter().copied()).collect();

        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();

        let (trace, _) = crate::recorder::record_execution(&mut vm);

        // Extract memory accesses
        let accesses = extract_memory_accesses(&trace);
        assert_eq!(accesses.len(), 2); // 1 STORE + 1 LOAD

        // Build sorted trace and verify
        let mem_trace = MemoryTrace::from_accesses(&accesses);
        assert!(verify_memory(&accesses, &mem_trace).is_ok());
    }
}
