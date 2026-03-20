//! Execution trace table for STARK proof generation.
//!
//! The trace table captures every cycle of PVM execution. Each row
//! represents one instruction execution with ~50-70 columns:
//!
//! - Program counter, opcode, decoded fields
//! - 16 GP registers (r0-r15)
//! - 8 wide registers (w0-w7), 4 limbs each = 32 columns
//! - Memory read/write addresses and values
//! - Storage read/write keys and values
//! - Gas counter
//! - Flags (overflow, zero, etc.)
//!
//! The Plonky3 AIR (Algebraic Intermediate Representation) defines
//! constraints that each row must satisfy. The prover generates a
//! STARK proof that the trace is valid.

use p3_field::{AbstractField, PrimeField64};
use p3_goldilocks::Goldilocks;

/// Number of GP register columns (r0-r15).
pub const NUM_GP_REGS: usize = 16;

/// Number of wide register columns (w0-w7, 4 u64 limbs each).
pub const NUM_WIDE_LIMBS: usize = 8 * 4; // 32

/// Trace row: one PVM execution step.
///
/// All values are Goldilocks field elements (u64 mod p).
#[derive(Clone, Debug)]
pub struct TraceRow {
    // === Control flow (5 columns) ===
    /// Program counter.
    pub pc: Goldilocks,
    /// Opcode (as field element).
    pub opcode: Goldilocks,
    /// Decoded rd field.
    pub rd: Goldilocks,
    /// Decoded rs1 field.
    pub rs1: Goldilocks,
    /// Decoded rs2/imm field.
    pub rs2_imm: Goldilocks,

    // === GP registers (16 columns) ===
    pub gp_regs: [Goldilocks; NUM_GP_REGS],

    // === Wide registers (32 columns) ===
    /// w0-w7, each split into 4 × u64 limbs for field compatibility.
    pub wide_limbs: [Goldilocks; NUM_WIDE_LIMBS],

    // === Memory (4 columns) ===
    /// Memory read address (0 if no read).
    pub mem_read_addr: Goldilocks,
    /// Memory read value.
    pub mem_read_val: Goldilocks,
    /// Memory write address (0 if no write).
    pub mem_write_addr: Goldilocks,
    /// Memory write value.
    pub mem_write_val: Goldilocks,

    // === Storage (4 columns) ===
    /// Storage key (hash, lower 64 bits).
    pub storage_key_lo: Goldilocks,
    /// Storage key (hash, upper 64 bits).
    pub storage_key_hi: Goldilocks,
    /// Storage value (lower 64 bits).
    pub storage_val_lo: Goldilocks,
    /// Storage value (upper 64 bits).
    pub storage_val_hi: Goldilocks,

    // === Gas (2 columns) ===
    /// Gas used this step.
    pub gas_step: Goldilocks,
    /// Cumulative gas used.
    pub gas_cumulative: Goldilocks,

    // === Flags (3 columns) ===
    /// Is this a memory instruction?
    pub is_memory_op: Goldilocks,
    /// Is this a storage instruction?
    pub is_storage_op: Goldilocks,
    /// Is this the last row (HALT/REVERT)?
    pub is_final: Goldilocks,
}

impl TraceRow {
    /// Total number of columns in the trace.
    pub const NUM_COLUMNS: usize = 5 + NUM_GP_REGS + NUM_WIDE_LIMBS + 4 + 4 + 2 + 3;
    // 5 + 16 + 32 + 4 + 4 + 2 + 3 = 66 columns

    /// Create an empty trace row (all zeros).
    pub fn zero() -> Self {
        Self {
            pc: Goldilocks::zero(),
            opcode: Goldilocks::zero(),
            rd: Goldilocks::zero(),
            rs1: Goldilocks::zero(),
            rs2_imm: Goldilocks::zero(),
            gp_regs: [Goldilocks::zero(); NUM_GP_REGS],
            wide_limbs: [Goldilocks::zero(); NUM_WIDE_LIMBS],
            mem_read_addr: Goldilocks::zero(),
            mem_read_val: Goldilocks::zero(),
            mem_write_addr: Goldilocks::zero(),
            mem_write_val: Goldilocks::zero(),
            storage_key_lo: Goldilocks::zero(),
            storage_key_hi: Goldilocks::zero(),
            storage_val_lo: Goldilocks::zero(),
            storage_val_hi: Goldilocks::zero(),
            gas_step: Goldilocks::zero(),
            gas_cumulative: Goldilocks::zero(),
            is_memory_op: Goldilocks::zero(),
            is_storage_op: Goldilocks::zero(),
            is_final: Goldilocks::zero(),
        }
    }

    /// Convert to a flat array of field elements (for Plonky3 matrix).
    pub fn to_fields(&self) -> Vec<Goldilocks> {
        let mut fields = Vec::with_capacity(Self::NUM_COLUMNS);
        fields.push(self.pc);
        fields.push(self.opcode);
        fields.push(self.rd);
        fields.push(self.rs1);
        fields.push(self.rs2_imm);
        fields.extend_from_slice(&self.gp_regs);
        fields.extend_from_slice(&self.wide_limbs);
        fields.push(self.mem_read_addr);
        fields.push(self.mem_read_val);
        fields.push(self.mem_write_addr);
        fields.push(self.mem_write_val);
        fields.push(self.storage_key_lo);
        fields.push(self.storage_key_hi);
        fields.push(self.storage_val_lo);
        fields.push(self.storage_val_hi);
        fields.push(self.gas_step);
        fields.push(self.gas_cumulative);
        fields.push(self.is_memory_op);
        fields.push(self.is_storage_op);
        fields.push(self.is_final);
        fields
    }
}

/// Helper: convert a u64 to a Goldilocks field element.
pub fn to_field(val: u64) -> Goldilocks {
    Goldilocks::from_canonical_u64(val)
}

/// The full execution trace: a list of rows.
#[derive(Clone, Debug)]
pub struct ExecutionTrace {
    /// Trace rows in execution order.
    pub rows: Vec<TraceRow>,
}

impl ExecutionTrace {
    pub fn new() -> Self {
        Self { rows: Vec::new() }
    }

    pub fn with_capacity(n: usize) -> Self {
        Self {
            rows: Vec::with_capacity(n),
        }
    }

    /// Add a row to the trace.
    pub fn push(&mut self, row: TraceRow) {
        self.rows.push(row);
    }

    /// Number of execution steps.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Convert the trace to a flat column-major matrix for Plonky3.
    /// Returns Vec of columns, each column is Vec<Goldilocks>.
    pub fn to_column_major(&self) -> Vec<Vec<Goldilocks>> {
        if self.rows.is_empty() {
            return vec![vec![]; TraceRow::NUM_COLUMNS];
        }

        let num_rows = self.rows.len();
        let mut columns = vec![Vec::with_capacity(num_rows); TraceRow::NUM_COLUMNS];

        for row in &self.rows {
            let fields = row.to_fields();
            for (col_idx, val) in fields.into_iter().enumerate() {
                columns[col_idx].push(val);
            }
        }

        columns
    }

    /// Pad the trace to a power of 2 (required by STARK provers).
    pub fn pad_to_power_of_two(&mut self) {
        if self.rows.is_empty() {
            return;
        }
        let target = self.rows.len().next_power_of_two();
        while self.rows.len() < target {
            self.rows.push(TraceRow::zero());
        }
    }
}

impl Default for ExecutionTrace {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_row_column_count() {
        assert_eq!(TraceRow::NUM_COLUMNS, 66);
    }

    #[test]
    fn zero_row_all_zeros() {
        let row = TraceRow::zero();
        let fields = row.to_fields();
        assert_eq!(fields.len(), 66);
        for f in &fields {
            assert_eq!(*f, Goldilocks::zero());
        }
    }

    #[test]
    fn to_fields_preserves_values() {
        let mut row = TraceRow::zero();
        row.pc = to_field(42);
        row.opcode = to_field(7);
        row.gp_regs[0] = to_field(100);
        row.gas_cumulative = to_field(21000);

        let fields = row.to_fields();
        assert_eq!(fields[0], to_field(42)); // pc
        assert_eq!(fields[1], to_field(7)); // opcode
        assert_eq!(fields[5], to_field(100)); // gp_regs[0]
                                              // gas_cumulative: 5 control + 16 gp + 32 wide + 4 mem + 4 storage + 1 gas_step = index 62
        assert_eq!(fields[62], to_field(21000)); // gas_cumulative
    }

    #[test]
    fn trace_push_and_len() {
        let mut trace = ExecutionTrace::new();
        assert!(trace.is_empty());

        trace.push(TraceRow::zero());
        trace.push(TraceRow::zero());
        assert_eq!(trace.len(), 2);
    }

    #[test]
    fn pad_to_power_of_two() {
        let mut trace = ExecutionTrace::new();
        for _ in 0..5 {
            trace.push(TraceRow::zero());
        }
        assert_eq!(trace.len(), 5);

        trace.pad_to_power_of_two();
        assert_eq!(trace.len(), 8); // next power of 2
    }

    #[test]
    fn pad_already_power_of_two() {
        let mut trace = ExecutionTrace::new();
        for _ in 0..4 {
            trace.push(TraceRow::zero());
        }
        trace.pad_to_power_of_two();
        assert_eq!(trace.len(), 4); // already power of 2
    }

    #[test]
    fn column_major_conversion() {
        let mut trace = ExecutionTrace::new();

        let mut row1 = TraceRow::zero();
        row1.pc = to_field(0);
        row1.opcode = to_field(1);

        let mut row2 = TraceRow::zero();
        row2.pc = to_field(4);
        row2.opcode = to_field(2);

        trace.push(row1);
        trace.push(row2);

        let cols = trace.to_column_major();
        assert_eq!(cols.len(), 66);
        assert_eq!(cols[0].len(), 2); // 2 rows

        // Column 0 = pc: [0, 4]
        assert_eq!(cols[0][0], to_field(0));
        assert_eq!(cols[0][1], to_field(4));

        // Column 1 = opcode: [1, 2]
        assert_eq!(cols[1][0], to_field(1));
        assert_eq!(cols[1][1], to_field(2));
    }

    #[test]
    fn empty_trace_column_major() {
        let trace = ExecutionTrace::new();
        let cols = trace.to_column_major();
        assert_eq!(cols.len(), 66);
        for col in &cols {
            assert!(col.is_empty());
        }
    }
}
