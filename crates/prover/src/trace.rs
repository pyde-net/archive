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

use p3_field::AbstractField;
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

    // === Memory (7 columns) ===
    /// Memory address (read or write).
    pub mem_addr: Goldilocks,
    /// Memory value: 4 × u64 limbs.
    /// - GP mode (width ≤ 8): val[0] = raw u64, val[1..3] = 0
    /// - Bulk mode (width > 8): val[0..3] = Poseidon2(raw_bytes) hash limbs
    ///   (actual bytes in auxiliary witness, AIR verifies hash)
    pub mem_val: [Goldilocks; 4],
    /// Memory access width in bytes (1, 2, 4, 8 for GP; or N for bulk writes).
    pub mem_width: Goldilocks,
    /// Memory is write (1) or read (0).
    pub mem_is_write: Goldilocks,

    // === Storage (10 columns) ===
    /// Storage key: 4 × u64 limbs (U256, always fixed size).
    pub storage_key: [Goldilocks; 4],
    /// Storage value: 4 × u64 limbs. Interpretation derived from storage_val_len:
    /// - len ≤ 8:  val[0] = raw u64, val[1..3] = 0
    /// - len ≤ 32: val[0..3] = raw U256 limbs
    /// - len > 32: val[0..3] = Poseidon2(raw_bytes) hash limbs
    ///   (actual bytes in auxiliary witness, AIR verifies hash)
    pub storage_val: [Goldilocks; 4],
    /// Length of the raw storage value in bytes (same role as mem_width).
    pub storage_val_len: Goldilocks,
    /// Storage is write (1) or read (0).
    pub storage_is_write: Goldilocks,

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
    /// 5 control + 16 GP + 32 wide + 7 memory + 10 storage + 2 gas + 3 flags = 75
    pub const NUM_COLUMNS: usize = 5 + NUM_GP_REGS + NUM_WIDE_LIMBS + 7 + 10 + 2 + 3;

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
            mem_addr: Goldilocks::zero(),
            mem_val: [Goldilocks::zero(); 4],
            mem_width: Goldilocks::zero(),
            mem_is_write: Goldilocks::zero(),
            storage_key: [Goldilocks::zero(); 4],
            storage_val: [Goldilocks::zero(); 4],
            storage_val_len: Goldilocks::zero(),
            storage_is_write: Goldilocks::zero(),
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
        fields.push(self.mem_addr);
        fields.extend_from_slice(&self.mem_val);
        fields.push(self.mem_width);
        fields.push(self.mem_is_write);
        fields.extend_from_slice(&self.storage_key);
        fields.extend_from_slice(&self.storage_val);
        fields.push(self.storage_val_len);
        fields.push(self.storage_is_write);
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
        assert_eq!(TraceRow::NUM_COLUMNS, 75);
    }

    #[test]
    fn zero_row_all_zeros() {
        let row = TraceRow::zero();
        let fields = row.to_fields();
        assert_eq!(fields.len(), 75);
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
                                              // gas_cumulative: 5 control + 16 gp + 32 wide + 7 mem + 10 storage + 1 gas_step = index 71
        assert_eq!(fields[71], to_field(21000)); // gas_cumulative
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
        assert_eq!(cols.len(), 75);
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
        assert_eq!(cols.len(), 75);
        for col in &cols {
            assert!(col.is_empty());
        }
    }
}
