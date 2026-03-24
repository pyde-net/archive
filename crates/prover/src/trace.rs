//! Execution trace: 128-column format for the custom STARK prover.
//!
//! Each row represents one PVM instruction execution. The trace captures
//! post-step state: register values AFTER the instruction executes.
//!
//! Design principles:
//! - GP registers: 1 column each (checked arithmetic → field arithmetic is exact)
//! - Wide registers: 4 limbs each (u256 needs limb decomposition, unavoidable)
//! - No bit decomposition columns (bitwise ops use lookup tables instead)
//! - No Merkle columns (verified via cross-table Poseidon2 bus)

use p3_field::AbstractField;
use p3_goldilocks::Goldilocks;

/// Number of GP registers.
pub const NUM_GP: usize = 16;
/// Number of wide registers.
pub const NUM_WIDE: usize = 8;
/// Limbs per wide register.
pub const WIDE_LIMBS: usize = 4;

/// Column indices into the flattened trace row.
pub mod col {
    // === Control (5 columns) ===
    pub const PC: usize = 0;
    pub const OPCODE: usize = 1;
    pub const RD: usize = 2;
    pub const RS1: usize = 3;
    pub const RS2_IMM: usize = 4;

    // === GP registers: 5..21 (16 columns) ===
    pub const GP_START: usize = 5;
    pub const fn gp(i: usize) -> usize { GP_START + i }

    // === Wide registers: 21..53 (8 × 4 = 32 columns) ===
    pub const WIDE_START: usize = 21;
    pub const fn wide(reg: usize, limb: usize) -> usize { WIDE_START + reg * 4 + limb }

    // === Memory: 53..60 (7 columns) ===
    pub const MEM_ADDR: usize = 53;
    pub const MEM_VAL_START: usize = 54; // 4 limbs (for wide loads)
    pub const fn mem_val(i: usize) -> usize { MEM_VAL_START + i }
    pub const MEM_WIDTH: usize = 58;
    pub const MEM_IS_WRITE: usize = 59;

    // === Storage: 60..70 (10 columns) ===
    pub const STORAGE_KEY_START: usize = 60; // 4 limbs
    pub const fn storage_key(i: usize) -> usize { STORAGE_KEY_START + i }
    pub const STORAGE_VAL_START: usize = 64; // 4 limbs
    pub const fn storage_val(i: usize) -> usize { STORAGE_VAL_START + i }
    pub const STORAGE_VAL_LEN: usize = 68;
    pub const STORAGE_IS_WRITE: usize = 69;

    // === Gas: 70..72 (2 columns) ===
    pub const GAS_STEP: usize = 70;
    pub const GAS_CUMULATIVE: usize = 71;

    // === Flags: 72..75 (3 columns) ===
    pub const IS_MEMORY_OP: usize = 72;
    pub const IS_STORAGE_OP: usize = 73;
    pub const IS_FINAL: usize = 74;

    // === Opcode bits: 75..81 (6 columns) ===
    pub const OPCODE_BITS_START: usize = 75;
    pub const fn opcode_bit(i: usize) -> usize { OPCODE_BITS_START + i }

    // === Operands: 81..85 (4 columns) ===
    pub const OP_A: usize = 81;      // resolved first operand (gp[rs1])
    pub const OP_B: usize = 82;      // resolved second operand (gp[rs2] or immediate)
    pub const OP_RESULT: usize = 83;  // result written to gp[rd]
    pub const OP_AUX: usize = 84;    // auxiliary: DIV remainder, MOD quotient, comparison diff, etc.

    // === Register selectors: 85..133 (48 columns) ===
    pub const RD_SEL_START: usize = 85;   // 16 one-hot for rd
    pub const RS1_SEL_START: usize = 101;  // 16 one-hot for rs1
    pub const RS2_SEL_START: usize = 117;  // 16 one-hot for rs2 (register-register ops)
    pub const fn rd_sel(i: usize) -> usize { RD_SEL_START + i }
    pub const fn rs1_sel(i: usize) -> usize { RS1_SEL_START + i }
    pub const fn rs2_sel(i: usize) -> usize { RS2_SEL_START + i }

    // === Branch/Call: 133..136 (3 columns) ===
    pub const BRANCH_TAKEN: usize = 133;
    pub const DIFF_INV: usize = 134;
    pub const CALL_DEPTH: usize = 135;

    // === Wide arithmetic: 136..144 (8 columns) ===
    pub const WIDE_CARRY_START: usize = 136;
    pub const fn wide_carry(i: usize) -> usize { WIDE_CARRY_START + i }
    pub const WIDE_QUOTIENT_START: usize = 140;
    pub const fn wide_quotient(i: usize) -> usize { WIDE_QUOTIENT_START + i }

    // === Wide register selectors: 144..160 (16 columns) ===
    pub const WIDE_RD_SEL_START: usize = 144;  // 8 one-hot for wide rd (w0-w7)
    pub const WIDE_RS1_SEL_START: usize = 152; // 8 one-hot for wide rs1 (w0-w7)
    pub const fn wide_rd_sel(i: usize) -> usize { WIDE_RD_SEL_START + i }
    pub const fn wide_rs1_sel(i: usize) -> usize { WIDE_RS1_SEL_START + i }

    /// Total columns.
    pub const NUM_COLUMNS: usize = 160;
}

/// A single trace row (one PVM execution step).
#[derive(Clone, Debug)]
pub struct TraceRow {
    pub fields: [Goldilocks; 160],
}

impl TraceRow {
    /// All zeros.
    pub fn zero() -> Self {
        Self {
            fields: [Goldilocks::zero(); 160],
        }
    }

    /// Get a column value.
    #[inline]
    pub fn get(&self, col: usize) -> Goldilocks {
        self.fields[col]
    }

    /// Set a column value.
    #[inline]
    pub fn set(&mut self, col: usize, val: Goldilocks) {
        self.fields[col] = val;
    }

    /// Set from u64.
    #[inline]
    pub fn set_u64(&mut self, col: usize, val: u64) {
        self.fields[col] = Goldilocks::from_canonical_u64(val);
    }

    /// Set a flag to 1.
    #[inline]
    pub fn set_flag(&mut self, col: usize) {
        self.fields[col] = Goldilocks::one();
    }

    /// Set opcode bits from opcode value.
    pub fn set_opcode_bits(&mut self, opcode: u64) {
        for i in 0..6 {
            self.fields[col::opcode_bit(i)] = if (opcode >> i) & 1 == 1 {
                Goldilocks::one()
            } else {
                Goldilocks::zero()
            };
        }
    }

    /// Set one-hot register selector.
    pub fn set_rd_sel(&mut self, rd: u8) {
        if (rd as usize) < 16 {
            self.fields[col::rd_sel(rd as usize)] = Goldilocks::one();
        }
    }

    pub fn set_rs1_sel(&mut self, rs1: u8) {
        if (rs1 as usize) < 16 {
            self.fields[col::rs1_sel(rs1 as usize)] = Goldilocks::one();
        }
    }

    pub fn set_rs2_sel(&mut self, rs2: u8) {
        if (rs2 as usize) < 16 {
            self.fields[col::rs2_sel(rs2 as usize)] = Goldilocks::one();
        }
    }

    /// Set one-hot wide register destination selector (w0-w7).
    pub fn set_wide_rd_sel(&mut self, wd: u8) {
        if (wd as usize) < 8 {
            self.fields[col::wide_rd_sel(wd as usize)] = Goldilocks::one();
        }
    }

    /// Set one-hot wide register source selector (w0-w7).
    pub fn set_wide_rs1_sel(&mut self, ws1: u8) {
        if (ws1 as usize) < 8 {
            self.fields[col::wide_rs1_sel(ws1 as usize)] = Goldilocks::one();
        }
    }
}

/// The full execution trace.
#[derive(Clone, Debug, Default)]
pub struct ExecutionTrace {
    pub rows: Vec<TraceRow>,
}

impl ExecutionTrace {
    pub fn new() -> Self {
        Self { rows: Vec::new() }
    }

    pub fn push(&mut self, row: TraceRow) {
        self.rows.push(row);
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Pad to next power of 2 with is_final=1 rows.
    pub fn pad_to_power_of_two(&mut self) {
        if self.rows.is_empty() {
            return;
        }
        let target = self.rows.len().next_power_of_two();
        while self.rows.len() < target {
            let mut pad = TraceRow::zero();
            pad.set_flag(col::IS_FINAL);
            // Valid one-hot selectors for padding
            pad.fields[col::rd_sel(0)] = Goldilocks::one();
            pad.fields[col::rs1_sel(0)] = Goldilocks::one();
            self.rows.push(pad);
        }
    }

    /// Convert to flat row-major values for polynomial commitment.
    pub fn to_row_major_values(&self) -> Vec<Goldilocks> {
        let mut values = Vec::with_capacity(self.rows.len() * col::NUM_COLUMNS);
        for row in &self.rows {
            values.extend_from_slice(&row.fields);
        }
        values
    }
}

/// Helper: u64 → Goldilocks.
#[inline]
pub fn to_field(val: u64) -> Goldilocks {
    Goldilocks::from_canonical_u64(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_count() {
        assert_eq!(col::NUM_COLUMNS, 160);
    }

    #[test]
    fn zero_row() {
        let row = TraceRow::zero();
        for i in 0..col::NUM_COLUMNS {
            assert_eq!(row.get(i), Goldilocks::zero());
        }
    }

    #[test]
    fn set_and_get() {
        let mut row = TraceRow::zero();
        row.set_u64(col::PC, 42);
        row.set_u64(col::OPCODE, 0x01);
        assert_eq!(row.get(col::PC), to_field(42));
        assert_eq!(row.get(col::OPCODE), to_field(0x01));
    }

    #[test]
    fn opcode_bits_decomposition() {
        let mut row = TraceRow::zero();
        row.set_opcode_bits(0x2C); // HALT = 0b101100
        assert_eq!(row.get(col::opcode_bit(0)), Goldilocks::zero());  // bit 0 = 0
        assert_eq!(row.get(col::opcode_bit(1)), Goldilocks::zero());  // bit 1 = 0
        assert_eq!(row.get(col::opcode_bit(2)), Goldilocks::one());   // bit 2 = 1
        assert_eq!(row.get(col::opcode_bit(3)), Goldilocks::one());   // bit 3 = 1
        assert_eq!(row.get(col::opcode_bit(4)), Goldilocks::zero());  // bit 4 = 0
        assert_eq!(row.get(col::opcode_bit(5)), Goldilocks::one());   // bit 5 = 1
    }

    #[test]
    fn register_selectors() {
        let mut row = TraceRow::zero();
        row.set_rd_sel(5);
        row.set_rs1_sel(3);
        assert_eq!(row.get(col::rd_sel(5)), Goldilocks::one());
        assert_eq!(row.get(col::rd_sel(0)), Goldilocks::zero());
        assert_eq!(row.get(col::rs1_sel(3)), Goldilocks::one());
    }

    #[test]
    fn pad_to_power_of_two() {
        let mut trace = ExecutionTrace::new();
        for _ in 0..5 {
            trace.push(TraceRow::zero());
        }
        trace.pad_to_power_of_two();
        assert_eq!(trace.len(), 8);
        // Padding rows have is_final=1
        assert_eq!(trace.rows[7].get(col::IS_FINAL), Goldilocks::one());
    }

    #[test]
    fn row_major_values() {
        let mut trace = ExecutionTrace::new();
        let mut row = TraceRow::zero();
        row.set_u64(col::PC, 100);
        trace.push(row);
        let values = trace.to_row_major_values();
        assert_eq!(values.len(), 160);
        assert_eq!(values[col::PC], to_field(100));
    }

    #[test]
    fn wide_register_indices() {
        // w0 limb 0 = index 21, w0 limb 3 = index 24
        assert_eq!(col::wide(0, 0), 21);
        assert_eq!(col::wide(0, 3), 24);
        // w7 limb 3 = last wide column = index 52
        assert_eq!(col::wide(7, 3), 52);
        // Next section (memory) starts at 53
        assert_eq!(col::MEM_ADDR, 53);
    }
}
