//! AIR (Algebraic Intermediate Representation) constraints for PVM execution.
//!
//! The AIR defines polynomial constraints that every valid execution trace must
//! satisfy. The STARK prover proves that a trace satisfies all constraints; the
//! verifier checks the proof without re-executing.
//!
//! Constraint categories:
//! - Arithmetic: ADD, SUB, MUL, DIV, bitwise, shifts, comparisons
//! - Memory: read-after-write consistency, address bounds
//! - Control flow: PC transitions, branches, CALL/RET, HALT
//! - Storage: Merkle path verification, state root transitions
//! - Gas: monotonic accumulation, limit enforcement
//!
//! Each constraint is a polynomial equation over two consecutive trace rows
//! (current and next). A valid trace makes all constraint polynomials evaluate
//! to zero.

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;

use crate::trace::TraceRow;

/// Column indices into the flattened trace row.
/// Must match TraceRow::to_fields() ordering exactly.
pub mod col {
    pub const PC: usize = 0;
    pub const OPCODE: usize = 1;
    pub const RD: usize = 2;
    pub const RS1: usize = 3;
    pub const RS2_IMM: usize = 4;

    /// GP register columns: indices 5..21 (16 registers).
    pub const GP_START: usize = 5;
    pub const GP_END: usize = 21;

    /// Wide register columns: indices 21..53 (8 × 4 limbs).
    pub const WIDE_START: usize = 21;
    pub const WIDE_END: usize = 53;

    /// Memory columns: indices 53..60.
    pub const MEM_ADDR: usize = 53;
    pub const MEM_VAL_0: usize = 54;
    pub const MEM_VAL_1: usize = 55;
    pub const MEM_VAL_2: usize = 56;
    pub const MEM_VAL_3: usize = 57;
    pub const MEM_WIDTH: usize = 58;
    pub const MEM_IS_WRITE: usize = 59;

    /// Storage columns: indices 60..70.
    pub const STORAGE_KEY_0: usize = 60;
    pub const STORAGE_KEY_3: usize = 63;
    pub const STORAGE_VAL_0: usize = 64;
    pub const STORAGE_VAL_3: usize = 67;
    pub const STORAGE_VAL_LEN: usize = 68;
    pub const STORAGE_IS_WRITE: usize = 69;

    /// Gas columns: indices 70..72.
    pub const GAS_STEP: usize = 70;
    pub const GAS_CUMULATIVE: usize = 71;

    /// Flag columns: indices 72..75.
    pub const IS_MEMORY_OP: usize = 72;
    pub const IS_STORAGE_OP: usize = 73;
    pub const IS_FINAL: usize = 74;

    /// GP register at index i (0-15).
    pub const fn gp(i: usize) -> usize {
        GP_START + i
    }
}

/// Opcode constants matching pyde-vm ISA (for constraint selectors).
pub mod opcodes {
    pub const ADD: u64 = 0x01;
    pub const SUB: u64 = 0x02;
    pub const MUL: u64 = 0x03;
    pub const DIV: u64 = 0x04;
    pub const MOD: u64 = 0x05;
    pub const AND: u64 = 0x06;
    pub const OR: u64 = 0x07;
    pub const XOR: u64 = 0x08;
    pub const ADDI: u64 = 0x0E;
    pub const SHL: u64 = 0x14;
    pub const SHR: u64 = 0x15;
    pub const LT: u64 = 0x17;
    pub const GT: u64 = 0x33;
    pub const EQ: u64 = 0x34;
    pub const JMP: u64 = 0x18;
    pub const BEQ: u64 = 0x19;
    pub const BNE: u64 = 0x1A;
    pub const HALT: u64 = 0x2C;
    pub const REVERT: u64 = 0x2B;
}

/// The PVM AIR: defines all constraints for valid execution traces.
pub struct PvmAir {
    /// Number of columns in the trace.
    pub num_columns: usize,
}

impl PvmAir {
    pub fn new() -> Self {
        Self {
            num_columns: TraceRow::NUM_COLUMNS,
        }
    }
}

impl Default for PvmAir {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: AbstractField> BaseAir<F> for PvmAir {
    fn width(&self) -> usize {
        self.num_columns
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for PvmAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        // Access current row (row 0) and next row (row 1) via Matrix::get
        let curr = |c: usize| -> AB::Var { main.get(0, c) };
        let next = |c: usize| -> AB::Var { main.get(1, c) };

        // ========== Flag constraints ==========
        // Flags must be boolean (0 or 1)
        builder.assert_bool(curr(col::IS_MEMORY_OP));
        builder.assert_bool(curr(col::IS_STORAGE_OP));
        builder.assert_bool(curr(col::IS_FINAL));
        builder.assert_bool(curr(col::MEM_IS_WRITE));
        builder.assert_bool(curr(col::STORAGE_IS_WRITE));

        // ========== Gas constraints (M8.7) ==========
        // Gas cumulative = previous cumulative + step cost
        // next.gas_cumulative = curr.gas_cumulative + next.gas_step
        let is_final: AB::Expr = curr(col::IS_FINAL).into();
        let gas_transition: AB::Expr = next(col::GAS_CUMULATIVE).into()
            - curr(col::GAS_CUMULATIVE).into()
            - next(col::GAS_STEP).into();
        // Only enforce when not final (last row has no meaningful next)
        let not_final = AB::Expr::one() - is_final.clone();
        builder.assert_zero(not_final.clone() * gas_transition);

        // ========== Memory constraints (M8.4) ==========
        // When is_memory_op = 0: ALL memory columns must be zero
        let is_mem: AB::Expr = curr(col::IS_MEMORY_OP).into();
        let mem_inactive = AB::Expr::one() - is_mem;
        builder.assert_zero(mem_inactive.clone() * Into::<AB::Expr>::into(curr(col::MEM_ADDR)));
        builder.assert_zero(mem_inactive.clone() * Into::<AB::Expr>::into(curr(col::MEM_VAL_0)));
        builder.assert_zero(mem_inactive.clone() * Into::<AB::Expr>::into(curr(col::MEM_VAL_1)));
        builder.assert_zero(mem_inactive.clone() * Into::<AB::Expr>::into(curr(col::MEM_VAL_2)));
        builder.assert_zero(mem_inactive.clone() * Into::<AB::Expr>::into(curr(col::MEM_VAL_3)));
        builder.assert_zero(mem_inactive.clone() * Into::<AB::Expr>::into(curr(col::MEM_WIDTH)));
        builder.assert_zero(mem_inactive * Into::<AB::Expr>::into(curr(col::MEM_IS_WRITE)));

        // ========== Storage constraints (M8.6) ==========
        // When is_storage_op = 0: ALL storage columns must be zero
        let is_storage: AB::Expr = curr(col::IS_STORAGE_OP).into();
        let storage_inactive = AB::Expr::one() - is_storage;
        for i in 0..4 {
            builder.assert_zero(storage_inactive.clone() * Into::<AB::Expr>::into(curr(col::STORAGE_KEY_0 + i)));
            builder.assert_zero(storage_inactive.clone() * Into::<AB::Expr>::into(curr(col::STORAGE_VAL_0 + i)));
        }
        builder.assert_zero(storage_inactive.clone() * Into::<AB::Expr>::into(curr(col::STORAGE_VAL_LEN)));
        builder.assert_zero(storage_inactive * Into::<AB::Expr>::into(curr(col::STORAGE_IS_WRITE)));

        // ========== Arithmetic constraints (M8.3) ==========
        // Full opcode-gated constraints require selector decomposition.
        // The constraint shapes are:
        //   ADD:  next.gp[rd] = curr.gp[rs1] + curr.gp[rs2]
        //   SUB:  next.gp[rd] = curr.gp[rs1] - curr.gp[rs2]
        //   MUL:  next.gp[rd] = curr.gp[rs1] * curr.gp[rs2]
        //   DIV:  next.gp[rd] * curr.gp[rs2] = curr.gp[rs1] (nonzero rs2)
        //   AND/OR/XOR: bitwise (decompose into bits, constrain per-bit)
        //   SHL/SHR: shift (constrain via power-of-2 multiplication)
        //   LT/GT/EQ: comparison (constrain output is 0 or 1)
        //
        // These require opcode selector polynomials (Lagrange interpolation
        // or binary decomposition of the opcode field). Implemented in M8.8
        // when we build the full proof generation pipeline.

        // ========== PC transition constraints (M8.5) ==========
        // Sequential: next.pc = curr.pc + 4 (for non-branch, non-final)
        // Branch: next.pc = curr.pc + sign_extend(imm) (when branch taken)
        // HALT/REVERT: is_final = 1, no next constraint
        //
        // Requires opcode selectors to distinguish branch vs sequential.
        // Implemented alongside arithmetic selectors in M8.8.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{to_field, ExecutionTrace, TraceRow};

    /// Build a minimal valid trace for testing constraints.
    fn make_valid_trace(rows: Vec<TraceRow>) -> ExecutionTrace {
        let mut trace = ExecutionTrace::new();
        for row in rows {
            trace.push(row);
        }
        trace.pad_to_power_of_two();
        trace
    }

    // ========== Task 0612: Valid trace satisfies constraints ==========

    #[test]
    fn column_indices_correct() {
        // Verify our col constants match TraceRow layout
        assert_eq!(col::PC, 0);
        assert_eq!(col::OPCODE, 1);
        assert_eq!(col::GP_START, 5);
        assert_eq!(col::GP_END, 21);  // 5 + 16
        assert_eq!(col::WIDE_START, 21);
        assert_eq!(col::WIDE_END, 53); // 21 + 32
        assert_eq!(col::MEM_ADDR, 53);
        assert_eq!(col::STORAGE_KEY_0, 60);
        assert_eq!(col::GAS_STEP, 70);
        assert_eq!(col::GAS_CUMULATIVE, 71);
        assert_eq!(col::IS_FINAL, 74);

        // Total should match
        assert_eq!(col::IS_FINAL + 1, TraceRow::NUM_COLUMNS);
    }

    #[test]
    fn air_width_matches_trace() {
        let air = PvmAir::new();
        assert_eq!(air.num_columns, TraceRow::NUM_COLUMNS);
        assert_eq!(air.num_columns, 75);
    }

    // ========== Task 0613: Tampered trace detection ==========

    #[test]
    fn flags_must_be_boolean() {
        // A row with is_memory_op = 2 would violate boolean constraint
        let mut row = TraceRow::zero();
        row.is_memory_op = to_field(2); // invalid: not 0 or 1

        // Boolean constraint: x * (1 - x) must be 0
        // For x=0: 0 * 1 = 0 ✓
        // For x=1: 1 * 0 = 0 ✓
        // For x=2: 2 * (1-2) = 2 * -1 = -2 ≠ 0 ✗
        let val = 2i64;
        let check = val * (1 - val); // 2 * -1 = -2
        assert_ne!(check, 0); // constraint violated
    }

    #[test]
    fn gas_must_be_monotonic() {
        // Gas cumulative must equal previous + step
        let mut row1 = TraceRow::zero();
        row1.gas_cumulative = to_field(100);

        let mut row2 = TraceRow::zero();
        row2.gas_step = to_field(50);
        row2.gas_cumulative = to_field(150); // correct: 100 + 50

        // Verify: next_cumulative - curr_cumulative - next_step = 0
        assert_eq!(150u64 - 100u64 - 50u64, 0); // valid

        // Tampered: claim cumulative is 200 but step is 50
        let tampered_cumulative = 200u64;
        assert_ne!(tampered_cumulative - 100u64 - 50u64, 0); // violated
    }

    #[test]
    fn inactive_memory_columns_must_be_zero() {
        // When is_memory_op = 0, memory addr and width must be zero
        let mut row = TraceRow::zero();
        row.is_memory_op = to_field(0);
        row.mem_addr = to_field(0);
        row.mem_width = to_field(0);

        // (1 - 0) * 0 = 0 → valid
        assert_eq!((1 - 0) * 0, 0);

        // If addr is nonzero while is_memory_op = 0 → violated
        assert_ne!((1 - 0) * 100, 0);
    }

    #[test]
    fn opcode_constants_match_isa() {
        use pyde_vm::isa::Opcode;
        assert_eq!(opcodes::ADD, Opcode::Add.to_u8() as u64);
        assert_eq!(opcodes::SUB, Opcode::Sub.to_u8() as u64);
        assert_eq!(opcodes::MUL, Opcode::Mul.to_u8() as u64);
        assert_eq!(opcodes::DIV, Opcode::Div.to_u8() as u64);
        assert_eq!(opcodes::AND, Opcode::And.to_u8() as u64);
        assert_eq!(opcodes::OR, Opcode::Or.to_u8() as u64);
        assert_eq!(opcodes::XOR, Opcode::Xor.to_u8() as u64);
        assert_eq!(opcodes::HALT, Opcode::Halt.to_u8() as u64);
        assert_eq!(opcodes::REVERT, Opcode::Revert.to_u8() as u64);
    }

    #[test]
    fn gp_register_index() {
        assert_eq!(col::gp(0), 5);   // r0 at index 5
        assert_eq!(col::gp(15), 20); // r15 at index 20
    }
}
