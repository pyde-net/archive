//! Thin AIR adapter: bridges our constraint evaluator to Plonky3's prove/verify.
//!
//! Our constraints live in constraint.rs as plain Rust functions.
//! Plonky3's prover needs an `Air<AB>` trait implementation.
//! This module provides that bridge — it's a wrapper, not a reimplementation.

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;

use crate::trace::col;

/// Build opcode selector from 6 bits at the current row.
macro_rules! opcode_sel {
    ($op:expr, $curr:expr, $AB:ty) => {{
        let mut sel = <$AB as AirBuilder>::Expr::one();
        for i in 0..6 {
            let bit: <$AB as AirBuilder>::Expr = $curr(col::opcode_bit(i)).into();
            if ($op >> i) & 1 == 1 {
                sel = sel * bit;
            } else {
                sel = sel * (<$AB as AirBuilder>::Expr::one() - bit);
            }
        }
        sel
    }};
}

/// PVM AIR adapter for Plonky3.
/// Calls into constraint.rs for the actual constraint evaluation.
pub struct PvmAir;

impl<F: AbstractField> BaseAir<F> for PvmAir {
    fn width(&self) -> usize {
        col::NUM_COLUMNS
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for PvmAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let curr = |c: usize| -> AB::Var { main.get(0, c) };
        let next = |c: usize| -> AB::Var { main.get(1, c) };

        // ========== Opcode bit constraints ==========
        for i in 0..6 {
            builder.assert_bool(curr(col::opcode_bit(i)));
        }
        let mut opcode_sum = AB::Expr::zero();
        for i in 0..6 {
            let bit: AB::Expr = curr(col::opcode_bit(i)).into();
            let weight = AB::Expr::from_canonical_u64(1u64 << i);
            opcode_sum = opcode_sum + bit * weight;
        }
        builder.assert_zero(Into::<AB::Expr>::into(curr(col::OPCODE)) - opcode_sum);

        // ========== Flag booleans ==========
        builder.assert_bool(curr(col::IS_FINAL));
        builder.assert_bool(curr(col::IS_MEMORY_OP));
        builder.assert_bool(curr(col::IS_STORAGE_OP));
        builder.assert_bool(curr(col::MEM_IS_WRITE));
        builder.assert_bool(curr(col::STORAGE_IS_WRITE));
        builder.assert_bool(curr(col::BRANCH_TAKEN));

        // ========== Register selector booleans + one-hot ==========
        let mut rd_sum = AB::Expr::zero();
        let mut rs1_sum = AB::Expr::zero();
        let mut rs2_sum = AB::Expr::zero();
        for i in 0..16 {
            builder.assert_bool(curr(col::rd_sel(i)));
            builder.assert_bool(curr(col::rs1_sel(i)));
            builder.assert_bool(curr(col::rs2_sel(i)));
            rd_sum = rd_sum + Into::<AB::Expr>::into(curr(col::rd_sel(i)));
            rs1_sum = rs1_sum + Into::<AB::Expr>::into(curr(col::rs1_sel(i)));
            rs2_sum = rs2_sum + Into::<AB::Expr>::into(curr(col::rs2_sel(i)));
        }
        builder.assert_one(rd_sum);
        builder.assert_one(rs1_sum);
        // rs2_sum ∈ {0, 1}
        builder.assert_zero(rs2_sum.clone() * (AB::Expr::one() - rs2_sum.clone()));

        // Selector consistency: rd = sum(i * rd_sel[i]), rs1 = sum(i * rs1_sel[i])
        let mut rd_from_sel = AB::Expr::zero();
        let mut rs1_from_sel = AB::Expr::zero();
        for i in 0..16 {
            let w = AB::Expr::from_canonical_u64(i as u64);
            rd_from_sel = rd_from_sel + Into::<AB::Expr>::into(curr(col::rd_sel(i))) * w.clone();
            rs1_from_sel = rs1_from_sel + Into::<AB::Expr>::into(curr(col::rs1_sel(i))) * w;
        }
        builder.assert_zero(Into::<AB::Expr>::into(curr(col::RD)) - rd_from_sel);
        builder.assert_zero(Into::<AB::Expr>::into(curr(col::RS1)) - rs1_from_sel);

        // ========== Register multiplexers ==========
        // op_a = sum(rs1_sel[i] * gp[i])
        let mut mux_a = AB::Expr::zero();
        for i in 0..16 {
            mux_a = mux_a
                + Into::<AB::Expr>::into(curr(col::rs1_sel(i)))
                    * Into::<AB::Expr>::into(curr(col::gp(i)));
        }
        builder.assert_zero(Into::<AB::Expr>::into(curr(col::OP_A)) - mux_a);

        // op_b = sum(rs2_sel[i] * gp[i]) for register-register ops
        let mut mux_b = AB::Expr::zero();
        for i in 0..16 {
            mux_b = mux_b
                + Into::<AB::Expr>::into(curr(col::rs2_sel(i)))
                    * Into::<AB::Expr>::into(curr(col::gp(i)));
        }
        builder.assert_zero(rs2_sum * (Into::<AB::Expr>::into(curr(col::OP_B)) - mux_b));

        // result = gp[rd] for GP-writing ops
        let mut mux_rd = AB::Expr::zero();
        for i in 0..16 {
            mux_rd = mux_rd
                + Into::<AB::Expr>::into(curr(col::rd_sel(i)))
                    * Into::<AB::Expr>::into(curr(col::gp(i)));
        }
        let result: AB::Expr = curr(col::OP_RESULT).into();
        let is_gp_write = opcode_sel!(0x01, curr, AB) + opcode_sel!(0x02, curr, AB) // ADD, SUB
            + opcode_sel!(0x03, curr, AB) + opcode_sel!(0x04, curr, AB) // MUL, DIV
            + opcode_sel!(0x05, curr, AB) + opcode_sel!(0x0E, curr, AB) // MOD, ADDI
            + opcode_sel!(0x06, curr, AB) + opcode_sel!(0x07, curr, AB) // AND, OR
            + opcode_sel!(0x08, curr, AB) + opcode_sel!(0x0F, curr, AB) // XOR, NOT
            + opcode_sel!(0x14, curr, AB) + opcode_sel!(0x15, curr, AB) // SHL, SHR
            + opcode_sel!(0x16, curr, AB) // SAR
            + opcode_sel!(0x34, curr, AB) + opcode_sel!(0x17, curr, AB) // EQ, LT
            + opcode_sel!(0x33, curr, AB) + opcode_sel!(0x35, curr, AB) // GT, SLT
            + opcode_sel!(0x36, curr, AB) + opcode_sel!(0x39, curr, AB) // SGT, FIELDMUL
            + opcode_sel!(0x10, curr, AB) + opcode_sel!(0x13, curr, AB) // LOAD, POP
            + opcode_sel!(0x3D, curr, AB) + opcode_sel!(0x23, curr, AB); // NARROW, CALLER
        builder.assert_zero(is_gp_write * (mux_rd - result.clone()));

        // ========== Common expressions ==========
        let is_final: AB::Expr = curr(col::IS_FINAL).into();
        let not_final = AB::Expr::one() - is_final.clone();
        let op_a: AB::Expr = curr(col::OP_A).into();
        let op_b: AB::Expr = curr(col::OP_B).into();
        let op_aux: AB::Expr = curr(col::OP_AUX).into();
        let diff_inv: AB::Expr = curr(col::DIFF_INV).into();

        // ========== Arithmetic ==========
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(0x01, curr, AB)
                * (result.clone() - op_a.clone() - op_b.clone()),
        );
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(0x02, curr, AB)
                * (result.clone() - op_a.clone() + op_b.clone()),
        );
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(0x03, curr, AB)
                * (result.clone() - op_a.clone() * op_b.clone()),
        );
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(0x04, curr, AB)
                * (op_a.clone() - result.clone() * op_b.clone() - op_aux.clone()),
        );
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(0x05, curr, AB)
                * (op_a.clone() - op_aux.clone() * op_b.clone() - result.clone()),
        );
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(0x0E, curr, AB)
                * (result.clone() - op_a.clone() - op_b.clone()),
        );
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(0x39, curr, AB)
                * (result.clone() - op_a.clone() * op_b.clone()),
        );

        // ========== Shifts ==========
        // SHL: result = op_a * op_b (recorder sets op_b = 2^shift_amount)
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(0x14, curr, AB)
                * (result.clone() - op_a.clone() * op_b.clone()),
        );
        // SHR/SAR: op_a = result * op_b + op_aux
        let is_shr = opcode_sel!(0x15, curr, AB) + opcode_sel!(0x16, curr, AB);
        builder.assert_zero(
            not_final.clone()
                * is_shr
                * (op_a.clone() - result.clone() * op_b.clone() - op_aux.clone()),
        );

        // ========== Comparisons ==========
        // EQ: diff_inv technique
        let is_eq: AB::Expr = opcode_sel!(0x34, curr, AB);
        let diff = op_a.clone() - op_b.clone();
        builder.assert_zero(
            is_eq.clone() * (diff.clone() * diff_inv.clone() - AB::Expr::one() + result.clone()),
        );
        builder.assert_zero(is_eq * (diff.clone() * result.clone()));

        // LT
        let is_lt = opcode_sel!(0x17, curr, AB);
        builder.assert_zero(is_lt.clone() * result.clone() * (AB::Expr::one() - result.clone()));
        builder.assert_zero(
            is_lt
                * (result.clone()
                    * (op_b.clone() - op_a.clone() - AB::Expr::one() - op_aux.clone())
                    + (AB::Expr::one() - result.clone())
                        * (op_a.clone() - op_b.clone() - op_aux.clone())),
        );

        // GT
        let is_gt = opcode_sel!(0x33, curr, AB);
        builder.assert_zero(is_gt.clone() * result.clone() * (AB::Expr::one() - result.clone()));
        builder.assert_zero(
            is_gt
                * (result.clone()
                    * (op_a.clone() - op_b.clone() - AB::Expr::one() - op_aux.clone())
                    + (AB::Expr::one() - result.clone())
                        * (op_b.clone() - op_a.clone() - op_aux.clone())),
        );

        // SLT/SGT/VERIFYSIG/WEQ/WLT: boolean
        builder.assert_zero(
            opcode_sel!(0x35, curr, AB) * result.clone() * (AB::Expr::one() - result.clone()),
        );
        builder.assert_zero(
            opcode_sel!(0x36, curr, AB) * result.clone() * (AB::Expr::one() - result.clone()),
        );
        builder.assert_zero(
            opcode_sel!(0x31, curr, AB) * result.clone() * (AB::Expr::one() - result.clone()),
        );
        builder.assert_zero(
            opcode_sel!(0x00, curr, AB) * result.clone() * (AB::Expr::one() - result.clone()),
        );
        builder.assert_zero(
            opcode_sel!(0x3F, curr, AB) * result.clone() * (AB::Expr::one() - result.clone()),
        );
        // MERKLEVERIFY (0x32): boolean result
        builder.assert_zero(
            opcode_sel!(0x32, curr, AB) * result.clone() * (AB::Expr::one() - result.clone()),
        );

        // ========== Memory ==========
        let mem_val0: AB::Expr = curr(col::mem_val(0)).into();
        let is_load = opcode_sel!(0x10, curr, AB) + opcode_sel!(0x13, curr, AB);
        builder.assert_zero(is_load.clone() * (result.clone() - mem_val0.clone()));
        builder.assert_zero(
            is_load * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::IS_MEMORY_OP))),
        );

        let is_store = opcode_sel!(0x11, curr, AB) + opcode_sel!(0x12, curr, AB);
        builder.assert_zero(is_store.clone() * (op_a.clone() - mem_val0));
        builder.assert_zero(
            is_store.clone() * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::IS_MEMORY_OP))),
        );
        builder.assert_zero(
            is_store * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::MEM_IS_WRITE))),
        );

        // Memory inactive
        let mem_inactive = AB::Expr::one() - Into::<AB::Expr>::into(curr(col::IS_MEMORY_OP));
        builder.assert_zero(mem_inactive.clone() * Into::<AB::Expr>::into(curr(col::MEM_ADDR)));
        for i in 0..4 {
            builder
                .assert_zero(mem_inactive.clone() * Into::<AB::Expr>::into(curr(col::mem_val(i))));
        }
        builder.assert_zero(mem_inactive.clone() * Into::<AB::Expr>::into(curr(col::MEM_WIDTH)));
        builder.assert_zero(mem_inactive * Into::<AB::Expr>::into(curr(col::MEM_IS_WRITE)));

        // WLOAD/WSTORE: must flag memory
        builder.assert_zero(
            opcode_sel!(0x37, curr, AB)
                * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::IS_MEMORY_OP))),
        );
        builder.assert_zero(
            opcode_sel!(0x3B, curr, AB)
                * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::IS_MEMORY_OP))),
        );
        builder.assert_zero(
            opcode_sel!(0x3B, curr, AB)
                * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::MEM_IS_WRITE))),
        );

        // Storage inactive
        let storage_inactive = AB::Expr::one() - Into::<AB::Expr>::into(curr(col::IS_STORAGE_OP));
        for i in 0..4 {
            builder.assert_zero(
                storage_inactive.clone() * Into::<AB::Expr>::into(curr(col::storage_key(i))),
            );
            builder.assert_zero(
                storage_inactive.clone() * Into::<AB::Expr>::into(curr(col::storage_val(i))),
            );
        }
        builder.assert_zero(
            storage_inactive.clone() * Into::<AB::Expr>::into(curr(col::STORAGE_VAL_LEN)),
        );
        builder.assert_zero(storage_inactive * Into::<AB::Expr>::into(curr(col::STORAGE_IS_WRITE)));

        // SLOAD/SSTORE/SDELETE must flag storage
        builder.assert_zero(
            opcode_sel!(0x20, curr, AB)
                * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::IS_STORAGE_OP))),
        );
        builder.assert_zero(
            opcode_sel!(0x21, curr, AB)
                * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::IS_STORAGE_OP))),
        );
        builder.assert_zero(
            opcode_sel!(0x21, curr, AB)
                * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::STORAGE_IS_WRITE))),
        );
        builder.assert_zero(
            opcode_sel!(0x22, curr, AB)
                * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::IS_STORAGE_OP))),
        );
        // LOG must not touch storage
        builder.assert_zero(
            opcode_sel!(0x2A, curr, AB) * Into::<AB::Expr>::into(curr(col::IS_STORAGE_OP)),
        );

        // ========== Gas ==========
        builder.assert_zero(
            not_final.clone()
                * (Into::<AB::Expr>::into(next(col::GAS_CUMULATIVE))
                    - Into::<AB::Expr>::into(curr(col::GAS_CUMULATIVE))
                    - Into::<AB::Expr>::into(next(col::GAS_STEP))),
        );

        // ========== Control flow ==========
        let four = AB::Expr::from_canonical_u64(4);
        let is_branch = opcode_sel!(0x18, curr, AB)
            + opcode_sel!(0x19, curr, AB)
            + opcode_sel!(0x1A, curr, AB)
            + opcode_sel!(0x1B, curr, AB)
            + opcode_sel!(0x1C, curr, AB)
            + opcode_sel!(0x1D, curr, AB)
            + opcode_sel!(0x1E, curr, AB);
        let next_pc: AB::Expr = next(col::PC).into();
        let curr_pc: AB::Expr = curr(col::PC).into();
        builder.assert_zero(
            not_final.clone()
                * (AB::Expr::one() - is_branch)
                * (next_pc.clone() - curr_pc.clone() - four.clone()),
        );

        // BEQ
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(0x19, curr, AB)
                * diff.clone()
                * (next_pc.clone() - curr_pc.clone() - four.clone()),
        );

        // BNE
        let branch_taken: AB::Expr = curr(col::BRANCH_TAKEN).into();
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(0x1A, curr, AB)
                * (diff.clone() * diff_inv.clone() - branch_taken.clone()),
        );
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(0x1A, curr, AB)
                * (AB::Expr::one() - branch_taken.clone())
                * (next_pc.clone() - curr_pc.clone() - four.clone()),
        );

        // BLT: branch_taken linked to comparison via op_aux
        let is_blt = opcode_sel!(0x1B, curr, AB);
        builder.assert_zero(
            not_final.clone()
                * is_blt.clone()
                * (branch_taken.clone()
                    * (op_b.clone() - op_a.clone() - AB::Expr::one() - op_aux.clone())
                    + (AB::Expr::one() - branch_taken.clone())
                        * (op_a.clone() - op_b.clone() - op_aux.clone())),
        );
        builder.assert_zero(
            not_final.clone()
                * is_blt
                * (AB::Expr::one() - branch_taken.clone())
                * (next_pc.clone() - curr_pc.clone() - four.clone()),
        );

        // BGE: branch_taken linked to comparison via op_aux
        let is_bge = opcode_sel!(0x1C, curr, AB);
        builder.assert_zero(
            not_final.clone()
                * is_bge.clone()
                * (branch_taken.clone() * (op_a.clone() - op_b.clone() - op_aux.clone())
                    + (AB::Expr::one() - branch_taken.clone())
                        * (op_b.clone() - op_a.clone() - AB::Expr::one() - op_aux.clone())),
        );
        builder.assert_zero(
            not_final.clone()
                * is_bge
                * (AB::Expr::one() - branch_taken.clone())
                * (next_pc.clone() - curr_pc.clone() - four),
        );

        // HALT/REVERT/SELFDESTRUCT → is_final
        builder.assert_zero(opcode_sel!(0x2C, curr, AB) * (AB::Expr::one() - is_final.clone()));
        builder.assert_zero(opcode_sel!(0x2B, curr, AB) * (AB::Expr::one() - is_final.clone()));
        builder.assert_zero(opcode_sel!(0x29, curr, AB) * (AB::Expr::one() - is_final.clone()));

        // ========== Call/Ret ==========
        let call_depth: AB::Expr = curr(col::CALL_DEPTH).into();
        let next_depth: AB::Expr = next(col::CALL_DEPTH).into();
        let is_call_like =
            opcode_sel!(0x1D, curr, AB) + opcode_sel!(0x26, curr, AB) + opcode_sel!(0x27, curr, AB);
        builder.assert_zero(
            not_final.clone()
                * is_call_like.clone()
                * (next_depth.clone() - call_depth.clone() - AB::Expr::one()),
        );
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(0x1E, curr, AB)
                * (next_depth.clone() - call_depth.clone() + AB::Expr::one()),
        );
        let is_call_or_ret = is_call_like + opcode_sel!(0x1E, curr, AB);
        builder.assert_zero(
            not_final.clone() * (AB::Expr::one() - is_call_or_ret) * (next_depth - call_depth),
        );

        // ASSERT
        builder.assert_zero(
            opcode_sel!(0x38, curr, AB) * (op_a * diff_inv - AB::Expr::one() + is_final),
        );

        // WADD/WSUB carry booleans
        let is_wadd = opcode_sel!(0x09, curr, AB);
        let is_wsub = opcode_sel!(0x0A, curr, AB);
        for i in 0..4 {
            let carry: AB::Expr = curr(col::wide_carry(i)).into();
            builder
                .assert_zero(is_wadd.clone() * carry.clone() * (AB::Expr::one() - carry.clone()));
            builder.assert_zero(is_wsub.clone() * carry.clone() * (AB::Expr::one() - carry));
        }
    }
}
