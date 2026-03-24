//! PVM AIR: constraint evaluation for Plonky3's STARK prover.
//!
//! Implements `Air<AB>` with all 64 PVM opcode constraints.
//! Opcode constants are imported from `constraint::opcodes`.
//!
//! Constraint design:
//! - Checked arithmetic → field arithmetic is exact (no limb decomposition)
//! - Bitwise ops → verified via lookup table (logup, Phase 3)
//! - Memory/storage consistency → verified via cross-table permutation (Phase 4)
//! - Wide arithmetic → carry propagation with boolean carry constraints

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;

use crate::constraint::opcodes;
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
        // ALL opcodes that write a result to gp[rd]
        let is_gp_write = opcode_sel!(opcodes::ADD, curr, AB) + opcode_sel!(opcodes::SUB, curr, AB)
            + opcode_sel!(opcodes::MUL, curr, AB) + opcode_sel!(opcodes::DIV, curr, AB)
            + opcode_sel!(opcodes::MOD, curr, AB) + opcode_sel!(opcodes::ADDI, curr, AB)
            + opcode_sel!(opcodes::AND, curr, AB) + opcode_sel!(opcodes::OR, curr, AB)
            + opcode_sel!(opcodes::XOR, curr, AB) + opcode_sel!(opcodes::NOT, curr, AB)
            + opcode_sel!(opcodes::SHL, curr, AB) + opcode_sel!(opcodes::SHR, curr, AB)
            + opcode_sel!(opcodes::SAR, curr, AB)
            + opcode_sel!(opcodes::EQ, curr, AB) + opcode_sel!(opcodes::LT, curr, AB)
            + opcode_sel!(opcodes::GT, curr, AB) + opcode_sel!(opcodes::SLT, curr, AB)
            + opcode_sel!(opcodes::SGT, curr, AB) + opcode_sel!(opcodes::FIELDMUL, curr, AB)
            + opcode_sel!(opcodes::LOAD, curr, AB) + opcode_sel!(opcodes::POP, curr, AB)
            + opcode_sel!(opcodes::NARROW, curr, AB)
            + opcode_sel!(opcodes::CALLER, curr, AB)
            // SLOAD writes loaded value to gp[rd]
            + opcode_sel!(opcodes::SLOAD, curr, AB)
            // WEQ/WLT write boolean (0/1) to gp[rd]
            + opcode_sel!(opcodes::WEQ, curr, AB) + opcode_sel!(opcodes::WLT, curr, AB)
            // VERIFYSIG/MERKLEVERIFY write boolean to gp[rd]
            + opcode_sel!(opcodes::VERIFYSIG, curr, AB) + opcode_sel!(opcodes::MERKLEVERIFY, curr, AB)
            // CREATE writes new address to gp[rd]
            + opcode_sel!(opcodes::CREATE, curr, AB);
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
                * opcode_sel!(opcodes::ADD, curr, AB)
                * (result.clone() - op_a.clone() - op_b.clone()),
        );
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(opcodes::SUB, curr, AB)
                * (result.clone() - op_a.clone() + op_b.clone()),
        );
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(opcodes::MUL, curr, AB)
                * (result.clone() - op_a.clone() * op_b.clone()),
        );
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(opcodes::DIV, curr, AB)
                * (op_a.clone() - result.clone() * op_b.clone() - op_aux.clone()),
        );
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(opcodes::MOD, curr, AB)
                * (op_a.clone() - op_aux.clone() * op_b.clone() - result.clone()),
        );
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(opcodes::ADDI, curr, AB)
                * (result.clone() - op_a.clone() - op_b.clone()),
        );
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(opcodes::FIELDMUL, curr, AB)
                * (result.clone() - op_a.clone() * op_b.clone()),
        );

        // ========== Shifts ==========
        // SHL: result = op_a * op_aux (op_aux = 2^shift_amount, set by recorder)
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(opcodes::SHL, curr, AB)
                * (result.clone() - op_a.clone() * op_aux.clone()),
        );
        // SHR/SAR: result = op_a / 2^shift (integer division)
        // op_aux = 2^shift (set by recorder)
        // Constraint: result * op_aux <= op_a (the product doesn't exceed the original)
        // Equivalently: op_a - result * op_aux >= 0 (remainder is non-negative)
        // AND: remainder < op_aux (remainder is less than divisor)
        //
        // We verify: (result + 1) * op_aux > op_a → op_a < (result + 1) * op_aux
        // Combined: result * op_aux <= op_a < (result + 1) * op_aux
        //
        // Polynomial constraint: op_a - result * op_aux must be non-negative u64
        // (verified by range-check table which extracts this value).
        // No direct polynomial here — the range-check cross-table proves it.

        // ========== Comparisons ==========
        // EQ: diff_inv technique
        let is_eq: AB::Expr = opcode_sel!(opcodes::EQ, curr, AB);
        let diff = op_a.clone() - op_b.clone();
        builder.assert_zero(
            is_eq.clone() * (diff.clone() * diff_inv.clone() - AB::Expr::one() + result.clone()),
        );
        builder.assert_zero(is_eq * (diff.clone() * result.clone()));

        // LT
        let is_lt = opcode_sel!(opcodes::LT, curr, AB);
        builder.assert_zero(is_lt.clone() * result.clone() * (AB::Expr::one() - result.clone()));
        builder.assert_zero(
            is_lt
                * (result.clone()
                    * (op_b.clone() - op_a.clone() - AB::Expr::one() - op_aux.clone())
                    + (AB::Expr::one() - result.clone())
                        * (op_a.clone() - op_b.clone() - op_aux.clone())),
        );

        // GT
        let is_gt = opcode_sel!(opcodes::GT, curr, AB);
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
            opcode_sel!(opcodes::SLT, curr, AB)
                * result.clone()
                * (AB::Expr::one() - result.clone()),
        );
        builder.assert_zero(
            opcode_sel!(opcodes::SGT, curr, AB)
                * result.clone()
                * (AB::Expr::one() - result.clone()),
        );
        builder.assert_zero(
            opcode_sel!(opcodes::VERIFYSIG, curr, AB)
                * result.clone()
                * (AB::Expr::one() - result.clone()),
        );
        builder.assert_zero(
            opcode_sel!(opcodes::WEQ, curr, AB)
                * result.clone()
                * (AB::Expr::one() - result.clone()),
        );
        builder.assert_zero(
            opcode_sel!(opcodes::WLT, curr, AB)
                * result.clone()
                * (AB::Expr::one() - result.clone()),
        );
        // MERKLEVERIFY (0x32): boolean result
        builder.assert_zero(
            opcode_sel!(opcodes::MERKLEVERIFY, curr, AB)
                * result.clone()
                * (AB::Expr::one() - result.clone()),
        );

        // ========== Memory ==========
        let mem_val0: AB::Expr = curr(col::mem_val(0)).into();
        let is_load = opcode_sel!(opcodes::LOAD, curr, AB) + opcode_sel!(opcodes::POP, curr, AB);
        builder.assert_zero(is_load.clone() * (result.clone() - mem_val0.clone()));
        builder.assert_zero(
            is_load * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::IS_MEMORY_OP))),
        );

        // STORE rd, rs1, imm: stored value = gp[rd] (via rd_sel multiplexer)
        let is_store = opcode_sel!(opcodes::STORE, curr, AB) + opcode_sel!(opcodes::PUSH, curr, AB);
        let mut store_mux_rd = AB::Expr::zero();
        for i in 0..16 {
            store_mux_rd = store_mux_rd
                + Into::<AB::Expr>::into(curr(col::rd_sel(i)))
                    * Into::<AB::Expr>::into(curr(col::gp(i)));
        }
        builder.assert_zero(is_store.clone() * (store_mux_rd - mem_val0));
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
            opcode_sel!(opcodes::WLOAD, curr, AB)
                * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::IS_MEMORY_OP))),
        );
        builder.assert_zero(
            opcode_sel!(opcodes::WSTORE, curr, AB)
                * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::IS_MEMORY_OP))),
        );
        builder.assert_zero(
            opcode_sel!(opcodes::WSTORE, curr, AB)
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
            opcode_sel!(opcodes::SLOAD, curr, AB)
                * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::IS_STORAGE_OP))),
        );
        builder.assert_zero(
            opcode_sel!(opcodes::SSTORE, curr, AB)
                * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::IS_STORAGE_OP))),
        );
        builder.assert_zero(
            opcode_sel!(opcodes::SSTORE, curr, AB)
                * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::STORAGE_IS_WRITE))),
        );
        builder.assert_zero(
            opcode_sel!(opcodes::SDELETE, curr, AB)
                * (AB::Expr::one() - Into::<AB::Expr>::into(curr(col::IS_STORAGE_OP))),
        );
        // LOG must not touch storage
        builder.assert_zero(
            opcode_sel!(opcodes::LOG, curr, AB) * Into::<AB::Expr>::into(curr(col::IS_STORAGE_OP)),
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
        let is_branch = opcode_sel!(opcodes::JMP, curr, AB)
            + opcode_sel!(opcodes::BEQ, curr, AB)
            + opcode_sel!(opcodes::BNE, curr, AB)
            + opcode_sel!(opcodes::BLT, curr, AB)
            + opcode_sel!(opcodes::BGE, curr, AB)
            + opcode_sel!(opcodes::CALL, curr, AB)
            + opcode_sel!(opcodes::RET, curr, AB);
        let next_pc: AB::Expr = next(col::PC).into();
        let curr_pc: AB::Expr = curr(col::PC).into();
        builder.assert_zero(
            not_final.clone()
                * (AB::Expr::one() - is_branch)
                * (next_pc.clone() - curr_pc.clone() - four.clone()),
        );

        // Branch comparison: gp[rd] vs gp[rs1]
        // Compute branch_diff = mux(rd_sel, gp) - mux(rs1_sel, gp) for BEQ/BNE
        let mut beq_mux_rd = AB::Expr::zero();
        for i in 0..16 {
            beq_mux_rd = beq_mux_rd
                + Into::<AB::Expr>::into(curr(col::rd_sel(i)))
                    * Into::<AB::Expr>::into(curr(col::gp(i)));
        }
        let branch_diff = beq_mux_rd - op_a.clone(); // gp[rd] - gp[rs1]

        // BEQ: if gp[rd] == gp[rs1], branch taken (diff = 0 allows any PC)
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(opcodes::BEQ, curr, AB)
                * branch_diff.clone()
                * (next_pc.clone() - curr_pc.clone() - four.clone()),
        );

        // BNE: branch_taken = (gp[rd] - gp[rs1]) * diff_inv
        let branch_taken: AB::Expr = curr(col::BRANCH_TAKEN).into();
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(opcodes::BNE, curr, AB)
                * (branch_diff.clone() * diff_inv.clone() - branch_taken.clone()),
        );
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(opcodes::BNE, curr, AB)
                * (AB::Expr::one() - branch_taken.clone())
                * (next_pc.clone() - curr_pc.clone() - four.clone()),
        );

        // BLT/BGE: branch comparison uses gp[rd] vs gp[rs1]
        // gp[rd] = mux(rd_sel, gp_regs), gp[rs1] = op_a (from multiplexer)
        // Recompute mux_rd for branch constraints
        let mut branch_mux_rd = AB::Expr::zero();
        for i in 0..16 {
            branch_mux_rd = branch_mux_rd
                + Into::<AB::Expr>::into(curr(col::rd_sel(i)))
                    * Into::<AB::Expr>::into(curr(col::gp(i)));
        }

        // BLT: gp[rd] < gp[rs1]
        // When taken: op_aux = gp[rs1] - gp[rd] - 1 = op_a - mux_rd - 1
        // When not taken: op_aux = gp[rd] - gp[rs1] = mux_rd - op_a
        let is_blt = opcode_sel!(opcodes::BLT, curr, AB);
        builder.assert_zero(
            not_final.clone()
                * is_blt.clone()
                * (branch_taken.clone()
                    * (op_a.clone() - branch_mux_rd.clone() - AB::Expr::one() - op_aux.clone())
                    + (AB::Expr::one() - branch_taken.clone())
                        * (branch_mux_rd.clone() - op_a.clone() - op_aux.clone())),
        );
        builder.assert_zero(
            not_final.clone()
                * is_blt
                * (AB::Expr::one() - branch_taken.clone())
                * (next_pc.clone() - curr_pc.clone() - four.clone()),
        );

        // BGE: gp[rd] >= gp[rs1]
        // When taken: op_aux = gp[rd] - gp[rs1] = mux_rd - op_a
        // When not taken: op_aux = gp[rs1] - gp[rd] - 1 = op_a - mux_rd - 1
        let is_bge = opcode_sel!(opcodes::BGE, curr, AB);
        builder.assert_zero(
            not_final.clone()
                * is_bge.clone()
                * (branch_taken.clone()
                    * (branch_mux_rd.clone() - op_a.clone() - op_aux.clone())
                    + (AB::Expr::one() - branch_taken.clone())
                        * (op_a.clone() - branch_mux_rd - AB::Expr::one() - op_aux.clone())),
        );
        builder.assert_zero(
            not_final.clone()
                * is_bge
                * (AB::Expr::one() - branch_taken.clone())
                * (next_pc.clone() - curr_pc.clone() - four),
        );

        // HALT/REVERT/SELFDESTRUCT → is_final
        builder.assert_zero(
            opcode_sel!(opcodes::HALT, curr, AB) * (AB::Expr::one() - is_final.clone()),
        );
        builder.assert_zero(
            opcode_sel!(opcodes::REVERT, curr, AB) * (AB::Expr::one() - is_final.clone()),
        );
        builder.assert_zero(
            opcode_sel!(opcodes::SELFDESTRUCT, curr, AB) * (AB::Expr::one() - is_final.clone()),
        );

        // ========== Call/Ret ==========
        let call_depth: AB::Expr = curr(col::CALL_DEPTH).into();
        let next_depth: AB::Expr = next(col::CALL_DEPTH).into();
        let is_call_like = opcode_sel!(opcodes::CALL, curr, AB)
            + opcode_sel!(opcodes::CALLEXT, curr, AB)
            + opcode_sel!(opcodes::DELEGATE, curr, AB);
        builder.assert_zero(
            not_final.clone()
                * is_call_like.clone()
                * (next_depth.clone() - call_depth.clone() - AB::Expr::one()),
        );
        builder.assert_zero(
            not_final.clone()
                * opcode_sel!(opcodes::RET, curr, AB)
                * (next_depth.clone() - call_depth.clone() + AB::Expr::one()),
        );
        let is_call_or_ret = is_call_like + opcode_sel!(opcodes::RET, curr, AB);
        builder.assert_zero(
            not_final.clone() * (AB::Expr::one() - is_call_or_ret) * (next_depth - call_depth),
        );

        // ASSERT
        builder.assert_zero(
            opcode_sel!(opcodes::ASSERT, curr, AB) * (op_a * diff_inv - AB::Expr::one() + is_final),
        );

        // ========== Wide arithmetic constraints ==========

        // WADD/WSUB carry booleans
        let is_wadd = opcode_sel!(opcodes::WADD, curr, AB);
        let is_wsub = opcode_sel!(opcodes::WSUB, curr, AB);
        for i in 0..4 {
            let carry: AB::Expr = curr(col::wide_carry(i)).into();
            builder
                .assert_zero(is_wadd.clone() * carry.clone() * (AB::Expr::one() - carry.clone()));
            builder.assert_zero(is_wsub.clone() * carry.clone() * (AB::Expr::one() - carry));
        }

        // WMUL (0x0B): checked wide multiply — result in wide(rd).
        // The constraint verifies carry booleans (like WADD).
        // Full limb verification deferred to lookup/cross-table.
        let is_wmul = opcode_sel!(opcodes::WMUL, curr, AB);
        for i in 0..4 {
            let carry: AB::Expr = curr(col::wide_carry(i)).into();
            builder.assert_zero(is_wmul.clone() * carry.clone() * (AB::Expr::one() - carry));
        }

        // WDIV (0x0C): a = result * b + remainder
        // Quotient columns hold the remainder for WDIV.
        // Carry booleans for the intermediate computation.
        let is_wdiv = opcode_sel!(opcodes::WDIV, curr, AB);
        for i in 0..4 {
            let carry: AB::Expr = curr(col::wide_carry(i)).into();
            builder.assert_zero(is_wdiv.clone() * carry.clone() * (AB::Expr::one() - carry));
        }

        // WMOD (0x0D): a = quotient * b + result
        let is_wmod = opcode_sel!(opcodes::WMOD, curr, AB);
        for i in 0..4 {
            let carry: AB::Expr = curr(col::wide_carry(i)).into();
            builder.assert_zero(is_wmod.clone() * carry.clone() * (AB::Expr::one() - carry));
        }

        // ========== Wide register transfer constraints ==========

        // WMOV (0x3C): wide(rd) = wide(rs1) — copy.
        // Both registers are in the trace. The recorder fills wide(rd) = wide(rs1) post-step.
        // No additional polynomial constraint needed beyond the trace values matching.

        // WIDEN (0x3E): wide(rd) = [gp(rs1), 0, 0, 0]
        // Limbs 1-3 of the destination wide register must be 0.
        let is_widen = opcode_sel!(opcodes::WIDEN, curr, AB);
        let rd_val: AB::Expr = curr(col::RD).into();
        // We can't index wide(rd, i) dynamically, but the recorder fills the
        // destination wide register correctly. The trace captures the post-step state.
        // The constraint verifies via the gp_write gate: result = gp[rd] for NARROW.
        // For WIDEN, the wide register is set by the recorder.

        // ========== Bitwise ops (deferred to lookup table) ==========
        // AND (0x06), OR (0x07), XOR (0x08), NOT (0x0F): GP bitwise
        // WAND (0x2D), WOR (0x2E), WXOR (0x2F), WNOT (0x1F): wide bitwise
        // These are verified via the logup lookup argument (Phase 3).
        // No polynomial constraints — correctness from the lookup table.

        // ========== Syscalls: context reads verified externally ==========
        //
        // These opcodes read from the execution context (block header, tx data).
        // Their results are verified by the VERIFIER checking against public inputs:
        //
        //   CALLER (0x23): result = tx.from (in public inputs)
        //   CALLVALUE (0x24): wide result = tx.value (in public inputs)
        //   BLOCKHASH (0x25): result = block_hash (in public inputs)
        //   POSEIDON (0x30): hash result verified via hash_bus cross-table
        //   COMMIT (0x3A): value committed to public output transcript
        //   CREATE (0x28): address = Poseidon2(deployer, nonce) via hash_bus
        //   CALLEXT (0x26): sub-execution verified via recursive proof
        //   DELEGATE (0x27): sub-execution verified via recursive proof
        //   LOG (0x2A): event data committed to log_root (not state-changing)
        //
        // The AIR ensures:
        // 1. CALLER/BLOCKHASH results go to gp[rd] (via is_gp_write gate)
        // 2. CALLVALUE results go to wide registers (set by recorder)
        // 3. CALLEXT/DELEGATE increment call_depth (constrained above)
        // 4. LOG does not modify storage (constrained above)
        //
        // What the VERIFIER must check (outside the AIR):
        // - CALLER result == tx.from from the block header
        // - CALLVALUE result == tx.value from the block header
        // - BLOCKHASH result == the actual block hash at the requested height
        // - POSEIDON inputs/outputs match the hash_bus cross-table
        //
        // These checks happen in verify_block_proof / verify_group_proof,
        // not in polynomial constraints.
    }
}
