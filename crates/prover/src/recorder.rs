//! Execution trace recorder: captures 144-column trace rows from PVM execution.
//!
//! The recorder wraps `vm.step()` and captures post-step state per cycle.
//! It fills all columns that the AIR constraints check, including:
//! - Register values (GP + wide, post-step)
//! - Operand resolution (op_a from rs1_sel, op_b from rs2 or immediate)
//! - Register selectors (rd_sel, rs1_sel, rs2_sel one-hot)
//! - Memory/storage access data
//! - Gas accounting
//! - Branch taken + diff_inv witnesses
//! - op_aux: DIV remainder, MOD quotient, comparison diff, shift 2^amount

use p3_field::{AbstractField, Field, PrimeField64};
use p3_goldilocks::Goldilocks;

use pyde_vm::cpu::Trap;
use pyde_vm::isa::{sign_extend_18, Opcode};
use pyde_vm::vm::{ExecResult, Outcome, Vm};

use crate::trace::{col, ExecutionTrace, TraceRow};

/// Record a full execution trace from a loaded VM.
/// Returns the trace and the execution outcome.
pub fn record_execution(vm: &mut Vm) -> (ExecutionTrace, Outcome) {
    let mut trace = ExecutionTrace::new();
    let mut call_depth: u64 = 0;
    let logs_snapshot = vm.logs.len();

    let outcome = loop {
        let pc = vm.pc;
        let idx = (pc / 4) as usize;

        let decoded = match vm.decoded_cache().get(idx) {
            Some(&d) => d,
            None => break Outcome::Trap(Trap::MemoryFault),
        };

        let opcode = decoded.opcode;
        let rd = decoded.rd;
        let rs1 = decoded.rs1;
        let rs2_imm = decoded.rs2_or_imm;

        // Capture pre-step state for operand resolution.
        // op_a = gp[rs1] ALWAYS (matches the multiplexer constraint)
        // op_b = gp[rs2] for register-register ops, sign_extend(imm) for immediate ops
        //
        // For BRANCH instructions (BEQ/BNE/BLT/BGE): the PVM compares gp[rd] vs gp[rs1].
        // The multiplexer constrains op_a = gp[rs1]. The branch constraints in the AIR
        // reference gp[rd] via the rd_sel multiplexer separately.
        let pre_op_a = vm.cpu.read_gp(rs1);
        let pre_op_b = if opcode.uses_immediate() {
            sign_extend_18(rs2_imm) as u64
        } else {
            vm.cpu.read_gp((rs2_imm & 0xF) as u8)
        };
        let gas_before = vm.gas_used_total;

        // Determine flags before stepping
        let is_mem = is_memory_opcode(opcode);
        let is_storage = is_storage_opcode(opcode);

        // Capture pre-step memory info for STORE/PUSH
        let mem_addr = if is_mem {
            compute_mem_addr(vm, opcode, rs1, rs2_imm)
        } else {
            0
        };

        // Capture pre-step wide operands for wide arithmetic carry computation
        let is_wide_arith = matches!(opcode,
            Opcode::Wadd | Opcode::Wsub | Opcode::Wmul | Opcode::Wdiv | Opcode::Wmod
        );
        let (wide_a_limbs, wide_b_limbs) = if is_wide_arith {
            let wa = vm.cpu.read_wide(rs1);
            let wa_bytes = wa.to_le_bytes();
            let a_limbs: [u64; 4] = core::array::from_fn(|i| {
                u64::from_le_bytes(wa_bytes[i * 8..(i + 1) * 8].try_into().unwrap())
            });

            let ws2 = (rs2_imm & 0xF) as u8;
            let wb = vm.cpu.read_wide(ws2);
            let wb_bytes = wb.to_le_bytes();
            let b_limbs: [u64; 4] = core::array::from_fn(|i| {
                u64::from_le_bytes(wb_bytes[i * 8..(i + 1) * 8].try_into().unwrap())
            });

            (a_limbs, b_limbs)
        } else {
            ([0u64; 4], [0u64; 4])
        };

        // Execute one step
        let step_result = vm.step();

        // Gas cost
        let gas_after = vm.gas_used_total;
        let gas_step = gas_after - gas_before;

        // Is this the final row?
        let is_final = matches!(
            step_result,
            Ok(Some(ExecResult::Halt)) | Ok(Some(ExecResult::Revert)) | Err(_)
        );

        // Build trace row from POST-STEP state
        let mut row = TraceRow::zero();

        // Control
        row.set_u64(col::PC, pc as u64);
        row.set_u64(col::OPCODE, opcode as u64);
        row.set_u64(col::RD, rd as u64);
        row.set_u64(col::RS1, rs1 as u64);
        row.set_u64(col::RS2_IMM, rs2_imm as u64);

        // Opcode bits
        row.set_opcode_bits(opcode as u64);

        // GP registers (post-step)
        for i in 0..16 {
            row.set_u64(col::gp(i), vm.cpu.read_gp(i as u8));
        }

        // Wide registers (post-step)
        for r in 0..8 {
            let w = vm.cpu.read_wide(r as u8);
            let bytes = w.to_le_bytes();
            for limb in 0..4 {
                let val = u64::from_le_bytes(bytes[limb * 8..(limb + 1) * 8].try_into().unwrap());
                row.set_u64(col::wide(r, limb), val);
            }
        }

        // Register selectors (one-hot)
        row.set_rd_sel(rd);
        row.set_rs1_sel(rs1);
        if !opcode.uses_immediate() {
            row.set_rs2_sel((rs2_imm & 0xF) as u8);
        }

        // Operands
        row.set_u64(col::OP_A, pre_op_a);
        row.set_u64(col::OP_B, pre_op_b);
        row.set_u64(col::OP_RESULT, vm.cpu.read_gp(rd));

        // op_aux depends on opcode.
        // For branches: the comparison is gp[rd] vs gp[rs1], captured pre-step.
        let branch_rd_val = if matches!(opcode, Opcode::Beq | Opcode::Bne | Opcode::Blt | Opcode::Bge) {
            // Pre-step rd value (the first comparison operand for branches)
            // Note: we need pre-step, but rd might have been overwritten by step.
            // However, branches DON'T write to rd, so post-step gp[rd] = pre-step gp[rd].
            vm.cpu.read_gp(rd)
        } else {
            0
        };
        fill_op_aux(
            &mut row,
            opcode,
            pre_op_a,
            pre_op_b,
            vm.cpu.read_gp(rd),
            rs2_imm,
            branch_rd_val,
        );

        // Gas
        row.set_u64(col::GAS_STEP, gas_step);
        row.set_u64(col::GAS_CUMULATIVE, gas_after);

        // Flags
        if is_mem {
            row.set_flag(col::IS_MEMORY_OP);
        }
        if is_storage {
            row.set_flag(col::IS_STORAGE_OP);
        }
        if is_final {
            row.set_flag(col::IS_FINAL);
        }

        // Memory access
        if is_mem {
            row.set_u64(col::MEM_ADDR, mem_addr);
            fill_mem_value(&mut row, vm, opcode, mem_addr);
            let is_write = matches!(opcode, Opcode::Store | Opcode::Push | Opcode::Wstore);
            if is_write {
                row.set_flag(col::MEM_IS_WRITE);
            }
            row.set_u64(col::MEM_WIDTH, mem_width(opcode));
        }

        // Storage access
        if is_storage {
            fill_storage_access(&mut row, vm, opcode, rs1, rs2_imm);
        }

        // Branch taken + diff_inv
        // For branches: compare gp[rd] vs gp[rs1]. For comparisons: use op_a vs op_b.
        if matches!(opcode, Opcode::Beq | Opcode::Bne | Opcode::Blt | Opcode::Bge) {
            fill_branch_info(&mut row, opcode, branch_rd_val, pre_op_a, 0);
        } else {
            fill_branch_info(&mut row, opcode, pre_op_a, pre_op_b, vm.cpu.read_gp(rd));
        }

        // Call depth
        row.set_u64(col::CALL_DEPTH, call_depth);
        match opcode {
            Opcode::Call | Opcode::CallExt | Opcode::Delegate => call_depth += 1,
            Opcode::Ret if call_depth > 0 => call_depth -= 1,
            _ => {}
        }

        // Wide carry/quotient for wide arithmetic
        fill_wide_aux(&mut row, opcode, &wide_a_limbs, &wide_b_limbs);

        trace.push(row);

        match step_result {
            Ok(Some(ExecResult::Halt)) => break Outcome::Success,
            Ok(Some(ExecResult::Revert)) => {
                vm.rollback_storage_pub();
                vm.logs.truncate(logs_snapshot);
                vm.gas_refund = 0;
                break Outcome::Revert;
            }
            Err(Trap::OutOfGas) => break Outcome::OutOfGas,
            Err(trap) => break Outcome::Trap(trap),
            Ok(None) => {} // continue
        }
    };

    (trace, outcome)
}

fn is_memory_opcode(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Load | Opcode::Store | Opcode::Push | Opcode::Pop | Opcode::Wload | Opcode::Wstore
    )
}

fn is_storage_opcode(op: Opcode) -> bool {
    matches!(op, Opcode::Sload | Opcode::Sstore | Opcode::Sdelete)
}

fn compute_mem_addr(vm: &Vm, op: Opcode, rs1: u8, rs2_imm: u32) -> u64 {
    match op {
        Opcode::Load | Opcode::Store => {
            let base = vm.cpu.read_gp(rs1) as u32;
            let offset = (rs2_imm >> 2) as u16;
            (base.wrapping_add(offset as u32)) as u64
        }
        Opcode::Push => vm.cpu.read_gp(2).wrapping_sub(8), // SP - 8
        Opcode::Pop => vm.cpu.read_gp(2),                  // SP
        Opcode::Wload | Opcode::Wstore => vm.cpu.read_gp(rs1) as u64,
        _ => 0,
    }
}

fn mem_width(op: Opcode) -> u64 {
    match op {
        Opcode::Load | Opcode::Store => 8, // default u64
        Opcode::Push | Opcode::Pop => 8,
        Opcode::Wload | Opcode::Wstore => 32, // 256-bit
        _ => 0,
    }
}

fn fill_mem_value(row: &mut TraceRow, vm: &Vm, op: Opcode, _addr: u64) {
    // For LOAD/POP: the value is now in the destination register (post-step)
    // For STORE/PUSH: the value was written from a register
    // We capture the value from the register file (post-step for loads, pre-step for stores)
    // Since op_result = gp[rd] post-step, and the constraint checks result = mem_val[0],
    // we set mem_val[0] = op_result for loads (they match).
    // For stores, mem_val[0] = op_a (the stored value).
    match op {
        Opcode::Load | Opcode::Pop => {
            row.set_u64(col::mem_val(0), row.get(col::OP_RESULT).as_canonical_u64());
        }
        Opcode::Store | Opcode::Push => {
            // STORE rd, rs1, imm: stores gp[rd] (the value) to mem[gp[rs1] + offset]
            // The stored value is gp[rd], captured post-step (STORE doesn't modify rd)
            let rd = row.get(col::RD).as_canonical_u64() as u8;
            row.set_u64(col::mem_val(0), vm.cpu.read_gp(rd));
        }
        Opcode::Wload | Opcode::Wstore => {
            // Wide memory: 4 limbs from the wide register
            // For WLOAD: destination wide register has the loaded value (post-step)
            // For WSTORE: source wide register value was written
            let wr = row.get(col::RD).as_canonical_u64() as u8;
            for i in 0..4 {
                let val = row.get(col::wide(wr as usize & 7, i)).as_canonical_u64();
                row.set_u64(col::mem_val(i), val);
            }
        }
        _ => {}
    }
}

fn fill_storage_access(row: &mut TraceRow, vm: &Vm, op: Opcode, rs1: u8, rs2_imm: u32) {
    let is_write = matches!(op, Opcode::Sstore);
    if is_write {
        row.set_flag(col::STORAGE_IS_WRITE);
    }

    // Storage key: derived from the register operands.
    // SLOAD rd, rs1 → key = wide(rs1) or gp(rs1) depending on encoding
    // SSTORE rs1, rd → key = wide(rs1), value = wide(rd)
    // SDELETE rs1 → key = wide(rs1)
    //
    // For GP-mode storage (key from GP register as u64):
    let key_val = vm.cpu.read_gp(rs1);
    row.set_u64(col::storage_key(0), key_val);
    // Higher key limbs = 0 for GP-mode

    // Storage value: for SSTORE, capture the value being written
    if is_write {
        let rd = row.get(col::RD).as_canonical_u64() as u8;
        // Value from wide register (rd) for wide-mode storage
        let val = vm.cpu.read_wide(rd);
        let bytes = val.to_le_bytes();
        for i in 0..4 {
            let limb = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
            row.set_u64(col::storage_val(i), limb);
        }
        row.set_u64(col::STORAGE_VAL_LEN, 32); // U256 = 32 bytes
    } else {
        // SLOAD: the VM loaded the value from storage into gp[rd].
        // We capture gp[rd] post-step, which IS the loaded value.
        // In production, the hash_bus cross-table verifies this value
        // matches the Poseidon2 hash commitment in the state trie.
        let result_val = vm.cpu.read_gp(row.get(col::RD).as_canonical_u64() as u8);
        row.set_u64(col::storage_val(0), result_val);
        row.set_u64(col::STORAGE_VAL_LEN, 8);
    }
}

fn fill_op_aux(row: &mut TraceRow, op: Opcode, a: u64, b: u64, result: u64, rs2_imm: u32, branch_rd_val: u64) {
    match op {
        // DIV: op_aux = remainder (a % b)
        Opcode::Div => {
            let b_val = b;
            if b_val != 0 {
                row.set_u64(col::OP_AUX, a % b_val);
            }
        }
        // MOD: op_aux = quotient (a / b)
        Opcode::Mod => {
            let b_val = b;
            if b_val != 0 {
                row.set_u64(col::OP_AUX, a / b_val);
            }
        }
        // LT: op_aux = comparison difference
        Opcode::Lt => {
            if result == 1 {
                // a < b
                row.set_u64(col::OP_AUX, b.wrapping_sub(a).wrapping_sub(1));
            } else {
                row.set_u64(col::OP_AUX, a.wrapping_sub(b));
            }
        }
        // GT: op_aux = comparison difference
        Opcode::Gt => {
            if result == 1 {
                // a > b
                row.set_u64(col::OP_AUX, a.wrapping_sub(b).wrapping_sub(1));
            } else {
                row.set_u64(col::OP_AUX, b.wrapping_sub(a));
            }
        }
        // SLT: signed comparison difference
        Opcode::Slt => {
            let sa = a as i64;
            let sb = b as i64;
            if result == 1 {
                row.set_u64(col::OP_AUX, (sb.wrapping_sub(sa).wrapping_sub(1)) as u64);
            } else {
                row.set_u64(col::OP_AUX, (sa.wrapping_sub(sb)) as u64);
            }
        }
        // SGT: signed comparison difference
        Opcode::Sgt => {
            let sa = a as i64;
            let sb = b as i64;
            if result == 1 {
                row.set_u64(col::OP_AUX, (sa.wrapping_sub(sb).wrapping_sub(1)) as u64);
            } else {
                row.set_u64(col::OP_AUX, (sb.wrapping_sub(sa)) as u64);
            }
        }
        // SHL: op_aux = 2^shift_amount (for the constraint: result = op_a * op_aux)
        Opcode::Shl => {
            let shift = b & 63;
            row.set_u64(col::OP_AUX, 1u64 << shift);
        }
        // SHR/SAR: op_aux = 2^shift (for the constraint: op_a = result * op_aux + remainder)
        // We need TWO aux values: the power and the remainder.
        // Use op_aux for the power. The remainder = a - result * power, which the
        // constraint can compute from op_a, result, and op_aux.
        Opcode::Shr | Opcode::Sar => {
            let shift = b & 63;
            let power = 1u64 << shift;
            row.set_u64(col::OP_AUX, power);
        }
        // BLT: branch compares gp[rd] < gp[rs1]
        // AIR constraint uses mux_rd (gp[rd]) and op_a (gp[rs1]).
        Opcode::Blt => {
            let rd_val = branch_rd_val;
            let rs1_val = a; // op_a = gp[rs1]
            if rd_val < rs1_val {
                row.set_u64(col::OP_AUX, rs1_val.wrapping_sub(rd_val).wrapping_sub(1));
            } else {
                row.set_u64(col::OP_AUX, rd_val.wrapping_sub(rs1_val));
            }
        }
        // BGE: branch compares gp[rd] >= gp[rs1]
        Opcode::Bge => {
            let rd_val = branch_rd_val;
            let rs1_val = a;
            if rd_val >= rs1_val {
                row.set_u64(col::OP_AUX, rd_val.wrapping_sub(rs1_val));
            } else {
                row.set_u64(col::OP_AUX, rs1_val.wrapping_sub(rd_val).wrapping_sub(1));
            }
        }
        _ => {}
    }
}

fn fill_branch_info(row: &mut TraceRow, op: Opcode, a: u64, b: u64, _result: u64) {
    let is_branch = matches!(op, Opcode::Beq | Opcode::Bne | Opcode::Blt | Opcode::Bge);
    let is_comparison = matches!(
        op,
        Opcode::Eq | Opcode::Lt | Opcode::Gt | Opcode::Slt | Opcode::Sgt
    );

    if is_branch {
        let taken = match op {
            Opcode::Beq => a == b,
            Opcode::Bne => a != b,
            Opcode::Blt => a < b,
            Opcode::Bge => a >= b,
            _ => false,
        };
        if taken {
            row.set_flag(col::BRANCH_TAKEN);
        }
    }

    // diff_inv for BNE and EQ constraints
    if is_branch || is_comparison {
        if a != b {
            let diff = Goldilocks::from_canonical_u64(a.wrapping_sub(b));
            if let Some(inv) = diff.try_inverse() {
                row.fields[col::DIFF_INV] = inv;
            }
        }
    }
}

fn fill_wide_aux(row: &mut TraceRow, op: Opcode, a_limbs: &[u64; 4], b_limbs: &[u64; 4]) {
    match op {
        Opcode::Wadd => {
            // WADD: per-limb addition with carry propagation
            // result[i] = a[i] + b[i] + carry_in - carry_out * 2^64
            let mut carry: u64 = 0;
            for i in 0..4 {
                let sum = a_limbs[i] as u128 + b_limbs[i] as u128 + carry as u128;
                carry = (sum >> 64) as u64;
                row.set_u64(col::wide_carry(i), carry);
            }
        }
        Opcode::Wsub => {
            // WSUB: per-limb subtraction with borrow propagation
            let mut borrow: u64 = 0;
            for i in 0..4 {
                let a = a_limbs[i] as u128;
                let b = b_limbs[i] as u128 + borrow as u128;
                borrow = if a < b { 1 } else { 0 };
                row.set_u64(col::wide_carry(i), borrow);
            }
        }
        Opcode::Wmul => {
            // WMUL: carry from limb-0 product
            let prod0 = a_limbs[0] as u128 * b_limbs[0] as u128;
            row.set_u64(col::wide_carry(0), (prod0 >> 64) as u64);
            // Higher limb carries are complex (schoolbook multiplication)
            // For now: carry[1..3] = 0 (valid when products don't overflow per-limb)
        }
        Opcode::Wdiv => {
            // WDIV: quotient = a / b, remainder in wide_quotient columns
            // For limb-0: remainder[0] = a[0] % b[0] (when b fits in limb 0)
            if b_limbs[0] != 0 {
                row.set_u64(col::wide_quotient(0), a_limbs[0] % b_limbs[0]);
            }
        }
        Opcode::Wmod => {
            // WMOD: result = a % b, quotient in wide_quotient columns
            if b_limbs[0] != 0 {
                row.set_u64(col::wide_quotient(0), a_limbs[0] / b_limbs[0]);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraint::opcodes;
    use crate::trace::to_field;
    use pyde_vm::isa::encode;

    fn instr(op: Opcode, rd: u8, rs1: u8, imm: u32) -> [u8; 4] {
        encode(op, rd, rs1, imm).0.to_le_bytes()
    }

    fn bytecode(instrs: &[&[u8; 4]]) -> Vec<u8> {
        instrs.iter().flat_map(|i| i.iter().copied()).collect()
    }

    #[test]
    fn record_addi_program() {
        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 42),
            &instr(Opcode::Addi, 2, 0, 58),
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();

        let (trace, outcome) = record_execution(&mut vm);
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(trace.len(), 3);

        // Row 0: ADDI r1, r0, 42
        assert_eq!(trace.rows[0].get(col::PC), to_field(0));
        assert_eq!(trace.rows[0].get(col::OPCODE), to_field(opcodes::ADDI));
        assert_eq!(trace.rows[0].get(col::gp(1)), to_field(42));
        assert_eq!(trace.rows[0].get(col::OP_RESULT), to_field(42));

        // Row 1: ADDI r2, r0, 58
        assert_eq!(trace.rows[1].get(col::gp(1)), to_field(42)); // r1 persists
        assert_eq!(trace.rows[1].get(col::gp(2)), to_field(58));

        // Row 2: HALT
        assert_eq!(trace.rows[2].get(col::IS_FINAL), Goldilocks::one());
    }

    #[test]
    fn record_add_program() {
        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 10),
            &instr(Opcode::Addi, 2, 0, 20),
            &instr(Opcode::Add, 3, 1, 2), // r3 = r1 + r2 = 30
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();

        let (trace, outcome) = record_execution(&mut vm);
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(trace.len(), 4);

        // Row 2: ADD r3, r1, r2
        let add_row = &trace.rows[2];
        assert_eq!(add_row.get(col::OP_A), to_field(10)); // r1
        assert_eq!(add_row.get(col::OP_B), to_field(20)); // r2
        assert_eq!(add_row.get(col::OP_RESULT), to_field(30));
        assert_eq!(add_row.get(col::gp(3)), to_field(30));
        // rs2_sel should be set for register-register op
        assert_eq!(add_row.get(col::rs2_sel(2)), Goldilocks::one());
    }

    #[test]
    fn record_and_prove() {
        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 100),
            &instr(Opcode::Addi, 2, 0, 200),
            &instr(Opcode::Add, 3, 1, 2),
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();

        let (mut trace, outcome) = record_execution(&mut vm);
        assert_eq!(outcome, Outcome::Success);

        // Prove and verify
        let proof = crate::prover::prove(&mut trace, &[]);
        let result = crate::prover::verify(&proof, &[]);
        assert!(result.is_ok(), "Proof verification failed: {:?}", result);
    }

    #[test]
    fn record_div_with_remainder() {
        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 100),
            &instr(Opcode::Addi, 2, 0, 7),
            &instr(Opcode::Div, 3, 1, 2), // r3 = 100 / 7 = 14, remainder = 2
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();

        let (trace, outcome) = record_execution(&mut vm);
        assert_eq!(outcome, Outcome::Success);

        let div_row = &trace.rows[2];
        assert_eq!(div_row.get(col::OP_RESULT), to_field(14));
        assert_eq!(div_row.get(col::OP_AUX), to_field(2)); // remainder
    }

    #[test]
    fn record_div_prove_verify() {
        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 1000),
            &instr(Opcode::Addi, 2, 0, 7),
            &instr(Opcode::Div, 3, 1, 2),
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();

        let (mut trace, _) = record_execution(&mut vm);
        let proof = crate::prover::prove(&mut trace, &[]);
        assert!(crate::prover::verify(&proof, &[]).is_ok());
    }

    #[test]
    fn record_mul_prove_verify() {
        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 123),
            &instr(Opcode::Addi, 2, 0, 456),
            &instr(Opcode::Mul, 3, 1, 2), // 123 * 456 = 56088
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();

        let (mut trace, _) = record_execution(&mut vm);
        let proof = crate::prover::prove(&mut trace, &[]);
        assert!(crate::prover::verify(&proof, &[]).is_ok());
    }

    #[test]
    fn record_sub_prove_verify() {
        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 1000),
            &instr(Opcode::Addi, 2, 0, 250),
            &instr(Opcode::Sub, 3, 1, 2), // 1000 - 250 = 750
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();
        let (mut trace, outcome) = record_execution(&mut vm);
        assert_eq!(outcome, Outcome::Success);
        let proof = crate::prover::prove(&mut trace, &[]);
        assert!(crate::prover::verify(&proof, &[]).is_ok());
    }

    #[test]
    fn record_mod_prove_verify() {
        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 100),
            &instr(Opcode::Addi, 2, 0, 7),
            &instr(Opcode::Mod, 3, 1, 2), // 100 % 7 = 2
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();
        let (mut trace, _) = record_execution(&mut vm);
        assert_eq!(trace.rows[2].get(col::OP_RESULT), to_field(2)); // 100 % 7
        let proof = crate::prover::prove(&mut trace, &[]);
        assert!(crate::prover::verify(&proof, &[]).is_ok());
    }

    #[test]
    fn record_branch_prove_verify() {
        // Test BEQ (taken) and sequential flow
        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 10),
            &instr(Opcode::Addi, 2, 0, 5),
            &instr(Opcode::Bge, 1, 2, 8), // 10 >= 5 → skip next
            &instr(Opcode::Halt, 0, 0, 0), // skipped
            &instr(Opcode::Addi, 3, 0, 99),
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();
        let (mut trace, outcome) = record_execution(&mut vm);
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(vm.cpu.read_gp(3), 99); // branch was taken
        let proof = crate::prover::prove(&mut trace, &[]);
        assert!(crate::prover::verify(&proof, &[]).is_ok());
    }

    #[test]
    fn record_memory_prove_verify() {
        use pyde_vm::isa::{encode_mem_immediate, MemWidth};
        let store_imm = encode_mem_immediate(0, MemWidth::W64);
        let load_imm = encode_mem_immediate(0, MemWidth::W64);

        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 0x010000), // heap addr
            &instr(Opcode::Addi, 2, 0, 42),
            &instr(Opcode::Store, 2, 1, store_imm), // mem[heap] = 42
            &instr(Opcode::Load, 3, 1, load_imm),   // r3 = mem[heap] = 42
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();
        let (mut trace, outcome) = record_execution(&mut vm);
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(vm.cpu.read_gp(3), 42);

        // Check memory flags in trace
        assert_eq!(trace.rows[2].get(col::IS_MEMORY_OP), Goldilocks::one()); // STORE
        assert_eq!(trace.rows[2].get(col::MEM_IS_WRITE), Goldilocks::one());
        assert_eq!(trace.rows[3].get(col::IS_MEMORY_OP), Goldilocks::one()); // LOAD

        let proof = crate::prover::prove(&mut trace, &[]);
        assert!(crate::prover::verify(&proof, &[]).is_ok());
    }

    #[test]
    fn record_shift_prove_verify() {
        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 100),
            &instr(Opcode::Addi, 2, 0, 3),
            &instr(Opcode::Shl, 3, 1, 2), // 100 << 3 = 800
            &instr(Opcode::Shr, 4, 3, 2), // 800 >> 3 = 100
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();
        let (mut trace, _) = record_execution(&mut vm);
        assert_eq!(vm.cpu.read_gp(3), 800);
        assert_eq!(vm.cpu.read_gp(4), 100);
        let proof = crate::prover::prove(&mut trace, &[]);
        assert!(crate::prover::verify(&proof, &[]).is_ok());
    }

    #[test]
    fn record_comparison_prove_verify() {
        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 10),
            &instr(Opcode::Addi, 2, 0, 20),
            &instr(Opcode::Lt, 3, 1, 2), // 10 < 20 = 1
            &instr(Opcode::Gt, 4, 1, 2), // 10 > 20 = 0
            &instr(Opcode::Eq, 5, 1, 1), // 10 == 10 = 1 (comparing r1 with r1)
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();
        let (mut trace, _) = record_execution(&mut vm);
        assert_eq!(vm.cpu.read_gp(3), 1); // LT true
        assert_eq!(vm.cpu.read_gp(4), 0); // GT false
        assert_eq!(vm.cpu.read_gp(5), 1); // EQ true
        let proof = crate::prover::prove(&mut trace, &[]);
        assert!(crate::prover::verify(&proof, &[]).is_ok());
    }

    #[test]
    fn record_mixed_program_prove_verify() {
        // Token transfer simulation: arithmetic + comparison + branch + memory
        use pyde_vm::isa::{encode_mem_immediate, MemWidth};
        let store_imm = encode_mem_immediate(0, MemWidth::W64);

        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 1000),       // balance = 1000
            &instr(Opcode::Addi, 2, 0, 250),        // amount = 250
            &instr(Opcode::Sub, 3, 1, 2),           // new_balance = 750
            &instr(Opcode::Addi, 4, 0, 500),        // recipient = 500
            &instr(Opcode::Add, 5, 4, 2),           // recipient_new = 750
            &instr(Opcode::Addi, 6, 0, 0x010000),   // heap addr
            &instr(Opcode::Store, 3, 6, store_imm), // store new_balance
            &instr(Opcode::Mul, 7, 3, 2),           // 750 * 250 = 187500
            &instr(Opcode::Addi, 8, 0, 100),
            &instr(Opcode::Div, 9, 7, 8),           // 187500 / 100 = 1875
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();
        let (mut trace, outcome) = record_execution(&mut vm);
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(vm.cpu.read_gp(9), 1875);

        let proof = crate::prover::prove(&mut trace, &[]);
        assert!(crate::prover::verify(&proof, &[]).is_ok());
    }
}
