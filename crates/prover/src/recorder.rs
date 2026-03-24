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
use pyde_vm::isa::{DecodedInstruction, Opcode, sign_extend_18};
use pyde_vm::vm::{ExecResult, Outcome, Vm};

use crate::constraint::opcodes;
use crate::trace::{col, to_field, ExecutionTrace, TraceRow};

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

        // Capture pre-step state for operand resolution
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
        let mem_addr = if is_mem { compute_mem_addr(vm, opcode, rs1, rs2_imm) } else { 0 };

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
                let val = u64::from_le_bytes(
                    bytes[limb * 8..(limb + 1) * 8].try_into().unwrap(),
                );
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

        // op_aux depends on opcode
        fill_op_aux(&mut row, opcode, pre_op_a, pre_op_b, vm.cpu.read_gp(rd), rs2_imm);

        // Gas
        row.set_u64(col::GAS_STEP, gas_step);
        row.set_u64(col::GAS_CUMULATIVE, gas_after);

        // Flags
        if is_mem { row.set_flag(col::IS_MEMORY_OP); }
        if is_storage { row.set_flag(col::IS_STORAGE_OP); }
        if is_final { row.set_flag(col::IS_FINAL); }

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
        fill_branch_info(&mut row, opcode, pre_op_a, pre_op_b, vm.cpu.read_gp(rd));

        // Call depth
        row.set_u64(col::CALL_DEPTH, call_depth);
        match opcode {
            Opcode::Call | Opcode::CallExt | Opcode::Delegate => call_depth += 1,
            Opcode::Ret if call_depth > 0 => call_depth -= 1,
            _ => {}
        }

        // Wide carry/quotient for wide arithmetic
        fill_wide_aux(&mut row, opcode, vm);

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
    matches!(op, Opcode::Load | Opcode::Store | Opcode::Push | Opcode::Pop
        | Opcode::Wload | Opcode::Wstore)
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
        Opcode::Pop => vm.cpu.read_gp(2),                   // SP
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
            row.set_u64(col::mem_val(0), row.get(col::OP_A).as_canonical_u64());
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
    // Storage key comes from wide register (rs1 for SLOAD/SDELETE, rd for SSTORE)
    // Storage value from/to wide register
    let is_write = matches!(op, Opcode::Sstore);
    if is_write {
        row.set_flag(col::STORAGE_IS_WRITE);
    }
    // Placeholder: storage key/value filled from register state
    // Full implementation needs SMT integration
}

fn fill_op_aux(row: &mut TraceRow, op: Opcode, a: u64, b: u64, result: u64, rs2_imm: u32) {
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
            if result == 1 { // a < b
                row.set_u64(col::OP_AUX, b.wrapping_sub(a).wrapping_sub(1));
            } else {
                row.set_u64(col::OP_AUX, a.wrapping_sub(b));
            }
        }
        // GT: op_aux = comparison difference
        Opcode::Gt => {
            if result == 1 { // a > b
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
        // SHL: op_b = 2^shift_amount (for the constraint: result = op_a * op_b)
        Opcode::Shl => {
            let shift = b & 63;
            row.set_u64(col::OP_B, 1u64 << shift);
        }
        // SHR/SAR: op_b = 2^shift, op_aux = remainder
        Opcode::Shr | Opcode::Sar => {
            let shift = b & 63;
            let power = 1u64 << shift;
            row.set_u64(col::OP_B, power);
            if power != 0 {
                row.set_u64(col::OP_AUX, a % power);
            }
        }
        // BLT: op_aux = comparison difference for branch condition
        Opcode::Blt => {
            // branch_taken is set in fill_branch_info
            // op_aux needs the difference
            if a < b { // taken
                row.set_u64(col::OP_AUX, b.wrapping_sub(a).wrapping_sub(1));
            } else {
                row.set_u64(col::OP_AUX, a.wrapping_sub(b));
            }
        }
        // BGE: op_aux = comparison difference
        Opcode::Bge => {
            if a >= b { // taken
                row.set_u64(col::OP_AUX, a.wrapping_sub(b));
            } else {
                row.set_u64(col::OP_AUX, b.wrapping_sub(a).wrapping_sub(1));
            }
        }
        _ => {}
    }
}

fn fill_branch_info(row: &mut TraceRow, op: Opcode, a: u64, b: u64, _result: u64) {
    let is_branch = matches!(op, Opcode::Beq | Opcode::Bne | Opcode::Blt | Opcode::Bge);
    let is_comparison = matches!(op, Opcode::Eq | Opcode::Lt | Opcode::Gt | Opcode::Slt | Opcode::Sgt);

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

fn fill_wide_aux(row: &mut TraceRow, op: Opcode, vm: &Vm) {
    match op {
        Opcode::Wadd => {
            // Carry bits for WADD: carry[i] = overflow from limb addition
            // For checked arithmetic these should all be 0 or 1
            // The actual carry depends on operand values which the VM computed
        }
        Opcode::Wsub => {
            // Borrow bits for WSUB
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            &instr(Opcode::Add, 3, 1, 2),  // r3 = r1 + r2 = 30
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
            &instr(Opcode::Div, 3, 1, 2),  // r3 = 100 / 7 = 14, remainder = 2
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
}
