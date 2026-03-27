//! `pyde-aot`: Ahead-of-Time compiler for PVM bytecode.
//!
//! Compiles PVM bytecode to native machine code via Cranelift at deploy time.
//! The compiled binary runs natively for maximum execution speed.

pub mod analysis;
pub mod codegen;
pub mod host;

pub use analysis::{analyze, AnalyzedProgram, BasicBlock};
pub use codegen::{compile, decode_result, CompiledCode, RESULT_OUT_OF_GAS, RESULT_REVERT, RESULT_SUCCESS, RESULT_TRAP};

/// Compile PVM bytecode end-to-end: analyze → codegen → native function.
pub fn compile_bytecode(bytecode: &[u8]) -> Result<CompiledCode, Box<dyn std::error::Error>> {
    let program = analyze(bytecode)?;
    let compiled = codegen::compile(&program)?;
    Ok(compiled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_vm::isa::{encode, encode_immediate, Opcode};

    fn instr_bytes(op: Opcode, rd: u8, rs1: u8, rs2_or_imm: u32) -> [u8; 4] {
        encode(op, rd, rs1, rs2_or_imm).0.to_le_bytes()
    }

    fn instr_ri(op: Opcode, rd: u8, rs1: u8, imm: i32) -> [u8; 4] {
        encode(op, rd, rs1, encode_immediate(imm).unwrap()).0.to_le_bytes()
    }

    fn bytecode(instrs: &[[u8; 4]]) -> Vec<u8> {
        instrs.iter().flat_map(|i| i.iter().copied()).collect()
    }

    /// Run compiled code with a VM context and return (status, gas_used, registers).
    fn run_aot(code: &[u8], gas_limit: u64) -> (u64, u64, [u64; 16]) {
        let compiled = compile_bytecode(code).unwrap();
        let func = compiled.as_fn();
        let mut regs = [0u64; 16];
        let mut vm = pyde_vm::vm::Vm::new();
        let raw = unsafe { func(regs.as_mut_ptr(), gas_limit, &mut vm as *mut _) };
        let (status, gas_used) = decode_result(raw);
        (status, gas_used, regs)
    }

    /// Run the same program on interpreter and AOT, compare results.
    fn compare_with_interpreter(code: &[u8], gas_limit: u64) {
        // Interpreter
        let mut vm = pyde_vm::vm::Vm::new();
        if gas_limit > 0 {
            vm = pyde_vm::vm::Vm::with_gas_limit(gas_limit);
        }
        vm.load(code).unwrap();
        let interp_output = vm.execute();

        // AOT
        let (aot_status, aot_gas, aot_regs) = run_aot(code, gas_limit);

        // Compare outcome
        match interp_output.outcome {
            pyde_vm::vm::Outcome::Success => assert_eq!(aot_status, RESULT_SUCCESS),
            pyde_vm::vm::Outcome::Revert => assert_eq!(aot_status, RESULT_REVERT),
            pyde_vm::vm::Outcome::OutOfGas => assert_eq!(aot_status, RESULT_OUT_OF_GAS),
            pyde_vm::vm::Outcome::Trap(_) => assert_eq!(aot_status, RESULT_TRAP),
        }

        // Compare registers (for success cases)
        if aot_status == RESULT_SUCCESS {
            for i in 1..16 {
                assert_eq!(
                    aot_regs[i],
                    vm.cpu.read_gp(i as u8),
                    "register r{} mismatch: aot={} interp={}",
                    i,
                    aot_regs[i],
                    vm.cpu.read_gp(i as u8)
                );
            }
        }
    }

    // ========== Task 0259: AOT produces same results as interpreter ==========

    #[test]
    fn aot_simple_halt() {
        let code = bytecode(&[instr_bytes(Opcode::Halt, 0, 0, 0)]);
        let (status, _, _) = run_aot(&code, 0);
        assert_eq!(status, RESULT_SUCCESS);
    }

    #[test]
    fn aot_simple_revert() {
        let code = bytecode(&[instr_bytes(Opcode::Revert, 0, 0, 0)]);
        let (status, _, _) = run_aot(&code, 0);
        assert_eq!(status, RESULT_REVERT);
    }

    #[test]
    fn aot_addi_matches_interpreter() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        compare_with_interpreter(&code, 0);
    }

    #[test]
    fn aot_add_two_numbers() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),
            instr_ri(Opcode::Addi, 2, 0, 20),
            instr_bytes(Opcode::Add, 3, 1, 2),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let (status, _, regs) = run_aot(&code, 0);
        assert_eq!(status, RESULT_SUCCESS);
        assert_eq!(regs[3], 30);
    }

    #[test]
    fn aot_add_matches_interpreter() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),
            instr_ri(Opcode::Addi, 2, 0, 20),
            instr_bytes(Opcode::Add, 3, 1, 2),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        compare_with_interpreter(&code, 0);
    }

    #[test]
    fn aot_branch_taken() {
        // BEQ r0, r0 → always taken (both zero)
        let code = bytecode(&[
            instr_ri(Opcode::Beq, 0, 0, 8),          // [0] branch to [8]
            instr_ri(Opcode::Addi, 1, 0, 99),        // [4] skipped
            instr_bytes(Opcode::Halt, 0, 0, 0),      // [8]
        ]);
        let (status, _, regs) = run_aot(&code, 0);
        assert_eq!(status, RESULT_SUCCESS);
        assert_eq!(regs[1], 0); // ADDI was skipped
    }

    #[test]
    fn aot_branch_not_taken() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 1),         // [0] r1 = 1
            instr_ri(Opcode::Beq, 1, 0, 8),          // [4] r1 != r0, not taken
            instr_ri(Opcode::Addi, 2, 0, 42),        // [8] runs
            instr_bytes(Opcode::Halt, 0, 0, 0),      // [12]
        ]);
        let (status, _, regs) = run_aot(&code, 0);
        assert_eq!(status, RESULT_SUCCESS);
        assert_eq!(regs[2], 42);
    }

    #[test]
    fn aot_loop_matches_interpreter() {
        // Loop: r1 = 10, r2 = 0; while r2 < r1: r2++
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),        // [0]
            instr_ri(Opcode::Addi, 2, 0, 0),         // [4]
            instr_ri(Opcode::Addi, 2, 2, 1),         // [8] loop body
            instr_ri(Opcode::Blt, 2, 1, -4),         // [12] back to [8]
            instr_bytes(Opcode::Halt, 0, 0, 0),      // [16]
        ]);
        compare_with_interpreter(&code, 0);
    }

    // ========== Task 0260: AOT gas metering matches interpreter ==========

    #[test]
    fn aot_gas_metering_basic() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),        // 1 gas
            instr_bytes(Opcode::Halt, 0, 0, 0),      // 1 gas
        ]);
        let (status, gas_used, _) = run_aot(&code, 1_000_000);
        assert_eq!(status, RESULT_SUCCESS);
        assert_eq!(gas_used, 2);
    }

    #[test]
    fn aot_out_of_gas() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),        // 1 gas
            instr_bytes(Opcode::Halt, 0, 0, 0),      // 1 gas — total 2
        ]);
        let (status, _, _) = run_aot(&code, 1); // only 1 gas available
        assert_eq!(status, RESULT_OUT_OF_GAS);
    }

    // ========== Task 0262: Benchmark placeholder ==========

    #[test]
    fn aot_fibonacci_matches_interpreter() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),        // [0] r1 = 10
            instr_ri(Opcode::Addi, 2, 0, 0),         // [4] r2 = 0 (fib_prev)
            instr_ri(Opcode::Addi, 3, 0, 1),         // [8] r3 = 1 (fib_curr)
            instr_ri(Opcode::Addi, 4, 0, 1),         // [12] r4 = 1 (counter)
            instr_bytes(Opcode::Bge, 4, 1, 24),      // [16] if r4 >= r1, jump to [40] halt
            instr_bytes(Opcode::Add, 5, 2, 3),       // [20] r5 = r2 + r3
            instr_bytes(Opcode::Add, 2, 3, 0),       // [24] r2 = r3
            instr_bytes(Opcode::Add, 3, 5, 0),       // [28] r3 = r5
            instr_ri(Opcode::Addi, 4, 4, 1),         // [32] r4++
            instr_ri(Opcode::Jmp, 0, 0, -20),        // [36] jmp to [16]
            instr_bytes(Opcode::Halt, 0, 0, 0),      // [40]
        ]);
        compare_with_interpreter(&code, 0);
    }
}
