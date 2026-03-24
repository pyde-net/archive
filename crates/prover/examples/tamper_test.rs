//! Tamper Test — verify constraints catch incorrect trace values.
//!
//! Run: cargo run -p pyde-prover --example tamper_test
//!
//! This program:
//! 1. Records a valid execution trace
//! 2. Proves + verifies it (should PASS)
//! 3. Tampers with specific columns
//! 4. Tries to prove + verify the tampered trace (should FAIL)
//!
//! Each test demonstrates that the constraint system catches the specific tampering.

use p3_field::{AbstractField, PrimeField64};
use p3_goldilocks::Goldilocks;

use pyde_prover::prover;
use pyde_prover::recorder;
use pyde_prover::trace::{col, to_field, ExecutionTrace, TraceRow};
use pyde_vm::isa::{encode, encode_mem_immediate, MemWidth, Opcode};
use pyde_vm::vm::Vm;

fn instr(op: Opcode, rd: u8, rs1: u8, imm: u32) -> [u8; 4] {
    encode(op, rd, rs1, imm).0.to_le_bytes()
}

fn bytecode(instrs: &[&[u8; 4]]) -> Vec<u8> {
    instrs.iter().flat_map(|i| i.iter().copied()).collect()
}

/// Try to prove a trace. Returns Ok if proof verifies, Err if any step fails.
/// Catches panics from p3-uni-stark's debug constraint checker.
fn try_prove_verify(trace: &mut ExecutionTrace) -> Result<(), String> {
    let mut t = trace.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let proof = prover::prove(&mut t, &[]);
        prover::verify(&proof, &[]).map_err(|e| format!("{:?}", e))
    }));

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("constraint check panicked (constraint violation detected)".to_string()),
    }
}

fn main() {
    println!("=== Constraint Tamper Tests ===\n");

    let mut passed = 0;
    let mut failed = 0;
    let mut total = 0;

    // Helper to run a tamper test
    macro_rules! tamper_test {
        ($name:expr, $code:expr, $tamper:expr) => {{
            total += 1;
            print!("  {:50}", $name);

            // Record valid trace
            let mut vm = Vm::with_gas_limit(100_000);
            vm.load(&$code).unwrap();
            let (valid_trace, _) = recorder::record_execution(&mut vm);

            // Verify valid trace passes
            let mut valid = valid_trace.clone();
            match try_prove_verify(&mut valid) {
                Ok(()) => {}
                Err(e) => {
                    println!("SETUP FAIL (valid trace rejected: {})", e);
                    failed += 1;
                    return;
                }
            }

            // Apply tampering
            let mut tampered = valid_trace.clone();
            $tamper(&mut tampered);

            // Verify tampered trace FAILS
            match try_prove_verify(&mut tampered) {
                Ok(()) => {
                    println!("FAIL (tampered trace accepted!)");
                    failed += 1;
                }
                Err(_) => {
                    println!("PASS (tampered trace correctly rejected)");
                    passed += 1;
                }
            }
        }};
    }

    // ================================================================
    // ARITHMETIC TAMPERING
    // ================================================================

    let add_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 10),
        &instr(Opcode::Addi, 2, 0, 20),
        &instr(Opcode::Add, 3, 1, 2),  // r3 = 30
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("ADD: tamper result (30 → 99)", add_code.clone(), |trace: &mut ExecutionTrace| {
        // Change ADD result from 30 to 99
        trace.rows[2].set_u64(col::OP_RESULT, 99);
        trace.rows[2].fields[col::gp(3)] = to_field(99);
    });

    tamper_test!("ADD: tamper op_a (10 → 50)", add_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].set_u64(col::OP_A, 50);
    });

    // SUB
    let sub_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 100),
        &instr(Opcode::Addi, 2, 0, 30),
        &instr(Opcode::Sub, 3, 1, 2),  // r3 = 70
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("SUB: tamper result (70 → 50)", sub_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].set_u64(col::OP_RESULT, 50);
        trace.rows[2].fields[col::gp(3)] = to_field(50);
    });

    // MUL
    let mul_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 7),
        &instr(Opcode::Addi, 2, 0, 6),
        &instr(Opcode::Mul, 3, 1, 2),  // r3 = 42
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("MUL: tamper result (42 → 100)", mul_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].set_u64(col::OP_RESULT, 100);
        trace.rows[2].fields[col::gp(3)] = to_field(100);
    });

    // DIV
    let div_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 100),
        &instr(Opcode::Addi, 2, 0, 7),
        &instr(Opcode::Div, 3, 1, 2),  // r3 = 14, remainder = 2
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("DIV: tamper result (14 → 15)", div_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].set_u64(col::OP_RESULT, 15);
        trace.rows[2].fields[col::gp(3)] = to_field(15);
    });

    tamper_test!("DIV: tamper remainder (2 → 0)", div_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].set_u64(col::OP_AUX, 0);
    });

    // MOD
    let mod_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 100),
        &instr(Opcode::Addi, 2, 0, 7),
        &instr(Opcode::Mod, 3, 1, 2),  // r3 = 2
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("MOD: tamper result (2 → 5)", mod_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].set_u64(col::OP_RESULT, 5);
        trace.rows[2].fields[col::gp(3)] = to_field(5);
    });

    // ================================================================
    // COMPARISON TAMPERING
    // ================================================================

    let cmp_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 10),
        &instr(Opcode::Addi, 2, 0, 20),
        &instr(Opcode::Lt, 3, 1, 2),   // r3 = 1 (10 < 20)
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("LT: flip result (1 → 0)", cmp_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].set_u64(col::OP_RESULT, 0);
        trace.rows[2].fields[col::gp(3)] = to_field(0);
    });

    let eq_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 42),
        &instr(Opcode::Eq, 2, 1, 1),   // r2 = 1 (r1 == r1)
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("EQ: flip result (1 → 0)", eq_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[1].set_u64(col::OP_RESULT, 0);
        trace.rows[1].fields[col::gp(2)] = to_field(0);
    });

    // ================================================================
    // SHIFT TAMPERING
    // ================================================================

    let shl_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 100),
        &instr(Opcode::Addi, 2, 0, 3),
        &instr(Opcode::Shl, 3, 1, 2),  // r3 = 800
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("SHL: tamper result (800 → 900)", shl_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].set_u64(col::OP_RESULT, 900);
        trace.rows[2].fields[col::gp(3)] = to_field(900);
    });

    // ================================================================
    // MEMORY TAMPERING
    // ================================================================

    let store_imm = encode_mem_immediate(0, MemWidth::W64);
    let load_imm = encode_mem_immediate(0, MemWidth::W64);

    let mem_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 0x010000),
        &instr(Opcode::Addi, 2, 0, 42),
        &instr(Opcode::Store, 2, 1, store_imm),
        &instr(Opcode::Load, 3, 1, load_imm),
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("STORE: tamper stored value (42 → 99)", mem_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].set_u64(col::mem_val(0), 99);
    });

    tamper_test!("LOAD: tamper loaded value (42 → 99)", mem_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[3].set_u64(col::OP_RESULT, 99);
        trace.rows[3].fields[col::gp(3)] = to_field(99);
    });

    // ================================================================
    // CONTROL FLOW TAMPERING
    // ================================================================

    tamper_test!("GAS: tamper cumulative gas", add_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[1].set_u64(col::GAS_CUMULATIVE, 999);
    });

    tamper_test!("PC: tamper program counter", add_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[1].set_u64(col::PC, 100); // should be 4
    });

    tamper_test!("OPCODE BITS: tamper bit decomposition", add_code.clone(), |trace: &mut ExecutionTrace| {
        // Flip a bit — opcode bits won't match opcode field
        let current = trace.rows[0].get(col::opcode_bit(0)).as_canonical_u64();
        trace.rows[0].fields[col::opcode_bit(0)] = to_field(1 - current);
    });

    tamper_test!("REGISTER SELECTOR: tamper rd_sel", add_code.clone(), |trace: &mut ExecutionTrace| {
        // Change which register the result goes to
        // Clear rd_sel[1] and set rd_sel[5]
        trace.rows[0].fields[col::rd_sel(1)] = Goldilocks::zero();
        trace.rows[0].fields[col::rd_sel(5)] = Goldilocks::one();
    });

    tamper_test!("IS_FINAL: remove halt flag", add_code.clone(), |trace: &mut ExecutionTrace| {
        let last = trace.rows.len() - 1;
        trace.rows[last].fields[col::IS_FINAL] = Goldilocks::zero();
    });

    // ================================================================
    // BRANCH TAMPERING
    // ================================================================

    let branch_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 10),
        &instr(Opcode::Addi, 2, 0, 5),
        &instr(Opcode::Bge, 1, 2, 8),  // 10 >= 5 → skip
        &instr(Opcode::Halt, 0, 0, 0), // skipped
        &instr(Opcode::Addi, 3, 0, 99),
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("BGE: flip branch_taken", branch_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].fields[col::BRANCH_TAKEN] = Goldilocks::zero();
    });

    // ================================================================
    // SUMMARY
    // ================================================================

    println!("\n=== Results ===");
    println!("  Total: {}", total);
    println!("  Passed: {} (tampered traces correctly rejected)", passed);
    println!("  Failed: {} (tampered traces incorrectly accepted!)", failed);

    if failed > 0 {
        println!("\n  WARNING: {} constraint gaps detected!", failed);
        std::process::exit(1);
    } else {
        println!("\n  All constraints working correctly.");
    }
}
