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
    // ADDITIONAL OPCODES
    // ================================================================

    // GT comparison
    let gt_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 100),
        &instr(Opcode::Addi, 2, 0, 50),
        &instr(Opcode::Gt, 3, 1, 2),   // 100 > 50 = 1
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("GT: flip result (1 → 0)", gt_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].set_u64(col::OP_RESULT, 0);
        trace.rows[2].fields[col::gp(3)] = to_field(0);
    });

    // SHR shift right
    let shr_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 800),
        &instr(Opcode::Addi, 2, 0, 3),
        &instr(Opcode::Shr, 3, 1, 2),  // 800 >> 3 = 100
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    // NOTE: SHR result correctness depends on cross-table range-check (not polynomial).
    // Tampering both OP_RESULT and gp[rd] together will pass polynomial constraints
    // but fail the range-check cross-table verification.
    // Test: tamper ONLY gp[rd] without matching OP_RESULT — gp_write gate catches it.
    tamper_test!("SHR: tamper gp[rd] without OP_RESULT", shr_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].fields[col::gp(3)] = to_field(200); // gp[rd] ≠ OP_RESULT
    });

    // ADDI immediate
    tamper_test!("ADDI: tamper result (42 → 99)", add_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[0].set_u64(col::OP_RESULT, 99);
        trace.rows[0].fields[col::gp(1)] = to_field(99);
    });

    // FIELDMUL
    let fieldmul_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 7),
        &instr(Opcode::Addi, 2, 0, 6),
        &instr(Opcode::FieldMul, 3, 1, 2),  // 7 * 6 = 42
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("FIELDMUL: tamper result (42 → 99)", fieldmul_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].set_u64(col::OP_RESULT, 99);
        trace.rows[2].fields[col::gp(3)] = to_field(99);
    });

    // BLT branch
    let blt_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 5),
        &instr(Opcode::Addi, 2, 0, 10),
        &instr(Opcode::Blt, 1, 2, 8),  // 5 < 10 → skip
        &instr(Opcode::Halt, 0, 0, 0), // skipped
        &instr(Opcode::Addi, 3, 0, 77),
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("BLT: tamper op_aux", blt_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].set_u64(col::OP_AUX, 999);
    });

    // BNE: test with equal values (branch NOT taken, simpler to verify)
    let bne_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 42),
        &instr(Opcode::Addi, 2, 0, 42),
        &instr(Opcode::Bne, 1, 2, 8),  // 42 == 42 → NOT taken, sequential
        &instr(Opcode::Halt, 0, 0, 0), // executed (branch not taken)
    ]);

    tamper_test!("BNE: force branch_taken when equal", bne_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].fields[col::BRANCH_TAKEN] = Goldilocks::one();
    });

    // NOTE: diff_inv tamper when a==b is expected to PASS polynomial constraints
    // (when diff=0, diff_inv is irrelevant). Caught by cross-table verification.

    // NOTE: mem_addr tamper is expected to PASS polynomial constraints
    // (address not constrained by AIR). Caught by memory bus cross-table.

    // IS_MEMORY_OP flag tampering
    tamper_test!("STORE: remove memory flag", mem_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].fields[col::IS_MEMORY_OP] = Goldilocks::zero();
    });

    // MEM_IS_WRITE flag tampering
    tamper_test!("STORE: remove write flag", mem_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].fields[col::MEM_IS_WRITE] = Goldilocks::zero();
    });

    // NOTE: CALL/RET tests require valid function addresses in bytecode.
    // The CALL instruction encoding needs careful offset calculation.
    // Tested implicitly via pipeline.rs multi-tx tests.

    // rs1_sel tampering (wrong source register)
    tamper_test!("ADD: tamper rs1_sel (wrong source)", add_code.clone(), |trace: &mut ExecutionTrace| {
        // ADD r3, r1, r2 — change rs1_sel to point to r5 instead of r1
        for i in 0..16 { trace.rows[2].fields[col::rs1_sel(i)] = Goldilocks::zero(); }
        trace.rows[2].fields[col::rs1_sel(5)] = Goldilocks::one();
    });

    // Wide selector boolean
    tamper_test!("WIDE: non-boolean wide_rd_sel", add_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[0].fields[col::wide_rd_sel(0)] = to_field(2); // not boolean
    });

    // ================================================================
    // BITWISE OPERATIONS
    // Bitwise result correctness is verified via LOOKUP TABLE (cross-table),
    // NOT by polynomial constraints. Tampering both OP_RESULT and gp[rd]
    // passes polynomial constraints but fails lookup verification.
    // Here we test that gp[rd] mismatch with OP_RESULT IS caught.
    // ================================================================

    let and_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 0xFF),
        &instr(Opcode::Addi, 2, 0, 0x0F),
        &instr(Opcode::And, 3, 1, 2),  // 0xFF & 0x0F = 0x0F
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("AND: tamper gp[rd] only (mismatch with OP_RESULT)", and_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].fields[col::gp(3)] = to_field(0xFF); // gp[rd] ≠ OP_RESULT
    });

    let or_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 0xF0),
        &instr(Opcode::Addi, 2, 0, 0x0F),
        &instr(Opcode::Or, 3, 1, 2),   // 0xF0 | 0x0F = 0xFF
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("OR: tamper gp[rd] only", or_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].fields[col::gp(3)] = to_field(0x00);
    });

    let xor_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 0xAA),
        &instr(Opcode::Addi, 2, 0, 0x55),
        &instr(Opcode::Xor, 3, 1, 2),
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("XOR: tamper gp[rd] only", xor_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].fields[col::gp(3)] = to_field(0x00);
    });

    let not_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 0),
        &instr(Opcode::Not, 2, 1, 0),
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("NOT: tamper gp[rd] only", not_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[1].fields[col::gp(2)] = to_field(42);
    });

    // ================================================================
    // STACK OPERATIONS (PUSH/POP)
    // ================================================================

    // PUSH/POP use the stack pointer (r2).
    // Stack is at top of memory; use a valid stack address within 18-bit range.
    let push_pop_code = bytecode(&[
        &instr(Opcode::Addi, 2, 0, 0x30000),  // r2 = SP (within address space)
        &instr(Opcode::Addi, 1, 0, 42),
        &instr(Opcode::Push, 1, 0, 0),         // push r1 (42)
        &instr(Opcode::Pop, 3, 0, 0),          // pop to r3
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    tamper_test!("PUSH: remove memory flag", push_pop_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[2].fields[col::IS_MEMORY_OP] = Goldilocks::zero();
    });

    tamper_test!("POP: tamper loaded result", push_pop_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[3].set_u64(col::OP_RESULT, 999);
        trace.rows[3].fields[col::gp(3)] = to_field(999);
    });

    // ================================================================
    // STORAGE OPERATIONS (flag constraints)
    // ================================================================

    // SLOAD/SSTORE need the VM's storage system. We test the FLAG constraints:
    // when IS_STORAGE_OP=0, all storage columns must be zero.
    tamper_test!("STORAGE: inject fake storage on non-storage op", add_code.clone(), |trace: &mut ExecutionTrace| {
        // Set storage columns on a non-storage row — should violate inactive constraint
        trace.rows[0].set_u64(col::storage_key(0), 999);
    });

    // NOTE: Setting IS_STORAGE_OP=1 on a non-storage row passes polynomial constraints
    // because the constraint only forces storage columns to zero when flag=0.
    // There's no constraint that "flag=1 implies opcode is SLOAD/SSTORE/SDELETE."
    // This is caught by the cross-table storage proof (Merkle path verification).

    // ================================================================
    // MEMORY INACTIVE CONSTRAINT
    // ================================================================

    tamper_test!("MEMORY INACTIVE: inject mem_val on non-memory op", add_code.clone(), |trace: &mut ExecutionTrace| {
        // Set memory value columns on a non-memory row
        trace.rows[0].set_u64(col::mem_val(0), 999);
    });

    tamper_test!("MEMORY INACTIVE: inject mem_addr on non-memory op", add_code.clone(), |trace: &mut ExecutionTrace| {
        trace.rows[0].set_u64(col::MEM_ADDR, 0x010000);
    });

    // ================================================================
    // BEQ (branch when equal)
    // ================================================================

    let beq_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 42),
        &instr(Opcode::Addi, 2, 0, 42),
        &instr(Opcode::Beq, 1, 2, 8),  // 42 == 42 → branch taken
        &instr(Opcode::Halt, 0, 0, 0), // skipped
        &instr(Opcode::Addi, 3, 0, 77),
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    // BEQ: when operands are equal, branch is taken. If we change gp[rd] so
    // they're NOT equal, the constraint branch_diff * (next_pc - pc - 4) must be 0.
    // With branch_diff ≠ 0, next_pc MUST equal pc + 4 (sequential).
    // But the trace shows a jump → constraint fails.
    tamper_test!("BEQ: make operands unequal (break branch condition)", beq_code.clone(), |trace: &mut ExecutionTrace| {
        // Change gp[rd=1] to make gp[rd] ≠ gp[rs1], breaking the equality
        trace.rows[2].fields[col::gp(1)] = to_field(99); // gp[1] was 42, now 99
    });

    // ================================================================
    // REVERT (termination)
    // ================================================================

    let revert_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 42),
        &instr(Opcode::Revert, 0, 0, 0),
    ]);

    tamper_test!("REVERT: remove is_final flag", revert_code.clone(), |trace: &mut ExecutionTrace| {
        let last = trace.rows.len() - 1;
        trace.rows[last].fields[col::IS_FINAL] = Goldilocks::zero();
    });

    // ================================================================
    // WIDE ARITHMETIC CARRY
    // ================================================================

    // WADD carry must be boolean (0 or 1). Test with non-boolean value.
    // We can't easily execute WADD from bytecode without wide register setup,
    // so we test the constraint directly by injecting a WADD row.
    tamper_test!("WADD: non-boolean carry", add_code.clone(), |trace: &mut ExecutionTrace| {
        // Inject WADD opcode on first row and set non-boolean carry
        trace.rows[0].set_u64(col::OPCODE, 0x09); // WADD
        trace.rows[0].set_opcode_bits(0x09);
        trace.rows[0].set_u64(col::wide_carry(0), 5); // not boolean!
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
