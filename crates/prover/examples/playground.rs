//! Prover Playground — experiment with opcodes, trace generation, and proof verification.
//!
//! Run with: cargo run -p pyde-prover --example playground
//!
//! Modify the bytecode below to test different opcodes and values.
//! The program will:
//! 1. Execute the bytecode on the PVM
//! 2. Record the execution trace
//! 3. Generate a STARK proof
//! 4. Verify the proof
//! 5. Print all register values and proof details

use std::time::Instant;

use pyde_prover::multi_table::{prove_single_tx, verify_multi_table};
use pyde_prover::prover;
use pyde_prover::recorder;
use pyde_prover::trace::col;
use pyde_vm::isa::{encode, encode_mem_immediate, MemWidth, Opcode};
use pyde_vm::vm::Vm;

fn instr(op: Opcode, rd: u8, rs1: u8, imm: u32) -> [u8; 4] {
    encode(op, rd, rs1, imm).0.to_le_bytes()
}

fn bytecode(instrs: &[&[u8; 4]]) -> Vec<u8> {
    instrs.iter().flat_map(|i| i.iter().copied()).collect()
}

fn main() {
    println!("=== Pyde Prover Playground ===\n");

    // =====================================================
    // MODIFY THIS SECTION TO TEST DIFFERENT OPCODES
    // =====================================================

    let store_imm = encode_mem_immediate(0, MemWidth::W64);
    let load_imm = encode_mem_immediate(0, MemWidth::W64);

    let code = bytecode(&[
        // --- Arithmetic ---
        &instr(Opcode::Addi, 1, 0, 1000),       // r1 = 1000
        &instr(Opcode::Addi, 2, 0, 250),        // r2 = 250
        &instr(Opcode::Add, 3, 1, 2),           // r3 = 1250
        &instr(Opcode::Sub, 4, 1, 2),           // r4 = 750
        &instr(Opcode::Mul, 5, 4, 2),           // r5 = 187500
        &instr(Opcode::Addi, 6, 0, 7),
        &instr(Opcode::Div, 7, 5, 6),           // r7 = 187500 / 7 = 26785
        &instr(Opcode::Mod, 8, 5, 6),           // r8 = 187500 % 7 = 5

        // --- Comparison ---
        &instr(Opcode::Lt, 9, 8, 6),            // r9 = (5 < 7) = 1
        &instr(Opcode::Gt, 10, 1, 2),           // r10 = (1000 > 250) = 1
        &instr(Opcode::Eq, 11, 9, 10),          // r11 = (1 == 1) = 1

        // --- Branch ---
        &instr(Opcode::Bge, 1, 2, 8),           // 1000 >= 250 → skip next
        &instr(Opcode::Halt, 0, 0, 0),          // skipped

        // --- Shift ---
        &instr(Opcode::Addi, 12, 0, 3),
        &instr(Opcode::Shl, 13, 7, 12),         // r13 = 26785 << 3
        &instr(Opcode::Shr, 14, 13, 12),        // r14 = back to 26785

        // --- Memory ---
        &instr(Opcode::Addi, 15, 0, 0x010000),
        &instr(Opcode::Store, 7, 15, store_imm), // mem[heap] = 26785
        &instr(Opcode::Load, 1, 15, load_imm),   // r1 = mem[heap] = 26785

        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    // =====================================================
    // END OF MODIFIABLE SECTION
    // =====================================================

    let gas_limit = 500_000;

    // Execute on PVM
    let mut vm = Vm::with_gas_limit(gas_limit);
    vm.load(&code).unwrap();

    println!("Program: {} instructions ({} bytes)\n", code.len() / 4, code.len());

    // Record trace
    let record_start = Instant::now();
    let (trace, outcome) = recorder::record_execution(&mut vm);
    let record_time = record_start.elapsed();

    println!("Execution:");
    println!("  Outcome:    {:?}", outcome);
    println!("  Gas used:   {}", vm.gas_used_total);
    println!("  Trace rows: {}", trace.len());
    println!("  Record:     {:.2?}", record_time);

    // Print register state
    println!("\nRegisters (post-execution):");
    for i in 0..16 {
        let val = vm.cpu.read_gp(i as u8);
        if val != 0 {
            println!("  r{:<2} = {} (0x{:x})", i, val, val);
        }
    }

    // Generate multi-table proof
    let mut vm2 = Vm::with_gas_limit(gas_limit);
    vm2.load(&code).unwrap();

    let prove_start = Instant::now();
    let proof = prove_single_tx(&mut vm2).unwrap();
    let prove_time = prove_start.elapsed();

    println!("\nProof Generation:");
    println!("  Prove time:     {:.2?}", prove_time);
    println!("  Proof size:     {} KB", proof.proof_bytes.len() / 1024);
    println!("  Memory ops:     {}", proof.memory_access_count);
    println!("  Lookup queries: {}", proof.lookup_query_count);
    println!("  Hash requests:  {}", proof.hash_request_count);
    println!("  Range checks:   {}", proof.range_check_count);
    println!("  Syscall reads:  {}", proof.syscall_reads.len());

    // Verify
    let verify_start = Instant::now();
    let result = verify_multi_table(&proof);
    let verify_time = verify_start.elapsed();

    println!("\nVerification:");
    println!("  Verify time: {:.2?}", verify_time);
    println!("  Memory OK:   {}", proof.memory_ok);
    println!("  Lookup OK:   {}", proof.lookup_ok);
    println!("  Hash OK:     {}", proof.hash_ok);
    println!("  RangeChk OK: {}", proof.range_check_ok);

    match result {
        Ok(()) => println!("\n  PROOF VERIFIED SUCCESSFULLY"),
        Err(e) => println!("\n  VERIFICATION FAILED: {}", e),
    }

    // Print trace details for debugging
    println!("\n--- Trace Details ---");
    use p3_field::PrimeField64;
    for (i, row) in trace.rows.iter().enumerate() {
        let pc = row.get(col::PC).as_canonical_u64();
        let opcode = row.get(col::OPCODE).as_canonical_u64();
        let rd = row.get(col::RD).as_canonical_u64();
        let rs1 = row.get(col::RS1).as_canonical_u64();
        let result = row.get(col::OP_RESULT).as_canonical_u64();
        let is_final = row.get(col::IS_FINAL).as_canonical_u64();
        let gas = row.get(col::GAS_CUMULATIVE).as_canonical_u64();

        println!("  [{:3}] pc={:<6} op=0x{:02x} rd=r{:<2} rs1=r{:<2} result={:<12} gas={:<6} {}",
            i, pc, opcode, rd, rs1, result, gas,
            if is_final == 1 { "FINAL" } else { "" });
    }
}
