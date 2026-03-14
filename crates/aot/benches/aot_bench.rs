use std::time::Instant;

use pyde_aot::{compile_bytecode, decode_result, RESULT_SUCCESS};
use pyde_vm::isa::{encode, encode_immediate, Opcode};
use pyde_vm::vm::Vm;

fn instr_bytes(op: Opcode, rd: u8, rs1: u8, rs2_or_imm: u32) -> [u8; 4] {
    encode(op, rd, rs1, rs2_or_imm).0.to_le_bytes()
}

fn instr_ri(op: Opcode, rd: u8, rs1: u8, imm: i32) -> [u8; 4] {
    encode(op, rd, rs1, encode_immediate(imm)).0.to_le_bytes()
}

fn bytecode(instrs: &[[u8; 4]]) -> Vec<u8> {
    instrs.iter().flat_map(|i| i.iter().copied()).collect()
}

fn bench_aot_vs_interpreter() {
    println!("=== AOT vs Interpreter throughput ===\n");

    let loop_count: i32 = 100_000;
    let code = bytecode(&[
        instr_ri(Opcode::Addi, 1, 0, loop_count),
        instr_ri(Opcode::Addi, 2, 0, 0),
        instr_ri(Opcode::Addi, 3, 0, 42),
        instr_ri(Opcode::Addi, 4, 0, 17),
        instr_bytes(Opcode::Add, 5, 3, 4),
        instr_bytes(Opcode::Sub, 6, 5, 4),
        instr_bytes(Opcode::Xor, 7, 5, 6),
        instr_bytes(Opcode::Shl, 8, 7, 3),
        instr_bytes(Opcode::Shr, 9, 8, 4),
        instr_bytes(Opcode::And, 10, 9, 7),
        instr_ri(Opcode::Addi, 2, 2, 1),
        instr_ri(Opcode::Blt, 2, 1, -28),
        instr_bytes(Opcode::Halt, 0, 0, 0),
    ]);

    let total_instrs = 4 + (8 * loop_count as u64) + 1;

    // --- Interpreter ---
    let runs = 100u64;
    let start = Instant::now();
    for _ in 0..runs {
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        vm.run().unwrap();
    }
    let interp_elapsed = start.elapsed();
    let interp_ips = (total_instrs * runs) as f64 / interp_elapsed.as_secs_f64();

    // --- AOT ---
    let compiled = compile_bytecode(&code).unwrap();
    let func = compiled.as_fn();

    // Warmup
    for _ in 0..3 {
        let mut regs = [0u64; 16];
        let mut vm = Vm::new();
        let raw = unsafe { func(regs.as_mut_ptr(), 0, &mut vm as *mut _ as *mut _) };
        let (status, _) = decode_result(raw);
        assert_eq!(status, RESULT_SUCCESS);
    }

    let start = Instant::now();
    for _ in 0..runs {
        let mut regs = [0u64; 16];
        let mut vm = Vm::new();
        std::hint::black_box(unsafe { func(regs.as_mut_ptr(), 0, &mut vm as *mut _ as *mut _) });
    }
    let aot_elapsed = start.elapsed();
    let aot_ips = (total_instrs * runs) as f64 / aot_elapsed.as_secs_f64();

    let speedup = aot_ips / interp_ips;

    println!("  Instructions/run:  {total_instrs}");
    println!("  Runs:              {runs}");
    println!();
    println!("  Interpreter:       {interp_ips:>12.0} instr/sec ({:.1}ms)", interp_elapsed.as_secs_f64() * 1000.0);
    println!("  AOT:               {aot_ips:>12.0} instr/sec ({:.1}ms)", aot_elapsed.as_secs_f64() * 1000.0);
    println!("  Speedup:           {speedup:.1}x");
}

fn bench_compilation_time() {
    println!("\n=== AOT compilation time ===\n");

    let sizes = [4, 16, 64, 256];
    for size in sizes {
        // Build a program of `size` instructions
        let mut instrs: Vec<[u8; 4]> = Vec::new();
        for _ in 0..size - 1 {
            instrs.push(instr_ri(Opcode::Addi, 1, 1, 1));
        }
        instrs.push(instr_bytes(Opcode::Halt, 0, 0, 0));
        let code = bytecode(&instrs);

        let iterations = 100;
        let start = Instant::now();
        for _ in 0..iterations {
            std::hint::black_box(compile_bytecode(&code).unwrap());
        }
        let elapsed = start.elapsed();
        let us_per_compile = elapsed.as_micros() as f64 / iterations as f64;

        println!("  {size:>4} instructions:  {us_per_compile:>8.0} µs/compile");
    }
}

fn main() {
    bench_aot_vs_interpreter();
    bench_compilation_time();
    println!();
}
