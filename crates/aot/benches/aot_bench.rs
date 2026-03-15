use std::time::Instant;

use pyde_aot::{compile_bytecode, decode_result, RESULT_SUCCESS};
use pyde_vm::isa::{encode, encode_immediate, Opcode};
use pyde_vm::vm::{ExecutionContext, Vm};
use pyde_vm::wide::U256;

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

fn transfer_code() -> Vec<u8> {
    bytecode(&[
        instr_bytes(Opcode::Sload, 2, 0, 0),       // [0]  w2 = storage[w0]
        instr_bytes(Opcode::Narrow, 5, 2, 0),       // [4]  r5 = narrow(w2)
        instr_ri(Opcode::Bge, 5, 6, 8),             // [8]  if r5 >= r6, skip revert
        instr_bytes(Opcode::Revert, 0, 0, 0),       // [12] insufficient
        instr_bytes(Opcode::Sub, 7, 5, 6),           // [16] r7 = r5 - r6
        instr_bytes(Opcode::Widen, 2, 7, 0),         // [20] w2 = widen(r7)
        instr_bytes(Opcode::Sstore, 2, 0, 0),        // [24] storage[w0] = w2
        instr_bytes(Opcode::Sload, 3, 1, 0),         // [28] w3 = storage[w1]
        instr_bytes(Opcode::Narrow, 8, 3, 0),        // [32] r8 = narrow(w3)
        instr_bytes(Opcode::Add, 9, 8, 6),            // [36] r9 = r8 + r6
        instr_bytes(Opcode::Widen, 3, 9, 0),          // [40] w3 = widen(r9)
        instr_bytes(Opcode::Sstore, 3, 1, 0),         // [44] storage[w1] = w3
        instr_bytes(Opcode::Halt, 0, 0, 0),           // [48]
    ])
}

fn setup_transfer_vm(code: &[u8]) -> Vm {
    let ctx = ExecutionContext {
        self_address: 0xAAAA,
        ..Default::default()
    };
    let mut vm = Vm::with_context(ctx);

    let sender_slot = U256::from(1u64);
    let receiver_slot = U256::from(2u64);
    vm.cpu.write_wide(0, sender_slot);
    vm.cpu.write_wide(1, receiver_slot);
    vm.cpu.write_gp(6, 50);

    let sender_key = vm.derive_storage_key(sender_slot);
    let receiver_key = vm.derive_storage_key(receiver_slot);
    vm.storage.insert(sender_key, 1000u64.to_le_bytes().to_vec());
    vm.storage.insert(receiver_key, 500u64.to_le_bytes().to_vec());

    vm.load(code).unwrap();
    vm
}

fn bench_aot_token_transfer() {
    println!("\n=== AOT Token Transfer ===\n");

    let code = transfer_code();
    let compiled = compile_bytecode(&code).unwrap();
    let func = compiled.as_fn();
    let iterations = 10_000u64;

    // --- Interpreter: execution only ---
    // (subtract setup cost from total)
    let start_setup = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(setup_transfer_vm(&code));
    }
    let setup_time = start_setup.elapsed();

    let start_interp = Instant::now();
    for _ in 0..iterations {
        let mut vm = setup_transfer_vm(&code);
        std::hint::black_box(vm.run().unwrap());
    }
    let interp_total = start_interp.elapsed();
    let interp_exec = interp_total.saturating_sub(setup_time);

    // --- Interpreter: full lifecycle (execute with trace) ---
    let start_full = Instant::now();
    for _ in 0..iterations {
        let mut vm = setup_transfer_vm(&code);
        std::hint::black_box(vm.execute());
    }
    let interp_full = start_full.elapsed();

    // --- AOT: execution only ---
    // Warmup
    for _ in 0..3 {
        let mut vm = setup_transfer_vm(&code);
        let mut regs = [0u64; 16];
        regs[6] = 50; // transfer amount
        let raw = unsafe { func(regs.as_mut_ptr(), 0, &mut vm as *mut _ as *mut _) };
        let (status, _) = decode_result(raw);
        assert_eq!(status, RESULT_SUCCESS);
    }

    let start_aot = Instant::now();
    for _ in 0..iterations {
        let mut vm = setup_transfer_vm(&code);
        let mut regs = [0u64; 16];
        regs[6] = 50;
        std::hint::black_box(unsafe { func(regs.as_mut_ptr(), 0, &mut vm as *mut _ as *mut _) });
    }
    let aot_total = start_aot.elapsed();
    let aot_exec = aot_total.saturating_sub(setup_time);

    let interp_exec_per_sec = iterations as f64 / interp_exec.as_secs_f64();
    let interp_full_per_sec = iterations as f64 / interp_full.as_secs_f64();
    let aot_exec_per_sec = iterations as f64 / aot_exec.as_secs_f64();
    let aot_total_per_sec = iterations as f64 / aot_total.as_secs_f64();

    println!("  Iterations:         {iterations}");
    println!("  Setup cost:         {:.2}ms", setup_time.as_secs_f64() * 1000.0);
    println!();
    println!("  --- Interpreter ---");
    println!("  Exec only (run):    {:>10.0} transfers/sec ({:.2}µs each)", interp_exec_per_sec, interp_exec.as_micros() as f64 / iterations as f64);
    println!("  Full lifecycle:     {:>10.0} transfers/sec ({:.2}µs each)", interp_full_per_sec, interp_full.as_micros() as f64 / iterations as f64);
    println!();
    println!("  --- AOT ---");
    println!("  Exec only:          {:>10.0} transfers/sec ({:.2}µs each)", aot_exec_per_sec, aot_exec.as_micros() as f64 / iterations as f64);
    println!("  Full (incl setup):  {:>10.0} transfers/sec ({:.2}µs each)", aot_total_per_sec, aot_total.as_micros() as f64 / iterations as f64);
    println!();
    if aot_exec.as_nanos() > 0 {
        println!("  Speedup (exec):     {:.1}x", interp_exec_per_sec / aot_exec_per_sec.min(interp_exec_per_sec).max(1.0));
        println!("  AOT exec vs interp exec: {:.1}x", aot_exec_per_sec / interp_exec_per_sec);
    }
}

/// Simulate a constant-product AMM swap: x * y = k
/// Given input amount, compute output with 0.3% fee.
/// This is compute-heavy: multiply, divide, subtract — no storage.
fn bench_aot_dex_swap() {
    println!("\n=== AOT DEX Swap (constant-product AMM) ===\n");

    // Program: compute output_amount for a swap
    // r1 = reserve_x (1,000,000)
    // r2 = reserve_y (2,000,000)
    // r3 = input_amount (1,000)
    // r4 = fee_numerator (997, i.e. 0.3% fee)
    // r5 = fee_denominator (1000)
    //
    // Formula: output = (reserve_y * input_with_fee) / (reserve_x * 1000 + input_with_fee)
    // where input_with_fee = input_amount * 997
    //
    // We loop this 10,000 times to simulate batch swap computation
    let loop_count: i32 = 10_000;
    let code = bytecode(&[
        // Setup constants
        instr_ri(Opcode::Addi, 1, 0, 10_000),     // [0]  r1 = reserve_x
        instr_ri(Opcode::Addi, 2, 0, 20_000),     // [4]  r2 = reserve_y
        instr_ri(Opcode::Addi, 3, 0, 100),        // [8]  r3 = input_amount
        instr_ri(Opcode::Addi, 4, 0, 997),        // [12] r4 = fee_num (0.3% fee)
        instr_ri(Opcode::Addi, 5, 0, 1000),       // [16] r5 = fee_denom
        instr_ri(Opcode::Addi, 10, 0, loop_count),// [20] r10 = loop count
        instr_ri(Opcode::Addi, 11, 0, 0),         // [24] r11 = counter
        // Loop:
        instr_bytes(Opcode::Mul, 6, 3, 4),        // [28] r6 = input * fee_num
        instr_bytes(Opcode::Mul, 7, 2, 6),        // [32] r7 = reserve_y * input_with_fee
        instr_bytes(Opcode::Mul, 8, 1, 5),        // [36] r8 = reserve_x * fee_denom
        instr_bytes(Opcode::Add, 9, 8, 6),        // [40] r9 = reserve_x*1000 + input_with_fee
        instr_bytes(Opcode::Div, 12, 7, 9),       // [44] r12 = output_amount
        // Update reserves (simulate state change)
        instr_bytes(Opcode::Add, 1, 1, 3),        // [48] reserve_x += input
        instr_bytes(Opcode::Sub, 2, 2, 12),       // [52] reserve_y -= output
        // Counter
        instr_ri(Opcode::Addi, 11, 11, 1),        // [56] r11++
        instr_ri(Opcode::Blt, 11, 10, -32),       // [60] if r11 < r10, loop to [28]
        instr_bytes(Opcode::Halt, 0, 0, 0),       // [64]
    ]);

    let setup_instrs = 7u64;
    let body_instrs = 8u64; // MUL, MUL, MUL, ADD, DIV, ADD, SUB, ADDI, BLT = 9... but BLT counted in control
    let instrs_per_iter = 9u64;
    let total_instrs = setup_instrs + (instrs_per_iter * loop_count as u64) + 1;

    let iterations = 100u64;

    // --- Interpreter ---
    for _ in 0..3 {
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        vm.run().unwrap();
    }

    let start = Instant::now();
    for _ in 0..iterations {
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        std::hint::black_box(vm.run().unwrap());
    }
    let interp_elapsed = start.elapsed();
    let interp_swaps_sec = (loop_count as u64 * iterations) as f64 / interp_elapsed.as_secs_f64();
    let interp_ips = (total_instrs * iterations) as f64 / interp_elapsed.as_secs_f64();

    // --- AOT ---
    let compiled = compile_bytecode(&code).unwrap();
    let func = compiled.as_fn();

    for _ in 0..3 {
        let mut regs = [0u64; 16];
        let mut vm = Vm::new();
        let raw = unsafe { func(regs.as_mut_ptr(), 0, &mut vm as *mut _ as *mut _) };
        let (status, _) = decode_result(raw);
        assert_eq!(status, RESULT_SUCCESS);
    }

    let start = Instant::now();
    for _ in 0..iterations {
        let mut regs = [0u64; 16];
        let mut vm = Vm::new();
        std::hint::black_box(unsafe { func(regs.as_mut_ptr(), 0, &mut vm as *mut _ as *mut _) });
    }
    let aot_elapsed = start.elapsed();
    let aot_swaps_sec = (loop_count as u64 * iterations) as f64 / aot_elapsed.as_secs_f64();
    let aot_ips = (total_instrs * iterations) as f64 / aot_elapsed.as_secs_f64();

    let speedup = aot_swaps_sec / interp_swaps_sec;

    println!("  Swaps per run:      {loop_count}");
    println!("  Instructions/run:   {total_instrs}");
    println!("  Runs:               {iterations}");
    println!();
    println!("  --- Interpreter ---");
    println!("  Throughput:         {:>12.0} swaps/sec", interp_swaps_sec);
    println!("  Instructions:       {:>12.0} instr/sec", interp_ips);
    println!("  Time:               {:.1}ms", interp_elapsed.as_secs_f64() * 1000.0);
    println!();
    println!("  --- AOT ---");
    println!("  Throughput:         {:>12.0} swaps/sec", aot_swaps_sec);
    println!("  Instructions:       {:>12.0} instr/sec", aot_ips);
    println!("  Time:               {:.1}ms", aot_elapsed.as_secs_f64() * 1000.0);
    println!();
    println!("  Speedup:            {speedup:.1}x");
}

fn main() {
    bench_aot_vs_interpreter();
    bench_aot_token_transfer();
    bench_aot_dex_swap();
    bench_compilation_time();
    println!();
}
