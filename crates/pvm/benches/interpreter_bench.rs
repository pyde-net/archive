use std::time::Instant;

use pyde_vm::isa::{encode, encode_immediate, Opcode};
use pyde_vm::vm::{ExecutionContext, ExecResult, Outcome, Vm, ZERO_ADDRESS};
use pyde_vm::wide::U256;

/// Helper: encode an instruction to little-endian bytes.
fn instr_bytes(op: Opcode, rd: u8, rs1: u8, rs2_or_imm: u32) -> [u8; 4] {
    encode(op, rd, rs1, rs2_or_imm).0.to_le_bytes()
}

fn instr_ri(op: Opcode, rd: u8, rs1: u8, imm: i32) -> [u8; 4] {
    encode(op, rd, rs1, encode_immediate(imm)).0.to_le_bytes()
}

fn bytecode(instrs: &[[u8; 4]]) -> Vec<u8> {
    instrs.iter().flat_map(|i| i.iter().copied()).collect()
}

// ---------------------------------------------------------------------------
// 0236 — Interpreter throughput (instructions/second)
// ---------------------------------------------------------------------------

/// Pure ALU dispatch: tight loop of register-only instructions.
/// Measures raw instruction decode + execute speed with no memory/storage.
fn bench_alu_throughput() {
    println!("--- ALU dispatch (no memory, no storage) ---\n");

    let loop_count: i32 = 100_000;
    let code = bytecode(&[
        instr_ri(Opcode::Addi, 1, 0, loop_count),  // [0]  r1 = loop_count
        instr_ri(Opcode::Addi, 2, 0, 0),            // [4]  r2 = 0 (counter)
        instr_ri(Opcode::Addi, 3, 0, 42),           // [8]  r3 = 42
        instr_ri(Opcode::Addi, 4, 0, 17),           // [12] r4 = 17
        // loop body (6 ALU + 1 ADDI + 1 BLT = 8 instructions):
        instr_bytes(Opcode::Add, 5, 3, 4),          // [16] r5 = r3 + r4
        instr_bytes(Opcode::Sub, 6, 5, 4),          // [20] r6 = r5 - r4
        instr_bytes(Opcode::Xor, 7, 5, 6),          // [24] r7 = r5 ^ r6
        instr_bytes(Opcode::Shl, 8, 7, 3),          // [28] r8 = r7 << r3
        instr_bytes(Opcode::Shr, 9, 8, 4),          // [32] r9 = r8 >> r4
        instr_bytes(Opcode::And, 10, 9, 7),         // [36] r10 = r9 & r7
        instr_ri(Opcode::Addi, 2, 2, 1),            // [40] r2++
        instr_ri(Opcode::Blt, 2, 1, -28),           // [44] if r2 < r1, jump to [16]
        instr_bytes(Opcode::Halt, 0, 0, 0),         // [48]
    ]);

    let setup_instrs = 4u64;
    let body_instrs = 8u64;
    let halt_instr = 1u64;
    let total_instrs = setup_instrs + (body_instrs * loop_count as u64) + halt_instr;

    // Use run() — no trace, no snapshot overhead
    // Warmup
    for _ in 0..3 {
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
    }

    let runs = 100u64;
    let start = Instant::now();
    for _ in 0..runs {
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        std::hint::black_box(vm.run().unwrap());
    }
    let elapsed = start.elapsed();

    let total_all_runs = total_instrs * runs;
    let instrs_per_sec = total_all_runs as f64 / elapsed.as_secs_f64();
    let ns_per_instr = elapsed.as_nanos() as f64 / total_all_runs as f64;

    println!("  Loop iterations:   {loop_count}");
    println!("  Instructions/run:  {total_instrs}");
    println!("  Runs:              {runs}");
    println!("  Total time:        {:.2}ms", elapsed.as_secs_f64() * 1000.0);
    println!("  Throughput:        {instrs_per_sec:>12.0} instructions/sec");
    println!("  Latency:           {ns_per_instr:>8.1} ns/instruction");
}

/// Same ALU loop but through execute() to measure trace recording overhead.
fn bench_alu_with_trace() {
    println!("\n--- ALU dispatch (with trace recording) ---\n");

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

    let setup_instrs = 4u64;
    let body_instrs = 8u64;
    let total_instrs = setup_instrs + (body_instrs * loop_count as u64) + 1;

    for _ in 0..3 {
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.execute().outcome, Outcome::Success);
    }

    let runs = 100u64;
    let start = Instant::now();
    for _ in 0..runs {
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        std::hint::black_box(vm.execute());
    }
    let elapsed = start.elapsed();

    let total_all_runs = total_instrs * runs;
    let instrs_per_sec = total_all_runs as f64 / elapsed.as_secs_f64();
    let ns_per_instr = elapsed.as_nanos() as f64 / total_all_runs as f64;

    println!("  Throughput:        {instrs_per_sec:>12.0} instructions/sec");
    println!("  Latency:           {ns_per_instr:>8.1} ns/instruction");
    println!("  (compare with no-trace to see overhead)");
}

// ---------------------------------------------------------------------------
// 0237 — Token transfer execution time
// ---------------------------------------------------------------------------

/// Build the token transfer bytecode once.
fn transfer_code() -> Vec<u8> {
    bytecode(&[
        // SLOAD sender balance into w2 from slot w0
        instr_bytes(Opcode::Sload, 2, 0, 0),       // [0]
        // NARROW w2 → r5
        instr_bytes(Opcode::Narrow, 5, 2, 0),       // [4]
        // Check: sender_balance >= transfer_amount (r6)
        instr_ri(Opcode::Bge, 5, 6, 8),             // [8]
        instr_bytes(Opcode::Revert, 0, 0, 0),       // [12]
        // Subtract from sender
        instr_bytes(Opcode::Sub, 7, 5, 6),           // [16]
        instr_bytes(Opcode::Widen, 2, 7, 0),         // [20]
        instr_bytes(Opcode::Sstore, 2, 0, 0),        // [24]
        // SLOAD receiver balance into w3 from slot w1
        instr_bytes(Opcode::Sload, 3, 1, 0),         // [28]
        instr_bytes(Opcode::Narrow, 8, 3, 0),        // [32]
        // Add to receiver
        instr_bytes(Opcode::Add, 9, 8, 6),            // [36]
        instr_bytes(Opcode::Widen, 3, 9, 0),          // [40]
        instr_bytes(Opcode::Sstore, 3, 1, 0),         // [44]
        instr_bytes(Opcode::Halt, 0, 0, 0),           // [48]
    ])
}

/// Set up a VM with pre-populated storage for a token transfer.
fn setup_transfer_vm(code: &[u8], gas_limit: u64) -> Vm {
    let ctx = ExecutionContext {
        self_address: {
            let mut a = ZERO_ADDRESS;
            a[..8].copy_from_slice(&0xAAAAu64.to_le_bytes());
            a
        },
        ..Default::default()
    };
    let mut vm = if gas_limit > 0 {
        Vm::with_gas_limit_and_context(gas_limit, ctx)
    } else {
        Vm::with_context(ctx)
    };

    let sender_slot = U256::from(1u64);
    let receiver_slot = U256::from(2u64);
    vm.cpu.write_wide(0, sender_slot);
    vm.cpu.write_wide(1, receiver_slot);
    vm.cpu.write_gp(6, 50); // transfer 50 tokens

    let sender_key = vm.derive_storage_key(sender_slot);
    let receiver_key = vm.derive_storage_key(receiver_slot);
    vm.storage.insert(sender_key, 1000u64.to_le_bytes().to_vec());
    vm.storage.insert(receiver_key, 500u64.to_le_bytes().to_vec());

    vm.load(code).unwrap();
    vm
}

/// Measure just the VM setup cost (allocation + storage key derivation + load).
fn bench_transfer_setup_cost() {
    println!("\n--- Token transfer: setup cost (VM alloc + key derivation + load) ---\n");

    let code = transfer_code();
    let iterations = 10_000u64;

    // Warmup
    for _ in 0..3 {
        std::hint::black_box(setup_transfer_vm(&code, 0));
    }

    let start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(setup_transfer_vm(&code, 0));
    }
    let elapsed = start.elapsed();

    let us_per_setup = elapsed.as_micros() as f64 / iterations as f64;
    println!("  Iterations:        {iterations}");
    println!("  Total time:        {:.2}ms", elapsed.as_secs_f64() * 1000.0);
    println!("  Latency:           {us_per_setup:>8.2} µs/setup");
}

/// Measure pure execution via run() (no trace, no snapshot).
fn bench_transfer_execution_only() {
    println!("\n--- Token transfer: execution only (run(), no trace) ---\n");

    let code = transfer_code();
    let iterations = 10_000u64;

    for _ in 0..3 {
        let mut vm = setup_transfer_vm(&code, 0);
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
    }

    let start = Instant::now();
    for _ in 0..iterations {
        let mut vm = setup_transfer_vm(&code, 0);
        std::hint::black_box(vm.run().unwrap());
    }
    let elapsed_total = start.elapsed();

    // Subtract setup cost
    let start_setup = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(setup_transfer_vm(&code, 0));
    }
    let elapsed_setup = start_setup.elapsed();

    let exec_only = elapsed_total.saturating_sub(elapsed_setup);
    let us_per_exec = exec_only.as_micros() as f64 / iterations as f64;
    let transfers_per_sec = iterations as f64 / exec_only.as_secs_f64();

    println!("  Iterations:        {iterations}");
    println!("  Total (incl setup):{:.2}ms", elapsed_total.as_secs_f64() * 1000.0);
    println!("  Setup overhead:    {:.2}ms", elapsed_setup.as_secs_f64() * 1000.0);
    println!("  Execution only:    {:.2}ms", exec_only.as_secs_f64() * 1000.0);
    println!("  Throughput:        {transfers_per_sec:>12.0} transfers/sec (execution only)");
    println!("  Latency:           {us_per_exec:>8.2} µs/transfer (execution only)");
}

/// Full lifecycle: setup + execute() with trace + snapshot/rollback.
fn bench_transfer_full_lifecycle() {
    println!("\n--- Token transfer: full lifecycle (execute() with trace + rollback) ---\n");

    let code = transfer_code();
    let iterations = 10_000u64;

    for _ in 0..3 {
        let mut vm = setup_transfer_vm(&code, 0);
        assert_eq!(vm.execute().outcome, Outcome::Success);
    }

    let start = Instant::now();
    for _ in 0..iterations {
        let mut vm = setup_transfer_vm(&code, 0);
        std::hint::black_box(vm.execute());
    }
    let elapsed = start.elapsed();

    let transfers_per_sec = iterations as f64 / elapsed.as_secs_f64();
    let us_per_transfer = elapsed.as_micros() as f64 / iterations as f64;

    println!("  Iterations:        {iterations}");
    println!("  Total time:        {:.2}ms", elapsed.as_secs_f64() * 1000.0);
    println!("  Throughput:        {transfers_per_sec:>12.0} transfers/sec (full lifecycle)");
    println!("  Latency:           {us_per_transfer:>8.2} µs/transfer (full lifecycle)");
}

// ---------------------------------------------------------------------------

fn main() {
    println!("=== 0236: Interpreter throughput ===\n");
    bench_alu_throughput();
    bench_alu_with_trace();

    println!("\n=== 0237: Token transfer execution time ===");
    bench_transfer_setup_cost();
    bench_transfer_execution_only();
    bench_transfer_full_lifecycle();

    println!();
}
