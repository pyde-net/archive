//! Realistic benchmarks for the Pyde ZK prover v2.
//!
//! Exercises all operation types: arithmetic, bitwise, shifts, comparisons,
//! branches, memory, and mixed programs. Measures proof generation time,
//! proof size, and verification time.

use std::time::Instant;

use pyde_prover::multi_table::{prove_single_tx, verify_multi_table};
use pyde_prover::pipeline::{
    compose_block_proof, prove_assigned_groups, verify_block_proof,
    Group, ScheduledBlock, Transaction,
};
use pyde_vm::isa::{encode, encode_mem_immediate, MemWidth, Opcode};
use pyde_vm::vm::Vm;

fn instr(op: Opcode, rd: u8, rs1: u8, imm: u32) -> [u8; 4] {
    encode(op, rd, rs1, imm).0.to_le_bytes()
}

fn bytecode(instrs: &[&[u8; 4]]) -> Vec<u8> {
    instrs.iter().flat_map(|i| i.iter().copied()).collect()
}

// ============================================================================
// Test 1: ERC20-style token transfer
// ============================================================================

#[test]
fn benchmark_erc20_transfer() {
    let store_imm = encode_mem_immediate(0, MemWidth::W64);
    let load_imm = encode_mem_immediate(0, MemWidth::W64);

    let code = bytecode(&[
        // Setup
        &instr(Opcode::Addi, 1, 0, 0x010000),  // r1 = heap
        &instr(Opcode::Addi, 2, 0, 1000),       // sender_balance = 1000
        &instr(Opcode::Addi, 3, 0, 250),        // amount = 250
        &instr(Opcode::Addi, 4, 0, 500),        // recipient_balance = 500
        // Store balances
        &instr(Opcode::Store, 2, 1, store_imm),
        &instr(Opcode::Addi, 5, 0, 0x010008),
        &instr(Opcode::Store, 4, 5, store_imm),
        // Transfer: sender -= amount
        &instr(Opcode::Sub, 6, 2, 3),           // 750
        &instr(Opcode::Store, 6, 1, store_imm),
        // Transfer: recipient += amount
        &instr(Opcode::Add, 7, 4, 3),           // 750
        &instr(Opcode::Store, 7, 5, store_imm),
        // Read back and verify
        &instr(Opcode::Load, 8, 1, load_imm),
        &instr(Opcode::Load, 9, 5, load_imm),
        &instr(Opcode::Add, 10, 8, 9),          // total = 1500
        // Fee calc
        &instr(Opcode::Addi, 11, 0, 21000),
        &instr(Opcode::Addi, 12, 0, 50),
        &instr(Opcode::Mul, 13, 11, 12),        // total_fee
        &instr(Opcode::Addi, 14, 0, 100),
        &instr(Opcode::Div, 15, 13, 14),        // fee / 100
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    let mut vm = Vm::with_gas_limit(500_000);
    vm.load(&code).unwrap();

    let start = Instant::now();
    let proof = prove_single_tx(&mut vm).unwrap();
    let prove_time = start.elapsed();

    let start = Instant::now();
    let result = verify_multi_table(&proof);
    let verify_time = start.elapsed();

    assert!(result.is_ok(), "ERC20 transfer failed: {:?}", result);

    println!("\n=== ERC20 Token Transfer ===");
    println!("  Rows:          {}", proof.execution_rows);
    println!("  Memory ops:    {}", proof.memory_access_count);
    println!("  Lookup queries: {}", proof.lookup_query_count);
    println!("  Range checks:  {}", proof.range_check_count);
    println!("  Proof size:    {} KB", proof.proof_bytes.len() / 1024);
    println!("  Prove time:    {:.2?}", prove_time);
    println!("  Verify time:   {:.2?}", verify_time);
}

// ============================================================================
// Test 2: AMM swap calculation
// ============================================================================

#[test]
fn benchmark_amm_swap() {
    let code = bytecode(&[
        // Reserves
        &instr(Opcode::Addi, 1, 0, 10000),      // reserve_a
        &instr(Opcode::Addi, 2, 0, 20000),      // reserve_b
        &instr(Opcode::Addi, 3, 0, 500),        // input
        // output = (reserve_b * input) / (reserve_a + input)
        &instr(Opcode::Mul, 4, 2, 3),           // 20000 * 500 = 10_000_000
        &instr(Opcode::Add, 5, 1, 3),           // 10000 + 500 = 10500
        &instr(Opcode::Div, 6, 4, 5),           // 10_000_000 / 10500 = 952
        // Apply 0.3% fee: output * 997 / 1000
        &instr(Opcode::Addi, 7, 0, 997),
        &instr(Opcode::Mul, 8, 6, 7),
        &instr(Opcode::Addi, 9, 0, 1000),
        &instr(Opcode::Div, 10, 8, 9),
        // Update reserves
        &instr(Opcode::Add, 11, 1, 3),          // new_a = 10500
        &instr(Opcode::Sub, 12, 2, 10),         // new_b = reserve_b - output
        // Verify k invariant: new_a * new_b >= old_a * old_b
        &instr(Opcode::Mul, 13, 1, 2),          // old_k
        &instr(Opcode::Addi, 14, 0, 100),
        &instr(Opcode::Div, 15, 13, 14),        // scaled old_k
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    let mut vm = Vm::with_gas_limit(500_000);
    vm.load(&code).unwrap();

    let start = Instant::now();
    let proof = prove_single_tx(&mut vm).unwrap();
    let prove_time = start.elapsed();

    let start = Instant::now();
    assert!(verify_multi_table(&proof).is_ok());
    let verify_time = start.elapsed();

    println!("\n=== AMM Swap Calculation ===");
    println!("  Rows:          {}", proof.execution_rows);
    println!("  Proof size:    {} KB", proof.proof_bytes.len() / 1024);
    println!("  Prove time:    {:.2?}", prove_time);
    println!("  Verify time:   {:.2?}", verify_time);
}

// ============================================================================
// Test 3: Mixed operations (arithmetic + comparison + branch + memory)
// ============================================================================

#[test]
fn benchmark_mixed_operations() {
    let store_imm = encode_mem_immediate(0, MemWidth::W64);
    let load_imm = encode_mem_immediate(0, MemWidth::W64);

    let code = bytecode(&[
        // Setup values
        &instr(Opcode::Addi, 1, 0, 1000),
        &instr(Opcode::Addi, 2, 0, 250),
        // Arithmetic
        &instr(Opcode::Sub, 3, 1, 2),
        &instr(Opcode::Mul, 4, 3, 2),
        &instr(Opcode::Addi, 5, 0, 100),
        &instr(Opcode::Div, 6, 4, 5),
        &instr(Opcode::Mod, 7, 4, 5),
        // Comparison
        &instr(Opcode::Lt, 8, 7, 5),            // mod < 100?
        &instr(Opcode::Gt, 9, 6, 1),            // div > 1000?
        &instr(Opcode::Eq, 10, 8, 8),           // 1 == 1
        // Branch
        &instr(Opcode::Bge, 1, 2, 8),           // 1000 >= 250 → skip
        &instr(Opcode::Halt, 0, 0, 0),          // skipped
        // Memory
        &instr(Opcode::Addi, 11, 0, 0x010000),
        &instr(Opcode::Store, 6, 11, store_imm),
        &instr(Opcode::Load, 12, 11, load_imm),
        // Shift
        &instr(Opcode::Addi, 13, 0, 2),
        &instr(Opcode::Shl, 14, 12, 13),
        &instr(Opcode::Shr, 15, 14, 13),
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    let mut vm = Vm::with_gas_limit(500_000);
    vm.load(&code).unwrap();

    let start = Instant::now();
    let proof = prove_single_tx(&mut vm).unwrap();
    let prove_time = start.elapsed();

    let start = Instant::now();
    assert!(verify_multi_table(&proof).is_ok());
    let verify_time = start.elapsed();

    println!("\n=== Mixed Operations ===");
    println!("  Rows:          {}", proof.execution_rows);
    println!("  Memory ops:    {}", proof.memory_access_count);
    println!("  Range checks:  {}", proof.range_check_count);
    println!("  Proof size:    {} KB", proof.proof_bytes.len() / 1024);
    println!("  Prove time:    {:.2?}", prove_time);
    println!("  Verify time:   {:.2?}", verify_time);
}

// ============================================================================
// Test 4: Multi-transaction block (full pipeline)
// ============================================================================

#[test]
fn benchmark_multi_tx_block() {
    let store_imm = encode_mem_immediate(0, MemWidth::W64);
    let load_imm = encode_mem_immediate(0, MemWidth::W64);

    println!("\n=== Multi-Transaction Block ===\n");

    let block = ScheduledBlock {
        slot: 42,
        block_hash: [0xBB; 32],
        pre_state_root: [0u8; 32],
        groups: vec![
            // Group 0: 3 transfer txs
            Group {
                index: 0,
                txs: vec![
                    Transaction {
                        bytecode: bytecode(&[
                            &instr(Opcode::Addi, 1, 0, 1000),
                            &instr(Opcode::Addi, 2, 0, 250),
                            &instr(Opcode::Sub, 3, 1, 2),
                            &instr(Opcode::Add, 4, 3, 2),
                            &instr(Opcode::Mul, 5, 4, 1),
                            &instr(Opcode::Addi, 6, 0, 7),
                            &instr(Opcode::Div, 7, 5, 6),
                            &instr(Opcode::Halt, 0, 0, 0),
                        ]),
                        gas_limit: 100_000,
                    },
                    Transaction {
                        bytecode: bytecode(&[
                            &instr(Opcode::Addi, 1, 0, 500),
                            &instr(Opcode::Addi, 2, 0, 100),
                            &instr(Opcode::Add, 3, 1, 2),
                            &instr(Opcode::Halt, 0, 0, 0),
                        ]),
                        gas_limit: 100_000,
                    },
                    Transaction {
                        bytecode: bytecode(&[
                            &instr(Opcode::Addi, 1, 0, 0x010000),
                            &instr(Opcode::Addi, 2, 0, 42),
                            &instr(Opcode::Store, 2, 1, store_imm),
                            &instr(Opcode::Load, 3, 1, load_imm),
                            &instr(Opcode::Halt, 0, 0, 0),
                        ]),
                        gas_limit: 100_000,
                    },
                ],
            },
            // Group 1: 2 compute txs
            Group {
                index: 1,
                txs: vec![
                    Transaction {
                        bytecode: bytecode(&[
                            &instr(Opcode::Addi, 1, 0, 1500),
                            &instr(Opcode::Addi, 2, 0, 3000),
                            &instr(Opcode::Addi, 3, 0, 100),
                            &instr(Opcode::Mul, 4, 2, 3),
                            &instr(Opcode::Add, 5, 1, 3),
                            &instr(Opcode::Div, 6, 4, 5),
                            &instr(Opcode::Halt, 0, 0, 0),
                        ]),
                        gas_limit: 100_000,
                    },
                    Transaction {
                        bytecode: bytecode(&[
                            &instr(Opcode::Addi, 1, 0, 10),
                            &instr(Opcode::Addi, 2, 0, 20),
                            &instr(Opcode::Lt, 3, 1, 2),
                            &instr(Opcode::Gt, 4, 1, 2),
                            &instr(Opcode::Eq, 5, 1, 1),
                            &instr(Opcode::Addi, 6, 0, 3),
                            &instr(Opcode::Shl, 7, 1, 6),
                            &instr(Opcode::Shr, 8, 7, 6),
                            &instr(Opcode::Halt, 0, 0, 0),
                        ]),
                        gas_limit: 100_000,
                    },
                ],
            },
        ],
    };

    let total_txs: usize = block.groups.iter().map(|g| g.txs.len()).sum();

    // Prove all groups
    let start = Instant::now();
    let proofs = prove_assigned_groups(&block, &[0, 1]).unwrap();
    let prove_time = start.elapsed();

    for gp in &proofs {
        println!("  Group {}: {} txs, {} rows, {} KB proof, {} gas",
            gp.group_index, gp.tx_count, gp.execution_rows,
            gp.proof_bytes.len() / 1024, gp.gas_used);
    }

    // Compose block proof
    let start = Instant::now();
    let block_proof = compose_block_proof(&block, proofs).unwrap();
    let compose_time = start.elapsed();

    // Verify
    let start = Instant::now();
    let result = verify_block_proof(&block_proof);
    let verify_time = start.elapsed();

    assert!(result.is_ok(), "Block verification failed: {:?}", result);

    let total_proof_bytes: usize = block_proof.group_proofs.iter()
        .map(|g| g.proof_bytes.len()).sum();

    println!();
    println!("  Block Summary:");
    println!("    Total txs:      {}", total_txs);
    println!("    Groups:         {}", block_proof.group_proofs.len());
    println!("    Total proof:    {} KB", total_proof_bytes / 1024);
    println!("    Total gas:      {}", block_proof.total_gas);
    println!("    Prove time:     {:.2?}", prove_time);
    println!("    Compose time:   {:.2?}", compose_time);
    println!("    Verify time:    {:.2?}", verify_time);
    println!("    Total:          {:.2?}", prove_time + compose_time + verify_time);
}

// ============================================================================
// Test 5: Performance summary
// ============================================================================

#[test]
fn benchmark_performance_summary() {
    println!("\n======== PROVER V2 PERFORMANCE SUMMARY ========");

    // Simple 4-instruction program
    let simple_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 42),
        &instr(Opcode::Addi, 2, 0, 58),
        &instr(Opcode::Add, 3, 1, 2),
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    let mut vm = Vm::with_gas_limit(100_000);
    vm.load(&simple_code).unwrap();
    let start = Instant::now();
    let simple_proof = prove_single_tx(&mut vm).unwrap();
    let simple_prove = start.elapsed();
    let start = Instant::now();
    verify_multi_table(&simple_proof).unwrap();
    let simple_verify = start.elapsed();

    // Medium 20-instruction program
    let store_imm = encode_mem_immediate(0, MemWidth::W64);
    let load_imm = encode_mem_immediate(0, MemWidth::W64);
    let medium_code = bytecode(&[
        &instr(Opcode::Addi, 1, 0, 1000),
        &instr(Opcode::Addi, 2, 0, 250),
        &instr(Opcode::Sub, 3, 1, 2),
        &instr(Opcode::Add, 4, 3, 2),
        &instr(Opcode::Mul, 5, 4, 1),
        &instr(Opcode::Addi, 6, 0, 7),
        &instr(Opcode::Div, 7, 5, 6),
        &instr(Opcode::Mod, 8, 5, 6),
        &instr(Opcode::Lt, 9, 8, 6),
        &instr(Opcode::Addi, 10, 0, 0x010000),
        &instr(Opcode::Store, 7, 10, store_imm),
        &instr(Opcode::Load, 11, 10, load_imm),
        &instr(Opcode::Addi, 12, 0, 2),
        &instr(Opcode::Shl, 13, 11, 12),
        &instr(Opcode::Shr, 14, 13, 12),
        &instr(Opcode::Eq, 15, 14, 11),
        &instr(Opcode::Halt, 0, 0, 0),
    ]);

    let mut vm = Vm::with_gas_limit(100_000);
    vm.load(&medium_code).unwrap();
    let start = Instant::now();
    let medium_proof = prove_single_tx(&mut vm).unwrap();
    let medium_prove = start.elapsed();
    let start = Instant::now();
    verify_multi_table(&medium_proof).unwrap();
    let medium_verify = start.elapsed();

    println!("\n  {:20} {:>8} {:>10} {:>10} {:>8}", "Program", "Rows", "Prove", "Verify", "Size");
    println!("  {:20} {:>8} {:>10} {:>10} {:>8}", "-------", "----", "-----", "------", "----");
    println!("  {:20} {:>8} {:>10.2?} {:>10.2?} {:>6} KB",
        "Simple (4 instr)", simple_proof.execution_rows, simple_prove, simple_verify,
        simple_proof.proof_bytes.len() / 1024);
    println!("  {:20} {:>8} {:>10.2?} {:>10.2?} {:>6} KB",
        "Medium (17 instr)", medium_proof.execution_rows, medium_prove, medium_verify,
        medium_proof.proof_bytes.len() / 1024);

    println!("\n  Trace width: 144 columns");
    println!("  FRI config:  log_blowup=4, queries=21, pow_bits=10");
}
