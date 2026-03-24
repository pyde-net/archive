//! Scale benchmark: 10K transactions across multiple groups.
//!
//! Run with: cargo run -p pyde-prover --release --example scale_benchmark
//!
//! Tests the prover pipeline at block scale:
//! - 10,000 transactions distributed across 10 groups (1,000 txs/group)
//! - Each group produces ONE STARK proof
//! - Measures: prove time, proof size, verify time, throughput

use std::time::Instant;

use pyde_prover::pipeline::{
    compose_block_proof, prove_group, verify_block_proof, Group, ScheduledBlock, Transaction,
};
use pyde_vm::isa::{encode, encode_mem_immediate, MemWidth, Opcode};

fn instr(op: Opcode, rd: u8, rs1: u8, imm: u32) -> [u8; 4] {
    encode(op, rd, rs1, imm).0.to_le_bytes()
}

fn bytecode(instrs: &[&[u8; 4]]) -> Vec<u8> {
    instrs.iter().flat_map(|i| i.iter().copied()).collect()
}

/// Generate a realistic transaction (ERC20-like transfer).
/// Each tx: ~8 instructions (setup, arithmetic, store, halt).
fn transfer_tx(sender_balance: u32, amount: u32, idx: u32) -> Transaction {
    let store_imm = encode_mem_immediate(0, MemWidth::W64);
    Transaction {
        bytecode: bytecode(&[
            &instr(Opcode::Addi, 1, 0, sender_balance),
            &instr(Opcode::Addi, 2, 0, amount),
            &instr(Opcode::Sub, 3, 1, 2),            // new_sender = balance - amount
            &instr(Opcode::Addi, 4, 0, 500),
            &instr(Opcode::Add, 5, 4, 2),            // new_recipient = 500 + amount
            &instr(Opcode::Addi, 6, 0, (0x010000 + idx * 8) & 0x3FFFFF),
            &instr(Opcode::Store, 3, 6, store_imm),  // persist new_sender balance
            &instr(Opcode::Halt, 0, 0, 0),
        ]),
        gas_limit: 100_000,
    }
}

/// Generate an arithmetic-heavy transaction (AMM swap-like).
fn compute_tx(reserve_a: u32, input: u32) -> Transaction {
    Transaction {
        bytecode: bytecode(&[
            &instr(Opcode::Addi, 1, 0, reserve_a),
            &instr(Opcode::Addi, 2, 0, 20000),
            &instr(Opcode::Addi, 3, 0, input),
            &instr(Opcode::Mul, 4, 2, 3),            // reserve_b * input
            &instr(Opcode::Add, 5, 1, 3),            // reserve_a + input
            &instr(Opcode::Div, 6, 4, 5),            // output
            &instr(Opcode::Addi, 7, 0, 997),
            &instr(Opcode::Mul, 8, 6, 7),            // output * 997
            &instr(Opcode::Addi, 9, 0, 1000),
            &instr(Opcode::Div, 10, 8, 9),           // fee-adjusted output
            &instr(Opcode::Halt, 0, 0, 0),
        ]),
        gas_limit: 100_000,
    }
}

/// Generate a mixed transaction (comparison + branch + memory).
fn mixed_tx(a: u32, b: u32, idx: u32) -> Transaction {
    let store_imm = encode_mem_immediate(0, MemWidth::W64);
    let load_imm = encode_mem_immediate(0, MemWidth::W64);
    Transaction {
        bytecode: bytecode(&[
            &instr(Opcode::Addi, 1, 0, a),
            &instr(Opcode::Addi, 2, 0, b),
            &instr(Opcode::Lt, 3, 1, 2),
            &instr(Opcode::Bge, 1, 2, 8),            // branch if a >= b
            &instr(Opcode::Add, 4, 1, 2),            // taken if a < b
            &instr(Opcode::Addi, 5, 0, (0x020000 + idx * 8) & 0x3FFFFF),
            &instr(Opcode::Store, 4, 5, store_imm),
            &instr(Opcode::Load, 6, 5, load_imm),
            &instr(Opcode::Halt, 0, 0, 0),
        ]),
        gas_limit: 100_000,
    }
}

fn main() {
    println!("=== Pyde Prover Scale Benchmark ===");
    println!("    10,000 transactions across 10 groups\n");

    let num_groups = 10;
    let txs_per_group = 1000;
    let total_txs = num_groups * txs_per_group;

    // Build groups with diverse transaction types
    let build_start = Instant::now();
    let mut groups = Vec::with_capacity(num_groups);

    for g in 0..num_groups {
        let mut txs = Vec::with_capacity(txs_per_group);
        for t in 0..txs_per_group {
            let global_idx = (g * txs_per_group + t) as u32;
            let tx = match t % 3 {
                0 => transfer_tx(10000, (t as u32 % 500) + 1, global_idx),
                1 => compute_tx((t as u32 % 9000) + 1000, (t as u32 % 400) + 50),
                _ => mixed_tx(
                    (t as u32 % 1000) + 1,
                    (t as u32 % 500) + 1,
                    global_idx,
                ),
            };
            txs.push(tx);
        }
        groups.push(Group { index: g, txs });
    }

    let build_time = build_start.elapsed();
    println!("TX generation:  {:.2?} ({} txs)", build_time, total_txs);

    let block = ScheduledBlock {
        slot: 1,
        block_hash: [0xBB; 32],
        pre_state_root: [0u8; 32],
        groups,
    };

    // Prove each group sequentially (in production these run in parallel on different provers)
    let mut group_proofs = Vec::with_capacity(num_groups);
    let mut total_prove_time = std::time::Duration::ZERO;
    let mut total_rows = 0usize;
    let mut total_proof_bytes = 0usize;

    println!("\n{:>6} {:>8} {:>8} {:>10} {:>10} {:>12}",
        "Group", "TXs", "Rows", "Proof KB", "Prove", "Gas");
    println!("{}", "-".repeat(62));

    for (i, group) in block.groups.iter().enumerate() {
        let start = Instant::now();
        let gp = prove_group(group, block.pre_state_root)
            .unwrap_or_else(|e| panic!("group {} failed: {}", i, e));
        let prove_time = start.elapsed();

        total_prove_time += prove_time;
        total_rows += gp.execution_rows;
        total_proof_bytes += gp.proof_bytes.len();

        println!("{:>6} {:>8} {:>8} {:>10} {:>10.2?} {:>12}",
            i, gp.tx_count, gp.execution_rows,
            gp.proof_bytes.len() / 1024, prove_time, gp.gas_used);

        group_proofs.push(gp);
    }

    // Compose block proof
    let compose_start = Instant::now();
    let block_proof = compose_block_proof(&block, group_proofs).unwrap();
    let compose_time = compose_start.elapsed();

    // Verify block proof
    let verify_start = Instant::now();
    verify_block_proof(&block_proof).unwrap();
    let verify_time = verify_start.elapsed();

    // Compute per-group verify time
    let per_group_verify = verify_time / num_groups as u32;

    // Summary
    println!("\n{}", "=".repeat(62));
    println!("BLOCK SUMMARY");
    println!("{}", "=".repeat(62));
    println!("  Total transactions:   {}", total_txs);
    println!("  Groups:               {}", num_groups);
    println!("  TXs per group:        {}", txs_per_group);
    println!("  Total trace rows:     {}", total_rows);
    println!("  Avg rows/group:       {}", total_rows / num_groups);
    println!();
    println!("  Total proof size:     {} KB ({:.2} MB)",
        total_proof_bytes / 1024,
        total_proof_bytes as f64 / (1024.0 * 1024.0));
    println!("  Avg proof/group:      {} KB", total_proof_bytes / num_groups / 1024);
    println!("  Proof per tx:         {} bytes", total_proof_bytes / total_txs);
    println!();
    println!("  Sequential prove:     {:.2?} (all groups one-by-one)", total_prove_time);
    println!("  Avg prove/group:      {:.2?}", total_prove_time / num_groups as u32);
    println!("  Compose time:         {:.2?}", compose_time);
    println!("  Verify time:          {:.2?} (all groups)", verify_time);
    println!("  Avg verify/group:     {:.2?}", per_group_verify);
    println!();
    println!("  Total wall time:      {:.2?}", total_prove_time + compose_time + verify_time);
    println!("  Total gas:            {}", block_proof.total_gas);

    // Parallel estimate (groups are independent)
    let max_group_prove: std::time::Duration = block_proof.group_proofs.iter().enumerate()
        .map(|(_, _)| total_prove_time / num_groups as u32) // approximate equal distribution
        .max()
        .unwrap_or_default();
    println!();
    println!("  Parallel estimate ({} provers):", num_groups);
    println!("    Prove (parallel):   {:.2?}", max_group_prove);
    println!("    Total (parallel):   {:.2?}", max_group_prove + compose_time + verify_time);

    // Throughput
    let sequential_secs = total_prove_time.as_secs_f64();
    let parallel_secs = max_group_prove.as_secs_f64();
    if sequential_secs > 0.0 {
        println!();
        println!("  Throughput (sequential): {:.0} tx/s", total_txs as f64 / sequential_secs);
    }
    if parallel_secs > 0.0 {
        println!("  Throughput (parallel):   {:.0} tx/s", total_txs as f64 / parallel_secs);
    }
}
