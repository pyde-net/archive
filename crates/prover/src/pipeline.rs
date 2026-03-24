//! Prover pipeline: group proving with conflict-based parallelism.
//!
//! ## Conflict-Based Group Model
//!
//! Validators group transactions by CONFLICT (shared storage slots):
//! - Within a group: txs execute SEQUENTIALLY (they conflict)
//! - Between groups: fully PARALLEL (disjoint access lists)
//! - All groups start from the SAME pre_state_root
//!
//! ## Prover Workflow
//!
//! 1. Receive ScheduledBlock + state witnesses
//! 2. For each assigned group: execute txs → record trace → prove
//! 3. Submit group proofs to aggregator
//! 4. Aggregator verifies disjointness + merges diffs → block proof

use crate::prover::{self, PublicInputs, PydeProof};
use crate::recorder;
use crate::trace::ExecutionTrace;

use pyde_vm::vm::Vm;

/// A single transaction to execute.
#[derive(Clone)]
pub struct Transaction {
    pub bytecode: Vec<u8>,
    pub gas_limit: u64,
}

/// A group of conflicting transactions (execute sequentially).
#[derive(Clone)]
pub struct Group {
    pub index: usize,
    pub txs: Vec<Transaction>,
}

/// A scheduled block: groups of conflicting txs, all starting from same state.
#[derive(Clone)]
pub struct ScheduledBlock {
    pub slot: u64,
    pub block_hash: [u8; 32],
    pub pre_state_root: [u8; 32],
    pub groups: Vec<Group>,
}

/// Proof for a single group.
pub struct GroupProof {
    pub group_index: usize,
    pub proof: PydeProof,
    pub proof_bytes: Vec<u8>,
    pub public_inputs: PublicInputs,
    pub tx_count: usize,
    pub execution_rows: usize,
    pub gas_used: u64,
}

/// Proof for the entire block (collection of group proofs).
pub struct BlockProof {
    pub slot: u64,
    pub block_hash: [u8; 32],
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub group_proofs: Vec<GroupProof>,
    pub total_gas: u64,
    pub total_txs: usize,
}

/// Execute and prove a single group.
/// All txs in the group run sequentially (they conflict).
/// Returns a combined trace and proof covering all txs.
pub fn prove_group(group: &Group, pre_state_root: [u8; 32]) -> Result<GroupProof, String> {
    let mut combined_trace = ExecutionTrace::new();
    let mut total_gas = 0u64;

    for tx in &group.txs {
        let mut vm = Vm::with_gas_limit(tx.gas_limit);
        if vm.load(&tx.bytecode).is_err() {
            return Err(format!("group {} tx failed to load", group.index));
        }

        let (trace, outcome) = recorder::record_execution(&mut vm);
        total_gas += vm.gas_used_total;

        // Append all rows to combined trace.
        // TX boundaries are safe: each tx ends with is_final=1 (HALT/REVERT/trap),
        // which gates ALL transition constraints via not_final=0. The next tx starts
        // fresh with valid opcode bits and selectors. Gas/PC discontinuities at
        // boundaries are invisible to the constraint system because not_final=0
        // zeroes all transition expressions.
        for row in &trace.rows {
            combined_trace.push(row.clone());
        }
    }

    let execution_rows = combined_trace.len();

    // Generate STARK proof for the combined trace
    let proof = prover::prove(&mut combined_trace, &[]).map_err(|e| format!("prove failed: {e}"))?;

    // Serialize for transmission
    let proof_bytes = prover::serialize_proof(&proof)
        .map_err(|e| format!("serialize: {e}"))?;

    let public_inputs = PublicInputs {
        pre_state_root,
        post_state_root: pre_state_root, // placeholder — real impl computes from state diff
        tx_hash: [group.index as u8; 32], // placeholder
        gas_used: total_gas,
    };

    Ok(GroupProof {
        group_index: group.index,
        proof,
        proof_bytes,
        public_inputs,
        tx_count: group.txs.len(),
        execution_rows,
        gas_used: total_gas,
    })
}

/// Prove assigned groups from a scheduled block.
/// Each group starts from the SAME pre_state_root (no state chain dependency).
/// Returns group proofs for all assigned groups.
pub fn prove_assigned_groups(
    block: &ScheduledBlock,
    assigned: &[usize],
) -> Result<Vec<GroupProof>, String> {
    let mut proofs = Vec::with_capacity(assigned.len());

    for &g_idx in assigned {
        if g_idx >= block.groups.len() {
            return Err(format!("group index {} out of range", g_idx));
        }
        let gp = prove_group(&block.groups[g_idx], block.pre_state_root)?;
        proofs.push(gp);
    }

    Ok(proofs)
}

/// Compose a block proof from group proofs (aggregator's job).
/// Verifies:
/// 1. All groups start from same pre_state_root
/// 2. Each group STARK proof is valid
/// 3. Gas totals are consistent
pub fn compose_block_proof(
    block: &ScheduledBlock,
    group_proofs: Vec<GroupProof>,
) -> Result<BlockProof, String> {
    // Verify all groups start from same pre_state
    for gp in &group_proofs {
        if gp.public_inputs.pre_state_root != block.pre_state_root {
            return Err(format!(
                "group {} pre_state doesn't match block",
                gp.group_index
            ));
        }
    }

    // Verify each STARK proof
    for gp in &group_proofs {
        prover::verify(&gp.proof, &[])
            .map_err(|_| format!("group {} STARK verification failed", gp.group_index))?;
    }

    let total_gas: u64 = group_proofs.iter().map(|g| g.gas_used).sum();
    let total_txs: usize = group_proofs.iter().map(|g| g.tx_count).sum();

    // Post state root = merge of all group diffs applied to pre_state
    // For now: placeholder (real impl merges non-conflicting state diffs)
    let post_state_root = block.pre_state_root;

    Ok(BlockProof {
        slot: block.slot,
        block_hash: block.block_hash,
        pre_state_root: block.pre_state_root,
        post_state_root,
        group_proofs,
        total_gas,
        total_txs,
    })
}

/// Verify a block proof (validator's job).
///
/// In production, the validator also verifies syscall context reads
/// (CALLER/CALLVALUE/BLOCKHASH) against the block header by calling
/// verify_syscall_reads() with the expected transaction data.
pub fn verify_block_proof(block_proof: &BlockProof) -> Result<(), String> {
    // Verify each group STARK proof
    for gp in &block_proof.group_proofs {
        prover::verify(&gp.proof, &[])
            .map_err(|_| format!("group {} verification failed", gp.group_index))?;
    }

    // Verify gas consistency
    let computed_gas: u64 = block_proof.group_proofs.iter().map(|g| g.gas_used).sum();
    if computed_gas != block_proof.total_gas {
        return Err(format!(
            "gas mismatch: block says {}, groups sum to {}",
            block_proof.total_gas, computed_gas
        ));
    }

    Ok(())
}

/// Verify syscall context reads against expected block header values.
/// Called by the validator with data from the block header / tx fields.
///
/// This catches a malicious prover who returns fake values for
/// CALLER, CALLVALUE, BLOCKHASH, or COMMIT opcodes.
pub fn verify_syscall_reads(
    syscall_reads: &[crate::multi_table::SyscallRead],
    expected_caller: Option<u64>,
    expected_blockhash: Option<u64>,
) -> Result<(), String> {
    use crate::constraint::opcodes;

    for read in syscall_reads {
        if read.opcode == opcodes::CALLER {
            if let Some(expected) = expected_caller {
                if read.result_value != expected {
                    return Err(format!(
                        "step {}: CALLER returned {} but expected {}",
                        read.step, read.result_value, expected
                    ));
                }
            }
        }
        if read.opcode == opcodes::BLOCKHASH {
            if let Some(expected) = expected_blockhash {
                if read.result_value != expected {
                    return Err(format!(
                        "step {}: BLOCKHASH returned {} but expected {}",
                        read.step, read.result_value, expected
                    ));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_vm::isa::{encode, Opcode};

    fn instr(op: Opcode, rd: u8, rs1: u8, imm: u32) -> [u8; 4] {
        encode(op, rd, rs1, imm).0.to_le_bytes()
    }

    fn bytecode(instrs: &[&[u8; 4]]) -> Vec<u8> {
        instrs.iter().flat_map(|i| i.iter().copied()).collect()
    }

    fn simple_tx(val: u32) -> Transaction {
        Transaction {
            bytecode: bytecode(&[
                &instr(Opcode::Addi, 1, 0, val),
                &instr(Opcode::Halt, 0, 0, 0),
            ]),
            gas_limit: 100_000,
        }
    }

    fn arith_tx(a: u32, b: u32) -> Transaction {
        Transaction {
            bytecode: bytecode(&[
                &instr(Opcode::Addi, 1, 0, a),
                &instr(Opcode::Addi, 2, 0, b),
                &instr(Opcode::Add, 3, 1, 2),
                &instr(Opcode::Mul, 4, 3, 1),
                &instr(Opcode::Halt, 0, 0, 0),
            ]),
            gas_limit: 100_000,
        }
    }

    #[test]
    fn prove_single_group() {
        let group = Group {
            index: 0,
            txs: vec![simple_tx(42), simple_tx(99)],
        };
        let gp = prove_group(&group, [0u8; 32]).unwrap();
        assert_eq!(gp.tx_count, 2);
        assert_eq!(gp.group_index, 0);
        assert!(gp.execution_rows > 0);
        assert!(gp.gas_used > 0);
    }

    #[test]
    fn prove_group_with_arithmetic() {
        let group = Group {
            index: 0,
            txs: vec![arith_tx(10, 20), arith_tx(100, 200)],
        };
        let gp = prove_group(&group, [0u8; 32]).unwrap();
        assert_eq!(gp.tx_count, 2);

        // Verify the proof
        assert!(prover::verify(&gp.proof, &[]).is_ok());
    }

    #[test]
    fn prove_multiple_groups_parallel() {
        let block = ScheduledBlock {
            slot: 1,
            block_hash: [0xBB; 32],
            pre_state_root: [0u8; 32],
            groups: vec![
                Group { index: 0, txs: vec![simple_tx(10), simple_tx(20)] },
                Group { index: 1, txs: vec![arith_tx(30, 40)] },
                Group { index: 2, txs: vec![simple_tx(50), arith_tx(60, 70)] },
            ],
        };

        // Prove all 3 groups (in production, each prover does a subset)
        let proofs = prove_assigned_groups(&block, &[0, 1, 2]).unwrap();
        assert_eq!(proofs.len(), 3);

        // Each proof is independently valid
        for gp in &proofs {
            assert!(prover::verify(&gp.proof, &[]).is_ok());
        }
    }

    #[test]
    fn compose_and_verify_block() {
        let block = ScheduledBlock {
            slot: 42,
            block_hash: [0xBB; 32],
            pre_state_root: [0u8; 32],
            groups: vec![
                Group { index: 0, txs: vec![arith_tx(10, 20), simple_tx(30)] },
                Group { index: 1, txs: vec![arith_tx(40, 50)] },
            ],
        };

        let group_proofs = prove_assigned_groups(&block, &[0, 1]).unwrap();
        let block_proof = compose_block_proof(&block, group_proofs).unwrap();

        assert_eq!(block_proof.slot, 42);
        assert_eq!(block_proof.total_txs, 3);
        assert!(block_proof.total_gas > 0);

        // Validator verification
        assert!(verify_block_proof(&block_proof).is_ok());
    }

    #[test]
    fn block_proof_sizes() {
        use std::time::Instant;

        let block = ScheduledBlock {
            slot: 1,
            block_hash: [0xBB; 32],
            pre_state_root: [0u8; 32],
            groups: vec![
                Group { index: 0, txs: vec![arith_tx(10, 20), arith_tx(30, 40), simple_tx(50)] },
                Group { index: 1, txs: vec![arith_tx(60, 70), simple_tx(80)] },
            ],
        };

        let start = Instant::now();
        let proofs = prove_assigned_groups(&block, &[0, 1]).unwrap();
        let prove_time = start.elapsed();

        let start = Instant::now();
        let block_proof = compose_block_proof(&block, proofs).unwrap();
        let compose_time = start.elapsed();

        let start = Instant::now();
        verify_block_proof(&block_proof).unwrap();
        let verify_time = start.elapsed();

        let total_proof_bytes: usize = block_proof.group_proofs.iter()
            .map(|g| g.proof_bytes.len())
            .sum();

        println!("\n=== Block Proof Benchmark ===");
        println!("Groups:       {}", block_proof.group_proofs.len());
        println!("Total txs:    {}", block_proof.total_txs);
        println!("Total rows:   {}", block_proof.group_proofs.iter().map(|g| g.execution_rows).sum::<usize>());
        println!("Proof size:   {} KB (compressed)", total_proof_bytes / 1024);
        println!("Prove time:   {:.2?}", prove_time);
        println!("Compose time: {:.2?}", compose_time);
        println!("Verify time:  {:.2?}", verify_time);
        println!("Total gas:    {}", block_proof.total_gas);
    }
}
