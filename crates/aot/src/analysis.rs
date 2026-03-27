//! Basic block analysis of PVM bytecode.
//!
//! Splits bytecode into basic blocks for efficient compilation. A basic block
//! is a maximal sequence of instructions with one entry and one exit.

use pyde_vm::isa::{
    decode, sign_extend_18, total_gas, DecodedInstruction, Instruction, Opcode,
};

/// A basic block in the PVM bytecode.
#[derive(Clone, Debug)]
pub struct BasicBlock {
    /// Byte offset of the first instruction in this block.
    pub start_pc: u32,
    /// Decoded instructions in this block.
    pub instructions: Vec<DecodedInstruction>,
    /// Total gas cost for the entire block (precomputed for block-level gas check).
    pub gas_cost: u64,
}

/// Result of AOT analysis: the bytecode broken into basic blocks.
#[derive(Clone, Debug)]
pub struct AnalyzedProgram {
    /// Basic blocks in program order.
    pub blocks: Vec<BasicBlock>,
    /// All decoded instructions (flat).
    pub decoded: Vec<DecodedInstruction>,
    /// Total instruction count.
    pub instruction_count: usize,
    /// Poseidon2 hash of the bytecode.
    pub bytecode_hash: [u8; 32],
}

/// Errors during analysis.
#[derive(Debug)]
pub enum AnalysisError {
    EmptyBytecode,
    UnalignedBytecode,
}

impl std::fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalysisError::EmptyBytecode => write!(f, "empty bytecode"),
            AnalysisError::UnalignedBytecode => {
                write!(f, "bytecode length not aligned to 4 bytes")
            }
        }
    }
}

impl std::error::Error for AnalysisError {}

/// Returns true if the opcode is a block terminator (branches, jumps, halt, revert, ret).
fn is_terminator(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Jmp
            | Opcode::Beq
            | Opcode::Bne
            | Opcode::Blt
            | Opcode::Bge
            | Opcode::Call
            | Opcode::Ret
            | Opcode::Halt
            | Opcode::Revert
    )
}

/// Returns true if the opcode is a branch (conditional or unconditional with a target).
fn has_branch_target(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Jmp
            | Opcode::Beq
            | Opcode::Bne
            | Opcode::Blt
            | Opcode::Bge
            | Opcode::Call
    )
}

/// Analyze PVM bytecode into basic blocks for compilation.
pub fn analyze(bytecode: &[u8]) -> Result<AnalyzedProgram, AnalysisError> {
    if bytecode.is_empty() {
        return Err(AnalysisError::EmptyBytecode);
    }
    if bytecode.len() % 4 != 0 {
        return Err(AnalysisError::UnalignedBytecode);
    }

    let num_instrs = bytecode.len() / 4;

    // Decode all instructions
    let decoded: Vec<DecodedInstruction> = (0..num_instrs)
        .map(|i| {
            let word = u32::from_le_bytes([
                bytecode[i * 4],
                bytecode[i * 4 + 1],
                bytecode[i * 4 + 2],
                bytecode[i * 4 + 3],
            ]);
            decode(Instruction(word))
        })
        .collect();

    // Find basic block boundaries
    let mut block_starts = std::collections::BTreeSet::new();
    block_starts.insert(0u32);

    for (i, d) in decoded.iter().enumerate() {
        let pc = (i * 4) as u32;

        if is_terminator(d.opcode) {
            // Instruction after a terminator starts a new block
            let next_pc = pc + 4;
            if (next_pc as usize) < bytecode.len() {
                block_starts.insert(next_pc);
            }
        }

        if has_branch_target(d.opcode) {
            let offset = sign_extend_18(d.rs2_or_imm);
            let target = pc.wrapping_add(offset as u32);
            if (target as usize) < bytecode.len() {
                block_starts.insert(target);
            }
        }
    }

    // Build basic blocks
    let starts: Vec<u32> = block_starts.into_iter().collect();
    let mut blocks = Vec::new();

    for (idx, &start) in starts.iter().enumerate() {
        let end = if idx + 1 < starts.len() {
            starts[idx + 1]
        } else {
            bytecode.len() as u32
        };

        let first_instr = (start / 4) as usize;
        let last_instr = (end / 4) as usize;
        let instrs = decoded[first_instr..last_instr].to_vec();

        let block_gas: u64 = instrs.iter().map(|d| total_gas(d.opcode.to_u8())).sum();

        blocks.push(BasicBlock {
            start_pc: start,
            instructions: instrs,
            gas_cost: block_gas,
        });
    }

    let hash = pyde_crypto::poseidon2::poseidon2_hash(bytecode);

    Ok(AnalyzedProgram {
        instruction_count: num_instrs,
        decoded,
        blocks,
        bytecode_hash: hash.to_bytes(),
    })
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

    #[test]
    fn analyze_simple_program() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),
            instr_ri(Opcode::Addi, 2, 0, 20),
            instr_bytes(Opcode::Add, 3, 1, 2),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let program = analyze(&code).unwrap();
        assert_eq!(program.instruction_count, 4);
        assert!(!program.blocks.is_empty());
        assert!(program.blocks[0].gas_cost > 0);
    }

    #[test]
    fn analyze_with_branch_creates_multiple_blocks() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 5),
            instr_ri(Opcode::Beq, 1, 0, 8),
            instr_ri(Opcode::Addi, 2, 0, 10),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let program = analyze(&code).unwrap();
        assert!(program.blocks.len() >= 3);
    }

    #[test]
    fn analyze_loop_detects_back_edge() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),
            instr_ri(Opcode::Addi, 2, 0, 0),
            instr_ri(Opcode::Addi, 2, 2, 1),
            instr_ri(Opcode::Blt, 2, 1, -4),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let program = analyze(&code).unwrap();
        let block_pcs: Vec<u32> = program.blocks.iter().map(|b| b.start_pc).collect();
        assert!(block_pcs.contains(&8));
    }

    #[test]
    fn analyze_empty_bytecode_errors() {
        assert!(analyze(&[]).is_err());
    }

    #[test]
    fn analyze_unaligned_bytecode_errors() {
        assert!(analyze(&[0, 1, 2]).is_err());
    }

    #[test]
    fn analyze_gas_cost_matches_sum() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),
            instr_ri(Opcode::Addi, 2, 0, 20),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let program = analyze(&code).unwrap();
        let total: u64 = program.blocks.iter().map(|b| b.gas_cost).sum();
        assert_eq!(total, 1 + 1 + 1);
    }

    #[test]
    fn bytecode_hash_is_deterministic() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let p1 = analyze(&code).unwrap();
        let p2 = analyze(&code).unwrap();
        assert_eq!(p1.bytecode_hash, p2.bytecode_hash);
        assert_ne!(p1.bytecode_hash, [0u8; 32]);
    }

    #[test]
    fn different_bytecode_different_hash() {
        let code1 = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let code2 = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 99),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let p1 = analyze(&code1).unwrap();
        let p2 = analyze(&code2).unwrap();
        assert_ne!(p1.bytecode_hash, p2.bytecode_hash);
    }
}
