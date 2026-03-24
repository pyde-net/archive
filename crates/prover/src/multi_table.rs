//! Multi-table orchestration: combines execution proof with cross-table verifications.
//!
//! A complete group proof consists of:
//! 1. Execution STARK proof (144-column trace)
//! 2. Memory consistency verification (read-after-write)
//! 3. Bitwise lookup verification (AND/OR/XOR/NOT correctness)
//! 4. Hash bus verification (Poseidon2 hash correctness)
//! 5. Range-check verification (u64 validity for diffs/shifts/carries)

use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;

use crate::constraint::opcodes;
use crate::hash_bus;
use crate::lookup;
use crate::memory_air;
use crate::prover::{self, PydeProof};
use crate::range_check;
use crate::recorder;
use crate::trace::{col, ExecutionTrace};

use pyde_vm::vm::Vm;

/// Complete multi-table proof for a group of transactions.
pub struct MultiTableProof {
    /// Execution STARK proof.
    pub execution_proof: PydeProof,
    /// Serialized proof (compressed).
    pub proof_bytes: Vec<u8>,
    /// Execution trace row count.
    pub execution_rows: usize,
    /// Memory consistency verified.
    pub memory_ok: bool,
    /// Number of memory accesses.
    pub memory_access_count: usize,
    /// Bitwise lookup verified.
    pub lookup_ok: bool,
    /// Number of lookup queries.
    pub lookup_query_count: usize,
    /// Hash bus verified.
    pub hash_ok: bool,
    /// Number of hash requests.
    pub hash_request_count: usize,
    /// Range-check verified.
    pub range_check_ok: bool,
    /// Number of range-check requests.
    pub range_check_count: usize,
    /// Total gas used.
    pub gas_used: u64,
}

/// Record execution and generate a complete multi-table proof.
pub fn prove_single_tx(vm: &mut Vm) -> Result<MultiTableProof, String> {
    let (trace, _outcome) = recorder::record_execution(vm);
    prove_from_trace(trace, vm.gas_used_total)
}

/// Generate a complete multi-table proof from a pre-recorded trace.
pub fn prove_from_trace(mut trace: ExecutionTrace, gas_used: u64) -> Result<MultiTableProof, String> {
    let execution_rows = trace.len();

    // 1. Extract all cross-table data from the trace BEFORE proving
    let memory_accesses = memory_air::extract_memory_accesses(&trace);
    let hash_requests = hash_bus::extract_hash_requests(&trace);
    let range_requests = range_check::extract_range_check_requests(&trace);
    let lookup_queries = extract_lookup_queries(&trace);

    // 2. Generate execution STARK proof
    let execution_proof = prover::prove(&mut trace, &[]);
    let proof_bytes = prover::serialize_proof(&execution_proof)
        .map_err(|e| format!("serialize: {e}"))?;

    // 3. Verify memory consistency
    let memory_trace = memory_air::MemoryTrace::from_accesses(&memory_accesses);
    let memory_ok = memory_air::verify_memory(&memory_accesses, &memory_trace).is_ok();

    // 4. Verify bitwise lookups
    let lookup_ok = lookup::verify_bitwise_queries(&lookup_queries);

    // 5. Verify hash bus
    let hash_ok = hash_bus::verify_hash_bus(&hash_requests).is_ok();

    // 6. Verify range checks
    let mut rc_trace = range_check::RangeCheckTrace::new();
    for req in &range_requests {
        rc_trace.add(req.value);
    }
    let range_check_ok = rc_trace.verify();

    Ok(MultiTableProof {
        execution_proof,
        proof_bytes,
        execution_rows,
        memory_ok,
        memory_access_count: memory_accesses.len(),
        lookup_ok,
        lookup_query_count: lookup_queries.len(),
        hash_ok,
        hash_request_count: hash_requests.len(),
        range_check_ok,
        range_check_count: range_requests.len(),
        gas_used,
    })
}

/// Verify a complete multi-table proof.
pub fn verify_multi_table(proof: &MultiTableProof) -> Result<(), String> {
    // 1. Verify execution STARK
    prover::verify(&proof.execution_proof, &[])
        .map_err(|_| "execution STARK verification failed".to_string())?;

    // 2. Check all cross-table verifications passed
    if !proof.memory_ok {
        return Err("memory consistency verification failed".to_string());
    }
    if !proof.lookup_ok {
        return Err("bitwise lookup verification failed".to_string());
    }
    if !proof.hash_ok {
        return Err("hash bus verification failed".to_string());
    }
    if !proof.range_check_ok {
        return Err("range-check verification failed".to_string());
    }

    Ok(())
}

/// Extract bitwise lookup queries from an execution trace.
fn extract_lookup_queries(trace: &ExecutionTrace) -> Vec<lookup::LookupQuery> {
    let mut queries = Vec::new();

    for row in &trace.rows {
        let op = row.get(col::OPCODE).as_canonical_u64();
        let op_a = row.get(col::OP_A).as_canonical_u64();
        let op_b = row.get(col::OP_B).as_canonical_u64();
        let result = row.get(col::OP_RESULT).as_canonical_u64();

        // GP bitwise
        if let Some(q) = lookup::collect_bitwise_queries(op, op_a, op_b, result) {
            queries.extend(q);
        }

        // Wide bitwise
        if op == opcodes::WAND || op == opcodes::WOR || op == opcodes::WXOR || op == opcodes::WNOT {
            let rd = row.get(col::RD).as_canonical_u64() as usize & 7;
            let rs1 = row.get(col::RS1).as_canonical_u64() as usize & 7;
            let rs2_imm = row.get(col::RS2_IMM).as_canonical_u64() as usize & 7;

            let a_limbs: [u64; 4] = core::array::from_fn(|i| {
                row.get(col::wide(rs1, i)).as_canonical_u64()
            });
            let b_limbs: [u64; 4] = if op == opcodes::WNOT {
                [0; 4] // NOT doesn't use second operand
            } else {
                core::array::from_fn(|i| row.get(col::wide(rs2_imm, i)).as_canonical_u64())
            };
            let result_limbs: [u64; 4] = core::array::from_fn(|i| {
                row.get(col::wide(rd, i)).as_canonical_u64()
            });

            if let Some(q) = lookup::collect_wide_bitwise_queries(op, &a_limbs, &b_limbs, &result_limbs) {
                queries.extend(q);
            }
        }
    }

    queries
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_vm::isa::{encode, encode_mem_immediate, MemWidth, Opcode};

    fn instr(op: Opcode, rd: u8, rs1: u8, imm: u32) -> [u8; 4] {
        encode(op, rd, rs1, imm).0.to_le_bytes()
    }

    fn bytecode(instrs: &[&[u8; 4]]) -> Vec<u8> {
        instrs.iter().flat_map(|i| i.iter().copied()).collect()
    }

    #[test]
    fn prove_and_verify_arithmetic() {
        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 100),
            &instr(Opcode::Addi, 2, 0, 7),
            &instr(Opcode::Add, 3, 1, 2),
            &instr(Opcode::Mul, 4, 3, 1),
            &instr(Opcode::Div, 5, 4, 2),
            &instr(Opcode::Sub, 6, 5, 3),
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();

        let proof = prove_single_tx(&mut vm).unwrap();
        assert!(verify_multi_table(&proof).is_ok());
        assert_eq!(proof.execution_rows, 7);
        assert!(proof.memory_ok);
        assert!(proof.lookup_ok);
        assert!(proof.range_check_ok);
    }

    #[test]
    fn prove_and_verify_with_memory() {
        let store_imm = encode_mem_immediate(0, MemWidth::W64);
        let load_imm = encode_mem_immediate(0, MemWidth::W64);

        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 0x010000),
            &instr(Opcode::Addi, 2, 0, 42),
            &instr(Opcode::Store, 2, 1, store_imm),
            &instr(Opcode::Load, 3, 1, load_imm),
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();

        let proof = prove_single_tx(&mut vm).unwrap();
        assert!(verify_multi_table(&proof).is_ok());
        assert!(proof.memory_ok);
        assert!(proof.memory_access_count > 0);
    }

    #[test]
    fn prove_and_verify_with_comparison() {
        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 10),
            &instr(Opcode::Addi, 2, 0, 20),
            &instr(Opcode::Lt, 3, 1, 2),  // 10 < 20 = 1
            &instr(Opcode::Gt, 4, 1, 2),  // 10 > 20 = 0
            &instr(Opcode::Eq, 5, 1, 1),  // 10 == 10 = 1
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();

        let proof = prove_single_tx(&mut vm).unwrap();
        assert!(verify_multi_table(&proof).is_ok());
        assert!(proof.range_check_ok);
        assert!(proof.range_check_count > 0); // comparison diffs range-checked
    }

    #[test]
    fn prove_and_verify_with_shifts() {
        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 1000),
            &instr(Opcode::Addi, 2, 0, 3),
            &instr(Opcode::Shl, 3, 1, 2),  // 1000 << 3 = 8000
            &instr(Opcode::Shr, 4, 3, 2),  // 8000 >> 3 = 1000
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();

        let proof = prove_single_tx(&mut vm).unwrap();
        assert!(verify_multi_table(&proof).is_ok());
    }

    #[test]
    fn prove_and_verify_with_branch() {
        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 10),
            &instr(Opcode::Addi, 2, 0, 5),
            &instr(Opcode::Bge, 1, 2, 8),
            &instr(Opcode::Halt, 0, 0, 0), // skipped
            &instr(Opcode::Addi, 3, 0, 99),
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();

        let proof = prove_single_tx(&mut vm).unwrap();
        assert!(verify_multi_table(&proof).is_ok());
    }

    #[test]
    fn prove_mixed_program() {
        let store_imm = encode_mem_immediate(0, MemWidth::W64);

        let code = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 1000),
            &instr(Opcode::Addi, 2, 0, 250),
            &instr(Opcode::Sub, 3, 1, 2),           // 750
            &instr(Opcode::Add, 4, 3, 2),           // 1000
            &instr(Opcode::Mul, 5, 3, 2),           // 187500
            &instr(Opcode::Addi, 6, 0, 100),
            &instr(Opcode::Div, 7, 5, 6),           // 1875
            &instr(Opcode::Lt, 8, 7, 1),            // 1875 < 1000 = 0
            &instr(Opcode::Addi, 9, 0, 0x010000),
            &instr(Opcode::Store, 7, 9, store_imm), // store 1875
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();

        let proof = prove_single_tx(&mut vm).unwrap();
        let result = verify_multi_table(&proof);
        assert!(result.is_ok(), "Mixed program failed: {:?}", result);

        println!("Mixed program proof:");
        println!("  Rows:          {}", proof.execution_rows);
        println!("  Memory ops:    {}", proof.memory_access_count);
        println!("  Lookup queries: {}", proof.lookup_query_count);
        println!("  Hash requests: {}", proof.hash_request_count);
        println!("  Range checks:  {}", proof.range_check_count);
        println!("  Proof size:    {} KB", proof.proof_bytes.len() / 1024);
    }

    #[test]
    fn prove_group_multi_table() {
        let code1 = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 42),
            &instr(Opcode::Addi, 2, 0, 58),
            &instr(Opcode::Add, 3, 1, 2),
            &instr(Opcode::Halt, 0, 0, 0),
        ]);
        let code2 = bytecode(&[
            &instr(Opcode::Addi, 1, 0, 100),
            &instr(Opcode::Addi, 2, 0, 7),
            &instr(Opcode::Div, 3, 1, 2),
            &instr(Opcode::Halt, 0, 0, 0),
        ]);

        // Record both txs and concatenate
        let mut combined = ExecutionTrace::new();
        let mut total_gas = 0;

        for code in [code1, code2] {
            let mut vm = Vm::with_gas_limit(100_000);
            vm.load(&code).unwrap();
            let (trace, _) = recorder::record_execution(&mut vm);
            total_gas += vm.gas_used_total;
            for row in &trace.rows {
                combined.push(row.clone());
            }
        }

        let proof = prove_from_trace(combined, total_gas).unwrap();
        assert!(verify_multi_table(&proof).is_ok());
        assert_eq!(proof.execution_rows, 8); // 4 + 4
    }
}
