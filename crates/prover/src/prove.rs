//! STARK proof generation and verification pipeline.
//!
//! Wires together: ExecutionTrace → RowMajorMatrix → Plonky3 STARK prover.
//! Uses Goldilocks field + Poseidon2 hash (Goldilocks diffusion) + FRI.
//!
//! The proof pipeline:
//! 1. ExecutionTrace → RowMajorMatrix (flatten rows)
//! 2. Configure STARK: Goldilocks + Poseidon2 + FRI
//! 3. prove(config, air, trace, public_values) → Proof
//! 4. verify(config, air, proof, public_values) → Ok/Err

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::AbstractField;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_goldilocks::{DiffusionMatrixGoldilocks, Goldilocks};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{
    prove as stark_prove, verify as stark_verify, Proof, StarkConfig, VerificationError,
};

use crate::air::PvmAir;
use crate::trace::ExecutionTrace;

// === Type aliases for the STARK configuration ===

/// Poseidon2 permutation width. 8 is standard for Goldilocks.
const WIDTH: usize = 8;
/// Sponge rate (elements absorbed per permutation).
const RATE: usize = 4;
/// Digest output elements.
const OUT: usize = 4;
/// Extension field degree for FRI challenges.
type EF = BinomialExtensionField<Goldilocks, 2>;

/// The Poseidon2 permutation type for Goldilocks.
type Perm = Poseidon2<Goldilocks, Poseidon2ExternalMatrixGeneral, DiffusionMatrixGoldilocks, WIDTH, 7>;
/// Hash function (sponge).
type Hash = PaddingFreeSponge<Perm, WIDTH, RATE, OUT>;
/// Compression function for Merkle tree.
type Compress = TruncatedPermutation<Perm, 2, OUT, WIDTH>;
/// Merkle tree MMCS over Goldilocks.
type ValMmcs = FieldMerkleTreeMmcs<
    <Goldilocks as p3_field::Field>::Packing,
    <Goldilocks as p3_field::Field>::Packing,
    Hash,
    Compress,
    OUT,
>;
/// Extension field MMCS.
type ChallengeMmcs = ExtensionMmcs<Goldilocks, EF, ValMmcs>;
/// DFT for polynomial evaluation.
type Dft = Radix2DitParallel;
/// The PCS (polynomial commitment scheme).
type Pcs = TwoAdicFriPcs<Goldilocks, Dft, ValMmcs, ChallengeMmcs>;
/// The challenger (Fiat-Shamir).
type Challenger = DuplexChallenger<Goldilocks, Perm, WIDTH, RATE>;
/// The full STARK config.
type PydeStarkConfig = StarkConfig<Pcs, EF, Challenger>;
/// Proof type alias.
pub type PydeProof = Proof<PydeStarkConfig>;

/// Build the Poseidon2 permutation with Goldilocks-specific parameters.
fn build_perm() -> Perm {
    // Standard parameters: 8 external rounds, 22 internal rounds
    let rounds_f = 8;
    let rounds_p = 22;

    // Deterministic round constants
    let external_constants: Vec<[Goldilocks; WIDTH]> = (0..rounds_f)
        .map(|r| {
            core::array::from_fn(|i| {
                Goldilocks::from_canonical_u64(((r * WIDTH + i) as u64).wrapping_mul(0x9e3779b97f4a7c15) + 1)
            })
        })
        .collect();

    let internal_constants: Vec<Goldilocks> = (0..rounds_p)
        .map(|r| Goldilocks::from_canonical_u64((r as u64).wrapping_mul(0x517cc1b727220a95) + 1))
        .collect();

    Poseidon2::new(
        rounds_f,
        external_constants,
        Poseidon2ExternalMatrixGeneral,
        rounds_p,
        internal_constants,
        DiffusionMatrixGoldilocks,
    )
}

/// Build the full STARK proving configuration.
pub fn build_config() -> PydeStarkConfig {
    let perm = build_perm();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft {};

    let fri_config = FriConfig {
        log_blowup: 4, // Supports high-degree constraints (bitwise: opcode selector * 64 bit sums)
        num_queries: 30,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };

    let pcs = Pcs::new(dft, val_mmcs, fri_config);
    StarkConfig::new(pcs)
}

/// Build a Fiat-Shamir challenger.
pub fn build_challenger() -> Challenger {
    let perm = build_perm();
    DuplexChallenger::new(perm)
}

/// Convert an ExecutionTrace to a Plonky3 RowMajorMatrix.
pub fn trace_to_matrix(trace: &ExecutionTrace) -> RowMajorMatrix<Goldilocks> {
    let num_rows = trace.rows.len();
    let num_cols = crate::trace::TraceRow::NUM_COLUMNS;

    let mut values = Vec::with_capacity(num_rows * num_cols);
    for row in &trace.rows {
        values.extend_from_slice(&row.to_fields());
    }

    RowMajorMatrix::new(values, num_cols)
}

/// Prepare a trace for proving: pad to power of 2 and convert to matrix.
pub fn prepare_trace(trace: &mut ExecutionTrace) -> RowMajorMatrix<Goldilocks> {
    trace.pad_to_power_of_two();
    trace_to_matrix(trace)
}

/// Generate a STARK proof for a PVM execution trace.
pub fn generate_proof(
    trace: &mut ExecutionTrace,
    public_values: &[Goldilocks],
) -> PydeProof {
    let config = build_config();
    let air = PvmAir::new();
    let mut challenger = build_challenger();
    let matrix = prepare_trace(trace);

    stark_prove(&config, &air, &mut challenger, matrix, &public_values.to_vec())
}

/// Verify a STARK proof.
pub fn verify_proof(
    proof: &PydeProof,
    public_values: &[Goldilocks],
) -> Result<(), VerificationError<p3_uni_stark::PcsError<PydeStarkConfig>>> {
    let config = build_config();
    let air = PvmAir::new();
    let mut challenger = build_challenger();

    stark_verify(&config, &air, &mut challenger, proof, &public_values.to_vec())
}

/// Serialize a proof to JSON bytes (for network transmission).
pub fn serialize_proof(proof: &PydeProof) -> Result<Vec<u8>, String> {
    serde_json::to_vec(proof).map_err(|e| format!("proof serialization failed: {e}"))
}

/// Deserialize a proof from JSON bytes.
pub fn deserialize_proof(bytes: &[u8]) -> Result<PydeProof, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("proof deserialization failed: {e}"))
}

/// Public inputs to the STARK proof.
#[derive(Clone, Debug)]
pub struct PublicInputs {
    /// Pre-execution state root.
    pub pre_state_root: [u8; 32],
    /// Post-execution state root (committed by the proof).
    pub post_state_root: [u8; 32],
    /// Transaction hash (what was executed).
    pub tx_hash: [u8; 32],
    /// Gas used.
    pub gas_used: u64,
}

impl PublicInputs {
    /// Convert to field elements for the proof.
    pub fn to_fields(&self) -> Vec<Goldilocks> {
        let mut fields = Vec::with_capacity(13); // 4 pre_root + 4 post_root + 4 tx_hash + 1 gas
        for i in 0..4 {
            fields.push(Goldilocks::from_canonical_u64(u64::from_le_bytes(
                self.pre_state_root[i * 8..(i + 1) * 8].try_into().unwrap(),
            )));
        }
        for i in 0..4 {
            fields.push(Goldilocks::from_canonical_u64(u64::from_le_bytes(
                self.post_state_root[i * 8..(i + 1) * 8].try_into().unwrap(),
            )));
        }
        for i in 0..4 {
            fields.push(Goldilocks::from_canonical_u64(u64::from_le_bytes(
                self.tx_hash[i * 8..(i + 1) * 8].try_into().unwrap(),
            )));
        }
        fields.push(Goldilocks::from_canonical_u64(self.gas_used));
        fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{to_field, TraceRow};

    /// Set opcode_bits and register selectors for a trace row.
    fn setup_row(row: &mut TraceRow, opcode: u64, rd: u8, rs1: u8, rs2: u8) {
        row.opcode = to_field(opcode);
        row.rd = to_field(rd as u64);
        row.rs1 = to_field(rs1 as u64);
        for i in 0..6 {
            row.opcode_bits[i] = if (opcode >> i) & 1 == 1 {
                Goldilocks::one()
            } else {
                Goldilocks::zero()
            };
        }
        // Register selectors (one-hot)
        if (rd as usize) < 16 {
            row.rd_sel[rd as usize] = Goldilocks::one();
        }
        if (rs1 as usize) < 16 {
            row.rs1_sel[rs1 as usize] = Goldilocks::one();
        }
        if (rs2 as usize) < 16 {
            row.rs2_sel[rs2 as usize] = Goldilocks::one();
        }
    }

    fn minimal_trace() -> ExecutionTrace {
        let mut trace = ExecutionTrace::new();

        let mut cumulative = 0u64;
        for i in 0..15u64 {
            let step_gas = 3;
            cumulative += step_gas;
            let mut row = TraceRow::zero();
            row.pc = to_field(i * 4);
            setup_row(&mut row, 0x0E, 1, 0, 0); // ADDI r1, r0, imm
            row.op_a = to_field(0); // gp[r0] = 0
            row.gas_step = to_field(step_gas);
            row.gas_cumulative = to_field(cumulative);
            trace.push(row);
        }
        let mut last = TraceRow::zero();
        last.pc = to_field(15 * 4);
        setup_row(&mut last, 0x2C, 0, 0, 0); // HALT
        last.gas_step = to_field(3);
        cumulative += 3;
        last.gas_cumulative = to_field(cumulative);
        last.is_final = Goldilocks::one();
        trace.push(last);

        trace
    }

    #[test]
    fn build_config_succeeds() {
        let _config = build_config();
    }

    #[test]
    fn trace_to_matrix_correct_dimensions() {
        let trace = minimal_trace();
        let matrix = trace_to_matrix(&trace);
        assert_eq!(matrix.height(), 16);
        assert_eq!(matrix.width, 861);
    }

    #[test]
    fn trace_to_matrix_values_preserved() {
        let trace = minimal_trace();
        let matrix = trace_to_matrix(&trace);
        // Row 0: gas_step=3, gas_cumulative=3
        assert_eq!(matrix.get(0, 70), to_field(3));   // gas_step
        assert_eq!(matrix.get(0, 71), to_field(3));   // gas_cumulative
        // Row 1: gas_cumulative=6
        assert_eq!(matrix.get(1, 71), to_field(6));
        // Last row (15): is_final=1
        assert_eq!(matrix.get(15, 74), Goldilocks::one());
    }

    #[test]
    fn prepare_trace_pads() {
        let mut trace = ExecutionTrace::new();
        for i in 0..5u64 {
            let mut row = TraceRow::zero();
            row.gas_step = to_field(i + 1);
            row.gas_cumulative = to_field((i + 1) * (i + 2) / 2);
            trace.push(row);
        }
        let matrix = prepare_trace(&mut trace);
        assert_eq!(matrix.height(), 8);
        assert_eq!(matrix.width, 861);
    }

    #[test]
    fn public_inputs_to_fields() {
        let pi = PublicInputs {
            pre_state_root: [0xAA; 32],
            post_state_root: [0xBB; 32],
            tx_hash: [0xCC; 32],
            gas_used: 21000,
        };
        let fields = pi.to_fields();
        assert_eq!(fields.len(), 13);
        assert_eq!(fields[12], Goldilocks::from_canonical_u64(21000));
    }

    #[test]
    fn prove_and_verify_minimal() {
        let mut trace = minimal_trace();
        let proof = generate_proof(&mut trace, &[]);
        let result = verify_proof(&proof, &[]);
        assert!(result.is_ok(), "verification failed: {:?}", result.err());
    }

    #[test]
    fn prove_and_verify_longer_trace() {
        let mut trace = ExecutionTrace::new();
        let mut cumulative = 0u64;
        for i in 0..31u64 {
            let step_gas = 3 + (i % 5);
            cumulative += step_gas;
            let mut row = TraceRow::zero();
            row.pc = to_field(i * 4);
            setup_row(&mut row, 0x0E, 1, 0, 0); // ADDI r1, r0, imm
            row.op_a = to_field(0);
            row.gas_step = to_field(step_gas);
            row.gas_cumulative = to_field(cumulative);
            trace.push(row);
        }
        let mut last = TraceRow::zero();
        last.pc = to_field(31 * 4);
        setup_row(&mut last, 0x2C, 0, 0, 0);
        last.gas_step = to_field(3);
        cumulative += 3;
        last.gas_cumulative = to_field(cumulative);
        last.is_final = Goldilocks::one();
        trace.push(last);

        let proof = generate_proof(&mut trace, &[]);
        assert!(verify_proof(&proof, &[]).is_ok());
    }

    #[test]
    fn tampered_trace_fails() {
        let mut trace = ExecutionTrace::new();

        let mut cumulative = 0u64;
        for i in 0..15u64 {
            cumulative += 3;
            let mut row = TraceRow::zero();
            row.pc = to_field(i * 4);
            setup_row(&mut row, 0x0E, 1, 0, 0);
            row.op_a = to_field(0);
            row.gas_step = to_field(3);
            row.gas_cumulative = to_field(cumulative);
            trace.push(row);
        }
        let mut last = TraceRow::zero();
        last.pc = to_field(15 * 4);
        setup_row(&mut last, 0x2C, 0, 0, 0);
        last.gas_step = to_field(3);
        last.gas_cumulative = to_field(99999); // WRONG
        last.is_final = Goldilocks::one();
        trace.push(last);

        // This should either panic during proving (debug) or produce
        // a proof that fails verification
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            generate_proof(&mut trace, &[])
        }));

        // In debug mode, Plonky3 checks constraints and panics on violation
        // In release mode, the proof would be generated but fail verification
        if let Ok(proof) = result {
            assert!(verify_proof(&proof, &[]).is_err());
        }
        // If it panicked, that's also correct behavior (constraint check caught it)
    }

    #[test]
    fn proof_serialize_deserialize_roundtrip() {
        let mut trace = minimal_trace();
        let proof = generate_proof(&mut trace, &[]);

        let bytes = serialize_proof(&proof).unwrap();
        assert!(!bytes.is_empty());

        let restored = deserialize_proof(&bytes).unwrap();
        // Verify the deserialized proof
        assert!(verify_proof(&restored, &[]).is_ok());
    }

    #[test]
    fn proof_from_recorder() {
        // End-to-end: PVM execution → trace recording → STARK proof
        use pyde_vm::isa::{encode, Opcode};
        use pyde_vm::vm::Vm;
        use crate::recorder::record_execution;

        let instr = |op: Opcode, rd: u8, rs1: u8, imm: u32| -> [u8; 4] {
            encode(op, rd, rs1, imm).0.to_le_bytes()
        };

        let code: Vec<u8> = [
            instr(Opcode::Addi, 1, 0, 42),
            instr(Opcode::Addi, 2, 0, 58),
            instr(Opcode::Add, 3, 1, 2),
            instr(Opcode::Halt, 0, 0, 0),
        ]
        .iter()
        .flat_map(|i| i.iter().copied())
        .collect();

        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();

        let (mut trace, outcome) = record_execution(&mut vm);
        assert_eq!(outcome, pyde_vm::vm::Outcome::Success);

        // Generate and verify STARK proof of this execution
        let proof = generate_proof(&mut trace, &[]);
        assert!(verify_proof(&proof, &[]).is_ok());
    }

    #[test]
    fn bench_proof_generation_time() {
        use std::time::Instant;
        use pyde_vm::isa::{encode, Opcode};
        use pyde_vm::vm::Vm;
        use crate::recorder::record_execution;

        let instr = |op: Opcode, rd: u8, rs1: u8, imm: u32| -> [u8; 4] {
            encode(op, rd, rs1, imm).0.to_le_bytes()
        };

        // ~16 instruction program (simulates a simple token transfer)
        let code: Vec<u8> = [
            instr(Opcode::Addi, 1, 0, 10000),
            instr(Opcode::Addi, 2, 0, 5000),
            instr(Opcode::Addi, 3, 0, 250),
            instr(Opcode::Sub, 5, 1, 3),
            instr(Opcode::Add, 6, 2, 3),
            instr(Opcode::Mul, 7, 5, 6),
            instr(Opcode::Xor, 8, 7, 3),
            instr(Opcode::Shr, 9, 8, 3),
            instr(Opcode::And, 10, 9, 1),
            instr(Opcode::Or, 11, 10, 2),
            instr(Opcode::Add, 12, 11, 5),
            instr(Opcode::Sub, 13, 12, 6),
            instr(Opcode::Mul, 14, 13, 7),
            instr(Opcode::Lt, 15, 14, 1),
            instr(Opcode::Add, 1, 15, 3),
            instr(Opcode::Halt, 0, 0, 0),
        ]
        .iter()
        .flat_map(|i| i.iter().copied())
        .collect();

        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();
        let (mut trace, _) = record_execution(&mut vm);

        let trace_rows = trace.len();

        // Benchmark proof generation
        let start = Instant::now();
        let proof = generate_proof(&mut trace, &[]);
        let prove_time = start.elapsed();

        // Benchmark verification
        let start = Instant::now();
        let result = verify_proof(&proof, &[]);
        let verify_time = start.elapsed();

        assert!(result.is_ok());

        // Benchmark proof size
        let proof_bytes = serialize_proof(&proof).unwrap();
        let proof_size_kb = proof_bytes.len() as f64 / 1024.0;

        println!("\n=== STARK Proof Benchmark ===");
        println!("Trace rows:      {trace_rows} (padded to {})", trace.len());
        println!("Prove time:      {:.2?}", prove_time);
        println!("Verify time:     {:.2?}", verify_time);
        println!("Proof size:      {:.1} KB ({} bytes)", proof_size_kb, proof_bytes.len());
        println!();
    }

    // ========== M8.9: Proof Verification tests ==========

    #[test]
    fn wrong_public_inputs_fails() {
        // Generate proof with no public inputs
        let mut trace = minimal_trace();
        let proof = generate_proof(&mut trace, &[]);

        // Verify with WRONG public inputs — should fail (panic or Err)
        let wrong_pi = vec![Goldilocks::from_canonical_u64(999)];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_proof(&proof, &wrong_pi)
        }));

        // Either panicked (dimension mismatch) or returned Err
        match result {
            Err(_) => {} // panicked — expected
            Ok(Err(_)) => {} // returned error — expected
            Ok(Ok(_)) => panic!("should fail with wrong public inputs"),
        }
    }

    #[test]
    fn batch_verify_multiple_proofs() {
        // Generate multiple proofs and verify all
        let mut results = Vec::new();

        for gas_base in [3u64, 5, 7] {
            let mut trace = ExecutionTrace::new();
            let mut cumulative = 0u64;
            for i in 0..15u64 {
                cumulative += gas_base;
                let mut row = TraceRow::zero();
                row.pc = to_field(i * 4);
                setup_row(&mut row, 0x0E, 1, 0, 0);
                row.op_a = to_field(0);
                row.gas_step = to_field(gas_base);
                row.gas_cumulative = to_field(cumulative);
                trace.push(row);
            }
            let mut last = TraceRow::zero();
            last.pc = to_field(15 * 4);
            setup_row(&mut last, 0x2C, 0, 0, 0);
            last.gas_step = to_field(gas_base);
            cumulative += gas_base;
            last.gas_cumulative = to_field(cumulative);
            last.is_final = Goldilocks::one();
            trace.push(last);

            let proof = generate_proof(&mut trace, &[]);
            results.push(verify_proof(&proof, &[]));
        }

        // All 3 proofs should verify
        for (i, r) in results.iter().enumerate() {
            assert!(r.is_ok(), "proof {} failed", i);
        }
    }

    #[test]
    fn public_inputs_extraction() {
        let pi = PublicInputs {
            pre_state_root: [0x11; 32],
            post_state_root: [0x22; 32],
            tx_hash: [0x33; 32],
            gas_used: 42000,
        };

        let fields = pi.to_fields();
        assert_eq!(fields.len(), 13);

        // Pre-state root limbs
        for i in 0..4 {
            assert_eq!(fields[i], Goldilocks::from_canonical_u64(
                u64::from_le_bytes([0x11; 8])
            ));
        }
        // Post-state root limbs
        for i in 4..8 {
            assert_eq!(fields[i], Goldilocks::from_canonical_u64(
                u64::from_le_bytes([0x22; 8])
            ));
        }
        // Gas
        assert_eq!(fields[12], Goldilocks::from_canonical_u64(42000));
    }
}
