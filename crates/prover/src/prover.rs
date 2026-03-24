//! STARK prover and verifier using our AIR adapter + Plonky3 FRI pipeline.
//!
//! Our constraints are defined in constraint.rs (plain Rust).
//! The AIR adapter (air_adapter.rs) bridges them to Plonky3's prove/verify.
//! This module provides the high-level API.

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
    prove as stark_prove, verify as stark_verify, Proof as StarkProof, StarkConfig,
    VerificationError,
};

use crate::air_adapter::PvmAir;
use crate::trace::{col, ExecutionTrace};

// === Type aliases ===
const WIDTH: usize = 8;
const RATE: usize = 4;
const OUT: usize = 4;

pub type EF = BinomialExtensionField<Goldilocks, 2>;
type Perm = Poseidon2<Goldilocks, Poseidon2ExternalMatrixGeneral, DiffusionMatrixGoldilocks, WIDTH, 7>;
type Hash = PaddingFreeSponge<Perm, WIDTH, RATE, OUT>;
type Compress = TruncatedPermutation<Perm, 2, OUT, WIDTH>;
type ValMmcs = FieldMerkleTreeMmcs<
    <Goldilocks as p3_field::Field>::Packing,
    <Goldilocks as p3_field::Field>::Packing,
    Hash, Compress, OUT,
>;
type ChallengeMmcs = ExtensionMmcs<Goldilocks, EF, ValMmcs>;
type Dft = Radix2DitParallel;
type Pcs = TwoAdicFriPcs<Goldilocks, Dft, ValMmcs, ChallengeMmcs>;
type Challenger = DuplexChallenger<Goldilocks, Perm, WIDTH, RATE>;
type PydeStarkConfig = StarkConfig<Pcs, EF, Challenger>;
pub type PydeProof = StarkProof<PydeStarkConfig>;

fn build_perm() -> Perm {
    let rounds_f = 8;
    let rounds_p = 22;
    let external_constants: Vec<[Goldilocks; WIDTH]> = (0..rounds_f)
        .map(|r| core::array::from_fn(|i| {
            Goldilocks::from_canonical_u64(((r * WIDTH + i) as u64).wrapping_mul(0x9e3779b97f4a7c15) + 1)
        }))
        .collect();
    let internal_constants: Vec<Goldilocks> = (0..rounds_p)
        .map(|r| Goldilocks::from_canonical_u64((r as u64).wrapping_mul(0x517cc1b727220a95) + 1))
        .collect();
    Poseidon2::new(rounds_f, external_constants, Poseidon2ExternalMatrixGeneral, rounds_p, internal_constants, DiffusionMatrixGoldilocks)
}

fn build_config() -> PydeStarkConfig {
    let perm = build_perm();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft {};
    let fri_config = FriConfig {
        log_blowup: 4,   // 16x blowup (supports constraint degree up to 16)
        num_queries: 21,  // ~100-bit security with 16x blowup
        proof_of_work_bits: 10,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_config);
    StarkConfig::new(pcs)
}

fn build_challenger() -> Challenger {
    DuplexChallenger::new(build_perm())
}

/// Generate a STARK proof from an execution trace.
/// Returns Err if the trace violates any constraint.
/// The prover NEVER generates invalid proofs — it validates constraints
/// and self-verifies before returning.
pub fn prove(trace: &mut ExecutionTrace, public_values: &[Goldilocks]) -> Result<PydeProof, String> {
    if trace.is_empty() {
        return Err("empty trace".to_string());
    }

    trace.pad_to_power_of_two();

    // Generate the proof. In debug builds, p3-uni-stark's constraint checker
    // panics on violations (caught below). In release builds, constraint
    // violations produce invalid quotient polynomials that fail self-verification.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let config = build_config();
        let air = PvmAir;
        let mut challenger = build_challenger();
        let values = trace.to_row_major_values();
        let matrix = RowMajorMatrix::new(values, col::NUM_COLUMNS);
        stark_prove(&config, &air, &mut challenger, matrix, &public_values.to_vec())
    }));

    let proof = match result {
        Ok(p) => p,
        Err(_) => return Err("constraint violation detected — invalid trace".to_string()),
    };

    // Self-verify: the prover checks its own proof before returning.
    // This catches release-mode constraint violations that produce
    // invalid FRI proofs (no debug panic, but verifier rejects).
    verify(&proof, public_values)
        .map_err(|_| "self-verification failed — trace has constraint violations".to_string())?;

    Ok(proof)
}

/// Verify a STARK proof.
pub fn verify(
    proof: &PydeProof,
    public_values: &[Goldilocks],
) -> Result<(), VerificationError<p3_uni_stark::PcsError<PydeStarkConfig>>> {
    let config = build_config();
    let air = PvmAir;
    let mut challenger = build_challenger();

    stark_verify(&config, &air, &mut challenger, proof, &public_values.to_vec())
}

/// Serialize proof to compressed binary.
pub fn serialize_proof(proof: &PydeProof) -> Result<Vec<u8>, String> {
    let binary = serde_json::to_vec(proof).map_err(|e| format!("serialize: {e}"))?;
    zstd::encode_all(binary.as_slice(), 3).map_err(|e| format!("compress: {e}"))
}

/// Deserialize proof from compressed binary.
pub fn deserialize_proof(bytes: &[u8]) -> Result<PydeProof, String> {
    let decompressed = zstd::decode_all(bytes).map_err(|e| format!("decompress: {e}"))?;
    serde_json::from_slice(&decompressed).map_err(|e| format!("deserialize: {e}"))
}

/// Public inputs for a group proof.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PublicInputs {
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub tx_hash: [u8; 32],
    pub gas_used: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{to_field, TraceRow};

    fn make_addi_row(pc: u64, rd: u8, rs1: u8, imm: u64, result_val: u64, gas_cum: u64) -> TraceRow {
        let mut row = TraceRow::zero();
        row.set_u64(col::PC, pc);
        row.set_u64(col::OPCODE, 0x0E); // ADDI
        row.set_u64(col::RD, rd as u64);
        row.set_u64(col::RS1, rs1 as u64);
        row.set_u64(col::RS2_IMM, imm);
        row.set_opcode_bits(0x0E);
        row.set_rd_sel(rd);
        row.set_rs1_sel(rs1);
        // op_a = gp[rs1] = 0 (r0 hardwired zero for rs1=0)
        row.set_u64(col::OP_A, 0); // gp[0] = 0
        row.set_u64(col::OP_B, imm);
        row.set_u64(col::OP_RESULT, result_val);
        // gp[rd] = result
        row.fields[col::gp(rd as usize)] = to_field(result_val);
        // Gas
        row.set_u64(col::GAS_STEP, 3);
        row.set_u64(col::GAS_CUMULATIVE, gas_cum);
        row
    }

    fn make_halt_row(pc: u64, gas_cum: u64) -> TraceRow {
        let mut row = TraceRow::zero();
        row.set_u64(col::PC, pc);
        row.set_u64(col::OPCODE, 0x2C); // HALT
        row.set_opcode_bits(0x2C);
        row.set_rd_sel(0);
        row.set_rs1_sel(0);
        row.set_flag(col::IS_FINAL);
        row.set_u64(col::GAS_STEP, 3);
        row.set_u64(col::GAS_CUMULATIVE, gas_cum);
        row
    }

    #[test]
    fn prove_and_verify_minimal() {
        let mut trace = ExecutionTrace::new();

        // 15 ADDI instructions + 1 HALT = 16 rows (power of 2)
        for i in 0..15u64 {
            let row = make_addi_row(i * 4, 1, 0, i + 1, i + 1, (i + 1) * 3);
            trace.push(row);
        }
        trace.push(make_halt_row(15 * 4, 16 * 3));

        let proof = prove(&mut trace, &[]).unwrap();
        let result = verify(&proof, &[]);
        assert!(result.is_ok(), "Verification failed: {:?}", result);
    }

    #[test]
    fn proof_roundtrip() {
        let mut trace = ExecutionTrace::new();
        for i in 0..15u64 {
            trace.push(make_addi_row(i * 4, 1, 0, i + 1, i + 1, (i + 1) * 3));
        }
        trace.push(make_halt_row(15 * 4, 16 * 3));

        let proof = prove(&mut trace, &[]).unwrap();
        let bytes = serialize_proof(&proof).unwrap();
        let restored = deserialize_proof(&bytes).unwrap();
        assert!(verify(&restored, &[]).is_ok());

        println!("Proof size (compressed): {} KB", bytes.len() / 1024);
    }

    #[test]
    fn prove_add_program() {
        let mut trace = ExecutionTrace::new();

        // r1 = 42
        let mut r1 = make_addi_row(0, 1, 0, 42, 42, 3);
        trace.push(r1);

        // r2 = 58
        let mut r2 = make_addi_row(4, 2, 0, 58, 58, 6);
        r2.fields[col::gp(1)] = to_field(42); // r1 persists
        trace.push(r2);

        // r3 = r1 + r2 = 100
        let mut r3 = TraceRow::zero();
        r3.set_u64(col::PC, 8);
        r3.set_u64(col::OPCODE, 0x01); // ADD
        r3.set_u64(col::RD, 3);
        r3.set_u64(col::RS1, 1);
        r3.set_u64(col::RS2_IMM, 2);
        r3.set_opcode_bits(0x01);
        r3.set_rd_sel(3);
        r3.set_rs1_sel(1);
        r3.set_rs2_sel(2); // register-register op
        r3.set_u64(col::OP_A, 42);  // gp[1]
        r3.set_u64(col::OP_B, 58);  // gp[2]
        r3.set_u64(col::OP_RESULT, 100);
        r3.fields[col::gp(1)] = to_field(42);
        r3.fields[col::gp(2)] = to_field(58);
        r3.fields[col::gp(3)] = to_field(100);
        r3.set_u64(col::GAS_STEP, 3);
        r3.set_u64(col::GAS_CUMULATIVE, 9);
        trace.push(r3);

        // HALT
        let mut halt = make_halt_row(12, 12);
        halt.fields[col::gp(1)] = to_field(42);
        halt.fields[col::gp(2)] = to_field(58);
        halt.fields[col::gp(3)] = to_field(100);
        trace.push(halt);

        // Need power of 2, currently 4 rows — pad remaining
        // Actually 4 is already power of 2, but we need the padding logic
        // to set is_final on padding rows with correct selectors
        // trace has 4 rows, pad_to_power_of_two should keep it at 4

        let proof = prove(&mut trace, &[]).unwrap();
        let result = verify(&proof, &[]);
        assert!(result.is_ok(), "ADD program verification failed: {:?}", result);
    }
}
