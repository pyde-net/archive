//! Pyde ZK Prover v2: Custom STARK prover using Plonky3 primitives.
//!
//! Architecture: Our constraint evaluator (constraint.rs) defines PVM constraints
//! as plain Rust functions. The AIR adapter (air_adapter.rs) bridges them to
//! Plonky3's battle-tested FRI pipeline. The prover (prover.rs) provides the
//! high-level prove/verify API.
//!
//! ## Trace: 144 columns
//!
//! GP registers are single columns (checked arithmetic = field arithmetic for
//! valid traces). Wide registers use 4×u64 limbs. rs2_sel[16] verifies the
//! second operand. No bit decomposition — bitwise ops use lookup tables.
//!
//! ## Constraint Coverage
//!
//! - 35 opcodes: direct polynomial constraints
//! - 11 opcodes: via lookup table (bitwise ops — lookup.rs, next phase)
//! - 8 opcodes: via cross-table (memory, storage, hash — sub-AIRs, next phase)
//! - 5 opcodes: via public inputs (context queries)

pub mod trace;
pub mod constraint;
pub mod air_adapter;
pub mod prover;
pub mod recorder;
pub mod pipeline;
pub mod cross_table;
pub mod registry;
