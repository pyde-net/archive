//! Pyde ZK Prover: STARK proof generation using Plonky3.
//!
//! ## Architecture: Committee-Based Proving
//!
//! Provers are organized into a **prover committee** (e.g., 16 members per epoch).
//! When a ScheduledBlock arrives:
//!
//! 1. **All members execute independently** (no trust — each member executes
//!    all txs using witnesses verified against the previous block's proven
//!    state_root).
//! 2. **Parallel groups divided among members** (round-robin assignment).
//!    Each member generates STARK proofs for their assigned groups only.
//! 3. **Rotating aggregator** (slot % committee_size) collects sub-proofs
//!    and recursively combines them into a single block proof.
//! 4. **Block proof submitted** to validator committee for hard finality.
//!
//! If a member fails to submit their sub-proof by the deadline (t=1500ms),
//! the aggregator broadcasts unclaimed groups. First available member picks
//! up the work. If aggregator fails, next member takes over.
//!
//! ## Group-Level Proving (Not Per-Transaction)
//!
//! Each parallel execution group produces one trace and one STARK proof.
//! This keeps proof count manageable at high throughput:
//!
//! - Per-tx: 50K txs → 50K proofs (~5 GB, infeasible)
//! - Per-group: ~50 groups → 50 proofs (~5 MB, practical)
//!
//! Group proofs are recursively composed into a single block proof.
//!
//! ## Proof and State Commitment
//!
//! The proposer cannot include a state_root in the block header because
//! transactions are encrypted at proposal time. The state_root is committed
//! by the STARK proof and included in the HardFinalityCert:
//!
//! - Proposal:     tx_root ✓, state_root unknown (txs encrypted)
//! - Soft finality: ordering locked, full nodes execute optimistically
//! - Hard finality: STARK proof commits state_root, proven correct
//!
//! Full nodes apply state changes at soft finality (optimistic execution).
//! The proof CONFIRMS correctness — it doesn't cause execution. A proof
//! failure means the prover failed, not the state. State reverts only
//! happen in catastrophic consensus failures (43+ malicious validators).
//!
//! ## Witness Verification
//!
//! Provers receive state witnesses from full nodes. Each witness contains
//! (key, value, merkle_proof) verified against the previous block's proven
//! state_root. A rogue full node cannot corrupt execution because:
//!
//! - Calldata comes from the ScheduledBlock (signed by 86+ validators)
//! - Witness values are bound to the proven state_root via Merkle proofs
//! - Modified calldata or wrong state values fail Merkle verification
//!
//! ## Proving Failure Recovery
//!
//! If the prover committee fails to generate a proof:
//!
//! - Soft finality is unaffected (no proof needed, 400ms confirmation)
//! - Hard finality is delayed until proof is submitted
//! - Block production continues, unproven blocks accumulate
//! - MAX_UNPROVEN_WINDOW (100 blocks): production slows (800ms block time)
//! - MAX_UNPROVEN_CRITICAL (500 blocks): empty blocks only (no new txs)
//! - Absent provers slashed (same graduated penalties as validators)
//! - Provers can catch up retroactively (prove backlog blocks)
//!
//! ## Competitive vs Committee
//!
//! Unlike competitive proving (race to submit, wasteful), committee proving
//! divides work efficiently. Market dynamics still apply: prover rewards
//! incentivize fast hardware, and the committee is selected from registered
//! provers each epoch.

pub mod recorder;
pub mod registry;
pub mod trace;

