//! Shared slashing constants. Single source of truth for:
//!
//! - `VALIDATOR_STAKE` — exact amount a validator locks on register
//!   (also the cap on per-offense slash amount)
//! - `FINDER_FEE_PERCENT` — percentage of burned stake that goes to the
//!   reporter of double-sign evidence
//! - `EVIDENCE_VERSION` — wire-format version byte on
//!   `DoubleSignEvidence` serialization
//!
//! Pre-consolidation, these lived in three places:
//! `pyde-consensus::validator`, `pyde-consensus::slashing`, and inline
//! `const` in `pyde-tx::pipeline`. The duplication existed because
//! `pyde-tx` can't depend on `pyde-consensus` (cycle — consensus
//! depends on tx), so the slash-tx handler had to shadow the values.
//! Drift across forks would have broken slash-tx execution silently.
//! A shared leaf crate eliminates the drift risk.

#![no_std]

/// Validator stake denomination. 10_000 PYDE = 10^13 quanta.
/// This value is load-bearing for slashing math — the slash handler
/// matches against `stake.min(VALIDATOR_STAKE)` to cap punishment at
/// one full stake even if the validator over-collateralized.
pub const VALIDATOR_STAKE: u128 = 10_000_000_000_000;

/// Finder's-fee percentage paid to the submitter of valid double-sign
/// evidence. Expressed as integer percent (10 = 10%).
pub const FINDER_FEE_PERCENT: u128 = 10;

/// Wire-format version byte on `DoubleSignEvidence`. Bump only when
/// the byte layout changes in a way that pre-upgrade nodes can't parse.
pub const EVIDENCE_VERSION: u8 = 1;
