pub mod backend;
pub mod jmt_store;
pub mod keys;
pub mod smt;
pub mod snapshot;
pub mod tiers;
// `versioning` (VersionedState — undo-log abstraction) was removed
// once StateManager grew its own per-block undo logging in audit 230.
// The standalone module had no production callers and duplicated the
// shape we now have. If a future stateless-validator path needs an
// SMT-bound undo abstraction again, restore from git history.
pub mod witness;
