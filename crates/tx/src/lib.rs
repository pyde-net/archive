// Frozen pre-pivot archive: the lints below were promoted to default-warn
// in clippy 1.95, after this code was frozen. The archive is historical and
// not developed further, so it is not conformed to new clippy-version style
// opinions. Allowed at the crate level because the CI's `-- -D warnings`
// overrides Cargo.toml lint tables but not source attributes.
#![allow(
    clippy::cloned_ref_to_slice_refs,
    clippy::explicit_counter_loop,
    clippy::if_same_then_else,
    clippy::manual_checked_ops,
    clippy::manual_flatten,
    clippy::unnecessary_get_then_check,
    clippy::assertions_on_constants,
    clippy::unnecessary_sort_by,
    dead_code
)]

//! Pyde Transaction Processing: transaction types, serialization, and hashing.

pub mod access_infer;
pub mod airdrop;
pub mod execution;
pub mod fee;
pub mod gas_tank;
pub mod multisig;
pub mod parallel;
pub mod pipeline;
pub mod types;
pub mod validation;
pub mod vesting;
