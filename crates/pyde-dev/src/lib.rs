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

pub mod build;
pub mod cheatcodes;
pub mod clean;
pub mod cli;
pub mod console;
pub mod deploy;
pub mod doc;
pub mod fmt;
pub mod init;
pub mod install;
pub mod project;
pub mod script;
pub mod signer;
pub mod test_runner;
pub mod trace;
pub mod verify;
pub mod wallet;
