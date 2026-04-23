//! Library surface of the node crate.
//!
//! `pyde-node` is primarily a binary (`src/main.rs` → the `pyde` CLI).
//! This `lib.rs` exists so a small set of bin-internal modules can also
//! be used by out-of-workspace consumers — today that means the
//! `fuzz/` crate (task 053) which needs to hand arbitrary bytes to the
//! wire decoders without reconstructing the bin's module tree.
//!
//! Modules listed here are **additionally** compiled into the library
//! target; the binary declares its own `mod wire;` in `main.rs` and
//! keeps using it via `crate::wire::`. The doubled compilation is
//! negligible and means we don't have to refactor the binary's module
//! tree to expose anything.
//!
//! Keep this surface small. If a module has internal-only state or
//! needs to share a global with the binary (channels, runtime
//! handles), it stays out of here.

pub mod wire;
