//! Fuzz target: `pyde_node::wire::decode_transaction` on arbitrary bytes.
//!
//! The node's compact-block + gossip tx path uses the `wire` decoder
//! (distinct from `Transaction::from_bytes` — see `tx_decoder.rs`).
//! Both paths see untrusted peer bytes; both need to return a
//! `Result`, not panic.
//!
//! Reached via the lib target added to `crates/node/src/lib.rs`
//! alongside this target.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pyde_node::wire::decode_transaction(data);
});
