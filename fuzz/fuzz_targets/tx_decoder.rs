//! Fuzz target: `Transaction::from_bytes` on arbitrary bytes.
//!
//! The tx wire format is accepted over RPC (`pyde_sendRawTransaction`)
//! and gossip. Any byte string from a peer has to round-trip through
//! `from_bytes` before ingress validation even runs; a panic here
//! means a single malformed tx can crash the node before the sender
//! ever gets rate-limited. Must return `Option<Transaction>` for any
//! input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Just the decoder. We explicitly accept `None` as a valid
    // outcome — this fuzz only flags panics + aborts.
    let _ = pyde_tx::types::Transaction::from_bytes(data);
});
