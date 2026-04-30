//! Fuzz target: `EncryptedTx::from_bytes` on arbitrary bytes.
//!
//! Reachable from `pyde_sendRawEncryptedTransaction` (anonymous RPC),
//! peer-sent `EncryptedTxBundle` blobs, and
//! `inclusion::audit_block_inclusion`. Every byte here is
//! attacker-controlled. Combined with `panic = "abort"` in the
//! workspace release profile, a single panic in the decoder is a
//! remote-unauth node-abort DoS — must return `Option<EncryptedTx>`
//! for any input, never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pyde_mempool::encrypted::EncryptedTx::from_bytes(data);
});
