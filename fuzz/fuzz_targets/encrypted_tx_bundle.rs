//! Fuzz target: `pyde_node::wire::decode_encrypted_tx_bundle` on
//! arbitrary bytes.
//!
//! `EncryptedTxBundle` is the proposer-side payload that ships the
//! ordering commitment plus the encrypted-tx hash list on the
//! `pyde/blocks/1` channel. Decoded BEFORE the proposer signature
//! is checked (since we need the proposer field out of the bundle
//! header), so any peer who can publish on the channel can feed a
//! malformed bundle. Distinct from `encrypted_tx_decoder.rs` which
//! covers the per-tx envelope reachable from
//! `pyde_sendRawEncryptedTransaction`. Must return
//! `Result<EncryptedTxBundle, &'static str>` for any input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pyde_node::wire::decode_encrypted_tx_bundle(data);
});
