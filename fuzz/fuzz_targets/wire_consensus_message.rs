//! Fuzz target: `pyde_node::wire::decode_consensus_message` on
//! arbitrary bytes.
//!
//! The consensus message decoder is the entry point for everything
//! on the `pyde/consensus/1` gossipsub channel — prepare, pre-commit,
//! commit votes, view-change votes, finality checkpoints, decryption
//! shares, slashing evidence. Authenticated committee membership is
//! checked AFTER the decode, so a malformed envelope panicking here
//! is reachable to any peer who passes the libp2p auth handshake.
//! `panic = "abort"` in the workspace release profile turns the
//! panic into a remote validator-kill. Must return
//! `Result<ConsensusMessage, &'static str>` for any input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pyde_node::wire::decode_consensus_message(data);
});
