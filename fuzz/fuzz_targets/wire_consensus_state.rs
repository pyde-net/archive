//! Fuzz target: `pyde_node::wire::decode_consensus_state` on
//! arbitrary bytes.
//!
//! `ConsensusState` is the cold-sync / catch-up payload exchanged
//! on the `pyde/sync/1` channel. It carries the snapshot of HotStuff
//! state (highest QC, locked QC, view, etc.) a freshly-started node
//! pulls from peers before live-tailing. The decoder is reachable
//! from any peer that responds to a sync request; a malformed
//! response that panics the requester is a remote validator-kill
//! against any node restarting from a stale checkpoint. Must
//! return `Result<_, &'static str>` for any input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pyde_node::wire::decode_consensus_state(data);
});
