//! Fuzz target: `pyde_node::wire::decode_block` on arbitrary bytes.
//!
//! Reachable from any authenticated peer via the `pyde/blocks/1`
//! gossipsub topic. The block decoder runs BEFORE proposer-signature
//! verification (to read the proposer field out of the header), so
//! a panic here is reachable to any committee member who can open
//! a libp2p channel — no valid signature required. Combined with
//! `panic = "abort"` in the workspace release profile, that turns
//! a single malformed gossip block into a remote validator-kill.
//! Must return `Result<Block, &'static str>` for any input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pyde_node::wire::decode_block(data);
});
