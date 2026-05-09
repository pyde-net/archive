//! Fuzz target: `pyde_node::wire::decode_block_header` on arbitrary bytes.
//!
//! The header decoder is the inner half of `decode_block` and is
//! also called directly on `pyde/blocks/1` and `pyde/sync/1` paths
//! that ship just the header (e.g. light-client checkpoint
//! gossip). Same DoS shape as `wire_block`: any authenticated peer
//! can publish a malformed header, the decoder runs before the
//! attached FALCON quorum certificate is verified, and a panic
//! aborts the validator under the workspace's
//! `panic = "abort"` release profile. Must return
//! `Result<BlockHeader, &'static str>` for any input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pyde_node::wire::decode_block_header(data);
});
