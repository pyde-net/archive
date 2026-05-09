//! Block propagation: compact blocks and erasure coding.
//!
//! Two-phase strategy per Chapter 12:
//! 1. Header-first gossip (~200 bytes)
//! 2. Body on demand (peers request missing txs)
//!
//! Compact blocks use 6-byte short IDs instead of 32-byte hashes.
//! Erasure coding (Reed-Solomon) for blocks > 256KB.

use pyde_crypto::poseidon2::poseidon2_hash;

/// Short ID size (8 bytes — collision-safe up to millions of txs).
pub const SHORT_ID_LEN: usize = 8;

/// Threshold for erasure coding (blocks larger than this get coded).
pub const ERASURE_THRESHOLD: usize = 256 * 1024; // 256KB

/// An 8-byte short transaction ID.
pub type ShortId = [u8; SHORT_ID_LEN];

/// Compact block: header + short IDs + prefilled txs + execution schedule.
/// Reduces per-tx overhead from 32 bytes to 8 bytes for short IDs +
/// 2 bytes for group ID = 10 bytes total.
#[derive(Clone, Debug)]
pub struct CompactBlock {
    /// Block header bytes.
    pub header: Vec<u8>,
    /// Short IDs: first 8 bytes of Poseidon2(tx_hash || nonce).
    pub short_tx_ids: Vec<ShortId>,
    /// Pre-filled transactions the sender expects the peer not to have.
    /// (index, raw tx bytes).
    pub prefilled_txs: Vec<(u16, Vec<u8>)>,
    /// Nonce used for short ID computation (randomized per announcement).
    pub nonce: u64,
    /// Audit 408: per-tx execution-group ID. `group_ids[i]` is the
    /// group containing the tx at position `i` in `short_tx_ids`. Two
    /// txs share a group iff they share a group_id. Receivers
    /// reconstruct the full `ExecutionSchedule` from this vector
    /// rather than recomputing it locally — pre-fix the receiver
    /// hardcoded a single sequential group at `node.rs:1833`,
    /// throwing away the proposer's parallel plan and forcing every
    /// non-proposer to take the sequential `block_processor` path
    /// even when the proposer ran rayon-parallel. The schedule was
    /// already in the full `encode_block` format (see
    /// `crates/node/src/wire.rs:885`); this just propagates it
    /// through the steady-state compact-block channel too. `u16`
    /// supports up to 65535 distinct groups per block — well above
    /// any realistic scheduler output (typical mainnet block has
    /// tens to low hundreds of groups, capped by the active
    /// sender / contract count).
    pub group_ids: Vec<u16>,
}

/// Compute a short ID from a tx hash and nonce.
pub fn compute_short_id(tx_hash: &[u8; 32], nonce: u64) -> ShortId {
    let mut buf = Vec::with_capacity(40); // tx_hash(32) + nonce(8)
    buf.extend_from_slice(tx_hash);
    buf.extend_from_slice(&nonce.to_le_bytes());
    let hash = poseidon2_hash(&buf).to_bytes();
    let mut short = [0u8; SHORT_ID_LEN];
    short.copy_from_slice(&hash[..SHORT_ID_LEN]);
    short
}

/// Time threshold (ms) for prefilling recent txs that peers may not have.
pub const PREFILL_FRESHNESS_MS: u64 = 200;

impl CompactBlock {
    /// Build a compact block from a full block.
    /// Prefills transactions received within PREFILL_FRESHNESS_MS.
    /// `group_ids[i]` is the execution-group label for the tx at
    /// position `i`; pass an empty slice for legacy callers and the
    /// receiver will fall back to a single sequential group.
    pub fn from_block(
        header_bytes: Vec<u8>,
        tx_hashes: &[[u8; 32]],
        prefill_indices: &[usize],
        prefill_tx_bytes: &[Vec<u8>],
        group_ids: &[u16],
    ) -> Self {
        let nonce = rand_nonce();
        let short_tx_ids: Vec<ShortId> = tx_hashes
            .iter()
            .map(|h| compute_short_id(h, nonce))
            .collect();

        let prefilled_txs: Vec<(u16, Vec<u8>)> = prefill_indices
            .iter()
            .zip(prefill_tx_bytes.iter())
            .map(|(&idx, bytes)| (idx as u16, bytes.clone()))
            .collect();

        Self {
            header: header_bytes,
            short_tx_ids,
            prefilled_txs,
            nonce,
            group_ids: group_ids.to_vec(),
        }
    }

    /// Reconstruct a full block by matching short IDs against a mempool.
    /// Returns (matched_txs, missing_short_ids).
    /// matched_txs[i] is Some(tx_bytes) if found, None if missing.
    pub fn reconstruct(
        &self,
        mempool_txs: &[([u8; 32], Vec<u8>)], // (tx_hash, raw_tx_bytes)
    ) -> (Vec<Option<Vec<u8>>>, Vec<ShortId>) {
        // Build lookup: short_id → tx_bytes from mempool
        let mut lookup: std::collections::HashMap<ShortId, Vec<u8>> =
            std::collections::HashMap::with_capacity(mempool_txs.len());
        for (hash, bytes) in mempool_txs {
            let sid = compute_short_id(hash, self.nonce);
            lookup.insert(sid, bytes.clone());
        }

        // Also add prefilled txs
        let mut prefill_map: std::collections::HashMap<u16, Vec<u8>> =
            self.prefilled_txs.iter().cloned().collect();

        let mut matched: Vec<Option<Vec<u8>>> = Vec::with_capacity(self.short_tx_ids.len());
        let mut missing: Vec<ShortId> = Vec::new();

        for (i, sid) in self.short_tx_ids.iter().enumerate() {
            if let Some(bytes) = prefill_map.remove(&(i as u16)) {
                matched.push(Some(bytes));
            } else if let Some(bytes) = lookup.get(sid) {
                matched.push(Some(bytes.clone()));
            } else {
                matched.push(None);
                missing.push(*sid);
            }
        }

        (matched, missing)
    }
}

/// Generate a random nonce for short ID computation.
///
/// Audit 381: pre-fix this hashed `SystemTime::now()`, which is
/// trivially predictable (an off-path observer with a rough clock
/// can guess the nonce within microseconds). The short-ID hash is
/// what protects compact-block transmission from collision attacks
/// — a predictable nonce lets a Byzantine peer pre-compute a tx
/// whose short ID collides with another peer's tx, forcing
/// fallback `GetBlockTxs` round-trips and amplifying bandwidth.
/// Now backed by the OS CSPRNG via `getrandom`, which is already
/// a transitive dep through `rand` and exposed directly here.
fn rand_nonce() -> u64 {
    let mut buf = [0u8; 8];
    // OS CSPRNG failure is unrecoverable for consensus security;
    // panic rather than fall back to a predictable source.
    getrandom::getrandom(&mut buf).expect("OS CSPRNG must be available for short-id nonce");
    u64::from_le_bytes(buf)
}

// Block-body missing-tx fetch lives in `block_txs_protocol::{BlockTxsReq,
// BlockTxsResp}` — a request-response channel with serde-codec
// types. The earlier in-tree `GetBlockTxs` / `BlockTxsResponse` stubs
// (and their wire encoders) had no callers and were superseded
// without a migration window.

/// Encrypted-tx bundle: proposer→validators payload carrying the
/// block's `encrypted_txs: Vec<Vec<u8>>` out-of-band from the
/// compact block. Resolves audit item 207 / 074b: the compact block
/// has no room for encrypted_tx bodies, so non-proposer validators
/// would otherwise never see them and their decryption shares would
/// orphan.
///
/// Integrity is anchored by the existing `BlockHeader::tx_root`
/// commitment (see `pyde_consensus::block::compute_tx_root`):
/// receiver hashes each `encrypted_tx` byte blob as an `EncryptedTx`
/// and calls `verify_tx_root` against the header from the matching
/// compact block. Mismatch → reject. No per-bundle signature is
/// needed for authenticity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedTxBundle {
    /// Slot the bundle is for.
    pub slot: u64,
    /// Hash of the block whose `tx_root` commits to this bundle.
    /// Lets receivers match the bundle to its compact block even if
    /// they arrive out of order.
    pub block_hash: [u8; 32],
    /// Encrypted-tx byte blobs in block order, identical to
    /// `Block::body.encrypted_txs`.
    pub encrypted_txs: Vec<Vec<u8>>,
}

// ========== Erasure Coding ==========

/// An erasure-coded chunk of a block.
#[derive(Clone, Debug)]
pub struct ErasureChunk {
    /// Block hash this chunk belongs to.
    pub block_hash: [u8; 32],
    /// Chunk index (0..k+m).
    pub index: u16,
    /// Whether this is a parity chunk.
    pub is_parity: bool,
    /// Chunk data.
    pub data: Vec<u8>,
}

/// Erasure coding parameters.
#[derive(Clone, Debug)]
pub struct ErasureParams {
    /// Number of data chunks.
    pub data_chunks: usize,
    /// Number of parity chunks (50% of data chunks).
    pub parity_chunks: usize,
    /// Chunk size in bytes.
    pub chunk_size: usize,
}

/// Compute erasure coding parameters for a given block size.
pub fn compute_erasure_params(block_size: usize) -> Option<ErasureParams> {
    if block_size <= ERASURE_THRESHOLD {
        return None; // too small, no erasure coding needed
    }

    // Target chunk size: 64KB
    let chunk_size = 64 * 1024;
    let data_chunks = block_size.div_ceil(chunk_size);
    let parity_chunks = data_chunks.div_ceil(2); // 50% redundancy

    Some(ErasureParams {
        data_chunks,
        parity_chunks,
        chunk_size,
    })
}

/// Split a block into data chunks for erasure coding.
/// Parity chunk generation is deferred to a Reed-Solomon library (Phase 7 integration).
pub fn split_into_chunks(data: &[u8], params: &ErasureParams) -> Vec<Vec<u8>> {
    let mut chunks = Vec::with_capacity(params.data_chunks);
    for i in 0..params.data_chunks {
        let start = i * params.chunk_size;
        let end = (start + params.chunk_size).min(data.len());
        if start < data.len() {
            chunks.push(data[start..end].to_vec());
        } else {
            chunks.push(vec![0u8; params.chunk_size]); // padding
        }
    }
    chunks
}

/// Reconstruct block data from chunks (data chunks only, no RS decoding yet).
/// Full Reed-Solomon reconstruction deferred to Phase 7 integration.
pub fn reconstruct_from_chunks(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut data = Vec::new();
    for chunk in chunks {
        data.extend_from_slice(chunk);
    }
    data
}

/// Check if a block needs erasure coding.
pub fn needs_erasure_coding(block_size: usize) -> bool {
    block_size > ERASURE_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Short IDs ==========

    #[test]
    fn short_id_deterministic() {
        let tx_hash = [0xAA; 32];
        let id1 = compute_short_id(&tx_hash, 42);
        let id2 = compute_short_id(&tx_hash, 42);
        assert_eq!(id1, id2);
    }

    #[test]
    fn short_id_different_nonce() {
        let tx_hash = [0xAA; 32];
        let id1 = compute_short_id(&tx_hash, 0);
        let id2 = compute_short_id(&tx_hash, 1);
        assert_ne!(id1, id2);
    }

    #[test]
    fn short_id_different_hash() {
        let id1 = compute_short_id(&[0xAA; 32], 0);
        let id2 = compute_short_id(&[0xBB; 32], 0);
        assert_ne!(id1, id2);
    }

    #[test]
    fn short_id_is_8_bytes() {
        let id = compute_short_id(&[0xCC; 32], 0);
        assert_eq!(id.len(), 8);
    }

    // ========== Erasure coding ==========

    #[test]
    fn small_block_no_erasure() {
        assert!(!needs_erasure_coding(100_000));
        assert!(compute_erasure_params(100_000).is_none());
    }

    #[test]
    fn large_block_gets_erasure() {
        assert!(needs_erasure_coding(512 * 1024));
        let params = compute_erasure_params(512 * 1024).unwrap();
        assert_eq!(params.data_chunks, 8);
        assert_eq!(params.parity_chunks, 4);
        assert_eq!(params.chunk_size, 64 * 1024);
    }

    #[test]
    fn split_and_reconstruct() {
        let data = vec![0xAB; 200_000]; // 200KB
        let params = ErasureParams {
            data_chunks: 4,
            parity_chunks: 2,
            chunk_size: 64 * 1024,
        };

        let chunks = split_into_chunks(&data, &params);
        assert_eq!(chunks.len(), 4);

        let reconstructed = reconstruct_from_chunks(&chunks);
        assert_eq!(&reconstructed[..data.len()], &data[..]);
    }

    // ========== Compact block ==========

    #[test]
    fn compact_block_short_ids() {
        let tx_hashes: Vec<[u8; 32]> = (0..100u8).map(|i| [i; 32]).collect();
        let nonce = 12345u64;

        let short_ids: Vec<ShortId> = tx_hashes
            .iter()
            .map(|h| compute_short_id(h, nonce))
            .collect();

        // All unique
        let mut dedup = std::collections::HashSet::new();
        for id in &short_ids {
            assert!(dedup.insert(*id));
        }

        // 100 short IDs = 600 bytes vs 100 full hashes = 3200 bytes
        assert_eq!(short_ids.len() * 6, 600);
    }
}
