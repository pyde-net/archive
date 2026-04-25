use pyde_consensus::block::{BlockHeader, EPOCH_LENGTH};
use std::collections::HashMap;
use tracing::debug;

/// Tracks the chain head and recent block headers.
pub struct ChainState {
    /// Current chain tip slot.
    pub head_slot: u64,
    /// Current epoch (head_slot / EPOCH_LENGTH).
    pub epoch: u64,
    /// State root at chain tip.
    pub state_root: [u8; 32],
    /// Recent block headers (slot → header) for finality checks.
    pub headers: HashMap<u64, BlockHeader>,
    /// Block hash → slot index (for getBlockByHash lookups).
    pub hash_to_slot: HashMap<[u8; 32], u64>,
    /// Genesis block hash.
    #[allow(dead_code)]
    pub genesis_hash: [u8; 32],
    /// Base fee for EIP-1559 gas pricing.
    pub base_fee: u128,
    /// Chain ID.
    pub chain_id: u64,
}

impl ChainState {
    /// Initialize at genesis.
    pub fn genesis(state_root: [u8; 32], chain_id: u64) -> Self {
        Self {
            head_slot: 0,
            epoch: 0,
            state_root,
            headers: HashMap::new(),
            hash_to_slot: HashMap::new(),
            genesis_hash: [0u8; 32],
            base_fee: pyde_tx::fee::GENESIS_BASE_FEE,
            chain_id,
        }
    }

    /// Advance chain head after processing a block.
    pub fn advance(&mut self, header: BlockHeader) {
        let slot = header.slot;
        let epoch = slot / EPOCH_LENGTH;

        self.head_slot = slot;
        self.epoch = epoch;
        self.state_root = header.state_root;
        let block_hash = header.hash();
        self.hash_to_slot.insert(block_hash, slot);
        self.headers.insert(slot, header);

        // Prune headers older than 2 epochs to bound memory.
        // Keep current + previous epoch. E.g. at epoch 3, keep epochs 2 and 3.
        if epoch >= 2 {
            let prune_before = (epoch - 1) * EPOCH_LENGTH;
            self.headers.retain(|s, _| *s >= prune_before);
            self.hash_to_slot.retain(|_, s| *s >= prune_before);
        }

        debug!(slot, epoch, "chain head advanced");
    }

    /// Get the header for a slot.
    pub fn header(&self, slot: u64) -> Option<&BlockHeader> {
        self.headers.get(&slot)
    }

    /// Get the header by block hash.
    pub fn header_by_hash(&self, hash: &[u8; 32]) -> Option<&BlockHeader> {
        self.hash_to_slot
            .get(hash)
            .and_then(|s| self.headers.get(s))
    }

    /// Whether we're at genesis (no blocks processed yet).
    pub fn is_genesis(&self) -> bool {
        self.head_slot == 0 && self.headers.is_empty()
    }

    /// Revert the chain head back to `target_slot` (audit 230).
    ///
    /// Drops every header at slot > target_slot from the in-memory
    /// header map, sets `head_slot = target_slot`, and restores
    /// `state_root` to the target slot's stored header.
    ///
    /// Caller is responsible for matching state-side rollback via
    /// `StateManager::revert_to(target_slot)` — these two together
    /// form the complete reorg rollback (chain metadata + state).
    /// They are intentionally separate so each subsystem can be
    /// tested in isolation; `BlockProcessor` and the receive-path
    /// fork-choice (audit 231) call them in sequence.
    ///
    /// Returns the number of headers dropped, or `Err(...)` if
    /// `target_slot > head_slot` (caller bug — only backwards
    /// reverts are valid) or if the target's header is not in
    /// memory (header pruned beyond the 2-epoch window).
    ///
    /// Audit 230 ships the mechanism; call site lights up in
    /// 231 — `#[allow(dead_code)]` covers the gap.
    #[allow(dead_code)]
    pub fn revert(&mut self, target_slot: u64) -> Result<usize, String> {
        if target_slot > self.head_slot {
            return Err(format!(
                "ChainState::revert: target {target_slot} > head {} (only backwards reverts valid)",
                self.head_slot
            ));
        }
        if target_slot == self.head_slot {
            return Ok(0);
        }
        // Genesis case: target_slot == 0 with no header for slot 0
        // means revert all headers and reset to genesis state.
        // Otherwise target's header must still be in memory.
        let target_header = if target_slot == 0 {
            None
        } else {
            match self.headers.get(&target_slot) {
                Some(h) => Some(h.clone()),
                None => {
                    return Err(format!(
                        "ChainState::revert: target slot {target_slot} header not in memory \
                         (likely pruned beyond 2-epoch window — fall back to snapshot restore)"
                    ));
                }
            }
        };

        let mut dropped = 0usize;
        let to_drop: Vec<u64> = self
            .headers
            .keys()
            .copied()
            .filter(|s| *s > target_slot)
            .collect();
        for slot in to_drop {
            if let Some(header) = self.headers.remove(&slot) {
                self.hash_to_slot.remove(&header.hash());
                dropped += 1;
            }
        }

        self.head_slot = target_slot;
        self.epoch = target_slot / EPOCH_LENGTH;
        self.state_root = match target_header {
            Some(h) => h.state_root,
            None => [0u8; 32], // genesis state root
        };

        debug!(target_slot, dropped, "chain head reverted to target slot");
        Ok(dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::ZERO_ADDRESS;
    use pyde_consensus::block::QuorumCert;

    fn dummy_header(slot: u64, parent_hash: [u8; 32]) -> BlockHeader {
        BlockHeader {
            slot,
            epoch: slot / EPOCH_LENGTH,
            parent_hash,
            proposer: ZERO_ADDRESS,
            vrf_proof: vec![],
            qc_previous: QuorumCert {
                slot: slot.saturating_sub(1),
                block_hash: parent_hash,
                voter_bitmap: 0,
                signatures: vec![],
            },
            tx_root: [0u8; 32],
            state_root: [slot as u8; 32],
            timestamp: slot * 400,
        }
    }

    #[test]
    fn genesis_state() {
        let chain = ChainState::genesis([0xAA; 32], 1);
        assert!(chain.is_genesis());
        assert_eq!(chain.head_slot, 0);
        assert_eq!(chain.state_root, [0xAA; 32]);
    }

    #[test]
    fn advance_updates_head() {
        let mut chain = ChainState::genesis([0; 32], 1);
        let header = dummy_header(1, [0; 32]);
        chain.advance(header);

        assert_eq!(chain.head_slot, 1);
        assert_eq!(chain.state_root, [1u8; 32]);
        assert!(!chain.is_genesis());
        assert!(chain.header(1).is_some());
    }

    #[test]
    fn old_headers_pruned() {
        let mut chain = ChainState::genesis([0; 32], 1);

        // Add headers across 3 epochs (EPOCH_LENGTH = 1000)
        for slot in 1..=2500 {
            chain.advance(dummy_header(slot, [(slot - 1) as u8; 32]));
        }

        // Epoch 2 (slot 2500): keep epochs 1+2 (slots >= 1000), prune epoch 0
        assert!(chain.header(1).is_none()); // epoch 0, pruned
        assert!(chain.header(999).is_none()); // epoch 0, pruned
        assert!(chain.header(1000).is_some()); // epoch 1, kept
        assert!(chain.header(2500).is_some()); // epoch 2, kept
    }

    #[test]
    fn revert_drops_headers_above_target() {
        // Audit 230 — basic revert correctness.
        let mut chain = ChainState::genesis([0; 32], 1);
        // Build a chain of 5 headers.
        let mut parent = [0u8; 32];
        for slot in 1..=5 {
            let header = dummy_header(slot, parent);
            parent = header.hash();
            chain.advance(header);
        }
        assert_eq!(chain.head_slot, 5);

        // Revert to slot 3.
        let dropped = chain.revert(3).unwrap();
        assert_eq!(dropped, 2, "should drop slots 4 and 5");
        assert_eq!(chain.head_slot, 3);
        assert_eq!(chain.state_root, [3u8; 32]);
        assert!(chain.header(4).is_none());
        assert!(chain.header(5).is_none());
        assert!(chain.header(3).is_some()); // target preserved
    }

    #[test]
    fn revert_to_same_slot_is_noop() {
        let mut chain = ChainState::genesis([0; 32], 1);
        chain.advance(dummy_header(1, [0; 32]));
        let dropped = chain.revert(1).unwrap();
        assert_eq!(dropped, 0);
        assert_eq!(chain.head_slot, 1);
    }

    #[test]
    fn revert_forward_rejected() {
        // Forward "reverts" are caller bugs — must error explicitly.
        let mut chain = ChainState::genesis([0; 32], 1);
        chain.advance(dummy_header(1, [0; 32]));
        let err = chain.revert(5).unwrap_err();
        assert!(err.contains("only backwards reverts"));
    }

    #[test]
    fn revert_to_pruned_target_errors() {
        // If the target's header has been pruned beyond the 2-epoch
        // window, revert must refuse rather than corrupt state.
        // EPOCH_LENGTH = 1000, so building to slot 2500 prunes
        // anything before slot 1000.
        let mut chain = ChainState::genesis([0; 32], 1);
        let mut parent = [0u8; 32];
        for slot in 1..=2500 {
            let header = dummy_header(slot, parent);
            parent = header.hash();
            chain.advance(header);
        }
        // Attempt to revert to slot 1 (pruned).
        let err = chain.revert(1).unwrap_err();
        assert!(err.contains("not in memory"));
    }

    #[test]
    fn revert_to_genesis_clears_all() {
        let mut chain = ChainState::genesis([0; 32], 1);
        let mut parent = [0u8; 32];
        for slot in 1..=3 {
            let header = dummy_header(slot, parent);
            parent = header.hash();
            chain.advance(header);
        }
        let dropped = chain.revert(0).unwrap();
        assert_eq!(dropped, 3);
        assert_eq!(chain.head_slot, 0);
        assert!(chain.is_genesis());
    }

    #[test]
    fn lookup_by_hash() {
        let mut chain = ChainState::genesis([0; 32], 1);
        let header = dummy_header(1, [0; 32]);
        let hash = header.hash();
        chain.advance(header);

        // Lookup by hash should find the same header
        let found = chain.header_by_hash(&hash);
        assert!(found.is_some());
        assert_eq!(found.unwrap().slot, 1);

        // Unknown hash returns None
        assert!(chain.header_by_hash(&[0xFF; 32]).is_none());
    }
}
