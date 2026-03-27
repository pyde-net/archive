use pyde_consensus::block::{BlockHeader, QuorumCert, EPOCH_LENGTH};
use std::collections::HashMap;
use tracing::info;

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
    /// Genesis block hash.
    pub genesis_hash: [u8; 32],
    /// Base fee for EIP-1559 gas pricing.
    pub base_fee: u128,
}

impl ChainState {
    /// Initialize at genesis.
    pub fn genesis(state_root: [u8; 32]) -> Self {
        Self {
            head_slot: 0,
            epoch: 0,
            state_root,
            headers: HashMap::new(),
            genesis_hash: [0u8; 32],
            base_fee: pyde_tx::fee::GENESIS_BASE_FEE,
        }
    }

    /// Advance chain head after processing a block.
    pub fn advance(&mut self, header: BlockHeader) {
        let slot = header.slot;
        let epoch = slot / EPOCH_LENGTH as u64;

        self.head_slot = slot;
        self.epoch = epoch;
        self.state_root = header.state_root;
        self.headers.insert(slot, header);

        // Prune headers older than 2 epochs to bound memory.
        // Keep current + previous epoch. E.g. at epoch 3, keep epochs 2 and 3.
        if epoch >= 2 {
            let prune_before = (epoch - 1) * EPOCH_LENGTH;
            self.headers.retain(|s, _| *s >= prune_before);
        }

        info!(slot, epoch, "chain head advanced");
    }

    /// Get the header for a slot.
    pub fn header(&self, slot: u64) -> Option<&BlockHeader> {
        self.headers.get(&slot)
    }

    /// Whether we're at genesis (no blocks processed yet).
    pub fn is_genesis(&self) -> bool {
        self.head_slot == 0 && self.headers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::ZERO_ADDRESS;

    fn dummy_header(slot: u64, parent_hash: [u8; 32]) -> BlockHeader {
        BlockHeader {
            slot,
            epoch: slot / EPOCH_LENGTH as u64,
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
        let chain = ChainState::genesis([0xAA; 32]);
        assert!(chain.is_genesis());
        assert_eq!(chain.head_slot, 0);
        assert_eq!(chain.state_root, [0xAA; 32]);
    }

    #[test]
    fn advance_updates_head() {
        let mut chain = ChainState::genesis([0; 32]);
        let header = dummy_header(1, [0; 32]);
        chain.advance(header);

        assert_eq!(chain.head_slot, 1);
        assert_eq!(chain.state_root, [1u8; 32]);
        assert!(!chain.is_genesis());
        assert!(chain.header(1).is_some());
    }

    #[test]
    fn old_headers_pruned() {
        let mut chain = ChainState::genesis([0; 32]);

        // Add headers across 3 epochs (EPOCH_LENGTH = 1000)
        for slot in 1..=2500 {
            chain.advance(dummy_header(slot, [(slot - 1) as u8; 32]));
        }

        // Epoch 2 (slot 2500): keep epochs 1+2 (slots >= 1000), prune epoch 0
        assert!(chain.header(1).is_none());    // epoch 0, pruned
        assert!(chain.header(999).is_none());  // epoch 0, pruned
        assert!(chain.header(1000).is_some()); // epoch 1, kept
        assert!(chain.header(2500).is_some()); // epoch 2, kept
    }
}
