use crate::chain::ChainState;
use crate::state_manager::StateManager;
use pyde_consensus::block::BlockHeader;
use pyde_tx::fee::adjust_base_fee;
use std::time::Instant;
use tracing::{info, warn};

/// Processes incoming blocks: validates, executes transactions, updates state.
pub struct BlockProcessor;

impl BlockProcessor {
    /// Process a block: validate header, execute transactions, update state.
    ///
    /// Returns (tx_count, gas_used) on success.
    pub fn process_block(
        chain: &mut ChainState,
        state: &mut StateManager,
        header: BlockHeader,
        tx_data: &[Vec<u8>],
    ) -> Result<(u64, u64), String> {
        let start = Instant::now();
        let slot = header.slot;
        let tx_count = tx_data.len() as u64;

        // 1. Validate header chains to current head
        if !chain.is_genesis() {
            if header.parent_hash != chain.state_root {
                // In a real implementation, parent_hash references the previous block hash,
                // not state root. This is a simplified check for the skeleton.
                warn!(
                    slot,
                    expected = hex::encode(chain.state_root),
                    got = hex::encode(header.parent_hash),
                    "block parent hash mismatch (simplified check)"
                );
            }

            if header.slot <= chain.head_slot {
                return Err(format!(
                    "block slot {} is not ahead of head {}",
                    header.slot, chain.head_slot
                ));
            }
        }

        // 2. Execute transactions against state
        // Full tx execution (decode → validate → run in PVM → update state)
        // is wired in M10.2 when we have the validator block proposal pipeline.
        // For now, we process the block header and advance chain state.
        let gas_used = 0u64; // placeholder until tx execution is wired

        // 3. Adjust base fee for next block (EIP-1559)
        let gas_target = pyde_tx::fee::GAS_TARGET as u64;
        chain.base_fee = adjust_base_fee(chain.base_fee, gas_used, gas_target);

        // 4. Advance chain head
        chain.advance(header);

        let elapsed_ms = start.elapsed().as_millis() as u64;

        // 5. Record metrics
        crate::metrics::record_block(slot, tx_count, gas_used, elapsed_ms);

        info!(
            slot,
            txs = tx_count,
            gas = gas_used,
            elapsed_ms,
            "block processed"
        );

        Ok((tx_count, gas_used))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainState;
    use crate::state_manager::StateManager;
    use pyde_account::address::ZERO_ADDRESS;
    use pyde_consensus::block::QuorumCert;

    fn dummy_header(slot: u64) -> BlockHeader {
        BlockHeader {
            slot,
            epoch: 0,
            parent_hash: [0u8; 32],
            proposer: ZERO_ADDRESS,
            vrf_proof: vec![],
            qc_previous: QuorumCert {
                slot: slot.saturating_sub(1),
                block_hash: [0u8; 32],
                voter_bitmap: 0,
                signatures: vec![],
            },
            tx_root: [0u8; 32],
            state_root: [slot as u8; 32],
            timestamp: slot * 400,
        }
    }

    #[test]
    fn process_genesis_block() {
        let mut chain = ChainState::genesis([0u8; 32]);
        let mut state =
            StateManager::open(&std::env::temp_dir().join("pyde-test-bp-genesis"), 1024).unwrap();

        let header = dummy_header(1);
        let (tx_count, gas_used) =
            BlockProcessor::process_block(&mut chain, &mut state, header, &[]).unwrap();

        assert_eq!(tx_count, 0);
        assert_eq!(gas_used, 0);
        assert_eq!(chain.head_slot, 1);
    }

    #[test]
    fn reject_old_slot() {
        let mut chain = ChainState::genesis([0u8; 32]);
        let mut state =
            StateManager::open(&std::env::temp_dir().join("pyde-test-bp-old"), 1024).unwrap();

        // Process slot 5
        chain.advance(dummy_header(5));

        // Try to process slot 3 (behind head)
        let result = BlockProcessor::process_block(&mut chain, &mut state, dummy_header(3), &[]);
        assert!(result.is_err());
    }

    #[test]
    fn sequential_blocks() {
        let mut chain = ChainState::genesis([0u8; 32]);
        let mut state =
            StateManager::open(&std::env::temp_dir().join("pyde-test-bp-seq"), 1024).unwrap();

        for slot in 1..=5 {
            BlockProcessor::process_block(&mut chain, &mut state, dummy_header(slot), &[]).unwrap();
        }

        assert_eq!(chain.head_slot, 5);
    }
}
