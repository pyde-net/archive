use crate::chain::ChainState;
use crate::state_manager::StateManager;
use pyde_consensus::block::{Block, BlockHeader};
use pyde_tx::execution::Receipt;
use pyde_tx::fee::adjust_base_fee;
use pyde_tx::pipeline::{execute_transaction, BlockContext};
use pyde_tx::types::Transaction;
use std::time::Instant;
use tracing::{debug, info, warn};

/// Processes incoming blocks: validates header, executes transactions, updates state.
pub struct BlockProcessor;

impl BlockProcessor {
    /// Process a full block with transactions.
    /// Executes each tx against the state, collects receipts, updates chain head.
    /// Returns (tx_count, total_gas_used, receipts).
    pub fn process_full_block(
        chain: &mut ChainState,
        state: &mut StateManager,
        block: &Block,
    ) -> Result<(u64, u64, Vec<Receipt>), String> {
        let start = Instant::now();
        let slot = block.header.slot;

        // 1. Validate header
        Self::validate_header(&block.header, chain)?;

        // 2. Build block context for tx execution
        let block_ctx = BlockContext {
            height: slot,
            timestamp: block.header.timestamp,
            base_fee: chain.base_fee,
            block_gas_limit: pyde_tx::fee::GAS_CEILING as u64,
            chain_id: 1, // TODO: from config
            validator_address: block.header.proposer,
        };

        // 3. Execute each transaction
        let mut receipts = Vec::with_capacity(block.body.transactions.len());
        let mut total_gas = 0u64;

        for (i, tx) in block.body.transactions.iter().enumerate() {
            match execute_transaction(tx, state.smt_mut(), &block_ctx) {
                Ok(receipt) => {
                    total_gas += receipt.effective_gas;
                    debug!(
                        slot,
                        tx_index = i,
                        gas = receipt.effective_gas,
                        success = receipt.success,
                        "tx executed"
                    );
                    receipts.push(receipt);
                }
                Err(e) => {
                    warn!(
                        slot,
                        tx_index = i,
                        error = ?e,
                        "tx execution failed"
                    );
                    // Failed txs still consume gas (up to gas_limit)
                    // but we skip them for now — in production, we'd charge
                    // and create a failed receipt
                }
            }
        }

        // 4. Refresh state root after all tx mutations
        state.refresh_root();

        // 5. Adjust base fee for next block (EIP-1559)
        let gas_target = pyde_tx::fee::GAS_TARGET as u64;
        chain.base_fee = adjust_base_fee(chain.base_fee, total_gas, gas_target);

        // 6. Advance chain head
        chain.advance(block.header.clone());

        let elapsed_ms = start.elapsed().as_millis() as u64;
        let tx_count = block.body.transactions.len() as u64;

        // 7. Record metrics
        crate::metrics::record_block(slot, tx_count, total_gas, elapsed_ms);

        info!(
            slot,
            txs = tx_count,
            gas = total_gas,
            elapsed_ms,
            state_root = hex::encode(state.root()),
            "block processed"
        );

        Ok((tx_count, total_gas, receipts))
    }

    /// Process a header-only block (no transactions — used during header sync).
    /// Returns (0, 0) since no txs are executed.
    pub fn process_block(
        chain: &mut ChainState,
        state: &mut StateManager,
        header: BlockHeader,
        _tx_data: &[Vec<u8>],
    ) -> Result<(u64, u64), String> {
        Self::validate_header(&header, chain)?;

        let gas_target = pyde_tx::fee::GAS_TARGET as u64;
        chain.base_fee = adjust_base_fee(chain.base_fee, 0, gas_target);
        chain.advance(header);

        Ok((0, 0))
    }

    fn validate_header(header: &BlockHeader, chain: &ChainState) -> Result<(), String> {
        if !chain.is_genesis() {
            if header.slot <= chain.head_slot {
                return Err(format!(
                    "block slot {} is not ahead of head {}",
                    header.slot, chain.head_slot
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainState;
    use crate::genesis::{initialize_genesis, devnet_genesis};
    use crate::state_manager::StateManager;
    use pyde_account::address::{derive_eoa_address, ZERO_ADDRESS};
    use pyde_consensus::block::{BlockBody, QuorumCert};
    use pyde_tx::parallel::ExecutionSchedule;
    use pyde_tx::types::{AccessEntry, FeePayer, TransactionType};

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

    fn make_transfer_tx(from: [u8; 32], to: [u8; 32], value: u128, nonce: u64) -> Transaction {
        Transaction {
            from,
            to,
            value,
            data: vec![],
            gas_limit: 50_000,
            nonce,
            signature: vec![0xAA; 666], // dummy sig (validation deferred)
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        }
    }

    #[test]
    fn process_genesis_block() {
        let mut chain = ChainState::genesis([0u8; 32]);
        let mut state =
            StateManager::open(&std::env::temp_dir().join("pyde-test-bp2-genesis"), 1024).unwrap();

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
            StateManager::open(&std::env::temp_dir().join("pyde-test-bp2-old"), 1024).unwrap();

        chain.advance(dummy_header(5));

        let result = BlockProcessor::process_block(&mut chain, &mut state, dummy_header(3), &[]);
        assert!(result.is_err());
    }

    #[test]
    fn sequential_blocks() {
        let mut chain = ChainState::genesis([0u8; 32]);
        let mut state =
            StateManager::open(&std::env::temp_dir().join("pyde-test-bp2-seq"), 1024).unwrap();

        for slot in 1..=5 {
            BlockProcessor::process_block(&mut chain, &mut state, dummy_header(slot), &[]).unwrap();
        }

        assert_eq!(chain.head_slot, 5);
    }

    #[test]
    fn process_block_with_transfer() {
        let dir = std::env::temp_dir().join("pyde-test-bp2-transfer");
        let mut state = StateManager::open(&dir, 1024).unwrap();

        // Initialize genesis with funded accounts
        let config = devnet_genesis();
        let _genesis = initialize_genesis(&mut state, &config).unwrap();

        let mut chain = ChainState::genesis(state.root());

        // Account 0x0101...01 has 1M PYDE from genesis
        let sender = [0x01; 32];
        let recipient = [0x02; 32];

        // Transfer 100 quanta
        let tx = make_transfer_tx(sender, recipient, 100, 0);

        let block = Block {
            header: dummy_header(1),
            body: BlockBody {
                transactions: vec![tx],
                execution_schedule: ExecutionSchedule { groups: vec![], total_txs: 1 },
            },
            proposer_signature: vec![],
        };

        let (tx_count, gas_used, receipts) =
            BlockProcessor::process_full_block(&mut chain, &mut state, &block).unwrap();

        assert_eq!(tx_count, 1);
        // Tx fails validation (dummy signature, no auth keys on genesis account)
        // but the block still processes — failed txs are skipped gracefully.
        // In production, genesis accounts need auth_keys set for real tx execution.
        assert_eq!(receipts.len(), 0); // failed tx produces no receipt
        assert_eq!(chain.head_slot, 1);
    }
}
