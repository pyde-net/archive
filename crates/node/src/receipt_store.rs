//! In-memory receipt and log storage.
//!
//! Stores transaction receipts and logs for RPC queries.
//! Bounded to recent blocks — old receipts are pruned.

use pyde_tx::execution::{LogEntry, Receipt};
use std::collections::HashMap;

/// Maximum number of slots to keep receipts for.
const MAX_RECEIPT_SLOTS: u64 = 10_000;

/// Stores receipts indexed by tx_hash, with logs indexed by slot.
pub struct ReceiptStore {
    /// tx_hash → Receipt
    receipts: HashMap<[u8; 32], Receipt>,
    /// slot → list of tx_hashes in that slot (for pruning)
    slot_txs: HashMap<u64, Vec<[u8; 32]>>,
    /// Lowest slot still stored.
    lowest_slot: u64,
}

impl ReceiptStore {
    pub fn new() -> Self {
        Self {
            receipts: HashMap::new(),
            slot_txs: HashMap::new(),
            lowest_slot: 0,
        }
    }

    /// Store receipts for a block.
    ///
    /// Audit 411: first-write-wins. The same block can be executed
    /// twice on the same validator under race conditions:
    ///   1. The canonical-apply path (after QC) executes the block,
    ///      writes state, advances `chain.head_slot`, and inserts
    ///      `success=true` receipts.
    ///   2. The gossip-blocks topic delivers the SAME block at
    ///      slot S. `validate_header_with_checkpoint` rejects
    ///      `slot <= chain.head_slot`, but the validate read isn't
    ///      synchronized against the canonical-apply chain.write()
    ///      lock — a stale-head read lets the gossip-blocks path
    ///      re-enter `process_full_block`, which now executes
    ///      against the post-canonical state. Every tx in the
    ///      block sees its sender's nonce already past the window
    ///      and the pipeline emits `success=false` receipts via
    ///      `emit_failed_execution_receipt`.
    /// Pre-411 the gossip-blocks `BlockProcessed` handler then
    /// re-inserted the stale `success=false` receipts on top of
    /// the canonical `success=true` ones, breaking
    /// `pyde_getTransactionReceipt` for every tx in the block.
    /// State changes (balances, nonces) were unaffected because
    /// `process_full_block` wrote to a fresh overlay that the
    /// stale-head path's `take_pending_writes` swallowed — only
    /// the receipt metadata diverged. First-write-wins closes the
    /// metadata divergence at the cheapest layer: callers don't
    /// need head_slot guards before invoking, and any other future
    /// race (reorg, sync replay) lands in the same defensive
    /// posture.
    pub fn insert_block_receipts(&mut self, slot: u64, receipts: Vec<Receipt>) {
        if self
            .slot_txs
            .get(&slot)
            .map(|h| !h.is_empty())
            .unwrap_or(false)
        {
            return;
        }
        let hashes: Vec<[u8; 32]> = receipts.iter().map(|r| r.tx_hash).collect();
        for receipt in receipts {
            self.receipts.insert(receipt.tx_hash, receipt);
        }
        self.slot_txs.insert(slot, hashes);

        // Prune old slots
        if slot > MAX_RECEIPT_SLOTS {
            let prune_before = slot - MAX_RECEIPT_SLOTS;
            self.prune_before(prune_before);
        }
    }

    /// Get a receipt by tx hash.
    pub fn get(&self, tx_hash: &[u8; 32]) -> Option<&Receipt> {
        self.receipts.get(tx_hash)
    }

    /// Get all logs matching a filter.
    pub fn get_logs(
        &self,
        from_slot: u64,
        to_slot: u64,
        address_filter: Option<&[u8; 32]>,
    ) -> Vec<(u64, &LogEntry)> {
        let mut results = Vec::new();
        // Iterate over stored slots only (not the full range which could be u64::MAX)
        for (&slot, tx_hashes) in &self.slot_txs {
            if slot < from_slot || slot > to_slot {
                continue;
            }
            for hash in tx_hashes {
                if let Some(receipt) = self.receipts.get(hash) {
                    for log in &receipt.logs {
                        if let Some(addr) = address_filter {
                            if &log.address != addr {
                                continue;
                            }
                        }
                        results.push((slot, log));
                    }
                }
            }
        }
        results.sort_by_key(|(slot, _)| *slot);
        results
    }

    /// Number of stored receipts.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Tx hashes committed at `slot`, in inclusion order. Returns
    /// `None` for a slot that's been pruned or never indexed.
    /// Used by `pyde_getBlockByNumber` to surface transactions in
    /// the block-detail RPC response — the chain's `header(slot)`
    /// only carries `tx_root`, so external indexers (block
    /// explorers) need this to enumerate a slot's contents without
    /// per-tx-hash lookups.
    pub fn tx_hashes_at_slot(&self, slot: u64) -> Option<Vec<[u8; 32]>> {
        self.slot_txs.get(&slot).cloned()
    }

    fn prune_before(&mut self, slot: u64) {
        let slots_to_remove: Vec<u64> = self
            .slot_txs
            .keys()
            .filter(|s| **s < slot)
            .copied()
            .collect();

        for s in slots_to_remove {
            if let Some(hashes) = self.slot_txs.remove(&s) {
                for h in hashes {
                    self.receipts.remove(&h);
                }
            }
        }
        self.lowest_slot = slot;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sparse_merkle_tree::H256;

    fn dummy_receipt(tx_hash: [u8; 32], gas: u64) -> Receipt {
        Receipt {
            tx_hash,
            success: true,
            gas_used: gas,
            gas_refund: 0,
            effective_gas: gas,
            fee_paid: 0,
            fee_burned: 0,
            fee_validator: 0,
            fee_treasury: 0,
            logs: vec![],
            state_root: H256::zero(),
            return_data: vec![],
        }
    }

    #[test]
    fn insert_and_get() {
        let mut store = ReceiptStore::new();
        let hash = [0xAA; 32];
        store.insert_block_receipts(1, vec![dummy_receipt(hash, 21000)]);

        let r = store.get(&hash).unwrap();
        assert_eq!(r.gas_used, 21000);
        assert!(r.success);
    }

    /// Audit 411: a second `insert_block_receipts` for an already-
    /// populated slot is a no-op. Pre-411 the stale-head gossip-
    /// blocks re-execution path overwrote canonical `success=true`
    /// receipts with `success=false` ones; this guard preserves the
    /// canonical apply's metadata regardless of arrival order.
    #[test]
    fn duplicate_insert_does_not_overwrite() {
        let mut store = ReceiptStore::new();
        let hash = [0xAA; 32];
        let mut good = dummy_receipt(hash, 21000);
        good.success = true;
        store.insert_block_receipts(1, vec![good]);

        let mut bad = dummy_receipt(hash, 0);
        bad.success = false;
        store.insert_block_receipts(1, vec![bad]);

        let r = store.get(&hash).unwrap();
        assert!(r.success, "first-write-wins: success flag preserved");
        assert_eq!(r.gas_used, 21000, "first-write-wins: gas preserved");
    }

    #[test]
    fn missing_receipt_returns_none() {
        let store = ReceiptStore::new();
        assert!(store.get(&[0xFF; 32]).is_none());
    }

    #[test]
    fn prune_old_slots() {
        let mut store = ReceiptStore::new();
        store.insert_block_receipts(1, vec![dummy_receipt([0x01; 32], 100)]);
        store.insert_block_receipts(20_000, vec![dummy_receipt([0x02; 32], 200)]);

        // Slot 1 should be pruned (20000 - 10000 = 10000 > 1)
        assert!(store.get(&[0x01; 32]).is_none());
        assert!(store.get(&[0x02; 32]).is_some());
    }

    #[test]
    fn get_logs_with_filter() {
        let mut store = ReceiptStore::new();
        let addr = [0xCC; 32];
        let receipt = Receipt {
            tx_hash: [0xAA; 32],
            success: true,
            gas_used: 50000,
            gas_refund: 0,
            effective_gas: 50000,
            fee_paid: 0,
            fee_burned: 0,
            fee_validator: 0,
            fee_treasury: 0,
            logs: vec![
                LogEntry {
                    address: addr,
                    topics: vec![],
                    data: vec![1, 2, 3],
                },
                LogEntry {
                    address: [0xDD; 32],
                    topics: vec![],
                    data: vec![4, 5],
                },
            ],
            state_root: H256::zero(),
            return_data: vec![],
        };
        store.insert_block_receipts(5, vec![receipt]);

        // Filter by address
        let logs = store.get_logs(0, 10, Some(&addr));
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].1.data, vec![1, 2, 3]);

        // No filter — all logs
        let all_logs = store.get_logs(0, 10, None);
        assert_eq!(all_logs.len(), 2);
    }
}
