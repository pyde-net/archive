//! Fair block building: nonce-ordered, interleaved, per-sender capped.
//!
//! Transactions are grouped by sender, sorted by nonce, then round-robin
//! interleaved across senders. Each sender is capped at SENDER_CAP txs
//! per block to prevent monopolization. Block gas limit AND tx-count
//! cap are enforced.

use pyde_tx::types::Transaction;
use std::collections::{BTreeMap, VecDeque};

/// Maximum transactions from a single sender per block.
/// Matches the nonce window size (16).
pub const SENDER_CAP: usize = 16;

/// Audit-417: hard cap on plaintext transactions per block.
///
/// The mixed-load 1000-TPS soak wedged at slot 2228 with a 1374-tx
/// block that took ~500 ms total apply (signature verify + parallel
/// exec + state-root + vote propagation). That exceeded the
/// `PROGRESS_TIMEOUT_MS = 200 ms` view-change budget, causing 3 of 4
/// validators to flip into view-1 fallback before the canonical
/// view-0 QC formed. The cluster split.
///
/// The gas-only cap (`GAS_CEILING = 1.6 B`) admits up to ~76 K txs
/// per block at the 21 K min-gas floor, mitigated only by
/// `SENDER_CAP` × distinct senders. Under high-fan-in load (1000 TPS
/// from many wallets) that left the proposer building blocks the
/// rest of the cluster physically could not apply in time.
///
/// Sizing rationale: at the empirical ~360 µs/tx total apply
/// budget (execution + sig verify + propagation), 500 txs ≈ 180 ms
/// total apply — comfortably under the 200 ms timeout with margin.
/// At gas-min 21 K, 500 txs = 10.5 M gas, well under the 400 M
/// `GAS_TARGET`, so this cap binds only on high-fan-in low-gas
/// workloads (the wedge mode); large-tx workloads stay
/// gas-bound. Mirrors the design of `MAX_ENCRYPTED_TXS_PER_BLOCK`
/// (=100) which solves the same class of issue for the encrypted
/// pipeline.
///
/// Validator-side defense-in-depth lives in
/// `BlockProcessor::validate_block_body`: a Byzantine proposer
/// shipping `> MAX_TXS_PER_BLOCK` plaintext txs is rejected by
/// every honest validator, so the cap is a hard consensus rule —
/// not a soft policy.
pub const MAX_TXS_PER_BLOCK: usize = 500;

/// Build a fair transaction list for a block.
///
/// Algorithm:
/// 1. Group pending txs by sender
/// 2. Sort each sender's txs by nonce (ascending)
/// 3. Cap each sender at SENDER_CAP txs
/// 4. Round-robin: take 1 tx from each sender, repeat
/// 5. Stop when block gas limit OR `max_count` reached
///
/// Returns (selected_txs, remaining_txs).
/// Remaining txs go back to the pending queue.
pub fn build_tx_list(
    mut pending: Vec<Transaction>,
    block_gas_limit: u64,
    max_count: usize,
) -> (Vec<Transaction>, Vec<Transaction>) {
    if pending.is_empty() {
        return (vec![], vec![]);
    }

    // 1. Group by sender
    let mut by_sender: BTreeMap<[u8; 32], Vec<Transaction>> = BTreeMap::new();
    for tx in pending.drain(..) {
        by_sender.entry(tx.from).or_default().push(tx);
    }

    // 2. Sort each sender's txs by nonce, cap at SENDER_CAP
    let mut queues: Vec<VecDeque<Transaction>> = Vec::new();
    let mut overflow: Vec<Transaction> = Vec::new();

    for (_sender, mut txs) in by_sender {
        txs.sort_by_key(|tx| tx.nonce);

        // Cap: first SENDER_CAP go into the queue, rest go back to pending
        if txs.len() > SENDER_CAP {
            overflow.extend(txs.split_off(SENDER_CAP));
        }
        queues.push(VecDeque::from(txs));
    }

    // 3. Round-robin interleave across senders, enforce gas + count limits
    let mut selected: Vec<Transaction> = Vec::new();
    let mut gas_used: u64 = 0;

    loop {
        let mut any_taken = false;

        // One pass through all sender queues
        for queue in queues.iter_mut() {
            if selected.len() >= max_count {
                break;
            }
            if let Some(tx) = queue.front() {
                // Check gas limit
                if gas_used + tx.gas_limit > block_gas_limit {
                    continue; // skip this tx (too much gas), try next sender
                }

                let tx = queue.pop_front().unwrap();
                gas_used += tx.gas_limit;
                selected.push(tx);
                any_taken = true;

                if gas_used >= block_gas_limit {
                    break;
                }
            }
        }

        if !any_taken || gas_used >= block_gas_limit || selected.len() >= max_count {
            break;
        }
    }

    // 4. Collect remaining txs (not selected) to return to pending queue
    for queue in queues {
        overflow.extend(queue);
    }

    (selected, overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_tx::types::{FeePayer, TransactionType};

    fn make_tx(from: [u8; 32], nonce: u64, gas: u64) -> Transaction {
        Transaction {
            from,
            to: [0xBB; 32],
            value: 0,
            data: vec![],
            gas_limit: gas,
            nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        }
    }

    #[test]
    fn empty_pending() {
        let (selected, remaining) = build_tx_list(vec![], 1_000_000, MAX_TXS_PER_BLOCK);
        assert!(selected.is_empty());
        assert!(remaining.is_empty());
    }

    #[test]
    fn single_sender_nonce_ordered() {
        let alice = [0x01; 32];
        let pending = vec![
            make_tx(alice, 3, 21_000),
            make_tx(alice, 1, 21_000),
            make_tx(alice, 2, 21_000),
            make_tx(alice, 0, 21_000),
        ];

        let (selected, _) = build_tx_list(pending, 1_000_000, MAX_TXS_PER_BLOCK);
        assert_eq!(selected.len(), 4);
        assert_eq!(selected[0].nonce, 0);
        assert_eq!(selected[1].nonce, 1);
        assert_eq!(selected[2].nonce, 2);
        assert_eq!(selected[3].nonce, 3);
    }

    #[test]
    fn round_robin_interleaved() {
        let alice = [0x01; 32];
        let bob = [0x02; 32];
        let pending = vec![
            make_tx(alice, 0, 21_000),
            make_tx(alice, 1, 21_000),
            make_tx(bob, 0, 21_000),
            make_tx(bob, 1, 21_000),
        ];

        let (selected, _) = build_tx_list(pending, 1_000_000, MAX_TXS_PER_BLOCK);
        assert_eq!(selected.len(), 4);
        // Round-robin: alice:0, bob:0, alice:1, bob:1
        assert_eq!(selected[0].from, alice);
        assert_eq!(selected[0].nonce, 0);
        assert_eq!(selected[1].from, bob);
        assert_eq!(selected[1].nonce, 0);
        assert_eq!(selected[2].from, alice);
        assert_eq!(selected[2].nonce, 1);
        assert_eq!(selected[3].from, bob);
        assert_eq!(selected[3].nonce, 1);
    }

    #[test]
    fn per_sender_cap_enforced() {
        let alice = [0x01; 32];
        // Send 20 txs from alice (cap is 16)
        let pending: Vec<Transaction> = (0..20).map(|i| make_tx(alice, i, 21_000)).collect();

        let (selected, remaining) = build_tx_list(pending, 100_000_000, MAX_TXS_PER_BLOCK);
        assert_eq!(selected.len(), SENDER_CAP); // 16
        assert_eq!(remaining.len(), 4); // 20 - 16
                                        // First 16 selected, nonce ordered
        for (i, tx) in selected.iter().enumerate() {
            assert_eq!(tx.nonce, i as u64);
        }
    }

    #[test]
    fn gas_limit_respected() {
        let alice = [0x01; 32];
        let bob = [0x02; 32];
        let pending = vec![
            make_tx(alice, 0, 50_000),
            make_tx(alice, 1, 50_000),
            make_tx(bob, 0, 50_000),
            make_tx(bob, 1, 50_000),
        ];

        // Gas limit only fits 2 txs
        let (selected, remaining) = build_tx_list(pending, 100_000, MAX_TXS_PER_BLOCK);
        assert_eq!(selected.len(), 2);
        assert_eq!(remaining.len(), 2);
        // Round-robin: one from each sender
        assert_eq!(selected[0].from, alice);
        assert_eq!(selected[1].from, bob);
    }

    #[test]
    fn no_monopolization() {
        let alice = [0x01; 32];
        let bob = [0x02; 32];
        // Alice sends 100 txs, Bob sends 2
        let mut pending: Vec<Transaction> = (0..100).map(|i| make_tx(alice, i, 21_000)).collect();
        pending.push(make_tx(bob, 0, 21_000));
        pending.push(make_tx(bob, 1, 21_000));

        let (selected, _) = build_tx_list(pending, 100_000_000, MAX_TXS_PER_BLOCK);
        // Alice capped at 16, Bob gets both
        let alice_count = selected.iter().filter(|tx| tx.from == alice).count();
        let bob_count = selected.iter().filter(|tx| tx.from == bob).count();
        assert_eq!(alice_count, SENDER_CAP);
        assert_eq!(bob_count, 2);
        // Bob's txs are interleaved, not at the end
        assert_eq!(selected[1].from, bob); // bob:0 after alice:0
    }

    /// Audit-417: when many distinct senders submit just under
    /// `SENDER_CAP` each, the gas budget alone is not enough to
    /// stop the proposer from selecting more than
    /// `MAX_TXS_PER_BLOCK` txs (this is the slot-2228 wedge mode:
    /// 1000-TPS fan-in across ~500 wallets producing ~1374-2244-tx
    /// blocks that exceed `PROGRESS_TIMEOUT_MS`). The count cap
    /// must clamp the selection regardless of remaining gas.
    #[test]
    fn audit_417_count_cap_clamps_high_fan_in() {
        // 1000 senders × 2 txs = 2000 pending. Gas budget unlimited
        // for this test (we want the count cap to bind, not gas).
        let mut pending: Vec<Transaction> = Vec::new();
        for i in 0..1000u64 {
            let mut sender = [0u8; 32];
            sender[..8].copy_from_slice(&i.to_le_bytes());
            pending.push(make_tx(sender, 0, 21_000));
            pending.push(make_tx(sender, 1, 21_000));
        }

        let (selected, remaining) = build_tx_list(pending, u64::MAX, MAX_TXS_PER_BLOCK);

        assert_eq!(
            selected.len(),
            MAX_TXS_PER_BLOCK,
            "count cap must bind under high-fan-in load"
        );
        // Remaining must equal total - selected; nothing dropped.
        assert_eq!(remaining.len(), 2000 - MAX_TXS_PER_BLOCK);
    }

    /// The count cap is a per-block cap, not a per-call cap — once
    /// the cap is reached, the round-robin loop exits cleanly and
    /// every untouched tx is returned in `remaining` for the next
    /// block's proposal. No tx is silently dropped.
    #[test]
    fn audit_417_count_cap_preserves_remaining() {
        let alice = [0x01; 32];
        let bob = [0x02; 32];
        let pending = vec![
            make_tx(alice, 0, 21_000),
            make_tx(alice, 1, 21_000),
            make_tx(alice, 2, 21_000),
            make_tx(bob, 0, 21_000),
            make_tx(bob, 1, 21_000),
        ];

        let (selected, remaining) = build_tx_list(pending, u64::MAX, 2);

        assert_eq!(selected.len(), 2);
        assert_eq!(remaining.len(), 3);
        // Round-robin order: alice:0 + bob:0 selected first.
        assert_eq!(selected[0].from, alice);
        assert_eq!(selected[1].from, bob);
    }
}
