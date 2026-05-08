//! Block construction: proposer selects and orders transactions.
//!
//! The proposer's block building pipeline:
//! 1. Select transactions from mempool (FCFS, respect gas limit)
//! 2. Order by nonce per sender (ensure sequential execution correctness)
//! 3. VRF-shuffle the ordering (MEV protection)
//! 4. Build parallel execution schedule from access lists
//! 5. Package into block

use crate::encrypted::EncryptedTx;
use crate::ordering::{apply_shuffle, shuffle_seed, vrf_shuffle};
use crate::pool::Mempool;
use pyde_account::address::Address;
use pyde_tx::parallel::{schedule_from_access_lists, ExecutionSchedule};
use pyde_tx::types::AccessEntry;
use std::collections::HashMap;

/// A constructed block ready for proposal.
#[derive(Clone, Debug)]
pub struct ConstructedBlock {
    /// Selected encrypted transactions in final order (VRF-shuffled).
    pub transactions: Vec<EncryptedTx>,
    /// Parallel execution schedule built from access lists.
    pub execution_schedule: ExecutionSchedule,
    /// Total gas used by selected transactions.
    pub total_gas: u64,
    /// The VRF shuffle permutation (for verification).
    pub shuffle_permutation: Vec<usize>,
}

/// Select transactions from the mempool, ordered by nonce per sender.
///
/// Within a sender's transactions, they must be in nonce order for
/// sequential execution correctness. Across senders, FCFS applies.
fn select_and_order(
    mempool: &Mempool,
    block_gas_limit: u64,
    current_slot: u64,
) -> Vec<EncryptedTx> {
    // Group by sender
    let mut by_sender: HashMap<Address, Vec<&EncryptedTx>> = HashMap::new();
    for tx in mempool.in_arrival_order() {
        if tx.is_expired(current_slot) {
            continue;
        }
        by_sender.entry(tx.sender).or_default().push(tx);
    }

    // Sort each sender's txs by nonce
    for txs in by_sender.values_mut() {
        txs.sort_by_key(|tx| tx.nonce);
    }

    // Interleave senders' txs in round-robin (deterministic order across senders)
    // while respecting per-sender nonce ordering
    let mut selected = Vec::new();
    let mut gas_used = 0u64;

    // Sort senders for deterministic ordering
    let mut cursors: HashMap<Address, usize> = HashMap::new();
    let mut senders: Vec<Address> = by_sender.keys().copied().collect();
    senders.sort();
    let mut progress = true;

    while progress {
        progress = false;
        for sender in &senders {
            let txs = &by_sender[sender];
            let cursor = cursors.entry(*sender).or_insert(0);
            if *cursor >= txs.len() {
                continue;
            }

            let tx = txs[*cursor];
            if gas_used.saturating_add(tx.gas_limit) > block_gas_limit {
                *cursor = txs.len(); // skip this sender from now on
                continue;
            }

            selected.push(tx.clone());
            gas_used += tx.gas_limit;
            *cursor += 1;
            progress = true;
        }
    }

    selected
}

/// Build a block from the mempool.
///
/// Full pipeline:
/// 1. Select txs (FCFS, gas limit, nonce ordering)
/// 2. VRF-shuffle
/// 3. Build parallel schedule from access lists
pub fn build_block(
    mempool: &Mempool,
    block_gas_limit: u64,
    current_slot: u64,
    vrf_output: &[u8; 32],
) -> ConstructedBlock {
    // 1. Select and order by nonce
    let ordered = select_and_order(mempool, block_gas_limit, current_slot);
    let total_gas: u64 = ordered.iter().map(|tx| tx.gas_limit).sum();

    if ordered.is_empty() {
        return ConstructedBlock {
            transactions: vec![],
            execution_schedule: ExecutionSchedule {
                groups: vec![],
                total_txs: 0,
            },
            total_gas: 0,
            shuffle_permutation: vec![],
        };
    }

    // 2. VRF-shuffle
    let seed = shuffle_seed(vrf_output);
    let permutation = vrf_shuffle(ordered.len(), &seed);
    let shuffled = apply_shuffle(&ordered, &permutation);

    // 3. Build parallel schedule from access lists
    let access_lists: Vec<Vec<AccessEntry>> =
        shuffled.iter().map(|tx| tx.access_list.clone()).collect();
    let execution_schedule = schedule_from_access_lists(&access_lists);

    ConstructedBlock {
        transactions: shuffled,
        execution_schedule,
        total_gas,
        shuffle_permutation: permutation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypted::encrypt_transaction;
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::threshold;
    use pyde_tx::types::AccessEntry;

    fn make_pk() -> threshold::ThresholdPublicKey {
        let (pk, _) = threshold::threshold_keygen(3, 2).unwrap();
        pk
    }

    fn dummy_sig() -> Vec<u8> {
        vec![0xAA; 666]
    }

    fn make_access(addr_seed: u8, key: [u8; 32], write: bool) -> Vec<AccessEntry> {
        let addr = derive_eoa_address(&[addr_seed; 897]);
        vec![AccessEntry {
            address: addr,
            reads: if write { vec![] } else { vec![key] },
            writes: if write { vec![key] } else { vec![] },
        }]
    }

    fn add_tx(
        pool: &mut Mempool,
        pk: &threshold::ThresholdPublicKey,
        sender_seed: &[u8],
        nonce: u64,
        gas: u64,
        access_list: Vec<AccessEntry>,
    ) {
        let sender = derive_eoa_address(sender_seed);
        let to = derive_eoa_address(b"to");
        let tx = encrypt_transaction(
            sender,
            nonce,
            gas,
            access_list,
            None,
            1,
            dummy_sig(),
            &to,
            0,
            b"",
            pk,
        )
        .unwrap();
        pool.add_unverified_for_devnet(tx).unwrap();
    }

    // ========== Task 0539: Block respects gas limit ==========

    #[test]
    fn block_respects_gas_limit() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        // Add 3 txs: 50K + 50K + 50K = 150K total
        for i in 0..3u64 {
            add_tx(
                &mut pool,
                &pk,
                &i.to_le_bytes(),
                0,
                50_000,
                make_access(i as u8, [i as u8; 32], false),
            );
        }

        // Block gas limit of 100K → can fit at most 2
        let block = build_block(&pool, 100_000, 0, &[0xAA; 32]);
        assert!(block.total_gas <= 100_000);
        assert_eq!(block.transactions.len(), 2);
    }

    // ========== Task 0540: Nonce order within same sender ==========

    #[test]
    fn nonce_order_per_sender() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        let sender_seed = b"alice_key";
        // Add out of nonce order
        add_tx(
            &mut pool,
            &pk,
            sender_seed,
            2,
            30_000,
            make_access(1, [0x01; 32], false),
        );
        add_tx(
            &mut pool,
            &pk,
            sender_seed,
            0,
            30_000,
            make_access(2, [0x02; 32], false),
        );
        add_tx(
            &mut pool,
            &pk,
            sender_seed,
            1,
            30_000,
            make_access(3, [0x03; 32], false),
        );

        // select_and_order should sort by nonce
        let ordered = select_and_order(&pool, 1_000_000, 0);
        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered[0].nonce, 0);
        assert_eq!(ordered[1].nonce, 1);
        assert_eq!(ordered[2].nonce, 2);
    }

    // ========== Task 0541: Parallel groups have no conflicts ==========

    #[test]
    fn conflicting_txs_grouped_together() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        let shared_key = [0xAA; 32];

        // tx0 and tx1 write to same key → conflict → same group
        add_tx(
            &mut pool,
            &pk,
            b"sender0",
            0,
            30_000,
            make_access(1, shared_key, true),
        );
        add_tx(
            &mut pool,
            &pk,
            b"sender1",
            0,
            30_000,
            make_access(1, shared_key, true),
        );

        // tx2 touches a different key → independent → own group
        add_tx(
            &mut pool,
            &pk,
            b"sender2",
            0,
            30_000,
            make_access(2, [0xBB; 32], false),
        );

        let block = build_block(&pool, 1_000_000, 0, &[0xCC; 32]);
        assert_eq!(block.transactions.len(), 3);

        // Conflicting txs in same group, independent tx in separate group
        // (VRF shuffle may reorder, so we check group count)
        assert!(block.execution_schedule.group_count() >= 2);

        // Verify no cross-group conflicts
        let groups = &block.execution_schedule.groups;
        let access_lists: Vec<Vec<AccessEntry>> = block
            .transactions
            .iter()
            .map(|tx| tx.access_list.clone())
            .collect();
        for (i, g1) in groups.iter().enumerate() {
            for g2 in groups.iter().skip(i + 1) {
                for &a in &g1.tx_indices {
                    for &b in &g2.tx_indices {
                        assert!(
                            !pyde_tx::parallel::access_lists_conflict(
                                &access_lists[a],
                                &access_lists[b]
                            ),
                            "cross-group conflict between tx {} and tx {}",
                            a,
                            b
                        );
                    }
                }
            }
        }
    }

    // ========== VRF shuffle applied ==========

    #[test]
    fn block_is_vrf_shuffled() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        for i in 0..10u64 {
            add_tx(
                &mut pool,
                &pk,
                &i.to_le_bytes(),
                0,
                25_000,
                make_access(i as u8, [i as u8; 32], false),
            );
        }

        let block1 = build_block(&pool, 1_000_000, 0, &[0xAA; 32]);
        let block2 = build_block(&pool, 1_000_000, 0, &[0xBB; 32]);

        // Different VRF outputs → different orderings (compare sender addresses)
        let order1: Vec<Address> = block1.transactions.iter().map(|t| t.sender).collect();
        let order2: Vec<Address> = block2.transactions.iter().map(|t| t.sender).collect();
        assert_ne!(order1, order2);
    }

    #[test]
    fn same_vrf_same_block() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        for i in 0..5u64 {
            add_tx(
                &mut pool,
                &pk,
                &i.to_le_bytes(),
                0,
                25_000,
                make_access(i as u8, [i as u8; 32], false),
            );
        }

        let block1 = build_block(&pool, 1_000_000, 0, &[0xAA; 32]);
        let block2 = build_block(&pool, 1_000_000, 0, &[0xAA; 32]);

        let order1: Vec<Address> = block1.transactions.iter().map(|t| t.sender).collect();
        let order2: Vec<Address> = block2.transactions.iter().map(|t| t.sender).collect();
        assert_eq!(order1, order2);
    }

    // ========== Empty block ==========

    #[test]
    fn empty_mempool_empty_block() {
        let pool = Mempool::new();
        let block = build_block(&pool, 1_000_000, 0, &[0xAA; 32]);
        assert!(block.transactions.is_empty());
        assert_eq!(block.total_gas, 0);
        assert_eq!(block.execution_schedule.group_count(), 0);
    }

    // ========== Multiple senders interleaved ==========

    #[test]
    fn multiple_senders_interleaved() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        // Alice: nonce 0, 1
        add_tx(
            &mut pool,
            &pk,
            b"alice",
            0,
            25_000,
            make_access(1, [0x01; 32], false),
        );
        add_tx(
            &mut pool,
            &pk,
            b"alice",
            1,
            25_000,
            make_access(2, [0x02; 32], false),
        );

        // Bob: nonce 0
        add_tx(
            &mut pool,
            &pk,
            b"bob",
            0,
            25_000,
            make_access(3, [0x03; 32], false),
        );

        let ordered = select_and_order(&pool, 1_000_000, 0);
        assert_eq!(ordered.len(), 3);

        // Alice's txs should maintain nonce order relative to each other
        let alice_addr = derive_eoa_address(b"alice");
        let alice_nonces: Vec<u64> = ordered
            .iter()
            .filter(|t| t.sender == alice_addr)
            .map(|t| t.nonce)
            .collect();
        assert_eq!(alice_nonces, vec![0, 1]);
    }
}
