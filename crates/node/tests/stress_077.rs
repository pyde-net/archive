//! MAINNET_PLAN task 077 stress tests.
//!
//! Part B — "wide parallel": 1,000 non-conflicting transfers. Asserts
//!   that our access-list-driven scheduler classifies every tx as
//!   independent (1,000 single-tx groups — the max-parallel outcome),
//!   every tx commits cleanly through the tx pipeline, and every
//!   recipient's balance matches the expected transfer amount.
//!
//!   Scope: this test verifies the *schedule* the block processor
//!   would hand to rayon is correct and the per-tx commit path is
//!   sound. The rayon executor itself is exercised by `bench_mempool`
//!   and by the multi-node loadgen; it isn't re-tested here.
//!
//! Part A — "deep call chain": 50 nested cross-contract calls in one
//!   transaction. Proves PVM's `MAX_EXT_CALL_DEPTH = 64` headroom is
//!   real (not just documented), storage writes at every level survive,
//!   and the call returns propagate bottom-up without stack-overflow
//!   or gas-accounting drift.
//!
//!   NOTE: Part A is pending a reusable multi-contract deploy helper
//!   (constructor-arg ABI encoding + per-slot address derivation for
//!   CREATE). The VM-level `MAX_EXT_CALL_DEPTH = 64` enforcement is
//!   already covered by pvm unit tests; what's missing here is the
//!   integration test that deploys N linked contracts and exercises
//!   the full 50-hop path through the tx pipeline.
//!
//! Run with #[ignore] so the default `cargo test` stays quick.

use pyde_account::address::derive_eoa_address;
use pyde_tx::parallel::schedule;
use pyde_tx::pipeline::{execute_transaction, BlockContext};
use pyde_tx::types::*;
use sparse_merkle_tree::H256;

fn block_ctx() -> BlockContext {
    BlockContext {
        height: 100,
        timestamp: 1_000_000,
        base_fee: 1,
        block_gas_limit: 4_000_000_000,
        chain_id: 31337,
        validator_address: derive_eoa_address(b"validator"),
        dev_skip_signature: true,
        block_sigs_pre_verified: false,
    }
}

fn fund_account(smt: &mut pyde_state::smt::PydeSMT, idx: u64) -> [u8; 32] {
    // Synthetic account derivation — seeds `idx` into a dummy FALCON
    // public-key buffer so every idx produces a distinct address.
    // dev_skip_signature=true in the BlockContext lets us bypass the
    // real FALCON verify path for these tests.
    let seed = idx.to_le_bytes();
    let mut pk_bytes = vec![0u8; 897];
    pk_bytes[..8].copy_from_slice(&seed);
    let address = derive_eoa_address(&pk_bytes);

    let account = pyde_account::types::Account {
        address,
        nonce: 0,
        balance: 1_000_000_000_000,
        code_hash: H256::zero(),
        storage_root: H256::zero(),
        account_type: pyde_account::types::AccountType::EOA,
        auth_keys: pyde_account::types::AuthKeys::None,
        gas_tank: 0,
        key_nonce: 0,
    };
    smt.insert(
        pyde_state::keys::balance_key(&address),
        account.to_bytes(),
    )
    .unwrap();
    smt.insert(
        pyde_state::keys::nonce_key(&address),
        pyde_account::nonce::NonceState::new().to_bytes().to_vec(),
    )
    .unwrap();
    address
}

fn fund_recipient_only(smt: &mut pyde_state::smt::PydeSMT, idx: u64) -> [u8; 32] {
    // Recipient addresses derived from a separate seed space so we
    // can't accidentally collide with sender addresses.
    let seed = (idx ^ 0xFFFF_FFFF_FFFF_FFFF).to_le_bytes();
    let mut pk_bytes = vec![0u8; 897];
    pk_bytes[..8].copy_from_slice(&seed);
    let address = derive_eoa_address(&pk_bytes);
    let account = pyde_account::types::Account {
        address,
        nonce: 0,
        balance: 0,
        code_hash: H256::zero(),
        storage_root: H256::zero(),
        account_type: pyde_account::types::AccountType::EOA,
        auth_keys: pyde_account::types::AuthKeys::None,
        gas_tank: 0,
        key_nonce: 0,
    };
    smt.insert(
        pyde_state::keys::balance_key(&address),
        account.to_bytes(),
    )
    .unwrap();
    address
}

fn make_transfer(from: [u8; 32], to: [u8; 32], nonce: u64) -> Transaction {
    // Access list declares the two balance slots this transfer touches
    // so the parallel scheduler can group non-conflicting txs.
    let from_slot = pyde_crypto::poseidon2::poseidon2_hash(&{
        let mut buf = Vec::with_capacity(33);
        buf.extend_from_slice(&from);
        buf.push(0x04);
        buf
    })
    .to_bytes();
    let to_slot = pyde_crypto::poseidon2::poseidon2_hash(&{
        let mut buf = Vec::with_capacity(33);
        buf.extend_from_slice(&to);
        buf.push(0x04);
        buf
    })
    .to_bytes();
    Transaction {
        from,
        to,
        value: 1_000,
        data: vec![],
        gas_limit: 21_000,
        nonce,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![
            AccessEntry {
                address: from,
                reads: vec![],
                writes: vec![from_slot],
            },
            AccessEntry {
                address: to,
                reads: vec![],
                writes: vec![to_slot],
            },
        ],
        deadline: None,
        chain_id: 31337,
        tx_type: TransactionType::Standard,
    }
}

/// Task 077 Part B — 1,000 non-conflicting transfers.
///
/// Every sender has a distinct recipient, so the access list for tx
/// `i` (writes to sender_i + recipient_i) shares no slot with tx
/// `j != i`. Our union-find scheduler must classify each tx as
/// independent (1,000 groups of 1). The pipeline must then commit
/// all 1,000 cleanly, with every recipient credited exactly once.
#[test]
#[ignore = "stress test — run with --ignored"]
fn task_077_wide_parallel_1000_transfers() {
    const N: u64 = 1_000;

    let mut smt = pyde_state::smt::PydeSMT::new();
    let ctx = block_ctx();

    // --- Setup: fund N unique senders + create N unique recipients ---
    let mut senders: Vec<[u8; 32]> = Vec::with_capacity(N as usize);
    let mut recipients: Vec<[u8; 32]> = Vec::with_capacity(N as usize);
    for i in 0..N {
        senders.push(fund_account(&mut smt, i));
        recipients.push(fund_recipient_only(&mut smt, i));
    }

    // --- Build N non-conflicting transfer txs ---
    let txs: Vec<Transaction> = (0..N)
        .map(|i| make_transfer(senders[i as usize], recipients[i as usize], 0))
        .collect();

    // --- Parallel scheduler must see every tx as independent ---
    // Union-find unions two txs when they share a write slot. With
    // disjoint senders and disjoint recipients, nothing shares a
    // write → each tx lands in its own group. N groups of 1 is the
    // max-parallel outcome the scheduler can produce for this
    // workload; the block processor then fans them across rayon.
    let plan = schedule(&txs);
    assert_eq!(
        plan.groups.len(),
        N as usize,
        "expected {} independent groups for fully disjoint transfers, got {}",
        N,
        plan.groups.len()
    );
    assert_eq!(
        plan.total_txs, N as usize,
        "schedule total_txs should match input len"
    );
    for (i, group) in plan.groups.iter().enumerate() {
        assert_eq!(
            group.tx_indices.len(),
            1,
            "group {} should hold exactly 1 tx",
            i
        );
    }

    // --- Execute and verify every tx committed ---
    let mut successes = 0u64;
    let mut total_gas_charged: u128 = 0;
    for tx in &txs {
        let r = execute_transaction(tx, &mut smt, &ctx).expect("tx executed");
        assert!(r.success, "transfer failed: {:?}", r.return_data);
        successes += 1;
        total_gas_charged += r.effective_gas as u128 * ctx.base_fee;
    }
    assert_eq!(successes, N, "all {} transfers should succeed", N);

    // --- Verify recipient balances reflect the transfers ---
    for r_addr in &recipients {
        let bal_key = pyde_state::keys::balance_key(r_addr);
        let bytes = smt.get(&bal_key).expect("recipient account exists");
        let account = pyde_account::types::Account::from_bytes(&bytes)
            .expect("account decodes");
        assert_eq!(
            account.balance, 1_000,
            "recipient {:?} should have received exactly 1000 quanta",
            hex::encode(r_addr)
        );
    }

    println!(
        "\n  ✓ task 077 Part B PASS: {} transfers, {} independent parallel groups, total gas charged {} quanta",
        N, plan.groups.len(), total_gas_charged
    );
}
