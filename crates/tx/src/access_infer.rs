//! Access list inference: simulate tx execution to discover which storage
//! keys are touched. Used by the block builder to enable parallel scheduling
//! without requiring users to manually declare access lists.

use crate::types::{AccessEntry, Transaction};
use pyde_state::smt::StateAccess;

/// Simulate a transaction to discover which storage keys it reads/writes.
/// Returns a list of AccessEntry with the discovered keys.
/// The simulation runs on a read-only overlay — no state is modified.
pub fn infer_access_list(
    tx: &Transaction,
    state: &dyn StateAccess,
    block_ctx: &crate::pipeline::BlockContext,
) -> Vec<AccessEntry> {
    // Skip if already has access list
    if !tx.access_list.is_empty() {
        return tx.access_list.clone();
    }

    // Skip non-contract calls (transfers don't touch storage)
    if tx.to == [0u8; 32] || tx.data.is_empty() {
        return vec![];
    }

    // Check if target has code
    let code_key = pyde_state::keys::code_key(&tx.to);
    let code = match state.get(&code_key) {
        Some(c) if !c.is_empty() => c,
        _ => return vec![], // no code = simple transfer
    };

    // Load sender account for simulation
    let _sender = match state.get(&pyde_state::keys::balance_key(&tx.from)) {
        Some(bytes) => match pyde_account::types::Account::from_bytes(&bytes) {
            Some(a) => a,
            None => return vec![],
        },
        None => return vec![],
    };

    // Quick simulation: run the tx and collect storage keys
    let ctx = pyde_vm::vm::ExecutionContext {
        caller: tx.from,
        self_address: tx.to,
        call_value: ethnum::U256::from(tx.value),
        block_number: block_ctx.height,
        timestamp: block_ctx.timestamp,
        gas_price: ethnum::U256::from(block_ctx.base_fee),
        tx_nonce: tx.nonce,
        tx_gas_limit: tx.gas_limit,
        tx_hash: ethnum::U256::ZERO,
        block_proposer: [0u8; 32],
        block_hashes: vec![],
        balances: std::collections::HashMap::new(),
    };

    let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(tx.gas_limit, ctx);
    vm.calldata = tx.data.clone();

    // Set up storage backend for simulation reads.
    // SAFETY: state is not mutated during simulation. The closure is dropped
    // before this function returns, so the reference remains valid.
    let state_vtable = unsafe { std::mem::transmute::<&dyn StateAccess, [usize; 2]>(state) };
    vm.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
        let smt_key = sparse_merkle_tree::H256::from(key.to_le_bytes());
        let state_ref: &dyn StateAccess =
            unsafe { std::mem::transmute::<[usize; 2], &dyn StateAccess>(state_vtable) };
        state_ref.get(&smt_key)
    }));

    if vm.load(&code).is_err() {
        return vec![];
    }

    let _ = vm.execute();

    // Collect all storage keys that were accessed (from warm_storage_keys + storage overlay)
    let mut writes: Vec<[u8; 32]> = Vec::new();
    let mut reads: Vec<[u8; 32]> = Vec::new();

    // Keys written to (in vm.storage overlay)
    for key in vm.storage.keys() {
        writes.push(key.to_le_bytes());
    }

    // Keys read (in warm_storage_keys but not written)
    for key in &vm.warm_storage_keys {
        let key_bytes = key.to_le_bytes();
        if !writes.contains(&key_bytes) {
            reads.push(key_bytes);
        }
    }

    if writes.is_empty() && reads.is_empty() {
        return vec![];
    }

    vec![AccessEntry {
        address: tx.to,
        reads,
        writes,
    }]
}

/// Infer access lists for all txs that don't have one.
/// Uses parallel simulation via rayon for speed.
pub fn infer_access_lists_batch(
    txs: &mut [Transaction],
    state: &dyn StateAccess,
    block_ctx: &crate::pipeline::BlockContext,
) {
    // Only infer for txs without access lists
    for tx in txs.iter_mut() {
        if tx.access_list.is_empty() && !tx.data.is_empty() && tx.to != [0u8; 32] {
            tx.access_list = infer_access_list(tx, state, block_ctx);
        }
    }
}
