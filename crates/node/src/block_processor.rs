use crate::chain::ChainState;
use crate::state_manager::StateManager;
use pyde_consensus::block::{Block, BlockHeader};
use pyde_consensus::hotstuff::proposer_sign_message;
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
    /// Optionally triggers AOT background compilation for new contracts.
    /// Returns (tx_count, total_gas_used, receipts).
    pub fn process_full_block(
        chain: &mut ChainState,
        state: &mut StateManager,
        block: &Block,
    ) -> Result<(u64, u64, Vec<Receipt>), String> {
        Self::process_full_block_with_aot(chain, state, block, None)
    }

    /// Process a full block with optional AOT cache for background compilation.
    pub fn process_full_block_with_aot(
        chain: &mut ChainState,
        state: &mut StateManager,
        block: &Block,
        aot_cache: Option<&std::sync::Arc<crate::aot_cache::AotCache>>,
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
            chain_id: chain.chain_id,
            validator_address: block.header.proposer,
            dev_skip_signature: false,
        };

        // 3. Batch signature verification (parallel across all CPU cores).
        // Verify ALL signatures upfront before execution. This parallelizes the
        // expensive FALCON-512 verification across rayon's thread pool.
        // Devnet (chain_id=31337) skips this.
        let txs = &block.body.transactions;
        if chain.chain_id != 31337 && !txs.is_empty() {
            use rayon::prelude::*;
            let sig_results: Vec<bool> = txs.par_iter().map(|tx| {
                if tx.signature.is_empty() { return true; } // unsigned = skip (validated later)
                let sender_key = pyde_state::keys::balance_key(&tx.from);
                if let Some(acct_bytes) = state.get(&sender_key) {
                    if let Some(acct) = pyde_account::types::Account::from_bytes(&acct_bytes) {
                        if let pyde_account::types::AuthKeys::Single(ref pk) = acct.auth_keys {
                            return tx.verify_signature(pk);
                        }
                    }
                }
                true // no auth keys = system account, skip
            }).collect();
            // Mark invalid signatures (they'll be rejected during execution)
            let invalid_count = sig_results.iter().filter(|&&ok| !ok).count();
            if invalid_count > 0 {
                debug!(slot, invalid_sigs = invalid_count, "batch signature verification found invalid signatures");
            }
        }

        // 4. Execute transactions by group (Sealevel-style parallel execution).
        let groups = &block.body.execution_schedule.groups;

        let mut receipts = Vec::with_capacity(txs.len());
        let mut total_gas = 0u64;

        // Helper: trigger background AOT compilation for contract calls
        let trigger_aot = |tx: &pyde_tx::types::Transaction, state: &StateManager, cache: &Option<&std::sync::Arc<crate::aot_cache::AotCache>>| {
            if let Some(cache) = cache {
                // Only for contract calls (not deploys, not transfers)
                if tx.tx_type == pyde_tx::types::TransactionType::Standard
                    && tx.to != pyde_account::address::ZERO_ADDRESS
                    && !cache.is_known(&tx.to)
                {
                    // Load bytecode and trigger background compilation
                    let code_key = pyde_state::keys::code_key(&tx.to);
                    if let Some(bytecode) = state.get(&code_key) {
                        crate::aot_cache::compile_in_background(
                            cache.clone().clone(),
                            tx.to,
                            bytecode,
                        );
                    }
                }
            }
        };

        if groups.len() <= 1 {
            // Single group — execute sequentially but through StateOverlay
            // to avoid per-tx RocksDB I/O. All reads hit cache/fallback-to-RocksDB,
            // all writes buffer in HashMap, single batch commit at the end.
            use pyde_state::smt::StateOverlay;
            let mut overlay = StateOverlay::new(state as &dyn pyde_state::smt::StateAccess);
            for (i, tx) in txs.iter().enumerate() {
                trigger_aot(tx, state, &aot_cache);
                let aot_fn = aot_cache.as_ref()
                    .filter(|c| !c.is_blacklisted(&tx.to))
                    .and_then(|c| c.get(&tx.to))
                    .map(|compiled| compiled.as_fn());
                match pyde_tx::pipeline::execute_transaction_aot(tx, &mut overlay, &block_ctx, aot_fn) {
                    Ok(receipt) => {
                        total_gas += receipt.effective_gas;
                        debug!(slot, tx_index = i, gas = receipt.effective_gas, success = receipt.success, "tx executed");
                        receipts.push(receipt);
                    }
                    Err(e) => {
                        warn!(slot, tx_index = i, error = ?e, "tx execution failed");
                        let failed_receipt = pyde_tx::execution::Receipt {
                            tx_hash: tx.hash(), success: false,
                            gas_used: 0, gas_refund: 0, effective_gas: 0,
                            fee_paid: 0, fee_burned: 0, fee_validator: 0, fee_treasury: 0,
                            return_data: format!("{:?}", e).into_bytes(),
                            logs: vec![], state_root: sparse_merkle_tree::H256::zero(),
                        };
                        receipts.push(failed_receipt);
                    }
                }
            }
            // Deferred batch commit — buffer writes, Merkle computed lazily
            let writes = overlay.into_writes();
            if !writes.is_empty() {
                let _ = state.update_batch_deferred(writes);
            }
        } else {
            // Multiple groups — TRUE PARALLEL EXECUTION via rayon + StateOverlay.
            // Each group gets a StateOverlay (reads from shared SMT, writes to local HashMap).
            // Groups run on separate rayon threads. After all groups complete, all writes
            // are merged into the main SMT via update_batch().
            use rayon::prelude::*;
            use pyde_state::smt::StateOverlay;

            // Use StateManager as overlay base (reads from cache → SMT)
            let base: &dyn pyde_state::smt::StateAccess = state;

            // Execute each group in parallel
            let group_results: Vec<Vec<(usize, Receipt, Vec<(sparse_merkle_tree::H256, Vec<u8>)>)>> = groups
                .par_iter()
                .map(|group| {
                    let mut overlay = StateOverlay::new(base);
                    let mut results = Vec::new();

                    for &tx_idx in &group.tx_indices {
                        if tx_idx >= txs.len() { continue; }
                        let tx = &txs[tx_idx];
                        let aot_fn = aot_cache.as_ref()
                            .filter(|c| !c.is_blacklisted(&tx.to))
                            .and_then(|c| c.get(&tx.to))
                            .map(|compiled| compiled.as_fn());
                        match pyde_tx::pipeline::execute_transaction_aot(tx, &mut overlay, &block_ctx, aot_fn) {
                            Ok(receipt) => {
                                results.push((tx_idx, receipt, vec![]));
                            }
                            Err(e) => {
                                let failed = pyde_tx::execution::Receipt {
                                    tx_hash: tx.hash(), success: false,
                                    gas_used: 0, gas_refund: 0, effective_gas: 0,
                                    fee_paid: 0, fee_burned: 0, fee_validator: 0, fee_treasury: 0,
                                    return_data: format!("{:?}", e).into_bytes(),
                                    logs: vec![], state_root: sparse_merkle_tree::H256::zero(),
                                };
                                results.push((tx_idx, failed, vec![]));
                            }
                        }
                    }

                    // Collect overlay writes
                    let writes = overlay.into_writes();
                    // Attach writes to last result for merging
                    if let Some(last) = results.last_mut() {
                        last.2 = writes;
                    }
                    results
                })
                .collect();

            // Merge: collect all receipts (sorted by tx index) and all writes
            let mut all_results: Vec<(usize, Receipt)> = Vec::new();
            let mut all_writes: Vec<(sparse_merkle_tree::H256, Vec<u8>)> = Vec::new();

            for group_result in group_results {
                for (tx_idx, receipt, writes) in group_result {
                    total_gas += receipt.effective_gas;
                    all_results.push((tx_idx, receipt));
                    all_writes.extend(writes);
                }
            }

            // Sort receipts by original tx index for deterministic ordering
            all_results.sort_by_key(|(idx, _)| *idx);
            receipts = all_results.into_iter().map(|(_, r)| r).collect();

            // Batch-insert all writes from all groups into the main SMT
            if !all_writes.is_empty() {
                let write_count = all_writes.len();
                let _ = state.update_batch_deferred(all_writes);
                info!(
                    slot,
                    groups = groups.len(),
                    txs = txs.len(),
                    writes = write_count,
                    "parallel execution: {} groups on rayon threads",
                    groups.len()
                );
            }
        }

        // 4. Block reward: credit proposer with inflation reward
        let reward = pyde_tx::fee::block_reward(slot);
        if reward > 0 && block.header.proposer != [0u8; 32] {
            let proposer_key = pyde_state::keys::balance_key(&block.header.proposer);
            if let Some(acct_bytes) = state.get(&proposer_key) {
                if let Some(mut acct) = pyde_account::types::Account::from_bytes(&acct_bytes) {
                    acct.balance += reward;
                    let _ = state.insert(proposer_key, acct.to_bytes());
                }
            }
        }

        // 5. Merkle commit is handled by the CALLER (node event loop).
        // Block execution wrote to write_cache via update_batch_deferred.
        // The caller extracts pending writes and spawns the Merkle commit
        // on a background task, allowing the next block to start immediately.

        // 6. Adjust base fee for next block (EIP-1559)
        let gas_target = pyde_tx::fee::GAS_TARGET as u64;
        chain.base_fee = adjust_base_fee(chain.base_fee, total_gas, gas_target);

        // 7. Advance chain head
        chain.advance(block.header.clone());

        let elapsed_ms = start.elapsed().as_millis() as u64;
        let tx_count = block.body.transactions.len() as u64;

        // 8. Record metrics
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

    /// Extended validation for blocks received from the network.
    /// Checks: proposer signature, proposer in committee, VRF proof, QC quorum.
    pub fn validate_network_block(
        header: &BlockHeader,
        proposer_signature: &[u8],
        committee_keys: &[Vec<u8>],
        epoch_randomness: &[u8; 32],
    ) -> Result<(), String> {
        let slot = header.slot;

        // Skip validation for genesis block
        if slot == 0 {
            return Ok(());
        }

        // 1. Proposer must be a committee member
        let proposer_idx = committee_keys.iter().position(|k| {
            let addr = pyde_account::address::derive_eoa_address(k);
            addr == header.proposer
        });
        if proposer_idx.is_none() {
            return Err(format!(
                "proposer {} is not in the committee",
                hex::encode(header.proposer)
            ));
        }
        let proposer_idx = proposer_idx.unwrap();

        // 2. Verify proposer signature
        if proposer_signature.is_empty() {
            return Err("block missing proposer signature".into());
        }
        let pk = pyde_crypto::falcon::FalconPublicKey::from_bytes(&committee_keys[proposer_idx])
            .ok_or("invalid committee public key")?;
        let block_hash = header.hash();
        let sig = pyde_crypto::falcon::FalconSignature::from_bytes(proposer_signature)
            .ok_or("invalid proposer signature format")?;
        // Proposers sign `slot || block_hash` (canonical layout shared
        // with votes) to prevent cross-slot signature replay.
        let sign_msg = proposer_sign_message(slot, &block_hash);
        if !pyde_crypto::falcon::falcon_verify(&pk, &sign_msg, &sig) {
            return Err("proposer signature verification failed".into());
        }

        // 3. Verify VRF proof (encoded as [output:32 || proof:N])
        if header.vrf_proof.len() >= 33 {
            let vrf_output_bytes = &header.vrf_proof[..32];
            let vrf_proof_bytes = &header.vrf_proof[32..];

            let pk = pyde_crypto::falcon::FalconPublicKey::from_bytes(&committee_keys[proposer_idx])
                .ok_or("invalid committee public key for VRF verification")?;
            let vrf_output = pyde_crypto::vrf::VrfOutput::from_hash_bytes(vrf_output_bytes);
            let vrf_proof = pyde_crypto::vrf::VrfProof::from_bytes(vrf_proof_bytes);

            let mut vrf_input = Vec::with_capacity(40);
            vrf_input.extend_from_slice(epoch_randomness);
            vrf_input.extend_from_slice(&slot.to_le_bytes());

            if !pyde_crypto::vrf::vrf_verify(&pk, &vrf_input, &vrf_output, &vrf_proof) {
                return Err("invalid VRF proof in block header".into());
            }
        }

        // 4. Previous QC should have quorum (skip for early blocks with empty QC)
        let committee_size = committee_keys.len();
        if header.qc_previous.slot > 0 && !header.qc_previous.has_quorum_for(committee_size) {
            return Err(format!(
                "previous QC at slot {} has insufficient votes ({}/{})",
                header.qc_previous.slot,
                header.qc_previous.vote_count(),
                pyde_consensus::block::quorum_for_committee(committee_size),
            ));
        }

        Ok(())
    }

    /// Validate transactions within a block body before execution.
    /// Checks: no duplicate tx hashes, total gas within ceiling.
    /// Signature verification only for synced blocks (gossip txs are verified at mempool entry).
    pub fn validate_block_body(
        block: &Block,
        state: &StateManager,
        chain_id: u64,
    ) -> Result<(), String> {
        Self::validate_block_body_inner(block, state, chain_id, false)
    }

    /// Validate block body for synced blocks (includes signature verification).
    pub fn validate_synced_block_body(
        block: &Block,
        state: &StateManager,
        chain_id: u64,
    ) -> Result<(), String> {
        Self::validate_block_body_inner(block, state, chain_id, true)
    }

    fn validate_block_body_inner(
        block: &Block,
        state: &StateManager,
        chain_id: u64,
        verify_signatures: bool,
    ) -> Result<(), String> {
        // 0. Verify tx_root commits to the full transaction ordering —
        // plaintext AND encrypted. Without this, a proposer could reorder
        // encrypted_txs after the QC without changing the signed block
        // hash, defeating MEV protection.
        let encrypted_tx_hashes: Vec<[u8; 32]> = block
            .body
            .encrypted_txs
            .iter()
            .filter_map(|b| pyde_mempool::encrypted::EncryptedTx::from_bytes(b))
            .map(|etx| etx.hash())
            .collect();
        if !pyde_consensus::block::verify_tx_root(
            &block.header.tx_root,
            &block.body.transactions,
            &encrypted_tx_hashes,
        ) {
            return Err(format!(
                "tx_root mismatch: header {} — block body has been \
                 tampered with or the proposer reordered encrypted txs after QC",
                hex::encode(block.header.tx_root)
            ));
        }

        let txs = &block.body.transactions;
        if txs.is_empty() && block.body.encrypted_txs.is_empty() {
            return Ok(());
        }

        // 1. No duplicate tx hashes
        let mut seen_hashes = std::collections::HashSet::with_capacity(txs.len());
        for tx in txs {
            let hash = tx.hash();
            if !seen_hashes.insert(hash) {
                return Err(format!(
                    "duplicate transaction {} in block",
                    hex::encode(hash)
                ));
            }
        }

        // 2. Total gas within block gas ceiling
        let total_gas: u64 = txs.iter().map(|tx| tx.gas_limit).sum();
        if total_gas > pyde_tx::fee::GAS_CEILING {
            return Err(format!(
                "block gas {} exceeds ceiling {}",
                total_gas, pyde_tx::fee::GAS_CEILING
            ));
        }

        // 3. Verify tx signatures for synced blocks (gossip txs already verified at mempool entry)
        if verify_signatures && chain_id != 31337 {
            for (i, tx) in txs.iter().enumerate() {
                if tx.signature.is_empty() {
                    return Err(format!("tx {} has empty signature", i));
                }
                // Load sender's public key from state
                let balance_key = pyde_state::keys::balance_key(&tx.from);
                if let Some(acct_bytes) = state.get(&balance_key) {
                    if let Some(acct) = pyde_account::types::Account::from_bytes(&acct_bytes) {
                        match &acct.auth_keys {
                            pyde_account::types::AuthKeys::Single(pk) => {
                                if !tx.verify_signature(pk) {
                                    return Err(format!(
                                        "tx {} has invalid signature",
                                        i
                                    ));
                                }
                            }
                            pyde_account::types::AuthKeys::None => {
                                // System account — no sig check
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Outcome of `try_decrypt_and_execute`.
///
/// `TxRootMismatch` is the MEV-protection path: the decryptor's encrypted_txs
/// ordering does not match what the block's tx_root committed to, so applying
/// its decrypted output would violate the commitment validators voted on.
#[derive(Debug)]
pub enum DecryptOutcome {
    Executed {
        tx_count: usize,
        receipts: Vec<Receipt>,
    },
    HeaderMissing,
    TxRootMismatch,
    DecryptFailed(String),
}

/// Verify a decryptor's encrypted_txs ordering matches a block's committed tx_root.
///
/// This is the decryption-time MEV invariant. The block's tx_root (signed by the
/// proposer, voted on by 2/3+, cemented in the QC) binds a specific ordering of
/// encrypted_txs. Anything that feeds a decryptor MUST produce the same order,
/// or the committee would collectively decrypt state that no one voted for.
pub fn verify_decryptor_against_committed_root(
    committed_tx_root: &[u8; 32],
    block_plaintext_txs: &[Transaction],
    decryptor_encrypted_txs: &[pyde_mempool::encrypted::EncryptedTx],
) -> bool {
    let enc_hashes: Vec<[u8; 32]> = decryptor_encrypted_txs
        .iter()
        .map(|e| e.hash())
        .collect();
    pyde_consensus::block::verify_tx_root(
        committed_tx_root,
        block_plaintext_txs,
        &enc_hashes,
    )
}

/// Full decrypt + execute flow with MEV tx_root check.
///
/// 1. Load block header + plaintext body from `block_store`.
/// 2. Verify the decryptor's encrypted_txs match the committed tx_root.
///    If not → `TxRootMismatch`, no state change.
/// 3. `decrypt_all` on the decryptor.
/// 4. Execute each decrypted tx against state. Failures don't abort the block
///    (they produce failed receipts like any other tx execution path).
/// 5. Refresh state root.
///
/// Returns outcome for caller observability (logging + receipt storage).
pub fn try_decrypt_and_execute(
    block_store: &crate::block_store::BlockStore,
    slot: u64,
    decryptor: &mut pyde_mempool::decryption::BlockDecryptor,
    state: &mut StateManager,
    block_gas_limit: u64,
    base_fee: u128,
    chain_id: u64,
    proposer_addr: [u8; 32],
) -> DecryptOutcome {
    let header = match block_store.get_header(slot) {
        Some(h) => h,
        None => return DecryptOutcome::HeaderMissing,
    };
    let plaintext_txs = block_store
        .get_block_raw(slot)
        .and_then(|raw| crate::wire::decode_block(&raw).ok())
        .map(|b| b.body.transactions)
        .unwrap_or_default();

    if !verify_decryptor_against_committed_root(
        &header.tx_root,
        &plaintext_txs,
        &decryptor.encrypted_txs,
    ) {
        return DecryptOutcome::TxRootMismatch;
    }

    // Re-verify each EncryptedTx's FALCON signature against the sender's
    // on-chain public key BEFORE decrypting. The sig lives in the
    // `EncryptedTx::hash()` domain (binds sender + ciphertext_hash +
    // nonce + gas + chain). Verifying here closes the malicious-proposer
    // attack: a byzantine proposer could otherwise include an EncryptedTx
    // with forged sender (bypassing mempool admission entirely), have it
    // decrypted by the honest committee, and executed. Without this check
    // a single byzantine proposer steals funds from any EOA.
    //
    // Txs whose sender has no `AuthKeys::Single` registration are rejected
    // here: for mainnet, the only legitimate way an encrypted tx reaches
    // a block is submit via RPC, which requires the sender to have a
    // registered auth key (task 028). Accounts without auth_keys (system
    // accounts, pre-auth EOAs) can't originate encrypted txs.
    //
    // A tx that fails verification is dropped from the execution list
    // rather than aborting the whole block — matches the receipt-per-tx
    // failure model used elsewhere.
    let mut verified_enc_indices: Vec<usize> = Vec::with_capacity(decryptor.encrypted_txs.len());
    for (i, etx) in decryptor.encrypted_txs.iter().enumerate() {
        let sender_key = pyde_state::keys::balance_key(&etx.sender);
        let sender_pk: Option<Vec<u8>> = state.get(&sender_key)
            .and_then(|bytes| pyde_account::types::Account::from_bytes(&bytes))
            .and_then(|acct| match acct.auth_keys {
                pyde_account::types::AuthKeys::Single(pk) => Some(pk),
                _ => None,
            });
        match sender_pk {
            Some(pk) => {
                if pyde_mempool::pool::Mempool::verify_signature_with_key(etx, &pk) {
                    verified_enc_indices.push(i);
                } else {
                    warn!(
                        slot,
                        sender = hex::encode(etx.sender),
                        "dropping encrypted tx with invalid FALCON signature — block may have been built by a byzantine proposer"
                    );
                }
            }
            None => {
                warn!(
                    slot,
                    sender = hex::encode(etx.sender),
                    "dropping encrypted tx from sender with no registered auth key"
                );
            }
        }
    }

    let decrypted_txs = match decryptor.decrypt_all() {
        Ok(t) => t,
        Err(e) => return DecryptOutcome::DecryptFailed(e),
    };

    // After explicit verification above, the Transaction's signature
    // field (which is over `EncryptedTx::hash()`, not `Transaction::hash()`)
    // would fail a naive re-check. `dev_skip_signature: true` is safe
    // here because each tx we execute below was already FALCON-verified
    // in the correct hash domain.
    let block_ctx = BlockContext {
        height: slot,
        timestamp: header.timestamp,
        base_fee,
        block_gas_limit,
        chain_id,
        validator_address: proposer_addr,
        dev_skip_signature: true,
    };
    let mut receipts = Vec::with_capacity(decrypted_txs.len());
    for (i, dtx) in decrypted_txs.iter().enumerate() {
        if !verified_enc_indices.contains(&i) {
            continue;
        }
        match execute_transaction(dtx, &mut *state.smt_mut(), &block_ctx) {
            Ok(r) => receipts.push(r),
            Err(e) => warn!(slot, error = ?e, "decrypted tx execution failed"),
        }
    }
    state.refresh_root();

    DecryptOutcome::Executed {
        tx_count: verified_enc_indices.len(),
        receipts,
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
        let mut chain = ChainState::genesis([0u8; 32], 31337);
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();

        let header = dummy_header(1);
        let (tx_count, gas_used) =
            BlockProcessor::process_block(&mut chain, &mut state, header, &[]).unwrap();

        assert_eq!(tx_count, 0);
        assert_eq!(gas_used, 0);
        assert_eq!(chain.head_slot, 1);
    }

    #[test]
    fn reject_old_slot() {
        let mut chain = ChainState::genesis([0u8; 32], 31337);
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();

        chain.advance(dummy_header(5));

        let result = BlockProcessor::process_block(&mut chain, &mut state, dummy_header(3), &[]);
        assert!(result.is_err());
    }

    #[test]
    fn sequential_blocks() {
        let mut chain = ChainState::genesis([0u8; 32], 31337);
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();

        for slot in 1..=5 {
            BlockProcessor::process_block(&mut chain, &mut state, dummy_header(slot), &[]).unwrap();
        }

        assert_eq!(chain.head_slot, 5);
    }

    #[test]
    fn process_block_with_transfer() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();

        // Initialize genesis with funded accounts
        let (config, _accounts) = devnet_genesis();
        let _genesis = initialize_genesis(&mut state, &config).unwrap();

        let mut chain = ChainState::genesis(state.root(), 31337);

        // Account 0x0101...01 has 1M PYDE from genesis
        let sender = [0x01; 32];
        let recipient = [0x02; 32];

        // Transfer 100 quanta
        let tx = make_transfer_tx(sender, recipient, 100, 0);

        let block = Block {
            header: dummy_header(1),
            body: BlockBody {
                transactions: vec![tx],
                encrypted_txs: vec![],
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
        assert_eq!(receipts.len(), 1); // failed tx now produces a failed receipt
        assert!(!receipts[0].success);  // receipt marks failure
        assert_eq!(chain.head_slot, 1);
    }

    // ========== tx_root commits to full transaction order ==========

    fn build_dummy_encrypted_tx(seed: u8) -> Vec<u8> {
        // Real EncryptedTx via the public API. Private threshold-
        // ciphertext fields can't be synthesized directly. We use a
        // throwaway 2-of-3 committee key — hash stability + wire
        // roundtrip is what the tests need, not decryption.
        let (committee_pk, _shares) = pyde_crypto::threshold::threshold_keygen(3, 2).unwrap();
        let etx = pyde_mempool::encrypted::encrypt_transaction(
            [seed; 32], // sender
            seed as u64,
            21_000,
            vec![],
            None,
            1,
            vec![0xAA; 666],
            &[seed; 32],        // to
            (seed as u128) * 100,
            &[seed, seed, seed], // calldata
            &committee_pk,
        )
        .unwrap();
        etx.to_bytes()
    }

    #[test]
    fn validate_body_rejects_reordered_encrypted_txs() {
        // The MEV-protection invariant: a proposer who has committed to
        // ordering via the QC cannot swap encrypted_tx positions afterwards.
        // Here we simulate a tampered block — header tx_root was computed
        // over [enc_a, enc_b], but the body ships [enc_b, enc_a].
        let tmp = tempfile::tempdir().unwrap();
        let state = StateManager::open(tmp.path(), 1024).unwrap();

        let enc_a = build_dummy_encrypted_tx(0xAA);
        let enc_b = build_dummy_encrypted_tx(0xBB);
        let hash_a = pyde_mempool::encrypted::EncryptedTx::from_bytes(&enc_a).unwrap().hash();
        let hash_b = pyde_mempool::encrypted::EncryptedTx::from_bytes(&enc_b).unwrap().hash();

        // Honest tx_root covers [A, B].
        let honest_root = pyde_consensus::block::compute_tx_root(&[], &[hash_a, hash_b]);

        let mut header = dummy_header(1);
        header.tx_root = honest_root;

        // Tampered body ships [B, A] while claiming the [A, B] root.
        let tampered = Block {
            header,
            body: BlockBody {
                transactions: vec![],
                encrypted_txs: vec![enc_b, enc_a],
                execution_schedule: ExecutionSchedule { groups: vec![], total_txs: 0 },
            },
            proposer_signature: vec![],
        };

        let err = BlockProcessor::validate_block_body(&tampered, &state, 1).unwrap_err();
        assert!(
            err.contains("tx_root mismatch"),
            "expected tx_root mismatch, got: {}",
            err
        );
    }

    #[test]
    fn validate_body_rejects_added_encrypted_tx() {
        // Proposer tries to slip an extra encrypted tx into the body
        // without updating tx_root — rejected.
        let tmp = tempfile::tempdir().unwrap();
        let state = StateManager::open(tmp.path(), 1024).unwrap();

        let honest_root = pyde_consensus::block::compute_tx_root(&[], &[]);

        let mut header = dummy_header(1);
        header.tx_root = honest_root; // empty — no txs promised

        let tampered = Block {
            header,
            body: BlockBody {
                transactions: vec![],
                encrypted_txs: vec![build_dummy_encrypted_tx(0xCC)], // surprise!
                execution_schedule: ExecutionSchedule { groups: vec![], total_txs: 0 },
            },
            proposer_signature: vec![],
        };

        assert!(BlockProcessor::validate_block_body(&tampered, &state, 1).is_err());
    }

    #[test]
    fn validate_body_accepts_honest_block() {
        // Sanity: a well-formed block with matching tx_root passes.
        let tmp = tempfile::tempdir().unwrap();
        let state = StateManager::open(tmp.path(), 1024).unwrap();

        let enc = build_dummy_encrypted_tx(0xAA);
        let hash = pyde_mempool::encrypted::EncryptedTx::from_bytes(&enc).unwrap().hash();
        let tx_root = pyde_consensus::block::compute_tx_root(&[], &[hash]);

        let mut header = dummy_header(1);
        header.tx_root = tx_root;

        let block = Block {
            header,
            body: BlockBody {
                transactions: vec![],
                encrypted_txs: vec![enc],
                execution_schedule: ExecutionSchedule { groups: vec![], total_txs: 0 },
            },
            proposer_signature: vec![],
        };

        BlockProcessor::validate_block_body(&block, &state, 1).unwrap();
    }

    // ========== Decrypt-time tx_root check (task 025 integration) ==========

    fn build_two_encrypted_txs_with_keys() -> (
        pyde_crypto::threshold::ThresholdPublicKey,
        Vec<pyde_crypto::threshold::KeyShare>,
        pyde_mempool::encrypted::EncryptedTx,
        pyde_mempool::encrypted::EncryptedTx,
    ) {
        let (pk, shares) = pyde_crypto::threshold::threshold_keygen(3, 2).unwrap();
        let enc_a = pyde_mempool::encrypted::encrypt_transaction(
            [0xAA; 32], 0, 21_000, vec![], None, 1,
            vec![0xAA; 666],
            &[0x11; 32], 100,
            &[0xAA, 0xAA],
            &pk,
        ).unwrap();
        let enc_b = pyde_mempool::encrypted::encrypt_transaction(
            [0xBB; 32], 1, 21_000, vec![], None, 1,
            vec![0xBB; 666],
            &[0x22; 32], 200,
            &[0xBB, 0xBB],
            &pk,
        ).unwrap();
        (pk, shares, enc_a, enc_b)
    }

    fn store_block_with_encrypted_order(
        bs: &crate::block_store::BlockStore,
        slot: u64,
        enc_order: &[&pyde_mempool::encrypted::EncryptedTx],
    ) -> [u8; 32] {
        let hashes: Vec<[u8; 32]> = enc_order.iter().map(|e| e.hash()).collect();
        let committed_root = pyde_consensus::block::compute_tx_root(&[], &hashes);
        let mut header = dummy_header(slot);
        header.tx_root = committed_root;
        let body = BlockBody {
            transactions: vec![],
            encrypted_txs: enc_order.iter().map(|e| e.to_bytes()).collect(),
            execution_schedule: ExecutionSchedule { groups: vec![], total_txs: 0 },
        };
        let block = Block {
            header: header.clone(),
            body,
            proposer_signature: vec![],
        };
        let raw = crate::wire::encode_block(&block);
        bs.put_block(&header, &raw).unwrap();
        committed_root
    }

    #[test]
    fn try_decrypt_and_execute_aborts_on_tampered_decryptor() {
        // This is the REGRESSION TEST for the decrypt-time MEV check.
        // If someone deletes the verify_decryptor_against_committed_root call
        // inside try_decrypt_and_execute, this test must fail.
        //
        // Setup: an honest block commits to encrypted_txs [A, B]. A tampered
        // decryptor holds them as [B, A] — as would happen if an attacker
        // swapped ciphertexts between block acceptance and decrypt time.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let bs = crate::block_store::BlockStore::open(tmp.path()).unwrap();

        let (_pk, _shares, enc_a, enc_b) = build_two_encrypted_txs_with_keys();
        store_block_with_encrypted_order(&bs, 1, &[&enc_a, &enc_b]);

        // Tampered decryptor: [B, A] — opposite of what tx_root committed to.
        let mut tampered = pyde_mempool::decryption::BlockDecryptor::new(
            vec![enc_b, enc_a],
            2,
        ).unwrap();

        let outcome = try_decrypt_and_execute(
            &bs, 1, &mut tampered, &mut state,
            /* gas_limit */ 400_000_000,
            /* base_fee  */ 1_000_000_000,
            /* chain_id  */ 1,
            /* proposer  */ [0u8; 32],
        );

        assert!(
            matches!(outcome, DecryptOutcome::TxRootMismatch),
            "tampered decryptor must be rejected; got {:?}",
            outcome
        );
    }

    #[test]
    fn try_decrypt_and_execute_runs_on_honest_decryptor() {
        // Positive case: honest decryptor + honest block → Executed outcome.
        // Note `tx_count` reports VERIFIED txs (passed FALCON check against
        // on-chain auth key). The test's helper builds ciphertexts with
        // dummy-byte signatures and unregistered senders, so verified
        // count is 0 — but the Executed variant confirms the end-to-end
        // pipeline ran without tx_root / header / decrypt failures.
        // End-to-end with real keys is covered by the e2e suite in
        // validator.rs tests.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let bs = crate::block_store::BlockStore::open(tmp.path()).unwrap();

        let (_pk, shares, enc_a, enc_b) = build_two_encrypted_txs_with_keys();
        store_block_with_encrypted_order(&bs, 1, &[&enc_a, &enc_b]);

        let mut honest = pyde_mempool::decryption::BlockDecryptor::new(
            vec![enc_a, enc_b],
            2,
        ).unwrap();
        for ks in &shares[..2] {
            honest.add_member_shares(ks);
        }
        assert!(honest.all_ready(), "should have threshold shares");

        let outcome = try_decrypt_and_execute(
            &bs, 1, &mut honest, &mut state,
            400_000_000, 1_000_000_000, 1, [0u8; 32],
        );

        assert!(
            matches!(outcome, DecryptOutcome::Executed { .. }),
            "honest decryptor must reach the Executed outcome; got {:?}",
            outcome
        );
    }

    #[test]
    fn try_decrypt_and_execute_returns_header_missing_when_unknown() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = StateManager::open(tmp.path(), 1024).unwrap();
        let bs = crate::block_store::BlockStore::open(tmp.path()).unwrap();

        let (_pk, _shares, enc_a, enc_b) = build_two_encrypted_txs_with_keys();
        let mut decryptor = pyde_mempool::decryption::BlockDecryptor::new(
            vec![enc_a, enc_b],
            2,
        ).unwrap();

        let outcome = try_decrypt_and_execute(
            &bs, 42, &mut decryptor, &mut state,
            400_000_000, 1_000_000_000, 1, [0u8; 32],
        );

        assert!(matches!(outcome, DecryptOutcome::HeaderMissing));
    }
}
