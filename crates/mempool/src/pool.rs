//! Encrypted mempool: stores and manages encrypted transactions.
//!
//! - FCFS ordering (no tips in Pyde, everyone pays same base fee)
//! - Eviction: oldest first when pool is full
//! - Deduplication: reject transactions with same hash
//! - Expiry: remove transactions past their deadline
//!
//! Mempool validation (structural, no state access):
//!   1. FALCON-512 signature valid
//!   2. Gas limit in [21_000, block_gas_limit]
//!   3. Ciphertext non-empty (well-formed)
//!   4. Access list non-empty
//!   5. Tx size within limit
//!   6. Deadline not expired
//!   7. No duplicate hash
//!
//! State-dependent checks (nonce, balance) deferred to Phase 7
//! when mempool connects to full node state.

use crate::encrypted::EncryptedTx;
use pyde_account::address::Address;
use pyde_crypto::falcon::{falcon_verify, FalconPublicKey, FalconSignature};
use std::collections::{HashMap, HashSet};

/// Default maximum mempool capacity (number of transactions).
/// Sized for ~100 blocks at sustained throughput (12,500 TPS × 0.4s × 100).
pub const DEFAULT_MAX_POOL_SIZE: usize = 500_000;

/// Mempool validation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MempoolError {
    /// Transaction is a duplicate (same hash already in pool).
    Duplicate,
    /// Transaction has expired (past deadline).
    Expired,
    /// Transaction exceeds size limit.
    Oversized,
    /// Transaction signature is invalid or missing.
    InvalidSignature,
    /// Gas limit too low (below minimum 21,000).
    GasTooLow,
    /// Gas limit exceeds block gas limit.
    GasTooHigh,
    /// Ciphertext is empty or malformed.
    MalformedEncryption,
    /// Access list is empty (required for parallel scheduling).
    MissingAccessList,
}

/// The encrypted mempool.
#[derive(Debug)]
pub struct Mempool {
    /// All transactions in arrival order.
    txs: Vec<EncryptedTx>,
    /// Set of tx hashes for deduplication.
    seen_hashes: HashSet<[u8; 32]>,
    /// Per-sender nonce tracking (sender → highest nonce seen).
    sender_nonces: HashMap<Address, u64>,
    /// Slot at which each tx first entered this pool. Used by the
    /// inclusion-audit path (task 026) to distinguish txs that have
    /// been in the mempool long enough that the proposer *should*
    /// have seen them, versus txs so new that missing them is not
    /// evidence of censorship.
    first_seen_slot: HashMap<[u8; 32], u64>,
    /// Maximum pool size.
    max_size: usize,
    /// Current block height (for expiry checks).
    current_block: u64,
    /// Block gas limit (for gas_limit upper bound check).
    block_gas_limit: u64,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            txs: Vec::new(),
            seen_hashes: HashSet::new(),
            sender_nonces: HashMap::new(),
            first_seen_slot: HashMap::new(),
            max_size: DEFAULT_MAX_POOL_SIZE,
            current_block: 0,
            block_gas_limit: pyde_tx::fee::GAS_CEILING as u64,
        }
    }

    pub fn with_capacity(max_size: usize) -> Self {
        Self {
            txs: Vec::with_capacity(max_size),
            seen_hashes: HashSet::with_capacity(max_size),
            sender_nonces: HashMap::new(),
            first_seen_slot: HashMap::with_capacity(max_size),
            max_size,
            current_block: 0,
            block_gas_limit: pyde_tx::fee::GAS_CEILING as u64,
        }
    }

    /// Update the current block height (for expiry checks).
    pub fn set_current_block(&mut self, block: u64) {
        self.current_block = block;
    }

    /// Update the block gas limit.
    pub fn set_block_gas_limit(&mut self, limit: u64) {
        self.block_gas_limit = limit;
    }

    /// Number of transactions in the pool.
    /// Iterate over all transactions in the mempool.
    pub fn iter_txs(&self) -> impl Iterator<Item = &EncryptedTx> {
        self.txs.iter()
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Add an encrypted transaction to the mempool.
    ///
    /// Structural validation (no state access required):
    /// 1. Signature valid (FALCON-512)
    /// 2. Gas limit in bounds [21K, block_gas_limit]
    /// 3. Ciphertext non-empty
    /// 4. Access list non-empty
    /// 5. Size within limit
    /// 6. Not expired
    /// 7. Not duplicate
    pub fn add(&mut self, tx: EncryptedTx) -> Result<(), MempoolError> {
        // 1. Signature check
        self.verify_signature(&tx)?;

        // 2. Gas limit bounds
        if tx.gas_limit < 21_000 {
            return Err(MempoolError::GasTooLow);
        }
        if tx.gas_limit > self.block_gas_limit {
            return Err(MempoolError::GasTooHigh);
        }

        // 3. Ciphertext well-formed
        if tx.ciphertext.encrypted_len() == 0 {
            return Err(MempoolError::MalformedEncryption);
        }

        // 4. Access list non-empty
        if tx.access_list.is_empty() {
            return Err(MempoolError::MissingAccessList);
        }

        // 5. Size limit
        if tx.is_oversized() {
            return Err(MempoolError::Oversized);
        }

        // 6. Expiry
        if tx.is_expired(self.current_block) {
            return Err(MempoolError::Expired);
        }

        // 7. Duplicate
        let hash = tx.hash();
        if self.seen_hashes.contains(&hash) {
            return Err(MempoolError::Duplicate);
        }

        // Evict if full: drop oldest transaction (FCFS — newest survive)
        if self.txs.len() >= self.max_size {
            self.evict_oldest();
        }

        // Track sender nonce
        let entry = self.sender_nonces.entry(tx.sender).or_insert(0);
        if tx.nonce > *entry {
            *entry = tx.nonce;
        }

        self.seen_hashes.insert(hash);
        self.first_seen_slot.insert(hash, self.current_block);
        self.txs.push(tx);

        Ok(())
    }

    /// Evict the oldest transaction (first in the list).
    fn evict_oldest(&mut self) {
        if self.txs.is_empty() {
            return;
        }
        let evicted = self.txs.remove(0);
        let h = evicted.hash();
        self.seen_hashes.remove(&h);
        self.first_seen_slot.remove(&h);
    }

    /// Verify the FALCON-512 signature on an encrypted transaction.
    ///
    /// Full cryptographic verification requires the sender's public key,
    /// which needs state access (deferred to Phase 7). For now, we check
    /// that the signature is structurally valid (non-empty, correct size
    /// range for FALCON-512 signatures).
    fn verify_signature(&self, tx: &EncryptedTx) -> Result<(), MempoolError> {
        // FALCON-512 signatures are typically 617-690 bytes (variable due to compression)
        if tx.signature.is_empty() {
            return Err(MempoolError::InvalidSignature);
        }
        // FALCON-512 compressed signatures range: ~600-700 bytes
        if tx.signature.len() < 500 || tx.signature.len() > 1000 {
            return Err(MempoolError::InvalidSignature);
        }
        Ok(())
    }

    /// Verify a signature with a known public key (called when state is available).
    pub fn verify_signature_with_key(tx: &EncryptedTx, public_key: &[u8]) -> bool {
        let pk = match FalconPublicKey::from_bytes(public_key) {
            Some(pk) => pk,
            None => return false,
        };
        let sig = match FalconSignature::from_bytes(&tx.signature) {
            Some(s) => s,
            None => return false,
        };
        falcon_verify(&pk, &tx.hash(), &sig)
    }

    /// Remove expired transactions.
    pub fn prune_expired(&mut self) {
        let current = self.current_block;
        let before = self.txs.len();
        self.txs.retain(|tx| !tx.is_expired(current));

        // Rebuild hash set + first-seen tracking if we pruned anything
        if self.txs.len() != before {
            self.seen_hashes.clear();
            let kept: HashSet<[u8; 32]> = self.txs.iter().map(|tx| tx.hash()).collect();
            self.first_seen_slot.retain(|h, _| kept.contains(h));
            self.seen_hashes = kept;
        }
    }

    /// Get transactions in arrival order (FCFS).
    /// No fee-based priority — Pyde has no tips, everyone pays the same base fee.
    pub fn in_arrival_order(&self) -> &[EncryptedTx] {
        &self.txs
    }

    /// Select transactions for a block in arrival order, respecting gas limit.
    /// The proposer VRF-shuffles the selected set after this.
    pub fn select_for_block(
        &self,
        block_gas_limit: u64,
        current_slot: u64,
    ) -> Vec<&EncryptedTx> {
        let mut selected = Vec::new();
        let mut gas_used = 0u64;

        for tx in &self.txs {
            if tx.is_expired(current_slot) {
                continue;
            }
            if gas_used.saturating_add(tx.gas_limit) > block_gas_limit {
                continue; // skip this tx, try next (might fit)
            }
            gas_used += tx.gas_limit;
            selected.push(tx);
        }

        selected
    }

    /// Remove transactions that were included in a block.
    pub fn remove_included(&mut self, hashes: &[[u8; 32]]) {
        let hash_set: HashSet<[u8; 32]> = hashes.iter().copied().collect();
        self.txs.retain(|tx| !hash_set.contains(&tx.hash()));

        for hash in hashes {
            self.seen_hashes.remove(hash);
            self.first_seen_slot.remove(hash);
        }
    }

    /// View of mempool entries paired with the slot they first arrived.
    /// Used by the inclusion-audit path (task 026).
    pub fn view_with_slots(&self) -> impl Iterator<Item = (&EncryptedTx, u64)> {
        self.txs.iter().filter_map(move |tx| {
            let h = tx.hash();
            self.first_seen_slot.get(&h).map(|s| (tx, *s))
        })
    }

    /// Check if a transaction hash is already in the pool.
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.seen_hashes.contains(hash)
    }
}

/// Validate that a block's transaction list has no duplicates.
/// Called by validators when receiving a proposed block.
pub fn check_no_duplicate_txs(txs: &[EncryptedTx]) -> Result<(), [u8; 32]> {
    let mut seen = HashSet::with_capacity(txs.len());
    for tx in txs {
        let hash = tx.hash();
        if !seen.insert(hash) {
            return Err(hash); // return the duplicate hash
        }
    }
    Ok(())
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypted::encrypt_transaction;
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::threshold;

    fn make_pk() -> threshold::ThresholdPublicKey {
        let (pk, _) = threshold::threshold_keygen(3, 2).unwrap();
        pk
    }

    use pyde_tx::types::AccessEntry;

    fn dummy_access_list() -> Vec<AccessEntry> {
        vec![AccessEntry {
            address: derive_eoa_address(b"contract"),
            reads: vec![[0x01; 32]],
            writes: vec![],
        }]
    }

    fn dummy_signature() -> Vec<u8> {
        vec![0xAA; 666] // FALCON-512 signature range (~600-700 bytes)
    }

    fn make_enc_tx(pk: &threshold::ThresholdPublicKey, gas: u64, nonce: u64) -> EncryptedTx {
        let sender = derive_eoa_address(&nonce.to_le_bytes());
        let to = derive_eoa_address(b"to");
        encrypt_transaction(sender, nonce, gas, dummy_access_list(), None, 1, dummy_signature(), &to, 0, b"", pk).unwrap()
    }

    fn make_enc_tx_with_deadline(
        pk: &threshold::ThresholdPublicKey,
        gas: u64,
        nonce: u64,
        deadline: u64,
    ) -> EncryptedTx {
        let sender = derive_eoa_address(&nonce.to_le_bytes());
        let to = derive_eoa_address(b"to");
        encrypt_transaction(sender, nonce, gas, dummy_access_list(), Some(deadline), 1, dummy_signature(), &to, 0, b"", pk).unwrap()
    }

    // ========== Task 0520: Encrypted tx stored in mempool ==========

    #[test]
    fn add_encrypted_tx() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        let tx = make_enc_tx(&pk, 50_000, 0);
        pool.add(tx).unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn reject_duplicate() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        let tx = make_enc_tx(&pk, 50_000, 0);
        pool.add(tx.clone()).unwrap();
        assert_eq!(pool.add(tx), Err(MempoolError::Duplicate));
    }

    #[test]
    fn reject_expired() {
        let pk = make_pk();
        let mut pool = Mempool::new();
        pool.set_current_block(200);

        let tx = make_enc_tx_with_deadline(&pk, 50_000, 0, 100); // expired
        assert_eq!(pool.add(tx), Err(MempoolError::Expired));
    }

    #[test]
    fn reject_gas_too_low() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        let tx = make_enc_tx(&pk, 20_999, 0); // below 21K
        assert_eq!(pool.add(tx), Err(MempoolError::GasTooLow));
    }

    #[test]
    fn reject_gas_too_high() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        let tx = make_enc_tx(&pk, 2_000_000_000, 0); // exceeds GAS_CEILING
        assert_eq!(pool.add(tx), Err(MempoolError::GasTooHigh));
    }

    #[test]
    fn reject_empty_signature() {
        let pk = make_pk();
        let mut pool = Mempool::new();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"to");

        let tx = encrypt_transaction(
            sender, 0, 50_000, dummy_access_list(), None, 1,
            vec![], // empty sig
            &to, 0, b"", &pk,
        )
        .unwrap();
        assert_eq!(pool.add(tx), Err(MempoolError::InvalidSignature));
    }

    #[test]
    fn reject_empty_access_list() {
        let pk = make_pk();
        let mut pool = Mempool::new();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"to");

        let tx = encrypt_transaction(
            sender, 0, 50_000, vec![], None, 1, // empty access list
            dummy_signature(), &to, 0, b"", &pk,
        )
        .unwrap();
        assert_eq!(pool.add(tx), Err(MempoolError::MissingAccessList));
    }

    // ========== Task 0521: Eviction when full ==========

    #[test]
    fn evict_oldest_when_full() {
        let pk = make_pk();
        let mut pool = Mempool::with_capacity(3);

        // Fill pool: nonce 0 (oldest), 1, 2
        pool.add(make_enc_tx(&pk, 30_000, 0)).unwrap();
        pool.add(make_enc_tx(&pk, 40_000, 1)).unwrap();
        pool.add(make_enc_tx(&pk, 50_000, 2)).unwrap();
        assert_eq!(pool.len(), 3);

        // Add new tx → evicts oldest (nonce 0, gas 30K)
        pool.add(make_enc_tx(&pk, 60_000, 3)).unwrap();
        assert_eq!(pool.len(), 3);

        // Oldest (30K) should be gone, newest (60K) should be present
        assert!(pool.txs.iter().any(|t| t.gas_limit == 60_000));
        assert!(!pool.txs.iter().any(|t| t.gas_limit == 30_000));
    }

    // ========== FCFS ordering ==========

    #[test]
    fn arrival_order_preserved() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        pool.add(make_enc_tx(&pk, 30_000, 0)).unwrap();
        pool.add(make_enc_tx(&pk, 60_000, 1)).unwrap();
        pool.add(make_enc_tx(&pk, 45_000, 2)).unwrap();

        let txs = pool.in_arrival_order();
        assert_eq!(txs[0].gas_limit, 30_000); // first in
        assert_eq!(txs[1].gas_limit, 60_000);
        assert_eq!(txs[2].gas_limit, 45_000); // last in
    }

    // ========== Block selection ==========

    #[test]
    fn select_for_block_respects_gas_limit() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        pool.add(make_enc_tx(&pk, 50_000, 0)).unwrap();
        pool.add(make_enc_tx(&pk, 60_000, 1)).unwrap();
        pool.add(make_enc_tx(&pk, 40_000, 2)).unwrap();

        // Block gas limit of 100K → picks 60K + 40K (or 60K + 50K... highest first)
        let selected = pool.select_for_block(100_000, 0);
        let total_gas: u64 = selected.iter().map(|t| t.gas_limit).sum();
        assert!(total_gas <= 100_000);
        assert!(selected.len() >= 1);
    }

    #[test]
    fn select_skips_expired() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        pool.add(make_enc_tx_with_deadline(&pk, 50_000, 0, 200)).unwrap();
        pool.add(make_enc_tx(&pk, 60_000, 1)).unwrap(); // no deadline

        // At slot 300, first tx is expired
        let selected = pool.select_for_block(1_000_000, 300);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].gas_limit, 60_000);
    }

    // ========== Prune expired ==========

    #[test]
    fn prune_removes_expired() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        pool.add(make_enc_tx_with_deadline(&pk, 50_000, 0, 100)).unwrap();
        pool.add(make_enc_tx(&pk, 60_000, 1)).unwrap();
        assert_eq!(pool.len(), 2);

        pool.set_current_block(200);
        pool.prune_expired();
        assert_eq!(pool.len(), 1);
    }

    // ========== Remove included ==========

    #[test]
    fn remove_included_txs() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        let tx1 = make_enc_tx(&pk, 50_000, 0);
        let tx2 = make_enc_tx(&pk, 60_000, 1);
        let hash1 = tx1.hash();

        pool.add(tx1).unwrap();
        pool.add(tx2).unwrap();
        assert_eq!(pool.len(), 2);

        pool.remove_included(&[hash1]);
        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&hash1));
    }

    // ========== Block-level duplicate check ==========

    #[test]
    fn no_duplicates_passes() {
        let pk = make_pk();
        let txs = vec![
            make_enc_tx(&pk, 50_000, 0),
            make_enc_tx(&pk, 60_000, 1),
        ];
        assert!(check_no_duplicate_txs(&txs).is_ok());
    }

    #[test]
    fn duplicate_tx_detected() {
        let pk = make_pk();
        let tx = make_enc_tx(&pk, 50_000, 0);
        let dup = tx.clone();
        let txs = vec![tx, dup];
        assert!(check_no_duplicate_txs(&txs).is_err());
    }
}
