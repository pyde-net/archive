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
use std::collections::{HashMap, HashSet, VecDeque};

/// Default maximum mempool capacity (number of transactions).
/// Sized for ~100 blocks at sustained throughput (12,500 TPS × 0.4s × 100).
pub const DEFAULT_MAX_POOL_SIZE: usize = 500_000;

/// Per-sender rate limit: max submissions per `RATE_WINDOW_MS` (task 027).
pub const DEFAULT_MAX_TX_PER_WINDOW_PER_SENDER: u32 = 10;

/// Per-sender concurrent cap: max simultaneously-held txs (task 027).
pub const DEFAULT_MAX_CONCURRENT_PER_SENDER: u32 = 100;

/// Rate-window size in milliseconds. The `submit_timestamps_ms` deque of each
/// `SenderQuota` drops entries older than this. 1000 ms pairs naturally with
/// the "10 tx/s" mainnet target.
pub const RATE_WINDOW_MS: u64 = 1000;

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
    /// Sender submitted more than `max_tx_per_window_per_sender` txs in the
    /// last `RATE_WINDOW_MS` — token bucket exhausted.
    RateLimitExceeded,
    /// Sender already has `max_concurrent_per_sender` txs simultaneously in
    /// the pool and must wait for some to clear.
    TooManyConcurrentFromSender,
    /// Sender's FALCON public key could not be resolved (not in state) or
    /// did not verify against the tx signature. Used by the verified-add
    /// path to kill relay-inflation attacks (task 028).
    UnknownOrUnverifiedSender,
}

/// Tracks a single sender's recent activity for rate + concurrency caps.
#[derive(Debug, Default)]
struct SenderQuota {
    /// Millisecond timestamps of submissions in the last `RATE_WINDOW_MS`.
    /// Prune-on-read: caller evicts entries older than `now - RATE_WINDOW_MS`
    /// before consulting the length.
    submit_timestamps_ms: VecDeque<u64>,
    /// Count of txs this sender currently holds in the pool. Incremented on
    /// successful add, decremented on evict / prune / remove_included.
    in_pool_count: u32,
}

/// Clock callback for the rate limiter. Default is wall-clock
/// `SystemTime::now()` in ms since UNIX epoch; tests inject a controllable
/// counter. Returning ms rather than a `Duration` keeps the arithmetic in
/// the same integer space as `RATE_WINDOW_MS` / `submit_timestamps_ms`.
pub type ClockMs = fn() -> u64;

fn wallclock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Sender → (hash → nonce) mapping for tracking a sender's in-pool txs.
/// Used to decrement the quota correctly on individual tx removal.
type SenderTxIndex = HashMap<Address, HashSet<[u8; 32]>>;

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
    /// Per-sender submission rate + concurrency state (task 027). Populated
    /// on add, decremented on remove/evict/prune.
    sender_quotas: HashMap<Address, SenderQuota>,
    /// Sender → set of tx hashes they currently own in the pool. Kept
    /// alongside `sender_quotas` so bulk remove paths can locate which
    /// senders to decrement without scanning the full pool each time.
    sender_tx_index: SenderTxIndex,
    /// Max txs from a single sender per `RATE_WINDOW_MS`.
    max_tx_per_window_per_sender: u32,
    /// Max txs a single sender may simultaneously hold in the pool.
    max_concurrent_per_sender: u32,
    /// Time source for rate-limit bookkeeping. Overridable for tests.
    clock_ms: ClockMs,
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
            sender_quotas: HashMap::new(),
            sender_tx_index: HashMap::new(),
            max_tx_per_window_per_sender: DEFAULT_MAX_TX_PER_WINDOW_PER_SENDER,
            max_concurrent_per_sender: DEFAULT_MAX_CONCURRENT_PER_SENDER,
            clock_ms: wallclock_ms,
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
            sender_quotas: HashMap::new(),
            sender_tx_index: HashMap::new(),
            max_tx_per_window_per_sender: DEFAULT_MAX_TX_PER_WINDOW_PER_SENDER,
            max_concurrent_per_sender: DEFAULT_MAX_CONCURRENT_PER_SENDER,
            clock_ms: wallclock_ms,
            max_size,
            current_block: 0,
            block_gas_limit: pyde_tx::fee::GAS_CEILING as u64,
        }
    }

    /// Install a custom time source. Tests use this to drive the rate-limit
    /// window deterministically; production always uses `wallclock_ms`.
    pub fn set_clock(&mut self, clock: ClockMs) {
        self.clock_ms = clock;
    }

    /// Override rate-limit caps. Production uses defaults; tests use lower
    /// values to keep runtime small.
    pub fn set_rate_limits(&mut self, per_window: u32, concurrent: u32) {
        self.max_tx_per_window_per_sender = per_window;
        self.max_concurrent_per_sender = concurrent;
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

    /// Add an encrypted transaction to the mempool with structural
    /// validation + per-sender rate limit (task 027).
    ///
    /// This path does NOT cryptographically verify the FALCON signature —
    /// it only checks the signature is structurally plausible (length).
    /// Mainnet consumers must use `add_with_pubkey` which also enforces
    /// task 028 (ciphertext-to-pubkey binding). `add` remains available
    /// for devnet and for tests that don't want to construct a full key.
    ///
    /// Checks, in order:
    /// 1. Per-sender rate limit (windowed)
    /// 2. Per-sender concurrent-in-pool cap
    /// 3. Signature structurally plausible
    /// 4. Gas limit in bounds
    /// 5. Ciphertext non-empty
    /// 6. Access list non-empty
    /// 7. Size within limit
    /// 8. Not expired
    /// 9. Not duplicate
    pub fn add(&mut self, tx: EncryptedTx) -> Result<(), MempoolError> {
        self.check_sender_rate(&tx.sender)?;
        self.verify_signature(&tx)?;
        self.check_core_validity(&tx)?;
        self.insert_tx(tx);
        Ok(())
    }

    /// Add an encrypted transaction with full FALCON signature verification
    /// against the sender's known public key (task 028).
    ///
    /// Bindings closed by this path:
    /// - Ciphertext-to-sender: the signature covers `tx.hash()` which
    ///   includes both the sender address and the ciphertext hash, so
    ///   relay-inflation (wrapping the same ciphertext under a different
    ///   sender) produces a sig that will not verify.
    /// - Sender-to-pubkey: verification runs against `sender_pubkey` looked
    ///   up from on-chain state by the caller, so a forged pubkey would
    ///   also fail.
    ///
    /// Applies the same structural + rate-limit checks as `add`.
    pub fn add_with_pubkey(
        &mut self,
        tx: EncryptedTx,
        sender_pubkey: &[u8],
    ) -> Result<(), MempoolError> {
        self.check_sender_rate(&tx.sender)?;
        if !Self::verify_signature_with_key(&tx, sender_pubkey) {
            return Err(MempoolError::UnknownOrUnverifiedSender);
        }
        self.check_core_validity(&tx)?;
        self.insert_tx(tx);
        Ok(())
    }

    fn check_sender_rate(&mut self, sender: &Address) -> Result<(), MempoolError> {
        let now = (self.clock_ms)();
        let window_cutoff = now.saturating_sub(RATE_WINDOW_MS);
        let quota = self.sender_quotas.entry(*sender).or_default();
        while let Some(&front) = quota.submit_timestamps_ms.front() {
            if front < window_cutoff {
                quota.submit_timestamps_ms.pop_front();
            } else {
                break;
            }
        }
        if quota.submit_timestamps_ms.len() as u32 >= self.max_tx_per_window_per_sender {
            return Err(MempoolError::RateLimitExceeded);
        }
        if quota.in_pool_count >= self.max_concurrent_per_sender {
            return Err(MempoolError::TooManyConcurrentFromSender);
        }
        Ok(())
    }

    fn check_core_validity(&self, tx: &EncryptedTx) -> Result<(), MempoolError> {
        if tx.gas_limit < 21_000 {
            return Err(MempoolError::GasTooLow);
        }
        if tx.gas_limit > self.block_gas_limit {
            return Err(MempoolError::GasTooHigh);
        }
        if tx.ciphertext.encrypted_len() == 0 {
            return Err(MempoolError::MalformedEncryption);
        }
        if tx.access_list.is_empty() {
            return Err(MempoolError::MissingAccessList);
        }
        if tx.is_oversized() {
            return Err(MempoolError::Oversized);
        }
        if tx.is_expired(self.current_block) {
            return Err(MempoolError::Expired);
        }
        let hash = tx.hash();
        if self.seen_hashes.contains(&hash) {
            return Err(MempoolError::Duplicate);
        }
        Ok(())
    }

    fn insert_tx(&mut self, tx: EncryptedTx) {
        // Evict if full: drop oldest transaction (FCFS — newest survive).
        // Eviction decrements the evicted sender's in_pool_count.
        if self.txs.len() >= self.max_size {
            self.evict_oldest();
        }

        let hash = tx.hash();
        let sender = tx.sender;

        let entry = self.sender_nonces.entry(sender).or_insert(0);
        if tx.nonce > *entry {
            *entry = tx.nonce;
        }

        // Rate-limit bookkeeping: record the submit timestamp + bump the
        // concurrent count. `check_sender_rate` already pruned stale
        // timestamps and has ensured we're under the caps.
        let now = (self.clock_ms)();
        let quota = self.sender_quotas.entry(sender).or_default();
        quota.submit_timestamps_ms.push_back(now);
        quota.in_pool_count += 1;

        self.sender_tx_index.entry(sender).or_default().insert(hash);
        self.seen_hashes.insert(hash);
        self.first_seen_slot.insert(hash, self.current_block);
        self.txs.push(tx);
    }

    /// Decrement a sender's concurrent count when a tx leaves the pool.
    fn release_sender_slot(&mut self, sender: &Address, hash: &[u8; 32]) {
        if let Some(set) = self.sender_tx_index.get_mut(sender) {
            set.remove(hash);
            if set.is_empty() {
                self.sender_tx_index.remove(sender);
            }
        }
        if let Some(q) = self.sender_quotas.get_mut(sender) {
            q.in_pool_count = q.in_pool_count.saturating_sub(1);
            // Keep submit_timestamps_ms — those represent rate history, not
            // occupancy. They'll age out on their own via window pruning.
            if q.in_pool_count == 0 && q.submit_timestamps_ms.is_empty() {
                self.sender_quotas.remove(sender);
            }
        }
    }

    /// Evict the oldest transaction (first in the list).
    fn evict_oldest(&mut self) {
        if self.txs.is_empty() {
            return;
        }
        let evicted = self.txs.remove(0);
        let h = evicted.hash();
        let sender = evicted.sender;
        self.seen_hashes.remove(&h);
        self.first_seen_slot.remove(&h);
        self.release_sender_slot(&sender, &h);
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
        let expired_senders: Vec<(Address, [u8; 32])> = self
            .txs
            .iter()
            .filter(|tx| tx.is_expired(current))
            .map(|tx| (tx.sender, tx.hash()))
            .collect();
        self.txs.retain(|tx| !tx.is_expired(current));

        if self.txs.len() != before {
            self.seen_hashes.clear();
            let kept: HashSet<[u8; 32]> = self.txs.iter().map(|tx| tx.hash()).collect();
            self.first_seen_slot.retain(|h, _| kept.contains(h));
            self.seen_hashes = kept;
            for (sender, hash) in &expired_senders {
                self.release_sender_slot(sender, hash);
            }
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
        let removed: Vec<(Address, [u8; 32])> = self
            .txs
            .iter()
            .filter(|tx| hash_set.contains(&tx.hash()))
            .map(|tx| (tx.sender, tx.hash()))
            .collect();
        self.txs.retain(|tx| !hash_set.contains(&tx.hash()));

        for hash in hashes {
            self.seen_hashes.remove(hash);
            self.first_seen_slot.remove(hash);
        }
        for (sender, hash) in &removed {
            self.release_sender_slot(sender, hash);
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

    // ========== Task 027: per-sender rate limit ==========

    /// Build an encrypted tx from a specific sender address (not derived from
    /// nonce, as `make_enc_tx` does). Used by rate-limit tests that need
    /// many txs from one sender.
    fn make_enc_tx_from(
        pk: &threshold::ThresholdPublicKey,
        sender: Address,
        nonce: u64,
    ) -> EncryptedTx {
        let to = derive_eoa_address(b"rate-to");
        encrypt_transaction(
            sender, nonce, 50_000,
            dummy_access_list(), None, 1,
            dummy_signature(), &to, 0, b"",
            pk,
        ).unwrap()
    }

    // Test clock backed by a thread-local counter. `set_test_clock_ms`
    // moves the needle; `test_clock_ms` is the function pointer fed to
    // `Mempool::set_clock`. (Regular comment, not a doc comment — `///`
    // doesn't attach to `thread_local!` macro items.)
    thread_local! {
        static TEST_CLOCK: std::cell::Cell<u64> = std::cell::Cell::new(0);
    }
    fn test_clock_ms() -> u64 {
        TEST_CLOCK.with(|c| c.get())
    }
    fn set_test_clock_ms(ms: u64) {
        TEST_CLOCK.with(|c| c.set(ms));
    }

    #[test]
    fn rate_limit_rejects_over_window_cap() {
        let pk = make_pk();
        let mut pool = Mempool::new();
        pool.set_clock(test_clock_ms);
        pool.set_rate_limits(3, 100);
        set_test_clock_ms(1_000);

        let sender = derive_eoa_address(b"rate-sender");
        for n in 0..3 {
            pool.add(make_enc_tx_from(&pk, sender, n)).unwrap();
        }

        // Fourth submission within the same window → rate-limited.
        let err = pool.add(make_enc_tx_from(&pk, sender, 3)).unwrap_err();
        assert_eq!(err, MempoolError::RateLimitExceeded);
        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn rate_limit_resets_after_window_rolls() {
        let pk = make_pk();
        let mut pool = Mempool::new();
        pool.set_clock(test_clock_ms);
        pool.set_rate_limits(2, 100);

        let sender = derive_eoa_address(b"rolling-sender");
        set_test_clock_ms(100);
        pool.add(make_enc_tx_from(&pk, sender, 0)).unwrap();
        pool.add(make_enc_tx_from(&pk, sender, 1)).unwrap();

        // Still within window — third is rejected.
        set_test_clock_ms(500);
        assert_eq!(
            pool.add(make_enc_tx_from(&pk, sender, 2)).unwrap_err(),
            MempoolError::RateLimitExceeded,
        );

        // Advance past window boundary (window = 1000ms, start was 100 ms).
        // At t=1101 all original timestamps are older than now - 1000 = 101.
        set_test_clock_ms(1_101);
        pool.add(make_enc_tx_from(&pk, sender, 3))
            .expect("window should have rolled");
    }

    #[test]
    fn concurrent_cap_blocks_new_submits_until_release() {
        let pk = make_pk();
        let mut pool = Mempool::new();
        pool.set_clock(test_clock_ms);
        // Per-window cap high so the concurrent cap is what we actually hit.
        pool.set_rate_limits(1000, 3);

        let sender = derive_eoa_address(b"concurrent-sender");
        set_test_clock_ms(1_000);
        let mut hashes = Vec::new();
        for n in 0..3 {
            let tx = make_enc_tx_from(&pk, sender, n);
            hashes.push(tx.hash());
            pool.add(tx).unwrap();
        }

        // 4th concurrently → blocked.
        assert_eq!(
            pool.add(make_enc_tx_from(&pk, sender, 3)).unwrap_err(),
            MempoolError::TooManyConcurrentFromSender,
        );

        // Include one of the in-pool txs → slot opens up.
        pool.remove_included(&[hashes[0]]);
        set_test_clock_ms(2_100); // roll window so the rate counter doesn't
                                   // independently block (submits are windowed
                                   // but in_pool count is not).
        pool.add(make_enc_tx_from(&pk, sender, 3))
            .expect("slot should have been released");
    }

    #[test]
    fn different_senders_have_independent_quotas() {
        let pk = make_pk();
        let mut pool = Mempool::new();
        pool.set_clock(test_clock_ms);
        pool.set_rate_limits(2, 100);
        set_test_clock_ms(1_000);

        let alice = derive_eoa_address(b"alice");
        let bob = derive_eoa_address(b"bob");

        pool.add(make_enc_tx_from(&pk, alice, 0)).unwrap();
        pool.add(make_enc_tx_from(&pk, alice, 1)).unwrap();

        // Alice is at her rate cap, but Bob still has headroom.
        assert_eq!(
            pool.add(make_enc_tx_from(&pk, alice, 2)).unwrap_err(),
            MempoolError::RateLimitExceeded,
        );
        pool.add(make_enc_tx_from(&pk, bob, 0))
            .expect("bob is unaffected by alice's cap");
        pool.add(make_enc_tx_from(&pk, bob, 1)).unwrap();
    }

    // ========== Task 028: FALCON-pubkey binding on submit ==========

    /// Build an encrypted tx signed by a real FALCON keypair so the
    /// signature verifies against the corresponding pubkey. Returns the
    /// tx + pubkey bytes so tests can pass them to `add_with_pubkey`.
    fn make_falcon_signed_tx(
        threshold_pk: &threshold::ThresholdPublicKey,
        gas: u64,
        nonce: u64,
    ) -> (EncryptedTx, Vec<u8>, pyde_crypto::falcon::FalconSecretKey) {
        let (falcon_pk, falcon_sk) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let sender = derive_eoa_address(falcon_pk.as_bytes());
        let to = derive_eoa_address(b"falcon-to");

        // First build the tx with a placeholder signature so we can compute
        // the hash, then re-sign and rebuild (hash ignores signature field).
        let template = encrypt_transaction(
            sender, nonce, gas, dummy_access_list(), None, 1,
            vec![0u8; 666], &to, 0, b"", threshold_pk,
        ).unwrap();
        let hash = template.hash();
        let sig = pyde_crypto::falcon::falcon_sign(&falcon_sk, &hash)
            .unwrap()
            .to_vec();

        let signed = EncryptedTx {
            sender,
            nonce,
            gas_limit: gas,
            access_list: template.access_list.clone(),
            deadline: template.deadline,
            chain_id: template.chain_id,
            signature: sig,
            ciphertext: template.ciphertext.clone(),
        };
        (signed, falcon_pk.as_bytes().to_vec(), falcon_sk)
    }

    #[test]
    fn add_with_pubkey_accepts_matching_signature() {
        let pk = make_pk();
        let (tx, sender_pk_bytes, _sk) = make_falcon_signed_tx(&pk, 50_000, 0);
        let mut pool = Mempool::new();
        pool.add_with_pubkey(tx, &sender_pk_bytes).unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn add_with_pubkey_rejects_wrong_pubkey() {
        // Relay-inflation attack simulation: attacker intercepts a validly
        // signed ciphertext and tries to insert it under their own pubkey.
        // The FALCON verify fails → rejected.
        let pk = make_pk();
        let (tx, _real_pk, _real_sk) = make_falcon_signed_tx(&pk, 50_000, 0);

        // Different keypair belonging to the attacker.
        let (attacker_pk, _) = pyde_crypto::falcon::falcon_keygen().unwrap();

        let mut pool = Mempool::new();
        let err = pool.add_with_pubkey(tx, attacker_pk.as_bytes()).unwrap_err();
        assert_eq!(err, MempoolError::UnknownOrUnverifiedSender);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn add_with_pubkey_rejects_tampered_ciphertext() {
        // If the ciphertext bytes are mutated after signing, `tx.hash()`
        // changes and the FALCON sig over the old hash no longer verifies.
        // Construct a valid tx, flip a byte in the ciphertext, retry.
        let pk = make_pk();
        let (mut tx, sender_pk_bytes, _sk) = make_falcon_signed_tx(&pk, 50_000, 0);

        // Swap in a fresh ciphertext (different plaintext → different bytes)
        // while keeping the old signature. The hash changes and sig verification
        // against the (now wrong) hash fails.
        let to = derive_eoa_address(b"tampered");
        tx.ciphertext = threshold::threshold_encrypt(&pk, b"tampered payload").unwrap();

        let mut pool = Mempool::new();
        assert_eq!(
            pool.add_with_pubkey(tx, &sender_pk_bytes).unwrap_err(),
            MempoolError::UnknownOrUnverifiedSender,
        );
        let _ = to;
    }

    #[test]
    fn add_with_pubkey_still_enforces_rate_limit() {
        // Verified path must compose with rate limiting — an attacker with a
        // valid key still can't spam.
        let pk = make_pk();
        let mut pool = Mempool::new();
        pool.set_clock(test_clock_ms);
        pool.set_rate_limits(1, 100);
        set_test_clock_ms(1_000);

        let (tx1, pk1, sk1) = make_falcon_signed_tx(&pk, 50_000, 0);
        pool.add_with_pubkey(tx1, &pk1).unwrap();

        // Second submission from the same sender; re-sign with the same sk.
        let (mut tx2, _, _) = make_falcon_signed_tx(&pk, 50_000, 1);
        // Align sender + resign with sk1 so the pubkey matches.
        tx2.sender = derive_eoa_address(&pk1);
        let new_hash = tx2.hash();
        tx2.signature = pyde_crypto::falcon::falcon_sign(&sk1, &new_hash).unwrap().to_vec();

        assert_eq!(
            pool.add_with_pubkey(tx2, &pk1).unwrap_err(),
            MempoolError::RateLimitExceeded,
        );
    }
}
