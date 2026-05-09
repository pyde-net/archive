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
use pyde_account::address::{derive_eoa_address, Address};
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

/// Maximum encrypted txs the proposer will include in a single block.
///
/// Two separate constraints set this ceiling:
///
/// 1. **Wire format.** The committee broadcasts one
///    `DecryptionShareMsg` per validator per slot, carrying one
///    decryption share per encrypted tx in the block. The
///    consensus-topic message budget is 64 KB and the wire decoder
///    bounds the share count via `dec.u16_count(...)` — anything
///    above the bound is silently rejected at deserialization, so
///    the threshold never reaches and the encrypted_txs never
///    decrypt. Setting the proposer-side cap below the decoder's
///    bound is what keeps the broadcast self-consistent.
///
/// 2. **Per-validator decrypt + apply CPU.** Threshold-decrypt +
///    apply for an encrypted tx costs ~3-5 ms per validator (Lagrange
///    combine, Kyber decap, FALCON re-verify, state apply). Slot
///    budget is 400 ms; leaving room for vote+QC means decrypt+apply
///    should fit in ~200 ms ⇒ ~50 txs/block on laptop, ~200 on
///    dedicated cores. Below this ceiling the chain commits steady;
///    above it `prune_committed_txs` falls behind, the proposer
///    re-includes the same set every slot, and the chain wedges.
///
/// 100/block hits the safe sweet-spot: comfortably under the wire
/// decoder's 128-share bound (so encoded share messages round-trip
/// cleanly), and high enough to not throttle laptop loadgen (which
/// organically tops out at ~50/block under the audit-027 per-sender
/// caps), while preventing the runaway pile-ups (5 000+-per-slot
/// re-circle observed at 5 K-sender loadgen). Operator-config knob
/// for cluster-class hardware lands in a follow-up.
pub const MAX_ENCRYPTED_TXS_PER_BLOCK: usize = 100;

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
    ///
    /// TPL-509: switched from `Vec<EncryptedTx>` to `VecDeque<…>`
    /// so `evict_oldest` runs in O(1) (`pop_front`) instead of
    /// O(n) (`Vec::remove(0)` shifts every remaining element).
    /// Under sustained near-cap load — N adds while at the size
    /// limit — pre-fix eviction was O(n) per add → O(n²) total
    /// for the burst, which dominated the mempool's hot path
    /// during stress testing. `VecDeque` keeps the same arrival-
    /// order semantics.
    txs: VecDeque<EncryptedTx>,
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
            txs: VecDeque::new(),
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
            block_gas_limit: pyde_tx::fee::GAS_CEILING,
        }
    }

    pub fn with_capacity(max_size: usize) -> Self {
        Self {
            txs: VecDeque::with_capacity(max_size),
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
            block_gas_limit: pyde_tx::fee::GAS_CEILING,
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

    /// Add an encrypted transaction with structural validation +
    /// per-sender rate limit only — does NOT cryptographically verify
    /// the FALCON signature against the sender's on-chain pubkey.
    ///
    /// TPL-406: previously named `add`, which made it the obvious
    /// default verb for any caller writing `mempool.add_unverified_for_devnet(tx)`. The
    /// shorter name was a footgun — production code paths that
    /// should bind sender → pubkey via `add_with_pubkey` could
    /// silently accept unverified txs by reaching for the wrong
    /// method. The renamed `add_unverified_for_devnet` forces every
    /// caller to consciously acknowledge the bypass; mainnet
    /// gating still lives in
    /// `crate::rpc::encrypted_tx_ingest_policy`, which maps
    /// non-devnet chains away from this path.
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
    pub fn add_unverified_for_devnet(&mut self, tx: EncryptedTx) -> Result<(), MempoolError> {
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
    ///
    /// TPL-407: also asserts `derive_eoa_address(sender_pubkey)
    /// == tx.sender`. Pre-fix the FALCON sig binding closed
    /// (sender_pubkey, tx.hash()) but NOT (sender_pubkey,
    /// tx.sender) — an attacker could submit a tx claiming
    /// `sender = victim`, signed by their own (attacker) pubkey,
    /// and the sig still verified because verification only
    /// requires the supplied pubkey to match the signing key. The
    /// crafted tx then sat in the mempool charged to the victim's
    /// nonce/quota slot. The address-binding check below closes
    /// that gap: if the on-chain address derived from the supplied
    /// pubkey doesn't match `tx.sender`, reject before either the
    /// sig verify or any further state mutation.
    pub fn add_with_pubkey(
        &mut self,
        tx: EncryptedTx,
        sender_pubkey: &[u8],
    ) -> Result<(), MempoolError> {
        self.check_sender_rate(&tx.sender)?;
        // TPL-407: pubkey → sender binding. Cheap (Poseidon2 over
        // the pubkey bytes) so it goes ahead of the FALCON verify.
        if derive_eoa_address(sender_pubkey) != tx.sender {
            return Err(MempoolError::UnknownOrUnverifiedSender);
        }
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
        self.txs.push_back(tx);
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
    /// TPL-509: O(1) `pop_front` on a `VecDeque`. Pre-fix this was
    /// `Vec::remove(0)`, which shifts every remaining element.
    fn evict_oldest(&mut self) {
        let evicted = match self.txs.pop_front() {
            Some(tx) => tx,
            None => return,
        };
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
        // Audit 385: incrementally remove expired entries from the
        // dedup state instead of clearing + rebuilding `seen_hashes`
        // and re-iterating every retained tx to re-collect its hash.
        // Pre-fix this was O(N) per prune (one Poseidon2 hash per
        // retained tx, plus a HashSet rebuild) even when only a few
        // entries expired; post-fix it's O(K) where K is the expired
        // count, so a mempool with thousands of valid txs and one
        // expired entry doesn't pay the full-sweep cost on every
        // block.
        let expired: Vec<(Address, [u8; 32])> = self
            .txs
            .iter()
            .filter(|tx| tx.is_expired(current))
            .map(|tx| (tx.sender, tx.hash()))
            .collect();

        if expired.is_empty() {
            return;
        }

        self.txs.retain(|tx| !tx.is_expired(current));

        for (sender, hash) in &expired {
            self.seen_hashes.remove(hash);
            self.first_seen_slot.remove(hash);
            self.release_sender_slot(sender, hash);
        }
    }

    /// Get transactions in arrival order (FCFS).
    /// No fee-based priority — Pyde has no tips, everyone pays the same base fee.
    ///
    /// TPL-509: post-VecDeque-switch, the underlying storage is no
    /// longer a contiguous slice, so this returns `Vec<&EncryptedTx>`
    /// (cheap — only borrowing references, not cloning the txs).
    /// Existing call sites that iterate (`for tx in mempool.in_arrival_order()`)
    /// or index (`txs[0]`) keep working unchanged.
    pub fn in_arrival_order(&self) -> Vec<&EncryptedTx> {
        self.txs.iter().collect()
    }

    /// Select transactions for a block, respecting the gas limit
    /// AND a per-block count cap, using **round-robin per-sender
    /// fairness** (TPL-921).
    ///
    /// `max_count` bounds the number of encrypted txs the proposer
    /// will include per block. Production callers pass
    /// [`MAX_ENCRYPTED_TXS_PER_BLOCK`]; tests that don't care about
    /// this dimension pass `usize::MAX` to fall back to gas-only
    /// selection. See the constant's doc comment for the full
    /// rationale (tl;dr: without it the proposer over-includes and
    /// the receive-side decrypt+apply pipeline falls indefinitely
    /// behind).
    ///
    /// ## Fairness (TPL-921)
    ///
    /// Pre-fix the loop walked `self.txs` in raw arrival order. That
    /// meant a single sender who had filled the mempool with 5 K txs
    /// across the per-sender quota windows could claim every slot of
    /// every block until their backlog drained — a self-spam DoS
    /// against any other sender's tx submitted in the same window.
    /// The new algorithm:
    ///
    ///   1. Group pending (non-expired) txs by sender, preserving
    ///      per-sender arrival order via `VecDeque`.
    ///   2. Walk senders in **first-appearance arrival order** — so
    ///      ordering across senders still matches original arrival
    ///      timing for the case "two senders, no contention".
    ///   3. Per round, give each sender at most ONE inclusion (their
    ///      next tx that fits the remaining gas budget). Repeat
    ///      rounds until either we hit `max_count`, every sender's
    ///      queue is exhausted, or no sender's frontmost tx fits the
    ///      remaining gas.
    ///
    /// Properties:
    ///
    ///   * No single sender can occupy more than ⌈n/k⌉ slots of a
    ///     block where `n = max_count` and `k` is the number of
    ///     senders with pending txs in the block. With one sender,
    ///     the algorithm degrades to FCFS arrival order; with
    ///     `max_count` senders it gives every sender exactly one
    ///     inclusion.
    ///   * Gas-pressure semantics match the pre-fix path: a tx that
    ///     doesn't fit the remaining budget is skipped (not
    ///     selected, but also not popped from the sender's queue
    ///     until we choose to give up on that sender). On the next
    ///     round we retry the same tx — which is correct because
    ///     `gas_used` only grows, so once the frontmost tx of a
    ///     sender doesn't fit, their queue is effectively done for
    ///     this block. We mark the sender exhausted to skip them in
    ///     subsequent rounds.
    ///   * Expired txs are filtered up front during the grouping
    ///     pass; they never appear in any sender's queue.
    ///
    /// The proposer VRF-shuffles the selected set after this.
    pub fn select_for_block(
        &self,
        block_gas_limit: u64,
        max_count: usize,
        current_slot: u64,
    ) -> Vec<&EncryptedTx> {
        if max_count == 0 {
            return Vec::new();
        }

        // Step 1: per-sender VecDeque of pending (non-expired) txs,
        // preserving arrival order within each sender. `sender_order`
        // captures first-appearance arrival timing — the order in
        // which we'll round-robin walk senders below.
        let mut per_sender: HashMap<Address, VecDeque<&EncryptedTx>> =
            HashMap::with_capacity(self.txs.len().min(max_count));
        let mut sender_order: Vec<Address> = Vec::new();
        for tx in &self.txs {
            if tx.is_expired(current_slot) {
                continue;
            }
            let entry = per_sender.entry(tx.sender);
            if let std::collections::hash_map::Entry::Vacant(_) = entry {
                sender_order.push(tx.sender);
            }
            per_sender
                .entry(tx.sender)
                .or_insert_with(VecDeque::new)
                .push_back(tx);
        }

        // Step 2: round-robin selection. `exhausted` short-circuits
        // senders whose frontmost tx didn't fit the remaining gas
        // budget — they cannot recover this block (gas only grows).
        let mut selected: Vec<&EncryptedTx> = Vec::with_capacity(max_count.min(self.txs.len()));
        let mut gas_used = 0u64;
        let mut exhausted: HashSet<Address> = HashSet::new();

        loop {
            if selected.len() >= max_count {
                break;
            }
            let mut progressed_this_round = false;
            for sender in &sender_order {
                if selected.len() >= max_count {
                    break;
                }
                if exhausted.contains(sender) {
                    continue;
                }
                let queue = match per_sender.get_mut(sender) {
                    Some(q) => q,
                    None => continue,
                };
                let tx = match queue.front() {
                    Some(tx) => *tx,
                    None => {
                        // Drained.
                        exhausted.insert(*sender);
                        continue;
                    }
                };
                if gas_used.saturating_add(tx.gas_limit) > block_gas_limit {
                    // Frontmost doesn't fit. Skip this sender for
                    // the rest of the block.
                    exhausted.insert(*sender);
                    continue;
                }
                queue.pop_front();
                gas_used += tx.gas_limit;
                selected.push(tx);
                progressed_this_round = true;
            }
            if !progressed_this_round {
                break;
            }
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
        encrypt_transaction(
            sender,
            nonce,
            gas,
            dummy_access_list(),
            None,
            1,
            dummy_signature(),
            &to,
            0,
            b"",
            pk,
        )
        .unwrap()
    }

    /// TPL-921: build a tx with an explicit sender so fairness tests
    /// can stack many txs against the same address. The default
    /// `make_enc_tx` derives a fresh sender from the nonce, which is
    /// fine for FCFS coverage but useless for verifying round-robin
    /// behaviour across senders.
    fn make_enc_tx_for_sender(
        pk: &threshold::ThresholdPublicKey,
        sender: Address,
        gas: u64,
        nonce: u64,
    ) -> EncryptedTx {
        let to = derive_eoa_address(b"to");
        encrypt_transaction(
            sender,
            nonce,
            gas,
            dummy_access_list(),
            None,
            1,
            dummy_signature(),
            &to,
            0,
            b"",
            pk,
        )
        .unwrap()
    }

    fn make_enc_tx_with_deadline(
        pk: &threshold::ThresholdPublicKey,
        gas: u64,
        nonce: u64,
        deadline: u64,
    ) -> EncryptedTx {
        let sender = derive_eoa_address(&nonce.to_le_bytes());
        let to = derive_eoa_address(b"to");
        encrypt_transaction(
            sender,
            nonce,
            gas,
            dummy_access_list(),
            Some(deadline),
            1,
            dummy_signature(),
            &to,
            0,
            b"",
            pk,
        )
        .unwrap()
    }

    // ========== Task 0520: Encrypted tx stored in mempool ==========

    #[test]
    fn add_encrypted_tx() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        let tx = make_enc_tx(&pk, 50_000, 0);
        pool.add_unverified_for_devnet(tx).unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn reject_duplicate() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        let tx = make_enc_tx(&pk, 50_000, 0);
        pool.add_unverified_for_devnet(tx.clone()).unwrap();
        assert_eq!(pool.add_unverified_for_devnet(tx), Err(MempoolError::Duplicate));
    }

    #[test]
    fn reject_expired() {
        let pk = make_pk();
        let mut pool = Mempool::new();
        pool.set_current_block(200);

        let tx = make_enc_tx_with_deadline(&pk, 50_000, 0, 100); // expired
        assert_eq!(pool.add_unverified_for_devnet(tx), Err(MempoolError::Expired));
    }

    #[test]
    fn reject_gas_too_low() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        let tx = make_enc_tx(&pk, 20_999, 0); // below 21K
        assert_eq!(pool.add_unverified_for_devnet(tx), Err(MempoolError::GasTooLow));
    }

    #[test]
    fn reject_gas_too_high() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        let tx = make_enc_tx(&pk, 2_000_000_000, 0); // exceeds GAS_CEILING
        assert_eq!(pool.add_unverified_for_devnet(tx), Err(MempoolError::GasTooHigh));
    }

    #[test]
    fn reject_empty_signature() {
        let pk = make_pk();
        let mut pool = Mempool::new();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"to");

        let tx = encrypt_transaction(
            sender,
            0,
            50_000,
            dummy_access_list(),
            None,
            1,
            vec![], // empty sig
            &to,
            0,
            b"",
            &pk,
        )
        .unwrap();
        assert_eq!(pool.add_unverified_for_devnet(tx), Err(MempoolError::InvalidSignature));
    }

    #[test]
    fn reject_empty_access_list() {
        let pk = make_pk();
        let mut pool = Mempool::new();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"to");

        let tx = encrypt_transaction(
            sender,
            0,
            50_000,
            vec![],
            None,
            1, // empty access list
            dummy_signature(),
            &to,
            0,
            b"",
            &pk,
        )
        .unwrap();
        assert_eq!(pool.add_unverified_for_devnet(tx), Err(MempoolError::MissingAccessList));
    }

    // ========== Task 0521: Eviction when full ==========

    #[test]
    fn evict_oldest_when_full() {
        let pk = make_pk();
        let mut pool = Mempool::with_capacity(3);

        // Fill pool: nonce 0 (oldest), 1, 2
        pool.add_unverified_for_devnet(make_enc_tx(&pk, 30_000, 0)).unwrap();
        pool.add_unverified_for_devnet(make_enc_tx(&pk, 40_000, 1)).unwrap();
        pool.add_unverified_for_devnet(make_enc_tx(&pk, 50_000, 2)).unwrap();
        assert_eq!(pool.len(), 3);

        // Add new tx → evicts oldest (nonce 0, gas 30K)
        pool.add_unverified_for_devnet(make_enc_tx(&pk, 60_000, 3)).unwrap();
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

        pool.add_unverified_for_devnet(make_enc_tx(&pk, 30_000, 0)).unwrap();
        pool.add_unverified_for_devnet(make_enc_tx(&pk, 60_000, 1)).unwrap();
        pool.add_unverified_for_devnet(make_enc_tx(&pk, 45_000, 2)).unwrap();

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

        pool.add_unverified_for_devnet(make_enc_tx(&pk, 50_000, 0)).unwrap();
        pool.add_unverified_for_devnet(make_enc_tx(&pk, 60_000, 1)).unwrap();
        pool.add_unverified_for_devnet(make_enc_tx(&pk, 40_000, 2)).unwrap();

        // Block gas limit of 100K → picks 60K + 40K (or 60K + 50K... highest first)
        let selected = pool.select_for_block(100_000, usize::MAX, 0);
        let total_gas: u64 = selected.iter().map(|t| t.gas_limit).sum();
        assert!(total_gas <= 100_000);
        assert!(!selected.is_empty());
    }

    #[test]
    fn select_skips_expired() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        pool.add_unverified_for_devnet(make_enc_tx_with_deadline(&pk, 50_000, 0, 200))
            .unwrap();
        pool.add_unverified_for_devnet(make_enc_tx(&pk, 60_000, 1)).unwrap(); // no deadline

        // At slot 300, first tx is expired
        let selected = pool.select_for_block(1_000_000, usize::MAX, 300);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].gas_limit, 60_000);
    }

    #[test]
    fn select_for_block_caps_at_max_count() {
        // Per-block cap is the brake on proposer over-inclusion
        // (PR follow-up to the encrypted-path loadgen). With gas
        // headroom for 5 txs but max_count=2, only 2 are selected.
        let pk = make_pk();
        let mut pool = Mempool::new();
        // Lift rate limits so add() doesn't rate-limit us before the
        // pool has the test-relevant txs.
        pool.set_rate_limits(1_000, 1_000);
        for nonce in 0..5 {
            pool.add_unverified_for_devnet(make_enc_tx(&pk, 30_000, nonce)).unwrap();
        }
        // Gas room = 5×30k = 150k well under 1M, count cap = 2
        let selected = pool.select_for_block(1_000_000, 2, 0);
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn select_for_block_uses_production_cap_const() {
        // Sanity check: passing MAX_ENCRYPTED_TXS_PER_BLOCK behaves
        // identically to passing the constant by value. Locks the
        // production-call shape so a future refactor that shadows
        // the constant fails this test.
        let pk = make_pk();
        let mut pool = Mempool::new();
        pool.set_rate_limits(10_000, 10_000);
        // Add more than the cap so the cap is the binding constraint.
        for nonce in 0..(MAX_ENCRYPTED_TXS_PER_BLOCK as u64 + 5) {
            pool.add_unverified_for_devnet(make_enc_tx(&pk, 30_000, nonce)).unwrap();
        }
        let selected = pool.select_for_block(1_000_000_000, MAX_ENCRYPTED_TXS_PER_BLOCK, 0);
        assert_eq!(selected.len(), MAX_ENCRYPTED_TXS_PER_BLOCK);
    }

    // ========== TPL-921: per-sender fairness in select_for_block ==========

    #[test]
    fn tpl_921_select_round_robins_across_senders() {
        // Sender A has 50 pending txs, sender B has just 1. With a
        // count cap of 10, the pre-fix FCFS-arrival selector would
        // give all 10 slots to A (B's tx never reaches the front
        // because it arrived after A's). The new round-robin selector
        // gives B at least one inclusion in the first round and A
        // takes the remaining 9.
        let pk = make_pk();
        let mut pool = Mempool::new();
        pool.set_rate_limits(1_000, 1_000);
        let alice = derive_eoa_address(b"tpl-921-alice");
        let bob = derive_eoa_address(b"tpl-921-bob");
        for nonce in 0..50 {
            pool.add_unverified_for_devnet(make_enc_tx_for_sender(&pk, alice, 30_000, nonce))
                .unwrap();
        }
        // Bob's single tx arrives last in the FCFS log.
        pool.add_unverified_for_devnet(make_enc_tx_for_sender(&pk, bob, 30_000, 0))
            .unwrap();

        let selected = pool.select_for_block(1_000_000, 10, 0);
        assert_eq!(selected.len(), 10);

        let bob_count = selected.iter().filter(|tx| tx.sender == bob).count();
        let alice_count = selected.iter().filter(|tx| tx.sender == alice).count();
        assert_eq!(bob_count, 1, "bob must get at least one inclusion");
        assert_eq!(alice_count, 9, "alice fills the remainder");

        // Bob's slot must land in the first round (slot 0 or 1, since
        // alice arrived first and gets the round-1 first pick).
        let bob_position = selected.iter().position(|tx| tx.sender == bob).unwrap();
        assert!(
            bob_position <= 1,
            "bob's tx must land in the first round-robin pass, got position {bob_position}"
        );
    }

    #[test]
    fn tpl_921_select_single_sender_falls_back_to_fcfs() {
        // With one sender, round-robin degrades to FCFS arrival
        // order — 5 txs, 5 slots, all selected in arrival order.
        let pk = make_pk();
        let mut pool = Mempool::new();
        pool.set_rate_limits(100, 100);
        let alice = derive_eoa_address(b"tpl-921-solo-alice");
        for nonce in 0..5 {
            pool.add_unverified_for_devnet(make_enc_tx_for_sender(
                &pk,
                alice,
                30_000 + nonce, // unique gas per tx → unique hash
                nonce,
            ))
            .unwrap();
        }

        let selected = pool.select_for_block(1_000_000, 100, 0);
        assert_eq!(selected.len(), 5);
        for (i, tx) in selected.iter().enumerate() {
            assert_eq!(tx.gas_limit, 30_000 + i as u64, "arrival order must hold");
        }
    }

    #[test]
    fn tpl_921_select_skips_sender_when_frontmost_overflows_gas() {
        // Sender A's first tx is huge and exceeds the remaining
        // budget; sender B has small txs that fit. Round-robin must
        // exhaust A (gas only grows, retrying A's frontmost would
        // never succeed) and fill the block from B.
        let pk = make_pk();
        let mut pool = Mempool::new();
        pool.set_rate_limits(100, 100);
        let alice = derive_eoa_address(b"tpl-921-fat-alice");
        let bob = derive_eoa_address(b"tpl-921-fit-bob");

        // Alice's tx is bigger than the entire block budget below.
        pool.add_unverified_for_devnet(make_enc_tx_for_sender(&pk, alice, 800_000, 0))
            .unwrap();
        // Bob has 3 small txs.
        for nonce in 0..3 {
            pool.add_unverified_for_devnet(make_enc_tx_for_sender(&pk, bob, 30_000, nonce))
                .unwrap();
        }

        let selected = pool.select_for_block(500_000, 100, 0);
        let alice_count = selected.iter().filter(|tx| tx.sender == alice).count();
        let bob_count = selected.iter().filter(|tx| tx.sender == bob).count();
        assert_eq!(alice_count, 0, "alice's oversize tx is skipped");
        assert_eq!(bob_count, 3, "bob fills the block");
    }

    // ========== Prune expired ==========

    #[test]
    fn prune_removes_expired() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        pool.add_unverified_for_devnet(make_enc_tx_with_deadline(&pk, 50_000, 0, 100))
            .unwrap();
        pool.add_unverified_for_devnet(make_enc_tx(&pk, 60_000, 1)).unwrap();
        assert_eq!(pool.len(), 2);

        pool.set_current_block(200);
        pool.prune_expired();
        assert_eq!(pool.len(), 1);
    }

    /// Audit 385: pre-fix `prune_expired` cleared and rebuilt
    /// `seen_hashes` from scratch on every prune that evicted any
    /// tx — re-hashing every retained tx (Poseidon2-heavy) even
    /// when only a single entry expired. Post-fix removes only the
    /// expired hashes incrementally. Both must produce the same
    /// final dedup state; this test pins that contract.
    #[test]
    fn audit_385_prune_keeps_seen_hashes_consistent() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        // Mix: tx 0 expires at slot 100, txs 1..5 don't expire.
        let expired_tx = make_enc_tx_with_deadline(&pk, 50_000, 0, 100);
        let expired_hash = expired_tx.hash();
        pool.add_unverified_for_devnet(expired_tx).unwrap();
        let mut retained_hashes = Vec::new();
        for nonce in 1..5u64 {
            let tx = make_enc_tx(&pk, 60_000, nonce);
            retained_hashes.push(tx.hash());
            pool.add_unverified_for_devnet(tx).unwrap();
        }
        assert_eq!(pool.len(), 5);

        pool.set_current_block(200);
        pool.prune_expired();

        // 1 expired removed, 4 retained.
        assert_eq!(pool.len(), 4);

        // Expired hash gone from dedup.
        assert!(!pool.contains(&expired_hash));

        // Every retained hash still recognized as seen — re-adding
        // any retained tx must reject as duplicate.
        for h in &retained_hashes {
            assert!(
                pool.contains(h),
                "retained hash {:?} must remain in seen_hashes",
                h,
            );
        }

        // first_seen_slot must not retain stale entries.
        assert_eq!(pool.first_seen_slot.len(), 4);
        assert!(!pool.first_seen_slot.contains_key(&expired_hash));
        for h in &retained_hashes {
            assert!(pool.first_seen_slot.contains_key(h));
        }
    }

    /// Audit 385: a prune that evicts nothing must NOT touch the
    /// dedup state. Pre-fix the function would early-return on
    /// `txs.len() != before`; post-fix the equivalent gate is
    /// `expired.is_empty()`. This test pins the no-op invariant.
    #[test]
    fn audit_385_prune_no_op_when_nothing_expired() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        let tx = make_enc_tx_with_deadline(&pk, 50_000, 0, 1_000);
        let hash = tx.hash();
        pool.add_unverified_for_devnet(tx).unwrap();

        // Block far below the deadline — nothing expires.
        pool.set_current_block(10);
        let seen_before = pool.seen_hashes.clone();
        let first_seen_before = pool.first_seen_slot.clone();
        pool.prune_expired();

        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&hash));
        assert_eq!(pool.seen_hashes, seen_before);
        assert_eq!(pool.first_seen_slot, first_seen_before);
    }

    // ========== Remove included ==========

    #[test]
    fn remove_included_txs() {
        let pk = make_pk();
        let mut pool = Mempool::new();

        let tx1 = make_enc_tx(&pk, 50_000, 0);
        let tx2 = make_enc_tx(&pk, 60_000, 1);
        let hash1 = tx1.hash();

        pool.add_unverified_for_devnet(tx1).unwrap();
        pool.add_unverified_for_devnet(tx2).unwrap();
        assert_eq!(pool.len(), 2);

        pool.remove_included(&[hash1]);
        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&hash1));
    }

    // ========== Block-level duplicate check ==========

    #[test]
    fn no_duplicates_passes() {
        let pk = make_pk();
        let txs = vec![make_enc_tx(&pk, 50_000, 0), make_enc_tx(&pk, 60_000, 1)];
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
            sender,
            nonce,
            50_000,
            dummy_access_list(),
            None,
            1,
            dummy_signature(),
            &to,
            0,
            b"",
            pk,
        )
        .unwrap()
    }

    // Test clock backed by a thread-local counter. `set_test_clock_ms`
    // moves the needle; `test_clock_ms` is the function pointer fed to
    // `Mempool::set_clock`. (Regular comment, not a doc comment — `///`
    // doesn't attach to `thread_local!` macro items.)
    thread_local! {
        static TEST_CLOCK: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
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
            pool.add_unverified_for_devnet(make_enc_tx_from(&pk, sender, n)).unwrap();
        }

        // Fourth submission within the same window → rate-limited.
        let err = pool.add_unverified_for_devnet(make_enc_tx_from(&pk, sender, 3)).unwrap_err();
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
        pool.add_unverified_for_devnet(make_enc_tx_from(&pk, sender, 0)).unwrap();
        pool.add_unverified_for_devnet(make_enc_tx_from(&pk, sender, 1)).unwrap();

        // Still within window — third is rejected.
        set_test_clock_ms(500);
        assert_eq!(
            pool.add_unverified_for_devnet(make_enc_tx_from(&pk, sender, 2)).unwrap_err(),
            MempoolError::RateLimitExceeded,
        );

        // Advance past window boundary (window = 1000ms, start was 100 ms).
        // At t=1101 all original timestamps are older than now - 1000 = 101.
        set_test_clock_ms(1_101);
        pool.add_unverified_for_devnet(make_enc_tx_from(&pk, sender, 3))
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
            pool.add_unverified_for_devnet(tx).unwrap();
        }

        // 4th concurrently → blocked.
        assert_eq!(
            pool.add_unverified_for_devnet(make_enc_tx_from(&pk, sender, 3)).unwrap_err(),
            MempoolError::TooManyConcurrentFromSender,
        );

        // Include one of the in-pool txs → slot opens up.
        pool.remove_included(&[hashes[0]]);
        set_test_clock_ms(2_100); // roll window so the rate counter doesn't
                                  // independently block (submits are windowed
                                  // but in_pool count is not).
        pool.add_unverified_for_devnet(make_enc_tx_from(&pk, sender, 3))
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

        pool.add_unverified_for_devnet(make_enc_tx_from(&pk, alice, 0)).unwrap();
        pool.add_unverified_for_devnet(make_enc_tx_from(&pk, alice, 1)).unwrap();

        // Alice is at her rate cap, but Bob still has headroom.
        assert_eq!(
            pool.add_unverified_for_devnet(make_enc_tx_from(&pk, alice, 2)).unwrap_err(),
            MempoolError::RateLimitExceeded,
        );
        pool.add_unverified_for_devnet(make_enc_tx_from(&pk, bob, 0))
            .expect("bob is unaffected by alice's cap");
        pool.add_unverified_for_devnet(make_enc_tx_from(&pk, bob, 1)).unwrap();
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
            sender,
            nonce,
            gas,
            dummy_access_list(),
            None,
            1,
            vec![0u8; 666],
            &to,
            0,
            b"",
            threshold_pk,
        )
        .unwrap();
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
        let err = pool
            .add_with_pubkey(tx, attacker_pk.as_bytes())
            .unwrap_err();
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

    /// TPL-407: an attacker submits a tx with `sender = victim`,
    /// signs it with their own (attacker) key, and supplies their
    /// own pubkey. Pre-fix the FALCON verify passed (their pk
    /// signed the hash) and the tx landed in the mempool charged
    /// to the victim's nonce/quota slot. Post-fix the
    /// pubkey → sender binding rejects before the sig check
    /// because `derive_eoa_address(attacker_pk) != victim`.
    #[test]
    fn tpl_407_add_with_pubkey_rejects_sender_pubkey_mismatch() {
        let pk = make_pk();
        // Build a tx legitimately signed by attacker_sk with
        // sender = derive_eoa_address(attacker_pk).
        let (mut tx, attacker_pk_bytes, attacker_sk) = make_falcon_signed_tx(&pk, 50_000, 0);

        // Attack: rewrite the sender field to the victim's
        // address, then re-sign so the FALCON sig verifies against
        // the attacker's pubkey under the new tx.hash(). Pre-fix
        // this is enough to slip into the mempool.
        let victim = derive_eoa_address(b"victim-target-address");
        tx.sender = victim;
        let new_hash = tx.hash();
        tx.signature = pyde_crypto::falcon::falcon_sign(&attacker_sk, &new_hash)
            .unwrap()
            .to_vec();

        // Sanity: the sig DOES verify under the supplied pubkey.
        // The only thing keeping this tx out is the new
        // address-binding check.
        assert!(Mempool::verify_signature_with_key(&tx, &attacker_pk_bytes));

        let mut pool = Mempool::new();
        let err = pool
            .add_with_pubkey(tx, &attacker_pk_bytes)
            .expect_err("pubkey/sender mismatch must reject");
        assert_eq!(err, MempoolError::UnknownOrUnverifiedSender);
        assert_eq!(pool.len(), 0);
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
        tx2.signature = pyde_crypto::falcon::falcon_sign(&sk1, &new_hash)
            .unwrap()
            .to_vec();

        assert_eq!(
            pool.add_with_pubkey(tx2, &pk1).unwrap_err(),
            MempoolError::RateLimitExceeded,
        );
    }
}
