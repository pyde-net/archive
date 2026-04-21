//! Block structure per Chapter 6 spec.
//!
//! - BlockHeader: slot, epoch, parent_hash, proposer, vrf_proof, qc, tx_root, timestamp
//! - BlockBody: transactions, execution schedule
//! - Block: header + body
//! - QuorumCert: slot, block_hash, voter_bitmap, signatures
//! - Genesis block creation

use pyde_account::address::Address;
use pyde_crypto::poseidon2::poseidon2_hash;
use pyde_tx::parallel::ExecutionSchedule;
use pyde_tx::types::Transaction;

/// Committee size (128 validators per epoch).
pub const COMMITTEE_SIZE: usize = 128;

/// Quorum threshold for production (2/3 of 128 = 86).
pub const QUORUM_THRESHOLD: usize = 86;

/// Compute quorum threshold for a given committee size: ceil(2/3 * size).
/// For production (128 members) this returns 86.
/// For devnet (2-4 members) this returns the correct BFT threshold.
pub fn quorum_for_committee(committee_size: usize) -> usize {
    if committee_size == 0 {
        return 0;
    }
    // ceil(2/3 * n) = (2*n + 2) / 3
    (2 * committee_size).div_ceil(3)
}

/// Blocks per epoch (~1000 blocks, ~6.6 minutes at 400ms).
pub const EPOCH_LENGTH: u64 = 1000;

/// Block time target in milliseconds.
pub const BLOCK_TIME_MS: u64 = 400;

/// Quorum Certificate: proof that 2/3+ validators voted for a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumCert {
    /// Slot this QC covers.
    pub slot: u64,
    /// Hash of the block being certified.
    pub block_hash: [u8; 32],
    /// 128-bit bitmap of which validators voted (bit i = validator i).
    pub voter_bitmap: u128,
    /// FALCON-512 signatures from voting validators.
    pub signatures: Vec<Vec<u8>>,
}

impl QuorumCert {
    /// Number of votes in this QC.
    pub fn vote_count(&self) -> u32 {
        self.voter_bitmap.count_ones()
    }

    /// Whether this QC has enough votes (>= 86/128) for production committee.
    pub fn has_quorum(&self) -> bool {
        self.vote_count() >= QUORUM_THRESHOLD as u32
    }

    /// Whether this QC has enough votes for a given committee size.
    pub fn has_quorum_for(&self, committee_size: usize) -> bool {
        self.vote_count() >= quorum_for_committee(committee_size) as u32
    }

    /// Hash this QC: Poseidon2(slot + block_hash + voter_bitmap).
    pub fn hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(56); // 8 + 32 + 16 = 56
        buf.extend_from_slice(&self.slot.to_le_bytes());
        buf.extend_from_slice(&self.block_hash);
        buf.extend_from_slice(&self.voter_bitmap.to_le_bytes());
        poseidon2_hash(&buf).to_bytes()
    }

    /// Empty QC (for genesis block).
    pub fn empty() -> Self {
        Self {
            slot: 0,
            block_hash: [0u8; 32],
            voter_bitmap: 0,
            signatures: vec![],
        }
    }
}

/// Block header: metadata for a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Slot number (monotonically increasing).
    pub slot: u64,
    /// Epoch number (slot / EPOCH_LENGTH).
    pub epoch: u64,
    /// Poseidon2 hash of the parent block header.
    pub parent_hash: [u8; 32],
    /// Address of the block proposer.
    pub proposer: Address,
    /// VRF proof that this proposer was selected.
    pub vrf_proof: Vec<u8>,
    /// Quorum Certificate for the previous slot.
    pub qc_previous: QuorumCert,
    /// Merkle root of the transactions in this block.
    pub tx_root: [u8; 32],
    /// State root after executing all transactions.
    /// NOTE: Empty at proposal time (txs encrypted, can't compute).
    /// Set by full nodes after optimistic execution at soft finality.
    /// Verified by validator re-execution and committed in HardFinalityCert.
    pub state_root: [u8; 32],
    /// Block timestamp (Unix milliseconds).
    pub timestamp: u64,
}

impl BlockHeader {
    /// Compute the block hash: Poseidon2 of header fields.
    ///
    /// Includes all fields that uniquely identify this block's CONTENT.
    /// Does NOT include state_root — it's unknown at proposal time (txs encrypted)
    /// and committed separately via HardFinalityCert after validator re-execution.
    /// Excludes QC signatures/bitmap (large, and QC slot+hash suffice).
    pub fn hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(192); // 8+8+32+32+32+32+8+32 = 184
        buf.extend_from_slice(&self.slot.to_le_bytes()); // 8
        buf.extend_from_slice(&self.epoch.to_le_bytes()); // 8
        buf.extend_from_slice(&self.parent_hash); // 32
        buf.extend_from_slice(&self.proposer); // 32
        buf.extend_from_slice(&poseidon2_hash(&self.vrf_proof).to_bytes()); // 32
        buf.extend_from_slice(&self.tx_root); // 32
        buf.extend_from_slice(&self.timestamp.to_le_bytes()); // 8
        buf.extend_from_slice(&self.qc_previous.hash()); // 32 (hashed QC)
        poseidon2_hash(&buf).to_bytes()
    }
}

/// Block body: transactions and execution schedule.
#[derive(Clone, Debug)]
pub struct BlockBody {
    /// Ordered list of plaintext transactions (dev mode or post-decryption).
    pub transactions: Vec<Transaction>,
    /// Encrypted transaction blobs (threshold-encrypted, decrypted after QC).
    /// Empty in dev mode. In production, proposer includes these from the encrypted mempool.
    pub encrypted_txs: Vec<Vec<u8>>,
    /// Conflict-based execution schedule. Each group contains transitively
    /// conflicting txs (sequential within group). Groups are independent
    /// and can be proven in parallel from the same pre_state_root.
    pub execution_schedule: ExecutionSchedule,
}

/// A complete block: header + body.
#[derive(Clone, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
    /// Proposer's FALCON-512 signature over the header hash.
    pub proposer_signature: Vec<u8>,
}

impl Block {
    /// Block hash (delegates to header).
    pub fn hash(&self) -> [u8; 32] {
        self.header.hash()
    }

    /// Number of transactions in this block.
    pub fn tx_count(&self) -> usize {
        self.body.transactions.len()
    }

    /// Slot number.
    pub fn slot(&self) -> u64 {
        self.header.slot
    }

    /// Epoch number.
    pub fn epoch(&self) -> u64 {
        self.header.epoch
    }

    /// Whether this is the genesis block.
    pub fn is_genesis(&self) -> bool {
        self.header.slot == 0 && self.header.parent_hash == [0u8; 32]
    }
}

/// Commit to the full transaction ordering of a block: plaintext
/// transactions first, then encrypted-tx hashes in the order they
/// appear in the block body.
///
/// Hashing BOTH kinds is load-bearing for MEV protection. If tx_root
/// covered only plaintext txs, a proposer could swap the order of
/// encrypted_txs *after* the QC was formed on the header — they'd
/// decrypt first, then reorder to front-run profitable trades, all
/// without changing the block hash. Including encrypted_tx hashes in
/// tx_root binds the execution order to the proposer signature +
/// quorum certificate, so any post-QC reordering is detectable.
///
/// `encrypted_tx_hashes` are the `EncryptedTx::hash()` values in block
/// order. Passing pre-computed hashes keeps this crate free of any
/// mempool dep (`pyde-consensus` cannot depend on `pyde-mempool`).
pub fn compute_tx_root(txs: &[Transaction], encrypted_tx_hashes: &[[u8; 32]]) -> [u8; 32] {
    if txs.is_empty() && encrypted_tx_hashes.is_empty() {
        return [0u8; 32];
    }
    let mut buf = Vec::with_capacity((txs.len() + encrypted_tx_hashes.len()) * 32);
    for tx in txs {
        buf.extend_from_slice(&tx.hash());
    }
    for h in encrypted_tx_hashes {
        buf.extend_from_slice(h);
    }
    poseidon2_hash(&buf).to_bytes()
}

/// Verify that a block's plaintext txs and encrypted-tx hashes recompute
/// to the committed `tx_root`. Returns `true` iff the ordering matches
/// the header's commitment.
///
/// Used at two points:
///   1. On block receive, before accepting the body (block_processor).
///   2. On decrypt time, before applying decrypted state (node).
///
/// Step 2 is defense-in-depth: step 1 already rejects tampered bodies,
/// but re-checking immediately before decryption makes the ordering
/// invariant visible at the site that actually depends on it.
pub fn verify_tx_root(
    committed_tx_root: &[u8; 32],
    txs: &[Transaction],
    encrypted_tx_hashes: &[[u8; 32]],
) -> bool {
    &compute_tx_root(txs, encrypted_tx_hashes) == committed_tx_root
}

/// Create the genesis block.
pub fn genesis_block(genesis_state_root: [u8; 32], timestamp: u64) -> Block {
    let header = BlockHeader {
        slot: 0,
        epoch: 0,
        parent_hash: [0u8; 32],
        proposer: [0u8; 32],
        vrf_proof: vec![],
        qc_previous: QuorumCert::empty(),
        tx_root: [0u8; 32],
        state_root: genesis_state_root,
        timestamp,
    };

    Block {
        header,
        body: BlockBody {
            transactions: vec![],
            encrypted_txs: vec![],
            execution_schedule: ExecutionSchedule {
                groups: vec![],
                total_txs: 0,
            },
        },
        proposer_signature: vec![],
    }
}

#[cfg(test)]
// `cloned_ref_to_slice_refs` — tests build 1-element `&[tx.clone()]`
// slices for determinism assertions. The clone is harmless here and
// the `std::slice::from_ref(&tx)` rewrite makes each call site noisier
// without test-level benefit.
#[allow(clippy::cloned_ref_to_slice_refs)]
mod tests {
    use super::*;
    use pyde_account::address::derive_eoa_address;

    // ========== Task 0455: Block hash is deterministic ==========

    #[test]
    fn block_hash_deterministic() {
        let block = genesis_block([0xAA; 32], 1_000_000);
        assert_eq!(block.hash(), block.hash());
    }

    #[test]
    fn different_blocks_different_hash() {
        // state_root not in hash (unknown at proposal), so differ by timestamp
        let b1 = genesis_block([0xAA; 32], 1_000_000);
        let b2 = genesis_block([0xAA; 32], 2_000_000);
        assert_ne!(b1.hash(), b2.hash());
    }

    #[test]
    fn different_timestamp_different_hash() {
        let b1 = genesis_block([0xAA; 32], 1_000_000);
        let b2 = genesis_block([0xAA; 32], 2_000_000);
        assert_ne!(b1.hash(), b2.hash());
    }

    // ========== Task 0456: Genesis block ==========

    #[test]
    fn genesis_has_correct_values() {
        let block = genesis_block([0xFF; 32], 1_000_000);
        assert!(block.is_genesis());
        assert_eq!(block.slot(), 0);
        assert_eq!(block.epoch(), 0);
        assert_eq!(block.header.parent_hash, [0u8; 32]);
        assert_eq!(block.header.state_root, [0xFF; 32]);
        assert_eq!(block.header.timestamp, 1_000_000);
        assert_eq!(block.tx_count(), 0);
        assert!(block.header.qc_previous.signatures.is_empty());
    }

    #[test]
    fn genesis_hash_is_not_zero() {
        let block = genesis_block([0xAA; 32], 1_000_000);
        assert_ne!(block.hash(), [0u8; 32]);
    }

    // ========== QuorumCert ==========

    #[test]
    fn quorum_cert_vote_count() {
        let mut qc = QuorumCert::empty();
        assert_eq!(qc.vote_count(), 0);
        assert!(!qc.has_quorum());

        // Set 86 bits
        qc.voter_bitmap = (1u128 << 86) - 1; // bits 0-85
        assert_eq!(qc.vote_count(), 86);
        assert!(qc.has_quorum());
    }

    #[test]
    fn quorum_needs_86_of_128() {
        let mut qc = QuorumCert::empty();
        qc.voter_bitmap = (1u128 << 85) - 1; // 85 votes
        assert!(!qc.has_quorum());

        qc.voter_bitmap = (1u128 << 86) - 1; // 86 votes
        assert!(qc.has_quorum());
    }

    // ========== TX root ==========

    #[test]
    fn empty_tx_root_is_zero() {
        assert_eq!(compute_tx_root(&[], &[]), [0u8; 32]);
    }

    fn dummy_tx(nonce: u64) -> Transaction {
        use pyde_tx::types::{FeePayer, TransactionType};
        Transaction {
            from: derive_eoa_address(&[0xAA; 897]),
            to: derive_eoa_address(&[0xBB; 897]),
            value: 100,
            data: vec![],
            gas_limit: 21_000,
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
    fn tx_root_deterministic() {
        let tx = dummy_tx(0);
        assert_eq!(
            compute_tx_root(&[tx.clone()], &[]),
            compute_tx_root(&[tx], &[])
        );
    }

    #[test]
    fn tx_root_includes_encrypted_tx_hashes() {
        // Plaintext-only vs with an encrypted tx → different roots.
        let tx = dummy_tx(0);
        let enc_hash = [0xCC; 32];
        let plain = compute_tx_root(&[tx.clone()], &[]);
        let mixed = compute_tx_root(&[tx], &[enc_hash]);
        assert_ne!(
            plain, mixed,
            "adding an encrypted tx must change tx_root; otherwise encrypted \
             order isn't committed and a proposer can reorder post-QC"
        );
    }

    #[test]
    fn tx_root_order_sensitive_for_encrypted() {
        // Same encrypted hashes, different order → different roots. This
        // is what closes the proposer-frontrunning hole: after the QC,
        // any reordering of encrypted_txs produces a tx_root that no
        // longer matches the signed block header.
        let tx = dummy_tx(0);
        let a = [0x01; 32];
        let b = [0x02; 32];
        let ab = compute_tx_root(&[tx.clone()], &[a, b]);
        let ba = compute_tx_root(&[tx], &[b, a]);
        assert_ne!(ab, ba);
    }

    #[test]
    fn verify_tx_root_accepts_matching() {
        let tx = dummy_tx(0);
        let h = [0xAA; 32];
        let root = compute_tx_root(&[tx.clone()], &[h]);
        assert!(verify_tx_root(&root, &[tx], &[h]));
    }

    #[test]
    fn verify_tx_root_rejects_reordered_encrypted() {
        // Same attack surface as tx_root_order_sensitive, expressed
        // through the helper used on the receive + decrypt paths.
        let tx = dummy_tx(0);
        let a = [0x01; 32];
        let b = [0x02; 32];
        let committed = compute_tx_root(&[tx.clone()], &[a, b]);
        assert!(verify_tx_root(&committed, &[tx.clone()], &[a, b]));
        assert!(!verify_tx_root(&committed, &[tx], &[b, a]));
    }

    // ========== Epoch ==========

    #[test]
    #[allow(clippy::erasing_op)] // `0 / EPOCH_LENGTH` is deliberate — the test's point is "genesis slot = epoch 0"
    fn epoch_from_slot() {
        assert_eq!(0 / EPOCH_LENGTH, 0);
        assert_eq!(999 / EPOCH_LENGTH, 0);
        assert_eq!(1000 / EPOCH_LENGTH, 1);
        assert_eq!(2500 / EPOCH_LENGTH, 2);
    }

    // ========== Constants ==========

    #[test]
    fn constants_match_spec() {
        assert_eq!(COMMITTEE_SIZE, 128);
        assert_eq!(QUORUM_THRESHOLD, 86);
        assert_eq!(EPOCH_LENGTH, 1000);
        assert_eq!(BLOCK_TIME_MS, 400);
    }

    // ========== Dynamic quorum ==========

    #[test]
    fn quorum_for_committee_production() {
        // 128 members → 86 (matches production constant)
        assert_eq!(quorum_for_committee(128), 86);
    }

    #[test]
    fn quorum_for_committee_small() {
        assert_eq!(quorum_for_committee(0), 0);
        assert_eq!(quorum_for_committee(1), 1); // single node: needs 1
        assert_eq!(quorum_for_committee(2), 2); // 2 nodes: needs 2
        assert_eq!(quorum_for_committee(3), 2); // 3 nodes: needs 2
        assert_eq!(quorum_for_committee(4), 3); // 4 nodes: needs 3
        assert_eq!(quorum_for_committee(5), 4); // 5 nodes: needs 4
        assert_eq!(quorum_for_committee(10), 7);
    }

    #[test]
    fn has_quorum_for_dynamic() {
        let mut qc = QuorumCert::empty();
        qc.voter_bitmap = 0b11; // 2 votes
        assert!(qc.has_quorum_for(2)); // 2/2 = quorum
        assert!(qc.has_quorum_for(3)); // 2/3 = quorum (threshold=2)
        assert!(!qc.has_quorum_for(4)); // 2/4, threshold=3
    }
}
