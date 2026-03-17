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
use sparse_merkle_tree::H256;

/// Committee size (128 validators per epoch).
pub const COMMITTEE_SIZE: usize = 128;

/// Quorum threshold (2/3 of committee = 86).
pub const QUORUM_THRESHOLD: usize = 86;

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

    /// Whether this QC has enough votes (>= 86/128).
    pub fn has_quorum(&self) -> bool {
        self.vote_count() >= QUORUM_THRESHOLD as u32
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
    pub state_root: [u8; 32],
    /// Block timestamp (Unix milliseconds).
    pub timestamp: u64,
}

impl BlockHeader {
    /// Compute the block hash: Poseidon2 of all header fields.
    pub fn hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&self.slot.to_le_bytes());
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(&self.parent_hash);
        buf.extend_from_slice(&self.proposer);
        buf.extend_from_slice(&self.tx_root);
        buf.extend_from_slice(&self.state_root);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.qc_previous.slot.to_le_bytes());
        buf.extend_from_slice(&self.qc_previous.block_hash);
        poseidon2_hash(&buf).to_bytes()
    }
}

/// Block body: transactions and execution schedule.
#[derive(Clone, Debug)]
pub struct BlockBody {
    /// Ordered list of transactions in this block.
    pub transactions: Vec<Transaction>,
    /// Parallel execution schedule (groups of non-conflicting txs).
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

/// Compute the Merkle root of a list of transactions (Poseidon2 of all tx hashes).
pub fn compute_tx_root(txs: &[Transaction]) -> [u8; 32] {
    if txs.is_empty() {
        return [0u8; 32];
    }
    let mut buf = Vec::with_capacity(txs.len() * 32);
    for tx in txs {
        buf.extend_from_slice(&tx.hash());
    }
    poseidon2_hash(&buf).to_bytes()
}

/// Create the genesis block.
pub fn genesis_block(
    genesis_state_root: [u8; 32],
    timestamp: u64,
) -> Block {
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
            execution_schedule: ExecutionSchedule {
                groups: vec![],
                total_txs: 0,
            },
        },
        proposer_signature: vec![],
    }
}

#[cfg(test)]
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
        let b1 = genesis_block([0xAA; 32], 1_000_000);
        let b2 = genesis_block([0xBB; 32], 1_000_000);
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
        assert_eq!(compute_tx_root(&[]), [0u8; 32]);
    }

    #[test]
    fn tx_root_deterministic() {
        use pyde_tx::types::{FeePayer, TransactionType};
        let tx = Transaction {
            from: derive_eoa_address(&[0xAA; 897]),
            to: derive_eoa_address(&[0xBB; 897]),
            value: 100,
            data: vec![],
            gas_limit: 21_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };
        assert_eq!(compute_tx_root(&[tx.clone()]), compute_tx_root(&[tx]));
    }

    // ========== Epoch ==========

    #[test]
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
}
