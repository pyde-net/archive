//! Binary wire format for P2P message serialization.
//!
//! All messages use a simple length-prefixed binary encoding for speed.
//! Format: message_type(1) || payload_bytes
//!
//! This is NOT a general-purpose serialization library — it's purpose-built
//! for Pyde's P2P protocol and optimized for fast encode/decode.

use pyde_account::address::Address;
use pyde_consensus::block::{Block, BlockBody, BlockHeader, QuorumCert};
use pyde_consensus::hotstuff::ConsensusMessage;
use pyde_tx::parallel::ExecutionSchedule;
use pyde_tx::types::{AccessEntry, FeePayer, Transaction, TransactionType};

/// Message type tags for wire encoding.
pub mod tag {
    pub const BLOCK: u8 = 0x01;
    pub const TRANSACTION: u8 = 0x02;
    pub const CONSENSUS_PROPOSAL: u8 = 0x10;
    pub const CONSENSUS_VOTE: u8 = 0x11;
    pub const CONSENSUS_TIMEOUT: u8 = 0x12;
    pub const CONSENSUS_NEW_VIEW: u8 = 0x13;
    pub const CONSENSUS_FINALITY_VOTE: u8 = 0x14;
    pub const DECRYPTION_SHARES: u8 = 0x20;
}

/// Decryption share broadcast message.
/// Sent by each committee member after QC is formed for a block.
#[derive(Clone, Debug)]
pub struct DecryptionShareMsg {
    /// Slot this share is for.
    pub slot: u64,
    /// Voter/committee member index.
    pub member_index: u8,
    /// One share per encrypted tx in the block.
    /// Each share is the raw bytes of the DecryptionShare.
    pub shares: Vec<Vec<u8>>,
}

pub fn encode_finality_vote(vote: &pyde_consensus::finality::FinalityVote) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u8(tag::CONSENSUS_FINALITY_VOTE);
    enc.u64(vote.slot);
    enc.bytes32(&vote.block_hash);
    enc.bytes32(&vote.state_root);
    enc.u8(vote.voter_index);
    enc.bytes32(&vote.voter_address);
    enc.var_bytes(&vote.signature);
    enc.finish()
}

pub fn decode_finality_vote(data: &[u8]) -> Result<pyde_consensus::finality::FinalityVote, &'static str> {
    let mut dec = Decoder::new(data);
    let tag_byte = dec.u8()?;
    if tag_byte != tag::CONSENSUS_FINALITY_VOTE {
        return Err("not a finality vote");
    }
    let slot = dec.u64()?;
    let block_hash = dec.bytes32()?;
    let state_root = dec.bytes32()?;
    let voter_index = dec.u8()?;
    let voter_address = dec.bytes32()?;
    let signature = dec.var_bytes()?;
    Ok(pyde_consensus::finality::FinalityVote {
        slot,
        block_hash,
        state_root,
        voter_index,
        voter_address,
        signature,
    })
}

pub fn encode_decryption_shares(msg: &DecryptionShareMsg) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u8(tag::DECRYPTION_SHARES);
    enc.u64(msg.slot);
    enc.u8(msg.member_index);
    enc.u16(msg.shares.len() as u16);
    for share in &msg.shares {
        enc.var_bytes(share);
    }
    enc.finish()
}

pub fn decode_decryption_shares(data: &[u8]) -> Result<DecryptionShareMsg, &'static str> {
    let mut dec = Decoder::new(data);
    let msg_tag = dec.u8()?;
    if msg_tag != tag::DECRYPTION_SHARES { return Err("not a decryption shares message"); }
    let slot = dec.u64()?;
    let member_index = dec.u8()?;
    let count = dec.u16()? as usize;
    let mut shares = Vec::with_capacity(count);
    for _ in 0..count {
        shares.push(dec.var_bytes()?);
    }
    Ok(DecryptionShareMsg { slot, member_index, shares })
}

// ============================================================
// Encoding helpers
// ============================================================

struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self { buf: Vec::with_capacity(1024) }
    }

    fn u8(&mut self, v: u8) { self.buf.push(v); }
    fn u16(&mut self, v: u16) { self.buf.extend_from_slice(&v.to_le_bytes()); }
    fn u32(&mut self, v: u32) { self.buf.extend_from_slice(&v.to_le_bytes()); }
    fn u64(&mut self, v: u64) { self.buf.extend_from_slice(&v.to_le_bytes()); }
    fn u128(&mut self, v: u128) { self.buf.extend_from_slice(&v.to_le_bytes()); }
    fn bytes32(&mut self, v: &[u8; 32]) { self.buf.extend_from_slice(v); }
    fn var_bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.buf.extend_from_slice(v);
    }
    fn finish(self) -> Vec<u8> { self.buf }
}

struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize { self.data.len() - self.pos }

    fn u8(&mut self) -> Result<u8, &'static str> {
        if self.remaining() < 1 { return Err("unexpected end of data"); }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn u16(&mut self) -> Result<u16, &'static str> {
        if self.remaining() < 2 { return Err("unexpected end of data"); }
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 2]);
        self.pos += 2;
        Ok(u16::from_le_bytes(buf))
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        if self.remaining() < 4 { return Err("unexpected end of data"); }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_le_bytes(buf))
    }

    fn u64(&mut self) -> Result<u64, &'static str> {
        if self.remaining() < 8 { return Err("unexpected end of data"); }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(buf))
    }

    fn u128(&mut self) -> Result<u128, &'static str> {
        if self.remaining() < 16 { return Err("unexpected end of data"); }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 16]);
        self.pos += 16;
        Ok(u128::from_le_bytes(buf))
    }

    fn bytes32(&mut self) -> Result<[u8; 32], &'static str> {
        if self.remaining() < 32 { return Err("unexpected end of data"); }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 32]);
        self.pos += 32;
        Ok(buf)
    }

    fn var_bytes(&mut self) -> Result<Vec<u8>, &'static str> {
        let len = self.u32()? as usize;
        if self.remaining() < len { return Err("unexpected end of data"); }
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }
}

// ============================================================
// QuorumCert
// ============================================================

fn encode_qc(enc: &mut Encoder, qc: &QuorumCert) {
    enc.u64(qc.slot);
    enc.bytes32(&qc.block_hash);
    enc.u128(qc.voter_bitmap);
    enc.u16(qc.signatures.len() as u16);
    for sig in &qc.signatures {
        enc.var_bytes(sig);
    }
}

fn decode_qc(dec: &mut Decoder) -> Result<QuorumCert, &'static str> {
    let slot = dec.u64()?;
    let block_hash = dec.bytes32()?;
    let voter_bitmap = dec.u128()?;
    let sig_count = dec.u16()? as usize;
    let mut signatures = Vec::with_capacity(sig_count);
    for _ in 0..sig_count {
        signatures.push(dec.var_bytes()?);
    }
    Ok(QuorumCert { slot, block_hash, voter_bitmap, signatures })
}

// ============================================================
// BlockHeader
// ============================================================

pub fn encode_block_header(header: &BlockHeader) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u64(header.slot);
    enc.u64(header.epoch);
    enc.bytes32(&header.parent_hash);
    enc.bytes32(&header.proposer);
    enc.var_bytes(&header.vrf_proof);
    encode_qc(&mut enc, &header.qc_previous);
    enc.bytes32(&header.tx_root);
    enc.bytes32(&header.state_root);
    enc.u64(header.timestamp);
    enc.finish()
}

pub fn decode_block_header(data: &[u8]) -> Result<BlockHeader, &'static str> {
    let mut dec = Decoder::new(data);
    Ok(BlockHeader {
        slot: dec.u64()?,
        epoch: dec.u64()?,
        parent_hash: dec.bytes32()?,
        proposer: dec.bytes32()?,
        vrf_proof: dec.var_bytes()?,
        qc_previous: decode_qc(&mut dec)?,
        tx_root: dec.bytes32()?,
        state_root: dec.bytes32()?,
        timestamp: dec.u64()?,
    })
}

// ============================================================
// Transaction
// ============================================================

fn encode_access_entry(enc: &mut Encoder, entry: &AccessEntry) {
    enc.bytes32(&entry.address);
    enc.u16(entry.reads.len() as u16);
    for key in &entry.reads { enc.bytes32(key); }
    enc.u16(entry.writes.len() as u16);
    for key in &entry.writes { enc.bytes32(key); }
}

fn decode_access_entry(dec: &mut Decoder) -> Result<AccessEntry, &'static str> {
    let address = dec.bytes32()?;
    let read_count = dec.u16()? as usize;
    let mut reads = Vec::with_capacity(read_count);
    for _ in 0..read_count { reads.push(dec.bytes32()?); }
    let write_count = dec.u16()? as usize;
    let mut writes = Vec::with_capacity(write_count);
    for _ in 0..write_count { writes.push(dec.bytes32()?); }
    Ok(AccessEntry { address, reads, writes })
}

pub fn encode_transaction(tx: &Transaction) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.bytes32(&tx.from);
    enc.bytes32(&tx.to);
    enc.u128(tx.value);
    enc.var_bytes(&tx.data);
    enc.u64(tx.gas_limit);
    enc.u64(tx.nonce);
    enc.var_bytes(&tx.signature);
    // fee_payer
    enc.u8(match tx.fee_payer {
        FeePayer::Sender => 0,
        FeePayer::GasTank(_) => 1,
        FeePayer::Paymaster(_) => 2,
    });
    match &tx.fee_payer {
        FeePayer::GasTank(addr) | FeePayer::Paymaster(addr) => enc.bytes32(addr),
        _ => {}
    }
    // access list
    enc.u16(tx.access_list.len() as u16);
    for entry in &tx.access_list { encode_access_entry(&mut enc, entry); }
    // deadline
    enc.u8(tx.deadline.is_some() as u8);
    if let Some(d) = tx.deadline { enc.u64(d); }
    enc.u64(tx.chain_id);
    // tx_type
    enc.u8(match tx.tx_type {
        TransactionType::Standard => 0,
        TransactionType::Deploy => 1,
        TransactionType::Batch => 2,
    });
    enc.finish()
}

pub fn decode_transaction(data: &[u8]) -> Result<Transaction, &'static str> {
    let mut dec = Decoder::new(data);
    let from = dec.bytes32()?;
    let to = dec.bytes32()?;
    let value = dec.u128()?;
    let data_field = dec.var_bytes()?;
    let gas_limit = dec.u64()?;
    let nonce = dec.u64()?;
    let signature = dec.var_bytes()?;
    let fee_payer = match dec.u8()? {
        0 => FeePayer::Sender,
        1 => FeePayer::GasTank(dec.bytes32()?),
        2 => FeePayer::Paymaster(dec.bytes32()?),
        _ => return Err("invalid fee_payer tag"),
    };
    let access_count = dec.u16()? as usize;
    let mut access_list = Vec::with_capacity(access_count);
    for _ in 0..access_count { access_list.push(decode_access_entry(&mut dec)?); }
    let deadline = if dec.u8()? == 1 { Some(dec.u64()?) } else { None };
    let chain_id = dec.u64()?;
    let tx_type = match dec.u8()? {
        0 => TransactionType::Standard,
        1 => TransactionType::Deploy,
        2 => TransactionType::Batch,
        _ => return Err("invalid tx_type tag"),
    };
    Ok(Transaction {
        from, to, value, data: data_field, gas_limit, nonce, signature,
        fee_payer, access_list, deadline, chain_id, tx_type,
    })
}

// ============================================================
// Block (header + body + signature)
// ============================================================

pub fn encode_block(block: &Block) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u8(tag::BLOCK);
    // Header
    let header_bytes = encode_block_header(&block.header);
    enc.var_bytes(&header_bytes);
    // Proposer signature
    enc.var_bytes(&block.proposer_signature);
    // Transactions
    enc.u32(block.body.transactions.len() as u32);
    for tx in &block.body.transactions {
        let tx_bytes = encode_transaction(tx);
        enc.var_bytes(&tx_bytes);
    }
    // Execution schedule: group count + tx indices per group
    enc.u16(block.body.execution_schedule.groups.len() as u16);
    for group in &block.body.execution_schedule.groups {
        enc.u16(group.tx_indices.len() as u16);
        for &idx in &group.tx_indices {
            enc.u32(idx as u32);
        }
    }
    enc.finish()
}

pub fn decode_block(data: &[u8]) -> Result<Block, &'static str> {
    let mut dec = Decoder::new(data);
    let msg_tag = dec.u8()?;
    if msg_tag != tag::BLOCK { return Err("not a block message"); }
    // Header
    let header_bytes = dec.var_bytes()?;
    let header = decode_block_header(&header_bytes)?;
    // Proposer signature
    let proposer_signature = dec.var_bytes()?;
    // Transactions
    let tx_count = dec.u32()? as usize;
    let mut transactions = Vec::with_capacity(tx_count);
    for _ in 0..tx_count {
        let tx_bytes = dec.var_bytes()?;
        transactions.push(decode_transaction(&tx_bytes)?);
    }
    // Execution schedule
    let group_count = dec.u16()? as usize;
    let mut groups = Vec::with_capacity(group_count);
    for _ in 0..group_count {
        let idx_count = dec.u16()? as usize;
        let mut tx_indices = Vec::with_capacity(idx_count);
        for _ in 0..idx_count { tx_indices.push(dec.u32()? as usize); }
        groups.push(pyde_tx::parallel::ExecutionGroup { tx_indices });
    }
    let total_txs = transactions.len();
    Ok(Block {
        header,
        body: BlockBody {
            transactions,
            execution_schedule: ExecutionSchedule { groups, total_txs },
        },
        proposer_signature,
    })
}

// ============================================================
// ConsensusMessage
// ============================================================

pub fn encode_consensus_message(msg: &ConsensusMessage) -> Vec<u8> {
    let mut enc = Encoder::new();
    match msg {
        ConsensusMessage::Proposal { header, proposer_signature } => {
            enc.u8(tag::CONSENSUS_PROPOSAL);
            let hdr = encode_block_header(header);
            enc.var_bytes(&hdr);
            enc.var_bytes(proposer_signature);
        }
        ConsensusMessage::Vote { slot, block_hash, voter_index, voter_address, signature } => {
            enc.u8(tag::CONSENSUS_VOTE);
            enc.u64(*slot);
            enc.bytes32(block_hash);
            enc.u8(*voter_index);
            enc.bytes32(voter_address);
            enc.var_bytes(signature);
        }
        ConsensusMessage::Timeout { slot, voter_index, voter_address, highest_qc, signature } => {
            enc.u8(tag::CONSENSUS_TIMEOUT);
            enc.u64(*slot);
            enc.u8(*voter_index);
            enc.bytes32(voter_address);
            encode_qc(&mut enc, highest_qc);
            enc.var_bytes(signature);
        }
        ConsensusMessage::NewView { slot, highest_qc, voter_address, signature } => {
            enc.u8(tag::CONSENSUS_NEW_VIEW);
            enc.u64(*slot);
            encode_qc(&mut enc, highest_qc);
            enc.bytes32(voter_address);
            enc.var_bytes(signature);
        }
    }
    enc.finish()
}

pub fn decode_consensus_message(data: &[u8]) -> Result<ConsensusMessage, &'static str> {
    let mut dec = Decoder::new(data);
    let msg_tag = dec.u8()?;
    match msg_tag {
        tag::CONSENSUS_PROPOSAL => {
            let hdr_bytes = dec.var_bytes()?;
            let header = decode_block_header(&hdr_bytes)?;
            let proposer_signature = dec.var_bytes()?;
            Ok(ConsensusMessage::Proposal { header, proposer_signature })
        }
        tag::CONSENSUS_VOTE => {
            Ok(ConsensusMessage::Vote {
                slot: dec.u64()?,
                block_hash: dec.bytes32()?,
                voter_index: dec.u8()?,
                voter_address: dec.bytes32()?,
                signature: dec.var_bytes()?,
            })
        }
        tag::CONSENSUS_TIMEOUT => {
            let slot = dec.u64()?;
            let voter_index = dec.u8()?;
            let voter_address = dec.bytes32()?;
            let highest_qc = decode_qc(&mut dec)?;
            let signature = dec.var_bytes()?;
            Ok(ConsensusMessage::Timeout { slot, voter_index, voter_address, highest_qc, signature })
        }
        tag::CONSENSUS_NEW_VIEW => {
            let slot = dec.u64()?;
            let highest_qc = decode_qc(&mut dec)?;
            let voter_address = dec.bytes32()?;
            let signature = dec.var_bytes()?;
            Ok(ConsensusMessage::NewView { slot, highest_qc, voter_address, signature })
        }
        _ => Err("unknown consensus message tag"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::{derive_eoa_address, ZERO_ADDRESS};

    fn dummy_qc(slot: u64) -> QuorumCert {
        QuorumCert {
            slot,
            block_hash: [slot as u8; 32],
            voter_bitmap: 0xFF,
            signatures: vec![vec![0xAA; 50], vec![0xBB; 60]],
        }
    }

    fn dummy_header(slot: u64) -> BlockHeader {
        BlockHeader {
            slot,
            epoch: 0,
            parent_hash: [0x11; 32],
            proposer: ZERO_ADDRESS,
            vrf_proof: vec![0xCC; 100],
            qc_previous: dummy_qc(slot.saturating_sub(1)),
            tx_root: [0x22; 32],
            state_root: [0x33; 32],
            timestamp: slot * 400,
        }
    }

    fn dummy_tx() -> Transaction {
        Transaction {
            from: derive_eoa_address(b"sender"),
            to: derive_eoa_address(b"recipient"),
            value: 1_000_000,
            data: vec![0xDD; 64],
            gas_limit: 100_000,
            nonce: 42,
            signature: vec![0xEE; 666],
            fee_payer: FeePayer::Sender,
            access_list: vec![AccessEntry {
                address: derive_eoa_address(b"contract"),
                reads: vec![[0x01; 32]],
                writes: vec![[0x02; 32], [0x03; 32]],
            }],
            deadline: Some(1000),
            chain_id: 1,
            tx_type: TransactionType::Batch,
        }
    }

    // ========== BlockHeader roundtrip ==========

    #[test]
    fn header_roundtrip() {
        let header = dummy_header(5);
        let bytes = encode_block_header(&header);
        let restored = decode_block_header(&bytes).unwrap();

        assert_eq!(restored.slot, 5);
        assert_eq!(restored.epoch, 0);
        assert_eq!(restored.parent_hash, [0x11; 32]);
        assert_eq!(restored.proposer, ZERO_ADDRESS);
        assert_eq!(restored.vrf_proof.len(), 100);
        assert_eq!(restored.qc_previous.slot, 4);
        assert_eq!(restored.qc_previous.signatures.len(), 2);
        assert_eq!(restored.tx_root, [0x22; 32]);
        assert_eq!(restored.state_root, [0x33; 32]);
        assert_eq!(restored.timestamp, 2000);
    }

    // ========== Transaction roundtrip ==========

    #[test]
    fn transaction_roundtrip() {
        let tx = dummy_tx();
        let bytes = encode_transaction(&tx);
        let restored = decode_transaction(&bytes).unwrap();

        assert_eq!(restored.from, tx.from);
        assert_eq!(restored.to, tx.to);
        assert_eq!(restored.value, 1_000_000);
        assert_eq!(restored.data.len(), 64);
        assert_eq!(restored.gas_limit, 100_000);
        assert_eq!(restored.nonce, 42);
        assert_eq!(restored.signature.len(), 666);
        assert!(matches!(restored.fee_payer, FeePayer::Sender));
        assert_eq!(restored.access_list.len(), 1);
        assert_eq!(restored.access_list[0].reads.len(), 1);
        assert_eq!(restored.access_list[0].writes.len(), 2);
        assert_eq!(restored.deadline, Some(1000));
        assert_eq!(restored.chain_id, 1);
        assert!(matches!(restored.tx_type, TransactionType::Batch));
    }

    // ========== Block roundtrip ==========

    #[test]
    fn block_roundtrip() {
        let block = Block {
            header: dummy_header(10),
            body: BlockBody {
                transactions: vec![dummy_tx(), dummy_tx()],
                execution_schedule: ExecutionSchedule {
                    groups: vec![
                        pyde_tx::parallel::ExecutionGroup { tx_indices: vec![0] },
                        pyde_tx::parallel::ExecutionGroup { tx_indices: vec![1] },
                    ],
                    total_txs: 2,
                },
            },
            proposer_signature: vec![0xFF; 700],
        };

        let bytes = encode_block(&block);
        let restored = decode_block(&bytes).unwrap();

        assert_eq!(restored.header.slot, 10);
        assert_eq!(restored.body.transactions.len(), 2);
        assert_eq!(restored.body.execution_schedule.groups.len(), 2);
        assert_eq!(restored.body.execution_schedule.groups[0].tx_indices, vec![0]);
        assert_eq!(restored.body.execution_schedule.groups[1].tx_indices, vec![1]);
        assert_eq!(restored.proposer_signature.len(), 700);
    }

    // ========== ConsensusMessage roundtrips ==========

    #[test]
    fn consensus_vote_roundtrip() {
        let msg = ConsensusMessage::Vote {
            slot: 5,
            block_hash: [0xAA; 32],
            voter_index: 3,
            voter_address: ZERO_ADDRESS,
            signature: vec![0xBB; 500],
        };

        let bytes = encode_consensus_message(&msg);
        let restored = decode_consensus_message(&bytes).unwrap();

        match restored {
            ConsensusMessage::Vote { slot, block_hash, voter_index, signature, .. } => {
                assert_eq!(slot, 5);
                assert_eq!(block_hash, [0xAA; 32]);
                assert_eq!(voter_index, 3);
                assert_eq!(signature.len(), 500);
            }
            _ => panic!("expected Vote"),
        }
    }

    #[test]
    fn consensus_proposal_roundtrip() {
        let msg = ConsensusMessage::Proposal {
            header: dummy_header(7),
            proposer_signature: vec![0xCC; 600],
        };

        let bytes = encode_consensus_message(&msg);
        let restored = decode_consensus_message(&bytes).unwrap();

        match restored {
            ConsensusMessage::Proposal { header, proposer_signature } => {
                assert_eq!(header.slot, 7);
                assert_eq!(proposer_signature.len(), 600);
            }
            _ => panic!("expected Proposal"),
        }
    }

    #[test]
    fn consensus_timeout_roundtrip() {
        let msg = ConsensusMessage::Timeout {
            slot: 12,
            voter_index: 5,
            voter_address: ZERO_ADDRESS,
            highest_qc: dummy_qc(11),
            signature: vec![0xDD; 400],
        };

        let bytes = encode_consensus_message(&msg);
        let restored = decode_consensus_message(&bytes).unwrap();

        match restored {
            ConsensusMessage::Timeout { slot, voter_index, highest_qc, .. } => {
                assert_eq!(slot, 12);
                assert_eq!(voter_index, 5);
                assert_eq!(highest_qc.slot, 11);
            }
            _ => panic!("expected Timeout"),
        }
    }

    #[test]
    fn decode_truncated_data_fails() {
        assert!(decode_block_header(&[0u8; 10]).is_err());
        assert!(decode_transaction(&[0u8; 5]).is_err());
        assert!(decode_consensus_message(&[]).is_err());
    }

    #[test]
    fn decode_invalid_tag_fails() {
        assert!(decode_consensus_message(&[0xFF]).is_err());
        assert!(decode_block(&[0xFF, 0, 0, 0, 0]).is_err());
    }
}
