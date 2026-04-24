//! Binary wire format for P2P message serialization.
//!
//! All messages use a simple length-prefixed binary encoding for speed.
//! Format: message_type(1) || payload_bytes
//!
//! This is NOT a general-purpose serialization library — it's purpose-built
//! for Pyde's P2P protocol and optimized for fast encode/decode.

use pyde_account::address::Address;
use pyde_consensus::block::{Block, BlockBody, BlockHeader, QuorumCert, COMMITTEE_SIZE};
use pyde_consensus::hotstuff::ConsensusMessage;
use pyde_consensus::slashing::DoubleSignEvidence;
use pyde_tx::multisig::MAX_SIGNERS;
use pyde_tx::parallel::ExecutionSchedule;
use pyde_tx::types::{AccessEntry, FeePayer, Transaction, TransactionType};

/// Umbrella cap on any length field decoded from an untrusted wire
/// message before `Vec::with_capacity` is called with it. Prevents a
/// peer from forcing huge preallocations by stuffing a giant u32/u16
/// count into a well-formed frame. 1M items is well above any
/// legitimate protocol structure; sites with a tighter semantic
/// bound (committee size, multisig signer set, etc.) pass that
/// instead via `u16_count` / `u32_count`.
const MAX_DECODE_ITEMS: usize = 1_000_000;

/// Message type tags for wire encoding.
pub mod tag {
    pub const BLOCK: u8 = 0x01;
    pub const TRANSACTION: u8 = 0x02;
    pub const CONSENSUS_PROPOSAL: u8 = 0x10;
    pub const CONSENSUS_VOTE: u8 = 0x11;
    pub const CONSENSUS_TIMEOUT: u8 = 0x12;
    pub const CONSENSUS_NEW_VIEW: u8 = 0x13;
    pub const CONSENSUS_FINALITY_VOTE: u8 = 0x14;
    pub const COMPACT_BLOCK: u8 = 0x03;
    pub const RANDOMNESS_SHARE: u8 = 0x15;
    pub const PSS_REFRESH: u8 = 0x16;
    /// Equivocation evidence broadcast on the consensus channel so any
    /// validator — not just the one that directly observed the double
    /// proposal — can include the offender in a `Slash` tx.
    pub const CONSENSUS_SLASH_EVIDENCE: u8 = 0x17;
    /// Cross-committee resharing contribution (task 034). Broadcast by
    /// outgoing committee members to the incoming committee at epoch
    /// boundary.
    pub const COMMITTEE_RESHARING: u8 = 0x18;
    /// Hard-finality checkpoint broadcast on the consensus topic (slice 4.3
    /// gap 1). Validators publish after `record_hard_finality`; receivers
    /// update their local WS anchor. Carries the full cert so validator
    /// receivers can cross-verify signatures against their own
    /// committee_keys. Non-validator receivers, absent access to the
    /// historical committee keys, trust the slice-3.4 consensus-channel
    /// filter (validator-only publisher).
    pub const CONSENSUS_FINALITY_CHECKPOINT: u8 = 0x19;
    pub const GET_BLOCK_TXS: u8 = 0x04;
    pub const BLOCK_TXS_RESPONSE: u8 = 0x05;
    /// Proposer-published bundle of encrypted_txs for a block (audit
    /// item 207 / 074b). Published on the Blocks channel immediately
    /// after the compact block. Integrity is anchored by the block
    /// header's `tx_root` commitment — no per-bundle signature.
    pub const ENCRYPTED_TX_BUNDLE: u8 = 0x06;
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

pub fn decode_finality_vote(
    data: &[u8],
) -> Result<pyde_consensus::finality::FinalityVote, &'static str> {
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

// ============================================================
// Epoch Randomness Share
// ============================================================

pub fn encode_randomness_share(
    epoch: u64,
    share: &pyde_consensus::epoch_randomness::RandomnessShare,
) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u8(tag::RANDOMNESS_SHARE);
    enc.u64(epoch);
    enc.u8(share.validator_index);
    enc.bytes32(&share.address);
    enc.var_bytes(share.vrf_output.as_bytes());
    enc.var_bytes(share.vrf_proof.as_bytes());
    enc.finish()
}

pub fn decode_randomness_share(
    data: &[u8],
) -> Result<(u64, pyde_consensus::epoch_randomness::RandomnessShare), &'static str> {
    let mut dec = Decoder::new(data);
    let t = dec.u8()?;
    if t != tag::RANDOMNESS_SHARE {
        return Err("not a randomness share");
    }
    let epoch = dec.u64()?;
    let validator_index = dec.u8()?;
    let address = dec.bytes32()?;
    let output_bytes = dec.var_bytes()?;
    let proof_bytes = dec.var_bytes()?;
    Ok((
        epoch,
        pyde_consensus::epoch_randomness::RandomnessShare {
            validator_index,
            address,
            vrf_output: pyde_crypto::vrf::VrfOutput::from_hash_bytes(&output_bytes),
            vrf_proof: pyde_crypto::vrf::VrfProof::from_bytes(&proof_bytes),
        },
    ))
}

// ============================================================
// PSS Refresh Contribution
// ============================================================

pub fn encode_pss_refresh(epoch: u64, contribution_bytes: &[u8]) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u8(tag::PSS_REFRESH);
    enc.u64(epoch);
    enc.var_bytes(contribution_bytes);
    enc.finish()
}

pub fn decode_pss_refresh(data: &[u8]) -> Result<(u64, Vec<u8>), &'static str> {
    let mut dec = Decoder::new(data);
    let t = dec.u8()?;
    if t != tag::PSS_REFRESH {
        return Err("not a PSS refresh");
    }
    let epoch = dec.u64()?;
    let contribution = dec.var_bytes()?;
    Ok((epoch, contribution))
}

// ============================================================
// Committee resharing contribution (task 034)
// ============================================================

/// Wire payload:
/// [tag:1][target_epoch:8][contribution_bytes: var_bytes]
/// The `contribution_bytes` blob is `ResharingContribution::to_bytes()`;
/// `target_epoch` is the epoch the new committee takes over.
pub fn encode_resharing(target_epoch: u64, contribution_bytes: &[u8]) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u8(tag::COMMITTEE_RESHARING);
    enc.u64(target_epoch);
    enc.var_bytes(contribution_bytes);
    enc.finish()
}

pub fn decode_resharing(data: &[u8]) -> Result<(u64, Vec<u8>), &'static str> {
    let mut dec = Decoder::new(data);
    let t = dec.u8()?;
    if t != tag::COMMITTEE_RESHARING {
        return Err("not a resharing");
    }
    let target_epoch = dec.u64()?;
    let contribution = dec.var_bytes()?;
    Ok((target_epoch, contribution))
}

// ============================================================
// FinalityCheckpoint (Phase 4 slice 4.3 — WS checkpoint persistence)
// ============================================================

/// Wire payload for a `FinalityCheckpoint`. Stored at a fixed key in
/// ConsensusStateStore; no tag byte since it's not gossipsubbed.
/// Layout:
/// `[slot:8][block_hash:32][state_root:32][cert_slot:8][cert_block_hash:32]
///  [cert_state_root:32][voter_bitmap:16][sig_count:4][[sig: var_bytes]*]`
pub fn encode_finality_checkpoint(cp: &pyde_consensus::finality::FinalityCheckpoint) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u64(cp.slot);
    enc.raw(&cp.block_hash);
    enc.raw(&cp.state_root);
    enc.u64(cp.cert.slot);
    enc.raw(&cp.cert.block_hash);
    enc.raw(&cp.cert.state_root);
    enc.raw(&cp.cert.voter_bitmap.to_le_bytes());
    enc.u32(cp.cert.signatures.len() as u32);
    for sig in &cp.cert.signatures {
        enc.var_bytes(sig);
    }
    enc.finish()
}

/// Wrap a checkpoint in a tagged gossip envelope.
/// Format: `[tag:CONSENSUS_FINALITY_CHECKPOINT:1][checkpoint_bytes]`
/// where `checkpoint_bytes` is the storage-format from
/// `encode_finality_checkpoint`.
pub fn encode_finality_checkpoint_msg(
    cp: &pyde_consensus::finality::FinalityCheckpoint,
) -> Vec<u8> {
    let body = encode_finality_checkpoint(cp);
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(tag::CONSENSUS_FINALITY_CHECKPOINT);
    out.extend_from_slice(&body);
    out
}

/// Decode the tagged gossip envelope. Rejects payloads with the wrong tag.
pub fn decode_finality_checkpoint_msg(
    data: &[u8],
) -> Result<pyde_consensus::finality::FinalityCheckpoint, &'static str> {
    if data.is_empty() || data[0] != tag::CONSENSUS_FINALITY_CHECKPOINT {
        return Err("not a finality checkpoint message");
    }
    decode_finality_checkpoint(&data[1..])
}

pub fn decode_finality_checkpoint(
    data: &[u8],
) -> Result<pyde_consensus::finality::FinalityCheckpoint, &'static str> {
    let mut dec = Decoder::new(data);
    let slot = dec.u64()?;
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(dec.raw(32)?);
    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(dec.raw(32)?);
    let cert_slot = dec.u64()?;
    let mut cert_block_hash = [0u8; 32];
    cert_block_hash.copy_from_slice(dec.raw(32)?);
    let mut cert_state_root = [0u8; 32];
    cert_state_root.copy_from_slice(dec.raw(32)?);
    let mut bitmap_bytes = [0u8; 16];
    bitmap_bytes.copy_from_slice(dec.raw(16)?);
    let voter_bitmap = u128::from_le_bytes(bitmap_bytes);
    let sig_count = dec.u32_count(COMMITTEE_SIZE)?;
    let mut signatures = Vec::with_capacity(sig_count);
    for _ in 0..sig_count {
        signatures.push(dec.var_bytes()?);
    }
    Ok(pyde_consensus::finality::FinalityCheckpoint {
        slot,
        block_hash,
        state_root,
        cert: pyde_consensus::finality::HardFinalityCert {
            slot: cert_slot,
            block_hash: cert_block_hash,
            state_root: cert_state_root,
            voter_bitmap,
            signatures,
        },
    })
}

// ============================================================
// ReshareState — persistent resharing runtime (task 034 crash safety)
// ============================================================

/// Persistable resharing state for `ValidatorEngine`.
///
/// Excludes the in-flight contribution pool; on restart we rely on
/// gossip rebroadcasts to refill it. That's a deliberate trade-off: the
/// persisted blob stays small (new_committee keys + scalars only,
/// tens of KB) so fsync latency on each state transition is bounded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReshareState {
    pub target_epoch: u64,
    pub new_index: u64,
    pub aggregation_trigger_slot: u64,
    pub aggregated: bool,
    pub broadcast_start_slot: u64,
    /// Stashed contribution bytes + target epoch if we're still in the
    /// outgoing-member rebroadcast window.
    pub pending_rebroadcast: Option<(u64, Vec<u8>)>,
    /// FALCON pubkeys of the incoming committee members, in index order.
    pub new_committee_keys: Vec<Vec<u8>>,
}

/// Wire format (no tag — this is stored in RocksDB under a fixed key,
/// not gossipsub'd):
/// `[target_epoch:8 LE][new_index:8 LE][trigger_slot:8 LE][aggregated:1]`
/// `[broadcast_start:8 LE][has_pending:1]`
/// `  if has_pending: [rebroadcast_target:8 LE][bytes: var_bytes]`
/// `[committee_len:4 LE][[key: var_bytes]*]`
pub fn encode_reshare_state(s: &ReshareState) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u64(s.target_epoch);
    enc.u64(s.new_index);
    enc.u64(s.aggregation_trigger_slot);
    enc.u8(s.aggregated as u8);
    enc.u64(s.broadcast_start_slot);
    match &s.pending_rebroadcast {
        Some((epoch, bytes)) => {
            enc.u8(1);
            enc.u64(*epoch);
            enc.var_bytes(bytes);
        }
        None => enc.u8(0),
    }
    enc.u32(s.new_committee_keys.len() as u32);
    for key in &s.new_committee_keys {
        enc.var_bytes(key);
    }
    enc.finish()
}

pub fn decode_reshare_state(data: &[u8]) -> Result<ReshareState, &'static str> {
    let mut dec = Decoder::new(data);
    let target_epoch = dec.u64()?;
    let new_index = dec.u64()?;
    let aggregation_trigger_slot = dec.u64()?;
    let aggregated = dec.u8()? != 0;
    let broadcast_start_slot = dec.u64()?;
    let pending_flag = dec.u8()?;
    let pending_rebroadcast = if pending_flag != 0 {
        let epoch = dec.u64()?;
        let bytes = dec.var_bytes()?;
        Some((epoch, bytes))
    } else {
        None
    };
    let count = dec.u32_count(COMMITTEE_SIZE)?;
    let mut new_committee_keys = Vec::with_capacity(count);
    for _ in 0..count {
        new_committee_keys.push(dec.var_bytes()?);
    }
    Ok(ReshareState {
        target_epoch,
        new_index,
        aggregation_trigger_slot,
        aggregated,
        broadcast_start_slot,
        pending_rebroadcast,
        new_committee_keys,
    })
}

// ============================================================
// Compact Block
// ============================================================

pub fn encode_compact_block(cb: &pyde_net::propagation::CompactBlock) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u8(tag::COMPACT_BLOCK);
    enc.var_bytes(&cb.header);
    enc.u64(cb.nonce);
    // Short IDs
    enc.u32(cb.short_tx_ids.len() as u32);
    for sid in &cb.short_tx_ids {
        enc.raw(sid);
    }
    // Prefilled txs
    enc.u16(cb.prefilled_txs.len() as u16);
    for (idx, bytes) in &cb.prefilled_txs {
        enc.u16(*idx);
        enc.var_bytes(bytes);
    }
    enc.finish()
}

pub fn decode_compact_block(
    data: &[u8],
) -> Result<pyde_net::propagation::CompactBlock, &'static str> {
    let mut dec = Decoder::new(data);
    let t = dec.u8()?;
    if t != tag::COMPACT_BLOCK {
        return Err("not a compact block");
    }
    let header = dec.var_bytes()?;
    let nonce = dec.u64()?;
    let sid_count = dec.u32_count(MAX_DECODE_ITEMS)?;
    let mut short_tx_ids = Vec::with_capacity(sid_count);
    for _ in 0..sid_count {
        let mut sid = [0u8; pyde_net::propagation::SHORT_ID_LEN];
        let raw = dec.raw(pyde_net::propagation::SHORT_ID_LEN)?;
        sid.copy_from_slice(raw);
        short_tx_ids.push(sid);
    }
    let prefill_count = dec.u16_count(MAX_DECODE_ITEMS)?;
    let mut prefilled_txs = Vec::with_capacity(prefill_count);
    for _ in 0..prefill_count {
        let idx = dec.u16()?;
        let bytes = dec.var_bytes()?;
        prefilled_txs.push((idx, bytes));
    }
    Ok(pyde_net::propagation::CompactBlock {
        header,
        short_tx_ids,
        prefilled_txs,
        nonce,
    })
}

/// Encode a request for missing block transactions.
pub fn encode_get_block_txs(
    block_hash: &[u8; 32],
    missing_sids: &[pyde_net::propagation::ShortId],
) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u8(tag::GET_BLOCK_TXS);
    enc.bytes32(block_hash);
    enc.u32(missing_sids.len() as u32);
    for sid in missing_sids {
        enc.raw(sid);
    }
    enc.finish()
}

/// Encode a response with the requested full transactions.
pub fn encode_block_txs_response(block_hash: &[u8; 32], txs: &[Vec<u8>]) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u8(tag::BLOCK_TXS_RESPONSE);
    enc.bytes32(block_hash);
    enc.u32(txs.len() as u32);
    for tx_bytes in txs {
        enc.var_bytes(tx_bytes);
    }
    enc.finish()
}

/// Encode an `EncryptedTxBundle` for gossip on the Blocks channel.
/// Proposer publishes immediately after `encode_compact_block`; the
/// bundle carries the encrypted_tx byte blobs that the compact block
/// omits. Integrity is anchored by the block header's `tx_root`
/// commitment, verified on receive. See audit item 207.
pub fn encode_encrypted_tx_bundle(bundle: &pyde_net::propagation::EncryptedTxBundle) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u8(tag::ENCRYPTED_TX_BUNDLE);
    enc.u64(bundle.slot);
    enc.bytes32(&bundle.block_hash);
    enc.u32(bundle.encrypted_txs.len() as u32);
    for tx_bytes in &bundle.encrypted_txs {
        enc.var_bytes(tx_bytes);
    }
    enc.finish()
}

/// Decode an `EncryptedTxBundle`. Rejects oversized item counts via
/// `u32_count(MAX_DECODE_ITEMS)`; per-entry byte length is indirectly
/// bounded by the channel's frame-size cap (4 MB for Blocks).
pub fn decode_encrypted_tx_bundle(
    data: &[u8],
) -> Result<pyde_net::propagation::EncryptedTxBundle, &'static str> {
    let mut dec = Decoder::new(data);
    let msg_tag = dec.u8()?;
    if msg_tag != tag::ENCRYPTED_TX_BUNDLE {
        return Err("not an encrypted-tx bundle message");
    }
    let slot = dec.u64()?;
    let block_hash = dec.bytes32()?;
    let count = dec.u32_count(MAX_DECODE_ITEMS)?;
    let mut encrypted_txs = Vec::with_capacity(count);
    for _ in 0..count {
        encrypted_txs.push(dec.var_bytes()?);
    }
    Ok(pyde_net::propagation::EncryptedTxBundle {
        slot,
        block_hash,
        encrypted_txs,
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
    if msg_tag != tag::DECRYPTION_SHARES {
        return Err("not a decryption shares message");
    }
    let slot = dec.u64()?;
    let member_index = dec.u8()?;
    let count = dec.u16_count(COMMITTEE_SIZE)?;
    let mut shares = Vec::with_capacity(count);
    for _ in 0..count {
        shares.push(dec.var_bytes()?);
    }
    Ok(DecryptionShareMsg {
        slot,
        member_index,
        shares,
    })
}

// ============================================================
// Encoding helpers
// ============================================================

struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(1024),
        }
    }

    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u128(&mut self, v: u128) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes32(&mut self, v: &[u8; 32]) {
        self.buf.extend_from_slice(v);
    }
    fn var_bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.buf.extend_from_slice(v);
    }
    fn raw(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn u8(&mut self) -> Result<u8, &'static str> {
        if self.remaining() < 1 {
            return Err("unexpected end of data");
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn u16(&mut self) -> Result<u16, &'static str> {
        if self.remaining() < 2 {
            return Err("unexpected end of data");
        }
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 2]);
        self.pos += 2;
        Ok(u16::from_le_bytes(buf))
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        if self.remaining() < 4 {
            return Err("unexpected end of data");
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_le_bytes(buf))
    }

    /// Read a `u16` length field and cap it at `max` before it drives
    /// any `Vec::with_capacity`. See `MAX_DECODE_ITEMS` for rationale.
    fn u16_count(&mut self, max: usize) -> Result<usize, &'static str> {
        let n = self.u16()? as usize;
        if n > max {
            return Err("decoded count exceeds max");
        }
        Ok(n)
    }

    /// Read a `u32` length field and cap it at `max` before it drives
    /// any `Vec::with_capacity`. See `MAX_DECODE_ITEMS` for rationale.
    fn u32_count(&mut self, max: usize) -> Result<usize, &'static str> {
        let n = self.u32()? as usize;
        if n > max {
            return Err("decoded count exceeds max");
        }
        Ok(n)
    }

    fn u64(&mut self) -> Result<u64, &'static str> {
        if self.remaining() < 8 {
            return Err("unexpected end of data");
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(buf))
    }

    fn u128(&mut self) -> Result<u128, &'static str> {
        if self.remaining() < 16 {
            return Err("unexpected end of data");
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 16]);
        self.pos += 16;
        Ok(u128::from_le_bytes(buf))
    }

    fn bytes32(&mut self) -> Result<[u8; 32], &'static str> {
        if self.remaining() < 32 {
            return Err("unexpected end of data");
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 32]);
        self.pos += 32;
        Ok(buf)
    }

    fn var_bytes(&mut self) -> Result<Vec<u8>, &'static str> {
        let len = self.u32()? as usize;
        if self.remaining() < len {
            return Err("unexpected end of data");
        }
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }

    fn raw(&mut self, len: usize) -> Result<&'a [u8], &'static str> {
        if self.remaining() < len {
            return Err("unexpected end of data");
        }
        let v = &self.data[self.pos..self.pos + len];
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
    let sig_count = dec.u16_count(MAX_SIGNERS as usize)?;
    let mut signatures = Vec::with_capacity(sig_count);
    for _ in 0..sig_count {
        signatures.push(dec.var_bytes()?);
    }
    Ok(QuorumCert {
        slot,
        block_hash,
        voter_bitmap,
        signatures,
    })
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
    for key in &entry.reads {
        enc.bytes32(key);
    }
    enc.u16(entry.writes.len() as u16);
    for key in &entry.writes {
        enc.bytes32(key);
    }
}

fn decode_access_entry(dec: &mut Decoder) -> Result<AccessEntry, &'static str> {
    let address = dec.bytes32()?;
    let read_count = dec.u16_count(MAX_DECODE_ITEMS)?;
    let mut reads = Vec::with_capacity(read_count);
    for _ in 0..read_count {
        reads.push(dec.bytes32()?);
    }
    let write_count = dec.u16_count(MAX_DECODE_ITEMS)?;
    let mut writes = Vec::with_capacity(write_count);
    for _ in 0..write_count {
        writes.push(dec.bytes32()?);
    }
    Ok(AccessEntry {
        address,
        reads,
        writes,
    })
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
    for entry in &tx.access_list {
        encode_access_entry(&mut enc, entry);
    }
    // deadline
    enc.u8(tx.deadline.is_some() as u8);
    if let Some(d) = tx.deadline {
        enc.u64(d);
    }
    enc.u64(tx.chain_id);
    // tx_type
    enc.u8(tx.tx_type as u8);
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
    let access_count = dec.u16_count(MAX_DECODE_ITEMS)?;
    let mut access_list = Vec::with_capacity(access_count);
    for _ in 0..access_count {
        access_list.push(decode_access_entry(&mut dec)?);
    }
    let deadline = if dec.u8()? == 1 {
        Some(dec.u64()?)
    } else {
        None
    };
    let chain_id = dec.u64()?;
    let tx_type = TransactionType::from_u8(dec.u8()?).ok_or("invalid tx_type tag")?;
    Ok(Transaction {
        from,
        to,
        value,
        data: data_field,
        gas_limit,
        nonce,
        signature,
        fee_payer,
        access_list,
        deadline,
        chain_id,
        tx_type,
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
    // Encrypted transactions (threshold-encrypted blobs)
    enc.u32(block.body.encrypted_txs.len() as u32);
    for etx in &block.body.encrypted_txs {
        enc.var_bytes(etx);
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
    if msg_tag != tag::BLOCK {
        return Err("not a block message");
    }
    // Header
    let header_bytes = dec.var_bytes()?;
    let header = decode_block_header(&header_bytes)?;
    // Proposer signature
    let proposer_signature = dec.var_bytes()?;
    // Transactions
    let tx_count = dec.u32_count(MAX_DECODE_ITEMS)?;
    let mut transactions = Vec::with_capacity(tx_count);
    for _ in 0..tx_count {
        let tx_bytes = dec.var_bytes()?;
        transactions.push(decode_transaction(&tx_bytes)?);
    }
    // Encrypted transactions
    let enc_count = if dec.remaining() >= 4 {
        dec.u32_count(MAX_DECODE_ITEMS)?
    } else {
        0
    };
    let mut encrypted_txs = Vec::with_capacity(enc_count);
    for _ in 0..enc_count {
        encrypted_txs.push(dec.var_bytes()?);
    }
    // Execution schedule
    let group_count = if dec.remaining() >= 2 {
        dec.u16_count(MAX_DECODE_ITEMS)?
    } else {
        0
    };
    let mut groups = Vec::with_capacity(group_count);
    for _ in 0..group_count {
        let idx_count = dec.u16_count(MAX_DECODE_ITEMS)?;
        let mut tx_indices = Vec::with_capacity(idx_count);
        for _ in 0..idx_count {
            tx_indices.push(dec.u32()? as usize);
        }
        groups.push(pyde_tx::parallel::ExecutionGroup { tx_indices });
    }
    let total_txs = transactions.len();
    Ok(Block {
        header,
        body: BlockBody {
            transactions,
            encrypted_txs,
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
        ConsensusMessage::Proposal {
            header,
            proposer_signature,
        } => {
            enc.u8(tag::CONSENSUS_PROPOSAL);
            let hdr = encode_block_header(header);
            enc.var_bytes(&hdr);
            enc.var_bytes(proposer_signature);
        }
        ConsensusMessage::Vote {
            slot,
            block_hash,
            voter_index,
            voter_address,
            signature,
        } => {
            enc.u8(tag::CONSENSUS_VOTE);
            enc.u64(*slot);
            enc.bytes32(block_hash);
            enc.u8(*voter_index);
            enc.bytes32(voter_address);
            enc.var_bytes(signature);
        }
        ConsensusMessage::Timeout {
            slot,
            voter_index,
            voter_address,
            highest_qc,
            signature,
        } => {
            enc.u8(tag::CONSENSUS_TIMEOUT);
            enc.u64(*slot);
            enc.u8(*voter_index);
            enc.bytes32(voter_address);
            encode_qc(&mut enc, highest_qc);
            enc.var_bytes(signature);
        }
        ConsensusMessage::NewView {
            slot,
            highest_qc,
            voter_address,
            signature,
        } => {
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
            Ok(ConsensusMessage::Proposal {
                header,
                proposer_signature,
            })
        }
        tag::CONSENSUS_VOTE => Ok(ConsensusMessage::Vote {
            slot: dec.u64()?,
            block_hash: dec.bytes32()?,
            voter_index: dec.u8()?,
            voter_address: dec.bytes32()?,
            signature: dec.var_bytes()?,
        }),
        tag::CONSENSUS_TIMEOUT => {
            let slot = dec.u64()?;
            let voter_index = dec.u8()?;
            let voter_address = dec.bytes32()?;
            let highest_qc = decode_qc(&mut dec)?;
            let signature = dec.var_bytes()?;
            Ok(ConsensusMessage::Timeout {
                slot,
                voter_index,
                voter_address,
                highest_qc,
                signature,
            })
        }
        tag::CONSENSUS_NEW_VIEW => {
            let slot = dec.u64()?;
            let highest_qc = decode_qc(&mut dec)?;
            let voter_address = dec.bytes32()?;
            let signature = dec.var_bytes()?;
            Ok(ConsensusMessage::NewView {
                slot,
                highest_qc,
                voter_address,
                signature,
            })
        }
        _ => Err("unknown consensus message tag"),
    }
}

// ============================================================
// ConsensusState (for crash-safe persistence)
// ============================================================

const CONSENSUS_STATE_VERSION: u8 = 1;

pub fn encode_consensus_state(state: &pyde_consensus::hotstuff::ConsensusState) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u8(CONSENSUS_STATE_VERSION);
    enc.u64(state.current_slot);
    enc.u64(state.current_epoch);
    encode_qc(&mut enc, &state.highest_qc);
    enc.u64(state.last_voted_slot);
    enc.bytes32(&state.last_committed_hash);
    enc.u64(state.last_committed_slot);
    enc.u16(state.pending_votes.len() as u16);
    for msg in &state.pending_votes {
        enc.var_bytes(&encode_consensus_message(msg));
    }
    enc.u16(state.pending_timeouts.len() as u16);
    for msg in &state.pending_timeouts {
        enc.var_bytes(&encode_consensus_message(msg));
    }
    enc.finish()
}

pub fn decode_consensus_state(
    data: &[u8],
) -> Result<pyde_consensus::hotstuff::ConsensusState, &'static str> {
    let mut dec = Decoder::new(data);
    let version = dec.u8()?;
    if version != CONSENSUS_STATE_VERSION {
        return Err("unsupported consensus state version");
    }
    let current_slot = dec.u64()?;
    let current_epoch = dec.u64()?;
    let highest_qc = decode_qc(&mut dec)?;
    let last_voted_slot = dec.u64()?;
    let last_committed_hash = dec.bytes32()?;
    let last_committed_slot = dec.u64()?;

    let votes_count = dec.u16_count(MAX_DECODE_ITEMS)?;
    let mut pending_votes = Vec::with_capacity(votes_count);
    for _ in 0..votes_count {
        let msg_bytes = dec.var_bytes()?;
        pending_votes.push(decode_consensus_message(&msg_bytes)?);
    }

    let timeouts_count = dec.u16_count(MAX_DECODE_ITEMS)?;
    let mut pending_timeouts = Vec::with_capacity(timeouts_count);
    for _ in 0..timeouts_count {
        let msg_bytes = dec.var_bytes()?;
        pending_timeouts.push(decode_consensus_message(&msg_bytes)?);
    }

    Ok(pyde_consensus::hotstuff::ConsensusState {
        current_slot,
        current_epoch,
        highest_qc,
        last_voted_slot,
        last_committed_hash,
        last_committed_slot,
        pending_votes,
        pending_timeouts,
    })
}

// ============================================================
// DoubleSignEvidence (payload for TransactionType::Slash)
// ============================================================

/// Schema version tag for the Slash-tx payload. Bumping this is a
/// protocol change: old nodes would reject new evidence and vice versa.
pub(crate) const EVIDENCE_VERSION: u8 = 1;

/// Layout:
///   u8 version = 1
///   u64 slot
///   [u8; 32] block_hash_1
///   var_bytes signature_1
///   [u8; 32] block_hash_2
///   var_bytes signature_2
///   [u8; 32] signer
///   [u8; 32] submitter
///
/// Carrying just the hashes (not full `BlockHeader`s) is enough because
/// each signature is verified over `proposer_sign_message(slot, hash)`
/// — the slot binding lives inside the signed message, not the wire
/// format, so a third-party verifier needs nothing besides the hashes.
pub fn encode_double_sign_evidence(evidence: &DoubleSignEvidence) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u8(EVIDENCE_VERSION);
    enc.u64(evidence.slot);
    enc.bytes32(&evidence.block_hash_1);
    enc.var_bytes(&evidence.signature_1);
    enc.bytes32(&evidence.block_hash_2);
    enc.var_bytes(&evidence.signature_2);
    enc.bytes32(&evidence.signer);
    enc.bytes32(&evidence.submitter);
    enc.finish()
}

/// Wrap encoded evidence in a gossip envelope: `tag || evidence_bytes`.
/// The tag lets the consensus channel handler dispatch this message
/// alongside proposals, votes, timeouts, etc. without collision.
pub fn encode_slash_evidence_msg(evidence: &DoubleSignEvidence) -> Vec<u8> {
    let payload = encode_double_sign_evidence(evidence);
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(tag::CONSENSUS_SLASH_EVIDENCE);
    out.extend_from_slice(&payload);
    out
}

/// Unwrap a gossip envelope produced by `encode_slash_evidence_msg`.
/// Returns the decoded `DoubleSignEvidence`, or an error if the tag is
/// wrong or the payload is malformed.
pub fn decode_slash_evidence_msg(data: &[u8]) -> Result<DoubleSignEvidence, &'static str> {
    if data.is_empty() {
        return Err("empty slash-evidence gossip message");
    }
    if data[0] != tag::CONSENSUS_SLASH_EVIDENCE {
        return Err("not a slash-evidence gossip message");
    }
    decode_double_sign_evidence(&data[1..])
}

pub fn decode_double_sign_evidence(data: &[u8]) -> Result<DoubleSignEvidence, &'static str> {
    let mut dec = Decoder::new(data);
    let version = dec.u8()?;
    if version != EVIDENCE_VERSION {
        return Err("unsupported double-sign evidence version");
    }
    let slot = dec.u64()?;
    let block_hash_1 = dec.bytes32()?;
    let signature_1 = dec.var_bytes()?;
    let block_hash_2 = dec.bytes32()?;
    let signature_2 = dec.var_bytes()?;
    let signer = dec.bytes32()?;
    let submitter = dec.bytes32()?;
    Ok(DoubleSignEvidence {
        slot,
        block_hash_1,
        signature_1,
        block_hash_2,
        signature_2,
        signer,
        submitter,
    })
}

// ============================================================
// EvidenceState — ingest queues persisted as a single blob
// ============================================================

/// Full evidence state of a running `ValidatorEngine`:
/// what's queued for block inclusion, what's queued for broadcast,
/// and what we've already ingested. Persisted together as one
/// atomic blob so a crash mid-ingest cannot leave the three in
/// mutually inconsistent states.
#[derive(Clone, Debug, Default)]
pub struct EvidenceState {
    pub pending: Vec<DoubleSignEvidence>,
    pub broadcast: Vec<DoubleSignEvidence>,
    /// (slot, signer) pairs already seen, for dedup.
    pub seen: Vec<(u64, Address)>,
}

const EVIDENCE_STATE_VERSION: u8 = 1;

pub fn encode_evidence_state(state: &EvidenceState) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u8(EVIDENCE_STATE_VERSION);
    enc.u16(state.pending.len() as u16);
    for ev in &state.pending {
        enc.var_bytes(&encode_double_sign_evidence(ev));
    }
    enc.u16(state.broadcast.len() as u16);
    for ev in &state.broadcast {
        enc.var_bytes(&encode_double_sign_evidence(ev));
    }
    enc.u32(state.seen.len() as u32);
    for (slot, addr) in &state.seen {
        enc.u64(*slot);
        enc.bytes32(addr);
    }
    enc.finish()
}

pub fn decode_evidence_state(data: &[u8]) -> Result<EvidenceState, &'static str> {
    let mut dec = Decoder::new(data);
    let version = dec.u8()?;
    if version != EVIDENCE_STATE_VERSION {
        return Err("unsupported evidence state version");
    }
    let pending_count = dec.u16_count(MAX_DECODE_ITEMS)?;
    let mut pending = Vec::with_capacity(pending_count);
    for _ in 0..pending_count {
        pending.push(decode_double_sign_evidence(&dec.var_bytes()?)?);
    }
    let broadcast_count = dec.u16_count(MAX_DECODE_ITEMS)?;
    let mut broadcast = Vec::with_capacity(broadcast_count);
    for _ in 0..broadcast_count {
        broadcast.push(decode_double_sign_evidence(&dec.var_bytes()?)?);
    }
    let seen_count = dec.u32_count(MAX_DECODE_ITEMS)?;
    let mut seen = Vec::with_capacity(seen_count);
    for _ in 0..seen_count {
        let slot = dec.u64()?;
        let addr = dec.bytes32()?;
        seen.push((slot, addr));
    }
    Ok(EvidenceState {
        pending,
        broadcast,
        seen,
    })
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

    #[test]
    fn tx_type_roundtrip_all_variants() {
        // The prior decode hand-coded only Standard/Deploy/Batch and rejected
        // StakeDeposit/StakeWithdraw; this guards against that class of regression.
        let variants = [
            TransactionType::Standard,
            TransactionType::Deploy,
            TransactionType::Batch,
            TransactionType::StakeDeposit,
            TransactionType::StakeWithdraw,
            TransactionType::Slash,
        ];
        for ty in variants {
            let mut tx = dummy_tx();
            tx.tx_type = ty;
            let bytes = encode_transaction(&tx);
            let restored = decode_transaction(&bytes).unwrap();
            assert_eq!(
                restored.tx_type, ty,
                "tx_type roundtrip failed for {:?}",
                ty
            );
        }
    }

    // ========== Block roundtrip ==========

    #[test]
    fn block_roundtrip() {
        let block = Block {
            header: dummy_header(10),
            body: BlockBody {
                transactions: vec![dummy_tx(), dummy_tx()],
                encrypted_txs: vec![],
                execution_schedule: ExecutionSchedule {
                    groups: vec![
                        pyde_tx::parallel::ExecutionGroup {
                            tx_indices: vec![0],
                        },
                        pyde_tx::parallel::ExecutionGroup {
                            tx_indices: vec![1],
                        },
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
        assert_eq!(
            restored.body.execution_schedule.groups[0].tx_indices,
            vec![0]
        );
        assert_eq!(
            restored.body.execution_schedule.groups[1].tx_indices,
            vec![1]
        );
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
            ConsensusMessage::Vote {
                slot,
                block_hash,
                voter_index,
                signature,
                ..
            } => {
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
            ConsensusMessage::Proposal {
                header,
                proposer_signature,
            } => {
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
            ConsensusMessage::Timeout {
                slot,
                voter_index,
                highest_qc,
                ..
            } => {
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

    // ========== ConsensusState roundtrip ==========

    #[test]
    fn consensus_state_empty_roundtrip() {
        let state = pyde_consensus::hotstuff::ConsensusState::new();
        let bytes = encode_consensus_state(&state);
        let restored = decode_consensus_state(&bytes).unwrap();

        assert_eq!(restored.current_slot, 0);
        assert_eq!(restored.current_epoch, 0);
        assert_eq!(restored.last_voted_slot, 0);
        assert_eq!(restored.last_committed_slot, 0);
        assert_eq!(restored.last_committed_hash, [0u8; 32]);
        assert_eq!(restored.highest_qc.slot, 0);
        assert!(restored.pending_votes.is_empty());
        assert!(restored.pending_timeouts.is_empty());
    }

    #[test]
    fn consensus_state_populated_roundtrip() {
        let state = pyde_consensus::hotstuff::ConsensusState {
            current_slot: 42,
            current_epoch: 3,
            highest_qc: dummy_qc(41),
            last_voted_slot: 42,
            last_committed_hash: [0x77; 32],
            last_committed_slot: 40,
            pending_votes: vec![
                ConsensusMessage::Vote {
                    slot: 42,
                    block_hash: [0xAA; 32],
                    voter_index: 7,
                    voter_address: ZERO_ADDRESS,
                    signature: vec![0xBB; 600],
                },
                ConsensusMessage::Vote {
                    slot: 42,
                    block_hash: [0xAA; 32],
                    voter_index: 9,
                    voter_address: ZERO_ADDRESS,
                    signature: vec![0xCC; 600],
                },
            ],
            pending_timeouts: vec![ConsensusMessage::Timeout {
                slot: 42,
                voter_index: 3,
                voter_address: ZERO_ADDRESS,
                highest_qc: dummy_qc(40),
                signature: vec![0xDD; 600],
            }],
        };

        let bytes = encode_consensus_state(&state);
        let restored = decode_consensus_state(&bytes).unwrap();

        assert_eq!(restored.current_slot, 42);
        assert_eq!(restored.current_epoch, 3);
        assert_eq!(restored.highest_qc.slot, 41);
        assert_eq!(restored.last_voted_slot, 42);
        assert_eq!(restored.last_committed_hash, [0x77; 32]);
        assert_eq!(restored.last_committed_slot, 40);
        assert_eq!(restored.pending_votes.len(), 2);
        assert_eq!(restored.pending_timeouts.len(), 1);

        match &restored.pending_votes[1] {
            ConsensusMessage::Vote { voter_index, .. } => assert_eq!(*voter_index, 9),
            _ => panic!("expected Vote"),
        }
    }

    #[test]
    fn consensus_state_wrong_version_fails() {
        // Build bytes with version 0xFF
        let mut bytes = encode_consensus_state(&pyde_consensus::hotstuff::ConsensusState::new());
        bytes[0] = 0xFF;
        assert!(decode_consensus_state(&bytes).is_err());
    }

    #[test]
    fn consensus_state_truncated_fails() {
        assert!(decode_consensus_state(&[]).is_err());
        assert!(decode_consensus_state(&[1]).is_err());
    }

    // ========== DoubleSignEvidence roundtrip ==========

    fn dummy_evidence(slot: u64) -> DoubleSignEvidence {
        DoubleSignEvidence {
            slot,
            block_hash_1: [0x01; 32],
            signature_1: vec![0xAA; 600],
            block_hash_2: [0x02; 32],
            signature_2: vec![0xBB; 600],
            signer: [0x11; 32],
            submitter: [0x22; 32],
        }
    }

    #[test]
    fn double_sign_evidence_roundtrip() {
        let evidence = dummy_evidence(42);
        let bytes = encode_double_sign_evidence(&evidence);
        let restored = decode_double_sign_evidence(&bytes).unwrap();

        assert_eq!(restored.slot, 42);
        assert_eq!(restored.block_hash_1, [0x01; 32]);
        assert_eq!(restored.block_hash_2, [0x02; 32]);
        assert_eq!(restored.signature_1, vec![0xAA; 600]);
        assert_eq!(restored.signature_2, vec![0xBB; 600]);
        assert_eq!(restored.signer, [0x11; 32]);
        assert_eq!(restored.submitter, [0x22; 32]);
        // Sanity: distinct hashes or it isn't evidence of equivocation.
        assert_ne!(restored.block_hash_1, restored.block_hash_2);
    }

    #[test]
    fn double_sign_evidence_wrong_version_fails() {
        let mut bytes = encode_double_sign_evidence(&dummy_evidence(1));
        bytes[0] = 0xFF;
        assert!(decode_double_sign_evidence(&bytes).is_err());
    }

    #[test]
    fn double_sign_evidence_truncated_fails() {
        assert!(decode_double_sign_evidence(&[]).is_err());
        assert!(decode_double_sign_evidence(&[EVIDENCE_VERSION]).is_err());
        // Truncate mid-encoding
        let bytes = encode_double_sign_evidence(&dummy_evidence(5));
        assert!(decode_double_sign_evidence(&bytes[..bytes.len() - 10]).is_err());
    }

    #[test]
    fn slash_evidence_gossip_envelope_roundtrip() {
        let evidence = dummy_evidence(99);
        let bytes = encode_slash_evidence_msg(&evidence);
        assert_eq!(bytes[0], tag::CONSENSUS_SLASH_EVIDENCE);
        let restored = decode_slash_evidence_msg(&bytes).unwrap();
        assert_eq!(restored.slot, 99);
        assert_eq!(restored.block_hash_1, evidence.block_hash_1);
    }

    #[test]
    fn slash_evidence_wrong_tag_fails() {
        let mut bytes = encode_slash_evidence_msg(&dummy_evidence(1));
        bytes[0] = tag::CONSENSUS_VOTE; // wrong tag
        assert!(decode_slash_evidence_msg(&bytes).is_err());
    }

    #[test]
    fn slash_evidence_empty_fails() {
        assert!(decode_slash_evidence_msg(&[]).is_err());
    }

    // ========== EvidenceState roundtrip ==========

    #[test]
    fn evidence_state_empty_roundtrip() {
        let state = EvidenceState::default();
        let bytes = encode_evidence_state(&state);
        let restored = decode_evidence_state(&bytes).unwrap();
        assert!(restored.pending.is_empty());
        assert!(restored.broadcast.is_empty());
        assert!(restored.seen.is_empty());
    }

    #[test]
    fn evidence_state_populated_roundtrip() {
        let state = EvidenceState {
            pending: vec![dummy_evidence(10), dummy_evidence(11)],
            broadcast: vec![dummy_evidence(12)],
            seen: vec![(10, [0x11; 32]), (11, [0x22; 32]), (12, [0x33; 32])],
        };
        let bytes = encode_evidence_state(&state);
        let restored = decode_evidence_state(&bytes).unwrap();
        assert_eq!(restored.pending.len(), 2);
        assert_eq!(restored.pending[0].slot, 10);
        assert_eq!(restored.pending[1].slot, 11);
        assert_eq!(restored.broadcast.len(), 1);
        assert_eq!(restored.broadcast[0].slot, 12);
        assert_eq!(restored.seen.len(), 3);
        assert_eq!(restored.seen[1], (11, [0x22; 32]));
    }

    #[test]
    fn evidence_state_wrong_version_fails() {
        let mut bytes = encode_evidence_state(&EvidenceState::default());
        bytes[0] = 0xFF;
        assert!(decode_evidence_state(&bytes).is_err());
    }

    // ========== Decoder count-bound guards ==========

    #[test]
    fn decoder_u32_count_rejects_over_max() {
        let bytes = (MAX_DECODE_ITEMS as u32 + 1).to_le_bytes();
        let mut dec = Decoder::new(&bytes);
        assert_eq!(
            dec.u32_count(MAX_DECODE_ITEMS),
            Err("decoded count exceeds max")
        );
    }

    #[test]
    fn decoder_u16_count_rejects_over_max() {
        let bytes = (COMMITTEE_SIZE as u16 + 1).to_le_bytes();
        let mut dec = Decoder::new(&bytes);
        assert_eq!(
            dec.u16_count(COMMITTEE_SIZE),
            Err("decoded count exceeds max")
        );
    }

    #[test]
    fn decoder_count_at_max_is_accepted() {
        // Boundary: exactly max passes, one-over fails (exercised above).
        let bytes = (MAX_DECODE_ITEMS as u32).to_le_bytes();
        let mut dec = Decoder::new(&bytes);
        assert_eq!(dec.u32_count(MAX_DECODE_ITEMS), Ok(MAX_DECODE_ITEMS));
    }

    #[test]
    fn compact_block_rejects_huge_short_id_count() {
        // Construct a compact-block frame by hand with sid_count set to
        // MAX_DECODE_ITEMS + 1, proving the cap is wired through.
        let mut bytes = vec![tag::COMPACT_BLOCK];
        bytes.extend_from_slice(&0u32.to_le_bytes()); // var_bytes(header) len = 0
        bytes.extend_from_slice(&0u64.to_le_bytes()); // nonce
        bytes.extend_from_slice(&((MAX_DECODE_ITEMS as u32) + 1).to_le_bytes());
        let result = decode_compact_block(&bytes);
        assert_eq!(result.err(), Some("decoded count exceeds max"));
    }

    #[test]
    fn decryption_shares_rejects_over_committee() {
        // DecryptionShareMsg caps `shares` at COMMITTEE_SIZE. Hand-
        // construct a frame with count = COMMITTEE_SIZE + 1.
        let mut bytes = vec![tag::DECRYPTION_SHARES];
        bytes.extend_from_slice(&0u64.to_le_bytes()); // slot
        bytes.push(0u8); // member_index
        bytes.extend_from_slice(&((COMMITTEE_SIZE as u16) + 1).to_le_bytes());
        let result = decode_decryption_shares(&bytes);
        assert_eq!(result.err(), Some("decoded count exceeds max"));
    }

    // ========== EncryptedTxBundle (audit item 207) ==========

    #[test]
    fn encrypted_bundle_empty_roundtrip() {
        let bundle = pyde_net::propagation::EncryptedTxBundle {
            slot: 0,
            block_hash: [0u8; 32],
            encrypted_txs: vec![],
        };
        let bytes = encode_encrypted_tx_bundle(&bundle);
        let restored = decode_encrypted_tx_bundle(&bytes).unwrap();
        assert_eq!(restored, bundle);
    }

    #[test]
    fn encrypted_bundle_populated_roundtrip() {
        let bundle = pyde_net::propagation::EncryptedTxBundle {
            slot: 42,
            block_hash: [0xABu8; 32],
            encrypted_txs: vec![
                vec![0x01, 0x02, 0x03],
                vec![0xFF; 64],
                vec![], // empty entry is legal — var_bytes handles it
                vec![0xDE; 1024],
            ],
        };
        let bytes = encode_encrypted_tx_bundle(&bundle);
        let restored = decode_encrypted_tx_bundle(&bytes).unwrap();
        assert_eq!(restored, bundle);
    }

    #[test]
    fn encrypted_bundle_wrong_tag_fails() {
        let bundle = pyde_net::propagation::EncryptedTxBundle {
            slot: 1,
            block_hash: [0u8; 32],
            encrypted_txs: vec![],
        };
        let mut bytes = encode_encrypted_tx_bundle(&bundle);
        bytes[0] = tag::COMPACT_BLOCK;
        assert_eq!(
            decode_encrypted_tx_bundle(&bytes).err(),
            Some("not an encrypted-tx bundle message")
        );
    }

    #[test]
    fn encrypted_bundle_empty_frame_fails() {
        assert!(decode_encrypted_tx_bundle(&[]).is_err());
    }

    #[test]
    fn encrypted_bundle_rejects_huge_count() {
        // Hand-construct a frame whose declared count exceeds
        // MAX_DECODE_ITEMS; decode must reject before allocating.
        let mut bytes = vec![tag::ENCRYPTED_TX_BUNDLE];
        bytes.extend_from_slice(&42u64.to_le_bytes()); // slot
        bytes.extend_from_slice(&[0u8; 32]); // block_hash
        bytes.extend_from_slice(&((MAX_DECODE_ITEMS as u32) + 1).to_le_bytes());
        assert_eq!(
            decode_encrypted_tx_bundle(&bytes).err(),
            Some("decoded count exceeds max")
        );
    }
}
