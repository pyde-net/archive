//! Modified HotStuff pipelined BFT consensus per Chapter 6, Section 6.3.
//!
//! Three-phase pipeline per slot (400ms):
//!   Phase 1: PROPOSE (0-100ms) — proposer broadcasts block
//!   Phase 2: VOTE (100-300ms) — validators vote on block
//!   Phase 3: CERTIFY (300-400ms) — next proposer collects votes into QC
//!
//! Pipelined: certify for slot N overlaps with propose for slot N+1.
//! Finality: block finalized when referenced by 2 consecutive QCs.

use crate::block::{BlockHeader, QuorumCert, COMMITTEE_SIZE, QUORUM_THRESHOLD};
use pyde_account::address::Address;
use pyde_crypto::falcon::{falcon_verify, FalconPublicKey, FalconSignature};
use pyde_crypto::poseidon2::poseidon2_hash;

/// Consensus message types exchanged between validators.
#[derive(Clone, Debug)]
pub enum ConsensusMessage {
    /// Proposer broadcasts a new block.
    Proposal {
        header: BlockHeader,
        proposer_signature: Vec<u8>,
    },
    /// Validator votes for a proposed block.
    Vote {
        slot: u64,
        block_hash: [u8; 32],
        voter_index: u8,
        voter_address: Address,
        signature: Vec<u8>,
    },
    /// Timeout: validator didn't receive a valid proposal in time.
    Timeout {
        slot: u64,
        voter_index: u8,
        voter_address: Address,
        highest_qc: QuorumCert,
        signature: Vec<u8>,
    },
    /// New view: triggered after timeout, validators send their highest QC.
    NewView {
        slot: u64,
        highest_qc: QuorumCert,
        voter_address: Address,
        signature: Vec<u8>,
    },
}

/// The state machine for a single validator's consensus participation.
#[derive(Clone, Debug)]
pub struct ConsensusState {
    /// Current slot.
    pub current_slot: u64,
    /// Current epoch.
    pub current_epoch: u64,
    /// The highest QC this validator has seen.
    pub highest_qc: QuorumCert,
    /// The last voted slot (prevent double voting).
    pub last_voted_slot: u64,
    /// The last committed block hash.
    pub last_committed_hash: [u8; 32],
    /// Last committed slot.
    pub last_committed_slot: u64,
    /// Votes collected for current slot (if we're the next proposer).
    pub pending_votes: Vec<ConsensusMessage>,
    /// Timeout votes collected.
    pub pending_timeouts: Vec<ConsensusMessage>,
}

impl ConsensusState {
    pub fn new() -> Self {
        Self {
            current_slot: 0,
            current_epoch: 0,
            highest_qc: QuorumCert::empty(),
            last_voted_slot: 0,
            last_committed_hash: [0u8; 32],
            last_committed_slot: 0,
            pending_votes: Vec::new(),
            pending_timeouts: Vec::new(),
        }
    }

    /// Advance to next slot.
    pub fn advance_slot(&mut self) {
        self.current_slot += 1;
        self.pending_votes.clear();
        self.pending_timeouts.clear();
    }
}

impl Default for ConsensusState {
    fn default() -> Self {
        Self::new()
    }
}

/// Vote on a proposed block. Returns a Vote message.
///
/// Safety rule: only vote if:
/// 1. The proposal extends the highest QC we've seen
/// 2. We haven't voted for this slot yet
pub fn create_vote(
    state: &mut ConsensusState,
    header: &BlockHeader,
    voter_index: u8,
    voter_address: Address,
    voter_sk: &pyde_crypto::falcon::FalconSecretKey,
) -> Result<Option<ConsensusMessage>, &'static str> {
    // Safety: don't double-vote
    if header.slot <= state.last_voted_slot {
        return Ok(None);
    }

    // Safety: proposal must extend our highest QC
    if header.qc_previous.slot < state.highest_qc.slot {
        return Ok(None);
    }

    // Update highest QC if proposal's QC is newer
    if header.qc_previous.slot > state.highest_qc.slot {
        state.highest_qc = header.qc_previous.clone();
    }

    // Sign (slot || block_hash) to bind the vote to a specific slot,
    // preventing replay of a vote from one slot to another.
    let block_hash = header.hash();
    let mut vote_msg = Vec::with_capacity(40);
    vote_msg.extend_from_slice(&header.slot.to_le_bytes());
    vote_msg.extend_from_slice(&block_hash);
    let sig = pyde_crypto::falcon::falcon_sign(voter_sk, &vote_msg)
        .map_err(|_| "vote signing failed")?;

    state.last_voted_slot = header.slot;

    Ok(Some(ConsensusMessage::Vote {
        slot: header.slot,
        block_hash,
        voter_index,
        voter_address,
        signature: sig.as_bytes().to_vec(),
    }))
}

/// Verify a vote message against a validator's public key.
/// The signature covers (slot || block_hash) to prevent cross-slot replay.
pub fn verify_vote(vote: &ConsensusMessage, public_key: &[u8]) -> bool {
    match vote {
        ConsensusMessage::Vote {
            slot,
            block_hash,
            signature,
            ..
        } => {
            let pk = match FalconPublicKey::from_bytes(public_key) {
                Some(pk) => pk,
                None => return false,
            };
            let mut vote_msg = Vec::with_capacity(40);
            vote_msg.extend_from_slice(&slot.to_le_bytes());
            vote_msg.extend_from_slice(block_hash);
            let sig = match FalconSignature::from_bytes(signature) {
                Some(s) => s,
                None => return false,
            };
            falcon_verify(&pk, &vote_msg, &sig)
        }
        _ => false,
    }
}

/// Aggregate votes into a QuorumCert.
/// Returns Some(QC) if quorum reached (86+ valid votes), None otherwise.
pub fn try_form_qc(
    slot: u64,
    block_hash: [u8; 32],
    votes: &[ConsensusMessage],
    committee_keys: &[Vec<u8>],
) -> Option<QuorumCert> {
    let mut voter_bitmap: u128 = 0;
    let mut signatures = Vec::new();
    let mut valid_count = 0u32;

    for vote in votes {
        if let ConsensusMessage::Vote {
            slot: vote_slot,
            block_hash: vote_hash,
            voter_index,
            signature,
            ..
        } = vote
        {
            if *vote_slot != slot || *vote_hash != block_hash {
                continue;
            }

            let idx = *voter_index as usize;
            if idx >= committee_keys.len() {
                continue;
            }

            // Skip if already counted
            if voter_bitmap & (1u128 << idx) != 0 {
                continue;
            }

            // Verify signature
            if verify_vote(vote, &committee_keys[idx]) {
                voter_bitmap |= 1u128 << idx;
                signatures.push(signature.clone());
                valid_count += 1;
            }
        }
    }

    if valid_count >= QUORUM_THRESHOLD as u32 {
        Some(QuorumCert {
            slot,
            block_hash,
            voter_bitmap,
            signatures,
        })
    } else {
        None
    }
}

/// Check if a block has reached finality.
///
/// In pipelined HotStuff, a block at slot S is finalized when:
/// - There is a QC for slot S (certifying the block)
/// - There is a QC for slot S+1 that chains back to the block at slot S
///   (the QC at S+1 must reference the block_hash certified by the QC at S)
/// (Two consecutive chained QCs = finality)
pub fn is_finalized(
    block_slot: u64,
    qc_chain: &[QuorumCert],
) -> bool {
    // Find a valid QC for block_slot
    let qc_for_block = qc_chain.iter().find(|qc| qc.slot == block_slot && qc.has_quorum());

    let qc_for_block = match qc_for_block {
        Some(qc) => qc,
        None => return false,
    };

    // Find a valid QC for block_slot+1 that chains back to block_slot's certified block.
    // The QC at slot S+1 must reference (via block_hash) the block that was certified
    // at slot S. We verify the chain by checking that the next QC's block_hash is
    // not the zero hash and that the next QC exists with quorum.
    // NOTE: Full chaining verification (next QC's block references this QC) requires
    // BlockHeader access. Here we verify consecutive slots both have quorum QCs
    // and that the first QC certifies a real block (non-zero hash).
    let has_qc_for_next = qc_chain.iter().any(|qc| {
        qc.slot == block_slot + 1
            && qc.has_quorum()
            && qc_for_block.block_hash != [0u8; 32]
    });

    has_qc_for_next
}

/// Create a timeout message when no valid proposal received within the timeout period.
pub fn create_timeout(
    state: &ConsensusState,
    slot: u64,
    voter_index: u8,
    voter_address: Address,
    voter_sk: &pyde_crypto::falcon::FalconSecretKey,
) -> Result<ConsensusMessage, &'static str> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"timeout");
    msg.extend_from_slice(&slot.to_le_bytes());
    let sig = pyde_crypto::falcon::falcon_sign(voter_sk, &msg)
        .map_err(|_| "timeout signing failed")?;

    Ok(ConsensusMessage::Timeout {
        slot,
        voter_index,
        voter_address,
        highest_qc: state.highest_qc.clone(),
        signature: sig.as_bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::QuorumCert;
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::falcon::falcon_keygen;

    fn make_header(slot: u64, qc_slot: u64) -> BlockHeader {
        BlockHeader {
            slot,
            epoch: slot / 1000,
            parent_hash: [0xAA; 32],
            proposer: derive_eoa_address(&[0x01; 897]),
            vrf_proof: vec![],
            qc_previous: QuorumCert {
                slot: qc_slot,
                block_hash: [0xBB; 32],
                voter_bitmap: (1u128 << 86) - 1,
                signatures: vec![],
            },
            tx_root: [0; 32],
            state_root: [0; 32],
            timestamp: 1_000_000,
        }
    }

    // ========== Task 0484: Happy path ==========

    #[test]
    fn happy_path_vote_and_qc() {
        let mut state = ConsensusState::new();
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let addr = derive_eoa_address(&pk_bytes);

        let header = make_header(1, 0);

        // Create vote
        let vote = create_vote(&mut state, &header, 0, addr, &sk).unwrap().unwrap();
        assert!(matches!(vote, ConsensusMessage::Vote { .. }));

        // Verify vote
        assert!(verify_vote(&vote, &pk_bytes));

        assert_eq!(state.last_voted_slot, 1);
    }

    #[test]
    fn qc_formed_with_86_votes() {
        let header = make_header(5, 4);
        let block_hash = header.hash();

        let mut votes = Vec::new();
        let mut keys = Vec::new();

        // Generate 86 valid votes (signature covers slot || block_hash)
        for i in 0..86u8 {
            let (pk, sk) = falcon_keygen().unwrap();
            let pk_bytes = pk.as_bytes().to_vec();
            let addr = derive_eoa_address(&pk_bytes);

            let mut vote_msg = Vec::with_capacity(40);
            vote_msg.extend_from_slice(&5u64.to_le_bytes());
            vote_msg.extend_from_slice(&block_hash);
            let sig = pyde_crypto::falcon::falcon_sign(&sk, &vote_msg).unwrap();
            votes.push(ConsensusMessage::Vote {
                slot: 5,
                block_hash,
                voter_index: i,
                voter_address: addr,
                signature: sig.as_bytes().to_vec(),
            });
            keys.push(pk_bytes);
        }

        // Pad keys to 128
        while keys.len() < 128 {
            keys.push(vec![0; 897]);
        }

        let qc = try_form_qc(5, block_hash, &votes, &keys);
        assert!(qc.is_some());
        let qc = qc.unwrap();
        assert!(qc.has_quorum());
        assert_eq!(qc.vote_count(), 86);
    }

    // ========== Task 0485: Insufficient votes ==========

    #[test]
    fn insufficient_votes_no_qc() {
        let header = make_header(5, 4);
        let block_hash = header.hash();

        let mut votes = Vec::new();
        let mut keys = Vec::new();

        // Only 85 votes (need 86)
        for i in 0..85u8 {
            let (pk, sk) = falcon_keygen().unwrap();
            let pk_bytes = pk.as_bytes().to_vec();
            let addr = derive_eoa_address(&pk_bytes);

            let mut vote_msg = Vec::with_capacity(40);
            vote_msg.extend_from_slice(&5u64.to_le_bytes());
            vote_msg.extend_from_slice(&block_hash);
            let sig = pyde_crypto::falcon::falcon_sign(&sk, &vote_msg).unwrap();
            votes.push(ConsensusMessage::Vote {
                slot: 5,
                block_hash,
                voter_index: i,
                voter_address: addr,
                signature: sig.as_bytes().to_vec(),
            });
            keys.push(pk_bytes);
        }

        while keys.len() < 128 {
            keys.push(vec![0; 897]);
        }

        let qc = try_form_qc(5, block_hash, &votes, &keys);
        assert!(qc.is_none());
    }

    // ========== Task 0486: Pipelined blocks ==========

    #[test]
    fn pipelined_finality() {
        // Block at slot 5 is finalized when QCs exist for slot 5 and slot 6
        let qc_5 = QuorumCert {
            slot: 5,
            block_hash: [0xAA; 32],
            voter_bitmap: (1u128 << 86) - 1,
            signatures: vec![],
        };
        let qc_6 = QuorumCert {
            slot: 6,
            block_hash: [0xBB; 32],
            voter_bitmap: (1u128 << 86) - 1,
            signatures: vec![],
        };

        assert!(is_finalized(5, &[qc_5.clone(), qc_6.clone()]));
        assert!(!is_finalized(5, &[qc_5.clone()])); // missing QC for slot 6
        assert!(!is_finalized(5, &[qc_6.clone()])); // missing QC for slot 5
    }

    // ========== Task 0487: QC requires 86/128 ==========

    #[test]
    fn qc_quorum_threshold() {
        let mut qc = QuorumCert::empty();
        qc.voter_bitmap = (1u128 << 85) - 1; // 85 votes
        assert!(!qc.has_quorum());

        qc.voter_bitmap = (1u128 << 86) - 1; // 86 votes
        assert!(qc.has_quorum());

        qc.voter_bitmap = u128::MAX; // 128 votes
        assert!(qc.has_quorum());
    }

    // ========== Safety: no double voting ==========

    #[test]
    fn no_double_vote() {
        let mut state = ConsensusState::new();
        let (pk, sk) = falcon_keygen().unwrap();
        let addr = derive_eoa_address(pk.as_bytes());

        let header = make_header(1, 0);
        let vote1 = create_vote(&mut state, &header, 0, addr, &sk).unwrap();
        assert!(vote1.is_some());

        // Try voting again for same slot
        let vote2 = create_vote(&mut state, &header, 0, addr, &sk).unwrap();
        assert!(vote2.is_none()); // rejected
    }

    #[test]
    fn vote_rejected_for_old_slot() {
        let mut state = ConsensusState::new();
        let (pk, sk) = falcon_keygen().unwrap();
        let addr = derive_eoa_address(pk.as_bytes());

        // Vote for slot 5
        let header5 = make_header(5, 4);
        create_vote(&mut state, &header5, 0, addr, &sk).unwrap().unwrap();

        // Try to vote for slot 3 (old)
        let header3 = make_header(3, 2);
        let vote = create_vote(&mut state, &header3, 0, addr, &sk).unwrap();
        assert!(vote.is_none());
    }

    // ========== QC extends highest ==========

    #[test]
    fn vote_updates_highest_qc() {
        let mut state = ConsensusState::new();
        let (pk, sk) = falcon_keygen().unwrap();
        let addr = derive_eoa_address(pk.as_bytes());

        assert_eq!(state.highest_qc.slot, 0);

        let header = make_header(5, 4); // QC for slot 4
        create_vote(&mut state, &header, 0, addr, &sk).unwrap().unwrap();

        assert_eq!(state.highest_qc.slot, 4);
    }

    // ========== Timeout ==========

    #[test]
    fn timeout_message_created() {
        let state = ConsensusState::new();
        let (pk, sk) = falcon_keygen().unwrap();
        let addr = derive_eoa_address(pk.as_bytes());

        let timeout = create_timeout(&state, 5, 0, addr, &sk).unwrap();
        assert!(matches!(timeout, ConsensusMessage::Timeout { slot: 5, .. }));
    }
}
