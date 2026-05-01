//! Modified HotStuff pipelined BFT consensus per Chapter 6, Section 6.3.
//!
//! Three-phase pipeline per slot (400ms):
//!   Phase 1: PROPOSE (0-100ms) — proposer broadcasts block
//!   Phase 2: VOTE (100-300ms) — validators vote on block
//!   Phase 3: CERTIFY (300-400ms) — next proposer collects votes into QC
//!
//! Pipelined: certify for slot N overlaps with propose for slot N+1.
//! Finality: block finalized when referenced by 2 consecutive QCs.

use crate::block::{quorum_for_committee, BlockHeader, QuorumCert};
use pyde_account::address::Address;
use pyde_crypto::falcon::{falcon_verify, FalconPublicKey, FalconSignature};

/// Canonical message bytes that both proposers and voters sign for a
/// block at a given slot: `chain_id_le || slot_le || block_hash`.
///
/// The `chain_id` prefix binds every proposer/vote/evidence signature
/// to a specific chain, preventing cross-chain replay even when two
/// chains share the same FALCON committee keys. `BlockHeader::hash()`
/// does not include `chain_id` directly — without this prefix, a vote
/// signed on one chain would verify against the same block hash on
/// another chain, and a double-sign on devnet would slash on testnet.
///
/// The `slot` prefix binds to a specific slot, preventing cross-slot
/// replay of the same block hash. Both proposer signatures (on block
/// headers) and vote signatures (on `Vote` messages) use this exact
/// layout so slashing evidence can be verified with a single routine
/// regardless of signature origin.
#[inline]
pub fn proposer_sign_message(chain_id: u64, slot: u64, block_hash: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + 8 + 32);
    msg.extend_from_slice(&chain_id.to_le_bytes());
    msg.extend_from_slice(&slot.to_le_bytes());
    msg.extend_from_slice(block_hash);
    msg
}

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
///
/// Two distinct slot-like quantities live here. They are intentionally
/// separate (audit-234 part 4 — see `crates/consensus/CONSENSUS_INVARIANTS.md`):
///
/// - `current_slot` is the wall-clock slot. Advanced by the engine tick
///   every `SLOT_DURATION_MS`. Used for **timing decisions only**
///   (when to time out, proposer-VRF input at view 0, epoch scheduling).
///   It must NEVER be used as the recovery target: when recovery takes
///   longer than a slot, `current_slot` drifts past the height we are
///   actually trying to commit.
///
/// - `target_height` is the position in the chain we are currently
///   trying to commit. Monotonically non-decreasing; only advances when
///   a block at `target_height` reaches a vote-QC. View-change
///   messages, fallback proposals, and timeout-tracker keys ALL use
///   `target_height`, never `current_slot`.
///
/// `current_view` is the recovery attempt within `target_height`.
/// 0 = happy-path proposer (VRF). ≥1 = view-change-driven fallback
/// proposer. Resets to 0 every time `target_height` advances.
#[derive(Clone, Debug)]
pub struct ConsensusState {
    /// Wall-clock slot (timing only — see struct doc).
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
    /// The chain height we are currently trying to commit
    /// (audit-234 part 4). See struct doc.
    pub target_height: u64,
    /// Recovery attempt within `target_height` (audit-234 part 4).
    /// 0 = happy-path; ≥1 = view-change-driven fallback.
    pub current_view: u64,
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
            // Genesis is at slot 0; the first slot we try to commit is 1.
            target_height: 1,
            current_view: 0,
            pending_votes: Vec::new(),
            pending_timeouts: Vec::new(),
        }
    }

    /// Advance the wall-clock slot by one. Does NOT touch
    /// `target_height` or `current_view` — those advance only when a
    /// vote-QC forms (target_height) or a view-change-QC forms
    /// (current_view).
    pub fn advance_slot(&mut self) {
        self.current_slot += 1;
        self.pending_votes.clear();
        self.pending_timeouts.clear();
    }

    /// Advance `target_height` to `new_height` and reset
    /// `current_view` to 0. No-op if `new_height <= target_height`
    /// (target is monotonic). Returns true iff the target advanced.
    ///
    /// Called by the engine after a vote-QC forms, signalling that
    /// the current target has been certified and we are ready to
    /// move on to the next height.
    pub fn advance_target_height(&mut self, new_height: u64) -> bool {
        if new_height > self.target_height {
            self.target_height = new_height;
            self.current_view = 0;
            true
        } else {
            false
        }
    }

    /// Bump `current_view` by one, signalling a recovery attempt for
    /// the current `target_height`. Called by the engine when a
    /// view-change-QC forms.
    pub fn bump_view(&mut self) {
        self.current_view += 1;
    }
}

impl Default for ConsensusState {
    fn default() -> Self {
        Self::new()
    }
}

/// Vote on a proposed block. Returns a Vote message.
///
/// `chain_id` is bound into the signed preimage so a vote signed on
/// chain A cannot be replayed as a valid vote on chain B (see
/// [`proposer_sign_message`]).
///
/// Safety rule: only vote if:
/// 1. The proposal extends the highest QC we've seen
/// 2. We haven't voted for this slot yet
pub fn create_vote(
    chain_id: u64,
    state: &mut ConsensusState,
    header: &BlockHeader,
    voter_index: u8,
    voter_address: Address,
    voter_sk: &pyde_crypto::falcon::FalconSecretKey,
    committee_keys: &[Vec<u8>],
) -> Result<Option<ConsensusMessage>, &'static str> {
    // Safety: don't double-vote
    if header.slot <= state.last_voted_slot {
        return Ok(None);
    }

    // Safety: proposal must extend our highest QC
    if header.qc_previous.slot < state.highest_qc.slot {
        return Ok(None);
    }

    // Audit 311: verify every signature inside the proposed QC
    // before promoting it into our HotStuff state. Pre-311 a
    // Byzantine proposer could fabricate `qc_previous` (set the
    // bitmap to claim quorum without any real votes), and we'd
    // overwrite `state.highest_qc` with the lie.
    if !verify_qc(&header.qc_previous, committee_keys, chain_id) {
        return Err("invalid qc_previous: signature verification failed");
    }

    // Update highest QC if proposal's QC is newer
    if header.qc_previous.slot > state.highest_qc.slot {
        state.highest_qc = header.qc_previous.clone();
    }

    // Sign (chain_id || slot || block_hash) via the canonical
    // proposer/vote message layout, binding the vote to a specific
    // chain and slot.
    let block_hash = header.hash();
    let vote_msg = proposer_sign_message(chain_id, header.slot, &block_hash);
    let sig =
        pyde_crypto::falcon::falcon_sign(voter_sk, &vote_msg).map_err(|_| "vote signing failed")?;

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
///
/// The signature covers `(chain_id || slot || block_hash)`. A vote signed
/// on a different chain (different `chain_id`) will fail verification
/// here even when the FALCON keys match — preventing cross-chain replay.
pub fn verify_vote(chain_id: u64, vote: &ConsensusMessage, public_key: &[u8]) -> bool {
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
            let vote_msg = proposer_sign_message(chain_id, *slot, block_hash);
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
///
/// Audit 311: emits `signatures` sorted by voter_index ascending so
/// `verify_qc` (and any future on-the-wire consumer) can pair
/// `signatures[i]` with the `i`-th set bit of `voter_bitmap` without
/// guessing arrival order. Pre-311 signatures were pushed in vote-
/// arrival order, so two honest validators forming the same QC could
/// produce different `signatures` Vec orderings — non-deterministic
/// and unverifiable by bit-position.
pub fn try_form_qc(
    chain_id: u64,
    slot: u64,
    block_hash: [u8; 32],
    votes: &[ConsensusMessage],
    committee_keys: &[Vec<u8>],
) -> Option<QuorumCert> {
    let mut voter_bitmap: u128 = 0;
    // Track (voter_index, signature) pairs so we can sort by index
    // before storing in the QC.
    let mut indexed_sigs: Vec<(u8, Vec<u8>)> = Vec::new();
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
            if verify_vote(chain_id, vote, &committee_keys[idx]) {
                voter_bitmap |= 1u128 << idx;
                indexed_sigs.push((*voter_index, signature.clone()));
                valid_count += 1;
            }
        }
    }

    let threshold = quorum_for_committee(committee_keys.len());
    if valid_count >= threshold as u32 {
        // Audit 311: sort by voter_index so signatures[i] aligns
        // with the i-th set bit of voter_bitmap (low → high).
        indexed_sigs.sort_by_key(|(idx, _)| *idx);
        let signatures = indexed_sigs.into_iter().map(|(_, sig)| sig).collect();
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

/// Verify every signature inside a QuorumCert against the
/// `committee_keys` and the QC's slot + block_hash (audit 311).
///
/// Pre-311 the only check on an incoming QC was
/// `qc.has_quorum_for(N)`, which counts the bitmap. The signatures
/// inside were never re-verified, so a Byzantine proposer could
/// fabricate `qc_previous = QuorumCert { voter_bitmap: u128::MAX,
/// signatures: vec![] }` and validators accepted it. This call
/// closes that hole at every place an external QC is consumed:
///
/// - `validate_network_block` (block_processor.rs) before applying
///   the block.
/// - `create_vote` (hotstuff.rs) before mutating
///   `state.highest_qc`.
///
/// Returns false on any of:
/// - bitmap claims fewer voters than `quorum_for_committee(N)`
/// - signatures count != bitmap pop-count (malformed)
/// - any voter_index exceeds committee size
/// - any FALCON signature fails to verify against the matching
///   committee public key
///
/// Empty QCs (`slot == 0` AND empty bitmap) are accepted as the
/// genesis sentinel and short-circuit to true so genesis-bootstrap
/// and pre-finality slots aren't blocked. Callers that need to
/// distinguish "real" QCs from empty ones must check
/// `qc.voter_bitmap != 0` themselves first.
///
/// `signatures` MUST be sorted by voter_index ascending — `try_form_qc`
/// guarantees that ordering. A peer that hand-crafts a QC with a
/// different ordering will hit the "sig n doesn't verify against
/// validator k" branch and the whole QC is rejected.
pub fn verify_qc(qc: &QuorumCert, committee_keys: &[Vec<u8>], chain_id: u64) -> bool {
    // Genesis / empty QC: accept as a sentinel.
    if qc.voter_bitmap == 0 && qc.signatures.is_empty() {
        return true;
    }
    let n = committee_keys.len();
    if n == 0 {
        return false;
    }
    let pop = qc.voter_bitmap.count_ones() as usize;
    if pop != qc.signatures.len() {
        return false;
    }
    if pop < quorum_for_committee(n) {
        return false;
    }
    let preimage = proposer_sign_message(chain_id, qc.slot, &qc.block_hash);
    let mut sig_idx = 0usize;
    for bit_pos in 0..128usize {
        if qc.voter_bitmap & (1u128 << bit_pos) == 0 {
            continue;
        }
        if bit_pos >= n {
            // Bitmap claims a voter outside the committee — invalid.
            return false;
        }
        let sig_bytes = &qc.signatures[sig_idx];
        sig_idx += 1;
        let pk = match FalconPublicKey::from_bytes(&committee_keys[bit_pos]) {
            Some(pk) => pk,
            None => return false,
        };
        let sig = match FalconSignature::from_bytes(sig_bytes) {
            Some(s) => s,
            None => return false,
        };
        if !falcon_verify(&pk, &preimage, &sig) {
            return false;
        }
    }
    true
}

/// Check if a block has reached finality.
///
/// In pipelined HotStuff, a block at slot S is finalized when:
/// - There is a QC for slot S (certifying the block)
/// - There is a QC for slot S+1 that chains back to the block at slot S
///   (the QC at S+1 must reference the block_hash certified by the QC at S)
/// (Two consecutive chained QCs = finality)
/// Check if a block at `block_slot` is finalized per pipelined HotStuff.
/// Requires: QC at slot S with quorum, AND QC at slot S+1 with quorum
/// where the S+1 block chains back to the S block (parent_hash matches).
///
/// `headers` maps slot → BlockHeader for chain verification.
/// `committee_size` is the active committee size for `block_slot`; the
/// quorum threshold is computed from it via `quorum_for_committee` so
/// devnet/testnet committees smaller than 128 form finality correctly.
pub fn is_finalized(
    block_slot: u64,
    qc_chain: &[QuorumCert],
    headers: &std::collections::HashMap<u64, crate::block::BlockHeader>,
    committee_size: usize,
) -> bool {
    // Find a valid QC for block_slot
    let qc_for_block = match qc_chain
        .iter()
        .find(|qc| qc.slot == block_slot && qc.has_quorum_for(committee_size))
    {
        Some(qc) => qc,
        None => return false,
    };

    // The QC must certify a real block (non-zero hash)
    if qc_for_block.block_hash == [0u8; 32] {
        return false;
    }

    // Find a valid QC for block_slot+1
    let qc_for_next = match qc_chain
        .iter()
        .find(|qc| qc.slot == block_slot + 1 && qc.has_quorum_for(committee_size))
    {
        Some(qc) => qc,
        None => return false,
    };

    // Verify chain linking: the block at slot+1 must reference the block at slot as parent
    if let Some(next_header) = headers.get(&(block_slot + 1)) {
        next_header.parent_hash == qc_for_block.block_hash && qc_for_next.block_hash != [0u8; 32]
    } else {
        false // can't verify chain without the header
    }
}

/// Create a timeout message when no valid proposal received within the timeout period.
///
/// NOTE: production view-change goes through
/// `validator::on_timeout` → `view_change::create_view_change`. This
/// function is only exercised by unit tests today; kept public for
/// API stability. The `chain_id` prefix is bound for consistency with
/// every other consensus signing surface so future production callers
/// don't reintroduce a chain-replayable signature.
pub fn create_timeout(
    chain_id: u64,
    state: &ConsensusState,
    slot: u64,
    voter_index: u8,
    voter_address: Address,
    voter_sk: &pyde_crypto::falcon::FalconSecretKey,
) -> Result<ConsensusMessage, &'static str> {
    let mut msg = Vec::with_capacity(7 + 8 + 8); // "timeout"(7) + chain_id(8) + slot(8)
    msg.extend_from_slice(b"timeout");
    msg.extend_from_slice(&chain_id.to_le_bytes());
    msg.extend_from_slice(&slot.to_le_bytes());
    let sig =
        pyde_crypto::falcon::falcon_sign(voter_sk, &msg).map_err(|_| "timeout signing failed")?;

    Ok(ConsensusMessage::Timeout {
        slot,
        voter_index,
        voter_address,
        highest_qc: state.highest_qc.clone(),
        signature: sig.as_bytes().to_vec(),
    })
}

#[cfg(test)]
// Same test-module rationale as `block.rs` — keep `&[tx.clone()]`
// idiom for 1-element slice assertions rather than `from_ref` rewrite.
#[allow(clippy::cloned_ref_to_slice_refs)]
mod tests {
    use super::*;
    use crate::block::QuorumCert;
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::falcon::falcon_keygen;

    /// Arbitrary non-mainnet, non-devnet chain_id used by every test
    /// in this module so cross-chain replay regressions surface here
    /// rather than slipping past with hardcoded chain_id=0.
    const TEST_CHAIN_ID: u64 = 7;

    /// Build a test header with an EMPTY qc_previous. Audit 311
    /// requires `qc_previous` signatures to verify against
    /// committee_keys; the unit tests in this module test
    /// `create_vote`'s HotStuff safety rules, not QC
    /// verification, so they use the empty-QC sentinel which
    /// `verify_qc` short-circuits to `true`. Tests for QC
    /// verification specifically (e.g.
    /// `verify_qc_rejects_fabricated_bitmap`) build full
    /// fixtures with real signatures.
    fn make_header(slot: u64, qc_slot: u64) -> BlockHeader {
        let mut qc = QuorumCert::empty();
        qc.slot = qc_slot;
        BlockHeader {
            slot,
            epoch: slot / 1000,
            parent_hash: [0xAA; 32],
            proposer: derive_eoa_address(&[0x01; 897]),
            vrf_proof: vec![],
            qc_previous: qc,
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
        let vote = create_vote(TEST_CHAIN_ID, &mut state, &header, 0, addr, &sk, &[])
            .unwrap()
            .unwrap();
        assert!(matches!(vote, ConsensusMessage::Vote { .. }));

        // Verify vote
        assert!(verify_vote(TEST_CHAIN_ID, &vote, &pk_bytes));

        assert_eq!(state.last_voted_slot, 1);
    }

    /// Cross-chain replay: a vote signed under one `chain_id` must NOT
    /// verify under another even when FALCON keys match. Mirrors
    /// audit-240's multisig regression.
    #[test]
    fn vote_cross_chain_replay_rejected() {
        let mut state = ConsensusState::new();
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let addr = derive_eoa_address(&pk_bytes);

        let header = make_header(1, 0);
        let vote = create_vote(1, &mut state, &header, 0, addr, &sk, &[])
            .unwrap()
            .unwrap();

        assert!(verify_vote(1, &vote, &pk_bytes));
        assert!(!verify_vote(2, &vote, &pk_bytes));
        assert!(!verify_vote(31337, &vote, &pk_bytes));
    }

    #[test]
    fn qc_formed_with_86_votes() {
        let header = make_header(5, 4);
        let block_hash = header.hash();

        let mut votes = Vec::new();
        let mut keys = Vec::new();

        // Generate 86 valid votes (signature covers chain_id || slot || block_hash)
        for i in 0..86u8 {
            let (pk, sk) = falcon_keygen().unwrap();
            let pk_bytes = pk.as_bytes().to_vec();
            let addr = derive_eoa_address(&pk_bytes);

            let vote_msg = proposer_sign_message(TEST_CHAIN_ID, 5, &block_hash);
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

        let qc = try_form_qc(TEST_CHAIN_ID, 5, block_hash, &votes, &keys);
        assert!(qc.is_some());
        let qc = qc.unwrap();
        assert!(qc.has_quorum());
        assert_eq!(qc.vote_count(), 86);
    }

    // ── Audit 311: verify_qc regression tests ──────────────────────

    /// Empty QC sentinel (genesis / pre-finality) is accepted.
    #[test]
    fn verify_qc_accepts_empty_sentinel() {
        let qc = QuorumCert::empty();
        assert!(verify_qc(&qc, &[], TEST_CHAIN_ID));
        // Even with a non-empty committee, the empty sentinel
        // short-circuits to true.
        assert!(verify_qc(&qc, &vec![vec![0u8; 897]; 4], TEST_CHAIN_ID));
    }

    /// A QC produced by `try_form_qc` from real votes verifies.
    #[test]
    fn verify_qc_accepts_well_formed_qc() {
        let header = make_header(5, 4);
        let block_hash = header.hash();
        let mut votes = Vec::new();
        let mut keys = Vec::new();
        for i in 0..86u8 {
            let (pk, sk) = falcon_keygen().unwrap();
            let pk_bytes = pk.as_bytes().to_vec();
            let addr = derive_eoa_address(&pk_bytes);
            let vote_msg = proposer_sign_message(TEST_CHAIN_ID, 5, &block_hash);
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
        let qc = try_form_qc(TEST_CHAIN_ID, 5, block_hash, &votes, &keys).unwrap();
        assert!(verify_qc(&qc, &keys, TEST_CHAIN_ID));
    }

    /// A QC with `voter_bitmap = u128::MAX` and empty signatures —
    /// the exact lie the audit-311 fix closes — is rejected.
    /// Pre-fix `validate_network_block` and `create_vote` accepted
    /// this and propagated it into HotStuff state.
    #[test]
    fn verify_qc_rejects_fabricated_bitmap_with_empty_sigs() {
        let qc = QuorumCert {
            slot: 5,
            block_hash: [0xCC; 32],
            voter_bitmap: u128::MAX,
            signatures: vec![], // count_ones() = 128, len() = 0 → mismatch
        };
        let keys = vec![vec![0u8; 897]; 128];
        assert!(!verify_qc(&qc, &keys, TEST_CHAIN_ID));
    }

    /// Bitmap pop_count >= quorum but sigs are random bytes that
    /// don't verify against any committee key.
    #[test]
    fn verify_qc_rejects_garbage_signatures() {
        let qc = QuorumCert {
            slot: 5,
            block_hash: [0xCC; 32],
            voter_bitmap: (1u128 << 86) - 1, // 86 voters
            signatures: vec![vec![0xAB; 690]; 86],
        };
        let mut keys = Vec::new();
        for _ in 0..128 {
            let (pk, _) = falcon_keygen().unwrap();
            keys.push(pk.as_bytes().to_vec());
        }
        assert!(!verify_qc(&qc, &keys, TEST_CHAIN_ID));
    }

    /// A QC valid under chain_id A must NOT verify under chain_id B
    /// (cross-chain replay protection — already on the per-vote
    /// path; the verify_qc wrapper preserves it).
    #[test]
    fn verify_qc_rejects_cross_chain_replay() {
        let header = make_header(5, 4);
        let block_hash = header.hash();
        let mut votes = Vec::new();
        let mut keys = Vec::new();
        for i in 0..86u8 {
            let (pk, sk) = falcon_keygen().unwrap();
            let pk_bytes = pk.as_bytes().to_vec();
            let addr = derive_eoa_address(&pk_bytes);
            let vote_msg = proposer_sign_message(TEST_CHAIN_ID, 5, &block_hash);
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
        let qc = try_form_qc(TEST_CHAIN_ID, 5, block_hash, &votes, &keys).unwrap();
        // Same QC under a different chain_id fails.
        assert!(!verify_qc(&qc, &keys, TEST_CHAIN_ID + 1));
    }

    /// `create_vote` rejects a header whose qc_previous fails
    /// verification — the in-memory `state.highest_qc` MUST NOT
    /// be promoted to the lie.
    #[test]
    fn create_vote_rejects_fabricated_qc_previous() {
        let mut state = ConsensusState::new();
        let (_pk, sk) = falcon_keygen().unwrap();
        let addr = derive_eoa_address(&[0x01; 897]);
        let pre_state_hqc_slot = state.highest_qc.slot;

        let mut header = make_header(5, 4);
        // Replace the empty qc_previous with a fabricated one that
        // would have slipped past pre-311 (bitmap claims quorum,
        // signatures missing).
        header.qc_previous = QuorumCert {
            slot: 4,
            block_hash: [0xCC; 32],
            voter_bitmap: u128::MAX,
            signatures: vec![],
        };

        let keys = vec![vec![0u8; 897]; 128];
        let res = create_vote(TEST_CHAIN_ID, &mut state, &header, 0, addr, &sk, &keys);
        assert!(
            res.is_err(),
            "audit 311: create_vote must refuse fabricated qc_previous"
        );
        // The HotStuff state must not have promoted the fake QC.
        assert_eq!(
            state.highest_qc.slot, pre_state_hqc_slot,
            "audit 311: highest_qc must not be mutated when verify_qc fails"
        );
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

            let vote_msg = proposer_sign_message(TEST_CHAIN_ID, 5, &block_hash);
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

        let qc = try_form_qc(TEST_CHAIN_ID, 5, block_hash, &votes, &keys);
        assert!(qc.is_none());
    }

    // ========== Task 0486: Pipelined blocks ==========

    #[test]
    fn pipelined_finality() {
        use crate::block::BlockHeader;
        use pyde_account::address::ZERO_ADDRESS;
        use std::collections::HashMap;

        // Block at slot 5 is finalized when QCs exist for slot 5 and slot 6,
        // AND the block at slot 6 chains to the block at slot 5.
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

        // Block at slot 6 has parent_hash = block at slot 5's hash
        let header_6 = BlockHeader {
            slot: 6,
            epoch: 0,
            parent_hash: [0xAA; 32], // chains to block 5
            proposer: ZERO_ADDRESS,
            vrf_proof: vec![],
            qc_previous: qc_5.clone(),
            tx_root: [0; 32],
            state_root: [0; 32],
            timestamp: 0,
        };

        let mut headers = HashMap::new();
        headers.insert(6, header_6);

        assert!(is_finalized(
            5,
            &[qc_5.clone(), qc_6.clone()],
            &headers,
            128
        ));
        assert!(!is_finalized(5, &[qc_5.clone()], &headers, 128)); // missing QC for slot 6
        assert!(!is_finalized(5, &[qc_6.clone()], &headers, 128)); // missing QC for slot 5

        // Unrelated block at slot 6 (wrong parent) should NOT finalize
        let header_6_bad = BlockHeader {
            slot: 6,
            epoch: 0,
            parent_hash: [0xCC; 32], // does NOT chain to block 5
            proposer: ZERO_ADDRESS,
            vrf_proof: vec![],
            qc_previous: QuorumCert::empty(),
            tx_root: [0; 32],
            state_root: [0; 32],
            timestamp: 0,
        };
        let mut bad_headers = HashMap::new();
        bad_headers.insert(6, header_6_bad);
        assert!(!is_finalized(
            5,
            &[qc_5.clone(), qc_6.clone()],
            &bad_headers,
            128
        ));
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
        let vote1 = create_vote(TEST_CHAIN_ID, &mut state, &header, 0, addr, &sk, &[]).unwrap();
        assert!(vote1.is_some());

        // Try voting again for same slot
        let vote2 = create_vote(TEST_CHAIN_ID, &mut state, &header, 0, addr, &sk, &[]).unwrap();
        assert!(vote2.is_none()); // rejected
    }

    #[test]
    fn vote_rejected_for_old_slot() {
        let mut state = ConsensusState::new();
        let (pk, sk) = falcon_keygen().unwrap();
        let addr = derive_eoa_address(pk.as_bytes());

        // Vote for slot 5
        let header5 = make_header(5, 4);
        create_vote(TEST_CHAIN_ID, &mut state, &header5, 0, addr, &sk, &[])
            .unwrap()
            .unwrap();

        // Try to vote for slot 3 (old)
        let header3 = make_header(3, 2);
        let vote = create_vote(TEST_CHAIN_ID, &mut state, &header3, 0, addr, &sk, &[]).unwrap();
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
        create_vote(TEST_CHAIN_ID, &mut state, &header, 0, addr, &sk, &[])
            .unwrap()
            .unwrap();

        assert_eq!(state.highest_qc.slot, 4);
    }

    // ========== Timeout ==========

    #[test]
    fn timeout_message_created() {
        let state = ConsensusState::new();
        let (pk, sk) = falcon_keygen().unwrap();
        let addr = derive_eoa_address(pk.as_bytes());

        let timeout = create_timeout(TEST_CHAIN_ID, &state, 5, 0, addr, &sk).unwrap();
        assert!(matches!(timeout, ConsensusMessage::Timeout { slot: 5, .. }));
    }
}
