//! View change protocol: leader failure recovery per Chapter 6, Section 6.9.
//!
//! When the proposer fails to produce a block within 200ms:
//! 1. Validators broadcast ViewChange messages with their highest QC
//! 2. Upon collecting 86+ ViewChange messages → form ViewChangeQC
//! 3. Fallback proposer (2nd lowest VRF score) takes over
//! 4. If fallback also fails → empty block, advance to next slot
//!
//! Liveness: guaranteed if 86+ of 128 validators are honest and online.

use crate::block::{quorum_for_committee, BlockHeader, QuorumCert, QUORUM_THRESHOLD};
use pyde_account::address::Address;
use pyde_crypto::falcon::{
    falcon_sign, falcon_verify, FalconPublicKey, FalconSecretKey, FalconSignature,
};

/// Timeout duration before declaring proposer failure (milliseconds).
pub const PROPOSAL_TIMEOUT_MS: u64 = 200;

/// Audit 234 part 3: secondary timeout. After voting for a proposal,
/// if no QC for the slot is observed within this window, the
/// validator triggers view-change as a liveness fallback. Set well
/// above the 400ms slot time so a healthy chain never trips it
/// (a slot that gets its QC promptly clears the validator's
/// state before this fires), but low enough that gossip-mesh
/// inconsistency is recovered within a few seconds.
pub const PROGRESS_TIMEOUT_MS: u64 = 2_000;

/// Slot duration (milliseconds).
pub const SLOT_DURATION_MS: u64 = 400;

/// A view change message broadcast when a proposer fails.
#[derive(Clone, Debug)]
pub struct ViewChangeMessage {
    /// The slot that timed out.
    pub slot: u64,
    /// The highest QC this validator has seen.
    pub highest_qc: QuorumCert,
    /// Validator's committee index.
    pub voter_index: u8,
    /// Validator's address.
    pub voter_address: Address,
    /// FALCON signature over (slot || "view_change").
    pub signature: Vec<u8>,
}

/// A ViewChange QC: proof that 86+ validators reported timeout.
#[derive(Clone, Debug)]
pub struct ViewChangeQC {
    /// The slot that timed out.
    pub slot: u64,
    /// The highest QC from all view change messages (the one with max slot).
    pub highest_qc: QuorumCert,
    /// Bitmap of which validators sent view change messages.
    pub voter_bitmap: u128,
    /// Number of valid view change messages.
    pub vote_count: u32,
}

impl ViewChangeQC {
    /// Whether enough validators reported timeout.
    pub fn has_quorum(&self) -> bool {
        self.vote_count >= QUORUM_THRESHOLD as u32
    }
}

/// Timeout state tracker for a single slot.
///
/// The runtime (Phase 7) provides timestamps via `is_expired(now_ms)`.
/// This crate never reads the system clock directly.
#[derive(Clone, Debug)]
pub struct TimeoutTracker {
    /// Slot being tracked.
    pub slot: u64,
    /// Timestamp when this slot started (Unix ms, set by runtime).
    pub slot_start_ms: u64,
    /// Collected view change messages.
    pub messages: Vec<ViewChangeMessage>,
    /// Whether a valid proposal was received (cancels timeout).
    pub proposal_received: bool,
    /// Whether view change QC has been formed.
    pub view_change_qc: Option<ViewChangeQC>,
}

impl TimeoutTracker {
    pub fn new(slot: u64, slot_start_ms: u64) -> Self {
        Self {
            slot,
            slot_start_ms,
            messages: Vec::new(),
            proposal_received: false,
            view_change_qc: None,
        }
    }

    /// Mark that a valid proposal was received (cancels timeout).
    pub fn receive_proposal(&mut self) {
        self.proposal_received = true;
    }

    /// Check if the proposal timeout has expired.
    /// `now_ms` is provided by the runtime (system clock).
    pub fn is_expired(&self, now_ms: u64) -> bool {
        !self.proposal_received
            && self.view_change_qc.is_none()
            && now_ms.saturating_sub(self.slot_start_ms) >= PROPOSAL_TIMEOUT_MS
    }

    /// Check if the entire slot duration has elapsed.
    pub fn slot_elapsed(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.slot_start_ms) >= SLOT_DURATION_MS
    }

    /// Milliseconds remaining until proposal timeout.
    pub fn ms_until_timeout(&self, now_ms: u64) -> u64 {
        let elapsed = now_ms.saturating_sub(self.slot_start_ms);
        PROPOSAL_TIMEOUT_MS.saturating_sub(elapsed)
    }
}

/// Build the message that validators sign for view change.
fn view_change_sign_message(slot: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(19); // "view_change"(11) + slot(8)
    msg.extend_from_slice(b"view_change");
    msg.extend_from_slice(&slot.to_le_bytes());
    msg
}

/// Create a view change message when timeout is detected.
pub fn create_view_change(
    slot: u64,
    highest_qc: &QuorumCert,
    voter_index: u8,
    voter_address: Address,
    voter_sk: &FalconSecretKey,
) -> Result<ViewChangeMessage, &'static str> {
    let msg = view_change_sign_message(slot);
    let sig = falcon_sign(voter_sk, &msg).map_err(|_| "view change signing failed")?;

    Ok(ViewChangeMessage {
        slot,
        highest_qc: highest_qc.clone(),
        voter_index,
        voter_address,
        signature: sig.as_bytes().to_vec(),
    })
}

/// Verify a view change message.
pub fn verify_view_change(msg: &ViewChangeMessage, public_key: &[u8]) -> bool {
    let pk = match FalconPublicKey::from_bytes(public_key) {
        Some(pk) => pk,
        None => return false,
    };
    let sign_msg = view_change_sign_message(msg.slot);
    let sig = match FalconSignature::from_bytes(&msg.signature) {
        Some(s) => s,
        None => return false,
    };
    falcon_verify(&pk, &sign_msg, &sig)
}

/// Try to form a ViewChangeQC from collected messages.
/// Returns Some(ViewChangeQC) if 86+ valid messages for the same slot.
pub fn try_form_view_change_qc(
    slot: u64,
    messages: &[ViewChangeMessage],
    committee_keys: &[Vec<u8>],
) -> Option<ViewChangeQC> {
    let mut voter_bitmap: u128 = 0;
    let mut valid_count = 0u32;
    let mut highest_qc = QuorumCert::empty();

    for msg in messages {
        if msg.slot != slot {
            continue;
        }

        let idx = msg.voter_index as usize;
        if idx >= committee_keys.len() {
            continue;
        }

        // Skip duplicates
        if voter_bitmap & (1u128 << idx) != 0 {
            continue;
        }

        if verify_view_change(msg, &committee_keys[idx]) {
            voter_bitmap |= 1u128 << idx;
            valid_count += 1;

            // Track highest QC across all messages.
            // Only accept a reported highest_qc if it actually has quorum —
            // otherwise a malicious validator could claim an arbitrarily high
            // slot with a fake (zero-vote) QC to manipulate the view change.
            //
            // Audit 235/236 sweep: use `has_quorum_for(committee_keys.len())`
            // not `has_quorum()` — the latter hardcodes 86 and silently
            // rejected every devnet QC (which has 3-5 votes), making
            // view-change unable to track highest_qc correctly on any
            // committee smaller than 86.
            if msg.highest_qc.slot > highest_qc.slot
                && msg.highest_qc.has_quorum_for(committee_keys.len())
            {
                highest_qc = msg.highest_qc.clone();
            }
        }
    }

    // audit 234: use the dynamic threshold so devnet committees
    // (which are smaller than the production 128) can still form
    // a view-change QC. Hardcoding QUORUM_THRESHOLD = 86 made
    // view-change effectively impossible on any committee with
    // fewer than 86 validators.
    let threshold = quorum_for_committee(committee_keys.len());
    if valid_count >= threshold as u32 {
        Some(ViewChangeQC {
            slot,
            highest_qc,
            voter_bitmap,
            vote_count: valid_count,
        })
    } else {
        None
    }
}

/// Determine the fallback proposer for a slot.
/// The fallback is the committee member with the 2nd lowest VRF score.
/// `sorted_scores` should be (address, score) sorted by score ascending.
///
/// Note: superseded by `fallback_leader_index((H, V), n)` for the
/// audit-234 part 4 single-leader-per-view design. Kept for tests.
#[allow(dead_code)]
pub fn fallback_proposer(sorted_scores: &[(Address, u64)]) -> Option<Address> {
    sorted_scores.get(1).map(|(addr, _)| *addr)
}

/// Marker prefix in a `BlockHeader.vrf_proof` field signalling
/// "this is a view-change fallback proposal, validate against the
/// view-change-QC rather than VRF". The marker is followed by:
///   - u64 LE: VC-QC slot (target_height the fallback is for)
///   - u64 LE: view number the fallback was built at
/// Total: 8 (marker) + 8 (slot) + 8 (view) = 24 bytes.
pub const FALLBACK_PROPOSAL_MARKER: &[u8; 8] = b"FALLBACK";

/// Audit-234 part 4 (CONSENSUS_INVARIANTS.md L2): deterministic
/// fallback leader for the recovery view at `(height, view)`.
/// All honest validators compute the same answer regardless of
/// which view-change messages they observed, so the fallback
/// proposer is unanimous without depending on the gossip mesh
/// having delivered identical VC-message subsets to every peer.
///
/// The mapping `(H + V) mod n` is intentionally simple:
///   - deterministic and cheap (no hashing)
///   - rotates within a height: each failing view picks a different
///     committee member, so a stuck leader is bypassed within at
///     most n-1 view bumps
///   - rotates across heights: even if every view-0 leader is
///     honest-but-unreachable, the V≥1 fallback for the next height
///     picks a different member
///
/// Pre-mainnet: if grinding-resistance becomes a concern (committee
/// members predicting future leadership and timing out strategically),
/// upgrade to `Poseidon2(epoch_randomness || H || V) mod n`. For now
/// the simple modular sum is sufficient — V advances only on quorum
/// timeout, not on individual proposer choice.
pub fn fallback_leader_index(height: u64, view: u64, committee_size: usize) -> usize {
    if committee_size == 0 {
        return 0;
    }
    (height.wrapping_add(view) as usize) % committee_size
}

/// Deterministically pick the fallback proposer's committee index
/// from a view-change-QC's voter bitmap: the lowest-indexed bit
/// that is set.
///
/// Note: superseded by `fallback_leader_index((H, V), n)` for the
/// audit-234 part 4 single-leader-per-view design. Bitmap-based
/// selection failed under mesh inconsistency because different
/// validators observed different VC-message subsets and computed
/// different fallback leaders, splitting votes across the
/// candidates. Kept dead for now; remove with the next view_change
/// cleanup pass.
#[allow(dead_code)]
pub fn deterministic_fallback_index(voter_bitmap: u128) -> Option<u8> {
    if voter_bitmap == 0 {
        return None;
    }
    Some(voter_bitmap.trailing_zeros() as u8)
}

/// Build a `vrf_proof` field carrying the fallback marker + the
/// view-change-QC's slot + the recovery view number. Receivers
/// recognize this prefix and validate the proposer against
/// `fallback_leader_index(slot, view, committee_size)` instead of
/// running VRF verification.
pub fn encode_fallback_proof(vc_qc_slot: u64, view: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FALLBACK_PROPOSAL_MARKER.len() + 16);
    buf.extend_from_slice(FALLBACK_PROPOSAL_MARKER);
    buf.extend_from_slice(&vc_qc_slot.to_le_bytes());
    buf.extend_from_slice(&view.to_le_bytes());
    buf
}

/// True iff `vrf_proof` was produced by `encode_fallback_proof`.
pub fn is_fallback_proof(vrf_proof: &[u8]) -> bool {
    vrf_proof.len() >= FALLBACK_PROPOSAL_MARKER.len()
        && &vrf_proof[..FALLBACK_PROPOSAL_MARKER.len()] == FALLBACK_PROPOSAL_MARKER
}

/// Decode a fallback proof produced by `encode_fallback_proof`,
/// returning `(vc_qc_slot, view)`. Returns None if the buffer is
/// not a fallback proof or is truncated.
pub fn decode_fallback_proof(vrf_proof: &[u8]) -> Option<(u64, u64)> {
    if !is_fallback_proof(vrf_proof) {
        return None;
    }
    let after_marker = &vrf_proof[FALLBACK_PROPOSAL_MARKER.len()..];
    if after_marker.len() < 16 {
        return None;
    }
    let slot = u64::from_le_bytes(after_marker[0..8].try_into().ok()?);
    let view = u64::from_le_bytes(after_marker[8..16].try_into().ok()?);
    Some((slot, view))
}

/// Create an empty block header for when both primary and fallback fail.
pub fn empty_block_header(
    slot: u64,
    epoch: u64,
    parent_hash: [u8; 32],
    qc_previous: QuorumCert,
    state_root: [u8; 32],
    timestamp: u64,
) -> BlockHeader {
    BlockHeader {
        slot,
        epoch,
        parent_hash,
        proposer: [0u8; 32], // no proposer
        vrf_proof: vec![],
        qc_previous,
        tx_root: [0u8; 32], // no transactions
        state_root,
        timestamp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::falcon::falcon_keygen;

    // ========== Task 0493: Leader timeout → view change → new leader ==========

    #[test]
    fn view_change_message_created_and_verified() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let addr = derive_eoa_address(&pk_bytes);
        let qc = QuorumCert::empty();

        let msg = create_view_change(5, &qc, 0, addr, &sk).unwrap();
        assert_eq!(msg.slot, 5);
        assert!(verify_view_change(&msg, &pk_bytes));
    }

    #[test]
    fn view_change_wrong_key_rejected() {
        let (pk1, sk1) = falcon_keygen().unwrap();
        let (pk2, _sk2) = falcon_keygen().unwrap();
        let addr = derive_eoa_address(pk1.as_bytes());
        let qc = QuorumCert::empty();

        let msg = create_view_change(5, &qc, 0, addr, &sk1).unwrap();
        assert!(!verify_view_change(&msg, pk2.as_bytes()));
    }

    #[test]
    fn view_change_qc_formed_with_86_messages() {
        let mut messages = Vec::new();
        let mut keys = Vec::new();

        for i in 0..86u8 {
            let (pk, sk) = falcon_keygen().unwrap();
            let pk_bytes = pk.as_bytes().to_vec();
            let addr = derive_eoa_address(&pk_bytes);
            let qc = QuorumCert::empty();

            let msg = create_view_change(10, &qc, i, addr, &sk).unwrap();
            messages.push(msg);
            keys.push(pk_bytes);
        }

        while keys.len() < 128 {
            keys.push(vec![0; 897]);
        }

        let vc_qc = try_form_view_change_qc(10, &messages, &keys);
        assert!(vc_qc.is_some());
        assert!(vc_qc.unwrap().has_quorum());
    }

    #[test]
    fn view_change_qc_not_formed_with_85() {
        let mut messages = Vec::new();
        let mut keys = Vec::new();

        for i in 0..85u8 {
            let (pk, sk) = falcon_keygen().unwrap();
            let pk_bytes = pk.as_bytes().to_vec();
            let addr = derive_eoa_address(&pk_bytes);

            let msg = create_view_change(10, &QuorumCert::empty(), i, addr, &sk).unwrap();
            messages.push(msg);
            keys.push(pk_bytes);
        }

        while keys.len() < 128 {
            keys.push(vec![0; 897]);
        }

        let vc_qc = try_form_view_change_qc(10, &messages, &keys);
        assert!(vc_qc.is_none());
    }

    // ========== audit 234: dynamic-threshold view-change QC ==========

    /// Verify view-change QC forms with the BFT threshold for a
    /// small (devnet) committee. Pre-fix this used the hardcoded
    /// production threshold of 86, making view-change unable to
    /// recover any committee smaller than 86 validators.
    #[test]
    fn view_change_qc_dynamic_threshold_small_committee() {
        // 4-validator committee — quorum_for_committee(4) = ceil(8/3) = 3.
        let mut messages = Vec::new();
        let mut keys = Vec::new();
        for i in 0..3u8 {
            let (pk, sk) = falcon_keygen().unwrap();
            let pk_bytes = pk.as_bytes().to_vec();
            let addr = derive_eoa_address(&pk_bytes);
            let msg = create_view_change(7, &QuorumCert::empty(), i, addr, &sk).unwrap();
            messages.push(msg);
            keys.push(pk_bytes);
        }
        // Pad to a 4th key — we have 3 valid messages, 4 committee slots.
        let (pk4, _) = falcon_keygen().unwrap();
        keys.push(pk4.as_bytes().to_vec());

        // 3 valid view-change messages, committee_size=4, threshold=3 → QC.
        let vc_qc = try_form_view_change_qc(7, &messages, &keys);
        assert!(
            vc_qc.is_some(),
            "3 valid view-change messages on a 4-validator committee should form a QC (threshold 3)"
        );
        assert_eq!(vc_qc.unwrap().vote_count, 3);
    }

    /// Below-threshold view-change for a small committee must NOT
    /// form a QC.
    #[test]
    fn view_change_qc_dynamic_threshold_below_quorum() {
        // 4-validator committee: 2 messages, threshold 3 → no QC.
        let mut messages = Vec::new();
        let mut keys = Vec::new();
        for i in 0..2u8 {
            let (pk, sk) = falcon_keygen().unwrap();
            let pk_bytes = pk.as_bytes().to_vec();
            let addr = derive_eoa_address(&pk_bytes);
            let msg = create_view_change(7, &QuorumCert::empty(), i, addr, &sk).unwrap();
            messages.push(msg);
            keys.push(pk_bytes);
        }
        for _ in 0..2 {
            let (pk, _) = falcon_keygen().unwrap();
            keys.push(pk.as_bytes().to_vec());
        }
        let vc_qc = try_form_view_change_qc(7, &messages, &keys);
        assert!(
            vc_qc.is_none(),
            "2 view-change messages on a 4-validator committee must NOT form a QC (threshold 3)"
        );
    }

    // ========== Task 0494: Multiple consecutive failures ==========

    #[test]
    fn fallback_proposer_is_second_lowest() {
        let scores = vec![([0x01; 32], 100), ([0x02; 32], 200), ([0x03; 32], 300)];
        let fallback = fallback_proposer(&scores).unwrap();
        assert_eq!(fallback, [0x02; 32]); // 2nd lowest
    }

    // ===== audit-234 part 4: (height, view) leader + fallback proof =====

    #[test]
    fn fallback_leader_index_deterministic_per_height_view() {
        // Same (H, V) → same leader, regardless of call order.
        for n in [3usize, 4, 7, 16, 128] {
            for h in [0u64, 1, 5, 145, 1_000_000] {
                for v in [0u64, 1, 2, 5] {
                    let a = fallback_leader_index(h, v, n);
                    let b = fallback_leader_index(h, v, n);
                    assert_eq!(a, b, "non-deterministic at (H={h}, V={v}, n={n})");
                    assert!(a < n, "leader index out of range at (H={h}, V={v}, n={n})");
                }
            }
        }
    }

    #[test]
    fn fallback_leader_index_rotates_within_height() {
        // Different views for the same height pick different leaders
        // (within one full rotation). After n bumps the cycle repeats,
        // which is fine — the chain only needs at most f failed views
        // to reach an honest leader.
        let n = 4;
        let h = 145;
        let leaders: std::collections::HashSet<usize> =
            (0..(n as u64)).map(|v| fallback_leader_index(h, v, n)).collect();
        assert_eq!(
            leaders.len(),
            n,
            "n consecutive views should cover every committee slot exactly once"
        );
    }

    #[test]
    fn fallback_leader_index_zero_committee_safe() {
        // Defensive: no panic on degenerate committee.
        assert_eq!(fallback_leader_index(5, 0, 0), 0);
    }

    #[test]
    fn fallback_proof_roundtrip() {
        let proof = encode_fallback_proof(145, 3);
        assert!(is_fallback_proof(&proof));
        let decoded = decode_fallback_proof(&proof).expect("must decode");
        assert_eq!(decoded, (145, 3));
    }

    #[test]
    fn decode_fallback_proof_rejects_non_fallback() {
        // VRF-shaped data (no fallback marker) returns None.
        let vrf_like = vec![0xAB; 96];
        assert!(decode_fallback_proof(&vrf_like).is_none());
    }

    #[test]
    fn decode_fallback_proof_rejects_truncated() {
        // Marker present but missing the view u64.
        let mut truncated = FALLBACK_PROPOSAL_MARKER.to_vec();
        truncated.extend_from_slice(&145u64.to_le_bytes()); // slot only, no view
        assert!(is_fallback_proof(&truncated));
        assert!(decode_fallback_proof(&truncated).is_none());
    }

    #[test]
    fn empty_block_when_all_fail() {
        let header = empty_block_header(
            42,
            0,
            [0xAA; 32],
            QuorumCert::empty(),
            [0xBB; 32],
            1_000_000,
        );
        assert_eq!(header.slot, 42);
        assert_eq!(header.proposer, [0u8; 32]); // no proposer
        assert_eq!(header.tx_root, [0u8; 32]); // no txs
    }

    // ========== Task 0495: Safety preserved ==========

    #[test]
    fn view_change_qc_tracks_highest_qc() {
        let mut messages = Vec::new();
        let mut keys = Vec::new();

        for i in 0..86u8 {
            let (pk, sk) = falcon_keygen().unwrap();
            let pk_bytes = pk.as_bytes().to_vec();
            let addr = derive_eoa_address(&pk_bytes);

            // Validators report different highest QCs
            let qc = QuorumCert {
                slot: i as u64, // different QC slots
                block_hash: [i; 32],
                voter_bitmap: (1u128 << 86) - 1,
                signatures: vec![],
            };

            let msg = create_view_change(100, &qc, i, addr, &sk).unwrap();
            messages.push(msg);
            keys.push(pk_bytes);
        }

        while keys.len() < 128 {
            keys.push(vec![0; 897]);
        }

        let vc_qc = try_form_view_change_qc(100, &messages, &keys).unwrap();
        // Should pick the highest QC (slot 85)
        assert_eq!(vc_qc.highest_qc.slot, 85);
    }

    // ========== Timeout tracker ==========

    #[test]
    fn not_expired_before_200ms() {
        let tracker = TimeoutTracker::new(5, 1000);
        // At 1199ms (199ms elapsed) → not expired
        assert!(!tracker.is_expired(1199));
    }

    #[test]
    fn expired_at_200ms() {
        let tracker = TimeoutTracker::new(5, 1000);
        // At 1200ms (200ms elapsed) → expired
        assert!(tracker.is_expired(1200));
    }

    #[test]
    fn expired_well_past_200ms() {
        let tracker = TimeoutTracker::new(5, 1000);
        assert!(tracker.is_expired(5000));
    }

    #[test]
    fn timeout_cancelled_by_proposal() {
        let mut tracker = TimeoutTracker::new(5, 1000);
        tracker.receive_proposal();
        // Even past 200ms, not expired because proposal received
        assert!(!tracker.is_expired(2000));
    }

    #[test]
    fn slot_elapsed_at_400ms() {
        let tracker = TimeoutTracker::new(5, 1000);
        assert!(!tracker.slot_elapsed(1399)); // 399ms
        assert!(tracker.slot_elapsed(1400)); // 400ms
    }

    #[test]
    fn ms_until_timeout() {
        let tracker = TimeoutTracker::new(5, 1000);
        assert_eq!(tracker.ms_until_timeout(1000), 200); // just started
        assert_eq!(tracker.ms_until_timeout(1100), 100); // 100ms in
        assert_eq!(tracker.ms_until_timeout(1200), 0); // at timeout
        assert_eq!(tracker.ms_until_timeout(1500), 0); // past timeout
    }
}
