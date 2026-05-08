//! FALCON peer-authentication protocol (tasks 029 + 030).
//!
//! Binds a libp2p `PeerId` to a FALCON-512 pubkey via challenge-response, so
//! the node layer can enforce validator-only access to the consensus topic.
//!
//! ## Flow
//!
//! 1. When a connection is established, the initiator sends `PydeAuthReq`
//!    containing a random 32-byte nonce.
//! 2. The responder signs `nonce || peer_id_bytes` with their FALCON secret
//!    key and replies with `PydeAuthResp { falcon_pubkey, signature }`.
//! 3. The initiator verifies the signature against `falcon_pubkey`. On
//!    success, the PeerId↔FALCON-pubkey binding is recorded in
//!    `PeerManager`. On failure, the peer is marked `PeerRole::Unknown`
//!    and will be ignored by the consensus-topic filter.
//!
//! ## What this protocol does NOT do
//!
//! - It does not prove the FALCON pubkey belongs to a committee member —
//!   the node layer checks `attested_pubkey ∈ committee_keys` separately.
//!   A non-validator with a valid FALCON keypair can still attest; they
//!   just won't pass the committee filter.
//! - It does not authorize RPC submissions — that path uses task 028's
//!   on-chain auth_key lookup (see `pyde-mempool::pool::add_with_pubkey`).
//!
//! Transport confidentiality is handled by libp2p's noise/QUIC layer; this
//! module runs on top of that already-encrypted channel.

use crate::peer::PeerManager;
use libp2p::StreamProtocol;
use libp2p::{request_response, PeerId};
use pyde_crypto::falcon::{
    falcon_sign, falcon_verify, FalconPublicKey, FalconSecretKey, FalconSignature,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Protocol name for the FALCON peer-auth handshake.
pub const AUTH_PROTOCOL: StreamProtocol = StreamProtocol::new("/pyde/auth/1");

/// Handshake request: initiator sends a fresh random nonce.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PydeAuthReq {
    /// 32 random bytes picked by the initiator. The responder signs
    /// `nonce || peer_id_bytes`, so replaying an older nonce against a
    /// different peer produces a sig that won't verify.
    pub nonce: [u8; 32],
}

/// Handshake response: responder's FALCON pubkey + FALCON sig over the
/// `build_attestation_message(nonce, peer_id_bytes)` payload.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PydeAuthResp {
    /// FALCON-512 public key bytes. ~897 bytes for standard FALCON-512.
    pub falcon_pubkey: Vec<u8>,
    /// FALCON-512 signature over `build_attestation_message(req.nonce, responder_peer_id)`.
    pub signature: Vec<u8>,
}

/// Canonical attestation payload the responder signs.
///
/// Returns `nonce || peer_id_bytes`. Fixing the layout here prevents the
/// initiator and responder from disagreeing about the signed content.
pub fn build_attestation_message(nonce: &[u8; 32], peer_id_bytes: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + peer_id_bytes.len());
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(peer_id_bytes);
    buf
}

/// Produce a signed `PydeAuthResp` for an incoming `PydeAuthReq`.
pub fn build_auth_resp(
    req: &PydeAuthReq,
    responder_peer_id_bytes: &[u8],
    falcon_sk: &FalconSecretKey,
    falcon_pk: &FalconPublicKey,
) -> Result<PydeAuthResp, String> {
    let msg = build_attestation_message(&req.nonce, responder_peer_id_bytes);
    let sig = falcon_sign(falcon_sk, &msg).map_err(|e| format!("falcon_sign failed: {:?}", e))?;
    Ok(PydeAuthResp {
        falcon_pubkey: falcon_pk.as_bytes().to_vec(),
        signature: sig.to_vec(),
    })
}

/// Verify a `PydeAuthResp` against the request that produced it.
///
/// Returns the verified FALCON pubkey on success. On any failure (malformed
/// pubkey, malformed sig, verification mismatch) returns `None` and the
/// caller must NOT record the binding.
pub fn verify_auth_resp(
    req: &PydeAuthReq,
    resp: &PydeAuthResp,
    responder_peer_id_bytes: &[u8],
) -> Option<Vec<u8>> {
    let pk = FalconPublicKey::from_bytes(&resp.falcon_pubkey)?;
    let sig = FalconSignature::from_bytes(&resp.signature)?;
    let msg = build_attestation_message(&req.nonce, responder_peer_id_bytes);
    if falcon_verify(&pk, &msg, &sig) {
        Some(resp.falcon_pubkey.clone())
    } else {
        None
    }
}

/// Create the libp2p request-response behaviour for the FALCON auth protocol.
pub fn auth_behaviour() -> request_response::cbor::Behaviour<PydeAuthReq, PydeAuthResp> {
    request_response::cbor::Behaviour::new(
        [(AUTH_PROTOCOL, request_response::ProtocolSupport::Full)],
        request_response::Config::default(),
    )
}

/// Generate a fresh 32-byte nonce for an auth request.
pub fn generate_nonce() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    buf
}

/// Outcome of `apply_auth_response`, exported for telemetry + testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// No pending nonce matched this peer — response is spurious or stale.
    NoPendingNonce,
    /// FALCON signature verification failed (wrong pubkey, bad sig,
    /// replay, malformed fields).
    VerifyFailed,
    /// Peer previously attested a DIFFERENT pubkey on the same connection.
    /// Treated as a protocol violation; the caller should disconnect.
    RebindRejected,
    /// TPL-510: the peer's PeerId has an operator-pinned FALCON
    /// pubkey in `Discovery::pinned_falcon_pubkey`, but the
    /// attested pubkey doesn't match. Either the pin is wrong,
    /// the pinned peer rotated keys without operator coordination,
    /// or the peer at this `(IP, port, libp2p-noise-id)` tuple is
    /// an impostor that doesn't hold the expected FALCON sk.
    /// Caller should hard-disconnect — the safety property of
    /// pinning is "no acceptance under wrong identity."
    PinnedPubkeyMismatch,
    /// Pubkey recorded in the peer manager and matched an entry in
    /// `committee_keys` — peer was promoted to `PeerRole::Validator`.
    StoredAsValidator,
    /// Pubkey recorded but not in `committee_keys`. The peer can still
    /// forward non-consensus traffic; the consensus filter (task 030)
    /// will drop any consensus messages they try to publish.
    StoredAsNonValidator,
}

/// Apply an incoming `PydeAuthResp` end-to-end: consume the pending
/// nonce, verify, and update peer state. Returns a structured outcome
/// so the node layer can log + emit metrics without a tangle of nested
/// match arms in the swarm-event handler.
///
/// This is the testable seam for the handshake-response path — the
/// node layer's swarm handler is purely the wire glue around this.
/// Committee membership is resolved by byte-level equality with
/// `committee_keys`, matching the rule used by
/// `PeerManager::is_consensus_authorized`.
///
/// TPL-510: `pinned_falcon_pubkey` is the operator-supplied
/// FALCON pubkey pin for this peer (resolved via
/// `Discovery::pinned_falcon_pubkey` at the call site). When
/// supplied, the attested pubkey MUST byte-match — a mismatch
/// returns `AuthOutcome::PinnedPubkeyMismatch` and the caller
/// hard-disconnects. `None` preserves the prior "trust whatever
/// the peer attests" behavior for peers without a configured
/// pin.
pub fn apply_auth_response(
    peer: PeerId,
    response: &PydeAuthResp,
    pending_auth_nonces: &mut HashMap<PeerId, [u8; 32]>,
    peer_manager: &mut PeerManager,
    committee_keys: &[Vec<u8>],
    pinned_falcon_pubkey: Option<&[u8]>,
) -> AuthOutcome {
    let nonce = match pending_auth_nonces.remove(&peer) {
        Some(n) => n,
        None => return AuthOutcome::NoPendingNonce,
    };
    let req = PydeAuthReq { nonce };

    // Responder signs over (nonce || derive_eoa_address(pubkey)).
    // Computing the EOA from the attested pubkey closes the loop: a
    // captured attestation can't be re-presented for a different EOA
    // without breaking the signature.
    let derived_addr = pyde_account::address::derive_eoa_address(&response.falcon_pubkey);
    let pk_bytes = match verify_auth_resp(&req, response, &derived_addr) {
        Some(pk) => pk,
        None => return AuthOutcome::VerifyFailed,
    };

    // TPL-510: bootstrap pubkey pinning. Check BEFORE
    // recording the pubkey on `peer_manager` so a mismatch
    // doesn't pollute the manager's state with a key that the
    // caller will then have to disconnect. Byte-equality match
    // mirrors `is_consensus_authorized`'s comparison rule.
    if let Some(expected_pk) = pinned_falcon_pubkey {
        if expected_pk != pk_bytes.as_slice() {
            return AuthOutcome::PinnedPubkeyMismatch;
        }
    }

    if !peer_manager.set_falcon_pubkey(&peer, pk_bytes.clone()) {
        return AuthOutcome::RebindRejected;
    }

    let in_committee = committee_keys
        .iter()
        .any(|ck| ck.as_slice() == pk_bytes.as_slice());
    if in_committee {
        peer_manager.mark_validator(&peer);
        AuthOutcome::StoredAsValidator
    } else {
        AuthOutcome::StoredAsNonValidator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_crypto::falcon::falcon_keygen;

    const PEER_ID_A: &[u8] = b"peer-id-A-arbitrary-multihash";
    const PEER_ID_B: &[u8] = b"peer-id-B-arbitrary-multihash";

    #[test]
    fn nonces_are_unique() {
        let a = generate_nonce();
        let b = generate_nonce();
        assert_ne!(a, b, "entropy source broken");
    }

    #[test]
    fn honest_handshake_roundtrips() {
        let (pk, sk) = falcon_keygen().unwrap();
        let req = PydeAuthReq {
            nonce: generate_nonce(),
        };
        let resp = build_auth_resp(&req, PEER_ID_A, &sk, &pk).unwrap();

        let verified = verify_auth_resp(&req, &resp, PEER_ID_A).unwrap();
        assert_eq!(verified, pk.as_bytes().to_vec());
    }

    #[test]
    fn verify_rejects_replay_under_different_peer_id() {
        // Captured attestation from PEER_A cannot be replayed by someone
        // claiming to be PEER_B — the signed message includes peer_id.
        let (pk, sk) = falcon_keygen().unwrap();
        let req = PydeAuthReq {
            nonce: generate_nonce(),
        };
        let resp = build_auth_resp(&req, PEER_ID_A, &sk, &pk).unwrap();

        assert!(verify_auth_resp(&req, &resp, PEER_ID_B).is_none());
    }

    #[test]
    fn verify_rejects_stale_nonce() {
        let (pk, sk) = falcon_keygen().unwrap();
        let req_signed = PydeAuthReq { nonce: [0x11; 32] };
        let resp = build_auth_resp(&req_signed, PEER_ID_A, &sk, &pk).unwrap();

        // Fresh request with a different nonce — responder's old sig
        // should NOT verify against it.
        let req_current = PydeAuthReq { nonce: [0x22; 32] };
        assert!(verify_auth_resp(&req_current, &resp, PEER_ID_A).is_none());
    }

    #[test]
    fn verify_rejects_pubkey_mismatch() {
        // Attacker tries to pass off a different pubkey with a valid sig
        // from a different key. The sig won't verify against the swapped pk.
        let (pk_real, sk_real) = falcon_keygen().unwrap();
        let (pk_other, _sk_other) = falcon_keygen().unwrap();

        let req = PydeAuthReq {
            nonce: generate_nonce(),
        };
        let mut resp = build_auth_resp(&req, PEER_ID_A, &sk_real, &pk_real).unwrap();
        // Swap in an unrelated pubkey.
        resp.falcon_pubkey = pk_other.as_bytes().to_vec();

        assert!(verify_auth_resp(&req, &resp, PEER_ID_A).is_none());
    }

    #[test]
    fn verify_rejects_malformed_signature() {
        let (pk, sk) = falcon_keygen().unwrap();
        let req = PydeAuthReq {
            nonce: generate_nonce(),
        };
        let mut resp = build_auth_resp(&req, PEER_ID_A, &sk, &pk).unwrap();
        resp.signature = vec![0u8; 10]; // too short for FALCON-512

        assert!(verify_auth_resp(&req, &resp, PEER_ID_A).is_none());
    }

    #[test]
    fn verify_rejects_malformed_pubkey() {
        let (pk, sk) = falcon_keygen().unwrap();
        let req = PydeAuthReq {
            nonce: generate_nonce(),
        };
        let mut resp = build_auth_resp(&req, PEER_ID_A, &sk, &pk).unwrap();
        resp.falcon_pubkey = vec![0u8; 5]; // too short

        assert!(verify_auth_resp(&req, &resp, PEER_ID_A).is_none());
    }

    #[test]
    fn attestation_message_layout_is_stable() {
        // Future versions must keep compatibility or bump AUTH_PROTOCOL.
        // Lock the byte layout in a test so accidental changes are caught.
        let nonce = [0x42u8; 32];
        let peer = b"peer";
        let msg = build_attestation_message(&nonce, peer);
        assert_eq!(msg.len(), 32 + 4);
        assert_eq!(&msg[..32], &nonce);
        assert_eq!(&msg[32..], peer);
    }

    // ========== apply_auth_response (handshake glue) ==========

    use crate::peer::{Direction, PeerInfo, PeerManager};

    fn fresh_manager_with_peer(id: PeerId) -> PeerManager {
        let mut mgr = PeerManager::new(10, 10, 10, 100);
        mgr.add_peer(PeerInfo::new(id, Direction::Inbound));
        mgr
    }

    /// Build a genuine attestation using the EOA derived from the FALCON
    /// pubkey — matches the convention enforced by `apply_auth_response`.
    fn build_real_attestation(nonce: [u8; 32]) -> (PydeAuthResp, Vec<u8>, FalconSecretKey) {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let eoa = pyde_account::address::derive_eoa_address(&pk_bytes);
        let req = PydeAuthReq { nonce };
        let resp = build_auth_resp(&req, &eoa, &sk, &pk).unwrap();
        (resp, pk_bytes, sk)
    }

    #[test]
    fn apply_auth_response_stores_committee_member_as_validator() {
        let peer = PeerId::random();
        let mut mgr = fresh_manager_with_peer(peer);
        let mut nonces = HashMap::new();
        let nonce = generate_nonce();
        nonces.insert(peer, nonce);

        let (resp, pk_bytes, _sk) = build_real_attestation(nonce);
        let committee = vec![pk_bytes.clone()];

        let outcome = apply_auth_response(peer, &resp, &mut nonces, &mut mgr, &committee, None);
        assert_eq!(outcome, AuthOutcome::StoredAsValidator);
        assert_eq!(mgr.peer_falcon_pubkey(&peer), Some(pk_bytes.as_slice()));
        assert_eq!(
            mgr.get_peer(&peer).unwrap().role,
            crate::peer::PeerRole::Validator
        );
        // Nonce consumed.
        assert!(!nonces.contains_key(&peer));
    }

    #[test]
    fn apply_auth_response_stores_non_committee_peer_as_non_validator() {
        let peer = PeerId::random();
        let mut mgr = fresh_manager_with_peer(peer);
        let mut nonces = HashMap::new();
        let nonce = generate_nonce();
        nonces.insert(peer, nonce);

        let (resp, pk_bytes, _sk) = build_real_attestation(nonce);
        // Empty committee — peer is attested but not in consensus.
        let committee: Vec<Vec<u8>> = vec![];

        let outcome = apply_auth_response(peer, &resp, &mut nonces, &mut mgr, &committee, None);
        assert_eq!(outcome, AuthOutcome::StoredAsNonValidator);
        assert_eq!(mgr.peer_falcon_pubkey(&peer), Some(pk_bytes.as_slice()));
        assert_eq!(
            mgr.get_peer(&peer).unwrap().role,
            crate::peer::PeerRole::Unknown
        );
    }

    #[test]
    fn apply_auth_response_rejects_stale_response() {
        // Peer sends a response but we have no pending nonce for them —
        // likely a stale or spurious message.
        let peer = PeerId::random();
        let mut mgr = fresh_manager_with_peer(peer);
        let mut nonces = HashMap::new(); // nothing for this peer

        let (resp, _, _) = build_real_attestation([0x01; 32]);
        let outcome = apply_auth_response(peer, &resp, &mut nonces, &mut mgr, &[], None);
        assert_eq!(outcome, AuthOutcome::NoPendingNonce);
        assert!(mgr.peer_falcon_pubkey(&peer).is_none());
    }

    #[test]
    fn apply_auth_response_rejects_bad_signature() {
        // Attestation built for a DIFFERENT nonce than the one we sent.
        // Verification fails.
        let peer = PeerId::random();
        let mut mgr = fresh_manager_with_peer(peer);
        let mut nonces = HashMap::new();
        let nonce_we_sent = [0x11; 32];
        nonces.insert(peer, nonce_we_sent);

        let (resp_other_nonce, _, _) = build_real_attestation([0x22; 32]);
        let outcome = apply_auth_response(peer, &resp_other_nonce, &mut nonces, &mut mgr, &[], None);
        assert_eq!(outcome, AuthOutcome::VerifyFailed);
        assert!(mgr.peer_falcon_pubkey(&peer).is_none());
        // Nonce still consumed so the peer can't keep retrying the same slot.
        assert!(!nonces.contains_key(&peer));
    }

    #[test]
    fn apply_auth_response_rejects_rebind_to_different_pubkey() {
        let peer = PeerId::random();
        let mut mgr = fresh_manager_with_peer(peer);

        // First, legitimately attest pubkey A.
        let mut nonces = HashMap::new();
        let nonce_a = generate_nonce();
        nonces.insert(peer, nonce_a);
        let (resp_a, _pk_a, _) = build_real_attestation(nonce_a);
        assert_eq!(
            apply_auth_response(peer, &resp_a, &mut nonces, &mut mgr, &[], None),
            AuthOutcome::StoredAsNonValidator
        );

        // Same peer tries to re-attest with pubkey B on the same connection.
        let nonce_b = generate_nonce();
        nonces.insert(peer, nonce_b);
        let (resp_b, _pk_b, _) = build_real_attestation(nonce_b);
        let outcome = apply_auth_response(peer, &resp_b, &mut nonces, &mut mgr, &[], None);
        assert_eq!(outcome, AuthOutcome::RebindRejected);
    }

    #[test]
    fn apply_auth_response_idempotent_on_duplicate_same_key() {
        // Not every duplicate is malicious — a retry can legitimately
        // re-attest the same key. The set_falcon_pubkey idempotent path
        // lets this succeed without a rebind error.
        let peer = PeerId::random();
        let mut mgr = fresh_manager_with_peer(peer);

        let mut nonces = HashMap::new();
        let nonce_a = [0xA1; 32];
        nonces.insert(peer, nonce_a);
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let eoa = pyde_account::address::derive_eoa_address(&pk_bytes);
        let resp_a = build_auth_resp(&PydeAuthReq { nonce: nonce_a }, &eoa, &sk, &pk).unwrap();
        assert_eq!(
            apply_auth_response(peer, &resp_a, &mut nonces, &mut mgr, &[], None),
            AuthOutcome::StoredAsNonValidator
        );

        // Same peer, same FALCON key, fresh nonce → still accepted.
        let nonce_b = [0xB2; 32];
        nonces.insert(peer, nonce_b);
        let resp_b = build_auth_resp(&PydeAuthReq { nonce: nonce_b }, &eoa, &sk, &pk).unwrap();
        assert_eq!(
            apply_auth_response(peer, &resp_b, &mut nonces, &mut mgr, &[], None),
            AuthOutcome::StoredAsNonValidator
        );
    }

    // ========== TPL-510: bootstrap FALCON pubkey pinning ==========

    /// `apply_auth_response` accepts an attested pubkey when
    /// the operator's pin matches it byte-for-byte.
    #[test]
    fn tpl_510_apply_auth_response_accepts_matching_pin() {
        let peer = PeerId::random();
        let mut mgr = fresh_manager_with_peer(peer);
        let mut nonces = HashMap::new();
        let nonce = generate_nonce();
        nonces.insert(peer, nonce);

        let (resp, pk_bytes, _sk) = build_real_attestation(nonce);

        // Pin is exactly the pubkey the peer is about to attest.
        let outcome =
            apply_auth_response(peer, &resp, &mut nonces, &mut mgr, &[], Some(&pk_bytes));
        assert_eq!(outcome, AuthOutcome::StoredAsNonValidator);
        assert_eq!(mgr.peer_falcon_pubkey(&peer), Some(pk_bytes.as_slice()));
    }

    /// `apply_auth_response` rejects an attested pubkey when
    /// the operator's pin DOES NOT match. The peer manager is
    /// NOT mutated — pre-fix the pubkey check happened before
    /// the pin check, leaving a polluted manager state on a
    /// mismatch.
    #[test]
    fn tpl_510_apply_auth_response_rejects_mismatched_pin() {
        let peer = PeerId::random();
        let mut mgr = fresh_manager_with_peer(peer);
        let mut nonces = HashMap::new();
        let nonce = generate_nonce();
        nonces.insert(peer, nonce);

        let (resp, _pk_bytes, _sk) = build_real_attestation(nonce);

        // Pin a DIFFERENT pubkey than what the peer will attest.
        let (other_pk, _) = falcon_keygen().unwrap();
        let other_pk_bytes = other_pk.as_bytes().to_vec();
        let outcome = apply_auth_response(
            peer,
            &resp,
            &mut nonces,
            &mut mgr,
            &[],
            Some(&other_pk_bytes),
        );
        assert_eq!(outcome, AuthOutcome::PinnedPubkeyMismatch);
        assert!(
            mgr.peer_falcon_pubkey(&peer).is_none(),
            "pin mismatch must NOT leave the rejected pubkey on peer_manager"
        );
        // Nonce IS still consumed — the response was a valid
        // FALCON sig, just not for the pinned identity. No
        // replay-via-stuck-nonce attack.
        assert!(!nonces.contains_key(&peer));
    }

    /// `apply_auth_response` with `None` pin preserves the
    /// pre-TPL-510 behavior — accept any valid attestation.
    /// This is the path for unpinned peers and for operators
    /// who haven't configured pinning at all.
    #[test]
    fn tpl_510_apply_auth_response_no_pin_preserves_prior_behavior() {
        let peer = PeerId::random();
        let mut mgr = fresh_manager_with_peer(peer);
        let mut nonces = HashMap::new();
        let nonce = generate_nonce();
        nonces.insert(peer, nonce);

        let (resp, pk_bytes, _sk) = build_real_attestation(nonce);

        // No pin — accept whatever the peer attests.
        let outcome = apply_auth_response(peer, &resp, &mut nonces, &mut mgr, &[], None);
        assert_eq!(outcome, AuthOutcome::StoredAsNonValidator);
        assert_eq!(mgr.peer_falcon_pubkey(&peer), Some(pk_bytes.as_slice()));
    }
}
