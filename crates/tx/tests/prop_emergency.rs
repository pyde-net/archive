//! Property tests for emergency pause/resume wire formats (slice 4.6).

use proptest::prelude::*;
use pyde_tx::multisig::{EmergencyPausePayload, EmergencyResumePayload, SigEntry, MAX_SIGNERS};

/// Strategy: generate a `SigEntry` with any valid signer_index + a
/// signature-sized byte vec within the range FalconSignature accepts
/// (500..=1000). We don't need real FALCON sigs to test wire-format
/// roundtrip — just bytes of valid length.
fn any_sig_entry() -> impl Strategy<Value = SigEntry> {
    (0u8..MAX_SIGNERS, 500usize..=1000).prop_flat_map(|(idx, len)| {
        prop::collection::vec(any::<u8>(), len..=len).prop_map(move |bytes| SigEntry {
            signer_index: idx,
            signature: bytes,
        })
    })
}

fn any_sig_slate() -> impl Strategy<Value = Vec<SigEntry>> {
    prop::collection::vec(any_sig_entry(), 1..=MAX_SIGNERS as usize)
}

proptest! {
    /// Encode then decode should yield an identical payload for any
    /// syntactically valid input. Guards against off-by-one cursor
    /// bugs in the length-prefixed sig array.
    #[test]
    fn pause_payload_roundtrip(duration in 1u64..=10_000_000, sigs in any_sig_slate()) {
        let payload = EmergencyPausePayload {
            duration_slots: duration,
            sigs,
        };
        let bytes = payload.encode();
        let decoded = EmergencyPausePayload::decode(&bytes).unwrap();
        prop_assert_eq!(payload, decoded);
    }

    #[test]
    fn resume_payload_roundtrip(sigs in any_sig_slate()) {
        let payload = EmergencyResumePayload { sigs };
        let bytes = payload.encode();
        let decoded = EmergencyResumePayload::decode(&bytes).unwrap();
        prop_assert_eq!(payload, decoded);
    }

    /// Decoders must never panic on arbitrary bytes. Malformed inputs
    /// return None; well-formed inputs parse. No input should trigger
    /// an index-out-of-bounds or allocation panic.
    #[test]
    fn pause_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..=4096)) {
        let _ = EmergencyPausePayload::decode(&bytes);
    }

    #[test]
    fn resume_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..=4096)) {
        let _ = EmergencyResumePayload::decode(&bytes);
    }

    /// Cross-action decoding must reject: pause bytes decoded as resume
    /// (and vice versa) returns None. Protects against a caller
    /// accidentally feeding a pause payload to the resume handler.
    #[test]
    fn pause_bytes_reject_resume_decode(
        duration in 1u64..=10_000_000,
        sigs in any_sig_slate(),
    ) {
        let payload = EmergencyPausePayload {
            duration_slots: duration,
            sigs,
        };
        let bytes = payload.encode();
        prop_assert!(EmergencyResumePayload::decode(&bytes).is_none());
    }

    #[test]
    fn resume_bytes_reject_pause_decode(sigs in any_sig_slate()) {
        let payload = EmergencyResumePayload { sigs };
        let bytes = payload.encode();
        prop_assert!(EmergencyPausePayload::decode(&bytes).is_none());
    }

    /// Pause signing_bytes must differ whenever ANY of (nonce, duration)
    /// differ. This is what binds signatures to a specific execution;
    /// if two distinct nonce/duration pairs produced the same hash, a
    /// signature for one could be replayed as authorization for the
    /// other.
    #[test]
    fn pause_signing_bytes_distinguish_nonce_duration(
        n1 in 0u64..u64::MAX,
        n2 in 0u64..u64::MAX,
        d1 in 1u64..=10_000_000,
        d2 in 1u64..=10_000_000,
    ) {
        // Skip the identity case — duplicate inputs produce duplicate bytes
        // and that's expected.
        prop_assume!((n1, d1) != (n2, d2));
        let p1 = EmergencyPausePayload { duration_slots: d1, sigs: vec![] };
        let p2 = EmergencyPausePayload { duration_slots: d2, sigs: vec![] };
        prop_assert_ne!(p1.signing_bytes(n1), p2.signing_bytes(n2));
    }

    /// Resume signing_bytes must differ by nonce.
    #[test]
    fn resume_signing_bytes_distinguish_nonce(
        n1 in 0u64..u64::MAX,
        n2 in 0u64..u64::MAX,
    ) {
        prop_assume!(n1 != n2);
        prop_assert_ne!(
            EmergencyResumePayload::signing_bytes(n1),
            EmergencyResumePayload::signing_bytes(n2)
        );
    }

    /// Pause vs resume bytes must never collide. Signatures for a
    /// pause action must not verify as a resume (or vice versa) — the
    /// action label in the signed preimage is what prevents this.
    #[test]
    fn pause_resume_signing_bytes_never_collide(
        nonce in 0u64..u64::MAX,
        duration in 1u64..=10_000_000,
    ) {
        let pause_bytes =
            EmergencyPausePayload { duration_slots: duration, sigs: vec![] }.signing_bytes(nonce);
        let resume_bytes = EmergencyResumePayload::signing_bytes(nonce);
        prop_assert_ne!(pause_bytes, resume_bytes);
    }
}
