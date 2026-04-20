//! Property tests for multisig wire formats + logic invariants
//! (slice 4.5).

use proptest::prelude::*;
use pyde_tx::multisig::{
    count_valid_sigs, decode_signer_set, encode_signer_set, MultisigPayload, MultisigRotate,
    MultisigSpend, SigEntry, MAX_SIGNERS,
};

fn any_address() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

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

fn any_pk_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 897..=897)
}

fn any_signer_set() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(any_pk_bytes(), 1..=MAX_SIGNERS as usize)
}

proptest! {
    /// Spend payload encode→decode roundtrip for arbitrary fields.
    #[test]
    fn spend_payload_roundtrip(
        target in any_address(),
        value in any::<u128>(),
        digest in any_address(),
        sigs in any_sig_slate(),
    ) {
        let payload = MultisigPayload::Spend {
            spend: MultisigSpend { target, value, data_digest: digest },
            sigs,
        };
        let bytes = payload.encode();
        let decoded = MultisigPayload::decode(&bytes).unwrap();
        prop_assert_eq!(payload, decoded);
    }

    /// Rotate payload encode→decode roundtrip.
    #[test]
    fn rotate_payload_roundtrip(
        new_pks in any_signer_set(),
        new_threshold in 1u8..=MAX_SIGNERS,
        sigs in any_sig_slate(),
    ) {
        let payload = MultisigPayload::Rotate {
            rotate: MultisigRotate {
                new_signer_pks: new_pks,
                new_threshold,
            },
            sigs,
        };
        let bytes = payload.encode();
        let decoded = MultisigPayload::decode(&bytes).unwrap();
        prop_assert_eq!(payload, decoded);
    }

    /// Decoder must never panic on arbitrary input.
    #[test]
    fn multisig_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..=8192)) {
        let _ = MultisigPayload::decode(&bytes);
    }

    /// Signer-set encode→decode roundtrip.
    #[test]
    fn signer_set_roundtrip(pks in any_signer_set()) {
        let bytes = encode_signer_set(&pks);
        let decoded = decode_signer_set(&bytes).unwrap();
        prop_assert_eq!(pks, decoded);
    }

    /// Signer-set decoder robustness.
    #[test]
    fn signer_set_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..=20_000)) {
        let _ = decode_signer_set(&bytes);
    }

    /// Spend signing_bytes must differ whenever ANY field differs
    /// (nonce, target, value, digest). A sig authorizing spend X must
    /// not verify as authorization for spend Y.
    #[test]
    fn spend_signing_bytes_distinguish_fields(
        n1 in 0u64..u64::MAX,
        n2 in 0u64..u64::MAX,
        t1 in any_address(),
        t2 in any_address(),
        v1 in any::<u128>(),
        v2 in any::<u128>(),
        d1 in any_address(),
        d2 in any_address(),
    ) {
        prop_assume!((n1, t1, v1, d1) != (n2, t2, v2, d2));
        let s1 = MultisigSpend { target: t1, value: v1, data_digest: d1 };
        let s2 = MultisigSpend { target: t2, value: v2, data_digest: d2 };
        prop_assert_ne!(s1.signing_bytes(n1), s2.signing_bytes(n2));
    }

    /// Rotate signing_bytes must differ whenever the new set or
    /// threshold or nonce differs. Protects against signer
    /// authorizing one new set and having the sig reused to install
    /// a different set.
    #[test]
    fn rotate_signing_bytes_distinguish_fields(
        n1 in 0u64..u64::MAX,
        n2 in 0u64..u64::MAX,
        pks1 in any_signer_set(),
        pks2 in any_signer_set(),
        t1 in 1u8..=MAX_SIGNERS,
        t2 in 1u8..=MAX_SIGNERS,
    ) {
        prop_assume!((n1, pks1.clone(), t1) != (n2, pks2.clone(), t2));
        let r1 = MultisigRotate { new_signer_pks: pks1, new_threshold: t1 };
        let r2 = MultisigRotate { new_signer_pks: pks2, new_threshold: t2 };
        prop_assert_ne!(r1.signing_bytes(n1), r2.signing_bytes(n2));
    }

    /// `count_valid_sigs` must reject any slate with duplicate
    /// signer_index. This is the anti-replay defense — without it,
    /// one signer could fill half the quorum by submitting their own
    /// sig twice under distinct slate positions.
    #[test]
    fn count_valid_sigs_rejects_any_duplicate(
        dup_idx in 0u8..MAX_SIGNERS,
        other in any_sig_entry(),
        pks in any_signer_set(),
    ) {
        let msg = [0u8; 32];
        let dup_a = SigEntry { signer_index: dup_idx, signature: vec![0xAB; 666] };
        let dup_b = SigEntry { signer_index: dup_idx, signature: vec![0xCD; 666] };
        // Put the duplicate pair anywhere in the slate; always error.
        for slate in [
            vec![dup_a.clone(), dup_b.clone()],
            vec![dup_a.clone(), other.clone(), dup_b.clone()],
            vec![other.clone(), dup_a.clone(), dup_b.clone()],
        ] {
            let result = count_valid_sigs(&slate, &pks, &msg);
            prop_assert!(result.is_err(), "duplicate index must error");
        }
    }

    /// `count_valid_sigs` must reject any signer_index >= MAX_SIGNERS
    /// regardless of how many pks are configured.
    #[test]
    fn count_valid_sigs_rejects_over_max_index(
        bad_idx in MAX_SIGNERS..=u8::MAX,
        pks in any_signer_set(),
    ) {
        let entry = SigEntry { signer_index: bad_idx, signature: vec![0xAB; 666] };
        let result = count_valid_sigs(&[entry], &pks, &[0u8; 32]);
        prop_assert!(result.is_err());
    }
}
