//! Integration property tests: replay immunity (slice 5.2, plan 053b).
//!
//! After a successful multisig-style operation, the on-chain
//! `multisig_nonce` advances. Re-submitting the SAME signed payload
//! against the new nonce must fail because the sigs were bound to the
//! old nonce and no longer verify against the new signing-bytes.

mod common;

use common::*;
use proptest::prelude::*;
use pyde_state::smt::PydeSMT;
use pyde_tx::multisig;
use pyde_tx::pipeline::{execute_transaction, read_multisig_nonce};
use pyde_tx::types::{FeePayer, Transaction, TransactionType};

fn build_rotate_tx(
    submitter: pyde_account::address::Address,
    submitter_sk: &pyde_crypto::falcon::FalconSecretKey,
    payload_bytes: Vec<u8>,
    outer_nonce: u64,
) -> Transaction {
    let mut tx = Transaction {
        from: submitter,
        to: [0u8; 32],
        value: 0,
        data: payload_bytes,
        gas_limit: 2_000_000,
        nonce: outer_nonce,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id: 1,
        tx_type: TransactionType::RotateMultisig,
    };
    sign_outer_tx(&mut tx, submitter_sk);
    tx
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// After a successful `MultisigTx` spend, replaying the same
    /// signed payload at a fresh outer nonce must fail.
    #[test]
    fn spend_replay_rejected(
        n_signers in 2u8..=6,
        threshold in 1u8..=6,
        value in 100u128..=100_000,
    ) {
        prop_assume!(threshold as u8 <= n_signers);
        let n = n_signers as usize;
        let t = threshold as usize;

        let mut smt = PydeSMT::new();
        let sks = install_multisig(&mut smt, n, threshold, 1_000_000_000);
        let (submitter, sub_sk) = fund_submitter(&mut smt, n, 10_000_000_000_000);
        let ctx = block_ctx(100);

        let spend = multisig::MultisigSpend {
            target: [0xEE; 32],
            value,
            data_digest: [0xAA; 32],
        };
        let indices: Vec<u8> = (0..t as u8).collect();
        let sks_thr: Vec<_> = sks[..t].iter().copied().collect();
        let sigs = sign_multisig_spend(&spend, &sks_thr, &indices, 0);
        let payload = multisig::MultisigPayload::Spend {
            spend: spend.clone(),
            sigs,
        };
        let payload_bytes = payload.encode();

        // First execution succeeds.
        let tx1 = build_multisig_tx(submitter, sub_sk, payload_bytes.clone(), 0);
        let r1 = execute_transaction(&tx1, &mut smt, &ctx).unwrap();
        prop_assert!(r1.success);
        prop_assert_eq!(read_multisig_nonce(&smt), 1);

        // Replay — same payload bytes, fresh outer nonce.
        let tx2 = build_multisig_tx(submitter, sub_sk, payload_bytes, 1);
        let r2 = execute_transaction(&tx2, &mut smt, &ctx).unwrap();
        prop_assert!(!r2.success, "replay of same signed payload must fail");
        prop_assert_eq!(read_multisig_nonce(&smt), 1, "failed replay must not bump nonce");
    }

    /// After a successful `RotateMultisig`, replay fails. Also
    /// exercises: new signer set is installed, old signers lose
    /// authority immediately.
    #[test]
    fn rotate_replay_rejected(
        n_signers in 2u8..=6,
        threshold in 1u8..=6,
    ) {
        prop_assume!(threshold as u8 <= n_signers);
        let n = n_signers as usize;
        let t = threshold as usize;

        let mut smt = PydeSMT::new();
        let sks = install_multisig(&mut smt, n, threshold, 1_000_000_000);
        let (submitter, sub_sk) = fund_submitter(&mut smt, n, 10_000_000_000_000);
        let ctx = block_ctx(100);

        let new_pk = pool()[n + 1].0.as_bytes().to_vec();
        let rotate = multisig::MultisigRotate {
            new_signer_pks: vec![new_pk],
            new_threshold: 1,
        };
        let msg = rotate.signing_bytes(0);
        let indices: Vec<u8> = (0..t as u8).collect();
        let sigs: Vec<multisig::SigEntry> = indices
            .iter()
            .enumerate()
            .map(|(pos, idx)| multisig::SigEntry {
                signer_index: *idx,
                signature: pyde_crypto::falcon::falcon_sign(sks[pos], &msg)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            })
            .collect();
        let payload = multisig::MultisigPayload::Rotate {
            rotate: rotate.clone(),
            sigs,
        };
        let payload_bytes = payload.encode();

        let tx1 = build_rotate_tx(submitter, sub_sk, payload_bytes.clone(), 0);
        let r1 = execute_transaction(&tx1, &mut smt, &ctx).unwrap();
        prop_assert!(r1.success);
        prop_assert_eq!(read_multisig_nonce(&smt), 1);

        // Replay.
        let tx2 = build_rotate_tx(submitter, sub_sk, payload_bytes, 1);
        let r2 = execute_transaction(&tx2, &mut smt, &ctx).unwrap();
        prop_assert!(!r2.success, "rotate replay must fail");
        prop_assert_eq!(read_multisig_nonce(&smt), 1);
    }

    /// After rotation, a spend signed by the OLD signer set must
    /// fail — the new set has sole authority immediately.
    #[test]
    fn spend_by_old_signers_after_rotation_fails(
        n_signers in 2u8..=6,
        threshold in 1u8..=6,
    ) {
        prop_assume!(threshold as u8 <= n_signers);
        let n = n_signers as usize;
        let t = threshold as usize;

        let mut smt = PydeSMT::new();
        let old_sks = install_multisig(&mut smt, n, threshold, 1_000_000_000);
        let (submitter, sub_sk) = fund_submitter(&mut smt, n, 10_000_000_000_000);
        let ctx = block_ctx(100);

        // Rotate to a fresh single-signer set with threshold 1.
        let new_pk = pool()[n + 1].0.as_bytes().to_vec();
        let rotate = multisig::MultisigRotate {
            new_signer_pks: vec![new_pk],
            new_threshold: 1,
        };
        let rmsg = rotate.signing_bytes(0);
        let rindices: Vec<u8> = (0..t as u8).collect();
        let rsigs: Vec<multisig::SigEntry> = rindices
            .iter()
            .enumerate()
            .map(|(pos, idx)| multisig::SigEntry {
                signer_index: *idx,
                signature: pyde_crypto::falcon::falcon_sign(old_sks[pos], &rmsg)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            })
            .collect();
        let rpayload = multisig::MultisigPayload::Rotate { rotate, sigs: rsigs };
        let rtx = build_rotate_tx(submitter, sub_sk, rpayload.encode(), 0);
        let rr = execute_transaction(&rtx, &mut smt, &ctx).unwrap();
        prop_assert!(rr.success);

        // Attempt a spend signed by the old committee. Nonce is now 1.
        let spend = multisig::MultisigSpend {
            target: [0xCC; 32],
            value: 1_000,
            data_digest: [0xBB; 32],
        };
        let sindices: Vec<u8> = (0..t as u8).collect();
        let sks_thr: Vec<_> = old_sks[..t].iter().copied().collect();
        let sigs = sign_multisig_spend(&spend, &sks_thr, &sindices, 1);
        let spayload = multisig::MultisigPayload::Spend { spend, sigs };
        let stx = build_multisig_tx(submitter, sub_sk, spayload.encode(), 1);
        let sr = execute_transaction(&stx, &mut smt, &ctx).unwrap();
        prop_assert!(
            !sr.success,
            "spend by old signers after rotation must fail"
        );
    }
}
