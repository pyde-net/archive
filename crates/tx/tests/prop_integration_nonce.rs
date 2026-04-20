//! Integration property tests: nonce invariants (slice 5.2, plan 053b).
//!
//! Drives arbitrary multisig-signed operations through
//! `execute_transaction_inner` and asserts that the on-chain
//! `multisig_nonce` counter advances in lockstep with the number of
//! successful emergency/rotate/spend operations — and never on
//! failure.

mod common;

use common::*;
use proptest::prelude::*;
use pyde_state::smt::PydeSMT;
use pyde_tx::multisig;
use pyde_tx::pipeline::{execute_transaction, read_multisig_nonce};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Each successful `MultisigTx` must increment the on-chain
    /// `multisig_nonce` by exactly one, and the new nonce must never
    /// wrap (u64 headroom is astronomical). Failed txs leave it
    /// untouched.
    #[test]
    fn spend_nonce_increments_only_on_success(
        n_signers in 2u8..=8,
        threshold in 1u8..=8,
        // Scripted sequence of (good_sig_count) per attempted spend.
        attempts in prop::collection::vec(0u8..=8, 1..=5),
    ) {
        prop_assume!(threshold as u8 <= n_signers);
        let n = n_signers as usize;
        let mut smt = PydeSMT::new();
        let sks = install_multisig(&mut smt, n, threshold, 1_000_000_000);
        let (submitter, sub_sk) = fund_submitter(&mut smt, n, 5_000_000_000_000);

        let ctx = block_ctx(100);

        let mut expected_nonce = 0u64;
        let mut outer_nonce = 0u64;

        for (i, good_sig_count) in attempts.iter().enumerate() {
            let good = (*good_sig_count as usize).min(n);
            let spend = multisig::MultisigSpend {
                // Pick a fresh target per attempt (no submitter-self).
                target: {
                    let mut t = [0u8; 32];
                    t[0] = 0xE0 + (i as u8);
                    t
                },
                value: 1_000,
                data_digest: [0xAA; 32],
            };
            let indices: Vec<u8> = (0..good as u8).collect();
            let sks_slice: Vec<_> = sks[..good].iter().copied().collect();
            let sigs = sign_multisig_spend(&spend, &sks_slice, &indices, expected_nonce);
            let payload = multisig::MultisigPayload::Spend { spend, sigs };
            let tx = build_multisig_tx(submitter, sub_sk, payload.encode(), outer_nonce);
            outer_nonce += 1;

            let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();

            let valid_threshold_met = good >= threshold as usize;
            if valid_threshold_met {
                prop_assert!(receipt.success, "should have succeeded with {} valid sigs", good);
                expected_nonce += 1;
            } else {
                prop_assert!(!receipt.success, "should have failed with {} valid sigs", good);
                // nonce UNCHANGED on failure
            }

            prop_assert_eq!(
                read_multisig_nonce(&smt),
                expected_nonce,
                "multisig nonce drift after step {}",
                i
            );
        }
    }

    /// `RotateMultisig` obeys the same nonce discipline: success bumps
    /// the counter, failure doesn't.
    #[test]
    fn rotate_nonce_increments_only_on_success(
        n_signers in 2u8..=8,
        threshold in 1u8..=8,
        good_sigs in 0u8..=8,
    ) {
        prop_assume!(threshold as u8 <= n_signers);
        let n = n_signers as usize;
        let good = (good_sigs as usize).min(n);

        let mut smt = PydeSMT::new();
        let sks = install_multisig(&mut smt, n, threshold, 1_000_000_000);
        let (submitter, sub_sk) = fund_submitter(&mut smt, n, 5_000_000_000_000);
        let ctx = block_ctx(100);

        // Use the next pool member for the new signer.
        let new_pk = pool()[n + 1].0.as_bytes().to_vec();
        let rotate = multisig::MultisigRotate {
            new_signer_pks: vec![new_pk],
            new_threshold: 1,
        };
        let msg = rotate.signing_bytes(0);
        let indices: Vec<u8> = (0..good as u8).collect();
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
        let payload = multisig::MultisigPayload::Rotate { rotate, sigs };

        let mut tx = pyde_tx::types::Transaction {
            from: submitter,
            to: [0u8; 32],
            value: 0,
            data: payload.encode(),
            gas_limit: 2_000_000,
            nonce: 0,
            signature: vec![],
            fee_payer: pyde_tx::types::FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: pyde_tx::types::TransactionType::RotateMultisig,
        };
        sign_outer_tx(&mut tx, sub_sk);

        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        let expected_success = good >= threshold as usize;
        if expected_success {
            prop_assert!(receipt.success);
            prop_assert_eq!(read_multisig_nonce(&smt), 1);
        } else {
            prop_assert!(!receipt.success);
            prop_assert_eq!(read_multisig_nonce(&smt), 0);
        }
    }

    /// EmergencyPause + Resume sequence: each success bumps nonce by 1.
    #[test]
    fn emergency_nonce_progression(
        n_signers in 2u8..=6,
        threshold in 2u8..=6,
        duration in 10u64..=1_000_000,
    ) {
        prop_assume!(threshold as u8 <= n_signers);
        let n = n_signers as usize;
        let mut smt = PydeSMT::new();
        let sks = install_multisig(&mut smt, n, threshold, 1_000_000_000);
        let (submitter, sub_sk) = fund_submitter(&mut smt, n, 5_000_000_000_000);
        let ctx = block_ctx(100);

        // Pause with full threshold.
        let indices: Vec<u8> = (0..threshold).collect();
        let sks_thr: Vec<_> = sks[..threshold as usize].iter().copied().collect();
        let pause_sigs = sign_pause(duration, &sks_thr, &indices, 0);
        let pause_payload = multisig::EmergencyPausePayload {
            duration_slots: duration,
            sigs: pause_sigs,
        };
        let pause_tx = build_pause_tx(submitter, sub_sk, pause_payload.encode(), 0);
        let r1 = execute_transaction(&pause_tx, &mut smt, &ctx).unwrap();
        prop_assert!(r1.success);
        prop_assert_eq!(read_multisig_nonce(&smt), 1, "pause must bump nonce once");

        // Resume with full threshold.
        let resume_sigs = sign_resume(&sks_thr, &indices, 1);
        let resume_payload = multisig::EmergencyResumePayload { sigs: resume_sigs };
        let resume_tx = build_resume_tx(submitter, sub_sk, resume_payload.encode(), 1);
        let r2 = execute_transaction(&resume_tx, &mut smt, &ctx).unwrap();
        prop_assert!(r2.success);
        prop_assert_eq!(read_multisig_nonce(&smt), 2, "resume must bump nonce once");
    }
}
