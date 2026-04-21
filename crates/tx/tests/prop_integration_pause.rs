//! Integration property tests: emergency pause gate + auto-expiry
//! (slice 5.2, plan 053b).
//!
//! While paused, every tx type except `EmergencyResume` must be
//! rejected BEFORE state writes or gas charging. Auto-expiry kicks in
//! at `current_slot >= pause_end_slot` without any explicit resume tx.

mod common;

use common::*;
use proptest::prelude::*;
use pyde_account::address::derive_eoa_address;
use pyde_state::smt::PydeSMT;
use pyde_tx::multisig;
use pyde_tx::pipeline::{execute_transaction, is_paused, read_multisig_nonce};
use pyde_tx::types::{FeePayer, Transaction, TransactionType};

/// Helper: assemble a transfer from pool member 0 to a random target.
fn build_transfer(
    from: pyde_account::address::Address,
    from_sk: &pyde_crypto::falcon::FalconSecretKey,
    to: pyde_account::address::Address,
    value: u128,
    nonce: u64,
) -> Transaction {
    let mut tx = Transaction {
        from,
        to,
        value,
        data: vec![],
        gas_limit: 100_000,
        nonce,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id: 1,
        tx_type: TransactionType::Standard,
    };
    sign_outer_tx(&mut tx, from_sk);
    tx
}

/// Helper: submit a paused-chain spend tx. Returns Result from
/// execute_transaction.
fn attempt_spend(
    smt: &mut PydeSMT,
    sks: &[&pyde_crypto::falcon::FalconSecretKey],
    submitter: pyde_account::address::Address,
    sub_sk: &pyde_crypto::falcon::FalconSecretKey,
    outer_nonce: u64,
    multisig_nonce: u64,
    ctx: &pyde_tx::pipeline::BlockContext,
) -> Result<pyde_tx::execution::Receipt, pyde_tx::pipeline::PipelineError> {
    let spend = multisig::MultisigSpend {
        target: [0xEE; 32],
        value: 1_000,
        data_digest: [0xAA; 32],
    };
    let indices: Vec<u8> = (0..sks.len() as u8).collect();
    let sigs = sign_multisig_spend(&spend, sks, &indices, multisig_nonce);
    let payload = multisig::MultisigPayload::Spend { spend, sigs };
    let tx = build_multisig_tx(submitter, sub_sk, payload.encode(), outer_nonce);
    execute_transaction(&tx, smt, ctx)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// While paused, a standard transfer is rejected with no state
    /// change. The sender's outer nonce is NOT consumed (the pause
    /// gate returns before any pipeline state mutations).
    #[test]
    fn pause_gate_rejects_standard_transfer(
        n_signers in 2u8..=6,
        threshold in 2u8..=6,
        duration in 100u64..=1_000_000,
    ) {
        prop_assume!(threshold <= n_signers);
        let n = n_signers as usize;
        let t = threshold as usize;
        let mut smt = PydeSMT::new();
        let sks = install_multisig(&mut smt, n, threshold, 1_000_000_000);
        let (submitter, sub_sk) = fund_submitter(&mut smt, n, 10_000_000_000_000);
        let ctx = block_ctx(100);

        // Pause.
        let indices: Vec<u8> = (0..t as u8).collect();
        let sks_thr: Vec<_> = sks[..t].to_vec();
        let pause_sigs = sign_pause(duration, &sks_thr, &indices, 0);
        let pause_payload = multisig::EmergencyPausePayload {
            duration_slots: duration,
            sigs: pause_sigs,
        };
        let pause_tx = build_pause_tx(submitter, sub_sk, pause_payload.encode(), 0);
        let r1 = execute_transaction(&pause_tx, &mut smt, &ctx).unwrap();
        prop_assert!(r1.success);
        prop_assert!(is_paused(&smt, ctx.height));

        // Try a vanilla transfer — must be rejected before state mutation.
        let (recv_pk, _) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let recipient = derive_eoa_address(recv_pk.as_bytes());
        let transfer = build_transfer(submitter, sub_sk, recipient, 10, 1);
        let result = execute_transaction(&transfer, &mut smt, &ctx);
        prop_assert!(result.is_err(), "standard transfer must fail during pause");

        // Multisig nonce untouched (pause gate is before any handler).
        prop_assert_eq!(read_multisig_nonce(&smt), 1);
    }

    /// While paused, a `MultisigTx` spend is rejected. Treasury must
    /// not be debited, multisig_nonce must not advance.
    #[test]
    fn pause_gate_rejects_multisig_spend(
        n_signers in 2u8..=6,
        threshold in 2u8..=6,
        duration in 100u64..=1_000_000,
    ) {
        prop_assume!(threshold <= n_signers);
        let n = n_signers as usize;
        let t = threshold as usize;
        let mut smt = PydeSMT::new();
        let sks = install_multisig(&mut smt, n, threshold, 1_000_000_000);
        let (submitter, sub_sk) = fund_submitter(&mut smt, n, 10_000_000_000_000);
        let ctx = block_ctx(100);

        let indices: Vec<u8> = (0..t as u8).collect();
        let sks_thr: Vec<_> = sks[..t].to_vec();
        let pause_sigs = sign_pause(duration, &sks_thr, &indices, 0);
        let pause_payload = multisig::EmergencyPausePayload {
            duration_slots: duration,
            sigs: pause_sigs,
        };
        let pause_tx = build_pause_tx(submitter, sub_sk, pause_payload.encode(), 0);
        execute_transaction(&pause_tx, &mut smt, &ctx).unwrap();

        let treasury_before = pyde_tx::pipeline::load_account(
            &smt,
            &pyde_account::address::treasury_address(),
        )
        .balance;

        let spend_result = attempt_spend(&mut smt, &sks_thr, submitter, sub_sk, 1, 1, &ctx);
        prop_assert!(spend_result.is_err(), "multisig spend must fail during pause");

        let treasury_after = pyde_tx::pipeline::load_account(
            &smt,
            &pyde_account::address::treasury_address(),
        )
        .balance;
        prop_assert_eq!(treasury_before, treasury_after, "treasury must be untouched");
        prop_assert_eq!(read_multisig_nonce(&smt), 1, "pause+0 = 1");
    }

    /// `EmergencyResume` passes the gate while paused and restores
    /// normal operation: `is_paused` clears, multisig_nonce bumps.
    #[test]
    fn pause_gate_passes_resume(
        n_signers in 2u8..=6,
        threshold in 2u8..=6,
        duration in 100u64..=1_000_000,
    ) {
        prop_assume!(threshold <= n_signers);
        let n = n_signers as usize;
        let t = threshold as usize;
        let mut smt = PydeSMT::new();
        let sks = install_multisig(&mut smt, n, threshold, 1_000_000_000);
        let (submitter, sub_sk) = fund_submitter(&mut smt, n, 10_000_000_000_000);
        let ctx = block_ctx(100);

        let indices: Vec<u8> = (0..t as u8).collect();
        let sks_thr: Vec<_> = sks[..t].to_vec();
        let pause_sigs = sign_pause(duration, &sks_thr, &indices, 0);
        let pause_payload = multisig::EmergencyPausePayload {
            duration_slots: duration,
            sigs: pause_sigs,
        };
        let pause_tx = build_pause_tx(submitter, sub_sk, pause_payload.encode(), 0);
        execute_transaction(&pause_tx, &mut smt, &ctx).unwrap();
        prop_assert!(is_paused(&smt, ctx.height));

        let resume_sigs = sign_resume(&sks_thr, &indices, 1);
        let resume_payload = multisig::EmergencyResumePayload { sigs: resume_sigs };
        let resume_tx = build_resume_tx(submitter, sub_sk, resume_payload.encode(), 1);
        let r = execute_transaction(&resume_tx, &mut smt, &ctx).unwrap();
        prop_assert!(r.success);
        prop_assert!(!is_paused(&smt, ctx.height));
        prop_assert_eq!(read_multisig_nonce(&smt), 2);
    }

    /// Auto-expiry: for any valid pause (duration D at slot S), the
    /// chain is paused at slots [S, S+D) and unpaused at slot S+D and
    /// beyond. No resume tx needed.
    #[test]
    fn auto_expiry_boundary(
        n_signers in 2u8..=6,
        threshold in 2u8..=6,
        duration in 10u64..=10_000,
    ) {
        prop_assume!(threshold <= n_signers);
        let n = n_signers as usize;
        let t = threshold as usize;
        let mut smt = PydeSMT::new();
        let sks = install_multisig(&mut smt, n, threshold, 1_000_000_000);
        let (submitter, sub_sk) = fund_submitter(&mut smt, n, 10_000_000_000_000);

        let pause_slot = 100u64;
        let ctx_at_pause = block_ctx(pause_slot);

        let indices: Vec<u8> = (0..t as u8).collect();
        let sks_thr: Vec<_> = sks[..t].to_vec();
        let pause_sigs = sign_pause(duration, &sks_thr, &indices, 0);
        let pause_payload = multisig::EmergencyPausePayload {
            duration_slots: duration,
            sigs: pause_sigs,
        };
        let pause_tx = build_pause_tx(submitter, sub_sk, pause_payload.encode(), 0);
        execute_transaction(&pause_tx, &mut smt, &ctx_at_pause).unwrap();

        let end_slot = pause_slot + duration;

        // At end_slot - 1: still paused.
        prop_assert!(is_paused(&smt, end_slot - 1), "paused at end_slot - 1");

        // At end_slot: auto-unpaused.
        prop_assert!(!is_paused(&smt, end_slot), "auto-unpaused at end_slot");

        // Far beyond: still unpaused.
        prop_assert!(
            !is_paused(&smt, end_slot + 10_000_000),
            "remains unpaused indefinitely without resume"
        );

        // Standard tx at end_slot should execute normally (no state writes
        // blocked by the gate).
        let ctx_after = block_ctx(end_slot);
        let (recv_pk, _) = pyde_crypto::falcon::falcon_keygen().unwrap();
        let recipient = derive_eoa_address(recv_pk.as_bytes());
        let transfer = build_transfer(submitter, sub_sk, recipient, 10, 1);
        let r = execute_transaction(&transfer, &mut smt, &ctx_after).unwrap();
        prop_assert!(r.success, "transfer at end_slot must succeed (auto-unpaused)");
    }
}
