//! Integration property test: value conservation across transfers
//! (slice 5.2, plan 053b).
//!
//! Every successful standard transfer must preserve total ledger value
//! *minus* the burned fraction of the fee. The fee distribution code
//! at `execution.rs::distribute_fee` assigns the rounding remainder
//! to treasury, so `burned + validator_share + treasury_share ==
//! total_fee` exactly — no rounding loss.
//!
//! Property asserted here:
//!
//! ```text
//! Δ(sender) + Δ(recipient) + Δ(validator) + Δ(treasury) == -burned
//! ```
//!
//! where the deltas are before/after the tx. Equivalently, the sum of
//! all on-chain balances drops by exactly the burned amount per tx.

mod common;

use common::*;
use proptest::prelude::*;
use pyde_account::address::Address;
use pyde_state::smt::PydeSMT;
use pyde_tx::pipeline::{execute_transaction, load_account};
use pyde_tx::types::{FeePayer, Transaction, TransactionType};

fn build_transfer(
    from: Address,
    from_sk: &pyde_crypto::falcon::FalconSecretKey,
    to: Address,
    value: u128,
    gas_limit: u64,
    nonce: u64,
) -> Transaction {
    let mut tx = Transaction {
        from,
        to,
        value,
        data: vec![],
        gas_limit,
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// A successful Standard transfer preserves total value modulo the
    /// burned portion of the fee. Sum of (sender, recipient, validator,
    /// treasury) balance deltas equals `-burned`.
    #[test]
    fn transfer_conserves_value_minus_burn(
        transfer_value in 1u128..=10_000,
        gas_limit in 50_000u64..=200_000,
        recipient_seed in 0u8..=0xFF,
    ) {
        let mut smt = PydeSMT::new();
        let (sender, sender_sk) = fund_submitter(&mut smt, 0, 5_000_000_000_000);
        let ctx = block_ctx(100);

        // Recipient: fresh address derived from the seed so it differs
        // from sender/validator/treasury across shrinks.
        let mut recipient = [0u8; 32];
        recipient[0] = recipient_seed;
        recipient[1] = 0xAB; // disambiguate from pool-derived addresses
        prop_assume!(
            recipient != sender
                && recipient != ctx.validator_address
                && recipient != pyde_account::address::treasury_address()
                && recipient != [0u8; 32]
        );

        let validator_addr = ctx.validator_address;
        let treasury_addr = pyde_account::address::treasury_address();

        // Capture before-balances for the four participants.
        let sender_before = load_account(&smt, &sender).balance;
        let recipient_before = load_account(&smt, &recipient).balance;
        let validator_before = load_account(&smt, &validator_addr).balance;
        let treasury_before = load_account(&smt, &treasury_addr).balance;

        let tx = build_transfer(sender, sender_sk, recipient, transfer_value, gas_limit, 0);
        let receipt = execute_transaction(&tx, &mut smt, &ctx).unwrap();
        prop_assume!(receipt.success);

        // After-balances.
        let sender_after = load_account(&smt, &sender).balance;
        let recipient_after = load_account(&smt, &recipient).balance;
        let validator_after = load_account(&smt, &validator_addr).balance;
        let treasury_after = load_account(&smt, &treasury_addr).balance;

        // Signed deltas (widen to i256 would be cleaner, but i128
        // suffices given our bounded fixtures — no participant can
        // hold 2^127 quanta in this test).
        let delta_sender = sender_after as i128 - sender_before as i128;
        let delta_recipient = recipient_after as i128 - recipient_before as i128;
        let delta_validator = validator_after as i128 - validator_before as i128;
        let delta_treasury = treasury_after as i128 - treasury_before as i128;

        let total_delta = delta_sender + delta_recipient + delta_validator + delta_treasury;
        let burned = pyde_tx::execution::distribute_fee(
            receipt.effective_gas,
            ctx.base_fee,
        )
        .burned as i128;

        // Invariant: sum of balance changes across all four
        // participating accounts equals -burned. Any deviation
        // indicates a bookkeeping bug in the pipeline.
        prop_assert_eq!(
            total_delta,
            -burned,
            "value conservation violated: deltas sum to {}, expected -{} (burned)",
            total_delta,
            burned
        );
    }
}
