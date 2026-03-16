//! Transaction execution: pre-execution charges, PVM invocation,
//! post-execution refunds, fee distribution, and receipt generation.
//!
//! Execution lifecycle:
//! 1. Pre-execution: deduct max gas cost from fee payer
//! 2. Value transfer: sender → recipient
//! 3. PVM execution (contract call or deployment)
//! 4. Post-execution: refund unused gas, apply SDELETE refunds
//! 5. Fee distribution: 70% burn, 20% validator, 10% prover
//! 6. Generate receipt

use crate::types::{FeePayer, Transaction, TransactionType};
use pyde_account::address::{Address, ZERO_ADDRESS};
use pyde_account::types::Account;
use pyde_crypto::poseidon2::poseidon2_hash;
use sparse_merkle_tree::H256;

/// Fee distribution ratios (percentages).
/// 70% burn (deflationary + MEV prevention), 15% validator, 15% prover.
pub const FEE_BURN_PCT: u64 = 70;
pub const FEE_VALIDATOR_PCT: u64 = 15;
pub const FEE_PROVER_PCT: u64 = 15;

/// Transaction receipt: result of executing a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Whether execution succeeded.
    pub success: bool,
    /// Total gas used (exec + prove).
    pub gas_used: u64,
    /// Gas refunded (from SDELETE, capped at 50%).
    pub gas_refund: u64,
    /// Effective gas charged (gas_used - refund).
    pub effective_gas: u64,
    /// Fee paid (effective_gas × base_fee).
    pub fee_paid: u128,
    /// Fee distribution.
    pub fee_burned: u128,
    pub fee_validator: u128,
    pub fee_prover: u128,
    /// Event logs emitted during execution.
    pub logs: Vec<LogEntry>,
    /// Post-execution state root (if available).
    pub state_root: H256,
}

/// A log entry in the receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub address: Address,
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// Fee distribution result.
#[derive(Clone, Debug)]
pub struct FeeDistribution {
    pub burned: u128,
    pub validator: u128,
    pub prover: u128,
}

/// Execution context: mutable state during transaction execution.
pub struct ExecutionState {
    /// Sender's balance (modified during execution).
    pub sender_balance: u128,
    /// Recipient's balance.
    pub recipient_balance: u128,
    /// Gas tank balance (if FeePayer::GasTank).
    pub gas_tank_balance: u128,
    /// Fee payer balance (whichever account pays gas).
    pub fee_payer_balance: u128,
    /// Validator reward accumulator.
    pub validator_reward: u128,
    /// Prover reward accumulator.
    pub prover_reward: u128,
    /// Total burned.
    pub burned: u128,
}

/// Pre-execution: deduct max gas cost from fee payer.
/// Returns the amount deducted, or error if insufficient.
pub fn pre_execution_charge(
    tx: &Transaction,
    sender_balance: &mut u128,
    gas_tank_balance: &mut u128,
    base_fee: u128,
) -> Result<u128, String> {
    let max_gas_cost = tx.gas_limit as u128 * base_fee;

    match &tx.fee_payer {
        FeePayer::Sender => {
            let total = max_gas_cost + tx.value;
            if *sender_balance < total {
                return Err(format!(
                    "insufficient balance: need {total}, have {}", *sender_balance
                ));
            }
            *sender_balance -= max_gas_cost;
            Ok(max_gas_cost)
        }
        FeePayer::GasTank(_) => {
            if *gas_tank_balance < max_gas_cost {
                return Err(format!(
                    "insufficient gas tank: need {max_gas_cost}, have {}", *gas_tank_balance
                ));
            }
            if *sender_balance < tx.value {
                return Err(format!(
                    "insufficient balance for value: need {}, have {}",
                    tx.value, *sender_balance
                ));
            }
            *gas_tank_balance -= max_gas_cost;
            Ok(max_gas_cost)
        }
        FeePayer::Paymaster(_) => {
            // Paymaster validation happens via contract call — charge deferred
            Ok(0)
        }
    }
}

/// Value transfer: move `value` from sender to recipient.
pub fn transfer_value(
    sender_balance: &mut u128,
    recipient_balance: &mut u128,
    value: u128,
) -> Result<(), String> {
    if value == 0 {
        return Ok(());
    }
    if *sender_balance < value {
        return Err(format!(
            "insufficient balance for transfer: need {value}, have {}", *sender_balance
        ));
    }
    *sender_balance -= value;
    *recipient_balance += value;
    Ok(())
}

/// Post-execution: refund unused gas and apply SDELETE refunds.
/// Returns (effective_gas, refund_amount).
pub fn post_execution_refund(
    gas_used: u64,
    gas_limit: u64,
    gas_refund_from_sdelete: u64,
    fee_payer_balance: &mut u128,
    base_fee: u128,
) -> (u64, u64) {
    // SDELETE refund capped at 50% of gas used
    let max_refund = gas_used / 2;
    let actual_refund = gas_refund_from_sdelete.min(max_refund);
    let effective_gas = gas_used - actual_refund;

    // Refund unused gas (gas_limit - gas_used) + SDELETE refund
    let unused_gas = gas_limit - gas_used;
    let total_refund_gas = unused_gas + actual_refund;
    let refund_amount = total_refund_gas as u128 * base_fee;
    *fee_payer_balance += refund_amount;

    (effective_gas, actual_refund)
}

/// Distribute the fee: 70% burn, 20% validator, 10% prover.
pub fn distribute_fee(effective_gas: u64, base_fee: u128) -> FeeDistribution {
    let total_fee = effective_gas as u128 * base_fee;
    let burned = total_fee * FEE_BURN_PCT as u128 / 100;
    let validator = total_fee * FEE_VALIDATOR_PCT as u128 / 100;
    let prover = total_fee - burned - validator; // remainder to prover (handles rounding)
    FeeDistribution {
        burned,
        validator,
        prover,
    }
}

/// Generate a transaction receipt.
pub fn generate_receipt(
    tx: &Transaction,
    success: bool,
    gas_used: u64,
    gas_refund: u64,
    effective_gas: u64,
    base_fee: u128,
    logs: Vec<LogEntry>,
    state_root: H256,
) -> Receipt {
    let fee = distribute_fee(effective_gas, base_fee);
    Receipt {
        tx_hash: tx.hash(),
        success,
        gas_used,
        gas_refund,
        effective_gas,
        fee_paid: effective_gas as u128 * base_fee,
        fee_burned: fee.burned,
        fee_validator: fee.validator,
        fee_prover: fee.prover,
        logs,
        state_root,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AccessEntry, TransactionType};
    use pyde_account::address::derive_eoa_address;

    fn make_tx(value: u128, gas_limit: u64) -> Transaction {
        Transaction {
            from: derive_eoa_address(&[0xAA; 897]),
            to: derive_eoa_address(&[0xBB; 897]),
            value,
            data: vec![],
            gas_limit,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        }
    }

    // ========== Task 0405: Successful transfer updates balances ==========

    #[test]
    fn value_transfer_updates_balances() {
        let mut sender = 1_000_000u128;
        let mut recipient = 500u128;
        transfer_value(&mut sender, &mut recipient, 1_000).unwrap();
        assert_eq!(sender, 999_000);
        assert_eq!(recipient, 1_500);
    }

    #[test]
    fn zero_value_transfer() {
        let mut sender = 100u128;
        let mut recipient = 200u128;
        transfer_value(&mut sender, &mut recipient, 0).unwrap();
        assert_eq!(sender, 100);
        assert_eq!(recipient, 200);
    }

    #[test]
    fn insufficient_transfer_fails() {
        let mut sender = 100u128;
        let mut recipient = 0u128;
        assert!(transfer_value(&mut sender, &mut recipient, 200).is_err());
    }

    // ========== Task 0406: Failed tx still deducts gas ==========

    #[test]
    fn pre_execution_deducts_max_gas() {
        let tx = make_tx(0, 50_000);
        let base_fee = 1_000u128;
        let mut sender_balance = 100_000_000u128;
        let mut gas_tank = 0u128;

        let deducted = pre_execution_charge(&tx, &mut sender_balance, &mut gas_tank, base_fee).unwrap();
        assert_eq!(deducted, 50_000 * 1_000); // 50M
        assert_eq!(sender_balance, 100_000_000 - 50_000_000);
    }

    #[test]
    fn pre_execution_includes_value() {
        let tx = make_tx(10_000, 21_000);
        let base_fee = 100u128;
        let mut sender_balance = 10_000_000u128;
        let mut gas_tank = 0u128;

        // Need: 21_000 * 100 + 10_000 = 2_110_000
        pre_execution_charge(&tx, &mut sender_balance, &mut gas_tank, base_fee).unwrap();
        // Only gas deducted in pre-execution, value deducted in transfer
        assert_eq!(sender_balance, 10_000_000 - 2_100_000);
    }

    #[test]
    fn gas_tank_pays_gas() {
        let mut tx = make_tx(1_000, 21_000);
        tx.fee_payer = FeePayer::GasTank([0xFF; 32]);
        let base_fee = 100u128;
        let mut sender_balance = 5_000u128; // enough for value only
        let mut gas_tank = 10_000_000u128;

        pre_execution_charge(&tx, &mut sender_balance, &mut gas_tank, base_fee).unwrap();
        assert_eq!(sender_balance, 5_000); // unchanged (gas from tank)
        assert_eq!(gas_tank, 10_000_000 - 2_100_000);
    }

    #[test]
    fn gas_tank_insufficient_fails() {
        let mut tx = make_tx(0, 21_000);
        tx.fee_payer = FeePayer::GasTank([0xFF; 32]);
        let mut sender_balance = 1_000_000u128;
        let mut gas_tank = 100u128; // too low

        assert!(pre_execution_charge(&tx, &mut sender_balance, &mut gas_tank, 1_000).is_err());
    }

    // ========== Task 0407: Gas refund correctly applied ==========

    #[test]
    fn post_execution_refund_unused_gas() {
        let mut fee_payer = 0u128; // balance after pre-deduction
        let base_fee = 1_000u128;

        let (effective, refund) = post_execution_refund(
            30_000,  // gas_used
            50_000,  // gas_limit
            0,       // no sdelete refund
            &mut fee_payer,
            base_fee,
        );

        assert_eq!(effective, 30_000);
        assert_eq!(refund, 0);
        assert_eq!(fee_payer, 20_000 * 1_000); // 20K unused gas refunded
    }

    #[test]
    fn sdelete_refund_capped_at_50_pct() {
        let mut fee_payer = 0u128;
        let base_fee = 100u128;

        let (effective, refund) = post_execution_refund(
            10_000,  // gas_used
            10_000,  // gas_limit (no unused)
            8_000,   // 8K sdelete refund requested
            &mut fee_payer,
            base_fee,
        );

        // Cap: 50% of 10K = 5K
        assert_eq!(refund, 5_000);
        assert_eq!(effective, 5_000); // 10K - 5K
        assert_eq!(fee_payer, 5_000 * 100); // 5K refunded
    }

    // ========== Task 0408: Fee distribution ==========

    #[test]
    fn fee_distribution_70_15_15() {
        let dist = distribute_fee(100_000, 1_000); // 100M total fee
        let total = 100_000u128 * 1_000;
        assert_eq!(dist.burned, total * 70 / 100);
        assert_eq!(dist.validator, total * 15 / 100);
        // Prover gets remainder (handles rounding)
        assert_eq!(dist.burned + dist.validator + dist.prover, total);
    }

    #[test]
    fn fee_distribution_zero_gas() {
        let dist = distribute_fee(0, 1_000);
        assert_eq!(dist.burned, 0);
        assert_eq!(dist.validator, 0);
        assert_eq!(dist.prover, 0);
    }

    // ========== Task 0410: Receipt generation ==========

    #[test]
    fn receipt_contains_correct_fields() {
        let tx = make_tx(1_000, 50_000);
        let base_fee = 100u128;
        let logs = vec![LogEntry {
            address: tx.from,
            topics: vec![[0xAA; 32]],
            data: b"transfer".to_vec(),
        }];

        let receipt = generate_receipt(
            &tx,
            true,
            30_000,  // gas_used
            5_000,   // gas_refund
            25_000,  // effective_gas
            base_fee,
            logs.clone(),
            H256::zero(),
        );

        assert!(receipt.success);
        assert_eq!(receipt.gas_used, 30_000);
        assert_eq!(receipt.gas_refund, 5_000);
        assert_eq!(receipt.effective_gas, 25_000);
        assert_eq!(receipt.fee_paid, 25_000 * 100);
        assert_eq!(receipt.logs.len(), 1);
        assert_eq!(receipt.logs[0].data, b"transfer");
        assert_eq!(
            receipt.fee_burned + receipt.fee_validator + receipt.fee_prover,
            receipt.fee_paid
        );
    }

    #[test]
    fn failed_tx_receipt() {
        let tx = make_tx(0, 21_000);
        let receipt = generate_receipt(
            &tx, false, 21_000, 0, 21_000, 100, vec![], H256::zero(),
        );
        assert!(!receipt.success);
        assert_eq!(receipt.gas_used, 21_000);
    }
}
