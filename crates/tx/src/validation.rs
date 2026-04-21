//! Transaction validation: check all preconditions before execution.
//!
//! Validates: signature, nonce window, balance, gas limits, deadline,
//! access list format, and transaction size.

use crate::types::Transaction;
use pyde_account::nonce::NonceState;
use pyde_account::types::Account;

/// Minimum gas limit for any transaction (simple transfer baseline).
pub const MIN_GAS_LIMIT: u64 = 21_000;

/// Maximum transaction size in bytes (wire format).
pub const MAX_TX_SIZE: usize = 128 * 1024; // 128 KB

/// Maximum calldata (tx.data) size in bytes (Phase 5 slice 5.3).
///
/// Separate from `MAX_TX_SIZE` because calldata dominates a tx's
/// size budget. Without a dedicated cap, a malicious tx with a
/// near-`MAX_TX_SIZE` data field (e.g. 120 KB of worthless bytes)
/// still passes validation and burns validator cycles during
/// execution + witness propagation. 64 KB is the standard cap used
/// by comparable EVM-family chains — large enough for legitimate
/// contract-deploy bytecode, small enough to bound DoS surface.
pub const MAX_CALLDATA: usize = 64 * 1024;

/// Block gas limit (target). Elastic blocks can go up to 4x.
pub const BLOCK_GAS_TARGET: u64 = 400_000_000;
pub const BLOCK_GAS_MAX: u64 = 1_600_000_000; // 4x elastic

/// Validation context: block-level info needed for checks.
pub struct ValidationContext {
    /// Current block height.
    pub block_height: u64,
    /// Current base fee (per gas unit, in quanta).
    pub base_fee: u128,
    /// Maximum gas allowed in this block.
    pub block_gas_limit: u64,
    /// Expected chain ID.
    pub chain_id: u64,
    /// When true, FALCON signature verification is skipped. Intended
    /// only for in-process devnet tests that construct transactions
    /// without real FALCON keys. Production must keep this `false`
    /// regardless of `chain_id` — the previous check was "skip sigs
    /// if chain_id == 31337" which let a misconfigured mainnet node
    /// with a devnet chain_id accept forged transactions.
    pub dev_skip_signature: bool,
    /// Sender's currently-locked vesting balance (Phase 4 slice 4.4).
    /// Computed by the caller from the sender's `VestingSchedule`
    /// before validation. Deducted from `sender.balance` when checking
    /// that `gas_cost + value` fits. Zero for accounts with no vesting.
    pub sender_locked: u128,
}

/// Validation error with specific reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// FALCON signature doesn't match sender's public key.
    InvalidSignature,
    /// Nonce not within sender's nonce window.
    InvalidNonce(String),
    /// Insufficient balance to cover gas + value.
    InsufficientBalance { required: u128, available: u128 },
    /// Gas limit below minimum (21,000).
    GasLimitTooLow { limit: u64, min: u64 },
    /// Gas limit exceeds block gas limit.
    GasLimitTooHigh { limit: u64, max: u64 },
    /// Transaction deadline has passed.
    DeadlineExpired { deadline: u64, current: u64 },
    /// Transaction is too large.
    TxTooLarge { size: usize, max: usize },
    /// Calldata (`tx.data`) exceeds `MAX_CALLDATA` (slice 5.3).
    CalldataTooLarge { size: usize, max: usize },
    /// Access list malformed.
    InvalidAccessList(String),
    /// Wrong chain ID.
    WrongChainId { expected: u64, got: u64 },
    /// Paymaster address is invalid (zero address).
    InvalidPaymaster,
}

/// Validate a transaction against the sender's account and block context.
/// Returns Ok(()) if all checks pass, or the first error found.
pub fn validate_transaction(
    tx: &Transaction,
    sender: &Account,
    nonce_state: &NonceState,
    ctx: &ValidationContext,
) -> Result<(), ValidationError> {
    // 1. Chain ID
    validate_chain_id(tx, ctx)?;

    // 2. Signature. Skipping is only allowed when the caller explicitly
    // sets `dev_skip_signature` — chain_id is NOT consulted here, so a
    // misconfigured production validator with chain_id = 31337 cannot
    // accidentally accept forged transactions.
    if !ctx.dev_skip_signature {
        validate_signature(tx, sender)?;
    }

    // 3. Nonce
    validate_nonce(tx, nonce_state)?;

    // 4. Balance
    validate_balance(tx, sender, ctx)?;

    // 5. Gas limits
    validate_gas_limit(tx, ctx)?;

    // 6. Deadline
    validate_deadline(tx, ctx)?;

    // 7. Access list
    validate_access_list(tx)?;

    // 8. Size
    validate_size(tx)?;

    Ok(())
}

fn validate_chain_id(tx: &Transaction, ctx: &ValidationContext) -> Result<(), ValidationError> {
    if tx.chain_id != ctx.chain_id {
        return Err(ValidationError::WrongChainId {
            expected: ctx.chain_id,
            got: tx.chain_id,
        });
    }
    Ok(())
}

fn validate_signature(tx: &Transaction, sender: &Account) -> Result<(), ValidationError> {
    match &sender.auth_keys {
        pyde_account::types::AuthKeys::Single(pk) => {
            if !tx.verify_signature(pk) {
                return Err(ValidationError::InvalidSignature);
            }
        }
        pyde_account::types::AuthKeys::None => {
            // System/contract accounts — no signature check at this level
        }
        pyde_account::types::AuthKeys::MultiSig { .. } => {
            // Multi-sig validation is handled by the auth module
            // For now, skip (requires multiple signatures in tx)
        }
    }
    Ok(())
}

fn validate_nonce(tx: &Transaction, nonce_state: &NonceState) -> Result<(), ValidationError> {
    nonce_state
        .validate(tx.nonce)
        .map(|_| ())
        .map_err(|e| ValidationError::InvalidNonce(format!("{:?}", e)))
}

fn validate_balance(
    tx: &Transaction,
    sender: &Account,
    ctx: &ValidationContext,
) -> Result<(), ValidationError> {
    let gas_cost = tx.gas_limit as u128 * ctx.base_fee;
    let total_required = gas_cost + tx.value;

    // Vested / locked balance (slice 4.4) is subtracted from the raw
    // account balance before any solvency check. `saturating_sub`
    // handles the edge case where a slash reduces balance below the
    // lock amount — the account is effectively frozen until vesting
    // progresses further (or the lock ends).
    let spendable = sender.balance.saturating_sub(ctx.sender_locked);

    // Check the fee payer's balance
    let available = match &tx.fee_payer {
        crate::types::FeePayer::Sender => spendable,
        crate::types::FeePayer::GasTank(_) => {
            // Gas tank pays gas, sender pays value only.
            // Gas tank balance check happens at execution time.
            if spendable < tx.value {
                return Err(ValidationError::InsufficientBalance {
                    required: tx.value,
                    available: spendable,
                });
            }
            return Ok(());
        }
        crate::types::FeePayer::Paymaster(paymaster_addr) => {
            // Paymaster pays everything — but verify the paymaster address is non-zero.
            // Full paymaster balance/existence check happens at execution time when
            // state is available. This structural check catches obvious misconfiguration.
            if *paymaster_addr == [0u8; 32] {
                return Err(ValidationError::InvalidPaymaster);
            }
            return Ok(());
        }
    };

    if available < total_required {
        return Err(ValidationError::InsufficientBalance {
            required: total_required,
            available,
        });
    }
    Ok(())
}

fn validate_gas_limit(tx: &Transaction, ctx: &ValidationContext) -> Result<(), ValidationError> {
    if tx.gas_limit < MIN_GAS_LIMIT {
        return Err(ValidationError::GasLimitTooLow {
            limit: tx.gas_limit,
            min: MIN_GAS_LIMIT,
        });
    }
    if tx.gas_limit > ctx.block_gas_limit {
        return Err(ValidationError::GasLimitTooHigh {
            limit: tx.gas_limit,
            max: ctx.block_gas_limit,
        });
    }
    Ok(())
}

fn validate_deadline(tx: &Transaction, ctx: &ValidationContext) -> Result<(), ValidationError> {
    if let Some(deadline) = tx.deadline {
        if ctx.block_height >= deadline {
            return Err(ValidationError::DeadlineExpired {
                deadline,
                current: ctx.block_height,
            });
        }
    }
    Ok(())
}

fn validate_access_list(tx: &Transaction) -> Result<(), ValidationError> {
    for (i, entry) in tx.access_list.iter().enumerate() {
        // Each storage key must be 32 bytes (enforced by type system)
        // Check for duplicate addresses
        for j in (i + 1)..tx.access_list.len() {
            if entry.address == tx.access_list[j].address {
                return Err(ValidationError::InvalidAccessList(format!(
                    "duplicate address at entries {} and {}",
                    i, j
                )));
            }
        }
    }
    Ok(())
}

fn validate_size(tx: &Transaction) -> Result<(), ValidationError> {
    // Calldata cap runs BEFORE the wire-encode size check so a pathological
    // tx with 1 GB of data can't force a 1 GB allocation inside
    // `to_bytes()` just to then reject.
    if tx.data.len() > MAX_CALLDATA {
        return Err(ValidationError::CalldataTooLarge {
            size: tx.data.len(),
            max: MAX_CALLDATA,
        });
    }
    let size = tx.to_bytes().len();
    if size > MAX_TX_SIZE {
        return Err(ValidationError::TxTooLarge {
            size,
            max: MAX_TX_SIZE,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AccessEntry, FeePayer, TransactionType};
    use pyde_account::address::{derive_eoa_address, ZERO_ADDRESS};
    use pyde_account::types::Account;
    use pyde_crypto::falcon::{falcon_keygen, falcon_sign};

    fn make_valid_tx_and_account() -> (Transaction, Account, NonceState) {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let account = Account {
            balance: 1_000_000_000_000, // plenty
            ..Account::new_eoa(&pk_bytes)
        };
        let nonce_state = NonceState::new();

        let mut tx = Transaction {
            from: account.address,
            to: derive_eoa_address(&[0xBB; 897]),
            value: 1_000,
            data: vec![],
            gas_limit: 21_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };

        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).unwrap().as_bytes().to_vec();

        (tx, account, nonce_state)
    }

    fn default_ctx() -> ValidationContext {
        ValidationContext {
            block_height: 100,
            base_fee: 1_000,
            block_gas_limit: BLOCK_GAS_TARGET,
            chain_id: 1,
            // validation.rs unit tests exercise each rule in isolation;
            // individual tests pass signed txs when they want to exercise
            // signature validation, and the module's signature test
            // overrides this field.
            dev_skip_signature: true,
            sender_locked: 0,
        }
    }

    // ========== Task 0393: Each validation rule ==========

    #[test]
    fn valid_transaction_passes() {
        let (tx, account, nonce) = make_valid_tx_and_account();
        let ctx = default_ctx();
        assert!(validate_transaction(&tx, &account, &nonce, &ctx).is_ok());
    }

    #[test]
    fn wrong_chain_id_rejected() {
        let (tx, account, nonce) = make_valid_tx_and_account();
        let mut ctx = default_ctx();
        ctx.chain_id = 999;
        let err = validate_transaction(&tx, &account, &nonce, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::WrongChainId { .. }));
    }

    #[test]
    fn invalid_signature_rejected() {
        let (mut tx, account, nonce) = make_valid_tx_and_account();
        tx.signature = vec![0xFF; 666]; // garbage sig
                                        // Override default_ctx()'s dev_skip_signature so the sig check
                                        // actually runs — the whole point of this test.
        let ctx = ValidationContext {
            dev_skip_signature: false,
            ..default_ctx()
        };
        let err = validate_transaction(&tx, &account, &nonce, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidSignature));
    }

    // ========== Task 0396: Nonce outside window rejected ==========

    #[test]
    fn nonce_outside_window_rejected() {
        let (mut tx, _account, nonce) = make_valid_tx_and_account();
        tx.nonce = 100; // way outside [0, 15]
                        // Re-sign with correct hash
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let account = Account {
            balance: 1_000_000_000_000,
            ..Account::new_eoa(&pk_bytes)
        };
        tx.from = account.address;
        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).unwrap().as_bytes().to_vec();

        let ctx = default_ctx();
        let err = validate_transaction(&tx, &account, &nonce, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidNonce(_)));
    }

    // ========== Task 0395: Insufficient balance rejected ==========

    #[test]
    fn insufficient_balance_rejected() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let account = Account {
            balance: 100, // way too low
            ..Account::new_eoa(&pk_bytes)
        };
        let nonce = NonceState::new();

        let mut tx = Transaction {
            from: account.address,
            to: ZERO_ADDRESS,
            value: 0,
            data: vec![],
            gas_limit: 21_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };
        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).unwrap().as_bytes().to_vec();

        let ctx = default_ctx(); // base_fee = 1000, so 21000 * 1000 = 21M > 100
        let err = validate_transaction(&tx, &account, &nonce, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::InsufficientBalance { .. }));
    }

    #[test]
    fn paymaster_skips_balance_check() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let account = Account {
            balance: 0, // zero balance
            ..Account::new_eoa(&pk_bytes)
        };
        let nonce = NonceState::new();

        let mut tx = Transaction {
            from: account.address,
            to: ZERO_ADDRESS,
            value: 0,
            data: vec![],
            gas_limit: 21_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Paymaster([0xFF; 32]),
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };
        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).unwrap().as_bytes().to_vec();

        let ctx = default_ctx();
        assert!(validate_transaction(&tx, &account, &nonce, &ctx).is_ok());
    }

    // ========== Task 0394: Expired deadline rejected ==========

    #[test]
    fn expired_deadline_rejected() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let account = Account {
            balance: 1_000_000_000_000,
            ..Account::new_eoa(&pk_bytes)
        };
        let nonce = NonceState::new();

        let mut tx = Transaction {
            from: account.address,
            to: ZERO_ADDRESS,
            value: 0,
            data: vec![],
            gas_limit: 21_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: Some(50), // deadline at block 50
            chain_id: 1,
            tx_type: TransactionType::Standard,
        };
        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).unwrap().as_bytes().to_vec();

        let ctx = default_ctx(); // block_height = 100 > deadline 50
        let err = validate_transaction(&tx, &account, &nonce, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::DeadlineExpired { .. }));
    }

    #[test]
    fn future_deadline_passes() {
        let (tx, _account, _nonce) = make_valid_tx_and_account();
        let mut tx = tx;
        // Need to re-sign with deadline
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let account = Account {
            balance: 1_000_000_000_000,
            ..Account::new_eoa(&pk_bytes)
        };
        tx.from = account.address;
        tx.deadline = Some(999); // future
        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).unwrap().as_bytes().to_vec();

        let ctx = default_ctx();
        assert!(validate_transaction(&tx, &account, &NonceState::new(), &ctx).is_ok());
    }

    // ========== Gas limits ==========

    #[test]
    fn gas_limit_too_low_rejected() {
        let (mut tx, _account, _nonce) = make_valid_tx_and_account();
        tx.gas_limit = 1_000; // below 21,000 minimum
        let ctx = default_ctx();
        // Skip sig check — gas limit is checked before execution
        let err = validate_gas_limit(&tx, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::GasLimitTooLow { .. }));
    }

    #[test]
    fn gas_limit_too_high_rejected() {
        let (mut tx, _, _) = make_valid_tx_and_account();
        tx.gas_limit = BLOCK_GAS_MAX + 1;
        let ctx = ValidationContext {
            block_gas_limit: BLOCK_GAS_MAX,
            ..default_ctx()
        };
        let err = validate_gas_limit(&tx, &ctx).unwrap_err();
        assert!(matches!(err, ValidationError::GasLimitTooHigh { .. }));
    }

    // ========== Access list ==========

    #[test]
    fn duplicate_access_list_address_rejected() {
        let (mut tx, _, _) = make_valid_tx_and_account();
        tx.access_list = vec![
            AccessEntry {
                address: [0xAA; 32],
                reads: vec![],
                writes: vec![],
            },
            AccessEntry {
                address: [0xAA; 32],
                reads: vec![],
                writes: vec![],
            }, // duplicate
        ];
        let err = validate_access_list(&tx).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidAccessList(_)));
    }

    #[test]
    fn valid_access_list_passes() {
        let (mut tx, _, _) = make_valid_tx_and_account();
        tx.access_list = vec![
            AccessEntry {
                address: [0xAA; 32],
                reads: vec![[0x11; 32]],
                writes: vec![],
            },
            AccessEntry {
                address: [0xBB; 32],
                reads: vec![],
                writes: vec![],
            },
        ];
        assert!(validate_access_list(&tx).is_ok());
    }

    // ========== Slice 5.3: MAX_CALLDATA ==========

    #[test]
    fn calldata_at_max_accepted() {
        let (mut tx, account, nonce_state) = make_valid_tx_and_account();
        tx.data = vec![0u8; MAX_CALLDATA];
        // Re-sign after mutating the body.
        let (_pk, sk) = falcon_keygen().unwrap();
        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).unwrap().as_bytes().to_vec();
        // Calldata check is size-only; signature check is bypassed under
        // dev_skip_signature = true in default_ctx.
        assert!(validate_size(&tx).is_ok());

        // Also run through full validation — signature is skipped by ctx,
        // account has headroom balance.
        let ctx = default_ctx();
        let _ = validate_transaction(&tx, &account, &nonce_state, &ctx);
    }

    #[test]
    fn calldata_over_max_rejected_by_size() {
        let (mut tx, _, _) = make_valid_tx_and_account();
        tx.data = vec![0u8; MAX_CALLDATA + 1];
        let err = validate_size(&tx).unwrap_err();
        match err {
            ValidationError::CalldataTooLarge { size, max } => {
                assert_eq!(size, MAX_CALLDATA + 1);
                assert_eq!(max, MAX_CALLDATA);
            }
            other => panic!("wrong error: {:?}", other),
        }
    }

    #[test]
    fn calldata_check_runs_before_tx_size_check() {
        // A tx with ridiculously oversized calldata should hit the
        // calldata cap first, not the tx-size cap — guards against
        // a future refactor reordering the checks and forcing the
        // pipeline to allocate MAX_TX_SIZE + K bytes via to_bytes()
        // before rejecting.
        let (mut tx, _, _) = make_valid_tx_and_account();
        tx.data = vec![0u8; MAX_CALLDATA * 10];
        let err = validate_size(&tx).unwrap_err();
        assert!(matches!(err, ValidationError::CalldataTooLarge { .. }));
    }
}
