//! Shared integration-test fixtures (slice 5.2).
//!
//! FALCON-512 keygen is ~4.4 ms per call, so proptest runs with
//! hundreds of cases need a keypair pool. We pre-generate 32 keypairs
//! once per test binary via `OnceLock` and let strategies pick from
//! the pool by index. This keeps a 256-case proptest suite under a
//! second instead of minutes.
//!
//! `#![allow(dead_code)]` because each `tests/*.rs` file is its own
//! binary crate and only uses a subset of the helpers; Rust reports
//! everything else as dead per-binary, which makes `-D warnings` in
//! CI impossible without this allow.

#![allow(dead_code)]

use pyde_account::address::{derive_eoa_address, Address};
use pyde_crypto::falcon::{falcon_keygen, falcon_sign, FalconPublicKey, FalconSecretKey};
use pyde_state::smt::PydeSMT;
use pyde_tx::multisig;
use pyde_tx::pipeline::{
    store_account, write_multisig_nonce, write_multisig_signers, write_multisig_threshold,
    BlockContext,
};
use pyde_tx::types::{FeePayer, Transaction, TransactionType};
use std::sync::OnceLock;

/// Pool size — enough signers for any realistic multisig config
/// (MAX_SIGNERS = 16) plus headroom for submitters and random targets.
pub const POOL_SIZE: usize = 32;

/// Lazily-initialized keypair pool.
static POOL: OnceLock<Vec<(FalconPublicKey, FalconSecretKey)>> = OnceLock::new();

pub fn pool() -> &'static [(FalconPublicKey, FalconSecretKey)] {
    POOL.get_or_init(|| {
        let mut out = Vec::with_capacity(POOL_SIZE);
        for _ in 0..POOL_SIZE {
            out.push(falcon_keygen().expect("FALCON keygen must not fail in tests"));
        }
        out
    })
    .as_slice()
}

/// Standard block context for tests. `dev_skip_signature = true` so
/// unsigned fixtures validate.
pub fn block_ctx(height: u64) -> BlockContext {
    BlockContext {
        height,
        timestamp: 1_000_000 + height * 400,
        base_fee: 1_000,
        block_gas_limit: 400_000_000,
        chain_id: 1,
        validator_address: derive_eoa_address(b"validator"),
        dev_skip_signature: true,
        block_sigs_pre_verified: false,
    }
}

/// Install a multisig on the SMT using the first `n` keypairs from
/// the pool and the given threshold. Funds the treasury to
/// `treasury_balance`. Returns the signer secret keys for signing
/// payloads.
pub fn install_multisig(
    smt: &mut PydeSMT,
    n: usize,
    threshold: u8,
    treasury_balance: u128,
) -> Vec<&'static FalconSecretKey> {
    assert!(n >= 1 && n <= multisig::MAX_SIGNERS as usize);
    assert!(threshold as usize >= 1 && threshold as usize <= n);
    let pool = pool();
    let pks: Vec<Vec<u8>> = pool[..n]
        .iter()
        .map(|(pk, _)| pk.as_bytes().to_vec())
        .collect();
    write_multisig_signers(smt, &pks);
    write_multisig_threshold(smt, threshold);
    write_multisig_nonce(smt, 0);

    // Fund treasury.
    let treasury = pyde_account::address::treasury_address();
    let mut account = pyde_account::types::Account {
        address: treasury,
        nonce: 0,
        balance: treasury_balance,
        code_hash: sparse_merkle_tree::H256::zero(),
        storage_root: sparse_merkle_tree::H256::zero(),
        account_type: pyde_account::types::AccountType::EOA,
        auth_keys: pyde_account::types::AuthKeys::None,
        gas_tank: 0,
        key_nonce: 0,
    };
    account.balance = treasury_balance;
    store_account(smt, &account).unwrap();

    pool[..n].iter().map(|(_, sk)| sk).collect()
}

/// Pick a pool member by index and fund them as a submitter. Returns
/// (address, secret_key).
pub fn fund_submitter(
    smt: &mut PydeSMT,
    pool_idx: usize,
    balance: u128,
) -> (Address, &'static FalconSecretKey) {
    let (pk, sk) = &pool()[pool_idx];
    let address = derive_eoa_address(pk.as_bytes());
    let mut account = pyde_account::types::Account::new_eoa(pk.as_bytes());
    account.address = address;
    account.balance = balance;
    store_account(smt, &account).unwrap();

    // Initialize nonce state.
    let nonce_state = pyde_account::nonce::NonceState::new();
    let _ = smt.insert(
        pyde_state::keys::nonce_key(&address),
        nonce_state.to_bytes().to_vec(),
    );

    (address, sk)
}

/// Sign the outer tx (the transport layer) with the submitter's key.
pub fn sign_outer_tx(tx: &mut Transaction, sk: &FalconSecretKey) {
    let hash = tx.hash();
    tx.signature = falcon_sign(sk, &hash).unwrap().as_bytes().to_vec();
}

/// Build a signed MultisigTx wrapping a pre-made payload.
pub fn build_multisig_tx(
    submitter: Address,
    submitter_sk: &FalconSecretKey,
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
        tx_type: TransactionType::MultisigTx,
    };
    sign_outer_tx(&mut tx, submitter_sk);
    tx
}

pub fn build_pause_tx(
    submitter: Address,
    submitter_sk: &FalconSecretKey,
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
        tx_type: TransactionType::EmergencyPause,
    };
    sign_outer_tx(&mut tx, submitter_sk);
    tx
}

pub fn build_resume_tx(
    submitter: Address,
    submitter_sk: &FalconSecretKey,
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
        tx_type: TransactionType::EmergencyResume,
    };
    sign_outer_tx(&mut tx, submitter_sk);
    tx
}

/// Sign a `MultisigSpend` with a set of pool signers. `indices` maps
/// the position in `sks` to its signer_index slot — for the common
/// case pass `&[0, 1, 2, ...]`.
pub fn sign_multisig_spend(
    spend: &multisig::MultisigSpend,
    sks: &[&FalconSecretKey],
    indices: &[u8],
    multisig_nonce: u64,
) -> Vec<multisig::SigEntry> {
    let msg = spend.signing_bytes(multisig_nonce);
    sks.iter()
        .zip(indices)
        .map(|(sk, idx)| multisig::SigEntry {
            signer_index: *idx,
            signature: falcon_sign(sk, &msg).unwrap().as_bytes().to_vec(),
        })
        .collect()
}

pub fn sign_pause(
    duration_slots: u64,
    sks: &[&FalconSecretKey],
    indices: &[u8],
    multisig_nonce: u64,
) -> Vec<multisig::SigEntry> {
    let msg_holder = multisig::EmergencyPausePayload {
        duration_slots,
        sigs: vec![],
    };
    let msg = msg_holder.signing_bytes(multisig_nonce);
    sks.iter()
        .zip(indices)
        .map(|(sk, idx)| multisig::SigEntry {
            signer_index: *idx,
            signature: falcon_sign(sk, &msg).unwrap().as_bytes().to_vec(),
        })
        .collect()
}

pub fn sign_resume(
    sks: &[&FalconSecretKey],
    indices: &[u8],
    multisig_nonce: u64,
) -> Vec<multisig::SigEntry> {
    let msg = multisig::EmergencyResumePayload::signing_bytes(multisig_nonce);
    sks.iter()
        .zip(indices)
        .map(|(sk, idx)| multisig::SigEntry {
            signer_index: *idx,
            signature: falcon_sign(sk, &msg).unwrap().as_bytes().to_vec(),
        })
        .collect()
}
