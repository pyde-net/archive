//! End-to-end test for `TransactionType::RegisterPubkey` (audit 229)
//! exercised through the Rust SDK's `Wallet::register_pubkey`
//! helper across a 4-node production-mode testnet.
//!
//! Without `RegisterPubkey`, a fresh address that received funds had
//! no way to ever submit a tx — the audit-226 fix rejects
//! `AuthKeys::None` senders on production, and no protocol path
//! upgraded the account from `None` to `Single(pk)`. This test
//! proves the bootstrap path works end-to-end:
//!
//!   1. Faucet (genesis-registered) sends PYDE to a freshly-generated
//!      wallet's address.
//!   2. Without registration, a normal signed tx from the fresh
//!      wallet must be REJECTED at ingress with -32001 (the 226 gate
//!      tripping on `AuthKeys::None`).
//!   3. Fresh wallet calls `register_pubkey` (unsigned, no gas). This
//!      registration goes through `validate_register_pubkey` which
//!      enforces `tx.from == Poseidon2(tx.data)` + funded +
//!      one-time + correct shape.
//!   4. Now `transfer` from the fresh wallet succeeds.
//!
//! Production-mode (chain_id=7331 — audit 383 refuses mainnet id 1
//! at the testnet generator) so block_processor enforces real FALCON
//! signature verification — no `dev_skip_signature` cheating.

mod common;

use common::TestNetwork;
use pyde_crypto::falcon::{falcon_sign, FalconSecretKey};
use pyde_rust_sdk::{Provider, Wallet};
use pyde_tx::types::{FeePayer, Transaction, TransactionType};
use std::time::Duration;

fn sign_tx(tx: &mut Transaction, sk: &FalconSecretKey) {
    let hash = tx.hash();
    tx.signature = falcon_sign(sk, &hash).unwrap().as_bytes().to_vec();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
async fn register_pubkey_unblocks_first_tx_for_fresh_account() {
    // chain_id=7331 (canonical public testnet id) — block_processor
    // still enforces FALCON sigs on every tx because
    // `dev_skip_signature` only fires at 31337. audit 383 refuses
    // the mainnet id (1) at the `pyde testnet` generator, so we use
    // 7331 for production-mode subprocess tests.
    let net = TestNetwork::spawn_with_chain_id(4, 7331)
        .unwrap_or_else(|e| panic!("spawn 4v@chain_id=7331: {}", e));

    // Wait so the first tx has a slot to land in.
    net.wait_for_slot(3, Duration::from_secs(30))
        .unwrap_or_else(|e| panic!("warm-up: {}", e));

    // Faucet — pre-registered at genesis with AuthKeys::Single.
    let (faucet_pk_bytes, faucet_sk_bytes) = net
        .load_faucet_key()
        .unwrap_or_else(|e| panic!("load faucet.key: {}", e));
    let faucet_sk =
        FalconSecretKey::from_bytes(&faucet_sk_bytes).expect("faucet.key invalid FALCON sk");
    let faucet_addr = pyde_account::address::derive_eoa_address(&faucet_pk_bytes);

    // ── 1. Generate a fresh wallet (not registered anywhere) ────
    let fresh = Wallet::generate().expect("generate fresh wallet");
    let fresh_addr = *fresh.address();
    eprintln!("fresh wallet address: 0x{}", hex::encode(fresh_addr));

    // ── 2. Faucet sends 2M PYDE to fresh address ────────────────
    // Enough to cover a real-base-fee transfer + register pubkey
    // overhead. At GENESIS_BASE_FEE (50 gwei × 21 K gas ≈ 1 M PYDE
    // per transfer in the worst case) the previous 100 PYDE was
    // insufficient — the test was always going to hit
    // `InsufficientBalance` once `chain_id != 1` (audit 383) forced
    // it onto the same generator-produced genesis as production.
    let mut faucet_tx = Transaction {
        from: faucet_addr,
        to: fresh_addr,
        value: 2_000_000 * 1_000_000_000, // 2M PYDE in quanta (10^9 quanta = 1 PYDE)
        data: vec![],
        gas_limit: 21_000,
        nonce: 0,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id: 7331,
        tx_type: TransactionType::Standard,
    };
    sign_tx(&mut faucet_tx, &faucet_sk);
    let fund_hash = net
        .submit_raw_tx(0, &faucet_tx.to_bytes())
        .unwrap_or_else(|e| panic!("submit faucet drip: {}", e));
    let _ = net
        .wait_for_receipt_on_all(&fund_hash, Duration::from_secs(60))
        .unwrap_or_else(|e| panic!("wait faucet drip: {}", e));

    let fresh_balance_before = net
        .get_balance(0, &fresh_addr)
        .unwrap_or_else(|e| panic!("balance after drip: {}", e));
    assert_eq!(
        fresh_balance_before,
        2_000_000 * 1_000_000_000,
        "faucet drip should give fresh wallet 2M PYDE"
    );

    // ── 3. Confirm normal signed tx is REJECTED before registration
    //       (the 226 gate enforces AuthKeys::None must be registered
    //       before any signed tx).
    let provider = Provider::new(&net.nodes[0].rpc_url());
    let pre_register_err = fresh
        .transfer(&provider, &faucet_addr, 1_000_000)
        .await
        .err();
    assert!(
        pre_register_err.is_some(),
        "transfer from unregistered fresh wallet must fail (audit 226 gate)"
    );
    eprintln!(
        "pre-register transfer rejected as expected: {:?}",
        pre_register_err.unwrap()
    );

    // ── 4. Register the fresh wallet's pubkey (audit 229) ───────
    let register_receipt = fresh
        .register_pubkey(&provider)
        .await
        .unwrap_or_else(|e| panic!("register_pubkey: {:?}", e));
    assert!(
        register_receipt.success,
        "register_pubkey receipt should be success"
    );
    assert_eq!(
        register_receipt.gas_used, "0x0",
        "RegisterPubkey is gas-free"
    );

    // ── 5. Now a normal signed transfer must succeed ────────────
    // Send 1 PYDE back to the faucet to prove the wallet is now
    // operational. The faucet is registered already so it's a fine
    // sink; we just want to prove the fresh wallet can send.
    let post_register_receipt = fresh
        .transfer(&provider, &faucet_addr, 1_000_000_000) // 1 PYDE
        .await
        .unwrap_or_else(|e| panic!("post-register transfer: {:?}", e));
    assert!(
        post_register_receipt.success,
        "post-register transfer should succeed"
    );

    // Final balance sanity: fresh wallet started with 2M PYDE,
    // sent 1 PYDE, paid gas. Should be a bit less than 2M PYDE.
    let fresh_balance_after = net
        .get_balance(0, &fresh_addr)
        .unwrap_or_else(|e| panic!("balance after: {}", e));
    assert!(
        fresh_balance_after > 0,
        "fresh wallet should still have balance"
    );
    assert!(
        fresh_balance_after < fresh_balance_before,
        "fresh wallet balance should decrease (gas + transfer): before={} after={}",
        fresh_balance_before,
        fresh_balance_after
    );
    eprintln!(
        "fresh wallet balance: before={} after={} (delta covers 1 PYDE transfer + gas)",
        fresh_balance_before, fresh_balance_after
    );
}
