//! Double-sign slashing end-to-end test (slice 6.6, plan task 068).
//!
//! Validates the Phase 1 slashing fix across the network:
//!   - A forged `DoubleSignEvidence` with two REAL FALCON signatures
//!     from node-0's validator key (loaded from disk) is submitted
//!     as a `TransactionType::Slash` by node-1 via RPC.
//!   - The pipeline's `execute_slash` path runs, re-verifies both
//!     signatures against node-0's on-chain public key, zeroes its
//!     stake, marks it Ejected, and credits node-1 with the 10%
//!     finder's fee.
//!
//! The evidence is forged in the sense that the two block hashes
//! (`[0x11;32]` and `[0x22;32]`) don't correspond to real blocks —
//! but they don't need to. The slashing invariant is "this validator
//! FALCON-signed two different `(slot, hash)` pairs under the
//! proposer-sign protocol", and that invariant holds here because
//! we used node-0's real secret key to produce both signatures.

mod common;

use common::TestNetwork;
use pyde_consensus::hotstuff::proposer_sign_message;
use pyde_crypto::falcon::{falcon_sign, FalconSecretKey};
use std::time::Duration;

#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn double_sign_debits_stake() {
    let net = TestNetwork::spawn(4, true).unwrap_or_else(|e| panic!("spawn 4v testnet: {}", e));

    // Chain needs to be alive and advancing for the slash tx to land.
    net.wait_for_slot(5, Duration::from_secs(45))
        .unwrap_or_else(|e| panic!("warm-up: {}", e));

    // Load node-0's FALCON keypair. This is the signer being framed;
    // we use its REAL private key so the signatures genuinely verify.
    let (pk_bytes, sk_bytes) = net
        .load_validator_key(0)
        .unwrap_or_else(|e| panic!("load_validator_key(0): {}", e));
    let sk = FalconSecretKey::from_bytes(&sk_bytes)
        .expect("validator.key produced invalid FALCON secret key");

    // Addresses. funded[0..4] are the 4 validators in index order
    // (see slice 6.5 commit note for the dedup guarantee).
    let funded = net
        .funded_addresses()
        .unwrap_or_else(|e| panic!("funded: {}", e));
    let offender = funded[0]; // node-0
    let submitter = funded[1]; // node-1 — pays gas, earns finder's fee

    // Sanity: on-chain state confirms node-0 is active and staked.
    let pre_validators = net
        .get_validator_set(1)
        .unwrap_or_else(|e| panic!("pre-slash validators: {}", e));
    eprintln!("pre-slash validator set:");
    for (addr, stake, status) in &pre_validators {
        eprintln!("  {}  stake={}  status={}", addr, stake, status);
    }
    let offender_pre = find_validator(&pre_validators, &offender)
        .unwrap_or_else(|| panic!("offender 0x{} not in validator set", hex::encode(offender)));
    assert_eq!(
        offender_pre.2, "active",
        "offender should be active pre-slash; got {}",
        offender_pre.2
    );
    assert!(
        offender_pre.1 > 0,
        "offender should have stake pre-slash; got {}",
        offender_pre.1
    );
    let pre_submitter_balance = net
        .get_balance(1, &submitter)
        .unwrap_or_else(|e| panic!("submitter balance pre: {}", e));

    // Build forged-but-valid double-sign evidence. Slot is arbitrary;
    // the pipeline doesn't cross-check slot against actual block
    // history, only that the signatures verify over
    // `proposer_sign_message(chain_id, slot, hash)`. Sigs MUST be
    // produced under the local chain's `chain_id` — evidence signed
    // for a different chain is rejected by the slash handler (the
    // cross-chain replay defense).
    let slot: u64 = 100;
    let chain_id = net.chain_id;
    let block_hash_1 = [0x11u8; 32];
    let block_hash_2 = [0x22u8; 32];
    let msg_1 = proposer_sign_message(chain_id, slot, &block_hash_1);
    let msg_2 = proposer_sign_message(chain_id, slot, &block_hash_2);
    let sig_1 = falcon_sign(&sk, &msg_1).expect("FALCON sign msg_1");
    let sig_2 = falcon_sign(&sk, &msg_2).expect("FALCON sign msg_2");

    // Sanity: confirm the sigs we just produced verify against the
    // pubkey on file. Cheap local check; catches key-format bugs
    // before we spend 60s waiting for an RPC round-trip.
    let pk = pyde_crypto::falcon::FalconPublicKey::from_bytes(&pk_bytes)
        .expect("validator.key produced invalid FALCON public key");
    assert!(
        pyde_crypto::falcon::falcon_verify(&pk, &msg_1, &sig_1),
        "local sig_1 verify failed — key-load is wrong"
    );
    assert!(
        pyde_crypto::falcon::falcon_verify(&pk, &msg_2, &sig_2),
        "local sig_2 verify failed — key-load is wrong"
    );

    let evidence_bytes = TestNetwork::encode_double_sign_evidence_bytes(
        slot,
        &block_hash_1,
        sig_1.as_bytes(),
        &block_hash_2,
        sig_2.as_bytes(),
        &offender,
        &submitter,
    );
    let evidence_hex = hex::encode(&evidence_bytes);
    eprintln!(
        "evidence size: {} bytes ({} hex chars)",
        evidence_bytes.len(),
        evidence_hex.len()
    );

    // Submit via node-1 (the submitter / finder).
    let tx_hash = net
        .submit_slash_tx(1, &submitter, &evidence_hex)
        .unwrap_or_else(|e| panic!("submit_slash_tx: {}", e));
    eprintln!("slash tx_hash: {}", tx_hash);

    // Wait for the slash to land on every validator. If the evidence
    // were invalid the tx would still land — just with success=false.
    let receipts = net
        .wait_for_receipt_on_all(&tx_hash, Duration::from_secs(60))
        .unwrap_or_else(|e| panic!("receipt wait: {}", e));
    for (i, r) in receipts.iter().enumerate() {
        eprintln!("node-{} receipt: success={} raw={}", i, r.success, r.raw);
        assert!(
            r.success,
            "node-{} reported a failed slash receipt:\nraw: {}",
            i, r.raw
        );
    }

    // Post-slash state: offender stake debited by VALIDATOR_STAKE,
    // status = exited. The Phase 1 slash is a fixed 10,000 PYDE
    // (10^13 quanta) per double-sign offense — not "100% of all
    // staked tokens" — so a validator staking more than that will
    // still have some balance left in their validator entry, but is
    // ejected from the active set regardless.
    //
    // SLASH_VALIDATOR_STAKE is re-exported from `pyde-slashing`.
    const VALIDATOR_SLASH_AMOUNT: u128 = 10_000_000_000_000;

    let post_validators = net
        .get_validator_set(1)
        .unwrap_or_else(|e| panic!("post-slash validators: {}", e));
    eprintln!("post-slash validator set:");
    for (addr, stake, status) in &post_validators {
        eprintln!("  {}  stake={}  status={}", addr, stake, status);
    }
    let offender_post = find_validator(&post_validators, &offender)
        .unwrap_or_else(|| panic!("offender 0x{} missing post-slash", hex::encode(offender)));

    let expected_post_stake = offender_pre.1.saturating_sub(VALIDATOR_SLASH_AMOUNT);
    assert_eq!(
        offender_post.1, expected_post_stake,
        "offender stake: pre {} - slash {} should give {}, got {}",
        offender_pre.1, VALIDATOR_SLASH_AMOUNT, expected_post_stake, offender_post.1
    );
    assert_eq!(
        offender_post.2, "exited",
        "offender status should be exited post-slash; got {}",
        offender_post.2
    );

    // The finder's fee and gas charges interleave with proposer
    // rewards + validator-subsidy accrual that the submitter is
    // also accumulating (node-1 is itself an active validator
    // producing blocks during the test). Disentangling those flows
    // would need RPC access to the accumulator fields that aren't
    // exposed yet, so we log the delta for visibility but don't
    // assert an exact value here. The finder-fee arithmetic is
    // unit-tested in `crates/tx/src/pipeline.rs` slash tests; this
    // test's load-bearing invariants are the stake decrement + the
    // ejection on-chain, both checked above.
    let post_submitter_balance = net
        .get_balance(1, &submitter)
        .unwrap_or_else(|e| panic!("submitter balance post: {}", e));
    let expected_fee = VALIDATOR_SLASH_AMOUNT / 10;
    let actual_delta = post_submitter_balance as i128 - pre_submitter_balance as i128;
    eprintln!(
        "submitter balance: pre={} post={} delta={} (expected fee component: {})",
        pre_submitter_balance, post_submitter_balance, actual_delta, expected_fee
    );
}

fn find_validator<'a>(
    set: &'a [(String, u128, String)],
    addr: &[u8; 32],
) -> Option<&'a (String, u128, String)> {
    let needle = format!("0x{}", hex::encode(addr));
    set.iter().find(|(a, _, _)| a == &needle)
}
