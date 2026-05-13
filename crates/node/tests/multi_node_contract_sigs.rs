//! Production-sigs + smart-contract lifecycle across a 4-node
//! network (plan backlog — closes the two biggest coverage gaps
//! in Phase 6).
//!
//! This single test covers two invariants that previously only
//! held at the in-memory / single-node level:
//!
//!  1. Real FALCON-512 signature verification across consensus.
//!     Every tx in every block is re-verified by every validator
//!     under `chain_id != 31337`. The devnet-chain tests skip
//!     FALCON entirely; this one does not.
//!
//!  2. Smart contract deploy + call propagates identically across
//!     the network. Code bytes are written at `code_key(addr)` on
//!     every node; a subsequent state-changing call via
//!     `pyde_sendRawTransaction` must reach every validator, land
//!     in a block, and update contract storage deterministically
//!     — `pyde_call(get_count)` from every node must return 42.
//!
//! Flow:
//!  - 4 validators at chain_id=7331 (production mode — audit 383
//!    refuses mainnet id 1 at the testnet generator).
//!  - Compile the on-chain `Counter` contract (same source used by
//!    `production_sigs.rs` — has `init()`, `set_count(n)`,
//!    `get_count()`).
//!  - Faucet (1T PYDE at genesis, pubkey pre-installed) signs a
//!    Deploy tx, submits via `pyde_sendRawTransaction`.
//!  - Wait for the deploy receipt; extract contract address from
//!    `returnData`.
//!  - Assert `pyde_getCode(contract)` agrees across all 4 nodes.
//!  - Faucet signs + submits `set_count(42)`. Wait for the call
//!    receipt to land on every node with `success = true`.
//!  - Query `pyde_call(get_count)` on each of the 4 nodes; all
//!    must return the same 8-byte LE encoding of 42.
//!  - Assert `pyde_stateRoot` matches across the 4 nodes.

mod common;

use common::TestNetwork;
use pyde_crypto::falcon::{falcon_sign, FalconSecretKey};
use pyde_tx::types::{FeePayer, Transaction, TransactionType};
use std::time::Duration;

const COUNTER_SRC: &str = r#"
contract Counter {
    storage { count: u64, }
    #[constructor] pub fn init() { self.count = 0; }
    pub fn increment() { self.count = self.count + 1; }
    pub fn set_count(n: u64) { self.count = n; }
    #[view] pub fn get_count() -> u64 { return self.count; }
}
"#;

#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn contract_deploy_and_call_with_real_sigs() {
    // chain_id=7331 (canonical public testnet id) → block processor
    // still enforces FALCON sig verification on every tx because
    // `dev_skip_signature` is only true at 31337. audit 383 refuses
    // the mainnet id (1) at the `pyde testnet` generator, so we use
    // 7331 for production-mode subprocess tests.
    let net = TestNetwork::spawn_with_chain_id(4, 7331)
        .unwrap_or_else(|e| panic!("spawn 4v@chain_id=7331: {}", e));

    // Wait for chain to advance so the first tx has somewhere to land.
    net.wait_for_slot(3, Duration::from_secs(30))
        .unwrap_or_else(|e| panic!("warm-up: {}", e));

    // Faucet: 1T PYDE allocation at genesis, AuthKeys::Single with
    // the pubkey from the .key file. Good for ~200 txs of deploy-
    // class gas before we'd have to think about nonce/balance.
    let (faucet_pk_bytes, faucet_sk_bytes) = net
        .load_faucet_key()
        .unwrap_or_else(|e| panic!("load faucet.key: {}", e));
    let faucet_sk = FalconSecretKey::from_bytes(&faucet_sk_bytes)
        .expect("faucet.key produced invalid FALCON secret key");
    let faucet_addr = pyde_account::address::derive_eoa_address(&faucet_pk_bytes);
    eprintln!("faucet address: 0x{}", hex::encode(faucet_addr));

    // Sanity: all 4 nodes see the faucet's genesis balance.
    let faucet_balance = net
        .get_balance(0, &faucet_addr)
        .unwrap_or_else(|e| panic!("faucet balance: {}", e));
    assert!(
        faucet_balance > 10_000_000_000_000_000, // > 10k PYDE minimum for ~200 deploys
        "faucet balance too low for test: {}",
        faucet_balance
    );

    // ── 1. Compile Counter contract ─────────────────────────────
    let deploy_payload = compile_deploy_payload(COUNTER_SRC);
    eprintln!("compiled deploy payload: {} bytes", deploy_payload.len());

    // ── 2. Build + sign + submit Deploy tx ──────────────────────
    let mut deploy_tx = Transaction {
        from: faucet_addr,
        to: [0u8; 32], // Deploy targets zero address
        value: 0,
        data: deploy_payload,
        gas_limit: 100_000_000, // Counter is tiny, but ctor + storage writes need headroom
        nonce: 0,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id: 7331,
        tx_type: TransactionType::Deploy,
    };
    sign_tx(&mut deploy_tx, &faucet_sk);
    let deploy_hash = net
        .submit_raw_tx(0, &deploy_tx.to_bytes())
        .unwrap_or_else(|e| panic!("submit deploy: {}", e));
    eprintln!("deploy tx_hash: {}", deploy_hash);

    // ── 3. Wait for deploy receipt on every node ────────────────
    let deploy_receipts = net
        .wait_for_receipt_on_all(&deploy_hash, Duration::from_secs(60))
        .unwrap_or_else(|e| panic!("deploy receipt wait: {}", e));
    for (i, r) in deploy_receipts.iter().enumerate() {
        eprintln!("node-{} deploy receipt: success={}", i, r.success);
        assert!(
            r.success,
            "node-{} reports failed deploy receipt:\n{}",
            i, r.raw
        );
    }

    // ── 4. Extract contract address from receipt returnData ─────
    let return_bytes = TestNetwork::decode_return_data(&deploy_receipts[0].raw)
        .unwrap_or_else(|e| panic!("decode deploy returnData: {}", e));
    assert_eq!(
        return_bytes.len(),
        32,
        "deploy returnData should be a 32-byte address, got {} bytes",
        return_bytes.len()
    );
    let mut contract_addr = [0u8; 32];
    contract_addr.copy_from_slice(&return_bytes);
    eprintln!("deployed at: 0x{}", hex::encode(contract_addr));

    // ── 5. Code present + identical on every node ───────────────
    let codes: Vec<(usize, String)> = net
        .nodes
        .iter()
        .map(|n| {
            let c = net
                .get_code(n.index, &contract_addr)
                .unwrap_or_else(|e| panic!("get_code node-{}: {}", n.index, e));
            (n.index, c)
        })
        .collect();
    let reference_code = codes[0].1.clone();
    assert!(
        !reference_code.is_empty(),
        "node-0 has no code at {:?} — deploy didn't install bytecode",
        contract_addr
    );
    for (i, c) in &codes[1..] {
        assert_eq!(
            c,
            &reference_code,
            "code mismatch node-0 vs node-{}: {} vs {}",
            i,
            reference_code.len(),
            c.len()
        );
    }
    eprintln!(
        "code agreement: {} bytes on all 4 nodes",
        reference_code.len() / 2
    );

    // ── 6. Build + sign + submit set_count(42) ──────────────────
    let selector = otic::codegen::compute_selector("set_count");
    let mut call_data = selector.to_be_bytes().to_vec();
    call_data.extend_from_slice(&42u64.to_le_bytes());

    let mut call_tx = Transaction {
        from: faucet_addr,
        to: contract_addr,
        value: 0,
        data: call_data.clone(),
        gas_limit: 5_000_000,
        nonce: 1,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id: 7331,
        tx_type: TransactionType::Standard,
    };
    sign_tx(&mut call_tx, &faucet_sk);
    let call_hash = net
        .submit_raw_tx(0, &call_tx.to_bytes())
        .unwrap_or_else(|e| panic!("submit set_count: {}", e));
    eprintln!("set_count tx_hash: {}", call_hash);

    let call_receipts = net
        .wait_for_receipt_on_all(&call_hash, Duration::from_secs(60))
        .unwrap_or_else(|e| panic!("call receipt wait: {}", e));
    for (i, r) in call_receipts.iter().enumerate() {
        eprintln!("node-{} set_count receipt: success={}", i, r.success);
        assert!(
            r.success,
            "node-{} reports failed set_count receipt:\n{}",
            i, r.raw
        );
    }

    // ── 7. get_count() via pyde_call on every node ──────────────
    let get_selector = otic::codegen::compute_selector("get_count");
    let view_calldata = get_selector.to_be_bytes().to_vec();
    let mut view_results: Vec<(usize, String)> = Vec::new();
    for n in &net.nodes {
        let r = net
            .pyde_call_view(n.index, &contract_addr, &view_calldata)
            .unwrap_or_else(|e| panic!("pyde_call node-{}: {}", n.index, e));
        view_results.push((n.index, r));
    }
    eprintln!("view results: {:?}", view_results);
    // pyde_call returns the GP return as 8 bytes LE hex — r1 = 42
    // for our set_count. Expected: 2a00000000000000 (LE u64 of 42).
    let expected = hex::encode(42u64.to_le_bytes());
    for (i, v) in &view_results {
        assert_eq!(
            v, &expected,
            "node-{} pyde_call(get_count) returned {:?}, expected {:?}",
            i, v, expected
        );
    }

    // ── 8. state_root converges ─────────────────────────────────
    let reference_root = net
        .state_root(0)
        .unwrap_or_else(|e| panic!("state_root node-0: {}", e));
    for n in &net.nodes[1..] {
        let r = net
            .state_root(n.index)
            .unwrap_or_else(|e| panic!("state_root node-{}: {}", n.index, e));
        assert_eq!(
            r, reference_root,
            "state_root divergence after deploy+call:\n  node-0: {}\n  node-{}: {}",
            reference_root, n.index, r
        );
    }
    eprintln!("state_root match across all 4 nodes: {}", reference_root);
}

/// FALCON-sign a transaction in place. Matches the convention in
/// `production_sigs.rs`: the signature binds `tx.hash()`, which is
/// the Poseidon2 hash over the tx fields MINUS the signature slot.
fn sign_tx(tx: &mut Transaction, sk: &FalconSecretKey) {
    tx.signature = falcon_sign(sk, &tx.hash())
        .expect("FALCON sign")
        .as_bytes()
        .to_vec();
}

/// Compile `src` with otic and pack into the Deploy-tx `data`
/// pipeline format: `[clen u32 LE][rlen u32 LE][constructor][runtime]`.
/// Mirrors `production_sigs.rs::compile` — this is the canonical
/// on-chain deploy envelope.
fn compile_deploy_payload(src: &str) -> Vec<u8> {
    let c = otic::__compile_all_unchecked(src);
    let (_, cc) = &c[0];
    let mut out = Vec::with_capacity(8 + cc.constructor_bytecode.len() + cc.runtime_bytecode.len());
    out.extend_from_slice(&(cc.constructor_bytecode.len() as u32).to_le_bytes());
    out.extend_from_slice(&(cc.runtime_bytecode.len() as u32).to_le_bytes());
    out.extend_from_slice(&cc.constructor_bytecode);
    out.extend_from_slice(&cc.runtime_bytecode);
    out
}
