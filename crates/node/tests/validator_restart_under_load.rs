//! Validator restart under load — skeleton.
//!
//! Combines a continuous tx-submission task with a single
//! kill/restart cycle to verify the test infrastructure works for
//! the planned bulkier follow-up (mixed workload, 6 rotation cycles,
//! 65 min total). Validates that:
//!   - `TestNetwork::kill_node` + `restart_node` correctly tear down
//!     and bring up a subprocess validator while another tokio task
//!     is hammering the surviving nodes' RPC.
//!   - 3-of-4 quorum keeps producing blocks during the kill window.
//!   - The restarted node catches up to the network tip without
//!     state_root divergence.
//!   - The disk-prune restart edge (closed by `13e2f96` —
//!     `seen_proposals` survives a wedge + restart) doesn't fire a
//!     double-propose evidence event under sustained load.
//!
//! Skeleton scope (one kill cycle):
//!   - 4 validators, chain_id = 7331 (FALCON signature verification
//!     enforced, no `--dev` shortcut).
//!   - Faucet hammers transfers at ~30 TPS, round-robin across all
//!     4 nodes' RPC endpoints. Single sender keeps the test surface
//!     small; rate is capped to fit inside the 16-slot nonce window
//!     (see `TARGET_TPS`). The full version will fund 30+ wallets to
//!     mirror the loadgen_mixed setup.
//!   - 1 kill / 5 min downtime / restart / 5 min stabilize cycle on
//!     `VICTIM_NODE_IDX`.
//!   - Final assertions: state_root match across all 4, no
//!     `DOUBLE PROPOSE DETECTED` in any node's stdout, watchdog
//!     never tripped.
//!   - ~13 min total runtime.
//!
//! What this skeleton does NOT cover (full-version follow-up):
//!   - Mixed workload (calls, encrypted txs) under restart — the
//!     encrypted-tx pipeline's decryption coordinator across restart
//!     is the highest-priority gap once this skeleton is green.
//!   - Multi-cycle rotation covering all 4 nodes — the existing
//!     `validator_churn` test (idle chain) flagged a 4-of-4 stall
//!     audit item that the under-load version must re-probe.
//!   - Realistic operator-restart cadence variations (10 s blip vs
//!     5 min binary upgrade vs 30 min container restart).
//!
//! Marked `#[ignore]` because subprocess-based — run via
//! `cargo test --test validator_restart_under_load -- --ignored
//! --nocapture`.

mod common;

use common::TestNetwork;
use pyde_account::address::derive_eoa_address;
use pyde_crypto::falcon::{falcon_sign, FalconSecretKey};
use pyde_tx::types::{FeePayer, Transaction, TransactionType};
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// audit-383: `pyde testnet` refuses chain_id = 1 (mainnet) and the
// loadgen test fixture uses 7331 — match it so FALCON signature
// verification stays on (no `--dev` skip path).
const CHAIN_ID: u64 = 7331;
const NUM_VALIDATORS: usize = 4;
const VICTIM_NODE_IDX: usize = 0;
/// Single faucet sender keeps the test surface small but bumps into
/// the 16-slot nonce window: at >~40 TPS we submit nonces faster than
/// the chain can commit them, and the bulk land as
/// `InvalidNonce::AboveWindow`. 30 TPS gives ~12 in-flight per 400 ms
/// slot — well inside the window, so we don't spend the run thrashing
/// the resync branch. The full version (planned follow-up) will fund
/// 30+ wallets and target 200+ TPS aggregate, mirroring
/// `loadgen_mixed`.
const TARGET_TPS: u64 = 30;

const WARMUP_SLOT: u64 = 30;
const WARMUP_TIMEOUT_SECS: u64 = 60;

const PRE_KILL_LOAD_SECS: u64 = 120;
const DOWNTIME_SECS: u64 = 300;
const STABILIZE_SECS: u64 = 300;

/// Steady-state 4-of-4 produces ~2.5 slots/sec (400 ms/slot). With
/// node-0 down, every 4th slot's turn hits PROPOSAL_TIMEOUT_MS
/// (200 ms) before the fallback proposer fires, dragging the
/// average down to ~1.8 slots/sec — about 540 slots over 300 s.
/// Demand ≥ 500 to keep clear of that envelope while still flagging
/// any "engine wedged" or "split-brain" regression where progress
/// drops below ~1.7 slots/sec.
const MIN_SLOTS_DURING_DOWNTIME: u64 = 500;

const TX_VALUE: u128 = 1;
/// Fixed recipient for skeleton transfers — keeps the test small.
/// The recipient never has a registered FALCON pubkey, but that's
/// fine because we're testing send, not receive-side semantics.
const SKELETON_RECIPIENT: [u8; 32] = [0x42; 32];

#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn validator_restart_under_load_skeleton() {
    eprintln!("=== validator restart under load (skeleton) ===");

    let mut net = TestNetwork::spawn_with_chain_id(NUM_VALIDATORS, CHAIN_ID)
        .unwrap_or_else(|e| panic!("spawn {NUM_VALIDATORS}v: {e}"));

    net.wait_for_slot(WARMUP_SLOT, Duration::from_secs(WARMUP_TIMEOUT_SECS))
        .unwrap_or_else(|e| panic!("warm-up to slot {WARMUP_SLOT}: {e}"));
    eprintln!("warm-up: head={}", max_live_head(&net, None));

    // Pre-test state_root sanity. Catches a network that's already
    // wedged or divergent before we add load — keeps the test signal
    // clean if a regression elsewhere breaks the cold-boot path.
    let initial_root = net
        .state_root(0)
        .unwrap_or_else(|e| panic!("initial state_root: {e}"));
    for n in &net.nodes[1..] {
        let r = net
            .state_root(n.index)
            .unwrap_or_else(|e| panic!("initial state_root node-{}: {e}", n.index));
        assert_eq!(
            r, initial_root,
            "pre-test state_root divergence on node-{}",
            n.index
        );
    }

    let (faucet_pk_bytes, faucet_sk_bytes) = net
        .load_faucet_key()
        .unwrap_or_else(|e| panic!("load faucet.key: {e}"));
    let faucet_addr = derive_eoa_address(&faucet_pk_bytes);
    eprintln!("faucet 0x{} ready", hex::encode(faucet_addr));

    let rpc_urls: Vec<String> = net.nodes.iter().map(|n| n.rpc_url()).collect();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("reqwest client");

    let stop_senders = Arc::new(AtomicBool::new(false));
    let submit_ok = Arc::new(AtomicU64::new(0));
    let submit_err = Arc::new(AtomicU64::new(0));
    let wedge_detected = Arc::new(AtomicBool::new(false));

    // Sender + watchdog run on the tokio runtime; orchestration runs
    // on this thread because `kill_node` / `restart_node` are sync
    // and own `&mut TestNetwork`. Senders early-exit via
    // `stop_senders` so the runtime block_on at the bottom drains
    // cleanly.
    let sender_handle = runtime.spawn({
        let client = client.clone();
        let rpc_urls = rpc_urls.clone();
        let faucet_sk_bytes = faucet_sk_bytes.clone();
        let stop = stop_senders.clone();
        let ok = submit_ok.clone();
        let err = submit_err.clone();
        async move {
            let faucet_sk =
                FalconSecretKey::from_bytes(&faucet_sk_bytes).expect("invalid FALCON secret key");
            run_faucet_senders(client, rpc_urls, faucet_sk, faucet_addr, stop, ok, err).await;
        }
    });

    let watchdog_handle = runtime.spawn({
        let client = client.clone();
        let rpc_urls = rpc_urls.clone();
        let stop = stop_senders.clone();
        let flag = wedge_detected.clone();
        async move {
            run_watchdog(client, rpc_urls, stop, flag).await;
        }
    });

    // ── Pre-kill load window ───────────────────────────────────
    eprintln!("--- pre-kill load: {PRE_KILL_LOAD_SECS}s ---");
    std::thread::sleep(Duration::from_secs(PRE_KILL_LOAD_SECS));
    let pre_kill_head = max_live_head(&net, None);
    let pre_kill_ok = submit_ok.load(Ordering::Relaxed);
    eprintln!("pre-kill: head={pre_kill_head}, txs ok={pre_kill_ok}");
    assert!(
        wedge_detected.load(Ordering::Relaxed) == false,
        "wedge detected during pre-kill load window",
    );

    // ── Kill victim ─────────────────────────────────────────────
    eprintln!("--- killing node-{VICTIM_NODE_IDX} ---");
    net.kill_node(VICTIM_NODE_IDX)
        .unwrap_or_else(|e| panic!("kill node-{VICTIM_NODE_IDX}: {e}"));

    let downtime_start = Instant::now();
    std::thread::sleep(Duration::from_secs(DOWNTIME_SECS));
    let post_downtime_head = max_live_head(&net, Some(VICTIM_NODE_IDX));
    let advanced = post_downtime_head.saturating_sub(pre_kill_head);
    assert!(
        advanced >= MIN_SLOTS_DURING_DOWNTIME,
        "chain stalled while node-{VICTIM_NODE_IDX} down: \
         only advanced {advanced} slots in {}s (min {MIN_SLOTS_DURING_DOWNTIME})",
        downtime_start.elapsed().as_secs(),
    );
    eprintln!(
        "downtime: head {pre_kill_head} -> {post_downtime_head} (+{advanced} slots in {}s)",
        downtime_start.elapsed().as_secs(),
    );

    // ── Restart + stabilize ─────────────────────────────────────
    eprintln!("--- restarting node-{VICTIM_NODE_IDX} ---");
    net.restart_node(VICTIM_NODE_IDX)
        .unwrap_or_else(|e| panic!("restart node-{VICTIM_NODE_IDX}: {e}"));

    let stabilize_start = Instant::now();
    let catchup_target = max_live_head(&net, None) + 3;
    // The victim has ~750 slots of gap after a 300 s downtime. P2P
    // block-sync is much faster than slot pace, but validator
    // bootstrap (peer discovery, finding the right gossipsub mesh,
    // pulling missing blocks) still chews real wall-time. The
    // existing validator_churn test uses 60 s for a 5 s downtime;
    // scale to 180 s here to leave headroom without masking a real
    // sync regression.
    wait_for_node_slot(
        &net,
        VICTIM_NODE_IDX,
        catchup_target,
        Duration::from_secs(180),
    )
    .unwrap_or_else(|e| panic!("node-{VICTIM_NODE_IDX} catch-up to slot {catchup_target}: {e}"));
    eprintln!(
        "post-restart catch-up: node-{VICTIM_NODE_IDX} -> slot {catchup_target} in {}s",
        stabilize_start.elapsed().as_secs(),
    );

    // Stay under load for the remainder of the stabilize window so a
    // delayed wedge has time to manifest while traffic is still
    // flowing.
    let stab_remaining =
        Duration::from_secs(STABILIZE_SECS).saturating_sub(stabilize_start.elapsed());
    if !stab_remaining.is_zero() {
        eprintln!("stabilize: {} s remaining", stab_remaining.as_secs());
        std::thread::sleep(stab_remaining);
    }

    // ── Drain senders + watchdog ────────────────────────────────
    stop_senders.store(true, Ordering::SeqCst);
    runtime.block_on(async {
        let _ = sender_handle.await;
        let _ = watchdog_handle.await;
    });

    // ── Final assertions ────────────────────────────────────────
    assert!(
        !wedge_detected.load(Ordering::SeqCst),
        "watchdog reported wedge during run",
    );

    let final_root = net
        .state_root(VICTIM_NODE_IDX)
        .unwrap_or_else(|e| panic!("post-test state_root node-{VICTIM_NODE_IDX}: {e}"));
    for n in &net.nodes {
        if n.index == VICTIM_NODE_IDX {
            continue;
        }
        let r = net
            .state_root(n.index)
            .unwrap_or_else(|e| panic!("post-test state_root node-{}: {e}", n.index));
        assert_eq!(
            r, final_root,
            "post-test state_root divergence: node-{VICTIM_NODE_IDX}={final_root} node-{}={r}",
            n.index,
        );
    }
    eprintln!("state_root convergence: all 4 nodes = {final_root}");

    // Disk-prune restart edge (`13e2f96`): a wedge + restart MUST
    // NOT have caused the validator to rebuild the same
    // `(target_height, view=0)` block with a fresh `timestamp`. Peers
    // would log `DOUBLE PROPOSE DETECTED` if it had. Scan every
    // node's stdout buffer captured by the TestNetwork harness.
    for n in &net.nodes {
        let log = n.output_snapshot();
        assert!(
            !log.contains("DOUBLE PROPOSE DETECTED"),
            "node-{} logged DOUBLE PROPOSE during run — disk-prune restart edge may be open",
            n.index,
        );
    }
    eprintln!("no DOUBLE PROPOSE on any node");

    let final_ok = submit_ok.load(Ordering::Relaxed);
    let final_err = submit_err.load(Ordering::Relaxed);
    eprintln!(
        "=== skeleton complete: txs ok={final_ok}, err={final_err}, final head={} ===",
        max_live_head(&net, None),
    );
}

// ─── Background tasks ───────────────────────────────────────────

async fn run_faucet_senders(
    client: reqwest::Client,
    rpc_urls: Vec<String>,
    faucet_sk: FalconSecretKey,
    faucet_addr: [u8; 32],
    stop: Arc<AtomicBool>,
    ok: Arc<AtomicU64>,
    err: Arc<AtomicU64>,
) {
    let interval = Duration::from_secs_f64(1.0 / TARGET_TPS as f64);
    let mut nonce = 0u64;
    let mut rr_idx = 0usize;
    let mut next_submit = Instant::now();
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let now = Instant::now();
        if now < next_submit {
            tokio::time::sleep(next_submit - now).await;
        }
        next_submit += interval;
        let url = &rpc_urls[rr_idx % rpc_urls.len()];
        rr_idx += 1;
        match submit_transfer(&client, url, &faucet_sk, faucet_addr, nonce).await {
            Ok(_) => {
                ok.fetch_add(1, Ordering::Relaxed);
                nonce += 1;
            }
            Err(_) => {
                err.fetch_add(1, Ordering::Relaxed);
                // The chain may have committed the tx even though
                // the HTTP reply failed (e.g. the killed node's RPC
                // returns 500 mid-window). Re-sync from chain state
                // to avoid burning the rest of the run on
                // `InvalidNonce::BelowWindow`.
                if let Some(chain_nonce) = fetch_nonce(&client, url, &faucet_addr).await {
                    if chain_nonce > nonce {
                        nonce = chain_nonce;
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
                next_submit = Instant::now();
            }
        }
    }
}

async fn run_watchdog(
    client: reqwest::Client,
    rpc_urls: Vec<String>,
    stop: Arc<AtomicBool>,
    flag: Arc<AtomicBool>,
) {
    const POLL: Duration = Duration::from_secs(30);
    const STALL_THRESH: Duration = Duration::from_secs(60);
    let mut last_heads: Vec<Option<u64>> = vec![None; rpc_urls.len()];
    let mut last_advance = Instant::now();
    loop {
        tokio::time::sleep(POLL).await;
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let mut cur_heads = Vec::with_capacity(rpc_urls.len());
        let mut any_advanced = false;
        for (i, url) in rpc_urls.iter().enumerate() {
            let h = fetch_block_number(&client, url).await;
            cur_heads.push(h);
            match (h, last_heads[i]) {
                (Some(c), Some(p)) if c > p => any_advanced = true,
                (Some(_), None) => any_advanced = true,
                _ => {}
            }
        }
        if any_advanced {
            last_advance = Instant::now();
            last_heads = cur_heads.clone();
            eprintln!("[watchdog] heads: {:?}", cur_heads);
            continue;
        }
        let stalled = Instant::now().duration_since(last_advance);
        eprintln!(
            "[watchdog] heads: {:?} (NO ADVANCE for {} s)",
            cur_heads,
            stalled.as_secs(),
        );
        if stalled >= STALL_THRESH {
            eprintln!(
                "*** WEDGE: no head advance for {} s, heads={:?} ***",
                stalled.as_secs(),
                cur_heads,
            );
            flag.store(true, Ordering::SeqCst);
            return;
        }
    }
}

// ─── Network helpers (copied from validator_churn; refactor to common later) ───

fn max_live_head(net: &TestNetwork, exclude: Option<usize>) -> u64 {
    net.current_slots()
        .into_iter()
        .filter(|(idx, _)| Some(*idx) != exclude)
        .filter_map(|(_, s)| s)
        .max()
        .unwrap_or(0)
}

fn wait_for_node_slot(
    net: &TestNetwork,
    node_idx: usize,
    target_slot: u64,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let cur = net
            .current_slots()
            .into_iter()
            .find(|(i, _)| *i == node_idx)
            .and_then(|(_, s)| s)
            .unwrap_or(0);
        if cur >= target_slot {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "node-{node_idx} stuck at slot {cur} (target {target_slot})"
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ─── Tx submission + RPC ────────────────────────────────────────

async fn submit_transfer(
    client: &reqwest::Client,
    url: &str,
    sender_sk: &FalconSecretKey,
    sender_addr: [u8; 32],
    nonce: u64,
) -> Result<[u8; 32], ()> {
    let mut tx = Transaction {
        from: sender_addr,
        to: SKELETON_RECIPIENT,
        value: TX_VALUE,
        data: vec![],
        gas_limit: 50_000,
        nonce,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id: CHAIN_ID,
        tx_type: TransactionType::Standard,
    };
    let tx_hash = tx.hash();
    let sig = falcon_sign(sender_sk, &tx_hash).map_err(|_| ())?;
    tx.signature = sig.as_bytes().to_vec();
    rpc_send_raw(client, url, &hex::encode(tx.to_bytes()))
        .await
        .map(|_| tx_hash)
}

async fn rpc_send_raw(
    client: &reqwest::Client,
    url: &str,
    tx_hex: &str,
) -> Result<serde_json::Value, ()> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "pyde_sendRawTransaction",
        "params": [tx_hex],
    });
    let resp = client.post(url).json(&body).send().await.map_err(|_| ())?;
    let val: serde_json::Value = resp.json().await.map_err(|_| ())?;
    if val.get("error").is_some() {
        return Err(());
    }
    Ok(val)
}

async fn fetch_block_number(client: &reqwest::Client, url: &str) -> Option<u64> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "pyde_blockNumber",
        "params": [],
    });
    let resp = client.post(url).json(&body).send().await.ok()?;
    let val: serde_json::Value = resp.json().await.ok()?;
    let raw = val.get("result")?.as_str()?;
    u64::from_str_radix(raw.strip_prefix("0x").unwrap_or(raw), 16).ok()
}

async fn fetch_nonce(client: &reqwest::Client, url: &str, addr: &[u8; 32]) -> Option<u64> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "pyde_getTransactionCount",
        "params": [format!("0x{}", hex::encode(addr))],
    });
    let resp = client.post(url).json(&body).send().await.ok()?;
    let val: serde_json::Value = resp.json().await.ok()?;
    let raw = val.get("result")?.as_str()?;
    // pyde_getTransactionCount returns a DECIMAL string (rpc.rs:327
    // emits `nonce.to_string()`). Hex parsing happens to coincide
    // with decimal for digits 0–9, so the bug stays latent until
    // ≥10; "12" decimal then parses as 18 hex and the sender
    // starts overshooting the chain's nonce window.
    raw.parse::<u64>().ok()
}
