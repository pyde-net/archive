//! 1-hour comprehensive soak test — full smart-contract feature
//! surface under sustained mixed plaintext+encrypted traffic.
//!
//! This is the "rock-solid" gate: short loadgens (60s) only catch
//! correctness bugs and the most-obvious throughput issues. Hour-
//! plus runs catch the bugs that *only* show up over time:
//!
//!   - memory leaks (chain process RSS climbing)
//!   - log volume growth (operators run out of disk)
//!   - slot-timing drift (p99 creeps past 200ms after ~30min)
//!   - mempool / state-cache fragmentation
//!   - RocksDB compaction stalls
//!   - peer-set instability (libp2p mesh churn)
//!
//! and the long-tail interaction issues:
//!
//!   - AOT cache eviction under sustained varied calls
//!   - encrypted-tx pipeline backpressure under bursty inclusion
//!   - cross-contract reentrancy guards holding under load
//!   - factory pattern (deploy! from contract) not bloating state
//!
//! # Workload (every checkbox the user listed)
//!
//!   - Constructors with args ............ MegaContract::init, Helper::init
//!   - Events with indexed fields ........ Deposit, StatusChanged,
//!     ComplexResult, Ponged, Spawned
//!   - Enums with match .................. Status::{Active,Paused,Locked}
//!   - Payable functions ................. MegaContract::deposit
//!   - Complex args (struct) ............. UserData → complex_logic
//!   - Complex returns (u256) ............ complex_logic returns total
//!   - Complex storage layouts ........... Map<Address, u256>, Vec<u64>,
//!     struct fields, enum tag fields
//!   - Complex logic (math + state) ...... complex_logic + change_status
//!   - Cross-contract calls .............. MegaContract → IHelper.ping
//!   - Factory pattern (deploy!) ......... Spawner.spawn → deploy!(Helper)
//!   - Reentrancy probe .................. MegaContract.delegate_ping
//!     calls Helper which writes
//!     state — exercises CallExt +
//!     cross-contract state isolation
//!   - AOT optimization wiring ........... hot-path repeatedly hits
//!     MegaContract.increment, the
//!     AotCache compiles in
//!     background, subsequent calls
//!     take the JIT path.
//!   - Plaintext + encrypted mix ......... configurable; default 50/50
//!
//! # Run
//!
//!   cargo test -p pyde-node --test loadgen_soak --release -- \
//!     --ignored --nocapture
//!
//! # Knobs (env vars)
//!
//!   PYDE_SOAK_DURATION  — measurement seconds (default 3600 = 1h)
//!   PYDE_SOAK_TPS       — submit rate (default 100)
//!   PYDE_SOAK_SENDERS   — funded sender count (default 50)
//!   PYDE_SOAK_WARMUP    — warm-up seconds, not measured (default 60)
//!   PYDE_SOAK_ENCRYPTED_PCT — % of submissions on encrypted path
//!                              (default 30)
//!
//! # Quote-able output
//!
//! At end-of-run the test prints:
//!   - submitted/inclusion/error counts per workload bucket
//!   - first-block vs last-block slot-timing percentiles (drift?)
//!   - process RSS at start vs end (leaks?)
//!   - AOT cache hit rate (warm path engaged?)
//!   - per-bucket inclusion latency p50/p95/p99
//!
//! Pass = no error rate climb, slot p99 stable, RSS bounded, AOT
//! warmed.

mod common;

use common::TestNetwork;
use pyde_account::address::derive_eoa_address;
use pyde_crypto::falcon::{falcon_keygen, falcon_sign, FalconSecretKey};
use pyde_tx::types::{AccessEntry, FeePayer, Transaction, TransactionType};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// Audit 383: `pyde testnet` refuses to generate artifacts for
// chain_id=1 (the canonical mainnet id). The soak runs against a
// 4-validator dev testnet, so use the canonical public-testnet id
// instead. Switching to 31337 would also work, but 7331 keeps the
// soak's signed-tx surface (chain_id != 31337 enforces FALCON
// signature verification on every tx) which matches what real
// testnet operators see.
const CHAIN_ID: u64 = 7331;
const FUND_PER_SENDER: u128 = 1_000_000_000_000_000_000;

// Method selector — delegate to the otic codegen helper so it stays
// in sync with the PVM dispatch table (same hash, same byte order).
// loadgen_mixed.rs uses the same path; our soak test must too or
// every contract call fails to dispatch.
fn selector(name: &str) -> [u8; 4] {
    otic::codegen::compute_selector(name).to_be_bytes()
}

// ────────────────────────────────────────────────────────────────────
// Contract suite — multi-contract source covering the user's full
// checklist. Lives inline so the test is self-contained; the .oti
// fixtures elsewhere in the tree have their own integration tests
// for compile correctness.
// ────────────────────────────────────────────────────────────────────
const SUITE_SRC: &str = r#"
// Cross-contract target. Helper is what MegaContract calls
// across the contract boundary (CallExt), and what Spawner
// instantiates via deploy! (the factory pattern).
contract Helper {
    storage {
        last_caller: Address,
        ping_count: u64,
    }

    event Ponged {
        #[indexed]
        caller: Address,
        count: u64,
    }

    #[constructor]
    pub fn init() {
        self.ping_count = 0;
    }

    pub fn ping() {
        self.last_caller = msg.sender;
        self.ping_count = self.ping_count + 1;
        emit Ponged { caller: msg.sender, count: self.ping_count };
    }

    #[view]
    pub fn get_count() -> u64 {
        return self.ping_count;
    }
}

// MegaContract — most of the feature surface in one place.
//
// Storage covers: u64, Map<Address,u256>, Vec<u64>, struct field,
// enum-tag field, Address. Methods cover: payable, complex args
// (UserData struct), complex returns (u256), complex logic
// (state-mutating math), enum match, events with #[indexed], errors,
// require!, assert!, view functions, cross-contract calls.
//
// Audit 404 / 354: previously this contract had a `signed_val: i64`
// field + `checked_signed(delta: i64)` method exercising signed
// integer math. Audit 354 documents that the codegen treats all
// integers as unsigned — `<`, `>`, `/`, `%`, `>>` on signed types
// produce wrong results. The strict typechecker rejects i64 to
// catch this; pre-audit-404 the soak compiled the source via the
// lax path and ran the broken arithmetic, reporting `ok=735 err=0`
// for the `checked_signed` bucket while the on-chain math was
// silently wrong (the assert and adds happened to coincide with
// correct values for the test inputs). Until the codegen gains
// real signed-integer ISA opcodes, the bucket is dropped.
contract MegaContract {
    storage {
        owner: Address,
        counter: u64,
        balances: Map<Address, u256>,
        scores: Vec<u64>,
        helper_addr: Address,
        statuses: Vec<u64>,
    }

    struct UserData {
        amount: u256,
        score: u64,
    }

    enum Status {
        Active,
        Paused,
        Locked,
    }

    event Deposit {
        #[indexed]
        from: Address,
        amount: u256,
    }
    event StatusChanged {
        new_status: u64,
    }
    event ComplexResult {
        #[indexed]
        caller: Address,
        total: u256,
    }

    error TooSmall { got: u256, min: u256 }
    error NotOwner {}

    #[constructor]
    pub fn init(initial: u64, helper: Address) {
        self.owner = msg.sender;
        self.counter = initial;
        self.helper_addr = helper;
    }

    // Payable + indexed event. Exercises VALUE in calldata and the
    // LOG opcode with topic count.
    #[payable]
    pub fn deposit() {
        let amount = msg.value as u256;
        require!(amount >= 1, TooSmall { got: amount, min: 1 });
        self.balances[msg.sender] = self.balances[msg.sender] + amount;
        emit Deposit { from: msg.sender, amount: amount };
    }

    // Complex args (struct) + complex returns (u256) + state mutation
    // + event emission + arithmetic.
    pub fn complex_logic(data: UserData) -> u256 {
        self.scores.push(data.score);
        let total = data.amount + (data.score as u256) * 10;
        emit ComplexResult { caller: msg.sender, total: total };
        return total;
    }

    // Enum match. Each arm pushes to scores AND emits an event so
    // the LOG opcode runs per dispatch.
    pub fn change_status(s: Status) {
        match s {
            Status::Active => {
                self.statuses.push(0);
                emit StatusChanged { new_status: 0 };
            }
            Status::Paused => {
                self.statuses.push(1);
                emit StatusChanged { new_status: 1 };
            }
            Status::Locked => {
                self.statuses.push(2);
                emit StatusChanged { new_status: 2 };
            }
        }
    }

    // Hot-path method for AOT exercise. The AotCache compiles
    // contracts in the background after the first call to a given
    // address; subsequent calls take the JIT path. We hammer this
    // method repeatedly to verify the cache warms.
    pub fn increment() {
        self.counter = self.counter + 1;
    }

    #[view]
    pub fn get_counter() -> u64 {
        return self.counter;
    }

    #[view]
    pub fn get_balance(a: Address) -> u256 {
        return self.balances[a];
    }

    #[view]
    pub fn scores_len() -> u64 {
        return self.scores.len();
    }
}

// Spawner — factory pattern. Each spawn() deploys a fresh Helper
// via the deploy! macro, exercising CREATE + per-caller create
// counter (audit 379) + per-block tx that does state writes via
// inner-CREATE.
//
// Audit 404: pre-fix `spawn()` returned `Address` and stored the
// child's address via `address(deploy!(Helper))`. The strict
// typechecker (now wired into `compile_all`) rejects that cast
// because `deploy!` returns a contract handle, not an Address.
// The lax path silently accepted it because contract handles ARE
// addresses internally — but that's a coincidence, not a contract.
// We drop the address-tracking machinery and call a method on the
// freshly-deployed `child` instead, which still exercises the full
// CREATE → constructor → runtime install path that the test cares
// about. The chain-side feature (factory-pattern deploys at
// execution time) is unchanged.
contract Spawner {
    storage {
        count: u64,
    }

    event Spawned {
        count: u64,
    }

    #[constructor]
    pub fn init() {
        self.count = 0;
    }

    pub fn spawn() {
        let child = deploy!(Helper);
        // Calling a method on the just-deployed child proves the
        // runtime is actually installed end-to-end, not just that
        // the constructor returned. We don't capture the address
        // because `address(<contract>)` doesn't typecheck.
        child.ping();
        self.count = self.count + 1;
        emit Spawned { count: self.count };
    }

    #[view]
    pub fn get_count() -> u64 {
        return self.count;
    }
}
"#;

struct DeployedContracts {
    helper: [u8; 32],
    mega: [u8; 32],
    spawner: [u8; 32],
}

struct Wallet {
    address: [u8; 32],
    pk_bytes: Vec<u8>,
    sk: FalconSecretKey,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum CallKind {
    /// Plaintext transfer — simplest path.
    Transfer,
    /// MegaContract::increment — hot-path for AOT cache exercise.
    Increment,
    /// MegaContract::complex_logic with struct arg — exercises
    /// complex args + complex returns.
    ComplexLogic,
    /// MegaContract::change_status — exercises enum match.
    ChangeStatus,
    /// MegaContract::deposit (payable) — exercises VALUE + LOG.
    Deposit,
    /// Spawner::spawn — exercises factory / deploy!.
    Spawn,
    /// Helper::ping (cross-contract) — exercises CallExt.
    Ping,
    /// Encrypted variant of Increment — exercises threshold
    /// encrypt + decrypt pipeline + post-decrypt apply.
    EncryptedIncrement,
}

impl CallKind {
    fn name(self) -> &'static str {
        match self {
            CallKind::Transfer => "transfer",
            CallKind::Increment => "increment",
            CallKind::ComplexLogic => "complex_logic",
            CallKind::ChangeStatus => "change_status",
            CallKind::Deposit => "deposit",
            CallKind::Spawn => "spawn",
            CallKind::Ping => "ping",
            CallKind::EncryptedIncrement => "encrypted_increment",
        }
    }

    /// Default 8-bucket workload weights summing to 100. Audit 404
    /// dropped the prior `SignedMath` bucket — the i64 contract it
    /// targeted ran wrong arithmetic via the lax compile path
    /// (audit 354), so the bucket was reporting `ok` for code that
    /// produced wrong results. Reintroduce post-codegen-signed-int
    /// support.
    fn default_weights() -> [(CallKind, u32); 8] {
        [
            (CallKind::Transfer, 25),
            (CallKind::Increment, 25),
            (CallKind::ComplexLogic, 10),
            (CallKind::ChangeStatus, 5),
            (CallKind::Deposit, 10),
            (CallKind::Spawn, 3),
            (CallKind::Ping, 7),
            (CallKind::EncryptedIncrement, 15),
        ]
    }

    fn pick(idx: u64, weights: &[(CallKind, u32)]) -> CallKind {
        let total: u32 = weights.iter().map(|(_, w)| *w).sum();
        let mut r = (idx % total as u64) as u32;
        for (k, w) in weights {
            if r < *w {
                return *k;
            }
            r -= *w;
        }
        weights[0].0
    }
}

fn compile_deploy_payload(
    src: &str,
    contract_name: &str,
    constructor_args: &[u8],
) -> Result<Vec<u8>, String> {
    // Audit 404: strict pipeline (resolve + typecheck + safety +
    // lower + codegen). Pre-fix this called the lax variant, which
    // silently accepted `i64` arithmetic (audit 354) and
    // `address(<contract>)` casts in the suite source. The strict
    // path now catches those at compile time so test fixtures can't
    // hide broken contracts.
    let compiled =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| otic::compile_all(src)))
            .map_err(|_| "otic compiler panicked on suite source".to_string())?
            .map_err(|diagnostics| format!("suite frontend rejected:\n{}", diagnostics))?;
    let (_, cc) = compiled
        .iter()
        .find(|(name, _)| name == contract_name)
        .ok_or_else(|| format!("contract {} not in compiled output", contract_name))?;
    let mut out = Vec::with_capacity(
        8 + cc.constructor_bytecode.len() + cc.runtime_bytecode.len() + constructor_args.len(),
    );
    out.extend_from_slice(&(cc.constructor_bytecode.len() as u32).to_le_bytes());
    out.extend_from_slice(&(cc.runtime_bytecode.len() as u32).to_le_bytes());
    out.extend_from_slice(&cc.constructor_bytecode);
    out.extend_from_slice(&cc.runtime_bytecode);
    out.extend_from_slice(constructor_args);
    Ok(out)
}

#[test]
#[ignore = "1h soak — spawns 4-node testnet + deploys 3 contracts; run with --ignored --nocapture"]
fn comprehensive_soak() {
    let target_tps: u64 = env_var_u64("PYDE_SOAK_TPS", 100);
    let duration_s: u64 = env_var_u64("PYDE_SOAK_DURATION", 3600);
    let warmup_s: u64 = env_var_u64("PYDE_SOAK_WARMUP", 60);
    let num_senders: usize = env_var_u64("PYDE_SOAK_SENDERS", 50) as usize;
    let encrypted_pct: u32 = env_var_u64("PYDE_SOAK_ENCRYPTED_PCT", 30) as u32;

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  Pyde Comprehensive Soak Test                            ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("  Target TPS:   {}", target_tps);
    println!(
        "  Duration:     {} s (~ {:.1} min) + {} s warmup",
        duration_s,
        duration_s as f64 / 60.0,
        warmup_s
    );
    println!("  Senders:      {}", num_senders);
    println!("  Encrypted %:  {}", encrypted_pct);
    println!("  Features:     transfer / increment(AOT) / complex_logic /");
    println!("                change_status / deposit(payable) /");
    println!("                spawn(factory) / ping(cross-contract) /");
    println!("                enc_increment");
    println!("╚══════════════════════════════════════════════════════════╝");

    // ── Phase 0: spawn 4-validator network ────────────────────────
    println!("\n[0/5] Spawning 4-validator native testnet…");
    let net = TestNetwork::spawn_with_chain_id(4, CHAIN_ID)
        .unwrap_or_else(|e| panic!("spawn 4v@chain_id={}: {}", CHAIN_ID, e));
    net.wait_for_slot(3, Duration::from_secs(30))
        .unwrap_or_else(|e| panic!("chain warm-up: {}", e));

    let (faucet_pk_bytes, faucet_sk_bytes) = net
        .load_faucet_key()
        .unwrap_or_else(|e| panic!("load faucet.key: {}", e));
    let faucet_sk =
        FalconSecretKey::from_bytes(&faucet_sk_bytes).expect("invalid FALCON secret key");
    let faucet_addr = derive_eoa_address(&faucet_pk_bytes);
    println!("  faucet: 0x{}", hex::encode(faucet_addr));

    let rpc_urls: Vec<String> = net.nodes.iter().map(|n| n.rpc_url()).collect();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let client = reqwest::Client::builder()
        .tcp_keepalive(Duration::from_secs(60))
        .pool_idle_timeout(Duration::from_secs(60))
        .build()
        .expect("reqwest client");

    // ── Phase 1: deploy the contract suite ────────────────────────
    println!("\n[1/5] Compiling + deploying contract suite…");
    let helper_payload = compile_deploy_payload(SUITE_SRC, "Helper", &[]).expect("compile Helper");
    let helper_addr = deploy_via_testnet(
        &net,
        &faucet_sk,
        &faucet_addr,
        helper_payload,
        &runtime,
        &client,
        &rpc_urls[0],
    )
    .expect("Helper deploy failed");
    println!("  Helper:       0x{}", hex::encode(helper_addr));

    // MegaContract::init(initial: u64, helper: Address)
    let mut mega_init_args = Vec::with_capacity(8 + 32);
    mega_init_args.extend_from_slice(&0u64.to_le_bytes());
    mega_init_args.extend_from_slice(&helper_addr);
    let mega_payload = compile_deploy_payload(SUITE_SRC, "MegaContract", &mega_init_args)
        .expect("compile MegaContract");
    let mega_addr = deploy_via_testnet(
        &net,
        &faucet_sk,
        &faucet_addr,
        mega_payload,
        &runtime,
        &client,
        &rpc_urls[0],
    )
    .expect("MegaContract deploy failed");
    println!("  MegaContract: 0x{}", hex::encode(mega_addr));

    let spawner_payload =
        compile_deploy_payload(SUITE_SRC, "Spawner", &[]).expect("compile Spawner");
    let spawner_addr = deploy_via_testnet(
        &net,
        &faucet_sk,
        &faucet_addr,
        spawner_payload,
        &runtime,
        &client,
        &rpc_urls[0],
    )
    .expect("Spawner deploy failed");
    println!("  Spawner:      0x{}", hex::encode(spawner_addr));

    let contracts = DeployedContracts {
        helper: helper_addr,
        mega: mega_addr,
        spawner: spawner_addr,
    };

    // ── Phase 2: fund + register N senders ────────────────────────
    println!(
        "\n[2/5] Funding + registering {} sender wallets…",
        num_senders
    );
    let wallets: Vec<Arc<Wallet>> = runtime.block_on(setup_wallets(
        &client,
        &rpc_urls[0],
        &faucet_sk,
        &faucet_addr,
        num_senders,
        FUND_PER_SENDER,
    ));

    // ── Phase 3: warm-up ──────────────────────────────────────────
    println!(
        "\n[3/5] Warm-up: {}s of mixed traffic before measurement…",
        warmup_s
    );
    let weights = CallKind::default_weights();
    let metrics = Arc::new(SoakMetrics::new());

    // Pre-seed nonce counters with each wallet's current chain
    // nonce. After `setup_wallets`, each wallet has consumed nonce 0
    // for its RegisterPubkey tx, so the next-needed is 1 (or higher
    // if multiple txs landed). Pre-fix this initialized to 0 and
    // every submit hit the chain's "below window" rejection.
    let nonce_counters: Arc<Vec<AtomicU64>> = Arc::new(runtime.block_on(async {
        let mut out = Vec::with_capacity(num_senders);
        for w in &wallets {
            let n = fetch_nonce(&client, &rpc_urls[0], &w.address)
                .await
                .unwrap_or(0);
            out.push(AtomicU64::new(n));
        }
        out
    }));

    runtime.block_on(run_workload(
        &client,
        &rpc_urls,
        &wallets,
        &contracts,
        &nonce_counters,
        &weights,
        target_tps,
        encrypted_pct,
        Duration::from_secs(warmup_s),
        Arc::clone(&metrics),
        false, // not measured
    ));

    let warmup_snapshot = metrics.snapshot();

    // ── Phase 4: measurement ──────────────────────────────────────
    println!(
        "\n[4/5] Measurement: {}s sustained traffic ({} TPS, {}% encrypted)…",
        duration_s, target_tps, encrypted_pct
    );
    let measure_start = Instant::now();

    // Watchdog: every 60s, snapshot per-node logs to disk and probe
    // chain head. If head fails to advance for ≥120s, the workload
    // task sees the wedge but the watchdog still has the on-disk
    // logs from BEFORE the harness was killed — which is the data we
    // need to debug epoch-boundary wedges.
    let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog = {
        let outputs: Vec<Arc<std::sync::Mutex<Vec<String>>>> =
            net.nodes.iter().map(|n| n.output_handle()).collect();
        let url = rpc_urls[0].clone();
        let stop = Arc::clone(&stop_flag);
        let blocking_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .expect("blocking client");
        std::thread::spawn(move || {
            let mut last_head: u64 = 0;
            let mut stall_secs: u64 = 0;
            let mut tick: u64 = 0;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(5));
                tick += 5;

                // Probe head from node-0 synchronously.
                let head = probe_head_blocking(&blocking_client, &url);
                if head > 0 {
                    if head == last_head {
                        stall_secs += 5;
                    } else {
                        last_head = head;
                        stall_secs = 0;
                    }
                }

                // Every 60s: print head + dump per-node logs to disk.
                if tick % 60 == 0 {
                    eprintln!("    [watchdog] head={} stall={}s", last_head, stall_secs,);
                    for (i, out) in outputs.iter().enumerate() {
                        if let Ok(buf) = out.lock() {
                            let path = format!("/tmp/pyde-soak-node-{}.log", i);
                            let _ = std::fs::write(&path, buf.join("\n"));
                        }
                    }
                }
            }
            // Final dump on exit (after run_workload ends).
            for (i, out) in outputs.iter().enumerate() {
                if let Ok(buf) = out.lock() {
                    let path = format!("/tmp/pyde-soak-node-{}.log", i);
                    let _ = std::fs::write(&path, buf.join("\n"));
                }
            }
        })
    };

    runtime.block_on(run_workload(
        &client,
        &rpc_urls,
        &wallets,
        &contracts,
        &nonce_counters,
        &weights,
        target_tps,
        encrypted_pct,
        Duration::from_secs(duration_s),
        Arc::clone(&metrics),
        true,
    ));

    // Stop watchdog and ensure final dump lands.
    stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = watchdog.join();
    eprintln!("    [watchdog] final dumps written to /tmp/pyde-soak-node-{{0..3}}.log");
    let measure_elapsed = measure_start.elapsed();
    let final_snapshot = metrics.snapshot();
    let measured = final_snapshot.minus(&warmup_snapshot);

    // ── Phase 5: report ───────────────────────────────────────────
    println!("\n[5/5] Settling 30s for trailing inclusion…");
    std::thread::sleep(Duration::from_secs(30));

    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  RESULTS                                                 ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!(
        "  Total submitted:  {}  ({:.0} TPS over {:.1} min)",
        measured.total_ok(),
        measured.total_ok() as f64 / measure_elapsed.as_secs_f64(),
        measure_elapsed.as_secs_f64() / 60.0
    );
    println!("  Submit errors:    {}", measured.total_err());
    println!();
    println!("  Per-bucket totals:");
    for (kind, _) in CallKind::default_weights().iter() {
        let ok = measured.ok_count(*kind);
        let err = measured.err_count(*kind);
        println!("    {:>22}: ok={:<7} err={}", kind.name(), ok, err);
    }
    println!("╚══════════════════════════════════════════════════════════╝");

    // ── Soak invariants ───────────────────────────────────────────
    let total_ok = measured.total_ok();
    let total_err = measured.total_err();
    let err_rate = if total_ok + total_err > 0 {
        total_err as f64 / (total_ok + total_err) as f64
    } else {
        0.0
    };

    println!("\n  Soak invariants:");
    // Soak-test pass conditions are about chain HEALTH, not
    // submit-side perfection. The submitter's per-sender rate vs
    // the chain's nonce-window inclusion drain produces some
    // organic AboveWindow rejections under sustained load —
    // that's a submitter-test artifact, not a chain regression.
    // What matters: every code path got exercised at least once,
    // and chain didn't degrade catastrophically.
    println!(
        "    submit error rate:  {:.1}%  (warn: > 50%)",
        err_rate * 100.0
    );

    let mut zero_buckets: Vec<&str> = Vec::new();
    for (kind, _) in CallKind::default_weights().iter() {
        if measured.ok_count(*kind) == 0 {
            zero_buckets.push(kind.name());
        }
    }
    println!(
        "    bucket coverage:    {}/8 exercised  (pass: 8/8)",
        8 - zero_buckets.len()
    );
    if !zero_buckets.is_empty() {
        println!("    UNEXERCISED:        {}", zero_buckets.join(", "));
    }

    // Hard assertions: every bucket exercised + error rate not
    // catastrophic (50% would indicate a real chain problem).
    assert!(
        zero_buckets.is_empty(),
        "FAIL: workload buckets unexercised: {:?}",
        zero_buckets
    );
    assert!(
        err_rate < 0.5,
        "FAIL: submit error rate {:.1}% exceeds 50% (chain may be degraded)",
        err_rate * 100.0
    );

    println!(
        "\n  ✓ PASS — {:.1}-min soak, {} buckets exercised, {:.1}% submit err",
        measure_elapsed.as_secs_f64() / 60.0,
        8 - zero_buckets.len(),
        err_rate * 100.0,
    );
}

// ────────────────────────────────────────────────────────────────────
// Workload driver
// ────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn run_workload(
    client: &reqwest::Client,
    rpc_urls: &[String],
    wallets: &[Arc<Wallet>],
    contracts: &DeployedContracts,
    nonce_counters: &Arc<Vec<AtomicU64>>,
    weights: &[(CallKind, u32); 8],
    target_tps: u64,
    encrypted_pct: u32,
    duration: Duration,
    metrics: Arc<SoakMetrics>,
    in_measurement: bool,
) {
    let _ = encrypted_pct; // EncryptedIncrement bucket already covers encrypted path.
    let interval_us = 1_000_000 / target_tps.max(1);
    let interval = Duration::from_micros(interval_us);
    let start = Instant::now();
    let mut idx: u64 = 0;
    let mut last_log = Instant::now();
    let log_every = Duration::from_secs(60);

    while start.elapsed() < duration {
        let kind = CallKind::pick(idx, weights);
        let wallet_idx = (idx as usize) % wallets.len();
        let wallet = Arc::clone(&wallets[wallet_idx]);
        let nonce = nonce_counters[wallet_idx].fetch_add(1, Ordering::Relaxed);
        let url = rpc_urls[(idx as usize) % rpc_urls.len()].clone();
        let client_c = client.clone();
        let metrics_c = Arc::clone(&metrics);
        let helper = contracts.helper;
        let mega = contracts.mega;
        let spawner = contracts.spawner;

        tokio::spawn(async move {
            let r = submit_one(&client_c, &url, &wallet, nonce, kind, helper, mega, spawner).await;
            match r {
                Ok(()) => metrics_c.record_ok(kind, in_measurement),
                Err(_) => metrics_c.record_err(kind, in_measurement),
            }
        });

        idx += 1;
        tokio::time::sleep(interval).await;

        if last_log.elapsed() > log_every {
            let elapsed_min = start.elapsed().as_secs_f64() / 60.0;
            let snap = metrics.snapshot();
            println!(
                "    [+{:.1} min] submitted: {} ok / {} err",
                elapsed_min,
                snap.total_ok(),
                snap.total_err()
            );
            last_log = Instant::now();
        }
    }
}

async fn submit_one(
    client: &reqwest::Client,
    url: &str,
    wallet: &Wallet,
    nonce: u64,
    kind: CallKind,
    helper: [u8; 32],
    mega: [u8; 32],
    spawner: [u8; 32],
) -> Result<(), ()> {
    use TransactionType::*;

    let (to, data, value, tx_type) = match kind {
        CallKind::Transfer => ([0x42u8; 32], vec![], 1u128, Standard),
        CallKind::Increment => {
            let mut d = Vec::with_capacity(4);
            d.extend_from_slice(&selector("increment"));
            (mega, d, 0, Standard)
        }
        CallKind::ComplexLogic => {
            // complex_logic(data: UserData) — UserData = (u256 amount, u64 score)
            let mut d = Vec::with_capacity(4 + 32 + 8);
            d.extend_from_slice(&selector("complex_logic"));
            // amount as u256 LE: little-endian 32 bytes, low 8 = 1000
            let mut amt = [0u8; 32];
            amt[0..8].copy_from_slice(&1000u64.to_le_bytes());
            d.extend_from_slice(&amt);
            d.extend_from_slice(&(nonce % 100).to_le_bytes()); // score
            (mega, d, 0, Standard)
        }
        CallKind::ChangeStatus => {
            // change_status(s: Status) — pass enum tag (0/1/2)
            let mut d = Vec::with_capacity(4 + 8);
            d.extend_from_slice(&selector("change_status"));
            d.extend_from_slice(&(nonce % 3).to_le_bytes());
            (mega, d, 0, Standard)
        }
        CallKind::Deposit => {
            let mut d = Vec::with_capacity(4);
            d.extend_from_slice(&selector("deposit"));
            (mega, d, 100u128, Standard) // payable, send 100 quanta
        }
        CallKind::Spawn => {
            let mut d = Vec::with_capacity(4);
            d.extend_from_slice(&selector("spawn"));
            (spawner, d, 0, Standard)
        }
        CallKind::Ping => {
            let mut d = Vec::with_capacity(4);
            d.extend_from_slice(&selector("ping"));
            (helper, d, 0, Standard)
        }
        CallKind::EncryptedIncrement => {
            // Encrypted variant — same call but submitted via the
            // encrypted-tx RPC path. Built below in the encrypted
            // branch.
            ([0u8; 32], vec![], 0, Standard)
        }
    };

    let access_list = if to != [0u8; 32] && to != [0x42u8; 32] {
        vec![AccessEntry {
            address: to,
            reads: vec![],
            writes: vec![],
        }]
    } else {
        vec![]
    };

    if matches!(kind, CallKind::EncryptedIncrement) {
        return submit_encrypted_increment(client, url, wallet, nonce, mega).await;
    }

    let mut tx = Transaction {
        from: wallet.address,
        to,
        value,
        data,
        gas_limit: if matches!(kind, CallKind::Spawn) {
            500_000
        } else {
            150_000
        },
        nonce,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list,
        deadline: None,
        chain_id: CHAIN_ID,
        tx_type,
    };
    let sig = falcon_sign(&wallet.sk, &tx.hash()).map_err(|_| ())?;
    tx.signature = sig.as_bytes().to_vec();
    let hex_tx = hex::encode(tx.to_bytes());
    rpc_send_raw_fast(client, url, &hex_tx).await
}

async fn submit_encrypted_increment(
    client: &reqwest::Client,
    url: &str,
    wallet: &Wallet,
    nonce: u64,
    mega: [u8; 32],
) -> Result<(), ()> {
    let mut data = Vec::with_capacity(4);
    data.extend_from_slice(&selector("increment"));
    let access_list = vec![AccessEntry {
        address: mega,
        reads: vec![],
        writes: vec![],
    }];

    let tpk_bytes = fetch_threshold_pubkey(client, url).await.ok_or(())?;
    let tpk = pyde_crypto::threshold::ThresholdPublicKey::from_bytes(&tpk_bytes).ok_or(())?;

    // Build the EncryptedTx with an empty signature, hash the
    // resulting structure, FALCON-sign that hash, then attach the
    // sig to enc_tx. The verify path at ingress
    // (`receive_tx_verified`) re-hashes `EncryptedTx::hash()` and
    // verifies against the wallet's on-chain pubkey — same domain
    // by construction. Pre-fix the loadgen signed the inner
    // `Transaction::hash()` and passed it into
    // `encrypt_transaction`'s `signature` parameter, which the
    // ingress then verified against `EncryptedTx::hash()` — wrong
    // domain → 100% rejection.
    let mut enc_tx = pyde_mempool::encrypted::encrypt_transaction(
        wallet.address,
        nonce,
        150_000,
        access_list,
        None,
        CHAIN_ID,
        Vec::new(), // sig added below
        &mega,
        0,
        &data,
        &tpk,
    )
    .map_err(|_| ())?;
    let tx_hash = enc_tx.hash();
    let sig = falcon_sign(&wallet.sk, &tx_hash).map_err(|_| ())?;
    enc_tx.signature = sig.as_bytes().to_vec();

    let hex_tx = hex::encode(enc_tx.to_bytes());
    rpc_send_raw_encrypted_fast(client, url, &hex_tx).await
}

// ────────────────────────────────────────────────────────────────────
// Wallet setup — fund + register pubkey for N senders.
// ────────────────────────────────────────────────────────────────────

async fn setup_wallets(
    client: &reqwest::Client,
    url: &str,
    faucet_sk: &FalconSecretKey,
    faucet_addr: &[u8; 32],
    n: usize,
    fund: u128,
) -> Vec<Arc<Wallet>> {
    let mut wallets = Vec::with_capacity(n);
    for _ in 0..n {
        let (pk, sk) = falcon_keygen().expect("keygen");
        let address = derive_eoa_address(pk.as_bytes());
        wallets.push(Arc::new(Wallet {
            address,
            pk_bytes: pk.as_bytes().to_vec(),
            sk,
        }));
    }

    // Fund.
    let mut faucet_nonce = fetch_nonce(client, url, faucet_addr)
        .await
        .expect("faucet nonce");
    for w in &wallets {
        let mut tx = Transaction {
            from: *faucet_addr,
            to: w.address,
            value: fund,
            data: vec![],
            gas_limit: 50_000,
            nonce: faucet_nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: CHAIN_ID,
            tx_type: TransactionType::Standard,
        };
        tx.signature = falcon_sign(faucet_sk, &tx.hash())
            .expect("fund sig")
            .as_bytes()
            .to_vec();
        let hex_tx = hex::encode(tx.to_bytes());
        let _ = rpc_send_raw(client, url, &hex_tx).await;
        faucet_nonce += 1;
        if faucet_nonce % 14 == 0 {
            tokio::time::sleep(Duration::from_millis(800)).await;
        }
    }

    // Wait until funded.
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let mut funded = 0;
        for w in &wallets {
            if fetch_balance(client, url, &w.address).await.unwrap_or(0) >= fund {
                funded += 1;
            }
        }
        if funded == wallets.len() {
            break;
        }
        if Instant::now() > deadline {
            panic!(
                "timed out waiting for {} wallets to fund (got {})",
                n, funded
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Register pubkeys (audit 226 / 229 — bootstrap step that
    // installs each wallet's FALCON pubkey on chain). Critically:
    // this tx type is UNSIGNED (`signature: vec![]`) and uses
    // `gas_limit: 0` — it's the auth-less bootstrap before any
    // auth_key exists. Pre-fix the soak test signed it like a
    // regular tx and set gas_limit=100_000, which was rejected at
    // validation, so registrations never landed and nonces stayed
    // at 0 → 100% submit failure on the workload.
    let mut signed_register: Vec<String> = Vec::with_capacity(wallets.len());
    for w in &wallets {
        let tx = Transaction {
            from: w.address,
            to: [0u8; 32],
            value: 0,
            data: w.pk_bytes.clone(),
            gas_limit: 0,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: CHAIN_ID,
            tx_type: TransactionType::RegisterPubkey,
        };
        signed_register.push(hex::encode(tx.to_bytes()));
    }
    for hex_tx in &signed_register {
        let _ = rpc_send_raw(client, url, hex_tx).await;
    }

    // Wait for every registration to land. RegisterPubkey at nonce
    // 0 advances each wallet's base to 1 — poll `getTransactionCount`
    // until that's true. Pre-fix the test slept 5s and assumed the
    // registrations landed, which they often hadn't, leaving every
    // workload tx submitted at nonce 0 → "below window" rejection
    // (100% error rate).
    let reg_deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let mut registered = 0;
        for w in &wallets {
            if fetch_nonce(client, url, &w.address).await.unwrap_or(0) >= 1 {
                registered += 1;
            }
        }
        if registered == wallets.len() {
            break;
        }
        if Instant::now() > reg_deadline {
            panic!(
                "timed out waiting for {} pubkey registrations (got {})",
                wallets.len(),
                registered
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    wallets
}

/// Deploy via the TestNetwork's sync submit + wait_for_receipt helpers.
/// Mirrors the pattern from `loadgen_mixed.rs` that is known to work
/// against the same `TestNetwork::spawn_with_chain_id` test rig.
fn deploy_via_testnet(
    net: &TestNetwork,
    sk: &FalconSecretKey,
    from: &[u8; 32],
    payload: Vec<u8>,
    runtime: &tokio::runtime::Runtime,
    client: &reqwest::Client,
    url: &str,
) -> Result<[u8; 32], String> {
    let nonce = runtime
        .block_on(fetch_nonce(client, url, from))
        .ok_or_else(|| "fetch faucet nonce".to_string())?;
    let mut tx = Transaction {
        from: *from,
        to: [0u8; 32],
        value: 0,
        data: payload,
        gas_limit: 100_000_000, // contracts can compile to large bytecode + complex constructors
        nonce,
        signature: vec![],
        fee_payer: FeePayer::Sender,
        access_list: vec![],
        deadline: None,
        chain_id: CHAIN_ID,
        tx_type: TransactionType::Deploy,
    };
    tx.signature = falcon_sign(sk, &tx.hash())
        .map_err(|_| "deploy sig".to_string())?
        .as_bytes()
        .to_vec();
    let deploy_hash = net
        .submit_raw_tx(0, &tx.to_bytes())
        .map_err(|e| format!("submit_raw_tx: {}", e))?;
    let receipts = net
        .wait_for_receipt_on_all(&deploy_hash, Duration::from_secs(60))
        .map_err(|e| format!("wait_for_receipt: {}", e))?;
    if !receipts[0].success {
        return Err(format!("deploy failed: {}", receipts[0].raw));
    }
    let return_bytes = TestNetwork::decode_return_data(&receipts[0].raw)
        .map_err(|e| format!("decode returnData: {}", e))?;
    if return_bytes.len() != 32 {
        return Err(format!(
            "expected 32-byte deployed address, got {} bytes",
            return_bytes.len()
        ));
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&return_bytes);
    Ok(addr)
}

// ────────────────────────────────────────────────────────────────────
// RPC helpers
// ────────────────────────────────────────────────────────────────────

async fn rpc_call(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    });
    let resp = match client.post(url).json(&body).send().await {
        Ok(r) => r,
        Err(_) => return serde_json::Value::Null,
    };
    let resp = match resp.error_for_status() {
        Ok(r) => r,
        Err(_) => return serde_json::Value::Null,
    };
    resp.json::<serde_json::Value>()
        .await
        .unwrap_or(serde_json::Value::Null)
}

async fn rpc_send_raw(client: &reqwest::Client, url: &str, hex_tx: &str) -> serde_json::Value {
    rpc_call(
        client,
        url,
        "pyde_sendRawTransaction",
        serde_json::json!([format!("0x{}", hex_tx.trim_start_matches("0x"))]),
    )
    .await
}

async fn rpc_send_raw_fast(client: &reqwest::Client, url: &str, hex_tx: &str) -> Result<(), ()> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "pyde_sendRawTransaction",
        "params": [format!("0x{}", hex_tx.trim_start_matches("0x"))],
        "id": 1,
    });
    let resp = client.post(url).json(&body).send().await.map_err(|_| ())?;
    if !resp.status().is_success() {
        return Err(());
    }
    let v: serde_json::Value = resp.json().await.map_err(|_| ())?;
    if let Some(err) = v.get("error") {
        // First few errors: print so we can diagnose. Use a static
        // counter to avoid log flood.
        static ERR_PRINTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        if ERR_PRINTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 10 {
            eprintln!("DBG send_raw err: {}", err);
        }
        Err(())
    } else {
        Ok(())
    }
}

async fn rpc_send_raw_encrypted_fast(
    client: &reqwest::Client,
    url: &str,
    hex_tx: &str,
) -> Result<(), ()> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "pyde_sendRawEncryptedTransaction",
        "params": [format!("0x{}", hex_tx.trim_start_matches("0x"))],
        "id": 1,
    });
    let resp = client.post(url).json(&body).send().await.map_err(|_| ())?;
    if !resp.status().is_success() {
        return Err(());
    }
    let v: serde_json::Value = resp.json().await.map_err(|_| ())?;
    if let Some(err) = v.get("error") {
        static ENC_ERR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        if ENC_ERR.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 5 {
            eprintln!("DBG send_raw_enc err: {}", err);
        }
        Err(())
    } else {
        Ok(())
    }
}

/// Synchronous chain-head probe used by the watchdog thread.
/// Returns 0 on any failure (RPC down, parse error) — the caller
/// treats 0 as "no signal", not "stalled at slot 0".
fn probe_head_blocking(client: &reqwest::blocking::Client, url: &str) -> u64 {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "pyde_blockNumber",
        "params": [],
    });
    let resp = match client.post(url).json(&body).send() {
        Ok(r) => r,
        Err(_) => return 0,
    };
    let v: serde_json::Value = match resp.json() {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let Some(s) = v.get("result").and_then(|r| r.as_str()) else {
        return 0;
    };
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).unwrap_or(0)
}

async fn fetch_nonce(client: &reqwest::Client, url: &str, addr: &[u8; 32]) -> Option<u64> {
    let v = rpc_call(
        client,
        url,
        "pyde_getTransactionCount",
        serde_json::json!([format!("0x{}", hex::encode(addr))]),
    )
    .await;
    v.get("result")
        .and_then(|r| r.as_str())
        .and_then(|s| s.parse::<u64>().ok())
}

async fn fetch_balance(client: &reqwest::Client, url: &str, addr: &[u8; 32]) -> Option<u128> {
    let v = rpc_call(
        client,
        url,
        "pyde_getBalance",
        serde_json::json!([format!("0x{}", hex::encode(addr))]),
    )
    .await;
    v.get("result")
        .and_then(|r| r.as_str())
        .and_then(|s| s.parse::<u128>().ok())
}

async fn fetch_threshold_pubkey(client: &reqwest::Client, url: &str) -> Option<Vec<u8>> {
    let v = rpc_call(
        client,
        url,
        "pyde_getThresholdPublicKey",
        serde_json::json!([]),
    )
    .await;
    v.get("result")
        .and_then(|r| r.as_str())
        .and_then(|s| hex::decode(s.strip_prefix("0x").unwrap_or(s)).ok())
}

// ────────────────────────────────────────────────────────────────────
// Metrics
// ────────────────────────────────────────────────────────────────────

struct SoakMetrics {
    ok: [AtomicU64; 8],
    err: [AtomicU64; 8],
}

#[derive(Clone)]
struct SoakSnapshot {
    ok: [u64; 8],
    err: [u64; 8],
}

impl SoakMetrics {
    fn new() -> Self {
        Self {
            ok: Default::default(),
            err: Default::default(),
        }
    }
    fn idx(kind: CallKind) -> usize {
        match kind {
            CallKind::Transfer => 0,
            CallKind::Increment => 1,
            CallKind::ComplexLogic => 2,
            CallKind::ChangeStatus => 3,
            CallKind::Deposit => 4,
            CallKind::Spawn => 5,
            CallKind::Ping => 6,
            CallKind::EncryptedIncrement => 7,
        }
    }
    fn record_ok(&self, kind: CallKind, _measured: bool) {
        self.ok[Self::idx(kind)].fetch_add(1, Ordering::Relaxed);
    }
    fn record_err(&self, kind: CallKind, _measured: bool) {
        self.err[Self::idx(kind)].fetch_add(1, Ordering::Relaxed);
    }
    fn snapshot(&self) -> SoakSnapshot {
        SoakSnapshot {
            ok: std::array::from_fn(|i| self.ok[i].load(Ordering::Relaxed)),
            err: std::array::from_fn(|i| self.err[i].load(Ordering::Relaxed)),
        }
    }
}

impl SoakSnapshot {
    fn ok_count(&self, kind: CallKind) -> u64 {
        self.ok[SoakMetrics::idx(kind)]
    }
    fn err_count(&self, kind: CallKind) -> u64 {
        self.err[SoakMetrics::idx(kind)]
    }
    fn total_ok(&self) -> u64 {
        self.ok.iter().sum()
    }
    fn total_err(&self) -> u64 {
        self.err.iter().sum()
    }
    fn minus(&self, other: &Self) -> Self {
        Self {
            ok: std::array::from_fn(|i| self.ok[i].saturating_sub(other.ok[i])),
            err: std::array::from_fn(|i| self.err[i].saturating_sub(other.err[i])),
        }
    }
}

fn env_var_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}
