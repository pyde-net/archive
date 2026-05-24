//! External-RPC loadgen — submits sustained transfers from a pool
//! of pre-funded accounts to an RPC endpoint defined by env vars.
//!
//! Pairs with cross-region testnets where you want to drive load
//! into a running chain (4-validator AWS cluster, two-laptop, etc.)
//! without spinning up an in-process TestNetwork. The accounts file
//! is the `accounts.json` produced by `pyde testnet`.
//!
//! Env vars (all optional, sensible defaults):
//!   PYDE_RPC               RPC endpoint               default http://127.0.0.1:8545
//!   PYDE_ACCOUNTS          accounts.json path         default ./aws-3region-net/accounts.json
//!   PYDE_TPS               target submit rate         default 50
//!   PYDE_DURATION_S        soak duration seconds      default 600 (10 min)
//!   PYDE_SENDERS           number of senders to use   default 8 (taken from front of accounts)
//!   PYDE_GENERATE_SENDERS  if >0, generate N fresh    default 0 (use PYDE_SENDERS pre-funded)
//!                          wallets and fund each
//!                          from the faucet (if
//!                          PYDE_FAUCET_KEY set) or
//!                          from the last loaded
//!                          account otherwise
//!   PYDE_FAUCET_KEY        path to faucet.key file    default unset
//!                          (raw FALCON private key
//!                          bytes); used as funder for
//!                          self-fund mode when set
//!   PYDE_FUND_WEI          wei per generated sender   default 1e18 (1 PYDE)
//!
//! Run:
//!   cargo run --release -p pyde-rust-sdk --example loadgen_ext
//!
//! Periodic status (every 10s): submitted/confirmed/errored counters.

use pyde_rust_sdk::*;
use pyde_tx::types::{FeePayer, Transaction, TransactionType};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_or_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

#[derive(serde::Deserialize)]
struct AccountsFile {
    accounts: Vec<AccountEntry>,
}

#[derive(serde::Deserialize)]
struct AccountEntry {
    #[serde(rename = "privateKey")]
    private_key: String,
    #[allow(dead_code)]
    address: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let rpc_url = env_or("PYDE_RPC", "http://127.0.0.1:8545");
    let accounts_path = env_or("PYDE_ACCOUNTS", "./aws-3region-net/accounts.json");
    let target_tps = env_or_u64("PYDE_TPS", 50);
    let duration_s = env_or_u64("PYDE_DURATION_S", 600);
    let n_senders = env_or_u64("PYDE_SENDERS", 8) as usize;

    println!("loadgen_ext: rpc={rpc_url} accounts={accounts_path} tps={target_tps} duration={duration_s}s senders={n_senders}");

    // Load accounts and slice the pool.
    let raw = std::fs::read_to_string(&accounts_path)
        .unwrap_or_else(|e| panic!("read {accounts_path}: {e}"));
    let af: AccountsFile = serde_json::from_str(&raw).expect("parse accounts.json");
    let accounts = &af.accounts;
    assert!(
        accounts.len() >= n_senders,
        "accounts file has {} entries, need >= {}",
        accounts.len(),
        n_senders
    );

    // Build wallets + fetch starting state.
    let p = Arc::new(Provider::new(&rpc_url));
    let chain_id = p
        .get_chain_id()
        .await
        .expect("get_chain_id failed — RPC unreachable?");
    println!("connected to chain_id={chain_id}");

    let mut wallets: Vec<Wallet> = Vec::with_capacity(n_senders);
    let mut nonces: Vec<u64> = Vec::with_capacity(n_senders);
    for (i, acct) in accounts.iter().take(n_senders).enumerate() {
        let w = Wallet::from_private_key(&acct.private_key)
            .unwrap_or_else(|e| panic!("wallet[{i}] from_private_key: {e:?}"));
        let nonce = p
            .get_nonce(w.address())
            .await
            .unwrap_or_else(|e| panic!("get_nonce[{i}]: {e:?}"));
        let bal = p.get_balance(w.address()).await.unwrap_or(0);
        println!(
            "  sender[{i}] addr=0x{} starting_nonce={nonce} balance={bal}",
            hex::encode(w.address())
        );
        wallets.push(w);
        nonces.push(nonce);
    }

    // Self-funding mode: generate K fresh wallets and fund each from
    // the highest-balance account in the loaded set (typically the
    // faucet at index N-1). Required for high-TPS soaks because the
    // mempool nonce-window cap (16 per sender) limits sustained
    // throughput to ~`n_senders * 1 TPS` at 1s slots. With K=200 fresh
    // senders we can sustain ~200 TPS; with K=500, ~500 TPS.
    let generate_n = env_or_u64("PYDE_GENERATE_SENDERS", 0) as usize;
    if generate_n > 0 {
        let fund_wei: u128 = std::env::var("PYDE_FUND_WEI")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1_000_000_000_000_000_000u128); // 1 PYDE
                                                       // Pick funder: if PYDE_FAUCET_KEY is set, load that raw FALCON
                                                       // private-key file (the testnet faucet, typically 1000+ PYDE
                                                       // balance). Otherwise fall back to the last loaded account.
        let (funder, mut funder_nonce) = if let Ok(path) = std::env::var("PYDE_FAUCET_KEY") {
            let mut raw =
                std::fs::read(&path).unwrap_or_else(|e| panic!("read faucet key {path}: {e}"));
            // The faucet.key file written by `pyde testnet` is framed
            // as `[u32 LE pubkey_len=897][pubkey 897][secret 1281]` =
            // 2182 bytes. `Wallet::from_private_key` expects the
            // unframed `[pubkey 897][secret 1281]` = 2178 bytes. Strip
            // the 4-byte length prefix when present.
            if raw.len() == 2182 && raw[..4] == [0x81, 0x03, 0x00, 0x00] {
                raw.drain(0..4);
            }
            let hex_str = format!("0x{}", hex::encode(&raw));
            let w = Wallet::from_private_key(&hex_str)
                .unwrap_or_else(|e| panic!("faucet wallet from {path}: {e:?}"));
            let n = p
                .get_nonce(w.address())
                .await
                .unwrap_or_else(|e| panic!("faucet get_nonce: {e:?}"));
            println!(
                "  funder: faucet from {path} addr=0x{} starting_nonce={n}",
                hex::encode(w.address())
            );
            (w, n)
        } else {
            let funder_idx = wallets.len() - 1;
            let w = wallets.remove(funder_idx);
            let n = nonces.remove(funder_idx);
            println!(
                "  funder: account[{funder_idx}] addr=0x{} starting_nonce={n}",
                hex::encode(w.address())
            );
            (w, n)
        };
        let funder_bal = p.get_balance(funder.address()).await.unwrap_or(0);
        println!(
            "self-funding mode: generating {generate_n} senders @ {fund_wei} wei each (funder balance={funder_bal} wei)"
        );

        let new_wallets: Vec<Wallet> = (0..generate_n)
            .map(|_| Wallet::generate().expect("Wallet::generate failed"))
            .collect();

        // Batched drip: submit up to nonce-window-size (16) at a time,
        // sleep a slot or two for inclusion, then continue. Funder's
        // nonce is tracked locally; we don't await receipts to keep
        // the funding phase fast.
        let batch_size = 16usize;
        let mut i = 0usize;
        while i < generate_n {
            let end = (i + batch_size).min(generate_n);
            let mut ok = 0;
            let mut err = 0;
            for j in i..end {
                let mut tx = Transaction {
                    from: *funder.address(),
                    to: *new_wallets[j].address(),
                    value: fund_wei,
                    data: vec![],
                    gas_limit: 21_000,
                    nonce: funder_nonce,
                    signature: vec![],
                    fee_payer: FeePayer::Sender,
                    access_list: vec![],
                    deadline: None,
                    chain_id,
                    tx_type: TransactionType::Standard,
                };
                if funder.sign_transaction(&mut tx).is_err() {
                    err += 1;
                    continue;
                }
                match p.send_transaction(&tx).await {
                    Ok(_) => {
                        ok += 1;
                        funder_nonce += 1;
                    }
                    Err(e) => {
                        err += 1;
                        if err <= 3 {
                            eprintln!("  fund[{j}] failed: {e:?}");
                        }
                    }
                }
            }
            println!(
                "  funded batch {}..{end}: ok={ok} err={err} (sleeping 3s for inclusion)",
                i
            );
            tokio::time::sleep(Duration::from_secs(3)).await;
            i = end;
        }

        // Replace the sender pool with the freshly-funded wallets.
        wallets = new_wallets;
        nonces = vec![0u64; generate_n];
        println!("self-funding complete — using {generate_n} fresh senders");
    }
    let n_senders = wallets.len();

    // Status counters.
    let submitted = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));

    let interval = Duration::from_micros(1_000_000 / target_tps.max(1));
    let start = Instant::now();
    let deadline = start + Duration::from_secs(duration_s);

    // Reporter task: print snapshot every 10s.
    let r_submitted = submitted.clone();
    let r_errors = errors.clone();
    let r_handle = tokio::spawn(async move {
        let mut last = 0u64;
        let mut t = tokio::time::interval(Duration::from_secs(10));
        t.tick().await; // skip immediate
        loop {
            t.tick().await;
            let s = r_submitted.load(Ordering::Relaxed);
            let e = r_errors.load(Ordering::Relaxed);
            let delta = s - last;
            last = s;
            println!(
                "  [t+{:>4}s] submitted={s} ({delta} in last 10s) errors={e}",
                start.elapsed().as_secs()
            );
        }
    });

    // Submit loop.
    let mut next_tick = Instant::now();
    let mut idx = 0usize;
    while Instant::now() < deadline {
        let sender = idx % n_senders;
        let recipient = (idx + 1) % n_senders;
        idx += 1;

        let w = &wallets[sender];
        let to = *wallets[recipient].address();
        let nonce = nonces[sender];
        nonces[sender] += 1;

        let mut tx = Transaction {
            from: *w.address(),
            to,
            value: 1,
            data: vec![],
            gas_limit: 21_000,
            nonce,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id,
            tx_type: TransactionType::Standard,
        };
        if let Err(e) = w.sign_transaction(&mut tx) {
            errors.fetch_add(1, Ordering::Relaxed);
            eprintln!("  sign[{sender}]: {e:?}");
            continue;
        }

        let p2 = p.clone();
        let submitted2 = submitted.clone();
        let errors2 = errors.clone();
        tokio::spawn(async move {
            match p2.send_transaction(&tx).await {
                Ok(_) => {
                    submitted2.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    errors2.fetch_add(1, Ordering::Relaxed);
                    // Avoid log spam — only print 1-in-50 errors.
                    let n = errors2.load(Ordering::Relaxed);
                    if n % 50 == 1 {
                        eprintln!("  submit error #{n}: {e:?}");
                    }
                }
            }
        });

        next_tick += interval;
        let now = Instant::now();
        if next_tick > now {
            tokio::time::sleep(next_tick - now).await;
        } else if now - next_tick > Duration::from_secs(1) {
            // Falling behind — reset cadence to now to avoid burst-catch-up.
            next_tick = now;
        }
    }

    r_handle.abort();
    println!();
    println!("=== loadgen done ===");
    println!("  duration:  {}s", start.elapsed().as_secs());
    println!("  submitted: {}", submitted.load(Ordering::Relaxed));
    println!("  errors:    {}", errors.load(Ordering::Relaxed));
}
