// Frozen pre-pivot archive: the lints below were promoted to default-warn
// in clippy 1.95, after this code was frozen. The archive is historical and
// not developed further, so it is not conformed to new clippy-version style
// opinions. Allowed at the crate level because the CI's `-- -D warnings`
// overrides Cargo.toml lint tables but not source attributes.
#![allow(
    clippy::cloned_ref_to_slice_refs,
    clippy::explicit_counter_loop,
    clippy::if_same_then_else,
    clippy::manual_checked_ops,
    clippy::manual_flatten,
    clippy::unnecessary_get_then_check,
    clippy::assertions_on_constants,
    clippy::unnecessary_sort_by,
    dead_code
)]

/// Chain-wide compile-time gate for the encrypted-mempool (MEV-
/// protection) pipeline.
///
/// When `false`, the encrypted-tx path is fully disabled end-to-end:
/// - The RPC endpoints `pyde_sendRawEncryptedTransaction` and
///   `pyde_getThresholdPublicKey` return errors.
/// - The node does not subscribe to or publish on the
///   `pyde/encrypted_transactions/1` gossip topic.
/// - Block proposers select no encrypted txs and do not emit an
///   `EncryptedTxBundle`.
/// - Genesis does not write `threshold.pk` or per-validator key
///   shares.
///
/// This is a **compile-time** const rather than a runtime config
/// flag because the encrypted path is a consensus-level concern:
/// every node in the network must agree on whether encrypted txs
/// are part of the protocol. A binary built with this flag flipped
/// is incompatible at the consensus layer with one where it is not
/// flipped. Treat it as a hard-fork-level switch — don't mix
/// builds on the same network.
///
/// **On for testnet.** Public testnet ships with the threshold-
/// encryption pipeline live end-to-end: the RPC endpoints accept
/// encrypted-tx payloads, validators subscribe to the encrypted-
/// tx gossip topic, proposers include encrypted-tx bundles in
/// blocks, and the per-block decryption coordinator runs against
/// real gossip. Earlier `false` was a soak-test convenience while
/// we stabilised the chain without the threshold-encryption
/// layer; that exercise is complete.
///
/// **Trust framing for marketing copy:** the threshold-encryption
/// design in this codebase is rotating-dealer per-epoch key
/// escrow, NOT trustless threshold ML-KEM (which is a 2025-2026
/// research frontier). The testnet trust model is therefore
/// rotating-dealer; mainnet either lands the post-fundraise
/// lattice-DKG work (task #101) or ships with explicit documented
/// acceptance of the rotating-dealer model.
pub const MEV_PROTECTION_ENABLED: bool = true;

mod aot_cache;
mod block_builder;
mod block_processor;
mod block_store;
mod canonical_commit;
mod chain;
mod cli;
mod config;
mod consensus_store;
mod fast_tx;
mod faucet;
mod genesis;
mod gossip_cache;
mod keystore;
mod logging;
mod metrics;
mod node;
mod peer_book;
mod receipt_store;
mod rpc;
mod rpc_rate_limit;
mod shutdown;
mod slot_clock;
mod state_manager;
mod sync;
mod tui;
mod tx_relay;
mod validator;
pub mod wire;
mod ws_sub;

use clap::Parser;
use cli::{Cli, Command};
use config::NodeConfig;
use node::PydeNode;
use shutdown::ShutdownSignal;

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::DefaultConfig => {
            print!("{}", NodeConfig::default().to_toml());
        }
        Command::DefaultGenesis => {
            let (config, _) = genesis::devnet_genesis();
            print!("{}", config.to_toml());
        }
        Command::Testnet {
            validators,
            full_nodes,
            out,
            base_port,
            base_rpc_port,
            dev,
            chain_id,
            block_time_ms,
            node_addrs,
        } => {
            // Distributed mode: load the per-node (region, host, port)
            // table from the supplied TOML file. Localhost mode (no
            // flag) keeps the historical 127.0.0.1 + base_port + i
            // behaviour for `pyde testnet` development.
            let addrs = match node_addrs.as_ref() {
                Some(path) => match genesis::NodeAddrFile::load(path) {
                    Ok(file) => Some(file.into_addrs()),
                    Err(e) => {
                        eprintln!("error reading --node-addrs: {}", e);
                        std::process::exit(1);
                    }
                },
                None => None,
            };
            if let Err(e) = genesis::generate_testnet(
                &out,
                validators,
                full_nodes,
                base_port,
                base_rpc_port,
                dev,
                chain_id,
                block_time_ms,
                addrs.as_deref(),
            ) {
                eprintln!("error: {}", e);
                std::process::exit(1);
            }
        }
        Command::Faucet {
            rpc,
            port,
            amount,
            from,
            cooldown,
            private_key,
            chain_id,
            trust_x_forwarded_for,
        } => {
            logging::init("info", false);
            let rt = tokio::runtime::Runtime::new().expect("failed to create runtime");
            rt.block_on(async {
                let config = faucet::FaucetConfig {
                    rpc_url: rpc,
                    port,
                    amount_pyde: amount,
                    from_address: from,
                    cooldown_secs: cooldown,
                    private_key_path: private_key,
                    chain_id,
                    trust_x_forwarded_for,
                };
                if let Err(e) = faucet::run_faucet(config).await {
                    tracing::error!("faucet error: {}", e);
                    std::process::exit(1);
                }
            });
        }
        Command::Run {
            role,
            config: config_path,
            port,
            datadir,
            log_level,
            log_json,
            metrics_port,
            rpc_port,
            dev,
            bootstrap,
            tui,
        } => {
            // Load config from file (if provided) or use defaults
            let mut config = match &config_path {
                Some(path) => match NodeConfig::load(path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("error: {}", e);
                        std::process::exit(1);
                    }
                },
                None => NodeConfig::default(),
            };

            // Apply CLI overrides
            config.apply_cli_overrides(
                Some(&role.to_string()),
                port,
                datadir.as_deref(),
                Some(&log_level),
                log_json,
                metrics_port,
                &bootstrap,
            );
            if let Some(rp) = rpc_port {
                config.rpc.port = rp;
            }
            if dev {
                config.node.dev_mode = true;
            }

            // TPL-207: refuse to start with `dev_mode = true` on any
            // chain_id other than devnet. `dev_mode` short-circuits
            // signature verification (`validate_transaction` honours
            // `dev_skip_signature` only when `chain_id == 31337`, but
            // `pyde_sendTransaction` accepts unsigned txs whenever
            // `state.dev_mode` is set). A misconfigured operator
            // running `pyde run --dev --config testnet.toml` opens
            // unsigned-tx ingress for the duration; this guard
            // catches the combo at startup. Both `--dev` and a TOML
            // `dev_mode = true` are funnelled here, so the check
            // covers either source.
            if config.node.dev_mode && config.node.chain_id != pyde_net::discovery::DEVNET_CHAIN_ID
            {
                eprintln!(
                    "error: dev_mode is only permitted on devnet \
                     (chain_id = {}); configured chain_id = {}. Drop \
                     `--dev` / `[node].dev_mode = false` to run on \
                     testnet or mainnet.",
                    pyde_net::discovery::DEVNET_CHAIN_ID,
                    config.node.chain_id,
                );
                std::process::exit(1);
            }

            // Initialize logging first. With --tui we redirect to a
            // log file under datadir so stdout is free for the
            // dashboard; without --tui keep the existing stdout
            // behavior so headless / systemd / CI runs don't change.
            if tui {
                let log_path = config.node.datadir.join("pyde.log");
                if let Err(e) =
                    logging::init_file(&config.logging.level, config.logging.json, &log_path)
                {
                    eprintln!("error: --tui log file init failed: {}", e);
                    std::process::exit(1);
                }
                eprintln!("pyde-tui: logs → {}", log_path.display());
            } else {
                logging::init(&config.logging.level, config.logging.json);
            }

            // Stamp the local validator role into the metrics snapshot
            // so the TUI header reads correctly from start.
            metrics::set_is_validator(matches!(role, cli::Role::Validator));

            // Build async runtime and run
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(async {
                let shutdown = ShutdownSignal::new();
                let shutdown_clone = shutdown.clone();

                // Spawn signal handler
                tokio::spawn(shutdown::wait_for_signal(shutdown_clone));

                // Optional TUI dashboard. Runs on a blocking thread
                // so its sync render loop doesn't share a tokio
                // worker with the node; flips `tui_quit` on q/Esc
                // and pipes that into the broadcast shutdown so the
                // node tears down with the dashboard.
                let tui_quit = if tui {
                    let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let flag_for_thread = flag.clone();
                    let shutdown_for_tui = shutdown.clone();
                    std::thread::spawn(move || {
                        if let Err(e) = tui::run(flag_for_thread) {
                            eprintln!("tui exited with error: {}", e);
                        }
                        shutdown_for_tui.trigger();
                    });
                    Some(flag)
                } else {
                    None
                };

                // Run the node
                let node = PydeNode::new(config, shutdown);
                let exit_code = match node.run().await {
                    Ok(()) => 0,
                    Err(e) => {
                        tracing::error!("node exited with error: {}", e);
                        1
                    }
                };
                if let Some(q) = tui_quit {
                    q.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                if exit_code != 0 {
                    std::process::exit(exit_code);
                }
            });
        }
    }
}
