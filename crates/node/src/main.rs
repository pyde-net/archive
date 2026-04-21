mod aot_cache;
mod block_builder;
mod block_processor;
mod block_store;
mod chain;
mod cli;
mod config;
mod consensus_store;
mod fast_tx;
mod faucet;
mod genesis;
mod logging;
mod metrics;
mod node;
mod receipt_store;
mod rpc;
mod shutdown;
mod slot_clock;
mod state_manager;
mod sync;
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
        } => {
            if let Err(e) = genesis::generate_testnet(
                &out,
                validators,
                full_nodes,
                base_port,
                base_rpc_port,
                dev,
                chain_id,
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

            // Initialize logging first
            logging::init(&config.logging.level, config.logging.json);

            // Build async runtime and run
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(async {
                let shutdown = ShutdownSignal::new();
                let shutdown_clone = shutdown.clone();

                // Spawn signal handler
                tokio::spawn(shutdown::wait_for_signal(shutdown_clone));

                // Run the node
                let node = PydeNode::new(config, shutdown);
                if let Err(e) = node.run().await {
                    tracing::error!("node exited with error: {}", e);
                    std::process::exit(1);
                }
            });
        }
    }
}
