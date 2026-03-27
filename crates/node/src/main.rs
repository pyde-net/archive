mod block_processor;
mod chain;
mod cli;
mod config;
mod logging;
mod metrics;
mod node;
mod shutdown;
mod state_manager;
mod tx_relay;
mod validator;

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
        Command::Run {
            role,
            config: config_path,
            port,
            datadir,
            log_level,
            log_json,
            metrics_port,
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
                Some(metrics_port),
                &bootstrap,
            );

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
