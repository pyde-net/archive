use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pyde", version, about = "Pyde blockchain node")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start the node.
    Run {
        /// Node role.
        #[arg(long, default_value = "full")]
        role: Role,

        /// Path to config file.
        #[arg(long, short)]
        config: Option<PathBuf>,

        /// P2P listen port.
        #[arg(long)]
        port: Option<u16>,

        /// Data directory.
        #[arg(long)]
        datadir: Option<PathBuf>,

        /// Log level (trace, debug, info, warn, error).
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Enable JSON log output.
        #[arg(long)]
        log_json: bool,

        /// Prometheus metrics port (0 = disabled).
        #[arg(long, default_value = "9090")]
        metrics_port: u16,

        /// Bootstrap peer addresses (multiaddr).
        #[arg(long)]
        bootstrap: Vec<String>,
    },

    /// Print default configuration.
    DefaultConfig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Role {
    /// Validator node: participates in consensus, proposes and votes on blocks.
    Validator,
    /// Full node: stores state, relays transactions, serves RPC.
    Full,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Validator => write!(f, "validator"),
            Role::Full => write!(f, "full"),
        }
    }
}
