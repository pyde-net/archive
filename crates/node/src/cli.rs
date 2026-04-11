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

        /// Prometheus metrics port (0 = disabled). If omitted, uses config file or 9090.
        #[arg(long)]
        metrics_port: Option<u16>,

        /// JSON-RPC port. If omitted, uses config file or 8545.
        #[arg(long)]
        rpc_port: Option<u16>,

        /// Enable dev mode (allows unsigned pyde_sendTransaction, auto-mine).
        #[arg(long)]
        dev: bool,

        /// Bootstrap peer addresses (multiaddr).
        #[arg(long)]
        bootstrap: Vec<String>,
    },

    /// Print default configuration.
    DefaultConfig,

    /// Print default devnet genesis configuration.
    DefaultGenesis,

    /// Generate a multi-validator testnet directory.
    Testnet {
        /// Number of validators (2-128).
        #[arg(long, default_value = "2")]
        validators: usize,

        /// Output directory for testnet files.
        #[arg(long, short, default_value = "./testnet")]
        out: std::path::PathBuf,

        /// Base P2P port (nodes use base, base+1, base+2, ...).
        #[arg(long, default_value = "30303")]
        base_port: u16,

        /// Base RPC port (nodes use base, base+1, base+2, ...).
        #[arg(long, default_value = "8545")]
        base_rpc_port: u16,

        /// Enable dev mode on all nodes.
        #[arg(long)]
        dev: bool,

        /// Chain ID (31337 = devnet, skips signature validation).
        #[arg(long, default_value = "31337")]
        chain_id: u64,
    },

    /// Start a public faucet server.
    Faucet {
        /// RPC URL of the node to send transactions through.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Faucet listen port.
        #[arg(long, default_value = "8080")]
        port: u16,

        /// Amount to dispense per request (in PYDE).
        #[arg(long, default_value = "100")]
        amount: u64,

        /// Faucet sender address (hex, must be pre-funded on the network).
        #[arg(long)]
        from: String,

        /// Cooldown between requests per address (seconds).
        #[arg(long, default_value = "3600")]
        cooldown: u64,

        /// Path to faucet's private key file (same format as validator.key).
        /// If provided, signs transactions for production networks.
        /// If omitted, uses unsigned dev mode transactions.
        #[arg(long)]
        private_key: Option<String>,
    },
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
