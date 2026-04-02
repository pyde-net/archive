use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pyde-dev", version, about = "Pyde smart contract development framework")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize a new Pyde project.
    Init {
        /// Project name (creates a directory with this name).
        name: String,
    },

    /// Compile all contracts in src/.
    Build,

    /// Run tests in test/.
    Test {
        /// Optional filter: only run tests matching this string.
        #[arg(short, long)]
        filter: Option<String>,

        /// Verbosity level for execution traces.
        /// -v = call tree, -vv = + storage, -vvv = + logs/full.
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbosity: u8,
    },

    /// Remove build artifacts (out/).
    Clean,

    /// Deploy a contract to a network.
    Deploy {
        /// Network name (must be defined in pyde.toml [networks]).
        #[arg(short, long, default_value = "devnet")]
        network: String,

        /// Contract name to deploy (if multiple contracts exist).
        #[arg(short, long)]
        contract: Option<String>,

        /// Sender address (hex).
        #[arg(long, default_value = "0x0101010101010101010101010101010101010101010101010101010101010101")]
        from: String,
    },
}
