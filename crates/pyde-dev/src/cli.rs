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

    /// Auto-format all .oti files in src/ and test/.
    Fmt,

    /// Run a deployment/migration script.
    /// Format: `file.oti:ContractName` (e.g., `Deploy.oti:Erc20Deploy`).
    Script {
        /// Script file and optional contract: `file.oti` or `file.oti:ContractName`.
        file: String,

        /// Network name (must be defined in pyde.toml [networks]).
        #[arg(short, long, default_value = "devnet")]
        network: String,

        /// Sender address (hex).
        #[arg(long, default_value = "0x0101010101010101010101010101010101010101010101010101010101010101")]
        from: String,
    },

    /// Install a package from a git URL, or restore all from pyde.lock.
    /// Run with no arguments to restore all dependencies from the lock file.
    Install {
        /// Git repository URL (omit to restore all from pyde.lock).
        url: Option<String>,

        /// Branch, tag, or commit hash (default: main).
        #[arg(short, long)]
        rev: Option<String>,

        /// Override package name (default: repo name from URL).
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Remove an installed package.
    Remove {
        /// Package name to remove.
        name: String,
    },

    /// Verify a deployed contract matches local source.
    /// Example: `pyde-dev verify 0xaddr src/Counter.oti:Counter --network devnet`
    Verify {
        /// On-chain contract address (hex).
        address: String,

        /// Source file and contract: `file.oti:ContractName` or just `ContractName`.
        /// Auto-detected if only one contract exists.
        contract: Option<String>,

        /// Network name (must be defined in pyde.toml [networks]).
        #[arg(short, long, default_value = "devnet")]
        network: String,
    },

    /// Generate documentation from source contracts.
    Doc,

    /// Remove build artifacts (out/).
    Clean,

    /// Deploy a contract to a network.
    /// Example: `pyde-dev deploy src/Counter.oti:Counter --network devnet --verify`
    Deploy {
        /// Source file and contract: `file.oti:ContractName` or just `ContractName`.
        /// Auto-detected if only one contract exists.
        contract: Option<String>,

        /// Network name (must be defined in pyde.toml [networks]).
        #[arg(short, long, default_value = "devnet")]
        network: String,

        /// Sender address (hex).
        #[arg(long, default_value = "0x0101010101010101010101010101010101010101010101010101010101010101")]
        from: String,

        /// Verify the deployed bytecode matches local source after deploy.
        #[arg(long)]
        verify: bool,
    },
}
