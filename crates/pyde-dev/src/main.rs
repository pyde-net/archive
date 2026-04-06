mod cli;
mod project;
mod init;
mod build;
mod clean;
mod doc;
mod fmt;
mod console;
mod install;
mod script;
mod test_runner;
mod deploy;
mod verify;
mod wallet;
mod cheatcodes;
mod trace;
mod signer;

use clap::Parser;
use cli::{Cli, Command, WalletCommand};
use std::process;

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Init { name } => init::run(&name),
        Command::Build => build::run(),
        Command::Test { filter, verbosity } => test_runner::run(filter.as_deref(), verbosity),
        Command::Script { file, network, private_key, wallet } => {
            let rpc_url = project::get_rpc_url(&network).unwrap_or_else(|_| "http://127.0.0.1:8545".into());
            match signer::resolve_signer(private_key.as_deref(), wallet.as_deref(), &rpc_url) {
                Ok(s) => script::run(&file, &network, &s),
                Err(e) => Err(e),
            }
        }
        Command::Install { url, rev, name } => {
            match url {
                Some(u) => install::run(&u, rev.as_deref(), name.as_deref()),
                None => install::run("__restore__", None, None),
            }
        }
        Command::Remove { name } => install::remove(&name),
        Command::Console { network, private_key, wallet } => {
            let rpc_url = project::get_rpc_url(&network).unwrap_or_else(|_| "http://127.0.0.1:8545".into());
            match signer::resolve_signer(private_key.as_deref(), wallet.as_deref(), &rpc_url) {
                Ok(s) => console::run(&network, &s),
                Err(e) => Err(e),
            }
        }
        Command::Verify { address, contract, network } => {
            verify::run(&address, contract.as_deref(), &network)
        }
        Command::Wallet(cmd) => match cmd {
            WalletCommand::Create { name } => wallet::cmd_create(&name),
            WalletCommand::Import { public_key, secret_key, name } => {
                wallet::cmd_import(&name, &public_key, &secret_key)
            }
            WalletCommand::List => wallet::cmd_list(),
            WalletCommand::Balance { name, network } => wallet::cmd_balance(&name, &network),
        },
        Command::Transfer { to, amount, wallet: wallet_name, network } => {
            wallet::cmd_transfer(&to, amount, &wallet_name, &network)
        }
        Command::Call { address, function, network } => {
            console::cmd_call(&address, &function, &network)
        }
        Command::Send { address, function, network, value, private_key, wallet } => {
            let rpc_url = project::get_rpc_url(&network).unwrap_or_else(|_| "http://127.0.0.1:8545".into());
            match signer::resolve_signer(private_key.as_deref(), wallet.as_deref(), &rpc_url) {
                Ok(s) => console::cmd_send(&address, &function, &network, &s, value),
                Err(e) => Err(e),
            }
        }
        Command::Tx { hash, network } => {
            console::cmd_tx(&hash, &network)
        }
        Command::Fmt => fmt::run(),
        Command::Doc => doc::run(),
        Command::Clean => clean::run(),
        Command::Deploy { network, contract, value, private_key, wallet, verify } => {
            let rpc_url = project::get_rpc_url(&network).unwrap_or_else(|_| "http://127.0.0.1:8545".into());
            match signer::resolve_signer(private_key.as_deref(), wallet.as_deref(), &rpc_url) {
                Ok(s) => deploy::run(&network, contract.as_deref(), &s, value, verify),
                Err(e) => Err(e),
            }
        }
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}
