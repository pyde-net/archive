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

use clap::Parser;
use cli::{Cli, Command, WalletCommand};
use std::process;

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Init { name } => init::run(&name),
        Command::Build => build::run(),
        Command::Test { filter, verbosity } => test_runner::run(filter.as_deref(), verbosity),
        Command::Script { file, network, from } => script::run(&file, &network, &from),
        Command::Install { url, rev, name } => {
            match url {
                Some(u) => install::run(&u, rev.as_deref(), name.as_deref()),
                None => install::run("__restore__", None, None),
            }
        }
        Command::Remove { name } => install::remove(&name),
        Command::Console { network, from } => console::run(&network, &from),
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
        Command::Tx { hash, network } => {
            console::cmd_tx(&hash, &network)
        }
        Command::Fmt => fmt::run(),
        Command::Doc => doc::run(),
        Command::Clean => clean::run(),
        Command::Deploy { network, contract, from, wallet: _, verify } => {
            deploy::run(&network, contract.as_deref(), &from, verify)
        }
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}
