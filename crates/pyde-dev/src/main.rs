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
mod cheatcodes;
mod trace;

use clap::Parser;
use cli::{Cli, Command};
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
        Command::Fmt => fmt::run(),
        Command::Doc => doc::run(),
        Command::Clean => clean::run(),
        Command::Deploy { network, contract, from, verify } => {
            deploy::run(&network, contract.as_deref(), &from, verify)
        }
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}
