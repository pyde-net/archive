mod cli;
mod project;
mod init;
mod build;
mod clean;
mod doc;
mod fmt;
mod test_runner;
mod deploy;
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
        Command::Fmt => fmt::run(),
        Command::Doc => doc::run(),
        Command::Clean => clean::run(),
        Command::Deploy { network, contract, from } => {
            deploy::run(&network, contract.as_deref(), &from)
        }
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}
