//! otic — the Otigen smart contract compiler.
//!
//! Usage:
//!   otic build <file.oti>     Compile .oti to .pyc bytecode
//!   otic check <file.oti>     Type check without codegen
//!   otic fmt <file.oti>       Auto-format source code
//!   otic test <file.oti>      Run #[test] functions
//!   otic abi <file.oti>       Output ABI JSON

use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "build" => {
            let file = require_file(&args);
            cmd_build(&file);
        }
        "check" => {
            let file = require_file(&args);
            cmd_check(&file);
        }
        "fmt" => {
            let file = require_file(&args);
            cmd_fmt(&file);
        }
        "test" => {
            let file = require_file(&args);
            cmd_test(&file);
        }
        "abi" => {
            let file = require_file(&args);
            cmd_abi(&file);
        }
        "lex" => {
            // Debug command: dump token stream
            let file = require_file(&args);
            cmd_lex(&file);
        }
        "--help" | "-h" | "help" => {
            print_usage();
        }
        "--version" | "-V" => {
            println!("otic {}", env!("CARGO_PKG_VERSION"));
        }
        other => {
            eprintln!("error: unknown command '{other}'");
            eprintln!();
            print_usage();
            process::exit(1);
        }
    }
}

fn require_file(args: &[String]) -> String {
    if args.len() < 3 {
        eprintln!("error: expected a file path");
        eprintln!("usage: otic {} <file.oti>", args[1]);
        process::exit(1);
    }
    args[2].clone()
}

fn read_source(path: &str) -> String {
    match fs::read_to_string(path) {
        Ok(src) => src,
        Err(e) => {
            eprintln!("error: could not read '{}': {}", path, e);
            process::exit(1);
        }
    }
}

fn cmd_lex(path: &str) {
    let src = read_source(path);
    let (tokens, errors) = otic::lexer::Lexer::new(&src).tokenize();

    for tok in &tokens {
        println!("{:>4}:{:<3}  {}", tok.span.line, tok.span.col, tok.kind);
    }

    if !errors.is_empty() {
        eprintln!();
        for err in &errors {
            eprintln!("error: {}", err);
        }
        process::exit(1);
    }

    println!("\n{} tokens, {} errors", tokens.len(), errors.len());
}

fn cmd_build(path: &str) {
    let _src = read_source(path);
    // TODO: lex → parse → type check → IR → optimize → codegen → .pyc
    eprintln!("error: 'build' not yet implemented (lexer complete, parser next)");
    process::exit(1);
}

fn cmd_check(path: &str) {
    let _src = read_source(path);
    // TODO: lex → parse → type check
    eprintln!("error: 'check' not yet implemented");
    process::exit(1);
}

fn cmd_fmt(path: &str) {
    let _src = read_source(path);
    // TODO: lex → parse → pretty print
    eprintln!("error: 'fmt' not yet implemented");
    process::exit(1);
}

fn cmd_test(path: &str) {
    let _src = read_source(path);
    // TODO: lex → parse → type check → codegen → execute #[test] functions on PVM
    eprintln!("error: 'test' not yet implemented");
    process::exit(1);
}

fn cmd_abi(path: &str) {
    let _src = read_source(path);
    // TODO: lex → parse → extract ABI → JSON output
    eprintln!("error: 'abi' not yet implemented");
    process::exit(1);
}

fn print_usage() {
    println!("otic — the Otigen smart contract compiler");
    println!();
    println!("Usage: otic <command> [file.oti]");
    println!();
    println!("Commands:");
    println!("  build <file>    Compile .oti to .pyc bytecode");
    println!("  check <file>    Type check without codegen");
    println!("  fmt <file>      Auto-format source code");
    println!("  test <file>     Run #[test] functions");
    println!("  abi <file>      Output ABI JSON");
    println!("  lex <file>      Debug: dump token stream");
    println!();
    println!("Options:");
    println!("  --help, -h      Show this help");
    println!("  --version, -V   Show version");
}
