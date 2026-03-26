//! otic — the Otigen smart contract compiler.
//!
//! Usage:
//!   otic build <file.oti>     Compile .oti to .pyc bytecode
//!   otic check <file.oti>     Type check without codegen
//!   otic test <file.oti>      Run #[test] functions
//!   otic abi <file.oti>       Output ABI JSON
//!   otic lex <file.oti>       Debug: dump token stream

use std::env;
use std::fs;
use std::process;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "build" => cmd_build(&require_file(&args)),
        "check" => cmd_check(&require_file(&args)),
        "test" => cmd_test(&require_file(&args)),
        "abi" => cmd_abi(&require_file(&args)),
        "lex" => cmd_lex(&require_file(&args)),
        "--help" | "-h" | "help" => print_usage(),
        "--version" | "-V" => println!("otic {}", env!("CARGO_PKG_VERSION")),
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

use otic::diagnostic::{Diagnostic, Level, format_diagnostics};

/// Run the full frontend pipeline: lex → parse → resolve → typecheck → safety.
/// Returns the parsed file and source. Exits with rich diagnostics on error.
fn run_frontend(path: &str) -> (otic::ast::SourceFile, String) {
    let src = read_source(path);
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    let (tokens, lex_errors) = otic::lexer::Lexer::new(&src).tokenize();
    for err in &lex_errors {
        diagnostics.push(Diagnostic {
            level: Level::Error,
            message: err.message.clone(),
            file: path.into(),
            line: err.line,
            col: err.col,
        });
    }
    if !diagnostics.is_empty() {
        eprint!("{}", format_diagnostics(&diagnostics, &src));
        process::exit(1);
    }

    let (file, parse_errors) = otic::parser::Parser::new(tokens).parse();
    for err in &parse_errors {
        diagnostics.push(Diagnostic {
            level: Level::Error,
            message: err.message.clone(),
            file: path.into(),
            line: err.span.line,
            col: err.span.col,
        });
    }
    if !diagnostics.is_empty() {
        eprint!("{}", format_diagnostics(&diagnostics, &src));
        process::exit(1);
    }

    let resolve_result = otic::resolve::Resolver::new().resolve(&file);
    for err in &resolve_result.errors {
        diagnostics.push(Diagnostic {
            level: Level::Error,
            message: err.message.clone(),
            file: path.into(),
            line: err.span.line,
            col: err.span.col,
        });
    }
    if !diagnostics.is_empty() {
        eprint!("{}", format_diagnostics(&diagnostics, &src));
        process::exit(1);
    }

    let tc_result = otic::typecheck::TypeChecker::new().check(&file);
    for err in &tc_result.errors {
        diagnostics.push(Diagnostic {
            level: Level::Error,
            message: err.message.clone(),
            file: path.into(),
            line: err.span.line,
            col: err.span.col,
        });
    }
    if !diagnostics.is_empty() {
        eprint!("{}", format_diagnostics(&diagnostics, &src));
        process::exit(1);
    }

    let safety_result = otic::safety::SafetyChecker::new().check(&file);
    for err in &safety_result.errors {
        diagnostics.push(Diagnostic {
            level: Level::Error,
            message: err.message.clone(),
            file: path.into(),
            line: err.span.line,
            col: err.span.col,
        });
    }
    if !diagnostics.is_empty() {
        eprint!("{}", format_diagnostics(&diagnostics, &src));
        process::exit(1);
    }

    (file, src)
}

// ============================================================================
// Commands
// ============================================================================

fn cmd_build(path: &str) {
    let (file, _src) = run_frontend(path);

    // Lower → optimize → codegen
    let mut ir = otic::lower::lower(&file);
    otic::optimize::optimize(&mut ir);
    let abi = otic::abi::generate_abi(&ir);
    let codegen = otic::codegen::CodeGen::new();
    let contract = codegen.generate(&ir);

    // Generate JSON artifact (readable in any editor)
    let artifact = otic::abi::artifact_to_json(&abi, &contract);

    // Write .json artifact
    let json_path = Path::new(path).with_extension("json");
    if let Err(e) = fs::write(&json_path, &artifact) {
        eprintln!("error: could not write '{}': {}", json_path.display(), e);
        process::exit(1);
    }

    println!("  compiled {} → {}", path, json_path.display());
    println!("  contract:    {}", contract.name);
    println!("  bytecode:    {} bytes ({} instructions)",
        contract.bytecode.len(), contract.instruction_count);
    println!("  constructor: {} bytes", contract.constructor_bytecode.len());
    println!("  runtime:     {} bytes", contract.runtime_bytecode.len());
    println!("  functions:   {}", abi.functions.len());
    println!("  events:      {}", abi.events.len());
    println!("  storage:     {} fields", abi.storage.len());
}

fn cmd_check(path: &str) {
    let (_file, _src) = run_frontend(path);
    println!("  {} — no errors", path);
}

fn cmd_test(path: &str) {
    let (file, _src) = run_frontend(path);

    // Lower + codegen (no optimize for tests — preserve all test functions)
    let ir = otic::lower::lower(&file);

    let test_fns: Vec<&otic::ir::IrFunction> = ir.functions.iter()
        .filter(|f| f.is_test)
        .collect();

    if test_fns.is_empty() {
        println!("  {} — no #[test] functions found", path);
        return;
    }

    let mut passed = 0;
    let mut failed = 0;

    for func in &test_fns {
        // Build a minimal program with just this test function
        let mut test_ir = ir.clone();
        test_ir.functions = vec![(*func).clone()];
        // Mark as pub so codegen treats it as entry
        test_ir.functions[0].is_pub = true;
        test_ir.functions[0].is_test = false;

        let mut codegen = otic::codegen::CodeGen::new();
        codegen.emit_guards = false;
        let compiled = codegen.generate(&test_ir);

        // Run on PVM
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(1_000_000);
        vm.load(&compiled.bytecode).unwrap();

        let mut steps = 0;
        let mut result = None;
        loop {
            match vm.step() {
                Ok(Some(r)) => { result = Some(r); break; }
                Ok(None) => { steps += 1; if steps > 100_000 { break; } }
                Err(_) => break,
            }
        }

        let should_panic = func.doc.as_ref().map_or(false, |d| d.contains("should_panic"));

        let ok = match result {
            Some(pyde_vm::vm::ExecResult::Halt) => !should_panic,
            Some(pyde_vm::vm::ExecResult::Revert) => should_panic,
            _ => false,
        };

        if ok {
            println!("  test {} ... ok", func.name);
            passed += 1;
        } else {
            println!("  test {} ... FAILED", func.name);
            failed += 1;
        }
    }

    println!("\n  {} passed, {} failed", passed, failed);
    if failed > 0 {
        process::exit(1);
    }
}

fn cmd_abi(path: &str) {
    let (file, _src) = run_frontend(path);
    let ir = otic::lower::lower(&file);
    let abi = otic::abi::generate_abi(&ir);
    let json = otic::abi::abi_to_json(&abi);
    println!("{}", json);
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

    println!("\n  {} tokens, {} errors", tokens.len(), errors.len());
}

fn print_usage() {
    println!("otic — the Otigen smart contract compiler");
    println!();
    println!("Usage: otic <command> [file.oti]");
    println!();
    println!("Commands:");
    println!("  build <file>    Compile .oti to .pyc bytecode");
    println!("  check <file>    Type check without codegen");
    println!("  test <file>     Run #[test] functions on PVM");
    println!("  abi <file>      Output ABI JSON");
    println!("  lex <file>      Debug: dump token stream");
    println!();
    println!("Options:");
    println!("  --help, -h      Show this help");
    println!("  --version, -V   Show version");
}
