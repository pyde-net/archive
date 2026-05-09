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
use std::path::Path;
use std::process;

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

use otic::diagnostic::{format_diagnostics, Diagnostic, Level};

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
    let (_file, _src) = run_frontend(path);
    let src = read_source(path);

    // Multi-contract compilation: compile all contracts in the file.
    // Later contracts can reference earlier ones via create!(ContractName, args).
    //
    // Audit 404: this binary already ran the full frontend (resolve +
    // typecheck + safety) inside `run_frontend(path)` above, so we
    // intentionally use the lax `__compile_all_unchecked` here to avoid
    // re-running the same checks. The strict `compile_all` is for
    // callers that haven't yet run the frontend separately.
    let results = otic::__compile_all_unchecked(&src);

    if results.is_empty() {
        eprintln!("error: no contracts found in {}", path);
        process::exit(1);
    }

    for (name, contract) in &results {
        // Generate IR for ABI (single-contract lower for ABI generation)
        let (tokens, _) = otic::lexer::Lexer::new(&src).tokenize();
        let (file, _) = otic::parser::Parser::new(tokens).parse();
        // Build single-contract file for ABI
        let mut single = otic::ast::SourceFile { items: Vec::new() };
        for item in &file.items {
            match item {
                otic::ast::Item::Contract(c) if c.name.name == *name => {
                    single.items.push(item.clone())
                }
                otic::ast::Item::Contract(_) => {}
                _ => single.items.push(item.clone()),
            }
        }
        let ir = otic::lower::lower(&single);
        let abi = otic::abi::generate_abi(&ir);
        let artifact = otic::abi::artifact_to_json(&abi, contract);

        // Write .json artifact (use contract name for multi-contract files)
        let json_path = if results.len() == 1 {
            Path::new(path).with_extension("json")
        } else {
            let stem = Path::new(path)
                .file_stem()
                .unwrap_or_default()
                .to_str()
                .unwrap_or("out");
            Path::new(path).with_file_name(format!("{}_{}.json", stem, name.to_lowercase()))
        };
        if let Err(e) = fs::write(&json_path, &artifact) {
            eprintln!("error: could not write '{}': {}", json_path.display(), e);
            process::exit(1);
        }

        println!("  compiled {} → {}", path, json_path.display());
        println!("  contract:    {}", contract.name);
        println!(
            "  bytecode:    {} bytes ({} instructions)",
            contract.bytecode.len(),
            contract.instruction_count
        );
        println!(
            "  constructor: {} bytes",
            contract.constructor_bytecode.len()
        );
        println!("  runtime:     {} bytes", contract.runtime_bytecode.len());
        println!("  functions:   {}", abi.functions.len());
        println!("  events:      {}", abi.events.len());
        println!("  storage:     {} fields", abi.storage.len());
        println!();
    }
}

fn cmd_check(path: &str) {
    let (_file, _src) = run_frontend(path);
    println!("  {} — no errors", path);
}

fn cmd_test(path: &str) {
    let (file, _src) = run_frontend(path);

    // Lower + codegen (no optimize for tests — preserve all test functions)
    let mut ir = otic::lower::lower(&file);

    // Snapshot the test set + per-test metadata before mutating IR.
    let test_metas: Vec<(String, bool, Option<String>)> = ir
        .functions
        .iter()
        .filter(|f| f.is_test)
        .map(|f| (f.name.clone(), f.should_panic, f.expected_error.clone()))
        .collect();

    if test_metas.is_empty() {
        println!("  {} — no #[test] functions found", path);
        return;
    }

    // Promote test fns to pub so codegen includes them in the dispatch table.
    for func in &mut ir.functions {
        if func.is_test {
            func.is_pub = true;
            func.is_test = false;
        }
    }

    // TPL-602: contracts compile with default `emit_guards = true` and the
    // tests dispatch through the runtime selector, so reentrancy + payable
    // guard prologues run on every test call — the pre-fix path stripped
    // them out and let test fixtures pass against bytecode that diverged
    // from what the chain would deploy. Pure-library files (`module foo;`
    // with no contract block) have no contract surface to guard, so they
    // keep the single-fn-as-entry path; the guard machinery doesn't apply.
    let is_contract = !ir.contract_name.is_empty();

    let mut passed = 0;
    let mut failed = 0;

    if is_contract {
        let codegen = otic::codegen::CodeGen::new();
        let compiled = codegen.generate(&ir);

        // Run constructor (if any) to seed shared storage state.
        let constructor_storage: std::collections::HashMap<_, _> =
            if !compiled.constructor_bytecode.is_empty() {
                let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000_000);
                if let Err(e) = vm.load(&compiled.constructor_bytecode) {
                    eprintln!("constructor load error: {:?}", e);
                    process::exit(1);
                }
                let output = vm.execute();
                if output.outcome != pyde_vm::vm::Outcome::Success {
                    eprintln!("constructor failed: {:?}", output.outcome);
                    process::exit(1);
                }
                vm.storage.clone()
            } else {
                std::collections::HashMap::new()
            };

        for (name, should_panic, expected_error) in &test_metas {
            // Snapshot per test for isolation.
            let snapshot = constructor_storage.clone();

            // 4-byte selector dispatch. Setting `vm.calldata` BEFORE `load`
            // matches the pyde-dev runner so `map_calldata()` runs during load.
            let selector = otic::codegen::compute_selector(name);
            let calldata = selector.to_be_bytes().to_vec();

            let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000_000);
            vm.calldata = calldata;
            if let Err(e) = vm.load(&compiled.runtime_bytecode) {
                println!("  test {} ... FAILED (load: {:?})", name, e);
                failed += 1;
                continue;
            }
            vm.storage = snapshot;

            let output = vm.execute();

            let ok = if *should_panic {
                match output.outcome {
                    pyde_vm::vm::Outcome::Revert => match expected_error {
                        Some(expected) => {
                            let expected_selector = otic::codegen::compute_selector(expected);
                            let actual_selector = if vm.return_data.len() >= 8 {
                                u64::from_le_bytes(vm.return_data[..8].try_into().unwrap_or([0; 8]))
                            } else {
                                0
                            };
                            actual_selector == expected_selector as u64
                        }
                        None => true,
                    },
                    _ => false,
                }
            } else {
                matches!(output.outcome, pyde_vm::vm::Outcome::Success)
            };

            if ok {
                println!("  test {} ... ok", name);
                passed += 1;
            } else {
                println!("  test {} ... FAILED ({:?})", name, output.outcome);
                failed += 1;
            }
        }
    } else {
        // Library / module path: no contract dispatcher to thread tests
        // through. Compile each test in isolation as the single entry, with
        // guards disabled — there is no contract storage state for a
        // reentrancy guard to key on. This is the pre-fix `otic test` flow
        // preserved verbatim for library files; `cargo test` against the
        // `tests/` integration suite is the path that exercises helper-fn
        // calls, so this CLI stays as a quick-check for self-contained
        // `#[test]` fns.
        for (name, should_panic, _expected_error) in &test_metas {
            let func = match ir.functions.iter().find(|f| &f.name == name) {
                Some(f) => f.clone(),
                None => {
                    println!("  test {} ... FAILED (missing in IR)", name);
                    failed += 1;
                    continue;
                }
            };

            let mut entry = func;
            entry.is_pub = true;
            entry.is_test = false;
            let mut test_ir = ir.clone();
            test_ir.functions = vec![entry];

            let mut codegen = otic::codegen::CodeGen::new();
            codegen.emit_guards = false;
            let compiled = codegen.generate(&test_ir);

            let mut vm = pyde_vm::vm::Vm::with_gas_limit(1_000_000);
            if let Err(e) = vm.load(&compiled.bytecode) {
                println!("  test {} ... FAILED (load: {:?})", name, e);
                failed += 1;
                continue;
            }

            let mut steps = 0;
            let mut result = None;
            loop {
                match vm.step() {
                    Ok(Some(r)) => {
                        result = Some(r);
                        break;
                    }
                    Ok(None) => {
                        steps += 1;
                        if steps > 100_000 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            let ok = match result {
                Some(pyde_vm::vm::ExecResult::Halt) => !*should_panic,
                Some(pyde_vm::vm::ExecResult::Revert) => *should_panic,
                _ => false,
            };

            if ok {
                println!("  test {} ... ok", name);
                passed += 1;
            } else {
                println!("  test {} ... FAILED", name);
                failed += 1;
            }
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
