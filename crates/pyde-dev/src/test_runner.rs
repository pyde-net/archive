use crate::build;
use crate::cheatcodes::{self, CheatcodeState};
use crate::project;
use crate::trace::{self, ExecutionTrace, Verbosity};
use std::collections::HashMap;
use std::fs;
use std::time::Instant;

pub fn run(filter: Option<&str>, verbosity: u8) -> Result<(), String> {
    let (config, root) = project::load_config()?;

    // Resolve verbosity: CLI flag overrides pyde.toml config
    let effective_verbosity = if verbosity > 0 {
        verbosity
    } else {
        config.testing.verbosity
    };
    let trace_verbosity = Verbosity::from_count(effective_verbosity);

    // Build src/ contracts first (tests may depend on them)
    println!("  Building contracts...");
    let build_result = build::build_project(&config, &root)?;
    println!();

    // Find test files
    let test_dir = root.join(&config.compiler.test);
    if !test_dir.exists() {
        return Err(format!("test directory '{}' not found", test_dir.display()));
    }

    let pattern = format!("{}/**/*.oti", test_dir.display());
    let files: Vec<_> = glob::glob(&pattern)
        .map_err(|e| format!("glob error: {}", e))?
        .filter_map(|r| r.ok())
        .collect();

    if files.is_empty() {
        println!("  no test files found in {}", test_dir.display());
        return Ok(());
    }

    let start = Instant::now();
    let mut total_pass = 0u32;
    let mut total_fail = 0u32;
    let mut total_skip = 0u32;

    // Gas profiling: collect per-test gas usage for summary
    struct GasEntry {
        #[allow(dead_code)]
        file: String,
        test_name: String,
        gas_used: u64,
        passed: bool,
    }
    let mut gas_profile: Vec<GasEntry> = Vec::new();
    let gas_limit: u64 = 100_000_000; // matches VM gas limit used below

    for file in &files {
        let source = fs::read_to_string(file)
            .map_err(|e| format!("cannot read {}: {}", file.display(), e))?;
        let rel = file.strip_prefix(&root).unwrap_or(file);

        // Run frontend
        let (tokens, lex_errors) = otic::lexer::Lexer::new(&source).tokenize();
        if !lex_errors.is_empty() {
            eprintln!("  {} — lex errors, skipping", rel.display());
            total_skip += 1;
            continue;
        }

        let (ast_file, parse_errors) = otic::parser::Parser::new(tokens).parse();
        if !parse_errors.is_empty() {
            eprintln!("  {} — parse errors, skipping", rel.display());
            total_skip += 1;
            continue;
        }

        // Lower to IR with src/ contract context (bytecode + signatures for deploy!/dispatch)
        let mut ir = otic::lower::lower_with_context(
            &ast_file,
            &build_result.compiled_registry,
            &build_result.contract_functions,
            &build_result.contract_constructors,
        );
        otic::optimize::optimize(&mut ir);

        // Collect test function metadata before we modify the IR
        struct TestMeta {
            name: String,
            should_panic: bool,
            expected_error: Option<String>,
        }
        let test_metas: Vec<TestMeta> = ir
            .functions
            .iter()
            .filter(|f| f.is_test)
            .filter(|f| filter.map(|pat| f.name.contains(pat)).unwrap_or(true))
            .map(|f| TestMeta {
                name: f.name.clone(),
                should_panic: f.should_panic,
                expected_error: f.expected_error.clone(),
            })
            .collect();

        if test_metas.is_empty() {
            continue;
        }

        // Promote test functions to pub so codegen includes them in the dispatch table
        for func in &mut ir.functions {
            if func.is_test {
                func.is_pub = true;
                func.is_test = false;
            }
        }

        // Build error selector → name map from the contract's error definitions + revert names
        let error_map = build_error_map(&ir);

        // Compile full contract (constructor + runtime + dispatch including test fns)
        let codegen = otic::codegen::CodeGen::new();
        let compiled = codegen.generate(&ir);

        // --- Run constructor to initialize storage ---
        let constructor_storage = if !compiled.constructor_bytecode.is_empty() {
            let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000_000);
            if let Err(e) = vm.load(&compiled.constructor_bytecode) {
                eprintln!(
                    "  {} — constructor load error: {:?}, skipping",
                    rel.display(),
                    e
                );
                total_skip += 1;
                continue;
            }
            let output = vm.execute();
            if output.outcome != pyde_vm::vm::Outcome::Success {
                eprintln!(
                    "  {} — constructor failed: {:?}, skipping",
                    rel.display(),
                    output.outcome
                );
                total_skip += 1;
                continue;
            }
            vm.storage.clone()
        } else {
            HashMap::new()
        };

        println!("  {}", rel.display());

        // --- Run each test function against the runtime with initialized storage ---
        for meta in &test_metas {
            // Snapshot: clone constructor storage for each test (isolation)
            let snapshot = constructor_storage.clone();

            // Build calldata: 4-byte selector (BE)
            let selector = otic::codegen::compute_selector(&meta.name);
            let calldata = selector.to_be_bytes().to_vec();

            // Create VM with runtime bytecode
            // Set calldata BEFORE load() so map_calldata() runs during load
            let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000_000);
            vm.calldata = calldata;
            if let Err(e) = vm.load(&compiled.runtime_bytecode) {
                eprintln!("    FAIL {} — load error: {:?}", meta.name, e);
                total_fail += 1;
                continue;
            }

            // Inject constructor storage (after load so it doesn't get cleared)
            vm.storage = snapshot;

            // Execute with cheatcode interception (fresh state per test)
            let mut cheat_state = CheatcodeState::new();
            let mut exec_trace = ExecutionTrace::new();
            let outcome = if trace_verbosity > Verbosity::Silent {
                cheatcodes::execute_with_tracing(&mut vm, &mut cheat_state, &mut exec_trace)
            } else {
                cheatcodes::execute_with_cheatcodes(&mut vm, &mut cheat_state)
            };
            let gas = vm.gas_used_total;

            let ok = if meta.should_panic {
                // Expected to revert
                match outcome {
                    pyde_vm::vm::Outcome::Revert => {
                        // If expected_error specified, check revert data matches
                        if let Some(ref expected) = meta.expected_error {
                            let expected_selector = otic::codegen::compute_selector(expected);
                            let actual_selector = if vm.return_data.len() >= 8 {
                                u64::from_le_bytes(vm.return_data[..8].try_into().unwrap_or([0; 8]))
                            } else {
                                0
                            };
                            if actual_selector == expected_selector as u64 {
                                true
                            } else {
                                println!("    FAIL {} — reverted but wrong error (expected '{}', got selector 0x{:x})",
                                    meta.name, expected, actual_selector);
                                false
                            }
                        } else {
                            true // Any revert is fine
                        }
                    }
                    _ => {
                        println!(
                            "    FAIL {} — expected revert but got {:?}",
                            meta.name, outcome
                        );
                        false
                    }
                }
            } else {
                // Expected to succeed
                match outcome {
                    pyde_vm::vm::Outcome::Success => true,
                    pyde_vm::vm::Outcome::Revert => {
                        // Decode error name from revert data using contract's error map
                        let err_info = decode_revert_error(&vm.return_data, &error_map);
                        println!("    FAIL {} — reverted{}", meta.name, err_info);
                        false
                    }
                    other => {
                        println!("    FAIL {} — {:?}", meta.name, other);
                        false
                    }
                }
            };

            if ok {
                let panic_tag = if meta.should_panic {
                    " (expected panic)"
                } else {
                    ""
                };
                println!("    PASS {}{} ({} gas)", meta.name, panic_tag, gas);
                total_pass += 1;
            } else if !meta.should_panic || meta.expected_error.is_some() {
                // Error already printed above
                total_fail += 1;
            } else {
                total_fail += 1;
            }

            // Print execution trace if verbosity enabled
            if trace_verbosity > Verbosity::Silent && !exec_trace.is_empty() {
                let tree = trace::build_tree(&exec_trace.events);
                let formatted = trace::format_tree(&tree, trace_verbosity);
                println!("    Traces:");
                for line in formatted.lines() {
                    println!("      {}", line);
                }
            }

            // Collect for gas profile
            gas_profile.push(GasEntry {
                file: rel.to_string_lossy().to_string(),
                test_name: meta.name.clone(),
                gas_used: gas,
                passed: ok,
            });
        }
    }

    let elapsed = start.elapsed();
    println!();
    println!(
        "  {} passed, {} failed, {} skipped ({:.2}s)",
        total_pass,
        total_fail,
        total_skip,
        elapsed.as_secs_f64()
    );

    // Gas profiling summary
    if !gas_profile.is_empty() {
        // Sort by gas used (descending — most expensive first)
        gas_profile.sort_by(|a, b| b.gas_used.cmp(&a.gas_used));

        let total_gas: u64 = gas_profile.iter().map(|e| e.gas_used).sum();
        let max_name_len = gas_profile
            .iter()
            .map(|e| e.test_name.len())
            .max()
            .unwrap_or(20);
        let col_width = max_name_len.max(20);

        println!();
        println!("  Gas Profile");
        println!(
            "  {:<col_width$}  {:>12}  {:>8}  Status",
            "Test", "Gas Used", "% Limit"
        );
        println!("  {}", "-".repeat(col_width + 30));
        for entry in &gas_profile {
            let pct = (entry.gas_used as f64 / gas_limit as f64) * 100.0;
            let status = if entry.passed { "PASS" } else { "FAIL" };
            println!(
                "  {:<col_width$}  {:>12}  {:>7.2}%  {}",
                entry.test_name, entry.gas_used, pct, status
            );
        }
        println!("  {}", "-".repeat(col_width + 30));
        println!("  {:<col_width$}  {:>12}", "Total", total_gas);
        if gas_profile.len() > 1 {
            let avg = total_gas / gas_profile.len() as u64;
            println!("  {:<col_width$}  {:>12}", "Average", avg);
        }
    }

    if total_fail > 0 {
        Err(format!("{} test(s) failed", total_fail))
    } else {
        Ok(())
    }
}

/// Build a map of error selector → error name from the contract's IR.
/// Includes: error definitions, built-in names (AssertionFailed, Error),
/// and any string messages used in revert!("...") calls.
fn build_error_map(ir: &otic::ir::IrProgram) -> HashMap<u64, String> {
    let mut map = HashMap::new();

    // Built-in error names
    for name in &["AssertionFailed", "Error"] {
        let sel = otic::codegen::compute_selector(name) as u64;
        map.insert(sel, name.to_string());
    }

    // Contract-defined errors
    for err in &ir.error_defs {
        let sel = otic::codegen::compute_selector(&err.name) as u64;
        map.insert(sel, err.name.clone());
    }

    // Scan IR instructions for revert string names
    for func in &ir.functions {
        for block in &func.blocks {
            for inst in &block.instructions {
                if let otic::ir::Inst::Revert(name, _) = inst {
                    let sel = otic::codegen::compute_selector(name) as u64;
                    map.insert(sel, name.clone());
                }
            }
        }
    }

    map
}

/// Decode the error name from revert data using the contract's error map.
/// Revert data format: [selector:8 LE][field0:8][field1:8]...
fn decode_revert_error(data: &[u8], error_map: &HashMap<u64, String>) -> String {
    if data.len() < 8 {
        return String::new();
    }
    let selector = u64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]));

    if let Some(name) = error_map.get(&selector) {
        format!(" with error: {}", name)
    } else {
        format!(" with error selector: 0x{:08x}", selector as u32)
    }
}
