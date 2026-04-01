use crate::build;
use crate::project;
use std::fs;
use std::time::Instant;

pub fn run(filter: Option<&str>) -> Result<(), String> {
    let (config, root) = project::load_config()?;

    // Build src/ contracts first (tests may depend on them)
    println!("  Building contracts...");
    build::build_project(&config, &root)?;
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

        // Lower to IR
        let ir = otic::lower::lower(&ast_file);

        // Find test functions
        let test_fns: Vec<&otic::ir::IrFunction> = ir
            .functions
            .iter()
            .filter(|f| f.is_test)
            .filter(|f| filter.map(|pat| f.name.contains(pat)).unwrap_or(true))
            .collect();

        if test_fns.is_empty() {
            continue;
        }

        println!("  {}", rel.display());

        for func in &test_fns {
            // Build a minimal program with just this test function
            let mut test_ir = ir.clone();
            test_ir.functions = vec![(*func).clone()];
            test_ir.functions[0].is_pub = true;
            test_ir.functions[0].is_test = false;

            let mut codegen = otic::codegen::CodeGen::new();
            codegen.emit_guards = false;
            let compiled = codegen.generate(&test_ir);

            // Run on PVM
            let mut vm = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
            if let Err(e) = vm.load(&compiled.bytecode) {
                eprintln!("    FAIL {} — load error: {:?}", func.name, e);
                total_fail += 1;
                continue;
            }

            let mut steps = 0u64;
            let mut result = None;
            loop {
                match vm.step() {
                    Ok(Some(r)) => {
                        result = Some(r);
                        break;
                    }
                    Ok(None) => {
                        steps += 1;
                        if steps > 1_000_000 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            let should_panic = func
                .doc
                .as_ref()
                .map_or(false, |d| d.contains("should_panic"));

            let ok = match result {
                Some(pyde_vm::vm::ExecResult::Halt) => !should_panic,
                Some(pyde_vm::vm::ExecResult::Revert) => should_panic,
                _ => false,
            };

            let gas = vm.gas_used_total;
            if ok {
                println!("    PASS {} ({} gas)", func.name, gas);
                total_pass += 1;
            } else {
                println!("    FAIL {}", func.name);
                total_fail += 1;
            }
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

    if total_fail > 0 {
        Err(format!("{} test(s) failed", total_fail))
    } else {
        Ok(())
    }
}
