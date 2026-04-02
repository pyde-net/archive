use crate::project::{self, ProjectConfig};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::{Digest, Sha256};

/// Build cache stored in out/.build-cache.json for incremental builds.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct BuildCache {
    /// file path (relative to project root) → content SHA-256 hex
    hashes: HashMap<String, String>,
}

/// Function signature: (name, params, return_type).
pub type FnSig = (String, Vec<(String, otic::types::Ty)>, otic::types::Ty);

/// Result of building the project.
pub struct BuildResult {
    pub contracts: Vec<(String, String)>, // (contract_name, artifact_path)
    pub total_bytecode: usize,
    /// Contract name → deploy-format bytes [clen:4][rlen:4][constructor][runtime].
    /// Used by test runner for deploy!() and cross-contract calls.
    pub compiled_registry: HashMap<String, Vec<u8>>,
    /// Contract name → public function signatures (for typed method dispatch).
    pub contract_functions: HashMap<String, Vec<FnSig>>,
    /// Contract name → constructor param list (for deploy! arg validation).
    pub contract_constructors: HashMap<String, Vec<(String, otic::types::Ty)>>,
}

pub fn run() -> Result<(), String> {
    let (config, root) = project::load_config()?;
    let result = build_project(&config, &root)?;
    println!(
        "\n  {} contract(s) compiled, {} bytes total bytecode",
        result.contracts.len(),
        result.total_bytecode
    );
    Ok(())
}

/// Build the full project. Called by both `pyde-dev build` and `pyde-dev test`.
pub fn build_project(config: &ProjectConfig, root: &Path) -> Result<BuildResult, String> {
    let start = Instant::now();
    let src_dir = root.join(&config.compiler.src);
    let out_dir = root.join(&config.compiler.out);

    if !src_dir.exists() {
        return Err(format!(
            "source directory '{}' not found",
            src_dir.display()
        ));
    }

    // Find all .oti files
    let pattern = format!("{}/**/*.oti", src_dir.display());
    let files: Vec<PathBuf> = glob::glob(&pattern)
        .map_err(|e| format!("glob error: {}", e))?
        .filter_map(|r| r.ok())
        .collect();

    if files.is_empty() {
        return Err(format!("no .oti files found in {}", src_dir.display()));
    }

    // Load build cache for incremental builds
    let cache_path = out_dir.join(".build-cache.json");
    let old_cache = load_cache(&cache_path);
    let mut new_cache = BuildCache::default();

    // Read all source files + compute hashes
    let mut sources: Vec<(PathBuf, String, String)> = Vec::new(); // (path, source, hash)
    for file in &files {
        let source = fs::read_to_string(file)
            .map_err(|e| format!("cannot read {}: {}", file.display(), e))?;
        let hash = sha256_hex(&source);
        sources.push((file.clone(), source, hash));
    }

    // Build dependency graph from `use` statements
    let dep_graph = build_dependency_graph(&sources, &src_dir)?;

    // Topological sort (detect cycles)
    let compile_order = topological_sort(&dep_graph, &sources)?;

    // Check which files need recompilation
    let mut needs_rebuild: HashSet<usize> = HashSet::new();
    for (idx, (path, _, hash)) in sources.iter().enumerate() {
        let rel = path.strip_prefix(root).unwrap_or(path);
        let rel_str = rel.to_string_lossy().to_string();
        let old_hash = old_cache.hashes.get(&rel_str);
        if old_hash != Some(hash) {
            needs_rebuild.insert(idx);
            // If a file changed, all files that depend on it also need rebuilding
            mark_dependents(&dep_graph, idx, &mut needs_rebuild, sources.len());
        }
        new_cache.hashes.insert(rel_str, hash.clone());
    }

    // Create output directory
    fs::create_dir_all(&out_dir)
        .map_err(|e| format!("cannot create {}: {}", out_dir.display(), e))?;

    // Compile in dependency order
    let mut compiled_registry: HashMap<String, Vec<u8>> = HashMap::new();
    let mut contract_functions: HashMap<String, Vec<FnSig>> = HashMap::new();
    let mut contract_constructors: HashMap<String, Vec<(String, otic::types::Ty)>> = HashMap::new();
    let mut result = BuildResult {
        contracts: Vec::new(),
        total_bytecode: 0,
        compiled_registry: HashMap::new(),
        contract_functions: HashMap::new(),
        contract_constructors: HashMap::new(),
    };
    let mut had_errors = false;

    for &file_idx in &compile_order {
        let (ref path, ref source, _) = sources[file_idx];
        let rel = path.strip_prefix(root).unwrap_or(path);

        // Skip if unchanged and all deps unchanged
        if !needs_rebuild.contains(&file_idx) {
            // Still register previously compiled contracts from artifacts
            load_existing_artifacts(
                &out_dir,
                source,
                &mut compiled_registry,
                &mut contract_functions,
                &mut contract_constructors,
                &mut result,
            );
            continue;
        }

        // Run frontend: lex → parse → resolve → typecheck → safety
        if let Err(msg) = run_frontend(path, source) {
            eprintln!("{}", msg);
            had_errors = true;
            continue;
        }

        // Compile
        let contracts = otic::compile_all(source);
        if contracts.is_empty() {
            println!("  {} — no contracts", rel.display());
            continue;
        }

        for (name, contract) in &contracts {
            // Generate ABI
            let (tokens, _) = otic::lexer::Lexer::new(source).tokenize();
            let (file, _) = otic::parser::Parser::new(tokens).parse();
            let mut single = otic::ast::SourceFile { items: Vec::new() };
            for item in &file.items {
                match item {
                    otic::ast::Item::Contract(c) if c.name.name == *name => {
                        single.items.push(item.clone());
                    }
                    otic::ast::Item::Contract(_) => {}
                    _ => single.items.push(item.clone()),
                }
            }
            let ir = otic::lower::lower(&single);

            // Extract function signatures for typed dispatch in test files
            let mut pub_fns: Vec<FnSig> = Vec::new();
            for func in &ir.functions {
                if func.is_pub && !func.is_constructor && !func.is_test {
                    pub_fns.push((
                        func.name.clone(),
                        func.params.clone(),
                        func.return_ty.clone(),
                    ));
                }
                if func.is_constructor {
                    contract_constructors.insert(name.clone(), func.params.clone());
                }
            }
            if !pub_fns.is_empty() {
                contract_functions.insert(name.clone(), pub_fns);
            }

            let abi = otic::abi::generate_abi(&ir);
            let artifact_json = otic::abi::artifact_to_json(&abi, contract);

            // Write artifact
            let artifact_path = out_dir.join(format!("{}.json", name));
            fs::write(&artifact_path, &artifact_json)
                .map_err(|e| format!("cannot write {}: {}", artifact_path.display(), e))?;

            // Register in compiled_registry for cross-file references
            let clen = contract.constructor_bytecode.len() as u32;
            let rlen = contract.runtime_bytecode.len() as u32;
            let mut deploy_bytes = Vec::with_capacity(8 + clen as usize + rlen as usize);
            deploy_bytes.extend_from_slice(&clen.to_le_bytes());
            deploy_bytes.extend_from_slice(&rlen.to_le_bytes());
            deploy_bytes.extend_from_slice(&contract.constructor_bytecode);
            deploy_bytes.extend_from_slice(&contract.runtime_bytecode);
            compiled_registry.insert(name.clone(), deploy_bytes);

            result.total_bytecode += contract.bytecode.len();
            result
                .contracts
                .push((name.clone(), artifact_path.to_string_lossy().to_string()));

            println!(
                "  {} — {} ({} bytes, {} instructions)",
                rel.display(),
                name,
                contract.bytecode.len(),
                contract.instruction_count
            );
        }
    }

    if had_errors {
        return Err("build failed with errors".into());
    }

    // Populate result with registry and signatures
    result.compiled_registry = compiled_registry;
    result.contract_functions = contract_functions;
    result.contract_constructors = contract_constructors;

    // Save build cache
    save_cache(&cache_path, &new_cache);

    let elapsed = start.elapsed();
    println!("  compiled in {:.2}s", elapsed.as_secs_f64());

    Ok(result)
}

/// Run the otic frontend pipeline. Returns Err with formatted diagnostics on failure.
fn run_frontend(path: &Path, source: &str) -> Result<(), String> {
    let path_str = path.to_string_lossy();
    let mut diagnostics = Vec::new();

    let (tokens, lex_errors) = otic::lexer::Lexer::new(source).tokenize();
    for err in &lex_errors {
        diagnostics.push(otic::diagnostic::Diagnostic {
            level: otic::diagnostic::Level::Error,
            message: err.message.clone(),
            file: path_str.to_string(),
            line: err.line,
            col: err.col,
        });
    }
    if !diagnostics.is_empty() {
        return Err(otic::diagnostic::format_diagnostics(&diagnostics, source));
    }

    let (file, parse_errors) = otic::parser::Parser::new(tokens).parse();
    for err in &parse_errors {
        diagnostics.push(otic::diagnostic::Diagnostic {
            level: otic::diagnostic::Level::Error,
            message: err.message.clone(),
            file: path_str.to_string(),
            line: err.span.line,
            col: err.span.col,
        });
    }
    if !diagnostics.is_empty() {
        return Err(otic::diagnostic::format_diagnostics(&diagnostics, source));
    }

    let resolve_result = otic::resolve::Resolver::new().resolve(&file);
    for err in &resolve_result.errors {
        diagnostics.push(otic::diagnostic::Diagnostic {
            level: otic::diagnostic::Level::Error,
            message: err.message.clone(),
            file: path_str.to_string(),
            line: err.span.line,
            col: err.span.col,
        });
    }
    if !diagnostics.is_empty() {
        return Err(otic::diagnostic::format_diagnostics(&diagnostics, source));
    }

    let tc_result = otic::typecheck::TypeChecker::new().check(&file);
    for err in &tc_result.errors {
        diagnostics.push(otic::diagnostic::Diagnostic {
            level: otic::diagnostic::Level::Error,
            message: err.message.clone(),
            file: path_str.to_string(),
            line: err.span.line,
            col: err.span.col,
        });
    }
    if !diagnostics.is_empty() {
        return Err(otic::diagnostic::format_diagnostics(&diagnostics, source));
    }

    let safety_result = otic::safety::SafetyChecker::new().check(&file);
    for err in &safety_result.errors {
        diagnostics.push(otic::diagnostic::Diagnostic {
            level: otic::diagnostic::Level::Error,
            message: err.message.clone(),
            file: path_str.to_string(),
            line: err.span.line,
            col: err.span.col,
        });
    }
    if !diagnostics.is_empty() {
        return Err(otic::diagnostic::format_diagnostics(&diagnostics, source));
    }

    Ok(())
}

/// Build dependency graph: for each source file, find which other project files it imports.
/// Returns adjacency list: file_index → Vec<dependency_file_index>
fn build_dependency_graph(
    sources: &[(PathBuf, String, String)],
    src_dir: &Path,
) -> Result<Vec<Vec<usize>>, String> {
    // Map module paths to file indices.
    // Supports both flat (counter → src/counter.oti) and nested (events/event → src/events/event.oti).
    let mut name_to_idx: HashMap<String, usize> = HashMap::new();
    for (idx, (path, _, _)) in sources.iter().enumerate() {
        // Register by file stem (flat: "counter")
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            name_to_idx.insert(stem.to_string(), idx);
        }
        // Register by relative path from src/ without extension (nested: "events/event")
        if let Ok(rel) = path.strip_prefix(src_dir) {
            let rel_no_ext = rel.with_extension("");
            if let Some(rel_str) = rel_no_ext.to_str() {
                // Normalize path separators to forward slash
                let normalized = rel_str.replace('\\', "/");
                name_to_idx.insert(normalized, idx);
            }
        }
    }

    let mut graph: Vec<Vec<usize>> = vec![Vec::new(); sources.len()];

    for (idx, (path, source, _)) in sources.iter().enumerate() {
        let (tokens, _) = otic::lexer::Lexer::new(source).tokenize();
        let (file, _) = otic::parser::Parser::new(tokens).parse();

        for item in &file.items {
            if let otic::ast::Item::Use(import) = item {
                if !import.path.is_empty() && import.path[0].name == "std" {
                    continue;
                }

                // Build the module path from import segments.
                // For grouped imports (items non-empty), ALL path segments are module path.
                // For non-grouped, all segments except the last (item name) are module path.
                let module_segments = if !import.items.is_empty() {
                    // use events::event::{Deposit, Minted} → module = "events/event"
                    import
                        .path
                        .iter()
                        .map(|p| p.name.as_str())
                        .collect::<Vec<_>>()
                } else if import.path.len() >= 2 {
                    // use events::event::Deposit → module = "events/event"
                    import.path[..import.path.len() - 1]
                        .iter()
                        .map(|p| p.name.as_str())
                        .collect::<Vec<_>>()
                } else {
                    import
                        .path
                        .iter()
                        .map(|p| p.name.as_str())
                        .collect::<Vec<_>>()
                };

                let module_path = module_segments.join("/");

                if let Some(&dep_idx) = name_to_idx.get(&module_path) {
                    if dep_idx != idx && !graph[idx].contains(&dep_idx) {
                        graph[idx].push(dep_idx);
                    }
                } else if !module_path.is_empty() {
                    // Also try just the last segment (flat layout: counter.oti at src root)
                    let last_segment = module_segments.last().copied().unwrap_or("");
                    if let Some(&dep_idx) = name_to_idx.get(last_segment) {
                        if dep_idx != idx && !graph[idx].contains(&dep_idx) {
                            graph[idx].push(dep_idx);
                        }
                    } else {
                        let rel = path.strip_prefix(src_dir).unwrap_or(path);
                        return Err(format!(
                            "error in {}: cannot resolve import '{}' — no {}.oti found in src/",
                            rel.display(),
                            import
                                .path
                                .iter()
                                .map(|p| p.name.as_str())
                                .collect::<Vec<_>>()
                                .join("::"),
                            module_path,
                        ));
                    }
                }
            }
        }
    }

    Ok(graph)
}

/// Topological sort using Kahn's algorithm. Returns compile order. Errors on cycles.
fn topological_sort(
    graph: &[Vec<usize>],
    sources: &[(PathBuf, String, String)],
) -> Result<Vec<usize>, String> {
    let n = graph.len();
    let mut in_degree = vec![0u32; n];
    for deps in graph {
        for &dep in deps {
            in_degree[dep] += 1;
        }
    }

    // Wait — in_degree should count how many files depend on each file.
    // Actually for topological sort: if A depends on B, edge is A→B.
    // We want B compiled before A. So reverse: edge B←A means B has in_degree from A.
    // Let's recompute: in_degree[i] = number of files that i depends on (not reverse).
    // Actually Kahn's: if A→B means "A depends on B", then we want B first.
    // Standard: in_degree[node] = number of edges pointing TO node.
    // Our graph[A] = [B] means "A depends on B", so edge A→B.
    // For Kahn's on a DAG where we want dependencies first:
    // Reverse the edges: if A depends on B, then B→A in reverse graph.
    // in_degree of A in reverse = number of dependencies of A.
    // Nodes with in_degree 0 in reverse = no dependencies, compile first.

    let mut reverse_in_degree = vec![0u32; n];
    for (node, deps) in graph.iter().enumerate() {
        reverse_in_degree[node] = deps.len() as u32;
    }

    let mut queue: VecDeque<usize> = VecDeque::new();
    for i in 0..n {
        if reverse_in_degree[i] == 0 {
            queue.push_back(i);
        }
    }

    // Build reverse adjacency: if A depends on B, then B's dependents include A
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (node, deps) in graph.iter().enumerate() {
        for &dep in deps {
            dependents[dep].push(node);
        }
    }

    let mut order = Vec::with_capacity(n);
    while let Some(node) = queue.pop_front() {
        order.push(node);
        for &dependent in &dependents[node] {
            reverse_in_degree[dependent] -= 1;
            if reverse_in_degree[dependent] == 0 {
                queue.push_back(dependent);
            }
        }
    }

    if order.len() != n {
        // Cycle detected — find the cycle for a nice error message
        let in_cycle: Vec<&Path> = (0..n)
            .filter(|i| reverse_in_degree[*i] > 0)
            .map(|i| sources[i].0.as_path())
            .collect();
        let names: Vec<String> = in_cycle
            .iter()
            .map(|p| {
                p.file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        return Err(format!(
            "circular import detected between: {}",
            names.join(" <-> ")
        ));
    }

    Ok(order)
}

/// Mark all transitive dependents of a changed file as needing rebuild.
fn mark_dependents(
    graph: &[Vec<usize>],
    changed: usize,
    needs_rebuild: &mut HashSet<usize>,
    n: usize,
) {
    // Build reverse: who depends on `changed`?
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (node, deps) in graph.iter().enumerate() {
        for &dep in deps {
            dependents[dep].push(node);
        }
    }

    let mut queue = VecDeque::new();
    queue.push_back(changed);
    while let Some(node) = queue.pop_front() {
        for &dep in &dependents[node] {
            if needs_rebuild.insert(dep) {
                queue.push_back(dep);
            }
        }
    }
}

/// Load existing artifacts for unchanged files to populate the compiled_registry.
/// Also extracts function signatures from source for typed dispatch.
fn load_existing_artifacts(
    out_dir: &Path,
    source: &str,
    registry: &mut HashMap<String, Vec<u8>>,
    contract_functions: &mut HashMap<String, Vec<FnSig>>,
    contract_constructors: &mut HashMap<String, Vec<(String, otic::types::Ty)>>,
    result: &mut BuildResult,
) {
    // Quick parse to find contract names and extract signatures
    let (tokens, _) = otic::lexer::Lexer::new(source).tokenize();
    let (file, _) = otic::parser::Parser::new(tokens).parse();

    for item in &file.items {
        if let otic::ast::Item::Contract(c) = item {
            let name = &c.name.name;

            // Extract function signatures from AST (no IR needed)
            let ir = otic::lower::lower(&{
                let mut single = otic::ast::SourceFile { items: Vec::new() };
                for it in &file.items {
                    match it {
                        otic::ast::Item::Contract(cc) if cc.name.name == *name => {
                            single.items.push(it.clone())
                        }
                        otic::ast::Item::Contract(_) => {}
                        _ => single.items.push(it.clone()),
                    }
                }
                single
            });
            let mut pub_fns: Vec<FnSig> = Vec::new();
            for func in &ir.functions {
                if func.is_pub && !func.is_constructor && !func.is_test {
                    pub_fns.push((
                        func.name.clone(),
                        func.params.clone(),
                        func.return_ty.clone(),
                    ));
                }
                if func.is_constructor {
                    contract_constructors.insert(name.clone(), func.params.clone());
                }
            }
            if !pub_fns.is_empty() {
                contract_functions.insert(name.clone(), pub_fns);
            }

            let artifact_path = out_dir.join(format!("{}.json", name));
            if artifact_path.exists() {
                if let Ok(json_str) = fs::read_to_string(&artifact_path) {
                    // Parse constructor + deployed bytecode from artifact
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        let c_hex = val
                            .get("constructorBytecode")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0x")
                            .trim_start_matches("0x");
                        let r_hex = val
                            .get("deployedBytecode")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0x")
                            .trim_start_matches("0x");

                        if let (Ok(c_bytes), Ok(r_bytes)) = (hex::decode(c_hex), hex::decode(r_hex))
                        {
                            let clen = c_bytes.len() as u32;
                            let rlen = r_bytes.len() as u32;
                            let mut deploy = Vec::with_capacity(8 + clen as usize + rlen as usize);
                            deploy.extend_from_slice(&clen.to_le_bytes());
                            deploy.extend_from_slice(&rlen.to_le_bytes());
                            deploy.extend_from_slice(&c_bytes);
                            deploy.extend_from_slice(&r_bytes);
                            registry.insert(name.clone(), deploy);

                            result
                                .contracts
                                .push((name.clone(), artifact_path.to_string_lossy().to_string()));
                            result.total_bytecode += c_bytes.len() + r_bytes.len();

                            // Print skip message
                            println!("  {} — unchanged, skipped", name);
                        }
                    }
                }
            }
        }
    }
}

fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

fn load_cache(path: &Path) -> BuildCache {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_cache(path: &Path, cache: &BuildCache) {
    if let Ok(json) = serde_json::to_string_pretty(cache) {
        let _ = fs::write(path, json);
    }
}
