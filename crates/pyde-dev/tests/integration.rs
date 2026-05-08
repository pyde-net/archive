//! Integration tests for pyde-dev: project lifecycle, incremental builds, E2E workflow.

use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Create a minimal project in a temp directory.
fn setup_project(dir: &Path) {
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::create_dir_all(dir.join("test")).unwrap();
    fs::create_dir_all(dir.join("out")).unwrap();

    fs::write(
        dir.join("pyde.toml"),
        r#"
[project]
name = "test-project"
version = "0.1.0"

[compiler]
optimize = true
src = "src"
test = "test"
out = "out"
"#,
    )
    .unwrap();

    fs::write(
        dir.join("src/counter.oti"),
        r#"contract Counter {
    storage { count: u64, }

    #[constructor]
    pub fn init() {
        self.count = 0;
    }

    pub fn get_count() -> u64 {
        return self.count;
    }

    pub fn increment() {
        self.count = self.count + 1;
    }
}
"#,
    )
    .unwrap();
}

fn load_config(dir: &Path) -> pyde_dev::project::ProjectConfig {
    let content = fs::read_to_string(dir.join("pyde.toml")).unwrap();
    toml::from_str(&content).unwrap()
}

// ============================================================================
// Task 0893: Incremental build skips unchanged files
// ============================================================================

#[test]
fn incremental_build_skips_unchanged() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    setup_project(root);
    let config = load_config(root);

    // First build: compiles everything
    let result1 = pyde_dev::build::build_project(&config, root).unwrap();
    assert!(
        !result1.contracts.is_empty(),
        "first build should produce contracts"
    );
    let artifact = root.join("out/Counter.json");
    assert!(artifact.exists(), "artifact should exist after first build");
    let first_mtime = fs::metadata(&artifact).unwrap().modified().unwrap();

    // Second build (no changes): should skip
    // The build cache tracks SHA-256 hashes. Same source → same hash → skip.
    let result2 = pyde_dev::build::build_project(&config, root).unwrap();
    // Both builds succeed, but second should report contracts from cache
    assert!(!result2.contracts.is_empty());

    // Artifact mtime unchanged (file not rewritten)
    let second_mtime = fs::metadata(&artifact).unwrap().modified().unwrap();
    assert_eq!(
        first_mtime, second_mtime,
        "artifact should not be rewritten for unchanged source"
    );
}

#[test]
fn incremental_build_recompiles_on_change() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    setup_project(root);
    let config = load_config(root);

    // First build
    let result1 = pyde_dev::build::build_project(&config, root).unwrap();
    assert!(!result1.contracts.is_empty());
    let artifact = root.join("out/Counter.json");
    let first_content = fs::read_to_string(&artifact).unwrap();

    // Modify source
    fs::write(
        root.join("src/counter.oti"),
        r#"contract Counter {
    storage { count: u64, }

    #[constructor]
    pub fn init() {
        self.count = 100;
    }

    pub fn get_count() -> u64 {
        return self.count;
    }

    pub fn increment() {
        self.count = self.count + 1;
    }
}
"#,
    )
    .unwrap();

    // Second build: source changed → recompile
    let result2 = pyde_dev::build::build_project(&config, root).unwrap();
    assert!(!result2.contracts.is_empty());
    let second_content = fs::read_to_string(&artifact).unwrap();

    // Artifact should have different content (constructor changed)
    assert_ne!(
        first_content, second_content,
        "artifact should change when source changes"
    );
}

// ============================================================================
// Task 0891: End-to-end init → build → test → deploy
// ============================================================================

#[test]
fn e2e_init_build() {
    let tmp = TempDir::new().unwrap();
    let project_dir = tmp.path().join("myproject");

    // Init
    pyde_dev::init::run(project_dir.to_str().unwrap()).unwrap();

    // Verify structure
    assert!(project_dir.join("pyde.toml").exists());
    assert!(project_dir.join("src/Counter.oti").exists());
    assert!(project_dir.join("test/Counter.test.oti").exists());
    assert!(project_dir.join("lib/@std/vm.oti").exists());
    assert!(project_dir.join("lib/@std/token.oti").exists());
    assert!(project_dir.join("lib/@std/math.oti").exists());

    // Build
    let config = load_config(&project_dir);
    let result = pyde_dev::build::build_project(&config, &project_dir).unwrap();
    assert!(
        !result.contracts.is_empty(),
        "build should produce at least one contract"
    );
    assert!(
        result.total_bytecode > 0,
        "bytecode size should be non-zero"
    );
    assert!(
        project_dir.join("out/Counter.json").exists(),
        "artifact should exist"
    );

    // Verify artifact has expected fields
    let artifact_json = fs::read_to_string(project_dir.join("out/Counter.json")).unwrap();
    let artifact: serde_json::Value = serde_json::from_str(&artifact_json).unwrap();
    assert!(artifact.get("contractName").is_some());
    assert!(artifact.get("abi").is_some());
    assert!(artifact.get("deployedBytecode").is_some());
    assert!(artifact.get("constructorBytecode").is_some());
}

/// TPL-411: cross-file imports are checked against the populated
/// module-export table. Pre-fix, `build_project` shadowed the
/// populated `module_exports` with an empty `HashMap::new()`
/// before invoking `run_frontend`, so the resolver's
/// `is_known_module` always returned false and bogus imports
/// silently compiled. This test would have passed on broken code
/// (build succeeds despite a bad import) — post-fix it correctly
/// fails the build.
#[test]
fn tpl_411_strict_frontend_rejects_undeclared_cross_file_import() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("test")).unwrap();
    fs::create_dir_all(root.join("out")).unwrap();
    fs::write(
        root.join("pyde.toml"),
        r#"
[project]
name = "tpl-411-test"
version = "0.1.0"

[compiler]
optimize = false
src = "src"
test = "test"
out = "out"
"#,
    )
    .unwrap();

    // Module that exports exactly one contract.
    fs::write(
        root.join("src/exporter.oti"),
        r#"contract Exported {
    storage { x: u64, }

    #[constructor]
    pub fn init() {
        self.x = 0;
    }
}
"#,
    )
    .unwrap();

    // Module that imports a name the exporter does NOT export.
    // Pre-fix the resolver's `is_known_module(exporter)` returned
    // false (empty map) so the cross-export check was skipped and
    // build_project returned Ok. Post-fix the populated map flags
    // `DoesNotExist` as unexported and surfaces a build error.
    fs::write(
        root.join("src/importer.oti"),
        r#"use exporter::DoesNotExist;

contract Importer {
    storage { x: u64, }

    #[constructor]
    pub fn init() {
        self.x = 0;
    }
}
"#,
    )
    .unwrap();

    let config = load_config(root);
    let result = pyde_dev::build::build_project(&config, root);
    assert!(
        result.is_err(),
        "build_project must reject the bogus cross-file import; got {:?}",
        result.as_ref().map(|_| "Ok")
    );
}

#[test]
fn e2e_build_produces_registry() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    setup_project(root);
    let config = load_config(root);

    let result = pyde_dev::build::build_project(&config, root).unwrap();

    // Registry should contain the Counter contract
    assert!(
        result.compiled_registry.contains_key("Counter"),
        "registry should contain Counter bytecode"
    );

    // Function signatures should be extracted
    assert!(
        result.contract_functions.contains_key("Counter"),
        "contract_functions should contain Counter"
    );
    let fns = &result.contract_functions["Counter"];
    let fn_names: Vec<&str> = fns.iter().map(|(n, _, _)| n.as_str()).collect();
    assert!(fn_names.contains(&"get_count"), "should have get_count");
    assert!(fn_names.contains(&"increment"), "should have increment");

    // Constructor should be extracted
    assert!(
        result.contract_constructors.contains_key("Counter"),
        "should have Counter constructor"
    );
}
