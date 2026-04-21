use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Deserialize, Serialize, Debug)]
pub struct ProjectConfig {
    pub project: ProjectSection,
    #[serde(default)]
    pub compiler: CompilerSection,
    #[serde(default)]
    pub testing: TestSection,
    #[serde(default)]
    pub networks: HashMap<String, NetworkConfig>,
    #[serde(default)]
    pub dependencies: HashMap<String, Dependency>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Dependency {
    pub git: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(default)]
#[derive(Default)]
pub struct TestSection {
    /// Default verbosity for execution traces (0=silent, 1=calls, 2=storage, 3=full).
    /// CLI -v flag overrides this.
    pub verbosity: u8,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ProjectSection {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub authors: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct CompilerSection {
    #[serde(default = "default_true")]
    pub optimize: bool,
    #[serde(default = "default_src")]
    pub src: String,
    #[serde(default = "default_test")]
    pub test: String,
    #[serde(default = "default_out")]
    pub out: String,
}

impl Default for CompilerSection {
    fn default() -> Self {
        Self {
            optimize: true,
            src: "src".into(),
            test: "test".into(),
            out: "out".into(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct NetworkConfig {
    pub rpc_url: String,
    pub chain_id: u64,
}

fn default_true() -> bool {
    true
}
fn default_src() -> String {
    "src".into()
}
fn default_test() -> String {
    "test".into()
}
fn default_out() -> String {
    "out".into()
}

/// Find pyde.toml by walking up from the current directory.
/// Returns (config, project_root_dir).
pub fn load_config() -> Result<(ProjectConfig, PathBuf), String> {
    let mut dir =
        std::env::current_dir().map_err(|e| format!("cannot read current directory: {}", e))?;

    loop {
        let config_path = dir.join("pyde.toml");
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)
                .map_err(|e| format!("cannot read {}: {}", config_path.display(), e))?;
            let config: ProjectConfig =
                toml::from_str(&content).map_err(|e| format!("invalid pyde.toml: {}", e))?;
            return Ok((config, dir));
        }
        if !dir.pop() {
            return Err("no pyde.toml found (run `pyde-dev init` to create a project)".into());
        }
    }
}

/// Load a pyde.toml from a specific path (e.g., an installed package's config).
/// Returns None if the file doesn't exist.
pub fn load_config_from(toml_path: &std::path::Path) -> Result<Option<ProjectConfig>, String> {
    if !toml_path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(toml_path)
        .map_err(|e| format!("cannot read {}: {}", toml_path.display(), e))?;
    let config: ProjectConfig =
        toml::from_str(&content).map_err(|e| format!("invalid {}: {}", toml_path.display(), e))?;
    Ok(Some(config))
}

/// Parse a `path:ContractName` specifier. Returns (contract_name, optional_source_path).
/// Formats: `Counter`, `src/Counter.oti:Counter`, `src/v2/Counter.oti:Counter`.
pub fn parse_contract_specifier(spec: &str) -> (String, Option<String>) {
    if let Some(colon) = spec.rfind(':') {
        let path = &spec[..colon];
        let name = &spec[colon + 1..];
        if !name.is_empty() && !path.is_empty() {
            return (name.to_string(), Some(path.to_string()));
        }
    }
    // No colon or malformed — treat entire string as contract name
    (spec.to_string(), None)
}

/// Resolve a contract specifier to an artifact path in the output directory.
/// If `spec` is None, auto-detects (errors if ambiguous).
/// If `spec` is `path:Name`, compiles the specific file and uses that artifact.
/// If `spec` is just `Name`, looks for `Name.json` in out/.
pub fn resolve_artifact(
    out_dir: &std::path::Path,
    spec: Option<&str>,
) -> Result<(std::path::PathBuf, String), String> {
    if let Some(s) = spec {
        let (name, _source_path) = parse_contract_specifier(s);
        // Look for artifact by contract name
        let p = out_dir.join(format!("{}.json", name));
        if p.exists() {
            return Ok((p, name));
        }
        return Err(format!(
            "artifact not found: {} (run `pyde-dev build` first)",
            p.display()
        ));
    }

    // Auto-detect: find .json artifacts in out/ (skip cache)
    let mut artifacts: Vec<std::path::PathBuf> =
        glob::glob(&format!("{}/*.json", out_dir.display()))
            .map_err(|e| format!("glob error: {}", e))?
            .filter_map(|r| r.ok())
            .filter(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy() != ".build-cache.json")
                    .unwrap_or(false)
            })
            .collect();

    if artifacts.is_empty() {
        return Err("no compiled artifacts found — run `pyde-dev build` first".into());
    }
    if artifacts.len() > 1 {
        let names: Vec<String> = artifacts
            .iter()
            .filter_map(|p| p.file_stem().map(|s| s.to_string_lossy().to_string()))
            .collect();
        return Err(format!(
            "multiple contracts found: {}. Specify with path:ContractName",
            names.join(", ")
        ));
    }
    let path = artifacts.remove(0);
    let name = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    Ok((path, name))
}

/// Generate a default pyde.toml string for a new project.
pub fn default_toml(name: &str) -> String {
    format!(
        r#"[project]
name = "{}"
version = "0.1.0"
authors = []

[compiler]
optimize = true
src = "src"
test = "test"
out = "out"

[testing]
verbosity = 0    # 0=silent, 1=calls, 2=storage, 3=full traces

[networks.devnet]
rpc_url = "http://127.0.0.1:8545"
chain_id = 31337
"#,
        name
    )
}

/// Get the RPC URL for a network from pyde.toml.
/// Falls back to default localhost if config can't be loaded.
pub fn get_rpc_url(network: &str) -> Result<String, String> {
    let (config, _) = load_config()?;
    let net = config
        .networks
        .get(network)
        .ok_or_else(|| format!("network '{}' not found in pyde.toml", network))?;
    Ok(net.rpc_url.clone())
}
