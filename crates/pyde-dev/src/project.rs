use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Deserialize, Serialize, Debug)]
pub struct ProjectConfig {
    pub project: ProjectSection,
    #[serde(default)]
    pub compiler: CompilerSection,
    #[serde(default)]
    pub networks: HashMap<String, NetworkConfig>,
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

fn default_true() -> bool { true }
fn default_src() -> String { "src".into() }
fn default_test() -> String { "test".into() }
fn default_out() -> String { "out".into() }

/// Find pyde.toml by walking up from the current directory.
/// Returns (config, project_root_dir).
pub fn load_config() -> Result<(ProjectConfig, PathBuf), String> {
    let mut dir = std::env::current_dir()
        .map_err(|e| format!("cannot read current directory: {}", e))?;

    loop {
        let config_path = dir.join("pyde.toml");
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)
                .map_err(|e| format!("cannot read {}: {}", config_path.display(), e))?;
            let config: ProjectConfig = toml::from_str(&content)
                .map_err(|e| format!("invalid pyde.toml: {}", e))?;
            return Ok((config, dir));
        }
        if !dir.pop() {
            return Err("no pyde.toml found (run `pyde-dev init` to create a project)".into());
        }
    }
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

[networks.devnet]
rpc_url = "http://127.0.0.1:8545"
chain_id = 31337
"#,
        name
    )
}
