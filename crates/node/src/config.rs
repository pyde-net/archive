use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Top-level node configuration (loaded from TOML).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NodeConfig {
    #[serde(default)]
    pub node: NodeSection,
    #[serde(default)]
    pub network: NetworkSection,
    #[serde(default)]
    pub consensus: ConsensusSection,
    #[serde(default)]
    pub storage: StorageSection,
    #[serde(default)]
    pub rpc: RpcSection,
    #[serde(default)]
    pub fast_tx: FastTxSection,
    #[serde(default)]
    pub metrics: MetricsSection,
    #[serde(default)]
    pub logging: LoggingSection,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeSection {
    /// Node role: "validator" or "full".
    pub role: String,
    /// Chain ID.
    pub chain_id: u64,
    /// Data directory for state, keys, etc.
    pub datadir: PathBuf,
    /// Dev mode: allows unsigned pyde_sendTransaction.
    #[serde(default)]
    pub dev_mode: bool,
}

impl Default for NodeSection {
    fn default() -> Self {
        Self {
            role: "full".into(),
            chain_id: 31337,
            datadir: default_datadir(),
            dev_mode: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkSection {
    /// P2P listen port.
    pub port: u16,
    /// Maximum peer connections.
    pub max_peers: usize,
    /// Maximum inbound connections.
    pub max_inbound: usize,
    /// Maximum outbound connections.
    pub max_outbound: usize,
    /// Rate limit per IP (connections/sec).
    pub rate_limit_per_ip: u32,
    /// Bootstrap peer multiaddrs.
    pub bootstrap_peers: Vec<String>,
}

impl Default for NetworkSection {
    fn default() -> Self {
        Self {
            port: 30303,
            max_peers: 50,
            max_inbound: 30,
            max_outbound: 20,
            rate_limit_per_ip: 5,
            bootstrap_peers: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusSection {
    /// Block time target in milliseconds.
    pub block_time_ms: u64,
    /// Block gas target (sustained).
    pub gas_target: u64,
    /// Block gas ceiling (max, 4x target).
    pub gas_ceiling: u64,
    /// Weak-subjectivity bootstrap anchor (Phase 4 slice 4.3, gap 2).
    ///
    /// Initial slot that acts as a hard-finality lower bound when a node
    /// first starts and has no checkpoint persisted. Operators bootstrap
    /// a new node with a recent, trusted checkpoint slot — any incoming
    /// block at or before this slot is rejected regardless of
    /// cryptographic validity, closing the long-range-attack window
    /// that otherwise exists until the node has observed its first
    /// hard finality.
    ///
    /// `None` on networks where this is not configured (devnet) or on
    /// genesis validators who self-observe finality from epoch 1.
    /// Once the node records its own hard finality, the observed
    /// checkpoint overrides this value.
    #[serde(default)]
    pub initial_ws_checkpoint_slot: Option<u64>,
}

impl Default for ConsensusSection {
    fn default() -> Self {
        Self {
            block_time_ms: 400,
            gas_target: 400_000_000,
            gas_ceiling: 1_600_000_000,
            initial_ws_checkpoint_slot: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageSection {
    /// RocksDB path (relative to datadir).
    pub db_path: String,
    /// LRU cache size for state trie (entries).
    pub cache_size: usize,
}

impl Default for StorageSection {
    fn default() -> Self {
        Self {
            db_path: "state".into(),
            cache_size: 65_536,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcSection {
    /// Enable RPC server.
    pub enabled: bool,
    /// RPC listen address.
    pub listen: String,
    /// RPC listen port.
    pub port: u16,
}

impl Default for RpcSection {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "127.0.0.1".into(),
            port: 8545,
        }
    }
}

/// Fast binary transaction submission endpoint (no HTTP/JSON overhead).
/// Clients send raw signed tx bytes with length-prefix framing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FastTxSection {
    pub enabled: bool,
    pub listen: String,
    pub port: u16,
}

impl Default for FastTxSection {
    fn default() -> Self {
        // TPL-207: bind to loopback by default. The fast-tx listener
        // accepts length-prefixed signed transactions and submits them
        // straight into `pending_txs` + `tx_gossip_tx` without going
        // through `ingress_validate` (no `MEMPOOL_*` cap, no per-IP
        // rate-limit, no signature pre-check). The pre-fix default of
        // `0.0.0.0` exposed every `--config` deployment that didn't
        // explicitly override `[fast_tx].listen` to a public ingress
        // path that drains the validator's memory until peer-banning
        // cascades. Operators who genuinely want public fast-tx must
        // opt in via TOML.
        Self {
            enabled: true,
            listen: "127.0.0.1".into(),
            port: 9545,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricsSection {
    /// Enable Prometheus metrics endpoint.
    pub enabled: bool,
    /// Metrics listen port.
    pub port: u16,
}

impl Default for MetricsSection {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 9090,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoggingSection {
    /// Log level: trace, debug, info, warn, error.
    pub level: String,
    /// Output JSON-formatted logs.
    pub json: bool,
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            level: "info".into(),
            json: false,
        }
    }
}

impl NodeConfig {
    /// Load config from a TOML file, falling back to defaults for missing fields.
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config {}: {}", path.display(), e))?;
        toml::from_str(&content)
            .map_err(|e| format!("failed to parse config {}: {}", path.display(), e))
    }

    /// Serialize to TOML string (for --default-config).
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }

    /// Apply CLI overrides on top of file-loaded config.
    pub fn apply_cli_overrides(
        &mut self,
        role: Option<&str>,
        port: Option<u16>,
        datadir: Option<&Path>,
        log_level: Option<&str>,
        log_json: bool,
        metrics_port: Option<u16>,
        bootstrap: &[String],
    ) {
        if let Some(r) = role {
            self.node.role = r.to_string();
        }
        if let Some(p) = port {
            self.network.port = p;
        }
        if let Some(d) = datadir {
            self.node.datadir = d.to_path_buf();
        }
        if let Some(l) = log_level {
            self.logging.level = l.to_string();
        }
        if log_json {
            self.logging.json = true;
        }
        if let Some(mp) = metrics_port {
            self.metrics.port = mp;
            self.metrics.enabled = mp > 0;
        }
        if !bootstrap.is_empty() {
            self.network.bootstrap_peers = bootstrap.to_vec();
        }
    }
}

/// Default data directory: ~/.pyde/
fn default_datadir() -> PathBuf {
    directories::BaseDirs::new()
        .map(|d| d.home_dir().join(".pyde"))
        .unwrap_or_else(|| PathBuf::from(".pyde"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_serializes() {
        let config = NodeConfig::default();
        let toml_str = config.to_toml();
        assert!(toml_str.contains("role"));
        assert!(toml_str.contains("30303"));
    }

    #[test]
    fn default_config_roundtrip() {
        let config = NodeConfig::default();
        let toml_str = config.to_toml();
        let parsed: NodeConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.network.port, 30303);
        assert_eq!(parsed.node.role, "full");
    }

    #[test]
    fn cli_overrides_applied() {
        let mut config = NodeConfig::default();
        config.apply_cli_overrides(
            Some("validator"),
            Some(31337),
            None,
            Some("debug"),
            true,
            Some(9191),
            &["peer1".into()],
        );
        assert_eq!(config.node.role, "validator");
        assert_eq!(config.network.port, 31337);
        assert_eq!(config.logging.level, "debug");
        assert!(config.logging.json);
        assert_eq!(config.metrics.port, 9191);
        assert_eq!(config.network.bootstrap_peers, vec!["peer1".to_string()]);
    }

    #[test]
    fn partial_toml_fills_defaults() {
        let partial = r#"
[node]
role = "validator"
"#;
        let config: NodeConfig = toml::from_str(partial).unwrap();
        assert_eq!(config.node.role, "validator");
        assert_eq!(config.network.port, 30303); // default
        assert_eq!(config.rpc.port, 8545); // default
    }
}
