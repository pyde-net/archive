//! Network configuration and connection management.

use std::time::Duration;

/// Default listening port.
pub const DEFAULT_PORT: u16 = 30303;

/// Maximum number of peer connections.
pub const DEFAULT_MAX_PEERS: usize = 50;

/// Maximum number of inbound connections.
pub const DEFAULT_MAX_INBOUND: usize = 30;

/// Maximum number of outbound connections.
pub const DEFAULT_MAX_OUTBOUND: usize = 20;

/// Connection idle timeout.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Rate limit: max inbound connections per second per IP.
pub const DEFAULT_RATE_LIMIT_PER_IP: u32 = 5;

/// Network configuration.
#[derive(Clone, Debug)]
pub struct NetworkConfig {
    /// Port to listen on.
    pub port: u16,
    /// Maximum total peer connections.
    pub max_peers: usize,
    /// Maximum inbound connections.
    pub max_inbound: usize,
    /// Maximum outbound connections.
    pub max_outbound: usize,
    /// Connection idle timeout.
    pub idle_timeout: Duration,
    /// Rate limit per IP (connections per second).
    pub rate_limit_per_ip: u32,
    /// Bootstrap peer addresses.
    pub bootstrap_peers: Vec<String>,
    /// Whether this node is a validator.
    pub is_validator: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            max_peers: DEFAULT_MAX_PEERS,
            max_inbound: DEFAULT_MAX_INBOUND,
            max_outbound: DEFAULT_MAX_OUTBOUND,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            rate_limit_per_ip: DEFAULT_RATE_LIMIT_PER_IP,
            bootstrap_peers: Vec::new(),
            is_validator: false,
        }
    }
}

impl NetworkConfig {
    /// Create a validator node config.
    pub fn validator(port: u16) -> Self {
        Self {
            port,
            is_validator: true,
            ..Default::default()
        }
    }

    /// Create a full node config (non-validator).
    pub fn full_node(port: u16) -> Self {
        Self {
            port,
            is_validator: false,
            ..Default::default()
        }
    }

    /// Add bootstrap peers.
    pub fn with_bootstrap(mut self, peers: Vec<String>) -> Self {
        self.bootstrap_peers = peers;
        self
    }
}
