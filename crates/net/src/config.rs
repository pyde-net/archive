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
///
/// Audit 234 part 4 step 7p: effectively disabled (matches ethlambda's
/// `idle_connection_timeout = u64::MAX`). Earlier we lowered this to
/// 5s and 15s in attempts to drop stale post-restart QUIC connections
/// faster — both regressed the system because legitimate connections
/// have idle gaps during normal operation (gossipsub heartbeat is
/// 400ms but RPC traffic is bursty, and connections spend most of
/// their time idle between bursts). The proper layer for stale-peer
/// detection is the reactive `DisconnectStalePeer` on RR
/// OutboundFailure (1.5s timeout), not the swarm-level idle timer.
/// ethlambda runs production devnets with this disabled and we follow
/// their precedent.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60); // 1 hour, effectively disabled

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
    /// Audit 340: chain_id baked into the libp2p `identify`
    /// protocol-version string so peers from a different chain
    /// can be detected and dropped at handshake time. Pre-fix
    /// the protocol version was the static "/pyde/1.0.0" so a
    /// node from chain 12345 happily handshook with a node from
    /// chain 7331 — both passed the libp2p identity check, slot
    /// into Kademlia, and exchanged gossipsub topic
    /// subscriptions before any application-layer message
    /// revealed the chain mismatch. Post-fix the protocol
    /// version is `/pyde/1.0.0/<chain_id>` and the
    /// `IdentifyEvent::Received` handler disconnects on
    /// mismatch.
    pub chain_id: u64,
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
            // Default to devnet chain_id; production callers
            // ALWAYS set this from `[node].chain_id` in
            // config.toml.
            chain_id: 31337,
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
