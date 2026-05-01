//! Peer discovery via Kademlia DHT and bootstrap nodes.
//!
//! Discovery flow:
//! 1. Node starts with a list of bootstrap peers (hardcoded or configured)
//! 2. Connects to bootstrap peers and joins the Kademlia DHT
//! 3. Performs random walks to discover more peers
//! 4. Maintains a set of known peers for reconnection

use libp2p::{Multiaddr, PeerId};
use std::collections::HashMap;
use std::time::Instant;

/// Pyde mainnet chain ID. Bound into every consensus signing
/// preimage (proposer headers, votes, view-change votes, slashing
/// evidence, multisig payloads) so a signature on one network
/// cannot be replayed on another even when FALCON keys match.
pub const MAINNET_CHAIN_ID: u64 = 1;

/// Pyde public testnet chain ID. Distinct from devnet (`31337`)
/// and mainnet (`1`). Operators bringing up alternative testnets
/// should pick a different value to avoid replay collisions —
/// the on-chain bootstrap-peer hard gate
/// (`pyde_node::node::check_bootstrap_config`) only allows
/// startup with explicit `bootstrap_peers` for any non-devnet
/// chain, so a typo'd chain id can't silently produce a fork
/// of one.
pub const TESTNET_CHAIN_ID: u64 = 7331;

/// Devnet chain ID. The only chain id at which a node may start
/// with no bootstrap peers configured (laptop-local single-node
/// devnets are an explicit, intentional configuration).
pub const DEVNET_CHAIN_ID: u64 = 31337;

/// Default bootstrap peers for mainnet (empty until launch).
pub const MAINNET_BOOTSTRAP: &[&str] = &[];

/// Default bootstrap peers for testnet. Empty here so the binary
/// has no compile-time dependency on cloud DNS — operators inject
/// their actual `[network].bootstrap_peers` via `config.toml` (the
/// `pyde testnet --node-addrs <topology.toml>` flow does this
/// automatically). The startup-time
/// `check_bootstrap_config(chain_id, &bootstrap_peers)` gate hard-
/// refuses any non-devnet chain that launches with this list still
/// empty, so an operator who skips the inject step gets a clear
/// error instead of a silent fork-of-one.
pub const TESTNET_BOOTSTRAP: &[&str] = &[];

/// Ban duration in seconds.
pub const DEFAULT_BAN_DURATION_SECS: u64 = 3600; // 1 hour

/// Ban reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BanReason {
    /// Sent invalid consensus messages.
    InvalidConsensusMessage,
    /// Sent invalid or malformed transactions.
    InvalidTransaction,
    /// Exceeded rate limits repeatedly.
    RateLimitAbuse,
    /// Protocol violation (wrong message format, etc.).
    ProtocolViolation,
    /// Manual ban by operator.
    Manual(String),
}

/// A banned peer entry.
#[derive(Clone, Debug)]
pub struct BanEntry {
    pub peer_id: PeerId,
    pub reason: BanReason,
    pub banned_at: Instant,
    pub duration_secs: u64,
}

impl BanEntry {
    /// Whether the ban has expired.
    pub fn is_expired(&self) -> bool {
        self.banned_at.elapsed().as_secs() >= self.duration_secs
    }
}

/// Known peer with address and discovery metadata.
#[derive(Clone, Debug)]
pub struct KnownPeer {
    pub peer_id: PeerId,
    pub addresses: Vec<Multiaddr>,
    pub last_seen: Instant,
    pub connection_failures: u32,
}

/// Peer discovery and ban management.
#[derive(Debug)]
pub struct Discovery {
    /// Bootstrap peer addresses.
    bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    /// Known peers discovered via DHT.
    known_peers: HashMap<PeerId, KnownPeer>,
    /// Banned peers.
    banned: HashMap<PeerId, BanEntry>,
    /// Ban duration in seconds.
    ban_duration: u64,
}

impl Discovery {
    pub fn new() -> Self {
        Self {
            bootstrap_peers: Vec::new(),
            known_peers: HashMap::new(),
            banned: HashMap::new(),
            ban_duration: DEFAULT_BAN_DURATION_SECS,
        }
    }

    /// Add bootstrap peers from multiaddr strings.
    pub fn add_bootstrap_peers(&mut self, addrs: &[String]) {
        for addr_str in addrs {
            if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                // Extract PeerId from the multiaddr if present
                if let Some(peer_id) = extract_peer_id(&addr) {
                    self.bootstrap_peers.push((peer_id, addr));
                }
            }
        }
    }

    /// Get bootstrap peers for initial connection.
    pub fn bootstrap_peers(&self) -> &[(PeerId, Multiaddr)] {
        &self.bootstrap_peers
    }

    /// Record a discovered peer from DHT or gossip.
    pub fn add_known_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        if self.is_banned(&peer_id) {
            return; // don't track banned peers
        }

        let entry = self
            .known_peers
            .entry(peer_id)
            .or_insert_with(|| KnownPeer {
                peer_id,
                addresses: Vec::new(),
                last_seen: Instant::now(),
                connection_failures: 0,
            });

        entry.last_seen = Instant::now();
        if !entry.addresses.contains(&addr) {
            entry.addresses.push(addr);
        }
    }

    /// Record a failed connection attempt.
    pub fn record_failure(&mut self, peer_id: &PeerId) {
        if let Some(peer) = self.known_peers.get_mut(peer_id) {
            peer.connection_failures += 1;
        }
    }

    /// Get peers to try connecting to, sorted by reliability.
    pub fn peers_to_connect(&self, max: usize) -> Vec<&KnownPeer> {
        let mut peers: Vec<&KnownPeer> = self
            .known_peers
            .values()
            .filter(|p| !self.is_banned(&p.peer_id))
            .collect();

        // Sort by fewest failures, then most recently seen
        peers.sort_by(|a, b| {
            a.connection_failures
                .cmp(&b.connection_failures)
                .then_with(|| b.last_seen.cmp(&a.last_seen))
        });

        peers.into_iter().take(max).collect()
    }

    /// Number of known peers.
    pub fn known_peer_count(&self) -> usize {
        self.known_peers.len()
    }

    // ========== Banning ==========

    /// Ban a peer.
    pub fn ban_peer(&mut self, peer_id: PeerId, reason: BanReason) {
        self.banned.insert(
            peer_id,
            BanEntry {
                peer_id,
                reason,
                banned_at: Instant::now(),
                duration_secs: self.ban_duration,
            },
        );
        // Remove from known peers
        self.known_peers.remove(&peer_id);
    }

    /// Ban a peer with a custom duration.
    pub fn ban_peer_for(&mut self, peer_id: PeerId, reason: BanReason, duration_secs: u64) {
        self.banned.insert(
            peer_id,
            BanEntry {
                peer_id,
                reason,
                banned_at: Instant::now(),
                duration_secs,
            },
        );
        self.known_peers.remove(&peer_id);
    }

    /// Check if a peer is currently banned.
    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        if let Some(entry) = self.banned.get(peer_id) {
            !entry.is_expired()
        } else {
            false
        }
    }

    /// Unban a peer manually.
    pub fn unban_peer(&mut self, peer_id: &PeerId) {
        self.banned.remove(peer_id);
    }

    /// Remove expired bans.
    pub fn prune_expired_bans(&mut self) {
        self.banned.retain(|_, entry| !entry.is_expired());
    }

    /// Number of currently banned peers.
    pub fn banned_count(&self) -> usize {
        self.banned.values().filter(|e| !e.is_expired()).count()
    }

    /// Get all banned peer IDs.
    pub fn banned_peers(&self) -> Vec<PeerId> {
        self.banned
            .iter()
            .filter(|(_, e)| !e.is_expired())
            .map(|(id, _)| *id)
            .collect()
    }
}

impl Default for Discovery {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract PeerId from a multiaddr (if it ends with /p2p/<peer_id>).
fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|proto| {
        if let libp2p::multiaddr::Protocol::P2p(peer_id) = proto {
            Some(peer_id)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_peer() -> PeerId {
        PeerId::random()
    }

    fn dummy_addr() -> Multiaddr {
        "/ip4/127.0.0.1/tcp/30303".parse().unwrap()
    }

    // ========== Task 0554: Peer discovery ==========

    #[test]
    fn add_known_peer() {
        let mut disco = Discovery::new();
        let peer = random_peer();

        disco.add_known_peer(peer, dummy_addr());
        assert_eq!(disco.known_peer_count(), 1);
    }

    #[test]
    fn known_peer_dedup_addresses() {
        let mut disco = Discovery::new();
        let peer = random_peer();
        let addr = dummy_addr();

        disco.add_known_peer(peer, addr.clone());
        disco.add_known_peer(peer, addr); // same addr
        assert_eq!(disco.known_peers[&peer].addresses.len(), 1);
    }

    #[test]
    fn peers_sorted_by_reliability() {
        let mut disco = Discovery::new();
        let good = random_peer();
        let bad = random_peer();

        disco.add_known_peer(good, dummy_addr());
        disco.add_known_peer(bad, dummy_addr());
        disco.record_failure(&bad);
        disco.record_failure(&bad);

        let to_connect = disco.peers_to_connect(10);
        assert_eq!(to_connect[0].peer_id, good); // fewer failures first
    }

    // ========== Task 0555: Banned peer cannot reconnect ==========

    #[test]
    fn ban_peer() {
        let mut disco = Discovery::new();
        let peer = random_peer();

        disco.add_known_peer(peer, dummy_addr());
        assert_eq!(disco.known_peer_count(), 1);

        disco.ban_peer(peer, BanReason::ProtocolViolation);
        assert!(disco.is_banned(&peer));
        assert_eq!(disco.known_peer_count(), 0); // removed from known
        assert_eq!(disco.banned_count(), 1);
    }

    #[test]
    fn banned_peer_not_added_to_known() {
        let mut disco = Discovery::new();
        let peer = random_peer();

        disco.ban_peer(peer, BanReason::InvalidTransaction);
        disco.add_known_peer(peer, dummy_addr()); // should be ignored
        assert_eq!(disco.known_peer_count(), 0);
    }

    #[test]
    fn banned_peer_excluded_from_connect_list() {
        let mut disco = Discovery::new();
        let good = random_peer();
        let bad = random_peer();

        disco.add_known_peer(good, dummy_addr());
        disco.add_known_peer(bad, dummy_addr());
        disco.ban_peer(bad, BanReason::RateLimitAbuse);

        let to_connect = disco.peers_to_connect(10);
        assert_eq!(to_connect.len(), 1);
        assert_eq!(to_connect[0].peer_id, good);
    }

    #[test]
    fn unban_peer() {
        let mut disco = Discovery::new();
        let peer = random_peer();

        disco.ban_peer(peer, BanReason::Manual("test".into()));
        assert!(disco.is_banned(&peer));

        disco.unban_peer(&peer);
        assert!(!disco.is_banned(&peer));
    }

    #[test]
    fn ban_with_custom_duration() {
        let mut disco = Discovery::new();
        let peer = random_peer();

        // Ban for 0 seconds → immediately expired
        disco.ban_peer_for(peer, BanReason::ProtocolViolation, 0);
        assert!(!disco.is_banned(&peer)); // already expired
    }

    // ========== Bootstrap ==========

    #[test]
    fn bootstrap_peer_parsing() {
        let mut disco = Discovery::new();
        let peer = random_peer();
        let addr = format!("/ip4/1.2.3.4/tcp/30303/p2p/{}", peer);

        disco.add_bootstrap_peers(&[addr]);
        assert_eq!(disco.bootstrap_peers().len(), 1);
        assert_eq!(disco.bootstrap_peers()[0].0, peer);
    }

    #[test]
    fn invalid_bootstrap_ignored() {
        let mut disco = Discovery::new();
        disco.add_bootstrap_peers(&["not_a_valid_addr".to_string()]);
        assert_eq!(disco.bootstrap_peers().len(), 0);
    }
}
