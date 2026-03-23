//! Peer identity and connection tracking.

use libp2p::PeerId;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Peer connection direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Peer role in the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRole {
    /// Validator node (participates in consensus).
    Validator,
    /// Full node (stores state, relays txs, serves RPC).
    FullNode,
    /// Prover node (generates ZK proofs).
    Prover,
    /// Light client (verifies proofs only).
    LightClient,
    /// Unknown (not yet identified).
    Unknown,
}

/// Information about a connected peer.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// libp2p peer ID.
    pub peer_id: PeerId,
    /// Connection direction.
    pub direction: Direction,
    /// Peer's role.
    pub role: PeerRole,
    /// When the connection was established.
    pub connected_at: Instant,
    /// Remote IP address.
    pub ip: Option<IpAddr>,
    /// Number of messages received from this peer.
    pub messages_received: u64,
    /// Number of invalid messages from this peer (for reputation).
    pub invalid_messages: u64,
}

impl PeerInfo {
    pub fn new(peer_id: PeerId, direction: Direction) -> Self {
        Self {
            peer_id,
            direction,
            role: PeerRole::Unknown,
            connected_at: Instant::now(),
            ip: None,
            messages_received: 0,
            invalid_messages: 0,
        }
    }

    /// Reputation score (higher = better). Simple linear scoring.
    pub fn reputation(&self) -> i64 {
        self.messages_received as i64 - (self.invalid_messages as i64 * 10)
    }
}

/// Manages connected peers and enforces limits.
#[derive(Debug)]
pub struct PeerManager {
    /// Connected peers by ID.
    peers: HashMap<PeerId, PeerInfo>,
    /// Max total peers.
    max_peers: usize,
    /// Max inbound connections.
    max_inbound: usize,
    /// Max outbound connections.
    max_outbound: usize,
    /// Rate limiter: IP → (count, window_start).
    rate_limits: HashMap<IpAddr, (u32, Instant)>,
    /// Max connections per IP per second.
    rate_limit_per_ip: u32,
}

impl PeerManager {
    pub fn new(max_peers: usize, max_inbound: usize, max_outbound: usize, rate_limit_per_ip: u32) -> Self {
        Self {
            peers: HashMap::new(),
            max_peers,
            max_inbound,
            max_outbound,
            rate_limits: HashMap::new(),
            rate_limit_per_ip,
        }
    }

    /// Number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Number of inbound connections.
    pub fn inbound_count(&self) -> usize {
        self.peers.values().filter(|p| p.direction == Direction::Inbound).count()
    }

    /// Number of outbound connections.
    pub fn outbound_count(&self) -> usize {
        self.peers.values().filter(|p| p.direction == Direction::Outbound).count()
    }

    /// Check if we can accept a new connection.
    pub fn can_accept(&self, direction: Direction, ip: Option<IpAddr>) -> bool {
        if self.peers.len() >= self.max_peers {
            return false;
        }

        match direction {
            Direction::Inbound => {
                if self.inbound_count() >= self.max_inbound {
                    return false;
                }
                // Rate limit check
                if let Some(ip) = ip {
                    if self.is_rate_limited(ip) {
                        return false;
                    }
                }
            }
            Direction::Outbound => {
                if self.outbound_count() >= self.max_outbound {
                    return false;
                }
            }
        }

        true
    }

    /// Check if an IP is rate-limited.
    fn is_rate_limited(&self, ip: IpAddr) -> bool {
        if let Some((count, window_start)) = self.rate_limits.get(&ip) {
            if window_start.elapsed().as_secs() < 1 {
                return *count >= self.rate_limit_per_ip;
            }
        }
        false
    }

    /// Record a connection attempt from an IP.
    pub fn record_connection_attempt(&mut self, ip: IpAddr) {
        let entry = self.rate_limits.entry(ip).or_insert((0, Instant::now()));
        if entry.1.elapsed().as_secs() >= 1 {
            // Reset window
            *entry = (1, Instant::now());
        } else {
            entry.0 += 1;
        }
    }

    /// Prune expired rate limit entries to prevent unbounded HashMap growth.
    /// Call this periodically (e.g., once per block or every few seconds).
    pub fn prune_rate_limits(&mut self) {
        self.rate_limits.retain(|_, (_, window_start)| window_start.elapsed().as_secs() < 60);
    }

    /// Add a connected peer. Returns false if limits exceeded.
    pub fn add_peer(&mut self, info: PeerInfo) -> bool {
        if !self.can_accept(info.direction, info.ip) {
            return false;
        }
        if let Some(ip) = info.ip {
            self.record_connection_attempt(ip);
        }
        self.peers.insert(info.peer_id, info);
        true
    }

    /// Remove a disconnected peer.
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.peers.remove(peer_id)
    }

    /// Get peer info.
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    /// Get mutable peer info.
    pub fn get_peer_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerInfo> {
        self.peers.get_mut(peer_id)
    }

    /// Get all connected peers.
    pub fn all_peers(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.values()
    }

    /// Check if a peer is connected.
    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.peers.contains_key(peer_id)
    }

    /// Get validators only.
    pub fn validators(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.values().filter(|p| p.role == PeerRole::Validator)
    }

    /// Evict the peer with lowest reputation. Returns the evicted peer ID.
    pub fn evict_lowest_reputation(&mut self) -> Option<PeerId> {
        let worst = self
            .peers
            .iter()
            .min_by_key(|(_, info)| info.reputation())
            .map(|(id, _)| *id);

        if let Some(id) = worst {
            self.peers.remove(&id);
            Some(id)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_peer(direction: Direction) -> PeerInfo {
        PeerInfo::new(PeerId::random(), direction)
    }

    fn dummy_peer_with_ip(direction: Direction, ip: IpAddr) -> PeerInfo {
        let mut info = PeerInfo::new(PeerId::random(), direction);
        info.ip = Some(ip);
        info
    }

    #[test]
    fn add_and_remove_peer() {
        let mut mgr = PeerManager::new(10, 5, 5, 5);
        let peer = dummy_peer(Direction::Inbound);
        let id = peer.peer_id;

        assert!(mgr.add_peer(peer));
        assert_eq!(mgr.peer_count(), 1);
        assert!(mgr.is_connected(&id));

        mgr.remove_peer(&id);
        assert_eq!(mgr.peer_count(), 0);
    }

    #[test]
    fn max_peers_enforced() {
        let mut mgr = PeerManager::new(2, 2, 2, 100);

        assert!(mgr.add_peer(dummy_peer(Direction::Inbound)));
        assert!(mgr.add_peer(dummy_peer(Direction::Outbound)));
        assert!(!mgr.add_peer(dummy_peer(Direction::Inbound))); // full
    }

    #[test]
    fn max_inbound_enforced() {
        let mut mgr = PeerManager::new(10, 2, 10, 100);

        assert!(mgr.add_peer(dummy_peer(Direction::Inbound)));
        assert!(mgr.add_peer(dummy_peer(Direction::Inbound)));
        assert!(!mgr.add_peer(dummy_peer(Direction::Inbound))); // inbound full
        assert!(mgr.add_peer(dummy_peer(Direction::Outbound))); // outbound ok
    }

    #[test]
    fn max_outbound_enforced() {
        let mut mgr = PeerManager::new(10, 10, 2, 100);

        assert!(mgr.add_peer(dummy_peer(Direction::Outbound)));
        assert!(mgr.add_peer(dummy_peer(Direction::Outbound)));
        assert!(!mgr.add_peer(dummy_peer(Direction::Outbound))); // outbound full
        assert!(mgr.add_peer(dummy_peer(Direction::Inbound))); // inbound ok
    }

    #[test]
    fn rate_limiting() {
        let mut mgr = PeerManager::new(100, 100, 100, 2);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // First 2 from same IP ok
        assert!(mgr.add_peer(dummy_peer_with_ip(Direction::Inbound, ip)));
        assert!(mgr.add_peer(dummy_peer_with_ip(Direction::Inbound, ip)));

        // 3rd from same IP within 1 second → rate limited
        assert!(!mgr.add_peer(dummy_peer_with_ip(Direction::Inbound, ip)));

        // Different IP ok
        let ip2: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(mgr.add_peer(dummy_peer_with_ip(Direction::Inbound, ip2)));
    }

    #[test]
    fn evict_lowest_reputation() {
        let mut mgr = PeerManager::new(10, 10, 10, 100);

        let mut bad = dummy_peer(Direction::Inbound);
        bad.invalid_messages = 100;
        let bad_id = bad.peer_id;

        let good = dummy_peer(Direction::Inbound);

        mgr.add_peer(bad);
        mgr.add_peer(good);
        assert_eq!(mgr.peer_count(), 2);

        let evicted = mgr.evict_lowest_reputation().unwrap();
        assert_eq!(evicted, bad_id);
        assert_eq!(mgr.peer_count(), 1);
    }

    #[test]
    fn reputation_scoring() {
        let mut info = dummy_peer(Direction::Inbound);
        info.messages_received = 100;
        info.invalid_messages = 5;
        assert_eq!(info.reputation(), 100 - 50); // 50

        info.invalid_messages = 0;
        assert_eq!(info.reputation(), 100);
    }

    #[test]
    fn validators_filter() {
        let mut mgr = PeerManager::new(10, 10, 10, 100);

        let mut val = dummy_peer(Direction::Inbound);
        val.role = PeerRole::Validator;
        let mut full = dummy_peer(Direction::Inbound);
        full.role = PeerRole::FullNode;

        mgr.add_peer(val);
        mgr.add_peer(full);

        assert_eq!(mgr.validators().count(), 1);
    }
}
