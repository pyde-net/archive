//! Peer identity and connection tracking.

use libp2p::{Multiaddr, PeerId};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Extract the IPv4 / IPv6 address from a libp2p `Multiaddr` if any
/// (audit 336). Walks the protocol stack and returns the first
/// `Ip4(_)` or `Ip6(_)` segment. Pre-fix `PeerInfo.ip` was always
/// left as `None` because the connection-established handler
/// constructed `PeerInfo::new` without parsing the remote address;
/// `is_rate_limited` therefore never fired and `rate_limit_per_ip`
/// silently did nothing.
pub fn ip_from_multiaddr(addr: &Multiaddr) -> Option<IpAddr> {
    use libp2p::multiaddr::Protocol;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(v4) => return Some(IpAddr::V4(v4)),
            Protocol::Ip6(v6) => return Some(IpAddr::V6(v6)),
            _ => continue,
        }
    }
    None
}

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
    /// Light client (header-only verification).
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
    /// FALCON-512 pubkey the peer attested on connect (task 029). `None`
    /// until the auth handshake completes; populated via
    /// `PeerManager::set_falcon_pubkey` after `pyde_net::auth::verify_auth_resp`
    /// succeeds. Used by the consensus-channel filter (task 030) to drop
    /// gossip from peers not in the current committee.
    pub falcon_pubkey: Option<Vec<u8>>,
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
            falcon_pubkey: None,
        }
    }

    /// Builder helper: set the remote IP, typically extracted from
    /// the libp2p Multiaddr via `ip_from_multiaddr` (audit 336).
    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.ip = Some(ip);
        self
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
    pub fn new(
        max_peers: usize,
        max_inbound: usize,
        max_outbound: usize,
        rate_limit_per_ip: u32,
    ) -> Self {
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
        self.peers
            .values()
            .filter(|p| p.direction == Direction::Inbound)
            .count()
    }

    /// Number of outbound connections.
    pub fn outbound_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.direction == Direction::Outbound)
            .count()
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
        self.rate_limits
            .retain(|_, (_, window_start)| window_start.elapsed().as_secs() < 60);
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
        self.peers
            .values()
            .filter(|p| p.role == PeerRole::Validator)
    }

    /// Record the FALCON pubkey attested by a peer during the auth
    /// handshake (task 029). Idempotent: re-binding the same pubkey is a
    /// no-op; rebinding to a different pubkey returns `false` — the caller
    /// should treat this as a protocol violation (peers cannot change
    /// their FALCON identity mid-connection without reconnecting).
    pub fn set_falcon_pubkey(&mut self, peer_id: &PeerId, pubkey: Vec<u8>) -> bool {
        match self.peers.get_mut(peer_id) {
            Some(info) => match &info.falcon_pubkey {
                Some(existing) if existing == &pubkey => true,
                Some(_) => false,
                None => {
                    info.falcon_pubkey = Some(pubkey);
                    true
                }
            },
            None => false,
        }
    }

    /// Promote a peer to `PeerRole::Validator` once its attested FALCON
    /// pubkey is confirmed to match a current committee key. The node
    /// layer calls this after each auth handshake completes and after
    /// every committee rotation.
    pub fn mark_validator(&mut self, peer_id: &PeerId) -> bool {
        match self.peers.get_mut(peer_id) {
            Some(info) => {
                info.role = PeerRole::Validator;
                true
            }
            None => false,
        }
    }

    /// Look up a peer's attested FALCON pubkey, if any.
    pub fn peer_falcon_pubkey(&self, peer_id: &PeerId) -> Option<&[u8]> {
        self.peers.get(peer_id)?.falcon_pubkey.as_deref()
    }

    /// Evaluate whether a peer is authorized to publish on the
    /// consensus-topic. A peer is authorized iff their attested FALCON
    /// pubkey is present in `committee_keys` — missing attestations or
    /// out-of-committee pubkeys return `false`. Callers drop consensus
    /// gossip from unauthorized peers (task 030).
    pub fn is_consensus_authorized(&self, peer_id: &PeerId, committee_keys: &[Vec<u8>]) -> bool {
        match self.peer_falcon_pubkey(peer_id) {
            Some(pk) => committee_keys.iter().any(|ck| ck.as_slice() == pk),
            None => false,
        }
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

    // ── Audit 336: ip_from_multiaddr + with_ip ───────────────────────

    #[test]
    fn ip_from_multiaddr_extracts_ip4() {
        let ma: Multiaddr = "/ip4/192.168.1.42/tcp/30303".parse().unwrap();
        assert_eq!(
            ip_from_multiaddr(&ma),
            Some("192.168.1.42".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn ip_from_multiaddr_extracts_ip6() {
        let ma: Multiaddr = "/ip6/::1/tcp/30303".parse().unwrap();
        assert_eq!(
            ip_from_multiaddr(&ma),
            Some("::1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn ip_from_multiaddr_handles_quic_suffix() {
        // libp2p QUIC multiaddrs have additional segments after the
        // ip; the extractor should still find the ip4 / ip6 part.
        let ma: Multiaddr = "/ip4/10.0.0.1/udp/30303/quic-v1".parse().unwrap();
        assert_eq!(
            ip_from_multiaddr(&ma),
            Some("10.0.0.1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn ip_from_multiaddr_dnsaddr_returns_none() {
        // dns4 / dnsaddr multiaddrs don't carry a resolved IP — the
        // extractor returns None rather than guessing.
        let ma: Multiaddr = "/dns4/validator-0.testnet.example/tcp/30303"
            .parse()
            .unwrap();
        assert_eq!(ip_from_multiaddr(&ma), None);
    }

    #[test]
    fn peer_info_with_ip_builder() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let info = PeerInfo::new(PeerId::random(), Direction::Inbound).with_ip(ip);
        assert_eq!(info.ip, Some(ip));
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

    // ========== Task 029/030: FALCON attestation + consensus filter ==========

    #[test]
    fn set_falcon_pubkey_stores_attestation() {
        let mut mgr = PeerManager::new(10, 10, 10, 100);
        let peer = dummy_peer(Direction::Inbound);
        let id = peer.peer_id;
        mgr.add_peer(peer);

        let pk = vec![0xAA; 897];
        assert!(mgr.set_falcon_pubkey(&id, pk.clone()));
        assert_eq!(mgr.peer_falcon_pubkey(&id), Some(pk.as_slice()));
    }

    #[test]
    fn set_falcon_pubkey_idempotent_on_rebind_same_key() {
        let mut mgr = PeerManager::new(10, 10, 10, 100);
        let peer = dummy_peer(Direction::Inbound);
        let id = peer.peer_id;
        mgr.add_peer(peer);

        let pk = vec![0xAA; 897];
        assert!(mgr.set_falcon_pubkey(&id, pk.clone()));
        // Re-setting to the same key is harmless; common if handshake retries.
        assert!(mgr.set_falcon_pubkey(&id, pk));
    }

    #[test]
    fn set_falcon_pubkey_rejects_rebind_to_different_key() {
        // A peer switching FALCON identity mid-connection is a protocol
        // violation — callers treat this as evidence to disconnect.
        let mut mgr = PeerManager::new(10, 10, 10, 100);
        let peer = dummy_peer(Direction::Inbound);
        let id = peer.peer_id;
        mgr.add_peer(peer);

        assert!(mgr.set_falcon_pubkey(&id, vec![0xAA; 897]));
        assert!(!mgr.set_falcon_pubkey(&id, vec![0xBB; 897]));
        // First key sticks; the rebind attempt is ignored.
        assert_eq!(
            mgr.peer_falcon_pubkey(&id),
            Some(vec![0xAA; 897].as_slice())
        );
    }

    #[test]
    fn set_falcon_pubkey_returns_false_for_unknown_peer() {
        let mut mgr = PeerManager::new(10, 10, 10, 100);
        let id = PeerId::random();
        assert!(!mgr.set_falcon_pubkey(&id, vec![0xAA; 897]));
    }

    #[test]
    fn is_consensus_authorized_accepts_committee_member() {
        let mut mgr = PeerManager::new(10, 10, 10, 100);
        let peer = dummy_peer(Direction::Inbound);
        let id = peer.peer_id;
        mgr.add_peer(peer);

        let committee_pk = vec![0xCC; 897];
        mgr.set_falcon_pubkey(&id, committee_pk.clone());

        let committee = vec![committee_pk, vec![0xDD; 897]];
        assert!(mgr.is_consensus_authorized(&id, &committee));
    }

    #[test]
    fn is_consensus_authorized_rejects_non_committee_member() {
        let mut mgr = PeerManager::new(10, 10, 10, 100);
        let peer = dummy_peer(Direction::Inbound);
        let id = peer.peer_id;
        mgr.add_peer(peer);

        // Peer has a valid FALCON pubkey, but it's not in the committee.
        mgr.set_falcon_pubkey(&id, vec![0xEE; 897]);
        let committee = vec![vec![0xAA; 897], vec![0xBB; 897]];
        assert!(!mgr.is_consensus_authorized(&id, &committee));
    }

    #[test]
    fn is_consensus_authorized_rejects_unattested_peer() {
        let mut mgr = PeerManager::new(10, 10, 10, 100);
        let peer = dummy_peer(Direction::Inbound);
        let id = peer.peer_id;
        mgr.add_peer(peer);

        // No pubkey set → unauthorized, even if committee non-empty.
        let committee = vec![vec![0xAA; 897]];
        assert!(!mgr.is_consensus_authorized(&id, &committee));
    }

    #[test]
    fn is_consensus_authorized_rejects_unknown_peer() {
        let mgr = PeerManager::new(10, 10, 10, 100);
        let id = PeerId::random();
        let committee = vec![vec![0xAA; 897]];
        assert!(!mgr.is_consensus_authorized(&id, &committee));
    }

    #[test]
    fn mark_validator_updates_role() {
        let mut mgr = PeerManager::new(10, 10, 10, 100);
        let peer = dummy_peer(Direction::Inbound);
        let id = peer.peer_id;
        mgr.add_peer(peer);

        assert_eq!(mgr.get_peer(&id).unwrap().role, PeerRole::Unknown);
        assert!(mgr.mark_validator(&id));
        assert_eq!(mgr.get_peer(&id).unwrap().role, PeerRole::Validator);
    }
}
