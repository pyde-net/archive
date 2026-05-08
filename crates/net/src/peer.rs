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

/// Maximum number of in-flight RR requests per peer (TPL-504).
///
/// Per-peer cap on the consensus-RR + blocks-RR fan-out queue.
/// Without this, a 128-validator committee broadcasting a VC
/// round produces N*(N-1) ≈ 16K outbound requests in flight at
/// FALCON-sig payload sizes (~1KB), peaking around 16 MB of
/// queued outbound buffers per round. The cap drops *new* sends
/// to a peer once it already has K in flight; the gossip mesh
/// covers the happy path, so dropping the redundant RR is safe.
/// K = 8 leaves headroom for legitimate parallel rounds (vote
/// + finality vote + view-change in the same window) without
/// letting any single peer monopolize buffer space.
pub const MAX_RR_INFLIGHT_PER_PEER: usize = 8;

/// Maximum number of consensus-topic gossip messages we'll
/// accept (and therefore decode + FALCON-verify) per second
/// from an UNATTESTED `propagation_source` (TPL-505).
///
/// An unattested peer hasn't completed our FALCON auth
/// handshake yet — it might be a legitimately-pending
/// committee member during a reconnect race, or a new full
/// node, or an attacker that opened a connection just to
/// pump expensive messages through the mesh's forwarding
/// path. Without a budget every consensus-topic message from
/// such a peer costs us a FALCON verify (~100K cycles) at
/// the app layer; an attacker holding a few inbound TCP
/// substreams can stall the consensus loop with verify work
/// alone. Attested + authorized committee peers bypass this
/// budget entirely (they're trusted on the channel by
/// definition), and attested + non-committee peers were
/// already hard-dropped pre-fix at the `is_consensus_authorized`
/// gate. The cap targets the "unattested forwarder" middle
/// case, which is the only one whose CPU cost was unbounded.
///
/// 32 is roughly an order of magnitude above the steady-state
/// per-peer rate honest validators produce on the consensus
/// topic (vote + occasional FV/randomness/PSS gossip), so
/// honest unattested peers during their handshake window stay
/// well under it; sustained spam at 33+/s from one source
/// gets shed.
pub const MAX_UNATTESTED_CONSENSUS_PER_SEC: u32 = 32;

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
    /// TPL-504: per-peer count of RR requests we've sent and not
    /// yet seen acked / failed. Gates new sends to bound queued
    /// outbound buffers under quadratic-fanout consensus rounds.
    outbound_rr_inflight: HashMap<PeerId, usize>,
    /// TPL-505: per-`propagation_source` budget for consensus-
    /// topic gossip when the peer hasn't attested a FALCON pubkey
    /// yet. Stored as `(count, window_start)`; the count resets
    /// every wall-clock second.
    unattested_consensus_budget: HashMap<PeerId, (u32, Instant)>,
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
            outbound_rr_inflight: HashMap::new(),
            unattested_consensus_budget: HashMap::new(),
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
        // TPL-504: drop the in-flight counter so a re-connect
        // doesn't inherit a stale (and now-unrecoverable) count
        // from the prior connection — the libp2p substream is
        // gone, so there's nothing to ack the existing slots.
        self.outbound_rr_inflight.remove(peer_id);
        // TPL-505: drop any unattested-consensus budget so a
        // re-connecting peer starts with a clean window.
        self.unattested_consensus_budget.remove(peer_id);
        self.peers.remove(peer_id)
    }

    /// TPL-505: try to consume one unit of the per-second
    /// consensus-topic budget for an UNATTESTED peer. Returns
    /// `true` if the message is admitted (budget available),
    /// `false` if the per-second cap has been reached. Resets
    /// the window when the prior window is older than 1 second
    /// so honest peers post-handshake re-handshake races aren't
    /// permanently saddled with prior-window state. Should NOT
    /// be called for attested + authorized committee peers —
    /// they bypass this gate entirely. Saturating-add on the
    /// counter so a sustained-overflow attacker can't trigger
    /// integer wrap.
    pub fn try_consume_unattested_consensus_budget(&mut self, peer: &PeerId) -> bool {
        let now = Instant::now();
        let entry = self
            .unattested_consensus_budget
            .entry(*peer)
            .or_insert((0, now));
        if entry.1.elapsed().as_secs() >= 1 {
            *entry = (1, now);
            return true;
        }
        if entry.0 >= MAX_UNATTESTED_CONSENSUS_PER_SEC {
            return false;
        }
        entry.0 = entry.0.saturating_add(1);
        true
    }

    /// TPL-505: prune unattested-consensus budget entries whose
    /// window is more than 60 s stale. Mirrors `prune_rate_limits`
    /// for the IP rate-limiter; bounds HashMap growth from
    /// short-lived inbound peers we'll never see again.
    pub fn prune_unattested_consensus_budget(&mut self) {
        self.unattested_consensus_budget
            .retain(|_, (_, window_start)| window_start.elapsed().as_secs() < 60);
    }

    /// TPL-504: try to acquire an RR-send slot for a peer. Returns
    /// `true` and increments the per-peer in-flight counter when
    /// the peer is below `MAX_RR_INFLIGHT_PER_PEER`, otherwise
    /// returns `false` and leaves the counter unchanged. The
    /// caller must invoke `release_rr_slot` on RR
    /// `Message::Response`, `OutboundFailure`, AND `InboundFailure`
    /// for the matching peer so the counter eventually drains.
    pub fn try_acquire_rr_slot(&mut self, peer: &PeerId) -> bool {
        let entry = self.outbound_rr_inflight.entry(*peer).or_insert(0);
        if *entry >= MAX_RR_INFLIGHT_PER_PEER {
            return false;
        }
        *entry += 1;
        true
    }

    /// TPL-504: release a previously-acquired RR-send slot.
    /// Saturating-decrement so a stray release (e.g. an event the
    /// caller can't pre-correlate to a `try_acquire_rr_slot`) is
    /// a no-op rather than a crash. If the counter hits zero the
    /// entry is removed to bound HashMap growth as peers churn.
    pub fn release_rr_slot(&mut self, peer: &PeerId) {
        if let Some(slot) = self.outbound_rr_inflight.get_mut(peer) {
            *slot = slot.saturating_sub(1);
            if *slot == 0 {
                self.outbound_rr_inflight.remove(peer);
            }
        }
    }

    /// TPL-504: introspection for tests + metrics. Returns 0 for
    /// peers we've never sent to.
    pub fn rr_inflight_count(&self, peer: &PeerId) -> usize {
        self.outbound_rr_inflight.get(peer).copied().unwrap_or(0)
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

    // ── TPL-504: per-peer in-flight RR cap ─────────────────────────

    /// `try_acquire_rr_slot` admits up to `MAX_RR_INFLIGHT_PER_PEER`
    /// concurrent sends per peer, then refuses further admissions
    /// until `release_rr_slot` drains the count.
    #[test]
    fn tpl_504_try_acquire_rr_slot_caps_at_max() {
        let mut mgr = PeerManager::new(10, 10, 10, 100);
        let peer = PeerId::random();

        // First MAX_RR_INFLIGHT_PER_PEER admissions succeed.
        for i in 0..MAX_RR_INFLIGHT_PER_PEER {
            assert!(
                mgr.try_acquire_rr_slot(&peer),
                "admission #{i} below cap should succeed"
            );
            assert_eq!(mgr.rr_inflight_count(&peer), i + 1);
        }

        // Cap reached: further admissions are refused without
        // mutating the counter.
        assert!(!mgr.try_acquire_rr_slot(&peer));
        assert_eq!(mgr.rr_inflight_count(&peer), MAX_RR_INFLIGHT_PER_PEER);
        assert!(!mgr.try_acquire_rr_slot(&peer));
        assert_eq!(mgr.rr_inflight_count(&peer), MAX_RR_INFLIGHT_PER_PEER);

        // After a release, a new admission slots in.
        mgr.release_rr_slot(&peer);
        assert_eq!(mgr.rr_inflight_count(&peer), MAX_RR_INFLIGHT_PER_PEER - 1);
        assert!(mgr.try_acquire_rr_slot(&peer));
        assert_eq!(mgr.rr_inflight_count(&peer), MAX_RR_INFLIGHT_PER_PEER);
    }

    /// `release_rr_slot` is saturating: an unmatched release
    /// (e.g. an event the caller couldn't pre-correlate) is a
    /// no-op rather than a crash. And once the counter hits
    /// zero the entry is dropped to bound HashMap growth.
    #[test]
    fn tpl_504_release_rr_slot_is_saturating_and_drops_zero_entries() {
        let mut mgr = PeerManager::new(10, 10, 10, 100);
        let peer = PeerId::random();

        // Release on a never-acquired peer is a no-op.
        mgr.release_rr_slot(&peer);
        assert_eq!(mgr.rr_inflight_count(&peer), 0);

        // Acquire 2, release 2 → entry should be removed (count
        // zero ⇒ no map entry, so re-acquire goes through the
        // entry-insert path).
        assert!(mgr.try_acquire_rr_slot(&peer));
        assert!(mgr.try_acquire_rr_slot(&peer));
        assert_eq!(mgr.rr_inflight_count(&peer), 2);
        mgr.release_rr_slot(&peer);
        mgr.release_rr_slot(&peer);
        assert_eq!(mgr.rr_inflight_count(&peer), 0);

        // Extra release after the entry is gone — still a no-op.
        mgr.release_rr_slot(&peer);
        assert_eq!(mgr.rr_inflight_count(&peer), 0);
    }

    /// `remove_peer` clears any in-flight slots so a re-connect
    /// doesn't inherit an unrecoverable count from the prior
    /// connection — the libp2p substream is gone, no events will
    /// arrive to drain it.
    #[test]
    fn tpl_504_remove_peer_clears_inflight_slots() {
        let mut mgr = PeerManager::new(10, 10, 10, 100);
        let peer = dummy_peer(Direction::Outbound);
        let id = peer.peer_id;
        assert!(mgr.add_peer(peer));

        for _ in 0..3 {
            assert!(mgr.try_acquire_rr_slot(&id));
        }
        assert_eq!(mgr.rr_inflight_count(&id), 3);

        mgr.remove_peer(&id);
        assert_eq!(
            mgr.rr_inflight_count(&id),
            0,
            "remove_peer must drop in-flight counter"
        );
    }

    // ── TPL-505: unattested consensus-topic budget ─────────────────

    /// `try_consume_unattested_consensus_budget` admits up to
    /// `MAX_UNATTESTED_CONSENSUS_PER_SEC` messages per peer per
    /// second, then refuses further admissions in the same
    /// window without disturbing the budget state.
    #[test]
    fn tpl_505_unattested_consensus_budget_caps_per_second() {
        let mut mgr = PeerManager::new(10, 10, 10, 100);
        let peer = PeerId::random();

        for i in 0..MAX_UNATTESTED_CONSENSUS_PER_SEC {
            assert!(
                mgr.try_consume_unattested_consensus_budget(&peer),
                "admission #{i} below per-second cap should succeed"
            );
        }

        // Cap reached — further calls in the same window refuse.
        assert!(!mgr.try_consume_unattested_consensus_budget(&peer));
        assert!(!mgr.try_consume_unattested_consensus_budget(&peer));
    }

    /// `remove_peer` clears the budget entry so a reconnecting
    /// peer starts with a fresh window — without this the
    /// adversary path "open new TCP connection per second to
    /// reset state" would already work, but a stuck stale
    /// entry could lock out a legitimate reconnect.
    #[test]
    fn tpl_505_remove_peer_clears_unattested_budget() {
        let mut mgr = PeerManager::new(10, 10, 10, 100);
        let peer_info = dummy_peer(Direction::Inbound);
        let id = peer_info.peer_id;
        assert!(mgr.add_peer(peer_info));

        for _ in 0..MAX_UNATTESTED_CONSENSUS_PER_SEC {
            assert!(mgr.try_consume_unattested_consensus_budget(&id));
        }
        assert!(!mgr.try_consume_unattested_consensus_budget(&id));

        mgr.remove_peer(&id);
        // Post-disconnect: budget entry gone; a fresh
        // re-add gets a fresh window.
        assert!(mgr.try_consume_unattested_consensus_budget(&id));
    }

    /// `prune_unattested_consensus_budget` only drops entries
    /// older than 60 s. A fresh entry must survive a prune.
    #[test]
    fn tpl_505_prune_unattested_budget_keeps_fresh_entries() {
        let mut mgr = PeerManager::new(10, 10, 10, 100);
        let peer = PeerId::random();

        assert!(mgr.try_consume_unattested_consensus_budget(&peer));
        // Window is fresh (< 60 s) — must survive the prune.
        mgr.prune_unattested_consensus_budget();
        // Asserting via behavior: the next admission counts
        // against the existing window, so we can still
        // exhaust it `MAX - 1` more times without creating
        // a new entry.
        for _ in 1..MAX_UNATTESTED_CONSENSUS_PER_SEC {
            assert!(mgr.try_consume_unattested_consensus_budget(&peer));
        }
        assert!(!mgr.try_consume_unattested_consensus_budget(&peer));
    }
}
