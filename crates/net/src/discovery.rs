//! Peer discovery via Kademlia DHT and bootstrap nodes.
//!
//! Discovery flow:
//! 1. Node starts with a list of bootstrap peers (hardcoded or configured)
//! 2. Connects to bootstrap peers and joins the Kademlia DHT
//! 3. Performs random walks to discover more peers
//! 4. Maintains a set of known peers for reconnection

use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Pyde mainnet chain ID. Bound into every consensus signing
/// preimage (proposer headers, votes, view-change votes, slashing
/// evidence, multisig payloads) so a signature on one network
/// cannot be replayed on another even when FALCON keys match.
///
/// TPL-808 (pre-launch decision pending): the value `1` collides
/// with **Ethereum mainnet** under the chainlist.org / EIP-155
/// chain-id registry. The collision does not produce
/// cross-protocol signature replay (Pyde signs FALCON-512 over a
/// different preimage than Ethereum's secp256k1-over-RLP), but
/// every wallet, block explorer, SDK, and cross-chain protocol
/// uses the chain id as a network identifier — a user adding a
/// "Pyde mainnet" RPC to MetaMask at id 1 would conflict with
/// their Ethereum config; a bridge that keys on chain id alone
/// could route Pyde traffic into an Ethereum surface or vice
/// versa. The mainnet-genesis ceremony (§18.2 step 4) must
/// resolve this by either registering a unique id with
/// chainlist.org or choosing a clearly-vacant slot. Until that
/// decision lands, the constant stays `1` so existing test
/// fixtures and signing preimages don't churn; treat the value
/// as PROVISIONAL.
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

/// Default ban duration in seconds when a `BanReason` doesn't
/// have a more specific tier (currently only used by the
/// fallback path in `ban_peer_for(_, _, 0)`-style overrides).
pub const DEFAULT_BAN_DURATION_SECS: u64 = 3600; // 1 hour

/// TPL-511: per-reason ban duration tiers, in seconds. Each
/// `BanReason::default_duration_secs()` returns its tier. The
/// scaling is roughly:
///
/// - `RATE_LIMIT_ABUSE` (10 min): low-cost offense, often
///   triggered by ordinary back-pressure or buggy clients —
///   short ban encourages reconnect once back-pressure
///   subsides.
/// - `INVALID_TRANSACTION` (1 hour): a peer relaying garbage
///   txs, but that's catchable at the mempool gate without
///   permanent damage. 1h covers the typical mis-config
///   window.
/// - `PROTOCOL_VIOLATION` (1 day): wrong wire format, missing
///   tags, malformed framing. Indicates a buggy or hostile
///   client; longer ban gives the operator time to notice.
/// - `INVALID_CONSENSUS_MESSAGE` (7 days): the most expensive
///   class — every received consensus msg burns FALCON-verify
///   cycles, and a peer reliably emitting invalid ones is
///   either Byzantine or seriously broken. 7d effectively
///   blacklists the peer for the testnet's incentivized window.
/// - `MANUAL` (1 day default): operator override — the duration
///   parameter on `ban_peer_for` lets the operator pick a
///   different value when needed.
pub const BAN_TIER_RATE_LIMIT_ABUSE_SECS: u64 = 600; // 10 minutes
pub const BAN_TIER_INVALID_TRANSACTION_SECS: u64 = 3600; // 1 hour
pub const BAN_TIER_PROTOCOL_VIOLATION_SECS: u64 = 86_400; // 1 day
pub const BAN_TIER_INVALID_CONSENSUS_SECS: u64 = 604_800; // 7 days
pub const BAN_TIER_MANUAL_SECS: u64 = 86_400; // 1 day

/// Ban reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

impl BanReason {
    /// TPL-511: default per-reason ban duration in seconds.
    /// Used by `ban_peer` (the default path); `ban_peer_for`
    /// keeps the explicit-duration override.
    pub fn default_duration_secs(&self) -> u64 {
        match self {
            BanReason::RateLimitAbuse => BAN_TIER_RATE_LIMIT_ABUSE_SECS,
            BanReason::InvalidTransaction => BAN_TIER_INVALID_TRANSACTION_SECS,
            BanReason::ProtocolViolation => BAN_TIER_PROTOCOL_VIOLATION_SECS,
            BanReason::InvalidConsensusMessage => BAN_TIER_INVALID_CONSENSUS_SECS,
            BanReason::Manual(_) => BAN_TIER_MANUAL_SECS,
        }
    }
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
    /// TPL-510: operator-supplied FALCON pubkey pins for
    /// specific peer ids (typically bootstrap peers and
    /// other known infrastructure). When the auth handshake
    /// completes, the attested FALCON pubkey is compared to
    /// the pinned value; a mismatch is a hard-disconnect
    /// signal. Pre-fix bootstrap entries were trusted by
    /// multiaddr alone — anyone able to reach the operator's
    /// claimed (IP, port, libp2p-noise-PeerId) tuple was
    /// accepted as the bootstrap, with no ability for the
    /// operator to additionally pin the FALCON identity that
    /// signs blocks/votes.
    pinned_falcon_pubkeys: HashMap<PeerId, Vec<u8>>,
}

impl Discovery {
    pub fn new() -> Self {
        Self {
            bootstrap_peers: Vec::new(),
            known_peers: HashMap::new(),
            banned: HashMap::new(),
            pinned_falcon_pubkeys: HashMap::new(),
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

    /// TPL-510: register an operator-supplied FALCON pubkey
    /// pin for a specific peer id. The auth handshake's
    /// `apply_auth_response` rejects any attested pubkey that
    /// doesn't byte-match the pin. Idempotent on repeat
    /// registration of the same `(peer, pubkey)`; later calls
    /// with a different pubkey OVERWRITE the prior pin (the
    /// operator changed their mind in config and we trust the
    /// most recent value).
    pub fn add_falcon_pubkey_pin(&mut self, peer_id: PeerId, falcon_pubkey: Vec<u8>) {
        self.pinned_falcon_pubkeys.insert(peer_id, falcon_pubkey);
    }

    /// TPL-510: look up the operator's FALCON pubkey pin for a
    /// peer. Returns `None` if no pin is registered for that
    /// peer id (the handshake then accepts whatever pubkey the
    /// peer attests, same pre-fix behavior). Returns
    /// `Some(&[u8])` to enforce a byte-equality match against
    /// the attested pubkey.
    pub fn pinned_falcon_pubkey(&self, peer_id: &PeerId) -> Option<&[u8]> {
        self.pinned_falcon_pubkeys
            .get(peer_id)
            .map(|v| v.as_slice())
    }

    /// TPL-510: count of registered pins (for telemetry / startup logs).
    pub fn pinned_pubkey_count(&self) -> usize {
        self.pinned_falcon_pubkeys.len()
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

    /// Ban a peer with the per-reason default duration tier
    /// (TPL-511: `BanReason::default_duration_secs`). Pre-fix
    /// every ban used the constant `self.ban_duration` (1 hour),
    /// so a sustained-spam `InvalidConsensusMessage` peer was
    /// re-eligible to reconnect after the same window as a
    /// transient `RateLimitAbuse` — the rate-limit tripper
    /// stayed banned an order of magnitude longer than was
    /// proportional, the consensus spammer an order shorter.
    pub fn ban_peer(&mut self, peer_id: PeerId, reason: BanReason) {
        let duration_secs = reason.default_duration_secs();
        self.banned.insert(
            peer_id,
            BanEntry {
                peer_id,
                reason,
                banned_at: Instant::now(),
                duration_secs,
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

    // ========== TPL-511: ban persistence ==========

    /// Persist the active (non-expired) bans to
    /// `<datadir>/bans.json`. Each entry stores the absolute
    /// Unix-ms expiration time so a restart correctly recovers
    /// the remaining duration even though `Instant`s don't
    /// survive across processes.
    ///
    /// Atomic write via temp + rename — same crash-safety
    /// pattern as `PeerBook::save`. Already-expired bans are
    /// dropped at save time; load_bans drops anything still
    /// expired by the time it runs.
    pub fn save_bans(&self, datadir: &Path) -> Result<(), String> {
        let now_ms = current_unix_ms();
        let entries: Vec<BanFileEntry> = self
            .banned
            .iter()
            .filter(|(_, e)| !e.is_expired())
            .map(|(peer_id, entry)| {
                let remaining_secs =
                    entry.duration_secs.saturating_sub(entry.banned_at.elapsed().as_secs());
                let expires_at_unix_ms = now_ms.saturating_add(remaining_secs.saturating_mul(1000));
                BanFileEntry {
                    peer_id: peer_id.to_string(),
                    reason: entry.reason.clone(),
                    expires_at_unix_ms,
                }
            })
            .collect();
        let file = BanFile { entries };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;
        let final_path = datadir.join(BAN_FILENAME);
        let tmp_path = datadir.join(format!("{}.tmp", BAN_FILENAME));
        std::fs::write(&tmp_path, bytes).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp_path, &final_path).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Load persisted bans from `<datadir>/bans.json`. Missing
    /// file, parse errors, and unparseable entries all fall
    /// through to an empty ban set — corruption isn't fatal.
    /// Already-expired entries (`expires_at_unix_ms <= now_ms`)
    /// are skipped: a restart that crossed past the original
    /// expiry shouldn't re-impose a ban.
    pub fn load_bans(&mut self, datadir: &Path) {
        let path = datadir.join(BAN_FILENAME);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => return, // missing or unreadable — start clean
        };
        let parsed: BanFile = match serde_json::from_slice(&bytes) {
            Ok(p) => p,
            Err(_) => {
                // Corrupt / future format — skip silently to avoid
                // refusing startup on a bad ban-file.
                return;
            }
        };
        let now_ms = current_unix_ms();
        let restore_instant = Instant::now();
        let mut count = 0usize;
        for entry in parsed.entries {
            let peer_id = match PeerId::from_str(&entry.peer_id) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if entry.expires_at_unix_ms <= now_ms {
                continue;
            }
            let remaining_secs = (entry.expires_at_unix_ms - now_ms) / 1000;
            if remaining_secs == 0 {
                continue;
            }
            self.banned.insert(
                peer_id,
                BanEntry {
                    peer_id,
                    reason: entry.reason,
                    banned_at: restore_instant,
                    duration_secs: remaining_secs,
                },
            );
            count += 1;
        }
        if count > 0 {
            // Soft signal — operators can grep for this in logs to
            // confirm the on-disk ban set survived a restart.
            tracing::info!(count, "restored ban entries from disk");
        }
    }
}

const BAN_FILENAME: &str = "bans.json";

/// On-disk representation of a single ban. Stored separately
/// from `BanEntry` to avoid coupling the in-memory `Instant`
/// (monotonic, non-serializable) with the persisted layout.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct BanFileEntry {
    peer_id: String,
    reason: BanReason,
    /// Absolute Unix-ms time at which the ban expires. Computed
    /// at save time from `banned_at + duration_secs`.
    expires_at_unix_ms: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct BanFile {
    entries: Vec<BanFileEntry>,
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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

    // ========== TPL-510: bootstrap FALCON pubkey pinning ==========

    #[test]
    fn tpl_510_pinned_falcon_pubkey_round_trips() {
        let mut disco = Discovery::new();
        let peer = random_peer();
        let pk = vec![0xAB; 897];
        disco.add_falcon_pubkey_pin(peer, pk.clone());

        assert_eq!(disco.pinned_falcon_pubkey(&peer), Some(pk.as_slice()));
        assert_eq!(disco.pinned_pubkey_count(), 1);
    }

    #[test]
    fn tpl_510_pinned_falcon_pubkey_returns_none_for_unpinned() {
        let disco = Discovery::new();
        let peer = random_peer();
        assert_eq!(disco.pinned_falcon_pubkey(&peer), None);
        assert_eq!(disco.pinned_pubkey_count(), 0);
    }

    #[test]
    fn tpl_510_repeated_pin_overwrites_prior_value() {
        let mut disco = Discovery::new();
        let peer = random_peer();
        disco.add_falcon_pubkey_pin(peer, vec![0xAA; 897]);
        disco.add_falcon_pubkey_pin(peer, vec![0xBB; 897]);
        assert_eq!(disco.pinned_falcon_pubkey(&peer), Some(vec![0xBB; 897].as_slice()));
        assert_eq!(disco.pinned_pubkey_count(), 1);
    }

    // ========== TPL-511: ban tier durations + on-disk persistence ==========

    /// Each `BanReason` returns its tier'd default duration —
    /// rate-limit < tx-invalid < protocol-violation <
    /// invalid-consensus, with `Manual` near the top of the
    /// scale (operator override is the explicit-duration form).
    #[test]
    fn tpl_511_ban_reason_tier_durations() {
        assert_eq!(
            BanReason::RateLimitAbuse.default_duration_secs(),
            BAN_TIER_RATE_LIMIT_ABUSE_SECS
        );
        assert_eq!(
            BanReason::InvalidTransaction.default_duration_secs(),
            BAN_TIER_INVALID_TRANSACTION_SECS
        );
        assert_eq!(
            BanReason::ProtocolViolation.default_duration_secs(),
            BAN_TIER_PROTOCOL_VIOLATION_SECS
        );
        assert_eq!(
            BanReason::InvalidConsensusMessage.default_duration_secs(),
            BAN_TIER_INVALID_CONSENSUS_SECS
        );
        assert_eq!(
            BanReason::Manual("op".into()).default_duration_secs(),
            BAN_TIER_MANUAL_SECS
        );
        // Invariant: tier ordering preserves the "more
        // expensive offense → longer ban" property.
        assert!(BAN_TIER_RATE_LIMIT_ABUSE_SECS < BAN_TIER_INVALID_TRANSACTION_SECS);
        assert!(BAN_TIER_INVALID_TRANSACTION_SECS < BAN_TIER_PROTOCOL_VIOLATION_SECS);
        assert!(BAN_TIER_PROTOCOL_VIOLATION_SECS < BAN_TIER_INVALID_CONSENSUS_SECS);
    }

    /// `ban_peer` (the default path) now uses the per-reason
    /// tier instead of a single constant. A consensus spammer
    /// gets the long tier; a rate-limit tripper gets the
    /// short one.
    #[test]
    fn tpl_511_ban_peer_uses_per_reason_tier() {
        let mut disco = Discovery::new();
        let consensus_spammer = random_peer();
        let rate_limit_tripper = random_peer();
        disco.ban_peer(consensus_spammer, BanReason::InvalidConsensusMessage);
        disco.ban_peer(rate_limit_tripper, BanReason::RateLimitAbuse);

        let consensus_entry = disco.banned.get(&consensus_spammer).unwrap();
        let rate_entry = disco.banned.get(&rate_limit_tripper).unwrap();
        assert_eq!(
            consensus_entry.duration_secs,
            BAN_TIER_INVALID_CONSENSUS_SECS
        );
        assert_eq!(rate_entry.duration_secs, BAN_TIER_RATE_LIMIT_ABUSE_SECS);
    }

    /// Bans persist across save/load with their remaining
    /// duration intact. A ban saved with N seconds remaining
    /// reloads as ban with ≈N seconds remaining.
    #[test]
    fn tpl_511_ban_persistence_roundtrips_remaining_duration() {
        let dir = tempfile::tempdir().unwrap();
        let mut disco = Discovery::new();
        let peer = random_peer();
        // Custom 60-second ban so the test isn't sensitive to
        // tier values (and finishes quickly even if the test
        // host is slow).
        disco.ban_peer_for(peer, BanReason::Manual("test".into()), 60);
        assert!(disco.is_banned(&peer));

        disco.save_bans(dir.path()).unwrap();

        // Fresh Discovery — load from disk.
        let mut disco2 = Discovery::new();
        disco2.load_bans(dir.path());
        assert!(
            disco2.is_banned(&peer),
            "ban must survive save/load roundtrip"
        );
        let restored = disco2.banned.get(&peer).unwrap();
        assert_eq!(restored.reason, BanReason::Manual("test".into()));
        // Remaining ≤ 60 (some time elapsed during save+load).
        assert!(
            restored.duration_secs <= 60,
            "remaining duration must reflect time elapsed"
        );
    }

    /// Already-expired entries on disk are dropped at load
    /// time — a node that crashed and came back hours later
    /// shouldn't re-impose a ban that was supposed to have
    /// already expired. We exercise this by writing a bans
    /// file directly with an `expires_at_unix_ms` in the
    /// past.
    #[test]
    fn tpl_511_load_drops_already_expired_entries() {
        let dir = tempfile::tempdir().unwrap();
        let peer = random_peer();
        let file = BanFile {
            entries: vec![BanFileEntry {
                peer_id: peer.to_string(),
                reason: BanReason::ProtocolViolation,
                // 1 sec past the Unix epoch — definitely expired.
                expires_at_unix_ms: 1000,
            }],
        };
        let bytes = serde_json::to_vec_pretty(&file).unwrap();
        std::fs::write(dir.path().join("bans.json"), bytes).unwrap();

        let mut disco = Discovery::new();
        disco.load_bans(dir.path());
        assert!(
            !disco.is_banned(&peer),
            "expired ban entry must be dropped on load"
        );
    }

    /// Missing or corrupt bans file falls through to an empty
    /// ban set — corruption isn't fatal, mirroring `PeerBook::load`.
    #[test]
    fn tpl_511_missing_bans_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let mut disco = Discovery::new();
        disco.load_bans(dir.path());
        assert_eq!(disco.banned_count(), 0);
    }

    #[test]
    fn tpl_511_corrupt_bans_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bans.json"), b"not-json").unwrap();
        let mut disco = Discovery::new();
        disco.load_bans(dir.path());
        assert_eq!(disco.banned_count(), 0);
    }

    /// `save_bans` only persists non-expired entries — a
    /// dirty in-memory ban that's already expired doesn't
    /// land on disk.
    #[test]
    fn tpl_511_save_skips_already_expired_in_memory_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut disco = Discovery::new();
        let live = random_peer();
        let expired = random_peer();
        disco.ban_peer_for(live, BanReason::ProtocolViolation, 60);
        disco.ban_peer_for(expired, BanReason::ProtocolViolation, 0);
        // `expired` ban is immediately past — `is_banned` is
        // already false.
        assert!(disco.is_banned(&live));
        assert!(!disco.is_banned(&expired));

        disco.save_bans(dir.path()).unwrap();
        let mut disco2 = Discovery::new();
        disco2.load_bans(dir.path());
        assert!(disco2.is_banned(&live));
        assert!(!disco2.is_banned(&expired));
    }
}
