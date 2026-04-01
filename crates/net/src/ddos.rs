//! DDoS protection: rate limiting, connection limits, and flood mitigation.
//!
//! Defense layers:
//! 1. Per-peer message rate limiting (token bucket)
//! 2. Per-subnet (/24) connection limits
//! 3. Per-channel message size enforcement
//! 4. Proof-of-work challenge for connection floods
//! 5. Eclipse attack mitigation via diverse peer selection

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::channels::Channel;

// ============================================================================
// Per-peer rate limiting (token bucket)
// ============================================================================

/// Token bucket rate limiter for a single peer.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    /// Current token count.
    tokens: f64,
    /// Maximum tokens (burst capacity).
    max_tokens: f64,
    /// Tokens added per second.
    refill_rate: f64,
    /// Last refill time.
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate-limited.
    pub fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }

    /// Current token count.
    pub fn available(&self) -> f64 {
        self.tokens
    }
}

// ============================================================================
// Per-subnet connection limits
// ============================================================================

/// Track connections per /24 subnet.
#[derive(Clone, Debug, Default)]
pub struct SubnetLimiter {
    /// /24 subnet → connection count.
    subnets: HashMap<[u8; 3], u32>,
    /// Maximum connections per /24 subnet.
    max_per_subnet: u32,
}

impl SubnetLimiter {
    pub fn new(max_per_subnet: u32) -> Self {
        Self {
            subnets: HashMap::new(),
            max_per_subnet,
        }
    }

    /// Extract /24 prefix from an IP address.
    fn subnet_key(ip: &IpAddr) -> Option<[u8; 3]> {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                Some([octets[0], octets[1], octets[2]])
            }
            IpAddr::V6(_) => None, // V6 subnet limiting deferred
        }
    }

    /// Check if a new connection from this IP is allowed.
    pub fn allow_connection(&self, ip: &IpAddr) -> bool {
        if let Some(key) = Self::subnet_key(ip) {
            let count = self.subnets.get(&key).copied().unwrap_or(0);
            count < self.max_per_subnet
        } else {
            true // allow IPv6 for now
        }
    }

    /// Register a new connection from this IP.
    pub fn add_connection(&mut self, ip: &IpAddr) {
        if let Some(key) = Self::subnet_key(ip) {
            *self.subnets.entry(key).or_insert(0) += 1;
        }
    }

    /// Remove a connection from this IP.
    pub fn remove_connection(&mut self, ip: &IpAddr) {
        if let Some(key) = Self::subnet_key(ip) {
            if let Some(count) = self.subnets.get_mut(&key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.subnets.remove(&key);
                }
            }
        }
    }

    /// Number of connections from this IP's /24 subnet.
    pub fn subnet_count(&self, ip: &IpAddr) -> u32 {
        if let Some(key) = Self::subnet_key(ip) {
            self.subnets.get(&key).copied().unwrap_or(0)
        } else {
            0
        }
    }
}

// ============================================================================
// Per-channel message size limits
// ============================================================================

/// Maximum message size per channel (bytes).
/// Single source of truth — used by both DDoS validation and channel validation.
pub fn max_message_size(channel: Channel) -> usize {
    match channel {
        Channel::Consensus => 64 * 1024,       // 64 KB (votes, view changes)
        Channel::Transactions => 128 * 1024,    // 128 KB (encrypted transactions)
        Channel::Blocks => 4 * 1024 * 1024,     // 4 MB (full blocks)
        Channel::Sync => 8 * 1024 * 1024,       // 8 MB (state sync chunks)
    }
}

/// Check if a message size is within the channel limit.
pub fn validate_message_size(channel: Channel, size: usize) -> bool {
    size <= max_message_size(channel)
}

// NOTE: channels.rs has an identical inline match in validate_message().
// Future refactor: have channels.rs call ddos::max_message_size() to
// eliminate the duplication. Not done now to avoid changing the existing
// channels.rs API surface in this PR.

// ============================================================================
// Proof-of-work challenge for connection floods
// ============================================================================

/// A PoW challenge: the connecting peer must find a nonce such that
/// Poseidon2(challenge || nonce) has `difficulty` leading zero bits.
#[derive(Clone, Debug)]
pub struct PowChallenge {
    /// Random challenge bytes.
    pub challenge: [u8; 32],
    /// Required leading zero bits (higher = harder).
    pub difficulty: u8,
    /// When the challenge was issued.
    pub issued_at: Instant,
    /// Challenge validity period.
    pub ttl: Duration,
}

impl PowChallenge {
    pub fn new(challenge: [u8; 32], difficulty: u8) -> Self {
        Self {
            challenge,
            difficulty,
            issued_at: Instant::now(),
            ttl: Duration::from_secs(30),
        }
    }

    /// Verify a PoW solution: check that hash(challenge || nonce) has enough leading zeros.
    pub fn verify(&self, nonce: u64) -> bool {
        if self.issued_at.elapsed() > self.ttl {
            return false; // expired
        }
        let mut input = Vec::with_capacity(40);
        input.extend_from_slice(&self.challenge);
        input.extend_from_slice(&nonce.to_le_bytes());
        let hash = pyde_crypto::poseidon2::poseidon2_hash(&input);
        leading_zero_bits(hash.as_bytes()) >= self.difficulty as u32
    }
}

/// Count leading zero bits in a byte slice.
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0u32;
    for &b in bytes {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}

// ============================================================================
// Eclipse attack mitigation
// ============================================================================

/// Ensure peer set is diverse across /16 subnets.
/// Returns the number of distinct /16 subnets in the peer set.
pub fn subnet_diversity(peer_ips: &[IpAddr]) -> usize {
    let mut subnets = std::collections::HashSet::new();
    for ip in peer_ips {
        if let IpAddr::V4(v4) = ip {
            let octets = v4.octets();
            subnets.insert([octets[0], octets[1]]);
        }
    }
    subnets.len()
}

/// Check if adding a peer from this IP would maintain sufficient diversity.
/// Requires at least `min_diversity` distinct /16 subnets.
pub fn would_maintain_diversity(
    current_ips: &[IpAddr],
    new_ip: &IpAddr,
    min_diversity: usize,
) -> bool {
    // If we have fewer peers than the diversity requirement, always accept
    if current_ips.len() < min_diversity {
        return true;
    }
    // Check current diversity
    let current_diversity = subnet_diversity(current_ips);
    if current_diversity < min_diversity {
        // Only accept if the new IP adds a new subnet
        let mut with_new = current_ips.to_vec();
        with_new.push(*new_ip);
        subnet_diversity(&with_new) > current_diversity
    } else {
        true // already diverse enough
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ========== Task 0582: Per-peer rate limiting ==========

    #[test]
    fn rate_limiter_allows_within_limit() {
        let mut rl = RateLimiter::new(10.0, 1.0);
        for _ in 0..10 {
            assert!(rl.try_consume());
        }
    }

    #[test]
    fn rate_limiter_blocks_when_exhausted() {
        let mut rl = RateLimiter::new(3.0, 0.0); // no refill
        assert!(rl.try_consume());
        assert!(rl.try_consume());
        assert!(rl.try_consume());
        assert!(!rl.try_consume()); // exhausted
    }

    // ========== Task 0583: Per-subnet connection limits ==========

    #[test]
    fn subnet_limiter_allows_within_limit() {
        let mut sl = SubnetLimiter::new(3);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        assert!(sl.allow_connection(&ip));
        sl.add_connection(&ip);
        sl.add_connection(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)));
        sl.add_connection(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30)));
        // Same /24 subnet, 3 connections — at limit
        assert!(!sl.allow_connection(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40))));
    }

    #[test]
    fn subnet_limiter_different_subnets_independent() {
        let mut sl = SubnetLimiter::new(2);
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)); // different /24
        sl.add_connection(&ip_a);
        sl.add_connection(&ip_a);
        assert!(!sl.allow_connection(&ip_a)); // subnet A full
        assert!(sl.allow_connection(&ip_b)); // subnet B still open
    }

    #[test]
    fn subnet_limiter_remove_frees_slot() {
        let mut sl = SubnetLimiter::new(1);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
        sl.add_connection(&ip);
        assert!(!sl.allow_connection(&ip));
        sl.remove_connection(&ip);
        assert!(sl.allow_connection(&ip));
    }

    // ========== Task 0584: Message size limits ==========

    #[test]
    fn message_size_within_limit() {
        assert!(validate_message_size(Channel::Transactions, 1000));
        assert!(validate_message_size(Channel::Blocks, 3_000_000));
    }

    #[test]
    fn message_size_exceeds_limit() {
        assert!(!validate_message_size(Channel::Transactions, 200_000)); // > 128KB
        assert!(!validate_message_size(Channel::Consensus, 100_000)); // > 64KB
    }

    // ========== Task 0585: PoW challenge ==========

    #[test]
    fn pow_challenge_verify_valid() {
        let challenge = PowChallenge::new([0xAB; 32], 4); // 4 leading zero bits
        // Brute-force a valid nonce (low difficulty, should find quickly)
        let mut nonce = 0u64;
        loop {
            if challenge.verify(nonce) {
                break;
            }
            nonce += 1;
            if nonce > 100_000 {
                panic!("could not find valid nonce within 100K attempts");
            }
        }
    }

    #[test]
    fn pow_challenge_invalid_nonce() {
        let challenge = PowChallenge::new([0xAB; 32], 32); // very high difficulty
        // A random nonce is extremely unlikely to have 32 leading zero bits
        assert!(!challenge.verify(12345));
    }

    #[test]
    fn leading_zero_bits_count() {
        assert_eq!(leading_zero_bits(&[0, 0, 0xFF]), 16);
        assert_eq!(leading_zero_bits(&[0x0F, 0xFF]), 4);
        assert_eq!(leading_zero_bits(&[0xFF]), 0);
        assert_eq!(leading_zero_bits(&[0, 0, 0, 0]), 32);
    }

    // ========== Task 0586: Eclipse attack mitigation ==========

    #[test]
    fn subnet_diversity_counts_distinct() {
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)),   // same /16
            IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)),   // different /16
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), // different /16
        ];
        assert_eq!(subnet_diversity(&ips), 3); // 10.0, 10.1, 192.168
    }

    #[test]
    fn diversity_check_rejects_concentrated_peers() {
        // All peers from same /16 subnet
        let ips: Vec<IpAddr> = (1..=10)
            .map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, i, 1)))
            .collect();

        // Require diversity of 3 — only have 1 distinct /16
        let new_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 11, 1)); // same /16
        assert!(!would_maintain_diversity(&ips, &new_ip, 3));

        // New IP from different /16 — should be accepted (improves diversity)
        let diverse_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(would_maintain_diversity(&ips, &diverse_ip, 3));
    }

    // ========== Task 0587-0588: Integration ==========

    #[test]
    fn rate_limited_peer_throttled() {
        let mut rl = RateLimiter::new(5.0, 0.0); // 5 burst, no refill
        let mut allowed = 0;
        let mut denied = 0;
        for _ in 0..20 {
            if rl.try_consume() { allowed += 1; } else { denied += 1; }
        }
        assert_eq!(allowed, 5);
        assert_eq!(denied, 15);
    }

    #[test]
    fn connection_flood_mitigated() {
        let mut sl = SubnetLimiter::new(5);
        let mut connected = 0;
        let mut rejected = 0;
        // 100 connections from same /24 subnet
        for i in 0..100u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 1, i));
            if sl.allow_connection(&ip) {
                sl.add_connection(&ip);
                connected += 1;
            } else {
                rejected += 1;
            }
        }
        assert_eq!(connected, 5);
        assert_eq!(rejected, 95);
    }
}
