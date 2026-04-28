//! Bounded TTL cache for gossipsub messages that hit
//! `PublishError::InsufficientPeers`.
//!
//! Audit 234 follow-up — third slice. The race documented in
//! `rust-libp2p` issue #5097: when validator A restarts, A's
//! reconnect can land on B's swarm BEFORE B's `ConnectionClosed`
//! for the old half-open connection has fired. gossipsub's
//! `on_connection_established` checks `other_established > 0` and
//! returns early — DOES NOT re-emit SUBSCRIBE control frames.
//! Symmetrically, A's SUBSCRIBE arrives at B before B has
//! inserted A into `peer_topics`, and gossipsub silently drops it
//! ("Subscription by unknown peer"). Net: TCP is up, but
//! `topic_peers["consensus"]` on B's side is missing A. Subsequent
//! publishes from B that target A return `InsufficientPeers` (or
//! get filtered out at the publish-recipient computation in
//! `behaviour.rs:625-683`).
//!
//! The race resolves itself within ~1-2 heartbeats (400ms in our
//! config × 2 = 800ms) when gossipsub's heartbeat re-emits
//! subscriptions. The window is small but the messages dropped
//! during it are exactly the ones that matter for liveness:
//! consensus votes, view-change Timeouts, finality votes,
//! block-broadcast announcements.
//!
//! Lighthouse (Eth2) absorbs this same race with a similar cache
//! — see `beacon_node/lighthouse_network/src/service/gossip_cache.rs`
//! upstream. We follow their pattern: stash on `InsufficientPeers`,
//! replay on `gossipsub::Event::Subscribed`. Per-message TTL
//! (~12s) so a stale cached message can't be replayed long after
//! the runtime has moved past it.

use libp2p::gossipsub::TopicHash;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Per-message TTL. Longer than the heartbeat-driven re-subscribe
/// window (~800 ms) by 15× so a slow heartbeat doesn't prematurely
/// drop a still-valid cached vote, but short enough that consensus
/// messages older than a few slots aren't replayed long after the
/// chain has moved on.
const DEFAULT_TTL: Duration = Duration::from_secs(12);

/// Hard cap on cache size. Pathological churn (many publishes
/// failing in a row) would otherwise grow without bound. 200 is
/// plenty for the few-slot window we care about; eviction is
/// FIFO so the oldest stuck-in-cache message gets dropped first.
const MAX_ENTRIES: usize = 200;

#[derive(Debug)]
struct CachedMessage {
    topic: TopicHash,
    data: Vec<u8>,
    expires_at: Instant,
}

/// Bounded FIFO of (topic, data, expiry) tuples awaiting replay.
#[derive(Debug, Default)]
pub struct GossipCache {
    entries: VecDeque<CachedMessage>,
}

impl GossipCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stash a publish that returned `InsufficientPeers`. The
    /// matching `gossipsub::Event::Subscribed` for any peer
    /// subscribing to this topic will trigger replay.
    pub fn stash(&mut self, topic: TopicHash, data: Vec<u8>) {
        if self.entries.len() >= MAX_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back(CachedMessage {
            topic,
            data,
            expires_at: Instant::now() + DEFAULT_TTL,
        });
    }

    /// Drain and return all live (non-expired) entries for `topic`.
    /// Called on `gossipsub::Event::Subscribed` so the runtime can
    /// re-publish the messages now that the mesh has someone to
    /// send to. Expired entries from any topic are dropped during
    /// the same pass.
    pub fn drain_topic(&mut self, topic: &TopicHash) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut drained = Vec::new();
        let mut keep = VecDeque::with_capacity(self.entries.len());
        while let Some(entry) = self.entries.pop_front() {
            if entry.expires_at <= now {
                continue;
            }
            if &entry.topic == topic {
                drained.push(entry.data);
            } else {
                keep.push_back(entry);
            }
        }
        self.entries = keep;
        drained
    }

    /// Drop expired entries. Called from a periodic tick so a
    /// topic that never gets re-subscribed doesn't pin stale
    /// messages until the next `drain_topic` walks past them.
    pub fn prune_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|e| e.expires_at > now);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::gossipsub::IdentTopic;

    fn topic(name: &str) -> TopicHash {
        IdentTopic::new(name).hash()
    }

    #[test]
    fn stash_and_drain_topic() {
        let mut c = GossipCache::new();
        c.stash(topic("a"), vec![1]);
        c.stash(topic("b"), vec![2]);
        c.stash(topic("a"), vec![3]);
        let drained_a = c.drain_topic(&topic("a"));
        assert_eq!(drained_a, vec![vec![1], vec![3]]);
        assert_eq!(c.len(), 1);
        let drained_b = c.drain_topic(&topic("b"));
        assert_eq!(drained_b, vec![vec![2]]);
        assert!(c.is_empty());
    }

    #[test]
    fn drain_skips_expired() {
        let mut c = GossipCache::new();
        // Insert a fake-expired entry by reaching in. Avoids
        // having to wait DEFAULT_TTL in tests.
        c.entries.push_back(CachedMessage {
            topic: topic("a"),
            data: vec![1],
            expires_at: Instant::now() - Duration::from_secs(1),
        });
        c.stash(topic("a"), vec![2]);
        let drained = c.drain_topic(&topic("a"));
        assert_eq!(drained, vec![vec![2]]);
    }

    #[test]
    fn cap_evicts_oldest() {
        let mut c = GossipCache::new();
        for i in 0..MAX_ENTRIES + 10 {
            c.stash(topic("a"), vec![i as u8]);
        }
        assert_eq!(c.len(), MAX_ENTRIES);
        let drained = c.drain_topic(&topic("a"));
        // First 10 are gone (FIFO eviction); we kept the last MAX_ENTRIES.
        assert_eq!(drained.len(), MAX_ENTRIES);
        assert_eq!(drained[0], vec![10u8]);
    }

    #[test]
    fn prune_expired_clears_old() {
        let mut c = GossipCache::new();
        c.entries.push_back(CachedMessage {
            topic: topic("a"),
            data: vec![1],
            expires_at: Instant::now() - Duration::from_secs(1),
        });
        c.stash(topic("a"), vec![2]);
        assert_eq!(c.len(), 2);
        c.prune_expired();
        assert_eq!(c.len(), 1);
    }
}
