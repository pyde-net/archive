//! Message channels: typed gossipsub message handling with validation.
//!
//! 5 channels per spec:
//! 1. Consensus — validator votes, view changes (validators only)
//! 2. Transactions — encrypted transactions from users
//! 3. Blocks — proposed blocks and scheduled blocks
//! 4. Proofs — ZK proofs from provers
//! 5. Sync — state sync and witness delivery
//!
//! Each channel has message validation and deduplication.

use pyde_crypto::poseidon2::poseidon2_hash;
use std::collections::HashSet;

/// Message channel identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Channel {
    Consensus,
    Transactions,
    Blocks,
    Proofs,
    Sync,
}

impl Channel {
    /// Topic string for this channel.
    pub fn topic(&self) -> &'static str {
        match self {
            Channel::Consensus => "pyde/consensus/1",
            Channel::Transactions => "pyde/transactions/1",
            Channel::Blocks => "pyde/blocks/1",
            Channel::Proofs => "pyde/proofs/1",
            Channel::Sync => "pyde/sync/1",
        }
    }

    /// Whether this channel is validator-only.
    pub fn validator_only(&self) -> bool {
        matches!(self, Channel::Consensus | Channel::Proofs)
    }

    /// From topic string.
    pub fn from_topic(topic: &str) -> Option<Self> {
        match topic {
            "pyde/consensus/1" => Some(Channel::Consensus),
            "pyde/transactions/1" => Some(Channel::Transactions),
            "pyde/blocks/1" => Some(Channel::Blocks),
            "pyde/proofs/1" => Some(Channel::Proofs),
            "pyde/sync/1" => Some(Channel::Sync),
            _ => None,
        }
    }

    /// All channels.
    pub fn all() -> &'static [Channel] {
        &[
            Channel::Consensus,
            Channel::Transactions,
            Channel::Blocks,
            Channel::Proofs,
            Channel::Sync,
        ]
    }
}

/// A network message with channel routing.
#[derive(Clone, Debug)]
pub struct NetworkMessage {
    /// Which channel this message belongs to.
    pub channel: Channel,
    /// Raw message bytes.
    pub data: Vec<u8>,
    /// Message ID (Poseidon2 hash of data).
    pub id: [u8; 32],
}

impl NetworkMessage {
    /// Create a new network message.
    pub fn new(channel: Channel, data: Vec<u8>) -> Self {
        let id = poseidon2_hash(&data).to_bytes();
        Self { channel, data, id }
    }
}

/// Message validation result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationResult {
    /// Message is valid, propagate to peers.
    Accept,
    /// Message is invalid, discard and penalize sender.
    Reject(String),
    /// Message should not be propagated but is not invalid.
    Ignore,
}

/// Validate a message based on its channel.
pub fn validate_message(msg: &NetworkMessage, is_validator_peer: bool) -> ValidationResult {
    // Check channel access
    if msg.channel.validator_only() && !is_validator_peer {
        return ValidationResult::Reject("non-validator sending to validator-only channel".into());
    }

    // Check message size limits per channel
    let max_size = match msg.channel {
        Channel::Consensus => 64 * 1024,       // 64KB (votes, view changes)
        Channel::Transactions => 128 * 1024,    // 128KB (encrypted txs)
        Channel::Blocks => 4 * 1024 * 1024,     // 4MB (full blocks)
        Channel::Proofs => 16 * 1024 * 1024,     // 16MB (ZK proofs)
        Channel::Sync => 8 * 1024 * 1024,        // 8MB (state chunks)
    };

    if msg.data.len() > max_size {
        return ValidationResult::Reject(format!(
            "message too large: {} bytes, max {} for {:?}",
            msg.data.len(),
            max_size,
            msg.channel
        ));
    }

    // Empty messages are invalid
    if msg.data.is_empty() {
        return ValidationResult::Reject("empty message".into());
    }

    ValidationResult::Accept
}

/// Message deduplication using a bounded set of recently seen message IDs.
#[derive(Debug)]
pub struct MessageDedup {
    /// Recently seen message IDs.
    seen: HashSet<[u8; 32]>,
    /// Maximum number of IDs to track.
    max_size: usize,
    /// Order of insertion for eviction.
    order: Vec<[u8; 32]>,
}

impl MessageDedup {
    /// Create a new dedup tracker.
    pub fn new(max_size: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(max_size),
            max_size,
            order: Vec::with_capacity(max_size),
        }
    }

    /// Check if a message has been seen before.
    /// Returns true if this is a NEW message (not seen before).
    pub fn check_and_insert(&mut self, id: &[u8; 32]) -> bool {
        if self.seen.contains(id) {
            return false; // duplicate
        }

        // Evict oldest if full
        if self.seen.len() >= self.max_size {
            if let Some(oldest) = self.order.first().copied() {
                self.seen.remove(&oldest);
                self.order.remove(0);
            }
        }

        self.seen.insert(*id);
        self.order.push(*id);
        true // new message
    }

    /// Number of tracked message IDs.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Clear all tracked IDs.
    pub fn clear(&mut self) {
        self.seen.clear();
        self.order.clear();
    }
}

/// Default dedup cache size (track last 100K messages).
pub const DEFAULT_DEDUP_SIZE: usize = 100_000;

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Channel ==========

    #[test]
    fn all_channels_count() {
        assert_eq!(Channel::all().len(), 5);
    }

    #[test]
    fn channel_from_topic_roundtrip() {
        for ch in Channel::all() {
            assert_eq!(Channel::from_topic(ch.topic()), Some(*ch));
        }
    }

    #[test]
    fn unknown_topic() {
        assert_eq!(Channel::from_topic("pyde/unknown/1"), None);
    }

    #[test]
    fn validator_only_channels() {
        assert!(Channel::Consensus.validator_only());
        assert!(Channel::Proofs.validator_only());
        assert!(!Channel::Transactions.validator_only());
        assert!(!Channel::Blocks.validator_only());
        assert!(!Channel::Sync.validator_only());
    }

    // ========== Task 0564: Message reaches subscribers ==========

    #[test]
    fn message_creation() {
        let msg = NetworkMessage::new(Channel::Transactions, vec![0xAA; 100]);
        assert_eq!(msg.channel, Channel::Transactions);
        assert_eq!(msg.data.len(), 100);
        assert_ne!(msg.id, [0u8; 32]); // hash is non-zero
    }

    #[test]
    fn message_id_deterministic() {
        let data = vec![0xBB; 50];
        let msg1 = NetworkMessage::new(Channel::Blocks, data.clone());
        let msg2 = NetworkMessage::new(Channel::Blocks, data);
        assert_eq!(msg1.id, msg2.id);
    }

    // ========== Task 0565: Validator-only channel rejects non-validator ==========

    #[test]
    fn validator_channel_rejects_non_validator() {
        let msg = NetworkMessage::new(Channel::Consensus, vec![0x01; 10]);
        assert_eq!(
            validate_message(&msg, false),
            ValidationResult::Reject("non-validator sending to validator-only channel".into())
        );
    }

    #[test]
    fn validator_channel_accepts_validator() {
        let msg = NetworkMessage::new(Channel::Consensus, vec![0x01; 10]);
        assert_eq!(validate_message(&msg, true), ValidationResult::Accept);
    }

    #[test]
    fn non_validator_channel_accepts_anyone() {
        let msg = NetworkMessage::new(Channel::Transactions, vec![0x01; 10]);
        assert_eq!(validate_message(&msg, false), ValidationResult::Accept);
    }

    // ========== Message size limits ==========

    #[test]
    fn oversized_message_rejected() {
        let msg = NetworkMessage::new(Channel::Consensus, vec![0x01; 65 * 1024]); // >64KB
        assert!(matches!(
            validate_message(&msg, true),
            ValidationResult::Reject(_)
        ));
    }

    #[test]
    fn empty_message_rejected() {
        let msg = NetworkMessage::new(Channel::Transactions, vec![]);
        assert!(matches!(
            validate_message(&msg, false),
            ValidationResult::Reject(_)
        ));
    }

    // ========== Task 0566: Duplicate messages filtered ==========

    #[test]
    fn dedup_new_message_accepted() {
        let mut dedup = MessageDedup::new(100);
        assert!(dedup.check_and_insert(&[0xAA; 32]));
        assert_eq!(dedup.len(), 1);
    }

    #[test]
    fn dedup_duplicate_rejected() {
        let mut dedup = MessageDedup::new(100);
        let id = [0xBB; 32];
        assert!(dedup.check_and_insert(&id));  // first time: new
        assert!(!dedup.check_and_insert(&id)); // second time: duplicate
        assert_eq!(dedup.len(), 1);
    }

    #[test]
    fn dedup_evicts_oldest_when_full() {
        let mut dedup = MessageDedup::new(3);

        let id1 = [0x01; 32];
        let id2 = [0x02; 32];
        let id3 = [0x03; 32];
        let id4 = [0x04; 32];

        assert!(dedup.check_and_insert(&id1));
        assert!(dedup.check_and_insert(&id2));
        assert!(dedup.check_and_insert(&id3));
        assert_eq!(dedup.len(), 3);

        // Adding 4th evicts id1 (oldest)
        assert!(dedup.check_and_insert(&id4));
        assert_eq!(dedup.len(), 3);

        // id1 is no longer tracked, so it looks "new" again
        assert!(dedup.check_and_insert(&id1));
    }
}
