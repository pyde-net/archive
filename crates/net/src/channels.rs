//! Gossipsub topic channels for Pyde.
//!
//! 5 channels:
//! 1. Consensus — validator votes / view changes (validators only)
//! 2. Transactions — plaintext user txs
//! 3. EncryptedTransactions — MEV-protected encrypted txs
//! 4. Blocks — proposed blocks + encrypted-tx bundles
//! 5. Sync — state sync requests / responses
//!
//! Audit 339: this module previously also exposed `NetworkMessage`,
//! `ValidationResult`, `validate_message`, and `MessageDedup` — all
//! defined and tested in isolation but never wired into any
//! production path. Their roles are now fully covered by the
//! gossipsub layer:
//!   - `validate_message`'s validator-only check is enforced at
//!     subscribe time (`subscribe_topics` only adds the consensus
//!     topic for validators) — non-validators that try to publish
//!     fail at the libp2p layer because they aren't subscribed.
//!   - `validate_message`'s size cap is enforced by gossipsub's
//!     `max_transmit_size` (audit 333: 4 MB) on the
//!     ConfigBuilder.
//!   - `MessageDedup` is replaced by gossipsub's own
//!     `duplicate_cache_time` (60 s) on every received message.
//!
//! Deleted to remove dead code that gave a false impression of an
//! extra validation layer on top of gossipsub. Adding it back
//! should be considered a regression unless an actual call site is
//! plumbed in the same PR.

/// Message channel identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Channel {
    /// Validator consensus messages (votes, view-changes).
    Consensus,
    /// Plaintext user transactions.
    Transactions,
    /// MEV-protected encrypted transactions (audit-027 / item 227).
    EncryptedTransactions,
    /// Proposed blocks + encrypted-tx bundles.
    Blocks,
    /// State sync requests / responses.
    Sync,
}

impl Channel {
    /// Gossipsub topic string for this channel.
    pub fn topic(&self) -> &'static str {
        match self {
            Channel::Consensus => "pyde/consensus/1",
            Channel::Transactions => "pyde/transactions/1",
            Channel::EncryptedTransactions => "pyde/encrypted_transactions/1",
            Channel::Blocks => "pyde/blocks/1",
            Channel::Sync => "pyde/sync/1",
        }
    }

    /// Whether this channel is validator-only at subscribe time.
    /// Non-validators don't subscribe (see `subscribe_topics`), so
    /// the gossipsub layer drops their publishes before delivery.
    pub fn validator_only(&self) -> bool {
        matches!(self, Channel::Consensus)
    }

    /// Reverse lookup: parse a topic string back to a Channel.
    pub fn from_topic(topic: &str) -> Option<Self> {
        match topic {
            "pyde/consensus/1" => Some(Channel::Consensus),
            "pyde/transactions/1" => Some(Channel::Transactions),
            "pyde/encrypted_transactions/1" => Some(Channel::EncryptedTransactions),
            "pyde/blocks/1" => Some(Channel::Blocks),
            "pyde/sync/1" => Some(Channel::Sync),
            _ => None,
        }
    }

    /// Every channel.
    pub fn all() -> &'static [Channel] {
        &[
            Channel::Consensus,
            Channel::Transactions,
            Channel::EncryptedTransactions,
            Channel::Blocks,
            Channel::Sync,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(!Channel::Transactions.validator_only());
        assert!(!Channel::EncryptedTransactions.validator_only());
        assert!(!Channel::Blocks.validator_only());
        assert!(!Channel::Sync.validator_only());
    }
}
