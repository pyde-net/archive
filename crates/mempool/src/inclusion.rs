//! Mandatory-inclusion audit for the threshold-encrypted mempool (task 026).
//!
//! The invariant: a proposer cannot censor encrypted transactions they have
//! seen. At block-build time, every encrypted_tx the proposer has held in
//! mempool for at least `grace_slots` slots must be included in the block
//! body — unless the block's gas budget is already exhausted.
//!
//! The audit runs on each validator against their own mempool view when they
//! receive a compact block. Violations → skip vote (task 3.2 enforcement
//! layer). Committee-aggregated views and slashing evidence are post-mainnet
//! work — see MAINNET_PLAN.md "Deferred to post-mainnet".

use crate::encrypted::EncryptedTx;
use std::collections::HashSet;

/// Result of an inclusion audit over one block proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionAuditResult {
    /// Hashes of encrypted_txs the validator has held longer than the grace
    /// window that are absent from the block AND would have fit in the
    /// remaining gas budget. A non-empty list is evidence of censorship.
    pub missing_older_than_grace: Vec<[u8; 32]>,
    /// Total gas committed by the encrypted_txs actually present in the
    /// block. Reported for telemetry + future aggregate checks.
    pub gas_used_by_encrypted: u64,
    /// Gas headroom left after the block's encrypted set. A tx is only flagged
    /// as "should have been included" if its `gas_limit` fits here.
    pub gas_remaining: u64,
}

impl InclusionAuditResult {
    /// True when the audit found no inclusion violations.
    pub fn is_clean(&self) -> bool {
        self.missing_older_than_grace.is_empty()
    }
}

/// Audit a block's encrypted_tx inclusion against a validator's local view.
///
/// Parameters:
/// - `mempool_view`: (tx, first_seen_slot) pairs the validator currently
///   holds in mempool.
/// - `block_encrypted_tx_hashes`: hashes of the encrypted_txs present in the
///   block body (or compact-block manifest).
/// - `block_encrypted_gas`: aggregate `gas_limit` of the block's encrypted
///   entries — provided by the caller because only they can resolve each
///   hash back to an EncryptedTx (the validator's local mempool may be
///   missing some entries, which is fine for the audit).
/// - `current_slot`: the slot of the proposal being audited.
/// - `grace_slots`: how many slots a tx must have been in mempool before
///   its absence counts as censorship. Mainnet default is 2 (≈800ms).
/// - `gas_ceiling`: block gas budget.
///
/// Semantics:
/// - A tx first seen this slot (or within `grace_slots - 1`) is *not*
///   flagged when missing — the proposer may simply not have received it yet.
/// - A tx older than grace that is missing is flagged ONLY if its gas_limit
///   fits in the block's remaining gas budget. Otherwise the block was full
///   and the omission is legitimate.
/// - A tx older than grace that IS in the block is silently accepted.
/// End-to-end audit over a block's raw encrypted_txs bytes.
///
/// Convenience wrapper around `audit_inclusion` for the reception path in
/// `pyde-node`. Parses each entry of `block_encrypted_tx_bytes` into an
/// `EncryptedTx`, builds the hash set and gas total, and forwards to the
/// lower-level audit. Malformed entries are silently skipped — they were
/// already rejected by the block_processor's body validation before this
/// audit runs.
pub fn audit_block_inclusion<'a, I>(
    block_encrypted_tx_bytes: &[Vec<u8>],
    mempool_view: I,
    current_slot: u64,
    grace_slots: u64,
    gas_ceiling: u64,
) -> InclusionAuditResult
where
    I: IntoIterator<Item = (&'a EncryptedTx, u64)>,
{
    let mut block_hashes: HashSet<[u8; 32]> =
        HashSet::with_capacity(block_encrypted_tx_bytes.len());
    let mut block_gas: u64 = 0;
    for bytes in block_encrypted_tx_bytes {
        if let Some(etx) = EncryptedTx::from_bytes(bytes) {
            block_hashes.insert(etx.hash());
            block_gas = block_gas.saturating_add(etx.gas_limit);
        }
    }
    audit_inclusion(
        mempool_view,
        &block_hashes,
        block_gas,
        current_slot,
        grace_slots,
        gas_ceiling,
    )
}

pub fn audit_inclusion<'a, I>(
    mempool_view: I,
    block_encrypted_tx_hashes: &HashSet<[u8; 32]>,
    block_encrypted_gas: u64,
    current_slot: u64,
    grace_slots: u64,
    gas_ceiling: u64,
) -> InclusionAuditResult
where
    I: IntoIterator<Item = (&'a EncryptedTx, u64)>,
{
    let gas_remaining = gas_ceiling.saturating_sub(block_encrypted_gas);
    let mut missing = Vec::new();

    for (tx, first_seen) in mempool_view {
        let age = current_slot.saturating_sub(first_seen);
        if age < grace_slots {
            // Too new — proposer may not have it yet. Not evidence of
            // censorship.
            continue;
        }

        let h = tx.hash();
        if block_encrypted_tx_hashes.contains(&h) {
            continue;
        }

        if tx.gas_limit > gas_remaining {
            // Block was full when this tx would have needed to fit.
            // Missing is legitimate.
            continue;
        }

        missing.push(h);
    }

    InclusionAuditResult {
        missing_older_than_grace: missing,
        gas_used_by_encrypted: block_encrypted_gas,
        gas_remaining,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypted::{encrypt_transaction, EncryptedTx};
    use pyde_crypto::threshold::{threshold_keygen, ThresholdPublicKey};
    use pyde_tx::types::AccessEntry;

    const GAS_CEILING: u64 = 400_000_000;
    const GRACE: u64 = 2;

    fn access_list() -> Vec<AccessEntry> {
        vec![AccessEntry {
            address: [0x01; 32],
            reads: vec![[0x01; 32]],
            writes: vec![],
        }]
    }

    fn make_tx(pk: &ThresholdPublicKey, seed: u8, gas: u64) -> EncryptedTx {
        encrypt_transaction(
            [seed; 32],
            seed as u64,
            gas,
            access_list(),
            None,
            1,
            vec![0xAA; 666],
            &[seed; 32],
            100,
            &[seed, seed],
            pk,
        )
        .unwrap()
    }

    #[test]
    fn honest_block_includes_everything_clean_audit() {
        let (pk, _) = threshold_keygen(3, 2).unwrap();
        let t1 = make_tx(&pk, 0xAA, 21_000);
        let t2 = make_tx(&pk, 0xBB, 21_000);
        let view = vec![(&t1, 5u64), (&t2, 5u64)];
        let block_hashes: HashSet<[u8; 32]> =
            [t1.hash(), t2.hash()].into_iter().collect();

        let result = audit_inclusion(
            view, &block_hashes, 42_000, /* slot */ 10, GRACE, GAS_CEILING,
        );
        assert!(result.is_clean());
    }

    #[test]
    fn censored_aged_tx_is_flagged() {
        let (pk, _) = threshold_keygen(3, 2).unwrap();
        let included = make_tx(&pk, 0xAA, 21_000);
        let censored = make_tx(&pk, 0xBB, 21_000);
        let view = vec![(&included, 5u64), (&censored, 5u64)];
        let block_hashes: HashSet<[u8; 32]> = [included.hash()].into_iter().collect();

        // current_slot=10, first_seen=5, age=5 > grace=2 → aged
        // block_encrypted_gas=21_000 → gas_remaining=GAS_CEILING-21_000 (plenty)
        let result = audit_inclusion(
            view, &block_hashes, 21_000, 10, GRACE, GAS_CEILING,
        );
        assert!(!result.is_clean());
        assert_eq!(result.missing_older_than_grace, vec![censored.hash()]);
    }

    #[test]
    fn new_tx_within_grace_window_is_ignored() {
        let (pk, _) = threshold_keygen(3, 2).unwrap();
        let fresh = make_tx(&pk, 0xCC, 21_000);
        // first_seen=9, current_slot=10, age=1 < grace=2 → too new
        let view = vec![(&fresh, 9u64)];
        let block_hashes: HashSet<[u8; 32]> = HashSet::new();

        let result = audit_inclusion(view, &block_hashes, 0, 10, GRACE, GAS_CEILING);
        assert!(result.is_clean());
    }

    #[test]
    fn full_block_legitimately_excludes_tx() {
        let (pk, _) = threshold_keygen(3, 2).unwrap();
        let excluded = make_tx(&pk, 0xDD, 50_000);
        let view = vec![(&excluded, 5u64)];
        let block_hashes: HashSet<[u8; 32]> = HashSet::new();

        // Block's existing encrypted gas = ceiling - 10K → gas_remaining = 10K.
        // excluded.gas_limit = 50K > 10K, so exclusion is legitimate.
        let result = audit_inclusion(
            view, &block_hashes,
            GAS_CEILING - 10_000, 10, GRACE, GAS_CEILING,
        );
        assert!(result.is_clean());
    }

    #[test]
    fn empty_mempool_produces_clean_audit() {
        let block_hashes: HashSet<[u8; 32]> = HashSet::new();
        let view: Vec<(&EncryptedTx, u64)> = vec![];
        let result = audit_inclusion(view, &block_hashes, 0, 10, GRACE, GAS_CEILING);
        assert!(result.is_clean());
    }

    #[test]
    fn aged_tx_fits_when_gas_remaining_equals_gas_limit() {
        // Boundary: tx.gas_limit == gas_remaining → still flagged as
        // should-have-fit. Only strict > causes exemption.
        let (pk, _) = threshold_keygen(3, 2).unwrap();
        let boundary = make_tx(&pk, 0xEE, 21_000);
        let view = vec![(&boundary, 5u64)];
        let block_hashes: HashSet<[u8; 32]> = HashSet::new();

        let result = audit_inclusion(
            view, &block_hashes,
            GAS_CEILING - 21_000, 10, GRACE, GAS_CEILING,
        );
        assert_eq!(result.missing_older_than_grace, vec![boundary.hash()]);
    }

    #[test]
    fn multiple_aged_censored_are_all_reported() {
        let (pk, _) = threshold_keygen(3, 2).unwrap();
        let a = make_tx(&pk, 0x01, 21_000);
        let b = make_tx(&pk, 0x02, 21_000);
        let c = make_tx(&pk, 0x03, 21_000);
        let view = vec![(&a, 4u64), (&b, 4u64), (&c, 4u64)];
        let block_hashes: HashSet<[u8; 32]> = HashSet::new();

        let result = audit_inclusion(view, &block_hashes, 0, 10, GRACE, GAS_CEILING);
        assert_eq!(result.missing_older_than_grace.len(), 3);
    }

    // ========== audit_block_inclusion (byte-level wrapper) ==========

    #[test]
    fn audit_block_inclusion_passes_honest_block() {
        let (pk, _) = threshold_keygen(3, 2).unwrap();
        let a = make_tx(&pk, 0xAA, 21_000);
        let b = make_tx(&pk, 0xBB, 21_000);
        let view = vec![(&a, 5u64), (&b, 5u64)];

        // Block body contains both txs as raw bytes — the shape node.rs
        // passes in from block.body.encrypted_txs.
        let block_bytes = vec![a.to_bytes(), b.to_bytes()];

        let result = audit_block_inclusion(&block_bytes, view, 10, GRACE, GAS_CEILING);
        assert!(result.is_clean());
        assert_eq!(result.gas_used_by_encrypted, 42_000);
    }

    #[test]
    fn audit_block_inclusion_flags_censored_aged_tx_via_bytes() {
        let (pk, _) = threshold_keygen(3, 2).unwrap();
        let included = make_tx(&pk, 0xAA, 21_000);
        let censored = make_tx(&pk, 0xBB, 21_000);
        let view = vec![(&included, 5u64), (&censored, 5u64)];

        // Block bytes only contain `included`.
        let block_bytes = vec![included.to_bytes()];

        let result = audit_block_inclusion(&block_bytes, view, 10, GRACE, GAS_CEILING);
        assert!(!result.is_clean());
        assert_eq!(result.missing_older_than_grace, vec![censored.hash()]);
    }

    #[test]
    fn audit_block_inclusion_skips_malformed_bytes() {
        // Body validator already rejects these before the audit fires,
        // but the helper must not panic or mis-attribute them.
        let (pk, _) = threshold_keygen(3, 2).unwrap();
        let tx = make_tx(&pk, 0xAA, 21_000);
        let view = vec![(&tx, 5u64)];

        // Garbage byte blob mixed with a real one.
        let block_bytes = vec![vec![0xFF; 10], tx.to_bytes()];

        let result = audit_block_inclusion(&block_bytes, view, 10, GRACE, GAS_CEILING);
        assert!(result.is_clean());
        assert_eq!(result.gas_used_by_encrypted, 21_000);
    }
}
