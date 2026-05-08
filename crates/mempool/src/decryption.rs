//! Threshold decryption coordinator per Chapter 6, Section 6.5 Step 3.
//!
//! After the proposer broadcasts the encrypted block and ordering is locked:
//! 1. Each committee member generates a decryption share per tx
//! 2. Shares are broadcast to ALL committee members (not just proposer)
//! 3. Upon collecting 85+ shares → reconstruct and decrypt each tx
//! 4. Decrypted txs are validated (full validation after decryption)
//!
//! The decryption happens AFTER ordering is committed (QC formed).

use crate::encrypted::{decrypt_payload, EncryptedTx};
use pyde_crypto::falcon::{FalconPublicKey, FalconSecretKey};
use pyde_crypto::threshold::{generate_decryption_share, DecryptionShare, KeyShare};
use pyde_tx::types::{FeePayer, Transaction, TransactionType};
use std::fmt::Write;

/// Decryption state for a single block's worth of encrypted transactions.
#[derive(Debug)]
pub struct BlockDecryptor {
    /// The encrypted transactions to decrypt.
    pub encrypted_txs: Vec<EncryptedTx>,
    /// Collected decryption shares per transaction: tx_index → shares.
    shares: Vec<Vec<DecryptionShare>>,
    /// Threshold required for decryption.
    pub threshold: usize,
    /// Whether each tx has been successfully decrypted.
    decrypted: Vec<bool>,
    /// FALCON public keys for the current committee, indexed so that
    /// `committee_keys[k - 1]` belongs to the validator with share
    /// index `k`. TPL-301: combine_shares verifies each share's
    /// signature against this list before Lagrange interpolation.
    committee_keys: Vec<FalconPublicKey>,
}

impl BlockDecryptor {
    /// Create a new decryptor for a set of encrypted transactions.
    ///
    /// Returns an error if `threshold` is 0 or greater than 128 (committee size).
    pub fn new(
        encrypted_txs: Vec<EncryptedTx>,
        threshold: usize,
        committee_keys: Vec<FalconPublicKey>,
    ) -> Result<Self, String> {
        if !(1..=128).contains(&threshold) {
            return Err(format!(
                "decryption threshold must be in [1, 128], got {}",
                threshold
            ));
        }
        let n = encrypted_txs.len();
        Ok(Self {
            encrypted_txs,
            shares: vec![Vec::new(); n],
            threshold,
            decrypted: vec![false; n],
            committee_keys,
        })
    }

    /// Number of transactions to decrypt.
    pub fn tx_count(&self) -> usize {
        self.encrypted_txs.len()
    }

    /// Add a decryption share for a specific transaction.
    /// Returns true if this share was new (not a duplicate index).
    pub fn add_share(&mut self, tx_index: usize, share: DecryptionShare) -> bool {
        if tx_index >= self.shares.len() {
            return false;
        }

        // Check for duplicate share index
        if self.shares[tx_index].iter().any(|s| s.index == share.index) {
            return false;
        }

        self.shares[tx_index].push(share);
        true
    }

    /// Add decryption shares for ALL transactions from a single committee member.
    /// This is the common case: one member generates one share per tx.
    /// Returns the number of shares successfully added (excludes duplicates).
    ///
    /// TPL-301: each share is signed under `falcon_sk` so peers can
    /// authenticate it via `combine_shares` against the committee's
    /// FALCON public-key list. A signing failure on any tx aborts
    /// the whole batch (returns 0) so we never publish a partial
    /// set that other validators would treat as proof of
    /// participation.
    pub fn add_member_shares(
        &mut self,
        key_share: &KeyShare,
        falcon_sk: &FalconSecretKey,
    ) -> usize {
        // Generate all shares first to avoid borrow conflict
        let shares_res: Result<Vec<DecryptionShare>, &'static str> = self
            .encrypted_txs
            .iter()
            .map(|tx| generate_decryption_share(key_share, &tx.ciphertext, falcon_sk))
            .collect();
        let shares = match shares_res {
            Ok(v) => v,
            Err(_) => return 0,
        };

        if std::env::var("PYDE_DECRYPT_DIAG").is_ok() && !self.encrypted_txs.is_empty() {
            let kct_first8 = {
                let wire = self.encrypted_txs[0].ciphertext.to_wire_bytes();
                let mut out = [0u8; 8];
                let n = 8.min(wire.len());
                out[..n].copy_from_slice(&wire[..n]);
                out
            };
            let share_index_local = shares.first().map(|s| s.index).unwrap_or(0);
            eprintln!(
                "[decrypt-diag-add-member] my_key_share.index={} share_local.index={} num_txs={} kct[0..8]={:02x?}",
                key_share.index, share_index_local, self.encrypted_txs.len(), kct_first8
            );
        }

        let mut accepted = 0;
        for (i, share) in shares.into_iter().enumerate() {
            if self.add_share(i, share) {
                accepted += 1;
            }
        }
        accepted
    }

    /// Number of shares collected for a specific transaction.
    pub fn share_count(&self, tx_index: usize) -> usize {
        self.shares.get(tx_index).map_or(0, |s| s.len())
    }

    /// Whether a specific transaction has enough shares to decrypt.
    pub fn can_decrypt(&self, tx_index: usize) -> bool {
        self.share_count(tx_index) >= self.threshold
    }

    /// Whether ALL transactions have enough shares.
    pub fn all_ready(&self) -> bool {
        (0..self.encrypted_txs.len()).all(|i| self.can_decrypt(i))
    }

    /// Decrypt a single transaction. Returns the full Transaction or error.
    pub fn decrypt_tx(&mut self, tx_index: usize) -> Result<Transaction, String> {
        let tx = self.decrypt_tx_inner(tx_index)?;
        self.decrypted[tx_index] = true;
        Ok(tx)
    }

    /// Stateless decrypt for parallel callers — does NOT mark
    /// `self.decrypted[tx_index]`. Audit 401: hot path for
    /// `decrypt_all`'s rayon par_iter, where mutating shared
    /// per-call state would force serialization. The caller is
    /// responsible for marking the per-tx `decrypted` flags
    /// after the parallel decrypt completes.
    fn decrypt_tx_inner(&self, tx_index: usize) -> Result<Transaction, String> {
        if tx_index >= self.encrypted_txs.len() {
            return Err("tx_index out of bounds".into());
        }

        let share_count = self.shares.get(tx_index).map_or(0, |s| s.len());
        if share_count < self.threshold {
            return Err(format!(
                "insufficient shares: have {}, need {}",
                share_count, self.threshold
            ));
        }

        // Audit 406 diag: env-gated cross-node fingerprint so a
        // failing decryption can be cross-correlated against the
        // pool composition on every validator. Set
        // `PYDE_DECRYPT_DIAG=1` on the running node.
        if std::env::var("PYDE_DECRYPT_DIAG").is_ok() {
            let indices: Vec<usize> = self.shares[tx_index].iter().map(|s| s.index).collect();
            let wire = self.encrypted_txs[tx_index].ciphertext.to_wire_bytes();
            let kct_first8 = &wire[..8.min(wire.len())];
            let msg_len = wire.len();
            eprintln!(
                "[decrypt-diag] tx_index={} share_count={} threshold={} share_indices={:?} kct[0..8]={:02x?} msg_len={}",
                tx_index, share_count, self.threshold, indices, kct_first8, msg_len
            );
        }

        let (to, value, calldata) = decrypt_payload(
            &self.encrypted_txs[tx_index].ciphertext,
            &self.shares[tx_index],
            self.threshold,
            &self.committee_keys,
        )
        .inspect_err(|e| {
            if std::env::var("PYDE_DECRYPT_DIAG").is_ok() {
                let indices: Vec<usize> = self.shares[tx_index]
                    .iter()
                    .map(|s| s.index)
                    .collect();
                let to_hex = |b: &[u8]| -> String {
                    let mut s = String::with_capacity(b.len() * 2);
                    for x in b {
                        let _ = write!(s, "{:02x}", x);
                    }
                    s
                };
                let wire = self.encrypted_txs[tx_index].ciphertext.to_wire_bytes();
                let ct_hex = to_hex(&wire);
                let shares_hex: Vec<String> = self.shares[tx_index]
                    .iter()
                    .map(|s| to_hex(&s.to_bytes()))
                    .collect();
                eprintln!(
                    "[decrypt-diag-full] FAIL tx_index={} indices={:?} threshold={} ct={} shares={:?} err={}",
                    tx_index, indices, self.threshold, ct_hex, shares_hex, e
                );
            }
        })?;

        let enc_tx = &self.encrypted_txs[tx_index];
        Ok(Transaction {
            from: enc_tx.sender,
            to,
            value,
            data: calldata,
            gas_limit: enc_tx.gas_limit,
            nonce: enc_tx.nonce,
            signature: enc_tx.signature.clone(),
            fee_payer: FeePayer::Sender,
            access_list: enc_tx.access_list.clone(),
            deadline: enc_tx.deadline,
            chain_id: enc_tx.chain_id,
            tx_type: TransactionType::Standard,
        })
    }

    /// Decrypt all transactions in parallel. Returns the full list
    /// in original-index order, or stops at the first error.
    ///
    /// Audit 401: per-tx threshold decrypt (Lagrange combine over
    /// the share set + Kyber-768 decap + payload XOR + Transaction
    /// decode) is independent across txs in a block — each
    /// ciphertext has its own share vector and its own
    /// `EncryptedTx::ciphertext`. Pre-fix the path was a
    /// sequential `for` loop, capping per-block decrypt time at
    /// `n_txs * ~3ms` ≈ 300 ms for the laptop ceiling
    /// (`MAX_ENCRYPTED_TXS_PER_BLOCK = 100`). Post-fix the par_iter
    /// scales linearly with core count: an 8-core laptop fits the
    /// same 100-tx batch in ≈ 50 ms, leaving the slot's 400 ms QC
    /// deadline with comfortable headroom for FALCON re-verify +
    /// state apply. The wider win is on dedicated server cores
    /// where the per-block cap can safely rise.
    pub fn decrypt_all(&mut self) -> Result<Vec<Transaction>, String> {
        use rayon::prelude::*;
        let n = self.encrypted_txs.len();
        let txs: Result<Vec<Transaction>, String> = (0..n)
            .into_par_iter()
            .map(|i| self.decrypt_tx_inner(i))
            .collect();
        let txs = txs?;
        // Mark all decrypted only after the parallel pass succeeds.
        // Pre-fix `self.decrypted` was set per-iteration inside
        // `decrypt_tx`; in the parallel path we can't mutate
        // `self` from inside `par_iter`, so the flags update once
        // here. Functionally equivalent because no caller observes
        // `decrypted` mid-decrypt — it's checked after `decrypt_all`
        // returns.
        for d in self.decrypted.iter_mut() {
            *d = true;
        }
        Ok(txs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypted::encrypt_transaction;
    use pyde_account::address::{derive_eoa_address, Address};
    use pyde_crypto::falcon::{falcon_keygen, FalconPublicKey, FalconSecretKey};
    use pyde_crypto::threshold;
    use pyde_crypto::threshold::KeyShare;
    use pyde_tx::types::AccessEntry;

    fn make_keys(
        n: usize,
        t: usize,
    ) -> (
        threshold::ThresholdPublicKey,
        Vec<KeyShare>,
        Vec<FalconPublicKey>,
        Vec<FalconSecretKey>,
    ) {
        let (tpk, shares) = threshold::threshold_keygen(n, t).unwrap();
        let mut pks = Vec::with_capacity(n);
        let mut sks = Vec::with_capacity(n);
        for _ in 0..n {
            let (pk, sk) = falcon_keygen().unwrap();
            pks.push(pk);
            sks.push(sk);
        }
        (tpk, shares, pks, sks)
    }

    fn dummy_access_list() -> Vec<AccessEntry> {
        vec![AccessEntry {
            address: derive_eoa_address(b"contract"),
            reads: vec![[0x01; 32]],
            writes: vec![],
        }]
    }

    fn make_enc_tx(
        pk: &threshold::ThresholdPublicKey,
        to: Address,
        value: u128,
        calldata: &[u8],
    ) -> EncryptedTx {
        let sender = derive_eoa_address(b"sender");
        encrypt_transaction(
            sender,
            0,
            100_000,
            dummy_access_list(),
            None,
            1,
            vec![0xAA; 666],
            &to,
            value,
            calldata,
            pk,
        )
        .unwrap()
    }

    // ========== Task 0526: Successful decryption with 85 shares ==========

    #[test]
    fn decrypt_with_threshold_shares() {
        let (pk, key_shares, falcon_pks, falcon_sks) = make_keys(128, 85);
        let to = derive_eoa_address(b"recipient");
        let enc_tx = make_enc_tx(&pk, to, 5_000, b"transfer()");

        let mut decryptor = BlockDecryptor::new(vec![enc_tx], 85, falcon_pks).unwrap();

        // Add 85 shares
        for (i, ks) in key_shares.iter().enumerate().take(85) {
            decryptor.add_member_shares(ks, &falcon_sks[i]);
        }

        assert!(decryptor.can_decrypt(0));
        let tx = decryptor.decrypt_tx(0).unwrap();
        assert_eq!(tx.to, to);
        assert_eq!(tx.value, 5_000);
        assert_eq!(tx.data, b"transfer()");
    }

    // ========== Task 0527: Decryption fails with 84 shares ==========

    #[test]
    fn decrypt_fails_with_insufficient_shares() {
        let (pk, key_shares, falcon_pks, falcon_sks) = make_keys(128, 85);
        let to = derive_eoa_address(b"recipient");
        let enc_tx = make_enc_tx(&pk, to, 100, b"");

        let mut decryptor = BlockDecryptor::new(vec![enc_tx], 85, falcon_pks).unwrap();

        // Only 84 shares
        for (i, ks) in key_shares.iter().enumerate().take(84) {
            decryptor.add_member_shares(ks, &falcon_sks[i]);
        }

        assert!(!decryptor.can_decrypt(0));
        assert!(decryptor.decrypt_tx(0).is_err());
    }

    // ========== Task 0528: Invalid/duplicate share rejected ==========

    #[test]
    fn duplicate_share_rejected() {
        let (pk, key_shares, falcon_pks, falcon_sks) = make_keys(3, 2);
        let to = derive_eoa_address(b"recipient");
        let enc_tx = make_enc_tx(&pk, to, 100, b"");

        let mut decryptor = BlockDecryptor::new(vec![enc_tx.clone()], 2, falcon_pks).unwrap();

        // Add same share twice
        let share =
            generate_decryption_share(&key_shares[0], &enc_tx.ciphertext, &falcon_sks[0]).unwrap();
        assert!(decryptor.add_share(0, share.clone()));
        assert!(!decryptor.add_share(0, share)); // duplicate rejected

        assert_eq!(decryptor.share_count(0), 1); // only counted once
    }

    // ========== Multiple transactions ==========

    #[test]
    fn decrypt_multiple_txs() {
        let (pk, key_shares, falcon_pks, falcon_sks) = make_keys(3, 2);
        let to1 = derive_eoa_address(b"alice");
        let to2 = derive_eoa_address(b"bob");

        let txs = vec![
            make_enc_tx(&pk, to1, 1_000, b"call_a"),
            make_enc_tx(&pk, to2, 2_000, b"call_b"),
        ];

        let mut decryptor = BlockDecryptor::new(txs, 2, falcon_pks).unwrap();

        // Add 2 members' shares for all txs
        for (i, ks) in key_shares.iter().enumerate().take(2) {
            decryptor.add_member_shares(ks, &falcon_sks[i]);
        }

        assert!(decryptor.all_ready());

        let decrypted = decryptor.decrypt_all().unwrap();
        assert_eq!(decrypted.len(), 2);
        assert_eq!(decrypted[0].to, to1);
        assert_eq!(decrypted[0].value, 1_000);
        assert_eq!(decrypted[0].data, b"call_a");
        assert_eq!(decrypted[1].to, to2);
        assert_eq!(decrypted[1].value, 2_000);
        assert_eq!(decrypted[1].data, b"call_b");
    }

    // ========== Plaintext fields preserved ==========

    #[test]
    fn plaintext_fields_preserved_after_decrypt() {
        let (pk, key_shares, falcon_pks, falcon_sks) = make_keys(3, 2);
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"recipient");

        let enc_tx = encrypt_transaction(
            sender,
            42,
            500_000,
            dummy_access_list(),
            Some(1_000_000),
            7,
            vec![0xAA; 666],
            &to,
            999,
            b"data",
            &pk,
        )
        .unwrap();

        let mut decryptor = BlockDecryptor::new(vec![enc_tx], 2, falcon_pks).unwrap();
        for (i, ks) in key_shares.iter().enumerate().take(2) {
            decryptor.add_member_shares(ks, &falcon_sks[i]);
        }

        let tx = decryptor.decrypt_tx(0).unwrap();
        assert_eq!(tx.from, sender);
        assert_eq!(tx.nonce, 42);
        assert_eq!(tx.gas_limit, 500_000);
        assert_eq!(tx.deadline, Some(1_000_000));
        assert_eq!(tx.chain_id, 7);
        assert_eq!(tx.access_list.len(), 1);
    }

    // ========== Edge cases ==========

    #[test]
    fn out_of_bounds_tx_index() {
        let decryptor = BlockDecryptor::new(vec![], 2, Vec::new()).unwrap();
        assert!(!decryptor.can_decrypt(0));
        assert_eq!(decryptor.share_count(99), 0);
    }

    #[test]
    fn add_share_out_of_bounds() {
        let (pk, key_shares, _falcon_pks, falcon_sks) = make_keys(3, 2);
        let to = derive_eoa_address(b"recipient");
        let enc_tx = make_enc_tx(&pk, to, 100, b"");

        // Create share from the tx's ciphertext
        let share =
            generate_decryption_share(&key_shares[0], &enc_tx.ciphertext, &falcon_sks[0]).unwrap();

        // Empty decryptor — index 0 is out of bounds
        let mut decryptor = BlockDecryptor::new(vec![], 2, Vec::new()).unwrap();
        assert!(!decryptor.add_share(0, share));
    }
}
