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
use pyde_account::address::Address;
use pyde_crypto::threshold::{
    combine_shares, generate_decryption_share, DecryptionShare, KeyShare, ThresholdCiphertext,
};
use pyde_tx::types::{AccessEntry, FeePayer, Transaction, TransactionType};

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
}

impl BlockDecryptor {
    /// Create a new decryptor for a set of encrypted transactions.
    ///
    /// # Panics
    /// Panics if `threshold` is 0 or greater than 128 (committee size).
    pub fn new(encrypted_txs: Vec<EncryptedTx>, threshold: usize) -> Self {
        assert!(
            threshold >= 1 && threshold <= 128,
            "decryption threshold must be in [1, 128], got {}",
            threshold
        );
        let n = encrypted_txs.len();
        Self {
            encrypted_txs,
            shares: vec![Vec::new(); n],
            threshold,
            decrypted: vec![false; n],
        }
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
        if self.shares[tx_index]
            .iter()
            .any(|s| s.index == share.index)
        {
            return false;
        }

        self.shares[tx_index].push(share);
        true
    }

    /// Add decryption shares for ALL transactions from a single committee member.
    /// This is the common case: one member generates one share per tx.
    /// Returns the number of shares successfully added (excludes duplicates).
    pub fn add_member_shares(&mut self, key_share: &KeyShare) -> usize {
        // Generate all shares first to avoid borrow conflict
        let shares: Vec<DecryptionShare> = self
            .encrypted_txs
            .iter()
            .map(|tx| generate_decryption_share(key_share, &tx.ciphertext))
            .collect();

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

        let (to, value, calldata) = decrypt_payload(
            &self.encrypted_txs[tx_index].ciphertext,
            &self.shares[tx_index],
            self.threshold,
        )?;

        let enc_tx = &self.encrypted_txs[tx_index];
        let tx = Transaction {
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
        };

        self.decrypted[tx_index] = true;
        Ok(tx)
    }

    /// Decrypt all transactions. Returns the full list or stops at first error.
    pub fn decrypt_all(&mut self) -> Result<Vec<Transaction>, String> {
        let mut txs = Vec::with_capacity(self.encrypted_txs.len());
        for i in 0..self.encrypted_txs.len() {
            txs.push(self.decrypt_tx(i)?);
        }
        Ok(txs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypted::encrypt_transaction;
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::threshold;
    use pyde_tx::types::AccessEntry;

    fn make_keys(n: usize, t: usize) -> (threshold::ThresholdPublicKey, Vec<KeyShare>) {
        threshold::threshold_keygen(n, t)
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
            sender, 0, 100_000, dummy_access_list(), None, 1,
            vec![0xAA; 666], &to, value, calldata, pk,
        )
    }

    // ========== Task 0526: Successful decryption with 85 shares ==========

    #[test]
    fn decrypt_with_threshold_shares() {
        let (pk, key_shares) = make_keys(128, 85);
        let to = derive_eoa_address(b"recipient");
        let enc_tx = make_enc_tx(&pk, to, 5_000, b"transfer()");

        let mut decryptor = BlockDecryptor::new(vec![enc_tx], 85);

        // Add 85 shares
        for ks in key_shares.iter().take(85) {
            decryptor.add_member_shares(ks);
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
        let (pk, key_shares) = make_keys(128, 85);
        let to = derive_eoa_address(b"recipient");
        let enc_tx = make_enc_tx(&pk, to, 100, b"");

        let mut decryptor = BlockDecryptor::new(vec![enc_tx], 85);

        // Only 84 shares
        for ks in key_shares.iter().take(84) {
            decryptor.add_member_shares(ks);
        }

        assert!(!decryptor.can_decrypt(0));
        assert!(decryptor.decrypt_tx(0).is_err());
    }

    // ========== Task 0528: Invalid/duplicate share rejected ==========

    #[test]
    fn duplicate_share_rejected() {
        let (pk, key_shares) = make_keys(3, 2);
        let to = derive_eoa_address(b"recipient");
        let enc_tx = make_enc_tx(&pk, to, 100, b"");

        let mut decryptor = BlockDecryptor::new(vec![enc_tx.clone()], 2);

        // Add same share twice
        let share = generate_decryption_share(&key_shares[0], &enc_tx.ciphertext);
        assert!(decryptor.add_share(0, share.clone()));
        assert!(!decryptor.add_share(0, share)); // duplicate rejected

        assert_eq!(decryptor.share_count(0), 1); // only counted once
    }

    // ========== Multiple transactions ==========

    #[test]
    fn decrypt_multiple_txs() {
        let (pk, key_shares) = make_keys(3, 2);
        let to1 = derive_eoa_address(b"alice");
        let to2 = derive_eoa_address(b"bob");

        let txs = vec![
            make_enc_tx(&pk, to1, 1_000, b"call_a"),
            make_enc_tx(&pk, to2, 2_000, b"call_b"),
        ];

        let mut decryptor = BlockDecryptor::new(txs, 2);

        // Add 2 members' shares for all txs
        for ks in key_shares.iter().take(2) {
            decryptor.add_member_shares(ks);
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
        let (pk, key_shares) = make_keys(3, 2);
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"recipient");

        let enc_tx = encrypt_transaction(
            sender, 42, 500_000, dummy_access_list(), Some(1_000_000), 7,
            vec![0xAA; 666], &to, 999, b"data", &pk,
        );

        let mut decryptor = BlockDecryptor::new(vec![enc_tx], 2);
        for ks in key_shares.iter().take(2) {
            decryptor.add_member_shares(ks);
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
        let decryptor = BlockDecryptor::new(vec![], 2);
        assert!(!decryptor.can_decrypt(0));
        assert_eq!(decryptor.share_count(99), 0);
    }

    #[test]
    fn add_share_out_of_bounds() {
        let (pk, key_shares) = make_keys(3, 2);
        let to = derive_eoa_address(b"recipient");
        let enc_tx = make_enc_tx(&pk, to, 100, b"");

        // Create share from the tx's ciphertext
        let share = generate_decryption_share(&key_shares[0], &enc_tx.ciphertext);

        // Empty decryptor — index 0 is out of bounds
        let mut decryptor = BlockDecryptor::new(vec![], 2);
        assert!(!decryptor.add_share(0, share));
    }
}
