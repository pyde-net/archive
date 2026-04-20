//! Encrypted transaction type per Chapter 9 (MEV Protection).
//!
//! Plaintext fields (visible to everyone):
//!   sender, nonce, gas_limit, access_list, deadline, chain_id, signature
//!
//! Encrypted fields (hidden until threshold decryption):
//!   to, value, calldata
//!
//! Encryption: threshold_encrypt(committee_pk, (to || value || calldata))
//!             → ThresholdCiphertext (Kyber encaps + symmetric encryption + MAC)

use pyde_account::address::Address;
use pyde_crypto::poseidon2::poseidon2_hash;
use pyde_crypto::threshold::{
    self, DecryptionShare, ThresholdCiphertext, ThresholdPublicKey,
};
use pyde_tx::types::AccessEntry;

/// Maximum transaction size (128 KB).
pub const MAX_TX_SIZE: usize = 128 * 1024;

/// An encrypted transaction in the mempool.
/// Plaintext fields are visible for validation and scheduling.
/// Encrypted fields are hidden until threshold decryption.
#[derive(Clone, Debug)]
pub struct EncryptedTx {
    // === Plaintext fields (visible) ===
    /// Sender address.
    pub sender: Address,
    /// Transaction nonce.
    pub nonce: u64,
    /// Gas limit.
    pub gas_limit: u64,
    /// Access list (which contracts/slots this tx touches).
    pub access_list: Vec<AccessEntry>,
    /// Deadline block height (tx expires after this).
    pub deadline: Option<u64>,
    /// Chain ID.
    pub chain_id: u64,
    /// FALCON-512 signature over all fields (plaintext + encrypted).
    pub signature: Vec<u8>,

    // === Encrypted fields (hidden) ===
    /// Threshold-encrypted payload: contains to, value, calldata.
    pub ciphertext: ThresholdCiphertext,

}

impl EncryptedTx {
    /// Total size in bytes (rough estimate for MAX_TX_SIZE check).
    pub fn size(&self) -> usize {
        32 // sender
        + 8 // nonce
        + 8 // gas_limit
        + self.access_list.len() * 68 // rough estimate per entry
        + 8 // deadline
        + 8 // chain_id
        + self.signature.len()
        + self.ciphertext.encrypted_len()
    }

    /// Hash of the encrypted transaction (for deduplication and tx_root).
    pub fn hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(96); // sender(32) + nonce(8) + gas(8) + chain(8) + ct_hash(32)
        buf.extend_from_slice(&self.sender);
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&self.gas_limit.to_le_bytes());
        buf.extend_from_slice(&self.chain_id.to_le_bytes());
        // Hash the ciphertext bytes for uniqueness
        buf.extend_from_slice(&poseidon2_hash(&self.ciphertext.to_bytes()).to_bytes());
        poseidon2_hash(&buf).to_bytes()
    }

    /// Serialize to bytes for block inclusion (wire format).
    pub fn to_bytes(&self) -> Vec<u8> {
        let ct_bytes = self.ciphertext.to_wire_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.sender);                          // 32
        buf.extend_from_slice(&self.nonce.to_le_bytes());             // 8
        buf.extend_from_slice(&self.gas_limit.to_le_bytes());         // 8
        buf.extend_from_slice(&self.chain_id.to_le_bytes());          // 8
        buf.push(self.deadline.is_some() as u8);                      // 1
        if let Some(d) = self.deadline { buf.extend_from_slice(&d.to_le_bytes()); }
        // Access list
        buf.extend_from_slice(&(self.access_list.len() as u32).to_le_bytes());
        for entry in &self.access_list {
            buf.extend_from_slice(&entry.address);
            buf.extend_from_slice(&(entry.reads.len() as u16).to_le_bytes());
            for r in &entry.reads { buf.extend_from_slice(r); }
            buf.extend_from_slice(&(entry.writes.len() as u16).to_le_bytes());
            for w in &entry.writes { buf.extend_from_slice(w); }
        }
        // Signature
        buf.extend_from_slice(&(self.signature.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.signature);
        // Ciphertext
        buf.extend_from_slice(&(ct_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&ct_bytes);
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 57 { return None; } // minimum: 32+8+8+8+1
        let mut off = 0;
        let mut sender = [0u8; 32];
        sender.copy_from_slice(&data[off..off+32]); off += 32;
        let nonce = u64::from_le_bytes(data[off..off+8].try_into().ok()?); off += 8;
        let gas_limit = u64::from_le_bytes(data[off..off+8].try_into().ok()?); off += 8;
        let chain_id = u64::from_le_bytes(data[off..off+8].try_into().ok()?); off += 8;
        let has_deadline = data[off]; off += 1;
        let deadline = if has_deadline != 0 {
            let d = u64::from_le_bytes(data[off..off+8].try_into().ok()?); off += 8;
            Some(d)
        } else { None };
        // Access list
        let al_count = u32::from_le_bytes(data[off..off+4].try_into().ok()?) as usize; off += 4;
        let mut access_list = Vec::with_capacity(al_count);
        for _ in 0..al_count {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&data[off..off+32]); off += 32;
            let rc = u16::from_le_bytes(data[off..off+2].try_into().ok()?) as usize; off += 2;
            let mut reads = Vec::with_capacity(rc);
            for _ in 0..rc { let mut k=[0u8;32]; k.copy_from_slice(&data[off..off+32]); off+=32; reads.push(k); }
            let wc = u16::from_le_bytes(data[off..off+2].try_into().ok()?) as usize; off += 2;
            let mut writes = Vec::with_capacity(wc);
            for _ in 0..wc { let mut k=[0u8;32]; k.copy_from_slice(&data[off..off+32]); off+=32; writes.push(k); }
            access_list.push(pyde_tx::types::AccessEntry { address: addr, reads, writes });
        }
        // Signature
        let sig_len = u32::from_le_bytes(data[off..off+4].try_into().ok()?) as usize; off += 4;
        let signature = data[off..off+sig_len].to_vec(); off += sig_len;
        // Ciphertext
        let ct_len = u32::from_le_bytes(data[off..off+4].try_into().ok()?) as usize; off += 4;
        let ciphertext = pyde_crypto::threshold::ThresholdCiphertext::from_wire_bytes(&data[off..off+ct_len])?;
        Some(Self { sender, nonce, gas_limit, access_list, deadline, chain_id, signature, ciphertext })
    }

    /// Check if the transaction has expired.
    pub fn is_expired(&self, current_block: u64) -> bool {
        match self.deadline {
            Some(d) => current_block >= d,
            None => false,
        }
    }

    /// Check if the transaction exceeds the size limit.
    pub fn is_oversized(&self) -> bool {
        self.size() > MAX_TX_SIZE
    }
}

/// Encrypt a transaction's sensitive fields using the committee's threshold public key.
///
/// Plaintext fields remain visible. The to/value/calldata are encrypted.
pub fn encrypt_transaction(
    sender: Address,
    nonce: u64,
    gas_limit: u64,
    access_list: Vec<AccessEntry>,
    deadline: Option<u64>,
    chain_id: u64,
    signature: Vec<u8>,
    to: &Address,
    value: u128,
    calldata: &[u8],
    committee_pk: &ThresholdPublicKey,
) -> Result<EncryptedTx, &'static str> {
    // Build plaintext payload: to || value || calldata
    let mut payload = Vec::with_capacity(48 + calldata.len()); // to(32) + value(16) + calldata
    payload.extend_from_slice(to);
    payload.extend_from_slice(&value.to_le_bytes());
    payload.extend_from_slice(calldata);

    // Encrypt using threshold Kyber
    let ciphertext = threshold::threshold_encrypt(committee_pk, &payload)
        .map_err(|_| "threshold encryption failed")?;

    Ok(EncryptedTx {
        sender,
        nonce,
        gas_limit,
        access_list,
        deadline,
        chain_id,
        signature,
        ciphertext,
    })
}

/// Decrypt an encrypted transaction's payload using combined decryption shares.
/// Returns (to, value, calldata) or error.
pub fn decrypt_payload(
    ciphertext: &ThresholdCiphertext,
    shares: &[DecryptionShare],
    threshold: usize,
) -> Result<(Address, u128, Vec<u8>), String> {
    let plaintext = threshold::combine_shares(shares, threshold, ciphertext)
        .map_err(|e| format!("decryption failed: {}", e))?;

    if plaintext.len() < 48 {
        return Err("decrypted payload too short".into());
    }

    let mut to = [0u8; 32];
    to.copy_from_slice(&plaintext[..32]);

    let mut value_bytes = [0u8; 16];
    value_bytes.copy_from_slice(&plaintext[32..48]);
    let value = u128::from_le_bytes(value_bytes);
    let calldata = plaintext[48..].to_vec();

    Ok((to, value, calldata))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::threshold::KeyShare;

    fn make_threshold_keys() -> (ThresholdPublicKey, Vec<KeyShare>) {
        threshold::threshold_keygen(3, 2).unwrap() // 2-of-3
    }

    #[test]
    fn encrypt_and_decrypt_roundtrip() {
        let (pk, key_shares) = make_threshold_keys();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"recipient");

        let enc_tx = encrypt_transaction(
            sender,
            42,
            500_000,
            vec![],
            Some(1_000_500),
            1,
            vec![0xAA; 64],
            &to,
            1_000_000,
            b"swap(TOKEN_X, 500)",
            &pk,
        )
        .unwrap();

        // Plaintext fields visible
        assert_eq!(enc_tx.sender, sender);
        assert_eq!(enc_tx.nonce, 42);
        assert_eq!(enc_tx.gas_limit, 500_000);

        // Generate decryption shares (need 2 of 3)
        let dec_shares: Vec<DecryptionShare> = key_shares
            .iter()
            .take(2)
            .map(|ks| threshold::generate_decryption_share(ks, &enc_tx.ciphertext))
            .collect();

        // Decrypt
        let (dec_to, dec_value, dec_calldata) =
            decrypt_payload(&enc_tx.ciphertext, &dec_shares, 2).unwrap();
        assert_eq!(dec_to, to);
        assert_eq!(dec_value, 1_000_000);
        assert_eq!(dec_calldata, b"swap(TOKEN_X, 500)");
    }

    #[test]
    fn insufficient_shares_fails() {
        let (pk, key_shares) = make_threshold_keys();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"recipient");

        let enc_tx = encrypt_transaction(
            sender, 0, 21_000, vec![], None, 1, vec![], &to, 100, b"", &pk,
        )
        .unwrap();

        // Only 1 share (need 2)
        let dec_shares = vec![
            threshold::generate_decryption_share(&key_shares[0], &enc_tx.ciphertext),
        ];

        assert!(decrypt_payload(&enc_tx.ciphertext, &dec_shares, 2).is_err());
    }

    #[test]
    fn hash_is_deterministic() {
        let (pk, _) = make_threshold_keys();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"recipient");

        let enc_tx = encrypt_transaction(
            sender, 0, 21_000, vec![], None, 1, vec![], &to, 100, b"", &pk,
        )
        .unwrap();

        assert_eq!(enc_tx.hash(), enc_tx.hash());
    }

    #[test]
    fn expired_check() {
        let (pk, _) = make_threshold_keys();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"recipient");

        let enc_tx = encrypt_transaction(
            sender, 0, 21_000, vec![], Some(100), 1, vec![], &to, 0, b"", &pk,
        )
        .unwrap();

        assert!(!enc_tx.is_expired(99));
        assert!(enc_tx.is_expired(100));
        assert!(enc_tx.is_expired(200));
    }

    #[test]
    fn no_deadline_never_expires() {
        let (pk, _) = make_threshold_keys();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"recipient");

        let enc_tx = encrypt_transaction(
            sender, 0, 21_000, vec![], None, 1, vec![], &to, 0, b"", &pk,
        )
        .unwrap();

        assert!(!enc_tx.is_expired(u64::MAX));
    }

    #[test]
    fn size_check() {
        let (pk, _) = make_threshold_keys();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"recipient");

        let small_tx = encrypt_transaction(
            sender, 0, 21_000, vec![], None, 1, vec![], &to, 0, b"", &pk,
        )
        .unwrap();
        assert!(!small_tx.is_oversized());

        let big_tx = encrypt_transaction(
            sender, 0, 21_000, vec![], None, 1, vec![], &to, 0, &vec![0xFF; 200_000], &pk,
        )
        .unwrap();
        assert!(big_tx.is_oversized());
    }
}
