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
use pyde_crypto::falcon::FalconPublicKey;
use pyde_crypto::poseidon2::poseidon2_hash;
use pyde_crypto::threshold::{self, DecryptionShare, ThresholdCiphertext, ThresholdPublicKey};
use pyde_tx::types::AccessEntry;

/// Maximum transaction size (128 KB).
pub const MAX_TX_SIZE: usize = 128 * 1024;

/// Decoder caps for `EncryptedTx::from_bytes`. Each length field a peer
/// supplies must be capped before it drives a `Vec::with_capacity`,
/// otherwise a single malformed RPC / gossip blob can request an
/// allocation large enough to abort the process under
/// `panic = "abort"`. Caps mirror the `pyde_node::wire::Decoder`
/// pattern (audit-204) sized down for the encrypted-tx payload shape.
const MAX_ACCESS_ENTRIES: usize = 1024;
const MAX_KEYS_PER_ACCESS_ENTRY: usize = 1024;
/// FALCON-512 signatures are ~600-690 bytes in practice; the pool's
/// structural-only path accepts [500, 1000]. Cap at 1024 for headroom.
const MAX_SIG_LEN: usize = 1024;
/// TPL-410: cap derived from the actual ciphertext layout, not the
/// loose `MAX_TX_SIZE` bound. Wire format from
/// `ThresholdCiphertext::to_wire_bytes` is
///   `[ct_len:4][kyber_ct:1088][msg_len:4][encrypted_msg:N][mac:32]`
/// where `N = 48-byte payload header + calldata`, and calldata is
/// bounded by `pyde_tx::validation::MAX_CALLDATA = 64 KB`. Sum:
///   `4 + 1088 + 4 + 48 + 65 536 + 32 = 66 712 ≈ 65 KB`.
/// Round up to 72 KB for ~7 KB headroom against a future format bump
/// (version byte, additional length field, etc.). Pre-fix the cap
/// was the full 128 KB tx-size budget — a malicious peer could
/// claim a 128 KB ciphertext, drive a `Vec::with_capacity(128 KB)`
/// per malformed gossip blob, and trivially DoS the validator's
/// allocator under `panic = "abort"`.
const MAX_CT_LEN: usize = 72 * 1024;

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

/// Bounds-checked cursor used by `EncryptedTx::from_bytes`. Mirrors
/// `pyde_node::wire::Decoder` (audit-204) but lives here so the
/// mempool crate doesn't take a node dependency. Every read returns
/// `None` on underrun; length fields go through `u16_count` /
/// `u32_count` so an attacker-supplied count is capped before any
/// `Vec::with_capacity`.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Some(u64::from_le_bytes(a))
    }

    fn bytes32(&mut self) -> Option<[u8; 32]> {
        let b = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Some(a)
    }

    fn u16_count(&mut self, max: usize) -> Option<usize> {
        let n = self.u16()? as usize;
        if n > max {
            return None;
        }
        Some(n)
    }

    fn u32_count(&mut self, max: usize) -> Option<usize> {
        let n = self.u32()? as usize;
        if n > max {
            return None;
        }
        Some(n)
    }
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
        buf.extend_from_slice(&self.sender); // 32
        buf.extend_from_slice(&self.nonce.to_le_bytes()); // 8
        buf.extend_from_slice(&self.gas_limit.to_le_bytes()); // 8
        buf.extend_from_slice(&self.chain_id.to_le_bytes()); // 8
        buf.push(self.deadline.is_some() as u8); // 1
        if let Some(d) = self.deadline {
            buf.extend_from_slice(&d.to_le_bytes());
        }
        // Access list
        buf.extend_from_slice(&(self.access_list.len() as u32).to_le_bytes());
        for entry in &self.access_list {
            buf.extend_from_slice(&entry.address);
            buf.extend_from_slice(&(entry.reads.len() as u16).to_le_bytes());
            for r in &entry.reads {
                buf.extend_from_slice(r);
            }
            buf.extend_from_slice(&(entry.writes.len() as u16).to_le_bytes());
            for w in &entry.writes {
                buf.extend_from_slice(w);
            }
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
    ///
    /// Reachable from `pyde_sendRawEncryptedTransaction`, peer-sent
    /// `EncryptedTxBundle` blobs, and `inclusion::audit_block_inclusion`
    /// — every byte here is attacker-controlled. The decoder must
    /// return `None` (never panic, never abort) for any input. Length
    /// fields are capped before any `Vec::with_capacity` to avoid
    /// allocation-amplification DoS.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() > MAX_TX_SIZE {
            return None;
        }
        let mut cur = Cursor::new(data);
        let sender = cur.bytes32()?;
        let nonce = cur.u64()?;
        let gas_limit = cur.u64()?;
        let chain_id = cur.u64()?;
        let has_deadline = cur.u8()?;
        let deadline = if has_deadline != 0 {
            Some(cur.u64()?)
        } else {
            None
        };
        let al_count = cur.u32_count(MAX_ACCESS_ENTRIES)?;
        let mut access_list = Vec::with_capacity(al_count);
        for _ in 0..al_count {
            let address = cur.bytes32()?;
            let read_count = cur.u16_count(MAX_KEYS_PER_ACCESS_ENTRY)?;
            let mut reads = Vec::with_capacity(read_count);
            for _ in 0..read_count {
                reads.push(cur.bytes32()?);
            }
            let write_count = cur.u16_count(MAX_KEYS_PER_ACCESS_ENTRY)?;
            let mut writes = Vec::with_capacity(write_count);
            for _ in 0..write_count {
                writes.push(cur.bytes32()?);
            }
            access_list.push(pyde_tx::types::AccessEntry {
                address,
                reads,
                writes,
            });
        }
        let sig_len = cur.u32_count(MAX_SIG_LEN)?;
        let signature = cur.take(sig_len)?.to_vec();
        let ct_len = cur.u32_count(MAX_CT_LEN)?;
        let ct_bytes = cur.take(ct_len)?;
        let ciphertext = pyde_crypto::threshold::ThresholdCiphertext::from_wire_bytes(ct_bytes)?;
        Some(Self {
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
///
/// TPL-301: `committee_keys` carries the FALCON public keys of every
/// committee member, indexed so that `committee_keys[k - 1]` matches
/// the validator who holds share-index `k`. Each share's FALCON sig
/// is verified against this list before the share enters Lagrange
/// interpolation; a tampered or unsigned share is rejected with the
/// same `ORACLE_SAFE_ERR` as a downstream MAC failure (audit 360).
pub fn decrypt_payload(
    ciphertext: &ThresholdCiphertext,
    shares: &[DecryptionShare],
    threshold: usize,
    committee_keys: &[FalconPublicKey],
) -> Result<(Address, u128, Vec<u8>), String> {
    let plaintext = threshold::combine_shares(shares, threshold, ciphertext, committee_keys)
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
    use pyde_crypto::falcon::{falcon_keygen, FalconSecretKey};
    use pyde_crypto::threshold::KeyShare;

    fn make_threshold_keys() -> (
        ThresholdPublicKey,
        Vec<KeyShare>,
        Vec<FalconPublicKey>,
        Vec<FalconSecretKey>,
    ) {
        let (tpk, shares) = threshold::threshold_keygen(3, 2).unwrap(); // 2-of-3
        let mut pks = Vec::with_capacity(3);
        let mut sks = Vec::with_capacity(3);
        for _ in 0..3 {
            let (pk, sk) = falcon_keygen().unwrap();
            pks.push(pk);
            sks.push(sk);
        }
        (tpk, shares, pks, sks)
    }

    #[test]
    fn encrypt_and_decrypt_roundtrip() {
        let (pk, key_shares, falcon_pks, falcon_sks) = make_threshold_keys();
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
            .enumerate()
            .take(2)
            .map(|(i, ks)| {
                threshold::generate_decryption_share(ks, &enc_tx.ciphertext, &falcon_sks[i])
                    .unwrap()
            })
            .collect();

        // Decrypt
        let (dec_to, dec_value, dec_calldata) =
            decrypt_payload(&enc_tx.ciphertext, &dec_shares, 2, &falcon_pks).unwrap();
        assert_eq!(dec_to, to);
        assert_eq!(dec_value, 1_000_000);
        assert_eq!(dec_calldata, b"swap(TOKEN_X, 500)");
    }

    #[test]
    fn insufficient_shares_fails() {
        let (pk, key_shares, falcon_pks, falcon_sks) = make_threshold_keys();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"recipient");

        let enc_tx = encrypt_transaction(
            sender,
            0,
            21_000,
            vec![],
            None,
            1,
            vec![],
            &to,
            100,
            b"",
            &pk,
        )
        .unwrap();

        // Only 1 share (need 2)
        let dec_shares = vec![threshold::generate_decryption_share(
            &key_shares[0],
            &enc_tx.ciphertext,
            &falcon_sks[0],
        )
        .unwrap()];

        assert!(decrypt_payload(&enc_tx.ciphertext, &dec_shares, 2, &falcon_pks).is_err());
    }

    #[test]
    fn hash_is_deterministic() {
        let (pk, _, _, _) = make_threshold_keys();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"recipient");

        let enc_tx = encrypt_transaction(
            sender,
            0,
            21_000,
            vec![],
            None,
            1,
            vec![],
            &to,
            100,
            b"",
            &pk,
        )
        .unwrap();

        assert_eq!(enc_tx.hash(), enc_tx.hash());
    }

    #[test]
    fn expired_check() {
        let (pk, _, _, _) = make_threshold_keys();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"recipient");

        let enc_tx = encrypt_transaction(
            sender,
            0,
            21_000,
            vec![],
            Some(100),
            1,
            vec![],
            &to,
            0,
            b"",
            &pk,
        )
        .unwrap();

        assert!(!enc_tx.is_expired(99));
        assert!(enc_tx.is_expired(100));
        assert!(enc_tx.is_expired(200));
    }

    #[test]
    fn no_deadline_never_expires() {
        let (pk, _, _, _) = make_threshold_keys();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"recipient");

        let enc_tx =
            encrypt_transaction(sender, 0, 21_000, vec![], None, 1, vec![], &to, 0, b"", &pk)
                .unwrap();

        assert!(!enc_tx.is_expired(u64::MAX));
    }

    // ── from_bytes panic-free regression tests ─────────────────────
    //
    // The pre-audit-301 implementation panicked on malformed input
    // (raw slice indexing on attacker-controlled offsets, plus
    // `Vec::with_capacity(u32)` on attacker-controlled length fields).
    // Combined with `panic = "abort"`, one malformed
    // `pyde_sendRawEncryptedTransaction` could kill the node. These
    // tests pin the new contract: any byte string returns `None`.

    #[test]
    fn from_bytes_empty_returns_none() {
        assert!(EncryptedTx::from_bytes(&[]).is_none());
    }

    #[test]
    fn from_bytes_truncated_header_returns_none() {
        // 56 bytes = one short of the smallest valid header
        // (sender + nonce + gas + chain + has_dl = 57).
        for n in 0..57 {
            let bytes = vec![0u8; n];
            assert!(
                EncryptedTx::from_bytes(&bytes).is_none(),
                "len {} must reject",
                n
            );
        }
    }

    #[test]
    fn from_bytes_oversize_envelope_returns_none() {
        let bytes = vec![0u8; MAX_TX_SIZE + 1];
        assert!(EncryptedTx::from_bytes(&bytes).is_none());
    }

    #[test]
    fn from_bytes_huge_access_list_count_rejected() {
        // Build a header that claims `MAX_ACCESS_ENTRIES + 1` access
        // entries. The pre-fix decoder would call
        // `Vec::with_capacity(huge)` and crash; the new decoder must
        // reject before allocating.
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[0u8; 32]); // sender
        bytes.extend_from_slice(&0u64.to_le_bytes()); // nonce
        bytes.extend_from_slice(&21_000u64.to_le_bytes()); // gas
        bytes.extend_from_slice(&1u64.to_le_bytes()); // chain_id
        bytes.push(0); // has_deadline = 0
        bytes.extend_from_slice(&((MAX_ACCESS_ENTRIES as u32) + 1).to_le_bytes());
        assert!(EncryptedTx::from_bytes(&bytes).is_none());
    }

    #[test]
    fn from_bytes_huge_signature_len_rejected() {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[0u8; 32]); // sender
        bytes.extend_from_slice(&0u64.to_le_bytes()); // nonce
        bytes.extend_from_slice(&21_000u64.to_le_bytes()); // gas
        bytes.extend_from_slice(&1u64.to_le_bytes()); // chain_id
        bytes.push(0); // has_deadline = 0
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 access entries
        bytes.extend_from_slice(&((MAX_SIG_LEN as u32) + 1).to_le_bytes()); // huge sig_len
        assert!(EncryptedTx::from_bytes(&bytes).is_none());
    }

    #[test]
    fn from_bytes_huge_ciphertext_len_rejected() {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[0u8; 32]); // sender
        bytes.extend_from_slice(&0u64.to_le_bytes()); // nonce
        bytes.extend_from_slice(&21_000u64.to_le_bytes()); // gas
        bytes.extend_from_slice(&1u64.to_le_bytes()); // chain_id
        bytes.push(0); // has_deadline = 0
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 access entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0-byte signature
        bytes.extend_from_slice(&((MAX_CT_LEN as u32) + 1).to_le_bytes()); // huge ct_len
        assert!(EncryptedTx::from_bytes(&bytes).is_none());
    }

    /// TPL-410: pre-fix `MAX_CT_LEN` was the loose `MAX_TX_SIZE = 128 KB`
    /// budget; a malicious peer could claim a 100 KB ciphertext and
    /// trigger a `Vec::with_capacity(100 KB)` per malformed gossip
    /// blob. Post-fix the cap is 72 KB (just over the real ciphertext
    /// max of ~67 KB) so a 100 KB claim is rejected.
    #[test]
    fn tpl_410_from_bytes_rejects_100kb_ciphertext_len() {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[0u8; 32]); // sender
        bytes.extend_from_slice(&0u64.to_le_bytes()); // nonce
        bytes.extend_from_slice(&21_000u64.to_le_bytes()); // gas
        bytes.extend_from_slice(&1u64.to_le_bytes()); // chain_id
        bytes.push(0); // has_deadline = 0
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 access entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0-byte signature
        bytes.extend_from_slice(&(100u32 * 1024).to_le_bytes()); // 100 KB ct_len
        assert!(
            EncryptedTx::from_bytes(&bytes).is_none(),
            "100 KB ciphertext claim must be rejected by the tightened cap"
        );
    }

    #[test]
    fn from_bytes_inner_keys_count_rejected() {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[0u8; 32]); // sender
        bytes.extend_from_slice(&0u64.to_le_bytes()); // nonce
        bytes.extend_from_slice(&21_000u64.to_le_bytes()); // gas
        bytes.extend_from_slice(&1u64.to_le_bytes()); // chain_id
        bytes.push(0); // has_deadline = 0
        bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 access entry
        bytes.extend_from_slice(&[0u8; 32]); // entry address
        bytes.extend_from_slice(&((MAX_KEYS_PER_ACCESS_ENTRY as u16) + 1).to_le_bytes());
        assert!(EncryptedTx::from_bytes(&bytes).is_none());
    }

    #[test]
    fn from_bytes_truncated_signature_returns_none() {
        // Claim a sig_len that exceeds remaining bytes.
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&21_000u64.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&0u32.to_le_bytes()); // empty access list
        bytes.extend_from_slice(&100u32.to_le_bytes()); // sig_len = 100, but no bytes follow
        assert!(EncryptedTx::from_bytes(&bytes).is_none());
    }

    /// AUDIT 406 REGRESSION GUARD — the runtime decrypts an
    /// EncryptedTx that was wire-roundtripped at least twice (RPC
    /// in, block-body out → validator block-body in). Each
    /// roundtrip must preserve the ciphertext byte-for-byte;
    /// otherwise `ciphertext_binding_hash` differs between encrypt
    /// and decrypt and `combine_shares` collapses onto the audit-
    /// 360 oracle-safe error every single time.
    #[test]
    fn audit_406_encrypted_tx_double_roundtrip_is_byte_identical_and_decrypts() {
        let (pk, key_shares, falcon_pks, falcon_sks) = make_threshold_keys();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"recipient");
        let original = encrypt_transaction(
            sender,
            42,
            500_000,
            vec![],
            Some(1_000_500),
            7331,
            vec![0xAA; 64],
            &to,
            1_000_000,
            b"audit 406 double-roundtrip payload",
            &pk,
        )
        .unwrap();

        // First roundtrip: simulates RPC submission decode.
        let bytes_1 = original.to_bytes();
        let after_1 = EncryptedTx::from_bytes(&bytes_1).expect("first roundtrip");
        let bytes_2 = after_1.to_bytes();
        // Second roundtrip: simulates proposer block re-serialization.
        let after_2 = EncryptedTx::from_bytes(&bytes_2).expect("second roundtrip");
        let bytes_3 = after_2.to_bytes();

        assert_eq!(bytes_1, bytes_2, "first roundtrip changed bytes");
        assert_eq!(bytes_2, bytes_3, "second roundtrip changed bytes");
        assert_eq!(
            original.ciphertext.to_wire_bytes(),
            after_2.ciphertext.to_wire_bytes(),
            "ciphertext wire bytes drifted across two EncryptedTx roundtrips"
        );

        // Decrypt the post-double-roundtrip ciphertext via the
        // committee's shares. This is the exact path the runtime
        // takes: validators decode wire bytes from a block body,
        // generate shares, and combine.
        let dec_shares: Vec<pyde_crypto::threshold::DecryptionShare> = key_shares[..2]
            .iter()
            .enumerate()
            .map(|(i, ks)| {
                pyde_crypto::threshold::generate_decryption_share(
                    ks,
                    &after_2.ciphertext,
                    &falcon_sks[i],
                )
                .unwrap()
            })
            .collect();
        let plaintext_bytes = pyde_crypto::threshold::combine_shares(
            &dec_shares,
            2,
            &after_2.ciphertext,
            &falcon_pks,
        )
        .expect("post-roundtrip ciphertext must decrypt");
        // Plaintext layout: to(32) || value(16 LE) || calldata.
        assert_eq!(&plaintext_bytes[..32], &to);
        let value_le: [u8; 16] = plaintext_bytes[32..48].try_into().unwrap();
        assert_eq!(u128::from_le_bytes(value_le), 1_000_000);
        assert_eq!(
            &plaintext_bytes[48..],
            b"audit 406 double-roundtrip payload"
        );
    }

    #[test]
    fn from_bytes_roundtrip_with_real_payload() {
        // Sanity: the new decoder still accepts a real, encoded
        // EncryptedTx round-trip — i.e. the fix is panic-removal
        // not behaviour change on the happy path.
        let (pk, _, _, _) = make_threshold_keys();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"recipient");
        let enc_tx = encrypt_transaction(
            sender,
            7,
            21_000,
            vec![pyde_tx::types::AccessEntry {
                address: derive_eoa_address(b"contract"),
                reads: vec![[1u8; 32], [2u8; 32]],
                writes: vec![[3u8; 32]],
            }],
            Some(100),
            7331,
            vec![0xAB; 690],
            &to,
            42,
            b"hello",
            &pk,
        )
        .unwrap();
        let bytes = enc_tx.to_bytes();
        let decoded = EncryptedTx::from_bytes(&bytes).expect("happy path round-trip");
        assert_eq!(decoded.sender, enc_tx.sender);
        assert_eq!(decoded.nonce, enc_tx.nonce);
        assert_eq!(decoded.gas_limit, enc_tx.gas_limit);
        assert_eq!(decoded.chain_id, enc_tx.chain_id);
        assert_eq!(decoded.deadline, enc_tx.deadline);
        assert_eq!(decoded.access_list.len(), 1);
        assert_eq!(decoded.signature, enc_tx.signature);
    }

    #[test]
    fn from_bytes_fuzz_short_inputs_never_panic() {
        // Sweep every length [0, 256] of zero-bytes and a handful of
        // adversarially-shaped headers; the decoder must always
        // return None or Some, never panic.
        for n in 0..=256 {
            let _ = EncryptedTx::from_bytes(&vec![0u8; n]);
            let _ = EncryptedTx::from_bytes(&vec![0xFFu8; n]);
        }
        // Random-ish bit patterns to flush out subtle bugs.
        for seed in 0u64..32 {
            let mut bytes = Vec::with_capacity(512);
            let mut x = seed.wrapping_mul(0x9E3779B97F4A7C15);
            for _ in 0..512 {
                x = x.wrapping_mul(0x9E3779B97F4A7C15) ^ x.rotate_right(11);
                bytes.push((x & 0xFF) as u8);
            }
            let _ = EncryptedTx::from_bytes(&bytes);
        }
    }

    #[test]
    fn size_check() {
        let (pk, _, _, _) = make_threshold_keys();
        let sender = derive_eoa_address(b"sender");
        let to = derive_eoa_address(b"recipient");

        let small_tx =
            encrypt_transaction(sender, 0, 21_000, vec![], None, 1, vec![], &to, 0, b"", &pk)
                .unwrap();
        assert!(!small_tx.is_oversized());

        let big_tx = encrypt_transaction(
            sender,
            0,
            21_000,
            vec![],
            None,
            1,
            vec![],
            &to,
            0,
            &vec![0xFF; 200_000],
            &pk,
        )
        .unwrap();
        assert!(big_tx.is_oversized());
    }
}
