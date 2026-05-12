//! DKG (Distributed Key Generation) primitives.
//!
//! Two pieces:
//!
//! 1. **VSS commitments.** Each DKG contributor commits to a vector
//!    of share-rows (one per recipient) by Merkle-hashing the rows
//!    and Falcon-signing the root + tree metadata. Receivers later
//!    check their share against the root via a Merkle proof, and
//!    the signature binds the root to a specific (epoch,
//!    contributor_index, n, threshold) tuple so commitments can't
//!    be replayed across DKG rounds.
//!
//! 2. **Per-recipient encrypted share envelopes.** Each contributor
//!    encrypts each recipient's share-row under that recipient's
//!    Kyber-768 public key using a Poseidon2-keystream + Poseidon2-
//!    MAC AEAD construction. The keystream and MAC are bound to
//!    (epoch, from_index, recipient_index) so an envelope can't be
//!    replayed across rounds, contributors, or recipients.
//!
//! All hashing uses Poseidon2 with explicit domain-separation tags
//! per role (leaf / internal node / empty / commit sig / AEAD KS /
//! AEAD MAC). No KZG, no Pedersen — the entire stack stays
//! post-quantum.

#![allow(clippy::needless_range_loop)]

use alloc::vec;
use alloc::vec::Vec;

use p3_goldilocks::Goldilocks;
use subtle::ConstantTimeEq;

use crate::falcon::{falcon_sign, falcon_verify, FalconPublicKey, FalconSecretKey, FalconSignature};
use crate::kyber::{
    kyber_decapsulate, kyber_encapsulate, KyberCiphertext, KyberPublicKey, KyberSecretKey,
    SharedSecret,
};
use crate::poseidon2::poseidon2_hash;
use crate::threshold::{gl, gl_to_u64, GOLDILOCKS_PRIME, SEED_ELEMENTS};

/// Domain separator for the Falcon signature over a DKG commitment.
pub const DKG_COMMIT_SIG_DOMAIN: &[u8] = b"PYDE_DKG_COMMIT_V1\0";

/// Domain separator for the Merkle leaf hash of a share row.
pub const DKG_MERKLE_LEAF_DOMAIN: &[u8] = b"PYDE_DKG_MERKLE_LEAF_V1\0";

/// Domain separator for internal Merkle node hashes.
pub const DKG_MERKLE_NODE_DOMAIN: &[u8] = b"PYDE_DKG_MERKLE_NODE_V1\0";

/// Domain separator for padding leaves used when `n` is not a
/// power of two. The padded hash is bound to (epoch, from_index)
/// so padding from one contributor's tree can't be reused as a
/// real leaf in another's.
pub const DKG_MERKLE_EMPTY_DOMAIN: &[u8] = b"PYDE_DKG_MERKLE_EMPTY_V1\0";

/// Domain separator for the keystream KDF used to encrypt a
/// recipient's share-row under their Kyber public key.
pub const DKG_AEAD_KS_DOMAIN: &[u8] = b"PYDE_DKG_AEAD_KS_V1\0";

/// Domain separator for the MAC over an encrypted share-row.
pub const DKG_AEAD_MAC_DOMAIN: &[u8] = b"PYDE_DKG_AEAD_MAC_V1\0";

/// A single recipient's share-row from one DKG contributor.
///
/// Each contributor i samples a 64-byte seed which they unpack into
/// `SEED_ELEMENTS` (=8) Goldilocks field elements. They then run
/// Shamir secret-sharing on each element independently. Recipient
/// j's share-row is the `(t, n)` Shamir y-values at x=j across all
/// 8 polynomials. The total master share for j is the SUM (per
/// element) of every contributor's share-row for j.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareRow {
    /// 1-based committee position of the recipient (1..=n).
    pub receiver_index: usize,
    /// Field-element values, one per seed element.
    pub values: [Goldilocks; SEED_ELEMENTS],
}

impl ShareRow {
    /// Wire size: 4 (receiver_index) + 8 * SEED_ELEMENTS bytes.
    pub const WIRE_LEN: usize = 4 + 8 * SEED_ELEMENTS;

    /// Encode as `receiver_index(4 LE) || value_0(8 LE) || ... || value_{N-1}(8 LE)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::WIRE_LEN);
        out.extend_from_slice(&(self.receiver_index as u32).to_le_bytes());
        for v in &self.values {
            out.extend_from_slice(&gl_to_u64(*v).to_le_bytes());
        }
        out
    }

    /// Decode a `ShareRow` from exactly `WIRE_LEN` bytes. Returns
    /// `None` on length mismatch or if any value is `>= GOLDILOCKS_PRIME`
    /// (which would be a non-canonical Goldilocks element).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::WIRE_LEN {
            return None;
        }
        let receiver_index =
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let mut values = [Goldilocks::default(); SEED_ELEMENTS];
        for i in 0..SEED_ELEMENTS {
            let off = 4 + i * 8;
            let raw = u64::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ]);
            if raw >= GOLDILOCKS_PRIME {
                return None;
            }
            values[i] = gl(raw);
        }
        Some(Self {
            receiver_index,
            values,
        })
    }

    /// Compute the Merkle leaf hash, binding the leaf to its
    /// containing tree via (epoch, from_index). The binding closes
    /// off cross-tree replay: a leaf hash valid for epoch=A,
    /// contributor=X can't be re-presented as a leaf of epoch=B's
    /// tree even if the byte values coincide.
    pub fn leaf_hash(&self, epoch: u64, from_index: usize) -> [u8; 32] {
        let mut buf = Vec::with_capacity(
            DKG_MERKLE_LEAF_DOMAIN.len() + 8 + 4 + 4 + 8 * SEED_ELEMENTS,
        );
        buf.extend_from_slice(DKG_MERKLE_LEAF_DOMAIN);
        buf.extend_from_slice(&epoch.to_le_bytes());
        buf.extend_from_slice(&(from_index as u32).to_le_bytes());
        buf.extend_from_slice(&(self.receiver_index as u32).to_le_bytes());
        for v in &self.values {
            buf.extend_from_slice(&gl_to_u64(*v).to_le_bytes());
        }
        poseidon2_hash(&buf).to_bytes()
    }
}

/// Per-tree padding hash for slots beyond the actual leaf count.
fn empty_leaf_hash(epoch: u64, from_index: usize) -> [u8; 32] {
    let mut buf = Vec::with_capacity(DKG_MERKLE_EMPTY_DOMAIN.len() + 8 + 4);
    buf.extend_from_slice(DKG_MERKLE_EMPTY_DOMAIN);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.extend_from_slice(&(from_index as u32).to_le_bytes());
    poseidon2_hash(&buf).to_bytes()
}

/// Internal Merkle node hash: `H(NODE_DOMAIN || left || right)`.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(DKG_MERKLE_NODE_DOMAIN.len() + 64);
    buf.extend_from_slice(DKG_MERKLE_NODE_DOMAIN);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    poseidon2_hash(&buf).to_bytes()
}

/// Compute the Merkle root over `leaves`, padding to the next
/// power of two with the per-tree empty-leaf hash. Empty input
/// returns the empty-leaf hash itself.
pub fn compute_merkle_root(leaves: &[[u8; 32]], epoch: u64, from_index: usize) -> [u8; 32] {
    let empty = empty_leaf_hash(epoch, from_index);
    if leaves.is_empty() {
        return empty;
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let target = level.len().next_power_of_two();
    while level.len() < target {
        level.push(empty);
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for chunk in level.chunks(2) {
            next.push(node_hash(&chunk[0], &chunk[1]));
        }
        level = next;
    }
    level[0]
}

/// A Merkle inclusion proof. `siblings` is ordered from the leaf's
/// sibling up to (but not including) the root. The bit at position
/// `k` in `leaf_index` (LSB first) indicates whether `siblings[k]`
/// is the right-side hash (bit=0 → leaf is on the left).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub siblings: Vec<[u8; 32]>,
}

impl MerkleProof {
    /// Encode: `leaf_index(4 LE) || sibling_count(4 LE) || siblings...`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 * self.siblings.len());
        out.extend_from_slice(&(self.leaf_index as u32).to_le_bytes());
        out.extend_from_slice(&(self.siblings.len() as u32).to_le_bytes());
        for s in &self.siblings {
            out.extend_from_slice(s);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let leaf_index = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let count = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        if bytes.len() != 8 + 32 * count {
            return None;
        }
        let mut siblings = Vec::with_capacity(count);
        for i in 0..count {
            let off = 8 + i * 32;
            let mut s = [0u8; 32];
            s.copy_from_slice(&bytes[off..off + 32]);
            siblings.push(s);
        }
        Some(Self {
            leaf_index,
            siblings,
        })
    }
}

/// Generate a Merkle inclusion proof for `leaf_index`. Returns
/// `None` if the index is out of bounds.
pub fn merkle_proof(
    leaves: &[[u8; 32]],
    leaf_index: usize,
    epoch: u64,
    from_index: usize,
) -> Option<MerkleProof> {
    if leaf_index >= leaves.len() {
        return None;
    }
    let empty = empty_leaf_hash(epoch, from_index);
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let target = level.len().next_power_of_two().max(1);
    while level.len() < target {
        level.push(empty);
    }
    let mut idx = leaf_index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let sibling = if idx % 2 == 0 {
            level[idx + 1]
        } else {
            level[idx - 1]
        };
        siblings.push(sibling);
        idx /= 2;
        let mut next = Vec::with_capacity(level.len() / 2);
        for chunk in level.chunks(2) {
            next.push(node_hash(&chunk[0], &chunk[1]));
        }
        level = next;
    }
    Some(MerkleProof {
        leaf_index,
        siblings,
    })
}

/// Verify that `leaf` is at position `proof.leaf_index` in the
/// tree whose root is `root`. Returns false on any mismatch.
pub fn verify_merkle_proof(root: &[u8; 32], leaf: &[u8; 32], proof: &MerkleProof) -> bool {
    let mut idx = proof.leaf_index;
    let mut cur = *leaf;
    for sib in &proof.siblings {
        cur = if idx % 2 == 0 {
            node_hash(&cur, sib)
        } else {
            node_hash(sib, &cur)
        };
        idx /= 2;
    }
    cur == *root
}

/// Signed Merkle-root commitment from one DKG contributor. Receivers
/// verify the signature against the contributor's Falcon public key
/// and then check their share-row against `merkle_root`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgCommitment {
    pub epoch: u64,
    /// 1-based contributor index inside the committee.
    pub from_index: usize,
    pub n: usize,
    pub threshold: usize,
    pub merkle_root: [u8; 32],
    pub signature: Vec<u8>,
}

impl DkgCommitment {
    /// Construct an UNSIGNED commitment. Call [`Self::sign`] before sending.
    pub fn new_unsigned(
        epoch: u64,
        from_index: usize,
        n: usize,
        threshold: usize,
        merkle_root: [u8; 32],
    ) -> Self {
        Self {
            epoch,
            from_index,
            n,
            threshold,
            merkle_root,
            signature: Vec::new(),
        }
    }

    /// Canonical signing preimage. Includes the domain tag,
    /// `(epoch, from_index, n, threshold)`, and `merkle_root`. The
    /// preimage is what gets signed in [`Self::sign`] and verified
    /// in [`Self::verify`].
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(DKG_COMMIT_SIG_DOMAIN.len() + 8 + 4 + 4 + 4 + 32);
        buf.extend_from_slice(DKG_COMMIT_SIG_DOMAIN);
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(&(self.from_index as u32).to_le_bytes());
        buf.extend_from_slice(&(self.n as u32).to_le_bytes());
        buf.extend_from_slice(&(self.threshold as u32).to_le_bytes());
        buf.extend_from_slice(&self.merkle_root);
        buf
    }

    /// Falcon-sign the commitment in-place.
    pub fn sign(&mut self, sk: &FalconSecretKey) -> Result<(), &'static str> {
        let msg = self.signing_preimage();
        let sig = falcon_sign(sk, &msg)?;
        self.signature = sig.to_vec();
        Ok(())
    }

    /// Verify the Falcon signature with `pk`. Returns false if the
    /// signature bytes are malformed or the verification fails.
    pub fn verify(&self, pk: &FalconPublicKey) -> bool {
        let Some(sig) = FalconSignature::from_bytes(&self.signature) else {
            return false;
        };
        let msg = self.signing_preimage();
        falcon_verify(pk, &msg, &sig)
    }

    /// Wire encoding:
    /// `epoch(8 LE) || from_index(4 LE) || n(4 LE) || threshold(4 LE)
    ///   || merkle_root(32) || sig_len(4 LE) || sig`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(56 + self.signature.len());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&(self.from_index as u32).to_le_bytes());
        out.extend_from_slice(&(self.n as u32).to_le_bytes());
        out.extend_from_slice(&(self.threshold as u32).to_le_bytes());
        out.extend_from_slice(&self.merkle_root);
        out.extend_from_slice(&(self.signature.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 56 {
            return None;
        }
        let epoch = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let from_index =
            u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        let n = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let threshold =
            u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&bytes[20..52]);
        let sig_len = u32::from_le_bytes([bytes[52], bytes[53], bytes[54], bytes[55]]) as usize;
        if bytes.len() != 56 + sig_len {
            return None;
        }
        let signature = bytes[56..56 + sig_len].to_vec();
        Some(Self {
            epoch,
            from_index,
            n,
            threshold,
            merkle_root,
            signature,
        })
    }
}

// --- Per-recipient encrypted share-row envelope ---

/// Poseidon2-derived keystream of `len` bytes, keyed by the Kyber
/// shared secret and the kyber_ct plus the per-envelope binding
/// tuple. Binding both the keystream and the MAC (see
/// [`dkg_aead_mac`]) to `(epoch, from_index, recipient_index)`
/// means an envelope intended for one (round, contributor,
/// recipient) cannot be replayed under a different tuple even if
/// Kyber accidentally produced the same `(ss, ct)` (which under
/// IND-CCA Kyber it won't).
fn dkg_aead_keystream(
    ss: &SharedSecret,
    kyber_ct: &[u8],
    epoch: u64,
    from_index: usize,
    recipient_index: usize,
    len: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter: u64 = 0;
    while out.len() < len {
        let mut input = Vec::with_capacity(
            DKG_AEAD_KS_DOMAIN.len() + 32 + kyber_ct.len() + 8 + 4 + 4 + 8,
        );
        input.extend_from_slice(DKG_AEAD_KS_DOMAIN);
        input.extend_from_slice(ss.as_bytes());
        input.extend_from_slice(kyber_ct);
        input.extend_from_slice(&epoch.to_le_bytes());
        input.extend_from_slice(&(from_index as u32).to_le_bytes());
        input.extend_from_slice(&(recipient_index as u32).to_le_bytes());
        input.extend_from_slice(&counter.to_le_bytes());
        let block = poseidon2_hash(&input);
        out.extend_from_slice(block.as_bytes());
        counter += 1;
    }
    out.truncate(len);
    out
}

/// Poseidon2-keyed MAC over the AEAD envelope's ciphertext, with
/// the same `(epoch, from_index, recipient_index)` binding that
/// keys the keystream.
fn dkg_aead_mac(
    ss: &SharedSecret,
    kyber_ct: &[u8],
    epoch: u64,
    from_index: usize,
    recipient_index: usize,
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(
        DKG_AEAD_MAC_DOMAIN.len() + 32 + kyber_ct.len() + 8 + 4 + 4 + ciphertext.len(),
    );
    input.extend_from_slice(DKG_AEAD_MAC_DOMAIN);
    input.extend_from_slice(ss.as_bytes());
    input.extend_from_slice(kyber_ct);
    input.extend_from_slice(&epoch.to_le_bytes());
    input.extend_from_slice(&(from_index as u32).to_le_bytes());
    input.extend_from_slice(&(recipient_index as u32).to_le_bytes());
    input.extend_from_slice(ciphertext);
    *poseidon2_hash(&input).as_bytes()
}

/// One contributor's encrypted share-row for one recipient.
///
/// `kyber_ct` is the Kyber-768 ciphertext used to deliver the
/// per-envelope shared secret; `ciphertext` is the keystream-XOR
/// of [`ShareRow`]'s byte form; `mac` is the Poseidon2-keyed MAC
/// over (ciphertext, binding tuple). Tampering with any of these
/// fields, or trying to replay the envelope under a different
/// `(epoch, from_index, recipient_index)`, breaks the MAC and
/// causes decryption to fail uniformly with `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgShareEnvelope {
    pub kyber_ct: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub mac: [u8; 32],
}

impl DkgShareEnvelope {
    /// Wire format: `kyber_ct_len(4 LE) || kyber_ct || ciphertext_len(4 LE) || ciphertext || mac(32)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(4 + self.kyber_ct.len() + 4 + self.ciphertext.len() + 32);
        out.extend_from_slice(&(self.kyber_ct.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.kyber_ct);
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.mac);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        let ct_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let after_kct = 4 + ct_len;
        if bytes.len() < after_kct + 4 {
            return None;
        }
        let kyber_ct = bytes[4..after_kct].to_vec();
        let cipher_len = u32::from_le_bytes([
            bytes[after_kct],
            bytes[after_kct + 1],
            bytes[after_kct + 2],
            bytes[after_kct + 3],
        ]) as usize;
        let after_cipher = after_kct + 4 + cipher_len;
        if bytes.len() != after_cipher + 32 {
            return None;
        }
        let ciphertext = bytes[after_kct + 4..after_cipher].to_vec();
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&bytes[after_cipher..after_cipher + 32]);
        Some(Self {
            kyber_ct,
            ciphertext,
            mac,
        })
    }
}

/// Encrypt `row` for `recipient_pk`, binding the envelope to
/// `(epoch, from_index, row.receiver_index)`. The recipient_index
/// comes from the row itself so a caller can't accidentally encrypt
/// row j's data under recipient i's key but tag it with i's index.
pub fn encrypt_share_row(
    row: &ShareRow,
    recipient_pk: &KyberPublicKey,
    epoch: u64,
    from_index: usize,
) -> Result<DkgShareEnvelope, &'static str> {
    let (kct, ss) = kyber_encapsulate(recipient_pk)?;
    let plaintext = row.to_bytes();
    let keystream = dkg_aead_keystream(
        &ss,
        kct.as_bytes(),
        epoch,
        from_index,
        row.receiver_index,
        plaintext.len(),
    );
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for i in 0..plaintext.len() {
        ciphertext.push(plaintext[i] ^ keystream[i]);
    }
    let mac = dkg_aead_mac(
        &ss,
        kct.as_bytes(),
        epoch,
        from_index,
        row.receiver_index,
        &ciphertext,
    );
    Ok(DkgShareEnvelope {
        kyber_ct: kct.to_vec(),
        ciphertext,
        mac,
    })
}

/// Decrypt and verify a share-row envelope. Returns `None` for any
/// failure (malformed wire, wrong-size Kyber CT, MAC mismatch,
/// post-decrypt index mismatch). The function does not short-
/// circuit on Kyber failure: on a bad CT it computes the MAC under
/// a zero shared-secret and lets the constant-time compare reject
/// uniformly, so an attacker can't time-distinguish "bad CT" from
/// "bad MAC" (audit 360 pattern).
pub fn decrypt_share_row(
    envelope: &DkgShareEnvelope,
    recipient_sk: &KyberSecretKey,
    epoch: u64,
    from_index: usize,
    expected_receiver_index: usize,
) -> Option<ShareRow> {
    let ss = match KyberCiphertext::from_bytes(&envelope.kyber_ct) {
        Some(kct) => kyber_decapsulate(recipient_sk, &kct)
            .unwrap_or_else(|_| SharedSecret::zero_for_constant_time_mac_check()),
        None => SharedSecret::zero_for_constant_time_mac_check(),
    };
    let expected_mac = dkg_aead_mac(
        &ss,
        &envelope.kyber_ct,
        epoch,
        from_index,
        expected_receiver_index,
        &envelope.ciphertext,
    );
    if expected_mac.ct_eq(&envelope.mac).unwrap_u8() != 1 {
        return None;
    }
    let keystream = dkg_aead_keystream(
        &ss,
        &envelope.kyber_ct,
        epoch,
        from_index,
        expected_receiver_index,
        envelope.ciphertext.len(),
    );
    let mut plaintext = vec![0u8; envelope.ciphertext.len()];
    for i in 0..envelope.ciphertext.len() {
        plaintext[i] = envelope.ciphertext[i] ^ keystream[i];
    }
    let row = ShareRow::from_bytes(&plaintext)?;
    // Belt-and-suspenders: the binding tuple already prevents
    // cross-recipient replay via the MAC, but checking the decoded
    // row's own index catches a malicious contributor who tries to
    // send recipient i a row that internally claims receiver_index j.
    if row.receiver_index != expected_receiver_index {
        return None;
    }
    Some(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::falcon::falcon_keygen;
    use crate::kyber::{kyber_keygen, KyberCiphertext};
    use alloc::vec;

    fn make_row(receiver_index: usize, seed: u64) -> ShareRow {
        let mut values = [Goldilocks::default(); SEED_ELEMENTS];
        for i in 0..SEED_ELEMENTS {
            values[i] = gl(seed.wrapping_add(i as u64 * 7919));
        }
        ShareRow {
            receiver_index,
            values,
        }
    }

    #[test]
    fn share_row_roundtrip() {
        let row = make_row(3, 0xDEAD_BEEF_1234_5678);
        let bytes = row.to_bytes();
        assert_eq!(bytes.len(), ShareRow::WIRE_LEN);
        let decoded = ShareRow::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, row);
    }

    #[test]
    fn share_row_rejects_wrong_length() {
        assert!(ShareRow::from_bytes(&[]).is_none());
        assert!(ShareRow::from_bytes(&[0u8; ShareRow::WIRE_LEN - 1]).is_none());
        assert!(ShareRow::from_bytes(&[0u8; ShareRow::WIRE_LEN + 1]).is_none());
    }

    #[test]
    fn share_row_rejects_non_canonical_goldilocks() {
        let mut bytes = vec![0u8; ShareRow::WIRE_LEN];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        // First value: write a u64 >= GOLDILOCKS_PRIME.
        bytes[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(ShareRow::from_bytes(&bytes).is_none());
    }

    #[test]
    fn merkle_root_single_leaf() {
        let row = make_row(1, 42);
        let leaf = row.leaf_hash(1, 1);
        let root = compute_merkle_root(&[leaf], 1, 1);
        // Single leaf still gets padded to power of two ≥ 1, which is 1,
        // so the root is the leaf hash itself.
        assert_eq!(root, leaf);
    }

    #[test]
    fn merkle_proof_roundtrip_and_verify() {
        let epoch = 7;
        let from_index = 2;
        let n = 5;
        let rows: Vec<ShareRow> = (1..=n).map(|i| make_row(i, 1000 + i as u64)).collect();
        let leaves: Vec<[u8; 32]> = rows.iter().map(|r| r.leaf_hash(epoch, from_index)).collect();
        let root = compute_merkle_root(&leaves, epoch, from_index);

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = merkle_proof(&leaves, i, epoch, from_index).expect("proof exists");
            assert!(verify_merkle_proof(&root, leaf, &proof), "proof {} verifies", i);
            // Wire roundtrip.
            let encoded = proof.to_bytes();
            let decoded = MerkleProof::from_bytes(&encoded).expect("decode proof");
            assert_eq!(decoded, proof);
            assert!(verify_merkle_proof(&root, leaf, &decoded));
        }
    }

    #[test]
    fn merkle_proof_detects_tampered_leaf() {
        let epoch = 1;
        let from_index = 1;
        let rows: Vec<ShareRow> = (1..=8).map(|i| make_row(i, 100 + i as u64)).collect();
        let leaves: Vec<[u8; 32]> = rows.iter().map(|r| r.leaf_hash(epoch, from_index)).collect();
        let root = compute_merkle_root(&leaves, epoch, from_index);

        let proof = merkle_proof(&leaves, 3, epoch, from_index).expect("proof");
        // Flip a single bit in the leaf.
        let mut tampered = leaves[3];
        tampered[0] ^= 0x01;
        assert!(!verify_merkle_proof(&root, &tampered, &proof));
    }

    #[test]
    fn merkle_proof_rejects_wrong_index() {
        let epoch = 1;
        let from_index = 1;
        let rows: Vec<ShareRow> = (1..=8).map(|i| make_row(i, 200 + i as u64)).collect();
        let leaves: Vec<[u8; 32]> = rows.iter().map(|r| r.leaf_hash(epoch, from_index)).collect();
        let root = compute_merkle_root(&leaves, epoch, from_index);

        // Generate proof for index 3 and present leaf 5 with it.
        let proof_for_3 = merkle_proof(&leaves, 3, epoch, from_index).expect("proof");
        assert!(!verify_merkle_proof(&root, &leaves[5], &proof_for_3));

        // Or present leaf 3's hash but claim it lives at position 5.
        let mut wrong_position = proof_for_3.clone();
        wrong_position.leaf_index = 5;
        assert!(!verify_merkle_proof(&root, &leaves[3], &wrong_position));
    }

    #[test]
    fn merkle_proof_rejects_cross_tree_replay() {
        // Same share-row content, but committed under two different
        // (epoch, from_index) trees. A valid proof for tree A must
        // not verify against tree B's root.
        let row = make_row(1, 0xABCD);
        let leaf_a = row.leaf_hash(1, 1);
        let leaf_b = row.leaf_hash(2, 1);
        assert_ne!(leaf_a, leaf_b, "leaf hash binds to (epoch, from_index)");

        let leaves_a = vec![leaf_a];
        let leaves_b = vec![leaf_b];
        let root_a = compute_merkle_root(&leaves_a, 1, 1);
        let root_b = compute_merkle_root(&leaves_b, 2, 1);
        let proof_a = merkle_proof(&leaves_a, 0, 1, 1).expect("proof_a");
        assert!(verify_merkle_proof(&root_a, &leaf_a, &proof_a));
        // Replay against tree B should fail.
        assert!(!verify_merkle_proof(&root_b, &leaf_a, &proof_a));
    }

    #[test]
    fn merkle_proof_rejects_cross_domain_leaf_as_node() {
        // A leaf hash shouldn't be interpretable as an internal
        // node, because the leaf and node domain tags differ. If
        // an attacker tries to pass off `node_hash` output as a
        // leaf (or vice versa), the verifier won't accept it.
        let row = make_row(1, 42);
        let leaf = row.leaf_hash(1, 1);
        let bogus_node = node_hash(&leaf, &leaf);
        assert_ne!(leaf, bogus_node, "domain tags separate leaf vs node");
    }

    #[test]
    fn empty_leaf_hash_is_per_tree() {
        // The padding hash must differ across trees so an attacker
        // can't fill an under-populated tree with empty leaves
        // borrowed from another tree to forge inclusion.
        let a = empty_leaf_hash(1, 1);
        let b = empty_leaf_hash(1, 2);
        let c = empty_leaf_hash(2, 1);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn merkle_root_pads_non_power_of_two() {
        // 5 leaves → padded to 8 with empty hashes.
        let epoch = 11;
        let from_index = 4;
        let rows: Vec<ShareRow> = (1..=5).map(|i| make_row(i, 7 + i as u64)).collect();
        let leaves: Vec<[u8; 32]> = rows.iter().map(|r| r.leaf_hash(epoch, from_index)).collect();
        let root_5 = compute_merkle_root(&leaves, epoch, from_index);

        // Build the same tree explicitly with the empties.
        let empty = empty_leaf_hash(epoch, from_index);
        let mut padded = leaves.clone();
        padded.push(empty);
        padded.push(empty);
        padded.push(empty);
        let root_8 = compute_merkle_root(&padded, epoch, from_index);
        assert_eq!(root_5, root_8);
    }

    #[test]
    fn commitment_sign_and_verify() {
        let (pk, sk) = falcon_keygen().expect("falcon_keygen");
        let mut c = DkgCommitment::new_unsigned(
            5,
            2,
            7,
            5,
            [0x42u8; 32],
        );
        c.sign(&sk).expect("sign");
        assert!(c.verify(&pk));
    }

    #[test]
    fn commitment_verify_rejects_tampered_root() {
        let (pk, sk) = falcon_keygen().expect("falcon_keygen");
        let mut c = DkgCommitment::new_unsigned(5, 2, 7, 5, [0x42u8; 32]);
        c.sign(&sk).expect("sign");
        // Flip a byte in the root post-signing.
        c.merkle_root[0] ^= 0xFF;
        assert!(!c.verify(&pk));
    }

    #[test]
    fn commitment_verify_rejects_tampered_metadata() {
        let (pk, sk) = falcon_keygen().expect("falcon_keygen");
        let mut c = DkgCommitment::new_unsigned(5, 2, 7, 5, [0x42u8; 32]);
        c.sign(&sk).expect("sign");
        let mut bad_epoch = c.clone();
        bad_epoch.epoch = 6;
        assert!(!bad_epoch.verify(&pk));
        let mut bad_index = c.clone();
        bad_index.from_index = 3;
        assert!(!bad_index.verify(&pk));
        let mut bad_n = c.clone();
        bad_n.n = 8;
        assert!(!bad_n.verify(&pk));
        let mut bad_t = c.clone();
        bad_t.threshold = 4;
        assert!(!bad_t.verify(&pk));
    }

    #[test]
    fn commitment_verify_rejects_wrong_signer() {
        let (_pk_a, sk_a) = falcon_keygen().expect("keygen a");
        let (pk_b, _sk_b) = falcon_keygen().expect("keygen b");
        let mut c = DkgCommitment::new_unsigned(5, 2, 7, 5, [0x42u8; 32]);
        c.sign(&sk_a).expect("sign with A");
        // Verify with B's public key — must fail.
        assert!(!c.verify(&pk_b));
    }

    #[test]
    fn commitment_roundtrip() {
        let (_pk, sk) = falcon_keygen().expect("keygen");
        let mut c = DkgCommitment::new_unsigned(9, 3, 11, 8, [0xA5u8; 32]);
        c.sign(&sk).expect("sign");
        let encoded = c.to_bytes();
        let decoded = DkgCommitment::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, c);
    }

    #[test]
    fn commitment_signing_preimage_is_canonical() {
        // Same input fields produce the same preimage bytes — i.e.
        // signing is deterministic in (epoch, from_index, n, t, root).
        let c1 = DkgCommitment::new_unsigned(1, 2, 7, 5, [3u8; 32]);
        let c2 = DkgCommitment::new_unsigned(1, 2, 7, 5, [3u8; 32]);
        assert_eq!(c1.signing_preimage(), c2.signing_preimage());

        // And the preimage MUST start with the domain tag, so it
        // can't be confused with a non-DKG Falcon-signed message.
        let pre = c1.signing_preimage();
        assert!(pre.starts_with(DKG_COMMIT_SIG_DOMAIN));
    }

    #[test]
    fn large_committee_roundtrip() {
        // 128-member committee — the production target.
        let epoch = 100;
        let from_index = 7;
        let n = 128usize;
        let rows: Vec<ShareRow> = (1..=n).map(|i| make_row(i, 5000 + i as u64)).collect();
        let leaves: Vec<[u8; 32]> = rows.iter().map(|r| r.leaf_hash(epoch, from_index)).collect();
        let root = compute_merkle_root(&leaves, epoch, from_index);

        for i in [0usize, 1, 63, 64, 127] {
            let proof = merkle_proof(&leaves, i, epoch, from_index).expect("proof");
            assert!(verify_merkle_proof(&root, &leaves[i], &proof));
            // Proof depth for a 128-leaf tree is exactly 7.
            assert_eq!(proof.siblings.len(), 7);
        }
    }

    // --- Phase C: envelope tests ---

    #[test]
    fn envelope_encrypt_decrypt_roundtrip() {
        let (pk, sk) = kyber_keygen().expect("kyber_keygen");
        let row = make_row(4, 0xCAFE_BABE_F00D_DEAD);
        let env = encrypt_share_row(&row, &pk, 9, 2).expect("encrypt");
        let decoded = decrypt_share_row(&env, &sk, 9, 2, 4).expect("decrypt");
        assert_eq!(decoded, row);
    }

    #[test]
    fn envelope_kyber_ct_has_expected_size() {
        let (pk, _sk) = kyber_keygen().expect("kyber_keygen");
        let row = make_row(1, 1);
        let env = encrypt_share_row(&row, &pk, 0, 0).expect("encrypt");
        assert_eq!(env.kyber_ct.len(), KyberCiphertext::SIZE);
        assert_eq!(env.ciphertext.len(), ShareRow::WIRE_LEN);
    }

    #[test]
    fn envelope_rejects_tampered_ciphertext() {
        let (pk, sk) = kyber_keygen().expect("kyber_keygen");
        let row = make_row(2, 7);
        let mut env = encrypt_share_row(&row, &pk, 1, 1).expect("encrypt");
        env.ciphertext[0] ^= 0x01;
        assert!(decrypt_share_row(&env, &sk, 1, 1, 2).is_none());
    }

    #[test]
    fn envelope_rejects_tampered_mac() {
        let (pk, sk) = kyber_keygen().expect("kyber_keygen");
        let row = make_row(2, 7);
        let mut env = encrypt_share_row(&row, &pk, 1, 1).expect("encrypt");
        env.mac[0] ^= 0xFF;
        assert!(decrypt_share_row(&env, &sk, 1, 1, 2).is_none());
    }

    #[test]
    fn envelope_rejects_tampered_kyber_ct() {
        let (pk, sk) = kyber_keygen().expect("kyber_keygen");
        let row = make_row(2, 7);
        let mut env = encrypt_share_row(&row, &pk, 1, 1).expect("encrypt");
        env.kyber_ct[0] ^= 0xFF;
        // Tampered kyber_ct decapsulates to an implicit-reject SS,
        // so the MAC computed at decrypt time won't match.
        assert!(decrypt_share_row(&env, &sk, 1, 1, 2).is_none());
    }

    #[test]
    fn envelope_rejects_wrong_recipient_key() {
        let (pk_a, _sk_a) = kyber_keygen().expect("keygen a");
        let (_pk_b, sk_b) = kyber_keygen().expect("keygen b");
        let row = make_row(3, 11);
        // A encrypts for A; B tries to decrypt with B's key.
        let env = encrypt_share_row(&row, &pk_a, 1, 1).expect("encrypt");
        assert!(decrypt_share_row(&env, &sk_b, 1, 1, 3).is_none());
    }

    #[test]
    fn envelope_rejects_wrong_recipient_index_at_decrypt() {
        let (pk, sk) = kyber_keygen().expect("kyber_keygen");
        let row = make_row(3, 11);
        let env = encrypt_share_row(&row, &pk, 1, 1).expect("encrypt");
        // Sent for receiver 3 but verifier expects receiver 4.
        assert!(decrypt_share_row(&env, &sk, 1, 1, 4).is_none());
    }

    #[test]
    fn envelope_rejects_cross_epoch_replay() {
        let (pk, sk) = kyber_keygen().expect("kyber_keygen");
        let row = make_row(2, 22);
        let env = encrypt_share_row(&row, &pk, 5, 1).expect("encrypt");
        assert!(decrypt_share_row(&env, &sk, 5, 1, 2).is_some());
        // Same envelope, different epoch — must reject.
        assert!(decrypt_share_row(&env, &sk, 6, 1, 2).is_none());
    }

    #[test]
    fn envelope_rejects_cross_contributor_replay() {
        let (pk, sk) = kyber_keygen().expect("kyber_keygen");
        let row = make_row(2, 22);
        let env = encrypt_share_row(&row, &pk, 5, 1).expect("encrypt");
        // Same envelope, different contributor — must reject.
        assert!(decrypt_share_row(&env, &sk, 5, 2, 2).is_none());
    }

    #[test]
    fn envelope_rejects_internal_index_mismatch() {
        // Defense-in-depth: even if a contributor lies about
        // receiver_index inside the row, the post-decrypt check
        // catches it. We forge an envelope whose plaintext row
        // internally claims receiver_index=7 but whose MAC binding
        // says recipient=3.
        let (pk, sk) = kyber_keygen().expect("kyber_keygen");
        // Encrypt a row whose internal index is 7, bound to MAC
        // tuple (..., recipient_index=7). Then ask decryptor to
        // verify it as recipient_index=3 — MAC binding mismatch
        // already rejects this. Re-bind the envelope to recipient 3
        // by re-encrypting with row.receiver_index=7 forced into the
        // MAC at index 3 via a hand-crafted construction.
        //
        // To exercise the explicit `row.receiver_index !=
        // expected_receiver_index` post-decrypt check, we have to
        // re-encrypt manually with the MAC tuple = (epoch=1, from=1,
        // recipient=3) but the plaintext row carries index 7.
        let plaintext_row = make_row(7, 99);
        let (kct, ss) = kyber_encapsulate(&pk).expect("encap");
        let plaintext = plaintext_row.to_bytes();
        let keystream =
            dkg_aead_keystream(&ss, kct.as_bytes(), 1, 1, 3, plaintext.len());
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for i in 0..plaintext.len() {
            ciphertext.push(plaintext[i] ^ keystream[i]);
        }
        let mac = dkg_aead_mac(&ss, kct.as_bytes(), 1, 1, 3, &ciphertext);
        let env = DkgShareEnvelope {
            kyber_ct: kct.to_vec(),
            ciphertext,
            mac,
        };
        // MAC verifies (recipient=3 in tuple), but the decrypted
        // row's internal receiver_index is 7 — must reject.
        assert!(decrypt_share_row(&env, &sk, 1, 1, 3).is_none());
    }

    #[test]
    fn envelope_wire_roundtrip() {
        let (pk, _sk) = kyber_keygen().expect("kyber_keygen");
        let row = make_row(2, 7);
        let env = encrypt_share_row(&row, &pk, 1, 1).expect("encrypt");
        let bytes = env.to_bytes();
        let decoded = DkgShareEnvelope::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, env);
    }

    #[test]
    fn envelope_wire_rejects_short_input() {
        assert!(DkgShareEnvelope::from_bytes(&[]).is_none());
        assert!(DkgShareEnvelope::from_bytes(&[0u8; 3]).is_none());
        // Claims kyber_ct_len=100 but supplies only 10 bytes.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&100u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 10]);
        assert!(DkgShareEnvelope::from_bytes(&bytes).is_none());
    }

    #[test]
    fn envelope_wire_rejects_size_mismatch() {
        let (pk, _sk) = kyber_keygen().expect("kyber_keygen");
        let row = make_row(2, 7);
        let env = encrypt_share_row(&row, &pk, 1, 1).expect("encrypt");
        let mut bytes = env.to_bytes();
        // Append a garbage trailer — must reject.
        bytes.push(0xAA);
        assert!(DkgShareEnvelope::from_bytes(&bytes).is_none());
    }

    #[test]
    fn envelope_decrypt_rejects_wrong_kyber_ct_length() {
        // Hand-craft an envelope with a kyber_ct of the wrong length
        // (e.g. 100 bytes). `decrypt_share_row` should still return
        // None without panicking — the wrong-length path is taken,
        // SS becomes zero, MAC check fails uniformly.
        let (_pk, sk) = kyber_keygen().expect("keygen");
        let bad = DkgShareEnvelope {
            kyber_ct: vec![0u8; 100],
            ciphertext: vec![0u8; ShareRow::WIRE_LEN],
            mac: [0u8; 32],
        };
        assert!(decrypt_share_row(&bad, &sk, 1, 1, 1).is_none());
    }

    #[test]
    fn envelope_decryption_is_deterministic_in_keys() {
        // Same row, same keys, different invocations → encryption
        // is randomized (Kyber picks fresh randomness), so two
        // envelopes for the same row differ — but BOTH decrypt
        // back to the same row.
        let (pk, sk) = kyber_keygen().expect("kyber_keygen");
        let row = make_row(2, 42);
        let env1 = encrypt_share_row(&row, &pk, 1, 1).expect("encrypt 1");
        let env2 = encrypt_share_row(&row, &pk, 1, 1).expect("encrypt 2");
        assert_ne!(env1, env2, "Kyber encapsulation is randomized");
        let r1 = decrypt_share_row(&env1, &sk, 1, 1, 2).expect("decrypt 1");
        let r2 = decrypt_share_row(&env2, &sk, 1, 1, 2).expect("decrypt 2");
        assert_eq!(r1, r2);
        assert_eq!(r1, row);
    }
}
