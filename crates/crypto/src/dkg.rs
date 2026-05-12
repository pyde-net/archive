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

/// Domain separator for the Falcon signature over a DKG complaint.
pub const DKG_COMPLAINT_SIG_DOMAIN: &[u8] = b"PYDE_DKG_COMPLAINT_V1\0";

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

// --- Reveal-share complaint mechanism ---

/// The outcome of verifying a [`DkgComplaint`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComplaintVerdict {
    /// The complainant's Falcon signature over the complaint
    /// preimage doesn't verify against the supplied public key.
    /// The complaint is structurally invalid; no party is implicated.
    InvalidSignature,
    /// The complaint is internally malformed in a way that doesn't
    /// involve cryptography — e.g. the attached Merkle proof's
    /// declared leaf index doesn't match the complainant's stated
    /// committee position. No party is implicated.
    Malformed,
    /// Recomputing the envelope MAC under the revealed shared
    /// secret doesn't match the MAC in the envelope. Either the
    /// complainant published a fake shared secret or the envelope
    /// is corrupt — in either case the complaint can't be settled
    /// from the supplied evidence. The caller's policy decides
    /// whether to fall back to interactive re-broadcast or treat
    /// the accused as faulty.
    EnvelopeUnverifiable,
    /// The complaint settles AGAINST the accused contributor:
    /// either the envelope decrypts to malformed bytes, or the
    /// decoded row has the wrong receiver_index, or the row's
    /// leaf hash + supplied Merkle proof do not reconstruct the
    /// contributor's signed Merkle root.
    ContributorFaulty,
    /// The complaint settles AGAINST the complainant: the
    /// envelope decrypts to a well-formed row at the correct
    /// receiver_index, and that row's leaf hash + supplied Merkle
    /// proof reconstruct the contributor's signed Merkle root.
    /// The complainant is slandering an honest contributor.
    Slander,
}

/// A signed accusation that contributor `from_index` sent the
/// complainant (committee position `against_index`) a share-row
/// that is inconsistent with the contributor's signed Merkle root
/// for `epoch`.
///
/// To make the accusation publicly verifiable without forcing the
/// complainant to reveal their long-term Kyber secret key, the
/// complaint carries `revealed_ss` — the per-envelope shared
/// secret derived from `envelope.kyber_ct` via decapsulation. The
/// leak is bounded to this one envelope; the long-term key stays
/// private.
///
/// Slander is detected because revealing a fake `revealed_ss`
/// breaks the envelope MAC (handled by `EnvelopeUnverifiable`),
/// and revealing the real one lets verifiers re-derive the
/// plaintext and re-check the Merkle inclusion against the
/// contributor's signed root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgComplaint {
    pub epoch: u64,
    /// 1-based index of the contributor being accused.
    pub from_index: usize,
    /// 1-based committee position of the complainant.
    pub against_index: usize,
    /// The envelope the complainant claims they received.
    pub envelope: DkgShareEnvelope,
    /// The shared secret the complainant decapsulated from
    /// `envelope.kyber_ct`. Revealed so verifiers can replay
    /// keystream derivation and MAC check.
    pub revealed_ss: [u8; 32],
    /// The Merkle inclusion proof for the complainant's leaf
    /// position in the contributor's tree.
    pub merkle_proof: MerkleProof,
    /// Falcon-512 signature from the complainant over the
    /// canonical preimage.
    pub signature: Vec<u8>,
}

impl DkgComplaint {
    pub fn new_unsigned(
        epoch: u64,
        from_index: usize,
        against_index: usize,
        envelope: DkgShareEnvelope,
        revealed_ss: [u8; 32],
        merkle_proof: MerkleProof,
    ) -> Self {
        Self {
            epoch,
            from_index,
            against_index,
            envelope,
            revealed_ss,
            merkle_proof,
            signature: Vec::new(),
        }
    }

    /// Canonical signing preimage. Includes the domain tag, the
    /// `(epoch, from_index, against_index)` tuple, a hash binding
    /// the envelope wire bytes, the revealed shared secret, and a
    /// hash binding the Merkle proof wire bytes. Hashing the wire
    /// bytes keeps the preimage a fixed prefix length regardless
    /// of envelope / proof size.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let envelope_hash = poseidon2_hash(&self.envelope.to_bytes()).to_bytes();
        let proof_hash = poseidon2_hash(&self.merkle_proof.to_bytes()).to_bytes();
        let mut buf = Vec::with_capacity(
            DKG_COMPLAINT_SIG_DOMAIN.len() + 8 + 4 + 4 + 32 + 32 + 32,
        );
        buf.extend_from_slice(DKG_COMPLAINT_SIG_DOMAIN);
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(&(self.from_index as u32).to_le_bytes());
        buf.extend_from_slice(&(self.against_index as u32).to_le_bytes());
        buf.extend_from_slice(&envelope_hash);
        buf.extend_from_slice(&self.revealed_ss);
        buf.extend_from_slice(&proof_hash);
        buf
    }

    /// Falcon-sign the complaint in place.
    pub fn sign(&mut self, sk: &FalconSecretKey) -> Result<(), &'static str> {
        let msg = self.signing_preimage();
        let sig = falcon_sign(sk, &msg)?;
        self.signature = sig.to_vec();
        Ok(())
    }

    /// Wire encoding:
    /// `epoch(8) || from_index(4) || against_index(4)
    ///   || env_len(4) || env_bytes
    ///   || revealed_ss(32)
    ///   || proof_len(4) || proof_bytes
    ///   || sig_len(4) || sig_bytes`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let env_bytes = self.envelope.to_bytes();
        let proof_bytes = self.merkle_proof.to_bytes();
        let mut out = Vec::with_capacity(
            8 + 4 + 4 + 4 + env_bytes.len() + 32 + 4 + proof_bytes.len() + 4 + self.signature.len(),
        );
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&(self.from_index as u32).to_le_bytes());
        out.extend_from_slice(&(self.against_index as u32).to_le_bytes());
        out.extend_from_slice(&(env_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&env_bytes);
        out.extend_from_slice(&self.revealed_ss);
        out.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&proof_bytes);
        out.extend_from_slice(&(self.signature.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 + 4 + 4 + 4 {
            return None;
        }
        let epoch = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let from_index =
            u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        let against_index =
            u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let env_len =
            u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
        let env_end = 20 + env_len;
        if bytes.len() < env_end + 32 + 4 {
            return None;
        }
        let envelope = DkgShareEnvelope::from_bytes(&bytes[20..env_end])?;
        let mut revealed_ss = [0u8; 32];
        revealed_ss.copy_from_slice(&bytes[env_end..env_end + 32]);
        let proof_len_off = env_end + 32;
        let proof_len = u32::from_le_bytes([
            bytes[proof_len_off],
            bytes[proof_len_off + 1],
            bytes[proof_len_off + 2],
            bytes[proof_len_off + 3],
        ]) as usize;
        let proof_end = proof_len_off + 4 + proof_len;
        if bytes.len() < proof_end + 4 {
            return None;
        }
        let merkle_proof = MerkleProof::from_bytes(&bytes[proof_len_off + 4..proof_end])?;
        let sig_len = u32::from_le_bytes([
            bytes[proof_end],
            bytes[proof_end + 1],
            bytes[proof_end + 2],
            bytes[proof_end + 3],
        ]) as usize;
        if bytes.len() != proof_end + 4 + sig_len {
            return None;
        }
        let signature = bytes[proof_end + 4..].to_vec();
        Some(Self {
            epoch,
            from_index,
            against_index,
            envelope,
            revealed_ss,
            merkle_proof,
            signature,
        })
    }
}

/// Verify a [`DkgComplaint`] against the complainant's Falcon
/// public key and the contributor's signed Merkle root for the
/// epoch. See [`ComplaintVerdict`] for the possible outcomes; this
/// function never panics.
pub fn verify_complaint(
    complaint: &DkgComplaint,
    complainant_falcon_pk: &FalconPublicKey,
    contributor_merkle_root: &[u8; 32],
) -> ComplaintVerdict {
    // 1. Falcon signature over the canonical preimage.
    let Some(sig) = FalconSignature::from_bytes(&complaint.signature) else {
        return ComplaintVerdict::InvalidSignature;
    };
    let preimage = complaint.signing_preimage();
    if !falcon_verify(complainant_falcon_pk, &preimage, &sig) {
        return ComplaintVerdict::InvalidSignature;
    }

    // 2. Merkle proof must declare the complainant's position.
    if complaint.merkle_proof.leaf_index + 1 != complaint.against_index {
        return ComplaintVerdict::Malformed;
    }

    // 3. Reconstruct the SharedSecret from the revealed bytes and
    //    recompute the AEAD MAC over the envelope. Mismatch means
    //    the revealed_ss is wrong or the envelope is corrupt.
    let ss = SharedSecret::from_bytes(complaint.revealed_ss);
    let expected_mac = dkg_aead_mac(
        &ss,
        &complaint.envelope.kyber_ct,
        complaint.epoch,
        complaint.from_index,
        complaint.against_index,
        &complaint.envelope.ciphertext,
    );
    if expected_mac.ct_eq(&complaint.envelope.mac).unwrap_u8() != 1 {
        return ComplaintVerdict::EnvelopeUnverifiable;
    }

    // 4. MAC OK → derive keystream and decrypt the ciphertext.
    let keystream = dkg_aead_keystream(
        &ss,
        &complaint.envelope.kyber_ct,
        complaint.epoch,
        complaint.from_index,
        complaint.against_index,
        complaint.envelope.ciphertext.len(),
    );
    let mut plaintext = vec![0u8; complaint.envelope.ciphertext.len()];
    for i in 0..plaintext.len() {
        plaintext[i] = complaint.envelope.ciphertext[i] ^ keystream[i];
    }
    // Malformed plaintext or wrong internal receiver_index ⇒ contributor faulty.
    let Some(row) = ShareRow::from_bytes(&plaintext) else {
        return ComplaintVerdict::ContributorFaulty;
    };
    if row.receiver_index != complaint.against_index {
        return ComplaintVerdict::ContributorFaulty;
    }

    // 5. Merkle inclusion check against the contributor's signed root.
    let leaf = row.leaf_hash(complaint.epoch, complaint.from_index);
    if verify_merkle_proof(contributor_merkle_root, &leaf, &complaint.merkle_proof) {
        // Row is committed under the contributor's signed root at
        // the right position — there's nothing to complain about.
        ComplaintVerdict::Slander
    } else {
        // Row decrypts cleanly but the contributor's commitment
        // disowns it — contributor was equivocating between the
        // committed root and the encrypted share.
        ComplaintVerdict::ContributorFaulty
    }
}

// --- Phase E.1: contribution generation, share verification, share aggregation ---

/// Cap on Goldilocks rejection-sampling retries before we declare
/// the supplied entropy or RNG broken. The per-iteration success
/// probability is `~1 - 2^-32`; in practice the very first draw
/// succeeds.
const MAX_REJECTION_RETRIES: u32 = 64;

/// Domain separator for sampling the contributor's secret seed
/// elements from `rng_seed`.
const DKG_SECRET_SEED_DOMAIN: &[u8] = b"PYDE_DKG_SECRET_SEED_V1\0";

/// Domain separator for sampling Shamir polynomial coefficients
/// (non-constant terms) from `rng_seed`.
const DKG_POLY_COEFF_DOMAIN: &[u8] = b"PYDE_DKG_POLY_COEFF_V1\0";

/// Sample one canonical Goldilocks element keyed by
/// `(domain, rng_seed, from_index, element_idx, coeff_idx)`.
/// `coeff_idx = 0` is the constant term (the secret); higher
/// indices are polynomial coefficients. Rejection-samples values
/// `< GOLDILOCKS_PRIME` so the distribution is uniform on the
/// field (audit-391 pattern).
fn sample_goldilocks(
    domain: &[u8],
    rng_seed: &[u8; 32],
    from_index: usize,
    element_idx: usize,
    coeff_idx: usize,
) -> Result<Goldilocks, &'static str> {
    let mut attempt: u64 = 0;
    loop {
        if attempt as u32 >= MAX_REJECTION_RETRIES {
            return Err("DKG sampling exceeded rejection-retry budget");
        }
        let mut input =
            Vec::with_capacity(domain.len() + 32 + 4 + 4 + 4 + 8);
        input.extend_from_slice(domain);
        input.extend_from_slice(rng_seed);
        input.extend_from_slice(&(from_index as u32).to_le_bytes());
        input.extend_from_slice(&(element_idx as u32).to_le_bytes());
        input.extend_from_slice(&(coeff_idx as u32).to_le_bytes());
        input.extend_from_slice(&attempt.to_le_bytes());
        let hash = poseidon2_hash(&input);
        let bytes = hash.as_bytes();
        let val = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        if val < GOLDILOCKS_PRIME {
            return Ok(gl(val));
        }
        attempt += 1;
    }
}

/// Shamir-split a single Goldilocks element into `n` y-values at
/// `x = 1..=n`. Polynomial coefficients are sampled deterministically
/// from `(rng_seed, from_index, element_idx)` via
/// [`sample_goldilocks`]. The constant term is the secret.
fn dkg_shamir_split_y(
    secret: Goldilocks,
    n: usize,
    threshold: usize,
    rng_seed: &[u8; 32],
    from_index: usize,
    element_idx: usize,
) -> Result<Vec<Goldilocks>, &'static str> {
    let mut coeffs = Vec::with_capacity(threshold);
    coeffs.push(secret);
    for k in 1..threshold {
        coeffs.push(sample_goldilocks(
            DKG_POLY_COEFF_DOMAIN,
            rng_seed,
            from_index,
            element_idx,
            k,
        )?);
    }
    let mut ys = Vec::with_capacity(n);
    for j in 1..=n {
        let x = gl(j as u64);
        let mut y = Goldilocks::default();
        let mut x_pow = gl(1);
        for c in &coeffs {
            y += *c * x_pow;
            x_pow *= x;
        }
        ys.push(y);
    }
    Ok(ys)
}

/// One DKG contributor's outputs for round `epoch`: the signed
/// Merkle-root commitment, per-recipient encrypted share envelopes
/// + Merkle proofs, and the contributor's own share-row (which
/// they retain for the aggregation step instead of mailing to
/// themselves).
#[derive(Clone, Debug)]
pub struct DkgContribution {
    pub commitment: DkgCommitment,
    /// Length `n`. `recipient_envelopes[j - 1]` is the envelope +
    /// proof addressed to committee member `j` (1-based).
    pub recipient_envelopes: Vec<(DkgShareEnvelope, MerkleProof)>,
    /// The contributor's own share-row at position `from_index`.
    pub own_share_row: ShareRow,
    /// Merkle inclusion proof for `own_share_row`.
    pub own_merkle_proof: MerkleProof,
}

/// Why a recipient rejected a contributor's share. Maps directly
/// onto the inputs of a [`DkgComplaint`] (see Phase D).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareVerificationError {
    /// Contributor's Falcon signature on their `DkgCommitment`
    /// doesn't verify under their published Falcon pk.
    CommitmentSignatureInvalid,
    /// The commitment's `(epoch, from_index, n, threshold)` header
    /// doesn't match the round parameters the recipient expects.
    CommitmentHeaderMismatch,
    /// The envelope's MAC fails, the ciphertext doesn't decode as
    /// a `ShareRow`, or the row's `receiver_index` doesn't match
    /// the recipient's position. (All three collapse to a single
    /// rejection so the rejection is timing-uniform.)
    EnvelopeUndecryptable,
    /// `merkle_proof.leaf_index + 1` doesn't match the recipient's
    /// own committee position.
    MerkleProofPositionMismatch,
    /// The row's leaf hash + supplied Merkle proof do not
    /// reconstruct the contributor's signed Merkle root.
    MerkleProofMismatch,
}

/// One validator's share of the threshold master secret, formed
/// by element-wise summing share-rows from all non-faulty
/// contributors. The values are y-values of an implicit master
/// polynomial whose constant term is `Σ_i seed_i` (the sum of
/// contributors' fresh per-round secrets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MasterShare {
    /// 1-based committee position of the holder.
    pub index: usize,
    /// Aggregated y-values, one per seed element.
    pub values: [Goldilocks; SEED_ELEMENTS],
}

impl MasterShare {
    /// Wire size: 4 (index) + 8 * SEED_ELEMENTS bytes.
    pub const WIRE_LEN: usize = 4 + 8 * SEED_ELEMENTS;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::WIRE_LEN);
        out.extend_from_slice(&(self.index as u32).to_le_bytes());
        for v in &self.values {
            out.extend_from_slice(&gl_to_u64(*v).to_le_bytes());
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::WIRE_LEN {
            return None;
        }
        let index = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
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
        Some(Self { index, values })
    }
}

/// Build a full DKG contribution as committee member `from_index`.
///
/// The contributor's fresh secret seed is sampled deterministically
/// from `(rng_seed, from_index)` — callers should feed in a fresh
/// per-round random `rng_seed` for security; reusing the same seed
/// across rounds reproduces the same secret.
///
/// `recipient_kem_pks[j - 1]` must be committee member `j`'s Kyber
/// public key. The contributor's own slot in this list is allowed
/// to be any valid Kyber pk — the function does not encrypt the
/// contributor's own share-row (it goes back via `own_share_row`).
pub fn generate_dkg_contribution(
    rng_seed: &[u8; 32],
    epoch: u64,
    from_index: usize,
    n: usize,
    threshold: usize,
    recipient_kem_pks: &[KyberPublicKey],
    falcon_sk: &FalconSecretKey,
) -> Result<DkgContribution, &'static str> {
    if from_index == 0 || from_index > n {
        return Err("from_index out of range (must be 1..=n)");
    }
    if threshold == 0 || threshold > n {
        return Err("threshold out of range (must be 1..=n)");
    }
    if recipient_kem_pks.len() != n {
        return Err("recipient_kem_pks length must equal n");
    }

    // Sample the contributor's 8-element secret seed.
    let mut secret = [Goldilocks::default(); SEED_ELEMENTS];
    for k in 0..SEED_ELEMENTS {
        secret[k] = sample_goldilocks(
            DKG_SECRET_SEED_DOMAIN,
            rng_seed,
            from_index,
            k,
            0,
        )?;
    }

    // Per-element Shamir split. `ys[k]` is the length-`n` vector
    // of y-values for the k-th polynomial; `ys[k][j-1]` is the
    // y-value at x = j.
    let mut ys: Vec<Vec<Goldilocks>> = Vec::with_capacity(SEED_ELEMENTS);
    for k in 0..SEED_ELEMENTS {
        ys.push(dkg_shamir_split_y(
            secret[k],
            n,
            threshold,
            rng_seed,
            from_index,
            k,
        )?);
    }

    // Build the n share-rows and their leaf hashes.
    let mut rows: Vec<ShareRow> = Vec::with_capacity(n);
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(n);
    for j in 1..=n {
        let mut values = [Goldilocks::default(); SEED_ELEMENTS];
        for k in 0..SEED_ELEMENTS {
            values[k] = ys[k][j - 1];
        }
        let row = ShareRow {
            receiver_index: j,
            values,
        };
        leaves.push(row.leaf_hash(epoch, from_index));
        rows.push(row);
    }

    // Merkle root + Falcon-signed commitment.
    let merkle_root = compute_merkle_root(&leaves, epoch, from_index);
    let mut commitment =
        DkgCommitment::new_unsigned(epoch, from_index, n, threshold, merkle_root);
    commitment.sign(falcon_sk)?;

    // Pre-compute per-recipient Merkle proofs.
    let proofs: Vec<MerkleProof> = (0..n)
        .map(|j| {
            merkle_proof(&leaves, j, epoch, from_index)
                .expect("leaves and indices are in range by construction")
        })
        .collect();

    // Encrypt each recipient's row under their KEM pk. The
    // contributor's OWN row is not encrypted — it's returned as a
    // plaintext `own_share_row` so the contributor can feed it
    // directly into [`aggregate_local_share`].
    let mut recipient_envelopes: Vec<(DkgShareEnvelope, MerkleProof)> = Vec::with_capacity(n);
    let mut own_share_row: Option<ShareRow> = None;
    let mut own_merkle_proof: Option<MerkleProof> = None;
    for (j_minus_one, row) in rows.into_iter().enumerate() {
        let j = j_minus_one + 1;
        if j == from_index {
            // Slot still occupied in recipient_envelopes for
            // index alignment, but with a self-addressed envelope
            // that the contributor will skip.
            let env = encrypt_share_row(&row, &recipient_kem_pks[j - 1], epoch, from_index)?;
            recipient_envelopes.push((env, proofs[j_minus_one].clone()));
            own_share_row = Some(row);
            own_merkle_proof = Some(proofs[j_minus_one].clone());
        } else {
            let env = encrypt_share_row(&row, &recipient_kem_pks[j - 1], epoch, from_index)?;
            recipient_envelopes.push((env, proofs[j_minus_one].clone()));
        }
    }

    Ok(DkgContribution {
        commitment,
        recipient_envelopes,
        own_share_row: own_share_row.expect("from_index in 1..=n by check above"),
        own_merkle_proof: own_merkle_proof.expect("from_index in 1..=n by check above"),
    })
}

/// Verify a received share from a single contributor, returning
/// the decrypted [`ShareRow`] on success or a
/// [`ShareVerificationError`] indicating which check failed
/// (suitable for constructing a [`DkgComplaint`]).
///
/// Checks (in order):
/// 1. Commitment signature is valid under `contributor_falcon_pk`.
/// 2. Commitment header matches the expected round parameters.
/// 3. Merkle proof's `leaf_index + 1 == recipient_index`.
/// 4. Envelope decapsulates + decrypts to a well-formed row at
///    `recipient_index`.
/// 5. Row's leaf hash + proof reconstruct `commitment.merkle_root`.
pub fn verify_received_share(
    envelope: &DkgShareEnvelope,
    proof: &MerkleProof,
    contributor_commitment: &DkgCommitment,
    contributor_falcon_pk: &FalconPublicKey,
    expected_epoch: u64,
    expected_from_index: usize,
    expected_n: usize,
    expected_threshold: usize,
    recipient_index: usize,
    recipient_kem_sk: &KyberSecretKey,
) -> Result<ShareRow, ShareVerificationError> {
    if !contributor_commitment.verify(contributor_falcon_pk) {
        return Err(ShareVerificationError::CommitmentSignatureInvalid);
    }
    if contributor_commitment.epoch != expected_epoch
        || contributor_commitment.from_index != expected_from_index
        || contributor_commitment.n != expected_n
        || contributor_commitment.threshold != expected_threshold
    {
        return Err(ShareVerificationError::CommitmentHeaderMismatch);
    }
    if proof.leaf_index + 1 != recipient_index {
        return Err(ShareVerificationError::MerkleProofPositionMismatch);
    }
    let Some(row) = decrypt_share_row(
        envelope,
        recipient_kem_sk,
        expected_epoch,
        expected_from_index,
        recipient_index,
    ) else {
        return Err(ShareVerificationError::EnvelopeUndecryptable);
    };
    let leaf = row.leaf_hash(expected_epoch, expected_from_index);
    if !verify_merkle_proof(&contributor_commitment.merkle_root, &leaf, proof) {
        return Err(ShareVerificationError::MerkleProofMismatch);
    }
    Ok(row)
}

/// Aggregate per-contributor share-rows into the holder's local
/// share of the master secret. All input rows must address the
/// same holder (`receiver_index == holder_index`); per-element
/// summing is over the Goldilocks field.
///
/// Returns an `Err` for defensively-invalid inputs (empty input,
/// index mismatch). A degenerate `MasterShare` (`values` all zero,
/// e.g. every contributor was excluded) is a legitimate output
/// signaling "all contributors faulted" — callers decide whether
/// to treat that as a round failure.
pub fn aggregate_local_share(
    holder_index: usize,
    verified_share_rows: &[ShareRow],
) -> Result<MasterShare, &'static str> {
    if verified_share_rows.is_empty() {
        return Err("aggregate_local_share: no contributors");
    }
    let mut values = [Goldilocks::default(); SEED_ELEMENTS];
    for row in verified_share_rows {
        if row.receiver_index != holder_index {
            return Err("aggregate_local_share: row addressed to a different holder");
        }
        for k in 0..SEED_ELEMENTS {
            values[k] += row.values[k];
        }
    }
    Ok(MasterShare {
        index: holder_index,
        values,
    })
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

    // --- Phase D: complaint tests ---

    /// Build a contributor's tree, encrypt one of the rows for a
    /// specific recipient, decapsulate to expose the shared secret,
    /// and return everything needed for complaint testing.
    fn build_complaint_fixture(
        epoch: u64,
        from_index: usize,
        n: usize,
        target_recipient: usize, // 1-based
    ) -> (
        Vec<ShareRow>,
        [u8; 32], // contributor merkle root
        DkgShareEnvelope,
        [u8; 32], // revealed ss
        MerkleProof,
        FalconPublicKey,
        FalconSecretKey,
        crate::kyber::KyberSecretKey,
    ) {
        let rows: Vec<ShareRow> = (1..=n).map(|i| make_row(i, 1000 + i as u64)).collect();
        let leaves: Vec<[u8; 32]> = rows.iter().map(|r| r.leaf_hash(epoch, from_index)).collect();
        let root = compute_merkle_root(&leaves, epoch, from_index);
        let proof = merkle_proof(&leaves, target_recipient - 1, epoch, from_index)
            .expect("merkle proof exists");

        let (recipient_pk, recipient_sk) = kyber_keygen().expect("kyber_keygen recipient");
        let (kct, ss) = kyber_encapsulate(&recipient_pk).expect("encap");
        let row = &rows[target_recipient - 1];
        // Hand-encrypt so we can keep the SS around.
        let plaintext = row.to_bytes();
        let keystream = dkg_aead_keystream(
            &ss,
            kct.as_bytes(),
            epoch,
            from_index,
            target_recipient,
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
            target_recipient,
            &ciphertext,
        );
        let envelope = DkgShareEnvelope {
            kyber_ct: kct.to_vec(),
            ciphertext,
            mac,
        };
        let (complainant_pk, complainant_sk) = falcon_keygen().expect("falcon");

        (
            rows,
            root,
            envelope,
            *ss.as_bytes(),
            proof,
            complainant_pk,
            complainant_sk,
            recipient_sk,
        )
    }

    #[test]
    fn complaint_slander_when_row_matches_root() {
        // Honest contributor case: row at position j IS in the
        // tree under root r. Complainant tries to file a complaint
        // anyway. Verdict must be Slander.
        let epoch = 11;
        let from_index = 2;
        let n = 5;
        let target = 3;
        let (_rows, root, envelope, ss, proof, c_pk, c_sk, _sk) =
            build_complaint_fixture(epoch, from_index, n, target);
        let mut complaint = DkgComplaint::new_unsigned(
            epoch,
            from_index,
            target,
            envelope,
            ss,
            proof,
        );
        complaint.sign(&c_sk).expect("sign");
        assert_eq!(
            verify_complaint(&complaint, &c_pk, &root),
            ComplaintVerdict::Slander
        );
    }

    #[test]
    fn complaint_contributor_faulty_when_root_is_wrong() {
        // Adversarial contributor case: the complainant supplies
        // a proof against a root that the row's leaf hash does NOT
        // reconstruct to. Verdict must be ContributorFaulty.
        let epoch = 11;
        let from_index = 2;
        let target = 3;
        let (_rows, _real_root, envelope, ss, proof, c_pk, c_sk, _sk) =
            build_complaint_fixture(epoch, from_index, 5, target);
        let mut complaint = DkgComplaint::new_unsigned(
            epoch,
            from_index,
            target,
            envelope,
            ss,
            proof,
        );
        complaint.sign(&c_sk).expect("sign");
        let bogus_root = [0xAAu8; 32];
        assert_eq!(
            verify_complaint(&complaint, &c_pk, &bogus_root),
            ComplaintVerdict::ContributorFaulty
        );
    }

    #[test]
    fn complaint_contributor_faulty_on_malformed_plaintext() {
        // Encrypt random bytes (NOT a valid ShareRow) but with a
        // valid MAC. After decryption, the plaintext fails to
        // decode → ContributorFaulty.
        let epoch = 3;
        let from_index = 1;
        let target = 2;
        let (_rows, root, _envelope_real, _ss_real, proof, c_pk, c_sk, _sk) =
            build_complaint_fixture(epoch, from_index, 4, target);

        // Build a forged envelope: a "well-formed-by-MAC" envelope
        // whose plaintext is garbage that won't decode as a
        // ShareRow.
        let (recipient_pk, _recipient_sk) = kyber_keygen().expect("recipient");
        let (kct, ss) = kyber_encapsulate(&recipient_pk).expect("encap");
        let mut garbage = vec![0xFFu8; ShareRow::WIRE_LEN];
        // First 4 bytes = receiver_index; everything else is the
        // 8 Goldilocks values. Set every Goldilocks value to
        // u64::MAX (which is >= GOLDILOCKS_PRIME so ShareRow
        // rejects it during decode).
        garbage[0..4].copy_from_slice(&(target as u32).to_le_bytes());
        let keystream =
            dkg_aead_keystream(&ss, kct.as_bytes(), epoch, from_index, target, garbage.len());
        let mut ciphertext = Vec::with_capacity(garbage.len());
        for i in 0..garbage.len() {
            ciphertext.push(garbage[i] ^ keystream[i]);
        }
        let mac = dkg_aead_mac(
            &ss,
            kct.as_bytes(),
            epoch,
            from_index,
            target,
            &ciphertext,
        );
        let envelope = DkgShareEnvelope {
            kyber_ct: kct.to_vec(),
            ciphertext,
            mac,
        };
        let mut complaint = DkgComplaint::new_unsigned(
            epoch,
            from_index,
            target,
            envelope,
            *ss.as_bytes(),
            proof,
        );
        complaint.sign(&c_sk).expect("sign");
        assert_eq!(
            verify_complaint(&complaint, &c_pk, &root),
            ComplaintVerdict::ContributorFaulty
        );
    }

    #[test]
    fn complaint_contributor_faulty_on_wrong_internal_index() {
        // Contributor encrypts a row whose internal receiver_index
        // is 5, but binds the MAC under recipient_index=2. The
        // complaint settles ContributorFaulty.
        let epoch = 3;
        let from_index = 1;
        let target = 2;
        let (_rows, root, _env, _ss_real, proof, c_pk, c_sk, _sk) =
            build_complaint_fixture(epoch, from_index, 4, target);
        let (recipient_pk, _recipient_sk) = kyber_keygen().expect("recipient");
        let (kct, ss) = kyber_encapsulate(&recipient_pk).expect("encap");
        let plaintext_row = make_row(5, 7);
        let plaintext = plaintext_row.to_bytes();
        let keystream = dkg_aead_keystream(
            &ss,
            kct.as_bytes(),
            epoch,
            from_index,
            target,
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
            target,
            &ciphertext,
        );
        let envelope = DkgShareEnvelope {
            kyber_ct: kct.to_vec(),
            ciphertext,
            mac,
        };
        let mut complaint = DkgComplaint::new_unsigned(
            epoch,
            from_index,
            target,
            envelope,
            *ss.as_bytes(),
            proof,
        );
        complaint.sign(&c_sk).expect("sign");
        assert_eq!(
            verify_complaint(&complaint, &c_pk, &root),
            ComplaintVerdict::ContributorFaulty
        );
    }

    #[test]
    fn complaint_envelope_unverifiable_on_tampered_mac() {
        // Honest envelope, but the complainant submits a tampered
        // MAC (or a fake revealed_ss). Either way the MAC check
        // fails → EnvelopeUnverifiable.
        let epoch = 3;
        let from_index = 1;
        let target = 2;
        let (_rows, root, mut envelope, ss, proof, c_pk, c_sk, _sk) =
            build_complaint_fixture(epoch, from_index, 4, target);
        envelope.mac[0] ^= 0xFF;
        let mut complaint = DkgComplaint::new_unsigned(
            epoch,
            from_index,
            target,
            envelope,
            ss,
            proof,
        );
        complaint.sign(&c_sk).expect("sign");
        assert_eq!(
            verify_complaint(&complaint, &c_pk, &root),
            ComplaintVerdict::EnvelopeUnverifiable
        );
    }

    #[test]
    fn complaint_envelope_unverifiable_on_fake_revealed_ss() {
        // The complainant reveals a wrong SS. The recomputed MAC
        // won't match the real envelope's MAC.
        let epoch = 3;
        let from_index = 1;
        let target = 2;
        let (_rows, root, envelope, _real_ss, proof, c_pk, c_sk, _sk) =
            build_complaint_fixture(epoch, from_index, 4, target);
        let fake_ss = [0xAAu8; 32];
        let mut complaint = DkgComplaint::new_unsigned(
            epoch,
            from_index,
            target,
            envelope,
            fake_ss,
            proof,
        );
        complaint.sign(&c_sk).expect("sign");
        assert_eq!(
            verify_complaint(&complaint, &c_pk, &root),
            ComplaintVerdict::EnvelopeUnverifiable
        );
    }

    #[test]
    fn complaint_invalid_signature_when_signed_by_wrong_key() {
        let epoch = 3;
        let from_index = 1;
        let target = 2;
        let (_rows, root, envelope, ss, proof, c_pk_legit, _c_sk_legit, _sk) =
            build_complaint_fixture(epoch, from_index, 4, target);
        let (_pk_attacker, sk_attacker) = falcon_keygen().expect("attacker keys");
        let mut complaint = DkgComplaint::new_unsigned(
            epoch,
            from_index,
            target,
            envelope,
            ss,
            proof,
        );
        complaint.sign(&sk_attacker).expect("sign with attacker");
        assert_eq!(
            verify_complaint(&complaint, &c_pk_legit, &root),
            ComplaintVerdict::InvalidSignature
        );
    }

    #[test]
    fn complaint_invalid_signature_on_tampered_field() {
        let epoch = 3;
        let from_index = 1;
        let target = 2;
        let (_rows, root, envelope, ss, proof, c_pk, c_sk, _sk) =
            build_complaint_fixture(epoch, from_index, 4, target);
        let mut complaint = DkgComplaint::new_unsigned(
            epoch,
            from_index,
            target,
            envelope,
            ss,
            proof,
        );
        complaint.sign(&c_sk).expect("sign");
        // Flip the epoch after signing — preimage changes, sig stays.
        complaint.epoch = epoch + 1;
        assert_eq!(
            verify_complaint(&complaint, &c_pk, &root),
            ComplaintVerdict::InvalidSignature
        );
    }

    #[test]
    fn complaint_malformed_when_proof_index_mismatch() {
        let epoch = 3;
        let from_index = 1;
        let target = 2;
        let (_rows, root, envelope, ss, mut proof, c_pk, c_sk, _sk) =
            build_complaint_fixture(epoch, from_index, 4, target);
        // Force proof.leaf_index to a different position than
        // against_index suggests.
        proof.leaf_index = 0; // against_index 2 → expected 1
        let mut complaint = DkgComplaint::new_unsigned(
            epoch,
            from_index,
            target,
            envelope,
            ss,
            proof,
        );
        complaint.sign(&c_sk).expect("sign");
        assert_eq!(
            verify_complaint(&complaint, &c_pk, &root),
            ComplaintVerdict::Malformed
        );
    }

    #[test]
    fn complaint_wire_roundtrip() {
        let epoch = 9;
        let from_index = 2;
        let target = 3;
        let (_rows, _root, envelope, ss, proof, _c_pk, c_sk, _sk) =
            build_complaint_fixture(epoch, from_index, 6, target);
        let mut complaint = DkgComplaint::new_unsigned(
            epoch,
            from_index,
            target,
            envelope,
            ss,
            proof,
        );
        complaint.sign(&c_sk).expect("sign");
        let bytes = complaint.to_bytes();
        let decoded = DkgComplaint::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, complaint);
    }

    #[test]
    fn complaint_wire_rejects_truncation_and_garbage_trailer() {
        let epoch = 9;
        let from_index = 2;
        let target = 3;
        let (_rows, _root, envelope, ss, proof, _c_pk, c_sk, _sk) =
            build_complaint_fixture(epoch, from_index, 6, target);
        let mut complaint = DkgComplaint::new_unsigned(
            epoch,
            from_index,
            target,
            envelope,
            ss,
            proof,
        );
        complaint.sign(&c_sk).expect("sign");
        let bytes = complaint.to_bytes();
        assert!(DkgComplaint::from_bytes(&bytes[..bytes.len() - 1]).is_none());
        let mut padded = bytes.clone();
        padded.push(0xAA);
        assert!(DkgComplaint::from_bytes(&padded).is_none());
        assert!(DkgComplaint::from_bytes(&[]).is_none());
    }

    #[test]
    fn complaint_preimage_starts_with_domain() {
        let epoch = 1;
        let from_index = 1;
        let target = 1;
        let (_rows, _root, envelope, ss, proof, _c_pk, _c_sk, _sk) =
            build_complaint_fixture(epoch, from_index, 2, target);
        let complaint = DkgComplaint::new_unsigned(
            epoch,
            from_index,
            target,
            envelope,
            ss,
            proof,
        );
        assert!(complaint
            .signing_preimage()
            .starts_with(DKG_COMPLAINT_SIG_DOMAIN));
    }

    #[test]
    fn complaint_real_dkg_flow_end_to_end() {
        // End-to-end: a contributor sends shares via encrypt_share_row,
        // recipient decrypts via decrypt_share_row, recipient files a
        // complaint with the recovered SS by recapsulating their own
        // envelope.
        let epoch = 50;
        let from_index = 3;
        let target = 4;

        // Build contributor's tree.
        let n = 7;
        let rows: Vec<ShareRow> = (1..=n).map(|i| make_row(i, 200 + i as u64)).collect();
        let leaves: Vec<[u8; 32]> =
            rows.iter().map(|r| r.leaf_hash(epoch, from_index)).collect();
        let root = compute_merkle_root(&leaves, epoch, from_index);
        let proof = merkle_proof(&leaves, target - 1, epoch, from_index).expect("proof");

        // Recipient generates Kyber keys.
        let (recipient_pk, recipient_sk) = kyber_keygen().expect("kyber");
        // Contributor encrypts row j for the recipient.
        let env = encrypt_share_row(&rows[target - 1], &recipient_pk, epoch, from_index)
            .expect("encrypt");
        // Recipient decrypts.
        let recovered = decrypt_share_row(&env, &recipient_sk, epoch, from_index, target)
            .expect("decrypt");
        assert_eq!(recovered, rows[target - 1]);

        // Recipient's view: the share is consistent. Filing a
        // complaint anyway → must be Slander.
        let kct = KyberCiphertext::from_bytes(&env.kyber_ct).expect("kct from bytes");
        let ss = kyber_decapsulate(&recipient_sk, &kct).expect("decap");
        let (c_pk, c_sk) = falcon_keygen().expect("falcon");
        let mut complaint = DkgComplaint::new_unsigned(
            epoch,
            from_index,
            target,
            env,
            *ss.as_bytes(),
            proof,
        );
        complaint.sign(&c_sk).expect("sign");
        assert_eq!(
            verify_complaint(&complaint, &c_pk, &root),
            ComplaintVerdict::Slander
        );
    }

    // --- Phase E.1: contribution / verification / aggregation tests ---

    use crate::threshold::gl_inv as test_gl_inv;

    /// Lagrange interpolation at x=0 over Goldilocks. Used by tests
    /// to check that t MasterShares reconstruct the master secret.
    fn lagrange_at_zero(points: &[(Goldilocks, Goldilocks)]) -> Goldilocks {
        let t = points.len();
        let mut result = Goldilocks::default();
        for i in 0..t {
            let mut basis = gl(1);
            for j in 0..t {
                if i != j {
                    let num = Goldilocks::default() - points[j].0;
                    let den = points[i].0 - points[j].0;
                    basis *= num * test_gl_inv(den);
                }
            }
            result += points[i].1 * basis;
        }
        result
    }

    fn make_committee(n: usize) -> (Vec<KyberPublicKey>, Vec<crate::kyber::KyberSecretKey>, Vec<FalconPublicKey>, Vec<FalconSecretKey>) {
        let mut kem_pks = Vec::with_capacity(n);
        let mut kem_sks = Vec::with_capacity(n);
        let mut fal_pks = Vec::with_capacity(n);
        let mut fal_sks = Vec::with_capacity(n);
        for _ in 0..n {
            let (kpk, ksk) = kyber_keygen().expect("kyber keygen");
            let (fpk, fsk) = falcon_keygen().expect("falcon keygen");
            kem_pks.push(kpk);
            kem_sks.push(ksk);
            fal_pks.push(fpk);
            fal_sks.push(fsk);
        }
        (kem_pks, kem_sks, fal_pks, fal_sks)
    }

    fn run_full_dkg(
        epoch: u64,
        n: usize,
        threshold: usize,
    ) -> (
        Vec<DkgContribution>,
        Vec<MasterShare>,
        Vec<KyberPublicKey>,
        Vec<crate::kyber::KyberSecretKey>,
        Vec<FalconPublicKey>,
        Vec<FalconSecretKey>,
    ) {
        let (kem_pks, kem_sks, fal_pks, fal_sks) = make_committee(n);
        let mut contributions: Vec<DkgContribution> = Vec::with_capacity(n);
        for i in 1..=n {
            let mut seed = [0u8; 32];
            seed[0] = i as u8;
            seed[1] = epoch as u8;
            let contrib = generate_dkg_contribution(
                &seed,
                epoch,
                i,
                n,
                threshold,
                &kem_pks,
                &fal_sks[i - 1],
            )
            .expect("contribution");
            contributions.push(contrib);
        }

        let mut master_shares: Vec<MasterShare> = Vec::with_capacity(n);
        for j in 1..=n {
            let mut rows: Vec<ShareRow> = Vec::with_capacity(n);
            for (i_minus_one, contrib) in contributions.iter().enumerate() {
                let i = i_minus_one + 1;
                let row = if i == j {
                    // Own row — contributor uses the plaintext directly.
                    contrib.own_share_row.clone()
                } else {
                    let (env, proof) = &contrib.recipient_envelopes[j - 1];
                    verify_received_share(
                        env,
                        proof,
                        &contrib.commitment,
                        &fal_pks[i - 1],
                        epoch,
                        i,
                        n,
                        threshold,
                        j,
                        &kem_sks[j - 1],
                    )
                    .expect("share verifies in honest run")
                };
                rows.push(row);
            }
            master_shares.push(aggregate_local_share(j, &rows).expect("aggregate"));
        }

        (contributions, master_shares, kem_pks, kem_sks, fal_pks, fal_sks)
    }

    #[test]
    fn dkg_end_to_end_threshold_reconstructs_master_seed() {
        let epoch = 42;
        let n = 5;
        let threshold = 3;
        let (contributions, master_shares, _, _, _, _) = run_full_dkg(epoch, n, threshold);

        // Master secret = element-wise sum of contributors' secret
        // seeds. We can derive each contributor's seed by Lagrange-
        // reconstructing their own n-of-n shares — or, more
        // simply, by re-sampling using the same rng_seed deriviation
        // we used during contribution. Use t shares to reconstruct
        // each element of the MASTER seed and check it matches the
        // sum of per-contributor seeds reconstructed the same way.
        let pick: Vec<&MasterShare> = master_shares.iter().take(threshold).collect();
        let mut master_seed = [Goldilocks::default(); SEED_ELEMENTS];
        for k in 0..SEED_ELEMENTS {
            let points: Vec<(Goldilocks, Goldilocks)> = pick
                .iter()
                .map(|ms| (gl(ms.index as u64), ms.values[k]))
                .collect();
            master_seed[k] = lagrange_at_zero(&points);
        }

        // Reconstruct from each contributor's OWN share-rows.
        let mut expected = [Goldilocks::default(); SEED_ELEMENTS];
        for contrib in &contributions {
            // Take any threshold of this contributor's row pieces.
            // We have only `own_share_row` directly, plus envelopes
            // for others — to avoid a second decryption pass, build
            // up the rows from the contributor's own perspective by
            // re-running sample_goldilocks. Simpler: rebuild by
            // calling generate_dkg_contribution again with the same
            // seed and reading out the secret directly.
            let from_index = contrib.commitment.from_index;
            let mut seed = [0u8; 32];
            seed[0] = from_index as u8;
            seed[1] = epoch as u8;
            for k in 0..SEED_ELEMENTS {
                let s = sample_goldilocks(
                    DKG_SECRET_SEED_DOMAIN,
                    &seed,
                    from_index,
                    k,
                    0,
                )
                .expect("sample");
                expected[k] += s;
            }
        }
        assert_eq!(master_seed, expected);
    }

    #[test]
    fn dkg_distinct_threshold_subsets_reconstruct_same_master_seed() {
        let epoch = 10;
        let n = 6;
        let threshold = 4;
        let (_contribs, master_shares, _, _, _, _) = run_full_dkg(epoch, n, threshold);

        // First t shares.
        let pick_a: Vec<&MasterShare> = master_shares[0..threshold].iter().collect();
        // Last t shares.
        let pick_b: Vec<&MasterShare> = master_shares[n - threshold..].iter().collect();

        let mut seed_a = [Goldilocks::default(); SEED_ELEMENTS];
        let mut seed_b = [Goldilocks::default(); SEED_ELEMENTS];
        for k in 0..SEED_ELEMENTS {
            let pts_a: Vec<(Goldilocks, Goldilocks)> = pick_a
                .iter()
                .map(|m| (gl(m.index as u64), m.values[k]))
                .collect();
            let pts_b: Vec<(Goldilocks, Goldilocks)> = pick_b
                .iter()
                .map(|m| (gl(m.index as u64), m.values[k]))
                .collect();
            seed_a[k] = lagrange_at_zero(&pts_a);
            seed_b[k] = lagrange_at_zero(&pts_b);
        }
        assert_eq!(
            seed_a, seed_b,
            "any threshold-sized subset must reconstruct the same master seed"
        );
    }

    #[test]
    fn dkg_below_threshold_does_not_reconstruct() {
        // With fewer than `t` shares, Lagrange interpolation at x=0
        // produces some value that is NOT the actual master_seed —
        // i.e. the shares look independent of the secret. Test that
        // we don't accidentally reconstruct the right value.
        let epoch = 99;
        let n = 7;
        let threshold = 5;
        let (_contribs, master_shares, _, _, _, _) = run_full_dkg(epoch, n, threshold);

        let full: Vec<&MasterShare> = master_shares.iter().take(threshold).collect();
        let mut full_seed = [Goldilocks::default(); SEED_ELEMENTS];
        for k in 0..SEED_ELEMENTS {
            let pts: Vec<(Goldilocks, Goldilocks)> = full
                .iter()
                .map(|m| (gl(m.index as u64), m.values[k]))
                .collect();
            full_seed[k] = lagrange_at_zero(&pts);
        }

        let partial: Vec<&MasterShare> =
            master_shares.iter().take(threshold - 1).collect();
        let mut partial_seed = [Goldilocks::default(); SEED_ELEMENTS];
        for k in 0..SEED_ELEMENTS {
            let pts: Vec<(Goldilocks, Goldilocks)> = partial
                .iter()
                .map(|m| (gl(m.index as u64), m.values[k]))
                .collect();
            partial_seed[k] = lagrange_at_zero(&pts);
        }
        assert_ne!(
            full_seed, partial_seed,
            "t-1 shares must not match the t-share reconstruction"
        );
    }

    #[test]
    fn dkg_verify_share_rejects_commitment_signature() {
        let epoch = 7;
        let n = 4;
        let threshold = 3;
        let (kem_pks, kem_sks, fal_pks, fal_sks) = make_committee(n);
        let mut seed = [0u8; 32];
        seed[0] = 1;
        let contrib = generate_dkg_contribution(
            &seed, epoch, 1, n, threshold, &kem_pks, &fal_sks[0],
        )
        .expect("contribution");
        let (env, proof) = &contrib.recipient_envelopes[1];
        // Attacker's Falcon pk — sig should fail verify under it.
        let (attacker_pk, _attacker_sk) = falcon_keygen().expect("attacker");
        let _ = &fal_pks; // silence unused warning
        let err = verify_received_share(
            env,
            proof,
            &contrib.commitment,
            &attacker_pk,
            epoch,
            1,
            n,
            threshold,
            2,
            &kem_sks[1],
        )
        .unwrap_err();
        assert_eq!(err, ShareVerificationError::CommitmentSignatureInvalid);
    }

    #[test]
    fn dkg_verify_share_rejects_commitment_header_mismatch() {
        let epoch = 7;
        let n = 4;
        let threshold = 3;
        let (kem_pks, kem_sks, fal_pks, fal_sks) = make_committee(n);
        let mut seed = [0u8; 32];
        seed[0] = 1;
        let contrib = generate_dkg_contribution(
            &seed, epoch, 1, n, threshold, &kem_pks, &fal_sks[0],
        )
        .expect("contribution");
        let (env, proof) = &contrib.recipient_envelopes[1];
        // Wrong expected_epoch.
        let err = verify_received_share(
            env,
            proof,
            &contrib.commitment,
            &fal_pks[0],
            epoch + 1, // <-- mismatch
            1,
            n,
            threshold,
            2,
            &kem_sks[1],
        )
        .unwrap_err();
        assert_eq!(err, ShareVerificationError::CommitmentHeaderMismatch);
    }

    #[test]
    fn dkg_verify_share_rejects_proof_position_mismatch() {
        let epoch = 7;
        let n = 4;
        let threshold = 3;
        let (kem_pks, kem_sks, fal_pks, fal_sks) = make_committee(n);
        let mut seed = [0u8; 32];
        seed[0] = 1;
        let contrib = generate_dkg_contribution(
            &seed, epoch, 1, n, threshold, &kem_pks, &fal_sks[0],
        )
        .expect("contribution");
        let (env, _proof_for_j2) = &contrib.recipient_envelopes[1];
        // Use proof for j=3 while claiming we're j=2.
        let proof_for_j3 = contrib.recipient_envelopes[2].1.clone();
        let err = verify_received_share(
            env,
            &proof_for_j3,
            &contrib.commitment,
            &fal_pks[0],
            epoch,
            1,
            n,
            threshold,
            2, // <-- but proof.leaf_index = 2 (j=3 - 1)
            &kem_sks[1],
        )
        .unwrap_err();
        assert_eq!(err, ShareVerificationError::MerkleProofPositionMismatch);
    }

    #[test]
    fn dkg_verify_share_rejects_envelope_undecryptable() {
        let epoch = 7;
        let n = 4;
        let threshold = 3;
        let (kem_pks, kem_sks, fal_pks, fal_sks) = make_committee(n);
        let mut seed = [0u8; 32];
        seed[0] = 1;
        let contrib = generate_dkg_contribution(
            &seed, epoch, 1, n, threshold, &kem_pks, &fal_sks[0],
        )
        .expect("contribution");
        let (env, proof) = &contrib.recipient_envelopes[1];
        // Try decrypting with the WRONG recipient's KEM sk (j=3
        // instead of j=2 it was encrypted for).
        let err = verify_received_share(
            env,
            proof,
            &contrib.commitment,
            &fal_pks[0],
            epoch,
            1,
            n,
            threshold,
            2,
            &kem_sks[2], // wrong sk
        )
        .unwrap_err();
        assert_eq!(err, ShareVerificationError::EnvelopeUndecryptable);
    }

    #[test]
    fn dkg_verify_share_rejects_merkle_mismatch() {
        let epoch = 7;
        let n = 4;
        let threshold = 3;
        let (kem_pks, kem_sks, fal_pks, fal_sks) = make_committee(n);
        let mut seed = [0u8; 32];
        seed[0] = 1;
        let mut contrib = generate_dkg_contribution(
            &seed, epoch, 1, n, threshold, &kem_pks, &fal_sks[0],
        )
        .expect("contribution");
        // Tamper with the commitment's merkle_root AFTER signing.
        // The Falcon sig still validates against the *original*
        // root, so we have to re-sign over the tampered root for
        // the test to reach the Merkle-mismatch branch instead of
        // failing earlier at the sig check.
        contrib.commitment.merkle_root[0] ^= 0xFF;
        contrib.commitment.sign(&fal_sks[0]).expect("re-sign");
        let (env, proof) = &contrib.recipient_envelopes[1];
        let err = verify_received_share(
            env,
            proof,
            &contrib.commitment,
            &fal_pks[0],
            epoch,
            1,
            n,
            threshold,
            2,
            &kem_sks[1],
        )
        .unwrap_err();
        assert_eq!(err, ShareVerificationError::MerkleProofMismatch);
    }

    #[test]
    fn dkg_aggregate_local_share_rejects_empty() {
        let err = aggregate_local_share(3, &[]).unwrap_err();
        assert!(err.contains("no contributors"));
    }

    #[test]
    fn dkg_aggregate_local_share_rejects_index_mismatch() {
        let row_for_2 = make_row(2, 42);
        let err = aggregate_local_share(3, &[row_for_2]).unwrap_err();
        assert!(err.contains("different holder"));
    }

    #[test]
    fn dkg_generate_contribution_validates_inputs() {
        let (kem_pks, _kem_sks, _fal_pks, fal_sks) = make_committee(4);
        let seed = [1u8; 32];

        // from_index 0
        assert!(
            generate_dkg_contribution(&seed, 1, 0, 4, 3, &kem_pks, &fal_sks[0]).is_err()
        );
        // from_index > n
        assert!(
            generate_dkg_contribution(&seed, 1, 5, 4, 3, &kem_pks, &fal_sks[0]).is_err()
        );
        // threshold > n
        assert!(
            generate_dkg_contribution(&seed, 1, 1, 4, 5, &kem_pks, &fal_sks[0]).is_err()
        );
        // threshold 0
        assert!(
            generate_dkg_contribution(&seed, 1, 1, 4, 0, &kem_pks, &fal_sks[0]).is_err()
        );
        // wrong recipient_kem_pks length
        let short_pks = &kem_pks[..3];
        assert!(
            generate_dkg_contribution(&seed, 1, 1, 4, 3, short_pks, &fal_sks[0]).is_err()
        );
    }

    #[test]
    fn master_share_wire_roundtrip() {
        let mut values = [Goldilocks::default(); SEED_ELEMENTS];
        for k in 0..SEED_ELEMENTS {
            values[k] = gl(1000 + k as u64);
        }
        let ms = MasterShare { index: 4, values };
        let bytes = ms.to_bytes();
        assert_eq!(bytes.len(), MasterShare::WIRE_LEN);
        let decoded = MasterShare::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, ms);
    }

    #[test]
    fn master_share_wire_rejects_wrong_length() {
        assert!(MasterShare::from_bytes(&[]).is_none());
        assert!(MasterShare::from_bytes(&[0u8; MasterShare::WIRE_LEN - 1]).is_none());
        assert!(MasterShare::from_bytes(&[0u8; MasterShare::WIRE_LEN + 1]).is_none());
    }

    #[test]
    fn master_share_wire_rejects_non_canonical_goldilocks() {
        let mut bytes = vec![0u8; MasterShare::WIRE_LEN];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(MasterShare::from_bytes(&bytes).is_none());
    }
}
