//! Multisig governance primitives (slice 4.5).
//!
//! Two on-chain operations:
//!
//! 1. `MultisigTx` — debit `treasury_address()` and credit a target with
//!    a given value, provided ≥ threshold FALCON sigs from the declared
//!    signer set authorize the spend.
//!
//! 2. `RotateMultisig` — replace the signer set + threshold, provided
//!    ≥ current threshold sigs from the current set authorize the new
//!    configuration.
//!
//! Both operations sign a message that includes the **current multisig
//! nonce** so that a signed payload can be executed at most once —
//! after execution the nonce increments and old signatures no longer
//! verify against the new nonce.
//!
//! Wire format (common to both):
//!
//! ```text
//! [op_version:1][op_body:variable][sig_count:1][sig_entry_0]...[sig_entry_N-1]
//! sig_entry = [signer_index:1][sig_len:2 LE][falcon_sig:sig_len]
//! ```
//!
//! `op_version` currently `0x01` for both types. `op_body` differs per
//! type (see `MultisigSpend` / `MultisigRotate`).

use pyde_account::address::Address;
use pyde_crypto::falcon::{falcon_verify, FalconPublicKey, FalconSignature};
use pyde_crypto::poseidon2::poseidon2_hash;

/// Current wire-format version. Incrementing this is a hard-fork event
/// (handlers check the first byte and reject unknown versions).
pub const MULTISIG_VERSION: u8 = 0x01;

/// Hard cap on signer set size. 16 is plenty for a foundation + community +
/// validator-rep mix while keeping MultisigTx gas costs bounded.
pub const MAX_SIGNERS: u8 = 16;

/// One signature + the index of the signer in the declared set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigEntry {
    pub signer_index: u8,
    pub signature: Vec<u8>,
}

/// Spend-from-treasury operation body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigSpend {
    pub target: Address,
    pub value: u128,
    /// `hash(pip_file_contents)` for the PIP that rationalized the
    /// spend. All-zero is technically legal but strongly discouraged —
    /// it strips the audit trail that links spends to PIPs.
    pub data_digest: [u8; 32],
}

/// Rotate-signer-set operation body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigRotate {
    /// New public-key list. Each entry is a full FALCON-512 pk (897B).
    pub new_signer_pks: Vec<Vec<u8>>,
    pub new_threshold: u8,
}

/// Decoded multisig payload of either type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MultisigPayload {
    Spend {
        spend: MultisigSpend,
        sigs: Vec<SigEntry>,
    },
    Rotate {
        rotate: MultisigRotate,
        sigs: Vec<SigEntry>,
    },
}

impl MultisigSpend {
    /// Bytes over which signers compute their FALCON signature. Includes
    /// the on-chain nonce so each signature is bound to a specific
    /// execution. Signers must coordinate on the current nonce before
    /// signing.
    pub fn signing_bytes(&self, nonce: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 32 + 16 + 32);
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.extend_from_slice(&self.target);
        buf.extend_from_slice(&self.value.to_le_bytes());
        buf.extend_from_slice(&self.data_digest);
        poseidon2_hash(&buf).to_bytes().to_vec()
    }

    fn encode_body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 16 + 32);
        out.extend_from_slice(&self.target);
        out.extend_from_slice(&self.value.to_le_bytes());
        out.extend_from_slice(&self.data_digest);
        out
    }

    fn decode_body(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < 32 + 16 + 32 {
            return None;
        }
        let mut target = [0u8; 32];
        target.copy_from_slice(&bytes[0..32]);
        let value = u128::from_le_bytes(bytes[32..48].try_into().ok()?);
        let mut data_digest = [0u8; 32];
        data_digest.copy_from_slice(&bytes[48..80]);
        Some((
            Self {
                target,
                value,
                data_digest,
            },
            &bytes[80..],
        ))
    }
}

impl MultisigRotate {
    pub fn signing_bytes(&self, nonce: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 1 + self.new_signer_pks.len() * 897 + 1);
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.push(self.new_signer_pks.len() as u8);
        for pk in &self.new_signer_pks {
            buf.extend_from_slice(pk);
        }
        buf.push(self.new_threshold);
        poseidon2_hash(&buf).to_bytes().to_vec()
    }

    fn encode_body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.new_signer_pks.len() * 897 + 1);
        out.push(self.new_signer_pks.len() as u8);
        for pk in &self.new_signer_pks {
            assert_eq!(pk.len(), 897, "FALCON-512 pk must be 897 bytes");
            out.extend_from_slice(pk);
        }
        out.push(self.new_threshold);
        out
    }

    fn decode_body(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.is_empty() {
            return None;
        }
        let count = bytes[0] as usize;
        if count == 0 || count > MAX_SIGNERS as usize {
            return None;
        }
        let needed = 1 + count * 897 + 1;
        if bytes.len() < needed {
            return None;
        }
        let mut pks = Vec::with_capacity(count);
        for i in 0..count {
            let off = 1 + i * 897;
            pks.push(bytes[off..off + 897].to_vec());
        }
        let new_threshold = bytes[1 + count * 897];
        Some((
            Self {
                new_signer_pks: pks,
                new_threshold,
            },
            &bytes[needed..],
        ))
    }
}

impl MultisigPayload {
    /// Tag byte distinguishing Spend (0x01) from Rotate (0x02).
    const SPEND_TAG: u8 = 0x01;
    const ROTATE_TAG: u8 = 0x02;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(MULTISIG_VERSION);
        match self {
            MultisigPayload::Spend { spend, sigs } => {
                out.push(Self::SPEND_TAG);
                out.extend_from_slice(&spend.encode_body());
                encode_sigs(&mut out, sigs);
            }
            MultisigPayload::Rotate { rotate, sigs } => {
                out.push(Self::ROTATE_TAG);
                out.extend_from_slice(&rotate.encode_body());
                encode_sigs(&mut out, sigs);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }
        if bytes[0] != MULTISIG_VERSION {
            return None;
        }
        let tag = bytes[1];
        let rest = &bytes[2..];
        match tag {
            Self::SPEND_TAG => {
                let (spend, rest) = MultisigSpend::decode_body(rest)?;
                let sigs = decode_sigs(rest)?;
                Some(MultisigPayload::Spend { spend, sigs })
            }
            Self::ROTATE_TAG => {
                let (rotate, rest) = MultisigRotate::decode_body(rest)?;
                let sigs = decode_sigs(rest)?;
                Some(MultisigPayload::Rotate { rotate, sigs })
            }
            _ => None,
        }
    }

    pub fn sigs(&self) -> &[SigEntry] {
        match self {
            MultisigPayload::Spend { sigs, .. } => sigs,
            MultisigPayload::Rotate { sigs, .. } => sigs,
        }
    }
}

fn encode_sigs(out: &mut Vec<u8>, sigs: &[SigEntry]) {
    assert!(sigs.len() <= MAX_SIGNERS as usize, "too many sigs");
    out.push(sigs.len() as u8);
    for entry in sigs {
        out.push(entry.signer_index);
        let len = entry.signature.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&entry.signature);
    }
}

fn decode_sigs(bytes: &[u8]) -> Option<Vec<SigEntry>> {
    if bytes.is_empty() {
        return None;
    }
    let count = bytes[0] as usize;
    if count == 0 || count > MAX_SIGNERS as usize {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    let mut cursor = 1usize;
    for _ in 0..count {
        if cursor + 3 > bytes.len() {
            return None;
        }
        let signer_index = bytes[cursor];
        let len = u16::from_le_bytes([bytes[cursor + 1], bytes[cursor + 2]]) as usize;
        cursor += 3;
        if cursor + len > bytes.len() {
            return None;
        }
        let signature = bytes[cursor..cursor + len].to_vec();
        cursor += len;
        out.push(SigEntry {
            signer_index,
            signature,
        });
    }
    // Trailing garbage after the declared sigs is not allowed — protects
    // against adversarial payloads that hide extra data past the end.
    if cursor != bytes.len() {
        return None;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Signer-set encoding in state
// ---------------------------------------------------------------------------

/// Encode a signer set for storage in `MULTISIG_SIGNERS`:
/// `[count:1][pk:897]...[pk:897]`.
pub fn encode_signer_set(pks: &[Vec<u8>]) -> Vec<u8> {
    assert!(pks.len() <= MAX_SIGNERS as usize, "too many signers");
    let mut out = Vec::with_capacity(1 + pks.len() * 897);
    out.push(pks.len() as u8);
    for pk in pks {
        assert_eq!(pk.len(), 897);
        out.extend_from_slice(pk);
    }
    out
}

pub fn decode_signer_set(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    if bytes.is_empty() {
        return None;
    }
    let count = bytes[0] as usize;
    if count == 0 || count > MAX_SIGNERS as usize {
        return None;
    }
    if bytes.len() != 1 + count * 897 {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = 1 + i * 897;
        out.push(bytes[off..off + 897].to_vec());
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/// Verify a single `SigEntry` against the signer set.
///
/// Returns `Some(signer_index)` on success, `None` on any failure
/// (unknown signer index, bad signature encoding, sig doesn't verify).
pub fn verify_sig_entry(
    entry: &SigEntry,
    signer_pks: &[Vec<u8>],
    signing_bytes: &[u8],
) -> Option<u8> {
    let idx = entry.signer_index as usize;
    if idx >= signer_pks.len() {
        return None;
    }
    let pk = FalconPublicKey::from_bytes(&signer_pks[idx])?;
    let sig = FalconSignature::from_bytes(&entry.signature)?;
    if falcon_verify(&pk, signing_bytes, &sig) {
        Some(entry.signer_index)
    } else {
        None
    }
}

/// Verify a slate of sigs against a signing-bytes hash. Counts the
/// number of UNIQUE signers whose sigs verify. Returns `Ok(count)` on
/// clean verification, `Err(reason)` if any entry was malformed or a
/// signer_index was duplicated.
///
/// Duplicate-index defense is important: without it, one cooperating
/// signer could fill half the quorum by submitting N copies of their
/// own sig with identical `signer_index`.
pub fn count_valid_sigs(
    sigs: &[SigEntry],
    signer_pks: &[Vec<u8>],
    signing_bytes: &[u8],
) -> Result<usize, &'static str> {
    let mut seen = [false; MAX_SIGNERS as usize];
    let mut valid = 0usize;
    for entry in sigs {
        let idx = entry.signer_index as usize;
        if idx >= MAX_SIGNERS as usize {
            return Err("signer_index out of bounds");
        }
        if seen[idx] {
            return Err("duplicate signer_index in payload");
        }
        seen[idx] = true;
        if verify_sig_entry(entry, signer_pks, signing_bytes).is_some() {
            valid += 1;
        }
    }
    Ok(valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_crypto::falcon::{falcon_keygen, falcon_sign, FalconSecretKey};

    fn gen_signers(n: usize) -> (Vec<Vec<u8>>, Vec<FalconSecretKey>) {
        let mut pks = Vec::with_capacity(n);
        let mut sks = Vec::with_capacity(n);
        for _ in 0..n {
            let (pk, sk) = falcon_keygen().unwrap();
            pks.push(pk.as_bytes().to_vec());
            sks.push(sk);
        }
        (pks, sks)
    }

    fn sign_at(sk: &FalconSecretKey, msg: &[u8], idx: u8) -> SigEntry {
        let sig = falcon_sign(sk, msg).unwrap();
        SigEntry {
            signer_index: idx,
            signature: sig.as_bytes().to_vec(),
        }
    }

    #[test]
    fn spend_payload_roundtrip() {
        let spend = MultisigSpend {
            target: [0x11; 32],
            value: 42,
            data_digest: [0x22; 32],
        };
        let payload = MultisigPayload::Spend {
            spend: spend.clone(),
            sigs: vec![SigEntry {
                signer_index: 3,
                signature: vec![0xAB; 666],
            }],
        };
        let bytes = payload.encode();
        let decoded = MultisigPayload::decode(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn rotate_payload_roundtrip() {
        let (pks, _) = gen_signers(3);
        let rotate = MultisigRotate {
            new_signer_pks: pks,
            new_threshold: 2,
        };
        let payload = MultisigPayload::Rotate {
            rotate,
            sigs: vec![SigEntry {
                signer_index: 0,
                signature: vec![0xCD; 700],
            }],
        };
        let bytes = payload.encode();
        let decoded = MultisigPayload::decode(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let mut bytes = vec![0xFF, 0x01];
        bytes.extend_from_slice(&[0u8; 80]);
        bytes.push(0); // sig_count = 0
        assert!(MultisigPayload::decode(&bytes).is_none());
    }

    #[test]
    fn decode_rejects_unknown_tag() {
        let mut bytes = vec![MULTISIG_VERSION, 0x99];
        bytes.extend_from_slice(&[0u8; 80]);
        bytes.push(0);
        assert!(MultisigPayload::decode(&bytes).is_none());
    }

    #[test]
    fn decode_rejects_trailing_garbage() {
        let payload = MultisigPayload::Spend {
            spend: MultisigSpend {
                target: [0; 32],
                value: 0,
                data_digest: [0; 32],
            },
            sigs: vec![SigEntry {
                signer_index: 0,
                signature: vec![0xAB; 500],
            }],
        };
        let mut bytes = payload.encode();
        bytes.push(0xFF); // extra byte past declared sigs
        assert!(MultisigPayload::decode(&bytes).is_none());
    }

    #[test]
    fn signer_set_roundtrip() {
        let (pks, _) = gen_signers(5);
        let bytes = encode_signer_set(&pks);
        let decoded = decode_signer_set(&bytes).unwrap();
        assert_eq!(pks, decoded);
    }

    #[test]
    fn signer_set_rejects_bad_length() {
        let mut bytes = vec![2u8];
        bytes.extend_from_slice(&[0u8; 500]); // too short for 2 pks
        assert!(decode_signer_set(&bytes).is_none());
    }

    #[test]
    fn signer_set_rejects_over_max() {
        let mut bytes = vec![(MAX_SIGNERS + 1) as u8];
        bytes.extend_from_slice(&vec![0u8; (MAX_SIGNERS as usize + 1) * 897]);
        assert!(decode_signer_set(&bytes).is_none());
    }

    #[test]
    fn count_valid_sigs_happy_path() {
        let (pks, sks) = gen_signers(5);
        let spend = MultisigSpend {
            target: [0x33; 32],
            value: 100,
            data_digest: [0x44; 32],
        };
        let msg = spend.signing_bytes(7);
        let sigs = vec![
            sign_at(&sks[0], &msg, 0),
            sign_at(&sks[2], &msg, 2),
            sign_at(&sks[4], &msg, 4),
        ];
        let valid = count_valid_sigs(&sigs, &pks, &msg).unwrap();
        assert_eq!(valid, 3);
    }

    #[test]
    fn count_valid_sigs_rejects_duplicate_index() {
        let (pks, sks) = gen_signers(3);
        let spend = MultisigSpend {
            target: [0; 32],
            value: 0,
            data_digest: [0; 32],
        };
        let msg = spend.signing_bytes(0);
        let sigs = vec![sign_at(&sks[1], &msg, 1), sign_at(&sks[1], &msg, 1)];
        let err = count_valid_sigs(&sigs, &pks, &msg).unwrap_err();
        assert!(err.contains("duplicate"));
    }

    #[test]
    fn count_valid_sigs_skips_bad_sig() {
        let (pks, sks) = gen_signers(3);
        let spend = MultisigSpend {
            target: [0; 32],
            value: 0,
            data_digest: [0; 32],
        };
        let msg = spend.signing_bytes(0);
        // Signer 2 signs a DIFFERENT message — should fail verify.
        let wrong_msg = spend.signing_bytes(99);
        let sigs = vec![sign_at(&sks[0], &msg, 0), sign_at(&sks[2], &wrong_msg, 2)];
        let valid = count_valid_sigs(&sigs, &pks, &msg).unwrap();
        assert_eq!(valid, 1, "only signer 0's sig is valid");
    }

    #[test]
    fn count_valid_sigs_rejects_out_of_range_index() {
        let (pks, sks) = gen_signers(3);
        let spend = MultisigSpend {
            target: [0; 32],
            value: 0,
            data_digest: [0; 32],
        };
        let msg = spend.signing_bytes(0);
        // signer_index = 99 is beyond MAX_SIGNERS → hard error.
        let sigs = vec![sign_at(&sks[0], &msg, 99)];
        let err = count_valid_sigs(&sigs, &pks, &msg).unwrap_err();
        assert!(err.contains("out of bounds"));
    }

    #[test]
    fn signing_bytes_changes_with_nonce() {
        let spend = MultisigSpend {
            target: [0x55; 32],
            value: 123,
            data_digest: [0x66; 32],
        };
        assert_ne!(spend.signing_bytes(0), spend.signing_bytes(1));
    }
}
