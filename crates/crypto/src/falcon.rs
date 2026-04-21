use alloc::vec::Vec;

use falcon::{DomainSeparation, FnDsaKeyPair, FnDsaSignature as FnDsaSig};

/// FALCON-512 (FN-DSA-512) log-degree parameter.
const LOGN: u32 = 9;

/// FALCON-512 public key (897 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FalconPublicKey(Vec<u8>);

/// FALCON-512 secret key (1281 bytes).
#[derive(Clone)]
pub struct FalconSecretKey(Vec<u8>);

/// FALCON-512 signature (~666 bytes average).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FalconSignature(Vec<u8>);

impl FalconPublicKey {
    pub const SIZE: usize = 897;

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == Self::SIZE {
            Some(Self(bytes.to_vec()))
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl FalconSecretKey {
    pub const SIZE: usize = 1281;

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == Self::SIZE {
            Some(Self(bytes.to_vec()))
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl FalconSignature {
    /// FALCON-512 signatures are typically 600-900 bytes.
    /// Reject anything outside the 500-1000 byte range.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() >= 500 && bytes.len() <= 1000 {
            Some(Self(bytes.to_vec()))
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Generate a FALCON-512 keypair.
pub fn falcon_keygen() -> Result<(FalconPublicKey, FalconSecretKey), &'static str> {
    let kp = FnDsaKeyPair::generate(LOGN).map_err(|_| "FALCON-512 keygen failed")?;
    let pk = FalconPublicKey(kp.public_key().to_vec());
    let sk = FalconSecretKey(kp.private_key().to_vec());
    Ok((pk, sk))
}

/// Sign a message with a FALCON-512 secret key.
pub fn falcon_sign(sk: &FalconSecretKey, msg: &[u8]) -> Result<FalconSignature, &'static str> {
    let kp = FnDsaKeyPair::from_private_key(&sk.0).map_err(|_| "invalid FALCON-512 secret key")?;
    let sig = kp
        .sign(msg, &DomainSeparation::Context(b"pyde-falcon-v1"))
        .map_err(|_| "FALCON-512 signing failed")?;
    Ok(FalconSignature(sig.to_bytes().to_vec()))
}

/// Verify a FALCON-512 signature.
pub fn falcon_verify(pk: &FalconPublicKey, msg: &[u8], sig: &FalconSignature) -> bool {
    FnDsaSig::verify(
        &sig.0,
        &pk.0,
        msg,
        &DomainSeparation::Context(b"pyde-falcon-v1"),
    )
    .is_ok()
}

/// Batch verify multiple FALCON-512 signatures.
/// Returns true only if ALL signatures are valid.
pub fn falcon_batch_verify(items: &[(&FalconPublicKey, &[u8], &FalconSignature)]) -> bool {
    items
        .iter()
        .all(|(pk, msg, sig)| falcon_verify(pk, msg, sig))
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn keygen_produces_correct_sizes() {
        let (pk, sk) = falcon_keygen().unwrap();
        assert_eq!(pk.as_bytes().len(), FalconPublicKey::SIZE);
        assert_eq!(sk.as_bytes().len(), FalconSecretKey::SIZE);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (pk, sk) = falcon_keygen().unwrap();
        let msg = b"hello post-quantum world";
        let sig = falcon_sign(&sk, msg).unwrap();
        assert!(falcon_verify(&pk, msg, &sig));
    }

    #[test]
    fn tampered_message_fails() {
        let (pk, sk) = falcon_keygen().unwrap();
        let sig = falcon_sign(&sk, b"original message").unwrap();
        assert!(!falcon_verify(&pk, b"tampered message", &sig));
    }

    #[test]
    fn tampered_signature_fails() {
        let (pk, sk) = falcon_keygen().unwrap();
        let msg = b"test message";
        let sig = falcon_sign(&sk, msg).unwrap();
        let mut bad_sig_bytes = sig.to_vec();
        if let Some(byte) = bad_sig_bytes.last_mut() {
            *byte ^= 0xFF;
        }
        let bad_sig = FalconSignature::from_bytes(&bad_sig_bytes).unwrap();
        assert!(!falcon_verify(&pk, msg, &bad_sig));
    }

    #[test]
    fn wrong_public_key_fails() {
        let (_pk1, sk1) = falcon_keygen().unwrap();
        let (pk2, _sk2) = falcon_keygen().unwrap();
        let msg = b"test message";
        let sig = falcon_sign(&sk1, msg).unwrap();
        assert!(!falcon_verify(&pk2, msg, &sig));
    }

    #[test]
    fn signature_size_in_expected_range() {
        let (_pk, sk) = falcon_keygen().unwrap();
        let sig = falcon_sign(&sk, b"test").unwrap();
        // FALCON-512 signatures are ~666 bytes average, range roughly 600-700
        assert!(sig.len() >= 500, "sig too small: {}", sig.len());
        assert!(sig.len() <= 900, "sig too large: {}", sig.len());
    }

    #[test]
    fn signature_from_bytes_rejects_invalid_length() {
        // Too short
        assert!(FalconSignature::from_bytes(&[0u8; 100]).is_none());
        // Too long
        assert!(FalconSignature::from_bytes(&[0u8; 1500]).is_none());
        // Valid range
        assert!(FalconSignature::from_bytes(&[0u8; 666]).is_some());
    }

    #[test]
    fn serialization_roundtrip_public_key() {
        let (pk, _sk) = falcon_keygen().unwrap();
        let bytes = pk.to_vec();
        let pk2 = FalconPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn serialization_roundtrip_secret_key() {
        let (_pk, sk) = falcon_keygen().unwrap();
        let bytes = sk.to_vec();
        let sk2 = FalconSecretKey::from_bytes(&bytes).unwrap();
        // Re-derive pk from both and verify they match
        let kp = FnDsaKeyPair::from_private_key(&sk.0).unwrap();
        let kp2 = FnDsaKeyPair::from_private_key(&sk2.0).unwrap();
        assert_eq!(kp.public_key(), kp2.public_key());
    }

    #[test]
    fn serialization_roundtrip_signature() {
        let (_pk, sk) = falcon_keygen().unwrap();
        let sig = falcon_sign(&sk, b"test").unwrap();
        let bytes = sig.to_vec();
        let sig2 = FalconSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn batch_verify_all_valid() {
        let (pk, sk) = falcon_keygen().unwrap();
        let msgs: &[&[u8]] = &[b"msg1", b"msg2", b"msg3"];
        let sigs: Vec<FalconSignature> =
            msgs.iter().map(|m| falcon_sign(&sk, m).unwrap()).collect();
        let items: Vec<_> = msgs
            .iter()
            .zip(sigs.iter())
            .map(|(m, s)| (&pk, *m, s))
            .collect();
        assert!(falcon_batch_verify(&items));
    }

    #[test]
    fn batch_verify_one_invalid() {
        let (pk, sk) = falcon_keygen().unwrap();
        let sig1 = falcon_sign(&sk, b"msg1").unwrap();
        let sig2 = falcon_sign(&sk, b"msg2").unwrap();
        let sig3 = falcon_sign(&sk, b"msg3").unwrap();
        // Use wrong message for sig2
        let items: Vec<(&FalconPublicKey, &[u8], &FalconSignature)> = vec![
            (&pk, b"msg1", &sig1),
            (&pk, b"wrong", &sig2),
            (&pk, b"msg3", &sig3),
        ];
        assert!(!falcon_batch_verify(&items));
    }

    #[test]
    fn empty_message_sign_verify() {
        let (pk, sk) = falcon_keygen().unwrap();
        let sig = falcon_sign(&sk, b"").unwrap();
        assert!(falcon_verify(&pk, b"", &sig));
    }

    #[test]
    fn large_message_sign_verify() {
        let (pk, sk) = falcon_keygen().unwrap();
        let msg = vec![0xABu8; 10_000];
        let sig = falcon_sign(&sk, &msg).unwrap();
        assert!(falcon_verify(&pk, &msg, &sig));
    }
}
