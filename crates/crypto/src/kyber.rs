use alloc::vec::Vec;

use ml_kem::{
    kem::{Encapsulate, Kem, KeyExport},
    Decapsulate, MlKem768, Seed,
};

// ML-KEM-768 sizes
const EK_SIZE: usize = 1184; // encapsulation key
const CT_SIZE: usize = 1088; // ciphertext
const SEED_SIZE: usize = 64; // decapsulation key seed

/// Kyber-768 (ML-KEM-768) public key (encapsulation key, 1184 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KyberPublicKey(Vec<u8>);

/// Kyber-768 (ML-KEM-768) secret key (decapsulation seed, 64 bytes).
#[derive(Clone)]
pub struct KyberSecretKey(Vec<u8>);

/// Kyber-768 ciphertext (1088 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KyberCiphertext(Vec<u8>);

/// 32-byte shared secret from Kyber KEM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedSecret([u8; 32]);

impl KyberPublicKey {
    pub const SIZE: usize = EK_SIZE;

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == EK_SIZE {
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

impl KyberSecretKey {
    pub const SIZE: usize = SEED_SIZE;

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == SEED_SIZE {
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

impl KyberCiphertext {
    pub const SIZE: usize = CT_SIZE;

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == CT_SIZE {
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

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn ek_from_bytes(bytes: &[u8]) -> Result<ml_kem::EncapsulationKey768, &'static str> {
    let arr: &[u8; EK_SIZE] = bytes
        .try_into()
        .map_err(|_| "wrong encapsulation key size")?;
    ml_kem::EncapsulationKey768::new(arr.into()).map_err(|_| "invalid encapsulation key")
}

fn dk_from_seed(bytes: &[u8]) -> Result<ml_kem::DecapsulationKey768, &'static str> {
    let arr: &[u8; SEED_SIZE] = bytes
        .try_into()
        .map_err(|_| "wrong decapsulation seed size")?;
    let seed = Seed::from(*arr);
    Ok(ml_kem::DecapsulationKey768::from_seed(seed))
}

/// Generate a Kyber-768 keypair.
pub fn kyber_keygen() -> Result<(KyberPublicKey, KyberSecretKey), &'static str> {
    let (dk, ek) = MlKem768::generate_keypair();
    let pk = KyberPublicKey(ek.to_bytes().to_vec());
    let seed = dk.to_seed().ok_or("Kyber-768 seed export failed")?;
    let sk = KyberSecretKey(seed.to_vec());
    Ok((pk, sk))
}

/// Encapsulate: generate a shared secret and ciphertext using the public key.
pub fn kyber_encapsulate(
    pk: &KyberPublicKey,
) -> Result<(KyberCiphertext, SharedSecret), &'static str> {
    let ek = ek_from_bytes(&pk.0)?;
    let (ct, ss) = ek.encapsulate();
    let mut secret = [0u8; 32];
    secret.copy_from_slice(ss.as_slice());
    Ok((KyberCiphertext(ct.to_vec()), SharedSecret(secret)))
}

/// Decapsulate: recover the shared secret from a ciphertext using the secret key.
pub fn kyber_decapsulate(
    sk: &KyberSecretKey,
    ct: &KyberCiphertext,
) -> Result<SharedSecret, &'static str> {
    let dk = dk_from_seed(&sk.0)?;
    let ct_arr: &[u8; CT_SIZE] =
        ct.0.as_slice()
            .try_into()
            .map_err(|_| "wrong ciphertext size")?;
    let ss = dk.decapsulate(ct_arr.into());
    let mut secret = [0u8; 32];
    secret.copy_from_slice(ss.as_slice());
    Ok(SharedSecret(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_produces_correct_sizes() {
        let (pk, sk) = kyber_keygen().unwrap();
        assert_eq!(pk.as_bytes().len(), EK_SIZE);
        assert_eq!(sk.as_bytes().len(), SEED_SIZE);
    }

    #[test]
    fn encapsulate_decapsulate_roundtrip() {
        let (pk, sk) = kyber_keygen().unwrap();
        let (ct, ss_enc) = kyber_encapsulate(&pk).unwrap();
        let ss_dec = kyber_decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn wrong_secret_key_different_shared_secret() {
        let (pk, _sk1) = kyber_keygen().unwrap();
        let (_pk2, sk2) = kyber_keygen().unwrap();
        let (ct, ss_enc) = kyber_encapsulate(&pk).unwrap();
        let ss_dec = kyber_decapsulate(&sk2, &ct).unwrap();
        assert_ne!(ss_enc, ss_dec);
    }

    #[test]
    fn shared_secret_is_32_bytes() {
        let (pk, _sk) = kyber_keygen().unwrap();
        let (_ct, ss) = kyber_encapsulate(&pk).unwrap();
        assert_eq!(ss.as_bytes().len(), 32);
    }

    #[test]
    fn different_encapsulations_differ() {
        let (pk, sk) = kyber_keygen().unwrap();
        let (ct1, ss1) = kyber_encapsulate(&pk).unwrap();
        let (ct2, ss2) = kyber_encapsulate(&pk).unwrap();
        assert_ne!(ss1, ss2);
        assert_ne!(ct1, ct2);
        assert_eq!(ss1, kyber_decapsulate(&sk, &ct1).unwrap());
        assert_eq!(ss2, kyber_decapsulate(&sk, &ct2).unwrap());
    }

    #[test]
    fn serialization_roundtrip_public_key() {
        let (pk, _sk) = kyber_keygen().unwrap();
        let bytes = pk.to_vec();
        let pk2 = KyberPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn serialization_roundtrip_secret_key() {
        let (_pk, sk) = kyber_keygen().unwrap();
        let bytes = sk.to_vec();
        let sk2 = KyberSecretKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk.as_bytes(), sk2.as_bytes());
    }

    #[test]
    fn serialization_roundtrip_ciphertext() {
        let (pk, _sk) = kyber_keygen().unwrap();
        let (ct, _ss) = kyber_encapsulate(&pk).unwrap();
        let bytes = ct.to_vec();
        let ct2 = KyberCiphertext::from_bytes(&bytes).unwrap();
        assert_eq!(ct, ct2);
    }

    #[test]
    fn ciphertext_correct_size() {
        let (pk, _sk) = kyber_keygen().unwrap();
        let (ct, _ss) = kyber_encapsulate(&pk).unwrap();
        assert_eq!(ct.as_bytes().len(), CT_SIZE);
    }
}
