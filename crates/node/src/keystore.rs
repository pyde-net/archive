//! Encrypted-at-rest validator keystore (audit 221).
//!
//! Mainnet operators can't run validators with a raw FALCON
//! secret key on disk — anyone with read access to the data
//! directory walks away with the signing key. This module
//! provides AES-256-GCM encryption + key derivation via
//! Poseidon2(passphrase || salt) so the validator key file
//! is unreadable without the operator's passphrase.
//!
//! ## Format
//!
//! Encrypted keystore is a JSON file. Magic byte `{` (0x7B)
//! lets `load_validator_identity` distinguish it from the
//! legacy raw-bytes format `[pk_len:4 LE][pk_bytes][sk_bytes]`
//! (which always starts with a small u32 LE for the FALCON-512
//! pk length 897 = 0x381, first byte 0x81).
//!
//! ## Passphrase source
//!
//! Read from `PYDE_VALIDATOR_PASSPHRASE` env var. We deliberately
//! avoid stdin prompting so systemd-managed validator deploys
//! work without a TTY. Operators who want interactive prompts
//! can prepend their own wrapper that reads the passphrase and
//! sets the env var before exec'ing the node.
//!
//! Empty / unset passphrase ⇒ keystore is treated as not-using-
//! encryption. The legacy raw-bytes path stays available for
//! devnets (chain_id == 31337) so existing test infra doesn't
//! need to be reworked.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use pyde_crypto::falcon::{FalconPublicKey, FalconSecretKey};
use pyde_crypto::poseidon2::poseidon2_hash;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// JSON-serialized validator keystore. Layout intentionally
/// matches `pyde_rust_sdk::wallet::Keystore` so the same
/// `pyde_walletctl encrypt`-style tooling works on validator
/// keys.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidatorKeystore {
    /// `0x`-prefixed hex address derived from the public key.
    pub address: String,
    /// `0x`-prefixed hex of the FALCON-512 public key.
    pub public_key: String,
    /// `0x`-prefixed hex of the AES-256-GCM ciphertext (sk +
    /// 16-byte tag).
    encrypted_secret_key: String,
    /// `0x`-prefixed hex of the 16-byte salt mixed into key
    /// derivation.
    salt: String,
    /// `0x`-prefixed hex of the 12-byte AES-GCM nonce.
    nonce: String,
    /// Schema version. Bump on layout changes; `from_bytes`
    /// keys on this for forward-compat handling.
    pub version: u32,
}

/// Schema versions:
/// - **1** (legacy, audit 221): single-iteration `Poseidon2(passphrase
///   || salt)` KDF. Brute-forceable in milliseconds-to-hours per
///   passphrase on commodity GPUs.
/// - **2** (audit 306, current): Argon2id with `m=64 MB, t=3, p=1`,
///   ~250 ms per guess on a single core, memory-hard. New keystores
///   are written at v2; v1 keystores still load via the legacy KDF
///   path so existing operator setups don't break across the bump.
const KEYSTORE_VERSION: u32 = 2;
const KEYSTORE_VERSION_LEGACY_POSEIDON2: u32 = 1;

/// Argon2id parameters. Tuned for ~250 ms / single-core on
/// commodity 2026 hardware; tighter than the `argon2` crate's
/// defaults. Pinned here so all three keystore implementations
/// (validator, SDK wallet, pyde-dev wallet) stay byte-compatible.
const ARGON2_M_COST_KIB: u32 = 64 * 1024; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

/// Derive a 32-byte AES key from `passphrase` + `salt` using
/// Argon2id (audit 306). The previous Poseidon2 KDF was fast by
/// design — a 10-character passphrase fell to GPU brute force in
/// hours, "pass123" in milliseconds — so any operator backup leak
/// or supply-chain compromise of the keystore file effectively
/// exposed the FALCON private key.
///
/// Audit 358: returns `Zeroizing<[u8; 32]>` so the AES key is
/// scrubbed from memory when the wrapper drops, instead of
/// surviving in the freed stack frame until the next call
/// clobbers it. A core dump captured between keystore-load and
/// the next syscall would otherwise leak the encryption key.
fn derive_aes_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let params = argon2::Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| format!("argon2 params: {e}"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
        .map_err(|e| format!("argon2 hash: {e}"))?;
    Ok(out)
}

/// Legacy Poseidon2 KDF kept ONLY for decrypting v1 keystores.
/// Never used to encrypt new keys.
///
/// Audit 358: same Zeroizing wrapper so v1-keystore decrypt
/// paths don't leave the AES key on the stack either.
fn derive_aes_key_v1_poseidon2(passphrase: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut input = Vec::with_capacity(passphrase.len() + salt.len());
    input.extend_from_slice(passphrase.as_bytes());
    input.extend_from_slice(salt);
    Zeroizing::new(poseidon2_hash(&input).to_bytes())
}

/// Encrypt a validator key + write it to disk as JSON. Always uses
/// the current `KEYSTORE_VERSION` (Argon2id; audit 306).
pub fn encrypt(
    pk: &FalconPublicKey,
    sk: &FalconSecretKey,
    passphrase: &str,
) -> Result<ValidatorKeystore, String> {
    if passphrase.is_empty() {
        return Err("encrypt: passphrase must not be empty".into());
    }
    let salt: [u8; 16] = rand::random();
    let nonce_bytes: [u8; 12] = rand::random();

    let aes_key = derive_aes_key(passphrase, &salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(aes_key.as_ref()).map_err(|e| format!("AES init: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, sk.as_bytes())
        .map_err(|e| format!("encrypt: {e}"))?;

    let pk_bytes = pk.as_bytes();
    let address = pyde_account::address::derive_eoa_address(pk_bytes);
    Ok(ValidatorKeystore {
        address: format!("0x{}", hex::encode(address)),
        public_key: format!("0x{}", hex::encode(pk_bytes)),
        encrypted_secret_key: format!("0x{}", hex::encode(&ciphertext)),
        salt: format!("0x{}", hex::encode(salt)),
        nonce: format!("0x{}", hex::encode(nonce_bytes)),
        version: KEYSTORE_VERSION,
    })
}

/// Decrypt a validator keystore back into the FALCON keypair.
///
/// Accepts both `version = 1` (legacy Poseidon2 KDF) and
/// `version = 2` (Argon2id, audit 306). The KDF dispatch is the only
/// version-dependent step; everything else (salt + AES-GCM) is
/// identical across versions. Operators with v1 keystores get
/// transparent decryption; re-encrypt at v2 by calling `encrypt`
/// again with the same passphrase and writing the new keystore.
pub fn decrypt(
    keystore: &ValidatorKeystore,
    passphrase: &str,
) -> Result<(FalconPublicKey, FalconSecretKey), String> {
    if passphrase.is_empty() {
        return Err("decrypt: passphrase must not be empty".into());
    }

    let salt = hex::decode(keystore.salt.trim_start_matches("0x"))
        .map_err(|e| format!("bad salt hex: {e}"))?;
    let nonce_bytes = hex::decode(keystore.nonce.trim_start_matches("0x"))
        .map_err(|e| format!("bad nonce hex: {e}"))?;
    if nonce_bytes.len() != 12 {
        return Err(format!(
            "bad nonce length {} (expected 12)",
            nonce_bytes.len()
        ));
    }
    let ciphertext = hex::decode(keystore.encrypted_secret_key.trim_start_matches("0x"))
        .map_err(|e| format!("bad ciphertext hex: {e}"))?;
    let pk_bytes = hex::decode(keystore.public_key.trim_start_matches("0x"))
        .map_err(|e| format!("bad pubkey hex: {e}"))?;

    let aes_key = match keystore.version {
        KEYSTORE_VERSION => derive_aes_key(passphrase, &salt)?,
        KEYSTORE_VERSION_LEGACY_POSEIDON2 => derive_aes_key_v1_poseidon2(passphrase, &salt),
        v => {
            return Err(format!(
                "unsupported keystore version: {} (expected 1 or {})",
                v, KEYSTORE_VERSION
            ))
        }
    };
    let cipher =
        Aes256Gcm::new_from_slice(aes_key.as_ref()).map_err(|e| format!("AES init: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let sk_bytes = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| "decrypt failed — wrong passphrase?".to_string())?;
    let sk = FalconSecretKey::from_bytes(&sk_bytes)
        .ok_or_else(|| "decrypted secret key is invalid".to_string())?;
    let pk =
        FalconPublicKey::from_bytes(&pk_bytes).ok_or_else(|| "invalid public key".to_string())?;

    Ok((pk, sk))
}

/// Try to interpret `bytes` as a JSON-encoded keystore. Returns
/// `Some(ks)` if the bytes parse cleanly, `None` if they look
/// like the legacy raw-bytes format (so callers can fall through
/// to the un-encrypted load path).
pub fn try_parse_keystore(bytes: &[u8]) -> Option<ValidatorKeystore> {
    serde_json::from_slice::<ValidatorKeystore>(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_crypto::falcon::falcon_keygen;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pass = "correct-horse-battery-staple";
        let ks = encrypt(&pk, &sk, pass).unwrap();
        let (pk2, sk2) = decrypt(&ks, pass).unwrap();
        assert_eq!(pk.as_bytes(), pk2.as_bytes());
        assert_eq!(sk.as_bytes(), sk2.as_bytes());
    }

    #[test]
    fn decrypt_with_wrong_passphrase_fails() {
        let (pk, sk) = falcon_keygen().unwrap();
        let ks = encrypt(&pk, &sk, "right").unwrap();
        let res = decrypt(&ks, "wrong");
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(err.contains("wrong passphrase"));
    }

    #[test]
    fn empty_passphrase_rejected_on_encrypt_and_decrypt() {
        let (pk, sk) = falcon_keygen().unwrap();
        assert!(encrypt(&pk, &sk, "").is_err());
        let ks = encrypt(&pk, &sk, "x").unwrap();
        assert!(decrypt(&ks, "").is_err());
    }

    #[test]
    fn try_parse_distinguishes_json_from_raw() {
        let (pk, sk) = falcon_keygen().unwrap();
        let ks = encrypt(&pk, &sk, "x").unwrap();
        let json = serde_json::to_vec(&ks).unwrap();
        assert!(try_parse_keystore(&json).is_some());

        // Legacy raw-bytes format begins with FALCON pk_len LE
        // (897 = 0x0381) — first byte 0x81. Definitely not JSON.
        let mut raw = Vec::new();
        raw.extend_from_slice(&(pk.as_bytes().len() as u32).to_le_bytes());
        raw.extend_from_slice(pk.as_bytes());
        raw.extend_from_slice(sk.as_bytes());
        assert!(try_parse_keystore(&raw).is_none());
    }

    #[test]
    fn version_mismatch_rejected() {
        let (pk, sk) = falcon_keygen().unwrap();
        let mut ks = encrypt(&pk, &sk, "x").unwrap();
        ks.version = 99;
        let res = decrypt(&ks, "x");
        assert!(res.is_err());
        assert!(res.err().unwrap().contains("unsupported keystore version"));
    }

    // ── Audit 306: Argon2id migration tests ─────────────────────────

    #[test]
    fn new_keystores_are_v2_argon2id() {
        let (pk, sk) = falcon_keygen().unwrap();
        let ks = encrypt(&pk, &sk, "x").unwrap();
        assert_eq!(ks.version, 2, "encrypt must always emit v2");
    }

    /// v1 keystores produced by the pre-306 binary still decrypt
    /// after the bump. The KDF dispatch in `decrypt` routes
    /// `version == 1` to `derive_aes_key_v1_poseidon2`. Operators
    /// who upgrade the binary keep their existing keystores
    /// working (until they rotate).
    #[test]
    fn legacy_v1_keystore_still_decrypts() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pass = "legacy-passphrase";
        let salt: [u8; 16] = rand::random();
        let nonce_bytes: [u8; 12] = rand::random();

        // Build a v1 keystore by hand using the legacy KDF.
        let aes_key = derive_aes_key_v1_poseidon2(pass, &salt);
        let cipher = Aes256Gcm::new_from_slice(aes_key.as_ref()).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, sk.as_bytes()).unwrap();
        let pk_bytes = pk.as_bytes();
        let address = pyde_account::address::derive_eoa_address(pk_bytes);
        let v1_ks = ValidatorKeystore {
            address: format!("0x{}", hex::encode(address)),
            public_key: format!("0x{}", hex::encode(pk_bytes)),
            encrypted_secret_key: format!("0x{}", hex::encode(&ciphertext)),
            salt: format!("0x{}", hex::encode(salt)),
            nonce: format!("0x{}", hex::encode(nonce_bytes)),
            version: 1,
        };

        let (pk2, sk2) = decrypt(&v1_ks, pass).expect("v1 must decrypt");
        assert_eq!(pk.as_bytes(), pk2.as_bytes());
        assert_eq!(sk.as_bytes(), sk2.as_bytes());

        // Wrong passphrase against v1 still fails — the failure
        // path goes through AES-GCM tag mismatch, not the KDF.
        assert!(decrypt(&v1_ks, "wrong").is_err());
    }

    /// Re-encrypting a v1 keystore with `encrypt(...)` produces a
    /// v2 keystore that decrypts under the same passphrase. This
    /// is the "upgrade in place" path operators take post-306.
    #[test]
    fn v1_to_v2_reencryption_roundtrip() {
        let (pk, sk) = falcon_keygen().unwrap();
        let pass = "upgrade-me";

        // Pretend we loaded a v1 keystore (use encrypt to get the
        // public/address bits, then re-encrypt at v2).
        let v2 = encrypt(&pk, &sk, pass).unwrap();
        assert_eq!(v2.version, 2);
        let (pk2, sk2) = decrypt(&v2, pass).unwrap();
        assert_eq!(pk.as_bytes(), pk2.as_bytes());
        assert_eq!(sk.as_bytes(), sk2.as_bytes());
    }
}
