//! Client-side helpers for the MEV-protected encrypted-tx flow.
//!
//! Lets a wallet construct a fully client-encrypted, client-signed
//! `EncryptedTx` without giving an RPC node access to the plaintext.
//!
//! ```ignore
//! use pyde_rust_sdk::{Provider, Wallet};
//! use pyde_rust_sdk::encrypted::build_raw_encrypted_tx;
//!
//! # async fn demo(provider: &Provider, wallet: &Wallet) -> pyde_rust_sdk::Result<()> {
//! // 1. Fetch the committee's threshold pubkey.
//! let tpk = provider.get_threshold_public_key().await?;
//!
//! // 2. Build + sign the encrypted tx locally.
//! let bytes = build_raw_encrypted_tx(
//!     &tpk,
//!     wallet.secret_key(),
//!     *wallet.address(),
//!     /* nonce */ 0,
//!     /* gas_limit */ 100_000,
//!     /* access_list */ vec![],
//!     /* deadline */ None,
//!     /* chain_id */ 31337,
//!     &[0xBBu8; 32],
//!     /* value */ 1_000,
//!     /* calldata */ &[],
//! )?;
//!
//! // 3. Submit via the canonical RPC.
//! let tx_hash = provider.send_raw_encrypted_transaction(&bytes).await?;
//! # Ok(())
//! # }
//! ```
//!
//! The node never sees the plaintext `(to, value, calldata)` and the
//! FALCON signature binds to a hash the client actually knows — two
//! properties the server-side `pyde_sendEncryptedTransaction` path
//! cannot achieve.

use crate::error::{Result, SdkError};
use pyde_account::address::Address;
use pyde_crypto::falcon::{falcon_sign, FalconSecretKey};
use pyde_crypto::threshold::ThresholdPublicKey;
use pyde_mempool::encrypted::{encrypt_transaction, EncryptedTx};
use pyde_tx::types::AccessEntry;

/// Build a client-signed `EncryptedTx` ready for submission via
/// `pyde_sendRawEncryptedTransaction`.
///
/// Encryption order matters: the FALCON signature must be over
/// `EncryptedTx::hash()`, which includes the ciphertext. So we:
///
///   1. Encrypt `(to, value, calldata)` with the committee's
///      threshold pubkey, producing the inner ciphertext.
///   2. Assemble the outer `EncryptedTx` with an empty signature
///      field.
///   3. Compute `hash()`.
///   4. FALCON-sign the hash.
///   5. Write the signature back into the EncryptedTx.
///   6. Serialize via `to_bytes`.
///
/// The returned bytes are what `pyde_sendRawEncryptedTransaction`
/// expects (after hex encoding).
#[allow(clippy::too_many_arguments)]
pub fn build_raw_encrypted_tx(
    threshold_pk: &ThresholdPublicKey,
    secret_key: &FalconSecretKey,
    sender: Address,
    nonce: u64,
    gas_limit: u64,
    access_list: Vec<AccessEntry>,
    deadline: Option<u64>,
    chain_id: u64,
    to: &Address,
    value: u128,
    calldata: &[u8],
) -> Result<Vec<u8>> {
    // Encrypt the private fields against the committee pubkey.
    // `signature = vec![]` here — we'll fill it in after hashing.
    let mut enc_tx = encrypt_transaction(
        sender,
        nonce,
        gas_limit,
        access_list,
        deadline,
        chain_id,
        Vec::new(),
        to,
        value,
        calldata,
        threshold_pk,
    )
    .map_err(|e| SdkError::Other(format!("threshold encryption failed: {}", e)))?;

    // Sign the hash — which binds sender + nonce + gas + chain +
    // ciphertext-hash — so post-encrypt, pre-sign tampering by the
    // RPC node would be detectable.
    let hash = enc_tx.hash();
    let sig = falcon_sign(secret_key, &hash)
        .map_err(|e| SdkError::Other(format!("FALCON sign failed: {}", e)))?;
    enc_tx.signature = sig.as_bytes().to_vec();

    Ok(enc_tx.to_bytes())
}

/// Decode a `ThresholdPublicKey` from the hex bytes returned by
/// `pyde_getThresholdPublicKey`. Strips an optional `0x` prefix.
pub fn parse_threshold_public_key(hex_str: &str) -> Result<ThresholdPublicKey> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes =
        hex::decode(stripped).map_err(|e| SdkError::Other(format!("invalid hex: {}", e)))?;
    ThresholdPublicKey::from_bytes(&bytes)
        .ok_or_else(|| SdkError::Other("invalid ThresholdPublicKey bytes".into()))
}

/// Re-export so downstream callers don't need to pull in
/// `pyde-mempool` directly just to decode a returned tx.
pub use pyde_mempool::encrypted::EncryptedTx as RawEncryptedTx;

/// Round-trip decode: takes the wire bytes produced by
/// `build_raw_encrypted_tx` and returns the parsed struct. Useful
/// in tests and for clients that want to inspect a tx before
/// submitting.
pub fn decode_raw_encrypted_tx(bytes: &[u8]) -> Result<EncryptedTx> {
    EncryptedTx::from_bytes(bytes)
        .ok_or_else(|| SdkError::Other("invalid EncryptedTx wire format".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::falcon::{falcon_keygen, falcon_verify, FalconPublicKey};
    use pyde_crypto::threshold::threshold_keygen;

    #[test]
    fn round_trip_build_and_decode() {
        // Full client-side flow in one test: generate a threshold
        // committee, generate a FALCON keypair, build an encrypted
        // tx, decode it back, verify the signature against the
        // sender's pubkey, round-trip the wire format.
        let (tpk, _shares) = threshold_keygen(4, 3).unwrap();
        let (pk, sk) = falcon_keygen().unwrap();
        let sender = derive_eoa_address(pk.as_bytes());
        let to = [0xBBu8; 32];
        let calldata = b"hello encrypted world";

        let bytes = build_raw_encrypted_tx(
            &tpk,
            &sk,
            sender,
            /* nonce */ 7,
            /* gas_limit */ 42_000,
            /* access_list */ vec![],
            /* deadline */ Some(1000),
            /* chain_id */ 31337,
            &to,
            /* value */ 99,
            calldata,
        )
        .unwrap();

        let decoded = decode_raw_encrypted_tx(&bytes).unwrap();
        assert_eq!(decoded.sender, sender);
        assert_eq!(decoded.nonce, 7);
        assert_eq!(decoded.gas_limit, 42_000);
        assert_eq!(decoded.chain_id, 31337);
        assert_eq!(decoded.deadline, Some(1000));
        assert!(
            !decoded.signature.is_empty(),
            "signature field must be populated after build"
        );

        // Signature must verify against the sender's FALCON pubkey
        // over the decoded EncryptedTx::hash() — that's the exact
        // check `receive_tx_verified` runs on the server side.
        let falcon_pk = FalconPublicKey::from_bytes(pk.as_bytes()).unwrap();
        let sig_obj = pyde_crypto::falcon::FalconSignature::from_bytes(&decoded.signature).unwrap();
        assert!(
            falcon_verify(&falcon_pk, &decoded.hash(), &sig_obj),
            "signature must verify on a freshly-decoded tx"
        );
    }

    #[test]
    fn parse_threshold_public_key_round_trip() {
        let (tpk, _) = threshold_keygen(4, 3).unwrap();
        let hex_with_prefix = format!("0x{}", hex::encode(tpk.to_bytes()));
        let parsed = parse_threshold_public_key(&hex_with_prefix).unwrap();
        assert_eq!(parsed.to_bytes(), tpk.to_bytes());

        // No 0x prefix also works.
        let no_prefix = hex::encode(tpk.to_bytes());
        let parsed2 = parse_threshold_public_key(&no_prefix).unwrap();
        assert_eq!(parsed2.to_bytes(), tpk.to_bytes());
    }

    #[test]
    fn parse_threshold_public_key_rejects_garbage() {
        assert!(parse_threshold_public_key("0xzzz").is_err());
        assert!(parse_threshold_public_key("deadbeef").is_err()); // wrong length
    }

    #[test]
    fn tampering_invalidates_signature() {
        // If someone flips a byte in the ciphertext before submit,
        // the client's signature no longer verifies. Proves the
        // signature actually binds the ciphertext (the whole point
        // of doing encryption client-side — the server-side flow
        // cannot achieve this).
        let (tpk, _shares) = threshold_keygen(4, 3).unwrap();
        let (pk, sk) = falcon_keygen().unwrap();
        let sender = derive_eoa_address(pk.as_bytes());

        let bytes = build_raw_encrypted_tx(
            &tpk,
            &sk,
            sender,
            0,
            21_000,
            vec![],
            None,
            1,
            &[0xAAu8; 32],
            1,
            &[],
        )
        .unwrap();

        let mut tampered = bytes.clone();
        // Flip a byte deep in the buffer — where the ciphertext
        // lives in the serialized frame. Exact offset doesn't
        // matter for the assertion; the outcome is "hash changes,
        // signature no longer covers it."
        let last_quarter = (tampered.len() * 3) / 4;
        tampered[last_quarter] ^= 0x01;

        let decoded = match decode_raw_encrypted_tx(&tampered) {
            Ok(d) => d,
            // If tampering produced invalid wire bytes, the server
            // rejects at decode anyway — equally acceptable outcome.
            Err(_) => return,
        };

        let falcon_pk = FalconPublicKey::from_bytes(pk.as_bytes()).unwrap();
        let sig_obj = pyde_crypto::falcon::FalconSignature::from_bytes(&decoded.signature).unwrap();
        assert!(
            !falcon_verify(&falcon_pk, &decoded.hash(), &sig_obj),
            "tampered ciphertext must break the signature"
        );
    }
}
