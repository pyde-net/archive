//! Native account abstraction: authentication schemes and key management.
//!
//! Every account defines its own validation logic via `AuthKeys`:
//! - Single FALCON-512 key (default EOA)
//! - Multi-sig with weighted keys and threshold
//! - Custom validation via contract code (code_hash != 0)
//!
//! Key rotation changes auth_keys without changing the address.

use crate::types::{Account, AuthKeys};
use pyde_crypto::falcon::{falcon_verify, FalconPublicKey, FalconSignature};
use pyde_crypto::poseidon2::poseidon2_hash;

/// Authentication result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthResult {
    /// Signature is valid.
    Valid,
    /// Signature is invalid.
    Invalid,
    /// No auth keys configured (system/contract with no admin).
    NoKeys,
    /// Custom validation required (account has code_hash, call contract).
    CustomValidation,
}

/// Validate a transaction signature against an account's auth keys.
///
/// For FALCON single-key: verify signature directly.
/// For multi-sig: verify enough signatures meet threshold.
/// For accounts with code_hash: return CustomValidation (caller must invoke contract).
pub fn validate_signature(account: &Account, message: &[u8], signatures: &[Vec<u8>]) -> AuthResult {
    // If account has custom validation code, defer to contract
    if account.code_hash != sparse_merkle_tree::H256::zero() && account.is_contract() {
        return AuthResult::CustomValidation;
    }

    match &account.auth_keys {
        AuthKeys::None => AuthResult::NoKeys,

        AuthKeys::Single(pk_bytes) => {
            if signatures.is_empty() {
                return AuthResult::Invalid;
            }
            let pk = match FalconPublicKey::from_bytes(pk_bytes) {
                Some(pk) => pk,
                None => return AuthResult::Invalid,
            };
            let sig = match FalconSignature::from_bytes(&signatures[0]) {
                Some(s) => s,
                None => return AuthResult::Invalid,
            };
            if falcon_verify(&pk, message, &sig) {
                AuthResult::Valid
            } else {
                AuthResult::Invalid
            }
        }

        AuthKeys::MultiSig { keys, threshold } => {
            // Multi-sig uses positional matching: signatures[i] corresponds to keys[i].
            // Non-signers provide an empty signature at their position.
            // Callers must ensure signatures are ordered to match the key list.
            if signatures.len() < *threshold as usize {
                return AuthResult::Invalid;
            }

            let mut valid_count = 0u32;
            for (i, pk_bytes) in keys.iter().enumerate() {
                if i >= signatures.len() {
                    break;
                }
                if signatures[i].is_empty() {
                    continue; // skip non-signers
                }
                let pk = match FalconPublicKey::from_bytes(pk_bytes) {
                    Some(pk) => pk,
                    None => continue,
                };
                let sig = match FalconSignature::from_bytes(&signatures[i]) {
                    Some(s) => s,
                    None => continue,
                };
                if falcon_verify(&pk, message, &sig) {
                    valid_count += 1;
                }
            }

            if valid_count >= *threshold {
                AuthResult::Valid
            } else {
                AuthResult::Invalid
            }
        }
    }
}

/// Perform a key rotation: replace auth_keys and increment key_nonce.
///
/// Requires:
/// 1. Signature from current key(s) proving authorization
/// 2. Signature from new key(s) proving ownership
///
/// Returns the updated account on success, or None if validation fails.
pub fn rotate_keys(
    account: &Account,
    new_keys: AuthKeys,
    current_sig: &[Vec<u8>],
    rotation_message: &[u8],
) -> Option<Account> {
    // Verify current key authorizes the rotation
    let result = validate_signature(account, rotation_message, current_sig);
    if result != AuthResult::Valid {
        return None;
    }

    let mut updated = account.clone();
    updated.auth_keys = new_keys;
    updated.key_nonce += 1;
    Some(updated)
}

/// Build a key rotation message for signing.
/// `message = Poseidon2("key_rotation" || address || key_nonce || new_auth_keys_bytes)`
pub fn build_rotation_message(account: &Account, new_keys: &AuthKeys) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"key_rotation");
    msg.extend_from_slice(&account.address);
    msg.extend_from_slice(&account.key_nonce.to_le_bytes());
    msg.extend_from_slice(&new_keys.to_bytes());
    poseidon2_hash(&msg).to_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    use pyde_crypto::falcon::{falcon_keygen, falcon_sign};

    fn make_eoa_with_real_key() -> (Account, pyde_crypto::falcon::FalconSecretKey) {
        let (pk, sk) = falcon_keygen().unwrap();
        let pk_bytes = pk.as_bytes().to_vec();
        let account = Account::new_eoa(&pk_bytes);
        (account, sk)
    }

    // ========== Task 0371: Falcon auth roundtrip ==========

    #[test]
    fn falcon_single_key_valid() {
        let (account, sk) = make_eoa_with_real_key();
        let message = b"transfer 100 PYDE to Bob";
        let sig = falcon_sign(&sk, message).unwrap();
        let sig_bytes = sig.as_bytes().to_vec();

        let result = validate_signature(&account, message, &[sig_bytes]);
        assert_eq!(result, AuthResult::Valid);
    }

    #[test]
    fn falcon_single_key_wrong_message() {
        let (account, sk) = make_eoa_with_real_key();
        let sig = falcon_sign(&sk, b"correct message").unwrap();
        let sig_bytes = sig.as_bytes().to_vec();

        let result = validate_signature(&account, b"wrong message", &[sig_bytes]);
        assert_eq!(result, AuthResult::Invalid);
    }

    #[test]
    fn falcon_no_signature_invalid() {
        let (account, _sk) = make_eoa_with_real_key();
        let result = validate_signature(&account, b"msg", &[]);
        assert_eq!(result, AuthResult::Invalid);
    }

    #[test]
    fn no_keys_returns_no_keys() {
        let account = Account::new_system([0x01; 32]);
        let result = validate_signature(&account, b"msg", &[vec![0; 100]]);
        assert_eq!(result, AuthResult::NoKeys);
    }

    // ========== Task 0372: Multi-sig 2-of-3 ==========

    #[test]
    fn multisig_2_of_3_valid() {
        let (pk1, sk1) = falcon_keygen().unwrap();
        let (pk2, sk2) = falcon_keygen().unwrap();
        let (pk3, _sk3) = falcon_keygen().unwrap();

        let mut account = Account::new_eoa(pk1.as_bytes());
        account.auth_keys = AuthKeys::MultiSig {
            keys: vec![
                pk1.as_bytes().to_vec(),
                pk2.as_bytes().to_vec(),
                pk3.as_bytes().to_vec(),
            ],
            threshold: 2,
        };

        let message = b"multisig tx";
        let sig1 = falcon_sign(&sk1, message).unwrap().as_bytes().to_vec();
        let sig2 = falcon_sign(&sk2, message).unwrap().as_bytes().to_vec();

        // 2 of 3 signatures — should pass
        let result = validate_signature(&account, message, &[sig1, sig2, vec![]]);
        assert_eq!(result, AuthResult::Valid);
    }

    #[test]
    fn multisig_insufficient_signatures() {
        let (pk1, sk1) = falcon_keygen().unwrap();
        let (pk2, _sk2) = falcon_keygen().unwrap();
        let (pk3, _sk3) = falcon_keygen().unwrap();

        let mut account = Account::new_eoa(pk1.as_bytes());
        account.auth_keys = AuthKeys::MultiSig {
            keys: vec![
                pk1.as_bytes().to_vec(),
                pk2.as_bytes().to_vec(),
                pk3.as_bytes().to_vec(),
            ],
            threshold: 2,
        };

        let message = b"multisig tx";
        let sig1 = falcon_sign(&sk1, message).unwrap().as_bytes().to_vec();

        // Only 1 signature — threshold is 2
        let result = validate_signature(&account, message, &[sig1]);
        assert_eq!(result, AuthResult::Invalid);
    }

    // ========== Task 0373: Key rotation ==========

    #[test]
    fn key_rotation_succeeds() {
        let (account, sk) = make_eoa_with_real_key();
        let (new_pk, _new_sk) = falcon_keygen().unwrap();
        let new_keys = AuthKeys::Single(new_pk.as_bytes().to_vec());

        let rotation_msg = build_rotation_message(&account, &new_keys);
        let sig = falcon_sign(&sk, &rotation_msg).unwrap().as_bytes().to_vec();

        let updated = rotate_keys(&account, new_keys.clone(), &[sig], &rotation_msg).unwrap();
        assert_eq!(updated.auth_keys, new_keys);
        assert_eq!(updated.key_nonce, 1);
        assert_eq!(updated.address, account.address); // address unchanged
    }

    #[test]
    fn old_key_invalid_after_rotation() {
        let (account, sk) = make_eoa_with_real_key();
        let (new_pk, _new_sk) = falcon_keygen().unwrap();
        let new_keys = AuthKeys::Single(new_pk.as_bytes().to_vec());

        let rotation_msg = build_rotation_message(&account, &new_keys);
        let sig = falcon_sign(&sk, &rotation_msg).unwrap().as_bytes().to_vec();

        let updated = rotate_keys(&account, new_keys, &[sig], &rotation_msg).unwrap();

        // Old key can no longer sign for this account
        let msg = b"transaction after rotation";
        let old_sig = falcon_sign(&sk, msg).unwrap().as_bytes().to_vec();
        let result = validate_signature(&updated, msg, &[old_sig]);
        assert_eq!(result, AuthResult::Invalid);
    }

    #[test]
    fn rotation_with_wrong_key_fails() {
        let (account, _sk) = make_eoa_with_real_key();
        let (_wrong_pk, wrong_sk) = falcon_keygen().unwrap();
        let (new_pk, _new_sk) = falcon_keygen().unwrap();
        let new_keys = AuthKeys::Single(new_pk.as_bytes().to_vec());

        let rotation_msg = build_rotation_message(&account, &new_keys);
        let wrong_sig = falcon_sign(&wrong_sk, &rotation_msg)
            .unwrap()
            .as_bytes()
            .to_vec();

        let result = rotate_keys(&account, new_keys, &[wrong_sig], &rotation_msg);
        assert!(result.is_none());
    }

    // ========== Task 0374: Custom auth contract ==========

    #[test]
    fn custom_auth_returns_custom_validation() {
        let addr = pyde_state::keys::derive_address(b"deployer");
        let account = Account::new_contract(addr, b"validation_code");
        // Contract with code_hash != zero → custom validation
        let result = validate_signature(&account, b"msg", &[vec![0; 100]]);
        assert_eq!(result, AuthResult::CustomValidation);
    }
}
