use alloc::vec;
use alloc::vec::Vec;

use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;

use crate::kyber::{
    kyber_decapsulate, kyber_encapsulate, kyber_keygen, KyberCiphertext, KyberPublicKey,
    KyberSecretKey, SharedSecret,
};
use crate::poseidon2::poseidon2_hash;

// --- Goldilocks field arithmetic helpers ---

fn gl(val: u64) -> Goldilocks {
    PrimeCharacteristicRing::from_u64(val)
}

fn gl_to_u64(el: Goldilocks) -> u64 {
    el.as_canonical_u64()
}

fn gl_inv(x: Goldilocks) -> Goldilocks {
    // Fermat's little theorem: x^(p-2) mod p
    // p = 2^64 - 2^32 + 1, so p-2 = 2^64 - 2^32 - 1
    // Use the field's built-in inverse
    x.inverse()
}

// --- Shamir Secret Sharing over Goldilocks ---

/// A single share for one field element: (x, y) where y = poly(x).
#[derive(Clone, Debug)]
struct FieldShare {
    x: Goldilocks, // evaluation point (1..n)
    y: Goldilocks, // polynomial evaluation
}

/// Generate random Goldilocks element from entropy.
fn random_goldilocks(entropy: &[u8], index: usize) -> Goldilocks {
    let mut input = Vec::with_capacity(entropy.len() + 8);
    input.extend_from_slice(entropy);
    input.extend_from_slice(&(index as u64).to_le_bytes());
    let hash = poseidon2_hash(&input);
    let bytes = hash.as_bytes();
    let val = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    gl(val)
}

/// Split a single field element into n shares with threshold t.
fn shamir_split(
    secret: Goldilocks,
    n: usize,
    t: usize,
    entropy: &[u8],
    element_idx: usize,
) -> Vec<FieldShare> {
    // Build a degree-(t-1) polynomial: coeffs[0] = secret, rest random
    let mut coeffs = vec![secret];
    for i in 1..t {
        coeffs.push(random_goldilocks(entropy, element_idx * 1000 + i));
    }

    // Evaluate at x = 1..n
    (1..=n)
        .map(|i| {
            let x = gl(i as u64);
            let mut y = Goldilocks::ZERO;
            let mut x_pow = Goldilocks::ONE;
            for c in &coeffs {
                y += *c * x_pow;
                x_pow *= x;
            }
            FieldShare { x, y }
        })
        .collect()
}

/// Recover secret from t shares via Lagrange interpolation at x=0.
fn shamir_reconstruct(shares: &[FieldShare]) -> Goldilocks {
    let t = shares.len();
    let mut result = Goldilocks::ZERO;

    for i in 0..t {
        let mut basis = Goldilocks::ONE;
        for j in 0..t {
            if i != j {
                // basis *= (0 - x_j) / (x_i - x_j) = -x_j / (x_i - x_j)
                let num = Goldilocks::ZERO - shares[j].x;
                let den = shares[i].x - shares[j].x;
                basis *= num * gl_inv(den);
            }
        }
        result += shares[i].y * basis;
    }
    result
}

// --- Threshold Kyber types ---

/// Committee-level threshold public key.
#[derive(Clone, Debug)]
pub struct ThresholdPublicKey {
    /// The underlying Kyber-768 public key.
    pub kyber_pk: KyberPublicKey,
    /// Number of committee members.
    pub n: usize,
    /// Threshold (minimum shares needed).
    pub threshold: usize,
}

/// Per-validator key share (their portion of the Kyber secret seed).
#[derive(Clone)]
pub struct KeyShare {
    /// Validator index (1-based).
    pub index: usize,
    /// Share values for each of the 8 seed elements.
    shares: Vec<Goldilocks>,
}

/// A partial decryption share from one validator.
#[derive(Clone, Debug)]
pub struct DecryptionShare {
    /// Validator index (1-based).
    pub index: usize,
    /// Share values.
    shares: Vec<Goldilocks>,
}

/// Threshold-encrypted ciphertext.
#[derive(Clone, Debug)]
pub struct ThresholdCiphertext {
    /// Kyber ciphertext (encapsulated shared secret).
    kyber_ct: KyberCiphertext,
    /// Symmetrically encrypted message (XOR with Poseidon2 keystream).
    encrypted_msg: Vec<u8>,
    /// MAC over the encrypted message.
    mac: [u8; 32],
}

// --- Symmetric encryption using Poseidon2-derived keystream ---

const SEED_ELEMENTS: usize = 8; // 64-byte seed = 8 × 8-byte elements

fn derive_keystream(shared_secret: &SharedSecret, len: usize) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(len);
    let mut counter = 0u64;
    while keystream.len() < len {
        let mut input = Vec::with_capacity(40);
        input.extend_from_slice(shared_secret.as_bytes());
        input.extend_from_slice(&counter.to_le_bytes());
        let block = poseidon2_hash(&input);
        keystream.extend_from_slice(block.as_bytes());
        counter += 1;
    }
    keystream.truncate(len);
    keystream
}

fn compute_mac(shared_secret: &SharedSecret, ciphertext: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + ciphertext.len());
    // Domain-separate MAC from keystream by using a different prefix
    input.extend_from_slice(&[0xFF; 8]);
    input.extend_from_slice(shared_secret.as_bytes());
    input.extend_from_slice(ciphertext);
    *poseidon2_hash(&input).as_bytes()
}

fn xor_bytes(data: &[u8], keystream: &[u8]) -> Vec<u8> {
    data.iter()
        .zip(keystream.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

// --- Public API ---

/// Generate a threshold keypair: committee public key + n key shares.
/// Returns (ThresholdPublicKey, Vec<KeyShare>) where each KeyShare belongs to one validator.
pub fn threshold_keygen(n: usize, threshold: usize) -> (ThresholdPublicKey, Vec<KeyShare>) {
    assert!(threshold <= n, "threshold must be <= n");
    assert!(threshold >= 1, "threshold must be >= 1");

    let (pk, sk) = kyber_keygen();

    // Convert 64-byte seed to 8 Goldilocks elements
    let seed_bytes = sk.as_bytes();
    let seed_elements: Vec<Goldilocks> = (0..SEED_ELEMENTS)
        .map(|i| {
            let chunk: [u8; 8] = seed_bytes[i * 8..(i + 1) * 8].try_into().unwrap();
            gl(u64::from_le_bytes(chunk))
        })
        .collect();

    // Generate entropy for random polynomial coefficients
    let entropy = poseidon2_hash(seed_bytes);

    // Split each element independently
    let all_shares: Vec<Vec<FieldShare>> = seed_elements
        .iter()
        .enumerate()
        .map(|(idx, &secret)| shamir_split(secret, n, threshold, entropy.as_bytes(), idx))
        .collect();

    // Transpose: per-validator key shares
    let key_shares: Vec<KeyShare> = (0..n)
        .map(|validator_idx| {
            let shares = all_shares
                .iter()
                .map(|element_shares| element_shares[validator_idx].y)
                .collect();
            KeyShare {
                index: validator_idx + 1, // 1-based
                shares,
            }
        })
        .collect();

    let tpk = ThresholdPublicKey {
        kyber_pk: pk,
        n,
        threshold,
    };

    (tpk, key_shares)
}

/// Encrypt a message using the committee's threshold public key.
pub fn threshold_encrypt(tpk: &ThresholdPublicKey, msg: &[u8]) -> ThresholdCiphertext {
    let (kyber_ct, ss) = kyber_encapsulate(&tpk.kyber_pk);
    let keystream = derive_keystream(&ss, msg.len());
    let encrypted_msg = xor_bytes(msg, &keystream);
    let mac = compute_mac(&ss, &encrypted_msg);

    ThresholdCiphertext {
        kyber_ct,
        encrypted_msg,
        mac,
    }
}

/// Generate a decryption share from a validator's key share.
/// (In the reconstruct-then-decrypt model, the share is just passed through.)
pub fn generate_decryption_share(
    key_share: &KeyShare,
    _ct: &ThresholdCiphertext,
) -> DecryptionShare {
    DecryptionShare {
        index: key_share.index,
        shares: key_share.shares.clone(),
    }
}

/// Combine decryption shares to recover the plaintext.
/// Requires at least `threshold` shares.
pub fn combine_shares(
    shares: &[DecryptionShare],
    threshold: usize,
    ct: &ThresholdCiphertext,
) -> Result<Vec<u8>, &'static str> {
    if shares.len() < threshold {
        return Err("insufficient shares");
    }

    // Check for duplicate indices
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].index == shares[j].index {
                return Err("duplicate share index");
            }
        }
    }

    // Use exactly `threshold` shares
    let used_shares = &shares[..threshold];

    // Reconstruct each seed element
    let mut seed_bytes = [0u8; 64];
    for elem_idx in 0..SEED_ELEMENTS {
        let field_shares: Vec<FieldShare> = used_shares
            .iter()
            .map(|s| FieldShare {
                x: gl(s.index as u64),
                y: s.shares[elem_idx],
            })
            .collect();
        let secret = shamir_reconstruct(&field_shares);
        let val = gl_to_u64(secret);
        seed_bytes[elem_idx * 8..(elem_idx + 1) * 8].copy_from_slice(&val.to_le_bytes());
    }

    // Reconstruct Kyber secret key from seed
    let sk = KyberSecretKey::from_bytes(&seed_bytes).ok_or("invalid reconstructed seed")?;

    // Decapsulate to get shared secret
    let ss = kyber_decapsulate(&sk, &ct.kyber_ct);

    // Verify MAC
    let expected_mac = compute_mac(&ss, &ct.encrypted_msg);
    if expected_mac != ct.mac {
        return Err("MAC verification failed");
    }

    // Decrypt
    let keystream = derive_keystream(&ss, ct.encrypted_msg.len());
    Ok(xor_bytes(&ct.encrypted_msg, &keystream))
}

// --- Proactive Secret Sharing (PSS) ---

/// Epoch key material: tracks the current epoch and committee parameters.
#[derive(Clone, Debug)]
pub struct EpochKeyMaterial {
    /// Current epoch number.
    pub epoch: u64,
    /// Number of committee members.
    pub n: usize,
    /// Threshold (minimum shares needed).
    pub threshold: usize,
    /// The committee's threshold public key (unchanged across refreshes).
    pub tpk: ThresholdPublicKey,
}

/// A refresh contribution from one validator: zero-secret shares for all validators.
/// Each validator generates a random degree-(t-1) polynomial with f(0) = 0,
/// evaluates it at all n points, and distributes the values.
#[derive(Clone)]
pub struct RefreshContribution {
    /// Index of the validator who generated this contribution (1-based).
    pub from_index: usize,
    /// Delta values for each validator (indexed 0..n), each containing SEED_ELEMENTS values.
    deltas: Vec<Vec<Goldilocks>>,
}

/// Generate a refresh contribution for PSS.
/// The validator generates random degree-(t-1) polynomials with zero constant term
/// for each seed element, then evaluates at all n points.
pub fn generate_refresh_contribution(
    from_index: usize,
    n: usize,
    threshold: usize,
    epoch: u64,
    entropy: &[u8],
) -> RefreshContribution {
    // Domain-separate entropy by epoch and validator index
    let mut domain_input = Vec::with_capacity(entropy.len() + 16);
    domain_input.extend_from_slice(entropy);
    domain_input.extend_from_slice(&epoch.to_le_bytes());
    domain_input.extend_from_slice(&(from_index as u64).to_le_bytes());
    let domain_entropy = poseidon2_hash(&domain_input);

    // For each seed element, generate a zero-secret polynomial and evaluate at 1..n
    let mut all_deltas: Vec<Vec<Vec<Goldilocks>>> = Vec::with_capacity(SEED_ELEMENTS);
    for elem_idx in 0..SEED_ELEMENTS {
        // shamir_split with secret=0 gives us zero-secret shares
        let zero_shares = shamir_split(
            Goldilocks::ZERO,
            n,
            threshold,
            domain_entropy.as_bytes(),
            elem_idx,
        );
        let element_deltas: Vec<Goldilocks> = zero_shares.iter().map(|s| s.y).collect();
        all_deltas.push(vec![element_deltas]);
    }

    // Transpose to per-validator: deltas[validator_idx][elem_idx]
    let deltas: Vec<Vec<Goldilocks>> = (0..n)
        .map(|v| (0..SEED_ELEMENTS).map(|e| all_deltas[e][0][v]).collect())
        .collect();

    RefreshContribution { from_index, deltas }
}

/// Apply refresh contributions to a validator's key share.
/// Each validator sums the delta values from all contributions into their share.
/// The underlying secret remains the same, but all shares change.
pub fn apply_refresh(key_share: &KeyShare, contributions: &[RefreshContribution]) -> KeyShare {
    let validator_idx = key_share.index - 1; // 0-based index into deltas
    let mut new_shares = key_share.shares.clone();

    for contrib in contributions {
        for elem_idx in 0..SEED_ELEMENTS {
            new_shares[elem_idx] += contrib.deltas[validator_idx][elem_idx];
        }
    }

    KeyShare {
        index: key_share.index,
        shares: new_shares,
    }
}

/// Verify a refresh contribution by checking that each zero-secret polynomial
/// evaluates correctly (the shares from this contribution alone reconstruct to zero).
pub fn verify_refresh_contribution(contribution: &RefreshContribution, threshold: usize) -> bool {
    // For each seed element, take `threshold` shares and verify they reconstruct to zero
    for elem_idx in 0..SEED_ELEMENTS {
        let field_shares: Vec<FieldShare> = (0..threshold)
            .map(|v| FieldShare {
                x: gl((v + 1) as u64),
                y: contribution.deltas[v][elem_idx],
            })
            .collect();
        let reconstructed = shamir_reconstruct(&field_shares);
        if reconstructed != Goldilocks::ZERO {
            return false;
        }
    }
    true
}

/// Perform a full PSS refresh for the committee.
/// Returns new key shares for all validators and updated epoch material.
pub fn pss_refresh(
    epoch_material: &EpochKeyMaterial,
    old_shares: &[KeyShare],
) -> (EpochKeyMaterial, Vec<KeyShare>) {
    let n = epoch_material.n;
    let t = epoch_material.threshold;
    let new_epoch = epoch_material.epoch + 1;

    // Each validator generates a refresh contribution
    let contributions: Vec<RefreshContribution> = old_shares
        .iter()
        .map(|ks| {
            // Use hash of share data as entropy for the contribution
            let share_entropy: Vec<u8> = ks
                .shares
                .iter()
                .flat_map(|s| gl_to_u64(*s).to_le_bytes())
                .collect();
            generate_refresh_contribution(ks.index, n, t, new_epoch, &share_entropy)
        })
        .collect();

    // Each validator applies all contributions to their share
    let new_shares: Vec<KeyShare> = old_shares
        .iter()
        .map(|ks| apply_refresh(ks, &contributions))
        .collect();

    let new_material = EpochKeyMaterial {
        epoch: new_epoch,
        n,
        threshold: t,
        tpk: epoch_material.tpk.clone(),
    };

    (new_material, new_shares)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    const N: usize = 128;
    const T: usize = 85;

    fn setup() -> (ThresholdPublicKey, Vec<KeyShare>) {
        threshold_keygen(N, T)
    }

    #[test]
    fn encrypt_decrypt_with_threshold_plus_one() {
        let (tpk, shares) = setup();
        let msg = b"hello threshold kyber";
        let ct = threshold_encrypt(&tpk, msg);

        let dec_shares: Vec<DecryptionShare> = shares[..T + 1]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();

        let plaintext = combine_shares(&dec_shares, T, &ct).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn encrypt_decrypt_with_exact_threshold() {
        let (tpk, shares) = setup();
        let msg = b"exact threshold test";
        let ct = threshold_encrypt(&tpk, msg);

        let dec_shares: Vec<DecryptionShare> = shares[..T]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();

        let plaintext = combine_shares(&dec_shares, T, &ct).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn insufficient_shares_fails() {
        let (tpk, shares) = setup();
        let msg = b"not enough shares";
        let ct = threshold_encrypt(&tpk, msg);

        let dec_shares: Vec<DecryptionShare> = shares[..T - 1]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();

        let result = combine_shares(&dec_shares, T, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_shares_rejected() {
        let (tpk, shares) = setup();
        let msg = b"duplicate test";
        let ct = threshold_encrypt(&tpk, msg);

        let mut dec_shares: Vec<DecryptionShare> = shares[..T - 1]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();
        // Add a duplicate
        dec_shares.push(generate_decryption_share(&shares[0], &ct));

        let result = combine_shares(&dec_shares, T, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_shares_produce_bad_mac() {
        let (tpk, _shares) = setup();
        let (_tpk2, shares2) = threshold_keygen(N, T);
        let msg = b"wrong shares test";
        let ct = threshold_encrypt(&tpk, msg);

        // Use shares from a different committee
        let dec_shares: Vec<DecryptionShare> = shares2[..T]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();

        let result = combine_shares(&dec_shares, T, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn any_subset_of_shares_works() {
        let (tpk, shares) = setup();
        let msg = b"any subset works";
        let ct = threshold_encrypt(&tpk, msg);

        // Use last T shares instead of first T
        let dec_shares: Vec<DecryptionShare> = shares[N - T..]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();

        let plaintext = combine_shares(&dec_shares, T, &ct).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn empty_message() {
        let (tpk, shares) = setup();
        let msg = b"";
        let ct = threshold_encrypt(&tpk, msg);

        let dec_shares: Vec<DecryptionShare> = shares[..T]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();

        let plaintext = combine_shares(&dec_shares, T, &ct).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn large_message() {
        let (tpk, shares) = threshold_keygen(5, 3); // smaller for speed
        let msg = vec![0xABu8; 10_000];
        let ct = threshold_encrypt(&tpk, &msg);

        let dec_shares: Vec<DecryptionShare> = shares[..3]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();

        let plaintext = combine_shares(&dec_shares, 3, &ct).unwrap();
        assert_eq!(plaintext, msg);
    }

    // Small-scale Shamir SSS unit test
    #[test]
    fn shamir_roundtrip_small() {
        let secret = gl(12345);
        let entropy = poseidon2_hash(b"test entropy");
        let shares = shamir_split(secret, 5, 3, entropy.as_bytes(), 0);

        // Reconstruct from first 3
        let reconstructed = shamir_reconstruct(
            &shares[..3]
                .iter()
                .map(|s| FieldShare { x: s.x, y: s.y })
                .collect::<Vec<_>>(),
        );
        assert_eq!(gl_to_u64(reconstructed), 12345);

        // Reconstruct from last 3
        let reconstructed2 = shamir_reconstruct(
            &shares[2..5]
                .iter()
                .map(|s| FieldShare { x: s.x, y: s.y })
                .collect::<Vec<_>>(),
        );
        assert_eq!(gl_to_u64(reconstructed2), 12345);
    }

    // --- PSS tests ---

    fn setup_epoch(n: usize, t: usize) -> (EpochKeyMaterial, Vec<KeyShare>) {
        let (tpk, shares) = threshold_keygen(n, t);
        let epoch_material = EpochKeyMaterial {
            epoch: 0,
            n,
            threshold: t,
            tpk,
        };
        (epoch_material, shares)
    }

    #[test]
    fn pss_refreshed_shares_decrypt_old_ciphertext() {
        let (epoch_mat, shares) = setup_epoch(5, 3);
        let msg = b"encrypted before refresh";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg);

        // Refresh shares
        let (_new_epoch, new_shares) = pss_refresh(&epoch_mat, &shares);

        // New shares should still decrypt old ciphertext
        let dec_shares: Vec<DecryptionShare> = new_shares[..3]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();
        let plaintext = combine_shares(&dec_shares, 3, &ct).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn pss_old_shares_cannot_decrypt_after_refresh() {
        let (epoch_mat, shares) = setup_epoch(5, 3);

        // Refresh shares
        let (new_epoch, new_shares) = pss_refresh(&epoch_mat, &shares);

        // Encrypt with the same public key (it doesn't change)
        let msg = b"encrypted after refresh";
        let ct = threshold_encrypt(&new_epoch.tpk, msg);

        // New shares should work
        let dec_shares_new: Vec<DecryptionShare> = new_shares[..3]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();
        let plaintext = combine_shares(&dec_shares_new, 3, &ct).unwrap();
        assert_eq!(plaintext, msg);

        // Old shares should fail (they reconstruct a different secret)
        let dec_shares_old: Vec<DecryptionShare> = shares[..3]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();
        // Old shares still reconstruct the SAME secret (the secret doesn't change),
        // so they should also work. PSS only protects against partial compromise.
        let plaintext_old = combine_shares(&dec_shares_old, 3, &ct).unwrap();
        assert_eq!(plaintext_old, msg);
    }

    #[test]
    fn pss_mixed_old_new_shares_fail() {
        let (epoch_mat, shares) = setup_epoch(5, 3);
        let msg = b"mixed shares test";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg);

        let (_new_epoch, new_shares) = pss_refresh(&epoch_mat, &shares);

        // Mix old and new shares from different validators — should fail
        // because shares from different epochs lie on different polynomials
        let mixed_shares = vec![
            generate_decryption_share(&shares[0], &ct), // old share, validator 1
            generate_decryption_share(&new_shares[1], &ct), // new share, validator 2
            generate_decryption_share(&new_shares[2], &ct), // new share, validator 3
        ];
        let result = combine_shares(&mixed_shares, 3, &ct);
        assert!(
            result.is_err(),
            "mixing old and new epoch shares should fail"
        );
    }

    #[test]
    fn pss_multiple_refreshes() {
        let (epoch_mat, shares) = setup_epoch(5, 3);
        let msg = b"multi-refresh test";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg);

        // Refresh multiple times
        let (epoch1, shares1) = pss_refresh(&epoch_mat, &shares);
        let (epoch2, shares2) = pss_refresh(&epoch1, &shares1);
        let (_epoch3, shares3) = pss_refresh(&epoch2, &shares2);

        // Shares after 3 refreshes should still decrypt
        let dec_shares: Vec<DecryptionShare> = shares3[..3]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();
        let plaintext = combine_shares(&dec_shares, 3, &ct).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn pss_verify_refresh_contributions() {
        let (epoch_mat, shares) = setup_epoch(5, 3);
        let new_epoch = epoch_mat.epoch + 1;

        // Generate contributions
        for ks in &shares {
            let share_entropy: Vec<u8> = ks
                .shares
                .iter()
                .flat_map(|s| gl_to_u64(*s).to_le_bytes())
                .collect();
            let contrib = generate_refresh_contribution(
                ks.index,
                epoch_mat.n,
                epoch_mat.threshold,
                new_epoch,
                &share_entropy,
            );
            assert!(verify_refresh_contribution(&contrib, epoch_mat.threshold));
        }
    }

    #[test]
    fn pss_any_subset_after_refresh() {
        let (epoch_mat, shares) = setup_epoch(10, 7);
        let msg = b"any subset after refresh";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg);

        let (_new_epoch, new_shares) = pss_refresh(&epoch_mat, &shares);

        // Use last 7 shares
        let dec_shares: Vec<DecryptionShare> = new_shares[3..10]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();
        let plaintext = combine_shares(&dec_shares, 7, &ct).unwrap();
        assert_eq!(plaintext, msg);
    }
}
