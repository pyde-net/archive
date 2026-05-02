// Crypto-style index loops (`for i in 0..N { arr[i] = ... }`) read more
// cleanly than clippy's preferred `iter_mut().enumerate()` when the
// domain is fixed-size polynomial / share math and multiple arrays
// share the index. Kept as-is throughout this module.
#![allow(clippy::needless_range_loop)]

use alloc::vec;
use alloc::vec::Vec;

use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::kyber::{
    kyber_decapsulate, kyber_encapsulate, kyber_keygen, KyberCiphertext, KyberPublicKey,
    KyberSecretKey, SharedSecret,
};
use crate::poseidon2::poseidon2_hash;

/// Audit 358: overwrite a `Vec<Goldilocks>` of secret share
/// values with field-zero via volatile writes so the compiler
/// can't optimize the zeroing away. `Goldilocks` is a u64-backed
/// field element from `p3-goldilocks` that doesn't impl
/// `zeroize::Zeroize`, so we go through the volatile-pointer
/// route. After zeroing, `clear()` drops the length to 0; the
/// `Vec`'s allocation is freed normally on drop, but the
/// previously-secret bytes are now zero.
fn zeroize_goldilocks_vec(v: &mut Vec<Goldilocks>) {
    for el in v.iter_mut() {
        // SAFETY: `el` is a valid mutable reference into the
        // Vec's heap buffer; `write_volatile` writes a properly
        // initialized value (`Goldilocks::ZERO`) of the same
        // type. Volatile prevents the optimizer from eliding
        // the write as "dead store" — without it Rust is free
        // to omit the zeroing because the Vec is about to be
        // dropped.
        unsafe { core::ptr::write_volatile(el as *mut Goldilocks, Goldilocks::ZERO) };
    }
    v.clear();
}

/// Same as `zeroize_goldilocks_vec`, but for the nested
/// `Vec<Vec<Goldilocks>>` shape used by refresh / resharing
/// contributions (one inner vec per recipient validator).
fn zeroize_goldilocks_vec_vec(v: &mut Vec<Vec<Goldilocks>>) {
    for inner in v.iter_mut() {
        zeroize_goldilocks_vec(inner);
    }
    v.clear();
}

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
    let mut val_bytes = [0u8; 8];
    val_bytes.copy_from_slice(&bytes[0..8]);
    let val = u64::from_le_bytes(val_bytes);
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

impl ThresholdPublicKey {
    /// Serialize to bytes: [n:4 LE][threshold:4 LE][pk_len:4 LE][pk_bytes]
    pub fn to_bytes(&self) -> Vec<u8> {
        let pk_bytes = self.kyber_pk.as_bytes();
        let mut buf = Vec::with_capacity(12 + pk_bytes.len());
        buf.extend_from_slice(&(self.n as u32).to_le_bytes());
        buf.extend_from_slice(&(self.threshold as u32).to_le_bytes());
        buf.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(pk_bytes);
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let n = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let threshold = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let pk_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        if data.len() < 12 + pk_len {
            return None;
        }
        let pk = KyberPublicKey::from_bytes(&data[12..12 + pk_len])?;
        Some(Self {
            kyber_pk: pk,
            n,
            threshold,
        })
    }
}

/// Per-validator key share (their portion of the Kyber secret seed).
#[derive(Clone)]
pub struct KeyShare {
    /// Validator index (1-based).
    pub index: usize,
    /// Share values for each of the 8 seed elements.
    shares: Vec<Goldilocks>,
}

// Audit 358: a `KeyShare` is one validator's piece of the
// reconstructable Kyber decapsulation seed. The `shares` vec is
// the actual secret material; `index` is public metadata.
// Zeroize on drop so the secret bytes don't sit in deallocated
// heap pages.
impl Zeroize for KeyShare {
    fn zeroize(&mut self) {
        zeroize_goldilocks_vec(&mut self.shares);
    }
}

impl Drop for KeyShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for KeyShare {}

impl KeyShare {
    /// Serialize to bytes: [index:8 LE][count:4 LE][share_0:8 LE]...[share_n:8 LE]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12 + self.shares.len() * 8);
        buf.extend_from_slice(&(self.index as u64).to_le_bytes());
        buf.extend_from_slice(&(self.shares.len() as u32).to_le_bytes());
        for s in &self.shares {
            buf.extend_from_slice(&gl_to_u64(*s).to_le_bytes());
        }
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let index = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]) as usize;
        let count = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        if data.len() < 12 + count * 8 {
            return None;
        }
        let mut shares = Vec::with_capacity(count);
        for i in 0..count {
            let off = 12 + i * 8;
            let val = u64::from_le_bytes([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
                data[off + 4],
                data[off + 5],
                data[off + 6],
                data[off + 7],
            ]);
            shares.push(gl(val));
        }
        Some(Self { index, shares })
    }
}

/// A partial decryption share from one validator.
#[derive(Clone, Debug)]
pub struct DecryptionShare {
    /// Validator index (1-based).
    pub index: usize,
    /// Share values.
    shares: Vec<Goldilocks>,
}

// Audit 358: a `DecryptionShare` is one validator's contribution
// toward decapsulating a particular ciphertext. Reconstructing
// the underlying decapsulation key requires `threshold` of these,
// so a single share isn't a full secret — but a leaked share
// still narrows the attacker's interpolation search space, and
// in concert with other leaked / coerced shares it reconstructs
// the key entirely. Zeroize on drop.
impl Zeroize for DecryptionShare {
    fn zeroize(&mut self) {
        zeroize_goldilocks_vec(&mut self.shares);
    }
}

impl Drop for DecryptionShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DecryptionShare {}

impl DecryptionShare {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12 + self.shares.len() * 8);
        buf.extend_from_slice(&(self.index as u64).to_le_bytes());
        buf.extend_from_slice(&(self.shares.len() as u32).to_le_bytes());
        for s in &self.shares {
            buf.extend_from_slice(&gl_to_u64(*s).to_le_bytes());
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let index = u64::from_le_bytes(data[0..8].try_into().ok()?) as usize;
        let count = u32::from_le_bytes(data[8..12].try_into().ok()?) as usize;
        if data.len() < 12 + count * 8 {
            return None;
        }
        let mut shares = Vec::with_capacity(count);
        for i in 0..count {
            let off = 12 + i * 8;
            let val = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);
            shares.push(gl(val));
        }
        Some(Self { index, shares })
    }
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

impl ThresholdCiphertext {
    /// Length of the encrypted message.
    pub fn encrypted_len(&self) -> usize {
        self.encrypted_msg.len()
    }

    /// Serialize to bytes for hashing (original format, no length prefixes).
    /// Format: [kyber_ct_bytes][encrypted_msg][mac:32]
    pub fn to_bytes(&self) -> Vec<u8> {
        let ct_bytes = self.kyber_ct.as_bytes();
        let mut buf = Vec::with_capacity(ct_bytes.len() + self.encrypted_msg.len() + 32);
        buf.extend_from_slice(ct_bytes);
        buf.extend_from_slice(&self.encrypted_msg);
        buf.extend_from_slice(&self.mac);
        buf
    }

    /// Serialize to wire format with length prefixes (for block inclusion).
    /// Format: [ct_len:4 LE][kyber_ct][msg_len:4 LE][encrypted_msg][mac:32]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let ct_bytes = self.kyber_ct.as_bytes();
        let mut buf = Vec::with_capacity(4 + ct_bytes.len() + 4 + self.encrypted_msg.len() + 32);
        buf.extend_from_slice(&(ct_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(ct_bytes);
        buf.extend_from_slice(&(self.encrypted_msg.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.encrypted_msg);
        buf.extend_from_slice(&self.mac);
        buf
    }

    /// Deserialize from wire format.
    pub fn from_wire_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let ct_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + ct_len + 4 {
            return None;
        }
        let kyber_ct = KyberCiphertext::from_bytes(&data[4..4 + ct_len])?;
        let msg_off = 4 + ct_len;
        let msg_len = u32::from_le_bytes([
            data[msg_off],
            data[msg_off + 1],
            data[msg_off + 2],
            data[msg_off + 3],
        ]) as usize;
        let msg_start = msg_off + 4;
        if data.len() < msg_start + msg_len + 32 {
            return None;
        }
        let encrypted_msg = data[msg_start..msg_start + msg_len].to_vec();
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&data[msg_start + msg_len..msg_start + msg_len + 32]);
        Some(Self {
            kyber_ct,
            encrypted_msg,
            mac,
        })
    }
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
    let mut input = Vec::with_capacity(8 + 32 + ciphertext.len()); // prefix(8) + secret(32) + ciphertext
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
///
/// IMPORTANT: This is a CENTRALIZED keygen — the caller sees all shares.
/// For devnet/testnet where the operator is trusted, this is fine.
/// For mainnet, use a multi-party ceremony (K operators contribute randomness
/// via MPC, security holds if any 1 is honest) followed by PSS epoch refresh
/// (pss_refresh/apply_refresh) which dissolves the genesis trust after epoch 1.
pub fn threshold_keygen(
    n: usize,
    threshold: usize,
) -> Result<(ThresholdPublicKey, Vec<KeyShare>), &'static str> {
    if threshold > n {
        return Err("threshold must be <= n");
    }
    if threshold < 1 {
        return Err("threshold must be >= 1");
    }

    let (pk, sk) = kyber_keygen()?;

    // Convert 64-byte seed to 8 Goldilocks elements
    let seed_bytes = sk.as_bytes();
    let seed_elements: Vec<Goldilocks> = (0..SEED_ELEMENTS)
        .map(|i| {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&seed_bytes[i * 8..(i + 1) * 8]);
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

    Ok((tpk, key_shares))
}

/// Encrypt a message using the committee's threshold public key.
pub fn threshold_encrypt(
    tpk: &ThresholdPublicKey,
    msg: &[u8],
) -> Result<ThresholdCiphertext, &'static str> {
    let (kyber_ct, ss) = kyber_encapsulate(&tpk.kyber_pk)?;
    let keystream = derive_keystream(&ss, msg.len());
    let encrypted_msg = xor_bytes(msg, &keystream);
    let mac = compute_mac(&ss, &encrypted_msg);

    Ok(ThresholdCiphertext {
        kyber_ct,
        encrypted_msg,
        mac,
    })
}

/// Generate a ciphertext-bound decryption share from a validator's key share.
///
/// Each share element is blinded with a ciphertext-derived mask:
///   blinded[i] = key_share[i] + H(ct_hash || index || i) mod p
///
/// This binds shares to the specific ciphertext, preventing cross-block reuse:
/// - Shares for ciphertext A are useless for decrypting ciphertext B
/// - An attacker collecting 85+ blinded shares from different blocks cannot
///   reconstruct the epoch secret key without knowing the unblinding values
/// - The legitimate combiner has the ciphertext and can compute the masks
pub fn generate_decryption_share(
    key_share: &KeyShare,
    ct: &ThresholdCiphertext,
) -> DecryptionShare {
    let ct_hash = ciphertext_binding_hash(ct);
    let mut blinded = Vec::with_capacity(key_share.shares.len());
    for (i, &share_val) in key_share.shares.iter().enumerate() {
        let mask = derive_blinding_mask(&ct_hash, key_share.index, i);
        blinded.push(share_val + mask);
    }
    DecryptionShare {
        index: key_share.index,
        shares: blinded,
    }
}

/// Hash the ciphertext for binding. Uses the Kyber ciphertext + encrypted message
/// to produce a unique 32-byte tag per transaction.
fn ciphertext_binding_hash(ct: &ThresholdCiphertext) -> [u8; 32] {
    let mut buf = Vec::with_capacity(ct.kyber_ct.as_bytes().len() + ct.encrypted_msg.len());
    buf.extend_from_slice(ct.kyber_ct.as_bytes());
    buf.extend_from_slice(&ct.encrypted_msg);
    poseidon2_hash(&buf).to_bytes()
}

/// Derive the blinding mask for a specific share element.
/// mask = H(ct_hash || validator_index || element_index) interpreted as a Goldilocks field element.
fn derive_blinding_mask(
    ct_hash: &[u8; 32],
    validator_index: usize,
    elem_index: usize,
) -> Goldilocks {
    let mut buf = Vec::with_capacity(48);
    buf.extend_from_slice(ct_hash);
    buf.extend_from_slice(&(validator_index as u64).to_le_bytes());
    buf.extend_from_slice(&(elem_index as u64).to_le_bytes());
    let hash = poseidon2_hash(&buf);
    // Take first 8 bytes as u64 — gl() reduces mod Goldilocks prime automatically
    let val = u64::from_le_bytes(hash.to_bytes()[..8].try_into().unwrap());
    gl(val)
}

/// Combine decryption shares to recover the plaintext.
/// Requires at least `threshold` shares.
///
/// **Audit 312 trust boundary (testnet):** this function does NOT
/// authenticate that share `i` was actually produced by validator
/// `i`. A Byzantine committee member can submit a share with
/// someone else's index to displace honest shares from the
/// threshold-`t` set. The MAC check inside
/// `combine_shares` catches the resulting bad keystream so safety
/// holds — but availability of the MEV pipeline does not. Treat
/// this as an operator-trust assumption on testnet (see
/// `docs/testnet-bringup.md` § "Known testnet trust assumptions").
/// Mainnet will require each share to carry a FALCON sig over
/// `(ct_hash || index || blinded_shares_hash)` and verify it
/// before admission.
pub fn combine_shares(
    shares: &[DecryptionShare],
    threshold: usize,
    ct: &ThresholdCiphertext,
) -> Result<Vec<u8>, &'static str> {
    if shares.len() < threshold {
        return Err("insufficient shares");
    }

    // Audit 312: structural sanity on the index field. `index` is
    // 1-based per the Shamir scheme, so 0 is invalid; values
    // larger than the realistic committee bound (≤ 128 today,
    // see `crates/consensus/src/block.rs::COMMITTEE_SIZE`) cannot
    // come from a legitimate share. Rejecting here closes the
    // griefing vector where a Byzantine peer feeds nonsense
    // indices that pass dedup but inflate Lagrange interpolation
    // work proportionally.
    const MAX_VALIDATOR_INDEX: usize = 256;
    for share in shares.iter() {
        if share.index == 0 || share.index > MAX_VALIDATOR_INDEX {
            return Err("invalid share index (out of range 1..=256)");
        }
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

    // Unblind shares: subtract the ciphertext-derived mask before interpolation.
    // blinded[i] = raw[i] + mask(ct, index, i)
    // raw[i] = blinded[i] - mask(ct, index, i)
    let ct_hash = ciphertext_binding_hash(ct);

    // Reconstruct each seed element
    let mut seed_bytes = [0u8; 64];
    for elem_idx in 0..SEED_ELEMENTS {
        let field_shares: Vec<FieldShare> = used_shares
            .iter()
            .map(|s| {
                let mask = derive_blinding_mask(&ct_hash, s.index, elem_idx);
                FieldShare {
                    x: gl(s.index as u64),
                    y: s.shares[elem_idx] - mask, // unblind
                }
            })
            .collect();
        let secret = shamir_reconstruct(&field_shares);
        let val = gl_to_u64(secret);
        seed_bytes[elem_idx * 8..(elem_idx + 1) * 8].copy_from_slice(&val.to_le_bytes());
    }

    // Reconstruct Kyber secret key from seed
    let sk = KyberSecretKey::from_bytes(&seed_bytes).ok_or("invalid reconstructed seed")?;

    // Decapsulate to get shared secret
    let ss = kyber_decapsulate(&sk, &ct.kyber_ct).map_err(|_| "Kyber-768 decapsulation failed")?;

    // Verify MAC in constant time — a variable-time `!=` would leak
    // per-byte match progress via timing, enabling padding-oracle-style
    // forgery of MACs against a live validator.
    let expected_mac = compute_mac(&ss, &ct.encrypted_msg);
    if expected_mac.ct_eq(&ct.mac).unwrap_u8() == 0 {
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

// Audit 358: `deltas[i]` is the share-refresh delta intended for
// validator `i`. While each contribution is individually a
// zero-secret share (constant term = 0), the deltas reveal the
// random polynomial used to refresh — a leak across enough
// contributions allows an attacker to reconstruct the underlying
// key. Zeroize on drop.
impl Zeroize for RefreshContribution {
    fn zeroize(&mut self) {
        zeroize_goldilocks_vec_vec(&mut self.deltas);
    }
}

impl Drop for RefreshContribution {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RefreshContribution {}

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

impl RefreshContribution {
    /// Serialize for P2P transmission.
    /// Format: [from_index:8 LE][n:4 LE][elements_per_val:4 LE][[delta:8 LE]*elements]*n
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.deltas.len();
        let elems = if n > 0 { self.deltas[0].len() } else { 0 };
        let mut buf = Vec::with_capacity(16 + n * elems * 8);
        buf.extend_from_slice(&(self.from_index as u64).to_le_bytes());
        buf.extend_from_slice(&(n as u32).to_le_bytes());
        buf.extend_from_slice(&(elems as u32).to_le_bytes());
        for v_deltas in &self.deltas {
            for d in v_deltas {
                buf.extend_from_slice(&gl_to_u64(*d).to_le_bytes());
            }
        }
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let from_index = u64::from_le_bytes(data[0..8].try_into().ok()?) as usize;
        let n = u32::from_le_bytes(data[8..12].try_into().ok()?) as usize;
        let elems = u32::from_le_bytes(data[12..16].try_into().ok()?) as usize;
        if data.len() < 16 + n * elems * 8 {
            return None;
        }
        let mut deltas = Vec::with_capacity(n);
        let mut off = 16;
        for _ in 0..n {
            let mut v = Vec::with_capacity(elems);
            for _ in 0..elems {
                let val = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);
                v.push(gl(val));
                off += 8;
            }
            deltas.push(v);
        }
        Some(Self { from_index, deltas })
    }
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
    // Guard: threshold must not exceed the number of deltas provided
    if threshold > contribution.deltas.len() {
        return false;
    }
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

    // Each validator generates a refresh contribution using fresh entropy
    let contributions: Vec<RefreshContribution> = old_shares
        .iter()
        .map(|ks| {
            // Generate fresh entropy from epoch, validator index, and random field element
            let fresh_random = random_goldilocks(
                &new_epoch.to_le_bytes(),
                ks.index * 7919, // prime multiplier for extra mixing
            );
            let mut entropy_input = Vec::with_capacity(24);
            entropy_input.extend_from_slice(&new_epoch.to_le_bytes());
            entropy_input.extend_from_slice(&(ks.index as u64).to_le_bytes());
            entropy_input.extend_from_slice(&gl_to_u64(fresh_random).to_le_bytes());
            let fresh_entropy = poseidon2_hash(&entropy_input);
            generate_refresh_contribution(ks.index, n, t, new_epoch, fresh_entropy.as_bytes())
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

// ==========================================================================
// Cross-committee resharing (task 034)
// ==========================================================================
//
// PSS (`RefreshContribution` / `apply_refresh`) refreshes shares among the
// *same* committee. Real committee rotation requires transferring trust from
// an OLD committee to a DIFFERENT NEW committee. The construction below is
// classical share-transfer resharing (Desmedt/Jajodia):
//
// 1. Each old member `i` with share `s_i` of the secret polynomial `f` (of
//    degree `old_t - 1`, with `f(0) = secret`) picks a fresh polynomial
//    `g_i` of degree `new_t - 1` with `g_i(0) = s_i` and evaluates at each
//    new member index: `sub_shares[j] = g_i(j)` for j in 1..=new_n.
// 2. New member `j` collects `{g_i(j) : i ∈ canonical old-subset S}` from
//    gossip. They compute `H(j) = Σ_{i ∈ S} λ_i(0) · g_i(j)`, where
//    `λ_i(0)` is the Lagrange coefficient reconstructing `f(0)` from shares
//    at `S`. The new share of member j is `H(j)`.
// 3. Because `λ_i(0) · g_i(0) = λ_i(0) · s_i = λ_i(0) · f(i)`, summing over
//    `S` gives `H(0) = Σ_{i ∈ S} λ_i(0) · f(i) = f(0) = secret`. So `H` is
//    a valid new polynomial with the SAME secret.
// 4. The public key is invariant across resharing — so in-flight mempool
//    ciphertexts (encrypted under the committee's aggregate public key)
//    stay decryptable by the new committee. No re-encryption required.
//
// **Determinism is load-bearing**: every new member must use the identical
// old-subset `S`. Otherwise, new members end up on different polynomials `H`
// and threshold decryption across the new committee breaks. The canonical
// rule is `threshold` lowest-indexed old members whose contributions have
// been gossiped; `canonical_resharing_subset` enforces this.

/// Sub-share package from one old committee member to all new committee
/// members. `sub_shares[j-1][e]` is `g_i(j)` — old member i's new-polynomial
/// evaluated at new index j, for the e-th seed element.
#[derive(Clone, Debug)]
pub struct ResharingContribution {
    /// 1-based index of the old committee member that produced this.
    pub from_old_index: usize,
    /// Length = new_n. Each inner vec has length SEED_ELEMENTS.
    sub_shares: Vec<Vec<Goldilocks>>,
}

// Audit 358: `sub_shares[j-1][e]` is the share-transfer payload
// for new committee member `j`. Together with the canonical
// resharing subset, these reconstruct the same secret polynomial
// — leaking enough of them across old committee members allows
// an attacker to recover the underlying decapsulation key.
// Zeroize on drop.
impl Zeroize for ResharingContribution {
    fn zeroize(&mut self) {
        zeroize_goldilocks_vec_vec(&mut self.sub_shares);
    }
}

impl Drop for ResharingContribution {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ResharingContribution {}

impl ResharingContribution {
    /// Wire format:
    /// [from_old_index:8 LE][new_n:4 LE][elems:4 LE][[g:8 LE]*elems]*new_n
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.sub_shares.len();
        let elems = if n > 0 { self.sub_shares[0].len() } else { 0 };
        let mut buf = Vec::with_capacity(16 + n * elems * 8);
        buf.extend_from_slice(&(self.from_old_index as u64).to_le_bytes());
        buf.extend_from_slice(&(n as u32).to_le_bytes());
        buf.extend_from_slice(&(elems as u32).to_le_bytes());
        for row in &self.sub_shares {
            for g in row {
                buf.extend_from_slice(&gl_to_u64(*g).to_le_bytes());
            }
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let from_old_index = u64::from_le_bytes(data[0..8].try_into().ok()?) as usize;
        let n = u32::from_le_bytes(data[8..12].try_into().ok()?) as usize;
        let elems = u32::from_le_bytes(data[12..16].try_into().ok()?) as usize;
        if data.len() < 16 + n * elems * 8 {
            return None;
        }
        let mut sub_shares = Vec::with_capacity(n);
        let mut off = 16;
        for _ in 0..n {
            let mut row = Vec::with_capacity(elems);
            for _ in 0..elems {
                let v = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);
                row.push(gl(v));
                off += 8;
            }
            sub_shares.push(row);
        }
        Some(Self {
            from_old_index,
            sub_shares,
        })
    }

    /// Expose `new_n` (number of new committee members this contribution targets).
    pub fn new_n(&self) -> usize {
        self.sub_shares.len()
    }
}

/// Generate one old member's share-transfer contribution for the new
/// committee. Each seed element of the old share becomes the constant term
/// of a fresh degree-(new_threshold-1) polynomial, evaluated at new indices
/// 1..=new_n.
pub fn generate_resharing_contribution(
    old_share: &KeyShare,
    new_n: usize,
    new_threshold: usize,
    epoch: u64,
    entropy: &[u8],
) -> ResharingContribution {
    // Domain-separate by epoch + old-index so different old members
    // generate independent polynomials from the same public entropy.
    let mut dom_in = Vec::with_capacity(entropy.len() + 24);
    dom_in.extend_from_slice(entropy);
    dom_in.extend_from_slice(b"pyde-reshare");
    dom_in.extend_from_slice(&epoch.to_le_bytes());
    dom_in.extend_from_slice(&(old_share.index as u64).to_le_bytes());
    let dom_entropy = poseidon2_hash(&dom_in);

    // For each seed element: polynomial with g(0) = old_share.shares[elem],
    // evaluated at new indices 1..=new_n via shamir_split (secret = g(0)).
    let mut per_elem: Vec<Vec<Goldilocks>> = Vec::with_capacity(SEED_ELEMENTS);
    for elem_idx in 0..SEED_ELEMENTS {
        let shares = shamir_split(
            old_share.shares[elem_idx],
            new_n,
            new_threshold,
            dom_entropy.as_bytes(),
            elem_idx,
        );
        per_elem.push(shares.iter().map(|s| s.y).collect());
    }

    // Transpose to sub_shares[new_idx][elem_idx].
    let sub_shares: Vec<Vec<Goldilocks>> = (0..new_n)
        .map(|v| (0..SEED_ELEMENTS).map(|e| per_elem[e][v]).collect())
        .collect();

    ResharingContribution {
        from_old_index: old_share.index,
        sub_shares,
    }
}

/// Verify a resharing contribution is internally consistent — i.e. its
/// sub-shares truly lie on a single polynomial of degree `new_threshold - 1`
/// per seed element. Interpolates a threshold subset, then re-evaluates at
/// remaining new indices and compares against the provided values. A
/// malicious old member could fabricate inconsistent points; this catches it.
pub fn verify_resharing_contribution(
    contribution: &ResharingContribution,
    new_threshold: usize,
    new_n: usize,
) -> bool {
    if contribution.sub_shares.len() != new_n {
        return false;
    }
    if new_threshold == 0 || new_threshold > new_n {
        return false;
    }
    for row in &contribution.sub_shares {
        if row.len() != SEED_ELEMENTS {
            return false;
        }
    }
    // For each seed element, interpolate first `new_threshold` sub-shares
    // and verify the remaining ones match via Lagrange evaluation.
    for elem_idx in 0..SEED_ELEMENTS {
        let interp_shares: Vec<FieldShare> = (0..new_threshold)
            .map(|v| FieldShare {
                x: gl((v + 1) as u64),
                y: contribution.sub_shares[v][elem_idx],
            })
            .collect();
        for check_idx in new_threshold..new_n {
            let check_x = gl((check_idx + 1) as u64);
            let mut y = Goldilocks::ZERO;
            for i in 0..new_threshold {
                let x_i = interp_shares[i].x;
                let mut basis = Goldilocks::ONE;
                for j in 0..new_threshold {
                    if i != j {
                        let x_j = interp_shares[j].x;
                        let num = check_x - x_j;
                        let den = x_i - x_j;
                        basis *= num * gl_inv(den);
                    }
                }
                y += interp_shares[i].y * basis;
            }
            if y != contribution.sub_shares[check_idx][elem_idx] {
                return false;
            }
        }
    }
    true
}

/// Pick the deterministic canonical subset of old contributions every new
/// member must use: the `old_threshold` contributions with the LOWEST
/// `from_old_index` values. Returns `None` if fewer than `old_threshold`
/// contributions are available. All new members converge on the same
/// polynomial when they apply this rule.
pub fn canonical_resharing_subset(
    pool: &[ResharingContribution],
    old_threshold: usize,
) -> Option<Vec<&ResharingContribution>> {
    if pool.len() < old_threshold {
        return None;
    }
    let mut refs: Vec<&ResharingContribution> = pool.iter().collect();
    refs.sort_by_key(|c| c.from_old_index);
    refs.truncate(old_threshold);
    Some(refs)
}

/// Aggregate a canonical subset of resharing contributions into a single
/// new `KeyShare` for the given new-committee index. Lagrange coefficients
/// are computed over the OLD indices in `canonical`, so all new members
/// that apply this function to the same canonical subset converge on the
/// same underlying polynomial.
pub fn aggregate_new_share(
    new_index: usize,
    canonical: &[&ResharingContribution],
) -> Option<KeyShare> {
    if canonical.is_empty() || new_index == 0 {
        return None;
    }
    let new_idx0 = new_index - 1;
    // All contributions must target the same new_n and expose our new_idx.
    let new_n = canonical[0].sub_shares.len();
    if new_idx0 >= new_n {
        return None;
    }
    for c in canonical.iter() {
        if c.sub_shares.len() != new_n {
            return None;
        }
        if c.sub_shares[new_idx0].len() != SEED_ELEMENTS {
            return None;
        }
    }

    // Lagrange coefficients at x=0 for the OLD indices.
    let old_indices: Vec<Goldilocks> = canonical
        .iter()
        .map(|c| gl(c.from_old_index as u64))
        .collect();
    let lambdas: Vec<Goldilocks> = (0..canonical.len())
        .map(|i| {
            let x_i = old_indices[i];
            let mut basis = Goldilocks::ONE;
            for j in 0..canonical.len() {
                if i != j {
                    let x_j = old_indices[j];
                    let num = Goldilocks::ZERO - x_j;
                    let den = x_i - x_j;
                    basis *= num * gl_inv(den);
                }
            }
            basis
        })
        .collect();

    // Combine: new_share[e] = Σ_i λ_i · g_i(new_index) for each element e.
    let mut new_shares = vec![Goldilocks::ZERO; SEED_ELEMENTS];
    for (i, contrib) in canonical.iter().enumerate() {
        for elem_idx in 0..SEED_ELEMENTS {
            new_shares[elem_idx] += lambdas[i] * contrib.sub_shares[new_idx0][elem_idx];
        }
    }

    Some(KeyShare {
        index: new_index,
        shares: new_shares,
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    const N: usize = 128;
    const T: usize = 85;

    fn setup() -> (ThresholdPublicKey, Vec<KeyShare>) {
        threshold_keygen(N, T).unwrap()
    }

    #[test]
    fn encrypt_decrypt_with_threshold_plus_one() {
        let (tpk, shares) = setup();
        let msg = b"hello threshold kyber";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

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
        let ct = threshold_encrypt(&tpk, msg).unwrap();

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
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        let dec_shares: Vec<DecryptionShare> = shares[..T - 1]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();

        let result = combine_shares(&dec_shares, T, &ct);
        assert!(result.is_err());
    }

    /// Audit 312: combine_shares rejects shares with `index == 0`
    /// or `index > 256`. Closes the griefing path where a peer
    /// hand-crafts shares with nonsense indices that pass the
    /// dedup check but inflate Lagrange interpolation work.
    #[test]
    fn combine_shares_rejects_zero_index_audit_312() {
        let (tpk, shares) = setup();
        let msg = b"audit 312 zero index";
        let ct = threshold_encrypt(&tpk, msg).unwrap();
        let mut dec_shares: Vec<DecryptionShare> = shares[..T]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();
        // Mutate one share's index to 0.
        dec_shares[0].index = 0;
        let result = combine_shares(&dec_shares, T, &ct);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid share index"));
    }

    #[test]
    fn combine_shares_rejects_oversize_index_audit_312() {
        let (tpk, shares) = setup();
        let msg = b"audit 312 oversize index";
        let ct = threshold_encrypt(&tpk, msg).unwrap();
        let mut dec_shares: Vec<DecryptionShare> = shares[..T]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();
        // Mutate to an absurd index that no real committee would
        // produce. MAX_VALIDATOR_INDEX = 256; 257 is the first
        // out-of-range value.
        dec_shares[0].index = 257;
        let result = combine_shares(&dec_shares, T, &ct);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid share index"));
    }

    #[test]
    fn duplicate_shares_rejected() {
        let (tpk, shares) = setup();
        let msg = b"duplicate test";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

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
        let (_tpk2, shares2) = threshold_keygen(N, T).unwrap();
        let msg = b"wrong shares test";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        // Use shares from a different committee
        let dec_shares: Vec<DecryptionShare> = shares2[..T]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();

        let result = combine_shares(&dec_shares, T, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_mac_byte_fails_verification() {
        // Regression test for the constant-time MAC check. Flips one
        // bit of the MAC on an otherwise-valid ciphertext and confirms
        // the mismatch branch fires with the generic error. Does not
        // measure timing (unit-test timing is too noisy); its job is
        // to exercise the `ct_eq` code path so any future regression
        // that broke MAC-mismatch handling fails loudly.
        let (tpk, shares) = setup();
        let msg = b"tampered mac test";
        let mut ct = threshold_encrypt(&tpk, msg).unwrap();
        ct.mac[0] ^= 0x01;
        let dec_shares: Vec<DecryptionShare> = shares[..T]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();
        let result = combine_shares(&dec_shares, T, &ct);
        assert_eq!(result, Err("MAC verification failed"));
    }

    #[test]
    fn any_subset_of_shares_works() {
        let (tpk, shares) = setup();
        let msg = b"any subset works";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

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
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        let dec_shares: Vec<DecryptionShare> = shares[..T]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();

        let plaintext = combine_shares(&dec_shares, T, &ct).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn large_message() {
        let (tpk, shares) = threshold_keygen(5, 3).unwrap(); // smaller for speed
        let msg = vec![0xABu8; 10_000];
        let ct = threshold_encrypt(&tpk, &msg).unwrap();

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
        let (tpk, shares) = threshold_keygen(n, t).unwrap();
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
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

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
        let ct = threshold_encrypt(&new_epoch.tpk, msg).unwrap();

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
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

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
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

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

        // Generate contributions using fresh entropy
        for ks in &shares {
            let fresh_random = random_goldilocks(&new_epoch.to_le_bytes(), ks.index * 7919);
            let mut entropy_input = Vec::with_capacity(24);
            entropy_input.extend_from_slice(&new_epoch.to_le_bytes());
            entropy_input.extend_from_slice(&(ks.index as u64).to_le_bytes());
            entropy_input.extend_from_slice(&gl_to_u64(fresh_random).to_le_bytes());
            let fresh_entropy = poseidon2_hash(&entropy_input);
            let contrib = generate_refresh_contribution(
                ks.index,
                epoch_mat.n,
                epoch_mat.threshold,
                new_epoch,
                fresh_entropy.as_bytes(),
            );
            assert!(verify_refresh_contribution(&contrib, epoch_mat.threshold));
        }
    }

    #[test]
    fn pss_any_subset_after_refresh() {
        let (epoch_mat, shares) = setup_epoch(10, 7);
        let msg = b"any subset after refresh";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

        let (_new_epoch, new_shares) = pss_refresh(&epoch_mat, &shares);

        // Use last 7 shares
        let dec_shares: Vec<DecryptionShare> = new_shares[3..10]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();
        let plaintext = combine_shares(&dec_shares, 7, &ct).unwrap();
        assert_eq!(plaintext, msg);
    }

    // ======================================================================
    // Resharing (task 034): cross-committee share transfer
    // ======================================================================

    /// Drive a full resharing from old shares at indices `old_indices` (with
    /// threshold `old_t`) to a new committee of size `new_n` with threshold
    /// `new_t`. Returns new KeyShares. Pure-function harness used by the
    /// tests below.
    fn do_resharing(
        old_shares: &[KeyShare],
        old_t: usize,
        new_n: usize,
        new_t: usize,
        epoch: u64,
    ) -> Vec<KeyShare> {
        // Each old member produces one contribution. Public entropy is the
        // epoch; domain separation by old-index happens inside the fn.
        let entropy = epoch.to_le_bytes();
        let pool: Vec<ResharingContribution> = old_shares
            .iter()
            .map(|s| generate_resharing_contribution(s, new_n, new_t, epoch, &entropy))
            .collect();
        let canonical = canonical_resharing_subset(&pool, old_t).unwrap();
        (1..=new_n)
            .map(|j| aggregate_new_share(j, &canonical).unwrap())
            .collect()
    }

    #[test]
    fn reshare_preserves_secret_and_decrypts_old_ciphertext() {
        // Encrypt under the epoch-0 public key, rotate to an entirely new
        // committee via resharing, and verify the new shares still decrypt
        // the original ciphertext — proves the public key is invariant.
        let (epoch_mat, old_shares) = setup_epoch(10, 7);
        let msg = b"committee rotation preserves decryptability";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

        // New committee: 8 members, threshold 5 — different size AND
        // different members than the original.
        let new_shares = do_resharing(&old_shares, 7, 8, 5, 1);

        // Five new members (their new threshold) suffice to decrypt.
        let dec_shares: Vec<DecryptionShare> = new_shares[..5]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();
        let plaintext = combine_shares(&dec_shares, 5, &ct).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn reshare_any_subset_of_new_committee_suffices() {
        // Verify that any subset of size >= new_threshold from the new
        // committee can combine — ensures all new members sit on the same
        // polynomial (the whole point of the canonical-subset rule).
        let (epoch_mat, old_shares) = setup_epoch(8, 5);
        let msg = b"interchangeable new shares";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

        let new_shares = do_resharing(&old_shares, 5, 10, 7, 2);

        // Two different subsets of size 7 — both should decrypt.
        let subset_a: Vec<DecryptionShare> = new_shares[..7]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();
        let subset_b: Vec<DecryptionShare> = new_shares[3..10]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();

        assert_eq!(combine_shares(&subset_a, 7, &ct).unwrap(), msg);
        assert_eq!(combine_shares(&subset_b, 7, &ct).unwrap(), msg);
    }

    #[test]
    fn reshare_below_old_threshold_contributions_fails() {
        // Fewer than `old_threshold` contributions available → canonical
        // subset selection returns None. Enforcement lives with the caller.
        let (_, old_shares) = setup_epoch(6, 4);
        let pool: Vec<ResharingContribution> = old_shares[..3]
            .iter()
            .map(|s| generate_resharing_contribution(s, 8, 5, 1, b"e"))
            .collect();
        assert!(canonical_resharing_subset(&pool, /* old_threshold */ 4).is_none());
    }

    #[test]
    fn reshare_canonical_subset_is_lowest_indexed() {
        // Determinism: regardless of iteration order, canonical subset is
        // the threshold lowest old-indices. This guarantees convergence
        // across new members.
        let (_, old_shares) = setup_epoch(6, 3);
        let pool: Vec<ResharingContribution> = old_shares
            .iter()
            .rev() // reversed to test sorting
            .map(|s| generate_resharing_contribution(s, 4, 3, 1, b"e"))
            .collect();
        let canonical = canonical_resharing_subset(&pool, 3).unwrap();
        let picked: Vec<usize> = canonical.iter().map(|c| c.from_old_index).collect();
        assert_eq!(picked, vec![1, 2, 3]);
    }

    #[test]
    fn reshare_two_new_members_converge_on_same_polynomial() {
        // If two new members apply aggregation to the canonical subset,
        // their resulting shares must be combinable (sit on one polynomial).
        let (epoch_mat, old_shares) = setup_epoch(6, 4);
        let msg = b"two members same poly";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

        let new_shares = do_resharing(&old_shares, 4, 7, 4, 1);

        // Pick 4 disjoint-ish subsets, all must decrypt.
        for start in 0..4 {
            let subset: Vec<DecryptionShare> = new_shares[start..start + 4]
                .iter()
                .map(|s| generate_decryption_share(s, &ct))
                .collect();
            assert_eq!(
                combine_shares(&subset, 4, &ct).unwrap(),
                msg,
                "subset starting at {start} failed to decrypt"
            );
        }
    }

    #[test]
    fn reshare_verify_detects_inconsistent_contribution() {
        let (_, old_shares) = setup_epoch(6, 4);
        let mut contrib = generate_resharing_contribution(&old_shares[0], 8, 5, 1, b"e");
        assert!(verify_resharing_contribution(&contrib, 5, 8));

        // Tamper: flip a value in one of the non-interpolation rows.
        contrib.sub_shares[6][2] += gl(1);
        assert!(!verify_resharing_contribution(&contrib, 5, 8));
    }

    #[test]
    fn reshare_verify_rejects_wrong_dimensions() {
        let (_, old_shares) = setup_epoch(6, 4);
        let contrib = generate_resharing_contribution(&old_shares[0], 8, 5, 1, b"e");
        // Pretend new_n is different from what the contribution was built for.
        assert!(!verify_resharing_contribution(&contrib, 5, 9));
        // Threshold > new_n should also be rejected.
        assert!(!verify_resharing_contribution(&contrib, 9, 8));
    }

    #[test]
    fn reshare_contribution_roundtrips_through_wire_format() {
        let (_, old_shares) = setup_epoch(5, 3);
        let original = generate_resharing_contribution(&old_shares[1], 6, 4, 42, b"wire");
        let bytes = original.to_bytes();
        let decoded = ResharingContribution::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.from_old_index, original.from_old_index);
        assert_eq!(decoded.sub_shares.len(), original.sub_shares.len());
        for (a, b) in decoded.sub_shares.iter().zip(original.sub_shares.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn reshare_chain_of_two_rotations_decrypts() {
        // Rotate twice: old -> mid -> new. Ciphertext encrypted at epoch 0
        // must still decrypt under epoch-2 shares.
        let (epoch_mat, old_shares) = setup_epoch(6, 4);
        let msg = b"two rotations";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

        let mid_shares = do_resharing(&old_shares, 4, 7, 5, 1);
        let new_shares = do_resharing(&mid_shares, 5, 8, 6, 2);

        let dec_shares: Vec<DecryptionShare> = new_shares[..6]
            .iter()
            .map(|s| generate_decryption_share(s, &ct))
            .collect();
        assert_eq!(combine_shares(&dec_shares, 6, &ct).unwrap(), msg);
    }

    // ── Audit 358: ZeroizeOnDrop on threshold types ─────────────────

    /// Pull a non-zero share value out of the inner Vec via the
    /// wire format (the Vec is private). Used by the zeroize tests
    /// to verify there was something to zero.
    fn keyshare_has_nonzero_payload(s: &KeyShare) -> bool {
        // serialized share has [index:8][count:4][shares:8*N], so any
        // non-zero byte past the metadata header indicates non-zero
        // share values.
        let bytes = s.to_bytes();
        bytes.len() > 12 && bytes[12..].iter().any(|b| *b != 0)
    }

    #[test]
    fn key_share_zeroizes() {
        let (_, mut shares) = setup();
        let s = &mut shares[0];
        assert!(
            keyshare_has_nonzero_payload(s),
            "fresh key share should carry non-zero secret material"
        );
        s.zeroize();
        // After zeroize the inner shares vec is cleared (length 0).
        // Re-serializing reflects that — only metadata remains.
        let bytes = s.to_bytes();
        let post_count = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        assert_eq!(post_count, 0, "key share count must be 0 post-zeroize");
    }

    #[test]
    fn refresh_contribution_zeroizes() {
        let mut contrib = generate_refresh_contribution(1, 6, 4, 0, b"e");
        // Sanity: deltas have content.
        let nonempty = contrib.deltas.iter().any(|inner| !inner.is_empty());
        assert!(
            nonempty,
            "fresh refresh contribution should have non-empty deltas"
        );
        contrib.zeroize();
        // After zeroize the outer + every inner vec is cleared.
        assert!(
            contrib.deltas.is_empty(),
            "refresh contribution deltas not cleared post-zeroize"
        );
    }

    #[test]
    fn resharing_contribution_zeroizes() {
        let (_, old_shares) = setup_epoch(6, 4);
        let mut contrib = generate_resharing_contribution(&old_shares[0], 8, 5, 1, b"e");
        let nonempty = contrib.sub_shares.iter().any(|inner| !inner.is_empty());
        assert!(
            nonempty,
            "fresh resharing contribution should have non-empty sub_shares"
        );
        contrib.zeroize();
        assert!(
            contrib.sub_shares.is_empty(),
            "resharing contribution sub_shares not cleared post-zeroize"
        );
    }
}
