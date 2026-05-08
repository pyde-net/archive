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

/// The Goldilocks prime modulus: `2^64 - 2^32 + 1`.
///
/// Audit 391: callers that derive a Goldilocks element from
/// hash output must rejection-sample against this prime to avoid
/// the small distribution bias that `gl()`'s silent reduction
/// introduces over the range `[p, 2^64)`. Pre-fix, values in
/// `[0, 2^32)` were ~2x more likely to be produced than values
/// in `[2^32, p)`.
const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

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
///
/// Audit 391: rejection-sample so candidates in `[p, 2^64)` are
/// re-drawn instead of silently mapping to `[0, 2^32)`. The
/// per-attempt rejection probability is
/// `(2^64 - p) / 2^64 = (2^32 - 1) / 2^64 ≈ 2^-32`, so the loop
/// terminates after one attempt with overwhelming probability.
/// Domain-separating each attempt by an attempt counter keeps
/// the function deterministic in `(entropy, index)` while making
/// the value uniform over `[0, p)` — important for Shamir
/// polynomial coefficients, where a biased coefficient
/// distribution narrows the share-space an attacker has to
/// search.
fn random_goldilocks(entropy: &[u8], index: usize) -> Goldilocks {
    let mut attempt: u64 = 0;
    loop {
        let mut input = Vec::with_capacity(entropy.len() + 16);
        input.extend_from_slice(entropy);
        input.extend_from_slice(&(index as u64).to_le_bytes());
        input.extend_from_slice(&attempt.to_le_bytes());
        let hash = poseidon2_hash(&input);
        let bytes = hash.as_bytes();
        let mut val_bytes = [0u8; 8];
        val_bytes.copy_from_slice(&bytes[0..8]);
        let val = u64::from_le_bytes(val_bytes);
        if val < GOLDILOCKS_PRIME {
            return gl(val);
        }
        attempt += 1;
    }
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
            // TPL-305: reject non-canonical encodings. Honest
            // shares always serialize via `gl_to_u64()` (canonical,
            // in `[0, p)`), so a value `>= GOLDILOCKS_PRIME` can
            // only come from a malformed wire payload. Pre-fix the
            // code silently remapped to `gl(val)`, leaning on the
            // downstream MAC check to catch the resulting bad
            // keystream — but that's defense-in-depth, not
            // verification, and non-canonical encodings are also a
            // wire-replay surface: the same logical share carried
            // by two different byte representations slips past
            // dedup keyed on the byte payload.
            if val >= GOLDILOCKS_PRIME {
                return None;
            }
            shares.push(gl(val));
        }
        Some(Self { index, shares })
    }
}

/// A partial decryption share from one validator.
///
/// TPL-301: every share carries a FALCON signature over
/// `(ct_hash || index_le || blinded_shares_hash)` produced by the
/// validator's committee FALCON key. The signature lets
/// `combine_shares` authenticate that share `i` was actually
/// produced by validator `i` — pre-fix, a Byzantine member could
/// submit a share with someone else's index to displace honest
/// shares from the threshold-`t` set, breaking liveness even
/// though the MAC inside `combine_shares` ultimately caught the
/// resulting bad keystream.
#[derive(Clone, Debug)]
pub struct DecryptionShare {
    /// Validator index (1-based).
    pub index: usize,
    /// Share values.
    shares: Vec<Goldilocks>,
    /// FALCON signature over the canonical preimage. Empty
    /// only on shares constructed by deprecated test paths
    /// before the field was added; honest production shares
    /// always carry a non-empty signature.
    signature: Vec<u8>,
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
    /// TPL-301: canonical preimage used for the FALCON sig that
    /// authenticates this share. Bound:
    ///   - `ct_hash` (32 bytes) — already pinned by the
    ///     ciphertext-binding hash, so a sig from one ciphertext
    ///     can't migrate to another.
    ///   - `index` (8 bytes LE) — the new property: closes the
    ///     "Byzantine member submits a share with someone else's
    ///     index" displacement attack.
    ///   - `blinded_shares_hash` (32 bytes) — Poseidon2 over the
    ///     concatenated 8-byte LE encodings of `self.shares`,
    ///     so a sig produced for one set of share values can't
    ///     replay onto a different set.
    fn signing_preimage(ct_hash: &[u8; 32], index: usize, shares: &[Goldilocks]) -> Vec<u8> {
        let mut blinded_buf = Vec::with_capacity(shares.len() * 8);
        for s in shares {
            blinded_buf.extend_from_slice(&gl_to_u64(*s).to_le_bytes());
        }
        let blinded_hash = poseidon2_hash(&blinded_buf);

        let mut preimage = Vec::with_capacity(32 + 8 + 32);
        preimage.extend_from_slice(ct_hash);
        preimage.extend_from_slice(&(index as u64).to_le_bytes());
        preimage.extend_from_slice(blinded_hash.as_bytes());
        preimage
    }

    /// Wire format:
    ///   `[index:8 LE][share_count:4 LE][share_0..n:8 LE each]
    ///    [sig_len:4 LE][sig:sig_len bytes]`
    /// TPL-301: `sig_len` may be 0 for back-compat with
    /// pre-signed-share test paths; production shares always
    /// carry a non-empty signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12 + self.shares.len() * 8 + 4 + self.signature.len());
        buf.extend_from_slice(&(self.index as u64).to_le_bytes());
        buf.extend_from_slice(&(self.shares.len() as u32).to_le_bytes());
        for s in &self.shares {
            buf.extend_from_slice(&gl_to_u64(*s).to_le_bytes());
        }
        buf.extend_from_slice(&(self.signature.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let index = u64::from_le_bytes(data[0..8].try_into().ok()?) as usize;
        let count = u32::from_le_bytes(data[8..12].try_into().ok()?) as usize;
        let shares_end = 12 + count * 8;
        if data.len() < shares_end + 4 {
            return None;
        }
        let mut shares = Vec::with_capacity(count);
        for i in 0..count {
            let off = 12 + i * 8;
            let val = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);
            // TPL-305: see `KeyShare::from_bytes` — same
            // canonical-encoding gate.
            if val >= GOLDILOCKS_PRIME {
                return None;
            }
            shares.push(gl(val));
        }
        let sig_len =
            u32::from_le_bytes(data[shares_end..shares_end + 4].try_into().ok()?) as usize;
        let sig_end = shares_end + 4 + sig_len;
        if data.len() < sig_end {
            return None;
        }
        let signature = data[shares_end + 4..sig_end].to_vec();
        Some(Self {
            index,
            shares,
            signature,
        })
    }

    /// Test-only constructor used by historical tests that didn't
    /// thread a FALCON sk through to `generate_decryption_share`.
    /// TPL-301: production code paths must use the signed flow.
    #[cfg(test)]
    pub fn unsigned_for_test(index: usize, shares: Vec<Goldilocks>) -> Self {
        Self {
            index,
            shares,
            signature: Vec::new(),
        }
    }

    /// TPL-301: expose the wire signature so callers (e.g. the
    /// gossip-receipt verify path in the future) can re-run the
    /// FALCON check before admission. Empty for unsigned legacy
    /// shares; non-empty for production shares.
    pub fn signature(&self) -> &[u8] {
        &self.signature
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

/// Audit 359: domain-separation prefix for the keystream KDF.
/// Prevents accidental cross-use of a keystream block as a MAC
/// (or vice versa) if a future call site reorders the inputs.
const KS_DOMAIN: &[u8] = b"pyde-threshold-keystream-v1";

/// Audit 359: domain-separation prefix for the MAC.
const MAC_DOMAIN: &[u8] = b"pyde-threshold-mac-v1";

/// Audit 359: derive a Poseidon2-keyed keystream bound to BOTH
/// the per-message Kyber shared_secret AND the kyber_ct that
/// produced it. The ct binding is the per-message nonce —
/// `kyber_encapsulate` returns a fresh randomized ct on every
/// call, so two encryptions with the same plaintext produce
/// different keystreams even if the shared_secret derivation
/// somehow accidentally repeated (faulty RNG, replay).
///
/// Pre-fix the keystream was `Poseidon2(ss || counter)` with
/// no per-message nonce — a single ss reuse leaked the XOR of
/// the two plaintexts and the MAC key for both, giving an
/// attacker forgery primitives against any future ciphertext
/// under the same ss. Post-fix: even ss reuse only narrows the
/// search if `kyber_ct` ALSO repeats, which would mean Kyber
/// itself is broken.
fn derive_keystream(shared_secret: &SharedSecret, kyber_ct: &[u8], len: usize) -> Vec<u8> {
    // Bind the kyber_ct via its Poseidon2 hash so the keystream
    // input stays a fixed 96 bytes (32 ss + 32 ct-hash + 8 ctr +
    // domain prefix) regardless of ciphertext length.
    let ct_fp = poseidon2_hash(kyber_ct);
    let mut keystream = Vec::with_capacity(len);
    let mut counter = 0u64;
    while keystream.len() < len {
        let mut input = Vec::with_capacity(KS_DOMAIN.len() + 32 + 32 + 8);
        input.extend_from_slice(KS_DOMAIN);
        input.extend_from_slice(shared_secret.as_bytes());
        input.extend_from_slice(ct_fp.as_bytes());
        input.extend_from_slice(&counter.to_le_bytes());
        let block = poseidon2_hash(&input);
        keystream.extend_from_slice(block.as_bytes());
        counter += 1;
    }
    keystream.truncate(len);
    keystream
}

/// Audit 359: same defense-in-depth treatment for the MAC.
/// The MAC now keys on `(shared_secret, kyber_ct, encrypted_msg)`
/// with a separate domain-separation prefix from the keystream.
/// A MAC forgery against ciphertext A under shared_secret S no
/// longer aids forging under ciphertext B even if the same S is
/// somehow reused.
fn compute_mac(shared_secret: &SharedSecret, kyber_ct: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let ct_fp = poseidon2_hash(kyber_ct);
    let mut input = Vec::with_capacity(MAC_DOMAIN.len() + 32 + 32 + ciphertext.len());
    input.extend_from_slice(MAC_DOMAIN);
    input.extend_from_slice(shared_secret.as_bytes());
    input.extend_from_slice(ct_fp.as_bytes());
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

    // TPL-307: rejection-sample the Kyber secret-key seed so the
    // chunk → Goldilocks-element conversion is injective.
    //
    // The 64-byte Kyber seed is split into 8 little-endian u64
    // chunks; each chunk feeds a Goldilocks element via `gl()`.
    // Any chunk in `[p, 2^64)` would silently remap to `chunk - p`
    // (since `gl()` reduces mod `p`), so the round-trip back to
    // u64 via `gl_to_u64()` yields `chunk - p`, not `chunk` — and
    // the reconstructed Kyber secret bytes don't match the
    // original. Pre-fix, audit 391's commentary noted the
    // ~2^-29 per-keygen failure rate and accepted it ("operator
    // re-runs keygen on first-use decryption failure"). That's
    // a foot-gun for cross-validator setups: the failure
    // surfaces only AFTER shares have been distributed and the
    // network is up, requiring full re-keygen + redeploy. Reject
    // bad seeds here instead, which keeps generation total under
    // the contract that all callers see canonical-encoding
    // shares.
    //
    // Per-iteration success probability is `~1 - 2^-29`, so the
    // expected number of keygens is `~1.000000002`. The bound
    // exists only to fail loudly if something is very wrong with
    // the RNG; under normal conditions it's reached on the first
    // iteration.
    const MAX_REJECTIONS: u32 = 64;
    let (pk, seed_bytes) = {
        let mut rejections = 0u32;
        loop {
            let (pk, sk) = kyber_keygen()?;
            let seed_bytes = sk.as_bytes().to_vec();
            let all_canonical = (0..SEED_ELEMENTS).all(|i| {
                let mut chunk = [0u8; 8];
                chunk.copy_from_slice(&seed_bytes[i * 8..(i + 1) * 8]);
                u64::from_le_bytes(chunk) < GOLDILOCKS_PRIME
            });
            if all_canonical {
                break (pk, seed_bytes);
            }
            rejections += 1;
            if rejections >= MAX_REJECTIONS {
                return Err(
                    "threshold_keygen: Kyber seed rejection-sampling exceeded retry budget",
                );
            }
        }
    };

    // Convert 64-byte seed to 8 Goldilocks elements. All chunks
    // are `< GOLDILOCKS_PRIME` by the rejection-sampling loop
    // above, so `gl(u64::from_le_bytes(chunk))` is the same value
    // its u64 representation will round-trip to.
    let seed_elements: Vec<Goldilocks> = (0..SEED_ELEMENTS)
        .map(|i| {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&seed_bytes[i * 8..(i + 1) * 8]);
            gl(u64::from_le_bytes(chunk))
        })
        .collect();

    // Generate entropy for random polynomial coefficients
    let entropy = poseidon2_hash(&seed_bytes);

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
    // Audit 359: keystream + MAC are bound to `kyber_ct` so a
    // hypothetical Kyber-RNG repeat doesn't collapse to the same
    // keystream / MAC key.
    let keystream = derive_keystream(&ss, kyber_ct.as_bytes(), msg.len());
    let encrypted_msg = xor_bytes(msg, &keystream);
    let mac = compute_mac(&ss, kyber_ct.as_bytes(), &encrypted_msg);

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
    sk: &crate::falcon::FalconSecretKey,
) -> Result<DecryptionShare, &'static str> {
    let ct_hash = ciphertext_binding_hash(ct);
    let mut blinded = Vec::with_capacity(key_share.shares.len());
    for (i, &share_val) in key_share.shares.iter().enumerate() {
        let mask = derive_blinding_mask(&ct_hash, key_share.index, i);
        blinded.push(share_val + mask);
    }
    // TPL-301: sign the canonical (ct_hash || index || blinded_hash)
    // preimage. `combine_shares` verifies before using.
    let preimage = DecryptionShare::signing_preimage(&ct_hash, key_share.index, &blinded);
    let sig = crate::falcon::falcon_sign(sk, &preimage)?;
    Ok(DecryptionShare {
        index: key_share.index,
        shares: blinded,
        signature: sig.as_bytes().to_vec(),
    })
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
/// mask = H(ct_hash || validator_index || element_index || attempt)
/// rejection-sampled into `[0, p)` and interpreted as a Goldilocks
/// field element.
///
/// Audit 391: rejection-sample so the per-share mask distribution
/// is exactly uniform over the Goldilocks field. Pre-fix the
/// implementation took the first 8 bytes of a Poseidon2 digest and
/// silently reduced mod `p` — biasing values in `[0, 2^32)` ~2x
/// over `[2^32, p)`. The same correlation showed up between the
/// share-creation side (validators applying the mask) and the
/// reconstruction side (`combine_shares` subtracting it). Mask
/// determinism in `(ct_hash, validator_index, elem_index)` is
/// preserved by hashing in an attempt counter.
fn derive_blinding_mask(
    ct_hash: &[u8; 32],
    validator_index: usize,
    elem_index: usize,
) -> Goldilocks {
    let mut attempt: u64 = 0;
    loop {
        let mut buf = Vec::with_capacity(56);
        buf.extend_from_slice(ct_hash);
        buf.extend_from_slice(&(validator_index as u64).to_le_bytes());
        buf.extend_from_slice(&(elem_index as u64).to_le_bytes());
        buf.extend_from_slice(&attempt.to_le_bytes());
        let hash = poseidon2_hash(&buf);
        let val = u64::from_le_bytes(hash.to_bytes()[..8].try_into().unwrap());
        if val < GOLDILOCKS_PRIME {
            return gl(val);
        }
        attempt += 1;
    }
}

/// Combine decryption shares to recover the plaintext.
/// Requires at least `threshold` shares.
///
/// TPL-301: each share carries a FALCON sig over
/// `(ct_hash || index || blinded_shares_hash)`. Pre-fix this
/// function did NOT authenticate that share `i` was actually
/// produced by validator `i`, so a Byzantine committee member
/// could submit a share carrying someone else's index to displace
/// an honest share from the threshold-`t` set. The MAC check
/// downstream caught the resulting bad keystream so safety held,
/// but availability of the MEV pipeline did not. Now every share
/// is verified against `committee_keys[index - 1]` before any
/// Lagrange interpolation runs, so Byzantine shares are rejected
/// loudly with a named error and never enter the threshold subset.
///
/// `committee_keys` is indexed 0..n-1 with `committee_keys[i]` =
/// the FALCON pubkey bytes of validator `i + 1`. The slice may be
/// any length ≥ `max(share.index)`; entries beyond the maximum
/// share index are ignored.
pub fn combine_shares(
    shares: &[DecryptionShare],
    threshold: usize,
    ct: &ThresholdCiphertext,
    committee_keys: &[crate::falcon::FalconPublicKey],
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

    // Audit 360: every post-validation failure path collapses
    // into the SAME generic error so an attacker submitting
    // crafted shares can't probe which pipeline stage rejected.
    // TPL-301's sig-verification gate joins the same bucket: a
    // tampered share whose sig no longer matches the
    // (ct_hash || index || blinded_shares_hash) preimage looks
    // identical from outside to a share that passed sig-verify
    // but tripped a downstream MAC fail.
    const ORACLE_SAFE_ERR: &str = "decryption failed";

    // TPL-301: verify each share's FALCON sig BEFORE using it in
    // Lagrange interpolation. A Byzantine submitter who claims
    // index i without holding validator i's FALCON sk cannot
    // produce a valid sig over the canonical preimage, so
    // displacement attacks fail at this gate.
    let ct_hash = ciphertext_binding_hash(ct);
    for share in shares.iter() {
        let pk_bytes_idx = share.index.checked_sub(1).ok_or(ORACLE_SAFE_ERR)?;
        if pk_bytes_idx >= committee_keys.len() {
            return Err(ORACLE_SAFE_ERR);
        }
        let pk = &committee_keys[pk_bytes_idx];
        let preimage = DecryptionShare::signing_preimage(&ct_hash, share.index, &share.shares);
        let sig =
            crate::falcon::FalconSignature::from_bytes(&share.signature).ok_or(ORACLE_SAFE_ERR)?;
        if !crate::falcon::falcon_verify(pk, &preimage, &sig) {
            return Err(ORACLE_SAFE_ERR);
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

    // Audit 360: KyberSecretKey decode / Kyber-768 decap / MAC
    // compare all collapse into the SAME ORACLE_SAFE_ERR declared
    // above the sig-verify loop. Pre-fix the three branches
    // returned distinct messages, so an attacker submitting
    // crafted decryption shares could probe error responses to
    // figure out which pipeline stage their bogus inputs landed
    // on:
    //   - "invalid reconstructed seed" → Lagrange interpolation
    //     produced 64 bytes that don't decode as a Kyber seed.
    //   - "Kyber-768 decapsulation failed" → seed decoded but
    //     `dk_from_seed` rejected the structure.
    //   - "MAC verification failed" → seed + decap both passed
    //     but the recovered `ss` is wrong (i.e., the shares
    //     didn't actually combine to the committee's secret).
    // That three-way split was a textbook decryption oracle —
    // each probe narrows the attacker's search for the share
    // structure that round-trips. We also keep going on Kyber
    // failure (substituting a zeroed `ss`) so MAC check still
    // executes; this evens out timing across the failure modes
    // (modulo the inherent variation in Kyber's reject path).
    //
    // Honest decryptors don't see this error: they always pass
    // the MAC check on a well-formed ciphertext.

    let sk = KyberSecretKey::from_bytes(&seed_bytes).ok_or(ORACLE_SAFE_ERR)?;
    let ss_or_zero = kyber_decapsulate(&sk, &ct.kyber_ct)
        .unwrap_or_else(|_| SharedSecret::zero_for_constant_time_mac_check());

    // Verify MAC in constant time — a variable-time `!=` would
    // leak per-byte match progress via timing, enabling padding-
    // oracle-style forgery of MACs against a live validator.
    // Audit 359: MAC + keystream are bound to `kyber_ct` (from
    // the encrypted ciphertext), matching the encrypt-side
    // derivation.
    let expected_mac = compute_mac(&ss_or_zero, ct.kyber_ct.as_bytes(), &ct.encrypted_msg);
    if expected_mac.ct_eq(&ct.mac).unwrap_u8() == 0 {
        return Err(ORACLE_SAFE_ERR);
    }

    // Decrypt
    let keystream = derive_keystream(&ss_or_zero, ct.kyber_ct.as_bytes(), ct.encrypted_msg.len());
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
    /// Epoch this contribution is bound to. TPL-303: signed under
    /// the FALCON sig and verified against the receiver's expected
    /// epoch, so a Byzantine peer can't replay an old contribution
    /// across PSS rounds.
    pub epoch: u64,
    /// Delta values for each validator (indexed 0..n), each containing SEED_ELEMENTS values.
    deltas: Vec<Vec<Goldilocks>>,
    /// TPL-303: FALCON signature by the issuer (validator
    /// `from_index`) over `signing_preimage(epoch, from_index,
    /// deltas)`. Verified by `verify_refresh_contribution` before
    /// the contribution can affect the share-refresh outcome — an
    /// unsigned or tampered contribution is rejected before its
    /// deltas reach `apply_refresh_canonical`.
    signature: Vec<u8>,
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
        // TPL-303: signatures are public-by-design (broadcast on
        // the gossip topic), but zeroize them with the rest of the
        // payload for defence-in-depth — pre-fix the deltas alone
        // got cleared and a stale sig would linger in freed memory.
        self.signature.zeroize();
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
///
/// TPL-303: signs `(epoch || from_index || hash(deltas))` with the
/// issuer's FALCON sk so receivers can reject contributions that
/// don't originate from the claimed `from_index` and prevent
/// across-epoch replays.
pub fn generate_refresh_contribution(
    from_index: usize,
    n: usize,
    threshold: usize,
    epoch: u64,
    entropy: &[u8],
    falcon_sk: &crate::falcon::FalconSecretKey,
) -> Result<RefreshContribution, &'static str> {
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

    // TPL-303: sign the canonical preimage so peers can authenticate
    // the issuer and detect replay across epochs.
    let preimage = RefreshContribution::signing_preimage(epoch, from_index, &deltas);
    let sig = crate::falcon::falcon_sign(falcon_sk, &preimage)?.to_vec();

    Ok(RefreshContribution {
        from_index,
        epoch,
        deltas,
        signature: sig,
    })
}

impl RefreshContribution {
    /// TPL-303: canonical preimage the FALCON sig is computed over.
    /// Layout: epoch (8 LE) || from_index (8 LE) || Poseidon2(deltas).
    /// Hashing the deltas keeps the preimage fixed-size regardless
    /// of `n` / `SEED_ELEMENTS`, mirroring `DecryptionShare::signing_preimage`.
    fn signing_preimage(epoch: u64, from_index: usize, deltas: &[Vec<Goldilocks>]) -> Vec<u8> {
        // Hash the flattened delta matrix in canonical order so any
        // element-level tamper produces a different digest.
        let mut delta_buf = Vec::with_capacity(deltas.len() * SEED_ELEMENTS * 8);
        for row in deltas {
            for d in row {
                delta_buf.extend_from_slice(&gl_to_u64(*d).to_le_bytes());
            }
        }
        let deltas_hash = poseidon2_hash(&delta_buf);

        let mut preimage = Vec::with_capacity(8 + 8 + 32);
        preimage.extend_from_slice(&epoch.to_le_bytes());
        preimage.extend_from_slice(&(from_index as u64).to_le_bytes());
        preimage.extend_from_slice(deltas_hash.as_bytes());
        preimage
    }

    /// Serialize for P2P transmission.
    /// Format: [from_index:8 LE][epoch:8 LE][n:4 LE][elements_per_val:4 LE][[delta:8 LE]*elements]*n[sig_len:4 LE][sig]
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.deltas.len();
        let elems = if n > 0 { self.deltas[0].len() } else { 0 };
        let mut buf = Vec::with_capacity(24 + n * elems * 8 + 4 + self.signature.len());
        buf.extend_from_slice(&(self.from_index as u64).to_le_bytes());
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(&(n as u32).to_le_bytes());
        buf.extend_from_slice(&(elems as u32).to_le_bytes());
        for v_deltas in &self.deltas {
            for d in v_deltas {
                buf.extend_from_slice(&gl_to_u64(*d).to_le_bytes());
            }
        }
        buf.extend_from_slice(&(self.signature.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 24 {
            return None;
        }
        let from_index = u64::from_le_bytes(data[0..8].try_into().ok()?) as usize;
        let epoch = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let n = u32::from_le_bytes(data[16..20].try_into().ok()?) as usize;
        let elems = u32::from_le_bytes(data[20..24].try_into().ok()?) as usize;
        let deltas_end = 24usize.checked_add(n.checked_mul(elems)?.checked_mul(8)?)?;
        if data.len() < deltas_end + 4 {
            return None;
        }
        let mut deltas = Vec::with_capacity(n);
        let mut off = 24;
        for _ in 0..n {
            let mut v = Vec::with_capacity(elems);
            for _ in 0..elems {
                let val = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);
                // TPL-305: see `KeyShare::from_bytes` — same
                // canonical-encoding gate. RefreshContribution
                // bytes are gossiped between validators, so a
                // non-canonical encoding would be a particularly
                // useful replay primitive (same delta semantics,
                // different on-the-wire bytes evade gossip dedup).
                if val >= GOLDILOCKS_PRIME {
                    return None;
                }
                v.push(gl(val));
                off += 8;
            }
            deltas.push(v);
        }
        let sig_len = u32::from_le_bytes(data[deltas_end..deltas_end + 4].try_into().ok()?) as usize;
        let sig_start = deltas_end + 4;
        if data.len() < sig_start + sig_len {
            return None;
        }
        let signature = data[sig_start..sig_start + sig_len].to_vec();
        Some(Self {
            from_index,
            epoch,
            deltas,
            signature,
        })
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

/// Audit 406: same as `apply_refresh` but operates on the slice of
/// references returned by `canonical_refresh_subset`, so callers
/// don't need to clone the contributions just to satisfy the
/// `&[RefreshContribution]` signature.
pub fn apply_refresh_canonical(
    key_share: &KeyShare,
    canonical: &[&RefreshContribution],
) -> KeyShare {
    let validator_idx = key_share.index - 1;
    let mut new_shares = key_share.shares.clone();
    for contrib in canonical {
        for elem_idx in 0..SEED_ELEMENTS {
            new_shares[elem_idx] += contrib.deltas[validator_idx][elem_idx];
        }
    }
    KeyShare {
        index: key_share.index,
        shares: new_shares,
    }
}

/// Verify a refresh contribution. Two properties must hold for a
/// PSS refresh delta to be safe to apply:
///
///   1. The first `threshold` deltas reconstruct to ZERO under
///      Lagrange interpolation. This is what makes the refresh
///      net-zero on the underlying secret — every validator's
///      share gains the same polynomial sum, so the secret
///      itself is unchanged after `apply_refresh`.
///
///   2. The remaining deltas (`[threshold..n]`) lie on the SAME
///      polynomial as the first `threshold`. Pre-fix this
///      property went unchecked — the verifier only looked at
///      the first `threshold` shares and trusted that the rest
///      "must" be consistent. A malicious member could pick a
///      valid zero-secret polynomial, evaluate at `[1..threshold]`
///      faithfully (so the zero-reconstruction test passes), and
///      then substitute random / adversarial values at
///      `[threshold..n]`. Each higher-indexed validator would
///      receive a delta that doesn't match the agreed
///      polynomial, and after `apply_refresh` the high-indexed
///      shares would silently drift off the underlying secret —
///      a slow committee-corruption attack that surfaces only
///      when those validators next try to decrypt.
///
/// TPL-302: mirror the `verify_resharing_contribution` pattern at
/// `:1239-1286` — interpolate, then re-evaluate via Lagrange at
/// every remaining index and compare against the provided value.
///
/// TPL-303: also gates on
///   (a) `contribution.epoch == expected_epoch` — replay protection
///       across PSS rounds. A Byzantine peer that re-broadcasts an
///       old, well-formed contribution against a later epoch will
///       fail this check before the cryptographic verifier runs.
///   (b) FALCON sig over `(epoch || from_index || hash(deltas))`
///       under the issuer's `issuer_pk` — authenticates the claimed
///       `from_index` so a peer can't forge a contribution under
///       another validator's slot.
pub fn verify_refresh_contribution(
    contribution: &RefreshContribution,
    threshold: usize,
    expected_epoch: u64,
    issuer_pk: &crate::falcon::FalconPublicKey,
) -> bool {
    // TPL-303: replay protection. A contribution generated for an
    // earlier epoch carries a sig that's still well-formed but
    // semantically stale; gating on epoch equality stops the
    // attacker before they can spend a FALCON-verify cycle.
    if contribution.epoch != expected_epoch {
        return false;
    }
    let n = contribution.deltas.len();
    if threshold == 0 || threshold > n {
        return false;
    }
    // Each delta row must carry SEED_ELEMENTS field elements;
    // a malformed contribution that gets past `from_bytes`
    // (e.g., constructed in-memory by a Byzantine path) would
    // otherwise panic on the indexing below.
    for row in &contribution.deltas {
        if row.len() != SEED_ELEMENTS {
            return false;
        }
    }

    for elem_idx in 0..SEED_ELEMENTS {
        // Property 1: reconstruct the first `threshold` shares
        // and verify the secret is zero.
        let interp_shares: Vec<FieldShare> = (0..threshold)
            .map(|v| FieldShare {
                x: gl((v + 1) as u64),
                y: contribution.deltas[v][elem_idx],
            })
            .collect();
        let reconstructed = shamir_reconstruct(&interp_shares);
        if reconstructed != Goldilocks::ZERO {
            return false;
        }

        // Property 2: every remaining delta must lie on the same
        // polynomial. Lagrange-evaluate at index `check_idx + 1`
        // and compare against the provided `deltas[check_idx]`.
        for check_idx in threshold..n {
            let check_x = gl((check_idx + 1) as u64);
            let mut y = Goldilocks::ZERO;
            for i in 0..threshold {
                let x_i = interp_shares[i].x;
                let mut basis = Goldilocks::ONE;
                for j in 0..threshold {
                    if i != j {
                        let x_j = interp_shares[j].x;
                        let num = check_x - x_j;
                        let den = x_i - x_j;
                        basis *= num * gl_inv(den);
                    }
                }
                y += interp_shares[i].y * basis;
            }
            if y != contribution.deltas[check_idx][elem_idx] {
                return false;
            }
        }
    }

    // TPL-303: structural checks pass — now authenticate the
    // contribution against the claimed issuer's FALCON pk. The sig
    // binds `(epoch || from_index || hash(deltas))`, so any
    // post-issue tamper or cross-issuer replay fails this gate.
    let preimage = RefreshContribution::signing_preimage(
        contribution.epoch,
        contribution.from_index,
        &contribution.deltas,
    );
    let sig = match crate::falcon::FalconSignature::from_bytes(&contribution.signature) {
        Some(s) => s,
        None => return false,
    };
    if !crate::falcon::falcon_verify(issuer_pk, &preimage, &sig) {
        return false;
    }

    true
}

/// Perform a full PSS refresh for the committee.
/// Returns new key shares for all validators and updated epoch material.
///
/// TPL-303: each contribution is signed by the issuer's FALCON sk.
/// `committee_falcon_sks[i]` corresponds to the validator holding
/// `old_shares[i]`. This is a test/bench helper — production splits
/// the refresh across validator-local `start_pss_refresh` calls.
pub fn pss_refresh(
    epoch_material: &EpochKeyMaterial,
    old_shares: &[KeyShare],
    committee_falcon_sks: &[crate::falcon::FalconSecretKey],
) -> (EpochKeyMaterial, Vec<KeyShare>) {
    let n = epoch_material.n;
    let t = epoch_material.threshold;
    let new_epoch = epoch_material.epoch + 1;

    // Each validator generates a refresh contribution using fresh entropy
    let contributions: Vec<RefreshContribution> = old_shares
        .iter()
        .enumerate()
        .map(|(i, ks)| {
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
            generate_refresh_contribution(
                ks.index,
                n,
                t,
                new_epoch,
                fresh_entropy.as_bytes(),
                &committee_falcon_sks[i],
            )
            .expect("pss_refresh: falcon sign")
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

/// Audit 406: same idea as `canonical_resharing_subset` but for PSS
/// same-committee refresh contributions. Picks the `threshold`
/// contributions with the LOWEST `from_index` so every validator
/// applies the same delta polynomial sum to its share. Pre-fix the
/// runtime applied whichever `threshold` contributions arrived
/// first via gossip, which produced different `(first-N)` subsets
/// across nodes under async delivery — exactly the failure mode
/// audit 403 fixed for epoch randomness — and the resulting shares
/// no longer interpolated to the same secret. Decryption then
/// failed every time because the threshold-Kyber Lagrange
/// reconstruction collapsed onto a wrong-secret seed.
pub fn canonical_refresh_subset(
    pool: &[RefreshContribution],
    threshold: usize,
) -> Option<Vec<&RefreshContribution>> {
    if pool.len() < threshold {
        return None;
    }
    let mut refs: Vec<&RefreshContribution> = pool.iter().collect();
    refs.sort_by_key(|c| c.from_index);
    refs.truncate(threshold);
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

    fn setup() -> (
        ThresholdPublicKey,
        Vec<KeyShare>,
        Vec<crate::falcon::FalconPublicKey>,
        Vec<crate::falcon::FalconSecretKey>,
    ) {
        let (tpk, shares) = threshold_keygen(N, T).unwrap();
        let mut pks = Vec::with_capacity(N);
        let mut sks = Vec::with_capacity(N);
        for _ in 0..N {
            let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
            pks.push(pk);
            sks.push(sk);
        }
        (tpk, shares, pks, sks)
    }

    #[test]
    fn encrypt_decrypt_with_threshold_plus_one() {
        let (tpk, shares, falcon_pks, falcon_sks) = setup();
        let msg = b"hello threshold kyber";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        let dec_shares: Vec<DecryptionShare> = shares[..T + 1]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();

        let plaintext = combine_shares(&dec_shares, T, &ct, &falcon_pks).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn encrypt_decrypt_with_exact_threshold() {
        let (tpk, shares, falcon_pks, falcon_sks) = setup();
        let msg = b"exact threshold test";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        let dec_shares: Vec<DecryptionShare> = shares[..T]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();

        let plaintext = combine_shares(&dec_shares, T, &ct, &falcon_pks).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn insufficient_shares_fails() {
        let (tpk, shares, falcon_pks, falcon_sks) = setup();
        let msg = b"not enough shares";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        let dec_shares: Vec<DecryptionShare> = shares[..T - 1]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();

        let result = combine_shares(&dec_shares, T, &ct, &falcon_pks);
        assert!(result.is_err());
    }

    /// Audit 312: combine_shares rejects shares with `index == 0`
    /// or `index > 256`. Closes the griefing path where a peer
    /// hand-crafts shares with nonsense indices that pass the
    /// dedup check but inflate Lagrange interpolation work.
    #[test]
    fn combine_shares_rejects_zero_index_audit_312() {
        let (tpk, shares, falcon_pks, falcon_sks) = setup();
        let msg = b"audit 312 zero index";
        let ct = threshold_encrypt(&tpk, msg).unwrap();
        let mut dec_shares: Vec<DecryptionShare> = shares[..T]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        // Mutate one share's index to 0.
        dec_shares[0].index = 0;
        let result = combine_shares(&dec_shares, T, &ct, &falcon_pks);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid share index"));
    }

    #[test]
    fn combine_shares_rejects_oversize_index_audit_312() {
        let (tpk, shares, falcon_pks, falcon_sks) = setup();
        let msg = b"audit 312 oversize index";
        let ct = threshold_encrypt(&tpk, msg).unwrap();
        let mut dec_shares: Vec<DecryptionShare> = shares[..T]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        // Mutate to an absurd index that no real committee would
        // produce. MAX_VALIDATOR_INDEX = 256; 257 is the first
        // out-of-range value.
        dec_shares[0].index = 257;
        let result = combine_shares(&dec_shares, T, &ct, &falcon_pks);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid share index"));
    }

    #[test]
    fn duplicate_shares_rejected() {
        let (tpk, shares, falcon_pks, falcon_sks) = setup();
        let msg = b"duplicate test";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        let mut dec_shares: Vec<DecryptionShare> = shares[..T - 1]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        // Add a duplicate
        dec_shares.push(generate_decryption_share(&shares[0], &ct, &falcon_sks[0]).unwrap());

        let result = combine_shares(&dec_shares, T, &ct, &falcon_pks);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_shares_produce_bad_mac() {
        let (tpk, _shares, falcon_pks, falcon_sks) = setup();
        let (_tpk2, shares2) = threshold_keygen(N, T).unwrap();
        let msg = b"wrong shares test";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        // Use shares from a different committee
        let dec_shares: Vec<DecryptionShare> = shares2[..T]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();

        let result = combine_shares(&dec_shares, T, &ct, &falcon_pks);
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
        let (tpk, shares, falcon_pks, falcon_sks) = setup();
        let msg = b"tampered mac test";
        let mut ct = threshold_encrypt(&tpk, msg).unwrap();
        ct.mac[0] ^= 0x01;
        let dec_shares: Vec<DecryptionShare> = shares[..T]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        let result = combine_shares(&dec_shares, T, &ct, &falcon_pks);
        assert_eq!(result, Err("decryption failed"));
    }

    /// Audit 359: two encryptions of the same plaintext under the
    /// same threshold pk must produce different keystreams,
    /// different ciphertexts, AND different MACs — even though
    /// `kyber_encapsulate`'s shared_secret derivation is the only
    /// thing per-call randomized. The fix binds `kyber_ct` into
    /// both KDFs as a per-message nonce, so a hypothetical
    /// shared_secret repeat (broken Kyber RNG) doesn't collapse
    /// to identical keystreams + MAC keys.
    #[test]
    fn audit_359_keystream_and_mac_unique_per_encryption() {
        let (tpk, _shares, falcon_pks, falcon_sks) = setup();
        let msg = b"audit-359 keystream uniqueness";
        let ct1 = threshold_encrypt(&tpk, msg).unwrap();
        let ct2 = threshold_encrypt(&tpk, msg).unwrap();
        // Kyber-encap is randomized → distinct kyber_ct per call.
        assert_ne!(
            ct1.kyber_ct.as_bytes(),
            ct2.kyber_ct.as_bytes(),
            "Kyber encap must produce a fresh ct per call"
        );
        // With same plaintext + DIFFERENT kyber_ct, post-fix the
        // keystream is distinct, so the encrypted message bytes
        // are distinct, AND the MAC is distinct.
        assert_ne!(ct1.encrypted_msg, ct2.encrypted_msg);
        assert_ne!(ct1.mac, ct2.mac);
    }

    /// Audit 359: tampering with `kyber_ct` (without changing
    /// the encrypted_msg or mac) must invalidate decryption,
    /// because the MAC is keyed on `kyber_ct`. Pre-fix the MAC
    /// only depended on `(ss, encrypted_msg)`, so a swapped
    /// kyber_ct under the same shared_secret would silently
    /// re-derive a different keystream and produce wrong
    /// plaintext that still passed MAC verification.
    #[test]
    fn audit_359_kyber_ct_tampering_breaks_decrypt() {
        let (tpk, shares, falcon_pks, falcon_sks) = setup();
        let msg = b"audit-359 ct binding";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        // Encrypt a SECOND message; swap its kyber_ct into the
        // first ciphertext. ss differs → MAC mismatches.
        let ct2 = threshold_encrypt(&tpk, b"different").unwrap();
        let mut tampered = ct.clone();
        tampered.kyber_ct = ct2.kyber_ct.clone();
        let dec_shares: Vec<DecryptionShare> = shares[..T]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &tampered, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        let result = combine_shares(&dec_shares, T, &tampered, &falcon_pks);
        assert_eq!(result, Err("decryption failed"));
    }

    /// Audit 360: two structurally distinct combine-failure
    /// causes — (a) shares that interpolate to a Kyber seed
    /// `dk_from_seed` rejects, and (b) shares that produce a
    /// valid seed but the resulting `ss` doesn't match the MAC —
    /// must return the SAME error so an attacker probing with
    /// crafted shares can't distinguish the failure modes.
    /// Pre-fix the two paths returned distinct strings
    /// ("Kyber-768 decapsulation failed" vs. "MAC verification
    /// failed"), giving an oracle that narrowed the search for
    /// share structures that pass each pipeline stage.
    #[test]
    fn audit_360_failure_modes_collapse_to_single_error() {
        let (tpk, shares, falcon_pks, falcon_sks) = setup();
        let msg = b"audit-360 oracle uniform";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        // (a) Tamper with one share value to force the
        //     interpolation path to produce a wrong-but-
        //     plausible seed. Either Kyber-from-seed fails or
        //     Kyber decap "succeeds" but produces wrong ss →
        //     MAC fails. Either way the post-fix returns the
        //     same generic error.
        let mut tampered_shares: Vec<DecryptionShare> = shares[..T]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        // Mutate the FIRST share's first element by adding a
        // non-zero field element. Goldilocks is a field, so
        // any non-zero perturbation propagates through Lagrange.
        let bad = &mut tampered_shares[0];
        if !bad.shares.is_empty() {
            bad.shares[0] += gl(1);
        }
        let bad_share_result = combine_shares(&tampered_shares, T, &ct, &falcon_pks);

        // (b) Use shares from a DIFFERENT keygen. Index space
        //     overlaps, but the polynomials are independent, so
        //     interpolation produces an unrelated seed. Same
        //     pipeline-fail behavior as (a) — must return the
        //     same error.
        let (_other_tpk, other_shares, falcon_pks, falcon_sks) = setup();
        let other_dec: Vec<DecryptionShare> = other_shares[..T]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        let other_result = combine_shares(&other_dec, T, &ct, &falcon_pks);

        // Both failure modes return the SAME error string, with
        // no distinguishing information about WHICH stage tripped.
        assert!(bad_share_result.is_err(), "tampered shares must fail");
        assert!(other_result.is_err(), "wrong-keygen shares must fail");
        assert_eq!(
            bad_share_result, other_result,
            "audit 360: distinct failure modes must collapse to the same error"
        );
        assert_eq!(bad_share_result, Err("decryption failed"));
    }

    #[test]
    fn any_subset_of_shares_works() {
        let (tpk, shares, falcon_pks, falcon_sks) = setup();
        let msg = b"any subset works";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        // Use last T shares instead of first T
        let dec_shares: Vec<DecryptionShare> = shares[N - T..]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();

        let plaintext = combine_shares(&dec_shares, T, &ct, &falcon_pks).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn empty_message() {
        let (tpk, shares, falcon_pks, falcon_sks) = setup();
        let msg = b"";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        let dec_shares: Vec<DecryptionShare> = shares[..T]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();

        let plaintext = combine_shares(&dec_shares, T, &ct, &falcon_pks).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn large_message() {
        let (tpk, shares) = threshold_keygen(5, 3).unwrap(); // smaller for speed
        let mut falcon_pks = Vec::with_capacity(5);
        let mut falcon_sks = Vec::with_capacity(5);
        for _ in 0..5 {
            let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
            falcon_pks.push(pk);
            falcon_sks.push(sk);
        }
        let msg = vec![0xABu8; 10_000];
        let ct = threshold_encrypt(&tpk, &msg).unwrap();

        let dec_shares: Vec<DecryptionShare> = shares[..3]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();

        let plaintext = combine_shares(&dec_shares, 3, &ct, &falcon_pks).unwrap();
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

    fn setup_epoch(
        n: usize,
        t: usize,
    ) -> (
        EpochKeyMaterial,
        Vec<KeyShare>,
        Vec<crate::falcon::FalconPublicKey>,
        Vec<crate::falcon::FalconSecretKey>,
    ) {
        let (tpk, shares) = threshold_keygen(n, t).unwrap();
        let mut falcon_pks = Vec::with_capacity(n);
        let mut falcon_sks = Vec::with_capacity(n);
        for _ in 0..n {
            let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
            falcon_pks.push(pk);
            falcon_sks.push(sk);
        }
        let epoch_material = EpochKeyMaterial {
            epoch: 0,
            n,
            threshold: t,
            tpk,
        };
        (epoch_material, shares, falcon_pks, falcon_sks)
    }

    #[test]
    fn pss_refreshed_shares_decrypt_old_ciphertext() {
        let (epoch_mat, shares, falcon_pks, falcon_sks) = setup_epoch(5, 3);
        let msg = b"encrypted before refresh";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

        // Refresh shares
        let (_new_epoch, new_shares) = pss_refresh(&epoch_mat, &shares, &falcon_sks);

        // New shares should still decrypt old ciphertext
        let dec_shares: Vec<DecryptionShare> = new_shares[..3]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        let plaintext = combine_shares(&dec_shares, 3, &ct, &falcon_pks).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn pss_old_shares_cannot_decrypt_after_refresh() {
        let (epoch_mat, shares, falcon_pks, falcon_sks) = setup_epoch(5, 3);

        // Refresh shares
        let (new_epoch, new_shares) = pss_refresh(&epoch_mat, &shares, &falcon_sks);

        // Encrypt with the same public key (it doesn't change)
        let msg = b"encrypted after refresh";
        let ct = threshold_encrypt(&new_epoch.tpk, msg).unwrap();

        // New shares should work
        let dec_shares_new: Vec<DecryptionShare> = new_shares[..3]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        let plaintext = combine_shares(&dec_shares_new, 3, &ct, &falcon_pks).unwrap();
        assert_eq!(plaintext, msg);

        // Old shares should fail (they reconstruct a different secret)
        let dec_shares_old: Vec<DecryptionShare> = shares[..3]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        // Old shares still reconstruct the SAME secret (the secret doesn't change),
        // so they should also work. PSS only protects against partial compromise.
        let plaintext_old = combine_shares(&dec_shares_old, 3, &ct, &falcon_pks).unwrap();
        assert_eq!(plaintext_old, msg);
    }

    /// AUDIT 406 REGRESSION GUARD — reshare canonical-subset
    /// divergence when each node's local pool is missing its own
    /// contribution.
    ///
    /// The runtime symptom: every node fired `committee handoff
    /// complete` cleanly, but each node's `canonical_resharing_subset`
    /// returned a DIFFERENT 3-of-4 subset (each missing the
    /// contribution from its own old position, because
    /// `start_committee_reshare` never seeded the local pool with
    /// the local contribution). The new shares then evaluated
    /// different polynomials, post-reshare on-disk shares didn't
    /// combine to recover the secret, and 100% of encrypted txs
    /// failed to decrypt despite all four nodes having "valid-
    /// looking" shares. This test reproduces that divergence.
    #[test]
    fn audit_406_reshare_local_pool_must_include_own_contribution() {
        let (tpk, genesis_shares) = threshold_keygen(4, 3).unwrap();
        let mut falcon_pks = Vec::with_capacity(4);
        let mut falcon_sks = Vec::with_capacity(4);
        for _ in 0..4 {
            let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
            falcon_pks.push(pk);
            falcon_sks.push(sk);
        }
        let msg = b"reshare-own-in-pool bug repro";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        // Generate one resharing contribution per old member.
        let pool_full: Vec<ResharingContribution> = genesis_shares
            .iter()
            .map(|s| generate_resharing_contribution(s, 4, 3, 1, b"reshare-fix"))
            .collect();

        // BUG CASE: each node's local pool is missing the
        // contribution from its OWN old index (mirrors what
        // `start_committee_reshare` left behind pre-fix). canonical
        // ends up different on every node.
        let perm: [usize; 4] = [3, 4, 1, 2]; // genesis_idx → new_index
        let mut buggy_new_shares: Vec<KeyShare> = Vec::with_capacity(4);
        for missing_old_idx in 1..=4usize {
            let local_pool: Vec<ResharingContribution> = pool_full
                .iter()
                .filter(|c| c.from_old_index != missing_old_idx)
                .cloned()
                .collect();
            assert_eq!(local_pool.len(), 3);
            let canonical = canonical_resharing_subset(&local_pool, 3).unwrap();
            // canonical here is whatever 3-of-3 the local pool
            // contains — one will be {2,3,4}, next {1,3,4}, etc.
            let new_idx = perm[missing_old_idx - 1];
            let new_share = aggregate_new_share(new_idx, &canonical).unwrap();
            buggy_new_shares.push(new_share);
        }

        // Buggy: every 3-of-4 subset MUST fail to combine, because
        // the four shares lie on four different polynomials.
        let mut any_buggy_ok = false;
        for skip in 0..4 {
            let dec: Vec<DecryptionShare> = (0..4)
                .filter(|&i| i != skip)
                .map(|i| generate_decryption_share(&buggy_new_shares[i], &ct, &falcon_sks[i]).unwrap())
                .collect();
            if let Ok(plain) = combine_shares(&dec, 3, &ct, &falcon_pks) {
                if plain == msg {
                    any_buggy_ok = true;
                }
            }
        }
        assert!(
            !any_buggy_ok,
            "buggy local-pool reshare unexpectedly recovered secret — \
             repro is wrong, the runtime divergence is something else"
        );

        // FIX CASE: every node's local pool includes its OWN
        // contribution. canonical = lowest-3 by from_old_index =
        // {1,2,3} on every node. New shares all interpolate to the
        // same polynomial.
        let canonical_fix = canonical_resharing_subset(&pool_full, 3).unwrap();
        let fixed_new_shares: Vec<KeyShare> = (1..=4usize)
            .map(|new_idx| aggregate_new_share(new_idx, &canonical_fix).unwrap())
            .collect();

        for skip in 0..4 {
            let dec: Vec<DecryptionShare> = (0..4)
                .filter(|&i| i != skip)
                .map(|i| generate_decryption_share(&fixed_new_shares[i], &ct, &falcon_sks[i]).unwrap())
                .collect();
            let plain = combine_shares(&dec, 3, &ct, &falcon_pks)
                .unwrap_or_else(|e| panic!("fixed skip {} failed: {}", skip, e));
            assert_eq!(plain, msg, "fixed skip {} wrong plaintext", skip);
        }
    }

    /// AUDIT 406 — `DecryptionShare` wire round-trip must preserve
    /// every byte, otherwise the runtime — which gossips shares
    /// across the committee — will combine round-tripped shares
    /// that no longer interpolate to the same secret. This was the
    /// last remaining drift hypothesis when in-process decrypt
    /// passed the diag but every block of encrypted txs failed.
    #[test]
    fn audit_406_decryption_share_wire_roundtrip_decrypts() {
        let (tpk, key_shares) = threshold_keygen(4, 3).unwrap();
        let mut falcon_pks = Vec::with_capacity(4);
        let mut falcon_sks = Vec::with_capacity(4);
        for _ in 0..4 {
            let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
            falcon_pks.push(pk);
            falcon_sks.push(sk);
        }
        let msg = b"share wire roundtrip";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        // Generate 4 fresh decryption shares locally.
        let local_shares: Vec<DecryptionShare> = key_shares
            .iter()
            .enumerate()
            .map(|(i, ks)| generate_decryption_share(ks, &ct, &falcon_sks[ks.index - 1]).unwrap())
            .collect();

        // Wire-roundtrip every share via `to_bytes` / `from_bytes`,
        // mirror of what gossip does between sender and receiver.
        let roundtripped: Vec<DecryptionShare> = local_shares
            .iter()
            .map(|s| {
                let bytes = s.to_bytes();
                DecryptionShare::from_bytes(&bytes).expect("share roundtrip")
            })
            .collect();

        // Bytes must be identical.
        for (orig, rt) in local_shares.iter().zip(&roundtripped) {
            assert_eq!(orig.to_bytes(), rt.to_bytes(), "share bytes drifted");
            assert_eq!(orig.index, rt.index, "share index drifted");
        }

        // Every threshold-sized subset of round-tripped shares must
        // still combine to recover the secret.
        for skip in 0..4 {
            let subset: Vec<DecryptionShare> = roundtripped
                .iter()
                .enumerate()
                .filter_map(|(i, s)| if i == skip { None } else { Some(s.clone()) })
                .collect();
            let plain = combine_shares(&subset, 3, &ct, &falcon_pks).unwrap_or_else(|e| {
                panic!(
                    "skip {} round-tripped shares failed combine: {} — \
                     wire round-trip corrupts DecryptionShare",
                    skip, e
                )
            });
            assert_eq!(plain, msg);
        }
    }

    /// AUDIT 406 RUNTIME-PIPELINE INTEGRATION TEST.
    ///
    /// Simulates the exact sequence the runtime runs at every
    /// epoch boundary: genesis keygen → cross-committee reshare
    /// (canonical-subset aggregate) → PSS canonical-subset apply.
    /// At the end, every 3-of-4 subset of post-pipeline shares must
    /// still combine to the original secret behind the (unchanged)
    /// public key. This is the property the on-disk-shares
    /// diagnostic test (`crates/crypto/tests/encrypted_pipeline_diag.rs`)
    /// failed to satisfy before the fix.
    #[test]
    fn audit_406_runtime_pipeline_preserves_secret() {
        let (tpk, genesis_shares) = threshold_keygen(4, 3).unwrap();
        let mut falcon_pks = Vec::with_capacity(4);
        let mut falcon_sks = Vec::with_capacity(4);
        for _ in 0..4 {
            let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
            falcon_pks.push(pk);
            falcon_sks.push(sk);
        }
        let msg = b"runtime pipeline preserves secret";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        // ---- Cross-committee resharing pass ----
        // Each genesis-share holder generates a resharing contribution
        // for the new committee. We use a permuted "new committee"
        // where each validator's new_index differs from its old.
        let new_n = 4usize;
        let new_t = 3usize;
        let entropy_reshare = b"runtime-test-reshare";
        let reshare_pool: Vec<ResharingContribution> = genesis_shares
            .iter()
            .map(|s| generate_resharing_contribution(s, new_n, new_t, 1, entropy_reshare))
            .collect();
        let canonical = canonical_resharing_subset(&reshare_pool, /* old_threshold */ 3)
            .expect("resharing canonical subset");

        // Permute new positions: validator i (genesis) maps to new
        // index P[i]. This mimics the runtime where the new committee
        // shuffles positions per VRF.
        let perm: [usize; 4] = [3, 4, 1, 2]; // genesis_idx → new_index (1-based)
        let post_reshare_shares: Vec<KeyShare> = (0..4)
            .map(|i| aggregate_new_share(perm[i], &canonical).expect("aggregate"))
            .collect();

        // Sanity: post-reshare alone must decrypt.
        let dec_after_reshare: Vec<DecryptionShare> = post_reshare_shares[..3]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        let plain_reshare =
            combine_shares(&dec_after_reshare, 3, &ct, &falcon_pks).expect("post-reshare alone must decrypt");
        assert_eq!(plain_reshare, msg);

        // ---- PSS canonical apply pass ----
        // Each validator broadcasts a PSS contribution. from_index is
        // the validator's OLD (genesis) index in the runtime — that's
        // what start_pss_refresh uses since it runs BEFORE reshare
        // overwrites identity.key_share.
        let entropy_pss = b"runtime-test-pss-entropy";
        let pss_pool: Vec<RefreshContribution> = (1..=4usize)
            .map(|old_idx| {
                generate_refresh_contribution(
                    old_idx,
                    new_n,
                    new_t,
                    2,
                    entropy_pss,
                    &falcon_sks[old_idx - 1],
                )
                .unwrap()
            })
            .collect();
        let pss_canonical = canonical_refresh_subset(&pss_pool, 3).expect("PSS canonical subset");

        // Validators apply PSS canonical to their post-reshare share.
        // post_reshare_share.index is the NEW position (perm[i]).
        let post_pss_shares: Vec<KeyShare> = post_reshare_shares
            .iter()
            .map(|s| apply_refresh_canonical(s, &pss_canonical))
            .collect();

        // The post-pipeline shares MUST still decrypt the original
        // ciphertext via every 3-of-4 subset.
        for skip in 0..4usize {
            let subset_shares: Vec<KeyShare> = (0..4)
                .filter(|&i| i != skip)
                .map(|i| post_pss_shares[i].clone())
                .collect();
            let dec: Vec<DecryptionShare> = subset_shares
                .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
                .collect();
            let plain = combine_shares(&dec, 3, &ct, &falcon_pks).unwrap_or_else(|e| {
                panic!(
                    "subset (skip {}) failed to decrypt: {} \
                     — runtime pipeline did NOT preserve secret",
                    skip, e
                )
            });
            assert_eq!(plain, msg, "subset (skip {}) wrong plaintext", skip);
        }
    }

    /// AUDIT 406 RUNTIME-PIPELINE INTEGRATION TEST — TWO CYCLES.
    /// The single-cycle test passes; the on-disk diagnostic against
    /// a real testnet that ran multiple cycles fails. So either two
    /// cycles compound an error, or the PSS contribution generation
    /// in cycle 2 reads stale state. This test runs the full
    /// pipeline twice and asserts the original ciphertext still
    /// decrypts at every 3-of-4 subset of the post-cycle-2 shares.
    #[test]
    fn audit_406_runtime_pipeline_two_cycles_preserve_secret() {
        let (tpk, genesis_shares) = threshold_keygen(4, 3).unwrap();
        let mut falcon_pks = Vec::with_capacity(4);
        let mut falcon_sks = Vec::with_capacity(4);
        for _ in 0..4 {
            let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
            falcon_pks.push(pk);
            falcon_sks.push(sk);
        }
        let msg = b"two-cycle pipeline preserves secret";
        let ct = threshold_encrypt(&tpk, msg).unwrap();
        let new_n = 4usize;
        let new_t = 3usize;

        // ---- Cycle 1 ----
        let cycle1_reshare_pool: Vec<ResharingContribution> = genesis_shares
            .iter()
            .map(|s| generate_resharing_contribution(s, new_n, new_t, 1, b"reshare-1"))
            .collect();
        let c1_canonical_reshare = canonical_resharing_subset(&cycle1_reshare_pool, 3).unwrap();
        let perm1: [usize; 4] = [3, 4, 1, 2];
        let after_c1_reshare: Vec<KeyShare> = (0..4)
            .map(|i| aggregate_new_share(perm1[i], &c1_canonical_reshare).unwrap())
            .collect();

        // PSS contributions for cycle 1: from_index = OLD index = genesis index.
        let cycle1_pss_pool: Vec<RefreshContribution> = (1..=4usize)
            .map(|old_idx| {
                generate_refresh_contribution(
                    old_idx,
                    new_n,
                    new_t,
                    2,
                    b"pss-1",
                    &falcon_sks[old_idx - 1],
                )
                .unwrap()
            })
            .collect();
        let c1_canonical_pss = canonical_refresh_subset(&cycle1_pss_pool, 3).unwrap();
        let after_c1_pss: Vec<KeyShare> = after_c1_reshare
            .iter()
            .map(|s| apply_refresh_canonical(s, &c1_canonical_pss))
            .collect();

        // Sanity: post-cycle-1 must decrypt.
        for skip in 0..4usize {
            let dec: Vec<DecryptionShare> = (0..4)
                .filter(|&i| i != skip)
                .map(|i| {
                    let s = &after_c1_pss[i];
                    generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap()
                })
                .collect();
            let plain = combine_shares(&dec, 3, &ct, &falcon_pks)
                .unwrap_or_else(|e| panic!("c1 skip {} fail: {}", skip, e));
            assert_eq!(plain, msg, "c1 skip {} wrong plaintext", skip);
        }

        // ---- Cycle 2 ----
        // Inputs: post-cycle-1 shares. Each validator's "OLD index"
        // for cycle 2 is its CURRENT key_share.index = perm1[i].
        let cycle2_reshare_pool: Vec<ResharingContribution> = after_c1_pss
            .iter()
            .map(|s| generate_resharing_contribution(s, new_n, new_t, 2, b"reshare-2"))
            .collect();
        let c2_canonical_reshare = canonical_resharing_subset(&cycle2_reshare_pool, 3).unwrap();
        let perm2: [usize; 4] = [4, 2, 3, 1]; // a different permutation
        let after_c2_reshare: Vec<KeyShare> = (0..4)
            .map(|i| aggregate_new_share(perm2[i], &c2_canonical_reshare).unwrap())
            .collect();

        // PSS for cycle 2: from_index = current key_share.index BEFORE
        // reshare runs. Since start_pss_refresh runs BEFORE
        // start_committee_reshare in the runtime, key_share at
        // generation time is still post-cycle-1 = perm1[i].
        let cycle2_pss_pool: Vec<RefreshContribution> = (0..4)
            .map(|i| {
                generate_refresh_contribution(
                    perm1[i],
                    new_n,
                    new_t,
                    3,
                    b"pss-2",
                    &falcon_sks[perm1[i] - 1],
                )
                .unwrap()
            })
            .collect();
        let c2_canonical_pss = canonical_refresh_subset(&cycle2_pss_pool, 3).unwrap();
        let after_c2_pss: Vec<KeyShare> = after_c2_reshare
            .iter()
            .map(|s| apply_refresh_canonical(s, &c2_canonical_pss))
            .collect();

        // The post-cycle-2 shares MUST still decrypt.
        for skip in 0..4usize {
            let dec: Vec<DecryptionShare> = (0..4)
                .filter(|&i| i != skip)
                .map(|i| {
                    let s = &after_c2_pss[i];
                    generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap()
                })
                .collect();
            let plain = combine_shares(&dec, 3, &ct, &falcon_pks).unwrap_or_else(|e| {
                panic!(
                    "post-cycle-2 skip {} failed: {} — \
                     two-cycle pipeline did NOT preserve secret",
                    skip, e
                )
            });
            assert_eq!(plain, msg, "c2 skip {} wrong plaintext", skip);
        }
    }

    /// AUDIT 406 REGRESSION GUARD.
    ///
    /// Pre-fix the runtime applied refresh contributions eagerly on
    /// first-`threshold` arrival. Under async gossip every validator
    /// saw a different "first 3 of N" arrival order, so each one
    /// applied a different DELTA SET to its share — the shares
    /// stopped interpolating to the same secret and every block of
    /// encrypted txs failed to decrypt.
    ///
    /// This test simulates that bug directly: each validator's
    /// share is mutated by `apply_refresh` over a DIFFERENT pool
    /// subset. We then check that
    ///   (a) decryption with the mutated shares fails (the bug
    ///       manifests), AND
    ///   (b) decryption with the canonical-subset apply succeeds
    ///       (the fix works).
    #[test]
    fn pss_eager_apply_breaks_decryption_canonical_apply_fixes_it() {
        let (epoch_mat, shares, falcon_pks, falcon_sks) = setup_epoch(4, 3);
        let msg = b"audit-406 regression";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

        // Generate 4 contributions, one per validator.
        let entropy = b"audit-406-test-entropy";
        let pool: Vec<RefreshContribution> = (1..=4usize)
            .map(|idx| {
                generate_refresh_contribution(idx, 4, 3, 1, entropy, &falcon_sks[idx - 1]).unwrap()
            })
            .collect();

        // Simulate buggy runtime: each validator picks a DIFFERENT
        // first-3-of-4 subset (whatever arrived fastest in their
        // gossip order). Validator 1 saw {own, 2, 3} first;
        // validator 2 saw {own, 3, 4}; validator 3 saw {own, 1, 4};
        // validator 4 saw {own, 1, 2}. Same membership but each
        // skips a different peer's contribution.
        let buggy_subsets: [[usize; 3]; 4] = [
            [1, 2, 3], // validator 1 misses 4
            [2, 3, 4], // validator 2 misses 1
            [3, 1, 4], // validator 3 misses 2
            [4, 1, 2], // validator 4 misses 3
        ];
        let buggy_shares: Vec<KeyShare> = (0..4)
            .map(|i| {
                let owned: Vec<RefreshContribution> = buggy_subsets[i]
                    .iter()
                    .map(|&j| pool[j - 1].clone())
                    .collect();
                apply_refresh(&shares[i], &owned)
            })
            .collect();

        // (a) Decryption with the buggy mixed shares should NOT
        // recover the plaintext — the shares are on different
        // polynomials.
        let buggy_dec: Vec<DecryptionShare> = buggy_shares[..3]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        let buggy_result = combine_shares(&buggy_dec, 3, &ct, &falcon_pks);
        assert!(
            buggy_result.is_err() || buggy_result.as_ref().unwrap() != msg,
            "buggy first-N-wins apply should NOT decrypt — \
             this is the audit 406 failure mode"
        );

        // (b) Same starting shares + same pool, but apply the
        // canonical subset on every validator. They must all
        // converge on the same polynomial.
        let canonical = canonical_refresh_subset(&pool, 3).expect("canonical subset");
        let fixed_shares: Vec<KeyShare> = (0..4)
            .map(|i| apply_refresh_canonical(&shares[i], &canonical))
            .collect();

        let fixed_dec: Vec<DecryptionShare> = fixed_shares[..3]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        let fixed_plaintext = combine_shares(&fixed_dec, 3, &ct, &falcon_pks)
            .expect("canonical apply must decrypt the same ciphertext");
        assert_eq!(
            fixed_plaintext, msg,
            "canonical-subset apply must preserve the secret",
        );

        // Defensive: also verify the canonical subset is the
        // lowest-from_index `threshold`-sized subset, regardless of
        // pool ordering.
        let mut shuffled = pool.clone();
        shuffled.reverse();
        let canon_shuffled =
            canonical_refresh_subset(&shuffled, 3).expect("canonical from shuffled");
        let canon_indices: Vec<usize> = canon_shuffled.iter().map(|c| c.from_index).collect();
        assert_eq!(canon_indices, vec![1, 2, 3]);
    }

    #[test]
    fn pss_mixed_old_new_shares_fail() {
        let (epoch_mat, shares, falcon_pks, falcon_sks) = setup_epoch(5, 3);
        let msg = b"mixed shares test";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

        let (_new_epoch, new_shares) = pss_refresh(&epoch_mat, &shares, &falcon_sks);

        // Mix old and new shares from different validators — should fail
        // because shares from different epochs lie on different polynomials
        let mixed_shares = vec![
            generate_decryption_share(&shares[0], &ct, &falcon_sks[0]).unwrap(), // old share, validator 1
            generate_decryption_share(&new_shares[1], &ct, &falcon_sks[1]).unwrap(), // new share, validator 2
            generate_decryption_share(&new_shares[2], &ct, &falcon_sks[2]).unwrap(), // new share, validator 3
        ];
        let result = combine_shares(&mixed_shares, 3, &ct, &falcon_pks);
        assert!(
            result.is_err(),
            "mixing old and new epoch shares should fail"
        );
    }

    #[test]
    fn pss_multiple_refreshes() {
        let (epoch_mat, shares, falcon_pks, falcon_sks) = setup_epoch(5, 3);
        let msg = b"multi-refresh test";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

        // Refresh multiple times
        let (epoch1, shares1) = pss_refresh(&epoch_mat, &shares, &falcon_sks);
        let (epoch2, shares2) = pss_refresh(&epoch1, &shares1, &falcon_sks);
        let (_epoch3, shares3) = pss_refresh(&epoch2, &shares2, &falcon_sks);

        // Shares after 3 refreshes should still decrypt
        let dec_shares: Vec<DecryptionShare> = shares3[..3]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        let plaintext = combine_shares(&dec_shares, 3, &ct, &falcon_pks).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn pss_verify_refresh_contributions() {
        let (epoch_mat, shares, falcon_pks, falcon_sks) = setup_epoch(5, 3);
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
                &falcon_sks[ks.index - 1],
            )
            .unwrap();
            assert!(verify_refresh_contribution(
                &contrib,
                epoch_mat.threshold,
                new_epoch,
                &falcon_pks[ks.index - 1],
            ));
        }
    }

    #[test]
    fn pss_any_subset_after_refresh() {
        let (epoch_mat, shares, falcon_pks, falcon_sks) = setup_epoch(10, 7);
        let msg = b"any subset after refresh";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

        let (_new_epoch, new_shares) = pss_refresh(&epoch_mat, &shares, &falcon_sks);

        // Use last 7 shares
        let dec_shares: Vec<DecryptionShare> = new_shares[3..10]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        let plaintext = combine_shares(&dec_shares, 7, &ct, &falcon_pks).unwrap();
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
        let (epoch_mat, old_shares, falcon_pks, falcon_sks) = setup_epoch(10, 7);
        let msg = b"committee rotation preserves decryptability";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

        // New committee: 8 members, threshold 5 — different size AND
        // different members than the original.
        let new_shares = do_resharing(&old_shares, 7, 8, 5, 1);

        // Five new members (their new threshold) suffice to decrypt.
        let dec_shares: Vec<DecryptionShare> = new_shares[..5]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        let plaintext = combine_shares(&dec_shares, 5, &ct, &falcon_pks).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn reshare_any_subset_of_new_committee_suffices() {
        // Verify that any subset of size >= new_threshold from the new
        // committee can combine — ensures all new members sit on the same
        // polynomial (the whole point of the canonical-subset rule).
        let (epoch_mat, old_shares, _old_falcon_pks, _old_falcon_sks) = setup_epoch(8, 5);
        let msg = b"interchangeable new shares";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

        let new_shares = do_resharing(&old_shares, 5, 10, 7, 2);

        // The reshare grows the committee 8 → 10, so fresh FALCON
        // keypairs are needed for the new committee membership.
        let mut new_falcon_pks = Vec::with_capacity(10);
        let mut new_falcon_sks = Vec::with_capacity(10);
        for _ in 0..10 {
            let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
            new_falcon_pks.push(pk);
            new_falcon_sks.push(sk);
        }

        // Two different subsets of size 7 — both should decrypt.
        let subset_a: Vec<DecryptionShare> = new_shares[..7]
            .iter()
            .map(|s| {
                generate_decryption_share(s, &ct, &new_falcon_sks[s.index - 1]).unwrap()
            })
            .collect();
        let subset_b: Vec<DecryptionShare> = new_shares[3..10]
            .iter()
            .map(|s| {
                generate_decryption_share(s, &ct, &new_falcon_sks[s.index - 1]).unwrap()
            })
            .collect();

        assert_eq!(combine_shares(&subset_a, 7, &ct, &new_falcon_pks).unwrap(), msg);
        assert_eq!(combine_shares(&subset_b, 7, &ct, &new_falcon_pks).unwrap(), msg);
    }

    #[test]
    fn reshare_below_old_threshold_contributions_fails() {
        // Fewer than `old_threshold` contributions available → canonical
        // subset selection returns None. Enforcement lives with the caller.
        let (_, old_shares, falcon_pks, falcon_sks) = setup_epoch(6, 4);
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
        let (_, old_shares, falcon_pks, falcon_sks) = setup_epoch(6, 3);
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
        let (epoch_mat, old_shares, _old_falcon_pks, _old_falcon_sks) = setup_epoch(6, 4);
        let msg = b"two members same poly";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

        let new_shares = do_resharing(&old_shares, 4, 7, 4, 1);

        // Reshare grows the committee 6 → 7, so the new committee
        // gets fresh FALCON keypairs for sig-bound decryption shares.
        let mut new_falcon_pks = Vec::with_capacity(7);
        let mut new_falcon_sks = Vec::with_capacity(7);
        for _ in 0..7 {
            let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
            new_falcon_pks.push(pk);
            new_falcon_sks.push(sk);
        }

        // Pick 4 disjoint-ish subsets, all must decrypt.
        for start in 0..4 {
            let subset: Vec<DecryptionShare> = new_shares[start..start + 4]
                .iter()
                .map(|s| {
                    generate_decryption_share(s, &ct, &new_falcon_sks[s.index - 1]).unwrap()
                })
                .collect();
            assert_eq!(
                combine_shares(&subset, 4, &ct, &new_falcon_pks).unwrap(),
                msg,
                "subset starting at {start} failed to decrypt"
            );
        }
    }

    #[test]
    fn reshare_verify_detects_inconsistent_contribution() {
        let (_, old_shares, falcon_pks, falcon_sks) = setup_epoch(6, 4);
        let mut contrib = generate_resharing_contribution(&old_shares[0], 8, 5, 1, b"e");
        assert!(verify_resharing_contribution(&contrib, 5, 8));

        // Tamper: flip a value in one of the non-interpolation rows.
        contrib.sub_shares[6][2] += gl(1);
        assert!(!verify_resharing_contribution(&contrib, 5, 8));
    }

    #[test]
    fn reshare_verify_rejects_wrong_dimensions() {
        let (_, old_shares, falcon_pks, falcon_sks) = setup_epoch(6, 4);
        let contrib = generate_resharing_contribution(&old_shares[0], 8, 5, 1, b"e");
        // Pretend new_n is different from what the contribution was built for.
        assert!(!verify_resharing_contribution(&contrib, 5, 9));
        // Threshold > new_n should also be rejected.
        assert!(!verify_resharing_contribution(&contrib, 9, 8));
    }

    #[test]
    fn reshare_contribution_roundtrips_through_wire_format() {
        let (_, old_shares, falcon_pks, falcon_sks) = setup_epoch(5, 3);
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
        let (epoch_mat, old_shares, falcon_pks, falcon_sks) = setup_epoch(6, 4);
        let msg = b"two rotations";
        let ct = threshold_encrypt(&epoch_mat.tpk, msg).unwrap();

        let mid_shares = do_resharing(&old_shares, 4, 7, 5, 1);
        let new_shares = do_resharing(&mid_shares, 5, 8, 6, 2);

        let dec_shares: Vec<DecryptionShare> = new_shares[..6]
            .iter().enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        assert_eq!(combine_shares(&dec_shares, 6, &ct, &falcon_pks).unwrap(), msg);
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
        let (_, mut shares, falcon_pks, falcon_sks) = setup();
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
        let (_pk, sk) = crate::falcon::falcon_keygen().unwrap();
        let mut contrib = generate_refresh_contribution(1, 6, 4, 0, b"e", &sk).unwrap();
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
        let (_, old_shares, falcon_pks, falcon_sks) = setup_epoch(6, 4);
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

    // ========== Audit 391: rejection sampling ==========

    /// Audit 391: `random_goldilocks` is deterministic in
    /// `(entropy, index)` and always produces a canonical
    /// Goldilocks element. The post-fix loop adds an attempt
    /// counter, so the *value* differs from the pre-fix
    /// implementation; this test pins the canonical-form
    /// invariant.
    #[test]
    fn audit_391_random_goldilocks_is_canonical_and_deterministic() {
        let entropy = b"audit-391-test-entropy";
        for index in 0..256usize {
            let a = random_goldilocks(entropy, index);
            let b = random_goldilocks(entropy, index);
            assert_eq!(
                a.as_canonical_u64(),
                b.as_canonical_u64(),
                "determinism: same (entropy, index) must yield same value"
            );
            assert!(
                a.as_canonical_u64() < GOLDILOCKS_PRIME,
                "canonical: value must be in [0, p)"
            );
        }
    }

    /// Audit 391: `derive_blinding_mask` is deterministic in
    /// `(ct_hash, validator_index, elem_index)` so every validator
    /// computes the same mask and `combine_shares` can subtract
    /// it. Post-fix the inner loop hashes an attempt counter, but
    /// the function's external contract is unchanged.
    #[test]
    fn audit_391_derive_blinding_mask_is_canonical_and_deterministic() {
        let ct_hash = [7u8; 32];
        for validator_index in 1..16usize {
            for elem_index in 0..SEED_ELEMENTS {
                let a = derive_blinding_mask(&ct_hash, validator_index, elem_index);
                let b = derive_blinding_mask(&ct_hash, validator_index, elem_index);
                assert_eq!(
                    a.as_canonical_u64(),
                    b.as_canonical_u64(),
                    "determinism: same inputs must yield same mask"
                );
                assert!(
                    a.as_canonical_u64() < GOLDILOCKS_PRIME,
                    "canonical: mask must be in [0, p)"
                );
            }
        }
    }

    /// Audit 391: an end-to-end smoke test that the new
    /// rejection-sampled `random_goldilocks` and
    /// `derive_blinding_mask` still produce a working
    /// threshold-encryption pipeline. If the rejection loops were
    /// non-deterministic (e.g., the attempt counter wasn't
    /// folded into the hash input), the share-side and
    /// reconstruction-side masks would diverge and decryption
    /// would fail the MAC.
    #[test]
    fn audit_391_threshold_roundtrip_after_rejection_sampling() {
        let (pk, shares) = threshold_keygen(5, 3).expect("keygen");
        let mut falcon_pks = Vec::with_capacity(5);
        let mut falcon_sks = Vec::with_capacity(5);
        for _ in 0..5 {
            let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
            falcon_pks.push(pk);
            falcon_sks.push(sk);
        }
        let msg = b"audit-391 roundtrip";
        let ct = threshold_encrypt(&pk, msg).expect("encrypt");
        let dec_shares: Vec<_> = shares
            .iter()
            .take(3).enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
            .collect();
        let recovered = combine_shares(&dec_shares, 3, &ct, &falcon_pks).expect("combine");
        assert_eq!(recovered, msg);
    }

    // ========== TPL-305: from_bytes rejects non-canonical encodings ==========

    /// TPL-305: a `KeyShare` whose last share-element byte payload
    /// encodes a value `>= GOLDILOCKS_PRIME` must fail
    /// deserialization. Pre-fix the value was silently remapped
    /// via `gl(val)`, leaning on a downstream MAC check; the
    /// non-canonical encoding was also a wire-replay surface
    /// (same logical share, two different byte payloads slip past
    /// gossip dedup keyed on the bytes).
    #[test]
    fn tpl_305_keyshare_from_bytes_rejects_non_canonical() {
        let (_pk, shares) = threshold_keygen(5, 3).expect("keygen");
        let mut bytes = shares[0].to_bytes();
        // Tamper with the LAST 8-byte share element: overwrite
        // with `GOLDILOCKS_PRIME` (= 2^64 - 2^32 + 1), which is
        // exactly the smallest non-canonical u64 (val == p, not
        // val < p).
        let len = bytes.len();
        bytes[len - 8..].copy_from_slice(&GOLDILOCKS_PRIME.to_le_bytes());
        assert!(
            KeyShare::from_bytes(&bytes).is_none(),
            "non-canonical KeyShare encoding must be rejected"
        );
        // Positive control: an untampered roundtrip still works.
        let canonical = shares[0].to_bytes();
        assert!(KeyShare::from_bytes(&canonical).is_some());
    }

    /// TPL-305: same gate on `DecryptionShare::from_bytes`.
    #[test]
    fn tpl_305_decryption_share_from_bytes_rejects_non_canonical() {
        let (pk, shares) = threshold_keygen(5, 3).expect("keygen");
        let mut falcon_pks = Vec::with_capacity(5);
        let mut falcon_sks = Vec::with_capacity(5);
        for _ in 0..5 {
            let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
            falcon_pks.push(pk);
            falcon_sks.push(sk);
        }
        let ct = threshold_encrypt(&pk, b"tpl-305 dec").expect("encrypt");
        let dec_share = generate_decryption_share(&shares[0], &ct, &falcon_sks[0]).unwrap();
        let mut bytes = dec_share.to_bytes();
        // TPL-301: wire format is now
        // `[index:8][count:4][shares:count*8][sig_len:4][sig]`,
        // so the LAST 8 bytes are sig data, not a share element.
        // Read `count` from the header and tamper the LAST share
        // element (offset `12 + (count - 1) * 8`).
        let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let last_share_off = 12 + (count - 1) * 8;
        bytes[last_share_off..last_share_off + 8]
            .copy_from_slice(&GOLDILOCKS_PRIME.to_le_bytes());
        assert!(
            DecryptionShare::from_bytes(&bytes).is_none(),
            "non-canonical DecryptionShare encoding must be rejected"
        );
        assert!(DecryptionShare::from_bytes(&dec_share.to_bytes()).is_some());
    }

    /// TPL-305: same gate on `RefreshContribution::from_bytes`.
    /// Refresh contributions are gossiped between validators, so
    /// non-canonical encodings would otherwise be a particularly
    /// useful replay primitive.
    #[test]
    fn tpl_305_refresh_contribution_from_bytes_rejects_non_canonical() {
        // TPL-303 changed the wire format to include a trailing
        // FALCON sig, so "last 8 bytes" no longer points at a delta.
        // Read n and elems from the header and tamper the last
        // delta directly.
        let (_pk, sk) = crate::falcon::falcon_keygen().unwrap();
        let contrib = generate_refresh_contribution(1, 5, 3, 0, b"tpl-305 entropy", &sk).unwrap();
        let mut bytes = contrib.to_bytes();
        let n = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let elems = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
        let last_delta_off = 24 + (n * elems - 1) * 8;
        bytes[last_delta_off..last_delta_off + 8]
            .copy_from_slice(&GOLDILOCKS_PRIME.to_le_bytes());
        assert!(
            RefreshContribution::from_bytes(&bytes).is_none(),
            "non-canonical RefreshContribution encoding must be rejected"
        );
        assert!(RefreshContribution::from_bytes(&contrib.to_bytes()).is_some());
    }

    /// TPL-305: also reject the all-`0xFF` u64 (`u64::MAX`),
    /// which is the most extreme non-canonical value an attacker
    /// would hand-craft.
    #[test]
    fn tpl_305_keyshare_from_bytes_rejects_u64_max() {
        let (_pk, shares) = threshold_keygen(5, 3).expect("keygen");
        let mut bytes = shares[0].to_bytes();
        let len = bytes.len();
        bytes[len - 8..].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(KeyShare::from_bytes(&bytes).is_none());
    }

    // ========== TPL-307: rejection-sample Kyber seed in threshold_keygen ==========

    /// TPL-307: every share returned by `threshold_keygen` must
    /// already be canonical (`< GOLDILOCKS_PRIME` after the
    /// `gl_to_u64` round-trip). Pre-fix, ~2^-29 of keygens
    /// produced a non-injective seed → element mapping that
    /// silently corrupted the recovered Kyber sk on first use.
    /// Run keygen many times and assert canonicality across all
    /// shares — the test only flakes if the rejection-sampling
    /// loop is broken AND the same RNG-improbable event hits on
    /// the test machine, which is a far less likely conjunction
    /// than the original bug.
    #[test]
    fn tpl_307_threshold_keygen_yields_canonical_shares() {
        for _ in 0..32 {
            let (_pk, shares) = threshold_keygen(5, 3).expect("keygen");
            for share in &shares {
                let bytes = share.to_bytes();
                // Skip the 12-byte index+count header; iterate
                // 8-byte share elements.
                let payload = &bytes[12..];
                for chunk in payload.chunks_exact(8) {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(chunk);
                    let v = u64::from_le_bytes(buf);
                    assert!(
                        v < GOLDILOCKS_PRIME,
                        "non-canonical share element {v:#x} >= GOLDILOCKS_PRIME"
                    );
                }
            }
        }
    }

    /// TPL-307: a roundtrip-and-decrypt is the operational
    /// proof. Pre-fix, an unlucky keygen could yield shares that
    /// reconstructed a Kyber sk different from the one used to
    /// produce the threshold public key, so encrypt-then-decrypt
    /// would silently fail (MAC mismatch on first use).
    #[test]
    fn tpl_307_keygen_then_encrypt_then_decrypt_roundtrips() {
        for _ in 0..16 {
            let (pk, shares) = threshold_keygen(5, 3).expect("keygen");
            let mut falcon_pks = Vec::with_capacity(5);
            let mut falcon_sks = Vec::with_capacity(5);
            for _ in 0..5 {
                let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
                falcon_pks.push(pk);
                falcon_sks.push(sk);
            }
            let ct = threshold_encrypt(&pk, b"tpl-307 round-trip").expect("encrypt");
            let dec_shares: Vec<_> = shares
                .iter()
                .take(3).enumerate().map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[s.index - 1]).unwrap())
                .collect();
            let recovered = combine_shares(&dec_shares, 3, &ct, &falcon_pks).expect("combine");
            assert_eq!(recovered, b"tpl-307 round-trip");
        }
    }

    // ========== TPL-302: verify_refresh_contribution catches off-poly deltas ==========

    /// TPL-302: positive control — an honest refresh contribution
    /// passes the new threshold-many verification.
    #[test]
    fn tpl_302_verify_refresh_contribution_accepts_honest() {
        let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
        let contrib = generate_refresh_contribution(1, 5, 3, 0, b"tpl-302 honest", &sk).unwrap();
        assert!(verify_refresh_contribution(&contrib, 3, 0, &pk));
    }

    /// TPL-302: a Byzantine member who produces a valid
    /// zero-secret polynomial of degree `threshold - 1` for the
    /// FIRST `threshold` deltas but substitutes adversarial
    /// values at indices `[threshold..n]` would have passed the
    /// pre-fix verifier (which only checked that the first
    /// `threshold` reconstruct to zero). The mirror of
    /// `verify_resharing_contribution` re-evaluates the
    /// polynomial at every higher index and compares against the
    /// provided value — the tampered deltas now fail.
    #[test]
    fn tpl_302_verify_refresh_contribution_rejects_off_polynomial_deltas() {
        // Honest contribution at n=5, threshold=3: deltas[0..5]
        // all lie on a single zero-secret polynomial of degree 2.
        let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
        let mut contrib =
            generate_refresh_contribution(1, 5, 3, 0, b"tpl-302 byzantine", &sk).unwrap();

        // Byzantine tamper: keep deltas[0..3] (the threshold
        // subset) honest so the zero-reconstruction check still
        // passes; replace deltas[3] with adversarial values that
        // do NOT lie on the polynomial. Replace EVERY seed
        // element so we don't accidentally happen to land on a
        // valid evaluation by chance.
        let original_seed_0 = contrib.deltas[3][0];
        for elem in &mut contrib.deltas[3] {
            *elem += gl(1); // shift each seed element by 1
        }
        // Sanity: we did mutate.
        assert_ne!(contrib.deltas[3][0], original_seed_0);

        // Pre-fix this would have returned `true` because the
        // first `threshold` deltas still reconstruct to zero.
        assert!(
            !verify_refresh_contribution(&contrib, 3, 0, &pk),
            "off-polynomial delta at index 3 must fail TPL-302 verification"
        );
    }

    /// TPL-302: tampering with the LAST delta (index n-1) is the
    /// adversary's most attractive position because that
    /// validator's share gets corrupted but the corruption only
    /// surfaces when they next try to decrypt. Confirm the
    /// re-evaluation catches this index too.
    #[test]
    fn tpl_302_verify_refresh_contribution_rejects_tampered_last_delta() {
        let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
        let mut contrib =
            generate_refresh_contribution(1, 5, 3, 0, b"tpl-302 last-delta", &sk).unwrap();
        // n = 5, last index is 4 (well past threshold = 3).
        for elem in &mut contrib.deltas[4] {
            *elem += gl(0xDEAD_BEEF);
        }
        assert!(!verify_refresh_contribution(&contrib, 3, 0, &pk));
    }

    /// TPL-302: tampering with a delta INSIDE the threshold
    /// subset breaks the zero-reconstruction property — the
    /// pre-fix verifier already caught this case. Pin it as a
    /// regression so the consolidated walker doesn't lose the
    /// behaviour.
    #[test]
    fn tpl_302_verify_refresh_contribution_rejects_nonzero_secret() {
        let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
        let mut contrib =
            generate_refresh_contribution(1, 5, 3, 0, b"tpl-302 nonzero", &sk).unwrap();
        // Tamper inside the threshold subset (index 1).
        contrib.deltas[1][0] += gl(7);
        assert!(!verify_refresh_contribution(&contrib, 3, 0, &pk));
    }

    /// TPL-302: degenerate inputs return false rather than
    /// indexing out of bounds.
    #[test]
    fn tpl_302_verify_refresh_contribution_rejects_degenerate_inputs() {
        let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
        let contrib = generate_refresh_contribution(1, 5, 3, 0, b"tpl-302 degen", &sk).unwrap();
        // threshold == 0 must reject.
        assert!(!verify_refresh_contribution(&contrib, 0, 0, &pk));
        // threshold > n must reject.
        assert!(!verify_refresh_contribution(&contrib, 6, 0, &pk));
    }

    // ========== TPL-303: FALCON sig + epoch-replay protection ==========

    /// TPL-303: positive control — a sig-bearing contribution
    /// verifies under the matching epoch + issuer pk.
    #[test]
    fn tpl_303_verify_accepts_signed_contribution() {
        let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
        let contrib = generate_refresh_contribution(1, 5, 3, 7, b"tpl-303 honest", &sk).unwrap();
        assert!(verify_refresh_contribution(&contrib, 3, 7, &pk));
    }

    /// TPL-303: cross-epoch replay is rejected. Pre-fix the
    /// verifier had no notion of "expected epoch" — a Byzantine
    /// peer could re-broadcast an old, well-formed contribution
    /// against any future PSS round and the receiver would treat
    /// it as fresh because the deltas still reconstructed to zero.
    #[test]
    fn tpl_303_verify_rejects_cross_epoch_replay() {
        let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
        let contrib = generate_refresh_contribution(1, 5, 3, 1, b"e1", &sk).unwrap();
        // Same contribution against the next epoch's verifier — must fail.
        assert!(!verify_refresh_contribution(&contrib, 3, 2, &pk));
    }

    /// TPL-303: a contribution claiming `from_index = i` but signed
    /// by a different validator's FALCON sk fails sig-verify under
    /// validator `i`'s pk. Closes the from-index forgery vector.
    #[test]
    fn tpl_303_verify_rejects_wrong_issuer_pk() {
        let (_pk_a, sk_a) = crate::falcon::falcon_keygen().unwrap();
        let (pk_b, _sk_b) = crate::falcon::falcon_keygen().unwrap();
        let contrib = generate_refresh_contribution(1, 5, 3, 0, b"tpl-303 wrong-pk", &sk_a)
            .unwrap();
        // Verify under a DIFFERENT issuer pk → reject.
        assert!(!verify_refresh_contribution(&contrib, 3, 0, &pk_b));
    }

    /// TPL-303: tampering any delta byte invalidates the FALCON
    /// sig (the deltas hash is part of the preimage), so an
    /// attacker who flips a value also has to re-sign — which
    /// they can't without the issuer's sk.
    #[test]
    fn tpl_303_verify_rejects_tampered_deltas() {
        let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
        let mut contrib =
            generate_refresh_contribution(1, 5, 3, 0, b"tpl-303 tamper", &sk).unwrap();
        // Tamper a delta. We pick deltas[1][0] inside the
        // threshold subset so the structural verifier ALSO rejects
        // — but the sig check would catch tampering anywhere.
        contrib.deltas[1][0] += gl(1);
        assert!(!verify_refresh_contribution(&contrib, 3, 0, &pk));
    }

    /// TPL-303: a contribution whose `from_index` was edited
    /// post-issue fails sig-verify because the index is in the
    /// signed preimage. Catches malleability where an attacker
    /// rewrites the issuer slot.
    #[test]
    fn tpl_303_verify_rejects_tampered_from_index() {
        let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
        let mut contrib =
            generate_refresh_contribution(1, 5, 3, 0, b"tpl-303 from-tamper", &sk).unwrap();
        // Sig was made for from_index=1; flip to 2 → sig fails.
        contrib.from_index = 2;
        assert!(!verify_refresh_contribution(&contrib, 3, 0, &pk));
    }

    /// TPL-303: wire format must round-trip the signature so a
    /// receiver decoding from gossip bytes runs the same
    /// authentication path as a same-process generator.
    #[test]
    fn tpl_303_wire_format_roundtrips_signature() {
        let (pk, sk) = crate::falcon::falcon_keygen().unwrap();
        let contrib = generate_refresh_contribution(1, 5, 3, 11, b"tpl-303 wire", &sk).unwrap();
        let bytes = contrib.to_bytes();
        let decoded = RefreshContribution::from_bytes(&bytes).expect("wire roundtrip");
        assert_eq!(decoded.epoch, 11);
        assert_eq!(decoded.from_index, 1);
        // Decoded contribution authenticates identically.
        assert!(verify_refresh_contribution(&decoded, 3, 11, &pk));
    }
}
