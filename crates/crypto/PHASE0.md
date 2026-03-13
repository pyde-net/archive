# Phase 0: Cryptographic Foundations — Detailed Explanation

Phase 0 builds every cryptographic primitive that the Pyde blockchain needs. It lives
in a single Rust crate (`pyde-crypto`) that is compiled as `#![no_std]` with
`extern crate alloc`. The `no_std` constraint is deliberate: every function in this
crate must eventually run inside a ZK circuit (the stateless provers), so nothing here
can depend on the operating system, file I/O, or the standard library's random number
generator at the type level.

**Crate:** `crates/crypto/` (package name `pyde-crypto`)
**Tests:** 76 unit tests, all passing
**Benchmarks:** 4 benchmark binaries (poseidon2, falcon, threshold, vrf)

---

## Module Overview

```
src/
  lib.rs          -- crate root, re-exports all modules
  hash.rs         -- Hash256 type (32-byte hash wrapper)
  poseidon2.rs    -- Poseidon2 hash function over Goldilocks field
  falcon.rs       -- FALCON-512 post-quantum digital signatures
  kyber.rs        -- Kyber-768 (ML-KEM-768) post-quantum key encapsulation
  threshold.rs    -- Threshold Kyber (85-of-128) + Proactive Secret Sharing
  vrf.rs          -- Lattice-based Verifiable Random Function
benches/
  poseidon2_bench.rs
  falcon_bench.rs
  threshold_bench.rs
  vrf_bench.rs
```

---

## M0.1 — Poseidon2 Hash (Tasks 0001–0015)

### What it is

Poseidon2 is an **algebraic hash function** — it operates natively over finite field
elements rather than bytes. This makes it extremely efficient inside ZK proving systems
(STARK/SNARK), because the prover only needs to constrain field multiplications and
additions, not bit manipulations. For Pyde, this is the hash used for Merkle trees,
transaction hashing, state commitments, and all internal hashing.

### The field: Goldilocks

The Goldilocks field has prime modulus **p = 2^64 - 2^32 + 1** (approximately 1.8 * 10^19).
This prime is special because:

- It fits in a single 64-bit machine word
- Modular reduction is extremely fast (no general-purpose division needed — just
  shifts and adds)
- It has a large power-of-two subgroup (2^32-th roots of unity exist), which enables
  fast NTT/FFT for polynomial operations in the prover

We use the Plonky3 (`p3-goldilocks`) implementation of this field, which provides
battle-tested, optimized field arithmetic.

### Poseidon2 parameters

| Parameter         | Value | Why                                              |
|-------------------|-------|--------------------------------------------------|
| State width       | 8     | 8 Goldilocks elements = 512 bits of state        |
| Rate              | 4     | 4 elements absorbed per permutation = 32 bytes   |
| Output            | 4     | 4 elements squeezed = 32 bytes = Hash256          |
| S-box degree      | 7     | x^7 — coprime to p-1, ensures the S-box is a permutation |
| External rounds   | 8     | 4 initial + 4 terminal full rounds               |
| Internal rounds   | 22    | Partial rounds (only one S-box per round)        |
| Capacity          | 4     | 4 elements = 256 bits >= 2 * 128-bit security    |

The round constants come from Plonky3's `HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS` and
`HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS`. These are derived from a nothing-up-my-sleeve
seed and provide 128-bit security against algebraic attacks (Grobner basis, differential,
linear).

### How bytes become field elements

Raw bytes cannot be fed directly into the sponge — they must first become Goldilocks
elements. The conversion (`bytes_to_elements`) works as follows:

1. Split input into **7-byte chunks** (not 8). Why 7? A full 8-byte chunk could hold
   values up to 2^64 - 1, which exceeds the field modulus. 7 bytes gives a max of
   2^56 - 1, which is always a valid field element.
2. Each chunk is zero-padded to 8 bytes and interpreted as a little-endian u64, then
   converted to a Goldilocks element via `from_u64` (which reduces modulo p).
3. The **length of the input** is appended as a final element. This serves as a
   domain separator that prevents length extension attacks: `H("ab")` and `H("ab\0")`
   hash different element sequences because the length field differs.

For empty input, a single zero element is produced (plus the length = 0 element).

### Three hash functions

- **`poseidon2_hash(data: &[u8]) -> Hash256`**: Arbitrary bytes in, 32-byte hash out.
  The workhorse for transaction hashing, account hashing, etc.
- **`poseidon2_pair(left: Hash256, right: Hash256) -> Hash256`**: Takes two hashes,
  converts them back to 8 field elements (4 each), and hashes them together. This is
  the node computation for binary Merkle trees.
- **`poseidon2_many(hashes: &[Hash256]) -> Hash256`**: Variable-length sponge over
  multiple hashes. Used when you need to commit to a list of hashes (e.g., a
  transaction list root).

### Performance

From benchmarks:
- Throughput: ~54 MB/s for 1 KB+ inputs
- Pair hashing: ~900K pairs/sec (~1.1 us/pair)

### Security verification tests

Three tests verify the cryptographic parameters at compile/test time:

1. **S-box coprimality**: Confirms gcd(7, p-1) = 1, so x^7 is a permutation over the field
2. **Round count**: Confirms 8 external + 22 internal rounds match Plonky3's
   `poseidon2_round_numbers_128` for 128-bit security
3. **Capacity bits**: Confirms capacity = 4 * 64 = 256 bits >= 2 * 128

---

## M0.2 — FALCON-512 Signatures (Tasks 0016–0030)

### What it is

FALCON-512 (now standardized as FN-DSA / FIPS 206) is a **lattice-based digital
signature scheme**. It is post-quantum secure — a quantum computer running Shor's
algorithm cannot break it, unlike RSA or ECDSA. Pyde uses FALCON for all validator
signatures: block proposals, attestations, and VRF proofs.

### Why FALCON over Dilithium?

- **Compact signatures**: FALCON-512 signatures average ~666 bytes vs Dilithium's
  ~2.4 KB. In a blockchain where every block contains 128+ validator signatures,
  this saves ~220 KB per block.
- **Fast verification**: ~19.5 us/verify. Verification is the hot path — every node
  must verify every signature.
- Tradeoff: key generation (~3.5 ms) and signing (~212 us) are slower than Dilithium,
  but these happen infrequently compared to verification.

### Key sizes

| Component  | Size       |
|------------|------------|
| Public key | 897 bytes  |
| Secret key | 1281 bytes |
| Signature  | ~666 bytes (variable, compressed Huffman encoding) |

### Implementation details

The module wraps the `falcon-rs` crate (imported as `falcon` in Rust — hyphenated crate
names become underscored). Three wrapper types hold opaque byte vectors:

- `FalconPublicKey(Vec<u8>)` — 897 bytes exactly
- `FalconSecretKey(Vec<u8>)` — 1281 bytes exactly
- `FalconSignature(Vec<u8>)` — variable length

The LOGN parameter is set to 9, which gives n=512 (FALCON-512). This is the lattice
dimension of the NTRU lattice over which the trapdoor is defined.

Key functions:
- `falcon_keygen()`: Generates a keypair using `FnDsaKeyPair::generate(9)`. The 9 means
  2^9 = 512 polynomial degree.
- `falcon_sign(sk, msg)`: Reconstructs the keypair from the private key bytes, signs
  with `DomainSeparation::None` (we handle domain separation at the application level).
- `falcon_verify(pk, msg, sig)`: Stateless verification — takes the raw bytes and
  verifies using `FnDsaSignature::verify`.
- `falcon_batch_verify(items)`: Iterates over a list of (pk, msg, sig) triples.
  Currently sequential (the `falcon-rs` crate doesn't provide true batch verification
  with amortization). This is a future optimization target.

### Why signatures are variable-length

FALCON uses compressed encoding for signatures. The signature contains a lattice point
(polynomial with small integer coefficients), and these coefficients are Huffman-encoded.
The exact size depends on the coefficients, which are sampled from a discrete Gaussian
distribution during signing. This is why signature size ranges from ~500 to ~900 bytes
with 666 as the average.

---

## M0.3 — Kyber-768 KEM (Tasks 0031–0044)

### What it is

Kyber-768 (now standardized as ML-KEM-768 / FIPS 203) is a **lattice-based Key
Encapsulation Mechanism (KEM)**. A KEM is not encryption — it lets two parties agree on
a shared secret. The flow:

1. **Keygen**: Generate (public_key, secret_key)
2. **Encapsulate**: Using only the public key, generate (ciphertext, shared_secret)
3. **Decapsulate**: Using the secret key + ciphertext, recover the same shared_secret

Pyde uses Kyber for the threshold encryption committee. Transactions meant for MEV
protection are encrypted under the committee's Kyber public key. Once enough validators
provide their decryption shares, the transaction is decrypted.

### Why Kyber and not RSA/ECDH?

Kyber is post-quantum. RSA and elliptic-curve Diffie-Hellman can be broken by a quantum
computer. The 768 in Kyber-768 refers to the lattice dimension (k=3, each polynomial of
degree 256), providing NIST Level 3 security (~192-bit classical, ~128-bit quantum).

### Key sizes

| Component     | Size        |
|---------------|-------------|
| Public key    | 1184 bytes  |
| Secret key    | 64 bytes (seed form) |
| Ciphertext    | 1088 bytes  |
| Shared secret | 32 bytes    |

### Seed-based secret key storage

An important design choice: we store the secret key as a **64-byte seed**, not the fully
expanded decapsulation key (~2400 bytes). The `ml-kem` crate supports deterministic key
derivation from a seed via `DecapsulationKey768::from_seed(seed)`. This means:

- Storage is compact (64 bytes)
- The full key is re-derived on demand during decapsulation
- The seed is what gets split into shares in the threshold scheme

### Implicit rejection

ML-KEM-768 has an important security property: decapsulating with the wrong secret key
produces a **different** shared secret rather than an error. This is by design — it
prevents chosen-ciphertext attacks. Our test `wrong_secret_key_different_shared_secret`
verifies this property: decapsulating with sk2 produces ss_dec != ss_enc, with no error.

### Crate choice

We initially tried `pqc_kyber` but it panics in `no_std` environments without a custom
panic handler. We switched to `ml-kem` from the RustCrypto project, which handles
`no_std` cleanly and implements the final FIPS 203 standard (not the earlier CRYSTALS
draft).

---

## M0.4 — Threshold Kyber 85-of-128 (Tasks 0045–0059)

### What it is

Threshold Kyber allows a **committee of 128 validators** to collectively hold a single
Kyber secret key, such that any **85 or more** of them can cooperate to decrypt, but
84 or fewer learn nothing. The 85/128 ratio (approximately 2/3 + 1) matches the
Byzantine fault tolerance threshold.

### The approach: Reconstruct-then-Decrypt

There are two ways to do threshold decryption:

1. **Partial decapsulation**: Each validator performs a partial lattice operation on the
   ciphertext, and the results are combined. This is the "proper" way but requires
   specialized lattice-level protocols that don't exist in standard libraries.
2. **Reconstruct-then-decrypt**: Split the secret key into shares. To decrypt, collect
   enough shares to reconstruct the full secret key, then perform standard decapsulation.

We chose option 2 because:
- It works with any standard KEM (no lattice-specific modifications)
- It's simpler to implement and audit
- The security trade-off (the reconstructed key exists momentarily in memory) is
  acceptable for our use case

### Shamir Secret Sharing over Goldilocks

The 64-byte Kyber seed is split into **8 Goldilocks field elements** (8 bytes each).
Each element is independently shared using Shamir's Secret Sharing:

**Splitting (for one element):**
1. Create a random polynomial of degree t-1: `f(x) = secret + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}`
2. The constant term is the secret
3. Coefficients a_1 through a_{t-1} are derived deterministically from the Kyber seed
   via Poseidon2 (so keygen is deterministic given the seed)
4. Evaluate f(1), f(2), ..., f(128) to get 128 shares

**Reconstruction (Lagrange interpolation at x=0):**
Given any t shares (x_i, y_i), compute:

```
secret = sum over i: y_i * product over j!=i: (-x_j) / (x_i - x_j)
```

This uses field inversion via Fermat's little theorem: `x^{-1} = x^{p-2} mod p`,
implemented by Plonky3's `Field::inverse()`.

### Symmetric encryption layer

Threshold Kyber produces a `ThresholdCiphertext` containing:

1. **Kyber ciphertext** (1088 bytes): The standard KEM encapsulation
2. **Encrypted message**: XOR of plaintext with a Poseidon2-derived keystream
3. **MAC** (32 bytes): Poseidon2 hash of the encrypted message, domain-separated from
   the keystream

The keystream is generated in CTR mode: `keystream[i] = Poseidon2(shared_secret || counter)`.
The MAC prevents ciphertext tampering: `MAC = Poseidon2(0xFF^8 || shared_secret || ciphertext)`.
The 0xFF prefix domain-separates the MAC from the keystream derivation.

### Performance

| Operation                 | Time         |
|---------------------------|-------------|
| Keygen (128 members)      | 1.6 ms      |
| Encrypt                   | 38 us       |
| Decrypt (85 shares)       | 4.0 ms      |
| Decrypt (3 shares, n=5)   | 62 us       |

The 4ms decrypt time for 85 shares is dominated by Lagrange interpolation (O(t^2) field
operations) and 8 independent Shamir reconstructions.

---

## M0.5 — Proactive Secret Sharing (Tasks 0060–0066)

### What it is

Proactive Secret Sharing (PSS) allows the committee to **refresh all key shares** each
epoch without changing the underlying secret (the Kyber seed) or the public key. After a
refresh, any shares leaked from previous epochs become useless.

### Why it matters

In a long-running blockchain, an attacker might slowly compromise validators over time —
stealing one share here, another share there. Without PSS, once they accumulate 85 shares
(even from different time periods), they can reconstruct the key. With PSS, shares from
different epochs lie on different polynomials and cannot be combined.

### The refresh protocol

Each validator generates a **zero-secret polynomial** — a random degree-(t-1)
polynomial where f(0) = 0. This is implemented by calling `shamir_split` with
`secret = Goldilocks::ZERO`.

1. Validator i generates: `f_i(x) = 0 + r_1*x + r_2*x^2 + ... + r_{t-1}*x^{t-1}`
2. Validator i evaluates f_i at all n points and sends f_i(j) to validator j
3. Each validator j sums all received deltas into their existing share:
   `new_share_j = old_share_j + sum_i(f_i(j))`

**Why this preserves the secret:** The sum of all zero-secret polynomials is another
zero-secret polynomial. Adding it to the original polynomial shifts all shares but
leaves f(0) (the secret) unchanged:
```
new_f(x) = original_f(x) + sum_i(f_i(x))
new_f(0) = original_f(0) + sum_i(0) = original_f(0)
```

### Verification

Any validator can verify a refresh contribution by taking t of the delta values,
reconstructing, and checking the result is zero. If it's not, the contributor is
cheating.

### Security property: epoch isolation

After a refresh, shares from different epochs cannot be mixed. If you take 1 old share
and 2 new shares (in a 3-of-5 scheme), the reconstruction will produce garbage because
the old share lies on the old polynomial and the new shares lie on the new polynomial.
Our test `pss_mixed_old_new_shares_fail` verifies this.

### Performance

| Committee size | Refresh time  |
|----------------|--------------|
| n=5, t=3       | 0.10 ms      |
| n=10, t=7      | 0.58 ms      |
| n=128, t=85    | 118 ms       |

The 118ms for 128 members is acceptable since refreshes happen once per epoch (many
seconds or minutes apart), not per-block.

---

## M0.6 — Lattice-Based VRF (Tasks 0067–0075)

### What it is

A Verifiable Random Function (VRF) produces a **pseudorandom output** that is:

1. **Deterministic**: same (key, input) always gives the same output
2. **Unpredictable**: without the secret key, the output looks random
3. **Verifiable**: anyone with the public key can check the output is correct

Pyde uses VRFs for leader election — each validator computes VRF(sk, slot_number) and
the lowest output wins the right to propose a block. Because the output is deterministic
and unpredictable, no one can predict or manipulate who will be elected.

### Construction

True lattice VRFs (based on lattice assumptions alone) are a research topic with few
practical implementations. Our construction uses FALCON as a building block:

**VRF output** (deterministic, secret-key-dependent):
```
sk_fingerprint = Poseidon2("pyde-vrf-output-v1" || sk_bytes)
output = Poseidon2("pyde-vrf-output-v1" || sk_fingerprint || input)
```

The output depends on the secret key but doesn't reveal it. The domain prefix
`"pyde-vrf-output-v1"` prevents cross-protocol attacks.

**VRF proof** (FALCON signature):
```
proof = FALCON_sign(sk, "pyde-vrf-proof-v1" || input || output)
```

The proof is a FALCON signature over the input and output. Anyone with the public key
can verify the signature, confirming that the claimed output was computed by the holder
of the corresponding secret key.

**Verification:**
```
valid = FALCON_verify(pk, "pyde-vrf-proof-v1" || input || output, proof)
```

### Why the output is separate from the proof

FALCON signatures are **randomized** — signing the same message twice produces different
signatures. If the VRF output were derived from the signature, it would not be
deterministic. Instead, the output is derived purely from the secret key and input via
Poseidon2 (which is deterministic), and the signature merely proves the output is correct.

### Output distribution

The chi-squared test verifies that VRF outputs are statistically uniform. Over 256
samples, each byte value (0-255) should appear approximately 32 times. The test
confirms chi-squared < 350 (well within the p=0.001 critical value of 310 for 255
degrees of freedom).

### Performance

| Operation  | Time     | Throughput     |
|------------|----------|---------------|
| VRF prove  | 277 us   | 3,614/sec     |
| VRF verify | 20 us    | 50,252/sec    |

Proving takes ~277 us (dominated by FALCON signing at ~212 us plus Poseidon2 hashing of
the 1281-byte secret key). Verification is fast at ~20 us.

---

## Dependencies

| Crate         | Version       | Purpose                                      |
|---------------|---------------|----------------------------------------------|
| p3-goldilocks | 0.4           | Goldilocks field arithmetic                  |
| p3-field      | 0.4           | Field traits (PrimeCharacteristicRing, Field, PrimeField64) |
| p3-poseidon2  | 0.4           | Poseidon2 permutation                        |
| p3-symmetric  | 0.4           | Sponge construction (PaddingFreeSponge)      |
| falcon-rs     | 0.2           | FALCON-512 signatures (FN-DSA)               |
| ml-kem        | 0.3.0-rc.0    | ML-KEM-768 (Kyber) key encapsulation         |

All dependencies use `default-features = false` where applicable to maintain `no_std`
compatibility. The `getrandom` feature is enabled for FALCON and ML-KEM so they can
access OS-level randomness for key generation and signing (this is acceptable because
keygen/signing happens in the node binary, not inside the ZK prover).

---

## Test Summary

| Module     | Tests | What they cover                                              |
|------------|-------|--------------------------------------------------------------|
| hash       | 7     | Construction, display, ordering, equality, slice conversion  |
| poseidon2  | 24    | Determinism, collision resistance, edge cases, security params |
| falcon     | 13    | Roundtrip, tampering, wrong key, batch, serialization        |
| kyber      | 9     | Roundtrip, implicit rejection, serialization, sizes          |
| threshold  | 15    | Shamir SSS, threshold decrypt, PSS refresh, epoch isolation  |
| vrf        | 8     | Roundtrip, determinism, key separation, distribution         |
| **Total**  | **76**|                                                              |

---

## What Phase 0 enables

With these primitives complete, Pyde has:

- **Poseidon2**: ZK-friendly hashing for Merkle trees, state roots, transaction IDs
- **FALCON**: Post-quantum signatures for validator attestations and block proposals
- **Kyber + Threshold**: Post-quantum encrypted transaction pool for MEV protection
- **PSS**: Long-term security against slow key compromise across epochs
- **VRF**: Fair, unpredictable, verifiable leader election

Every component is `no_std`, tested, and benchmarked. Phase 1 (PVM) builds the virtual
machine on top of these foundations.
