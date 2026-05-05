use alloc::vec::Vec;

use crate::falcon::{falcon_sign, falcon_verify, FalconPublicKey, FalconSecretKey};
use crate::hash::Hash256;
use crate::poseidon2::poseidon2_hash;

/// VRF output: a 32-byte pseudorandom value derived deterministically from (sk, input).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfOutput(Hash256);

/// VRF proof: a FALCON signature that allows anyone to verify the output was computed correctly.
#[derive(Clone, Debug)]
pub struct VrfProof(Vec<u8>);

// Audit 393: separate domain tags per hash usage. Pre-fix, both
// `compute_vrf_output`'s sk-fingerprint hash and its output hash
// shared a single tag, so the two distinct cryptographic roles
// (key-binding vs. output derivation) collapsed into the same
// hash domain. Splitting them follows standard hash-domain-
// separation hygiene and matches the audit recommendation.
const VRF_FINGERPRINT_DOMAIN: &[u8] = b"pyde-vrf-sk-fingerprint-v1";
const VRF_OUTPUT_DOMAIN: &[u8] = b"pyde-vrf-output-v1";
const VRF_DOMAIN_PROOF: &[u8] = b"pyde-vrf-proof-v1";

impl VrfOutput {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn to_hash(&self) -> Hash256 {
        self.0
    }

    /// Reconstruct a VrfOutput from raw 32-byte hash.
    pub fn from_hash_bytes(bytes: &[u8]) -> Self {
        let mut arr = [0u8; 32];
        let len = bytes.len().min(32);
        arr[..len].copy_from_slice(&bytes[..len]);
        Self(Hash256::from(arr))
    }
}

impl VrfProof {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

/// Compute VRF output deterministically from secret key and input.
/// The output is: Poseidon2(VRF_OUTPUT_DOMAIN || sk_fingerprint || input)
/// where sk_fingerprint = Poseidon2(VRF_FINGERPRINT_DOMAIN || sk_bytes).
/// Audit 393: the two hashes use distinct domain tags so the
/// fingerprint can never be confused with an output value (or vice
/// versa) by any analysis that depends on hash-domain separation.
fn compute_vrf_output(sk: &FalconSecretKey, input: &[u8]) -> VrfOutput {
    // Derive a deterministic fingerprint from the secret key.
    let mut sk_input = Vec::with_capacity(VRF_FINGERPRINT_DOMAIN.len() + sk.as_bytes().len());
    sk_input.extend_from_slice(VRF_FINGERPRINT_DOMAIN);
    sk_input.extend_from_slice(sk.as_bytes());
    let sk_fingerprint = poseidon2_hash(&sk_input);

    // Compute output = H(output_domain || fingerprint || input).
    let mut output_input = Vec::with_capacity(VRF_OUTPUT_DOMAIN.len() + 32 + input.len());
    output_input.extend_from_slice(VRF_OUTPUT_DOMAIN);
    output_input.extend_from_slice(sk_fingerprint.as_bytes());
    output_input.extend_from_slice(input);
    VrfOutput(poseidon2_hash(&output_input))
}

/// Build the message that gets signed/verified for the VRF proof.
/// Includes the public key to bind the output to a specific key.
fn build_proof_message(pk: &FalconPublicKey, input: &[u8], output: &VrfOutput) -> Vec<u8> {
    let mut msg =
        Vec::with_capacity(VRF_DOMAIN_PROOF.len() + pk.as_bytes().len() + input.len() + 32);
    msg.extend_from_slice(VRF_DOMAIN_PROOF);
    msg.extend_from_slice(pk.as_bytes());
    msg.extend_from_slice(input);
    msg.extend_from_slice(output.as_bytes());
    msg
}

/// Generate a VRF output and proof.
/// The output is deterministic given (sk, input).
/// The proof is a FALCON signature over (pk || input || output).
pub fn vrf_prove(
    pk: &FalconPublicKey,
    sk: &FalconSecretKey,
    input: &[u8],
) -> Result<(VrfOutput, VrfProof), &'static str> {
    let output = compute_vrf_output(sk, input);
    let proof_msg = build_proof_message(pk, input, &output);
    let sig = falcon_sign(sk, &proof_msg)?;
    Ok((output, VrfProof(sig.to_vec())))
}

/// Verify a VRF output and proof against a public key.
/// Returns true if the proof is valid and the output matches.
pub fn vrf_verify(
    pk: &FalconPublicKey,
    input: &[u8],
    output: &VrfOutput,
    proof: &VrfProof,
) -> bool {
    let sig = match crate::falcon::FalconSignature::from_bytes(&proof.0) {
        Some(s) => s,
        None => return false,
    };
    let proof_msg = build_proof_message(pk, input, output);
    falcon_verify(pk, &proof_msg, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::falcon::falcon_keygen;

    #[test]
    fn vrf_prove_verify_roundtrip() {
        let (pk, sk) = falcon_keygen().unwrap();
        let input = b"test vrf input";
        let (output, proof) = vrf_prove(&pk, &sk, input).unwrap();
        assert!(vrf_verify(&pk, input, &output, &proof));
    }

    #[test]
    fn vrf_deterministic_output() {
        let (pk, sk) = falcon_keygen().unwrap();
        let input = b"deterministic test";
        let (output1, _proof1) = vrf_prove(&pk, &sk, input).unwrap();
        let (output2, _proof2) = vrf_prove(&pk, &sk, input).unwrap();
        assert_eq!(output1, output2, "VRF output must be deterministic");
    }

    #[test]
    fn vrf_different_keys_different_outputs() {
        let (pk1, sk1) = falcon_keygen().unwrap();
        let (pk2, sk2) = falcon_keygen().unwrap();
        let input = b"same input different keys";
        let (output1, _) = vrf_prove(&pk1, &sk1, input).unwrap();
        let (output2, _) = vrf_prove(&pk2, &sk2, input).unwrap();
        assert_ne!(output1, output2);
    }

    #[test]
    fn vrf_different_inputs_different_outputs() {
        let (pk, sk) = falcon_keygen().unwrap();
        let (output1, _) = vrf_prove(&pk, &sk, b"input A").unwrap();
        let (output2, _) = vrf_prove(&pk, &sk, b"input B").unwrap();
        assert_ne!(output1, output2);
    }

    #[test]
    fn vrf_wrong_key_verify_fails() {
        let (pk1, sk1) = falcon_keygen().unwrap();
        let (pk2, _sk2) = falcon_keygen().unwrap();
        let input = b"wrong key test";
        let (output, proof) = vrf_prove(&pk1, &sk1, input).unwrap();
        assert!(!vrf_verify(&pk2, input, &output, &proof));
    }

    #[test]
    fn vrf_tampered_output_fails() {
        let (pk, sk) = falcon_keygen().unwrap();
        let input = b"tamper test";
        let (_output, proof) = vrf_prove(&pk, &sk, input).unwrap();

        // Create a fake output
        let fake_output = VrfOutput(poseidon2_hash(b"fake"));
        assert!(!vrf_verify(&pk, input, &fake_output, &proof));
    }

    #[test]
    fn vrf_wrong_input_fails() {
        let (pk, sk) = falcon_keygen().unwrap();
        let (output, proof) = vrf_prove(&pk, &sk, b"correct input").unwrap();
        assert!(!vrf_verify(&pk, b"wrong input", &output, &proof));
    }

    #[test]
    fn vrf_output_distribution() {
        // Chi-squared test: generate many VRF outputs and check byte distribution
        let (pk, sk) = falcon_keygen().unwrap();
        let num_samples = 256;
        let mut byte_counts = [0u32; 256];

        for i in 0..num_samples {
            let input = (i as u64).to_le_bytes();
            let (output, _) = vrf_prove(&pk, &sk, &input).unwrap();
            for &byte in output.as_bytes().iter() {
                byte_counts[byte as usize] += 1;
            }
        }

        // Total bytes = 256 samples * 32 bytes = 8192
        // Expected per bucket = 8192 / 256 = 32
        let total_bytes = (num_samples * 32) as f64;
        let expected = total_bytes / 256.0;
        let chi_squared: f64 = byte_counts
            .iter()
            .map(|&count| {
                let diff = count as f64 - expected;
                diff * diff / expected
            })
            .sum();

        // Chi-squared critical value for 255 df at p=0.001 is ~310
        // A truly random distribution should be well below this
        assert!(
            chi_squared < 350.0,
            "VRF output distribution failed chi-squared test: {} (expected < 350)",
            chi_squared
        );
    }
}
