use alloc::vec::Vec;

use crate::falcon::{FalconPublicKey, FalconSecretKey, falcon_sign, falcon_verify};
use crate::hash::Hash256;
use crate::poseidon2::poseidon2_hash;

/// VRF output: a 32-byte pseudorandom value derived deterministically from (sk, input).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfOutput(Hash256);

/// VRF proof: a FALCON signature that allows anyone to verify the output was computed correctly.
#[derive(Clone, Debug)]
pub struct VrfProof(Vec<u8>);

const VRF_DOMAIN_OUTPUT: &[u8] = b"pyde-vrf-output-v1";
const VRF_DOMAIN_PROOF: &[u8] = b"pyde-vrf-proof-v1";

impl VrfOutput {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn to_hash(&self) -> Hash256 {
        self.0
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
/// The output is: Poseidon2(domain || sk_fingerprint || input)
/// where sk_fingerprint = Poseidon2(domain || sk_bytes).
fn compute_vrf_output(sk: &FalconSecretKey, input: &[u8]) -> VrfOutput {
    // Derive a deterministic fingerprint from the secret key
    let mut sk_input = Vec::with_capacity(VRF_DOMAIN_OUTPUT.len() + sk.as_bytes().len());
    sk_input.extend_from_slice(VRF_DOMAIN_OUTPUT);
    sk_input.extend_from_slice(sk.as_bytes());
    let sk_fingerprint = poseidon2_hash(&sk_input);

    // Compute output = H(domain || fingerprint || input)
    let mut output_input =
        Vec::with_capacity(VRF_DOMAIN_OUTPUT.len() + 32 + input.len());
    output_input.extend_from_slice(VRF_DOMAIN_OUTPUT);
    output_input.extend_from_slice(sk_fingerprint.as_bytes());
    output_input.extend_from_slice(input);
    VrfOutput(poseidon2_hash(&output_input))
}

/// Build the message that gets signed/verified for the VRF proof.
fn build_proof_message(input: &[u8], output: &VrfOutput) -> Vec<u8> {
    let mut msg = Vec::with_capacity(VRF_DOMAIN_PROOF.len() + input.len() + 32);
    msg.extend_from_slice(VRF_DOMAIN_PROOF);
    msg.extend_from_slice(input);
    msg.extend_from_slice(output.as_bytes());
    msg
}

/// Generate a VRF output and proof.
/// The output is deterministic given (sk, input).
/// The proof is a FALCON signature over (input || output).
pub fn vrf_prove(sk: &FalconSecretKey, input: &[u8]) -> (VrfOutput, VrfProof) {
    let output = compute_vrf_output(sk, input);
    let proof_msg = build_proof_message(input, &output);
    let sig = falcon_sign(sk, &proof_msg);
    (output, VrfProof(sig.to_vec()))
}

/// Verify a VRF output and proof against a public key.
/// Returns true if the proof is valid and the output matches.
pub fn vrf_verify(
    pk: &FalconPublicKey,
    input: &[u8],
    output: &VrfOutput,
    proof: &VrfProof,
) -> bool {
    let proof_msg = build_proof_message(input, output);
    let sig = crate::falcon::FalconSignature::from_bytes(&proof.0);
    falcon_verify(pk, &proof_msg, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::falcon::falcon_keygen;

    #[test]
    fn vrf_prove_verify_roundtrip() {
        let (pk, sk) = falcon_keygen();
        let input = b"test vrf input";
        let (output, proof) = vrf_prove(&sk, input);
        assert!(vrf_verify(&pk, input, &output, &proof));
    }

    #[test]
    fn vrf_deterministic_output() {
        let (_pk, sk) = falcon_keygen();
        let input = b"deterministic test";
        let (output1, _proof1) = vrf_prove(&sk, input);
        let (output2, _proof2) = vrf_prove(&sk, input);
        assert_eq!(output1, output2, "VRF output must be deterministic");
    }

    #[test]
    fn vrf_different_keys_different_outputs() {
        let (_pk1, sk1) = falcon_keygen();
        let (_pk2, sk2) = falcon_keygen();
        let input = b"same input different keys";
        let (output1, _) = vrf_prove(&sk1, input);
        let (output2, _) = vrf_prove(&sk2, input);
        assert_ne!(output1, output2);
    }

    #[test]
    fn vrf_different_inputs_different_outputs() {
        let (_pk, sk) = falcon_keygen();
        let (output1, _) = vrf_prove(&sk, b"input A");
        let (output2, _) = vrf_prove(&sk, b"input B");
        assert_ne!(output1, output2);
    }

    #[test]
    fn vrf_wrong_key_verify_fails() {
        let (_pk1, sk1) = falcon_keygen();
        let (pk2, _sk2) = falcon_keygen();
        let input = b"wrong key test";
        let (output, proof) = vrf_prove(&sk1, input);
        assert!(!vrf_verify(&pk2, input, &output, &proof));
    }

    #[test]
    fn vrf_tampered_output_fails() {
        let (pk, sk) = falcon_keygen();
        let input = b"tamper test";
        let (_output, proof) = vrf_prove(&sk, input);

        // Create a fake output
        let fake_output = VrfOutput(poseidon2_hash(b"fake"));
        assert!(!vrf_verify(&pk, input, &fake_output, &proof));
    }

    #[test]
    fn vrf_wrong_input_fails() {
        let (pk, sk) = falcon_keygen();
        let (output, proof) = vrf_prove(&sk, b"correct input");
        assert!(!vrf_verify(&pk, b"wrong input", &output, &proof));
    }

    #[test]
    fn vrf_output_distribution() {
        // Chi-squared test: generate many VRF outputs and check byte distribution
        let (_pk, sk) = falcon_keygen();
        let num_samples = 256;
        let mut byte_counts = [0u32; 256];

        for i in 0..num_samples {
            let input = (i as u64).to_le_bytes();
            let (output, _) = vrf_prove(&sk, &input);
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
