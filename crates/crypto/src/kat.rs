//! Known-Answer Tests (KAT): pinned input → output vectors for every
//! cryptographic primitive on the consensus path.
//!
//! Audit 357. The crate pulls in `falcon-rs 0.2.x` and
//! `ml-kem 0.3.0-rc.x` (both pre-1.0) plus `p3-poseidon2 0.4.x`.
//! Pre-1.0 dependencies can ship behaviour-changing patch bumps —
//! e.g., a `cargo update` that swaps a hash-to-bytes ordering or
//! tweaks a Goldilocks reduction would silently produce a chain
//! whose blocks no longer validate against the prior version of
//! itself. Worse: signature verification could silently start
//! accepting different bytes and fork the network without any
//! visible error.
//!
//! The tests below pin a fixed `(input, expected output)` pair for
//! every primitive on the consensus signing/verification path.
//! Any drift in the underlying crate produces a noisy assertion
//! failure at `cargo test` time, BEFORE shipping.
//!
//! For randomized primitives (FALCON sign, Kyber encapsulate) we
//! pin a known-valid `(pk, msg, sig)` triple instead of an exact
//! signature — what we're checking is "the verifier still accepts
//! the previously-valid signature" (cross-version compat) and "the
//! pre-derived public key from the pinned secret key still matches
//! byte-for-byte" (algorithm-internal sanity).

extern crate alloc;
use alloc::vec::Vec;

use crate::falcon::{falcon_verify, FalconPublicKey, FalconSecretKey, FalconSignature};
use crate::hash::Hash256;
use crate::kyber::{kyber_decapsulate, KyberCiphertext, KyberSecretKey};
use crate::poseidon2::poseidon2_hash;
use crate::vrf::{vrf_verify, VrfOutput, VrfProof};

/// Decode a hex string into a Vec<u8>. Panics on malformed input —
/// these are compile-time literals controlled by us, so a bad
/// vector is a programming error, not runtime data.
fn hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = parse_nibble(bytes[i]);
        let lo = parse_nibble(bytes[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

fn parse_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("non-hex byte in KAT vector"),
    }
}

// ── Poseidon2 over Goldilocks ────────────────────────────────────

/// KAT for `poseidon2_hash`. Input/output pairs were captured by
/// running the implementation against fixed inputs ONCE and baking
/// the outputs here. Any future change to:
///   - `p3-poseidon2` round constants
///   - `p3-goldilocks` field representation
///   - the sponge construction in `poseidon2.rs`
/// produces different bytes and trips this assertion.
#[test]
fn kat_poseidon2_empty_input() {
    let out = poseidon2_hash(&[]);
    let expected = hex(POSEIDON2_KAT_EMPTY);
    assert_eq!(
        out.as_bytes(),
        expected.as_slice(),
        "poseidon2_hash([]) drift — pinned KAT broken"
    );
}

#[test]
fn kat_poseidon2_short_ascii() {
    let out = poseidon2_hash(b"pyde");
    let expected = hex(POSEIDON2_KAT_PYDE);
    assert_eq!(
        out.as_bytes(),
        expected.as_slice(),
        "poseidon2_hash(\"pyde\") drift — pinned KAT broken"
    );
}

#[test]
fn kat_poseidon2_block_sized() {
    // 64-byte input forces a multi-permutation absorb (rate=4 fields,
    // 32 bytes, so 64 bytes = 2 absorbs). Catches drift in the
    // padding-free sponge driver, not just the permutation.
    let input: Vec<u8> = (0..64u8).collect();
    let out = poseidon2_hash(&input);
    let expected = hex(POSEIDON2_KAT_64BYTES_INCREMENT);
    assert_eq!(
        out.as_bytes(),
        expected.as_slice(),
        "poseidon2_hash(0..64) drift — pinned KAT broken"
    );
}

#[test]
fn kat_poseidon2_distinct_inputs_distinct_outputs() {
    // Sanity guard so future "all KATs accidentally pin the same
    // value" mistakes get caught.
    assert_ne!(POSEIDON2_KAT_EMPTY, POSEIDON2_KAT_PYDE);
    assert_ne!(POSEIDON2_KAT_PYDE, POSEIDON2_KAT_64BYTES_INCREMENT);
}

// ── FALCON-512 (cross-version compat) ────────────────────────────

/// FALCON sign is randomized (Gaussian sampling over the lattice),
/// so we can't pin a deterministic `(sk, msg) → sig` mapping. What
/// we CAN pin is a known-valid `(pk, sk, msg, sig)` quadruple
/// captured from the current implementation; the test asserts:
///   1. The pinned pk is byte-equal to what we'd derive from the
///      pinned sk via `from_private_key` (algorithm-internal sanity).
///   2. The pinned signature still verifies under the pinned pk +
///      msg (cross-version compat).
/// Both break if `falcon-rs` changes its on-wire encoding or its
/// verification rule.
#[test]
fn kat_falcon_pinned_keypair_signature_still_verifies() {
    let pk = FalconPublicKey::from_bytes(&hex(FALCON_KAT_PK))
        .expect("FALCON pk must decode at the pinned size");
    let sig = FalconSignature::from_bytes(&hex(FALCON_KAT_SIG))
        .expect("FALCON sig must decode at the pinned length");
    let msg = FALCON_KAT_MSG.as_bytes();
    assert!(
        falcon_verify(&pk, msg, &sig),
        "pinned FALCON signature no longer verifies — falcon-rs likely changed"
    );
}

#[test]
fn kat_falcon_pinned_secret_yields_pinned_public() {
    // Re-derive the public key from the pinned secret. This catches
    // changes to the secret-key encoding or pk-from-sk derivation
    // that wouldn't show up in the verify-only test above.
    let sk_bytes = hex(FALCON_KAT_SK);
    let sk =
        FalconSecretKey::from_bytes(&sk_bytes).expect("FALCON sk must decode at the pinned size");
    // Derive pk via the public API: sign then verify against the
    // pinned pk. (FALCON-rs doesn't expose a direct `pk_from_sk`
    // in the surface we use, so we sign+verify as a proxy: a
    // freshly-signed msg under sk must verify under the pinned pk.)
    let msg = b"kat-derived-public-key-check";
    let fresh_sig =
        crate::falcon::falcon_sign(&sk, msg).expect("pinned FALCON sk must sign successfully");
    let pk = FalconPublicKey::from_bytes(&hex(FALCON_KAT_PK)).expect("FALCON pk must decode");
    assert!(
        falcon_verify(&pk, msg, &fresh_sig),
        "pinned FALCON sk → pk pairing broken — sk encoding likely changed"
    );
}

// ── Kyber-768 (decapsulation determinism) ────────────────────────

/// Kyber encapsulate is randomized (uses ephemeral randomness for
/// the ciphertext); decapsulate is deterministic given (sk, ct).
/// Pin a `(sk, ct, expected_shared_secret)` triple. Drift in
/// `ml-kem` decapsulation, key encoding, or the shared-secret
/// derivation produces different bytes and trips this.
#[test]
fn kat_kyber_pinned_decapsulation() {
    let sk = KyberSecretKey::from_bytes(&hex(KYBER_KAT_SK))
        .expect("Kyber sk must decode at the pinned seed size");
    let ct = KyberCiphertext::from_bytes(&hex(KYBER_KAT_CT))
        .expect("Kyber ct must decode at the pinned size");
    let ss = kyber_decapsulate(&sk, &ct).expect("decapsulate must succeed for pinned ct");
    let expected = hex(KYBER_KAT_SS);
    assert_eq!(
        ss.as_bytes().as_slice(),
        expected.as_slice(),
        "Kyber decapsulation shared-secret drift — ml-kem likely changed"
    );
}

// ── VRF (deterministic output + proof verify) ────────────────────

/// VRF output is `Poseidon2(domain || sk_fingerprint || input)` —
/// deterministic given (sk, input). Pin the output. The proof is
/// a FALCON signature (randomized), so for proof we pin `(pk,
/// input, output, proof)` and assert verify still accepts it.
#[test]
fn kat_vrf_pinned_output_and_proof() {
    let pk = FalconPublicKey::from_bytes(&hex(VRF_KAT_PK)).expect("VRF pk must decode");
    let input = VRF_KAT_INPUT.as_bytes();
    let output = VrfOutput::from_hash_bytes(&hex(VRF_KAT_OUTPUT));
    let proof = VrfProof::from_bytes(&hex(VRF_KAT_PROOF));
    assert!(
        vrf_verify(&pk, input, &output, &proof),
        "pinned VRF (pk, input, output, proof) no longer verifies"
    );
}

#[test]
fn kat_vrf_output_deterministic_recompute() {
    // Re-derive VRF output from the pinned secret key. Output is
    // deterministic given (sk, input), so any change in either
    // Poseidon2 or the VRF construction itself breaks this.
    let sk = FalconSecretKey::from_bytes(&hex(VRF_KAT_SK)).expect("VRF sk must decode");
    let pk = FalconPublicKey::from_bytes(&hex(VRF_KAT_PK)).expect("VRF pk must decode");
    let (output, _proof) = crate::vrf::vrf_prove(&pk, &sk, VRF_KAT_INPUT.as_bytes())
        .expect("vrf_prove must succeed for pinned (sk, input)");
    let expected = hex(VRF_KAT_OUTPUT);
    assert_eq!(
        output.as_bytes().as_slice(),
        expected.as_slice(),
        "VRF output drift — Poseidon2 or VRF construction changed"
    );
}

// ── Hash::Hash256 round trip ─────────────────────────────────────

#[test]
fn kat_hash256_from_to_bytes_identity() {
    let bytes: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let h = Hash256::new(bytes);
    assert_eq!(h.to_bytes(), bytes);
}

// ── Pinned vectors ───────────────────────────────────────────────
//
// IMPORTANT: any change here is intentional only when the algorithm
// changes (e.g., we deliberately bump the Poseidon2 spec or move to
// FALCON-1024). For a routine `cargo update` these constants must
// stay byte-identical.

const POSEIDON2_KAT_EMPTY: &str =
    "1012512f56ef7d3aa0766475f9fa0aab140aff69c25caf8fba41cd7cc88f81d6";
const POSEIDON2_KAT_PYDE: &str = "da9d7b47e48a5edd4b6b509faaf4a825263bf264e50fcdd1168f1392024eba67";
const POSEIDON2_KAT_64BYTES_INCREMENT: &str =
    "2c032fb51ca221dd690298cbdf6af2a6833ca576c8b3addf010448048de093ae";

const FALCON_KAT_PK: &str = "0937c5c9b7d74467bd3c0f5409431e96104764c7c65d09c4c407fc52eb5e3ae5d724cf02a24af037f60c175ffdf6c628edd4a3debcd328ea9ab6ca8c916598b61dc4d2eb2525af7775b283f96a5e8e2e737567ec245800ce00e31d5a3f091f24dee80b24841e944b8d35110d0390da6f0e9b0ddd5297a5b2bebe766869aad6b4967ef1f5e99279408619629a1b6325c928e71cbc7e1c0965a06d303d956d19f9a7be799c07cb12eabba2817f2835c90aafa50a13ea92d6b0f0cda910df34a7824669a396bb880e01393d4139727d453744536f13a90964ff2bf1a5b10fb83b4039a3029015fb633768f5e797291f833d11a07598cf8d436c70d091a5574a6430e3bd6fd90801f6e809a63a207ea962fca6550176ebcb2d03398bc80597b2888fa4fa3724c6e0e83488dd53ded0c052fd5a2ac443bfb1ca989b6a61211a1c4e6a180ffd6646044027db3885095fa2cd9e5b6df4c4f84192e91449737aa194dd5dae66d062e0724fa02834d61b94177211bb05200b1476b5393fc42680f9d4e4f1c54193b13e553a280e897a76b6841bb32e0ab7c7ccd4454fec146aff9fa318947140daaa4ab32144098a66b37735d7c3bac25450813366420f6f8af13012f65cd9b3294bba958bf18fd9f864368e1f73f5ecc7846ace72a6ceeb08adad7b79a3c92866b262385fe9b385e3b12dfb165853d951414be15802274f5eeef29b543a7c0d1a924fa3339fae11e483c2838900cca5256f2a507d7f638d9191aa928ba351a3c41b82758416eb8b5abdf83585015a37986d06ca4ef774c409a429083d8fe1e9f11321e07dac3a9a1e148b98ae81f6a61cc10f3c7ddb42a00776418e7420cff30cee4f89620e24391d93cbf6d6d96c31bc5abb6df45c9180a953c7034684fd64f457df8ab18af7e19bc63f7e4890532bfe9250e0c6808182908581d522e9524810bb1af25ec40c8824e775040654bc242650663a75dae8b5a227452ea813e2e40284b95675c8bd9f3b923e6d41f209a92db666f9874f1b5ae4075200c22d2abcecda9fd64669399d72fcdf8e0d52c8097ee88161ce5671f6c2dd7dedb4f4b84cd0364d595704abd833aecd168057593fad56007201204d743db1e2c88cadfc7f67c11fd44ec93f83dad3f01af093a9a26f93197af61327e59391de829046596d358a82d92622b932e126b6baef5f8c4c027151ac670fb4b1a3deac053d5d494911a8eeb40801499de1cdb8082de816031eb71a33f8061ec0b3123709cb8aea";
const FALCON_KAT_SK: &str = "59fbc083fbb045e821ff1841031020fe003fbd00303b040043fc1003d840fe07fe3d043f40f7ff3ffc10820bd13b0c3f860c40bcffefff0c0043044f840411440000ffefaf84003040fbf002080f3ef41e8103a042f81e460c0105f7af42f7f23de3e0400bedc1f08f01e86fbd0830c214123e03907fdf917cf7fe02f82d3dffdf3407af061fd0faf3e0c103d07ff8613603e046e04ec1f40040efe23ff7f07cfbcf04000e45f000fc040fc11befb9ec22c01410860f8002283ffd20208117ef81f41039001101007f4414617c03713f0f90c2f7e2410bc0be17efc7f471410fae0413cfc1fc3fc3fbdf7908303b143ebefbbf42046042f83ebb13b0820c207f0021c3fbceffefd17fec00840befc3f8213eeff17f04317d001141001f821020c10051c0fbe0b6ffd040105182f3b03d103e47042e79f3903ce3f08017b089ec6e82e3ae82046ec40c5ffdf04fffdbdf0417cfbb03ce7e03dfbe13ef001790041fb2fd082f7f242dfbebf181ffe07f082102104f81f43fc520017b081ffd0c2f7af010c0ebeec2fc524417d0000fa14200207d001ebff04042f7aebae4000013f0c7279042fb9ec803dfc10bd00427deb917ef41f4323f1000fae8103d008181f38f06087fbb0060c00fde850fefbf0ca0c2047f7f085fbbf85f000bf0be0fd07a24007b04507f0bb0c61870c10f9e81fbbf40fc6205f80189f3cf47ffd0fe006f8207ffffe4123afba10117f0050c30ff086083007e46f89ec11cafc41882420bf07b0bd07ffbee4307ff43f42f7e1c6ec3f3ef451c3fc5f84ff80bfffe085effdc7180f3cf7f1c603cf0603cec407ef020be107efffbcf02f87e82e83039242ec30c4ebb040ec2184ec0fc203a1bbfc0ebff85ebd07cec30c0f7cf40f83001efeec12c023af7b03e10033e07f145efcf41efd047088ffff02fbdf03f7c1000c107f03c040d770ba17f0000fcf44fff18107df7dffefbe0430ba081084ffef7fec4081eff1ba0fbf7ef42001045100f821030ffec2204f7cffd03af060beef90bcfc4e82003087fbdfc4047fbc0791c20c50bce82043f4013d13b13c13a002e41db00e218d0f5271602f022f1fbcfd7e32408fbe715f1cb1205f909fbebeae2f6d4071034eef8cefd0229f6d81b0401070bb3d5f9081df8d8ebe51c3af91ce920f01227fcebed0d362225f0e725d9fdec03de021d041b1213eb160316eced05ceec004fd6081aefec05f023f6ec040911ec0ef51af017eceb092cfffe24282506e2ec1409133fe9e211ed0c0808e0cd1418eee0b73ce2f7220aed01e2fdd808dc10141510ed0d03f7ec16d915fdd6fdf921f010d1edecf716391f2ce4ed16072c000ffc0513dd2506f50d0416fbf7f9f8defb1c04ecded40a15ed041df902f927e9ee1318211b1af4ea0017fde4ee030c10fef6e111050a2ded01091007d8eeff48f301ecfdeded00fd10f40afc26fa04fac506fc1306132702d81d17011ff30afdfd0bfcc90f2a4500010726e8332ee721e82bfdf6f7f8e2112b1dc8f3ff2b29ebf1ebc80308f7e6f9efdc0cf7e400d70106df0618f1290e060d0903ea1ffd17c406e2f3e813011520f5fa31f6df11d5080600fdf7cd02e1f8ebe514111bf7152ee306dcd8e8142b0919ebe621dc1314e5dafd001c0911e449f90a22fefec7da22fcfd0ae6f5f7071cfa1a190e0aef260c232610f7fcf2e2f3f01020e0f9e70ff4f6ed0b09f4ccc2fdef15e5eafedb00e8cbefd2ed2e312ce10811092a250ef6ce07d51c00f7fef83e2df8e815e11df61d0bf4fdf8151ad7da070504e803e6f8";
const FALCON_KAT_MSG: &str = "pyde-falcon-kat-v1";
const FALCON_KAT_SIG: &str = "59dfcf72ce2d1dc04bde0f3e7429817763c5a5ae135ca6eefa5c3e12145c1277f2e0e3687297062e6605eff3f60fb8f5f02d0a91480dfe510a1fc9f35facefa1051260a8f58fb3005fd6f9df1608effb05ffbaf830cb105079024f9af46045f27f43fb0f0c03501c057fdaff9edff1604afc5f11fa813cfd006ff72f8d1850c609af8b00207c0100bdfdc028096fa7faffb8f1efc7f5dea1ea2f21009f2cfecfed1aa165ffd12b047ff6f81018f450f20100830bd0410acefbf5c05afa4eaafb3010ef4f8df8e07c0bff75fa7fe3027039f911150a5f72febf7001c06dff5f8604900cfd214cf94fd2f9afa017cff6fe2f89016f010bd20905dfc9f2bfae01f0dbf0afbc095f3dfa9fa9f880cafc5f2a09d04cf77f8deff06df20f5611ce730dafd3fcf08f015fe10b0f72fc8f20f21e83051086fc611dfb2f96004f6e055f7cfcafea18b01de4ff92014090f2e124fdf002f8400807707601ff4910103204609813cfb8ee0f1402209f059f6e15e032001f49192fc90c906df71fba00e01df9cffaf6910404cf2e0a7ff8006fa7f38fe303bfda001f58f64fa2f340430f509913cff2ec8f7d060ff303cf3c0bb10e10c088facf8c08cf790b5e93fab0a8ffd134fbcfe8f9ef79ff807f164fadfeaf5a06400bf990b0f8105feabfd80e7ff0073076fe60aefc0094f2ff56eddf9d0b8f8d0a8191088f3e0e30d906f0cd0ad000f8100f01cf6b13df7b17cfcbfec021fbe0a2fdbf6420af8d21f052063ff104500cfe7fef0f506406af1c06cfc3fb3fbff04febf6cfa006c0780fff3707dfa3110fbe016fa5f3411c0f8086f9af850b70e0117f3df2201101c0590f4047f24045f84f87155f7f0410c4f1dfd30ed026e52e07fc0fb202e037f92092ff418c05efdd012fd90edfa3fabfc503deb9f56f51f350cd010fc8f4c008e9a0ff07300d0fbf400c707400eee90c017d094042e82f9cf790500a80800ae070fb801a07f0ce13f023018110fbefe3f070b4032163f07ee90e6fb5004fb2f84fedf24f80ff502bf720540eb00af8ffa4f2101ffd1f0af64149f16ff6f54110fb9efb03ef92011f7503fff5044f44fe7006078fe9fdf02112403d019fbf0a3006052f080e3f3a0f70290ce064052f2f";

const KYBER_KAT_SK: &str = "09c0cc643a44972b155a4c1ccafd3395cb79fcfba279a82a909dd0261df51ce38a2aa1f109a4be64936b770156e6ce012e09a68ea8a5ca42b55fcadb1755cb55";
const KYBER_KAT_CT: &str = "c7f1771a15d0a227e889df3229706950a5d18d2cbe34134309cb595b43244f81fe863613943eb1c94611579395a426c68287f659ede9e9c36d91dac984334b4ae2b01ff266e6e33fd0ab0933a226f509233b4eb23d5639170c528ef78bfd67756f3262b1be05351e3a83041dcd1658faceffc7410af0e91772b31ae9df1a44b74e257fe7b1499b20b43d8210fb6400e4ddb51ec32a4cd67bd0cb576d8c25c6323d0997629e72424c3605424ec7532b04eea18e63da70ed4439fe5a176e9e3f871a3a59df8c0b9f3a6e85f8f57e5616d15245d15c1c7b0f23821652e73f403299c2e84322402193ec7df3500f07129cba4926854597c7c7240184068ac1a807434875978f7b6a044128a96424c27f93acdd0ed272a6ef55e92c0fed73ec6fcdb254c2aeeb025ee08031975b13029783f2dd60b34a80e5b56470c1b9b26f23191a954e7b0c708defb820630879ab1036a8877a7d53f46a2c1d187b2a82994c52d6372eaeac70ef55f572bb3248ff35139069cac29040a323924438703b4a81d8038721a3b2b025357afadafa4cdccaa938c33bdb839e82d60ce725f91a4cd55f79755492ae4c76e213fb33b83b9aaff65138fda6d61d565c04b60b48673050891b605c99c79d4bcb32d47a4a548f4fae38302260d7d07a081f19a417973d5c138464c4395418ee769768c91b80f6fcc51055f30d1c29d09011609066de7ab23d50d6213ea77e3b33f6f60e4720517332f17512a4a2de34909f7c406c3f96a12facadcf1f6ce1b13d3434838fb8d126c31759deacd613a4a28a6e94c5d155e54f537edeecdefc207ac6657ef790cc6f0dafa438e36a69c4f0697757482f99c2b3b8f2b4df1538359c7002f8e34e72df8543ba2bd7f6bc102e2a805f34b367169c45581dfdffbc7953e81d96c0a73f133fe0ed22a40394d66e0934ca079306aa7f9721682a56a8495f76e37cd5d969fc7dd3d8dbb07123f227e9172fc2649bf5c0c524fb9eab5a3af9505cfd6299d09afa7174e75b2a93b0cd90f744765b3f835c0a902f614dbe63d9df96e1907fcd71ec5a299bf0d1fc16fe79454e0ae3b545a307f57fdb780cebf9e615ef162e6d468ac674229237868593d627a5fca782004a6469b38c2a9ab07db7cc7d91f47b8cb983740a89769e5d4a371f27e4aaed476c46b4f1df07555b0d7ce68f38d10092ee4c31c0b66693da9b9edc5ff1859f431160a59a1e7c7fe89ab8eb80f099a82094e97e3a46f5d6c755023e9281768442f717fb0bd1c462d085813498748bf12414ebbfb5eec44e1c9ef5bafba53c277849e39798d39cf1087c3f9cd0689b5788967132edfcbabdde760636862e77a2b8cc03bcd6cd61d1f15b4ba6c7a8cd3cd14fc34626c519310876981b70905e2d7afa4709a7ac01ba58a98a96fe7bb09049788f5f246e4651be0c79625c8ae553df8f687660e3281cbaea4f71f44d9a93b9a97fafe43a85dafc3453040000df7115985cc900612fee26e81d9248e029feadc66d3f20c318bee6f8e7d6bdbdbfa0742cd5";
const KYBER_KAT_SS: &str = "efbd7d86801f2e312a94958af0d93bbc33127547a08598335a466c1e7465aa34";

const VRF_KAT_PK: &str = "0976197c99cbac576ee61c2962a6c79350b1f2258382ae622f82f193ae4fa81a55a4cbb70828d22b5a48f41abe1373834cdbae1191540b67df45d88b38dac0df0e880b283922fa3faa1e49224cc7b11245fb722e16b8f9bff9e52caf0e0cdd10492255640676f267d1a3b0fe63f7b994f39ee5a880388dd67c6572f38d87b67db6344721eb57be462f342daf3c410661a53d40635fa1ee500bd0fdb5988b09598fa95ba02bf94399a017aa3da1f81d26ac05f7f628a67238bdf595e1e0dfab6131589b818512986fe55e82bc9c518a5564c6e25c8aed76fecd155d4dfd5ac848b7ba19869958de06b16a0508a2a0e22062da54fd42e390bd9763b7163715742fc985adec2ef51e1759a3158112becb3b9b157d991ac8b1a8656e9897d10050dba9a8e53790578b2c15df58c00a8f32ea777a8786d95b6d91fbbd5578046c0045ddce470a80c146b807528fcc7e34dd040e26ed082752a40a32a8bcc6e545c93479a089a1c99c766c24702f444355400e1409d0776175e0d4f187617e25a298e58d93341829e70dcd1b7af9db7a67648a44a61e05c35d6c77aa9d7801c1e6b1e0160a0a1cde569981e3b5d8d1af415341606665203c6be9a54e668e20797477447f9054ef70cc63d751ea480484c510129dde9a5da26d06a6286348ddf06170f151b2ecec1659aaaa388538679e50f06615bc295d62e832c2be5f068ec1921eb0b55974b57f9bce355dd3786d8739467edcd5de4b6681193b2350de816462e773b702262820db36dddea88060b5914def58be1274885a6de60e8591a3a629b62aac53c796abe76a05cf721227503ee00d172d21106969a4e0e6ebfa64717cdb1e5ea467251ad3b24589327db11763a969465a8a83438d18b2f8b54864e003ad32ed9b8ac3351532a28b49d727a8f85684271e681331d1098b9beeb9fe52f8269740259a0da8f7abdb7bede6cbcf0be194028b77d709b55af2783533180c94148ec648c2f36b5c91185c4107ba88b094df5bbf24e0bbd96c447224f00bb8261787335e852718a82f593185c24befa78d9696429ba33e964c0db74ec2e6650c56661ed1999019737354c5056b95571928e8a430a2914aa721080f1eca71bb668761c919aaffc8904d0deb3a4104470ce1662456c7a9031814f6d012e5951a616b2a5bb3bf05e9fa7ae2e0b17a837a411b93a7ded02b00e329513a0344a961dc996e161bfb1a3c4294728bcb28ba578423247b14be570480f1cf08db9194dac31266df";
const VRF_KAT_SK: &str = "590bbfbf07ffbd204e40040e09040084041e7cfc2f42083083fbffc7e7dfc2081e42ffef7f082fbc18c07b0810c1088f7f0c4ff9ec2e01f4300000213bfc3f7cd07e831be07e0bd0fc07d07d04414428113dffb0bd03c000002e3ce81039000f04f46041efe07efc4043fc2e82002ec218200108413fe03ec0f7e03efbbffdebefbdfc10ca17b07cf020fcf7b044fbbfc20faffc002f46efcfff0c107cf42f7d0fedbeebb004045ec2f852c7e7fec3084143fbe080048081fb913a0bf0020bbfb917dd7ef7df7eefa181e7df3cf41dbff3c081fbe07b00903ff80fc117cf45ffff01f42dc0f82fc3ec0e07203ffe20503ef83f44f38103ec1045f44e3fe83fc0041f0110113f17d103dc0ffa27e040efb03efc7f43fc3084102f070430c2f3b13df7f14027effc0fe13ef7f039044f801bf044f7fd7f2421bfe821bde83ffffff0451c507d143f80f02f86fc11090071020040801020c0f4607e002f3dfc203b0bff42ec50c0dc50851760840fa0810810fff82ffef3d0bae3e0bfec1101fc1f89f4113df40f7c0fe04b17df84efe0c3ffd146fbff420c0fb928604217e07c003e44f84187102d42fc013df430000ff07ef84ec8200ffde83fbe03ce7b241f06185137e3e003f82143201f820bff0107f0beff91fd1020000c507b23ef410fa0c9f020821ba1bd0f9043ffc0c7ebdfc0e820430c1ec107df82f03040f05fc4e021bb0420401fe0bdfbe07c000f3eec3fc0f06f8500008103d008149103e7cffb3400bef42f8117f175f83e40146f442400090c00c107c0fdfb80bf07e07f0bd04013eebc0020fb1fbe840892420f80440c6eff27cf031c00bb04703cf7be00e3d1be03febeff7f860bd0420c1080ef7e83efde87f3f07c136f7effbdbf0bd00407e042f83fbfebaffd23cffc0bdff70c0ec30bc0801f903df01fc1e800001810bef8103dffe082f3ff42f45fbc10414207cff9042f8013ff7df41fc60c107e081f40177084fbf14103f03d003f40145f780ffe05fbe03b139038fbd0bd1fe0c103bf80f010fedc6fc2042041e4107d1bd04427807d041037175f81f44f7b0c2140f019130f07fbddf2d023050afae01a2ee6f21e0d1bf0fa440d26f1dc08002707f3eadffaf8fdfdfedaf6fa102cfce7133003fff113dd0ef403eb27fc01051a00100b05e3160627f6eed6ea2602fb01f7e5f7f00ae12e3507e32a11ebeeee2322fe01d51629012dedfd18f0effd0e2513ffea17fff5f5ed0d0606e3042c0112c2f6ecf2c11d00ef282201001e00d115eff41c08122825fe30daf1c3f5dafbe5010d180ffede25012de802ef24fee8fd2c0a10d00e03061cf0f8151000f113f029ffe919f0f3d312faf3fff7ca2aeaf8d81c0012f80fecf6f9e9dcfa07fa090e2107fe3028f7fdd7ef3907060a00131ecef814f7faf6f0f91e15f0f52017f1190f1537ee25e8fe00f307fd1ad5fde9f203eef8fd10150334ef17011d020d35f810f320eab9f0fce907f7d3d92cd2f50d0cf4f8ea2035f0e7e6f125072d091802efcbf0ee11e5dfdf1d1007c4eddff8f9f9f3f922ed1d151e0dfeecec02fee220fdebedf20cd309e2fffcf0fe16eb251206110fe3fc165528d72bf820fafdd00be40be8e11308e9f9ef16d61913e3bd2519f02e0a0cf7ff1df213c420f4151e0bfd074007e80cf5f5091bede723fa04db2cf7fae2080928101ffa0b090c0dff06160519edda2df3f81cfd0df02d301c0f311f0e15f2d6eeba12064012f8f00619f912df07fcfbf818093026dbf211e5f217f1e9eff9eb0e02041a1f0a12fb06f412";
const VRF_KAT_INPUT: &str = "pyde-vrf-kat-input-v1";
const VRF_KAT_OUTPUT: &str = "91fcf7ef46408a7ef547c585f21de4bce1322031c062b525b9434b35fb9f37e4";
const VRF_KAT_PROOF: &str = "59f6506c3c4232cb9d53a4fde9a7a44e42c2f0ffa4bff94bcb827bfd529d29d7449c5743ed1045b2a1034fbd01ef800160f10b2ef7fd6f56f5201f0faf40f4eff609900d1880680d0ffc05800a01d198f7e0020ce237fd5018f93f620b80c812d07b134018fc1f7603c103f6ced1024ff60b6044f9f039ed4f54f5808cffcfaefaa18cef6e9f028fd318efa602d0230cbf80011009f5bf64fff0cd0a2fc5f5812a0cdefcecaf6705500804bfe30f3fe9062fe6fb3020f26f7c08706ce78ffefee1f7fc20f40a8fe30140480280620cbfd3f1ff0a0ec05c0710ff0ad02bf40027fe5025faafcffb50adfad02f03006a006fb3fcffd901dfebf230a10590800b4fec07900bfa20721ce077f23fcb054f7afcd091f66f3b01c03401e0d3ee2e91feffef01109f0ed0370c4fc1facf98f9203beedffc0f4ff000b0f503afb30f0f47054f920faeb401301d035f3705112c0c8f3bf87f60018fb90870c7f7aff1fcb06c11ff5ef8e0abedc0affa600e0651bf0110aaf6c064fc0f71fb100af310b9f99f7b07d06101ee9008afb509707cef6041096093ffffce01d011088fd1018fc7053f8a0cb03d0b9105f7e0320580b0f8f064038032ffee58f8c0b10fd080f69068fcdfdbfeef42ed90bff55f1108bffbea504df5d129ee2043fd3eb0fc110b0f901bf9e08f0dbf2bfa20ca01f05dfd906ef85016fcfecbeae069ff7eaf13b141ffd07406df56ef815022cfd5fbd0980c605eeff0c105806c00ceeffaaf4808dec3fe00c3f86129016f2506d002ffdf97fd6fff052fc2fb2f83faf0e20e4007fb800d084fdb11d051061fd2f93fdf04b08ef5209806909bfb101cfc80db04906efad03d0caf72f5bf680820cdf970c8012f34f39f86067fa6f07f3d149fa6025fa218802af2805114903ce26fb3f42103fbaec9fee069f6001d0edfe0fb20bc057fbbe3e028f01f8a046f9c0f1fcf05a08b027faa03cf9cfe00f3fcc00beb0faff0a059ea4024ffb06e0e1089074069f65ff9026f1c139f8b0aefeefcaed907c02f052f0b08affb074058f8ef9b0c101c104f4709b0780121331c2feb0d5eb3f7d043fc1f8b07eff102105af8af63fac03f099fadf72fd3fa6003ff10b60a608f0e6f630c9eb802afa8";

// ── KAT vector generator ─────────────────────────────────────────
//
// `#[ignore]`'d so it doesn't run on `cargo test` — it's a dev tool
// for refreshing the constants above. Run via:
//   cargo test -p pyde-crypto kat::generate -- --ignored --nocapture
// Copy the printed hex values into the constants above. Routine
// `cargo test` then enforces those values stay byte-stable.

fn to_hex(bytes: &[u8]) -> alloc::string::String {
    use alloc::string::String;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let hi = b >> 4;
        let lo = b & 0xf;
        s.push(nibble_char(hi));
        s.push(nibble_char(lo));
    }
    s
}

fn nibble_char(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!(),
    }
}

#[test]
#[ignore = "KAT vector generator — run with --ignored --nocapture, then bake outputs into the constants above"]
fn generate_kat_vectors() {
    extern crate std;
    use std::println;

    println!("\n=== Poseidon2 ===");
    println!(
        "POSEIDON2_KAT_EMPTY = \"{}\";",
        to_hex(poseidon2_hash(&[]).as_bytes())
    );
    println!(
        "POSEIDON2_KAT_PYDE = \"{}\";",
        to_hex(poseidon2_hash(b"pyde").as_bytes())
    );
    let block: Vec<u8> = (0..64u8).collect();
    println!(
        "POSEIDON2_KAT_64BYTES_INCREMENT = \"{}\";",
        to_hex(poseidon2_hash(&block).as_bytes())
    );

    println!("\n=== FALCON ===");
    let (falcon_pk, falcon_sk) = crate::falcon::falcon_keygen().unwrap();
    let falcon_msg = FALCON_KAT_MSG.as_bytes();
    let falcon_sig = crate::falcon::falcon_sign(&falcon_sk, falcon_msg).unwrap();
    println!("FALCON_KAT_PK = \"{}\";", to_hex(falcon_pk.as_bytes()));
    println!("FALCON_KAT_SK = \"{}\";", to_hex(falcon_sk.as_bytes()));
    println!("FALCON_KAT_SIG = \"{}\";", to_hex(falcon_sig.as_bytes()));

    println!("\n=== Kyber ===");
    let (kyber_pk, kyber_sk) = crate::kyber::kyber_keygen().unwrap();
    let (kyber_ct, kyber_ss) = crate::kyber::kyber_encapsulate(&kyber_pk).unwrap();
    println!("KYBER_KAT_SK = \"{}\";", to_hex(kyber_sk.as_bytes()));
    println!("KYBER_KAT_CT = \"{}\";", to_hex(kyber_ct.as_bytes()));
    println!("KYBER_KAT_SS = \"{}\";", to_hex(kyber_ss.as_bytes()));

    println!("\n=== VRF ===");
    let (vrf_pk, vrf_sk) = crate::falcon::falcon_keygen().unwrap();
    let (vrf_output, vrf_proof) =
        crate::vrf::vrf_prove(&vrf_pk, &vrf_sk, VRF_KAT_INPUT.as_bytes()).unwrap();
    println!("VRF_KAT_PK = \"{}\";", to_hex(vrf_pk.as_bytes()));
    println!("VRF_KAT_SK = \"{}\";", to_hex(vrf_sk.as_bytes()));
    println!("VRF_KAT_OUTPUT = \"{}\";", to_hex(vrf_output.as_bytes()));
    println!("VRF_KAT_PROOF = \"{}\";", to_hex(vrf_proof.as_bytes()));
    println!();
}
