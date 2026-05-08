use std::time::Instant;

use pyde_crypto::falcon::falcon_keygen;
use pyde_crypto::threshold::{
    combine_shares, generate_decryption_share, pss_refresh, threshold_encrypt, threshold_keygen,
    EpochKeyMaterial,
};

fn bench_keygen() {
    println!("=== Threshold Kyber keygen ===\n");

    for (n, t) in [(5, 3), (10, 7), (128, 85)] {
        let iterations = if n <= 10 { 100 } else { 10 };
        let start = Instant::now();
        for _ in 0..iterations {
            // Bench measures keygen latency; unwrap to consume the
            // `#[must_use]` Result and fail loudly on unexpected error.
            let _ = std::hint::black_box(threshold_keygen(n, t).unwrap());
        }
        let elapsed = start.elapsed();
        println!(
            "  n={:<3} t={:<3}: {:.2}ms/keygen",
            n,
            t,
            elapsed.as_millis() as f64 / iterations as f64,
        );
    }
}

fn bench_encrypt() {
    println!("\n=== Threshold Kyber encrypt ===\n");
    let (tpk, _shares) = threshold_keygen(128, 85).unwrap();
    let msg = b"benchmark message for threshold encryption";
    let iterations = 100;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = std::hint::black_box(threshold_encrypt(&tpk, std::hint::black_box(msg)));
    }
    let elapsed = start.elapsed();
    println!(
        "  {:.1}µs/encrypt  ({:.0} encrypts/sec)",
        elapsed.as_micros() as f64 / iterations as f64,
        iterations as f64 / elapsed.as_secs_f64()
    );
}

fn bench_decrypt() {
    println!("\n=== Threshold Kyber decrypt (combine_shares) ===\n");

    for (n, t) in [(5, 3), (10, 7), (128, 85)] {
        let (tpk, shares) = threshold_keygen(n, t).unwrap();
        let msg = b"benchmark message for threshold decryption";
        let ct = threshold_encrypt(&tpk, msg).unwrap();

        // TPL-301: each decryption share now carries a FALCON sig.
        let mut falcon_pks = Vec::with_capacity(n);
        let mut falcon_sks = Vec::with_capacity(n);
        for _ in 0..n {
            let (pk, sk) = falcon_keygen().unwrap();
            falcon_pks.push(pk);
            falcon_sks.push(sk);
        }
        let dec_shares: Vec<_> = shares[..t]
            .iter()
            .enumerate()
            .map(|(i, s)| generate_decryption_share(s, &ct, &falcon_sks[i]).unwrap())
            .collect();

        let iterations = if n <= 10 { 1000 } else { 100 };
        let start = Instant::now();
        for _ in 0..iterations {
            std::hint::black_box(combine_shares(
                std::hint::black_box(&dec_shares),
                t,
                std::hint::black_box(&ct),
                std::hint::black_box(&falcon_pks),
            ))
            .unwrap();
        }
        let elapsed = start.elapsed();
        println!(
            "  n={:<3} t={:<3}: {:.1}µs/decrypt  ({:.0} decrypts/sec)",
            n,
            t,
            elapsed.as_micros() as f64 / iterations as f64,
            iterations as f64 / elapsed.as_secs_f64()
        );
    }
}

fn bench_pss_refresh() {
    println!("\n=== PSS Refresh ===\n");

    for (n, t) in [(5, 3), (10, 7), (128, 85)] {
        let (tpk, shares) = threshold_keygen(n, t).unwrap();
        let epoch_mat = EpochKeyMaterial {
            epoch: 0,
            n,
            threshold: t,
            tpk,
        };

        let iterations = if n <= 10 { 100 } else { 5 };
        let start = Instant::now();
        for i in 0..iterations {
            let mut current_mat = epoch_mat.clone();
            current_mat.epoch = i as u64;
            std::hint::black_box(pss_refresh(&current_mat, std::hint::black_box(&shares)));
        }
        let elapsed = start.elapsed();
        println!(
            "  n={:<3} t={:<3}: {:.2}ms/refresh",
            n,
            t,
            elapsed.as_millis() as f64 / iterations as f64,
        );
    }
}

fn main() {
    bench_keygen();
    bench_encrypt();
    bench_decrypt();
    bench_pss_refresh();
    println!();
}
