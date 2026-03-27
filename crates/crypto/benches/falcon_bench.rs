use std::time::Instant;

use pyde_crypto::falcon::{falcon_batch_verify, falcon_keygen, falcon_sign, falcon_verify};

fn bench_keygen() {
    println!("=== FALCON-512 keygen ===\n");
    let iterations = 100;
    let start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(falcon_keygen().unwrap());
    }
    let elapsed = start.elapsed();
    println!(
        "  {:.1}ms/keygen  ({:.0} keygens/sec)",
        elapsed.as_millis() as f64 / iterations as f64,
        iterations as f64 / elapsed.as_secs_f64()
    );
}

fn bench_sign() {
    println!("\n=== FALCON-512 sign ===\n");
    let (_pk, sk) = falcon_keygen().unwrap();
    let msg = b"benchmark message for signing";
    let iterations = 1_000;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = std::hint::black_box(falcon_sign(&sk, std::hint::black_box(msg)));
    }
    let elapsed = start.elapsed();
    println!(
        "  {:.1}µs/sign  ({:.0} signs/sec)",
        elapsed.as_micros() as f64 / iterations as f64,
        iterations as f64 / elapsed.as_secs_f64()
    );
}

fn bench_verify() {
    println!("\n=== FALCON-512 verify (single) ===\n");
    let (pk, sk) = falcon_keygen().unwrap();
    let msg = b"benchmark message for verification";
    let sig = falcon_sign(&sk, msg).unwrap();
    let iterations = 1_000;

    let start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(falcon_verify(
            std::hint::black_box(&pk),
            std::hint::black_box(msg),
            std::hint::black_box(&sig),
        ));
    }
    let elapsed = start.elapsed();
    println!(
        "  {:.1}µs/verify  ({:.0} verifies/sec)",
        elapsed.as_micros() as f64 / iterations as f64,
        iterations as f64 / elapsed.as_secs_f64()
    );
}

fn bench_batch_verify() {
    println!("\n=== FALCON-512 batch verify ===\n");
    let (pk, sk) = falcon_keygen().unwrap();

    for count in [100, 1000] {
        let msgs: Vec<Vec<u8>> = (0..count)
            .map(|i| format!("message {}", i).into_bytes())
            .collect();
        let sigs: Vec<_> = msgs.iter().map(|m| falcon_sign(&sk, m).unwrap()).collect();
        let items: Vec<_> = msgs
            .iter()
            .zip(sigs.iter())
            .map(|(m, s)| (&pk, m.as_slice(), s))
            .collect();

        let start = Instant::now();
        std::hint::black_box(falcon_batch_verify(&items));
        let elapsed = start.elapsed();

        println!(
            "  {} sigs: {:.1}ms total  ({:.1}µs/verify)",
            count,
            elapsed.as_millis() as f64,
            elapsed.as_micros() as f64 / count as f64
        );
    }
}

fn main() {
    bench_keygen();
    bench_sign();
    bench_verify();
    bench_batch_verify();
    println!();
}
