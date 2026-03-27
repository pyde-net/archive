use std::time::Instant;

use pyde_crypto::falcon::falcon_keygen;
use pyde_crypto::vrf::{vrf_prove, vrf_verify};

fn bench_prove() {
    println!("=== VRF prove ===\n");
    let (pk, sk) = falcon_keygen().unwrap();
    let input = b"benchmark vrf input";
    let iterations = 1_000;

    let start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(vrf_prove(&pk, &sk, std::hint::black_box(input)));
    }
    let elapsed = start.elapsed();
    println!(
        "  {:.1}µs/prove  ({:.0} proves/sec)",
        elapsed.as_micros() as f64 / iterations as f64,
        iterations as f64 / elapsed.as_secs_f64()
    );
}

fn bench_verify() {
    println!("\n=== VRF verify ===\n");
    let (pk, sk) = falcon_keygen().unwrap();
    let input = b"benchmark vrf verify";
    let (output, proof) = vrf_prove(&pk, &sk, input).unwrap();
    let iterations = 1_000;

    let start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(vrf_verify(
            std::hint::black_box(&pk),
            std::hint::black_box(input),
            std::hint::black_box(&output),
            std::hint::black_box(&proof),
        ));
    }
    let elapsed = start.elapsed();
    println!(
        "  {:.1}µs/verify  ({:.0} verifies/sec)",
        elapsed.as_micros() as f64 / iterations as f64,
        iterations as f64 / elapsed.as_secs_f64()
    );
}

fn main() {
    bench_prove();
    bench_verify();
    println!();
}
