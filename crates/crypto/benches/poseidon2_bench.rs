use std::time::Instant;

use pyde_crypto::poseidon2::{poseidon2_hash, poseidon2_pair};

fn bench_hash_throughput() {
    let sizes = [32, 64, 256, 1024, 4096];

    println!("=== poseidon2_hash throughput ===\n");
    for size in sizes {
        let data = vec![0xABu8; size];
        let iterations = 10_000;

        let start = Instant::now();
        for _ in 0..iterations {
            std::hint::black_box(poseidon2_hash(std::hint::black_box(&data)));
        }
        let elapsed = start.elapsed();

        let total_bytes = size as f64 * iterations as f64;
        let mb_per_sec = total_bytes / elapsed.as_secs_f64() / 1_000_000.0;
        let hashes_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!(
            "  {size:>5} bytes: {mb_per_sec:>8.1} MB/s  ({hashes_per_sec:>10.0} hashes/sec, {:.1}µs/hash)",
            elapsed.as_micros() as f64 / iterations as f64
        );
    }
}

fn bench_pair_throughput() {
    let iterations = 10_000;
    let a = poseidon2_hash(b"left");
    let b = poseidon2_hash(b"right");

    println!("\n=== poseidon2_pair throughput ===\n");

    let start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(poseidon2_pair(
            std::hint::black_box(a),
            std::hint::black_box(b),
        ));
    }
    let elapsed = start.elapsed();

    let pairs_per_sec = iterations as f64 / elapsed.as_secs_f64();
    println!(
        "  {pairs_per_sec:>10.0} pairs/sec  ({:.1}µs/pair)",
        elapsed.as_micros() as f64 / iterations as f64
    );
}

fn bench_pair_chain() {
    let iterations = 10_000;

    println!("\n=== poseidon2_pair chain (Merkle path simulation) ===\n");

    let mut current = poseidon2_hash(b"leaf");
    let sibling = poseidon2_hash(b"sibling");

    let start = Instant::now();
    for _ in 0..iterations {
        current = poseidon2_pair(current, sibling);
    }
    let elapsed = start.elapsed();
    std::hint::black_box(current);

    let pairs_per_sec = iterations as f64 / elapsed.as_secs_f64();
    println!(
        "  {pairs_per_sec:>10.0} pairs/sec  ({:.1}µs/pair)",
        elapsed.as_micros() as f64 / iterations as f64
    );
}

fn main() {
    bench_hash_throughput();
    bench_pair_throughput();
    bench_pair_chain();
    println!();
}
