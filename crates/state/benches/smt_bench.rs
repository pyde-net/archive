use std::time::Instant;

use pyde_state::backend::RocksDBBackend;
use pyde_state::smt::{key_from_seed, Poseidon2Hasher, SmtValue};
use pyde_state::smt::{PydeSMT};
use sparse_merkle_tree::SparseMerkleTree;
use sparse_merkle_tree::H256;

fn bench_insert() {
    println!("=== SMT insert throughput ===\n");

    for count in [100u64, 1_000, 10_000] {
        let mut smt = PydeSMT::new();
        let pairs: Vec<_> = (0..count)
            .map(|i| (key_from_seed(i), format!("v{i}").into_bytes()))
            .collect();

        let start = Instant::now();
        for (k, v) in &pairs {
            smt.insert(*k, v.clone());
        }
        let elapsed = start.elapsed();

        let ops_sec = count as f64 / elapsed.as_secs_f64();
        println!(
            "  {count:>6} inserts:  {ops_sec:>10.0} ops/sec ({:.1}ms)",
            elapsed.as_secs_f64() * 1000.0
        );
    }
}

fn bench_get() {
    println!("\n=== SMT get throughput ===\n");

    let mut smt = PydeSMT::new();
    let keys: Vec<_> = (0..10_000).map(|i| key_from_seed(i)).collect();
    for (i, k) in keys.iter().enumerate() {
        smt.insert(*k, format!("v{i}").into_bytes());
    }

    let iterations = 10_000u64;
    let start = Instant::now();
    for i in 0..iterations {
        std::hint::black_box(smt.get(&keys[i as usize % keys.len()]));
    }
    let elapsed = start.elapsed();
    let ops_sec = iterations as f64 / elapsed.as_secs_f64();
    println!("  {iterations:>6} lookups:  {ops_sec:>10.0} ops/sec ({:.1}ms)", elapsed.as_secs_f64() * 1000.0);
}

fn bench_proof() {
    println!("\n=== SMT proof generation & verification ===\n");

    let mut smt = PydeSMT::new();
    let keys: Vec<_> = (0..1_000).map(|i| key_from_seed(i)).collect();
    for (i, k) in keys.iter().enumerate() {
        smt.insert(*k, format!("v{i}").into_bytes());
    }

    let root = smt.root();
    let iterations = 1_000u64;

    let start = Instant::now();
    for i in 0..iterations {
        std::hint::black_box(smt.prove(vec![keys[i as usize % keys.len()]]));
    }
    let elapsed = start.elapsed();
    let us_per_proof = elapsed.as_micros() as f64 / iterations as f64;
    println!("  {iterations:>6} proofs:   {us_per_proof:>8.1} µs/proof");

    let key = keys[0];
    let value = b"v0".to_vec();
    let proof = smt.prove(vec![key]);

    let start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(proof.verify(root, vec![(key, value.clone())]));
    }
    let elapsed = start.elapsed();
    let us_per_verify = elapsed.as_micros() as f64 / iterations as f64;
    println!("  {iterations:>6} verifies: {us_per_verify:>8.1} µs/verify");
}

fn bench_batch_insert() {
    println!("\n=== SMT batch insert (update_all) ===\n");

    for count in [100u64, 1_000, 10_000] {
        let pairs: Vec<_> = (0..count)
            .map(|i| (key_from_seed(i + 100_000), format!("v{i}").into_bytes()))
            .collect();

        let mut smt = PydeSMT::new();
        let start = Instant::now();
        smt.update_all(pairs);
        let elapsed = start.elapsed();

        let ops_sec = count as f64 / elapsed.as_secs_f64();
        println!(
            "  {count:>6} batch:    {ops_sec:>10.0} ops/sec ({:.1}ms)",
            elapsed.as_secs_f64() * 1000.0
        );
    }
}

fn bench_rocksdb() {
    println!("\n=== RocksDB backend ===\n");

    type SMT = SparseMerkleTree<Poseidon2Hasher, SmtValue, RocksDBBackend>;

    for count in [100u64, 1_000] {
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDBBackend::open(dir.path().to_str().unwrap()).unwrap();
        let mut smt = SMT::new(H256::zero(), store);

        let pairs: Vec<_> = (0..count)
            .map(|i| (key_from_seed(i), SmtValue(format!("v{i}").into_bytes())))
            .collect();

        let start = Instant::now();
        smt.update_all(pairs).unwrap();
        let elapsed = start.elapsed();

        let ops_sec = count as f64 / elapsed.as_secs_f64();
        println!(
            "  {count:>6} inserts:  {ops_sec:>10.0} ops/sec ({:.1}ms)",
            elapsed.as_secs_f64() * 1000.0
        );

        // Read benchmark
        let keys: Vec<_> = (0..count).map(|i| key_from_seed(i)).collect();
        let iterations = count;
        let start = Instant::now();
        for i in 0..iterations {
            std::hint::black_box(smt.get(&keys[i as usize % keys.len()]).unwrap());
        }
        let elapsed = start.elapsed();
        let read_ops = iterations as f64 / elapsed.as_secs_f64();
        println!(
            "  {iterations:>6} reads:    {read_ops:>10.0} ops/sec ({:.1}ms)",
            elapsed.as_secs_f64() * 1000.0
        );
    }
}

fn bench_update_all_scaling() {
    println!("\n=== update_all scaling (single call per block) ===\n");

    for count in [1_000u64, 5_000, 10_000, 20_000, 50_000, 80_000] {
        let mut smt = PydeSMT::new();
        let entries: Vec<_> = (0..count)
            .map(|i| (key_from_seed(i), format!("v{i}").into_bytes()))
            .collect();

        let start = Instant::now();
        smt.update_all(entries);
        let elapsed = start.elapsed();

        let ops_sec = count as f64 / elapsed.as_secs_f64();
        let ms = elapsed.as_secs_f64() * 1000.0;
        let within_budget = if ms < 400.0 { "OK" } else { "SLOW" };
        println!(
            "  {count:>6} updates:  {ops_sec:>10.0} ops/sec ({ms:.0}ms) [{within_budget}]"
        );
    }
}


fn main() {
    bench_insert();
    bench_batch_insert();
    bench_update_all_scaling();
    bench_get();
    bench_proof();
    bench_rocksdb();
    println!();
}
