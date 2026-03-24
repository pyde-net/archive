use criterion::{criterion_group, criterion_main, Criterion};

use pyde_prover::multi_table::{prove_single_tx, verify_multi_table};
use pyde_prover::prover;
use pyde_prover::recorder;
use pyde_vm::isa::{encode, encode_mem_immediate, MemWidth, Opcode};
use pyde_vm::vm::Vm;

fn instr(op: Opcode, rd: u8, rs1: u8, imm: u32) -> [u8; 4] {
    encode(op, rd, rs1, imm).0.to_le_bytes()
}

fn bytecode(instrs: &[&[u8; 4]]) -> Vec<u8> {
    instrs.iter().flat_map(|i| i.iter().copied()).collect()
}

fn simple_program() -> Vec<u8> {
    bytecode(&[
        &instr(Opcode::Addi, 1, 0, 42),
        &instr(Opcode::Addi, 2, 0, 58),
        &instr(Opcode::Add, 3, 1, 2),
        &instr(Opcode::Halt, 0, 0, 0),
    ])
}

fn medium_program() -> Vec<u8> {
    let store_imm = encode_mem_immediate(0, MemWidth::W64);
    let load_imm = encode_mem_immediate(0, MemWidth::W64);
    bytecode(&[
        &instr(Opcode::Addi, 1, 0, 1000),
        &instr(Opcode::Addi, 2, 0, 250),
        &instr(Opcode::Sub, 3, 1, 2),
        &instr(Opcode::Mul, 4, 3, 2),
        &instr(Opcode::Addi, 5, 0, 100),
        &instr(Opcode::Div, 6, 4, 5),
        &instr(Opcode::Mod, 7, 4, 5),
        &instr(Opcode::Lt, 8, 7, 5),
        &instr(Opcode::Addi, 9, 0, 0x010000),
        &instr(Opcode::Store, 6, 9, store_imm),
        &instr(Opcode::Load, 10, 9, load_imm),
        &instr(Opcode::Addi, 11, 0, 2),
        &instr(Opcode::Shl, 12, 10, 11),
        &instr(Opcode::Shr, 13, 12, 11),
        &instr(Opcode::Eq, 14, 13, 10),
        &instr(Opcode::Halt, 0, 0, 0),
    ])
}

fn bench_record(c: &mut Criterion) {
    let code = medium_program();
    c.bench_function("record_medium_16instr", |b| {
        b.iter(|| {
            let mut vm = Vm::with_gas_limit(100_000);
            vm.load(&code).unwrap();
            recorder::record_execution(&mut vm)
        })
    });
}

fn bench_prove(c: &mut Criterion) {
    let code = medium_program();
    let mut vm = Vm::with_gas_limit(100_000);
    vm.load(&code).unwrap();
    let (mut trace, _) = recorder::record_execution(&mut vm);

    c.bench_function("prove_medium_16instr", |b| {
        b.iter(|| {
            let mut t = trace.clone();
            prover::prove(&mut t, &[]).unwrap()
        })
    });
}

fn bench_verify(c: &mut Criterion) {
    let code = medium_program();
    let mut vm = Vm::with_gas_limit(100_000);
    vm.load(&code).unwrap();
    let (mut trace, _) = recorder::record_execution(&mut vm);
    let proof = prover::prove(&mut trace, &[]).unwrap();

    c.bench_function("verify_medium_16instr", |b| {
        b.iter(|| prover::verify(&proof, &[]))
    });
}

fn bench_multi_table(c: &mut Criterion) {
    let code = medium_program();
    c.bench_function("multi_table_medium_16instr", |b| {
        b.iter(|| {
            let mut vm = Vm::with_gas_limit(100_000);
            vm.load(&code).unwrap();
            prove_single_tx(&mut vm).unwrap()
        })
    });
}

fn bench_proof_size(c: &mut Criterion) {
    let code = medium_program();
    let mut vm = Vm::with_gas_limit(100_000);
    vm.load(&code).unwrap();
    let proof = prove_single_tx(&mut vm).unwrap();

    c.bench_function("serialize_proof", |b| {
        b.iter(|| prover::serialize_proof(&proof.execution_proof))
    });

    println!("Proof size: {} KB", proof.proof_bytes.len() / 1024);
}

criterion_group!(
    benches,
    bench_record,
    bench_prove,
    bench_verify,
    bench_multi_table,
    bench_proof_size,
);
criterion_main!(benches);
