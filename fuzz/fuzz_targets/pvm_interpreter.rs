//! Fuzz target: PVM interpreter on arbitrary bytecode.
//!
//! Feeds `data` directly into `Vm::load` + `Vm::execute` and requires
//! the interpreter to never panic. Any reachable panic (out-of-bounds
//! index, arithmetic overflow in the decoder, unreachable arms on
//! malformed opcodes) is a bug that needs a `Trap` or explicit error
//! path, not a panic.
//!
//! Coverage: every byte of `data` is exposed to the instruction
//! decoder (`Opcode::from_u8`), the immediate decoder, and the
//! dispatcher. The guest bytecode comes from smart-contract deploys
//! today; any PVM crash on attacker-crafted bytecode is a liveness
//! bug (panicking validator) and potentially a safety bug (forks on
//! pre-check divergence across validators with different compiler
//! versions).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut vm = pyde_vm::vm::Vm::new();
    // `load` may reject malformed bytecode with `Trap` — that's the
    // correct response, not a crash. Early-return on load failure.
    if vm.load(data).is_err() {
        return;
    }
    // Give the VM a bounded gas budget so an adversary can't make the
    // harness loop forever on a large `data`. 10 M gas is well beyond
    // any real deploy but bounded from the fuzzer's view.
    vm.gas_limit = 10_000_000;
    let _ = vm.execute();
});
