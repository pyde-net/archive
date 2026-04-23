# pyde-fuzz

`cargo-fuzz` harnesses for MAINNET_PLAN task 053. Lives outside the
main workspace (`Cargo.toml`'s `[workspace] exclude = ["fuzz"]`)
because libfuzzer needs nightly + coverage instrumentation that
would poison the stable-toolchain build.

## Targets

| Target            | What it fuzzes                                    | Why it matters                                                                                |
| ----------------- | ------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `pvm_interpreter` | `Vm::load` + `Vm::execute` on arbitrary bytecode  | Contract-deploy bytecode is attacker-supplied; a panic here crashes validators post-deploy.   |
| `tx_decoder`      | `pyde_tx::types::Transaction::from_bytes`         | RPC-ingress + gossip bytes hit this before validation. Must return `Option`, never panic.     |

## Planned follow-up targets

- `wire_transaction` / `wire_block` / `wire_consensus_message` —
  blocked on exposing a lib target from `crates/node` (currently
  bin-only). Once `pyde-node` has a `src/lib.rs` re-exporting
  `wire`, these are one-liners.
- `otic_parser` — fuzz `.oti` source parsing.
- `falcon_verify` / `kyber_decrypt` — fuzz PQ crypto deserialisers
  (likely thin wrappers; real coverage comes from upstream fuzzing).

## Running

```bash
# One-time setup
rustup toolchain install nightly
cargo +nightly install cargo-fuzz

# From the repo root
cd fuzz
cargo +nightly fuzz run pvm_interpreter
cargo +nightly fuzz run tx_decoder
```

By default libfuzzer runs forever, discovering new inputs + storing
them in `fuzz/corpus/<target>/`. Interrupt with `Ctrl-C`. Reproduce a
crash with:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-hash>
```

## 72-hour soak runs (task 054)

Task 054 is the scheduled long soak. Run each target for 72 h under
CI or a dedicated box, fix every discovered crash, re-run. Track
coverage regressions with `cargo +nightly fuzz coverage <target>`.

## Seed corpus

Drop known-good inputs into `fuzz/corpus/<target>/` to give libfuzzer
a head start. For `tx_decoder`, a handful of real `Transaction`
encodings is enough; the fuzzer mutates from there. Seed corpus is
optional — libfuzzer starts from the empty byte string otherwise.
