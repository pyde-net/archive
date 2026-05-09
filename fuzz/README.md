# pyde-fuzz

`cargo-fuzz` harnesses for MAINNET_PLAN task 053. Lives outside the
main workspace (`Cargo.toml`'s `[workspace] exclude = ["fuzz"]`)
because libfuzzer needs nightly + coverage instrumentation that
would poison the stable-toolchain build.

## Targets

| Target                    | What it fuzzes                                              | Why it matters                                                                                 |
| ------------------------- | ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `pvm_interpreter`         | `Vm::load` + `Vm::execute` on arbitrary bytecode            | Contract-deploy bytecode is attacker-supplied; a panic here crashes validators post-deploy.    |
| `tx_decoder`              | `pyde_tx::types::Transaction::from_bytes`                   | RPC-ingress + gossip bytes hit this before validation. Must return `Option`, never panic.      |
| `wire_transaction`        | `pyde_node::wire::decode_transaction`                       | Compact-block + gossip decoder; distinct from `from_bytes`. Reached via `pyde-node`'s lib target. |
| `encrypted_tx_decoder`    | `pyde_mempool::encrypted::EncryptedTx::from_bytes`          | Per-tx envelope from `pyde_sendRawEncryptedTransaction` and the `pyde/encrypted_transactions/1` topic. Anonymous-RPC reachable. |
| `wire_block`              | `pyde_node::wire::decode_block`                             | TPL-701: full-block decode runs BEFORE proposer-signature verification on `pyde/blocks/1`. Reachable to any authenticated peer. |
| `wire_block_header`       | `pyde_node::wire::decode_block_header`                      | TPL-701: header decoder also called directly on `pyde/sync/1` light-client paths.              |
| `wire_consensus_message`  | `pyde_node::wire::decode_consensus_message`                 | TPL-701: entry point for everything on `pyde/consensus/1` — votes, view-changes, finality, decryption shares, slashing evidence. Committee-membership check is downstream of the decode. |
| `wire_consensus_state`    | `pyde_node::wire::decode_consensus_state`                   | TPL-701: cold-sync HotStuff state response on `pyde/sync/1`. Malformed response is a remote-kill against a node restarting from a checkpoint. |
| `encrypted_tx_bundle`     | `pyde_node::wire::decode_encrypted_tx_bundle`               | TPL-701: proposer-side ordering-commitment bundle on `pyde/blocks/1`. Decoded before the proposer signature is checked. |
| `otic_parser`             | `otic` lex + parse + resolve + typecheck + safety           | TPL-701: developer-tooling DoS surface. A hostile `.oti` source must not crash `pyde-dev build`, `otic build/check/test`, or any IDE plugin that runs the front-end. |

## Planned follow-up targets

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
cargo +nightly fuzz run wire_transaction
cargo +nightly fuzz run encrypted_tx_decoder
# TPL-701 targets:
cargo +nightly fuzz run wire_block
cargo +nightly fuzz run wire_block_header
cargo +nightly fuzz run wire_consensus_message
cargo +nightly fuzz run wire_consensus_state
cargo +nightly fuzz run encrypted_tx_bundle
cargo +nightly fuzz run otic_parser
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
