# Pyde

High-performance, post-quantum Layer 1 blockchain with native MEV protection.

## Architecture

- **Monolith binary** — consensus + execution in a single process
- **Post-quantum cryptography** — FALCON-512 signatures, Kyber-768 KEM, Poseidon2 hashing, lattice-based VRF
- **PVM (Pyde Virtual Machine)** — custom register-based VM with 32-bit fixed-width ISA
- **Encrypted mempool** — threshold decryption prevents MEV extraction
- **EIP-1559 gas model** — no tips, elastic 4x blocks, 80% burn / 20% validator
- **Otigen language** (.oti) — purpose-built smart contract language with Rust-like syntax
- **HotStuff BFT consensus** — committee-based with VRF proposer selection

## Workspace

| Crate | Description |
|-------|-------------|
| `crates/crypto` | Post-quantum primitives: Poseidon2, FALCON-512, Kyber-768, threshold encryption, VRF |
| `crates/pvm` | Pyde Virtual Machine: ISA, CPU, memory, 256-bit wide registers, Memcpy |
| `crates/aot` | Ahead-of-time JIT compiler (Cranelift backend) |
| `crates/state` | Sparse Merkle Tree, state roots, witness generation |
| `crates/account` | Account model, address derivation, nonce management |
| `crates/tx` | Transaction types, gas, parallel execution, fee distribution |
| `crates/consensus` | HotStuff BFT, finality, slashing, VRF proposer selection |
| `crates/mempool` | Encrypted mempool, block construction, tx ordering |
| `crates/net` | P2P networking, peer discovery, gossipsub channels |
| `crates/otic` | Otigen compiler: lexer → parser → typecheck → IR → optimize → codegen → .json artifact |

## PVM Specs

- 16 x 64-bit general-purpose registers (r0 hardwired zero)
- 8 x 256-bit wide registers for crypto operations
- 62 opcodes: arithmetic, memory, control flow, storage, crypto, assertions
- Checked arithmetic with trap-on-error semantics
- 4 MB address space: null page, code, heap (grows up), stack (grows down)
- Memcpy instruction for efficient bulk memory operations

## Otigen Compiler

```
otic build contract.oti    # Compile to .json artifact (bytecode + ABI)
otic check contract.oti    # Type check only
otic test contract.oti     # Run #[test] functions on PVM
otic abi contract.oti      # Output ABI JSON
```

Features: 30 keywords, storage maps, structs, enums, Vec with realloc, events, custom errors, `#[view]`/`#[payable]`/`#[reentrant]` attributes, reentrancy guards, payable guards, function dispatch with 4-byte selectors.

## Targets

- 400M sustained / 1.6B max block gas
- ~12,500 sustained / ~50,000 peak TPS

## Building

```
cargo build
cargo test --workspace
```

## License

Proprietary. All rights reserved.
