# Pyde

Post-quantum, ZK-proven Layer 1 blockchain.

## Architecture

- **Monolith binary** — consensus + execution in a single process
- **Post-quantum cryptography** — Poseidon2, FALCON, Kyber, lattice-based VRF
- **PVM (Pyde Virtual Machine)** — custom register-based VM with 32-bit fixed-width ISA
- **ZK-proven execution** — every block is provable via STARKs
- **EIP-1559 gas model** — two-dimensional (exec + prove), no tips, elastic 4x blocks
- **Otigen language** (.oti) — purpose-built smart contract language
- **Parachains** — infrastructure utility chains, not general-purpose smart contract platforms

## Workspace

| Crate | Description |
|-------|-------------|
| `crates/crypto` | Post-quantum cryptographic primitives (Poseidon2, FALCON, Kyber, threshold Kyber, PSS, VRF) |
| `crates/pvm` | Pyde Virtual Machine — ISA, CPU, 256-bit wide registers |

## PVM Specs

- 16 x 64-bit general-purpose registers (r0 hardwired zero)
- 8 x 256-bit wide registers for crypto operations
- 62 opcodes across 7 categories
- Checked arithmetic with trap-on-error semantics
- Two-dimensional gas metering (execution + proving cost)

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
