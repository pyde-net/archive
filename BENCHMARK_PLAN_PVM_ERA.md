# Engine Workspace — Benchmark Plan

**Status: planned. Not started. Post-application work.**

This document specifies the benchmarking discipline for the Pyde
execution layer (PVM + AOT + state + LRU caching + parallel scheduler).
It is **distinct from** the full-chain performance harness in
[`pyde-book/docs/PERFORMANCE_HARNESS.md`](../pyde-book/docs/PERFORMANCE_HARNESS.md),
which measures end-to-end TPS under multi-region consensus and network
conditions. This plan covers what an honest **execution-layer-only**
benchmark looks like — single-machine, in-process, no consensus, no
network — and is the prerequisite for the full-chain numbers.

**Numbers in this document are targets, not measurements.** No external
TPS claim from this benchmark suite will be published until the suite
exists, has been run, and the methodology is reproducible by third
parties. Headline numbers will be **1/3 of measured peak** — the same
discipline as the full-chain harness (the "HotStuff lesson":
lab benchmarks ≠ production).

---

## 1. Scope

The execution-layer benchmark measures:

- **PVM interpreter** throughput and per-opcode latency
- **AOT-compiled** (Cranelift) throughput and speedup vs interpreter
- **State layer** (JMT) commit latency, batch-update throughput
- **LRU caching** hit rates (node cache, value cache)
- **Parallel execution** scheduler effectiveness (static access lists +
  Block-STM speculation)
- **Memory** peaks per execution, page-allocation patterns
- **Gas accounting** overhead

Out of scope (covered separately):
- Consensus, networking, gossip → full-chain harness
- Threshold decryption ceremony → crypto crate benchmarks
- Mempool admission → mempool benchmarks (when mempool is rebuilt)
- Multi-region effects → full-chain harness

---

## 2. Hardening prerequisites (must complete before benchmarks are credible)

Running benchmarks against an unhardened codebase produces numbers
that don't survive contact with adversarial inputs or audit. The
following are gating items, in priority order:

| Item | Source / tracker | Effort |
|---|---|---|
| Fix `require!`-revert bug in test path | Task #18 — `[POST-APP]` | ~1 day |
| Audit `unsafe` blocks in `pyde-crypto` (Goldilocks zeroize, FALCON, Kyber, threshold) | New | ~3 days |
| Audit `unsafe` blocks in `pyde-aot` (Cranelift codegen + host trampolines) | New | ~3 days |
| Triage every `unwrap()` / `expect()` on untrusted-input paths | New | ~2 days |
| 72-hour `cargo-fuzz` run: PVM interpreter | `pyde-book` Ch 19 Phase 5 | continuous |
| 72-hour `cargo-fuzz` run: tx validation | `pyde-book` Ch 19 Phase 5 | continuous |
| 72-hour `cargo-fuzz` run: otic compiler | `pyde-book` Ch 19 Phase 5 | continuous |
| Determinism cross-test: AOT vs interpreter byte-identity on 1000 contracts | New | ~3 days |
| State-commit determinism: same tx sequence → identical state root across runs/machines | New | ~2 days |
| Property tests for all 12 PVM trap kinds | `pyde-book` Ch 19 Phase 5 | ~5 days |
| Property tests for gas accounting (no underflow, no overflow, refunds capped) | New | ~3 days |
| Property tests for JMT batched proofs vs single-key proofs | New | ~3 days |
| Integration test: 16-validator local devnet sustains 1000 TPS for 1 hour | `pyde-book` Ch 19 Phase 6 | ~1 week setup + 1 hour run |

**Estimated total: 4-6 weeks** of hardening effort (parallelizable
across multiple Claude sessions or contributors). The benchmarks are
not meaningful until this is complete.

---

## 3. Workload categories

Real workloads, not synthetic micro-loops. Each workload has a
canonical Otigen contract under `engine/bench/workloads/` and a
real-FALCON-signed transaction stream.

| Workload | What it stresses | Realism notes |
|---|---|---|
| **Simple transfer** | PVM dispatch, FALCON verify, fee distribution | Baseline. 21,000 gas. No contract execution. |
| **Token transfer** | Single-`Sstore`, single-`Sload`, event emission | Otigen Token contract from the demo. ~65,000 gas. |
| **Token `approve` + `transferFrom`** | Two storage writes, nested map access | ~100,000 gas. Standard ERC-20 pattern. |
| **DEX swap (constant-product)** | Multiple storage reads/writes, branching, arithmetic | ~200,000 gas. Worst case for state-cache thrashing if pools rotate. |
| **NFT mint** | Storage growth, event with indexed fields | ~150,000 gas. Stresses state-tree depth growth over time. |
| **Mixed (realistic)** | 70% transfers, 15% token ops, 10% DEX, 5% complex | Closest to expected mainnet traffic mix. |
| **Encrypted path** | Same workloads but post-threshold-decryption | Measures the cost of decryption integration, not encryption itself (which is per-share). |
| **Adversarial: max-storage-touching** | Pathological tx that touches maximum slots within witness cap | Validates 1 MB witness cap is enforced before proof work. |
| **Adversarial: gas-griefing** | Tx that consumes max gas with min state change | Validates gas refunds are capped at 50% (no over-refund attack). |

Workload mixes can be swapped via a config file; the harness consumes
the YAML.

---

## 4. Measurements

### Throughput
- `tx/sec sustained` over 60s after warmup
- `tx/sec peak burst` over 10s
- `gas/sec` (both PVM-execution gas and total-tx gas including fee distribution)
- `state-ops/sec` (Sload + Sstore + Sdelete)

### Latency (per-tx, percentiles p50, p90, p99, p99.9)
- Full tx pipeline: validate → execute → state-commit → receipt-emit
- PVM-only execution time
- State commit time (per-tx and per-batch)
- AOT compile time at deploy (one-time cost per contract)

### Speedup / efficiency
- **AOT vs interpreter ratio** per workload — should be 5–20× depending on workload type
- **Parallel scheduler speedup** at N = 1, 2, 4, 8, 16 cores
- **Static access list vs Block-STM fallback ratio** by workload
- **LRU cache hit rates**: JMT node cache, JMT value cache
- **Gas accounting overhead**: gas-tracked vs gas-untracked execution time delta

### Resource utilization
- Peak RSS per execution
- Page allocations per tx
- Disk I/O (RocksDB read/write rates)
- CPU utilization breakdown (PVM dispatch / Cranelift codegen / state commit / FALCON verify)

### Crypto-specific
- FALCON-512 verify rate (sequential, batched, batched-with-SIMD-if-available)
- Poseidon2 hash rate
- Blake3 hash rate
- Threshold decryption: shares/sec combined, per-batch combination cost

---

## 5. Reproducible runner

Anyone — Alliance auditors, validator candidates, suspicious-mind
reviewers — should be able to run the benchmarks on their own
hardware and submit results.

```sh
# Single command from engine workspace root:
cargo bench --workspace

# Orchestrated runner with config + machine fingerprint capture:
./scripts/bench-all.sh --output bench-results/$(date +%Y%m%d-%H%M%S)/

# Specific workload:
cargo bench --bench token_transfer

# Profile a single tx through the execution path:
./scripts/profile-tx.sh --workload dex_swap --tx-count 1000
```

Output of each run:
- `machine.json` — CPU model, core count, RAM, disk class, kernel
- `workload.json` — config used
- `results.json` — structured measurements with timestamp + git commit hash
- `summary.md` — human-readable summary with comparison vs published targets

Published targets live in `engine/BENCHMARK_RESULTS.md` and are
updated whenever a new measurement is published.

---

## 6. Publication discipline

Same rule as the full-chain harness:

> **"Claim 1/3 of measured peak."** Headline numbers are conservatively
> derived from sustained measurement, never burst, never microbenchmark,
> never single-machine if multi-machine is in scope.

Publication format:

> *"Pyde execution layer sustained X tx/sec over a 60-second mixed
> workload (70% transfer / 15% token / 10% DEX / 5% complex) on a
> 16-core / 32 GB / NVMe machine. AOT speedup over interpreter: Y×.
> Median per-tx latency: Z μs. Full methodology + raw data:
> `engine/BENCHMARK_RESULTS.md` (commit `abc1234`)."*

Specific. Methodology referenced. Reproducible. **Never:** "Pyde does
1 million TPS" without the surrounding caveats.

---

## 7. Hardware classes to measure

| Class | Spec | Where it lives |
|---|---|---|
| Modest dev | 8c / 16GB / 500GB NVMe / 100 Mbps | Developer workstation |
| Production-realistic | 16c / 32GB / 1TB NVMe / 1 Gbps | Standard cloud VM |
| Datacenter | 32c / 64GB / 4TB NVMe / 10 Gbps | High-end committee target |

All three should be exercised. The headline number is from
production-realistic (the v1 target). Datacenter is the stretch
ceiling; modest dev validates the commodity-decentralization claim.

---

## 8. Timeline

| Phase | What | Duration |
|---|---|---|
| 0 | This document (planning) | ✅ Done |
| 1 | Hardening (§2) | 4-6 weeks |
| 2 | Benchmark infrastructure (cargo-bench harness, runner script, output formats) | 2 weeks |
| 3 | Measurement runs across hardware classes | 1 week |
| 4 | Methodology documentation + reproducer hardening | 1 week |
| | **Total to publishable benchmarks** | **~8-10 weeks** |

This is **post-application work**. The Alliance application's status
table currently reads "Performance harness: not yet built — mandatory
before any TPS claim." That framing stays honest until Phase 4
completes.

---

## 9. Relationship to the full-chain harness

| Dimension | This (engine benchmarks) | `PERFORMANCE_HARNESS.md` (full-chain) |
|---|---|---|
| Scope | PVM + AOT + state + caches | All of the above + consensus + network |
| Topology | Single machine | Multi-region (US-East, EU-West, AP-Southeast) |
| Validators | 1 (in-process) | 16-128 |
| Network | None (in-process) | Real WAN + simulated chaos |
| What it answers | "How fast does the execution layer run on this CPU?" | "How fast does Pyde run end-to-end under real conditions?" |
| Prerequisite for | The full-chain harness | Public TPS claims |
| Status | Planned, post-application | Planned, post-application + post-consensus-rebuild |

This benchmark suite is the **easier** of the two and the **gating
prerequisite** for the harder one. Both must exist before any
external TPS claim.

---

## 10. References

- Full-chain harness spec: [`pyde-book/docs/PERFORMANCE_HARNESS.md`](../pyde-book/docs/PERFORMANCE_HARNESS.md)
- Honest-throughput discipline (memory): `~/.claude/.../memory/honest_throughput_reset.md`
- PVM ISA + gas table: [`engine/crates/pvm/src/isa.rs`](crates/pvm/src/isa.rs)
- AOT compiler (Cranelift): [`engine/crates/aot/src/`](crates/aot/src/)
- JMT state layer: [`engine/crates/state/src/`](crates/state/src/)
- Hybrid scheduler spec: [`pyde-book/src/chapters/09-mev-protection.md`](../pyde-book/src/chapters/09-mev-protection.md) (§9.2 hybrid + access lists)
- `pyde-book` Chapter 19 Phase 5 (hardening + CI): [`pyde-book/src/chapters/19-launch-strategy.md`](../pyde-book/src/chapters/19-launch-strategy.md)
