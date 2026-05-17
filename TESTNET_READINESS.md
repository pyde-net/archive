# Pyde — Testnet Readiness Summary

**Date:** 2026-05-17
**Branch:** `main` @ `9ea1ece` (audit-418 commit 3 of 3)
**Last validation:** 4h 200-TPS soak completed clean (`/tmp/pyde-soak-418-200tps.log`)

---

## TL;DR

The chain is **lab-grade verified** and ready for public-testnet deployment
**after** one remaining gate: distributed-hardware soak. Every wedge mode
discovered in prior soaks is closed in code and empirically confirmed by a
4-hour 200-TPS run with 2.86M transactions landed and zero permanent head
divergence.

Mainnet requires additional work (external audit, multi-day soaks,
adversarial testing) — see [Open gaps for mainnet](#open-gaps-for-mainnet).

---

## What is verified

### Empirical (4h 200-TPS soak, 2026-05-16 → 2026-05-17)

| Metric                                  | Result                            |
| --------------------------------------- | --------------------------------- |
| Duration (measure window)               | 14,400 s (4 hours)                |
| Sustained throughput                    | 198 / 200 TPS (99%)               |
| Total txs landed                        | 2,861,778                         |
| — transfers                             | 1,698,754                         |
| — contract calls                        | 872,304                           |
| — encrypted (MEV-protected)             | 290,720                           |
| Permanent head divergence               | 0 (none)                          |
| Transient 1-slot divergences            | several — all self-healed in ≤1 watchdog interval |
| Loadgen submission errors               | 45,646 (1.59%) — all `InvalidNonce`, all recovered |
| Chain-side execution failures           | 0 (zero failed receipts) |
| Final head                              | slot 36,971, epoch 36, hard-final |
| Hardware                                | 4 validators on one MacBook (M-series, 14 cores) |

### Code — wedge modes closed

| Audit  | Mode                                                            | Closed by                                                |
| ------ | --------------------------------------------------------------- | -------------------------------------------------------- |
| 411    | Committee rotation race vs in-flight votes                      | `committee_keys_for_slot(slot)` everywhere               |
| 412    | Deferred-fallback drain on VC-QC formation                      | drain on view-change-QC                                  |
| 414    | Self-origin gossipsub loopback rate-limited                     | self-origin bypass with local-peer-id check              |
| 415    | WS checkpoint `<=` off-by-one rejecting block at checkpoint slot | strict-less `<`                                          |
| 416    | Silent consensus-message drops masking root cause               | `debug!` → `warn!` visibility                            |
| 417    | Block-size races `PROGRESS_TIMEOUT_MS`                          | `MAX_TXS_PER_BLOCK = 500` cap, validator-side enforced   |
| 418    | 2-vs-2 head-divergence deadlock at QC propagation               | `ConsensusMessage::QcAnnounce` broadcast/receive (3 commits) |
| ω      | Five speculative-apply paths committing pre-QC                  | `commit_canonical` single-source-of-truth (5 commits)    |

### Loadgen → realistic client behaviour

Loadgen now handles bidirectional nonce drift (commits to `main`
post-audit-417). Real wallets (TS / Rust SDKs, dapps) will need the same
pattern; the loadgen now models the production-client pattern faithfully.

---

## Decision boundary

### Sufficient for public testnet IF the remaining gate passes

A **distributed-hardware soak** is the last lab validation before public
launch. Every wedge to date has been reproducible on the single-laptop
harness; the chain is now wedge-free there. The remaining risk is
distributed-specific failure modes (inter-region latency vs.
`PROGRESS_TIMEOUT_MS = 200 ms`, real-network packet loss, region-paired
gossipsub mesh topology) — none of which the laptop harness can surface.

### Recommended distributed-validation plan

1. Deploy 4 validators across 4 cloud regions via
   `pyde testnet --node-addrs <file>` (existing distributed-mode CLI).
2. Run loadgen at 200 TPS for 24h.
3. Repeat at 500 TPS for 4h to probe headroom.
4. Repeat at 1000 TPS for 4h — the laptop wedge at slot 4290 was CPU
   saturation; distributed hardware should reveal the real ceiling.
5. Validate that real SDK clients (`pyde-rust-sdk`, `pyde-ts-sdk`)
   handle nonce drift identically to the patched loadgen.

If all four pass, the chain is **production-grade for public testnet**.

---

## Open gaps for mainnet

Listed here for visibility; **none are public-testnet blockers**.

- **External security audit.** Not yet engaged. Required before mainnet
  exposure. ~6-12 weeks lead time at most audit firms.
- **Long-duration soak (≥7 days).** Some failure classes (state-store
  growth, memory leaks, slow timing drift) only surface at multi-day
  scale.
- **Adversarial testing.** Network partitions, Byzantine validators,
  coordinated equivocation, censorship — covered by the BFT design but
  not yet exercised end-to-end.
- **Sustained 12,500 TPS (mainnet target throughput).** Lab harness has
  validated 200 TPS clean and 1000 TPS limited by single-machine CPU.
  Per-node CPU on real validator hardware (32+ cores, dedicated network)
  should give an order-of-magnitude headroom — but unconfirmed.
- **PSS / committee resharing under load.** PSS warnings appear in the
  soak logs ("aggregation trigger fired but below threshold") — by
  design when committee size is small (4 validators, threshold 3), but
  should re-validate on a larger committee.
- **State growth durability.** JMT pruning, snapshot reads under heavy
  write load, hard-finality cert storage.
- **Cross-validator clock skew.** Currently NTP-assumed; degraded NTP
  could trigger view-change cascades.

---

## Suggested next steps

1. **This week:** distributed-hardware soak (4 validators across 4
   cloud regions, 24h at 200 TPS).
2. **Next week:** SDK validation — drive `pyde-ts-sdk` and
   `pyde-rust-sdk` at 200 TPS for 4h, verify identical drift-handling.
3. **After both pass:** announce public testnet (incentivized, time-
   boxed). Use the public period to surface real-world issues.
4. **Mainnet path (post-fundraise):** external audit → adversarial-
   testing window → multi-week soak → mainnet candidate.

---

## Provenance

- All audit fixes referenced above are individual commits on `main`,
  identifiable by `(audit-XXX)` in the subject line.
- 4h soak log: `/tmp/pyde-soak-418-200tps.log` (~2,500 lines incl.
  per-validator final tails).
- Tracker for individual TPL-NNN items:
  [`TESTNET_LAUNCH_TRACKER.md`](TESTNET_LAUNCH_TRACKER.md).
