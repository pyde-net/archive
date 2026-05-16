# Audit-ω: single-source-of-truth convergence invariant

**Status:** specced — implementation in progress
**Origin:** 1000-TPS mixed-load soak hit five distinct wedges (audits 411, 414, 415, 416, and the slot-1413 / slot-3251 races). Each was patched in isolation. They are all expressions of the same architectural gap.

## The invariant

> For every slot N, the canonical block at slot N is uniquely determined by the QC for slot N. Local state may **speculate** (proposer self-apply, view-1 fallback, etc.) but speculation is **staged**, never **committed**. Only QC promotes a block to `chain.head_slot`. Any apply path observing a QC for slot N whose hash differs from local state at slot N must **reorganize**.

Two corollary rules:

1. **No silent skips on the consensus path.** Every drop is logged at `warn!` or louder.
2. **No time-based trigger commits state.** Timers (`PROGRESS_TIMEOUT_MS`, rotation, WS anchor) only request votes / messages. State only mutates on QC.

## Why every recent wedge violates this rule

| Wedge | Path that violated the invariant | How |
|---|---|---|
| Slot 2834 (audit-411) | committee-rotation timer | wall-clock rotation flipped `committee_keys` mid-vote; votes counted against wrong epoch's bitmap |
| Slot 1325-era (audit-414) | self-origin gossipsub loopback | own vote rate-limit-dropped → no QC formed → wedge |
| Slot 1324 (audit-415) | `validate_header_with_checkpoint` `<=` | WS anchor advance was a time-based trigger that retroactively rejected the canonical block being applied |
| Slot 1413 (latent) | partial vote propagation | only some nodes form QC locally; cluster splits into "has QC" vs "doesn't" |
| Slot 3251 (today) | "applied own fallback block" (`node.rs:4176`) | proposer committed view-1 fallback BEFORE QC arrived; canonical QC arrived for a different block; silent `head_slot >= qc_slot` skip at `node.rs:2009` prevented reorg |

Five different wedges. One underlying disease: **local state diverges from canonical, the code treats local as ground truth, no reconciliation fires.**

## Current architecture inventory

### Six paths that advance `chain.head_slot` in `crates/node/src/node.rs`

| Path | Line | What it does | Honors invariant? |
|---|---|---|---|
| RR-fallback canonical apply | 1404 | apply when RR fallback QC arrives | ❌ silent skip on `head_slot >= qc_slot` (line 1396) |
| `ApplyCanonicalAfterQc` | 2017 | apply when peer QC arrives via gossip + body recovery | ❌ silent skip (line 2009) — **slot-3251 wedge** |
| Own-vote-QC inline apply | 3626 | apply when own vote completes a QC | ✅ has audit-232 reorg-on-mismatch (lines 3712-3771) |
| "applied own fallback block" | 4176-4190 | proposer applies its own view-1 fallback locally | ❌ **commits pre-QC**, no QC check at all — **fork root cause** |
| Hard-finality re-apply | 5650 | apply on finality-cert ingest | ❌ no mismatch handling |
| `reorg_to_block` invocation | 3722 | the audit-232 reorg branch | ✅ correct |

### Supporting structure in `crates/node/src/block_processor.rs`

- `process_full_block_with_aot_and_checkpoint` (line 127) — the actual chain-mutating function. All six paths call it.
- `reorg_to_block` (line 74) — already implements the right semantics for the divergence case. Currently invoked from only one of the six paths.
- `validate_header_with_checkpoint` (line 713) — audit-415 fixed the `<=` off-by-one. Kept for defense-in-depth.

## Target architecture

### Three consolidations

**1. Single `commit_canonical` function.** All six paths route through it.

```rust
// crates/node/src/canonical_commit.rs (new)
pub enum CanonicalSource {
    OwnVoteInline,
    RrFallback,
    ApplyCanonicalAfterQc,
    HardFinalityReapply,
}

pub enum CommitOutcome {
    Applied { txs: u64, gas: u64 },
    Idempotent,
    Reorged { txs: u64, gas: u64 },
    DivergenceUnresolved { local_hash: [u8; 32] },
    Gap { head_slot: u64, qc_slot: u64 },
    Failed { error: String },
}

pub fn commit_canonical(
    chain: &mut ChainState,
    state: &mut StateManager,
    aot_cache: Option<&Arc<AotCache>>,
    ws_checkpoint_slot: Option<u64>,
    qc_slot: u64,
    qc_block_hash: [u8; 32],
    block: &Block,
    competing_blocks: Option<&mut HashMap<(u64, [u8; 32]), Block>>,
    source: CanonicalSource,
) -> CommitOutcome;
```

Branches:

- Local hash at `qc_slot` absent and `qc_slot == head_slot + 1` → forward apply.
- Local hash absent and `qc_slot > head_slot + 1` → `Gap` (caller triggers sync).
- Local hash present and equal to `qc_block_hash` → `Idempotent`.
- Local hash present and not equal to `qc_block_hash` → `reorg_to_block`. If `competing_blocks` has the canonical body → `Reorged`. Otherwise → `DivergenceUnresolved` (caller decides whether to GetBlockByHash or wait).
- Pre-checkpoint slot → refused via existing `reorg_to_block` semantic.
- All errors `warn!` — never silent.

**2. Stage speculation, don't commit it.**

Add a `staged_block: Option<(slot, hash, Block)>` field to `ChainState` (or a parallel `SpeculativeState` next to it). The proposer's self-applied block and the view-1 fallback go HERE, not into `chain.head_slot`. Only QC promotes them via `commit_canonical`. If a *different* QC arrives, `staged_block` is dropped (no reorg needed because we never committed).

Concrete deletes:

- `node.rs:4176-4190` (the "applied own fallback block" inline commit) → replaced with `engine.stage_block(slot, hash, block)`.
- The proposer's slot-tick self-apply moves to staging.

This requires `staged_block` to be queryable for the finality-vote and decryption-share pipelines (they currently read `chain.state_root` post-apply). The state-root computation works against staged state and resolves to canonical once promoted.

**3. Time-based triggers become advisory-only.**

- `PROGRESS_TIMEOUT_MS`: emits a view-change *vote*. The VC-QC, when it forms, triggers fallback proposal *building*. Building → broadcasting → vote → QC → `commit_canonical`. We restore the build-vs-apply gap that was collapsed.
- Rotation: still wall-clock-triggered (audit-408 anchored clock) but only updates `engine.committee_keys` after `chain.head_slot >= rotation_slot`. Vote emission/verification reads `committee_keys_for_slot(slot)` (audit-411).
- WS anchor: peer-cert ingest unchanged. `validate_header_with_checkpoint` keeps the audit-415 strict-`<`.

### What gets cleaner

- `competing_blocks` (`node.rs:512`) becomes the *only* mechanism for fork resolution post-QC. Today only the own-vote-QC path consults it; under audit-ω `commit_canonical` consults it always.
- The audit-232 reorg logic at `node.rs:3712-3771` is *deleted* — `commit_canonical` does it.
- The audit-94 body-recovery path stays — body recovery is orthogonal — but its handler shrinks to "seed body → call `commit_canonical`".

## Migration sequence

Five commits, each independently buildable and testable:

### Commit 1: introduce `commit_canonical` + tests (this is what's being built first)

- New file `crates/node/src/canonical_commit.rs`.
- Function exists; nothing calls it yet.
- Unit tests cover every branch.
- Build green; no behavior change.

### Commit 2: route `ApplyCanonicalAfterQc` (line 2017) through `commit_canonical`

- Silent skip at line 2009 becomes hash-comparison via `commit_canonical`.
- New regression test: deterministic slot-3251 reproduction (two-validator harness, force one into view-1 fallback while the other commits canonical → assert lagging node reorgs).

### Commit 3: route RR-fallback canonical apply (line 1404) through `commit_canonical`

- Same skip-to-reorg conversion.
- Existing `validator::tests::audit_411_rotation_race_qc_verifies_under_old_committee_keys` should still pass.

### Commit 4: route own-vote-QC + hard-finality re-apply through `commit_canonical`

- Delete the audit-232 inline reorg at 3712-3771.
- Audit-94 body-recovery path simplifies.

### Commit 5: stage proposer + fallback self-apply

- Largest commit. Add `staged_block` to `ChainState`.
- Remove "applied own fallback block" inline commit.
- Proposer's slot-tick self-apply moves to staging.
- Soak validates: no more fork at slot 3251.

## Test plan

### Unit (`canonical_commit.rs`)

- Forward apply
- Idempotent: same hash, head already at slot → no-op, no log noise
- Reorg: different hash at slot, competing block buffered → reorg succeeds, head moves
- Reorg target not buffered → `DivergenceUnresolved` (warn, no panic)
- Gap: `qc_slot > head_slot + 1` → returns Gap variant
- WS-checkpoint-below: refuses to reorg past hard finality
- Header validation failure → `Failed`
- Body validation failure → `Failed`

### Integration (`crates/node/tests/`)

- `audit_omega_fork_on_fallback.rs`: deterministic slot-3251 reproduction.
- `audit_omega_lagging_node_via_cert.rs`: deterministic slot-1324 reproduction.
- `audit_omega_partial_vote_propagation.rs`: deterministic slot-1413 reproduction with `NetworkSim` shim dropping ~50% of votes.

### Property tests (`proptest`)

- 4-validator simulation. Random drop / reorder / delay of consensus messages.
- 1000 iterations. Assert: every iteration ends with all 4 nodes on the same `head_slot` and `state_root` after a quiescent period.
- Vary: `PROGRESS_TIMEOUT_MS`, drop rate (0–50%), delay distribution, rotation timing.

### Soak

Full 4h 1000 TPS soak should complete clean. Saturation (audit-417) tracked separately.

## Estimate

| Commit | Effort |
|---|---|
| 1: `commit_canonical` + unit tests | 0.5 day |
| 2: route `ApplyCanonicalAfterQc` | 0.5 day |
| 3: route RR-fallback | 0.5 day |
| 4: route own-vote + hard-finality | 0.5 day |
| 5: staging refactor | 1 day |
| Property tests | 1 day |
| Soak validation | 4–8h elapsed (unattended) |

**Total: ~3.5 dev-days + soak time.**
