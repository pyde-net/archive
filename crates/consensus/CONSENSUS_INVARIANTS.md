# Pyde Consensus — State Machine Invariants

Written 2026-04-26 as the design contract for the audit-234 follow-up
refactor (decouple `target_height` from `current_slot`,
single-leader-per-view fallback, RR fallback for liveness messages).

The invariants below are what the new state machine MUST hold. Each
characterization and regression test in `crates/consensus/tests/` and
`crates/node/tests/` should map to one of these.

---

## State

The validator's consensus state is keyed on `(height, view)`:

- `height: u64` — the position in the chain we are currently trying to
  commit. Monotonically non-decreasing; only advances when a block at
  `height` reaches a vote-QC AND is applied locally.
- `view: u64` — the recovery attempt within `height`. Starts at 0 for
  every fresh height; increments on view-change-QC formation.
- `current_slot: u64` — wall-clock slot, advanced by the engine tick
  every `SLOT_DURATION_MS`. Used for **timing decisions only**
  (when to time out, when to refresh randomness). Never used as the
  recovery target.

The relationship `height ≤ current_slot` always holds. They diverge
during recovery — the chain falls behind wall-clock until view-change
recovers, then catches up.

---

## Invariants

### Safety (must not be violated under any execution)

**S1 — Single-block-per-height.**
For every height `H`, the chain commits at most one block. Two
distinct blocks at the same `H` is a safety violation.

**S2 — No double-vote across views.**
For a given `(H, V)`, a validator votes for at most one block. A
validator MAY vote for different blocks at `(H, V1)` and `(H, V2)`
where `V1 ≠ V2` (this is what view-change is for), but only if it
locked on no QC at the lower view.

**S3 — Locked-QC monotonicity.**
A validator's `locked_qc.height` only increases. A vote for `(H, V)`
where `H ≤ locked_qc.height` is rejected at the create-vote layer.

**S4 — Persist-before-broadcast.**
For every state mutation that establishes `(H, V)` participation
(vote, view-change message, lock-bump), the change is fsync'd to
`ConsensusStateStore` BEFORE the corresponding wire message is
broadcast. A crash between persist and broadcast is recoverable; a
crash between broadcast and persist breaks S2.

### Liveness (must hold under partial-synchrony)

**L1 — Oldest-unresolved-height invariant.**
View-change always operates on the OLDEST `H` for which no block
has been committed locally, regardless of `current_slot`. If
`height = 145` and the wall-clock is now at slot 150, view-change
messages still target `(145, V)`, not `(150, *)`. The chain does
not skip past unresolved heights.

**L2 — Single deterministic leader per (H, V).**
For a given `(H, V)`, there is exactly one designated proposer:
`committee[fallback_index(H, V, committee_keys.len())]`. All
honest validators compute the same answer. Multiple
fallback-proposal candidates per `(H, V)` are NOT permitted.

> Note: the happy-path proposer (V=0) is selected by VRF as today.
> This invariant only applies to recovery views (V ≥ 1).

**L3 — View advancement.**
A validator advances `view` for height `H` when EITHER:
- it receives a `ViewChangeQC(H, V)` (advances to `V+1`), OR
- its view-change timeout for `(H, V)` expires AND it has not
  observed a vote-QC for `(H, V)` (advances to `V+1` and broadcasts
  a new view-change message).

`view` only increases. There is no "view 2 then view 1 again."

**L4 — At-least-once delivery for liveness messages.**
For each `(H, V)` recovery, the messages
`{ViewChange(H, V), Vote(H, V), Proposal(H, V)}` are delivered to
the designated leader (and to all validators for vote messages) via
**either** gossipsub OR the request-response fallback transport,
within `RECOVERY_DELIVERY_TIMEOUT_MS`. If gossipsub returns
`InsufficientPeers` OR a per-message deadline elapses, the sender
falls back to direct RR delivery to all known committee peers.

**L5 — Recovery progress.**
If `(H, V)` fails to commit within `VIEW_TIMEOUT_MS` (a function
of `V` — typically exponential backoff: `200ms * 2^V`), the
validator broadcasts `ViewChange(H, V+1)`. There is no upper bound
on `V`; recovery continues until 2f+1 validators are online and
mutually reachable.

### State-machine ordering

**O1 — Lock-then-vote.**
On receiving a valid proposal for `(H, V)`, the validator FIRST
updates its `locked_qc` if the proposal extends a higher QC, THEN
persists, THEN signs the vote, THEN broadcasts. Out-of-order writes
risk S3.

**O2 — Apply-then-advance.**
A block at height `H` is applied to local state only after a vote-QC
is formed AND the block matches the QC's `block_hash`. After apply,
`height` advances to `H+1` and `view` resets to 0.

**O3 — `current_slot` is timing-only.**
No safety or liveness decision reads `current_slot` directly. Only
`height` and `view` drive the state machine. `current_slot` is read
exclusively by:
- the timeout-firing predicate (`now_ms - slot_start_ms ≥ T`)
- the proposer-VRF input (which slot to compute candidacy for at V=0)
- epoch-randomness scheduling

---

## Failure modes the new design must close

These are what audit 234 surfaced. Each maps to an invariant above:

| Failure mode | Invariant violated today | New invariant that closes it |
|---|---|---|
| Slot-sync drift (VC msg targets wrong slot) | L1 | L1 (operate on oldest unresolved H) |
| Vote splitting (multiple fallback proposals per slot) | L2 | L2 (single deterministic leader per (H,V)) |
| Mesh inconsistency (gossipsub drops VC/votes) | L4 | L4 (RR fallback for liveness msgs) |
| `timeout` tracker reset on `advance_slot` (recovery state lost) | L1 + O3 | O3 (current_slot is timing-only) |

---

## Non-invariants (deliberate design choices, NOT properties to enforce)

- **The happy-path proposer is multi-proposer (lowest VRF score).**
  This is the latency-optimization that makes the chain fast on the
  happy path. Only the recovery (V≥1) leader is single-proposer.
- **Wall-clock fairness.** Different validators may observe slot
  boundaries at slightly different `now_ms`. The state machine is
  resilient to this skew via L3 and L5.
- **Equivalence between `height` and on-chain block slot.** They are
  the same number, but conceptually distinct: `height` is "what
  position am I trying to commit", which equals the block's `slot`
  field once the block exists.

---

## Testing matrix (what the regression tests cover)

| Test | Invariant under test |
|---|---|
| `slot_drift_does_not_advance_target_height` | L1, O3 |
| `view_change_targets_oldest_unresolved_height` | L1 |
| `single_fallback_leader_per_view` | L2 |
| `vote_split_recovers_via_view_advancement` | L3 |
| `gossip_drop_recovers_via_rr_fallback` | L4 |
| `repeated_view_failures_eventually_commit` | L5 |
| `persist_before_broadcast_holds_under_crash` | S4 |
| `locked_qc_never_decreases` | S3 |
| `single_block_per_height_under_partition` | S1 |

The first three are the failing tests in step 1c/1d of this PR
sequence; the rest land alongside steps 2-4 of the audit-234 fix.
