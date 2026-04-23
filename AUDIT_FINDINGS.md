# Pyde Audit Findings (2026-04-23)

> Full-workspace audit surfaced while reviewing mainnet readiness.
> Complements `MAINNET_PLAN.md` — items here are NEW findings not
> already tracked as plan tasks. IDs start at 201 to avoid collision.
>
> Legend:
>
> - `[ ]` = not started
> - `[x]` = complete
> - `[~]` = in progress
> - `[?]` = claim unverified; investigation required before fix
> - `[!]` = blocked
>
> Verification marks:
>
> - `✓` self-verified against source
> - `⚠` agent-claimed, not yet independently verified
>
> Ordering rationale (top of file):
>
> 1. **Verify-before-fix** first. One P1 finding (hard-finality race)
>    could flip to P0 — resolve its severity before touching anything
>    else so the queue below is actually in priority order.
> 2. **Trivial + isolated P0s next.** Single-file, low-blast-radius,
>    testable in isolation. Builds PR rhythm, avoids half-finished
>    branches blocking each other.
> 3. **Boundary-logic P0 (028 fall-through) after trivials.** Needs
>    decision on the devnet vs mainnet split; still small.
> 4. **Architectural P0 (074b encrypted gossip) last in the P0
>    cluster.** Biggest design space; do it when the smaller P0s have
>    drained so we can focus without context-switching.
> 5. **P1 track** once P0s land.
> 6. **P2 track** before testnet alpha, parallelisable.

---

## At a glance

- 5 parallel audit agents + follow-up spot checks, 2026-04-23.
- 4 P0 (mainnet blockers), 11 P1 (must-fix before audit/launch),
  7 P2 (pre-testnet-alpha hygiene).
- 22 fix items total. Sized for one PR each.
- Each item carries its own file:line refs and verification mark so
  the rework after auditor findings is smaller.

---

## Closed before classification

- [x] 201 — `✓` **Verify hard-finality persistence race.**
      Traced `on_finality_vote` (validator.rs:1545-1570),
      `record_hard_finality` (finality.rs:257-281),
      `persist_finality_checkpoint` (validator.rs:768), and
      the two sibling call sites at 1629 and 761. Race is real
      but NOT a classical BFT safety violation: no broadcast in
      the window (broadcast runs after `on_finality_vote` returns,
      see comment at validator.rs:1572-1577); self-healing via
      peer gossip + `ingest_finality_checkpoint`; cannot produce
      two hard-finalized blocks at the same slot. Exploitable
      only in an esoteric combined crash + isolation + active
      long-range-attack scenario.
      **Verdict: not P0. Promoted to head of P1 as task 207a
      below.** Fix approach: refactor `persist_finality_
      checkpoint` to take cert/checkpoint directly instead of
      reading from `self.finality`; persist before in-memory
      update at all three call sites.

---

## P0 — Mainnet blockers

> Order: smallest / most-isolated first.

- [x] 202 — `✓` **PVM `Addi` divergence-risk parity test.**
      Original audit framing ("trap-bypass; change to `checked_add`")
      was wrong. Investigation found `Addi` wraps BY DESIGN — the
      otic compiler relies on it for:
      - constant materialisation via sign-extended negatives
        (e.g. `REENTRANCY_SLOT = (-2i32 as u32) & 0x3FFFF`,
        `crates/otic/src/codegen.rs:44`, emitted at `:843, :870`);
      - two's-complement negation pattern `Not rd; Addi rd, rd, 1`
        (`crates/otic/src/codegen.rs:1131`);
      - loading `u64::MAX` via `Addi rN, r0, -1` (`:1615, :1639,
        :1661, :1681, :2918, :3078`).
      Changing to trap-on-overflow broke 3 real-contract AOT tests
      on revert. The REAL audit concern was divergence risk between
      interpreter and Cranelift AOT. Both wrap consistently today;
      fix is a parity test that fails loudly if either side drifts.
      **Shipped:** clarifying comment at
      `crates/aot/src/codegen.rs:527` + new test
      `addi_aot_interp_wrap_parity` in `crates/aot/src/lib.rs`
      covering 9 adversarial `(imm1, imm2)` pairs including
      u64::MAX roll-over in both directions.

- [x] 203 — `✓` **Constant-time MAC verification in threshold
      decryption.** Shipped: added `subtle = "2"` (no_std) as a
      direct dep of `pyde-crypto`; `threshold.rs:540` now uses
      `expected_mac.ct_eq(&ct.mac).unwrap_u8() == 0` instead of
      `!=`. New regression test `tampered_mac_byte_fails_
      verification` flips one MAC bit and asserts the mismatch
      branch returns the generic error.
      Sweep verdict: the other `==`/`!=` hits in `crates/crypto/`
      and `crates/consensus/` are on public data (block hashes
      used in slashing evidence + QC / finality lookup, share
      indices that identify which validator contributed, length
      comparisons on public-structure fields) — no additional
      constant-time fixes needed today. One borderline site
      (`threshold.rs:928` in `verify_resharing_contribution`,
      comparing reconstructed polynomial evaluation against
      sub-share) left alone: the compared values are destined
      for cross-committee delivery and not secret from the new
      committee; upgrading it is worth a look if PSS ever gets
      a VSS commitment layer (see Deferred section of
      `MAINNET_PLAN.md`).

- [ ] 204 — `✓` **Wire-decoder unbounded `Vec::with_capacity`.**
      `crates/node/src/wire.rs:256-260, 361-370, 591-598, 760-764`
      decode u16/u32 length fields straight into
      `Vec::with_capacity` before validating. Gossipsub frame caps
      (64 KB consensus / 128 KB tx) mitigate worst case, but nested
      lists inside a legal frame can still force large allocations.
      Fix: per-field constants (`MAX_VOTES`, `MAX_SIGS`,
      `MAX_ACCESS`, `MAX_TIMEOUTS`) enforced after decode, before
      any allocation.

- [ ] 205 — `⚠` **Persist double-vote evidence on detection.**
      `crates/node/src/validator.rs:1443-1449` — the equivocation
      branch only `warn!`s; only the "new vote" branch persists
      via `ConsensusStateStore`. Crash between detection and next
      slot drops the evidence, loses slashing + finder's fee.
      Fix: on detection, save evidence via the store before
      continuing; reuse task 014c persistence schema.

- [ ] 206 — `✓` **Close task 028 structural-only fall-through.**
      `crates/node/src/rpc.rs:1117-1141` + `crates/mempool/src/
      pool.rs:370-384`. Encrypted-tx RPC ingress only runs full
      FALCON verify when the sender has a registered `auth_key`;
      senders with no registered key take the length-only path.
      Every fresh address has this window — an attacker can forge
      encrypted txs claiming `sender = victim_new_address` until
      the victim registers. Plan marks 028 done but the fall-through
      is mainnet-exploitable.
      Fix: on `chain_id != devnet`, require either a registered
      `auth_key` OR membership in a narrow faucet allowlist.
      Devnet keeps the fall-through for bootstrap UX.

- [ ] 207 — `⚠` **Encrypted-tx gossip flow (074b root cause).**
      Compact-block broadcast in `crates/node/src/node.rs` omits
      `encrypted_txs`; full blocks only served on-demand via
      `GET_BLOCK_TXS` (`crates/node/src/wire.rs:415`). Non-proposer
      validators never see encrypted_tx lists → decryption shares
      arrive orphaned and queue forever. Blocks the headline
      MEV-protection claim and 074b.
      Fix: design doc first, choose among:
      (A) extend compact-block protocol with encrypted_tx short IDs;
      (B) separate gossipsub topic for encrypted_txs, published by
      proposer alongside the block;
      (C) proactive full-block push to committee members.
      Then implement + add `074b` loadgen pass.

---

## P1 — Must fix before external audit / launch

> Parallelisable with 207 once P0 trivials are in.

- [ ] 207a — `✓` **Hard-finality persistence ordering.**
      Promoted from 201. `crates/node/src/validator.rs:1560-1566,
      1628-1630, 758-762` — three call sites update
      `self.finality.latest_checkpoint` in-memory via
      `record_hard_finality` / direct assignment / synthetic-anchor
      assignment, then call `persist_finality_checkpoint` which
      reads the value back out of `self.finality`. Crash in the
      window reverts the WS anchor on restart (self-heals via
      peer gossip, but a non-self-healing window exists).
      Fix: new `persist_finality_checkpoint_direct(&cp)` that
      takes the checkpoint explicitly; call it BEFORE the
      in-memory mutation at each of the three sites; keep the
      current `persist_finality_checkpoint()` as a no-longer-used
      thin wrapper (or remove) so no new site can regress.

- [ ] 208 — `⚠` **Committee rotation: clear old committee keys.**
      `crates/node/src/validator.rs:828-841` — `set_committee`
      overwrites but if a rotation is reverted mid-reshare, an
      isolated old member can keep signing. Not fund-loss; quorum
      dilution + liveness risk.

- [ ] 209 — `⚠` **PVM gas-metering audit.**
      (a) verify `isa::total_gas(Opcode::Addi)` is non-zero (else
      infinite `ADDI`-only loop is free);
      (b) audit cold/warm storage tracking: `warm_storage_keys`
      lives inside each `Vm`, so each parallel execution group
      starts cold — over- or under-charging depending on group
      merge semantics.

- [ ] 210 — `⚠` **Weak-subjectivity enforcement API.**
      `crates/node/src/block_processor.rs:45-56` —
      `ws_checkpoint_slot` is `Option<u64>`; public variants pass
      `None`. Easy to call a non-enforcing variant and re-open
      long-range attack window. Make required or assert at entry.

- [ ] 211 — `⚠` **Kyber ciphertext domain separation.**
      `crates/crypto/src/kyber.rs` — encapsulation has no explicit
      chain_id/slot binding. Sender-FALCON binding (028) covers
      the dominant replay vector; protocol-level binding is
      defence-in-depth and required for cross-chain replay
      resistance.

- [ ] 212 — `⚠` **FALCON signature malleability check.**
      Any site that dedups / slashes keyed on signature bytes
      is brittle if the upstream `falcon` crate permits multiple
      valid sigs per `(pk, msg)`. Verify upstream; add a
      malleability proptest; add canonicalisation if needed.

- [ ] 213 — `⚠` **VRF input audit.**
      `crates/crypto/src/vrf.rs` — confirm all VRF preimage
      components are chain-determined (epoch, prev block hash,
      slot). Any proposer-chooseable input opens committee
      selection to grinding.

- [ ] 214 — `⚠` **Per-peer rate limit on decryption shares.**
      `crates/node/src/node.rs` consensus handler — frame-size
      cap bounds per-message burst but no per-peer token bucket.
      Add same `RateLimiter` pattern used for evidence (task 014d).

- [ ] 215 — `⚠` **PVM `MEMCPY` + calldata u32 wrap.**
      `crates/pvm/src/vm.rs:1265-1288` (MEMCPY no src/dst overlap
      check) + `:364-388` (calldata `aligned_len = (len + 7) & !7`
      can wrap `u32`). Potential heap/stack collision under
      adversarial input. Pair with task 054 cargo-fuzz soak.

- [ ] 216 — `⚠` **Poseidon2 spec-match test.**
      `crates/crypto/src/poseidon2.rs` — tests assert capacity but
      not round counts (RF=8, RI=22 for Plonky3 default). Add a
      constants-match test pinned to the reference.

- [ ] 217 — `⚠` **Witness oversize rejected without charging.**
      `crates/state/src/witness.rs:149-173` — `verify_witnesses`
      returns `false` on >1 MB witness with no gas charge.
      Mitigated by the 1 MB gate; worth charging a minimum inspection
      fee so RPC-reachable DoS is non-free.

- [ ] 218 — `✓` **Validator-only consensus channel: publish-time
      guard.** `crates/net/src/channels.rs` enforces on inbound
      validate; no pre-publish check. Belt-and-suspenders. Add
      assertion before any `swarm.gossipsub.publish` on the
      consensus topic.

---

## P2 — Pre-testnet-alpha hygiene

- [ ] 219 — **Startup guard on empty `MAINNET_BOOTSTRAP`.**
      `crates/net/src/discovery.rs:14` — empty array, allowed by
      task 011's config-file-injection option. Add a startup
      refusal when `chain_id == 1` and no bootstrap peers
      configured.

- [ ] 220 — **Fast-sync / snapshot wiring.**
      `crates/state/src/state_manager.rs:220-253` has
      `export_snapshot` / `import_snapshot` but `crates/node/src/
      sync.rs` never calls them. Cold-sync works; no fast-sync.

- [ ] 221 — **Operator keystore / HSM design.**
      `crates/node/src/validator.rs:40` holds raw `FalconSecretKey`
      in memory. No encrypted-at-rest keystore, no HSM hook.
      Mainnet operators will require this.

- [ ] 222 — **Operator metrics coverage.**
      `crates/node/src/metrics.rs` exposes a Prometheus endpoint
      but mempool depth, block-lag, missed-proposal counters are
      not instrumented. Grafana dashboards under `docker/grafana/`
      are minimal.

- [ ] 223 — **Reorg handling.**
      No explicit state-rollback / chain-tip-reversal code path
      found. Document current reorg semantics; add explicit path
      if gaps exist.

- [ ] 224 — **Block explorer / indexer (plan 083).**
      No code. Plan tracks; listed here for visibility alongside
      other mainnet-operator gaps.

- [ ] 225 — **Faucet web UI (plan 082 partial).**
      `crates/node/src/faucet.rs` is the RPC half only; no
      frontend / public API exposure.

---

## Test-coverage follow-ups (not standalone fix items)

Fold into the relevant fix PRs above when possible:

- `crates/consensus/` and `crates/mempool/` have zero integration
  tests (`tests/` dir). Add per-fix as PRs land.
- `crates/net/` has one integration test for a whole P2P layer.
- Multi-node gap list (tracked by plan, not repeated here).
- Fuzz targets: 3 live, 4+ queued (plan 053, 054).

---

## Verification log

| ID  | Verified on | How | Verdict |
|-----|-------------|-----|---------|
| 201 | pending     | —   | —       |
| 202 | 2026-04-23  | Read `crates/pvm/src/vm.rs:525-575` | Confirmed asymmetry |
| 203 | 2026-04-23  | Read `threshold.rs:530-547` + `rg ConstantTimeEq crates/crypto/` (0 hits) | Confirmed |
| 204 | 2026-04-23  | Agent-traced; self-check pending at fix time | Accepted |
| 205 | 2026-04-23  | Read `validator.rs:1443-1466` | Confirmed: `else` persists, `if` only logs |
| 206 | 2026-04-23  | Read `rpc.rs:1117-1148` + `pool.rs:370-384` | Confirmed fall-through on no-auth_key |
| 207 | 2026-04-23  | Agent-traced against wire.rs compact-block encoding | Accepted; design decision needed |
