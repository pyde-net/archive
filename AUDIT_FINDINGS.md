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

- [x] 204 — `✓` **Wire-decoder unbounded `Vec::with_capacity`.**
      Audit called out 4 sites; full sweep found 18. Shipped:
      - `MAX_DECODE_ITEMS = 1_000_000` umbrella cap in
        `crates/node/src/wire.rs`.
      - New `Decoder::u16_count(max)` / `u32_count(max)` helpers
        that reject any length field above `max` before it drives
        `Vec::with_capacity`.
      - All 18 call sites migrated: 13 use the umbrella cap, 3 use
        `COMMITTEE_SIZE` (finality cert sigs, reshare committee
        keys, decryption shares), 2 use `MAX_SIGNERS` (multisig
        signatures).
      - 5 new tests: `decoder_u16_count_rejects_over_max`,
        `decoder_u32_count_rejects_over_max`,
        `decoder_count_at_max_is_accepted`,
        `compact_block_rejects_huge_short_id_count`,
        `decryption_shares_rejects_over_committee`.
      Line 891 left alone: index value pushed inside an already-
      bounded loop, not a count driving allocation.

- [x] 205 — `✓` **Persist double-vote evidence on detection.**
      `crates/node/src/validator.rs` `on_vote` equivocation branch
      now builds a full `DoubleSignEvidence` from the prior + current
      votes (both sigs, both hashes, signer from `voter_address`) and
      routes it through `ingest_evidence`, mirroring the existing
      double-propose path (`on_proposal` at :1189). `ingest_evidence`
      re-verifies both sigs, dedups on `(slot, signer)`, pushes to
      `pending_evidence` + `broadcast_evidence`, and persists via
      `ConsensusStateStore` before returning — crash between
      detection and next slot can no longer drop the evidence.
      New test `on_vote_detects_double_vote_and_queues_evidence`
      feeds two conflicting votes from the same signer and asserts
      the evidence lands in both queues with the correct sigs +
      hashes + signer.

- [x] 206 — `✓` **Close task 028 structural-only fall-through.**
      `crates/node/src/rpc.rs` `send_encrypted_transaction` now
      routes through a new `encrypted_tx_ingest_policy` helper with
      three arms: `Verify(pk)` when sender has a registered
      `Single` auth_key; `StructuralOnly` only on `chain_id ==
      31337` (devnet) for faucet / bootstrap UX; `Reject` on every
      other chain_id with RPC error `-32001`. 3 new unit tests
      cover all three branches across representative chain_ids
      (1, 2, 7, 1337, 1_000_000).

      Follow-up flagged while investigating: the PLAINTEXT path
      has an analogous issue — `validate_signature` in
      `crates/tx/src/validation.rs:140-149` accepts any tx whose
      sender account has `AuthKeys::None` without a signature
      check ("System/contract accounts — no signature check at
      this level"), and `load_account` at
      `crates/tx/src/pipeline.rs:148-158` returns a default EOA
      with `AuthKeys::None` for any address not yet in state.
      Balance-check gates the fund-loss exploit (a fresh
      attacker-chosen `from` has 0 balance, can't cover gas) but
      DoS-style mempool pollution is still possible within the
      M1/M3 caps. Not strictly a 206 fix; tracked as item **226**
      below for a follow-up PR.

- [~] 207 — `⚠` **Encrypted-tx gossip flow (074b root cause).**
      Compact-block broadcast omits `encrypted_txs`; full blocks
      only served on-demand via `GET_BLOCK_TXS`. Non-proposer
      validators never see encrypted_tx lists → decryption shares
      arrive orphaned and queue forever. Blocks the MEV headline
      and 074b.

      **Design locked in: option (D) — proposer publishes a
      dedicated `EncryptedTxBundle{slot, block_hash,
      encrypted_txs: Vec<Vec<u8>>}` message on the Blocks
      channel immediately after the compact block.**

      Rationale over original options:
      - (A) compact-block extension was the audit's default but
        costs a wire-format version bump and three new resolution
        paths (short-ID resolve → prefill check → GET_BLOCK_TXS
        fallback). More failure modes per PR.
      - (B) separate channel on Consensus topic — 64 KB cap too
        tight for an encrypted-tx bundle at useful scale.
      - (C) proactive full-block push — burns bandwidth at scale.
      - (D) picked: proposer→validators message on the 4 MB
        Blocks channel. No wire-format version bump to CompactBlock,
        no new short-ID tables, one message type. Testnet-MVP
        scale suits simplicity over efficiency; (A) upgrade
        remains open for later (short-ID derivation is already
        generic — `compute_short_id` takes any `[u8; 32]`).

      **Integrity anchor: existing `tx_root`.** `BlockHeader::
      tx_root` already commits to plaintext-tx hashes ++
      encrypted-tx hashes in order (`crates/consensus/src/
      block.rs:198`, load-bearing for MEV). Receiver reassembles
      the bundle, computes `EncryptedTx::hash()` per entry, calls
      `verify_tx_root(&header.tx_root, &plaintext_txs,
      &encrypted_tx_hashes)`. Mismatch → reject. No new sigs.

      **Implementation plan (3 PRs):**
      1. **Wire + struct.** Add `EncryptedTxBundle` to
         `crates/net/src/propagation.rs`; add tag +
         encode/decode in `crates/node/src/wire.rs`; round-trip
         tests. No behaviour change — wire only.
      2. **Proposer + receiver plumbing.** Proposer publishes
         the bundle immediately after `encode_compact_block`;
         receiver queues bundle alongside compact block, runs
         `verify_tx_root` when both arrive, hands full
         `encrypted_txs` into the existing `BlockDecryptor`
         pipeline so queued shares can drain.
      3. **Multi-node integration + 074b.** Spawn a testnet,
         submit via `pyde_sendEncryptedTransaction`, assert the
         decrypted tx commits. Unblocks 074b loadgen.

      **Non-issues deliberately excluded:**
      - No per-bundle signature. `tx_root` verifies integrity.
      - No ordering invariant beyond the block body's own order.
        Ordering commitment to mempool-seen txs (task 024) is
        unchanged.
      - No encrypted-tx gossip outside of block context.
        Users still submit via `pyde_sendEncryptedTransaction`
        → `tx_relay` → Transactions channel, and the proposer
        picks from their local mempool as today. The new
        bundle is strictly a block-time proposer→validators
        distribution mechanism.

      **Known risks:**
      - Bundle and compact block arrive out of order. Mitigation:
        receiver queues either arrival and resolves when both
        are present, with a slot-bounded TTL (drop if the slot
        is already 2+ behind head).
      - Proposer publishes bundle but a validator never receives
        it (gossip gap). Same mitigation as today for
        compact-block tx resolution: fall back to `GET_BLOCK_TXS`
        with a new tag for encrypted-tx bodies.
      - Malicious proposer omits bundle. Receiver doesn't have
        encrypted_tx bytes; `verify_tx_root` fails if any
        encrypted_tx is expected (tx_root non-zero from
        encrypted inputs). Block is rejected at the validator,
        QC won't form. Liveness impact only.

---

## P1 — Must fix before external audit / launch

> Parallelisable with 207 once P0 trivials are in.

- [x] 207a — `✓` **Hard-finality persistence ordering.**
      Shipped: new `persist_finality_checkpoint_direct(&cp)` takes
      the checkpoint explicitly and writes it to disk before
      returning. All three call sites — `install_bootstrap_ws_
      anchor`, `on_finality_vote` (hard-finality cert path), and
      `ingest_finality_checkpoint` (gossip path) — now construct
      the checkpoint, fsync it via `_direct`, and ONLY then mutate
      `self.finality`. Persist panics on I/O failure, which aborts
      before the memory mutation, so the invariant "on-disk ≥
      in-memory" holds across every crash window. Kept the old
      `persist_finality_checkpoint()` as a thin `dead_code`
      wrapper for tests + devnet bootstrap. 65 validator tests +
      multi-node encrypted e2e still pass.

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

- [ ] 226 — `⚠` **Plaintext RPC path: `AuthKeys::None` sig-skip
      analog.** Surfaced while closing 206.
      `crates/tx/src/validation.rs:140-149` — `validate_signature`
      accepts any tx whose sender account has `AuthKeys::None`
      without a FALCON check (comment: "System/contract accounts
      — no signature check at this level"). `load_account` at
      `crates/tx/src/pipeline.rs:148-158` returns a default EOA
      with `AuthKeys::None` for any address not yet in state, so
      an attacker can submit `send_raw_transaction` with
      `from = victim_fresh_address` and no signature and clear
      `validate_signature`. Balance-check gates fund-loss (fresh
      account has 0 balance) but the mempool pollution surface is
      still non-zero within M1/M3 caps. Fix: at RPC ingress on
      production chain_id, require the sender account to exist
      with a registered auth_key (OR take a narrow
      faucet-allowlist path), mirroring the 206 policy. Keep the
      internal contract-to-contract path unaffected.

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
| 201 | 2026-04-23  | Traced `on_finality_vote` + `persist_finality_checkpoint` call order | Real race but not BFT-critical; P1 (207a) |
| 202 | 2026-04-23  | Read `crates/pvm/src/vm.rs:525-575` | Wrapping is by-design; shipped parity test |
| 203 | 2026-04-23  | Read `threshold.rs:530-547` + `rg ConstantTimeEq crates/crypto/` (0 hits) | Confirmed; fixed with `ct_eq` |
| 204 | 2026-04-23  | Full sweep of `wire.rs` decoders (18 sites) | Fixed with `u16/u32_count(max)` helpers |
| 205 | 2026-04-23  | Read `validator.rs:1443-1466` | Confirmed: `else` persists, `if` only logs; routed through `ingest_evidence` |
| 206 | 2026-04-23  | Read `rpc.rs:1117-1148` + `pool.rs:370-384` | Confirmed fall-through on no-auth_key; closed for non-devnet chain_id |
| 207 | 2026-04-23  | Agent-traced against wire.rs compact-block encoding | Accepted; design decision needed |
