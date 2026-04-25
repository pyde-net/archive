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

- [x] 208 — `✓` **Committee rotation: clear old committee keys.**
      Closed on investigation, not a bug. `set_committee` does
      `self.committee_keys = keys;` — Rust's assignment drops the
      old Vec (memory freed, no references remain); old pubkeys
      aren't "lingering." Agent conflated this with a distinct
      concern — "isolated old validator comes back with stale
      state" — which is covered by weak-subjectivity checkpoints,
      not by `set_committee`'s memory semantics.

- [x] 209 — `✓` **PVM gas-metering audit.** Closed on
      investigation, both sub-concerns not bugs.
      (a) `Opcode::Addi => GasCost::new(3)` at
      `crates/pvm/src/isa.rs:480`. Non-zero; infinite-loop DoS
      concern invalid. Test `total_gas_table_matches_gas_cost`
      (`isa.rs:854`) enforces table consistency.
      (b) `warm_storage_keys` per-tx is exactly EIP-2929
      semantics — warm tracking is intentionally reset per tx.
      Cross-tx warming within a parallel group isn't a feature
      (and wouldn't be correct; two txs touching the same slot
      both pay cold on their first access). Child calls inside
      a single tx do inherit parent's warm keys (`vm.rs:1644`
      clone, `:1684` extend), which matches Ethereum.

- [x] 210 — `✓` **Weak-subjectivity enforcement API.** Shipped:
      the non-checkpoint public wrappers `process_full_block`
      and `process_full_block_with_aot` are now `#[cfg(test)]`
      so they can't be reached from production code. Production
      callers (`sync.rs:242`, `node.rs:994 / 1494 / 2298`) all
      go through `process_full_block_with_aot_and_checkpoint`
      with the live tracker's `latest_checkpoint.slot`. Test
      callers (`block_processor.rs` mod tests, `validator.rs`
      mod tests) unaffected.

- [x] 211 — `✓` **Kyber ciphertext domain separation.** Closed
      on investigation, not a bug at the layer that matters. The
      outer `EncryptedTx::hash()` already binds `(sender ||
      nonce || gas_limit || chain_id || ct_hash)` and the FALCON
      signature covers this hash. Cross-chain / cross-slot
      replay is blocked at the envelope layer. Adding inner
      Kyber context-binding would be defence-in-depth but isn't
      load-bearing; the envelope is.

- [x] 212 — `✓` **FALCON signature malleability check.** Closed
      on investigation, not a critical bug. Audit of dedup sites:
      `seen_votes` (validator.rs) keys on `(slot, voter_index)`,
      not sig bytes. `seen_evidence` (validator.rs) keys on
      `(slot, signer address)`, not sig bytes. `seen_proposals`
      keys on `(slot, proposer address)`, not sig bytes.
      No production dedup uses signature bytes as the key, so
      even if FALCON permits multiple valid sigs per (pk, msg),
      none of Pyde's slashing / vote counting / evidence
      submission logic is affected.

- [x] 213 — `✓` **VRF input audit.** Closed on investigation,
      not a bug. VRF inputs used on the consensus hot path:
      - Proposer VRF (`validator.rs:1190`,
        `block_processor.rs:568`): `epoch_randomness || slot_le`.
        Both chain-deterministic (epoch_randomness is itself a
        VRF output from the prior epoch; slot is a counter).
      - Randomness VRF (`epoch_randomness.rs:64`): input is
        `epoch`. Deterministic.
      No proposer-chooseable inputs anywhere, so the committee-
      selection grinding attack the agent flagged is not
      reachable.

- [x] 214 — `✓` **Per-peer rate limit on decryption shares.**
      Shipped: `crates/node/src/node.rs` decryption-share gossip
      branch now checks `peer_manager.get_peer(propagation_source)
      .invalid_messages` against `DECRYPT_SHARE_SPAM_THRESHOLD = 5`
      before decode, mirroring the slash-evidence pattern from
      task 014d. Malformed shares bump `invalid_messages` via
      `saturating_add(1)` in the decode-Err arm, so repeat
      offenders cross the threshold and get dropped without CPU
      cost on the next message. Honest committee shares decode
      cleanly and never bump the counter. Also dropped dead
      `process_full_block_with_aot` test wrapper (zero callers
      after 210's `#[cfg(test)]` gate). Multi-node encrypted e2e
      (`multi_node_encrypted_lifecycle` --ignored) still passes.

- [x] 215 — `✓` **PVM MEMCPY + calldata u32 wrap.** Original audit
      framing was wrong on the surface concerns — `MEMCPY` uses an
      owned `Vec<u8>` intermediate (`checked_read_slice`) so guest
      src/dst overlap is memmove-safe, not a memory-safety issue.
      But investigation surfaced **three real consensus-critical
      bugs** in the same opcode, fixed in this PR:
      
      1. **Interpreter MEMCPY len truncation** — `len: usize` from
         `read_gp` flows into `checked_read_slice` → `check_access`,
         which casts `len as u32` and silently wraps for any
         `len > u32::MAX`. A guest passing `u64::MAX` would slip
         past bounds checking and trigger `vec![0u8; huge_len]`
         host-RAM DoS. Fixed by gating `len > MEMORY_SIZE → trap`
         before the cast. Also switched gas-charge `+=` to
         `checked_add` so a crafted len that wraps `gas_used_total`
         past `gas_limit` cannot bypass OOG.
      2. **AOT host_memcpy missing per-byte dynamic gas** —
         interpreter charges `(len/8)*3` in its handler; AOT bypassed
         it entirely (only static base gas of 5 was charged via the
         block prologue). Same contract burned 384 vs 0 dynamic gas
         on AOT vs interpreter validators ⇒ consensus fork on every
         memcpy. Fixed by emitting the dynamic-gas charge in the
         Cranelift codegen before the host call (AOT tracks gas in
         a Cranelift SSA variable, not in `vm.gas_used_total`, so
         charging it in `host_memcpy` would have been a no-op).
      3. **AOT host_memcpy missing per-page allocation gas** —
         interpreter drains `vm.memory.page_gas_used` (200 per
         fresh page) into `gas_used_total` after every step at
         `vm.rs:1388`. AOT bypasses that loop. `host_memcpy` now
         packs the drained `page_gas_used` into the high 32 bits
         of its return value; codegen folds it into `VAR_GAS_USED`
         after the call. Plus: AOT codegen previously discarded
         the host_memcpy fault return entirely — silently continued
         on memory fault. Now routes through `trap_block`.
      
      `crates/pvm/src/vm.rs` `map_calldata` got the same defensive
      gate (`len > MEMORY_SIZE - HEAP_START → trap`) — calldata is
      bounded in practice by tx/block size so this is defense-in-
      depth, not a known reachable bug.
      
      Tests: 4 PVM tests
      (`memcpy_len_over_memory_size_traps_memory_fault`,
      `memcpy_len_at_memory_size_boundary_is_accepted`,
      `memcpy_gas_overflow_cannot_bypass_oog`,
      `map_calldata_oversize_traps_memory_fault`) +
      2 AOT tests
      (`memcpy_aot_charges_dynamic_gas_parity_with_interp` —
      asserts exact AOT/interp gas equality on a 1024-byte copy;
      `memcpy_aot_huge_len_traps`).
      
      **Surfaced for follow-up: item 228 below** — the broader AOT
      page-gas parity gap (Load/Store/wide-load/wide-store all
      bypass the page-allocation gas the interpreter charges).

- [ ] 216 — `⚠` **Poseidon2 spec-match test.**
      `crates/crypto/src/poseidon2.rs` — tests assert capacity but
      not round counts (RF=8, RI=22 for Plonky3 default). Add a
      constants-match test pinned to the reference.

- [x] 217 — `✓` **Witness oversize rejected without charging.**
      Closed on investigation, not currently a bug. Searched
      every caller of `verify_witnesses`: **only tests and
      benches** (`crates/state/benches/smt_bench.rs:193`,
      same module's tests). No RPC handler, gossip handler, or
      tx pipeline path verifies witnesses today. The `BlockWitness`
      type lives in `crates/state/src/witness.rs` as
      stateless-validator infrastructure that hasn't been wired
      into the production block-processing path yet. The
      audit's "RPC-reachable DoS" concern doesn't apply because
      the surface isn't reachable. Re-open with a gas charge
      when the stateless path lands (post-mainnet).

- [x] 218 — `✓` **Validator-only consensus channel: publish-time
      guard.** Shipped: `crates/node/src/node.rs` now wraps
      every consensus-topic publish in an `is_validator` gate.
      Three sites covered:
      - `PostEventAction::BroadcastConsensus` handler (the
        general-purpose path)
      - `PostEventAction::BroadcastConsensusMany` handler
      - The engine-driven `maybe_rebroadcast_reshare` inline
        publish in the slot tick.
      
      The other consensus publishes (epoch randomness share,
      PSS refresh, committee reshare contribution) are already
      inside `if let Some(identity) = validator_identity.as_ref()`
      blocks, which by construction implies validator role.
      The new gates are defense-in-depth — they catch any
      future code path that builds a consensus message
      without the validator-state precondition. Non-validator
      attempts log `warn!` so the bug shows up in logs
      instead of silently propagating to the wire.
      
      Multi-node encrypted e2e still passes; clippy clean.

---

## P2 — Pre-testnet-alpha hygiene

- [ ] 219 — **Startup guard on empty `MAINNET_BOOTSTRAP`.**
      `crates/net/src/discovery.rs:14` — empty array, allowed by
      task 011's config-file-injection option. Add a startup
      refusal when `chain_id == 1` and no bootstrap peers
      configured.

- [x] 220 — `✓` **Fast-sync / snapshot wiring.** Investigation
      found that snapshot endpoints (`request_state_snapshot`,
      chunked `import_snapshot`) WERE already implemented in
      `crates/node/src/sync.rs` and the response handler — what
      was missing was the **auto-trigger**: nothing called
      `request_state_snapshot` from production code, so a fresh
      node always cold-synced block-by-block (impractical past
      ~1000 slots).
      
      Shipped: `request_next_batch` now checks
      `should_use_snapshot_sync()` first. Snapshot mode is
      preferred when:
      - initial sync isn't done yet (post-initial-sync nodes
        keep using gossip + small block-batch catch-up to avoid
        bouncing back into snapshot mode)
      - no snapshot is already in flight
      - `slots_behind > SNAPSHOT_THRESHOLD` (1000 slots,
        ~6.7 minutes at 400 ms/slot)
      
      Predicate extracted as a separate fn for unit testability
      (the swarm-mocking required to hit `request_state_snapshot`
      directly is heavy). 4 new tests cover the trigger branches:
      far-behind triggers, close-enough doesn't, post-initial
      doesn't, in-flight doesn't double-request. Removed two
      `#[allow(dead_code)]` annotations (`SNAPSHOT_THRESHOLD`
      and `request_state_snapshot`) now that they're live. 231
      pyde-node unit tests + multi-node encrypted e2e pass.

- [x] 221 — `✓` **Operator keystore (encrypted-at-rest validator
      key).** Shipped: new `crates/node/src/keystore.rs` provides
      AES-256-GCM encryption with a Poseidon2-derived key
      (passphrase + salt). Format mirrors the Rust SDK's wallet
      `Keystore` so the same operator tooling works.
      `load_validator_identity` now auto-detects format on disk:
      JSON → encrypted (decrypt via `PYDE_VALIDATOR_PASSPHRASE`
      env var); raw bytes → legacy path with a deprecation
      `warn!`. New keys are written encrypted iff the env var
      is set, falling back to raw bytes for devnet ergonomics.
      File permissions tightened to 0o600 on Unix regardless of
      format. Tests: roundtrip, wrong-passphrase rejection,
      empty-passphrase rejection on both directions, format-
      discrimination, version-mismatch rejection. 227 pyde-node
      unit tests + multi-node encrypted e2e pass.
      
      HSM hook deferred: the abstraction surface is small (read
      `FalconSecretKey` from somewhere) and can wrap the keystore
      module with a `KeyProvider` trait when an actual HSM is
      brought online. For testnet / early-mainnet, encrypted-at-
      rest is the operator-blocking gap.
      
      Open follow-up: PBKDF2 / Argon2 instead of single-pass
      Poseidon2 for KDF. Single-pass is fine for the strong
      passphrases operators use, but external auditors typically
      want a memory-hard KDF.

- [x] 222 — `✓` **Operator metrics coverage.** Existing
      `metrics.rs` had: head_slot, blocks_processed,
      transactions_processed, gas_used, block_processing_ms,
      peers, mempool_size. Added the operator-actionable
      gauges + counters most Prometheus alert rules need:
      
      - `pyde_block_lag` (gauge): `network_tip - head_slot`.
        Operators alert on > 10 → node falling behind.
      - `pyde_finality_lag` (gauge): slots since the latest
        hard-finality checkpoint. Steady state ~2 slots; > 100
        → consensus liveness degrading.
      - `pyde_encrypted_mempool_size` (gauge): separate from
        plaintext `pyde_mempool_size` so alerts can target
        the MEV-protected queue specifically (signals stuck
        threshold-decryption pipeline).
      - `pyde_reorgs_total{outcome}` (counter): bumped on every
        reorg attempt from the audit-232 paths, labelled by
        outcome (`succeeded`/`target_not_buffered`/`failed`).
      - `pyde_state_commit_ms` (histogram): SMT/RocksDB commit
        latency, isolated from end-to-end block processing.
        Spikes here drive `block_processing_ms` p99 — having
        them split lets operators root-cause without staring
        at end-to-end histograms.
      - `pyde_rpc_requests_total{method, outcome}` (counter):
        wired into `pyde_sendRawTransaction` as the canonical
        write path. Other handlers can be wrapped one-by-one
        with the same pattern (single async-block + the
        `record_rpc_request` call).
      - `pyde_validator_missed_proposals_total` (counter):
        defined but `#[allow(dead_code)]`. Wiring point is in
        `validator.rs` where the multi-proposer VRF window
        expires without `select_and_vote` producing a
        proposal — flagged as a 222 follow-up so this PR
        stays focused on the gauge plumbing.
      
      Wired into the existing periodic-maintenance tick in
      node.rs, the background Merkle-commit task, the audit-232
      reorg handlers (both gossip-vote and own-vote paths),
      and the RPC handler. All 222 pyde-node unit tests +
      multi-node encrypted e2e pass.

- [~] 223 — `✓` **Reorg handling.** Investigation found
      structural gaps: state is committed eagerly on block
      receive (not after QC), `chain.head_slot` is monotonic
      (no rollback), `VersionedState` exists in
      `crates/state/src/versioning.rs` but is unwired, and
      sync rejects any block at `slot ≤ head_slot` so a node
      that committed the wrong block at slot N can never
      recover via gossip. HotStuff + multi-proposer VRF
      makes the bug rare in practice (failures are liveness
      not safety) but it's a real prod-readiness gap.
      
      Splitting into 3 PRs (was 2; 232 split off because the
      receive-path wire-up + multi-node partition test deserve
      their own review surface):
      - **230 (shipped): mechanism**. `StateOverlay::into_writes_with_undo`
        + `StateManager::revert_to` + `ChainState::revert`.
        Wired into BlockProcessor's single-group + multi-group
        paths so every block emits an undo log. Bounded to 128
        recent blocks. APIs `#[allow(dead_code)]`.
      - **231 (this PR): reorg primitive**. Adds
        `BlockProcessor::reorg_to_block(target)` that orchestrates
        the revert + reapply + WS-checkpoint guard. Crucially,
        also fixes a 230 gap: block-reward / subsidy / total_burned
        writes happen AFTER the overlay commit, so 230's undo log
        was missing them. 231 captures pre-write snapshots for the
        4 post-overlay keys (proposer balance, rewards-per-validator,
        total-supply, total-burned) and records a second undo log
        per slot, popped LIFO to restore each layer correctly. A
        state-equality test (process A → reorg to B → assert root
        bit-matches fresh-apply-B) proves end-to-end correctness.
      - **232 (this PR): receive-path integration**. Buffers
        competing blocks at slot ≤ head_slot via new
        `PostEventAction::BufferCompetingBlock`. On QC formation
        (both gossip-vote and own-vote paths), detects mismatch
        between QC's `block_hash` and local `chain.headers[slot]`
        and triggers `BlockProcessor::reorg_to_block` via new
        `PostEventAction::TryReorgToQc`. The TryReorgToQc handler
        also re-runs the post-QC decrypt pipeline so audit-227
        encrypted-tx flow keeps working when reorgs happen.
        Bounded competing-block buffer (cap 64). 222 unit tests +
        multi-node encrypted e2e pass. The standalone multi-node
        partition test that produces a deterministic divergent
        chain is deferred to **233** (HotStuff with 2/3 honest
        makes natural divergence rare; needs Byzantine-injection
        test infra that's its own scope).
      
      Tests in 231: 3 BlockProcessor reorg tests
      (`reorg_to_block_state_matches_fresh_apply` proving root
      equality across the post-overlay undo path,
      `reorg_to_block_rejects_forward_target`,
      `reorg_to_block_refuses_past_ws_checkpoint`).
      All 222 pyde-node unit tests + multi-node encrypted e2e
      pass.

- [ ] 224 — **Block explorer / indexer (plan 083).**
      No code. Plan tracks; listed here for visibility alongside
      other mainnet-operator gaps.

- [ ] 225 — **Faucet web UI (plan 082 partial).**
      `crates/node/src/faucet.rs` is the RPC half only; no
      frontend / public API exposure.

- [x] 228a — `✓` **AOT page-gas parity for direct memory ops.**
      Shipped: new `host_drain_page_gas(ctx) -> u64` host function
      that returns `vm.memory.page_gas_used` and resets to 0. New
      `emit_drain_page_gas!` codegen macro folds the drained
      amount into `VAR_GAS_USED` + runs the same OOG check the
      block prologue uses. Applied after every direct memory op:
      `Load`, `Store`, `Wload`, `Wstore`, `Push`, `Pop`,
      `Poseidon`, `Memcpy`. Memcpy converted from 215's
      pack-into-return-value to the uniform drain-macro pattern.
      While writing parity tests, caught an additional divergence:
      Poseidon charges `(len/32)*250` dynamic gas in the
      interpreter but AOT was charging zero. Fixed by emitting
      the dynamic charge in codegen before the host_poseidon
      call, same pattern as memcpy's per-byte charge. Tests:
      6 new gas-parity tests
      (`load_aot_charges_page_gas_parity_with_interp`,
      `store_aot_charges_page_gas_parity_with_interp`,
      `wload_aot_charges_page_gas_parity_with_interp`,
      `wstore_aot_charges_page_gas_parity_with_interp`,
      `push_pop_aot_charges_page_gas_parity_with_interp`,
      `poseidon_aot_charges_page_gas_parity_with_interp`) plus
      the existing memcpy parity test, all asserting exact
      AOT/interp gas equality. Multi-node encrypted e2e still
      passes.

- [x] 228c — `✓` **AOT gas-parity harness + storage/log fixes.**
      Shipped: new `assert_gas_parity_with_state` helper for tests
      that need pre-prepared VM state (storage/wide-regs/contracts).
      Used to surface and fix:
      
      1. **Storage cold-access surcharge (1800 gas / EIP-2929).**
         Interp Sload/Sstore/Sdelete charge 1800 on first touch
         of a key per-tx; AOT host functions skipped this entirely.
         Every storage access: AOT 200 vs interp 2000. Fixed: each
         storage host fn now adds 1800 to `vm.memory.page_gas_used`
         on first touch + inserts key into `vm.warm_storage_keys`.
         Codegen drains via `emit_drain_page_gas!` after the call.
      
      2. **Log dynamic gas (`100 + data_len*8 + num_topics*50`).**
         Interp `Opcode::Log` charges this; AOT host_log skipped
         it. Every log emission diverged. Fixed: `host_log` adds
         the dynamic charge to `page_gas_used`; codegen drains.
      
      3. **Sdelete refund parity.** Already worked via existing
         `vm.gas_refund += 1500` in host_sdelete. Now verified
         by an explicit parity test that compares both
         `gas_used_total` AND `gas_refund` between paths.
      
      `vm.memory.page_gas_used` now serves as the
      AOT-drainable dynamic-gas accumulator for any host
      function that needs to charge gas the AOT can't see.
      Field doc updated to reflect this. Drain helper name kept
      (`host_drain_page_gas`) for branch hygiene; rename to
      something more general (e.g. `host_drain_dynamic_gas`)
      can land separately.
      
      Tests: 5 new parity tests
      (`sload_cold_aot_gas_parity_with_interp`,
      `sload_warm_aot_gas_parity_with_interp`,
      `sstore_cold_aot_gas_parity_with_interp`,
      `sdelete_aot_gas_parity_with_interp`,
      `log_aot_gas_parity_with_interp`).
      All 38 AOT tests + multi-node encrypted e2e pass.
      
      **Gaps surfaced but NOT fixed in this PR (tracked as
      228d):**
      - SstoreB / SloadB (mode 1 / memory mode) dynamic gas
        per byte stored/loaded. Interp charges `(len/8)*3`;
        AOT codegen falls through to wide-mode for SloadB
        (loses semantics) and traps for SstoreB. Needs full
        mode-1 implementation in AOT host + parity tests.
      - OOG behavior parity (interp can OOG mid-op; AOT
        OOGs at drain time). End state is identical because
        of journal rollback, but the precise OOG point may
        differ. Worth a stress test.

- [x] 228d — `✓` **AOT SloadB/SstoreB (mode 1, bulk-bytes
      storage).** Shipped: new `host_sloadb` and `host_sstoreb`
      that mirror interp's `Opcode::Sload`/`Sstore` mode-1
      handlers (`pvm/src/vm.rs:898-914` / `:965-983`). Both
      charge:
      - EIP-2929 cold-access surcharge (1800) on first touch,
      - Dynamic gas `(len/8)*3` based on bytes stored/loaded,
      - Plus the natural memory page-gas from `checked_read_slice` /
        `checked_write_slice`,
      
      all into `vm.memory.page_gas_used`; codegen drains via
      `emit_drain_page_gas!` after the call. Codegen now wires
      mode 1 through these new host fns instead of falling
      through to wide mode (Sload mode 1) or trapping (Sstore
      mode 1). 2 new parity tests
      (`sloadb_aot_gas_parity_with_interp`,
      `sstoreb_aot_gas_parity_with_interp`) assert exact
      gas equality. All 40 AOT tests + multi-node encrypted e2e
      pass.
      
      OOG-timing parity stress test deferred — end state is
      identical via journal rollback, exact trap-point divergence
      is a polish item.

- [x] 228b — `✓` **AOT delegated-op gas sync.** Shipped:
      `host_exec_opcode` ABI extended to take `gas_used_in` +
      `gas_limit_in` and return `(gas_used_out << 2) | result`
      so the AOT's `VAR_GAS_USED` can be synced in and out
      across every delegated call. Codegen now:
      (1) passes `VAR_GAS_USED` + `VAR_GAS_LIMIT` into the call;
      (2) unpacks the returned gas_used_out back into
      `VAR_GAS_USED`;
      (3) OOG-checks the updated counter against the limit
      after the sync (belt-and-suspenders; step() also traps
      OOG internally).
      
      Also fixed: AOT `analysis.rs` was including delegated
      opcodes (CallExt / Delegate / Create / VerifySig /
      MerkleVerify) in `bb.gas_cost`, and `step()` inside
      host_exec_opcode also charges each opcode's static gas
      from the table. Result: every CallExt was charging 2×
      its static gas in AOT (5000 vs 2500, caught by the
      parity test). Fix: basic-block gas-cost sum now skips
      delegated opcodes so the runtime step() is the single
      source of truth for their static gas.
      
      Tests: 1 new gas-parity test (`callext_aot_gas_parity_
      with_interp`) asserts exact AOT/interp gas equality for
      a CallExt-heavy program. Existing functional tests
      (`aot_callext_delegates_to_interpreter`,
      `aot_factory_cross_contract_full`,
      `aot_complex_contract_events_u256`,
      `aot_real_counter_contract`) all still pass. Multi-node
      encrypted e2e still passes.

- [x] 226 — `✓` **Plaintext RPC path: `AuthKeys::None` sig-skip
      analog.** Surfaced while closing 206. Shipped at two layers:
      
      1. **RPC ingress gate** (`crates/node/src/rpc.rs`
         `ingress_validate`) — new `plaintext_tx_ingest_policy`
         helper rejects txs with `sender.auth_keys == None` on any
         chain_id != 31337. Returns clear `-32001` error with
         "audit 226" tag. Devnet keeps the relaxed faucet/bootstrap
         UX. Mirrors the 206 policy (`encrypted_tx_ingest_policy`).
      
      2. **Validation defense-in-depth**
         (`crates/tx/src/validation.rs` `validate_transaction`) —
         same gate added BEFORE the existing
         `dev_skip_signature` / `sig_pre_verified` branch so any
         caller (RPC ingress, block-execution pipeline,
         `sig_pre_verified` fast path) sees the same enforcement.
         Closes a malicious-block-builder bypass: a validator
         could otherwise include a `from = victim_fresh_address`
         tx with `fee_payer = Paymaster(...)` in their proposed
         block, slipping past both the signature short-circuit
         AND the balance gate.
      
      Tests: 3 unit tests on `plaintext_tx_ingest_policy` covering
      Single / MultiSig / None across devnet and mainnet
      chain_ids; 2 integration tests on `validate_transaction`
      asserting AuthKeys::None rejects on production and accepts
      on devnet. Multi-node encrypted e2e still passes.

- [x] 229 — `✓` **`RegisterPubkey` tx type — bootstrap path for
      pubkey registration.** Surfaced while shipping 226. Without
      this, a fresh address that received funds had no way to
      ever submit a tx because `validate_transaction` rejected
      AuthKeys::None senders on production (the 226 fix), and
      no protocol path could upgrade the account from
      AuthKeys::None to AuthKeys::Single(pk).
      
      Shipped: new `TransactionType::RegisterPubkey = 13`. The
      pubkey holder submits an unsigned tx with their FALCON
      pubkey in `tx.data`; protocol verifies
      `tx.from == Poseidon2(tx.data)` and registers
      `auth_keys = Single(tx.data)`. Rules:
      
      - **No signature** — the address-derivation check is the
        proof of pubkey ownership; only the keypair holder can
        produce a pubkey that hashes to a given address.
      - **No gas, no value** — fresh accounts have no balance
        to spend; charging gas creates a chicken-and-egg.
      - **Anyone can submit** — registering YOUR pubkey on YOUR
        address is harmless (only the legit pubkey passes the
        hash check; same-pubkey re-registration is a no-op;
        different-pubkey rejected).
      - **One-time only** — refuse if `auth_keys != None`. Key
        rotation goes through the existing `pyde_account::auth::
        rotate` flow which requires a current-key signature.
      - **Balance > 0 required** — without this gate, an attacker
        could spam-register from millions of locally-generated
        keypairs and bloat state cheaply. Funding a recipient
        first costs PYDE per address, naturally rate-limiting.
      
      Validation routed through `validate_register_pubkey` BEFORE
      the audit-226 AuthKeys::None gate fires (otherwise the tx
      type couldn't exist). Pipeline dispatch executes by setting
      `sender.auth_keys = AuthKeys::Single(tx.data)` and returns
      a zero-cost successful receipt.
      
      Tests: 7 unit tests covering happy path + every reject
      branch (with-signature, with-value, with-gas, wrong-pubkey,
      wrong-size, zero-balance, already-registered). All 229
      pyde-tx tests + multi-node encrypted e2e pass.

- [~] 234 — `✓` **View-change broken (empty signature + hardcoded
      threshold) + 4-of-4 rolling-restart gossipsub mesh stall.**
      Surfaced by `validator_churn` test then traced via
      diagnostic instrumentation.
      
      Root causes uncovered (3 separate bugs):
      
      1. **Empty view-change signature (FIXED).** `node.rs:2196`
         called `engine.on_timeout(identity)` to construct a
         properly-signed `ViewChangeMessage`, then THREW IT AWAY
         (`_vc_msg`) and constructed a fresh `ConsensusMessage::
         Timeout` with `signature: vec![]` for gossip. Receivers
         verified the empty signature, rejected it, and
         `try_form_view_change_qc` never reached quorum. Effect:
         view-change has been entirely non-functional in
         production code since the path was wired. Fix: forward
         the signed `vc_msg` fields directly into the published
         `Timeout`.
      
      2. **Hardcoded view-change threshold (FIXED).**
         `view_change.rs:194` used `QUORUM_THRESHOLD as u32` (= 86,
         the production constant) for the threshold check
         regardless of actual `committee_keys.len()`. Devnet
         committees of 4 validators would need 86 view-change
         votes to form a QC — impossible. Fix: switch to
         `quorum_for_committee(committee_keys.len())`, mirroring
         `try_form_qc` in hotstuff.rs.
      
      3. **Gossipsub mesh degradation (still open).** Even with
         #1 + #2 fixed, the 4-of-4 stall persists because
         `gossipsub.publish` for the consensus topic returns
         `InsufficientPeers` after the live nodes have been
         through restart cycles. Only the never-restarted node
         was holding the consensus-topic mesh together; removing
         it leaves restarted peers unable to publish to each
         other (their gossipsub state shows 0 peers in the
         consensus mesh / 0 known subscribers). The 3-of-4
         `validator_churn` test still passes because the chain
         can advance via slots whose proposer is alive, with
         view-change as the recovery path for missed-proposer
         slots — but in 4-of-4, view-change publish itself fails.
      
      Open follow-ups for #3:
      - Add periodic re-subscribe to `consensus` topic from the
        validator side so restarted peers re-broadcast SUBSCRIBE
        control messages to refresh peer subscriber state.
      - Add a request-response fallback for view-change messages
        when gossipsub publish returns `InsufficientPeers`
        (direct point-to-point to known committee peers).
      - Consider lowering `mesh_n_low` for small-committee
        devnets — `mesh_n_low=4` is unsatisfiable with N=4
        validators (max possible mesh peers = N-1 = 3).

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
| 214 | 2026-04-23  | Read decrypt-share branch + verified `PeerInfo::invalid_messages` reuse from 014d | Fixed with spam-threshold drop + decode-Err bump |
| 215 | 2026-04-24  | Traced interp `Memcpy` + `host_memcpy` + AOT codegen + `page_gas_used` drain; added gas-parity test that exposed 2 divergences (per-byte + per-page) | Fixed all three in one PR; surfaced 228 as follow-up |
| 228a| 2026-04-24  | Enumerated AOT memory-touching host calls; gas-parity tests for each. Poseidon dynamic-gas divergence surfaced by the test harness | Fixed all 7 direct mem ops + poseidon dynamic gas; split 228b |
| 228b| 2026-04-24  | Gas-parity test on CallExt exposed 2× double-charging (static gas in both bb prologue + delegated step); ABI change routes updated gas back into VAR_GAS_USED | Fixed sync + analysis.rs double-count |
| 228c| 2026-04-24  | Wrote `assert_gas_parity_with_state` helper; targeted tests for Sload/Sstore/Sdelete cold + Log dynamic gas all failed before fix | Fixed via `page_gas_used` accumulator pattern; 5 new parity tests pass |
| 228d| 2026-04-24  | Added `host_sloadb` + `host_sstoreb`; rerouted Sload/Sstore mode 1 in codegen; parity tests against interp's mode-1 handler | Fixed semantic + gas divergence on bulk-bytes storage |
| 217 | 2026-04-24  | Searched every caller of `verify_witnesses`; only tests/benches. No production path verifies witnesses today | Not a bug; re-open if stateless validation wires into production |
| 218 | 2026-04-24  | Wrapped BroadcastConsensus / BroadcastConsensusMany / maybe_rebroadcast_reshare in `is_validator` gates | Belt-and-suspenders egress guard added |
| 226 | 2026-04-25  | New `plaintext_tx_ingest_policy` mirrors 206 + same gate added in `validate_transaction` for defense-in-depth at block-validation | Closed at both RPC ingress and validation layers |
| 229 | 2026-04-25  | New `TransactionType::RegisterPubkey`; address-derivation check (`from == Poseidon2(data)`) is the proof; gated by funded + unregistered + one-time | Bootstrap path for pubkey registration shipped |
