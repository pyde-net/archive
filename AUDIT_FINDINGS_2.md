# Pyde Audit Findings — Cycle 2 (2026-04-30)

> Pre-testnet-launch deep audit, run after the 2026-04-23 cycle in
> `AUDIT_FINDINGS.md`. Five parallel agents (crypto, consensus, tx,
> state, net + pvm/aot, node, mempool/otic/sdks) crawled all 105k LoC
> across 15 workspace crates; the items below are NEW findings the
> prior cycle did not surface.
>
> Numbering starts at 301 to avoid collision with the prior cycle
> (201–241). Severity: **P0** = blocks testnet launch, **P1** = must fix
> before public/external-audit, **P2** = hygiene.
>
> Legend (matches `AUDIT_FINDINGS.md`):
>
> - `[ ]` not started | `[x]` complete | `[~]` in progress | `[!]` blocked
> - `✓` self-verified against source | `⚠` agent-claimed, not yet
>   independently verified

---

## At a glance

- **12 P0** (launch blockers), **~30 P1** (pre-public/pre-audit),
  **~30 P2** (hygiene). One PR per item.
- The P0 cluster is concentrated in: wire decoders that panic under
  `panic = "abort"` (1 item), consensus QC verification (1), PVM
  cross-contract semantics (2), AOT/interpreter parity (1 item
  bundling 7 sub-divergences), threshold MEV soundness (1 item with
  3 sub-issues), tx pipeline writeback (1), fee/auth gates (3), and
  cross-chain replay surfaces (3).
- Recommended order at the bottom — smallest blast-radius first.

---

## P0 — Testnet launch blockers

### Trivial single-file fixes (do first)

- [x] 301 — `✓` **`EncryptedTx::from_bytes` aborts node on hostile
      input.**
      Shipped: replaced raw slice indexing with a `Cursor` helper
      mirroring `pyde_node::wire::Decoder` (audit-204 pattern). New
      caps: `MAX_ACCESS_ENTRIES = 1024`,
      `MAX_KEYS_PER_ACCESS_ENTRY = 1024`, `MAX_SIG_LEN = 1024`
      (FALCON-512 ≤ 1000 in practice), `MAX_CT_LEN = MAX_TX_SIZE`,
      plus an upfront `data.len() > MAX_TX_SIZE` rejection. 9 new
      panic-free regression tests covering empty / truncated header
      / oversize envelope / huge counts on access list, sig, ct,
      per-entry keys / truncated signature / 256-length zero/0xFF
      sweep + happy-path roundtrip. New `cargo-fuzz` target
      `encrypted_tx_decoder` wired into `fuzz/Cargo.toml`. 75
      pyde-mempool tests pass; clippy clean; pyde-node downstream
      builds clean.

- [x] 302 — `✓` **RPC `send_encrypted_transaction` defaults
      `chain_id = 1` (mainnet) when caller omits it.**
      Shipped: extracted `resolve_request_chain_id(supplied,
      node_chain_id) -> Result<u64, String>` helper near the other
      pure RPC helpers (`clamp_call_gas`, `encrypted_tx_ingest_policy`).
      Three branches: missing → node's chain_id; matching → accepted;
      mismatching → -32602 with a clear `"chainId mismatch: tx
      claims X but node is on Y"` error. `send_encrypted_transaction`
      now routes through it. 3 new unit tests covering each branch
      across [1, 7, 7331, 31337, 1_000_000]. 20 pyde-node rpc tests
      pass.

- [x] 303 — `✓` **Faucet `chain_id` defaults to 31337 on RPC failure.**
      Shipped: removed the silent `"0x7a69"` default in
      `fetch_chain_id`; missing/null result now propagates as `Err`.
      Removed the per-request `unwrap_or(31337)` in `send_faucet_tx`
      — chain_id is now pinned at boot via a new
      `resolve_faucet_chain_id` helper that polls the node once,
      caches the value, and (when `--chain-id` is supplied) refuses
      to start on mismatch. New `--chain-id` CLI flag on
      `pyde faucet` + `chain_id: Option<u64>` field on `FaucetConfig`.
      Pure decision logic split into `check_pinned_chain_id` for unit
      testing. 3 new unit tests covering unpinned / matching pin /
      mismatch (mainnet↔testnet, devnet↔testnet). 12 faucet tests
      pass; bonus: each dispense saves a `pyde_chainId` RPC
      round-trip.

- [x] 304 — `✓` **`AuthKeys::MultiSig` validation silently passes any
      tx.**
      Shipped: `validate_transaction` now rejects MultiSig senders
      on every `chain_id != 31337` (mirrors the audit-226 None gate
      shape — same `InvalidSignature` error variant). RPC ingress
      `plaintext_tx_ingest_policy` tightened to match: Single
      always-OK, MultiSig devnet-only with a clear "MultiSig
      auth_keys not yet enforced" error on production. 1 new
      validation test (`validate_transaction_rejects_multisig_on_
      production` over [1, 7, 7331, 1_000_000]) + 1 new ingress
      test (`plaintext_ingest_policy_multisig_devnet_only`)
      replacing the old "MultiSig allowed everywhere" assertion.

- [x] 305 — `✓` **`FeePayer::Paymaster` mints fees, charges nothing;
      `FeePayer::GasTank` inner address ignored.**
      Shipped: `validate_transaction` now rejects both
      `FeePayer::Paymaster(_)` and `FeePayer::GasTank(_)` on every
      `chain_id != 31337` with `ValidationError::InvalidPaymaster`.
      New `fee_payer_ingest_policy` helper at the RPC layer mirrors
      the same gate at ingress (called from `ingress_validate`
      before `validate_transaction`). Devnet keeps both for dev /
      test ergonomics. 3 new RPC tests
      (`fee_payer_ingest_policy_sender_always_ok`,
      `..._paymaster_devnet_only`, `..._gas_tank_devnet_only`) +
      3 new validation tests covering the production reject
      branches and the devnet-allow branch + 1 pre-existing test
      (`paymaster_skips_balance_check`) flipped to chain_id=31337
      to keep its semantics. 235 pyde-tx + 24 pyde-node rpc tests
      pass.

### Crypto / cross-chain replay surfaces

- [x] 306 — `✓` **Wallet keystore KDF is single-iteration Poseidon2.**
      Shipped: replaced `derive_aes_key` with Argon2id (`m=64 MiB,
      t=3, p=1`, ~250 ms per guess on a single core, memory-hard) in
      all three keystore implementations: `node/src/keystore.rs`,
      `pyde-rust-sdk/src/wallet.rs`, `pyde-dev/src/wallet.rs`. Bumped
      `KEYSTORE_VERSION` from 1 to 2 in each. Backward compat
      preserved: v1 keystores still decrypt via a retained
      `derive_aes_key_v1_poseidon2` legacy KDF dispatch — operators
      with pre-306 files keep working without manual migration.
      `version = 99` (or any other unknown) cleanly rejected with
      "unsupported keystore version" in all three. New `argon2 =
      "0.5"` dep on each of the three crates. Tests: 9 new cases
      across the three crates (always-v2 emit, v1 still decrypts,
      v1 wrong-pass still fails, v99 rejected, v1→v2 re-encrypt
      roundtrip in node/keystore). 8 + 17 + 7 = 32 keystore-related
      tests pass.

### Pipeline / fee / state-corruption

- [x] 307 — `✓` **Tx pipeline writeback clobbers per-type handler
      effects.**
      Shipped: snapshot `sender_initial` / `recipient_initial` at
      the top of `execute_transaction`, then replace the late
      `store_account(smt, &sender)` / `store_account(smt,
      &recipient)` with a new `apply_account_delta` helper that
      re-loads the latest SMT state, applies (final - initial)
      deltas for `balance` / `gas_tank` / `auth_keys`, and stores.
      The re-load picks up handler / validator / treasury writes
      that landed at lines 609 / 616 / inside per-type handlers,
      so the pipeline's debit + transfer + refund deltas land on
      top of those credits instead of overwriting them.
      Self-transfer handled correctly: sender apply runs first,
      recipient apply re-reads sender's just-stored state and
      adds `+tx.value` on top → end balance pre-tx − gas_paid.
      4 new regression tests
      (`self_transfer_pays_gas_after_307`,
      `proposer_self_tx_earns_validator_credit_after_307`,
      `recipient_is_validator_keeps_credit_after_307`,
      `sender_is_treasury_keeps_credit_after_307`) confirm each
      of the four clobber paths the audit identified is now
      closed. All 91 pyde-tx pipeline tests pass.

### PVM / consensus-fork

- [x] 308 — `✓` **PVM `Selfdestruct` clears the entire shared
      `storage` HashMap.**
      Shipped: `Opcode::Selfdestruct` now traps with
      `Trap::InvalidOpcode` unconditionally. The interpreter no
      longer touches `self.storage`. AOT codegen at
      `crates/aot/src/codegen.rs:1219` flipped from `jump
      success_block` to `jump trap_block` — interpreter and AOT
      agree on the trap semantics, removing the silent
      consensus-fork pre-308 had where interp cleared all storage
      and AOT continued. Static-mode SELFDESTRUCT still trips
      `Trap::StaticModeViolation` first (precedence preserved).
      2 new vm tests (`selfdestruct_traps_invalid_opcode`,
      `selfdestruct_traps_in_static_mode_too`). 333 PVM + 43 AOT
      tests pass.

- [x] 309 — `✓` **Cross-contract storage writes survive parent
      revert (atomicity broken).**
      Shipped: every cross-contract storage merge in `do_ext_call`
      and `do_create` now calls `journal_storage_write(&k)` BEFORE
      the `self.storage.insert(*k, v.clone())` so a later parent
      revert restores parent's pre-call value. Three sites
      patched:
      - non-delegate success merge (`vm.rs:1697-1699`): journal
        each child-written key on the way in.
      - delegate-success merge (`vm.rs:1694-1700`): re-journal
        each key from `child.storage_journal_keys` before
        adopting `child.storage` (the child-vm journal is
        otherwise dropped at scope exit).
      - CREATE constructor merge (`vm.rs:1871-1873`): same
        pattern.
      `journal_storage_write` is idempotent on already-journaled
      keys, so re-journaling parent's own pre-call writes that
      child inherited (line 1678 clone) is safe. 2 new vm tests
      (`cross_contract_merge_journals_writes_for_revert` confirms
      revert restores both overlapping AND new keys;
      `pre309_behavior_no_longer_applies` documents the bug shape
      that motivated the fix).

- [x] 310 — `✓` **Multiple AOT/interpreter consensus divergences.**
      Shipped in one bundle:
      - **Wide-ALU rs2 mask** (`codegen.rs:756, 774`): flipped
        `& 0xF` → `& 0xFF` to match the interpreter's `as u8`
        (`cpu.rs:238…314`). Closes the adversarial-bytecode fork
        where rs2 = 0x15 addressed wide-reg 5 in AOT vs trapping
        in the interpreter.
      - **Store fault capture** (`codegen.rs Opcode::Store`):
        AOT now captures host_store's fault return and branches
        to `trap_block` on `!= 0`. Pre-fix discarded the return,
        silently succeeding on OOB stores.
      - **Widen fault capture** (`codegen.rs Opcode::Widen`):
        same pattern — capture and trap on `wd >= 8`.
      - **Caller env subcodes 3-4** (`codegen.rs Opcode::Caller`):
        new `host_tx_nonce` + `host_tx_gas_limit` host fns;
        codegen handles subcodes 0..=4 to match
        `vm.rs::env_gp::*`.
      - **Callvalue env subcodes 5-6 + fault capture**
        (`codegen.rs Opcode::Callvalue`): new `host_tx_hash` +
        `host_block_proposer` host fns; codegen handles 0..=6 to
        match `vm.rs::env_wide::*`. Also captures every wide-write
        host fn's fault return → trap on `wd >= 8` (silent
        success pre-fix).
      - **Blockhash** (`codegen.rs Opcode::Blockhash`): new
        `host_blockhash` host fn that mirrors the interpreter's
        recent-256-block window. Pre-fix AOT always wrote zero,
        forking any contract that used BLOCKHASH for randomness
        or audit.
      - **Selfdestruct** (already shipped under audit 308):
        AOT now traps too.

      6 new parity tests
      (`store_oob_traps_on_aot_audit_310`,
      `caller_env_tx_nonce_parity_audit_310`,
      `caller_env_tx_gas_limit_parity_audit_310`,
      `callvalue_env_tx_hash_parity_audit_310`,
      `callvalue_env_block_proposer_parity_audit_310`,
      `blockhash_parity_audit_310`) plus the existing 38 AOT
      tests cover the regression cluster. 49 AOT + 333 PVM tests
      pass.

      **Deferred** (lower priority, documented):
      - Load + Pop u64::MAX sentinel collision (a legitimate load
        of all-1-bits is indistinguishable from the host fault
        sentinel). Requires either an ABI change to multi-value
        return or an out-pointer for the value. Tracked as a
        post-launch follow-up.

### Consensus

- [x] 311 — `✓` **No QC signature verification on incoming blocks.**
      Shipped: new `pyde_consensus::hotstuff::verify_qc(qc,
      committee_keys, chain_id) -> bool` walks the bitmap (low-to-
      high), pairs each set bit with `qc.signatures[i]`, rebuilds
      `proposer_sign_message(chain_id, qc.slot, qc.block_hash)`,
      and runs `falcon_verify` per voter. Returns false on any of:
      bitmap pop-count below quorum, signatures.len() ≠ pop-count,
      voter_index out of committee, FALCON verify fail. Empty QCs
      (bitmap == 0 AND signatures empty) short-circuit to true as
      the genesis sentinel.
      Wired in two production call sites:
      - `validate_network_block` (block_processor.rs) — runs after
        the bitmap pop-count check.
      - `create_vote` (hotstuff.rs) — runs BEFORE mutating
        `state.highest_qc`. New `committee_keys: &[Vec<u8>]`
        parameter; threaded through every test/bench caller (15
        sites updated).
      Bonus determinism fix: `try_form_qc` now sorts signatures by
      voter_index ascending, so two honest validators forming the
      same QC produce identical `signatures` Vec orderings and
      `verify_qc` can pair signatures with bitmap bits without
      arrival-order ambiguity (closes the audit-310 P1 #18 note).
      6 new tests
      (`verify_qc_accepts_empty_sentinel`,
      `verify_qc_accepts_well_formed_qc`,
      `verify_qc_rejects_fabricated_bitmap_with_empty_sigs`,
      `verify_qc_rejects_garbage_signatures`,
      `verify_qc_rejects_cross_chain_replay`,
      `create_vote_rejects_fabricated_qc_previous`). 124 consensus
      tests pass; workspace builds clean.

- [~] 312 — `✓` **Threshold MEV pipeline soundness gaps.**
      Partially shipped for testnet; full fix tracked for mainnet.
      The three sub-issues are exploitable only by an actively-
      Byzantine committee member, and the testnet committee is
      operator-known + trust-honest by construction. The split:
      - **Documentation** (shipped): new "Known testnet trust
        assumptions" section in `docs/testnet-bringup.md` makes
        all three gaps explicit — centralized genesis keygen,
        deterministic PSS-refresh entropy, unauthenticated
        decryption shares. Operators are instructed to run the
        coordinator host air-gapped and shred it post-ceremony.
      - **Structural hardening** (shipped):
        `combine_shares` now rejects shares with `index == 0` or
        `index > 256` before any Lagrange interpolation, closing
        the obvious griefing path where a peer feeds nonsense
        indices that pass dedup but inflate combine work.
        Doc-comment block on `combine_shares` explicitly calls
        out the trust boundary that the MAC check still enforces
        safety while availability depends on operator trust. 2
        new tests
        (`combine_shares_rejects_zero_index_audit_312`,
        `combine_shares_rejects_oversize_index_audit_312`); 90
        crypto tests pass.
      - **Deferred to mainnet (NOT shipped, tracked here):**
        - Per-validator `OsRng` seed parameter on `pss_refresh`,
          plus FALCON sig per `RefreshContribution` and
          receiver-side verify before `apply_refresh`.
        - FALCON sig over `(ct_hash || index ||
          blinded_shares_hash)` on every `DecryptionShare`;
          verify before admission into the combine set in
          `combine_shares`.
        - Distributed Key Generation to replace
          `threshold_keygen`'s single-coordinator ceremony.

      The mainnet fixes require a hard wire-format break on
      `RefreshContribution` and `DecryptionShare` (new signature
      field) and an API change to `pss_refresh`/`generate_
      decryption_share`/`combine_shares`. Tracked as a single
      mainnet-blocking item in MAINNET_PLAN.md.

---

## P1 — Pre-public-launch (or pre-external-audit)

> One-liners. Each is real and worth a PR; the team can prioritize
> within this list. File:line included for jump-to-source.

### Pre-existing regressions surfaced during e2e validation

- [ ] 319 — `✓` **Encrypted-tx burst at audit-027 cap fails with
      cross-node state divergence.**
      Surfaced by running `cargo test -p pyde-node --test
      loadgen_encrypted_burst -- --ignored` end-to-end after
      shipping the cycle-2 P0 train. **Predates this audit cycle**
      — the test fails at both `aee961d` (pre-fix baseline) and
      HEAD with two distinct shapes:
      - **Baseline (138 s):** chain advances, node-0 reaches
        `inclusion=100%`, but node-3 has applied **zero** of the
        40 transfers — full state divergence between nodes that
        all voted on the same finalized chain.
      - **HEAD (192 s):** node-0 never reaches inclusion; the
        same 40 encrypted txs reproposed at slot 466 / 467 / 468
        (proposer log: `encrypted=40 pending=0`) — txs included
        in proposed blocks but never decrypt + apply, so the
        mempool never drains.

      **Root cause sketch.** Voting on a block requires the
      compact block (header + tx hashes); decrypting + applying
      encrypted txs requires the `EncryptedTxBundle` published as
      a separate gossipsub message on the Blocks topic
      (audit-227). Under sustained 40-tx/s load, the bundle is
      occasionally not delivered to ≥1 validator. That validator
      still votes on the compact block (advancing finality), but
      never applies the encrypted contents — its state silently
      lags. The `GET_BLOCK_TXS` retry path
      (`crates/node/src/sync.rs`) only triggers on missing-tx
      detection at compact-block reconstruct; a node whose local
      mempool already has the txs (RPC fan-out) reconstructs
      successfully and never re-requests the bundle, even though
      its threshold-decrypt path is starved.

      **Where:**
      - `crates/node/src/node.rs:1458-1510` — compact-block
        reconstruct path, opportunistically pulls encrypted_txs
        from queued bundles but never re-requests if the bundle
        is missing.
      - `crates/node/src/node.rs:1640-1661` — bundle buffering
        with slot-bounded TTL (drops after 100 slots).
      - `crates/node/src/sync.rs` `GET_BLOCK_TXS` — retry path
        gated on missing-tx, not on missing-bundle.

      **Reproducer.**
      ```
      cargo test -p pyde-node --test loadgen_encrypted_burst -- \
        --ignored --nocapture
      ```
      Half-load (`PYDE_ENC_BURST_PER_SENDER=5`, 20 txs aggregate)
      passes 100% in ~2 s. Lifecycle (1 tx) passes in ~9 s. Bug
      is specifically a function of sustained rate ≥ ~25-40
      encrypted txs/sec.

      **Pre-launch impact:** real testnet operators submitting
      < 20 enc-tx/s aggregate are unaffected (and our lifecycle
      e2e proves the pipeline works at that load). A loadgen bot
      hitting the audit-027 design ceiling will reproduce the
      regression and produce divergent state. Flag in the testnet
      runbook + lower the documented sustainable cap until fix
      lands.

      **Fix direction:** wire bundle re-request into the
      threshold-decrypt pending-shares path. If a validator has
      pending encrypted_txs in `BlockDecryptor` but no bundle
      received within ~5 slots, send `GET_BLOCK_TXS` directly
      (RR fallback) targeting the proposer or any other validator
      that voted for the block. Lower priority: gossipsub
      reliability tuning (audit P1 #334 re: peer scoring) may
      reduce the underlying message-loss rate enough that the
      retry rarely fires.

      Bisect to root-cause commit between 2026-04-23 (audit log:
      "5/5 stable runs at 100% inclusion") and 2026-04-29
      (`aee961d`) is needed but deferred. ~30 commits in window
      (PRs #300-#310 inclusive).

### Consensus / finality

- [x] 320 — `✓` **Hard-finality `finality_sign_message` doesn't bind
      `chain_id`.** Shipped: `finality_sign_message` now hashes
      `tag(13) || chain_id_le(8) || slot_le(8) || block_hash(32) ||
      state_root(32)`. `create_finality_vote`,
      `verify_finality_vote`, `try_form_hard_finality` all take
      `chain_id`; threaded through `validator.rs:1999, 2419` and the
      finality-vote receive path in node.rs. Tests updated to use
      `TEST_CHAIN_ID = 7` (mirrors hotstuff.rs convention) plus a
      new `finality_vote_cross_chain_replay_rejected` regression
      that asserts a vote signed under chain_id=1 fails to verify
      under chain_id ∈ {2, 7331, 31337}. 17 finality tests pass;
      125 consensus + 286 node-bin tests clean.
- [x] 321 — `✓` **Header `parent_hash` not validated.**
      Shipped: `validate_network_block` now takes
      `expected_parent_hash: Option<&[u8; 32]>` and rejects on
      mismatch with a clear `"parent_hash mismatch ... audit 321"`
      error. Caller in `node.rs:3947-3984` computes the expected
      hash: `chain.genesis_hash` for slot=1, `chain.header(slot-1)
      .hash()` for slot>1, `None` for the bootstrap case where
      local headers aren't populated yet. The check fires BEFORE
      the proposer-in-committee step so a forged block is rejected
      cheaply. 4 new tests cover the four branches: mismatch
      rejected, None skips, matching passes, genesis short-
      circuits. 25 block_processor tests pass.
- [ ] 322 — `⚠` **`RandomnessCollector::finalize` hardcodes 85-share
      threshold.** `crates/consensus/src/epoch_randomness.rs:189-202`.
      A 16-validator testnet (per the bring-up runbook) cannot
      advance epoch randomness past the first epoch boundary
      (1000 blocks). Same fix pattern as audits 234/235/236 —
      thread `committee_size` through and use
      `randomness_threshold_for(n) = n.div_ceil(3) + 1` (f+1 is
      sufficient; 2/3 is overkill for unbiased reconstruction).
- [ ] 323 — `⚠` **No proposer-VRF score threshold check on incoming
      blocks.** `crates/node/src/block_processor.rs:699-717`. The
      VRF *proof* is verified but not the *score* against the
      eligibility threshold; any committee member can propose every
      slot. Replicate the `check_proposer` threshold formula from
      validator.rs.
- [ ] 324 — `⚠` **`view_change_sign_message` doesn't bind
      `highest_qc`.** `crates/consensus/src/view_change.rs:128-134`.
      Middleboxes can swap `highest_qc` mid-flight. Include
      `highest_qc.hash()` in the preimage.
- [ ] 325 — `⚠` **No timestamp validation.**
      `crates/node/src/block_processor.rs:181, 971`. Header
      timestamp can be anything; require
      `parent.timestamp < ts <= now_ms + DRIFT_TOLERANCE`.
- [ ] 326 — `⚠` **`seen_evidence`, `seen_finality_votes` unbounded
      memory.** `crates/node/src/validator.rs:315`. Add prune loop
      mirroring `seen_proposals`/`seen_votes`.
- [ ] 327 — `⚠` **Vote / view-change vec accept unbounded duplicates
      pre-dedup.** `validator.rs:1830-1834, 1941-1942`. Dedup
      on `(slot, voter_index)` BEFORE push to bound FALCON-verify
      cost per slot.
- [ ] 328 — `⚠` **`compute_slash` uses fixed `VALIDATOR_STAKE`
      (10K), not actual current stake.**
      `crates/consensus/src/slashing.rs:163-179, 244-277`. Pass
      `validator.stake` from the live entry to keep
      `total_burned`/`finder_fee` consistent for repeat offenders.
- [ ] 329 — `⚠` **`is_finalized` (2-chained-QC rule) is dead code.**
      `crates/consensus/src/hotstuff.rs:329-364`. Production
      records soft finality on the first QC; the documented chain
      check never runs. Either wire it in or update the doc to
      match.

### State

- [ ] 330 — `⚠` **JMT commit non-atomic across two `db.write` calls.**
      `crates/state/src/jmt_store.rs:474-479`. Crash between writes
      leaves nodes for `next_version` persisted while
      `META_LATEST_VERSION` still points at the old version. Combine
      both writes into a single `rocksdb::WriteBatch`.
- [ ] 331 — `⚠` **No fsync on per-block JMT writes.**
      `crates/state/src/jmt_store.rs:343-344`,
      `crates/state/src/backend.rs:599`. Default `WriteOptions`;
      power loss in the WAL window can lose state. Add
      `WriteOptions::set_sync(true)` (or `flush_wal(true)`) at the
      block-final commit point.
- [ ] 332 — `⚠` **Decrypted-tx execution writes directly to SMT
      bypassing cache + undo log.**
      `crates/node/src/block_processor.rs:984` (try_decrypt_and_execute)
      and `crates/node/src/node.rs:2732-2747` (single-node decrypt).
      Reorg cannot revert decrypted-tx state; cache reads stale.
      Funnel through `update_batch_deferred` and append a third
      undo batch to `record_block_undo`.

### Net

- [ ] 333 — `⚠` **Gossipsub `max_transmit_size = 1MB` ≠ Blocks-channel
      4MB cap.** `crates/net/src/node.rs:120` vs
      `crates/net/src/channels.rs:113-114`. Encrypted-tx-heavy bundles
      near 4 MB silently fail publish, dropping the block from
      non-proposer mempools. Lift `max_transmit_size` to 4MB or
      shrink the per-channel cap to 1MB.
- [ ] 334 — `⚠` **No peer scoring config.**
      `crates/net/src/node.rs:117-129`. `with_peer_score(...)` is
      never called; `ValidationMode::Permissive`. Misbehaving peers
      never get demoted. Install
      `gossipsub::PeerScoreParams::default()` for testnet.
- [ ] 335 — `⚠` **`crates/net/src/ddos.rs` is entirely dead code.**
      RateLimiter/SubnetLimiter/PowChallenge primitives have zero
      callers outside their own tests. Either wire `SubnetLimiter`
      into `ConnectionEstablished` and `RateLimiter` per-peer for
      Transactions, or delete the file so nobody assumes protection
      that isn't there.
- [ ] 336 — `⚠` **`PeerInfo.ip` never populated.**
      `crates/net/src/peer.rs:40,303` + `crates/net/src/node.rs:5052`.
      `is_rate_limited` always returns false because IP is never
      parsed from the multiaddr. Set `info.ip` from
      `endpoint.get_remote_address()` before `add_peer`.
- [ ] 337 — `⚠` **`SyncReq::GetBlocks` count unbounded server-side.**
      `crates/node/src/sync.rs:587-610`. A peer with `count=u32::MAX`
      iterates ~4B slots. Clamp `count <= 256` before the loop.
- [ ] 338 — `⚠` **`SyncReq::StateSnapshotChunk` chunk_size unbounded
      server-side.** `crates/node/src/sync.rs:668-693`. Cap to e.g.
      50_000 entries before slicing.
- [ ] 339 — `⚠` **`channels.rs::validate_message` /
      `discovery.rs::Discovery` ban list dead code.** Either wire
      both into receive paths or delete to match reality.
- [ ] 340 — `⚠` **`identify::Behaviour` protocol-version doesn't
      bind chain_id.** `crates/net/src/node.rs:152-155`. Cross-chain
      peers slot into peer book + Kademlia; rely solely on
      app-layer FALCON auth. Encode chain_id into the protocol
      version and refuse mismatch at `ConnectionEstablished`.

### RPC / node

- [ ] 341 — `⚠` **Full nodes skip header validation on gossip full
      blocks.** `crates/node/src/node.rs:3947-3958`.
      `validate_network_block` only runs when
      `validator_engine.is_some()`; non-validator full nodes accept
      any header. Add a `NonValidatorVerifier` mirror.
- [ ] 342 — `⚠` **`pyde_estimateGas` and `pyde_createAccessList`
      lack the gas cap that audit 735bcef added to `pyde_call`.**
      `crates/node/src/rpc.rs:853-856, 932-935`. Apply
      `clamp_call_gas` at both sites.
- [ ] 343 — `⚠` **`config.toml` `chain_id` not cross-checked against
      `genesis.toml`.** `crates/node/src/node.rs:246`. Assert match
      in `PydeNode::run` after loading `genesis_config`; refuse
      otherwise.
- [ ] 344 — `⚠` **`pyde testnet` writes keys with default umask.**
      `crates/node/src/genesis.rs:1018,1024,1028,1032,1036,1144,1145,
      1148,1286,1287`. Add `fs::set_permissions(0o600)` after every
      key-file write. Have `load_validator_identity` tighten or
      `warn!` on existing-file load if mode > 0o600.
- [ ] 345 — `⚠` **Missing `set_max_request_body_size` / batch caps
      on jsonrpsee Server.** `crates/node/src/rpc.rs:1544-1546`.
      Default ~10MB request lets a single connection saturate.
      Configure explicit `max_request_body_size(1_048_576)` +
      `max_response_body_size(16_777_216)`.
- [ ] 346 — `⚠` **WS subscribe count uncapped per connection;
      unbounded mpsc backs each.** `crates/node/src/ws_sub.rs:59,
      70-176`. Cap `tasks.len()` at 16 per connection; switch
      `mpsc::unbounded_channel` → bounded with try_send drop.
- [ ] 347 — `⚠` **Faucet rate-limiter map grows unbounded.**
      `crates/node/src/faucet.rs:50-86, 379-382, 541-545`. Validate
      address against `^0x[0-9a-fA-F]{64}$` BEFORE recording in the
      cooldown map; LRU-cap the map; reject non-UTF-8 bodies.
- [ ] 348 — `⚠` **Faucet behind reverse proxy: `peer_addr.ip()`
      collapses to one IP.** `crates/node/src/faucet.rs:530`. Add a
      `--trust-x-forwarded-for` CLI flag; parse rightmost untrusted
      hop only when set. Document the must-strip-XFF-at-edge risk.
- [ ] 349 — `⚠` **`pyde_call` block context is zeroed.**
      `crates/node/src/rpc.rs:776-789`. Populate `block_number`,
      `timestamp`, `block_proposer`, `block_hashes` from chain head.
      Same for `estimateGas` / `createAccessList`.

### Tx

- [ ] 350 — `⚠` **`tx.hash()` includes only `fee_payer.tag()`, not
      full bytes.** `crates/tx/src/types.rs:227`. Two physically
      distinct serialized txs hash identically; signature authorizes
      the swap. Replace `buf.push(tag())` with
      `buf.extend_from_slice(&fee_payer.to_bytes())`.
- [ ] 351 — `⚠` **`StakeWithdraw` never returns stake.**
      `crates/tx/src/pipeline.rs:467-508`. There is no
      `CompleteUnbonding` tx type. Operators who experiment lose
      10K PYDE silently. Either implement the unbonding-complete
      path OR refuse `StakeWithdraw` at validation until shipped
      (preferred for testnet).
- [ ] 352 — `⚠` **`tx.value` runs unconditionally for non-Standard
      tx types.** `crates/tx/src/pipeline.rs:249`. Slash, MultisigTx,
      ClaimReward, etc. with `tx.value > 0` perform side-channel
      transfers. Reject `tx.value != 0` for every variant that has
      no value semantics; allow only Standard + Deploy.
- [ ] 353 — `⚠` **Failed-execution txs leak validator CPU without
      consuming nonce.** `crates/tx/src/pipeline.rs:227-230 vs 625`.
      `nonce_state.use_nonce` runs in-memory but `store_nonce` only
      runs on full success. A failing tx (e.g. a fixed Paymaster
      path failure) can be resubmitted indefinitely. Persist nonce
      + charge gas on failure.

### Otic

- [ ] 354 — `⚠` **Signed arithmetic broken end-to-end.**
      `crates/otic/src/codegen.rs:1109-1110, 1089-1090,
      1179-1190, 1115`. `Div`/`Mod`/`<`/`>`/`<=`/`>=`/`Shr` always
      emit unsigned PVM ops. Optimizer at
      `crates/otic/src/optimize.rs:137-186` uses U256 (unsigned)
      for fold_binop/fold_cmp. Any contract using `i*` types is
      wrong. Either gate signed types at typecheck (preferred for
      testnet) OR add `Sdiv`/`Smod`/`Slt`/`Sgt`/`Sar` ISA opcodes
      and cascade through codegen + optimizer + AOT.
- [ ] 355 — `⚠` **`find_field_offset_any` iterates `HashMap.values()`
      → non-deterministic bytecode.** `crates/otic/src/codegen.rs:632-640`.
      Switch to `BTreeMap`-backed lookup or sort by struct name.
- [ ] 356 — `⚠` **FNV-1a-32 selectors with no compile-time dedup
      check.** `crates/otic/src/codegen.rs:3622-3629, 396-399`.
      Easy collision on adversarial function names; first match
      wins silently. Error on duplicate at `extract_all_contract_
      signatures`. Long-term: switch to Poseidon2-derived
      selector to align with `pyde_state::keys`.

### Crypto

- [ ] 357 — `⚠` **No KAT pinning for ml-kem 0.3.0-rc.x or falcon-rs
      0.2.4.** `crates/crypto/Cargo.toml:13` and
      `crates/crypto/src/falcon.rs:6`. Silent dep bump = silent
      wire-format change. Pin a FIPS-203 KEM KAT and a FN-DSA
      signature KAT in tests, mirroring audit-216's Poseidon2
      round-constants pin.
- [ ] 358 — `⚠` **No `Zeroize`/`ZeroizeOnDrop` on any secret type.**
      `crates/crypto/src/falcon.rs:13-14, kyber.rs:18-19,
      threshold.rs:154-159, 206-211, 555-565`. Add the derive
      across `FalconSecretKey`, `KyberSecretKey`, `KeyShare`,
      `DecryptionShare`. Wrap the local `seed_bytes` in
      `combine_shares` (line 516) with `Zeroizing`.
- [ ] 359 — `⚠` **Threshold MAC keystream collision risk:
      keystream + MAC share `ss` with weak prefix-disjoint domain
      separation.** `crates/crypto/src/threshold.rs:321-343`.
      Add explicit domain tags
      (`Poseidon2("pyde-keystream-v1" || ss || nonce || counter)`,
      `Poseidon2("pyde-mac-v1" || ss || ciphertext)`) plus a
      per-ciphertext nonce (current keystream is purely
      deterministic on `ss`).
- [ ] 360 — `⚠` **`combine_shares` error split between Kyber
      decapsulate failure and MAC failure leaks oracle bits.**
      `crates/crypto/src/threshold.rs:537-549`. Collapse both to a
      single opaque `"threshold decryption failed"` error.

### WASM crypto crate

- [ ] 361 — `⚠` **`generateKeypair` returns secret key as JSON
      hex.** `crates/pyde-crypto-wasm/src/lib.rs:11-21`. JS heap
      retains the string; dev-tools / extensions / crash dumps
      preserve it. For testnet wallets, document loudly + offer an
      opaque-handle mode that keeps sk inside WASM-internal state.
- [ ] 362 — `⚠` **WASM defaults `chainId = 31337` when missing.**
      `crates/pyde-crypto-wasm/src/lib.rs:150, 260, 368`. Same
      cross-chain replay surface as 302/303. Make `chainId`
      required; fail with a clear error if absent.

---

## P2 — Hygiene (do as bandwidth allows)

- [ ] 370 — Otic map-key derivation diverges from
      `pyde_state::keys::map_entry_key`. `crates/otic/src/codegen.rs:2806-2817`
      vs `crates/state/src/keys.rs:163-168`. Currently no caller
      uses `map_entry_key` from prod, so benign — but align before
      indexer / migration tooling assumes the documented derivation.
- [ ] 371 — RocksDB column families unused; all key spaces share
      the default CF. `crates/state/src/backend.rs:296-298`,
      `crates/state/src/jmt_store.rs:133`.
- [ ] 372 — JMT value cache keyed only by `key_hash`, not
      `(key_hash, max_version)`. `crates/state/src/jmt_store.rs:231,
      86, 261`. Critical before exposing historical-state RPC.
- [ ] 373 — Dead code: `crates/state/src/snapshot.rs`,
      `crates/state/src/tiers.rs`, `crates/net/src/sync.rs`,
      `crates/consensus/src/hotstuff.rs::create_timeout`,
      `crates/node/src/aot_cache.rs` LRU promotion path,
      `validator.rs:632 pending_tx_tx`. Delete or wire — pick one.
- [ ] 374 — `StateOverlay::insert` / `into_writes` use
      `HashMap<Key, Vec<u8>>` (non-deterministic order in
      collection / undo logs). `crates/state/src/smt.rs:225-227`.
      Switch to `BTreeMap`.
- [ ] 375 — `SmtValue::to_h256` collision: empty vec returns
      `H256::zero()` — same as absent leaf. `crates/state/src/smt.rs:73-85`.
      Either reject empty-byte writes at the storage-trie boundary
      or document the tombstone semantics.
- [ ] 376 — Unbounded `gas_used_total += ...` in 22 sites in PVM.
      Mirror Memcpy's `checked_add` pattern.
- [ ] 377 — VerifySig / MerkleVerify early-return paths skip OOG
      check after page-gas drain. `crates/pvm/src/vm.rs:1128-1132,
      1140-1144, 1347-1355`.
- [ ] 378 — `len: u64 → as u32` truncation in checked_read_slice /
      checked_write_slice callers (Poseidon, SstoreB, Log,
      VerifySig, MerkleVerify, do_ext_call, do_create). Mirror the
      audit-215 Memcpy pre-cast bound check at every call site.
- [ ] 379 — CREATE deterministic address has no nonce —
      front-runnable address grabbing. `crates/pvm/src/vm.rs:1779-1782`.
- [ ] 380 — Heartbeat 400ms (matches slot time). Bump to 1 s once
      peer scoring + peer-book restoration stabilize the mesh
      post-restart. `crates/net/src/node.rs:118`.
- [ ] 381 — `propagation::rand_nonce` uses SystemTime, not CSPRNG.
      `crates/net/src/propagation.rs:117-124`. Switch to
      `getrandom::getrandom` (already a dep).
- [ ] 382 — Faucet `signing_lock` doesn't bound queue length;
      semaphore + 503 on saturation. `crates/node/src/faucet.rs:430-460`.
- [ ] 383 — `pyde testnet --chain-id 1` not refused.
      `crates/node/src/genesis.rs:845-1368`.
- [ ] 384 — Mempool `EncryptedTx` `add()` (structural-only) accepts
      sig length [500, 1000] — verify mainnet path always takes
      `Verify` or `Reject`, never `StructuralOnly`.
- [ ] 385 — `prune_expired` clears + rebuilds `seen_hashes` on
      eviction. `crates/mempool/src/pool.rs:443-451`. Track removed
      hashes incrementally.
- [ ] 386 — Encrypted nonce-window check at RPC ingress can
      overflow on near-`u64::MAX` base. `crates/node/src/rpc.rs:1365`,
      `crates/account/src/nonce.rs:53`. Use `checked_add`.
- [ ] 387 — `prompt_password` echoes input.
      `crates/pyde-dev/src/wallet.rs:291-298`. Use `rpassword`.
- [ ] 388 — `is_localhost` uses `String::contains`.
      `crates/pyde-dev/src/signer.rs:178-184`. Parse with
      `url::Url::host_str` and exact-match.
- [ ] 389 — `account::auth::validate_signature` for MultiSig
      doesn't dedup keys. `crates/account/src/auth.rs:60-94`.
      Cross-with #304 fix: invariant check at construction.
- [ ] 390 — `NonceState::from_bytes` silently returns
      `Self::new()` on invalid input; should be `Option<Self>`.
      `crates/account/src/nonce.rs:100-113`.
- [ ] 391 — Goldilocks bias: `gl(u64::from_le_bytes(...))` reduces
      mod p, biasing values in `[p, 2^64)`.
      `crates/crypto/src/threshold.rs:55, 199, 238, 381, 484, 653,
      822`. Use rejection sampling for randomness paths; document
      the silent-remap on Kyber-seed reconstruction.
- [ ] 392 — `Hash256::from_slice` silently truncates/pads.
      `crates/crypto/src/hash.rs:24-29`. Return `Option<Hash256>`.
- [ ] 393 — VRF input domain reuse: `VRF_DOMAIN_OUTPUT` used for
      both `sk_input` and `output_input`.
      `crates/crypto/src/vrf.rs:15-16, 49-62`. Split into
      `VRF_FINGERPRINT_DOMAIN` and `VRF_OUTPUT_DOMAIN`.
- [ ] 394 — `falcon_batch_verify` is a sequential `.all(...)`,
      not algebraic batch verification.
      `crates/crypto/src/falcon.rs:118-122`. Rename to
      `falcon_verify_all` until upstream supports a true batch
      API, OR wire to the upstream batch path if available.
- [ ] 395 — `validator.key` regeneration on missing file silently
      re-keys the validator. `crates/node/src/node.rs:5181-5224`.
      Refuse on non-devnet `chain_id` unless explicit
      `--init-validator-key` flag.

---

## Verification log

| ID  | Verified on | How | Verdict |
|-----|-------------|-----|---------|
| 301 | 2026-04-30  | Read `crates/mempool/src/encrypted.rs:106-181` end-to-end; confirmed raw-slice indexing on user-controlled offsets; cross-checked `panic = "abort"` at `Cargo.toml:63` | Real; trivial RPC-aborts-node DoS |
| 308 | 2026-04-30  | Read `crates/pvm/src/vm.rs:1316-1322` and the parent merge at `:1697-1699` | Confirmed: `self.storage.clear()` plus unjournalled merge nukes shared storage |
| 309 | 2026-04-30  | Same read as 308 + `rollback_storage` at `vm.rs:1906-1918` | Confirmed: child writes merged without journal entry |
| 311 | 2026-04-30  | Read `block_processor.rs:719-728`; grep `verify_qc\|verify.*QuorumCert\|qc.*verify` across the whole tree → zero hits outside per-vote `verify_vote` inside `try_form_qc` | Confirmed: incoming QCs accepted on bitmap count alone |
| 312 (PSS) | 2026-04-30 | Read `crates/crypto/src/threshold.rs:706-746` and `random_goldilocks` definition at `:47-57` | Confirmed: `fresh_random` is deterministic on public `(epoch, index)` |

The remaining `⚠` items are agent-claimed with cited file:line refs.
Mark each `✓` after the implementer reads + reproduces.

---

## Suggested order (smallest blast-radius first)

The first cluster lands quickly and unblocks the rest:

1. **301** — checked-cursor decoder for `EncryptedTx::from_bytes`.
   Single file, includes a fuzz target, lands in a day.
2. **302, 303** — RPC + faucet `chain_id` defaults. Two-line fixes
   each, one PR.
3. **306** — Argon2id KDF + keystore version bump. Touches three
   files but mechanical.
4. **304, 305** — Reject `AuthKeys::MultiSig`,
   `FeePayer::Paymaster`, `FeePayer::GasTank` at validation +
   ingress (mirror audit-226). One PR.
5. **307** — Tx pipeline writeback fix. Larger refactor; either
   add MultisigTx-style guards everywhere (one PR) or unified-update
   refactor (~3 days).
6. **310** — AOT/interpreter parity bundle + property test.
   The AOT-side fixes are mostly mechanical once the property test
   surfaces each divergence — start with the property test, then
   patch.
7. **308, 309** — PVM Selfdestruct + cross-contract storage
   journal. Combined PR. Includes property test for parent-revert
   storage restoration.
8. **311** — `QuorumCert::verify` + call from
   `validate_network_block` AND `create_vote`. Single file edit,
   single new fn. Add the `single_block_per_height_under_partition`
   test the consensus invariants doc references.
9. **312** — PSS refresh + decryption-share auth + testnet runbook
   note. Bigger crypto-protocol PR; can run in parallel with the
   above starting day 2.

Then the P1 track in parallel — consensus / state / net / RPC each
have an obvious owner.

---

## Out-of-scope for this audit cycle

- Items already tracked in `AUDIT_FINDINGS.md` (cycle 1) — see that
  file.
- 234 #3 (gossipsub mesh stall during 4-of-4 rolling restart) —
  documented open; not testnet-blocking on a stable
  16-validator network.
- 224 (block explorer) and 225 (faucet UI) — separate repos /
  partially shipped.
- Mainnet-only items (real DKG, Argon2 → HSM-backed signing,
  STARK proving for stateless validation, full reorg Byzantine
  harness 233).
