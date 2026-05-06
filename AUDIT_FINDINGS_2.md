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

      **Follow-up (2026-05): missing `account.nonce` propagation.**
      `apply_account_delta` originally handled `balance`,
      `gas_tank`, and `auth_keys`, but `account.nonce` was the
      lone field the pipeline mutates that wasn't propagated.
      The Deploy handler does `sender.nonce += 1` to advance the
      CREATE-address counter, but the late write-back loaded
      sender fresh from SMT and stored without applying that
      increment — so the persisted counter stayed at 0 and every
      Deploy from the same sender resolved to
      `create_address(sender, 0)`, with each new contract
      silently overwriting the previous one's runtime bytecode.
      Surfaced by `pyde-node`'s `reentrancy_attack_blocked`
      integration test (deploys two contracts back-to-back; the
      attacker overwrote the vault, all subsequent calls hit
      no-code paths). Fix: mirror the auth_keys override
      semantics — if `final_.nonce != initial.nonce`, set
      `current.nonce = final_.nonce`. New
      `deploy_increments_persisted_nonce_after_307` regression
      test in pyde-tx pins the fix.

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

- [x] 319 — `✓` **Encrypted-tx burst at audit-027 cap fails with
      cross-node state divergence.** **SHIPPED.** Three layers,
      each addressing a distinct contributing failure:
      1. **Sync-path decryption bootstrap.** `SyncEngine::on_response`
         now also returns synced blocks whose
         `body.encrypted_txs` is non-empty, and the event-loop
         action handler runs the same
         `maybe_kick_decryption_pipeline` against each that the
         gossip-arrival path runs. Pre-fix the sync path
         applied plaintext txs but never started the
         BlockDecryptor / share-broadcast on the syncing node;
         a validator that reached a block via sync (because it
         missed the compact-block + bundle gossip — common
         under sustained ≥ 25 enc-tx/s when gossipsub mesh
         churn drops bundle messages) therefore never broadcast
         its shares, the per-slot share threshold stalled, and
         the encrypted txs in that block never decrypted on ANY
         validator's local state.
      2. **Mandatory-inclusion audit observational-only on
         small committees.** New
         `MEV_INCLUSION_MIN_ENFORCEMENT_COMMITTEE = 32` gate
         downgrades the task-026 audit's "skip vote" enforcement
         to log-only when the committee size is below the
         threshold where 1 abstainer is < 1/128 dissent. Pre-fix
         a 4-validator devnet/testnet committee under burst load
         saw 3445 audit-fail warnings in a 181 s run with every
         encrypted-tx slot blocked by unanimous abstention —
         chain advanced on plaintext only, inclusion = 0%.
         Mainnet's 128-validator committee continues to enforce
         (slack of 42 dissenters before quorum lost).
      3. **Periodic decryption-share rebroadcast.** New 100 ms
         retry tick walks `pending_decryptors` and re-broadcasts
         our shares for any decryptor that hasn't reached
         threshold yet. Closes the gossipsub 1-3% loss window
         where a single share-broadcast miss leaves the
         cluster's per-slot share count below threshold and the
         encrypted_txs silently never decrypt for the affected
         validator(s). Shares are deterministic from
         `(key_share, ciphertext)` so regeneration is cheap and
         `BlockDecryptor::add_share` is idempotent (set-insert)
         on the receiver. Self-heals: once threshold reached,
         the decryptor is removed and the tick stops emitting
         for that slot.

      Test outcome: `loadgen_encrypted_burst` went from 0%
      inclusion / 181 s timeout (pre-fix) to 100% inclusion in
      ~2-3 s with full cross-node convergence on 3 consecutive
      runs. Throughput at the audit-027 cap (40 enc-tx/s
      aggregate via 4-sender × 10-tx fan-out) is now ~14-17
      enc-tx/s sustained.

- [x] 396 — `✓` **Cold-start sync hung at slot 0.** **SHIPPED.**
      Three independent gaps in the late-joiner pathway:

      **(a) `RequestChainTip` action was emitted nowhere.** The
      `PostEventAction::RequestChainTip(peer)` variant existed
      with a wired handler, but no event-loop branch ever
      produced it. A fresh full node connected to peers, never
      asked any of them for their chain tip, so
      `sync_manager.network_tip` stayed at 0,
      `is_behind` returned false, no `GetBlocks` ever fired.
      Fix: `RecordPeerAndAuth` (the action emitted on every
      `ConnectionEstablished`) now also calls
      `chain_sync.request_chain_tip(&mut swarm, peer_id)`.

      **(b) Compact-block gossip didn't refresh
      `network_tip`.** `update_network_tip(slot)` only fired on
      the `missing_txs.is_empty() == false` branch of
      `ReconstructCompactBlock` — i.e., only when local
      reconstruction needed sync help. Empty warm-up blocks
      (which validators produce in droves at testnet startup)
      reconstructed cleanly, so a node that joined at genesis
      and only ever saw empty blocks never learned the
      validators were ahead. Fix: hoist the
      `update_network_tip(slot)` call to the top of the handler,
      before the missing-tx branch.

      **(c) Sync-applied blocks dropped their receipts.**
      `on_response` called
      `process_full_block_with_aot_and_checkpoint(...)` but
      destructured the result as `Ok((_, _, _receipts))` — the
      receipts were discarded. A node that reached its head
      purely via sync executed every tx but had no receipts to
      serve over `pyde_getTransactionReceipt`. Fix: change
      `on_response` return type to
      `(u64, Vec<(u64, Vec<Receipt>)>)` and emit a new
      `PostEventAction::SyncedBlocksApplied` that persists
      receipts via the same `ReceiptStore` the QC-apply path
      uses, then optionally continues sync.

      **Verification:** `multi_node_sync` ✅ passes (was the
      direct repro). `multi_node_full_node_relay` now reaches the
      receipt-divergence assertion (was failing 60 s prior at
      "receipt never appeared on full node") — separate
      pre-existing nonce-window test-infra issue surfaces next.
      `validator_churn` failures are independent (view-change
      stall, not sync) — see #399.

- [ ] 397 — `✓` **`epoch_rotation_crosses_boundary` exceeds 240 s
      timeout reaching slot 1005 at `block_time_ms=100`.**
      Surfaced same e2e run as #396. **Predates this audit cycle**
      — fails identically on `aee961d` (244 s) and HEAD (243 s).
      Test config asks for slot 1005 in 100 ms × 1005 = 100.5 s of
      ideal-case slot ticks, with a 240 s deadline (2.4×
      ideal-case headroom). Fails at 240 s, so actual slot rate is
      < ~250 ms/slot — 2.5× slower than configured under 4-node
      subprocess load on a laptop.

      **Suspected cause.** Either
      (a) `block_time_ms` plumbing isn't reaching every code path
      (some loop still uses the 400 ms compile-time const), or
      (b) consensus throughput under the 4-subprocess load on the
      test machine just can't sustain 10 slots/s.

      **Where to look:**
      - `pyde_consensus::block::BLOCK_TIME_MS = 400` —
        compile-time constant; runtime `block_time_ms` should
        override it but call sites in `node.rs` /
        `validator.rs` may still read the const.
      - `tokio::time::interval` constructions for slot pacing.

      **Reproducer:**
      ```
      cargo test -p pyde-node --test multi_node_epoch_rotation \
        -- --ignored --nocapture
      ```

      **Pre-launch impact:** epoch boundaries on real testnet run
      at the canonical 400 ms slot time, so they cross at ~6.7
      min — no real-network deadline pressure. The test was
      designed for fast iteration, not as a production gate.
      Risk band: zero for testnet. Worth fixing before the chain
      reaches its first real epoch boundary so the rotation code
      path is exercised end-to-end at production speed.

- [x] 398 — `✓` **`tx_via_full_node_reaches_validator` fails:
      tx submitted to full node never appears at validator within
      30 s.** **SHIPPED.** Pre-fix the failure was misdiagnosed as
      a relay-pathway bug; the actual root cause was a
      port-allocation collision in the `pyde testnet` config
      generator that sometimes prevented the test from spawning
      4 nodes at all. The node binds two TCP ports per RPC —
      `rpc.port` (JSON-RPC) and `rpc.port + 1` (dedicated
      WebSocket subscription server, see
      `node.rs::start_ws_server`) — but the genesis CLI assigned
      RPC ports with stride 1 (`base_rpc_port + i`). With stride
      1, node-0's WS port (base + 1) collides with node-1's RPC
      port (base + 1) on the bind race; whichever child won the
      race got the port, the other logged "Address already in
      use" and ran with RPC disabled. The test polled the
      RPC-disabled node's port for 30-45 s and timed out. The
      failure was racy — about 30% of spawns hit the collision —
      which is why earlier runs sometimes succeeded and obscured
      the root cause. Fix:
      1. `pyde testnet` writes per-node RPC ports with stride 2
         (`base_rpc_port + 2*i`), giving each node an exclusive
         pair `(rpc, ws)` of contiguous ports.
      2. `pyde testnet` also writes a per-node `[fast_tx]`
         section with `port = 9545 + i`. Pre-fix the
         FastTxSection default (port 9545, listen 0.0.0.0) was
         inherited by every node — only the first could bind
         9545, the rest logged "fast_tx bind failed" (warn-only,
         not fatal, but cosmetically alarming).
      3. The test harness (`crates/node/tests/common/mod.rs`)
         allocates `2 * total` contiguous TCP ports for the RPC
         range and uses stride 2 when computing per-node
         `rpc_port`.
      Test outcome: `multi_node_full_node_relay` was flaky
      (3/5 passing pre-fix → 5/5 passing post-fix) with no
      additional churn elsewhere. Single-node-operator
      conventions are unchanged (`pyde run --rpc-port 8545`
      still gives RPC=8545); only multi-node `pyde testnet`
      layouts use the new stride.

- [x] 399 — `✓` **Validator restart-rejoin stalled the chain.**
      **SHIPPED.** Two distinct bugs in the late-joiner pathway,
      surfaced when killing + restarting validators in the
      `validator_churn` and `validator_churn_4_of_4` tests:

      **(a) `slot_clock` anchor was wrong on restart.** The
      original logic backdated genesis to `now - saved_head *
      block_time_ms`. After a restart, this anchor sat further
      forward in wall-clock than the still-running validators'
      anchor (their `genesis_instant` was their original startup
      time). Net effect: a restarted validator's `current_slot()`
      returned `saved_head` while live peers were many slots
      ahead. `select_and_vote` keys off
      `consensus.current_slot` (which tracks `slot_clock`), so
      the restarted validator kept proposing/voting on stale
      slots. With one node killed AND one node muted by this
      clock skew, a 4-of-4 cluster fell below 3-of-4 quorum and
      stalled. Fix: derive the anchor from
      `chain.headers[head_slot].timestamp - head_slot *
      block_time_ms` — `block.timestamp` is wall-clock at
      proposal time, so this recovers the original
      `genesis_instant` that all validators share.

      **(b) Compact-block tip-bump triggered NotFound sync
      loops.** Pre-fix the `update_network_tip(slot)` call
      inside `ReconstructCompactBlock` bumped the tip from any
      proposal received via gossip — including
      proposals-in-flight that hadn't QC'd yet. Sync engaged for
      those slots, server returned NotFound (full block doesn't
      exist anywhere until QC + apply), and the tight retry
      loop starved the consensus message handler — votes
      couldn't drain, no QC formed, chain stalled. Fix:
      replaced direct `update_network_tip` with a
      `request_chain_tip(peer)` re-poll for slots more than
      `head + 1` ahead. The peer responds with their applied
      head (`chain.head_slot` in `SyncResp::ChainTip`), which is
      the right tip signal for sync.

      **(c) `target_height` didn't advance for sync-applied
      blocks.** The QC-apply path advances target_height via
      `on_vote`'s success branch. The sync-apply path bypassed
      that, leaving `target_height` pinned at the pre-restart
      slot — the restarted validator received proposals for the
      live network's current slot but its
      `select_and_vote` targeted target_height, not wall-clock
      slot. Fix: after `on_response` applies sync blocks, call
      `engine.advance_target_height_after_sync(chain.head_slot
      + 1)` so the engine follows along. `advance_target_height`
      is monotonic, so it no-ops if the engine is already ahead.

      **Verification:** `validator_churn` ✅ (47s),
      `validator_churn_4_of_4` ✅ (69s),
      `multi_node_full_node_relay` ✅ (5s — was secondary
      symptom of (b)), `multi_node_sync` ✅ regression-free.
      Full multi-node battery: 13/14 pass; only #397
      (epoch_rotation 240s deadline at 100ms/slot under
      4-subprocess load) remains as a doc'd test-config
      limit.

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
- [x] 322 — `✓` **`RandomnessCollector::finalize` hardcodes 85-share
      threshold.** Shipped: `RandomnessCollector` now stores the
      active `committee_size` (passed at construction) and routes
      `is_complete()` + `finalize()` through
      `randomness_threshold_for(N) = quorum_for_committee(N)`.
      `RandomnessCollector::new(epoch, committee_size)` is the new
      signature; production caller in `validator.rs:1043` passes
      `self.committee_keys.len()`. Mirrors audits 234/235/236
      (dynamic quorum for QC + view-change + hard-finality).
      2 new tests (`collector_completes_on_small_committee_audit_322`
      proves a 4-validator devnet finalizes at 3-of-4;
      `collector_below_dynamic_threshold_stays_incomplete` proves
      4-of-7 stays incomplete since `randomness_threshold_for(7) =
      5`). Surfaced + fixed an off-by-one in the legacy
      `RANDOMNESS_THRESHOLD = 85` constant — `quorum_for_committee
      (128) = 86`. 13 epoch_randomness tests pass.
- [x] 323 — `✓` **No proposer-VRF score threshold check on incoming
      blocks.** Shipped: extracted the threshold formula into
      `pyde_consensus::proposer::vrf_proposer_threshold(committee_size)`
      and the score helper into `score_from_output(&VrfOutput)`,
      both `pub`. `validate_network_block` now extracts the score
      from the verified VRF output and rejects when `score >
      threshold`. `validator::check_proposer` switched to the
      shared helper so producer and verifier can never drift.
      3 new tests on the helpers (small-committee everyone-eligible
      branch, linear scaling with N, `score_from_output` LE
      decoding). 14 proposer tests pass; workspace builds clean.
- [x] 324 — `⚠` **`view_change_sign_message` doesn't bind
      `highest_qc`.** **SHIPPED.** `view_change_sign_message` now
      takes `&QuorumCert` and folds `highest_qc.hash()` (which
      itself binds slot + block_hash + voter_bitmap) into the
      FALCON preimage. Pre-fix the message only committed to
      `(chain_id, slot)` while the gossip envelope carried
      `highest_qc` as an unauthenticated tag-along — a middlebox
      observing a legitimate `ViewChangeMessage` could strip the
      embedded `highest_qc` and swap a stale or empty QC; the
      FALCON sig still verified, and `try_form_view_change_qc`'s
      "highest QC" aggregator picked the fabricated value, biasing
      the fallback proposer onto a stale chain head. With the QC
      hash mixed in, any rewrite produces a payload whose
      `highest_qc.hash()` differs from the signed preimage and
      `verify_view_change` rejects. New 3 audit-324 tests pin:
      swapping `highest_qc` to empty breaks the sig, rewriting any
      single field of `highest_qc` (slot / block_hash /
      voter_bitmap) breaks the sig, honest non-empty round-trip
      still verifies.
- [x] 325 — `⚠` **No timestamp validation.** **SHIPPED.**
      Added `MAX_TIMESTAMP_DRIFT_MS = 15_000` constant and extended
      `validate_network_block` with `parent_timestamp: Option<u64>`
      + `now_ms: u64` parameters. Enforces
      `parent.timestamp < header.timestamp` (when parent_ts known)
      AND `header.timestamp ≤ now_ms + DRIFT`. Smart contracts read
      `block.timestamp` via the PVM, so an unbounded proposer-set
      timestamp is a contract-level attack vector. The gossip-block
      call site in `node.rs` now pulls
      `chain.header(slot-1).timestamp` for slot>1 (slot=1 falls back
      to drift-only since the genesis header isn't tracked in
      `chain.headers`). 4 new tests covering: ≤parent rejection,
      far-future rejection, in-drift acceptance, None-parent skip.
- [x] 326 — `⚠` **`seen_evidence`, `seen_finality_votes` unbounded
      memory.** **SHIPPED.** `seen_evidence` is now pruned in the
      slot-prune loop alongside `seen_proposals` / `seen_votes`,
      with the same 10-slot retention window. Pre-fix the HashSet
      grew unbounded for the validator's lifetime — a long-running
      testnet validator with thousands of slashing events would
      accumulate one entry per distinct (slot, signer) pair
      indefinitely. `seen_finality_votes` was added in audit 327
      with prune already wired; double-checked. New 1 audit-326
      test seeds 20 slots' worth of entries, jumps to slot 25, and
      asserts entries < 15 are dropped while ≥ 15 remain.
- [x] 327 — `⚠` **Vote / view-change vec accept unbounded duplicates
      pre-dedup.** **SHIPPED.** Three call sites (`on_vote`,
      `on_view_change`, `on_finality_vote`) now short-circuit on
      `(slot, voter_index)` BEFORE pushing into the per-slot Vec
      and BEFORE running FALCON verification:
      * `on_vote` reuses `seen_votes` (already keyed on
        `(slot, voter_index)`); same-hash replays drop pre-verify,
        different-hash continues to the existing equivocation /
        evidence path.
      * `on_view_change` and `on_finality_vote` get new HashSets
        (`seen_view_changes`, `seen_finality_votes`) keyed on
        `(slot, voter_index)`. The slot-prune loop retains both
        sets in lockstep with the Vecs.
      Pre-fix `try_form_view_change_qc` and `try_form_hard_finality`
      ran FALCON verification on every entry of the per-slot Vec,
      so a peer flooding the same `(slot, voter_index)` repeats
      forced O(N) FALCON re-verifies per QC-formation attempt —
      the per-slot CPU cost grew unbounded with adversarial
      gossip. Now any flood drops at the dedup gate. New 3
      audit-327 tests pin: 100 vote replays leave per-slot Vec at
      length 1, same for view-changes, same for finality votes.
- [x] 328 — `⚠` **`compute_slash` uses fixed `VALIDATOR_STAKE`
      (10K), not actual current stake.** **SHIPPED.**
      `slash_double_sign` now takes a `current_stake: u128`
      parameter and `LivenessReport` carries `current_stake: u128`;
      both feed `compute_slash` so the returned `amount_burned +
      finder_fee` honours the offender's live stake instead of the
      genesis-time constant. Pre-fix a repeat offender whose stake
      had already been halved by a prior slash got a SlashResult
      promising the full 10k-PYDE-equivalent — a number the
      subsequent `apply_slash` could not actually debit (it clamps
      to 0), so any caller crediting `amount_burned` to the
      treasury would over-credit and leave a phantom shortage.
      The on-chain `pyde_tx::pipeline::execute_slash` was already
      doing the right thing (`entry.stake.min(SLASH_VALIDATOR_STAKE)`),
      so the production money-flow path is unaffected; the fix is
      to the public consensus-layer API used by the gossip-side
      ingestion harness and downstream slash-routing tooling.
      Node-side `ingest_evidence` switched from `slash_double_sign`
      to `verify_double_sign` since it only cared about signature
      validity (the SlashResult was discarded). New 4 audit-328
      tests pin: repeat offender's slash scales to half-stake,
      zero-stake offender yields zero amounts (still ejected),
      liveness slash uses live stake, apply_slash debit equals
      promised slash exactly (no phantom mint).
- [x] 329 — `⚠` **`is_finalized` (2-chained-QC rule) is dead code.**
      **SHIPPED.** Took the doc-aligned path: deleted
      `is_finalized` and its `pipelined_finality` test, and
      replaced both with a long comment block at the deletion
      site explaining what Pyde's actual finality protocol is
      (the soft+hard split in `pyde_consensus::finality`). Pre-fix
      the helper was textbook pipelined-HotStuff finality, but no
      production code path ever called it — the dispatch runs
      end-to-end through `FinalityTracker::record_soft_finality`
      (set on the first vote-QC for a slot) and
      `record_hard_finality` (set when a separate `FinalityVote`
      round produces a `FinalityCert` with FALCON sigs over
      `(slot, block_hash, state_root)`). Keeping the unused helper
      around as documentation-only public API was actively
      misleading: explorers / WS clients use the FinalityCheckpoint
      as their reorg-safe anchor, and a reader landing on
      `is_finalized` would reasonably assume the textbook rule was
      authoritative when it isn't. The deletion comment makes it
      easy to reintroduce the rule if Pyde ever migrates to
      pipelined-HotStuff finality.

### State

- [x] 330 — `⚠` **JMT commit non-atomic across two `db.write` calls.**
      **SHIPPED.** New `JmtRocksStore::commit_atomic(node_batch,
      next_version)` builds a single `rocksdb::WriteBatch` containing
      nodes + values + rightmost-leaf marker AND
      `META_LATEST_VERSION` together; one `db.write_opt(batch)`
      lands them all-or-nothing. Pre-fix `update_all` issued two
      sequential `db.write` / `db.put` calls and a crash between
      them left nodes persisted for `next_version` while the
      version pointer still referenced the previous version —
      orphaned tree pages permanently leaked storage and the
      reopened validator resumed at the OLD version. Removed the
      now-unused `set_latest_version` helper. The trait-required
      `TreeWriter::write_node_batch` impl stays for the JMT
      crate's snapshot-restore path, with a doc-comment warning
      callers not to use it directly. 2 new tests
      (`audit_330_atomic_commit_advances_version_pointer_atomically`,
      `audit_330_commit_atomic_writes_full_set_in_one_batch`); 81
      state tests pass.
- [x] 331 — `⚠` **No fsync on per-block JMT writes.** **SHIPPED.**
      `commit_atomic` (JMT) and `BufferedWriteBackend::flush`
      (legacy SMT) now use `WriteOptions::set_sync(true)` so the
      RocksDB WAL is fdatasync'd before the call returns. Pre-fix
      the default `sync=false` left a ~1 s WAL window during which
      a power loss / VM crash silently rolled back the last
      committed block, putting the recovered validator behind the
      live network on restart. ~1-5 ms cost per commit on
      commodity SSDs, well within the 400 ms slot budget. Combined
      with audit-330's atomic batch, the per-block commit is now a
      true crash-consistent durable write.
- [x] 332 — `⚠` **Decrypted-tx execution writes directly to SMT
      bypassing cache + undo log.** **SHIPPED.** Both call sites
      that executed decrypted txs (`block_processor::try_decrypt_and_execute`
      and the single-node decrypt path in `node.rs`) used to call
      `execute_transaction(dtx, &mut *state.smt_mut(), &block_ctx)`,
      writing straight into the underlying JMT and bypassing the
      StateManager's cache + undo log. Two consequences:
      1. Cache reads returned stale pre-decrypt values until the
         next invalidation.
      2. `revert_to(slot - 1)` (reorg path, audit 231) only
         walked the undo log and rolled back plaintext writes,
         leaving decrypted-tx state stuck — silent state
         divergence between the chain head and the data on disk.

      Post-fix both paths route through a `StateOverlay` over the
      StateManager, then commit via `update_batch_deferred` +
      `record_block_undo` (matching the plaintext path). The
      block_processor side already calls `record_block_undo(slot,
      ...)` once for plaintext during apply; decrypted-tx execution
      now appends a SECOND `(slot, undo)` tuple — `revert_to` walks
      both together when rolling the slot back. Added explicit
      `flush_pending()` before `refresh_root()` since
      `update_batch_deferred` doesn't immediately push writes to
      the underlying SMT.

      Removed the `smt_mut()` escape hatch entirely so future
      callers can't re-introduce the same skip-the-cache-and-undo
      bug class. 298 node binary tests pass. The
      `multi_node_encrypted_lifecycle` e2e test still passes after
      the refactor (validators converge on the same post-decrypt
      state root).

### Net

- [x] 333 — `✓` **Gossipsub `max_transmit_size = 1MB` ≠ Blocks-channel
      4MB cap.** Shipped: lifted gossipsub
      `max_transmit_size` to 4 MB to match the Blocks-channel
      logical cap (`channels.rs:113-114`,
      `ddos.rs:150-151`). Pre-fix a proposer publishing a compact
      block + a heavy `EncryptedTxBundle` near the per-channel
      ceiling had its publish silently fail at the gossipsub
      layer. This is one component of the audit P1 #319 burst-
      test stall — full investigation deferred but this
      mismatch is closed.
- [x] 334 — `⚠` **No peer scoring config.** **SHIPPED.**
      `gossipsub.with_peer_score(params, thresholds)` now wired into
      `create_node`. Params: `behaviour_penalty_weight = -10.0`
      with threshold 6 and decay 0.5 (squared penalty for
      sustained misbehaviour like graft floods / dropped IWANT,
      lenient toward transient flaps); `ip_colocation_factor_weight
      = -5.0` with threshold 10 (Sybil farms behind one IP get
      scored down without penalizing healthy 4-8 localhost test
      clusters); default `PeerScoreThresholds` (gossip = -10,
      publish = -50, graylist = -80). Without this, a single
      hostile peer that re-grafted faster than the prune backoff
      silently degraded the gossipsub mesh for everyone with no
      recovery path. New `audit_334_peer_scoring_is_installed_on_create`
      regression test exploits the "Peer score set twice" error
      to assert installation. 83 net tests pass.
- [x] 335 — `⚠` **`crates/net/src/ddos.rs` entirely dead code.**
      **SHIPPED — deleted.** The 431-line module of unwired
      RateLimiter/SubnetLimiter/PowChallenge/diversity primitives
      gave a false sense of protection (operators reading the
      source might assume per-peer flood limits + per-/24
      connection caps were active). Audit 334's gossipsub
      peer-score covers the most-needed pieces:
      `behaviour_penalty_weight` replaces RateLimiter,
      `ip_colocation_factor_weight` replaces SubnetLimiter at IP
      granularity, and audit-333's `max_transmit_size` covers
      message-size enforcement. PoW connection-flood mitigation
      and /24-subnet limits aren't covered exactly; if real-world
      telemetry shows them needed, re-introduce wired into
      `ConnectionEstablished`. Until then keeping dead code is
      worse than honest removal.
- [x] 336 — `✓` **`PeerInfo.ip` never populated.** Shipped: new
      `pyde_net::peer::ip_from_multiaddr(&Multiaddr) ->
      Option<IpAddr>` walks the protocol stack and returns the
      first `Ip4` / `Ip6` segment. New `PeerInfo::with_ip(ip)`
      builder. The `ConnectionEstablished` handler in
      `node.rs` now extracts the ip from the remote multiaddr and
      threads it into `PeerInfo` before `add_peer`. Pre-fix `info.
      ip` was always `None`, so `is_rate_limited` short-circuited
      false and `rate_limit_per_ip` silently did nothing. 5 new
      tests covering ip4 / ip6 / quic-suffix / dnsaddr-returns-none
      / `with_ip` builder. 22 peer tests pass.
- [x] 337 — `✓` **`SyncReq::GetBlocks` count unbounded server-side.**
      Shipped: clamped to `MAX_GET_BLOCKS_COUNT = 256` before any
      iteration. Same clamp shape applied to `SyncReq::GetHeaders`
      (`MAX_GET_HEADERS_COUNT = 1024`) since the symmetric loop had
      the same uncontrolled bound.
- [x] 338 — `✓` **`SyncReq::StateSnapshotChunk` chunk_size unbounded
      server-side.** Shipped: clamped to `MAX_SNAPSHOT_CHUNK_SIZE
      = 50_000` entries. Pre-fix a peer requesting `chunk_size =
      u32::MAX` sliced the whole `snap.entries` into one response,
      defeating chunked transfer + driving full-snapshot
      allocations per request. 17 sync tests pass.
- [x] 339 — `⚠` **`channels.rs::validate_message` dead code.**
      **SHIPPED — pruned.** `NetworkMessage`, `ValidationResult`,
      `validate_message`, and `MessageDedup` had zero callers.
      Their roles are fully covered by gossipsub: validator-only
      enforcement at subscribe time, size cap by
      `max_transmit_size` (audit 333), and dedup by
      `duplicate_cache_time`. Kept only `Channel` (used by
      node.rs) and trimmed channels.rs from 325 → 113 lines.
- [x] 340 — `⚠` **`identify::Behaviour` protocol-version doesn't
      bind chain_id.** **SHIPPED.** Protocol version is now
      `format!("/pyde/1.0.0/{chain_id}")` so peers from a
      different chain are visible at handshake time. New
      `chain_id: u64` field on `NetworkConfig` plumbed from
      `[node].chain_id` in config.toml. The
      `IdentifyEvent::Received` handler in node.rs disconnects
      peers whose `protocol_version` doesn't match the local
      chain — they're benign (FALCON peer-attestation also
      catches them downstream) but consumed Kademlia + gossipsub
      resources until the downstream rejection. Pre-fix the
      protocol version was the static "/pyde/1.0.0", so a chain-
      7331 node and a chain-12345 node happily handshook.

### RPC / node

- [x] 341 — `⚠` **Full nodes skip header validation on gossip full
      blocks.** **SHIPPED.** Pre-fix `validate_network_block` was
      gated on `validator_engine.is_some()`, so a non-validator
      full node accepted any gossip block whose header signature
      was bytes-shaped — a Byzantine peer could feed it a block
      with a bogus proposer (FALCON-signed by a stranger key,
      VRF-faked, QC empty) and the full node would persist + relay
      it. Post-fix the full node also runs the header check using
      a `committee_keys_for_validation` + `epoch_randomness_for_validation`
      derived from `genesis_config` at startup. Validators still
      use their engine's live committee/epoch state (which rotates
      across epochs); full nodes anchor to the genesis committee
      for now — needs a follow-up to track epoch rotation when
      committee membership changes after genesis. Threaded the
      two new params through `handle_swarm_event`. Same
      `multi_node_propagation` integration test still passes (no
      regression on the same-chain happy path).
- [x] 342 — `✓` **`pyde_estimateGas` and `pyde_createAccessList`
      lack the gas cap that audit 735bcef added to `pyde_call`.**
      Shipped: replaced raw `unwrap_or(1_000_000)` /
      `unwrap_or(50_000_000)` defaults at `rpc.rs:853-856` and
      `rpc.rs:932-935` with `clamp_call_gas(...)`, mirroring the
      `pyde_call` mitigation. `clamp_call_gas`'s existing 3 unit
      tests now cover both call sites since they share the helper;
      explicit per-RPC tests would require a full `RpcState`
      fixture (overhead unjustified for a one-line dispatch).
- [x] 343 — `✓` **`config.toml` `chain_id` not cross-checked against
      `genesis.toml`.** Shipped: new
      `check_config_genesis_chain_id_match(config_id, genesis_id)`
      helper next to `check_bootstrap_config` in `node.rs`.
      Refuses startup with a clear error pointing operators at
      either updating config.toml or regenerating the genesis
      bundle. Wired in `PydeNode::run` immediately after the
      genesis-config load + before any chain or block-store init.
      2 new unit tests on the helper covering matching cases [1,
      7, 7331, 31337, 1M] and 5 mismatch shapes (config↔genesis
      pairs operators commonly mishandle: forgotten regen,
      forged genesis, etc.).
- [x] 344 — `✓` **`pyde testnet` writes keys with default umask.**
      Shipped: new `write_secret_file(path, bytes)` helper at the
      top of `genesis.rs` writes the file then tightens to `0o600`
      on Unix. Used at every secret-bearing site:
      `validator.key`, `node.key`, `threshold.share`, and
      `faucet.key`. Non-secret files (`threshold.pk`,
      `genesis.toml`, `config.toml`) keep default umask. 2 new
      tests on the helper — fresh-file write + overwriting an
      existing 0o644 file (catches the "tighten only on first
      write" hazard). Combined with audit 221's encrypted-keystore
      path, secret-bearing files now ship at 0o600 from the
      moment a coordinator runs `pyde testnet`.
- [x] 345 — `✓` **Missing `set_max_request_body_size` / batch caps
      on jsonrpsee Server.** Shipped: `start_rpc_server` now builds
      the jsonrpsee `Server` with `max_request_body_size(1 MB)`,
      `max_response_body_size(16 MB)`, `max_connections(1024)`,
      and `set_batch_request_config(Limit(32))`. The 1 MB request
      cap fits the largest legitimate `pyde_call` calldata; the
      16 MB response cap covers `pyde_getBlockByNumber(slot,
      full_tx)` and broad `pyde_getLogs` queries; the 32-request
      batch ceiling stops a single connection from rolling
      thousands of cheap sub-requests through one HTTP frame.
      24 rpc tests pass.
- [x] 346 — `✓` **WS subscribe count uncapped per connection;
      unbounded mpsc backs each.** Shipped: replaced
      `mpsc::unbounded_channel::<String>()` with
      `mpsc::channel::<String>(256)` and converted every `out_tx.
      send(...)` to `out_tx.try_send(...)` (drop on full, break the
      pumping task on Closed). Added a `MAX_SUBS_PER_CONN = 16`
      cap before each `tasks.push(tokio::spawn(...))`; over-cap
      requests get a clear `-32603 "subscription cap reached
      (16 per connection); audit 346"` reply.
- [x] 347 — `⚠` **Faucet rate-limiter map grows unbounded.**
      **SHIPPED.** Three layers:
      1. New `is_valid_address(s: &str) -> bool` enforces
         `^0x[0-9a-fA-F]{64}$` (strict 66-char shape) at both
         the POST `/api/request` and GET `/faucet?address=` paths.
         Pre-fix any 64+-char string slipped through and could be
         recorded in the cooldown map.
      2. `RateLimiter`'s backing map switched from
         `HashMap<String, Instant>` to `lru::LruCache` capped at
         `RATE_LIMITER_MAX_ENTRIES = 50_000`. `check` uses
         `LruCache::get` (mutating, moves to MRU) so an
         active-but-still-cooling entry stays warm; `record`
         uses `put` which evicts the LRU entry once the cap is
         reached. Eliminates the unbounded-map OOM vector that
         pre-fix grew with every unique address / IP that ever
         requested.
      3. Body parsing now uses `String::from_utf8` (not
         `from_utf8_lossy`) and rejects non-UTF-8 bodies with a
         400 response. The lossy decoder previously silently
         replaced invalid bytes with U+FFFD, corrupting the JSON
         parser's view AND giving attackers a way to inject
         garbage that survived address-shape checks downstream.
      New 3 audit-347 tests pin: strict address validation
      (length, hex, prefix, unicode), LRU evicts at cap, and
      `check` keeps active entries at MRU.
- [x] 348 — `⚠` **Faucet behind reverse proxy: `peer_addr.ip()`
      collapses to one IP.** **SHIPPED.** New
      `--trust-x-forwarded-for` flag on `pyde faucet` plumbs
      through `FaucetConfig::trust_x_forwarded_for` to the
      connection handler. New `resolve_rate_limit_ip(peer_addr,
      forwarded_for, trust_xff)` helper:
      * `trust_xff = false` (default): always returns
        `peer_addr.ip()`. Direct-internet deployments keep the
        pre-fix behaviour.
      * `trust_xff = true`: returns the rightmost trimmed hop in
        the `X-Forwarded-For` header, lowercased so v6 addresses
        round-trip through `LruCache`'s case-insensitive lookup.
        Falls back to `peer_addr.ip()` when XFF is absent or empty.
      Why "rightmost untrusted hop": the leftmost XFF entry is
      the original (potentially attacker-controlled) client claim;
      the rightmost is whoever the proxy itself last saw connect.
      With the operator's promise that the edge proxy strips any
      inbound XFF before adding its own, the proxy IS the closest
      trusted hop and its view wins. A boot-time `tracing::warn!`
      reminds the operator that the proxy must strip inbound XFF
      headers — without that, an attacker can spoof their client
      IP and bypass per-IP rate-limits. New 6 audit-348 tests
      pin: XFF ignored when not trusted, rightmost-of-many
      selection, single-hop case, whitespace trim, empty/absent
      fallback to peer_addr, IPv6 lowercase round-trip.
- [x] 349 — `⚠` **`pyde_call` block context is zeroed.**
      **SHIPPED.** New `build_call_block_context` helper hydrates
      `block_number` / `timestamp` / `block_proposer` from
      `chain.head_slot` and the head header, and builds the 256-
      slot `block_hashes` window from in-memory `chain.headers`
      with `BlockStore` fallback for older slots. All three
      simulator entry points (`pyde_call`, `pyde_estimateGas`,
      `pyde_createAccessList`) now share the same hydration.
      Pre-fix the simulators built a zero-filled `ExecutionContext`
      so any view function reading `block.number` /
      `block.timestamp` / proposer / `BLOCKHASH` got `0` —
      wallets relying on the simulator to preview a function got
      results that diverged from on-chain execution, painfully
      so on time-locked or block-height-gated views which always
      returned the "before genesis" branch. `gas_price` is also
      now hydrated from `chain.base_fee` so EIP-1559 view
      functions report sensible numbers. New 4 audit-349 tests
      cover the genesis (zero-context) path, head-fields-match,
      newest-first hash indexing (the consumer-side PVM opcode
      lookup convention), and the 256-slot cap.

### Tx

- [x] 350 — `⚠` **`tx.hash()` includes only `fee_payer.tag()`, not
      full bytes.** **SHIPPED.** `Transaction::hash` now mixes in
      `fee_payer.to_bytes()` (1 byte for `Sender`, 33 bytes for
      `GasTank(addr)` / `Paymaster(addr)`) instead of just the
      variant tag. Pre-fix two physically distinct txs that
      differed only in the fee_payer's contained address hashed
      identically — a single FALCON signature authorising
      `GasTank(victim)` was reusable on a tx with
      `GasTank(attacker)` substituted on the wire. `Sender` txs
      hash unchanged (`to_bytes()` for `Sender` is the single
      byte `0`, the same value `tag()` returned), so the only
      production-path tx shape (audit 305 already hard-rejects
      GasTank/Paymaster on non-devnet chain_id) sees no signature
      churn. New 4 audit-350 tests pin: distinct GasTank addresses
      hash differently, GasTank vs Paymaster of the same address
      hash differently, Sender hash is unchanged, and an
      end-to-end FALCON signature minted over `GasTank(A)` does
      NOT verify against the same tx with `GasTank(B)` substituted
      (the actual attack the audit prevents).
- [x] 351 — `⚠` **`StakeWithdraw` never returns stake.**
      **SHIPPED.** Took the testnet-safe path:
      `validate_transaction` now hard-rejects every
      `TransactionType::StakeWithdraw` with the new
      `ValidationError::DisabledTxType` variant on every chain_id
      (devnet included). Pre-fix the handler flipped the
      validator entry to `Unbonding` and recorded `exit_block`,
      but no other code path ever returned the locked
      `VALIDATOR_STAKE` to the operator's balance — operators
      experimenting with the variant on testnet would silently
      lose 10k PYDE. The handler is preserved (it's the
      transition logic we'll re-enable post-mainnet) and the 3
      pipeline-level tests that exercised it are
      `#[ignore = "audit 351..."]`'d so the handler's behaviour
      is documented. Lifting this gate is paired with shipping
      the unbonding-complete path post-mainnet (either as a new
      `CompleteUnbonding` tx type or as a slot-driven sweep that
      re-credits stake once `block_height >= exit_block +
      UNBONDING_DELAY`). 2 new audit-351 tests pin: every
      chain_id rejects `StakeWithdraw` with `DisabledTxType(4)`,
      and `StakeDeposit` is precisely NOT gated (gate is
      variant-specific, not type-class).
- [x] 352 — `⚠` **`tx.value` runs unconditionally for non-Standard
      tx types.** **SHIPPED.** Two layers:
      1. `validate_transaction` rejects `tx.value != 0` for every
         tx_type that isn't `Standard` or `Deploy`, with a new
         `ValidationError::UnexpectedValue { tx_type, value }`
         carrying both fields for the wallet to surface.
      2. `execute_transaction_inner` now matches on `tx.tx_type`
         around `transfer_value` so even an internal caller that
         bypassed validation (replay harnesses, regression
         fixtures, future fast paths) cannot trigger the
         pre-fix behaviour: `Slash` / `MultisigTx` / `ClaimReward`
         / `StakeDeposit` / etc. with `tx.value > 0` performing
         a silent `tx.from → tx.to` transfer alongside their
         declared semantics.
      Pre-fix shape was unreachable from honest tooling but a
      hand-crafted tx exploited it as a free side-channel
      transfer that bypassed all per-type intent analysis
      (paymaster billing, gas-tank accounting, mempool +
      explorer summaries). New 4 audit-352 tests pin:
      `Standard`/`Deploy` with value still accepted, every
      non-value variant with `value > 0` rejected with the
      expected error shape, and the same set with `value == 0`
      not tripping the gate (reaches whatever payload-shape
      check applies further along).
- [x] 353 — `⚠` **Failed-execution txs leak validator CPU without
      consuming nonce.** **SHIPPED.** Two changes:
      1. `nonce_state.use_nonce(...)` is now followed *immediately*
         by `store_nonce(smt, &tx.from, &nonce_state)?;` —
         persisting the new nonce as soon as validation passes
         instead of waiting for the late `store_nonce` at the
         end of the function. The redundant late call was
         removed (it would re-write the same value). Any `?`
         propagation between this point and the end of the
         function (e.g., a `GasTank`-paid tx whose `gas_tank`
         is empty, an SMT write error during fee distribution)
         used to drop the in-memory nonce and let the same tx
         be resubmitted indefinitely; now the nonce slot is
         consumed regardless.
      2. New `emit_failed_execution_receipt` helper catches
         `pre_execution_charge` errors and emits a
         `success = false` Receipt with baseline gas
         (`MIN_GAS_LIMIT * base_fee`) charged from
         sender.balance (saturating) and distributed through
         the standard validator/treasury split. Mirrors
         Ethereum's "buy gas before execute, refund after"
         pattern: even a tx that can't pay still pays
         baseline.
      New 3 audit-353 tests pin: the failed-charge path
      produces success=false (not bubbled Err), replay of the
      same tx after a failed charge hits `InvalidNonce`, the
      failed-charge path debits exactly `21k * base_fee` from
      sender.balance, validator receives its 20% share of the
      failed-tx fee, and the helper saturates (no underflow)
      when sender balance is below baseline cost.

### Otic

- [x] 354 — `⚠` **Signed arithmetic broken end-to-end.**
      **SHIPPED.** Took the conservative typecheck-gate path:
      every `i8`/`i16`/`i32`/`i64`/`i128`/`i256` usage now
      produces a typecheck error pointing at the audit. Codegen
      emits unsigned PVM ops for `Div` / `Mod` / comparisons /
      `Shr`, and the optimizer's constant folder uses `U256`,
      so a contract that compiled with signed types would
      silently produce wrong arithmetic at runtime
      (`i32::MIN / -1`, `-1 < 0`, etc.). New
      `reject_signed_types_in_item` pre-pass walks the entire
      AST (function params + returns, struct/event/storage/error
      fields, type aliases, consts, interface signatures, Vec /
      Map / Tuple / Array element types) and emits errors. 6
      audit-354 tests cover function param, storage field, Vec
      element, Map value, return type rejection plus an
      unsigned-types-still-accepted regression. Post-mainnet path
      to lift the gate is documented: add `Sdiv` / `Smod` /
      `Slt` / `Sgt` / `Sar` ISA opcodes + cascade through
      codegen + optimizer + AOT.
- [x] 355 — `⚠` **`find_field_offset_any` non-deterministic
      bytecode.** **SHIPPED.** The fallback now sorts struct
      names with `BTreeMap`-style ordering (`keys().sort()`)
      before iterating, so the first match is deterministic.
      Pre-fix walked `HashMap.values()` directly — Rust's HashMap
      iteration order is unspecified and varies per process via
      SipHash random seed, so two compilations of the same source
      could pick different fields when a name collides across
      structs and produce different bytecodes. Breaks reproducible-
      builds (operator deploys hash A, CI hashes B, audit reviewer
      hashes C — all valid contracts, none byte-equal). New
      `audit_355_compile_output_is_deterministic_across_runs`
      test compiles the same source 5x and asserts byte-equal
      runtime bytecode; surfaces any future non-determinism leak
      (HashMap iteration, RNG, system time, etc.) as a loud
      assertion failure.
- [x] 356 — `⚠` **FNV-1a-32 selectors with no compile-time dedup
      check.** **SHIPPED.** New
      `audit_356_rejects_contract_with_colliding_selectors` check
      in `check_contract` builds a `HashMap<u32, name>` of public
      function selectors and emits a typecheck error when two
      different names hash to the same FNV-1a-32. Pre-fix the
      dispatch table picked the first match silently, so a
      contract author writing two functions with names that
      happen to collide silently shipped one shadowed by the
      other. Collision probability is ~1.05e-7 for 30 functions
      via birthday paradox; adversarial naming can force one in
      seconds. The regression test brute-forces a real collision
      (1M alphanumeric candidates, ~50 ms) and asserts the
      typecheck rejects it. Plus
      `audit_356_compute_fnv1a_matches_codegen_compute_selector`
      pins byte-equality between the typecheck-side and codegen-
      side FNV-1a-32 helpers so the duplicated implementation
      can't drift. Long-term: still worth switching to Poseidon2-
      truncated to align with `pyde_state::keys` and to get
      cryptographic collision resistance — separate effort.

### Crypto

- [x] 357 — `⚠` **No KAT pinning for ml-kem 0.3.0-rc.x or falcon-rs
      0.2.4.** **SHIPPED.** New `crates/crypto/src/kat.rs` pins
      Known-Answer Tests for every primitive on the consensus
      signing/verification path:
      - **Poseidon2**: 3 vectors covering empty-input, short ASCII,
        and a 64-byte multi-permutation absorb. Catches drift in
        `p3-poseidon2` round constants, `p3-goldilocks` field
        representation, and the padding-free sponge driver.
      - **FALCON-512**: pinned `(pk, sk, msg, sig)` quadruple. Two
        tests: (a) the pinned signature still verifies under the
        pinned pk + msg (cross-version compat), (b) re-signing
        with the pinned sk produces a fresh signature that still
        verifies under the pinned pk (sk encoding sanity).
      - **Kyber-768**: pinned `(sk_seed, ct, expected_shared_secret)`
        triple. Decapsulate is deterministic given (sk, ct), so
        any drift in `ml-kem` decapsulation, key encoding, or
        shared-secret derivation produces different bytes.
      - **VRF**: pinned `(pk, sk, input, output, proof)`. VRF
        output is deterministic (Poseidon2-derived), so we assert
        byte-equality. Proof is a FALCON signature (randomized),
        so we assert verify still accepts it.

      Plus `generate_kat_vectors` `#[ignore]`-gated dev tool that
      prints fresh values when the algorithm is intentionally
      bumped — copy-paste into the constants. 10 KAT tests, all
      pass. Clippy / fmt clean.
- [x] 358 — `⚠` **No `Zeroize`/`ZeroizeOnDrop` on any secret type.**
      **SHIPPED.** Added `zeroize` crate dep to `pyde-crypto`,
      `pyde-node`, `pyde-dev`, and `pyde-rust-sdk`, and applied
      `ZeroizeOnDrop` to every type holding secret material:
      - `FalconSecretKey` (1281-byte FALCON-512 sk) — derive
        `Zeroize, ZeroizeOnDrop` so the inner `Vec<u8>` zeros
        on drop.
      - `KyberSecretKey` (64-byte ML-KEM-768 seed).
      - `SharedSecret([u8; 32])` (post-decap KEM secret).
      - `KeyShare`, `DecryptionShare`,
        `RefreshContribution`, `ResharingContribution` — manual
        `Zeroize` impls walking their `Vec<Goldilocks>` /
        `Vec<Vec<Goldilocks>>` payloads via volatile writes
        (Goldilocks doesn't impl `Zeroize` directly, so we use
        `core::ptr::write_volatile` to overwrite each element
        with `Goldilocks::ZERO` before clearing the vec).
      - Keystore AES keys derived from operator passphrase —
        wrapped in `Zeroizing<[u8; 32]>` in
        `crates/node/src/keystore.rs`,
        `crates/pyde-dev/src/wallet.rs`, and
        `crates/pyde-rust-sdk/src/wallet.rs`. Pre-fix the
        stack-allocated `[u8; 32]` survived in the freed stack
        frame until the next syscall clobbered it; a core dump
        captured between keystore-load and syscall would
        otherwise leak the encryption key.

      6 explicit zeroize tests pass: FALCON sk, Kyber sk, Kyber
      shared secret, KeyShare, RefreshContribution,
      ResharingContribution. `cargo fmt` / `cargo clippy
      -D warnings` clean. Existing 100+ crypto tests + node /
      wallet test suites all green.
      `crates/crypto/src/falcon.rs:13-14, kyber.rs:18-19,
      threshold.rs:154-159, 206-211, 555-565`. Add the derive
      across `FalconSecretKey`, `KyberSecretKey`, `KeyShare`,
      `DecryptionShare`. Wrap the local `seed_bytes` in
      `combine_shares` (line 516) with `Zeroizing`.
- [x] 359 — `⚠` **Threshold MAC keystream collision risk.**
      **SHIPPED.** Bound `kyber_ct` into both the keystream
      derivation AND the MAC keying so a hypothetical Kyber-RNG
      repeat (or any other reuse of `shared_secret`) can't
      collapse two encryptions to the same keystream / MAC key.
      Pre-fix:
      ```
      keystream = Poseidon2(ss || counter)
      mac       = Poseidon2(0xFF*8 || ss || encrypted_msg)
      ```
      Post-fix:
      ```
      keystream = Poseidon2(KS_DOMAIN || ss || H(kyber_ct) || counter)
      mac       = Poseidon2(MAC_DOMAIN || ss || H(kyber_ct) || encrypted_msg)
      ```
      The `kyber_ct` binding turns the Kyber ciphertext (which
      Kyber's IND-CCA2 design already binds to a fresh `ss`) into
      a per-message nonce we control. Even if Kyber's RNG were
      compromised and produced the same `ss` twice, two
      encryptions would still have different `kyber_ct`s →
      different keystreams + MAC keys → no XOR-attack primitive.
      Defense-in-depth against a broken/tampered Kyber.

      Plus explicit `KS_DOMAIN` / `MAC_DOMAIN` byte prefixes so
      a future call site that swaps argument order can't
      accidentally produce a keystream block that also serves as
      a MAC. 2 new tests:
      - `audit_359_keystream_and_mac_unique_per_encryption`:
        two encryptions of the same plaintext under the same
        TPK produce distinct keystreams, ciphertexts, and MACs.
      - `audit_359_kyber_ct_tampering_breaks_decrypt`: swapping
        the `kyber_ct` in a ciphertext (under the same
        `encrypted_msg`+`mac`) trips MAC verify. Pre-fix this
        would have silently re-derived a wrong keystream.
      32 threshold tests pass; 106 total crypto tests pass.
      Mempool + node test suites green (no wire-format break
      because `kyber_ct` was already part of `ThresholdCiphertext`).
      keystream + MAC share `ss` with weak prefix-disjoint domain
      separation.** `crates/crypto/src/threshold.rs:321-343`.
      Add explicit domain tags
      (`Poseidon2("pyde-keystream-v1" || ss || nonce || counter)`,
      `Poseidon2("pyde-mac-v1" || ss || ciphertext)`) plus a
      per-ciphertext nonce (current keystream is purely
      deterministic on `ss`).
- [x] 360 — `⚠` **`combine_shares` error split between Kyber
      decapsulate failure and MAC failure leaks oracle bits.**
      **SHIPPED.** Pre-fix the post-share-validation paths
      returned three distinct error strings:
      - `"invalid reconstructed seed"` — Lagrange-interpolated
        bytes don't decode as a Kyber seed.
      - `"Kyber-768 decapsulation failed"` — seed decoded but
        `dk_from_seed` rejected the structure.
      - `"MAC verification failed"` — seed + decap both passed
        but the recovered `ss` is wrong.

      An attacker submitting crafted decryption shares could
      probe error responses to figure out which pipeline stage
      their inputs landed on, narrowing the search for share
      structures that round-trip the various validators. Each
      probe gives them ~1 bit about the secret committee
      polynomial.

      Fix: collapse all three into a single
      `ORACLE_SAFE_ERR = "decryption failed"`. Also keep going
      on Kyber decap failure (substituting an all-zero placeholder
      `SharedSecret` via a `pub(crate)` constructor in
      `kyber.rs`) so the MAC-verify code path always executes —
      evens out timing across the failure modes modulo Kyber's
      inherent reject-path variance. New
      `audit_360_failure_modes_collapse_to_single_error` test
      asserts that two distinct failure causes (tampered shares
      → seed-or-decap failure vs. wrong-keygen shares → ss
      mismatch) return byte-identical error values. Existing
      `tampered_mac_byte_fails_verification` updated to expect
      the collapsed error. 33 threshold tests pass; 107
      crypto tests; mempool + node tests green.
      `crates/crypto/src/threshold.rs:537-549`. Collapse both to a
      single opaque `"threshold decryption failed"` error.

### WASM crypto crate

- [x] 361 — `⚠` **`generateKeypair` returns secret key as JSON
      hex.** **SHIPPED.** Both halves of the audit:
      1. `generateKeypair` got a stern doc-comment block calling
         out the JS-heap-retention vector (dev-tools, extensions,
         crash dumps, accidental `JSON.stringify` exposure) and
         pointing wallet authors at the new opaque-handle path.
         The legacy API is preserved for the encrypt-to-disk
         keystore flow that genuinely needs the SK string for
         the brief encrypt-discard window.
      2. New opaque-handle API: `generateKeypairHandle` returns
         JSON with `publicKey`, `address`, and an opaque `u32`
         `handle`. The SK lives inside this crate's WASM heap in
         a process-global `OnceLock<Mutex<KeyTable>>` (single-
         threaded wasm32, so uncontended). Companion APIs:
         `signMessageWithHandle(handle, msg_hex)`,
         `signTransactionWithHandle(tx_json, handle)`, and
         `dropKeypair(handle)`. Drop calls `HashMap::remove` →
         `Drop::drop` → the `ZeroizeOnDrop` impl on
         `FalconSecretKey` (audit 358) overwrites the secret
         bytes in place. SK bytes never enter the JS heap on
         this path, so they can't be `JSON.stringify`'d, can't
         be read by content-script extensions, and can't survive
         in a crash dump as a recoverable hex string. Handle 0 is
         reserved as "no handle"; handles never wrap (u32 max
         exhausts after 4G keypairs in a single session — emits
         `Err`). New 4 audit-361 tests pin: handle JSON does not
         expose SK under any plausible field name, sign-with-
         handle produces a FALCON sig that verifies against the
         returned pk, drop is idempotent (true → false), and
         multiple handles are independent (different keys, drop
         A leaves B alive).
- [x] 362 — `⚠` **WASM defaults `chainId = 31337` when missing.**
      **SHIPPED.** All three sites that previously did
      `unwrap_or(31337)` now do
      `.ok_or_else(|| JsValue::from_str("audit 362: chainId is
      required..."))`: `compute_tx_hash` (plain tx hash),
      `serialize_tx` (plain tx wire format), and
      `build_raw_encrypted_tx_wasm` (encrypted-tx flow). Pre-fix a
      wallet that omitted `chainId` from the JSON params silently
      bound the tx to chain 31337 — replayable onto whatever
      production chain happened to share the default once one
      ships, and (more pressingly) onto devnet right now if a
      tester accidentally re-pointed their wallet. Mirrors audit
      302/303 on the RPC side (which made `chainId` resolution
      strict at every entry point). New 1 audit-362 test pins
      that the same tx with two different `chainId`s produces two
      different hashes — the actual cross-chain replay
      protection. Negative-path testing (missing chainId →
      JsValue Err) is exercised by the `pyde-ts-sdk` jest suite,
      consistent with the other negative-path tests in this
      module that can't run natively because `panic = "abort"`
      aborts on `wasm_bindgen` Err returns.

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
- [x] 374 — `StateOverlay::insert` / `into_writes` use
      `HashMap<Key, Vec<u8>>` (non-deterministic order in
      collection / undo logs). `crates/state/src/smt.rs:225-227`.
      Switch to `BTreeMap`.
      **SHIPPED.** Two coordinated changes covering the full
      gap, not just the audit's cited line:
      (1) `StateOverlay::writes` is now `BTreeMap<Key, Vec<u8>>`,
      so `into_writes()` and `into_writes_with_undo()` iterate
      in `Key` order regardless of insertion order.
      (2) The cross-group undo merge in
      `block_processor.rs:374-377` (the parallel-execution
      scheduler that combines per-rayon-group undo entries)
      is also a `BTreeMap<Key, UndoEntry>`. Pre-fix this was
      a HashMap that the audit didn't list — it would have
      preserved the bug at the merge layer even with a
      BTreeMap overlay. JMT (the canonical merkle tree)
      sorts its inputs internally via `BTreeMap::collect` at
      `jmt-0.12.0/src/tree.rs:98-100`, so the block hash
      / state root were always deterministic regardless;
      this fix makes the *undo log* — which feeds
      `revert_to` for reorg rollback and would diverge
      across honest validators if persisted or hashed —
      byte-identical too.
- [x] 375 — `SmtValue::to_h256` collision: empty vec returns
      `H256::zero()` — same as absent leaf. `crates/state/src/smt.rs:73-85`.
      Either reject empty-byte writes at the storage-trie boundary
      or document the tombstone semantics.
      **SHIPPED-IN-JMT.** The audit was written against the
      legacy SMT path. The production canonical merkle tree
      pivoted to JMT (`PersistentJMT` per `state_manager.rs:19`),
      and the JMT write path at `jmt_store.rs:563-564` already
      maps empty-vec writes to `None` (a JMT tombstone),
      which is encoded distinctly from `Some(value)` in the
      tree — no collision. The legacy `SmtValue::to_h256` only
      feeds `crates/state/src/witness.rs::verify_witnesses`,
      and that function has zero production callers (covered
      by audit 373's dead-code cleanup queue). No code change
      needed for production correctness.
- [x] 376 — Unbounded `gas_used_total += ...` in 22 sites in PVM.
      **SHIPPED.** Every `gas_used_total +=` site now uses
      `checked_add(..).ok_or(Trap::OutOfGas)?`. Mirrors the
      Memcpy pattern from audit 215. Per-instruction baseline
      cost (line ~449), Poseidon dynamic gas, Sload/Sstore cold-
      surcharge + dynamic gas, Log dynamic gas, MerkleVerify
      dynamic gas + page-gas drain, VerifySig early-return page-
      gas drain, page-gas drain at end of step(), CallExt
      child-gas charge, Create constructor + per-byte-code
      charges — all 16 distinct sites (audit's "22 sites" count
      included repeats of the cold-surcharge pattern across
      Sload/Sloadb/Sstoreb modes). Pre-fix a hostile contract
      crafting an execution path with cumulative dynamic gas
      large enough to wrap u64::MAX past `gas_limit` would
      silently restart its budget — accumulator wraps to a small
      value, the post-add `> gas_limit` check passes, contract
      keeps running with effectively infinite gas. Reachable in
      principle (LOG / KECCAK / CALL / CREATE all add millions
      per call) but not practically observed pre-fix because the
      attacker would need to control gas budget in addition. New
      `audit_376_per_instruction_gas_overflow_cannot_bypass_oog`
      and `audit_376_call_ext_charge_cannot_bypass_oog`
      regression tests pin the fix.
- [x] 377 — VerifySig / MerkleVerify early-return paths skip OOG
      check after page-gas drain. `crates/pvm/src/vm.rs:1128-1132,
      1140-1144, 1347-1355`.
      **SHIPPED.** Three early-return arms (VerifySig invalid pubkey,
      VerifySig invalid signature, MerkleVerify proof_len > 256) drain
      `page_gas_used` into `gas_used_total` via `checked_add` but
      pre-fix did not re-check `gas_limit` before returning
      `Ok(None)`. Per-instruction baseline at the top of the next
      `step()` would catch the over-budget condition, but only after
      one extra instruction's grace — the contract observably ran
      past its declared gas budget. Post-fix mirrors the canonical
      end-of-step drain (vm.rs:1476-1487): the OOG check runs
      immediately after the drain and traps inside the early-return.
      Three regression tests
      (`audit_377_verifysig_invalid_pk_traps_during_drain`,
      `audit_377_verifysig_invalid_sig_traps_during_drain`,
      `audit_377_merkle_verify_overdeep_proof_traps_during_drain`)
      seed `gas_used_total` and inject `page_gas_used` so the drain
      crosses the limit, and assert the trap fires inside the
      VerifySig/MerkleVerify step rather than the next.
- [x] 378 — `len: u64 → as u32` truncation in checked_read_slice /
      checked_write_slice callers (Poseidon, SstoreB, Log,
      VerifySig, MerkleVerify, do_ext_call, do_create). Mirror the
      audit-215 Memcpy pre-cast bound check at every call site.
      **SHIPPED.** Centralized fix in `Memory::checked_read_slice` and
      `Memory::checked_write_slice` themselves: reject `len > MEMORY_SIZE`
      before the `len as u32` cast in `check_access` (which would
      silently truncate) and before `read_slice`'s `vec![0u8; len]`
      allocates a host-side buffer. Pre-fix, a guest passing
      `len = 0x1_0000_0000` would see the bounds check pass (truncated
      to 0) while the host allocated 4 GiB+ — combined with
      `panic = "abort"`, that's a host-OOM DoS. Centralizing at the
      bottleneck covers all 33 call sites (Poseidon, SstoreB, Log,
      VerifySig, MerkleVerify, do_ext_call, do_create, plus aot/host,
      pyde-dev cheatcodes/script, etc.) without per-site churn. Four
      regression tests
      (`audit_378_checked_read_slice_rejects_oversize_len`,
      `audit_378_checked_read_slice_rejects_u32_overflow_len`,
      `audit_378_checked_read_slice_accepts_max_in_bounds_len`,
      `audit_378_checked_write_slice_rejects_oversize_data`) pin the
      reject + boundary-accept behavior. The pre-existing audit-215
      Memcpy pre-cast check (`vm.rs:1370-1374`) is now redundant with
      the centralized check but kept as a defense-in-depth.
- [x] 379 — CREATE deterministic address has no nonce —
      front-runnable address grabbing. **SHIPPED.** Pre-fix the
      PVM CREATE opcode derived its child address as
      `Poseidon2(self_address || init_code)` with no per-CREATE
      entropy. A front-runner who saw a pending tx (or just
      guessed the init code) could compute the resulting address
      and deploy malicious code there before the victim's tx
      landed. Post-fix the derivation is
      `Poseidon2(self_address || tx_hash || create_count ||
      init_code)`:
      * `tx_hash` from `ExecutionContext` ensures every signed
        tx produces a unique address even with identical caller
        + init_code; a front-runner's tx (different signed bytes
        → different hash) cannot land at the victim's predicted
        address.
      * `create_count` from a new per-caller `HashMap<Address,
        u64>` advances on each CREATE within the tx so back-to-
        back CREATEs from the same contract land at distinct
        addresses (pre-fix the second one tripped the
        `contracts.contains_key` collision guard and trapped,
        forcing contract authors to vary init_code unnecessarily).
      CREATE2 is intentionally untouched — its user-provided
      salt is the front-runner protection by design (callers
      explicitly opt in to predictable addressing). New 2
      audit-379 tests pin: tx_hash variation produces distinct
      addresses; back-to-back CREATEs in the same VM yield
      distinct addresses.
- [ ] 380 — Heartbeat 400ms (matches slot time). Bump to 1 s once
      peer scoring + peer-book restoration stabilize the mesh
      post-restart. `crates/net/src/node.rs:118`.
- [x] 381 — `propagation::rand_nonce` uses SystemTime, not CSPRNG.
      `crates/net/src/propagation.rs:117-124`. Switch to
      `getrandom::getrandom` (already a dep).
      **SHIPPED.** Now reads 8 bytes from `getrandom::getrandom`
      and panics on OS CSPRNG failure (unrecoverable for
      consensus security). Pre-fix the short-ID nonce was
      trivially predictable from a wall-clock estimate; an
      off-path peer could pre-compute a tx whose short ID
      collides with another peer's tx, forcing fallback
      `GetBlockTxs` round-trips and amplifying compact-block
      bandwidth.
- [x] 382 — Faucet `signing_lock` doesn't bound queue length;
      semaphore + 503 on saturation. `crates/node/src/faucet.rs:430-460`.
      **SHIPPED.** Added `signing_capacity:
      Arc<tokio::sync::Semaphore>` with `MAX_FAUCET_QUEUE = 16`
      permits alongside the existing `signing_lock`. Each
      handler calls `try_acquire_owned` before waiting on the
      lock; if no permit is available the request is shed
      with HTTP 503 (`{"error":"faucet queue saturated, retry
      shortly"}`). Worst-case waiter count is bounded to 16
      → single-digit MB of queued tokio-task RAM under DoS,
      vs unbounded growth pre-fix.
- [x] 383 — `pyde testnet --chain-id 1` not refused.
      `crates/node/src/genesis.rs:845-1368`.
      **SHIPPED.** `generate_testnet` now rejects
      `chain_id == MAINNET_CHAIN_ID (1)` with an explicit
      error directing the operator to the canonical testnet
      id (7331) or the dedicated mainnet genesis ceremony.
      Pre-fix an operator could silently mint a fake mainnet
      genesis with arbitrary validator keys + a faucet pre-
      funded address; anything signed against that genesis
      carried the real mainnet `chain_id` and could be
      replayed onto mainnet later. Two existing tests updated
      to use `TESTNET_CHAIN_ID` instead of the hardcoded `1`,
      plus a new regression test
      (`generate_testnet_refuses_mainnet_chain_id_audit_383`)
      pins the refusal contract.
- [x] 384 — Mempool `EncryptedTx` `add()` (structural-only) accepts
      sig length [500, 1000] — verify mainnet path always takes
      `Verify` or `Reject`, never `StructuralOnly`.
      **SHIPPED.** The `encrypted_tx_ingest_policy` function in
      `rpc.rs:1867` already mapped `(None, chain_id != 31337)` to
      `Reject`, but the gossip ingress in `node.rs:1587` open-coded
      the same `(sender_pk_opt, chain_id)` match inline — three
      ingress sites, two implementations. A future change to the
      devnet rule that updated only the RPC paths would silently
      re-open the structural-only window on mainnet through gossip.
      Fix promotes `EncryptedTxIngestPolicy` and
      `encrypted_tx_ingest_policy` to `pub(crate)` and refactors
      the gossip ingress to call the same function — single source
      of truth across all three ingress sites. Adds
      `ingest_policy_structural_only_is_devnet_exclusive` test that
      sweeps `chain_id` over `[0, 10_000]` plus the canonical
      mainnet/testnet/edge values (1, 7331, 100_000, 1_000_000,
      u64::MAX) and asserts `StructuralOnly` is never returned for
      `None` sender_pk except at chain_id 31337.
- [x] 385 — `prune_expired` clears + rebuilds `seen_hashes` on
      eviction. `crates/mempool/src/pool.rs:443-451`. Track removed
      hashes incrementally.
      **SHIPPED.** Pre-fix the function cleared `seen_hashes`,
      iterated every retained tx to recompute its `EncryptedTx::hash()`
      (each hash = two Poseidon2 invocations + ciphertext-to-bytes
      copy), collected into a fresh `HashSet`, and reassigned —
      O(N) work even when only a single tx had expired. Post-fix
      collects the expired hashes (O(K)), early-returns if none,
      then incrementally `seen_hashes.remove` /
      `first_seen_slot.remove` / `release_sender_slot` for each
      expired entry — O(K) total, where K is the per-prune
      eviction count. On a steady-state mempool with thousands of
      valid txs and one expired entry per block, this drops the
      per-prune cost from "Poseidon2-bound full sweep" to "K hash
      lookups." Two regression tests
      (`audit_385_prune_keeps_seen_hashes_consistent` and
      `audit_385_prune_no_op_when_nothing_expired`) pin the dedup
      invariant: retained hashes stay in `seen_hashes` and
      `first_seen_slot`, expired ones don't, and a no-op prune
      doesn't mutate either map.
- [x] 386 — Encrypted nonce-window check at RPC ingress can
      overflow on near-`u64::MAX` base. `crates/node/src/rpc.rs:1365`,
      `crates/account/src/nonce.rs:53`. Use `checked_add`.
      **SHIPPED.** Four arithmetic sites converted to overflow-safe
      forms: `NonceState::validate` (window-end), `NonceState::advance`
      (base increment), `NonceState::max_nonce` (display upper bound),
      and `send_raw_encrypted_transaction` ingress check. Pre-fix, a
      base near `u64::MAX` would panic in debug or wrap in release; the
      wrap caused valid nonces to be rejected and bogus ones near the
      wrap boundary to be accepted. Post-fix semantics: when the math
      overflows, the window naturally clamps at `u64::MAX` (no nonces
      exist beyond it), so every nonce in `[base, u64::MAX]` is
      in-window and the upper-bound check is skipped. The `advance`
      loop now checks the addition *before* shifting the bit out of
      `used` — otherwise it would consume the slot from the bitmap
      without moving `base`, leaving the same nonce reusable. Four
      regression tests cover `validate` at u64::MAX-near and exact
      base, `advance` at u64::MAX, and `max_nonce` saturation.
- [x] 387 — `prompt_password` echoes input.
      `crates/pyde-dev/src/wallet.rs:291-298`. Use `rpassword`.
      **SHIPPED.** Switched to `rpassword::prompt_password`,
      which puts the TTY into no-echo mode for the duration
      of the read. Pre-fix the wallet passphrase rendered to
      the screen as it was typed — anyone over the operator's
      shoulder, on a shared screen, or scrubbing a terminal
      recording could recover the passphrase verbatim.
- [x] 388 — `is_localhost` uses `String::contains`.
      `crates/pyde-dev/src/signer.rs:178-184`. Parse with
      `url::Url::host_str` and exact-match.
      **SHIPPED.** Now parses with `url::Url::parse` and
      exact-matches the host component against the loopback
      set `{localhost, 127.0.0.1, 0.0.0.0, [::1], ::1}`.
      Pre-fix `String::contains("localhost")` matched
      attacker URLs like `http://attacker.example/?ref=localhost`
      or `http://127.0.0.1.attacker.example/`, which would
      unlock the devnet-auto-key fallback against an
      attacker-controlled RPC.
- [x] 389 — `account::auth::validate_signature` for MultiSig
      doesn't dedup keys. `crates/account/src/auth.rs:60-94`.
      Cross-with #304 fix: invariant check at construction.
      **SHIPPED.** Two coordinated changes:
      (1) `validate_signature` now tracks which public-key
      bytes already counted toward the quorum and skips
      subsequent positions whose key is a repeat. With
      positional matching, a `keys: vec![k1, k1, k2]` slate
      previously let a single `(k1, sig)` pair satisfy two
      threshold positions — collapsing 2-of-3 into 1-of-1
      whenever k1 appeared twice. (2) `AuthKeys::from_bytes`
      now refuses to deserialize a `MultiSig` variant whose
      key list contains duplicates, so persisted state can
      never carry an unsafe slate. Two regression tests
      pinned (`multisig_duplicate_key_does_not_double_credit_audit_389`,
      `authkeys_from_bytes_rejects_duplicate_multisig_keys_audit_389`).
- [x] 390 — `NonceState::from_bytes` silently returns
      `Self::new()` on invalid input; should be `Option<Self>`.
      `crates/account/src/nonce.rs:100-113`.
      **SHIPPED.** Pre-fix the function silently returned
      `Self::new()` for inputs shorter than 10 bytes — meaning a
      truncated SMT read or a corrupted nonce-key value would
      roll the sender's nonce window back to `base = 0` rather
      than surface as a parse failure. An attacker who corrupted
      a nonce-key entry (or a node that crashed mid-write) could
      then silently replay every nonce up to the original base.
      Post-fix returns `Option<Self>`, returning `None` for
      `data.len() < 10`. Updated all 9 call sites: `pipeline.rs`
      `load_nonce` collapses None into the same default-on-missing
      shape (the corruption then surfaces downstream when
      `validate_nonce` rejects the tx); the three RPC sites in
      `rpc.rs` also collapse to `base = 0` (consistent with the
      missing-key case for fresh EOAs); the five test/bench
      sites use `.expect(...)` since the canonical store
      round-trips 10-byte values. Two regression tests
      (`audit_390_from_bytes_short_returns_none`,
      `audit_390_from_bytes_at_or_above_10_succeeds`) pin the
      reject-on-short / accept-on-≥10 contract.
- [x] 391 — Goldilocks bias: `gl(u64::from_le_bytes(...))` reduces
      mod p, biasing values in `[p, 2^64)`.
      `crates/crypto/src/threshold.rs:55, 199, 238, 381, 484, 653,
      822`. Use rejection sampling for randomness paths; document
      the silent-remap on Kyber-seed reconstruction.
      **SHIPPED.** Pre-fix `gl()` silently reduced any input ≥ p
      (`p = 2^64 - 2^32 + 1`) by subtracting p, making values in
      `[0, 2^32)` ≈ 2x more likely than values in `[2^32, p)` for
      hash-derived inputs. Post-fix categorizes the seven cited
      sites and applies the appropriate fix per category:
      *(a) Randomness paths* — `random_goldilocks` (Shamir
      polynomial coefficients) and `derive_blinding_mask`
      (per-share unblinding mask) now rejection-sample by
      re-hashing with an attempt counter folded into the hash
      input. Per-attempt rejection is `(2^32 - 1) / 2^64 ≈ 2^-32`,
      so the loop terminates after one attempt with overwhelming
      probability. Determinism in the public arguments is
      preserved (cross-validator agreement on shares + masks).
      *(b) Kyber-seed reconstruction* — `threshold_keygen`
      keeps the silent remap (rejection-sampling there would
      mean re-running Kyber keygen, breaking the protocol's
      determinism on the produced sk). The non-injective
      round-trip is now documented inline with collision
      probability bounds (≈ 2^-29 per keygen) and the operator
      recovery path (re-keygen on first failed decap).
      *(c) Deserialization paths* — `KeyShare::from_bytes`,
      `DecryptionShare::from_bytes`, and
      `RefreshContribution::from_bytes` keep the silent remap
      (honest serialization is canonical via `gl_to_u64()`; the
      remap only affects malformed inputs, which the downstream
      MAC catches). Documented inline. Three regression tests
      (`audit_391_random_goldilocks_is_canonical_and_deterministic`,
      `audit_391_derive_blinding_mask_is_canonical_and_deterministic`,
      `audit_391_threshold_roundtrip_after_rejection_sampling`)
      pin the canonical-output, determinism, and end-to-end
      decryption invariants.
- [x] 392 — `Hash256::from_slice` silently truncates/pads.
      `crates/crypto/src/hash.rs:24-29`. Return `Option<Hash256>`.
      **SHIPPED.** Pre-fix the function silently zero-padded short
      slices and silently truncated long ones — both behaviors hide
      programming bugs (a 31-byte hash compared equal to a real
      `Hash256(...)` whose 32nd byte was zero, and a 33-byte payload
      had its trailing byte dropped without surfacing the size
      mismatch). Post-fix returns `Option<Self>`, returning `None`
      for any length other than exactly 32. Updated all three
      callers in `MerkleVerify` (vm.rs:1485, 1494, 1500) to
      `.ok_or(Trap::MemoryFault)?` — defensive since each upstream
      `checked_read_slice(_, 32)` call always produces a 32-byte
      buffer, so `None` here is a host invariant violation rather
      than a guest-reachable case. Three regression tests
      (`from_slice_exact_length`,
      `audit_392_from_slice_short_returns_none`,
      `audit_392_from_slice_long_returns_none`) pin the
      reject-on-mismatch contract at slice boundaries.
- [x] 393 — VRF input domain reuse: `VRF_DOMAIN_OUTPUT` used for
      both `sk_input` and `output_input`.
      `crates/crypto/src/vrf.rs:15-16, 49-62`. Split into
      `VRF_FINGERPRINT_DOMAIN` and `VRF_OUTPUT_DOMAIN`.
      **SHIPPED.** `compute_vrf_output` now derives the
      sk-fingerprint hash under `VRF_FINGERPRINT_DOMAIN` =
      `b"pyde-vrf-sk-fingerprint-v1"` and the output hash under
      `VRF_OUTPUT_DOMAIN` = `b"pyde-vrf-output-v1"`. Standard
      hash-domain-separation hygiene — prevents any future
      analysis from confusing the two distinct cryptographic
      roles (key-binding vs. output derivation) by virtue of
      sharing a hash tag. KAT vectors re-pinned (the output
      changes mechanically because the fingerprint hash input
      changes, and the FALCON proof signs `pk || input ||
      output` so it changes too). 114 crypto tests pass + 141
      consensus tests pass against the new vectors.
- [x] 394 — `falcon_batch_verify` is a sequential `.all(...)`,
      not algebraic batch verification.
      `crates/crypto/src/falcon.rs:118-122`. Rename to
      `falcon_verify_all` until upstream supports a true batch
      API, OR wire to the upstream batch path if available.
      **SHIPPED.** Audit's two-option recommendation: rename or
      wire to upstream. Upstream `falcon-rs` 0.2.x (the version
      we depend on) has no batch API (verified by grepping
      `~/.cargo/registry/src/.../falcon-rs-0.2.4` for any
      `batch`/`verify_batch` symbol — zero hits). Renamed
      `falcon_batch_verify` → `falcon_verify_all` to communicate
      the actual semantics: a `forall` short-circuit over
      `falcon_verify`, NOT an algebraic batch scheme that
      amortizes work across signatures (Ed25519/BLS-style).
      Updated all callers (the standalone `falcon_bench` and
      two unit tests). The `pyde-crypto` crate is `no_std`, so
      rayon-parallelism would require a separate `std`-feature
      gate; deferred. Tests `verify_all_with_all_valid_returns_true`
      and `verify_all_with_one_invalid_returns_false` (renamed
      from the old `batch_verify_*` names) still pin behavior.
- [x] 395 — `validator.key` regeneration on missing file silently
      re-keys the validator. `crates/node/src/node.rs:5181-5224`.
      Refuse on non-devnet `chain_id` unless explicit
      `--init-validator-key` flag.
      **SHIPPED.** `load_validator_identity` now takes
      `chain_id` and refuses to mint a fresh keypair when
      the file is missing on any non-devnet chain unless the
      operator explicitly opts in via
      `PYDE_INIT_VALIDATOR_KEY=1`. Pre-fix, a deleted /
      mis-restored / never-provisioned `validator.key` would
      silently mint a NEW keypair under a different identity —
      the chain saw a different validator with a different
      derived address that couldn't sign on behalf of the
      original stake position, quietly degrading the network
      to N-1 effective validators with no log signal.
      Devnet (`chain_id == 31337`) keeps the silent-generate
      ergonomics for laptop test infra.
- [x] 400 — Slot clocks diverge by per-node startup wall-clock when
      operators boot apart. `crates/node/src/genesis.rs:972`,
      `crates/node/src/node.rs:846-869`.
      **SHIPPED.** Surfaced by walking `docs/testnet-bringup.md`
      end-to-end with a deliberate operator stagger. Pre-fix the
      generator wrote `timestamp = 0` into `genesis.toml`, and
      `node.rs`'s fresh-start branch returned `slot_clock_anchor_ms
      = 0`, so `SlotClock::with_block_time` fell back to anchoring
      slot 0 at each node's per-host `Instant::now()`. A 4-minute
      stagger between operators became ~600 slots of permanent skew:
      each node's `current_slot()` walked from a different
      wall-clock origin, votes covered different
      `(slot, block_hash)` tuples than what neighbors expected, the
      "invalid vote signature" path fired hundreds of times per
      second, and the chain silently stalled even though every node
      individually looked healthy (peers connected, threshold key
      loaded, RPC up). **Real-world severity**: any public testnet
      where operators don't start within ~ms of each other would
      silently fail to make progress — the runbook does not
      mandate that. Post-fix the generator stamps
      `genesis.timestamp = current_time_ms()`, every node anchors
      its slot_clock to that absolute Unix-ms (regardless of
      individual boot time), and `current_slot()` is the same
      function of wall-clock across the network. Verified on a
      4-validator local run with a 60-second deliberate stagger:
      pre-fix saw 670+ "invalid vote signature" warnings and a
      stuck chain at block 0; post-fix all four nodes anchored
      identically (`slot_clock_anchor_ms=1777952611407`) and
      produced 2.5 blocks/sec in lockstep with zero signature
      errors. Adds `audit_400_generator_stamps_genesis_timestamp`
      regression in the generator and an operational
      "slot_clock initialized" info-log on every node startup so
      operators can quickly confirm their anchor matches the
      coordinator-supplied genesis timestamp.
- [x] 401 — Encrypted-tx pipeline serializes the per-block FALCON
      verify + threshold decrypt loops.
      `crates/node/src/block_processor.rs:1031-1061`,
      `crates/mempool/src/decryption.rs:145-151`. Convert to
      `rayon::par_iter`.
      **SHIPPED.** Surfaced while reasoning about the encrypted-TPS
      ceiling. Pre-fix the per-block decrypt+apply path was three
      sequential loops (FALCON re-verify in
      `try_decrypt_and_execute`, `decrypt_all` over per-tx
      Lagrange + Kyber decap, and `execute_transaction` over a
      `StateOverlay`). Per-tx FALCON-512 verify is ~5–10 ms,
      Lagrange + Kyber decap is ~3 ms; at the laptop ceiling
      `MAX_ENCRYPTED_TXS_PER_BLOCK = 100` the sequential pipeline
      consumed ~800 ms — already over the 400 ms slot budget.
      Post-fix the FALCON-verify loop and `decrypt_all` are
      `rayon::par_iter` over per-tx-independent state (each tx
      has its own ciphertext + share vector + sender key);
      8-core laptop fits the same 100-tx batch in ~50 ms each
      phase, leaving the slot's 400 ms QC deadline with comfortable
      headroom for state apply (still sequential pending Phase 3
      access-list integration). The wider win is on dedicated
      server cores where `MAX_ENCRYPTED_TXS_PER_BLOCK` can safely
      rise toward the 128-share wire-format bound, putting
      encrypted-TPS at ~500-1000 once Phase 3 lands. All 77
      mempool tests + 317 node tests + the encrypted-path loadgen
      (30 TPS / 60s / 0 errors / 100% inclusion) pass on the new
      code — sequential vs parallel decrypt is observably
      identical to the consensus / sync paths. Phase 3 (parallel
      state apply via the access-list scheduler the plaintext
      path already runs) is tracked as a follow-up; it's the
      remaining 50–100 ms of the per-block budget.
- [x] 402 — Chain liveness fails at epoch boundary under
      sustained load. Caught by 1h soak test (`loadgen_soak.rs`).
      Reproduces deterministically: chain produces blocks
      cleanly for ~6.5 min then wedges at slot 999/1000 (= one
      EPOCH_LENGTH = 1000-slot boundary). Two coupled failures:
      (a) `failed to create vote slot=1000 error="invalid
      qc_previous: signature verification failed"` — the new
      committee verifies the block-1000 `qc_previous` (which
      signs slot 999) against NEW-epoch committee keys, but
      slot 999's QC was signed by the OLD committee → sig
      verification fails → no vote created → no QC for slot
      1000. (b) `invalid VRF proof from proposer slot=1000`
      — VRF proof for the new-epoch proposer election uses
      epoch-2 randomness (just installed by `epoch randomness
      updated epoch=2`), but the proposer's VRF was produced
      against epoch-1 randomness. Both are the same class of
      bug: epoch-transition state desync. Once the chain
      misses slot 1000's QC, every subsequent slot inherits
      the same `qc_previous` problem and the chain never
      recovers. Fix path: keep OLD-epoch committee keys +
      randomness available for at least one slot past the
      boundary, and have `verify_qc_previous` /
      `verify_vrf` use the epoch context of the slot being
      verified (not the validator's current-epoch context).
      Diagnostic dumps from a 9-min repro live at
      `/tmp/pyde-soak-node-{0..3}.log` (~500 MB each); search
      for "invalid qc_previous" or "invalid VRF proof from
      proposer". This is the gating bug for testnet launch
      under sustained traffic — short-window loadgens
      (<EPOCH_LENGTH × block_time = 400 s) miss it
      entirely, and we shipped 18 PRs of audit fixes before
      the 1-hour soak surfaced this in 7 minutes.
      **SHIPPED.** Three coordinated changes in
      `crates/node/src/validator.rs` + `node.rs`:
      (1) New `prev_committee_keys`, `prev_epoch_randomness`,
      `current_epoch`, and `next_epoch_randomness` fields on
      `ConsensusEngine`. Boundary block verification now
      consults the prior-epoch caches when `qc_previous.slot`
      / proposal slot belong to the just-finished epoch.
      (2) New `rotate_to_epoch(new_epoch, new_keys)` method:
      atomically saves outgoing committee keys + randomness
      into the prior caches and swaps the buffered
      `next_epoch_randomness` (written by `on_randomness_share`
      during the prior epoch) into `epoch_randomness` —
      eliminating the proposer/verifier randomness drift that
      wedged slot 1000 in the soak. The boundary handler in
      `node.rs:2156` now calls `rotate_to_epoch` instead of
      bare `set_committee`. (3) New helpers
      `committee_keys_for_slot(slot)` and
      `epoch_randomness_for_slot(slot)` return the right
      key set / randomness for whichever epoch the slot
      belongs to; the `create_vote` callsite at
      `validator.rs::on_proposal` and the VRF verify at
      `validate_block_header_internal` use them. Verified by
      re-running the 9-min repro: pre-fix the chain stuck at
      slot 998 forever; post-fix the chain crossed the
      boundary and reached slot 1515 cleanly with QCs
      forming at every slot in the new epoch.
- [x] 403 — Epoch randomness combine is non-deterministic across the
      committee. Surfaced after audit 402 unblocked the slot 1000
      boundary: longer 1h soak runs wedged at the *next* boundary
      they happened to hit (slot 1999 in one run, slot 2999 in
      another) with no `invalid VRF` / `qc_previous` errors. Per-node
      log dumps showed two validators reporting `epoch=N
      randomness=088436b4…` and the other two reporting `epoch=N
      randomness=e3e4b11f…` for the same epoch — split-brain. Cause:
      `on_randomness_share` finalized as soon as the dynamic threshold
      (3-of-4 in devnet) was hit, but gossipsub delivers shares in
      different orders across validators, so two nodes that saw
      first {0,1,2} vs first {0,1,3} hashed those two different
      sets to two different randomness bytes. Once randomness
      diverged, half the committee computed VRF/proposals against
      one value and the other half against the other — neither
      side reached a 3-vote quorum and the chain stalled at the
      first slot of the new epoch. Latent in audit 402's repro
      because at the slot 1000 boundary epoch_randomness stays
      `[0u8; 32]` (no shares are collected for epoch 1), so no
      divergence; the bug only fires on the SECOND boundary
      onward when fresh randomness lands. Diagnostic dumps live
      at `/tmp/pyde-soak-node-{0..3}.log`; grep `epoch randomness
      updated` for the divergent hex on the wedge run.
      **SHIPPED.** Three coordinated changes:
      (1) `combine_shares_with_threshold` now selects the
      canonical subset — the `threshold` shares with the LOWEST
      `validator_index` values — instead of combining every share
      received. So two nodes that received different super-sets
      converge on the same sub-set provided each has the
      canonical members' shares.
      (2) New `try_finalize_randomness_on_slot(slot)` on
      `ValidatorEngine`. Driven by the node slot tick. Fires when
      either (a) all `n` shares received, or (b) slot has crossed
      `randomness_aggregation_trigger_slot =
      collection_start_slot + RANDOMNESS_AGGREGATION_DELAY_SLOTS`
      (20 slots ≈ 8s — orders of magnitude over realistic gossip
      latency, still ~2% of an epoch). Same pattern as
      `try_aggregate_reshare_on_slot` for cross-committee
      resharing.
      (3) `on_randomness_share` now buffers only and returns
      `bool` — no race-against-gossip finalize. Both call paths
      converge through the deterministic combine. Verified by
      25-min soak: chain crosses slots 1000/2000/3000 cleanly to
      slot 3710, all 4 nodes derive byte-identical randomness
      for epochs 2/3/4 (`e1b80a7c…`, `337785f7…`, `3a93693e…`).
      A 1h follow-up soak confirms the same across boundaries
      4–6.
- [x] 404 — `otic::compile_all` silently bypasses the frontend
      (resolve + typecheck + safety), so production callers and
      test fixtures that didn't run the frontend separately got
      a "lex + parse + lower + codegen" pipeline that accepted
      contracts the strict typechecker rejects. Surfaced while
      writing the bombard suite for a multi-laptop network
      stress test: the same `SUITE_SRC` that compiled cleanly
      via `compile_all` (the path the local soak takes) failed
      under `pyde-dev build` with two distinct errors —
      "signed integer type `i64` is not supported (audit 354)"
      and "address() expects 'self' or an Address, found
      Helper". Audit 354 already documents the codegen issue
      (no signed-int ISA opcodes; `<`, `>`, `/`, `%`, `>>` on
      i64/i128/i256 silently produce wrong results), and the
      typechecker rejects those types at the AST level — but
      the lax `compile_all` path skipped the typechecker, so
      `loadgen_soak.rs` happily compiled `signed_val: i64` +
      `checked_signed(delta: i64)` for hours of soak runtime
      while reporting `ok=735 err=0` for the bucket against
      bytecode whose comparisons were silently broken
      (additions wrap correctly in two's complement; the
      `assert!(self.signed_val > -1000)` line ran an unsigned
      comparison that gave the right answer by coincidence
      for the test's input range). The same bypass also let
      `pyde-dev script` (the production developer toolchain)
      compile scripts with undefined identifiers, multi-
      constructor contracts, view functions that write state,
      and audit-356 selector collisions — all of which the
      typechecker / safety pass would have caught.

      Production leak surface: `crates/pyde-dev/src/script.rs`
      called `compile_all` without first running the frontend.
      Every other production caller (`pyde-dev build`, `otic`
      CLI) explicitly ran the frontend first.

      **SHIPPED.** Three coordinated changes:

      (1) `crates/otic/src/lib.rs` — split the public API.
      `compile_all_unchecked` retains the old lex+parse+
      lower+codegen behaviour for compiler-internal tests
      (`crates/otic/src/codegen.rs` codegen self-tests, AOT
      cache tests, `pyde-dev build` and `otic` CLI which run
      the frontend explicitly first). The new strict
      `compile_all` runs lex → parse → resolve → typecheck →
      safety → lower → codegen and returns
      `Result<Vec<...>, String>` with formatted diagnostics
      on any frontend failure. Production callers that don't
      separately run the frontend now route through this
      path.

      (2) `crates/pyde-dev/src/script.rs` — migrated to the
      strict `compile_all`. Bubbles diagnostics up as a
      formatted error for the operator. Pre-fix this was the
      only production toolchain that silently accepted
      audit-354 violations and selector collisions.

      (3) `crates/node/tests/loadgen_soak.rs` — SUITE_SRC
      cleaned of patterns the strict typechecker rejects.
      `signed_val: i64` + `checked_signed(delta: i64)` are
      gone (broken arithmetic per audit 354; reintroduce
      post-codegen-signed-int-support). The `Spawner.spawn()`
      method no longer captures the deployed child's address
      via `address(deploy!(Helper))` (which the strict path
      rejects); it calls `child.ping()` instead, still
      exercising CREATE → constructor → runtime install
      end-to-end. The default workload drops from 9 to 8
      buckets (no more `SignedMath`).

      Test files using `compile_all` in fixtures stayed on
      the renamed `compile_all_unchecked` (`crates/tx/src/
      pipeline.rs` test code, `crates/node/tests/*.rs`,
      `crates/aot/src/lib.rs` AOT cache tests). They probe
      chain pipeline behaviour against simple contracts that
      should pass the strict frontend; migrating each one
      individually to `compile_all` is a follow-up to
      surface any latent contract bugs in those fixtures.

      Verified by extracting the cleaned `SUITE_SRC` to a
      `pyde-dev` project and running `pyde-dev build`:
      Helper (135 instructions), MegaContract (951
      instructions), Spawner (1036 instructions), all three
      compile cleanly through the full frontend. 1714 / 1714
      workspace lib tests pass post-fix. 25-min soak confirms
      end-to-end: chain crosses boundaries 1/2/3 cleanly, all
      4 nodes derive byte-identical epoch randomness, 8/8
      workload buckets exercised, 21.1% submit err (same
      regime as the audit-403 baseline).
- [x] 405 — `address(<contract or interface handle>)` rejected
      by the strict typechecker, blocking the canonical factory
      pattern (`Spawner::spawn() -> Address` returning the
      deployed child's address). The shape compiled silently via
      the lax `compile_all_unchecked` path and produced WRONG
      bytecode: the lower pass for `address(...)` always emitted
      `BuiltinOp::AddressOfSelf` regardless of argument, so
      `let child = deploy!(Helper); address(child)` returned the
      factory's OWN address instead of the deployed child's.
      `simple_factory.oti` (the otic test suite's canonical
      factory fixture) shipped with this exact pattern; its
      `lower_simple_factory` test passed because it only checks
      that the IR is non-empty + Display doesn't panic, not that
      the emitted opcodes do the right thing.

      **SHIPPED.** Two coordinated changes:

      (1) `crates/otic/src/typecheck.rs::call` — `address(arg)`
      now accepts `Ty::Contract(_)` and `Ty::Interface(_)` in
      addition to `self`, `Ty::Address`, `Ty::Unknown`, and
      `Ty::Error`. The error message updates to
      "expects 'self', an Address, or a Contract/Interface
      handle".

      (2) `crates/otic/src/lower.rs::Expr::Call` — the
      `address(...)` arm differentiates by argument shape:
      `address(self)` still emits `BuiltinOp::AddressOfSelf`,
      but for any other argument we emit
      `Inst::Cast(dst, src, Ty::Address)`. Codegen lowers the
      Wide → Wide cast to a `Wmov` (or no-op if the register
      allocator picks `dst == src`), preserving the 32-byte
      address bits — Contract / Interface handles + Address
      all share the same wide-register layout, so the copy is
      bit-exact.

      Regression test
      `check_address_of_contract_handle_audit_405` in
      `typecheck::tests` pins the typechecker rule. The full
      otic test suite (387 unit + integration tests) is
      green post-fix. The same 25-min soak that verified
      audit 404 also verified this fix end-to-end (the
      cleaned SUITE_SRC's Spawner exercises CREATE +
      constructor + runtime install per spawn; future re-
      introduction of the canonical
      `address(deploy!(Helper))` capture will compile via
      strict).

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
