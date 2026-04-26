# 4-of-4 Validator Churn — Open Residual

`crates/node/tests/validator_churn_4_of_4.rs` is `#[ignore]`'d. This
doc explains why and what would close it, so the next engineer who
picks it up doesn't re-explore the same dead ends.

## What the test asks for

Spawn 4 validators. Warm to slot 30. For each victim 0..4:
- SIGKILL the validator
- Wait 8s
- Assert chain advanced ≥5 slots during downtime
- Restart the victim, wait for catch-up + convergence

The 4th rotation kills the **only never-restarted node** while the
other 3 are all post-restart. This is the worst case: every surviving
peer's libp2p connection state is degraded from prior rotations, and
no node has a "stable reference" to anchor mesh repair against.

## Current status (after #280 + #282 + #283)

- 3-of-4 churn (rotates 3 of 4 — realistic operator rolling-restart
  cadence): **passes solidly**.
- 4-of-4 churn (rotates all 4): **probabilistic**. Best run: 29
  vote-QCs, 10 buffered fallback proposals, 1 slot of recovery.
  Worst run: 0 slots, 0 QCs. Test threshold (≥5 slots in 8s) does
  not reliably pass.

## The 5-layer cascade

The wedge is not one bug. It's five interacting layers, all on the
critical path within a tight 8s budget:

| # | Layer | Status |
|---|-------|--------|
| 1 | Transport-level dead-peer detection | **Closed** by TCP transport (kernel FIN/RST → RTT-grade detection, vs. QUIC keepalive at 10s+). |
| 2 | Gossipsub mesh-state stickiness on disconnect | Open. libp2p removes the peer from `mesh[topic]` automatically on `FromSwarm::ConnectionClosed`, but the `peer_topics` / message-id-cache state takes a heartbeat (~400ms) to fully reflect. |
| 3 | `target_height` divergence between surviving validators | Open. When peers see different subsets of vote-QCs, their `target_height` advances at different rates → view-change msgs target different slots → quorum on any single slot becomes impossible. |
| 4 | Block body unavailability post-QC on peers | **Closed** in #283 by `synthesize empty body + apply` path — peers form QC, synthesize the body, apply locally, advance chain.head. Works for empty blocks (all blocks under load-free test conditions, also any production block with no txs). |
| 5 | Recovery-cycle timing budget | Open. One full recovery cycle (detect dead peer → reconnect → mesh re-converge → VC msg exchange → VC-QC → leader builds fallback → vote-QC → apply) is ~6-10s. Test budget is 8s for ≥5 slots — mathematically tight even when everything works. |

Layers 1 and 4 are fixed. Layers 2/3/5 compound and are inherent to
libp2p + recovery cadence under simultaneous SIGKILL.

## Tried-and-reverted (don't re-attempt these unless you have new info)

| Attempt | Outcome | Why it didn't help |
|---------|---------|-------------------|
| QUIC `keep_alive_interval=500ms`, `max_idle_timeout=2s` | Regressed to 0 slots | Aggressive QUIC ping killed healthy connections faster than mesh could repair. |
| Periodic gossipsub `unsubscribe`+`subscribe` every 2s | Mesh collapsed (`mesh_consensus = 3` → `0`) | Unsub-sub cycle is slower than gossipsub's heartbeat-driven mesh re-establishment. |
| Conditional redial gated on `!is_connected` | Regressed | Hid stale "connected but half-broken" peers from the redial path. |
| Reconnect lockout (5s, modeled on Lighthouse `temporary_banned_peers` 600s) | Convergence loop on rotation 1 | Force-disconnect → ConnectionClosed → records lockout → blocks reconnect → repeat. Lighthouse's 600s works because their peer-churn model is much slower than our test's 8s downtime. |
| `libp2p::ping::Behaviour` at 1s interval / 1.5s timeout | Killed healthy connections during startup latency | Active ping adds another failure mode without addressing the cascade. Detection speed isn't the bottleneck — the *cascade* is. |
| QUIC-only transport | 0-1 slot, calmer recovery on TCP | QUIC keepalive too slow for an 8s window. |

## What might actually close it

In rough order of effort:

1. **Loosen the test threshold** to match realistic operator patterns.
   3-of-4 (which passes) models real rolling restarts. 4-of-4
   simultaneous SIGKILL is operationally rare. **If we accept that
   the bar is "operators don't kill all validators at once", this
   test isn't load-bearing and can stay `#[ignore]`'d permanently.**

2. **Upstream libp2p contribution.** The specific gap in layer 2 —
   gossipsub's `peer_topics` / mesh-state stickiness on
   `ConnectionClosed` — would benefit every libp2p user. The
   research (see PR #283 commit body) traced it to behavior that
   neither Lighthouse nor ethlambda has filed against, so this is
   greenfield. Estimated effort: weeks of upstream work + waiting
   for review/release cycles.

3. **Custom transport for liveness messages.** Bypass libp2p RR
   entirely with a UDP-based reliable channel (with retransmit +
   FALCON-signed framing) for view-change / vote / fallback-proposal
   messages. Multi-week build. Significant new attack surface
   (we'd own transport-level encryption + auth + replay protection).
   Not recommended — see PR #283 commit for the full risk write-up.

4. **Layer 3 fix: `target_height` convergence protocol.** Add an
   explicit gossip message "I'm at target_height H" so surviving
   validators converge before VC-QC formation. New consensus
   message type, new convergence semantics, possibly new safety
   invariants to verify. Days of design work + property tests.

## How to reproduce

```
cargo test -p pyde-node --test validator_churn_4_of_4 -- --ignored --nocapture
```

Diagnostic counters worth grepping in the output:
- `view change QC formed` — should be ≥3 to recover
- `buffered fallback proposal` — receivers got fallback header
- `applied block from local QC` — peer synthesize-and-apply fired
- `applied own fallback block` — proposer applied its own
- `peer disconnected` — TCP/QUIC saw the dead peer drop
- `force-disconnected stale peer` — reactive RR-failure-driven cleanup
- `block received and processed` — gossip block delivery succeeded

## Related PRs

- #280 — `(height, view)` state machine + single-leader fallback
- #282 — RR fallback for consensus-topic messages
- #283 — hybrid TCP+QUIC + RR fallback for blocks + transport-liveness
