# Pyde On-Call Playbook

One-page reference for "panel goes red — what now." Pairs with
[`deploy/grafana-pyde-testnet.json`](../deploy/grafana-pyde-testnet.json);
each row of the quick-reference table maps to a panel in that
dashboard.

If you're new to operator duty, read [§ How to use this](#how-to-use-this)
first. If a chain-wide incident is unfolding right now, jump to
[§ Quick reference](#quick-reference) and pattern-match.

## How to use this

Three rules:

1. **Look at trend, not instantaneous value.** "Block lag = 3" is
   normal during gossip churn. "Block lag = 3 sustained for 60s"
   is a problem.

2. **Diagnose locally before assuming network issue.** If your
   node's panel is red but your peer-operator's is green, the
   problem is on your host. RocksDB compaction, NTP drift, libp2p
   peer churn — all are local.

3. **Don't restart a validator in panic.** A validator that
   restarts mid-slot misses its proposal. Page another operator,
   diagnose, then restart only if necessary. The chain absorbs
   one validator going dark; it doesn't absorb half the committee
   panicking.

The recovery commands below assume you have shell access on the
affected host. For multi-region operators, mirror the access via
SSH bastions; never run remote-management RPCs over the public
JSON-RPC.

## Quick reference

| Panel red | Likely cause | First check | First action |
|---|---|---|---|
| **Block height stops advancing** | Sub-quorum validator set | `pyde_peers_connected` across all nodes — sum < `quorum-1`? | [§ peers-low](#peers-low) |
| **Finality lag > 10 sustained** | Slow validator(s) holding up QC | Block-processing p99 on every node, find the slow one | [§ finality-lag](#finality-lag) |
| **Block lag > 5 on one node only** | That node fell behind | `pyde_syncing` returns true on the lagging node | [§ block-lag](#block-lag) |
| **Encrypted mempool grows unbounded** | Decrypt pipeline stalled | `pyde_encrypted_mempool_size` rate of growth | [§ encrypted-mempool-grew](#encrypted-mempool-grew) |
| **Block-processing p99 > 200ms** | RocksDB compaction or CPU contention | `pyde_state_commit_ms` p99 — does it correlate? | [§ slow-blocks](#slow-blocks) |
| **Reorg rate non-zero** | Network partition or byzantine proposer | `pyde_reorgs_total` outcome label (`Succeeded` / `Failed` / `TargetNotBuffered`) | [§ reorg](#reorg) |
| **Missed proposals > 0 (my validator)** | Slot-clock skew or process busy | NTP offset, system load | [§ missed-proposals](#missed-proposals) |
| **RPC error rate > 5%** | Full-node falling behind, upstream unhealthy | nginx upstream status | [§ rpc-errors](#rpc-errors) |
| **Faucet balance ≈ 0** | Drained or mis-distributed | `pyde_getBalance` on the faucet address | [§ faucet-drained](#faucet-drained) |

---

## peers-low

Low peer count (< quorum threshold) directly causes the chain to
stall — without enough peers, no QC forms.

**Diagnose:**
```sh
# On each validator host:
curl -s http://127.0.0.1:9090/metrics | grep '^pyde_peers_connected'

# Sum across all running nodes:
# - quorum threshold for n=4 is 2f+1 = 3
# - quorum threshold for n=16 is 11
```

If the sum < quorum, the chain CANNOT advance until peers reconnect.

**Action:**
1. Check inter-region connectivity:
   ```sh
   nc -zv validator-N.testnet.pyde.network 30303
   ```
2. If a region is down, page that region's operators.
3. If individual peers are down (process not running), restart
   them (see [`docs/run-validator.md`](./run-validator.md)).
4. If everyone's up but peers can't dial each other, check firewall
   — the libp2p port `30303/tcp` + `30303/udp` is the most common
   firewall regression after a host migration.

**Prevent:** spread operators across at least 3 regions; no
single-region majority. The 16v-3region.toml topology
(`crates/node/testdata/testnet-16v-3region.toml`) is sized so a
full-region outage of 5 nodes still leaves quorum.

## finality-lag

Finality lagging means blocks are being proposed but the QC needed
to finalize them isn't forming fast enough. Usually one validator
is slow.

**Diagnose:**
```sh
# Check block-processing p99 on each validator's metrics:
for h in validator-{0..15}.testnet.pyde.network; do
  echo -n "$h: "
  ssh $h 'curl -s http://127.0.0.1:9090/metrics' \
    | grep 'pyde_block_processing_ms_bucket' | tail -1
done
```

The validator with consistently-high p99 is the culprit.

**Action:**
1. If one node is much slower than the others, check that host's:
   - CPU load (`top`)
   - Disk IO (`iostat -x 1` — look for high `%util` on the data
     volume)
   - RocksDB compaction (search logs for `"compaction"`)
2. If RocksDB is compacting heavily, let it finish — it's
   self-limiting. Don't restart.
3. If CPU is pegged due to other workloads on the host, move the
   validator to a dedicated host.
4. If multiple nodes are slow simultaneously, suspect a network
   partition — check `pyde_peers_connected` on each.

## block-lag

`pyde_block_lag = network_tip − local_head` on a single node. The
node has fallen behind the rest of the network.

**Diagnose:**
```sh
curl -s http://that-node:8545 -X POST \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"pyde_syncing","params":[],"id":1}'
```

`true` confirms it's actively syncing.

**Action:**
- Lag < 100 blocks: wait. Sync via gossip mesh catches up in seconds.
- Lag > 1000 blocks for > 1 min: the sync state is broken. Restart:
  ```sh
  systemctl restart pyde-validator   # or your service name
  ```
  The node re-bootstraps and pulls block-by-block from peers.
- Lag never decreases after restart: the local block store is
  corrupted. Wipe `datadir/state` + `datadir/blocks` and re-sync
  from genesis. Validator key + threshold share are in separate
  files, do NOT delete them.

## encrypted-mempool-grew

Encrypted mempool size growing unbounded means encrypted txs are
arriving faster than they can be decrypted + applied.

Two possible causes:

(a) **Decryption pipeline stalled** — committee can't aggregate
    threshold shares. Look for repeated "below threshold —
    waiting" warnings in validator logs.

(b) **Submission burst** — legit users + bots flooding the
    encrypted lane. The 250 enc-TPS ceiling is real; if submit
    rate > 250 TPS sustained, mempool grows linearly.

**Diagnose:**
```sh
# On a validator:
journalctl -u pyde-validator -n 1000 \
  | grep -E 'resharing aggregation|decryption.*fail|threshold not reached'
```

If you see "below threshold" repeating: case (a).
If logs are clean: case (b).

**Action for (a):**
1. Check committee membership — `pyde_getValidators` returns the
   live set. If < threshold members are responsive, decryption
   can't proceed.
2. Restart the lagging validator(s).

**Action for (b):**
1. Check the faucet — has someone been draining it?
2. Tighten the public RPC's rate-limit zone for
   `pyde_sendRawEncryptedTransaction` (in
   `deploy/nginx-pyde-rpc.conf.example`, change the `rpc_write`
   zone from `10r/s` to `5r/s`).
3. Encrypted-tx ceiling is `MAX_ENCRYPTED_TXS_PER_BLOCK = 100`
   * 2.5 blocks/s = 250 enc-TPS. If real demand exceeds this,
   raise the cap (governance + code change — not a hot fix).

## slow-blocks

Block-processing p99 > 200ms eats into the slot's QC budget. If it
keeps growing, slots get skipped and finality lags.

**Diagnose:**
```sh
# Is state commit the dominant component?
# Compare pyde_block_processing_ms vs pyde_state_commit_ms p99.
```

If `state_commit_ms` ≈ `block_processing_ms`: RocksDB is the
bottleneck. Otherwise execution + sig verify dominates.

**Action:**
- RocksDB-bound: increase the storage cache, turn on background
  compactions, move data to faster disk. Bump `cache_size` in
  `[storage]` section of config.toml (default 65536 = 64 MB, try
  524288 = 512 MB for high-traffic full-nodes).
- Execution-bound: probable abuse. A contract with a hot tight
  loop in encrypted-tx land can hog a slot. Check
  `pyde_transactions_processed_total` per block — if a single tx
  takes most of the slot, blocklist that contract address (no
  protocol mechanism today; flag in operator-coordinated chat).

## reorg

Any non-zero reorg rate is concerning. Possible causes:

(a) **Network partition** — two halves of the validator set
    proposed on different forks; resolved when the partition
    heals.

(b) **Byzantine proposer** — building blocks on a different parent
    than the canonical chain. Audit-311 verify_qc gate catches
    most of this; if reorg fires anyway, slashing-class evidence
    likely exists.

**Diagnose:**
```sh
# Check the outcome label of each reorg event:
journalctl -u pyde-validator -n 500 \
  | grep -E 'reorg|fork choice'
```

`Succeeded` = chain switched cleanly. `Failed` = reorg attempt
rejected (good). `TargetNotBuffered` = the reorg target is past
the buffer window (bad — data lost).

**Action:**
1. If `Failed` only: chain is defending itself, nothing to do.
2. If `Succeeded` rate > 0 sustained: investigate WHY. Was there
   a partition? Coordinate via operator chat.
3. If `TargetNotBuffered`: that node's view is permanently
   corrupted relative to the canonical chain. Restart + resync
   from genesis.

## missed-proposals

`pyde_validator_missed_proposals_total` going up = your validator
is being scheduled to propose but isn't producing a block in time.

**Diagnose:**
```sh
# NTP offset on the host:
chronyc tracking | grep 'System time'
# or
timedatectl status

# Process load:
top -p $(pgrep pyde)
```

**Action:**
- NTP offset > 200ms → fix NTP. The slot_clock derives slot from
  wall-clock; >200ms drift causes the proposer to miss its window.
- Process pegged at 100% CPU → another tx-execution bottleneck.
  See [§ slow-blocks](#slow-blocks).
- Process under-loaded but still missing proposals → check
  `slot_clock initialized` log line at startup; verify
  `slot_clock_anchor_ms` matches the genesis timestamp the
  coordinator distributed (audit 400 regression test — should
  always match for properly-bundled testnets).

## rpc-errors

> 5% RPC error rate → public RPC users are seeing failures.

**Diagnose:**
```sh
# Per-method breakdown:
curl -s http://127.0.0.1:9090/metrics | grep 'pyde_rpc_requests_total'

# nginx upstream status:
journalctl -u nginx -n 100 | grep -E 'upstream timed out|connection refused'
```

**Action:**
- `pyde_call` / `pyde_estimateGas` errors dominating: a contract
  is reverting, or gas-estimation is hitting a tight upper bound.
  Likely just clients passing bad calldata; not your problem.
- `pyde_sendRawTransaction` errors dominating: mempool
  rate-limited, full, or auth-key-rejected. Check
  `pyde_mempool_size` — if at 500K cap, ingress is rejecting.
- nginx logs show upstream timeout: the full-node deadlocked or
  fell behind. See [§ block-lag](#block-lag) recovery.
- nginx logs show connection refused: full-node process died.
  Restart it; nginx will route to other upstreams while it boots.

## faucet-drained

Faucet balance approaching zero means it's been used heavily —
either by legit demand or a draining attack.

**Diagnose:**
```sh
curl -s https://rpc.testnet.pyde.network -X POST \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"pyde_getBalance","params":["0x<faucet_addr>"],"id":1}'

# Check faucet's drip rate over the last hour:
journalctl -u pyde-faucet --since "1 hour ago" \
  | grep -c 'dispensed'
```

If drip rate > legitimate-user expectation: drain attack.

**Action:**
1. Tighten the cooldown:
   ```sh
   # pyde faucet --cooldown <new value> ...
   # Default 3600 (1h). Bump to 86400 (24h) under attack.
   ```
2. Top up the faucet via a one-off transfer from the genesis-funded
   coordinator wallet. `accounts.json` (kept on coordinator host
   per [`docs/testnet-bringup.md`](./testnet-bringup.md) Phase 3)
   has the keys.
3. If you need to disable the faucet entirely while investigating,
   `systemctl stop pyde-faucet`. The chain keeps running; only the
   faucet is offline.

---

## Alerting rules (Prometheus / Alertmanager)

Drop these into your Prometheus rule file. Adjust `for:` durations
to match your noise tolerance.

```yaml
groups:
  - name: pyde-testnet
    interval: 30s
    rules:
      - alert: ChainStuck
        expr: rate(pyde_chain_head_slot[2m]) == 0
        for: 2m
        labels: {severity: critical, runbook: peers-low}
        annotations:
          summary: "Pyde chain head not advancing for 2m on {{ $labels.instance }}"
          runbook_url: "https://github.com/zarah-s/pyde/blob/main/docs/oncall.md#peers-low"

      - alert: FinalityLagging
        expr: pyde_finality_lag > 10
        for: 1m
        labels: {severity: warning, runbook: finality-lag}
        annotations:
          summary: "{{ $labels.instance }} finality lag = {{ $value }} slots (>10)"
          runbook_url: "https://github.com/zarah-s/pyde/blob/main/docs/oncall.md#finality-lag"

      - alert: BlockLagHigh
        expr: pyde_block_lag > 5
        for: 1m
        labels: {severity: warning, runbook: block-lag}
        annotations:
          summary: "{{ $labels.instance }} block lag = {{ $value }} slots"
          runbook_url: "https://github.com/zarah-s/pyde/blob/main/docs/oncall.md#block-lag"

      - alert: PeersLow
        expr: pyde_peers_connected < 3
        for: 30s
        labels: {severity: critical, runbook: peers-low}
        annotations:
          summary: "{{ $labels.instance }} has only {{ $value }} peers (need quorum-1)"
          runbook_url: "https://github.com/zarah-s/pyde/blob/main/docs/oncall.md#peers-low"

      - alert: EncryptedMempoolGrowing
        expr: pyde_encrypted_mempool_size > 5000
        for: 5m
        labels: {severity: warning, runbook: encrypted-mempool-grew}
        annotations:
          summary: "encrypted mempool = {{ $value }} on {{ $labels.instance }}"
          runbook_url: "https://github.com/zarah-s/pyde/blob/main/docs/oncall.md#encrypted-mempool-grew"

      - alert: ReorgsHappening
        expr: rate(pyde_reorgs_total{outcome="Succeeded"}[5m]) > 0
        for: 1m
        labels: {severity: warning, runbook: reorg}
        annotations:
          summary: "Successful reorgs at {{ $value }}/s on {{ $labels.instance }}"
          runbook_url: "https://github.com/zarah-s/pyde/blob/main/docs/oncall.md#reorg"

      - alert: ValidatorMissingProposals
        expr: rate(pyde_validator_missed_proposals_total[5m]) > 0
        for: 1m
        labels: {severity: critical, runbook: missed-proposals}
        annotations:
          summary: "{{ $labels.instance }} missing proposals at {{ $value }}/s"
          runbook_url: "https://github.com/zarah-s/pyde/blob/main/docs/oncall.md#missed-proposals"

      - alert: RpcErrorRateHigh
        expr: |
          sum(rate(pyde_rpc_requests_total{outcome="error"}[5m])) /
          sum(rate(pyde_rpc_requests_total[5m])) > 0.05
        for: 5m
        labels: {severity: warning, runbook: rpc-errors}
        annotations:
          summary: "RPC error rate {{ $value | humanizePercentage }}"
          runbook_url: "https://github.com/zarah-s/pyde/blob/main/docs/oncall.md#rpc-errors"
```

## Setup notes

The dashboard at `deploy/grafana-pyde-testnet.json` imports cleanly
into Grafana 9+ via:

1. Grafana → + → Import → Upload JSON file → select the file
2. Set the Prometheus datasource (the panels use the default
   datasource; rebind if your name differs)
3. Click Import

Each validator's Prometheus should scrape `:9090/metrics` on each
node. A minimal `prometheus.yml` snippet:

```yaml
scrape_configs:
  - job_name: 'pyde-validators'
    scrape_interval: 5s
    static_configs:
      - targets:
          - validator-0.testnet.pyde.network:9090
          - validator-1.testnet.pyde.network:9090
          # … etc
```

For a public testnet, scrape over a private network (VPN /
Tailscale / WireGuard). The `:9090/metrics` endpoint is loopback-
only by default; expose it inside your trusted operator network,
not on the public internet.
