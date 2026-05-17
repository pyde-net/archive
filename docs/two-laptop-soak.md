# Two-Laptop Distributed Soak

Quick-start runbook for spinning up a 4-validator Pyde testnet across
two laptops on the same LAN. Intermediate validation step between the
single-laptop harness (`loadgen_mixed.rs`) and the full cloud
deployment described in [`testnet-bringup.md`](./testnet-bringup.md).

## Why this exists

Single-laptop soaks share one CPU, one thermal envelope, and use
`127.0.0.1` loopback for all peer traffic. They cannot validate:

- Real socket-level gossipsub mesh between machines
- libp2p TCP handshakes under genuine network conditions
- Inter-machine clock sync vs `PROGRESS_TIMEOUT_MS = 200 ms`
- Independent OS / kernel paths (macOS vs Linux exposes different
  socket / scheduler quirks)

Cloud deployment validates all of the above, plus cross-region
latency. The two-laptop step covers the first four cheaply.

## Topology

| Node    | Host             | P2P port | RPC port |
| ------- | ---------------- | -------- | -------- |
| node-0  | laptop A         | 30303    | 8545     |
| node-1  | laptop A         | 30304    | 8546     |
| node-2  | laptop B         | 30303    | 8547     |
| node-3  | laptop B         | 30304    | 8548     |

The `[[nodes]]` entries live in
[`crates/node/testdata/two-laptops.toml`](../crates/node/testdata/two-laptops.toml).
The committed file has placeholder hosts (`LAPTOP_A_LAN_IP`,
`LAPTOP_B_LAN_IP`). **Replace them locally** with your actual LAN
IPs before running step 1 — but **do not commit your real IPs** to
a public repo. Find each laptop's LAN IP via:

```bash
ifconfig | grep 'inet ' | grep -v 127.0.0.1   # macOS / Linux
```

Quorum is 3-of-4 — neither laptop alone can form a QC, so any
"chain advancing" result requires real cross-laptop traffic.

## Prerequisites

On **both laptops**:

```bash
# 1. Pull the latest main.
git pull origin main

# 2. Build the release binary.
cargo build --release -p pyde-node

# 3. Confirm they can ping each other on the LAN.
ping <LAPTOP_A_LAN_IP>   # from laptop B
ping <LAPTOP_B_LAN_IP>   # from laptop A
```

If `ping` fails: same Wi-Fi network? macOS firewall blocking ICMP?
(`System Settings → Network → Firewall` on macOS — allow `pyde`
inbound, or temporarily disable for the soak.)

## Step 1 — Generate genesis (laptop A only)

```bash
cd ~/Documents/zarah/systems/rust/pyde

./target/release/pyde testnet \
  --validators 4 \
  --node-addrs crates/node/testdata/two-laptops.toml \
  --chain-id 7331 \
  --out ./two-laptop-net
```

This produces:

```
two-laptop-net/
├── node-0/
│   ├── config.toml          ← laptop A keeps
│   ├── genesis.toml
│   ├── node.key             ← libp2p identity
│   ├── kem.key              ← threshold-encryption per-validator key
│   ├── threshold.pk         ← committee threshold pubkey
│   └── threshold.share      ← this node's share
├── node-1/                  ← laptop A keeps
├── node-2/                  ← copy to laptop B
└── node-3/                  ← copy to laptop B
```

## Step 2 — Copy node-2 and node-3 to laptop B

```bash
# From laptop A (replace user/path/IP as appropriate):
rsync -av --progress two-laptop-net/node-2 \
  user@<LAPTOP_B_LAN_IP>:~/pyde/two-laptop-net/

rsync -av --progress two-laptop-net/node-3 \
  user@<LAPTOP_B_LAN_IP>:~/pyde/two-laptop-net/
```

Or USB stick / `scp` / any file transfer that preserves directory
contents. The keys are sensitive but lab-bounded (chain_id 7331,
no real value at stake).

## Step 3 — Launch validators

### Laptop A (two terminals)

```bash
# Terminal 1 — node-0
./target/release/pyde run \
  --role validator \
  --config two-laptop-net/node-0/config.toml \
  --datadir two-laptop-net/node-0 \
  --log-level info 2>&1 | tee /tmp/node-0.log

# Terminal 2 — node-1
./target/release/pyde run \
  --role validator \
  --config two-laptop-net/node-1/config.toml \
  --datadir two-laptop-net/node-1 \
  --log-level info 2>&1 | tee /tmp/node-1.log
```

### Laptop B (two terminals)

```bash
# Terminal 1 — node-2
./target/release/pyde run \
  --role validator \
  --config two-laptop-net/node-2/config.toml \
  --datadir two-laptop-net/node-2 \
  --log-level info 2>&1 | tee /tmp/node-2.log

# Terminal 2 — node-3
./target/release/pyde run \
  --role validator \
  --config two-laptop-net/node-3/config.toml \
  --datadir two-laptop-net/node-3 \
  --log-level info 2>&1 | tee /tmp/node-3.log
```

Within ~10 s you should see `QC formed slot=N votes=3` on all four
nodes, with `slot=N` advancing every ~400 ms.

## Step 4 — Smoke verification

From either laptop (substitute `$LAPTOP_A` / `$LAPTOP_B` with your
actual LAN IPs first):

```bash
LAPTOP_A=<LAPTOP_A_LAN_IP>
LAPTOP_B=<LAPTOP_B_LAN_IP>

# Confirm all 4 nodes report the same head slot (within ±1).
for port in 8545 8546; do
  echo "node @ ${LAPTOP_A}:${port}:"
  curl -s -X POST http://${LAPTOP_A}:${port} \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"pyde_blockNumber","params":[]}' \
    | jq .result
done
for port in 8547 8548; do
  echo "node @ ${LAPTOP_B}:${port}:"
  curl -s -X POST http://${LAPTOP_B}:${port} \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"pyde_blockNumber","params":[]}' \
    | jq .result
done
```

All four should return the same (or ±1) hex slot. If they diverge by
more than 1 slot and don't reconverge within 30 s, something's wrong
— check the logs for `WARN` / `ERROR` lines.

## Step 5 — Drive load

`loadgen_mixed.rs` supports external mode via two env vars:

- `PYDE_LOADGEN_EXTERNAL_RPC_URLS` — comma-separated list of the
  four RPC endpoints
- `PYDE_LOADGEN_EXTERNAL_FAUCET_KEY` — path to the `faucet.key`
  file from step 1's output dir

When both are set, the test skips its internal testnet-spawn and
drives the four external nodes you launched in step 3, with the
same setup → fund → register → measure → verify pipeline.

From **laptop A** (where the `faucet.key` lives), substitute
`$LAPTOP_A` / `$LAPTOP_B` with your real LAN IPs:

```bash
LAPTOP_A=<LAPTOP_A_LAN_IP>
LAPTOP_B=<LAPTOP_B_LAN_IP>

PYDE_LOADGEN_EXTERNAL_RPC_URLS="http://${LAPTOP_A}:8545,http://${LAPTOP_A}:8546,http://${LAPTOP_B}:8547,http://${LAPTOP_B}:8548" \
PYDE_LOADGEN_EXTERNAL_FAUCET_KEY="$(pwd)/two-laptop-net/faucet.key" \
PYDE_LOADGEN_TPS=200 \
PYDE_LOADGEN_DURATION=14400 \
PYDE_LOADGEN_WARMUP=30 \
cargo test -p pyde-node --release --test loadgen_mixed -- \
  --ignored --nocapture mixed_workload_load_test \
  2>&1 | tee /tmp/pyde-two-laptop-soak.log
```

Recommended first run: 200 TPS for 1 hour
(`PYDE_LOADGEN_DURATION=3600`). If that passes clean, stretch to
the full 4 hours to match the single-laptop benchmark.

## Things to watch

- **Head divergence**: a 1-slot skew between nodes is normal and
  self-heals via the audit-418 `QcAnnounce` broadcast. A 2-slot
  skew persisting for >30 s is a regression — capture logs.
- **PSS warnings**: `PSS aggregation trigger fired but below
  threshold — waiting` is expected on a 4-node committee
  (threshold = 3, fewer-than-3 shares is normal mid-epoch).
- **`audit-416` consensus drops**: `WARN dropping consensus
  gossip ...` — these were silent pre-audit-416. A sustained burst
  (>1/s) is worth investigating; occasional fires under load are
  fine.

## Cleanup

```bash
# On both laptops:
# Ctrl-C each validator terminal.
rm -rf ~/pyde/two-laptop-net  # or wherever you put it
```

## Next step

If a 1h soak runs clean (~3000 slots advancing, ±1-slot skew only,
no `WARN` cascade):

- Stretch to 4h to match the single-laptop benchmark.
- Bump load past whatever the smoke loop can drive — needs the
  loadgen-external-endpoint follow-up.
- Then move to actual cloud-distributed (cross-region) — see
  [`testnet-bringup.md`](./testnet-bringup.md) for the canonical
  16-validator deployment.
