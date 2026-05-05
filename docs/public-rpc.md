# Public RPC Operator Guide

Operator runbook for running a Pyde public RPC fleet — the
internet-facing endpoint that wallets, dapps, and explorers hit.
Audience: whoever is setting up the public RPC behind your testnet
(often the coordinator + 1-2 dedicated full-node operators).

If you're a validator operator, you want
[`run-validator.md`](./run-validator.md) instead. **Validators MUST
NOT expose JSON-RPC publicly** — see [§ Topology](#topology) below.

## Topology

```
┌──────────────────────────────────────────────────────────────────┐
│  internet                                                        │
│     │                                                            │
│     ▼                                                            │
│  ┌──────────────┐    rate-limited, TLS,                          │
│  │ nginx :443   │ ── XFF-normalized, body-cap ──▶               │
│  └──────────────┘                                                │
│     │                                                            │
│     ▼                                                            │
│  ┌──────────────────────────────────────────┐                    │
│  │ pyde --role full-node     :8545 / :8546  │                    │
│  │   (loopback-bound, no public exposure)   │                    │
│  └──────────────────────────────────────────┘                    │
│     │                                                            │
│     ▼ libp2p                                                     │
│  ┌──────────────────────────────────────────┐                    │
│  │ validator fleet (private network only)   │                    │
│  └──────────────────────────────────────────┘                    │
└──────────────────────────────────────────────────────────────────┘
```

Three rules that hold this topology together:

1. **Validators run with `--role validator`** and bind RPC to
   loopback (the default in the testnet bundle's `config.toml`).
   They participate in consensus and never serve public traffic.

2. **Public RPC fleet runs `--role full-node`** on separate hosts
   (or at minimum separate processes / containers). Full nodes
   replicate state from the validator gossip mesh but don't sign
   blocks. A misbehaved RPC client can DoS a full-node — that's
   acceptable; it can't DoS consensus.

3. **nginx fronts the full-node fleet** for TLS, rate-limiting,
   header normalization, and load balancing. The full-node's
   JSON-RPC port stays on `127.0.0.1` even on the host running
   nginx.

## What's in `deploy/nginx-pyde-rpc.conf.example`

- TLS termination (Let's Encrypt-friendly cert paths)
- Per-IP rate-limit zones for read / write / subscribe traffic
- Per-IP concurrent-connection cap (default 50)
- 64 KB body-size cap (encrypted-tx wire format is ~12 KB; plaintext
  smaller; 64 KB leaves headroom for `pyde_call` calldata)
- Slowloris defenses (header / body / keepalive timeouts)
- WebSocket upgrade for `pyde_subscribe*` channels
- `X-Forwarded-For` rewrite that pairs with audit 348's trust
  mechanism — see [§ X-Forwarded-For pairing](#x-forwarded-for-pairing)
- HTTP → HTTPS redirect

## Setup steps

### 1. Provision a full-node host

```sh
# On the full-node host:
mkdir -p /var/lib/pyde
# Drop in the bundle's genesis.toml + the public-RPC node config.
# (The bundle's per-node config.toml is for VALIDATORS — for a
#  full-node, generate a custom config or take the bundle's
#  template and set role = "full".)
cat > /var/lib/pyde/config.toml <<EOF
[node]
role = "full"
chain_id = 7331
datadir = "/var/lib/pyde"

[network]
port = 30303
max_peers = 100
bootstrap_peers = [
  # paste the testnet's validator multiaddrs from genesis.toml
]

[rpc]
enabled = true
listen = "127.0.0.1"   # loopback only — nginx fronts it
port = 8545

[storage]
db_path = "state"
cache_size = 524288    # 512 MB; bump for high read traffic
EOF

# Start the full node.
pyde run --role full --config /var/lib/pyde/config.toml --datadir /var/lib/pyde
```

### 2. Install + configure nginx

```sh
# Install nginx + certbot (Debian/Ubuntu):
apt-get update && apt-get install -y nginx certbot python3-certbot-nginx

# Get a TLS cert. Replace rpc.testnet.pyde.network with your DNS:
certbot certonly --nginx -d rpc.testnet.pyde.network

# Drop in the template:
cp /path/to/pyde/deploy/nginx-pyde-rpc.conf.example /etc/nginx/sites-available/pyde-rpc
ln -s /etc/nginx/sites-available/pyde-rpc /etc/nginx/sites-enabled/pyde-rpc

# Edit /etc/nginx/sites-enabled/pyde-rpc:
#   - replace CHANGE_ME_RPC_HOST with your DNS
#   - confirm ssl_certificate paths match certbot's output
#   - if load-balancing across multiple full-nodes, add them to the
#     `upstream pyde_rpc` and `upstream pyde_ws` blocks

# Sanity-check the config and reload:
nginx -t
systemctl reload nginx
```

### 3. Tell the full-node to trust the proxy's XFF header

When the proxy sets `X-Forwarded-For: <client_ip>`, the full-node's
faucet path needs to be told to trust it. From your faucet command:

```sh
pyde faucet \
  --rpc http://127.0.0.1:8545 \
  --from 0x... \
  --private-key /path/to/faucet.key \
  --trust-x-forwarded-for     # ← only when behind a proxy
```

**Do NOT set `--trust-x-forwarded-for`** if the faucet is exposed
directly to the public internet — clients can fake `X-Forwarded-For`
and bypass per-IP rate limits.

### 4. Verify

```sh
# Plain JSON-RPC works:
curl -s https://rpc.testnet.pyde.network -X POST \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"pyde_blockNumber","params":[],"id":1}'
# → {"jsonrpc":"2.0","id":1,"result":"0x..."}

# Body-size cap works:
curl -s https://rpc.testnet.pyde.network -X POST \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/100kb-blob
# → 413 Request Entity Too Large

# Rate-limit works (run from a single IP — should start 503-ing):
for i in $(seq 1 500); do
  curl -s https://rpc.testnet.pyde.network -X POST \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"pyde_blockNumber","params":[],"id":1}' \
    > /dev/null &
done
wait
# Some requests return 503 once the burst window is exceeded.
```

## X-Forwarded-For pairing

Audit 348 added per-IP rate-limit support to the faucet's HTTP
ingress with a configurable trust mode for `X-Forwarded-For`. The
full picture:

```
client (203.0.113.5) ──HTTP──▶ nginx ──HTTP──▶ pyde --role full-node
                                      │
                                      └── X-Forwarded-For: 203.0.113.5
                                          (overridden by nginx, NOT appended)
```

The pyde faucet, when started with `--trust-x-forwarded-for`,
reads the **rightmost** entry in XFF as the client IP for
rate-limiting. Because nginx OVERRIDES (not appends) any inbound
XFF, the rightmost entry is always the real client IP.

If nginx APPENDED (the default before this template), an attacker
sending `X-Forwarded-For: 1.2.3.4` would get nginx to append:
`X-Forwarded-For: 1.2.3.4, 203.0.113.5`. The faucet's rightmost-
hop policy would still resolve the right IP — but a poorly-
configured proxy might use the leftmost. **Always override XFF at
the trust boundary** to avoid that whole class of mistake.

The template at `deploy/nginx-pyde-rpc.conf.example` does the
override correctly:

```nginx
proxy_set_header X-Forwarded-For $remote_addr;  # OVERRIDE, not append
```

## Method-level rate limits

The template applies a single zone (`rpc_cheap` at 100 r/s/IP) to
all `/` traffic. For finer-grained limits per method class, you
have two options:

1. **Application-layer (recommended)**: the validator node already
   rate-limits at the mempool ingress (audit 027 — 10 enc-tx/s/sender,
   100 concurrent-tx/sender). RPC reads are stateless and cheap; a
   single global zone is usually fine.

2. **Proxy-layer (advanced)**: drop in OpenResty + a small Lua
   handler that parses the JSON-RPC body's `method` field and sets
   a `$rpc_zone` variable used by `limit_req`. The template
   reserves zones (`rpc_medium`, `rpc_expensive`, `rpc_write`,
   `rpc_subscribe`) for this — uncomment / wire them up if you need
   per-method enforcement at the proxy.

For a launch-day public testnet the application-layer limits are
sufficient. Method-level proxy limits are an upgrade path if a
specific method class becomes a hot abuse target.

## Common pitfalls

### "Health checks are getting rate-limited"

The template whitelists `/health` ahead of the rate-limit. If your
load-balancer probes a different path, add it:

```nginx
if ($request_uri = "/your-probe-path") {
    return 200 "ok\n";
}
```

### "Subscriptions disconnect after 60s"

Default nginx `proxy_read_timeout` is 60s. The template raises it
to 1h for the `/ws` location, but if you front the proxy with
*another* proxy (CDN, AWS ALB), each layer has its own timeout.
Configure each one to keep WebSocket connections alive.

### "Faucet is rate-limiting everyone to one IP"

You forgot `--trust-x-forwarded-for` on the faucet. Without it,
every request looks like it's coming from `127.0.0.1` (the
nginx → faucet hop), so the IP rate-limit zone collapses to a
single bucket. Set the flag and restart.

### "TLS handshake fails with `unable to get local issuer certificate`"

Cert chain incomplete. `certbot --nginx` should set
`ssl_certificate` to `fullchain.pem` (NOT `cert.pem`). If you
see only `cert.pem`, switch to `fullchain.pem`.

## Monitoring this layer

The full-node already exposes Prometheus metrics on `:9090`. Add an
nginx-exporter sidecar (e.g.,
[nginxinc/nginx-prometheus-exporter](https://github.com/nginxinc/nginx-prometheus-exporter))
to surface proxy-layer metrics — request rate, 4xx/5xx ratios,
upstream connection pool — alongside the chain metrics.

Key panels to watch:

- 5xx ratio > 1% → upstream issue (full-node down, slow query)
- 429/503 ratio sustained → legit user demand or DoS attempt;
  raise zone limits if legit
- Connection-pool exhaustion → bump `keepalive 32` in the upstream
  blocks
- TLS handshake failures → cert expiry approaching

## Recovery

### Full-node falls behind

Symptom: `pyde_syncing` returns true; clients get stale balance
reads. Cause: usually a slow RocksDB compaction or a libp2p peer
churn event.

```sh
# Check sync state on the loopback (skip nginx):
curl -s http://127.0.0.1:8545 -X POST \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"pyde_syncing","params":[],"id":1}'
```

If lagging by < 100 blocks, wait — full-nodes catch up via the
validator gossip mesh in seconds. If lagging by > 1000 blocks for
more than a minute, restart the full-node and let it re-bootstrap.

### A full-node deadlocks

Symptom: requests time out; `pyde_blockNumber` stops responding.

```sh
# Take the upstream out of rotation:
# Edit /etc/nginx/sites-enabled/pyde-rpc, comment out the affected
# `server` line in `upstream pyde_rpc`, then:
nginx -s reload

# Restart the full-node:
systemctl restart pyde-fullnode

# Verify it's caught up before adding back to the pool:
curl -s http://that-host:8545 -X POST \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"pyde_blockNumber","params":[],"id":1}'
```
