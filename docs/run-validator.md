# Run a Pyde Validator

Operator guide for running a validator node on the Pyde testnet.
Validators participate in HotStuff BFT consensus, propose blocks,
vote on finality, and earn block rewards + transaction fees.

## Before you start

A validator is materially harder to run than a full node:

- **Staking** — 10,000 PYDE locked in the validator-staking contract.
  Slashable for double-sign or extended downtime.
- **Threshold-share custody** — your `threshold.share` is a piece of
  the committee's MEV-protection decryption key. Loss = no PSS
  refresh participation, possible eviction at next epoch.
- **Uptime** — extended downtime risks slashing under the inactivity
  rules (`crates/consensus/src/slashing.rs`).
- **Hardware** — at least 4 dedicated cores, 16 GB RAM, NVMe SSD,
  multi-region preferred.
- **Network** — public reachability on TCP/30303 + UDP/30303 at a
  stable DNS name or static IP.

If any of those are dealbreakers, run a [full node](./connect-to-testnet.md)
instead.

## 1. Generate validator keys

The standard pre-launch path is for the testnet operator to
distribute keys via `pyde testnet --node-addrs <topology.toml>`
(task 078). You receive a directory containing:

- `validator.key` — FALCON-512 keypair, signs proposals + votes
- `node.key` — libp2p Ed25519 identity
- `threshold.share` — your share of the committee MEV-decryption
  secret
- `threshold.pk` — the (public) committee threshold pubkey
- `genesis.toml` — testnet genesis config (allocations, validators,
  initial supply)
- `config.toml` — pre-filled config with your region/host/port and
  full mesh of other validators in `bootstrap_peers`

Inspect the `# region: ... / # host: ...` header of your
`config.toml` to confirm you got the right validator slot.

> **Custody:** never commit `validator.key` or `threshold.share` to
> a repo, never email them, never paste in chat. Use an encrypted
> keystore (`PYDE_VALIDATOR_PASSPHRASE` env var, audit 221) for
> at-rest protection.

## 2. Encrypt the validator key

Pyde's keystore uses AES-256-GCM with a Poseidon2-derived key.

```sh
export PYDE_VALIDATOR_PASSPHRASE='your-strong-passphrase'

# First start with PYDE_VALIDATOR_PASSPHRASE set: the node detects
# the legacy raw-bytes validator.key, re-writes it encrypted, and
# logs a single deprecation warning.
pyde run --role validator --config /path/to/config.toml
```

After the first run, `validator.key` is in encrypted JSON format.
File permissions are tightened to 0o600 on Unix.

## 3. Start the validator

```sh
pyde run \
  --role validator \
  --config /path/to/config.toml \
  --datadir /path/to/datadir
```

Or with a systemd unit (recommended for production):

```ini
# /etc/systemd/system/pyde-validator.service
[Unit]
Description=Pyde Validator
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pyde
Group=pyde
WorkingDirectory=/home/pyde
Environment="PYDE_VALIDATOR_PASSPHRASE=__set_via_systemctl_edit__"
ExecStart=/usr/local/bin/pyde run --role validator --config /etc/pyde/config.toml --datadir /var/lib/pyde
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl edit pyde-validator   # set PYDE_VALIDATOR_PASSPHRASE
sudo systemctl enable --now pyde-validator
sudo journalctl -u pyde-validator -f
```

## 4. Confirm participation

Once synced, your validator should appear in the active set:

```sh
curl -s -X POST http://127.0.0.1:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"pyde_getValidators","params":[],"id":1}'
```

Find your address in the response. Your `voter_index` determines
your VRF position for proposer selection.

## 5. Watch the operator metrics

Pyde exposes Prometheus metrics on the configured port (default
9090):

```
pyde_block_lag                 # network_tip - head_slot. Alert > 10.
pyde_finality_lag              # slots since last hard-finality. Alert > 100.
pyde_peers                     # connected libp2p peers. Alert < 4.
pyde_block_processing_ms       # p99 block-execution latency.
pyde_state_commit_ms           # SMT/RocksDB commit p99.
pyde_validator_missed_proposals_total  # missed proposal slots (audit 222).
pyde_reorgs_total{outcome=...} # reorg attempts by outcome.
pyde_encrypted_mempool_size    # MEV-protected mempool depth.
```

A pre-built Grafana dashboard ships in `docker/grafana/`. Point it
at your Prometheus scraper and import.

## 6. Network exposure & firewall

The default `config.toml` ships safe-by-default:

| Endpoint | Default bind | Default port | Expose externally? |
|---|---|---|---|
| Consensus (libp2p) | `0.0.0.0` (TCP + QUIC) | `30303` | **Yes** — required for peer connections |
| JSON-RPC | `127.0.0.1` | `8545` | **No** — loopback only by default |
| Fast-tx (binary) | `0.0.0.0` | `9545` | Optional — only if you want public tx ingress |
| Prometheus metrics | `127.0.0.1` | `9090` | **No** — loopback or VPN-only |

Recommended firewall rules (UFW shown; adapt for nftables/cloud SG):

```sh
# Inbound: only the libp2p port and SSH
sudo ufw allow 22/tcp
sudo ufw allow 30303/tcp
sudo ufw allow 30303/udp           # QUIC
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable
```

If you want to expose RPC publicly (e.g., to serve dApps), do
**not** flip `network.listen = "0.0.0.0"` directly. Put a TLS reverse
proxy in front:

```nginx
# /etc/nginx/sites-available/pyde-rpc
server {
    listen 443 ssl http2;
    server_name rpc.your-domain.example;
    ssl_certificate     /etc/letsencrypt/live/.../fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/.../privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8545;
        proxy_http_version 1.1;
        proxy_read_timeout 60s;
        # Rate limit at the proxy — pyde_call gas is capped (audit
        # Tier 1D) but per-IP request rate is not.
        limit_req zone=rpc_per_ip burst=20 nodelay;
    }
}
```

Set `limit_req_zone $binary_remote_addr zone=rpc_per_ip:10m rate=10r/s;`
in `nginx.conf` to cap each IP at 10 RPC/s.

## 7. Logging

Pyde uses [`tracing`](https://docs.rs/tracing) with env-filter
configuration. Set `RUST_LOG` to control verbosity:

| Setting | Use case | Disk usage (rough) |
|---|---|---|
| `RUST_LOG=warn` | Silent operations; alert-driven monitoring | ~10 MB/day |
| `RUST_LOG=info` (default) | Production validators | ~100 MB/day |
| `RUST_LOG=info,pyde_node=debug` | Debugging consensus issues | ~1 GB/day |
| `RUST_LOG=debug` | Active troubleshooting only — high I/O cost | ~5+ GB/day |

For systemd, set in the unit's `[Service]` section:

```ini
Environment="RUST_LOG=info"
Environment="RUST_LOG_FORMAT=json"   # structured logs, ingestable by Loki/ELK
```

If you're shipping logs to a central pipeline, JSON format is
preferred — the field names match `tracing` spans/events one-to-one.

`journalctl` rotates and compresses automatically; standalone log
files need `logrotate`:

```
# /etc/logrotate.d/pyde
/var/log/pyde/*.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    sharedscripts
    postrotate
        systemctl reload pyde-validator > /dev/null 2>&1 || true
    endscript
}
```

## 8. Operational tasks

### Restart safely

A clean restart preserves state. The persisted `ConsensusState`
includes `pending_votes`, `seen_proposals`, `seen_votes`, and
`pending_evidence` (audits 001-007, 014c) — the validator picks up
exactly where it left off without re-voting on already-voted slots.

Crash recovery is exercised by the `validator_crash_recovery` test
(audit, see commit `03e051d`).

### Restore from a snapshot (fast sync)

A fresh node block-by-block-syncing from genesis is impractical
past ~1000 slots. The node's snapshot-sync trigger (audit 220)
fires automatically when:

- initial sync hasn't completed yet, AND
- no snapshot is already in flight, AND
- `network_tip - head_slot > SNAPSHOT_THRESHOLD` (1000 slots)

You don't have to do anything manually for this case — the node
will request `StateSnapshot` from a peer that's at the network
head, verify chunks against the live weak-subjectivity checkpoint
(audit 241), and apply them in order. Watch for the log lines:

```
INFO snapshot sync requested  slots_behind=4321
INFO snapshot import complete  state_root=...
```

If snapshot sync wedges (peer disconnects mid-import, root
mismatch, etc.), stop the node, delete `<datadir>/state/` and
`<datadir>/blocks/`, then restart. The node will re-issue the
snapshot request from scratch. **Do not delete `<datadir>/keys/`
or `<datadir>/consensus/`** — those hold your validator key and
last-voted state; losing them risks a double-vote on restart.

If a peer-supplied snapshot fails the WS-anchor check (audit 241
guards this), the node refuses to import it and logs a warning:
`snapshot import rejected: pre-checkpoint slot`. Switch peers and
retry.

### Rotate the validator FALCON key

Compromised key, scheduled rotation, or hardware migration: submit
an `auth_key.rotate` tx signed with the **current** key, naming
the new pubkey. The on-chain `pyde_account::auth::rotate` flow
verifies the old-key signature before installing the new one
(`crates/account/src/auth.rs`).

**Procedure:**

1. Generate a new FALCON keypair (`pyde keygen --out validator-new.key`).
2. Stop the validator: `sudo systemctl stop pyde-validator`.
3. Submit the rotate tx from a separate signing host using the OLD
   key. Wait for the tx to land in a hard-finalized block — query
   `pyde_getTransactionReceipt` until you see a non-zero block_slot
   AND that slot is ≤ the latest finality checkpoint.
4. Replace `validator.key` on disk with the new keypair (encrypted
   format; same `PYDE_VALIDATOR_PASSPHRASE`).
5. Start the validator. New proposals + votes are signed with the
   new key; old key is no longer recognized by the consensus
   verifier.

Cross-chain replay protection (`chain_id` in every signing preimage,
PR #301) means your old testnet sigs aren't replayable on mainnet
after rotation, but the rotation itself only affects the chain it's
submitted on.

> **Threshold-share rotation is separate** — that's PSS, runs every
> epoch automatically, and doesn't require a manual tx (see "Rotate
> threshold shares" below).

### Stake / unbond

Staking is performed by submitting a `TransactionType::StakeDeposit`
transaction (`crates/tx/src/types.rs`). Build the transaction in
your client of choice (Rust SDK or raw JSON-RPC), sign with the
validator's FALCON-512 key, and submit via
`pyde_sendRawTransaction`.

The `Transaction` fields for staking:

```rust
use pyde_tx::types::{Transaction, TransactionType};

let mut tx = Transaction {
    tx_type: TransactionType::StakeDeposit,
    from: validator_addr,
    to: validator_addr,            // self-stake; ignored for stake-tx
    value: 10_000_000_000_000,     // 10,000 PYDE in quanta
    nonce,
    gas_limit: 100_000,
    chain_id,
    signature: Vec::new(),
    /* ...remaining fields... */
};
let sig = falcon_sign(&sk, &tx.hash())?;
tx.signature = sig.as_bytes().to_vec();
provider.send_transaction(&tx).await?;
```

Unbonding uses `TransactionType::StakeWithdraw`. The 14-day
waiting period is enforced in the tx pipeline; balance becomes
spendable automatically after the window closes.

### Rotate threshold shares (PSS)

Threshold shares automatically refresh at every epoch boundary via
PSS (proactive secret sharing). The combined secret is unchanged;
your share rotates so genesis-ceremony trust dissolves after the
first epoch.

If you bring a new operator online mid-epoch, they receive shares
via the resharing protocol at the next boundary
(`canonical_resharing_subset`).

### Apply software upgrades

```sh
sudo systemctl stop pyde-validator
# Replace /usr/local/bin/pyde with the new binary
sudo systemctl start pyde-validator
sudo journalctl -u pyde-validator -f   # confirm sync resumes
```

Plan upgrades for low-traffic windows. The 14-day unbonding period
means an upgrade-induced bug that gets you slashed costs you 14
days of unstaked liquidity, not just downtime.

## Slashing — what to watch

| Event | Detection | Slash | How to avoid |
|---|---|---|---|
| Double-sign | Two votes for the same slot at different block hashes | 100% of stake + ejection + forced unbonding | Don't run two validators with the same key. Don't restore from a backup that includes votes already broadcast. |
| Equivocation on proposal | Two proposals at the same slot | 100% of stake + ejection + forced unbonding | Same as above. |
| Liveness < 90% participation | Per-epoch participation report | 1% of stake (no ejection) | Healthy uptime; bound on `pyde_validator_missed_proposals_total` |
| Liveness < 50% participation | Per-epoch participation report | 5% of stake + ejection | Same as above |
| Liveness == 0% participation | Per-epoch participation report | 10% of stake + forced unbonding | Same as above |

Double-sign and proposal equivocation are detected, gossiped, and
auto-slashed in production (audits 005, 014c, 205). Evidence is
persisted to disk as soon as it's detected and applied via
`TransactionType::Slash` once a validator includes it in a block.

> **Liveness slashing — current status:** the slashing mechanism
> (`pyde_consensus::slashing::slash_liveness`) is implemented and
> tested, but the per-epoch participation report that feeds it is
> not yet wired into block production. Public testnet phases will
> expose participation metrics (`pyde_validator_missed_proposals_total`)
> for monitoring; on-chain liveness slashing turns on before mainnet.

Cross-chain replay protection: every consensus signature
(proposer, vote, view-change, evidence) is bound to the local
chain's `chain_id` (PR #301), so a double-sign on devnet cannot
slash you on testnet/mainnet even if you reuse FALCON keys across
networks during dev cycles. Reusing keys is still bad operational
hygiene (loss of one ⇒ loss of all), but it's no longer a
chain-wiping mistake.

## Troubleshooting

### Validator never becomes active

```sh
curl -s -X POST http://127.0.0.1:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"pyde_getValidators","params":[],"id":1}'
```

If your address isn't there, you haven't staked yet (testnet may
require a faucet step) or your registration hasn't been included.
Check your stake-deposit tx hash via `pyde_getTransactionReceipt`.

### "panic: persist failure" on startup

The node refuses to continue if it cannot fsync consensus state to
disk (audit 014b — safety-optimal: continuing risks a BFT
double-vote on next start). Check disk free space, mount options
(no `nosync` / `commit=N` weirdness), and rerun.

### Threshold-share decode failure

Your `threshold.share` is the wrong format or for the wrong
committee. Re-fetch from the operator-issued bundle. Don't try to
hand-edit it.

## Stake economics (testnet)

- Validator stake: 10,000 PYDE
- Block reward: per-slot inflation pool, distributed by stake-weight
  to the active validator set
- Fee split: 70% burn / 20% validator / 10% treasury
- Double-sign slash: full stake
- Unbonding period: 14 days (still earning during this window)

Mainnet parameters are subject to change before genesis ceremony —
see `MAINNET_PLAN.md` Phase 4.
