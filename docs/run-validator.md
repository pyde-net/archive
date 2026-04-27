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

## 6. Operational tasks

### Restart safely

A clean restart preserves state. The persisted `ConsensusState`
includes `pending_votes`, `seen_proposals`, `seen_votes`, and
`pending_evidence` (audits 001-007, 014c) — the validator picks up
exactly where it left off without re-voting on already-voted slots.

Crash recovery is exercised by the `validator_crash_recovery` test
(audit, see commit `03e051d`).

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
| Double-sign | Two votes for the same slot at different block hashes | Full stake | Don't run two validators with the same key. Don't restore from a backup that includes votes already broadcast. |
| Equivocation on proposal | Two proposals at the same slot | Full stake | Same as above. |
| Extended downtime | TODO: not yet enforced | TBD | Healthy uptime monitoring. |

Double-sign evidence is gossiped as soon as it's detected, persisted
to disk (audit 005, 014c), and applied via `TransactionType::Slash`
once a validator includes it in a block.

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
