# Pyde Testnet Bring-Up

Operator runbook for spinning up a fresh public Pyde testnet from
scratch. Audience: the network coordinator + the 16 (or N) validator
operators who will run the genesis committee.

If you're a regular validator joining an *already-running* testnet,
you want [`run-validator.md`](./run-validator.md) instead. This doc
covers the **first-time genesis ceremony** end-to-end.

> **Canonical testnet chain_id is `7331`.** Defined in
> `pyde_net::discovery::TESTNET_CHAIN_ID`. Use this for the public
> testnet. Custom / staging testnets should pick a *different*
> non-mainnet, non-devnet chain_id to keep replay protection clean.

## Phases

```
┌───────────────────────────────────────────┐
│  1. Coordinator: plan topology            │
│  2. Coordinator: generate genesis bundle  │
│  3. Coordinator: distribute keys          │
│  4. Operators: encrypt + start their node │
│  5. Coordinator: smoke verification       │
│  6. Coordinator: announce + open RPC      │
└───────────────────────────────────────────┘
```

Phase 1-2 happen on a single trusted machine. Phase 3 is the only
network-sensitive step (private key bytes leave your machine). Phase
4 happens in parallel across operators. Phase 5-6 are observational.

## 1. Coordinator: plan topology

You need:

- Final operator list with **public DNS hostname or static IP** per
  validator. DNS is preferred — easier to recover from IP changes.
- Region distribution. The canonical testnet target is **6 / 5 / 5
  across us-east, eu-west, ap-southeast** for a 16-validator network.
  This gives `f = 5` Byzantine tolerance with the BFT bound `2f+1 = 11`,
  so a full-region outage of 5 nodes still leaves a quorum. Smaller
  testnets should preserve `n ≥ 3f+1` and aim for at least 3 regions.
- TCP/UDP port for libp2p (default `30303`). Operators SHOULD all use
  the same port — simplifies firewalling and topology files.

Edit `crates/node/testdata/testnet-16v-3region.toml` (or copy it) and
substitute your real hosts:

```toml
[[nodes]]
index = 0
region = "us-east-1"
host = "validator-0.testnet.pyde.network"   # ← your DNS or static IP
port = 30303
```

The file is dense-indexed (no gaps). Validate with
`grep -c '^\[\[nodes\]\]' your-topology.toml` — must equal validator
count.

## 2. Coordinator: generate genesis bundle

```sh
pyde testnet \
  --validators 16 \
  --chain-id 7331 \
  --node-addrs ./testnet-16v.toml \
  --out ./testnet-bundle
```

This produces `./testnet-bundle/`:

```
testnet-bundle/
├── genesis.toml              # initial allocations + validator set
├── faucet.key                # faucet signing key (raw bytes)
├── node-0/
│   ├── config.toml           # baked with chain_id=7331, port from
│   │                         # topology, bootstrap_peers = the 15
│   │                         # other validators' DNS multiaddrs
│   ├── validator.key         # raw FALCON signing key (NOT yet
│   │                         # encrypted; operator does that)
│   ├── node.key              # libp2p Ed25519 identity
│   ├── threshold.share       # validator's share of the threshold
│   │                         # decryption key (MEV protection)
│   └── threshold.pk          # public threshold pubkey
├── node-1/ … node-15/        # one directory per validator
```

Inspect:

```sh
head -3 ./testnet-bundle/node-0/config.toml
# Should print:
# region: us-east-1
# host:   validator-0.testnet.pyde.network
# [node]

grep '^chain_id' ./testnet-bundle/genesis.toml
# chain_id = 7331

grep -c '^\[\[validators\]\]' ./testnet-bundle/genesis.toml
# 16
```

Each `node-N/config.toml` already has the full mesh of bootstrap_peers
pointing at the other 15 validators' DNS. Operators do NOT need to
copy multiaddrs from each other — the topology file you supplied
already wired them.

## 3. Coordinator: distribute keys

Each operator gets the SINGLE directory matching their slot:

| Operator | Bundle dir |
|---|---|
| validator-0 | `./testnet-bundle/node-0/` |
| validator-1 | `./testnet-bundle/node-1/` |
| ... | ... |

Distribute the directory **encrypted, point-to-point**, never via
chat / email / public Git:

```sh
# Coordinator side, per operator:
tar -czf node-0.tar.gz -C ./testnet-bundle node-0
age -r AGE-KEY-OF-OPERATOR-0 -o node-0.tar.gz.age node-0.tar.gz
# Send node-0.tar.gz.age via signal / matrix / whatever the operator agreed to
```

The faucet key (`./testnet-bundle/faucet.key`) stays with whoever runs
the faucet service (often the coordinator). It is NOT part of any
operator bundle.

The bundle root also contains an `accounts.json` file with the dev
EOA private keys + the faucet keypair. This is intentional dev
convenience for E2E test scripts — operators do NOT receive it.
Keep it on the coordinator alongside `faucet.key`. (For an
extra-paranoid public testnet, delete `accounts.json` after
extracting whatever the faucet host needs; the dev EOAs aren't
load-bearing.)

## 4. Operators: encrypt + start their node

Each operator decrypts their bundle on their target host, then:

```sh
# 1. Pick a strong passphrase (at-rest encryption for validator.key,
#    audit 221). Store it in a password manager — losing it means
#    re-keying the validator on-chain (`auth_key.rotate` flow).
export PYDE_VALIDATOR_PASSPHRASE='your-strong-passphrase'

# 2. The bundle's validator.key is in legacy raw-bytes format.
#    `pyde run` loads it and logs a deprecation warning every
#    start until the file is re-saved encrypted. Today the
#    encryption-on-first-load auto-upgrade is NOT wired (see
#    audit 221) — the warning is informational and consensus
#    proceeds normally. To silence it, rotate the validator key
#    (auth_key.rotate flow) so the new key is generated locally
#    *with* the passphrase set; the new keygen path writes
#    encrypted by default.
pyde run \
  --role validator \
  --config /var/lib/pyde/config.toml \
  --datadir /var/lib/pyde
```

For systemd, set `Environment="PYDE_VALIDATOR_PASSPHRASE=…"` in the
unit file via `systemctl edit pyde-validator` — see
[`run-validator.md` § 3](./run-validator.md) for the full template.

Firewall:

| Port | Direction | Purpose |
|---|---|---|
| `30303/tcp` + `30303/udp` | inbound | libp2p (TCP + QUIC). **Required.** |
| `8545/tcp` | inbound | JSON-RPC. Recommended TLS reverse-proxy via nginx ([§6 of `run-validator.md`](./run-validator.md#6-network-exposure--firewall)) — do NOT bind to `0.0.0.0` directly. |
| `9090/tcp` | inbound (loopback only) | Prometheus metrics. |

## 5. Coordinator: smoke verification

Once 11+ of the 16 validators are up (BFT quorum threshold for n=16:
`2*16/3 = 11`), the chain begins producing blocks. Verify from any
node's RPC:

```sh
# 5.1 — chain advancing
curl -s http://your-node:8545 -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"pyde_blockNumber","params":[],"id":1}'
# Run twice, 1 second apart. Result should advance by ~2 (slot rate
# 400ms = 2.5 blocks/sec, accounting for view-change recovery).

# 5.2 — committee complete
curl -s http://your-node:8545 -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"pyde_getValidators","params":[],"id":1}' \
  | jq '.result.count'
# Should print: 16
# (`.result` is { count, validators }, not an array — `.result | length`
# returns the field count of the object, which is always 2.)

# 5.3 — finality progressing
curl -s http://your-node:9090/metrics | grep -E 'pyde_finality_lag|pyde_block_lag'
# pyde_finality_lag should stay under ~10 in steady state.
# pyde_block_lag should stay under 5.

# 5.4 — encrypted-tx pipeline alive
# Submit a small encrypted-path test tx and confirm it commits.
# See loadgen_sustained.rs (PYDE_LOADGEN_ENCRYPTED=1) for the
# full instrument; even a 30-second 50-TPS run is enough to
# validate the pipeline end-to-end.
```

If `pyde_finality_lag` keeps growing, you have either:
- A regional partition (check connectivity between regions with
  `nc -zv validator-N.testnet.pyde.network 30303`)
- A sub-quorum bring-up (count the `pyde_peers_connected` gauge across
  all running nodes; sum must be ≥ `quorum-1` for finality)
- A clock-skew issue (validators drift > ±200ms at slot rate cause
  view-change cascades; sync NTP on every host)

## 6. Coordinator: announce + open RPC

Once smoke passes:

1. Stand up a public RPC fleet. Validator RPCs are loopback-bound by
   default. Run **separate full nodes** behind a load balancer with
   TLS — never expose validator RPCs publicly. The complete operator
   playbook (topology, nginx template, X-Forwarded-For pairing,
   recovery procedures) is at [`docs/public-rpc.md`](./public-rpc.md);
   a drop-in nginx config is at
   `deploy/nginx-pyde-rpc.conf.example`.
2. Spin up the [pyde-explorer](../../pyde-explorer/) — its backend
   indexer needs `PYDE_RPC_URL` pointed at one full node, frontend
   `NEXT_PUBLIC_API_URL` pointed at the backend.
3. Run the faucet (`pyde faucet --rpc … --private-key
   ./testnet-bundle/faucet.key --port 8080`) on a separate host with
   per-IP rate limiting. See `crates/node/src/faucet.rs`.
4. Publish the testnet announcement: `chain_id`, `bootstrap_peers`
   (operator DNS list), public RPC URL, faucet URL, explorer URL,
   `connect-to-testnet.md` link.

Done.

## Recovery / replacement procedures

### A validator can't start (key corrupt, host migration)

1. Operator regenerates their FALCON keypair locally.
2. Operator submits an `auth_key.rotate` tx signed with their **old**
   key, naming the new pubkey. See
   [`run-validator.md § 8 — Rotate the validator FALCON key`](./run-validator.md#rotate-the-validator-falcon-key).
3. Wait for the rotate tx to land in a hard-finalized block. New key
   replaces old in `auth_keys` on chain.
4. Operator restarts node with the new key on disk.

If the operator lost the old key entirely (no rotate tx possible),
they're ejected at the next epoch boundary via the liveness slashing
path. Rejoining requires a new stake-deposit at the new pubkey —
treat as a fresh validator.

### One whole region goes offline

For 16 validators / 3 regions / `f=5`: losing all 5 in one region
leaves 11 alive, exactly at the quorum threshold. Chain keeps
producing blocks but has zero further fault tolerance — a single
additional validator going down halts finality.

Mitigation: ensure operators in the same region are spread across at
least two cloud providers / two availability zones. The topology
file's `region = ...` is informational only — Pyde doesn't actually
enforce regional policy in consensus.

### Key compromise

Treated as malicious. The compromised validator should be slashed
(if double-signing is observed) or unstaked + ejected via governance
multisig. See `crates/consensus/src/slashing.rs` for the slash flow
and [`run-validator.md` Slashing section](./run-validator.md#slashing--what-to-watch).

---

## Known testnet trust assumptions (audit 312)

The threshold-decryption MEV pipeline ships with three soundness
gaps that are *acceptable for an operator-trusted testnet* but
must be closed before mainnet. The testnet committee is assumed to
be honest-majority + non-Byzantine. Operators should be aware of
these so the threat model is explicit:

1. **Centralized genesis keygen.** `pyde testnet` runs
   `threshold_keygen` on a single coordinator host that produces
   every validator's threshold-key share. Anyone with read access
   to the coordinator filesystem at ceremony time owns the
   threshold secret forever — PSS refresh rotates *shares*, not
   the underlying secret value. **Coordinator hosts MUST be
   destroyed (zeroed disks, evicted from any backup system) once
   the bundles are distributed.** Treat the coordinator like a
   one-shot HSM. Mainnet will replace this with a Distributed Key
   Generation (DKG) protocol — tracked as
   `AUDIT_FINDINGS_2.md` 312.

2. **PSS refresh entropy is deterministic.** `pss_refresh` in
   `crates/crypto/src/threshold.rs` derives "fresh randomness"
   from `(epoch, validator_index)` via `random_goldilocks`,
   which is a deterministic Poseidon2 hash. Anyone observing the
   public epoch number can recompute every validator's "secret"
   PSS contribution. PSS refresh therefore provides ZERO actual
   secrecy on testnet — the protocol runs as documented but the
   refresh ceremony is theatrical. Acceptable for a testnet
   committee that trusts itself; mainnet must accept per-validator
   `OsRng` entropy and FALCON-sign each contribution.

3. **Decryption shares are not authenticated.**
   `generate_decryption_share` produces `(index, blinded_shares)`
   with no signature; `combine_shares` only checks index
   uniqueness. A Byzantine committee member can submit shares
   with someone else's index to displace honest shares from the
   threshold-`t` set, griefing the entire decryption pipeline
   until the proposer falls back to a smaller share set or times
   out. Operator-trusted testnet committees won't exhibit this;
   mainnet requires a FALCON signature over `(ct_hash || index ||
   blinded_shares_hash)` with verification before admission into
   the combine set.

**Operator action required:** when generating a testnet bundle on
the coordinator host, do the ceremony in an air-gapped /
ephemeral-VM environment. After distributing the per-validator
directories (encrypted, point-to-point per Phase 3), shred the
bundle directory + zero the coordinator host's disk before
returning it to general use. Keys produced on a compromised
coordinator silently compromise the entire MEV pipeline for the
testnet's lifetime.

---

## Reference: testnet identity constants

Defined in `crates/net/src/discovery.rs`:

```rust
pub const MAINNET_CHAIN_ID: u64 = 1;
pub const TESTNET_CHAIN_ID: u64 = 7331;   // canonical public testnet
pub const DEVNET_CHAIN_ID: u64 = 31337;   // laptop-local devnets
```

The startup-time bootstrap-peer hard gate
(`pyde_node::node::check_bootstrap_config`) refuses any non-devnet
chain that launches with empty `[network].bootstrap_peers` — operators
who skip the topology-file step get a clear error naming their chain
("refusing to start public testnet (chain_id=7331) with no bootstrap
peers …") instead of a silent fork-of-one.
