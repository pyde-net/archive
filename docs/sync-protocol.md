# Pyde Sync Protocol

How a fresh `pyde-node` reaches the live chain head and joins the network.
Audience: validator operators reading the source for the first time,
security auditors, future contributors. For the operator runbook
("which command do I run?") see [`connect-to-testnet.md`](./connect-to-testnet.md).

> **Status note.** Parts of this document describe the target shape of
> the sync protocol as Pyde moves from devnet → public testnet. Items
> marked **(planned)** are the contract the sync-infrastructure work
> (task tracker #82) validates itself against. Items without that
> marker reflect the current implementation in `crates/node/src/sync.rs`,
> `crates/node/src/state_manager.rs`, and `crates/net/src/propagation.rs`.

## Why this exists

Pyde is post-quantum and targets high throughput at mainnet. Under the
**projected** sustained-load assumption of ~300K TPS and ~84 MB blocks
(FALCON-512 sigs at ~660 bytes/tx dominate block size — this is a
design target, not a measured number; see task #86 for the measurement
work), downloading every block since genesis is impossible: a year of
chain history projects to multiple petabytes, and re-verifying every
signature would take a single CPU literal years. Even at one or two
orders of magnitude lower throughput, the constraint is the same shape
— and it hits every L1 at scale. The standard answer is
**weak-subjectivity (WS) checkpoint + state snapshot + replay forward**.
Pyde follows that pattern.

This doc walks the lifecycle stage by stage, calls out the trust
assumption planted at each step, and shows how every byte after the
checkpoint is cryptographically verified.

## The trust chain

There is exactly one operator-trusted input: **the genesis file**,
which ships with the binary and contains:

- `chain_id`
- Initial committee FALCON public keys
- Initial threshold pubkey (Kyber-768 + Shamir share aggregate)
- Genesis state hash (root of the JMT at slot 0)
- Block time, epoch length, etc. — protocol parameters

Everything downstream chains back to those bytes:

```
  genesis_file
    │  (operator trust)
    ▼
  initial committee FALCON pubkeys
    │  used to verify ▼
  WS checkpoint multisig                  ──→ trust state_root @ slot S
    │  used to anchor ▼
  state snapshot at slot S                ──→ rebuild JMT, verify root
    │  used to ground replay ▼
  block headers S+1, S+2, …               ──→ parent_hash chain + QC sigs
    │  bodies executed against ▼
  state at slot S → state at head         ──→ post-block state_root
    │  matches next block's qc_previous ▼
  live head, byte-identical to honest peers
```

The single trust point is the genesis file (and, transitively, whoever
signed off on the WS checkpoint that's quorum-signed by initial-committee
keys). Every other byte is verified.

## Lifecycle

A new node moves through nine stages on its way to live participation.
Stage 9 is validators-only.

### Stage 0 — Boot

| Has         | Genesis file, an empty datadir, the binary                                   |
| Does        | Generate a libp2p identity keypair, open RPC port, start logging            |
| Trust delta | Genesis is loaded — operator-side trust anchor                              |
| Failure     | Wrong/tampered genesis file → wrong chain_id mismatches every later peer    |

```
$ pyde-node --datadir ~/.pyde --bootstrap-from <bootstrap-list>
```

### Stage 1 — Peer discovery

| Has         | Identity, bootstrap list                                                     |
| Does        | Dial bootstrap peers; libp2p Identify exchanges peer info; Kademlia DHT populates more peers; AutoNAT v2 reports public addressability; Circuit Relay v2 establishes if behind NAT *(planned, task #79 lever 3)* |
| Produces    | Live peer set, each tagged with FALCON pubkey ↔ libp2p PeerId mapping        |
| Failure     | All bootstrap peers dead → node hangs at this stage; clear timeout + error required |

### Stage 2 — Fetch a signed WS checkpoint **(planned)**

| Has         | Live peers, knowledge of who's in the *initial* committee (from genesis)    |
| Does        | Send `GetLatestCheckpoint` to several peers; receive `WSCheckpoint { slot, block_hash, state_root, FALCON_multisig[] }`; verify each FALCON sig in the multisig against a pubkey from the committee active at `slot`; require ≥ 2/3 stake quorum |
| Produces    | Verified `(slot S, block_hash H, state_root R)` — canonical chain pin       |
| Trust delta | "I trust the chain at slot S because 2/3 of slot-S's committee signed for it" |
| Failure     | All peers serve invalid/stale checkpoints → eclipse attack suspected; refuse to proceed; require operator override |

The bootstrap edge case: at first connection, the new node only knows
the *initial* committee from the genesis file. If the chain has been
running long enough that the active committee has rotated multiple
times, the new node needs to follow the rotation chain to find the
committee active at slot S. Concretely: trust initial committee →
verify checkpoint at end of epoch 1 → that checkpoint carries the
committee for epoch 2 → verify checkpoint at end of epoch 2, and so
on. Standard pattern; same shape as Tendermint / Cosmos light client.

### Stage 3 — Download state snapshot **(planned)**

| Has         | Verified `(S, H, R)`                                                         |
| Does        | Send `GetSnapshotManifest(slot=S)` to a peer; receive a JMT-subtree descriptor `[(subtree_path, subtree_root_hash, byte_size)]`; request subtrees in parallel from multiple peers via `GetSnapshotSubtree(path)`; rebuild each subtree locally; verify subtree roots; compose to global root; verify equals `R` |
| Produces    | Full world state at slot S — every account, every contract slot, every config entry |
| Verifies    | Cryptographic match against the WS-checkpoint state root                    |
| Failure     | Subtree mismatch → discard, request from another peer; persistent mismatch → eclipse-attack suspected |

Reed-Solomon parity *(planned — currently stubbed at
`crates/net/src/propagation.rs:225`)* lets a slow or dropping peer's
chunks be reconstructed from other peers' parity, so the snapshot
download isn't capped by the slowest peer.

### Stage 4 — Fetch headers from S+1 to head

| Has         | State at S, list of peers, current chain tip from peers                      |
| Does        | `GetHeaders(start=S+1, count=N)` in batches; verify `header[i+1].parent_hash == header[i].block_hash`; verify each header's QC FALCON sigs against the committee active at that slot |
| Produces    | Cryptographically continuous header chain from S+1 to head                  |
| Failure     | Parent-hash break → peer is malicious or on a fork; switch peer             |

### Stage 5 — Fetch block bodies

| Has         | Header chain, peer set                                                       |
| Does        | Parallel block-body fetch across peers *(planned — current `chain_sync` is single-peer per request)*; once mempool starts populating, compact-block reconstruction with `GetBlockTxs` *(planned per task #80)* fills only the missing txs instead of redownloading whole blocks |
| Produces    | Full block bodies S+1..head, persisted to local block store                 |

### Stage 6 — Replay blocks (execute forward)

| Has         | Bodies + headers from S+1, state at S                                        |
| Does        | Apply each block sequentially via `process_full_block_with_aot_and_checkpoint`; sigs already verified at fetch time per the verify-once architecture *(planned per task #80)*; each block's post-state root matches the next block's `qc_previous` commitment |
| Produces    | State at the block-store head (which may be behind live head)               |
| Verifies    | Post-execution state root agrees with chain consensus at every step         |
| Failure     | State-root mismatch → peer fed wrong body for a real header; invalidate, re-fetch |

### Stage 7 — Catch up to the moving target

The chain has been advancing while Stages 4-6 ran. Repeat fetch-and-replay
until the new node's catch-up rate exceeds the chain's production rate.
At sustained 300K TPS this only converges if sync throughput beats
block-production throughput.

`pyde-node sync-status` *(planned)* shows progress:

```
state:  45/200 GB     ETA  3h 20m
blocks: 1234/12000    ETA    12m
head_slot: 12000      gap: 56 slots
```

Operator UX requirement: progress is visible, ETA is honest, "we are
sync'd" is a clear binary indicator.

### Stage 8 — Transition to live consensus

| Has         | State at live head                                                           |
| Does        | Subscribe to gossip topics (blocks, votes, view-change, decryption shares, randomness); listen-only for ~few slots to confirm clean apply; declare "synced" via metrics; if a validator, begin participating in HotStuff (proposing on VRF win, voting on proposals) |
| Failure     | Wall-clock skew → proposals are early/late; NTP is required at the operator level |

### Stage 9 — Committee membership + threshold share *(validators only)*

This is **separate from chain sync**. Chain sync makes you a *full
node*; becoming a *validator* requires:

1. Stake registered on-chain (see `docs/run-validator.md`)
2. Election to the committee at the next epoch boundary
3. Threshold-share state for the new committee, delivered via the
   cross-committee resharing protocol already on-chain

At the epoch boundary, if elected, you receive your share via the
resharing artifacts in committed state. From that slot onward you
participate in encrypted-tx decryption alongside the rest of the
committee.

## Wire formats

Sketches; canonical encoders live in `crates/node/src/wire.rs`.

### `WSCheckpoint` *(planned)*

```
{
  slot: u64,
  block_hash: [u8; 32],
  state_root: [u8; 32],
  committee_epoch: u64,                 // which committee signed
  signatures: Vec<{                     // FALCON multisig
    voter_index: u8,
    signature: Vec<u8>,                 // FALCON-512, ~660 bytes each
  }>,
}
```

Multisig requires ≥ ceil(2/3 × committee_size) entries. Each entry's
`voter_index` selects a pubkey from the committee active at
`committee_epoch`.

### `GetSnapshotManifest` / `SnapshotManifest` *(planned)*

```
GetSnapshotManifest { slot: u64 }

SnapshotManifest {
  slot: u64,
  state_root: [u8; 32],
  subtrees: Vec<{
    subtree_path: Vec<u8>,              // path bits in the JMT
    subtree_root_hash: [u8; 32],        // for verification
    byte_size: u32,                     // for download budgeting
  }>,
  reed_solomon_params: { k: u8, m: u8 } // when finished
}
```

### `GetSnapshotSubtree` / `SnapshotSubtree` *(planned)*

```
GetSnapshotSubtree { slot: u64, subtree_path: Vec<u8> }

SnapshotSubtree {
  subtree_path: Vec<u8>,
  entries: Vec<(key: [u8; 32], value: Vec<u8>)>,
  internal_nodes: Vec<JmtInternalNode>,
}
```

Receiver rebuilds the subtree, computes its root, MUST match the
`subtree_root_hash` from the manifest.

### `GetHeaders` / `Headers`

Already implemented; see `crates/node/src/sync.rs`. Multi-peer
parallel fetch *(planned)* on top of the existing single-peer-per-request
shape.

### `GetBlockTxs` / `BlockTxsResponse`

Half-built. Types and wire encoders exist
(`crates/net/src/propagation.rs:137,146`,
`crates/node/src/wire.rs:436,451`); the request/response wiring is the
work in task #80. Lets a syncing node fetch *only* the missing txs from
a partially-reconstructable block instead of the whole-block-sync
fallback the current `node.rs:1812` code uses.

## Failure modes

| Stage | Failure                                | Recovery                                     |
|-------|----------------------------------------|----------------------------------------------|
| 0     | Wrong genesis file                     | Operator error; clear chain_id mismatch log  |
| 1     | All bootstrap peers unreachable        | Timeout + actionable error                   |
| 2     | All peers serve invalid checkpoints    | Refuse to proceed; require operator override |
| 3     | Subtree root mismatch                  | Discard, request from another peer           |
| 4     | Header chain break (parent_hash mismatch) | Switch peer                              |
| 4     | QC sigs invalid                        | Peer is malicious; ban + score down          |
| 5     | Body unavailable for a header          | Re-request from another peer                 |
| 6     | State root mismatch after execution    | Body is wrong; invalidate, re-fetch          |
| 7     | Cannot catch up to live head           | Throughput problem; needs operator visibility |
| 8     | Wall-clock skew                        | Operator NTP issue; clear diagnostic         |
| 9     | Threshold share missing                | Wait for next reshare; check committee membership |

## Eclipse-resistance assumptions

The protocol assumes that not all of a new node's peers are byzantine.
Specifically:

- At Stage 2, the new node trusts the WS checkpoint that ≥ 2/3 of
  slot-S's committee signed. An adversary controlling 2/3 of stake at
  slot S can fake a checkpoint, but at that point they control consensus
  anyway.
- At Stages 3-5, peers serving wrong data are detected by cryptographic
  mismatch (subtree roots, parent_hash chain, QC sigs). The new node
  discards and re-requests. Worst case: it fails to find an honest peer
  and times out.
- The bootstrap list (CLI / genesis-shipped fallback) is the operator's
  initial peer set. It must contain *at least one* honest endpoint; the
  protocol's later stages can recover from byzantine majorities at any
  *runtime* peer set.

## See also

- [`connect-to-testnet.md`](./connect-to-testnet.md) — operator runbook for joining as a full node
- [`run-validator.md`](./run-validator.md) — extension for becoming a validator (Stage 9)
- [`testnet-bringup.md`](./testnet-bringup.md) — coordinator runbook for the genesis ceremony
- [`oncall.md`](./oncall.md) — operator response procedures
- `crates/node/src/sync.rs` — current sync orchestration
- `crates/node/src/state_manager.rs` — `import_snapshot` / `export_snapshot` entry points
- `crates/net/src/propagation.rs` — compact-block + erasure-coding primitives
- `crates/node/src/wire.rs` — canonical wire encoders / decoders
