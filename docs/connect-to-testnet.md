# Connect to Pyde Testnet

This guide walks you through running a full node against the Pyde
testnet, verifying that you're synced, getting test tokens from the
faucet, and submitting your first transaction.

> **Status:** the testnet network is launching imminently. Bootstrap
> peers, faucet, and explorer URLs in this guide are placeholders —
> the published values appear in the launch announcement and in
> `crates/net/src/discovery.rs:TESTNET_BOOTSTRAP`. Until then this
> guide is best run against a local devnet (see "Local devnet" at
> the bottom).

## Prerequisites

- 64-bit Linux or macOS (Windows via WSL works but is untested)
- 8 GB RAM minimum (16 GB recommended for an indexer / archive node)
- 200 GB SSD (testnet state grows steadily; archive node needs more)
- Outbound TCP/30303 + UDP/30303 (P2P), optional inbound for better mesh peering
- Rust 1.75+ if building from source

## 1. Get the binary

### Option A — build from source

```sh
git clone https://github.com/zarah-s/pyde
cd pyde
cargo build --release
# Binary lands at ./target/release/pyde
```

### Option B — prebuilt release

Download the latest `pyde-<version>-<os>-<arch>.tar.gz` from the
GitHub releases page and extract `pyde` into `$PATH`.

```sh
tar -xzf pyde-<version>-linux-x86_64.tar.gz
sudo mv pyde /usr/local/bin/
pyde --version
```

## 2. Generate a node identity

A full node needs a libp2p Ed25519 keypair and a data directory.
Both are created automatically on first run if absent:

```sh
mkdir -p ~/.pyde-testnet
pyde run \
  --role full \
  --datadir ~/.pyde-testnet \
  --port 30303 \
  --rpc-port 8545
```

On first start the node generates `~/.pyde-testnet/node.key` (libp2p
identity) and creates an empty state DB at
`~/.pyde-testnet/state/`.

You can stop the node now (Ctrl-C) — we'll add bootstrap peers
next.

## 3. Configure bootstrap peers

### Quickstart: one-line CLI flag

```sh
pyde run \
  --role full \
  --datadir ~/.pyde-testnet \
  --port 30303 \
  --rpc-port 8545 \
  --bootstrap "/dns4/seed-0.testnet.pyde.network/tcp/30303/p2p/<peer-id>" \
  --bootstrap "/dns4/seed-1.testnet.pyde.network/tcp/30303/p2p/<peer-id>"
```

### Recommended: write a config file

```sh
pyde default-config > ~/.pyde-testnet/config.toml
```

Edit `~/.pyde-testnet/config.toml`:

```toml
[node]
role = "full"
chain_id = 1   # mainnet placeholder; testnet chain_id will be published at launch
datadir = "/home/<you>/.pyde-testnet"
dev_mode = false

[network]
port = 30303
max_peers = 50
bootstrap_peers = [
  "/dns4/seed-0.testnet.pyde.network/tcp/30303/p2p/<peer-id>",
  "/dns4/seed-1.testnet.pyde.network/tcp/30303/p2p/<peer-id>",
  "/dns4/seed-2.testnet.pyde.network/tcp/30303/p2p/<peer-id>",
]

[rpc]
enabled = true
listen = "127.0.0.1"   # 0.0.0.0 if you want external RPC clients
port = 8545

[metrics]
enabled = true
port = 9090
```

Then run with `--config`:

```sh
pyde run --config ~/.pyde-testnet/config.toml
```

> **Heads-up:** `pyde run` refuses to start a `chain_id == 1` node
> with an empty `bootstrap_peers` list (audit 219). If you see
> `refusing to start mainnet (chain_id=1) with no bootstrap peers`,
> you forgot the bootstrap entries.

## 4. Watch initial sync

The node will print sync progress as it catches up:

```
INFO peer connected peer_id=12D3KooW... addr=/dns4/seed-0...
INFO sync batch processed received=64 processed=64 head=64
INFO sync batch processed received=64 processed=64 head=128
...
```

On a healthy network, you should see `head_slot` advancing.

If you get more than `SNAPSHOT_THRESHOLD = 1000` slots behind, the
node automatically switches from block-by-block sync to chunked
state-snapshot sync (audit 220). Snapshot sync downloads the
canonical state at a recent finality checkpoint in one shot, then
continues block-by-block from there.

Confirm sync via RPC. `pyde_syncing` reports current head + epoch
+ state root:

```sh
curl -s -X POST http://127.0.0.1:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"pyde_syncing","params":[],"id":1}'
# → { "headSlot": 41728, "epoch": 41, "stateRoot": "0x..." }
```

`pyde_blockNumber` returns the current head slot directly:

```sh
curl -s -X POST http://127.0.0.1:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"pyde_blockNumber","params":[],"id":1}'
```

Re-poll every few seconds. Once `headSlot` stops advancing on the
network side and matches yours, you're synced.

## 5. Get test tokens

The testnet faucet dispenses test tokens to any address that has
not received tokens in the last hour.

### Web faucet

Visit `https://faucet.testnet.pyde.network`, paste your address,
solve the captcha. Tokens land within one slot (~400 ms) once the
faucet's tx is included.

### CLI / script

```sh
curl -s -X POST https://faucet.testnet.pyde.network/api/request \
  -H 'Content-Type: application/json' \
  -d '{"address": "0x<your-32-byte-address-hex>"}'
```

Response includes the faucet's tx hash; track it via your local
RPC:

```sh
curl -s -X POST http://127.0.0.1:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"pyde_getTransactionReceipt","params":["0x<tx-hash>"],"id":1}'
```

## 6. Send your first transaction

The Rust SDK exposes `Provider` for read + submit, plus
`build_raw_encrypted_tx` for encrypted submission. You sign the
plaintext `Transaction` with FALCON-512 yourself before sending:

```rust
use pyde_crypto::falcon::{falcon_keygen, falcon_sign};
use pyde_rust_sdk::Provider;
use pyde_tx::types::Transaction;

let provider = Provider::new("http://127.0.0.1:8545");
let (pk, sk) = falcon_keygen()?;
let from = pyde_account::address::derive_eoa_address(pk.as_bytes());

let chain_id = provider.get_chain_id().await?;
let nonce = provider.get_nonce(&from).await?;
let base_fee = provider.get_gas_price().await?;

let mut tx = Transaction { /* to, value, gas_limit, ... */ };
tx.from = from;
tx.nonce = nonce;
tx.chain_id = chain_id;
let sig = falcon_sign(&sk, &tx.hash())?;
tx.signature = sig.as_bytes().to_vec();

let resp = provider.send_transaction(&tx).await?;
let receipt = resp.wait(30_000).await?;
println!("tx hash {} success={}", receipt.tx_hash, receipt.success);
```

For raw JSON-RPC, see [`rpc-reference.md`](./rpc-reference.md).
The integration test `crates/node/tests/multi_node_encrypted_lifecycle.rs`
is a working end-to-end example covering FALCON sign + submit +
receipt polling.

## 7. (Optional) Encrypted MEV-protected transactions

Pyde offers a threshold-encrypted mempool for MEV protection. Txs
submitted via `pyde_sendRawEncryptedTransaction` are decrypted only
*after* their order in the block is committed, blocking
front-running.

Per-sender rate limit is **10 enc-txs/sec** by design (audit 027 —
spam defense). Real-time use cases (DEXes, oracles) sit well below
this; if you need higher rates, batch into multiple sender keys.

See the encrypted-tx integration test
(`crates/node/tests/multi_node_encrypted_lifecycle.rs`) for an
end-to-end Rust example.

## Troubleshooting

### "refusing to start mainnet (chain_id=1) with no bootstrap peers"

You're missing `network.bootstrap_peers` in your config (or the
`--bootstrap` flag). See section 3.

### Node never reaches network tip

Check peer count via the Prometheus metric on
`http://127.0.0.1:9090/metrics`:

```sh
curl -s http://127.0.0.1:9090/metrics | grep '^pyde_peers '
# → pyde_peers 4
```

If `pyde_peers == 0`, your bootstrap multiaddrs are wrong or your
firewall is blocking outbound TCP/30303 (and UDP/30303 for QUIC).
The `pyde_block_lag` gauge tells you how many slots behind the
network tip you currently are.

### "tx rejected (duplicate, rate-limited, or signature failed verification)"

Three possibilities:
- **Duplicate**: same `(sender, nonce)` already in mempool. Check
  `pyde_getTransactionStatus`.
- **Rate-limited**: per-sender 10 tx/s cap (audit 027). Spread the
  burst across multiple sender keys, or pace at ≥100 ms intervals.
- **Bad signature**: the sender doesn't have a registered FALCON
  pubkey on-chain. Send a `RegisterPubkey` tx first (audit 229).

### Snapshot sync hangs

Snapshots are served by validators only. If you're behind a
firewall that blocks inbound libp2p connections AND the validators
all happen to be load-shedding, you may stall. Try:
- Restart the node (forces a fresh peer set)
- Switch bootstrap peers (different validators serve different
  snapshot chunks)

## Local devnet (run today)

While the public testnet is pre-launch, you can run a local
4-validator devnet to exercise the same flow:

```sh
pyde testnet --validators 4 --out ./devnet --dev
cd devnet
./run.sh                   # starts all 4 nodes
```

This generates per-node configs, validator keys, threshold shares,
and a `run.sh` launch script. RPC for node-0 lands on
`http://127.0.0.1:8545`. Faucet info is in `./devnet/README.txt`.

## Next steps

- [`run-validator.md`](./run-validator.md) — operator guide for
  running a validator node (requires staking, threshold-share key
  custody, and uptime SLAs).
- [`rpc-reference.md`](./rpc-reference.md) — full JSON-RPC method
  list with request/response shapes.
- [Rust SDK](../crates/pyde-rust-sdk/README.md) — type-safe client
  library for Pyde.
