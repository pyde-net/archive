# Pyde JSON-RPC Reference

The Pyde node exposes a JSON-RPC 2.0 interface on `[rpc].port` (default
8545). Methods are namespaced `pyde_*`. The full source of truth lives
in `crates/node/src/rpc.rs` — this page is a quick reference.

> **Convention:** addresses are 32-byte hex with `0x` prefix
> (example: `0xa264...`). Balances and gas values are decimal strings
> (`"1000000000"`). Slot / block numbers are unsigned 64-bit hex
> (`"0x42"`).

## State queries

### `pyde_getBalance(address)`
Account balance in quanta (10⁻⁹ PYDE).

```sh
curl -s -X POST http://127.0.0.1:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"pyde_getBalance","params":["0x<addr>"],"id":1}'
```

### `pyde_getTransactionCount(address)`
Current sender nonce (the next nonce to use). Hex-encoded.

### `pyde_getCode(address)`
Contract bytecode at `address`, hex. Returns `0x` for EOAs.

### `pyde_getStorageAt(address, slot)`
Storage word at the given slot, hex.

### `pyde_chainId()`
Network chain id (decimal-string).

### `pyde_blockNumber()`
Current head slot, hex.

### `pyde_stateRoot()`
Current state root (32-byte hex).

### `pyde_getBlockByNumber(slot, full_tx)`
Block at slot, optionally with full tx bodies.

### `pyde_getBlockByHash(hash, full_tx)`
Block by header hash.

### `pyde_getValidators()`
Active validator set: addresses, public keys, voter indexes, stake.

### `pyde_syncing()`
Returns the local node's chain head as
`{ headSlot, epoch, stateRoot }`. Compare `headSlot` against the
network tip you observe from a peer (or via Prometheus
`pyde_block_lag` gauge) to tell whether you're caught up.

### `pyde_gasPrice()`
Current `base_fee` (gwei-equivalent, decimal-string).

## Transaction submission

### `pyde_sendRawTransaction(hex)`
Submit a wire-encoded signed transaction. The transaction must include
a valid FALCON-512 signature over `Transaction::hash()`.

```sh
curl -s -X POST http://127.0.0.1:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"pyde_sendRawTransaction","params":["0x<hex>"],"id":1}'
```

Returns the tx hash on success, or a JSON-RPC error:
- `-32000` "tx rejected (duplicate, rate-limited, or signature failed)"
- `-32001` "encrypted-tx ingress disallowed on this chain_id"
- `-32009` per-sender mempool cap (audit 027 / M1)
- `-32010` `(sender, nonce)` duplicate
- `-32011` global mempool cap

### `pyde_sendTransaction(tx_object)`
Higher-level submit — takes structured fields. Devnet only
(`chain_id == 31337`); production paths must go through
`sendRawTransaction` to enforce signature presence.

### `pyde_sendRawEncryptedTransaction(hex)`
Submit a threshold-encrypted MEV-protected transaction. The wire format
is `EncryptedTx` (`crates/mempool/src/encrypted.rs`). Per-sender rate
limit: 10 enc-tx/sec (audit 027).

### `pyde_getThresholdPublicKey()`
Returns the committee's threshold public key (hex). Required to encrypt
a transaction client-side before submitting via the encrypted path.

### `pyde_call(tx_object)`
Read-only contract execution. Doesn't broadcast a tx; runs against
current state and returns the call's return data.

### `pyde_estimateGas(tx_object)`
Returns gas estimate for a tx (no broadcast).

### `pyde_createAccessList(tx_object)`
Returns the access list (per-storage-key reads/writes) the tx would
trigger. Required for parallel execution (audit task 077).

## Receipts + logs

### `pyde_getTransactionReceipt(tx_hash)`
Receipt for a committed tx: status, gas_used, effective_gas_price,
logs, contract_address (for `Deploy` txs).

### `pyde_getTransactionStatus(tx_hash)` (M4)
Lightweight status query for clients polling pre-receipt:
- `{ included: true, success, gasUsed, effectiveGas }` if committed
- `{ pending: true, ageSecs }` if in mempool
- `{ not_found: true }` if neither

### `pyde_getLogs(filter)`
Filtered log lookup. `filter` supports `{ from_slot, to_slot, address,
topics }`.

## Mempool

### `pyde_mempoolSize()`
Plaintext-mempool depth. Encrypted-mempool depth is exposed via the
`pyde_encrypted_mempool_size` Prometheus gauge (audit 222).

## Subscriptions (WebSocket only)

The same RPC server accepts WebSocket connections at the same port.
Subscriptions deliver server-pushed events:

### `pyde_subscribe(topic)`
Generic subscription. `topic` ∈ { `"newHeads"`, `"newPendingTransactions"`,
`"logs"` }.

### `pyde_subscribePending`
Streams every new pending tx as the hex tx hash.

### `pyde_subscribeLogs(filter)`
Streams matching logs from new blocks.

Unsubscribe via the matching `pyde_unsubscribe*` method with the
subscription id returned by the subscribe call.

## Error codes (recap)

| Code | Meaning |
|---|---|
| `-32000` | Generic tx rejection (duplicate / rate-limited / bad sig) |
| `-32001` | Encrypted-tx ingress disallowed for this chain_id |
| `-32009` | Per-sender mempool cap |
| `-32010` | `(sender, nonce)` duplicate |
| `-32011` | Global mempool cap |

## Rust SDK

For type-safe access from Rust, prefer the SDK over raw JSON-RPC:

```rust
use pyde_rust_sdk::Provider;

let provider = Provider::new("http://127.0.0.1:8545");
let head = provider.get_block_number().await?;
let balance = provider.get_balance(&addr).await?;

// Submit (caller signs the Transaction themselves):
let resp = provider.send_transaction(&signed_tx).await?;
let receipt = provider.wait_for_receipt(&resp.hash, 30_000).await?;
```

See [`crates/pyde-rust-sdk/README.md`](../crates/pyde-rust-sdk/README.md)
for the full surface.
