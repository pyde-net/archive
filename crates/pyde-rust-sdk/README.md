# pyde-rust-sdk

Rust SDK for interacting with the Pyde blockchain. Async RPC client, FALCON-512 wallet with AES-256-GCM encrypted keystore, ABI-aware contract interaction, and typed error handling.

---

## Table of Contents

- [Installation](#installation)
- [Getting Started](#getting-started)
- [Provider](#provider)
  - [Connecting to a Node](#connecting-to-a-node)
  - [Chain Queries](#chain-queries)
  - [Account Queries](#account-queries)
  - [Block Queries](#block-queries)
  - [Static Calls](#static-calls)
  - [Gas Estimation](#gas-estimation)
- [Wallet](#wallet)
  - [Creating a Wallet](#creating-a-wallet)
  - [Restoring a Wallet](#restoring-a-wallet)
  - [Encrypted Keystore](#encrypted-keystore)
  - [Exporting Keys](#exporting-keys)
  - [Signing Transactions](#signing-transactions)
- [Transactions](#transactions)
  - [Sending a Transfer](#sending-a-transfer)
  - [Calling a Contract Function](#calling-a-contract-function)
  - [Deploying a Contract](#deploying-a-contract)
  - [SignerProvider (Convenience)](#signerprovider-convenience)
  - [Waiting for Receipts](#waiting-for-receipts)
- [Contract Interaction](#contract-interaction)
  - [Building Calldata](#building-calldata)
  - [Multi-Arg Calls](#multi-arg-calls)
  - [Deploy Data with Constructor Args](#deploy-data-with-constructor-args)
  - [ABI-Aware Reads](#abi-aware-reads)
  - [The Value Enum](#the-value-enum)
  - [Decoding Return Values](#decoding-return-values)
- [Events & Logs](#events--logs)
- [Error Handling](#error-handling)
  - [Error Variants](#error-variants)
  - [Pattern Matching](#pattern-matching)
- [Security](#security)
  - [Keystore Encryption](#keystore-encryption)
  - [File Permissions](#file-permissions)
  - [Post-Quantum Cryptography](#post-quantum-cryptography)
- [Architecture](#architecture)

---

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
pyde-rust-sdk = { path = "../pyde/crates/pyde-rust-sdk" }
tokio = { version = "1", features = ["full"] }
```

---

## Getting Started

```rust
use pyde_rust_sdk::{Provider, Wallet, ContractCall};

#[tokio::main]
async fn main() -> pyde_rust_sdk::Result<()> {
    // 1. Connect to a node
    let provider = Provider::new("http://127.0.0.1:8545");

    // 2. Create a wallet
    let wallet = Wallet::generate()?;
    println!("My address: {}", wallet.address_hex());

    // 3. Check balance
    let balance = provider.get_balance(wallet.address()).await?;
    println!("Balance: {} quanta", balance);

    // 4. Transfer tokens
    let receipt = wallet.transfer(&provider, &recipient, 1_000_000).await?;
    println!("Tx hash: {}", receipt.tx_hash);

    Ok(())
}
```

---

## Provider

### Connecting to a Node

```rust
let provider = Provider::new("http://127.0.0.1:8545");
```

All provider methods are async and return `Result<T, SdkError>`.

### Chain Queries

```rust
let chain_id = provider.get_chain_id().await?;      // u64
let block_num = provider.get_block_number().await?;  // u64
let gas_price = provider.get_gas_price().await?;     // u128 (quanta per gas)
```

### Account Queries

```rust
// Balance in quanta (1 PYDE = 10^9 quanta)
let balance = provider.get_balance(&addr).await?;      // u128

// Nonce for building the next transaction
let nonce = provider.get_nonce(&addr).await?;           // u64

// Contract bytecode (empty vec if EOA)
let code = provider.get_code(&addr).await?;             // Vec<u8>

// Storage slot value
let storage = provider.get_storage_at(&addr, 0).await?; // Vec<u8>
```

### Block Queries

```rust
let block = provider.get_block_by_number(42).await?;  // Option<BlockHeader>
if let Some(b) = block {
    println!("Slot: {}, Proposer: {}", b.slot, b.proposer);
}
```

### Static Calls

Execute a contract function without creating a transaction. No gas consumed.

```rust
let calldata = ContractCall::new("get_count").build();
let result = provider.call(&contract_addr, &calldata).await?; // Vec<u8>
let count = decode_u64(&result);  // Some(42)
```

### Gas Estimation

```rust
let calldata = ContractCall::new("deposit").arg_u64(500).build();
let gas = provider.estimate_gas(&contract_addr, &calldata).await?; // u64
```

---

## Wallet

### Creating a Wallet

```rust
// Generate a new random FALCON-512 keypair (in-memory)
let wallet = Wallet::generate()?;

println!("Address: {}", wallet.address_hex());
println!("Public Key: {} bytes", wallet.public_key().as_bytes().len()); // 897
```

### Restoring a Wallet

```rust
// From combined private key hex (pk + sk = 2178 bytes)
let wallet = Wallet::from_private_key("0xabcdef...")?;

// From individual key objects
let wallet = Wallet::from_keys(public_key, secret_key);

// From encrypted keystore file
let wallet = Wallet::from_keystore(Path::new("wallet.json"), "password")?;

// From encrypted keystore struct (in-memory)
let wallet = Wallet::from_encrypted(&keystore, "password")?;
```

### Encrypted Keystore

Create and manage password-encrypted keystore files.

```rust
// Generate + save encrypted (file permissions set to 600 on Unix)
let wallet = Wallet::create_encrypted(
    Path::new("~/.pyde/wallets/main.json"),
    "my_secure_password"
)?;

// Load later with password
let wallet = Wallet::from_keystore(
    Path::new("~/.pyde/wallets/main.json"),
    "my_secure_password"
)?;

// Export keystore struct (e.g., for database storage)
let keystore = wallet.to_keystore("password")?;
let json = serde_json::to_string_pretty(&keystore)?;
```

### Exporting Keys

```rust
let pk = wallet.public_key_hex();    // "0x..." (897 bytes hex)
let sk = wallet.secret_key_hex();    // "0x..." (1281 bytes hex)
let full = wallet.private_key_hex(); // "0x..." (2178 bytes, pk+sk combined)

// Restore from export:
let restored = Wallet::from_private_key(&full)?;
assert_eq!(wallet.address(), restored.address());
```

### Signing Transactions

```rust
let mut tx = Transaction { /* ... */ };
wallet.sign_transaction(&mut tx)?;
// tx.signature is now populated with FALCON-512 signature
```

---

## Transactions

### Sending a Transfer

Build, sign, send, and wait for confirmation in one call.

```rust
let receipt = wallet.transfer(&provider, &to_addr, 1_000_000).await?;
println!("Success: {}", receipt.success);
println!("Gas: {}", receipt.gas());
println!("Fee: {} quanta", receipt.fee_paid);
```

### Calling a Contract Function

```rust
let calldata = ContractCall::new("deposit").arg_u64(500).build();
let receipt = wallet.send_call(
    &provider,
    &contract_addr,
    calldata,
    100_000_000,  // gas limit
).await?;
```

### Deploying a Contract

```rust
let deploy_data = DeployData::new(constructor_bytes, runtime_bytes)
    .arg_u64(1000)   // constructor arg
    .arg_u64(5)       // constructor arg
    .build();

let receipt = wallet.deploy(&provider, deploy_data, 100_000_000).await?;
// Contract address in receipt.return_data
```

### SignerProvider (Convenience)

Bind a wallet to a provider so you don't pass both every time.

```rust
let signer = SignerProvider::new(&wallet, &provider);

let balance = signer.get_balance().await?;
let receipt = signer.transfer(&to, 1000).await?;
let receipt = signer.send_call(&contract, data, gas).await?;
let receipt = signer.deploy(deploy_data, gas).await?;
let result = signer.call(&contract, &calldata).await?;
let nonce = signer.get_nonce().await?;
```

### Waiting for Receipts

```rust
// Poll until receipt is available (with timeout)
let receipt = provider.wait_for_receipt(&tx_hash, 10_000).await?;

// Send + wait combined (auto-throws on revert)
let receipt = provider.send_and_wait(&signed_tx, 10_000).await?;
```

---

## Contract Interaction

### Building Calldata

```rust
// No args
let data = ContractCall::new("increment").build();

// Single arg
let data = ContractCall::new("deposit").arg_u64(500).build();

// Boolean
let data = ContractCall::new("set_active").arg_bool(true).build();

// Address (32 bytes)
let data = ContractCall::new("set_owner").arg_address(owner_addr).build();

// String (length-prefixed, 8-byte aligned)
let data = ContractCall::new("set_name").arg_string("hello").build();

// U256 (wide integer)
let data = ContractCall::new("set_amount").arg_u256(U256::from(99u64)).build();

// Raw bytes
let data = ContractCall::new("set_data").arg_bytes(&[1, 2, 3]).build();
```

### Multi-Arg Calls

Chain arguments in parameter order.

```rust
let data = ContractCall::new("set_all")
    .arg_string("hello")
    .arg_u64(42)
    .arg_bool(true)
    .arg_u256(U256::from(99u64))
    .arg_address(some_addr)
    .build();
```

### Deploy Data with Constructor Args

```rust
let data = DeployData::new(constructor_bytecode, runtime_bytecode)
    .arg_u64(initial_supply)
    .arg_string("TokenName")
    .build();
```

### ABI-Aware Reads

Load function signatures and get auto-decoded return values.

```rust
// From build artifact JSON
let contract = Contract::from_artifact("out/Counter.json", addr, &provider)?;

// Or manual setup
let mut contract = Contract::new(addr, &provider);
contract.add_function("get_count", "u64", true);
contract.add_function("get_name", "String", true);
contract.add_function("is_active", "bool", true);

// Auto-decoded based on registered return type
let count = contract.read("get_count", &[]).await?;   // Value::U64(1)
let name = contract.read("get_name", &[]).await?;     // Value::String("hello")
let flag = contract.read("is_active", &[]).await?;    // Value::Bool(true)
```

### The Value Enum

Return values are decoded into a `Value` enum supporting all Pyde types.

```rust
pub enum Value {
    U64(u64),
    U128(u128),
    U256(ethnum::U256),
    Bool(bool),
    Address([u8; 32]),
    String(String),
    Bytes(Vec<u8>),
    Vec(Vec<Value>),
    Struct(HashMap<String, Value>),
    Unit,
}

// Accessors
value.as_u64()       // Option<u64>
value.as_string()    // Option<&str>
value.as_bool()      // Option<bool>
value.as_vec()       // Option<&[Value]>
value.as_struct()    // Option<&HashMap<String, Value>>

// Struct field access
value.field("name")  // Option<&Value>

// Vec index access
value.index(0)       // Option<&Value>
```

### Decoding Return Values

Manual decoders for raw return bytes.

```rust
let count = decode_u64(&bytes);     // Option<u64>
let big = decode_u256(&bytes);      // Option<U256>
let flag = decode_bool(&bytes);     // Option<bool>
let addr = decode_address(&bytes);  // Option<[u8; 32]>
let name = decode_string(&bytes);   // Option<String>
let amt = decode_u128(&bytes);      // Option<u128>
```

---

## Events & Logs

### Basic — filter by contract and block range

```rust
let logs = provider.get_logs(&LogFilter {
    from_block: Some(0),
    to_block: Some(100),
    address: Some("0xcontract...".to_string()),
    topics: None,
}).await?;

for log in &logs {
    println!("Contract: {}", log.address);
    println!("Topics: {:?}", log.topics);
    println!("Data: {}", log.data);
}
```

### Filter by event signature (topic[0])

```rust
use pyde_rust_sdk::types::LogFilter;

let transfer_sig = format!("0x{}", hex::encode(
    pyde_crypto::poseidon2::poseidon2_hash(b"Transfer").to_bytes()
));

let logs = provider.get_logs(&LogFilter {
    from_block: Some(0),
    to_block: Some(1000),
    address: None,
    topics: Some(vec![Some(vec![transfer_sig])]),  // only Transfer events
}).await?;
```

### Filter by indexed parameters

```rust
// Transfer events TO a specific address
let logs = provider.get_logs(&LogFilter {
    from_block: None,
    to_block: None,
    address: Some(token_addr.to_string()),
    topics: Some(vec![
        Some(vec![transfer_sig.clone()]),  // topic[0] = event sig
        None,                               // topic[1] = from (any)
        Some(vec![recipient_addr]),         // topic[2] = to (specific)
    ]),
}).await?;
```

### OR matching on a topic position

```rust
// Transfer events FROM alice OR bob
let logs = provider.get_logs(&LogFilter {
    from_block: None,
    to_block: None,
    address: None,
    topics: Some(vec![
        Some(vec![transfer_sig]),
        Some(vec![alice_addr, bob_addr]),  // topic[1] = alice OR bob
    ]),
}).await?;
```

---

## Error Handling

### Error Variants

```rust
pub enum SdkError {
    Rpc(String),                // RPC call returned an error
    Connection(String),          // Can't reach the node
    Signing(String),             // FALCON-512 sign/encrypt failure
    Timeout(String),             // Receipt polling exceeded timeout
    Reverted { gas_used: u64, data: Vec<u8> },  // Tx executed but reverted
    InsufficientBalance { required: u128, available: u128 },
    InvalidAddress(String),      // Bad hex address format
    InvalidResponse(String),     // Malformed RPC response
}
```

### Pattern Matching

```rust
match wallet.transfer(&provider, &to, amount).await {
    Ok(receipt) => {
        println!("Success! Gas: {}", receipt.gas());
    }
    Err(SdkError::Reverted { gas_used, data }) => {
        println!("Reverted after {} gas", gas_used);
    }
    Err(SdkError::Connection(msg)) => {
        println!("Node unreachable: {}", msg);
    }
    Err(SdkError::Timeout(msg)) => {
        println!("Timeout: {}", msg);
    }
    Err(SdkError::Signing(msg)) => {
        println!("Signing error: {}", msg);
    }
    Err(SdkError::InsufficientBalance { required, available }) => {
        println!("Need {} quanta but only have {}", required, available);
    }
    Err(e) => println!("Error: {}", e),
}
```

---

## Security

### Keystore Encryption

Wallets are encrypted with **AES-256-GCM** (post-quantum safe symmetric encryption). The encryption key is derived from the user's password via **Poseidon2(password || random_salt)**.

```rust
// Create encrypted keystore
let wallet = Wallet::create_encrypted(Path::new("key.json"), "password")?;

// Each keystore has unique random salt + nonce — no reuse
```

### File Permissions

On Unix systems, keystore files are automatically set to:
- File: `600` (owner read/write only)
- Directory: `700` (owner only)

### Post-Quantum Cryptography

All cryptographic operations are post-quantum safe:
- **Signing**: FALCON-512 (lattice-based, NIST standard)
- **Hashing**: Poseidon2 (ZK-friendly algebraic hash)
- **Encryption**: AES-256-GCM (Grover-resistant at 128-bit equivalent)

---

## Architecture

```
crates/pyde-rust-sdk/
├── src/
│   ├── lib.rs         — re-exports, top-level API
│   ├── client.rs      — Provider (async HTTP RPC client)
│   ├── wallet.rs      — Wallet (keygen, keystore, signing)
│   ├── abi.rs         — Contract (ABI-aware reads, Value enum)
│   ├── contract.rs    — ContractCall/DeployData builders, decoders
│   ├── types.rs       — Receipt, Log, Address, re-exports
│   └── error.rs       — SdkError enum, Result type alias
```

Dependencies:
- **pyde-crypto** — FALCON-512 signatures, Poseidon2 hashing
- **pyde-tx** — Transaction types, serialization, hashing
- **pyde-account** — Address derivation
- **reqwest** — Async HTTP client
- **aes-gcm** — Keystore encryption
