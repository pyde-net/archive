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
  - [Transaction Lookup](#transaction-lookup)
  - [Fee Data](#fee-data)
  - [Static Calls](#static-calls)
  - [Gas Estimation](#gas-estimation)
- [Wallet](#wallet)
  - [Creating a Wallet](#creating-a-wallet)
  - [Restoring a Wallet](#restoring-a-wallet)
  - [Provider Binding (connect)](#provider-binding-connect)
  - [Encrypted Keystore](#encrypted-keystore)
  - [Exporting Keys](#exporting-keys)
  - [Validation](#validation)
  - [Signing](#signing)
- [Address Utilities](#address-utilities)
- [Transactions](#transactions)
  - [Sending a Transfer](#sending-a-transfer)
  - [Calling a Contract Function](#calling-a-contract-function)
  - [Deploying a Contract](#deploying-a-contract)
  - [SignerProvider (Convenience)](#signerprovider-convenience)
  - [Waiting for Receipts](#waiting-for-receipts)
- [Contract Interaction](#contract-interaction)
  - [Building Calldata](#building-calldata)
  - [Wide Types (u128, u256)](#wide-types-u128-u256)
  - [Multi-Arg Calls](#multi-arg-calls)
  - [Vectors](#vectors)
  - [Structs & Tuples](#structs--tuples)
  - [Nested Types](#nested-types)
  - [Deploy Data with Constructor Args](#deploy-data-with-constructor-args)
  - [ABI-Aware Contract (fromArtifact + connect)](#abi-aware-contract-fromartifact--connect)
  - [Simulating Calls](#simulating-calls)
  - [Gas Estimation (ABI-Aware)](#gas-estimation-abi-aware)
  - [Payable Functions](#payable-functions)
  - [Decoding Write Return Data](#decoding-write-return-data)
  - [The Value Enum](#the-value-enum)
  - [Decoding Return Values](#decoding-return-values)
  - [Contract Events](#contract-events)
  - [Interface (Standalone ABI)](#interface-standalone-abi)
- [WebSocket Provider](#websocket-provider)
- [Events & Logs](#events--logs)
- [Error Handling](#error-handling)
  - [Error Variants](#error-variants)
  - [Pattern Matching](#pattern-matching)
- [Hex Utilities](#hex-utilities)
- [Security](#security)
  - [Keystore Encryption](#keystore-encryption)
  - [File Permissions](#file-permissions)
  - [Post-Quantum Cryptography](#post-quantum-cryptography)
- [Utility Functions](#utility-functions)
- [Unit Formatting](#unit-formatting)
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
use pyde_rust_sdk::{Provider, Wallet, Contract};
use serde_json::json;

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
    let to = pyde_rust_sdk::parse_address("0x00bb...")?;
    let receipt = wallet.transfer(&provider, &to, 1_000_000).await?;
    println!("Tx hash: {}", receipt.tx_hash);

    // 5. Interact with a contract (load ABI from build artifact)
    let contract = Contract::from_artifact("out/Counter.json", addr, &provider)?
        .connect(&wallet);
    let count = contract.read("get_count", None).await?;
    contract.write("increment", None, 100_000_000).await?;

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

### Transaction Lookup

```rust
let tx = provider.get_transaction(&tx_hash).await?; // Option<serde_json::Value>
if let Some(tx) = tx {
    println!("From: {}", tx["from"]);
}
```

Note: `return_data` is ephemeral — only available in the receipt immediately after execution, not in transaction lookups.

### Fee Data

Get current network fee info (Pyde uses EIP-1559 with no tips).

```rust
let fees = provider.get_fee_data().await?;   // FeeData
println!("Gas price: {}", fees.gas_price);    // u128 (quanta per gas)
println!("Base fee: {}", fees.base_fee);      // same as gas_price in Pyde
```

### Static Calls

Execute a contract function without creating a transaction. No gas consumed.

```rust
// Using Contract (recommended)
let contract = Contract::from_artifact("out/Counter.json", addr, &provider)?;
let count = contract.read("get_count", None).await?; // Value::U64(42)

// Low-level (manual calldata)
let result = provider.call(&contract_addr, &calldata).await?; // Vec<u8>
```

### Gas Estimation

```rust
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

### Provider Binding (connect)

Bind a provider to the wallet for shorter method signatures.

```rust
let signer = wallet.connect(&provider);

// Now call without passing provider
let balance = signer.get_balance().await?;
let nonce = signer.get_nonce().await?;
let receipt = signer.transfer(&to, 1000).await?;
let receipt = signer.send_call(&contract, data, gas).await?;
let receipt = signer.send_call_with_value(&contract, data, value, gas).await?;
let receipt = signer.deploy(deploy_data, gas).await?;
let result = signer.call(&contract, &calldata).await?;
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

### Validation

```rust
// Validate a private key before importing
Wallet::is_valid_private_key("0xabcdef...");  // true/false

// Generate a random private key (without creating a full wallet)
let pk = Wallet::generate_private_key()?;  // "0x..." (2178 bytes)
let wallet = Wallet::from_private_key(&pk)?;
```

### Signing

```rust
// Sign a transaction in place
let mut tx = Transaction { /* ... */ };
wallet.sign_transaction(&mut tx)?;

// Sign an arbitrary 32-byte message
let msg = [0xAB; 32];
let sig = wallet.sign(&msg)?;  // Vec<u8>
```

---

## Address Utilities

```rust
use pyde_rust_sdk::{
    parse_address, format_address, is_valid_address,
    is_zero_address, address_eq, ZERO_ADDRESS,
    is_valid_private_key,
};

// Zero address
let zero = ZERO_ADDRESS;                          // [0u8; 32]
assert!(is_zero_address(&zero));

// Parse / format
let addr = parse_address("0xaabb...")?;           // [u8; 32]
let hex = format_address(&addr);                   // "0xaabb..."

// Validation
is_valid_address("0x" + &"ab".repeat(32));        // true
is_valid_address("0xshort");                       // false

// Equality
address_eq(&addr1, &addr2);                        // bool

// Private key validation
is_valid_private_key("0x...");                     // true/false
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
// Using Contract (recommended — validates args against ABI)
let contract = Contract::from_artifact("out/Contract.json", addr, &provider)?
    .connect(&wallet);
let receipt = contract.write("deposit", Some(&json!({"amount": 500})), 100_000_000).await?;

// Low-level (manual calldata + wallet)
let calldata = ContractCall::new("deposit").arg_u64(500).build();
let receipt = wallet.send_call(&provider, &contract_addr, calldata, 100_000_000).await?;
```

### Deploying a Contract

```rust
let deploy_data = DeployData::from_artifact("out/Counter.json", &json!({
    "initial_supply": 1000,
}))?.build();

let receipt = wallet.deploy(&provider, deploy_data, 100_000_000).await?;
let addr = receipt.contract_address(); // Option<[u8; 32]>

// Deploy with value (payable constructor)
let receipt = wallet.deploy_with_value(&provider, deploy_data, 1_000_000, 100_000_000).await?;
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

> **Recommended**: Use `Contract::from_artifact()` with `.read()` / `.write()` for ABI-aware
> interaction with validation. The `ContractCall` builder below is for low-level / dynamic use
> when you don't have an artifact.

### Low-Level Calldata Builder

```rust
// No args
ContractCall::new("increment").build();

// Unsigned GP types (8 bytes LE, zero-extended)
ContractCall::new("set_u8").arg_u8(255).build();
ContractCall::new("set_u16").arg_u16(1000).build();
ContractCall::new("set_u32").arg_u32(100000).build();
ContractCall::new("set_u64").arg_u64(42).build();

// Signed GP types (8 bytes LE, sign-extended)
ContractCall::new("set_i8").arg_i8(-1).build();
ContractCall::new("set_i16").arg_i16(-500).build();
ContractCall::new("set_i32").arg_i32(-1_000_000).build();
ContractCall::new("set_i64").arg_i64(-42).build();

// Bool
ContractCall::new("set_active").arg_bool(true).build();

// Address (32 bytes)
ContractCall::new("set_owner").arg_address(owner_addr).build();

// String (length-prefixed, 8-byte aligned)
ContractCall::new("set_name").arg_string("hello").build();

// Raw bytes
ContractCall::new("set_data").arg_bytes(&[1, 2, 3]).build();
```

### Wide Types (u128, u256)

```rust
// u128 / i128 (16 bytes)
ContractCall::new("set_amount").arg_u128(1_000_000_000_000).build();
ContractCall::new("set_signed").arg_i128(-500).build();

// u256 / i256 (32 bytes)
ContractCall::new("set_big").arg_u256(U256::from(99u64)).build();
ContractCall::new("set_signed_big").arg_i256(I256::from(-1i64)).build();
```

### Multi-Arg Calls

Chain arguments in parameter order.

```rust
ContractCall::new("set_all")
    .arg_string("hello")
    .arg_u64(42)
    .arg_bool(true)
    .arg_u256(U256::from(99u64))
    .arg_address(some_addr)
    .build();
```

### Vectors

```rust
// Vec<u64>
ContractCall::new("set_scores").arg_vec_u64(&[100, 200, 300]).build();

// Vec<bool>
ContractCall::new("set_flags").arg_vec_bool(&[true, false, true]).build();

// Vec<Address>
ContractCall::new("set_addrs").arg_vec_address(&[addr1, addr2]).build();

// Vec<String> — use arg_vec_of for any element type
ContractCall::new("set_names")
    .arg_vec_of(3, |b| b
        .arg_string("alice")
        .arg_string("bob")
        .arg_string("charlie"))
    .build();

// Vec<u256>
ContractCall::new("set_bigs")
    .arg_vec_of(2, |b| b.arg_u256(U256::from(100u64)).arg_u256(U256::from(200u64)))
    .build();
```

### Structs & Tuples

```rust
// Struct: [byte_len:8][fields...]
ContractCall::new("set_user")
    .arg_struct(|s| s
        .arg_string("alice")
        .arg_u64(25)
        .arg_bool(true))
    .build();

// Tuple: sequential fields, no length prefix
ContractCall::new("set_pair")
    .arg_tuple(|t| t.arg_u64(1).arg_string("one"))
    .build();
```

### Nested Types

`arg_vec_of` and `arg_struct` are composable — nest arbitrarily.

```rust
// Vec<Struct>
ContractCall::new("set_users")
    .arg_vec_of(2, |b| b
        .arg_struct(|s| s.arg_string("alice").arg_u64(25))
        .arg_struct(|s| s.arg_string("bob").arg_u64(30)))
    .build();

// Vec<Vec<u64>>
ContractCall::new("set_matrix")
    .arg_vec_of(2, |b| b
        .arg_vec_u64(&[1, 2, 3])
        .arg_vec_u64(&[4, 5, 6]))
    .build();

// Vec<Tuple>
ContractCall::new("set_pairs")
    .arg_vec_of(2, |b| b
        .arg_tuple(|t| t.arg_u64(1).arg_string("one"))
        .arg_tuple(|t| t.arg_u64(2).arg_string("two")))
    .build();

// Struct containing Vec
ContractCall::new("set_team")
    .arg_struct(|s| s
        .arg_string("Team Alpha")
        .arg_vec_of(3, |b| b
            .arg_string("alice")
            .arg_string("bob")
            .arg_string("charlie")))
    .build();
```

### Deploy Data with Constructor Args

```rust
// From artifact with named constructor args (recommended)
let data = DeployData::from_artifact("out/Counter.json", &json!({
    "initial_supply": 1000,
    "name": "MyToken",
    "owner": format!("0x{}", hex::encode(owner_addr)),
}))?.build();

// Constructor args are validated against the ABI
DeployData::from_artifact("out/Counter.json", &json!({}))?;
// Error: constructor: missing arg 'initial_supply' (u64)

// No constructor args
let data = DeployData::from_artifact("out/Simple.json", &json!({}))?.build();

// From raw bytecodes with manual arg chaining (low-level)
let data = DeployData::new(constructor_bytes, runtime_bytes)
    .arg_u64(1000)
    .arg_string("hello")
    .build();
```

### ABI-Aware Contract (fromArtifact + connect)

The recommended way to interact with contracts — loads the full ABI including
struct/enum definitions, validates args before broadcast, auto-encodes and decodes.

```rust
use serde_json::json;

// Load from build artifact file (gets all functions, structs, enums)
let contract = Contract::from_artifact("out/MyContract.json", addr, &provider)?
    .connect(&wallet);

// Or load from a raw ABI JSON string
let contract = Contract::from_json(&abi_json_string, addr, &provider)?
    .connect(&wallet);

// Or create a minimal contract (no ABI — for low-level use)
let contract = Contract::new(addr, &provider);

// Read — auto-decoded return value
let count = contract.read("get_count", None).await?;    // Value::U64(42)
let user = contract.read("get_user", None).await?;      // Value::Struct(...)
let scores = contract.read("get_scores", None).await?;  // Value::Vec(...)

// Write — validated, encoded, signed, sent, waited
contract.write("deposit", Some(&json!({"amount": 500})), 100_000_000).await?;

contract.write("set_user", Some(&json!({
    "user": {"name": "alice", "age": 25, "active": true}
})), 100_000_000).await?;

contract.write("set_status", Some(&json!({"status": "Active"})), 100_000_000).await?;

contract.write("set_scores", Some(&json!({"scores": [100, 200, 300]})), 100_000_000).await?;
```

### Simulating Calls

Static-call ANY function (view or setter) without sending a transaction.

```rust
// Simulate a setter to preview the return value
let result = contract.simulate("deposit", Some(&json!({"amount": 500}))).await?;

// Same as read() but the name makes intent clear for non-view functions
let count = contract.simulate("get_count", None).await?;
```

### Gas Estimation (ABI-Aware)

```rust
let gas = contract.estimate_gas("deposit", Some(&json!({"amount": 500}))).await?;
// Then use it:
contract.write("deposit", Some(&json!({"amount": 500})), gas).await?;
```

### Payable Functions

Send native tokens (value) with a contract call. Validates the `payable` attribute from the ABI.

```rust
// Send value with a payable function
contract.write_with_value("deposit", Some(&json!({"amount": 500})), 1_000_000, gas).await?;

// Non-payable function rejects value
contract.write_with_value("withdraw", Some(&json!({"amount": 100})), 1, gas).await?;
// Error: withdraw() is not payable — cannot send value
```

### Arg Validation (before broadcast)

```rust
// Missing param → error
contract.write("deposit", None, gas).await?;
// Error: deposit(): missing required param 'amount' (u64)

// Wrong type → error
contract.write("deposit", Some(&json!({"amount": "hello"})), gas).await?;
// Error: deposit().amount: expected u64, got "hello"

// Out of range → error
contract.write("deposit", Some(&json!({"amount": -1})), gas).await?;
// Error: deposit().amount: value -1 out of range for u64 (0 to ...)

// Missing struct field → error
contract.write("set_user", Some(&json!({"user": {"name": "alice"}})), gas).await?;
// Error: set_user().user: missing field 'age' for struct UserInfo

// Unknown enum variant → error
contract.write("set_status", Some(&json!({"status": "Unknown"})), gas).await?;
// Error: set_status().status: unknown variant 'Unknown' for enum Status. Valid: Active, Banned
```

### Decoding Write Return Data

`Contract::write()` returns a `ContractReceipt` with `decode_return_data()` that
auto-decodes using the ABI return type. Derefs to `Receipt` so all fields are accessible.

```rust
let receipt = contract.write("deposit", Some(&json!({"amount": 500})), gas).await?;
println!("Success: {}", receipt.success);           // Receipt field via Deref

let val = receipt.decode_return_data();              // Option<Value>
// Returns None if return_data is absent or function returns ()
```

Note: `return_data` is ephemeral — only available in the receipt immediately after
tx execution. It is not persisted on-chain.

### The Value Enum

Return values are decoded into a `Value` enum supporting all Pyde types.

```rust
pub enum Value {
    U64(u64),
    I64(i64),
    U128(u128),
    I128(i128),
    U256(ethnum::U256),
    I256(ethnum::I256),
    Bool(bool),
    Address([u8; 32]),
    String(String),
    Bytes(Vec<u8>),
    Vec(Vec<Value>),
    Struct(HashMap<String, Value>),
    Enum(String),        // variant name
    Unit,
}

// Accessors — each returns Option<T>
value.as_u64()       // Option<u64>
value.as_i64()       // Option<i64>
value.as_u128()      // Option<u128>
value.as_i128()      // Option<i128>
value.as_u256()      // Option<U256>
value.as_i256()      // Option<I256>
value.as_bool()      // Option<bool>
value.as_address()   // Option<&[u8; 32]>
value.as_string()    // Option<&str>
value.as_bytes()     // Option<&[u8]>
value.as_vec()       // Option<&[Value]>
value.as_struct()    // Option<&HashMap<String, Value>>
value.as_enum()      // Option<&str>  (variant name)

// Struct field access
value.field("name")  // Option<&Value>

// Vec index access
value.index(0)       // Option<&Value>
```

### Decoding Return Values

Manual decoders for raw return bytes.

```rust
// GP integers
let count = decode_u64(&bytes);      // Option<u64>
let neg   = decode_i64(&bytes);      // Option<i64>

// Wide integers
let amt   = decode_u128(&bytes);     // Option<u128>
let sneg  = decode_i128(&bytes);     // Option<i128>
let big   = decode_u256(&bytes);     // Option<U256>
let sbig  = decode_i256(&bytes);     // Option<I256>

// Other types
let flag  = decode_bool(&bytes);     // Option<bool>
let addr  = decode_address(&bytes);  // Option<[u8; 32]>
let name  = decode_string(&bytes);   // Option<String>
let raw   = decode_bytes(&bytes);    // Option<Vec<u8>>

// Vec decoders
let nums  = decode_vec_u64(&bytes);     // Option<Vec<u64>>
let flags = decode_vec_bool(&bytes);    // Option<Vec<bool>>
let addrs = decode_vec_address(&bytes); // Option<Vec<[u8; 32]>>
```

---

### Contract Events

Query and decode contract events using the ABI.

```rust
// Query historical events (decoded with named args)
let transfers = contract.query_filter("Transfer", Some(0), Some(1000)).await?;
for e in &transfers {
    println!("{}: {:?}", e.name, e.args);
}

// Parse a single raw log
let decoded = contract.parse_log(&raw_log);

// Get topic0 hash for building custom filters
let topic = contract.get_event_topic("Transfer");
```

### Interface (Standalone ABI)

Encode/decode without a contract address or provider.

```rust
let iface = Interface::from_artifact("out/Counter.json")?;

// Encode calldata
let data = iface.encode_function_data("deposit", &json!({"amount": 500}))?;

// Decode return value
let val = iface.decode_function_result("get_count", &bytes);

// Parse logs
let event = iface.parse_log(&raw_log);
```

---

## WebSocket Provider

Real-time subscriptions via WebSocket.

```rust
let ws = WsProvider::connect("ws://127.0.0.1:8546").await?;

// Subscribe to new block headers
let mut blocks = ws.subscribe_new_heads().await?;
tokio::spawn(async move {
    while let Ok(header) = blocks.recv().await {
        println!("New block: {}", header.slot);
    }
});

// Subscribe to pending transactions
let mut pending = ws.subscribe_pending_transactions().await?;

// Subscribe to contract event logs
let mut logs = ws.subscribe_logs(&LogFilter {
    address: Some("0xcontract...".into()),
    ..Default::default()
}).await?;

// Standard queries also work
let balance = ws.get_balance(&addr).await?;

// Cleanup
ws.close().await;
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
    InvalidArgument(String),     // Invalid argument to SDK method
    InvalidResponse(String),     // Malformed RPC response
}

// Helper methods
error.code();            // "CALL_EXCEPTION", "CONNECTION_ERROR", etc.
error.revert_reason();   // Some("require failed") — auto-decoded from return data
error.is_revert();       // true if Reverted variant
```

### Pattern Matching

```rust
match contract.write("deposit", Some(&json!({"amount": 500})), gas).await {
    Ok(receipt) => {
        println!("Success! Gas: {}", receipt.gas());
        if let Some(val) = receipt.decode_return_data() {
            println!("Return: {:?}", val);
        }
    }
    Err(ref e) if e.is_revert() => {
        println!("Reverted! Reason: {:?}", e.revert_reason());
    }
    Err(SdkError::Connection(msg)) => println!("Node unreachable: {}", msg),
    Err(SdkError::Timeout(msg)) => println!("Timeout: {}", msg),
    Err(e) => println!("Error [{}]: {}", e.code(), e),
}
```

---

## Hex Utilities

```rust
use pyde_rust_sdk::{
    is_hex_string, hexlify, get_bytes, to_be_hex,
    concat_bytes, zero_pad_value, strip_zeros, data_length,
};

// Check if valid hex
is_hex_string("0xdeadbeef");                  // true
is_hex_string("0xgg");                         // false

// Convert to/from hex
let hex = hexlify(&[0xde, 0xad]);             // "0xdead"
let bytes = get_bytes("0xdeadbeef")?;          // Vec<u8>

// BigInt to big-endian hex (with optional width)
to_be_hex(255, None);                          // "0xff"
to_be_hex(255, Some(4));                       // "0x000000ff"

// Concatenate
let combined = concat_bytes(&[&[0xde, 0xad], &[0xbe, 0xef]]);

// Pad / strip
let padded = zero_pad_value(&[0xff], 4)?;     // [0, 0, 0, 0xff]
let stripped = strip_zeros(&[0, 0, 0, 0xff]); // [0xff]

// Length
data_length("0xdeadbeef");                     // 4
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

## Utility Functions

```rust
use pyde_rust_sdk::{parse_address, format_address, compute_selector};

// Parse a hex address string to [u8; 32]
let addr = parse_address("0xaabb...")?;

// Format a [u8; 32] address as 0x-prefixed hex
let hex = format_address(&addr);  // "0xaabb..."

// Compute FNV-1a function selector (same as Otigen compiler)
let selector = compute_selector("get_count");  // 0xd9e32bf7
```

---

## Unit Formatting

Convert between human-readable token amounts and raw integer units.
1 PYDE = 10^9 quanta (default). Custom decimals supported.

```rust
use pyde_rust_sdk::{parse_units, format_units, parse_quanta, format_quanta};

// Parse human-readable → raw (with custom decimals)
let raw = parse_units("1.5", 9)?;    // 1_500_000_000
let raw = parse_units("100", 18)?;   // 100_000_000_000_000_000_000
let raw = parse_units("0.001", 9)?;  // 1_000_000

// Format raw → human-readable
let s = format_units(1_500_000_000, 9);   // "1.5"
let s = format_units(1_000_000, 9);       // "0.001"

// PYDE shortcuts (9 decimals)
let raw = parse_quanta("2.5")?;           // 2_500_000_000
let s = format_quanta(2_500_000_000);     // "2.5"

// Custom token with 18 decimals
let raw = parse_units("0.5", 18)?;
let s = format_units(raw, 18);            // "0.5"
```

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
