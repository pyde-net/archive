# SDK Live Integration Test Plan

## Prerequisites (blocked — need devnet changes first)

The live tests require the devnet to generate real FALCON-512 keypairs for the 10 pre-funded accounts. Currently the devnet creates addresses without keypairs, so we can't sign transactions.

**Devnet changes needed before these tests can run:**
1. Generate 10 FALCON keypairs at devnet genesis
2. Fund each with 10M PYDE (10,000,000 × 10^9 quanta)
3. Print private keys + addresses on startup (Anvil-style)
4. Persist keys across restarts (~/.pyde/devnet-keys.json)

## Test Environment

- Start a local Pyde node in devnet mode
- Load Account #0 private key from devnet output
- All tests use HTTP provider at http://127.0.0.1:8545
- WebSocket tests use ws://127.0.0.1:8546

## Test Contracts Needed

### 1. Counter.oti (basic read/write)
```
contract Counter {
    count: u64,

    #[constructor]
    pub fn init(initial: u64) {
        self.count = initial;
    }

    pub fn get_count() -> u64 {
        self.count
    }

    pub fn increment() {
        self.count += 1;
    }

    pub fn set_count(val: u64) {
        self.count = val;
    }
}
```

### 2. Vault.oti (payable constructor + payable functions + events)
```
contract Vault {
    owner: Address,
    total_deposited: u128,

    event Deposit { from: Address, amount: u128 }
    event Withdraw { to: Address, amount: u128 }

    #[constructor]
    #[payable]
    pub fn init(owner: Address) {
        self.owner = owner;
        self.total_deposited = msg_value();
    }

    #[payable]
    pub fn deposit() {
        self.total_deposited += msg_value();
        emit Deposit { from: msg_sender(), amount: msg_value() };
    }

    pub fn withdraw(amount: u128) {
        require!(msg_sender() == self.owner, "not owner");
        self.total_deposited -= amount;
        transfer(self.owner, amount);
        emit Withdraw { to: self.owner, amount: amount };
    }

    pub fn get_balance() -> u128 {
        self.total_deposited
    }

    pub fn get_owner() -> Address {
        self.owner
    }
}
```

### 3. TypeStore.oti (all types — struct, enum, vec, tuple, array)
```
contract TypeStore {
    name: String,
    scores: Vec<u64>,
    status: Status,
    user: UserInfo,

    struct UserInfo { name: String, age: u64, active: bool }
    enum Status { Active, Inactive, Banned }

    #[constructor]
    pub fn init(name: String) {
        self.name = name;
    }

    pub fn set_user(user: UserInfo) { self.user = user; }
    pub fn get_user() -> UserInfo { self.user }

    pub fn set_status(s: Status) { self.status = s; }
    pub fn get_status() -> Status { self.status }

    pub fn set_scores(s: Vec<u64>) { self.scores = s; }
    pub fn get_scores() -> Vec<u64> { self.scores }

    pub fn get_name() -> String { self.name }
}
```

## Test Scenarios

### Group 1: Provider Basics
- [ ] getBalance — check funded account has 10M PYDE
- [ ] getNonce — fresh account has nonce 0
- [ ] getChainId — returns 31337
- [ ] getBlockNumber — returns >= 0
- [ ] getGasPrice — returns > 0
- [ ] getFeeData — returns { gasPrice, baseFee }
- [ ] getBlockByNumber(0) — genesis block exists

### Group 2: Wallet + Transfer
- [ ] Wallet.fromPrivateKey(devnetKey) — restores correct address
- [ ] wallet.transfer(recipient, amount) — receipt.success = true
- [ ] getBalance after transfer — sender decreased, recipient increased
- [ ] getNonce after transfer — incremented by 1
- [ ] Transfer to zero address — should fail/revert

### Group 3: Deploy (no constructor args)
- [ ] Deploy Counter with no args — receipt has contract address
- [ ] getCode(contractAddress) — non-empty
- [ ] Contract.fromArtifact + read("get_count") — returns 0

### Group 4: Deploy (with constructor args)
- [ ] DeployData.fromArtifact("Counter.json", { initial: 42 }) — deploys
- [ ] read("get_count") — returns 42 (constructor arg applied)

### Group 5: Deploy (payable constructor)
- [ ] Deploy Vault with value — constructor receives native tokens
- [ ] read("get_balance") — returns the value sent with deploy
- [ ] read("get_owner") — returns deployer address

### Group 6: Contract Read/Write
- [ ] write("increment") — receipt.success
- [ ] read("get_count") — returns 1 (was 0)
- [ ] write("set_count", { val: 99 }) + read("get_count") — returns 99
- [ ] simulate("set_count", { val: 50 }) — returns value without state change
- [ ] read("get_count") still 99 (simulate didn't mutate)

### Group 7: Payable Contract Functions
- [ ] write("deposit", {}, { value: 1000000n }) — sends native tokens
- [ ] read("get_balance") — increased by deposit amount
- [ ] write("withdraw", { amount: 500000 }) — succeeds from owner
- [ ] write("deposit", {}, { value: 0 }) — should succeed (payable, zero value ok)
- [ ] Non-payable function with value — should throw "not payable"

### Group 8: Struct/Enum/Vec Types
- [ ] write("set_user", { user: { name: "alice", age: 25, active: true } })
- [ ] read("get_user") — returns { name: "alice", age: 25n, active: true }
- [ ] write("set_status", { s: "Active" }) + read("get_status") — "Active"
- [ ] write("set_scores", { s: [100, 200, 300] }) + read("get_scores") — [100n, 200n, 300n]

### Group 9: Contract Events
- [ ] write("deposit") emits Deposit event
- [ ] contract.queryFilter("Deposit") — returns decoded EventLog[]
- [ ] EventLog.args.from === sender address
- [ ] EventLog.args.amount === deposit amount
- [ ] contract.parseLog(rawLog) — decodes correctly

### Group 10: Gas Estimation
- [ ] contract.estimateGas("increment") — returns > 0
- [ ] contract.estimateGas("deposit", {}) — returns > 0
- [ ] provider.estimateGas with overrides — works

### Group 11: ContractReceipt.decodeReturnData()
- [ ] write("set_count", { val: 42 }) → receipt.decodeReturnData() for void return
- [ ] Any write with return value → receipt.decodeReturnData() returns decoded value

### Group 12: Interface (standalone)
- [ ] Interface.fromArtifact — encode calldata without contract instance
- [ ] Interface.decodeFunctionResult — decode return data
- [ ] Interface.parseLog — decode event log

### Group 13: WebSocket Provider
- [ ] Connect to ws://127.0.0.1:8546
- [ ] onBlock — receives new block headers when txs are sent
- [ ] onLogs — receives event logs matching filter
- [ ] Standard queries (getBalance, getChainId) work over WS

### Group 14: Error Handling
- [ ] Revert produces CallExceptionError with reason
- [ ] isCallException(e) returns true
- [ ] Connection to dead node produces ConnectionError
- [ ] isError(e, "CONNECTION_ERROR") returns true

### Group 15: Hex/Address/Unit Utilities
- [ ] parseQuanta("10.5") → 10500000000n
- [ ] formatQuanta(balance) → human readable
- [ ] Address.isValid(contractAddress) — true
- [ ] Address.isZero(Address.zero()) — true

### Group 16: Batch RPC
- [ ] provider.batch([getBalance, getNonce, getChainId]) — all return correct values in one call

### Group 17: TransactionResponse
- [ ] sendRawTransaction returns { hash, wait() }
- [ ] tx.wait() returns receipt

## Running the Tests

```bash
# 1. Start devnet node
pyde node --dev

# 2. Run TS SDK live tests
cd pyde-ts-sdk && npm run test:live

# 3. Run Rust SDK live tests
cd pyde && cargo test -p pyde-rust-sdk --features live-test
```

## Notes

- All tests should clean up after themselves where possible
- Tests should be idempotent (can run multiple times)
- Each test group gets a fresh contract deployment to avoid state pollution
- Use Account #0 as the primary signer, Account #1 as a secondary (for transfer recipient, etc.)
- returnData is ephemeral — only available in receipt right after execution
