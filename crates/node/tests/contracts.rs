//! Test contract sources for the production benchmark.
//! 30+ contracts covering every Otigen feature.
//!
//! `#![allow(dead_code)]` — each `tests/*.rs` file is its own binary
//! crate. Only a subset of these `pub const`s is referenced by any
//! given test binary; Rust reports the rest as unused. `-D warnings`
//! in CI would fail without this allow.

#![allow(dead_code)]

// ═══════════════════════════════════════════════════════════════════
// SIMPLE CONTRACTS (10) — basic patterns, light storage
// ═══════════════════════════════════════════════════════════════════

pub const COUNTER: &str = r#"
contract Counter {
    storage { count: u64, }
    #[constructor] pub fn init() { self.count = 0; }
    pub fn increment() { self.count = self.count + 1; }
    pub fn decrement() { require!(self.count > 0); self.count = self.count - 1; }
    pub fn set_count(n: u64) { self.count = n; }
    pub fn add(n: u64) { self.count = self.count + n; }
    #[view] pub fn get_count() -> u64 { return self.count; }
}
"#;

pub const COUNTER_ARGS: &str = r#"
contract CounterArgs {
    storage { count: u64, step: u64, }
    #[constructor] pub fn init(initial: u64, step: u64) {
        self.count = initial;
        self.step = step;
    }
    pub fn increment() { self.count = self.count + self.step; }
    #[view] pub fn get_count() -> u64 { return self.count; }
    #[view] pub fn get_step() -> u64 { return self.step; }
}
"#;

pub const SIMPLE_STORE: &str = r#"
contract SimpleStore {
    storage { value: u64, flag: bool, }
    #[constructor] pub fn init() { self.value = 0; self.flag = false; }
    pub fn set_value(v: u64) { self.value = v; }
    pub fn toggle() { self.flag = !self.flag; }
    #[view] pub fn get_value() -> u64 { return self.value; }
    #[view] pub fn get_flag() -> bool { return self.flag; }
}
"#;

pub const ACCUMULATOR: &str = r#"
contract Accumulator {
    storage { total: u64, count: u64, }
    #[constructor] pub fn init() { self.total = 0; self.count = 0; }
    pub fn add(n: u64) {
        self.total = self.total + n;
        self.count = self.count + 1;
    }
    #[view] pub fn average() -> u64 {
        if self.count == 0 { return 0; }
        return self.total / self.count;
    }
    #[view] pub fn get_total() -> u64 { return self.total; }
}
"#;

pub const OWNERSHIP: &str = r#"
contract Ownership {
    storage { owner: Address, pending_owner: Address, }
    #[constructor] pub fn init() { self.owner = msg.sender; }
    pub fn transfer_ownership(new_owner: Address) {
        require!(msg.sender == self.owner);
        self.pending_owner = new_owner;
    }
    pub fn accept_ownership() {
        require!(msg.sender == self.pending_owner);
        self.owner = msg.sender;
    }
    #[view] pub fn get_owner() -> Address { return self.owner; }
}
"#;

pub const PIGGYBANK: &str = r#"
contract Piggybank {
    storage { owner: Address, balance: u64, }
    #[constructor] pub fn init() { self.owner = msg.sender; self.balance = 0; }
    #[payable] pub fn deposit() { self.balance = self.balance + msg.value; }
    #[view] pub fn get_balance() -> u64 { return self.balance; }
}
"#;

pub const WHITELIST: &str = r#"
contract Whitelist {
    storage { admin: Address, allowed: Map<Address, bool>, count: u64, }
    #[constructor] pub fn init() { self.admin = msg.sender; self.count = 0; }
    pub fn add(addr: Address) {
        require!(msg.sender == self.admin);
        self.allowed[addr] = true;
        self.count = self.count + 1;
    }
    pub fn remove(addr: Address) {
        require!(msg.sender == self.admin);
        self.allowed[addr] = false;
    }
    #[view] pub fn is_allowed(addr: Address) -> bool { return self.allowed[addr]; }
    #[view] pub fn get_count() -> u64 { return self.count; }
}
"#;

pub const RATE_COUNTER: &str = r#"
contract RateCounter {
    storage { slots: Map<u64, u64>, current_slot: u64, }
    #[constructor] pub fn init() { self.current_slot = 0; }
    pub fn tick() {
        let s = self.current_slot;
        self.slots[s] = self.slots[s] + 1;
    }
    pub fn advance() { self.current_slot = self.current_slot + 1; }
    #[view] pub fn rate(slot: u64) -> u64 { return self.slots[slot]; }
}
"#;

pub const BITMAP: &str = r#"
contract Bitmap {
    storage { bits: u64, }
    #[constructor] pub fn init() { self.bits = 0; }
    pub fn set_bit(pos: u64) {
        let mask: u64 = 1 << pos;
        self.bits = self.bits | mask;
    }
    pub fn clear_bit(pos: u64) {
        let mask: u64 = !(1 << pos);
        self.bits = self.bits & mask;
    }
    #[view] pub fn get_bit(pos: u64) -> bool { return (self.bits >> pos) & 1 == 1; }
    #[view] pub fn get_bits() -> u64 { return self.bits; }
}
"#;

pub const MULTISLOT: &str = r#"
contract MultiSlot {
    storage { a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, }
    #[constructor] pub fn init() {
        self.a = 0; self.b = 0; self.c = 0; self.d = 0;
        self.e = 0; self.f = 0; self.g = 0; self.h = 0;
    }
    pub fn write_all(v: u64) {
        self.a = v; self.b = v + 1; self.c = v + 2; self.d = v + 3;
        self.e = v + 4; self.f = v + 5; self.g = v + 6; self.h = v + 7;
    }
    #[view] pub fn sum() -> u64 {
        return self.a + self.b + self.c + self.d + self.e + self.f + self.g + self.h;
    }
}
"#;

// ═══════════════════════════════════════════════════════════════════
// COMPLEX CONTRACTS (12) — u256, events, maps, math, memory
// ═══════════════════════════════════════════════════════════════════

pub const VAULT: &str = r#"
contract Vault {
    storage { total: u256, balances: Map<Address, u256>, }
    event Deposit { #[indexed] sender: Address, amount: u256, }
    event Withdraw { #[indexed] sender: Address, amount: u256, }
    #[constructor] pub fn init() { self.total = 0u256; }
    #[payable] pub fn deposit() {
        self.balances[msg.sender] = self.balances[msg.sender] + msg.value;
        self.total = self.total + msg.value;
        emit Deposit { sender: msg.sender, amount: msg.value };
    }
    pub fn withdraw(amount: u256) {
        require!(self.balances[msg.sender] >= amount);
        self.balances[msg.sender] = self.balances[msg.sender] - amount;
        self.total = self.total - amount;
        emit Withdraw { sender: msg.sender, amount: amount };
    }
    #[view] pub fn get_total() -> u256 { return self.total; }
    #[view] pub fn get_balance(addr: Address) -> u256 { return self.balances[addr]; }
}
"#;

pub const TOKEN: &str = r#"
contract Token {
    storage { name: String, supply: u256, balances: Map<Address, u256>, allowances: Map<Address, Map<Address, u256>>, }
    event Transfer { #[indexed] from: Address, #[indexed] to: Address, amount: u256, }
    event Approval { #[indexed] owner: Address, #[indexed] spender: Address, amount: u256, }
    #[constructor] pub fn init(name: String, supply: u256) {
        self.name = name; self.supply = supply; self.balances[msg.sender] = supply;
    }
    pub fn transfer(to: Address, amount: u256) {
        let bal = self.balances[msg.sender];
        require!(bal >= amount);
        self.balances[msg.sender] = bal - amount;
        self.balances[to] = self.balances[to] + amount;
        emit Transfer { from: msg.sender, to: to, amount: amount };
    }
    pub fn approve(spender: Address, amount: u256) {
        self.allowances[msg.sender][spender] = amount;
        emit Approval { owner: msg.sender, spender: spender, amount: amount };
    }
    #[view] pub fn balance_of(addr: Address) -> u256 { return self.balances[addr]; }
    #[view] pub fn get_supply() -> u256 { return self.supply; }
}
"#;

pub const STAKING: &str = r#"
contract Staking {
    storage { total_staked: u256, stakes: Map<Address, u256>, reward_rate: u64, }
    event Staked { #[indexed] user: Address, amount: u256, }
    event Unstaked { #[indexed] user: Address, amount: u256, }
    #[constructor] pub fn init(rate: u64) { self.reward_rate = rate; self.total_staked = 0u256; }
    #[payable] pub fn stake() {
        self.stakes[msg.sender] = self.stakes[msg.sender] + msg.value;
        self.total_staked = self.total_staked + msg.value;
        emit Staked { user: msg.sender, amount: msg.value };
    }
    pub fn unstake(amount: u256) {
        require!(self.stakes[msg.sender] >= amount);
        self.stakes[msg.sender] = self.stakes[msg.sender] - amount;
        self.total_staked = self.total_staked - amount;
        emit Unstaked { user: msg.sender, amount: amount };
    }
    #[view] pub fn get_stake(addr: Address) -> u256 { return self.stakes[addr]; }
    #[view] pub fn get_total() -> u256 { return self.total_staked; }
}
"#;

pub const MATH_HEAVY: &str = r#"
contract MathHeavy {
    storage { result: u64, }
    #[constructor] pub fn init() { self.result = 0; }
    pub fn compute_sum_squares(n: u64) {
        let mut sum: u64 = 0;
        for i in 0..n { sum = sum + i * i; }
        self.result = sum;
    }
    pub fn compute_fibonacci(n: u64) {
        let mut a: u64 = 0;
        let mut b: u64 = 1;
        for i in 0..n {
            let tmp = a + b;
            a = b;
            b = tmp;
        }
        self.result = a;
    }
    pub fn compute_bitwise(n: u64) {
        let mut acc: u64 = 0xDEADBEEF;
        for i in 0..n {
            acc = acc ^ (i * 0x9E3779B97F4A7C15);
            acc = (acc << 13) | (acc >> 51);
            acc = acc + i;
        }
        self.result = acc;
    }
    #[view] pub fn get_result() -> u64 { return self.result; }
}
"#;

pub const LOTTERY: &str = r#"
contract Lottery {
    storage { pot: u256, entries: u64, seed: u64, }
    event Entry { #[indexed] player: Address, }
    #[constructor] pub fn init() { self.pot = 0u256; self.entries = 0; self.seed = 42; }
    #[payable] pub fn enter() {
        self.pot = self.pot + msg.value;
        self.entries = self.entries + 1;
        self.seed = self.seed * 6364136223846793005 + 1;
        emit Entry { player: msg.sender };
    }
    #[view] pub fn get_pot() -> u256 { return self.pot; }
    #[view] pub fn get_entries() -> u64 { return self.entries; }
}
"#;

pub const REGISTRY: &str = r#"
contract Registry {
    storage { owner: Address, entries: Map<u64, Address>, count: u64, }
    event Registered { id: u64, addr: Address, }
    #[constructor] pub fn init() { self.owner = msg.sender; self.count = 0; }
    pub fn register(addr: Address) {
        let id = self.count;
        self.entries[id] = addr;
        self.count = id + 1;
        emit Registered { id: id, addr: addr };
    }
    #[view] pub fn get_count() -> u64 { return self.count; }
    #[view] pub fn lookup(id: u64) -> Address { return self.entries[id]; }
}
"#;

pub const ESCROW: &str = r#"
contract Escrow {
    storage { buyer: Address, seller: Address, amount: u256, released: bool, }
    #[constructor] #[payable] pub fn init(seller: Address) {
        self.buyer = msg.sender; self.seller = seller;
        self.amount = msg.value; self.released = false;
    }
    pub fn release() {
        require!(msg.sender == self.buyer);
        require!(!self.released);
        self.released = true;
    }
    #[view] pub fn is_released() -> bool { return self.released; }
}
"#;

pub const MULTISIG: &str = r#"
contract Multisig {
    storage { owner1: Address, owner2: Address, threshold: u64, nonce: u64, approved: Map<u64, u64>, }
    #[constructor] pub fn init(o1: Address, o2: Address) {
        self.owner1 = o1; self.owner2 = o2; self.threshold = 2; self.nonce = 0;
    }
    pub fn approve() {
        let n = self.nonce;
        self.approved[n] = self.approved[n] + 1;
    }
    pub fn execute() {
        let n = self.nonce;
        require!(self.approved[n] >= self.threshold);
        self.nonce = n + 1;
    }
    #[view] pub fn get_nonce() -> u64 { return self.nonce; }
}
"#;

pub const TIMELOCK: &str = r#"
contract Timelock {
    storage { owner: Address, locked_until: u64, value: u64, }
    #[constructor] pub fn init(lock_duration: u64) {
        self.owner = msg.sender; self.locked_until = lock_duration; self.value = 0;
    }
    pub fn set_value(v: u64) {
        require!(msg.sender == self.owner);
        self.value = v;
    }
    #[view] pub fn get_value() -> u64 { return self.value; }
}
"#;

pub const AMM_POOL: &str = r#"
contract AmmPool {
    storage {
        reserve_x: u256,
        reserve_y: u256,
        total_lp: u256,
        lp_balances: Map<Address, u256>,
    }
    event Swap { #[indexed] user: Address, amount_in: u256, amount_out: u256, }
    #[constructor] pub fn init() {
        self.reserve_x = 0u256; self.reserve_y = 0u256; self.total_lp = 0u256;
    }
    pub fn add_liquidity(x: u256, y: u256) {
        self.reserve_x = self.reserve_x + x;
        self.reserve_y = self.reserve_y + y;
        let lp = x + y;
        self.lp_balances[msg.sender] = self.lp_balances[msg.sender] + lp;
        self.total_lp = self.total_lp + lp;
    }
    pub fn swap_x_for_y(amount_in: u256) {
        let new_x = self.reserve_x + amount_in;
        let k = self.reserve_x * self.reserve_y;
        let new_y = k / new_x;
        let amount_out = self.reserve_y - new_y;
        self.reserve_x = new_x;
        self.reserve_y = new_y;
        emit Swap { user: msg.sender, amount_in: amount_in, amount_out: amount_out };
    }
    #[view] pub fn get_reserves() -> (u256, u256) { return (self.reserve_x, self.reserve_y); }
}
"#;

pub const VOTING: &str = r#"
contract Voting {
    storage { proposals: Map<u64, u256>, votes_cast: Map<Address, Map<u64, bool>>, proposal_count: u64, }
    event Voted { #[indexed] voter: Address, proposal: u64, weight: u256, }
    #[constructor] pub fn init() { self.proposal_count = 0; }
    pub fn create_proposal() {
        let id = self.proposal_count;
        self.proposals[id] = 0u256;
        self.proposal_count = id + 1;
    }
    pub fn vote(proposal_id: u64, weight: u256) {
        require!(!self.votes_cast[msg.sender][proposal_id]);
        self.votes_cast[msg.sender][proposal_id] = true;
        self.proposals[proposal_id] = self.proposals[proposal_id] + weight;
        emit Voted { voter: msg.sender, proposal: proposal_id, weight: weight };
    }
    #[view] pub fn get_votes(proposal_id: u64) -> u256 { return self.proposals[proposal_id]; }
    #[view] pub fn get_proposal_count() -> u64 { return self.proposal_count; }
}
"#;

pub const STACK_HEAP_STRESS: &str = r#"
contract StackHeapStress {
    storage { result: u64, }
    #[constructor] pub fn init() { self.result = 0; }
    pub fn deep_call(depth: u64) {
        if depth == 0 {
            self.result = self.result + 1;
        } else {
            let a: u64 = depth * 7;
            let b: u64 = a + depth * 3;
            let c: u64 = b ^ a;
            self.result = self.result + c;
            self.deep_call(depth - 1);
        }
    }
    pub fn loop_heavy(n: u64) {
        let mut acc: u64 = 0;
        for i in 0..n {
            let x = i * i;
            let y = x ^ (i << 3);
            let z = y + (x >> 2);
            acc = acc + z;
        }
        self.result = acc;
    }
    #[view] pub fn get_result() -> u64 { return self.result; }
}
"#;

// ═══════════════════════════════════════════════════════════════════
// FACTORY + CROSS-CONTRACT (multi-contract files)
// ═══════════════════════════════════════════════════════════════════

pub const TOKEN_FACTORY: &str = r#"
contract SimpleToken {
    storage { supply: u256, owner: Address, balances: Map<Address, u256>, }
    event Transfer { #[indexed] from: Address, #[indexed] to: Address, amount: u256, }
    #[constructor] pub fn init(supply: u256) {
        self.supply = supply; self.owner = msg.sender; self.balances[msg.sender] = supply;
    }
    pub fn mint(to: Address, amount: u256) {
        self.supply = self.supply + amount;
        self.balances[to] = self.balances[to] + amount;
        emit Transfer { from: msg.sender, to: to, amount: amount };
    }
    pub fn transfer(to: Address, amount: u256) {
        let bal = self.balances[msg.sender];
        require!(bal >= amount);
        self.balances[msg.sender] = bal - amount;
        self.balances[to] = self.balances[to] + amount;
        emit Transfer { from: msg.sender, to: to, amount: amount };
    }
    #[view] pub fn balance_of(addr: Address) -> u256 { return self.balances[addr]; }
    #[view] pub fn get_supply() -> u256 { return self.supply; }
}

contract TokenFactory {
    storage { last_token: Address, token_count: u64, }
    event TokenCreated { token: Address, }
    #[constructor] pub fn init() { self.token_count = 0; }
    pub fn create_token(initial_supply: u256) {
        let t = deploy!(SimpleToken, initial_supply);
        self.last_token = address(t);
        self.token_count = self.token_count + 1;
        emit TokenCreated { token: address(t) };
    }
    pub fn mint_on_last(to: Address, amount: u256) {
        SimpleToken::at(self.last_token).mint(to, amount);
    }
    #[view] pub fn get_token_count() -> u64 { return self.token_count; }
    #[view] pub fn get_last_token() -> Address { return self.last_token; }
}
"#;

// ═══════════════════════════════════════════════════════════════════
// Contract metadata for the benchmark
// ═══════════════════════════════════════════════════════════════════

pub struct ContractSpec {
    pub name: &'static str,
    pub source: &'static str,
    pub is_multi: bool, // compile_all returns multiple contracts
    pub has_constructor_args: bool,
    pub has_payable: bool,
}

pub fn all_contracts() -> Vec<ContractSpec> {
    vec![
        // Simple (10)
        ContractSpec {
            name: "Counter",
            source: COUNTER,
            is_multi: false,
            has_constructor_args: false,
            has_payable: false,
        },
        ContractSpec {
            name: "CounterArgs",
            source: COUNTER_ARGS,
            is_multi: false,
            has_constructor_args: true,
            has_payable: false,
        },
        ContractSpec {
            name: "SimpleStore",
            source: SIMPLE_STORE,
            is_multi: false,
            has_constructor_args: false,
            has_payable: false,
        },
        ContractSpec {
            name: "Accumulator",
            source: ACCUMULATOR,
            is_multi: false,
            has_constructor_args: false,
            has_payable: false,
        },
        ContractSpec {
            name: "Ownership",
            source: OWNERSHIP,
            is_multi: false,
            has_constructor_args: false,
            has_payable: false,
        },
        ContractSpec {
            name: "Piggybank",
            source: PIGGYBANK,
            is_multi: false,
            has_constructor_args: false,
            has_payable: true,
        },
        ContractSpec {
            name: "Whitelist",
            source: WHITELIST,
            is_multi: false,
            has_constructor_args: false,
            has_payable: false,
        },
        ContractSpec {
            name: "RateCounter",
            source: RATE_COUNTER,
            is_multi: false,
            has_constructor_args: false,
            has_payable: false,
        },
        ContractSpec {
            name: "Bitmap",
            source: BITMAP,
            is_multi: false,
            has_constructor_args: false,
            has_payable: false,
        },
        ContractSpec {
            name: "MultiSlot",
            source: MULTISLOT,
            is_multi: false,
            has_constructor_args: false,
            has_payable: false,
        },
        // Complex (12)
        ContractSpec {
            name: "Vault",
            source: VAULT,
            is_multi: false,
            has_constructor_args: false,
            has_payable: true,
        },
        ContractSpec {
            name: "Token",
            source: TOKEN,
            is_multi: false,
            has_constructor_args: true,
            has_payable: false,
        },
        ContractSpec {
            name: "Staking",
            source: STAKING,
            is_multi: false,
            has_constructor_args: true,
            has_payable: true,
        },
        ContractSpec {
            name: "MathHeavy",
            source: MATH_HEAVY,
            is_multi: false,
            has_constructor_args: false,
            has_payable: false,
        },
        ContractSpec {
            name: "Lottery",
            source: LOTTERY,
            is_multi: false,
            has_constructor_args: false,
            has_payable: true,
        },
        ContractSpec {
            name: "Registry",
            source: REGISTRY,
            is_multi: false,
            has_constructor_args: false,
            has_payable: false,
        },
        ContractSpec {
            name: "Escrow",
            source: ESCROW,
            is_multi: false,
            has_constructor_args: true,
            has_payable: true,
        },
        ContractSpec {
            name: "Multisig",
            source: MULTISIG,
            is_multi: false,
            has_constructor_args: true,
            has_payable: false,
        },
        ContractSpec {
            name: "Timelock",
            source: TIMELOCK,
            is_multi: false,
            has_constructor_args: true,
            has_payable: false,
        },
        ContractSpec {
            name: "AmmPool",
            source: AMM_POOL,
            is_multi: false,
            has_constructor_args: false,
            has_payable: false,
        },
        ContractSpec {
            name: "Voting",
            source: VOTING,
            is_multi: false,
            has_constructor_args: false,
            has_payable: false,
        },
        ContractSpec {
            name: "StackHeapStress",
            source: STACK_HEAP_STRESS,
            is_multi: false,
            has_constructor_args: false,
            has_payable: false,
        },
        // Factory + cross-contract (1 multi-contract file)
        ContractSpec {
            name: "TokenFactory",
            source: TOKEN_FACTORY,
            is_multi: true,
            has_constructor_args: false,
            has_payable: false,
        },
    ]
}
