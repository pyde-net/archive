# Cheatcodes, Typed Contracts, and Import-Based Test Model — Roadmap

## Overview

Add typed contract/interface instances to the compiler (production + tests), cross-file imports,
Foundry-style cheatcodes, and proper test isolation.
PVM stays 100% production-clean — all cheatcode logic lives in pyde-dev only.

---

## Execution Order

Steps are ordered by dependency — each builds on the previous.

### Step 1: `deploy!` macro + `create!` alias ---- DONE

- [x] Add `deploy!` macro in lowerer — returns `Ty::Contract("Counter")`
- [x] `create!` becomes alias for `deploy!` (both return typed handle)
- [x] Runtime: identical to current `create!` (CreateContract instruction)
- [x] Works within single-file multi-contract compilation
- [x] Typechecker returns `Ty::Contract(name)` for deploy!/create!
- [x] Type propagates through `let c = deploy!(Counter);` via reg_types → local_types

### Step 2: Complete method signature resolution ---- DONE

- [x] Populate `contract_functions` from current file's contract definitions (pub fns)
- [x] Populate `interface_functions` from interface definitions (already done in pre-pass)
- [x] Lowerer resolves `c.increment()` → correct `ExtCall` with selector
- [x] Pre-pass 2 collects contract pub fns before lowering (declaration-order independent)

### Step 3: Return value decoding from ExtCall ---- DONE

- [x] GP return (u64, bool) — PVM sets r1 = value, r2 = 0
- [x] Wide return (u256, Address) — PVM writes 32 bytes to parent heap, r1 = ptr, r2 = 32
- [x] Callee wide return uses blob convention (r1=ptr, r2=32) instead of lossy r1-only
- [x] PVM do_ext_call reads r2 bytes from child memory for blob/wide returns
- [x] PVM CallExt handler writes wide return_data to parent heap for Wload
- [x] ExtCall IR instruction carries return type: `ExtCall(dst, addr, method, args, Ty)`
- [x] Lowerer looks up return type from contract_functions/interface_functions
- [x] Makes `assert!(c.get_count() == 1)` work end-to-end

### Step 4: Constructor arg validation ---- DONE

- [x] At compile time, check `deploy!(Counter, x, y)` args match constructor params
- [x] Count + type checking against stored constructor signature
- [x] Lowerer: contract_constructors populated in pre-pass 2, arg count validated
- [x] Typechecker: contract_constructors in TypeEnv, validates count + types with widening

### Step 5: `as` casts for Contract/Interface types ---- DONE

- [x] `contract_handle as Address` — strip type, return raw address (wide→wide Wmov)
- [x] `addr as IERC20` / `addr as Counter` — wrap address with type info, sets reg_types
- [x] Typecheck validates all cast directions (Contract/Interface ↔ Address, cross-cast)
- [x] `is_wide_type` includes Contract/Interface (they're addresses under the hood)
- [x] Cast codegen handles wide→wide copies (was missing, used alloc_gp before)
- [x] Typechecker resolve_type resolves named types to Contract/Interface via contract_names set

### Step 6: Wire cheatcodes into test runner ---- DONE

- [x] Replace `vm.execute()` with `execute_with_cheatcodes()` in test_runner.rs
- [x] Fresh `CheatcodeState::new()` per test (no prank/warp leaking)
- [x] Each test gets fresh VM + storage snapshot (already worked, unchanged)
- [x] Constructor still uses `vm.execute()` (no cheatcodes during init)

### Step 7: Cross-file imports — resolver ---- DONE

- [x] Rust-like import syntax: `use counter::Counter;`, `use counter::{Counter, MyError};`
- [x] `SymbolKind::Contract` added, contract declarations use it (was incorrectly `Struct`)
- [x] Non-std imports register items as `Contract`, module name as `Module`
- [x] `is_type_defined` includes `Contract` (valid as type annotation and cast target)
- [x] std:: imports return early, don't fall through to non-std handling
- [x] Typechecker skips constructor validation for imported contracts (unknown sig)

### Step 8: Build pipeline returns registry + ASTs ---- DONE

- [x] `BuildResult` includes `compiled_registry`, `contract_functions`, `contract_constructors`
- [x] Function signatures extracted from IR during compilation (pub fns + constructor)
- [x] Dependency graph resolver uses first path segment (module name) for Rust-like imports
- [x] Available to callers (test runner, deploy, etc.)

### Step 9: Test files compiled with registry ---- DONE

- [x] `lower_with_context()` accepts bytecode + fn sigs + constructor sigs
- [x] Imported contract function signatures available for typed method dispatch
- [x] Cycle detection already done (build.rs topological sort)

### Step 10: Test runner registry integration ---- DONE

- [x] Test runner captures `BuildResult`, passes all maps to `lower_with_context()`
- [x] Deployed contracts auto-registered in `vm.contracts` by PVM Create instruction
- [x] Full isolation: fresh VM + storage + CheatcodeState per test function

### Step 11: `@std/vm.oti` cheatcode library ---- DONE

- [x] Ships with `pyde-dev init` (embedded via include_str!)
<!-- The magic address approach for cheatcodes:

 How it works:
 1. Cheatcode library (@std/vm.oti) has functions like warp(timestamp), deal(addr, amount), etc.
 2. These functions compile to CallExt targeting a hardcoded address 0xCCCCCC...CC (32 bytes of 0xCC)
 3. The calldata contains: [selector:8 bytes][args...] — selector is FNV-1a hash of the cheatcode name

 In production (validator node):
 - VM calls do_ext_call → looks up 0xCC..CC → no code found → returns success: false
 - Nothing happens. Completely harmless.

 In tests (pyde-dev test):
 - Test runner uses execute_with_cheatcodes() instead of vm.execute()
 - Custom step loop peeks at each instruction before executing
 - If it sees CallExt with target 0xCC..CC, it intercepts:
   - Reads calldata from VM memory
   - Decodes selector → determines which cheatcode
   - Applies the effect directly (e.g., vm.ctx.timestamp = value)
   - Writes success: 1 to result register
   - Skips the instruction (vm.pc += 4)
 - All other instructions execute normally via vm.step()

 Key point: Zero PVM changes. The interception logic lives entirely in crates/pyde-dev/src/cheatcodes.rs. The PVM doesn't know cheatcodes exist. -->

- [x] Vm interface with warp, roll, prank, startPrank, stopPrank, deal, makeAddr
- [x] Cheatcode selectors aligned with codegen compute_selector (FNV-1a of method name)
- [x] Calldata format aligned: [selector:4 BE][args:8 LE each]
- [x] `use std::vm;` in test files → `Vm::at(CHEATCODE_ADDRESS).warp(1000)`

### Step 12: Standard library ---- DONE

- [x] `lib/@std/vm.oti` — Vm interface (cheatcode methods)
- [x] `lib/@std/token.oti` — IERC20, IERC721 interfaces
- [x] `lib/@std/math.oti` — Math interface (min, max, sqrt, pow, etc.)
- [x] Starter test updated to use `use counter::Counter;` + `deploy!(Counter)`
- [x] All stdlib files embedded via `include_str!` and shipped with `pyde-dev init`

---

## Already Done

- [x] `Ty::Contract(name)` and `Ty::Interface(name)` in the type system (`types.rs`)
- [x] `Contract::at(address)` / `Interface::at(address)` in lowerer (`lower.rs`)
- [x] Method calls on typed handles → `Inst::ExtCall` with auto-resolved selector (`lower.rs`)
- [x] Magic address interception in step loop (`cheatcodes.rs`)
- [x] Cheatcode handlers: warp, roll, prank, startPrank, stopPrank, deal, makeAddr
- [x] `create!` macro embeds bytecode + deploys via CreateContract
- [x] `reg_types` tracking for Contract/Interface typed handles in lowerer
- [x] `clear_journal()` public method on VM

---

## Final test example

```
use counter::Counter;
use std::vm;

contract CounterTest {
    #[test]
    fn test_increment() {
        let c = deploy!(Counter);
        c.increment();
        assert!(c.get_count() == 1);
    }

    #[test]
    fn test_with_cheatcodes() {
        vm.warp(1000);
        vm.roll(42);
        let alice = vm.makeAddr("alice");
        vm.deal(alice, 1000000 as u256);
        vm.prank(alice);
        let c = deploy!(Counter);
        c.increment();
        assert!(c.get_count() == 1);
    }

    #[test]
    #[should_panic(expected = "InsufficientBalance")]
    fn test_overdraw() {
        let v = deploy!(Vault);
        v.withdraw(9999);
    }
}
```

## Architecture

```
Production PVM (untouched)
    |
    +-- vm.execute()     <- used by validator node
    |
pyde-dev test runner
    |
    +-- execute_with_cheatcodes()  <- custom step loop
    |   +-- peek at instruction before step
    |   +-- if CallExt to 0xCC..CC -> intercept, apply cheatcode
    |   +-- else -> normal vm.step()
    |
    +-- cheatcodes.rs (all logic here, not in PVM)
```

## Files involved

| File                                 | Role                                                             |
| ------------------------------------ | ---------------------------------------------------------------- |
| `crates/otic/src/types.rs`           | Ty::Contract, Ty::Interface                                      |
| `crates/otic/src/resolve.rs`         | Accept non-std imports, validate contract types                  |
| `crates/otic/src/lower.rs`           | deploy!, ::at(), method calls -> ExtCall, constructor validation |
| `crates/otic/src/codegen.rs`         | ExtCall codegen (already works), cast support                    |
| `crates/otic/src/typecheck.rs`       | Contract/Interface type checking, cast validation                |
| `crates/pyde-dev/src/build.rs`       | Return compiled_registry + contract ASTs                         |
| `crates/pyde-dev/src/test_runner.rs` | Wire registry, cheatcodes, contract isolation                    |
| `crates/pyde-dev/src/cheatcodes.rs`  | Cheatcode interception + handlers                                |
| `crates/pyde-dev/src/init.rs`        | Ship @std/ with new projects                                     |
| `crates/pvm/src/vm.rs`               | Only change: clear_journal() public method (done)                |

---

## Language Design: Per-Call Value for Payable Functions

### Problem

Current `Counter::at_payable(addr, value)` bakes the value into the contract handle.
This means ALL calls through that handle send the same value — even non-payable reads.

```otigen
let c = Counter::at_payable(addr, 1000);
c.deposit();     // sends 1000 ✓ (intended)
c.get_count();   // sends 1000 ✗ (wasteful/wrong)
c.withdraw(50);  // sends 1000 ✗ (definitely wrong)
```

### Proposed Fix

Value should be per-call, not per-instance. Options:

**Option A: Annotation syntax (Solidity-style)**
```otigen
let c = Counter::at(addr);
c.deposit{ value: 1000 }();
c.get_count();               // no value
```

**Option B: Builder pattern**
```otigen
let c = Counter::at(addr);
c.deposit().value(1000).send();
c.get_count();
```

**Option C: Named parameter**
```otigen
let c = Counter::at(addr);
c.deposit(value: 1000);
c.get_count();
```

### Also Needed

- `deploy!(Counter, arg1, value: 1000)` — deploy with value for payable constructors
- Deprecate `at_payable()` once per-call value is implemented

### Priority

Medium — the CLI `pyde-dev deploy --value` and `pyde-dev send --value` work correctly.
This is a language ergonomics improvement for the Otigen compiler.
