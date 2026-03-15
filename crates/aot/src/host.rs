//! Host functions called by AOT-compiled native code.
//!
//! These functions bridge between native code and VM state (memory, storage,
//! crypto, events). The AOT code receives an opaque `*mut VmContext` pointer
//! and calls these functions for any operation that touches VM state.

use pyde_vm::vm::Vm;
use pyde_vm::wide::U256;

/// Opaque context pointer passed to AOT code. Points to a `Vm`.
pub type VmCtx = Vm;

// ── Memory operations ──────────────────────────────────────────────────

/// Host: load from memory. Returns the value, or u64::MAX on fault.
/// Width: 0=8bit, 1=16bit, 2=32bit, 3=64bit
pub extern "C" fn host_load(ctx: *mut VmCtx, addr: u64, width: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    let addr = addr as u32;
    let result = match width {
        0 => vm.memory.load8(addr).map(|v| v as u64),
        1 => vm.memory.load16(addr).map(|v| v as u64),
        2 => vm.memory.load32(addr).map(|v| v as u64),
        3 => vm.memory.load64(addr),
        _ => return u64::MAX,
    };
    match result {
        Ok(v) => v,
        Err(_) => u64::MAX, // signal fault
    }
}

/// Host: store to memory. Returns 0 on success, 1 on fault.
pub extern "C" fn host_store(ctx: *mut VmCtx, addr: u64, value: u64, width: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    let addr = addr as u32;
    let result = match width {
        0 => vm.memory.store8(addr, value as u8),
        1 => vm.memory.store16(addr, value as u16),
        2 => vm.memory.store32(addr, value as u32),
        3 => vm.memory.store64(addr, value),
        _ => return 1,
    };
    match result {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// Host: load 256-bit value from memory into wide register.
/// Returns 0 on success, 1 on fault.
pub extern "C" fn host_wload(ctx: *mut VmCtx, addr: u64, wd: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    match vm.memory.load256(addr as u32) {
        Ok(bytes) => {
            vm.cpu.write_wide(wd as u8, U256::from_le_bytes(bytes));
            0
        }
        Err(_) => 1,
    }
}

/// Host: store 256-bit value from wide register to memory.
/// Returns 0 on success, 1 on fault.
pub extern "C" fn host_wstore(ctx: *mut VmCtx, addr: u64, ws: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    let val = vm.cpu.read_wide(ws as u8);
    match vm.memory.store256(addr as u32, &val.to_le_bytes()) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

// ── Stack operations ───────────────────────────────────────────────────

/// Host: push a 64-bit value to stack. Returns 0 on success, 1 on fault.
pub extern "C" fn host_push(ctx: *mut VmCtx, value: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    match vm.memory.stack_alloc(8) {
        Ok(sp) => {
            vm.memory.store64(sp, value).unwrap_or(());
            0
        }
        Err(_) => 1,
    }
}

/// Host: pop a 64-bit value from stack. Returns the value, u64::MAX on fault.
pub extern "C" fn host_pop(ctx: *mut VmCtx) -> u64 {
    let vm = unsafe { &mut *ctx };
    let sp = vm.memory.stack_pointer;
    match vm.memory.load64(sp) {
        Ok(val) => {
            vm.memory.stack_pointer += 8;
            val
        }
        Err(_) => u64::MAX,
    }
}

// ── Storage operations ─────────────────────────────────────────────────

/// Host: sload wide register mode. Reads storage[slot_from_ws1] → wd.
/// Returns 0 on success.
pub extern "C" fn host_sload(ctx: *mut VmCtx, ws_slot: u64, wd: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    let slot = vm.cpu.read_wide(ws_slot as u8);
    let key = vm.derive_storage_key(slot);
    let mut buf = [0u8; 32];
    if let Some(data) = vm.storage.get(&key) {
        let len = data.len().min(32);
        buf[..len].copy_from_slice(&data[..len]);
    }
    vm.cpu.write_wide(wd as u8, U256::from_le_bytes(buf));
    0
}

/// Host: sload GP register mode. Reads storage[slot_from_ws1] → rd (8 bytes).
/// Returns the loaded value.
pub extern "C" fn host_sloadg(ctx: *mut VmCtx, ws_slot: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    let slot = vm.cpu.read_wide(ws_slot as u8);
    let key = vm.derive_storage_key(slot);
    let mut buf = [0u8; 8];
    if let Some(data) = vm.storage.get(&key) {
        let len = data.len().min(8);
        buf[..len].copy_from_slice(&data[..len]);
    }
    u64::from_le_bytes(buf)
}

/// Host: sstore wide register mode. Writes storage[slot_from_ws1] = wd.
/// Returns 0 on success, 1 if static mode violation.
pub extern "C" fn host_sstore(ctx: *mut VmCtx, ws_slot: u64, wd: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    if vm.static_mode {
        return 1;
    }
    let slot = vm.cpu.read_wide(ws_slot as u8);
    let key = vm.derive_storage_key(slot);
    vm.journal_storage_write(&key);
    let value = vm.cpu.read_wide(wd as u8);
    vm.storage.insert(key, value.to_le_bytes().to_vec());
    0
}

/// Host: sstore GP register mode. Writes storage[slot_from_ws1] = rd (8 bytes).
/// Returns 0 on success, 1 if static mode violation.
pub extern "C" fn host_sstoreg(ctx: *mut VmCtx, ws_slot: u64, value: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    if vm.static_mode {
        return 1;
    }
    let slot = vm.cpu.read_wide(ws_slot as u8);
    let key = vm.derive_storage_key(slot);
    vm.journal_storage_write(&key);
    vm.storage.insert(key, value.to_le_bytes().to_vec());
    0
}

/// Host: sdelete. Clears storage[slot_from_ws1], grants refund if non-empty.
/// Returns 0 on success, 1 if static mode violation.
pub extern "C" fn host_sdelete(ctx: *mut VmCtx, ws_slot: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    if vm.static_mode {
        return 1;
    }
    let slot = vm.cpu.read_wide(ws_slot as u8);
    let key = vm.derive_storage_key(slot);
    vm.journal_storage_write(&key);
    if let Some(v) = vm.storage.get(&key) {
        if !v.is_empty() {
            vm.gas_refund += 1500;
        }
    }
    vm.storage.insert(key, Vec::new());
    0
}

// ── Crypto operations ──────────────────────────────────────────────────

/// Host: poseidon hash. Hashes memory[addr..addr+len] → wd.
/// Returns 0 on success, 1 on fault.
pub extern "C" fn host_poseidon(ctx: *mut VmCtx, addr: u64, len: u64, wd: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    let addr = addr as u32;
    let len = len as usize;
    let mut data = vec![0u8; len];
    for (i, b) in data.iter_mut().enumerate() {
        match vm.memory.load8(addr + i as u32) {
            Ok(v) => *b = v,
            Err(_) => return 1,
        }
    }
    let hash = pyde_crypto::poseidon2::poseidon2_hash(&data);
    let hash_bytes: [u8; 32] = hash.to_bytes();
    vm.cpu.write_wide(wd as u8, U256::from_le_bytes(hash_bytes));
    0
}

// ── Wide arithmetic operations ─────────────────────────────────────────

/// Host: execute a wide (256-bit) ALU operation.
/// op_code: raw opcode byte (Wadd=0x09, Wsub=0x0A, etc.)
/// wd, ws1, ws2: wide register indices.
/// Returns 0 on success, 1 on trap (overflow/underflow/div-by-zero).
pub extern "C" fn host_wide_alu(ctx: *mut VmCtx, op_code: u64, wd: u64, ws1: u64, ws2: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    let instr = pyde_vm::isa::encode(
        pyde_vm::isa::Opcode::from_u8(op_code as u8),
        wd as u8,
        ws1 as u8,
        ws2 as u32,
    );
    match vm.cpu.exec_wide(instr) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// Host: narrow (wide → GP). Returns the narrowed u64 value.
/// Sets *trap_out to 1 if value exceeds u64::MAX.
pub extern "C" fn host_narrow(ctx: *mut VmCtx, ws1: u64, trap_out: *mut u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    let wide_val = vm.cpu.read_wide(ws1 as u8);
    let bytes = wide_val.to_le_bytes();
    // Check if any bytes above the first 8 are non-zero
    if bytes[8..].iter().any(|&b| b != 0) {
        unsafe { *trap_out = 1; }
        return 0;
    }
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

/// Host: widen (GP → wide). Takes the GP value directly from AOT, writes to wide register.
pub extern "C" fn host_widen(ctx: *mut VmCtx, wd: u64, gp_value: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    vm.cpu.write_wide(wd as u8, pyde_vm::wide::U256::from(gp_value));
    0
}

// ── Checked arithmetic (overflow detection) ────────────────────────────

/// Host: checked add. Returns result, sets *trap_out to 1 on overflow.
pub extern "C" fn host_checked_add(a: u64, b: u64, trap_out: *mut u64) -> u64 {
    match a.checked_add(b) {
        Some(r) => r,
        None => {
            unsafe { *trap_out = 1; }
            0
        }
    }
}

/// Host: checked sub. Returns result, sets *trap_out to 1 on underflow.
pub extern "C" fn host_checked_sub(a: u64, b: u64, trap_out: *mut u64) -> u64 {
    match a.checked_sub(b) {
        Some(r) => r,
        None => {
            unsafe { *trap_out = 1; }
            0
        }
    }
}

/// Host: checked mul. Returns result, sets *trap_out to 1 on overflow.
pub extern "C" fn host_checked_mul(a: u64, b: u64, trap_out: *mut u64) -> u64 {
    match a.checked_mul(b) {
        Some(r) => r,
        None => {
            unsafe { *trap_out = 1; }
            0
        }
    }
}

/// Host: checked div. Returns result, sets *trap_out to 1 on div-by-zero.
pub extern "C" fn host_checked_div(a: u64, b: u64, trap_out: *mut u64) -> u64 {
    if b == 0 {
        unsafe { *trap_out = 1; }
        return 0;
    }
    a / b
}

/// Host: checked mod. Returns result, sets *trap_out to 1 on div-by-zero.
pub extern "C" fn host_checked_mod(a: u64, b: u64, trap_out: *mut u64) -> u64 {
    if b == 0 {
        unsafe { *trap_out = 1; }
        return 0;
    }
    a % b
}

// ── Event operations ───────────────────────────────────────────────────

/// Host: emit log event. Returns 0 on success, 1 on static mode violation, 2 on fault.
pub extern "C" fn host_log(ctx: *mut VmCtx, desc_ptr: u64, num_topics: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    if vm.static_mode {
        return 1;
    }
    // Delegate to VM's existing LOG logic would require refactoring.
    // For now, return 0 (success stub — full implementation deferred to
    // when LOG is factored into a callable helper on Vm).
    0
}

// ── Environment queries ────────────────────────────────────────────────

/// Host: get caller (msg.sender) into wide register wd.
pub extern "C" fn host_caller(ctx: *mut VmCtx, wd: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    vm.cpu.write_wide(wd as u8, pyde_vm::wide::U256::from_le_bytes(vm.ctx.caller));
    0
}

/// Host: get self address into wide register wd.
pub extern "C" fn host_address(ctx: *mut VmCtx, wd: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    vm.cpu.write_wide(wd as u8, pyde_vm::wide::U256::from_le_bytes(vm.ctx.self_address));
    0
}

/// Host: get block number.
pub extern "C" fn host_block_number(ctx: *mut VmCtx) -> u64 {
    let vm = unsafe { &mut *ctx };
    vm.ctx.block_number
}

/// Host: get timestamp.
pub extern "C" fn host_timestamp(ctx: *mut VmCtx) -> u64 {
    let vm = unsafe { &mut *ctx };
    vm.ctx.timestamp
}

/// Host: get gas remaining.
pub extern "C" fn host_gas_remaining(ctx: *mut VmCtx) -> u64 {
    let vm = unsafe { &mut *ctx };
    vm.gas_remaining()
}

/// Host: get call value (256-bit) into wide register.
pub extern "C" fn host_callvalue(ctx: *mut VmCtx, wd: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    vm.cpu.write_wide(wd as u8, vm.ctx.call_value);
    0
}

/// Host: get gas price into wide register.
pub extern "C" fn host_gasprice(ctx: *mut VmCtx, wd: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    vm.cpu.write_wide(wd as u8, vm.ctx.gas_price);
    0
}

/// Host: get balance of address (in wide register ws) into wide register wd.
pub extern "C" fn host_balance(ctx: *mut VmCtx, ws_addr: u64, wd: u64) -> u64 {
    let vm = unsafe { &mut *ctx };
    let addr_u256 = vm.cpu.read_wide(ws_addr as u8);
    let addr: [u8; 32] = addr_u256.to_le_bytes();
    let bal = vm.ctx.balances.get(&addr).copied().unwrap_or(U256::ZERO);
    vm.cpu.write_wide(wd as u8, bal);
    0
}

/// Host: assert — returns 0 if val != 0, 1 (revert) if val == 0.
pub extern "C" fn host_assert(_ctx: *mut VmCtx, val: u64) -> u64 {
    if val == 0 { 1 } else { 0 }
}

/// Host: field_mul rd = (a * b) mod Goldilocks prime. Returns result.
pub extern "C" fn host_field_mul(_ctx: *mut VmCtx, a: u64, b: u64) -> u64 {
    const GOLDILOCKS_P: u128 = (1u128 << 64) - (1u128 << 32) + 1;
    ((a as u128 * b as u128) % GOLDILOCKS_P) as u64
}

/// List of all host function names and their function pointers, for
/// registration with the JIT module.
pub fn host_functions() -> Vec<(&'static str, *const u8)> {
    vec![
        ("host_load", host_load as *const u8),
        ("host_store", host_store as *const u8),
        ("host_wload", host_wload as *const u8),
        ("host_wstore", host_wstore as *const u8),
        ("host_push", host_push as *const u8),
        ("host_pop", host_pop as *const u8),
        ("host_sload", host_sload as *const u8),
        ("host_sloadg", host_sloadg as *const u8),
        ("host_sstore", host_sstore as *const u8),
        ("host_sstoreg", host_sstoreg as *const u8),
        ("host_sdelete", host_sdelete as *const u8),
        ("host_poseidon", host_poseidon as *const u8),
        ("host_log", host_log as *const u8),
        ("host_wide_alu", host_wide_alu as *const u8),
        ("host_narrow", host_narrow as *const u8),
        ("host_widen", host_widen as *const u8),
        ("host_caller", host_caller as *const u8),
        ("host_address", host_address as *const u8),
        ("host_block_number", host_block_number as *const u8),
        ("host_timestamp", host_timestamp as *const u8),
        ("host_gas_remaining", host_gas_remaining as *const u8),
        ("host_callvalue", host_callvalue as *const u8),
        ("host_gasprice", host_gasprice as *const u8),
        ("host_balance", host_balance as *const u8),
        ("host_assert", host_assert as *const u8),
        ("host_field_mul", host_field_mul as *const u8),
        ("host_checked_add", host_checked_add as *const u8),
        ("host_checked_sub", host_checked_sub as *const u8),
        ("host_checked_mul", host_checked_mul as *const u8),
        ("host_checked_div", host_checked_div as *const u8),
        ("host_checked_mod", host_checked_mod as *const u8),
    ]
}
