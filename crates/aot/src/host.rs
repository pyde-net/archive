//! Host functions called by AOT-compiled native code.
//!
//! These functions bridge between native code and VM state (memory, storage,
//! crypto, events). The AOT code receives an opaque `*mut VmContext` pointer
//! and calls these functions for any operation that touches VM state.
//!
//! ## Pointer safety contract
//!
//! Every function here is `extern "C"` and takes `*mut VmCtx` as its first
//! argument. The pointer comes from the AOT JIT (`aot/src/codegen.rs`),
//! which emits call-site code that loads a live `&mut Vm` address into the
//! platform ABI's first register.
//!
//! Clippy's `not_unsafe_ptr_arg_deref` is correct in principle — these
//! functions ARE unsafe to call with an invalid pointer. Marking every
//! signature `unsafe extern "C" fn` would force matching `unsafe { }` blocks
//! at every JIT emission site, which is purely ergonomic friction (the
//! generated assembly already dereferences the pointer unconditionally).
//! Reviewers of this module should verify the JIT's callsite emission
//! whenever host signatures change.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use pyde_vm::vm::Vm;
use pyde_vm::wide::U256;

/// Opaque context pointer passed to AOT code. Points to a `Vm`.
pub type VmCtx = Vm;

// ── Memory operations ──────────────────────────────────────────────────

/// Host: load from memory. Returns the value, or u64::MAX on fault.
/// Width: 0=8bit, 1=16bit, 2=32bit, 3=64bit
pub extern "C" fn host_load(ctx: *mut VmCtx, addr: u64, width: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
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
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
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
/// Returns 0 on success, 1 on fault (memory fault or invalid wide reg).
pub extern "C" fn host_wload(ctx: *mut VmCtx, addr: u64, wd: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    match vm.memory.load256(addr as u32) {
        Ok(bytes) => {
            if vm
                .cpu
                .write_wide_checked(wd as u8, U256::from_le_bytes(bytes))
                .is_err()
            {
                return 1;
            }
            0
        }
        Err(_) => 1,
    }
}

/// Host: store 256-bit value from wide register to memory.
/// Returns 0 on success, 1 on fault.
pub extern "C" fn host_wstore(ctx: *mut VmCtx, addr: u64, ws: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    let val = match vm.cpu.read_wide_checked(ws as u8) {
        Ok(v) => v,
        Err(_) => return 1,
    };
    match vm.memory.store256(addr as u32, &val.to_le_bytes()) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

// ── Stack operations ───────────────────────────────────────────────────

/// Host: push a 64-bit value to stack. Returns 0 on success, 1 on fault.
pub extern "C" fn host_push(ctx: *mut VmCtx, value: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    match vm.memory.stack_alloc(8) {
        Ok(sp) => match vm.memory.store64(sp, value) {
            Ok(()) => 0,
            // stack_alloc succeeded but the store failed (e.g. page
            // fault underneath the just-allocated region). Return fault
            // so the AOT-compiled caller traps — previously this was
            // silently swallowed with .unwrap_or(()).
            Err(_) => 1,
        },
        Err(_) => 1,
    }
}

/// Host: pop a 64-bit value from stack. Returns the value, u64::MAX on fault.
pub extern "C" fn host_pop(ctx: *mut VmCtx) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
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
///
/// Audit 228c — also charges the EIP-2929 cold-access surcharge
/// (1800 gas) on first touch of a key per-tx, mirroring the
/// interpreter's `Opcode::Sload` handler. Surcharge is added to
/// `vm.memory.page_gas_used` so the AOT codegen drains it via
/// `host_drain_page_gas` after the call (the field doubles as
/// the AOT-drainable dynamic-gas accumulator, not just memory
/// pages).
pub extern "C" fn host_sload(ctx: *mut VmCtx, ws_slot: u64, wd: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    let slot = match vm.cpu.read_wide_checked(ws_slot as u8) {
        Ok(v) => v,
        Err(_) => return 1,
    };
    let key = vm.derive_storage_key(slot);
    if !vm.warm_storage_keys.contains(&key) {
        vm.warm_storage_keys.insert(key);
        vm.memory.page_gas_used = vm.memory.page_gas_used.saturating_add(1800);
    }
    // Check overlay first, then fall back to storage backend (SMT)
    let data = vm.storage.get(&key).cloned().or_else(|| {
        if let Some(ref backend) = vm.storage_backend {
            let val = backend(&key);
            if let Some(ref v) = val {
                vm.storage.insert(key, v.clone());
            }
            val
        } else {
            None
        }
    });
    let mut buf = [0u8; 32];
    if let Some(ref d) = data {
        let len = d.len().min(32);
        buf[..len].copy_from_slice(&d[..len]);
    }
    if vm
        .cpu
        .write_wide_checked(wd as u8, U256::from_le_bytes(buf))
        .is_err()
    {
        return 1;
    }
    0
}

/// Host: sload GP register mode. Reads storage[slot_from_ws1] → rd (8 bytes).
/// Returns the loaded value.
pub extern "C" fn host_sloadg(ctx: *mut VmCtx, ws_slot: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    // Invalid wide reg → return 0. host_sloadg signals "no data" via 0,
    // matching the behavior when the slot is empty.
    let slot = match vm.cpu.read_wide_checked(ws_slot as u8) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let key = vm.derive_storage_key(slot);
    // Audit 228c: same EIP-2929 cold-access surcharge as host_sload.
    if !vm.warm_storage_keys.contains(&key) {
        vm.warm_storage_keys.insert(key);
        vm.memory.page_gas_used = vm.memory.page_gas_used.saturating_add(1800);
    }
    // Check overlay first, then fall back to storage backend (SMT)
    let data = vm.storage.get(&key).cloned().or_else(|| {
        if let Some(ref backend) = vm.storage_backend {
            let val = backend(&key);
            if let Some(ref v) = val {
                vm.storage.insert(key, v.clone());
            }
            val
        } else {
            None
        }
    });
    let mut buf = [0u8; 8];
    if let Some(ref d) = data {
        let len = d.len().min(8);
        buf[..len].copy_from_slice(&d[..len]);
    }
    u64::from_le_bytes(buf)
}

/// Host: sstore wide register mode. Writes storage[slot_from_ws1] = wd.
/// Returns 0 on success, 1 if static mode violation.
pub extern "C" fn host_sstore(ctx: *mut VmCtx, ws_slot: u64, wd: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    if vm.static_mode {
        return 1;
    }
    let slot = match vm.cpu.read_wide_checked(ws_slot as u8) {
        Ok(v) => v,
        Err(_) => return 1,
    };
    let key = vm.derive_storage_key(slot);
    // Audit 228c: EIP-2929 cold-access surcharge on first Sstore.
    if !vm.warm_storage_keys.contains(&key) {
        vm.warm_storage_keys.insert(key);
        vm.memory.page_gas_used = vm.memory.page_gas_used.saturating_add(1800);
    }
    vm.journal_storage_write(&key);
    let value = match vm.cpu.read_wide_checked(wd as u8) {
        Ok(v) => v,
        Err(_) => return 1,
    };
    vm.storage.insert(key, value.to_le_bytes().to_vec());
    0
}

/// Host: sstore GP register mode. Writes storage[slot_from_ws1] = rd (8 bytes).
/// Returns 0 on success, 1 if static mode violation.
pub extern "C" fn host_sstoreg(ctx: *mut VmCtx, ws_slot: u64, value: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    if vm.static_mode {
        return 1;
    }
    let slot = match vm.cpu.read_wide_checked(ws_slot as u8) {
        Ok(v) => v,
        Err(_) => return 1,
    };
    let key = vm.derive_storage_key(slot);
    // Audit 228c: EIP-2929 cold-access surcharge on first Sstoreg.
    if !vm.warm_storage_keys.contains(&key) {
        vm.warm_storage_keys.insert(key);
        vm.memory.page_gas_used = vm.memory.page_gas_used.saturating_add(1800);
    }
    vm.journal_storage_write(&key);
    vm.storage.insert(key, value.to_le_bytes().to_vec());
    0
}

/// Host: sdelete. Clears storage[slot_from_ws1], grants refund if non-empty.
/// Returns 0 on success, 1 if static mode violation.
pub extern "C" fn host_sdelete(ctx: *mut VmCtx, ws_slot: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    if vm.static_mode {
        return 1;
    }
    let slot = match vm.cpu.read_wide_checked(ws_slot as u8) {
        Ok(v) => v,
        Err(_) => return 1,
    };
    let key = vm.derive_storage_key(slot);
    // Audit 228c: EIP-2929 cold-access surcharge on first Sdelete.
    if !vm.warm_storage_keys.contains(&key) {
        vm.warm_storage_keys.insert(key);
        vm.memory.page_gas_used = vm.memory.page_gas_used.saturating_add(1800);
    }
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
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    let addr = addr as u32;
    let len = len as usize;
    let data = match vm.memory.checked_read_slice(addr, len) {
        Ok(d) => d,
        Err(_) => return 1,
    };
    let hash = pyde_crypto::poseidon2::poseidon2_hash(&data);
    let hash_bytes: [u8; 32] = hash.to_bytes();
    if vm
        .cpu
        .write_wide_checked(wd as u8, U256::from_le_bytes(hash_bytes))
        .is_err()
    {
        return 1;
    }
    0
}

// ── Wide arithmetic operations ─────────────────────────────────────────

/// Host: execute a wide (256-bit) ALU operation.
/// op_code: raw opcode byte (Wadd=0x09, Wsub=0x0A, etc.)
/// wd, ws1, ws2: wide register indices.
/// Returns 0 on success, 1 on trap (overflow/underflow/div-by-zero).
pub extern "C" fn host_wide_alu(ctx: *mut VmCtx, op_code: u64, wd: u64, ws1: u64, ws2: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
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
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    let wide_val = match vm.cpu.read_wide_checked(ws1 as u8) {
        Ok(v) => v,
        Err(_) => {
            // SAFETY: `trap_out` is a valid out-pointer provided by the
            // AOT JIT (emitted alongside the call). See module-level
            // pointer safety contract.
            unsafe {
                *trap_out = 1;
            }
            return 0;
        }
    };
    let bytes = wide_val.to_le_bytes();
    // Check if any bytes above the first 8 are non-zero
    if bytes[8..].iter().any(|&b| b != 0) {
        // SAFETY: `trap_out` is a valid out-pointer provided by the
        // AOT JIT (emitted alongside the call). See module-level
        // pointer safety contract.
        unsafe {
            *trap_out = 1;
        }
        return 0;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(buf)
}

/// Host: widen (GP → wide). Takes the GP value directly from AOT, writes to wide register.
pub extern "C" fn host_widen(ctx: *mut VmCtx, wd: u64, gp_value: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    if vm
        .cpu
        .write_wide_checked(wd as u8, pyde_vm::wide::U256::from(gp_value))
        .is_err()
    {
        return 1;
    }
    0
}

/// Host: read a GP register value from the VM. Used by AOT to sync
/// GP register state after wide ops that write to GP (Weq, Wlt).
pub extern "C" fn host_read_gp(ctx: *mut VmCtx, reg: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    vm.cpu.read_gp(reg as u8)
}

// ── Checked arithmetic (overflow detection) ────────────────────────────

/// Host: checked add. Returns result, sets *trap_out to 1 on overflow.
pub extern "C" fn host_checked_add(a: u64, b: u64, trap_out: *mut u64) -> u64 {
    match a.checked_add(b) {
        Some(r) => r,
        None => {
            // SAFETY: `trap_out` is a valid out-pointer provided by the
            // AOT JIT (emitted alongside the call). See module-level
            // pointer safety contract.
            unsafe {
                *trap_out = 1;
            }
            0
        }
    }
}

/// Host: checked sub. Returns result, sets *trap_out to 1 on underflow.
pub extern "C" fn host_checked_sub(a: u64, b: u64, trap_out: *mut u64) -> u64 {
    match a.checked_sub(b) {
        Some(r) => r,
        None => {
            // SAFETY: `trap_out` is a valid out-pointer provided by the
            // AOT JIT (emitted alongside the call). See module-level
            // pointer safety contract.
            unsafe {
                *trap_out = 1;
            }
            0
        }
    }
}

/// Host: checked mul. Returns result, sets *trap_out to 1 on overflow.
pub extern "C" fn host_checked_mul(a: u64, b: u64, trap_out: *mut u64) -> u64 {
    match a.checked_mul(b) {
        Some(r) => r,
        None => {
            // SAFETY: `trap_out` is a valid out-pointer provided by the
            // AOT JIT (emitted alongside the call). See module-level
            // pointer safety contract.
            unsafe {
                *trap_out = 1;
            }
            0
        }
    }
}

/// Host: checked div. Returns result, sets *trap_out to 1 on div-by-zero.
pub extern "C" fn host_checked_div(a: u64, b: u64, trap_out: *mut u64) -> u64 {
    if b == 0 {
        // SAFETY: `trap_out` is a valid out-pointer provided by the
        // AOT JIT (emitted alongside the call). See module-level
        // pointer safety contract.
        unsafe {
            *trap_out = 1;
        }
        return 0;
    }
    a / b
}

/// Host: checked mod. Returns result, sets *trap_out to 1 on div-by-zero.
pub extern "C" fn host_checked_mod(a: u64, b: u64, trap_out: *mut u64) -> u64 {
    if b == 0 {
        // SAFETY: `trap_out` is a valid out-pointer provided by the
        // AOT JIT (emitted alongside the call). See module-level
        // pointer safety contract.
        unsafe {
            *trap_out = 1;
        }
        return 0;
    }
    a % b
}

// ── Event operations ───────────────────────────────────────────────────

/// Host: emit log event. Returns 0 on success, 1 on static mode violation or fault.
pub extern "C" fn host_log(ctx: *mut VmCtx, desc_ptr: u64, num_topics: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    if vm.static_mode {
        return 1;
    }
    let desc_ptr = desc_ptr as u32;
    let num_topics = num_topics as usize;
    if num_topics > 4 {
        return 1;
    }

    let mut topics = Vec::new();
    for t in 0..num_topics {
        let offset = desc_ptr.wrapping_add((t as u32) * 32);
        let mut buf = [0u8; 32];
        for j in 0..32u32 {
            match vm.memory.load8(offset.wrapping_add(j)) {
                Ok(b) => buf[j as usize] = b,
                Err(_) => return 1,
            }
        }
        topics.push(pyde_vm::wide::U256::from_le_bytes(buf));
    }

    let after_topics = desc_ptr.wrapping_add((num_topics as u32) * 32);
    let data_ptr = match vm.memory.load64(after_topics) {
        Ok(v) => v as u32,
        Err(_) => return 1,
    };
    let data_len = match vm.memory.load64(after_topics.wrapping_add(8)) {
        Ok(v) => v as usize,
        Err(_) => return 1,
    };
    let data = match vm.memory.checked_read_slice(data_ptr, data_len) {
        Ok(d) => d,
        Err(_) => return 1,
    };

    // Audit 228c: dynamic gas (matching interpreter's Opcode::Log
    // at `pvm/src/vm.rs:1063`). Folded into the AOT-drainable
    // accumulator so codegen picks it up via host_drain_page_gas.
    let dynamic_gas = 100u64
        .saturating_add((data_len as u64).saturating_mul(8))
        .saturating_add((num_topics as u64).saturating_mul(50));
    vm.memory.page_gas_used = vm.memory.page_gas_used.saturating_add(dynamic_gas);

    vm.logs.push(pyde_vm::vm::EventLog {
        address: vm.ctx.self_address,
        topics,
        data,
    });
    0
}

// ── Environment queries ────────────────────────────────────────────────

/// Host: get caller (msg.sender) into wide register wd.
pub extern "C" fn host_caller(ctx: *mut VmCtx, wd: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    if vm
        .cpu
        .write_wide_checked(wd as u8, pyde_vm::wide::U256::from_le_bytes(vm.ctx.caller))
        .is_err()
    {
        return 1;
    }
    0
}

/// Host: get self address into wide register wd.
pub extern "C" fn host_address(ctx: *mut VmCtx, wd: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    if vm
        .cpu
        .write_wide_checked(
            wd as u8,
            pyde_vm::wide::U256::from_le_bytes(vm.ctx.self_address),
        )
        .is_err()
    {
        return 1;
    }
    0
}

/// Host: get block number.
pub extern "C" fn host_block_number(ctx: *mut VmCtx) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    vm.ctx.block_number
}

/// Host: get timestamp.
pub extern "C" fn host_timestamp(ctx: *mut VmCtx) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    vm.ctx.timestamp
}

/// Host: get gas remaining.
pub extern "C" fn host_gas_remaining(ctx: *mut VmCtx) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    vm.gas_remaining()
}

/// Host: get call value (256-bit) into wide register.
pub extern "C" fn host_callvalue(ctx: *mut VmCtx, wd: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    if vm
        .cpu
        .write_wide_checked(wd as u8, vm.ctx.call_value)
        .is_err()
    {
        return 1;
    }
    0
}

/// Host: get gas price into wide register.
pub extern "C" fn host_gasprice(ctx: *mut VmCtx, wd: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    if vm
        .cpu
        .write_wide_checked(wd as u8, vm.ctx.gas_price)
        .is_err()
    {
        return 1;
    }
    0
}

/// Host: get balance of address (in wide register ws) into wide register wd.
pub extern "C" fn host_balance(ctx: *mut VmCtx, ws_addr: u64, wd: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    let addr_u256 = match vm.cpu.read_wide_checked(ws_addr as u8) {
        Ok(v) => v,
        Err(_) => return 1,
    };
    let addr: [u8; 32] = addr_u256.to_le_bytes();
    let bal = vm.ctx.balances.get(&addr).copied().unwrap_or(U256::ZERO);
    if vm.cpu.write_wide_checked(wd as u8, bal).is_err() {
        return 1;
    }
    0
}

/// Host: assert — returns 0 if val != 0, 1 (revert) if val == 0.
pub extern "C" fn host_assert(_ctx: *mut VmCtx, val: u64) -> u64 {
    if val == 0 {
        1
    } else {
        0
    }
}

/// Host: memcpy — bulk memory copy. Returns 0 on success, 1 on fault.
///
/// Per-byte dynamic gas (3 per 8 bytes, matching `pvm/src/vm.rs`
/// Opcode::Memcpy) is charged by the AOT codegen before this call,
/// and per-page allocation gas is drained via `host_drain_page_gas`
/// after — AOT tracks gas in a Cranelift SSA variable, not in
/// `vm.gas_used_total` (audit items 215 + 228a).
pub extern "C" fn host_memcpy(ctx: *mut VmCtx, dst: u64, src: u64, len: u64) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    if len == 0 {
        return 0;
    }
    // Gate any len that doesn't fit in PVM's u32 address space — the
    // `as u32` casts on src/dst/len below would silently truncate
    // otherwise. Same ceiling as the interpreter (audit item 215).
    if len > pyde_vm::memory::MEMORY_SIZE as u64 {
        return 1;
    }
    let len = len as usize;
    match vm.memory.checked_read_slice(src as u32, len) {
        Ok(data) => match vm.memory.checked_write_slice(dst as u32, &data) {
            Ok(()) => 0,
            Err(_) => 1,
        },
        Err(_) => 1,
    }
}

/// Host: drain accumulated page-allocation gas.
///
/// Returns `vm.memory.page_gas_used` and resets it to 0. The
/// interpreter folds this into `vm.gas_used_total` after every
/// `step()` at `pvm/src/vm.rs:1388`, charging `PAGE_ALLOC_GAS` (200)
/// per fresh page touched. The AOT tracks gas in a Cranelift SSA
/// variable (`VAR_GAS_USED`) that is **independent** of
/// `vm.gas_used_total`, so the drain has to be exposed as a host
/// call and folded into the AOT's counter by codegen after every
/// op that can bump `page_gas_used` via `check_access`
/// (Load/Store/Wload/Wstore/Push/Pop/Poseidon/Memcpy). Without this
/// drain, the same contract charges different gas on AOT vs
/// interpreter validators ⇒ consensus fork (audit item 228a).
pub extern "C" fn host_drain_page_gas(ctx: *mut VmCtx) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    let drained = vm.memory.page_gas_used;
    vm.memory.page_gas_used = 0;
    drained
}

// ============================================================================
// Cross-contract calls, Create, VerifySig, MerkleVerify
// These delegate to the PVM's existing methods via step().
// ============================================================================

/// Copy GP registers from the AOT's external regs[] array into vm.cpu.gp[].
/// Must be called before host_exec_opcode for opcodes that read GP state (CallExt, Create, etc.).
pub extern "C" fn host_sync_gp_to_vm(ctx: *mut VmCtx, regs_ptr: *const u64) {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    // SAFETY: `regs_ptr` is the JIT-emitted address of the caller's
    // 16-slot `u64` GP-mirror array; layout is fixed at codegen time
    // (`aot/src/codegen.rs`) so the 16-element length is invariant.
    let regs = unsafe { std::slice::from_raw_parts(regs_ptr, 16) };
    for (i, r) in regs.iter().enumerate() {
        vm.cpu.write_gp(i as u8, *r);
    }
}

/// Copy GP registers from vm.cpu.gp[] back into the AOT's external regs[] array.
/// Must be called after host_exec_opcode for opcodes that modify GP state.
pub extern "C" fn host_sync_gp_from_vm(ctx: *mut VmCtx, regs_ptr: *mut u64) {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    // SAFETY: `regs_ptr` is the JIT-emitted mutable address of the
    // caller's 16-slot `u64` GP-mirror array; layout is fixed at
    // codegen time (`aot/src/codegen.rs`) so the 16-element length
    // is invariant. Exclusive access is guaranteed by the caller
    // (the JIT serializes host_exec_opcode + sync pairs).
    let regs = unsafe { std::slice::from_raw_parts_mut(regs_ptr, 16) };
    for (i, r) in regs.iter_mut().enumerate() {
        *r = vm.cpu.read_gp(i as u8);
    }
}

/// Execute a delegated opcode via the interpreter, syncing gas
/// state in and out of the AOT.
///
/// Audit 228b — the AOT tracks gas in its own Cranelift SSA
/// variable (`VAR_GAS_USED`), which is **independent** of
/// `vm.gas_used_total`. Before this fix any gas charged by
/// `step()` for a delegated opcode (CallExt / Delegate / Create
/// / VerifySig / MerkleVerify) was lost the moment the host
/// call returned. Now the AOT passes its current counter values
/// in (`gas_used_in`, `gas_limit_in`), the interpreter runs
/// with those values, and the updated `vm.gas_used_total` is
/// packed into the high 62 bits of the return so codegen can
/// fold it back into `VAR_GAS_USED`.
///
/// Returns: `(gas_used_out << 2) | result` where result is:
///   0 = success, continue
///   1 = trap (includes OutOfGas)
///   2 = halt / revert
#[allow(clippy::too_many_arguments)]
pub extern "C" fn host_exec_opcode(
    ctx: *mut VmCtx,
    opcode: u64,
    rd: u64,
    rs1: u64,
    imm: u64,
    gas_used_in: u64,
    gas_limit_in: u64,
) -> u64 {
    // SAFETY: `ctx` is a valid `&mut Vm` per the module-level pointer
    // safety contract (top of file). The AOT JIT's callsite emission
    // in `aot/src/codegen.rs` loads a live VM pointer into the ABI's
    // first register before calling any host_* function.
    let vm = unsafe { &mut *ctx };
    // Sync gas state into the VM so step() can see the current
    // counter and trap OOG at the right point.
    vm.gas_used_total = gas_used_in;
    vm.gas_limit = gas_limit_in;
    let d = pyde_vm::isa::DecodedInstruction {
        opcode: pyde_vm::isa::Opcode::from_u8(opcode as u8),
        rd: rd as u8,
        rs1: rs1 as u8,
        rs2_or_imm: imm as u32,
    };
    let result: u64 = match vm.exec_single(d) {
        Ok(None) => 0,    // success, continue
        Ok(Some(_)) => 2, // halt/revert
        Err(_) => 1,      // trap
    };
    // Pack gas_used_out into high 62 bits so AOT codegen can fold
    // it back into VAR_GAS_USED. Gas values fit easily in 62 bits
    // (block gas limit is 1.6B = ~2^30.5).
    (vm.gas_used_total << 2) | result
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
        ("host_read_gp", host_read_gp as *const u8),
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
        ("host_memcpy", host_memcpy as *const u8),
        ("host_drain_page_gas", host_drain_page_gas as *const u8),
        ("host_checked_add", host_checked_add as *const u8),
        ("host_checked_sub", host_checked_sub as *const u8),
        ("host_checked_mul", host_checked_mul as *const u8),
        ("host_checked_div", host_checked_div as *const u8),
        ("host_checked_mod", host_checked_mod as *const u8),
        ("host_exec_opcode", host_exec_opcode as *const u8),
        ("host_sync_gp_to_vm", host_sync_gp_to_vm as *const u8),
        ("host_sync_gp_from_vm", host_sync_gp_from_vm as *const u8),
    ]
}
