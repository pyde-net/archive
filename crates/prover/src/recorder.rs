//! Execution trace recorder: captures full PVM state per cycle for STARK proving.
//!
//! The recorder wraps a PVM VM and captures a TraceRow after each step:
//! - Program counter, opcode, decoded fields
//! - All 16 GP registers
//! - All 8 wide registers (4 limbs each)
//! - Memory read/write address and value (if applicable)
//! - Storage key and value (if applicable)
//! - Gas step cost and cumulative gas
//! - Flags (is_memory_op, is_storage_op, is_final)
//!
//! Recording is opt-in: provers use `record_execution()`, normal nodes
//! use the standard `vm.execute()` without overhead.

use crate::trace::{to_field, ExecutionTrace, TraceRow, NUM_GP_REGS};
use p3_field::{AbstractField, Field};
use p3_goldilocks::Goldilocks;
use pyde_vm::isa::Opcode;
use pyde_vm::vm::{ExecResult, Outcome, Vm};
use pyde_vm::cpu::Trap;

/// Record a full execution trace from a loaded VM.
///
/// The VM must have bytecode loaded (via `vm.load()`).
/// Returns the ExecutionTrace and the execution outcome.
pub fn record_execution(vm: &mut Vm) -> (ExecutionTrace, Outcome) {
    let mut trace = ExecutionTrace::new();
    let logs_snapshot_len = vm.logs.len();
    let mut call_depth: u64 = 0;

    let outcome = loop {
        let pc = vm.pc;
        let idx = (pc / 4) as usize;

        let decoded = match vm.decoded_cache().get(idx) {
            Some(&d) => d,
            None => break Outcome::Trap(Trap::MemoryFault),
        };

        // Capture pre-step gas for computing step cost
        let gas_before = vm.gas_used_total;

        // Determine if this is a memory/storage op (from opcode)
        let is_mem = is_memory_opcode(decoded.opcode);
        let is_storage = is_storage_opcode(decoded.opcode);

        // Capture pre-step memory/storage access info from registers + opcode
        let mem_access = if is_mem {
            capture_memory_access(vm, decoded.opcode, decoded.rd, decoded.rs1, decoded.rs2_or_imm)
        } else {
            MemAccess::default()
        };

        let storage_access = if is_storage {
            capture_storage_access(vm, decoded.opcode, decoded.rd, decoded.rs1, decoded.rs2_or_imm)
        } else {
            StorageAccess::default()
        };

        // Execute one step
        let step_result = vm.step();

        // Compute gas cost for this step
        let gas_after = vm.gas_used_total;
        let gas_step = gas_after - gas_before;

        // Build trace row from post-step state
        let is_final = matches!(
            step_result,
            Ok(Some(ExecResult::Halt)) | Ok(Some(ExecResult::Revert)) | Err(_)
        );

        let mut row = build_trace_row(vm, pc, decoded.opcode, decoded.rd, decoded.rs1,
            decoded.rs2_or_imm, gas_step, gas_after, is_mem, is_storage, is_final,
            &mem_access, &storage_access);
        // Set call depth and update for next iteration
        row.call_depth = to_field(call_depth);
        if decoded.opcode == Opcode::Call || decoded.opcode == Opcode::CallExt
            || decoded.opcode == Opcode::Delegate {
            call_depth += 1;
        } else if decoded.opcode == Opcode::Ret && call_depth > 0 {
            call_depth -= 1;
        }

        trace.push(row);

        match step_result {
            Ok(Some(ExecResult::Halt)) => break Outcome::Success,
            Ok(Some(ExecResult::Revert)) => {
                vm.rollback_storage_pub();
                vm.logs.truncate(logs_snapshot_len);
                vm.gas_refund = 0;
                break Outcome::Revert;
            }
            Ok(None) => {} // continue
            Err(Trap::OutOfGas) => {
                vm.rollback_storage_pub();
                vm.logs.truncate(logs_snapshot_len);
                vm.gas_refund = 0;
                break Outcome::OutOfGas;
            }
            Err(trap) => {
                vm.rollback_storage_pub();
                vm.logs.truncate(logs_snapshot_len);
                vm.gas_refund = 0;
                break Outcome::Trap(trap);
            }
        }
    };

    (trace, outcome)
}

/// Captured memory access for a single step.
#[derive(Default)]
struct MemAccess {
    addr: u64,
    /// Value: 4 × u64 limbs.
    /// GP mode (≤8 bytes): val[0] = raw u64, rest = 0
    /// Bulk mode (>8 bytes): val[0..3] = Poseidon2(raw_bytes) hash limbs
    val: [u64; 4],
    /// Access width in bytes (1-8 for GP, or N for bulk writes like checked_write_slice).
    width: u64,
    /// Is this a write (true) or read (false)?
    is_write: bool,
}

/// Captured storage access for a single step.
#[derive(Default)]
struct StorageAccess {
    /// Key: 4 × u64 limbs (U256).
    key: [u64; 4],
    /// Value: 4 × u64 limbs. Interpretation derived from val_len:
    /// len ≤ 8:  val[0] = raw u64, rest = 0
    /// len ≤ 32: val[0..3] = raw U256 limbs
    /// len > 32: val[0..3] = Poseidon2(raw_bytes) hash limbs
    val: [u64; 4],
    /// Raw value length in bytes.
    val_len: u64,
    /// Is this a write?
    is_write: bool,
}

/// Capture memory access info before step executes.
/// Reads the address and value from registers based on the opcode.
fn capture_memory_access(vm: &Vm, op: Opcode, rd: u8, rs1: u8, rs2_imm: u32) -> MemAccess {
    let mut access = MemAccess::default();
    match op {
        Opcode::Load => {
            let base = vm.cpu.read_gp(rs1);
            let offset = pyde_vm::isa::decode_mem_offset(rs2_imm);
            let width = pyde_vm::isa::decode_mem_width(rs2_imm);
            access.addr = (base as i64 + offset as i64) as u64;
            access.width = match width {
                pyde_vm::isa::MemWidth::W8 => 1,
                pyde_vm::isa::MemWidth::W16 => 2,
                pyde_vm::isa::MemWidth::W32 => 4,
                pyde_vm::isa::MemWidth::W64 => 8,
            };
            access.is_write = false;
            // Value captured post-step from destination register
        }
        Opcode::Store => {
            let base = vm.cpu.read_gp(rs1);
            let offset = pyde_vm::isa::decode_mem_offset(rs2_imm);
            let width = pyde_vm::isa::decode_mem_width(rs2_imm);
            access.addr = (base as i64 + offset as i64) as u64;
            access.val[0] = vm.cpu.read_gp(rd);
            access.width = match width {
                pyde_vm::isa::MemWidth::W8 => 1,
                pyde_vm::isa::MemWidth::W16 => 2,
                pyde_vm::isa::MemWidth::W32 => 4,
                pyde_vm::isa::MemWidth::W64 => 8,
            };
            access.is_write = true;
        }
        Opcode::Push => {
            access.val[0] = vm.cpu.read_gp(rd);
            access.width = 8;
            access.is_write = true;
        }
        Opcode::Pop => {
            access.width = 8;
            access.is_write = false;
        }
        Opcode::Wstore => {
            // WSTORE: writes U256 (32 bytes) from wide register to memory
            let base = vm.cpu.read_gp(rs1);
            let offset = pyde_vm::isa::sign_extend_18(rs2_imm) as i64;
            access.addr = (base as i64 + offset) as u64;
            let val = vm.cpu.read_wide(rd);
            let limbs = val.to_le_bytes();
            for i in 0..4 {
                access.val[i] = u64::from_le_bytes(
                    limbs[i * 8..(i + 1) * 8].try_into().unwrap(),
                );
            }
            access.width = 32;
            access.is_write = true;
        }
        Opcode::Wload => {
            // WLOAD: reads U256 (32 bytes) from memory to wide register
            let base = vm.cpu.read_gp(rs1);
            let offset = pyde_vm::isa::sign_extend_18(rs2_imm) as i64;
            access.addr = (base as i64 + offset) as u64;
            access.width = 32;
            access.is_write = false;
            // Value captured post-step from wide register
        }
        _ => {}
    }
    access
}

/// Compute Poseidon2 hash of raw bytes and return as 4 × u64 limbs.
fn hash_value(data: &[u8]) -> [u64; 4] {
    let hash = pyde_crypto::poseidon2::poseidon2_hash(data).to_bytes();
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        limbs[i] = u64::from_le_bytes(hash[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    limbs
}

/// Capture storage access info before step executes.
fn capture_storage_access(vm: &Vm, op: Opcode, rd: u8, rs1: u8, rs2_or_imm: u32) -> StorageAccess {
    let mut access = StorageAccess::default();
    let slot = vm.cpu.read_wide(rs1);
    let key = vm.derive_storage_key(slot);
    let key_bytes = key.to_le_bytes();

    // Key: full U256 (4 × u64 limbs)
    for i in 0..4 {
        access.key[i] = u64::from_le_bytes(key_bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }

    if op == Opcode::Sload {
        access.is_write = false;
        if let Some(data) = vm.storage.get(&key) {
            fill_storage_val(&mut access, data);
        }
    } else if op == Opcode::Sstore {
        access.is_write = true;
        let mode = rs2_or_imm & 0x3;
        match mode {
            0 => {
                // Wide register mode: value = U256 from wide register rd
                let val = vm.cpu.read_wide(rd);
                let bytes = val.to_le_bytes();
                access.val_len = 32;
                for i in 0..4 {
                    access.val[i] = u64::from_le_bytes(
                        bytes[i * 8..(i + 1) * 8].try_into().unwrap(),
                    );
                }
            }
            2 => {
                // GP register mode: value = u64 from GP register rd
                access.val[0] = vm.cpu.read_gp(rd);
                access.val_len = 8;
            }
            1 => {
                // Memory mode: value = bytes from memory[ptr..ptr+len]
                let ptr_reg = ((rs2_or_imm >> 2) & 0xF) as u8;
                let len_reg = ((rs2_or_imm >> 6) & 0xF) as u8;
                let ptr = vm.cpu.read_gp(ptr_reg) as u32;
                let len = vm.cpu.read_gp(len_reg) as usize;
                let data = vm.memory.read_slice(ptr, len);
                fill_storage_val(&mut access, &data);
            }
            _ => {}
        }
    } else if op == Opcode::Sdelete {
        // Delete: capture the key, value is the current value being deleted
        access.is_write = true;
        if let Some(data) = vm.storage.get(&key) {
            fill_storage_val(&mut access, data);
        }
    }
    access
}

/// Fill storage_val and storage_val_len from raw bytes.
fn fill_storage_val(access: &mut StorageAccess, data: &[u8]) {
    access.val_len = data.len() as u64;
    if data.len() <= 8 {
        let mut buf = [0u8; 8];
        buf[..data.len()].copy_from_slice(data);
        access.val[0] = u64::from_le_bytes(buf);
    } else if data.len() <= 32 {
        for i in 0..4 {
            if data.len() >= (i + 1) * 8 {
                access.val[i] = u64::from_le_bytes(
                    data[i * 8..(i + 1) * 8].try_into().unwrap(),
                );
            }
        }
    } else {
        access.val = hash_value(data);
    }
}

/// Build a TraceRow from the current VM state.
fn build_trace_row(
    vm: &Vm,
    pc: u32,
    opcode: Opcode,
    rd: u8,
    rs1: u8,
    rs2_imm: u32,
    gas_step: u64,
    gas_cumulative: u64,
    is_mem: bool,
    is_storage: bool,
    is_final: bool,
    mem_access: &MemAccess,
    storage_access: &StorageAccess,
) -> TraceRow {
    let mut row = TraceRow::zero();

    // Control flow
    row.pc = to_field(pc as u64);
    row.opcode = to_field(opcode.to_u8() as u64);
    row.rd = to_field(rd as u64);
    row.rs1 = to_field(rs1 as u64);
    row.rs2_imm = to_field(rs2_imm as u64);

    // GP registers (post-step state)
    for i in 0..NUM_GP_REGS {
        row.gp_regs[i] = to_field(vm.cpu.read_gp(i as u8));
    }

    // Wide registers (4 u64 limbs each, post-step state)
    for w in 0..8 {
        let val = vm.cpu.read_wide(w as u8);
        let limbs = val.to_le_bytes();
        for l in 0..4 {
            let limb = u64::from_le_bytes(
                limbs[l * 8..(l + 1) * 8].try_into().unwrap(),
            );
            row.wide_limbs[w * 4 + l] = to_field(limb);
        }
    }

    // Memory access
    row.mem_addr = to_field(mem_access.addr);
    for i in 0..4 {
        row.mem_val[i] = to_field(mem_access.val[i]);
    }
    row.mem_width = to_field(mem_access.width);
    row.mem_is_write = if mem_access.is_write { Goldilocks::one() } else { Goldilocks::zero() };

    // For reads: capture the value post-step from destination register
    if is_mem && !mem_access.is_write {
        if mem_access.width <= 8 {
            // GP LOAD: value in GP register
            row.mem_val[0] = to_field(vm.cpu.read_gp(rd));
        } else if mem_access.width <= 32 {
            // WLOAD: value in wide register (4 limbs)
            let val = vm.cpu.read_wide(rd);
            let limbs = val.to_le_bytes();
            for i in 0..4 {
                row.mem_val[i] = to_field(u64::from_le_bytes(
                    limbs[i * 8..(i + 1) * 8].try_into().unwrap(),
                ));
            }
        } else {
            // Bulk read (>32 bytes): hash the memory region, raw in aux witness
            let addr = mem_access.addr as u32;
            let len = mem_access.width as usize;
            let data = vm.memory.read_slice(addr, len);
            let h = hash_value(&data);
            for i in 0..4 {
                row.mem_val[i] = to_field(h[i]);
            }
        }
    }

    // Storage access
    for i in 0..4 {
        row.storage_key[i] = to_field(storage_access.key[i]);
        row.storage_val[i] = to_field(storage_access.val[i]);
    }
    row.storage_val_len = to_field(storage_access.val_len);
    row.storage_is_write = if storage_access.is_write { Goldilocks::one() } else { Goldilocks::zero() };

    // Gas
    row.gas_step = to_field(gas_step);
    row.gas_cumulative = to_field(gas_cumulative);

    // Flags
    row.is_memory_op = if is_mem { Goldilocks::one() } else { Goldilocks::zero() };
    row.is_storage_op = if is_storage { Goldilocks::one() } else { Goldilocks::zero() };
    row.is_final = if is_final { Goldilocks::one() } else { Goldilocks::zero() };

    // Opcode bits: binary decomposition of 6-bit opcode
    let op_val = opcode.to_u8() as u64;
    for bit in 0..6 {
        row.opcode_bits[bit] = if (op_val >> bit) & 1 == 1 {
            Goldilocks::one()
        } else {
            Goldilocks::zero()
        };
    }

    // Operand columns: resolved from registers post-step
    // op_a = gp[rs1] (first source operand)
    // op_b = gp[rs2] or immediate (second operand)
    // op_result = gp[rd] post-step (result written)
    row.op_a = to_field(vm.cpu.read_gp(rs1));
    // For register-register ops, rs2 is in rs2_imm lower 4 bits.
    // For immediate ops (ADDI), rs2_imm is the immediate value.
    let is_immediate = matches!(opcode,
        Opcode::Addi | Opcode::Jmp | Opcode::Beq | Opcode::Bne
        | Opcode::Blt | Opcode::Bge | Opcode::Call
    );
    if is_immediate {
        row.op_b = to_field(pyde_vm::isa::sign_extend_18(rs2_imm) as u64);
    } else {
        let rs2_reg = (rs2_imm & 0xF) as u8;
        row.op_b = to_field(vm.cpu.read_gp(rs2_reg));
    }
    row.op_result = to_field(vm.cpu.read_gp(rd));

    // SHR remainder: op_a = result * 2^shift + remainder
    if opcode == Opcode::Shr || opcode == Opcode::Sar {
        let a = vm.cpu.read_gp(rs1);
        let b_reg = (rs2_imm & 0xF) as u8;
        let shift = vm.cpu.read_gp(b_reg) & 63; // shift amount mod 64
        if shift > 0 {
            let mask = (1u64 << shift) - 1;
            row.shift_remainder = to_field(a & mask);
        }
    }

    // Wide operands (for WADD, WSUB, WMUL, etc.)
    // rs1 field selects the wide source register for wide ops
    let is_wide_op = matches!(opcode,
        Opcode::Wadd | Opcode::Wsub | Opcode::Wmul | Opcode::Wdiv | Opcode::Wmod
        | Opcode::Wand | Opcode::Wor | Opcode::Wxor | Opcode::Wnot
    );
    if is_wide_op {
        // wide_op_a from ws1 (rs1 field), wide_op_b from ws2 (rs2 field)
        let wa = vm.cpu.read_wide(rs1);
        let wa_bytes = wa.to_le_bytes();
        for i in 0..4 {
            row.wide_op_a[i] = to_field(u64::from_le_bytes(
                wa_bytes[i * 8..(i + 1) * 8].try_into().unwrap(),
            ));
        }

        if opcode != Opcode::Wnot {
            let ws2 = (rs2_imm & 0xF) as u8;
            let wb = vm.cpu.read_wide(ws2);
            let wb_bytes = wb.to_le_bytes();
            for i in 0..4 {
                row.wide_op_b[i] = to_field(u64::from_le_bytes(
                    wb_bytes[i * 8..(i + 1) * 8].try_into().unwrap(),
                ));
            }
        }

        // Result from destination wide register (post-step)
        let wr = vm.cpu.read_wide(rd);
        let wr_bytes = wr.to_le_bytes();
        for i in 0..4 {
            row.wide_result[i] = to_field(u64::from_le_bytes(
                wr_bytes[i * 8..(i + 1) * 8].try_into().unwrap(),
            ));
        }

        // Carry computation for WADD/WSUB
        if opcode == Opcode::Wadd {
            let mut carry = 0u128;
            for i in 0..4 {
                let a_limb = u64::from_le_bytes(wa_bytes[i * 8..(i + 1) * 8].try_into().unwrap()) as u128;
                let wb = vm.cpu.read_wide((rs2_imm & 0xF) as u8);
                let wb_bytes = wb.to_le_bytes();
                let b_limb = u64::from_le_bytes(wb_bytes[i * 8..(i + 1) * 8].try_into().unwrap()) as u128;
                let sum = a_limb + b_limb + carry;
                carry = sum >> 64;
                row.wide_carry[i] = to_field(carry as u64);
            }
        }

        // Wide quotient for WMOD: a = quotient * b + result
        // After step, wide_result = remainder. Quotient = a / b (integer).
        // We compute quotient per-limb from the pre-step operands.
        if opcode == Opcode::Wmod || opcode == Opcode::Wdiv {
            // For simple cases where b fits in limb 0 and higher limbs are 0,
            // quotient[0] = a[0] / b[0]. For full U256 division, the VM
            // already computed the result. We store the quotient from the
            // relationship: quotient = (a - result) / b, using limb 0.
            let ws2 = (rs2_imm & 0xF) as u8;
            let b0 = {
                let wb = vm.cpu.read_wide(ws2);
                let wb_bytes = wb.to_le_bytes();
                u64::from_le_bytes(wb_bytes[0..8].try_into().unwrap())
            };
            if b0 != 0 {
                let a0 = {
                    let bytes = wa_bytes;
                    u64::from_le_bytes(bytes[0..8].try_into().unwrap())
                };
                row.wide_quotient[0] = to_field(a0 / b0);
            }
        }
    }

    // Quotient for MOD: op_a = quotient * op_b + result
    if opcode == Opcode::Mod {
        let a = vm.cpu.read_gp(rs1);
        let b_reg = (rs2_imm & 0xF) as u8;
        let b = vm.cpu.read_gp(b_reg);
        if b != 0 {
            row.op_quotient = to_field(a / b);
        }
    }
    // Quotient also useful for DIV verification
    if opcode == Opcode::Div {
        let a = vm.cpu.read_gp(rs1);
        let b_reg = (rs2_imm & 0xF) as u8;
        let b = vm.cpu.read_gp(b_reg);
        if b != 0 {
            row.op_quotient = to_field(a % b); // remainder for DIV cross-check
        }
    }

    // Branch taken + diff_inv for BEQ/BNE constraints
    let is_branch_op = matches!(opcode,
        Opcode::Beq | Opcode::Bne | Opcode::Blt | Opcode::Bge
    );
    if is_branch_op {
        let a_val = vm.cpu.read_gp(rd); // BEQ uses rd and rs1 for comparison
        let b_val = vm.cpu.read_gp(rs1);
        let taken = match opcode {
            Opcode::Beq => a_val == b_val,
            Opcode::Bne => a_val != b_val,
            Opcode::Blt => (a_val as i64) < (b_val as i64),
            Opcode::Bge => (a_val as i64) >= (b_val as i64),
            _ => false,
        };
        row.branch_taken = if taken { Goldilocks::one() } else { Goldilocks::zero() };

        // diff_inv = 1/(a - b) when a != b, 0 when equal
        // Goldilocks field: p = 2^64 - 2^32 + 1
        // Inverse via Fermat: inv = diff^(p-2) mod p
        if a_val != b_val {
            let diff = Goldilocks::from_canonical_u64(a_val.wrapping_sub(b_val));
            // Use p3_field's inverse
            let inv = diff.try_inverse();
            if let Some(inv_val) = inv {
                row.diff_inv = inv_val;
            }
        }
    }

    // Call depth tracking: we maintain a static counter in the trace.
    // The AIR constrains: CALL → depth+1, RET → depth-1, else stable.
    // The recorder reads from the previous row's value + opcode delta.
    // Since we're building rows sequentially, we compute it here.
    // Note: the actual call_depth is set AFTER the step, so we read
    // the VM's state. The ext_call_depth field tracks this.
    // For external calls, the VM increments ext_call_depth internally.

    // Wide bit decomposition for WAND/WOR/WXOR
    let is_wide_bitwise = matches!(opcode, Opcode::Wand | Opcode::Wor | Opcode::Wxor);
    if is_wide_bitwise {
        let wa = vm.cpu.read_wide(rs1);
        let wa_bytes = wa.to_le_bytes();
        let ws2 = (rs2_imm & 0xF) as u8;
        let wb = vm.cpu.read_wide(ws2);
        let wb_bytes = wb.to_le_bytes();

        // Decompose all 256 bits of each operand
        for byte_idx in 0..32 {
            for bit in 0..8 {
                let bit_idx = byte_idx * 8 + bit;
                row.wide_a_bits[bit_idx] = if (wa_bytes[byte_idx] >> bit) & 1 == 1 {
                    Goldilocks::one()
                } else {
                    Goldilocks::zero()
                };
                row.wide_b_bits[bit_idx] = if (wb_bytes[byte_idx] >> bit) & 1 == 1 {
                    Goldilocks::one()
                } else {
                    Goldilocks::zero()
                };
            }
        }
    }

    // Bit decomposition of operands (for bitwise/shift constraints)
    let a_raw = vm.cpu.read_gp(rs1);
    let b_raw = if is_immediate {
        pyde_vm::isa::sign_extend_18(rs2_imm) as u64
    } else {
        vm.cpu.read_gp((rs2_imm & 0xF) as u8)
    };
    for bit in 0..64 {
        row.op_a_bits[bit] = if (a_raw >> bit) & 1 == 1 {
            Goldilocks::one()
        } else {
            Goldilocks::zero()
        };
        row.op_b_bits[bit] = if (b_raw >> bit) & 1 == 1 {
            Goldilocks::one()
        } else {
            Goldilocks::zero()
        };
    }

    // Register selectors: one-hot encoding of rd, rs1, rs2
    if (rd as usize) < 16 {
        row.rd_sel[rd as usize] = Goldilocks::one();
    }
    if (rs1 as usize) < 16 {
        row.rs1_sel[rs1 as usize] = Goldilocks::one();
    }
    if !is_immediate {
        let rs2_reg = (rs2_imm & 0xF) as usize;
        if rs2_reg < 16 {
            row.rs2_sel[rs2_reg] = Goldilocks::one();
        }
    }

    row
}

/// Check if an opcode is a memory operation.
fn is_memory_opcode(op: Opcode) -> bool {
    matches!(op, Opcode::Load | Opcode::Store | Opcode::Push | Opcode::Pop
        | Opcode::Wload | Opcode::Wstore)
}

/// Check if an opcode is a storage operation.
fn is_storage_opcode(op: Opcode) -> bool {
    matches!(op, Opcode::Sload | Opcode::Sstore | Opcode::Sdelete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_vm::isa::{encode, Opcode};
    use pyde_vm::vm::Vm;

    /// Helper: encode an instruction to 4 bytes.
    fn instr(op: Opcode, rd: u8, rs1: u8, rs2_or_imm: u32) -> [u8; 4] {
        encode(op, rd, rs1, rs2_or_imm).0.to_le_bytes()
    }

    fn build_bytecode(instrs: &[&[u8; 4]]) -> Vec<u8> {
        instrs.iter().flat_map(|i| i.iter().copied()).collect()
    }

    // ========== Task 0601: Trace captures ADD ==========

    #[test]
    fn trace_captures_add() {
        let code = build_bytecode(&[
            &instr(Opcode::Addi, 1, 0, 42),  // r1 = 42
            &instr(Opcode::Addi, 2, 0, 58),  // r2 = 58
            &instr(Opcode::Add, 3, 1, 2),     // r3 = r1 + r2 = 100
            &instr(Opcode::Halt, 0, 0, 0),
        ]);

        let mut vm = Vm::new();
        vm.load(&code).unwrap();

        let (trace, outcome) = record_execution(&mut vm);
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(trace.len(), 4); // 3 instructions + halt

        // After ADD (row 2, 0-indexed), r3 should be 100
        let add_row = &trace.rows[2];
        assert_eq!(add_row.gp_regs[3], to_field(100));

        // Final row is marked
        assert_eq!(trace.rows[3].is_final, Goldilocks::one());
        assert_eq!(trace.rows[0].is_final, Goldilocks::zero());
    }

    // ========== Task 0598: PC and opcode recorded ==========

    #[test]
    fn trace_captures_pc_and_opcode() {
        let code = build_bytecode(&[
            &instr(Opcode::Addi, 1, 0, 10),
            &instr(Opcode::Addi, 2, 0, 20),
            &instr(Opcode::Halt, 0, 0, 0),
        ]);

        let mut vm = Vm::new();
        vm.load(&code).unwrap();

        let (trace, _) = record_execution(&mut vm);
        assert_eq!(trace.len(), 3);

        // PC advances by 4 each step
        assert_eq!(trace.rows[0].pc, to_field(0));
        assert_eq!(trace.rows[1].pc, to_field(4));
        assert_eq!(trace.rows[2].pc, to_field(8));

        // Opcodes recorded
        assert_eq!(trace.rows[0].opcode, to_field(Opcode::Addi.to_u8() as u64));
        assert_eq!(trace.rows[2].opcode, to_field(Opcode::Halt.to_u8() as u64));
    }

    // ========== Task 0595: Register state per cycle ==========

    #[test]
    fn trace_captures_registers_per_cycle() {
        let code = build_bytecode(&[
            &instr(Opcode::Addi, 1, 0, 10), // r1 = 10
            &instr(Opcode::Addi, 1, 1, 5),  // r1 = r1 + 5 = 15
            &instr(Opcode::Halt, 0, 0, 0),
        ]);

        let mut vm = Vm::new();
        vm.load(&code).unwrap();

        let (trace, _) = record_execution(&mut vm);

        // After step 0: r1 = 10
        assert_eq!(trace.rows[0].gp_regs[1], to_field(10));
        // After step 1: r1 = 15
        assert_eq!(trace.rows[1].gp_regs[1], to_field(15));
    }

    // ========== Task 0599: Gas counter per cycle ==========

    #[test]
    fn trace_captures_gas() {
        let code = build_bytecode(&[
            &instr(Opcode::Addi, 1, 0, 10),
            &instr(Opcode::Add, 2, 1, 0),
            &instr(Opcode::Halt, 0, 0, 0),
        ]);

        let mut vm = Vm::with_gas_limit(100_000);
        vm.load(&code).unwrap();

        let (trace, _) = record_execution(&mut vm);

        // Gas should be monotonically increasing
        let gas_0 = trace.rows[0].gas_cumulative;
        let gas_1 = trace.rows[1].gas_cumulative;
        let gas_2 = trace.rows[2].gas_cumulative;
        assert!(gas_0 < gas_1 || gas_0 == gas_1); // non-decreasing
        assert!(gas_1 < gas_2 || gas_1 == gas_2);

        // Step gas should be non-zero
        assert_ne!(trace.rows[0].gas_step, Goldilocks::zero());
    }

    // ========== Flags ==========

    #[test]
    fn trace_flags_correct() {
        let code = build_bytecode(&[
            &instr(Opcode::Addi, 1, 0, 10), // not memory, not storage
            &instr(Opcode::Halt, 0, 0, 0),  // final
        ]);

        let mut vm = Vm::new();
        vm.load(&code).unwrap();

        let (trace, _) = record_execution(&mut vm);

        // First row: not final, not memory, not storage
        assert_eq!(trace.rows[0].is_final, Goldilocks::zero());
        assert_eq!(trace.rows[0].is_memory_op, Goldilocks::zero());
        assert_eq!(trace.rows[0].is_storage_op, Goldilocks::zero());

        // Last row: final
        assert_eq!(trace.rows[1].is_final, Goldilocks::one());
    }

    // ========== Trace padded for STARK ==========

    #[test]
    fn trace_pads_to_power_of_two() {
        let code = build_bytecode(&[
            &instr(Opcode::Addi, 1, 0, 1),
            &instr(Opcode::Addi, 2, 0, 2),
            &instr(Opcode::Addi, 3, 0, 3),
            &instr(Opcode::Halt, 0, 0, 0),
        ]);

        let mut vm = Vm::new();
        vm.load(&code).unwrap();

        let (mut trace, _) = record_execution(&mut vm);
        assert_eq!(trace.len(), 4); // already power of 2

        // Add one more for non-power-of-2
        trace.push(TraceRow::zero());
        assert_eq!(trace.len(), 5);
        trace.pad_to_power_of_two();
        assert_eq!(trace.len(), 8);
    }

    // ========== Task 0596: Memory reads/writes recorded ==========

    #[test]
    fn trace_captures_memory_store() {
        use pyde_vm::isa::{encode_mem_immediate, MemWidth};
        let code = build_bytecode(&[
            &instr(Opcode::Addi, 1, 0, 0x010000),                        // r1 = HEAP_START (address)
            &instr(Opcode::Addi, 2, 0, 42),                             // r2 = 42 (value)
            &instr(Opcode::Store, 2, 1, encode_mem_immediate(0, MemWidth::W64)), // store64(r1+0, r2)
            &instr(Opcode::Halt, 0, 0, 0),
        ]);

        let mut vm = Vm::new();
        vm.load(&code).unwrap();

        let (trace, outcome) = record_execution(&mut vm);
        assert_eq!(outcome, Outcome::Success);

        // Store instruction (row 2) should have memory flag
        assert_eq!(trace.rows[2].is_memory_op, Goldilocks::one());
        assert_eq!(trace.rows[2].mem_is_write, Goldilocks::one());
        // Write address should be HEAP_START
        assert_eq!(trace.rows[2].mem_addr, to_field(0x010000));
        // Write value should be 42 (GP mode: raw value in limb 0)
        assert_eq!(trace.rows[2].mem_val[0], to_field(42));
        // Width should be 8 (W64)
        assert_eq!(trace.rows[2].mem_width, to_field(8));
    }

    // ========== Task 0597: Storage flag recorded ==========

    #[test]
    fn trace_marks_storage_ops() {
        // SSTORE requires wide register setup which is complex to encode.
        // Verify the flag detection works for the opcode classification.
        assert!(is_storage_opcode(Opcode::Sload));
        assert!(is_storage_opcode(Opcode::Sstore));
        assert!(is_storage_opcode(Opcode::Sdelete));
        assert!(!is_storage_opcode(Opcode::Add));
        assert!(!is_storage_opcode(Opcode::Load));
    }

    #[test]
    fn trace_marks_memory_ops() {
        assert!(is_memory_opcode(Opcode::Load));
        assert!(is_memory_opcode(Opcode::Store));
        assert!(is_memory_opcode(Opcode::Push));
        assert!(is_memory_opcode(Opcode::Pop));
        assert!(!is_memory_opcode(Opcode::Add));
        assert!(!is_memory_opcode(Opcode::Sstore));
    }
}
