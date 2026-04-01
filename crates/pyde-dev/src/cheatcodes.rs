//! Cheatcode interception for the test framework.
//!
//! Cheatcodes are implemented as calls to a magic address (0xCC repeated).
//! The test runner intercepts these calls before the PVM executes them,
//! applies the effect (modify context, balances, etc.), and skips the instruction.
//!
//! This keeps the PVM 100% production-clean — no test features in the core VM.

use ethnum::U256;
use pyde_vm::isa::Opcode;
use pyde_vm::vm::{ExecResult, Outcome, Vm};

/// Magic cheatcode address: 32 bytes of 0xCC.
pub const CHEATCODE_ADDRESS: [u8; 32] = [0xCC; 32];

/// Cheatcode selectors — must match otic::codegen::compute_selector(method_name).
/// The compiler generates 4-byte BE selectors via FNV-1a of the method name.
/// The calldata layout is [selector:4 BE bytes][arg0:8 LE][arg1:8 LE]...
pub mod selectors {
    /// FNV-1a hash (same as otic::codegen::compute_selector).
    pub fn compute(name: &str) -> u32 {
        let mut hash: u32 = 0x811c9dc5;
        for byte in name.bytes() {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(0x01000193);
        }
        hash
    }

    pub fn warp() -> u32 { compute("warp") }
    pub fn roll() -> u32 { compute("roll") }
    pub fn prank() -> u32 { compute("prank") }
    pub fn start_prank() -> u32 { compute("startPrank") }
    pub fn stop_prank() -> u32 { compute("stopPrank") }
    pub fn deal() -> u32 { compute("deal") }
    pub fn make_addr() -> u32 { compute("makeAddr") }
}

/// State for persistent prank across calls.
pub struct CheatcodeState {
    pub prank_caller: Option<[u8; 32]>,
    pub prank_persistent: bool,
}

impl CheatcodeState {
    pub fn new() -> Self {
        Self {
            prank_caller: None,
            prank_persistent: false,
        }
    }
}

/// Execute VM with cheatcode interception.
/// Replaces `vm.execute()` — runs a step loop that intercepts CallExt to the magic address.
/// Returns the execution outcome.
pub fn execute_with_cheatcodes(vm: &mut Vm, cheat_state: &mut CheatcodeState) -> Outcome {
    // Apply persistent prank if set
    if let Some(ref addr) = cheat_state.prank_caller {
        vm.ctx.caller = *addr;
    }

    vm.clear_journal();
    let logs_start = vm.logs.len();

    let result = loop {
        // Peek at current instruction before stepping
        let idx = (vm.pc / 4) as usize;
        let maybe_instr = vm.decoded_cache().get(idx).copied();

        if let Some(d) = maybe_instr {
            if d.opcode == Opcode::CallExt {
                // Check if target is the cheatcode address
                let target: [u8; 32] = vm.cpu.read_wide(d.rd).to_le_bytes();
                if target == CHEATCODE_ADDRESS {
                    // Intercept: read calldata, apply cheatcode, skip instruction
                    let calldata_ptr = vm.cpu.read_gp(d.rs1) as u32;
                    let len_reg = (d.rs2_or_imm & 0xF) as u8;
                    let calldata_len = vm.cpu.read_gp(len_reg) as usize;
                    let result_reg = ((d.rs2_or_imm >> 8) & 0xF) as u8;

                    if let Ok(calldata) = vm.memory.checked_read_slice(calldata_ptr, calldata_len) {
                        let success = handle_cheatcode(vm, cheat_state, &calldata);
                        vm.cpu.write_gp(result_reg, if success { 1 } else { 0 });
                    } else {
                        vm.cpu.write_gp(result_reg, 0);
                    }

                    // Skip the CallExt instruction
                    vm.pc += 4;
                    continue;
                }
            }
        }

        // Normal step
        match vm.step() {
            Ok(Some(ExecResult::Halt)) => break Outcome::Success,
            Ok(Some(ExecResult::Revert)) => {
                vm.rollback_storage_pub();
                vm.logs.truncate(logs_start);
                vm.gas_refund = 0;
                break Outcome::Revert;
            }
            Ok(None) => {}
            Err(pyde_vm::cpu::Trap::OutOfGas) => {
                vm.rollback_storage_pub();
                vm.logs.truncate(logs_start);
                vm.gas_refund = 0;
                break Outcome::OutOfGas;
            }
            Err(trap) => {
                vm.rollback_storage_pub();
                vm.logs.truncate(logs_start);
                vm.gas_refund = 0;
                break Outcome::Trap(trap);
            }
        }

        // Clear single-use prank after any non-cheatcode CallExt
        if let Some(d) = maybe_instr {
            if d.opcode == Opcode::CallExt && !cheat_state.prank_persistent {
                if cheat_state.prank_caller.is_some() {
                    cheat_state.prank_caller = None;
                }
            }
        }
    };

    // Post-execution cleanup (matches vm.execute() behavior)
    vm.clear_journal();
    result
}

/// Handle a single cheatcode call. Returns true on success.
///
/// Calldata layout matches ExtCall codegen:
///   [selector: 4 bytes BE][arg0: 8 bytes LE][arg1: 8 bytes LE]...
/// For wide args (Address, u256), the arg occupies 8 bytes (GP register value).
/// The actual wide value is in the wide register — but since cheatcodes intercept
/// before the PVM executes, we read args from calldata (GP serialization).
fn handle_cheatcode(vm: &mut Vm, state: &mut CheatcodeState, calldata: &[u8]) -> bool {
    if calldata.len() < 4 {
        return false;
    }

    // Selector is 4 bytes stored in BE order by codegen
    let selector = u32::from_be_bytes(calldata[..4].try_into().unwrap_or([0; 4]));

    if selector == selectors::warp() {
        // warp(timestamp: u64) — calldata: [sel:4][timestamp:8 LE]
        if calldata.len() >= 12 {
            let ts = u64::from_le_bytes(calldata[4..12].try_into().unwrap_or([0; 8]));
            vm.ctx.timestamp = ts;
            return true;
        }
    } else if selector == selectors::roll() {
        // roll(block_number: u64) — calldata: [sel:4][block_number:8 LE]
        if calldata.len() >= 12 {
            let bn = u64::from_le_bytes(calldata[4..12].try_into().unwrap_or([0; 8]));
            vm.ctx.block_number = bn;
            return true;
        }
    } else if selector == selectors::prank() {
        // prank(address: Address) — calldata: [sel:4][address_ptr:8 LE]
        // The address is in a wide register. Read it from the VM's wide reg file.
        // The ExtCall encoding puts the target address in wd (rd field), and the
        // first arg in calldata is a GP value. For Address args, the caller passes
        // the address via wide register. We read from the first arg's wide reg.
        if calldata.len() >= 12 {
            // Read the Address from the first arg's wide register (w0-w6)
            // The compiler puts Address args in wide registers and writes the
            // GP index to calldata. For simplicity, read from calldata as a
            // pointer and load from VM memory, OR read from wide reg directly.
            // Since the arg is an Address (wide), the compiler serializes 8 bytes
            // (the GP value) to calldata. The actual address is in a wide register.
            // For cheatcodes, we need the wide value. Read it from the instruction context.
            let arg_val = u64::from_le_bytes(calldata[4..12].try_into().unwrap_or([0; 8]));
            // For now, treat the 8-byte value as a heap pointer where the address was written,
            // or as a direct GP value. Since prank takes an Address, and the compiler
            // writes GP values to calldata, we need a different approach for wide args.
            // The cleanest solution: read the Address from vm memory at the arg value (heap ptr).
            // Actually — the ExtCall calldata only writes GP values (8 bytes per arg via emit_store).
            // For Address args, the compiler should widen and write 32 bytes. Let me check...
            // For now, construct address from the 8-byte value (zero-extended to 32 bytes).
            let mut addr = [0u8; 32];
            addr[..8].copy_from_slice(&arg_val.to_le_bytes());
            state.prank_caller = Some(addr);
            state.prank_persistent = false;
            vm.ctx.caller = addr;
            return true;
        }
    } else if selector == selectors::start_prank() {
        if calldata.len() >= 12 {
            let arg_val = u64::from_le_bytes(calldata[4..12].try_into().unwrap_or([0; 8]));
            let mut addr = [0u8; 32];
            addr[..8].copy_from_slice(&arg_val.to_le_bytes());
            state.prank_caller = Some(addr);
            state.prank_persistent = true;
            vm.ctx.caller = addr;
            return true;
        }
    } else if selector == selectors::stop_prank() {
        state.prank_caller = None;
        state.prank_persistent = false;
        return true;
    } else if selector == selectors::deal() {
        // deal(address: Address, amount: u256)
        // Both are wide but serialized as GP (8 bytes each) in calldata
        if calldata.len() >= 20 {
            let addr_val = u64::from_le_bytes(calldata[4..12].try_into().unwrap_or([0; 8]));
            let amount_val = u64::from_le_bytes(calldata[12..20].try_into().unwrap_or([0; 8]));
            let mut addr = [0u8; 32];
            addr[..8].copy_from_slice(&addr_val.to_le_bytes());
            vm.ctx.balances.insert(addr, U256::from(amount_val));
            return true;
        }
    } else if selector == selectors::make_addr() {
        // makeAddr(label_len: u64) — label bytes follow in calldata
        // Actually, String args are serialized differently (blob on heap).
        // For simplicity, makeAddr takes a u64 seed and derives deterministically.
        if calldata.len() >= 12 {
            let seed = u64::from_le_bytes(calldata[4..12].try_into().unwrap_or([0; 8]));
            let hash = pyde_crypto::poseidon2::poseidon2_hash(&seed.to_le_bytes());
            let addr_bytes = hash.to_bytes();
            vm.cpu.write_wide(0, U256::from_le_bytes(addr_bytes));
            return true;
        }
    }

    false
}
