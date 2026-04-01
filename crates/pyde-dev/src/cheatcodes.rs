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

/// Cheatcode selectors (FNV-1a of the name, stored as first 8 bytes of calldata).
pub mod selectors {
    pub fn compute(name: &str) -> u64 {
        let mut hash: u32 = 0x811c9dc5;
        for byte in name.bytes() {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(0x01000193);
        }
        hash as u64
    }

    pub fn warp() -> u64 {
        compute("vm::warp")
    }
    pub fn roll() -> u64 {
        compute("vm::roll")
    }
    pub fn prank() -> u64 {
        compute("vm::prank")
    }
    pub fn start_prank() -> u64 {
        compute("vm::startPrank")
    }
    pub fn stop_prank() -> u64 {
        compute("vm::stopPrank")
    }
    pub fn deal() -> u64 {
        compute("vm::deal")
    }
    pub fn make_addr() -> u64 {
        compute("vm::makeAddr")
    }
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

    loop {
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
    }
}

/// Handle a single cheatcode call. Returns true on success.
fn handle_cheatcode(vm: &mut Vm, state: &mut CheatcodeState, calldata: &[u8]) -> bool {
    if calldata.len() < 8 {
        return false;
    }

    let selector = u64::from_le_bytes(calldata[..8].try_into().unwrap_or([0; 8]));

    if selector == selectors::warp() {
        // vm::warp!(timestamp) — calldata: [sel:8][timestamp:8 LE]
        if calldata.len() >= 16 {
            let ts = u64::from_le_bytes(calldata[8..16].try_into().unwrap_or([0; 8]));
            vm.ctx.timestamp = ts;
            return true;
        }
    } else if selector == selectors::roll() {
        // vm::roll!(block_number) — calldata: [sel:8][block_number:8 LE]
        if calldata.len() >= 16 {
            let bn = u64::from_le_bytes(calldata[8..16].try_into().unwrap_or([0; 8]));
            vm.ctx.block_number = bn;
            return true;
        }
    } else if selector == selectors::prank() {
        // vm::prank!(address) — calldata: [sel:8][address:32 LE]
        if calldata.len() >= 40 {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&calldata[8..40]);
            state.prank_caller = Some(addr);
            state.prank_persistent = false;
            vm.ctx.caller = addr;
            return true;
        }
    } else if selector == selectors::start_prank() {
        // vm::startPrank!(address) — calldata: [sel:8][address:32 LE]
        if calldata.len() >= 40 {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&calldata[8..40]);
            state.prank_caller = Some(addr);
            state.prank_persistent = true;
            vm.ctx.caller = addr;
            return true;
        }
    } else if selector == selectors::stop_prank() {
        // vm::stopPrank!() — no args
        state.prank_caller = None;
        state.prank_persistent = false;
        return true;
    } else if selector == selectors::deal() {
        // vm::deal!(address, amount) — calldata: [sel:8][address:32 LE][amount:32 LE]
        if calldata.len() >= 72 {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&calldata[8..40]);
            let amount = U256::from_le_bytes(calldata[40..72].try_into().unwrap_or([0; 32]));
            vm.ctx.balances.insert(addr, amount);
            return true;
        }
    } else if selector == selectors::make_addr() {
        // vm::makeAddr!("label") — calldata: [sel:8][len:8 LE][label bytes]
        if calldata.len() >= 16 {
            let len = u64::from_le_bytes(calldata[8..16].try_into().unwrap_or([0; 8])) as usize;
            if calldata.len() >= 16 + len {
                let label = &calldata[16..16 + len];
                // Deterministic address: hash the label
                let hash = pyde_crypto::poseidon2::poseidon2_hash(label);
                let addr_bytes = hash.to_bytes();
                // Write result to w0 (wide register 0) — the compiler expects it there
                vm.cpu.write_wide(0, U256::from_le_bytes(addr_bytes));
                return true;
            }
        }
    }

    false
}
