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
use crate::trace::{ExecutionTrace, TraceEvent};

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

/// Execute VM with cheatcode interception AND trace recording.
/// Same as execute_with_cheatcodes but also records trace events.
pub fn execute_with_tracing(
    vm: &mut Vm,
    cheat_state: &mut CheatcodeState,
    trace: &mut ExecutionTrace,
) -> Outcome {
    if let Some(ref addr) = cheat_state.prank_caller {
        vm.ctx.caller = *addr;
    }

    vm.clear_journal();
    let logs_start = vm.logs.len();
    let mut call_depth: u32 = 0;

    let result = loop {
        let idx = (vm.pc / 4) as usize;
        let maybe_instr = vm.decoded_cache().get(idx).copied();

        if let Some(d) = maybe_instr {
            // Record trace events BEFORE stepping
            match d.opcode {
                Opcode::CallExt => {
                    let target: [u8; 32] = vm.cpu.read_wide(d.rd).to_le_bytes();

                    // Cheatcode interception (same as execute_with_cheatcodes)
                    if target == CHEATCODE_ADDRESS {
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
                        vm.pc += 4;
                        continue;
                    }

                    // Record call trace
                    let calldata_ptr = vm.cpu.read_gp(d.rs1) as u32;
                    let selector = if let Ok(sel_bytes) = vm.memory.checked_read_slice(calldata_ptr, 4) {
                        u32::from_be_bytes(sel_bytes[..4].try_into().unwrap_or([0; 4]))
                    } else {
                        0
                    };
                    trace.push(TraceEvent::Call {
                        target,
                        selector,
                        function_name: format!("0x{:08x}", selector),
                        gas_start: vm.gas_used_total,
                        depth: call_depth,
                    });
                    call_depth += 1;
                }
                Opcode::Create => {
                    trace.push(TraceEvent::Deploy {
                        address: [0u8; 32], // filled after step
                        code_size: 0,
                        gas_used: 0,
                        depth: call_depth,
                    });
                }
                Opcode::Sload => {
                    let slot = vm.cpu.read_wide(d.rs1);
                    trace.push(TraceEvent::SLoad {
                        key: slot,
                        value: 0, // value unknown until after step
                        depth: call_depth,
                    });
                }
                Opcode::Sstore => {
                    let slot = vm.cpu.read_wide(d.rs1);
                    let mode = d.rs2_or_imm & 0x3;
                    let value = if mode == 2 { vm.cpu.read_gp(d.rd) } else { 0 };
                    trace.push(TraceEvent::SStore {
                        key: slot,
                        value,
                        depth: call_depth,
                    });
                }
                Opcode::Log => {
                    trace.push(TraceEvent::Log {
                        topic_count: d.rd,
                        data_size: 0,
                        depth: call_depth,
                    });
                }
                _ => {}
            }
        }

        // Normal step
        match vm.step() {
            Ok(Some(ExecResult::Halt)) => break Outcome::Success,
            Ok(Some(ExecResult::Revert)) => {
                trace.push(TraceEvent::Revert {
                    error_selector: None,
                    error_name: None,
                    depth: call_depth,
                });
                vm.rollback_storage_pub();
                vm.logs.truncate(logs_start);
                vm.gas_refund = 0;
                break Outcome::Revert;
            }
            Ok(None) => {
                // After CallExt returns, record the return event
                if let Some(d) = maybe_instr {
                    if d.opcode == Opcode::CallExt {
                        let target: [u8; 32] = vm.cpu.read_wide(d.rd).to_le_bytes();
                        if target != CHEATCODE_ADDRESS {
                            call_depth = call_depth.saturating_sub(1);
                            let result_reg = ((d.rs2_or_imm >> 8) & 0xF) as u8;
                            let success = vm.cpu.read_gp(result_reg) == 1;
                            trace.push(TraceEvent::Return {
                                success,
                                gas_used: 0,
                                return_value: vm.cpu.read_gp(1),
                                depth: call_depth,
                            });
                        }
                    }
                }
            }
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

        // Clear single-use prank
        if let Some(d) = maybe_instr {
            if d.opcode == Opcode::CallExt && !cheat_state.prank_persistent {
                if cheat_state.prank_caller.is_some() {
                    cheat_state.prank_caller = None;
                }
            }
        }
    };

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

    // Calldata layout: [selector:4 BE][args...]
    // GP args (u64, bool): 8 bytes LE
    // Wide args (Address, u256): 32 bytes LE
    if selector == selectors::warp() {
        // warp(timestamp: u64) — [sel:4][timestamp:8 LE]
        if calldata.len() >= 12 {
            let ts = u64::from_le_bytes(calldata[4..12].try_into().unwrap_or([0; 8]));
            vm.ctx.timestamp = ts;
            return true;
        }
    } else if selector == selectors::roll() {
        // roll(block_number: u64) — [sel:4][block_number:8 LE]
        if calldata.len() >= 12 {
            let bn = u64::from_le_bytes(calldata[4..12].try_into().unwrap_or([0; 8]));
            vm.ctx.block_number = bn;
            return true;
        }
    } else if selector == selectors::prank() {
        // prank(sender: Address) — [sel:4][address:32 LE]
        if calldata.len() >= 36 {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&calldata[4..36]);
            state.prank_caller = Some(addr);
            state.prank_persistent = false;
            vm.ctx.caller = addr;
            return true;
        }
    } else if selector == selectors::start_prank() {
        // startPrank(sender: Address) — [sel:4][address:32 LE]
        if calldata.len() >= 36 {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&calldata[4..36]);
            state.prank_caller = Some(addr);
            state.prank_persistent = true;
            vm.ctx.caller = addr;
            return true;
        }
    } else if selector == selectors::stop_prank() {
        // stopPrank() — [sel:4] (no args)
        state.prank_caller = None;
        state.prank_persistent = false;
        return true;
    } else if selector == selectors::deal() {
        // deal(account: Address, amount: u256) — [sel:4][address:32 LE][amount:32 LE]
        if calldata.len() >= 68 {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&calldata[4..36]);
            let amount = U256::from_le_bytes(calldata[36..68].try_into().unwrap_or([0; 32]));
            vm.ctx.balances.insert(addr, amount);
            return true;
        }
    } else if selector == selectors::make_addr() {
        // makeAddr(seed: u64) — [sel:4][seed:8 LE]
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
