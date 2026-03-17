//! PVM execution engine: ties CPU, memory, and control flow together.

use crate::cpu::{Cpu, Trap};
use crate::isa::{
    decode, decode_mem_offset, decode_mem_width, sign_extend_18, DecodedInstruction, Instruction,
    MemWidth, Opcode,
};
use crate::memory::Memory;
use crate::wide::U256;
use std::collections::HashMap;

/// 32-byte address type (Poseidon2 hash of FALCON-512 public key).
pub type Address = [u8; 32];

/// Zero address constant.
pub const ZERO_ADDRESS: Address = [0u8; 32];

/// Maximum call depth (nested function calls).
const MAX_CALL_DEPTH: usize = 1024;

/// Sub-codes for the `Caller` opcode (GP-width environment queries).
/// The immediate field selects which value to return.
pub mod env_gp {
    pub const BLOCK_NUMBER: u32 = 0;
    pub const TIMESTAMP: u32 = 1;
    pub const GAS_REMAINING: u32 = 2;
}

/// Sub-codes for the `Callvalue` opcode (wide environment queries).
/// Addresses are 32 bytes, so CALLER and ADDRESS are wide.
pub mod env_wide {
    pub const CALL_VALUE: u32 = 0;
    pub const GAS_PRICE: u32 = 1;
    pub const BALANCE: u32 = 2;
    pub const CALLER: u32 = 3;
    pub const ADDRESS: u32 = 4;
}

/// Execution context: caller info, block info, and balances.
#[derive(Clone, Debug)]
pub struct ExecutionContext {
    /// Address of the caller (msg.sender), 32 bytes.
    pub caller: Address,
    /// Address of the current contract, 32 bytes.
    pub self_address: Address,
    /// Value sent with the call (msg.value), 256-bit.
    pub call_value: U256,
    /// Current block number.
    pub block_number: u64,
    /// Current block timestamp (Unix seconds).
    pub timestamp: u64,
    /// Current base fee / gas price, 256-bit.
    pub gas_price: U256,
    /// Recent block hashes (index 0 = most recent). Up to 256 entries.
    pub block_hashes: Vec<U256>,
    /// Balance lookup: address → balance.
    pub balances: HashMap<Address, U256>,
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self {
            caller: ZERO_ADDRESS,
            self_address: ZERO_ADDRESS,
            call_value: U256::ZERO,
            block_number: 0,
            timestamp: 0,
            gas_price: U256::ZERO,
            block_hashes: Vec::new(),
            balances: HashMap::new(),
        }
    }
}

/// A saved call frame on the internal call stack (CALL/RET within a contract).
#[derive(Clone, Copy, Debug)]
struct CallFrame {
    /// Return address (PC to resume after RET).
    return_addr: u32,
    /// Previous frame pointer.
    frame_pointer: u32,
}

/// Maximum depth for cross-contract calls (CALL_EXT/DELEGATECALL/STATICCALL).
const MAX_EXT_CALL_DEPTH: usize = 1024;

/// Result of a cross-contract call.
#[derive(Clone, Debug)]
pub struct CallResult {
    /// Whether the call succeeded.
    pub success: bool,
    /// Return data from the callee.
    pub return_data: Vec<u8>,
    /// Gas consumed by the callee.
    pub gas_used: u64,
}

/// Execution outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecResult {
    /// Execution completed successfully (HALT).
    Halt,
    /// Execution reverted (REVERT).
    Revert,
}

/// Detailed execution outcome (Success, Revert, OutOfGas, or Trap).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Execution completed successfully.
    Success,
    /// Execution reverted (all state changes rolled back).
    Revert,
    /// Ran out of gas (all state changes rolled back).
    OutOfGas,
    /// Execution trapped (bug/invalid code).
    Trap(Trap),
}

/// A single step in the execution trace (for ZK prover).
#[derive(Clone, Copy, Debug)]
pub struct TraceStep {
    /// Program counter before this step.
    pub pc: u32,
    /// Opcode executed.
    pub opcode: Opcode,
    /// Cumulative gas after this step.
    pub gas_used: u64,
}

/// Full execution output returned by `execute()`.
#[derive(Clone, Debug)]
pub struct ExecutionOutput {
    /// High-level outcome.
    pub outcome: Outcome,
    /// Gas consumed (after refund).
    pub gas_used: u64,
    /// Raw gas consumed (before refund).
    pub gas_raw: GasUsed,
    /// Gas refunded.
    pub gas_refund: u64,
    /// Event logs (empty on revert/OOG).
    pub logs: Vec<EventLog>,
    /// Execution trace for ZK prover.
    pub trace: Vec<TraceStep>,
}

/// Two-dimensional gas tracker: execution + proving costs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GasUsed {
    /// Total execution gas consumed.
    pub exec: u64,
    /// Total proving gas consumed.
    pub prove: u64,
}

impl GasUsed {
    /// Total gas = exec + prove.
    pub fn total(&self) -> u64 {
        self.exec + self.prove
    }
}

/// An emitted event log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventLog {
    /// Contract address that emitted the event.
    pub address: Address,
    /// Indexed topics (up to 4: topic0 = event signature hash, topic1-3 = indexed fields).
    pub topics: Vec<U256>,
    /// Non-indexed data payload.
    pub data: Vec<u8>,
}

/// The full VM state.
///
/// Struct layout optimized for cache locality: hot fields (pc, gas, cpu)
/// are placed first so they share cache lines during the step() hot loop.
/// Cold fields (storage, logs, journal) are at the end.
pub struct Vm {
    // --- Hot: accessed every step() ---
    /// Program counter (byte offset into code section).
    pub pc: u32,
    /// Frame pointer register.
    pub fp: u32,
    /// Running total gas (exec + prove), precomputed for fast OOG checks.
    pub gas_used_total: u64,
    /// Gas limit for this execution. 0 = unlimited.
    pub gas_limit: u64,
    /// Two-dimensional gas consumed (exec + prove).
    pub gas: GasUsed,
    /// Accumulated gas refund (e.g. from SDELETE).
    pub gas_refund: u64,
    /// CPU register file (GP + wide registers).
    pub cpu: Cpu,
    /// Pre-decoded instruction cache. Populated at load time to avoid
    /// decode overhead in the hot loop.
    decoded_cache: Vec<DecodedInstruction>,

    // --- Warm: accessed on memory/storage instructions ---
    /// Linear memory (lazily allocated pages).
    pub memory: Memory,
    /// Execution context (caller, block info, etc.).
    pub ctx: ExecutionContext,
    /// Key-value storage overlay (derived_key → variable-length bytes).
    pub storage: HashMap<U256, Vec<u8>>,

    // --- Cold: accessed infrequently ---
    /// Internal call stack for CALL/RET within a contract.
    call_stack: Vec<CallFrame>,
    /// Accumulated event logs emitted during execution.
    pub logs: Vec<EventLog>,
    /// Storage write journal for rollback.
    storage_journal: Vec<(U256, Option<Vec<u8>>)>,
    /// Keys already journaled (O(1) dedup instead of O(n) scan).
    storage_journal_keys: std::collections::HashSet<U256>,
    /// Contract registry: address → deployed bytecode.
    pub contracts: HashMap<Address, Vec<u8>>,
    /// Calldata: input bytes passed to this contract.
    pub calldata: Vec<u8>,
    /// Return data from the last external call.
    pub return_data: Vec<u8>,
    /// Whether this execution is in static mode (no state writes allowed).
    pub static_mode: bool,
    /// Set of contract addresses currently on the external call stack (reentrancy detection).
    reentrancy_set: std::collections::HashSet<Address>,
    /// Current external call depth.
    ext_call_depth: usize,
}

/// Safe address calculation: base (u64) + offset (i64) → u32, or MemoryFault.
#[inline]
fn safe_addr(base: u64, offset: i64) -> Result<u32, Trap> {
    let result = (base as i128) + (offset as i128);
    if result < 0 || result > u32::MAX as i128 {
        return Err(Trap::MemoryFault);
    }
    Ok(result as u32)
}

impl Vm {
    /// Create a new VM with no gas limit (unlimited).
    pub fn new() -> Self {
        Self {
            cpu: Cpu::new(),
            memory: Memory::new(),
            pc: 0,
            call_stack: Vec::new(),
            fp: 0,
            gas: GasUsed::default(),
            gas_used_total: 0,
            gas_limit: 0,
            gas_refund: 0,
            ctx: ExecutionContext::default(),
            storage: HashMap::new(),
            logs: Vec::new(),
            storage_journal: Vec::new(),
            storage_journal_keys: std::collections::HashSet::new(),
            decoded_cache: Vec::new(),
            contracts: HashMap::new(),
            calldata: Vec::new(),
            return_data: Vec::new(),
            static_mode: false,
            reentrancy_set: std::collections::HashSet::new(),
            ext_call_depth: 0,
        }
    }

    /// Create a new VM with a gas limit.
    pub fn with_gas_limit(gas_limit: u64) -> Self {
        Self {
            gas_limit,
            ..Self::new()
        }
    }

    /// Create a new VM with an execution context.
    pub fn with_context(ctx: ExecutionContext) -> Self {
        Self { ctx, ..Self::new() }
    }

    /// Create a new VM with both a gas limit and execution context.
    pub fn with_gas_limit_and_context(gas_limit: u64, ctx: ExecutionContext) -> Self {
        Self {
            gas_limit,
            ctx,
            ..Self::new()
        }
    }

    /// Load bytecode and prepare for execution.
    /// Pre-decodes all instructions at load time for faster dispatch.
    pub fn load(&mut self, bytecode: &[u8]) -> Result<(), Trap> {
        self.memory
            .load_code(bytecode)
            .map_err(|_| Trap::MemoryFault)?;
        self.pc = 0;

        // Pre-decode instruction cache
        let num_instrs = bytecode.len() / 4;
        self.decoded_cache = Vec::with_capacity(num_instrs);
        for i in 0..num_instrs {
            let word = u32::from_le_bytes([
                bytecode[i * 4],
                bytecode[i * 4 + 1],
                bytecode[i * 4 + 2],
                bytecode[i * 4 + 3],
            ]);
            self.decoded_cache.push(decode(Instruction(word)));
        }

        // Map calldata into memory if present
        if !self.calldata.is_empty() {
            self.map_calldata()?;
        }

        Ok(())
    }

    /// Copy calldata into memory at HEAP_START and set r4 = calldata length.
    /// Advances heap_top past the calldata so allocations don't overwrite it.
    /// Aligns heap_top to 8 bytes after calldata for clean memory access.
    fn map_calldata(&mut self) -> Result<(), Trap> {
        let heap_start = crate::memory::HEAP_START;
        let len = self.calldata.len();

        if len == 0 {
            return Ok(());
        }

        // Bulk write calldata into memory at HEAP_START (single bounds check)
        self.memory
            .checked_write_slice(heap_start, &self.calldata)
            .map_err(|_| Trap::MemoryFault)?;

        // Advance heap_top past calldata (aligned to 8 bytes)
        let aligned_len = (len + 7) & !7; // round up to 8-byte boundary
        self.memory.heap_top = heap_start + aligned_len as u32;

        // r4 = calldata length (function argument register convention)
        self.cpu.write_gp(4, len as u64);

        // r5 = calldata pointer (HEAP_START) for convenience
        self.cpu.write_gp(5, heap_start as u64);

        Ok(())
    }

    /// Fetch the instruction at the current PC.
    fn fetch(&self) -> Result<Instruction, Trap> {
        let addr = crate::memory::CODE_START + self.pc;
        if self.pc + 4 > self.memory.code_end - crate::memory::CODE_START {
            return Err(Trap::InvalidOpcode);
        }
        let word = self.memory.fetch_code_u32(addr);
        Ok(Instruction(word))
    }

    /// Execute a single step. Returns Some(ExecResult) if execution finished.
    pub fn step(&mut self) -> Result<Option<ExecResult>, Trap> {
        let idx = (self.pc / 4) as usize;
        let d = match self.decoded_cache.get(idx) {
            Some(&d) => d,
            None => return Err(Trap::InvalidOpcode),
        };

        // Charge gas: single addition from precomputed lookup table
        self.gas_used_total += crate::isa::total_gas(d.opcode.to_u8());

        // Check gas limit (0 = unlimited)
        if self.gas_limit > 0 && self.gas_used_total > self.gas_limit {
            return Err(Trap::OutOfGas);
        }

        // Track two-dimensional breakdown (exec + prove)
        let cost = crate::isa::gas_cost(d.opcode);
        self.gas.exec += cost.exec as u64;
        self.gas.prove += cost.prove as u64;

        match d.opcode {
            // --- Control flow ---
            Opcode::Jmp => {
                let target = sign_extend_18(d.rs2_or_imm);
                self.pc = self.pc.wrapping_add(target as u32);
            }
            Opcode::Beq => {
                let rs1_val = self.cpu.read_gp(d.rd);
                let rs2_val = self.cpu.read_gp(d.rs1);
                if rs1_val == rs2_val {
                    let offset = sign_extend_18(d.rs2_or_imm);
                    self.pc = self.pc.wrapping_add(offset as u32);
                } else {
                    self.pc += 4;
                }
            }
            Opcode::Bne => {
                let rs1_val = self.cpu.read_gp(d.rd);
                let rs2_val = self.cpu.read_gp(d.rs1);
                if rs1_val != rs2_val {
                    let offset = sign_extend_18(d.rs2_or_imm);
                    self.pc = self.pc.wrapping_add(offset as u32);
                } else {
                    self.pc += 4;
                }
            }
            Opcode::Blt => {
                let rs1_val = self.cpu.read_gp(d.rd);
                let rs2_val = self.cpu.read_gp(d.rs1);
                if rs1_val < rs2_val {
                    let offset = sign_extend_18(d.rs2_or_imm);
                    self.pc = self.pc.wrapping_add(offset as u32);
                } else {
                    self.pc += 4;
                }
            }
            Opcode::Bge => {
                let rs1_val = self.cpu.read_gp(d.rd);
                let rs2_val = self.cpu.read_gp(d.rs1);
                if rs1_val >= rs2_val {
                    let offset = sign_extend_18(d.rs2_or_imm);
                    self.pc = self.pc.wrapping_add(offset as u32);
                } else {
                    self.pc += 4;
                }
            }
            Opcode::Call => {
                if self.call_stack.len() >= MAX_CALL_DEPTH {
                    return Err(Trap::StackOverflow);
                }
                self.call_stack.push(CallFrame {
                    return_addr: self.pc + 4,
                    frame_pointer: self.fp,
                });
                self.fp = self.memory.stack_pointer;
                let target = sign_extend_18(d.rs2_or_imm);
                self.pc = self.pc.wrapping_add(target as u32);
            }
            Opcode::Ret => {
                let frame = self.call_stack.pop().ok_or(Trap::StackUnderflow)?;
                self.pc = frame.return_addr;
                self.fp = frame.frame_pointer;
            }
            Opcode::Halt => {
                return Ok(Some(ExecResult::Halt));
            }
            Opcode::Revert => {
                return Ok(Some(ExecResult::Revert));
            }

            // --- ALU ops: delegate to cpu ---
            Opcode::Add
            | Opcode::Sub
            | Opcode::Mul
            | Opcode::Div
            | Opcode::Mod
            | Opcode::Addi
            | Opcode::And
            | Opcode::Or
            | Opcode::Xor
            | Opcode::Not
            | Opcode::Shl
            | Opcode::Shr
            | Opcode::Sar
            | Opcode::Lt
            | Opcode::Gt
            | Opcode::Eq
            | Opcode::Slt
            | Opcode::Sgt => {
                let instr = crate::isa::encode(d.opcode, d.rd, d.rs1, d.rs2_or_imm);
                self.cpu.exec_alu(instr)?;
                self.pc += 4;
            }

            // --- Wide ops: delegate to cpu ---
            Opcode::Wadd
            | Opcode::Wsub
            | Opcode::Wmul
            | Opcode::Wdiv
            | Opcode::Wmod
            | Opcode::Wand
            | Opcode::Wor
            | Opcode::Wxor
            | Opcode::Wnot
            | Opcode::Wmov
            | Opcode::Narrow
            | Opcode::Widen
            | Opcode::Weq
            | Opcode::Wlt => {
                let instr = crate::isa::encode(d.opcode, d.rd, d.rs1, d.rs2_or_imm);
                self.cpu.exec_wide(instr)?;
                self.pc += 4;
            }

            // --- Memory ops (width-encoded) ---
            Opcode::Load => {
                let base = self.cpu.read_gp(d.rs1);
                let offset = decode_mem_offset(d.rs2_or_imm) as i64;
                let width = decode_mem_width(d.rs2_or_imm);
                let addr = safe_addr(base, offset)?;
                let val = match width {
                    MemWidth::W8 => self.memory.load8(addr).map_err(|_| Trap::MemoryFault)? as u64,
                    MemWidth::W16 => {
                        self.memory.load16(addr).map_err(|_| Trap::MemoryFault)? as u64
                    }
                    MemWidth::W32 => {
                        self.memory.load32(addr).map_err(|_| Trap::MemoryFault)? as u64
                    }
                    MemWidth::W64 => self.memory.load64(addr).map_err(|_| Trap::MemoryFault)?,
                };
                self.cpu.write_gp(d.rd, val);
                self.pc += 4;
            }
            Opcode::Store => {
                let base = self.cpu.read_gp(d.rs1);
                let offset = decode_mem_offset(d.rs2_or_imm) as i64;
                let width = decode_mem_width(d.rs2_or_imm);
                let addr = safe_addr(base, offset)?;
                let val = self.cpu.read_gp(d.rd);
                match width {
                    MemWidth::W8 => self
                        .memory
                        .store8(addr, val as u8)
                        .map_err(|_| Trap::MemoryFault)?,
                    MemWidth::W16 => self
                        .memory
                        .store16(addr, val as u16)
                        .map_err(|_| Trap::MemoryFault)?,
                    MemWidth::W32 => self
                        .memory
                        .store32(addr, val as u32)
                        .map_err(|_| Trap::MemoryFault)?,
                    MemWidth::W64 => self
                        .memory
                        .store64(addr, val)
                        .map_err(|_| Trap::MemoryFault)?,
                };
                self.pc += 4;
            }
            Opcode::Wload => {
                let base = self.cpu.read_gp(d.rs1);
                let offset = sign_extend_18(d.rs2_or_imm) as i64;
                let addr = safe_addr(base, offset)?;
                let bytes = self.memory.load256(addr).map_err(|_| Trap::MemoryFault)?;
                self.cpu.write_wide(d.rd, U256::from_le_bytes(bytes));
                self.pc += 4;
            }
            Opcode::Wstore => {
                let base = self.cpu.read_gp(d.rs1);
                let offset = sign_extend_18(d.rs2_or_imm) as i64;
                let addr = safe_addr(base, offset)?;
                let val = self.cpu.read_wide(d.rd);
                self.memory
                    .store256(addr, &val.to_le_bytes())
                    .map_err(|_| Trap::MemoryFault)?;
                self.pc += 4;
            }
            Opcode::Push => {
                let val = self.cpu.read_gp(d.rd);
                let sp = self.memory.stack_alloc(8).map_err(|_| Trap::MemoryFault)?;
                self.memory
                    .store64(sp, val)
                    .map_err(|_| Trap::MemoryFault)?;
                self.pc += 4;
            }
            Opcode::Pop => {
                let sp = self.memory.stack_pointer;
                if sp.checked_add(8).is_none() || sp + 8 > crate::memory::STACK_TOP {
                    return Err(Trap::MemoryFault);
                }
                let val = self.memory.load64(sp).map_err(|_| Trap::MemoryFault)?;
                self.cpu.write_gp(d.rd, val);
                self.memory.stack_pointer = sp + 8;
                self.pc += 4;
            }

            // --- System instructions (environment queries) ---
            Opcode::Caller => {
                let sub = d.rs2_or_imm;
                let val = match sub {
                    env_gp::BLOCK_NUMBER => self.ctx.block_number,
                    env_gp::TIMESTAMP => self.ctx.timestamp,
                    env_gp::GAS_REMAINING => self.gas_remaining(),
                    _ => return Err(Trap::InvalidOpcode),
                };
                self.cpu.write_gp(d.rd, val);
                self.pc += 4;
            }
            Opcode::Callvalue => {
                let sub = d.rs2_or_imm;
                let val = match sub {
                    env_wide::CALL_VALUE => self.ctx.call_value,
                    env_wide::GAS_PRICE => self.ctx.gas_price,
                    env_wide::BALANCE => {
                        // Address in wide register ws1
                        let addr_u256 = self.cpu.read_wide(d.rs1);
                        let addr: Address = addr_u256.to_le_bytes();
                        *self.ctx.balances.get(&addr).unwrap_or(&U256::ZERO)
                    }
                    env_wide::CALLER => U256::from_le_bytes(self.ctx.caller),
                    env_wide::ADDRESS => U256::from_le_bytes(self.ctx.self_address),
                    _ => return Err(Trap::InvalidOpcode),
                };
                self.cpu.write_wide(d.rd, val);
                self.pc += 4;
            }
            Opcode::Blockhash => {
                let height = self.cpu.read_gp(d.rs1);
                let current = self.ctx.block_number;
                // Only allow recent blocks (up to 256 back), and not current/future
                let hash = if height < current && current - height <= 256 {
                    let idx = (current - height - 1) as usize;
                    self.ctx
                        .block_hashes
                        .get(idx)
                        .copied()
                        .unwrap_or(U256::ZERO)
                } else {
                    U256::ZERO
                };
                self.cpu.write_wide(d.rd, hash);
                self.pc += 4;
            }

            // --- Crypto instructions ---
            Opcode::Poseidon => {
                // poseidon wd, rs1, rs2 — hash rs2 bytes from memory[rs1] → wd
                let addr = self.cpu.read_gp(d.rs1) as u32;
                let len = (d.rs2_or_imm & 0xF) as u8;
                let byte_len = self.cpu.read_gp(len) as usize;
                let data = self
                    .memory
                    .checked_read_slice(addr, byte_len)
                    .map_err(|_| Trap::MemoryFault)?;
                let hash = pyde_crypto::poseidon2::poseidon2_hash(&data);
                let hash_bytes: [u8; 32] = hash.to_bytes();
                self.cpu.write_wide(d.rd, U256::from_le_bytes(hash_bytes));
                self.pc += 4;
            }
            // --- Storage instructions ---
            // imm & 0x3: 0 = wide register (32 bytes), 1 = memory (variable), 2 = GP register (8 bytes)
            Opcode::Sload => {
                let slot = self.cpu.read_wide(d.rs1);
                let key = self.derive_storage_key(slot);
                let mode = d.rs2_or_imm & 0x3;
                match mode {
                    0 => {
                        // Wide register mode: sload wd, ws1
                        let mut buf = [0u8; 32];
                        if let Some(data) = self.storage.get(&key) {
                            let len = data.len().min(32);
                            buf[..len].copy_from_slice(&data[..len]);
                        }
                        self.cpu.write_wide(d.rd, U256::from_le_bytes(buf));
                    }
                    1 => {
                        // Memory mode: sloadb rd_len, ws1, rs_ptr
                        let ptr_reg = ((d.rs2_or_imm >> 2) & 0xF) as u8;
                        let ptr = self.cpu.read_gp(ptr_reg) as u32;
                        if let Some(data) = self.storage.get(&key) {
                            self.memory
                                .checked_write_slice(ptr, data)
                                .map_err(|_| Trap::MemoryFault)?;
                            self.cpu.write_gp(d.rd, data.len() as u64);
                        } else {
                            self.cpu.write_gp(d.rd, 0);
                        }
                    }
                    2 => {
                        // GP register mode: sloadg rd, ws1
                        let mut buf = [0u8; 8];
                        if let Some(data) = self.storage.get(&key) {
                            let len = data.len().min(8);
                            buf[..len].copy_from_slice(&data[..len]);
                        }
                        self.cpu.write_gp(d.rd, u64::from_le_bytes(buf));
                    }
                    _ => return Err(Trap::InvalidOpcode),
                }
                self.pc += 4;
            }
            Opcode::Sstore => {
                if self.static_mode {
                    return Err(Trap::StaticModeViolation);
                }
                let slot = self.cpu.read_wide(d.rs1);
                let key = self.derive_storage_key(slot);
                self.journal_storage_write(&key);
                let mode = d.rs2_or_imm & 0x3;
                match mode {
                    0 => {
                        // Wide register mode: sstore ws1, wd
                        let value = self.cpu.read_wide(d.rd);
                        self.storage.insert(key, value.to_le_bytes().to_vec());
                    }
                    2 => {
                        // GP register mode: sstoreg ws1, rd
                        let value = self.cpu.read_gp(d.rd);
                        self.storage.insert(key, value.to_le_bytes().to_vec());
                    }
                    1 => {
                        // Memory mode: sstoreb ws1, rs_ptr, rs_len
                        // ptr register in imm bits [5:2], len register in imm bits [9:6]
                        let ptr_reg = ((d.rs2_or_imm >> 2) & 0xF) as u8;
                        let len_reg = ((d.rs2_or_imm >> 6) & 0xF) as u8;
                        let ptr = self.cpu.read_gp(ptr_reg) as u32;
                        let len = self.cpu.read_gp(len_reg) as usize;
                        let data = self
                            .memory
                            .checked_read_slice(ptr, len)
                            .map_err(|_| Trap::MemoryFault)?;
                        self.storage.insert(key, data);
                    }
                    _ => return Err(Trap::InvalidOpcode),
                }
                self.pc += 4;
            }
            Opcode::Sdelete => {
                if self.static_mode {
                    return Err(Trap::StaticModeViolation);
                }
                // sdelete ws1 — clear storage slot, grant gas refund if non-empty
                let slot = self.cpu.read_wide(d.rs1);
                let key = self.derive_storage_key(slot);
                self.journal_storage_write(&key);
                if let Some(v) = self.storage.get(&key) {
                    if !v.is_empty() {
                        self.gas_refund += 1500;
                    }
                }
                self.storage.insert(key, Vec::new());
                self.pc += 4;
            }

            // --- Event instruction ---
            Opcode::Log => {
                if self.static_mode {
                    return Err(Trap::StaticModeViolation);
                }
                // log rs1, imm — emit an event log
                // imm = number of topics (0-4)
                // rs1 = pointer to descriptor in memory:
                //   [topic0:32][topic1:32]...[topicN:32][data_ptr:8][data_len:8]
                let num_topics = (d.rs2_or_imm & 0x7) as usize;
                if num_topics > 4 {
                    return Err(Trap::InvalidOpcode);
                }
                let desc_ptr = self.cpu.read_gp(d.rs1) as u32;

                // Read topics
                let mut topics = Vec::with_capacity(num_topics);
                for t in 0..num_topics {
                    let offset = desc_ptr + (t as u32) * 32;
                    let mut buf = [0u8; 32];
                    for (j, byte) in buf.iter_mut().enumerate() {
                        *byte = self
                            .memory
                            .load8(offset + j as u32)
                            .map_err(|_| Trap::MemoryFault)?;
                    }
                    topics.push(U256::from_le_bytes(buf));
                }

                // Read data_ptr and data_len after the topics
                let after_topics = desc_ptr + (num_topics as u32) * 32;
                let data_ptr = self
                    .memory
                    .load64(after_topics)
                    .map_err(|_| Trap::MemoryFault)? as u32;
                let data_len = self
                    .memory
                    .load64(after_topics + 8)
                    .map_err(|_| Trap::MemoryFault)? as usize;

                // Read data payload (bulk)
                let data = self
                    .memory
                    .checked_read_slice(data_ptr, data_len)
                    .map_err(|_| Trap::MemoryFault)?;

                // Charge dynamic gas: 100 base + 8 per data byte + 50 per topic
                let dynamic_gas = 100u64 + (data_len as u64) * 8 + (num_topics as u64) * 50;
                self.gas.exec += dynamic_gas;
                self.gas_used_total += dynamic_gas;
                if self.gas_limit > 0 && self.gas_used_total > self.gas_limit {
                    return Err(Trap::OutOfGas);
                }

                self.logs.push(EventLog {
                    address: self.ctx.self_address,
                    topics,
                    data,
                });
                self.pc += 4;
            }

            Opcode::VerifySig => {
                // verifysig rd, rs1 — rs1 points to descriptor in memory:
                //   [msg_ptr:8][msg_len:8][sig_ptr:8][sig_len:8][pk_ptr:8][pk_len:8]
                // rd = 1 if valid, 0 if invalid
                let desc_addr = self.cpu.read_gp(d.rs1) as u32;
                let msg_ptr = self
                    .memory
                    .load64(desc_addr)
                    .map_err(|_| Trap::MemoryFault)? as u32;
                let msg_len = self
                    .memory
                    .load64(desc_addr + 8)
                    .map_err(|_| Trap::MemoryFault)? as usize;
                let sig_ptr = self
                    .memory
                    .load64(desc_addr + 16)
                    .map_err(|_| Trap::MemoryFault)? as u32;
                let sig_len = self
                    .memory
                    .load64(desc_addr + 24)
                    .map_err(|_| Trap::MemoryFault)? as usize;
                let pk_ptr = self
                    .memory
                    .load64(desc_addr + 32)
                    .map_err(|_| Trap::MemoryFault)? as u32;
                let pk_len = self
                    .memory
                    .load64(desc_addr + 40)
                    .map_err(|_| Trap::MemoryFault)? as usize;

                // Read msg, sig, pk from memory
                let msg = self
                    .memory
                    .checked_read_slice(msg_ptr, msg_len)
                    .map_err(|_| Trap::MemoryFault)?;
                let sig_bytes = self
                    .memory
                    .checked_read_slice(sig_ptr, sig_len)
                    .map_err(|_| Trap::MemoryFault)?;
                let pk_bytes = self
                    .memory
                    .checked_read_slice(pk_ptr, pk_len)
                    .map_err(|_| Trap::MemoryFault)?;

                let pk = match pyde_crypto::falcon::FalconPublicKey::from_bytes(&pk_bytes) {
                    Some(pk) => pk,
                    None => {
                        // Invalid public key size → verification fails
                        self.cpu.write_gp(d.rd, 0);
                        self.pc += 4;
                        return Ok(None);
                    }
                };
                let sig = pyde_crypto::falcon::FalconSignature::from_bytes(&sig_bytes);
                let valid = pyde_crypto::falcon::falcon_verify(&pk, &msg, &sig);
                self.cpu.write_gp(d.rd, if valid { 1 } else { 0 });
                self.pc += 4;
            }

            // --- Cross-contract call instructions ---
            Opcode::CallExt => {
                // call_ext wd, rs1, imm
                // wd = wide register with target address (32 bytes)
                // rs1 = GP register with calldata pointer in memory
                // imm[3:0] = GP register with calldata length
                // imm[7:4] = GP register with gas to forward
                // imm[11:8] = GP register for result (1=success, 0=failure)
                if self.static_mode {
                    return Err(Trap::StaticModeViolation);
                }
                let result_reg = ((d.rs2_or_imm >> 8) & 0xF) as u8;
                let result = self.do_ext_call(d, false, false)?;
                self.cpu
                    .write_gp(result_reg, if result.success { 1 } else { 0 });
                self.return_data = result.return_data;
                self.pc += 4;
            }

            Opcode::Delegate => {
                // delegate wd, rs1, imm — same encoding as CallExt
                if self.static_mode {
                    return Err(Trap::StaticModeViolation);
                }
                let result_reg = ((d.rs2_or_imm >> 8) & 0xF) as u8;
                let result = self.do_ext_call(d, false, true)?;
                self.cpu
                    .write_gp(result_reg, if result.success { 1 } else { 0 });
                self.return_data = result.return_data;
                self.pc += 4;
            }

            // STATICCALL: uses CallExt opcode with a flag. We encode it as
            // the same opcode layout but with imm bit 8 set.
            // For now, we use a separate opcode slot (not yet in ISA — reuse Assert).
            // Actually, we can detect static from the immediate field:
            // imm[8] = 1 means static call. But cleaner: just add handling here.
            // The ISA doesn't have a STATICCALL opcode, so we'll encode it as
            // CallExt with imm bit 8 set. The VM checks this bit.
            Opcode::Create => {
                // create wd, rs1, imm
                // wd = wide register for new contract address (32 bytes)
                // rs1 = GP register with init code pointer
                // imm[3:0] = GP register with init code length
                if self.static_mode {
                    return Err(Trap::StaticModeViolation);
                }
                let new_addr = self.do_create(d, false)?;
                self.cpu.write_wide(d.rd, U256::from_le_bytes(new_addr));
                self.pc += 4;
            }

            // --- ZK-native instructions ---
            Opcode::Assert => {
                // assert rs1 — if rs1 == 0, revert (provable assertion)
                let val = self.cpu.read_gp(d.rs1);
                if val == 0 {
                    return Ok(Some(ExecResult::Revert));
                }
                self.pc += 4;
            }
            Opcode::FieldMul => {
                // field_mul rd, rs1, rs2 — modular multiplication over Goldilocks field
                // p = 2^64 - 2^32 + 1 (Goldilocks prime)
                let a = self.cpu.read_gp(d.rs1) as u128;
                let rs2 = (d.rs2_or_imm & 0xF) as u8;
                let b = self.cpu.read_gp(rs2) as u128;
                const GOLDILOCKS_P: u128 = (1u128 << 64) - (1u128 << 32) + 1;
                let result = ((a * b) % GOLDILOCKS_P) as u64;
                self.cpu.write_gp(d.rd, result);
                self.pc += 4;
            }
            Opcode::Commit => {
                // commit rd — write rd value to public output (ZK prover captures from trace)
                self.pc += 4;
            }
            Opcode::Selfdestruct => {
                if self.static_mode {
                    return Err(Trap::StaticModeViolation);
                }
                self.storage.clear();
                return Ok(Some(ExecResult::Halt));
            }
            Opcode::MerkleVerify => {
                // merkle_verify rd, ws1, rs2 — stub: always returns 1
                // Full impl needs witness data from full nodes
                self.cpu.write_gp(d.rd, 1);
                self.pc += 4;
            }

            _ => return Err(Trap::InvalidOpcode),
        }

        Ok(None)
    }

    /// Run until HALT, REVERT, or error. Returns the execution result.
    pub fn run(&mut self) -> Result<ExecResult, Trap> {
        loop {
            if let Some(result) = self.step()? {
                return Ok(result);
            }
        }
    }

    /// Execute with full state management: journaled rollback on revert/OOG,
    /// execution trace recording for ZK provers, and detailed output.
    pub fn execute(&mut self) -> ExecutionOutput {
        self.storage_journal.clear();
        self.storage_journal_keys.clear();
        let logs_snapshot_len = self.logs.len();

        let mut trace = Vec::new();
        let outcome = loop {
            let pc = self.pc;
            let idx = (pc / 4) as usize;
            let opcode = match self.decoded_cache.get(idx) {
                Some(d) => d.opcode,
                None => break Outcome::Trap(Trap::MemoryFault),
            };

            match self.step() {
                Ok(Some(ExecResult::Halt)) => {
                    trace.push(TraceStep {
                        pc,
                        opcode,
                        gas_used: self.gas_used_total,
                    });
                    break Outcome::Success;
                }
                Ok(Some(ExecResult::Revert)) => {
                    trace.push(TraceStep {
                        pc,
                        opcode,
                        gas_used: self.gas_used_total,
                    });
                    self.rollback_storage();
                    self.logs.truncate(logs_snapshot_len);
                    self.gas_refund = 0;
                    break Outcome::Revert;
                }
                Ok(None) => {
                    trace.push(TraceStep {
                        pc,
                        opcode,
                        gas_used: self.gas_used_total,
                    });
                }
                Err(Trap::OutOfGas) => {
                    trace.push(TraceStep {
                        pc,
                        opcode,
                        gas_used: self.gas_used_total,
                    });
                    self.rollback_storage();
                    self.logs.truncate(logs_snapshot_len);
                    self.gas_refund = 0;
                    break Outcome::OutOfGas;
                }
                Err(trap) => {
                    trace.push(TraceStep {
                        pc,
                        opcode,
                        gas_used: self.gas_used_total,
                    });
                    self.rollback_storage();
                    self.logs.truncate(logs_snapshot_len);
                    self.gas_refund = 0;
                    break Outcome::Trap(trap);
                }
            }
        };

        self.storage_journal.clear();
        self.storage_journal_keys.clear();

        ExecutionOutput {
            outcome,
            gas_used: self.effective_gas_used(),
            gas_raw: self.gas,
            gas_refund: self.gas_refund,
            logs: self.logs[logs_snapshot_len..].to_vec(),
            trace,
        }
    }

    /// Current call depth.
    pub fn call_depth(&self) -> usize {
        self.call_stack.len()
    }

    /// Remaining gas (returns u64::MAX if unlimited).
    pub fn gas_remaining(&self) -> u64 {
        if self.gas_limit == 0 {
            u64::MAX
        } else {
            self.gas_limit.saturating_sub(self.gas_used_total)
        }
    }

    /// Derive a storage key from a slot and the contract's address.
    /// key = poseidon2(slot_bytes ++ address_bytes)
    pub fn derive_storage_key(&self, slot: U256) -> U256 {
        let mut buf = [0u8; 64]; // 32 (slot) + 32 (address)
        buf[..32].copy_from_slice(&slot.to_le_bytes());
        buf[32..64].copy_from_slice(&self.ctx.self_address);
        let hash = pyde_crypto::poseidon2::poseidon2_hash(&buf);
        U256::from_le_bytes(hash.to_bytes())
    }

    /// Effective gas used after applying refund (capped at 50% of total used).
    pub fn effective_gas_used(&self) -> u64 {
        let max_refund = self.gas_used_total / 2; // cap at 50%
        let refund = self.gas_refund.min(max_refund);
        self.gas_used_total - refund
    }

    /// Execute an external contract call (CALL_EXT, DELEGATECALL, or STATICCALL).
    ///
    /// Spawns a child VM with the target contract's bytecode, forwards gas,
    /// passes calldata, and collects return data. On child revert, only the
    /// child's state changes are rolled back.
    fn do_ext_call(
        &mut self,
        d: DecodedInstruction,
        is_static: bool,
        is_delegate: bool,
    ) -> Result<CallResult, Trap> {
        if self.ext_call_depth >= MAX_EXT_CALL_DEPTH {
            return Err(Trap::StackOverflow);
        }

        let target_addr: Address = self.cpu.read_wide(d.rd).to_le_bytes();
        let calldata_ptr = self.cpu.read_gp(d.rs1) as u32;
        let len_reg = (d.rs2_or_imm & 0xF) as u8;
        let gas_reg = ((d.rs2_or_imm >> 4) & 0xF) as u8;
        let calldata_len = self.cpu.read_gp(len_reg) as usize;
        let gas_to_forward = self.cpu.read_gp(gas_reg);
        let is_static_call = is_static || ((d.rs2_or_imm >> 12) & 1) == 1;

        // Read calldata from caller's memory (bulk)
        let calldata = self
            .memory
            .checked_read_slice(calldata_ptr, calldata_len)
            .map_err(|_| Trap::MemoryFault)?;

        // Look up target contract bytecode
        let bytecode = match self.contracts.get(&target_addr) {
            Some(code) => code.clone(),
            None => {
                // No contract at target address — call fails
                return Ok(CallResult {
                    success: false,
                    return_data: Vec::new(),
                    gas_used: 0,
                });
            }
        };

        // Reentrancy check (default: no reentrancy allowed)
        let call_target = if is_delegate {
            self.ctx.self_address
        } else {
            target_addr
        };
        if self.reentrancy_set.contains(&call_target) {
            return Ok(CallResult {
                success: false,
                return_data: Vec::new(),
                gas_used: 0,
            });
        }

        // Gas forwarding: forward requested amount, capped at available - 2300 (retain minimum)
        let available_gas = if self.gas_limit > 0 {
            self.gas_limit.saturating_sub(self.gas_used_total)
        } else {
            u64::MAX
        };
        let retained = 2300u64; // minimum gas kept by caller
        let max_forward = available_gas.saturating_sub(retained);
        let forwarded = if gas_to_forward == 0 {
            max_forward // 0 means "forward all available"
        } else {
            gas_to_forward.min(max_forward)
        };

        // Build child execution context
        let child_ctx = if is_delegate {
            // DELEGATECALL: preserve caller's address and msg.sender
            ExecutionContext {
                caller: self.ctx.caller,
                self_address: self.ctx.self_address,
                call_value: self.ctx.call_value,
                block_number: self.ctx.block_number,
                timestamp: self.ctx.timestamp,
                gas_price: self.ctx.gas_price,
                block_hashes: self.ctx.block_hashes.clone(),
                balances: self.ctx.balances.clone(),
            }
        } else {
            ExecutionContext {
                caller: self.ctx.self_address,
                self_address: target_addr,
                call_value: U256::ZERO, // value transfer not yet implemented
                block_number: self.ctx.block_number,
                timestamp: self.ctx.timestamp,
                gas_price: self.ctx.gas_price,
                block_hashes: self.ctx.block_hashes.clone(),
                balances: self.ctx.balances.clone(),
            }
        };

        // Spawn child VM
        let mut child = Vm::with_gas_limit_and_context(forwarded, child_ctx);
        child.static_mode = is_static_call || self.static_mode;
        child.contracts = self.contracts.clone();
        child.ext_call_depth = self.ext_call_depth + 1;
        child.reentrancy_set = self.reentrancy_set.clone();
        child.reentrancy_set.insert(self.ctx.self_address); // caller is on the stack
        child.reentrancy_set.insert(call_target); // callee is being entered
        child.calldata = calldata;

        // Share storage for delegate calls
        if is_delegate {
            child.storage = std::mem::take(&mut self.storage);
        } else {
            child.storage = self.storage.clone();
        }

        child.load(&bytecode).map_err(|_| Trap::MemoryFault)?;
        let output = child.execute();

        // Charge parent for gas used by child
        self.gas_used_total += output.gas_used;
        self.gas.exec += output.gas_raw.exec;
        self.gas.prove += output.gas_raw.prove;

        let success = output.outcome == Outcome::Success;

        if success {
            // Merge child's storage changes into parent
            if is_delegate {
                self.storage = child.storage;
            } else {
                for (k, v) in &child.storage {
                    self.storage.insert(*k, v.clone());
                }
            }
            // Merge child's logs
            self.logs.extend(output.logs);
            // Accumulate refunds
            self.gas_refund += output.gas_refund;
        } else if is_delegate {
            // Restore parent's storage on delegate failure
            self.storage = child.storage;
        }

        Ok(CallResult {
            success,
            return_data: child.return_data,
            gas_used: output.gas_used,
        })
    }

    /// Deploy a new contract (CREATE/CREATE2). Returns the 32-byte address.
    fn do_create(&mut self, d: DecodedInstruction, is_create2: bool) -> Result<Address, Trap> {
        if self.ext_call_depth >= MAX_EXT_CALL_DEPTH {
            return Err(Trap::StackOverflow);
        }

        let code_ptr = self.cpu.read_gp(d.rs1) as u32;
        let len_reg = (d.rs2_or_imm & 0xF) as u8;
        let code_len = self.cpu.read_gp(len_reg) as usize;

        let init_code = self
            .memory
            .checked_read_slice(code_ptr, code_len)
            .map_err(|_| Trap::MemoryFault)?;

        // Derive 32-byte contract address
        let new_addr: Address = if is_create2 {
            // CREATE2: address = poseidon2(0xFF ++ sender ++ salt ++ code_hash)
            let salt = self.cpu.read_wide(0);
            let code_hash = pyde_crypto::poseidon2::poseidon2_hash(&init_code);
            let mut addr_input = Vec::with_capacity(1 + 32 + 32 + 32);
            addr_input.push(0xFF);
            addr_input.extend_from_slice(&self.ctx.self_address);
            addr_input.extend_from_slice(&salt.to_le_bytes());
            addr_input.extend_from_slice(&code_hash.to_bytes());
            pyde_crypto::poseidon2::poseidon2_hash(&addr_input).to_bytes()
        } else {
            // CREATE: address = poseidon2(sender ++ code)
            let mut addr_input = Vec::with_capacity(32 + init_code.len());
            addr_input.extend_from_slice(&self.ctx.self_address);
            addr_input.extend_from_slice(&init_code);
            pyde_crypto::poseidon2::poseidon2_hash(&addr_input).to_bytes()
        };

        self.contracts.insert(new_addr, init_code);

        Ok(new_addr)
    }

    /// Record a storage key's current value in the journal before writing.
    /// Only journals the first write to each key (subsequent writes to the
    /// same key don't need a new journal entry — the original value is already saved).
    #[inline]
    pub fn journal_storage_write(&mut self, key: &U256) {
        if self.storage_journal_keys.insert(*key) {
            let old = self.storage.get(key).cloned();
            self.storage_journal.push((*key, old));
        }
    }

    /// Rollback storage to the state before journaled writes.
    fn rollback_storage(&mut self) {
        self.storage_journal_keys.clear();
        for (key, old_value) in self.storage_journal.drain(..).rev() {
            match old_value {
                Some(v) => {
                    self.storage.insert(key, v);
                }
                None => {
                    self.storage.remove(&key);
                }
            }
        }
    }
}

impl Default for Vm {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::{encode, encode_immediate, encode_mem_immediate, MemWidth, Opcode};

    /// Helper: encode an instruction to little-endian bytes.
    fn instr_bytes(op: Opcode, rd: u8, rs1: u8, rs2_or_imm: u32) -> [u8; 4] {
        encode(op, rd, rs1, rs2_or_imm).0.to_le_bytes()
    }

    fn instr_ri(op: Opcode, rd: u8, rs1: u8, imm: i32) -> [u8; 4] {
        encode(op, rd, rs1, encode_immediate(imm)).0.to_le_bytes()
    }

    /// Helper: encode a LOAD/STORE instruction with width and offset.
    fn instr_mem(op: Opcode, rd: u8, rs1: u8, offset: i32, width: MemWidth) -> [u8; 4] {
        encode(op, rd, rs1, encode_mem_immediate(offset, width))
            .0
            .to_le_bytes()
    }

    /// Build bytecode from instruction byte arrays.
    fn bytecode(instrs: &[[u8; 4]]) -> Vec<u8> {
        instrs.iter().flat_map(|i| i.iter().copied()).collect()
    }

    /// Helper: create a 32-byte Address from a u64 seed (for test readability).
    fn addr(seed: u64) -> Address {
        let mut a = ZERO_ADDRESS;
        a[..8].copy_from_slice(&seed.to_le_bytes());
        a
    }

    // ========== Task 0145: JMP ==========

    #[test]
    fn jmp_forward() {
        // [0] JMP +8 (skip one instruction)
        // [4] ADDI r1, r0, 99  (skipped)
        // [8] HALT
        let code = bytecode(&[
            instr_ri(Opcode::Jmp, 0, 0, 8),
            instr_ri(Opcode::Addi, 1, 0, 99),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(1), 0); // r1 was never set
    }

    #[test]
    fn jmp_backward() {
        // [0] ADDI r1, r0, 1
        // [4] JMP +8 (jump to [12])
        // [8] ADDI r1, r1, 10 (jumped back to here from [12])
        // [12] ...but wait, we need to be careful about infinite loops
        // Simpler test:
        // [0] ADDI r1, r0, 1
        // [4] JMP +8 (jump to HALT at [12])
        // [8] ADDI r1, r0, 99 (skipped)
        // [12] HALT
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 1),
            instr_ri(Opcode::Jmp, 0, 0, 8),
            instr_ri(Opcode::Addi, 1, 0, 99),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(1), 1); // only first ADDI ran
    }

    // ========== Task 0146: BEQ ==========

    #[test]
    fn beq_taken() {
        // r1 = r2 = 0 (both default to 0), so BEQ is taken
        // [0] BEQ r1, r2, +8 (jump to HALT)
        // [4] ADDI r3, r0, 99 (skipped)
        // [8] HALT
        let code = bytecode(&[
            instr_ri(Opcode::Beq, 1, 2, 8),
            instr_ri(Opcode::Addi, 3, 0, 99),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 0);
    }

    #[test]
    fn beq_not_taken() {
        // [0] ADDI r1, r0, 1
        // [4] BEQ r1, r0, +8 (r1=1, r0=0, not equal, not taken)
        // [8] ADDI r3, r0, 42
        // [12] HALT
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 1),
            instr_ri(Opcode::Beq, 1, 0, 8),
            instr_ri(Opcode::Addi, 3, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 42); // ADDI ran
    }

    // ========== Task 0147: BNE ==========

    #[test]
    fn bne_taken() {
        // [0] ADDI r1, r0, 1
        // [4] BNE r1, r0, +8 (r1=1 != r0=0, taken)
        // [8] ADDI r3, r0, 99 (skipped)
        // [12] HALT
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 1),
            instr_ri(Opcode::Bne, 1, 0, 8),
            instr_ri(Opcode::Addi, 3, 0, 99),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 0);
    }

    #[test]
    fn bne_not_taken() {
        // [0] BNE r0, r0, +8 (r0==r0, not taken)
        // [4] ADDI r3, r0, 42
        // [8] HALT
        let code = bytecode(&[
            instr_ri(Opcode::Bne, 0, 0, 8),
            instr_ri(Opcode::Addi, 3, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 42);
    }

    // ========== Task 0148: BLT ==========

    #[test]
    fn blt_taken() {
        // [0] ADDI r1, r0, 5
        // [4] ADDI r2, r0, 10
        // [8] BLT r1, r2, +8 (5 < 10, taken)
        // [12] ADDI r3, r0, 99 (skipped)
        // [16] HALT
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 5),
            instr_ri(Opcode::Addi, 2, 0, 10),
            instr_ri(Opcode::Blt, 1, 2, 8),
            instr_ri(Opcode::Addi, 3, 0, 99),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 0);
    }

    #[test]
    fn blt_not_taken() {
        // [0] ADDI r1, r0, 10
        // [4] ADDI r2, r0, 5
        // [8] BLT r1, r2, +8 (10 < 5 is false, not taken)
        // [12] ADDI r3, r0, 42
        // [16] HALT
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),
            instr_ri(Opcode::Addi, 2, 0, 5),
            instr_ri(Opcode::Blt, 1, 2, 8),
            instr_ri(Opcode::Addi, 3, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 42);
    }

    // ========== Task 0149: BGE ==========

    #[test]
    fn bge_equal() {
        // [0] ADDI r1, r0, 5
        // [4] ADDI r2, r0, 5
        // [8] BGE r1, r2, +8 (5 >= 5, taken)
        // [12] ADDI r3, r0, 99
        // [16] HALT
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 5),
            instr_ri(Opcode::Addi, 2, 0, 5),
            instr_ri(Opcode::Bge, 1, 2, 8),
            instr_ri(Opcode::Addi, 3, 0, 99),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 0);
    }

    #[test]
    fn bge_greater() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),
            instr_ri(Opcode::Addi, 2, 0, 5),
            instr_ri(Opcode::Bge, 1, 2, 8),
            instr_ri(Opcode::Addi, 3, 0, 99),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 0);
    }

    // ========== Task 0152: CALL ==========

    #[test]
    fn call_and_ret() {
        // [0] ADDI r1, r0, 1
        // [4] CALL +8 (jump to [12])
        // [8] HALT           (return here after RET)
        // [12] ADDI r2, r0, 2  (function body)
        // [16] RET
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 1),
            instr_ri(Opcode::Call, 0, 0, 8),
            instr_bytes(Opcode::Halt, 0, 0, 0),
            instr_ri(Opcode::Addi, 2, 0, 2),
            instr_bytes(Opcode::Ret, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(1), 1);
        assert_eq!(vm.cpu.read_gp(2), 2);
    }

    // ========== Task 0155: Max call depth ==========

    #[test]
    fn max_call_depth_exceeded() {
        // Recursive function that calls itself forever
        // [0] CALL +0 (call self, offset 0 means jump to same address)
        let code = bytecode(&[
            instr_ri(Opcode::Call, 0, 0, 0), // infinite recursion
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run(), Err(Trap::StackOverflow));
        assert_eq!(vm.call_depth(), MAX_CALL_DEPTH);
    }

    // ========== Task 0156: HALT ==========

    #[test]
    fn halt_stops_execution() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
            instr_ri(Opcode::Addi, 1, 0, 99), // never reached
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(1), 42);
    }

    // ========== Task 0157: REVERT ==========

    #[test]
    fn revert_stops_execution() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),
            instr_bytes(Opcode::Revert, 0, 0, 0),
            instr_ri(Opcode::Addi, 1, 0, 99),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Revert);
        assert_eq!(vm.cpu.read_gp(1), 42);
    }

    // ========== Task 0158: Forward and backward jumps ==========

    #[test]
    fn backward_jump_loop() {
        // Simple loop: r1 counts from 0 to 3
        // [0]  ADDI r1, r0, 0     (counter = 0)
        // [4]  ADDI r2, r0, 3     (limit = 3)
        // [8]  BEQ r1, r2, +12    (if counter == limit, jump to HALT at [20])
        // [12] ADDI r1, r1, 1     (counter++)
        // [16] JMP -8             (jump back to BEQ at [8])
        // [20] HALT
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 0),
            instr_ri(Opcode::Addi, 2, 0, 3),
            instr_ri(Opcode::Beq, 1, 2, 12),
            instr_ri(Opcode::Addi, 1, 1, 1),
            instr_ri(Opcode::Jmp, 0, 0, -8),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(1), 3);
    }

    // ========== Task 0159: All branch conditions ==========

    #[test]
    fn blt_equal_not_taken() {
        // 5 < 5 is false
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 5),
            instr_ri(Opcode::Addi, 2, 0, 5),
            instr_ri(Opcode::Blt, 1, 2, 8),
            instr_ri(Opcode::Addi, 3, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 42); // not taken, ADDI ran
    }

    #[test]
    fn bge_less_not_taken() {
        // 3 >= 5 is false
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 3),
            instr_ri(Opcode::Addi, 2, 0, 5),
            instr_ri(Opcode::Bge, 1, 2, 8),
            instr_ri(Opcode::Addi, 3, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 42);
    }

    // ========== Task 0160: Nested function calls ==========

    #[test]
    fn nested_calls_5_deep() {
        // Each function increments r1 then calls the next, until depth 5
        // [0]  ADDI r1, r0, 0
        // [4]  CALL +8 -> func1 at [12]
        // [8]  HALT
        // [12] ADDI r1, r1, 1   ; func1
        // [16] CALL +8 -> func2 at [24]
        // [20] RET
        // [24] ADDI r1, r1, 1   ; func2
        // [28] CALL +8 -> func3 at [36]
        // [32] RET
        // [36] ADDI r1, r1, 1   ; func3
        // [40] CALL +8 -> func4 at [48]
        // [44] RET
        // [48] ADDI r1, r1, 1   ; func4
        // [52] CALL +8 -> func5 at [60]
        // [56] RET
        // [60] ADDI r1, r1, 1   ; func5
        // [64] RET
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 0),    // [0]
            instr_ri(Opcode::Call, 0, 0, 8),    // [4]
            instr_bytes(Opcode::Halt, 0, 0, 0), // [8]
            instr_ri(Opcode::Addi, 1, 1, 1),    // [12]
            instr_ri(Opcode::Call, 0, 0, 8),    // [16]
            instr_bytes(Opcode::Ret, 0, 0, 0),  // [20]
            instr_ri(Opcode::Addi, 1, 1, 1),    // [24]
            instr_ri(Opcode::Call, 0, 0, 8),    // [28]
            instr_bytes(Opcode::Ret, 0, 0, 0),  // [32]
            instr_ri(Opcode::Addi, 1, 1, 1),    // [36]
            instr_ri(Opcode::Call, 0, 0, 8),    // [40]
            instr_bytes(Opcode::Ret, 0, 0, 0),  // [44]
            instr_ri(Opcode::Addi, 1, 1, 1),    // [48]
            instr_ri(Opcode::Call, 0, 0, 8),    // [52]
            instr_bytes(Opcode::Ret, 0, 0, 0),  // [56]
            instr_ri(Opcode::Addi, 1, 1, 1),    // [60]
            instr_bytes(Opcode::Ret, 0, 0, 0),  // [64]
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(1), 5);
    }

    // ========== Task 0162: RET with no CALL ==========

    #[test]
    fn ret_without_call_traps() {
        let code = bytecode(&[instr_bytes(Opcode::Ret, 0, 0, 0)]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run(), Err(Trap::StackUnderflow));
    }

    // ========== Task 0163: HALT vs REVERT ==========

    #[test]
    fn halt_vs_revert() {
        // HALT returns Halt
        let code1 = bytecode(&[instr_bytes(Opcode::Halt, 0, 0, 0)]);
        let mut vm1 = Vm::new();
        vm1.load(&code1).unwrap();
        assert_eq!(vm1.run().unwrap(), ExecResult::Halt);

        // REVERT returns Revert
        let code2 = bytecode(&[instr_bytes(Opcode::Revert, 0, 0, 0)]);
        let mut vm2 = Vm::new();
        vm2.load(&code2).unwrap();
        assert_eq!(vm2.run().unwrap(), ExecResult::Revert);
    }

    // ========== Gas metering ==========

    #[test]
    fn gas_is_charged() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        vm.run().unwrap();
        assert!(vm.gas.total() > 0);
    }

    // ========== Push/Pop through VM ==========

    #[test]
    fn push_pop_roundtrip() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),
            instr_bytes(Opcode::Push, 1, 0, 0), // push r1
            instr_ri(Opcode::Addi, 1, 0, 0),    // clobber r1
            instr_bytes(Opcode::Pop, 2, 0, 0),  // pop into r2
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(2), 42);
    }

    // ========== ALU through VM ==========

    #[test]
    fn alu_through_vm() {
        // r1=10, r2=20, r3 = r1 + r2 = 30
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),
            instr_ri(Opcode::Addi, 2, 0, 20),
            instr_bytes(Opcode::Add, 3, 1, 2),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 30);
    }

    // ========== Width-encoded LOAD/STORE ==========

    #[test]
    fn load_store_8bit() {
        let heap = crate::memory::HEAP_START;
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap as i32), // r1 = heap addr
            instr_ri(Opcode::Addi, 2, 0, 0xAB),        // r2 = 0xAB
            instr_mem(Opcode::Store, 2, 1, 0, MemWidth::W8), // store8(r1+0, r2)
            instr_mem(Opcode::Load, 3, 1, 0, MemWidth::W8), // r3 = load8(r1+0)
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 0xAB);
    }

    #[test]
    fn load_store_16bit() {
        let heap = crate::memory::HEAP_START;
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap as i32),
            instr_ri(Opcode::Addi, 2, 0, 0x1234),
            instr_mem(Opcode::Store, 2, 1, 0, MemWidth::W16),
            instr_mem(Opcode::Load, 3, 1, 0, MemWidth::W16),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 0x1234);
    }

    #[test]
    fn load_store_32bit() {
        let heap = crate::memory::HEAP_START;
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap as i32),
            instr_ri(Opcode::Addi, 2, 0, 0x7FFF), // small value that fits in imm
            instr_mem(Opcode::Store, 2, 1, 0, MemWidth::W32),
            instr_mem(Opcode::Load, 3, 1, 0, MemWidth::W32),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 0x7FFF);
    }

    #[test]
    fn load_store_64bit() {
        let heap = crate::memory::HEAP_START;
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap as i32),
            instr_ri(Opcode::Addi, 2, 0, 12345),
            instr_mem(Opcode::Store, 2, 1, 0, MemWidth::W64),
            instr_mem(Opcode::Load, 3, 1, 0, MemWidth::W64),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 12345);
    }

    #[test]
    fn load_store_with_offset() {
        let heap = crate::memory::HEAP_START;
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap as i32),
            instr_ri(Opcode::Addi, 2, 0, 0xFF),
            instr_mem(Opcode::Store, 2, 1, 16, MemWidth::W8), // store at heap+16
            instr_mem(Opcode::Load, 3, 1, 16, MemWidth::W8),  // load from heap+16
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 0xFF);
    }

    #[test]
    fn load_8bit_zero_extends() {
        // Store a 64-bit value, load back as 8-bit — should only get the lowest byte
        let heap = crate::memory::HEAP_START;
        let mut vm = Vm::new();
        vm.memory.store64(heap, 0xDEADBEEFCAFEBABE).unwrap();
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap as i32),
            instr_mem(Opcode::Load, 3, 1, 0, MemWidth::W8),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(3), 0xBE); // lowest byte, little-endian
    }

    // ========== WLOAD/WSTORE ==========

    #[test]
    fn wload_wstore_roundtrip() {
        let heap = crate::memory::HEAP_START;
        let mut vm = Vm::new();
        // Pre-write a U256 value into memory
        let val: U256 = U256::from(0xDEADBEEFu64) << 128 | U256::from(0xCAFEBABEu64);
        vm.memory.store256(heap, &val.to_le_bytes()).unwrap();

        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap as i32), // r1 = heap addr
            instr_ri(Opcode::Addi, 2, 0, (heap + 32) as i32), // r2 = heap+32
            instr_bytes(Opcode::Wload, 0, 1, 0),       // w0 = mem256[r1]
            instr_bytes(Opcode::Wstore, 0, 2, 0),      // mem256[r2] = w0
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);

        // Verify the copy
        let copied = vm.memory.load256(heap + 32).unwrap();
        assert_eq!(U256::from_le_bytes(copied), val);
    }

    #[test]
    fn wload_stores_to_wide_register() {
        let heap = crate::memory::HEAP_START;
        let mut vm = Vm::new();
        let val = U256::from(42u64);
        vm.memory.store256(heap, &val.to_le_bytes()).unwrap();

        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap as i32),
            instr_bytes(Opcode::Wload, 3, 1, 0), // w3 = mem256[r1]
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_wide(3), U256::from(42u64));
    }

    // ========== Gas metering ==========

    #[test]
    fn two_dimensional_gas_tracked() {
        // ADDI costs (exec=1, prove=2), HALT costs (exec=1, prove=1)
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        vm.run().unwrap();
        assert_eq!(vm.gas.exec, 2); // ADDI(1) + HALT(1)
        assert_eq!(vm.gas.prove, 3); // ADDI(2) + HALT(1)
        assert_eq!(vm.gas.total(), 5);
    }

    #[test]
    fn out_of_gas_traps() {
        // ADDI costs 3 total, HALT costs 2 total = 5 total
        // Set limit to 4 — should fail on HALT
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(4);
        vm.load(&code).unwrap();
        assert_eq!(vm.run(), Err(Trap::OutOfGas));
    }

    #[test]
    fn gas_limit_exact_succeeds() {
        // ADDI(3) + HALT(2) = 5 total
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(5);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.gas_remaining(), 0);
    }

    #[test]
    fn gas_limit_zero_means_unlimited() {
        // Many instructions, no limit
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 1),
            instr_ri(Opcode::Addi, 2, 0, 2),
            instr_ri(Opcode::Addi, 3, 0, 3),
            instr_ri(Opcode::Addi, 4, 0, 4),
            instr_ri(Opcode::Addi, 5, 0, 5),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new(); // gas_limit = 0
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.gas_remaining(), u64::MAX);
    }

    #[test]
    fn gas_remaining_decreases() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(100);
        vm.load(&code).unwrap();
        vm.run().unwrap();
        assert_eq!(vm.gas_remaining(), 95); // 100 - 5
    }

    #[test]
    fn out_of_gas_mid_loop() {
        // Loop: ADDI + BNE + ADDI costs per iteration
        // Counter from 0 to 100 — should run out of gas partway
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 0),   // r1 = 0 (counter)
            instr_ri(Opcode::Addi, 2, 0, 100), // r2 = 100 (limit)
            instr_ri(Opcode::Addi, 1, 1, 1),   // r1++ (3 gas)
            instr_ri(Opcode::Bne, 1, 2, -4),   // if r1 != r2, jump back (3 gas)
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(30); // not enough for 100 iterations
        vm.load(&code).unwrap();
        assert_eq!(vm.run(), Err(Trap::OutOfGas));
        // Counter should be partway through
        assert!(vm.cpu.read_gp(1) > 0);
        assert!(vm.cpu.read_gp(1) < 100);
    }

    #[test]
    fn gas_refund_cap_50_percent() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        vm.run().unwrap();

        let total = vm.gas.total(); // 5

        // No refund → effective = total
        assert_eq!(vm.effective_gas_used(), total);

        // Refund less than 50% → fully applied
        vm.gas_refund = 1;
        assert_eq!(vm.effective_gas_used(), total - 1);

        // Refund exactly 50% → fully applied
        vm.gas_refund = total / 2; // 2
        assert_eq!(vm.effective_gas_used(), total - total / 2);

        // Refund more than 50% → capped
        vm.gas_refund = total; // try 100% refund
        assert_eq!(vm.effective_gas_used(), total - total / 2); // capped at 50%
    }

    #[test]
    fn mul_costs_more_gas_than_add() {
        let code_add = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),
            instr_ri(Opcode::Addi, 2, 0, 20),
            instr_bytes(Opcode::Add, 3, 1, 2),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let code_mul = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),
            instr_ri(Opcode::Addi, 2, 0, 20),
            instr_bytes(Opcode::Mul, 3, 1, 2),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let mut vm_add = Vm::new();
        vm_add.load(&code_add).unwrap();
        vm_add.run().unwrap();

        let mut vm_mul = Vm::new();
        vm_mul.load(&code_mul).unwrap();
        vm_mul.run().unwrap();

        // MUL(10) > ADD(3), so total should differ
        assert!(vm_mul.gas.total() > vm_add.gas.total());
        assert!(vm_mul.gas.exec > vm_add.gas.exec);
        assert!(vm_mul.gas.prove > vm_add.gas.prove);
    }

    // ========== System instructions (M1.8) ==========

    #[test]
    fn caller_returns_msg_sender() {
        let caller_addr = addr(0xDEAD_BEEF);
        let ctx = ExecutionContext {
            caller: caller_addr,
            ..Default::default()
        };
        let code = bytecode(&[
            // CALLER returns 32-byte address via wide register
            instr_bytes(Opcode::Callvalue, 0, 0, env_wide::CALLER),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_context(ctx);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_wide(0).to_le_bytes(), caller_addr);
    }

    #[test]
    fn address_returns_self() {
        let self_addr = addr(0xCAFE_BABE);
        let ctx = ExecutionContext {
            self_address: self_addr,
            ..Default::default()
        };
        let code = bytecode(&[
            instr_bytes(Opcode::Callvalue, 0, 0, env_wide::ADDRESS),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_context(ctx);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_wide(0).to_le_bytes(), self_addr);
    }

    #[test]
    fn blocknumber_returns_height() {
        let ctx = ExecutionContext {
            block_number: 12345,
            ..Default::default()
        };
        let code = bytecode(&[
            instr_bytes(Opcode::Caller, 1, 0, env_gp::BLOCK_NUMBER),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_context(ctx);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(1), 12345);
    }

    #[test]
    fn timestamp_returns_unix_time() {
        let ctx = ExecutionContext {
            timestamp: 1_700_000_000,
            ..Default::default()
        };
        let code = bytecode(&[
            instr_bytes(Opcode::Caller, 1, 0, env_gp::TIMESTAMP),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_context(ctx);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(1), 1_700_000_000);
    }

    #[test]
    fn gasremaining_returns_remaining() {
        let code = bytecode(&[
            instr_bytes(Opcode::Caller, 1, 0, env_gp::GAS_REMAINING),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_gas_limit(1000);
        vm.load(&code).unwrap();
        // After executing Caller (gas cost 3), remaining should be 1000 - 3 = 997
        vm.step().unwrap();
        assert_eq!(vm.cpu.read_gp(1), 997);
    }

    #[test]
    fn callvalue_returns_msg_value() {
        let val = U256::from(1_000_000_000u64) * U256::from(10u64).pow(9); // 1e18
        let ctx = ExecutionContext {
            call_value: val,
            ..Default::default()
        };
        let code = bytecode(&[
            instr_bytes(Opcode::Callvalue, 0, 0, env_wide::CALL_VALUE),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_context(ctx);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_wide(0), val);
    }

    #[test]
    fn gasprice_returns_base_fee() {
        let price = U256::from(25_000_000_000u64); // 25 gwei
        let ctx = ExecutionContext {
            gas_price: price,
            ..Default::default()
        };
        let code = bytecode(&[
            instr_bytes(Opcode::Callvalue, 0, 0, env_wide::GAS_PRICE),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_context(ctx);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_wide(0), price);
    }

    #[test]
    fn balance_returns_account_balance() {
        let bal = U256::from(42_000u64);
        let target_addr = addr(100);
        let mut ctx = ExecutionContext::default();
        ctx.balances.insert(target_addr, bal);

        // Put target address into wide register w1, query balance into w0
        let mut vm = Vm::with_context(ctx);
        vm.cpu.write_wide(1, U256::from_le_bytes(target_addr));
        let code = bytecode(&[
            instr_bytes(Opcode::Callvalue, 0, 1, env_wide::BALANCE), // w0 = balance(w1)
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_wide(0), bal);
    }

    #[test]
    fn balance_unknown_address_returns_zero() {
        let mut vm = Vm::new();
        vm.cpu.write_wide(1, U256::from(999u64));
        let code = bytecode(&[
            instr_bytes(Opcode::Callvalue, 0, 1, env_wide::BALANCE),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_wide(0), U256::ZERO);
    }

    #[test]
    fn blockhash_recent_block() {
        let hash = U256::from(0xABCD_1234u64) << 128 | U256::from(0x5678u64);
        let ctx = ExecutionContext {
            block_number: 10,
            block_hashes: vec![hash], // index 0 = block 9 (most recent)
            ..Default::default()
        };
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 9),         // r1 = block height 9
            instr_bytes(Opcode::Blockhash, 0, 1, 0), // w0 = blockhash(9)
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_context(ctx);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_wide(0), hash);
    }

    #[test]
    fn blockhash_too_old_returns_zero() {
        let ctx = ExecutionContext {
            block_number: 300,
            block_hashes: vec![U256::from(1u64); 256], // 256 recent hashes
            ..Default::default()
        };
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 43), // block 43 (300 - 43 = 257 blocks ago)
            instr_bytes(Opcode::Blockhash, 0, 1, 0),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_context(ctx);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_wide(0), U256::ZERO); // too old
    }

    #[test]
    fn blockhash_current_block_returns_zero() {
        let ctx = ExecutionContext {
            block_number: 10,
            block_hashes: vec![U256::from(1u64); 10],
            ..Default::default()
        };
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10), // current block
            instr_bytes(Opcode::Blockhash, 0, 1, 0),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_context(ctx);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_wide(0), U256::ZERO); // current block not available
    }

    #[test]
    fn blockhash_future_block_returns_zero() {
        let ctx = ExecutionContext {
            block_number: 10,
            block_hashes: vec![U256::from(1u64); 10],
            ..Default::default()
        };
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 15), // future block
            instr_bytes(Opcode::Blockhash, 0, 1, 0),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::with_context(ctx);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_wide(0), U256::ZERO);
    }

    #[test]
    fn invalid_env_subcode_traps() {
        let code = bytecode(&[
            instr_bytes(Opcode::Caller, 1, 0, 99), // invalid sub-code
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run(), Err(Trap::InvalidOpcode));
    }

    // ========== Crypto instructions (M1.9) ==========

    #[test]
    fn poseidon_hashes_memory() {
        let heap = crate::memory::HEAP_START;
        let input = b"hello pyde";
        let expected = pyde_crypto::poseidon2::poseidon2_hash(input);

        let mut vm = Vm::new();
        // Write input bytes to heap
        for (i, &b) in input.iter().enumerate() {
            vm.memory.store8(heap + i as u32, b).unwrap();
        }

        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap as i32), // r1 = data ptr
            instr_ri(Opcode::Addi, 2, 0, input.len() as i32), // r2 = data len
            instr_bytes(Opcode::Poseidon, 0, 1, 2),    // w0 = poseidon(mem[r1..r1+r2])
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);

        let result = vm.cpu.read_wide(0);
        assert_eq!(result, U256::from_le_bytes(expected.to_bytes()));
    }

    #[test]
    fn poseidon_empty_input() {
        let expected = pyde_crypto::poseidon2::poseidon2_hash(b"");
        let heap = crate::memory::HEAP_START;

        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap as i32), // r1 = ptr (doesn't matter)
            instr_ri(Opcode::Addi, 2, 0, 0),           // r2 = 0 bytes
            instr_bytes(Opcode::Poseidon, 0, 1, 2),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(
            vm.cpu.read_wide(0),
            U256::from_le_bytes(expected.to_bytes())
        );
    }

    #[test]
    fn poseidon_different_inputs_differ() {
        let heap = crate::memory::HEAP_START;
        let mut vm = Vm::new();

        // Write "aaa" to heap
        for i in 0..3 {
            vm.memory.store8(heap + i, b'a').unwrap();
        }
        // Write "bbb" to heap+8
        for i in 0..3 {
            vm.memory.store8(heap + 8 + i, b'b').unwrap();
        }

        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap as i32),
            instr_ri(Opcode::Addi, 2, 0, 3),
            instr_bytes(Opcode::Poseidon, 0, 1, 2), // w0 = hash("aaa")
            instr_ri(Opcode::Addi, 3, 0, (heap + 8) as i32),
            instr_bytes(Opcode::Poseidon, 1, 3, 2), // w1 = hash("bbb")
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_ne!(vm.cpu.read_wide(0), vm.cpu.read_wide(1));
    }

    #[test]
    fn verifysig_valid_signature() {
        let heap = crate::memory::HEAP_START;
        let (pk, sk) = pyde_crypto::falcon::falcon_keygen();
        let msg = b"test message";
        let sig = pyde_crypto::falcon::falcon_sign(&sk, msg);

        let mut vm = Vm::new();

        // Layout in memory:
        // heap+0:    descriptor (48 bytes)
        // heap+48:   msg
        // heap+48+msg_len: sig
        // heap+48+msg_len+sig_len: pk
        let msg_ptr = heap + 48;
        let sig_ptr = msg_ptr + msg.len() as u32;
        let pk_ptr = sig_ptr + sig.len() as u32;

        // Write descriptor: [msg_ptr:8][msg_len:8][sig_ptr:8][sig_len:8][pk_ptr:8][pk_len:8]
        vm.memory.store64(heap, msg_ptr as u64).unwrap();
        vm.memory.store64(heap + 8, msg.len() as u64).unwrap();
        vm.memory.store64(heap + 16, sig_ptr as u64).unwrap();
        vm.memory.store64(heap + 24, sig.len() as u64).unwrap();
        vm.memory.store64(heap + 32, pk_ptr as u64).unwrap();
        vm.memory
            .store64(heap + 40, pk.as_bytes().len() as u64)
            .unwrap();

        // Write msg, sig, pk to memory
        for (i, &b) in msg.iter().enumerate() {
            vm.memory.store8(msg_ptr + i as u32, b).unwrap();
        }
        for (i, &b) in sig.as_bytes().iter().enumerate() {
            vm.memory.store8(sig_ptr + i as u32, b).unwrap();
        }
        for (i, &b) in pk.as_bytes().iter().enumerate() {
            vm.memory.store8(pk_ptr + i as u32, b).unwrap();
        }

        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap as i32),
            instr_bytes(Opcode::VerifySig, 2, 1, 0), // r2 = verifysig(descriptor at r1)
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(2), 1); // valid
    }

    #[test]
    fn verifysig_invalid_signature() {
        let heap = crate::memory::HEAP_START;
        let (pk, sk) = pyde_crypto::falcon::falcon_keygen();
        let msg = b"test message";
        let sig = pyde_crypto::falcon::falcon_sign(&sk, msg);

        let mut vm = Vm::new();

        let msg_ptr = heap + 48;
        let sig_ptr = msg_ptr + msg.len() as u32;
        let pk_ptr = sig_ptr + sig.len() as u32;

        // Write descriptor
        vm.memory.store64(heap, msg_ptr as u64).unwrap();
        vm.memory.store64(heap + 8, msg.len() as u64).unwrap();
        vm.memory.store64(heap + 16, sig_ptr as u64).unwrap();
        vm.memory.store64(heap + 24, sig.len() as u64).unwrap();
        vm.memory.store64(heap + 32, pk_ptr as u64).unwrap();
        vm.memory
            .store64(heap + 40, pk.as_bytes().len() as u64)
            .unwrap();

        // Write WRONG msg (different from what was signed)
        let wrong_msg = b"wrong message";
        for (i, &b) in wrong_msg.iter().enumerate() {
            vm.memory.store8(msg_ptr + i as u32, b).unwrap();
        }
        // Update msg_len in descriptor
        vm.memory.store64(heap + 8, wrong_msg.len() as u64).unwrap();

        for (i, &b) in sig.as_bytes().iter().enumerate() {
            vm.memory.store8(sig_ptr + i as u32, b).unwrap();
        }
        for (i, &b) in pk.as_bytes().iter().enumerate() {
            vm.memory.store8(pk_ptr + i as u32, b).unwrap();
        }

        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap as i32),
            instr_bytes(Opcode::VerifySig, 2, 1, 0),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(2), 0); // invalid
    }

    #[test]
    fn verifysig_bad_pk_size_returns_zero() {
        let heap = crate::memory::HEAP_START;
        let mut vm = Vm::new();

        let msg_ptr = heap + 48;
        let sig_ptr = msg_ptr + 4;
        let pk_ptr = sig_ptr + 4;

        // Descriptor with wrong pk_len (should be 897)
        vm.memory.store64(heap, msg_ptr as u64).unwrap();
        vm.memory.store64(heap + 8, 4).unwrap();
        vm.memory.store64(heap + 16, sig_ptr as u64).unwrap();
        vm.memory.store64(heap + 24, 4).unwrap();
        vm.memory.store64(heap + 32, pk_ptr as u64).unwrap();
        vm.memory.store64(heap + 40, 10).unwrap(); // wrong size

        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap as i32),
            instr_bytes(Opcode::VerifySig, 2, 1, 0),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(2), 0); // invalid pk → 0
    }

    #[test]
    fn poseidon_gas_cost() {
        let heap = crate::memory::HEAP_START;
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap as i32),
            instr_ri(Opcode::Addi, 2, 0, 0),
            instr_bytes(Opcode::Poseidon, 0, 1, 2),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        vm.run().unwrap();
        // Poseidon costs (exec=50, prove=150) = 200 total
        // Plus 2x ADDI (3 each) + HALT (2) = 208 total
        assert!(vm.gas.total() >= 200);
    }

    // --- Storage instruction tests ---

    #[test]
    fn sload_uninitialized_returns_zero() {
        // SLOAD from a slot that was never written should return U256::ZERO
        let mut vm = Vm::new();
        // Set slot in w0 to some arbitrary value
        vm.cpu.write_wide(0, U256::from(42u64));
        let code = bytecode(&[
            instr_bytes(Opcode::Sload, 1, 0, 0), // w1 = storage[w0]
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_wide(1), U256::ZERO);
    }

    #[test]
    fn sstore_then_sload_roundtrip() {
        let ctx = ExecutionContext {
            self_address: addr(0xBEEF),
            ..Default::default()
        };
        let mut vm = Vm::with_context(ctx);
        // w0 = slot, w1 = value to store
        vm.cpu.write_wide(0, U256::from(1u64));
        vm.cpu.write_wide(1, U256::from(0xDEAD_CAFEu64));
        let code = bytecode(&[
            instr_bytes(Opcode::Sstore, 1, 0, 0), // storage[w0] = w1
            instr_bytes(Opcode::Sload, 2, 0, 0),  // w2 = storage[w0]
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_wide(2), U256::from(0xDEAD_CAFEu64));
    }

    #[test]
    fn sdelete_sets_value_to_zero_and_grants_refund() {
        let ctx = ExecutionContext {
            self_address: addr(0xBEEF),
            ..Default::default()
        };
        let mut vm = Vm::with_context(ctx);
        // Write a value first
        vm.cpu.write_wide(0, U256::from(5u64));
        vm.cpu.write_wide(1, U256::from(999u64));
        let code = bytecode(&[
            instr_bytes(Opcode::Sstore, 1, 0, 0),  // storage[w0] = w1
            instr_bytes(Opcode::Sdelete, 0, 0, 0), // delete storage[w0]
            instr_bytes(Opcode::Sload, 2, 0, 0),   // w2 = storage[w0] (should be 0)
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_wide(2), U256::ZERO);
        assert_eq!(vm.gas_refund, 1500);
    }

    #[test]
    fn sdelete_nonexistent_no_refund() {
        let mut vm = Vm::new();
        vm.cpu.write_wide(0, U256::from(99u64));
        let code = bytecode(&[
            instr_bytes(Opcode::Sdelete, 0, 0, 0), // delete nonexistent key
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.gas_refund, 0); // no refund for deleting nothing
    }

    #[test]
    fn storage_key_derivation_uses_contract_address() {
        // Same slot, different contract address → different derived key
        let ctx1 = ExecutionContext {
            self_address: addr(0xAAAA),
            ..Default::default()
        };
        let ctx2 = ExecutionContext {
            self_address: addr(0xBBBB),
            ..Default::default()
        };
        let mut vm1 = Vm::with_context(ctx1);
        let mut vm2 = Vm::with_context(ctx2);
        let slot = U256::from(1u64);
        let value = U256::from(42u64);

        // Write same slot+value to both VMs
        vm1.cpu.write_wide(0, slot);
        vm1.cpu.write_wide(1, value);
        vm2.cpu.write_wide(0, slot);
        vm2.cpu.write_wide(1, value);

        let code = bytecode(&[
            instr_bytes(Opcode::Sstore, 1, 0, 0),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm1.load(&code).unwrap();
        vm2.load(&code).unwrap();
        vm1.run().unwrap();
        vm2.run().unwrap();

        // Derived keys should differ
        let key1: Vec<_> = vm1.storage.keys().collect();
        let key2: Vec<_> = vm2.storage.keys().collect();
        assert_eq!(key1.len(), 1);
        assert_eq!(key2.len(), 1);
        assert_ne!(key1[0], key2[0]);
    }

    #[test]
    fn storage_gas_costs() {
        let mut vm = Vm::with_gas_limit(100_000);
        vm.cpu.write_wide(0, U256::from(1u64));
        vm.cpu.write_wide(1, U256::from(42u64));
        let code = bytecode(&[
            instr_bytes(Opcode::Sstore, 1, 0, 0),  // 3000 gas
            instr_bytes(Opcode::Sload, 2, 0, 0),   // 300 gas
            instr_bytes(Opcode::Sdelete, 0, 0, 0), // 700 gas
            instr_bytes(Opcode::Halt, 0, 0, 0),    // 2 gas
        ]);
        vm.load(&code).unwrap();
        vm.run().unwrap();
        // SSTORE=3000, SLOAD=300, SDELETE=700, HALT=2
        assert_eq!(vm.gas.total(), 3000 + 300 + 700 + 2);
    }

    #[test]
    fn sstoreb_sloadb_roundtrip() {
        // Store a 50-byte value via memory mode, load it back
        let heap = crate::memory::HEAP_START;
        let ctx = ExecutionContext {
            self_address: addr(0xBEEF),
            ..Default::default()
        };
        let mut vm = Vm::with_context(ctx);

        // Write 50 bytes of test data to heap memory
        let test_data: Vec<u8> = (0..50).collect();
        for (i, &b) in test_data.iter().enumerate() {
            vm.memory.store8(heap + i as u32, b).unwrap();
        }

        // w0 = slot key
        vm.cpu.write_wide(0, U256::from(7u64));
        // r1 = pointer to data, r2 = length
        vm.cpu.write_gp(1, heap as u64);
        vm.cpu.write_gp(2, 50);

        // sstoreb w0, r1, r2 → imm = 1 | (1 << 2) | (2 << 6) = 1 + 4 + 128 = 133
        // sloadb r3, w0, r4 where r4 = output pointer
        // r4 = heap + 100 (read into a different spot)
        vm.cpu.write_gp(4, (heap + 100) as u64);

        let code = bytecode(&[
            instr_bytes(Opcode::Sstore, 0, 0, 133), // sstoreb w0, r1, r2
            instr_bytes(Opcode::Sload, 3, 0, 1 | (4 << 2)), // sloadb r3, w0, r4
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);

        // r3 should have the length
        assert_eq!(vm.cpu.read_gp(3), 50);

        // Verify data at heap+100 matches original
        for i in 0..50u32 {
            let b = vm.memory.load8(heap + 100 + i).unwrap();
            assert_eq!(b, i as u8);
        }
    }

    #[test]
    fn sstore_register_then_sloadb_memory() {
        // Store via register mode (32 bytes), load back via memory mode
        let heap = crate::memory::HEAP_START;
        let mut vm = Vm::new();

        vm.cpu.write_wide(0, U256::from(1u64)); // slot
        vm.cpu.write_wide(1, U256::from(0xCAFEu64)); // value
        vm.cpu.write_gp(3, heap as u64); // output pointer

        let code = bytecode(&[
            instr_bytes(Opcode::Sstore, 1, 0, 0), // sstore w0, w1 (register mode)
            instr_bytes(Opcode::Sload, 2, 0, 1 | (3 << 2)), // sloadb r2, w0, r3
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);

        // Register mode stores 32 bytes
        assert_eq!(vm.cpu.read_gp(2), 32);
    }

    #[test]
    fn sstoreb_then_sload_register_truncates() {
        // Store >32 bytes via memory mode, load back via register mode (truncates to 32)
        let heap = crate::memory::HEAP_START;
        let mut vm = Vm::new();

        // Write 64 bytes of data
        for i in 0..64u32 {
            vm.memory.store8(heap + i, (i + 1) as u8).unwrap();
        }

        vm.cpu.write_wide(0, U256::from(1u64)); // slot
        vm.cpu.write_gp(1, heap as u64); // pointer
        vm.cpu.write_gp(2, 64); // length

        let code = bytecode(&[
            instr_bytes(Opcode::Sstore, 0, 0, 1 | (1 << 2) | (2 << 6)), // sstoreb w0, r1, r2
            instr_bytes(Opcode::Sload, 3, 0, 0),                        // sload w3, w0 (register)
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);

        // w3 should contain first 32 bytes only
        let loaded = vm.cpu.read_wide(3);
        let bytes = loaded.to_le_bytes();
        for i in 0..32 {
            assert_eq!(bytes[i], (i + 1) as u8);
        }
    }

    #[test]
    fn sstoreg_sloadg_roundtrip() {
        // Store a u64 via GP mode (8 bytes), load it back
        let mut vm = Vm::new();
        vm.cpu.write_wide(0, U256::from(3u64)); // slot
        vm.cpu.write_gp(1, 0xDEAD_BEEF_CAFE_BABEu64); // value

        let code = bytecode(&[
            instr_bytes(Opcode::Sstore, 1, 0, 2), // sstoreg w0, r1
            instr_bytes(Opcode::Sload, 2, 0, 2),  // sloadg r2, w0
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(2), 0xDEAD_BEEF_CAFE_BABEu64);
    }

    #[test]
    fn sstoreg_stores_only_8_bytes() {
        // Verify GP mode stores exactly 8 bytes, not 32
        let mut vm = Vm::new();
        vm.cpu.write_wide(0, U256::from(1u64)); // slot
        vm.cpu.write_gp(1, 42);

        let code = bytecode(&[
            instr_bytes(Opcode::Sstore, 1, 0, 2), // sstoreg w0, r1
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        vm.run().unwrap();

        let key = vm.derive_storage_key(U256::from(1u64));
        let stored = vm.storage.get(&key).unwrap();
        assert_eq!(stored.len(), 8); // exactly 8 bytes, not 32
    }

    #[test]
    fn sstoreg_then_sload_wide_zero_pads() {
        // Store 8 bytes via GP, load via wide register — should zero-pad to 32
        let mut vm = Vm::new();
        vm.cpu.write_wide(0, U256::from(1u64));
        vm.cpu.write_gp(1, 0xFF);

        let code = bytecode(&[
            instr_bytes(Opcode::Sstore, 1, 0, 2), // sstoreg w0, r1 (8 bytes)
            instr_bytes(Opcode::Sload, 2, 0, 0),  // sload w2, w0 (wide, zero-padded)
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        vm.run().unwrap();

        // Should get 0xFF in first byte, rest zeros
        assert_eq!(vm.cpu.read_wide(2), U256::from(0xFFu64));
    }

    // --- Event instruction tests ---

    /// Helper: build a LOG descriptor in memory.
    /// Returns the descriptor start address.
    fn setup_log_descriptor(vm: &mut Vm, base: u32, topics: &[U256], data: &[u8]) -> u32 {
        let mut offset = base;
        // Write topics (32 bytes each)
        for topic in topics {
            let bytes = topic.to_le_bytes();
            for (j, &b) in bytes.iter().enumerate() {
                vm.memory.store8(offset + j as u32, b).unwrap();
            }
            offset += 32;
        }
        // Write data to a separate region and store pointer + length
        let data_start = offset + 16; // after ptr+len fields
        vm.memory.store64(offset, data_start as u64).unwrap();
        vm.memory.store64(offset + 8, data.len() as u64).unwrap();
        for (i, &b) in data.iter().enumerate() {
            vm.memory.store8(data_start + i as u32, b).unwrap();
        }
        base
    }

    #[test]
    fn log_emits_event_with_topics_and_data() {
        let heap = crate::memory::HEAP_START;
        let ctx = ExecutionContext {
            self_address: addr(0xCAFE),
            ..Default::default()
        };
        let mut vm = Vm::with_context(ctx);

        let topic0 = U256::from(0xABCDu64);
        let topic1 = U256::from(0x1234u64);
        let data = b"hello";

        setup_log_descriptor(&mut vm, heap, &[topic0, topic1], data);
        vm.cpu.write_gp(1, heap as u64);

        let code = bytecode(&[
            instr_bytes(Opcode::Log, 0, 1, 2), // log r1, 2 (2 topics)
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);

        assert_eq!(vm.logs.len(), 1);
        let log = &vm.logs[0];
        assert_eq!(log.address, addr(0xCAFE));
        assert_eq!(log.topics.len(), 2);
        assert_eq!(log.topics[0], topic0);
        assert_eq!(log.topics[1], topic1);
        assert_eq!(log.data, b"hello");
    }

    #[test]
    fn log_zero_topics() {
        let heap = crate::memory::HEAP_START;
        let mut vm = Vm::new();

        let data = b"event data";
        setup_log_descriptor(&mut vm, heap, &[], data);
        vm.cpu.write_gp(1, heap as u64);

        let code = bytecode(&[
            instr_bytes(Opcode::Log, 0, 1, 0), // log r1, 0
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);

        assert_eq!(vm.logs.len(), 1);
        assert!(vm.logs[0].topics.is_empty());
        assert_eq!(vm.logs[0].data, b"event data");
    }

    #[test]
    fn log_multiple_events() {
        let heap = crate::memory::HEAP_START;
        let mut vm = Vm::new();

        // First event at heap
        let topic_a = U256::from(1u64);
        setup_log_descriptor(&mut vm, heap, &[topic_a], b"first");
        vm.cpu.write_gp(1, heap as u64);

        // Second event at heap + 200
        let topic_b = U256::from(2u64);
        setup_log_descriptor(&mut vm, heap + 200, &[topic_b], b"second");
        vm.cpu.write_gp(2, (heap + 200) as u64);

        let code = bytecode(&[
            instr_bytes(Opcode::Log, 0, 1, 1), // log r1, 1
            instr_bytes(Opcode::Log, 0, 2, 1), // log r2, 1
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);

        assert_eq!(vm.logs.len(), 2);
        assert_eq!(vm.logs[0].topics[0], U256::from(1u64));
        assert_eq!(vm.logs[0].data, b"first");
        assert_eq!(vm.logs[1].topics[0], U256::from(2u64));
        assert_eq!(vm.logs[1].data, b"second");
    }

    #[test]
    fn log_dynamic_gas_cost() {
        let heap = crate::memory::HEAP_START;
        let mut vm = Vm::with_gas_limit(100_000);

        // 3 topics, 10 bytes of data
        let topics = [U256::from(1u64), U256::from(2u64), U256::from(3u64)];
        setup_log_descriptor(&mut vm, heap, &topics, &[0u8; 10]);
        vm.cpu.write_gp(1, heap as u64);

        let code = bytecode(&[
            instr_bytes(Opcode::Log, 0, 1, 3), // log r1, 3
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        vm.run().unwrap();

        // Base ISA gas (50 exec + 25 prove = 75) + dynamic (100 + 10*8 + 3*50 = 330)
        // + HALT (2) = 407
        let log_gas = 75 + 100 + 80 + 150; // 405
        let halt_gas = 2;
        assert_eq!(vm.gas.total(), log_gas + halt_gas);
    }

    #[test]
    fn log_too_many_topics_fails() {
        let heap = crate::memory::HEAP_START;
        let mut vm = Vm::new();

        setup_log_descriptor(&mut vm, heap, &[], b"");
        vm.cpu.write_gp(1, heap as u64);

        let code = bytecode(&[
            instr_bytes(Opcode::Log, 0, 1, 5), // 5 topics — invalid
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        assert!(vm.run().is_err());
    }

    // --- Interpreter (execute) tests ---

    #[test]
    fn execute_simple_add() {
        // r1 = 10, r2 = 20, r3 = r1 + r2 → expect 30
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),
            instr_ri(Opcode::Addi, 2, 0, 20),
            instr_bytes(Opcode::Add, 3, 1, 2),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        let output = vm.execute();

        assert_eq!(output.outcome, Outcome::Success);
        assert_eq!(vm.cpu.read_gp(3), 30);
        assert!(!output.trace.is_empty());
        assert_eq!(output.trace.last().unwrap().opcode, Opcode::Halt);
    }

    #[test]
    fn execute_fibonacci() {
        // Compute fib(10) = 55 using a loop
        // r1 = n (10), r2 = fib(i-1), r3 = fib(i), r4 = counter, r5 = temp
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10), // [0] r1 = 10
            instr_ri(Opcode::Addi, 2, 0, 0),  // [4] r2 = 0 (fib_prev)
            instr_ri(Opcode::Addi, 3, 0, 1),  // [8] r3 = 1 (fib_curr)
            instr_ri(Opcode::Addi, 4, 0, 1),  // [12] r4 = 1 (counter)
            // loop:
            instr_bytes(Opcode::Bge, 4, 1, 24), // [16] if r4 >= r1, jump +24 → pc 40 (halt)
            instr_bytes(Opcode::Add, 5, 2, 3),  // [20] r5 = r2 + r3
            instr_bytes(Opcode::Add, 2, 3, 0),  // [24] r2 = r3 (move via add r3+r0)
            instr_bytes(Opcode::Add, 3, 5, 0),  // [28] r3 = r5
            instr_ri(Opcode::Addi, 4, 4, 1),    // [32] r4++
            instr_ri(Opcode::Jmp, 0, 0, -20),   // [36] jmp -20 → pc 16 (loop)
            instr_bytes(Opcode::Halt, 0, 0, 0), // [40]
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        let output = vm.execute();

        assert_eq!(output.outcome, Outcome::Success);
        assert_eq!(vm.cpu.read_gp(3), 55);
        assert!(output.trace.len() > 10); // looped multiple times
    }

    #[test]
    fn execute_revert_rolls_back_storage() {
        let ctx = ExecutionContext {
            self_address: addr(0xBEEF),
            ..Default::default()
        };
        let mut vm = Vm::with_context(ctx);

        // Pre-populate storage with a value
        let slot = U256::from(1u64);
        let key = vm.derive_storage_key(slot);
        vm.storage.insert(key, vec![42]);

        // Program: overwrite storage then revert
        vm.cpu.write_wide(0, slot);
        vm.cpu.write_wide(1, U256::from(999u64));

        let code = bytecode(&[
            instr_bytes(Opcode::Sstore, 1, 0, 0), // storage[w0] = w1 (overwrite)
            instr_bytes(Opcode::Revert, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        let output = vm.execute();

        assert_eq!(output.outcome, Outcome::Revert);
        // Storage should be rolled back to original value
        assert_eq!(vm.storage.get(&key).unwrap(), &vec![42u8]);
        // Logs should be empty
        assert!(output.logs.is_empty());
    }

    #[test]
    fn execute_revert_rolls_back_logs() {
        let heap = crate::memory::HEAP_START;
        let mut vm = Vm::new();

        // Set up a log descriptor
        setup_log_descriptor(&mut vm, heap, &[U256::from(1u64)], b"hello");
        vm.cpu.write_gp(1, heap as u64);

        let code = bytecode(&[
            instr_bytes(Opcode::Log, 0, 1, 1), // emit event
            instr_bytes(Opcode::Revert, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        let output = vm.execute();

        assert_eq!(output.outcome, Outcome::Revert);
        assert!(output.logs.is_empty());
        assert!(vm.logs.is_empty()); // rolled back
    }

    #[test]
    fn execute_out_of_gas_rolls_back() {
        let ctx = ExecutionContext {
            self_address: addr(0xBEEF),
            ..Default::default()
        };
        let mut vm = Vm::with_gas_limit_and_context(10, ctx); // very tight gas limit

        let slot = U256::from(1u64);
        let key = vm.derive_storage_key(slot);
        vm.storage.insert(key, vec![42]);

        vm.cpu.write_wide(0, slot);
        vm.cpu.write_wide(1, U256::from(999u64));

        let code = bytecode(&[
            instr_bytes(Opcode::Sstore, 1, 0, 0), // 3000 gas — will exceed limit
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        let output = vm.execute();

        assert_eq!(output.outcome, Outcome::OutOfGas);
        // Storage should be rolled back
        assert_eq!(vm.storage.get(&key).unwrap(), &vec![42u8]);
    }

    #[test]
    fn execute_token_transfer() {
        // Simulate: read balance from slot 0, check >= amount, deduct, write new balance
        // r1 = amount to transfer (100)
        // w0 = slot 0 (sender balance)
        // w1 = loaded balance
        let ctx = ExecutionContext {
            self_address: addr(0xAAAA),
            ..Default::default()
        };
        let mut vm = Vm::with_context(ctx);

        // Pre-populate sender balance = 500
        let slot = U256::from(0u64);
        let key = vm.derive_storage_key(slot);
        vm.storage.insert(key, 500u64.to_le_bytes().to_vec());

        vm.cpu.write_wide(0, slot); // w0 = slot

        let code = bytecode(&[
            instr_bytes(Opcode::Sload, 1, 0, 2), // [0] sloadg r1, w0 (balance → r1)
            instr_ri(Opcode::Addi, 2, 0, 100),   // [4] r2 = 100 (amount)
            instr_bytes(Opcode::Blt, 1, 2, 16),  // [8] if r1 < r2, jump to revert (pc 24)
            instr_bytes(Opcode::Sub, 1, 1, 2),   // [12] r1 = r1 - amount
            instr_bytes(Opcode::Sstore, 1, 0, 2), // [16] sstoreg w0, r1 (write new balance)
            instr_bytes(Opcode::Halt, 0, 0, 0),  // [20]
            instr_bytes(Opcode::Revert, 0, 0, 0), // [24] insufficient balance
        ]);
        vm.load(&code).unwrap();
        let output = vm.execute();

        assert_eq!(output.outcome, Outcome::Success);
        // Balance should be 400
        let stored = vm.storage.get(&key).unwrap();
        let balance = u64::from_le_bytes(stored[..8].try_into().unwrap());
        assert_eq!(balance, 400);
    }

    #[test]
    fn execute_token_transfer_insufficient_reverts() {
        let ctx = ExecutionContext {
            self_address: addr(0xAAAA),
            ..Default::default()
        };
        let mut vm = Vm::with_context(ctx);

        // Sender balance = 50, try to transfer 100
        let slot = U256::from(0u64);
        let key = vm.derive_storage_key(slot);
        vm.storage.insert(key, 50u64.to_le_bytes().to_vec());

        vm.cpu.write_wide(0, slot);

        let code = bytecode(&[
            instr_bytes(Opcode::Sload, 1, 0, 2), // sloadg r1, w0
            instr_ri(Opcode::Addi, 2, 0, 100),   // r2 = 100
            instr_bytes(Opcode::Blt, 1, 2, 16),  // if r1 < r2, jump to revert
            instr_bytes(Opcode::Sub, 1, 1, 2),
            instr_bytes(Opcode::Sstore, 1, 0, 2),
            instr_bytes(Opcode::Halt, 0, 0, 0),
            instr_bytes(Opcode::Revert, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        let output = vm.execute();

        assert_eq!(output.outcome, Outcome::Revert);
        // Balance should be unchanged (rolled back)
        let stored = vm.storage.get(&key).unwrap();
        let balance = u64::from_le_bytes(stored[..8].try_into().unwrap());
        assert_eq!(balance, 50);
    }

    #[test]
    fn execute_trace_records_all_steps() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 5),
            instr_ri(Opcode::Addi, 2, 0, 10),
            instr_bytes(Opcode::Add, 3, 1, 2),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        let output = vm.execute();

        assert_eq!(output.outcome, Outcome::Success);
        assert_eq!(output.trace.len(), 4);
        assert_eq!(output.trace[0].opcode, Opcode::Addi);
        assert_eq!(output.trace[0].pc, 0);
        assert_eq!(output.trace[1].pc, 4);
        assert_eq!(output.trace[2].opcode, Opcode::Add);
        assert_eq!(output.trace[3].opcode, Opcode::Halt);
        // Gas should be monotonically increasing
        for w in output.trace.windows(2) {
            assert!(w[1].gas_used >= w[0].gas_used);
        }
    }

    #[test]
    fn execute_success_preserves_storage_and_logs() {
        let heap = crate::memory::HEAP_START;
        let ctx = ExecutionContext {
            self_address: addr(0xBEEF),
            ..Default::default()
        };
        let mut vm = Vm::with_context(ctx);

        // Set up storage write and log emission
        vm.cpu.write_wide(0, U256::from(1u64));
        vm.cpu.write_wide(1, U256::from(42u64));
        setup_log_descriptor(&mut vm, heap, &[U256::from(0xABu64)], b"ok");
        vm.cpu.write_gp(3, heap as u64);

        let code = bytecode(&[
            instr_bytes(Opcode::Sstore, 1, 0, 0), // write storage
            instr_bytes(Opcode::Log, 0, 3, 1),    // emit log
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        let output = vm.execute();

        assert_eq!(output.outcome, Outcome::Success);
        // Storage should be preserved (not rolled back)
        let key = vm.derive_storage_key(U256::from(1u64));
        assert!(vm.storage.contains_key(&key));
        // Logs should be present
        assert_eq!(output.logs.len(), 1);
        assert_eq!(output.logs[0].data, b"ok");
        assert_eq!(vm.logs.len(), 1);
    }

    // --- M1.13: Contract Call Instruction tests ---

    /// Helper: create a VM with a contract registry containing the given contracts.
    fn vm_with_contracts(contracts: Vec<(Address, Vec<u8>)>) -> Vm {
        let mut vm = Vm::new();
        for (a, code) in contracts {
            vm.contracts.insert(a, code);
        }
        vm
    }

    // ========== Task 0202: Cross-contract call with value transfer ==========

    #[test]
    fn ext_call_basic() {
        // Caller contract at 0xAAA calls callee contract at 0xBBB
        // Callee: ADDI r1, r0, 42; HALT
        let callee_code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        // Caller: target address in w0, calldata in r2, len in r3, gas in r4
        // CallExt wd=0, rs1=2, imm = (result_reg=1 << 8) | (gas_reg=4 << 4) | len_reg=3
        let caller_code = bytecode(&[
            instr_ri(Opcode::Addi, 3, 0, 0),           // r3 = calldata len = 0
            instr_ri(Opcode::Addi, 4, 0, 0),           // r4 = gas = 0 (all)
            instr_bytes(Opcode::CallExt, 0, 2, 0x143), // call_ext w0, r2, (r1<<8|r4<<4|r3)
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let ctx = ExecutionContext {
            self_address: addr(0xAAA),
            ..Default::default()
        };
        let mut vm = Vm::with_context(ctx);
        vm.cpu.write_wide(0, U256::from_le_bytes(addr(0xBBB)));
        vm.contracts.insert(addr(0xBBB), callee_code);
        vm.load(&caller_code).unwrap();
        let output = vm.execute();

        assert_eq!(output.outcome, Outcome::Success);
        assert_eq!(vm.cpu.read_gp(1), 1); // call succeeded
    }

    // ========== Task 0203: Reentrancy guard blocks re-entrant call ==========

    #[test]
    fn ext_call_reentrancy_blocked() {
        // B's code: load addr A into w0, call A (reentrancy!)
        let code_b = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 0xAA),
            instr_bytes(Opcode::Widen, 0, 1, 0), // w0 = addr(0xAA)
            instr_ri(Opcode::Addi, 3, 0, 0),
            instr_ri(Opcode::Addi, 4, 0, 0),
            instr_bytes(Opcode::CallExt, 0, 2, 0x143), // result→r1
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        // A's code: load addr B into w0, call B
        let code_a = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 0xBB),
            instr_bytes(Opcode::Widen, 0, 1, 0), // w0 = addr(0xBB)
            instr_ri(Opcode::Addi, 3, 0, 0),
            instr_ri(Opcode::Addi, 4, 0, 0),
            instr_bytes(Opcode::CallExt, 0, 2, 0x143), // result→r1
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let ctx = ExecutionContext {
            self_address: addr(0xAA),
            ..Default::default()
        };
        let mut vm = Vm::with_context(ctx);
        vm.contracts.insert(addr(0xAA), code_a.clone());
        vm.contracts.insert(addr(0xBB), code_b);
        vm.load(&code_a).unwrap();
        let output = vm.execute();

        assert_eq!(output.outcome, Outcome::Success);
        assert_eq!(vm.cpu.read_gp(1), 1);
    }

    // ========== Task 0205: STATICCALL reverts on state modification ==========

    #[test]
    fn staticcall_reverts_on_sstore() {
        let callee_code = bytecode(&[
            instr_bytes(Opcode::Sstore, 0, 0, 0),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        // imm = (result_reg=1 << 8) | (static=1 << 12) | (gas_reg=4 << 4) | len_reg=3
        // But we need static bit — with new encoding, static is imm[12]
        // For simplicity, pre-load w0 with target and set static_mode on caller
        let caller_code = bytecode(&[
            instr_ri(Opcode::Addi, 3, 0, 0),
            instr_ri(Opcode::Addi, 4, 0, 0),
            instr_bytes(Opcode::CallExt, 0, 2, 0x1143), // result→r1, static bit[12]=1
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let ctx = ExecutionContext {
            self_address: addr(0xDD),
            ..Default::default()
        };
        let mut vm = Vm::with_context(ctx);
        vm.cpu.write_wide(0, U256::from_le_bytes(addr(0xCC)));
        vm.contracts.insert(addr(0xCC), callee_code);
        vm.load(&caller_code).unwrap();
        let output = vm.execute();

        assert_eq!(output.outcome, Outcome::Success);
        assert_eq!(vm.cpu.read_gp(1), 0);
    }

    // ========== Task 0206: Nested calls (A calls B calls C) ==========

    #[test]
    fn nested_ext_calls_three_deep() {
        // C: just halts
        let code_c = bytecode(&[instr_bytes(Opcode::Halt, 0, 0, 0)]);

        // B: calls C, then halts
        let code_b = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 0x30),
            instr_bytes(Opcode::Widen, 0, 1, 0), // w0 = addr(0x30)
            instr_ri(Opcode::Addi, 3, 0, 0),
            instr_ri(Opcode::Addi, 4, 0, 0),
            instr_bytes(Opcode::CallExt, 0, 2, 0x143), // result→r1
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let code_a = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 0x20),
            instr_bytes(Opcode::Widen, 0, 1, 0), // w0 = addr(0x20)
            instr_ri(Opcode::Addi, 3, 0, 0),
            instr_ri(Opcode::Addi, 4, 0, 0),
            instr_bytes(Opcode::CallExt, 0, 2, 0x143), // result→r1
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let ctx = ExecutionContext {
            self_address: addr(0x10),
            ..Default::default()
        };
        let mut vm = Vm::with_context(ctx);
        vm.contracts.insert(addr(0x20), code_b);
        vm.contracts.insert(addr(0x30), code_c);
        vm.load(&code_a).unwrap();
        let output = vm.execute();

        assert_eq!(output.outcome, Outcome::Success);
        assert_eq!(vm.cpu.read_gp(1), 1); // B→C succeeded
    }

    // ========== Task 0207: Call with insufficient gas → revert child only ==========

    #[test]
    fn ext_call_child_oog_parent_continues() {
        // Callee: expensive loop that will run out of gas
        let callee_code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 1000),
            instr_ri(Opcode::Addi, 2, 0, 0),
            instr_bytes(Opcode::Add, 3, 1, 2), // loop body
            instr_ri(Opcode::Addi, 2, 2, 1),
            instr_ri(Opcode::Blt, 2, 1, -12),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let caller_code = bytecode(&[
            instr_ri(Opcode::Addi, 3, 0, 0),
            instr_ri(Opcode::Addi, 4, 0, 10), // only 10 gas forwarded
            instr_bytes(Opcode::CallExt, 0, 2, 0x143), // result→r1
            instr_ri(Opcode::Addi, 5, 0, 99), // parent continues
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let ctx = ExecutionContext {
            self_address: addr(0xFF),
            ..Default::default()
        };
        let mut vm = Vm::with_context(ctx);
        vm.cpu.write_wide(0, U256::from_le_bytes(addr(0xEE)));
        vm.contracts.insert(addr(0xEE), callee_code);
        vm.load(&caller_code).unwrap();
        let output = vm.execute();

        assert_eq!(output.outcome, Outcome::Success);
        assert_eq!(vm.cpu.read_gp(1), 0); // child failed (OOG)
        assert_eq!(vm.cpu.read_gp(5), 99); // parent continued
    }

    // ========== Task 0208: CREATE deploys and returns correct address ==========

    #[test]
    fn create_deploys_contract() {
        let heap = crate::memory::HEAP_START;

        // Init code to deploy: ADDI r1, r0, 77; HALT
        let init_code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 77),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let ctx = ExecutionContext {
            self_address: addr(0x1234),
            ..Default::default()
        };
        let mut vm = Vm::with_context(ctx);

        // Write init code to memory
        for (i, &b) in init_code.iter().enumerate() {
            vm.memory.store8(heap + i as u32, b).unwrap();
        }
        vm.cpu.write_gp(2, heap as u64); // r2 = code ptr
        vm.cpu.write_gp(3, init_code.len() as u64); // r3 = code len

        // CREATE wd=1, rs1=2, imm = len_reg=3 → 0x03
        // Result address written to wide register w1
        let caller_code = bytecode(&[
            instr_bytes(Opcode::Create, 1, 2, 0x03),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&caller_code).unwrap();
        let output = vm.execute();

        assert_eq!(output.outcome, Outcome::Success);
        let new_addr: Address = vm.cpu.read_wide(1).to_le_bytes();
        assert_ne!(new_addr, ZERO_ADDRESS);
        // Contract should be registered
        assert!(vm.contracts.contains_key(&new_addr));
        assert_eq!(vm.contracts[&new_addr], init_code);
    }

    // ========== Task 0238: CREATE2 address is deterministic ==========

    #[test]
    fn create_address_is_deterministic() {
        let heap = crate::memory::HEAP_START;
        let init_code = bytecode(&[instr_bytes(Opcode::Halt, 0, 0, 0)]);

        // Run CREATE twice with same inputs → should get same address
        let mut addrs = Vec::new();
        for _ in 0..2 {
            let ctx = ExecutionContext {
                self_address: addr(0x5678),
                ..Default::default()
            };
            let mut vm = Vm::with_context(ctx);
            for (i, &b) in init_code.iter().enumerate() {
                vm.memory.store8(heap + i as u32, b).unwrap();
            }
            vm.cpu.write_gp(2, heap as u64);
            vm.cpu.write_gp(3, init_code.len() as u64);

            let code = bytecode(&[
                instr_bytes(Opcode::Create, 1, 2, 0x03),
                instr_bytes(Opcode::Halt, 0, 0, 0),
            ]);
            vm.load(&code).unwrap();
            vm.execute();
            let new_addr: Address = vm.cpu.read_wide(1).to_le_bytes();
            addrs.push(new_addr);
        }

        assert_eq!(addrs[0], addrs[1]);
        assert_ne!(addrs[0], ZERO_ADDRESS);
    }

    // --- Memory-mapped calldata tests ---

    #[test]
    fn calldata_mapped_to_heap_start() {
        let heap = crate::memory::HEAP_START;
        let mut vm = Vm::new();
        vm.calldata = b"hello world".to_vec();

        let code = bytecode(&[instr_bytes(Opcode::Halt, 0, 0, 0)]);
        vm.load(&code).unwrap();

        // r4 = calldata length
        assert_eq!(vm.cpu.read_gp(4), 11);
        // r5 = calldata pointer (HEAP_START)
        assert_eq!(vm.cpu.read_gp(5), heap as u64);

        // Read calldata from memory
        assert_eq!(vm.memory.load8(heap).unwrap(), b'h');
        assert_eq!(vm.memory.load8(heap + 1).unwrap(), b'e');
        assert_eq!(vm.memory.load8(heap + 10).unwrap(), b'd');
    }

    #[test]
    fn calldata_heap_advanced_past_data() {
        let heap = crate::memory::HEAP_START;
        let mut vm = Vm::new();
        vm.calldata = vec![0xAB; 13]; // 13 bytes, aligned to 16

        let code = bytecode(&[instr_bytes(Opcode::Halt, 0, 0, 0)]);
        vm.load(&code).unwrap();

        // heap_top should be past calldata, aligned to 8
        assert_eq!(vm.memory.heap_top, heap + 16); // 13 → aligned to 16
    }

    #[test]
    fn calldata_readable_via_load_instruction() {
        let heap = crate::memory::HEAP_START;
        let mut vm = Vm::new();
        // Calldata: 8 bytes representing u64 value 42
        vm.calldata = 42u64.to_le_bytes().to_vec();

        // Load calldata[0..8] into r1 via LOAD64
        // r5 already points to HEAP_START after map_calldata
        let code = bytecode(&[
            instr_mem(Opcode::Load, 1, 5, 0, MemWidth::W64), // r1 = mem[r5 + 0]
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        vm.run().unwrap();

        assert_eq!(vm.cpu.read_gp(1), 42);
    }

    #[test]
    fn calldata_multiple_args() {
        let mut vm = Vm::new();
        // Calldata: two u64 values: 100 and 200
        let mut cd = Vec::new();
        cd.extend_from_slice(&100u64.to_le_bytes());
        cd.extend_from_slice(&200u64.to_le_bytes());
        vm.calldata = cd;

        let code = bytecode(&[
            instr_mem(Opcode::Load, 1, 5, 0, MemWidth::W64), // r1 = arg0 = 100
            instr_mem(Opcode::Load, 2, 5, 8, MemWidth::W64), // r2 = arg1 = 200
            instr_bytes(Opcode::Add, 3, 1, 2),               // r3 = 100 + 200
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        vm.load(&code).unwrap();
        vm.run().unwrap();

        assert_eq!(vm.cpu.read_gp(1), 100);
        assert_eq!(vm.cpu.read_gp(2), 200);
        assert_eq!(vm.cpu.read_gp(3), 300);
    }

    #[test]
    fn empty_calldata_no_effect() {
        let heap = crate::memory::HEAP_START;
        let mut vm = Vm::new();
        // No calldata

        let code = bytecode(&[instr_bytes(Opcode::Halt, 0, 0, 0)]);
        vm.load(&code).unwrap();

        assert_eq!(vm.cpu.read_gp(4), 0); // no calldata length
        assert_eq!(vm.memory.heap_top, heap); // heap not advanced
    }

    #[test]
    fn calldata_in_cross_contract_call() {
        let heap = crate::memory::HEAP_START;

        // Callee reads first arg from calldata (r5 = calldata ptr set by map_calldata)
        let callee_code = bytecode(&[
            instr_mem(Opcode::Load, 1, 5, 0, MemWidth::W64), // r1 = calldata[0]
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        // Caller: write arg (99) to its own heap, then call with it as calldata
        // Caller has no calldata, so r5 is 0. Use r8 = HEAP_START instead.
        let caller_code = bytecode(&[
            instr_ri(Opcode::Addi, 8, 0, heap as i32), // r8 = HEAP_START
            instr_ri(Opcode::Addi, 6, 0, 99),          // r6 = 99
            instr_mem(Opcode::Store, 6, 8, 0, MemWidth::W64), // mem[HEAP_START] = 99
            instr_ri(Opcode::Addi, 3, 0, 8),           // r3 = calldata len = 8
            instr_ri(Opcode::Addi, 7, 0, 0),           // r7 = gas = 0 (all)
            instr_bytes(Opcode::CallExt, 0, 8, 0x173), // call w0, r8, (result=1,gas=7,len=3)
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let ctx = ExecutionContext {
            self_address: addr(0xAA),
            ..Default::default()
        };
        let mut vm = Vm::with_context(ctx);
        vm.cpu.write_wide(0, U256::from_le_bytes(addr(0xBB)));
        vm.contracts.insert(addr(0xBB), callee_code);
        vm.load(&caller_code).unwrap();
        let output = vm.execute();

        assert_eq!(output.outcome, Outcome::Success);
        assert_eq!(vm.cpu.read_gp(1), 1); // call succeeded
    }
}
