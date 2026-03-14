//! PVM execution engine: ties CPU, memory, and control flow together.

use crate::cpu::{Cpu, Trap};
use crate::isa::{decode, decode_mem_offset, decode_mem_width, sign_extend_18, Instruction, MemWidth, Opcode};
use crate::wide::U256;
use crate::memory::Memory;

/// Maximum call depth (nested function calls).
const MAX_CALL_DEPTH: usize = 1024;

/// A saved call frame on the call stack.
#[derive(Clone, Copy, Debug)]
struct CallFrame {
    /// Return address (PC to resume after RET).
    return_addr: u32,
    /// Previous frame pointer.
    frame_pointer: u32,
}

/// Execution outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecResult {
    /// Execution completed successfully (HALT).
    Halt,
    /// Execution reverted (REVERT).
    Revert,
}

/// The full VM state.
pub struct Vm {
    pub cpu: Cpu,
    pub memory: Memory,
    /// Program counter (byte offset into code section).
    pub pc: u32,
    /// Call stack for CALL/RET.
    call_stack: Vec<CallFrame>,
    /// Frame pointer register.
    pub fp: u32,
    /// Total gas consumed.
    pub gas_used: u64,
}

impl Vm {
    pub fn new() -> Self {
        Self {
            cpu: Cpu::new(),
            memory: Memory::new(),
            pc: 0,
            call_stack: Vec::new(),
            fp: 0,
            gas_used: 0,
        }
    }

    /// Load bytecode and prepare for execution.
    pub fn load(&mut self, bytecode: &[u8]) -> Result<(), Trap> {
        self.memory.load_code(bytecode).map_err(|_| Trap::MemoryFault)?;
        self.pc = 0;
        Ok(())
    }

    /// Fetch the instruction at the current PC.
    fn fetch(&self) -> Result<Instruction, Trap> {
        let addr = crate::memory::CODE_START + self.pc;
        if self.pc + 4 > self.memory.code_end - crate::memory::CODE_START {
            return Err(Trap::InvalidOpcode);
        }
        let a = addr as usize;
        // Instructions are stored in little-endian
        let word = u32::from_le_bytes([
            self.memory.data_ref()[a],
            self.memory.data_ref()[a + 1],
            self.memory.data_ref()[a + 2],
            self.memory.data_ref()[a + 3],
        ]);
        Ok(Instruction(word))
    }

    /// Execute a single step. Returns Some(ExecResult) if execution finished.
    pub fn step(&mut self) -> Result<Option<ExecResult>, Trap> {
        let instr = self.fetch()?;
        let d = decode(instr);

        // Charge gas
        let cost = crate::isa::gas_cost(d.opcode);
        self.gas_used += cost.total() as u64;

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
            Opcode::Add | Opcode::Sub | Opcode::Mul | Opcode::Div | Opcode::Mod
            | Opcode::Addi | Opcode::And | Opcode::Or | Opcode::Xor | Opcode::Not
            | Opcode::Shl | Opcode::Shr | Opcode::Sar
            | Opcode::Lt | Opcode::Gt | Opcode::Eq | Opcode::Slt | Opcode::Sgt => {
                self.cpu.exec_alu(instr)?;
                self.pc += 4;
            }

            // --- Wide ops: delegate to cpu ---
            Opcode::Wadd | Opcode::Wsub | Opcode::Wmul | Opcode::Wdiv | Opcode::Wmod
            | Opcode::Wand | Opcode::Wor | Opcode::Wxor | Opcode::Wnot
            | Opcode::Wmov | Opcode::Narrow | Opcode::Widen
            | Opcode::Weq | Opcode::Wlt => {
                self.cpu.exec_wide(instr)?;
                self.pc += 4;
            }

            // --- Memory ops (width-encoded) ---
            Opcode::Load => {
                let base = self.cpu.read_gp(d.rs1);
                let offset = decode_mem_offset(d.rs2_or_imm) as i64;
                let width = decode_mem_width(d.rs2_or_imm);
                let addr = (base as i64 + offset) as u32;
                let val = match width {
                    MemWidth::W8 => self.memory.load8(addr).map_err(|_| Trap::MemoryFault)? as u64,
                    MemWidth::W16 => self.memory.load16(addr).map_err(|_| Trap::MemoryFault)? as u64,
                    MemWidth::W32 => self.memory.load32(addr).map_err(|_| Trap::MemoryFault)? as u64,
                    MemWidth::W64 => self.memory.load64(addr).map_err(|_| Trap::MemoryFault)?,
                };
                self.cpu.write_gp(d.rd, val);
                self.pc += 4;
            }
            Opcode::Store => {
                let base = self.cpu.read_gp(d.rs1);
                let offset = decode_mem_offset(d.rs2_or_imm) as i64;
                let width = decode_mem_width(d.rs2_or_imm);
                let addr = (base as i64 + offset) as u32;
                let val = self.cpu.read_gp(d.rd);
                match width {
                    MemWidth::W8 => self.memory.store8(addr, val as u8).map_err(|_| Trap::MemoryFault)?,
                    MemWidth::W16 => self.memory.store16(addr, val as u16).map_err(|_| Trap::MemoryFault)?,
                    MemWidth::W32 => self.memory.store32(addr, val as u32).map_err(|_| Trap::MemoryFault)?,
                    MemWidth::W64 => self.memory.store64(addr, val).map_err(|_| Trap::MemoryFault)?,
                };
                self.pc += 4;
            }
            Opcode::Wload => {
                let base = self.cpu.read_gp(d.rs1);
                let offset = sign_extend_18(d.rs2_or_imm) as i64;
                let addr = (base as i64 + offset) as u32;
                let bytes = self.memory.load256(addr).map_err(|_| Trap::MemoryFault)?;
                self.cpu.write_wide(d.rd, U256::from_le_bytes(bytes));
                self.pc += 4;
            }
            Opcode::Wstore => {
                let base = self.cpu.read_gp(d.rs1);
                let offset = sign_extend_18(d.rs2_or_imm) as i64;
                let addr = (base as i64 + offset) as u32;
                let val = self.cpu.read_wide(d.rd);
                self.memory.store256(addr, &val.to_le_bytes()).map_err(|_| Trap::MemoryFault)?;
                self.pc += 4;
            }
            Opcode::Push => {
                let val = self.cpu.read_gp(d.rd);
                self.memory.stack_pointer -= 8;
                self.memory.store64(self.memory.stack_pointer, val)
                    .map_err(|_| Trap::MemoryFault)?;
                self.pc += 4;
            }
            Opcode::Pop => {
                let val = self.memory.load64(self.memory.stack_pointer)
                    .map_err(|_| Trap::MemoryFault)?;
                self.cpu.write_gp(d.rd, val);
                self.memory.stack_pointer += 8;
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

    /// Current call depth.
    pub fn call_depth(&self) -> usize {
        self.call_stack.len()
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
        encode(op, rd, rs1, encode_mem_immediate(offset, width)).0.to_le_bytes()
    }

    /// Build bytecode from instruction byte arrays.
    fn bytecode(instrs: &[[u8; 4]]) -> Vec<u8> {
        instrs.iter().flat_map(|i| i.iter().copied()).collect()
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
            instr_ri(Opcode::Call, 0, 0, 8),     // [4]
            instr_bytes(Opcode::Halt, 0, 0, 0),  // [8]
            instr_ri(Opcode::Addi, 1, 1, 1),     // [12]
            instr_ri(Opcode::Call, 0, 0, 8),     // [16]
            instr_bytes(Opcode::Ret, 0, 0, 0),   // [20]
            instr_ri(Opcode::Addi, 1, 1, 1),     // [24]
            instr_ri(Opcode::Call, 0, 0, 8),     // [28]
            instr_bytes(Opcode::Ret, 0, 0, 0),   // [32]
            instr_ri(Opcode::Addi, 1, 1, 1),     // [36]
            instr_ri(Opcode::Call, 0, 0, 8),     // [40]
            instr_bytes(Opcode::Ret, 0, 0, 0),   // [44]
            instr_ri(Opcode::Addi, 1, 1, 1),     // [48]
            instr_ri(Opcode::Call, 0, 0, 8),     // [52]
            instr_bytes(Opcode::Ret, 0, 0, 0),   // [56]
            instr_ri(Opcode::Addi, 1, 1, 1),     // [60]
            instr_bytes(Opcode::Ret, 0, 0, 0),   // [64]
        ]);
        let mut vm = Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(1), 5);
    }

    // ========== Task 0162: RET with no CALL ==========

    #[test]
    fn ret_without_call_traps() {
        let code = bytecode(&[
            instr_bytes(Opcode::Ret, 0, 0, 0),
        ]);
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
        assert!(vm.gas_used > 0);
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
            instr_ri(Opcode::Addi, 1, 0, heap as i32),       // r1 = heap addr
            instr_ri(Opcode::Addi, 2, 0, 0xAB),              // r2 = 0xAB
            instr_mem(Opcode::Store, 2, 1, 0, MemWidth::W8), // store8(r1+0, r2)
            instr_mem(Opcode::Load, 3, 1, 0, MemWidth::W8),  // r3 = load8(r1+0)
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
            instr_ri(Opcode::Addi, 2, 0, 0x7FFF),            // small value that fits in imm
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
            instr_ri(Opcode::Addi, 1, 0, heap as i32),        // r1 = heap addr
            instr_ri(Opcode::Addi, 2, 0, (heap + 32) as i32), // r2 = heap+32
            instr_bytes(Opcode::Wload, 0, 1, 0),              // w0 = mem256[r1]
            instr_bytes(Opcode::Wstore, 0, 2, 0),             // mem256[r2] = w0
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
}
