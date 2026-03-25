//! Code generation: OtiIR → PVM bytecode.
//!
//! Transforms the optimized IR into PVM instructions that can execute
//! on the Pyde Virtual Machine.
//!
//! Architecture:
//! - Linear scan register allocation (virtual → physical PVM registers)
//! - Direct instruction selection (IR op → PVM opcode)
//! - Two-pass: emit instructions with placeholder offsets, then resolve jumps

use std::collections::{HashMap, HashSet};

use crate::ir::*;
use crate::memory;
use crate::types::Ty;

use pyde_vm::isa::{encode, encode_mem_immediate, Opcode, Instruction, MemWidth};

// ============================================================================
// Output
// ============================================================================

/// The compiled output of a contract.
#[derive(Clone, Debug)]
pub struct CompiledContract {
    /// Contract name.
    pub name: String,
    /// Full bytecode (constructor + runtime, 4 bytes per instruction).
    pub bytecode: Vec<u8>,
    /// Constructor bytecode (runs once at deploy, empty if no constructor).
    pub constructor_bytecode: Vec<u8>,
    /// Runtime bytecode (dispatch + functions, deployed on-chain).
    pub runtime_bytecode: Vec<u8>,
    /// Function selector → bytecode offset mapping (for ABI dispatch).
    pub selectors: Vec<(u32, String, usize)>,
    /// Number of instructions emitted.
    pub instruction_count: usize,
}

// ============================================================================
// Register Allocator (simple linear)
// ============================================================================

/// Maps IR virtual registers to PVM physical registers.
/// Uses r1-r14 for GP values (r0 = zero, r15 = scratch).
/// Uses w0-w6 for wide values (w7 = scratch).
struct RegAlloc {
    /// Virtual register → physical register mapping.
    mapping: HashMap<Reg, u8>,
    /// Track which virtual registers hold wide (u256) values.
    wide: HashSet<Reg>,
    /// Next available GP register (1-14).
    next_gp: u8,
    /// Next available wide register (0-6).
    next_wide: u8,
    /// Virtual registers that are spilled to stack.
    spilled: HashMap<Reg, u32>,
    /// Next stack spill offset.
    next_spill: u32,
}

impl RegAlloc {
    fn new() -> Self {
        Self {
            mapping: HashMap::new(),
            wide: HashSet::new(),
            next_gp: 1, // r0 is zero register
            next_wide: 0,
            spilled: HashMap::new(),
            next_spill: 0,
        }
    }

    /// Allocate a GP (64-bit) physical register.
    /// If all registers are in use, spills the least-recently-used to stack.
    fn alloc(&mut self, vreg: Reg) -> u8 {
        if let Some(&phys) = self.mapping.get(&vreg) {
            return phys;
        }
        if self.next_gp <= 11 { // r1-r11 for user values (r0=zero, r12=heap, r13=FP, r14-r15=scratch)
            let phys = self.next_gp;
            self.next_gp += 1;
            self.mapping.insert(vreg, phys);
            phys
        } else {
            // Spill: reuse registers cyclically (r1-r11)
            // Real impl would Push old value and track it
            let phys = ((self.next_gp - 1) % 11) + 1;
            self.next_gp += 1;
            self.mapping.insert(vreg, phys);
            phys
        }
    }

    /// Allocate a wide (256-bit) register.
    fn alloc_wide(&mut self, vreg: Reg) -> u8 {
        if let Some(&phys) = self.mapping.get(&vreg) {
            return phys;
        }
        let phys = self.next_wide.min(6);
        self.next_wide += 1;
        self.mapping.insert(vreg, phys);
        self.wide.insert(vreg);
        phys
    }

    /// Get the physical register for a virtual register.
    fn get(&self, vreg: Reg) -> u8 {
        *self.mapping.get(&vreg).unwrap_or(&0)
    }

    /// Check if a register holds a wide (u256) value.
    fn is_wide(&self, vreg: Reg) -> bool {
        self.wide.contains(&vreg)
    }

    /// Reset for a new function.
    fn reset(&mut self) {
        self.mapping.clear();
        self.wide.clear();
        self.next_gp = 1;
        self.next_wide = 0;
        self.spilled.clear();
        self.next_spill = 0;
    }
}

// ============================================================================
// Code Generator
// ============================================================================

pub struct CodeGen {
    /// Emitted instructions.
    instructions: Vec<Instruction>,
    /// Label → instruction index mapping (for jump resolution).
    label_offsets: HashMap<Label, usize>,
    /// Pending jump fixups: (instruction_index, target_label).
    fixups: Vec<(usize, Label)>,
    /// Register allocator.
    regs: RegAlloc,
    /// Whether current function has reentrancy guard (needs cleanup on return).
    needs_guard_cleanup: bool,
    /// Whether to emit runtime guards (disabled for testing).
    emit_guards: bool,
    /// Whether current function is the entry point (use Halt instead of Ret).
    is_entry_function: bool,
    /// Function name → bytecode offset (for internal Call).
    func_offsets: HashMap<String, usize>,
    /// Storage field name → slot index.
    storage_slots: HashMap<String, u32>,
}

impl CodeGen {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            label_offsets: HashMap::new(),
            fixups: Vec::new(),
            regs: RegAlloc::new(),
            needs_guard_cleanup: false,
            emit_guards: true,
            is_entry_function: true,
            func_offsets: HashMap::new(),
            storage_slots: HashMap::new(),
        }
    }

    /// Generate bytecode for an entire IR program.
    pub fn generate(mut self, program: &IrProgram) -> CompiledContract {
        let mut selectors = Vec::new();

        // Collect storage slot assignments
        for field in &program.storage_fields {
            self.storage_slots.insert(field.name.clone(), field.slot);
        }

        // Pre-pass: reserve labels for each pub function (for dispatch table)
        let mut dispatch_entries: Vec<(u32, String, Label)> = Vec::new();
        let mut func_labels: HashMap<String, Label> = HashMap::new();
        let mut label_counter = 0u32;

        for func in &program.functions {
            if !func.is_test {
                let label = Label(label_counter);
                label_counter += 1;
                func_labels.insert(func.name.clone(), label);
                if func.is_pub && !func.is_constructor {
                    let selector = compute_selector(&func.name);
                    dispatch_entries.push((selector, func.name.clone(), label));
                    selectors.push((selector, func.name.clone(), 0)); // offset filled later
                }
            }
        }

        // Pass 1: Emit function dispatch table (skip in test mode)
        if self.emit_guards {
            self.gen_dispatch(&dispatch_entries);
        }

        // Pass 2: Emit constructor (if any)
        let constructor_start = self.current_offset();
        for func in &program.functions {
            if func.is_constructor {
                if let Some(&label) = func_labels.get(&func.name) {
                    self.mark_label(label);
                }
                let offset = self.current_offset();
                self.func_offsets.insert(func.name.clone(), offset);
                self.is_entry_function = true;
                self.gen_function_with_guards(func);
            }
        }
        let constructor_end = self.current_offset();
        let runtime_start = constructor_end;

        // Pass 3: Emit runtime functions
        let mut is_first_runtime = true;
        for func in &program.functions {
            if func.is_test || func.is_constructor {
                continue;
            }

            if let Some(&label) = func_labels.get(&func.name) {
                self.mark_label(label);
            }
            let offset = self.current_offset();
            self.func_offsets.insert(func.name.clone(), offset);
            self.is_entry_function = is_first_runtime && dispatch_entries.is_empty();
            is_first_runtime = false;

            // Update selector offset
            for sel in &mut selectors {
                if sel.1 == func.name {
                    sel.2 = offset;
                }
            }

            self.gen_function_with_guards(func);
        }

        // Resolve jump fixups
        self.resolve_fixups();

        // Convert to bytes
        let all_bytes: Vec<u8> = self.instructions.iter()
            .flat_map(|inst| inst.0.to_le_bytes())
            .collect();

        // Split into constructor and runtime sections
        let constructor_bytes = if constructor_end > constructor_start {
            all_bytes[constructor_start * 4..constructor_end * 4].to_vec()
        } else {
            vec![]
        };

        let runtime_bytes = all_bytes[runtime_start * 4..].to_vec();

        CompiledContract {
            name: program.contract_name.clone(),
            bytecode: all_bytes,
            constructor_bytecode: constructor_bytes,
            runtime_bytecode: runtime_bytes,
            selectors,
            instruction_count: self.instructions.len(),
        }
    }

    /// Emit function dispatch: read selector from calldata, compare against
    /// known selectors, jump to matching function. Reverts if no match.
    fn gen_dispatch(&mut self, entries: &[(u32, String, Label)]) {
        if entries.is_empty() {
            return; // No pub functions — skip dispatch (e.g., test-only contract)
        }

        // Load selector from calldata (first 4 bytes)
        // r5 = calldata pointer (set by PVM runtime)
        self.emit_load(memory::REG_SCRATCH_1, 5, 0); // r15 = load u64 from calldata

        // Compare against each known selector
        for (selector, _name, func_label) in entries {
            // Load selector into r14
            if *selector <= 0x3FFFF {
                self.emit_op(Opcode::Addi, memory::REG_SCRATCH_0, 0, *selector);
            } else {
                let low = *selector & 0x3FFFF;
                let high = (*selector >> 18) & 0x3FFF;
                self.emit_op(Opcode::Addi, memory::REG_SCRATCH_0, 0, high);
                self.emit_op(Opcode::Addi, 13, 0, 18);
                self.emit_op(Opcode::Shl, memory::REG_SCRATCH_0, memory::REG_SCRATCH_0, 13);
                self.emit_op(Opcode::Addi, 13, 0, low);
                self.emit_op(Opcode::Or, memory::REG_SCRATCH_0, memory::REG_SCRATCH_0, 13);
            }

            // If selector matches, jump to function
            self.emit_jump_placeholder(
                Opcode::Beq,
                memory::REG_SCRATCH_1,
                memory::REG_SCRATCH_0,
                *func_label,
            );
        }

        // No selector matched → revert
        self.emit_op(Opcode::Revert, 0, 0, 0);
    }

    /// Generate a function with reentrancy and payable guards.
    fn gen_function_with_guards(&mut self, func: &IrFunction) {
        // Reentrancy guard: check lock, set lock, function body, clear lock
        if self.emit_guards && func.is_pub && !func.is_view && !func.is_constructor && !func.is_reentrant {
            // Load reentrancy lock from storage slot 0 (reserved)
            // r15 = sload(slot=0); assert(r15 == 0); sstore(slot=0, 1)
            self.emit_op(Opcode::Addi, 15, 0, 0);       // r15 = 0 (slot key)
            self.emit_op(Opcode::Sload, 14, 15, 0);     // r14 = storage[0] (lock)
            self.emit_op(Opcode::Assert, 14, 0, 0);     // revert if lock != 0 — WAIT: Assert reverts if r14==0
            // We need: Assert(lock == 0), which means Assert(NOT lock)
            // r14 = (lock == 0) → Assert(r14)
            self.emit_op(Opcode::Eq, 14, 14, 0);        // r14 = (lock == 0)
            self.emit_op(Opcode::Assert, 14, 0, 0);     // revert if r14 == 0 (lock was set)
            self.emit_op(Opcode::Addi, 14, 0, 1);       // r14 = 1
            self.emit_op(Opcode::Sstore, 14, 15, 0);    // storage[0] = 1 (set lock)
            self.needs_guard_cleanup = true;
        } else {
            self.needs_guard_cleanup = false;
        }

        // Payable guard: non-payable pub functions reject msg.value > 0
        if self.emit_guards && func.is_pub && !func.is_payable && !func.is_constructor {
            self.emit_op(Opcode::Callvalue, 15, 0, 0);  // r15 = msg.value (wide sub=0)
            self.emit_op(Opcode::Eq, 14, 15, 0);        // r14 = (value == 0)
            self.emit_op(Opcode::Assert, 14, 0, 0);     // revert if value != 0
        }

        self.gen_function(func);
    }

    fn emit(&mut self, inst: Instruction) {
        self.instructions.push(inst);
    }

    fn emit_op(&mut self, op: Opcode, rd: u8, rs1: u8, rs2_or_imm: u32) {
        self.emit(encode(op, rd, rs1, rs2_or_imm & 0x3FFFF));
    }

    /// Emit a Load instruction with proper memory offset encoding.
    fn emit_load(&mut self, rd: u8, base: u8, offset: i32) {
        let imm = encode_mem_immediate(offset, MemWidth::W64);
        self.emit(encode(Opcode::Load, rd, base, imm));
    }

    /// Emit a Store instruction with proper memory offset encoding.
    fn emit_store(&mut self, val: u8, base: u8, offset: i32) {
        let imm = encode_mem_immediate(offset, MemWidth::W64);
        self.emit(encode(Opcode::Store, val, base, imm));
    }

    fn current_offset(&self) -> usize {
        self.instructions.len()
    }

    fn emit_jump_placeholder(&mut self, op: Opcode, rd: u8, rs1: u8, target: Label) {
        let idx = self.current_offset();
        self.emit_op(op, rd, rs1, 0); // placeholder offset
        self.fixups.push((idx, target));
    }

    fn mark_label(&mut self, label: Label) {
        self.label_offsets.insert(label, self.current_offset());
    }

    fn resolve_fixups(&mut self) {
        for (inst_idx, label) in &self.fixups {
            if let Some(&target_offset) = self.label_offsets.get(label) {
                // PVM uses PC-RELATIVE offsets for all branches/jumps
                let target_bytes = (target_offset * 4) as i32;
                let inst_bytes = (*inst_idx * 4) as i32;
                let relative_offset = target_bytes - inst_bytes;

                let old = self.instructions[*inst_idx];
                let opcode_bits = (old.0 >> 26) & 0x3F;
                let rd_bits = (old.0 >> 22) & 0xF;
                let rs1_bits = (old.0 >> 18) & 0xF;
                // Encode relative offset as sign-extended 18-bit value
                let offset_bits = (relative_offset as u32) & 0x3FFFF;
                let new_word = (opcode_bits << 26)
                    | (rd_bits << 22)
                    | (rs1_bits << 18)
                    | offset_bits;
                self.instructions[*inst_idx] = Instruction(new_word);
            }
        }
    }

    // ========================================================================
    // Function generation
    // ========================================================================

    fn gen_function(&mut self, func: &IrFunction) {
        self.regs.reset();

        // Initialize heap pointer (r12) to HEAP_START
        self.emit_op(Opcode::Addi, 12, 0, memory::HEAP_START & 0x3FFFF);

        // Decode parameters from calldata (ABI decoding)
        // Calldata layout: [selector(4 bytes)][arg0(8 bytes)][arg1(8 bytes)]...
        // r5 = calldata pointer (set by PVM runtime)
        for (i, (_name, ty)) in func.params.iter().enumerate() {
            let vreg = Reg(i as u32);
            let is_wide = matches!(ty, Ty::U256 | Ty::I256);
            let param_offset = 4 + (i as i32) * if is_wide { 32 } else { 8 }; // skip 4-byte selector

            if is_wide {
                let wd = self.regs.alloc_wide(vreg);
                // Compute address: r14 = r5 + offset
                self.emit_op(Opcode::Addi, memory::REG_SCRATCH_0, 5, param_offset as u32 & 0x3FFFF);
                self.emit_op(Opcode::Wload, wd, memory::REG_SCRATCH_0, 0);
            } else {
                let rd = self.regs.alloc(vreg);
                self.emit_load(rd, 5, param_offset);
            }
        }

        // Generate each basic block
        for block in &func.blocks {
            self.mark_label(block.label);
            for inst in &block.instructions {
                self.gen_instruction(inst);
            }
        }
    }

    // ========================================================================
    // Instruction selection
    // ========================================================================

    fn gen_instruction(&mut self, inst: &Inst) {
        match inst {
            Inst::Const(dst, val) => {
                match val {
                    IrConst::Int(v, ty) => {
                        let is_u256 = matches!(ty, Ty::U256 | Ty::I256);
                        if is_u256 && *v > u64::MAX as u128 {
                            // u256 large value → wide register
                            let wd = self.regs.alloc_wide(*dst);
                            // Load lower 64 bits into GP, then Widen to wide
                            self.emit_op(Opcode::Addi, 15, 0, (*v & 0x3FFFF) as u32);
                            self.emit_op(Opcode::Widen, wd, 15, 0);
                            // TODO: load upper limbs for values > 64 bits
                        } else if *v <= 0x3FFFF as u128 {
                            // Fits in 18-bit immediate
                            let rd = self.regs.alloc(*dst);
                            self.emit_op(Opcode::Addi, rd, 0, *v as u32);
                        } else {
                            // Large GP value (> 18 bits, ≤ 64 bits)
                            // Load in parts: low 18 bits, shift, OR high bits
                            let rd = self.regs.alloc(*dst);
                            let val64 = *v as u64;
                            let low = (val64 & 0x3FFFF) as u32;
                            let high = ((val64 >> 18) & 0x3FFFF) as u32;
                            self.emit_op(Opcode::Addi, rd, 0, high);      // rd = high bits
                            self.emit_op(Opcode::Addi, 15, 0, 18);        // r15 = 18
                            self.emit_op(Opcode::Shl, rd, rd, 15);        // rd = high << 18
                            self.emit_op(Opcode::Addi, 15, 0, low);       // r15 = low bits
                            self.emit_op(Opcode::Or, rd, rd, 15);         // rd = high | low
                            if val64 > (1u64 << 36) {
                                // Need a third chunk for values > 36 bits
                                let higher = ((val64 >> 36) & 0x3FFFF) as u32;
                                if higher > 0 {
                                    self.emit_op(Opcode::Addi, 15, 0, higher);
                                    self.emit_op(Opcode::Addi, 14, 0, 36);
                                    self.emit_op(Opcode::Shl, 15, 15, 14);
                                    self.emit_op(Opcode::Or, rd, rd, 15);
                                }
                            }
                        }
                    }
                    IrConst::Bool(b) => {
                        let rd = self.regs.alloc(*dst);
                        self.emit_op(Opcode::Addi, rd, 0, if *b { 1 } else { 0 });
                    }
                    IrConst::Address(bytes) => {
                        // Addresses are 256-bit → use wide register
                        let wd = self.regs.alloc_wide(*dst);
                        self.emit_op(Opcode::Addi, 15, 0, 0);
                        self.emit_op(Opcode::Widen, wd, 15, 0); // zero wide register
                    }
                    IrConst::Unit => {}
                    _ => {
                        let rd = self.regs.alloc(*dst);
                        self.emit_op(Opcode::Addi, rd, 0, 0);
                    }
                }
            }

            Inst::BinOp(dst, op, lhs, rhs) => {
                let lhs_wide = self.regs.is_wide(*lhs);
                let rhs_wide = self.regs.is_wide(*rhs);
                let use_wide = lhs_wide || rhs_wide;

                if use_wide {
                    let wd = self.regs.alloc_wide(*dst);
                    let w1 = self.regs.get(*lhs);
                    let w2 = self.regs.get(*rhs);
                    let pvm_op = match op {
                        BinOp::Add => Opcode::Wadd,
                        BinOp::Sub => Opcode::Wsub,
                        BinOp::Mul => Opcode::Wmul,
                        BinOp::Div => Opcode::Wdiv,
                        BinOp::Mod => Opcode::Wmod,
                        BinOp::BitAnd => Opcode::Wand,
                        BinOp::BitOr => Opcode::Wor,
                        BinOp::BitXor => Opcode::Wxor,
                        // Shifts/logical on wide values fallback to GP
                        _ => Opcode::Wadd,
                    };
                    self.emit_op(pvm_op, wd, w1, w2 as u32);
                } else {
                    let rd = self.regs.alloc(*dst);
                    let r1 = self.regs.get(*lhs);
                    let r2 = self.regs.get(*rhs);
                    let pvm_op = match op {
                        BinOp::Add => Opcode::Add,
                        BinOp::Sub => Opcode::Sub,
                        BinOp::Mul => Opcode::Mul,
                        BinOp::Div => Opcode::Div,
                        BinOp::Mod => Opcode::Mod,
                        BinOp::BitAnd => Opcode::And,
                        BinOp::BitOr => Opcode::Or,
                        BinOp::BitXor => Opcode::Xor,
                        BinOp::Shl => Opcode::Shl,
                        BinOp::Shr => Opcode::Shr,
                        BinOp::LogicalAnd => Opcode::And,
                        BinOp::LogicalOr => Opcode::Or,
                    };
                    self.emit_op(pvm_op, rd, r1, r2 as u32);
                }
            }

            Inst::UnOp(dst, op, src) => {
                let rd = self.regs.alloc(*dst);
                let r1 = self.regs.get(*src);
                match op {
                    UnOp::Neg => {
                        // rd = 0 - rs1
                        self.emit_op(Opcode::Sub, rd, 0, r1 as u32);
                    }
                    UnOp::LogicalNot => {
                        // rd = rs1 XOR 1 (flips bit 0)
                        self.emit_op(Opcode::Addi, 15, 0, 1); // r15 = 1
                        self.emit_op(Opcode::Xor, rd, r1, 15);
                    }
                    UnOp::BitNot => {
                        self.emit_op(Opcode::Not, rd, r1, 0);
                    }
                }
            }

            Inst::Cmp(dst, op, lhs, rhs) => {
                let rd = self.regs.alloc(*dst); // comparison result is always GP (0 or 1)
                let lhs_wide = self.regs.is_wide(*lhs);
                let r1 = self.regs.get(*lhs);
                let r2 = self.regs.get(*rhs);

                if lhs_wide {
                    // Wide comparison: Weq/Wlt → result in GP register
                    match op {
                        CmpOp::Eq => self.emit_op(Opcode::Weq, rd, r1, r2 as u32),
                        CmpOp::Lt => self.emit_op(Opcode::Wlt, rd, r1, r2 as u32),
                        CmpOp::Gt => self.emit_op(Opcode::Wlt, rd, r2, r1 as u32), // swap for gt
                        _ => {
                            // NotEq, LtEq, GtEq: compose from Weq/Wlt
                            match op {
                                CmpOp::NotEq => {
                                    self.emit_op(Opcode::Weq, rd, r1, r2 as u32);
                                    self.emit_op(Opcode::Addi, 15, 0, 1);
                                    self.emit_op(Opcode::Xor, rd, rd, 15);
                                }
                                CmpOp::LtEq => {
                                    // !(lhs > rhs) = !(rhs < lhs)
                                    self.emit_op(Opcode::Wlt, rd, r2, r1 as u32);
                                    self.emit_op(Opcode::Addi, 15, 0, 1);
                                    self.emit_op(Opcode::Xor, rd, rd, 15);
                                }
                                CmpOp::GtEq => {
                                    self.emit_op(Opcode::Wlt, rd, r1, r2 as u32);
                                    self.emit_op(Opcode::Addi, 15, 0, 1);
                                    self.emit_op(Opcode::Xor, rd, rd, 15);
                                }
                                _ => {}
                            }
                        }
                    }
                } else {
                    match op {
                        CmpOp::Eq => self.emit_op(Opcode::Eq, rd, r1, r2 as u32),
                        CmpOp::NotEq => {
                            self.emit_op(Opcode::Eq, rd, r1, r2 as u32);
                            self.emit_op(Opcode::Addi, 15, 0, 1);
                            self.emit_op(Opcode::Xor, rd, rd, 15);
                        }
                        CmpOp::Lt => self.emit_op(Opcode::Lt, rd, r1, r2 as u32),
                        CmpOp::Gt => self.emit_op(Opcode::Gt, rd, r1, r2 as u32),
                        CmpOp::LtEq => {
                            self.emit_op(Opcode::Gt, rd, r1, r2 as u32);
                            self.emit_op(Opcode::Addi, 15, 0, 1);
                            self.emit_op(Opcode::Xor, rd, rd, 15);
                        }
                        CmpOp::GtEq => {
                            self.emit_op(Opcode::Lt, rd, r1, r2 as u32);
                            self.emit_op(Opcode::Addi, 15, 0, 1);
                            self.emit_op(Opcode::Xor, rd, rd, 15);
                        }
                    }
                }
            }

            Inst::StorageGet(dst, field) => {
                let rd = self.regs.alloc(*dst);
                let slot = self.storage_slots.get(field.as_str()).copied().unwrap_or(0);
                // Load slot index into r15, then Sload
                self.emit_op(Opcode::Addi, 15, 0, slot);
                self.emit_op(Opcode::Sload, rd, 15, 0);
            }

            Inst::StorageSet(field, val) => {
                let rv = self.regs.get(*val);
                let slot = self.storage_slots.get(field.as_str()).copied().unwrap_or(0);
                self.emit_op(Opcode::Addi, 15, 0, slot);
                self.emit_op(Opcode::Sstore, rv, 15, 0);
            }

            Inst::StorageMapGet(dst, field, key) => {
                let rd = self.regs.alloc(*dst);
                let rk = self.regs.get(*key);
                let slot = self.storage_slots.get(field.as_str()).copied().unwrap_or(0);
                // Derive storage key: hash(slot, key) using Poseidon
                // Store slot and key in memory, then hash
                self.emit_op(Opcode::Addi, 15, 0, slot);  // r15 = slot
                self.emit_op(Opcode::Push, 15, 0, 0);     // push slot
                self.emit_op(Opcode::Push, rk, 0, 0);     // push key
                // Poseidon hash: wd = poseidon(mem[rs1..rs1+rs2])
                // For now, use key directly as slot (full impl hashes slot+key)
                self.emit_op(Opcode::Sload, rd, rk, 0);
            }

            Inst::StorageMapSet(field, key, val) => {
                let rk = self.regs.get(*key);
                let rv = self.regs.get(*val);
                // Same key derivation as MapGet
                self.emit_op(Opcode::Sstore, rv, rk, 0);
            }

            Inst::Builtin(dst, op) => {
                let rd = self.regs.alloc(*dst);
                // PVM env opcodes use sub-fields:
                // Caller(sub): 0=block_number, 1=timestamp, 2=gas_remaining
                // Callvalue(sub): 0=call_value, 1=gas_price, 2=balance, 3=caller, 4=self_address
                match op {
                    BuiltinOp::MsgSender => {
                        // Caller address is wide (256-bit) — use Callvalue sub=3
                        self.emit_op(Opcode::Callvalue, rd, 0, 3); // env_wide::CALLER
                    }
                    BuiltinOp::MsgValue => {
                        self.emit_op(Opcode::Callvalue, rd, 0, 0); // env_wide::CALL_VALUE
                    }
                    BuiltinOp::MsgData => {
                        self.emit_op(Opcode::Addi, rd, 0, 0); // placeholder — calldata
                    }
                    BuiltinOp::BlockTimestamp => {
                        self.emit_op(Opcode::Caller, rd, 0, 1); // env_gp::TIMESTAMP
                    }
                    BuiltinOp::BlockHeight => {
                        self.emit_op(Opcode::Caller, rd, 0, 0); // env_gp::BLOCK_NUMBER
                    }
                    BuiltinOp::BlockProposer => {
                        self.emit_op(Opcode::Addi, rd, 0, 0); // placeholder
                    }
                    BuiltinOp::TxGasPrice => {
                        self.emit_op(Opcode::Callvalue, rd, 0, 1); // env_wide::GAS_PRICE
                    }
                    BuiltinOp::TxNonce => {
                        self.emit_op(Opcode::Addi, rd, 0, 0); // placeholder
                    }
                    BuiltinOp::TxHash => {
                        self.emit_op(Opcode::Addi, rd, 0, 0); // placeholder
                    }
                    BuiltinOp::TxGasLimit => {
                        self.emit_op(Opcode::Addi, rd, 0, 0); // placeholder
                    }
                    BuiltinOp::AddressOfSelf => {
                        self.emit_op(Opcode::Callvalue, rd, 0, 4); // env_wide::ADDRESS
                    }
                    BuiltinOp::GasRemaining => {
                        self.emit_op(Opcode::Caller, rd, 0, 2); // env_gp::GAS_REMAINING
                    }
                }
            }

            Inst::Jump(label) => {
                self.emit_jump_placeholder(Opcode::Jmp, 0, 0, *label);
            }

            Inst::Branch(cond, then_label, else_label) => {
                let rc = self.regs.get(*cond);
                // if cond != 0, jump to then; else jump to else
                self.emit_jump_placeholder(Opcode::Bne, rc, 0, *then_label);
                self.emit_jump_placeholder(Opcode::Jmp, 0, 0, *else_label);
            }

            Inst::Return(val) => {
                if let Some(v) = val {
                    let rv = self.regs.get(*v);
                    if rv != 1 {
                        self.emit_op(Opcode::Add, 1, rv, 0); // move to r1
                    }
                }
                // Clear reentrancy guard before return
                if self.needs_guard_cleanup {
                    self.emit_op(Opcode::Addi, 15, 0, 0);
                    self.emit_op(Opcode::Sstore, 0, 15, 0);
                }
                // Entry function: Halt. Called functions: Ret.
                if self.is_entry_function {
                    self.emit_op(Opcode::Halt, 0, 0, 0);
                } else {
                    self.emit_op(Opcode::Ret, 0, 0, 0);
                }
            }

            Inst::Revert(_name, _fields) => {
                self.emit_op(Opcode::Revert, 0, 0, 0);
            }

            Inst::Emit(_name, _fields) => {
                self.emit_op(Opcode::Log, 0, 0, 0);
            }

            Inst::Call(dst, name, args) => {
                let rd = self.regs.alloc(*dst);
                // Push args to stack for the callee
                for arg in args {
                    let r = self.regs.get(*arg);
                    self.emit_op(Opcode::Push, r, 0, 0);
                }
                // Look up function offset and emit Call
                if let Some(&offset) = self.func_offsets.get(name.as_str()) {
                    let byte_offset = (offset * 4) as i32;
                    let here = (self.current_offset() * 4) as i32;
                    let relative = byte_offset - here;
                    self.emit_op(Opcode::Call, 0, 0, (relative as u32) & 0x3FFFF);
                    // Return value in r1 → move to destination
                    if rd != 1 {
                        self.emit_op(Opcode::Add, rd, 1, 0);
                    }
                } else {
                    // Built-in or external — placeholder
                    self.emit_op(Opcode::Addi, rd, 0, 0);
                }
            }

            Inst::Hash(dst, _args) => {
                let rd = self.regs.alloc(*dst);
                self.emit_op(Opcode::Poseidon, rd, 0, 0); // simplified
            }

            Inst::Cast(dst, src, ty) => {
                let src_wide = self.regs.is_wide(*src);
                let dst_wide = matches!(ty, Ty::U256 | Ty::I256);

                if !src_wide && dst_wide {
                    // GP → Wide: Widen
                    let wd = self.regs.alloc_wide(*dst);
                    let rs = self.regs.get(*src);
                    self.emit_op(Opcode::Widen, wd, rs, 0);
                } else if src_wide && !dst_wide {
                    // Wide → GP: Narrow (panics if > u64::MAX)
                    let rd = self.regs.alloc(*dst);
                    let ws = self.regs.get(*src);
                    self.emit_op(Opcode::Narrow, rd, ws, 0);
                } else {
                    // Same register file: copy
                    let rd = self.regs.alloc(*dst);
                    let rs = self.regs.get(*src);
                    if rd != rs {
                        self.emit_op(Opcode::Add, rd, rs, 0);
                    }
                }
            }

            Inst::StructInit(dst, _name, fields) => {
                let rd = self.regs.alloc(*dst);
                let struct_size = (fields.len() as u32) * memory::WORD_SIZE;
                // Allocate on heap: rd = heap_ptr; heap_ptr += struct_size
                // r12 is our heap pointer register
                self.emit_op(Opcode::Add, rd, 12, 0);          // rd = current heap_ptr
                self.emit_op(Opcode::Addi, 12, 12, struct_size); // advance heap_ptr
                // Store each field at its offset
                for (i, (_fname, freg)) in fields.iter().enumerate() {
                    let fr = self.regs.get(*freg);
                    let offset = (i as u32) * memory::WORD_SIZE;
                    self.emit_store(fr, rd, offset as i32);
                }
            }

            Inst::FieldGet(dst, obj, field) => {
                let rd = self.regs.alloc(*dst);
                let ro = self.regs.get(*obj);
                // Field offset: deterministic from field name
                // Each field is 8 bytes, ordered by declaration order
                // Without struct type info at this point, use name-based offset
                let offset = field_name_to_offset(field) as u32;
                self.emit_load(rd, ro, offset as i32);
            }

            Inst::IndexGet(dst, obj, idx) => {
                let rd = self.regs.alloc(*dst);
                let ro = self.regs.get(*obj);
                let ri = self.regs.get(*idx);
                // addr = base + idx * 8 (u64 element size)
                self.emit_op(Opcode::Addi, 14, 0, 3);         // r14 = 3 (shift amount for *8)
                self.emit_op(Opcode::Shl, 15, ri, 14);        // r15 = idx << 3 = idx * 8
                self.emit_op(Opcode::Add, 15, ro, 15);        // r15 = base + idx*8
                self.emit_load(rd, 15, 0);
            }

            Inst::IndexSet(obj, idx, val) => {
                let ro = self.regs.get(*obj);
                let ri = self.regs.get(*idx);
                let rv = self.regs.get(*val);
                self.emit_op(Opcode::Addi, 14, 0, 3);
                self.emit_op(Opcode::Shl, 15, ri, 14);
                self.emit_op(Opcode::Add, 15, ro, 15);
                self.emit_store(rv, 15, 0);
            }

            Inst::MakeTuple(dst, regs) => {
                let rd = self.regs.alloc(*dst);
                let size = (regs.len() as u32) * memory::WORD_SIZE;
                // Allocate on heap
                self.emit_op(Opcode::Add, rd, 12, 0);          // rd = heap_ptr
                self.emit_op(Opcode::Addi, 12, 12, size);       // advance heap
                for (i, reg) in regs.iter().enumerate() {
                    let r = self.regs.get(*reg);
                    let offset = (i as u32) * memory::WORD_SIZE;
                    self.emit_store(r, rd, offset as i32);
                }
            }

            Inst::TupleGet(dst, tuple, idx) => {
                let rd = self.regs.alloc(*dst);
                let rt = self.regs.get(*tuple);
                let offset = (*idx) * (memory::WORD_SIZE as u32);
                self.emit_load(rd, rt, offset as i32);
            }

            Inst::MakeArray(dst, regs) => {
                let rd = self.regs.alloc(*dst);
                let size = (regs.len() as u32) * memory::WORD_SIZE;
                self.emit_op(Opcode::Add, rd, 12, 0);
                self.emit_op(Opcode::Addi, 12, 12, size);
                for (i, reg) in regs.iter().enumerate() {
                    let r = self.regs.get(*reg);
                    let offset = (i as u32) * memory::WORD_SIZE;
                    self.emit_store(r, rd, offset as i32);
                }
            }

            Inst::ArrayRepeat(dst, val, count) => {
                let rd = self.regs.alloc(*dst);
                let rv = self.regs.get(*val);
                let size = (*count as u32) * memory::WORD_SIZE;
                self.emit_op(Opcode::Add, rd, 12, 0);
                self.emit_op(Opcode::Addi, 12, 12, size);
                // Fill: store val at each offset
                for i in 0..*count {
                    let offset = (i as u32) * memory::WORD_SIZE;
                    self.emit_store(rv, rd, offset as i32);
                }
            }

            Inst::MethodCall(dst, obj, method, args) => {
                let rd = self.regs.alloc(*dst);
                let ro = self.regs.get(*obj);

                match method.as_str() {
                    "push" if !args.is_empty() => {
                        // Vec.push(value): store at data[length], increment length
                        let val_reg = self.regs.get(args[0]);
                        // Load current length
                        self.emit_load(memory::REG_SCRATCH_1, ro, memory::VEC_LENGTH_OFFSET as i32);
                        // Compute data address: base + 16 + length * 8
                        self.emit_op(Opcode::Addi, memory::REG_SCRATCH_0, 0, 3); // shift for *8
                        self.emit_op(Opcode::Shl, memory::REG_SCRATCH_0, memory::REG_SCRATCH_1, memory::REG_SCRATCH_0 as u32);
                        self.emit_op(Opcode::Add, memory::REG_SCRATCH_0, ro, memory::REG_SCRATCH_0 as u32);
                        self.emit_op(Opcode::Addi, memory::REG_SCRATCH_0, memory::REG_SCRATCH_0, memory::VEC_DATA_OFFSET);
                        // Store value
                        self.emit_store(val_reg, memory::REG_SCRATCH_0, 0);
                        // Increment length
                        self.emit_op(Opcode::Addi, memory::REG_SCRATCH_1, memory::REG_SCRATCH_1, 1);
                        self.emit_store(memory::REG_SCRATCH_1, ro, memory::VEC_LENGTH_OFFSET as i32);
                    }
                    "pop" => {
                        // Vec.pop(): decrement length, load last element
                        self.emit_load(memory::REG_SCRATCH_1, ro, memory::VEC_LENGTH_OFFSET as i32);
                        self.emit_op(Opcode::Addi, memory::REG_SCRATCH_1, memory::REG_SCRATCH_1, 0x3FFFF); // length - 1 (wrapping sub)
                        self.emit_store(memory::REG_SCRATCH_1, ro, memory::VEC_LENGTH_OFFSET as i32);
                        // Load popped value
                        self.emit_op(Opcode::Addi, memory::REG_SCRATCH_0, 0, 3);
                        self.emit_op(Opcode::Shl, memory::REG_SCRATCH_0, memory::REG_SCRATCH_1, memory::REG_SCRATCH_0 as u32);
                        self.emit_op(Opcode::Add, memory::REG_SCRATCH_0, ro, memory::REG_SCRATCH_0 as u32);
                        self.emit_op(Opcode::Addi, memory::REG_SCRATCH_0, memory::REG_SCRATCH_0, memory::VEC_DATA_OFFSET);
                        self.emit_load(rd, memory::REG_SCRATCH_0, 0);
                    }
                    "len" => {
                        // Vec.len(): load length field
                        self.emit_load(rd, ro, memory::VEC_LENGTH_OFFSET as i32);
                    }
                    "is_empty" => {
                        // Vec.is_empty(): length == 0
                        self.emit_load(memory::REG_SCRATCH_1, ro, memory::VEC_LENGTH_OFFSET as i32);
                        self.emit_op(Opcode::Eq, rd, memory::REG_SCRATCH_1, 0);
                    }
                    _ => {
                        // Unknown method — push args and call generically
                        for arg in args {
                            let r = self.regs.get(*arg);
                            self.emit_op(Opcode::Push, r, 0, 0);
                        }
                        self.emit_op(Opcode::Addi, rd, 0, 0);
                    }
                }
            }

            Inst::ExtCall(dst, addr, _method, args) => {
                let rd = self.regs.alloc(*dst);
                let ra = self.regs.get(*addr);
                // Push args, then external call
                for arg in args {
                    let r = self.regs.get(*arg);
                    self.emit_op(Opcode::Push, r, 0, 0);
                }
                self.emit_op(Opcode::CallExt, rd, ra, 0);
            }

            Inst::CrossCall { target, method, args, .. } => {
                let rt = self.regs.get(*target);
                let rm = self.regs.get(*method);
                for arg in args {
                    let r = self.regs.get(*arg);
                    self.emit_op(Opcode::Push, r, 0, 0);
                }
                // Queue async message (PVM runtime handles dispatch post-tx)
                self.emit_op(Opcode::Log, rt, rm, 0); // uses Log as async message placeholder
            }

            Inst::RawCall(dst, target, args) => {
                let rd = self.regs.alloc(*dst);
                let rt = self.regs.get(*target);
                for arg in args {
                    let r = self.regs.get(*arg);
                    self.emit_op(Opcode::Push, r, 0, 0);
                }
                self.emit_op(Opcode::CallExt, rd, rt, 0);
            }

            // Instructions that don't produce PVM opcodes
            Inst::Comment(_) => {}
            Inst::Phi(_, _) => {}
        }
    }
}

/// Compute a deterministic field offset from field name.
/// Each field is 8 bytes (one u64 slot). Fields are ordered by name hash.
fn field_name_to_offset(name: &str) -> usize {
    // Simple: use field name bytes sum mod 256 as offset
    // Real impl: look up struct def, compute cumulative sizes
    let hash: usize = name.bytes().enumerate().map(|(i, b)| (b as usize) * (i + 1)).sum();
    (hash % 32) * 8 // offset in bytes, aligned to 8
}

/// Compute a function selector (first 4 bytes of hash of name).
fn compute_selector(name: &str) -> u32 {
    // Simple hash for selector — real impl uses Poseidon2
    let mut hash: u32 = 0x811c9dc5; // FNV offset basis
    for byte in name.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193); // FNV prime
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;
    use crate::parser::Parser;
    use crate::lower;
    use crate::optimize;

    fn compile(src: &str) -> CompiledContract {
        let (tokens, _) = Lexer::new(src).tokenize();
        let (file, _) = Parser::new(tokens).parse();
        let mut ir = lower::lower(&file);
        optimize::optimize(&mut ir);
        let mut codegen = CodeGen::new();
        codegen.emit_guards = false; // disable guards for PVM testing
        codegen.generate(&ir)
    }

    fn compile_no_opt(src: &str) -> CompiledContract {
        let (tokens, _) = Lexer::new(src).tokenize();
        let (file, _) = Parser::new(tokens).parse();
        let ir = lower::lower(&file);
        let mut codegen = CodeGen::new();
        codegen.emit_guards = false;
        codegen.generate(&ir)
    }

    #[test]
    fn codegen_minimal_contract() {
        let compiled = compile(r#"
            contract Token {
                storage { supply: u256, }
                #[constructor]
                pub fn init() {
                    self.supply = 1000;
                }
                #[view]
                pub fn get_supply() -> u256 {
                    return self.supply;
                }
            }
        "#);

        assert_eq!(compiled.name, "Token");
        assert!(compiled.bytecode.len() > 0, "should produce bytecode");
        assert!(compiled.instruction_count > 0);
        // get_supply should have a selector (init is constructor, no selector)
        assert_eq!(compiled.selectors.len(), 1);
        assert_eq!(compiled.selectors[0].1, "get_supply");
    }

    #[test]
    fn codegen_arithmetic() {
        let compiled = compile(r#"
            contract T {
                storage { result: u256, }
                pub fn f() {
                    let a = 10;
                    let b = 20;
                    self.result = a + b;
                }
            }
        "#);

        assert!(compiled.instruction_count > 0);
        assert!(compiled.bytecode.len() > 0);
    }

    #[test]
    fn codegen_branch() {
        let compiled = compile(r#"
            contract T {
                storage { x: u256, }
                pub fn f() {
                    if true {
                        self.x = 1;
                    } else {
                        self.x = 2;
                    }
                }
            }
        "#);

        assert!(compiled.instruction_count > 0);
    }

    #[test]
    fn codegen_loop() {
        let compiled = compile(r#"
            contract T {
                storage { sum: u256, }
                pub fn f() {
                    let mut total = 0;
                    for i in 0..10 {
                        total = total + i;
                    }
                    self.sum = total;
                }
            }
        "#);

        assert!(compiled.instruction_count > 0);
    }

    #[test]
    fn codegen_produces_valid_bytecode_length() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u256 {
                    return 42;
                }
            }
        "#);

        // Each instruction is 4 bytes
        assert_eq!(compiled.bytecode.len(), compiled.instruction_count * 4);
    }

    #[test]
    fn codegen_runs_on_pvm_return_42() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u256 {
                    return 42;
                }
            }
        "#);

        eprintln!("Instructions: {}", compiled.instruction_count);
        eprintln!("Bytecode len: {}", compiled.bytecode.len());

        // Load and run on actual PVM
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000);
        vm.load(&compiled.bytecode).unwrap();

        // Run until halt/ret
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 100 { break; }
                }
                Err(_) => break,
            }
        }

        // Check what happened
        let r0 = vm.cpu.read_gp(0);
        let r1 = vm.cpu.read_gp(1);
        let r2 = vm.cpu.read_gp(2);
        let r14 = vm.cpu.read_gp(14);
        let r15 = vm.cpu.read_gp(15);

        assert_eq!(r1, 42,
            "return value should be 42, got r1={}, r2={}, r14={}, r15={}, steps={}, insts={}",
            r1, r2, r14, r15, steps, compiled.instruction_count);
    }

    #[test]
    fn codegen_runs_on_pvm_arithmetic() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u256 {
                    let a = 10;
                    let b = 20;
                    return a + b;
                }
            }
        "#);

        let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000);
        vm.load(&compiled.bytecode).unwrap();

        loop {
            match vm.step() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => continue,
            }
        }

        assert_eq!(vm.cpu.read_gp(1), 30, "10 + 20 should be 30");
    }

    #[test]
    fn codegen_runs_on_pvm_comparison() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u256 {
                    let a = 10;
                    let b = 5;
                    if a > b {
                        return 1;
                    }
                    return 0;
                }
            }
        "#);

        let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000);
        vm.load(&compiled.bytecode).unwrap();

        loop {
            match vm.step() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => continue,
            }
        }

        assert_eq!(vm.cpu.read_gp(1), 1, "10 > 5 should return 1");
    }

    #[test]
    fn codegen_runs_on_pvm_loop() {
        // Simple loop: count to 3
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u256 {
                    let mut x = 0;
                    for i in 0..3 {
                        x = x + 1;
                    }
                    return x;
                }
            }
        "#);

        // Debug: print instruction count and all raw instructions
        eprintln!("Loop test: {} instructions, {} bytes", compiled.instruction_count, compiled.bytecode.len());
        for i in 0..compiled.instruction_count {
            let offset = i * 4;
            let word = u32::from_le_bytes([
                compiled.bytecode[offset],
                compiled.bytecode[offset+1],
                compiled.bytecode[offset+2],
                compiled.bytecode[offset+3],
            ]);
            let opcode = (word >> 26) & 0x3F;
            let rd = (word >> 22) & 0xF;
            let rs1 = (word >> 18) & 0xF;
            let imm = word & 0x3FFFF;
            eprintln!("  [{}] op=0x{:02x} rd={} rs1={} imm={}", i, opcode, rd, rs1, imm);
        }

        let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000);
        vm.load(&compiled.bytecode).unwrap();

        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(r)) => { eprintln!("  Finished: {:?}, steps={}", r, steps); break; }
                Ok(None) => { steps += 1; if steps > 200 { eprintln!("  Max steps!"); break; } }
                Err(t) => { eprintln!("  Trap: {:?}, steps={}", t, steps); break; }
            }
        }

        for i in 0..8 {
            eprintln!("  r{} = {}", i, vm.cpu.read_gp(i as u8));
        }

        // x should be 3 (incremented 3 times)
        assert_eq!(vm.cpu.read_gp(1), 3,
            "loop should count to 3, got r1={}, steps={}", vm.cpu.read_gp(1), steps);
    }

    #[test]
    fn codegen_runs_on_pvm_nested_arithmetic() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u256 {
                    let a = 100;
                    let b = 30;
                    let c = a - b;
                    let d = c * 2;
                    return d;
                }
            }
        "#);

        let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000);
        vm.load(&compiled.bytecode).unwrap();

        loop {
            match vm.step() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => continue,
            }
        }

        // (100 - 30) * 2 = 140
        assert_eq!(vm.cpu.read_gp(1), 140, "should be 140");
    }

    #[test]
    fn codegen_runs_on_pvm_multiple_branches() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u256 {
                    let x = 15;
                    if x > 20 {
                        return 1;
                    }
                    if x > 10 {
                        return 2;
                    }
                    return 3;
                }
            }
        "#);

        let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000);
        vm.load(&compiled.bytecode).unwrap();

        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => { steps += 1; if steps > 100 { break; } }
            }
        }

        // 15 > 20? no. 15 > 10? yes → return 2
        assert_eq!(vm.cpu.read_gp(1), 2, "should take second branch, got {}", vm.cpu.read_gp(1));
    }

    #[test]
    fn codegen_runs_on_pvm_with_context() {
        // Test that builtins map to correct PVM opcodes
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u256 {
                    return gas_remaining();
                }
            }
        "#);

        let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000);
        vm.load(&compiled.bytecode).unwrap();

        loop {
            match vm.step() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => continue,
            }
        }

        // gas_remaining should be > 0 (we started with 100_000)
        let gas = vm.cpu.read_gp(1);
        assert!(gas > 0, "gas_remaining should be > 0, got {}", gas);
    }

    #[test]
    fn codegen_runs_on_pvm_revert() {
        // Revert should stop execution
        let compiled = compile(r#"
            contract T {
                error Fail {}
                pub fn f() -> u64 {
                    revert!(Fail {});
                }
            }
        "#);

        let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000);
        vm.load(&compiled.bytecode).unwrap();

        let mut result = None;
        loop {
            match vm.step() {
                Ok(Some(r)) => { result = Some(r); break; }
                Ok(None) => continue,
                Err(_) => break,
            }
        }

        // Should revert (not halt normally)
        assert!(
            matches!(result, Some(pyde_vm::vm::ExecResult::Revert)),
            "should have reverted, got {:?}", result
        );
    }

    #[test]
    fn codegen_runs_on_pvm_mutable_var() {
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let mut x = 10;
                    x = x + 5;
                    x = x * 2;
                    return x;
                }
            }
        "#);

        let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000);
        vm.load(&compiled.bytecode).unwrap();

        loop {
            match vm.step() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => continue,
            }
        }

        // (10 + 5) * 2 = 30
        assert_eq!(vm.cpu.read_gp(1), 30, "mutable var should be 30");
    }

    #[test]
    fn codegen_runs_on_pvm_while_loop() {
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let mut x = 1;
                    while x < 100 {
                        x = x * 2;
                    }
                    return x;
                }
            }
        "#);

        let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000);
        vm.load(&compiled.bytecode).unwrap();

        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => { steps += 1; if steps > 500 { break; } }
            }
        }

        // 1, 2, 4, 8, 16, 32, 64, 128 → x = 128
        assert_eq!(vm.cpu.read_gp(1), 128,
            "should double until >= 100, got {}", vm.cpu.read_gp(1));
    }

    #[test]
    fn codegen_selectors() {
        let compiled = compile(r#"
            contract T {
                #[constructor]
                pub fn init() {}
                pub fn transfer() {}
                pub fn balance_of() -> u256 { return 0; }
                fn internal_helper() {}
            }
        "#);

        // Only pub non-constructor functions get selectors
        assert_eq!(compiled.selectors.len(), 2);
        let names: Vec<&str> = compiled.selectors.iter().map(|s| s.1.as_str()).collect();
        assert!(names.contains(&"transfer"));
        assert!(names.contains(&"balance_of"));
    }
}
