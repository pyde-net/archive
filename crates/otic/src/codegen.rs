//! Code generation: OtiIR → PVM bytecode.
//!
//! Transforms the optimized IR into PVM instructions that can execute
//! on the Pyde Virtual Machine.
//!
//! Architecture:
//! - Linear scan register allocation (virtual → physical PVM registers)
//! - Direct instruction selection (IR op → PVM opcode)
//! - Two-pass: emit instructions with placeholder offsets, then resolve jumps
//!
//! PVM register conventions:
//!   GP: r0=zero, r1=return, r2..r11=args/locals, r12=heap_ptr, r13=spill_base, r14-r15=scratch
//!   Wide: w0..w6=user, w7=scratch
//!
//! Calling convention:
//!   - Args in r2, r3, ..., r(1+N)
//!   - Return value in r1
//!   - All registers caller-clobbered
//!   - Dispatch entries decode calldata → arg registers → Call → Halt
//!   - All functions end with Ret (dispatch wrapper emits Halt)

use std::collections::{HashMap, HashSet};

use ethnum::U256;

use crate::ir::*;
use crate::memory;
use crate::types::Ty;

use pyde_vm::isa::{encode, encode_mem_immediate, Opcode, Instruction, MemWidth};

/// Reentrancy guard slot (well above user-defined storage slots).
/// Must fit in 17-bit positive Addi (PVM sign-extends 18-bit immediate).
const REENTRANCY_SLOT: u32 = 0x1FFFE;

/// Wide scratch register index.
const WIDE_SCRATCH: u8 = 7;
/// Second wide scratch register index.
const WIDE_SCRATCH2: u8 = 6;

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
// Register Allocator
// ============================================================================

/// Spill event: the CodeGen must emit Store/Load for register pressure.
enum SpillAction {
    /// Store this physical register to spill slot before reusing it.
    Save(u8, u32), // (physical_reg, spill_slot_offset)
}

/// Restore event: the CodeGen must emit Load to bring a spilled value back.
enum RestoreAction {
    /// Load from spill slot into this physical register.
    Restore(u8, u32), // (physical_reg, spill_slot_offset)
}

/// Maps IR virtual registers to PVM physical registers.
/// GP: r1-r11 for user values (r0=zero, r12=heap, r13=spill_base, r14-r15=scratch).
/// Wide: w0-w6 for user values (w7=scratch).
///
/// Spilling uses memory at r13 (spill base pointer, set at function entry).
/// Each spilled vreg gets a fixed 8-byte slot: mem[r13 + slot*8].
struct RegAlloc {
    /// Virtual register → physical register mapping (currently in register).
    mapping: HashMap<Reg, u8>,
    /// Reverse mapping: physical register → virtual register (for eviction).
    reverse: HashMap<u8, Reg>,
    /// Spilled virtual registers → spill slot offset from r13.
    spilled: HashMap<Reg, u32>,
    /// Next spill slot.
    next_spill_slot: u32,
    /// Track which virtual registers hold wide (u256) values.
    wide: HashSet<Reg>,
    /// Next available GP register (1-11).
    next_gp: u8,
    /// Next available wide register (0-6).
    next_wide: u8,
}

impl RegAlloc {
    fn new() -> Self {
        Self {
            mapping: HashMap::new(),
            reverse: HashMap::new(),
            spilled: HashMap::new(),
            next_spill_slot: 0,
            wide: HashSet::new(),
            next_gp: 1,
            next_wide: 0,
        }
    }

    /// Allocate a GP (64-bit) physical register.
    /// Returns (physical_reg, optional spill action if eviction needed).
    fn alloc(&mut self, vreg: Reg) -> (u8, Option<SpillAction>) {
        if let Some(&phys) = self.mapping.get(&vreg) {
            return (phys, None);
        }
        // If this vreg was previously spilled, it will be restored on get()
        if self.next_gp <= 11 {
            let phys = self.next_gp;
            self.next_gp += 1;
            self.mapping.insert(vreg, phys);
            self.reverse.insert(phys, vreg);
            (phys, None)
        } else {
            // Evict: reuse registers cyclically (r1-r11)
            let phys = ((self.next_gp - 1) % 11) + 1;
            self.next_gp += 1;
            // Evict the old occupant to spill slot
            let spill = if let Some(&old_vreg) = self.reverse.get(&phys) {
                let slot = self.next_spill_slot;
                self.next_spill_slot += 1;
                self.spilled.insert(old_vreg, slot);
                self.mapping.remove(&old_vreg);
                Some(SpillAction::Save(phys, slot))
            } else {
                None
            };
            self.mapping.insert(vreg, phys);
            self.reverse.insert(phys, vreg);
            (phys, spill)
        }
    }

    /// Get the physical register for a virtual register.
    /// If the vreg was spilled, returns None (caller must restore).
    fn get_or_spilled(&self, vreg: Reg) -> Result<u8, RestoreAction> {
        if let Some(&phys) = self.mapping.get(&vreg) {
            Ok(phys)
        } else if let Some(&slot) = self.spilled.get(&vreg) {
            // Need to restore from spill slot into a scratch register
            Err(RestoreAction::Restore(15, slot)) // use r15 as temp
        } else {
            Ok(0) // unknown vreg → r0
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

    /// Pre-map a virtual register to a specific physical register.
    fn pre_map(&mut self, vreg: Reg, phys: u8) {
        self.mapping.insert(vreg, phys);
        self.reverse.insert(phys, vreg);
        if phys >= self.next_gp && phys <= 11 {
            self.next_gp = phys + 1;
        }
    }

    /// Get the physical register (backward compat — panics on spill).
    fn get(&self, vreg: Reg) -> u8 {
        *self.mapping.get(&vreg).unwrap_or(&0)
    }

    /// Check if a register holds a wide (u256) value.
    fn is_wide(&self, vreg: Reg) -> bool {
        self.wide.contains(&vreg)
    }

    /// Check if a vreg is currently spilled to memory.
    fn is_spilled(&self, vreg: Reg) -> bool {
        self.spilled.contains_key(&vreg) && !self.mapping.contains_key(&vreg)
    }

    /// Reset for a new function.
    fn reset(&mut self) {
        self.mapping.clear();
        self.reverse.clear();
        self.spilled.clear();
        self.next_spill_slot = 0;
        self.wide.clear();
        self.next_gp = 1;
        self.next_wide = 0;
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
    pub emit_guards: bool,
    /// Function name → label (for call resolution).
    func_labels: HashMap<String, Label>,
    /// Storage field name → slot index.
    storage_slots: HashMap<String, u32>,
    /// Storage field name → type (for GP vs wide Sload mode selection).
    storage_types: HashMap<String, Ty>,
    /// Struct name → ordered fields (for field offset computation).
    struct_defs: HashMap<String, Vec<(String, Ty)>>,
    /// Global field name → byte offset (built from struct_defs).
    field_offsets: HashMap<String, u32>,
    /// Label counter for generating unique labels.
    label_counter: u32,
    /// Current function's IR label → codegen label remapping.
    current_label_remap: Option<HashMap<Label, Label>>,
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
            func_labels: HashMap::new(),
            storage_slots: HashMap::new(),
            storage_types: HashMap::new(),
            struct_defs: HashMap::new(),
            field_offsets: HashMap::new(),
            label_counter: 0,
            current_label_remap: None,
        }
    }

    /// Remap an IR label to a unique codegen label (prevents cross-function collisions).
    fn remap_label(&self, label: Label) -> Label {
        self.current_label_remap.as_ref()
            .and_then(|m| m.get(&label).copied())
            .unwrap_or(label)
    }

    fn alloc_label(&mut self) -> Label {
        let l = Label(self.label_counter);
        self.label_counter += 1;
        l
    }

    /// Generate bytecode for an entire IR program.
    pub fn generate(mut self, program: &IrProgram) -> CompiledContract {
        let mut selectors = Vec::new();

        // Set label_counter above all IR block labels to avoid collision
        let max_ir_label = program.functions.iter()
            .flat_map(|f| f.blocks.iter().map(|b| b.label.0))
            .max()
            .unwrap_or(0);
        self.label_counter = max_ir_label + 100; // safe margin above IR labels

        // Collect storage slot assignments and types
        for field in &program.storage_fields {
            self.storage_slots.insert(field.name.clone(), field.slot);
            self.storage_types.insert(field.name.clone(), field.ty.clone());
        }

        // Build struct field offset map
        for sdef in &program.struct_defs {
            let mut offset = 0u32;
            let mut fields = Vec::new();
            for (fname, fty) in &sdef.fields {
                self.field_offsets.insert(fname.clone(), offset);
                fields.push((fname.clone(), fty.clone()));
                offset += field_byte_size(fty);
            }
            self.struct_defs.insert(sdef.name.clone(), fields);
        }

        // Pre-pass: reserve labels for each function body + dispatch entry
        let mut dispatch_entries: Vec<(u32, String, Label, Label)> = Vec::new(); // (selector, name, dispatch_label, func_label)

        for func in &program.functions {
            if func.is_test {
                continue;
            }
            let func_label = self.alloc_label();
            self.func_labels.insert(func.name.clone(), func_label);

            if func.is_pub && !func.is_constructor {
                let dispatch_label = self.alloc_label();
                let selector = compute_selector(&func.name);
                dispatch_entries.push((selector, func.name.clone(), dispatch_label, func_label));
                selectors.push((selector, func.name.clone(), 0)); // offset filled later
            }
        }

        // ====================================================================
        // Emit constructor section
        // ====================================================================
        let constructor_start = self.current_offset();
        for func in &program.functions {
            if func.is_constructor {
                // Init heap pointer: r12 = r5 + r4 + 8 (past calldata)
                self.emit_heap_init();
                // Decode calldata params into arg registers
                self.emit_calldata_decode(func);
                // Emit constructor body directly (no Call/Ret, just Halt at end)
                self.gen_function(func, true);
            }
        }
        let constructor_end = self.current_offset();

        // ====================================================================
        // Emit runtime section: dispatch table + dispatch entries + functions
        // ====================================================================
        let runtime_start = constructor_end;

        // Dispatch table + entries (only in production mode, not test mode)
        if self.emit_guards {
            self.gen_dispatch_table(&dispatch_entries);

            // Dispatch entries: decode calldata → Call function → Halt
            for (_, name, dispatch_label, func_label) in &dispatch_entries {
                self.mark_label(*dispatch_label);

                let func = program.functions.iter().find(|f| f.name == *name)
                    .expect("dispatch entry references non-existent function");

                self.emit_heap_init();
                self.emit_calldata_decode(func);
                self.emit_function_guards(func);
                self.emit_jump_placeholder(Opcode::Call, 0, 0, *func_label);
                if func.is_pub && !func.is_view && !func.is_constructor && !func.is_reentrant {
                    self.emit_reentrancy_cleanup();
                }
                self.emit_op(Opcode::Halt, 0, 0, 0);
            }
        }

        // Function bodies
        // In production mode, all functions use Ret (dispatch wrapper handles Halt).
        // In test mode, emit Jmp to first pub function at start, only it gets Halt.
        let first_pub_name = program.functions.iter()
            .find(|f| !f.is_test && !f.is_constructor && f.is_pub)
            .map(|f| f.name.clone());

        // In test mode: if there are private functions before the first pub function,
        // emit a Jmp to skip them. PVM always starts at PC=0.
        if !self.emit_guards {
            if let Some(ref pub_name) = first_pub_name {
                if let Some(&pub_label) = self.func_labels.get(pub_name.as_str()) {
                    // Check if first runtime function IS the pub function
                    let first_runtime = program.functions.iter()
                        .find(|f| !f.is_test && !f.is_constructor);
                    if first_runtime.map(|f| &f.name) != first_pub_name.as_ref() {
                        // Private functions come first — emit Jmp to pub function
                        self.emit_jump_placeholder(Opcode::Jmp, 0, 0, pub_label);
                    }
                }
            }
        }

        for func in &program.functions {
            if func.is_test || func.is_constructor {
                continue;
            }
            if let Some(&label) = self.func_labels.get(&func.name) {
                self.mark_label(label);
            }
            let offset = self.current_offset();
            for sel in &mut selectors {
                if sel.1 == func.name {
                    sel.2 = offset;
                }
            }
            // In test mode: first pub function is entry (Halt), all others Ret.
            // In production mode: all functions Ret (dispatch handles Halt).
            let is_entry = !self.emit_guards && first_pub_name.as_ref() == Some(&func.name);
            self.gen_function(func, is_entry);
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

    // ========================================================================
    // Dispatch table: selector comparison
    // ========================================================================

    fn gen_dispatch_table(&mut self, entries: &[(u32, String, Label, Label)]) {
        if entries.is_empty() {
            return;
        }

        // Load 4-byte selector from calldata into r13 (u32 load, like Solidity).
        // NOT r15, because load_u32_to_reg uses r15 as scratch.
        let imm = encode_mem_immediate(0, MemWidth::W32).unwrap();
        self.emit(encode(Opcode::Load, 13, 5, imm)); // r13 = load u32 from calldata[0]

        for (selector, _name, dispatch_label, _func_label) in entries {
            // Selector bytes are BE in calldata (e.g., [0x38, 0x12, 0xe7, 0x3e]).
            // Load W32 reads them as LE u32, so we compare against the LE interpretation.
            let selector_le = (*selector).swap_bytes();
            self.load_u32_to_reg(memory::REG_SCRATCH_0, selector_le);
            self.emit_jump_placeholder(Opcode::Beq, 13, memory::REG_SCRATCH_0, *dispatch_label);
        }

        // No selector matched → revert
        self.emit_op(Opcode::Revert, 0, 0, 0);
    }

    // ========================================================================
    // Calldata decode + heap init
    // ========================================================================

    /// Initialize heap pointer past calldata.
    /// When calldata exists: r5=HEAP_START, r4=len, so r12 = r5 + r4 + 8.
    /// When calldata is empty: PVM doesn't set r5/r4, so fallback to HEAP_START.
    fn emit_heap_init(&mut self) {
        // Load HEAP_START as base (always safe even without calldata)
        self.load_u32_to_reg(12, memory::HEAP_START);
        // If calldata exists, advance past it: r12 = max(HEAP_START, r5 + r4) + 8
        // We add r4 (calldata len, 0 if none) to move past calldata
        self.emit_op(Opcode::Add, 12, 12, 4);   // r12 += r4 (calldata length, 0 if empty)
        self.emit_op(Opcode::Addi, 12, 12, 8);  // r12 += 8 (alignment gap)
    }

    /// Decode function params from calldata into arg registers (r2, r3, ...).
    /// For regular functions, params start after the 4-byte selector.
    /// For constructors, params start at offset 0 (no selector).
    ///
    /// IMPORTANT: r4 = calldata length, r5 = calldata pointer (set by PVM).
    /// Params are mapped to r2, r3, r4, r5, r6, ... which OVERWRITES r4/r5.
    /// We save the calldata pointer to r14 first, then decode using r14 as base.
    fn emit_calldata_decode(&mut self, func: &IrFunction) {
        if func.params.is_empty() {
            return;
        }
        let selector_skip = if func.is_constructor { 0i32 } else { 4 };
        let mut param_offset = selector_skip;

        // Save calldata pointer to r14 before decoding overwrites r5
        self.emit_op(Opcode::Add, memory::REG_SCRATCH_0, 5, 0); // r14 = r5

        for (i, (_name, ty)) in func.params.iter().enumerate() {
            let phys = (i as u8) + 2; // r2, r3, r4, ...
            let is_wide = is_wide_type(ty);

            if is_wide {
                // Compute address: r15 = r14 + offset
                self.emit_op(Opcode::Addi, 15, memory::REG_SCRATCH_0, param_offset as u32 & 0x3FFFF);
                self.emit_op(Opcode::Wload, phys, 15, 0);
                param_offset += 32;
            } else {
                // Load from r14 (saved calldata ptr) instead of r5
                self.emit_load(phys, memory::REG_SCRATCH_0, param_offset);
                param_offset += 8;
            }
        }
    }

    // ========================================================================
    // Function guards (reentrancy, payable)
    // ========================================================================

    fn emit_function_guards(&mut self, func: &IrFunction) {
        if !self.emit_guards {
            return;
        }

        // Reentrancy guard: check lock, set lock
        if func.is_pub && !func.is_view && !func.is_constructor && !func.is_reentrant {
            // Widen reentrancy slot to wide scratch
            self.emit_op(Opcode::Addi, 15, 0, REENTRANCY_SLOT);
            self.emit_op(Opcode::Widen, WIDE_SCRATCH, 15, 0);    // w7 = slot key
            // Sload mode 2 (GP value): r14 = storage[w7]
            self.emit_op(Opcode::Sload, 14, WIDE_SCRATCH, 2);
            // Check: lock must be 0
            self.emit_op(Opcode::Eq, 14, 14, 0);                 // r14 = (lock == 0)
            self.emit_op(Opcode::Assert, 0, 14, 0);              // Assert reads rs1: revert if r14==0
            // Set lock = 1
            self.emit_op(Opcode::Addi, 14, 0, 1);
            self.emit_op(Opcode::Sstore, 14, WIDE_SCRATCH, 2);   // storage[w7] = 1
        }

        // Payable guard: non-payable pub functions reject msg.value > 0
        if func.is_pub && !func.is_payable && !func.is_constructor {
            // w7 = msg.value (Callvalue writes to wide register)
            self.emit_op(Opcode::Callvalue, WIDE_SCRATCH, 0, 0); // w7 = call_value
            // w6 = 0 (for comparison)
            self.emit_op(Opcode::Addi, 15, 0, 0);
            self.emit_op(Opcode::Widen, WIDE_SCRATCH2, 15, 0);   // w6 = 0
            // r14 = (w7 == w6) i.e. (value == 0)
            self.emit_op(Opcode::Weq, 14, WIDE_SCRATCH, WIDE_SCRATCH2 as u32);
            self.emit_op(Opcode::Assert, 0, 14, 0);              // Assert reads rs1: revert if r14==0
        }
    }

    /// Emit reentrancy guard cleanup (clear lock).
    fn emit_reentrancy_cleanup(&mut self) {
        self.emit_op(Opcode::Addi, 15, 0, REENTRANCY_SLOT);
        self.emit_op(Opcode::Widen, WIDE_SCRATCH, 15, 0);     // w7 = slot key
        self.emit_op(Opcode::Sstore, 0, WIDE_SCRATCH, 2);     // storage[w7] = r0 = 0
    }

    // ========================================================================
    // Function body generation
    // ========================================================================

    /// Generate a function body.
    /// `is_entry`: if true, emit Halt at end (constructor/standalone); if false, emit Ret.
    fn gen_function(&mut self, func: &IrFunction, is_entry: bool) {
        self.regs.reset();
        self.needs_guard_cleanup = false;

        // Remap IR labels to unique codegen labels to prevent cross-function collisions.
        // IR labels (L0, L1, L2, ...) restart per function, but codegen label_offsets is global.
        // Without remapping, a later function's L0 overwrites an earlier function's L0.
        let mut label_remap: HashMap<Label, Label> = HashMap::new();
        for block in &func.blocks {
            let unique = self.alloc_label();
            label_remap.insert(block.label, unique);
        }

        // In test mode (no guards/dispatch), every function needs heap init
        // because there's no dispatch wrapper to do it.
        // In production mode, the dispatch wrapper handles heap init.
        if !self.emit_guards {
            self.emit_heap_init();
        }

        // Initialize spill base pointer: r13 = r12 (current heap top).
        // Spill slots live at r13 + 0, r13 + 8, r13 + 16, ...
        // Advance r12 past the spill area (reserve 256 bytes = 32 slots max).
        self.emit_op(Opcode::Add, 13, 12, 0);  // r13 = r12
        self.load_u32_to_reg(15, 256);
        self.emit_op(Opcode::Add, 12, 12, 15); // r12 += 256

        // Pre-map params to convention registers (r2, r3, ...)
        // In test mode without dispatch, params aren't loaded from calldata,
        // so standalone tests with params won't work (this is fine for now).
        for (i, (_name, _ty)) in func.params.iter().enumerate() {
            let vreg = Reg(i as u32);
            let phys = (i as u8) + 2; // r2, r3, r4, ...
            self.regs.pre_map(vreg, phys);
        }

        // Store label remap for use in gen_instruction
        self.current_label_remap = Some(label_remap);

        // Generate each basic block
        for block in &func.blocks {
            let mapped = self.remap_label(block.label);
            self.mark_label(mapped);
            for inst in &block.instructions {
                self.gen_instruction(inst, is_entry);
            }
        }

        self.current_label_remap = None;
    }

    // ========================================================================
    // Instruction selection
    // ========================================================================

    fn gen_instruction(&mut self, inst: &Inst, is_entry: bool) {
        match inst {
            Inst::Const(dst, val) => {
                match val {
                    IrConst::Int(v, ty) => {
                        let is_u256 = matches!(ty, Ty::U256 | Ty::I256);
                        if is_u256 && *v > U256::from(u64::MAX) {
                            // u256 large value → store all 32 bytes to heap, Wload
                            let wd = self.regs.alloc_wide(*dst);
                            // Split U256 into 4 x u64 limbs (LE order)
                            let limb0 = (v & U256::from(u64::MAX)).as_u64();
                            let limb1 = ((v >> 64u32) & U256::from(u64::MAX)).as_u64();
                            let limb2 = ((v >> 128u32) & U256::from(u64::MAX)).as_u64();
                            let limb3 = ((v >> 192u32) & U256::from(u64::MAX)).as_u64();
                            self.load_u64_to_reg(15, limb0);
                            self.emit_store(15, 12, 0);   // heap[0..8] = limb0
                            self.load_u64_to_reg(15, limb1);
                            self.emit_store(15, 12, 8);   // heap[8..16] = limb1
                            self.load_u64_to_reg(15, limb2);
                            self.emit_store(15, 12, 16);  // heap[16..24] = limb2
                            self.load_u64_to_reg(15, limb3);
                            self.emit_store(15, 12, 24);  // heap[24..32] = limb3
                            // Wload from heap into wide register
                            self.emit_op(Opcode::Wload, wd, 12, 0);
                            // Advance heap past the 32 bytes
                            self.emit_op(Opcode::Addi, 12, 12, 32);
                        } else if *v <= U256::from(0x1FFFFu64) {
                            // Fits in 17-bit positive Addi (PVM sign-extends 18-bit immediate)
                            let rd = self.alloc_gp(*dst);
                            self.emit_op(Opcode::Addi, rd, 0, v.as_u64() as u32);
                        } else {
                            let rd = self.alloc_gp(*dst);
                            self.load_u64_to_reg(rd, v.as_u64());
                        }
                    }
                    IrConst::Bool(b) => {
                        let rd = self.alloc_gp(*dst);
                        self.emit_op(Opcode::Addi, rd, 0, if *b { 1 } else { 0 });
                    }
                    IrConst::Address(bytes) => {
                        // Addresses are 256-bit → wide register
                        let wd = self.regs.alloc_wide(*dst);
                        // Load address bytes to memory, then Wload
                        // For zero address, just widen 0
                        let all_zero = bytes.iter().all(|&b| b == 0);
                        if all_zero {
                            self.emit_op(Opcode::Addi, 15, 0, 0);
                            self.emit_op(Opcode::Widen, wd, 15, 0);
                        } else {
                            // Store bytes to heap, Wload from heap
                            for (i, chunk) in bytes.chunks(8).enumerate() {
                                let mut buf = [0u8; 8];
                                buf[..chunk.len()].copy_from_slice(chunk);
                                let val = u64::from_le_bytes(buf);
                                self.load_u64_to_reg(15, val);
                                self.emit_store(15, 12, (i as i32) * 8);
                            }
                            self.emit_op(Opcode::Wload, wd, 12, 0);
                            // Advance heap past the 32 bytes
                            self.emit_op(Opcode::Addi, 12, 12, 32);
                        }
                    }
                    IrConst::Bytes(data) => {
                        // Write raw bytes to heap, set dst = heap pointer
                        let rd = self.alloc_gp(*dst);
                        self.emit_op(Opcode::Add, rd, 12, 0); // rd = current heap ptr
                        // Write bytes in 8-byte chunks
                        for (i, chunk) in data.chunks(8).enumerate() {
                            let mut buf = [0u8; 8];
                            buf[..chunk.len()].copy_from_slice(chunk);
                            let val = u64::from_le_bytes(buf);
                            self.load_u64_to_reg(15, val);
                            self.emit_store(15, 12, (i as i32) * 8);
                        }
                        // Advance heap past the data (aligned to 8)
                        let aligned = ((data.len() + 7) / 8) * 8;
                        self.load_u32_to_reg(15, aligned as u32);
                        self.emit_op(Opcode::Add, 12, 12, 15);
                    }
                    IrConst::Unit => {}
                    _ => {
                        let rd = self.alloc_gp(*dst);
                        self.emit_op(Opcode::Addi, rd, 0, 0);
                    }
                }
            }

            Inst::BinOp(dst, op, lhs, rhs) => {
                let lhs_wide = self.regs.is_wide(*lhs);
                let rhs_wide = self.regs.is_wide(*rhs);
                let use_wide = lhs_wide || rhs_wide;

                if use_wide {
                    if matches!(op, BinOp::Shl | BinOp::Shr) {
                        // Wide shift: shift amount is a GP value, not wide.
                        let wd = self.regs.alloc_wide(*dst);
                        let w1 = self.get_reg(*lhs);
                        let shift_reg = self.get_reg_to(*rhs, 14);
                        let dir = if matches!(op, BinOp::Shr) { 1u32 } else { 0u32 };
                        let imm = (shift_reg as u32) << 1 | dir;
                        self.emit_op(Opcode::Wshift, wd, w1, imm);
                    } else {
                        let wd = self.regs.alloc_wide(*dst);
                        let w1 = self.get_reg(*lhs);
                        let w2 = self.get_reg(*rhs);
                        let pvm_op = match op {
                            BinOp::Add => Opcode::Wadd,
                            BinOp::Sub => Opcode::Wsub,
                            BinOp::Mul => Opcode::Wmul,
                            BinOp::Div => Opcode::Wdiv,
                            BinOp::Mod => Opcode::Wmod,
                            BinOp::BitAnd => Opcode::Wand,
                            BinOp::BitOr => Opcode::Wor,
                            BinOp::BitXor => Opcode::Wxor,
                            BinOp::LogicalAnd => Opcode::Wand,
                            BinOp::LogicalOr => Opcode::Wor,
                            BinOp::Shl | BinOp::Shr => unreachable!(),
                        };
                        self.emit_op(pvm_op, wd, w1, w2 as u32);
                    }
                } else {
                    let rd = self.alloc_gp(*dst);
                    // Use different restore targets so both operands survive if both spilled
                    let r1 = self.get_reg_to(*lhs, 15);
                    let r2 = self.get_reg_to(*rhs, 14);
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
                let rd = self.alloc_gp(*dst);
                let r1 = self.get_reg(*src);
                match op {
                    UnOp::Neg => {
                        // Two's complement: -a = ~a + 1 (avoids PVM checked_sub underflow trap)
                        self.emit_op(Opcode::Not, rd, r1, 0);      // rd = ~a
                        self.emit_op(Opcode::Addi, rd, rd, 1);     // rd = ~a + 1 = -a
                    }
                    UnOp::LogicalNot => {
                        self.emit_op(Opcode::Addi, 15, 0, 1);
                        self.emit_op(Opcode::Xor, rd, r1, 15);
                    }
                    UnOp::BitNot => {
                        self.emit_op(Opcode::Not, rd, r1, 0);
                    }
                }
            }

            Inst::Cmp(dst, op, lhs, rhs) => {
                let rd = self.alloc_gp(*dst);
                let lhs_wide = self.regs.is_wide(*lhs);
                // Use different restore targets so both operands survive if both spilled
                let r1 = self.get_reg_to(*lhs, 15);
                let r2 = self.get_reg_to(*rhs, 14);

                if lhs_wide {
                    match op {
                        CmpOp::Eq => self.emit_op(Opcode::Weq, rd, r1, r2 as u32),
                        CmpOp::Lt => self.emit_op(Opcode::Wlt, rd, r1, r2 as u32),
                        CmpOp::Gt => self.emit_op(Opcode::Wlt, rd, r2, r1 as u32),
                        CmpOp::NotEq => {
                            self.emit_op(Opcode::Weq, rd, r1, r2 as u32);
                            self.emit_op(Opcode::Addi, 15, 0, 1);
                            self.emit_op(Opcode::Xor, rd, rd, 15);
                        }
                        CmpOp::LtEq => {
                            self.emit_op(Opcode::Wlt, rd, r2, r1 as u32); // gt
                            self.emit_op(Opcode::Addi, 15, 0, 1);
                            self.emit_op(Opcode::Xor, rd, rd, 15); // !gt = le
                        }
                        CmpOp::GtEq => {
                            self.emit_op(Opcode::Wlt, rd, r1, r2 as u32); // lt
                            self.emit_op(Opcode::Addi, 15, 0, 1);
                            self.emit_op(Opcode::Xor, rd, rd, 15); // !lt = ge
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

            // ==== Storage operations (fixed: wide register keys + mode bits) ====

            Inst::StorageGet(dst, field) => {
                let slot = self.storage_slots.get(field.as_str()).copied().unwrap_or(0);
                let ty = self.storage_types.get(field.as_str()).cloned().unwrap_or(Ty::U64);
                let wide_value = is_wide_type(&ty);

                // Widen slot to wide scratch
                self.emit_op(Opcode::Addi, 15, 0, slot);
                self.emit_op(Opcode::Widen, WIDE_SCRATCH, 15, 0);

                if wide_value {
                    let wd = self.regs.alloc_wide(*dst);
                    self.emit_op(Opcode::Sload, wd, WIDE_SCRATCH, 0); // mode 0: wide value
                } else {
                    let rd = self.alloc_gp(*dst);
                    self.emit_op(Opcode::Sload, rd, WIDE_SCRATCH, 2); // mode 2: GP value
                }
            }

            Inst::StorageSet(field, val) => {
                let slot = self.storage_slots.get(field.as_str()).copied().unwrap_or(0);
                let ty = self.storage_types.get(field.as_str()).cloned().unwrap_or(Ty::U64);
                let wide_value = is_wide_type(&ty);

                // Widen slot to wide scratch
                self.emit_op(Opcode::Addi, 15, 0, slot);
                self.emit_op(Opcode::Widen, WIDE_SCRATCH, 15, 0);

                let rv = self.get_reg(*val);
                if wide_value {
                    self.emit_op(Opcode::Sstore, rv, WIDE_SCRATCH, 0); // mode 0: wide value
                } else {
                    self.emit_op(Opcode::Sstore, rv, WIDE_SCRATCH, 2); // mode 2: GP value
                }
            }

            Inst::StorageMapGet(dst, field, key) => {
                let slot = self.storage_slots.get(field.as_str()).copied().unwrap_or(0);
                let map_ty = self.storage_types.get(field.as_str()).cloned().unwrap_or(Ty::U64);
                let key_ty = map_key_type(&map_ty);
                let val_ty = map_value_type(&map_ty);
                let key_wide = is_wide_type(&key_ty);
                let wide_value = is_wide_type(&val_ty);

                let rk = self.get_reg(*key);
                self.emit_map_key_derivation(slot, rk, key_wide);

                if wide_value {
                    let wd = self.regs.alloc_wide(*dst);
                    self.emit_op(Opcode::Sload, wd, WIDE_SCRATCH, 0);
                } else {
                    let rd = self.alloc_gp(*dst);
                    self.emit_op(Opcode::Sload, rd, WIDE_SCRATCH, 2);
                }
            }

            Inst::StorageMapSet(field, key, val) => {
                let slot = self.storage_slots.get(field.as_str()).copied().unwrap_or(0);
                let map_ty = self.storage_types.get(field.as_str()).cloned().unwrap_or(Ty::U64);
                let key_ty = map_key_type(&map_ty);
                let val_ty = map_value_type(&map_ty);
                let key_wide = is_wide_type(&key_ty);
                let wide_value = is_wide_type(&val_ty);

                // Get key and derive storage key FIRST
                let rk = self.get_reg(*key);
                self.emit_map_key_derivation(slot, rk, key_wide);
                // Get val AFTER derivation — derivation clobbers r14/r15,
                // so getting val before would lose it if val was spilled to r15.
                let rv = self.get_reg(*val);

                if wide_value {
                    self.emit_op(Opcode::Sstore, rv, WIDE_SCRATCH, 0);
                } else {
                    self.emit_op(Opcode::Sstore, rv, WIDE_SCRATCH, 2);
                }
            }

            Inst::StorageNestedMapGet(dst, field, key1, key2) => {
                let slot = self.storage_slots.get(field.as_str()).copied().unwrap_or(0);
                let map_ty = self.storage_types.get(field.as_str()).cloned().unwrap_or(Ty::U64);
                let key1_ty = map_key_type(&map_ty);
                let inner_map_ty = map_value_type(&map_ty);
                let key2_ty = map_key_type(&inner_map_ty);
                let val_ty = map_value_type(&inner_map_ty);
                let key1_wide = is_wide_type(&key1_ty);
                let key2_wide = is_wide_type(&key2_ty);
                let wide_value = is_wide_type(&val_ty);

                // Interleave get_reg with immediate heap writes to prevent
                // r15 clobbering when both keys are spilled.
                // Each key is stored to heap right after get_reg, before the next get_reg.
                let rk1 = self.get_reg(*key1);
                let k1_size = self.emit_key_store(rk1, 12, 8, key1_wide);
                let rk2 = self.get_reg(*key2);
                let k2_offset = 8 + k1_size as i32;
                let k2_size = self.emit_key_store(rk2, 12, k2_offset, key2_wide);
                // Now safe to clobber r15 for slot
                self.emit_op(Opcode::Addi, 15, 0, slot);
                self.emit_store(15, 12, 0);
                let total = 8 + k1_size + k2_size;
                self.emit_op(Opcode::Addi, 14, 0, total);
                self.emit_op(Opcode::Poseidon, WIDE_SCRATCH, 12, 14);

                if wide_value {
                    let wd = self.regs.alloc_wide(*dst);
                    self.emit_op(Opcode::Sload, wd, WIDE_SCRATCH, 0);
                } else {
                    let rd = self.alloc_gp(*dst);
                    self.emit_op(Opcode::Sload, rd, WIDE_SCRATCH, 2);
                }
            }

            Inst::StorageNestedMapSet(field, key1, key2, val) => {
                let slot = self.storage_slots.get(field.as_str()).copied().unwrap_or(0);
                let map_ty = self.storage_types.get(field.as_str()).cloned().unwrap_or(Ty::U64);
                let key1_ty = map_key_type(&map_ty);
                let inner_map_ty = map_value_type(&map_ty);
                let key2_ty = map_key_type(&inner_map_ty);
                let val_ty = map_value_type(&inner_map_ty);
                let key1_wide = is_wide_type(&key1_ty);
                let key2_wide = is_wide_type(&key2_ty);
                let wide_value = is_wide_type(&val_ty);

                // Interleave get_reg with immediate heap writes (same as NestedMapGet)
                let rk1 = self.get_reg(*key1);
                let k1_size = self.emit_key_store(rk1, 12, 8, key1_wide);
                let rk2 = self.get_reg(*key2);
                let k2_offset = 8 + k1_size as i32;
                let k2_size = self.emit_key_store(rk2, 12, k2_offset, key2_wide);
                // Now safe to clobber r15 for slot
                self.emit_op(Opcode::Addi, 15, 0, slot);
                self.emit_store(15, 12, 0);
                let total = 8 + k1_size + k2_size;
                self.emit_op(Opcode::Addi, 14, 0, total);
                self.emit_op(Opcode::Poseidon, WIDE_SCRATCH, 12, 14);

                // Get val AFTER derivation — derivation clobbers r14/r15
                let rv = self.get_reg(*val);
                if wide_value {
                    self.emit_op(Opcode::Sstore, rv, WIDE_SCRATCH, 0);
                } else {
                    self.emit_op(Opcode::Sstore, rv, WIDE_SCRATCH, 2);
                }
            }

            // ==== Builtins (fixed: Callvalue → wide, Caller → GP) ====

            Inst::Builtin(dst, op) => {
                match op {
                    BuiltinOp::MsgSender => {
                        let wd = self.regs.alloc_wide(*dst);
                        self.emit_op(Opcode::Callvalue, wd, 0, 3); // env_wide::CALLER
                    }
                    BuiltinOp::MsgValue => {
                        let wd = self.regs.alloc_wide(*dst);
                        self.emit_op(Opcode::Callvalue, wd, 0, 0); // env_wide::CALL_VALUE
                    }
                    BuiltinOp::MsgData => {
                        // Calldata pointer is in r5
                        let rd = self.alloc_gp(*dst);
                        self.emit_op(Opcode::Add, rd, 5, 0); // rd = r5
                    }
                    BuiltinOp::BlockTimestamp => {
                        let rd = self.alloc_gp(*dst);
                        self.emit_op(Opcode::Caller, rd, 0, 1); // env_gp::TIMESTAMP
                    }
                    BuiltinOp::BlockHeight => {
                        let rd = self.alloc_gp(*dst);
                        self.emit_op(Opcode::Caller, rd, 0, 0); // env_gp::BLOCK_NUMBER
                    }
                    BuiltinOp::BlockProposer => {
                        let wd = self.regs.alloc_wide(*dst);
                        self.emit_op(Opcode::Callvalue, wd, 0, 6); // env_wide::BLOCK_PROPOSER
                    }
                    BuiltinOp::TxGasPrice => {
                        let wd = self.regs.alloc_wide(*dst);
                        self.emit_op(Opcode::Callvalue, wd, 0, 1); // env_wide::GAS_PRICE
                    }
                    BuiltinOp::TxNonce => {
                        let rd = self.alloc_gp(*dst);
                        self.emit_op(Opcode::Caller, rd, 0, 3); // env_gp::TX_NONCE
                    }
                    BuiltinOp::TxHash => {
                        let wd = self.regs.alloc_wide(*dst);
                        self.emit_op(Opcode::Callvalue, wd, 0, 5); // env_wide::TX_HASH
                    }
                    BuiltinOp::TxGasLimit => {
                        let rd = self.alloc_gp(*dst);
                        self.emit_op(Opcode::Caller, rd, 0, 4); // env_gp::TX_GAS_LIMIT
                    }
                    BuiltinOp::AddressOfSelf => {
                        let wd = self.regs.alloc_wide(*dst);
                        self.emit_op(Opcode::Callvalue, wd, 0, 4); // env_wide::ADDRESS
                    }
                    BuiltinOp::GasRemaining => {
                        let rd = self.alloc_gp(*dst);
                        self.emit_op(Opcode::Caller, rd, 0, 2); // env_gp::GAS_REMAINING
                    }
                }
            }

            Inst::Jump(label) => {
                let mapped = self.remap_label(*label);
                self.emit_jump_placeholder(Opcode::Jmp, 0, 0, mapped);
            }

            Inst::Branch(cond, then_label, else_label) => {
                let rc = self.get_reg(*cond);
                let mapped_then = self.remap_label(*then_label);
                let mapped_else = self.remap_label(*else_label);
                self.emit_jump_placeholder(Opcode::Bne, rc, 0, mapped_then);
                self.emit_jump_placeholder(Opcode::Jmp, 0, 0, mapped_else);
            }

            Inst::Return(val) => {
                if let Some(v) = val {
                    let rv = self.get_reg(*v);
                    if rv != 1 {
                        if self.regs.is_wide(*v) {
                            // Wide return: Narrow to GP r1 (traps if > u64::MAX)
                            self.emit_op(Opcode::Narrow, 1, rv, 0);
                        } else {
                            self.emit_op(Opcode::Add, 1, rv, 0);
                        }
                    }
                }
                if is_entry {
                    self.emit_op(Opcode::Halt, 0, 0, 0);
                } else {
                    self.emit_op(Opcode::Ret, 0, 0, 0);
                }
            }

            Inst::Revert(name, fields) => {
                // Encode error data to heap: [selector:8][field0:8][field1:8]...
                // Then pass pointer (r12) and length to PVM Revert opcode.
                let total_len = (1 + fields.len()) * 8; // selector + fields
                let selector = compute_selector(name) as u64;
                self.load_u64_to_reg(15, selector);
                self.emit_store(15, 12, 0);
                for (i, freg) in fields.iter().enumerate() {
                    let fr = self.get_reg(*freg);
                    self.emit_store(fr, 12, ((i + 1) * 8) as i32);
                }
                // r14 = data length
                self.emit_op(Opcode::Addi, 14, 0, total_len as u32);
                // Revert rs1=r12 (pointer), imm[3:0]=r14 (length register)
                self.emit_op(Opcode::Revert, 0, 12, 14);
            }

            Inst::Emit(name, fields) => {
                // Write event descriptor to heap memory, then Log
                // Layout: [topic0: 32 bytes (event name hash)] [data_ptr: 8] [data_len: 8]
                let desc_base = 12; // r12 = heap pointer (descriptor start)

                // Topic 0: hash of event name (simplified: FNV hash widened to 256-bit)
                let name_hash = compute_selector(name) as u64;
                self.load_u64_to_reg(15, name_hash);
                self.emit_store(15, 12, 0);  // store low 8 bytes of topic
                self.emit_op(Opcode::Addi, 15, 0, 0);
                self.emit_store(15, 12, 8);  // zero upper bytes
                self.emit_store(15, 12, 16);
                self.emit_store(15, 12, 24);

                // Data: store field values after descriptor
                let data_start_offset = 32 + 16; // after topic + ptr/len
                for (i, freg) in fields.iter().enumerate() {
                    let fr = self.get_reg(*freg);
                    self.emit_store(fr, 12, (data_start_offset + i * 8) as i32);
                }

                // Write data_ptr and data_len at offset 32
                // data_ptr = r12 + data_start_offset
                self.emit_op(Opcode::Addi, 14, 12, data_start_offset as u32);
                self.emit_store(14, 12, 32); // data_ptr
                let data_len = (fields.len() * 8) as u32;
                self.emit_op(Opcode::Addi, 14, 0, data_len);
                self.emit_store(14, 12, 40); // data_len

                // Log rs1=descriptor pointer, imm=num_topics
                // PVM reads descriptor from rs1, NOT rd
                self.emit_op(Opcode::Log, 0, desc_base, 1);

                // Advance heap past descriptor + data
                let total = data_start_offset as u32 + data_len;
                self.emit_op(Opcode::Addi, 12, 12, total);
            }

            Inst::Call(dst, name, args) => {
                let rd = self.alloc_gp(*dst);
                // Push all args to stack first (avoids register clobbering)
                for arg in args.iter() {
                    let src = self.get_reg(*arg);
                    self.emit_op(Opcode::Push, src, 0, 0);
                }
                // Pop into convention registers (reverse order, stack is LIFO)
                for i in (0..args.len()).rev() {
                    let dst_phys = (i as u8) + 2;
                    self.emit_op(Opcode::Pop, dst_phys, 0, 0);
                }
                // Call (PVM pushes return frame, jumps to target)
                if let Some(&label) = self.func_labels.get(name.as_str()) {
                    let offset = self.current_offset();
                    self.emit_op(Opcode::Call, 0, 0, 0); // placeholder
                    self.fixups.push((offset, label));
                } else {
                    // Unknown function (built-in or external) — placeholder
                    self.emit_op(Opcode::Addi, rd, 0, 0);
                }
                // Return value in r1 → move to destination
                if rd != 1 {
                    self.emit_op(Opcode::Add, rd, 1, 0);
                }
            }

            Inst::Hash(dst, args) => {
                let wd = self.regs.alloc_wide(*dst);
                // Write hash arguments to heap memory
                for (i, arg) in args.iter().enumerate() {
                    let r = self.get_reg(*arg);
                    self.emit_store(r, 12, (i as i32) * 8);
                }
                let byte_len = (args.len() * 8) as u32;
                // Set up Poseidon: wd = poseidon(mem[r12..r12+len])
                // r14 = length in bytes
                self.emit_op(Opcode::Addi, 14, 0, byte_len);
                // Poseidon: encode(Poseidon, wd, base_reg, len_reg_index)
                self.emit_op(Opcode::Poseidon, wd, 12, 14); // len_reg = r14
                // Don't advance heap (temporary data, will be overwritten)
            }

            Inst::Cast(dst, src, ty) => {
                let src_wide = self.regs.is_wide(*src);
                let dst_wide = is_wide_type(ty);

                if !src_wide && dst_wide {
                    // GP → Wide: Widen
                    let wd = self.regs.alloc_wide(*dst);
                    let rs = self.get_reg(*src);
                    self.emit_op(Opcode::Widen, wd, rs, 0);
                } else if src_wide && !dst_wide {
                    // Wide → GP: Narrow (traps if > u64::MAX)
                    let rd = self.alloc_gp(*dst);
                    let ws = self.get_reg(*src);
                    self.emit_op(Opcode::Narrow, rd, ws, 0);
                } else {
                    // Same register file: copy
                    let rd = self.alloc_gp(*dst);
                    let rs = self.get_reg(*src);
                    if rd != rs {
                        self.emit_op(Opcode::Add, rd, rs, 0);
                    }
                }
            }

            Inst::StructInit(dst, _name, fields) => {
                let rd = self.alloc_gp(*dst);
                let struct_size = (fields.len() as u32) * memory::WORD_SIZE;
                // Allocate on heap: rd = heap_ptr; heap_ptr += struct_size
                self.emit_op(Opcode::Add, rd, 12, 0);
                self.emit_op(Opcode::Addi, 12, 12, struct_size);
                for (i, (fname, freg)) in fields.iter().enumerate() {
                    let fr = self.get_reg(*freg);
                    let offset = (i as u32) * memory::WORD_SIZE;
                    self.emit_store(fr, rd, offset as i32);
                }
            }

            Inst::FieldGet(dst, obj, field) => {
                let rd = self.alloc_gp(*dst);
                let ro = self.get_reg(*obj);
                // Numeric field name (e.g., "0", "1") = tuple index access
                let offset = if let Ok(idx) = field.parse::<u32>() {
                    idx * memory::WORD_SIZE as u32
                } else {
                    // Named field: look up in struct_defs
                    self.field_offsets.get(field.as_str())
                        .copied()
                        .unwrap_or(0)
                };
                self.emit_load(rd, ro, offset as i32);
            }

            Inst::IndexGet(dst, obj, idx) => {
                let rd = self.alloc_gp(*dst);
                let ro = self.get_reg(*obj);
                let ri = self.get_reg(*idx);
                // addr = base + idx * 8
                self.emit_op(Opcode::Addi, 14, 0, 3);
                self.emit_op(Opcode::Shl, 15, ri, 14);
                self.emit_op(Opcode::Add, 15, ro, 15);
                self.emit_load(rd, 15, 0);
            }

            Inst::IndexSet(obj, idx, val) => {
                let ro = self.get_reg(*obj);
                let ri = self.get_reg(*idx);
                let rv = self.get_reg(*val);
                self.emit_op(Opcode::Addi, 14, 0, 3);
                self.emit_op(Opcode::Shl, 15, ri, 14);
                self.emit_op(Opcode::Add, 15, ro, 15);
                self.emit_store(rv, 15, 0);
            }

            Inst::MakeTuple(dst, regs) => {
                let rd = self.alloc_gp(*dst);
                let size = (regs.len() as u32) * memory::WORD_SIZE;
                self.emit_op(Opcode::Add, rd, 12, 0);
                self.emit_op(Opcode::Addi, 12, 12, size);
                for (i, reg) in regs.iter().enumerate() {
                    let r = self.get_reg(*reg);
                    let offset = (i as u32) * memory::WORD_SIZE;
                    self.emit_store(r, rd, offset as i32);
                }
            }

            Inst::TupleGet(dst, tuple, idx) => {
                let rd = self.alloc_gp(*dst);
                let rt = self.get_reg(*tuple);
                let offset = (*idx) * (memory::WORD_SIZE as u32);
                self.emit_load(rd, rt, offset as i32);
            }

            Inst::MakeArray(dst, regs) => {
                let rd = self.alloc_gp(*dst);
                let size = (regs.len() as u32) * memory::WORD_SIZE;
                self.emit_op(Opcode::Add, rd, 12, 0);
                self.emit_op(Opcode::Addi, 12, 12, size);
                for (i, reg) in regs.iter().enumerate() {
                    let r = self.get_reg(*reg);
                    let offset = (i as u32) * memory::WORD_SIZE;
                    self.emit_store(r, rd, offset as i32);
                }
            }

            Inst::ArrayRepeat(dst, val, count) => {
                let rd = self.alloc_gp(*dst);
                let rv = self.get_reg(*val);
                let size = (*count as u32) * memory::WORD_SIZE;
                self.emit_op(Opcode::Add, rd, 12, 0);
                self.emit_op(Opcode::Addi, 12, 12, size);
                for i in 0..*count {
                    let offset = (i as u32) * memory::WORD_SIZE;
                    self.emit_store(rv, rd, offset as i32);
                }
            }

            Inst::MethodCall(dst, obj, method, args) => {
                let rd = self.alloc_gp(*dst);
                let ro = self.get_reg(*obj);

                match method.as_str() {
                    "push" if !args.is_empty() => {
                        let val_reg = self.get_reg(args[0]);
                        // Load length and capacity
                        self.emit_load(memory::REG_SCRATCH_1, ro, memory::VEC_LENGTH_OFFSET as i32);  // r15 = length
                        self.emit_load(memory::REG_SCRATCH_0, ro, memory::VEC_CAPACITY_OFFSET as i32); // r14 = capacity

                        // Branch: length < capacity → fast path, else → realloc
                        let fast_label = self.alloc_label();
                        let realloc_label = self.alloc_label();
                        let write_label = self.alloc_label();

                        self.emit_op(Opcode::Lt, 15, memory::REG_SCRATCH_1, memory::REG_SCRATCH_0 as u32);
                        self.emit_jump_placeholder(Opcode::Bne, 15, 0, fast_label);
                        self.emit_jump_placeholder(Opcode::Jmp, 0, 0, realloc_label);

                        // === Realloc: allocate 2x block, Memcpy old data, update pointer ===
                        self.mark_label(realloc_label);
                        // Step 1: compute new_cap = old_cap * 2 → r14
                        self.emit_load(memory::REG_SCRATCH_0, ro, memory::VEC_CAPACITY_OFFSET as i32); // r14 = old cap
                        self.emit_op(Opcode::Addi, 15, 0, 1);
                        self.emit_op(Opcode::Shl, memory::REG_SCRATCH_0, memory::REG_SCRATCH_0, 15); // r14 = cap*2
                        // Step 2: write new header at r12 (new base)
                        self.emit_load(memory::REG_SCRATCH_1, ro, memory::VEC_LENGTH_OFFSET as i32); // r15 = length
                        self.emit_store(memory::REG_SCRATCH_1, 12, memory::VEC_LENGTH_OFFSET as i32); // new.length
                        self.emit_store(memory::REG_SCRATCH_0, 12, memory::VEC_CAPACITY_OFFSET as i32); // new.capacity
                        // Step 3: compute memcpy args — r13 = byte count, r14 = dst, r15 = src
                        // r13 = length * 8
                        self.emit_op(Opcode::Addi, 13, 0, 3);
                        self.emit_op(Opcode::Shl, 13, memory::REG_SCRATCH_1, 13); // r13 = length * 8
                        // r14 = new data start = r12 + 16
                        self.emit_op(Opcode::Addi, memory::REG_SCRATCH_0, 12, memory::VEC_DATA_OFFSET);
                        // r15 = old data start = ro + 16
                        self.emit_op(Opcode::Addi, memory::REG_SCRATCH_1, ro, memory::VEC_DATA_OFFSET);
                        // Step 4: Memcpy rd=r14(dst), rs1=r15(src), imm[3:0]=13(len reg)
                        self.emit_op(Opcode::Memcpy, memory::REG_SCRATCH_0, memory::REG_SCRATCH_1, 13);
                        // Step 5: update ro and advance heap
                        // Reload new_cap from new header for heap advance
                        self.emit_load(memory::REG_SCRATCH_0, 12, memory::VEC_CAPACITY_OFFSET as i32); // r14 = new_cap
                        self.emit_op(Opcode::Add, ro, 12, 0); // ro = new Vec base
                        self.emit_op(Opcode::Addi, 15, 0, 3);
                        self.emit_op(Opcode::Shl, 15, memory::REG_SCRATCH_0, 15); // r15 = new_cap * 8
                        self.emit_op(Opcode::Addi, 15, 15, memory::VEC_DATA_OFFSET);
                        self.emit_op(Opcode::Add, 12, 12, 15); // r12 += header + data
                        // Reload length for write
                        self.emit_load(memory::REG_SCRATCH_1, ro, memory::VEC_LENGTH_OFFSET as i32);
                        self.emit_jump_placeholder(Opcode::Jmp, 0, 0, write_label);

                        // === Fast path (no realloc) ===
                        self.mark_label(fast_label);
                        self.emit_load(memory::REG_SCRATCH_1, ro, memory::VEC_LENGTH_OFFSET as i32);

                        // === Write value at data[length] ===
                        self.mark_label(write_label);
                        self.emit_op(Opcode::Addi, memory::REG_SCRATCH_0, 0, 3);
                        self.emit_op(Opcode::Shl, memory::REG_SCRATCH_0, memory::REG_SCRATCH_1, memory::REG_SCRATCH_0 as u32);
                        self.emit_op(Opcode::Add, memory::REG_SCRATCH_0, ro, memory::REG_SCRATCH_0 as u32);
                        self.emit_op(Opcode::Addi, memory::REG_SCRATCH_0, memory::REG_SCRATCH_0, memory::VEC_DATA_OFFSET);
                        self.emit_store(val_reg, memory::REG_SCRATCH_0, 0);
                        // Increment length
                        self.emit_op(Opcode::Addi, memory::REG_SCRATCH_1, memory::REG_SCRATCH_1, 1);
                        self.emit_store(memory::REG_SCRATCH_1, ro, memory::VEC_LENGTH_OFFSET as i32);
                    }
                    "pop" => {
                        // Load length, assert > 0
                        self.emit_load(memory::REG_SCRATCH_1, ro, memory::VEC_LENGTH_OFFSET as i32);
                        self.emit_op(Opcode::Assert, 0, memory::REG_SCRATCH_1, 0); // revert if empty
                        // Decrement length: Addi with sign-extended -1 (0x3FFFF in 18-bit = -1)
                        self.emit_op(Opcode::Addi, memory::REG_SCRATCH_1, memory::REG_SCRATCH_1, 0x3FFFF);
                        self.emit_store(memory::REG_SCRATCH_1, ro, memory::VEC_LENGTH_OFFSET as i32);
                        // Load popped value from data[new_length]
                        self.emit_op(Opcode::Addi, memory::REG_SCRATCH_0, 0, 3);
                        self.emit_op(Opcode::Shl, memory::REG_SCRATCH_0, memory::REG_SCRATCH_1, memory::REG_SCRATCH_0 as u32);
                        self.emit_op(Opcode::Add, memory::REG_SCRATCH_0, ro, memory::REG_SCRATCH_0 as u32);
                        self.emit_op(Opcode::Addi, memory::REG_SCRATCH_0, memory::REG_SCRATCH_0, memory::VEC_DATA_OFFSET);
                        self.emit_load(rd, memory::REG_SCRATCH_0, 0);
                    }
                    "len" => {
                        self.emit_load(rd, ro, memory::VEC_LENGTH_OFFSET as i32);
                    }
                    "is_empty" => {
                        self.emit_load(memory::REG_SCRATCH_1, ro, memory::VEC_LENGTH_OFFSET as i32);
                        self.emit_op(Opcode::Eq, rd, memory::REG_SCRATCH_1, 0);
                    }
                    _ => {
                        for arg in args {
                            let r = self.get_reg(*arg);
                            self.emit_op(Opcode::Push, r, 0, 0);
                        }
                        self.emit_op(Opcode::Addi, rd, 0, 0);
                    }
                }
            }

            Inst::ExtCall(dst, addr, method, args) => {
                let rd = self.alloc_gp(*dst);
                let ra = self.get_reg(*addr);

                // Write calldata to heap: [selector(4 BE bytes)][arg0(8 LE)][arg1(8 LE)]...
                // Selector: FNV-1a hash stored as BE bytes in calldata (dispatch
                // loads with W32 LE and compares against selector.swap_bytes()).
                let selector = compute_selector(method);
                // Store selector bytes in BE order to match the dispatch convention
                let sel_be = selector.to_be_bytes();
                let sel_as_le_u32 = u32::from_le_bytes(sel_be); // reinterpret BE bytes as LE u32
                self.load_u32_to_reg(15, sel_as_le_u32);
                let sel_imm = encode_mem_immediate(0, MemWidth::W32).unwrap();
                self.emit(encode(Opcode::Store, 15, 12, sel_imm));

                // Write args after selector (offset 4)
                for (i, arg) in args.iter().enumerate() {
                    let r = self.get_reg(*arg);
                    self.emit_store(r, 12, 4 + (i as i32) * 8);
                }
                let calldata_len = 4 + (args.len() as u32) * 8;

                // Set up CallExt: rd=target(wide), rs1=calldata_ptr(r12), imm=len/gas/result
                self.emit_op(Opcode::Addi, 14, 0, calldata_len);  // r14 = calldata len
                self.emit_op(Opcode::Caller, 15, 0, 2);           // r15 = gas_remaining
                let imm = (14 & 0xF)           // len_reg = r14
                    | ((15 & 0xF) << 4)         // gas_reg = r15
                    | ((13 & 0xF) << 8);        // result_reg = r13
                self.emit_op(Opcode::CallExt, ra, 12, imm);

                // Advance heap past calldata
                self.emit_op(Opcode::Addi, 12, 12, calldata_len);

                // After CallExt, r1 = child's return value (set by PVM convention)
                if rd != 1 {
                    self.emit_op(Opcode::Add, rd, 1, 0);
                }
            }

            Inst::CrossCall { target, method, args, .. } => {
                let rt = self.get_reg(*target);
                let rm = self.get_reg(*method);
                for arg in args {
                    let r = self.get_reg(*arg);
                    self.emit_op(Opcode::Push, r, 0, 0);
                }
                // Use Log as async message queue placeholder
                self.emit_op(Opcode::Log, rt, rm, 0);
            }

            Inst::RawCall(dst, target, args) => {
                let rd = self.alloc_gp(*dst);
                // Target is an Address (wide register)
                let rt = self.get_reg(*target);

                // Write calldata (args) to heap memory at r12
                for (i, arg) in args.iter().enumerate() {
                    let r = self.get_reg(*arg);
                    if self.regs.is_wide(*arg) {
                        self.emit_op(Opcode::Wstore, r, 12, (i as u32 * 32) & 0x3FFFF);
                    } else {
                        self.emit_store(r, 12, (i as i32) * 8);
                    }
                }
                let calldata_len = (args.len() * 8) as u32;

                // Set up CallExt encoding:
                // rd = target address (wide register)
                // rs1 = calldata pointer (r12 = heap)
                // imm[3:0] = len register, imm[7:4] = gas register, imm[11:8] = result register
                self.emit_op(Opcode::Addi, 14, 0, calldata_len);  // r14 = calldata len
                self.emit_op(Opcode::Caller, 15, 0, 2);           // r15 = gas_remaining
                let imm = (14 & 0xF)           // len_reg = r14
                    | ((15 & 0xF) << 4)         // gas_reg = r15
                    | ((13 & 0xF) << 8);        // result_reg = r13
                self.emit_op(Opcode::CallExt, rt, 12, imm);

                // Advance heap past calldata
                self.emit_op(Opcode::Addi, 12, 12, calldata_len);

                // After CallExt, r1 = child's return value
                if rd != 1 {
                    self.emit_op(Opcode::Add, rd, 1, 0);
                }
            }

            Inst::CreateContract(dst, blob_reg, args) => {
                // The blob register holds an IrConst::Bytes value.
                // At codegen time, the Const handler has already written the blob to heap.
                // blob_reg points to the heap location of the deploy-format bytes.
                // We need to: write constructor args after the blob, then Create.
                let wd = self.regs.alloc_wide(*dst);
                let rb = self.get_reg(*blob_reg); // GP reg with blob heap pointer

                // The Const(blob_reg, Bytes(data)) handler writes data to heap[r12]
                // and sets blob_reg = r12, then advances r12.
                // Now r12 is right after the blob — perfect for appending args.

                // Write constructor args (LE u64 each) after the blob
                for (i, arg) in args.iter().enumerate() {
                    let ra = self.get_reg(*arg);
                    self.emit_store(ra, 12, (i as i32) * 8);
                }
                let args_size = (args.len() as u32) * 8;

                // Total length = blob_size (r12 - rb) + args_size
                // r14 = r12 - rb (blob size)
                self.emit_op(Opcode::Sub, 14, 12, rb as u32);
                // r14 += args_size (total deploy data length)
                if args_size > 0 {
                    self.emit_op(Opcode::Addi, 14, 14, args_size);
                    self.emit_op(Opcode::Addi, 12, 12, args_size); // advance heap past args
                }

                // Create: wd = new address, rs1 = blob pointer, imm[3:0] = length register (r14)
                self.emit_op(Opcode::Create, wd, rb, 14 & 0xF);
            }

            Inst::MakeVec(dst, cap) => {
                let rd = self.alloc_gp(*dst);
                let total_size = 16 + (*cap as u32) * memory::WORD_SIZE; // header + data slots
                // rd = current heap pointer (Vec base)
                self.emit_op(Opcode::Add, rd, 12, 0);
                // Store length = 0
                self.emit_op(Opcode::Addi, 15, 0, 0);
                self.emit_store(15, rd, memory::VEC_LENGTH_OFFSET as i32);
                // Store capacity
                self.load_u32_to_reg(15, *cap as u32);
                self.emit_store(15, rd, memory::VEC_CAPACITY_OFFSET as i32);
                // Advance heap past header + data slots
                self.load_u32_to_reg(15, total_size);
                self.emit_op(Opcode::Add, 12, 12, 15);
            }

            Inst::Comment(_) => {}
            Inst::Phi(_, _) => {}
        }
    }

    // ========================================================================
    // Emit helpers
    // ========================================================================

    /// Allocate a GP register for a virtual register, emitting spill Store if eviction needed.
    fn alloc_gp(&mut self, vreg: Reg) -> u8 {
        let (phys, spill) = self.regs.alloc(vreg);
        if let Some(SpillAction::Save(reg, slot)) = spill {
            // Store evicted register to spill area: mem[r13 + slot*8] = reg
            let offset = (slot * 8) as i32;
            let imm = encode_mem_immediate(offset, MemWidth::W64).unwrap();
            self.instructions.push(encode(Opcode::Store, reg, 13, imm));
        }
        phys
    }

    /// Get the physical register for a virtual register, emitting spill Load if needed.
    /// Restores to r15 by default. Use `get_reg_to` when you need a different target
    /// (e.g., when two operands might both be spilled and would clobber each other).
    fn get_reg(&mut self, vreg: Reg) -> u8 {
        self.get_reg_to(vreg, 15)
    }

    /// Get the physical register for a virtual register, restoring to `restore_to` if spilled.
    /// Use different restore targets when an instruction has multiple source operands
    /// that could both be spilled (prevents second restore from clobbering the first).
    fn get_reg_to(&mut self, vreg: Reg, restore_to: u8) -> u8 {
        match self.regs.get_or_spilled(vreg) {
            Ok(phys) => phys,
            Err(RestoreAction::Restore(_, slot)) => {
                let offset = (slot * 8) as i32;
                let imm = encode_mem_immediate(offset, MemWidth::W64).unwrap();
                self.instructions.push(encode(Opcode::Load, restore_to, 13, imm));
                restore_to
            }
        }
    }

    fn emit(&mut self, inst: Instruction) {
        self.instructions.push(inst);
    }

    fn emit_op(&mut self, op: Opcode, rd: u8, rs1: u8, rs2_or_imm: u32) {
        self.emit(encode(op, rd, rs1, rs2_or_imm & 0x3FFFF));
    }

    fn emit_load(&mut self, rd: u8, base: u8, offset: i32) {
        let imm = encode_mem_immediate(offset, MemWidth::W64).unwrap();
        self.emit(encode(Opcode::Load, rd, base, imm));
    }

    fn emit_store(&mut self, val: u8, base: u8, offset: i32) {
        let imm = encode_mem_immediate(offset, MemWidth::W64).unwrap();
        self.emit(encode(Opcode::Store, val, base, imm));
    }

    fn current_offset(&self) -> usize {
        self.instructions.len()
    }

    fn emit_jump_placeholder(&mut self, op: Opcode, rd: u8, rs1: u8, target: Label) {
        let idx = self.current_offset();
        self.emit_op(op, rd, rs1, 0);
        self.fixups.push((idx, target));
    }

    fn mark_label(&mut self, label: Label) {
        self.label_offsets.insert(label, self.current_offset());
    }

    fn resolve_fixups(&mut self) {
        for (inst_idx, label) in &self.fixups {
            if let Some(&target_offset) = self.label_offsets.get(label) {
                let target_bytes = (target_offset * 4) as i32;
                let inst_bytes = (*inst_idx * 4) as i32;
                let relative_offset = target_bytes - inst_bytes;

                let old = self.instructions[*inst_idx];
                let opcode_bits = (old.0 >> 26) & 0x3F;
                let rd_bits = (old.0 >> 22) & 0xF;
                let rs1_bits = (old.0 >> 18) & 0xF;
                let offset_bits = (relative_offset as u32) & 0x3FFFF;
                let new_word = (opcode_bits << 26)
                    | (rd_bits << 22)
                    | (rs1_bits << 18)
                    | offset_bits;
                self.instructions[*inst_idx] = Instruction(new_word);
            }
        }
    }

    /// Load a u32 into a GP register (handles > 17-bit values).
    /// PVM's Addi sign-extends the 18-bit immediate, so max positive is 0x1FFFF (131071).
    fn load_u32_to_reg(&mut self, rd: u8, val: u32) {
        if val <= 0x1FFFF {
            self.emit_op(Opcode::Addi, rd, 0, val);
        } else {
            let scratch = if rd == 15 { 14 } else { 15 };
            let low = val & 0x1FFFF;
            let high = val >> 17;
            self.emit_op(Opcode::Addi, rd, 0, high);
            self.emit_op(Opcode::Addi, scratch, 0, 17);
            self.emit_op(Opcode::Shl, rd, rd, scratch as u32);
            if low > 0 {
                self.emit_op(Opcode::Addi, scratch, 0, low);
                self.emit_op(Opcode::Or, rd, rd, scratch as u32);
            }
        }
    }

    /// Load a u64 into a GP register (handles full 64-bit range).
    /// Uses 17-bit chunks to avoid PVM Addi sign extension.
    /// Uses r15 as scratch (or r14 if rd==15) to avoid self-clobbering.
    fn load_u64_to_reg(&mut self, rd: u8, val: u64) {
        if val <= 0x1FFFF {
            self.emit_op(Opcode::Addi, rd, 0, val as u32);
            return;
        }

        // Scratch register: use r15 normally, r14 if rd==15 (avoid self-clobber)
        let scratch = if rd == 15 { 14 } else { 15 };

        let chunk0 = (val & 0x1FFFF) as u32;
        let chunk1 = ((val >> 17) & 0x1FFFF) as u32;
        let chunk2 = ((val >> 34) & 0x1FFFF) as u32;
        let chunk3 = ((val >> 51) & 0x1FFF) as u32;

        if chunk3 > 0 {
            self.emit_op(Opcode::Addi, rd, 0, chunk3);
            self.emit_op(Opcode::Addi, scratch, 0, 17);
            self.emit_op(Opcode::Shl, rd, rd, scratch as u32);
            self.emit_op(Opcode::Addi, scratch, 0, chunk2);
            self.emit_op(Opcode::Or, rd, rd, scratch as u32);
            self.emit_op(Opcode::Addi, scratch, 0, 17);
            self.emit_op(Opcode::Shl, rd, rd, scratch as u32);
            self.emit_op(Opcode::Addi, scratch, 0, chunk1);
            self.emit_op(Opcode::Or, rd, rd, scratch as u32);
            self.emit_op(Opcode::Addi, scratch, 0, 17);
            self.emit_op(Opcode::Shl, rd, rd, scratch as u32);
            if chunk0 > 0 {
                self.emit_op(Opcode::Addi, scratch, 0, chunk0);
                self.emit_op(Opcode::Or, rd, rd, scratch as u32);
            }
        } else if chunk2 > 0 {
            self.emit_op(Opcode::Addi, rd, 0, chunk2);
            self.emit_op(Opcode::Addi, scratch, 0, 17);
            self.emit_op(Opcode::Shl, rd, rd, scratch as u32);
            self.emit_op(Opcode::Addi, scratch, 0, chunk1);
            self.emit_op(Opcode::Or, rd, rd, scratch as u32);
            self.emit_op(Opcode::Addi, scratch, 0, 17);
            self.emit_op(Opcode::Shl, rd, rd, scratch as u32);
            if chunk0 > 0 {
                self.emit_op(Opcode::Addi, scratch, 0, chunk0);
                self.emit_op(Opcode::Or, rd, rd, scratch as u32);
            }
        } else {
            self.emit_op(Opcode::Addi, rd, 0, chunk1);
            self.emit_op(Opcode::Addi, scratch, 0, 17);
            self.emit_op(Opcode::Shl, rd, rd, scratch as u32);
            if chunk0 > 0 {
                self.emit_op(Opcode::Addi, scratch, 0, chunk0);
                self.emit_op(Opcode::Or, rd, rd, scratch as u32);
            }
        }
    }

    /// Derive a map storage key: w7 = poseidon2(slot || key).
    /// Writes slot + key to heap memory, hashes them, result in w7.
    /// Store a register value to heap at the given offset.
    /// Uses Wstore for wide types (32 bytes), Store for GP types (8 bytes).
    /// Returns the number of bytes written.
    fn emit_key_store(&mut self, reg: u8, base: u8, offset: i32, wide: bool) -> u32 {
        if wide {
            // Wstore takes a plain byte offset (sign-extended 18-bit), NOT encode_mem_immediate
            self.emit_op(Opcode::Wstore, reg, base, (offset as u32) & 0x3FFFF);
            32
        } else {
            self.emit_store(reg, base, offset);
            8
        }
    }

    /// Derive a map storage key: w7 = poseidon2(slot || key).
    /// Handles any key type (GP or wide).
    ///
    /// CRITICAL: Writes key to heap FIRST (at offset 8), then slot (at offset 0).
    /// key_reg might be r15 (spilled register restore target), and the slot load
    /// clobbers r15. By consuming key_reg first, we avoid losing the key value.
    /// Memory layout is unchanged: [slot:0-8][key:8-N].
    fn emit_map_key_derivation(&mut self, slot: u32, key_reg: u8, key_wide: bool) {
        // Store key FIRST at offset 8 — key_reg might be r15, consumed before clobber
        let key_size = self.emit_key_store(key_reg, 12, 8, key_wide);
        // Now safe to clobber r15 for slot
        self.emit_op(Opcode::Addi, 15, 0, slot);
        self.emit_store(15, 12, 0);
        // Hash: poseidon(heap[r12..r12+8+key_size])
        let total = 8 + key_size;
        self.emit_op(Opcode::Addi, 14, 0, total);
        self.emit_op(Opcode::Poseidon, WIDE_SCRATCH, 12, 14);
    }

}

// ============================================================================
// Helper functions
// ============================================================================

/// Check if a type uses wide (256-bit) register.
fn is_wide_type(ty: &Ty) -> bool {
    matches!(ty, Ty::U256 | Ty::I256 | Ty::Address | Ty::Bytes)
}

/// Extract value type from a Map type.
fn map_value_type(ty: &Ty) -> Ty {
    if let Ty::Map(_, v) = ty {
        *v.clone()
    } else {
        Ty::U64
    }
}

/// Extract key type from a Map type.
fn map_key_type(ty: &Ty) -> Ty {
    if let Ty::Map(k, _) = ty {
        *k.clone()
    } else {
        Ty::U64
    }
}

/// Compute byte size of a struct field.
fn field_byte_size(ty: &Ty) -> u32 {
    if is_wide_type(ty) {
        memory::WIDE_SIZE
    } else {
        memory::WORD_SIZE
    }
}

/// Compute a function selector (FNV-1a hash of name).
pub fn compute_selector(name: &str) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for byte in name.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
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
        codegen.emit_guards = false;
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

    fn run_pvm(bytecode: &[u8]) -> pyde_vm::vm::Vm {
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000);
        vm.load(bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => { steps += 1; if steps > 1000 { break; } }
                Err(_) => break,
            }
        }
        vm
    }

    fn run_pvm_with_context(bytecode: &[u8], ctx: pyde_vm::vm::ExecutionContext) -> pyde_vm::vm::Vm {
        let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000, ctx);
        vm.load(bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => { steps += 1; if steps > 1000 { break; } }
                Err(_) => break,
            }
        }
        vm
    }

    // ========================================================================
    // Basic PVM-verified tests (arithmetic, branches, loops)
    // ========================================================================

    #[test]
    fn pvm_return_42() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 { return 42; }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 42);
    }

    #[test]
    fn pvm_arithmetic() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    let a = 10;
                    let b = 20;
                    return a + b;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 30);
    }

    #[test]
    fn pvm_subtraction() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    let a = 100;
                    let b = 37;
                    return a - b;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 63);
    }

    #[test]
    fn pvm_multiplication() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    return 7 * 6;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 42);
    }

    #[test]
    fn pvm_division() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    return 100 / 3;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 33);
    }

    #[test]
    fn pvm_modulo() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    return 100 % 7;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 2);
    }

    #[test]
    fn pvm_comparison_gt() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    if 10 > 5 { return 1; }
                    return 0;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1);
    }

    #[test]
    fn pvm_comparison_lt() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    if 3 < 7 { return 1; }
                    return 0;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1);
    }

    #[test]
    fn pvm_comparison_eq() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    if 42 == 42 { return 1; }
                    return 0;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1);
    }

    #[test]
    fn pvm_comparison_neq() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    if 42 != 43 { return 1; }
                    return 0;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1);
    }

    #[test]
    fn pvm_multiple_branches() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    let x = 15;
                    if x > 20 { return 1; }
                    if x > 10 { return 2; }
                    return 3;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 2);
    }

    #[test]
    fn pvm_nested_arithmetic() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    let a = 100;
                    let b = 30;
                    let c = a - b;
                    let d = c * 2;
                    return d;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 140);
    }

    // ========================================================================
    // Loops (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_for_loop() {
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let mut x = 0;
                    for i in 0..3 {
                        x = x + 1;
                    }
                    return x;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 3);
    }

    #[test]
    fn pvm_while_loop() {
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
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 128);
    }

    #[test]
    fn pvm_mutable_var() {
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
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 30);
    }

    // ========================================================================
    // Unary operations (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_logical_not() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    let x = !true;
                    if x { return 1; }
                    return 0;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 0);
    }

    #[test]
    fn pvm_bitwise_ops() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    let a: u64 = 0xFF;
                    let b: u64 = 0x0F;
                    return a & b;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 0x0F);
    }

    // ========================================================================
    // Revert (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_revert() {
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
        assert!(matches!(result, Some(pyde_vm::vm::ExecResult::Revert)));
    }

    // ========================================================================
    // Gas remaining builtin (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_gas_remaining() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 { return gas_remaining(); }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert!(vm.cpu.read_gp(1) > 0);
    }

    // ========================================================================
    // Storage operations (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_storage_write_read() {
        let compiled = compile_no_opt(r#"
            contract T {
                storage { value: u64, }
                pub fn f() -> u64 {
                    self.value = 42;
                    return self.value;
                }
            }
        "#);
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: [1u8; 32],
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        assert_eq!(vm.cpu.read_gp(1), 42, "storage write+read should return 42");
    }

    #[test]
    fn pvm_storage_multiple_fields() {
        let compiled = compile_no_opt(r#"
            contract T {
                storage { a: u64, b: u64, }
                pub fn f() -> u64 {
                    self.a = 10;
                    self.b = 20;
                    return self.a + self.b;
                }
            }
        "#);
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: [2u8; 32],
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        assert_eq!(vm.cpu.read_gp(1), 30, "a + b should be 30");
    }

    // ========================================================================
    // Struct operations (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_struct_init_field_access() {
        let compiled = compile(r#"
            contract T {
                struct Point { x: u64, y: u64, }
                pub fn f() -> u64 {
                    let p = Point { x: 10, y: 20 };
                    return p.x;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 10, "p.x should be 10");
    }

    #[test]
    fn pvm_struct_second_field() {
        let compiled = compile(r#"
            contract T {
                struct Point { x: u64, y: u64, }
                pub fn f() -> u64 {
                    let p = Point { x: 10, y: 20 };
                    return p.y;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 20, "p.y should be 20");
    }

    // ========================================================================
    // Tuple operations (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_tuple_destructuring() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    let (a, b, c) = (10, 20, 30);
                    return b;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 20, "second tuple element should be 20");
    }

    #[test]
    fn pvm_tuple_dot_access() {
        // Test tuple .0/.1/.2 field access syntax
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    let t = (10, 20, 30);
                    return t.1;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 20, "t.1 should be 20");
    }

    // ========================================================================
    // Array operations (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_array_index() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    let arr = [10, 20, 30];
                    return arr[2];
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 30, "arr[2] should be 30");
    }

    // ========================================================================
    // Large constants (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_large_constant_18bit() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    return 262143;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 262143, "max 18-bit value");
    }

    #[test]
    fn pvm_large_constant_32bit() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    return 1000000;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1000000, "1 million");
    }

    #[test]
    fn pvm_large_constant_max_u64() {
        // Test with a value that requires all 4 chunks
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    return 1152921504606846975;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1152921504606846975u64);
    }

    // ========================================================================
    // Cast operations (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_cast_gp_copy() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    let a: u64 = 42;
                    let b = a as u64;
                    return b;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 42);
    }

    // ========================================================================
    // Block context builtins (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_block_timestamp() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    return block.timestamp;
                }
            }
        "#);
        let ctx = pyde_vm::vm::ExecutionContext {
            timestamp: 1234567890,
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        assert_eq!(vm.cpu.read_gp(1), 1234567890);
    }

    #[test]
    fn pvm_block_height() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    return block.height;
                }
            }
        "#);
        let ctx = pyde_vm::vm::ExecutionContext {
            block_number: 42,
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        assert_eq!(vm.cpu.read_gp(1), 42);
    }

    // ========================================================================
    // Function dispatch + selectors
    // ========================================================================

    #[test]
    fn codegen_selectors() {
        let compiled = compile(r#"
            contract T {
                #[constructor]
                pub fn init() {}
                pub fn transfer() {}
                pub fn balance_of() -> u64 { return 0; }
                fn internal_helper() {}
            }
        "#);
        assert_eq!(compiled.selectors.len(), 2);
        let names: Vec<&str> = compiled.selectors.iter().map(|s| s.1.as_str()).collect();
        assert!(names.contains(&"transfer"));
        assert!(names.contains(&"balance_of"));
    }

    #[test]
    fn codegen_produces_valid_bytecode() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 { return 42; }
            }
        "#);
        assert_eq!(compiled.bytecode.len(), compiled.instruction_count * 4);
        assert!(compiled.bytecode.len() > 0);
    }

    #[test]
    fn codegen_minimal_contract() {
        let compiled = compile(r#"
            contract Token {
                storage { supply: u256, }
                #[constructor]
                pub fn init() { self.supply = 1000; }
                #[view]
                pub fn get_supply() -> u256 { return self.supply; }
            }
        "#);
        assert_eq!(compiled.name, "Token");
        assert!(compiled.bytecode.len() > 0);
        assert_eq!(compiled.selectors.len(), 1);
        assert_eq!(compiled.selectors[0].1, "get_supply");
    }

    // ========================================================================
    // Additional PVM-verified tests for remaining features
    // ========================================================================

    #[test]
    fn pvm_bitwise_or_xor_shl_shr() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    let a: u64 = 0x0F;
                    let b: u64 = 0xF0;
                    let c = a | b;
                    if c == 255 { return 1; }
                    return 0;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1, "0x0F | 0xF0 = 0xFF = 255");
    }

    #[test]
    fn pvm_shift_left() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    let a: u64 = 1;
                    let b: u64 = 10;
                    return a << b;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1024, "1 << 10 = 1024");
    }

    #[test]
    fn pvm_shift_right() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    let a: u64 = 1024;
                    let b: u64 = 3;
                    return a >> b;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 128, "1024 >> 3 = 128");
    }

    #[test]
    fn pvm_index_set() {
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let mut arr = [10, 20, 30];
                    arr[1] = 99;
                    return arr[1];
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 99, "arr[1] after set should be 99");
    }

    #[test]
    fn pvm_internal_function_call() {
        let compiled = compile_no_opt(r#"
            contract T {
                fn add(a: u64, b: u64) -> u64 {
                    return a + b;
                }
                pub fn f() -> u64 {
                    return add(10, 32);
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 42, "add(10, 32) should be 42");
    }

    #[test]
    fn pvm_storage_accumulate() {
        // Write, read, modify, write back, read again
        let compiled = compile_no_opt(r#"
            contract T {
                storage { counter: u64, }
                pub fn f() -> u64 {
                    self.counter = 10;
                    let x = self.counter;
                    self.counter = x + 5;
                    return self.counter;
                }
            }
        "#);
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: [3u8; 32],
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        assert_eq!(vm.cpu.read_gp(1), 15, "counter should be 10+5=15");
    }

    #[test]
    fn pvm_struct_three_fields() {
        let compiled = compile(r#"
            contract T {
                struct Color { r: u64, g: u64, b: u64, }
                pub fn f() -> u64 {
                    let c = Color { r: 255, g: 128, b: 64 };
                    return c.r + c.g + c.b;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 447, "255 + 128 + 64 = 447");
    }

    #[test]
    fn pvm_array_sum_loop() {
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let arr = [10, 20, 30, 40];
                    let mut sum = 0;
                    for i in 0..4 {
                        sum = sum + arr[i];
                    }
                    return sum;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 100, "10+20+30+40=100");
    }

    #[test]
    fn pvm_nested_if_else() {
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let x = 50;
                    if x > 100 {
                        return 1;
                    } else {
                        if x > 25 {
                            return 2;
                        } else {
                            return 3;
                        }
                    }
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 2, "50 > 25 but not > 100 → 2");
    }

    #[test]
    fn pvm_for_loop_sum() {
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let mut sum = 0;
                    for i in 0..10 {
                        sum = sum + i;
                    }
                    return sum;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 45, "0+1+2+...+9 = 45");
    }

    #[test]
    fn pvm_comparison_lteq() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    if 5 <= 5 { return 1; }
                    return 0;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1, "5 <= 5 should be true");
    }

    #[test]
    fn pvm_comparison_gteq() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    if 10 >= 5 { return 1; }
                    return 0;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1, "10 >= 5 should be true");
    }

    // ========================================================================
    // Wide register builtins (msg.sender, msg.value, address(self))
    // ========================================================================

    #[test]
    fn pvm_msg_sender() {
        // msg.sender is a wide (256-bit) address value.
        // We can't return it as u64 directly, but we can check it's non-zero
        // by narrowing (which traps if > u64::MAX) or by comparing with a known value.
        // Simplest: check gas_remaining still works when msg.sender is in the function.
        // Better: use msg.sender in a comparison.
        let compiled = compile_no_opt(r#"
            contract T {
                storage { owner: u64, }
                pub fn f() -> u64 {
                    let s = msg.sender;
                    return 1;
                }
            }
        "#);
        let ctx = pyde_vm::vm::ExecutionContext {
            caller: [0xAB; 32],
            self_address: [1u8; 32],
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        // If Callvalue wrote to wrong register file, this would trap.
        // Returning 1 proves msg.sender didn't corrupt execution.
        assert_eq!(vm.cpu.read_gp(1), 1, "msg.sender should not corrupt execution");
        // Also verify the wide register actually got the caller value
        let w = vm.cpu.read_wide(0); // first wide alloc = w0
        assert_ne!(w, pyde_vm::wide::U256::ZERO, "msg.sender should be non-zero");
    }

    #[test]
    fn pvm_msg_value() {
        // msg.value is u256 (wide). Test with #[payable] function that reads it.
        let (tokens, _) = Lexer::new(r#"
            contract T {
                #[payable]
                pub fn f() -> u64 {
                    let v = msg.value;
                    return 1;
                }
            }
        "#).tokenize();
        let (file, _) = Parser::new(tokens).parse();
        let ir = lower::lower(&file);
        let mut codegen = CodeGen::new();
        codegen.emit_guards = false;
        let compiled = codegen.generate(&ir);

        let ctx = pyde_vm::vm::ExecutionContext {
            call_value: pyde_vm::wide::U256::from(500u64),
            self_address: [1u8; 32],
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        assert_eq!(vm.cpu.read_gp(1), 1, "msg.value read should not trap");
    }

    #[test]
    fn pvm_address_of_self() {
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let a = address(self);
                    return 1;
                }
            }
        "#);
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: [0xCD; 32],
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        assert_eq!(vm.cpu.read_gp(1), 1, "address(self) should not trap");
    }

    // ========================================================================
    // Payable guard (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_payable_guard_rejects_value() {
        // Non-payable function should revert when call_value > 0
        let (tokens, _) = Lexer::new(r#"
            contract T {
                pub fn f() -> u64 {
                    return 42;
                }
            }
        "#).tokenize();
        let (file, _) = Parser::new(tokens).parse();
        let ir = lower::lower(&file);
        let mut codegen = CodeGen::new();
        codegen.emit_guards = true; // production mode with guards
        let compiled = codegen.generate(&ir);

        let ctx = pyde_vm::vm::ExecutionContext {
            call_value: pyde_vm::wide::U256::from(100u64), // non-zero value
            self_address: [1u8; 32],
            ..Default::default()
        };
        // Use runtime_bytecode (includes dispatch + guards)
        let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000, ctx);
        // Set up calldata with the correct selector
        let selector = compute_selector("f");
        vm.calldata = selector.to_be_bytes().to_vec();
        vm.load(&compiled.runtime_bytecode).unwrap();

        let mut result = None;
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(r)) => { result = Some(r); break; }
                Ok(None) => { steps += 1; if steps > 500 { break; } }
                Err(_) => break,
            }
        }
        assert!(
            matches!(result, Some(pyde_vm::vm::ExecResult::Revert)),
            "non-payable function should revert when call_value > 0, got {:?}", result
        );
    }

    // ========================================================================
    // Storage maps (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_storage_map_write_read() {
        let compiled = compile_no_opt(r#"
            contract T {
                storage { balances: Map<u64, u64>, }
                pub fn f() -> u64 {
                    self.balances[42] = 100;
                    return self.balances[42];
                }
            }
        "#);
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: [5u8; 32],
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        assert_eq!(vm.cpu.read_gp(1), 100, "map[42] should be 100");
    }

    // ========================================================================
    // Reentrancy guard (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_reentrancy_guard_sets_and_clears() {
        // Verify the reentrancy guard doesn't prevent a single normal call.
        // The guard sets lock=1 before function body, clears lock=0 after return.
        let (tokens, _) = Lexer::new(r#"
            contract T {
                storage { value: u64, }
                pub fn f() -> u64 {
                    self.value = 42;
                    return self.value;
                }
            }
        "#).tokenize();
        let (file, _) = Parser::new(tokens).parse();
        let ir = lower::lower(&file);
        let mut codegen = CodeGen::new();
        codegen.emit_guards = true;
        let compiled = codegen.generate(&ir);

        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: [6u8; 32],
            ..Default::default()
        };
        let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000, ctx);
        let selector = compute_selector("f");
        vm.calldata = selector.to_be_bytes().to_vec();
        vm.load(&compiled.runtime_bytecode).unwrap();

        let mut result = None;
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(r)) => { result = Some(r); break; }
                Ok(None) => { steps += 1; if steps > 1000 { break; } }
                Err(_) => break,
            }
        }
        // Should complete normally (Halt), not revert
        assert!(
            matches!(result, Some(pyde_vm::vm::ExecResult::Halt)),
            "single call should succeed with reentrancy guard, got {:?}", result
        );
        assert_eq!(vm.cpu.read_gp(1), 42, "should return 42");
    }

    // ========================================================================
    // Dispatch with calldata (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_dispatch_with_calldata() {
        // Test the full dispatch path: selector matching + calldata decode
        let compiled = compile(r#"
            contract T {
                pub fn add(a: u64, b: u64) -> u64 {
                    return a + b;
                }
            }
        "#);
        // Build calldata: [selector(4 bytes)] [arg0(8 bytes)] [arg1(8 bytes)]
        let selector = compute_selector("add");
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&selector.to_be_bytes()); // 4 bytes selector (BE, like Ethereum)
        calldata.extend_from_slice(&10u64.to_le_bytes());    // arg0 = 10
        calldata.extend_from_slice(&32u64.to_le_bytes());    // arg1 = 32

        let mut codegen = CodeGen::new();
        codegen.emit_guards = true; // production mode with dispatch
        let (tokens, _) = Lexer::new(r#"
            contract T {
                pub fn add(a: u64, b: u64) -> u64 {
                    return a + b;
                }
            }
        "#).tokenize();
        let (file, _) = Parser::new(tokens).parse();
        let ir = lower::lower(&file);
        let compiled = codegen.generate(&ir);

        let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000);
        vm.calldata = calldata;
        vm.load(&compiled.runtime_bytecode).unwrap();

        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => { steps += 1; if steps > 500 { break; } }
                Err(_) => break,
            }
        }
        assert_eq!(vm.cpu.read_gp(1), 42, "add(10, 32) via dispatch should be 42");
    }

    #[test]
    fn pvm_storage_increment_persists() {
        // Verify that increment() actually writes to vm.storage
        let (tokens, _) = Lexer::new(r#"
            contract Counter {
                storage { count: u64 }
                pub fn increment() { self.count = self.count + 1; }
                pub fn get_count() -> u64 { return self.count; }
            }
        "#).tokenize();
        let (file, _) = Parser::new(tokens).parse();
        let ir = lower::lower(&file);
        let mut codegen = CodeGen::new();
        codegen.emit_guards = true;
        let compiled = codegen.generate(&ir);

        // Run increment()
        let selector = compute_selector("increment");
        let calldata = selector.to_be_bytes().to_vec();

        let mut vm = pyde_vm::vm::Vm::with_gas_limit(500_000);
        vm.calldata = calldata;
        vm.load(&compiled.runtime_bytecode).unwrap();
        let output = vm.execute();

        println!("outcome: {:?}", output.outcome);
        println!("gas: {}", output.gas_used);
        println!("storage entries: {}", vm.storage.len());
        for (k, v) in &vm.storage {
            println!("  key={} value_bytes={:?}", k, &v[..v.len().min(16)]);
        }

        assert_eq!(output.outcome, pyde_vm::vm::Outcome::Success, "increment should succeed");
        assert!(vm.storage.len() > 0, "vm.storage should have entries after Sstore");
    }

    // ========================================================================
    // Wide storage u256 (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_wide_storage_u256() {
        // u256 storage field uses Sload/Sstore mode 0 (wide register)
        let compiled = compile_no_opt(r#"
            contract T {
                storage { total: u256, }
                pub fn f() -> u64 {
                    self.total = 999;
                    return 1;
                }
            }
        "#);
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: [7u8; 32],
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        assert_eq!(vm.cpu.read_gp(1), 1, "u256 storage write should not trap");
    }

    // ========================================================================
    // Poseidon hash (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_poseidon_hash() {
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let h = hash(42);
                    return 1;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1, "hash() should not trap");
    }

    // ========================================================================
    // Event emission (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_event_emit_no_fields() {
        // emit uses keyword syntax: `emit EventName { fields };` (NOT emit!())
        let compiled = compile_no_opt(r#"
            contract T {
                event Ping {}
                pub fn f() -> u64 {
                    emit Ping {};
                    return 1;
                }
            }
        "#);
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: [8u8; 32],
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        assert_eq!(vm.cpu.read_gp(1), 1, "emit should not trap");
    }

    #[test]
    fn pvm_event_emit_with_fields() {
        let compiled = compile_no_opt(r#"
            contract T {
                event Transfer { from: u64, to: u64, amount: u64, }
                pub fn f() -> u64 {
                    emit Transfer { from: 1, to: 2, amount: 100 };
                    return 1;
                }
            }
        "#);
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: [9u8; 32],
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        assert_eq!(vm.cpu.read_gp(1), 1, "emit with fields should not trap");
    }

    // ========================================================================
    // u256 large constants (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_u256_large_constant() {
        // u256 value > u64::MAX: store to heap, Wload, use in storage
        let compiled = compile_no_opt(r#"
            contract T {
                storage { big: u256, }
                pub fn f() -> u64 {
                    self.big = 340282366920938463463374607431768211455_u256;
                    return 1;
                }
            }
        "#);
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: [10u8; 32],
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        assert_eq!(vm.cpu.read_gp(1), 1, "u256 large constant should not trap");
    }

    // ========================================================================
    // Register pressure (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_many_locals_optimized() {
        // Optimizer folds constants, so this fits in few registers
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    let a = 1;
                    let b = 2;
                    let c = 3;
                    let d = 4;
                    let e = 5;
                    let g = 6;
                    let h = 7;
                    let i = 8;
                    return a + b + c + d + e + g + h + i;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 36, "1+2+3+4+5+6+7+8=36");
    }

    #[test]
    fn pvm_array_repeat() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    let arr = [0; 5];
                    return arr[3];
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 0, "repeated array should have 0 at index 3");
    }

    #[test]
    fn pvm_bitwise_not() {
        let compiled = compile(r#"
            contract T {
                pub fn f() -> u64 {
                    let a: u64 = 0;
                    let b = ~a;
                    if b > 100 { return 1; }
                    return 0;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        // ~0 = u64::MAX (all bits set, > 100)
        assert_eq!(vm.cpu.read_gp(1), 1, "bitwise NOT of 0 should be max");
    }

    // ========================================================================
    // Vec operations (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_vec_push_and_len() {
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let mut v = Vec::new();
                    v.push(10);
                    return v.len();
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1, "Vec should have 1 element after push");
    }

    #[test]
    fn pvm_vec_push_and_pop() {
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let mut v = Vec::new();
                    v.push(10);
                    v.push(20);
                    v.push(30);
                    let last = v.pop();
                    return last;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 30, "pop should return last pushed (30)");
    }

    #[test]
    fn pvm_vec_is_empty() {
        // Simplest Vec test: create and return length
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let v = Vec::new();
                    return v.len();
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 0, "new Vec length should be 0");
    }

    #[test]
    fn pvm_vec_push_pop_sequence() {
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let mut v = Vec::new();
                    v.push(100);
                    v.push(200);
                    v.pop();
                    v.push(300);
                    return v.len();
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 2, "push push pop push → len 2");
    }

    #[test]
    fn pvm_cast_widen_narrow() {
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let a: u64 = 42;
                    let b = a as u256;
                    let c = b as u64;
                    return c;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 42, "u64 → u256 → u64 round-trip should be 42");
    }

    #[test]
    fn pvm_unary_neg() {
        // -10 as u64 wraps to u64::MAX - 9
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let a: u64 = 10;
                    let b = -a;
                    return b;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        let expected = 0u64.wrapping_sub(10); // u64::MAX - 9
        assert_eq!(vm.cpu.read_gp(1), expected, "negation of 10 should wrap to {}", expected);
    }

    #[test]
    fn pvm_register_spill_restore() {
        // This function uses >11 virtual registers, forcing spill/restore.
        // Without optimizer, each variable + temporary gets its own register.
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let a = 1;
                    let b = 2;
                    let c = 3;
                    let d = 4;
                    let e = 5;
                    let g = 6;
                    let h = 7;
                    let i = 8;
                    let j = 9;
                    let k = 10;
                    let l = a + b;
                    let m = c + d;
                    return l + m + e + g;
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        // l = 1+2 = 3, m = 3+4 = 7, result = 3 + 7 + 5 + 6 = 21
        assert_eq!(vm.cpu.read_gp(1), 21, "spilled register values should be correct");
    }

    #[test]
    fn pvm_vec_push_loop() {
        // Push 10 elements in a loop (within initial capacity)
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let mut v = Vec::new();
                    for i in 0..10 {
                        v.push(i);
                    }
                    return v.len();
                }
            }
        "#);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 10, "Vec should have 10 elements");
    }

    #[test]
    fn pvm_vec_realloc() {
        // Push 100 elements — exceeds initial capacity of 64, triggers Memcpy realloc
        let compiled = compile_no_opt(r#"
            contract T {
                pub fn f() -> u64 {
                    let mut v = Vec::new();
                    for i in 0..100 {
                        v.push(i);
                    }
                    return v.len();
                }
            }
        "#);
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(1_000_000);
        vm.load(&compiled.bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => { steps += 1; if steps > 50_000 { break; } }
                Err(_) => break,
            }
        }
        assert_eq!(vm.cpu.read_gp(1), 100, "Vec should have 100 elements after realloc");
    }

    #[test]
    fn pvm_map_set_under_register_pressure() {
        // This test creates enough local variables to exhaust GP registers (r1-r11),
        // forcing the register allocator to spill. Then does map set/get to verify
        // spilled key/val registers are correctly handled in storage operations.
        let compiled = compile_no_opt(r#"
            contract T {
                storage {
                    data: Map<u64, u64>,
                    count: u64,
                }
                pub fn f() -> u64 {
                    // Create enough locals to exhaust registers and force spilling
                    let a = 1;
                    let b = 2;
                    let c = 3;
                    let d = 4;
                    let e = 5;
                    let f = 6;
                    let g = 7;
                    let h = 8;
                    let i = 9;
                    let j = 10;
                    let k = 11;
                    let l = 12;

                    // Map set with key and val likely spilled
                    self.data[a] = b;
                    self.data[c] = d;
                    self.data[e] = f;

                    // Read back — key is likely spilled
                    let r1 = self.data[a];
                    let r2 = self.data[c];
                    let r3 = self.data[e];

                    // Use all the locals to prevent optimizer from eliminating them
                    self.count = a + b + c + d + e + f + g + h + i + j + k + l;

                    return r1 + r2 + r3;
                }
            }
        "#);
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(1_000_000);
        vm.load(&compiled.bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => { steps += 1; if steps > 10_000 { break; } }
                Err(e) => { panic!("PVM error: {:?}", e); }
            }
        }
        // data[1]=2, data[3]=4, data[5]=6 → r1+r2+r3 = 2+4+6 = 12
        assert_eq!(vm.cpu.read_gp(1), 12,
            "Map operations under register pressure must preserve correct key/val");
    }

    #[test]
    fn pvm_map_set_bool_under_pressure() {
        // Regression test: map set of false (0) must not be confused with
        // a clobbered register that happens to be 0.
        let compiled = compile_no_opt(r#"
            contract T {
                storage {
                    flags: Map<u64, bool>,
                    a: u64,
                    b: u64,
                    c: u64,
                    d: u64,
                    e: u64,
                    f: u64,
                }
                pub fn f() -> u64 {
                    let x = 1;
                    let y = 2;
                    let z = 3;
                    self.a = x;
                    self.b = y;
                    self.c = z;
                    self.d = 4;
                    self.e = 5;
                    self.f = 6;

                    // Set flag to true
                    self.flags[x] = true;
                    let v1 = self.flags[x];

                    // Set flag to false (the value false=0 must survive register pressure)
                    self.flags[x] = false;
                    let v2 = self.flags[x];

                    // v1 should be 1 (true), v2 should be 0 (false)
                    if v1 == true {
                        if v2 == false {
                            return 99;
                        }
                    }
                    return 0;
                }
            }
        "#);
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(1_000_000);
        vm.load(&compiled.bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => { steps += 1; if steps > 10_000 { break; } }
                Err(e) => { panic!("PVM error: {:?}", e); }
            }
        }
        assert_eq!(vm.cpu.read_gp(1), 99,
            "Bool map set(false) must work under register pressure");
    }

    #[test]
    fn pvm_marketplace_buy_pattern() {
        // Regression test for the Marketplace buy_item pattern:
        // Multiple map reads/writes in a single function under heavy register pressure.
        // This is the exact pattern that was broken: read multiple map fields for an item,
        // compute fees, update balances, flip active flag.
        let compiled = compile_no_opt(r#"
            contract Marketplace {
                storage {
                    item_prices: Map<u64, u64>,
                    item_sellers: Map<u64, u64>,
                    item_active: Map<u64, bool>,
                    balances: Map<u64, u64>,
                    fee_percent: u64,
                    owner: u64,
                    total_fees: u64,
                }

                pub fn test_buy() -> u64 {
                    // Setup: list an item
                    let item_id = 1;
                    let seller = 42;
                    let price = 1000;
                    let fee_pct = 5;
                    let the_owner = 99;
                    self.fee_percent = fee_pct;
                    self.owner = the_owner;

                    self.item_prices[item_id] = price;
                    self.item_sellers[item_id] = seller;
                    self.item_active[item_id] = true;

                    // Buy: read item fields
                    let p = self.item_prices[item_id];
                    let s = self.item_sellers[item_id];
                    let active = self.item_active[item_id];

                    // Compute fee
                    let fp = self.fee_percent;
                    let fee = p * fp / 100;
                    let seller_amount = p - fee;

                    // Update balances
                    let old_bal = self.balances[s];
                    self.balances[s] = old_bal + seller_amount;

                    let old_fee_bal = self.balances[the_owner];
                    self.balances[the_owner] = old_fee_bal + fee;

                    // Flip active to false
                    self.item_active[item_id] = false;
                    self.total_fees = fee;

                    // Verify everything
                    let final_active = self.item_active[item_id];
                    let seller_bal = self.balances[s];
                    let owner_bal = self.balances[the_owner];
                    let stored_fee = self.total_fees;

                    // active=0, seller_bal=950, owner_bal=50, stored_fee=50
                    // Encode as: active*10000 + stored_fee*100 + (seller_bal - 900)
                    // Expected: 0*10000 + 50*100 + 50 = 5050
                    if final_active == false {
                        if seller_bal == 950 {
                            if owner_bal == 50 {
                                return 5050;
                            }
                        }
                    }
                    return 0;
                }
            }
        "#);
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
        vm.load(&compiled.bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => { steps += 1; if steps > 100_000 { break; } }
                Err(e) => { panic!("PVM error: {:?}", e); }
            }
        }
        assert_eq!(vm.cpu.read_gp(1), 5050,
            "Marketplace buy pattern: active flipped, balances correct, fees computed");
    }

    #[test]
    fn pvm_batch_reward_register_pressure() {
        // Reproduces the batch_reward pattern from the E2E StressTest:
        // 4 params, 3 map reads, fee math, 4 map writes — extreme register pressure.
        // This was producing off-by-16 for the second user's balance.
        let compiled = compile_no_opt(r#"
            contract T {
                storage {
                    balances: Map<u64, u64>,
                    fee_rate: u64,
                    owner_id: u64,
                }
                pub fn f() -> u64 {
                    self.fee_rate = 10;
                    self.owner_id = 1;
                    self.balances[1] = 1200;
                    self.balances[10] = 38000;
                    self.balances[20] = 39000;
                    self.balances[30] = 21800;

                    let b1 = self.balances[10];
                    let b2 = self.balances[20];
                    let b3 = self.balances[30];
                    let rate = self.fee_rate;
                    let total = 3000 * 3;
                    let tax = total * rate / 100;
                    let per_user = (total - tax) / 3;

                    self.balances[10] = b1 + per_user;
                    self.balances[20] = b2 + per_user;
                    self.balances[30] = b3 + per_user;

                    let oid = self.owner_id;
                    let owner_bal = self.balances[oid];
                    self.balances[oid] = owner_bal + tax;

                    // Verify all balances
                    let r1 = self.balances[10];
                    let r2 = self.balances[20];
                    let r3 = self.balances[30];
                    let r4 = self.balances[1];
                    return r1 + r2 + r3 + r4;
                }
            }
        "#);
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
        vm.load(&compiled.bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => { steps += 1; if steps > 100_000 { break; } }
                Err(e) => { panic!("PVM error: {:?}", e); }
            }
        }
        // b10=38000+2700=40700, b20=39000+2700=41700, b30=21800+2700=24500, b1=1200+900=2100
        // total = 40700+41700+24500+2100 = 109000
        assert_eq!(vm.cpu.read_gp(1), 109000,
            "batch reward: all balances must be exact");
    }

    #[test]
    fn pvm_batch_reward_with_guards() {
        // Same as above but with guards enabled (production dispatch mode).
        // This matches the E2E execution path.
        let src = r#"
            contract T {
                storage {
                    balances: Map<u64, u64>,
                    fee_rate: u64,
                    owner_id: u64,
                }

                pub fn setup() {
                    self.fee_rate = 10;
                    self.owner_id = 1;
                    self.balances[1] = 1200;
                    self.balances[10] = 38000;
                    self.balances[20] = 39000;
                    self.balances[30] = 21800;
                }

                pub fn batch_reward(u1: u64, u2: u64, u3: u64, reward: u64) -> u64 {
                    let b1 = self.balances[u1];
                    let b2 = self.balances[u2];
                    let b3 = self.balances[u3];
                    let rate = self.fee_rate;
                    let total = reward * 3;
                    let tax = total * rate / 100;
                    let per_user = (total - tax) / 3;

                    self.balances[u1] = b1 + per_user;
                    self.balances[u2] = b2 + per_user;
                    self.balances[u3] = b3 + per_user;

                    let oid = self.owner_id;
                    let owner_bal = self.balances[oid];
                    self.balances[oid] = owner_bal + tax;

                    return per_user;
                }

                #[view]
                pub fn get_balance(user_id: u64) -> u64 {
                    return self.balances[user_id];
                }
            }
        "#;

        // Compile WITH guards (production mode)
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let ir = crate::lower::lower(&file);
        let codegen = CodeGen::new(); // emit_guards = true (default)
        let contract = codegen.generate(&ir);

        // Step 1: Run setup() to initialize storage
        let setup_sel = compute_selector("setup");
        let mut calldata = setup_sel.to_be_bytes().to_vec();

        let mut vm = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
        vm.calldata = calldata;
        vm.load(&contract.runtime_bytecode).unwrap();
        let output = vm.execute();
        assert_eq!(output.outcome, pyde_vm::vm::Outcome::Success, "setup must succeed");

        // Step 2: Run batch_reward(10, 20, 30, 3000)
        let batch_sel = compute_selector("batch_reward");
        calldata = batch_sel.to_be_bytes().to_vec();
        calldata.extend_from_slice(&10u64.to_le_bytes());
        calldata.extend_from_slice(&20u64.to_le_bytes());
        calldata.extend_from_slice(&30u64.to_le_bytes());
        calldata.extend_from_slice(&3000u64.to_le_bytes());

        let mut vm2 = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
        // Copy storage from setup
        vm2.storage = vm.storage.clone();
        vm2.calldata = calldata;
        vm2.load(&contract.runtime_bytecode).unwrap();
        let output2 = vm2.execute();
        assert_eq!(output2.outcome, pyde_vm::vm::Outcome::Success, "batch_reward must succeed");

        // per_user = (9000 - 900) / 3 = 2700
        assert_eq!(vm2.cpu.read_gp(1), 2700, "per_user return value");

        // Step 3: Read balances via get_balance
        let get_sel = compute_selector("get_balance");

        // Check user20 balance
        let mut calldata20 = get_sel.to_be_bytes().to_vec();
        calldata20.extend_from_slice(&20u64.to_le_bytes());

        let mut vm3 = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
        vm3.storage = vm2.storage.clone();
        vm3.calldata = calldata20;
        vm3.load(&contract.runtime_bytecode).unwrap();
        let output3 = vm3.execute();
        assert_eq!(output3.outcome, pyde_vm::vm::Outcome::Success, "get_balance must succeed");
        assert_eq!(vm3.cpu.read_gp(1), 41700, "user20 balance = 39000 + 2700 = 41700");

        // Check user10 balance
        let mut calldata10 = get_sel.to_be_bytes().to_vec();
        calldata10.extend_from_slice(&10u64.to_le_bytes());

        let mut vm4 = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
        vm4.storage = vm2.storage.clone();
        vm4.calldata = calldata10;
        vm4.load(&contract.runtime_bytecode).unwrap();
        let output4 = vm4.execute();
        assert_eq!(output4.outcome, pyde_vm::vm::Outcome::Success);
        assert_eq!(vm4.cpu.read_gp(1), 40700, "user10 balance = 38000 + 2700 = 40700");
    }

    #[test]
    fn pvm_batch_reward_smt_roundtrip() {
        // Tests the exact E2E path: setup → persist to SMT → load from SMT → batch_reward
        let src = r#"
            contract T {
                storage {
                    balances: Map<u64, u64>,
                    fee_rate: u64,
                    owner_id: u64,
                }
                pub fn setup() {
                    self.fee_rate = 10;
                    self.owner_id = 1;
                    self.balances[1] = 0;
                }
                pub fn set_balance(user: u64, amount: u64) {
                    self.balances[user] = amount;
                }
                #[reentrant]
                pub fn batch_reward(u1: u64, u2: u64, u3: u64, reward: u64) -> u64 {
                    let b1 = self.balances[u1];
                    let b2 = self.balances[u2];
                    let b3 = self.balances[u3];
                    let rate = self.fee_rate;
                    let total = reward * 3;
                    let tax = total * rate / 100;
                    let per_user = (total - tax) / 3;
                    self.balances[u1] = b1 + per_user;
                    self.balances[u2] = b2 + per_user;
                    self.balances[u3] = b3 + per_user;
                    let oid = self.owner_id;
                    let owner_bal = self.balances[oid];
                    self.balances[oid] = owner_bal + tax;
                    return per_user;
                }
                #[view]
                pub fn get_balance(user: u64) -> u64 { return self.balances[user]; }
            }
        "#;

        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let ir = crate::lower::lower(&file);
        let codegen = CodeGen::new();
        let contract = codegen.generate(&ir);

        let contract_addr = [0x42u8; 32]; // fixed contract address

        // Helper: run a function on the runtime bytecode with calldata
        // CRITICAL: all VMs must use the same contract_addr for consistent storage keys
        let run = |calldata: Vec<u8>| -> pyde_vm::vm::Vm {
            let ctx = pyde_vm::vm::ExecutionContext {
                self_address: contract_addr,
                ..Default::default()
            };
            let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(10_000_000, ctx);
            vm.calldata = calldata;
            vm.load(&contract.runtime_bytecode).unwrap();
            let _ = vm.execute();
            vm
        };

        // Helper: persist vm.storage to SMT, return SMT
        let persist = |vm: &pyde_vm::vm::Vm, smt: &mut pyde_state::smt::PydeSMT| {
            for (key, value) in &vm.storage {
                let smt_key = sparse_merkle_tree::H256::from(key.to_le_bytes());
                let _ = smt.insert(smt_key, value.clone());
            }
        };

        // Helper: create a lazy backend from SMT
        let load_from_smt = |smt: &pyde_state::smt::PydeSMT,
                              storage: &mut std::collections::HashMap<ethnum::U256, Vec<u8>>,
                              keys: &[ethnum::U256]| {
            for key in keys {
                let smt_key = sparse_merkle_tree::H256::from(key.to_le_bytes());
                if let Some(val) = smt.get(&smt_key) {
                    storage.insert(*key, val);
                }
            }
        };

        let mut smt = pyde_state::smt::PydeSMT::new();

        // Step 1: Setup (acts as constructor)
        let setup_sel = compute_selector("setup");
        let vm0 = run(setup_sel.to_be_bytes().to_vec());
        persist(&vm0, &mut smt);

        // Step 2: set_balance(10, 38000)
        let set_sel = compute_selector("set_balance");
        let mut cd = set_sel.to_be_bytes().to_vec();
        cd.extend_from_slice(&10u64.to_le_bytes());
        cd.extend_from_slice(&38000u64.to_le_bytes());
        let vm1 = run(cd);
        // Merge with SMT: load existing, add new
        persist(&vm1, &mut smt);

        // Step 3: set_balance(20, 39000)
        let mut cd = set_sel.to_be_bytes().to_vec();
        cd.extend_from_slice(&20u64.to_le_bytes());
        cd.extend_from_slice(&39000u64.to_le_bytes());
        let vm2 = run(cd);
        persist(&vm2, &mut smt);

        // Step 4: set_balance(30, 21800)
        let mut cd = set_sel.to_be_bytes().to_vec();
        cd.extend_from_slice(&30u64.to_le_bytes());
        cd.extend_from_slice(&21800u64.to_le_bytes());
        let vm3 = run(cd);
        persist(&vm3, &mut smt);

        // Step 5: set_balance(1, 1200)
        let mut cd = set_sel.to_be_bytes().to_vec();
        cd.extend_from_slice(&1u64.to_le_bytes());
        cd.extend_from_slice(&1200u64.to_le_bytes());
        let vm4 = run(cd);
        persist(&vm4, &mut smt);

        // Step 6: batch_reward(10, 20, 30, 3000) with lazy SMT backend
        let batch_sel = compute_selector("batch_reward");
        let mut cd = batch_sel.to_be_bytes().to_vec();
        cd.extend_from_slice(&10u64.to_le_bytes());
        cd.extend_from_slice(&20u64.to_le_bytes());
        cd.extend_from_slice(&30u64.to_le_bytes());
        cd.extend_from_slice(&3000u64.to_le_bytes());

        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: contract_addr,
            ..Default::default()
        };
        let mut vm5 = pyde_vm::vm::Vm::with_gas_limit_and_context(10_000_000, ctx);
        // Use lazy storage backend (same as pipeline)
        let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
        vm5.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let smt_key = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr).get(&smt_key) }
        }));
        vm5.calldata = cd;
        vm5.load(&contract.runtime_bytecode).unwrap();
        let output = vm5.execute();
        assert_eq!(output.outcome, pyde_vm::vm::Outcome::Success, "batch_reward must succeed");
        assert_eq!(vm5.cpu.read_gp(1), 2700, "per_user = 2700");

        // Persist and read back
        vm5.storage_backend = None;
        persist(&vm5, &mut smt);

        // Step 7: get_balance(20) via lazy backend
        let get_sel = compute_selector("get_balance");
        let mut cd = get_sel.to_be_bytes().to_vec();
        cd.extend_from_slice(&20u64.to_le_bytes());

        let ctx2 = pyde_vm::vm::ExecutionContext {
            self_address: contract_addr,
            ..Default::default()
        };
        let mut vm6 = pyde_vm::vm::Vm::with_gas_limit_and_context(10_000_000, ctx2);
        let smt_ptr2 = &smt as *const pyde_state::smt::PydeSMT;
        vm6.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let smt_key = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr2).get(&smt_key) }
        }));
        vm6.calldata = cd;
        vm6.load(&contract.runtime_bytecode).unwrap();
        let output6 = vm6.execute();
        assert_eq!(output6.outcome, pyde_vm::vm::Outcome::Success);
        assert_eq!(vm6.cpu.read_gp(1), 41700, "bal(20) = 39000 + 2700 = 41700");
    }
}
