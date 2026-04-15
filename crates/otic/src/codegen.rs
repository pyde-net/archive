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

use pyde_vm::isa::{encode, encode_mem_immediate, Instruction, MemWidth, Opcode};

/// Reentrancy guard storage slot — 18-bit Addi encoding of -2.
///
/// At runtime, PVM sign-extends this to r15 = 0xFFFFFFFFFFFFFFFE (u64),
/// then Widen produces U256(0xFFFFFFFFFFFFFFFE). User-defined storage slots
/// count up from 0 via a u32 counter (max ~4 billion), so collision with
/// this value (18 quintillion) is impossible.
const REENTRANCY_SLOT: u32 = (-2i32 as u32) & 0x3FFFF;

/// Wide scratch register index.
const WIDE_SCRATCH: u8 = 7;
/// Second wide scratch register index.
const WIDE_SCRATCH2: u8 = 6;

/// Total bytes reserved for spill area + serialize loop state per function.
const SPILL_AREA_TOTAL: u32 = 512;
/// Base offset (from r13) for serialize/deserialize loop state.
/// Placed above the register spill slots (which use r13+0..r13+447) to avoid collision.
const LOOP_STATE_BASE: i32 = 448;
// Loop state slots at r13+LOOP_STATE_BASE:
//   +0  = loop counter (i) or remaining
//   +8  = count
//   +16 = src_ptr
//   +24 = dst_data_ptr

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
    ///
    /// NO-EVICTION policy: once a register is assigned (r1-r11), it stays
    /// assigned for the entire function. When all 11 registers are in use,
    /// new vregs become "spill-only" — they use r14 as a temporary write
    /// target and immediately write through to their spill slot. This
    /// prevents loop-carried register corruption where a register assigned
    /// to one vreg gets repurposed for another within a loop body.
    fn alloc(&mut self, vreg: Reg) -> (u8, Option<SpillAction>) {
        if let Some(&phys) = self.mapping.get(&vreg) {
            return (phys, None);
        }
        if self.next_gp <= 11 {
            let phys = self.next_gp;
            self.next_gp += 1;
            self.mapping.insert(vreg, phys);
            self.reverse.insert(phys, vreg);
            (phys, None)
        } else {
            // No free registers — borrow r1 via Push/Pop.
            // r1 is saved to the PVM stack at alloc_gp time and restored
            // at the end of gen_instruction. The borrowed register is used
            // for the new vreg's computation. The vreg gets a spill slot
            // for subsequent reads.
            if !self.spilled.contains_key(&vreg) {
                let slot = self.next_spill_slot;
                self.next_spill_slot += 1;
                self.spilled.insert(vreg, slot);
            }
            // Return r1 as the borrowed register (Push/Pop handled by alloc_gp)
            (1, None)
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
        // w0-w5 are user registers, w6=WIDE_SCRATCH2, w7=WIDE_SCRATCH (reserved)
        let phys = self.next_wide.min(5);
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
        // Also advance wide counter if this is a wide register
        // (prevents alloc_wide from reusing parameter registers)
        if self.wide.contains(&vreg) && phys >= self.next_wide && phys <= 6 {
            self.next_wide = phys + 1;
        }
    }

    /// Get the physical register (backward compat — panics on spill).
    fn get(&self, vreg: Reg) -> u8 {
        *self.mapping.get(&vreg).unwrap_or(&0)
    }

    /// Invalidate any virtual register mapped to a physical register.
    /// Call this after operations that clobber specific physical registers.
    fn invalidate_physical(&mut self, phys: u8) {
        if let Some(vreg) = self.reverse.remove(&phys) {
            self.mapping.remove(&vreg);
        }
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
    /// Pending write-through stores: (physical_reg, vreg).
    /// Collected by alloc_gp, emitted at the end of gen_instruction.
    pending_writebacks: Vec<(u8, Reg)>,
    /// Registers borrowed for spill-only vregs (need Pop to restore at end of instruction).
    pending_restores: Vec<u8>,
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
    /// Struct-scoped field offsets: struct_name → field_name → (byte_offset, field_type).
    field_offsets: HashMap<String, HashMap<String, (u32, Ty)>>,
    /// Label counter for generating unique labels.
    label_counter: u32,
    /// Current function's IR label → codegen label remapping.
    current_label_remap: Option<HashMap<Label, Label>>,
    /// Current function's return type (for blob return serialization).
    current_return_ty: Ty,
}

impl CodeGen {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            label_offsets: HashMap::new(),
            fixups: Vec::new(),
            regs: RegAlloc::new(),
            pending_writebacks: Vec::new(),
            pending_restores: Vec::new(),
            needs_guard_cleanup: false,
            emit_guards: true,
            func_labels: HashMap::new(),
            storage_slots: HashMap::new(),
            storage_types: HashMap::new(),
            struct_defs: HashMap::new(),
            field_offsets: HashMap::new(),
            label_counter: 0,
            current_label_remap: None,
            current_return_ty: Ty::Unit,
        }
    }

    /// Remap an IR label to a unique codegen label (prevents cross-function collisions).
    fn remap_label(&self, label: Label) -> Label {
        self.current_label_remap
            .as_ref()
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
        let max_ir_label = program
            .functions
            .iter()
            .flat_map(|f| f.blocks.iter().map(|b| b.label.0))
            .max()
            .unwrap_or(0);
        self.label_counter = max_ir_label + 100; // safe margin above IR labels

        // Collect storage slot assignments and types
        for field in &program.storage_fields {
            self.storage_slots.insert(field.name.clone(), field.slot);
            self.storage_types
                .insert(field.name.clone(), field.ty.clone());
        }

        // Build struct definitions first (needed for recursive field_byte_size)
        for sdef in &program.struct_defs {
            let fields: Vec<(String, Ty)> = sdef
                .fields
                .iter()
                .map(|(fname, fty)| (fname.clone(), fty.clone()))
                .collect();
            self.struct_defs.insert(sdef.name.clone(), fields);
        }

        // Build struct-scoped field offset map using recursive field sizes
        for sdef in &program.struct_defs {
            let mut offset = 0u32;
            let mut field_map = HashMap::new();
            for (fname, fty) in &sdef.fields {
                field_map.insert(fname.clone(), (offset, fty.clone()));
                offset += self.field_byte_size(fty);
            }
            self.field_offsets.insert(sdef.name.clone(), field_map);
        }

        // Pre-pass: reserve labels for each function body + dispatch entry
        let mut dispatch_entries: Vec<(u32, String, Label, Label)> = Vec::new(); // (selector, name, dispatch_label, func_label)
        let mut receive_label: Option<Label> = None;
        let mut fallback_label: Option<Label> = None;

        for func in &program.functions {
            if func.is_test {
                continue;
            }
            let func_label = self.alloc_label();
            self.func_labels.insert(func.name.clone(), func_label);

            if func.is_receive {
                let dispatch_label = self.alloc_label();
                receive_label = Some(dispatch_label);
                dispatch_entries.push((0, func.name.clone(), dispatch_label, func_label));
            } else if func.is_fallback {
                let dispatch_label = self.alloc_label();
                fallback_label = Some(dispatch_label);
                dispatch_entries.push((0, func.name.clone(), dispatch_label, func_label));
            } else if func.is_pub && !func.is_constructor {
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
                // Set up r13 (spill base) for calldata decode
                self.emit_op(Opcode::Add, 13, 12, 0);
                self.load_u32_to_reg(15, SPILL_AREA_TOTAL);
                self.emit_op(Opcode::Add, 12, 12, 15);
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
            self.gen_dispatch_table(&dispatch_entries, receive_label, fallback_label);

            // Dispatch entries: decode calldata → Call function → Halt
            for (_, name, dispatch_label, func_label) in &dispatch_entries {
                self.mark_label(*dispatch_label);

                let func = program
                    .functions
                    .iter()
                    .find(|f| f.name == *name)
                    .expect("dispatch entry references non-existent function");

                self.emit_heap_init();
                // Set up r13 (spill base) for calldata decode — emit_unflatten
                // may use LOOP_STATE_BASE which is r13-relative.
                self.emit_op(Opcode::Add, 13, 12, 0);
                self.load_u32_to_reg(15, SPILL_AREA_TOTAL);
                self.emit_op(Opcode::Add, 12, 12, 15);
                self.emit_calldata_decode(func);
                self.emit_function_guards(func);
                self.emit_jump_placeholder(Opcode::Call, 0, 0, *func_label);
                // Reentrancy cleanup is in the function body (before Ret).
                // This ensures cleanup runs in the same call frame as the guard SET,
                // which is more reliable than post-Call cleanup in the dispatch wrapper.
                self.emit_op(Opcode::Halt, 0, 0, 0);
            }
        }

        // Function bodies
        // In production mode, all functions use Ret (dispatch wrapper handles Halt).
        // In test mode, emit Jmp to first pub function at start, only it gets Halt.
        let first_pub_name = program
            .functions
            .iter()
            .find(|f| !f.is_test && !f.is_constructor && f.is_pub)
            .map(|f| f.name.clone());

        // In test mode: if there are private functions before the first pub function,
        // emit a Jmp to skip them. PVM always starts at PC=0.
        if !self.emit_guards {
            if let Some(ref pub_name) = first_pub_name {
                if let Some(&pub_label) = self.func_labels.get(pub_name.as_str()) {
                    // Check if first runtime function IS the pub function
                    let first_runtime = program
                        .functions
                        .iter()
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
        let all_bytes: Vec<u8> = self
            .instructions
            .iter()
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

    fn gen_dispatch_table(
        &mut self,
        entries: &[(u32, String, Label, Label)],
        receive_label: Option<Label>,
        fallback_label: Option<Label>,
    ) {
        if entries.is_empty() && receive_label.is_none() && fallback_label.is_none() {
            return;
        }

        // Step 1: Check for empty calldata + value > 0 → #[receive]
        // r4 = calldata length (set by PVM loader). If 0 AND msg.value > 0 → receive.
        // If calldata empty and value == 0 → fallback (or revert).
        if receive_label.is_some() || fallback_label.is_some() {
            let selector_check = self.alloc_label();
            // Skip if calldata is not empty (r4 != 0 → go to selector matching)
            self.emit_jump_placeholder(Opcode::Bne, 4, 0, selector_check);

            // Calldata is empty — check msg.value
            if let Some(recv_label) = receive_label {
                // Load msg.value into w7, check if > 0
                self.emit_op(Opcode::Callvalue, WIDE_SCRATCH, 0, 0); // w7 = msg.value
                self.emit_op(Opcode::Addi, 15, 0, 0);
                self.emit_op(Opcode::Widen, WIDE_SCRATCH2, 15, 0);  // w6 = 0
                self.emit_op(Opcode::Weq, 15, WIDE_SCRATCH, WIDE_SCRATCH2 as u32); // r15 = (value == 0)
                // If value != 0 (r15 == 0) → receive
                self.emit_jump_placeholder(Opcode::Beq, 15, 0, recv_label);
            }

            // Calldata empty + value == 0 → fallback (or revert)
            if let Some(fb_label) = fallback_label {
                self.emit_jump_placeholder(Opcode::Jmp, 0, 0, fb_label);
            } else {
                self.emit_op(Opcode::Revert, 0, 0, 0);
            }

            self.mark_label(selector_check);
        }

        // Step 2: Load selector and match against dispatch entries
        let imm = encode_mem_immediate(0, MemWidth::W32).unwrap();
        self.emit(encode(Opcode::Load, 13, 5, imm)); // r13 = load u32 from calldata[0]

        for (selector, _name, dispatch_label, _func_label) in entries {
            if *selector == 0 {
                continue; // skip receive/fallback entries (selector=0)
            }
            let selector_le = (*selector).swap_bytes();
            self.load_u32_to_reg(memory::REG_SCRATCH_0, selector_le);
            self.emit_jump_placeholder(Opcode::Beq, 13, memory::REG_SCRATCH_0, *dispatch_label);
        }

        // Step 3: No selector matched → #[fallback] or revert
        if let Some(fb_label) = fallback_label {
            self.emit_jump_placeholder(Opcode::Jmp, 0, 0, fb_label);
        } else {
            self.emit_op(Opcode::Revert, 0, 0, 0);
        }
    }

    // ========================================================================
    // Calldata decode + heap init
    // ========================================================================

    // ========================================================================
    // Struct layout helpers (inline nested structs)
    // ========================================================================

    /// Compute the byte size of a struct field in the packed inline layout.
    /// Uses actual type sizes: u8→1, u16→2, u32→4, u64→8, u256→32, etc.
    fn field_byte_size(&self, ty: &Ty) -> u32 {
        match ty {
            Ty::U8 | Ty::I8 | Ty::Bool | Ty::Enum(_) => 1,
            Ty::U16 | Ty::I16 => 2,
            Ty::U32 | Ty::I32 => 4,
            Ty::U64 | Ty::I64 => 8,
            Ty::U128 | Ty::I128 => 16,
            Ty::U256 | Ty::I256 | Ty::Address => 32,
            Ty::Struct(name) => self.compute_struct_size(name),
            // Vec/String/Bytes/Map stored as pointers (8 bytes) — they can grow
            _ => 8,
        }
    }

    /// Compute total byte size of a struct with inline nested structs.
    fn compute_struct_size(&self, name: &str) -> u32 {
        if let Some(fields) = self.struct_defs.get(name) {
            fields
                .iter()
                .map(|(_, fty)| self.field_byte_size(fty))
                .sum()
        } else {
            memory::WORD_SIZE // fallback
        }
    }

    /// Fallback: search all structs for a field name (backward compat for untyped access).
    fn find_field_offset_any(&self, field_name: &str) -> u32 {
        for (_sname, fmap) in &self.field_offsets {
            if let Some((off, _)) = fmap.get(field_name) {
                return *off;
            }
        }
        0
    }

    /// Look up a field's (offset, type) from the struct-scoped field_offsets.
    fn lookup_field(&self, struct_name: &str, field_name: &str) -> (u32, Ty) {
        self.field_offsets
            .get(struct_name)
            .and_then(|m| m.get(field_name))
            .cloned()
            .unwrap_or((0, Ty::U64))
    }

    /// Initialize heap pointer past calldata.
    /// When calldata exists: r5=HEAP_START, r4=len, so r12 = r5 + r4 + 8.
    /// When calldata is empty: PVM doesn't set r5/r4, so fallback to HEAP_START.
    fn emit_heap_init(&mut self) {
        // Load HEAP_START as base (always safe even without calldata)
        self.load_u32_to_reg(12, memory::HEAP_START);
        // If calldata exists, advance past it: r12 = max(HEAP_START, r5 + r4) + 8
        // We add r4 (calldata len, 0 if none) to move past calldata
        self.emit_op(Opcode::Add, 12, 12, 4); // r12 += r4 (calldata length, 0 if empty)
        self.emit_op(Opcode::Addi, 12, 12, 8); // r12 += 8 (alignment gap)
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

        // Check if any param is variable-length (needs runtime cursor)
        let has_blob = func.params.iter().any(|(_, ty)| is_blob_type(ty));

        if has_blob {
            // Dynamic calldata decode: use a runtime cursor register.
            // r14 = current calldata cursor (advances at runtime for each param).
            self.emit_op(
                Opcode::Addi,
                memory::REG_SCRATCH_0,
                5,
                selector_skip as u32 & 0x3FFFF,
            );

            for (i, (_name, ty)) in func.params.iter().enumerate() {
                let phys = (i as u8) + 2;

                if matches!(ty, Ty::Vec(_)) || matches!(ty, Ty::Struct(_)) {
                    // Vec/Struct arg: calldata has [byte_len:8 LE][flat data].
                    // Copy blob to heap buffer, then unflatten to pointer-based layout.
                    // Same approach as the Struct calldata path (proven working).
                    self.emit_op(Opcode::Push, memory::REG_SCRATCH_0, 0, 0); // save cursor

                    self.emit_load(15, memory::REG_SCRATCH_0, 0); // r15 = byte_len
                    self.emit_op(
                        Opcode::Addi,
                        memory::REG_SCRATCH_0,
                        memory::REG_SCRATCH_0,
                        8,
                    );
                    self.emit_op(Opcode::Push, 12, 0, 0); // save buffer_start
                    self.emit_op(Opcode::Memcpy, 12, memory::REG_SCRATCH_0, 15);
                    // Advance heap past buffer (aligned)
                    self.emit_op(Opcode::Addi, 14, 15, 7);
                    self.emit_op(Opcode::Addi, 15, 0, 3);
                    self.emit_op(Opcode::Shr, 14, 14, 15);
                    self.emit_op(Opcode::Shl, 14, 14, 15);
                    self.emit_op(Opcode::Add, 12, 12, 14);
                    // Stack: [old_cursor, buffer_start]

                    // Unflatten: use r11 as read cursor
                    self.emit_op(Opcode::Push, 11, 0, 0); // save r11
                                                          // Stack: [old_cursor, buffer_start, r11_saved]
                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = r11_saved
                    self.emit_op(Opcode::Pop, 11, 0, 0); // r11 = buffer_start
                    self.emit_op(Opcode::Push, 15, 0, 0); // push r11_saved back
                                                          // Stack: [old_cursor, r11_saved]

                    let ty_clone = ty.clone();
                    self.emit_unflatten(&ty_clone, 11, phys);

                    self.emit_op(Opcode::Pop, 11, 0, 0); // restore r11
                                                         // Stack: [old_cursor]

                    // Advance calldata cursor: old_cursor + 8 + align8(byte_len)
                    self.emit_op(Opcode::Pop, memory::REG_SCRATCH_0, 0, 0);
                    self.emit_load(15, memory::REG_SCRATCH_0, 0); // re-read byte_len
                    self.emit_op(Opcode::Addi, 14, 15, 7);
                    self.emit_op(Opcode::Addi, 15, 0, 3);
                    self.emit_op(Opcode::Shr, 14, 14, 15);
                    self.emit_op(Opcode::Shl, 14, 14, 15);
                    self.emit_op(
                        Opcode::Addi,
                        memory::REG_SCRATCH_0,
                        memory::REG_SCRATCH_0,
                        8,
                    );
                    self.emit_op(
                        Opcode::Add,
                        memory::REG_SCRATCH_0,
                        memory::REG_SCRATCH_0,
                        14,
                    );
                } else if matches!(ty, Ty::StringTy | Ty::Bytes) {
                    // String/bytes: calldata has [byte_len:8 LE][data bytes]
                    // Build Vec on heap directly (format unchanged)
                    self.emit_op(Opcode::Add, phys, 12, 0); // phys = Vec base = r12
                    self.emit_load(15, memory::REG_SCRATCH_0, 0); // r15 = byte_len
                    self.emit_store(15, 12, 0); // header.length
                    self.emit_store(15, 12, 8); // header.capacity
                    self.emit_op(Opcode::Addi, 12, 12, memory::VEC_DATA_OFFSET);
                    self.emit_op(Opcode::Push, memory::REG_SCRATCH_0, 0, 0);
                    self.emit_op(
                        Opcode::Addi,
                        memory::REG_SCRATCH_0,
                        memory::REG_SCRATCH_0,
                        8,
                    );
                    self.emit_op(Opcode::Memcpy, 12, memory::REG_SCRATCH_0, 15);
                    // Compute align8(byte_len) and advance heap
                    self.emit_op(Opcode::Addi, 14, 15, 7);
                    self.emit_op(Opcode::Addi, 15, 0, 3);
                    self.emit_op(Opcode::Shr, 14, 14, 15);
                    self.emit_op(Opcode::Shl, 14, 14, 15);
                    self.emit_op(Opcode::Add, 12, 12, 14);
                    // Save align8(byte_len) before restoring cursor
                    self.emit_op(Opcode::Push, 14, 0, 0);
                    // Restore cursor: old_cursor + 8 (byte_len field) + align8 (data)
                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = align8(byte_len)
                    self.emit_op(Opcode::Pop, memory::REG_SCRATCH_0, 0, 0); // r14 = old cursor
                    self.emit_op(
                        Opcode::Addi,
                        memory::REG_SCRATCH_0,
                        memory::REG_SCRATCH_0,
                        8,
                    ); // cursor += 8 (past byte_len)
                    self.emit_op(
                        Opcode::Add,
                        memory::REG_SCRATCH_0,
                        memory::REG_SCRATCH_0,
                        15,
                    ); // cursor += align8(byte_len)
                } else if is_wide_type(ty) {
                    self.emit_op(Opcode::Wload, phys, memory::REG_SCRATCH_0, 0);
                    self.emit_op(
                        Opcode::Addi,
                        memory::REG_SCRATCH_0,
                        memory::REG_SCRATCH_0,
                        32,
                    );
                } else {
                    self.emit_load(phys, memory::REG_SCRATCH_0, 0);
                    self.emit_op(
                        Opcode::Addi,
                        memory::REG_SCRATCH_0,
                        memory::REG_SCRATCH_0,
                        8,
                    );
                }
            }
        } else {
            // Static calldata decode: all params fixed-size, use compile-time offsets.
            let mut param_offset = selector_skip;
            self.emit_op(Opcode::Add, memory::REG_SCRATCH_0, 5, 0); // r14 = r5

            for (i, (_name, ty)) in func.params.iter().enumerate() {
                let phys = (i as u8) + 2;

                if is_wide_type(ty) {
                    self.emit_op(
                        Opcode::Addi,
                        15,
                        memory::REG_SCRATCH_0,
                        param_offset as u32 & 0x3FFFF,
                    );
                    self.emit_op(Opcode::Wload, phys, 15, 0);
                    param_offset += 32;
                } else {
                    self.emit_load(phys, memory::REG_SCRATCH_0, param_offset);
                    param_offset += 8;
                }
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
            self.needs_guard_cleanup = true;
            // Widen reentrancy slot to wide scratch
            self.emit_op(Opcode::Addi, 15, 0, REENTRANCY_SLOT);
            self.emit_op(Opcode::Widen, WIDE_SCRATCH, 15, 0); // w7 = slot key
                                                              // Sload mode 2 (GP value): r14 = storage[w7]
            self.emit_op(Opcode::Sload, 14, WIDE_SCRATCH, 2);
            // Check: lock must be 0
            self.emit_op(Opcode::Eq, 14, 14, 0); // r14 = (lock == 0)
            self.emit_op(Opcode::Assert, 0, 14, 0); // Assert reads rs1: revert if r14==0
                                                    // Set lock = 1
            self.emit_op(Opcode::Addi, 14, 0, 1);
            self.emit_op(Opcode::Sstore, 14, WIDE_SCRATCH, 2); // storage[w7] = 1
        }

        // Payable guard: non-payable pub functions reject msg.value > 0
        if func.is_pub && !func.is_payable && !func.is_constructor {
            // w7 = msg.value (Callvalue writes to wide register)
            self.emit_op(Opcode::Callvalue, WIDE_SCRATCH, 0, 0); // w7 = call_value
                                                                 // w6 = 0 (for comparison)
            self.emit_op(Opcode::Addi, 15, 0, 0);
            self.emit_op(Opcode::Widen, WIDE_SCRATCH2, 15, 0); // w6 = 0
                                                               // r14 = (w7 == w6) i.e. (value == 0)
            self.emit_op(Opcode::Weq, 14, WIDE_SCRATCH, WIDE_SCRATCH2 as u32);
            self.emit_op(Opcode::Assert, 0, 14, 0); // Assert reads rs1: revert if r14==0
        }
    }

    /// Emit reentrancy guard cleanup (clear lock).
    fn emit_reentrancy_cleanup(&mut self) {
        self.emit_op(Opcode::Addi, 15, 0, REENTRANCY_SLOT);
        self.emit_op(Opcode::Widen, WIDE_SCRATCH, 15, 0); // w7 = slot key
        self.emit_op(Opcode::Sstore, 0, WIDE_SCRATCH, 2); // storage[w7] = r0 = 0
    }

    // ========================================================================
    // Function body generation
    // ========================================================================

    /// Generate a function body.
    /// `is_entry`: if true, emit Halt at end (constructor/standalone); if false, emit Ret.
    fn gen_function(&mut self, func: &IrFunction, is_entry: bool) {
        self.regs.reset();
        // Set guard cleanup flag based on function properties (same condition as guard emission).
        // This ensures cleanup is emitted before Ret in the function body.
        self.needs_guard_cleanup = self.emit_guards
            && func.is_pub && !func.is_view && !func.is_constructor && !func.is_reentrant;
        self.current_return_ty = func.return_ty.clone();

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
        // Spill slots live at r13 + 0, r13 + 8, ... (up to ~56 slots).
        // Serialize/deserialize loop state lives at r13 + LOOP_STATE_BASE.
        // Advance r12 past the entire reserved area.
        self.emit_op(Opcode::Add, 13, 12, 0); // r13 = r12
        self.load_u32_to_reg(15, SPILL_AREA_TOTAL);
        self.emit_op(Opcode::Add, 12, 12, 15); // r12 += SPILL_AREA_TOTAL

        // Pre-map params to convention registers (r2, r3, ...)
        // Wide params (u256, Address) must also be marked in the wide set
        // so that BinOp/Cmp/Return use the wide instruction path.
        // CRITICAL: advance next_wide past pre-mapped wide registers to prevent
        // alloc_wide from handing out the same physical wide register to a later
        // vreg, which would silently clobber the parameter value.
        for (i, (_name, ty)) in func.params.iter().enumerate() {
            let vreg = Reg(i as u32);
            let phys = (i as u8) + 2; // r2, r3, r4, ...
            self.regs.pre_map(vreg, phys);
            if is_wide_type(ty) {
                self.regs.wide.insert(vreg);
                if phys >= self.regs.next_wide && phys <= 6 {
                    self.regs.next_wide = phys + 1;
                }
            }
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
        // Clear pending writebacks from previous instruction
        self.pending_writebacks.clear();
        self.pending_restores.clear();
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
                            self.emit_store(15, 12, 0); // heap[0..8] = limb0
                            self.load_u64_to_reg(15, limb1);
                            self.emit_store(15, 12, 8); // heap[8..16] = limb1
                            self.load_u64_to_reg(15, limb2);
                            self.emit_store(15, 12, 16); // heap[16..24] = limb2
                            self.load_u64_to_reg(15, limb3);
                            self.emit_store(15, 12, 24); // heap[24..32] = limb3
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
                    IrConst::String(s) => {
                        // Build Vec layout on heap: [byte_len:8][cap:8][char data...]
                        let rd = self.alloc_gp(*dst);
                        self.emit_op(Opcode::Add, rd, 12, 0); // rd = Vec base
                        let byte_len = s.len() as u32;
                        // Write header
                        self.load_u32_to_reg(15, byte_len);
                        self.emit_store(15, 12, 0); // length = byte_len
                        self.emit_store(15, 12, 8); // capacity = byte_len
                                                    // Write string bytes after header
                        for (i, chunk) in s.as_bytes().chunks(8).enumerate() {
                            let mut buf = [0u8; 8];
                            buf[..chunk.len()].copy_from_slice(chunk);
                            let val = u64::from_le_bytes(buf);
                            self.load_u64_to_reg(15, val);
                            self.emit_store(
                                15,
                                12,
                                (memory::VEC_DATA_OFFSET as i32) + (i as i32) * 8,
                            );
                        }
                        // Advance heap past header + data (aligned)
                        let total = memory::VEC_DATA_OFFSET as u32 + ((byte_len + 7) / 8) * 8;
                        self.load_u32_to_reg(15, total);
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
                // Restore to r14 (not r15) so LogicalNot's Addi r15 can't clobber src
                let r1 = self.get_reg_to(*src, 14);
                match op {
                    UnOp::Neg => {
                        // Two's complement: -a = ~a + 1 (avoids PVM checked_sub underflow trap)
                        self.emit_op(Opcode::Not, rd, r1, 0); // rd = ~a
                        self.emit_op(Opcode::Addi, rd, rd, 1); // rd = ~a + 1 = -a
                    }
                    UnOp::LogicalNot => {
                        self.emit_op(Opcode::Addi, 15, 0, 1); // r15 = 1 (safe: r1 ∈ {r1-r11, r14})
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
                let ty = self
                    .storage_types
                    .get(field.as_str())
                    .cloned()
                    .unwrap_or(Ty::U64);

                // Use w5 as a dedicated storage slot register (not WIDE_SCRATCH which
                // the reentrancy guard and payable guard clobber before we get here).
                const WIDE_SLOT: u8 = 5;

                if is_blob_type(&ty) {
                    let rd = self.alloc_gp(*dst);
                    self.emit_op(Opcode::Addi, 15, 0, slot);
                    self.emit_op(Opcode::Widen, WIDE_SLOT, 15, 0);
                    let imm = 1 | ((12 & 0xF) << 2);
                    self.emit_op(Opcode::Sload, 15, WIDE_SLOT, imm);
                    self.emit_op(Opcode::Push, 11, 0, 0);
                    self.emit_op(Opcode::Add, 11, 12, 0);
                    self.emit_op(Opcode::Addi, 15, 15, 7);
                    self.emit_op(Opcode::Addi, 14, 0, 3);
                    self.emit_op(Opcode::Shr, 15, 15, 14);
                    self.emit_op(Opcode::Shl, 15, 15, 14);
                    self.emit_op(Opcode::Add, 12, 12, 15);
                    self.emit_unflatten(&ty, 11, rd);
                    self.emit_op(Opcode::Pop, 11, 0, 0);
                } else if is_wide_type(&ty) {
                    let wd = self.regs.alloc_wide(*dst);
                    self.emit_op(Opcode::Addi, 15, 0, slot);
                    self.emit_op(Opcode::Widen, WIDE_SLOT, 15, 0);
                    self.emit_op(Opcode::Sload, wd, WIDE_SLOT, 0);
                } else {
                    let rd = self.alloc_gp(*dst);
                    self.emit_op(Opcode::Addi, 15, 0, slot);
                    self.emit_op(Opcode::Widen, WIDE_SLOT, 15, 0);
                    self.emit_op(Opcode::Sload, rd, WIDE_SLOT, 2);
                }
            }

            Inst::StorageSet(field, val) => {
                let slot = self.storage_slots.get(field.as_str()).copied().unwrap_or(0);
                let ty = self
                    .storage_types
                    .get(field.as_str())
                    .cloned()
                    .unwrap_or(Ty::U64);

                const WIDE_SLOT: u8 = 5;

                // Get value register FIRST (may trigger spill/reload that clobbers r15)
                let rv = self.get_reg(*val);
                // Save value if it's in r15 (which we need for slot)
                let val_saved = rv == 15;
                if val_saved { self.emit_op(Opcode::Push, 15, 0, 0); }

                // NOW set slot in wide register (r15 is safe to clobber)
                self.emit_op(Opcode::Addi, 15, 0, slot);
                self.emit_op(Opcode::Widen, WIDE_SLOT, 15, 0);

                // Restore value if it was in r15
                let rv = if val_saved {
                    self.emit_op(Opcode::Pop, 14, 0, 0); // use r14 instead
                    14u8
                } else { rv };

                if is_blob_type(&ty) {
                    self.emit_op(Opcode::Push, 12, 0, 0);
                    self.emit_flatten(&ty, rv);
                    self.emit_op(Opcode::Pop, 14, 0, 0);
                    self.emit_op(Opcode::Sub, 15, 12, 14);
                    let imm = 1 | ((14 & 0xF) << 2) | ((15 & 0xF) << 6);
                    self.emit_op(Opcode::Sstore, 0, WIDE_SLOT, imm);
                    self.emit_op(Opcode::Add, 12, 14, 0);
                } else if is_wide_type(&ty) {
                    self.emit_op(Opcode::Sstore, rv, WIDE_SLOT, 0);
                } else {
                    self.emit_op(Opcode::Sstore, rv, WIDE_SLOT, 2);
                }
            }

            Inst::StorageMapGet(dst, field, key) => {
                let slot = self.storage_slots.get(field.as_str()).copied().unwrap_or(0);
                let map_ty = self
                    .storage_types
                    .get(field.as_str())
                    .cloned()
                    .unwrap_or(Ty::U64);
                let key_ty = map_key_type(&map_ty);
                let val_ty = map_value_type(&map_ty);
                let key_wide = is_wide_type(&key_ty);
                let wide_value = is_wide_type(&val_ty);

                let rk = self.get_reg(*key);
                self.emit_map_key_derivation(slot, rk, key_wide);
                // Invalidate r14/r15 — clobbered by key derivation
                self.regs.invalidate_physical(14);
                self.regs.invalidate_physical(15);

                if is_blob_type(&val_ty) {
                    // Allocate dest BEFORE Sload to prevent spill clobbering WIDE_SCRATCH
                    let rd = self.alloc_gp(*dst);
                    let imm = 1 | ((12 & 0xF) << 2);
                    self.emit_op(Opcode::Sload, 15, 5, imm); // r15 = byte_len, data at r12 (w5=slot)
                    self.emit_op(Opcode::Push, 11, 0, 0);
                    self.emit_op(Opcode::Add, 11, 12, 0);
                    self.emit_op(Opcode::Addi, 15, 15, 7);
                    self.emit_op(Opcode::Addi, 14, 0, 3);
                    self.emit_op(Opcode::Shr, 15, 15, 14);
                    self.emit_op(Opcode::Shl, 15, 15, 14);
                    self.emit_op(Opcode::Add, 12, 12, 15);
                    self.emit_unflatten(&val_ty, 11, rd);
                    self.emit_op(Opcode::Pop, 11, 0, 0);
                } else if is_wide_type(&val_ty) {
                    // Allocate dest BEFORE Sload to prevent spill clobbering WIDE_SCRATCH
                    let wd = self.regs.alloc_wide(*dst);
                    self.emit_op(Opcode::Sload, wd, 5, 0); // w5=slot
                } else {
                    // Allocate dest BEFORE Sload to prevent spill clobbering WIDE_SCRATCH
                    let rd = self.alloc_gp(*dst);
                    self.emit_op(Opcode::Sload, rd, 5, 2); // w5=slot
                }
            }

            Inst::StorageMapSet(field, key, val) => {
                let slot = self.storage_slots.get(field.as_str()).copied().unwrap_or(0);
                let map_ty = self
                    .storage_types
                    .get(field.as_str())
                    .cloned()
                    .unwrap_or(Ty::U64);
                let key_ty = map_key_type(&map_ty);
                let val_ty = map_value_type(&map_ty);
                let key_wide = is_wide_type(&key_ty);

                // For blob types, save val to stack BEFORE key derivation
                if is_blob_type(&val_ty) {
                    let rv_early = self.get_reg(*val);
                    self.emit_op(Opcode::Push, rv_early, 0, 0);
                }
                let rk = self.get_reg(*key);
                self.emit_map_key_derivation(slot, rk, key_wide);
                // CRITICAL: invalidate r14/r15 mappings — map key derivation clobbers them.
                // Without this, subsequent get_reg() calls return stale physical registers.
                self.regs.invalidate_physical(14);
                self.regs.invalidate_physical(15);

                let rv = if is_blob_type(&val_ty) {
                    self.emit_op(Opcode::Pop, 15, 0, 0);
                    15u8
                } else {
                    self.get_reg(*val)
                };

                if is_blob_type(&val_ty) {
                    self.emit_op(Opcode::Push, 12, 0, 0);
                    self.emit_flatten(&val_ty, rv);
                    self.emit_op(Opcode::Pop, 14, 0, 0);
                    self.emit_op(Opcode::Sub, 15, 12, 14);
                    let imm = 1 | ((14 & 0xF) << 2) | ((15 & 0xF) << 6);
                    self.emit_op(Opcode::Sstore, 0, 5, imm); // w5=slot
                    self.emit_op(Opcode::Add, 12, 14, 0);
                } else if is_wide_type(&val_ty) {
                    self.emit_op(Opcode::Sstore, rv, 5, 0); // w5=slot
                } else {
                    self.emit_op(Opcode::Sstore, rv, 5, 2); // w5=slot
                }
            }

            Inst::StorageNestedMapGet(dst, field, key1, key2) => {
                let slot = self.storage_slots.get(field.as_str()).copied().unwrap_or(0);
                let map_ty = self
                    .storage_types
                    .get(field.as_str())
                    .cloned()
                    .unwrap_or(Ty::U64);
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
                self.regs.invalidate_physical(14);
                self.regs.invalidate_physical(15);

                if wide_value {
                    let wd = self.regs.alloc_wide(*dst);
                    self.emit_op(Opcode::Sload, wd, 5, 0); // w5=slot
                } else {
                    let rd = self.alloc_gp(*dst);
                    self.emit_op(Opcode::Sload, rd, 5, 2); // w5=slot
                }
            }

            Inst::StorageNestedMapSet(field, key1, key2, val) => {
                let slot = self.storage_slots.get(field.as_str()).copied().unwrap_or(0);
                let map_ty = self
                    .storage_types
                    .get(field.as_str())
                    .cloned()
                    .unwrap_or(Ty::U64);
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
                self.regs.invalidate_physical(14);
                self.regs.invalidate_physical(15);

                // Get val AFTER derivation — derivation clobbers r14/r15
                let rv = self.get_reg(*val);
                if wide_value {
                    self.emit_op(Opcode::Sstore, rv, 5, 0); // w5=slot
                } else {
                    self.emit_op(Opcode::Sstore, rv, 5, 2); // w5=slot
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
                    let ret_ty = self.current_return_ty.clone();
                    if is_blob_type(&ret_ty) {
                        // Blob return (Struct/Vec/String): Borsh-serialize to heap,
                        // set r1 = buffer_start, r2 = byte_length.
                        // The RPC handler reads vm.memory[r1..r1+r2] for the full result.
                        let rv = self.get_reg(*v);
                        self.emit_op(Opcode::Push, 12, 0, 0); // save buffer_start = current r12
                        self.emit_flatten(&ret_ty, rv);
                        self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = buffer_start
                        self.emit_op(Opcode::Sub, 2, 12, 15); // r2 = byte_length = r12 - buffer_start
                        self.emit_op(Opcode::Add, 1, 15, 0); // r1 = buffer_start
                    } else {
                        let rv = self.get_reg(*v);
                        if self.regs.is_wide(*v) {
                            // Wide return (u256, Address): use blob convention
                            // Write 32 bytes to heap, set r1 = ptr, r2 = 32
                            if rv != 0 {
                                self.emit_op(Opcode::Wmov, 0, rv, 0);
                            }
                            self.emit_op(Opcode::Wstore, 0, 12, 0);  // mem[heap] = w0
                            self.emit_op(Opcode::Add, 1, 12, 0);     // r1 = heap ptr
                            self.emit_op(Opcode::Addi, 2, 0, 32);    // r2 = 32 bytes
                        } else if rv != 1 {
                            self.emit_op(Opcode::Add, 1, rv, 0);
                            // Clear r2 AFTER rv→r1 copy so blob return check doesn't false-trigger
                            self.emit_op(Opcode::Addi, 2, 0, 0);
                        } else {
                            // rv is already r1, just clear r2
                            self.emit_op(Opcode::Addi, 2, 0, 0);
                        }
                    }
                } else {
                    // Void return: clear r2 to prevent false blob detection
                    self.emit_op(Opcode::Addi, 2, 0, 0);
                }
                // Reentrancy guard cleanup: clear lock before returning.
                // Emitted inside the function body (before Ret) rather than in the
                // dispatch wrapper (after Call returns) for reliable state persistence.
                if self.needs_guard_cleanup && !is_entry {
                    self.emit_reentrancy_cleanup();
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

                // Topic 0: hash of event name (FNV hash, stored as LE u32 in 32 bytes)
                let name_hash = compute_selector(name) as u64;
                self.load_u64_to_reg(15, name_hash);
                self.emit_store(15, 12, 0); // store low 8 bytes of topic
                self.emit_op(Opcode::Addi, 15, 0, 0);
                self.emit_store(15, 12, 8); // zero upper bytes
                self.emit_store(15, 12, 16);
                self.emit_store(15, 12, 24);

                // Data: store field values with correct byte widths per type
                let data_start_offset = 32 + 16; // after topic + ptr/len
                let mut data_offset = data_start_offset;
                for (freg, ty) in fields.iter() {
                    let fr = self.get_reg(*freg);
                    let is_wide = ty == "Address" || ty == "u256" || ty == "i256";
                    if is_wide {
                        // Wide types: store 32 bytes via 4 × Store64
                        // The value is in a wide register; use Narrow to get pieces
                        // For simplicity, store the GP value (8 bytes) + 24 zero bytes
                        self.emit_store(fr, 12, data_offset as i32);
                        // Zero the remaining 24 bytes
                        self.emit_op(Opcode::Addi, 15, 0, 0);
                        self.emit_store(15, 12, (data_offset + 8) as i32);
                        self.emit_store(15, 12, (data_offset + 16) as i32);
                        self.emit_store(15, 12, (data_offset + 24) as i32);
                        data_offset += 32;
                    } else {
                        // GP types (u8-u64, bool, etc.): 8 bytes
                        self.emit_store(fr, 12, data_offset as i32);
                        data_offset += 8;
                    }
                }
                let data_len = (data_offset - data_start_offset) as u32;

                // Write data_ptr and data_len at offset 32
                self.emit_op(Opcode::Addi, 14, 12, data_start_offset as u32);
                self.emit_store(14, 12, 32); // data_ptr
                self.emit_op(Opcode::Addi, 14, 0, data_len);
                self.emit_store(14, 12, 40); // data_len

                // Log rs1=descriptor pointer, imm=num_topics
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
                } else if src_wide && dst_wide {
                    // Wide → Wide: copy (e.g., Address ↔ Contract/Interface)
                    let wd = self.regs.alloc_wide(*dst);
                    let ws = self.get_reg(*src);
                    if wd != ws {
                        self.emit_op(Opcode::Wmov, wd, ws, 0);
                    }
                } else {
                    // GP → GP: copy
                    let rd = self.alloc_gp(*dst);
                    let rs = self.get_reg(*src);
                    if rd != rs {
                        self.emit_op(Opcode::Add, rd, rs, 0);
                    }
                }
            }

            Inst::StructInit(dst, name, fields) => {
                let rd = self.alloc_gp(*dst);
                let struct_size = self.compute_struct_size(name);
                // Allocate on heap: rd = heap_ptr; heap_ptr += struct_size
                self.emit_op(Opcode::Add, rd, 12, 0);
                if struct_size <= 0x1FFFF {
                    self.emit_op(Opcode::Addi, 12, 12, struct_size);
                } else {
                    self.load_u32_to_reg(15, struct_size);
                    self.emit_op(Opcode::Add, 12, 12, 15);
                }
                for (fname, freg) in fields.iter() {
                    let (offset, field_ty) = self.lookup_field(name, fname);
                    let fr = self.get_reg(*freg);
                    if let Ty::Struct(inner) = &field_ty {
                        // Inline nested struct: Memcpy from temp alloc into rd+offset.
                        // Get fr AFTER computing dst to avoid r15 clobber (get_reg
                        // may load from spill into r15, which Addi would overwrite).
                        let copy_size = self.compute_struct_size(inner);
                        self.emit_op(Opcode::Push, rd, 0, 0);
                        self.emit_op(Opcode::Addi, 15, rd, offset); // r15 = dst
                        self.emit_op(Opcode::Push, 11, 0, 0); // save r11
                        self.load_u32_to_reg(11, copy_size); // r11 = byte count
                        let fr2 = self.get_reg_to(*freg, 14); // r14 = src (after dst computed)
                        self.emit_op(Opcode::Memcpy, 15, fr2, 11); // dst=r15, src=r14, len=r11
                        self.emit_op(Opcode::Pop, 11, 0, 0); // restore r11
                        self.emit_op(Opcode::Pop, rd, 0, 0);
                    } else {
                        // GP/wide field: typed store at computed offset
                        self.emit_store_typed(fr, rd, offset as i32, &field_ty);
                    }
                }
            }

            Inst::FieldGet(dst, obj, struct_name, field) => {
                let ro = self.get_reg(*obj);

                if let Ok(idx) = field.parse::<u32>() {
                    // Tuple index access: fixed 8-byte offsets
                    let rd = self.alloc_gp(*dst);
                    let offset = idx * memory::WORD_SIZE;
                    self.emit_load(rd, ro, offset as i32);
                } else if !struct_name.is_empty() {
                    // Struct-aware field access
                    let (offset, field_ty) = self.lookup_field(struct_name, field);
                    if matches!(field_ty, Ty::Struct(_)) {
                        // Inline nested struct: return interior pointer (Addi, no Load)
                        let rd = self.alloc_gp(*dst);
                        self.emit_op(Opcode::Addi, rd, ro, offset);
                    } else if is_wide_type(&field_ty) {
                        // Wide field: Wload
                        let wd = self.regs.alloc_wide(*dst);
                        self.emit_load_typed(wd, ro, offset as i32, &field_ty);
                    } else {
                        // GP field: typed load (W8/W16/W32/W64 based on field type)
                        let rd = self.alloc_gp(*dst);
                        self.emit_load_typed(rd, ro, offset as i32, &field_ty);
                    }
                } else {
                    // Non-struct access (balance, etc.): fallback global search
                    let rd = self.alloc_gp(*dst);
                    let offset = self.find_field_offset_any(field);
                    self.emit_load(rd, ro, offset as i32);
                }
            }

            Inst::IndexGet(dst, obj, idx) => {
                let rd = self.alloc_gp(*dst);
                // With write-through, get_reg_to always re-loads from spill,
                // so each call gets the correct value regardless of prior clobbers.
                let ri = self.get_reg_to(*idx, 14); // r14 = idx
                self.emit_op(Opcode::Addi, 15, 0, 3); // r15 = 3
                self.emit_op(Opcode::Shl, 14, ri, 15); // r14 = idx * 8
                let ro = self.get_reg_to(*obj, 15); // r15 = base (re-loaded from spill)
                self.emit_op(Opcode::Add, 15, ro, 14); // r15 = base + idx*8
                self.emit_op(Opcode::Addi, 15, 15, memory::VEC_DATA_OFFSET);
                self.emit_load(rd, 15, 0);
            }

            Inst::IndexSet(obj, idx, val) => {
                // With write-through, get_reg_to re-loads from spill each call,
                // so sequential calls are safe without Push/Pop.
                let ri = self.get_reg_to(*idx, 14); // r14 = idx
                self.emit_op(Opcode::Addi, 15, 0, 3); // r15 = 3
                self.emit_op(Opcode::Shl, 14, ri, 15); // r14 = idx * 8
                let ro = self.get_reg_to(*obj, 15); // r15 = base (re-loaded)
                self.emit_op(Opcode::Add, 15, ro, 14); // r15 = base + idx*8
                self.emit_op(Opcode::Addi, 15, 15, memory::VEC_DATA_OFFSET);
                let rv = self.get_reg_to(*val, 14); // r14 = val (re-loaded)
                self.emit_store(rv, 15, 0); // data[idx] = val
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
                // Reserve header (16 bytes) + data, matching Vec layout for IndexGet
                let data_size = (regs.len() as u32) * memory::WORD_SIZE;
                let total = memory::VEC_DATA_OFFSET as u32 + data_size;
                self.emit_op(Opcode::Add, rd, 12, 0);
                self.emit_op(Opcode::Addi, 12, 12, total);
                // Write length/capacity header
                self.load_u32_to_reg(15, regs.len() as u32);
                self.emit_store(15, rd, 0); // length
                self.emit_store(15, rd, 8); // capacity
                                            // Write elements at VEC_DATA_OFFSET
                for (i, reg) in regs.iter().enumerate() {
                    let r = self.get_reg(*reg);
                    let offset = memory::VEC_DATA_OFFSET as u32 + (i as u32) * memory::WORD_SIZE;
                    self.emit_store(r, rd, offset as i32);
                }
            }

            Inst::ArrayRepeat(dst, val, count) => {
                let rd = self.alloc_gp(*dst);
                let rv = self.get_reg(*val);
                // Save val to stack — load_u32_to_reg(15, count) clobbers r15 (and r14 as scratch)
                self.emit_op(Opcode::Push, rv, 0, 0);
                let data_size = (*count as u32) * memory::WORD_SIZE;
                let total = memory::VEC_DATA_OFFSET as u32 + data_size;
                self.emit_op(Opcode::Add, rd, 12, 0);
                self.emit_op(Opcode::Addi, 12, 12, total);
                self.load_u32_to_reg(15, *count as u32);
                self.emit_store(15, rd, 0); // length
                self.emit_store(15, rd, 8); // capacity
                                            // Restore val from stack
                self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = val (restored)
                for i in 0..*count {
                    let offset = memory::VEC_DATA_OFFSET as u32 + (i as u32) * memory::WORD_SIZE;
                    self.emit_store(15, rd, offset as i32);
                }
            }

            Inst::MethodCall(dst, obj, method, args) => {
                let rd = self.alloc_gp(*dst);
                let ro = self.get_reg(*obj);

                match method.as_str() {
                    "push" if !args.is_empty() => {
                        // Unified push handler: works for both permanent (r1-r11) and
                        // spill-only (r14/r15) Vec registers. Saves the Vec base to a
                        // fixed spill slot and reloads as needed. Includes full realloc.
                        const PUSH_OBJ_SPILL: i32 = LOOP_STATE_BASE + 32;

                        let val_reg = self.get_reg_to(args[0], 14);
                        self.emit_op(Opcode::Push, val_reg, 0, 0); // save val on stack
                        self.emit_store(ro, 13, PUSH_OBJ_SPILL); // save Vec base

                        // Load length (r15) and capacity (r14) from base
                        // Load base once, read both fields before base register is clobbered.
                        self.emit_load(15, 13, PUSH_OBJ_SPILL); // r15 = base
                        self.emit_load(
                            memory::REG_SCRATCH_0,
                            15,
                            memory::VEC_CAPACITY_OFFSET as i32,
                        ); // r14 = cap
                        self.emit_load(memory::REG_SCRATCH_1, 15, memory::VEC_LENGTH_OFFSET as i32); // r15 = len (clobbers base, OK)

                        let fast_label = self.alloc_label();
                        let realloc_label = self.alloc_label();
                        let write_label = self.alloc_label();

                        // Branch: len < cap → fast path, else → realloc
                        self.emit_op(
                            Opcode::Lt,
                            15,
                            memory::REG_SCRATCH_1,
                            memory::REG_SCRATCH_0 as u32,
                        );
                        self.emit_jump_placeholder(Opcode::Bne, 15, 0, fast_label);
                        self.emit_jump_placeholder(Opcode::Jmp, 0, 0, realloc_label);

                        // === Realloc ===
                        self.mark_label(realloc_label);
                        // New capacity = old_cap * 2
                        self.emit_load(15, 13, PUSH_OBJ_SPILL);
                        self.emit_load(
                            memory::REG_SCRATCH_0,
                            15,
                            memory::VEC_CAPACITY_OFFSET as i32,
                        );
                        self.emit_op(Opcode::Addi, 15, 0, 1);
                        self.emit_op(
                            Opcode::Shl,
                            memory::REG_SCRATCH_0,
                            memory::REG_SCRATCH_0,
                            15,
                        ); // r14 = cap*2
                           // Read old length
                        self.emit_load(15, 13, PUSH_OBJ_SPILL);
                        self.emit_load(memory::REG_SCRATCH_1, 15, memory::VEC_LENGTH_OFFSET as i32); // r15 = len
                                                                                                     // Write new header at r12 (new allocation)
                        self.emit_store(
                            memory::REG_SCRATCH_1,
                            12,
                            memory::VEC_LENGTH_OFFSET as i32,
                        );
                        self.emit_store(
                            memory::REG_SCRATCH_0,
                            12,
                            memory::VEC_CAPACITY_OFFSET as i32,
                        );
                        // Memcpy old data: count = len*8, src = old_base+16, dst = r12+16
                        self.emit_op(Opcode::Addi, 14, 0, 3);
                        self.emit_op(Opcode::Shl, 14, memory::REG_SCRATCH_1, 14); // r14 = len*8
                        self.emit_op(Opcode::Addi, 15, 12, memory::VEC_DATA_OFFSET); // r15 = new data ptr
                        self.emit_op(Opcode::Push, 15, 0, 0); // save new data ptr
                        self.emit_load(15, 13, PUSH_OBJ_SPILL);
                        self.emit_op(Opcode::Addi, 15, 15, memory::VEC_DATA_OFFSET); // r15 = old data ptr
                        self.emit_op(Opcode::Pop, memory::REG_SCRATCH_0, 0, 0); // r14_tmp = new data ptr (actually into r14... let me use stack properly)
                                                                                // Stack juggle: need Memcpy(new_data, old_data, len*8)
                                                                                // r15 = old data ptr, r14 = len*8, need new_data_ptr
                        self.emit_op(Opcode::Push, 14, 0, 0); // save len*8
                        self.emit_op(Opcode::Push, 15, 0, 0); // save old_data
                        self.emit_op(Opcode::Addi, 15, 12, memory::VEC_DATA_OFFSET); // r15 = new data
                        self.emit_op(Opcode::Pop, 14, 0, 0); // r14 = old_data (src)
                        self.emit_op(Opcode::Pop, memory::REG_SCRATCH_0, 0, 0); // ... need 3 regs for Memcpy
                                                                                // Use r11 for len
                        self.emit_op(Opcode::Push, 11, 0, 0);
                        self.emit_op(Opcode::Addi, 11, 0, 3);
                        self.emit_load(memory::REG_SCRATCH_0, 13, PUSH_OBJ_SPILL);
                        self.emit_load(
                            memory::REG_SCRATCH_0,
                            memory::REG_SCRATCH_0,
                            memory::VEC_LENGTH_OFFSET as i32,
                        );
                        self.emit_op(Opcode::Shl, 11, memory::REG_SCRATCH_0, 11); // r11 = len*8
                        self.emit_load(14, 13, PUSH_OBJ_SPILL);
                        self.emit_op(Opcode::Addi, 14, 14, memory::VEC_DATA_OFFSET); // r14 = old data
                        self.emit_op(Opcode::Addi, 15, 12, memory::VEC_DATA_OFFSET); // r15 = new data
                        self.emit_op(Opcode::Memcpy, 15, 14, 11); // copy old→new
                        self.emit_op(Opcode::Pop, 11, 0, 0); // restore r11
                                                             // Update base to new allocation, advance heap
                        self.emit_store(12, 13, PUSH_OBJ_SPILL); // base = r12 (new alloc)
                        self.emit_load(
                            memory::REG_SCRATCH_0,
                            12,
                            memory::VEC_CAPACITY_OFFSET as i32,
                        );
                        self.emit_op(Opcode::Addi, 15, 0, 3);
                        self.emit_op(Opcode::Shl, 15, memory::REG_SCRATCH_0, 15); // r15 = cap*8
                        self.emit_op(Opcode::Addi, 15, 15, memory::VEC_DATA_OFFSET);
                        self.emit_op(Opcode::Add, 12, 12, 15); // r12 past new allocation
                                                               // Load len for write path
                        self.emit_load(15, 13, PUSH_OBJ_SPILL);
                        self.emit_load(memory::REG_SCRATCH_1, 15, memory::VEC_LENGTH_OFFSET as i32);
                        self.emit_jump_placeholder(Opcode::Jmp, 0, 0, write_label);

                        // === Fast path ===
                        self.mark_label(fast_label);
                        self.emit_load(15, 13, PUSH_OBJ_SPILL);
                        self.emit_load(memory::REG_SCRATCH_1, 15, memory::VEC_LENGTH_OFFSET as i32);

                        // === Write value ===
                        self.mark_label(write_label);
                        // r15 (REG_SCRATCH_1) = len from fast/realloc path.
                        // First: increment length and store it (before r15 gets clobbered)
                        self.emit_op(
                            Opcode::Addi,
                            memory::REG_SCRATCH_1,
                            memory::REG_SCRATCH_1,
                            1,
                        ); // r15 = len+1
                        self.emit_op(Opcode::Push, memory::REG_SCRATCH_1, 0, 0); // save new_len
                        self.emit_load(memory::REG_SCRATCH_0, 13, PUSH_OBJ_SPILL); // r14 = base
                        self.emit_op(Opcode::Pop, memory::REG_SCRATCH_1, 0, 0); // r15 = new_len
                        self.emit_store(
                            memory::REG_SCRATCH_1,
                            memory::REG_SCRATCH_0,
                            memory::VEC_LENGTH_OFFSET as i32,
                        );
                        // Compute write addr = base + VEC_DATA_OFFSET + old_len*8
                        // old_len = new_len - 1
                        self.emit_op(
                            Opcode::Addi,
                            memory::REG_SCRATCH_1,
                            memory::REG_SCRATCH_1,
                            0x3FFFF,
                        ); // r15 = old_len (-1)
                        self.emit_op(Opcode::Addi, memory::REG_SCRATCH_0, 0, 3); // r14 = 3
                        self.emit_op(
                            Opcode::Shl,
                            memory::REG_SCRATCH_0,
                            memory::REG_SCRATCH_1,
                            memory::REG_SCRATCH_0 as u32,
                        ); // r14 = old_len*8
                        self.emit_load(15, 13, PUSH_OBJ_SPILL); // r15 = base
                        self.emit_op(
                            Opcode::Add,
                            memory::REG_SCRATCH_0,
                            15,
                            memory::REG_SCRATCH_0 as u32,
                        ); // r14 = base+old_len*8
                        self.emit_op(
                            Opcode::Addi,
                            memory::REG_SCRATCH_0,
                            memory::REG_SCRATCH_0,
                            memory::VEC_DATA_OFFSET,
                        );
                        // Pop val and write
                        self.emit_op(Opcode::Pop, memory::REG_SCRATCH_1, 0, 0);
                        self.emit_store(memory::REG_SCRATCH_1, memory::REG_SCRATCH_0, 0);

                        // If obj was spill-only, update its vreg's canonical spill slot
                        // so subsequent reads get the (potentially reallocated) base.
                        if self.regs.is_spilled(*obj) {
                            self.emit_load(15, 13, PUSH_OBJ_SPILL);
                            self.emit_writeback(*obj, 15);
                        } else if ro <= 11 {
                            // Permanent register: update it with the (potentially new) base
                            self.emit_load(ro, 13, PUSH_OBJ_SPILL);
                        }
                    }
                    "pop" => {
                        // Load length, assert > 0
                        self.emit_load(memory::REG_SCRATCH_1, ro, memory::VEC_LENGTH_OFFSET as i32);
                        self.emit_op(Opcode::Assert, 0, memory::REG_SCRATCH_1, 0); // revert if empty
                                                                                   // Decrement length: Addi with sign-extended -1 (0x3FFFF in 18-bit = -1)
                        self.emit_op(
                            Opcode::Addi,
                            memory::REG_SCRATCH_1,
                            memory::REG_SCRATCH_1,
                            0x3FFFF,
                        );
                        self.emit_store(
                            memory::REG_SCRATCH_1,
                            ro,
                            memory::VEC_LENGTH_OFFSET as i32,
                        );
                        // Load popped value from data[new_length]
                        self.emit_op(Opcode::Addi, memory::REG_SCRATCH_0, 0, 3);
                        self.emit_op(
                            Opcode::Shl,
                            memory::REG_SCRATCH_0,
                            memory::REG_SCRATCH_1,
                            memory::REG_SCRATCH_0 as u32,
                        );
                        self.emit_op(
                            Opcode::Add,
                            memory::REG_SCRATCH_0,
                            ro,
                            memory::REG_SCRATCH_0 as u32,
                        );
                        self.emit_op(
                            Opcode::Addi,
                            memory::REG_SCRATCH_0,
                            memory::REG_SCRATCH_0,
                            memory::VEC_DATA_OFFSET,
                        );
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

            Inst::ExtCall(dst, addr, method, args, ret_ty, value_reg) => {
                let wide_return = is_wide_type(ret_ty);
                let blob_return = matches!(ret_ty, Ty::StringTy | Ty::Bytes | Ty::Vec(_) | Ty::Struct(_));
                let ra = self.get_reg(*addr);

                // Save calldata start for dynamic length calculation
                self.emit_op(Opcode::Push, 12, 0, 0); // save r12 = calldata start

                // Write calldata to heap: [selector(4 BE bytes)][arg0][arg1]...
                // Empty method = value-only transfer (no selector, triggers #[receive])
                let has_selector = !method.is_empty();
                if has_selector {
                    let selector = compute_selector(method);
                    let sel_be = selector.to_be_bytes();
                    let sel_as_le_u32 = u32::from_le_bytes(sel_be);
                    self.load_u32_to_reg(15, sel_as_le_u32);
                    let sel_imm = encode_mem_immediate(0, MemWidth::W32).unwrap();
                    self.emit(encode(Opcode::Store, 15, 12, sel_imm));
                }

                // Write args after selector (offset 4 if selector, 0 if no selector)
                // GP args: 8 bytes via Store. Wide args: 32 bytes via Wstore.
                // Blob args (String, Vec, Struct, Bytes): [byte_len:8][flat data].
                let mut arg_offset: i32 = if has_selector { 4 } else { 0 };
                let mut has_blob_args = false;
                for (arg, ty) in args.iter() {
                    let is_blob = matches!(ty,
                        Ty::StringTy | Ty::Bytes | Ty::Vec(_) | Ty::Struct(_));
                    if is_blob {
                        has_blob_args = true;
                    }
                    if is_wide_type(ty) {
                        // Wide arg: 32 bytes via Wstore
                        let r = self.get_reg(*arg);
                        // If the value is in a GP register (e.g., small u256 literal),
                        // widen it to a wide register first.
                        let wr = if !self.regs.is_wide(*arg) {
                            self.emit_op(Opcode::Widen, WIDE_SCRATCH, r, 0);
                            WIDE_SCRATCH
                        } else {
                            r
                        };
                        if arg_offset != 0 {
                            self.emit_op(Opcode::Addi, 15, 12, arg_offset as u32 & 0x3FFFF);
                            self.emit_op(Opcode::Wstore, wr, 15, 0);
                        } else {
                            self.emit_op(Opcode::Wstore, wr, 12, 0);
                        }
                        arg_offset += 32;
                    } else if matches!(ty, Ty::StringTy | Ty::Bytes) {
                        // String/Bytes: emit_flatten already writes [byte_len:8][data]
                        // which is exactly what the callee expects. No wrapping needed.
                        if arg_offset > 0 {
                            self.emit_op(Opcode::Addi, 12, 12, arg_offset as u32 & 0x3FFFF);
                            arg_offset = 0;
                        }
                        // Move arg to safe register — emit_flatten clobbers r14/r15
                        let r = self.get_reg(*arg);
                        if r == 14 || r == 15 {
                            self.emit_op(Opcode::Add, 11, r, 0);
                            self.emit_flatten(ty, 11);
                        } else {
                            self.emit_flatten(ty, r);
                        }
                    } else if matches!(ty, Ty::Vec(_) | Ty::Struct(_)) {
                        // Vec/Struct: callee expects [byte_len:8][flat data].
                        // emit_flatten writes raw fields/elements (no byte_len prefix).
                        // Wrap with byte_len placeholder → flatten → patch.
                        if arg_offset > 0 {
                            self.emit_op(Opcode::Addi, 12, 12, arg_offset as u32 & 0x3FFFF);
                            arg_offset = 0;
                        }
                        // Move arg to safe register — emit_flatten clobbers r14/r15
                        let r = self.get_reg(*arg);
                        let safe_r = if r == 14 || r == 15 {
                            self.emit_op(Opcode::Add, 11, r, 0); 11
                        } else { r };
                        self.emit_op(Opcode::Push, 12, 0, 0); // save start for byte_len patch
                        self.emit_op(Opcode::Addi, 12, 12, 8); // skip byte_len placeholder
                        self.emit_flatten(ty, safe_r);
                        // Compute byte_len = r12 - (start + 8), patch it
                        self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = start
                        self.emit_op(Opcode::Addi, 14, 15, 8); // r14 = data_start
                        self.emit_op(Opcode::Sub, 14, 12, 14); // r14 = byte_len
                        self.emit_store(14, 15, 0); // patch byte_len at start
                    } else {
                        // GP arg: 8 bytes
                        let r = self.get_reg(*arg);
                        self.emit_store(r, 12, arg_offset);
                        arg_offset += 8;
                    }
                }
                // Compute calldata length: if blob args present, length is dynamic (r12 - start)
                // Otherwise it's a compile-time constant.
                if has_blob_args {
                    // r12 is already past all data; calldata_len = r12 - calldata_start
                    // We need the original calldata start (before selector). It was r12 at entry.
                    // But r12 has been modified. Use a different approach:
                    // We'll compute length via register at CallExt time.
                    // For now, advance past any trailing fixed offset
                    if arg_offset > 0 {
                        self.emit_op(Opcode::Addi, 12, 12, arg_offset as u32 & 0x3FFFF);
                    }
                }
                let static_calldata_len = if !has_blob_args { arg_offset as u32 } else { 0 };

                // Set up CallExt: rd=target(wide), rs1=calldata_ptr(r12), imm=len/gas/result
                // Pop the calldata start we saved before the selector write.
                self.emit_op(Opcode::Pop, 14, 0, 0); // r14 = calldata_start
                if has_blob_args {
                    // Dynamic length: r14 = r12 - calldata_start
                    self.emit_op(Opcode::Sub, 14, 12, 14); // r14 = total calldata len
                    // Restore r12 to calldata start for the CallExt rs1 operand
                    self.emit_op(Opcode::Sub, 12, 12, 14); // r12 = calldata start
                } else {
                    // Static length — r14 is the calldata_start (not needed), overwrite with len
                    self.emit_op(Opcode::Addi, 14, 0, static_calldata_len);
                }
                self.emit_op(Opcode::Caller, 15, 0, 2); // r15 = gas_remaining
                let imm = (14 & 0xF)           // len_reg = r14
                    | ((15 & 0xF) << 4)         // gas_reg = r15
                    | ((13 & 0xF) << 8); // result_reg = r13
                // Load call value into r8 (convention: r8 = msg.value for child)
                // Only set r8 if value is explicitly provided — otherwise leave it alone
                let has_value = value_reg.is_some();
                if let Some(val_vreg) = value_reg {
                    let val_r = self.get_reg(*val_vreg);
                    if val_r != 8 {
                        self.emit_op(Opcode::Add, 8, val_r, 0); // r8 = value
                    }
                }
                // Add value flag to immediate
                let imm = imm | if has_value { 1 << 13 } else { 0 };
                // Save r13 (spill base) — CallExt overwrites it with success flag
                self.emit_op(Opcode::Push, 13, 0, 0);
                self.emit_op(Opcode::CallExt, ra, 12, imm);
                self.emit_op(Opcode::Pop, 13, 0, 0); // restore spill base

                // Advance heap past calldata
                self.emit_op(Opcode::Add, 12, 12, 14); // r12 += calldata_len

                if wide_return {
                    // Wide return (u256, Address): PVM wrote 32 bytes to parent heap
                    // at r12 and set r1 = r12. Wload from r1 into destination.
                    let wd = self.regs.alloc_wide(*dst);
                    self.emit_op(Opcode::Wload, wd, 1, 0);
                    // Advance heap past the 32-byte return data
                    self.emit_op(Opcode::Addi, 12, 12, 32);
                } else if blob_return {
                    // Blob return (String, Vec, Struct, Bytes): callee set r1=ptr, r2=len.
                    // The blob data is in child memory — PVM's do_ext_call copied it to
                    // parent heap at r12. Unflatten from r1 (src) into rd (dst).
                    let rd = self.alloc_gp(*dst);
                    // r1 = heap pointer to blob data, r2 = blob length
                    // Unflatten: src=r1 (blob pointer), dst=rd
                    self.emit_unflatten(ret_ty, 1, rd);
                } else {
                    // GP return (u64, bool, etc.): PVM set r1 = value
                    let rd = self.alloc_gp(*dst);
                    if rd != 1 {
                        self.emit_op(Opcode::Add, rd, 1, 0);
                    }
                }
            }

            Inst::CrossCall {
                target,
                method,
                args,
                ..
            } => {
                // Use different restore targets so both survive if both spilled
                let rt = self.get_reg_to(*target, 15);
                let rm = self.get_reg_to(*method, 14);
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
                // Wide args (Address, u256) get 32 bytes, GP args get 8 bytes.
                let mut arg_offset: i32 = 0;
                for arg in args.iter() {
                    let r = self.get_reg(*arg);
                    if self.regs.is_wide(*arg) {
                        if arg_offset != 0 {
                            self.emit_op(Opcode::Addi, 15, 12, arg_offset as u32 & 0x3FFFF);
                            self.emit_op(Opcode::Wstore, r, 15, 0);
                        } else {
                            self.emit_op(Opcode::Wstore, r, 12, 0);
                        }
                        arg_offset += 32;
                    } else {
                        self.emit_store(r, 12, arg_offset);
                        arg_offset += 8;
                    }
                }
                let calldata_len = arg_offset as u32;

                // Set up CallExt encoding:
                // rd = target address (wide register)
                // rs1 = calldata pointer (r12 = heap)
                // imm[3:0] = len register, imm[7:4] = gas register, imm[11:8] = result register
                self.emit_op(Opcode::Addi, 14, 0, calldata_len); // r14 = calldata len
                self.emit_op(Opcode::Caller, 15, 0, 2); // r15 = gas_remaining
                let imm = (14 & 0xF)           // len_reg = r14
                    | ((15 & 0xF) << 4)         // gas_reg = r15
                    | ((13 & 0xF) << 8); // result_reg = r13
                // Save r13 (spill base) — CallExt overwrites it with success flag
                self.emit_op(Opcode::Push, 13, 0, 0);
                self.emit_op(Opcode::CallExt, rt, 12, imm);
                self.emit_op(Opcode::Pop, 13, 0, 0); // restore spill base

                // Advance heap past calldata
                self.emit_op(Opcode::Addi, 12, 12, calldata_len);

                // After CallExt, r1 = child's return value
                if rd != 1 {
                    self.emit_op(Opcode::Add, rd, 1, 0);
                }
            }

            Inst::CreateContract(dst, blob_reg, args, value_reg) => {
                // The blob register holds an IrConst::Bytes value.
                // At codegen time, the Const handler has already written the blob to heap.
                // blob_reg points to the heap location of the deploy-format bytes.
                // We need to: write constructor args after the blob, then Create.
                let wd = self.regs.alloc_wide(*dst);
                let rb = self.get_reg(*blob_reg); // GP reg with blob heap pointer
                                                  // Save blob pointer to stack — args loop's get_reg calls may clobber r15
                self.emit_op(Opcode::Push, rb, 0, 0);

                // The Const(blob_reg, Bytes(data)) handler writes data to heap[r12]
                // and sets blob_reg = r12, then advances r12.
                // Now r12 is right after the blob — perfect for appending args.

                // Write constructor args after the blob.
                // r12 points to right after the blob — append args here.
                let has_blob_args = args.iter().any(|(_, ty)| matches!(ty,
                    Ty::StringTy | Ty::Bytes | Ty::Vec(_) | Ty::Struct(_)));

                if !has_blob_args {
                    // All fixed-size: use static offsets (original path)
                    for (i, (arg, _ty)) in args.iter().enumerate() {
                        let ra = self.get_reg(*arg);
                        self.emit_store(ra, 12, (i as i32) * 8);
                    }
                    let args_size = (args.len() as u32) * 8;

                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = blob pointer
                    self.emit_op(Opcode::Sub, 14, 12, 15); // r14 = blob_size
                    if args_size > 0 {
                        self.emit_op(Opcode::Addi, 14, 14, args_size);
                        self.emit_op(Opcode::Addi, 12, 12, args_size);
                    }
                } else {
                    // Has blob args: get_reg for each arg FIRST (into safe regs
                    // or stack), then serialize. emit_flatten clobbers r14/r15.
                    // Strategy: push all arg values to stack, then pop and serialize.
                    let mut arg_info: Vec<(Ty, bool)> = Vec::new();
                    for (arg, ty) in args.iter().rev() {
                        // Push args in reverse so first arg pops first
                        let r = self.get_reg(*arg);
                        self.emit_op(Opcode::Push, r, 0, 0);
                        let is_blob = matches!(ty,
                            Ty::StringTy | Ty::Bytes | Ty::Vec(_) | Ty::Struct(_));
                        arg_info.push((ty.clone(), is_blob));
                    }
                    arg_info.reverse(); // back to original order

                    for (ty, is_blob) in &arg_info {
                        // Pop arg value into r11 (safe from emit_flatten's r14/r15)
                        self.emit_op(Opcode::Pop, 11, 0, 0);
                        if matches!(ty, Ty::StringTy | Ty::Bytes) {
                            self.emit_flatten(ty, 11);
                        } else if matches!(ty, Ty::Vec(_) | Ty::Struct(_)) {
                            // Wrap with byte_len prefix
                            self.emit_op(Opcode::Push, 12, 0, 0); // save start
                            self.emit_op(Opcode::Addi, 12, 12, 8);
                            self.emit_flatten(ty, 11);
                            self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = start
                            self.emit_op(Opcode::Addi, 14, 15, 8);
                            self.emit_op(Opcode::Sub, 14, 12, 14);
                            self.emit_store(14, 15, 0);
                        } else if !is_blob {
                            // GP arg
                            self.emit_store(11, 12, 0);
                            self.emit_op(Opcode::Addi, 12, 12, 8);
                        }
                    }

                    // Pop blob pointer, compute total length
                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = blob pointer
                    self.emit_op(Opcode::Sub, 14, 12, 15); // r14 = total length
                }

                // Create: wd = new address, rs1 = blob pointer (r15), imm[3:0] = length register (r14)
                // Load value into r8 if provided (same convention as CallExt)
                if let Some(val_vreg) = value_reg {
                    let val_r = self.get_reg(*val_vreg);
                    if val_r != 8 {
                        self.emit_op(Opcode::Add, 8, val_r, 0);
                    }
                }
                self.emit_op(Opcode::Create, wd, 15, 14 & 0xF);
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

        // Flush pending write-through stores: after each instruction that writes
        // a GP register, store the result to the canonical spill slot.
        for (phys, vreg) in std::mem::take(&mut self.pending_writebacks) {
            self.emit_writeback(vreg, phys);
        }
        // Restore borrowed registers (LIFO order — Pop in reverse)
        for reg in std::mem::take(&mut self.pending_restores).into_iter().rev() {
            self.emit_op(Opcode::Pop, reg, 0, 0);
        }
    }

    // ========================================================================
    // Emit helpers
    // ========================================================================

    /// Allocate a GP register for a virtual register, emitting spill Store if eviction needed.
    /// Also ensures the vreg has a canonical spill slot (for write-through loop safety).
    fn alloc_gp(&mut self, vreg: Reg) -> u8 {
        let (phys, spill) = self.regs.alloc(vreg);
        if let Some(SpillAction::Save(reg, slot)) = spill {
            // Store evicted register to spill area: mem[r13 + slot*8] = reg
            let offset = (slot * 8) as i32;
            let imm = encode_mem_immediate(offset, MemWidth::W64).unwrap();
            self.instructions.push(encode(Opcode::Store, reg, 13, imm));
        }
        // If this vreg is spill-only (no permanent register), borrow r1:
        // 1. Ensure the vreg currently in r1 has a spill slot (so get_reg_to
        //    can load it from spill while r1 is borrowed)
        // 2. Store r1 to that spill slot (write-through for the displaced vreg)
        // 3. Push r1 to PVM stack (for restoration at end of instruction)
        // 4. Use r1 for the new vreg
        if self.regs.is_spilled(vreg) {
            // Ensure the vreg occupying r1 has a spill slot
            if let Some(&displaced_vreg) = self.regs.reverse.get(&phys) {
                if !self.regs.spilled.contains_key(&displaced_vreg) {
                    let slot = self.regs.next_spill_slot;
                    self.regs.next_spill_slot += 1;
                    self.regs.spilled.insert(displaced_vreg, slot);
                }
                // Write r1's current value to the displaced vreg's spill slot
                self.emit_writeback(displaced_vreg, phys);
            }
            self.emit_op(Opcode::Push, phys, 0, 0); // save r1 to stack
            self.pending_writebacks.push((phys, vreg));
            self.pending_restores.push(phys);
        }
        phys
    }

    /// Write-through: store a GP register's value to its canonical spill slot.
    /// Must be called AFTER every instruction that writes a GP destination register.
    fn emit_writeback(&mut self, vreg: Reg, phys: u8) {
        if let Some(&slot) = self.regs.spilled.get(&vreg) {
            self.emit_store(phys, 13, (slot * 8) as i32);
        }
    }

    /// Get the physical register for a virtual register, emitting spill Load if needed.
    /// Restores to r15 by default. Use `get_reg_to` when you need a different target
    /// (e.g., when two operands might both be spilled and would clobber each other).
    fn get_reg(&mut self, vreg: Reg) -> u8 {
        self.get_reg_to(vreg, 15)
    }

    /// Get the physical register for a virtual register, restoring to `restore_to` if spilled.
    /// If the vreg's register is currently borrowed (in pending_restores), loads from
    /// the vreg's spill slot instead of returning the register directly.
    fn get_reg_to(&mut self, vreg: Reg, restore_to: u8) -> u8 {
        match self.regs.get_or_spilled(vreg) {
            Ok(phys) => {
                // Check if this register is currently borrowed by a spill-only alloc.
                // If so, the register doesn't hold this vreg's value — load from spill.
                if self.pending_restores.contains(&phys) {
                    if let Some(&slot) = self.regs.spilled.get(&vreg) {
                        self.emit_load(restore_to, 13, (slot * 8) as i32);
                        return restore_to;
                    }
                }
                phys
            }
            Err(RestoreAction::Restore(_, slot)) => {
                self.emit_load(restore_to, 13, (slot * 8) as i32);
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

    /// Load a struct field using the correct memory width for the type.
    /// Wide types use Wload (32 bytes), GP types use Load with W8/W16/W32/W64.
    fn emit_load_typed(&mut self, rd: u8, base: u8, offset: i32, ty: &Ty) {
        if is_wide_type(ty) {
            if offset != 0 {
                self.emit_op(Opcode::Addi, 15, base, offset as u32 & 0x3FFFF);
                self.emit_op(Opcode::Wload, rd, 15, 0);
            } else {
                self.emit_op(Opcode::Wload, rd, base, 0);
            }
        } else {
            let width = mem_width_for_type(ty);
            let imm = encode_mem_immediate(offset, width).unwrap();
            self.emit(encode(Opcode::Load, rd, base, imm));
        }
    }

    /// Store a struct field using the correct memory width for the type.
    /// Wide types use Wstore (32 bytes), GP types use Store with W8/W16/W32/W64.
    fn emit_store_typed(&mut self, val: u8, base: u8, offset: i32, ty: &Ty) {
        if is_wide_type(ty) {
            if offset != 0 {
                self.emit_op(Opcode::Addi, 15, base, offset as u32 & 0x3FFFF);
                self.emit_op(Opcode::Wstore, val, 15, 0);
            } else {
                self.emit_op(Opcode::Wstore, val, base, 0);
            }
        } else {
            let width = mem_width_for_type(ty);
            let imm = encode_mem_immediate(offset, width).unwrap();
            self.emit(encode(Opcode::Store, val, base, imm));
        }
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
                let new_word =
                    (opcode_bits << 26) | (rd_bits << 22) | (rs1_bits << 18) | offset_bits;
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
        // Use w5 (WIDE_SLOT) instead of WIDE_SCRATCH to avoid clobbering by guards
        let total = 8 + key_size;
        self.emit_op(Opcode::Addi, 14, 0, total);
        self.emit_op(Opcode::Poseidon, 5, 12, 14); // w5 = hash result
    }

    /// DEPRECATED: old Borsh-style serializer. Replaced by emit_flatten.
    #[allow(dead_code)]
    fn emit_serialize(&mut self, ty: &Ty, val_reg: u8) {
        if is_wide_type(ty) {
            // Wide types (u256, i256, Address): 32 bytes via Wstore
            self.emit_op(Opcode::Wstore, val_reg, 12, 0);
            self.emit_op(Opcode::Addi, 12, 12, 32);
        } else if matches!(ty, Ty::StringTy | Ty::Bytes) {
            // String/Bytes: val_reg points to Vec layout [len:8][cap:8][data...]
            // Save val_reg (might be r14 which gets clobbered by byte_len load)
            self.emit_op(Opcode::Push, val_reg, 0, 0);
            self.emit_load(14, val_reg, 0); // r14 = byte_len
            self.emit_store(14, 12, 0); // write byte_len prefix
            self.emit_op(Opcode::Addi, 12, 12, 8); // advance past prefix
            self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = val_reg (string base)
            self.emit_op(Opcode::Addi, 15, 15, memory::VEC_DATA_OFFSET); // r15 = data ptr
            self.emit_op(Opcode::Memcpy, 12, 15, 14); // Memcpy dst=r12, src=r15, len=r14
                                                      // Advance r12 by align8(byte_len): r12 += (byte_len + 7) & ~7
            self.emit_op(Opcode::Addi, 14, 14, 7);
            self.emit_op(Opcode::Addi, 15, 0, 3); // shift amount = 3
            self.emit_op(Opcode::Shr, 14, 14, 15); // r14 = (len+7) >> 3
            self.emit_op(Opcode::Shl, 14, 14, 15); // r14 = ((len+7) >> 3) << 3 = align8
            self.emit_op(Opcode::Add, 12, 12, 14); // r12 += aligned size
        } else if let Ty::Vec(elem_ty) = ty {
            let elem_size = serialized_elem_size(elem_ty);
            // Save val_reg on stack (it may be r14/r15 which get clobbered)
            self.emit_op(Opcode::Push, val_reg, 0, 0);
            // Write count prefix
            self.emit_load(14, val_reg, 0); // r14 = element count
            self.emit_store(14, 12, 0); // write count
            self.emit_op(Opcode::Addi, 12, 12, 8); // advance past count prefix

            match elem_size {
                Some(8) => {
                    // Vec of GP-sized elements: bulk Memcpy count*8 bytes
                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = vec base (saved)
                    self.emit_op(Opcode::Addi, 15, 15, memory::VEC_DATA_OFFSET); // r15 = data ptr
                    self.emit_op(Opcode::Push, 15, 0, 0); // save data ptr
                    self.emit_op(Opcode::Addi, 15, 0, 3);
                    self.emit_op(Opcode::Shl, 14, 14, 15); // r14 = count * 8
                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = data ptr
                    self.emit_op(Opcode::Memcpy, 12, 15, 14); // copy data
                    self.emit_op(Opcode::Add, 12, 12, 14); // advance r12
                }
                Some(32) => {
                    // Vec of wide elements: loop with Wload/Wstore
                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = vec base (saved)
                    self.emit_store(14, 13, LOOP_STATE_BASE + 8); // spill count
                    self.emit_op(Opcode::Addi, 15, 15, memory::VEC_DATA_OFFSET);
                    self.emit_store(15, 13, LOOP_STATE_BASE + 16); // spill src_ptr
                    self.emit_op(Opcode::Addi, 14, 0, 0); // i = 0
                    self.emit_store(14, 13, LOOP_STATE_BASE); // spill i

                    let loop_label = self.alloc_label();
                    let done_label = self.alloc_label();
                    self.mark_label(loop_label);

                    // Check i < count
                    self.emit_load(14, 13, LOOP_STATE_BASE); // r14 = i
                    self.emit_load(15, 13, LOOP_STATE_BASE + 8); // r15 = count
                    self.emit_jump_placeholder(Opcode::Beq, 14, 15, done_label); // if i == count → done

                    // Load src_ptr, Wload element, Wstore to r12
                    self.emit_load(15, 13, LOOP_STATE_BASE + 16); // r15 = src_ptr
                    self.emit_op(Opcode::Wload, WIDE_SCRATCH2, 15, 0); // w6 = *src_ptr
                    self.emit_op(Opcode::Wstore, WIDE_SCRATCH2, 12, 0); // *r12 = w6
                    self.emit_op(Opcode::Addi, 12, 12, 32); // r12 += 32
                    self.emit_op(Opcode::Addi, 15, 15, 32); // src_ptr += 32
                    self.emit_store(15, 13, LOOP_STATE_BASE + 16); // update src_ptr

                    // i++
                    self.emit_load(14, 13, LOOP_STATE_BASE);
                    self.emit_op(Opcode::Addi, 14, 14, 1);
                    self.emit_store(14, 13, LOOP_STATE_BASE);
                    self.emit_jump_placeholder(Opcode::Jmp, 0, 0, loop_label);

                    self.mark_label(done_label);
                }
                None => {
                    // Vec of variable-size elements (Vec<String>, Vec<Vec<T>>, Vec<Struct>).
                    // Stack-based countdown loop. At each iteration top-of-stack = [src_ptr, remaining].
                    // No GP registers are used for persistent state — only stack.
                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = vec base (saved from Push earlier)
                    self.emit_load(14, 15, 0); // r14 = count from vec header
                    self.emit_op(Opcode::Addi, 15, 15, memory::VEC_DATA_OFFSET); // r15 = data start
                                                                                 // Push initial state: [src_ptr, remaining]
                    self.emit_op(Opcode::Push, 14, 0, 0); // push remaining = count
                    self.emit_op(Opcode::Push, 15, 0, 0); // push src_ptr

                    let loop_label = self.alloc_label();
                    let done_label = self.alloc_label();
                    self.mark_label(loop_label);

                    // Pop state
                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = src_ptr
                    self.emit_op(Opcode::Pop, 14, 0, 0); // r14 = remaining
                    self.emit_jump_placeholder(Opcode::Beq, 14, 0, done_label);

                    // Decrement remaining, advance src_ptr, push updated state BEFORE serialize
                    self.emit_op(Opcode::Addi, 14, 14, 0x3FFFF); // r14 = remaining - 1 (twos complement -1)
                    self.emit_op(Opcode::Push, 14, 0, 0); // push remaining-1
                    self.emit_op(Opcode::Addi, 14, 15, 8); // r14 = src_ptr + 8
                    self.emit_op(Opcode::Push, 14, 0, 0); // push new src_ptr
                                                          // Load element pointer from OLD src_ptr (r15)
                    self.emit_load(14, 15, 0); // r14 = *src_ptr

                    // Recursively serialize (clobbers r14, r15, but stack has the state)
                    let elem_ty_clone = (**elem_ty).clone();
                    self.emit_serialize(&elem_ty_clone, 14);

                    self.emit_jump_placeholder(Opcode::Jmp, 0, 0, loop_label);
                    self.mark_label(done_label);
                }
                Some(_) => {
                    // 16-byte elements (u128/i128): bulk Memcpy count*16 bytes
                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = vec base (saved)
                    self.emit_op(Opcode::Addi, 15, 15, memory::VEC_DATA_OFFSET);
                    self.emit_op(Opcode::Push, 15, 0, 0); // save data ptr
                    self.emit_op(Opcode::Addi, 15, 0, 4); // shift by 4
                    self.emit_op(Opcode::Shl, 14, 14, 15); // r14 = count * 16
                    self.emit_op(Opcode::Pop, 15, 0, 0); // data ptr
                    self.emit_op(Opcode::Memcpy, 12, 15, 14);
                    self.emit_op(Opcode::Add, 12, 12, 14);
                }
            }
        } else if let Ty::Struct(name) = ty {
            // Struct: serialize field-by-field, recursing into nested structs.
            if let Some(fields) = self.struct_defs.get(name).cloned() {
                let has_nested = fields
                    .iter()
                    .any(|(_, fty)| matches!(fty, Ty::Struct(_)) || is_blob_type(fty));
                if has_nested {
                    // Recursive: serialize each field individually.
                    // Push val_reg (struct base) before each field, Pop AFTER serialize
                    // so that emit_serialize can freely use r14/r15 as scratch without
                    // clobbering val_reg (critical when val_reg is r14/r15 for spill-only).
                    for (i, (_, fty)) in fields.iter().enumerate() {
                        let offset = (i as u32) * memory::WORD_SIZE;
                        self.emit_op(Opcode::Push, val_reg, 0, 0);
                        // Load field value from struct
                        if is_wide_type(&fty) {
                            self.emit_op(Opcode::Addi, 15, val_reg, offset);
                            self.emit_op(Opcode::Wload, WIDE_SCRATCH2, 15, 0);
                            self.emit_serialize(&fty, WIDE_SCRATCH2);
                        } else {
                            self.emit_load(14, val_reg, offset as i32);
                            self.emit_serialize(&fty, 14);
                        }
                        // Restore struct base for next field iteration
                        self.emit_op(Opcode::Pop, val_reg, 0, 0);
                    }
                } else {
                    // Flat: all GP fields, Memcpy the whole struct
                    let byte_size = (fields.len() as u32) * memory::WORD_SIZE;
                    self.emit_op(Opcode::Push, val_reg, 0, 0);
                    self.emit_op(Opcode::Pop, 15, 0, 0);
                    self.load_u32_to_reg(14, byte_size);
                    self.emit_op(Opcode::Memcpy, 12, 15, 14);
                    self.emit_op(Opcode::Add, 12, 12, 14);
                }
            }
        } else {
            // GP types (u8-u64, bool, Enum, etc.): 8 bytes via Store
            self.emit_store(val_reg, 12, 0);
            self.emit_op(Opcode::Addi, 12, 12, 8);
        }
    }

    // ========================================================================
    // Flat inline format: flatten (pointer-based → flat wire bytes at r12)
    // ========================================================================

    /// Flatten a value in `val_reg` to heap at r12, advancing r12.
    /// Produces flat inline bytes: GP→8B, wide→32B, String→[byte_len:8][data],
    /// Vec→[len:8][cap:8][elem0][elem1]..., Struct→fields inlined recursively.
    fn emit_flatten(&mut self, ty: &Ty, val_reg: u8) {
        if is_wide_type(ty) {
            self.emit_op(Opcode::Wstore, val_reg, 12, 0);
            self.emit_op(Opcode::Addi, 12, 12, 32);
        } else if matches!(ty, Ty::StringTy | Ty::Bytes) {
            // String/Bytes: val_reg → Vec layout [len:8][cap:8][data...]
            // Write [byte_len:8][data padded to 8]
            self.emit_op(Opcode::Push, val_reg, 0, 0);
            self.emit_load(14, val_reg, 0); // r14 = byte_len
            self.emit_store(14, 12, 0); // write byte_len prefix
            self.emit_op(Opcode::Addi, 12, 12, 8);
            self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = string base
            self.emit_op(Opcode::Addi, 15, 15, memory::VEC_DATA_OFFSET);
            self.emit_op(Opcode::Memcpy, 12, 15, 14);
            // Advance r12 by align8(byte_len)
            self.emit_op(Opcode::Addi, 14, 14, 7);
            self.emit_op(Opcode::Addi, 15, 0, 3);
            self.emit_op(Opcode::Shr, 14, 14, 15);
            self.emit_op(Opcode::Shl, 14, 14, 15);
            self.emit_op(Opcode::Add, 12, 12, 14);
        } else if let Ty::Vec(elem_ty) = ty {
            let defs = self.struct_defs.clone();
            let elem_size = flat_elem_size(elem_ty, &defs);
            // Save val_reg (may be r14/r15), then Pop to r15 for safe field access
            self.emit_op(Opcode::Push, val_reg, 0, 0);
            self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = vec base (safe)
            self.emit_op(Opcode::Push, 15, 0, 0); // push back for later use
                                                  // Write [len:8][cap:8] header
            self.emit_load(14, 15, memory::VEC_LENGTH_OFFSET as i32); // r14 = len
            self.emit_store(14, 12, 0); // write len
            self.emit_op(Opcode::Push, 14, 0, 0); // save len
            self.emit_load(14, 15, memory::VEC_CAPACITY_OFFSET as i32); // r14 = cap
            self.emit_store(14, 12, 8); // write cap
            self.emit_op(Opcode::Pop, 14, 0, 0); // restore r14 = len (count)
            self.emit_op(Opcode::Addi, 12, 12, 16); // advance past 16-byte header
                                                    // r14 = count for the element loop below

            match elem_size {
                Some(sz) if sz == 8 || sz == 16 || sz == 32 => {
                    // Fixed-size elements: bulk Memcpy count * sz bytes
                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = vec base
                    self.emit_op(Opcode::Addi, 15, 15, memory::VEC_DATA_OFFSET);
                    self.emit_op(Opcode::Push, 15, 0, 0); // save data ptr
                    let shift = if sz == 8 {
                        3
                    } else if sz == 16 {
                        4
                    } else {
                        5
                    };
                    self.emit_op(Opcode::Addi, 15, 0, shift);
                    self.emit_op(Opcode::Shl, 14, 14, 15); // r14 = count * sz
                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = data ptr
                    self.emit_op(Opcode::Memcpy, 12, 15, 14);
                    self.emit_op(Opcode::Add, 12, 12, 14);
                }
                Some(sz) => {
                    // Fixed-size struct elements: bulk Memcpy count * sz bytes
                    // sz is not a power of 2, so compute count * sz via multiply
                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = vec base
                    self.emit_op(Opcode::Addi, 15, 15, memory::VEC_DATA_OFFSET);
                    self.emit_op(Opcode::Push, 15, 0, 0);
                    self.load_u32_to_reg(15, sz);
                    self.emit_op(Opcode::Mul, 14, 14, 15); // r14 = count * sz
                    self.emit_op(Opcode::Pop, 15, 0, 0);
                    self.emit_op(Opcode::Memcpy, 12, 15, 14);
                    self.emit_op(Opcode::Add, 12, 12, 14);
                }
                None => {
                    // Variable-size elements: stack-based countdown loop
                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = vec base
                    self.emit_load(14, 15, 0); // r14 = count
                    self.emit_op(Opcode::Addi, 15, 15, memory::VEC_DATA_OFFSET);
                    self.emit_op(Opcode::Push, 14, 0, 0); // push remaining
                    self.emit_op(Opcode::Push, 15, 0, 0); // push src_ptr

                    let loop_label = self.alloc_label();
                    let done_label = self.alloc_label();
                    self.mark_label(loop_label);

                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = src_ptr
                    self.emit_op(Opcode::Pop, 14, 0, 0); // r14 = remaining
                    self.emit_jump_placeholder(Opcode::Beq, 14, 0, done_label);

                    self.emit_op(Opcode::Addi, 14, 14, 0x3FFFF); // remaining--
                    self.emit_op(Opcode::Push, 14, 0, 0);
                    self.emit_op(Opcode::Addi, 14, 15, 8); // new src_ptr
                    self.emit_op(Opcode::Push, 14, 0, 0);
                    self.emit_load(14, 15, 0); // r14 = *src_ptr (element ptr)

                    let elem_ty_clone = (**elem_ty).clone();
                    self.emit_flatten(&elem_ty_clone, 14);

                    self.emit_jump_placeholder(Opcode::Jmp, 0, 0, loop_label);
                    self.mark_label(done_label);
                }
            }
        } else if let Ty::Struct(name) = ty {
            // Struct: ALWAYS recursive field-by-field with actual byte offsets.
            // For inline nested structs, use Addi (interior pointer) instead of Load.
            if let Some(fields) = self.struct_defs.get(name).cloned() {
                let offsets: Vec<(u32, Ty)> = fields
                    .iter()
                    .map(|(fname, _)| self.lookup_field(name, fname))
                    .collect();
                for (offset, fty) in &offsets {
                    self.emit_op(Opcode::Push, val_reg, 0, 0);
                    if matches!(fty, Ty::Struct(_)) {
                        // Inline nested struct: Addi to get interior pointer
                        self.emit_op(Opcode::Addi, 14, val_reg, *offset);
                        self.emit_flatten(fty, 14);
                    } else if is_wide_type(fty) {
                        self.emit_load_typed(WIDE_SCRATCH2, val_reg, *offset as i32, fty);
                        self.emit_flatten(fty, WIDE_SCRATCH2);
                    } else {
                        // GP: typed load (W8/W16/W32/W64) into r14
                        self.emit_load_typed(14, val_reg, *offset as i32, fty);
                        self.emit_flatten(fty, 14);
                    }
                    self.emit_op(Opcode::Pop, val_reg, 0, 0);
                }
            }
        } else {
            // GP types: 8 bytes
            self.emit_store(val_reg, 12, 0);
            self.emit_op(Opcode::Addi, 12, 12, 8);
        }
    }

    // ========================================================================
    // Flat inline format: unflatten (flat wire bytes → pointer-based in-memory)
    // ========================================================================

    /// Unflatten from flat wire bytes at mem[src_reg] into pointer-based in-memory
    /// layout, advancing src_reg. Result goes into dst_reg.
    /// Flat format: GP→8B, wide→32B, String→[byte_len:8][data],
    /// Vec→[len:8][cap:8][elem0]..., Struct→fields inlined recursively.
    fn emit_unflatten(&mut self, ty: &Ty, src_reg: u8, dst_reg: u8) {
        if is_wide_type(ty) {
            self.emit_op(Opcode::Wload, dst_reg, src_reg, 0);
            self.emit_op(Opcode::Addi, src_reg, src_reg, 32);
        } else if matches!(ty, Ty::StringTy | Ty::Bytes) {
            // String: read [byte_len:8][data...], build Vec layout on heap
            self.emit_op(Opcode::Add, dst_reg, 12, 0); // dst = Vec base
            let dst_saved = dst_reg == 14 || dst_reg == 15;
            if dst_saved {
                self.emit_op(Opcode::Push, dst_reg, 0, 0);
            }
            self.emit_load(14, src_reg, 0); // r14 = byte_len
            self.emit_op(Opcode::Addi, src_reg, src_reg, 8);
            self.emit_store(14, 12, 0); // header.length
            self.emit_store(14, 12, 8); // header.capacity
            self.emit_op(Opcode::Addi, 12, 12, memory::VEC_DATA_OFFSET);
            self.emit_op(Opcode::Memcpy, 12, src_reg, 14);
            // Advance src and r12 by align8(byte_len)
            self.emit_op(Opcode::Addi, 15, 14, 7);
            self.emit_op(Opcode::Addi, 14, 0, 3);
            self.emit_op(Opcode::Shr, 15, 15, 14);
            self.emit_op(Opcode::Shl, 15, 15, 14);
            self.emit_op(Opcode::Add, src_reg, src_reg, 15);
            self.emit_op(Opcode::Add, 12, 12, 15);
            if dst_saved {
                self.emit_op(Opcode::Pop, dst_reg, 0, 0);
            }
        } else if let Ty::Vec(elem_ty) = ty {
            let defs = self.struct_defs.clone();
            let elem_size = flat_elem_size(elem_ty, &defs);
            // dst = Vec base on heap
            self.emit_op(Opcode::Add, dst_reg, 12, 0);
            let dst_saved = dst_reg == 14 || dst_reg == 15;
            if dst_saved {
                self.emit_op(Opcode::Push, dst_reg, 0, 0);
            }
            // Read [len:8][cap:8] from flat wire
            self.emit_load(14, src_reg, 0); // r14 = len
            self.emit_op(Opcode::Addi, src_reg, src_reg, 8);
            self.emit_load(15, src_reg, 0); // r15 = cap
            self.emit_op(Opcode::Addi, src_reg, src_reg, 8);
            // Write Vec header on heap
            self.emit_store(14, 12, 0); // header.length = len
            self.emit_store(15, 12, 8); // header.capacity = cap
            self.emit_op(Opcode::Addi, 12, 12, memory::VEC_DATA_OFFSET);

            match elem_size {
                Some(sz) if sz == 8 || sz == 16 || sz == 32 => {
                    // Fixed-size elements: bulk Memcpy
                    let shift = if sz == 8 {
                        3
                    } else if sz == 16 {
                        4
                    } else {
                        5
                    };
                    self.emit_op(Opcode::Addi, 15, 0, shift);
                    self.emit_op(Opcode::Shl, 14, 14, 15); // r14 = count * sz
                    self.emit_op(Opcode::Memcpy, 12, src_reg, 14);
                    self.emit_op(Opcode::Add, src_reg, src_reg, 14);
                    self.emit_op(Opcode::Add, 12, 12, 14);
                }
                Some(sz) => {
                    // Fixed-size struct elements: bulk Memcpy count * sz
                    self.emit_op(Opcode::Push, 14, 0, 0); // save count
                    self.load_u32_to_reg(15, sz);
                    self.emit_op(Opcode::Pop, 14, 0, 0);
                    self.emit_op(Opcode::Mul, 14, 14, 15); // r14 = count * sz
                    self.emit_op(Opcode::Memcpy, 12, src_reg, 14);
                    self.emit_op(Opcode::Add, src_reg, src_reg, 14);
                    self.emit_op(Opcode::Add, 12, 12, 14);
                }
                None => {
                    // Variable-size elements: loop unflatten each into Vec data slots
                    self.emit_store(14, 13, LOOP_STATE_BASE + 8); // spill count
                    self.emit_store(src_reg, 13, LOOP_STATE_BASE + 16); // spill src_reg
                    self.emit_op(Opcode::Add, 14, 12, 0); // r14 = data start
                    self.emit_store(14, 13, LOOP_STATE_BASE + 24); // spill dst_data_ptr
                                                                   // Reserve pointer array: count * 8
                    self.emit_load(14, 13, LOOP_STATE_BASE + 8);
                    self.emit_op(Opcode::Addi, 15, 0, 3);
                    self.emit_op(Opcode::Shl, 14, 14, 15);
                    self.emit_op(Opcode::Add, 12, 12, 14);

                    self.emit_op(Opcode::Addi, 14, 0, 0); // i = 0
                    self.emit_store(14, 13, LOOP_STATE_BASE);

                    let loop_label = self.alloc_label();
                    let done_label = self.alloc_label();
                    self.mark_label(loop_label);

                    self.emit_load(14, 13, LOOP_STATE_BASE);
                    self.emit_load(15, 13, LOOP_STATE_BASE + 8);
                    self.emit_jump_placeholder(Opcode::Beq, 14, 15, done_label);

                    self.emit_op(Opcode::Push, 12, 0, 0); // save elem_ptr
                    self.emit_load(src_reg, 13, LOOP_STATE_BASE + 16);
                    let elem_ty_clone = (**elem_ty).clone();
                    self.emit_unflatten(&elem_ty_clone, src_reg, 14);
                    self.emit_store(src_reg, 13, LOOP_STATE_BASE + 16);

                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = elem_ptr
                    self.emit_load(14, 13, LOOP_STATE_BASE + 24);
                    self.emit_store(15, 14, 0);
                    self.emit_op(Opcode::Addi, 14, 14, 8);
                    self.emit_store(14, 13, LOOP_STATE_BASE + 24);

                    self.emit_load(14, 13, LOOP_STATE_BASE);
                    self.emit_op(Opcode::Addi, 14, 14, 1);
                    self.emit_store(14, 13, LOOP_STATE_BASE);
                    self.emit_jump_placeholder(Opcode::Jmp, 0, 0, loop_label);

                    self.mark_label(done_label);
                    self.emit_load(src_reg, 13, LOOP_STATE_BASE + 16);
                }
            }
            if dst_saved {
                self.emit_op(Opcode::Pop, dst_reg, 0, 0);
            }
        } else if let Ty::Struct(name) = ty {
            // Struct: ALWAYS recursive — allocate struct on heap with actual inline size,
            // unflatten each field at its actual byte offset.
            if let Some(fields) = self.struct_defs.get(name).cloned() {
                let struct_size = self.compute_struct_size(name);
                self.emit_op(Opcode::Push, 12, 0, 0); // push struct base = r12
                if struct_size <= 0x1FFFF {
                    self.emit_op(Opcode::Addi, 12, 12, struct_size);
                } else {
                    self.load_u32_to_reg(15, struct_size);
                    self.emit_op(Opcode::Add, 12, 12, 15);
                }

                let offsets: Vec<(u32, Ty)> = fields
                    .iter()
                    .map(|(fname, _)| self.lookup_field(name, fname))
                    .collect();
                for (offset, fty) in &offsets {
                    if matches!(fty, Ty::Struct(..)) {
                        // Inline nested struct: unflatten creates a temp heap alloc,
                        // then Memcpy into parent's inline slot at struct_base + offset.
                        let inner_size = self.field_byte_size(fty);
                        self.emit_unflatten(fty, src_reg, 14); // r14 = temp alloc ptr (src)
                        self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = struct_base (peek)
                        self.emit_op(Opcode::Push, 15, 0, 0);
                        self.emit_op(Opcode::Addi, 15, 15, *offset); // r15 = dst
                                                                     // Borrow r11 for len
                        self.emit_op(Opcode::Push, 11, 0, 0);
                        self.load_u32_to_reg(11, inner_size);
                        self.emit_op(Opcode::Memcpy, 15, 14, 11); // dst=r15, src=r14, len=r11
                        self.emit_op(Opcode::Pop, 11, 0, 0);
                    } else if is_wide_type(fty) {
                        // Wide field: unflatten into wide register, Wstore at offset
                        let wd = WIDE_SCRATCH2; // w6
                        self.emit_unflatten(fty, src_reg, wd);
                        self.emit_op(Opcode::Pop, 15, 0, 0); // peek struct base
                        self.emit_op(Opcode::Push, 15, 0, 0);
                        self.emit_store_typed(wd, 15, *offset as i32, fty);
                    } else {
                        // GP field or pointer: unflatten returns value in r14, typed store
                        self.emit_unflatten(fty, src_reg, 14);
                        self.emit_op(Opcode::Pop, 15, 0, 0); // peek struct base
                        self.emit_op(Opcode::Push, 15, 0, 0);
                        self.emit_store_typed(14, 15, *offset as i32, fty);
                    }
                }
                self.emit_op(Opcode::Pop, dst_reg, 0, 0); // dst = struct base
            }
        } else {
            // GP types: 8 bytes
            self.emit_load(dst_reg, src_reg, 0);
            self.emit_op(Opcode::Addi, src_reg, src_reg, 8);
        }
    }

    /// DEPRECATED: old Borsh-style deserializer. Replaced by emit_unflatten.
    #[allow(dead_code)]
    fn emit_deserialize(&mut self, ty: &Ty, src_reg: u8, dst_reg: u8) {
        if is_wide_type(ty) {
            // Wide types: 32 bytes via Wload
            self.emit_op(Opcode::Wload, dst_reg, src_reg, 0);
            self.emit_op(Opcode::Addi, src_reg, src_reg, 32);
        } else if matches!(ty, Ty::StringTy | Ty::Bytes) {
            // String/Bytes: read [byte_len:8][data...]
            // Build Vec layout at r12: [len:8][cap:8][data...]
            // dst_reg = base of new Vec = r12
            self.emit_op(Opcode::Add, dst_reg, 12, 0); // dst = r12 (Vec base)
                                                       // Save dst_reg if it conflicts with scratch
            let dst_saved = dst_reg == 14 || dst_reg == 15;
            if dst_saved {
                self.emit_op(Opcode::Push, dst_reg, 0, 0);
            }
            self.emit_load(14, src_reg, 0); // r14 = byte_len
            self.emit_op(Opcode::Addi, src_reg, src_reg, 8); // advance past length prefix
                                                             // Write Vec header
            self.emit_store(14, 12, 0); // header.length = byte_len
            self.emit_store(14, 12, 8); // header.capacity = byte_len
            self.emit_op(Opcode::Addi, 12, 12, memory::VEC_DATA_OFFSET); // skip header
                                                                         // Memcpy data from src to r12
            self.emit_op(Opcode::Memcpy, 12, src_reg, 14); // copy byte_len bytes
                                                           // Advance src_reg by align8(byte_len)
            self.emit_op(Opcode::Addi, 15, 14, 7); // r15 = byte_len + 7
            self.emit_op(Opcode::Addi, 14, 0, 3); // shift = 3
            self.emit_op(Opcode::Shr, 15, 15, 14); // r15 = (byte_len+7) >> 3
            self.emit_op(Opcode::Shl, 15, 15, 14); // r15 = align8(byte_len)
            self.emit_op(Opcode::Add, src_reg, src_reg, 15); // src_reg += aligned
                                                             // Advance r12 past data
            self.emit_op(Opcode::Add, 12, 12, 15); // r12 += aligned
            if dst_saved {
                self.emit_op(Opcode::Pop, dst_reg, 0, 0);
            }
        } else if let Ty::Vec(elem_ty) = ty {
            let elem_size = serialized_elem_size(elem_ty);
            // dst_reg = base of new Vec = r12
            self.emit_op(Opcode::Add, dst_reg, 12, 0); // dst = Vec base
                                                       // Save dst_reg if it's a scratch register (r14/r15) — scratch gets
                                                       // clobbered during header setup and element processing below.
            let dst_saved = dst_reg == 14 || dst_reg == 15;
            if dst_saved {
                self.emit_op(Opcode::Push, dst_reg, 0, 0);
            }
            self.emit_load(14, src_reg, 0); // r14 = count
            self.emit_op(Opcode::Addi, src_reg, src_reg, 8); // advance past count prefix
                                                             // Write Vec header
            self.emit_store(14, 12, 0); // header.length = count
            self.emit_store(14, 12, 8); // header.capacity = count
            self.emit_op(Opcode::Addi, 12, 12, memory::VEC_DATA_OFFSET); // skip header

            match elem_size {
                Some(8) => {
                    // Vec<GP>: bulk Memcpy count*8 bytes
                    self.emit_op(Opcode::Addi, 15, 0, 3);
                    self.emit_op(Opcode::Shl, 14, 14, 15); // r14 = count * 8
                    self.emit_op(Opcode::Memcpy, 12, src_reg, 14); // copy data
                    self.emit_op(Opcode::Add, src_reg, src_reg, 14); // advance src
                    self.emit_op(Opcode::Add, 12, 12, 14); // advance r12
                }
                Some(32) => {
                    // Vec<wide>: loop Wload/Wstore
                    // Spill state at r13+LOOP_STATE_BASE: +0=i, +8=count, +16=src_reg
                    self.emit_store(14, 13, LOOP_STATE_BASE + 8); // spill count
                    self.emit_store(src_reg, 13, LOOP_STATE_BASE + 16); // spill src_reg
                    self.emit_op(Opcode::Addi, 14, 0, 0); // i = 0
                    self.emit_store(14, 13, LOOP_STATE_BASE); // spill i

                    let loop_label = self.alloc_label();
                    let done_label = self.alloc_label();
                    self.mark_label(loop_label);

                    self.emit_load(14, 13, LOOP_STATE_BASE); // r14 = i
                    self.emit_load(15, 13, LOOP_STATE_BASE + 8); // r15 = count
                    self.emit_jump_placeholder(Opcode::Beq, 14, 15, done_label);

                    self.emit_load(15, 13, LOOP_STATE_BASE + 16); // r15 = src ptr
                    self.emit_op(Opcode::Wload, WIDE_SCRATCH2, 15, 0);
                    self.emit_op(Opcode::Wstore, WIDE_SCRATCH2, 12, 0);
                    self.emit_op(Opcode::Addi, 12, 12, 32);
                    self.emit_op(Opcode::Addi, 15, 15, 32);
                    self.emit_store(15, 13, LOOP_STATE_BASE + 16); // update src ptr

                    self.emit_load(14, 13, LOOP_STATE_BASE);
                    self.emit_op(Opcode::Addi, 14, 14, 1);
                    self.emit_store(14, 13, LOOP_STATE_BASE);
                    self.emit_jump_placeholder(Opcode::Jmp, 0, 0, loop_label);

                    self.mark_label(done_label);
                    // Restore src_reg to final position
                    self.emit_load(src_reg, 13, LOOP_STATE_BASE + 16);
                }
                None => {
                    // Vec of variable-size elements: loop deserialize each into Vec data slots.
                    // Each data slot holds a pointer (8 bytes) to the deserialized object.
                    self.emit_store(14, 13, LOOP_STATE_BASE + 8); // spill count
                    self.emit_store(src_reg, 13, LOOP_STATE_BASE + 16); // spill src_reg
                                                                        // r13+224 = dst_data_ptr (where to write element pointers in Vec data)
                    self.emit_op(Opcode::Add, 14, 12, 0); // r14 = data start = r12
                    self.emit_store(14, 13, LOOP_STATE_BASE + 24);
                    // Reserve space for pointer array: count * 8 bytes
                    self.emit_load(14, 13, LOOP_STATE_BASE + 8); // r14 = count
                    self.emit_op(Opcode::Addi, 15, 0, 3);
                    self.emit_op(Opcode::Shl, 14, 14, 15); // r14 = count * 8
                    self.emit_op(Opcode::Add, 12, 12, 14); // r12 past pointer array

                    self.emit_op(Opcode::Addi, 14, 0, 0); // i = 0
                    self.emit_store(14, 13, LOOP_STATE_BASE);

                    let loop_label = self.alloc_label();
                    let done_label = self.alloc_label();
                    self.mark_label(loop_label);

                    self.emit_load(14, 13, LOOP_STATE_BASE); // r14 = i
                    self.emit_load(15, 13, LOOP_STATE_BASE + 8); // r15 = count
                    self.emit_jump_placeholder(Opcode::Beq, 14, 15, done_label);

                    // Deserialize element from src into heap at r12
                    // The deserialized object's base pointer will be r12 (before deserialize advances it)
                    self.emit_op(Opcode::Push, 12, 0, 0); // save elem_ptr = r12
                    self.emit_load(src_reg, 13, LOOP_STATE_BASE + 16); // restore src_reg
                    let elem_ty_clone = (**elem_ty).clone();
                    // Use r14 as temp dst for deserialize (we just need r12 to be the base)
                    self.emit_deserialize(&elem_ty_clone, src_reg, 14);
                    self.emit_store(src_reg, 13, LOOP_STATE_BASE + 16); // save updated src_reg

                    // Store element pointer into Vec data array
                    self.emit_op(Opcode::Pop, 15, 0, 0); // r15 = elem_ptr
                    self.emit_load(14, 13, LOOP_STATE_BASE + 24); // r14 = dst_data_ptr
                    self.emit_store(15, 14, 0); // *dst_data_ptr = elem_ptr
                    self.emit_op(Opcode::Addi, 14, 14, 8);
                    self.emit_store(14, 13, LOOP_STATE_BASE + 24); // advance dst_data_ptr

                    // i++
                    self.emit_load(14, 13, LOOP_STATE_BASE);
                    self.emit_op(Opcode::Addi, 14, 14, 1);
                    self.emit_store(14, 13, LOOP_STATE_BASE);
                    self.emit_jump_placeholder(Opcode::Jmp, 0, 0, loop_label);

                    self.mark_label(done_label);
                    self.emit_load(src_reg, 13, LOOP_STATE_BASE + 16); // restore final src_reg
                }
                Some(_) => {
                    // 16-byte elements: bulk Memcpy count*16
                    self.emit_op(Opcode::Addi, 15, 0, 4); // shift = 4
                    self.emit_op(Opcode::Shl, 14, 14, 15); // r14 = count * 16
                    self.emit_op(Opcode::Memcpy, 12, src_reg, 14);
                    self.emit_op(Opcode::Add, src_reg, src_reg, 14);
                    self.emit_op(Opcode::Add, 12, 12, 14);
                }
            }
            // Restore dst_reg from stack if it was saved (scratch register conflict)
            if dst_saved {
                self.emit_op(Opcode::Pop, dst_reg, 0, 0);
            }
        } else if let Ty::Struct(name) = ty {
            if let Some(fields) = self.struct_defs.get(name).cloned() {
                let has_nested = fields
                    .iter()
                    .any(|(_, fty)| matches!(fty, Ty::Struct(_)) || is_blob_type(fty));
                if has_nested {
                    // Recursive: allocate struct on heap, deserialize each field
                    self.emit_op(Opcode::Push, 12, 0, 0); // push struct base = r12
                    let field_count = fields.len() as u32;
                    let struct_size = field_count * memory::WORD_SIZE;
                    self.emit_op(Opcode::Addi, 12, 12, struct_size); // reserve struct space

                    for (i, (_, fty)) in fields.iter().enumerate() {
                        let offset = (i as u32) * memory::WORD_SIZE;
                        // Deserialize field from src into temp register, then store to struct
                        if is_wide_type(&fty) {
                            self.emit_deserialize(&fty, src_reg, 14); // wide → but we use 14 as GP temp
                                                                      // For wide fields in struct, store the wide value at struct+offset
                                                                      // Actually wide fields need 32 bytes but struct layout uses 8 per field (pointer)
                                                                      // This is a limitation — skip for now
                            self.emit_op(Opcode::Pop, 15, 0, 0); // peek struct base
                            self.emit_op(Opcode::Push, 15, 0, 0);
                            self.emit_store(14, 15, offset as i32);
                        } else {
                            self.emit_deserialize(&fty, src_reg, 14);
                            // Store field value/pointer at struct[offset]
                            self.emit_op(Opcode::Pop, 15, 0, 0); // peek struct base
                            self.emit_op(Opcode::Push, 15, 0, 0);
                            self.emit_store(14, 15, offset as i32);
                        }
                    }
                    self.emit_op(Opcode::Pop, dst_reg, 0, 0); // dst = struct base
                } else {
                    // Flat: all GP fields, bulk Memcpy
                    let byte_size = (fields.len() as u32) * memory::WORD_SIZE;
                    self.emit_op(Opcode::Push, 12, 0, 0);
                    self.load_u32_to_reg(14, byte_size);
                    self.emit_op(Opcode::Memcpy, 12, src_reg, 14);
                    self.emit_op(Opcode::Add, src_reg, src_reg, 14);
                    self.emit_op(Opcode::Add, 12, 12, 14);
                    self.emit_op(Opcode::Pop, dst_reg, 0, 0);
                }
            }
        } else {
            // GP types: 8 bytes via Load
            self.emit_load(dst_reg, src_reg, 0);
            self.emit_op(Opcode::Addi, src_reg, src_reg, 8);
        }
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Check if a type uses wide (256-bit) register.
fn is_wide_type(ty: &Ty) -> bool {
    matches!(ty, Ty::U256 | Ty::I256 | Ty::Address | Ty::Contract(_) | Ty::Interface(_))
}

/// Return the PVM MemWidth for a GP type (used by emit_load_typed / emit_store_typed).
fn mem_width_for_type(ty: &Ty) -> MemWidth {
    match ty {
        Ty::U8 | Ty::I8 | Ty::Bool | Ty::Enum(_) => MemWidth::W8,
        Ty::U16 | Ty::I16 => MemWidth::W16,
        Ty::U32 | Ty::I32 => MemWidth::W32,
        _ => MemWidth::W64, // u64, u128 (low half), pointers, etc.
    }
}

/// Whether a type is variable-length (stored via Sload/Sstore mode 1: memory blob).
fn is_blob_type(ty: &Ty) -> bool {
    matches!(ty, Ty::StringTy | Ty::Bytes | Ty::Vec(_) | Ty::Struct(_))
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

/// Return the fixed serialized element size for a type, or None for variable-length types.
/// Used by Borsh-style serialization to decide between memcpy (fixed) and loop (variable).
fn serialized_elem_size(ty: &Ty) -> Option<u32> {
    match ty {
        Ty::U8
        | Ty::U16
        | Ty::U32
        | Ty::U64
        | Ty::I8
        | Ty::I16
        | Ty::I32
        | Ty::I64
        | Ty::Bool
        | Ty::Enum(_) => Some(8),
        Ty::U128 | Ty::I128 => Some(16),
        Ty::U256 | Ty::I256 | Ty::Address => Some(32),
        // Variable-size types: need recursive serialization
        Ty::StringTy | Ty::Bytes | Ty::Vec(_) | Ty::Struct(_) => None,
        _ => Some(8),
    }
}

// ============================================================================
// Flat inline format helpers
// ============================================================================

/// Return the fixed flat-inline size for a type, or None for variable-length types.
/// Used by emit_flatten/emit_unflatten to decide between bulk Memcpy (fixed) and
/// per-element loop (variable). Unlike `serialized_elem_size`, this correctly
/// returns `Some(N*8)` for all-fixed-field structs (enabling bulk copy for Vec<Struct>).
fn flat_elem_size(ty: &Ty, struct_defs: &HashMap<String, Vec<(String, Ty)>>) -> Option<u32> {
    match ty {
        Ty::U8
        | Ty::U16
        | Ty::U32
        | Ty::U64
        | Ty::I8
        | Ty::I16
        | Ty::I32
        | Ty::I64
        | Ty::Bool
        | Ty::Enum(_) => Some(8),
        Ty::U128 | Ty::I128 => Some(16),
        Ty::U256 | Ty::I256 | Ty::Address => Some(32),
        Ty::StringTy | Ty::Bytes | Ty::Vec(_) => None, // variable due to inline data
        // Struct is always None for Vec element sizing: Vec<Struct> must use per-element
        // unflatten loop (allocates each struct on heap, stores pointer in Vec data slot).
        // Bulk Memcpy would copy raw flat bytes into pointer slots — wrong.
        Ty::Struct(_) => None,
        _ => Some(8),
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
    use crate::lower;
    use crate::optimize;
    use crate::parser::Parser;

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
                Ok(None) => {
                    steps += 1;
                    if steps > 1000 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        vm
    }

    fn run_pvm_with_context(
        bytecode: &[u8],
        ctx: pyde_vm::vm::ExecutionContext,
    ) -> pyde_vm::vm::Vm {
        let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000, ctx);
        vm.load(bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 1000 {
                        break;
                    }
                }
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
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 { return 42; }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 42);
    }

    #[test]
    fn pvm_arithmetic() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let a = 10;
                    let b = 20;
                    return a + b;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 30);
    }

    #[test]
    fn pvm_subtraction() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let a = 100;
                    let b = 37;
                    return a - b;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 63);
    }

    #[test]
    fn pvm_multiplication() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    return 7 * 6;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 42);
    }

    #[test]
    fn pvm_division() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    return 100 / 3;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 33);
    }

    #[test]
    fn pvm_modulo() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    return 100 % 7;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 2);
    }

    #[test]
    fn pvm_comparison_gt() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    if 10 > 5 { return 1; }
                    return 0;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1);
    }

    #[test]
    fn pvm_comparison_lt() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    if 3 < 7 { return 1; }
                    return 0;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1);
    }

    #[test]
    fn pvm_comparison_eq() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    if 42 == 42 { return 1; }
                    return 0;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1);
    }

    #[test]
    fn pvm_comparison_neq() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    if 42 != 43 { return 1; }
                    return 0;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1);
    }

    #[test]
    fn pvm_multiple_branches() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let x = 15;
                    if x > 20 { return 1; }
                    if x > 10 { return 2; }
                    return 3;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 2);
    }

    #[test]
    fn pvm_nested_arithmetic() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let a = 100;
                    let b = 30;
                    let c = a - b;
                    let d = c * 2;
                    return d;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 140);
    }

    // ========================================================================
    // Loops (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_for_loop() {
        let compiled = compile_no_opt(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let mut x = 0;
                    for i in 0..3 {
                        x = x + 1;
                    }
                    return x;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 3);
    }

    #[test]
    fn pvm_while_loop() {
        let compiled = compile_no_opt(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let mut x = 1;
                    while x < 100 {
                        x = x * 2;
                    }
                    return x;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 128);
    }

    #[test]
    fn pvm_mutable_var() {
        let compiled = compile_no_opt(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let mut x = 10;
                    x = x + 5;
                    x = x * 2;
                    return x;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 30);
    }

    // ========================================================================
    // Unary operations (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_logical_not() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let x = !true;
                    if x { return 1; }
                    return 0;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 0);
    }

    #[test]
    fn pvm_bitwise_ops() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let a: u64 = 0xFF;
                    let b: u64 = 0x0F;
                    return a & b;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 0x0F);
    }

    // ========================================================================
    // Revert (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_revert() {
        let compiled = compile(
            r#"
            contract T {
                error Fail {}
                pub fn f() -> u64 {
                    revert!(Fail {});
                }
            }
        "#,
        );
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000);
        vm.load(&compiled.bytecode).unwrap();
        let mut result = None;
        loop {
            match vm.step() {
                Ok(Some(r)) => {
                    result = Some(r);
                    break;
                }
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
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 { return gas_remaining(); }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert!(vm.cpu.read_gp(1) > 0);
    }

    // ========================================================================
    // Storage operations (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_storage_write_read() {
        let compiled = compile_no_opt(
            r#"
            contract T {
                storage { value: u64, }
                pub fn f() -> u64 {
                    self.value = 42;
                    return self.value;
                }
            }
        "#,
        );
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: [1u8; 32],
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        assert_eq!(vm.cpu.read_gp(1), 42, "storage write+read should return 42");
    }

    #[test]
    fn pvm_storage_multiple_fields() {
        let compiled = compile_no_opt(
            r#"
            contract T {
                storage { a: u64, b: u64, }
                pub fn f() -> u64 {
                    self.a = 10;
                    self.b = 20;
                    return self.a + self.b;
                }
            }
        "#,
        );
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
        let compiled = compile(
            r#"
            contract T {
                struct Point { x: u64, y: u64, }
                pub fn f() -> u64 {
                    let p = Point { x: 10, y: 20 };
                    return p.x;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 10, "p.x should be 10");
    }

    #[test]
    fn pvm_struct_second_field() {
        let compiled = compile(
            r#"
            contract T {
                struct Point { x: u64, y: u64, }
                pub fn f() -> u64 {
                    let p = Point { x: 10, y: 20 };
                    return p.y;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 20, "p.y should be 20");
    }

    // ========================================================================
    // Tuple operations (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_tuple_destructuring() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let (a, b, c) = (10, 20, 30);
                    return b;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 20, "second tuple element should be 20");
    }

    #[test]
    fn pvm_tuple_dot_access() {
        // Test tuple .0/.1/.2 field access syntax
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let t = (10, 20, 30);
                    return t.1;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 20, "t.1 should be 20");
    }

    // ========================================================================
    // Array operations (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_array_index() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let arr = [10, 20, 30];
                    return arr[2];
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 30, "arr[2] should be 30");
    }

    // ========================================================================
    // Large constants (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_large_constant_18bit() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    return 262143;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 262143, "max 18-bit value");
    }

    #[test]
    fn pvm_large_constant_32bit() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    return 1000000;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1000000, "1 million");
    }

    #[test]
    fn pvm_large_constant_max_u64() {
        // Test with a value that requires all 4 chunks
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    return 1152921504606846975;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1152921504606846975u64);
    }

    // ========================================================================
    // Cast operations (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_cast_gp_copy() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let a: u64 = 42;
                    let b = a as u64;
                    return b;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 42);
    }

    // ========================================================================
    // Block context builtins (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_block_timestamp() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    return block.timestamp;
                }
            }
        "#,
        );
        let ctx = pyde_vm::vm::ExecutionContext {
            timestamp: 1234567890,
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        assert_eq!(vm.cpu.read_gp(1), 1234567890);
    }

    #[test]
    fn pvm_block_height() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    return block.height;
                }
            }
        "#,
        );
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
        let compiled = compile(
            r#"
            contract T {
                #[constructor]
                pub fn init() {}
                pub fn transfer() {}
                pub fn balance_of() -> u64 { return 0; }
                fn internal_helper() {}
            }
        "#,
        );
        assert_eq!(compiled.selectors.len(), 2);
        let names: Vec<&str> = compiled.selectors.iter().map(|s| s.1.as_str()).collect();
        assert!(names.contains(&"transfer"));
        assert!(names.contains(&"balance_of"));
    }

    #[test]
    fn codegen_produces_valid_bytecode() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 { return 42; }
            }
        "#,
        );
        assert_eq!(compiled.bytecode.len(), compiled.instruction_count * 4);
        assert!(compiled.bytecode.len() > 0);
    }

    #[test]
    fn codegen_minimal_contract() {
        let compiled = compile(
            r#"
            contract Token {
                storage { supply: u256, }
                #[constructor]
                pub fn init() { self.supply = 1000; }
                #[view]
                pub fn get_supply() -> u256 { return self.supply; }
            }
        "#,
        );
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
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let a: u64 = 0x0F;
                    let b: u64 = 0xF0;
                    let c = a | b;
                    if c == 255 { return 1; }
                    return 0;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1, "0x0F | 0xF0 = 0xFF = 255");
    }

    #[test]
    fn pvm_shift_left() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let a: u64 = 1;
                    let b: u64 = 10;
                    return a << b;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1024, "1 << 10 = 1024");
    }

    #[test]
    fn pvm_shift_right() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let a: u64 = 1024;
                    let b: u64 = 3;
                    return a >> b;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 128, "1024 >> 3 = 128");
    }

    #[test]
    fn pvm_index_set() {
        let compiled = compile_no_opt(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let mut arr = [10, 20, 30];
                    arr[1] = 99;
                    return arr[1];
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 99, "arr[1] after set should be 99");
    }

    #[test]
    fn pvm_internal_function_call() {
        let compiled = compile_no_opt(
            r#"
            contract T {
                fn add(a: u64, b: u64) -> u64 {
                    return a + b;
                }
                pub fn f() -> u64 {
                    return add(10, 32);
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 42, "add(10, 32) should be 42");
    }

    #[test]
    fn pvm_storage_accumulate() {
        // Write, read, modify, write back, read again
        let compiled = compile_no_opt(
            r#"
            contract T {
                storage { counter: u64, }
                pub fn f() -> u64 {
                    self.counter = 10;
                    let x = self.counter;
                    self.counter = x + 5;
                    return self.counter;
                }
            }
        "#,
        );
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: [3u8; 32],
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        assert_eq!(vm.cpu.read_gp(1), 15, "counter should be 10+5=15");
    }

    #[test]
    fn pvm_struct_three_fields() {
        let compiled = compile(
            r#"
            contract T {
                struct Color { r: u64, g: u64, b: u64, }
                pub fn f() -> u64 {
                    let c = Color { r: 255, g: 128, b: 64 };
                    return c.r + c.g + c.b;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 447, "255 + 128 + 64 = 447");
    }

    #[test]
    fn pvm_array_sum_loop() {
        let compiled = compile_no_opt(
            r#"
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
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 100, "10+20+30+40=100");
    }

    #[test]
    fn pvm_nested_if_else() {
        let compiled = compile_no_opt(
            r#"
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
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 2, "50 > 25 but not > 100 → 2");
    }

    #[test]
    fn pvm_for_loop_sum() {
        let compiled = compile_no_opt(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let mut sum = 0;
                    for i in 0..10 {
                        sum = sum + i;
                    }
                    return sum;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 45, "0+1+2+...+9 = 45");
    }

    #[test]
    fn pvm_comparison_lteq() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    if 5 <= 5 { return 1; }
                    return 0;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1, "5 <= 5 should be true");
    }

    #[test]
    fn pvm_comparison_gteq() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    if 10 >= 5 { return 1; }
                    return 0;
                }
            }
        "#,
        );
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
        let compiled = compile_no_opt(
            r#"
            contract T {
                storage { owner: u64, }
                pub fn f() -> u64 {
                    let s = msg.sender;
                    return 1;
                }
            }
        "#,
        );
        let ctx = pyde_vm::vm::ExecutionContext {
            caller: [0xAB; 32],
            self_address: [1u8; 32],
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        // If Callvalue wrote to wrong register file, this would trap.
        // Returning 1 proves msg.sender didn't corrupt execution.
        assert_eq!(
            vm.cpu.read_gp(1),
            1,
            "msg.sender should not corrupt execution"
        );
        // Also verify the wide register actually got the caller value
        let w = vm.cpu.read_wide(0); // first wide alloc = w0
        assert_ne!(
            w,
            pyde_vm::wide::U256::ZERO,
            "msg.sender should be non-zero"
        );
    }

    #[test]
    fn pvm_msg_value() {
        // msg.value is u256 (wide). Test with #[payable] function that reads it.
        let (tokens, _) = Lexer::new(
            r#"
            contract T {
                #[payable]
                pub fn f() -> u64 {
                    let v = msg.value;
                    return 1;
                }
            }
        "#,
        )
        .tokenize();
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
        let compiled = compile_no_opt(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let a = address(self);
                    return 1;
                }
            }
        "#,
        );
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
        let (tokens, _) = Lexer::new(
            r#"
            contract T {
                pub fn f() -> u64 {
                    return 42;
                }
            }
        "#,
        )
        .tokenize();
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
                Ok(Some(r)) => {
                    result = Some(r);
                    break;
                }
                Ok(None) => {
                    steps += 1;
                    if steps > 500 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        assert!(
            matches!(result, Some(pyde_vm::vm::ExecResult::Revert)),
            "non-payable function should revert when call_value > 0, got {:?}",
            result
        );
    }

    // ========================================================================
    // Storage maps (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_storage_map_write_read() {
        let compiled = compile_no_opt(
            r#"
            contract T {
                storage { balances: Map<u64, u64>, }
                pub fn f() -> u64 {
                    self.balances[42] = 100;
                    return self.balances[42];
                }
            }
        "#,
        );
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
        let (tokens, _) = Lexer::new(
            r#"
            contract T {
                storage { value: u64, }
                pub fn f() -> u64 {
                    self.value = 42;
                    return self.value;
                }
            }
        "#,
        )
        .tokenize();
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
                Ok(Some(r)) => {
                    result = Some(r);
                    break;
                }
                Ok(None) => {
                    steps += 1;
                    if steps > 1000 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        // Should complete normally (Halt), not revert
        assert!(
            matches!(result, Some(pyde_vm::vm::ExecResult::Halt)),
            "single call should succeed with reentrancy guard, got {:?}",
            result
        );
        assert_eq!(vm.cpu.read_gp(1), 42, "should return 42");
    }

    #[test]
    fn pvm_reentrant_annotation_allows_reentry() {
        // Task 0204: #[reentrant] function allows re-entry while normal pub fn blocks it.
        //
        // Contract T has:
        //   pub fn guarded() — default reentrancy guard (should revert on re-entry)
        //   #[reentrant] pub fn reentrant_ok() — no guard (should allow re-entry)
        //
        // Test: deploy T, register as its own callee, then simulate re-entry by
        // having the reentrancy slot already locked (=1) before calling. A #[reentrant]
        // function should succeed; a guarded function should revert.

        let src = r#"
            contract T {
                storage { value: u64, }
                pub fn guarded() -> u64 {
                    self.value = 1;
                    return self.value;
                }
                #[reentrant]
                pub fn reentrant_ok() -> u64 {
                    self.value = 2;
                    return self.value;
                }
            }
        "#;

        let (tokens, _) = Lexer::new(src).tokenize();
        let (file, _) = Parser::new(tokens).parse();
        let ir = lower::lower(&file);
        let mut codegen = CodeGen::new();
        codegen.emit_guards = true;
        let compiled = codegen.generate(&ir);

        let self_addr = [7u8; 32];
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: self_addr,
            ..Default::default()
        };

        // Derive the reentrancy lock storage key using the VM's own method.
        // REENTRANCY_SLOT is the raw 18-bit encoding of -2. The PVM sign-extends
        // it to 0xFFFFFFFFFFFFFFFE (u64), then Widen gives U256 of that value.
        let lock_slot = ethnum::U256::from((-2i64) as u64);
        let derived_key = {
            let tmp_vm = pyde_vm::vm::Vm::with_gas_limit_and_context(0, ctx.clone());
            tmp_vm.derive_storage_key(lock_slot)
        };

        // --- Test 1: reentrant_ok() succeeds even when lock is already set ---
        {
            let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(200_000, ctx.clone());
            let selector = compute_selector("reentrant_ok");
            vm.calldata = selector.to_be_bytes().to_vec();
            vm.load(&compiled.runtime_bytecode).unwrap();

            // Pre-set the reentrancy lock to simulate re-entry
            vm.storage.insert(derived_key, vec![1, 0, 0, 0, 0, 0, 0, 0]);

            let output = vm.execute();
            assert_eq!(
                output.outcome,
                pyde_vm::vm::Outcome::Success,
                "#[reentrant] function should succeed even with lock set"
            );
            assert_eq!(vm.cpu.read_gp(1), 2, "should return 2");
        }

        // --- Test 2: guarded() reverts when lock is already set ---
        {
            let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(200_000, ctx.clone());
            let selector = compute_selector("guarded");
            vm.calldata = selector.to_be_bytes().to_vec();
            vm.load(&compiled.runtime_bytecode).unwrap();

            // Pre-set the reentrancy lock to simulate re-entry
            vm.storage.insert(derived_key, vec![1, 0, 0, 0, 0, 0, 0, 0]);

            let output = vm.execute();
            assert_eq!(
                output.outcome,
                pyde_vm::vm::Outcome::Revert,
                "guarded function should revert when lock is already set (re-entry blocked)"
            );
        }

        // --- Test 3: guarded() succeeds when lock is NOT set (normal call) ---
        {
            let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(200_000, ctx.clone());
            let selector = compute_selector("guarded");
            vm.calldata = selector.to_be_bytes().to_vec();
            vm.load(&compiled.runtime_bytecode).unwrap();

            let output = vm.execute();
            assert_eq!(
                output.outcome,
                pyde_vm::vm::Outcome::Success,
                "guarded function should succeed on normal (non-reentrant) call"
            );
            assert_eq!(vm.cpu.read_gp(1), 1, "should return 1");
        }
    }

    // ========================================================================
    // Dispatch with calldata (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_dispatch_with_calldata() {
        // Test the full dispatch path: selector matching + calldata decode
        let compiled = compile(
            r#"
            contract T {
                pub fn add(a: u64, b: u64) -> u64 {
                    return a + b;
                }
            }
        "#,
        );
        // Build calldata: [selector(4 bytes)] [arg0(8 bytes)] [arg1(8 bytes)]
        let selector = compute_selector("add");
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&selector.to_be_bytes()); // 4 bytes selector (BE, like Ethereum)
        calldata.extend_from_slice(&10u64.to_le_bytes()); // arg0 = 10
        calldata.extend_from_slice(&32u64.to_le_bytes()); // arg1 = 32

        let mut codegen = CodeGen::new();
        codegen.emit_guards = true; // production mode with dispatch
        let (tokens, _) = Lexer::new(
            r#"
            contract T {
                pub fn add(a: u64, b: u64) -> u64 {
                    return a + b;
                }
            }
        "#,
        )
        .tokenize();
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
                Ok(None) => {
                    steps += 1;
                    if steps > 500 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        assert_eq!(
            vm.cpu.read_gp(1),
            42,
            "add(10, 32) via dispatch should be 42"
        );
    }

    #[test]
    fn pvm_storage_increment_persists() {
        // Verify that increment() actually writes to vm.storage
        let (tokens, _) = Lexer::new(
            r#"
            contract Counter {
                storage { count: u64 }
                pub fn increment() { self.count = self.count + 1; }
                pub fn get_count() -> u64 { return self.count; }
            }
        "#,
        )
        .tokenize();
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

        assert_eq!(
            output.outcome,
            pyde_vm::vm::Outcome::Success,
            "increment should succeed"
        );
        assert!(
            vm.storage.len() > 0,
            "vm.storage should have entries after Sstore"
        );
    }

    // ========================================================================
    // Wide storage u256 (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_wide_storage_u256() {
        // u256 storage field uses Sload/Sstore mode 0 (wide register)
        let compiled = compile_no_opt(
            r#"
            contract T {
                storage { total: u256, }
                pub fn f() -> u64 {
                    self.total = 999;
                    return 1;
                }
            }
        "#,
        );
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
        let compiled = compile_no_opt(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let h = hash(42);
                    return 1;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1, "hash() should not trap");
    }

    // ========================================================================
    // Event emission (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_event_emit_no_fields() {
        // emit uses keyword syntax: `emit EventName { fields };` (NOT emit!())
        let compiled = compile_no_opt(
            r#"
            contract T {
                event Ping {}
                pub fn f() -> u64 {
                    emit Ping {};
                    return 1;
                }
            }
        "#,
        );
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: [8u8; 32],
            ..Default::default()
        };
        let vm = run_pvm_with_context(&compiled.bytecode, ctx);
        assert_eq!(vm.cpu.read_gp(1), 1, "emit should not trap");
    }

    #[test]
    fn pvm_event_emit_with_fields() {
        let compiled = compile_no_opt(
            r#"
            contract T {
                event Transfer { from: u64, to: u64, amount: u64, }
                pub fn f() -> u64 {
                    emit Transfer { from: 1, to: 2, amount: 100 };
                    return 1;
                }
            }
        "#,
        );
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
        let compiled = compile_no_opt(
            r#"
            contract T {
                storage { big: u256, }
                pub fn f() -> u64 {
                    self.big = 340282366920938463463374607431768211455_u256;
                    return 1;
                }
            }
        "#,
        );
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
        let compiled = compile(
            r#"
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
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 36, "1+2+3+4+5+6+7+8=36");
    }

    #[test]
    fn pvm_array_repeat() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let arr = [0; 5];
                    return arr[3];
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(
            vm.cpu.read_gp(1),
            0,
            "repeated array should have 0 at index 3"
        );
    }

    #[test]
    fn pvm_bitwise_not() {
        let compiled = compile(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let a: u64 = 0;
                    let b = ~a;
                    if b > 100 { return 1; }
                    return 0;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        // ~0 = u64::MAX (all bits set, > 100)
        assert_eq!(vm.cpu.read_gp(1), 1, "bitwise NOT of 0 should be max");
    }

    // ========================================================================
    // Vec operations (PVM-verified)
    // ========================================================================

    #[test]
    fn pvm_vec_push_and_len() {
        let compiled = compile_no_opt(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let mut v = Vec::new();
                    v.push(10);
                    return v.len();
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 1, "Vec should have 1 element after push");
    }

    #[test]
    fn pvm_vec_push_and_pop() {
        let compiled = compile_no_opt(
            r#"
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
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 30, "pop should return last pushed (30)");
    }

    #[test]
    fn pvm_vec_is_empty() {
        // Simplest Vec test: create and return length
        let compiled = compile_no_opt(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let v = Vec::new();
                    return v.len();
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 0, "new Vec length should be 0");
    }

    #[test]
    fn pvm_vec_push_pop_sequence() {
        let compiled = compile_no_opt(
            r#"
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
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 2, "push push pop push → len 2");
    }

    #[test]
    fn pvm_cast_widen_narrow() {
        let compiled = compile_no_opt(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let a: u64 = 42;
                    let b = a as u256;
                    let c = b as u64;
                    return c;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(
            vm.cpu.read_gp(1),
            42,
            "u64 → u256 → u64 round-trip should be 42"
        );
    }

    #[test]
    fn pvm_unary_neg() {
        // -10 as u64 wraps to u64::MAX - 9
        let compiled = compile_no_opt(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let a: u64 = 10;
                    let b = -a;
                    return b;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        let expected = 0u64.wrapping_sub(10); // u64::MAX - 9
        assert_eq!(
            vm.cpu.read_gp(1),
            expected,
            "negation of 10 should wrap to {}",
            expected
        );
    }

    #[test]
    fn pvm_register_spill_restore() {
        // This function uses >11 virtual registers, forcing spill/restore.
        // Without optimizer, each variable + temporary gets its own register.
        let compiled = compile_no_opt(
            r#"
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
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        // l = 1+2 = 3, m = 3+4 = 7, result = 3 + 7 + 5 + 6 = 21
        assert_eq!(
            vm.cpu.read_gp(1),
            21,
            "spilled register values should be correct"
        );
    }

    #[test]
    fn pvm_vec_push_loop() {
        // Push 10 elements in a loop (within initial capacity)
        let compiled = compile_no_opt(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let mut v = Vec::new();
                    for i in 0..10 {
                        v.push(i);
                    }
                    return v.len();
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 10, "Vec should have 10 elements");
    }

    #[test]
    fn pvm_vec_realloc() {
        // Push 100 elements — exceeds initial capacity of 64, triggers Memcpy realloc
        let compiled = compile_no_opt(
            r#"
            contract T {
                pub fn f() -> u64 {
                    let mut v = Vec::new();
                    for i in 0..100 {
                        v.push(i);
                    }
                    return v.len();
                }
            }
        "#,
        );
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(1_000_000);
        vm.load(&compiled.bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 50_000 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        assert_eq!(
            vm.cpu.read_gp(1),
            100,
            "Vec should have 100 elements after realloc"
        );
    }

    #[test]
    fn pvm_map_set_under_register_pressure() {
        // This test creates enough local variables to exhaust GP registers (r1-r11),
        // forcing the register allocator to spill. Then does map set/get to verify
        // spilled key/val registers are correctly handled in storage operations.
        let compiled = compile_no_opt(
            r#"
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
        "#,
        );
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(1_000_000);
        vm.load(&compiled.bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 10_000 {
                        break;
                    }
                }
                Err(e) => {
                    panic!("PVM error: {:?}", e);
                }
            }
        }
        // data[1]=2, data[3]=4, data[5]=6 → r1+r2+r3 = 2+4+6 = 12
        assert_eq!(
            vm.cpu.read_gp(1),
            12,
            "Map operations under register pressure must preserve correct key/val"
        );
    }

    #[test]
    fn pvm_map_set_bool_under_pressure() {
        // Regression test: map set of false (0) must not be confused with
        // a clobbered register that happens to be 0.
        let compiled = compile_no_opt(
            r#"
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
        "#,
        );
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(1_000_000);
        vm.load(&compiled.bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 10_000 {
                        break;
                    }
                }
                Err(e) => {
                    panic!("PVM error: {:?}", e);
                }
            }
        }
        assert_eq!(
            vm.cpu.read_gp(1),
            99,
            "Bool map set(false) must work under register pressure"
        );
    }

    #[test]
    fn pvm_marketplace_buy_pattern() {
        // Regression test for the Marketplace buy_item pattern:
        // Multiple map reads/writes in a single function under heavy register pressure.
        // This is the exact pattern that was broken: read multiple map fields for an item,
        // compute fees, update balances, flip active flag.
        let compiled = compile_no_opt(
            r#"
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
        "#,
        );
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
        vm.load(&compiled.bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 100_000 {
                        break;
                    }
                }
                Err(e) => {
                    panic!("PVM error: {:?}", e);
                }
            }
        }
        assert_eq!(
            vm.cpu.read_gp(1),
            5050,
            "Marketplace buy pattern: active flipped, balances correct, fees computed"
        );
    }

    #[test]
    fn pvm_batch_reward_register_pressure() {
        // Reproduces the batch_reward pattern from the E2E StressTest:
        // 4 params, 3 map reads, fee math, 4 map writes — extreme register pressure.
        // This was producing off-by-16 for the second user's balance.
        let compiled = compile_no_opt(
            r#"
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
        "#,
        );
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
        vm.load(&compiled.bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 100_000 {
                        break;
                    }
                }
                Err(e) => {
                    panic!("PVM error: {:?}", e);
                }
            }
        }
        // b10=38000+2700=40700, b20=39000+2700=41700, b30=21800+2700=24500, b1=1200+900=2100
        // total = 40700+41700+24500+2100 = 109000
        assert_eq!(
            vm.cpu.read_gp(1),
            109000,
            "batch reward: all balances must be exact"
        );
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
        assert_eq!(
            output.outcome,
            pyde_vm::vm::Outcome::Success,
            "setup must succeed"
        );

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
        assert_eq!(
            output2.outcome,
            pyde_vm::vm::Outcome::Success,
            "batch_reward must succeed"
        );

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
        assert_eq!(
            output3.outcome,
            pyde_vm::vm::Outcome::Success,
            "get_balance must succeed"
        );
        assert_eq!(
            vm3.cpu.read_gp(1),
            41700,
            "user20 balance = 39000 + 2700 = 41700"
        );

        // Check user10 balance
        let mut calldata10 = get_sel.to_be_bytes().to_vec();
        calldata10.extend_from_slice(&10u64.to_le_bytes());

        let mut vm4 = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
        vm4.storage = vm2.storage.clone();
        vm4.calldata = calldata10;
        vm4.load(&contract.runtime_bytecode).unwrap();
        let output4 = vm4.execute();
        assert_eq!(output4.outcome, pyde_vm::vm::Outcome::Success);
        assert_eq!(
            vm4.cpu.read_gp(1),
            40700,
            "user10 balance = 38000 + 2700 = 40700"
        );
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
        assert_eq!(
            output.outcome,
            pyde_vm::vm::Outcome::Success,
            "batch_reward must succeed"
        );
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

    #[test]
    fn pvm_vec_vec_storage() {
        // Vec<Vec<u64>> serialize + store: 2 inner Vecs with 3 elements each
        let compiled = compile_no_opt(
            r#"
            contract T {
                storage {
                    data: Map<u64, Vec<Vec<u64>>>,
                    step: u64,
                }
                pub fn store_it() -> u64 {
                    self.step = 1;
                    let mut r1 = Vec::new();
                    r1.push(1);
                    r1.push(2);
                    r1.push(3);
                    self.step = 2;
                    let mut r2 = Vec::new();
                    r2.push(4);
                    r2.push(5);
                    r2.push(6);
                    self.step = 3;
                    let mut m = Vec::new();
                    m.push(r1);
                    m.push(r2);
                    self.step = 4;
                    self.data[1] = m;
                    self.step = 5;
                    return 5;
                }
            }
        "#,
        );
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
        vm.load(&compiled.bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 200_000 {
                        panic!("too many steps at step {}", steps);
                    }
                    // Print last 10 instructions before fault (around step 180-190)
                    if steps >= 150 && steps <= 245 {
                        let pc = vm.pc as usize;
                        if pc + 4 <= compiled.bytecode.len() {
                            let w = u32::from_le_bytes(
                                compiled.bytecode[pc..pc + 4].try_into().unwrap(),
                            );
                            let d = pyde_vm::isa::decode(pyde_vm::isa::Instruction(w));
                            eprintln!(
                                "  step={} PC={} {:?} rd={} rs1={} imm={:#x} | r14={:#x} r15={:#x}",
                                steps,
                                pc,
                                d.opcode,
                                d.rd,
                                d.rs1,
                                d.rs2_or_imm,
                                vm.cpu.read_gp(14),
                                vm.cpu.read_gp(15)
                            );
                        }
                    }
                }
                Err(e) => {
                    // Decode the faulting instruction
                    let pc = vm.pc as usize;
                    let instr_word = if pc + 4 <= compiled.bytecode.len() {
                        u32::from_le_bytes(compiled.bytecode[pc..pc + 4].try_into().unwrap())
                    } else {
                        0
                    };
                    let decoded = pyde_vm::isa::decode(pyde_vm::isa::Instruction(instr_word));
                    panic!("PVM trap at step {}, PC={} (instr {}): {:?}\n  opcode={:?} rd={} rs1={} imm={:#x}\n  r1={:#x} r2={:#x} r3={:#x} r4={:#x} r5={:#x}\n  r6={:#x} r7={:#x} r8={:#x} r9={:#x} r10={:#x} r11={:#x}\n  r12={:#x} r13={:#x} r14={:#x} r15={:#x}",
                        steps, pc, pc/4, e,
                        decoded.opcode, decoded.rd, decoded.rs1, decoded.rs2_or_imm,
                        vm.cpu.read_gp(1), vm.cpu.read_gp(2), vm.cpu.read_gp(3),
                        vm.cpu.read_gp(4), vm.cpu.read_gp(5), vm.cpu.read_gp(6),
                        vm.cpu.read_gp(7), vm.cpu.read_gp(8), vm.cpu.read_gp(9),
                        vm.cpu.read_gp(10), vm.cpu.read_gp(11),
                        vm.cpu.read_gp(12), vm.cpu.read_gp(13),
                        vm.cpu.read_gp(14), vm.cpu.read_gp(15));
                }
            }
        }
        assert_eq!(vm.cpu.read_gp(1), 5, "should complete store_it");
    }

    #[test]
    fn pvm_while_loop_over_vec() {
        // While loop iterating over a Vec — tests that IndexGet doesn't
        // clobber the loop counter or length registers.
        let compiled = compile_no_opt(
            r#"
            contract T {
                storage {}
                pub fn sum_vec() -> u64 {
                    let mut v = Vec::new();
                    v.push(10);
                    v.push(20);
                    v.push(30);
                    v.push(40);
                    v.push(50);
                    let mut total = 0;
                    let mut i = 0;
                    let len = v.len();
                    while i < len {
                        total = total + v[i];
                        i = i + 1;
                    }
                    return total;
                }
            }
        "#,
        );
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
        vm.load(&compiled.bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 50_000 {
                        panic!("infinite loop at step {}", steps);
                    }
                }
                Err(e) => {
                    let pc = vm.pc as usize;
                    let instr_word = if pc + 4 <= compiled.bytecode.len() {
                        u32::from_le_bytes(compiled.bytecode[pc..pc + 4].try_into().unwrap())
                    } else {
                        0
                    };
                    let d = pyde_vm::isa::decode(pyde_vm::isa::Instruction(instr_word));
                    panic!("PVM error at step {}, PC={}: {:?}\n  {:?} rd={} rs1={} imm={:#x}\n  r1={:#x} r12={:#x} r13={:#x} r14={:#x} r15={:#x}",
                        steps, pc, e, d.opcode, d.rd, d.rs1, d.rs2_or_imm,
                        vm.cpu.read_gp(1), vm.cpu.read_gp(12), vm.cpu.read_gp(13),
                        vm.cpu.read_gp(14), vm.cpu.read_gp(15));
                }
            }
        }
        assert_eq!(vm.cpu.read_gp(1), 150, "sum = 10+20+30+40+50 = 150");
    }

    #[test]
    fn pvm_while_loop_production_mode() {
        // Same test but WITH guards (production dispatch mode)
        let src = r#"
            contract T {
                storage {
                    data: Map<u64, Vec<u64>>,
                }
                pub fn store_and_sum() -> u64 {
                    let mut v = Vec::new();
                    v.push(10);
                    v.push(20);
                    v.push(30);
                    v.push(40);
                    v.push(50);
                    self.data[1] = v;

                    let loaded = self.data[1];
                    let mut total = 0;
                    let mut i = 0;
                    let len = loaded.len();
                    while i < len {
                        total = total + loaded[i];
                        i = i + 1;
                    }
                    return total;
                }
            }
        "#;
        // Compile WITH guards (production mode)
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let ir = crate::lower::lower(&file);
        let codegen = CodeGen::new(); // emit_guards = true
        let contract = codegen.generate(&ir);

        // Build calldata with selector
        let sel = compute_selector("store_and_sum");
        let calldata = sel.to_be_bytes().to_vec();

        let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000_000);
        vm.calldata = calldata;
        vm.load(&contract.runtime_bytecode).unwrap();
        let mut steps = 0u64;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 500_000 {
                        // Dump register state to diagnose infinite loop
                        panic!("infinite loop at step {}. r1={} r2={} r3={} r4={} r5={} r6={} r7={} r8={} r9={} r10={} r11={}",
                            steps,
                            vm.cpu.read_gp(1), vm.cpu.read_gp(2), vm.cpu.read_gp(3),
                            vm.cpu.read_gp(4), vm.cpu.read_gp(5), vm.cpu.read_gp(6),
                            vm.cpu.read_gp(7), vm.cpu.read_gp(8), vm.cpu.read_gp(9),
                            vm.cpu.read_gp(10), vm.cpu.read_gp(11));
                    }
                }
                Err(e) => {
                    let pc = vm.pc as usize;
                    let w = u32::from_le_bytes(
                        contract.runtime_bytecode[pc..pc + 4]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
                    let d = pyde_vm::isa::decode(pyde_vm::isa::Instruction(w));
                    panic!(
                        "PVM trap at step {}, PC={}: {:?}\n  {:?} rd={} rs1={} imm={:#x}",
                        steps, pc, e, d.opcode, d.rd, d.rs1, d.rs2_or_imm
                    );
                }
            }
        }
        assert_eq!(vm.cpu.read_gp(1), 150, "production mode sum");
    }

    #[test]
    fn pvm_while_loop_deserialized_vec() {
        // Test: store Vec in one execution, load + iterate in another (via SMT).
        // This reproduces the E2E failure where the deserialized Vec causes an infinite loop.
        let src = r#"
            contract T {
                storage { data: Map<u64, Vec<u64>>, }
                pub fn store_vec() {
                    let mut v = Vec::new();
                    v.push(10); v.push(20); v.push(30);
                    self.data[1] = v;
                }
                #[view]
                pub fn sum_vec() -> u64 {
                    let v = self.data[1];
                    let mut t = 0;
                    let mut i = 0;
                    let len = v.len();
                    while i < len { t = t + v[i]; i = i + 1; }
                    return t;
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let ir = crate::lower::lower(&file);
        let codegen = CodeGen::new();
        let contract = codegen.generate(&ir);

        let contract_addr = [0x42u8; 32];

        // Step 1: store_vec
        let store_sel = compute_selector("store_vec");
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: contract_addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = store_sel.to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(
            out1.outcome,
            pyde_vm::vm::Outcome::Success,
            "store_vec must succeed"
        );

        // Persist to SMT
        let mut smt = pyde_state::smt::PydeSMT::new();
        for (key, val) in &vm1.storage {
            let smt_key = sparse_merkle_tree::H256::from(key.to_le_bytes());
            let _ = smt.insert(smt_key, val.clone());
        }

        // Step 2: sum_vec via lazy backend
        let sum_sel = compute_selector("sum_vec");
        let ctx2 = pyde_vm::vm::ExecutionContext {
            self_address: contract_addr,
            ..Default::default()
        };
        let mut vm2 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx2);
        vm2.calldata = sum_sel.to_be_bytes().to_vec();
        let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
        vm2.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let smt_key = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr).get(&smt_key) }
        }));
        vm2.load(&contract.runtime_bytecode).unwrap();

        let mut steps = 0u64;
        loop {
            match vm2.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 500_000 {
                        panic!("infinite loop at step {} in sum_vec. PC={}", steps, vm2.pc);
                    }
                }
                Err(e) => panic!("trap at step {}: {:?}", steps, e),
            }
        }
        assert_eq!(vm2.cpu.read_gp(1), 60, "sum = 10+20+30 = 60");
    }

    #[test]
    fn pvm_while_loop_many_functions() {
        // Reproduce E2E: contract with many functions, compile with optimizer,
        // store Vec then read+sum via SMT in separate execution.
        let src = r#"
            contract T {
                struct Profile { score: u64, level: u64, badges: u64, }
                storage {
                    profiles: Map<u64, Vec<Profile>>,
                    matrix: Map<u64, Vec<Vec<u64>>>,
                    nums: Map<u64, Vec<u64>>,
                    count: u64,
                }
                pub fn store_vec(id: u64) -> u64 {
                    let mut v = Vec::new(); v.push(10); v.push(20); v.push(30); v.push(40); v.push(50);
                    self.nums[id] = v; let c = self.count; self.count = c + 1; return 5;
                }
                pub fn read_vec_len(id: u64) -> u64 { let v = self.nums[id]; return v.len(); }
                pub fn read_vec_elem(id: u64, idx: u64) -> u64 { let v = self.nums[id]; return v[idx]; }
                pub fn read_vec_sum(id: u64) -> u64 {
                    let v = self.nums[id]; let mut t = 0; let mut i = 0; let len = v.len();
                    while i < len { t = t + v[i]; i = i + 1; } return t;
                }
                pub fn store_profiles(id: u64) -> u64 {
                    let mut p = Vec::new();
                    p.push(Profile { score: 100, level: 5, badges: 3 });
                    p.push(Profile { score: 200, level: 10, badges: 7 });
                    self.profiles[id] = p; let c = self.count; self.count = c + 1; return 2;
                }
                pub fn read_profile_score(id: u64, idx: u64) -> u64 { let p = self.profiles[id]; let s = p[idx]; return s.score; }
                pub fn read_profile_level(id: u64, idx: u64) -> u64 { let p = self.profiles[id]; let s = p[idx]; return s.level; }
                pub fn store_matrix(id: u64) -> u64 {
                    let mut r1 = Vec::new(); r1.push(1); r1.push(2); r1.push(3);
                    let mut r2 = Vec::new(); r2.push(4); r2.push(5); r2.push(6);
                    let mut m = Vec::new(); m.push(r1); m.push(r2);
                    self.matrix[id] = m; let c = self.count; self.count = c + 1; return 2;
                }
                pub fn read_matrix(id: u64, row: u64, col: u64) -> u64 { let m = self.matrix[id]; let r = m[row]; return r[col]; }
                #[view] pub fn get_count() -> u64 { return self.count; }
            }
        "#;
        // Compile WITH optimizer (matching CLI)
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let codegen = CodeGen::new();
        let contract = codegen.generate(&ir);

        let contract_addr = [0x42u8; 32];

        // Step 1: store_vec(1)
        let sel = compute_selector("store_vec");
        let mut cd = sel.to_be_bytes().to_vec();
        cd.extend_from_slice(&1u64.to_le_bytes());
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: contract_addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = cd;
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(
            out1.outcome,
            pyde_vm::vm::Outcome::Success,
            "store_vec failed"
        );

        // Persist to SMT
        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        // Step 2: read_vec_sum(1) via lazy backend
        let sel2 = compute_selector("read_vec_sum");
        let mut cd2 = sel2.to_be_bytes().to_vec();
        cd2.extend_from_slice(&1u64.to_le_bytes());
        let ctx2 = pyde_vm::vm::ExecutionContext {
            self_address: contract_addr,
            ..Default::default()
        };
        let mut vm2 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx2);
        vm2.calldata = cd2;
        let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
        vm2.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr).get(&sk) }
        }));
        vm2.load(&contract.runtime_bytecode).unwrap();
        let mut steps = 0u64;
        loop {
            match vm2.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 1_000_000 {
                        panic!("infinite loop at step {}", steps);
                    }
                    // Trace last 20 steps before cutoff
                    if steps >= 999_980 {
                        let pc = vm2.pc as usize;
                        if pc + 4 <= contract.runtime_bytecode.len() {
                            let w = u32::from_le_bytes(
                                contract.runtime_bytecode[pc..pc + 4].try_into().unwrap(),
                            );
                            let d = pyde_vm::isa::decode(pyde_vm::isa::Instruction(w));
                            eprintln!("  s={} PC={} {:?} rd={} rs1={} imm={:#x} r1={} r2={} r14={:#x} r15={:#x}",
                                steps, pc, d.opcode, d.rd, d.rs1, d.rs2_or_imm,
                                vm2.cpu.read_gp(1), vm2.cpu.read_gp(2),
                                vm2.cpu.read_gp(14), vm2.cpu.read_gp(15));
                        }
                    }
                }
                Err(e) => panic!("trap at step {}: {:?}", steps, e),
            }
        }
        assert_eq!(
            vm2.cpu.read_gp(1),
            150,
            "sum = 10+20+30+40+50 = 150 (many-function contract)"
        );
    }

    #[test]
    fn pvm_vec_string_storage() {
        // Vec<String> storage: store vec of strings, read back lengths
        let compiled = compile_no_opt(
            r#"
            contract T {
                storage {
                    tags: Map<u64, Vec<String>>,
                }
                pub fn store_tags(id: u64) -> u64 {
                    let mut v = Vec::new();
                    v.push("hello");
                    v.push("world");
                    self.tags[id] = v;
                    return 2;
                }
                pub fn read_tag_count(id: u64) -> u64 {
                    let v = self.tags[id];
                    return v.len();
                }
            }
        "#,
        );
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
        vm.load(&compiled.bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 200_000 {
                        panic!("too many steps");
                    }
                }
                Err(e) => {
                    panic!("PVM error at step {}: {:?}", steps, e);
                }
            }
        }
        assert_eq!(vm.cpu.read_gp(1), 2, "stored 2 strings");
    }

    #[test]
    fn pvm_string_storage() {
        // Test String storage: store a string, read it back, check length
        let compiled = compile_no_opt(
            r#"
            contract T {
                storage {
                    names: Map<u64, String>,
                }
                pub fn store_name(id: u64) -> u64 {
                    let s = "hello world";
                    self.names[id] = s;
                    return s.len();
                }
                pub fn read_name_len(id: u64) -> u64 {
                    let s = self.names[id];
                    return s.len();
                }
            }
        "#,
        );
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
        vm.load(&compiled.bytecode).unwrap();
        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 100_000 {
                        panic!("too many steps");
                    }
                }
                Err(e) => {
                    panic!("PVM error at step {}: {:?}", steps, e);
                }
            }
        }
        // "hello world" = 11 chars
        assert_eq!(vm.cpu.read_gp(1), 11, "string length should be 11");
    }

    #[test]
    fn pvm_struct_vec_rank() {
        // Reproduces compute_rank: read struct + vec from storage, loop with comparison
        let src = r#"
            contract T {
                struct Player { id: u64, score: u64, }
                storage { players: Map<u64, Player>, boards: Map<u64, Vec<u64>>, }
                pub fn setup() {
                    let p = Player { id: 1, score: 400 };
                    self.players[1] = p;
                    let mut b = Vec::new();
                    b.push(100); b.push(200); b.push(300);
                    self.boards[1] = b;
                }
                pub fn rank() -> u64 {
                    let p = self.players[1];
                    let board = self.boards[1];
                    let score = p.score;
                    let mut r = 0;
                    let mut i = 0;
                    let len = board.len();
                    while i < len {
                        if board[i] > score { r = r + 1; }
                        i = i + 1;
                    }
                    return r + 1;
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let codegen = CodeGen::new();
        let contract = codegen.generate(&ir);
        let addr = [0x42u8; 32];

        // Setup
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = compute_selector("setup").to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(out1.outcome, pyde_vm::vm::Outcome::Success, "setup failed");

        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        // Rank
        let ctx2 = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm2 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx2);
        vm2.calldata = compute_selector("rank").to_be_bytes().to_vec();
        let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
        vm2.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr).get(&sk) }
        }));
        vm2.load(&contract.runtime_bytecode).unwrap();
        let mut steps = 0u64;
        loop {
            match vm2.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 1_000_000 {
                        panic!("infinite loop at step {}", steps);
                    }
                }
                Err(e) => {
                    let pc = vm2.pc as usize;
                    let w = u32::from_le_bytes(
                        contract.runtime_bytecode[pc..pc + 4]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
                    let d = pyde_vm::isa::decode(pyde_vm::isa::Instruction(w));
                    panic!("trap at step {} PC={}: {:?}\n  {:?} rd={} rs1={} imm={:#x}\n  r1={:#x} r2={:#x} r3={:#x} r4={:#x} r5={:#x} r6={:#x} r7={:#x} r8={:#x} r9={:#x} r10={:#x} r11={:#x}\n  r12={:#x} r13={:#x} r14={:#x} r15={:#x}",
                        steps, pc, e, d.opcode, d.rd, d.rs1, d.rs2_or_imm,
                        vm2.cpu.read_gp(1), vm2.cpu.read_gp(2), vm2.cpu.read_gp(3),
                        vm2.cpu.read_gp(4), vm2.cpu.read_gp(5), vm2.cpu.read_gp(6),
                        vm2.cpu.read_gp(7), vm2.cpu.read_gp(8), vm2.cpu.read_gp(9),
                        vm2.cpu.read_gp(10), vm2.cpu.read_gp(11),
                        vm2.cpu.read_gp(12), vm2.cpu.read_gp(13),
                        vm2.cpu.read_gp(14), vm2.cpu.read_gp(15));
                }
            }
        }
        // score=400, board=[100,200,300]. 0 entries > 400. rank = 0+1 = 1.
        assert_eq!(vm2.cpu.read_gp(1), 1, "rank should be 1");
    }

    #[test]
    fn pvm_nested_struct_with_vec_storage() {
        // Nested struct (Hero { Stats, Vec<u64> }) in Map storage:
        // serialize, store, load, deserialize, access nested fields + loop over Vec.
        let src = r#"
            contract T {
                struct Stats { hp: u64, mp: u64, level: u64, }
                struct Hero { id: u64, stats: Stats, scores: Vec<u64>, }
                storage { heroes: Map<u64, Hero>, }
                pub fn create_hero() {
                    let s = Stats { hp: 100, mp: 50, level: 5 };
                    let mut sc = Vec::new();
                    sc.push(10); sc.push(20); sc.push(30);
                    let h = Hero { id: 1, stats: s, scores: sc };
                    self.heroes[1] = h;
                }
                pub fn hero_power() -> u64 {
                    let h = self.heroes[1];
                    let base = h.stats.hp + h.stats.mp * h.stats.level;
                    let mut bonus = 0;
                    let mut i = 0;
                    let len = h.scores.len();
                    while i < len {
                        bonus = bonus + h.scores[i];
                        i = i + 1;
                    }
                    return base + bonus;
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let codegen = CodeGen::new();
        let contract = codegen.generate(&ir);
        let addr = [0x55u8; 32];

        // Run create_hero
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = compute_selector("create_hero").to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let mut steps = 0u64;
        loop {
            match vm1.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 1_000_000 {
                        panic!("infinite loop");
                    }
                }
                Err(e) => {
                    let pc = vm1.pc as usize;
                    let w = u32::from_le_bytes(
                        contract.runtime_bytecode[pc..pc + 4]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
                    let d = pyde_vm::isa::decode(pyde_vm::isa::Instruction(w));
                    panic!("create_hero trap at step {} PC={}: {:?}\n  {:?} rd={} rs1={} imm={:#x}\n  r1={:#x} r2={:#x} r3={:#x} r4={:#x} r5={:#x} r6={:#x} r7={:#x} r8={:#x} r9={:#x} r10={:#x} r11={:#x}\n  r12={:#x} r13={:#x} r14={:#x} r15={:#x}",
                        steps, pc, e, d.opcode, d.rd, d.rs1, d.rs2_or_imm,
                        vm1.cpu.read_gp(1), vm1.cpu.read_gp(2), vm1.cpu.read_gp(3),
                        vm1.cpu.read_gp(4), vm1.cpu.read_gp(5), vm1.cpu.read_gp(6),
                        vm1.cpu.read_gp(7), vm1.cpu.read_gp(8), vm1.cpu.read_gp(9),
                        vm1.cpu.read_gp(10), vm1.cpu.read_gp(11),
                        vm1.cpu.read_gp(12), vm1.cpu.read_gp(13),
                        vm1.cpu.read_gp(14), vm1.cpu.read_gp(15));
                }
            }
        }

        // Persist storage to SMT
        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        // Run hero_power
        let ctx2 = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm2 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx2);
        vm2.calldata = compute_selector("hero_power").to_be_bytes().to_vec();
        let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
        vm2.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr).get(&sk) }
        }));
        vm2.load(&contract.runtime_bytecode).unwrap();
        let mut steps = 0u64;
        loop {
            match vm2.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 1_000_000 {
                        panic!("infinite loop at step {}", steps);
                    }
                }
                Err(e) => {
                    let pc = vm2.pc as usize;
                    let w = u32::from_le_bytes(
                        contract.runtime_bytecode[pc..pc + 4]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
                    let d = pyde_vm::isa::decode(pyde_vm::isa::Instruction(w));
                    panic!("trap at step {} PC={}: {:?}\n  {:?} rd={} rs1={} imm={:#x}\n  r1={:#x} r2={:#x} r3={:#x} r4={:#x} r5={:#x} r6={:#x} r7={:#x} r8={:#x}\n  r12={:#x} r13={:#x} r14={:#x} r15={:#x}",
                        steps, pc, e, d.opcode, d.rd, d.rs1, d.rs2_or_imm,
                        vm2.cpu.read_gp(1), vm2.cpu.read_gp(2), vm2.cpu.read_gp(3),
                        vm2.cpu.read_gp(4), vm2.cpu.read_gp(5), vm2.cpu.read_gp(6),
                        vm2.cpu.read_gp(7), vm2.cpu.read_gp(8),
                        vm2.cpu.read_gp(12), vm2.cpu.read_gp(13),
                        vm2.cpu.read_gp(14), vm2.cpu.read_gp(15));
                }
            }
        }
        // base = hp + mp * level = 100 + 50 * 5 = 350
        // bonus = 10 + 20 + 30 = 60
        // total = 350 + 60 = 410
        assert_eq!(vm2.cpu.read_gp(1), 410, "hero_power should be 410");
    }

    #[test]
    fn pvm_complex_struct_arg_and_return() {
        // Tests:
        // 1. Struct with Vec<u64> field as function ARGUMENT (calldata deserialization)
        // 2. Struct as function RETURN VALUE (blob return serialization, r1=ptr r2=len)
        // 3. Struct with Vec field in storage (round-trip serialize/deserialize)
        let src = r#"
            contract T {
                struct Profile {
                    id: u64,
                    score: u64,
                    tags: Vec<u64>,
                }
                storage { profiles: Map<u64, Profile>, }

                pub fn store_profile(p: Profile) {
                    self.profiles[p.id] = p;
                }

                pub fn get_score(pid: u64) -> u64 {
                    let p = self.profiles[pid];
                    return p.score;
                }

                pub fn tag_sum(pid: u64) -> u64 {
                    let p = self.profiles[pid];
                    let mut total = 0;
                    let mut i = 0;
                    let len = p.tags.len();
                    while i < len {
                        total = total + p.tags[i];
                        i = i + 1;
                    }
                    return total;
                }

                pub fn load_profile(pid: u64) -> Profile {
                    let p = self.profiles[pid];
                    return p;
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let codegen = CodeGen::new();
        let contract = codegen.generate(&ir);
        let addr = [0x77u8; 32];

        // === Step 1: Call store_profile(Profile { id: 42, score: 99, tags: [10, 20, 30] }) ===
        // Build calldata: selector + Borsh-serialized Profile blob
        // Profile Borsh: [id:8][score:8][tags_count:8][tag0:8][tag1:8][tag2:8] = 48 bytes
        let store_sel = compute_selector("store_profile");
        let mut calldata = store_sel.to_be_bytes().to_vec();
        // Blob prefix: byte_len = 48
        calldata.extend_from_slice(&56u64.to_le_bytes()); // flat: id(8)+score(8)+len(8)+cap(8)+3*tag(24)=56
                                                          // id = 42
        calldata.extend_from_slice(&42u64.to_le_bytes());
        // score = 99
        calldata.extend_from_slice(&99u64.to_le_bytes());
        // tags: len=3, cap=3 (flat format), elements=[10,20,30]
        calldata.extend_from_slice(&3u64.to_le_bytes()); // len
        calldata.extend_from_slice(&3u64.to_le_bytes()); // cap
        calldata.extend_from_slice(&10u64.to_le_bytes());
        calldata.extend_from_slice(&20u64.to_le_bytes());
        calldata.extend_from_slice(&30u64.to_le_bytes());

        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = calldata;
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(
            out1.outcome,
            pyde_vm::vm::Outcome::Success,
            "store_profile failed: {:?}",
            out1.outcome
        );

        // Persist storage
        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        // === Step 2: Call get_score(42) — scalar return from stored struct ===
        let score_sel = compute_selector("get_score");
        let mut cd2 = score_sel.to_be_bytes().to_vec();
        cd2.extend_from_slice(&42u64.to_le_bytes());

        let ctx2 = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm2 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx2);
        vm2.calldata = cd2;
        let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
        vm2.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr).get(&sk) }
        }));
        vm2.load(&contract.runtime_bytecode).unwrap();
        let out2 = vm2.execute();
        assert_eq!(
            out2.outcome,
            pyde_vm::vm::Outcome::Success,
            "get_score failed"
        );
        assert_eq!(vm2.cpu.read_gp(1), 99, "score should be 99");

        // === Step 3: Call tag_sum(42) — loop over Vec field from stored struct ===
        let tag_sel = compute_selector("tag_sum");
        let mut cd3 = tag_sel.to_be_bytes().to_vec();
        cd3.extend_from_slice(&42u64.to_le_bytes());

        let ctx3 = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm3 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx3);
        vm3.calldata = cd3;
        let smt_ptr3 = &smt as *const pyde_state::smt::PydeSMT;
        vm3.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr3).get(&sk) }
        }));
        vm3.load(&contract.runtime_bytecode).unwrap();
        let out3 = vm3.execute();
        assert_eq!(
            out3.outcome,
            pyde_vm::vm::Outcome::Success,
            "tag_sum failed"
        );
        assert_eq!(vm3.cpu.read_gp(1), 60, "tag_sum should be 10+20+30=60");

        // === Step 4: Call load_profile(42) — struct RETURN (blob serialization) ===
        let load_sel = compute_selector("load_profile");
        let mut cd4 = load_sel.to_be_bytes().to_vec();
        cd4.extend_from_slice(&42u64.to_le_bytes());

        let ctx4 = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm4 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx4);
        vm4.calldata = cd4;
        let smt_ptr4 = &smt as *const pyde_state::smt::PydeSMT;
        vm4.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr4).get(&sk) }
        }));
        vm4.load(&contract.runtime_bytecode).unwrap();
        let out4 = vm4.execute();
        assert_eq!(
            out4.outcome,
            pyde_vm::vm::Outcome::Success,
            "load_profile failed"
        );

        // r1 = buffer pointer, r2 = byte length of Borsh-serialized Profile
        let r1 = vm4.cpu.read_gp(1) as usize;
        let r2 = vm4.cpu.read_gp(2) as usize;
        assert!(r2 > 0, "r2 should be > 0 for blob return");
        // Flat format: [id:8][score:8][len:8][cap:8][tag0:8][tag1:8][tag2:8] = 56 bytes
        assert_eq!(
            r2, 56,
            "flat Profile should be 56 bytes (id+score+len+cap+3*tag)"
        );
        let blob = vm4.memory.load_bytes(r1, r2);
        let id = u64::from_le_bytes(blob[0..8].try_into().unwrap());
        let score = u64::from_le_bytes(blob[8..16].try_into().unwrap());
        let count = u64::from_le_bytes(blob[16..24].try_into().unwrap());
        let cap = u64::from_le_bytes(blob[24..32].try_into().unwrap());
        let tag0 = u64::from_le_bytes(blob[32..40].try_into().unwrap());
        let tag1 = u64::from_le_bytes(blob[40..48].try_into().unwrap());
        let tag2 = u64::from_le_bytes(blob[48..56].try_into().unwrap());
        assert_eq!(id, 42, "returned profile.id");
        assert_eq!(score, 99, "returned profile.score");
        assert_eq!(count, 3, "returned profile.tags.len");
        assert_eq!(cap, 3, "returned profile.tags.cap");
        assert_eq!((tag0, tag1, tag2), (10, 20, 30), "returned profile.tags");
    }

    #[test]
    fn pvm_all_global_vars() {
        // Test every global variable: msg.sender, msg.value, block.height,
        // block.timestamp, block.proposer, tx.nonce, tx.gas_limit, tx.gas_price,
        // tx.hash, address(self), gas_remaining
        let src = r#"
            contract T {
                storage {}
                pub fn get_block_height() -> u64 { return block.height; }
                pub fn get_block_timestamp() -> u64 { return block.timestamp; }
                pub fn get_tx_nonce() -> u64 { return tx.nonce; }
                pub fn get_tx_gas_limit() -> u64 { return tx.gas_limit; }
                pub fn get_gas_remaining() -> u64 { return gas_remaining(); }
                pub fn get_msg_sender() -> Address { return msg.sender; }
                pub fn get_msg_value() -> u256 { return msg.value; }
                pub fn get_self_address() -> Address { return address(self); }
                pub fn get_tx_gas_price() -> u256 { return tx.gas_price; }
                pub fn get_block_proposer() -> Address { return block.proposer; }
                pub fn get_tx_hash() -> u256 { return tx.hash; }
            }
        "#;
        // Use production compilation (with dispatch + guards) for selector-based calling
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let ir = crate::lower::lower(&file);
        let compiled = CodeGen::new().generate(&ir);

        let caller = [0xAAu8; 32];
        let self_addr = [0xBBu8; 32];
        let proposer = [0xCCu8; 32];
        // call_value must be 0 for non-payable functions (production guard checks)
        let ctx = pyde_vm::vm::ExecutionContext {
            caller,
            self_address: self_addr,
            call_value: ethnum::U256::ZERO,
            block_number: 42,
            timestamp: 1_700_000_000,
            gas_price: ethnum::U256::from(50_000_000_000u64),
            tx_nonce: 7,
            tx_gas_limit: 100_000_000,
            tx_hash: ethnum::U256::from(0xDEADBEEFu64),
            block_proposer: proposer,
            block_hashes: vec![],
            balances: std::collections::HashMap::new(),
        };

        // Helper: run a function and return (r1, w0)
        let run = |sel_name: &str, ctx: &pyde_vm::vm::ExecutionContext| -> (u64, ethnum::U256) {
            let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(10_000_000, ctx.clone());
            vm.calldata = compute_selector(sel_name).to_be_bytes().to_vec();
            vm.load(&compiled.runtime_bytecode).unwrap();
            let out = vm.execute();
            assert_eq!(
                out.outcome,
                pyde_vm::vm::Outcome::Success,
                "{} failed",
                sel_name
            );
            (vm.cpu.read_gp(1), vm.cpu.read_wide(0))
        };

        // GP globals (returned in r1)
        let (r1, _) = run("get_block_height", &ctx);
        assert_eq!(r1, 42, "block.height");

        let (r1, _) = run("get_block_timestamp", &ctx);
        assert_eq!(r1, 1_700_000_000, "block.timestamp");

        let (r1, _) = run("get_tx_nonce", &ctx);
        assert_eq!(r1, 7, "tx.nonce");

        let (r1, _) = run("get_tx_gas_limit", &ctx);
        assert_eq!(r1, 100_000_000, "tx.gas_limit");

        let (r1, _) = run("get_gas_remaining", &ctx);
        assert!(
            r1 > 0 && r1 <= 10_000_000,
            "gas_remaining should be >0, got {}",
            r1
        );

        // Wide globals (returned in w0, with low 64 bits in r1)
        let (_, w0) = run("get_msg_sender", &ctx);
        assert_eq!(w0.to_le_bytes(), caller, "msg.sender");

        let (_, w0) = run("get_msg_value", &ctx);
        assert_eq!(w0, ethnum::U256::ZERO, "msg.value (0 for non-payable)");

        let (_, w0) = run("get_self_address", &ctx);
        assert_eq!(w0.to_le_bytes(), self_addr, "address(self)");

        let (_, w0) = run("get_tx_gas_price", &ctx);
        assert_eq!(w0, ethnum::U256::from(50_000_000_000u64), "tx.gas_price");

        let (_, w0) = run("get_block_proposer", &ctx);
        assert_eq!(w0.to_le_bytes(), proposer, "block.proposer");

        let (_, w0) = run("get_tx_hash", &ctx);
        assert_eq!(w0, ethnum::U256::from(0xDEADBEEFu64), "tx.hash");
    }

    #[test]
    fn pvm_packed_struct_mixed_field_sizes() {
        // Test packed layout: u8 (1B) + u8 (1B) + u64 (8B) + u64 (8B) = 18 bytes total
        // Offsets: age@+0, level@+1, hp@+2, score@+10
        let compiled = compile_no_opt(
            r#"
            contract T {
                storage {}
                struct Char { age: u8, level: u8, hp: u64, score: u64, }
                pub fn test_packed() -> u64 {
                    let c = Char { age: 25, level: 10, hp: 1000, score: 9999 };
                    let a = c.age;
                    let l = c.level;
                    let h = c.hp;
                    let s = c.score;
                    return a + l + h + s;
                }
            }
        "#,
        );
        let vm = run_pvm(&compiled.bytecode);
        // 25 + 10 + 1000 + 9999 = 11034
        assert_eq!(
            vm.cpu.read_gp(1),
            11034,
            "packed struct field access: 25+10+1000+9999"
        );
    }

    #[test]
    fn pvm_packed_struct_storage_roundtrip() {
        // Packed struct (u8, u8, u32) through FULL storage roundtrip:
        // StructInit → emit_flatten → Sstore → Sload → emit_unflatten → FieldGet
        let src = r#"
            contract T {
                struct Stats { hp: u8, mp: u8, level: u32, }
                storage { data: Map<u64, Stats>, }
                pub fn store_stats() {
                    let s = Stats { hp: 100, mp: 50, level: 5 };
                    self.data[1] = s;
                }
                pub fn read_stats() -> u64 {
                    let s = self.data[1];
                    return s.hp + s.mp * s.level;
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let codegen = CodeGen::new();
        let contract = codegen.generate(&ir);
        let addr = [0x88u8; 32];

        // Store
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = compute_selector("store_stats").to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(
            out1.outcome,
            pyde_vm::vm::Outcome::Success,
            "store_stats failed"
        );

        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        // Read
        let ctx2 = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm2 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx2);
        vm2.calldata = compute_selector("read_stats").to_be_bytes().to_vec();
        let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
        vm2.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr).get(&sk) }
        }));
        vm2.load(&contract.runtime_bytecode).unwrap();
        let mut steps = 0u64;
        loop {
            match vm2.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 1_000_000 {
                        panic!("infinite loop");
                    }
                }
                Err(e) => {
                    let pc = vm2.pc as usize;
                    let w = u32::from_le_bytes(
                        contract.runtime_bytecode[pc..pc + 4]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
                    let d = pyde_vm::isa::decode(pyde_vm::isa::Instruction(w));
                    panic!("trap at step {} PC={}: {:?}\n  {:?} rd={} rs1={} imm={:#x}\n  r1={:#x} r2={:#x} r3={:#x} r4={:#x} r5={:#x} r6={:#x}\n  r12={:#x} r13={:#x} r14={:#x} r15={:#x}",
                        steps, pc, e, d.opcode, d.rd, d.rs1, d.rs2_or_imm,
                        vm2.cpu.read_gp(1), vm2.cpu.read_gp(2), vm2.cpu.read_gp(3),
                        vm2.cpu.read_gp(4), vm2.cpu.read_gp(5), vm2.cpu.read_gp(6),
                        vm2.cpu.read_gp(12), vm2.cpu.read_gp(13),
                        vm2.cpu.read_gp(14), vm2.cpu.read_gp(15));
                }
            }
        }
        // hp + mp * level = 100 + 50 * 5 = 350
        assert_eq!(
            vm2.cpu.read_gp(1),
            350,
            "packed struct storage roundtrip: 100 + 50*5"
        );
    }

    #[test]
    fn pvm_packed_hero_with_vec_storage() {
        // Full test: packed Stats (u8+u8+u32) inside Hero with Vec<u64>, through storage.
        let src = r#"
            contract T {
                struct Stats { hp: u8, mp: u8, level: u32, }
                struct Hero { id: u64, stats: Stats, scores: Vec<u64>, }
                storage { heroes: Map<u64, Hero>, }
                pub fn create() {
                    let s = Stats { hp: 100, mp: 50, level: 5 };
                    let mut sc = Vec::new();
                    sc.push(10); sc.push(20); sc.push(30); sc.push(40); sc.push(50);
                    let h = Hero { id: 1, stats: s, scores: sc };
                    self.heroes[1] = h;
                }
                pub fn power() -> u64 {
                    let h = self.heroes[1];
                    let base = h.stats.hp + h.stats.mp * h.stats.level;
                    let mut bonus = 0;
                    let mut i = 0;
                    let len = h.scores.len();
                    while i < len {
                        bonus = bonus + h.scores[i];
                        i = i + 1;
                    }
                    return base + bonus;
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let codegen = CodeGen::new();
        let contract = codegen.generate(&ir);
        let addr = [0x99u8; 32];

        // Create hero
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = compute_selector("create").to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(out1.outcome, pyde_vm::vm::Outcome::Success, "create failed");

        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        // Read power
        let ctx2 = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm2 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx2);
        vm2.calldata = compute_selector("power").to_be_bytes().to_vec();
        let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
        vm2.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr).get(&sk) }
        }));
        vm2.load(&contract.runtime_bytecode).unwrap();
        let mut steps = 0u64;
        loop {
            match vm2.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 1_000_000 {
                        panic!("infinite loop");
                    }
                }
                Err(e) => {
                    let pc = vm2.pc as usize;
                    let w = u32::from_le_bytes(
                        contract.runtime_bytecode[pc..pc + 4]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
                    let d = pyde_vm::isa::decode(pyde_vm::isa::Instruction(w));
                    panic!("trap at step {} PC={}: {:?}\n  {:?} rd={} rs1={} imm={:#x}\n  r1-r6: {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}\n  r7-r11: {:#x} {:#x} {:#x} {:#x} {:#x}\n  r14={:#x} r15={:#x}",
                        steps, pc, e, d.opcode, d.rd, d.rs1, d.rs2_or_imm,
                        vm2.cpu.read_gp(1), vm2.cpu.read_gp(2), vm2.cpu.read_gp(3),
                        vm2.cpu.read_gp(4), vm2.cpu.read_gp(5), vm2.cpu.read_gp(6),
                        vm2.cpu.read_gp(7), vm2.cpu.read_gp(8), vm2.cpu.read_gp(9),
                        vm2.cpu.read_gp(10), vm2.cpu.read_gp(11),
                        vm2.cpu.read_gp(14), vm2.cpu.read_gp(15));
                }
            }
        }
        // base = 100 + 50*5 = 350, bonus = 10+20+30+40+50 = 150, total = 500
        assert_eq!(
            vm2.cpu.read_gp(1),
            500,
            "packed hero power: 100+50*5+10+20+30+40+50"
        );
    }

    #[test]
    fn pvm_vec_of_struct_storage_roundtrip() {
        // Vec<Struct> through full storage roundtrip: flatten, store, load, unflatten, access.
        let src = r#"
            contract T {
                struct Point { x: u64, y: u64, }
                storage { points: Map<u64, Vec<Point>>, }
                pub fn store_points() {
                    let mut v = Vec::new();
                    v.push(Point { x: 10, y: 20 });
                    v.push(Point { x: 30, y: 40 });
                    v.push(Point { x: 50, y: 60 });
                    self.points[1] = v;
                }
                pub fn sum_points() -> u64 {
                    let pts = self.points[1];
                    let mut total = 0;
                    let mut i = 0;
                    let len = pts.len();
                    while i < len {
                        let p = pts[i];
                        total = total + p.x + p.y;
                        i = i + 1;
                    }
                    return total;
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let codegen = CodeGen::new();
        let contract = codegen.generate(&ir);
        let addr = [0xAAu8; 32];

        // Store
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = compute_selector("store_points").to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(
            out1.outcome,
            pyde_vm::vm::Outcome::Success,
            "store_points failed"
        );

        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        // Read
        let ctx2 = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm2 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx2);
        vm2.calldata = compute_selector("sum_points").to_be_bytes().to_vec();
        let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
        vm2.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr).get(&sk) }
        }));
        vm2.load(&contract.runtime_bytecode).unwrap();
        let mut steps = 0u64;
        loop {
            match vm2.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 1_000_000 {
                        panic!("infinite loop");
                    }
                }
                Err(e) => {
                    let pc = vm2.pc as usize;
                    let w = u32::from_le_bytes(
                        contract.runtime_bytecode[pc..pc + 4]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
                    let d = pyde_vm::isa::decode(pyde_vm::isa::Instruction(w));
                    panic!(
                        "trap at step {} PC={}: {:?}\n  {:?} rd={} rs1={} imm={:#x}",
                        steps, pc, e, d.opcode, d.rd, d.rs1, d.rs2_or_imm
                    );
                }
            }
        }
        // (10+20) + (30+40) + (50+60) = 210
        assert_eq!(
            vm2.cpu.read_gp(1),
            210,
            "Vec<Point> storage roundtrip: sum of x+y"
        );
    }

    #[test]
    fn pvm_vec_struct_as_arg() {
        // Vec<Point> as function argument via calldata
        let src = r#"
            contract T {
                struct Point { x: u64, y: u64, }
                storage {}
                pub fn sum_arg(pts: Vec<Point>) -> u64 {
                    let mut total = 0;
                    let mut i = 0;
                    let len = pts.len();
                    while i < len {
                        let p = pts[i];
                        total = total + p.x + p.y;
                        i = i + 1;
                    }
                    return total;
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let ir = crate::lower::lower(&file);
        let contract = CodeGen::new().generate(&ir);

        // Build calldata: selector + [byte_len:8][len:8][cap:8][p0.x:8][p0.y:8][p1.x:8][p1.y:8]
        let sel = compute_selector("sum_arg");
        let mut calldata = sel.to_be_bytes().to_vec();
        calldata.extend_from_slice(&48u64.to_le_bytes()); // byte_len = 48
        calldata.extend_from_slice(&2u64.to_le_bytes()); // len = 2
        calldata.extend_from_slice(&2u64.to_le_bytes()); // cap = 2
        calldata.extend_from_slice(&5u64.to_le_bytes()); // p0.x = 5
        calldata.extend_from_slice(&10u64.to_le_bytes()); // p0.y = 10
        calldata.extend_from_slice(&20u64.to_le_bytes()); // p1.x = 20
        calldata.extend_from_slice(&40u64.to_le_bytes()); // p1.y = 40

        let ctx = pyde_vm::vm::ExecutionContext::default();
        let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm.calldata = calldata;
        vm.load(&contract.runtime_bytecode).unwrap();
        let mut steps = 0u64;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    steps += 1;
                    if steps > 1_000_000 {
                        panic!("infinite loop");
                    }
                }
                Err(e) => {
                    let pc = vm.pc as usize;
                    let w = u32::from_le_bytes(
                        contract.runtime_bytecode[pc..pc + 4]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
                    let d = pyde_vm::isa::decode(pyde_vm::isa::Instruction(w));
                    panic!("trap at step {} PC={}: {:?}\n  {:?} rd={} rs1={} imm={:#x}\n  r1={:#x} r2={:#x} r3={:#x} r4={:#x} r5={:#x}\n  r11={:#x} r12={:#x} r13={:#x} r14={:#x} r15={:#x}",
                        steps, pc, e, d.opcode, d.rd, d.rs1, d.rs2_or_imm,
                        vm.cpu.read_gp(1), vm.cpu.read_gp(2), vm.cpu.read_gp(3),
                        vm.cpu.read_gp(4), vm.cpu.read_gp(5),
                        vm.cpu.read_gp(11), vm.cpu.read_gp(12), vm.cpu.read_gp(13),
                        vm.cpu.read_gp(14), vm.cpu.read_gp(15));
                }
            }
        }
        // 5 + 10 + 20 + 40 = 75
        assert_eq!(vm.cpu.read_gp(1), 75, "Vec<Point> arg: sum of x+y");
    }

    #[test]
    fn pvm_string_struct_vec_full() {
        // Full test: struct with String field + Vec<Point> + String in storage/return.
        // Tests: String in struct, Vec<String> in storage, struct+string round-trip.
        let src = r#"
            contract T {
                struct NamedPoint { x: u64, y: u64, label: String, }
                storage {
                    points: Map<u64, Vec<NamedPoint>>,
                    tags: Map<u64, Vec<String>>,
                    name: Map<u64, String>,
                }
                pub fn store_data() {
                    self.name[1] = "hello";
                    let mut t = Vec::new();
                    t.push("alpha");
                    t.push("beta");
                    self.tags[1] = t;
                    let mut pts = Vec::new();
                    pts.push(NamedPoint { x: 10, y: 20, label: "first" });
                    pts.push(NamedPoint { x: 30, y: 40, label: "second" });
                    self.points[1] = pts;
                }
                pub fn sum_xy() -> u64 {
                    let pts = self.points[1];
                    let mut total = 0;
                    let mut i = 0;
                    let len = pts.len();
                    while i < len {
                        let p = pts[i];
                        total = total + p.x + p.y;
                        i = i + 1;
                    }
                    return total;
                }
                pub fn get_name_len() -> u64 {
                    let n = self.name[1];
                    return n.len();
                }
                pub fn get_tags_count() -> u64 {
                    let t = self.tags[1];
                    return t.len();
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let contract = CodeGen::new().generate(&ir);
        let addr = [0xBBu8; 32];

        // Store
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = compute_selector("store_data").to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(
            out1.outcome,
            pyde_vm::vm::Outcome::Success,
            "store_data failed: {:?}",
            out1.outcome
        );

        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        // Helper to run a function
        let run = |sel: &str| -> u64 {
            let ctx = pyde_vm::vm::ExecutionContext {
                self_address: addr,
                ..Default::default()
            };
            let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
            vm.calldata = compute_selector(sel).to_be_bytes().to_vec();
            let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
            vm.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
                let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
                unsafe { (*smt_ptr).get(&sk) }
            }));
            vm.load(&contract.runtime_bytecode).unwrap();
            let out = vm.execute();
            assert_eq!(out.outcome, pyde_vm::vm::Outcome::Success, "{} failed", sel);
            vm.cpu.read_gp(1)
        };

        assert_eq!(run("sum_xy"), 100, "sum_xy: (10+20)+(30+40) = 100");
        assert_eq!(run("get_name_len"), 5, "name 'hello' has 5 bytes");
        assert_eq!(run("get_tags_count"), 2, "tags has 2 elements");
    }

    #[test]
    fn pvm_profile_string_first_field() {
        // Reproducer: struct with String as FIRST field, through storage round-trip.
        let src = r#"
            contract T {
                struct Profile { name: String, age: u64, }
                storage { profiles: Map<u64, Profile>, }
                pub fn store_prof() {
                    let p = Profile { name: "alice", age: 30 };
                    self.profiles[1] = p;
                }
                pub fn get_age() -> u64 {
                    let p = self.profiles[1];
                    return p.age;
                }
                pub fn get_name_len() -> u64 {
                    let p = self.profiles[1];
                    return p.name.len();
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let contract = CodeGen::new().generate(&ir);
        let addr = [0xCCu8; 32];

        // Store
        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = compute_selector("store_prof").to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(
            out1.outcome,
            pyde_vm::vm::Outcome::Success,
            "store_prof failed"
        );

        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        let run = |sel: &str| -> u64 {
            let ctx = pyde_vm::vm::ExecutionContext {
                self_address: addr,
                ..Default::default()
            };
            let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
            vm.calldata = compute_selector(sel).to_be_bytes().to_vec();
            let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
            vm.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
                let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
                unsafe { (*smt_ptr).get(&sk) }
            }));
            vm.load(&contract.runtime_bytecode).unwrap();
            let out = vm.execute();
            assert_eq!(out.outcome, pyde_vm::vm::Outcome::Success, "{} failed", sel);
            vm.cpu.read_gp(1)
        };

        assert_eq!(run("get_age"), 30, "age should be 30");
        assert_eq!(run("get_name_len"), 5, "name 'alice' should be 5 bytes");
    }

    #[test]
    fn pvm_profile_full_fields() {
        // Profile { name: String, age: u64, tags: Vec<String>, scores: Vec<u64> }
        let src = r#"
            contract T {
                struct Profile { age: u64, name: String, tags: Vec<u64>, scores: Vec<u64>, }
                storage { profiles: Map<u64, Profile>, }
                pub fn store_prof() {
                    let mut tags = Vec::new(); tags.push(100); tags.push(200); tags.push(300);
                    let mut scores = Vec::new(); scores.push(10); scores.push(20); scores.push(30);
                    let p = Profile { age: 30, name: "alice", tags: tags, scores: scores };
                    self.profiles[1] = p;
                }
                pub fn get_age() -> u64 { let p = self.profiles[1]; return p.age; }
                pub fn get_name_len() -> u64 { let p = self.profiles[1]; return p.name.len(); }
                pub fn get_tags_count() -> u64 { let p = self.profiles[1]; return p.tags.len(); }
                pub fn get_score_sum() -> u64 {
                    let p = self.profiles[1];
                    let mut t=0; let mut i=0; let l=p.scores.len();
                    while i<l { t=t+p.scores[i]; i=i+1; }
                    return t;
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let contract = CodeGen::new().generate(&ir);
        let addr = [0xDDu8; 32];

        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = compute_selector("store_prof").to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(
            out1.outcome,
            pyde_vm::vm::Outcome::Success,
            "store_prof failed"
        );

        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        let run = |sel: &str| -> u64 {
            let ctx = pyde_vm::vm::ExecutionContext {
                self_address: addr,
                ..Default::default()
            };
            let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
            vm.calldata = compute_selector(sel).to_be_bytes().to_vec();
            let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
            vm.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
                let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
                unsafe { (*smt_ptr).get(&sk) }
            }));
            vm.load(&contract.runtime_bytecode).unwrap();
            let out = vm.execute();
            assert_eq!(out.outcome, pyde_vm::vm::Outcome::Success, "{} failed", sel);
            vm.cpu.read_gp(1)
        };

        for (k, v) in &vm1.storage {
            eprintln!(
                "STORAGE key={}: {} bytes: {:02x?}",
                k,
                v.len(),
                &v[..v.len().min(80)]
            );
        }
        assert_eq!(run("get_age"), 30, "age");
        assert_eq!(run("get_name_len"), 5, "name 'alice' = 5 bytes");
        assert_eq!(run("get_tags_count"), 3, "tags count");
        assert_eq!(run("get_score_sum"), 60, "scores 10+20+30");
    }

    // ========================================================================
    // Compiler hardening: test every untested feature
    // ========================================================================

    #[test]
    fn hardening_nested_vec_vec_u64() {
        // Vec<Vec<u64>> in storage round-trip
        let src = r#"
            contract T {
                storage { matrix: Map<u64, Vec<Vec<u64>>>, }
                pub fn store_matrix() {
                    let mut row1 = Vec::new(); row1.push(1); row1.push(2); row1.push(3);
                    let mut row2 = Vec::new(); row2.push(4); row2.push(5); row2.push(6);
                    let mut m = Vec::new(); m.push(row1); m.push(row2);
                    self.matrix[1] = m;
                }
                pub fn sum_matrix() -> u64 {
                    let m = self.matrix[1];
                    let mut total = 0;
                    let mut i = 0;
                    let rows = m.len();
                    while i < rows {
                        let row = m[i];
                        let mut j = 0;
                        let cols = row.len();
                        while j < cols {
                            total = total + row[j];
                            j = j + 1;
                        }
                        i = i + 1;
                    }
                    return total;
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let contract = CodeGen::new().generate(&ir);
        let addr = [0xE1u8; 32];

        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = compute_selector("store_matrix").to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(
            out1.outcome,
            pyde_vm::vm::Outcome::Success,
            "store_matrix failed"
        );

        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        let ctx2 = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm2 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx2);
        vm2.calldata = compute_selector("sum_matrix").to_be_bytes().to_vec();
        let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
        vm2.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr).get(&sk) }
        }));
        vm2.load(&contract.runtime_bytecode).unwrap();
        let out2 = vm2.execute();
        assert_eq!(
            out2.outcome,
            pyde_vm::vm::Outcome::Success,
            "sum_matrix failed: {:?}",
            out2.outcome
        );
        assert_eq!(vm2.cpu.read_gp(1), 21, "matrix sum: 1+2+3+4+5+6 = 21");
    }

    #[test]
    fn hardening_u256_in_struct() {
        // Struct with u256 (Address) field — packed layout puts it at 32 bytes
        let src = r#"
            contract T {
                storage { wallets: Map<u64, Address>, }
                pub fn store_addr() {
                    let a = address(self);
                    self.wallets[1] = a;
                }
                pub fn check_addr() -> u64 {
                    let a = self.wallets[1];
                    let s = address(self);
                    if a == s { return 1; }
                    return 0;
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let contract = CodeGen::new().generate(&ir);
        let addr = [0xF0u8; 32];

        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = compute_selector("store_addr").to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(
            out1.outcome,
            pyde_vm::vm::Outcome::Success,
            "store_addr failed"
        );

        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        let ctx2 = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm2 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx2);
        vm2.calldata = compute_selector("check_addr").to_be_bytes().to_vec();
        let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
        vm2.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr).get(&sk) }
        }));
        vm2.load(&contract.runtime_bytecode).unwrap();
        let out2 = vm2.execute();
        assert_eq!(
            out2.outcome,
            pyde_vm::vm::Outcome::Success,
            "check_addr failed"
        );
        assert_eq!(vm2.cpu.read_gp(1), 1, "stored address should match self");
    }

    #[test]
    fn hardening_empty_vec_and_string() {
        // Edge cases: empty Vec, empty String
        let src = r#"
            contract T {
                storage { items: Map<u64, Vec<u64>>, name: Map<u64, String>, }
                pub fn store_empty() {
                    let v = Vec::new();
                    self.items[1] = v;
                    self.name[1] = "";
                }
                pub fn check_empty() -> u64 {
                    let v = self.items[1];
                    let n = self.name[1];
                    return v.len() + n.len();
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let contract = CodeGen::new().generate(&ir);
        let addr = [0xE2u8; 32];

        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = compute_selector("store_empty").to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(
            out1.outcome,
            pyde_vm::vm::Outcome::Success,
            "store_empty failed"
        );

        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        let ctx2 = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm2 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx2);
        vm2.calldata = compute_selector("check_empty").to_be_bytes().to_vec();
        let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
        vm2.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr).get(&sk) }
        }));
        vm2.load(&contract.runtime_bytecode).unwrap();
        let out2 = vm2.execute();
        assert_eq!(
            out2.outcome,
            pyde_vm::vm::Outcome::Success,
            "check_empty failed"
        );
        assert_eq!(
            vm2.cpu.read_gp(1),
            0,
            "empty vec + empty string = 0 total len"
        );
    }

    #[test]
    fn hardening_multiple_storage_writes() {
        // Multiple storage map writes in one transaction
        let src = r#"
            contract T {
                storage { balances: Map<u64, u64>, counter: u64, }
                pub fn batch_write() {
                    self.balances[1] = 100;
                    self.balances[2] = 200;
                    self.balances[3] = 300;
                    self.counter = 3;
                }
                pub fn total() -> u64 {
                    return self.balances[1] + self.balances[2] + self.balances[3] + self.counter;
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let contract = CodeGen::new().generate(&ir);
        let addr = [0xE3u8; 32];

        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = compute_selector("batch_write").to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(
            out1.outcome,
            pyde_vm::vm::Outcome::Success,
            "batch_write failed"
        );

        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        let ctx2 = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm2 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx2);
        vm2.calldata = compute_selector("total").to_be_bytes().to_vec();
        let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
        vm2.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr).get(&sk) }
        }));
        vm2.load(&contract.runtime_bytecode).unwrap();
        let out2 = vm2.execute();
        assert_eq!(out2.outcome, pyde_vm::vm::Outcome::Success, "total failed");
        assert_eq!(vm2.cpu.read_gp(1), 603, "100+200+300+3 = 603");
    }

    #[test]
    fn hardening_many_locals_stress() {
        // Stress test: 20+ local variables forcing many Push/Pop borrows
        let src = r#"
            contract T {
                storage {}
                pub fn stress() -> u64 {
                    let a = 1; let b = 2; let c = 3; let d = 4; let e = 5;
                    let f = 6; let g = 7; let h = 8; let i = 9; let j = 10;
                    let k = 11; let l = 12; let m = 13; let n = 14; let o = 15;
                    let p = 16; let q = 17; let r = 18; let s = 19; let t = 20;
                    return a+b+c+d+e+f+g+h+i+j+k+l+m+n+o+p+q+r+s+t;
                }
            }
        "#;
        let compiled = compile_no_opt(src);
        let vm = run_pvm(&compiled.bytecode);
        assert_eq!(vm.cpu.read_gp(1), 210, "sum 1..20 = 210");
    }

    #[test]
    fn hardening_enum_storage() {
        // Enum in storage, args, computation
        let src = r#"
            contract T {
                enum Status { Active, Paused, Closed, }
                storage { state: Map<u64, Status>, }
                pub fn set_paused() {
                    self.state[1] = Status::Paused;
                }
                pub fn get_status() -> u64 {
                    let s = self.state[1];
                    return s as u64;
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let contract = CodeGen::new().generate(&ir);
        let addr = [0xE4u8; 32];

        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = compute_selector("set_paused").to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(
            out1.outcome,
            pyde_vm::vm::Outcome::Success,
            "set_status failed"
        );

        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        let ctx2 = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm2 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx2);
        vm2.calldata = compute_selector("get_status").to_be_bytes().to_vec();
        let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
        vm2.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr).get(&sk) }
        }));
        vm2.load(&contract.runtime_bytecode).unwrap();
        let out2 = vm2.execute();
        assert_eq!(
            out2.outcome,
            pyde_vm::vm::Outcome::Success,
            "get_status failed"
        );
        assert_eq!(vm2.cpu.read_gp(1), 1, "status should be Paused (1)");
    }

    #[test]
    fn hardening_struct_with_address() {
        // Struct with Address (u256) field — tests packed layout with wide inline
        let src = r#"
            contract T {
                struct Wallet { owner: Address, balance: u64, label: String, }
                storage { wallets: Map<u64, Wallet>, }
                pub fn store_wallet() {
                    let w = Wallet { owner: msg.sender, balance: 1000, label: "main" };
                    self.wallets[1] = w;
                }
                pub fn get_balance() -> u64 {
                    let w = self.wallets[1];
                    return w.balance;
                }
                pub fn get_label_len() -> u64 {
                    let w = self.wallets[1];
                    return w.label.len();
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let contract = CodeGen::new().generate(&ir);
        let addr = [0xE5u8; 32];
        let caller = [0xABu8; 32];

        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            caller,
            call_value: ethnum::U256::ZERO,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = compute_selector("store_wallet").to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(
            out1.outcome,
            pyde_vm::vm::Outcome::Success,
            "store_wallet failed"
        );

        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        let run = |sel: &str| -> u64 {
            let ctx = pyde_vm::vm::ExecutionContext {
                self_address: addr,
                caller,
                call_value: ethnum::U256::ZERO,
                ..Default::default()
            };
            let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
            vm.calldata = compute_selector(sel).to_be_bytes().to_vec();
            let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
            vm.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
                let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
                unsafe { (*smt_ptr).get(&sk) }
            }));
            vm.load(&contract.runtime_bytecode).unwrap();
            let out = vm.execute();
            assert_eq!(out.outcome, pyde_vm::vm::Outcome::Success, "{} failed", sel);
            vm.cpu.read_gp(1)
        };

        assert_eq!(run("get_balance"), 1000, "balance should be 1000");
        assert_eq!(run("get_label_len"), 4, "label 'main' = 4 bytes");
    }

    #[test]
    fn hardening_packed_stats_in_player() {
        // Focused: packed Stats{u8,u8,u32,u64} nested in Player with String+Vec
        let src = r#"
            contract T {
                struct Stats { hp: u8, mp: u8, level: u32, xp: u64, }
                enum Role { Admin, User, Guest, }
                struct Player { name: String, age: u64, role: Role, stats: Stats, items: Vec<String>, scores: Vec<u64>, }
                storage { extra: Map<u64, u64>, names2: Map<u64, String>, tags2: Map<u64, Vec<String>>, matrix2: Map<u64, Vec<Vec<u64>>>, players: Map<u64, Player>, }
                pub fn store_player() {
                    // Many prior storage writes (high vreg count before Player creation)
                    self.extra[1] = 42;
                    self.names2[1] = "hello";
                    let mut t = Vec::new(); t.push("a"); t.push("b"); t.push("c"); self.tags2[1] = t;
                    let mut r1 = Vec::new(); r1.push(1); r1.push(2); r1.push(3);
                    let mut r2 = Vec::new(); r2.push(4); r2.push(5); r2.push(6);
                    let mut m = Vec::new(); m.push(r1); m.push(r2); self.matrix2[1] = m;
                    // NOW create packed Player with many fields
                    let stats = Stats { hp: 100, mp: 50, level: 5, xp: 9999 };
                    let mut items = Vec::new(); items.push("sword"); items.push("shield");
                    let mut scores = Vec::new(); scores.push(10); scores.push(20);
                    let p = Player { name: "bob", age: 25, role: Role::Admin, stats: stats, items: items, scores: scores };
                    self.players[1] = p;
                }
                pub fn get_hp() -> u64 { let p = self.players[1]; return p.stats.hp; }
                pub fn get_xp() -> u64 { let p = self.players[1]; return p.stats.xp; }
                pub fn get_age() -> u64 { let p = self.players[1]; return p.age; }
                pub fn get_score_sum() -> u64 {
                    let p = self.players[1];
                    let mut t=0; let mut i=0; let l=p.scores.len();
                    while i<l { t=t+p.scores[i]; i=i+1; }
                    return t;
                }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let contract = CodeGen::new().generate(&ir);
        let addr = [0xF1u8; 32];

        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = compute_selector("store_player").to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(
            out1.outcome,
            pyde_vm::vm::Outcome::Success,
            "store_player failed"
        );

        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        let run = |sel: &str| -> u64 {
            let ctx = pyde_vm::vm::ExecutionContext {
                self_address: addr,
                ..Default::default()
            };
            let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
            vm.calldata = compute_selector(sel).to_be_bytes().to_vec();
            let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
            vm.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
                let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
                unsafe { (*smt_ptr).get(&sk) }
            }));
            vm.load(&contract.runtime_bytecode).unwrap();
            let out = vm.execute();
            assert_eq!(out.outcome, pyde_vm::vm::Outcome::Success, "{} failed", sel);
            vm.cpu.read_gp(1)
        };

        assert_eq!(run("get_age"), 25, "age");
        assert_eq!(run("get_hp"), 100, "hp");
        assert_eq!(run("get_xp"), 9999, "xp");
        assert_eq!(run("get_score_sum"), 30, "scores 10+20");
    }

    #[test]
    fn hardening_u256_nonmap_storage() {
        let src = r#"
            contract T {
                storage { supply: u256, count: u64, }
                pub fn store_vals() {
                    self.supply = 1000000 as u256;
                    self.count = 7;
                }
                pub fn get_supply() -> u256 { return self.supply; }
                pub fn get_count() -> u64 { return self.count; }
            }
        "#;
        let (tokens, _) = crate::lexer::Lexer::new(src).tokenize();
        let (file, _) = crate::parser::Parser::new(tokens).parse();
        let mut ir = crate::lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let contract = CodeGen::new().generate(&ir);
        let addr = [0xF2u8; 32];

        let ctx = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm1 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
        vm1.calldata = compute_selector("store_vals").to_be_bytes().to_vec();
        vm1.load(&contract.runtime_bytecode).unwrap();
        let out1 = vm1.execute();
        assert_eq!(
            out1.outcome,
            pyde_vm::vm::Outcome::Success,
            "store_vals failed"
        );

        let mut smt = pyde_state::smt::PydeSMT::new();
        for (k, v) in &vm1.storage {
            let sk = sparse_merkle_tree::H256::from(k.to_le_bytes());
            let _ = smt.insert(sk, v.clone());
        }

        let run_gp = |sel: &str| -> u64 {
            let ctx = pyde_vm::vm::ExecutionContext {
                self_address: addr,
                ..Default::default()
            };
            let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx);
            vm.calldata = compute_selector(sel).to_be_bytes().to_vec();
            let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
            vm.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
                let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
                unsafe { (*smt_ptr).get(&sk) }
            }));
            vm.load(&contract.runtime_bytecode).unwrap();
            let out = vm.execute();
            assert_eq!(out.outcome, pyde_vm::vm::Outcome::Success, "{} failed", sel);
            vm.cpu.read_gp(1)
        };
        assert_eq!(run_gp("get_count"), 7, "count should be 7");

        let ctx2 = pyde_vm::vm::ExecutionContext {
            self_address: addr,
            ..Default::default()
        };
        let mut vm2 = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx2);
        vm2.calldata = compute_selector("get_supply").to_be_bytes().to_vec();
        let smt_ptr = &smt as *const pyde_state::smt::PydeSMT;
        vm2.storage_backend = Some(std::sync::Arc::new(move |key: &ethnum::U256| {
            let sk = sparse_merkle_tree::H256::from(key.to_le_bytes());
            unsafe { (*smt_ptr).get(&sk) }
        }));
        vm2.load(&contract.runtime_bytecode).unwrap();
        let out2 = vm2.execute();
        assert_eq!(
            out2.outcome,
            pyde_vm::vm::Outcome::Success,
            "get_supply failed"
        );
        assert_eq!(
            vm2.cpu.read_wide(0),
            ethnum::U256::from(1_000_000u64),
            "supply should be 1000000"
        );
    }
}
