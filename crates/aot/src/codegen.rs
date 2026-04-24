//! Cranelift code generation for PVM bytecode.
//!
//! Translates analyzed basic blocks into native machine code. Pure computation
//! (ALU, branches) is compiled to native instructions. VM state operations
//! (memory, storage, crypto, events) call back into host functions via an
//! opaque VM context pointer.

use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::types::I64;
use cranelift_codegen::ir::{AbiParam, InstBuilder, MemFlags, UserFuncName};
use cranelift_codegen::settings::{self, Configurable};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{Linkage, Module};

use pyde_vm::isa::{sign_extend_18, Opcode};

use crate::analysis::AnalyzedProgram;
use crate::host;

#[derive(Debug)]
pub enum CodegenError {
    CompilationFailed(String),
}

impl std::fmt::Display for CodegenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodegenError::CompilationFailed(msg) => write!(f, "codegen failed: {msg}"),
        }
    }
}

impl std::error::Error for CodegenError {}

/// Compiled native code.
pub struct CompiledCode {
    _module: JITModule,
    code_ptr: *const u8,
    pub bytecode_hash: [u8; 32],
    pub block_count: usize,
    pub instruction_count: usize,
}

// SAFETY: `CompiledCode` owns an immutable `*const u8` pointer into
// a `JITModule`-managed memory region (`_module`). The region lives as
// long as `_module` does, and `JITModule` itself is `Send + Sync` in
// its relevant operations. The pointer is only ever dereferenced through
// the fn-pointer transmutes below, which do not themselves mutate the
// struct. Treating `CompiledCode` as shareable across threads is sound
// as long as callers don't invoke `as_fn`/`as_fn_no_ctx` with aliasing
// mutable state — the AOT host ABI takes `*mut u64` / `*mut VmCtx` per
// call site, so each caller provides its own scratch registers and VM.
unsafe impl Send for CompiledCode {}
unsafe impl Sync for CompiledCode {}

pub const RESULT_SUCCESS: u64 = 0;
pub const RESULT_REVERT: u64 = 1;
pub const RESULT_OUT_OF_GAS: u64 = 2;
pub const RESULT_TRAP: u64 = u64::MAX;

impl CompiledCode {
    /// Signature: `fn(gp_regs: *mut u64, gas_limit: u64, vm_ctx: *mut Vm) -> u64`
    ///
    /// Returns: `(gas_used << 2) | status`
    pub fn as_fn(&self) -> unsafe fn(*mut u64, u64, *mut host::VmCtx) -> u64 {
        // SAFETY: `code_ptr` points at the entry block emitted by
        // Cranelift's `compile(...)` in this module. The entry block's
        // ABI (three params, u64 return) is fixed by
        // `finalize_function_signature` / `entry_block`; matches this
        // function-pointer type. Memory is kept alive by `_module`.
        unsafe { std::mem::transmute(self.code_ptr) }
    }

    /// Convenience: run without VM context (ALU-only programs).
    pub fn as_fn_no_ctx(&self) -> unsafe fn(*mut u64, u64) -> u64 {
        // SAFETY: same region as `as_fn`. Callers pass `null` / unused
        // `VmCtx` so the 2-argument signature works via argument
        // truncation on every supported ABI. Only legitimate for
        // ALU-only programs per the doc comment.
        unsafe { std::mem::transmute(self.code_ptr) }
    }
}

// Variable assignments
const VAR_GAS_USED: u32 = 16;
const VAR_GAS_LIMIT: u32 = 17;
const VAR_REGS_PTR: u32 = 18;
const VAR_VM_CTX: u32 = 19;

/// Compile an analyzed program to native code.
pub fn compile(program: &AnalyzedProgram) -> Result<CompiledCode, CodegenError> {
    let mut flag_builder = settings::builder();
    flag_builder
        .set("opt_level", "speed")
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let isa_builder =
        cranelift_native::builder().map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let isa = isa_builder
        .finish(settings::Flags::new(flag_builder))
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // Register host functions with JIT
    let mut jit_builder = JITBuilder::with_isa(isa, cranelift_module::default_libcall_names());
    for (name, ptr) in host::host_functions() {
        jit_builder.symbol(name, ptr);
    }
    let mut module = JITModule::new(jit_builder);

    let ptr_type = module.target_config().pointer_type();

    // Main function: fn(regs: *mut u64, gas_limit: u64, vm_ctx: *mut Vm) -> u64
    let mut sig = module.make_signature();
    sig.params.push(AbiParam::new(ptr_type)); // gp_regs
    sig.params.push(AbiParam::new(I64)); // gas_limit
    sig.params.push(AbiParam::new(ptr_type)); // vm_ctx
    sig.returns.push(AbiParam::new(I64)); // result

    let func_id = module
        .declare_function("pvm_aot_entry", Linkage::Export, &sig)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // Declare host function signatures in the module
    // host_load(ctx, addr, width) -> u64
    let mut sig_load = module.make_signature();
    sig_load.params.push(AbiParam::new(ptr_type));
    sig_load.params.push(AbiParam::new(I64));
    sig_load.params.push(AbiParam::new(I64));
    sig_load.returns.push(AbiParam::new(I64));
    let fn_load = module
        .declare_function("host_load", Linkage::Import, &sig_load)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_store(ctx, addr, value, width) -> u64
    let mut sig_store = module.make_signature();
    sig_store.params.push(AbiParam::new(ptr_type));
    sig_store.params.push(AbiParam::new(I64));
    sig_store.params.push(AbiParam::new(I64));
    sig_store.params.push(AbiParam::new(I64));
    sig_store.returns.push(AbiParam::new(I64));
    let fn_store = module
        .declare_function("host_store", Linkage::Import, &sig_store)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_sload(ctx, ws_slot, wd) -> u64
    let mut sig_sload = module.make_signature();
    sig_sload.params.push(AbiParam::new(ptr_type));
    sig_sload.params.push(AbiParam::new(I64));
    sig_sload.params.push(AbiParam::new(I64));
    sig_sload.returns.push(AbiParam::new(I64));
    let fn_sload = module
        .declare_function("host_sload", Linkage::Import, &sig_sload)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_sstore(ctx, ws_slot, wd) -> u64
    let fn_sstore = module
        .declare_function("host_sstore", Linkage::Import, &sig_sload)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_sstoreg(ctx, ws_slot, value) -> u64 (same signature as sload: ctx + 2 args)
    let fn_sstoreg = module
        .declare_function("host_sstoreg", Linkage::Import, &sig_sload)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_sdelete(ctx, ws_slot) -> u64 / host_sloadg(ctx, ws_slot) -> u64
    let mut sig_sdel = module.make_signature();
    sig_sdel.params.push(AbiParam::new(ptr_type));
    sig_sdel.params.push(AbiParam::new(I64));
    sig_sdel.returns.push(AbiParam::new(I64));
    let fn_sdelete = module
        .declare_function("host_sdelete", Linkage::Import, &sig_sdel)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_sloadg(ctx, ws_slot) -> u64 (same signature as sdelete)
    let fn_sloadg = module
        .declare_function("host_sloadg", Linkage::Import, &sig_sdel)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_sloadb(ctx, ws_slot, ptr, rd_idx) -> u64 (4 i64 args + ptr) and
    // host_sstoreb(ctx, ws_slot, ptr, len) -> u64 — both share `sig_store`'s
    // (ptr_type, I64, I64, I64) -> I64 shape (audit 228d).
    let fn_sloadb = module
        .declare_function("host_sloadb", Linkage::Import, &sig_store)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_sstoreb = module
        .declare_function("host_sstoreb", Linkage::Import, &sig_store)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_log(ctx, desc_ptr, num_topics) -> u64
    let fn_log = module
        .declare_function("host_log", Linkage::Import, &sig_sload)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_poseidon(ctx, addr, len, wd) -> u64
    let mut sig_pos = module.make_signature();
    sig_pos.params.push(AbiParam::new(ptr_type));
    sig_pos.params.push(AbiParam::new(I64));
    sig_pos.params.push(AbiParam::new(I64));
    sig_pos.params.push(AbiParam::new(I64));
    sig_pos.returns.push(AbiParam::new(I64));
    let fn_poseidon = module
        .declare_function("host_poseidon", Linkage::Import, &sig_pos)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    let mut ctx = module.make_context();
    ctx.func.signature = sig;
    ctx.func.name = UserFuncName::user(0, 0);

    // host_push(ctx, value) -> u64
    let mut sig_push = module.make_signature();
    sig_push.params.push(AbiParam::new(ptr_type));
    sig_push.params.push(AbiParam::new(I64));
    sig_push.returns.push(AbiParam::new(I64));
    let fn_push = module
        .declare_function("host_push", Linkage::Import, &sig_push)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_pop(ctx) -> u64
    let mut sig_pop = module.make_signature();
    sig_pop.params.push(AbiParam::new(ptr_type));
    sig_pop.returns.push(AbiParam::new(I64));
    let fn_pop = module
        .declare_function("host_pop", Linkage::Import, &sig_pop)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // Environment host functions: (ctx) -> u64
    // host_caller(ctx, wd) -> u64, host_address(ctx, wd) -> u64
    let fn_caller = module
        .declare_function("host_caller", Linkage::Import, &sig_sdel)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_address = module
        .declare_function("host_address", Linkage::Import, &sig_sdel)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_block_number = module
        .declare_function("host_block_number", Linkage::Import, &sig_pop)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_timestamp = module
        .declare_function("host_timestamp", Linkage::Import, &sig_pop)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_gas_remaining = module
        .declare_function("host_gas_remaining", Linkage::Import, &sig_pop)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    // (ctx, wd) -> u64
    let fn_callvalue = module
        .declare_function("host_callvalue", Linkage::Import, &sig_sdel)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_gasprice = module
        .declare_function("host_gasprice", Linkage::Import, &sig_sdel)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    // (ctx, addr, wd) -> u64
    let fn_balance = module
        .declare_function("host_balance", Linkage::Import, &sig_sload)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    // (ctx, val) -> u64
    let fn_assert = module
        .declare_function("host_assert", Linkage::Import, &sig_sdel)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    // (ctx, a, b) -> u64
    let fn_memcpy = module
        .declare_function("host_memcpy", Linkage::Import, &sig_store)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // (ctx) -> u64 — returns vm.memory.page_gas_used, resets to 0.
    // Folded into VAR_GAS_USED after every memory-touching op so AOT
    // stays in gas lockstep with the interpreter (audit item 228a).
    let fn_drain_page_gas = module
        .declare_function("host_drain_page_gas", Linkage::Import, &sig_pop)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_wload(ctx, addr, wd) -> u64
    let fn_wload = module
        .declare_function("host_wload", Linkage::Import, &sig_sload)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_wstore(ctx, addr, ws) -> u64
    let fn_wstore = module
        .declare_function("host_wstore", Linkage::Import, &sig_sload)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_wide_alu(ctx, opcode, wd, ws1, ws2) -> u64
    let mut sig_wide = module.make_signature();
    sig_wide.params.push(AbiParam::new(ptr_type));
    sig_wide.params.push(AbiParam::new(I64));
    sig_wide.params.push(AbiParam::new(I64));
    sig_wide.params.push(AbiParam::new(I64));
    sig_wide.params.push(AbiParam::new(I64));
    sig_wide.returns.push(AbiParam::new(I64));
    let fn_wide_alu = module
        .declare_function("host_wide_alu", Linkage::Import, &sig_wide)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_exec_opcode(ctx, opcode, rd, rs1, imm, gas_used_in, gas_limit_in)
    // -> packed u64 where: low 2 bits = result (0=ok, 1=trap, 2=halt/revert),
    // high 62 bits = gas_used_out. Audit 228b: delegated ops must sync
    // AOT's VAR_GAS_USED with vm.gas_used_total across the call, otherwise
    // gas charged by step() inside the delegated execution is invisible
    // to AOT and validators fork on any contract using CallExt / Delegate
    // / Create / VerifySig / MerkleVerify.
    let mut sig_exec_opcode = module.make_signature();
    sig_exec_opcode.params.push(AbiParam::new(ptr_type)); // ctx
    sig_exec_opcode.params.push(AbiParam::new(I64)); // opcode
    sig_exec_opcode.params.push(AbiParam::new(I64)); // rd
    sig_exec_opcode.params.push(AbiParam::new(I64)); // rs1
    sig_exec_opcode.params.push(AbiParam::new(I64)); // imm
    sig_exec_opcode.params.push(AbiParam::new(I64)); // gas_used_in
    sig_exec_opcode.params.push(AbiParam::new(I64)); // gas_limit_in
    sig_exec_opcode.returns.push(AbiParam::new(I64)); // packed
    let fn_exec_opcode = module
        .declare_function("host_exec_opcode", Linkage::Import, &sig_exec_opcode)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_sync_gp_to_vm(ctx, regs_ptr) — copy external regs to vm.cpu.gp
    // host_sync_gp_from_vm(ctx, regs_ptr) — copy vm.cpu.gp to external regs
    let mut sig_sync_gp = module.make_signature();
    sig_sync_gp.params.push(AbiParam::new(ptr_type));
    sig_sync_gp.params.push(AbiParam::new(ptr_type));
    let fn_sync_gp_to_vm = module
        .declare_function("host_sync_gp_to_vm", Linkage::Import, &sig_sync_gp)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_sync_gp_from_vm = module
        .declare_function("host_sync_gp_from_vm", Linkage::Import, &sig_sync_gp)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_read_gp(ctx, reg_idx) -> u64 (reads GP register from VM)
    let mut sig_read_gp = module.make_signature();
    sig_read_gp.params.push(AbiParam::new(ptr_type));
    sig_read_gp.params.push(AbiParam::new(I64));
    sig_read_gp.returns.push(AbiParam::new(I64));
    let fn_read_gp = module
        .declare_function("host_read_gp", Linkage::Import, &sig_read_gp)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_narrow(ctx, ws1, trap_out) -> u64 (returns narrowed value)
    let mut sig_narrow = module.make_signature();
    sig_narrow.params.push(AbiParam::new(ptr_type));
    sig_narrow.params.push(AbiParam::new(I64));
    sig_narrow.params.push(AbiParam::new(ptr_type)); // trap_out pointer
    sig_narrow.returns.push(AbiParam::new(I64));
    let fn_narrow = module
        .declare_function("host_narrow", Linkage::Import, &sig_narrow)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_widen(ctx, wd, gp_value) -> u64
    let fn_widen = module
        .declare_function("host_widen", Linkage::Import, &sig_sload)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_checked_add/sub/mul(a, b, trap_out) -> u64
    let mut sig_checked = module.make_signature();
    sig_checked.params.push(AbiParam::new(I64));
    sig_checked.params.push(AbiParam::new(I64));
    sig_checked.params.push(AbiParam::new(ptr_type));
    sig_checked.returns.push(AbiParam::new(I64));
    let fn_checked_add = module
        .declare_function("host_checked_add", Linkage::Import, &sig_checked)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_checked_sub = module
        .declare_function("host_checked_sub", Linkage::Import, &sig_checked)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_checked_mul = module
        .declare_function("host_checked_mul", Linkage::Import, &sig_checked)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_checked_div = module
        .declare_function("host_checked_div", Linkage::Import, &sig_checked)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_checked_mod = module
        .declare_function("host_checked_mod", Linkage::Import, &sig_checked)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // Import host function references for use inside the function
    let fn_load_ref = module.declare_func_in_func(fn_load, &mut ctx.func);
    let fn_store_ref = module.declare_func_in_func(fn_store, &mut ctx.func);
    let fn_sload_ref = module.declare_func_in_func(fn_sload, &mut ctx.func);
    let fn_sstore_ref = module.declare_func_in_func(fn_sstore, &mut ctx.func);
    let fn_sstoreg_ref = module.declare_func_in_func(fn_sstoreg, &mut ctx.func);
    let fn_sdelete_ref = module.declare_func_in_func(fn_sdelete, &mut ctx.func);
    let fn_sloadb_ref = module.declare_func_in_func(fn_sloadb, &mut ctx.func);
    let fn_sstoreb_ref = module.declare_func_in_func(fn_sstoreb, &mut ctx.func);
    let fn_sloadg_ref = module.declare_func_in_func(fn_sloadg, &mut ctx.func);
    let fn_log_ref = module.declare_func_in_func(fn_log, &mut ctx.func);
    let fn_exec_opcode_ref = module.declare_func_in_func(fn_exec_opcode, &mut ctx.func);
    let fn_poseidon_ref = module.declare_func_in_func(fn_poseidon, &mut ctx.func);
    let fn_push_ref = module.declare_func_in_func(fn_push, &mut ctx.func);
    let fn_pop_ref = module.declare_func_in_func(fn_pop, &mut ctx.func);
    let fn_wload_ref = module.declare_func_in_func(fn_wload, &mut ctx.func);
    let fn_wstore_ref = module.declare_func_in_func(fn_wstore, &mut ctx.func);
    let fn_wide_alu_ref = module.declare_func_in_func(fn_wide_alu, &mut ctx.func);
    let fn_read_gp_ref = module.declare_func_in_func(fn_read_gp, &mut ctx.func);
    let fn_narrow_ref = module.declare_func_in_func(fn_narrow, &mut ctx.func);
    let fn_widen_ref = module.declare_func_in_func(fn_widen, &mut ctx.func);
    let fn_checked_add_ref = module.declare_func_in_func(fn_checked_add, &mut ctx.func);
    let fn_checked_sub_ref = module.declare_func_in_func(fn_checked_sub, &mut ctx.func);
    let fn_checked_mul_ref = module.declare_func_in_func(fn_checked_mul, &mut ctx.func);
    let fn_checked_div_ref = module.declare_func_in_func(fn_checked_div, &mut ctx.func);
    let fn_checked_mod_ref = module.declare_func_in_func(fn_checked_mod, &mut ctx.func);
    let fn_caller_ref = module.declare_func_in_func(fn_caller, &mut ctx.func);
    let fn_address_ref = module.declare_func_in_func(fn_address, &mut ctx.func);
    let fn_block_number_ref = module.declare_func_in_func(fn_block_number, &mut ctx.func);
    let fn_timestamp_ref = module.declare_func_in_func(fn_timestamp, &mut ctx.func);
    let fn_gas_remaining_ref = module.declare_func_in_func(fn_gas_remaining, &mut ctx.func);
    let fn_callvalue_ref = module.declare_func_in_func(fn_callvalue, &mut ctx.func);
    let fn_gasprice_ref = module.declare_func_in_func(fn_gasprice, &mut ctx.func);
    let fn_balance_ref = module.declare_func_in_func(fn_balance, &mut ctx.func);
    let fn_assert_ref = module.declare_func_in_func(fn_assert, &mut ctx.func);
    let fn_memcpy_ref = module.declare_func_in_func(fn_memcpy, &mut ctx.func);
    let fn_drain_page_gas_ref = module.declare_func_in_func(fn_drain_page_gas, &mut ctx.func);
    let fn_sync_gp_to_vm_ref = module.declare_func_in_func(fn_sync_gp_to_vm, &mut ctx.func);
    let fn_sync_gp_from_vm_ref = module.declare_func_in_func(fn_sync_gp_from_vm, &mut ctx.func);

    {
        let mut fn_builder_ctx = FunctionBuilderContext::new();
        let mut builder = FunctionBuilder::new(&mut ctx.func, &mut fn_builder_ctx);

        // GP registers r0-r15 accessed via regs_ptr memory (no Cranelift variables).
        // Only declare non-GP variables.
        builder.declare_var(Variable::from_u32(VAR_GAS_USED), I64);
        builder.declare_var(Variable::from_u32(VAR_GAS_LIMIT), I64);
        builder.declare_var(Variable::from_u32(VAR_REGS_PTR), ptr_type);
        builder.declare_var(Variable::from_u32(VAR_VM_CTX), ptr_type);

        // Stack-allocated trap flag for checked arithmetic (address passed to host fns)
        let trap_flag_ss =
            builder.create_sized_stack_slot(cranelift_codegen::ir::StackSlotData::new(
                cranelift_codegen::ir::StackSlotKind::ExplicitSlot,
                8,
                0,
            ));

        let entry_block = builder.create_block();
        builder.append_block_params_for_function_params(entry_block);

        let oog_block = builder.create_block();
        let success_block = builder.create_block();
        let revert_block = builder.create_block();
        let trap_block = builder.create_block();

        let mut pc_to_block = std::collections::HashMap::new();
        let mut cl_blocks = Vec::new();
        for bb in &program.blocks {
            let cl_block = builder.create_block();
            pc_to_block.insert(bb.start_pc, cl_block);
            cl_blocks.push(cl_block);
        }

        // === Entry ===
        builder.switch_to_block(entry_block);
        builder.seal_block(entry_block);

        let param_regs_ptr = builder.block_params(entry_block)[0];
        let param_gas_limit = builder.block_params(entry_block)[1];
        let param_vm_ctx = builder.block_params(entry_block)[2];

        builder.def_var(Variable::from_u32(VAR_REGS_PTR), param_regs_ptr);
        builder.def_var(Variable::from_u32(VAR_GAS_LIMIT), param_gas_limit);
        builder.def_var(Variable::from_u32(VAR_VM_CTX), param_vm_ctx);

        let zero = builder.ins().iconst(I64, 0);
        builder.def_var(Variable::from_u32(VAR_GAS_USED), zero);

        // GP registers r0-r15 are accessed DIRECTLY through regs_ptr (vm.cpu.gp).
        // No Cranelift local variables for GP — all reads/writes go through memory.
        // This eliminates ALL desync between AOT and host functions.
        // The 128-byte register array stays in L1 cache (1-2 cycle access).
        // We still declare variables 0-15 but only use them as temporaries.

        if let Some(&first) = cl_blocks.first() {
            builder.ins().jump(first, &[]);
        } else {
            builder.ins().jump(success_block, &[]);
        }

        // === Basic blocks ===
        for (bb_idx, bb) in program.blocks.iter().enumerate() {
            let cl_block = cl_blocks[bb_idx];
            builder.switch_to_block(cl_block);

            // Gas check
            if bb.gas_cost > 0 {
                let gas_used = builder.use_var(Variable::from_u32(VAR_GAS_USED));
                let cost = builder.ins().iconst(I64, bb.gas_cost as i64);
                let new_gas = builder.ins().iadd(gas_used, cost);
                builder.def_var(Variable::from_u32(VAR_GAS_USED), new_gas);

                let gas_limit = builder.use_var(Variable::from_u32(VAR_GAS_LIMIT));
                let limit_nonzero = builder.ins().icmp_imm(IntCC::NotEqual, gas_limit, 0);
                let over = builder
                    .ins()
                    .icmp(IntCC::UnsignedGreaterThan, new_gas, gas_limit);
                let oog = builder.ins().band(limit_nonzero, over);

                let cont = builder.create_block();
                builder.ins().brif(oog, oog_block, &[], cont, &[]);
                builder.seal_block(cont);
                builder.switch_to_block(cont);
            }

            let mut terminated = false;

            // Helper macro: emit checked arith via host call, trap on overflow
            macro_rules! emit_checked_op {
                ($builder:expr, $fn_ref:expr, $d:expr, $trap_flag_ss:expr, $trap_block:expr) => {{
                    let a = gp_read!($builder, $d.rs1);
                    let b = gp_read!($builder, ($d.rs2_or_imm & 0xF) as u8);
                    let z = $builder.ins().iconst(I64, 0);
                    $builder.ins().stack_store(z, $trap_flag_ss, 0);
                    let trap_ptr = $builder.ins().stack_addr(ptr_type, $trap_flag_ss, 0);
                    let call = $builder.ins().call($fn_ref, &[a, b, trap_ptr]);
                    let result = $builder.inst_results(call)[0];
                    gp_write!($builder, $d.rd, result);
                    let flag = $builder.ins().stack_load(I64, $trap_flag_ss, 0);
                    let trapped = $builder.ins().icmp_imm(IntCC::NotEqual, flag, 0);
                    let cont = $builder.create_block();
                    $builder.ins().brif(trapped, $trap_block, &[], cont, &[]);
                    $builder.seal_block(cont);
                    $builder.switch_to_block(cont);
                }};
            }

            // Helper macro: drain vm.memory.page_gas_used into
            // VAR_GAS_USED, then run the same OOG check the block
            // prologue uses. Call after every AOT-emitted op whose
            // host implementation can bump `page_gas_used` through
            // `check_access` (Load/Store/Wload/Wstore/Push/Pop/
            // Poseidon/Memcpy). The interpreter drains after every
            // step; AOT has to do it here per op, otherwise AOT
            // and interp disagree on gas_used and the chain forks
            // on any contract with non-trivial memory access
            // (audit item 228a).
            macro_rules! emit_drain_page_gas {
                ($builder:expr) => {{
                    let vm_ctx = $builder.use_var(Variable::from_u32(VAR_VM_CTX));
                    let call = $builder.ins().call(fn_drain_page_gas_ref, &[vm_ctx]);
                    let drained = $builder.inst_results(call)[0];
                    let gas_used = $builder.use_var(Variable::from_u32(VAR_GAS_USED));
                    let new_gas = $builder.ins().iadd(gas_used, drained);
                    $builder.def_var(Variable::from_u32(VAR_GAS_USED), new_gas);
                    let gas_limit = $builder.use_var(Variable::from_u32(VAR_GAS_LIMIT));
                    let limit_nonzero = $builder.ins().icmp_imm(IntCC::NotEqual, gas_limit, 0);
                    let over = $builder
                        .ins()
                        .icmp(IntCC::UnsignedGreaterThan, new_gas, gas_limit);
                    let oog = $builder.ins().band(limit_nonzero, over);
                    let cont = $builder.create_block();
                    $builder.ins().brif(oog, oog_block, &[], cont, &[]);
                    $builder.seal_block(cont);
                    $builder.switch_to_block(cont);
                }};
            }

            // GP register access: always through regs_ptr (vm.cpu.gp memory).
            // No Cranelift variables for GP — eliminates ALL desync with host functions.
            macro_rules! gp_read {
                ($builder:expr, $reg:expr) => {{
                    if $reg == 0 {
                        $builder.ins().iconst(I64, 0) // r0 always zero
                    } else {
                        let rp = $builder.use_var(Variable::from_u32(VAR_REGS_PTR));
                        $builder
                            .ins()
                            .load(I64, MemFlags::trusted(), rp, ($reg as i32) * 8)
                    }
                }};
            }
            macro_rules! gp_write {
                ($builder:expr, $reg:expr, $val:expr) => {{
                    if $reg != 0 {
                        let rp = $builder.use_var(Variable::from_u32(VAR_REGS_PTR));
                        $builder
                            .ins()
                            .store(MemFlags::trusted(), $val, rp, ($reg as i32) * 8);
                    }
                }};
            }

            for (i, d) in bb.instructions.iter().enumerate() {
                match d.opcode {
                    // --- Checked arithmetic (host calls for overflow detection) ---
                    Opcode::Add => {
                        emit_checked_op!(builder, fn_checked_add_ref, d, trap_flag_ss, trap_block);
                    }
                    Opcode::Sub => {
                        emit_checked_op!(builder, fn_checked_sub_ref, d, trap_flag_ss, trap_block);
                    }
                    Opcode::Mul => {
                        emit_checked_op!(builder, fn_checked_mul_ref, d, trap_flag_ss, trap_block);
                    }
                    Opcode::Div => {
                        emit_checked_op!(builder, fn_checked_div_ref, d, trap_flag_ss, trap_block);
                    }
                    Opcode::Mod => {
                        emit_checked_op!(builder, fn_checked_mod_ref, d, trap_flag_ss, trap_block);
                    }
                    Opcode::Addi => {
                        let a = gp_read!(builder, d.rs1);
                        let imm = sign_extend_18(d.rs2_or_imm) as i64;
                        let b = builder.ins().iconst(I64, imm);
                        // Addi wraps on overflow by design — the otic
                        // compiler relies on this for constant materialisation
                        // (e.g. `Addi rd, r0, -2` → u64::MAX-1 for the
                        // reentrancy-guard slot) and for two's-complement
                        // negation (`Not rd; Addi rd, rd, 1` → -a). Changing
                        // to checked_add would break otic codegen and
                        // every contract's stack-frame setup. Divergence
                        // between AOT and interpreter is guarded by
                        // `addi_aot_interp_wrap_parity` in tests.
                        let r = builder.ins().iadd(a, b);
                        gp_write!(builder, d.rd, r);
                    }

                    // --- Bitwise & shifts (no overflow possible) ---
                    Opcode::And => {
                        let a = gp_read!(builder, d.rs1);
                        let b = gp_read!(builder, (d.rs2_or_imm & 0xF) as u8);
                        let r = builder.ins().band(a, b);
                        gp_write!(builder, d.rd, r);
                    }
                    Opcode::Or => {
                        let a = gp_read!(builder, d.rs1);
                        let b = gp_read!(builder, (d.rs2_or_imm & 0xF) as u8);
                        let r = builder.ins().bor(a, b);
                        gp_write!(builder, d.rd, r);
                    }
                    Opcode::Xor => {
                        let a = gp_read!(builder, d.rs1);
                        let b = gp_read!(builder, (d.rs2_or_imm & 0xF) as u8);
                        let r = builder.ins().bxor(a, b);
                        gp_write!(builder, d.rd, r);
                    }
                    Opcode::Not => {
                        let a = gp_read!(builder, d.rs1);
                        let r = builder.ins().bnot(a);
                        gp_write!(builder, d.rd, r);
                    }
                    Opcode::Shl => {
                        let a = gp_read!(builder, d.rs1);
                        let b = gp_read!(builder, (d.rs2_or_imm & 0xF) as u8);
                        let r = builder.ins().ishl(a, b);
                        gp_write!(builder, d.rd, r);
                    }
                    Opcode::Shr => {
                        let a = gp_read!(builder, d.rs1);
                        let b = gp_read!(builder, (d.rs2_or_imm & 0xF) as u8);
                        let r = builder.ins().ushr(a, b);
                        gp_write!(builder, d.rd, r);
                    }
                    Opcode::Sar => {
                        let a = gp_read!(builder, d.rs1);
                        let b = gp_read!(builder, (d.rs2_or_imm & 0xF) as u8);
                        let r = builder.ins().sshr(a, b);
                        gp_write!(builder, d.rd, r);
                    }

                    // --- Comparisons ---
                    Opcode::Lt => {
                        let a = gp_read!(builder, d.rs1);
                        let b = gp_read!(builder, (d.rs2_or_imm & 0xF) as u8);
                        let cmp = builder.ins().icmp(IntCC::UnsignedLessThan, a, b);
                        let r = builder.ins().uextend(I64, cmp);
                        gp_write!(builder, d.rd, r);
                    }
                    Opcode::Gt => {
                        let a = gp_read!(builder, d.rs1);
                        let b = gp_read!(builder, (d.rs2_or_imm & 0xF) as u8);
                        let cmp = builder.ins().icmp(IntCC::UnsignedGreaterThan, a, b);
                        let r = builder.ins().uextend(I64, cmp);
                        gp_write!(builder, d.rd, r);
                    }
                    Opcode::Eq => {
                        let a = gp_read!(builder, d.rs1);
                        let b = gp_read!(builder, (d.rs2_or_imm & 0xF) as u8);
                        let cmp = builder.ins().icmp(IntCC::Equal, a, b);
                        let r = builder.ins().uextend(I64, cmp);
                        gp_write!(builder, d.rd, r);
                    }
                    Opcode::Slt => {
                        let a = gp_read!(builder, d.rs1);
                        let b = gp_read!(builder, (d.rs2_or_imm & 0xF) as u8);
                        let cmp = builder.ins().icmp(IntCC::SignedLessThan, a, b);
                        let r = builder.ins().uextend(I64, cmp);
                        gp_write!(builder, d.rd, r);
                    }
                    Opcode::Sgt => {
                        let a = gp_read!(builder, d.rs1);
                        let b = gp_read!(builder, (d.rs2_or_imm & 0xF) as u8);
                        let cmp = builder.ins().icmp(IntCC::SignedGreaterThan, a, b);
                        let r = builder.ins().uextend(I64, cmp);
                        gp_write!(builder, d.rd, r);
                    }

                    // --- Push/Pop (host calls) ---
                    Opcode::Push => {
                        let val = gp_read!(builder, d.rd);
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let call = builder.ins().call(fn_push_ref, &[vm_ctx, val]);
                        let result = builder.inst_results(call)[0];
                        emit_drain_page_gas!(builder);
                        let is_err = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(is_err, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                    }
                    Opcode::Pop => {
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let call = builder.ins().call(fn_pop_ref, &[vm_ctx]);
                        let result = builder.inst_results(call)[0];
                        emit_drain_page_gas!(builder);
                        // Check for fault (u64::MAX)
                        let is_err = builder.ins().icmp_imm(IntCC::Equal, result, -1i64);
                        let cont = builder.create_block();
                        builder.ins().brif(is_err, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                        gp_write!(builder, d.rd, result);
                    }

                    // --- Wide register ops (host calls) ---
                    // Pure wide-to-wide: no GP interaction
                    Opcode::Wadd
                    | Opcode::Wsub
                    | Opcode::Wmul
                    | Opcode::Wdiv
                    | Opcode::Wmod
                    | Opcode::Wand
                    | Opcode::Wor
                    | Opcode::Wxor
                    | Opcode::Wnot
                    | Opcode::Wmov => {
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let op = builder.ins().iconst(I64, d.opcode.to_u8() as i64);
                        let wd = builder.ins().iconst(I64, d.rd as i64);
                        let ws1 = builder.ins().iconst(I64, d.rs1 as i64);
                        let ws2 = builder.ins().iconst(I64, (d.rs2_or_imm & 0xF) as i64);
                        let call = builder
                            .ins()
                            .call(fn_wide_alu_ref, &[vm_ctx, op, wd, ws1, ws2]);
                        let result = builder.inst_results(call)[0];
                        let trapped = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(trapped, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                    }
                    // Wide comparisons: result written to GP register rd
                    Opcode::Weq | Opcode::Wlt => {
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let _regs_ptr_val = builder.use_var(Variable::from_u32(VAR_REGS_PTR));
                        let op = builder.ins().iconst(I64, d.opcode.to_u8() as i64);
                        let wd = builder.ins().iconst(I64, d.rd as i64);
                        let ws1 = builder.ins().iconst(I64, d.rs1 as i64);
                        let ws2 = builder.ins().iconst(I64, (d.rs2_or_imm & 0xF) as i64);
                        let call = builder
                            .ins()
                            .call(fn_wide_alu_ref, &[vm_ctx, op, wd, ws1, ws2]);
                        let result = builder.inst_results(call)[0];
                        let trapped = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(trapped, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                        // Read back GP result: Weq/Wlt write comparison to vm.cpu.gp[rd]
                        let rd_idx = builder.ins().iconst(I64, d.rd as i64);
                        let gp_call = builder.ins().call(fn_read_gp_ref, &[vm_ctx, rd_idx]);
                        let gp_val = builder.inst_results(gp_call)[0];
                        gp_write!(builder, d.rd, gp_val);
                    }
                    // Wide shift: reads shift amount from GP register
                    Opcode::Wshift => {
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let regs_ptr_val = builder.use_var(Variable::from_u32(VAR_REGS_PTR));
                        // Sync GP to VM (Wshift reads shift amount from a GP register)
                        builder
                            .ins()
                            .call(fn_sync_gp_to_vm_ref, &[vm_ctx, regs_ptr_val]);
                        let op = builder.ins().iconst(I64, d.opcode.to_u8() as i64);
                        let wd = builder.ins().iconst(I64, d.rd as i64);
                        let ws1 = builder.ins().iconst(I64, d.rs1 as i64);
                        // Pass full imm (direction bit + shift reg index), not truncated
                        let imm = builder.ins().iconst(I64, d.rs2_or_imm as i64);
                        let call = builder
                            .ins()
                            .call(fn_wide_alu_ref, &[vm_ctx, op, wd, ws1, imm]);
                        let result = builder.inst_results(call)[0];
                        let trapped = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(trapped, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                    }
                    Opcode::Wload => {
                        let base = gp_read!(builder, d.rs1);
                        let offset = sign_extend_18(d.rs2_or_imm) as i64;
                        let off_val = builder.ins().iconst(I64, offset);
                        let addr = builder.ins().iadd(base, off_val);
                        let wd = builder.ins().iconst(I64, d.rd as i64);
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let call = builder.ins().call(fn_wload_ref, &[vm_ctx, addr, wd]);
                        let result = builder.inst_results(call)[0];
                        emit_drain_page_gas!(builder);
                        let is_err = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(is_err, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                    }
                    Opcode::Wstore => {
                        let base = gp_read!(builder, d.rs1);
                        let offset = sign_extend_18(d.rs2_or_imm) as i64;
                        let off_val = builder.ins().iconst(I64, offset);
                        let addr = builder.ins().iadd(base, off_val);
                        let ws = builder.ins().iconst(I64, d.rd as i64);
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let call = builder.ins().call(fn_wstore_ref, &[vm_ctx, addr, ws]);
                        let result = builder.inst_results(call)[0];
                        emit_drain_page_gas!(builder);
                        let is_err = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(is_err, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                    }
                    Opcode::Narrow => {
                        // host_narrow(ctx, ws1, trap_out) -> u64 (the narrowed value)
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let ws1 = builder.ins().iconst(I64, d.rs1 as i64);
                        // Zero trap flag, get pointer
                        let z = builder.ins().iconst(I64, 0);
                        builder.ins().stack_store(z, trap_flag_ss, 0);
                        let trap_ptr = builder.ins().stack_addr(ptr_type, trap_flag_ss, 0);
                        let call = builder.ins().call(fn_narrow_ref, &[vm_ctx, ws1, trap_ptr]);
                        let narrowed_val = builder.inst_results(call)[0];
                        // Update the AOT GP variable with the result
                        gp_write!(builder, d.rd, narrowed_val);
                        // Check trap flag
                        let flag = builder.ins().stack_load(I64, trap_flag_ss, 0);
                        let trapped = builder.ins().icmp_imm(IntCC::NotEqual, flag, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(trapped, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                    }
                    Opcode::Widen => {
                        // host_widen(ctx, wd, gp_value) -> 0
                        // Pass the current AOT variable value directly
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let wd = builder.ins().iconst(I64, d.rd as i64);
                        let gp_val = gp_read!(builder, d.rs1);
                        builder.ins().call(fn_widen_ref, &[vm_ctx, wd, gp_val]);
                    }

                    // --- Memory operations (host calls) ---
                    Opcode::Load => {
                        let base = gp_read!(builder, d.rs1);
                        let offset = pyde_vm::isa::decode_mem_offset(d.rs2_or_imm) as i64;
                        let width = pyde_vm::isa::decode_mem_width(d.rs2_or_imm) as u64;
                        let off_val = builder.ins().iconst(I64, offset);
                        let addr = builder.ins().iadd(base, off_val);
                        let w = builder.ins().iconst(I64, width as i64);
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let call = builder.ins().call(fn_load_ref, &[vm_ctx, addr, w]);
                        let result = builder.inst_results(call)[0];
                        emit_drain_page_gas!(builder);
                        gp_write!(builder, d.rd, result);
                    }
                    Opcode::Store => {
                        let base = gp_read!(builder, d.rs1);
                        let offset = pyde_vm::isa::decode_mem_offset(d.rs2_or_imm) as i64;
                        let width = pyde_vm::isa::decode_mem_width(d.rs2_or_imm) as u64;
                        let val = gp_read!(builder, d.rd);
                        let off_val = builder.ins().iconst(I64, offset);
                        let addr = builder.ins().iadd(base, off_val);
                        let w = builder.ins().iconst(I64, width as i64);
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        builder.ins().call(fn_store_ref, &[vm_ctx, addr, val, w]);
                        emit_drain_page_gas!(builder);
                    }

                    // --- Storage operations (host calls) ---
                    // Audit 228c: each storage host fn writes the
                    // EIP-2929 cold-access surcharge into
                    // `vm.memory.page_gas_used`; codegen drains it
                    // afterwards via `emit_drain_page_gas!`.
                    Opcode::Sload => {
                        let mode = d.rs2_or_imm & 0x3;
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let ws_slot = builder.ins().iconst(I64, d.rs1 as i64);
                        match mode {
                            0 => {
                                let wd = builder.ins().iconst(I64, d.rd as i64);
                                builder.ins().call(fn_sload_ref, &[vm_ctx, ws_slot, wd]);
                                emit_drain_page_gas!(builder);
                            }
                            1 => {
                                // Memory mode (sloadb): writes raw storage
                                // bytes to mem[ptr..ptr+len], length to
                                // gp[rd]. Audit 228d — previously fell
                                // through to wide mode silently. Now goes
                                // through host_sloadb which handles cold
                                // surcharge + dynamic gas + memory write.
                                let ptr_reg = ((d.rs2_or_imm >> 2) & 0xF) as u8;
                                let ptr = gp_read!(builder, ptr_reg);
                                let rd_idx = builder.ins().iconst(I64, d.rd as i64);
                                let call = builder
                                    .ins()
                                    .call(fn_sloadb_ref, &[vm_ctx, ws_slot, ptr, rd_idx]);
                                let result = builder.inst_results(call)[0];
                                emit_drain_page_gas!(builder);
                                let is_err = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                                let cont = builder.create_block();
                                builder.ins().brif(is_err, trap_block, &[], cont, &[]);
                                builder.seal_block(cont);
                                builder.switch_to_block(cont);
                            }
                            2 => {
                                let call = builder.ins().call(fn_sloadg_ref, &[vm_ctx, ws_slot]);
                                let result = builder.inst_results(call)[0];
                                gp_write!(builder, d.rd, result);
                                emit_drain_page_gas!(builder);
                            }
                            _ => {
                                let wd = builder.ins().iconst(I64, d.rd as i64);
                                builder.ins().call(fn_sload_ref, &[vm_ctx, ws_slot, wd]);
                                emit_drain_page_gas!(builder);
                            }
                        }
                    }
                    Opcode::Sstore => {
                        let mode = d.rs2_or_imm & 0x3;
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let ws_slot = builder.ins().iconst(I64, d.rs1 as i64);
                        let call = match mode {
                            0 => {
                                let wd = builder.ins().iconst(I64, d.rd as i64);
                                builder.ins().call(fn_sstore_ref, &[vm_ctx, ws_slot, wd])
                            }
                            1 => {
                                // Memory mode (sstoreb): reads
                                // mem[ptr..ptr+len] and writes to storage.
                                // Audit 228d — previously trapped. Now
                                // goes through host_sstoreb which handles
                                // cold surcharge + dynamic gas + memory
                                // read.
                                let ptr_reg = ((d.rs2_or_imm >> 2) & 0xF) as u8;
                                let len_reg = ((d.rs2_or_imm >> 6) & 0xF) as u8;
                                let ptr = gp_read!(builder, ptr_reg);
                                let len = gp_read!(builder, len_reg);
                                builder
                                    .ins()
                                    .call(fn_sstoreb_ref, &[vm_ctx, ws_slot, ptr, len])
                            }
                            2 => {
                                let rd_val = gp_read!(builder, d.rd);
                                builder
                                    .ins()
                                    .call(fn_sstoreg_ref, &[vm_ctx, ws_slot, rd_val])
                            }
                            _ => {
                                builder.ins().jump(trap_block, &[]);
                                terminated = true;
                                continue;
                            }
                        };
                        let result = builder.inst_results(call)[0];
                        emit_drain_page_gas!(builder);
                        let is_err = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(is_err, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                    }
                    Opcode::Sdelete => {
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let ws_slot = builder.ins().iconst(I64, d.rs1 as i64);
                        let call = builder.ins().call(fn_sdelete_ref, &[vm_ctx, ws_slot]);
                        let result = builder.inst_results(call)[0];
                        emit_drain_page_gas!(builder);
                        let is_err = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(is_err, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                    }

                    // --- Crypto (host calls) ---
                    Opcode::Poseidon => {
                        // Audit item 228a — interpreter charges 250 gas
                        // per 32-byte chunk (`pvm/src/vm.rs` Poseidon
                        // handler); AOT must charge the same. Emitted
                        // inline because host_poseidon can't reach
                        // VAR_GAS_USED. Plus page-gas drain after the
                        // call for the memory read inside host_poseidon.
                        let addr = gp_read!(builder, d.rs1);
                        let len_reg = (d.rs2_or_imm & 0xF) as u8;
                        let len = gp_read!(builder, len_reg);
                        let wd = builder.ins().iconst(I64, d.rd as i64);
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));

                        // dynamic_gas = ((len + 31) >> 5) * 250
                        let thirty_one = builder.ins().iconst(I64, 31);
                        let len_plus = builder.ins().iadd(len, thirty_one);
                        let chunks = builder.ins().ushr_imm(len_plus, 5);
                        let two_fifty = builder.ins().iconst(I64, 250);
                        let dynamic_gas = builder.ins().imul(chunks, two_fifty);
                        let gas_used = builder.use_var(Variable::from_u32(VAR_GAS_USED));
                        let new_gas = builder.ins().iadd(gas_used, dynamic_gas);
                        builder.def_var(Variable::from_u32(VAR_GAS_USED), new_gas);
                        let gas_limit = builder.use_var(Variable::from_u32(VAR_GAS_LIMIT));
                        let limit_nonzero = builder.ins().icmp_imm(IntCC::NotEqual, gas_limit, 0);
                        let over =
                            builder
                                .ins()
                                .icmp(IntCC::UnsignedGreaterThan, new_gas, gas_limit);
                        let oog = builder.ins().band(limit_nonzero, over);
                        let after_oog = builder.create_block();
                        builder.ins().brif(oog, oog_block, &[], after_oog, &[]);
                        builder.seal_block(after_oog);
                        builder.switch_to_block(after_oog);

                        let call = builder
                            .ins()
                            .call(fn_poseidon_ref, &[vm_ctx, addr, len, wd]);
                        let result = builder.inst_results(call)[0];
                        emit_drain_page_gas!(builder);
                        let is_err = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(is_err, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                    }

                    // --- Control flow ---
                    Opcode::Halt => {
                        builder.ins().jump(success_block, &[]);
                        terminated = true;
                        break;
                    }
                    Opcode::Revert => {
                        builder.ins().jump(revert_block, &[]);
                        terminated = true;
                        break;
                    }
                    Opcode::Jmp => {
                        let pc = bb.start_pc + (i as u32) * 4;
                        let offset = sign_extend_18(d.rs2_or_imm);
                        let target = pc.wrapping_add(offset as u32);
                        let bl = pc_to_block.get(&target).copied().unwrap_or(trap_block);
                        builder.ins().jump(bl, &[]);
                        terminated = true;
                        break;
                    }
                    Opcode::Beq | Opcode::Bne | Opcode::Blt | Opcode::Bge => {
                        let a = gp_read!(builder, d.rd);
                        let b = gp_read!(builder, d.rs1);
                        let pc = bb.start_pc + (i as u32) * 4;
                        let offset = sign_extend_18(d.rs2_or_imm);
                        let target = pc.wrapping_add(offset as u32);
                        let fall = pc + 4;

                        let target_bl = pc_to_block.get(&target).copied().unwrap_or(trap_block);
                        let fall_bl = pc_to_block.get(&fall).copied().unwrap_or(trap_block);

                        let cc = match d.opcode {
                            Opcode::Beq => IntCC::Equal,
                            Opcode::Bne => IntCC::NotEqual,
                            Opcode::Blt => IntCC::UnsignedLessThan,
                            Opcode::Bge => IntCC::UnsignedGreaterThanOrEqual,
                            _ => unreachable!(),
                        };
                        let cond = builder.ins().icmp(cc, a, b);
                        builder.ins().brif(cond, target_bl, &[], fall_bl, &[]);
                        terminated = true;
                        break;
                    }

                    // --- Environment queries (host calls) ---
                    Opcode::Caller => {
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let sub = d.rs2_or_imm;
                        let call = match sub {
                            0 => builder.ins().call(fn_block_number_ref, &[vm_ctx]),
                            1 => builder.ins().call(fn_timestamp_ref, &[vm_ctx]),
                            2 => builder.ins().call(fn_gas_remaining_ref, &[vm_ctx]),
                            _ => {
                                builder.ins().jump(trap_block, &[]);
                                terminated = true;
                                break;
                            }
                        };
                        let result = builder.inst_results(call)[0];
                        gp_write!(builder, d.rd, result);
                    }
                    Opcode::Callvalue => {
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let sub = d.rs2_or_imm;
                        let wd = builder.ins().iconst(I64, d.rd as i64);
                        match sub {
                            0 => {
                                builder.ins().call(fn_callvalue_ref, &[vm_ctx, wd]);
                            }
                            1 => {
                                builder.ins().call(fn_gasprice_ref, &[vm_ctx, wd]);
                            }
                            2 => {
                                let addr = gp_read!(builder, d.rs1);
                                builder.ins().call(fn_balance_ref, &[vm_ctx, addr, wd]);
                            }
                            3 => {
                                builder.ins().call(fn_caller_ref, &[vm_ctx, wd]);
                            } // CALLER
                            4 => {
                                builder.ins().call(fn_address_ref, &[vm_ctx, wd]);
                            } // ADDRESS
                            _ => {
                                builder.ins().jump(trap_block, &[]);
                                terminated = true;
                                break;
                            }
                        }
                    }
                    Opcode::Blockhash => {
                        // Blockhash not yet fully supported in AOT — write zero
                        let z = builder.ins().iconst(I64, 0);
                        gp_write!(builder, d.rd, z);
                    }

                    // --- Assertions + Memory (host calls) ---
                    Opcode::Assert => {
                        let val = gp_read!(builder, d.rs1);
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let call = builder.ins().call(fn_assert_ref, &[vm_ctx, val]);
                        let result = builder.inst_results(call)[0];
                        let should_revert = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                        let cont = builder.create_block();
                        builder
                            .ins()
                            .brif(should_revert, revert_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                    }
                    Opcode::Memcpy => {
                        // Memcpy via VM runtime call.
                        //
                        // Gas parity with the interpreter (audit items
                        // 215 + 228a):
                        //   1. Per-byte dynamic gas (3 per 8 bytes)
                        //      charged inline in the JIT before the
                        //      host call.
                        //   2. Per-page allocation gas drained via
                        //      `emit_drain_page_gas!` after the host
                        //      call, uniform with the other memory
                        //      ops.
                        //   3. host_memcpy fault return routed to
                        //      `trap_block` (previously discarded).
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let dst = gp_read!(builder, d.rd);
                        let src = gp_read!(builder, d.rs1);
                        let len_reg = (d.rs2_or_imm & 0xF) as u8;
                        let len = gp_read!(builder, len_reg);

                        // Per-byte dynamic_gas = ((len + 7) >> 3) * 3
                        let seven = builder.ins().iconst(I64, 7);
                        let len_plus_seven = builder.ins().iadd(len, seven);
                        let chunks = builder.ins().ushr_imm(len_plus_seven, 3);
                        let three = builder.ins().iconst(I64, 3);
                        let dynamic_gas = builder.ins().imul(chunks, three);

                        let gas_used = builder.use_var(Variable::from_u32(VAR_GAS_USED));
                        let new_gas = builder.ins().iadd(gas_used, dynamic_gas);
                        builder.def_var(Variable::from_u32(VAR_GAS_USED), new_gas);

                        // OOG check after dynamic charge.
                        let gas_limit = builder.use_var(Variable::from_u32(VAR_GAS_LIMIT));
                        let limit_nonzero = builder.ins().icmp_imm(IntCC::NotEqual, gas_limit, 0);
                        let over =
                            builder
                                .ins()
                                .icmp(IntCC::UnsignedGreaterThan, new_gas, gas_limit);
                        let oog = builder.ins().band(limit_nonzero, over);
                        let after_oog = builder.create_block();
                        builder.ins().brif(oog, oog_block, &[], after_oog, &[]);
                        builder.seal_block(after_oog);
                        builder.switch_to_block(after_oog);

                        // host_memcpy: 0=success, 1=fault.
                        let call = builder.ins().call(fn_memcpy_ref, &[vm_ctx, dst, src, len]);
                        let result = builder.inst_results(call)[0];

                        emit_drain_page_gas!(builder);

                        let is_fault = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(is_fault, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                    }
                    Opcode::Selfdestruct => {
                        // Selfdestruct halts execution after clearing storage
                        builder.ins().jump(success_block, &[]);
                        terminated = true;
                        break;
                    }

                    // Internal Call: jump to target (in AOT, Call is just a jump —
                    // return address tracking isn't needed since blocks link directly).
                    Opcode::Call => {
                        let pc = bb.start_pc + (i as u32) * 4;
                        let offset = sign_extend_18(d.rs2_or_imm);
                        let target = pc.wrapping_add(offset as u32);
                        let bl = pc_to_block.get(&target).copied().unwrap_or(trap_block);
                        builder.ins().jump(bl, &[]);
                        terminated = true;
                        break;
                    }
                    // Internal Ret: jump to success block (same as Halt).
                    Opcode::Ret => {
                        builder.ins().jump(success_block, &[]);
                        terminated = true;
                        break;
                    }

                    // Log: emit event via host_log(ctx, desc_ptr, num_topics).
                    // Audit 228c: host_log writes its dynamic gas
                    // (`100 + data_len*8 + num_topics*50`) plus the
                    // page-gas from reading topics + data into
                    // `vm.memory.page_gas_used`; codegen drains both
                    // via `emit_drain_page_gas!` after the call.
                    Opcode::Log => {
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let desc_ptr = gp_read!(builder, d.rs1);
                        let num_topics = builder.ins().iconst(I64, (d.rs2_or_imm & 0x7) as i64);
                        let call = builder
                            .ins()
                            .call(fn_log_ref, &[vm_ctx, desc_ptr, num_topics]);
                        let result = builder.inst_results(call)[0];
                        emit_drain_page_gas!(builder);
                        let is_err = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(is_err, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                    }

                    // Complex opcodes delegated to the interpreter via host_exec_opcode.
                    // GP registers are synced to vm.cpu.gp before the call and reloaded after.
                    // Wide registers are already in the VM (managed by host_wide_alu/host_widen).
                    //
                    // Audit 228b: the delegated step charges gas into
                    // `vm.gas_used_total`, which is independent of AOT's
                    // `VAR_GAS_USED`. Now passes current `VAR_GAS_USED` +
                    // `VAR_GAS_LIMIT` into the host call, unpacks the
                    // returned `(gas_used_out << 2) | result`, and folds
                    // `gas_used_out` back into `VAR_GAS_USED`.
                    Opcode::CallExt
                    | Opcode::Delegate
                    | Opcode::Create
                    | Opcode::VerifySig
                    | Opcode::MerkleVerify => {
                        // Sync GP registers: external regs[] → vm.cpu.gp[]
                        let regs_ptr_val = builder.use_var(Variable::from_u32(VAR_REGS_PTR));
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        builder
                            .ins()
                            .call(fn_sync_gp_to_vm_ref, &[vm_ctx, regs_ptr_val]);

                        let op = builder.ins().iconst(I64, d.opcode.to_u8() as i64);
                        let rd_val = builder.ins().iconst(I64, d.rd as i64);
                        let rs1_val = builder.ins().iconst(I64, d.rs1 as i64);
                        let imm_val = builder.ins().iconst(I64, d.rs2_or_imm as i64);
                        let gas_used_in = builder.use_var(Variable::from_u32(VAR_GAS_USED));
                        let gas_limit_in = builder.use_var(Variable::from_u32(VAR_GAS_LIMIT));
                        let call = builder.ins().call(
                            fn_exec_opcode_ref,
                            &[
                                vm_ctx,
                                op,
                                rd_val,
                                rs1_val,
                                imm_val,
                                gas_used_in,
                                gas_limit_in,
                            ],
                        );
                        let raw = builder.inst_results(call)[0];

                        // Unpack: low 2 bits = result, high 62 = gas_used_out.
                        let result = builder.ins().band_imm(raw, 3);
                        let gas_used_out = builder.ins().ushr_imm(raw, 2);
                        builder.def_var(Variable::from_u32(VAR_GAS_USED), gas_used_out);

                        // Sync GP registers back: vm.cpu.gp[] → external regs[]
                        builder
                            .ins()
                            .call(fn_sync_gp_from_vm_ref, &[vm_ctx, regs_ptr_val]);

                        // OOG if the updated VAR_GAS_USED is over VAR_GAS_LIMIT.
                        // Belt-and-suspenders: step() also traps OOG internally
                        // (result=1), but a successful step that exactly
                        // saturated gas should map to the AOT's oog_block
                        // rather than continuing.
                        let gas_limit = builder.use_var(Variable::from_u32(VAR_GAS_LIMIT));
                        let limit_nonzero = builder.ins().icmp_imm(IntCC::NotEqual, gas_limit, 0);
                        let over =
                            builder
                                .ins()
                                .icmp(IntCC::UnsignedGreaterThan, gas_used_out, gas_limit);
                        let oog = builder.ins().band(limit_nonzero, over);
                        let after_oog = builder.create_block();
                        builder.ins().brif(oog, oog_block, &[], after_oog, &[]);
                        builder.seal_block(after_oog);
                        builder.switch_to_block(after_oog);

                        // Check result: 0=ok, 1=trap, 2=halt/revert
                        let is_trap = builder.ins().icmp_imm(IntCC::Equal, result, 1);
                        let cont = builder.create_block();
                        builder.ins().brif(is_trap, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                        let is_halt = builder.ins().icmp_imm(IntCC::Equal, result, 2);
                        let cont2 = builder.create_block();
                        builder.ins().brif(is_halt, success_block, &[], cont2, &[]);
                        builder.seal_block(cont2);
                        builder.switch_to_block(cont2);
                    }

                    // Truly unknown opcodes trap
                    _ => {
                        builder.ins().jump(trap_block, &[]);
                        terminated = true;
                        break;
                    }
                }

                // Reload GP registers from vm.cpu.gp after host calls
                // that may have modified GP state (Weq, Wlt, Narrow, etc.)
                // No flush/reload needed — GP registers go through regs_ptr memory directly
            }

            if !terminated {
                let next_pc = bb.start_pc + (bb.instructions.len() as u32) * 4;
                if let Some(&next_bl) = pc_to_block.get(&next_pc) {
                    builder.ins().jump(next_bl, &[]);
                } else {
                    builder.ins().jump(success_block, &[]);
                }
            }
        }

        // === Success: store registers back ===
        builder.switch_to_block(success_block);
        // GP registers are already in regs_ptr memory — no write-back needed.
        let gas = builder.use_var(Variable::from_u32(VAR_GAS_USED));
        let shifted = builder.ins().ishl_imm(gas, 2);
        let result = builder.ins().bor_imm(shifted, RESULT_SUCCESS as i64);
        builder.ins().return_(&[result]);

        // === Revert ===
        builder.switch_to_block(revert_block);
        let gas = builder.use_var(Variable::from_u32(VAR_GAS_USED));
        let shifted = builder.ins().ishl_imm(gas, 2);
        let result = builder.ins().bor_imm(shifted, RESULT_REVERT as i64);
        builder.ins().return_(&[result]);

        // === OOG ===
        builder.switch_to_block(oog_block);
        let gas = builder.use_var(Variable::from_u32(VAR_GAS_USED));
        let shifted = builder.ins().ishl_imm(gas, 2);
        let result = builder.ins().bor_imm(shifted, RESULT_OUT_OF_GAS as i64);
        builder.ins().return_(&[result]);

        // === Trap ===
        builder.switch_to_block(trap_block);
        let trap_val = builder.ins().iconst(I64, RESULT_TRAP as i64);
        builder.ins().return_(&[trap_val]);

        for &bl in &cl_blocks {
            builder.seal_block(bl);
        }
        builder.seal_block(success_block);
        builder.seal_block(revert_block);
        builder.seal_block(oog_block);
        builder.seal_block(trap_block);

        builder.finalize();
    }

    module
        .define_function(func_id, &mut ctx)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    module.clear_context(&mut ctx);
    module
        .finalize_definitions()
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    let code_ptr = module.get_finalized_function(func_id);

    Ok(CompiledCode {
        _module: module,
        code_ptr,
        bytecode_hash: program.bytecode_hash,
        block_count: program.blocks.len(),
        instruction_count: program.instruction_count,
    })
}

pub fn decode_result(raw: u64) -> (u64, u64) {
    if raw == RESULT_TRAP {
        return (RESULT_TRAP, 0);
    }
    let status = raw & 0x3;
    let gas_used = raw >> 2;
    (status, gas_used)
}
