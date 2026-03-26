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
        unsafe { std::mem::transmute(self.code_ptr) }
    }

    /// Convenience: run without VM context (ALU-only programs).
    pub fn as_fn_no_ctx(&self) -> unsafe fn(*mut u64, u64) -> u64 {
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
    flag_builder.set("opt_level", "speed").unwrap();
    let isa_builder = cranelift_native::builder()
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
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
    sig.params.push(AbiParam::new(I64));       // gas_limit
    sig.params.push(AbiParam::new(ptr_type)); // vm_ctx
    sig.returns.push(AbiParam::new(I64));      // result

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
    let fn_load = module.declare_function("host_load", Linkage::Import, &sig_load)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_store(ctx, addr, value, width) -> u64
    let mut sig_store = module.make_signature();
    sig_store.params.push(AbiParam::new(ptr_type));
    sig_store.params.push(AbiParam::new(I64));
    sig_store.params.push(AbiParam::new(I64));
    sig_store.params.push(AbiParam::new(I64));
    sig_store.returns.push(AbiParam::new(I64));
    let fn_store = module.declare_function("host_store", Linkage::Import, &sig_store)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_sload(ctx, ws_slot, wd) -> u64
    let mut sig_sload = module.make_signature();
    sig_sload.params.push(AbiParam::new(ptr_type));
    sig_sload.params.push(AbiParam::new(I64));
    sig_sload.params.push(AbiParam::new(I64));
    sig_sload.returns.push(AbiParam::new(I64));
    let fn_sload = module.declare_function("host_sload", Linkage::Import, &sig_sload)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_sstore(ctx, ws_slot, wd) -> u64
    let fn_sstore = module.declare_function("host_sstore", Linkage::Import, &sig_sload)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_sdelete(ctx, ws_slot) -> u64 / host_sloadg(ctx, ws_slot) -> u64
    let mut sig_sdel = module.make_signature();
    sig_sdel.params.push(AbiParam::new(ptr_type));
    sig_sdel.params.push(AbiParam::new(I64));
    sig_sdel.returns.push(AbiParam::new(I64));
    let fn_sdelete = module.declare_function("host_sdelete", Linkage::Import, &sig_sdel)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_sloadg(ctx, ws_slot) -> u64 (same signature as sdelete)
    let fn_sloadg = module.declare_function("host_sloadg", Linkage::Import, &sig_sdel)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_poseidon(ctx, addr, len, wd) -> u64
    let mut sig_pos = module.make_signature();
    sig_pos.params.push(AbiParam::new(ptr_type));
    sig_pos.params.push(AbiParam::new(I64));
    sig_pos.params.push(AbiParam::new(I64));
    sig_pos.params.push(AbiParam::new(I64));
    sig_pos.returns.push(AbiParam::new(I64));
    let fn_poseidon = module.declare_function("host_poseidon", Linkage::Import, &sig_pos)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    let mut ctx = module.make_context();
    ctx.func.signature = sig;
    ctx.func.name = UserFuncName::user(0, 0);

    // host_push(ctx, value) -> u64
    let mut sig_push = module.make_signature();
    sig_push.params.push(AbiParam::new(ptr_type));
    sig_push.params.push(AbiParam::new(I64));
    sig_push.returns.push(AbiParam::new(I64));
    let fn_push = module.declare_function("host_push", Linkage::Import, &sig_push)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_pop(ctx) -> u64
    let mut sig_pop = module.make_signature();
    sig_pop.params.push(AbiParam::new(ptr_type));
    sig_pop.returns.push(AbiParam::new(I64));
    let fn_pop = module.declare_function("host_pop", Linkage::Import, &sig_pop)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // Environment host functions: (ctx) -> u64
    // host_caller(ctx, wd) -> u64, host_address(ctx, wd) -> u64
    let fn_caller = module.declare_function("host_caller", Linkage::Import, &sig_sdel)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_address = module.declare_function("host_address", Linkage::Import, &sig_sdel)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_block_number = module.declare_function("host_block_number", Linkage::Import, &sig_pop)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_timestamp = module.declare_function("host_timestamp", Linkage::Import, &sig_pop)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_gas_remaining = module.declare_function("host_gas_remaining", Linkage::Import, &sig_pop)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    // (ctx, wd) -> u64
    let fn_callvalue = module.declare_function("host_callvalue", Linkage::Import, &sig_sdel)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_gasprice = module.declare_function("host_gasprice", Linkage::Import, &sig_sdel)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    // (ctx, addr, wd) -> u64
    let fn_balance = module.declare_function("host_balance", Linkage::Import, &sig_sload)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    // (ctx, val) -> u64
    let fn_assert = module.declare_function("host_assert", Linkage::Import, &sig_sdel)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    // (ctx, a, b) -> u64
    let fn_memcpy = module.declare_function("host_memcpy", Linkage::Import, &sig_sload)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_wload(ctx, addr, wd) -> u64
    let fn_wload = module.declare_function("host_wload", Linkage::Import, &sig_sload)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_wstore(ctx, addr, ws) -> u64
    let fn_wstore = module.declare_function("host_wstore", Linkage::Import, &sig_sload)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_wide_alu(ctx, opcode, wd, ws1, ws2) -> u64
    let mut sig_wide = module.make_signature();
    sig_wide.params.push(AbiParam::new(ptr_type));
    sig_wide.params.push(AbiParam::new(I64));
    sig_wide.params.push(AbiParam::new(I64));
    sig_wide.params.push(AbiParam::new(I64));
    sig_wide.params.push(AbiParam::new(I64));
    sig_wide.returns.push(AbiParam::new(I64));
    let fn_wide_alu = module.declare_function("host_wide_alu", Linkage::Import, &sig_wide)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_narrow(ctx, ws1, trap_out) -> u64 (returns narrowed value)
    let mut sig_narrow = module.make_signature();
    sig_narrow.params.push(AbiParam::new(ptr_type));
    sig_narrow.params.push(AbiParam::new(I64));
    sig_narrow.params.push(AbiParam::new(ptr_type)); // trap_out pointer
    sig_narrow.returns.push(AbiParam::new(I64));
    let fn_narrow = module.declare_function("host_narrow", Linkage::Import, &sig_narrow)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_widen(ctx, wd, gp_value) -> u64
    let fn_widen = module.declare_function("host_widen", Linkage::Import, &sig_sload)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // host_checked_add/sub/mul(a, b, trap_out) -> u64
    let mut sig_checked = module.make_signature();
    sig_checked.params.push(AbiParam::new(I64));
    sig_checked.params.push(AbiParam::new(I64));
    sig_checked.params.push(AbiParam::new(ptr_type));
    sig_checked.returns.push(AbiParam::new(I64));
    let fn_checked_add = module.declare_function("host_checked_add", Linkage::Import, &sig_checked)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_checked_sub = module.declare_function("host_checked_sub", Linkage::Import, &sig_checked)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_checked_mul = module.declare_function("host_checked_mul", Linkage::Import, &sig_checked)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_checked_div = module.declare_function("host_checked_div", Linkage::Import, &sig_checked)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    let fn_checked_mod = module.declare_function("host_checked_mod", Linkage::Import, &sig_checked)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;

    // Import host function references for use inside the function
    let fn_load_ref = module.declare_func_in_func(fn_load, &mut ctx.func);
    let fn_store_ref = module.declare_func_in_func(fn_store, &mut ctx.func);
    let fn_sload_ref = module.declare_func_in_func(fn_sload, &mut ctx.func);
    let fn_sstore_ref = module.declare_func_in_func(fn_sstore, &mut ctx.func);
    let fn_sdelete_ref = module.declare_func_in_func(fn_sdelete, &mut ctx.func);
    let fn_sloadg_ref = module.declare_func_in_func(fn_sloadg, &mut ctx.func);
    let fn_poseidon_ref = module.declare_func_in_func(fn_poseidon, &mut ctx.func);
    let fn_push_ref = module.declare_func_in_func(fn_push, &mut ctx.func);
    let fn_pop_ref = module.declare_func_in_func(fn_pop, &mut ctx.func);
    let fn_wload_ref = module.declare_func_in_func(fn_wload, &mut ctx.func);
    let fn_wstore_ref = module.declare_func_in_func(fn_wstore, &mut ctx.func);
    let fn_wide_alu_ref = module.declare_func_in_func(fn_wide_alu, &mut ctx.func);
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

    {
        let mut fn_builder_ctx = FunctionBuilderContext::new();
        let mut builder = FunctionBuilder::new(&mut ctx.func, &mut fn_builder_ctx);

        for i in 0..16u32 {
            builder.declare_var(Variable::from_u32(i), I64);
        }
        builder.declare_var(Variable::from_u32(VAR_GAS_USED), I64);
        builder.declare_var(Variable::from_u32(VAR_GAS_LIMIT), I64);
        builder.declare_var(Variable::from_u32(VAR_REGS_PTR), ptr_type);
        builder.declare_var(Variable::from_u32(VAR_VM_CTX), ptr_type);

        // Stack-allocated trap flag for checked arithmetic (address passed to host fns)
        let trap_flag_ss = builder.create_sized_stack_slot(cranelift_codegen::ir::StackSlotData::new(
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
        builder.def_var(Variable::from_u32(0), zero); // r0 always zero

        for i in 1..16u32 {
            let val = builder.ins().load(I64, MemFlags::trusted(), param_regs_ptr, (i as i32) * 8);
            builder.def_var(Variable::from_u32(i), val);
        }

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
                let over = builder.ins().icmp(IntCC::UnsignedGreaterThan, new_gas, gas_limit);
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
                    let a = $builder.use_var(Variable::from_u32($d.rs1 as u32));
                    let b = $builder.use_var(Variable::from_u32(($d.rs2_or_imm & 0xF) as u32));
                    // Zero the trap flag
                    let z = $builder.ins().iconst(I64, 0);
                    $builder.ins().stack_store(z, $trap_flag_ss, 0);
                    let trap_ptr = $builder.ins().stack_addr(ptr_type, $trap_flag_ss, 0);
                    let call = $builder.ins().call($fn_ref, &[a, b, trap_ptr]);
                    let result = $builder.inst_results(call)[0];
                    if $d.rd != 0 { $builder.def_var(Variable::from_u32($d.rd as u32), result); }
                    // Check trap flag
                    let flag = $builder.ins().stack_load(I64, $trap_flag_ss, 0);
                    let trapped = $builder.ins().icmp_imm(IntCC::NotEqual, flag, 0);
                    let cont = $builder.create_block();
                    $builder.ins().brif(trapped, $trap_block, &[], cont, &[]);
                    $builder.seal_block(cont);
                    $builder.switch_to_block(cont);
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
                        let a = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let imm = sign_extend_18(d.rs2_or_imm) as i64;
                        let b = builder.ins().iconst(I64, imm);
                        // ADDI doesn't overflow check in interpreter (immediate is small)
                        let r = builder.ins().iadd(a, b);
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), r); }
                    }

                    // --- Bitwise & shifts (no overflow possible) ---
                    Opcode::And => {
                        let a = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let b = builder.use_var(Variable::from_u32((d.rs2_or_imm & 0xF) as u32));
                        let r = builder.ins().band(a, b);
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), r); }
                    }
                    Opcode::Or => {
                        let a = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let b = builder.use_var(Variable::from_u32((d.rs2_or_imm & 0xF) as u32));
                        let r = builder.ins().bor(a, b);
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), r); }
                    }
                    Opcode::Xor => {
                        let a = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let b = builder.use_var(Variable::from_u32((d.rs2_or_imm & 0xF) as u32));
                        let r = builder.ins().bxor(a, b);
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), r); }
                    }
                    Opcode::Not => {
                        let a = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let r = builder.ins().bnot(a);
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), r); }
                    }
                    Opcode::Shl => {
                        let a = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let b = builder.use_var(Variable::from_u32((d.rs2_or_imm & 0xF) as u32));
                        let r = builder.ins().ishl(a, b);
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), r); }
                    }
                    Opcode::Shr => {
                        let a = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let b = builder.use_var(Variable::from_u32((d.rs2_or_imm & 0xF) as u32));
                        let r = builder.ins().ushr(a, b);
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), r); }
                    }
                    Opcode::Sar => {
                        let a = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let b = builder.use_var(Variable::from_u32((d.rs2_or_imm & 0xF) as u32));
                        let r = builder.ins().sshr(a, b);
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), r); }
                    }

                    // --- Comparisons ---
                    Opcode::Lt => {
                        let a = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let b = builder.use_var(Variable::from_u32((d.rs2_or_imm & 0xF) as u32));
                        let cmp = builder.ins().icmp(IntCC::UnsignedLessThan, a, b);
                        let r = builder.ins().uextend(I64, cmp);
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), r); }
                    }
                    Opcode::Gt => {
                        let a = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let b = builder.use_var(Variable::from_u32((d.rs2_or_imm & 0xF) as u32));
                        let cmp = builder.ins().icmp(IntCC::UnsignedGreaterThan, a, b);
                        let r = builder.ins().uextend(I64, cmp);
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), r); }
                    }
                    Opcode::Eq => {
                        let a = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let b = builder.use_var(Variable::from_u32((d.rs2_or_imm & 0xF) as u32));
                        let cmp = builder.ins().icmp(IntCC::Equal, a, b);
                        let r = builder.ins().uextend(I64, cmp);
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), r); }
                    }
                    Opcode::Slt => {
                        let a = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let b = builder.use_var(Variable::from_u32((d.rs2_or_imm & 0xF) as u32));
                        let cmp = builder.ins().icmp(IntCC::SignedLessThan, a, b);
                        let r = builder.ins().uextend(I64, cmp);
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), r); }
                    }
                    Opcode::Sgt => {
                        let a = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let b = builder.use_var(Variable::from_u32((d.rs2_or_imm & 0xF) as u32));
                        let cmp = builder.ins().icmp(IntCC::SignedGreaterThan, a, b);
                        let r = builder.ins().uextend(I64, cmp);
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), r); }
                    }

                    // --- Push/Pop (host calls) ---
                    Opcode::Push => {
                        let val = builder.use_var(Variable::from_u32(d.rd as u32));
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let call = builder.ins().call(fn_push_ref, &[vm_ctx, val]);
                        let result = builder.inst_results(call)[0];
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
                        // Check for fault (u64::MAX)
                        let is_err = builder.ins().icmp_imm(IntCC::Equal, result, -1i64);
                        let cont = builder.create_block();
                        builder.ins().brif(is_err, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), result); }
                    }

                    // --- Wide register ops (host calls) ---
                    Opcode::Wadd | Opcode::Wsub | Opcode::Wmul | Opcode::Wdiv
                    | Opcode::Wmod | Opcode::Wand | Opcode::Wor | Opcode::Wxor
                    | Opcode::Wnot | Opcode::Wmov | Opcode::Weq | Opcode::Wlt => {
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let op = builder.ins().iconst(I64, d.opcode.to_u8() as i64);
                        let wd = builder.ins().iconst(I64, d.rd as i64);
                        let ws1 = builder.ins().iconst(I64, d.rs1 as i64);
                        let ws2 = builder.ins().iconst(I64, (d.rs2_or_imm & 0xF) as i64);
                        let call = builder.ins().call(fn_wide_alu_ref, &[vm_ctx, op, wd, ws1, ws2]);
                        let result = builder.inst_results(call)[0];
                        let trapped = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(trapped, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                    }
                    Opcode::Wload => {
                        let addr = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let wd = builder.ins().iconst(I64, d.rd as i64);
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let call = builder.ins().call(fn_wload_ref, &[vm_ctx, addr, wd]);
                        let result = builder.inst_results(call)[0];
                        let is_err = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(is_err, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                    }
                    Opcode::Wstore => {
                        let addr = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let ws = builder.ins().iconst(I64, d.rd as i64);
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let call = builder.ins().call(fn_wstore_ref, &[vm_ctx, addr, ws]);
                        let result = builder.inst_results(call)[0];
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
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), narrowed_val); }
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
                        let gp_val = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        builder.ins().call(fn_widen_ref, &[vm_ctx, wd, gp_val]);
                    }

                    // --- Memory operations (host calls) ---
                    Opcode::Load => {
                        let base = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let offset = pyde_vm::isa::decode_mem_offset(d.rs2_or_imm) as i64;
                        let width = pyde_vm::isa::decode_mem_width(d.rs2_or_imm) as u64;
                        let off_val = builder.ins().iconst(I64, offset);
                        let addr = builder.ins().iadd(base, off_val);
                        let w = builder.ins().iconst(I64, width as i64);
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let call = builder.ins().call(fn_load_ref, &[vm_ctx, addr, w]);
                        let result = builder.inst_results(call)[0];
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), result); }
                    }
                    Opcode::Store => {
                        let base = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let offset = pyde_vm::isa::decode_mem_offset(d.rs2_or_imm) as i64;
                        let width = pyde_vm::isa::decode_mem_width(d.rs2_or_imm) as u64;
                        let val = builder.use_var(Variable::from_u32(d.rd as u32));
                        let off_val = builder.ins().iconst(I64, offset);
                        let addr = builder.ins().iadd(base, off_val);
                        let w = builder.ins().iconst(I64, width as i64);
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        builder.ins().call(fn_store_ref, &[vm_ctx, addr, val, w]);
                    }

                    // --- Storage operations (host calls) ---
                    Opcode::Sload => {
                        let mode = d.rs2_or_imm & 0x3;
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let ws_slot = builder.ins().iconst(I64, d.rs1 as i64);
                        match mode {
                            0 => {
                                // Wide register mode: sload wd, ws1
                                let wd = builder.ins().iconst(I64, d.rd as i64);
                                builder.ins().call(fn_sload_ref, &[vm_ctx, ws_slot, wd]);
                            }
                            2 => {
                                // GP register mode: sloadg rd, ws1 → returns u64
                                let call = builder.ins().call(fn_sloadg_ref, &[vm_ctx, ws_slot]);
                                let result = builder.inst_results(call)[0];
                                if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), result); }
                            }
                            _ => {
                                // Mode 1 (memory) and others: delegate to wide mode for now
                                let wd = builder.ins().iconst(I64, d.rd as i64);
                                builder.ins().call(fn_sload_ref, &[vm_ctx, ws_slot, wd]);
                            }
                        }
                    }
                    Opcode::Sstore => {
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let ws_slot = builder.ins().iconst(I64, d.rs1 as i64);
                        let wd = builder.ins().iconst(I64, d.rd as i64);
                        let call = builder.ins().call(fn_sstore_ref, &[vm_ctx, ws_slot, wd]);
                        let result = builder.inst_results(call)[0];
                        // result = 1 means static mode violation → trap
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
                        let is_err = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(is_err, trap_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                    }

                    // --- Crypto (host calls) ---
                    Opcode::Poseidon => {
                        let addr = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let len_reg = (d.rs2_or_imm & 0xF) as u32;
                        let len = builder.use_var(Variable::from_u32(len_reg));
                        let wd = builder.ins().iconst(I64, d.rd as i64);
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let call = builder.ins().call(fn_poseidon_ref, &[vm_ctx, addr, len, wd]);
                        let result = builder.inst_results(call)[0];
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
                        let a = builder.use_var(Variable::from_u32(d.rd as u32));
                        let b = builder.use_var(Variable::from_u32(d.rs1 as u32));
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
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), result); }
                    }
                    Opcode::Callvalue => {
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let sub = d.rs2_or_imm;
                        let wd = builder.ins().iconst(I64, d.rd as i64);
                        match sub {
                            0 => { builder.ins().call(fn_callvalue_ref, &[vm_ctx, wd]); }
                            1 => { builder.ins().call(fn_gasprice_ref, &[vm_ctx, wd]); }
                            2 => {
                                let addr = builder.use_var(Variable::from_u32(d.rs1 as u32));
                                builder.ins().call(fn_balance_ref, &[vm_ctx, addr, wd]);
                            }
                            3 => { builder.ins().call(fn_caller_ref, &[vm_ctx, wd]); }  // CALLER
                            4 => { builder.ins().call(fn_address_ref, &[vm_ctx, wd]); } // ADDRESS
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
                        if d.rd != 0 { builder.def_var(Variable::from_u32(d.rd as u32), z); }
                    }

                    // --- Assertions + Memory (host calls) ---
                    Opcode::Assert => {
                        let val = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let call = builder.ins().call(fn_assert_ref, &[vm_ctx, val]);
                        let result = builder.inst_results(call)[0];
                        let should_revert = builder.ins().icmp_imm(IntCC::NotEqual, result, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(should_revert, revert_block, &[], cont, &[]);
                        builder.seal_block(cont);
                        builder.switch_to_block(cont);
                    }
                    Opcode::Memcpy => {
                        // Memcpy handled by VM runtime call (AOT fallback)
                        let vm_ctx = builder.use_var(Variable::from_u32(VAR_VM_CTX));
                        let dst = builder.use_var(Variable::from_u32(d.rd as u32));
                        let src = builder.use_var(Variable::from_u32(d.rs1 as u32));
                        let len_reg = (d.rs2_or_imm & 0xF) as u32;
                        let len = builder.use_var(Variable::from_u32(len_reg));
                        builder.ins().call(fn_memcpy_ref, &[vm_ctx, dst, src, len]);
                    }
                    Opcode::Commit => {
                        // Commit is captured from trace, no runtime effect
                    }
                    Opcode::Selfdestruct => {
                        // Selfdestruct halts execution after clearing storage
                        builder.ins().jump(success_block, &[]);
                        terminated = true;
                        break;
                    }

                    // Remaining opcodes not yet AOT-compiled (Call, Ret, CallExt,
                    // Delegate, Create, Log, VerifySig, MerkleVerify) trap.
                    // These require complex VM state interaction that's better
                    // handled by falling back to the interpreter for now.
                    _ => {
                        builder.ins().jump(trap_block, &[]);
                        terminated = true;
                        break;
                    }
                }
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
        let regs_ptr = builder.use_var(Variable::from_u32(VAR_REGS_PTR));
        // Write r1-r15 back (r0 is always zero, skip it)
        for i in 1..16u32 {
            let val = builder.use_var(Variable::from_u32(i));
            builder.ins().store(MemFlags::trusted(), val, regs_ptr, (i as i32) * 8);
        }
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

    module.define_function(func_id, &mut ctx)
        .map_err(|e| CodegenError::CompilationFailed(e.to_string()))?;
    module.clear_context(&mut ctx);
    module.finalize_definitions()
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
