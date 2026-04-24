//! `pyde-aot`: Ahead-of-Time compiler for PVM bytecode.
//!
//! Compiles PVM bytecode to native machine code via Cranelift at deploy time.
//! The compiled binary runs natively for maximum execution speed.

pub mod analysis;
pub mod codegen;
pub mod host;

pub use analysis::{analyze, AnalyzedProgram, BasicBlock};
pub use codegen::{
    compile, decode_result, CompiledCode, RESULT_OUT_OF_GAS, RESULT_REVERT, RESULT_SUCCESS,
    RESULT_TRAP,
};

/// Compile PVM bytecode end-to-end: analyze → codegen → native function.
pub fn compile_bytecode(bytecode: &[u8]) -> Result<CompiledCode, Box<dyn std::error::Error>> {
    let program = analyze(bytecode)?;
    let compiled = codegen::compile(&program)?;
    Ok(compiled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_vm::isa::{encode, encode_immediate, Opcode};

    fn instr_bytes(op: Opcode, rd: u8, rs1: u8, rs2_or_imm: u32) -> [u8; 4] {
        encode(op, rd, rs1, rs2_or_imm).0.to_le_bytes()
    }

    fn instr_ri(op: Opcode, rd: u8, rs1: u8, imm: i32) -> [u8; 4] {
        encode(op, rd, rs1, encode_immediate(imm).unwrap())
            .0
            .to_le_bytes()
    }

    fn bytecode(instrs: &[[u8; 4]]) -> Vec<u8> {
        instrs.iter().flat_map(|i| i.iter().copied()).collect()
    }

    /// Run compiled code with a VM context and return (status, gas_used, registers).
    fn run_aot(code: &[u8], gas_limit: u64) -> (u64, u64, [u64; 16]) {
        let compiled = compile_bytecode(code).unwrap();
        let func = compiled.as_fn();
        let mut regs = [0u64; 16];
        let mut vm = pyde_vm::vm::Vm::new();
        let raw = unsafe { func(regs.as_mut_ptr(), gas_limit, &mut vm as *mut _) };
        let (status, gas_used) = decode_result(raw);
        (status, gas_used, regs)
    }

    /// Run the same program on interpreter and AOT, compare results.
    fn compare_with_interpreter(code: &[u8], gas_limit: u64) {
        // Interpreter
        let mut vm = pyde_vm::vm::Vm::new();
        if gas_limit > 0 {
            vm = pyde_vm::vm::Vm::with_gas_limit(gas_limit);
        }
        vm.load(code).unwrap();
        let interp_output = vm.execute();

        // AOT
        let (aot_status, _aot_gas, aot_regs) = run_aot(code, gas_limit);

        // Compare outcome
        match interp_output.outcome {
            pyde_vm::vm::Outcome::Success => assert_eq!(aot_status, RESULT_SUCCESS),
            pyde_vm::vm::Outcome::Revert => assert_eq!(aot_status, RESULT_REVERT),
            pyde_vm::vm::Outcome::OutOfGas => assert_eq!(aot_status, RESULT_OUT_OF_GAS),
            pyde_vm::vm::Outcome::Trap(_) => assert_eq!(aot_status, RESULT_TRAP),
        }

        // Compare registers (for success cases)
        if aot_status == RESULT_SUCCESS {
            for i in 1..16 {
                assert_eq!(
                    aot_regs[i],
                    vm.cpu.read_gp(i as u8),
                    "register r{} mismatch: aot={} interp={}",
                    i,
                    aot_regs[i],
                    vm.cpu.read_gp(i as u8)
                );
            }
        }
    }

    // ========== Task 0259: AOT produces same results as interpreter ==========

    #[test]
    fn aot_simple_halt() {
        let code = bytecode(&[instr_bytes(Opcode::Halt, 0, 0, 0)]);
        let (status, _, _) = run_aot(&code, 0);
        assert_eq!(status, RESULT_SUCCESS);
    }

    #[test]
    fn aot_simple_revert() {
        let code = bytecode(&[instr_bytes(Opcode::Revert, 0, 0, 0)]);
        let (status, _, _) = run_aot(&code, 0);
        assert_eq!(status, RESULT_REVERT);
    }

    #[test]
    fn aot_addi_matches_interpreter() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        compare_with_interpreter(&code, 0);
    }

    #[test]
    fn addi_aot_interp_wrap_parity() {
        // Addi wraps on overflow by design — the otic compiler relies on
        // this for constant materialisation and two's-complement negation.
        // This test closes audit finding 202 (divergence risk) by asserting
        // AOT and interpreter wrap identically across adversarial inputs.
        // Any future edit to one side that doesn't match the other fails
        // here before shipping.
        for (imm1, imm2) in [
            (-1i32, 1i32),      // u64::MAX + 1 → 0
            (-1, -1),           // u64::MAX + -1 → u64::MAX - 1
            (-2, 2),            // u64::MAX - 1 + 2 → 0
            (0, -1),            // 0 + -1 → u64::MAX (sign-extend)
            (131071, 131071),   // +max18 + +max18 (no wrap)
            (-131072, -131072), // -max18 + -max18 (wraps into u64 top)
            (0, 0),             // no-op
            (1, -1),            // 1 + -1 → 0
            (-131072, 131071),  // -min18 + max18 → -1 → u64::MAX
        ] {
            let code = bytecode(&[
                instr_ri(Opcode::Addi, 1, 0, imm1),
                instr_ri(Opcode::Addi, 2, 1, imm2),
                instr_bytes(Opcode::Halt, 0, 0, 0),
            ]);
            compare_with_interpreter(&code, 0);
        }
    }

    #[test]
    fn memcpy_aot_charges_dynamic_gas_parity_with_interp() {
        // Audit item 215 — host_memcpy used to skip the per-byte
        // dynamic-gas charge that the interpreter pays. Same contract
        // would burn different gas on AOT vs interp validators ⇒
        // consensus fork. This test asserts gas parity for a 1024-byte
        // copy.
        let heap = pyde_vm::memory::HEAP_START as i32;
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap), // dst = HEAP_START
            instr_ri(Opcode::Addi, 2, 0, heap), // src = HEAP_START
            instr_ri(Opcode::Addi, 5, 0, 1024), // len = 1024
            instr_bytes(Opcode::Memcpy, 1, 2, 5),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let mut vm = pyde_vm::vm::Vm::with_gas_limit(1_000_000);
        vm.load(&code).unwrap();
        let _ = vm.execute();
        let interp_gas = vm.gas_used_total;

        let (aot_status, aot_gas, _) = run_aot(&code, 1_000_000);
        assert_eq!(aot_status, RESULT_SUCCESS);
        assert_eq!(
            aot_gas, interp_gas,
            "AOT gas {aot_gas} != interp gas {interp_gas} — \
             host_memcpy dynamic-gas / page-gas parity broken"
        );
    }

    /// Assert AOT and interpreter burn identical gas for a program
    /// that runs to success on both paths. Used for audit item 228a
    /// parity tests across memory-touching ops.
    fn assert_gas_parity(code: &[u8], gas_limit: u64, label: &str) {
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(gas_limit);
        vm.load(code).unwrap();
        let _ = vm.execute();
        let interp_gas = vm.gas_used_total;

        let (aot_status, aot_gas, _) = run_aot(code, gas_limit);
        assert_eq!(aot_status, RESULT_SUCCESS, "{label}: AOT did not succeed");
        assert_eq!(
            aot_gas, interp_gas,
            "{label}: AOT gas {aot_gas} != interp gas {interp_gas}"
        );
    }

    #[test]
    fn load_aot_charges_page_gas_parity_with_interp() {
        // Audit item 228a — host_load bumps vm.memory.page_gas_used
        // via check_access; AOT must drain it into VAR_GAS_USED to
        // match the interpreter's post-step drain.
        let heap = pyde_vm::memory::HEAP_START as i32;
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap), // r1 = HEAP_START
            // load r2, [r1 + 0], width=64
            instr_bytes(
                Opcode::Load,
                2,
                1,
                pyde_vm::isa::encode_mem_immediate(0, pyde_vm::isa::MemWidth::W64).unwrap(),
            ),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        assert_gas_parity(&code, 1_000_000, "Load page-gas parity");
    }

    #[test]
    fn store_aot_charges_page_gas_parity_with_interp() {
        let heap = pyde_vm::memory::HEAP_START as i32;
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap), // r1 = HEAP_START
            instr_ri(Opcode::Addi, 2, 0, 42),   // r2 = value
            // store r2, [r1 + 0], width=64
            instr_bytes(
                Opcode::Store,
                2,
                1,
                pyde_vm::isa::encode_mem_immediate(0, pyde_vm::isa::MemWidth::W64).unwrap(),
            ),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        assert_gas_parity(&code, 1_000_000, "Store page-gas parity");
    }

    #[test]
    fn wload_aot_charges_page_gas_parity_with_interp() {
        let heap = pyde_vm::memory::HEAP_START as i32;
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap),
            // wload w0, [r1 + 0] — reads 32 bytes
            instr_ri(Opcode::Wload, 0, 1, 0),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        assert_gas_parity(&code, 1_000_000, "Wload page-gas parity");
    }

    #[test]
    fn wstore_aot_charges_page_gas_parity_with_interp() {
        let heap = pyde_vm::memory::HEAP_START as i32;
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap),
            // wstore w0, [r1 + 0] — writes 32 bytes (w0 is zero)
            instr_ri(Opcode::Wstore, 0, 1, 0),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        assert_gas_parity(&code, 1_000_000, "Wstore page-gas parity");
    }

    #[test]
    fn push_pop_aot_charges_page_gas_parity_with_interp() {
        // Push writes to the stack page (fresh) → page_gas. Pop
        // reads from the stack page (same page) → no additional
        // page_gas since already touched. Together they exercise
        // both host_push and host_pop drain paths.
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 99),
            instr_bytes(Opcode::Push, 1, 0, 0),
            instr_bytes(Opcode::Pop, 2, 0, 0),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        assert_gas_parity(&code, 1_000_000, "Push/Pop page-gas parity");
    }

    #[test]
    fn poseidon_aot_charges_page_gas_parity_with_interp() {
        // host_poseidon reads `len` bytes from memory via
        // checked_read_slice, which bumps page_gas_used for any
        // fresh page touched. Must drain after.
        let heap = pyde_vm::memory::HEAP_START as i32;
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap), // addr
            instr_ri(Opcode::Addi, 5, 0, 64),   // len (fits in first heap page)
            // poseidon w0 = hash(mem[r1..r1+r5])
            instr_bytes(Opcode::Poseidon, 0, 1, 5),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        assert_gas_parity(&code, 1_000_000, "Poseidon page-gas parity");
    }

    #[test]
    fn memcpy_aot_huge_len_traps() {
        // Audit item 215 — guest passing a huge len used to slip
        // through `as u32` truncation in host_memcpy and either
        // succeed silently (codegen ignored the fault return) or
        // trigger an unbounded host allocation. Now the AOT must trap.
        // ADDI r5, r0, -1 materialises u64::MAX in r5 by sign-extension.
        let heap = pyde_vm::memory::HEAP_START as i32;
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap),
            instr_ri(Opcode::Addi, 2, 0, heap),
            instr_ri(Opcode::Addi, 5, 0, -1), // r5 = u64::MAX
            instr_bytes(Opcode::Memcpy, 1, 2, 5),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let (aot_status, _, _) = run_aot(&code, 10_000_000);
        assert_eq!(aot_status, RESULT_TRAP);
    }

    #[test]
    fn aot_add_two_numbers() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),
            instr_ri(Opcode::Addi, 2, 0, 20),
            instr_bytes(Opcode::Add, 3, 1, 2),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let (status, _, regs) = run_aot(&code, 0);
        assert_eq!(status, RESULT_SUCCESS);
        assert_eq!(regs[3], 30);
    }

    #[test]
    fn aot_add_matches_interpreter() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),
            instr_ri(Opcode::Addi, 2, 0, 20),
            instr_bytes(Opcode::Add, 3, 1, 2),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        compare_with_interpreter(&code, 0);
    }

    #[test]
    fn aot_branch_taken() {
        // BEQ r0, r0 → always taken (both zero)
        let code = bytecode(&[
            instr_ri(Opcode::Beq, 0, 0, 8),     // [0] branch to [8]
            instr_ri(Opcode::Addi, 1, 0, 99),   // [4] skipped
            instr_bytes(Opcode::Halt, 0, 0, 0), // [8]
        ]);
        let (status, _, regs) = run_aot(&code, 0);
        assert_eq!(status, RESULT_SUCCESS);
        assert_eq!(regs[1], 0); // ADDI was skipped
    }

    #[test]
    fn aot_branch_not_taken() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 1),    // [0] r1 = 1
            instr_ri(Opcode::Beq, 1, 0, 8),     // [4] r1 != r0, not taken
            instr_ri(Opcode::Addi, 2, 0, 42),   // [8] runs
            instr_bytes(Opcode::Halt, 0, 0, 0), // [12]
        ]);
        let (status, _, regs) = run_aot(&code, 0);
        assert_eq!(status, RESULT_SUCCESS);
        assert_eq!(regs[2], 42);
    }

    #[test]
    fn aot_loop_matches_interpreter() {
        // Loop: r1 = 10, r2 = 0; while r2 < r1: r2++
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),   // [0]
            instr_ri(Opcode::Addi, 2, 0, 0),    // [4]
            instr_ri(Opcode::Addi, 2, 2, 1),    // [8] loop body
            instr_ri(Opcode::Blt, 2, 1, -4),    // [12] back to [8]
            instr_bytes(Opcode::Halt, 0, 0, 0), // [16]
        ]);
        compare_with_interpreter(&code, 0);
    }

    // ========== Task 0260: AOT gas metering matches interpreter ==========

    #[test]
    fn aot_gas_metering_basic() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),   // 3 gas
            instr_bytes(Opcode::Halt, 0, 0, 0), // 3 gas
        ]);
        let (status, gas_used, _) = run_aot(&code, 1_000_000);
        assert_eq!(status, RESULT_SUCCESS);
        assert_eq!(gas_used, 6);
    }

    #[test]
    fn aot_out_of_gas() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 42),   // 3 gas
            instr_bytes(Opcode::Halt, 0, 0, 0), // 3 gas — total 6
        ]);
        let (status, _, _) = run_aot(&code, 1); // only 1 gas available (needs 6)
        assert_eq!(status, RESULT_OUT_OF_GAS);
    }

    // ========== Task 0262: Benchmark placeholder ==========

    #[test]
    fn aot_fibonacci_matches_interpreter() {
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, 10),   // [0] r1 = 10
            instr_ri(Opcode::Addi, 2, 0, 0),    // [4] r2 = 0 (fib_prev)
            instr_ri(Opcode::Addi, 3, 0, 1),    // [8] r3 = 1 (fib_curr)
            instr_ri(Opcode::Addi, 4, 0, 1),    // [12] r4 = 1 (counter)
            instr_bytes(Opcode::Bge, 4, 1, 24), // [16] if r4 >= r1, jump to [40] halt
            instr_bytes(Opcode::Add, 5, 2, 3),  // [20] r5 = r2 + r3
            instr_bytes(Opcode::Add, 2, 3, 0),  // [24] r2 = r3
            instr_bytes(Opcode::Add, 3, 5, 0),  // [28] r3 = r5
            instr_ri(Opcode::Addi, 4, 4, 1),    // [32] r4++
            instr_ri(Opcode::Jmp, 0, 0, -20),   // [36] jmp to [16]
            instr_bytes(Opcode::Halt, 0, 0, 0), // [40]
        ]);
        compare_with_interpreter(&code, 0);
    }

    // ========== Real Otigen contract: AOT vs interpreter ==========

    /// Compile an Otigen contract and run a function call through both
    /// AOT and interpreter, comparing all GP registers and storage.
    #[test]
    fn aot_real_counter_contract() {
        // Compile Counter contract
        let src = r#"
            contract Counter {
                storage { count: u64, }
                #[constructor]
                pub fn init() { self.count = 0; }
                pub fn increment() { self.count = self.count + 1; }
                pub fn add(n: u64) { self.count = self.count + n; }
                #[view]
                pub fn get_count() -> u64 { return self.count; }
            }
        "#;
        let results = otic::compile_all(src);
        assert_eq!(results.len(), 1);
        let (_, compiled) = &results[0];
        let runtime = &compiled.runtime_bytecode;

        // Compile to native AOT
        let aot = compile_bytecode(runtime).expect("AOT compilation should succeed");

        // Compute selectors using FNV-1a (same as codegen)
        let inc_sel = otic::codegen::compute_selector("increment");
        let get_sel = otic::codegen::compute_selector("get_count");
        let add_sel = otic::codegen::compute_selector("add");

        // --- Test 1: increment via AOT ---
        {
            // AOT: load runtime to set up calldata mapping (r4, r5, memory), then run native
            let mut vm_aot = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
            vm_aot.calldata = inc_sel.to_be_bytes().to_vec();
            vm_aot.load(runtime).unwrap(); // maps calldata to memory, sets r4/r5
            let func = aot.as_fn();
            let mut regs = [0u64; 16];
            // Copy initial GP state from VM (r4=len, r5=ptr, r12=heap)
            for i in 0..16 {
                regs[i] = vm_aot.cpu.read_gp(i as u8);
            }
            let raw = unsafe { func(regs.as_mut_ptr(), 10_000_000, &mut vm_aot as *mut _) };
            let (status, _) = decode_result(raw);
            assert_eq!(status, RESULT_SUCCESS, "AOT increment should succeed");

            // Interpreter
            let mut vm_interp = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
            vm_interp.calldata = inc_sel.to_be_bytes().to_vec();
            vm_interp.load(runtime).unwrap();
            let out = vm_interp.execute();
            assert_eq!(
                out.outcome,
                pyde_vm::vm::Outcome::Success,
                "Interpreter increment should succeed"
            );

            // Compare storage — both should have count = 1
            assert_eq!(
                vm_aot.storage.len(),
                vm_interp.storage.len(),
                "Storage entry count mismatch"
            );
            for (k, v) in &vm_interp.storage {
                let aot_v = vm_aot.storage.get(k);
                assert_eq!(
                    aot_v,
                    Some(v),
                    "Storage mismatch at key {}: interp={:?}, aot={:?}",
                    k,
                    v,
                    aot_v
                );
            }
        }

        // --- Test 2: add(5) via AOT ---
        {
            let mut calldata = add_sel.to_be_bytes().to_vec();
            calldata.extend_from_slice(&5u64.to_le_bytes());

            let mut vm_aot = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
            vm_aot.calldata = calldata.clone();
            vm_aot.load(runtime).unwrap();
            let func = aot.as_fn();
            let mut regs = [0u64; 16];
            for i in 0..16 {
                regs[i] = vm_aot.cpu.read_gp(i as u8);
            }
            let raw = unsafe { func(regs.as_mut_ptr(), 10_000_000, &mut vm_aot as *mut _) };
            let (status, _) = decode_result(raw);
            assert_eq!(status, RESULT_SUCCESS, "AOT add(5) should succeed");

            let mut vm_interp = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
            vm_interp.calldata = calldata;
            vm_interp.load(runtime).unwrap();
            let out = vm_interp.execute();
            assert_eq!(out.outcome, pyde_vm::vm::Outcome::Success);

            for (k, v) in &vm_interp.storage {
                let aot_v = vm_aot.storage.get(k);
                assert_eq!(aot_v, Some(v), "Storage mismatch after add(5)");
            }
        }

        // --- Test 3: increment then get_count (read-after-write) ---
        {
            // First increment via interpreter to get valid storage
            let mut vm_setup = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
            vm_setup.calldata = inc_sel.to_be_bytes().to_vec();
            vm_setup.load(runtime).unwrap();
            let out = vm_setup.execute();
            assert_eq!(out.outcome, pyde_vm::vm::Outcome::Success);
            let storage_after_inc = vm_setup.storage.clone();

            // AOT get_count with pre-populated storage from increment
            let mut vm_aot = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
            vm_aot.calldata = get_sel.to_be_bytes().to_vec();
            vm_aot.storage = storage_after_inc.clone();
            vm_aot.load(runtime).unwrap();
            let func = aot.as_fn();
            let mut regs = [0u64; 16];
            for i in 0..16 {
                regs[i] = vm_aot.cpu.read_gp(i as u8);
            }
            let raw = unsafe { func(regs.as_mut_ptr(), 10_000_000, &mut vm_aot as *mut _) };
            let (status, _) = decode_result(raw);
            assert_eq!(status, RESULT_SUCCESS, "AOT get_count should succeed");

            // Interpreter get_count with same storage
            let mut vm_interp = pyde_vm::vm::Vm::with_gas_limit(10_000_000);
            vm_interp.calldata = get_sel.to_be_bytes().to_vec();
            vm_interp.storage = storage_after_inc;
            vm_interp.load(runtime).unwrap();
            let out = vm_interp.execute();
            assert_eq!(out.outcome, pyde_vm::vm::Outcome::Success);

            // Compare GP r1 (return value)
            assert_eq!(
                regs[1],
                vm_interp.cpu.read_gp(1),
                "get_count return value mismatch: aot={} interp={}",
                regs[1],
                vm_interp.cpu.read_gp(1)
            );
            assert_eq!(regs[1], 1, "get_count should return 1 after increment");
        }
    }

    /// Real contract with events, u256, u256 comparisons, payable, require! — the works.
    #[test]
    fn aot_complex_contract_events_u256() {
        let src = r#"
            contract Vault {
                storage {
                    owner: Address,
                    total: u256,
                    balances: Map<Address, u256>,
                }

                event Deposit {
                    #[indexed]
                    sender: Address,
                    amount: u256,
                }

                event Withdrawal {
                    #[indexed]
                    to: Address,
                    amount: u256,
                }

                #[constructor]
                pub fn init() {
                    self.owner = msg.sender;
                    self.total = 0u256;
                }

                #[payable]
                pub fn deposit() {
                    let amount = msg.value;
                    self.balances[msg.sender] = self.balances[msg.sender] + amount;
                    self.total = self.total + amount;
                    emit Deposit { sender: msg.sender, amount: amount };
                }

                #[view]
                pub fn get_total() -> u256 {
                    return self.total;
                }

                #[view]
                pub fn get_balance(addr: Address) -> u256 {
                    return self.balances[addr];
                }
            }
        "#;
        let results = otic::compile_all(src);
        assert_eq!(results.len(), 1);
        let (_, compiled) = &results[0];
        let runtime = &compiled.runtime_bytecode;

        // AOT compile
        let aot = compile_bytecode(runtime).expect("AOT compilation of Vault should succeed");
        let deposit_sel = otic::codegen::compute_selector("deposit");
        let get_total_sel = otic::codegen::compute_selector("get_total");

        // --- deposit() with msg.value ---
        let caller_addr = {
            let mut a = [0u8; 32];
            a[0] = 0xAA;
            a[1] = 0xBB;
            a
        };
        let ctx = pyde_vm::vm::ExecutionContext {
            caller: caller_addr,
            self_address: {
                let mut a = [0u8; 32];
                a[0] = 0xCC;
                a
            },
            call_value: ethnum::U256::from(1_000_000u64),
            ..Default::default()
        };

        // Interpreter
        let mut vm_interp = pyde_vm::vm::Vm::with_gas_limit_and_context(50_000_000, ctx.clone());
        vm_interp.calldata = deposit_sel.to_be_bytes().to_vec();
        vm_interp.load(runtime).unwrap();
        let out_interp = vm_interp.execute();
        assert_eq!(
            out_interp.outcome,
            pyde_vm::vm::Outcome::Success,
            "Interpreter deposit should succeed"
        );

        // AOT
        let mut vm_aot = pyde_vm::vm::Vm::with_gas_limit_and_context(50_000_000, ctx);
        vm_aot.calldata = deposit_sel.to_be_bytes().to_vec();
        vm_aot.load(runtime).unwrap();
        let func = aot.as_fn();
        let mut regs = [0u64; 16];
        for i in 0..16 {
            regs[i] = vm_aot.cpu.read_gp(i as u8);
        }
        let raw = unsafe { func(regs.as_mut_ptr(), 50_000_000, &mut vm_aot as *mut _) };
        let (status, _) = decode_result(raw);
        assert_eq!(status, RESULT_SUCCESS, "AOT deposit should succeed");

        // Compare storage
        assert_eq!(
            vm_aot.storage.len(),
            vm_interp.storage.len(),
            "Storage count: aot={} interp={}",
            vm_aot.storage.len(),
            vm_interp.storage.len()
        );
        for (k, v) in &vm_interp.storage {
            assert_eq!(
                vm_aot.storage.get(k),
                Some(v),
                "Storage mismatch at key {}",
                k
            );
        }

        // Compare events
        assert_eq!(
            vm_aot.logs.len(),
            vm_interp.logs.len(),
            "Event count: aot={} interp={}",
            vm_aot.logs.len(),
            vm_interp.logs.len()
        );
        for (i, (a, b)) in vm_aot.logs.iter().zip(vm_interp.logs.iter()).enumerate() {
            assert_eq!(a.topics, b.topics, "Event {} topics mismatch", i);
            assert_eq!(a.data, b.data, "Event {} data mismatch", i);
        }

        // --- get_total() after deposit (view, returns u256) ---
        let storage_snap = vm_interp.storage.clone();

        let mut vm_aot2 = pyde_vm::vm::Vm::with_gas_limit(50_000_000);
        vm_aot2.calldata = get_total_sel.to_be_bytes().to_vec();
        vm_aot2.storage = storage_snap.clone();
        vm_aot2.load(runtime).unwrap();
        let mut regs2 = [0u64; 16];
        for i in 0..16 {
            regs2[i] = vm_aot2.cpu.read_gp(i as u8);
        }
        let raw2 = unsafe { func(regs2.as_mut_ptr(), 50_000_000, &mut vm_aot2 as *mut _) };
        let (status2, _) = decode_result(raw2);
        assert_eq!(status2, RESULT_SUCCESS, "AOT get_total should succeed");

        let mut vm_interp2 = pyde_vm::vm::Vm::with_gas_limit(50_000_000);
        vm_interp2.calldata = get_total_sel.to_be_bytes().to_vec();
        vm_interp2.storage = storage_snap;
        vm_interp2.load(runtime).unwrap();
        let out2 = vm_interp2.execute();
        assert_eq!(out2.outcome, pyde_vm::vm::Outcome::Success);

        // Compare wide return (r1=ptr, r2=len for u256 returns)
        assert_eq!(
            regs2[1],
            vm_interp2.cpu.read_gp(1),
            "r1 mismatch on get_total"
        );
        assert_eq!(
            regs2[2],
            vm_interp2.cpu.read_gp(2),
            "r2 mismatch on get_total"
        );
    }

    /// The hardest test: factory deploys child, cross-contract calls it,
    /// events emitted, u256 math, map storage. AOT must match interpreter exactly.
    #[test]
    fn aot_factory_cross_contract_full() {
        let src = r#"
            contract Token {
                storage {
                    supply: u256,
                    balances: Map<Address, u256>,
                }

                event Mint {
                    #[indexed]
                    to: Address,
                    amount: u256,
                }

                #[constructor]
                pub fn init(initial: u256) {
                    self.supply = initial;
                    self.balances[msg.sender] = initial;
                }

                pub fn mint(to: Address, amount: u256) {
                    self.supply = self.supply + amount;
                    self.balances[to] = self.balances[to] + amount;
                    emit Mint { to: to, amount: amount };
                }

                #[view]
                pub fn get_supply() -> u256 {
                    return self.supply;
                }

                #[view]
                pub fn balance_of(addr: Address) -> u256 {
                    return self.balances[addr];
                }
            }

            contract Factory {
                storage {
                    last_token: Address,
                    token_count: u64,
                }

                event TokenCreated {
                    token: Address,
                }

                #[constructor]
                pub fn init() {
                    self.token_count = 0;
                }

                pub fn create_token(initial_supply: u256) {
                    let t = deploy!(Token, initial_supply);
                    self.last_token = address(t);
                    self.token_count = self.token_count + 1;
                    emit TokenCreated { token: address(t) };
                }

                pub fn mint_on_last(to: Address, amount: u256) {
                    Token::at(self.last_token).mint(to, amount);
                }

                #[view]
                pub fn get_token_count() -> u64 {
                    return self.token_count;
                }

                #[view]
                pub fn get_last_token() -> Address {
                    return self.last_token;
                }
            }
        "#;
        let all = otic::compile_all(src);
        assert_eq!(all.len(), 2, "Should compile Token and Factory");
        let (_, factory_compiled) = &all[1];
        let runtime = &factory_compiled.runtime_bytecode;

        let aot = compile_bytecode(runtime).expect("AOT compilation of Factory should succeed");

        // --- create_token(1000000u256) ---
        let create_sel = otic::codegen::compute_selector("create_token");
        let mut calldata = create_sel.to_be_bytes().to_vec();
        // u256 arg: 1,000,000 as 32-byte LE
        let mut supply_bytes = [0u8; 32];
        supply_bytes[..8].copy_from_slice(&1_000_000u64.to_le_bytes());
        calldata.extend_from_slice(&supply_bytes);

        let factory_addr = {
            let mut a = [0u8; 32];
            a[0] = 0xFF;
            a
        };
        let caller = {
            let mut a = [0u8; 32];
            a[0] = 0xAA;
            a
        };
        let ctx = pyde_vm::vm::ExecutionContext {
            caller,
            self_address: factory_addr,
            ..Default::default()
        };

        // Run both through interpreter and AOT
        let run = |use_aot: bool| -> pyde_vm::vm::Vm {
            let mut vm = pyde_vm::vm::Vm::with_gas_limit_and_context(100_000_000, ctx.clone());
            vm.calldata = calldata.clone();
            vm.load(runtime).unwrap();

            if use_aot {
                let func = aot.as_fn();
                let mut regs = [0u64; 16];
                for i in 0..16 {
                    regs[i] = vm.cpu.read_gp(i as u8);
                }
                let raw = unsafe { func(regs.as_mut_ptr(), 100_000_000, &mut vm as *mut _) };
                let (status, _) = decode_result(raw);
                assert_eq!(
                    status, RESULT_SUCCESS,
                    "create_token should succeed (aot={use_aot})"
                );
            } else {
                let out = vm.execute();
                assert_eq!(
                    out.outcome,
                    pyde_vm::vm::Outcome::Success,
                    "create_token should succeed (interpreter)"
                );
            }
            vm
        };

        let vm_interp = run(false);
        let vm_aot = run(true);

        // Both should have the same storage entries (keys AND values)
        assert_eq!(
            vm_aot.storage.len(),
            vm_interp.storage.len(),
            "Storage count mismatch: aot={} interp={}",
            vm_aot.storage.len(),
            vm_interp.storage.len()
        );

        for (k, v) in &vm_interp.storage {
            let aot_v = vm_aot.storage.get(k);
            assert_eq!(
                aot_v,
                Some(v),
                "Storage mismatch at key {}...",
                &k.to_string()[..20]
            );
        }

        // Both should emit the same events
        assert_eq!(
            vm_aot.logs.len(),
            vm_interp.logs.len(),
            "Event count mismatch: aot={} interp={}",
            vm_aot.logs.len(),
            vm_interp.logs.len()
        );
        for (i, (a, b)) in vm_aot.logs.iter().zip(vm_interp.logs.iter()).enumerate() {
            assert_eq!(a.topics, b.topics, "Event {i} topics mismatch");
            assert_eq!(a.data, b.data, "Event {i} data mismatch");
        }
    }

    // ========== CallExt delegation via host_exec_opcode ==========

    #[test]
    fn aot_callext_delegates_to_interpreter() {
        use pyde_vm::memory::HEAP_START;

        // Child contract: loads calldata[0] into r1, halts.
        let callee_code = bytecode(&[
            instr_bytes(Opcode::Load, 1, 5, 0x03), // r1 = load64(r5+0) = calldata[0]
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        // Caller: write 99 to heap, CallExt to child, read return.
        // imm encoding: len_reg(r3)=3, gas_reg(r7)=7, result_reg(r2)=2
        // Use r2 for success flag so r1 holds the child's return value.
        let imm: u32 = (3 & 0xF)            // len_reg = r3
            | ((7 & 0xF) << 4)              // gas_reg = r7
            | ((2 & 0xF) << 8); // result_reg = r2
        let heap = HEAP_START as i32;
        let caller_code = bytecode(&[
            instr_ri(Opcode::Addi, 8, 0, heap), // [0]  r8 = HEAP_START (calldata ptr)
            instr_ri(Opcode::Addi, 6, 0, 99),   // [4]  r6 = 99
            instr_bytes(Opcode::Store, 6, 8, 0x03), // [8]  mem[HEAP_START] = 99 (64-bit)
            instr_ri(Opcode::Addi, 3, 0, 8),    // [12] r3 = calldata len = 8
            instr_ri(Opcode::Addi, 7, 0, 0),    // [16] r7 = gas = 0 (forward all)
            instr_bytes(Opcode::CallExt, 0, 8, imm), // [20] call child at w0, calldata at r8
            // After: r1 = child's return (99), r2 = success flag
            instr_bytes(Opcode::Halt, 0, 0, 0), // [24]
        ]);

        // Set up target address in wide register 0
        let mut target_addr = [0u8; 32];
        target_addr[0] = 0xBB;

        // --- Run with AOT ---
        let compiled = compile_bytecode(&caller_code).unwrap();
        let func = compiled.as_fn();
        let mut regs = [0u64; 16];
        let mut vm = pyde_vm::vm::Vm::with_gas_limit(1_000_000);
        vm.cpu
            .write_wide(0, pyde_vm::wide::U256::from_le_bytes(target_addr));
        vm.contracts.insert(target_addr, callee_code.clone());
        let raw = unsafe { func(regs.as_mut_ptr(), 1_000_000, &mut vm as *mut _) };
        let (status, _gas_used) = decode_result(raw);

        assert_eq!(status, RESULT_SUCCESS, "AOT CallExt should succeed");
        // After host_sync_gp_from_vm, GP regs are reloaded from vm.cpu.gp
        let return_val = vm.cpu.read_gp(1);
        assert_eq!(return_val, 99, "r1 should hold child's return value (99)");
    }

    /// Run a program on both interp and AOT against pre-prepared VM
    /// state (storage/wide-regs/contracts), asserting exact gas
    /// parity. The closure receives the VM right after `with_gas_limit`
    /// and before `load`, so callers can inject wide-reg values,
    /// storage backends, contracts, etc.
    ///
    /// Audit 228c — used to surface every per-opcode gas divergence
    /// between AOT and interpreter (storage cold-access, log
    /// dynamic, gas refund, ...).
    fn assert_gas_parity_with_state<F: FnMut(&mut pyde_vm::vm::Vm)>(
        code: &[u8],
        gas_limit: u64,
        label: &str,
        mut prepare: F,
    ) {
        // Interpreter
        let mut interp_vm = pyde_vm::vm::Vm::with_gas_limit(gas_limit);
        prepare(&mut interp_vm);
        interp_vm.load(code).unwrap();
        let _ = interp_vm.execute();
        let interp_gas = interp_vm.gas_used_total;

        // AOT
        let compiled = compile_bytecode(code).unwrap();
        let func = compiled.as_fn();
        let mut regs = [0u64; 16];
        let mut aot_vm = pyde_vm::vm::Vm::with_gas_limit(gas_limit);
        prepare(&mut aot_vm);
        let raw = unsafe { func(regs.as_mut_ptr(), gas_limit, &mut aot_vm as *mut _) };
        let (aot_status, aot_gas) = decode_result(raw);

        assert_eq!(
            aot_status, RESULT_SUCCESS,
            "{label}: AOT did not succeed (status={aot_status})"
        );
        assert_eq!(
            aot_gas, interp_gas,
            "{label}: AOT gas {aot_gas} != interp gas {interp_gas}"
        );
    }

    #[test]
    fn sload_cold_aot_gas_parity_with_interp() {
        // Audit 228c — interp charges 1800 cold-access surcharge on
        // first Sload of a key per-tx (EIP-2929). AOT host_sload
        // skips this entirely. Same contract burns Sload base only
        // on AOT vs base+1800 on interp.
        let code = bytecode(&[
            instr_bytes(Opcode::Sload, 1, 0, 0), // sload w1, w0 (mode 0 = wide)
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        assert_gas_parity_with_state(&code, 1_000_000, "Sload cold", |vm| {
            // w0 = arbitrary slot (key derivation handles it)
            vm.cpu.write_wide(0, pyde_vm::wide::U256::from(0x1234u64));
        });
    }

    #[test]
    fn sload_warm_aot_gas_parity_with_interp() {
        // After the first Sload, the second (same key) should be
        // warm: just base, no surcharge.
        let code = bytecode(&[
            instr_bytes(Opcode::Sload, 1, 0, 0),
            instr_bytes(Opcode::Sload, 2, 0, 0),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        assert_gas_parity_with_state(&code, 1_000_000, "Sload warm", |vm| {
            vm.cpu.write_wide(0, pyde_vm::wide::U256::from(0x1234u64));
        });
    }

    #[test]
    fn sstore_cold_aot_gas_parity_with_interp() {
        // Cold Sstore: 2000 base + 1800 surcharge.
        let code = bytecode(&[
            instr_bytes(Opcode::Sstore, 1, 0, 0), // sstore w1 → slot in w0
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        assert_gas_parity_with_state(&code, 1_000_000, "Sstore cold", |vm| {
            vm.cpu.write_wide(0, pyde_vm::wide::U256::from(0x1234u64));
            vm.cpu.write_wide(1, pyde_vm::wide::U256::from(0xCAFEu64));
        });
    }

    #[test]
    fn sstoreb_aot_gas_parity_with_interp() {
        // Audit 228d — Sstore mode 1 (sstoreb): reads
        // mem[ptr..ptr+len] and writes those bytes into storage.
        // Charges 2000 base + 1800 cold + (len/8)*3 dynamic gas.
        // AOT used to trap on mode 1; now wired through host_sstoreb.
        use pyde_vm::memory::HEAP_START;
        let heap = HEAP_START as i32;
        let code = bytecode(&[
            // Populate mem[heap..heap+24] with some bytes
            instr_ri(Opcode::Addi, 1, 0, heap), // r1 = HEAP_START
            instr_ri(Opcode::Addi, 2, 0, 0xABCD), // r2 = sentinel
            instr_bytes(
                Opcode::Store,
                2,
                1,
                pyde_vm::isa::encode_mem_immediate(0, pyde_vm::isa::MemWidth::W64).unwrap(),
            ),
            instr_bytes(
                Opcode::Store,
                2,
                1,
                pyde_vm::isa::encode_mem_immediate(8, pyde_vm::isa::MemWidth::W64).unwrap(),
            ),
            instr_bytes(
                Opcode::Store,
                2,
                1,
                pyde_vm::isa::encode_mem_immediate(16, pyde_vm::isa::MemWidth::W64).unwrap(),
            ),
            instr_ri(Opcode::Addi, 3, 0, 24), // r3 = len = 24 bytes
            // sstoreb: imm = 1 (mode) | (1 << 2) (ptr_reg=r1) | (3 << 6) (len_reg=r3)
            instr_bytes(Opcode::Sstore, 0, 0, 1 | (1 << 2) | (3 << 6)),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        assert_gas_parity_with_state(&code, 1_000_000, "Sstoreb", |vm| {
            vm.cpu.write_wide(0, pyde_vm::wide::U256::from(0x1234u64));
        });
    }

    #[test]
    fn sloadb_aot_gas_parity_with_interp() {
        // Audit 228d — Sload mode 1 (sloadb): reads raw bytes from
        // storage[slot] into memory, writes length to gp[rd].
        // AOT used to fall through to wide mode (silently wrong).
        // Now wired through host_sloadb. Pre-populate storage so
        // there's data to load + dynamic gas applies.
        use pyde_vm::memory::HEAP_START;
        let heap = HEAP_START as i32;
        let code = bytecode(&[
            instr_ri(Opcode::Addi, 1, 0, heap),
            // sloadb r2, w0, ptr_reg=r1: imm = 1 (mode) | (1 << 2) (ptr_reg)
            instr_bytes(Opcode::Sload, 2, 0, 1 | (1 << 2)),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        assert_gas_parity_with_state(&code, 1_000_000, "Sloadb", |vm| {
            vm.cpu.write_wide(0, pyde_vm::wide::U256::from(0x1234u64));
            // Pre-populate the storage key with 24 bytes.
            let key = vm.derive_storage_key(pyde_vm::wide::U256::from(0x1234u64));
            vm.storage.insert(key, vec![0xAB; 24]);
        });
    }

    #[test]
    fn sdelete_aot_gas_parity_with_interp() {
        // Sdelete on a populated key: 2000 base + 1800 cold + 1500
        // refund (interp at `pvm/src/vm.rs:996-1004`). Tests parity
        // for both gas_used_total and gas_refund.
        let code = bytecode(&[
            instr_bytes(Opcode::Sstore, 1, 0, 0), // populate so refund applies
            instr_bytes(Opcode::Sdelete, 0, 0, 0),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let mut interp_vm = pyde_vm::vm::Vm::with_gas_limit(1_000_000);
        interp_vm
            .cpu
            .write_wide(0, pyde_vm::wide::U256::from(0x1234u64));
        interp_vm
            .cpu
            .write_wide(1, pyde_vm::wide::U256::from(0xCAFEu64));
        interp_vm.load(&code).unwrap();
        let _ = interp_vm.execute();
        let interp_gas = interp_vm.gas_used_total;
        let interp_refund = interp_vm.gas_refund;

        let compiled = compile_bytecode(&code).unwrap();
        let func = compiled.as_fn();
        let mut regs = [0u64; 16];
        let mut aot_vm = pyde_vm::vm::Vm::with_gas_limit(1_000_000);
        aot_vm
            .cpu
            .write_wide(0, pyde_vm::wide::U256::from(0x1234u64));
        aot_vm
            .cpu
            .write_wide(1, pyde_vm::wide::U256::from(0xCAFEu64));
        let raw = unsafe { func(regs.as_mut_ptr(), 1_000_000, &mut aot_vm as *mut _) };
        let (aot_status, aot_gas) = decode_result(raw);
        let aot_refund = aot_vm.gas_refund;

        assert_eq!(aot_status, RESULT_SUCCESS);
        assert_eq!(
            aot_gas, interp_gas,
            "Sdelete gas parity broken: AOT={aot_gas} interp={interp_gas}"
        );
        assert_eq!(
            aot_refund, interp_refund,
            "Sdelete refund parity broken: AOT={aot_refund} interp={interp_refund}"
        );
    }

    #[test]
    fn log_aot_gas_parity_with_interp() {
        // Log charges `100 + data_len*8 + num_topics*50` dynamic gas.
        // AOT host_log doesn't. Test with 2 topics + 16 bytes of data
        // → expected dynamic = 100 + 16*8 + 2*50 = 328 gas extra
        // on interp vs AOT.
        use pyde_vm::memory::HEAP_START;
        let heap = HEAP_START as i32;
        let imm = 2u32; // 2 topics
        let code = bytecode(&[
            // Set up descriptor at HEAP_START:
            //   topic0 (32 zero bytes), topic1 (32 zero bytes),
            //   data_ptr (8 bytes = HEAP_START+64+16),
            //   data_len (8 bytes = 16)
            instr_ri(Opcode::Addi, 1, 0, heap),
            instr_ri(Opcode::Addi, 2, 0, heap + 64 + 16), // data_ptr value
            instr_bytes(
                Opcode::Store,
                2,
                1,
                pyde_vm::isa::encode_mem_immediate(64, pyde_vm::isa::MemWidth::W64).unwrap(),
            ), // mem[heap+64] = heap+80 (data ptr)
            instr_ri(Opcode::Addi, 3, 0, 16),             // data_len value = 16
            instr_bytes(
                Opcode::Store,
                3,
                1,
                pyde_vm::isa::encode_mem_immediate(72, pyde_vm::isa::MemWidth::W64).unwrap(),
            ), // mem[heap+72] = 16
            // log r1, 2 (descriptor at r1, 2 topics)
            instr_bytes(Opcode::Log, 0, 1, imm),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        assert_gas_parity_with_state(&code, 1_000_000, "Log dynamic", |_vm| {});
    }

    #[test]
    fn callext_aot_gas_parity_with_interp() {
        // Audit item 228b — delegated ops (CallExt/Delegate/Create/
        // VerifySig/MerkleVerify) charge gas into `vm.gas_used_total`
        // via step() but the AOT's VAR_GAS_USED is independent.
        // Before 228b, AOT reported ~zero gas for delegated ops ⇒
        // consensus fork with interpreter. This test asserts exact
        // gas equality for a CallExt-heavy program.
        use pyde_vm::memory::HEAP_START;

        let callee_code = bytecode(&[
            instr_bytes(Opcode::Load, 1, 5, 0x03),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);
        let imm: u32 = (3 & 0xF) | ((7 & 0xF) << 4) | ((2 & 0xF) << 8);
        let heap = HEAP_START as i32;
        let caller_code = bytecode(&[
            instr_ri(Opcode::Addi, 8, 0, heap),
            instr_ri(Opcode::Addi, 6, 0, 99),
            instr_bytes(Opcode::Store, 6, 8, 0x03),
            instr_ri(Opcode::Addi, 3, 0, 8),
            instr_ri(Opcode::Addi, 7, 0, 0),
            instr_bytes(Opcode::CallExt, 0, 8, imm),
            instr_bytes(Opcode::Halt, 0, 0, 0),
        ]);

        let mut target_addr = [0u8; 32];
        target_addr[0] = 0xBB;

        // --- Interpreter run ---
        let mut interp_vm = pyde_vm::vm::Vm::with_gas_limit(1_000_000);
        interp_vm
            .cpu
            .write_wide(0, pyde_vm::wide::U256::from_le_bytes(target_addr));
        interp_vm.contracts.insert(target_addr, callee_code.clone());
        interp_vm.load(&caller_code).unwrap();
        let _ = interp_vm.execute();
        let interp_gas = interp_vm.gas_used_total;

        // --- AOT run ---
        let compiled = compile_bytecode(&caller_code).unwrap();
        let func = compiled.as_fn();
        let mut regs = [0u64; 16];
        let mut aot_vm = pyde_vm::vm::Vm::with_gas_limit(1_000_000);
        aot_vm
            .cpu
            .write_wide(0, pyde_vm::wide::U256::from_le_bytes(target_addr));
        aot_vm.contracts.insert(target_addr, callee_code.clone());
        let raw = unsafe { func(regs.as_mut_ptr(), 1_000_000, &mut aot_vm as *mut _) };
        let (aot_status, aot_gas) = decode_result(raw);

        assert_eq!(aot_status, RESULT_SUCCESS);
        assert_eq!(
            aot_gas, interp_gas,
            "CallExt gas parity broken: AOT={aot_gas} interp={interp_gas}"
        );
    }
}
