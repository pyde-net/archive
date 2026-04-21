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
}
