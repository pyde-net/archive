# Prover v2 — Implementation Roadmap

> Tracks progress for the custom STARK prover rebuild.
> Each task is atomic. Dependencies noted where critical.

Legend:
- `[x]` = complete
- `[ ]` = not started
- `[~]` = in progress

---

## Phase 1: Core Infrastructure

### M1.1 — Trace Format (144 columns)

- [x] Define column layout (col module with constants)
- [x] TraceRow struct with get/set/set_u64/set_flag helpers
- [x] Opcode bit decomposition (set_opcode_bits)
- [x] Register selector helpers (set_rd_sel, set_rs1_sel, set_rs2_sel)
- [x] ExecutionTrace with push, pad_to_power_of_two, to_row_major_values
- [x] Wide register columns (8 regs × 4 limbs = 32 cols)
- [x] Memory columns (addr, val[4], width, is_write)
- [x] Storage columns (key[4], val[4], len, is_write)
- [x] Gas columns (step, cumulative)
- [x] Branch/call columns (taken, diff_inv, call_depth)
- [x] Wide carry/quotient columns (4 + 4)
- [x] Tests: column count, zero row, set/get, opcode bits, selectors, padding

### M1.2 — Constraint Evaluator (constraint.rs)

- [x] Opcode constants for all 65 ISA opcodes (including Invalid)
- [x] evaluate_constraints generic over field type
- [x] Opcode selector (6-bit product)
- [x] Register multiplexer: op_a = mux(rs1_sel, gp_regs)
- [x] Register multiplexer: op_b = mux(rs2_sel, gp_regs) for register-register ops
- [x] Result writeback: gp[rd] = result for GP-writing ops
- [x] GP arithmetic: ADD, SUB, MUL, DIV, MOD, ADDI, FIELDMUL
- [x] Comparisons: EQ (diff_inv), LT/GT (comparison diff), SLT/SGT (boolean)
- [x] Shifts: SHL (result = a * 2^shift), SHR/SAR (a = result * 2^shift + remainder)
- [x] Memory: LOAD/POP (result = mem_val), STORE/PUSH (op_a = mem_val), WLOAD/WSTORE flags
- [x] Storage: SLOAD/SSTORE/SDELETE flag constraints
- [x] Control flow: sequential PC, JMP, BEQ, BNE, BLT (with comparison), BGE (with comparison)
- [x] Call/Ret: call_depth increment/decrement, CALLEXT/DELEGATE
- [x] Halt/Revert/Selfdestruct: is_final = 1
- [x] Assert: op_a == 0 → final (via diff_inv)
- [x] Gas: monotonic accumulation
- [x] Boolean constraints: VERIFYSIG, MERKLEVERIFY, WEQ, WLT
- [x] Wide carry booleans: WADD/WSUB carry ∈ {0, 1}
- [x] Memory inactive: zero columns when not memory op
- [x] Storage inactive: zero columns when not storage op
- [x] LOG: must not touch storage
- [x] Tests: all 65 opcode constants match PVM ISA

### M1.3 — AIR Adapter (air_adapter.rs)

- [x] PvmAir struct implementing BaseAir + Air
- [x] opcode_sel macro for type-safe selector building
- [x] All constraints from M1.2 translated to AirBuilder API
- [x] BLT/BGE branch-taken verification via op_aux

### M1.4 — Prover + Verifier (prover.rs)

- [x] Plonky3 type aliases (Perm, Hash, Compress, Pcs, Challenger, etc.)
- [x] build_perm(), build_config(), build_challenger()
- [x] FRI configuration: log_blowup=3, num_queries=24, pow_bits=12
- [x] prove(): trace → padded → matrix → STARK proof
- [x] verify(): proof → FRI check → constraint re-evaluation → accept/reject
- [x] serialize_proof(): JSON + zstd compression
- [x] deserialize_proof(): decompress + deserialize
- [x] PublicInputs struct
- [x] Tests: prove_and_verify_minimal (16-row ADDI)
- [x] Tests: prove_add_program (register-register ADD with rs2_sel)
- [x] Tests: proof_roundtrip (serialize → deserialize → verify)

---

## Phase 2: Trace Recording

### M2.1 — Recorder (recorder.rs)

- [x] record_execution(vm) → (ExecutionTrace, Outcome)
- [x] Per-step state capture: PC, opcode, decoded fields
- [x] GP register capture (all 16, post-step)
- [x] Wide register capture (all 8 × 4 limbs, post-step)
- [x] Opcode bit decomposition
- [x] Register selector generation (rd_sel, rs1_sel, rs2_sel)
- [x] op_a from gp[rs1], op_b from gp[rs2] or immediate
- [x] op_result from gp[rd] (post-step)
- [x] op_aux: DIV remainder, MOD quotient, comparison diff, shift remainder
- [x] Memory access capture: addr, val[4], width, is_write
- [x] Storage access capture: key[4], val[4], len, is_write (placeholder)
- [x] Gas step and cumulative
- [x] Flags: is_memory_op, is_storage_op, is_final
- [x] Branch taken + diff_inv for BEQ/BNE/BLT/BGE
- [x] Call depth tracking (CALL +1, RET -1)
- [ ] Wide carry/quotient for WADD/WSUB/WDIV/WMOD
- [x] SHL: set op_b = 2^shift_amount
- [x] SHR/SAR: set op_b = 2^shift_amount, op_aux = remainder
- [x] Tests: trace captures ADDI, ADD with register selectors
- [x] Tests: trace captures DIV with remainder in op_aux
- [ ] Tests: trace captures LOAD/STORE with memory columns
- [ ] Tests: trace captures branch with taken/not-taken
- [x] Tests: end-to-end PVM → trace → prove → verify (ADD, MUL, DIV)

---

## Phase 3: Lookup Tables (Bitwise Operations)

### M3.1 — Lookup Table (lookup.rs)

- [ ] Precomputed 8-bit AND/OR/XOR table (65,536 rows)
- [ ] NOT table (256 rows)
- [ ] Logup argument: prover-side multiplicities
- [ ] Logup argument: random challenge β from Fiat-Shamir
- [ ] Logup argument: running sum verification
- [ ] Integration with constraint evaluator
- [ ] Tests: AND correctness via lookup
- [ ] Tests: XOR correctness via lookup
- [ ] Tests: NOT correctness via lookup
- [ ] Benchmark: lookup overhead vs bit-decomposition overhead

### M3.2 — Wide Bitwise via Lookup

- [ ] WAND: 32 byte-level lookups (256-bit = 32 bytes)
- [ ] WOR: 32 byte-level lookups
- [ ] WXOR: 32 byte-level lookups
- [ ] WNOT: 32 byte-level NOT lookups
- [ ] Tests: wide bitwise correctness

---

## Phase 4: Cross-Table Verification

### M4.1 — Memory AIR (memory_air.rs)

- [ ] MemoryTrace: sorted by (address, timestamp)
- [ ] MemoryAir constraints: read-after-write consistency
- [ ] First-access-is-zero constraint
- [ ] Timestamp ordering constraint
- [ ] Build memory trace from execution trace side channel
- [ ] Permutation argument: execution ↔ sorted memory
- [ ] STARK proof generation for memory table
- [ ] Tests: write then read returns correct value
- [ ] Tests: tampered read value detected

### M4.2 — Poseidon2 AIR (poseidon2_air.rs)

- [ ] Poseidon2 round constraints (S-box x^7, MDS, round constants)
- [ ] Build Poseidon2 trace from hash requests
- [ ] Hash bus: execution ↔ Poseidon2 table permutation
- [ ] STARK proof generation for Poseidon2 table
- [ ] Tests: hash computation correctness

### M4.3 — Range-Check AIR (range_check_air.rs)

- [ ] Decompose u64 into 4 × 16-bit limbs
- [ ] Bit-level boolean constraints for each limb
- [ ] Range-check bus: execution ↔ range-check table
- [ ] Tests: valid u64 passes, invalid value fails

---

## Phase 5: Multi-Table Proving

### M5.1 — Multi-Table Orchestration (multi_table.rs)

- [ ] record_with_side_channels(): capture memory/hash/range-check logs
- [ ] Build memory trace from memory log
- [ ] Build range-check trace from comparison diffs + shift values
- [ ] Generate STARK proofs for all sub-tables
- [ ] Cross-table permutation verification
- [ ] MultiTableProof struct with all sub-proofs
- [ ] prove_group(): multiple txs → one combined proof
- [ ] verify_multi_table(): verify all sub-proofs + permutations
- [ ] Tests: single tx prove + verify
- [ ] Tests: group of 3 txs prove + verify

---

## Phase 6: Pipeline + Block Proving

### M6.1 — Conflict-Based Grouping

- [ ] ConflictGraph: build from transaction access lists
- [ ] Connected components → conflict groups
- [ ] Within-group ordering (by sender + nonce)
- [ ] Tests: disjoint access lists → separate groups
- [ ] Tests: overlapping access lists → same group

### M6.2 — Prover Pipeline (pipeline.rs)

- [x] ScheduledBlock: groups of conflicting txs
- [x] Transaction, Group, GroupProof, BlockProof data structures
- [x] prove_group(): execute txs sequentially → combined trace → ONE STARK proof
- [x] prove_assigned_groups(): prove subset of groups (committee workflow)
- [x] All groups start from same pre_state_root (no state chain)
- [ ] State diff capture per group
- [ ] ProverTask: status tracking, timeout, deadline
- [ ] ProverReward: compute rewards for submitted proofs
- [x] Tests: single group prove + verify
- [x] Tests: multi-group parallel prove + verify

### M6.3 — Block Composition (pipeline.rs)

- [x] compose_block_proof(): collect group proofs, verify STARK + consistency
- [x] verify_block_proof(): verify each group STARK + gas consistency
- [x] Tests: compose 2 groups into block proof
- [x] Tests: benchmark (5 txs / 2 groups → 53 KB, 94ms prove)
- [ ] Tests: detect overlapping access lists
- [ ] Tests: state diff merge produces correct post_state

---

## Phase 7: Integration + Benchmarking

### M7.1 — End-to-End Tests

- [ ] ERC20-style token transfer (55+ instructions)
- [ ] DEX swap computation (80+ instructions)
- [ ] Memory-intensive program (store/load patterns)
- [ ] Mixed-type block (20 txs, 4 conflict groups)
- [ ] Proof size measurement (target: 50-100 KB per group)

### M7.2 — Benchmarking

- [ ] Group proving time (target: <1500ms on server hardware)
- [ ] Proof size (target: <100 KB compressed per group)
- [ ] Verification time (target: <200ms per group, <5ms with recursion)
- [ ] AOT dry-run time (target: <100ms)
- [ ] Full pipeline: 20 txs → 4 groups → prove → aggregate → verify
- [ ] Comparison: v1 (880 cols) vs v2 (144 cols) on same workload

---

## Phase 8: Future Optimizations (Post-Launch)

- [ ] GPU-accelerated FRI (CUDA/Metal backend for NTT + Merkle)
- [ ] Recursive STARK verifier circuit (compress N proofs into 1)
- [ ] Column splitting: separate conditional tables for rare opcodes
- [ ] Proof batching: verify multiple group proofs with shared randomness
- [ ] Prover market: dynamic committee sizing based on demand

---

## Progress Summary

| Phase | Tasks | Done | Status |
|-------|-------|------|--------|
| Phase 1: Core Infrastructure | 45 | 45 | **COMPLETE** |
| Phase 2: Trace Recording | 20 | 17 | **85%** |
| Phase 3: Lookup Tables | 10 | 0 | Not started |
| Phase 4: Cross-Table | 12 | 0 | Not started |
| Phase 5: Multi-Table | 10 | 0 | Not started |
| Phase 6: Pipeline + Block | 15 | 10 | **67%** |
| Phase 7: Integration | 11 | 0 | Not started |
| Phase 8: Future | 5 | 0 | Deferred |
| **Total** | **128** | **72** | **56%** |
