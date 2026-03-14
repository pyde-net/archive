# Pyde Implementation Roadmap

> Micro-task breakdown for building the Pyde blockchain from scratch.
> Each task is a single, atomic unit of work (1–4 hours).
> Tasks are grouped by phase → milestone → component.
> Dependencies are noted where critical.

Legend:

- `[ ]` = not started
- `[x]` = complete
- `[~]` = in progress
- `[!]` = blocked

---

## Phase 0: Cryptographic Primitives

Everything else depends on these. Build and test in isolation first.

### M0.1 — Poseidon2 Hash

- [x] 0001 — Create `pyde-crypto` crate with workspace config
- [x] 0002 — Define `Hash256` type (32-byte wrapper with Display, Debug, Eq, Ord, Serialize)
- [x] 0003 — Define Poseidon2 Goldilocks field parameters (MDS matrix, round constants)
- [x] 0004 — Implement Poseidon2 permutation (full rounds)
- [x] 0005 — Implement Poseidon2 permutation (partial rounds)
- [x] 0006 — Implement Poseidon2 sponge construction (absorb/squeeze)
- [x] 0007 — Implement `poseidon2_hash(data: &[u8]) -> Hash256`
- [x] 0008 — Implement `poseidon2_pair(left: Hash256, right: Hash256) -> Hash256`
- [x] 0009 — Implement `poseidon2_many(elements: &[Hash256]) -> Hash256` (variable-length sponge)
- [x] 0010 — Add known-answer test vectors (at least 20)
- [x] 0011 — Test edge cases: empty input, single byte, max-length input
- [x] 0012 — Benchmark: hash throughput (MB/s) on single core
- [x] 0013 — Benchmark: pair hashing throughput (hashes/sec)
- [x] 0014 — Add `no_std` support for ZK circuit compatibility
- [x] 0015 — Verify algebraic degree matches expected security level

### M0.2 — FALCON-512 Signatures

- [x] 0016 — Add FALCON-512 dependency (pqcrypto or custom binding)
- [x] 0017 — Define `FalconPublicKey` type (897 bytes)
- [x] 0018 — Define `FalconSecretKey` type
- [x] 0019 — Define `FalconSignature` type (666 bytes average)
- [x] 0020 — Implement `falcon_keygen() -> (FalconPublicKey, FalconSecretKey)`
- [x] 0021 — Implement `falcon_sign(sk: &FalconSecretKey, msg: &[u8]) -> FalconSignature`
- [x] 0022 — Implement `falcon_verify(pk: &FalconPublicKey, msg: &[u8], sig: &FalconSignature) -> bool`
- [x] 0023 — Implement batch verification (verify N signatures faster)
- [x] 0024 — Add serialization/deserialization for all FALCON types
- [x] 0025 — Test: sign/verify roundtrip
- [x] 0026 — Test: tampered message fails verification
- [x] 0027 — Test: tampered signature fails verification
- [x] 0028 — Test: wrong public key fails verification
- [x] 0029 — Benchmark: keygen time
- [x] 0030 — Benchmark: sign time
- [x] 0031 — Benchmark: verify time (single)
- [x] 0032 — Benchmark: batch verify time (100, 1000 sigs)

### M0.3 — Kyber-768 Key Encapsulation

- [x] 0033 — Add Kyber-768 dependency (pqcrypto-kem or custom)
- [x] 0034 — Define `KyberPublicKey` type
- [x] 0035 — Define `KyberSecretKey` type
- [x] 0036 — Define `KyberCiphertext` type
- [x] 0037 — Define `SharedSecret` type (32 bytes)
- [x] 0038 — Implement `kyber_keygen() -> (KyberPublicKey, KyberSecretKey)`
- [x] 0039 — Implement `kyber_encapsulate(pk: &KyberPublicKey) -> (KyberCiphertext, SharedSecret)`
- [x] 0040 — Implement `kyber_decapsulate(sk: &KyberSecretKey, ct: &KyberCiphertext) -> SharedSecret`
- [x] 0041 — Add serialization for all Kyber types
- [x] 0042 — Test: encapsulate/decapsulate roundtrip
- [x] 0043 — Test: wrong secret key produces different shared secret
- [x] 0044 — Benchmark: keygen, encapsulate, decapsulate times

### M0.4 — Threshold Kyber (85-of-128)

- [x] 0045 — Define `ThresholdPublicKey` type (committee-level)
- [x] 0046 — Define `KeyShare` type (per-validator share)
- [x] 0047 — Define `DecryptionShare` type
- [x] 0048 — Implement Shamir secret sharing over Kyber key material
- [x] 0049 — Implement `threshold_encrypt(tpk: &ThresholdPublicKey, msg: &[u8]) -> ThresholdCiphertext`
- [x] 0050 — Implement `generate_decryption_share(share: &KeyShare, ct: &ThresholdCiphertext) -> DecryptionShare`
- [x] 0051 — Implement `combine_shares(shares: &[DecryptionShare], threshold: usize) -> Result<Vec<u8>>`
- [x] 0052 — Test: encrypt with t+1 shares decrypts correctly
- [x] 0053 — Test: encrypt with t-1 shares fails
- [x] 0054 — Test: encrypt with t shares works (exact threshold)
- [x] 0055 — Test: duplicate shares are rejected
- [x] 0056 — Test: invalid shares are detected
- [x] 0057 — Benchmark: encryption time
- [x] 0058 — Benchmark: share generation time
- [x] 0059 — Benchmark: share combination time (85 shares)

### M0.5 — Proactive Secret Sharing (PSS)

- [x] 0060 — Define `EpochKeyMaterial` type
- [x] 0061 — Implement PSS share refresh protocol
- [x] 0062 — Implement share verification (each validator checks their new share)
- [x] 0063 — Test: refreshed shares decrypt messages encrypted with old public key
- [x] 0064 — Test: old shares cannot decrypt messages encrypted with new public key
- [x] 0065 — Test: committee rotation (add/remove validators) during refresh
- [x] 0066 — Benchmark: PSS refresh time for 128-member committee

### M0.6 — Lattice-Based VRF

- [x] 0067 — Define `VrfProof` type
- [x] 0068 — Define `VrfOutput` type (32 bytes, uniformly distributed)
- [x] 0069 — Implement `vrf_prove(sk: &FalconSecretKey, input: &[u8]) -> (VrfOutput, VrfProof)`
- [x] 0070 — Implement `vrf_verify(pk: &FalconPublicKey, input: &[u8], output: &VrfOutput, proof: &VrfProof) -> bool`
- [x] 0071 — Test: prove/verify roundtrip
- [x] 0072 — Test: same input produces same output (deterministic)
- [x] 0073 — Test: different keys produce different outputs
- [x] 0074 — Test: output distribution is statistically uniform (chi-squared test)
- [x] 0075 — Benchmark: prove time, verify time

---

## Phase 1: Pyde Virtual Machine (PVM)

### M1.1 — ISA Definition

- [x] 0076 — Define `Opcode` enum (~45 variants)
- [x] 0077 — Define `Instruction` type (u32 fixed-width)
- [x] 0078 — Implement instruction encoding: `encode(op, rd, rs1, rs2_or_imm) -> u32`
- [x] 0079 — Implement instruction decoding: `decode(u32) -> (Opcode, rd, rs1, rs2_or_imm)`
- [x] 0080 — Define `GasTable` — static mapping of opcode -> (exec_cost, prove_cost)
- [x] 0081 — Test: encode/decode roundtrip for every opcode
- [x] 0082 — Test: invalid opcode bits decode to `Opcode::Invalid`
- [x] 0083 — Test: immediate field sign extension (18-bit signed)
- [x] 0084 — Test: register field bounds (4-bit, 0-15 for GP, separate encoding for wide)

### M1.2 — Arithmetic Instructions

- [x] 0085 — Implement `ADD rd, rs1, rs2` (checked, panic on overflow)
- [x] 0086 — Implement `SUB rd, rs1, rs2` (checked, panic on underflow)
- [x] 0087 — Implement `MUL rd, rs1, rs2` (checked)
- [x] 0088 — Implement `DIV rd, rs1, rs2` (checked, panic on div-by-zero)
- [x] 0089 — Implement `MOD rd, rs1, rs2`
- [x] 0090 — Implement `ADDI rd, rs1, imm` (add immediate)
- [x] 0091 — Implement `AND rd, rs1, rs2`
- [x] 0092 — Implement `OR rd, rs1, rs2`
- [x] 0093 — Implement `XOR rd, rs1, rs2`
- [x] 0094 — Implement `NOT rd, rs1`
- [x] 0095 — Implement `SHL rd, rs1, rs2` (shift left)
- [x] 0096 — Implement `SHR rd, rs1, rs2` (logical shift right)
- [x] 0097 — Implement `SAR rd, rs1, rs2` (arithmetic shift right, for signed)
- [x] 0098 — Implement `LT rd, rs1, rs2` (unsigned less-than, rd = 0 or 1)
- [x] 0099 — Implement `GT rd, rs1, rs2`
- [x] 0100 — Implement `EQ rd, rs1, rs2`
- [x] 0101 — Implement `SLT rd, rs1, rs2` (signed less-than)
- [x] 0102 — Implement `SGT rd, rs1, rs2` (signed greater-than)
- [x] 0103 — Test: each arithmetic op with boundary values (0, 1, MAX, MAX-1)
- [x] 0104 — Test: overflow detection for ADD, SUB, MUL
- [x] 0105 — Test: division by zero trap
- [x] 0106 — Test: shift by 0, 1, 63, 64 (full width)
- [x] 0107 — Test: signed comparison correctness (negative vs positive)

### M1.3 — Wide Register Instructions (256-bit)

- [x] 0108 — Implement `WADD wd, ws1, ws2` (256-bit checked add)
- [x] 0109 — Implement `WSUB wd, ws1, ws2` (256-bit checked sub)
- [x] 0110 — Implement `WMUL wd, ws1, ws2` (256-bit checked mul)
- [x] 0111 — Implement `WDIV wd, ws1, ws2` (256-bit checked div)
- [x] 0112 — Implement `WMOD wd, ws1, ws2`
- [x] 0113a — Implement `WAND wd, ws1, ws2` (256-bit bitwise AND)
- [x] 0113b — Implement `WOR wd, ws1, ws2` (256-bit bitwise OR)
- [x] 0113c — Implement `WXOR wd, ws1, ws2` (256-bit bitwise XOR)
- [x] 0113d — Implement `WNOT wd, ws1` (256-bit bitwise NOT)
- [x] 0113 — Implement `WMOV wd, ws1` (256-bit register copy)
- [x] 0114 — Implement `WLOAD wd, rs1` (load 256-bit value from memory at address in rs1)
- [x] 0115 — Implement `WSTORE rs1, ws1` (store 256-bit value to memory)
- [x] 0116 — Implement `NARROW rd, ws1` (256-bit -> 64-bit, panic if > u64::MAX)
- [x] 0117 — Implement `WIDEN wd, rs1` (64-bit -> 256-bit, zero-extend)
- [x] 0118 — Test: 256-bit arithmetic with large values (> 2^128)
- [x] 0119 — Test: 256-bit overflow detection
- [x] 0120 — Test: NARROW panics when value exceeds 64 bits
- [x] 0121 — Test: WIDEN zero-extends correctly

### M1.4 — Memory Instructions

- [x] 0122 — Define memory layout constants (null page, code, heap, stack boundaries)
- [x] 0123 — Implement `Memory` struct (4 MB linear address space)
- [x] 0124 — Implement page tracking (4 KB pages, gas metering on first access)
- [x] 0125 — Implement `LOAD8 rd, rs1, imm` (load byte, zero-extend)
- [x] 0126 — Implement `LOAD16 rd, rs1, imm`
- [x] 0127 — Implement `LOAD32 rd, rs1, imm`
- [x] 0128 — Implement `LOAD64 rd, rs1, imm`
- [x] 0129 — Implement `STORE8 rs1, imm, rs2`
- [x] 0130 — Implement `STORE16 rs1, imm, rs2`
- [x] 0131 — Implement `STORE32 rs1, imm, rs2`
- [x] 0132 — Implement `STORE64 rs1, imm, rs2`
- [x] 0133 — Implement null page trap (access to 0x000000-0x000FFF)
- [x] 0134 — Implement code section read-only enforcement
- [x] 0135 — Implement heap growth (upward from 0x010000)
- [x] 0136 — Implement stack growth (downward from 0x3FFFFF)
- [x] 0137 — Implement heap-stack collision detection
- [x] 0138 — Test: null page access traps
- [x] 0139 — Test: write to code section traps
- [x] 0140 — Test: heap allocation and access
- [x] 0141 — Test: stack push/pop
- [x] 0142 — Test: heap/stack collision detection
- [x] 0143 — Test: page gas metering (200 gas per first access to 4KB page)
- [x] 0144 — Test: alignment requirements (if any)
- [x] 1168 — Implement lazy page allocation (allocate 4KB pages on first touch instead of 4MB upfront)
- [x] 1169 — Test: lazy allocation produces identical results to eager allocation
- [x] 1170 — Benchmark: VM instantiation time with lazy vs eager allocation (setup: 122µs → 3µs, 40x faster)

### M1.5 — Control Flow Instructions

- [x] 0145 — Implement `JMP imm` (unconditional jump)
- [x] 0146 — Implement `BEQ rs1, rs2, imm` (branch if equal)
- [x] 0147 — Implement `BNE rs1, rs2, imm` (branch if not equal)
- [x] 0148 — Implement `BLT rs1, rs2, imm` (branch if less than, unsigned)
- [x] 0149 — Implement `BGE rs1, rs2, imm` (branch if greater or equal, unsigned)
- [x] 0150 — Implement `WEQ rd, ws1, ws2` (wide equal → GP register) + `WLT rd, ws1, ws2` (wide less-than → GP register)
- [x] 0151 — Implement width-encoded LOAD/STORE (8/16/32/64-bit via 2-bit width field in immediate)
- [x] 0152 — Implement `CALL imm` (push return address + frame pointer, jump)
- [x] 0153 — Implement `RET` (pop return address + restore frame pointer)
- [x] 0154 — Implement call stack frame management (RA, FP, locals)
- [x] 0155 — Implement max call depth enforcement (1,024 frames)
- [x] 0156 — Implement `HALT` (stop execution, success)
- [x] 0157 — Implement `REVERT` (stop execution, revert all state changes)
- [x] 0158 — Test: forward and backward jumps
- [x] 0159 — Test: all branch conditions (true/false paths)
- [x] 0160 — Test: nested function calls (5 deep, 10 deep)
- [x] 0161 — Test: max call depth exceeded → trap
- [x] 0162 — Test: RET with no matching CALL → trap
- [x] 0163 — Test: HALT vs REVERT behavior

### M1.6 — Gas Metering

> Moved up: gas metering is foundational — needed before any instruction that costs gas.

- [x] 0216 — Implement gas counter (two-dimensional: exec + prove)
- [x] 0217 — Implement out-of-gas detection and revert (OutOfGas trap)
- [x] 0218 — Implement gas refund tracking (gas_refund field, for future SDELETE)
- [x] 0219 — Implement gas refund cap (50% of total gas used)
- [x] 0220 — Implement two-dimensional gas tracking (exec_cost + prove_cost)
- [x] 0221 — Implement gas forwarding rules for external calls (remaining - 2300)
- [x] 0222 — Test: transaction runs out of gas mid-execution → revert
- [x] 0223 — Test: gas refund applied correctly at end of transaction
- [x] 0224 — Test: gas refund capped at 50%
- [x] 0225 — Test: nested call gas forwarding
- [x] 0226 — Test: two-dimensional gas both components tracked
- [x] 1171 — Implement combined gas lookup table (precompute total_gas per opcode, charge once per step instead of two additions)
- [x] 1172 — Test: combined gas charging matches two-dimensional tracking

### M1.7 — Assembler

> Self-contained. Enables writing programs as text for all subsequent testing.

- [x] 0241 — Define assembly text format (mnemonics, registers, labels)
- [x] 0242 — Implement lexer for assembly text
- [x] 0243 — Implement parser (instruction, label, directive)
- [x] 0244 — Implement label resolution (forward references)
- [x] 0245 — Implement assembler output (binary bytecode)
- [x] 0246 — Implement disassembler (bytecode → assembly text)
- [x] 0247 — Test: assemble/disassemble roundtrip
- [x] 0248 — Test: forward label resolution
- [x] 0249 — Test: error reporting for invalid assembly

### M1.8 — System Instructions

> Requires: ExecutionContext struct (created here). Provides caller/block info to contracts.

- [x] 0164 — Implement `ExecutionContext` struct (caller, block info, contract address)
- [x] 0165 — Implement `CALLER rd` (rd = msg.sender) — via Caller opcode, imm=0
- [x] 0166 — Implement `CALLVALUE wd` (wd = msg.value, 256-bit) — via Callvalue opcode, imm=0
- [x] 0167 — Implement `BLOCKHASH wd, rs1` (wd = hash of block at height rs1)
- [x] 0168 — Implement `BLOCKNUMBER rd` (rd = current block height) — via Caller opcode, imm=2
- [x] 0169 — Implement `TIMESTAMP rd` (rd = current block timestamp) — via Caller opcode, imm=3
- [x] 0170 — Implement `GASPRICE wd` (wd = current base fee, 256-bit) — via Callvalue opcode, imm=1
- [x] 0171 — Implement `GASREMAINING rd` (rd = remaining gas) — via Caller opcode, imm=4
- [x] 0172 — Implement `ADDRESS rd` (rd = current contract address) — via Caller opcode, imm=1
- [x] 0173 — Implement `BALANCE wd, rs1` (wd = balance of address in rs1) — via Callvalue opcode, imm=2
- [x] 0174 — Test: each system instruction returns correct context values
- [x] 0175 — Test: BLOCKHASH for recent blocks vs too-old blocks

### M1.9 — Crypto Instructions

> Requires: crypto crate (Phase 0). Wires Poseidon2 and FALCON-512 into VM opcodes.

- [x] 0186 — Implement `POSEIDON wd, rs1, rs2` (wd = poseidon2_hash(memory[rs1..rs1+rs2]))
- [x] 0187 — Implement `VERIFYSIG rd, rs1` (FALCON-512 verify via memory descriptor)
- [x] 0188 — Test: POSEIDON matches software Poseidon2 implementation
- [x] 0189 — Test: SIGVERIFY with valid signature → rd = 1
- [x] 0190 — Test: SIGVERIFY with invalid signature → rd = 0
- [x] 0191 — Test: gas costs for crypto operations

### M1.10 — Storage Instructions

> Requires: M1.8 ExecutionContext. Provides key-value persistent storage for contracts.

- [x] 0176 — Implement `SLOAD rd, rs1` (rd = storage[key]) — uses wide registers for U256 slots/values
- [x] 0177 — Implement `SSTORE rs1, rd` (storage[key] = value) — uses wide registers
- [x] 0178 — Implement `SDELETE rs1` (delete storage[key], gas refund 1500) — only refunds if key existed
- [x] 0179 — Implement storage key derivation (Poseidon2 hash of slot + contract address)
- [x] 0180 — ~~Storage read tracking~~ — removed; witness/read tracking belongs in execution engine layer above VM
- [x] 0181 — ~~Storage write tracking~~ — removed; state diff derived by diffing storage map before/after execution
- [x] 0182 — Implement gas refund counter for SDELETE — uses existing gas_refund field
- [x] 0183 — Test: SLOAD returns 0 for uninitialized storage
- [x] 0184 — Test: SSTORE then SLOAD roundtrip
- [x] 0185 — Test: SDELETE sets value to 0 and grants refund
- [x] 0192 — Test: gas costs correct for each storage op

### M1.11 — Event Instructions

> Requires: M1.8 ExecutionContext. Accumulates event logs during execution.

- [x] 0209 — Implement `LOG` instruction (emit event with topics + data) — memory descriptor: [topics...][data_ptr:8][data_len:8], imm = topic count
- [x] 0210 — ~~Topic hashing~~ — compiler concern; VM stores whatever topics are provided
- [x] 0211 — ~~Indexed field topic encoding~~ — compiler concern; VM just stores topics as U256 values
- [x] 0212 — Implement event log accumulation — `Vec<EventLog>` on Vm, rolled back in M1.12
- [x] 0213 — Test: event emitted with correct topics and data
- [x] 0214 — Test: events rolled back on revert (covered by execute_revert_rolls_back_logs)
- [x] 0215 — Test: multiple events in single transaction

### M1.12 — Interpreter (Full Execution Engine)

> Requires: M1.8, M1.10, M1.11. Ties everything together with state rollback and execution traces.

- [x] 0227 — Implement state rollback on revert (storage, events, balance changes)
- [x] 0228 — Implement execution trace recording (for ZK prover)
- [x] 0229 — Implement execution result type (Success, Revert, OutOfGas, Trap)
- [x] 0230 — Test: simple program (add two numbers, return result)
- [x] 0231 — Test: fibonacci sequence computation
- [x] 0232 — Test: contract deployment and call
- [x] 0233 — Test: token transfer (read balance, check, write balance)
- [x] 0234 — Test: revert rolls back all changes
- [x] 0235 — Test: out-of-gas rolls back all changes
- [x] 0236 — Benchmark: interpreter throughput (149M instr/sec run(), 91M with trace)
- [x] 0237 — Benchmark: token transfer execution time (129K transfers/sec full lifecycle)
- [x] 1173 — Implement journaled storage rollback (write-ahead journal instead of HashMap clone on execute)
- [x] 1174 — Test: journaled rollback produces identical state to snapshot-based rollback (all 306 existing tests pass)
- [x] 1175 — Implement pre-decoded instruction cache (decode entire code segment at load time)
- [x] 1176 — Test: pre-decoded execution produces identical results to on-the-fly decode (306 tests pass)
- [x] 1177 — Benchmark: pre-decoded vs on-the-fly decode throughput (ALU: 149M → 189M instr/sec)
- ~~1178~~ — ~~Conditional trace recording~~ — removed: only provers execute, and they always need the trace
- [x] 1179 — Optimize VM struct layout for cache locality (hot fields pc/gas/cpu first, cold fields last)
- [x] 1180 — Benchmark: interpreter throughput after all M1.12 optimizations (189M instr/sec, 129K transfers/sec full lifecycle)

### M1.13 — Contract Call Instructions

> Requires: M1.8, M1.10, M1.12. Most complex — needs full execution context, storage, and state rollback.

- [x] 0193 — Implement `CALL` (external contract call with gas forwarding)
- [x] 0194 — Implement call context creation (new msg.sender, self, gas)
- [x] 0195 — Implement calldata encoding/decoding
- [x] 0196 — Implement return data handling
- [x] 0197 — Implement reentrancy guard (default on, per-function flag)
- [x] 0198 — Implement `STATICCALL` (view call, no state modification allowed)
- [x] 0199 — Implement `DELEGATECALL` (call with caller's context)
- [x] 0200 — Implement `CREATE` (deploy new contract)
- [x] 0201 — Implement `CREATE2` (deterministic contract address)
- [x] 0202 — Test: cross-contract call with value transfer
- [x] 0203 — Test: reentrancy guard blocks re-entrant call
- [ ] 0204 — Test: #[reentrant] function allows re-entry _(deferred: needs compiler annotation support)_
- [x] 0205 — Test: STATICCALL reverts on state modification attempt
- [x] 0206 — Test: nested calls (A calls B calls C)
- [x] 0207 — Test: call with insufficient gas → revert called contract only
- [x] 0208 — Test: CREATE deploys and returns correct address
- [x] 0238 — Test: CREATE2 address is deterministic

### M1.14 — AOT Compiler

> Requires: all above. Optimization layer — compiles bytecode to native code for faster execution.

- [x] 0250 — Define AOT compilation target (Cranelift, cross-arch: x86_64/ARM64/RISC-V)
- [x] 0251 — Implement bytecode → native IR translation (basic blocks via Cranelift)
- [x] 0252 — Implement register allocation (PVM r0-r15 → Cranelift variables)
- [x] 0253 — Implement gas metering injection (gas check per basic block)
- [x] 0254 — Implement memory bounds checking in native code (LOAD/STORE via host calls)
- [x] 0255 — Implement overflow checking in native code (checked ADD/SUB/MUL/DIV/MOD via host calls)
- [x] 0256 — Implement native function prologue/epilogue (register load/store from memory)
- [x] 0257 — Implement AOT output format (JIT-compiled callable function pointer)
- [x] 0258 — Implement AOT hash computation (Poseidon2 of bytecode)
- [x] 0259 — Test: AOT produces same results as interpreter (add, fibonacci, branches, loops)
- [x] 0260 — Test: AOT gas metering matches interpreter
- [x] 0261 — Test: AOT overflow detection matches interpreter (checked arithmetic → trap)
- [x] 0262 — Benchmark: AOT vs interpreter speedup (151x on ALU workloads)
- [x] 0263 — Benchmark: AOT compilation time per contract (<1ms for typical contracts)

---

## Phase 2: State Model

### M2.1 — Sparse Merkle Tree Core

- [ ] 0264 — Create `pyde-state` crate
- [ ] 0265 — Define `SMT` struct (root hash, depth = 256)
- [ ] 0266 — Define `LeafNode` struct (key, value, hash)
- [ ] 0267 — Define `InternalNode` struct (left_hash, right_hash)
- [ ] 0268 — Define `EmptyNode` (precomputed empty subtree hashes for all depths)
- [ ] 0269 — Precompute all 256 empty subtree hashes (Poseidon2 chain)
- [ ] 0270 — Implement `smt.get(key) -> Option<Vec<u8>>` (leaf lookup)
- [ ] 0271 — Implement `smt.insert(key, value)` (leaf insertion with path update)
- [ ] 0272 — Implement `smt.delete(key)` (leaf removal with path update)
- [ ] 0273 — Implement `smt.root() -> Hash256` (current root hash)
- [ ] 0274 — Implement Merkle path generation for a key
- [ ] 0275 — Implement Merkle path verification
- [ ] 0276 — Test: insert and retrieve single value
- [ ] 0277 — Test: insert 1000 random key-value pairs and verify all
- [ ] 0278 — Test: delete key and verify absence
- [ ] 0279 — Test: root changes after insert
- [ ] 0280 — Test: root reverts after insert + delete of same key
- [ ] 0281 — Test: Merkle proof verifies for existing key
- [ ] 0282 — Test: Merkle proof verifies non-existence for missing key
- [ ] 0283 — Test: tampered proof fails verification
- [ ] 0284 — Benchmark: insert throughput (ops/sec)
- [ ] 0285 — Benchmark: get throughput (ops/sec)
- [ ] 0286 — Benchmark: proof generation time

### M2.2 — Storage Backend

- [ ] 0287 — Define `StorageBackend` trait (get, put, delete, batch)
- [ ] 0288 — Implement `InMemoryBackend` (HashMap-based, for tests)
- [ ] 0289 — Implement `RocksDBBackend` (persistent storage)
- [ ] 0290 — Implement batch write support (atomic multi-key updates)
- [ ] 0291 — Implement node caching (LRU cache for hot tree nodes)
- [ ] 0292 — Implement cache eviction policy
- [ ] 0293 — Test: backend get/put/delete roundtrip
- [ ] 0294 — Test: batch write atomicity (all or nothing)
- [ ] 0295 — Test: cache hit/miss behavior
- [ ] 0296 — Benchmark: RocksDB read/write latency

### M2.3 — State Key Derivation

- [ ] 0297 — Implement account key derivation: `Poseidon2(address, "account")`
- [ ] 0298 — Implement storage slot key derivation: `Poseidon2(contract_address, slot_index)`
- [ ] 0299 — Implement map entry key derivation: `Poseidon2(Poseidon2(contract, slot), map_key)`
- [ ] 0300 — Implement nested map key derivation (2-level deep)
- [ ] 0301 — Test: key derivation is deterministic
- [ ] 0302 — Test: different contracts produce different keys for same slot index
- [ ] 0303 — Test: different map keys produce different storage keys
- [ ] 0304 — Test: no key collisions across account/storage/map domains

### M2.4 — State Witnesses

- [ ] 0305 — Define `StateWitness` struct (key, value, merkle_path)
- [ ] 0306 — Define `BlockWitness` struct (Vec<StateWitness>, pre_state_root, post_state_root)
- [ ] 0307 — Implement witness generation from access list
- [ ] 0308 — Implement witness verification (check each path against pre_state_root)
- [ ] 0309 — Implement witness-based execution (execute against witnesses, not full state)
- [ ] 0310 — Implement post-state root computation from witnesses + state diffs
- [ ] 0311 — Test: witness for single storage read
- [ ] 0312 — Test: witness for storage write (before + after values)
- [ ] 0313 — Test: witness for account balance check
- [ ] 0314 — Test: witness verification catches tampered path
- [ ] 0315 — Test: execution against witnesses matches execution against full state
- [ ] 0316 — Benchmark: witness generation time per block
- [ ] 0317 — Benchmark: witness size per transaction

### M2.5 — State Snapshots and Sync

- [ ] 0318 — Implement state snapshot creation (serialize full SMT)
- [ ] 0319 — Implement state snapshot restoration (deserialize to SMT)
- [ ] 0320 — Implement incremental snapshot (only changed nodes since last snapshot)
- [ ] 0321 — Implement snapshot chunking (for network transfer)
- [ ] 0322 — Implement snapshot verification (reconstruct root from chunks)
- [ ] 0323 — Test: snapshot/restore roundtrip
- [ ] 0324 — Test: incremental snapshot correctness
- [ ] 0325 — Benchmark: full snapshot time, incremental snapshot time

### M2.6 — State Versioning

- [ ] 0326 — Implement copy-on-write state diffs
- [ ] 0327 — Implement undo log (for reorgs)
- [ ] 0328 — Implement state-at-height query (current state + undo logs)
- [ ] 0329 — Implement undo log pruning (keep last 128 blocks)
- [ ] 0330 — Test: apply block, undo block, verify state matches pre-block
- [ ] 0331 — Test: multi-block undo (reorg scenario)
- [ ] 0332 — Test: historical state query returns correct values

### M2.7 — Data Tiers

- [ ] 0333 — Implement hot tier (RAM-based, current block state)
- [ ] 0334 — Implement warm tier (SSD-based, last 100K blocks)
- [ ] 0335 — Implement cold tier interface (archival, lazy retrieval)
- [ ] 0336 — Implement tier promotion (cold → warm → hot on access)
- [ ] 0337 — Implement tier demotion (hot → warm after 128 blocks without access)
- [ ] 0338 — Test: tier transitions on access patterns
- [ ] 0339 — Benchmark: read latency per tier

---

## Phase 3: Account Model

### M3.1 — Account Types

- [ ] 0340 — Define `Account` struct (address, balance, nonce, code_hash, storage_root, auth_keys)
- [ ] 0341 — Define `EOA` (Externally Owned Account) — no code
- [ ] 0342 — Define `ContractAccount` — has code + storage
- [ ] 0343 — Define `SystemAccount` — native protocol functions
- [ ] 0344 — Implement account creation (EOA from first incoming transfer)
- [ ] 0345 — Implement contract account creation (from CREATE/CREATE2)
- [ ] 0346 — Implement account serialization to SMT leaf
- [ ] 0347 — Implement account deserialization from SMT leaf
- [ ] 0348 — Test: EOA creation and balance update
- [ ] 0349 — Test: contract account creation with code storage
- [ ] 0350 — Test: serialize/deserialize roundtrip

### M3.2 — Address Derivation

- [ ] 0351 — Implement EOA address: `Poseidon2(falcon_public_key)[0..32]`
- [ ] 0352 — Implement contract address (CREATE): `Poseidon2(deployer, nonce)`
- [ ] 0353 — Implement contract address (CREATE2): `Poseidon2(deployer, salt, code_hash)`
- [ ] 0354 — Define `Address` type (32 bytes) with Display formatting
- [ ] 0355 — Implement `Address::ZERO` constant
- [ ] 0356 — Test: address derivation is deterministic
- [ ] 0357 — Test: CREATE2 same salt + same code → same address
- [ ] 0358 — Test: CREATE2 different salt → different address

### M3.3 — Nonce Management

- [ ] 0359 — Implement nonce window (16 concurrent in-flight transactions)
- [ ] 0360 — Implement nonce bitmap (track which of 16 slots are used)
- [ ] 0361 — Implement nonce window advancement (when low nonces are consumed)
- [ ] 0362 — Test: sequential nonce usage
- [ ] 0363 — Test: out-of-order nonce usage within window
- [ ] 0364 — Test: nonce outside window rejected
- [ ] 0365 — Test: window advancement after gap fill

### M3.4 — Native Account Abstraction

- [ ] 0366 — Define `AuthScheme` enum (Falcon, MultiSig, Custom)
- [ ] 0367 — Implement Falcon signature validation (default)
- [ ] 0368 — Implement multi-sig validation (m-of-n Falcon keys)
- [ ] 0369 — Implement custom validation (contract-defined auth logic)
- [ ] 0370 — Implement key rotation (change auth keys with current key signature)
- [ ] 0371 — Test: Falcon auth roundtrip
- [ ] 0372 — Test: multi-sig 2-of-3 approval
- [ ] 0373 — Test: key rotation (old key invalid after rotation)
- [ ] 0374 — Test: custom auth contract validation

---

## Phase 4: Transaction Processing

### M4.1 — Transaction Types

- [ ] 0375 — Define `Transaction` struct (to, value, data, gas_limit, nonce, deadline, access_list, signature)
- [ ] 0376 — Define `SignedTransaction` (transaction + encrypted payload)
- [ ] 0377 — Define `AccessList` struct (Vec<(Address, Vec<StorageKey>)>)
- [ ] 0378 — Implement transaction serialization (wire format)
- [ ] 0379 — Implement transaction deserialization
- [ ] 0380 — Implement transaction hash computation
- [ ] 0381 — Implement transaction signature verification
- [ ] 0382 — Test: serialize/deserialize roundtrip
- [ ] 0383 — Test: hash is deterministic
- [ ] 0384 — Test: valid signature passes verification
- [ ] 0385 — Test: tampered transaction fails verification

### M4.2 — Transaction Validation

- [ ] 0386 — Implement nonce check (within sender's nonce window)
- [ ] 0387 — Implement balance check (balance >= gas_limit × base_fee + value)
- [ ] 0388 — Implement gas limit bounds check (min: 21000, max: block gas limit)
- [ ] 0389 — Implement deadline check (block height < deadline)
- [ ] 0390 — Implement signature verification
- [ ] 0391 — Implement access list validation (well-formed addresses and keys)
- [ ] 0392 — Implement transaction size limit check
- [ ] 0393 — Test: each validation rule with valid and invalid inputs
- [ ] 0394 — Test: expired deadline rejected
- [ ] 0395 — Test: insufficient balance rejected
- [ ] 0396 — Test: nonce outside window rejected

### M4.3 — Transaction Execution

- [ ] 0397 — Implement pre-execution: deduct max gas cost from sender
- [ ] 0398 — Implement PVM execution invocation
- [ ] 0399 — Implement post-execution: refund unused gas to sender
- [ ] 0400 — Implement gas refund application (SDELETE refunds, capped at 50%)
- [ ] 0401 — Implement fee distribution (70% burn, 20% validator, 10% prover)
- [ ] 0402 — Implement value transfer (sender → recipient)
- [ ] 0403 — Implement contract deployment (store code, create account)
- [ ] 0404 — Implement receipt generation (status, gas_used, logs, state_root)
- [ ] 0405 — Test: successful transfer updates balances correctly
- [ ] 0406 — Test: failed transaction still deducts gas
- [ ] 0407 — Test: gas refund correctly applied
- [ ] 0408 — Test: fee distribution to burn/validator/prover addresses
- [ ] 0409 — Test: contract deployment stores code and creates account
- [ ] 0410 — Test: receipt contains correct log entries
- [ ] 1181 — Implement access-list storage key pre-derivation (batch Poseidon2 key derivation before execution)
- [ ] 1182 — Implement storage key cache passed to VM (SLOAD/SSTORE use pre-derived keys)
- [ ] 1183 — Test: pre-derived keys match runtime-derived keys for all storage operations
- [ ] 1184 — Benchmark: token transfer with pre-derived keys vs runtime derivation

### M4.4 — Parallel Execution

- [ ] 0411 — Implement access list conflict detection
- [ ] 0412 — Implement transaction grouping (non-conflicting transactions → same group)
- [ ] 0413 — Implement parallel execution scheduler (execute groups concurrently)
- [ ] 0414 — Implement group-level state isolation (no cross-group reads during execution)
- [ ] 0415 — Implement state merge after group execution
- [ ] 0416 — Implement sequential fallback for conflicting transactions
- [ ] 0417 — Test: two non-conflicting transfers execute in parallel
- [ ] 0418 — Test: two conflicting transfers execute sequentially
- [ ] 0419 — Test: parallel execution produces same state root as sequential
- [ ] 0420 — Benchmark: parallel vs sequential execution (100 transactions)
- [ ] 0421 — Benchmark: parallel vs sequential execution (1000 transactions)

### M4.5 — EIP-1559 Base Fee

- [ ] 0422 — Implement base fee adjustment formula
- [ ] 0423 — Implement `adjust_base_fee(parent_base_fee, parent_gas_used, gas_target) -> u128`
- [ ] 0424 — Implement minimum base fee floor (1 wei equivalent)
- [ ] 0425 — Implement genesis base fee (initial value)
- [ ] 0426 — Test: empty block → base fee decreases
- [ ] 0427 — Test: full block (at target) → base fee unchanged
- [ ] 0428 — Test: over-target block → base fee increases
- [ ] 0429 — Test: max increase is 12.5% per block
- [ ] 0430 — Test: max decrease is 12.5% per block
- [ ] 0431 — Test: base fee never goes below floor
- [ ] 0432 — Test: elastic 4x block → base fee increases proportionally

### M4.6 — Elastic Blocks

- [ ] 0433 — Implement gas target (400,000,000)
- [ ] 0434 — Implement gas ceiling (1,600,000,000 = 4x target)
- [ ] 0435 — Implement block gas limit enforcement
- [ ] 0436 — Implement block fullness tracking for base fee adjustment
- [ ] 0437 — Test: block at target gas → normal operation
- [ ] 0438 — Test: block exceeding ceiling → transactions dropped
- [ ] 0439 — Test: elastic expansion under demand surge

### M4.7 — Sponsored Transactions (Gas Tanks)

- [ ] 0440 — Define `GasTank` struct (owner, balance, whitelist, per_tx_limit)
- [ ] 0441 — Implement gas tank creation and funding
- [ ] 0442 — Implement gas tank withdrawal
- [ ] 0443 — Implement gas tank sponsorship (pay gas on behalf of sender)
- [ ] 0444 — Implement paymaster pattern (contract-defined sponsorship logic)
- [ ] 0445 — Test: sponsored transaction deducts from gas tank
- [ ] 0446 — Test: gas tank with insufficient balance → reject sponsorship
- [ ] 0447 — Test: per-transaction limit enforcement
- [ ] 0448 — Test: paymaster contract can approve/reject sponsorship

---

## Phase 5: Consensus (Modified HotStuff)

### M5.1 — Block Structure

- [ ] 0449 — Define `BlockHeader` struct (parent_hash, height, timestamp, state_root, tx_root, proof_hash, proposer, committee_sig)
- [ ] 0450 — Define `BlockBody` struct (transactions, execution_schedule, proof)
- [ ] 0451 — Define `Block` struct (header + body)
- [ ] 0452 — Implement block hash computation (Poseidon2 of header fields)
- [ ] 0453 — Implement block serialization/deserialization
- [ ] 0454 — Implement genesis block creation
- [ ] 0455 — Test: block hash is deterministic
- [ ] 0456 — Test: genesis block has correct initial values

### M5.2 — Validator Set Management

- [ ] 0457 — Define `Validator` struct (address, public_key, stake, is_active)
- [ ] 0458 — Define `Committee` struct (128 validators, epoch, threshold_public_key)
- [ ] 0459 — Implement validator registration (stake 10,000 PYDE)
- [ ] 0460 — Implement validator deregistration (unstake with delay)
- [ ] 0461 — Implement committee selection (random subset of eligible validators)
- [ ] 0462 — Implement committee rotation (every ~1000 blocks)
- [ ] 0463 — Implement epoch transitions
- [ ] 0464 — Test: register validator with sufficient stake
- [ ] 0465 — Test: reject registration with insufficient stake
- [ ] 0466 — Test: committee has exactly 128 members
- [ ] 0467 — Test: committee rotates at epoch boundary
- [ ] 0468 — Test: deregistered validator excluded from future committees

### M5.3 — VRF-Based Proposer Selection

- [ ] 0469 — Implement proposer selection: VRF(sk, slot_number) → output
- [ ] 0470 — Implement proposer determination: lowest VRF output in committee
- [ ] 0471 — Implement proposer proof broadcast
- [ ] 0472 — Implement proposer verification by other validators
- [ ] 0473 — Test: proposer selection is deterministic for same key + slot
- [ ] 0474 — Test: different slots produce different proposers (statistically)
- [ ] 0475 — Test: invalid VRF proof rejected

### M5.4 — HotStuff Core Protocol

- [ ] 0476 — Define `ConsensusMessage` enum (Proposal, Vote, NewView, Timeout)
- [ ] 0477 — Define `QuorumCertificate` (QC) struct (block_hash, signatures, aggregated)
- [ ] 0478 — Implement Prepare phase (proposer sends Proposal with parent QC)
- [ ] 0479 — Implement Pre-commit phase (validators vote on Proposal)
- [ ] 0480 — Implement Commit phase (proposer collects votes into QC)
- [ ] 0481 — Implement Decide phase (block finalized when QC chain reaches depth 3)
- [ ] 0482 — Implement pipelined HotStuff (overlap phases across consecutive blocks)
- [ ] 0483 — Implement QC aggregation (combine 86+ signatures)
- [ ] 0484 — Test: happy path — block proposed, voted, committed, decided
- [ ] 0485 — Test: insufficient votes → block not committed
- [ ] 0486 — Test: pipelined blocks — block N commits while N+1 is proposed
- [ ] 0487 — Test: QC requires 86 of 128 signatures (2/3 + 1)

### M5.5 — View Change (Leader Failure)

- [ ] 0488 — Implement timeout mechanism (400ms + jitter)
- [ ] 0489 — Implement timeout certificate (TC) collection
- [ ] 0490 — Implement view change trigger (no valid proposal within timeout)
- [ ] 0491 — Implement new-view message (validators send highest QC they've seen)
- [ ] 0492 — Implement leader recovery (next VRF-selected proposer takes over)
- [ ] 0493 — Test: leader timeout → view change → new leader
- [ ] 0494 — Test: multiple consecutive leader failures
- [ ] 0495 — Test: view change preserves safety (no conflicting commits)

### M5.6 — Soft Finality

- [ ] 0496 — Implement soft finality detection (2/3 committee signatures on block)
- [ ] 0497 — Implement soft finality notification to subscribers
- [ ] 0498 — Test: soft finality reached at 86/128 votes
- [ ] 0499 — Test: soft finality timing (~400ms from proposal)

### M5.7 — Hard Finality

- [ ] 0500 — Implement hard finality detection (ZK proof verified for block)
- [ ] 0501 — Implement hard finality notification
- [ ] 0502 — Implement finality checkpoint storage
- [ ] 0503 — Test: hard finality after proof verification
- [ ] 0504 — Test: blocks before hard finality can be reorganized
- [ ] 0505 — Test: blocks after hard finality cannot be reorganized

### M5.8 — Slashing

- [ ] 0506 — Implement double-sign detection (two blocks for same slot)
- [ ] 0507 — Implement double-sign evidence struct
- [ ] 0508 — Implement slashing execution (burn 100% of stake for double-sign)
- [ ] 0509 — Implement liveness slashing (miss 500+ consecutive slots → 1% per 100)
- [ ] 0510 — Implement invalid proof slashing (prover submits invalid proof → 100% bond)
- [ ] 0511 — Implement slashing evidence submission and verification
- [ ] 0512 — Test: double-sign slashes validator
- [ ] 0513 — Test: liveness failure slashes proportionally
- [ ] 0514 — Test: invalid proof slashes prover bond
- [ ] 0515 — Test: false slashing evidence rejected

---

## Phase 6: Mempool and Transaction Ordering

### M6.1 — Encrypted Mempool

- [ ] 0516 — Implement transaction encryption (Threshold Kyber encrypt before broadcast)
- [ ] 0517 — Implement encrypted mempool storage
- [ ] 0518 — Implement mempool size limits and eviction policy
- [ ] 0519 — Implement mempool transaction validation (signature check on encrypted tx)
- [ ] 0520 — Test: encrypted transaction stored in mempool
- [ ] 0521 — Test: mempool eviction when full (lowest gas price first)

### M6.2 — Threshold Decryption

- [ ] 0522 — Implement decryption share request (proposer → committee members)
- [ ] 0523 — Implement decryption share collection (collect 85 of 128 shares)
- [ ] 0524 — Implement share combination and transaction decryption
- [ ] 0525 — Implement decrypted transaction validation (full validation after decryption)
- [ ] 0526 — Test: successful decryption with 85 shares
- [ ] 0527 — Test: decryption fails with 84 shares
- [ ] 0528 — Test: invalid share rejected

### M6.3 — VRF Transaction Ordering

- [ ] 0529 — Implement VRF shuffle seed generation (VRF output of proposer)
- [ ] 0530 — Implement deterministic shuffle (Fisher-Yates with VRF seed)
- [ ] 0531 — Implement shuffle verification (any node can reproduce with VRF output)
- [ ] 0532 — Test: same seed produces same ordering
- [ ] 0533 — Test: different seed produces different ordering
- [ ] 0534 — Test: shuffle is statistically uniform

### M6.4 — Block Construction

- [ ] 0535 — Implement transaction selection from mempool (by nonce order per sender)
- [ ] 0536 — Implement gas limit enforcement during block construction
- [ ] 0537 — Implement access list extraction and parallel group construction
- [ ] 0538 — Implement execution schedule serialization
- [ ] 0539 — Test: block respects gas limit
- [ ] 0540 — Test: transactions ordered by nonce within same sender
- [ ] 0541 — Test: parallel groups have no access list conflicts

---

## Phase 7: Networking

### M7.1 — Transport Layer

- [ ] 0542 — Create `pyde-net` crate
- [ ] 0543 — Implement libp2p node with QUIC transport
- [ ] 0544 — Implement Kyber-768 key exchange for P2P encryption
- [ ] 0545 — Implement peer identity (Dilithium-3 signed PeerId)
- [ ] 0546 — Implement connection management (max connections, rate limiting)
- [ ] 0547 — Test: two nodes establish encrypted connection
- [ ] 0548 — Test: connection rejected without valid identity
- [ ] 0549 — Benchmark: connection establishment time

### M7.2 — Peer Discovery

- [ ] 0550 — Implement Kademlia DHT for peer discovery
- [ ] 0551 — Implement bootstrap node list (hardcoded genesis peers)
- [ ] 0552 — Implement peer scoring (reputation based on behavior)
- [ ] 0553 — Implement peer banning (misbehaving peers)
- [ ] 0554 — Test: new node discovers peers via DHT
- [ ] 0555 — Test: banned peer cannot reconnect

### M7.3 — Message Channels

- [ ] 0556 — Implement 5-channel Gossipsub topology
- [ ] 0557 — Implement consensus channel (validator messages only)
- [ ] 0558 — Implement transaction channel (encrypted transactions)
- [ ] 0559 — Implement block channel (proposed blocks)
- [ ] 0560 — Implement proof channel (ZK proofs from provers)
- [ ] 0561 — Implement sync channel (state sync, witness delivery)
- [ ] 0562 — Implement channel-specific message validation
- [ ] 0563 — Implement message deduplication
- [ ] 0564 — Test: message reaches all subscribers on channel
- [ ] 0565 — Test: validator-only channel rejects non-validator messages
- [ ] 0566 — Test: duplicate messages filtered
- [ ] 0567 — Benchmark: message propagation latency (simulated 1000 nodes)

### M7.4 — Block Propagation

- [ ] 0568 — Implement block announcement (compact block relay)
- [ ] 0569 — Implement block body request/response
- [ ] 0570 — Implement erasure coding for large blocks (4x elastic)
- [ ] 0571 — Implement block reconstruction from erasure-coded chunks
- [ ] 0572 — Test: block propagates to all nodes
- [ ] 0573 — Test: erasure coding reconstruction with missing chunks
- [ ] 0574 — Benchmark: block propagation time (target: < 100ms)

### M7.5 — Sync Protocol

- [ ] 0575 — Implement chain sync (header-first sync)
- [ ] 0576 — Implement state sync (snapshot download + verification)
- [ ] 0577 — Implement fast sync (recent state + replay)
- [ ] 0578 — Implement witness sync (deliver witnesses to provers)
- [ ] 0579 — Test: new node syncs chain from genesis
- [ ] 0580 — Test: new node syncs from snapshot
- [ ] 0581 — Benchmark: full sync time (simulated 100K blocks)

### M7.6 — DDoS Protection

- [ ] 0582 — Implement per-peer rate limiting
- [ ] 0583 — Implement per-subnet connection limits (/24 subnet)
- [ ] 0584 — Implement message size limits per channel
- [ ] 0585 — Implement proof-of-work challenge for connection flood
- [ ] 0586 — Implement eclipse attack mitigation (diverse peer selection)
- [ ] 0587 — Test: rate-limited peer throttled correctly
- [ ] 0588 — Test: connection flood mitigated

---

## Phase 8: ZK Proving System

### M8.1 — Plonky3 Integration

- [ ] 0589 — Create `pyde-prover` crate
- [ ] 0590 — Add Plonky3 dependency and configure field (Goldilocks)
- [ ] 0591 — Define AIR trait implementation for PVM
- [ ] 0592 — Implement trace table structure (~50-70 columns)
- [ ] 0593 — Test: Plonky3 basic proof generation and verification

### M8.2 — Execution Trace Generation

- [ ] 0594 — Implement trace recorder in interpreter (capture every cycle)
- [ ] 0595 — Record register state per cycle
- [ ] 0596 — Record memory reads/writes per cycle
- [ ] 0597 — Record storage reads/writes per cycle
- [ ] 0598 — Record program counter and opcode per cycle
- [ ] 0599 — Record gas counter per cycle
- [ ] 0600 — Implement trace serialization
- [ ] 0601 — Test: trace captures correct state for ADD instruction
- [ ] 0602 — Test: trace captures correct state for SLOAD/SSTORE
- [ ] 0603 — Test: trace captures correct state for CALL instruction
- [ ] 0604 — Benchmark: trace recording overhead vs non-traced execution

### M8.3 — AIR Constraints — Arithmetic

- [ ] 0605 — Implement ADD constraint: `next.rd = curr.rs1 + curr.rs2`
- [ ] 0606 — Implement SUB constraint
- [ ] 0607 — Implement MUL constraint (with overflow check constraint)
- [ ] 0608 — Implement DIV constraint (with division-by-zero constraint)
- [ ] 0609 — Implement bitwise operation constraints (AND, OR, XOR)
- [ ] 0610 — Implement shift constraints (SHL, SHR, SAR)
- [ ] 0611 — Implement comparison constraints (LT, GT, EQ)
- [ ] 0612 — Test: valid trace satisfies arithmetic constraints
- [ ] 0613 — Test: tampered trace violates constraints

### M8.4 — AIR Constraints — Memory

- [ ] 0614 — Implement memory consistency constraint (read returns last written value)
- [ ] 0615 — Implement memory sorting (by address, then by time)
- [ ] 0616 — Implement memory permission constraints (code read-only, null page trap)
- [ ] 0617 — Implement memory range constraints (within 4MB address space)
- [ ] 0618 — Test: valid memory trace satisfies constraints
- [ ] 0619 — Test: out-of-bounds memory access detected

### M8.5 — AIR Constraints — Control Flow

- [ ] 0620 — Implement PC transition constraint (next.pc = curr.pc + 4 or branch target)
- [ ] 0621 — Implement branch condition constraint
- [ ] 0622 — Implement CALL/RET stack constraints
- [ ] 0623 — Implement HALT/REVERT constraints
- [ ] 0624 — Test: valid control flow trace satisfies constraints
- [ ] 0625 — Test: invalid jump target detected

### M8.6 — AIR Constraints — State

- [ ] 0626 — Implement Merkle path verification constraint (for SLOAD)
- [ ] 0627 — Implement Merkle path update constraint (for SSTORE)
- [ ] 0628 — Implement state root transition constraint (pre_root → post_root)
- [ ] 0629 — Implement Poseidon2 hash constraint (in-circuit)
- [ ] 0630 — Test: valid state transition satisfies constraints
- [ ] 0631 — Test: tampered state root detected

### M8.7 — AIR Constraints — Gas

- [ ] 0632 — Implement gas decrement constraint (next.gas = curr.gas - opcode_cost)
- [ ] 0633 — Implement out-of-gas halt constraint
- [ ] 0634 — Implement two-dimensional gas constraint (exec + prove separately)
- [ ] 0635 — Test: valid gas trace satisfies constraints
- [ ] 0636 — Test: negative gas triggers halt

### M8.8 — Proof Generation Pipeline

- [ ] 0637 — Implement trace → polynomial commitment pipeline
- [ ] 0638 — Implement FRI-based proof generation
- [ ] 0639 — Implement proof serialization
- [ ] 0640 — Implement proof size optimization (FRI folding parameters)
- [ ] 0641 — Implement GPU-accelerated proof generation (CUDA/OpenCL)
- [ ] 0642 — Test: generate proof for simple program
- [ ] 0643 — Test: generate proof for token transfer
- [ ] 0644 — Test: generate proof for complex contract interaction
- [ ] 0645 — Benchmark: proof generation time per transaction
- [ ] 0646 — Benchmark: proof size (target: 50-100 KB per block)

### M8.9 — Proof Verification

- [ ] 0647 — Implement proof deserialization
- [ ] 0648 — Implement STARK proof verification
- [ ] 0649 — Implement public input extraction (pre_root, post_root, tx_hash)
- [ ] 0650 — Implement batch proof verification
- [ ] 0651 — Test: valid proof verifies
- [ ] 0652 — Test: tampered proof fails verification
- [ ] 0653 — Test: proof with wrong public inputs fails
- [ ] 0654 — Benchmark: verification time (target: < 5ms per block proof)

### M8.10 — Recursive Proof Composition

- [ ] 0655 — Implement recursive proof circuit (prove N sub-proofs in one proof)
- [ ] 0656 — Implement parallel group proofs → block proof composition
- [ ] 0657 — Implement proof tree structure (leaf proofs → intermediate → root)
- [ ] 0658 — Test: recursive proof verifies correctly
- [ ] 0659 — Test: recursive proof is smaller than sum of sub-proofs
- [ ] 0660 — Benchmark: recursive composition overhead

### M8.11 — Prover Pipeline

- [ ] 0661 — Implement prover node role (receive block + witnesses, execute, prove)
- [ ] 0662 — Implement proof assignment (pipeline model, each prover gets different block)
- [ ] 0663 — Implement proof submission to validators
- [ ] 0664 — Implement proof deadline enforcement
- [ ] 0665 — Implement prover reward tracking
- [ ] 0666 — Test: prover receives block and produces valid proof
- [ ] 0667 — Test: pipeline — prover A on block N while prover B on block N+1
- [ ] 0668 — Test: late proof submission handled gracefully
- [ ] 0669 — Benchmark: end-to-end proving time per block

---

## Phase 9: Otigen Compiler (otic)

### M9.1 — Lexer

- [ ] 0670 — Create `otic` crate (compiler binary)
- [ ] 0671 — Define `Token` enum (keywords, identifiers, literals, operators, punctuation)
- [ ] 0672 — Define all keywords: contract, storage, event, error, resource, struct, interface, pub, fn, let, mut, if, else, for, while, match, return, emit, destroy, move, use, module, in, as, break, continue, true, false, self
- [ ] 0673 — Define attribute tokens: #[constructor], #[view], #[reentrant], #[parallel_safe], #[indexed], #[only_owner], #[role(...)], #[test],#[sponsored], #[should_panic(...)]
- [ ] 0674 — Implement string literal lexing (double-quoted, escape sequences)
- [ ] 0675 — Implement numeric literal lexing (decimal, hex 0x, underscore separators)
- [ ] 0676 — Implement identifier lexing (alphanumeric + underscore)
- [ ] 0677 — Implement operator lexing (+, -, \*, /, %, ==, !=, <, >, <=, >=, &&, ||, !, &, |, ^, <<, >>)
- [ ] 0678 — Implement punctuation lexing ({, }, (, ), [, ], ,, ;, :, ::, ., ->, =>, ..)
- [ ] 0679 — Implement comment lexing (// line comments, /_ block comments _/)
- [ ] 0680 — Implement error recovery (skip to next statement on invalid token)
- [ ] 0681 — Implement source location tracking (line, column per token)
- [ ] 0682 — Test: lex simple contract
- [ ] 0683 — Test: lex all keyword variants
- [ ] 0684 — Test: lex numeric literals (decimal, hex, with underscores)
- [ ] 0685 — Test: lex string literals with escapes
- [ ] 0686 — Test: error reporting with line/column numbers

### M9.2 — Parser

- [ ] 0687 — Define AST node types: ContractDef, StorageBlock, FunctionDef, StructDef, InterfaceDef, EventDef, ErrorDef, ResourceDef
- [ ] 0688 — Define expression AST: BinaryOp, UnaryOp, Call, MemberAccess, IndexAccess, Literal, Identifier, StructInit, If, Match, Block
- [ ] 0689 — Define statement AST: Let, Assignment, Return, Emit, Destroy, Expression, For, While, Break, Continue
- [ ] 0690 — Define type AST: PrimitiveType (u8..u256, i8..i256, bool, Address), ArrayType, VecType, MapType, StructType, bytes, String
- [ ] 0691 — Implement contract parsing: `contract Name { ... }`
- [ ] 0692 — Implement storage block parsing: `storage { field: Type, ... }`
- [ ] 0693 — Implement function parsing with attributes: `#[view] pub fn name(params) -> RetType { body }`
- [ ] 0694 — Implement struct parsing: `struct Name { field: Type, ... }`
- [ ] 0695 — Implement resource parsing: `resource Name { field: Type, ... }`
- [ ] 0696 — Implement interface parsing: `interface Name { fn sig; ... }`
- [ ] 0697 — Implement event parsing with #[indexed]: `event Name { #[indexed] field: Type, ... }`
- [ ] 0698 — Implement error parsing: `error Name { field: Type, ... }`
- [ ] 0699 — Implement expression parsing (precedence climbing)
- [ ] 0700 — Implement if/else parsing
- [ ] 0701 — Implement for loop parsing: `for i in start..end { ... }`
- [ ] 0702 — Implement while loop parsing
- [ ] 0703 — Implement match expression parsing
- [ ] 0704 — Implement let statement parsing: `let [mut] name [: Type] = expr;`
- [ ] 0705 — Implement emit statement parsing: `emit EventName { fields };`
- [ ] 0706 — Implement require! macro parsing: `require!(cond, error);`
- [ ] 0707 — Implement revert! macro parsing: `revert!(error);`
- [ ] 0708 — Implement raw_call! macro parsing
- [ ] 0709 — Implement assert_eq! macro parsing (for tests)
- [ ] 0710 — Implement cross-contract call parsing: `Interface::at(addr).method(args)`
- [ ] 0711 — Implement type cast parsing: `expr as Type`
- [ ] 0712 — Implement module and use statement parsing
- [ ] 0713 — Implement attribute parsing (#[...] on functions, fields)
- [ ] 0714 — Implement error recovery (synchronize on `}` or `;`)
- [ ] 0715 — Test: parse minimal contract (storage + one function)
- [ ] 0716 — Test: parse ERC20 contract (full example from book)
- [ ] 0717 — Test: parse auction contract
- [ ] 0718 — Test: parse resource types (Coin, NFT)
- [ ] 0719 — Test: parse all attribute variants
- [ ] 0720 — Test: error messages with source location

### M9.3 — Name Resolution

- [ ] 0721 — Build symbol table (contract-level scope)
- [ ] 0722 — Resolve storage field references (self.field)
- [ ] 0723 — Resolve function references (local and cross-contract)
- [ ] 0724 — Resolve type references (struct, resource, interface)
- [ ] 0725 — Resolve module imports (use statements)
- [ ] 0726 — Detect duplicate definitions
- [ ] 0727 — Detect undefined references
- [ ] 0728 — Test: undefined variable detected
- [ ] 0729 — Test: duplicate function name detected
- [ ] 0730 — Test: cross-module reference resolved

### M9.4 — Type Checking

- [ ] 0731 — Implement type inference for `let` bindings
- [ ] 0732 — Implement type checking for assignments
- [ ] 0733 — Implement type checking for function arguments and return types
- [ ] 0734 — Implement type checking for arithmetic operations (both operands same type)
- [ ] 0735 — Implement type checking for comparisons
- [ ] 0736 — Implement type checking for `as` casts (widening/narrowing rules)
- [ ] 0737 — Implement type checking for map access (storage only)
- [ ] 0738 — Implement type checking for struct field access
- [ ] 0739 — Implement type checking for event emit (all fields match event def)
- [ ] 0740 — Implement type checking for error constructors
- [ ] 0741 — Implement type checking for cross-contract calls (interface matching)
- [ ] 0742 — Test: type mismatch in assignment detected
- [ ] 0743 — Test: wrong argument type detected
- [ ] 0744 — Test: narrowing cast from u256 to u64 compiles
- [ ] 0745 — Test: map used outside storage rejected

### M9.5 — Resource Linearity Checking

- [ ] 0746 — Implement move tracking (resource invalidated after move)
- [ ] 0747 — Implement use-after-move detection
- [ ] 0748 — Implement drop detection (resource goes out of scope without destroy)
- [ ] 0749 — Implement copy detection (resource assigned to two variables)
- [ ] 0750 — Implement destroy statement validation
- [ ] 0751 — Implement resource return tracking (function must return/destroy/transfer)
- [ ] 0752 — Test: use-after-move error
- [ ] 0753 — Test: undestroyed resource error
- [ ] 0754 — Test: valid resource move compiles
- [ ] 0755 — Test: destroy + return extracted value compiles

### M9.6 — Visibility and Safety Checking

- [ ] 0756 — Implement visibility enforcement (pub vs internal)
- [ ] 0757 — Implement view function purity check (no SSTORE, no emit, no state-modifying calls)
- [ ] 0758 — Implement reentrancy guard insertion (default on for pub functions)
- [ ] 0759 — Implement #[reentrant] flag (skip guard insertion)
- [ ] 0760 — Implement #[only_owner] insertion (inject require! at function start)
- [ ] 0761 — Implement #[role(ROLE)] insertion
- [ ] 0762 — Implement #[constructor] validation (only one, runs once)
- [ ] 0763 — Implement #[parallel_safe] verification (static access analysis)
- [ ] 0764 — Test: internal function called externally → error
- [ ] 0765 — Test: view function with SSTORE → error
- [ ] 0766 — Test: #[only_owner] injects correct require! check
- [ ] 0767 — Test: #[constructor] rejects second constructor
- [ ] 0768 — Test: #[parallel_safe] rejects function with global state access

### M9.7 — IR Generation (OtiIR)

- [ ] 0769 — Define OtiIR instruction set (SSA form, register-based)
- [ ] 0770 — Implement AST → OtiIR lowering for expressions
- [ ] 0771 — Implement AST → OtiIR lowering for control flow
- [ ] 0772 — Implement AST → OtiIR lowering for storage operations
- [ ] 0773 — Implement AST → OtiIR lowering for function calls
- [ ] 0774 — Implement overflow check insertion for arithmetic
- [ ] 0775 — Implement bounds check insertion for array/vector access
- [ ] 0776 — Implement event encoding (topic hash + ABI encode)
- [ ] 0777 — Implement error encoding (selector + ABI encode)
- [ ] 0778 — Implement storage key derivation code generation
- [ ] 0779 — Test: simple function lowers to correct IR
- [ ] 0780 — Test: overflow checks present in IR for arithmetic ops

### M9.8 — IR Optimization Passes

- [ ] 0781 — Implement constant folding
- [ ] 0782 — Implement dead code elimination
- [ ] 0783 — Implement common subexpression elimination
- [ ] 0784 — Implement function inlining (small internal functions)
- [ ] 0785 — Implement storage coalescing (batch reads/writes to same slot)
- [ ] 0786 — Implement overflow check fusion (merge adjacent checks)
- [ ] 0787 — Implement unused variable elimination
- [ ] 0788 — Test: constant folding reduces `1 + 2` to `3`
- [ ] 0789 — Test: dead code after revert! removed
- [ ] 0790 — Test: small function inlined

### M9.9 — Code Generation (OtiIR → PVM Bytecode)

- [ ] 0791 — Implement register allocation (IR virtual registers → PVM r0-r15, w0-w7)
- [ ] 0792 — Implement register spilling (spill to stack when registers exhausted)
- [ ] 0793 — Implement instruction selection (IR ops → PVM opcodes)
- [ ] 0794 — Implement jump/branch target resolution
- [ ] 0795 — Implement function prologue/epilogue generation
- [ ] 0796 — Implement ABI encoding for calldata and return data
- [ ] 0797 — Implement constructor vs runtime code separation
- [ ] 0798 — Implement function selector dispatch (entry point routing)
- [ ] 0799 — Test: compiled bytecode runs correctly on PVM interpreter
- [ ] 0800 — Test: ERC20 contract compiles and runs token transfer

### M9.10 — Binary Output (.pyc)

- [ ] 0801 — Implement .pyc binary format (magic, version, code, storage schema, ABI, events, errors)
- [ ] 0802 — Implement ABI generation (JSON format for SDK consumption)
- [ ] 0803 — Implement storage schema generation
- [ ] 0804 — Implement source map generation (bytecode offset → source line)
- [ ] 0805 — Test: .pyc file parseable
- [ ] 0806 — Test: ABI matches function signatures
- [ ] 0807 — Test: source map maps correctly

### M9.11 — Compiler CLI

- [ ] 0808 — Implement `otic build` command (compile .oti → .pyc)
- [ ] 0809 — Implement `otic check` command (type check without codegen)
- [ ] 0810 — Implement `otic fmt` command (auto-format source code)
- [ ] 0811 — Implement `otic test` command (run #[test] functions)
- [ ] 0812 — Implement `otic abi` command (output ABI JSON)
- [ ] 0813 — Implement `otic build --parachain` command (Otigen Extended → native)
- [ ] 0814 — Implement error output formatting (colored, with source context)
- [ ] 0815 — Implement warning output (unused variables, etc.)
- [ ] 0816 — Test: CLI builds example contracts
- [ ] 0817 — Test: CLI reports errors with correct line numbers
- [ ] 0818 — Test: `otic test` runs and reports test results

---

## Phase 10: Node Binary

### M10.1 — Node Skeleton

- [ ] 0819 — Create `pyde-node` crate (binary)
- [ ] 0820 — Implement CLI argument parsing (--role validator|prover|full)
- [ ] 0821 — Implement configuration file loading (TOML)
- [ ] 0822 — Implement logging framework (structured logs, levels)
- [ ] 0823 — Implement metrics collection (Prometheus endpoint)
- [ ] 0824 — Implement graceful shutdown (SIGTERM handler)
- [ ] 0825 — Test: node starts and stops cleanly for each role

### M10.2 — Validator Role

- [ ] 0826 — Implement validator startup (load keys, connect to network)
- [ ] 0827 — Implement stake verification (check 10,000 PYDE deposited)
- [ ] 0828 — Implement consensus participation (HotStuff message loop)
- [ ] 0829 — Implement block proposal (when selected as proposer)
- [ ] 0830 — Implement block voting
- [ ] 0831 — Implement threshold decryption participation
- [ ] 0832 — Implement proof verification (when proof arrives)
- [ ] 0833 — Implement committee duty tracking
- [ ] 0834 — Test: validator joins committee and participates in consensus
- [ ] 0835 — Test: validator proposes block when selected

### M10.3 — Prover Role

- [ ] 0836 — Implement prover startup (load bond info, connect to network)
- [ ] 0837 — Implement block assignment reception
- [ ] 0838 — Implement witness reception from full nodes
- [ ] 0839 — Implement block execution against witnesses
- [ ] 0840 — Implement proof generation (invoke pyde-prover)
- [ ] 0841 — Implement proof submission to validators
- [ ] 0842 — Implement prover reward claim
- [ ] 0843 — Test: prover receives block, executes, proves, submits

### M10.4 — Full Node Role

- [ ] 0844 — Implement full node startup (sync state)
- [ ] 0845 — Implement state storage (full SMT on disk)
- [ ] 0846 — Implement transaction relay (receive from users, forward to validators)
- [ ] 0847 — Implement witness generation (from access lists)
- [ ] 0848 — Implement witness delivery to provers
- [ ] 0849 — Implement RPC server startup
- [ ] 0850 — Test: full node syncs and serves state queries

### M10.5 — RPC API

- [ ] 0851 — Implement JSON-RPC server (HTTP + WebSocket)
- [ ] 0852 — Implement `pyde_getBalance(address)` → u256
- [ ] 0853 — Implement `pyde_getTransactionCount(address)` → nonce
- [ ] 0854 — Implement `pyde_getCode(address)` → bytecode
- [ ] 0855 — Implement `pyde_getStorageAt(address, key)` → value
- [ ] 0856 — Implement `pyde_sendTransaction(signedTx)` → tx_hash
- [ ] 0857 — Implement `pyde_call(callObject)` → result (simulate without committing)
- [ ] 0858 — Implement `pyde_estimateGas(callObject)` → gas estimate
- [ ] 0859 — Implement `pyde_getBlockByNumber(height)` → Block
- [ ] 0860 — Implement `pyde_getBlockByHash(hash)` → Block
- [ ] 0861 — Implement `pyde_getTransactionReceipt(tx_hash)` → Receipt
- [ ] 0862 — Implement `pyde_getLogs(filter)` → Vec<Log> (event filtering)
- [ ] 0863 — Implement `pyde_gasPrice()` → current base fee
- [ ] 0864 — Implement `pyde_chainId()` → chain ID
- [ ] 0865 — Implement `pyde_blockNumber()` → latest block height
- [ ] 0866 — Implement WebSocket subscriptions (newHeads, logs, pendingTransactions)
- [ ] 0867 — Test: each RPC method returns correct data
- [ ] 0868 — Test: WebSocket subscription delivers events
- [ ] 0869 — Benchmark: RPC throughput (requests/sec)

---

## Phase 11: Developer Tools

### M11.1 — SDK (TypeScript)

- [ ] 0870 — Create `pyde-sdk` npm package
- [ ] 0871 — Implement Provider class (connect to RPC node)
- [ ] 0872 — Implement Wallet class (FALCON-512 key management)
- [ ] 0873 — Implement transaction building (create, sign, send)
- [ ] 0874 — Implement contract deployment helper
- [ ] 0875 — Implement contract interaction (ABI-based call encoding/decoding)
- [ ] 0876 — Implement event listener (filter logs by topic)
- [ ] 0877 — Implement access list auto-generation (simulate tx, extract state access)
- [ ] 0878 — Implement gas estimation
- [ ] 0879 — Implement transaction receipt polling
- [ ] 0880 — Test: deploy contract via SDK
- [ ] 0881 — Test: call contract function via SDK
- [ ] 0882 — Test: listen for events via SDK

### M11.2 — SDK (Rust)

- [ ] 0883 — Create `pyde-sdk` Rust crate
- [ ] 0884 — Implement RPC client (HTTP + WebSocket)
- [ ] 0885 — Implement FALCON-512 key management
- [ ] 0886 — Implement transaction building and signing
- [ ] 0887 — Implement contract ABI encoding/decoding
- [ ] 0888 — Implement access list generation
- [ ] 0889 — Test: end-to-end contract deployment and call

### M11.3 — CLI Wallet

- [ ] 0890 — Create `pyde-cli` crate
- [ ] 0891 — Implement `pyde wallet create` (generate FALCON-512 keypair)
- [ ] 0892 — Implement `pyde wallet import` (import secret key)
- [ ] 0893 — Implement `pyde wallet balance` (query balance)
- [ ] 0894 — Implement `pyde transfer` (send native tokens)
- [ ] 0895 — Implement `pyde deploy` (deploy .pyc contract)
- [ ] 0896 — Implement `pyde call` (call contract function)
- [ ] 0897 — Implement `pyde tx status` (check transaction receipt)
- [ ] 0898 — Implement keystore encryption (password-protected key file)
- [ ] 0899 — Test: create wallet, fund it, send transfer, check receipt

### M11.4 — Block Explorer Backend

- [ ] 0900 — Create `pyde-explorer` crate
- [ ] 0901 — Implement block indexer (subscribe to new blocks, store in DB)
- [ ] 0902 — Implement transaction indexer
- [ ] 0903 — Implement event/log indexer
- [ ] 0904 — Implement address balance tracker
- [ ] 0905 — Implement contract verification (match source to deployed bytecode)
- [ ] 0906 — Implement REST API for explorer frontend
- [ ] 0907 — Test: indexer processes blocks and serves queries

### M11.5 — Testing Framework

- [ ] 0908 — Implement local devnet (single-node validator for testing)
- [ ] 0909 — Implement test harness (deploy contracts, send txs, assert state)
- [ ] 0910 — Implement time manipulation (advance block timestamp)
- [ ] 0911 — Implement snapshot/revert (save/restore state for test isolation)
- [ ] 0912 — Implement gas profiling (per-function gas usage report)
- [ ] 0913 — Implement coverage analysis (which bytecode lines executed)
- [ ] 0914 — Test: test harness runs ERC20 test suite

---

## Phase 12: Integration Testing

### M12.1 — Single-Node Tests

- [ ] 0915 — Test: genesis block created on startup
- [ ] 0916 — Test: submit transaction, mine block, verify receipt
- [ ] 0917 — Test: deploy contract, call function, verify state change
- [ ] 0918 — Test: ERC20 token: deploy, mint, transfer, check balances
- [ ] 0919 — Test: auction contract: create, bid, withdraw, end
- [ ] 0920 — Test: resource type contract: mint, split, merge, burn
- [ ] 0921 — Test: out-of-gas transaction reverts correctly
- [ ] 0922 — Test: revert rolls back all state changes
- [ ] 0923 — Test: reentrancy guard blocks re-entrant call
- [ ] 0924 — Test: overflow panics correctly
- [ ] 0925 — Test: access list validation
- [ ] 0926 — Test: base fee adjusts based on block fullness
- [ ] 0927 — Test: elastic block (2x, 3x, 4x gas target)

### M12.2 — Multi-Node Tests

- [ ] 0928 — Test: 4-node validator network reaches consensus
- [ ] 0929 — Test: 10-node network with provers and full nodes
- [ ] 0930 — Test: block propagation to all nodes
- [ ] 0931 — Test: transaction submitted to full node reaches validator
- [ ] 0932 — Test: new node syncs from existing network
- [ ] 0933 — Test: leader failure triggers view change
- [ ] 0934 — Test: double-sign slashing
- [ ] 0935 — Test: committee rotation at epoch boundary
- [ ] 0936 — Test: threshold decryption of transactions
- [ ] 0937 — Test: VRF ordering of decrypted transactions

### M12.3 — Stress Tests

- [ ] 0938 — Test: sustain 1,000 TPS for 10 minutes
- [ ] 0939 — Test: sustain 5,000 TPS for 10 minutes
- [ ] 0940 — Test: sustain 12,500 TPS for 10 minutes (target sustained)
- [ ] 0941 — Test: burst 50,000 TPS for 30 seconds (target peak)
- [ ] 0942 — Test: large contract deployment (100 KB bytecode)
- [ ] 0943 — Test: deep call chain (50 nested contract calls)
- [ ] 0944 — Test: wide parallel execution (1000 non-conflicting transfers)
- [ ] 0945 — Test: state growth over 100,000 blocks
- [ ] 0946 — Benchmark: end-to-end latency (tx submission → soft finality)
- [ ] 0947 — Benchmark: end-to-end latency (tx submission → hard finality)

### M12.4 — Fault Tolerance Tests

- [ ] 0948 — Test: network partition (split validators, heal, verify no fork)
- [ ] 0949 — Test: 42 of 128 validators offline (< 1/3 byzantine threshold)
- [ ] 0950 — Test: prover failure (block still gets proven by backup prover)
- [ ] 0951 — Test: full node crash and recovery
- [ ] 0952 — Test: disk full handling (graceful degradation)
- [ ] 0953 — Test: clock skew between validators (up to 200ms)

---

## Phase 13: Governance

### M13.1 — PIP (Pyde Improvement Proposal) System

- [ ] 0954 — Define PIP struct (id, title, description, type, proposer, status)
- [ ] 0955 — Define PIP types: Parameter, Protocol, Constitutional
- [ ] 0956 — Implement PIP submission (on-chain transaction)
- [ ] 0957 — Implement PIP discussion period (7 days)
- [ ] 0958 — Implement PIP voting period (14 days)
- [ ] 0959 — Test: submit and query PIP

### M13.2 — Two-Chamber Voting

- [ ] 0960 — Implement Validator Council voting (1 validator = 1 vote)
- [ ] 0961 — Implement Community Assembly voting (10K PYDE cap per address)
- [ ] 0962 — Implement quorum requirements per PIP type
- [ ] 0963 — Implement threshold requirements (51% Parameter, 67% Protocol, 90% Constitutional)
- [ ] 0964 — Implement vote tallying and result computation
- [ ] 0965 — Test: parameter PIP passes with 51% approval
- [ ] 0966 — Test: protocol PIP requires 67%
- [ ] 0967 — Test: constitutional PIP requires 90%
- [ ] 0968 — Test: insufficient quorum → PIP fails

### M13.3 — Parameter Governance

- [ ] 0969 — Implement parameter change execution (on PIP approval)
- [ ] 0970 — Implement gas limit parameter change
- [ ] 0971 — Implement base fee bounds parameter change
- [ ] 0972 — Implement validator stake amount change (protocol tier)
- [ ] 0973 — Implement prover bond amount change
- [ ] 0974 — Implement parameter bounds enforcement (min/max limits)
- [ ] 0975 — Test: approved parameter PIP changes parameter at next epoch

### M13.4 — Treasury

- [ ] 0976 — Implement treasury account (accumulates portion of inflation)
- [ ] 0977 — Implement treasury spend proposals
- [ ] 0978 — Implement treasury balance query
- [ ] 0979 — Test: treasury accumulates funds from inflation
- [ ] 0980 — Test: approved spend proposal transfers from treasury

---

## Phase 14: Tokenomics Implementation

### M14.1 — Token Mechanics

- [ ] 0981 — Implement PYDE native token (genesis distribution)
- [ ] 0982 — Implement genesis allocation (1 billion PYDE)
- [ ] 0983 — Implement inflation schedule (5% → 3% → 2% → 1%)
- [ ] 0984 — Implement inflation per-block calculation
- [ ] 0985 — Implement block reward distribution
- [ ] 0986 — Test: genesis state has correct total supply
- [ ] 0987 — Test: inflation rate decreases on schedule
- [ ] 0988 — Test: block reward distributed correctly

### M14.2 — Staking

- [ ] 0989 — Implement validator staking (lock 10,000 PYDE)
- [ ] 0990 — Implement validator unstaking (with unbonding period)
- [ ] 0991 — Implement prover bonding (lock 1,000 PYDE)
- [ ] 0992 — Implement prover unbonding
- [ ] 0993 — Implement staking reward distribution
- [ ] 0994 — Implement slashing deduction from stake/bond
- [ ] 0995 — Test: stake, earn rewards, unstake after unbonding period
- [ ] 0996 — Test: slashing reduces stake correctly

### M14.3 — Fee Burning

- [ ] 0997 — Implement fee collection on transaction execution
- [ ] 0998 — Implement 70% burn (send to burn address, reduce total supply)
- [ ] 0999 — Implement 20% validator reward
- [ ] 1000 — Implement 10% prover reward
- [ ] 1001 — Implement burn tracking (cumulative burned amount)
- [ ] 1002 — Test: fee split matches 70/20/10
- [ ] 1003 — Test: burned tokens reduce circulating supply
- [ ] 1004 — Test: validator and prover receive correct shares

---

## Phase 15: MEV Protection Integration

### M15.1 — End-to-End MEV Protection

- [ ] 1005 — Integrate threshold encryption into transaction submission flow
- [ ] 1006 — Integrate threshold decryption into block construction
- [ ] 1007 — Integrate VRF shuffle into transaction ordering
- [ ] 1008 — Implement MEV protection verification (check ordering is VRF-determined)
- [ ] 1009 — Test: transaction content invisible to proposer during ordering
- [ ] 1010 — Test: decrypted transactions are shuffled by VRF
- [ ] 1011 — Test: front-running attempt fails (transaction encrypted)
- [ ] 1012 — Test: sandwich attack impossible (ordering unpredictable)

### M15.2 — PSS Integration

- [ ] 1013 — Implement PSS key refresh at epoch boundary
- [ ] 1014 — Implement committee handoff (old committee → new committee)
- [ ] 1015 — Implement in-flight transaction re-encryption (if needed)
- [ ] 1016 — Test: key refresh preserves ability to decrypt pending transactions
- [ ] 1017 — Test: old committee cannot decrypt new epoch transactions

---

## Phase 16: Devnet

### M16.1 — Local Devnet

- [ ] 1018 — Implement devnet genesis config generator
- [ ] 1019 — Implement `pyde devnet` command (start local 4-validator network)
- [ ] 1020 — Implement automatic account funding (faucet)
- [ ] 1021 — Implement devnet dashboard (block explorer + metrics)
- [ ] 1022 — Test: devnet starts and produces blocks
- [ ] 1023 — Test: deploy and interact with contract on devnet

### M16.2 — Docker Setup

- [ ] 1024 — Create Dockerfile for pyde-node
- [ ] 1025 — Create docker-compose.yml for multi-node devnet
- [ ] 1026 — Create docker-compose.yml for validator + prover + full node
- [ ] 1027 — Test: docker-compose network starts and operates

### M16.3 — Monitoring

- [ ] 1028 — Implement Prometheus metrics endpoint
- [ ] 1029 — Create Grafana dashboard (blocks, TPS, latency, peers, gas)
- [ ] 1030 — Implement structured logging (JSON format for log aggregation)
- [ ] 1031 — Implement alerting rules (missed blocks, peer count drop, etc.)
- [ ] 1032 — Test: metrics endpoint returns valid Prometheus data

---

## Phase 17: Public Testnet Alpha

### M17.1 — Testnet Genesis

- [ ] 1033 — Define testnet genesis config (validators, initial balances)
- [ ] 1034 — Implement testnet faucet service (web + API)
- [ ] 1035 — Implement testnet block explorer deployment
- [ ] 1036 — Implement testnet RPC endpoint (public)
- [ ] 1037 — Create testnet documentation (how to connect, get tokens, deploy)

### M17.2 — Testnet Infrastructure

- [ ] 1038 — Deploy 16 validator nodes (geographically distributed)
- [ ] 1039 — Deploy 4 prover nodes
- [ ] 1040 — Deploy 8 full nodes (RPC endpoints)
- [ ] 1041 — Deploy monitoring stack (Prometheus + Grafana)
- [ ] 1042 — Implement automated restart on crash
- [ ] 1043 — Implement log aggregation

### M17.3 — Testnet Validation

- [ ] 1044 — Run 500+ PVM test vectors on testnet
- [ ] 1045 — Deploy ERC20 on testnet and run token operations
- [ ] 1046 — Deploy auction contract on testnet
- [ ] 1047 — Test: 100 TPS sustained for 1 hour
- [ ] 1048 — Test: 1000 TPS sustained for 1 hour
- [ ] 1049 — Test: node restart and resync
- [ ] 1050 — Test: validator rotation at epoch boundary

---

## Phase 18: Public Testnet Beta

### M18.1 — ZK Integration on Testnet

- [ ] 1051 — Deploy provers on testnet with proof generation enabled
- [ ] 1052 — Implement proof verification in validator consensus loop
- [ ] 1053 — Test: blocks finalized with valid ZK proofs
- [ ] 1054 — Test: invalid proof rejected by validators
- [ ] 1055 — Benchmark: proof generation time on testnet
- [ ] 1056 — Benchmark: hard finality latency on testnet

### M18.2 — MEV Protection on Testnet

- [ ] 1057 — Enable threshold encryption on testnet
- [ ] 1058 — Enable VRF transaction shuffling on testnet
- [ ] 1059 — Test: encrypted mempool operates correctly
- [ ] 1060 — Test: threshold decryption succeeds with committee
- [ ] 1061 — Test: MEV extraction attempt fails

### M18.3 — Performance Optimization

- [ ] 1062 — Profile and optimize PVM interpreter hot path
- [ ] 1063 — Profile and optimize AOT compiler output
- [ ] 1064 — Profile and optimize Poseidon2 hash throughput
- [ ] 1065 — Profile and optimize state tree operations
- [ ] 1066 — Profile and optimize proof generation pipeline
- [ ] 1067 — Profile and optimize network message handling
- [ ] 1068 — Profile and optimize block construction pipeline
- [ ] 1069 — Implement memory pool optimization (reduce allocations)
- [ ] 1070 — Implement parallel proof verification
- [ ] 1071 — Benchmark: sustained TPS after optimization (target: 12,500)

---

## Phase 19: Cross-Chain (Phase 2 Feature)

### M19.1 — Parachain Framework

- [ ] 1072 — Define parachain registration protocol
- [ ] 1073 — Implement parachain ID allocation
- [ ] 1074 — Implement parachain state root commitment on main chain
- [ ] 1075 — Implement collator node framework
- [ ] 1076 — Implement parachain block production
- [ ] 1077 — Implement shared security (main chain validates parachain proofs)
- [ ] 1078 — Test: register parachain and produce blocks

### M19.2 — Cross-Chain Parachain

- [ ] 1079 — Implement unified cross-chain parachain
- [ ] 1080 — Implement CrossChainMessage type
- [ ] 1081 — Implement cross_call() contract API
- [ ] 1082 — Implement callback pattern (success/error handlers)
- [ ] 1083 — Implement message routing (main chain → parachain → external chain)
- [ ] 1084 — Test: cross_call() emits message, parachain receives it

### M19.3 — Chain Modules

- [ ] 1085 — Implement ChainModule trait (Rust interface)
- [ ] 1086 — Implement Ethereum module (light client verification)
- [ ] 1087 — Implement Solana module (light client verification)
- [ ] 1088 — Implement Bitcoin module (SPV verification)
- [ ] 1089 — Test: cross-chain message to Ethereum testnet
- [ ] 1090 — Test: cross-chain message to Solana devnet
- [ ] 1091 — Test: cross-chain callback received and processed

### M19.4 — Otigen Extended Compiler

- [ ] 1092 — Implement `parachain` keyword in parser
- [ ] 1093 — Implement `on message` handler in parser
- [ ] 1094 — Implement `send_to_main()` in parser
- [ ] 1095 — Implement `on external_response` in parser
- [ ] 1096 — Implement `config {}` block parsing
- [ ] 1097 — Implement Otigen Extended → native binary compilation
- [ ] 1098 — Implement `otic build --parachain` pipeline
- [ ] 1099 — Test: compile cross-chain bridge parachain from book example
- [ ] 1100 — Test: compile oracle parachain from book example

---

## Phase 20: Protocol Upgrades System

### M20.1 — Upgrade Infrastructure

- [ ] 1101 — Implement protocol version tracking
- [ ] 1102 — Implement activation height mechanism
- [ ] 1103 — Implement feature flags (enable/disable features per version)
- [ ] 1104 — Implement upgrade signaling (validators signal readiness)
- [ ] 1105 — Implement upgrade activation (auto-activate at height when threshold met)
- [ ] 1106 — Test: upgrade signals collected from validators
- [ ] 1107 — Test: upgrade activates at correct height

### M20.2 — Emergency Path

- [ ] 1108 — Implement emergency upgrade proposal (90% threshold, 24h voting)
- [ ] 1109 — Implement emergency halt (stop chain for critical bug)
- [ ] 1110 — Implement recovery from emergency halt
- [ ] 1111 — Test: emergency upgrade activates within 24 hours

---

## Phase 21: Security Audit Preparation

### M21.1 — Code Quality

- [ ] 1112 — Run clippy on all crates (zero warnings)
- [ ] 1113 — Run cargo audit (zero known vulnerabilities in dependencies)
- [ ] 1114 — Run cargo deny (license compliance check)
- [ ] 1115 — Implement fuzzing targets for PVM interpreter
- [ ] 1116 — Implement fuzzing targets for transaction validation
- [ ] 1117 — Implement fuzzing targets for consensus message handling
- [ ] 1118 — Implement fuzzing targets for RPC input parsing
- [ ] 1119 — Implement fuzzing targets for Otigen parser
- [ ] 1120 — Run fuzzers for 72+ hours each target
- [ ] 1121 — Fix all crashes found by fuzzers

### M21.2 — Formal Verification (Critical Paths)

- [ ] 1122 — Formally verify Poseidon2 implementation matches spec
- [ ] 1123 — Formally verify base fee adjustment correctness
- [ ] 1124 — Formally verify gas metering never underflows
- [ ] 1125 — Formally verify state root computation determinism
- [ ] 1126 — Formally verify threshold decryption correctness

### M21.3 — Audit Preparation

- [ ] 1127 — Prepare audit scope document
- [ ] 1128 — Prepare architecture overview for auditors
- [ ] 1129 — Prepare threat model document
- [ ] 1130 — Document all cryptographic assumptions
- [ ] 1131 — Document all trust boundaries
- [ ] 1132 — Create invariant documentation (properties that must always hold)

---

## Phase 22: Incentivized Testnet

### M22.1 — Incentivized Testnet Launch

- [ ] 1133 — Deploy incentivized testnet (rewards for validators/provers)
- [ ] 1134 — Implement reward tracking system
- [ ] 1135 — Implement bug bounty program
- [ ] 1136 — Deploy reference dApps (DEX, lending, NFT marketplace)
- [ ] 1137 — Run for 3+ months

### M22.2 — Load Testing

- [ ] 1138 — Achieve 12,500 sustained TPS
- [ ] 1139 — Achieve 50,000 peak TPS (4x elastic burst)
- [ ] 1140 — Sustain for 7 days without restart
- [ ] 1141 — Handle 1000+ concurrent validators attempting to join
- [ ] 1142 — Handle 100+ concurrent provers

### M22.3 — Community Testing

- [ ] 1143 — Community deploys 100+ contracts
- [ ] 1144 — Community runs 50+ validators
- [ ] 1145 — Community runs 20+ provers
- [ ] 1146 — Community runs 50+ full nodes
- [ ] 1147 — Document all issues found by community
- [ ] 1148 — Fix all critical and high-severity issues

---

## Phase 23: Mainnet Preparation

### M23.1 — Final Audit

- [ ] 1149 — External audit: consensus layer
- [ ] 1150 — External audit: PVM and execution layer
- [ ] 1151 — External audit: cryptographic implementations
- [ ] 1152 — External audit: networking layer
- [ ] 1153 — External audit: Otigen compiler
- [ ] 1154 — External audit: ZK proving system
- [ ] 1155 — Fix all audit findings

### M23.2 — Mainnet Genesis

- [ ] 1156 — Finalize mainnet genesis config
- [ ] 1157 — Finalize token distribution
- [ ] 1158 — Deploy genesis validators (initial 128+ committee)
- [ ] 1159 — Deploy genesis provers
- [ ] 1160 — Deploy genesis full nodes (RPC infrastructure)
- [ ] 1161 — Coordinate genesis ceremony

### M23.3 — Launch Infrastructure

- [ ] 1162 — Deploy mainnet block explorer
- [ ] 1163 — Deploy mainnet faucet (for initial distribution)
- [ ] 1164 — Deploy mainnet RPC endpoints (geographically distributed)
- [ ] 1165 — Deploy mainnet monitoring (24/7 alerting)
- [ ] 1166 — Establish incident response process
- [ ] 1167 — Create operator documentation

---

## Task Count Summary

| Phase                             | Tasks     |
| --------------------------------- | --------- |
| Phase 0: Cryptographic Primitives | 75        |
| Phase 1: PVM                      | 201       |
| Phase 2: State Model              | 76        |
| Phase 3: Account Model            | 35        |
| Phase 4: Transaction Processing   | 78        |
| Phase 5: Consensus                | 67        |
| Phase 6: Mempool & Ordering       | 26        |
| Phase 7: Networking               | 47        |
| Phase 8: ZK Proving               | 81        |
| Phase 9: Otigen Compiler          | 149       |
| Phase 10: Node Binary             | 51        |
| Phase 11: Developer Tools         | 45        |
| Phase 12: Integration Testing     | 39        |
| Phase 13: Governance              | 27        |
| Phase 14: Tokenomics              | 24        |
| Phase 15: MEV Protection          | 13        |
| Phase 16: Devnet                  | 15        |
| Phase 17: Testnet Alpha           | 18        |
| Phase 18: Testnet Beta            | 21        |
| Phase 19: Cross-Chain             | 29        |
| Phase 20: Protocol Upgrades       | 11        |
| Phase 21: Security Audit Prep     | 21        |
| Phase 22: Incentivized Testnet    | 16        |
| Phase 23: Mainnet Preparation     | 19        |
| **TOTAL**                         | **1,184** |
