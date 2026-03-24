# Pyde Custom STARK Prover — Design Plan

## Core Insights

### 1. Checked Arithmetic = Native Field Arithmetic

The PVM uses **checked arithmetic** — ADD/SUB/MUL all trap on overflow/underflow.
This means for every valid execution trace, all intermediate values stay within [0, 2^64).
Since Goldilocks p = 2^64 - 2^32 + 1 ≈ 2^64, **field arithmetic directly represents
PVM arithmetic** for valid traces — no limb decomposition needed for GP registers.

For u256 (wide registers): 4 × u64 limbs in Goldilocks, same checked semantics.

### 2. Conflict-Based Grouping = Full Prover Parallelism

Transactions are grouped by **conflict** (shared storage slots), not by independence.

- **Within a group**: transactions conflict → execute SEQUENTIALLY
- **Between groups**: no conflicts → execute and prove FULLY IN PARALLEL

This eliminates inter-group state chains entirely. Each group starts from the same
`pre_state_root`, produces its own `state_diff`, and groups merge cleanly because
their storage access sets are disjoint by construction.

```
ScheduledBlock:
  pre_state_root: R0

  Group 0: [txA → txC → txG]   all touch storage slot S1
  Group 1: [txB → txE → txH]   all touch storage slot S2
  Group 2: [txD → txF]         all touch storage slot S3

  Execution (FULLY PARALLEL):
    Prover A: execute Group 0 from R0 → diff_0 = {S1: old→new}
    Prover B: execute Group 1 from R0 → diff_1 = {S2: old→new}
    Prover C: execute Group 2 from R0 → diff_2 = {S3: old→new}

  Aggregator:
    Verify: diff_0 ∩ diff_1 ∩ diff_2 = ∅ (no conflicts)
    post_state = apply(R0, diff_0 ∪ diff_1 ∪ diff_2)
```

**Benefits over sequential group model:**

- No state chain dependency between provers (fully parallel)
- No dry-run of all groups (each prover only executes their group)
- No waiting for prior group's post_state
- Simpler aggregation (merge non-conflicting diffs)
- Simpler proof: each group proves "from R0, these txs produce this diff"

---

## Architecture

```
OUR CODE (PVM-specific):
├── trace.rs          — Execution trace format
├── constraint.rs     — PVM constraint evaluator (plain Rust, no traits)
├── prover.rs         — Trace → polynomial commits → FRI proof
├── verifier.rs       — Proof → check commits → verify FRI → accept/reject
├── lookup.rs         — Lookup argument for bitwise ops (logup)
├── multi_table.rs    — Group proving orchestration (keep existing)
├── pipeline.rs       — Committee pipeline (keep existing)
├── recursive.rs      — Block composition (keep existing)
└── registry.rs       — Prover committee (keep existing)

PLONKY3 PRIMITIVES (imported, not wrapped):
├── p3-goldilocks     — Goldilocks field arithmetic
├── p3-poseidon2      — Poseidon2 hash
├── p3-dft            — NTT (polynomial evaluation on domains)
├── p3-fri            — FRI protocol (low-degree testing)
├── p3-merkle-tree    — Merkle commitments for polynomials
├── p3-commit         — PCS interface (TwoAdicFriPcs)
└── p3-challenger     — Fiat-Shamir transcript

NOT USED:
├── p3-air            — Generic AIR traits (replaced by our constraint.rs)
└── p3-uni-stark      — Generic prover/verifier (replaced by our prover.rs/verifier.rs)
```

---

## Phase 1: Trace Format

### GP Registers (64-bit): 1 column each

Since PVM uses checked arithmetic, GP values always fit in Goldilocks natively.
No limb decomposition. 16 registers = 16 columns.

```
value < 2^64 (checked by PVM)
value < p (p ≈ 2^64, almost all u64 values)
field_element = Goldilocks::from_canonical_u64(value)
```

For the rare case where value ∈ [p, 2^64): `from_canonical_u64` reduces mod p.
Field equation `result = a + b` still holds because (a+b) mod p = (result) mod p.

### Wide Registers (256-bit): 4 columns each (4 × u64 limbs)

No field exists where u256 fits natively. Standard limb decomposition:

```
wide_value = limb[0] + limb[1]*2^64 + limb[2]*2^128 + limb[3]*2^192
```

8 wide registers × 4 limbs = 32 columns.

Wide arithmetic (WADD/WSUB/WMUL) uses carry propagation between limbs.
Same approach as current `air.rs` but cleaner (no AIR trait overhead).

### Core Trace Columns

| Section                                      | Columns | Count   |
| -------------------------------------------- | ------- | ------- |
| Control (pc, opcode, rd, rs1, rs2_imm)       | 5       | 5       |
| GP registers (r0-r15)                        | 16      | 16      |
| Wide registers (w0-w7 × 4 limbs)             | 32      | 32      |
| Memory (addr, val[4], width, is_write)       | 7       | 7       |
| Storage (key[4], val[4], len, is_write)      | 10      | 10      |
| Gas (step, cumulative)                       | 2       | 2       |
| Flags (is_mem, is_storage, is_final)         | 3       | 3       |
| Opcode bits (6-bit decomposition)            | 6       | 6       |
| Operands (op_a, op_b, op_result, op_aux)     | 4       | 4       |
| Register selectors (rd_sel[16], rs1_sel[16]) | 32      | 32      |
| Branch/call (taken, diff_inv, call_depth)    | 3       | 3       |
| Wide carry (4 limbs)                         | 4       | 4       |
| Wide quotient (4 limbs)                      | 4       | 4       |
| **Total**                                    |         | **128** |

**128 columns vs current 880.** Dramatically smaller trace.

### What's Removed

| Removed                             | Was      | Why                                                      |
| ----------------------------------- | -------- | -------------------------------------------------------- |
| op_a_bits[64] + op_b_bits[64]       | 128 cols | Replaced by lookup table for bitwise ops                 |
| wide_a_bits[256] + wide_b_bits[256] | 512 cols | Replaced by lookup table for wide bitwise                |
| rs2_sel[16]                         | 16 cols  | Only needed for register-register ops, use op_b directly |
| shift_remainder                     | 1 col    | Folded into op_aux                                       |
| comparison_diff                     | 1 col    | Folded into op_aux                                       |
| wmul_cross_lo[9] + wmul_cross_hi[9] | 18 cols  | Handled via lookup or recursive MUL                      |
| merkle_path[32] + merkle_dir[32]    | 64 cols  | Moved to separate Merkle verification table              |

---

## Phase 2: Constraint Evaluator

### Design: Plain Rust Functions

No traits. No generics. Two concrete implementations:

```rust
/// Prover-side: evaluates constraints at packed Goldilocks values.
/// Called once per quotient-domain row during proving.
fn evaluate_constraints_prover(
    curr: &TraceRow,           // current row values
    next: &TraceRow,           // next row values
    alpha: Goldilocks,         // constraint folding challenge
    selectors: &RowSelectors,  // is_first, is_last, is_transition
) -> Goldilocks {
    let mut acc = Goldilocks::ZERO;

    // Each constraint: acc = acc * alpha + constraint_value
    // Constraint value must be 0 for valid traces

    evaluate_opcode_constraints(curr, next, &mut acc, alpha);
    evaluate_memory_constraints(curr, &mut acc, alpha);
    evaluate_control_flow(curr, next, &mut acc, alpha, selectors);
    evaluate_gas_constraints(curr, next, &mut acc, alpha, selectors);

    acc
}

/// Verifier-side: evaluates constraints at extension field point (zeta).
/// Called once during verification.
fn evaluate_constraints_verifier(
    curr: &[EF],              // opened trace values at zeta
    next: &[EF],              // opened trace values at zeta*g
    alpha: EF,
    selectors: &PointSelectors,
) -> EF {
    // Same logic but over extension field
}
```

### Constraint Categories

#### Arithmetic (ADD, SUB, MUL, DIV, MOD, ADDI)

For checked arithmetic, the constraint is simply field arithmetic:

```
ADD:  is_add * not_final * (result - op_a - op_b) = 0
SUB:  is_sub * not_final * (result + op_b - op_a) = 0
MUL:  is_mul * not_final * (result - op_a * op_b) = 0
DIV:  is_div * not_final * (op_a - result * op_b - op_aux) = 0  // op_aux = remainder
MOD:  is_mod * not_final * (op_a - op_aux * op_b - result) = 0  // op_aux = quotient
ADDI: is_addi * not_final * (result - op_a - op_b) = 0
```

The `not_final` gate ensures trapped instructions don't fire constraints.
No carry columns needed — checked arithmetic guarantees no overflow.

#### Bitwise Operations (AND, OR, XOR, NOT, SHL, SHR) — Via Lookup Table

**Problem**: Bitwise ops are not algebraic. `a & b` has no polynomial representation.

**Old approach**: 64-bit decomposition (128 extra columns per row). Expensive.

**New approach**: 8-bit lookup table (logup argument).

Decompose each 64-bit value into 8 bytes. For each byte position, look up
the bitwise operation result in a precomputed table:

```
Lookup table (256 × 256 = 65536 entries):
  AND_TABLE[a_byte][b_byte] = a_byte & b_byte
  OR_TABLE[a_byte][b_byte]  = a_byte | b_byte
  XOR_TABLE[a_byte][b_byte] = a_byte ^ b_byte
```

For a 64-bit AND: 8 lookup queries (one per byte), reconstruct result from bytes.

**Columns needed**: 16 per bitwise row (8 bytes of op_a + 8 bytes of op_b).
The result bytes come from the lookup table.

BUT: we can do even better. Instead of adding byte columns to every row,
use a **separate lookup table** connected via logup:

1. Execution trace emits (opcode, a_byte, b_byte, result_byte) per byte position
2. Lookup table AIR proves each (a, b, result) triple is in the precomputed table
3. Logup argument proves the multisets match

This adds 0 columns to the main trace. The lookup table is a separate ~65K-row table
proven once per block.

**For SHL/SHR**: Use the power-of-2 trick (already working, no lookup needed):

```
SHL: result = op_a * 2^shift_amount
SHR: op_a = result * 2^shift_amount + remainder
```

#### Comparisons (EQ, LT, GT, SLT, SGT)

**EQ**: Uses diff_inv witness (already correct):

```
(op_a - op_b) * diff_inv = 1 - result
(op_a - op_b) * result = 0
```

**LT/GT**: For checked arithmetic, we know both values are < 2^64.
Use the subtraction approach:

```
LT(a, b): if a < b, then b - a - 1 is a valid u64 (non-negative)
           if a >= b, then a - b is a valid u64
```

Store the difference in op_aux. The range check (value is valid u64) is enforced
by the lookup table: decompose op_aux into 8 bytes, look up each byte ∈ [0, 255].

**SLT/SGT**: Signed comparison. XOR the sign bit (bit 63) to convert to unsigned,
then apply the same difference technique.

#### Memory Operations (LOAD, STORE, PUSH, POP, WLOAD, WSTORE)

```
LOAD/POP:   is_load * (result - mem_val[0]) = 0      // loaded value matches
STORE/PUSH: is_store * (op_a - mem_val[0]) = 0        // stored value matches
WLOAD:      is_wload * (wide_result[i] - mem_val[i]) = 0  // per limb
WSTORE:     is_wstore * (wide_op_a[i] - mem_val[i]) = 0   // per limb
```

Plus: is_memory_op flag must be set. Memory consistency (read-after-write)
verified by separate Memory AIR + permutation argument (keep existing approach).

#### Control Flow (JMP, BEQ, BNE, BLT, BGE, CALL, RET, HALT, REVERT)

```
Sequential PC: not_final * not_branch * (next_pc - pc - 4) = 0
JMP:           is_jmp * (next_pc - pc - offset) = 0
BEQ:           is_beq * (op_a - op_b) * (next_pc - pc - 4) = 0
BNE:           is_bne * (1 - (op_a - op_b)*diff_inv) * (next_pc - pc - 4) = 0
CALL:          is_call * (next_call_depth - call_depth - 1) = 0
RET:           is_ret * (next_call_depth - call_depth + 1) = 0
HALT:          is_halt * (1 - is_final) = 0
REVERT:        is_revert * (1 - is_final) = 0
```

#### Syscalls (CALLER, CALLVALUE, BLOCKHASH, SLOAD, SSTORE, etc.)

```
SLOAD:   is_sload * (1 - is_storage_op) = 0     // must flag storage
SSTORE:  is_sstore * (1 - is_storage_op) = 0
         is_sstore * (1 - storage_is_write) = 0  // must flag write
CALLEXT: is_callext * (next_call_depth - call_depth - 1) = 0
LOG:     is_log * is_storage_op = 0              // LOG doesn't touch storage
ASSERT:  is_assert * (op_a * diff_inv - 1 + is_final) = 0  // if op_a=0 → final
```

Context queries (CALLER, CALLVALUE, BLOCKHASH) verified via public inputs.
POSEIDON hash verified via cross-table Poseidon2 bus.

#### Gas Accounting

```
Transition: not_final * (next_gas_cum - gas_cum - next_gas_step) = 0
```

#### Register Writeback

```
// For ops that write to GP[rd]: gp[rd] in current row matches result
is_writes_gp * (mux(rd_sel, gp_regs) - result) = 0

// For ops that write to wide registers: handled per-opcode
```

---

## Phase 3: Lookup Table (Logup) for Bitwise Ops

### Why Lookups

Bitwise AND/OR/XOR/NOT cannot be expressed as polynomial constraints without
bit decomposition (which adds 128 columns). Lookup arguments replace bit
decomposition with a precomputed table check.

### The Table

A fixed table of all 8-bit operations:

```
| a (0-255) | b (0-255) | and_result | or_result | xor_result |
|-----------|-----------|------------|-----------|------------|
| 0         | 0         | 0          | 0         | 0          |
| 0         | 1         | 0          | 1         | 1          |
| ...       | ...       | ...        | ...       | ...        |
| 255       | 255       | 255        | 255       | 0          |
```

65,536 rows. Fixed (preprocessed), never changes.

### The Argument (Logarithmic Derivative / Logup)

For each bitwise operation in the execution trace:

1. Decompose op_a into 8 bytes: a[0], a[1], ..., a[7]
2. Decompose op_b into 8 bytes: b[0], b[1], ..., b[7]
3. For each byte position i: assert (a[i], b[i], result_byte[i]) exists in the table
4. Reconstruct: result = sum of result_byte[i] \* 256^i

The logup argument proves this with O(1) verifier work per lookup,
regardless of how many lookups there are.

### Columns Added to Main Trace: 0

The byte decompositions go into a separate "lookup bus" table (like memory bus).
The main trace only has op_a, op_b, result — same 3 columns as before.

### Implementation

Use Plonky3's logup support or implement a basic version:

- Prover: compute multiplicities (how many times each table row is accessed)
- Random challenge β from Fiat-Shamir
- Running sum: Σ multiplicity_i / (β - row_fingerprint_i) = Σ 1 / (β - query_fingerprint_j)
- Single field element comparison at the end

---

## Phase 4: Custom Prover Pipeline

### prove() — Step by Step

```rust
pub fn prove(trace: &PaddedTrace, public_values: &[Goldilocks]) -> Proof {
    let config = build_fri_config();
    let pcs = build_pcs(config);
    let mut challenger = new_challenger();

    // 1. Commit to trace polynomials
    let (trace_commit, trace_data) = pcs.commit(trace_domain, trace_matrix);

    // 2. Fiat-Shamir: get constraint folding challenge
    challenger.observe(trace_commit);
    challenger.observe_slice(public_values);
    let alpha: EF = challenger.sample_ext_element();

    // 3. Compute quotient polynomial on quotient domain
    //    This is where OUR constraint evaluator runs
    let quotient_values = compute_quotient(
        &trace_data, &pcs, trace_domain, quotient_domain, alpha, public_values
    );

    // 4. Commit to quotient polynomial
    let (quotient_commit, quotient_data) = pcs.commit(quotient_chunks);

    // 5. Fiat-Shamir: get OOD evaluation point
    challenger.observe(quotient_commit);
    let zeta: EF = challenger.sample();

    // 6. Open trace + quotient at zeta, produce FRI proof
    let opening = pcs.open(trace_data, quotient_data, zeta, &mut challenger);

    // 7. Package proof
    Proof { commitments, opened_values, opening_proof }
}
```

### compute_quotient() — The Hot Loop

```rust
fn compute_quotient(trace_data, pcs, trace_domain, quotient_domain, alpha, public_values)
    -> Vec<Goldilocks>
{
    let trace_on_quot = pcs.get_evaluations_on_domain(trace_data, quotient_domain);
    let selectors = quotient_domain.selectors_on_coset(trace_domain);

    let mut quotient = Vec::with_capacity(quotient_domain.size());

    for i in 0..quotient_domain.size() {
        let curr = trace_on_quot.row(i);
        let next = trace_on_quot.row((i + 1) % quotient_domain.size());
        let sel = selectors[i];

        // OUR constraint evaluator — plain Rust, no traits
        let constraint_value = evaluate_constraints_prover(curr, next, alpha, sel);

        quotient.push(constraint_value * sel.inv_zeroifier);
    }

    quotient
}
```

### verify() — Step by Step

```rust
pub fn verify(proof: &Proof, public_values: &[Goldilocks]) -> Result<(), Error> {
    let config = build_fri_config();
    let pcs = build_pcs(config);
    let mut challenger = new_challenger();

    // 1. Replay Fiat-Shamir (must match prover exactly)
    challenger.observe(proof.commitments.trace);
    challenger.observe_slice(public_values);
    let alpha: EF = challenger.sample_ext_element();
    challenger.observe(proof.commitments.quotient);
    let zeta: EF = challenger.sample();

    // 2. Verify PCS openings (FRI check)
    pcs.verify(proof.opening_proof, &mut challenger)?;

    // 3. Re-evaluate constraints at zeta (single point)
    let folded = evaluate_constraints_verifier(
        &proof.opened_values.trace_local,
        &proof.opened_values.trace_next,
        alpha, zeta, public_values,
    );

    // 4. Check: constraints(zeta) / Z_H(zeta) == quotient(zeta)
    if folded * inv_zeroifier_at_zeta != quotient_at_zeta {
        return Err(Error::ConstraintMismatch);
    }

    Ok(())
}
```

---

## Phase 5: FRI Configuration

```
Field:          Goldilocks (p = 2^64 - 2^32 + 1)
Extension:      Quadratic (degree 2 over Goldilocks)
Hash:           Poseidon2 (width=8, Goldilocks)
log_blowup:     3 (8x blowup — good balance of proof size vs speed)
num_queries:     24 (≈100-bit security)
pow_bits:        12
Max constraint degree: ~8 (opcode_selector(6) × operand × result)
```

### Proof Size Estimate

With 128 columns and 24 FRI queries:

- Trace commitment: 1 Merkle root (32 bytes)
- Quotient commitment: 1 Merkle root (32 bytes)
- Opened values: 128 × 2 (local + next) × 16 bytes = ~4 KB
- FRI query proofs: 24 queries × ~2 KB each = ~48 KB
- **Total: ~55 KB per group proof** (within 50-100 KB target)

---

## Phase 6: Cross-Table Arguments

### Memory Bus (keep existing approach)

Execution trace → Memory AIR (sorted by address + timestamp).
Permutation argument proves same multiset of (addr, value, is_write, timestamp).

### Hash Bus (keep existing approach)

Execution trace → Poseidon2 AIR.
Each POSEIDON/SLOAD/SSTORE hash operation verified via cross-table bus.

### Lookup Bus (new — for bitwise ops)

Execution trace → Lookup Table (precomputed 8-bit operations).
Logup argument proves each byte-level operation exists in the table.

### Range-Check Bus (keep existing approach)

Values that need u64 range verification → Range-Check AIR.
Comparison diffs, shift remainders, wide carries.

---

## Implementation Order

### Step 1: New trace format (trace.rs rewrite)

- 128-column TraceRow
- to_fields() / from_fields()
- Padding logic
- Column index constants

### Step 2: Constraint evaluator (constraint.rs — new file)

- evaluate_constraints_prover() for Goldilocks
- evaluate_constraints_verifier() for extension field
- All 62 opcode constraints as plain Rust
- Opcode selector computation (6-bit product)
- Register multiplexer (rd_sel × gp_regs)

### Step 3: Custom prover (prover.rs rewrite)

- prove() using TwoAdicFriPcs directly
- compute_quotient() with our constraint evaluator
- FRI configuration
- Proof type definition

### Step 4: Custom verifier (verifier.rs — new file)

- verify() using TwoAdicFriPcs directly
- Constraint re-evaluation at OOD point
- Quotient check

### Step 5: Lookup table for bitwise ops (lookup.rs — new file)

- Precomputed 8-bit AND/OR/XOR/NOT table
- Logup argument (prover + verifier)
- Integration with constraint evaluator

### Step 6: Recorder update (recorder.rs update)

- Emit 128-column rows instead of 880
- Remove bit decomposition columns
- Remove wmul_cross columns
- Remove merkle columns

### Step 7: Multi-table integration (multi_table.rs update)

- Wire new prover/verifier
- Keep memory bus, hash bus, range-check bus
- Add lookup bus for bitwise ops

### Step 8: Pipeline integration (pipeline.rs — major update)

Rewrite group model:

- Groups contain CONFLICTING txs (sequential within group)
- All groups run in PARALLEL (no cross-group conflicts)
- No state chain between groups
- Each group starts from same pre_state_root
- Each group produces an independent state_diff
- Aggregator merges non-conflicting diffs

### Step 9: Aggregation + Block Proof (recursive.rs — rewrite)

New aggregation model:

```rust
pub struct GroupProof {
    pub group_index: usize,
    /// All groups share the same pre_state_root
    pub pre_state_root: [u8; 32],
    /// State diff: (storage_key, old_value, new_value) for modified slots
    pub state_diff: Vec<StateDiffEntry>,
    /// Access list: all storage keys this group touches
    pub access_list: Vec<[u8; 32]>,
    /// STARK proof of correct execution
    pub proof_bytes: Vec<u8>,
    /// Gas used by all txs in this group
    pub gas_used: u64,
    /// Number of transactions
    pub tx_count: usize,
}

pub struct BlockProof {
    pub slot: u64,
    pub block_hash: [u8; 32],
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub group_proofs: Vec<GroupProof>,
    pub total_gas: u64,
    pub total_txs: usize,
}

pub fn compose_block_proof(
    slot: u64,
    block_hash: [u8; 32],
    pre_state_root: [u8; 32],
    group_proofs: Vec<GroupProof>,
) -> Result<BlockProof, String> {
    // 1. Verify ALL groups start from same pre_state_root
    for gp in &group_proofs {
        if gp.pre_state_root != pre_state_root {
            return Err("group doesn't start from block pre_state");
        }
    }

    // 2. Verify no access list overlaps between groups
    //    (groups are disjoint by construction)
    for i in 0..group_proofs.len() {
        for j in (i+1)..group_proofs.len() {
            if has_overlap(&group_proofs[i].access_list, &group_proofs[j].access_list) {
                return Err("groups have overlapping access lists");
            }
        }
    }

    // 3. Merge all state diffs → compute post_state_root
    let merged_diff = merge_diffs(&group_proofs);
    let post_state_root = apply_diff(pre_state_root, &merged_diff);

    // 4. Package block proof
    Ok(BlockProof {
        slot, block_hash, pre_state_root, post_state_root,
        group_proofs, total_gas, total_txs,
    })
}

pub fn verify_block_proof(block_proof: &BlockProof) -> Result<(), String> {
    // 1. Verify each group STARK proof
    for gp in &block_proof.group_proofs {
        verify_group_stark(&gp.proof_bytes)?;
    }

    // 2. Verify access list disjointness
    verify_no_overlaps(&block_proof.group_proofs)?;

    // 3. Verify post_state_root = apply(pre_state, merged_diffs)
    verify_state_transition(block_proof)?;

    Ok(())
}
```

### Step 10: Prover Pipeline (pipeline.rs — simplified)

```rust
/// Each committee member's workflow:
pub fn prove_my_groups(
    block: &ScheduledBlock,
    my_group_indices: &[usize],
    witnesses: &StateWitnesses,
) -> Vec<GroupProof> {
    // All groups start from the SAME pre_state_root
    // No dry-run of other groups needed!

    my_group_indices.par_iter().map(|&g_idx| {
        let group = &block.groups[g_idx];

        // 1. Execute txs sequentially (they conflict within group)
        let (trace, state_diff) = execute_group(group, &block.pre_state_root, witnesses);

        // 2. Generate STARK proof
        let proof = prove(&trace, &public_inputs_for(g_idx, &state_diff));

        GroupProof {
            group_index: g_idx,
            pre_state_root: block.pre_state_root,
            state_diff,
            access_list: group.access_list(),
            proof_bytes: serialize_proof(&proof),
            gas_used: trace.total_gas(),
            tx_count: group.txs.len(),
        }
    }).collect()
}
```

### Step 11: Testing + benchmarking

- Port existing tests to new format
- Realistic benchmark (20 txs, parallel groups)
- Verify no state chain needed
- Performance comparison vs old approach

---

## The Full Pipeline (End-to-End)

```
VALIDATORS build ScheduledBlock:
  Conflict graph from access lists → group conflicting txs together
  Result: N groups, each internally sequential, mutually disjoint

VALIDATORS broadcast ScheduledBlock + threshold-decrypt tx payloads

FULL NODES generate state witnesses for each group's access list

PROVER COMMITTEE receives ScheduledBlock + witnesses
  Each member assigned K groups (round-robin)
  ALL groups start from the SAME pre_state_root

  Prover A: prove_my_groups([G0, G3, G6]) → 3 GroupProofs  ← parallel!
  Prover B: prove_my_groups([G1, G4, G7]) → 3 GroupProofs  ← parallel!
  Prover C: prove_my_groups([G2, G5, G8]) → 3 GroupProofs  ← parallel!

  Each GroupProof contains:
    - pre_state_root (same for all)
    - state_diff (only this group's changes)
    - access_list (disjoint from other groups)
    - STARK proof

AGGREGATOR collects all GroupProofs:
  1. Verify access lists are disjoint (no conflicts between groups)
  2. Merge all state_diffs
  3. Compute post_state_root
  4. Package BlockProof

VALIDATORS verify BlockProof:
  1. Verify each group STARK proof
  2. Verify access list disjointness
  3. Verify post_state = apply(pre_state, merged_diffs)
  → HARD FINALITY
```

---

## Expected Performance

| Metric              | Old (880 cols, p3-uni-stark) | New (128 cols, custom) | Target           |
| ------------------- | ---------------------------- | ---------------------- | ---------------- |
| Group prove (8 txs) | 1540ms                       | ~200-400ms             | 1500ms           |
| Proof size          | 100-120 KB                   | ~50-60 KB              | 50-100 KB        |
| Verify (per group)  | ~100ms                       | ~30-50ms               | <5ms (recursive) |
| Trace width         | 880 columns                  | 128 columns            | —                |
| Constraint count    | ~96                          | ~50                    | —                |

The 128-column trace is ~7x narrower. Since STARK proving scales roughly
linearly with trace width, we expect ~5-7x speedup just from the column reduction,
plus additional gains from:

- Removing AIR trait overhead (direct Rust function calls)
- Full prover parallelism (no state chain waits)
- Lookup tables instead of bit decomposition

---

## What We Keep vs Replace

### Keep (proven, working):

- `registry.rs` — prover committee management
- `poseidon2_air.rs` — Poseidon2 hash verification (adapt for custom prover)
- `memory_air.rs` — memory consistency verification (adapt for custom prover)
- `range_check_air.rs` — u64 range verification (adapt for custom prover)
- `cross_table.rs` — permutation argument math

### Rewrite (new architecture):

- `trace.rs` → 128-column format
- `air.rs` → `constraint.rs` (plain Rust constraint evaluator)
- `prove.rs` → `prover.rs` (custom pipeline using Plonky3 primitives)
- New: `verifier.rs` (custom verifier)
- `recorder.rs` → emit 128-column rows
- `multi_table.rs` → parallel group model, no state chain
- `pipeline.rs` → simplified (no dry-run needed)
- `recursive.rs` → diff-merge model instead of state chain
- New: `lookup.rs` (logup for bitwise ops)
- `trace.rs` → rewrite (128 columns)
- `recorder.rs` → update (emit 128-column rows)

### Dependencies Change:

```
Remove:  p3-air, p3-uni-stark
Keep:    p3-goldilocks, p3-poseidon2, p3-dft, p3-fri, p3-merkle-tree,
         p3-commit, p3-challenger, p3-symmetric, p3-maybe-rayon
Add:     zstd (proof compression)
```

---

## Why Conflict-Based Grouping is Superior

### Old Model (Independence-Based):

```
Group = {non-conflicting txs} → parallel WITHIN group
Groups execute SEQUENTIALLY → serial BETWEEN groups
Prover needs state chain: G0.post → G1.pre → G1.post → G2.pre ...
Every prover must dry-run ALL groups to know intermediate states
```

### New Model (Conflict-Based):

```
Group = {conflicting txs} → sequential WITHIN group (must be)
Groups are DISJOINT → parallel BETWEEN groups (can be)
All groups start from SAME pre_state_root
No prover needs any other prover's output
```

### Comparison:

| Aspect            | Old (sequential groups)          | New (parallel groups)                  |
| ----------------- | -------------------------------- | -------------------------------------- |
| Prover dependency | Each needs prior group's state   | None — fully independent               |
| Dry-run required? | Yes — all groups, all provers    | No — only assigned groups              |
| State chain       | Complex (chain of roots)         | None (shared pre_state)                |
| Aggregation       | Verify chain integrity           | Verify disjointness + merge diffs      |
| Max parallelism   | Limited by chain                 | Unlimited (all groups parallel)        |
| Proving latency   | Bottleneck = sum of dependencies | Bottleneck = slowest single group      |
| Fault tolerance   | One late prover delays the chain | One late prover only delays its groups |

### Scheduling Algorithm (Validators):

```rust
fn build_conflict_groups(txs: Vec<Transaction>) -> Vec<Vec<Transaction>> {
    // 1. Build conflict graph: edge between txs that share storage keys
    let mut conflict_graph = ConflictGraph::new();
    for i in 0..txs.len() {
        for j in (i+1)..txs.len() {
            if txs[i].access_list.overlaps(&txs[j].access_list) {
                conflict_graph.add_edge(i, j);
            }
        }
    }

    // 2. Find connected components = conflict groups
    //    All txs in a connected component touch overlapping storage
    //    and must execute sequentially
    let components = conflict_graph.connected_components();

    // 3. Within each component, order by nonce (sender ordering)
    components.iter().map(|component| {
        let mut group: Vec<Transaction> = component.iter()
            .map(|&idx| txs[idx].clone())
            .collect();
        group.sort_by_key(|tx| (tx.from, tx.nonce));
        group
    }).collect()
}
```

Connected components naturally give us the groups:

- Txs in the same component MUST be sequential (they conflict)
- Txs in different components CAN be parallel (they don't conflict)
- This is optimal — no unnecessary serialization

---

## Security Properties

| Property                     | How enforced                                                     |
| ---------------------------- | ---------------------------------------------------------------- |
| Arithmetic correctness       | Field constraints (checked arith = field arith for valid traces) |
| Memory consistency           | Memory AIR + permutation argument                                |
| Hash integrity               | Poseidon2 AIR + hash bus                                         |
| Bitwise correctness          | Lookup table + logup argument                                    |
| Range validity               | Range-check AIR + range bus                                      |
| Control flow integrity       | PC continuity + branch constraints                               |
| Group disjointness           | Access list overlap check by aggregator + validators             |
| State transition correctness | Each group proves pre_state + txs → diff; aggregator merges      |
| Gas accounting               | Gas monotonic accumulation constraint                            |
| Instruction authenticity     | Opcode bits decomposition + selector product                     |
| Register integrity           | rd_sel multiplexer + writeback constraint                        |
| FRI soundness                | Plonky3 (battle-tested, used by SP1, Polygon)                    |
| Fiat-Shamir binding          | Plonky3 challenger (DuplexChallenger with Poseidon2)             |
| Proof-of-work                | Grinding resistance via PoW bits in FRI config                   |
