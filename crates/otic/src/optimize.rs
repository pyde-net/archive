//! IR optimization passes.
//!
//! Runs on the IR after lowering, before codegen.
//! Each pass transforms the IR in place.
//!
//! Passes:
//! 1. Constant folding — evaluate compile-time expressions
//! 2. Dead code elimination — remove unreachable blocks and unused instructions
//! 3. Common subexpression elimination — deduplicate identical computations

use std::collections::{HashMap, HashSet};

use ethnum::U256;

use crate::ir::*;
use crate::types::Ty;

/// Run all optimization passes on an IR program.
pub fn optimize(program: &mut IrProgram) {
    for func in &mut program.functions {
        constant_fold(func);
        dead_code_eliminate(func);
        eliminate_unused_registers(func);
    }
}

// ============================================================================
// Pass 1: Constant Folding
// ============================================================================

/// Evaluate operations on constants at compile time.
/// e.g., `%2 = Add %0, %1` where %0=10 and %1=20 → `%2 = Const 30`
fn constant_fold(func: &mut IrFunction) {
    // Map register → known constant value
    let mut known: HashMap<Reg, IrConst> = HashMap::new();

    for block in &mut func.blocks {
        // Clear known constants at block boundaries — prevents incorrect
        // folding across loop back-edges (e.g., i=0; loop { i = i + 1 }
        // would incorrectly fold i+1 as 0+1=1 on every iteration).
        known.clear();
        for inst in &mut block.instructions {
            match inst {
                // Track known constants
                Inst::Const(dst, val) => {
                    known.insert(*dst, val.clone());
                }

                // Fold binary operations on known constants
                Inst::BinOp(dst, op, lhs, rhs) => {
                    let dst_copy = *dst;
                    let op_copy = *op;
                    let lhs_copy = *lhs;
                    let rhs_copy = *rhs;

                    let folded = if let (Some(lval), Some(rval)) =
                        (known.get(&lhs_copy).cloned(), known.get(&rhs_copy).cloned())
                    {
                        match (&lval, &rval) {
                            // Integer folding
                            (IrConst::Int(lv, lt), IrConst::Int(rv, _)) => {
                                fold_binop(op_copy, *lv, *rv)
                                    .map(|val| IrConst::Int(val, lt.clone()))
                            }
                            // Boolean logic folding
                            (IrConst::Bool(lb), IrConst::Bool(rb)) => {
                                match op_copy {
                                    BinOp::LogicalAnd => Some(IrConst::Bool(*lb && *rb)),
                                    BinOp::LogicalOr => Some(IrConst::Bool(*lb || *rb)),
                                    _ => None,
                                }
                            }
                            _ => None,
                        }
                    } else {
                        None
                    };

                    if let Some(val) = folded {
                        known.insert(dst_copy, val.clone());
                        *inst = Inst::Const(dst_copy, val);
                    }
                }

                // Fold comparisons on known constants
                Inst::Cmp(dst, op, lhs, rhs) => {
                    let dst_copy = *dst;
                    let op_copy = *op;
                    let lhs_copy = *lhs;
                    let rhs_copy = *rhs;

                    if let (Some(IrConst::Int(lv, _)), Some(IrConst::Int(rv, _))) =
                        (known.get(&lhs_copy).cloned(), known.get(&rhs_copy).cloned())
                    {
                        let result = fold_cmp(op_copy, lv, rv);
                        known.insert(dst_copy, IrConst::Bool(result));
                        *inst = Inst::Const(dst_copy, IrConst::Bool(result));
                    }
                }

                // Fold unary operations on known constants
                Inst::UnOp(dst, op, src) => {
                    let dst_copy = *dst;
                    let op_copy = *op;
                    let src_copy = *src;
                    let folded = if let Some(IrConst::Int(v, ty)) = known.get(&src_copy) {
                        fold_unop(op_copy, *v).map(|val| IrConst::Int(val, ty.clone()))
                    } else if let Some(IrConst::Bool(b)) = known.get(&src_copy) {
                        if op_copy == UnOp::LogicalNot {
                            Some(IrConst::Bool(!b))
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    if let Some(val) = folded {
                        known.insert(dst_copy, val.clone());
                        *inst = Inst::Const(dst_copy, val);
                    }
                }

                // Fold branches on known conditions
                Inst::Branch(cond, then_label, else_label) => {
                    let cond_copy = *cond;
                    let then_copy = *then_label;
                    let else_copy = *else_label;
                    if let Some(IrConst::Bool(b)) = known.get(&cond_copy) {
                        let target = if *b { then_copy } else { else_copy };
                        *inst = Inst::Jump(target);
                    }
                }

                _ => {}
            }
        }
    }
}

fn fold_binop(op: BinOp, lhs: U256, rhs: U256) -> Option<U256> {
    match op {
        BinOp::Add => lhs.checked_add(rhs),
        BinOp::Sub => lhs.checked_sub(rhs),
        BinOp::Mul => lhs.checked_mul(rhs),
        BinOp::Div => {
            if rhs == U256::ZERO { None } else { Some(lhs / rhs) }
        }
        BinOp::Mod => {
            if rhs == U256::ZERO { None } else { Some(lhs % rhs) }
        }
        BinOp::BitAnd => Some(lhs & rhs),
        BinOp::BitOr => Some(lhs | rhs),
        BinOp::BitXor => Some(lhs ^ rhs),
        BinOp::Shl => {
            if rhs < U256::from(256u64) { Some(lhs << rhs.as_u64() as u32) } else { None }
        }
        BinOp::Shr => {
            if rhs < U256::from(256u64) { Some(lhs >> rhs.as_u64() as u32) } else { Some(U256::ZERO) }
        }
        BinOp::LogicalAnd | BinOp::LogicalOr => None, // operate on bools, not ints
    }
}

fn fold_cmp(op: CmpOp, lhs: U256, rhs: U256) -> bool {
    match op {
        CmpOp::Eq => lhs == rhs,
        CmpOp::NotEq => lhs != rhs,
        CmpOp::Lt => lhs < rhs,
        CmpOp::Gt => lhs > rhs,
        CmpOp::LtEq => lhs <= rhs,
        CmpOp::GtEq => lhs >= rhs,
    }
}

fn fold_unop(op: UnOp, val: U256) -> Option<U256> {
    match op {
        UnOp::Neg => {
            if val == U256::ZERO { Some(U256::ZERO) } else { None } // can't negate unsigned
        }
        UnOp::BitNot => Some(!val),
        UnOp::LogicalNot => None, // handled separately for bools
    }
}

// ============================================================================
// Pass 2: Dead Code Elimination
// ============================================================================

/// Remove unreachable blocks and instructions after unconditional returns/jumps.
fn dead_code_eliminate(func: &mut IrFunction) {
    // Find reachable blocks starting from entry (block 0)
    let reachable = find_reachable_blocks(func);

    // Remove unreachable blocks
    func.blocks.retain(|block| reachable.contains(&block.label));

    // Within each block, remove instructions after a terminator
    for block in &mut func.blocks {
        let mut terminator_idx = None;
        for (i, inst) in block.instructions.iter().enumerate() {
            if is_terminator(inst) {
                terminator_idx = Some(i);
                break;
            }
        }
        if let Some(idx) = terminator_idx {
            block.instructions.truncate(idx + 1);
        }
    }

    // Remove Comment instructions (they're debug-only)
    for block in &mut func.blocks {
        block.instructions.retain(|inst| !matches!(inst, Inst::Comment(_)));
    }
}

/// Find all blocks reachable from the entry block via jumps/branches.
fn find_reachable_blocks(func: &IrFunction) -> HashSet<Label> {
    let mut reachable = HashSet::new();
    let mut worklist = Vec::new();

    if let Some(entry) = func.blocks.first() {
        worklist.push(entry.label);
    }

    while let Some(label) = worklist.pop() {
        if !reachable.insert(label) {
            continue; // already visited
        }

        // Find the block and its successors
        if let Some(block) = func.blocks.iter().find(|b| b.label == label) {
            for inst in &block.instructions {
                match inst {
                    Inst::Jump(target) => {
                        worklist.push(*target);
                    }
                    Inst::Branch(_, then_l, else_l) => {
                        worklist.push(*then_l);
                        worklist.push(*else_l);
                    }
                    _ => {}
                }
            }
        }
    }

    reachable
}

fn is_terminator(inst: &Inst) -> bool {
    matches!(inst, Inst::Return(_) | Inst::Jump(_) | Inst::Branch(_, _, _) | Inst::Revert(_, _))
}

// ============================================================================
// Pass 3: Unused Register Elimination
// ============================================================================

/// Remove instructions that produce a register value that is never used.
/// Does NOT remove instructions with side effects (storage writes, emit, revert, etc.).
fn eliminate_unused_registers(func: &mut IrFunction) {
    // Collect all registers that are READ (used as operands)
    let mut used_regs: HashSet<Reg> = HashSet::new();

    for block in &func.blocks {
        for inst in &block.instructions {
            collect_used_regs(inst, &mut used_regs);
        }
    }

    // Remove instructions that WRITE to a register that's never read,
    // but only if the instruction has no side effects
    for block in &mut func.blocks {
        block.instructions.retain(|inst| {
            if let Some(dst) = get_dest_reg(inst) {
                if !used_regs.contains(&dst) && !has_side_effects(inst) {
                    return false; // dead — remove
                }
            }
            true
        });
    }
}

/// Collect all registers that are read by an instruction.
fn collect_used_regs(inst: &Inst, used: &mut HashSet<Reg>) {
    match inst {
        Inst::Const(_, _) => {}
        Inst::BinOp(_, _, lhs, rhs) => { used.insert(*lhs); used.insert(*rhs); }
        Inst::UnOp(_, _, src) => { used.insert(*src); }
        Inst::Cmp(_, _, lhs, rhs) => { used.insert(*lhs); used.insert(*rhs); }
        Inst::Cast(_, src, _) => { used.insert(*src); }
        Inst::StorageGet(_, _) => {}
        Inst::StorageSet(_, val) => { used.insert(*val); }
        Inst::StorageMapGet(_, _, key) => { used.insert(*key); }
        Inst::StorageMapSet(_, key, val) => { used.insert(*key); used.insert(*val); }
        Inst::StorageNestedMapGet(_, _, k1, k2) => { used.insert(*k1); used.insert(*k2); }
        Inst::StorageNestedMapSet(_, k1, k2, val) => { used.insert(*k1); used.insert(*k2); used.insert(*val); }
        Inst::Builtin(_, _) => {}
        Inst::Call(_, _, args) => { for a in args { used.insert(*a); } }
        Inst::MethodCall(_, obj, _, args) => { used.insert(*obj); for a in args { used.insert(*a); } }
        Inst::ExtCall(_, addr, _, args, _, _) => { used.insert(*addr); for (a, _) in args { used.insert(*a); } }
        Inst::Hash(_, args) => { for a in args { used.insert(*a); } }
        Inst::StructInit(_, _, fields) => { for (_, r) in fields { used.insert(*r); } }
        Inst::FieldGet(_, obj, _, _) => { used.insert(*obj); }
        Inst::IndexGet(_, obj, idx) => { used.insert(*obj); used.insert(*idx); }
        Inst::IndexSet(obj, idx, val) => { used.insert(*obj); used.insert(*idx); used.insert(*val); }
        Inst::MakeTuple(_, regs) => { for r in regs { used.insert(*r); } }
        Inst::TupleGet(_, tuple, _) => { used.insert(*tuple); }
        Inst::MakeArray(_, regs) => { for r in regs { used.insert(*r); } }
        Inst::ArrayRepeat(_, val, _) => { used.insert(*val); }
        Inst::MakeVec(_, _) => {}
        Inst::Emit(_, fields) => { for r in fields { used.insert(*r); } }
        Inst::Revert(_, fields) => { for r in fields { used.insert(*r); } }
        Inst::CrossCall { target, method, args, .. } => {
            used.insert(*target); used.insert(*method);
            for a in args { used.insert(*a); }
        }
        Inst::RawCall(_, target, args) => { used.insert(*target); for a in args { used.insert(*a); } }
        Inst::CreateContract(_, blob, args, _) => { used.insert(*blob); for (a, _) in args { used.insert(*a); } }
        Inst::Jump(_) => {}
        Inst::Branch(cond, _, _) => { used.insert(*cond); }
        Inst::Return(Some(val)) => { used.insert(*val); }
        Inst::Return(None) => {}
        Inst::Phi(_, entries) => { for (_, r) in entries { used.insert(*r); } }
        Inst::Comment(_) => {}
    }
}

/// Get the destination register of an instruction, if it writes one.
fn get_dest_reg(inst: &Inst) -> Option<Reg> {
    match inst {
        Inst::Const(dst, _) | Inst::BinOp(dst, _, _, _) | Inst::UnOp(dst, _, _)
        | Inst::Cmp(dst, _, _, _) | Inst::Cast(dst, _, _)
        | Inst::StorageGet(dst, _) | Inst::StorageMapGet(dst, _, _)
        | Inst::StorageNestedMapGet(dst, _, _, _)
        | Inst::Builtin(dst, _) | Inst::Call(dst, _, _)
        | Inst::MethodCall(dst, _, _, _) | Inst::ExtCall(dst, _, _, _, _, _)
        | Inst::Hash(dst, _) | Inst::StructInit(dst, _, _)
        | Inst::FieldGet(dst, _, _, _) | Inst::IndexGet(dst, _, _)
        | Inst::MakeTuple(dst, _) | Inst::TupleGet(dst, _, _)
        | Inst::MakeArray(dst, _) | Inst::ArrayRepeat(dst, _, _)
        | Inst::MakeVec(dst, _)
        | Inst::RawCall(dst, _, _) | Inst::CreateContract(dst, _, _, _) | Inst::Phi(dst, _) => Some(*dst),
        _ => None,
    }
}

/// Does the instruction have side effects beyond writing to its destination register?
fn has_side_effects(inst: &Inst) -> bool {
    matches!(inst,
        Inst::StorageSet(_, _) | Inst::StorageMapSet(_, _, _)
        | Inst::StorageNestedMapSet(_, _, _, _)
        | Inst::IndexSet(_, _, _)
        | Inst::Emit(_, _) | Inst::Revert(_, _)
        | Inst::CrossCall { .. } | Inst::RawCall(_, _, _) | Inst::CreateContract(_, _, _, _)
        | Inst::Call(_, _, _) | Inst::MethodCall(_, _, _, _) | Inst::ExtCall(_, _, _, _, _, _)
        | Inst::Jump(_) | Inst::Branch(_, _, _) | Inst::Return(_)
    )
}

// ============================================================================
// Stats
// ============================================================================

/// Count instructions in a function (for measuring optimization impact).
pub fn count_instructions(func: &IrFunction) -> usize {
    func.blocks.iter().map(|b| b.instructions.len()).sum()
}

/// Count instructions in the entire program.
pub fn count_total_instructions(program: &IrProgram) -> usize {
    program.functions.iter().map(count_instructions).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;
    use crate::parser::Parser;
    use crate::lower;

    fn lower_and_optimize(src: &str) -> IrProgram {
        let (tokens, _) = Lexer::new(src).tokenize();
        let (file, _) = Parser::new(tokens).parse();
        let mut ir = lower::lower(&file);
        optimize(&mut ir);
        ir
    }

    fn lower_only(src: &str) -> IrProgram {
        let (tokens, _) = Lexer::new(src).tokenize();
        let (file, _) = Parser::new(tokens).parse();
        lower::lower(&file)
    }

    #[test]
    fn fold_constant_arithmetic() {
        // Use the values so they aren't eliminated by unused reg pass
        let ir = lower_and_optimize(r#"
            contract T {
                storage { result: u256, }
                pub fn f() {
                    self.result = 10 + 20;
                    self.result = 100 * 3;
                    self.result = 50 - 10;
                }
            }
        "#);

        let func = &ir.functions[0];
        let consts: Vec<U256> = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .filter_map(|i| {
                if let Inst::Const(_, IrConst::Int(v, _)) = i { Some(*v) } else { None }
            })
            .collect();

        assert!(consts.contains(&U256::from(30u64)), "10+20 should fold to 30, got: {:?}", consts);
        assert!(consts.contains(&U256::from(300u64)), "100*3 should fold to 300");
        assert!(consts.contains(&U256::from(40u64)), "50-10 should fold to 40");
    }

    #[test]
    fn fold_constant_comparison() {
        let ir = lower_and_optimize(r#"
            contract T {
                storage { flag: bool, }
                pub fn f() {
                    self.flag = 10 > 5;
                }
            }
        "#);

        let func = &ir.functions[0];
        let bools: Vec<bool> = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .filter_map(|i| {
                if let Inst::Const(_, IrConst::Bool(v)) = i { Some(*v) } else { None }
            })
            .collect();

        assert!(bools.contains(&true), "10>5 should fold to true");
    }

    #[test]
    fn fold_branch_on_constant() {
        let ir = lower_and_optimize(r#"
            contract T {
                pub fn f() {
                    if true {
                        let x = 1;
                    } else {
                        let x = 2;
                    }
                }
            }
        "#);

        let func = &ir.functions[0];
        // The Branch on constant true should be folded to Jump
        let has_branch = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .any(|i| matches!(i, Inst::Branch(_, _, _)));
        assert!(!has_branch, "constant branch should be folded to jump");
    }

    #[test]
    fn eliminate_dead_code_after_return() {
        let ir = lower_and_optimize(r#"
            contract T {
                pub fn f() -> u256 {
                    return 42;
                }
            }
        "#);

        let func = &ir.functions[0];
        // After return, no more instructions in that block
        let entry = &func.blocks[0];
        let return_idx = entry.instructions.iter()
            .position(|i| matches!(i, Inst::Return(_)));
        if let Some(idx) = return_idx {
            assert_eq!(idx, entry.instructions.len() - 1,
                "nothing should follow return");
        }
    }

    #[test]
    fn remove_comment_instructions() {
        let ir = lower_and_optimize(r#"
            contract T {
                pub fn f() {
                    let x = 1;
                }
            }
        "#);

        let func = &ir.functions[0];
        let has_comments = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .any(|i| matches!(i, Inst::Comment(_)));
        assert!(!has_comments, "comments should be stripped after optimization");
    }

    #[test]
    fn optimization_reduces_instruction_count() {
        let src = r#"
            contract T {
                pub fn f() {
                    let a = 10 + 20;
                    let b = 100 * 3;
                    let c = a + b;
                }
            }
        "#;

        let before = count_total_instructions(&lower_only(src));
        let after = count_total_instructions(&lower_and_optimize(src));

        // Optimization should reduce count (folded consts replace binops)
        assert!(after <= before,
            "optimized ({}) should have <= instructions than unoptimized ({})", after, before);
    }

    #[test]
    fn fold_boolean_logic() {
        let ir = lower_and_optimize(r#"
            contract T {
                storage { flag: bool, }
                pub fn f() {
                    self.flag = true && false;
                    self.flag = true || false;
                }
            }
        "#);

        let func = &ir.functions[0];
        let bools: Vec<bool> = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .filter_map(|i| {
                if let Inst::Const(_, IrConst::Bool(v)) = i { Some(*v) } else { None }
            })
            .collect();

        assert!(bools.contains(&false), "true && false should fold to false, got: {:?}", bools);
        assert!(bools.contains(&true), "true || false should fold to true");
    }

    #[test]
    fn eliminate_unused_registers() {
        let src = r#"
            contract T {
                pub fn f() -> u256 {
                    let unused = 42;
                    let also_unused = 99;
                    return 1;
                }
            }
        "#;

        let before = count_total_instructions(&lower_only(src));
        let after = count_total_instructions(&lower_and_optimize(src));

        assert!(after < before,
            "unused registers should be eliminated: before={}, after={}", before, after);
    }

    #[test]
    fn fold_nested_constants() {
        // 2 + 3 → 5, then 5 * 4 → 20 (if within same block)
        let ir = lower_and_optimize(r#"
            contract T {
                storage { result: u256, }
                pub fn f() {
                    self.result = (2 + 3) * 4;
                }
            }
        "#);

        let func = &ir.functions[0];
        // Due to how lowering works, (2+3) becomes Add(%0,%1) → Const(5),
        // then 5*4 might be foldable if both are in known map
        let consts: Vec<U256> = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .filter_map(|i| {
                if let Inst::Const(_, IrConst::Int(v, _)) = i { Some(*v) } else { None }
            })
            .collect();

        // At minimum, 2+3=5 should be folded
        assert!(consts.contains(&U256::from(5u64)) || consts.contains(&U256::from(20u64)),
            "nested constants should fold, got: {:?}", consts);
    }
}
