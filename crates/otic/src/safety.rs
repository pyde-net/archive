//! Visibility and safety checking: validates attributes, visibility rules,
//! and contract-level safety constraints.
//!
//! Runs after type checking. Checks:
//! - #[view] function purity (no state writes, no emit, no state-modifying calls)
//! - #[constructor] uniqueness (only one per contract)
//! - #[sponsored] attribute validation
//! - #[reentrant] attribute validation
//! - Visibility enforcement (pub vs internal)
//! - cross_call! callback function existence
//! - Unknown attribute detection

use std::collections::{HashMap, HashSet};

use crate::ast::*;
use crate::token::Span;

// ============================================================================
// Errors
// ============================================================================

#[derive(Clone, Debug)]
pub struct SafetyError {
    pub message: String,
    pub span: Span,
}

impl std::fmt::Display for SafetyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.span.line, self.span.col, self.message)
    }
}

// ============================================================================
// Known attributes
// ============================================================================

const KNOWN_ATTRIBUTES: &[&str] = &[
    "constructor",
    "view",
    "payable",
    "sponsored",
    "reentrant",
    "indexed",
    "test",
    "should_panic",
    "receive",
    "fallback",
];

/// Check if an attribute name (without args) is known.
fn is_known_attribute(content: &str) -> bool {
    let name = content.split('(').next().unwrap_or(content).trim();
    KNOWN_ATTRIBUTES.contains(&name)
}

// ============================================================================
// Safety Checker
// ============================================================================

pub struct SafetyChecker {
    errors: Vec<SafetyError>,
    /// All function names in the current contract (for callback validation).
    contract_functions: Vec<String>,
    /// Names of storage fields whose declared type is `Map<K, V>` in the
    /// current contract. Populated at the top of `check_contract` and
    /// cleared at the end so the set never bleeds across contracts in the
    /// same `SourceFile`. Used by the for-loop iteration diagnostic
    /// (TPL-603) to flag `for _ in self.<map_field> { ... }` — the IR
    /// codegen has no `StorageMapIter` opcode (see `crates/otic/src/ir.rs`
    /// at the StorageMapGet/Set comments around L256-259), so iteration
    /// over a `Map` lowers to nothing useful and silently runs an empty
    /// body. Catching it in the safety pass turns the silent-no-op into a
    /// loud compile error pointing at the offending `for` line.
    storage_maps: HashSet<String>,
}

impl Default for SafetyChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyChecker {
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
            contract_functions: Vec::new(),
            storage_maps: HashSet::new(),
        }
    }

    pub fn check(mut self, file: &SourceFile) -> SafetyCheckResult {
        for item in &file.items {
            match item {
                Item::Contract(c) => self.check_contract(c),
                Item::Function(f) => self.check_top_level_function(f),
                _ => {}
            }
        }
        SafetyCheckResult {
            errors: self.errors,
        }
    }

    fn error(&mut self, message: String, span: Span) {
        self.errors.push(SafetyError { message, span });
    }

    // ========================================================================
    // Top-level function checks
    // ========================================================================

    fn check_top_level_function(&mut self, func: &FunctionDef) {
        // Contract-only attributes on top-level functions
        let contract_only = ["constructor", "view", "payable", "sponsored", "reentrant"];
        for attr in &func.attributes {
            let name = attr
                .content
                .split('(')
                .next()
                .unwrap_or(&attr.content)
                .trim();
            if contract_only.contains(&name) {
                self.error(
                    format!(
                        "#[{}] can only be used on functions inside a contract",
                        name
                    ),
                    attr.span,
                );
            }
            // #[test] and #[should_panic] are allowed on top-level functions
            if !is_known_attribute(&attr.content) && name != "test" && name != "should_panic" {
                self.error(
                    format!("unknown attribute '#[{}]'", attr.content),
                    attr.span,
                );
            }
        }
    }

    // ========================================================================
    // Contract-level checks
    // ========================================================================

    fn check_contract(&mut self, contract: &ContractDef) {
        // Collect all function names for callback validation
        self.contract_functions.clear();
        for item in &contract.items {
            if let ContractItem::Function(f) = item {
                self.contract_functions.push(f.name.name.clone());
            }
        }

        // TPL-603: collect names of storage fields declared as `Map<K, V>`
        // (or any nesting where the outer type is `Map`) so the for-loop
        // diagnostic can fire on `for _ in self.<map_field>`.
        self.storage_maps.clear();
        for item in &contract.items {
            if let ContractItem::Storage(storage) = item {
                for field in &storage.fields {
                    if matches!(field.ty, Type::Map(..)) {
                        self.storage_maps.insert(field.name.name.clone());
                    }
                }
            }
        }

        // Check for exactly one constructor
        let constructors: Vec<&FunctionDef> = contract
            .items
            .iter()
            .filter_map(|item| {
                if let ContractItem::Function(f) = item {
                    if f.is_constructor() {
                        return Some(f);
                    }
                }
                None
            })
            .collect();

        if constructors.len() > 1 {
            for ctor in &constructors[1..] {
                self.error(
                    "contract can only have one #[constructor]".into(),
                    ctor.span,
                );
            }
        }

        // Check for at most one #[receive]
        let receives: Vec<&FunctionDef> = contract
            .items
            .iter()
            .filter_map(|item| {
                if let ContractItem::Function(f) = item {
                    if f.is_receive() {
                        return Some(f);
                    }
                }
                None
            })
            .collect();
        if receives.len() > 1 {
            for recv in &receives[1..] {
                self.error(
                    "contract can only have one #[receive] function".into(),
                    recv.span,
                );
            }
        }

        // Check for at most one #[fallback]
        let fallbacks: Vec<&FunctionDef> = contract
            .items
            .iter()
            .filter_map(|item| {
                if let ContractItem::Function(f) = item {
                    if f.is_fallback() {
                        return Some(f);
                    }
                }
                None
            })
            .collect();
        if fallbacks.len() > 1 {
            for fb in &fallbacks[1..] {
                self.error(
                    "contract can only have one #[fallback] function".into(),
                    fb.span,
                );
            }
        }

        // Build purity map: which functions are impure (modify state)?
        let purity_map = self.build_purity_map(&contract.items);

        // Check each function
        for item in &contract.items {
            if let ContractItem::Function(f) = item {
                self.check_function_attrs(f);
                self.check_view_purity_transitive(f, &purity_map);
                self.check_constructor_rules(f);
                self.check_payable_rules(f);
                self.check_receive_rules(f);
                self.check_fallback_rules(f);
                self.check_cross_call_callbacks(f);
                self.check_map_iteration(&f.body);
            }
        }

        self.contract_functions.clear();
        self.storage_maps.clear();
    }

    // ========================================================================
    // TPL-603 — Map iteration diagnostic
    // ========================================================================

    /// Walk a block looking for `for _ in self.<storage_map_field>`. The
    /// IR has no `StorageMapIter` opcode, so an iterator like that lowers
    /// to a no-op body that runs zero times — silently. Emit a loud
    /// compile error pointing at the `for` line so authors don't write
    /// contract logic that depends on iteration that never happens.
    fn check_map_iteration(&mut self, block: &Block) {
        for stmt in &block.stmts {
            self.check_stmt_map_iteration(stmt);
        }
    }

    fn check_stmt_map_iteration(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::For(f) => {
                if let Some(name) = self.iterator_targets_storage_map(&f.iterator) {
                    self.error(
                        format!(
                            "iteration over `Map` is not supported: storage field `self.{}` is `Map<K, V>`, which has no in-IR iterator. Track keys explicitly via a `Vec<K>` companion field, or rewrite the loop to walk the key set you maintain on writes.",
                            name
                        ),
                        f.span,
                    );
                }
                self.check_map_iteration(&f.body);
            }
            Stmt::While(w) => self.check_map_iteration(&w.body),
            Stmt::Expr(e) => self.check_expr_map_iteration(&e.expr),
            Stmt::Let(l) => self.check_expr_map_iteration(&l.initializer),
            Stmt::Assign(a) => {
                self.check_expr_map_iteration(&a.target);
                self.check_expr_map_iteration(&a.value);
            }
            Stmt::Return(r) => {
                if let Some(v) = &r.value {
                    self.check_expr_map_iteration(v);
                }
            }
            Stmt::Emit(e) => {
                for f in &e.fields {
                    self.check_expr_map_iteration(&f.value);
                }
            }
            _ => {}
        }
    }

    fn check_expr_map_iteration(&mut self, expr: &Expr) {
        match expr {
            Expr::If(_, then_block, else_clause, _) => {
                self.check_map_iteration(then_block);
                if let Some(clause) = else_clause {
                    match clause {
                        ElseClause::ElseBlock(b) => self.check_map_iteration(b),
                        ElseClause::ElseIf(e) => self.check_expr_map_iteration(e),
                    }
                }
            }
            Expr::Match(_, arms, _) => {
                for arm in arms {
                    if let Expr::Block(b) = &arm.body {
                        self.check_map_iteration(b);
                    }
                }
            }
            Expr::Block(block) => self.check_map_iteration(block),
            _ => {}
        }
    }

    /// If the iterator expression is `self.<field>` (or `(self.<field>)`)
    /// and `<field>` is a known storage Map, return its name. Otherwise
    /// return None (the iterator is some other expression — a Vec, a
    /// range, a function-returned iterator, etc., all of which are
    /// supported and not the concern of this diagnostic).
    fn iterator_targets_storage_map(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::FieldAccess(obj, field, _) => {
                if matches!(obj.as_ref(), Expr::SelfExpr(_))
                    && self.storage_maps.contains(&field.name)
                {
                    Some(field.name.clone())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    // ========================================================================
    // Attribute validation
    // ========================================================================

    fn check_function_attrs(&mut self, func: &FunctionDef) {
        let mut has_constructor = false;
        let mut has_view = false;
        let mut _has_sponsored = false; // TODO see note at "sponsored" arm below
        let mut has_reentrant = false;
        let mut has_payable = false;
        let mut has_test = false;

        for attr in &func.attributes {
            // Check for unknown attributes
            if !is_known_attribute(&attr.content) {
                self.error(
                    format!("unknown attribute '#[{}]'", attr.content),
                    attr.span,
                );
                continue;
            }

            let name = attr
                .content
                .split('(')
                .next()
                .unwrap_or(&attr.content)
                .trim();
            match name {
                "constructor" => {
                    if has_constructor {
                        self.error("duplicate #[constructor] attribute".into(), attr.span);
                    }
                    has_constructor = true;
                }
                "view" => {
                    if has_view {
                        self.error("duplicate #[view] attribute".into(), attr.span);
                    }
                    has_view = true;
                }
                "sponsored" => {
                    // TODO(post-slice-5.4): #[sponsored] has no conflict-
                    // detection below (unlike every other attribute here).
                    // Determining which attributes conflict with #[sponsored]
                    // requires a design decision, not a style fix — leaving
                    // the assignment live so `cargo fix` doesn't silently
                    // drop it. Likely candidates to forbid: #[view] (view
                    // functions read state and don't consume gas),
                    // #[constructor] (constructors run once at deploy).
                    _has_sponsored = true;
                }
                "reentrant" => {
                    has_reentrant = true;
                }
                "payable" => {
                    has_payable = true;
                }
                "test" => {
                    has_test = true;
                }
                "should_panic" => {
                    if !has_test {
                        self.error(
                            "#[should_panic] can only be used with #[test]".into(),
                            attr.span,
                        );
                    }
                }
                _ => {}
            }
        }

        // Conflicting attributes
        if has_constructor && has_view {
            self.error(
                "#[constructor] and #[view] cannot be combined".into(),
                func.span,
            );
        }
        if has_constructor && has_test {
            self.error(
                "#[constructor] and #[test] cannot be combined".into(),
                func.span,
            );
        }
        if has_constructor && has_reentrant {
            self.error(
                "#[constructor] and #[reentrant] cannot be combined (constructors run once at deploy)".into(),
                func.span,
            );
        }
        if has_view && has_reentrant {
            self.error(
                "#[view] and #[reentrant] cannot be combined (view functions don't need reentrancy guards)".into(),
                func.span,
            );
        }
        if has_view && has_payable {
            self.error(
                "#[view] and #[payable] cannot be combined (view functions cannot receive value)"
                    .into(),
                func.span,
            );
        }

        // View functions must have a return type (otherwise they're useless)
        if has_view && func.return_type.is_none() {
            self.error(
                "#[view] function must have a return type (view functions read and return data)"
                    .into(),
                func.span,
            );
        }
    }

    // ========================================================================
    // Purity analysis (transitive)
    // ========================================================================

    /// Build a map of function_name → is_impure for all functions in the contract.
    /// Uses fixpoint iteration: first mark direct impurity, then propagate through calls.
    fn build_purity_map(&self, items: &[ContractItem]) -> HashMap<String, bool> {
        let mut impure: HashSet<String> = HashSet::new();
        let mut calls: HashMap<String, Vec<String>> = HashMap::new();

        // Pass 1: find directly impure functions and collect call edges
        for item in items {
            if let ContractItem::Function(f) = item {
                let mut call_targets = Vec::new();
                let directly_impure = self.scan_direct_impurity(&f.body, &mut call_targets);
                if directly_impure {
                    impure.insert(f.name.name.clone());
                }
                calls.insert(f.name.name.clone(), call_targets);
            }
        }

        // Pass 2: propagate impurity through call graph (fixpoint)
        loop {
            let mut changed = false;
            for item in items {
                if let ContractItem::Function(f) = item {
                    if impure.contains(&f.name.name) {
                        continue; // already impure
                    }
                    if let Some(targets) = calls.get(&f.name.name) {
                        for target in targets {
                            if impure.contains(target) {
                                impure.insert(f.name.name.clone());
                                changed = true;
                                break;
                            }
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }

        // Build result map
        let mut map = HashMap::new();
        for item in items {
            if let ContractItem::Function(f) = item {
                map.insert(f.name.name.clone(), impure.contains(&f.name.name));
            }
        }
        map
    }

    /// Check if a function body directly modifies state.
    /// Also collects self.method() call targets for transitive analysis.
    fn scan_direct_impurity(&self, block: &Block, call_targets: &mut Vec<String>) -> bool {
        let mut impure = false;
        for stmt in &block.stmts {
            if self.stmt_is_impure(stmt, call_targets) {
                impure = true;
            }
        }
        impure
    }

    fn stmt_is_impure(&self, stmt: &Stmt, call_targets: &mut Vec<String>) -> bool {
        match stmt {
            Stmt::Assign(a) => {
                self.collect_calls_in_expr(&a.value, call_targets);
                self.is_storage_write(&a.target)
            }
            Stmt::Emit(_) => true,
            Stmt::For(f) => {
                self.collect_calls_in_expr(&f.iterator, call_targets);
                self.scan_direct_impurity(&f.body, call_targets)
            }
            Stmt::While(w) => {
                self.collect_calls_in_expr(&w.condition, call_targets);
                self.scan_direct_impurity(&w.body, call_targets)
            }
            Stmt::Expr(e) => {
                self.collect_calls_in_expr(&e.expr, call_targets);
                self.expr_is_impure(&e.expr, call_targets)
            }
            Stmt::Let(l) => {
                self.collect_calls_in_expr(&l.initializer, call_targets);
                false
            }
            Stmt::Return(r) => {
                if let Some(ref val) = r.value {
                    self.collect_calls_in_expr(val, call_targets);
                }
                false
            }
            _ => false,
        }
    }

    /// Check if a method call on a storage field is mutating (push, pop, etc.).
    fn is_storage_mutating_call(&self, expr: &Expr) -> bool {
        if let Expr::Call(callee, _, _, _) = expr {
            if let Expr::FieldAccess(obj, method, _) = callee.as_ref() {
                let is_mutating_method = matches!(
                    method.name.as_str(),
                    "push" | "pop" | "insert" | "remove" | "clear" | "append"
                );
                if is_mutating_method && self.is_storage_access(obj) {
                    return true;
                }
            }
        }
        false
    }

    fn expr_is_impure(&self, expr: &Expr, call_targets: &mut Vec<String>) -> bool {
        match expr {
            Expr::MacroCall(name, _, _) if name.name == "cross_call" => true,
            Expr::MacroCall(name, _, _) if name.name == "raw_call" => true,
            _ if self.is_storage_mutating_call(expr) => true,
            Expr::If(_, then_block, else_clause, _) => {
                let mut impure = self.scan_direct_impurity(then_block, call_targets);
                if let Some(clause) = else_clause {
                    match clause {
                        ElseClause::ElseBlock(block) => {
                            impure |= self.scan_direct_impurity(block, call_targets);
                        }
                        ElseClause::ElseIf(else_if) => {
                            impure |= self.expr_is_impure(else_if, call_targets);
                        }
                    }
                }
                impure
            }
            Expr::Match(_, arms, _) => {
                let mut impure = false;
                for arm in arms {
                    if let Expr::Block(block) = &arm.body {
                        impure |= self.scan_direct_impurity(block, call_targets);
                    }
                }
                impure
            }
            Expr::Block(block) => self.scan_direct_impurity(block, call_targets),
            _ => false,
        }
    }

    /// Collect self.method() call targets from an expression.
    #[allow(clippy::only_used_in_recursion)] // `&self` kept for call-site symmetry with sibling methods
    fn collect_calls_in_expr(&self, expr: &Expr, targets: &mut Vec<String>) {
        match expr {
            Expr::Call(callee, args, _, _) => {
                // self.method(...) → record method name
                if let Expr::FieldAccess(obj, method, _) = callee.as_ref() {
                    if matches!(obj.as_ref(), Expr::SelfExpr(_)) {
                        targets.push(method.name.clone());
                    }
                }
                for arg in args {
                    self.collect_calls_in_expr(arg, targets);
                }
            }
            Expr::Binary(lhs, _, rhs, _) => {
                self.collect_calls_in_expr(lhs, targets);
                self.collect_calls_in_expr(rhs, targets);
            }
            Expr::Unary(_, operand, _) => {
                self.collect_calls_in_expr(operand, targets);
            }
            Expr::FieldAccess(obj, _, _) => {
                self.collect_calls_in_expr(obj, targets);
            }
            Expr::Index(obj, idx, _) => {
                self.collect_calls_in_expr(obj, targets);
                self.collect_calls_in_expr(idx, targets);
            }
            _ => {}
        }
    }

    /// Check #[view] purity using the pre-computed purity map.
    fn check_view_purity_transitive(
        &mut self,
        func: &FunctionDef,
        purity_map: &HashMap<String, bool>,
    ) {
        if !func.is_view() {
            return;
        }

        // Direct scan for specific error messages (storage write, emit, cross_call)
        self.check_block_purity_direct(&func.body, &func.name.name);

        // Transitive check: does this view call any impure function?
        let mut call_targets = Vec::new();
        self.scan_direct_impurity(&func.body, &mut call_targets);
        for target in &call_targets {
            if let Some(true) = purity_map.get(target.as_str()) {
                self.error(
                    format!(
                        "#[view] function '{}' calls '{}' which modifies state",
                        func.name.name, target
                    ),
                    func.span,
                );
            }
        }
    }

    /// Direct purity check for specific error messages (storage write, emit, cross_call).
    fn check_block_purity_direct(&mut self, block: &Block, func_name: &str) {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign(a) => {
                    if self.is_storage_write(&a.target) {
                        self.error(
                            format!("#[view] function '{}' cannot modify storage", func_name),
                            a.span,
                        );
                    }
                }
                Stmt::Emit(e) => {
                    self.error(
                        format!("#[view] function '{}' cannot emit events", func_name),
                        e.span,
                    );
                }
                Stmt::For(f) => self.check_block_purity_direct(&f.body, func_name),
                Stmt::While(w) => self.check_block_purity_direct(&w.body, func_name),
                Stmt::Expr(e) => {
                    if let Expr::MacroCall(name, _, _) = &e.expr {
                        if name.name == "cross_call" {
                            self.error(
                                format!("#[view] function '{}' cannot make cross_call!", func_name),
                                e.span,
                            );
                        }
                        if name.name == "raw_call" {
                            self.error(
                                format!("#[view] function '{}' cannot make raw_call!", func_name),
                                e.span,
                            );
                        }
                    }
                    if self.is_storage_mutating_call(&e.expr) {
                        self.error(
                            format!(
                                "#[view] function '{}' cannot mutate storage collections",
                                func_name
                            ),
                            e.span,
                        );
                    }
                    self.check_expr_purity_direct(&e.expr, func_name);
                }
                _ => {}
            }
        }
    }

    fn check_expr_purity_direct(&mut self, expr: &Expr, func_name: &str) {
        match expr {
            Expr::If(_, then_block, else_clause, _) => {
                self.check_block_purity_direct(then_block, func_name);
                if let Some(clause) = else_clause {
                    match clause {
                        ElseClause::ElseBlock(block) => {
                            self.check_block_purity_direct(block, func_name)
                        }
                        ElseClause::ElseIf(else_if) => {
                            self.check_expr_purity_direct(else_if, func_name)
                        }
                    }
                }
            }
            Expr::Match(_, arms, _) => {
                for arm in arms {
                    if let Expr::Block(block) = &arm.body {
                        self.check_block_purity_direct(block, func_name);
                    }
                }
            }
            Expr::Block(block) => self.check_block_purity_direct(block, func_name),
            _ => {}
        }
    }

    /// Check if an expression is a storage write (self.field or self.map[key]).
    fn is_storage_write(&self, expr: &Expr) -> bool {
        match expr {
            Expr::FieldAccess(obj, _, _) => {
                matches!(obj.as_ref(), Expr::SelfExpr(_))
            }
            Expr::Index(obj, _, _) => self.is_storage_access(obj),
            _ => false,
        }
    }

    #[allow(clippy::only_used_in_recursion)] // `&self` kept for call-site symmetry with sibling methods
    fn is_storage_access(&self, expr: &Expr) -> bool {
        match expr {
            Expr::FieldAccess(obj, _, _) => {
                matches!(obj.as_ref(), Expr::SelfExpr(_)) || self.is_storage_access(obj)
            }
            Expr::Index(obj, _, _) => self.is_storage_access(obj),
            _ => false,
        }
    }

    // ========================================================================
    // #[constructor] rules
    // ========================================================================

    // ========================================================================
    // #[payable] — msg.value access enforcement
    // ========================================================================

    fn check_payable_rules(&mut self, func: &FunctionDef) {
        // Skip payable or constructor functions — they can access msg.value
        if func.is_payable() || func.is_constructor() {
            return;
        }

        // Scan for msg.value access
        if self.block_accesses_msg_value(&func.body) {
            self.error(
                format!(
                    "function '{}' accesses msg.value but is not marked #[payable]",
                    func.name.name
                ),
                func.span,
            );
        }
    }

    fn block_accesses_msg_value(&self, block: &Block) -> bool {
        for stmt in &block.stmts {
            if self.stmt_accesses_msg_value(stmt) {
                return true;
            }
        }
        false
    }

    fn stmt_accesses_msg_value(&self, stmt: &Stmt) -> bool {
        match stmt {
            Stmt::Let(l) => self.expr_accesses_msg_value(&l.initializer),
            Stmt::Assign(a) => {
                self.expr_accesses_msg_value(&a.target) || self.expr_accesses_msg_value(&a.value)
            }
            Stmt::Return(r) => r
                .value
                .as_ref()
                .is_some_and(|v| self.expr_accesses_msg_value(v)),
            Stmt::Emit(e) => e
                .fields
                .iter()
                .any(|f| self.expr_accesses_msg_value(&f.value)),
            Stmt::For(f) => {
                self.expr_accesses_msg_value(&f.iterator) || self.block_accesses_msg_value(&f.body)
            }
            Stmt::While(w) => {
                self.expr_accesses_msg_value(&w.condition) || self.block_accesses_msg_value(&w.body)
            }
            Stmt::Expr(e) => self.expr_accesses_msg_value(&e.expr),
            _ => false,
        }
    }

    fn expr_accesses_msg_value(&self, expr: &Expr) -> bool {
        match expr {
            // msg.value → this is what we're looking for
            Expr::FieldAccess(obj, field, _) => {
                if let Expr::Ident(ident) = obj.as_ref() {
                    if ident.name == "msg" && field.name == "value" {
                        return true;
                    }
                }
                self.expr_accesses_msg_value(obj)
            }
            // Recurse into subexpressions
            Expr::Binary(lhs, _, rhs, _) => {
                self.expr_accesses_msg_value(lhs) || self.expr_accesses_msg_value(rhs)
            }
            Expr::Unary(_, operand, _) => self.expr_accesses_msg_value(operand),
            Expr::Index(obj, idx, _) => {
                self.expr_accesses_msg_value(obj) || self.expr_accesses_msg_value(idx)
            }
            Expr::Call(callee, args, _, _) => {
                self.expr_accesses_msg_value(callee)
                    || args.iter().any(|a| self.expr_accesses_msg_value(a))
            }
            Expr::If(cond, then_block, else_clause, _) => {
                self.expr_accesses_msg_value(cond)
                    || self.block_accesses_msg_value(then_block)
                    || else_clause.as_ref().is_some_and(|c| match c {
                        ElseClause::ElseBlock(b) => self.block_accesses_msg_value(b),
                        ElseClause::ElseIf(e) => self.expr_accesses_msg_value(e),
                    })
            }
            Expr::Match(scrut, arms, _) => {
                self.expr_accesses_msg_value(scrut)
                    || arms.iter().any(|a| self.expr_accesses_msg_value(&a.body))
            }
            Expr::Block(block) => self.block_accesses_msg_value(block),
            Expr::MacroCall(_, args, _) => args.iter().any(|a| match a {
                MacroArg::Positional(e) => self.expr_accesses_msg_value(e),
                MacroArg::Named(_, e) => self.expr_accesses_msg_value(e),
            }),
            Expr::StructInit(_, fields, _) => fields
                .iter()
                .any(|f| self.expr_accesses_msg_value(&f.value)),
            Expr::Cast(inner, _, _) | Expr::Try(inner, _) => self.expr_accesses_msg_value(inner),
            Expr::Tuple(elems, _) | Expr::ArrayLiteral(elems, _) => {
                elems.iter().any(|e| self.expr_accesses_msg_value(e))
            }
            Expr::ArrayRepeat(val, _, _) => self.expr_accesses_msg_value(val),
            _ => false,
        }
    }

    // ========================================================================
    // #[constructor] rules
    // ========================================================================

    fn check_receive_rules(&mut self, func: &FunctionDef) {
        if !func.is_receive() {
            return;
        }
        // Cannot combine with #[constructor], #[view], #[test], or #[fallback]
        if func.is_constructor() {
            self.error(
                "#[receive] cannot be combined with #[constructor]".into(),
                func.span,
            );
        }
        if func.is_view() {
            self.error(
                "#[receive] cannot be combined with #[view]".into(),
                func.span,
            );
        }
        if func.is_fallback() {
            self.error(
                "#[receive] cannot be combined with #[fallback]".into(),
                func.span,
            );
        }
        if func.is_test() {
            self.error(
                "#[receive] cannot be combined with #[test]".into(),
                func.span,
            );
        }
        // #[receive] must also be #[payable]
        if !func.is_payable() {
            self.error(
                "#[receive] must also have #[payable] (it handles incoming value)".into(),
                func.span,
            );
        }
        // Must be pub (externally callable)
        if !func.is_pub {
            self.error("#[receive] must be a pub function".into(), func.span);
        }
        // No parameters
        if !func.params.is_empty() {
            self.error("#[receive] cannot have parameters".into(), func.span);
        }
        // No return type
        if func.return_type.is_some() {
            self.error("#[receive] cannot have a return type".into(), func.span);
        }
    }

    fn check_fallback_rules(&mut self, func: &FunctionDef) {
        if !func.is_fallback() {
            return;
        }
        // Cannot combine with #[constructor], #[view], #[test], or #[receive]
        if func.is_constructor() {
            self.error(
                "#[fallback] cannot be combined with #[constructor]".into(),
                func.span,
            );
        }
        if func.is_view() {
            self.error(
                "#[fallback] cannot be combined with #[view]".into(),
                func.span,
            );
        }
        if func.is_receive() {
            self.error(
                "#[fallback] cannot be combined with #[receive]".into(),
                func.span,
            );
        }
        if func.is_test() {
            self.error(
                "#[fallback] cannot be combined with #[test]".into(),
                func.span,
            );
        }
        // Must be pub (externally callable)
        if !func.is_pub {
            self.error("#[fallback] must be a pub function".into(), func.span);
        }
        // No parameters
        if !func.params.is_empty() {
            self.error("#[fallback] cannot have parameters".into(), func.span);
        }
        // No return type
        if func.return_type.is_some() {
            self.error("#[fallback] cannot have a return type".into(), func.span);
        }
    }

    fn check_constructor_rules(&mut self, func: &FunctionDef) {
        if !func.is_constructor() {
            return;
        }

        // Constructor must be pub
        if !func.is_pub {
            self.error("#[constructor] must be a pub function".into(), func.span);
        }

        // Constructor must not have a return type
        if func.return_type.is_some() {
            self.error("#[constructor] cannot have a return type".into(), func.span);
        }
    }

    // ========================================================================
    // cross_call! callback validation
    // ========================================================================

    fn check_cross_call_callbacks(&mut self, func: &FunctionDef) {
        self.scan_cross_calls(&func.body);
    }

    fn scan_cross_calls(&mut self, block: &Block) {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Expr(e) => self.scan_expr_cross_calls(&e.expr, e.span),
                Stmt::For(f) => self.scan_cross_calls(&f.body),
                Stmt::While(w) => self.scan_cross_calls(&w.body),
                Stmt::Let(l) => self.scan_expr_cross_calls(&l.initializer, l.span),
                _ => {}
            }
        }
    }

    fn scan_expr_cross_calls(&mut self, expr: &Expr, _span: Span) {
        match expr {
            Expr::MacroCall(name, args, macro_span) => {
                if name.name == "cross_call" {
                    // Look for callback: "fn_name" argument
                    for arg in args {
                        if let MacroArg::Named(key, value) = arg {
                            if key.name == "callback" {
                                if let Expr::Literal(Literal::String(callback_name), _) = value {
                                    if !self.contract_functions.contains(callback_name) {
                                        self.error(
                                            format!(
                                                "cross_call! callback '{}' not found in contract",
                                                callback_name
                                            ),
                                            *macro_span,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Expr::If(_, then_block, else_clause, _) => {
                self.scan_cross_calls(then_block);
                if let Some(ElseClause::ElseBlock(block)) = else_clause {
                    self.scan_cross_calls(block);
                }
            }
            Expr::Block(block) => self.scan_cross_calls(block),
            _ => {}
        }
    }
}

/// Result of safety checking.
pub struct SafetyCheckResult {
    pub errors: Vec<SafetyError>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;
    use crate::parser::Parser;

    fn check(src: &str) -> Vec<SafetyError> {
        let (tokens, lex_errors) = Lexer::new(src).tokenize();
        assert!(lex_errors.is_empty(), "lex errors: {:?}", lex_errors);
        let (file, parse_errors) = Parser::new(tokens).parse();
        assert!(parse_errors.is_empty(), "parse errors: {:?}", parse_errors);
        SafetyChecker::new().check(&file).errors
    }

    fn check_ok(src: &str) {
        let errors = check(src);
        assert!(errors.is_empty(), "safety errors: {:?}", errors);
    }

    fn check_err(src: &str) -> Vec<SafetyError> {
        let errors = check(src);
        assert!(!errors.is_empty(), "expected safety errors but got none");
        errors
    }

    // ========== #[constructor] ==========

    #[test]
    fn single_constructor_ok() {
        check_ok(
            r#"
            contract T {
                storage { owner: Address, }
                #[constructor]
                pub fn init() {
                    self.owner = msg.sender;
                }
            }
        "#,
        );
    }

    #[test]
    fn error_duplicate_constructor() {
        let errors = check_err(
            r#"
            contract T {
                #[constructor]
                pub fn init() {}
                #[constructor]
                pub fn init2() {}
            }
        "#,
        );
        assert!(errors[0].message.contains("only have one #[constructor]"));
    }

    #[test]
    fn error_constructor_not_pub() {
        let errors = check_err(
            r#"
            contract T {
                #[constructor]
                fn init() {}
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("#[constructor] must be a pub function"));
    }

    #[test]
    fn error_constructor_with_return_type() {
        let errors = check_err(
            r#"
            contract T {
                #[constructor]
                pub fn init() -> u256 {
                    return 0;
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("#[constructor] cannot have a return type"));
    }

    // ========== #[view] purity ==========

    #[test]
    fn view_read_only_ok() {
        check_ok(
            r#"
            contract T {
                storage { balance: u256, }
                #[view]
                pub fn get_balance() -> u256 {
                    return self.balance;
                }
            }
        "#,
        );
    }

    #[test]
    fn error_view_writes_storage() {
        let errors = check_err(
            r#"
            contract T {
                storage { balance: u256, }
                #[view]
                pub fn bad() -> u64 {
                    self.balance = 100;
                    return 0;
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("cannot modify storage"));
    }

    #[test]
    fn error_view_emits_event() {
        let errors = check_err(
            r#"
            contract T {
                event Transfer { amount: u256, }
                #[view]
                pub fn bad() -> u64 {
                    emit Transfer { amount: 100 };
                    return 0;
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("cannot emit events"));
    }

    #[test]
    fn error_view_cross_call() {
        let errors = check_err(
            r#"
            contract T {
                #[view]
                pub fn bad() -> u64 {
                    cross_call!(target: "oracle", method: "get_price", args: (1,));
                    return 0;
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("cannot make cross_call!"));
    }

    #[test]
    fn error_view_writes_map() {
        let errors = check_err(
            r#"
            contract T {
                storage { balances: Map<Address, u256>, }
                #[view]
                pub fn bad() -> u64 {
                    self.balances[msg.sender] = 100;
                    return 0;
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("cannot modify storage"));
    }

    #[test]
    fn error_view_no_return_type() {
        let errors = check_err(
            r#"
            contract T {
                storage { x: u64, }
                #[view]
                pub fn bad() {
                    let a = self.x;
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("must have a return type"));
    }

    // ========== Attribute conflicts ==========

    #[test]
    fn error_constructor_and_view() {
        let errors = check_err(
            r#"
            contract T {
                #[constructor]
                #[view]
                pub fn init() {}
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("#[constructor] and #[view] cannot be combined"));
    }

    #[test]
    fn error_view_and_reentrant() {
        let errors = check_err(
            r#"
            contract T {
                #[view]
                #[reentrant]
                pub fn f() {}
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("#[view] and #[reentrant] cannot be combined"));
    }

    #[test]
    fn error_should_panic_without_test() {
        let errors = check_err(
            r#"
            contract T {
                #[should_panic]
                pub fn f() {}
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("#[should_panic] can only be used with #[test]"));
    }

    // ========== Unknown attributes ==========

    #[test]
    fn error_unknown_attribute() {
        let errors = check_err(
            r#"
            contract T {
                #[banana]
                pub fn f() {}
            }
        "#,
        );
        assert!(errors[0].message.contains("unknown attribute '#[banana]'"));
    }

    #[test]
    fn known_attributes_ok() {
        check_ok(
            r#"
            contract T {
                storage { x: u256, }
                #[constructor]
                pub fn init() {}
                #[view]
                pub fn get() -> u256 { return self.x; }
                #[sponsored]
                pub fn transfer() {}
                #[reentrant]
                pub fn withdraw() {}
            }
        "#,
        );
    }

    // ========== cross_call! callback ==========

    #[test]
    fn cross_call_valid_callback() {
        check_ok(
            r#"
            contract T {
                pub fn request() {
                    cross_call!(target: "oracle", method: "get_price", args: (1,), callback: "on_price");
                }
                pub fn on_price() {}
            }
        "#,
        );
    }

    #[test]
    fn error_cross_call_missing_callback() {
        let errors = check_err(
            r#"
            contract T {
                pub fn request() {
                    cross_call!(target: "oracle", method: "get_price", args: (1,), callback: "nonexistent");
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("callback 'nonexistent' not found"));
    }

    #[test]
    fn cross_call_no_callback_ok() {
        // Fire-and-forget cross_call without callback is fine
        check_ok(
            r#"
            contract T {
                pub fn notify() {
                    cross_call!(target: "logger", method: "log", args: (1,));
                }
            }
        "#,
        );
    }

    // ========== #[test] and #[should_panic] ==========

    #[test]
    fn test_attribute_ok() {
        check_ok(
            r#"
            contract T {
                #[test]
                fn test_something() {}
                #[test]
                #[should_panic]
                fn test_panic() {}
            }
        "#,
        );
    }

    // ========== Transitive purity ==========

    #[test]
    fn error_view_calls_impure_function() {
        let errors = check_err(
            r#"
            contract T {
                storage { balance: u256, }
                fn modify_state() {
                    self.balance = 100;
                }
                #[view]
                pub fn bad() -> u256 {
                    self.modify_state();
                    return self.balance;
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("calls 'modify_state' which modifies state"));
    }

    #[test]
    fn error_view_calls_chain_impure() {
        // view → helper → impure (transitive chain)
        let errors = check_err(
            r#"
            contract T {
                storage { x: u256, }
                fn set_x() { self.x = 1; }
                fn helper() { self.set_x(); }
                #[view]
                pub fn bad() -> u256 {
                    self.helper();
                    return self.x;
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("calls 'helper' which modifies state"));
    }

    #[test]
    fn error_view_push_on_storage() {
        let errors = check_err(
            r#"
            contract T {
                storage { items: Vec<u256>, }
                #[view]
                pub fn bad() -> u64 {
                    self.items.push(42);
                    return 0;
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("cannot mutate storage collections"));
    }

    #[test]
    fn error_view_raw_call() {
        let errors = check_err(
            r#"
            contract T {
                #[view]
                pub fn bad() -> u64 {
                    raw_call!(msg.sender, 0);
                    return 0;
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("cannot make raw_call!"));
    }

    #[test]
    fn view_calls_pure_function_ok() {
        check_ok(
            r#"
            contract T {
                storage { balance: u256, }
                fn compute(x: u256) -> u256 {
                    return x + 1;
                }
                #[view]
                pub fn get() -> u256 {
                    return self.compute(self.balance);
                }
            }
        "#,
        );
    }

    // ========== msg.value payable enforcement ==========

    #[test]
    fn check_payable_function_accesses_msg_value() {
        check_ok(
            r#"
            contract T {
                storage { deposits: Map<Address, u256>, }
                #[payable]
                pub fn deposit() {
                    self.deposits[msg.sender] = self.deposits[msg.sender] + msg.value;
                }
            }
        "#,
        );
    }

    #[test]
    fn error_non_payable_accesses_msg_value() {
        let errors = check_err(
            r#"
            contract T {
                pub fn bad() {
                    let amount = msg.value;
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("not marked #[payable]"));
    }

    #[test]
    fn check_constructor_accesses_msg_value() {
        // Constructors can access msg.value (initial funding)
        check_ok(
            r#"
            contract T {
                storage { initial_funding: u256, }
                #[constructor]
                pub fn init() {
                    self.initial_funding = msg.value;
                }
            }
        "#,
        );
    }

    #[test]
    fn error_non_payable_nested_msg_value() {
        // msg.value buried in a nested expression
        let errors = check_err(
            r#"
            contract T {
                storage { x: u256, }
                pub fn bad() {
                    self.x = msg.value + 100;
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("not marked #[payable]"));
    }

    #[test]
    fn error_non_payable_msg_value_in_require() {
        let errors = check_err(
            r#"
            contract T {
                error NoValue {}
                pub fn bad() {
                    require!(msg.value > 0, NoValue {});
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("not marked #[payable]"));
    }

    #[test]
    fn check_msg_sender_without_payable() {
        // msg.sender is fine without #[payable] — only msg.value is restricted
        check_ok(
            r#"
            contract T {
                storage { owner: Address, }
                pub fn f() {
                    self.owner = msg.sender;
                }
            }
        "#,
        );
    }

    // ========== Top-level function attribute restrictions ==========

    #[test]
    fn error_constructor_outside_contract() {
        let errors = check_err(
            r#"
            #[constructor]
            pub fn init() {}
        "#,
        );
        assert!(errors[0]
            .message
            .contains("can only be used on functions inside a contract"));
    }

    #[test]
    fn error_view_outside_contract() {
        let errors = check_err(
            r#"
            #[view]
            pub fn get() -> u256 { return 0; }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("can only be used on functions inside a contract"));
    }

    #[test]
    fn error_sponsored_outside_contract() {
        let errors = check_err(
            r#"
            #[sponsored]
            pub fn transfer() {}
        "#,
        );
        assert!(errors[0]
            .message
            .contains("can only be used on functions inside a contract"));
    }

    #[test]
    fn test_attribute_on_top_level_ok() {
        // #[test] is allowed on top-level functions (module test functions)
        check_ok(
            r#"
            #[test]
            fn test_something() {}
        "#,
        );
    }

    #[test]
    fn error_constructor_and_test() {
        let errors = check_err(
            r#"
            contract T {
                #[constructor]
                #[test]
                pub fn init() {}
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("#[constructor] and #[test] cannot be combined"));
    }

    // ========== TPL-603: Map iteration diagnostic ==========

    #[test]
    fn error_for_iterates_storage_map() {
        let errors = check_err(
            r#"
            contract T {
                storage { balances: Map<Address, u256>, count: u64, }
                pub fn walk() {
                    for entry in self.balances {
                        self.count = self.count + 1u64;
                    }
                }
            }
        "#,
        );
        assert!(errors
            .iter()
            .any(|e| e.message.contains("iteration over `Map` is not supported")
                && e.message.contains("self.balances")));
    }

    #[test]
    fn for_iterates_storage_vec_ok() {
        // Vec iteration is supported and must NOT fire the new diagnostic.
        check_ok(
            r#"
            contract T {
                storage { items: Vec<u64>, }
                pub fn sum() -> u64 {
                    let mut total: u64 = 0u64;
                    for x in self.items {
                        total = total + x;
                    }
                    return total;
                }
            }
        "#,
        );
    }

    #[test]
    fn error_nested_for_in_storage_map() {
        // The diagnostic must reach `for` loops nested inside `if`/`while`,
        // not just top-level statements.
        let errors = check_err(
            r#"
            contract T {
                storage { balances: Map<Address, u256>, count: u64, }
                pub fn walk(flag: bool) {
                    if flag {
                        for entry in self.balances {
                            self.count = self.count + 1u64;
                        }
                    }
                }
            }
        "#,
        );
        assert!(errors
            .iter()
            .any(|e| e.message.contains("iteration over `Map` is not supported")));
    }
}
