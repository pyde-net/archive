//! Name resolution: validates that all identifiers in the AST refer to
//! valid definitions. Builds symbol tables, resolves references, and
//! reports errors for undefined names, duplicates, and scope violations.
//!
//! Runs after parsing, before type checking.

use std::collections::HashMap;

use crate::ast::*;
use crate::token::Span;

// ============================================================================
// Errors
// ============================================================================

#[derive(Clone, Debug)]
pub struct ResolveError {
    pub message: String,
    pub span: Span,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.span.line, self.span.col, self.message)
    }
}

// ============================================================================
// Result
// ============================================================================

/// The output of name resolution — passed to the type checker.
pub struct ResolveResult {
    /// All symbols discovered during resolution.
    pub symbols: SymbolTable,
    /// Any errors found during resolution.
    pub errors: Vec<ResolveError>,
}

/// A flat table of all symbols in the program.
/// Used by the type checker and later passes.
#[derive(Clone, Debug)]
pub struct SymbolTable {
    pub symbols: HashMap<String, Symbol>,
}

impl SymbolTable {
    pub fn get(&self, name: &str) -> Option<&Symbol> {
        self.symbols.get(name)
    }

    pub fn has(&self, name: &str) -> bool {
        self.symbols.contains_key(name)
    }
}

// ============================================================================
// Symbol kinds
// ============================================================================

#[derive(Clone, Debug, PartialEq)]
pub enum SymbolKind {
    StorageField,
    Function { is_pub: bool },
    Event,
    Error,
    Struct,
    Enum,
    EnumVariant { enum_name: String },
    Const,
    TypeAlias,
    Interface,
    InterfaceFn { interface_name: String },
    Contract,
    LocalVar { is_mutable: bool },
    FnParam,
    ForVar,
    Module,
}

#[derive(Clone, Debug)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub span: Span,
}

// ============================================================================
// Scope
// ============================================================================

#[derive(Clone, Debug)]
struct Scope {
    symbols: HashMap<String, Symbol>,
    kind: ScopeKind,
}

#[derive(Clone, Debug, PartialEq)]
enum ScopeKind {
    Global,
    Contract,
    Function,
    Block,
    ForLoop,
}

impl Scope {
    fn new(kind: ScopeKind) -> Self {
        Self {
            symbols: HashMap::new(),
            kind,
        }
    }
}

// ============================================================================
// Resolver
// ============================================================================

pub struct Resolver {
    scopes: Vec<Scope>,
    errors: Vec<ResolveError>,
    /// Track which contract we're inside (for self.field resolution).
    in_contract: bool,
    /// Track loop nesting depth (for break/continue validation).
    loop_depth: u32,
    /// Known built-in types.
    builtin_types: Vec<&'static str>,
    /// Known built-in functions.
    builtin_fns: Vec<&'static str>,
    /// Known built-in globals (msg, block, tx).
    builtin_globals: Vec<&'static str>,
}

impl Resolver {
    pub fn new() -> Self {
        Self {
            scopes: vec![Scope::new(ScopeKind::Global)],
            errors: Vec::new(),
            in_contract: false,
            loop_depth: 0,
            builtin_types: vec![
                "u8", "u16", "u32", "u64", "u128", "u256",
                "i8", "i16", "i32", "i64", "i128", "i256",
                "bool", "Address", "String", "bytes",
                "Vec", "Map",
            ],
            builtin_fns: vec!["hash", "address", "gas_remaining", "bytes", "sig_verify", "sig_recover"],
            builtin_globals: vec!["msg", "block", "tx"],
        }
    }

    /// Resolve all names in a source file.
    /// Returns the resolved symbol table and any errors.
    pub fn resolve(mut self, file: &SourceFile) -> ResolveResult {
        // First pass: collect all top-level definitions
        for item in &file.items {
            self.declare_item(item);
        }

        // Second pass: resolve all references
        for item in &file.items {
            self.resolve_item(item);
        }

        // Flatten all scopes into a single symbol table for downstream passes
        let mut all_symbols = HashMap::new();
        for scope in &self.scopes {
            for (name, sym) in &scope.symbols {
                all_symbols.insert(name.clone(), sym.clone());
            }
        }

        ResolveResult {
            symbols: SymbolTable { symbols: all_symbols },
            errors: self.errors,
        }
    }

    // ========================================================================
    // Scope management
    // ========================================================================

    fn push_scope(&mut self, kind: ScopeKind) {
        self.scopes.push(Scope::new(kind));
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    fn declare(&mut self, name: &str, kind: SymbolKind, span: Span) {
        // Reject shadowing of all builtins: types, globals, and functions.
        if matches!(kind, SymbolKind::LocalVar { .. } | SymbolKind::FnParam | SymbolKind::ForVar) {
            if self.builtin_types.contains(&name) {
                self.errors.push(ResolveError {
                    message: format!("cannot shadow builtin type '{}'", name),
                    span,
                });
                return;
            }
            if self.builtin_globals.contains(&name) {
                self.errors.push(ResolveError {
                    message: format!("cannot shadow builtin '{}'", name),
                    span,
                });
                return;
            }
            if self.builtin_fns.contains(&name) {
                self.errors.push(ResolveError {
                    message: format!("cannot shadow builtin function '{}'", name),
                    span,
                });
                return;
            }
        }

        let scope = self.scopes.last_mut().expect("resolver has no scope");

        if let Some(existing) = scope.symbols.get(name) {
            // Events, errors, functions, and storage fields are separate namespaces.
            // e.g., `event TransferLocked` and `error TransferLocked` can coexist.
            // e.g., `storage { is_killed: bool }` and `fn is_killed()` can coexist.
            let ns = |k: &SymbolKind| -> u8 {
                match k {
                    SymbolKind::Event => 0,
                    SymbolKind::Error => 1,
                    SymbolKind::Function { .. } => 2,
                    SymbolKind::StorageField => 3,
                    _ => 255, // everything else shares a namespace
                }
            };
            let different_namespace = ns(&existing.kind) != ns(&kind)
                && ns(&existing.kind) != 255 && ns(&kind) != 255;

            if !different_namespace {
                self.errors.push(ResolveError {
                    message: format!(
                        "'{}' is already defined in this scope (first defined at {}:{})",
                        name, existing.span.line, existing.span.col
                    ),
                    span,
                });
                return;
            }
        }

        scope.symbols.insert(name.to_string(), Symbol {
            name: name.to_string(),
            kind,
            span,
        });
    }

    fn lookup(&self, name: &str) -> Option<&Symbol> {
        // Walk scopes from innermost to outermost
        for scope in self.scopes.iter().rev() {
            if let Some(sym) = scope.symbols.get(name) {
                return Some(sym);
            }
        }
        None
    }

    fn is_type_defined(&self, name: &str) -> bool {
        if self.builtin_types.contains(&name) {
            return true;
        }
        for scope in self.scopes.iter().rev() {
            if let Some(sym) = scope.symbols.get(name) {
                match sym.kind {
                    SymbolKind::Struct | SymbolKind::Enum | SymbolKind::TypeAlias
                    | SymbolKind::Interface | SymbolKind::Contract => return true,
                    _ => {}
                }
            }
        }
        false
    }

    fn error(&mut self, message: String, span: Span) {
        self.errors.push(ResolveError { message, span });
    }

    // ========================================================================
    // Declaration pass (collect definitions)
    // ========================================================================

    fn declare_item(&mut self, item: &Item) {
        match item {
            Item::Contract(c) => {
                self.declare(&c.name.name, SymbolKind::Contract, c.name.span);
            }
            Item::Struct(s) => {
                self.declare(&s.name.name, SymbolKind::Struct, s.name.span);
            }
            Item::Enum(e) => {
                self.declare(&e.name.name, SymbolKind::Enum, e.name.span);
                for v in &e.variants {
                    self.declare(
                        &format!("{}::{}", e.name.name, v.name),
                        SymbolKind::EnumVariant { enum_name: e.name.name.clone() },
                        v.span,
                    );
                }
            }
            Item::Const(c) => {
                self.declare(&c.name.name, SymbolKind::Const, c.name.span);
            }
            Item::TypeAlias(t) => {
                self.declare(&t.name.name, SymbolKind::TypeAlias, t.name.span);
            }
            Item::Interface(i) => {
                self.declare(&i.name.name, SymbolKind::Interface, i.name.span);
                for f in &i.functions {
                    self.declare(
                        &format!("{}::{}", i.name.name, f.name.name),
                        SymbolKind::InterfaceFn { interface_name: i.name.name.clone() },
                        f.name.span,
                    );
                }
            }
            Item::Error(e) => {
                self.declare(&e.name.name, SymbolKind::Error, e.name.span);
            }
            Item::Function(f) => {
                self.declare(
                    &f.name.name,
                    SymbolKind::Function { is_pub: f.is_pub },
                    f.name.span,
                );
            }
            Item::Module(m) => {
                self.declare(&m.name.name, SymbolKind::Module, m.name.span);
            }
            Item::Use(_) => {
                // Imports are resolved separately
            }
        }
    }

    fn declare_contract_items(&mut self, items: &[ContractItem]) {
        for item in items {
            match item {
                ContractItem::Storage(s) => {
                    for field in &s.fields {
                        self.declare(
                            &field.name.name,
                            SymbolKind::StorageField,
                            field.name.span,
                        );
                    }
                }
                ContractItem::Event(e) => {
                    self.declare(&e.name.name, SymbolKind::Event, e.name.span);
                }
                ContractItem::Error(e) => {
                    self.declare(&e.name.name, SymbolKind::Error, e.name.span);
                }
                ContractItem::Struct(s) => {
                    self.declare(&s.name.name, SymbolKind::Struct, s.name.span);
                }
                ContractItem::Enum(e) => {
                    self.declare(&e.name.name, SymbolKind::Enum, e.name.span);
                    for v in &e.variants {
                        self.declare(
                            &format!("{}::{}", e.name.name, v.name),
                            SymbolKind::EnumVariant { enum_name: e.name.name.clone() },
                            v.span,
                        );
                    }
                }
                ContractItem::Const(c) => {
                    self.declare(&c.name.name, SymbolKind::Const, c.name.span);
                }
                ContractItem::TypeAlias(t) => {
                    self.declare(&t.name.name, SymbolKind::TypeAlias, t.name.span);
                }
                ContractItem::Function(f) => {
                    self.declare(
                        &f.name.name,
                        SymbolKind::Function { is_pub: f.is_pub },
                        f.name.span,
                    );
                }
            }
        }
    }

    // ========================================================================
    // Resolution pass (verify references)
    // ========================================================================

    fn resolve_item(&mut self, item: &Item) {
        match item {
            Item::Contract(c) => self.resolve_contract(c),
            Item::Function(f) => self.resolve_function(f),
            Item::Const(c) => self.resolve_expr(&c.value),
            Item::Struct(s) => self.resolve_struct_fields(&s.fields),
            Item::Error(e) => self.resolve_struct_fields(&e.fields),
            Item::Interface(i) => self.resolve_interface(i),
            Item::Use(u) => self.resolve_use(u),
            Item::Enum(_) | Item::Module(_) | Item::TypeAlias(_) => {}
        }
    }

    fn resolve_contract(&mut self, contract: &ContractDef) {
        self.push_scope(ScopeKind::Contract);
        self.in_contract = true;

        // Declare all contract-level items first (forward references)
        self.declare_contract_items(&contract.items);

        // Then resolve bodies
        for item in &contract.items {
            match item {
                ContractItem::Function(f) => self.resolve_function(f),
                ContractItem::Const(c) => self.resolve_expr(&c.value),
                ContractItem::Struct(s) => self.resolve_struct_fields(&s.fields),
                ContractItem::Error(e) => self.resolve_struct_fields(&e.fields),
                ContractItem::Storage(s) => {
                    for field in &s.fields {
                        self.resolve_type(&field.ty);
                    }
                }
                ContractItem::Event(e) => {
                    for field in &e.fields {
                        self.resolve_type(&field.ty);
                    }
                }
                _ => {}
            }
        }

        self.in_contract = false;
        self.pop_scope();
    }

    fn resolve_function(&mut self, func: &FunctionDef) {
        self.push_scope(ScopeKind::Function);

        // Declare parameters
        for param in &func.params {
            self.declare(&param.name.name, SymbolKind::FnParam, param.name.span);
            self.resolve_type(&param.ty);
        }

        // Resolve return type
        if let Some(ref ret_ty) = func.return_type {
            self.resolve_type(ret_ty);
        }

        // Resolve body
        self.resolve_block(&func.body);

        self.pop_scope();
    }

    fn resolve_interface(&mut self, iface: &InterfaceDef) {
        for func in &iface.functions {
            for param in &func.params {
                self.resolve_type(&param.ty);
            }
            if let Some(ref ret_ty) = func.return_type {
                self.resolve_type(ret_ty);
            }
        }
    }

    fn resolve_struct_fields(&mut self, fields: &[StructField]) {
        for field in fields {
            self.resolve_type(&field.ty);
        }
    }

    /// Known standard library modules and their exports.
    const STD_MODULES: &'static [(&'static str, &'static [&'static str])] = &[
        ("math", &["sqrt", "pow", "min", "max", "clamp", "mul_div", "abs_diff", "average", "log10",
                   "checked_add", "checked_sub", "saturating_add", "saturating_sub",
                   "wrapping_add", "wrapping_sub"]),
        ("hash", &["poseidon2", "poseidon2_pair", "poseidon2_many"]),
        ("signature", &["verify", "recover"]),
        ("token", &["IERC20", "IERC721", "INFT"]),
    ];

    fn resolve_use(&mut self, import: &UseImport) {
        // Validate std:: imports
        if import.path.len() >= 2 && import.path[0].name == "std" {
            let module_name = &import.path[1].name;
            let known_module = Self::STD_MODULES.iter().find(|(name, _)| name == module_name);

            if known_module.is_none() {
                self.error(
                    format!("unknown standard library module 'std::{}'", module_name),
                    import.path[1].span,
                );
                return;
            }

            // Validate specific imports: use std::math::sqrt;
            if import.path.len() >= 3 {
                let item_name = &import.path[2].name;
                if let Some((_, exports)) = known_module {
                    if !exports.contains(&item_name.as_str()) {
                        self.error(
                            format!("'{}' is not exported from 'std::{}'", item_name, module_name),
                            import.path[2].span,
                        );
                        return;
                    }
                }
            }

            // Validate grouped imports: use std::math::{sqrt, pow};
            if let Some((_, exports)) = known_module {
                for item in &import.items {
                    if !exports.contains(&item.name.as_str()) {
                        self.error(
                            format!("'{}' is not exported from 'std::{}'", item.name, module_name),
                            item.span,
                        );
                    }
                }
            }

            // Register std module and items, then return (don't fall through to non-std handling)
            if let Some(last) = import.path.last() {
                // Avoid re-declaring "std" — register the module name (e.g., "math")
                // Skip if already declared (multiple imports from same std module).
                if last.name != "std" && self.lookup(&last.name).is_none() {
                    self.declare(&last.name, SymbolKind::Module, last.span);
                }
            }
            for item in &import.items {
                if self.lookup(&item.name).is_none() {
                    self.declare(&item.name, SymbolKind::Module, item.span);
                }
            }
            return;
        }

        // Non-std imports: file-based contract/type imports.
        // Syntax mirrors Rust:
        //   use counter::Counter;                      → path=["counter","Counter"], items=[]
        //   use counter::{Counter, InsufficientBalance}; → path=["counter"], items=[...]
        //   use counter::*;                             → future: glob import
        //
        // First path segment = module name (maps to src/<name>.oti in build pipeline).
        // Remaining segments or grouped items = contract/error/struct names.
        if import.path.len() >= 2 && import.items.is_empty() {
            // Single import: use module::Item;
            // Register module name (skip if already declared — multiple imports from same module).
            if self.lookup(&import.path[0].name).is_none() {
                self.declare(&import.path[0].name, SymbolKind::Module, import.path[0].span);
            }
            for segment in &import.path[1..] {
                self.declare(&segment.name, SymbolKind::Contract, segment.span);
            }
            return;
        }

        if !import.items.is_empty() {
            // Grouped import: use module::{Item1, Item2};
            // Register module name (skip if already declared).
            if let Some(first) = import.path.first() {
                if self.lookup(&first.name).is_none() {
                    self.declare(&first.name, SymbolKind::Module, first.span);
                }
            }
            for item in &import.items {
                self.declare(&item.name, SymbolKind::Contract, item.span);
            }
            return;
        }

        // Single module import: use module; (register module name only)
        if let Some(last) = import.path.last() {
            self.declare(&last.name, SymbolKind::Module, last.span);
        }
    }

    // ========================================================================
    // Type resolution
    // ========================================================================

    fn resolve_type(&mut self, ty: &Type) {
        match ty {
            Type::Named(ident) => {
                if !self.is_type_defined(&ident.name) {
                    self.error(
                        format!("undefined type '{}'", ident.name),
                        ident.span,
                    );
                }
            }
            Type::Array(elem, _, _) => self.resolve_type(elem),
            Type::Vec(elem, _) => self.resolve_type(elem),
            Type::Map(key, val, _) => {
                self.resolve_type(key);
                self.resolve_type(val);
            }
            Type::Tuple(types, _) => {
                for t in types {
                    self.resolve_type(t);
                }
            }
            Type::Primitive(_, _) | Type::Bytes(_) => {}
        }
    }

    // ========================================================================
    // Block and statement resolution
    // ========================================================================

    fn resolve_block(&mut self, block: &Block) {
        for stmt in &block.stmts {
            self.resolve_stmt(stmt);
        }
    }

    fn resolve_block_new_scope(&mut self, block: &Block) {
        self.push_scope(ScopeKind::Block);
        self.resolve_block(block);
        self.pop_scope();
    }

    fn resolve_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Let(l) => {
                // Resolve initializer first (before declaring the variable)
                self.resolve_expr(&l.initializer);

                if let Some(ref ty) = l.ty {
                    self.resolve_type(ty);
                }

                // Declare the binding(s)
                match &l.binding {
                    LetBinding::Name(name) => {
                        self.declare(
                            &name.name,
                            SymbolKind::LocalVar { is_mutable: l.is_mutable },
                            name.span,
                        );
                    }
                    LetBinding::Tuple(names, _) => {
                        for name in names {
                            self.declare(
                                &name.name,
                                SymbolKind::LocalVar { is_mutable: l.is_mutable },
                                name.span,
                            );
                        }
                    }
                }
            }
            Stmt::Assign(a) => {
                self.resolve_expr(&a.target);
                self.resolve_expr(&a.value);
            }
            Stmt::Return(r) => {
                if let Some(ref val) = r.value {
                    self.resolve_expr(val);
                }
            }
            Stmt::Emit(e) => {
                // Verify event name exists
                if self.lookup(&e.event_name.name).is_none() {
                    self.error(
                        format!("undefined event '{}'", e.event_name.name),
                        e.event_name.span,
                    );
                }
                for field in &e.fields {
                    self.resolve_expr(&field.value);
                }
            }
            Stmt::For(f) => {
                self.resolve_expr(&f.iterator);
                self.push_scope(ScopeKind::ForLoop);
                self.loop_depth += 1;
                self.declare(&f.variable.name, SymbolKind::ForVar, f.variable.span);
                self.resolve_block(&f.body);
                self.loop_depth -= 1;
                self.pop_scope();
            }
            Stmt::While(w) => {
                self.resolve_expr(&w.condition);
                self.loop_depth += 1;
                self.resolve_block_new_scope(&w.body);
                self.loop_depth -= 1;
            }
            Stmt::Expr(e) => {
                self.resolve_expr(&e.expr);
            }
            Stmt::Break(span) => {
                if self.loop_depth == 0 {
                    self.error("'break' can only be used inside a loop".into(), *span);
                }
            }
            Stmt::Continue(span) => {
                if self.loop_depth == 0 {
                    self.error("'continue' can only be used inside a loop".into(), *span);
                }
            }
        }
    }

    // ========================================================================
    // Expression resolution
    // ========================================================================

    fn resolve_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Literal(_, _) => {}

            Expr::Ident(ident) => {
                if ident.name == "_" {
                    return; // wildcard
                }
                if self.lookup(&ident.name).is_none()
                    && !self.builtin_fns.contains(&ident.name.as_str())
                    && !self.builtin_globals.contains(&ident.name.as_str())
                {
                    self.error(
                        format!("undefined variable '{}'", ident.name),
                        ident.span,
                    );
                }
            }

            Expr::SelfExpr(_) => {
                if !self.in_contract {
                    self.error(
                        "'self' can only be used inside a contract".into(),
                        match expr { Expr::SelfExpr(s) => *s, _ => unreachable!() },
                    );
                }
            }

            Expr::Binary(lhs, _, rhs, _) => {
                self.resolve_expr(lhs);
                self.resolve_expr(rhs);
            }

            Expr::Unary(_, operand, _) => {
                self.resolve_expr(operand);
            }

            Expr::FieldAccess(obj, _, _) => {
                self.resolve_expr(obj);
                // Field name resolution happens in type checking
            }

            Expr::Index(obj, index, _) => {
                self.resolve_expr(obj);
                self.resolve_expr(index);
            }

            Expr::Call(callee, args, _) => {
                self.resolve_expr(callee);
                for arg in args {
                    self.resolve_expr(arg);
                }
            }

            Expr::Path(segments, span) => {
                // First segment should be a known name
                if let Some(first) = segments.first() {
                    if self.lookup(&first.name).is_none()
                        && !self.is_type_defined(&first.name)
                        && !self.builtin_fns.contains(&first.name.as_str())
                    {
                        // Check if it's a known module path (e.g., math_lib::percentage)
                        // or an enum variant (Status::Active)
                        let qualified = segments.iter()
                            .map(|s| s.name.as_str())
                            .collect::<Vec<_>>()
                            .join("::");
                        if self.lookup(&qualified).is_none() {
                            self.error(
                                format!("undefined name '{}'", first.name),
                                first.span,
                            );
                        }
                    }
                }
            }

            Expr::MacroCall(name, args, span) => {
                // Built-in macros: require!, revert!, cross_call!, raw_call!
                let known_macros = ["require", "revert", "assert", "cross_call", "raw_call", "create"];
                if !known_macros.contains(&name.name.as_str()) {
                    self.error(
                        format!("unknown macro '{}!'", name.name),
                        name.span,
                    );
                }
                for arg in args {
                    match arg {
                        MacroArg::Positional(expr) => self.resolve_expr(expr),
                        MacroArg::Named(_, expr) => self.resolve_expr(expr),
                    }
                }
            }

            Expr::StructInit(name_segments, fields, span) => {
                // Verify the struct/error name exists
                if let Some(first) = name_segments.first() {
                    if !self.is_type_defined(&first.name)
                        && self.lookup(&first.name).map(|s| matches!(s.kind, SymbolKind::Error)).unwrap_or(false) == false
                        && self.lookup(&first.name).is_none()
                    {
                        self.error(
                            format!("undefined struct or error '{}'", first.name),
                            first.span,
                        );
                    }
                }
                for field in fields {
                    self.resolve_expr(&field.value);
                }
            }

            Expr::If(cond, then_block, else_clause, _) => {
                self.resolve_expr(cond);
                self.resolve_block_new_scope(then_block);
                if let Some(clause) = else_clause {
                    match clause {
                        ElseClause::ElseBlock(block) => self.resolve_block_new_scope(block),
                        ElseClause::ElseIf(else_if) => self.resolve_expr(else_if),
                    }
                }
            }

            Expr::Match(scrutinee, arms, _) => {
                self.resolve_expr(scrutinee);
                for arm in arms {
                    self.resolve_pattern(&arm.pattern);
                    self.resolve_expr(&arm.body);
                }
            }

            Expr::Block(block) => {
                self.resolve_block_new_scope(block);
            }

            Expr::Cast(expr, ty, _) => {
                self.resolve_expr(expr);
                self.resolve_type(ty);
            }

            Expr::Tuple(elements, _) => {
                for elem in elements {
                    self.resolve_expr(elem);
                }
            }

            Expr::ArrayRepeat(value, _, _) => {
                self.resolve_expr(value);
            }

            Expr::ArrayLiteral(elements, _) => {
                for elem in elements {
                    self.resolve_expr(elem);
                }
            }

            Expr::Try(inner, _) => {
                self.resolve_expr(inner);
            }
        }
    }

    fn resolve_pattern(&mut self, pattern: &Pattern) {
        match pattern {
            Pattern::Path(segments, span) => {
                // Verify enum variant path exists (e.g., Status::Active)
                if segments.len() >= 2 {
                    let qualified = segments.iter()
                        .map(|s| s.name.as_str())
                        .collect::<Vec<_>>()
                        .join("::");
                    if self.lookup(&qualified).is_none() {
                        // Check if the first segment is a known enum
                        if !self.is_type_defined(&segments[0].name) {
                            self.error(
                                format!("undefined enum '{}'", segments[0].name),
                                segments[0].span,
                            );
                        }
                    }
                }
                // Single-segment path patterns are just identifiers (catch-all)
            }
            Pattern::Literal(_, _) | Pattern::Range(_, _, _) | Pattern::Wildcard(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;
    use crate::parser::Parser;

    fn resolve(src: &str) -> Vec<ResolveError> {
        let (tokens, lex_errors) = Lexer::new(src).tokenize();
        assert!(lex_errors.is_empty(), "lex errors: {:?}", lex_errors);
        let (file, parse_errors) = Parser::new(tokens).parse();
        assert!(parse_errors.is_empty(), "parse errors: {:?}", parse_errors);
        Resolver::new().resolve(&file).errors
    }

    fn resolve_ok(src: &str) {
        let errors = resolve(src);
        assert!(errors.is_empty(), "resolve errors: {:?}", errors);
    }

    fn resolve_err(src: &str) -> Vec<ResolveError> {
        let errors = resolve(src);
        assert!(!errors.is_empty(), "expected resolve errors but got none");
        errors
    }

    // ========== Basic resolution ==========

    #[test]
    fn resolve_minimal_contract() {
        resolve_ok(r#"
            contract Token {
                storage { supply: u256, }
                pub fn get_supply() -> u256 {
                    return self.supply;
                }
            }
        "#);
    }

    #[test]
    fn resolve_local_variable() {
        resolve_ok(r#"
            contract T {
                pub fn f() {
                    let x = 42;
                    let y = x + 1;
                }
            }
        "#);
    }

    #[test]
    fn resolve_function_params() {
        resolve_ok(r#"
            contract T {
                pub fn transfer(to: Address, amount: u256) {
                    let total = amount + 1;
                }
            }
        "#);
    }

    #[test]
    fn resolve_for_loop_variable() {
        resolve_ok(r#"
            contract T {
                pub fn f() {
                    for i in 0..10 {
                        let x = i;
                    }
                }
            }
        "#);
    }

    #[test]
    fn resolve_struct_type() {
        resolve_ok(r#"
            contract T {
                struct Point { x: u64, y: u64 }
                pub fn f() {
                    let p = Point { x: 1, y: 2 };
                }
            }
        "#);
    }

    #[test]
    fn resolve_enum_variant() {
        resolve_ok(r#"
            contract T {
                enum Status { Active, Paused }
                pub fn f() {
                    let s = Status::Active;
                }
            }
        "#);
    }

    #[test]
    fn resolve_const_reference() {
        resolve_ok(r#"
            contract T {
                const MAX: u256 = 1000;
                pub fn f() {
                    let x = MAX;
                }
            }
        "#);
    }

    #[test]
    fn resolve_event_emit() {
        resolve_ok(r#"
            contract T {
                event Transfer { from: Address, to: Address, amount: u256, }
                pub fn f() {
                    emit Transfer { from: msg.sender, to: msg.sender, amount: 100 };
                }
            }
        "#);
    }

    #[test]
    fn resolve_error_in_require() {
        resolve_ok(r#"
            contract T {
                error Unauthorized {}
                pub fn f() {
                    require!(true, Unauthorized {});
                }
            }
        "#);
    }

    #[test]
    fn resolve_self_in_contract() {
        resolve_ok(r#"
            contract T {
                storage { balance: u256, }
                pub fn f() {
                    self.balance = 100;
                }
            }
        "#);
    }

    #[test]
    fn resolve_builtin_globals() {
        resolve_ok(r#"
            contract T {
                pub fn f() {
                    let sender = msg.sender;
                    let ts = block.timestamp;
                }
            }
        "#);
    }

    #[test]
    fn resolve_builtin_hash() {
        resolve_ok(r#"
            contract T {
                pub fn f() {
                    let h = hash(42);
                }
            }
        "#);
    }

    #[test]
    fn resolve_type_alias() {
        resolve_ok(r#"
            contract T {
                type TokenId = u256;
                storage { next_id: TokenId, }
                pub fn f() -> TokenId {
                    return self.next_id;
                }
            }
        "#);
    }

    #[test]
    fn resolve_tuple_destructuring() {
        resolve_ok(r#"
            contract T {
                pub fn get_pair() -> (u256, u256) {
                    return (1, 2);
                }
                pub fn f() {
                    let (a, b) = self.get_pair();
                    let sum = a + b;
                }
            }
        "#);
    }

    #[test]
    fn resolve_forward_reference() {
        // Functions can call other functions defined later in the contract
        resolve_ok(r#"
            contract T {
                pub fn f() {
                    self.helper();
                }
                fn helper() {}
            }
        "#);
    }

    #[test]
    fn resolve_interface_cross_call() {
        resolve_ok(r#"
            interface IERC20 {
                fn transfer(to: Address, amount: u256);
                fn balance_of(owner: Address) -> u256;
            }
            contract T {
                pub fn f() {
                    let token = IERC20::at(msg.sender);
                }
            }
        "#);
    }

    #[test]
    fn resolve_use_import() {
        resolve_ok(r#"
            use std::math;
            contract T {
                pub fn f() {
                    let x = math::sqrt(100);
                }
            }
        "#);
    }

    #[test]
    fn resolve_grouped_import() {
        resolve_ok(r#"
            use std::math::{sqrt, pow};
            contract T {
                pub fn f() {
                    let x = sqrt(100);
                    let y = pow(2, 10);
                }
            }
        "#);
    }

    #[test]
    fn error_unknown_std_module() {
        let errors = resolve_err(r#"
            use std::banana;
            contract T {}
        "#);
        assert!(errors[0].message.contains("unknown standard library module 'std::banana'"));
    }

    #[test]
    fn error_unknown_std_export() {
        let errors = resolve_err(r#"
            use std::math::pineapple;
            contract T {}
        "#);
        assert!(errors[0].message.contains("'pineapple' is not exported from 'std::math'"));
    }

    #[test]
    fn error_unknown_grouped_export() {
        let errors = resolve_err(r#"
            use std::math::{sqrt, banana};
            contract T {}
        "#);
        assert!(errors[0].message.contains("'banana' is not exported from 'std::math'"));
    }

    #[test]
    fn error_standalone_sqrt_without_import() {
        // sqrt(x) requires import — not a global function
        let errors = resolve_err(r#"
            contract T {
                pub fn f() {
                    let x = sqrt(100);
                }
            }
        "#);
        assert!(errors[0].message.contains("undefined variable 'sqrt'"));
    }

    #[test]
    fn resolve_standalone_sqrt_with_import() {
        // use std::math::sqrt; → sqrt(x) works
        resolve_ok(r#"
            use std::math::sqrt;
            contract T {
                pub fn f() {
                    let x = sqrt(100);
                }
            }
        "#);
    }

    #[test]
    fn resolve_method_sqrt_without_import() {
        // x.sqrt() works on any numeric — no import needed
        resolve_ok(r#"
            contract T {
                pub fn f() {
                    let x: u256 = 100;
                    let root = x.sqrt();
                    let powered = x.pow(3);
                    let clamped = x.min(50);
                }
            }
        "#);
    }

    #[test]
    fn resolve_valid_std_imports() {
        resolve_ok("use std::math;");
        resolve_ok("use std::hash;");
        resolve_ok("use std::signature;");
        resolve_ok("use std::token;");
        resolve_ok("use std::math::sqrt;");
        resolve_ok("use std::signature::verify;");
        resolve_ok("use std::hash::poseidon2;");
    }

    #[test]
    fn resolve_nested_scope() {
        resolve_ok(r#"
            contract T {
                pub fn f() {
                    let x = 1;
                    {
                        let y = x + 1;
                    }
                }
            }
        "#);
    }

    #[test]
    fn resolve_match_with_enum() {
        resolve_ok(r#"
            contract T {
                enum Status { Active, Paused, Closed }
                pub fn f() {
                    let s = Status::Active;
                    match s {
                        Status::Active => { let x = 1; },
                        Status::Paused => { let x = 2; },
                        _ => { let x = 3; },
                    }
                }
            }
        "#);
    }

    // ========== Error detection ==========

    #[test]
    fn error_undefined_variable() {
        let errors = resolve_err(r#"
            contract T {
                pub fn f() {
                    let x = undefined_var;
                }
            }
        "#);
        assert!(errors[0].message.contains("undefined variable 'undefined_var'"));
    }

    #[test]
    fn error_shadow_builtin_type() {
        let errors = resolve_err(r#"
            contract T {
                pub fn f() {
                    let Vec = 5;
                }
            }
        "#);
        assert!(errors[0].message.contains("cannot shadow builtin type 'Vec'"));
    }

    #[test]
    fn error_shadow_builtin_type_map() {
        let errors = resolve_err(r#"
            contract T {
                pub fn f() {
                    let Map = 10;
                }
            }
        "#);
        assert!(errors[0].message.contains("cannot shadow builtin type 'Map'"));
    }

    #[test]
    fn error_shadow_builtin_msg() {
        let errors = resolve_err(r#"
            contract T {
                pub fn f() {
                    let msg = 10;
                }
            }
        "#);
        assert!(errors[0].message.contains("cannot shadow builtin 'msg'"));
    }

    #[test]
    fn error_shadow_builtin_tx() {
        let errors = resolve_err(r#"
            contract T {
                pub fn f() {
                    let tx = 10;
                }
            }
        "#);
        assert!(errors[0].message.contains("cannot shadow builtin 'tx'"));
    }

    #[test]
    fn error_undefined_type() {
        let errors = resolve_err(r#"
            contract T {
                storage { data: NonexistentType, }
            }
        "#);
        assert!(errors[0].message.contains("undefined type 'NonexistentType'"));
    }

    #[test]
    fn error_undefined_event() {
        let errors = resolve_err(r#"
            contract T {
                pub fn f() {
                    emit FakeEvent { x: 1 };
                }
            }
        "#);
        assert!(errors[0].message.contains("undefined event 'FakeEvent'"));
    }

    #[test]
    fn error_unknown_macro() {
        let errors = resolve_err(r#"
            contract T {
                pub fn f() {
                    fake_macro!(1, 2, 3);
                }
            }
        "#);
        assert!(errors[0].message.contains("unknown macro 'fake_macro!'"));
    }

    #[test]
    fn error_self_outside_contract() {
        let errors = resolve_err(r#"
            fn f() {
                self.x = 1;
            }
        "#);
        assert!(errors[0].message.contains("'self' can only be used inside a contract"));
    }

    #[test]
    fn error_duplicate_function() {
        let errors = resolve_err(r#"
            contract T {
                pub fn f() {}
                pub fn f() {}
            }
        "#);
        assert!(errors[0].message.contains("'f' is already defined"));
    }

    #[test]
    fn error_duplicate_storage_field() {
        let errors = resolve_err(r#"
            contract T {
                storage {
                    balance: u256,
                    balance: u64,
                }
            }
        "#);
        assert!(errors[0].message.contains("'balance' is already defined"));
    }

    // ========== Namespace separation ==========

    #[test]
    fn allow_same_name_event_and_error() {
        // Event and error can share a name — different namespaces
        resolve_ok(r#"
            contract T {
                event TransferLocked { locked_until: u64, }
                error TransferLocked { until: u64 }
                pub fn f() {
                    emit TransferLocked { locked_until: 100 };
                    require!(false, TransferLocked { until: 100 });
                }
            }
        "#);
    }

    #[test]
    fn allow_same_name_storage_and_function() {
        // Storage field and function can share a name
        resolve_ok(r#"
            contract T {
                storage { is_active: bool, }
                #[view]
                pub fn is_active() -> bool {
                    return self.is_active;
                }
            }
        "#);
    }

    #[test]
    fn reject_duplicate_events() {
        // Two events with the same name — same namespace
        let errors = resolve_err(r#"
            contract T {
                event Transfer { from: Address, }
                event Transfer { to: Address, }
            }
        "#);
        assert!(errors[0].message.contains("'Transfer' is already defined"));
    }

    #[test]
    fn reject_duplicate_errors() {
        // Two errors with the same name — same namespace
        let errors = resolve_err(r#"
            contract T {
                error Unauthorized {}
                error Unauthorized { reason: String }
            }
        "#);
        assert!(errors[0].message.contains("'Unauthorized' is already defined"));
    }

    // ========== Break/continue validation ==========

    #[test]
    fn break_inside_for_loop() {
        resolve_ok(r#"
            contract T {
                pub fn f() {
                    for i in 0..10 {
                        if i == 5 { break; }
                    }
                }
            }
        "#);
    }

    #[test]
    fn continue_inside_while_loop() {
        resolve_ok(r#"
            contract T {
                pub fn f() {
                    let mut i = 0;
                    while i < 10 {
                        i += 1;
                        if i == 5 { continue; }
                    }
                }
            }
        "#);
    }

    #[test]
    fn error_break_outside_loop() {
        let errors = resolve_err(r#"
            contract T {
                pub fn f() {
                    break;
                }
            }
        "#);
        assert!(errors[0].message.contains("'break' can only be used inside a loop"));
    }

    #[test]
    fn error_continue_outside_loop() {
        let errors = resolve_err(r#"
            contract T {
                pub fn f() {
                    continue;
                }
            }
        "#);
        assert!(errors[0].message.contains("'continue' can only be used inside a loop"));
    }
}
