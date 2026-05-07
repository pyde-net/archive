//! Type checker: validates type correctness across the entire AST.
//!
//! Receives the AST + SymbolTable from the resolver.
//! Infers types for expressions, checks assignments, function calls,
//! struct inits, emit statements, and casts.

// Compiler + VM internals pass around nested generics (HashMap of
// Vec of tuples, etc.) where the shape IS the documentation; clippy
// flags these as `type_complexity`. Adding aliases would add names
// to learn without improving readability. Scoped allow at the
// module level; narrow to specific items if this grows.
#![allow(clippy::type_complexity)]

use std::collections::{HashMap, HashSet};

use crate::ast::*;
use crate::token::Span;
use crate::types::Ty;

/// Audit 356: same FNV-1a-32 used by codegen's `compute_selector`,
/// duplicated here so the typecheck pass can detect collisions
/// without taking a dependency on the codegen module. Keep in sync
/// with `crates/otic/src/codegen.rs::compute_selector` — if the
/// hash function ever changes (e.g. switch to Poseidon2-truncated),
/// this helper must move too. A regression test in the codegen
/// module pins the wire format; here we only need byte-equality
/// with that.
fn compute_fnv1a_selector(name: &str) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for byte in name.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Clone, Debug)]
pub struct TypeError {
    pub message: String,
    pub span: Span,
}

impl std::fmt::Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.span.line, self.span.col, self.message)
    }
}

// ============================================================================
// Type environment
// ============================================================================

/// Stores type information for all definitions in the program.
#[derive(Clone, Debug)]
pub struct TypeEnv {
    /// Variable/param/field name → (type, is_mutable)
    locals: Vec<HashMap<String, (Ty, bool)>>,
    /// Storage field name → type
    storage_fields: HashMap<String, Ty>,
    /// Struct name → fields (name → type)
    struct_defs: HashMap<String, Vec<(String, Ty)>>,
    /// Enum name → variants
    enum_defs: HashMap<String, Vec<String>>,
    /// Const name → type
    const_defs: HashMap<String, Ty>,
    /// Type alias name → underlying type
    type_aliases: HashMap<String, Ty>,
    /// Function name → (params, return_type)
    func_sigs: HashMap<String, (Vec<(String, Ty)>, Ty)>,
    /// Event name → fields (name, type, indexed)
    event_defs: HashMap<String, Vec<(String, Ty, bool)>>,
    /// Error name → fields (name, type)
    error_defs: HashMap<String, Vec<(String, Ty)>>,
    /// Interface name → function sigs
    interface_defs: HashMap<String, Vec<(String, Vec<(String, Ty)>, Ty)>>,
    /// Contract name → constructor param types (for deploy!/create! validation)
    contract_constructors: HashMap<String, Vec<(String, Ty)>>,
    /// Known contract names (for cast validation and type resolution)
    contract_names: HashSet<String>,
}

impl TypeEnv {
    fn new() -> Self {
        Self {
            locals: vec![HashMap::new()],
            storage_fields: HashMap::new(),
            struct_defs: HashMap::new(),
            enum_defs: HashMap::new(),
            const_defs: HashMap::new(),
            type_aliases: HashMap::new(),
            func_sigs: HashMap::new(),
            event_defs: HashMap::new(),
            error_defs: HashMap::new(),
            interface_defs: HashMap::new(),
            contract_constructors: HashMap::new(),
            contract_names: HashSet::new(),
        }
    }

    fn push_scope(&mut self) {
        self.locals.push(HashMap::new());
    }

    fn pop_scope(&mut self) {
        self.locals.pop();
    }

    fn declare_local(&mut self, name: &str, ty: Ty, is_mutable: bool) {
        if let Some(scope) = self.locals.last_mut() {
            scope.insert(name.to_string(), (ty, is_mutable));
        }
    }

    fn lookup_local(&self, name: &str) -> Option<&Ty> {
        for scope in self.locals.iter().rev() {
            if let Some((ty, _)) = scope.get(name) {
                return Some(ty);
            }
        }
        None
    }

    fn is_mutable(&self, name: &str) -> bool {
        for scope in self.locals.iter().rev() {
            if let Some((_, mutable)) = scope.get(name) {
                return *mutable;
            }
        }
        // Storage fields and params are mutable by default for assignment
        true
    }
}

// ============================================================================
// Type Checker
// ============================================================================

pub struct TypeChecker {
    env: TypeEnv,
    errors: Vec<TypeError>,
    in_contract: bool,
    /// The expected return type of the current function (for return stmt checking).
    current_return_type: Option<Ty>,
}

impl Default for TypeChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeChecker {
    pub fn new() -> Self {
        Self {
            env: TypeEnv::new(),
            errors: Vec::new(),
            in_contract: false,
            current_return_type: None,
        }
    }

    /// Type check a source file.
    pub fn check(mut self, file: &SourceFile) -> TypeCheckResult {
        // Audit 354: pre-pass that rejects signed integer types
        // (`i8`/`i16`/`i32`/`i64`/`i128`/`i256`) anywhere in the
        // program. Codegen emits unsigned PVM ops for `Div`,
        // `Mod`, `<`, `>`, `<=`, `>=`, and `Shr`, and the
        // optimizer's constant-folder uses `U256` for fold_binop /
        // fold_cmp. So any contract using `i*` types compiles
        // silently but produces wrong results at runtime
        // (`i32::MIN / -1`, `-1 < 0`, etc.). Failing loudly at
        // typecheck is the conservative testnet fix; lifting
        // signed types post-mainnet requires adding `Sdiv` /
        // `Smod` / `Slt` / `Sgt` / `Sar` ISA opcodes plus
        // cascading the change through codegen + optimizer + AOT.
        for item in &file.items {
            self.reject_signed_types_in_item(item);
        }

        // First pass: collect all type definitions
        for item in &file.items {
            self.collect_defs(item);
        }

        // Second pass: check all bodies
        for item in &file.items {
            self.check_item(item);
        }

        TypeCheckResult {
            errors: self.errors,
        }
    }

    /// Audit 354: walk every type annotation in this item and emit
    /// a typecheck error for any signed-integer primitive. Covers
    /// function params + returns, struct/event/storage fields, type
    /// aliases — everywhere a `Type` node can appear in the AST.
    fn reject_signed_types_in_item(&mut self, item: &Item) {
        match item {
            Item::Function(f) => self.reject_signed_in_function(f),
            Item::Contract(c) => {
                for ci in &c.items {
                    match ci {
                        ContractItem::Storage(sb) => {
                            for sf in &sb.fields {
                                self.reject_signed_in_type(&sf.ty);
                            }
                        }
                        ContractItem::Event(ev) => {
                            for ef in &ev.fields {
                                self.reject_signed_in_type(&ef.ty);
                            }
                        }
                        ContractItem::Error(er) => {
                            for f in &er.fields {
                                self.reject_signed_in_type(&f.ty);
                            }
                        }
                        ContractItem::Struct(s) => {
                            for f in &s.fields {
                                self.reject_signed_in_type(&f.ty);
                            }
                        }
                        ContractItem::Const(cd) => {
                            if let Some(ty) = &cd.ty {
                                self.reject_signed_in_type(ty);
                            }
                        }
                        ContractItem::TypeAlias(ta) => {
                            self.reject_signed_in_type(&ta.ty);
                        }
                        ContractItem::Function(f) => self.reject_signed_in_function(f),
                        ContractItem::Enum(_) => {}
                    }
                }
            }
            Item::Struct(s) => {
                for f in &s.fields {
                    self.reject_signed_in_type(&f.ty);
                }
            }
            Item::Const(cd) => {
                if let Some(ty) = &cd.ty {
                    self.reject_signed_in_type(ty);
                }
            }
            Item::TypeAlias(ta) => self.reject_signed_in_type(&ta.ty),
            Item::Error(er) => {
                for f in &er.fields {
                    self.reject_signed_in_type(&f.ty);
                }
            }
            Item::Interface(iface) => {
                for f in &iface.functions {
                    for p in &f.params {
                        self.reject_signed_in_type(&p.ty);
                    }
                    if let Some(ret) = &f.return_type {
                        self.reject_signed_in_type(ret);
                    }
                }
            }
            Item::Module(_) | Item::Enum(_) | Item::Use(_) => {
                // module/use/enum carry no type annotations directly.
            }
        }
    }

    fn reject_signed_in_function(&mut self, f: &FunctionDef) {
        for p in &f.params {
            self.reject_signed_in_type(&p.ty);
        }
        if let Some(ret) = &f.return_type {
            self.reject_signed_in_type(ret);
        }
    }

    /// Recurse into a `Type` node and reject:
    ///   1. Signed integer primitives anywhere (audit 354).
    ///   2. Wide elements inside `Vec<…>` or `[…; N]` (TPL-209).
    ///
    /// Both walks share the same recursion shape (visit every
    /// container's payload), so they're folded into one pass.
    /// Each report carries its own audit/TPL identifier so the
    /// downstream tests pin the right error.
    fn reject_signed_in_type(&mut self, ty: &Type) {
        match ty {
            Type::Primitive(p, span) => {
                let signed_name = match p {
                    PrimitiveType::I8 => Some("i8"),
                    PrimitiveType::I16 => Some("i16"),
                    PrimitiveType::I32 => Some("i32"),
                    PrimitiveType::I64 => Some("i64"),
                    PrimitiveType::I128 => Some("i128"),
                    PrimitiveType::I256 => Some("i256"),
                    _ => None,
                };
                if let Some(name) = signed_name {
                    self.error(
                        format!(
                            "signed integer type `{}` is not supported (audit 354): \
                             codegen + optimizer treat all integers as unsigned, so a contract \
                             using signed types would silently produce wrong arithmetic. \
                             Use the corresponding unsigned type and explicit two's-complement \
                             encoding if needed; signed types will land post-mainnet alongside \
                             Sdiv/Smod/Slt/Sgt/Sar ISA opcodes.",
                            name
                        ),
                        *span,
                    );
                }
            }
            Type::Bytes(_) => {}
            Type::Array(elem, _, span) => {
                // TPL-209: arrays use the same 8-byte-stride
                // codegen as Vec (`MakeArray`/`ArrayRepeat` in
                // codegen.rs:1922-1946 store at `i * WORD_SIZE`),
                // so a wide element silently truncates.
                if let Some(name) = Self::wide_element_name(elem) {
                    self.error(
                        format!(
                            "[{}; N] is not supported (TPL-209): the codegen stores \
                             elements at an 8-byte stride, so a wider type silently \
                             truncates to its low 8 bytes. Stride-aware fixed arrays \
                             land post-mainnet.",
                            name
                        ),
                        *span,
                    );
                }
                self.reject_signed_in_type(elem);
            }
            Type::Vec(elem, span) => {
                // TPL-209: `IndexGet`/`IndexSet` codegen
                // (`codegen.rs:1869-1889`) reads/writes 8 bytes
                // at `base + idx*8 + VEC_DATA_OFFSET`, regardless
                // of the declared element type. A `Vec<Address>`
                // multisig signer list would lose every byte
                // past the first 8 of each address; `Vec<u256>`
                // and `Vec<bytes>` have the same shape. Reject
                // until per-element-pointer-and-deref (or
                // stride-aware allocation) lands post-mainnet.
                if let Some(name) = Self::wide_element_name(elem) {
                    self.error(
                        format!(
                            "Vec<{}> is not supported (TPL-209): the codegen stores Vec \
                             elements at an 8-byte stride, so a wider type silently \
                             truncates to its low 8 bytes. Stride-aware Vec lands \
                             post-mainnet; for now, store wide values via Map<u64, T> or \
                             a fixed-size struct.",
                            name
                        ),
                        *span,
                    );
                }
                self.reject_signed_in_type(elem);
            }
            Type::Map(k, v, _) => {
                self.reject_signed_in_type(k);
                self.reject_signed_in_type(v);
            }
            Type::Named(_) => {} // user-defined types resolve elsewhere
            Type::Tuple(types, _) => {
                for t in types {
                    self.reject_signed_in_type(t);
                }
            }
        }
    }

    /// TPL-209: name the element type if it is wide (more than
    /// 8 bytes at runtime). `Type::Bytes` is a length + heap
    /// pointer, which doesn't fit an 8-byte slot any better than
    /// `u256`. `Type::Named` could resolve to a struct that's
    /// also too wide, but per-struct size analysis is post-
    /// mainnet — for now the reject is scoped to the explicit
    /// wide primitives + bytes from the tracker.
    fn wide_element_name(ty: &Type) -> Option<&'static str> {
        match ty {
            Type::Primitive(p, _) => match p {
                PrimitiveType::U128 => Some("u128"),
                PrimitiveType::U256 => Some("u256"),
                PrimitiveType::I128 => Some("i128"),
                PrimitiveType::I256 => Some("i256"),
                PrimitiveType::Address => Some("Address"),
                PrimitiveType::StringType => Some("string"),
                _ => None,
            },
            Type::Bytes(_) => Some("bytes"),
            _ => None,
        }
    }

    fn error(&mut self, message: String, span: Span) {
        self.errors.push(TypeError { message, span });
    }

    /// Check if an inferred type is compatible with a declared type via structural matching.
    /// e.g., Vec<?> is compatible with Vec<u256>, bytes is compatible with bytes.
    fn is_compatible_init(&self, inferred: &Ty, declared: &Ty) -> bool {
        match (inferred, declared) {
            // Vec<?> compatible with any Vec<T> and vice versa
            (Ty::Vec(inner), Ty::Vec(_)) if **inner == Ty::Unknown => true,
            (Ty::Vec(_), Ty::Vec(inner)) if **inner == Ty::Unknown => true,
            // Vec<A> assignable to Vec<B> if A can widen to B or B to A
            (Ty::Vec(a), Ty::Vec(b)) => a == b || a.can_widen_to(b) || b.can_widen_to(a),
            // Array with int literal elements adapts to any numeric element type
            // e.g., [0; 32] (inferred as [u256; 32]) is compatible with [u8; 32]
            (Ty::Array(a_elem, a_size), Ty::Array(b_elem, b_size)) => {
                a_size == b_size
                    && (a_elem == b_elem
                        || **a_elem == Ty::Unknown
                        || **b_elem == Ty::Unknown
                        || a_elem.can_widen_to(b_elem)
                        || b_elem.can_widen_to(a_elem)
                        || (a_elem.is_numeric() && b_elem.is_numeric()))
            }
            // Unknown/Error declared type accepts anything
            (_, Ty::Unknown) | (_, Ty::Error) => true,
            (Ty::Unknown, _) | (Ty::Error, _) => true,
            // NB: `(Ty::Struct(_), Ty::Unknown)` used to live here but
            // is already subsumed by `(_, Ty::Unknown)` above — leaving
            // it caused a `#[warn(unreachable_patterns)]`.
            _ => false,
        }
    }

    /// Check if an expression is an integer literal that can adapt to the target type.
    /// Integer literals are polymorphic — `42` can be u8, u64, u256, i32, etc.
    fn is_int_literal_compatible(&self, expr: &Expr, target: &Ty) -> bool {
        match expr {
            Expr::Literal(Literal::Int(_), _) => target.is_numeric(),
            Expr::Unary(UnaryOp::Negate, inner, _) => {
                matches!(inner.as_ref(), Expr::Literal(Literal::Int(_), _)) && target.is_numeric()
            }
            _ => false,
        }
    }

    // ========================================================================
    // AST Type → Ty conversion
    // ========================================================================

    fn resolve_type(&self, ast_ty: &Type) -> Ty {
        match ast_ty {
            Type::Primitive(p, _) => self.primitive_to_ty(p),
            Type::Bytes(_) => Ty::Bytes,
            Type::Array(elem, size, _) => Ty::Array(Box::new(self.resolve_type(elem)), *size),
            Type::Vec(elem, _) => Ty::Vec(Box::new(self.resolve_type(elem))),
            Type::Map(key, val, _) => Ty::Map(
                Box::new(self.resolve_type(key)),
                Box::new(self.resolve_type(val)),
            ),
            Type::Named(path) => {
                // For qualified paths (module::Type), resolve the last segment.
                // The module prefix is validated by the resolver; here we just
                // need the concrete type name.
                let name = path.last().map(|i| i.name.as_str()).unwrap_or("");
                if let Some(ty) = self.env.type_aliases.get(name) {
                    return ty.clone();
                }
                if self.env.struct_defs.contains_key(name) {
                    return Ty::Struct(name.to_string());
                }
                if self.env.enum_defs.contains_key(name) {
                    return Ty::Enum(name.to_string());
                }
                if self.env.interface_defs.contains_key(name) {
                    return Ty::Interface(name.to_string());
                }
                if self.env.contract_names.contains(name) {
                    return Ty::Contract(name.to_string());
                }
                Ty::Unknown
            }
            Type::Tuple(types, _) => {
                Ty::Tuple(types.iter().map(|t| self.resolve_type(t)).collect())
            }
        }
    }

    fn primitive_to_ty(&self, p: &PrimitiveType) -> Ty {
        match p {
            PrimitiveType::U8 => Ty::U8,
            PrimitiveType::U16 => Ty::U16,
            PrimitiveType::U32 => Ty::U32,
            PrimitiveType::U64 => Ty::U64,
            PrimitiveType::U128 => Ty::U128,
            PrimitiveType::U256 => Ty::U256,
            PrimitiveType::I8 => Ty::I8,
            PrimitiveType::I16 => Ty::I16,
            PrimitiveType::I32 => Ty::I32,
            PrimitiveType::I64 => Ty::I64,
            PrimitiveType::I128 => Ty::I128,
            PrimitiveType::I256 => Ty::I256,
            PrimitiveType::Bool => Ty::Bool,
            PrimitiveType::Address => Ty::Address,
            PrimitiveType::StringType => Ty::StringTy,
        }
    }

    // ========================================================================
    // Definition collection (first pass)
    // ========================================================================

    fn collect_defs(&mut self, item: &Item) {
        match item {
            Item::Contract(c) => self.collect_contract_defs(c),
            Item::Struct(s) => self.collect_struct(s),
            Item::Enum(e) => self.collect_enum(e),
            Item::Const(c) => self.collect_const(c),
            Item::TypeAlias(t) => self.collect_type_alias(t),
            Item::Interface(i) => self.collect_interface(i),
            Item::Error(e) => self.collect_error(e),
            Item::Function(f) => self.collect_func_sig(f),
            Item::Use(u) => self.collect_std_import_sigs(u),
            _ => {}
        }
    }

    /// Register function signatures for known std library imports.
    fn collect_std_import_sigs(&mut self, import: &UseImport) {
        if import.path.len() < 2 || import.path[0].name != "std" {
            return;
        }
        let module = &import.path[1].name;

        // Collect which items are imported
        let imported_items: Vec<String> = if !import.items.is_empty() {
            // Grouped: use std::math::{sqrt, pow};
            import.items.iter().map(|i| i.name.clone()).collect()
        } else if import.path.len() >= 3 {
            // Single: use std::math::sqrt;
            vec![import.path[2].name.clone()]
        } else {
            // Module: use std::math; — don't register standalone functions
            // (they're called as math::sqrt(), handled by Path call)
            return;
        };

        // Register each imported function with its known signature
        for item_name in &imported_items {
            if let Some((params, ret)) = self.get_std_fn_sig(module, item_name) {
                self.env.func_sigs.insert(item_name.clone(), (params, ret));
            }
        }
    }

    /// Get the known signature of a standard library function.
    fn get_std_fn_sig(&self, module: &str, func: &str) -> Option<(Vec<(String, Ty)>, Ty)> {
        match (module, func) {
            // std::math
            ("math", "sqrt") => Some((vec![("x".into(), Ty::U256)], Ty::U256)),
            ("math", "pow") => Some((
                vec![("base".into(), Ty::U256), ("exp".into(), Ty::U256)],
                Ty::U256,
            )),
            ("math", "min") => Some((
                vec![("a".into(), Ty::U256), ("b".into(), Ty::U256)],
                Ty::U256,
            )),
            ("math", "max") => Some((
                vec![("a".into(), Ty::U256), ("b".into(), Ty::U256)],
                Ty::U256,
            )),
            ("math", "clamp") => Some((
                vec![
                    ("x".into(), Ty::U256),
                    ("lo".into(), Ty::U256),
                    ("hi".into(), Ty::U256),
                ],
                Ty::U256,
            )),
            ("math", "mul_div") => Some((
                vec![
                    ("a".into(), Ty::U256),
                    ("b".into(), Ty::U256),
                    ("c".into(), Ty::U256),
                ],
                Ty::U256,
            )),
            // std::signature
            ("signature", "verify") => Some((
                vec![
                    ("message".into(), Ty::Array(Box::new(Ty::U8), 32)),
                    ("sig".into(), Ty::Bytes),
                    ("pubkey".into(), Ty::Bytes),
                ],
                Ty::Bool,
            )),
            ("signature", "recover") => Some((
                vec![
                    ("message".into(), Ty::Array(Box::new(Ty::U8), 32)),
                    ("sig".into(), Ty::Bytes),
                ],
                Ty::Address,
            )),
            // std::hash
            ("hash", "poseidon2") => Some((
                vec![("data".into(), Ty::Bytes)],
                Ty::Array(Box::new(Ty::U8), 32),
            )),
            ("hash", "poseidon2_pair") => Some((
                vec![
                    ("a".into(), Ty::Array(Box::new(Ty::U8), 32)),
                    ("b".into(), Ty::Array(Box::new(Ty::U8), 32)),
                ],
                Ty::Array(Box::new(Ty::U8), 32),
            )),
            _ => None,
        }
    }

    fn collect_contract_defs(&mut self, contract: &ContractDef) {
        self.env.contract_names.insert(contract.name.name.clone());
        for item in &contract.items {
            match item {
                ContractItem::Storage(s) => {
                    for field in &s.fields {
                        let ty = self.resolve_type(&field.ty);
                        self.env.storage_fields.insert(field.name.name.clone(), ty);
                    }
                }
                ContractItem::Struct(s) => self.collect_struct(s),
                ContractItem::Enum(e) => self.collect_enum(e),
                ContractItem::Const(c) => self.collect_const(c),
                ContractItem::TypeAlias(t) => self.collect_type_alias(t),
                ContractItem::Event(e) => self.collect_event(e),
                ContractItem::Error(e) => self.collect_error(e),
                ContractItem::Function(f) => {
                    self.collect_func_sig(f);
                    if f.is_constructor() {
                        let params: Vec<(String, Ty)> = f
                            .params
                            .iter()
                            .map(|p| (p.name.name.clone(), self.resolve_type(&p.ty)))
                            .collect();
                        self.env
                            .contract_constructors
                            .insert(contract.name.name.clone(), params);
                    }
                }
            }
        }
    }

    fn collect_struct(&mut self, s: &StructDef) {
        let fields: Vec<(String, Ty)> = s
            .fields
            .iter()
            .map(|f| (f.name.name.clone(), self.resolve_type(&f.ty)))
            .collect();
        self.env.struct_defs.insert(s.name.name.clone(), fields);
    }

    fn collect_enum(&mut self, e: &EnumDef) {
        let variants: Vec<String> = e.variants.iter().map(|v| v.name.clone()).collect();
        self.env.enum_defs.insert(e.name.name.clone(), variants);
    }

    fn collect_const(&mut self, c: &ConstDef) {
        let ty = if let Some(ref t) = c.ty {
            self.resolve_type(t)
        } else {
            Ty::Unknown
        };
        self.env.const_defs.insert(c.name.name.clone(), ty);
    }

    fn collect_type_alias(&mut self, t: &TypeAliasDef) {
        let ty = self.resolve_type(&t.ty);
        self.env.type_aliases.insert(t.name.name.clone(), ty);
    }

    fn collect_event(&mut self, e: &EventDef) {
        let fields: Vec<(String, Ty, bool)> = e
            .fields
            .iter()
            .map(|f| (f.name.name.clone(), self.resolve_type(&f.ty), f.indexed))
            .collect();
        self.env.event_defs.insert(e.name.name.clone(), fields);
    }

    fn collect_error(&mut self, e: &ErrorDef) {
        let fields: Vec<(String, Ty)> = e
            .fields
            .iter()
            .map(|f| (f.name.name.clone(), self.resolve_type(&f.ty)))
            .collect();
        self.env.error_defs.insert(e.name.name.clone(), fields);
    }

    fn collect_func_sig(&mut self, f: &FunctionDef) {
        let params: Vec<(String, Ty)> = f
            .params
            .iter()
            .map(|p| (p.name.name.clone(), self.resolve_type(&p.ty)))
            .collect();
        let ret = f
            .return_type
            .as_ref()
            .map(|t| self.resolve_type(t))
            .unwrap_or(Ty::Unit);
        self.env
            .func_sigs
            .insert(f.name.name.clone(), (params, ret));
    }

    fn collect_interface(&mut self, iface: &InterfaceDef) {
        let funcs: Vec<(String, Vec<(String, Ty)>, Ty)> = iface
            .functions
            .iter()
            .map(|f| {
                let params: Vec<(String, Ty)> = f
                    .params
                    .iter()
                    .map(|p| (p.name.name.clone(), self.resolve_type(&p.ty)))
                    .collect();
                let ret = f
                    .return_type
                    .as_ref()
                    .map(|t| self.resolve_type(t))
                    .unwrap_or(Ty::Unit);
                (f.name.name.clone(), params, ret)
            })
            .collect();
        self.env
            .interface_defs
            .insert(iface.name.name.clone(), funcs);
    }

    // ========================================================================
    // Item checking (second pass)
    // ========================================================================

    fn check_item(&mut self, item: &Item) {
        match item {
            Item::Contract(c) => self.check_contract(c),
            Item::Function(f) => self.check_function(f),
            Item::Const(c) => {
                self.infer_expr(&c.value);
            }
            _ => {}
        }
    }

    fn check_contract(&mut self, contract: &ContractDef) {
        self.in_contract = true;
        // Audit 356: detect FNV-1a-32 selector collisions across
        // public functions in this contract before codegen. The
        // dispatch table picks the first match for any given
        // selector, so a collision silently shadows one function
        // with another — caller invokes `transfer(...)` and the
        // VM dispatches to `mint(...)`. The collision probability
        // is ~1.05e-7 for 30 functions (birthday paradox over
        // 2^32) but adversarial naming can force one in seconds,
        // and even one accidental collision in a compile is a
        // silent footgun.
        let mut seen_selectors: std::collections::HashMap<u32, String> =
            std::collections::HashMap::new();
        for item in &contract.items {
            if let ContractItem::Function(f) = item {
                if f.is_pub
                    && !f.is_constructor()
                    && !f.is_test()
                    && !f.is_receive()
                    && !f.is_fallback()
                {
                    let sel = compute_fnv1a_selector(&f.name.name);
                    if let Some(prev) = seen_selectors.get(&sel) {
                        if prev != &f.name.name {
                            self.error(
                                format!(
                                    "FNV-1a-32 selector collision (audit 356): \
                                     function `{}` and `{}` both hash to 0x{:08x}. \
                                     Rename one of them; the dispatch table picks \
                                     the first match silently and would shadow the \
                                     other.",
                                    prev, f.name.name, sel
                                ),
                                f.name.span,
                            );
                        }
                    } else {
                        seen_selectors.insert(sel, f.name.name.clone());
                    }
                }
            }
        }
        for item in &contract.items {
            match item {
                ContractItem::Function(f) => self.check_function(f),
                ContractItem::Const(c) => {
                    self.infer_expr(&c.value);
                }
                _ => {}
            }
        }
        self.in_contract = false;
    }

    fn check_function(&mut self, func: &FunctionDef) {
        self.env.push_scope();

        // Declare parameters
        for param in &func.params {
            let ty = self.resolve_type(&param.ty);
            self.env.declare_local(&param.name.name, ty, false); // params are immutable
        }

        // Check body with expected return type
        let ret_ty = func
            .return_type
            .as_ref()
            .map(|t| self.resolve_type(t))
            .unwrap_or(Ty::Unit);

        self.current_return_type = Some(ret_ty.clone());
        self.check_block(&func.body);

        // Check that non-void functions have a return path
        if ret_ty != Ty::Unit && ret_ty != Ty::Unknown && !self.block_has_return(&func.body) {
            self.error(
                format!(
                    "function '{}' must return {} but body may not return a value",
                    func.name.name, ret_ty
                ),
                func.span,
            );
        }

        self.current_return_type = None;
        self.env.pop_scope();
    }

    /// Check if a block definitely returns or exits (simplified control flow check).
    fn block_has_return(&self, block: &Block) -> bool {
        // Check if ANY statement in the block is a definite exit
        for stmt in &block.stmts {
            if self.stmt_definitely_exits(stmt) {
                return true;
            }
        }
        false
    }

    fn stmt_definitely_exits(&self, stmt: &Stmt) -> bool {
        match stmt {
            Stmt::Return(r) => r.value.is_some(),
            Stmt::Expr(e) => {
                match &e.expr {
                    // revert!() always exits
                    Expr::MacroCall(name, _, _) if name.name == "revert" => true,
                    // if/else where both branches exit
                    Expr::If(_, then_block, Some(else_clause), _) => {
                        let then_exits = self.block_has_return(then_block);
                        let else_exits = match else_clause {
                            ElseClause::ElseBlock(b) => self.block_has_return(b),
                            ElseClause::ElseIf(e) => {
                                if let Expr::If(_, tb, ec, _) = e.as_ref() {
                                    self.block_has_return(tb)
                                        && ec.as_ref().is_some_and(|c| match c {
                                            ElseClause::ElseBlock(b) => self.block_has_return(b),
                                            _ => false,
                                        })
                                } else {
                                    false
                                }
                            }
                        };
                        then_exits && else_exits
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    // ========================================================================
    // Block and statement checking
    // ========================================================================

    fn check_block(&mut self, block: &Block) {
        for stmt in &block.stmts {
            self.check_stmt(stmt);
        }
    }

    fn check_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Let(l) => self.check_let(l),
            Stmt::Assign(a) => self.check_assign(a),
            Stmt::Return(r) => {
                if let Some(ref expected) = self.current_return_type.clone() {
                    if let Some(ref val) = r.value {
                        let ret_ty = self.infer_expr(val);
                        // Void function returning a value
                        if *expected == Ty::Unit {
                            self.error(
                                "function does not return a value, but 'return' has an expression"
                                    .into(),
                                r.span,
                            );
                        }
                        // Type mismatch
                        else if ret_ty != Ty::Unknown
                            && ret_ty != Ty::Error
                            && *expected != Ty::Unknown
                            && ret_ty != *expected
                            && !self.is_int_literal_compatible(val, expected)
                            && !ret_ty.can_widen_to(expected)
                            && !(ret_ty.is_numeric() && expected.is_numeric())
                            && !self.is_compatible_init(&ret_ty, expected)
                        {
                            self.error(
                                format!(
                                    "return type mismatch: expected {}, found {}",
                                    expected, ret_ty
                                ),
                                r.span,
                            );
                        }
                    } else {
                        // Bare return; in non-void function
                        if *expected != Ty::Unit && *expected != Ty::Unknown {
                            self.error(
                                format!("function returns {} but 'return' has no value", expected),
                                r.span,
                            );
                        }
                    }
                }
            }
            Stmt::Emit(e) => self.check_emit(e),
            Stmt::For(f) => self.check_for(f),
            Stmt::While(w) => {
                let cond_ty = self.infer_expr(&w.condition);
                if cond_ty != Ty::Bool && cond_ty != Ty::Unknown && cond_ty != Ty::Error {
                    self.error(
                        format!("while condition must be bool, found {}", cond_ty),
                        w.span,
                    );
                }
                self.env.push_scope();
                self.check_block(&w.body);
                self.env.pop_scope();
            }
            Stmt::Expr(e) => {
                self.infer_expr(&e.expr);
            }
            Stmt::Break(_) | Stmt::Continue(_) => {}
        }
    }

    fn check_let(&mut self, l: &LetStmt) {
        let init_ty = self.infer_expr(&l.initializer);

        let declared_ty = if let Some(ref ty) = l.ty {
            // Audit 354: the upfront `reject_signed_types_in_item`
            // pass walks fn params, return types, and field
            // declarations — but `let x: i64 = ...` lives inside a
            // function body, so a signed annotation here would slip
            // through and feed an unsigned-only codegen with a
            // signed `Ty::I*`. Reject signed annotations on let
            // bindings the same way we reject them on declarations.
            self.reject_signed_in_type(ty);
            let t = self.resolve_type(ty);
            // Check compatibility — integer literals are polymorphic,
            // and Vec<?>/Unknown types are compatible with concrete types
            if init_ty != Ty::Unknown
                && init_ty != Ty::Error
                && t != init_ty
                && !self.is_int_literal_compatible(&l.initializer, &t)
                && !self.is_compatible_init(&init_ty, &t)
                && !init_ty.can_widen_to(&t)
            {
                self.error(
                    format!(
                        "type mismatch: declared {}, but initializer is {}",
                        t, init_ty
                    ),
                    l.span,
                );
            }
            t
        } else {
            init_ty
        };

        match &l.binding {
            LetBinding::Name(name) => {
                self.env
                    .declare_local(&name.name, declared_ty, l.is_mutable);
            }
            LetBinding::Tuple(names, span) => {
                if let Ty::Tuple(types) = &declared_ty {
                    if names.len() != types.len() {
                        self.error(
                            format!(
                                "tuple destructuring: expected {} elements, found {}",
                                types.len(),
                                names.len()
                            ),
                            *span,
                        );
                    }
                    for (i, name) in names.iter().enumerate() {
                        let ty = types.get(i).cloned().unwrap_or(Ty::Error);
                        self.env.declare_local(&name.name, ty, l.is_mutable);
                    }
                } else if declared_ty != Ty::Unknown && declared_ty != Ty::Error {
                    self.error(
                        format!("cannot destructure non-tuple type {}", declared_ty),
                        *span,
                    );
                    for name in names {
                        self.env.declare_local(&name.name, Ty::Error, l.is_mutable);
                    }
                } else {
                    for name in names {
                        self.env
                            .declare_local(&name.name, Ty::Unknown, l.is_mutable);
                    }
                }
            }
        }
    }

    fn check_assign(&mut self, a: &AssignStmt) {
        // Check mutability — only for simple ident targets
        if let Expr::Ident(ident) = &a.target {
            if !self.env.is_mutable(&ident.name) {
                self.error(
                    format!("cannot assign to immutable variable '{}'", ident.name),
                    a.span,
                );
            }
        }

        let target_ty = self.infer_expr(&a.target);
        let value_ty = self.infer_expr(&a.value);

        if target_ty != Ty::Unknown
            && value_ty != Ty::Unknown
            && target_ty != Ty::Error
            && value_ty != Ty::Error
        {
            match a.op {
                AssignOp::Assign => {
                    // Clippy offers a De-Morgan rewrite to a single big `!(A || B || ...)`,
                    // but the chain-of-ANDs form with per-line comments is what makes
                    // the compatibility matrix readable. Keeping as-is.
                    #[allow(clippy::nonminimal_bool)]
                    let type_mismatch = target_ty != value_ty
                        && !self.is_int_literal_compatible(&a.value, &target_ty)
                        && !value_ty.can_widen_to(&target_ty)
                        && !(target_ty.is_numeric() && value_ty.is_numeric()) // allow numeric narrowing
                        && !(target_ty.is_enum() && value_ty.is_enum()) // same-kind enum assignment
                        && !(target_ty.is_numeric() && value_ty.is_enum()) // Enum → numeric
                        && !(target_ty.is_enum() && value_ty.is_numeric()) // numeric → Enum
                        && !self.is_compatible_init(&value_ty, &target_ty);
                    if type_mismatch {
                        self.error(
                            format!("type mismatch in assignment: {} = {}", target_ty, value_ty),
                            a.span,
                        );
                    }
                }
                // Compound assignments: allow widening and literal coercion
                _ => {
                    if target_ty != value_ty
                        && !self.is_int_literal_compatible(&a.value, &target_ty)
                        && !value_ty.can_widen_to(&target_ty)
                    {
                        self.error(
                            format!(
                                "type mismatch in compound assignment: {} and {}",
                                target_ty, value_ty
                            ),
                            a.span,
                        );
                    }
                    if !target_ty.is_numeric() && target_ty != Ty::Unknown && target_ty != Ty::Error
                    {
                        self.error(
                            format!(
                                "compound assignment requires numeric type, found {}",
                                target_ty
                            ),
                            a.span,
                        );
                    }
                }
            }
        }
    }

    fn check_emit(&mut self, e: &EmitStmt) {
        // Resolve qualified event name: event::Deposit → "Deposit"
        let event_name = e.event_name.last().map(|i| i.name.as_str()).unwrap_or("");
        if let Some(event_fields) = self.env.event_defs.get(event_name).cloned() {
            // Check field count
            if e.fields.len() != event_fields.len() {
                self.error(
                    format!(
                        "event '{}' expects {} fields, found {}",
                        event_name,
                        event_fields.len(),
                        e.fields.len()
                    ),
                    e.span,
                );
            }

            // Check each field
            for (i, field) in e.fields.iter().enumerate() {
                let value_ty = self.infer_expr(&field.value);
                if let Some((expected_name, expected_ty, _)) = event_fields.get(i) {
                    if field.name.name != *expected_name {
                        self.error(
                            format!(
                                "event field name mismatch: expected '{}', found '{}'",
                                expected_name, field.name.name
                            ),
                            field.span,
                        );
                    }
                    if value_ty != Ty::Unknown
                        && value_ty != Ty::Error
                        && value_ty != *expected_ty
                        && !value_ty.can_widen_to(expected_ty)
                        && !self.is_int_literal_compatible(&field.value, expected_ty)
                        && !(value_ty.is_numeric() && expected_ty.is_numeric())
                    {
                        self.error(
                            format!(
                                "event field '{}' expects {}, found {}",
                                field.name.name, expected_ty, value_ty
                            ),
                            field.span,
                        );
                    }
                }
            }
        }
        // If event not found, resolver already reported it
    }

    fn check_for(&mut self, f: &ForStmt) {
        let iter_ty = self.infer_expr(&f.iterator);
        self.env.push_scope();

        // For loop variable type is inferred from the range
        // Range of u64..u64 → loop var is u64, etc.
        let var_ty = match &iter_ty {
            Ty::Unknown | Ty::Error => Ty::U64, // default to u64 for ranges
            other => other.clone(),
        };
        self.env.declare_local(&f.variable.name, var_ty, false); // for vars are immutable

        self.check_block(&f.body);
        self.env.pop_scope();
    }

    // ========================================================================
    // Expression type inference
    // ========================================================================

    fn infer_expr(&mut self, expr: &Expr) -> Ty {
        match expr {
            Expr::Literal(lit, _) => match lit {
                Literal::Int(_) => Ty::U64, // default integer type (matches PVM GP register width)
                Literal::String(_) => Ty::StringTy,
                Literal::Bool(_) => Ty::Bool,
            },

            Expr::Ident(ident) => {
                // Look up local, then const, then storage
                if let Some(ty) = self.env.lookup_local(&ident.name) {
                    return ty.clone();
                }
                if let Some(ty) = self.env.const_defs.get(&ident.name) {
                    return ty.clone();
                }
                Ty::Unknown // resolver already validated existence
            }

            Expr::SelfExpr(_) => Ty::Unknown, // self is a reference to contract

            Expr::Binary(lhs, op, rhs, span) => {
                let lhs_ty = self.infer_expr(lhs);
                let rhs_ty = self.infer_expr(rhs);
                self.check_binary_op_full(lhs, &lhs_ty, op, rhs, &rhs_ty, *span)
            }

            Expr::Unary(op, operand, span) => {
                let ty = self.infer_expr(operand);
                match op {
                    UnaryOp::Negate => {
                        if !ty.is_numeric() && ty != Ty::Unknown && ty != Ty::Error {
                            self.error(format!("cannot negate type {}", ty), *span);
                        }
                        ty
                    }
                    UnaryOp::LogicalNot => {
                        // Allow ! on bool (logical NOT) and integers (bitwise NOT, like C)
                        if ty != Ty::Bool
                            && !ty.is_integer()
                            && ty != Ty::Unknown
                            && ty != Ty::Error
                        {
                            self.error(
                                format!("logical NOT requires bool or integer, found {}", ty),
                                *span,
                            );
                        }
                        if ty.is_integer() {
                            ty
                        } else {
                            Ty::Bool
                        }
                    }
                    UnaryOp::BitNot => {
                        if !ty.is_integer() && ty != Ty::Unknown && ty != Ty::Error {
                            self.error(
                                format!("bitwise NOT requires integer, found {}", ty),
                                *span,
                            );
                        }
                        ty
                    }
                }
            }

            Expr::FieldAccess(obj, field, span) => {
                let obj_ty = self.infer_expr(obj);
                // self.field → storage field type
                if matches!(**obj, Expr::SelfExpr(_)) {
                    if let Some(ty) = self.env.storage_fields.get(&field.name) {
                        return ty.clone();
                    }
                    // Check if it's a known function (self.method accessed as value, not called)
                    if !self.env.func_sigs.contains_key(&field.name)
                        && !self.env.storage_fields.is_empty()
                    {
                        self.error(
                            format!(
                                "'{}' is not a storage field or function in this contract",
                                field.name
                            ),
                            *span,
                        );
                        return Ty::Error;
                    }
                }
                // Address.balance → u256
                if obj_ty == Ty::Address && field.name.as_str() == "balance" {
                    return Ty::U256;
                }
                // struct.field → field type
                if let Ty::Struct(name) = &obj_ty {
                    if let Some(fields) = self.env.struct_defs.get(name) {
                        for (fname, fty) in fields {
                            if fname == &field.name {
                                return fty.clone();
                            }
                        }
                    }
                }
                Ty::Unknown // method calls, etc. — resolved by context
            }

            Expr::Index(obj, index, _) => {
                let obj_ty = self.infer_expr(obj);
                self.infer_expr(index);
                match &obj_ty {
                    Ty::Vec(elem) => *elem.clone(),
                    Ty::Map(_, val) => *val.clone(),
                    Ty::Array(elem, _) => *elem.clone(),
                    _ => Ty::Unknown,
                }
            }

            Expr::Call(callee, args, _call_value, span) => {
                // Infer all argument types
                let arg_types: Vec<Ty> = args.iter().map(|arg| self.infer_expr(arg)).collect();

                // Try to resolve the function return type and check args
                match callee.as_ref() {
                    Expr::Ident(ident) => {
                        // Built-in functions
                        if ident.name == "hash" {
                            return Ty::Array(Box::new(Ty::U8), 32);
                        }
                        if ident.name == "address" {
                            // address() accepts:
                            //   - `self` (returns this contract's address)
                            //   - an Address-typed expression (no-op, identity)
                            //   - a Contract/Interface handle (audit 405; the
                            //     handle stores a 32-byte address internally,
                            //     so coercing to Address is a register-copy
                            //     in the lowerer). Without this case, the
                            //     canonical factory pattern
                            //     `let child = deploy!(Helper); address(child)`
                            //     was rejected even though the lower pass
                            //     already emits a contract handle that IS
                            //     the deployed child's address. Pre-audit-
                            //     405 this only worked through the lax
                            //     `compile_all_unchecked` path which produced
                            //     INCORRECT bytecode (the lowerer emitted
                            //     `AddressOfSelf` for any `address(...)`
                            //     call, regardless of argument — so the
                            //     factory got its OWN address back rather
                            //     than the child's). Fixed in lower.rs.
                            if args.len() != 1 {
                                self.error("address() takes exactly one argument".into(), *span);
                            } else if let Some(arg) = args.first() {
                                let is_self = matches!(arg, Expr::SelfExpr(_));
                                let arg_ty = &arg_types[0];
                                let is_contract_or_iface =
                                    matches!(arg_ty, Ty::Contract(_) | Ty::Interface(_));
                                if !is_self
                                    && !is_contract_or_iface
                                    && *arg_ty != Ty::Address
                                    && *arg_ty != Ty::Unknown
                                    && *arg_ty != Ty::Error
                                {
                                    self.error(
                                        format!(
                                            "address() expects 'self', an Address, or a Contract/Interface handle, found {}. Use Address::ZERO for zero address",
                                            arg_ty
                                        ),
                                        *span,
                                    );
                                }
                            }
                            return Ty::Address;
                        }
                        // sig_verify(message, signature, public_key) → bool
                        if ident.name == "sig_verify" {
                            if arg_types.len() != 3 {
                                self.error(
                                    format!("sig_verify() takes 3 arguments (message, signature, public_key), found {}", arg_types.len()),
                                    *span,
                                );
                            }
                            return Ty::Bool;
                        }
                        // sig_recover(message, signature) → Address
                        if ident.name == "sig_recover" {
                            if arg_types.len() != 2 {
                                self.error(
                                    format!("sig_recover() takes 2 arguments (message, signature), found {}", arg_types.len()),
                                    *span,
                                );
                            }
                            return Ty::Address;
                        }
                        // gas_remaining() → u64
                        if ident.name == "gas_remaining" {
                            return Ty::U64;
                        }
                        // bytes() constructor → bytes
                        if ident.name == "bytes" {
                            return Ty::Bytes;
                        }
                        // Local function — check args
                        if let Some((params, ret)) = self.env.func_sigs.get(&ident.name).cloned() {
                            self.check_call_args(&ident.name, &params, &arg_types, args, *span);
                            return ret;
                        }
                        Ty::Unknown
                    }
                    Expr::FieldAccess(obj, method, _) => {
                        let obj_ty = self.infer_expr(obj);
                        // self.method() → function return type + arg check
                        if matches!(**obj, Expr::SelfExpr(_)) {
                            if let Some((params, ret)) =
                                self.env.func_sigs.get(&method.name).cloned()
                            {
                                self.check_call_args(
                                    &method.name,
                                    &params,
                                    &arg_types,
                                    args,
                                    *span,
                                );
                                return ret;
                            }
                        }
                        // Common method return types
                        let is_math_method = matches!(
                            method.name.as_str(),
                            "sqrt"
                                | "pow"
                                | "min"
                                | "max"
                                | "clamp"
                                | "mul_div"
                                | "checked_add"
                                | "checked_sub"
                                | "saturating_add"
                                | "saturating_sub"
                                | "wrapping_add"
                                | "wrapping_sub"
                        );

                        // Math methods only work on numeric types
                        if is_math_method {
                            if !obj_ty.is_numeric() && obj_ty != Ty::Unknown && obj_ty != Ty::Error
                            {
                                self.error(
                                    format!(
                                        "'{}' can only be called on numeric types, found {}",
                                        method.name, obj_ty
                                    ),
                                    *span,
                                );
                                return Ty::Error;
                            }
                            return obj_ty;
                        }

                        match method.name.as_str() {
                            // len() → u64 — only on Vec, Map, Array, String, bytes
                            "len" => {
                                let valid = matches!(
                                    obj_ty,
                                    Ty::Vec(_)
                                        | Ty::Map(_, _)
                                        | Ty::Array(_, _)
                                        | Ty::StringTy
                                        | Ty::Bytes
                                        | Ty::Unknown
                                        | Ty::Error
                                );
                                if !valid {
                                    self.error(
                                        format!("'len' can only be called on collections, String, or bytes, found {}", obj_ty),
                                        *span,
                                    );
                                }
                                Ty::U64
                            }
                            // push/pop → Unit — only on Vec
                            "push" | "pop" => {
                                if !matches!(obj_ty, Ty::Vec(_) | Ty::Unknown | Ty::Error) {
                                    self.error(
                                        format!(
                                            "'{}' can only be called on Vec, found {}",
                                            method.name, obj_ty
                                        ),
                                        *span,
                                    );
                                }
                                Ty::Unit
                            }
                            // is_empty() → bool — on Vec, Map, String, bytes
                            "is_empty" => {
                                let valid = matches!(
                                    obj_ty,
                                    Ty::Vec(_)
                                        | Ty::Map(_, _)
                                        | Ty::StringTy
                                        | Ty::Bytes
                                        | Ty::Unknown
                                        | Ty::Error
                                );
                                if !valid {
                                    self.error(
                                        format!("'is_empty' can only be called on collections, String, or bytes, found {}", obj_ty),
                                        *span,
                                    );
                                }
                                Ty::Bool
                            }
                            // concat() → same type — only on String or bytes
                            "concat" => {
                                if obj_ty != Ty::StringTy
                                    && obj_ty != Ty::Bytes
                                    && obj_ty != Ty::Unknown
                                    && obj_ty != Ty::Error
                                {
                                    self.error(
                                        format!("'concat' can only be called on String or bytes, found {}", obj_ty),
                                        *span,
                                    );
                                }
                                obj_ty
                            }
                            // as_bytes/to_bytes → bytes — on String, Address, numeric types
                            "as_bytes" | "to_bytes" => {
                                let valid = matches!(
                                    obj_ty,
                                    Ty::StringTy
                                        | Ty::Address
                                        | Ty::Bytes
                                        | Ty::Unknown
                                        | Ty::Error
                                ) || obj_ty.is_numeric();
                                if !valid {
                                    self.error(
                                        format!("'{}' can only be called on String, Address, or numeric types, found {}", method.name, obj_ty),
                                        *span,
                                    );
                                }
                                Ty::Bytes
                            }
                            // append() → Unit — only on bytes or Vec
                            "append" => {
                                if !matches!(
                                    obj_ty,
                                    Ty::Bytes | Ty::Vec(_) | Ty::Unknown | Ty::Error
                                ) {
                                    self.error(
                                        format!(
                                            "'append' can only be called on bytes or Vec, found {}",
                                            obj_ty
                                        ),
                                        *span,
                                    );
                                }
                                Ty::Unit
                            }
                            // Unknown method — error only for primitives where we know all methods
                            _ => {
                                let is_primitive =
                                    obj_ty.is_numeric() || matches!(obj_ty, Ty::Bool | Ty::Address);
                                if is_primitive {
                                    self.error(
                                        format!("type {} has no method '{}'", obj_ty, method.name),
                                        *span,
                                    );
                                    Ty::Error
                                } else {
                                    // String, bytes, Vec, Map, Array, Struct, Enum, Unknown
                                    // — could be library-extended, user-defined, or cross-contract
                                    Ty::Unknown
                                }
                            }
                        }
                    }
                    Expr::Path(segments, _) => {
                        if segments.len() == 2 {
                            match (segments[0].name.as_str(), segments[1].name.as_str()) {
                                // Constructors
                                ("Vec", "new") => Ty::Vec(Box::new(Ty::Unknown)),
                                ("bytes", "new" | "empty" | "from_hex") => Ty::Bytes,
                                ("String", "new") => Ty::StringTy,
                                // Interface::at(addr) → callable handle
                                (_, "at") => Ty::Unknown,
                                // std::signature module
                                ("signature", "verify") => Ty::Bool,
                                ("signature", "recover") => Ty::Address,
                                // std::hash module (explicit forms)
                                ("hash", "poseidon2" | "poseidon2_pair" | "poseidon2_many") => {
                                    Ty::Array(Box::new(Ty::U8), 32)
                                }
                                // Module function calls default to Unknown
                                _ => Ty::Unknown,
                            }
                        } else {
                            Ty::Unknown
                        }
                    }
                    _ => Ty::Unknown,
                }
            }

            Expr::Path(segments, _) => {
                if segments.len() == 2 {
                    // EnumName::Variant → Enum type
                    if self.env.enum_defs.contains_key(&segments[0].name) {
                        return Ty::Enum(segments[0].name.clone());
                    }
                    // Address::ZERO
                    if segments[0].name == "Address" && segments[1].name == "ZERO" {
                        return Ty::Address;
                    }
                }
                Ty::Unknown
            }

            Expr::MacroCall(name, args, span) => {
                // Infer all arg types
                let mut arg_types = Vec::new();
                for arg in args {
                    match arg {
                        MacroArg::Positional(expr) => {
                            arg_types.push(self.infer_expr(expr));
                        }
                        MacroArg::Named(_, expr) => {
                            arg_types.push(self.infer_expr(expr));
                        }
                    }
                }

                // Validate macro-specific arg types
                match name.name.as_str() {
                    "require" => {
                        // require!(condition, error) — first arg must be bool
                        if let Some(cond_ty) = arg_types.first() {
                            if *cond_ty != Ty::Bool
                                && *cond_ty != Ty::Unknown
                                && *cond_ty != Ty::Error
                            {
                                self.error(
                                    format!("require! condition must be bool, found {}", cond_ty),
                                    *span,
                                );
                            }
                        }
                        Ty::Unit
                    }
                    "revert" | "cross_call" => Ty::Unit,
                    "raw_call" => Ty::Unknown,
                    "deploy" | "create" => {
                        // deploy!(ContractName, args...) → Ty::Contract("ContractName")
                        // First arg is the contract name (path expression).
                        if let Some(MacroArg::Positional(first)) = args.first() {
                            let contract_name_opt = if let Expr::Path(segments, _) = first {
                                Some(
                                    segments
                                        .iter()
                                        .map(|s| s.name.as_str())
                                        .collect::<Vec<_>>()
                                        .join("::"),
                                )
                            } else if let Expr::Ident(ident) = first {
                                Some(ident.name.clone())
                            } else {
                                None
                            };
                            if let Some(contract_name) = contract_name_opt {
                                // Validate constructor args (count + types)
                                let user_arg_types = &arg_types[1..]; // skip contract name
                                let ctor_params =
                                    self.env.contract_constructors.get(&contract_name).cloned();
                                if let Some(ref params) = ctor_params {
                                    if user_arg_types.len() != params.len() {
                                        self.error(
                                            format!(
                                                "deploy!: {}() constructor expects {} args, got {}",
                                                contract_name,
                                                params.len(),
                                                user_arg_types.len()
                                            ),
                                            *span,
                                        );
                                    } else {
                                        // Check each arg type
                                        for ((_param_name, param_ty), arg_ty) in
                                            params.iter().zip(user_arg_types.iter())
                                        {
                                            if *arg_ty != Ty::Unknown
                                                && *arg_ty != Ty::Error
                                                && *param_ty != Ty::Unknown
                                                && *arg_ty != *param_ty
                                                && !arg_ty.can_widen_to(param_ty)
                                                && !(arg_ty.is_numeric() && param_ty.is_numeric())
                                            {
                                                self.error(
                                                    format!(
                                                        "deploy!: {}() arg '{}' expects {}, got {}",
                                                        contract_name,
                                                        _param_name,
                                                        param_ty,
                                                        arg_ty
                                                    ),
                                                    *span,
                                                );
                                            }
                                        }
                                    }
                                } else if !user_arg_types.is_empty()
                                    && self.env.contract_names.contains(&contract_name)
                                {
                                    // Known contract with no constructor but args provided
                                    self.error(
                                        format!(
                                            "deploy!: {} has no constructor, but {} args provided",
                                            contract_name,
                                            user_arg_types.len()
                                        ),
                                        *span,
                                    );
                                }
                                // For imported contracts not in contract_names, skip validation
                                // (constructor signature unknown until build pipeline provides it)

                                Ty::Contract(contract_name)
                            } else {
                                self.error(
                                    "deploy! first argument must be a contract name".into(),
                                    *span,
                                );
                                Ty::Address
                            }
                        } else {
                            self.error("deploy! requires a contract name argument".into(), *span);
                            Ty::Address
                        }
                    }
                    _ => Ty::Unknown,
                }
            }

            Expr::StructInit(name_segments, fields, _span) => {
                let struct_name = name_segments.first().map(|s| s.name.as_str()).unwrap_or("");

                // Check if it's a struct init or error init
                if let Some(struct_fields) = self.env.struct_defs.get(struct_name).cloned() {
                    for field in fields {
                        let value_ty = self.infer_expr(&field.value);
                        if let Some((_, expected_ty)) = struct_fields
                            .iter()
                            .find(|(name, _)| name == &field.name.name)
                        {
                            if value_ty != Ty::Unknown
                                && value_ty != Ty::Error
                                && *expected_ty != Ty::Unknown
                                && *expected_ty != Ty::Error
                                && value_ty != *expected_ty
                                && !self.is_int_literal_compatible(&field.value, expected_ty)
                                && !value_ty.can_widen_to(expected_ty)
                                && !self.is_compatible_init(&value_ty, expected_ty)
                                && !(value_ty.is_numeric() && expected_ty.is_numeric())
                            // allow numeric narrowing (runtime checked)
                            {
                                self.error(
                                    format!(
                                        "struct field '{}' expects {}, found {}",
                                        field.name.name, expected_ty, value_ty
                                    ),
                                    field.span,
                                );
                            }
                        }
                    }
                    Ty::Struct(struct_name.to_string())
                } else if self.env.error_defs.contains_key(struct_name) {
                    for field in fields {
                        self.infer_expr(&field.value);
                    }
                    Ty::Struct(struct_name.to_string())
                } else {
                    for field in fields {
                        self.infer_expr(&field.value);
                    }
                    Ty::Unknown
                }
            }

            Expr::If(cond, then_block, else_clause, span) => {
                let cond_ty = self.infer_expr(cond);
                if cond_ty != Ty::Bool && cond_ty != Ty::Unknown && cond_ty != Ty::Error {
                    self.error(
                        format!("if condition must be bool, found {}", cond_ty),
                        *span,
                    );
                }

                self.env.push_scope();
                for stmt in &then_block.stmts {
                    self.check_stmt(stmt);
                }
                self.env.pop_scope();

                if let Some(clause) = else_clause {
                    match clause {
                        ElseClause::ElseBlock(block) => {
                            self.env.push_scope();
                            for stmt in &block.stmts {
                                self.check_stmt(stmt);
                            }
                            self.env.pop_scope();
                        }
                        ElseClause::ElseIf(else_if) => {
                            self.infer_expr(else_if);
                        }
                    }
                }
                Ty::Unknown // if as expression type needs more analysis
            }

            Expr::Match(scrutinee, arms, span) => {
                let scrut_ty = self.infer_expr(scrutinee);

                for arm in arms {
                    self.check_pattern(&arm.pattern, &scrut_ty);
                    self.infer_expr(&arm.body);
                }

                // Check match exhaustiveness for enums
                if let Ty::Enum(enum_name) = &scrut_ty {
                    self.check_match_exhaustiveness(enum_name, arms, *span);
                }

                Ty::Unknown
            }

            Expr::Block(block) => {
                self.env.push_scope();
                for stmt in &block.stmts {
                    self.check_stmt(stmt);
                }
                self.env.pop_scope();
                Ty::Unknown
            }

            Expr::Cast(expr, target_ty, span) => {
                let source_ty = self.infer_expr(expr);
                // Audit 354: `expr as i64` is the other body-level
                // doorway for signed types. The upfront reject pass
                // doesn't visit expressions, so a contract that
                // wrote `let x = (a as i64)` (or `(a as i64) + 1`,
                // with no `let` annotation at all) would route a
                // signed `Ty` straight through codegen.
                self.reject_signed_in_type(target_ty);
                let target = self.resolve_type(target_ty);

                // Validate cast compatibility
                if source_ty != Ty::Unknown
                    && source_ty != Ty::Error
                    && target != Ty::Unknown
                    && target != Ty::Error
                {
                    let valid = match (&source_ty, &target) {
                        // numeric → numeric (any direction)
                        (s, t) if s.is_numeric() && t.is_numeric() => true,
                        // bool ↔ numeric
                        (Ty::Bool, t) if t.is_numeric() => true,
                        (s, Ty::Bool) if s.is_numeric() => true,
                        // numeric ↔ Address
                        (s, Ty::Address) if s.is_numeric() => true,
                        (Ty::Address, t) if t.is_numeric() => true,
                        // enum ↔ numeric (discriminant cast)
                        (Ty::Enum(_), t) if t.is_numeric() => true,
                        (s, Ty::Enum(_)) if s.is_numeric() => true,
                        // Contract/Interface → Address (strip type info)
                        (Ty::Contract(_), Ty::Address) => true,
                        (Ty::Interface(_), Ty::Address) => true,
                        // Address → Contract/Interface (wrap with type info)
                        (Ty::Address, Ty::Contract(_)) => true,
                        (Ty::Address, Ty::Interface(_)) => true,
                        // Contract/Interface ↔ Contract/Interface (re-cast)
                        (Ty::Contract(_), Ty::Contract(_)) => true,
                        (Ty::Interface(_), Ty::Interface(_)) => true,
                        (Ty::Contract(_), Ty::Interface(_)) => true,
                        (Ty::Interface(_), Ty::Contract(_)) => true,
                        // same type (identity cast)
                        (s, t) if s == t => true,
                        _ => false,
                    };
                    if !valid {
                        self.error(format!("cannot cast {} to {}", source_ty, target), *span);
                    }
                }
                target
            }

            Expr::Tuple(elements, _) => {
                let types: Vec<Ty> = elements.iter().map(|e| self.infer_expr(e)).collect();
                Ty::Tuple(types)
            }

            Expr::ArrayRepeat(value, size, _) => {
                let elem_ty = self.infer_expr(value);
                Ty::Array(Box::new(elem_ty), *size)
            }

            Expr::ArrayLiteral(elements, span) => {
                if elements.is_empty() {
                    return Ty::Array(Box::new(Ty::Unknown), 0);
                }
                let first_ty = self.infer_expr(&elements[0]);
                for (i, elem) in elements.iter().enumerate().skip(1) {
                    let elem_ty = self.infer_expr(elem);
                    if elem_ty != first_ty && elem_ty != Ty::Unknown && first_ty != Ty::Unknown {
                        self.error(
                            format!(
                                "array element {} has type {}, expected {}",
                                i, elem_ty, first_ty
                            ),
                            *span,
                        );
                    }
                }
                Ty::Array(Box::new(first_ty), elements.len() as u64)
            }

            Expr::Try(inner, _) => {
                self.infer_expr(inner);
                Ty::Unknown // try wraps in Result-like
            }
        }
    }

    fn check_binary_op_full(
        &mut self,
        lhs_expr: &Expr,
        lhs: &Ty,
        op: &BinaryOp,
        rhs_expr: &Expr,
        rhs: &Ty,
        span: Span,
    ) -> Ty {
        // Error/Unknown propagation
        if matches!(lhs, Ty::Error | Ty::Unknown) || matches!(rhs, Ty::Error | Ty::Unknown) {
            return match op {
                BinaryOp::Eq
                | BinaryOp::NotEq
                | BinaryOp::Lt
                | BinaryOp::Gt
                | BinaryOp::LtEq
                | BinaryOp::GtEq
                | BinaryOp::LogicalAnd
                | BinaryOp::LogicalOr => Ty::Bool,
                BinaryOp::Range => Ty::Unknown,
                _ => {
                    if *lhs != Ty::Unknown && *lhs != Ty::Error {
                        lhs.clone()
                    } else {
                        rhs.clone()
                    }
                }
            };
        }

        // Integer literal coercion: if one side is a literal and the other is a
        // concrete numeric type, the literal adapts to the concrete type.
        let (lhs, rhs) = self.coerce_numeric_pair(lhs_expr, lhs, rhs_expr, rhs);

        match op {
            // Arithmetic: both same numeric type → same type
            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => {
                if lhs == Ty::StringTy || rhs == Ty::StringTy {
                    self.error(
                        "cannot use '+' on strings — use .concat() instead".into(),
                        span,
                    );
                    return Ty::Error;
                }
                if lhs == Ty::Bytes || rhs == Ty::Bytes {
                    self.error(
                        "cannot use arithmetic on bytes — use .append() instead".into(),
                        span,
                    );
                    return Ty::Error;
                }
                if !lhs.is_numeric() {
                    self.error(
                        format!("arithmetic requires numeric type, found {}", lhs),
                        span,
                    );
                    return Ty::Error;
                }
                if lhs != rhs {
                    self.error(
                        format!("type mismatch in arithmetic: {} and {}", lhs, rhs),
                        span,
                    );
                }
                lhs
            }

            // Bitwise: both same integer type → same type
            BinaryOp::BitAnd
            | BinaryOp::BitOr
            | BinaryOp::BitXor
            | BinaryOp::Shl
            | BinaryOp::Shr => {
                if !lhs.is_integer() {
                    self.error(
                        format!("bitwise op requires integer type, found {}", lhs),
                        span,
                    );
                    return Ty::Error;
                }
                if lhs != rhs {
                    self.error(
                        format!("type mismatch in bitwise op: {} and {}", lhs, rhs),
                        span,
                    );
                }
                lhs
            }

            // Comparison: compatible types → bool
            BinaryOp::Eq
            | BinaryOp::NotEq
            | BinaryOp::Lt
            | BinaryOp::Gt
            | BinaryOp::LtEq
            | BinaryOp::GtEq => {
                if !lhs.is_comparable_with(&rhs) {
                    self.error(format!("cannot compare {} with {}", lhs, rhs), span);
                }
                Ty::Bool
            }

            // Logical: both bool → bool
            BinaryOp::LogicalAnd | BinaryOp::LogicalOr => {
                if lhs != Ty::Bool {
                    self.error(format!("logical op requires bool, found {}", lhs), span);
                }
                if rhs != Ty::Bool {
                    self.error(format!("logical op requires bool, found {}", rhs), span);
                }
                Ty::Bool
            }

            // Range: numeric → range (used in for loops)
            BinaryOp::Range => Ty::Unknown,
        }
    }

    /// Coerce numeric types to a common type for binary operations.
    /// Rules:
    /// 1. Integer literals adapt to the other operand's concrete type
    /// 2. Implicit widening: smaller → larger (u64 + u256 → u256)
    /// 3. Same signedness required (no implicit signed/unsigned mixing)
    fn coerce_numeric_pair(
        &self,
        lhs_expr: &Expr,
        lhs: &Ty,
        rhs_expr: &Expr,
        rhs: &Ty,
    ) -> (Ty, Ty) {
        if lhs == rhs {
            return (lhs.clone(), rhs.clone());
        }

        // If LHS is a literal and RHS is concrete numeric, adapt LHS
        if self.is_int_literal_compatible(lhs_expr, rhs) && rhs.is_numeric() {
            return (rhs.clone(), rhs.clone());
        }
        // If RHS is a literal and LHS is concrete numeric, adapt RHS
        if self.is_int_literal_compatible(rhs_expr, lhs) && lhs.is_numeric() {
            return (lhs.clone(), lhs.clone());
        }

        // Implicit widening: promote the smaller type to the larger
        if lhs.is_numeric() && rhs.is_numeric() {
            if lhs.can_widen_to(rhs) {
                return (rhs.clone(), rhs.clone());
            }
            if rhs.can_widen_to(lhs) {
                return (lhs.clone(), lhs.clone());
            }
        }

        (lhs.clone(), rhs.clone())
    }

    /// Check function call arguments against parameter types.
    fn check_call_args(
        &mut self,
        func_name: &str,
        params: &[(String, Ty)],
        arg_types: &[Ty],
        arg_exprs: &[Expr],
        span: Span,
    ) {
        if arg_types.len() != params.len() {
            self.error(
                format!(
                    "'{}' expects {} arguments, found {}",
                    func_name,
                    params.len(),
                    arg_types.len()
                ),
                span,
            );
            return;
        }

        for (i, ((param_name, param_ty), arg_ty)) in params.iter().zip(arg_types.iter()).enumerate()
        {
            if *arg_ty != Ty::Unknown
                && *arg_ty != Ty::Error
                && *param_ty != Ty::Unknown
                && *arg_ty != *param_ty
                && !arg_ty.can_widen_to(param_ty)
                && !(arg_ty.is_numeric() && param_ty.is_numeric())
                && !self.is_compatible_init(arg_ty, param_ty)
            {
                // Also check if the arg is a literal that can adapt
                let is_literal = arg_exprs
                    .get(i)
                    .map(|e| self.is_int_literal_compatible(e, param_ty))
                    .unwrap_or(false);
                if !is_literal {
                    self.error(
                        format!(
                            "argument '{}' expects {}, found {}",
                            param_name, param_ty, arg_ty
                        ),
                        span,
                    );
                }
            }
        }
    }

    /// Check that a match on an enum covers all variants (or has a wildcard).
    fn check_match_exhaustiveness(&mut self, enum_name: &str, arms: &[MatchArm], span: Span) {
        // If there's a wildcard pattern, it's exhaustive
        let has_wildcard = arms
            .iter()
            .any(|a| matches!(a.pattern, Pattern::Wildcard(_)));
        if has_wildcard {
            return;
        }

        // Get enum variants
        if let Some(variants) = self.env.enum_defs.get(enum_name) {
            let covered: std::collections::HashSet<String> = arms
                .iter()
                .filter_map(|a| {
                    if let Pattern::Path(segments, _) = &a.pattern {
                        segments.last().map(|s| s.name.clone())
                    } else {
                        None
                    }
                })
                .collect();

            let missing: Vec<&String> = variants.iter().filter(|v| !covered.contains(*v)).collect();

            if !missing.is_empty() {
                let missing_str = missing
                    .iter()
                    .map(|v| format!("{}::{}", enum_name, v))
                    .collect::<Vec<_>>()
                    .join(", ");
                self.error(
                    format!(
                        "non-exhaustive match: missing variants {}. Add them or use _ wildcard",
                        missing_str
                    ),
                    span,
                );
            }
        }
    }

    fn check_pattern(&mut self, pattern: &Pattern, scrutinee_ty: &Ty) {
        match pattern {
            Pattern::Path(segments, span) => {
                // Enum variant pattern — check it matches the scrutinee's enum
                if segments.len() >= 2 {
                    if let Ty::Enum(enum_name) = scrutinee_ty {
                        if segments[0].name != *enum_name {
                            self.error(
                                format!(
                                    "pattern enum '{}' doesn't match scrutinee enum '{}'",
                                    segments[0].name, enum_name
                                ),
                                *span,
                            );
                        }
                    }
                }
            }
            Pattern::Literal(_, _) | Pattern::Range(_, _, _) | Pattern::Wildcard(_) => {}
        }
    }
}

/// Result of type checking.
pub struct TypeCheckResult {
    pub errors: Vec<TypeError>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;
    use crate::parser::Parser;

    fn typecheck(src: &str) -> Vec<TypeError> {
        let (tokens, lex_errors) = Lexer::new(src).tokenize();
        assert!(lex_errors.is_empty(), "lex errors: {:?}", lex_errors);
        let (file, parse_errors) = Parser::new(tokens).parse();
        assert!(parse_errors.is_empty(), "parse errors: {:?}", parse_errors);
        TypeChecker::new().check(&file).errors
    }

    fn check_ok(src: &str) {
        let errors = typecheck(src);
        assert!(errors.is_empty(), "type errors: {:?}", errors);
    }

    fn check_err(src: &str) -> Vec<TypeError> {
        let errors = typecheck(src);
        assert!(!errors.is_empty(), "expected type errors but got none");
        errors
    }

    // ========== Basic type checking ==========

    #[test]
    fn check_simple_contract() {
        check_ok(
            r#"
            contract Token {
                storage { supply: u256, }
                #[constructor]
                pub fn init(supply: u256) {
                    self.supply = supply;
                }
                #[view]
                pub fn get_supply() -> u256 {
                    return self.supply;
                }
            }
        "#,
        );
    }

    #[test]
    fn check_arithmetic_same_type() {
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    let a: u256 = 10;
                    let b: u256 = 20;
                    let c = a + b;
                }
            }
        "#,
        );
    }

    #[test]
    fn check_boolean_logic() {
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    let a = true;
                    let b = false;
                    let c = a && b;
                    let d = a || !b;
                }
            }
        "#,
        );
    }

    #[test]
    fn check_comparison_returns_bool() {
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    let a: u256 = 10;
                    let b: u256 = 20;
                    let c = a > b;
                    if c {
                        let x = 1;
                    }
                }
            }
        "#,
        );
    }

    #[test]
    fn check_struct_init() {
        check_ok(
            r#"
            contract T {
                struct Point { x: u64, y: u64 }
                pub fn f() {
                    let p = Point { x: 1, y: 2 };
                }
            }
        "#,
        );
    }

    #[test]
    fn check_enum_pattern() {
        check_ok(
            r#"
            contract T {
                enum Status { Active, Paused }
                pub fn f() {
                    let s = Status::Active;
                    match s {
                        Status::Active => { let x = 1; },
                        Status::Paused => { let x = 2; },
                        _ => { let x = 3; },
                    }
                }
            }
        "#,
        );
    }

    #[test]
    fn check_event_emit() {
        check_ok(
            r#"
            contract T {
                event Transfer { from: Address, to: Address, amount: u256, }
                pub fn f() {
                    emit Transfer { from: msg.sender, to: msg.sender, amount: 100 };
                }
            }
        "#,
        );
    }

    #[test]
    fn check_tuple_destructuring() {
        check_ok(
            r#"
            contract T {
                pub fn get_pair() -> (u64, u64) {
                    return (1, 2);
                }
                pub fn f() {
                    let (a, b) = self.get_pair();
                }
            }
        "#,
        );
    }

    #[test]
    fn check_cast_expression() {
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    let a: u64 = 42;
                    let b = a as u256;
                }
            }
        "#,
        );
    }

    #[test]
    fn check_array_literal() {
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    let arr = [1, 2, 3];
                }
            }
        "#,
        );
    }

    #[test]
    fn check_hash_builtin() {
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    let h = hash(42);
                }
            }
        "#,
        );
    }

    #[test]
    fn check_for_loop() {
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    for i in 0..10 {
                        let x = i;
                    }
                }
            }
        "#,
        );
    }

    // ========== Type errors ==========

    #[test]
    fn error_if_condition_not_bool() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    if 42 {
                        let x = 1;
                    }
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("if condition must be bool"));
    }

    #[test]
    fn error_while_condition_not_bool() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    while 42 {
                        let x = 1;
                    }
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("while condition must be bool"));
    }

    #[test]
    fn logical_not_on_int_is_allowed() {
        // ! on integers is bitwise NOT (like C), returns same type
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    let x = !42;
                }
            }
        "#,
        );
    }

    #[test]
    fn error_logical_not_on_string() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    let x = !"hello";
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("logical NOT requires bool or integer"));
    }

    #[test]
    fn error_wrong_event_field_count() {
        let errors = check_err(
            r#"
            contract T {
                event Transfer { from: Address, to: Address, amount: u256, }
                pub fn f() {
                    emit Transfer { from: msg.sender };
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("expects 3 fields, found 1"));
    }

    // ========== Return type validation ==========

    #[test]
    fn check_return_type_correct() {
        check_ok(
            r#"
            contract T {
                pub fn f() -> u256 {
                    return 42;
                }
            }
        "#,
        );
    }

    #[test]
    fn error_return_type_mismatch() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() -> u256 {
                    return "hello";
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("return type mismatch"));
    }

    #[test]
    fn check_return_type_widening() {
        // u64 returned for u256 function — widening is ok
        check_ok(
            r#"
            contract T {
                storage { count: u64, }
                pub fn f() -> u256 {
                    return self.count;
                }
            }
        "#,
        );
    }

    // ========== Function call argument validation ==========

    #[test]
    fn error_wrong_argument_count() {
        let errors = check_err(
            r#"
            contract T {
                fn helper(x: u256, y: u256) {}
                pub fn f() {
                    self.helper(1);
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("expects 2 arguments, found 1"));
    }

    #[test]
    fn error_wrong_argument_type() {
        let errors = check_err(
            r#"
            contract T {
                fn helper(x: u256) {}
                pub fn f() {
                    self.helper("hello");
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("argument 'x' expects u256, found String"));
    }

    #[test]
    fn check_argument_widening() {
        // u64 arg for u256 param — ok
        check_ok(
            r#"
            contract T {
                storage { count: u64, }
                fn helper(x: u256) {}
                pub fn f() {
                    self.helper(self.count);
                }
            }
        "#,
        );
    }

    #[test]
    fn check_argument_literal() {
        // Literal adapts to param type
        check_ok(
            r#"
            contract T {
                fn helper(x: u64) {}
                pub fn f() {
                    self.helper(42);
                }
            }
        "#,
        );
    }

    // ========== Mutability checking ==========

    #[test]
    fn check_mutable_assignment() {
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    let mut x = 1;
                    x = 2;
                }
            }
        "#,
        );
    }

    #[test]
    fn error_immutable_assignment() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    let x = 1;
                    x = 2;
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("cannot assign to immutable variable 'x'"));
    }

    #[test]
    fn check_compound_mutable_assignment() {
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    let mut count = 0;
                    count += 1;
                }
            }
        "#,
        );
    }

    #[test]
    fn error_immutable_compound_assignment() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    let count = 0;
                    count += 1;
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("cannot assign to immutable variable 'count'"));
    }

    // ========== require! condition checking ==========

    #[test]
    fn check_require_bool_condition() {
        check_ok(
            r#"
            contract T {
                error Fail {}
                pub fn f() {
                    require!(true, Fail {});
                }
            }
        "#,
        );
    }

    #[test]
    fn error_require_non_bool_condition() {
        let errors = check_err(
            r#"
            contract T {
                error Fail {}
                pub fn f() {
                    require!(42, Fail {});
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("require! condition must be bool"));
    }

    // ========== Void function returning value ==========

    #[test]
    fn check_void_function_no_return() {
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    let x = 1;
                }
            }
        "#,
        );
    }

    #[test]
    fn error_void_function_returning_value() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    return 42;
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("function does not return a value"));
    }

    // ========== String concat error ==========

    #[test]
    fn error_string_plus_operator() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    let x = "hello" + "world";
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("use .concat() instead"));
    }

    // ========== Math method type enforcement ==========

    #[test]
    fn error_sqrt_on_string() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    let x = "hello".sqrt();
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("can only be called on numeric types"));
    }

    #[test]
    fn error_pow_on_bool() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    let x = true.pow(3);
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("can only be called on numeric types"));
    }

    #[test]
    fn check_sqrt_on_u256() {
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    let x: u256 = 100;
                    let root = x.sqrt();
                }
            }
        "#,
        );
    }

    #[test]
    fn error_concat_on_number() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    let x: u256 = 100;
                    let y = x.concat(200);
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("can only be called on String or bytes"));
    }

    #[test]
    fn error_push_on_string() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    let s = "hello";
                    s.push("x");
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("'push' can only be called on Vec"));
    }

    #[test]
    fn error_len_on_number() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    let x: u256 = 100;
                    let n = x.len();
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("'len' can only be called on collections"));
    }

    #[test]
    fn error_is_empty_on_number() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    let x: u256 = 100;
                    let b = x.is_empty();
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("'is_empty' can only be called on collections"));
    }

    #[test]
    fn error_append_on_string() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    let s = "hello";
                    s.append("x");
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("'append' can only be called on bytes or Vec"));
    }

    // ========== address() enforcement ==========

    #[test]
    fn check_address_self() {
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    let addr = address(self);
                }
            }
        "#,
        );
    }

    #[test]
    fn error_address_integer() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    let addr = address(0);
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("expects 'self'"));
    }

    #[test]
    fn error_address_string() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    let addr = address("hello");
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("expects 'self'"));
    }

    #[test]
    fn check_address_of_address_var() {
        // Passing an Address variable is fine (identity)
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    let sender = msg.sender;
                    let addr = address(sender);
                }
            }
        "#,
        );
    }

    /// Audit 405 regression: `address(<contract handle>)` must
    /// typecheck. Pre-fix the canonical factory pattern
    /// (`let child = deploy!(Helper); let a = address(child);`)
    /// was rejected with "expects 'self' or an Address" even though
    /// the lowerer already produced a 32-byte address handle for
    /// the deploy!() result. The lax compile path silently let it
    /// through and generated WRONG bytecode (the factory got its
    /// own address back instead of the child's).
    #[test]
    fn check_address_of_contract_handle_audit_405() {
        // TPL-209 forced the `Vec<Address>` storage out of the
        // original test (silent stride-truncation for Address).
        // Audit-405's claim is about `address(c)` returning the
        // CHILD's address, not the parent's, so a single
        // `last_child: Address` slot is sufficient.
        check_ok(
            r#"
            contract Child {
                #[constructor]
                pub fn init() {}
            }
            contract Parent {
                storage {
                    last_child: Address,
                }
                #[constructor]
                pub fn init() {}
                pub fn spawn() -> Address {
                    let c = deploy!(Child);
                    let a = address(c);
                    self.last_child = a;
                    return a;
                }
            }
        "#,
        );
    }

    // ========== Std import function validation ==========

    #[test]
    fn check_imported_sqrt_correct_args() {
        check_ok(
            r#"
            use std::math::sqrt;
            contract T {
                pub fn f() {
                    let x = sqrt(100);
                }
            }
        "#,
        );
    }

    #[test]
    fn error_imported_sqrt_wrong_type() {
        let errors = check_err(
            r#"
            use std::math::sqrt;
            contract T {
                pub fn f() {
                    let x = sqrt("hello");
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("argument 'x' expects u256, found String"));
    }

    #[test]
    fn error_imported_sqrt_wrong_count() {
        let errors = check_err(
            r#"
            use std::math::sqrt;
            contract T {
                pub fn f() {
                    let x = sqrt(1, 2);
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("expects 1 arguments, found 2"));
    }

    #[test]
    fn check_imported_verify_correct() {
        check_ok(
            r#"
            use std::signature::verify;
            contract T {
                pub fn f() {
                    let msg_hash: [u8; 32] = [0; 32];
                    let sig: bytes = bytes("");
                    let pk: bytes = bytes("");
                    let valid = verify(msg_hash, sig, pk);
                }
            }
        "#,
        );
    }

    #[test]
    fn check_grouped_import_validation() {
        check_ok(
            r#"
            use std::math::{sqrt, pow};
            contract T {
                pub fn f() {
                    let a = sqrt(100);
                    let b = pow(2, 10);
                }
            }
        "#,
        );
    }

    // ========== Cast validation ==========

    #[test]
    fn check_valid_casts() {
        // TPL-208: `as i64` was a valid-cast positive case here
        // before audit-354 plugged the body-level signed-type
        // gap. Casts to signed targets are now rejected (the
        // signed-cast path has its own `audit_354_rejects_cast_to_signed`
        // test); this case stays as the unsigned-only happy path.
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    let a: u64 = 42;
                    let b = a as u256;
                    let c = b as u64;
                    let d = a as u32;
                    let e = true as u256;
                }
            }
        "#,
        );
    }

    #[test]
    fn error_cast_string_to_int() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    let x = "hello" as u256;
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("cannot cast String to u256"));
    }

    #[test]
    fn error_cast_bool_to_string() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() {
                    let x = true as String;
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("cannot cast bool to String"));
    }

    // ========== Match exhaustiveness ==========

    #[test]
    fn check_exhaustive_match_with_wildcard() {
        check_ok(
            r#"
            contract T {
                enum Status { Active, Paused, Closed }
                pub fn f() {
                    let s = Status::Active;
                    match s {
                        Status::Active => { let x = 1; },
                        _ => { let x = 0; },
                    }
                }
            }
        "#,
        );
    }

    #[test]
    fn check_exhaustive_match_all_variants() {
        check_ok(
            r#"
            contract T {
                enum Status { Active, Paused }
                pub fn f() {
                    let s = Status::Active;
                    match s {
                        Status::Active => { let x = 1; },
                        Status::Paused => { let x = 2; },
                    }
                }
            }
        "#,
        );
    }

    #[test]
    fn error_non_exhaustive_match() {
        let errors = check_err(
            r#"
            contract T {
                enum Status { Active, Paused, Closed }
                pub fn f() {
                    let s = Status::Active;
                    match s {
                        Status::Active => { let x = 1; },
                    }
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("non-exhaustive match"));
        assert!(errors[0].message.contains("Paused"));
        assert!(errors[0].message.contains("Closed"));
    }

    // ========== Missing return ==========

    #[test]
    fn check_function_with_return() {
        check_ok(
            r#"
            contract T {
                pub fn f() -> u256 {
                    return 42;
                }
            }
        "#,
        );
    }

    #[test]
    fn error_missing_return() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() -> u256 {
                    let x = 42;
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("must return"));
    }

    #[test]
    fn check_return_after_loop() {
        // Return after loop is fine — loop might not execute.
        // TPL-209 prohibits Vec<u256>; the test only cares about
        // the control-flow shape, so swap to Vec<u64>.
        check_ok(
            r#"
            contract T {
                pub fn find(items: Vec<u64>, target: u64) -> u64 {
                    for i in 0..10 {
                        if i == target {
                            return i;
                        }
                    }
                    return 0;
                }
            }
        "#,
        );
    }

    #[test]
    fn check_revert_after_loop() {
        // Revert after loop is a valid exit path. TPL-209 forces
        // u256 → u64 here as in `check_return_after_loop`.
        check_ok(
            r#"
            contract T {
                error NotFound {}
                pub fn find(items: Vec<u64>, target: u64) -> u64 {
                    for i in 0..10 {
                        if i == target {
                            return i;
                        }
                    }
                    revert!(NotFound {});
                }
            }
        "#,
        );
    }

    #[test]
    fn error_return_only_inside_loop() {
        // Return only inside loop — loop might not execute
        let errors = check_err(
            r#"
            contract T {
                pub fn f() -> u256 {
                    for i in 0..10 {
                        return i;
                    }
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("must return"));
    }

    #[test]
    fn error_bare_return_in_non_void() {
        let errors = check_err(
            r#"
            contract T {
                pub fn f() -> u256 {
                    return;
                }
            }
        "#,
        );
        assert!(errors[0].message.contains("'return' has no value"));
    }

    #[test]
    fn error_undefined_storage_field() {
        let errors = check_err(
            r#"
            contract T {
                storage { balance: u256, }
                pub fn f() {
                    let x = self.nonexistent;
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("not a storage field or function"));
    }

    #[test]
    fn error_assign_undefined_storage_field() {
        let errors = check_err(
            r#"
            contract T {
                storage { balance: u256, }
                pub fn f() {
                    self.fake = 100;
                }
            }
        "#,
        );
        assert!(errors[0]
            .message
            .contains("not a storage field or function"));
    }

    #[test]
    fn check_bare_return_in_void_ok() {
        // return; in void function is fine (early exit)
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    if true { return; }
                    let x = 42;
                }
            }
        "#,
        );
    }

    #[test]
    fn check_void_function_no_return_needed() {
        check_ok(
            r#"
            contract T {
                pub fn f() {
                    let x = 42;
                }
            }
        "#,
        );
    }

    #[test]
    fn check_valid_method_types() {
        // TPL-209 prohibits Vec<u256>; this test exercises the
        // method dispatch on Vec/bytes/string and doesn't depend
        // on the element width, so swap to Vec<u64>.
        check_ok(
            r#"
            contract T {
                storage { items: Vec<u64>, data: bytes, }
                pub fn f() {
                    let n = self.items.len();
                    let empty = self.items.is_empty();
                    self.items.push(42);
                    let b = self.data.len();
                    self.data.append(self.data);
                    let name = "hello";
                    let full = name.concat(" world");
                    let nb = name.as_bytes();
                }
            }
        "#,
        );
    }

    // ========== Audit 354: signed integer types rejected ==========

    /// Audit 354: every signed-integer primitive type must be
    /// rejected at typecheck time. Codegen + optimizer treat all
    /// integers as unsigned (Div/Mod/<,>,<=,>=/Shr emit unsigned
    /// PVM ops, fold_binop/fold_cmp use U256), so a contract that
    /// compiles with `i*` types silently produces wrong arithmetic
    /// at runtime. Ban at the language layer until the post-
    /// mainnet path adds Sdiv/Smod/Slt/Sgt/Sar opcodes.
    #[test]
    fn audit_354_rejects_i8_function_param() {
        let errs = check_err(
            r#"
            contract C {
                pub fn f(x: i8) -> u64 { return 0; }
            }
            "#,
        );
        assert!(
            errs.iter().any(|e| e.message.contains("audit 354")),
            "expected audit-354 error, got: {:?}",
            errs
        );
    }

    #[test]
    fn audit_354_rejects_i256_storage_field() {
        let errs = check_err(
            r#"
            contract C {
                storage { balance: i256, }
            }
            "#,
        );
        assert!(errs.iter().any(|e| e.message.contains("audit 354")));
    }

    #[test]
    fn audit_354_rejects_i32_in_vec() {
        let errs = check_err(
            r#"
            contract C {
                storage { nums: Vec<i32>, }
            }
            "#,
        );
        assert!(errs.iter().any(|e| e.message.contains("audit 354")));
    }

    #[test]
    fn audit_354_rejects_i64_in_map_value() {
        let errs = check_err(
            r#"
            contract C {
                storage { scores: Map<Address, i64>, }
            }
            "#,
        );
        assert!(errs.iter().any(|e| e.message.contains("audit 354")));
    }

    #[test]
    fn audit_354_rejects_i128_return_type() {
        let errs = check_err(
            r#"
            contract C {
                pub fn f() -> i128 { return 0; }
            }
            "#,
        );
        assert!(errs.iter().any(|e| e.message.contains("audit 354")));
    }

    #[test]
    fn audit_354_unsigned_types_still_accepted() {
        // TPL-209 forced `Vec<u128>` out of this positive control —
        // stride-truncating containers are gated until post-mainnet
        // even when the element is unsigned. The unsigned-type
        // positive case is now just narrow primitives plus Map
        // (which uses Sload/Sstore, not the 8-byte-stride codegen).
        check_ok(
            r#"
            contract C {
                storage { a: u256, b: Vec<u64>, c: Map<Address, u64>, }
                pub fn f(x: u32) -> u8 { return 0; }
            }
            "#,
        );
    }

    /// Audit 354: TPL-208 — `let x: i64 = 0;` inside a function body
    /// must be rejected. The original audit-354 pre-pass walks
    /// declarations only (params, returns, fields, aliases), so a
    /// signed annotation on a `let` slipped through and minted a
    /// `Ty::I64` local that downstream codegen then treated as
    /// unsigned.
    #[test]
    fn audit_354_rejects_i64_in_let_binding() {
        let errs = check_err(
            r#"
            contract C {
                pub fn f() -> u64 {
                    let x: i64 = 0;
                    return 0;
                }
            }
            "#,
        );
        assert!(
            errs.iter().any(|e| e.message.contains("audit 354")),
            "expected audit-354 error for `let x: i64`, got: {:?}",
            errs
        );
    }

    /// Audit 354: TPL-208 — `let v: Vec<i32> = ...` is the
    /// container variant of the let-binding gap; reject it the
    /// same way fields-of-Vec<i32> are rejected.
    #[test]
    fn audit_354_rejects_vec_signed_in_let_binding() {
        let errs = check_err(
            r#"
            contract C {
                pub fn f() -> u64 {
                    let v: Vec<i32> = Vec::new();
                    return 0;
                }
            }
            "#,
        );
        assert!(
            errs.iter().any(|e| e.message.contains("audit 354")),
            "expected audit-354 error for `let v: Vec<i32>`, got: {:?}",
            errs
        );
    }

    /// Audit 354: TPL-208 — `(expr as i32)` is the cast variant of
    /// the body-level gap. Without a `let` annotation at all, a
    /// contract that wrote `let x = (a as i32);` would still mint
    /// a signed `Ty` from the cast target type and route it
    /// straight into codegen.
    #[test]
    fn audit_354_rejects_cast_to_signed() {
        let errs = check_err(
            r#"
            contract C {
                pub fn f(a: u64) -> u64 {
                    let x = (a as i32);
                    return 0;
                }
            }
            "#,
        );
        assert!(
            errs.iter().any(|e| e.message.contains("audit 354")),
            "expected audit-354 error for `as i32` cast, got: {:?}",
            errs
        );
    }

    // ========== TPL-209: Vec/Array of wide elements rejected ==========

    /// TPL-209: `Vec<Address>` would silently truncate every
    /// element to its low 8 bytes — a multisig signer list
    /// stored this way would lose every byte past the first 8
    /// of every address. Reject at typecheck.
    #[test]
    fn tpl_209_rejects_vec_address() {
        let errs = check_err(
            r#"
            contract C {
                storage { signers: Vec<Address>, }
            }
            "#,
        );
        assert!(
            errs.iter().any(|e| e.message.contains("TPL-209")),
            "expected TPL-209 error for `Vec<Address>`, got: {:?}",
            errs
        );
    }

    /// TPL-209: `Vec<u256>` is the canonical instance — the bug
    /// description in the tracker calls it out by name.
    #[test]
    fn tpl_209_rejects_vec_u256() {
        let errs = check_err(
            r#"
            contract C {
                storage { values: Vec<u256>, }
            }
            "#,
        );
        assert!(
            errs.iter().any(|e| e.message.contains("TPL-209")),
            "expected TPL-209 error for `Vec<u256>`, got: {:?}",
            errs
        );
    }

    /// TPL-209: `Vec<bytes>` packs a length + heap pointer per
    /// element, which doesn't fit the 8-byte Vec slot any better
    /// than `u256`. Reject at typecheck.
    #[test]
    fn tpl_209_rejects_vec_bytes() {
        let errs = check_err(
            r#"
            contract C {
                storage { blobs: Vec<bytes>, }
            }
            "#,
        );
        assert!(
            errs.iter().any(|e| e.message.contains("TPL-209")),
            "expected TPL-209 error for `Vec<bytes>`, got: {:?}",
            errs
        );
    }

    /// TPL-209: nested-container case. `Map<K, Vec<u256>>`
    /// recurses into the Vec value, which then trips the
    /// element-width gate. Confirms the recursion through
    /// containers fires, not just top-level types.
    #[test]
    fn tpl_209_rejects_nested_vec_u256_in_map() {
        let errs = check_err(
            r#"
            contract C {
                storage { roles: Map<u64, Vec<u256>>, }
            }
            "#,
        );
        assert!(
            errs.iter().any(|e| e.message.contains("TPL-209")),
            "expected TPL-209 error for `Map<u64, Vec<u256>>`, got: {:?}",
            errs
        );
    }

    /// TPL-209: `[Address; 4]` (fixed-size array) shares the
    /// 8-byte-stride codegen with Vec, so the same gate applies.
    #[test]
    fn tpl_209_rejects_array_of_address() {
        let errs = check_err(
            r#"
            contract C {
                storage { signers: [Address; 4], }
            }
            "#,
        );
        assert!(
            errs.iter().any(|e| e.message.contains("TPL-209")),
            "expected TPL-209 error for `[Address; 4]`, got: {:?}",
            errs
        );
    }

    /// TPL-209: positive control — `Vec<u64>` (8-byte element)
    /// remains accepted, as do `Map<Address, u256>` (the Map
    /// codegen uses Sload/Sstore with full 32-byte wide
    /// registers, not the truncating Vec stride) and bare
    /// `Address` storage.
    #[test]
    fn tpl_209_narrow_vec_and_map_still_accepted() {
        check_ok(
            r#"
            contract C {
                storage {
                    nums: Vec<u64>,
                    flags: Vec<bool>,
                    bal: Map<Address, u256>,
                    owner: Address,
                }
            }
            "#,
        );
    }

    // ========== Audit 356: FNV-1a-32 selector collision detection ==========

    /// Audit 356: confirm the typecheck-side
    /// `compute_fnv1a_selector` is byte-equal to the codegen-side
    /// `compute_selector`. We duplicate the implementation
    /// (typecheck shouldn't depend on codegen), so this guard
    /// fires loudly if either copy drifts.
    #[test]
    fn audit_356_compute_fnv1a_matches_codegen_compute_selector() {
        for name in [
            "transfer",
            "approve",
            "mint",
            "burn",
            "balance_of",
            "owner",
            "init",
            "very_long_function_name_that_exercises_many_iterations",
        ] {
            assert_eq!(
                super::compute_fnv1a_selector(name),
                crate::codegen::compute_selector(name),
                "FNV-1a-32 helpers diverge for `{name}`"
            );
        }
    }

    /// Audit 356: brute-force a real FNV-1a-32 collision among
    /// short ASCII function names, then confirm the typecheck
    /// pass rejects a contract that defines BOTH colliding names
    /// as public functions. Without the dedup check the dispatch
    /// table would pick whichever entry got generated first and
    /// silently shadow the other.
    ///
    /// The brute-force search runs once per test invocation and
    /// completes in milliseconds; ~26^4 = 450K candidates to find
    /// a 4-char-vs-4-char or shorter pair via birthday collision
    /// over a 32-bit space (expected ~65K trials). If the hash
    /// changes the search just re-runs and still finds a pair.
    #[test]
    fn audit_356_rejects_contract_with_colliding_selectors() {
        let (a, b) = find_fnv1a_collision().expect(
            "no collision found in 200K-name search — \
             FNV-1a-32 collisions should occur within ~65K trials",
        );
        assert_ne!(a, b);
        let src = format!(
            "contract C {{ pub fn {a}() -> u64 {{ return 1; }} \
             pub fn {b}() -> u64 {{ return 2; }} }}"
        );
        let errs = check_err(&src);
        assert!(
            errs.iter().any(|e| e.message.contains("audit 356")),
            "expected audit-356 collision error for ({a}, {b}), got: {:?}",
            errs
        );
    }

    /// Brute-force search for a pair of distinct short ASCII
    /// strings that hash to the same FNV-1a-32 selector. Strings
    /// are valid Otic identifiers (start with letter).
    fn find_fnv1a_collision() -> Option<(String, String)> {
        let mut seen: HashMap<u32, String> = HashMap::new();
        // Birthday-paradox math says we need ~sqrt(2*2^32) ≈ 92K
        // trials for 50% collision probability over a 32-bit
        // space. 1M trials → ~117 expected collisions, very high
        // probability of finding at least one. Search runs in
        // ~50ms (single hash call per trial).
        for i in 0u32..1_000_000 {
            let name = idx_to_name(i);
            let sel = super::compute_fnv1a_selector(&name);
            if let Some(prev) = seen.insert(sel, name.clone()) {
                if prev != name {
                    return Some((prev, name));
                }
            }
        }
        None
    }

    fn idx_to_name(i: u32) -> String {
        // Mix letters + digits + suffix length to exhaust buckets
        // (alphabetic-only over short lengths leaves FNV-1a-32
        // surprisingly collision-light empirically). Identifier
        // syntax requires the first char to be a letter; anything
        // after that can be alphanumeric.
        let mut s = String::with_capacity(8);
        s.push('f');
        let mut x = i;
        while x > 0 {
            let d = (x % 36) as u8;
            let c = if d < 10 {
                (b'0' + d) as char
            } else {
                (b'a' + d - 10) as char
            };
            s.push(c);
            x /= 36;
        }
        if s.len() == 1 {
            s.push('0');
        }
        s
    }
}
