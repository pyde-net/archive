//! Type checker: validates type correctness across the entire AST.
//!
//! Receives the AST + SymbolTable from the resolver.
//! Infers types for expressions, checks assignments, function calls,
//! struct inits, emit statements, and casts.

use std::collections::HashMap;

use crate::ast::*;
use crate::token::Span;
use crate::types::Ty;

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
        // First pass: collect all type definitions
        for item in &file.items {
            self.collect_defs(item);
        }

        // Second pass: check all bodies
        for item in &file.items {
            self.check_item(item);
        }

        TypeCheckResult { errors: self.errors }
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
                a_size == b_size && (a_elem == b_elem
                    || **a_elem == Ty::Unknown || **b_elem == Ty::Unknown
                    || a_elem.can_widen_to(b_elem) || b_elem.can_widen_to(a_elem)
                    || (a_elem.is_numeric() && b_elem.is_numeric()))
            }
            // Unknown/Error declared type accepts anything
            (_, Ty::Unknown) | (_, Ty::Error) => true,
            (Ty::Unknown, _) | (Ty::Error, _) => true,
            // Struct inferred matches unknown declared
            (Ty::Struct(_), Ty::Unknown) => true,
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
            Type::Named(ident) => {
                // Check type aliases first
                if let Some(ty) = self.env.type_aliases.get(&ident.name) {
                    return ty.clone();
                }
                if self.env.struct_defs.contains_key(&ident.name) {
                    return Ty::Struct(ident.name.clone());
                }
                if self.env.enum_defs.contains_key(&ident.name) {
                    return Ty::Enum(ident.name.clone());
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
            _ => {}
        }
    }

    fn collect_contract_defs(&mut self, contract: &ContractDef) {
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
                ContractItem::Function(f) => self.collect_func_sig(f),
            }
        }
    }

    fn collect_struct(&mut self, s: &StructDef) {
        let fields: Vec<(String, Ty)> = s.fields.iter()
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
        let fields: Vec<(String, Ty, bool)> = e.fields.iter()
            .map(|f| (f.name.name.clone(), self.resolve_type(&f.ty), f.indexed))
            .collect();
        self.env.event_defs.insert(e.name.name.clone(), fields);
    }

    fn collect_error(&mut self, e: &ErrorDef) {
        let fields: Vec<(String, Ty)> = e.fields.iter()
            .map(|f| (f.name.name.clone(), self.resolve_type(&f.ty)))
            .collect();
        self.env.error_defs.insert(e.name.name.clone(), fields);
    }

    fn collect_func_sig(&mut self, f: &FunctionDef) {
        let params: Vec<(String, Ty)> = f.params.iter()
            .map(|p| (p.name.name.clone(), self.resolve_type(&p.ty)))
            .collect();
        let ret = f.return_type.as_ref()
            .map(|t| self.resolve_type(t))
            .unwrap_or(Ty::Unit);
        self.env.func_sigs.insert(f.name.name.clone(), (params, ret));
    }

    fn collect_interface(&mut self, iface: &InterfaceDef) {
        let funcs: Vec<(String, Vec<(String, Ty)>, Ty)> = iface.functions.iter()
            .map(|f| {
                let params: Vec<(String, Ty)> = f.params.iter()
                    .map(|p| (p.name.name.clone(), self.resolve_type(&p.ty)))
                    .collect();
                let ret = f.return_type.as_ref()
                    .map(|t| self.resolve_type(t))
                    .unwrap_or(Ty::Unit);
                (f.name.name.clone(), params, ret)
            })
            .collect();
        self.env.interface_defs.insert(iface.name.name.clone(), funcs);
    }

    // ========================================================================
    // Item checking (second pass)
    // ========================================================================

    fn check_item(&mut self, item: &Item) {
        match item {
            Item::Contract(c) => self.check_contract(c),
            Item::Function(f) => self.check_function(f),
            Item::Const(c) => { self.infer_expr(&c.value); }
            _ => {}
        }
    }

    fn check_contract(&mut self, contract: &ContractDef) {
        self.in_contract = true;
        for item in &contract.items {
            match item {
                ContractItem::Function(f) => self.check_function(f),
                ContractItem::Const(c) => { self.infer_expr(&c.value); }
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
        let ret_ty = func.return_type.as_ref()
            .map(|t| self.resolve_type(t))
            .unwrap_or(Ty::Unit);

        self.current_return_type = Some(ret_ty);
        self.check_block(&func.body);
        self.current_return_type = None;
        self.env.pop_scope();
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
                if let Some(ref val) = r.value {
                    let ret_ty = self.infer_expr(val);
                    if let Some(ref expected) = self.current_return_type {
                        // Void function returning a value
                        if *expected == Ty::Unit {
                            self.error(
                                "function does not return a value, but 'return' has an expression".into(),
                                r.span,
                            );
                        }
                        // Type mismatch
                        else if ret_ty != Ty::Unknown && ret_ty != Ty::Error
                            && *expected != Ty::Unknown
                            && ret_ty != *expected
                            && !self.is_int_literal_compatible(val, expected)
                            && !ret_ty.can_widen_to(expected)
                            && !(ret_ty.is_numeric() && expected.is_numeric())
                            && !self.is_compatible_init(&ret_ty, expected)
                        {
                            self.error(
                                format!("return type mismatch: expected {}, found {}", expected, ret_ty),
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
            Stmt::Expr(e) => { self.infer_expr(&e.expr); }
            Stmt::Break(_) | Stmt::Continue(_) => {}
        }
    }

    fn check_let(&mut self, l: &LetStmt) {
        let init_ty = self.infer_expr(&l.initializer);

        let declared_ty = if let Some(ref ty) = l.ty {
            let t = self.resolve_type(ty);
            // Check compatibility — integer literals are polymorphic,
            // and Vec<?>/Unknown types are compatible with concrete types
            if init_ty != Ty::Unknown && init_ty != Ty::Error && t != init_ty
                && !self.is_int_literal_compatible(&l.initializer, &t)
                && !self.is_compatible_init(&init_ty, &t)
                && !init_ty.can_widen_to(&t)
            {
                self.error(
                    format!("type mismatch: declared {}, but initializer is {}", t, init_ty),
                    l.span,
                );
            }
            t
        } else {
            init_ty
        };

        match &l.binding {
            LetBinding::Name(name) => {
                self.env.declare_local(&name.name, declared_ty, l.is_mutable);
            }
            LetBinding::Tuple(names, span) => {
                if let Ty::Tuple(types) = &declared_ty {
                    if names.len() != types.len() {
                        self.error(
                            format!(
                                "tuple destructuring: expected {} elements, found {}",
                                types.len(), names.len()
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
                        self.env.declare_local(&name.name, Ty::Unknown, l.is_mutable);
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

        if target_ty != Ty::Unknown && value_ty != Ty::Unknown
            && target_ty != Ty::Error && value_ty != Ty::Error
        {
            match a.op {
                AssignOp::Assign => {
                    if target_ty != value_ty
                        && !self.is_int_literal_compatible(&a.value, &target_ty)
                        && !value_ty.can_widen_to(&target_ty)
                        && !(target_ty.is_numeric() && value_ty.is_numeric()) // allow numeric narrowing
                        && !self.is_compatible_init(&value_ty, &target_ty)
                    {
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
                            format!("type mismatch in compound assignment: {} and {}", target_ty, value_ty),
                            a.span,
                        );
                    }
                    if !target_ty.is_numeric() && target_ty != Ty::Unknown && target_ty != Ty::Error {
                        self.error(
                            format!("compound assignment requires numeric type, found {}", target_ty),
                            a.span,
                        );
                    }
                }
            }
        }
    }

    fn check_emit(&mut self, e: &EmitStmt) {
        if let Some(event_fields) = self.env.event_defs.get(&e.event_name.name).cloned() {
            // Check field count
            if e.fields.len() != event_fields.len() {
                self.error(
                    format!(
                        "event '{}' expects {} fields, found {}",
                        e.event_name.name, event_fields.len(), e.fields.len()
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
                    if value_ty != Ty::Unknown && value_ty != Ty::Error && value_ty != *expected_ty
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
                Literal::Int(_) => Ty::U256, // default integer type
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
                        if ty != Ty::Bool && !ty.is_integer() && ty != Ty::Unknown && ty != Ty::Error {
                            self.error(format!("logical NOT requires bool or integer, found {}", ty), *span);
                        }
                        if ty.is_integer() { ty } else { Ty::Bool }
                    }
                    UnaryOp::BitNot => {
                        if !ty.is_integer() && ty != Ty::Unknown && ty != Ty::Error {
                            self.error(format!("bitwise NOT requires integer, found {}", ty), *span);
                        }
                        ty
                    }
                }
            }

            Expr::FieldAccess(obj, field, _) => {
                let obj_ty = self.infer_expr(obj);
                // self.field → storage field type
                if matches!(**obj, Expr::SelfExpr(_)) {
                    if let Some(ty) = self.env.storage_fields.get(&field.name) {
                        return ty.clone();
                    }
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

            Expr::Call(callee, args, span) => {
                // Infer all argument types
                let arg_types: Vec<Ty> = args.iter()
                    .map(|arg| self.infer_expr(arg))
                    .collect();

                // Try to resolve the function return type and check args
                match callee.as_ref() {
                    Expr::Ident(ident) => {
                        // Built-in functions
                        if ident.name == "hash" {
                            return Ty::Array(Box::new(Ty::U8), 32);
                        }
                        if ident.name == "address" {
                            return Ty::Address;
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
                            if let Some((params, ret)) = self.env.func_sigs.get(&method.name).cloned() {
                                self.check_call_args(&method.name, &params, &arg_types, args, *span);
                                return ret;
                            }
                        }
                        // Common method return types
                        match method.name.as_str() {
                            // Collections
                            "len" => Ty::U64,
                            "push" | "pop" => Ty::Unit,
                            "is_empty" => Ty::Bool,
                            // String (minimal — only essentials for contracts)
                            "concat" => obj_ty,  // String.concat() → String
                            // Bytes
                            "as_bytes" | "to_bytes" => Ty::Bytes,
                            "append" => Ty::Unit, // bytes.append()
                            // Math extension methods (use std::math)
                            "sqrt" | "pow" | "min" | "max" | "clamp"
                            | "mul_div" | "checked_add" | "checked_sub"
                            | "saturating_add" | "saturating_sub"
                            | "wrapping_add" | "wrapping_sub" => obj_ty,
                            _ => Ty::Unknown,
                        }
                    }
                    Expr::Path(segments, _) => {
                        // Vec::new(), bytes::new(), etc.
                        if segments.len() == 2 {
                            match (segments[0].name.as_str(), segments[1].name.as_str()) {
                                ("Vec", "new") => Ty::Vec(Box::new(Ty::Unknown)),
                                ("bytes", "new" | "empty") => Ty::Bytes,
                                (iface_name, "at") => {
                                    // Interface::at(addr) returns something call-able
                                    Ty::Unknown
                                }
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
                        MacroArg::Positional(expr) => { arg_types.push(self.infer_expr(expr)); }
                        MacroArg::Named(_, expr) => { arg_types.push(self.infer_expr(expr)); }
                    }
                }

                // Validate macro-specific arg types
                match name.name.as_str() {
                    "require" => {
                        // require!(condition, error) — first arg must be bool
                        if let Some(cond_ty) = arg_types.first() {
                            if *cond_ty != Ty::Bool && *cond_ty != Ty::Unknown && *cond_ty != Ty::Error {
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
                    _ => Ty::Unknown,
                }
            }

            Expr::StructInit(name_segments, fields, span) => {
                let struct_name = name_segments.first()
                    .map(|s| s.name.as_str())
                    .unwrap_or("");

                // Check if it's a struct init or error init
                if let Some(struct_fields) = self.env.struct_defs.get(struct_name).cloned() {
                    for field in fields {
                        let value_ty = self.infer_expr(&field.value);
                        if let Some((_, expected_ty)) = struct_fields.iter()
                            .find(|(name, _)| name == &field.name.name)
                        {
                            if value_ty != Ty::Unknown && value_ty != Ty::Error
                                && *expected_ty != Ty::Unknown && *expected_ty != Ty::Error
                                && value_ty != *expected_ty
                                && !self.is_int_literal_compatible(&field.value, expected_ty)
                                && !value_ty.can_widen_to(expected_ty)
                                && !self.is_compatible_init(&value_ty, expected_ty)
                                && !(value_ty.is_numeric() && expected_ty.is_numeric()) // allow numeric narrowing (runtime checked)
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

            Expr::Match(scrutinee, arms, _) => {
                let scrut_ty = self.infer_expr(scrutinee);

                for arm in arms {
                    // Check pattern compatibility with scrutinee
                    self.check_pattern(&arm.pattern, &scrut_ty);
                    self.infer_expr(&arm.body);
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

            Expr::Cast(expr, target_ty, _) => {
                self.infer_expr(expr);
                self.resolve_type(target_ty)
            }

            Expr::Tuple(elements, _) => {
                let types: Vec<Ty> = elements.iter()
                    .map(|e| self.infer_expr(e))
                    .collect();
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

    fn check_binary_op_full(&mut self, lhs_expr: &Expr, lhs: &Ty, op: &BinaryOp, rhs_expr: &Expr, rhs: &Ty, span: Span) -> Ty {
        // Error/Unknown propagation
        if matches!(lhs, Ty::Error | Ty::Unknown) || matches!(rhs, Ty::Error | Ty::Unknown) {
            return match op {
                BinaryOp::Eq | BinaryOp::NotEq | BinaryOp::Lt | BinaryOp::Gt
                | BinaryOp::LtEq | BinaryOp::GtEq | BinaryOp::LogicalAnd
                | BinaryOp::LogicalOr => Ty::Bool,
                BinaryOp::Range => Ty::Unknown,
                _ => if *lhs != Ty::Unknown && *lhs != Ty::Error { lhs.clone() } else { rhs.clone() },
            };
        }

        // Integer literal coercion: if one side is a literal and the other is a
        // concrete numeric type, the literal adapts to the concrete type.
        let (lhs, rhs) = self.coerce_numeric_pair(lhs_expr, lhs, rhs_expr, rhs);

        match op {
            // Arithmetic: both same numeric type → same type
            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul
            | BinaryOp::Div | BinaryOp::Mod => {
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
                    self.error(format!("arithmetic requires numeric type, found {}", lhs), span);
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
            BinaryOp::BitAnd | BinaryOp::BitOr | BinaryOp::BitXor
            | BinaryOp::Shl | BinaryOp::Shr => {
                if !lhs.is_integer() {
                    self.error(format!("bitwise op requires integer type, found {}", lhs), span);
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
            BinaryOp::Eq | BinaryOp::NotEq | BinaryOp::Lt | BinaryOp::Gt
            | BinaryOp::LtEq | BinaryOp::GtEq => {
                if !lhs.is_comparable_with(&rhs) {
                    self.error(
                        format!("cannot compare {} with {}", lhs, rhs),
                        span,
                    );
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
            BinaryOp::Range => {
                Ty::Unknown
            }
        }
    }

    /// Coerce numeric types to a common type for binary operations.
    /// Rules:
    /// 1. Integer literals adapt to the other operand's concrete type
    /// 2. Implicit widening: smaller → larger (u64 + u256 → u256)
    /// 3. Same signedness required (no implicit signed/unsigned mixing)
    fn coerce_numeric_pair(&self, lhs_expr: &Expr, lhs: &Ty, rhs_expr: &Expr, rhs: &Ty) -> (Ty, Ty) {
        if lhs == rhs { return (lhs.clone(), rhs.clone()); }

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
                    func_name, params.len(), arg_types.len()
                ),
                span,
            );
            return;
        }

        for (i, ((param_name, param_ty), arg_ty)) in params.iter().zip(arg_types.iter()).enumerate() {
            if *arg_ty != Ty::Unknown && *arg_ty != Ty::Error
                && *param_ty != Ty::Unknown
                && *arg_ty != *param_ty
                && !arg_ty.can_widen_to(param_ty)
                && !(arg_ty.is_numeric() && param_ty.is_numeric())
                && !self.is_compatible_init(arg_ty, param_ty)
            {
                // Also check if the arg is a literal that can adapt
                let is_literal = arg_exprs.get(i)
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
        check_ok(r#"
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
        "#);
    }

    #[test]
    fn check_arithmetic_same_type() {
        check_ok(r#"
            contract T {
                pub fn f() {
                    let a: u256 = 10;
                    let b: u256 = 20;
                    let c = a + b;
                }
            }
        "#);
    }

    #[test]
    fn check_boolean_logic() {
        check_ok(r#"
            contract T {
                pub fn f() {
                    let a = true;
                    let b = false;
                    let c = a && b;
                    let d = a || !b;
                }
            }
        "#);
    }

    #[test]
    fn check_comparison_returns_bool() {
        check_ok(r#"
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
        "#);
    }

    #[test]
    fn check_struct_init() {
        check_ok(r#"
            contract T {
                struct Point { x: u64, y: u64 }
                pub fn f() {
                    let p = Point { x: 1, y: 2 };
                }
            }
        "#);
    }

    #[test]
    fn check_enum_pattern() {
        check_ok(r#"
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
        "#);
    }

    #[test]
    fn check_event_emit() {
        check_ok(r#"
            contract T {
                event Transfer { from: Address, to: Address, amount: u256, }
                pub fn f() {
                    emit Transfer { from: msg.sender, to: msg.sender, amount: 100 };
                }
            }
        "#);
    }

    #[test]
    fn check_tuple_destructuring() {
        check_ok(r#"
            contract T {
                pub fn get_pair() -> (u256, u256) {
                    return (1, 2);
                }
                pub fn f() {
                    let (a, b) = self.get_pair();
                }
            }
        "#);
    }

    #[test]
    fn check_cast_expression() {
        check_ok(r#"
            contract T {
                pub fn f() {
                    let a: u64 = 42;
                    let b = a as u256;
                }
            }
        "#);
    }

    #[test]
    fn check_array_literal() {
        check_ok(r#"
            contract T {
                pub fn f() {
                    let arr = [1, 2, 3];
                }
            }
        "#);
    }

    #[test]
    fn check_hash_builtin() {
        check_ok(r#"
            contract T {
                pub fn f() {
                    let h = hash(42);
                }
            }
        "#);
    }

    #[test]
    fn check_for_loop() {
        check_ok(r#"
            contract T {
                pub fn f() {
                    for i in 0..10 {
                        let x = i;
                    }
                }
            }
        "#);
    }

    // ========== Type errors ==========

    #[test]
    fn error_if_condition_not_bool() {
        let errors = check_err(r#"
            contract T {
                pub fn f() {
                    if 42 {
                        let x = 1;
                    }
                }
            }
        "#);
        assert!(errors[0].message.contains("if condition must be bool"));
    }

    #[test]
    fn error_while_condition_not_bool() {
        let errors = check_err(r#"
            contract T {
                pub fn f() {
                    while 42 {
                        let x = 1;
                    }
                }
            }
        "#);
        assert!(errors[0].message.contains("while condition must be bool"));
    }

    #[test]
    fn logical_not_on_int_is_allowed() {
        // ! on integers is bitwise NOT (like C), returns same type
        check_ok(r#"
            contract T {
                pub fn f() {
                    let x = !42;
                }
            }
        "#);
    }

    #[test]
    fn error_logical_not_on_string() {
        let errors = check_err(r#"
            contract T {
                pub fn f() {
                    let x = !"hello";
                }
            }
        "#);
        assert!(errors[0].message.contains("logical NOT requires bool or integer"));
    }

    #[test]
    fn error_wrong_event_field_count() {
        let errors = check_err(r#"
            contract T {
                event Transfer { from: Address, to: Address, amount: u256, }
                pub fn f() {
                    emit Transfer { from: msg.sender };
                }
            }
        "#);
        assert!(errors[0].message.contains("expects 3 fields, found 1"));
    }

    // ========== Return type validation ==========

    #[test]
    fn check_return_type_correct() {
        check_ok(r#"
            contract T {
                pub fn f() -> u256 {
                    return 42;
                }
            }
        "#);
    }

    #[test]
    fn error_return_type_mismatch() {
        let errors = check_err(r#"
            contract T {
                pub fn f() -> u256 {
                    return "hello";
                }
            }
        "#);
        assert!(errors[0].message.contains("return type mismatch"));
    }

    #[test]
    fn check_return_type_widening() {
        // u64 returned for u256 function — widening is ok
        check_ok(r#"
            contract T {
                storage { count: u64, }
                pub fn f() -> u256 {
                    return self.count;
                }
            }
        "#);
    }

    // ========== Function call argument validation ==========

    #[test]
    fn error_wrong_argument_count() {
        let errors = check_err(r#"
            contract T {
                fn helper(x: u256, y: u256) {}
                pub fn f() {
                    self.helper(1);
                }
            }
        "#);
        assert!(errors[0].message.contains("expects 2 arguments, found 1"));
    }

    #[test]
    fn error_wrong_argument_type() {
        let errors = check_err(r#"
            contract T {
                fn helper(x: u256) {}
                pub fn f() {
                    self.helper("hello");
                }
            }
        "#);
        assert!(errors[0].message.contains("argument 'x' expects u256, found String"));
    }

    #[test]
    fn check_argument_widening() {
        // u64 arg for u256 param — ok
        check_ok(r#"
            contract T {
                storage { count: u64, }
                fn helper(x: u256) {}
                pub fn f() {
                    self.helper(self.count);
                }
            }
        "#);
    }

    #[test]
    fn check_argument_literal() {
        // Literal adapts to param type
        check_ok(r#"
            contract T {
                fn helper(x: u64) {}
                pub fn f() {
                    self.helper(42);
                }
            }
        "#);
    }

    // ========== Mutability checking ==========

    #[test]
    fn check_mutable_assignment() {
        check_ok(r#"
            contract T {
                pub fn f() {
                    let mut x = 1;
                    x = 2;
                }
            }
        "#);
    }

    #[test]
    fn error_immutable_assignment() {
        let errors = check_err(r#"
            contract T {
                pub fn f() {
                    let x = 1;
                    x = 2;
                }
            }
        "#);
        assert!(errors[0].message.contains("cannot assign to immutable variable 'x'"));
    }

    #[test]
    fn check_compound_mutable_assignment() {
        check_ok(r#"
            contract T {
                pub fn f() {
                    let mut count = 0;
                    count += 1;
                }
            }
        "#);
    }

    #[test]
    fn error_immutable_compound_assignment() {
        let errors = check_err(r#"
            contract T {
                pub fn f() {
                    let count = 0;
                    count += 1;
                }
            }
        "#);
        assert!(errors[0].message.contains("cannot assign to immutable variable 'count'"));
    }

    // ========== require! condition checking ==========

    #[test]
    fn check_require_bool_condition() {
        check_ok(r#"
            contract T {
                error Fail {}
                pub fn f() {
                    require!(true, Fail {});
                }
            }
        "#);
    }

    #[test]
    fn error_require_non_bool_condition() {
        let errors = check_err(r#"
            contract T {
                error Fail {}
                pub fn f() {
                    require!(42, Fail {});
                }
            }
        "#);
        assert!(errors[0].message.contains("require! condition must be bool"));
    }

    // ========== Void function returning value ==========

    #[test]
    fn check_void_function_no_return() {
        check_ok(r#"
            contract T {
                pub fn f() {
                    let x = 1;
                }
            }
        "#);
    }

    #[test]
    fn error_void_function_returning_value() {
        let errors = check_err(r#"
            contract T {
                pub fn f() {
                    return 42;
                }
            }
        "#);
        assert!(errors[0].message.contains("function does not return a value"));
    }

    // ========== String concat error ==========

    #[test]
    fn error_string_plus_operator() {
        let errors = check_err(r#"
            contract T {
                pub fn f() {
                    let x = "hello" + "world";
                }
            }
        "#);
        assert!(errors[0].message.contains("use .concat() instead"));
    }
}
