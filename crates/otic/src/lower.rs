//! AST → IR lowering: converts the validated AST into OtiIR.
//!
//! Walks the AST and emits flat IR instructions into basic blocks.
//! Variable names are mapped to virtual registers.

use std::collections::HashMap;

use ethnum::U256;

use crate::ast;
use crate::ast::*;
use crate::ir::{self, IrProgram, IrFunction, BasicBlock, Label, Reg, Inst, IrConst, BinOp, UnOp, CmpOp, BuiltinOp, StorageFieldDef};
use crate::types::Ty;

/// Lower a source file into an IR program.
pub fn lower(file: &SourceFile) -> IrProgram {
    let mut lowerer = Lowerer::new();
    lowerer.lower_file(file);
    lowerer.program
}

struct Lowerer {
    program: IrProgram,
    /// Current function being lowered.
    current_fn: Option<IrFunction>,
    /// Variable name → register mapping (scoped).
    locals: Vec<HashMap<String, Reg>>,
    /// Storage field name → slot index.
    storage_slots: HashMap<String, u32>,
    next_slot: u32,
    /// Loop label stack: (header_label, exit_label) for break/continue.
    loop_stack: Vec<(Label, Label)>,
    /// Enum name → variant names (in order, discriminant = index).
    enum_defs: HashMap<String, Vec<String>>,
    /// Const name → (value, type) for inlining.
    const_defs: HashMap<String, (U256, Ty)>,
}

impl Lowerer {
    fn new() -> Self {
        Self {
            program: IrProgram {
                contract_name: String::new(),
                functions: Vec::new(),
                storage_fields: Vec::new(),
                struct_defs: Vec::new(),
                enum_defs: Vec::new(),
                event_defs: Vec::new(),
                error_defs: Vec::new(),
                interface_defs: Vec::new(),
                const_defs: Vec::new(),
                type_aliases: Vec::new(),
                imports: Vec::new(),
            },
            current_fn: None,
            locals: vec![HashMap::new()],
            storage_slots: HashMap::new(),
            next_slot: 0,
            loop_stack: Vec::new(),
            enum_defs: HashMap::new(),
            const_defs: HashMap::new(),
        }
    }

    fn func(&mut self) -> &mut IrFunction {
        self.current_fn.as_mut().expect("not inside a function")
    }

    fn alloc_reg(&mut self) -> Reg {
        self.func().alloc_reg()
    }

    fn emit(&mut self, inst: Inst) {
        self.func().emit(inst);
    }

    fn push_scope(&mut self) {
        self.locals.push(HashMap::new());
    }

    fn pop_scope(&mut self) {
        self.locals.pop();
    }

    fn declare_local(&mut self, name: &str, reg: Reg) {
        if let Some(scope) = self.locals.last_mut() {
            scope.insert(name.to_string(), reg);
        }
    }

    fn lookup_local(&self, name: &str) -> Option<Reg> {
        for scope in self.locals.iter().rev() {
            if let Some(reg) = scope.get(name) {
                return Some(*reg);
            }
        }
        None
    }

    /// Convert an AST type to an IR type.
    fn resolve_ty(&self, ty: &ast::Type) -> Ty {
        match ty {
            ast::Type::Primitive(p, _) => match p {
                ast::PrimitiveType::U8 => Ty::U8,
                ast::PrimitiveType::U16 => Ty::U16,
                ast::PrimitiveType::U32 => Ty::U32,
                ast::PrimitiveType::U64 => Ty::U64,
                ast::PrimitiveType::U128 => Ty::U128,
                ast::PrimitiveType::U256 => Ty::U256,
                ast::PrimitiveType::I8 => Ty::I8,
                ast::PrimitiveType::I16 => Ty::I16,
                ast::PrimitiveType::I32 => Ty::I32,
                ast::PrimitiveType::I64 => Ty::I64,
                ast::PrimitiveType::I128 => Ty::I128,
                ast::PrimitiveType::I256 => Ty::I256,
                ast::PrimitiveType::Bool => Ty::Bool,
                ast::PrimitiveType::Address => Ty::Address,
                ast::PrimitiveType::StringType => Ty::StringTy,
            },
            ast::Type::Bytes(_) => Ty::Bytes,
            ast::Type::Array(elem, size, _) => Ty::Array(Box::new(self.resolve_ty(elem)), *size),
            ast::Type::Vec(elem, _) => Ty::Vec(Box::new(self.resolve_ty(elem))),
            ast::Type::Map(key, val, _) => Ty::Map(Box::new(self.resolve_ty(key)), Box::new(self.resolve_ty(val))),
            ast::Type::Named(ident) => Ty::Struct(ident.name.clone()),
            ast::Type::Tuple(types, _) => Ty::Tuple(types.iter().map(|t| self.resolve_ty(t)).collect()),
        }
    }

    fn alloc_storage_slot(&mut self, name: &str, ty: Ty) -> u32 {
        let slot = self.next_slot;
        self.next_slot += 1;
        self.storage_slots.insert(name.to_string(), slot);
        self.program.storage_fields.push(StorageFieldDef {
            name: name.to_string(),
            ty,
            slot,
        });
        slot
    }

    // ========================================================================
    // Top-level lowering
    // ========================================================================

    fn lower_file(&mut self, file: &SourceFile) {
        // Pre-pass: collect all definitions
        for item in &file.items {
            match item {
                Item::Enum(e) => {
                    let variants: Vec<String> = e.variants.iter().map(|v| v.name.clone()).collect();
                    self.program.enum_defs.push(ir::EnumDef {
                        name: e.name.name.clone(),
                        variants: variants.clone(),
                    });
                    self.enum_defs.insert(e.name.name.clone(), variants);
                }
                Item::Const(c) => {
                    if let Expr::Literal(Literal::Int(v), _) = &c.value {
                        self.const_defs.insert(c.name.name.clone(), (*v, Ty::U256));
                        self.program.const_defs.push(ir::ConstDef {
                            name: c.name.name.clone(),
                            ty: Ty::U256,
                            value: IrConst::Int(*v, Ty::U64),
                            is_pub: c.is_pub,
                        });
                    }
                }
                Item::Struct(s) => {
                    let fields: Vec<(String, Ty)> = s.fields.iter()
                        .map(|f| (f.name.name.clone(), self.resolve_ty(&f.ty)))
                        .collect();
                    self.program.struct_defs.push(ir::StructDef {
                        name: s.name.name.clone(),
                        fields,
                    });
                }
                Item::Interface(i) => {
                    let funcs: Vec<ir::InterfaceFnDef> = i.functions.iter()
                        .map(|f| ir::InterfaceFnDef {
                            name: f.name.name.clone(),
                            params: f.params.iter().map(|p| (p.name.name.clone(), self.resolve_ty(&p.ty))).collect(),
                            return_ty: f.return_type.as_ref().map(|t| self.resolve_ty(t)).unwrap_or(Ty::Unit),
                        })
                        .collect();
                    self.program.interface_defs.push(ir::InterfaceDef {
                        name: i.name.name.clone(),
                        functions: funcs,
                    });
                }
                Item::TypeAlias(t) => {
                    self.program.type_aliases.push(ir::TypeAliasDef {
                        name: t.name.name.clone(),
                        ty: self.resolve_ty(&t.ty),
                    });
                }
                Item::Use(u) => {
                    if u.items.is_empty() {
                        // Simple import: use std::math;
                        self.program.imports.push(ir::ImportDef {
                            path: u.path.iter().map(|s| s.name.clone()).collect(),
                        });
                    } else {
                        // Grouped import: use std::math::{sqrt, pow};
                        for item in &u.items {
                            let mut full_path: Vec<String> = u.path.iter().map(|s| s.name.clone()).collect();
                            full_path.push(item.name.clone());
                            self.program.imports.push(ir::ImportDef { path: full_path });
                        }
                    }
                }
                Item::Error(e) => {
                    let fields: Vec<(String, Ty)> = e.fields.iter()
                        .map(|f| (f.name.name.clone(), self.resolve_ty(&f.ty)))
                        .collect();
                    self.program.error_defs.push(ir::ErrorDef {
                        name: e.name.name.clone(),
                        fields,
                        doc: e.doc.clone(),
                    });
                }
                _ => {}
            }
        }

        // Main pass: lower contracts and functions
        for item in &file.items {
            match item {
                Item::Contract(c) => self.lower_contract(c),
                Item::Function(f) => self.lower_function(f),
                _ => {}
            }
        }
    }

    fn lower_contract(&mut self, contract: &ContractDef) {
        self.program.contract_name = contract.name.name.clone();

        // First pass: collect storage fields, enums, consts
        for item in &contract.items {
            match item {
                ContractItem::Storage(s) => {
                    for field in &s.fields {
                        let ty = self.resolve_ty(&field.ty);
                        self.alloc_storage_slot(&field.name.name, ty);
                    }
                }
                ContractItem::Struct(s) => {
                    let fields: Vec<(String, Ty)> = s.fields.iter()
                        .map(|f| (f.name.name.clone(), self.resolve_ty(&f.ty)))
                        .collect();
                    self.program.struct_defs.push(ir::StructDef {
                        name: s.name.name.clone(),
                        fields,
                    });
                }
                ContractItem::Enum(e) => {
                    let variants: Vec<String> = e.variants.iter().map(|v| v.name.clone()).collect();
                    self.program.enum_defs.push(ir::EnumDef {
                        name: e.name.name.clone(),
                        variants: variants.clone(),
                    });
                    self.enum_defs.insert(e.name.name.clone(), variants);
                }
                ContractItem::Event(e) => {
                    let fields: Vec<ir::EventFieldDef> = e.fields.iter()
                        .map(|f| ir::EventFieldDef {
                            name: f.name.name.clone(),
                            ty: self.resolve_ty(&f.ty),
                            indexed: f.indexed,
                        })
                        .collect();
                    self.program.event_defs.push(ir::EventDef {
                        name: e.name.name.clone(),
                        fields,
                        doc: e.doc.clone(),
                    });
                }
                ContractItem::Error(e) => {
                    let fields: Vec<(String, Ty)> = e.fields.iter()
                        .map(|f| (f.name.name.clone(), self.resolve_ty(&f.ty)))
                        .collect();
                    self.program.error_defs.push(ir::ErrorDef {
                        name: e.name.name.clone(),
                        fields,
                        doc: e.doc.clone(),
                    });
                }
                ContractItem::Const(c) => {
                    if let Expr::Literal(Literal::Int(v), _) = &c.value {
                        self.const_defs.insert(c.name.name.clone(), (*v, Ty::U256));
                        self.program.const_defs.push(ir::ConstDef {
                            name: c.name.name.clone(),
                            ty: Ty::U256,
                            value: IrConst::Int(*v, Ty::U64),
                            is_pub: c.is_pub,
                        });
                    }
                }
                _ => {}
            }
        }

        // Second pass: lower functions
        for item in &contract.items {
            if let ContractItem::Function(f) = item {
                self.lower_function(f);
            }
        }
    }

    fn lower_function(&mut self, func: &FunctionDef) {
        let params: Vec<(String, Ty)> = func.params.iter()
            .map(|p| (p.name.name.clone(), self.resolve_ty(&p.ty)))
            .collect();
        let return_ty = func.return_type.as_ref()
            .map(|t| self.resolve_ty(t))
            .unwrap_or(Ty::Unit);

        let mut ir_func = IrFunction::new(func.name.name.clone(), params.clone(), return_ty);
        ir_func.is_pub = func.is_pub;
        ir_func.is_constructor = func.is_constructor();
        ir_func.is_view = func.is_view();
        ir_func.is_reentrant = func.is_reentrant();
        ir_func.is_payable = func.is_payable();
        ir_func.is_test = func.is_test();
        ir_func.sponsorship = func.sponsorship();
        ir_func.doc = func.doc.clone();

        self.current_fn = Some(ir_func);
        self.push_scope();

        // Declare parameters as local registers
        for (name, _ty) in &params {
            let reg = self.alloc_reg();
            self.declare_local(name, reg);
        }

        // Lower body
        self.lower_block(&func.body);

        // Ensure function ends with a return
        let needs_ret = self.func().current_block().instructions.last()
            .map(|inst| !matches!(inst, Inst::Return(_) | Inst::Jump(_)))
            .unwrap_or(true);
        if needs_ret {
            self.emit(Inst::Return(None));
        }

        self.pop_scope();
        let ir_func = self.current_fn.take().unwrap();
        self.program.functions.push(ir_func);
    }

    // ========================================================================
    // Block and statement lowering
    // ========================================================================

    fn lower_block(&mut self, block: &Block) {
        for stmt in &block.stmts {
            self.lower_stmt(stmt);
        }
    }

    fn lower_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Let(l) => self.lower_let(l),
            Stmt::Assign(a) => self.lower_assign(a),
            Stmt::Return(r) => self.lower_return(r),
            Stmt::Emit(e) => self.lower_emit(e),
            Stmt::For(f) => self.lower_for(f),
            Stmt::While(w) => self.lower_while(w),
            Stmt::Expr(e) => { self.lower_expr(&e.expr); }
            Stmt::Break(_) => {
                if let Some((_, exit_label)) = self.loop_stack.last() {
                    self.emit(Inst::Jump(*exit_label));
                }
            }
            Stmt::Continue(_) => {
                if let Some((header_label, _)) = self.loop_stack.last() {
                    self.emit(Inst::Jump(*header_label));
                }
            }
        }
    }

    fn lower_let(&mut self, l: &LetStmt) {
        let val = self.lower_expr(&l.initializer);

        match &l.binding {
            LetBinding::Name(name) => {
                self.declare_local(&name.name, val);
            }
            LetBinding::Tuple(names, _) => {
                // Destructure tuple into individual registers
                for (i, name) in names.iter().enumerate() {
                    let elem = self.alloc_reg();
                    self.emit(Inst::TupleGet(elem, val, i as u32));
                    self.declare_local(&name.name, elem);
                }
            }
        }
    }

    fn lower_assign(&mut self, a: &AssignStmt) {
        let value = self.lower_expr(&a.value);

        // Handle compound assignments: target op= value → target = target op value
        let final_value = if a.op != AssignOp::Assign {
            let target_val = self.lower_expr(&a.target);
            let result = self.alloc_reg();
            let bin_op = match a.op {
                AssignOp::AddAssign => BinOp::Add,
                AssignOp::SubAssign => BinOp::Sub,
                AssignOp::MulAssign => BinOp::Mul,
                AssignOp::DivAssign => BinOp::Div,
                AssignOp::ModAssign => BinOp::Mod,
                AssignOp::BitAndAssign => BinOp::BitAnd,
                AssignOp::BitOrAssign => BinOp::BitOr,
                AssignOp::BitXorAssign => BinOp::BitXor,
                AssignOp::ShlAssign => BinOp::Shl,
                AssignOp::ShrAssign => BinOp::Shr,
                AssignOp::Assign => unreachable!(),
            };
            self.emit(Inst::BinOp(result, bin_op, target_val, value));
            result
        } else {
            value
        };

        // Write to target
        self.lower_assign_target(&a.target, final_value);
    }

    fn lower_assign_target(&mut self, target: &Expr, value: Reg) {
        match target {
            // self.field = value → storage.set
            Expr::FieldAccess(obj, field, _) if matches!(obj.as_ref(), Expr::SelfExpr(_)) => {
                self.emit(Inst::StorageSet(field.name.clone(), value));
            }
            // self.map[key1][key2] = value → storage.nested_map_set
            // self.map[key] = value → storage.map_set
            Expr::Index(obj, key, _) => {
                // Check for nested: self.map[key1][key2]
                if let Expr::Index(inner_obj, inner_key, _) = obj.as_ref() {
                    if let Expr::FieldAccess(self_expr, field, _) = inner_obj.as_ref() {
                        if matches!(self_expr.as_ref(), Expr::SelfExpr(_)) {
                            let key1 = self.lower_expr(inner_key);
                            let key2 = self.lower_expr(key);
                            self.emit(Inst::StorageNestedMapSet(field.name.clone(), key1, key2, value));
                            return;
                        }
                    }
                }
                // Single-level: self.map[key]
                if let Expr::FieldAccess(inner_obj, field, _) = obj.as_ref() {
                    if matches!(inner_obj.as_ref(), Expr::SelfExpr(_)) {
                        let key_reg = self.lower_expr(key);
                        self.emit(Inst::StorageMapSet(field.name.clone(), key_reg, value));
                        return;
                    }
                }
                // General index set
                let obj_reg = self.lower_expr(obj);
                let key_reg = self.lower_expr(key);
                self.emit(Inst::IndexSet(obj_reg, key_reg, value));
            }
            // Local variable reassignment — emit a copy to the original register
            Expr::Ident(ident) => {
                let existing_reg = self.lookup_local(&ident.name);
                if let Some(existing) = existing_reg {
                    if existing != value {
                        // Copy: existing_reg = value (critical for loops)
                        self.emit(Inst::Cast(existing, value, Ty::Unknown));
                    }
                } else {
                    if let Some(scope) = self.locals.last_mut() {
                        scope.insert(ident.name.clone(), value);
                    }
                }
            }
            _ => {
                self.emit(Inst::Comment(format!("unhandled assign target")));
            }
        }
    }

    fn lower_return(&mut self, r: &ReturnStmt) {
        let val = r.value.as_ref().map(|v| self.lower_expr(v));
        self.emit(Inst::Return(val));
    }

    fn lower_emit(&mut self, e: &EmitStmt) {
        let field_regs: Vec<Reg> = e.fields.iter()
            .map(|f| self.lower_expr(&f.value))
            .collect();
        self.emit(Inst::Emit(e.event_name.name.clone(), field_regs));
    }

    fn lower_for(&mut self, f: &ForStmt) {
        // for i in start..end { body }
        // → init loop var, check condition, body, increment, jump back

        let header_label = self.func().alloc_label();
        let body_label = self.func().alloc_label();
        let exit_label = self.func().alloc_label();

        // Lower the range expression (start..end)
        let (start, end) = if let Expr::Binary(lhs, BinaryOp::Range, rhs, _) = &f.iterator {
            (self.lower_expr(lhs), self.lower_expr(rhs))
        } else {
            let iter = self.lower_expr(&f.iterator);
            let zero = self.alloc_reg();
            self.emit(Inst::Const(zero, IrConst::Int(U256::ZERO, Ty::U64)));
            (zero, iter)
        };

        // Initialize loop variable (copy start value)
        let loop_var = start; // directly use the start register
        self.push_scope();
        self.declare_local(&f.variable.name, loop_var);

        // Jump to header
        self.emit(Inst::Jump(header_label));

        // Header: check condition (always uses loop_var register)
        self.func().push_block(header_label, "for.header".into());
        let cond = self.alloc_reg();
        self.emit(Inst::Cmp(cond, CmpOp::Lt, loop_var, end));
        self.emit(Inst::Branch(cond, body_label, exit_label));

        // Body
        self.func().push_block(body_label, "for.body".into());
        self.loop_stack.push((header_label, exit_label));
        self.lower_block(&f.body);
        self.loop_stack.pop();

        // Increment: loop_var = loop_var + 1 (overwrite same register)
        let one = self.alloc_reg();
        self.emit(Inst::Const(one, IrConst::Int(U256::from(1u64), Ty::U64)));
        self.emit(Inst::BinOp(loop_var, BinOp::Add, loop_var, one));
        self.emit(Inst::Jump(header_label));

        // Exit
        self.func().push_block(exit_label, "for.exit".into());
        self.pop_scope();
    }

    fn lower_while(&mut self, w: &WhileStmt) {
        let header_label = self.func().alloc_label();
        let body_label = self.func().alloc_label();
        let exit_label = self.func().alloc_label();

        self.emit(Inst::Jump(header_label));

        // Header: check condition
        self.func().push_block(header_label, "while.header".into());
        let cond = self.lower_expr(&w.condition);
        self.emit(Inst::Branch(cond, body_label, exit_label));

        // Body
        self.func().push_block(body_label, "while.body".into());
        self.push_scope();
        self.loop_stack.push((header_label, exit_label));
        self.lower_block(&w.body);
        self.loop_stack.pop();
        self.pop_scope();
        self.emit(Inst::Jump(header_label));

        // Exit
        self.func().push_block(exit_label, "while.exit".into());
    }

    // ========================================================================
    // Expression lowering — every expression returns a register
    // ========================================================================

    fn lower_expr(&mut self, expr: &Expr) -> Reg {
        match expr {
            Expr::Literal(lit, _) => {
                let dst = self.alloc_reg();
                let val = match lit {
                    Literal::Int(v) => IrConst::Int(*v, Ty::U64),
                    Literal::String(s) => IrConst::String(s.clone()),
                    Literal::Bool(b) => IrConst::Bool(*b),
                };
                self.emit(Inst::Const(dst, val));
                dst
            }

            Expr::Ident(ident) => {
                // Local variable
                if let Some(reg) = self.lookup_local(&ident.name) {
                    return reg;
                }
                // Const value — inline
                if let Some((value, ty)) = self.const_defs.get(&ident.name).cloned() {
                    let dst = self.alloc_reg();
                    self.emit(Inst::Const(dst, IrConst::Int(value, ty)));
                    return dst;
                }
                // Unknown — emit placeholder
                let dst = self.alloc_reg();
                self.emit(Inst::Comment(format!("lookup: {}", ident.name)));
                dst
            }

            Expr::SelfExpr(_) => {
                // self doesn't have a register — it's implicit in storage ops
                let dst = self.alloc_reg();
                self.emit(Inst::Builtin(dst, BuiltinOp::AddressOfSelf));
                dst
            }

            Expr::Binary(lhs, op, rhs, _) => {
                let l = self.lower_expr(lhs);
                let r = self.lower_expr(rhs);
                let dst = self.alloc_reg();

                match op {
                    BinaryOp::Add => self.emit(Inst::BinOp(dst, BinOp::Add, l, r)),
                    BinaryOp::Sub => self.emit(Inst::BinOp(dst, BinOp::Sub, l, r)),
                    BinaryOp::Mul => self.emit(Inst::BinOp(dst, BinOp::Mul, l, r)),
                    BinaryOp::Div => self.emit(Inst::BinOp(dst, BinOp::Div, l, r)),
                    BinaryOp::Mod => self.emit(Inst::BinOp(dst, BinOp::Mod, l, r)),
                    BinaryOp::BitAnd => self.emit(Inst::BinOp(dst, BinOp::BitAnd, l, r)),
                    BinaryOp::BitOr => self.emit(Inst::BinOp(dst, BinOp::BitOr, l, r)),
                    BinaryOp::BitXor => self.emit(Inst::BinOp(dst, BinOp::BitXor, l, r)),
                    BinaryOp::Shl => self.emit(Inst::BinOp(dst, BinOp::Shl, l, r)),
                    BinaryOp::Shr => self.emit(Inst::BinOp(dst, BinOp::Shr, l, r)),
                    BinaryOp::LogicalAnd => self.emit(Inst::BinOp(dst, BinOp::LogicalAnd, l, r)),
                    BinaryOp::LogicalOr => self.emit(Inst::BinOp(dst, BinOp::LogicalOr, l, r)),
                    BinaryOp::Eq => self.emit(Inst::Cmp(dst, CmpOp::Eq, l, r)),
                    BinaryOp::NotEq => self.emit(Inst::Cmp(dst, CmpOp::NotEq, l, r)),
                    BinaryOp::Lt => self.emit(Inst::Cmp(dst, CmpOp::Lt, l, r)),
                    BinaryOp::Gt => self.emit(Inst::Cmp(dst, CmpOp::Gt, l, r)),
                    BinaryOp::LtEq => self.emit(Inst::Cmp(dst, CmpOp::LtEq, l, r)),
                    BinaryOp::GtEq => self.emit(Inst::Cmp(dst, CmpOp::GtEq, l, r)),
                    BinaryOp::Range => {
                        // Range is structural, not a value — used by for loops
                        self.emit(Inst::Comment("range".into()));
                    }
                }
                dst
            }

            Expr::Unary(op, operand, _) => {
                let src = self.lower_expr(operand);
                let dst = self.alloc_reg();
                match op {
                    UnaryOp::Negate => self.emit(Inst::UnOp(dst, UnOp::Neg, src)),
                    UnaryOp::LogicalNot => self.emit(Inst::UnOp(dst, UnOp::LogicalNot, src)),
                    UnaryOp::BitNot => self.emit(Inst::UnOp(dst, UnOp::BitNot, src)),
                }
                dst
            }

            Expr::FieldAccess(obj, field, _) => {
                // self.field → storage.get
                if matches!(obj.as_ref(), Expr::SelfExpr(_)) {
                    if self.storage_slots.contains_key(&field.name) {
                        let dst = self.alloc_reg();
                        self.emit(Inst::StorageGet(dst, field.name.clone()));
                        return dst;
                    }
                }

                // msg.sender, msg.value, msg.data → builtins
                if let Expr::Ident(ident) = obj.as_ref() {
                    if ident.name == "msg" {
                        let dst = self.alloc_reg();
                        match field.name.as_str() {
                            "sender" => self.emit(Inst::Builtin(dst, BuiltinOp::MsgSender)),
                            "value" => self.emit(Inst::Builtin(dst, BuiltinOp::MsgValue)),
                            "data" => self.emit(Inst::Builtin(dst, BuiltinOp::MsgData)),
                            _ => self.emit(Inst::Comment(format!("msg.{}", field.name))),
                        }
                        return dst;
                    }
                    if ident.name == "block" {
                        let dst = self.alloc_reg();
                        match field.name.as_str() {
                            "timestamp" => self.emit(Inst::Builtin(dst, BuiltinOp::BlockTimestamp)),
                            "height" => self.emit(Inst::Builtin(dst, BuiltinOp::BlockHeight)),
                            "proposer" => self.emit(Inst::Builtin(dst, BuiltinOp::BlockProposer)),
                            _ => self.emit(Inst::Comment(format!("block.{}", field.name))),
                        }
                        return dst;
                    }
                    if ident.name == "tx" {
                        let dst = self.alloc_reg();
                        match field.name.as_str() {
                            "gas_price" => self.emit(Inst::Builtin(dst, BuiltinOp::TxGasPrice)),
                            "nonce" => self.emit(Inst::Builtin(dst, BuiltinOp::TxNonce)),
                            "hash" => self.emit(Inst::Builtin(dst, BuiltinOp::TxHash)),
                            "gas_limit" => self.emit(Inst::Builtin(dst, BuiltinOp::TxGasLimit)),
                            _ => self.emit(Inst::Comment(format!("tx.{}", field.name))),
                        }
                        return dst;
                    }
                }

                // address.balance → special builtin
                // Handles: address(self).balance, address(x).balance, msg.sender treated as Address
                if field.name == "balance" {
                    let obj_reg = self.lower_expr(obj);
                    let dst = self.alloc_reg();
                    self.emit(Inst::FieldGet(dst, obj_reg, "balance".into()));
                    return dst;
                }

                // obj.field → field_get
                let obj_reg = self.lower_expr(obj);
                let dst = self.alloc_reg();
                self.emit(Inst::FieldGet(dst, obj_reg, field.name.clone()));
                dst
            }

            Expr::Index(obj, index, _) => {
                // self.map[key1][key2] → storage.nested_map_get (2-level)
                if let Expr::Index(inner_obj, inner_idx, _) = obj.as_ref() {
                    if let Expr::FieldAccess(self_expr, field, _) = inner_obj.as_ref() {
                        if matches!(self_expr.as_ref(), Expr::SelfExpr(_))
                            && self.storage_slots.contains_key(&field.name)
                        {
                            let key1 = self.lower_expr(inner_idx);
                            let key2 = self.lower_expr(index);
                            let dst = self.alloc_reg();
                            self.emit(Inst::StorageNestedMapGet(dst, field.name.clone(), key1, key2));
                            return dst;
                        }
                    }
                }
                // self.map[key] → storage.map_get (1-level)
                if let Expr::FieldAccess(inner_obj, field, _) = obj.as_ref() {
                    if matches!(inner_obj.as_ref(), Expr::SelfExpr(_))
                        && self.storage_slots.contains_key(&field.name)
                    {
                        let key = self.lower_expr(index);
                        let dst = self.alloc_reg();
                        self.emit(Inst::StorageMapGet(dst, field.name.clone(), key));
                        return dst;
                    }
                }
                let obj_reg = self.lower_expr(obj);
                let idx_reg = self.lower_expr(index);
                let dst = self.alloc_reg();
                self.emit(Inst::IndexGet(dst, obj_reg, idx_reg));
                dst
            }

            Expr::Call(callee, args, _) => {
                let arg_regs: Vec<Reg> = args.iter().map(|a| self.lower_expr(a)).collect();
                let dst = self.alloc_reg();

                match callee.as_ref() {
                    // hash(...)
                    Expr::Ident(ident) if ident.name == "hash" => {
                        self.emit(Inst::Hash(dst, arg_regs));
                    }
                    // address(self)
                    Expr::Ident(ident) if ident.name == "address" => {
                        self.emit(Inst::Builtin(dst, BuiltinOp::AddressOfSelf));
                    }
                    // gas_remaining()
                    Expr::Ident(ident) if ident.name == "gas_remaining" => {
                        self.emit(Inst::Builtin(dst, BuiltinOp::GasRemaining));
                    }
                    // sig_verify(message, signature, public_key) → bool
                    Expr::Ident(ident) if ident.name == "sig_verify" => {
                        self.emit(Inst::Call(dst, "sig_verify".into(), arg_regs));
                    }
                    // sig_recover(message, signature) → Address
                    Expr::Ident(ident) if ident.name == "sig_recover" => {
                        self.emit(Inst::Call(dst, "sig_recover".into(), arg_regs));
                    }
                    // local_function(args)
                    Expr::Ident(ident) => {
                        self.emit(Inst::Call(dst, ident.name.clone(), arg_regs));
                    }
                    // self.method(args) or obj.method(args)
                    Expr::FieldAccess(obj, method, _) => {
                        if matches!(obj.as_ref(), Expr::SelfExpr(_)) {
                            self.emit(Inst::Call(dst, method.name.clone(), arg_regs));
                        } else {
                            let obj_reg = self.lower_expr(obj);
                            self.emit(Inst::MethodCall(dst, obj_reg, method.name.clone(), arg_regs));
                        }
                    }
                    // Path::call(args) — Vec::new(), IERC20::at(), etc.
                    Expr::Path(segments, _) => {
                        if segments.len() == 2 {
                            let type_name = segments[0].name.as_str();
                            let member = segments[1].name.as_str();
                            if type_name == "Vec" && member == "new" {
                                self.emit(Inst::MakeVec(dst, 64));
                                return dst;
                            }
                        }
                        let path = segments.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join("::");
                        self.emit(Inst::Call(dst, path, arg_regs));
                    }
                    _ => {
                        self.emit(Inst::Comment("unhandled call".into()));
                    }
                }
                dst
            }

            Expr::Path(segments, _) => {
                let dst = self.alloc_reg();

                if segments.len() == 2 {
                    let type_name = &segments[0].name;
                    let member = &segments[1].name;

                    // Address::ZERO
                    if type_name == "Address" && member == "ZERO" {
                        self.emit(Inst::Const(dst, IrConst::Address([0u8; 32])));
                        return dst;
                    }

                    // Enum variant → discriminant integer
                    if let Some(variants) = self.enum_defs.get(type_name.as_str()).cloned() {
                        if let Some(idx) = variants.iter().position(|v| v == member) {
                            self.emit(Inst::Const(dst, IrConst::Int(U256::from(idx as u64), Ty::U8)));
                            return dst;
                        }
                    }

                    // Vec::new(), bytes::new(), etc.
                    if type_name == "Vec" && member == "new" {
                        self.emit(Inst::MakeVec(dst, 64)); // initial capacity 16
                        return dst;
                    }
                    if type_name == "bytes" && (member == "new" || member == "empty") {
                        self.emit(Inst::Const(dst, IrConst::Bytes(vec![])));
                        return dst;
                    }
                }

                let path = segments.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join("::");
                self.emit(Inst::Comment(format!("path: {}", path)));
                dst
            }

            Expr::MacroCall(name, args, _) => {
                match name.name.as_str() {
                    "require" => {
                        // require!(cond, Error { fields }) → branch on cond, revert if false
                        if args.len() >= 2 {
                            if let MacroArg::Positional(cond_expr) = &args[0] {
                                let cond = self.lower_expr(cond_expr);
                                let ok_label = self.func().alloc_label();
                                let revert_label = self.func().alloc_label();

                                self.emit(Inst::Branch(cond, ok_label, revert_label));

                                // Revert block
                                self.func().push_block(revert_label, "require.fail".into());
                                if let MacroArg::Positional(err_expr) = &args[1] {
                                    let err_regs = self.lower_error_expr(err_expr);
                                    self.emit(Inst::Revert(err_regs.0, err_regs.1));
                                } else {
                                    self.emit(Inst::Revert("Error".into(), vec![]));
                                }

                                // Continue block
                                self.func().push_block(ok_label, "require.ok".into());
                            }
                        }
                        let dst = self.alloc_reg();
                        self.emit(Inst::Const(dst, IrConst::Unit));
                        dst
                    }
                    "revert" => {
                        if let Some(MacroArg::Positional(err_expr)) = args.first() {
                            let err_regs = self.lower_error_expr(err_expr);
                            self.emit(Inst::Revert(err_regs.0, err_regs.1));
                        } else {
                            self.emit(Inst::Revert("Error".into(), vec![]));
                        }
                        let dst = self.alloc_reg();
                        dst
                    }
                    "cross_call" => {
                        let mut target_reg = None;
                        let mut method_reg = None;
                        let mut call_args = Vec::new();
                        let mut callback = None;

                        for arg in args {
                            match arg {
                                MacroArg::Named(key, val) => {
                                    match key.name.as_str() {
                                        "target" => { target_reg = Some(self.lower_expr(val)); }
                                        "method" => { method_reg = Some(self.lower_expr(val)); }
                                        "callback" => {
                                            if let Expr::Literal(Literal::String(s), _) = val {
                                                callback = Some(s.clone());
                                            }
                                        }
                                        "args" => {
                                            // args is typically a tuple expression
                                            if let Expr::Tuple(elems, _) = val {
                                                for elem in elems {
                                                    call_args.push(self.lower_expr(elem));
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                MacroArg::Positional(expr) => {
                                    call_args.push(self.lower_expr(expr));
                                }
                            }
                        }

                        let t = target_reg.unwrap_or_else(|| {
                            let r = self.alloc_reg();
                            self.emit(Inst::Const(r, IrConst::Unit));
                            r
                        });
                        let m = method_reg.unwrap_or_else(|| {
                            let r = self.alloc_reg();
                            self.emit(Inst::Const(r, IrConst::String(String::new())));
                            r
                        });

                        self.emit(Inst::CrossCall {
                            target: t,
                            method: m,
                            args: call_args,
                            callback,
                        });

                        let dst = self.alloc_reg();
                        self.emit(Inst::Const(dst, IrConst::Unit));
                        dst
                    }
                    "raw_call" => {
                        let arg_regs: Vec<Reg> = args.iter().filter_map(|a| {
                            if let MacroArg::Positional(e) = a { Some(self.lower_expr(e)) } else { None }
                        }).collect();
                        let dst = self.alloc_reg();
                        let target = arg_regs.first().copied().unwrap_or(Reg(0));
                        self.emit(Inst::RawCall(dst, target, arg_regs[1..].to_vec()));
                        dst
                    }
                    _ => {
                        let dst = self.alloc_reg();
                        self.emit(Inst::Comment(format!("unknown macro: {}!", name.name)));
                        dst
                    }
                }
            }

            Expr::StructInit(name_segments, fields, _) => {
                let name = name_segments.first().map(|s| s.name.as_str()).unwrap_or("?");
                let field_regs: Vec<(String, Reg)> = fields.iter()
                    .map(|f| (f.name.name.clone(), self.lower_expr(&f.value)))
                    .collect();
                let dst = self.alloc_reg();
                self.emit(Inst::StructInit(dst, name.to_string(), field_regs));
                dst
            }

            Expr::If(cond, then_block, else_clause, _) => {
                let cond_reg = self.lower_expr(cond);
                let then_label = self.func().alloc_label();
                let else_label = self.func().alloc_label();
                let end_label = self.func().alloc_label();

                if else_clause.is_some() {
                    self.emit(Inst::Branch(cond_reg, then_label, else_label));
                } else {
                    self.emit(Inst::Branch(cond_reg, then_label, end_label));
                }

                // Then block
                self.func().push_block(then_label, "if.then".into());
                self.push_scope();
                self.lower_block(then_block);
                self.pop_scope();
                self.emit(Inst::Jump(end_label));

                // Else block
                if let Some(clause) = else_clause {
                    self.func().push_block(else_label, "if.else".into());
                    self.push_scope();
                    match clause {
                        ElseClause::ElseBlock(block) => self.lower_block(block),
                        ElseClause::ElseIf(else_if) => { self.lower_expr(else_if); }
                    }
                    self.pop_scope();
                    self.emit(Inst::Jump(end_label));
                }

                // End
                self.func().push_block(end_label, "if.end".into());
                let dst = self.alloc_reg();
                self.emit(Inst::Const(dst, IrConst::Unit));
                dst
            }

            Expr::Match(scrutinee, arms, _) => {
                let scrut = self.lower_expr(scrutinee);
                let end_label = self.func().alloc_label();
                let dst = self.alloc_reg();

                // Pre-allocate all arm labels to avoid collision with nested structures
                let arm_labels: Vec<Label> = (0..arms.len())
                    .map(|_| self.func().alloc_label())
                    .collect();

                for (i, arm) in arms.iter().enumerate() {
                    let arm_label = arm_labels[i];
                    let next_label = if i + 1 < arms.len() {
                        arm_labels[i + 1]
                    } else {
                        end_label
                    };

                    // Check pattern
                    match &arm.pattern {
                        Pattern::Wildcard(_) => {
                            self.emit(Inst::Jump(arm_label));
                        }
                        Pattern::Literal(lit, _) => {
                            let pat_reg = self.alloc_reg();
                            let val = match lit {
                                Literal::Int(v) => IrConst::Int(*v, Ty::U64),
                                Literal::String(s) => IrConst::String(s.clone()),
                                Literal::Bool(b) => IrConst::Bool(*b),
                            };
                            self.emit(Inst::Const(pat_reg, val));
                            let cmp = self.alloc_reg();
                            self.emit(Inst::Cmp(cmp, CmpOp::Eq, scrut, pat_reg));
                            self.emit(Inst::Branch(cmp, arm_label, next_label));
                        }
                        Pattern::Path(segments, _) => {
                            // Enum variant → compare scrutinee against discriminant
                            if segments.len() == 2 {
                                let enum_name = &segments[0].name;
                                let variant_name = &segments[1].name;
                                if let Some(variants) = self.enum_defs.get(enum_name.as_str()).cloned() {
                                    if let Some(idx) = variants.iter().position(|v| v == variant_name) {
                                        let pat_reg = self.alloc_reg();
                                        self.emit(Inst::Const(pat_reg, IrConst::Int(U256::from(idx as u64), Ty::U8)));
                                        let cmp = self.alloc_reg();
                                        self.emit(Inst::Cmp(cmp, CmpOp::Eq, scrut, pat_reg));
                                        self.emit(Inst::Branch(cmp, arm_label, next_label));
                                    } else {
                                        self.emit(Inst::Jump(arm_label));
                                    }
                                } else {
                                    // Unknown enum — fall through (could be a single-segment catch-all)
                                    self.emit(Inst::Jump(arm_label));
                                }
                            } else {
                                // Single-segment path — catch-all variable binding
                                self.emit(Inst::Jump(arm_label));
                            }
                        }
                        Pattern::Range(start, end_lit, _) => {
                            let start_reg = self.alloc_reg();
                            let end_reg = self.alloc_reg();
                            if let (Literal::Int(s), Literal::Int(e)) = (start, end_lit) {
                                self.emit(Inst::Const(start_reg, IrConst::Int(*s, Ty::U256)));
                                self.emit(Inst::Const(end_reg, IrConst::Int(*e, Ty::U256)));
                            }
                            let ge = self.alloc_reg();
                            let lt = self.alloc_reg();
                            let in_range = self.alloc_reg();
                            self.emit(Inst::Cmp(ge, CmpOp::GtEq, scrut, start_reg));
                            self.emit(Inst::Cmp(lt, CmpOp::Lt, scrut, end_reg));
                            self.emit(Inst::BinOp(in_range, BinOp::LogicalAnd, ge, lt));
                            self.emit(Inst::Branch(in_range, arm_label, next_label));
                        }
                    }

                    // Arm body
                    self.func().push_block(arm_label, format!("match.arm{}", i));
                    self.lower_expr(&arm.body);
                    self.emit(Inst::Jump(end_label));
                }

                self.func().push_block(end_label, "match.end".into());
                dst
            }

            Expr::Block(block) => {
                self.push_scope();
                self.lower_block(block);
                self.pop_scope();
                let dst = self.alloc_reg();
                self.emit(Inst::Const(dst, IrConst::Unit));
                dst
            }

            Expr::Cast(inner, _ty, _) => {
                let src = self.lower_expr(inner);
                let dst = self.alloc_reg();
                self.emit(Inst::Cast(dst, src, Ty::Unknown));
                dst
            }

            Expr::Tuple(elements, _) => {
                let regs: Vec<Reg> = elements.iter().map(|e| self.lower_expr(e)).collect();
                let dst = self.alloc_reg();
                self.emit(Inst::MakeTuple(dst, regs));
                dst
            }

            Expr::ArrayRepeat(val, count, _) => {
                let v = self.lower_expr(val);
                let dst = self.alloc_reg();
                self.emit(Inst::ArrayRepeat(dst, v, *count));
                dst
            }

            Expr::ArrayLiteral(elements, _) => {
                let regs: Vec<Reg> = elements.iter().map(|e| self.lower_expr(e)).collect();
                let dst = self.alloc_reg();
                self.emit(Inst::MakeArray(dst, regs));
                dst
            }

            Expr::Try(inner, _) => {
                // Try wraps in error handling — for now, just lower the inner expression
                self.lower_expr(inner)
            }
        }
    }

    /// Lower an error expression (from require!/revert!) into (name, field_regs).
    fn lower_error_expr(&mut self, expr: &Expr) -> (String, Vec<Reg>) {
        if let Expr::StructInit(name_segments, fields, _) = expr {
            let name = name_segments.first().map(|s| s.name.clone()).unwrap_or_default();
            let regs: Vec<Reg> = fields.iter().map(|f| self.lower_expr(&f.value)).collect();
            (name, regs)
        } else {
            ("Error".into(), vec![])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;
    use crate::parser::Parser;

    fn lower_src(src: &str) -> IrProgram {
        let (tokens, _) = Lexer::new(src).tokenize();
        let (file, _) = Parser::new(tokens).parse();
        lower(&file)
    }

    #[test]
    fn lower_minimal_contract() {
        let ir = lower_src(r#"
            contract Token {
                storage { supply: u256, }

                struct Holder { addr: Address, amount: u256 }
                enum Status { Active, Paused }
                event Transfer { from: Address, to: Address, amount: u256, }
                error Unauthorized {}

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

        assert_eq!(ir.contract_name, "Token");
        assert_eq!(ir.functions.len(), 2);
        assert_eq!(ir.storage_fields.len(), 1);
        assert_eq!(ir.storage_fields[0].name, "supply");

        // Definitions captured
        assert_eq!(ir.struct_defs.len(), 1);
        assert_eq!(ir.struct_defs[0].name, "Holder");
        assert_eq!(ir.struct_defs[0].fields.len(), 2);

        assert_eq!(ir.enum_defs.len(), 1);
        assert_eq!(ir.enum_defs[0].name, "Status");
        assert_eq!(ir.enum_defs[0].variants, vec!["Active", "Paused"]);

        assert_eq!(ir.event_defs.len(), 1);
        assert_eq!(ir.event_defs[0].name, "Transfer");
        assert_eq!(ir.event_defs[0].fields.len(), 3);

        assert_eq!(ir.error_defs.len(), 1);
        assert_eq!(ir.error_defs[0].name, "Unauthorized");

        assert!(ir.functions[0].is_constructor);
        assert!(ir.functions[1].is_view);
    }

    #[test]
    fn lower_arithmetic() {
        let ir = lower_src(r#"
            contract T {
                pub fn f() {
                    let a = 10;
                    let b = 20;
                    let c = a + b;
                }
            }
        "#);

        let func = &ir.functions[0];
        // Should have const, const, binop instructions
        let insts = &func.blocks[0].instructions;
        assert!(insts.iter().any(|i| matches!(i, Inst::BinOp(_, BinOp::Add, _, _))));
    }

    #[test]
    fn lower_storage_read_write() {
        let ir = lower_src(r#"
            contract T {
                storage { balance: u256, }
                pub fn f() {
                    let b = self.balance;
                    self.balance = 100;
                }
            }
        "#);

        let func = &ir.functions[0];
        let all_insts: Vec<&Inst> = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .collect();
        assert!(all_insts.iter().any(|i| matches!(i, Inst::StorageGet(_, _))));
        assert!(all_insts.iter().any(|i| matches!(i, Inst::StorageSet(_, _))));
    }

    #[test]
    fn lower_if_else() {
        let ir = lower_src(r#"
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
        // Should have multiple blocks (entry, if.then, if.else, if.end)
        assert!(func.blocks.len() >= 3);
    }

    #[test]
    fn lower_for_loop() {
        let ir = lower_src(r#"
            contract T {
                pub fn f() {
                    for i in 0..10 {
                        let x = i;
                    }
                }
            }
        "#);

        let func = &ir.functions[0];
        // Should have header, body, exit blocks
        assert!(func.blocks.len() >= 3);
    }

    #[test]
    fn lower_require() {
        let ir = lower_src(r#"
            contract T {
                error Fail {}
                pub fn f() {
                    require!(true, Fail {});
                }
            }
        "#);

        let func = &ir.functions[0];
        let all_insts: Vec<&Inst> = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .collect();
        assert!(all_insts.iter().any(|i| matches!(i, Inst::Branch(_, _, _))));
        assert!(all_insts.iter().any(|i| matches!(i, Inst::Revert(_, _))));
    }

    #[test]
    fn lower_emit() {
        let ir = lower_src(r#"
            contract T {
                event Transfer { from: Address, amount: u256, }
                pub fn f() {
                    emit Transfer { from: msg.sender, amount: 100 };
                }
            }
        "#);

        let func = &ir.functions[0];
        let all_insts: Vec<&Inst> = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .collect();
        assert!(all_insts.iter().any(|i| matches!(i, Inst::Emit(_, _))));
    }

    #[test]
    fn lower_enum_variant() {
        let ir = lower_src(r#"
            contract T {
                enum Status { Active, Paused, Closed }
                pub fn f() {
                    let s = Status::Active;
                    let p = Status::Paused;
                    let c = Status::Closed;
                }
            }
        "#);

        let func = &ir.functions[0];
        let all_insts: Vec<&Inst> = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .collect();

        // Active=0, Paused=1, Closed=2
        let consts: Vec<U256> = all_insts.iter().filter_map(|i| {
            if let Inst::Const(_, IrConst::Int(v, _)) = i { Some(*v) } else { None }
        }).collect();
        assert!(consts.contains(&U256::from(0u64)), "Active should be 0");
        assert!(consts.contains(&U256::from(1u64)), "Paused should be 1");
        assert!(consts.contains(&U256::from(2u64)), "Closed should be 2");
    }

    #[test]
    fn lower_enum_match_compares() {
        let ir = lower_src(r#"
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

        let func = &ir.functions[0];
        let all_insts: Vec<&Inst> = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .collect();

        // Should have Cmp instructions for enum variant matching (not just Jump)
        let cmp_count = all_insts.iter()
            .filter(|i| matches!(i, Inst::Cmp(_, CmpOp::Eq, _, _)))
            .count();
        assert!(cmp_count >= 2, "should have at least 2 comparisons for Active and Paused, got {}", cmp_count);
    }

    #[test]
    fn lower_const_inlining() {
        let ir = lower_src(r#"
            contract T {
                const MAX_SUPPLY: u256 = 1000000;
                pub fn f() {
                    let x = MAX_SUPPLY;
                }
            }
        "#);

        let func = &ir.functions[0];
        let all_insts: Vec<&Inst> = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .collect();

        // Should inline 1000000, not emit a comment
        assert!(all_insts.iter().any(|i| {
            if let Inst::Const(_, IrConst::Int(v, _)) = i { *v == U256::from(1000000u64) } else { false }
        }));
        assert!(!all_insts.iter().any(|i| {
            if let Inst::Comment(msg) = i { msg.contains("MAX_SUPPLY") } else { false }
        }));
    }

    #[test]
    fn lower_msg_sender_builtin() {
        let ir = lower_src(r#"
            contract T {
                pub fn f() {
                    let sender = msg.sender;
                    let ts = block.timestamp;
                    let val = msg.value;
                }
            }
        "#);

        let func = &ir.functions[0];
        let all_insts: Vec<&Inst> = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .collect();
        assert!(all_insts.iter().any(|i| matches!(i, Inst::Builtin(_, BuiltinOp::MsgSender))));
        assert!(all_insts.iter().any(|i| matches!(i, Inst::Builtin(_, BuiltinOp::BlockTimestamp))));
        assert!(all_insts.iter().any(|i| matches!(i, Inst::Builtin(_, BuiltinOp::MsgValue))));
    }

    #[test]
    fn lower_break_continue() {
        let ir = lower_src(r#"
            contract T {
                pub fn f() {
                    for i in 0..10 {
                        if i == 5 {
                            break;
                        }
                    }
                }
            }
        "#);

        let func = &ir.functions[0];
        let all_insts: Vec<&Inst> = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .collect();
        // break should produce a Jump to the exit label
        let jump_count = all_insts.iter()
            .filter(|i| matches!(i, Inst::Jump(_)))
            .count();
        assert!(jump_count >= 2); // at least: jump to header + break jump to exit
    }

    #[test]
    fn lower_display() {
        let ir = lower_src(r#"
            contract Token {
                storage { supply: u256, }
                #[constructor]
                pub fn init(supply: u256) {
                    self.supply = supply;
                }
            }
        "#);

        // Just verify Display doesn't panic
        let output = format!("{}", ir);
        assert!(output.contains("contract Token"));
        assert!(output.contains("fn init"));
        assert!(output.contains("storage.set"));
    }
}
