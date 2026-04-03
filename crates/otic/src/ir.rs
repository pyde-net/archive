//! OtiIR: intermediate representation for the Otigen compiler.
//!
//! Flat, register-based IR with typed operations and basic blocks.
//! Virtual registers are unlimited — register allocation happens in codegen.
//!
//! Structure: Program → Function → BasicBlock → Instruction

use std::fmt;

use crate::types::Ty;
use ethnum::U256;

/// A virtual register (unlimited, allocated to PVM regs later).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Reg(pub u32);

impl fmt::Display for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "%{}", self.0)
    }
}

/// A label for a basic block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Label(pub u32);

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@L{}", self.0)
    }
}

// ============================================================================
// Program structure
// ============================================================================

/// An entire compiled contract.
#[derive(Clone, Debug)]
pub struct IrProgram {
    pub contract_name: String,
    pub functions: Vec<IrFunction>,
    pub storage_fields: Vec<StorageFieldDef>,
    pub struct_defs: Vec<StructDef>,
    pub enum_defs: Vec<EnumDef>,
    pub event_defs: Vec<EventDef>,
    pub error_defs: Vec<ErrorDef>,
    pub interface_defs: Vec<InterfaceDef>,
    pub const_defs: Vec<ConstDef>,
    pub type_aliases: Vec<TypeAliasDef>,
    pub imports: Vec<ImportDef>,
}

/// A struct definition (for field layout in codegen).
#[derive(Clone, Debug)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<(String, Ty)>,
}

/// An enum definition (for discriminant mapping).
#[derive(Clone, Debug)]
pub struct EnumDef {
    pub name: String,
    pub variants: Vec<String>,
}

/// An event definition (for topic hashing + ABI encoding).
#[derive(Clone, Debug)]
pub struct EventDef {
    pub name: String,
    pub fields: Vec<EventFieldDef>,
    pub doc: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EventFieldDef {
    pub name: String,
    pub ty: Ty,
    pub indexed: bool,
}

/// An error definition (for revert data encoding).
#[derive(Clone, Debug)]
pub struct ErrorDef {
    pub name: String,
    pub fields: Vec<(String, Ty)>,
    pub doc: Option<String>,
}

/// An interface definition (for external call ABI encoding).
#[derive(Clone, Debug)]
pub struct InterfaceDef {
    pub name: String,
    pub functions: Vec<InterfaceFnDef>,
}

#[derive(Clone, Debug)]
pub struct InterfaceFnDef {
    pub name: String,
    pub params: Vec<(String, Ty)>,
    pub return_ty: Ty,
}

/// A constant definition.
#[derive(Clone, Debug)]
pub struct ConstDef {
    pub name: String,
    pub ty: Ty,
    pub value: IrConst,
    pub is_pub: bool,
}

/// A type alias (for ABI readability).
#[derive(Clone, Debug)]
pub struct TypeAliasDef {
    pub name: String,
    pub ty: Ty,
}

/// An import (for module resolution).
#[derive(Clone, Debug)]
pub struct ImportDef {
    pub path: Vec<String>,
}

/// A storage field definition (for slot assignment).
#[derive(Clone, Debug)]
pub struct StorageFieldDef {
    pub name: String,
    pub ty: Ty,
    pub slot: u32,
}

/// A compiled function.
#[derive(Clone, Debug)]
pub struct IrFunction {
    pub name: String,
    pub params: Vec<(String, Ty)>,
    pub return_ty: Ty,
    pub is_pub: bool,
    pub is_constructor: bool,
    pub is_view: bool,
    pub is_reentrant: bool,
    pub is_payable: bool,
    pub is_receive: bool,
    pub is_fallback: bool,
    pub is_test: bool,
    /// If true, the test is expected to revert.
    pub should_panic: bool,
    /// Expected error name for should_panic (e.g., "InsufficientBalance").
    pub expected_error: Option<String>,
    pub sponsorship: Option<crate::ast::Sponsorship>,
    pub doc: Option<String>,
    pub blocks: Vec<BasicBlock>,
    pub next_reg: u32,
    /// Monotonically increasing label counter (avoids collision in nested structures).
    pub next_label: u32,
}

impl IrFunction {
    pub fn new(name: String, params: Vec<(String, Ty)>, return_ty: Ty) -> Self {
        Self {
            name,
            params,
            return_ty,
            is_pub: false,
            is_constructor: false,
            is_view: false,
            is_reentrant: false,
            is_payable: false,
            is_receive: false,
            is_fallback: false,
            is_test: false,
            should_panic: false,
            expected_error: None,
            sponsorship: None,
            doc: None,
            blocks: vec![BasicBlock::new(Label(0), "entry".into())],
            next_reg: 0,
            next_label: 1, // Label(0) is entry
        }
    }

    pub fn alloc_reg(&mut self) -> Reg {
        let r = Reg(self.next_reg);
        self.next_reg += 1;
        r
    }

    pub fn alloc_label(&mut self) -> Label {
        let l = Label(self.next_label);
        self.next_label += 1;
        l
    }

    pub fn current_block(&mut self) -> &mut BasicBlock {
        self.blocks.last_mut().expect("IR function has no blocks")
    }

    pub fn push_block(&mut self, label: Label, name: String) {
        self.blocks.push(BasicBlock::new(label, name));
    }

    pub fn emit(&mut self, inst: Inst) {
        self.current_block().instructions.push(inst);
    }
}

/// A basic block: a sequence of instructions with no internal branches.
#[derive(Clone, Debug)]
pub struct BasicBlock {
    pub label: Label,
    pub name: String,
    pub instructions: Vec<Inst>,
}

impl BasicBlock {
    pub fn new(label: Label, name: String) -> Self {
        Self {
            label,
            name,
            instructions: Vec::new(),
        }
    }
}

// ============================================================================
// Instructions
// ============================================================================

/// An IR instruction.
#[derive(Clone, Debug)]
pub enum Inst {
    /// `%dst = const <value>`
    Const(Reg, IrConst),

    /// `%dst = add/sub/mul/div/mod %lhs, %rhs`
    BinOp(Reg, BinOp, Reg, Reg),

    /// `%dst = neg/not/bitnot %src`
    UnOp(Reg, UnOp, Reg),

    /// `%dst = cmp <op> %lhs, %rhs` → bool
    Cmp(Reg, CmpOp, Reg, Reg),

    /// `%dst = cast %src as <ty>`
    Cast(Reg, Reg, Ty),

    /// `%dst = storage.get "field_name"`
    StorageGet(Reg, String),

    /// `storage.set "field_name", %val`
    StorageSet(String, Reg),

    /// `%dst = storage.map_get "map_name", %key`
    StorageMapGet(Reg, String, Reg),

    /// `storage.map_set "map_name", %key, %val`
    StorageMapSet(String, Reg, Reg),

    /// `%dst = storage.nested_map_get "map_name", %key1, %key2` (for self.map[a][b])
    StorageNestedMapGet(Reg, String, Reg, Reg),

    /// `storage.nested_map_set "map_name", %key1, %key2, %val`
    StorageNestedMapSet(String, Reg, Reg, Reg),

    /// `%dst = builtin <name>` (msg.sender, block.timestamp, etc.)
    Builtin(Reg, BuiltinOp),

    /// `%dst = call "func_name", [args...]`
    Call(Reg, String, Vec<Reg>),

    /// `%dst = method_call %obj, "method", [args...]`
    MethodCall(Reg, Reg, String, Vec<Reg>),

    /// `ext_call %interface_addr, "method", [(arg, type)...], return_type`
    ExtCall(Reg, Reg, String, Vec<(Reg, Ty)>, Ty),

    /// `%dst = hash [args...]`
    Hash(Reg, Vec<Reg>),

    /// `%dst = struct_init "name", [(field, reg)...]`
    StructInit(Reg, String, Vec<(String, Reg)>),

    /// `%dst = field_get %obj, "struct_name", "field_name"`
    FieldGet(Reg, Reg, String, String),

    /// `%dst = index_get %obj, %idx`
    IndexGet(Reg, Reg, Reg),

    /// `index_set %obj, %idx, %val` (for Vec/Array mutation)
    IndexSet(Reg, Reg, Reg),

    /// `%dst = tuple [regs...]`
    MakeTuple(Reg, Vec<Reg>),

    /// `%dst = tuple_get %tuple, index`
    TupleGet(Reg, Reg, u32),

    /// `%dst = array [regs...]`
    MakeArray(Reg, Vec<Reg>),

    /// `%dst = array_repeat %val, count`
    ArrayRepeat(Reg, Reg, u64),

    /// `emit "event_name", [field_regs...]`
    Emit(String, Vec<Reg>),

    /// `revert "error_name", [field_regs...]`
    Revert(String, Vec<Reg>),

    /// `cross_call target, method, [args...], callback`
    CrossCall {
        target: Reg,
        method: Reg,
        args: Vec<Reg>,
        callback: Option<String>,
    },

    /// `raw_call %target, %value, %data`
    RawCall(Reg, Reg, Vec<Reg>),

    /// `%addr = create %deploy_blob, [constructor_args...]` — deploy a new contract.
    /// deploy_blob holds the deploy-format bytes. Returns Address.
    CreateContract(Reg, Reg, Vec<(Reg, Ty)>),

    /// `br @label` — unconditional jump
    Jump(Label),

    /// `br_true %cond, @then, @else` — conditional branch
    Branch(Reg, Label, Label),

    /// `ret` or `ret %val`
    Return(Option<Reg>),

    /// `%dst = phi [(@label, %reg), ...]` — SSA phi node (for optimization)
    Phi(Reg, Vec<(Label, Reg)>),

    /// `%dst = make_vec capacity` — allocate a Vec on heap with given initial capacity.
    MakeVec(Reg, u64),

    /// Comment / debug marker (stripped in codegen)
    Comment(String),
}

// ============================================================================
// Operand types
// ============================================================================

/// A constant value.
#[derive(Clone, Debug)]
pub enum IrConst {
    Int(U256, Ty),       // integer with type (full 256-bit range)
    Bool(bool),
    String(String),
    Address([u8; 32]),   // Address::ZERO etc.
    Bytes(Vec<u8>),
    Unit,
}

/// Binary operations.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BinOp {
    Add, Sub, Mul, Div, Mod,
    BitAnd, BitOr, BitXor, Shl, Shr,
    LogicalAnd, LogicalOr,
}

/// Unary operations.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UnOp {
    Neg,
    LogicalNot,
    BitNot,
}

/// Comparison operations.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CmpOp {
    Eq, NotEq, Lt, Gt, LtEq, GtEq,
}

/// Built-in values.
#[derive(Clone, Debug, PartialEq)]
pub enum BuiltinOp {
    MsgSender,
    MsgValue,
    MsgData,
    BlockTimestamp,
    BlockHeight,
    BlockProposer,
    TxGasPrice,
    TxNonce,
    TxHash,
    TxGasLimit,
    AddressOfSelf,
    GasRemaining,
}

// ============================================================================
// Display (for debugging / `otic ir` command)
// ============================================================================

impl fmt::Display for IrProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "contract {}:", self.contract_name)?;

        if !self.storage_fields.is_empty() {
            for field in &self.storage_fields {
                writeln!(f, "  storage[{}] {}: {}", field.slot, field.name, field.ty)?;
            }
            writeln!(f)?;
        }

        for s in &self.struct_defs {
            let fields: Vec<String> = s.fields.iter().map(|(n, t)| format!("{}: {}", n, t)).collect();
            writeln!(f, "  struct {} {{ {} }}", s.name, fields.join(", "))?;
        }

        for e in &self.enum_defs {
            writeln!(f, "  enum {} {{ {} }}", e.name, e.variants.join(", "))?;
        }

        for ev in &self.event_defs {
            let fields: Vec<String> = ev.fields.iter().map(|ef| {
                let idx = if ef.indexed { "#[indexed] " } else { "" };
                format!("{}{}: {}", idx, ef.name, ef.ty)
            }).collect();
            writeln!(f, "  event {} {{ {} }}", ev.name, fields.join(", "))?;
        }

        for err in &self.error_defs {
            let fields: Vec<String> = err.fields.iter().map(|(n, t)| format!("{}: {}", n, t)).collect();
            writeln!(f, "  error {} {{ {} }}", err.name, fields.join(", "))?;
        }

        if !self.struct_defs.is_empty() || !self.enum_defs.is_empty()
            || !self.event_defs.is_empty() || !self.error_defs.is_empty()
        {
            writeln!(f)?;
        }

        for func in &self.functions {
            write!(f, "{}", func)?;
        }
        Ok(())
    }
}

impl fmt::Display for IrFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let vis = if self.is_pub { "pub " } else { "" };
        let params: Vec<String> = self.params.iter()
            .map(|(name, ty)| format!("{}: {}", name, ty))
            .collect();
        writeln!(f, "  {}fn {}({}) -> {}:", vis, self.name, params.join(", "), self.return_ty)?;

        for block in &self.blocks {
            writeln!(f, "    {}:  // {}", block.label, block.name)?;
            for inst in &block.instructions {
                writeln!(f, "      {}", inst)?;
            }
        }
        writeln!(f)
    }
}

impl fmt::Display for Inst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Inst::Const(dst, val) => write!(f, "{} = const {}", dst, val),
            Inst::BinOp(dst, op, lhs, rhs) => write!(f, "{} = {:?} {}, {}", dst, op, lhs, rhs),
            Inst::UnOp(dst, op, src) => write!(f, "{} = {:?} {}", dst, op, src),
            Inst::Cmp(dst, op, lhs, rhs) => write!(f, "{} = {:?} {}, {}", dst, op, lhs, rhs),
            Inst::Cast(dst, src, ty) => write!(f, "{} = cast {} as {}", dst, src, ty),
            Inst::StorageGet(dst, name) => write!(f, "{} = storage.get \"{}\"", dst, name),
            Inst::StorageSet(name, val) => write!(f, "storage.set \"{}\", {}", name, val),
            Inst::StorageMapGet(dst, name, key) => write!(f, "{} = storage.map_get \"{}\", {}", dst, name, key),
            Inst::StorageMapSet(name, key, val) => write!(f, "storage.map_set \"{}\", {}, {}", name, key, val),
            Inst::StorageNestedMapGet(dst, name, k1, k2) => write!(f, "{} = storage.nested_map_get \"{}\"[{}][{}]", dst, name, k1, k2),
            Inst::StorageNestedMapSet(name, k1, k2, val) => write!(f, "storage.nested_map_set \"{}\"[{}][{}] = {}", name, k1, k2, val),
            Inst::Builtin(dst, op) => write!(f, "{} = builtin.{:?}", dst, op),
            Inst::Call(dst, name, args) => {
                let args_str: Vec<String> = args.iter().map(|r| r.to_string()).collect();
                write!(f, "{} = call \"{}\"({})", dst, name, args_str.join(", "))
            }
            Inst::MethodCall(dst, obj, method, args) => {
                let args_str: Vec<String> = args.iter().map(|r| r.to_string()).collect();
                write!(f, "{} = {}.{}({})", dst, obj, method, args_str.join(", "))
            }
            Inst::ExtCall(dst, addr, method, args, ret_ty) => {
                let args_str: Vec<String> = args.iter().map(|(r, t)| format!("{}:{}", r, t)).collect();
                write!(f, "{}: {} = ext_call {}, \"{}\"({})", dst, ret_ty, addr, method, args_str.join(", "))
            }
            Inst::Hash(dst, args) => {
                let args_str: Vec<String> = args.iter().map(|r| r.to_string()).collect();
                write!(f, "{} = hash({})", dst, args_str.join(", "))
            }
            Inst::StructInit(dst, name, fields) => {
                let fields_str: Vec<String> = fields.iter().map(|(n, r)| format!("{}: {}", n, r)).collect();
                write!(f, "{} = {} {{ {} }}", dst, name, fields_str.join(", "))
            }
            Inst::FieldGet(dst, obj, sname, field) => {
                if sname.is_empty() { write!(f, "{} = {}.{}", dst, obj, field) }
                else { write!(f, "{} = {}:{}.{}", dst, obj, sname, field) }
            }
            Inst::IndexGet(dst, obj, idx) => write!(f, "{} = {}[{}]", dst, obj, idx),
            Inst::IndexSet(obj, idx, val) => write!(f, "{}[{}] = {}", obj, idx, val),
            Inst::MakeTuple(dst, regs) => {
                let args_str: Vec<String> = regs.iter().map(|r| r.to_string()).collect();
                write!(f, "{} = tuple({})", dst, args_str.join(", "))
            }
            Inst::TupleGet(dst, tuple, idx) => write!(f, "{} = {}.{}", dst, tuple, idx),
            Inst::MakeArray(dst, regs) => {
                let args_str: Vec<String> = regs.iter().map(|r| r.to_string()).collect();
                write!(f, "{} = [{}]", dst, args_str.join(", "))
            }
            Inst::ArrayRepeat(dst, val, count) => write!(f, "{} = [{}; {}]", dst, val, count),
            Inst::Emit(name, fields) => {
                let args_str: Vec<String> = fields.iter().map(|r| r.to_string()).collect();
                write!(f, "emit \"{}\"({})", name, args_str.join(", "))
            }
            Inst::Revert(name, fields) => {
                let args_str: Vec<String> = fields.iter().map(|r| r.to_string()).collect();
                write!(f, "revert \"{}\"({})", name, args_str.join(", "))
            }
            Inst::CrossCall { target, method, args, callback } => {
                let args_str: Vec<String> = args.iter().map(|r| r.to_string()).collect();
                let cb = callback.as_deref().unwrap_or("none");
                write!(f, "cross_call {}, {}({}) callback={}", target, method, args_str.join(", "), cb)
            }
            Inst::RawCall(dst, target, args) => {
                let args_str: Vec<String> = args.iter().map(|r| r.to_string()).collect();
                write!(f, "{} = raw_call {}({})", dst, target, args_str.join(", "))
            }
            Inst::CreateContract(dst, blob, args) => {
                let args_str: Vec<String> = args.iter().map(|(r, t)| format!("{}:{}", r, t)).collect();
                write!(f, "{} = create({}, [{}])", dst, blob, args_str.join(", "))
            }
            Inst::Jump(label) => write!(f, "jump {}", label),
            Inst::Branch(cond, then_l, else_l) => write!(f, "br {}, {}, {}", cond, then_l, else_l),
            Inst::Return(None) => write!(f, "ret"),
            Inst::Return(Some(val)) => write!(f, "ret {}", val),
            Inst::Phi(dst, entries) => {
                let entries_str: Vec<String> = entries.iter()
                    .map(|(l, r)| format!("[{}: {}]", l, r)).collect();
                write!(f, "{} = phi {}", dst, entries_str.join(", "))
            }
            Inst::MakeVec(dst, cap) => write!(f, "{} = vec::new(cap={})", dst, cap),
            Inst::Comment(msg) => write!(f, "// {}", msg),
        }
    }
}

impl fmt::Display for IrConst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrConst::Int(v, ty) => write!(f, "{}_{}", v, ty),
            IrConst::Bool(b) => write!(f, "{}", b),
            IrConst::String(s) => write!(f, "\"{}\"", s),
            IrConst::Address(bytes) => {
                if bytes == &[0u8; 32] {
                    write!(f, "Address::ZERO")
                } else {
                    write!(f, "Address(0x{:02x}{:02x}...)", bytes[0], bytes[1])
                }
            }
            IrConst::Bytes(b) => write!(f, "bytes(len={})", b.len()),
            IrConst::Unit => write!(f, "()"),
        }
    }
}
