//! Abstract Syntax Tree for the Otigen language.
//!
//! Every node carries a `Span` for error reporting.

use crate::token::Span;

// ============================================================================
// Common
// ============================================================================

/// An identifier with source location.
#[derive(Clone, Debug, PartialEq)]
pub struct Ident {
    pub name: String,
    pub span: Span,
}

// ============================================================================
// Top-Level
// ============================================================================

/// Root of a .oti source file.
#[derive(Clone, Debug)]
pub struct SourceFile {
    pub items: Vec<Item>,
}

/// A top-level item in a source file.
#[derive(Clone, Debug)]
pub enum Item {
    Use(UseImport),
    Contract(ContractDef),
    Module(ModuleDef),
    Struct(StructDef),
    Enum(EnumDef),
    Const(ConstDef),
    TypeAlias(TypeAliasDef),
    Interface(InterfaceDef),
    Error(ErrorDef),
    Function(FunctionDef),
}

/// `use std::math;` or `use std::token::IERC20;` or `use std::math::{sqrt, pow};`
#[derive(Clone, Debug)]
pub struct UseImport {
    pub path: Vec<Ident>,
    /// Grouped imports: `use std::math::{sqrt, pow};` → items = ["sqrt", "pow"]
    /// Empty for simple imports: `use std::math;`
    pub items: Vec<Ident>,
    pub span: Span,
}

/// `module math_lib;`
#[derive(Clone, Debug)]
pub struct ModuleDef {
    pub name: Ident,
    pub span: Span,
}

/// `contract Token { ... }`
#[derive(Clone, Debug)]
pub struct ContractDef {
    pub name: Ident,
    pub items: Vec<ContractItem>,
    pub span: Span,
}

/// Items inside a contract body.
#[derive(Clone, Debug)]
pub enum ContractItem {
    Storage(StorageBlock),
    Event(EventDef),
    Error(ErrorDef),
    Struct(StructDef),
    Enum(EnumDef),
    Const(ConstDef),
    TypeAlias(TypeAliasDef),
    Function(FunctionDef),
}

// ============================================================================
// Declarations
// ============================================================================

/// `storage { field: Type, ... }`
#[derive(Clone, Debug)]
pub struct StorageBlock {
    pub fields: Vec<StorageField>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct StorageField {
    pub name: Ident,
    pub ty: Type,
    pub span: Span,
}

/// `event Transfer { #[indexed] from: Address, to: Address, amount: u256, }`
#[derive(Clone, Debug)]
pub struct EventDef {
    pub name: Ident,
    pub doc: Option<String>,
    pub fields: Vec<EventField>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct EventField {
    pub name: Ident,
    pub ty: Type,
    pub indexed: bool,
    pub span: Span,
}

/// `error InsufficientBalance { available: u256, required: u256 }`
#[derive(Clone, Debug)]
pub struct ErrorDef {
    pub name: Ident,
    pub doc: Option<String>,
    pub fields: Vec<StructField>,
    pub span: Span,
}

/// `struct Dimensions { length: u32, width: u32 }`
#[derive(Clone, Debug)]
pub struct StructDef {
    pub name: Ident,
    pub fields: Vec<StructField>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct StructField {
    pub name: Ident,
    pub ty: Type,
    pub span: Span,
}

/// `enum OrderStatus { Pending, Active, Filled, Cancelled }`
#[derive(Clone, Debug)]
pub struct EnumDef {
    pub name: Ident,
    pub variants: Vec<Ident>,
    pub span: Span,
}

/// `const MAX_SUPPLY: u256 = 1_000_000;`
#[derive(Clone, Debug)]
pub struct ConstDef {
    pub name: Ident,
    pub ty: Option<Type>,
    pub value: Expr,
    pub is_pub: bool,
    pub span: Span,
}

/// `type TokenId = u256;`
#[derive(Clone, Debug)]
pub struct TypeAliasDef {
    pub name: Ident,
    pub ty: Type,
    pub span: Span,
}

/// `interface IERC20 { fn transfer(to: Address, amount: u256); ... }`
#[derive(Clone, Debug)]
pub struct InterfaceDef {
    pub name: Ident,
    pub functions: Vec<InterfaceFnSig>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct InterfaceFnSig {
    pub name: Ident,
    pub params: Vec<FnParam>,
    pub return_type: Option<Type>,
    pub span: Span,
}

// ============================================================================
// Functions
// ============================================================================

/// A function definition with optional attributes.
#[derive(Clone, Debug)]
pub struct FunctionDef {
    pub name: Ident,
    pub doc: Option<String>,
    pub attributes: Vec<Attribute>,
    pub is_pub: bool,
    pub params: Vec<FnParam>,
    pub return_type: Option<Type>,
    pub body: Block,
    pub span: Span,
}

impl FunctionDef {
    pub fn is_view(&self) -> bool {
        self.attributes.iter().any(|a| a.content == "view")
    }

    pub fn is_constructor(&self) -> bool {
        self.attributes.iter().any(|a| a.content == "constructor")
    }

    pub fn is_reentrant(&self) -> bool {
        self.attributes.iter().any(|a| a.content == "reentrant")
    }

    pub fn is_sponsored(&self) -> bool {
        self.attributes.iter().any(|a| a.content.starts_with("sponsored"))
    }

    /// Returns the sponsorship kind: None, GasTank, or Paymaster(name).
    pub fn sponsorship(&self) -> Option<Sponsorship> {
        for attr in &self.attributes {
            if attr.content == "sponsored" {
                return Some(Sponsorship::GasTank);
            }
            if attr.content.starts_with("sponsored(") && attr.content.ends_with(')') {
                let paymaster = &attr.content[10..attr.content.len() - 1];
                return Some(Sponsorship::Paymaster(paymaster.to_string()));
            }
        }
        None
    }

    pub fn is_test(&self) -> bool {
        self.attributes.iter().any(|a| a.content == "test")
    }

    pub fn has_should_panic(&self) -> bool {
        self.attributes.iter().any(|a| a.content.starts_with("should_panic"))
    }
}

#[derive(Clone, Debug)]
pub struct FnParam {
    pub name: Ident,
    pub ty: Type,
    pub span: Span,
}

/// Gas sponsorship kind for `#[sponsored]` functions.
#[derive(Clone, Debug, PartialEq)]
pub enum Sponsorship {
    /// `#[sponsored]` — gas from caller's gas tank
    GasTank,
    /// `#[sponsored(Paymaster)]` — gas paid by paymaster contract
    Paymaster(String),
}

/// `#[constructor]`, `#[view]`, `#[sponsored(IPaymaster)]`, etc.
#[derive(Clone, Debug)]
pub struct Attribute {
    pub content: String,
    pub span: Span,
}

// ============================================================================
// Types
// ============================================================================

#[derive(Clone, Debug)]
pub enum Type {
    /// `u8`, `u256`, `i64`, `bool`, `Address`, `String`
    Primitive(PrimitiveType, Span),
    /// `bytes`
    Bytes(Span),
    /// `[u8; 32]`
    Array(Box<Type>, u64, Span),
    /// `Vec<Address>`
    Vec(Box<Type>, Span),
    /// `Map<Address, u256>`
    Map(Box<Type>, Box<Type>, Span),
    /// User-defined type: struct name, enum name
    Named(Ident),
    /// `(u256, u256)`
    Tuple(Vec<Type>, Span),
}

#[derive(Clone, Debug, PartialEq)]
pub enum PrimitiveType {
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    I8,
    I16,
    I32,
    I64,
    I128,
    I256,
    Bool,
    Address,
    StringType,
}

// ============================================================================
// Statements
// ============================================================================

/// A block: `{ stmt; stmt; ... }`
#[derive(Clone, Debug)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum Stmt {
    /// `let [mut] name [: Type] = expr;`
    Let(LetStmt),
    /// `expr = expr;` or `expr += expr;`
    Assign(AssignStmt),
    /// `return expr;` or `return;`
    Return(ReturnStmt),
    /// `emit Transfer { from: addr, amount: 100 };`
    Emit(EmitStmt),
    /// `for i in 0..10 { ... }`
    For(ForStmt),
    /// `while cond { ... }`
    While(WhileStmt),
    /// `break;`
    Break(Span),
    /// `continue;`
    Continue(Span),
    /// Expression as statement (function calls, etc.)
    Expr(ExprStmt),
}

#[derive(Clone, Debug)]
pub struct LetStmt {
    pub binding: LetBinding,
    pub is_mutable: bool,
    pub ty: Option<Type>,
    pub initializer: Expr,
    pub span: Span,
}

/// The left-hand side of a `let` statement.
#[derive(Clone, Debug)]
pub enum LetBinding {
    /// `let x = ...`
    Name(Ident),
    /// `let (a, b, c) = ...`
    Tuple(Vec<Ident>, Span),
}

#[derive(Clone, Debug)]
pub struct AssignStmt {
    pub target: Expr,
    pub op: AssignOp,
    pub value: Expr,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AssignOp {
    Assign,      // =
    AddAssign,   // +=
    SubAssign,   // -=
    MulAssign,   // *=
    DivAssign,   // /=
    ModAssign,   // %=
    BitAndAssign, // &=
    BitOrAssign, // |=
    BitXorAssign, // ^=
    ShlAssign,   // <<=
    ShrAssign,   // >>=
}

#[derive(Clone, Debug)]
pub struct ReturnStmt {
    pub value: Option<Expr>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct EmitStmt {
    pub event_name: Ident,
    pub fields: Vec<FieldInit>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct ForStmt {
    pub variable: Ident,
    pub iterator: Expr,
    pub body: Block,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct WhileStmt {
    pub condition: Expr,
    pub body: Block,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct ExprStmt {
    pub expr: Expr,
    pub span: Span,
}

// ============================================================================
// Expressions
// ============================================================================

#[derive(Clone, Debug)]
pub enum Expr {
    /// Integer, string, or bool literal.
    Literal(Literal, Span),
    /// Variable or type name.
    Ident(Ident),
    /// `self`
    SelfExpr(Span),
    /// `a + b`, `x == y`, `0..10`
    Binary(Box<Expr>, BinaryOp, Box<Expr>, Span),
    /// `-x`, `!flag`, `~mask`
    Unary(UnaryOp, Box<Expr>, Span),
    /// `obj.field`
    FieldAccess(Box<Expr>, Ident, Span),
    /// `arr[idx]`
    Index(Box<Expr>, Box<Expr>, Span),
    /// `func(args)` or `obj.method(args)`
    Call(Box<Expr>, Vec<Expr>, Span),
    /// `path::to::item` — `IERC20::at`, `Address::ZERO`, `GameState::Pending`
    Path(Vec<Ident>, Span),
    /// `require!(cond, err)`, `revert!(err)`, `cross_call!(...)`, `raw_call!(...)`
    MacroCall(Ident, Vec<MacroArg>, Span),
    /// `Token { name: "foo", supply: 100 }`
    StructInit(Vec<Ident>, Vec<FieldInit>, Span),
    /// `if cond { ... } else { ... }`
    If(Box<Expr>, Block, Option<ElseClause>, Span),
    /// `match expr { pat => body, ... }`
    Match(Box<Expr>, Vec<MatchArm>, Span),
    /// `{ stmts; expr }`
    Block(Block),
    /// `expr as Type`
    Cast(Box<Expr>, Type, Span),
    /// `(a, b)` tuple or `(expr)` grouping
    Tuple(Vec<Expr>, Span),
    /// `[0u8; 32]` array repeat init
    ArrayRepeat(Box<Expr>, u64, Span),
    /// `[a, b, c]` array literal
    ArrayLiteral(Vec<Expr>, Span),
    /// `try expr`
    Try(Box<Expr>, Span),
}

#[derive(Clone, Debug)]
pub enum Literal {
    Int(u128),
    String(String),
    Bool(bool),
}

#[derive(Clone, Debug, PartialEq)]
pub enum BinaryOp {
    Add, Sub, Mul, Div, Mod,
    BitAnd, BitOr, BitXor, Shl, Shr,
    LogicalAnd, LogicalOr,
    Eq, NotEq, Lt, Gt, LtEq, GtEq,
    Range,
}

#[derive(Clone, Debug, PartialEq)]
pub enum UnaryOp {
    Negate,     // -
    LogicalNot, // !
    BitNot,     // ~
}

/// An argument to a macro call. Macros have mixed positional and named args.
/// `cross_call!(target: "oracle", method: "get_price", args: (pair,), callback: "on_price")`
#[derive(Clone, Debug)]
pub enum MacroArg {
    /// Positional: `expr`
    Positional(Expr),
    /// Named: `key: expr`
    Named(Ident, Expr),
}

#[derive(Clone, Debug)]
pub struct FieldInit {
    pub name: Ident,
    pub value: Expr,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum ElseClause {
    ElseBlock(Block),
    ElseIf(Box<Expr>), // wraps Expr::If
}

#[derive(Clone, Debug)]
pub struct MatchArm {
    pub pattern: Pattern,
    pub body: Expr,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum Pattern {
    /// `42`, `"hello"`, `true`
    Literal(Literal, Span),
    /// `GameState::Active` or just `Active`
    Path(Vec<Ident>, Span),
    /// `100..200` — range pattern (inclusive start, exclusive end)
    Range(Literal, Literal, Span),
    /// `_`
    Wildcard(Span),
}
