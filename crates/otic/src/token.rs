//! Token types for the Otigen language.

use ethnum::U256;

/// Source location: line and column (both 1-based).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub line: u32,
    pub col: u32,
    pub offset: u32,
    pub len: u32,
}

/// A token with its source location.
#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

/// All token types in the Otigen language.
#[derive(Clone, Debug, PartialEq)]
pub enum TokenKind {
    // === Literals ===
    /// Integer literal (decimal or hex): `42`, `0xFF`, `1_000_000`
    IntLiteral(U256),
    /// String literal: `"hello world"`
    StringLiteral(String),
    /// Boolean `true`
    True,
    /// Boolean `false`
    False,

    // === Identifiers ===
    /// Identifier: variable, function, type name
    Ident(String),

    // === Keywords ===
    Contract,
    Storage,
    Struct,
    Interface,
    Event,
    Error,
    Enum,
    Const,
    Fn,
    Pub,
    Let,
    Mut,
    If,
    Else,
    For,
    While,
    Match,
    Return,
    Emit,
    Try,
    Use,
    Module,
    In,
    As,
    Break,
    Continue,
    SelfKw, // `self`
    TypeKw, // `type` alias

    // === Attributes ===
    /// `#[...]` attribute (the content is stored as string)
    Attribute(String),

    // === Arithmetic operators ===
    Plus,    // +   addition
    Minus,   // -   subtraction / unary negation
    Star,    // *   multiplication
    Slash,   // /   division
    Percent, // %   modulo

    // === Bitwise operators ===
    Amp,   // &   bitwise AND
    Pipe,  // |   bitwise OR
    Caret, // ^   bitwise XOR
    Tilde, // ~   bitwise NOT (complement)

    // === Logical operators ===
    AmpAmp,   // &&  logical AND (short-circuit)
    PipePipe, // ||  logical OR (short-circuit)
    Bang,     // !   logical NOT

    // === Comparison operators ===
    EqEq,   // ==  equal
    BangEq, // !=  not equal
    Lt,     // <   less than
    Gt,     // >   greater than
    LtEq,   // <=  less than or equal
    GtEq,   // >=  greater than or equal

    // === Shift operators ===
    Shl, // <<  shift left
    Shr, // >>  shift right

    // === Assignment operators ===
    Eq,        // =   assign
    PlusEq,    // +=  add-assign
    MinusEq,   // -=  subtract-assign
    StarEq,    // *=  multiply-assign
    SlashEq,   // /=  divide-assign
    PercentEq, // %=  modulo-assign
    AmpEq,     // &=  bitwise AND-assign
    PipeEq,    // |=  bitwise OR-assign
    CaretEq,   // ^=  bitwise XOR-assign
    ShlEq,     // <<= shift-left-assign
    ShrEq,     // >>= shift-right-assign

    // === Range operator ===
    DotDot, // ..  range

    // === Punctuation ===
    LBrace,     // {
    RBrace,     // }
    LParen,     // (
    RParen,     // )
    LBracket,   // [
    RBracket,   // ]
    Comma,      // ,
    Semicolon,  // ;
    Colon,      // :
    ColonColon, // ::
    Dot,        // .
    Arrow,      // ->
    FatArrow,   // =>
    Hash,       // #
    Underscore, // _ (wildcard in match)
    Question,   // ?

    // === Special ===
    /// Doc comment: `/// description text`
    DocComment(String),
    /// End of file.
    Eof,
}

impl TokenKind {
    /// Look up a keyword from an identifier string.
    pub fn keyword(s: &str) -> Option<TokenKind> {
        match s {
            "contract" => Some(TokenKind::Contract),
            "storage" => Some(TokenKind::Storage),
            "struct" => Some(TokenKind::Struct),
            "interface" => Some(TokenKind::Interface),
            "event" => Some(TokenKind::Event),
            "error" => Some(TokenKind::Error),
            "enum" => Some(TokenKind::Enum),
            "const" => Some(TokenKind::Const),
            "fn" => Some(TokenKind::Fn),
            "pub" => Some(TokenKind::Pub),
            "let" => Some(TokenKind::Let),
            "mut" => Some(TokenKind::Mut),
            "if" => Some(TokenKind::If),
            "else" => Some(TokenKind::Else),
            "for" => Some(TokenKind::For),
            "while" => Some(TokenKind::While),
            "match" => Some(TokenKind::Match),
            "return" => Some(TokenKind::Return),
            "emit" => Some(TokenKind::Emit),
            "try" => Some(TokenKind::Try),
            "use" => Some(TokenKind::Use),
            "module" => Some(TokenKind::Module),
            "in" => Some(TokenKind::In),
            "as" => Some(TokenKind::As),
            "break" => Some(TokenKind::Break),
            "continue" => Some(TokenKind::Continue),
            "self" => Some(TokenKind::SelfKw),
            "type" => Some(TokenKind::TypeKw),
            "true" => Some(TokenKind::True),
            "false" => Some(TokenKind::False),
            _ => None,
        }
    }

    /// Whether this token is a keyword.
    pub fn is_keyword(&self) -> bool {
        matches!(
            self,
            TokenKind::Contract
                | TokenKind::Storage
                | TokenKind::Struct
                | TokenKind::Interface
                | TokenKind::Event
                | TokenKind::Error
                | TokenKind::Enum
                | TokenKind::Const
                | TokenKind::Fn
                | TokenKind::Pub
                | TokenKind::Let
                | TokenKind::Mut
                | TokenKind::If
                | TokenKind::Else
                | TokenKind::For
                | TokenKind::While
                | TokenKind::Match
                | TokenKind::Return
                | TokenKind::Emit
                | TokenKind::Try
                | TokenKind::Use
                | TokenKind::Module
                | TokenKind::In
                | TokenKind::As
                | TokenKind::Break
                | TokenKind::Continue
                | TokenKind::SelfKw
                | TokenKind::TypeKw
                | TokenKind::True
                | TokenKind::False
        )
    }

    /// Whether this token is a literal (int, string, bool).
    pub fn is_literal(&self) -> bool {
        matches!(
            self,
            TokenKind::IntLiteral(_)
                | TokenKind::StringLiteral(_)
                | TokenKind::True
                | TokenKind::False
        )
    }

    /// Whether this token is an operator.
    pub fn is_operator(&self) -> bool {
        matches!(
            self,
            TokenKind::Plus
                | TokenKind::Minus
                | TokenKind::Star
                | TokenKind::Slash
                | TokenKind::Percent
                | TokenKind::Amp
                | TokenKind::Pipe
                | TokenKind::Caret
                | TokenKind::Tilde
                | TokenKind::AmpAmp
                | TokenKind::PipePipe
                | TokenKind::Bang
                | TokenKind::EqEq
                | TokenKind::BangEq
                | TokenKind::Lt
                | TokenKind::Gt
                | TokenKind::LtEq
                | TokenKind::GtEq
                | TokenKind::Shl
                | TokenKind::Shr
                | TokenKind::Eq
                | TokenKind::PlusEq
                | TokenKind::MinusEq
                | TokenKind::StarEq
                | TokenKind::SlashEq
                | TokenKind::PercentEq
                | TokenKind::AmpEq
                | TokenKind::PipeEq
                | TokenKind::CaretEq
                | TokenKind::ShlEq
                | TokenKind::ShrEq
                | TokenKind::DotDot
        )
    }

    /// Whether this token is an assignment operator (=, +=, -=, etc.).
    pub fn is_assignment(&self) -> bool {
        matches!(
            self,
            TokenKind::Eq
                | TokenKind::PlusEq
                | TokenKind::MinusEq
                | TokenKind::StarEq
                | TokenKind::SlashEq
                | TokenKind::PercentEq
                | TokenKind::AmpEq
                | TokenKind::PipeEq
                | TokenKind::CaretEq
                | TokenKind::ShlEq
                | TokenKind::ShrEq
        )
    }

    /// Whether this token is punctuation.
    pub fn is_punctuation(&self) -> bool {
        matches!(
            self,
            TokenKind::LBrace
                | TokenKind::RBrace
                | TokenKind::LParen
                | TokenKind::RParen
                | TokenKind::LBracket
                | TokenKind::RBracket
                | TokenKind::Comma
                | TokenKind::Semicolon
                | TokenKind::Colon
                | TokenKind::ColonColon
                | TokenKind::Dot
                | TokenKind::Arrow
                | TokenKind::FatArrow
                | TokenKind::Hash
                | TokenKind::Underscore
                | TokenKind::Question
        )
    }

    /// Human-readable name for this token kind. Covers all variants.
    pub fn description(&self) -> &'static str {
        match self {
            // Literals
            TokenKind::IntLiteral(_) => "integer literal",
            TokenKind::StringLiteral(_) => "string literal",
            TokenKind::True => "true",
            TokenKind::False => "false",
            // Identifiers
            TokenKind::Ident(_) => "identifier",
            // Keywords
            TokenKind::Contract => "contract",
            TokenKind::Storage => "storage",
            TokenKind::Struct => "struct",
            TokenKind::Interface => "interface",
            TokenKind::Event => "event",
            TokenKind::Error => "error",
            TokenKind::Fn => "fn",
            TokenKind::Pub => "pub",
            TokenKind::Let => "let",
            TokenKind::Mut => "mut",
            TokenKind::If => "if",
            TokenKind::Else => "else",
            TokenKind::For => "for",
            TokenKind::While => "while",
            TokenKind::Match => "match",
            TokenKind::Return => "return",
            TokenKind::Emit => "emit",
            TokenKind::Try => "try",
            TokenKind::Use => "use",
            TokenKind::Module => "module",
            TokenKind::In => "in",
            TokenKind::As => "as",
            TokenKind::Break => "break",
            TokenKind::Continue => "continue",
            TokenKind::SelfKw => "self",
            TokenKind::TypeKw => "type",
            TokenKind::Enum => "enum",
            TokenKind::Const => "const",
            // Attributes
            TokenKind::Attribute(_) => "attribute",
            // Operators
            TokenKind::Plus => "+",
            TokenKind::Minus => "-",
            TokenKind::Star => "*",
            TokenKind::Slash => "/",
            TokenKind::Percent => "%",
            TokenKind::Amp => "&",
            TokenKind::Pipe => "|",
            TokenKind::Caret => "^",
            TokenKind::Tilde => "~",
            TokenKind::AmpAmp => "&&",
            TokenKind::PipePipe => "||",
            TokenKind::Bang => "!",
            TokenKind::EqEq => "==",
            TokenKind::BangEq => "!=",
            TokenKind::Lt => "<",
            TokenKind::Gt => ">",
            TokenKind::LtEq => "<=",
            TokenKind::GtEq => ">=",
            TokenKind::Shl => "<<",
            TokenKind::Shr => ">>",
            TokenKind::Eq => "=",
            TokenKind::PlusEq => "+=",
            TokenKind::MinusEq => "-=",
            TokenKind::StarEq => "*=",
            TokenKind::SlashEq => "/=",
            TokenKind::PercentEq => "%=",
            TokenKind::AmpEq => "&=",
            TokenKind::PipeEq => "|=",
            TokenKind::CaretEq => "^=",
            TokenKind::ShlEq => "<<=",
            TokenKind::ShrEq => ">>=",
            TokenKind::DotDot => "..",
            // Punctuation
            TokenKind::LBrace => "{",
            TokenKind::RBrace => "}",
            TokenKind::LParen => "(",
            TokenKind::RParen => ")",
            TokenKind::LBracket => "[",
            TokenKind::RBracket => "]",
            TokenKind::Comma => ",",
            TokenKind::Semicolon => ";",
            TokenKind::Colon => ":",
            TokenKind::ColonColon => "::",
            TokenKind::Dot => ".",
            TokenKind::Arrow => "->",
            TokenKind::FatArrow => "=>",
            TokenKind::Hash => "#",
            TokenKind::Underscore => "_",
            TokenKind::Question => "?",
            // Special
            TokenKind::DocComment(_) => "doc comment",
            TokenKind::Eof => "end of file",
        }
    }
}

impl std::fmt::Display for TokenKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenKind::IntLiteral(v) => write!(f, "{v}"),
            TokenKind::StringLiteral(s) => write!(f, "\"{s}\""),
            TokenKind::Ident(s) => write!(f, "{s}"),
            TokenKind::Attribute(s) => write!(f, "#[{s}]"),
            TokenKind::DocComment(s) => write!(f, "/// {s}"),
            _ => write!(f, "{}", self.description()),
        }
    }
}

impl std::fmt::Display for Span {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.line, self.col)
    }
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at {}", self.kind, self.span)
    }
}
