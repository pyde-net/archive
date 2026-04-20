//! Recursive descent parser for Otigen.
//!
//! Consumes a token stream from the lexer and produces an AST.
//! Uses precedence climbing for expressions.

use crate::ast::*;
use crate::token::{Span, Token, TokenKind};

/// A parse error with source location.
#[derive(Clone, Debug)]
pub struct ParseError {
    pub message: String,
    pub span: Span,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.span.line, self.span.col, self.message)
    }
}

/// The parser state.
pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    errors: Vec<ParseError>,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            pos: 0,
            errors: Vec::new(),
        }
    }

    /// Parse the entire source file.
    pub fn parse(mut self) -> (SourceFile, Vec<ParseError>) {
        let mut items = Vec::new();

        while !self.at_eof() {
            match self.parse_item() {
                Ok(item) => items.push(item),
                Err(_) => {
                    // Error recovery: skip to next top-level keyword or EOF
                    self.recover_to_item();
                }
            }
        }

        (SourceFile { items }, self.errors)
    }

    // ========================================================================
    // Token helpers
    // ========================================================================

    fn peek(&self) -> &TokenKind {
        self.tokens.get(self.pos).map(|t| &t.kind).unwrap_or(&TokenKind::Eof)
    }

    fn peek_span(&self) -> Span {
        self.tokens.get(self.pos).map(|t| t.span).unwrap_or(Span {
            line: 0, col: 0, offset: 0, len: 0,
        })
    }

    fn at(&self, kind: &TokenKind) -> bool {
        std::mem::discriminant(self.peek()) == std::mem::discriminant(kind)
    }

    fn at_eof(&self) -> bool {
        matches!(self.peek(), TokenKind::Eof)
    }

    fn advance(&mut self) -> Token {
        let tok = self.tokens.get(self.pos).cloned().unwrap_or(Token {
            kind: TokenKind::Eof,
            span: Span { line: 0, col: 0, offset: 0, len: 0 },
        });
        self.pos += 1;
        tok
    }

    fn expect(&mut self, kind: &TokenKind) -> Result<Token, ()> {
        if self.at(kind) {
            Ok(self.advance())
        } else {
            self.error(format!("expected {}, found {}", kind.description(), self.peek().description()));
            Err(())
        }
    }

    fn expect_ident(&mut self) -> Result<Ident, ()> {
        match self.peek().clone() {
            TokenKind::Ident(_) => {
                let tok = self.advance();
                if let TokenKind::Ident(name) = tok.kind {
                    Ok(Ident { name, span: tok.span })
                } else {
                    unreachable!()
                }
            }
            _ => {
                self.error(format!("expected identifier, found {}", self.peek().description()));
                Err(())
            }
        }
    }

    fn expect_semi(&mut self) -> Result<(), ()> {
        self.expect(&TokenKind::Semicolon)?;
        Ok(())
    }

    /// Expect a `>` token, but also accept `>>` (Shr) by splitting it into
    /// two `>` tokens. This handles nested generics like `Map<Address, Map<Address, u256>>`.
    fn expect_gt(&mut self) -> Result<Token, ()> {
        if self.at(&TokenKind::Gt) {
            Ok(self.advance())
        } else if self.at(&TokenKind::Shr) {
            // Split >> into > + >: consume the >> but leave a virtual > behind
            let tok = self.advance();
            // Insert a synthetic > token at the current position
            let gt_span = Span {
                line: tok.span.line,
                col: tok.span.col + 1,
                offset: tok.span.offset + 1,
                len: 1,
            };
            self.tokens.insert(self.pos, Token { kind: TokenKind::Gt, span: gt_span });
            Ok(Token { kind: TokenKind::Gt, span: tok.span })
        } else {
            self.error(format!("expected >, found {}", self.peek().description()));
            Err(())
        }
    }

    fn eat(&mut self, kind: &TokenKind) -> bool {
        if self.at(kind) {
            self.advance();
            true
        } else {
            false
        }
    }

    /// Consume an optional integer type suffix: u8, u256, i32, _u64, etc.
    fn eat_int_suffix(&mut self) {
        if let TokenKind::Ident(ref s) = self.peek() {
            let suffix = s.strip_prefix('_').unwrap_or(s.as_str());
            match suffix {
                "u8" | "u16" | "u32" | "u64" | "u128" | "u256"
                | "i8" | "i16" | "i32" | "i64" | "i128" | "i256" => {
                    self.advance();
                }
                _ => {}
            }
        }
    }

    fn error(&mut self, message: String) {
        let span = self.peek_span();
        self.errors.push(ParseError { message, span });
    }

    fn recover_to_item(&mut self) {
        while !self.at_eof() {
            match self.peek() {
                TokenKind::Contract | TokenKind::Struct | TokenKind::Enum
                | TokenKind::Const | TokenKind::TypeKw | TokenKind::Interface
                | TokenKind::Use | TokenKind::Module | TokenKind::Error
                | TokenKind::Fn | TokenKind::Pub => return,
                TokenKind::Attribute(_) | TokenKind::DocComment(_) => return,
                _ => { self.advance(); }
            }
        }
    }

    fn recover_to_stmt(&mut self) {
        while !self.at_eof() {
            match self.peek() {
                TokenKind::RBrace => return,
                TokenKind::Semicolon => { self.advance(); return; }
                TokenKind::Let | TokenKind::Return | TokenKind::Emit
                | TokenKind::For | TokenKind::While | TokenKind::If
                | TokenKind::Break | TokenKind::Continue | TokenKind::Match => return,
                _ => { self.advance(); }
            }
        }
    }

    // ========================================================================
    // Top-level items
    // ========================================================================

    fn parse_item(&mut self) -> Result<Item, ()> {
        // Collect doc comments and attributes
        let doc = self.parse_doc_comments();
        let attrs = self.parse_attributes();

        match self.peek() {
            TokenKind::Use => Ok(Item::Use(self.parse_use()?)),
            TokenKind::Module => Ok(Item::Module(self.parse_module()?)),
            TokenKind::Contract => Ok(Item::Contract(self.parse_contract(attrs)?)),
            TokenKind::Struct => Ok(Item::Struct(self.parse_struct()?)),
            TokenKind::Enum => Ok(Item::Enum(self.parse_enum()?)),
            TokenKind::Interface => Ok(Item::Interface(self.parse_interface()?)),
            TokenKind::Error => Ok(Item::Error(self.parse_error_def_with_doc(doc)?)),
            TokenKind::Const => Ok(Item::Const(self.parse_const(false)?)),
            TokenKind::TypeKw => Ok(Item::TypeAlias(self.parse_type_alias()?)),
            TokenKind::Pub => {
                self.advance(); // eat 'pub'
                match self.peek() {
                    TokenKind::Fn => Ok(Item::Function(self.parse_function_with_doc(doc, attrs, true)?)),
                    TokenKind::Const => Ok(Item::Const(self.parse_const(true)?)),
                    _ => {
                        self.error("expected 'fn' or 'const' after 'pub'".into());
                        Err(())
                    }
                }
            }
            TokenKind::Fn => Ok(Item::Function(self.parse_function_with_doc(doc, attrs, false)?)),
            _ => {
                self.error(format!("expected item, found {}", self.peek().description()));
                Err(())
            }
        }
    }

    /// Collect consecutive `///` doc comment lines into a single string.
    fn parse_doc_comments(&mut self) -> Option<String> {
        let mut lines = Vec::new();
        while let TokenKind::DocComment(_) = self.peek() {
            let tok = self.advance();
            if let TokenKind::DocComment(content) = tok.kind {
                lines.push(content);
            }
        }
        if lines.is_empty() {
            None
        } else {
            Some(lines.join("\n"))
        }
    }

    fn parse_attributes(&mut self) -> Vec<Attribute> {
        let mut attrs = Vec::new();
        while let TokenKind::Attribute(_) = self.peek() {
            let tok = self.advance();
            if let TokenKind::Attribute(content) = tok.kind {
                attrs.push(Attribute { content, span: tok.span });
            }
        }
        attrs
    }

    fn parse_use(&mut self) -> Result<UseImport, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::Use)?;
        let mut path = vec![self.expect_ident()?];
        while self.eat(&TokenKind::ColonColon) {
            // Check for grouped import: use std::math::{sqrt, pow};
            if self.at(&TokenKind::LBrace) {
                self.advance(); // eat {
                let mut items = Vec::new();
                while !self.at(&TokenKind::RBrace) && !self.at_eof() {
                    items.push(self.expect_ident()?);
                    if !self.eat(&TokenKind::Comma) {
                        break;
                    }
                }
                self.expect(&TokenKind::RBrace)?;
                self.expect_semi()?;
                return Ok(UseImport { path, items, span: start });
            }
            path.push(self.expect_ident()?);
        }
        self.expect_semi()?;
        Ok(UseImport { path, items: vec![], span: start })
    }

    fn parse_module(&mut self) -> Result<ModuleDef, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::Module)?;
        let name = self.expect_ident()?;
        self.expect_semi()?;
        Ok(ModuleDef { name, span: start })
    }

    fn parse_contract(&mut self, _attrs: Vec<Attribute>) -> Result<ContractDef, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::Contract)?;
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LBrace)?;

        let mut items = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            match self.parse_contract_item() {
                Ok(item) => items.push(item),
                Err(_) => self.recover_to_contract_item(),
            }
        }

        self.expect(&TokenKind::RBrace)?;
        Ok(ContractDef { name, items, span: start })
    }

    fn parse_contract_item(&mut self) -> Result<ContractItem, ()> {
        let doc = self.parse_doc_comments();
        let attrs = self.parse_attributes();

        match self.peek() {
            TokenKind::Storage => Ok(ContractItem::Storage(self.parse_storage()?)),
            TokenKind::Event => Ok(ContractItem::Event(self.parse_event_with_doc(doc)?)),
            TokenKind::Error => Ok(ContractItem::Error(self.parse_error_def_with_doc(doc)?)),
            TokenKind::Struct => Ok(ContractItem::Struct(self.parse_struct()?)),
            TokenKind::Enum => Ok(ContractItem::Enum(self.parse_enum()?)),
            TokenKind::Const => Ok(ContractItem::Const(self.parse_const(false)?)),
            TokenKind::TypeKw => Ok(ContractItem::TypeAlias(self.parse_type_alias()?)),
            TokenKind::Pub => {
                self.advance(); // eat 'pub'
                match self.peek() {
                    TokenKind::Fn => Ok(ContractItem::Function(self.parse_function_with_doc(doc, attrs, true)?)),
                    TokenKind::Const => Ok(ContractItem::Const(self.parse_const(true)?)),
                    _ => {
                        self.error("expected 'fn' or 'const' after 'pub'".into());
                        Err(())
                    }
                }
            }
            TokenKind::Fn => Ok(ContractItem::Function(self.parse_function_with_doc(doc, attrs, false)?)),
            _ => {
                self.error(format!("expected contract item, found {}", self.peek().description()));
                Err(())
            }
        }
    }

    fn recover_to_contract_item(&mut self) {
        while !self.at_eof() {
            match self.peek() {
                TokenKind::RBrace => return,
                TokenKind::Storage | TokenKind::Event | TokenKind::Error
                | TokenKind::Struct | TokenKind::Enum | TokenKind::Const
                | TokenKind::Fn | TokenKind::Pub => return,
                TokenKind::Attribute(_) | TokenKind::DocComment(_) => return,
                _ => { self.advance(); }
            }
        }
    }

    // ========================================================================
    // Storage, Event, Error, Struct, Enum, Const, Interface
    // ========================================================================

    fn parse_storage(&mut self) -> Result<StorageBlock, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::Storage)?;
        self.expect(&TokenKind::LBrace)?;

        let mut fields = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            let fname = self.expect_ident()?;
            self.expect(&TokenKind::Colon)?;
            let ty = self.parse_type()?;
            let fspan = fname.span;
            fields.push(StorageField { name: fname, ty, span: fspan });
            // Require comma between fields (trailing comma before } is optional)
            if !self.at(&TokenKind::RBrace) {
                self.expect(&TokenKind::Comma)?;
            } else {
                self.eat(&TokenKind::Comma); // allow trailing comma
            }
        }

        self.expect(&TokenKind::RBrace)?;
        Ok(StorageBlock { fields, span: start })
    }

    fn parse_event_with_doc(&mut self, doc: Option<String>) -> Result<EventDef, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::Event)?;
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LBrace)?;

        let mut fields = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            let indexed = if let TokenKind::Attribute(ref s) = self.peek() {
                if s == "indexed" { self.advance(); true } else { false }
            } else {
                false
            };
            let fname = self.expect_ident()?;
            self.expect(&TokenKind::Colon)?;
            let ty = self.parse_type()?;
            let fspan = fname.span;
            fields.push(EventField { name: fname, ty, indexed, span: fspan });
            if !self.at(&TokenKind::RBrace) {
                self.expect(&TokenKind::Comma)?;
            } else {
                self.eat(&TokenKind::Comma);
            }
        }

        self.expect(&TokenKind::RBrace)?;
        Ok(EventDef { name, doc, fields, span: start })
    }

    fn parse_error_def_with_doc(&mut self, doc: Option<String>) -> Result<ErrorDef, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::Error)?;
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LBrace)?;

        let mut fields = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            let fname = self.expect_ident()?;
            self.expect(&TokenKind::Colon)?;
            let ty = self.parse_type()?;
            let fspan = fname.span;
            fields.push(StructField { name: fname, ty, span: fspan });
            if !self.at(&TokenKind::RBrace) {
                self.expect(&TokenKind::Comma)?;
            } else {
                self.eat(&TokenKind::Comma);
            }
        }

        self.expect(&TokenKind::RBrace)?;
        Ok(ErrorDef { name, doc, fields, span: start })
    }

    fn parse_struct(&mut self) -> Result<StructDef, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::Struct)?;
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LBrace)?;

        let mut fields = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            let fname = self.expect_ident()?;
            self.expect(&TokenKind::Colon)?;
            let ty = self.parse_type()?;
            let fspan = fname.span;
            fields.push(StructField { name: fname, ty, span: fspan });
            if !self.at(&TokenKind::RBrace) {
                self.expect(&TokenKind::Comma)?;
            } else {
                self.eat(&TokenKind::Comma);
            }
        }

        self.expect(&TokenKind::RBrace)?;
        Ok(StructDef { name, fields, span: start })
    }

    fn parse_enum(&mut self) -> Result<EnumDef, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::Enum)?;
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LBrace)?;

        let mut variants = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            variants.push(self.expect_ident()?);
            // Skip optional `= value` (enum discriminant)
            if self.eat(&TokenKind::Eq) {
                self.parse_expr()?; // consume the value expression
            }
            if !self.at(&TokenKind::RBrace) {
                self.expect(&TokenKind::Comma)?;
            } else {
                self.eat(&TokenKind::Comma);
            }
        }

        self.expect(&TokenKind::RBrace)?;
        Ok(EnumDef { name, variants, span: start })
    }

    fn parse_const(&mut self, is_pub: bool) -> Result<ConstDef, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::Const)?;
        let name = self.expect_ident()?;

        let ty = if self.eat(&TokenKind::Colon) {
            Some(self.parse_type()?)
        } else {
            None
        };

        self.expect(&TokenKind::Eq)?;
        let value = self.parse_expr()?;
        self.expect_semi()?;

        Ok(ConstDef { name, ty, value, is_pub, span: start })
    }

    fn parse_type_alias(&mut self) -> Result<TypeAliasDef, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::TypeKw)?;
        let name = self.expect_ident()?;
        self.expect(&TokenKind::Eq)?;
        let ty = self.parse_type()?;
        self.expect_semi()?;
        Ok(TypeAliasDef { name, ty, span: start })
    }

    fn parse_interface(&mut self) -> Result<InterfaceDef, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::Interface)?;
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LBrace)?;

        let mut functions = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            functions.push(self.parse_interface_fn()?);
        }

        self.expect(&TokenKind::RBrace)?;
        Ok(InterfaceDef { name, functions, span: start })
    }

    fn parse_interface_fn(&mut self) -> Result<InterfaceFnSig, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::Fn)?;
        let name = self.expect_ident()?;
        let params = self.parse_params()?;
        let return_type = if self.eat(&TokenKind::Arrow) {
            Some(self.parse_type()?)
        } else {
            None
        };
        self.expect_semi()?;
        Ok(InterfaceFnSig { name, params, return_type, span: start })
    }

    // ========================================================================
    // Functions
    // ========================================================================

    fn parse_function_with_doc(&mut self, doc: Option<String>, attrs: Vec<Attribute>, is_pub: bool) -> Result<FunctionDef, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::Fn)?;
        let name = self.expect_ident()?;
        let params = self.parse_params()?;
        let return_type = if self.eat(&TokenKind::Arrow) {
            Some(self.parse_type()?)
        } else {
            None
        };
        let body = self.parse_block()?;

        Ok(FunctionDef {
            name, doc, attributes: attrs, is_pub, params, return_type, body, span: start,
        })
    }

    fn parse_params(&mut self) -> Result<Vec<FnParam>, ()> {
        self.expect(&TokenKind::LParen)?;
        let mut params = Vec::new();

        while !self.at(&TokenKind::RParen) && !self.at_eof() {
            let name = self.expect_ident()?;
            self.expect(&TokenKind::Colon)?;
            let ty = self.parse_type()?;
            let span = name.span;
            params.push(FnParam { name, ty, span });
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }

        self.expect(&TokenKind::RParen)?;
        Ok(params)
    }

    // ========================================================================
    // Types
    // ========================================================================

    fn parse_type(&mut self) -> Result<Type, ()> {
        let span = self.peek_span();

        // Tuple type: (T1, T2, ...)
        if self.at(&TokenKind::LParen) {
            return self.parse_tuple_type();
        }

        // Array type: [T; N]
        if self.at(&TokenKind::LBracket) {
            return self.parse_array_type();
        }

        match self.peek().clone() {
            TokenKind::Ident(ref name) => {
                let name_str = name.clone();
                match name_str.as_str() {
                    // Primitive types
                    "u8" => { self.advance(); Ok(Type::Primitive(PrimitiveType::U8, span)) }
                    "u16" => { self.advance(); Ok(Type::Primitive(PrimitiveType::U16, span)) }
                    "u32" => { self.advance(); Ok(Type::Primitive(PrimitiveType::U32, span)) }
                    "u64" => { self.advance(); Ok(Type::Primitive(PrimitiveType::U64, span)) }
                    "u128" => { self.advance(); Ok(Type::Primitive(PrimitiveType::U128, span)) }
                    "u256" => { self.advance(); Ok(Type::Primitive(PrimitiveType::U256, span)) }
                    "i8" => { self.advance(); Ok(Type::Primitive(PrimitiveType::I8, span)) }
                    "i16" => { self.advance(); Ok(Type::Primitive(PrimitiveType::I16, span)) }
                    "i32" => { self.advance(); Ok(Type::Primitive(PrimitiveType::I32, span)) }
                    "i64" => { self.advance(); Ok(Type::Primitive(PrimitiveType::I64, span)) }
                    "i128" => { self.advance(); Ok(Type::Primitive(PrimitiveType::I128, span)) }
                    "i256" => { self.advance(); Ok(Type::Primitive(PrimitiveType::I256, span)) }
                    "bool" => { self.advance(); Ok(Type::Primitive(PrimitiveType::Bool, span)) }
                    "Address" => { self.advance(); Ok(Type::Primitive(PrimitiveType::Address, span)) }
                    "String" => { self.advance(); Ok(Type::Primitive(PrimitiveType::StringType, span)) }
                    "bytes" => { self.advance(); Ok(Type::Bytes(span)) }
                    // Generic types
                    "Vec" => {
                        self.advance();
                        self.expect(&TokenKind::Lt)?;
                        let elem = self.parse_type()?;
                        self.expect_gt()?;
                        Ok(Type::Vec(Box::new(elem), span))
                    }
                    "Map" => {
                        self.advance();
                        self.expect(&TokenKind::Lt)?;
                        let key = self.parse_type()?;
                        self.expect(&TokenKind::Comma)?;
                        let val = self.parse_type()?;
                        self.expect_gt()?;
                        Ok(Type::Map(Box::new(key), Box::new(val), span))
                    }
                    // Named type: struct, enum, contract, or qualified path (types::TokenId)
                    _ => {
                        let mut path = vec![self.expect_ident()?];
                        while self.eat(&TokenKind::ColonColon) {
                            path.push(self.expect_ident()?);
                        }
                        Ok(Type::Named(path))
                    }
                }
            }
            _ => {
                self.error(format!("expected type, found {}", self.peek().description()));
                Err(())
            }
        }
    }

    fn parse_array_type(&mut self) -> Result<Type, ()> {
        let span = self.peek_span();
        self.expect(&TokenKind::LBracket)?;
        let elem = self.parse_type()?;
        self.expect(&TokenKind::Semicolon)?;
        let size = match self.peek() {
            TokenKind::IntLiteral(_) => {
                let tok = self.advance();
                if let TokenKind::IntLiteral(v) = tok.kind { v.as_u64() } else { 0 }
            }
            _ => {
                self.error("expected array size".into());
                return Err(());
            }
        };
        self.expect(&TokenKind::RBracket)?;
        Ok(Type::Array(Box::new(elem), size, span))
    }

    fn parse_tuple_type(&mut self) -> Result<Type, ()> {
        let span = self.peek_span();
        self.expect(&TokenKind::LParen)?;
        let mut types = Vec::new();
        while !self.at(&TokenKind::RParen) && !self.at_eof() {
            types.push(self.parse_type()?);
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(&TokenKind::RParen)?;
        Ok(Type::Tuple(types, span))
    }

    // ========================================================================
    // Blocks and statements
    // ========================================================================

    fn parse_block(&mut self) -> Result<Block, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::LBrace)?;

        let mut stmts = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            match self.parse_stmt() {
                Ok(stmt) => stmts.push(stmt),
                Err(_) => self.recover_to_stmt(),
            }
        }

        self.expect(&TokenKind::RBrace)?;
        Ok(Block { stmts, span: start })
    }

    fn parse_stmt(&mut self) -> Result<Stmt, ()> {
        match self.peek() {
            TokenKind::Let => self.parse_let_stmt(),
            TokenKind::Return => self.parse_return_stmt(),
            TokenKind::Emit => self.parse_emit_stmt(),
            TokenKind::For => self.parse_for_stmt(),
            TokenKind::While => self.parse_while_stmt(),
            TokenKind::If => self.parse_if_stmt(),
            TokenKind::Match => self.parse_match_stmt(),
            TokenKind::Break => {
                let span = self.peek_span();
                self.advance();
                self.expect_semi()?;
                Ok(Stmt::Break(span))
            }
            TokenKind::Continue => {
                let span = self.peek_span();
                self.advance();
                self.expect_semi()?;
                Ok(Stmt::Continue(span))
            }
            _ => self.parse_expr_or_assign_stmt(),
        }
    }

    /// Parse `if` as a statement (no trailing `;` required).
    fn parse_if_stmt(&mut self) -> Result<Stmt, ()> {
        let start = self.peek_span();
        let expr = self.parse_if_expr()?;
        Ok(Stmt::Expr(ExprStmt { expr, span: start }))
    }

    /// Parse `match` as a statement (no trailing `;` required).
    fn parse_match_stmt(&mut self) -> Result<Stmt, ()> {
        let start = self.peek_span();
        let expr = self.parse_match_expr()?;
        Ok(Stmt::Expr(ExprStmt { expr, span: start }))
    }

    fn parse_let_stmt(&mut self) -> Result<Stmt, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::Let)?;
        let is_mutable = self.eat(&TokenKind::Mut);

        // Binding: either `name` or `(a, b, c)`
        let binding = if self.at(&TokenKind::LParen) {
            let paren_span = self.peek_span();
            self.advance(); // eat (
            let mut names = Vec::new();
            while !self.at(&TokenKind::RParen) && !self.at_eof() {
                names.push(self.expect_ident()?);
                if !self.eat(&TokenKind::Comma) {
                    break;
                }
            }
            self.expect(&TokenKind::RParen)?;
            LetBinding::Tuple(names, paren_span)
        } else {
            LetBinding::Name(self.expect_ident()?)
        };

        let ty = if self.eat(&TokenKind::Colon) {
            Some(self.parse_type()?)
        } else {
            None
        };

        self.expect(&TokenKind::Eq)?;
        let initializer = self.parse_expr()?;
        self.expect_semi()?;

        Ok(Stmt::Let(LetStmt { binding, is_mutable, ty, initializer, span: start }))
    }

    fn parse_return_stmt(&mut self) -> Result<Stmt, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::Return)?;

        let value = if self.at(&TokenKind::Semicolon) {
            None
        } else {
            Some(self.parse_expr()?)
        };

        self.expect_semi()?;
        Ok(Stmt::Return(ReturnStmt { value, span: start }))
    }

    fn parse_emit_stmt(&mut self) -> Result<Stmt, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::Emit)?;
        // Parse event name as a path: `Deposit` or `event::Deposit`
        let mut event_name = vec![self.expect_ident()?];
        while self.eat(&TokenKind::ColonColon) {
            event_name.push(self.expect_ident()?);
        }
        self.expect(&TokenKind::LBrace)?;

        let mut fields = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            let fname = self.expect_ident()?;
            self.expect(&TokenKind::Colon)?;
            let value = self.parse_expr()?;
            let fspan = fname.span;
            fields.push(FieldInit { name: fname, value, span: fspan });
            if !self.at(&TokenKind::RBrace) {
                self.expect(&TokenKind::Comma)?;
            } else {
                self.eat(&TokenKind::Comma);
            }
        }

        self.expect(&TokenKind::RBrace)?;
        self.expect_semi()?;
        Ok(Stmt::Emit(EmitStmt { event_name, fields, span: start }))
    }

    fn parse_for_stmt(&mut self) -> Result<Stmt, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::For)?;
        let variable = self.expect_ident()?;
        self.expect(&TokenKind::In)?;
        let iterator = self.parse_expr()?;
        let body = self.parse_block()?;

        Ok(Stmt::For(ForStmt { variable, iterator, body, span: start }))
    }

    fn parse_while_stmt(&mut self) -> Result<Stmt, ()> {
        let start = self.peek_span();
        self.expect(&TokenKind::While)?;
        let condition = self.parse_expr()?;
        let body = self.parse_block()?;

        Ok(Stmt::While(WhileStmt { condition, body, span: start }))
    }

    /// Parse an expression statement, or an assignment if followed by `=`/`+=`/etc.
    fn parse_expr_or_assign_stmt(&mut self) -> Result<Stmt, ()> {
        let start = self.peek_span();
        let expr = self.parse_expr()?;

        // Check for assignment
        if let Some(op) = self.try_parse_assign_op() {
            let value = self.parse_expr()?;
            self.expect_semi()?;
            return Ok(Stmt::Assign(AssignStmt { target: expr, op, value, span: start }));
        }

        // Allow trailing expression without ; if it's the last thing before }
        // This handles block expressions like `if true { 1 } else { 2 }`
        if self.at(&TokenKind::RBrace) {
            return Ok(Stmt::Expr(ExprStmt { expr, span: start }));
        }

        self.expect_semi()?;
        Ok(Stmt::Expr(ExprStmt { expr, span: start }))
    }

    fn try_parse_assign_op(&mut self) -> Option<AssignOp> {
        let op = match self.peek() {
            TokenKind::Eq => AssignOp::Assign,
            TokenKind::PlusEq => AssignOp::AddAssign,
            TokenKind::MinusEq => AssignOp::SubAssign,
            TokenKind::StarEq => AssignOp::MulAssign,
            TokenKind::SlashEq => AssignOp::DivAssign,
            TokenKind::PercentEq => AssignOp::ModAssign,
            TokenKind::AmpEq => AssignOp::BitAndAssign,
            TokenKind::PipeEq => AssignOp::BitOrAssign,
            TokenKind::CaretEq => AssignOp::BitXorAssign,
            TokenKind::ShlEq => AssignOp::ShlAssign,
            TokenKind::ShrEq => AssignOp::ShrAssign,
            _ => return None,
        };
        // Don't consume `=` if this is an `==` situation — but that's already
        // handled since `==` is a separate token (EqEq).
        self.advance();
        Some(op)
    }

    // ========================================================================
    // Expressions — precedence climbing
    // ========================================================================

    fn parse_expr(&mut self) -> Result<Expr, ()> {
        self.parse_expr_bp(0)
    }

    /// Parse expression with minimum binding power.
    fn parse_expr_bp(&mut self, min_bp: u8) -> Result<Expr, ()> {
        let mut lhs = self.parse_unary_expr()?;

        loop {
            // Cast: `expr as Type` — low precedence
            if self.at(&TokenKind::As) && min_bp <= 12 {
                let span = self.peek_span();
                self.advance();
                let ty = self.parse_type()?;
                lhs = Expr::Cast(Box::new(lhs), ty, span);
                continue;
            }

            let (op, bp) = match self.peek() {
                TokenKind::PipePipe => (BinaryOp::LogicalOr, (2, 3)),
                TokenKind::AmpAmp => (BinaryOp::LogicalAnd, (4, 5)),
                TokenKind::EqEq => (BinaryOp::Eq, (6, 7)),
                TokenKind::BangEq => (BinaryOp::NotEq, (6, 7)),
                TokenKind::Lt => (BinaryOp::Lt, (8, 9)),
                TokenKind::Gt => (BinaryOp::Gt, (8, 9)),
                TokenKind::LtEq => (BinaryOp::LtEq, (8, 9)),
                TokenKind::GtEq => (BinaryOp::GtEq, (8, 9)),
                TokenKind::Pipe => (BinaryOp::BitOr, (10, 11)),
                TokenKind::Caret => (BinaryOp::BitXor, (12, 13)),
                TokenKind::Amp => (BinaryOp::BitAnd, (14, 15)),
                TokenKind::Shl => (BinaryOp::Shl, (16, 17)),
                TokenKind::Shr => (BinaryOp::Shr, (16, 17)),
                TokenKind::DotDot => (BinaryOp::Range, (18, 19)),
                TokenKind::Plus => (BinaryOp::Add, (20, 21)),
                TokenKind::Minus => (BinaryOp::Sub, (20, 21)),
                TokenKind::Star => (BinaryOp::Mul, (22, 23)),
                TokenKind::Slash => (BinaryOp::Div, (22, 23)),
                TokenKind::Percent => (BinaryOp::Mod, (22, 23)),
                _ => break,
            };

            let (l_bp, r_bp) = bp;
            if l_bp < min_bp {
                break;
            }

            let span = self.peek_span();
            self.advance(); // consume operator
            let rhs = self.parse_expr_bp(r_bp)?;
            lhs = Expr::Binary(Box::new(lhs), op, Box::new(rhs), span);
        }

        Ok(lhs)
    }

    fn parse_unary_expr(&mut self) -> Result<Expr, ()> {
        let span = self.peek_span();
        match self.peek() {
            TokenKind::Minus => {
                self.advance();
                let operand = self.parse_unary_expr()?;
                Ok(Expr::Unary(UnaryOp::Negate, Box::new(operand), span))
            }
            TokenKind::Bang => {
                self.advance();
                let operand = self.parse_unary_expr()?;
                Ok(Expr::Unary(UnaryOp::LogicalNot, Box::new(operand), span))
            }
            TokenKind::Tilde => {
                self.advance();
                let operand = self.parse_unary_expr()?;
                Ok(Expr::Unary(UnaryOp::BitNot, Box::new(operand), span))
            }
            TokenKind::Try => {
                self.advance();
                let operand = self.parse_unary_expr()?;
                Ok(Expr::Try(Box::new(operand), span))
            }
            _ => self.parse_postfix_expr(),
        }
    }

    /// Parse postfix expressions: field access, indexing, function calls.
    fn parse_postfix_expr(&mut self) -> Result<Expr, ()> {
        let mut expr = self.parse_primary_expr()?;

        loop {
            match self.peek() {
                // Field access: expr.field
                TokenKind::Dot => {
                    let span = self.peek_span();
                    self.advance();
                    // Accept identifier OR integer literal for tuple field access (t.0, t.1)
                    let field = if let TokenKind::IntLiteral(n) = self.peek() {
                        let name = n.to_string();
                        let fspan = self.peek_span();
                        self.advance();
                        Ident { name, span: fspan }
                    } else {
                        self.expect_ident()?
                    };

                    // Check for method call: expr.field(args) or expr.field{ value: v }(args)
                    // Lookahead: only treat { as value annotation if tokens are { value :
                    let has_value_annotation = self.at(&TokenKind::LBrace)
                        && self.lookahead_is_value_annotation();
                    if has_value_annotation || self.at(&TokenKind::LParen) {
                        let call_value = if has_value_annotation {
                            let v = self.parse_call_value_annotation()?;
                            Some(Box::new(v))
                        } else {
                            None
                        };
                        let args = self.parse_call_args()?;
                        expr = Expr::Call(
                            Box::new(Expr::FieldAccess(Box::new(expr), field, span)),
                            args,
                            call_value,
                            span,
                        );
                    } else {
                        expr = Expr::FieldAccess(Box::new(expr), field, span);
                    }
                }
                // Index: expr[index]
                TokenKind::LBracket => {
                    let span = self.peek_span();
                    self.advance();
                    let index = self.parse_expr()?;
                    self.expect(&TokenKind::RBracket)?;
                    expr = Expr::Index(Box::new(expr), Box::new(index), span);
                }
                // Call: expr(args) — only if expr is not already handled above
                TokenKind::LParen => {
                    let span = self.peek_span();
                    let args = self.parse_call_args()?;
                    expr = Expr::Call(Box::new(expr), args, None, span);
                }
                _ => break,
            }
        }

        Ok(expr)
    }

    /// Check if the next tokens are `{ value :` (lookahead without consuming).
    fn lookahead_is_value_annotation(&self) -> bool {
        // Current token is `{`. Check if next is ident "value" and after that is `:`.
        if self.pos + 2 >= self.tokens.len() { return false; }
        let next = &self.tokens[self.pos + 1];
        let after = &self.tokens[self.pos + 2];
        matches!(&next.kind, TokenKind::Ident(name) if name == "value")
            && matches!(after.kind, TokenKind::Colon)
    }

    /// Parse `{ value: expr }` annotation for payable calls.
    fn parse_call_value_annotation(&mut self) -> Result<Expr, ()> {
        self.expect(&TokenKind::LBrace)?;
        let ident = self.expect_ident()?;
        if ident.name != "value" {
            self.error(format!("expected 'value' in call annotation, got '{}'", ident.name));
            self.expect(&TokenKind::RBrace)?;
            return Ok(Expr::Literal(Literal::Int(ethnum::U256::ZERO), ident.span));
        }
        self.expect(&TokenKind::Colon)?;
        let value_expr = self.parse_expr()?;
        self.expect(&TokenKind::RBrace)?;
        Ok(value_expr)
    }

    fn parse_call_args(&mut self) -> Result<Vec<Expr>, ()> {
        self.expect(&TokenKind::LParen)?;
        let mut args = Vec::new();

        while !self.at(&TokenKind::RParen) && !self.at_eof() {
            args.push(self.parse_expr()?);
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }

        self.expect(&TokenKind::RParen)?;
        Ok(args)
    }

    fn parse_primary_expr(&mut self) -> Result<Expr, ()> {
        let span = self.peek_span();

        match self.peek().clone() {
            // Integer literal — optionally followed by type suffix like `0u256`, `100u64`, `0_u64`
            TokenKind::IntLiteral(v) => {
                self.advance();
                // Consume optional type suffix (e.g., u256, u64, i32, _u64)
                if let TokenKind::Ident(ref s) = self.peek() {
                    let suffix = s.strip_prefix('_').unwrap_or(s.as_str());
                    match suffix {
                        "u8" | "u16" | "u32" | "u64" | "u128" | "u256"
                        | "i8" | "i16" | "i32" | "i64" | "i128" | "i256" => {
                            self.advance(); // consume suffix
                        }
                        _ => {}
                    }
                }
                Ok(Expr::Literal(Literal::Int(v), span))
            }

            // String literal
            TokenKind::StringLiteral(s) => {
                self.advance();
                Ok(Expr::Literal(Literal::String(s), span))
            }

            // Boolean literals
            TokenKind::True => {
                self.advance();
                Ok(Expr::Literal(Literal::Bool(true), span))
            }
            TokenKind::False => {
                self.advance();
                Ok(Expr::Literal(Literal::Bool(false), span))
            }

            // self
            TokenKind::SelfKw => {
                self.advance();
                Ok(Expr::SelfExpr(span))
            }

            // if expression
            TokenKind::If => self.parse_if_expr(),

            // match expression
            TokenKind::Match => self.parse_match_expr(),

            // Block expression
            TokenKind::LBrace => {
                let block = self.parse_block()?;
                Ok(Expr::Block(block))
            }

            // Parenthesized expr or tuple
            TokenKind::LParen => self.parse_paren_or_tuple(),

            // Array: [expr; N] or [a, b, c]
            TokenKind::LBracket => self.parse_array_expr(),

            // Identifier — could be variable, path, struct init, macro call, or function call
            TokenKind::Ident(_) => self.parse_ident_expr(),

            // Wildcard _ (in match patterns, not really an expression)
            TokenKind::Underscore => {
                self.advance();
                Ok(Expr::Ident(Ident { name: "_".into(), span }))
            }

            _ => {
                self.error(format!("expected expression, found {}", self.peek().description()));
                Err(())
            }
        }
    }

    fn parse_ident_expr(&mut self) -> Result<Expr, ()> {
        let span = self.peek_span();
        let first = self.expect_ident()?;

        // Check for macro call: ident!(...)
        if self.at(&TokenKind::Bang) {
            self.advance(); // eat !
            return self.parse_macro_call(first, span);
        }

        // Check for path: ident::ident::...
        if self.at(&TokenKind::ColonColon) {
            let mut segments = vec![first];
            while self.eat(&TokenKind::ColonColon) {
                segments.push(self.expect_ident()?);
            }

            // Path followed by call: IERC20::at(token)
            if self.at(&TokenKind::LParen) {
                let args = self.parse_call_args()?;
                return Ok(Expr::Call(Box::new(Expr::Path(segments, span)), args, None, span));
            }

            // Path followed by struct init: MyStruct { ... }
            // (only if the next tokens look like `{ ident: ...`)
            if self.at(&TokenKind::LBrace) && self.looks_like_struct_init() {
                return self.parse_struct_init_body(segments, span);
            }

            return Ok(Expr::Path(segments, span));
        }

        // Check for struct init: Name { field: value, ... }
        if self.at(&TokenKind::LBrace) && self.looks_like_struct_init() {
            return self.parse_struct_init_body(vec![first], span);
        }

        // Simple identifier
        Ok(Expr::Ident(first))
    }

    /// Heuristic: does `{ ... }` look like a struct init (`{ ident: expr }`)
    /// vs a block (`{ stmt; ... }`)? Look ahead for `ident :`.
    fn looks_like_struct_init(&self) -> bool {
        // Look at tokens after `{`: if we see `ident :` it's struct init
        let i = self.pos + 1; // skip the `{`
        if let Some(tok) = self.tokens.get(i) {
            if matches!(tok.kind, TokenKind::Ident(_)) {
                if let Some(next) = self.tokens.get(i + 1) {
                    return matches!(next.kind, TokenKind::Colon);
                }
            }
            // Empty struct init: `Name {}`
            if matches!(tok.kind, TokenKind::RBrace) {
                return true;
            }
        }
        false
    }

    fn parse_struct_init_body(&mut self, name: Vec<Ident>, span: Span) -> Result<Expr, ()> {
        self.expect(&TokenKind::LBrace)?;
        let mut fields = Vec::new();

        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            let fname = self.expect_ident()?;
            self.expect(&TokenKind::Colon)?;
            let value = self.parse_expr()?;
            let fspan = fname.span;
            fields.push(FieldInit { name: fname, value, span: fspan });
            self.eat(&TokenKind::Comma);
        }

        self.expect(&TokenKind::RBrace)?;
        Ok(Expr::StructInit(name, fields, span))
    }

    fn parse_macro_call(&mut self, name: Ident, span: Span) -> Result<Expr, ()> {
        self.expect(&TokenKind::LParen)?;
        let mut args = Vec::new();

        while !self.at(&TokenKind::RParen) && !self.at_eof() {
            // Check for named arg: `key: value`
            if let TokenKind::Ident(_) = self.peek() {
                // Lookahead: is it `ident: expr` (named) or just `expr` (positional)?
                let saved = self.pos;
                let ident = self.expect_ident().ok();
                if let (true, Some(name)) = (self.at(&TokenKind::Colon), ident) {
                    self.advance(); // eat :
                    let value = self.parse_expr()?;
                    args.push(MacroArg::Named(name, value));
                } else {
                    // Backtrack — it's a positional expression
                    self.pos = saved;
                    let expr = self.parse_expr()?;
                    args.push(MacroArg::Positional(expr));
                }
            } else {
                let expr = self.parse_expr()?;
                args.push(MacroArg::Positional(expr));
            }

            self.eat(&TokenKind::Comma);
        }

        self.expect(&TokenKind::RParen)?;
        Ok(Expr::MacroCall(name, args, span))
    }

    fn parse_if_expr(&mut self) -> Result<Expr, ()> {
        let span = self.peek_span();
        self.expect(&TokenKind::If)?;
        let condition = self.parse_expr()?;
        let then_block = self.parse_block()?;

        let else_clause = if self.eat(&TokenKind::Else) {
            if self.at(&TokenKind::If) {
                let else_if = self.parse_if_expr()?;
                Some(ElseClause::ElseIf(Box::new(else_if)))
            } else {
                let else_block = self.parse_block()?;
                Some(ElseClause::ElseBlock(else_block))
            }
        } else {
            None
        };

        Ok(Expr::If(Box::new(condition), then_block, else_clause, span))
    }

    fn parse_match_expr(&mut self) -> Result<Expr, ()> {
        let span = self.peek_span();
        self.expect(&TokenKind::Match)?;
        let scrutinee = self.parse_expr()?;
        self.expect(&TokenKind::LBrace)?;

        let mut arms = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            arms.push(self.parse_match_arm()?);
        }

        self.expect(&TokenKind::RBrace)?;
        Ok(Expr::Match(Box::new(scrutinee), arms, span))
    }

    fn parse_match_arm(&mut self) -> Result<MatchArm, ()> {
        let span = self.peek_span();
        let pattern = self.parse_pattern()?;
        self.expect(&TokenKind::FatArrow)?;

        // Arm body: block, return expr, or expression
        let body = if self.at(&TokenKind::LBrace) {
            let block = self.parse_block()?;
            self.eat(&TokenKind::Comma);
            Expr::Block(block)
        } else if self.at(&TokenKind::Return) {
            // `return expr` in match arm — wrap as a block with return stmt
            let ret_span = self.peek_span();
            self.advance(); // eat return
            let value = self.parse_expr()?;
            self.eat(&TokenKind::Comma);
            let ret_stmt = Stmt::Return(ReturnStmt { value: Some(value), span: ret_span });
            Expr::Block(Block { stmts: vec![ret_stmt], span: ret_span })
        } else {
            let expr = self.parse_expr()?;
            self.eat(&TokenKind::Comma);
            expr
        };

        Ok(MatchArm { pattern, body, span })
    }

    fn parse_pattern(&mut self) -> Result<Pattern, ()> {
        let span = self.peek_span();

        match self.peek().clone() {
            TokenKind::Underscore => {
                self.advance();
                Ok(Pattern::Wildcard(span))
            }
            TokenKind::IntLiteral(v) => {
                self.advance();
                // Skip optional type suffix in pattern (e.g., 0u8, 0_u8)
                self.eat_int_suffix();
                // Check for range pattern: `100..200`
                if self.at(&TokenKind::DotDot) {
                    self.advance(); // eat ..
                    let _end_span = self.peek_span();
                    match self.peek().clone() {
                        TokenKind::IntLiteral(end_v) => {
                            self.advance();
                            self.eat_int_suffix();
                            return Ok(Pattern::Range(Literal::Int(v), Literal::Int(end_v), span));
                        }
                        _ => {
                            self.error("expected integer literal after .. in range pattern".into());
                            return Err(());
                        }
                    }
                }
                Ok(Pattern::Literal(Literal::Int(v), span))
            }
            TokenKind::StringLiteral(s) => {
                self.advance();
                Ok(Pattern::Literal(Literal::String(s), span))
            }
            TokenKind::True => {
                self.advance();
                Ok(Pattern::Literal(Literal::Bool(true), span))
            }
            TokenKind::False => {
                self.advance();
                Ok(Pattern::Literal(Literal::Bool(false), span))
            }
            TokenKind::Ident(_) => {
                let mut segments = vec![self.expect_ident()?];
                while self.eat(&TokenKind::ColonColon) {
                    segments.push(self.expect_ident()?);
                }
                Ok(Pattern::Path(segments, span))
            }
            _ => {
                self.error(format!("expected pattern, found {}", self.peek().description()));
                Err(())
            }
        }
    }

    fn parse_paren_or_tuple(&mut self) -> Result<Expr, ()> {
        let span = self.peek_span();
        self.expect(&TokenKind::LParen)?;

        if self.at(&TokenKind::RParen) {
            self.advance();
            return Ok(Expr::Tuple(vec![], span)); // unit tuple
        }

        let first = self.parse_expr()?;

        if self.eat(&TokenKind::Comma) {
            // Tuple
            let mut elements = vec![first];
            while !self.at(&TokenKind::RParen) && !self.at_eof() {
                elements.push(self.parse_expr()?);
                if !self.eat(&TokenKind::Comma) {
                    break;
                }
            }
            self.expect(&TokenKind::RParen)?;
            Ok(Expr::Tuple(elements, span))
        } else {
            // Parenthesized expression — just return the inner expression
            self.expect(&TokenKind::RParen)?;
            Ok(first)
        }
    }

    /// Parse `[expr; N]` (repeat) or `[a, b, c]` (literal).
    fn parse_array_expr(&mut self) -> Result<Expr, ()> {
        let span = self.peek_span();
        self.expect(&TokenKind::LBracket)?;

        // Empty array: []
        if self.at(&TokenKind::RBracket) {
            self.advance();
            return Ok(Expr::ArrayLiteral(vec![], span));
        }

        let first = self.parse_expr()?;

        // Repeat init: [expr; N]
        if self.eat(&TokenKind::Semicolon) {
            let count = match self.peek() {
                TokenKind::IntLiteral(_) => {
                    let tok = self.advance();
                    if let TokenKind::IntLiteral(v) = tok.kind { v.as_u64() } else { 0 }
                }
                _ => {
                    self.error("expected array size literal".into());
                    return Err(());
                }
            };
            self.expect(&TokenKind::RBracket)?;
            return Ok(Expr::ArrayRepeat(Box::new(first), count, span));
        }

        // Array literal: [a, b, c, ...]
        let mut elements = vec![first];
        while self.eat(&TokenKind::Comma) {
            if self.at(&TokenKind::RBracket) {
                break; // trailing comma
            }
            elements.push(self.parse_expr()?);
        }
        self.expect(&TokenKind::RBracket)?;
        Ok(Expr::ArrayLiteral(elements, span))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethnum::U256;
    use crate::lexer::Lexer;

    fn parse(src: &str) -> (SourceFile, Vec<ParseError>) {
        let (tokens, lex_errors) = Lexer::new(src).tokenize();
        assert!(lex_errors.is_empty(), "lex errors: {:?}", lex_errors);
        Parser::new(tokens).parse()
    }

    fn parse_ok(src: &str) -> SourceFile {
        let (file, errors) = parse(src);
        assert!(errors.is_empty(), "parse errors: {:?}", errors);
        file
    }

    // ========== Use imports ==========

    #[test]
    fn parse_use_import() {
        let file = parse_ok("use std::math;");
        assert_eq!(file.items.len(), 1);
        if let Item::Use(u) = &file.items[0] {
            assert_eq!(u.path.len(), 2);
            assert_eq!(u.path[0].name, "std");
            assert_eq!(u.path[1].name, "math");
            assert!(u.items.is_empty());
        } else {
            panic!("expected Use");
        }
    }

    #[test]
    fn parse_grouped_import() {
        let file = parse_ok("use std::math::{sqrt, pow, min};");
        if let Item::Use(u) = &file.items[0] {
            assert_eq!(u.path.len(), 2);
            assert_eq!(u.path[0].name, "std");
            assert_eq!(u.path[1].name, "math");
            assert_eq!(u.items.len(), 3);
            assert_eq!(u.items[0].name, "sqrt");
            assert_eq!(u.items[1].name, "pow");
            assert_eq!(u.items[2].name, "min");
        } else {
            panic!("expected Use");
        }
    }

    // ========== Module ==========

    #[test]
    fn parse_module_declaration() {
        let file = parse_ok("module math_lib;");
        assert_eq!(file.items.len(), 1);
        if let Item::Module(m) = &file.items[0] {
            assert_eq!(m.name.name, "math_lib");
        } else {
            panic!("expected Module");
        }
    }

    // ========== Enum ==========

    #[test]
    fn parse_enum_def() {
        let file = parse_ok("enum Status { Active, Paused, Closed }");
        if let Item::Enum(e) = &file.items[0] {
            assert_eq!(e.name.name, "Status");
            assert_eq!(e.variants.len(), 3);
            assert_eq!(e.variants[0].name, "Active");
            assert_eq!(e.variants[2].name, "Closed");
        } else {
            panic!("expected Enum");
        }
    }

    // ========== Const ==========

    #[test]
    fn parse_const_def() {
        let file = parse_ok("const MAX_SUPPLY: u256 = 1000000;");
        if let Item::Const(c) = &file.items[0] {
            assert_eq!(c.name.name, "MAX_SUPPLY");
            assert!(c.ty.is_some());
            assert!(!c.is_pub);
        } else {
            panic!("expected Const");
        }
    }

    // ========== Struct ==========

    #[test]
    fn parse_struct_def() {
        let file = parse_ok("struct Point { x: u64, y: u64 }");
        if let Item::Struct(s) = &file.items[0] {
            assert_eq!(s.name.name, "Point");
            assert_eq!(s.fields.len(), 2);
        } else {
            panic!("expected Struct");
        }
    }

    // ========== Interface ==========

    #[test]
    fn parse_interface_def() {
        let file = parse_ok("interface IERC20 { fn transfer(to: Address, amount: u256); fn balance_of(owner: Address) -> u256; }");
        if let Item::Interface(i) = &file.items[0] {
            assert_eq!(i.name.name, "IERC20");
            assert_eq!(i.functions.len(), 2);
            assert_eq!(i.functions[0].name.name, "transfer");
            assert!(i.functions[0].return_type.is_none());
            assert_eq!(i.functions[1].name.name, "balance_of");
            assert!(i.functions[1].return_type.is_some());
        } else {
            panic!("expected Interface");
        }
    }

    // ========== Error ==========

    #[test]
    fn parse_error_def() {
        let file = parse_ok("error InsufficientBalance { available: u256, required: u256 }");
        if let Item::Error(e) = &file.items[0] {
            assert_eq!(e.name.name, "InsufficientBalance");
            assert_eq!(e.fields.len(), 2);
        } else {
            panic!("expected Error");
        }
    }

    #[test]
    fn parse_empty_error() {
        let file = parse_ok("error Unauthorized {}");
        if let Item::Error(e) = &file.items[0] {
            assert_eq!(e.name.name, "Unauthorized");
            assert!(e.fields.is_empty());
        } else {
            panic!("expected Error");
        }
    }

    // ========== Minimal contract ==========

    #[test]
    fn parse_minimal_contract() {
        let src = r#"
contract Token {
    storage {
        supply: u256,
        balances: Map<Address, u256>,
    }

    event Transfer {
        #[indexed]
        from: Address,
        to: Address,
        amount: u256,
    }

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
"#;
        let file = parse_ok(src);
        assert_eq!(file.items.len(), 1);
        if let Item::Contract(c) = &file.items[0] {
            assert_eq!(c.name.name, "Token");
            // storage + event + error + 2 functions = 5 items
            assert_eq!(c.items.len(), 5);
        } else {
            panic!("expected Contract");
        }
    }

    // ========== Expression tests ==========

    #[test]
    fn parse_binary_expr() {
        let src = "contract T { fn f() { let x = 1 + 2 * 3; } }";
        let file = parse_ok(src);
        // Should parse as 1 + (2 * 3) due to precedence
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    // Top-level is Add
                    assert!(matches!(l.initializer, Expr::Binary(_, BinaryOp::Add, _, _)));
                } else {
                    panic!("expected let");
                }
            }
        }
    }

    #[test]
    fn parse_field_access_and_index() {
        let src = "contract T { fn f() { let x = self.balances[msg.sender]; } }";
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    // Should be Index(FieldAccess(self, balances), FieldAccess(msg, sender))
                    assert!(matches!(l.initializer, Expr::Index(_, _, _)));
                }
            }
        }
    }

    #[test]
    fn parse_method_call() {
        let src = "contract T { fn f() { self.balances[msg.sender].push(42); } }";
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_path_and_call() {
        let src = "contract T { fn f() { let v = Vec::new(); } }";
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    assert!(matches!(l.initializer, Expr::Call(_, _, _, _)));
                }
            }
        }
    }

    #[test]
    fn parse_struct_init() {
        let src = r#"contract T { fn f() { let p = Point { x: 1, y: 2 }; } }"#;
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    assert!(matches!(l.initializer, Expr::StructInit(_, _, _)));
                }
            }
        }
    }

    #[test]
    fn parse_if_else_expr() {
        let src = "contract T { fn f() { let x = if true { 1 } else { 2 }; } }";
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    assert!(matches!(l.initializer, Expr::If(_, _, _, _)));
                }
            }
        }
    }

    #[test]
    fn parse_match_expr() {
        let src = r#"contract T { fn f() { let x = match status { Status::Active => 1, _ => 0, }; } }"#;
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_macro_call() {
        let src = "contract T { fn f() { require!(x > 0, ZeroAmount {}); } }";
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_cross_call_macro() {
        let src = r#"contract T { fn f() { cross_call!(target: "oracle", method: "get_price", args: (pair,), callback: "on_price"); } }"#;
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_cast_expr() {
        let src = "contract T { fn f() { let x = y as u256; } }";
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    assert!(matches!(l.initializer, Expr::Cast(_, _, _)));
                }
            }
        }
    }

    #[test]
    fn parse_for_loop() {
        let src = "contract T { fn f() { for i in 0..10 { let x = i; } } }";
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_while_loop() {
        let src = "contract T { fn f() { while x > 0 { x = x - 1; } } }";
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_emit_stmt() {
        let src = r#"contract T { event Transfer { from: Address, to: Address, amount: u256, } pub fn f() { emit Transfer { from: msg.sender, to: msg.sender, amount: 100 }; } }"#;
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_compound_assignment() {
        let src = "contract T { fn f() { self.count += 1; } }";
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_tuple_return() {
        let src = "contract T { fn f() -> (u256, u256) { return (1, 2); } }";
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                assert!(f.return_type.is_some());
            }
        }
    }

    #[test]
    fn parse_array_type_and_repeat() {
        let src = "contract T { fn f() { let hash: [u8; 32] = [0; 32]; } }";
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_nested_map_type() {
        let src = "contract T { storage { allowances: Map<Address, Map<Address, u256>>, } }";
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_error_recovery() {
        // Use a parse-level error (not lex-level) for recovery testing
        let src = "contract T { fn f() { 123 456; let x = 1; } }";
        let (file, errors) = parse(src);
        // Should recover and still produce a contract
        assert!(!errors.is_empty());
        assert_eq!(file.items.len(), 1);
    }

    // ========== New features ==========

    #[test]
    fn parse_underscore_type_suffix() {
        // 0_u64 should parse as a single literal
        let src = "contract T { fn f() { let x = 0_u64; } }";
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    assert!(matches!(&l.initializer, Expr::Literal(Literal::Int(v), _) if *v == U256::ZERO));
                }
            }
        }
    }

    #[test]
    fn parse_underscore_number_separators() {
        // 100_000_000 lexes as IntLiteral(100000000)
        let src = "contract T { fn f() { let x = 100_000_000; } }";
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    assert!(matches!(&l.initializer, Expr::Literal(Literal::Int(v), _) if *v == U256::from(100_000_000u64)));
                }
            }
        }
    }

    #[test]
    fn parse_type_alias() {
        let src = "type TokenId = u256;";
        let file = parse_ok(src);
        if let Item::TypeAlias(t) = &file.items[0] {
            assert_eq!(t.name.name, "TokenId");
        } else {
            panic!("expected TypeAlias");
        }
    }

    #[test]
    fn parse_type_alias_complex() {
        let src = "type Balances = Map<Address, u256>;";
        let file = parse_ok(src);
        assert!(matches!(file.items[0], Item::TypeAlias(_)));
    }

    #[test]
    fn parse_array_literal() {
        let src = "contract T { fn f() { let dims = [10, 20, 30]; } }";
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    assert!(matches!(l.initializer, Expr::ArrayLiteral(_, _)));
                    if let Expr::ArrayLiteral(elems, _) = &l.initializer {
                        assert_eq!(elems.len(), 3);
                    }
                }
            }
        }
    }

    #[test]
    fn parse_array_repeat_still_works() {
        let src = "contract T { fn f() { let h = [0; 32]; } }";
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    assert!(matches!(l.initializer, Expr::ArrayRepeat(_, 32, _)));
                }
            }
        }
    }

    #[test]
    fn parse_chained_method_on_paren_expr() {
        // (a + b).sqrt() — method call on parenthesized expression
        let src = "contract T { fn f() { let x = (a + b).sqrt(); } }";
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    // Should be Call(FieldAccess(Binary(a, +, b), sqrt), [])
                    assert!(matches!(l.initializer, Expr::Call(_, _, _, _)));
                }
            }
        }
    }

    #[test]
    fn parse_chained_method_on_call_result() {
        // get_value().pow(3) — method call on function return
        let src = "contract T { fn f() { let x = get_value().pow(3); } }";
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_deep_method_chain() {
        // self.balances[addr].checked_add(amount).unwrap()
        let src = "contract T { fn f() { let x = self.data[0].process().result(); } }";
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_range_pattern_in_match() {
        let src = r#"contract T { fn f() { let x = match code { 100..200 => 1, 200..300 => 2, _ => 0, }; } }"#;
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    if let Expr::Match(_, arms, _) = &l.initializer {
                        assert_eq!(arms.len(), 3);
                        assert!(matches!(arms[0].pattern, Pattern::Range(_, _, _)));
                        assert!(matches!(arms[1].pattern, Pattern::Range(_, _, _)));
                        assert!(matches!(arms[2].pattern, Pattern::Wildcard(_)));
                    }
                }
            }
        }
    }

    #[test]
    fn parse_block_scope() {
        let src = "contract T { fn f() { let x = 1; { let y = x + 1; } } }";
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_typed_literal_suffix() {
        // 0u256 should parse as a single literal, not two tokens
        let src = "contract T { fn f() { let x = 0u256; } }";
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    assert!(matches!(&l.initializer, Expr::Literal(Literal::Int(v), _) if *v == U256::ZERO));
                }
            }
        }
    }

    #[test]
    fn parse_enum_with_discriminants() {
        let src = "enum Status { Active = 0, Paused = 1, Closed = 2 }";
        let file = parse_ok(src);
        if let Item::Enum(e) = &file.items[0] {
            assert_eq!(e.variants.len(), 3);
        } else {
            panic!("expected Enum");
        }
    }

    #[test]
    fn parse_type_alias_in_contract() {
        let src = "contract T { type Balance = u256; fn f() { let b: Balance = 0; } }";
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_complex_expr_chain() {
        // (amount * fee_rate / 10000).min(max_fee)
        let src = "contract T { fn f() { let fee = (amount * fee_rate / 10000).min(max_fee); } }";
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_nested_method_calls() {
        // hash(data).to_bytes().len()
        let src = "contract T { fn f() { let n = hash(data).to_bytes().len(); } }";
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_return_in_match_arm() {
        let src = r#"contract T { fn f() -> u8 { match x { 0 => return 1, _ => return 0, } } }"#;
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    // ========== Tuple destructuring ==========

    #[test]
    fn parse_tuple_destructuring() {
        let src = "contract T { fn f() { let (a, b) = get_pair(); } }";
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    match &l.binding {
                        LetBinding::Tuple(names, _) => {
                            assert_eq!(names.len(), 2);
                            assert_eq!(names[0].name, "a");
                            assert_eq!(names[1].name, "b");
                        }
                        _ => panic!("expected tuple binding"),
                    }
                }
            }
        }
    }

    #[test]
    fn parse_tuple_destructuring_three() {
        let src = "contract T { fn f() { let (x, y, z) = get_triple(); } }";
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    match &l.binding {
                        LetBinding::Tuple(names, _) => assert_eq!(names.len(), 3),
                        _ => panic!("expected tuple binding"),
                    }
                }
            }
        }
    }

    #[test]
    fn parse_tuple_destructuring_with_type() {
        let src = "contract T { fn f() { let (a, b): (u256, u256) = pool.get_reserves(); } }";
        let (_, errors) = parse(src);
        assert!(errors.is_empty());
    }

    #[test]
    fn parse_tuple_destructuring_mut() {
        let src = "contract T { fn f() { let mut (a, b) = get_pair(); } }";
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    assert!(l.is_mutable);
                    assert!(matches!(l.binding, LetBinding::Tuple(_, _)));
                }
            }
        }
    }

    #[test]
    fn parse_single_let_still_works() {
        let src = "contract T { fn f() { let x = 42; } }";
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                if let Stmt::Let(l) = &f.body.stmts[0] {
                    match &l.binding {
                        LetBinding::Name(name) => assert_eq!(name.name, "x"),
                        _ => panic!("expected name binding"),
                    }
                }
            }
        }
    }

    // ========== Doc comments ==========

    #[test]
    fn parse_doc_comment_on_function() {
        let src = r#"
contract Token {
    /// Transfer tokens to a recipient.
    /// Reverts if sender has insufficient balance.
    pub fn transfer(to: Address, amount: u256) {
        self.balances[msg.sender] = self.balances[msg.sender] - amount;
    }
}
"#;
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                assert_eq!(f.doc.as_deref(), Some("Transfer tokens to a recipient.\nReverts if sender has insufficient balance."));
            }
        }
    }

    #[test]
    fn parse_doc_comment_on_event() {
        let src = r#"
contract Token {
    /// Emitted when tokens are transferred.
    event Transfer {
        from: Address,
        to: Address,
        amount: u256,
    }
}
"#;
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Event(e) = &c.items[0] {
                assert_eq!(e.doc.as_deref(), Some("Emitted when tokens are transferred."));
            }
        }
    }

    #[test]
    fn parse_doc_comment_on_error() {
        let src = r#"
contract Token {
    /// Sender does not have enough tokens.
    error InsufficientBalance { available: u256, required: u256 }
}
"#;
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Error(e) = &c.items[0] {
                assert_eq!(e.doc.as_deref(), Some("Sender does not have enough tokens."));
            }
        }
    }

    #[test]
    fn parse_no_doc_comment() {
        let src = "contract T { pub fn f() {} }";
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                assert!(f.doc.is_none());
            }
        }
    }

    #[test]
    fn parse_doc_comment_with_attribute() {
        let src = r#"
contract Token {
    /// Initialize the token contract.
    #[constructor]
    pub fn init(supply: u256) {
        self.total_supply = supply;
    }
}
"#;
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                assert_eq!(f.doc.as_deref(), Some("Initialize the token contract."));
                assert_eq!(f.attributes.len(), 1);
                assert_eq!(f.attributes[0].content, "constructor");
            }
        }
    }

    #[test]
    fn parse_regular_comment_not_captured() {
        let src = r#"
contract T {
    // This is NOT a doc comment
    pub fn f() {}
}
"#;
        let file = parse_ok(src);
        if let Item::Contract(c) = &file.items[0] {
            if let ContractItem::Function(f) = &c.items[0] {
                assert!(f.doc.is_none());
            }
        }
    }
}
