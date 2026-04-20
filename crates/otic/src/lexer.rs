//! Lexer: converts Otigen source text into a stream of tokens.
//!
//! Handles:
//! - Keywords and identifiers
//! - Integer literals (decimal, hex, with underscores, up to 256-bit)
//! - String literals with escape sequences
//! - All operators and punctuation
//! - Attributes (#[...])
//! - Comments (// line, /* block */, nested, doc)
//! - Error recovery (skip to next valid token)
//! - Source location tracking (line, column per token)

use ethnum::U256;
use crate::token::{Span, Token, TokenKind};

/// A lexer error with source location.
#[derive(Clone, Debug, PartialEq)]
pub struct LexError {
    pub message: String,
    pub line: u32,
    pub col: u32,
}

impl std::fmt::Display for LexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.col, self.message)
    }
}

/// Lexer state.
pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: u32,
    col: u32,
    errors: Vec<LexError>,
}

impl<'a> Lexer<'a> {
    pub fn new(source: &'a str) -> Self {
        Self {
            src: source.as_bytes(),
            pos: 0,
            line: 1,
            col: 1,
            errors: Vec::new(),
        }
    }

    /// Tokenize the entire source. Returns tokens and any errors encountered.
    pub fn tokenize(mut self) -> (Vec<Token>, Vec<LexError>) {
        let mut tokens = Vec::new();
        loop {
            let tok = self.next_token();
            let is_eof = tok.kind == TokenKind::Eof;
            tokens.push(tok);
            if is_eof {
                break;
            }
        }
        (tokens, self.errors)
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    #[allow(dead_code)]
    fn peek2(&self) -> Option<u8> {
        self.src.get(self.pos + 1).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let ch = self.src.get(self.pos).copied()?;
        self.pos += 1;
        if ch == b'\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(ch)
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek() {
            if ch == b' ' || ch == b'\t' || ch == b'\r' || ch == b'\n' {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn skip_line_comment(&mut self) {
        while let Some(ch) = self.advance() {
            if ch == b'\n' {
                break;
            }
        }
    }

    fn skip_block_comment(&mut self) {
        let start_line = self.line;
        let start_col = self.col;
        // Already consumed /*
        let mut depth = 1u32;
        while depth > 0 {
            match self.advance() {
                Some(b'/') if self.peek() == Some(b'*') => {
                    self.advance();
                    depth += 1;
                }
                Some(b'*') if self.peek() == Some(b'/') => {
                    self.advance();
                    depth -= 1;
                }
                Some(_) => {}
                None => {
                    self.errors.push(LexError {
                        message: "unterminated block comment".into(),
                        line: start_line,
                        col: start_col,
                    });
                    return;
                }
            }
        }
    }

    fn make_span(&self, start_offset: usize, start_line: u32, start_col: u32) -> Span {
        Span {
            line: start_line,
            col: start_col,
            offset: start_offset as u32,
            len: (self.pos - start_offset) as u32,
        }
    }

    fn next_token(&mut self) -> Token {
        // Skip whitespace and comments (but capture doc comments)
        loop {
            self.skip_whitespace();
            if self.pos + 1 < self.src.len() && self.src[self.pos] == b'/' {
                if self.src[self.pos + 1] == b'/' {
                    // Check for doc comment: ///
                    if self.pos + 2 < self.src.len() && self.src[self.pos + 2] == b'/'
                        && (self.pos + 3 >= self.src.len() || self.src[self.pos + 3] != b'/')
                    {
                        // Doc comment — return as token
                        let start = self.pos;
                        let start_line = self.line;
                        let start_col = self.col;
                        self.advance(); // /
                        self.advance(); // /
                        self.advance(); // /
                        // Skip optional leading space
                        if self.peek() == Some(b' ') {
                            self.advance();
                        }
                        let content_start = self.pos;
                        while let Some(ch) = self.peek() {
                            if ch == b'\n' { break; }
                            self.advance();
                        }
                        let content = std::str::from_utf8(&self.src[content_start..self.pos])
                            .unwrap_or("")
                            .to_string();
                        return Token {
                            kind: TokenKind::DocComment(content),
                            span: self.make_span(start, start_line, start_col),
                        };
                    }
                    // Regular line comment — skip
                    self.advance();
                    self.advance();
                    self.skip_line_comment();
                    continue;
                }
                if self.src[self.pos + 1] == b'*' {
                    self.advance();
                    self.advance();
                    self.skip_block_comment();
                    continue;
                }
            }
            break;
        }

        let start = self.pos;
        let start_line = self.line;
        let start_col = self.col;

        let ch = match self.advance() {
            Some(ch) => ch,
            None => {
                return Token {
                    kind: TokenKind::Eof,
                    span: self.make_span(start, start_line, start_col),
                };
            }
        };

        let kind = match ch {
            // Punctuation (single char, unambiguous)
            b'{' => TokenKind::LBrace,
            b'}' => TokenKind::RBrace,
            b'(' => TokenKind::LParen,
            b')' => TokenKind::RParen,
            b'[' => TokenKind::LBracket,
            b']' => TokenKind::RBracket,
            b',' => TokenKind::Comma,
            b';' => TokenKind::Semicolon,
            b'?' => TokenKind::Question,
            b'~' => TokenKind::Tilde,

            // # — either #[attribute] or standalone hash
            b'#' => {
                if self.peek() == Some(b'[') {
                    self.advance(); // consume [
                    self.lex_attribute(start, start_line, start_col)
                } else {
                    TokenKind::Hash
                }
            }

            // : or ::
            b':' => {
                if self.peek() == Some(b':') {
                    self.advance();
                    TokenKind::ColonColon
                } else {
                    TokenKind::Colon
                }
            }

            // . or ..
            b'.' => {
                if self.peek() == Some(b'.') {
                    self.advance();
                    TokenKind::DotDot
                } else {
                    TokenKind::Dot
                }
            }

            // + or +=
            b'+' => {
                if self.peek() == Some(b'=') {
                    self.advance();
                    TokenKind::PlusEq
                } else {
                    TokenKind::Plus
                }
            }

            // - or -= or ->
            b'-' => {
                if self.peek() == Some(b'=') {
                    self.advance();
                    TokenKind::MinusEq
                } else if self.peek() == Some(b'>') {
                    self.advance();
                    TokenKind::Arrow
                } else {
                    TokenKind::Minus
                }
            }

            // * or *=
            b'*' => {
                if self.peek() == Some(b'=') {
                    self.advance();
                    TokenKind::StarEq
                } else {
                    TokenKind::Star
                }
            }

            // / or /=  (comments already handled above)
            b'/' => {
                if self.peek() == Some(b'=') {
                    self.advance();
                    TokenKind::SlashEq
                } else {
                    TokenKind::Slash
                }
            }

            // % or %=
            b'%' => {
                if self.peek() == Some(b'=') {
                    self.advance();
                    TokenKind::PercentEq
                } else {
                    TokenKind::Percent
                }
            }

            // & or &= or &&
            b'&' => {
                if self.peek() == Some(b'&') {
                    self.advance();
                    TokenKind::AmpAmp
                } else if self.peek() == Some(b'=') {
                    self.advance();
                    TokenKind::AmpEq
                } else {
                    TokenKind::Amp
                }
            }

            // | or |= or ||
            b'|' => {
                if self.peek() == Some(b'|') {
                    self.advance();
                    TokenKind::PipePipe
                } else if self.peek() == Some(b'=') {
                    self.advance();
                    TokenKind::PipeEq
                } else {
                    TokenKind::Pipe
                }
            }

            // ^ or ^=
            b'^' => {
                if self.peek() == Some(b'=') {
                    self.advance();
                    TokenKind::CaretEq
                } else {
                    TokenKind::Caret
                }
            }

            // ! or !=
            b'!' => {
                if self.peek() == Some(b'=') {
                    self.advance();
                    TokenKind::BangEq
                } else {
                    TokenKind::Bang
                }
            }

            // = or == or =>
            b'=' => {
                if self.peek() == Some(b'=') {
                    self.advance();
                    TokenKind::EqEq
                } else if self.peek() == Some(b'>') {
                    self.advance();
                    TokenKind::FatArrow
                } else {
                    TokenKind::Eq
                }
            }

            // < or <= or << or <<=
            b'<' => {
                if self.peek() == Some(b'=') {
                    self.advance();
                    TokenKind::LtEq
                } else if self.peek() == Some(b'<') {
                    self.advance();
                    if self.peek() == Some(b'=') {
                        self.advance();
                        TokenKind::ShlEq
                    } else {
                        TokenKind::Shl
                    }
                } else {
                    TokenKind::Lt
                }
            }

            // > or >= or >> or >>=
            b'>' => {
                if self.peek() == Some(b'=') {
                    self.advance();
                    TokenKind::GtEq
                } else if self.peek() == Some(b'>') {
                    self.advance();
                    if self.peek() == Some(b'=') {
                        self.advance();
                        TokenKind::ShrEq
                    } else {
                        TokenKind::Shr
                    }
                } else {
                    TokenKind::Gt
                }
            }

            // String literal
            b'"' => self.lex_string(start_line, start_col),

            // Number literal
            b'0'..=b'9' => self.lex_number(ch, start, start_line, start_col),

            // Identifier or keyword
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                self.lex_ident_or_keyword(ch, start)
            }

            // Unknown character — error recovery
            _ => {
                self.errors.push(LexError {
                    message: format!("unexpected character: {:?}", ch as char),
                    line: start_line,
                    col: start_col,
                });
                // Skip and try next token
                return self.next_token();
            }
        };

        Token {
            kind,
            span: self.make_span(start, start_line, start_col),
        }
    }

    fn lex_attribute(&mut self, _start: usize, start_line: u32, start_col: u32) -> TokenKind {
        // Already consumed #[, now read until ]
        let content_start = self.pos;
        let mut depth = 1u32;
        while depth > 0 {
            match self.advance() {
                Some(b'[') => depth += 1,
                Some(b']') => depth -= 1,
                Some(_) => {}
                None => {
                    self.errors.push(LexError {
                        message: "unterminated attribute".into(),
                        line: start_line,
                        col: start_col,
                    });
                    return TokenKind::Attribute(String::new());
                }
            }
        }
        let content = std::str::from_utf8(&self.src[content_start..self.pos - 1])
            .unwrap_or("")
            .to_string();
        TokenKind::Attribute(content)
    }

    fn lex_string(&mut self, start_line: u32, start_col: u32) -> TokenKind {
        let mut s = String::new();
        loop {
            match self.advance() {
                Some(b'"') => return TokenKind::StringLiteral(s),
                Some(b'\\') => {
                    match self.advance() {
                        Some(b'n') => s.push('\n'),
                        Some(b't') => s.push('\t'),
                        Some(b'r') => s.push('\r'),
                        Some(b'\\') => s.push('\\'),
                        Some(b'"') => s.push('"'),
                        Some(b'0') => s.push('\0'),
                        Some(b'x') => {
                            // \xHH hex escape
                            let hi = self.advance().unwrap_or(b'0');
                            let lo = self.advance().unwrap_or(b'0');
                            let val = hex_digit(hi) * 16 + hex_digit(lo);
                            s.push(val as char);
                        }
                        Some(c) => {
                            self.errors.push(LexError {
                                message: format!("unknown escape sequence: \\{}", c as char),
                                line: self.line,
                                col: self.col,
                            });
                            s.push(c as char);
                        }
                        None => {
                            self.errors.push(LexError {
                                message: "unterminated string literal".into(),
                                line: start_line,
                                col: start_col,
                            });
                            return TokenKind::StringLiteral(s);
                        }
                    }
                }
                Some(b'\n') => {
                    self.errors.push(LexError {
                        message: "unterminated string literal (newline in string)".into(),
                        line: start_line,
                        col: start_col,
                    });
                    return TokenKind::StringLiteral(s);
                }
                Some(c) => s.push(c as char),
                None => {
                    self.errors.push(LexError {
                        message: "unterminated string literal".into(),
                        line: start_line,
                        col: start_col,
                    });
                    return TokenKind::StringLiteral(s);
                }
            }
        }
    }

    fn lex_number(&mut self, first: u8, _start: usize, start_line: u32, start_col: u32) -> TokenKind {
        // Check for hex: 0x...
        if first == b'0' && self.peek() == Some(b'x') {
            self.advance(); // consume 'x'
            return self.lex_hex_number(start_line, start_col);
        }

        let mut val: U256 = U256::from((first - b'0') as u64);
        while let Some(ch) = self.peek() {
            match ch {
                b'0'..=b'9' => {
                    self.advance();
                    val = val.checked_mul(U256::from(10u64))
                        .and_then(|v| v.checked_add(U256::from((ch - b'0') as u64)))
                        .unwrap_or_else(|| {
                            self.errors.push(LexError {
                                message: "integer literal overflow (max u256)".into(),
                                line: start_line,
                                col: start_col,
                            });
                            U256::ZERO
                        });
                }
                b'_' => { self.advance(); } // underscore separator
                _ => break,
            }
        }
        TokenKind::IntLiteral(val)
    }

    fn lex_hex_number(&mut self, start_line: u32, start_col: u32) -> TokenKind {
        let mut val: U256 = U256::ZERO;
        let mut has_digits = false;
        while let Some(ch) = self.peek() {
            match ch {
                b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                    self.advance();
                    has_digits = true;
                    val = val.checked_mul(U256::from(16u64))
                        .and_then(|v| v.checked_add(U256::from(hex_digit(ch) as u64)))
                        .unwrap_or_else(|| {
                            self.errors.push(LexError {
                                message: "hex literal overflow (max u256)".into(),
                                line: start_line,
                                col: start_col,
                            });
                            U256::ZERO
                        });
                }
                b'_' => { self.advance(); }
                _ => break,
            }
        }
        if !has_digits {
            self.errors.push(LexError {
                message: "expected hex digits after 0x".into(),
                line: start_line,
                col: start_col,
            });
        }
        TokenKind::IntLiteral(val)
    }

    fn lex_ident_or_keyword(&mut self, _first: u8, start: usize) -> TokenKind {
        let ident_start = start;
        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphanumeric() || ch == b'_' {
                self.advance();
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.src[ident_start..self.pos]).unwrap_or("");

        // _ as a standalone token is the wildcard pattern
        if text == "_" {
            return TokenKind::Underscore;
        }

        TokenKind::keyword(text).unwrap_or_else(|| TokenKind::Ident(text.to_string()))
    }
}

fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lex(src: &str) -> Vec<TokenKind> {
        let (tokens, errors) = Lexer::new(src).tokenize();
        assert!(errors.is_empty(), "unexpected errors: {:?}", errors);
        tokens.into_iter().map(|t| t.kind).collect()
    }

    fn lex_with_errors(src: &str) -> (Vec<TokenKind>, Vec<LexError>) {
        let (tokens, errors) = Lexer::new(src).tokenize();
        (tokens.into_iter().map(|t| t.kind).collect(), errors)
    }

    // ========== Keywords ==========

    #[test]
    fn lex_all_keywords() {
        let src = "contract storage struct interface event error enum const \
                   fn pub let mut if else for while match return emit try \
                   use module in as break continue self type true false";
        let kinds = lex(src);
        assert_eq!(kinds, vec![
            TokenKind::Contract, TokenKind::Storage, TokenKind::Struct,
            TokenKind::Interface, TokenKind::Event, TokenKind::Error,
            TokenKind::Enum, TokenKind::Const, TokenKind::Fn, TokenKind::Pub,
            TokenKind::Let, TokenKind::Mut, TokenKind::If, TokenKind::Else,
            TokenKind::For, TokenKind::While, TokenKind::Match, TokenKind::Return,
            TokenKind::Emit, TokenKind::Try, TokenKind::Use, TokenKind::Module,
            TokenKind::In, TokenKind::As, TokenKind::Break, TokenKind::Continue,
            TokenKind::SelfKw, TokenKind::TypeKw, TokenKind::True, TokenKind::False,
            TokenKind::Eof,
        ]);
    }

    // ========== Identifiers ==========

    #[test]
    fn lex_identifiers() {
        let kinds = lex("foo bar_baz MyType _private x123");
        assert_eq!(kinds, vec![
            TokenKind::Ident("foo".into()),
            TokenKind::Ident("bar_baz".into()),
            TokenKind::Ident("MyType".into()),
            TokenKind::Ident("_private".into()),
            TokenKind::Ident("x123".into()),
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn underscore_is_wildcard() {
        let kinds = lex("_ => foo");
        assert_eq!(kinds, vec![
            TokenKind::Underscore,
            TokenKind::FatArrow,
            TokenKind::Ident("foo".into()),
            TokenKind::Eof,
        ]);
    }

    // ========== Numeric literals ==========

    #[test]
    fn lex_decimal_integers() {
        let kinds = lex("0 42 1000 999999");
        assert_eq!(kinds, vec![
            TokenKind::IntLiteral(U256::from(0u64)),
            TokenKind::IntLiteral(U256::from(42u64)),
            TokenKind::IntLiteral(U256::from(1000u64)),
            TokenKind::IntLiteral(U256::from(999999u64)),
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_hex_integers() {
        let kinds = lex("0xFF 0x0 0xDEAD_BEEF 0xABCDEF");
        assert_eq!(kinds, vec![
            TokenKind::IntLiteral(U256::from(0xFFu64)),
            TokenKind::IntLiteral(U256::from(0x0u64)),
            TokenKind::IntLiteral(U256::from(0xDEAD_BEEFu64)),
            TokenKind::IntLiteral(U256::from(0xABCDEFu64)),
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_underscored_numbers() {
        let kinds = lex("1_000_000 0xFF_FF");
        assert_eq!(kinds, vec![
            TokenKind::IntLiteral(U256::from(1_000_000u64)),
            TokenKind::IntLiteral(U256::from(0xFFFFu64)),
            TokenKind::Eof,
        ]);
    }

    // ========== String literals ==========

    #[test]
    fn lex_simple_string() {
        let kinds = lex(r#""hello world""#);
        assert_eq!(kinds, vec![
            TokenKind::StringLiteral("hello world".into()),
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_string_with_escapes() {
        let kinds = lex(r#""hello\nworld\t\"foo\\bar""#);
        assert_eq!(kinds, vec![
            TokenKind::StringLiteral("hello\nworld\t\"foo\\bar".into()),
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_empty_string() {
        let kinds = lex(r#""""#);
        assert_eq!(kinds, vec![
            TokenKind::StringLiteral("".into()),
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_hex_escape_in_string() {
        let kinds = lex(r#""\x41\x42""#);
        assert_eq!(kinds, vec![
            TokenKind::StringLiteral("AB".into()),
            TokenKind::Eof,
        ]);
    }

    // ========== Operators ==========

    #[test]
    fn lex_arithmetic_operators() {
        let kinds = lex("+ - * / %");
        assert_eq!(kinds, vec![
            TokenKind::Plus, TokenKind::Minus, TokenKind::Star,
            TokenKind::Slash, TokenKind::Percent, TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_comparison_operators() {
        let kinds = lex("== != < > <= >=");
        assert_eq!(kinds, vec![
            TokenKind::EqEq, TokenKind::BangEq, TokenKind::Lt, TokenKind::Gt,
            TokenKind::LtEq, TokenKind::GtEq, TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_logical_operators() {
        let kinds = lex("&& || !");
        assert_eq!(kinds, vec![
            TokenKind::AmpAmp, TokenKind::PipePipe, TokenKind::Bang,
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_bitwise_operators() {
        let kinds = lex("& | ^ ~ << >>");
        assert_eq!(kinds, vec![
            TokenKind::Amp, TokenKind::Pipe, TokenKind::Caret,
            TokenKind::Tilde, TokenKind::Shl, TokenKind::Shr, TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_assignment_operators() {
        let kinds = lex("= += -= *= /= %= &= |= ^= <<= >>=");
        assert_eq!(kinds, vec![
            TokenKind::Eq, TokenKind::PlusEq, TokenKind::MinusEq,
            TokenKind::StarEq, TokenKind::SlashEq, TokenKind::PercentEq,
            TokenKind::AmpEq, TokenKind::PipeEq, TokenKind::CaretEq,
            TokenKind::ShlEq, TokenKind::ShrEq, TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_arrow_operators() {
        let kinds = lex("-> =>");
        assert_eq!(kinds, vec![
            TokenKind::Arrow, TokenKind::FatArrow, TokenKind::Eof,
        ]);
    }

    // ========== Punctuation ==========

    #[test]
    fn lex_punctuation() {
        let kinds = lex("{ } ( ) [ ] , ; : :: . .. ? #");
        assert_eq!(kinds, vec![
            TokenKind::LBrace, TokenKind::RBrace, TokenKind::LParen,
            TokenKind::RParen, TokenKind::LBracket, TokenKind::RBracket,
            TokenKind::Comma, TokenKind::Semicolon, TokenKind::Colon,
            TokenKind::ColonColon, TokenKind::Dot, TokenKind::DotDot,
            TokenKind::Question, TokenKind::Hash, TokenKind::Eof,
        ]);
    }

    // ========== Attributes ==========

    #[test]
    fn lex_attributes() {
        let kinds = lex("#[constructor] #[view] #[reentrant] #[parallel_safe]");
        assert_eq!(kinds, vec![
            TokenKind::Attribute("constructor".into()),
            TokenKind::Attribute("view".into()),
            TokenKind::Attribute("reentrant".into()),
            TokenKind::Attribute("parallel_safe".into()),
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_attribute_with_args() {
        let kinds = lex("#[role(ADMIN)] #[should_panic(expected = \"overflow\")]");
        assert_eq!(kinds, vec![
            TokenKind::Attribute("role(ADMIN)".into()),
            TokenKind::Attribute("should_panic(expected = \"overflow\")".into()),
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_indexed_attribute() {
        let kinds = lex("#[indexed] #[test] #[sponsored] #[only_owner]");
        assert_eq!(kinds, vec![
            TokenKind::Attribute("indexed".into()),
            TokenKind::Attribute("test".into()),
            TokenKind::Attribute("sponsored".into()),
            TokenKind::Attribute("only_owner".into()),
            TokenKind::Eof,
        ]);
    }

    // ========== Comments ==========

    #[test]
    fn lex_line_comment() {
        let kinds = lex("foo // this is a comment\nbar");
        assert_eq!(kinds, vec![
            TokenKind::Ident("foo".into()),
            TokenKind::Ident("bar".into()),
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_block_comment() {
        let kinds = lex("foo /* block comment */ bar");
        assert_eq!(kinds, vec![
            TokenKind::Ident("foo".into()),
            TokenKind::Ident("bar".into()),
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_nested_block_comment() {
        let kinds = lex("foo /* outer /* inner */ still comment */ bar");
        assert_eq!(kinds, vec![
            TokenKind::Ident("foo".into()),
            TokenKind::Ident("bar".into()),
            TokenKind::Eof,
        ]);
    }

    // ========== Source locations ==========

    #[test]
    fn lex_tracks_line_and_column() {
        let (tokens, _) = Lexer::new("foo\nbar  baz").tokenize();
        assert_eq!(tokens[0].span.line, 1);
        assert_eq!(tokens[0].span.col, 1);
        assert_eq!(tokens[1].span.line, 2);
        assert_eq!(tokens[1].span.col, 1);
        assert_eq!(tokens[2].span.line, 2);
        assert_eq!(tokens[2].span.col, 6);
    }

    // ========== Error recovery ==========

    #[test]
    fn lex_error_recovery() {
        let (kinds, errors) = lex_with_errors("foo @ bar");
        // Should skip '@' and continue
        assert_eq!(kinds, vec![
            TokenKind::Ident("foo".into()),
            TokenKind::Ident("bar".into()),
            TokenKind::Eof,
        ]);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("unexpected character"));
    }

    #[test]
    fn lex_unterminated_string() {
        let (kinds, errors) = lex_with_errors("\"hello");
        assert_eq!(kinds.len(), 2); // StringLiteral + Eof
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("unterminated string"));
    }

    #[test]
    fn lex_unterminated_block_comment() {
        let (_, errors) = lex_with_errors("foo /* unterminated");
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("unterminated block comment"));
    }

    // ========== Full contract ==========

    #[test]
    fn lex_simple_contract() {
        let src = r#"
contract Token {
    storage {
        total_supply: u256,
        balances: Map<Address, u256>,
    }

    event Transfer {
        #[indexed]
        from: Address,
        to: Address,
        amount: u256,
    }

    #[constructor]
    pub fn init(supply: u256) {
        self.total_supply = supply;
        self.balances[msg.sender] = supply;
    }

    #[view]
    pub fn balance_of(owner: Address) -> u256 {
        return self.balances[owner];
    }
}
"#;
        let (tokens, errors) = Lexer::new(src).tokenize();
        assert!(errors.is_empty(), "errors: {:?}", errors);
        // Just verify it produces tokens without errors
        assert!(tokens.len() > 40);
        assert_eq!(tokens.last().unwrap().kind, TokenKind::Eof);
        // First real token is 'contract'
        assert_eq!(tokens[0].kind, TokenKind::Contract);
    }

    // ========== Edge cases ==========

    #[test]
    fn lex_empty_source() {
        let kinds = lex("");
        assert_eq!(kinds, vec![TokenKind::Eof]);
    }

    #[test]
    fn lex_only_whitespace() {
        let kinds = lex("   \n\n\t  ");
        assert_eq!(kinds, vec![TokenKind::Eof]);
    }

    #[test]
    fn lex_range_expression() {
        let kinds = lex("0..10");
        assert_eq!(kinds, vec![
            TokenKind::IntLiteral(U256::from(0u64)),
            TokenKind::DotDot,
            TokenKind::IntLiteral(U256::from(10u64)),
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_generic_type() {
        // Map<Address, u256> should lex as individual tokens
        let kinds = lex("Map<Address, u256>");
        assert_eq!(kinds, vec![
            TokenKind::Ident("Map".into()),
            TokenKind::Lt,
            TokenKind::Ident("Address".into()),
            TokenKind::Comma,
            TokenKind::Ident("u256".into()),
            TokenKind::Gt,
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_method_call_chain() {
        let kinds = lex("self.balances[msg.sender]");
        assert_eq!(kinds, vec![
            TokenKind::SelfKw,
            TokenKind::Dot,
            TokenKind::Ident("balances".into()),
            TokenKind::LBracket,
            TokenKind::Ident("msg".into()),
            TokenKind::Dot,
            TokenKind::Ident("sender".into()),
            TokenKind::RBracket,
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn lex_require_macro() {
        let kinds = lex("require!(balance >= amount, InsufficientBalance {})");
        assert_eq!(kinds, vec![
            TokenKind::Ident("require".into()),
            TokenKind::Bang,
            TokenKind::LParen,
            TokenKind::Ident("balance".into()),
            TokenKind::GtEq,
            TokenKind::Ident("amount".into()),
            TokenKind::Comma,
            TokenKind::Ident("InsufficientBalance".into()),
            TokenKind::LBrace,
            TokenKind::RBrace,
            TokenKind::RParen,
            TokenKind::Eof,
        ]);
    }
}
