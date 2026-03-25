//! PVM Assembler and Disassembler.
//!
//! Assembly syntax:
//! ```text
//! ; line comments
//! label:
//!     add r3, r1, r2        ; GP arithmetic
//!     addi r1, r0, 42       ; immediate
//!     wadd w0, w1, w2       ; wide arithmetic
//!     load64 r1, r2, 8      ; load 64-bit from [r2+8]
//!     load8 r1, r2, 0       ; load 8-bit
//!     store32 r1, r2, -4    ; store 32-bit to [r2-4]
//!     wload w0, r1, 0       ; load 256-bit
//!     jmp loop              ; jump to label
//!     beq r1, r0, done      ; branch to label
//!     halt
//! ```

use crate::isa::{
    decode, decode_mem_offset, decode_mem_width, encode, encode_immediate, encode_mem_immediate,
    sign_extend_18, Instruction, MemWidth, Opcode,
};
use std::collections::HashMap;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum AsmError {
    #[error("line {line}: {msg}")]
    Parse { line: usize, msg: String },
    #[error("undefined label '{0}'")]
    UndefinedLabel(String),
    #[error("duplicate label '{0}'")]
    DuplicateLabel(String),
    #[error("immediate out of range: {0}")]
    ImmediateRange(String),
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Mnemonic(String),
    Register(u8),     // r0-r15
    WideRegister(u8), // w0-w7
    Immediate(i64),
    Label(String),    // "foo:"
    LabelRef(String), // "foo" used as operand
    Directive(String), // ".ascii", ".bytes", ".align"
    StringLiteral(Vec<u8>), // "hello"
    Comma,
    Newline,
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

fn lex(source: &str) -> Result<Vec<(usize, Token)>, AsmError> {
    let mut tokens = Vec::new();

    for (line_idx, line) in source.lines().enumerate() {
        let line_num = line_idx + 1;
        // Strip comments
        let line = if let Some(pos) = line.find(';') {
            &line[..pos]
        } else {
            line
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let mut chars = line.chars().peekable();

        while let Some(&ch) = chars.peek() {
            if ch.is_whitespace() {
                chars.next();
                continue;
            }

            if ch == ',' {
                tokens.push((line_num, Token::Comma));
                chars.next();
                continue;
            }

            // Negative number
            if ch == '-' {
                chars.next();
                let num_str: String = chars
                    .by_ref()
                    .take_while(|c| c.is_ascii_digit() || *c == 'x' || c.is_ascii_hexdigit())
                    .collect();
                if num_str.is_empty() {
                    return Err(AsmError::Parse {
                        line: line_num,
                        msg: "expected number after '-'".into(),
                    });
                }
                let val = parse_int(&num_str).map_err(|e| AsmError::Parse {
                    line: line_num,
                    msg: e,
                })?;
                tokens.push((line_num, Token::Immediate(-val)));
                continue;
            }

            // Number (decimal or 0x hex)
            if ch.is_ascii_digit() {
                let num_str: String = std::iter::once(ch)
                    .chain(
                        chars
                            .by_ref()
                            .skip(1)
                            .take_while(|c| c.is_ascii_hexdigit() || *c == 'x'),
                    )
                    .collect();
                let val = parse_int(&num_str).map_err(|e| AsmError::Parse {
                    line: line_num,
                    msg: e,
                })?;
                tokens.push((line_num, Token::Immediate(val)));
                continue;
            }

            // String literal
            if ch == '"' {
                chars.next(); // skip opening quote
                let mut bytes = Vec::new();
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some('n') => bytes.push(b'\n'),
                            Some('t') => bytes.push(b'\t'),
                            Some('\\') => bytes.push(b'\\'),
                            Some('"') => bytes.push(b'"'),
                            Some('0') => bytes.push(0),
                            Some(c) => {
                                return Err(AsmError::Parse {
                                    line: line_num,
                                    msg: format!("unknown escape '\\{}'", c),
                                })
                            }
                            None => {
                                return Err(AsmError::Parse {
                                    line: line_num,
                                    msg: "unterminated string".into(),
                                })
                            }
                        },
                        Some(c) => bytes.push(c as u8),
                        None => {
                            return Err(AsmError::Parse {
                                line: line_num,
                                msg: "unterminated string".into(),
                            })
                        }
                    }
                }
                tokens.push((line_num, Token::StringLiteral(bytes)));
                continue;
            }

            // Directive (.ascii, .bytes, .align)
            if ch == '.' {
                chars.next();
                let name: String = chars
                    .by_ref()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                tokens.push((line_num, Token::Directive(name.to_lowercase())));
                continue;
            }

            // Identifier: mnemonic, register, label, or label ref
            if ch.is_ascii_alphabetic() || ch == '_' {
                let ident: String = std::iter::once(ch)
                    .chain({
                        chars.next();
                        let mut rest = Vec::new();
                        while let Some(&c) = chars.peek() {
                            if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
                                rest.push(c);
                                chars.next();
                            } else {
                                break;
                            }
                        }
                        rest.into_iter()
                    })
                    .collect();

                // Check for label definition (followed by ':')
                if chars.peek() == Some(&':') {
                    chars.next();
                    tokens.push((line_num, Token::Label(ident.to_lowercase())));
                    continue;
                }

                let lower = ident.to_lowercase();

                // Register
                if let Some(reg) = parse_gp_reg(&lower) {
                    tokens.push((line_num, Token::Register(reg)));
                } else if let Some(wreg) = parse_wide_reg(&lower) {
                    tokens.push((line_num, Token::WideRegister(wreg)));
                } else if is_mnemonic(&lower) {
                    tokens.push((line_num, Token::Mnemonic(lower)));
                } else {
                    // Must be a label reference
                    tokens.push((line_num, Token::LabelRef(lower)));
                }

                continue;
            }

            return Err(AsmError::Parse {
                line: line_num,
                msg: format!("unexpected character '{}'", ch),
            });
        }

        tokens.push((line_num, Token::Newline));
    }

    Ok(tokens)
}

fn parse_int(s: &str) -> Result<i64, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        i64::from_str_radix(&s[2..], 16).map_err(|e| format!("invalid hex '{}': {}", s, e))
    } else {
        s.parse::<i64>()
            .map_err(|e| format!("invalid number '{}': {}", s, e))
    }
}

fn parse_gp_reg(s: &str) -> Option<u8> {
    if let Some(rest) = s.strip_prefix('r') {
        rest.parse::<u8>().ok().filter(|&n| n <= 15)
    } else {
        None
    }
}

fn parse_wide_reg(s: &str) -> Option<u8> {
    if let Some(rest) = s.strip_prefix('w') {
        if rest.len() == 1 {
            rest.parse::<u8>().ok().filter(|&n| n <= 7)
        } else {
            None
        }
    } else {
        None
    }
}

/// Pseudo-mnemonics for width-encoded load/store.
#[derive(Clone, Copy, Debug)]
enum PseudoMem {
    Load(MemWidth),
    Store(MemWidth),
}

fn parse_pseudo_mem(s: &str) -> Option<PseudoMem> {
    match s {
        "load8" => Some(PseudoMem::Load(MemWidth::W8)),
        "load16" => Some(PseudoMem::Load(MemWidth::W16)),
        "load32" => Some(PseudoMem::Load(MemWidth::W32)),
        "load64" | "load" => Some(PseudoMem::Load(MemWidth::W64)),
        "store8" => Some(PseudoMem::Store(MemWidth::W8)),
        "store16" => Some(PseudoMem::Store(MemWidth::W16)),
        "store32" => Some(PseudoMem::Store(MemWidth::W32)),
        "store64" | "store" => Some(PseudoMem::Store(MemWidth::W64)),
        _ => None,
    }
}

/// Pseudo-mnemonics for system/env instructions that map to Caller/Callvalue
/// with a sub-code in the immediate field.
#[derive(Clone, Copy, Debug)]
enum PseudoEnv {
    /// GP-width query: maps to Caller opcode with sub-code in imm
    Gp(u32),
    /// Wide query: maps to Callvalue opcode with sub-code in imm
    Wide(u32),
    /// Wide query that also takes an rs1 input (e.g., balance)
    WideWithInput(u32),
}

fn parse_pseudo_env(s: &str) -> Option<PseudoEnv> {
    use crate::vm::{env_gp, env_wide};
    match s {
        "blocknumber" => Some(PseudoEnv::Gp(env_gp::BLOCK_NUMBER)),
        "timestamp" => Some(PseudoEnv::Gp(env_gp::TIMESTAMP)),
        "gasremaining" => Some(PseudoEnv::Gp(env_gp::GAS_REMAINING)),
        "caller" => Some(PseudoEnv::Wide(env_wide::CALLER)),
        "address" => Some(PseudoEnv::Wide(env_wide::ADDRESS)),
        "gasprice" => Some(PseudoEnv::Wide(env_wide::GAS_PRICE)),
        "balance" => Some(PseudoEnv::WideWithInput(env_wide::BALANCE)),
        _ => None,
    }
}

fn is_mnemonic(s: &str) -> bool {
    s == "la"
        || parse_pseudo_mem(s).is_some()
        || parse_pseudo_env(s).is_some()
        || mnemonic_to_opcode(s).is_some()
}

fn mnemonic_to_opcode(s: &str) -> Option<Opcode> {
    match s {
        "add" => Some(Opcode::Add),
        "sub" => Some(Opcode::Sub),
        "mul" => Some(Opcode::Mul),
        "div" => Some(Opcode::Div),
        "mod" => Some(Opcode::Mod),
        "and" => Some(Opcode::And),
        "or" => Some(Opcode::Or),
        "xor" => Some(Opcode::Xor),
        "addi" => Some(Opcode::Addi),
        "not" => Some(Opcode::Not),
        "shl" => Some(Opcode::Shl),
        "shr" => Some(Opcode::Shr),
        "sar" => Some(Opcode::Sar),
        "lt" => Some(Opcode::Lt),
        "gt" => Some(Opcode::Gt),
        "eq" => Some(Opcode::Eq),
        "slt" => Some(Opcode::Slt),
        "sgt" => Some(Opcode::Sgt),
        "wadd" => Some(Opcode::Wadd),
        "wsub" => Some(Opcode::Wsub),
        "wmul" => Some(Opcode::Wmul),
        "wdiv" => Some(Opcode::Wdiv),
        "wmod" => Some(Opcode::Wmod),
        "wand" => Some(Opcode::Wand),
        "wor" => Some(Opcode::Wor),
        "wxor" => Some(Opcode::Wxor),
        "wnot" => Some(Opcode::Wnot),
        "wmov" => Some(Opcode::Wmov),
        "narrow" => Some(Opcode::Narrow),
        "widen" => Some(Opcode::Widen),
        "weq" => Some(Opcode::Weq),
        "wlt" => Some(Opcode::Wlt),
        "wload" => Some(Opcode::Wload),
        "wstore" => Some(Opcode::Wstore),
        "push" => Some(Opcode::Push),
        "pop" => Some(Opcode::Pop),
        "jmp" => Some(Opcode::Jmp),
        "beq" => Some(Opcode::Beq),
        "bne" => Some(Opcode::Bne),
        "blt" => Some(Opcode::Blt),
        "bge" => Some(Opcode::Bge),
        "call" => Some(Opcode::Call),
        "ret" => Some(Opcode::Ret),
        "halt" => Some(Opcode::Halt),
        "revert" => Some(Opcode::Revert),
        "assert" => Some(Opcode::Assert),
        "sload" | "sloadb" | "sloadg" => Some(Opcode::Sload),
        "sstore" | "sstoreb" | "sstoreg" => Some(Opcode::Sstore),
        "sdelete" => Some(Opcode::Sdelete),
        "caller" => Some(Opcode::Caller),
        "callvalue" => Some(Opcode::Callvalue),
        "blockhash" => Some(Opcode::Blockhash),
        "callext" => Some(Opcode::CallExt),
        "delegate" => Some(Opcode::Delegate),
        "create" => Some(Opcode::Create),
        "selfdestruct" => Some(Opcode::Selfdestruct),
        "log" => Some(Opcode::Log),
        "poseidon" => Some(Opcode::Poseidon),
        "verifysig" => Some(Opcode::VerifySig),
        "merkleverify" => Some(Opcode::MerkleVerify),
        "memcpy" => Some(Opcode::Memcpy),
        "commit" => Some(Opcode::Commit),
        _ => None,
    }
}

fn opcode_to_mnemonic(op: Opcode) -> &'static str {
    match op {
        Opcode::Add => "add",
        Opcode::Sub => "sub",
        Opcode::Mul => "mul",
        Opcode::Div => "div",
        Opcode::Mod => "mod",
        Opcode::And => "and",
        Opcode::Or => "or",
        Opcode::Xor => "xor",
        Opcode::Addi => "addi",
        Opcode::Not => "not",
        Opcode::Shl => "shl",
        Opcode::Shr => "shr",
        Opcode::Sar => "sar",
        Opcode::Lt => "lt",
        Opcode::Gt => "gt",
        Opcode::Eq => "eq",
        Opcode::Slt => "slt",
        Opcode::Sgt => "sgt",
        Opcode::Wadd => "wadd",
        Opcode::Wsub => "wsub",
        Opcode::Wmul => "wmul",
        Opcode::Wdiv => "wdiv",
        Opcode::Wmod => "wmod",
        Opcode::Wand => "wand",
        Opcode::Wor => "wor",
        Opcode::Wxor => "wxor",
        Opcode::Wnot => "wnot",
        Opcode::Wmov => "wmov",
        Opcode::Narrow => "narrow",
        Opcode::Widen => "widen",
        Opcode::Weq => "weq",
        Opcode::Wlt => "wlt",
        Opcode::Load => "load64",
        Opcode::Store => "store64",
        Opcode::Wload => "wload",
        Opcode::Wstore => "wstore",
        Opcode::Push => "push",
        Opcode::Pop => "pop",
        Opcode::Jmp => "jmp",
        Opcode::Beq => "beq",
        Opcode::Bne => "bne",
        Opcode::Blt => "blt",
        Opcode::Bge => "bge",
        Opcode::Call => "call",
        Opcode::Ret => "ret",
        Opcode::Halt => "halt",
        Opcode::Revert => "revert",
        Opcode::Assert => "assert",
        Opcode::Sload => "sload",
        Opcode::Sstore => "sstore",
        Opcode::Sdelete => "sdelete",
        Opcode::Caller => "caller",
        Opcode::Callvalue => "callvalue",
        Opcode::Blockhash => "blockhash",
        Opcode::CallExt => "callext",
        Opcode::Delegate => "delegate",
        Opcode::Create => "create",
        Opcode::Selfdestruct => "selfdestruct",
        Opcode::Log => "log",
        Opcode::Poseidon => "poseidon",
        Opcode::VerifySig => "verifysig",
        Opcode::MerkleVerify => "merkleverify",
        Opcode::Memcpy => "memcpy",
        Opcode::Commit => "commit",
        Opcode::Invalid => "invalid",
    }
}

// ---------------------------------------------------------------------------
// Parsed instruction (before label resolution)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Operand {
    GpReg(u8),
    WideReg(u8),
    Imm(i64),
    LabelRef(String),
}

#[derive(Clone, Debug)]
struct ParsedInstr {
    line: usize,
    opcode: Opcode,
    /// For pseudo load/store, the width.
    mem_width: Option<MemWidth>,
    /// For pseudo env instructions, the sub-code and variant.
    env_pseudo: Option<PseudoEnv>,
    /// Storage mode: 0=wide, 1=memory, 2=gp.
    storage_mode: u8,
    operands: Vec<Operand>,
}

/// A parsed item: either an instruction or raw data.
#[derive(Clone, Debug)]
enum ParsedItem {
    Instr(ParsedInstr),
    /// Raw data bytes (from .ascii, .bytes directives).
    Data(Vec<u8>),
    /// Load address pseudo: `la rd, label` → addi rd, r0, CODE_START + label_offset
    LoadAddr { line: usize, rd: u8, label: String },
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

fn parse(
    tokens: &[(usize, Token)],
) -> Result<(Vec<ParsedItem>, HashMap<String, u32>), AsmError> {
    let mut items: Vec<ParsedItem> = Vec::new();
    let mut labels: HashMap<String, u32> = HashMap::new();
    let mut offset: u32 = 0;

    let mut i = 0;
    while i < tokens.len() {
        let (line, ref tok) = tokens[i];

        match tok {
            Token::Newline => {
                i += 1;
                continue;
            }
            Token::Label(name) => {
                if labels.contains_key(name) {
                    return Err(AsmError::DuplicateLabel(name.clone()));
                }
                labels.insert(name.clone(), offset);
                i += 1;
                continue;
            }
            Token::Directive(dir) => {
                i += 1;
                match dir.as_str() {
                    "ascii" | "bytes" => {
                        // Collect data: string literals and/or comma-separated bytes
                        let mut data = Vec::new();
                        while i < tokens.len() {
                            let (_, ref t) = tokens[i];
                            match t {
                                Token::Newline => break,
                                Token::Comma => {
                                    i += 1;
                                    continue;
                                }
                                Token::StringLiteral(bytes) => {
                                    data.extend_from_slice(bytes);
                                    i += 1;
                                }
                                Token::Immediate(v) => {
                                    data.push(*v as u8);
                                    i += 1;
                                }
                                _ => {
                                    return Err(AsmError::Parse {
                                        line,
                                        msg: format!(
                                            ".{} expects string literals or byte values",
                                            dir
                                        ),
                                    });
                                }
                            }
                        }
                        let len = data.len() as u32;
                        items.push(ParsedItem::Data(data));
                        offset += len;
                    }
                    "align" => {
                        // Align to 4-byte boundary by padding with zeros
                        let padding = (4 - (offset % 4)) % 4;
                        if padding > 0 {
                            items.push(ParsedItem::Data(vec![0u8; padding as usize]));
                            offset += padding;
                        }
                        i += 1; // skip newline if present
                    }
                    _ => {
                        return Err(AsmError::Parse {
                            line,
                            msg: format!("unknown directive '.{}'", dir),
                        });
                    }
                }
            }
            Token::Mnemonic(mnem) => {
                // Handle `la rd, label` pseudo-instruction
                if mnem == "la" {
                    i += 1;
                    let rd = match tokens.get(i) {
                        Some((_, Token::Register(r))) => *r,
                        _ => {
                            return Err(AsmError::Parse {
                                line,
                                msg: "la requires: la rd, label".into(),
                            })
                        }
                    };
                    i += 1;
                    // skip comma
                    if matches!(tokens.get(i), Some((_, Token::Comma))) {
                        i += 1;
                    }
                    let label = match tokens.get(i) {
                        Some((_, Token::LabelRef(name))) => name.clone(),
                        _ => {
                            return Err(AsmError::Parse {
                                line,
                                msg: "la requires: la rd, label".into(),
                            })
                        }
                    };
                    i += 1;
                    items.push(ParsedItem::LoadAddr { line, rd, label });
                    offset += 4;
                    continue;
                }

                let mut operands = Vec::new();
                let mut mem_width = None;
                let opcode;

                let mut env_pseudo = None;

                if let Some(pseudo) = parse_pseudo_mem(mnem) {
                    match pseudo {
                        PseudoMem::Load(w) => {
                            opcode = Opcode::Load;
                            mem_width = Some(w);
                        }
                        PseudoMem::Store(w) => {
                            opcode = Opcode::Store;
                            mem_width = Some(w);
                        }
                    }
                } else if let Some(pseudo) = parse_pseudo_env(mnem) {
                    env_pseudo = Some(pseudo);
                    opcode = match pseudo {
                        PseudoEnv::Gp(_) => Opcode::Caller,
                        PseudoEnv::Wide(_) | PseudoEnv::WideWithInput(_) => Opcode::Callvalue,
                    };
                } else {
                    opcode = mnemonic_to_opcode(mnem).ok_or_else(|| AsmError::Parse {
                        line,
                        msg: format!("unknown mnemonic '{}'", mnem),
                    })?;
                }

                let storage_mode = match mnem.as_str() {
                    "sloadb" | "sstoreb" => 1,
                    "sloadg" | "sstoreg" => 2,
                    _ => 0,
                };

                i += 1;

                // Collect operands until newline or end
                while i < tokens.len() {
                    let (_, ref t) = tokens[i];
                    match t {
                        Token::Newline => break,
                        Token::Comma => {
                            i += 1;
                            continue;
                        }
                        Token::Register(r) => {
                            operands.push(Operand::GpReg(*r));
                            i += 1;
                        }
                        Token::WideRegister(w) => {
                            operands.push(Operand::WideReg(*w));
                            i += 1;
                        }
                        Token::Immediate(v) => {
                            operands.push(Operand::Imm(*v));
                            i += 1;
                        }
                        Token::LabelRef(name) => {
                            operands.push(Operand::LabelRef(name.clone()));
                            i += 1;
                        }
                        _ => {
                            return Err(AsmError::Parse {
                                line,
                                msg: format!("unexpected token {:?}", t),
                            });
                        }
                    }
                }

                items.push(ParsedItem::Instr(ParsedInstr {
                    line,
                    opcode,
                    mem_width,
                    env_pseudo,
                    storage_mode,
                    operands,
                }));
                offset += 4;
            }
            _ => {
                return Err(AsmError::Parse {
                    line,
                    msg: format!("expected mnemonic, directive, or label, got {:?}", tok),
                });
            }
        }
    }

    Ok((items, labels))
}

// ---------------------------------------------------------------------------
// Assembler (label resolution + encoding)
// ---------------------------------------------------------------------------

/// Assemble source text into bytecode.
pub fn assemble(source: &str) -> Result<Vec<u8>, AsmError> {
    let tokens = lex(source)?;
    let (items, labels) = parse(&tokens)?;

    let mut bytecode = Vec::new();

    for item in &items {
        let pc = bytecode.len() as u32;
        match item {
            ParsedItem::Instr(pi) => {
                let word = encode_instr(pi, pc, &labels)?;
                bytecode.extend_from_slice(&word.0.to_le_bytes());
            }
            ParsedItem::Data(data) => {
                bytecode.extend_from_slice(data);
            }
            ParsedItem::LoadAddr { line, rd, label } => {
                let target = *labels
                    .get(label)
                    .ok_or_else(|| AsmError::UndefinedLabel(label.clone()))?;
                let abs_addr = crate::memory::CODE_START + target;
                let abs_i32 = abs_addr as i32;
                if !(-131072..=131071).contains(&abs_i32) {
                    return Err(AsmError::ImmediateRange(format!(
                        "line {}: address 0x{:X} out of 18-bit range",
                        line, abs_addr
                    )));
                }
                let word = encode(Opcode::Addi, *rd, 0, encode_immediate(abs_i32));
                bytecode.extend_from_slice(&word.0.to_le_bytes());
            }
        }
    }

    Ok(bytecode)
}

fn resolve_label_offset(
    name: &str,
    pc: u32,
    labels: &HashMap<String, u32>,
) -> Result<i32, AsmError> {
    let target = *labels
        .get(name)
        .ok_or_else(|| AsmError::UndefinedLabel(name.to_string()))?;
    Ok(target as i32 - pc as i32)
}

fn expect_gp(op: &Operand, line: usize, pos: &str) -> Result<u8, AsmError> {
    match op {
        Operand::GpReg(r) => Ok(*r),
        _ => Err(AsmError::Parse {
            line,
            msg: format!("expected GP register for {}, got {:?}", pos, op),
        }),
    }
}

fn expect_wide(op: &Operand, line: usize, pos: &str) -> Result<u8, AsmError> {
    match op {
        Operand::WideReg(r) => Ok(*r),
        _ => Err(AsmError::Parse {
            line,
            msg: format!("expected wide register for {}, got {:?}", pos, op),
        }),
    }
}

fn expect_imm_or_label(
    op: &Operand,
    pc: u32,
    labels: &HashMap<String, u32>,
    line: usize,
) -> Result<i32, AsmError> {
    match op {
        Operand::Imm(v) => Ok(*v as i32),
        Operand::LabelRef(name) => resolve_label_offset(name, pc, labels),
        _ => Err(AsmError::Parse {
            line,
            msg: format!("expected immediate or label, got {:?}", op),
        }),
    }
}

fn expect_reg_or_imm(op: &Operand, line: usize) -> Result<u32, AsmError> {
    match op {
        Operand::GpReg(r) => Ok(*r as u32),
        Operand::WideReg(r) => Ok(*r as u32),
        Operand::Imm(v) => Ok(*v as u32),
        _ => Err(AsmError::Parse {
            line,
            msg: format!("expected register or immediate, got {:?}", op),
        }),
    }
}

fn encode_instr(
    pi: &ParsedInstr,
    pc: u32,
    labels: &HashMap<String, u32>,
) -> Result<Instruction, AsmError> {
    let ops = &pi.operands;
    let line = pi.line;

    // Env pseudo-mnemonics (address, blocknumber, timestamp, etc.)
    if let Some(env) = pi.env_pseudo {
        match env {
            PseudoEnv::Gp(sub) => {
                // e.g., "address r1" → Caller r1, r0, sub
                if ops.len() != 1 {
                    return Err(AsmError::Parse {
                        line,
                        msg: "env query requires 1 operand: rd".into(),
                    });
                }
                let rd = expect_gp(&ops[0], line, "rd")?;
                return Ok(encode(Opcode::Caller, rd, 0, sub));
            }
            PseudoEnv::Wide(sub) => {
                // e.g., "gasprice w0" → Callvalue w0, r0, sub
                if ops.len() != 1 {
                    return Err(AsmError::Parse {
                        line,
                        msg: "env query requires 1 operand: wd".into(),
                    });
                }
                let wd = expect_wide(&ops[0], line, "wd")?;
                return Ok(encode(Opcode::Callvalue, wd, 0, sub));
            }
            PseudoEnv::WideWithInput(sub) => {
                // e.g., "balance w0, r1" → Callvalue w0, r1, sub
                if ops.len() != 2 {
                    return Err(AsmError::Parse {
                        line,
                        msg: "balance requires 2 operands: wd, rs1".into(),
                    });
                }
                let wd = expect_wide(&ops[0], line, "wd")?;
                let rs1 = expect_gp(&ops[1], line, "rs1")?;
                return Ok(encode(Opcode::Callvalue, wd, rs1, sub));
            }
        }
    }

    // Width-encoded LOAD/STORE
    if let Some(width) = pi.mem_width {
        let actual_op = pi.opcode; // Load or Store
        if ops.len() != 3 {
            return Err(AsmError::Parse {
                line,
                msg: format!(
                    "{} requires 3 operands: rd, rs1, offset",
                    opcode_to_mnemonic(actual_op)
                ),
            });
        }
        let rd = expect_gp(&ops[0], line, "rd")?;
        let rs1 = expect_gp(&ops[1], line, "rs1")?;
        let offset = expect_imm_or_label(&ops[2], pc, labels, line)?;
        let imm = encode_mem_immediate(offset, width);
        return Ok(encode(actual_op, rd, rs1, imm));
    }

    match pi.opcode {
        // --- Three-register ops: op rd, rs1, rs2 ---
        Opcode::Add
        | Opcode::Sub
        | Opcode::Mul
        | Opcode::Div
        | Opcode::Mod
        | Opcode::And
        | Opcode::Or
        | Opcode::Xor
        | Opcode::Shl
        | Opcode::Shr
        | Opcode::Sar
        | Opcode::Lt
        | Opcode::Gt
        | Opcode::Eq
        | Opcode::Slt
        | Opcode::Sgt => {
            if ops.len() != 3 {
                return Err(AsmError::Parse {
                    line,
                    msg: format!("{} requires 3 operands", opcode_to_mnemonic(pi.opcode)),
                });
            }
            let rd = expect_gp(&ops[0], line, "rd")?;
            let rs1 = expect_gp(&ops[1], line, "rs1")?;
            let rs2 = expect_gp(&ops[2], line, "rs2")?;
            Ok(encode(pi.opcode, rd, rs1, rs2 as u32))
        }

        // --- Wide three-register: op wd, ws1, ws2 ---
        Opcode::Wadd
        | Opcode::Wsub
        | Opcode::Wmul
        | Opcode::Wdiv
        | Opcode::Wmod
        | Opcode::Wand
        | Opcode::Wor
        | Opcode::Wxor => {
            if ops.len() != 3 {
                return Err(AsmError::Parse {
                    line,
                    msg: format!("{} requires 3 operands", opcode_to_mnemonic(pi.opcode)),
                });
            }
            let wd = expect_wide(&ops[0], line, "wd")?;
            let ws1 = expect_wide(&ops[1], line, "ws1")?;
            let ws2 = expect_wide(&ops[2], line, "ws2")?;
            Ok(encode(pi.opcode, wd, ws1, ws2 as u32))
        }

        // --- Wide compare: op rd, ws1, ws2 (result → GP register) ---
        Opcode::Weq | Opcode::Wlt => {
            if ops.len() != 3 {
                return Err(AsmError::Parse {
                    line,
                    msg: format!("{} requires 3 operands", opcode_to_mnemonic(pi.opcode)),
                });
            }
            let rd = expect_gp(&ops[0], line, "rd")?;
            let ws1 = expect_wide(&ops[1], line, "ws1")?;
            let ws2 = expect_wide(&ops[2], line, "ws2")?;
            Ok(encode(pi.opcode, rd, ws1, ws2 as u32))
        }

        // --- rd = rs1 op imm: addi rd, rs1, imm ---
        Opcode::Addi => {
            if ops.len() != 3 {
                return Err(AsmError::Parse {
                    line,
                    msg: "addi requires 3 operands: rd, rs1, imm".into(),
                });
            }
            let rd = expect_gp(&ops[0], line, "rd")?;
            let rs1 = expect_gp(&ops[1], line, "rs1")?;
            let imm = expect_imm_or_label(&ops[2], pc, labels, line)?;
            Ok(encode(pi.opcode, rd, rs1, encode_immediate(imm)))
        }

        // --- Unary: not rd, rs1 ---
        Opcode::Not => {
            if ops.len() != 2 {
                return Err(AsmError::Parse {
                    line,
                    msg: "not requires 2 operands: rd, rs1".into(),
                });
            }
            let rd = expect_gp(&ops[0], line, "rd")?;
            let rs1 = expect_gp(&ops[1], line, "rs1")?;
            Ok(encode(pi.opcode, rd, rs1, 0))
        }

        // --- Wide unary: wnot wd, ws1 ---
        Opcode::Wnot => {
            if ops.len() != 2 {
                return Err(AsmError::Parse {
                    line,
                    msg: "wnot requires 2 operands: wd, ws1".into(),
                });
            }
            let wd = expect_wide(&ops[0], line, "wd")?;
            let ws1 = expect_wide(&ops[1], line, "ws1")?;
            Ok(encode(pi.opcode, wd, ws1, 0))
        }

        // --- Wide move: wmov wd, ws1 ---
        Opcode::Wmov => {
            if ops.len() != 2 {
                return Err(AsmError::Parse {
                    line,
                    msg: "wmov requires 2 operands: wd, ws1".into(),
                });
            }
            let wd = expect_wide(&ops[0], line, "wd")?;
            let ws1 = expect_wide(&ops[1], line, "ws1")?;
            Ok(encode(pi.opcode, wd, ws1, 0))
        }

        // --- Narrow: narrow rd, ws1 ---
        Opcode::Narrow => {
            if ops.len() != 2 {
                return Err(AsmError::Parse {
                    line,
                    msg: "narrow requires 2 operands: rd, ws1".into(),
                });
            }
            let rd = expect_gp(&ops[0], line, "rd")?;
            let ws1 = expect_wide(&ops[1], line, "ws1")?;
            Ok(encode(pi.opcode, rd, ws1, 0))
        }

        // --- Widen: widen wd, rs1 ---
        Opcode::Widen => {
            if ops.len() != 2 {
                return Err(AsmError::Parse {
                    line,
                    msg: "widen requires 2 operands: wd, rs1".into(),
                });
            }
            let wd = expect_wide(&ops[0], line, "wd")?;
            let rs1 = expect_gp(&ops[1], line, "rs1")?;
            Ok(encode(pi.opcode, wd, rs1, 0))
        }

        // --- WLOAD: wload wd, rs1, imm ---
        Opcode::Wload => {
            if ops.len() < 2 || ops.len() > 3 {
                return Err(AsmError::Parse {
                    line,
                    msg: "wload requires 2-3 operands: wd, rs1[, offset]".into(),
                });
            }
            let wd = expect_wide(&ops[0], line, "wd")?;
            let rs1 = expect_gp(&ops[1], line, "rs1")?;
            let imm = if ops.len() == 3 {
                expect_imm_or_label(&ops[2], pc, labels, line)?
            } else {
                0
            };
            Ok(encode(pi.opcode, wd, rs1, encode_immediate(imm)))
        }

        // --- WSTORE: wstore ws, rs1, imm ---
        Opcode::Wstore => {
            if ops.len() < 2 || ops.len() > 3 {
                return Err(AsmError::Parse {
                    line,
                    msg: "wstore requires 2-3 operands: ws, rs1[, offset]".into(),
                });
            }
            let ws = expect_wide(&ops[0], line, "ws")?;
            let rs1 = expect_gp(&ops[1], line, "rs1")?;
            let imm = if ops.len() == 3 {
                expect_imm_or_label(&ops[2], pc, labels, line)?
            } else {
                0
            };
            Ok(encode(pi.opcode, ws, rs1, encode_immediate(imm)))
        }

        // --- Push/Pop: push rd / pop rd ---
        Opcode::Push | Opcode::Pop => {
            if ops.len() != 1 {
                return Err(AsmError::Parse {
                    line,
                    msg: format!("{} requires 1 operand: rd", opcode_to_mnemonic(pi.opcode)),
                });
            }
            let rd = expect_gp(&ops[0], line, "rd")?;
            Ok(encode(pi.opcode, rd, 0, 0))
        }

        // --- JMP: jmp imm/label ---
        Opcode::Jmp => {
            if ops.len() != 1 {
                return Err(AsmError::Parse {
                    line,
                    msg: "jmp requires 1 operand: target".into(),
                });
            }
            let imm = expect_imm_or_label(&ops[0], pc, labels, line)?;
            Ok(encode(pi.opcode, 0, 0, encode_immediate(imm)))
        }

        // --- Branches: beq rd, rs1, imm/label ---
        Opcode::Beq | Opcode::Bne | Opcode::Blt | Opcode::Bge => {
            if ops.len() != 3 {
                return Err(AsmError::Parse {
                    line,
                    msg: format!(
                        "{} requires 3 operands: rs1, rs2, target",
                        opcode_to_mnemonic(pi.opcode)
                    ),
                });
            }
            let rd = expect_gp(&ops[0], line, "rs1")?;
            let rs1 = expect_gp(&ops[1], line, "rs2")?;
            let imm = expect_imm_or_label(&ops[2], pc, labels, line)?;
            Ok(encode(pi.opcode, rd, rs1, encode_immediate(imm)))
        }

        // --- CALL: call imm/label ---
        Opcode::Call => {
            if ops.len() != 1 {
                return Err(AsmError::Parse {
                    line,
                    msg: "call requires 1 operand: target".into(),
                });
            }
            let imm = expect_imm_or_label(&ops[0], pc, labels, line)?;
            Ok(encode(pi.opcode, 0, 0, encode_immediate(imm)))
        }

        // --- No operand: ret, halt, revert ---
        Opcode::Ret | Opcode::Halt | Opcode::Revert => {
            if !ops.is_empty() {
                return Err(AsmError::Parse {
                    line,
                    msg: format!("{} takes no operands", opcode_to_mnemonic(pi.opcode)),
                });
            }
            Ok(encode(pi.opcode, 0, 0, 0))
        }

        // --- System: caller rd (shorthand for Caller with sub=0) ---
        Opcode::Caller => {
            if ops.len() != 1 {
                return Err(AsmError::Parse {
                    line,
                    msg: "caller requires 1 operand: rd".into(),
                });
            }
            let rd = expect_gp(&ops[0], line, "rd")?;
            Ok(encode(pi.opcode, rd, 0, 0)) // sub-code 0 = CALLER
        }

        // --- System: callvalue wd ---
        Opcode::Callvalue => {
            if ops.len() != 1 {
                return Err(AsmError::Parse {
                    line,
                    msg: "callvalue requires 1 operand: wd".into(),
                });
            }
            let wd = expect_wide(&ops[0], line, "wd")?;
            Ok(encode(pi.opcode, wd, 0, 0)) // sub-code 0 = CALL_VALUE
        }

        // --- System: blockhash wd, rs1 ---
        Opcode::Blockhash => {
            if ops.len() != 2 {
                return Err(AsmError::Parse {
                    line,
                    msg: "blockhash requires 2 operands: wd, rs1".into(),
                });
            }
            let wd = expect_wide(&ops[0], line, "wd")?;
            let rs1 = expect_gp(&ops[1], line, "rs1")?;
            Ok(encode(pi.opcode, wd, rs1, 0))
        }

        // --- Storage: sload/sloadb/sloadg ---
        Opcode::Sload => {
            match pi.storage_mode {
                0 => {
                    // sload wd, ws1 (wide register mode)
                    if ops.len() != 2 {
                        return Err(AsmError::Parse {
                            line,
                            msg: "sload requires 2 operands: wd, ws1".into(),
                        });
                    }
                    let wd = expect_wide(&ops[0], line, "wd")?;
                    let ws1 = expect_wide(&ops[1], line, "ws1")?;
                    Ok(encode(pi.opcode, wd, ws1, 0))
                }
                1 => {
                    // sloadb rd_len, ws1, rs_ptr (memory mode)
                    if ops.len() != 3 {
                        return Err(AsmError::Parse {
                            line,
                            msg: "sloadb requires 3 operands: rd_len, ws1, rs_ptr".into(),
                        });
                    }
                    let rd = expect_gp(&ops[0], line, "rd_len")?;
                    let ws1 = expect_wide(&ops[1], line, "ws1")?;
                    let rs_ptr = expect_gp(&ops[2], line, "rs_ptr")?;
                    let imm = 1u32 | ((rs_ptr as u32) << 2);
                    Ok(encode(pi.opcode, rd, ws1, imm))
                }
                2 => {
                    // sloadg rd, ws1 (GP register mode)
                    if ops.len() != 2 {
                        return Err(AsmError::Parse {
                            line,
                            msg: "sloadg requires 2 operands: rd, ws1".into(),
                        });
                    }
                    let rd = expect_gp(&ops[0], line, "rd")?;
                    let ws1 = expect_wide(&ops[1], line, "ws1")?;
                    Ok(encode(pi.opcode, rd, ws1, 2))
                }
                _ => unreachable!(),
            }
        }

        // --- Storage: sstore/sstoreb/sstoreg ---
        Opcode::Sstore => {
            match pi.storage_mode {
                0 => {
                    // sstore ws1, wd (wide register mode)
                    if ops.len() != 2 {
                        return Err(AsmError::Parse {
                            line,
                            msg: "sstore requires 2 operands: ws1, wd".into(),
                        });
                    }
                    let ws1 = expect_wide(&ops[0], line, "ws1")?;
                    let wd = expect_wide(&ops[1], line, "wd")?;
                    Ok(encode(pi.opcode, wd, ws1, 0))
                }
                1 => {
                    // sstoreb ws1, rs_ptr, rs_len (memory mode)
                    if ops.len() != 3 {
                        return Err(AsmError::Parse {
                            line,
                            msg: "sstoreb requires 3 operands: ws1, rs_ptr, rs_len".into(),
                        });
                    }
                    let ws1 = expect_wide(&ops[0], line, "ws1")?;
                    let rs_ptr = expect_gp(&ops[1], line, "rs_ptr")?;
                    let rs_len = expect_gp(&ops[2], line, "rs_len")?;
                    let imm = 1u32 | ((rs_ptr as u32) << 2) | ((rs_len as u32) << 6);
                    Ok(encode(pi.opcode, 0, ws1, imm))
                }
                2 => {
                    // sstoreg ws1, rd (GP register mode)
                    if ops.len() != 2 {
                        return Err(AsmError::Parse {
                            line,
                            msg: "sstoreg requires 2 operands: ws1, rd".into(),
                        });
                    }
                    let ws1 = expect_wide(&ops[0], line, "ws1")?;
                    let rd = expect_gp(&ops[1], line, "rd")?;
                    Ok(encode(pi.opcode, rd, ws1, 2))
                }
                _ => unreachable!(),
            }
        }

        // --- Storage: sdelete ws1 ---
        Opcode::Sdelete => {
            if ops.len() != 1 {
                return Err(AsmError::Parse {
                    line,
                    msg: "sdelete requires 1 operand: ws1".into(),
                });
            }
            let ws1 = expect_wide(&ops[0], line, "ws1")?;
            Ok(encode(pi.opcode, 0, ws1, 0))
        }

        // --- Crypto: poseidon wd, rs1, rs2 ---
        Opcode::Poseidon => {
            if ops.len() != 3 {
                return Err(AsmError::Parse {
                    line,
                    msg: "poseidon requires 3 operands: wd, rs1, rs2".into(),
                });
            }
            let wd = expect_wide(&ops[0], line, "wd")?;
            let rs1 = expect_gp(&ops[1], line, "rs1")?;
            let rs2 = expect_gp(&ops[2], line, "rs2")?;
            Ok(encode(pi.opcode, wd, rs1, rs2 as u32))
        }

        // --- Event: log rs1, imm (imm = topic count) ---
        Opcode::Log => {
            if ops.len() != 2 {
                return Err(AsmError::Parse {
                    line,
                    msg: "log requires 2 operands: rs1, num_topics".into(),
                });
            }
            let rs1 = expect_gp(&ops[0], line, "rs1")?;
            let num_topics = match &ops[1] {
                Operand::Imm(v) => *v as u32,
                _ => {
                    return Err(AsmError::Parse {
                        line,
                        msg: "log: second operand must be immediate (topic count)".into(),
                    })
                }
            };
            Ok(encode(pi.opcode, 0, rs1, num_topics))
        }

        // --- Crypto: verifysig rd, rs1 ---
        Opcode::VerifySig => {
            if ops.len() != 2 {
                return Err(AsmError::Parse {
                    line,
                    msg: "verifysig requires 2 operands: rd, rs1".into(),
                });
            }
            let rd = expect_gp(&ops[0], line, "rd")?;
            let rs1 = expect_gp(&ops[1], line, "rs1")?;
            Ok(encode(pi.opcode, rd, rs1, 0))
        }

        // --- Assert: assert rs1 ---
        Opcode::Assert => {
            if ops.len() != 1 {
                return Err(AsmError::Parse {
                    line,
                    msg: "assert requires 1 operand: rs1".into(),
                });
            }
            let rs1 = expect_gp(&ops[0], line, "rs1")?;
            Ok(encode(pi.opcode, 0, rs1, 0))
        }

        // --- Fallback for unimplemented syscalls: encode raw ---
        _ => {
            let rd = if !ops.is_empty() {
                expect_reg_or_imm(&ops[0], line)? as u8
            } else {
                0
            };
            let rs1 = if ops.len() > 1 {
                expect_reg_or_imm(&ops[1], line)? as u8
            } else {
                0
            };
            let rs2 = if ops.len() > 2 {
                expect_reg_or_imm(&ops[2], line)? as u32
            } else {
                0
            };
            Ok(encode(pi.opcode, rd, rs1, rs2))
        }
    }
}

// ---------------------------------------------------------------------------
// Disassembler
// ---------------------------------------------------------------------------

/// Disassemble bytecode into assembly text.
pub fn disassemble(bytecode: &[u8]) -> String {
    let mut output = String::new();
    let mut offset = 0;

    while offset + 4 <= bytecode.len() {
        let word = u32::from_le_bytes([
            bytecode[offset],
            bytecode[offset + 1],
            bytecode[offset + 2],
            bytecode[offset + 3],
        ]);
        let instr = Instruction(word);
        let d = decode(instr);

        let line = disassemble_one(d.opcode, d.rd, d.rs1, d.rs2_or_imm);
        output.push_str(&format!("    {}\n", line));
        offset += 4;
    }

    output
}

fn disassemble_one(opcode: Opcode, rd: u8, rs1: u8, rs2_or_imm: u32) -> String {
    match opcode {
        // Three-register GP
        Opcode::Add
        | Opcode::Sub
        | Opcode::Mul
        | Opcode::Div
        | Opcode::Mod
        | Opcode::And
        | Opcode::Or
        | Opcode::Xor
        | Opcode::Shl
        | Opcode::Shr
        | Opcode::Sar
        | Opcode::Lt
        | Opcode::Gt
        | Opcode::Eq
        | Opcode::Slt
        | Opcode::Sgt => {
            format!(
                "{} r{}, r{}, r{}",
                opcode_to_mnemonic(opcode),
                rd,
                rs1,
                rs2_or_imm & 0xF
            )
        }

        // Three-register wide
        Opcode::Wadd
        | Opcode::Wsub
        | Opcode::Wmul
        | Opcode::Wdiv
        | Opcode::Wmod
        | Opcode::Wand
        | Opcode::Wor
        | Opcode::Wxor => {
            format!(
                "{} w{}, w{}, w{}",
                opcode_to_mnemonic(opcode),
                rd,
                rs1,
                rs2_or_imm & 0x7
            )
        }

        // Wide compare → GP
        Opcode::Weq | Opcode::Wlt => {
            format!(
                "{} r{}, w{}, w{}",
                opcode_to_mnemonic(opcode),
                rd,
                rs1,
                rs2_or_imm & 0x7
            )
        }

        // ADDI
        Opcode::Addi => {
            let imm = sign_extend_18(rs2_or_imm);
            format!("addi r{}, r{}, {}", rd, rs1, imm)
        }

        // NOT
        Opcode::Not => format!("not r{}, r{}", rd, rs1),

        // Wide unary
        Opcode::Wnot => format!("wnot w{}, w{}", rd, rs1),
        Opcode::Wmov => format!("wmov w{}, w{}", rd, rs1),

        // Narrow/Widen
        Opcode::Narrow => format!("narrow r{}, w{}", rd, rs1),
        Opcode::Widen => format!("widen w{}, r{}", rd, rs1),

        // Width-encoded LOAD/STORE
        Opcode::Load => {
            let width = decode_mem_width(rs2_or_imm);
            let offset = decode_mem_offset(rs2_or_imm);
            let mnem = match width {
                MemWidth::W8 => "load8",
                MemWidth::W16 => "load16",
                MemWidth::W32 => "load32",
                MemWidth::W64 => "load64",
            };
            format!("{} r{}, r{}, {}", mnem, rd, rs1, offset)
        }
        Opcode::Store => {
            let width = decode_mem_width(rs2_or_imm);
            let offset = decode_mem_offset(rs2_or_imm);
            let mnem = match width {
                MemWidth::W8 => "store8",
                MemWidth::W16 => "store16",
                MemWidth::W32 => "store32",
                MemWidth::W64 => "store64",
            };
            format!("{} r{}, r{}, {}", mnem, rd, rs1, offset)
        }

        // WLOAD/WSTORE
        Opcode::Wload => {
            let imm = sign_extend_18(rs2_or_imm);
            if imm == 0 {
                format!("wload w{}, r{}", rd, rs1)
            } else {
                format!("wload w{}, r{}, {}", rd, rs1, imm)
            }
        }
        Opcode::Wstore => {
            let imm = sign_extend_18(rs2_or_imm);
            if imm == 0 {
                format!("wstore w{}, r{}", rd, rs1)
            } else {
                format!("wstore w{}, r{}, {}", rd, rs1, imm)
            }
        }

        // Push/Pop
        Opcode::Push => format!("push r{}", rd),
        Opcode::Pop => format!("pop r{}", rd),

        // JMP
        Opcode::Jmp => {
            let imm = sign_extend_18(rs2_or_imm);
            format!("jmp {}", imm)
        }

        // Branches
        Opcode::Beq | Opcode::Bne | Opcode::Blt | Opcode::Bge => {
            let imm = sign_extend_18(rs2_or_imm);
            format!("{} r{}, r{}, {}", opcode_to_mnemonic(opcode), rd, rs1, imm)
        }

        // CALL
        Opcode::Call => {
            let imm = sign_extend_18(rs2_or_imm);
            format!("call {}", imm)
        }

        // No operand
        Opcode::Ret => "ret".into(),
        Opcode::Halt => "halt".into(),
        Opcode::Revert => "revert".into(),

        // System: Caller (GP env query dispatched by immediate)
        Opcode::Caller => {
            use crate::vm::env_gp;
            match rs2_or_imm {
                env_gp::BLOCK_NUMBER => format!("blocknumber r{}", rd),
                env_gp::TIMESTAMP => format!("timestamp r{}", rd),
                env_gp::GAS_REMAINING => format!("gasremaining r{}", rd),
                _ => format!("caller r{}, r{}, {}", rd, rs1, rs2_or_imm),
            }
        }

        // System: Callvalue (wide env query dispatched by immediate)
        Opcode::Callvalue => {
            use crate::vm::env_wide;
            match rs2_or_imm {
                env_wide::CALL_VALUE => format!("callvalue w{}", rd),
                env_wide::GAS_PRICE => format!("gasprice w{}", rd),
                env_wide::BALANCE => format!("balance w{}, r{}", rd, rs1),
                env_wide::CALLER => format!("caller w{}", rd),
                env_wide::ADDRESS => format!("address w{}", rd),
                _ => format!("callvalue w{}, r{}, {}", rd, rs1, rs2_or_imm),
            }
        }

        // System: Blockhash
        Opcode::Blockhash => format!("blockhash w{}, r{}", rd, rs1),

        // Crypto
        Opcode::Poseidon => format!("poseidon w{}, r{}, r{}", rd, rs1, rs2_or_imm & 0xF),
        Opcode::VerifySig => format!("verifysig r{}, r{}", rd, rs1),

        // Storage
        Opcode::Sload => {
            match rs2_or_imm & 0x3 {
                0 => format!("sload w{}, w{}", rd, rs1),
                1 => {
                    let ptr_reg = (rs2_or_imm >> 2) & 0xF;
                    format!("sloadb r{}, w{}, r{}", rd, rs1, ptr_reg)
                }
                2 => format!("sloadg r{}, w{}", rd, rs1),
                _ => format!("sload? {}, {}, {}", rd, rs1, rs2_or_imm),
            }
        }
        Opcode::Sstore => {
            match rs2_or_imm & 0x3 {
                0 => format!("sstore w{}, w{}", rs1, rd),
                1 => {
                    let ptr_reg = (rs2_or_imm >> 2) & 0xF;
                    let len_reg = (rs2_or_imm >> 6) & 0xF;
                    format!("sstoreb w{}, r{}, r{}", rs1, ptr_reg, len_reg)
                }
                2 => format!("sstoreg w{}, r{}", rs1, rd),
                _ => format!("sstore? {}, {}, {}", rd, rs1, rs2_or_imm),
            }
        }
        Opcode::Sdelete => format!("sdelete w{}", rs1),

        // Assert
        Opcode::Assert => format!("assert r{}", rs1),

        // Event
        Opcode::Log => format!("log r{}, {}", rs1, rs2_or_imm),

        // Fallback
        _ => format!(
            "{} {}, {}, {}",
            opcode_to_mnemonic(opcode),
            rd,
            rs1,
            rs2_or_imm
        ),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assemble_halt() {
        let code = assemble("halt").unwrap();
        assert_eq!(code.len(), 4);
        let word = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
        assert_eq!(decode(Instruction(word)).opcode, Opcode::Halt);
    }

    #[test]
    fn assemble_addi() {
        let code = assemble("addi r1, r0, 42").unwrap();
        let word = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
        let d = decode(Instruction(word));
        assert_eq!(d.opcode, Opcode::Addi);
        assert_eq!(d.rd, 1);
        assert_eq!(d.rs1, 0);
        assert_eq!(sign_extend_18(d.rs2_or_imm), 42);
    }

    #[test]
    fn assemble_add_three_reg() {
        let code = assemble("add r3, r1, r2").unwrap();
        let d = decode(Instruction(u32::from_le_bytes(
            code[..4].try_into().unwrap(),
        )));
        assert_eq!(d.opcode, Opcode::Add);
        assert_eq!(d.rd, 3);
        assert_eq!(d.rs1, 1);
        assert_eq!(d.rs2_or_imm, 2);
    }

    #[test]
    fn assemble_wide_ops() {
        let code = assemble("wadd w0, w1, w2").unwrap();
        let d = decode(Instruction(u32::from_le_bytes(
            code[..4].try_into().unwrap(),
        )));
        assert_eq!(d.opcode, Opcode::Wadd);
        assert_eq!(d.rd, 0);
        assert_eq!(d.rs1, 1);
        assert_eq!(d.rs2_or_imm, 2);
    }

    #[test]
    fn assemble_label_forward_ref() {
        let src = "\
            jmp end
            addi r1, r0, 99
        end:
            halt";
        let code = assemble(src).unwrap();
        assert_eq!(code.len(), 12); // 3 instructions
                                    // JMP should encode offset = +8 (skip addi, land on halt)
        let d = decode(Instruction(u32::from_le_bytes(
            code[0..4].try_into().unwrap(),
        )));
        assert_eq!(d.opcode, Opcode::Jmp);
        assert_eq!(sign_extend_18(d.rs2_or_imm), 8);
    }

    #[test]
    fn assemble_label_backward_ref() {
        let src = "\
        loop:
            addi r1, r1, 1
            jmp loop";
        let code = assemble(src).unwrap();
        // JMP is at offset 4, loop is at offset 0, so offset = -4
        let d = decode(Instruction(u32::from_le_bytes(
            code[4..8].try_into().unwrap(),
        )));
        assert_eq!(d.opcode, Opcode::Jmp);
        assert_eq!(sign_extend_18(d.rs2_or_imm), -4);
    }

    #[test]
    fn assemble_branch_with_label() {
        let src = "\
            addi r1, r0, 5
            addi r2, r0, 5
            beq r1, r2, done
            addi r3, r0, 99
        done:
            halt";
        let code = assemble(src).unwrap();
        assert_eq!(code.len(), 20); // 5 instructions
                                    // BEQ at offset 8, done at offset 16, so offset = +8
        let d = decode(Instruction(u32::from_le_bytes(
            code[8..12].try_into().unwrap(),
        )));
        assert_eq!(d.opcode, Opcode::Beq);
        assert_eq!(sign_extend_18(d.rs2_or_imm), 8);
    }

    #[test]
    fn assemble_comments_ignored() {
        let src = "\
            ; this is a comment
            addi r1, r0, 10  ; inline comment
            halt";
        let code = assemble(src).unwrap();
        assert_eq!(code.len(), 8);
    }

    #[test]
    fn assemble_load_store_widths() {
        let src = "\
            load8 r1, r2, 0
            load16 r3, r4, 4
            store32 r5, r6, -8
            load64 r7, r8, 16
            halt";
        let code = assemble(src).unwrap();
        assert_eq!(code.len(), 20);

        let d0 = decode(Instruction(u32::from_le_bytes(
            code[0..4].try_into().unwrap(),
        )));
        assert_eq!(d0.opcode, Opcode::Load);
        assert_eq!(decode_mem_width(d0.rs2_or_imm), MemWidth::W8);
        assert_eq!(decode_mem_offset(d0.rs2_or_imm), 0);

        let d1 = decode(Instruction(u32::from_le_bytes(
            code[4..8].try_into().unwrap(),
        )));
        assert_eq!(d1.opcode, Opcode::Load);
        assert_eq!(decode_mem_width(d1.rs2_or_imm), MemWidth::W16);
        assert_eq!(decode_mem_offset(d1.rs2_or_imm), 4);

        let d2 = decode(Instruction(u32::from_le_bytes(
            code[8..12].try_into().unwrap(),
        )));
        assert_eq!(d2.opcode, Opcode::Store);
        assert_eq!(decode_mem_width(d2.rs2_or_imm), MemWidth::W32);
        assert_eq!(decode_mem_offset(d2.rs2_or_imm), -8);
    }

    #[test]
    fn assemble_push_pop() {
        let src = "push r5\npop r6\nhalt";
        let code = assemble(src).unwrap();
        let d0 = decode(Instruction(u32::from_le_bytes(
            code[0..4].try_into().unwrap(),
        )));
        assert_eq!(d0.opcode, Opcode::Push);
        assert_eq!(d0.rd, 5);
        let d1 = decode(Instruction(u32::from_le_bytes(
            code[4..8].try_into().unwrap(),
        )));
        assert_eq!(d1.opcode, Opcode::Pop);
        assert_eq!(d1.rd, 6);
    }

    #[test]
    fn assemble_call_ret() {
        let src = "\
            call func
            halt
        func:
            addi r1, r0, 1
            ret";
        let code = assemble(src).unwrap();
        let d = decode(Instruction(u32::from_le_bytes(
            code[0..4].try_into().unwrap(),
        )));
        assert_eq!(d.opcode, Opcode::Call);
        assert_eq!(sign_extend_18(d.rs2_or_imm), 8); // func at offset 8
    }

    #[test]
    fn assemble_negative_immediate() {
        let code = assemble("addi r1, r0, -100").unwrap();
        let d = decode(Instruction(u32::from_le_bytes(
            code[..4].try_into().unwrap(),
        )));
        assert_eq!(sign_extend_18(d.rs2_or_imm), -100);
    }

    #[test]
    fn assemble_hex_immediate() {
        let code = assemble("addi r1, r0, 0xFF").unwrap();
        let d = decode(Instruction(u32::from_le_bytes(
            code[..4].try_into().unwrap(),
        )));
        assert_eq!(sign_extend_18(d.rs2_or_imm), 255);
    }

    #[test]
    fn undefined_label_error() {
        let err = assemble("jmp nowhere").unwrap_err();
        assert!(matches!(err, AsmError::UndefinedLabel(ref s) if s == "nowhere"));
    }

    #[test]
    fn duplicate_label_error() {
        let err = assemble("foo:\nfoo:\nhalt").unwrap_err();
        assert!(matches!(err, AsmError::DuplicateLabel(ref s) if s == "foo"));
    }

    #[test]
    fn invalid_mnemonic_error() {
        let err = assemble("foobar r1, r2, r3").unwrap_err();
        match err {
            AsmError::Parse { msg, .. } => assert!(msg.contains("foobar")),
            _ => panic!("expected parse error"),
        }
    }

    #[test]
    fn wrong_operand_count_error() {
        let err = assemble("add r1, r2").unwrap_err();
        assert!(matches!(err, AsmError::Parse { .. }));
    }

    // ========== Disassembler ==========

    #[test]
    fn disassemble_halt() {
        let code = assemble("halt").unwrap();
        let text = disassemble(&code);
        assert_eq!(text.trim(), "halt");
    }

    #[test]
    fn disassemble_addi() {
        let code = assemble("addi r1, r0, 42").unwrap();
        let text = disassemble(&code);
        assert_eq!(text.trim(), "addi r1, r0, 42");
    }

    #[test]
    fn disassemble_add() {
        let code = assemble("add r3, r1, r2").unwrap();
        let text = disassemble(&code);
        assert_eq!(text.trim(), "add r3, r1, r2");
    }

    #[test]
    fn disassemble_wide() {
        let code = assemble("wadd w0, w1, w2").unwrap();
        let text = disassemble(&code);
        assert_eq!(text.trim(), "wadd w0, w1, w2");
    }

    #[test]
    fn disassemble_load_widths() {
        let code = assemble("load8 r1, r2, 0").unwrap();
        let text = disassemble(&code);
        assert_eq!(text.trim(), "load8 r1, r2, 0");
    }

    #[test]
    fn assemble_disassemble_roundtrip() {
        let src = "\
            addi r1, r0, 10
            addi r2, r0, 20
            add r3, r1, r2
            push r3
            pop r4
            halt";

        let code = assemble(src).unwrap();
        let text = disassemble(&code);
        let code2 = assemble(&text).unwrap();
        assert_eq!(code, code2);
    }

    #[test]
    fn roundtrip_with_branches() {
        // Note: labels are lost in disassembly, replaced by numeric offsets
        // So roundtrip works because disassembler emits numeric immediates
        let src = "\
            addi r1, r0, 0
            addi r2, r0, 3
            beq r1, r2, 12
            addi r1, r1, 1
            jmp -8
            halt";
        let code = assemble(src).unwrap();
        let text = disassemble(&code);
        let code2 = assemble(&text).unwrap();
        assert_eq!(code, code2);
    }

    #[test]
    fn full_program_fibonacci() {
        // Fibonacci: compute fib(10) = 55
        // r1 = prev (0), r2 = curr (1), r3 = count (10), r4 = temp
        let src = "\
            addi r1, r0, 0       ; prev = 0
            addi r2, r0, 1       ; curr = 1
            addi r3, r0, 10      ; count = 10
            addi r5, r0, 0       ; i = 0
        loop:
            beq r5, r3, done     ; if i == count, done
            add r4, r1, r2       ; temp = prev + curr
            addi r1, r2, 0       ; prev = curr
            addi r2, r4, 0       ; curr = temp
            addi r5, r5, 1       ; i++
            jmp loop
        done:
            halt";

        let code = assemble(src).unwrap();

        // Run it through the VM
        let mut vm = crate::vm::Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), crate::vm::ExecResult::Halt);
        assert_eq!(vm.cpu.read_gp(1), 55); // fib(10) = 55
    }

    #[test]
    fn case_insensitive() {
        let code1 = assemble("ADDI R1, R0, 42\nHALT").unwrap();
        let code2 = assemble("addi r1, r0, 42\nhalt").unwrap();
        assert_eq!(code1, code2);
    }

    #[test]
    fn weq_wlt_assembly() {
        let code = assemble("weq r1, w0, w1\nwlt r2, w3, w4\nhalt").unwrap();
        let d0 = decode(Instruction(u32::from_le_bytes(
            code[0..4].try_into().unwrap(),
        )));
        assert_eq!(d0.opcode, Opcode::Weq);
        assert_eq!(d0.rd, 1);
        assert_eq!(d0.rs1, 0);
        assert_eq!(d0.rs2_or_imm, 1);
        let d1 = decode(Instruction(u32::from_le_bytes(
            code[4..8].try_into().unwrap(),
        )));
        assert_eq!(d1.opcode, Opcode::Wlt);
        assert_eq!(d1.rd, 2);
        assert_eq!(d1.rs1, 3);
        assert_eq!(d1.rs2_or_imm, 4);
    }

    #[test]
    fn narrow_widen_assembly() {
        let code = assemble("widen w0, r1\nnarrow r2, w3\nhalt").unwrap();
        let d0 = decode(Instruction(u32::from_le_bytes(
            code[0..4].try_into().unwrap(),
        )));
        assert_eq!(d0.opcode, Opcode::Widen);
        assert_eq!(d0.rd, 0); // wd
        assert_eq!(d0.rs1, 1); // rs1
        let d1 = decode(Instruction(u32::from_le_bytes(
            code[4..8].try_into().unwrap(),
        )));
        assert_eq!(d1.opcode, Opcode::Narrow);
        assert_eq!(d1.rd, 2); // rd
        assert_eq!(d1.rs1, 3); // ws1
    }

    #[test]
    fn assemble_system_pseudo_mnemonics() {
        use crate::vm::{env_gp, env_wide};

        // GP env queries
        let code =
            assemble("caller w1\naddress w2\nblocknumber r3\ntimestamp r4\ngasremaining r5\nhalt")
                .unwrap();
        let d0 = decode(Instruction(u32::from_le_bytes(
            code[0..4].try_into().unwrap(),
        )));
        // caller and address are now wide queries (Callvalue opcode)
        assert_eq!(d0.opcode, Opcode::Callvalue);
        assert_eq!(d0.rd, 1);
        assert_eq!(d0.rs2_or_imm, env_wide::CALLER);

        let d1 = decode(Instruction(u32::from_le_bytes(
            code[4..8].try_into().unwrap(),
        )));
        assert_eq!(d1.opcode, Opcode::Callvalue);
        assert_eq!(d1.rd, 2);
        assert_eq!(d1.rs2_or_imm, env_wide::ADDRESS);

        let d2 = decode(Instruction(u32::from_le_bytes(
            code[8..12].try_into().unwrap(),
        )));
        assert_eq!(d2.opcode, Opcode::Caller);
        assert_eq!(d2.rs2_or_imm, env_gp::BLOCK_NUMBER);

        let d3 = decode(Instruction(u32::from_le_bytes(
            code[12..16].try_into().unwrap(),
        )));
        assert_eq!(d3.opcode, Opcode::Caller);
        assert_eq!(d3.rs2_or_imm, env_gp::TIMESTAMP);

        let d4 = decode(Instruction(u32::from_le_bytes(
            code[16..20].try_into().unwrap(),
        )));
        assert_eq!(d4.opcode, Opcode::Caller);
        assert_eq!(d4.rs2_or_imm, env_gp::GAS_REMAINING);
    }

    #[test]
    fn assemble_wide_env_pseudo_mnemonics() {
        use crate::vm::env_wide;

        let code = assemble("callvalue w0\ngasprice w1\nbalance w2, r3\nhalt").unwrap();
        let d0 = decode(Instruction(u32::from_le_bytes(
            code[0..4].try_into().unwrap(),
        )));
        assert_eq!(d0.opcode, Opcode::Callvalue);
        assert_eq!(d0.rd, 0);
        assert_eq!(d0.rs2_or_imm, env_wide::CALL_VALUE);

        let d1 = decode(Instruction(u32::from_le_bytes(
            code[4..8].try_into().unwrap(),
        )));
        assert_eq!(d1.opcode, Opcode::Callvalue);
        assert_eq!(d1.rd, 1);
        assert_eq!(d1.rs2_or_imm, env_wide::GAS_PRICE);

        let d2 = decode(Instruction(u32::from_le_bytes(
            code[8..12].try_into().unwrap(),
        )));
        assert_eq!(d2.opcode, Opcode::Callvalue);
        assert_eq!(d2.rd, 2);
        assert_eq!(d2.rs1, 3);
        assert_eq!(d2.rs2_or_imm, env_wide::BALANCE);
    }

    #[test]
    fn assemble_blockhash() {
        let code = assemble("blockhash w0, r1\nhalt").unwrap();
        let d = decode(Instruction(u32::from_le_bytes(
            code[0..4].try_into().unwrap(),
        )));
        assert_eq!(d.opcode, Opcode::Blockhash);
        assert_eq!(d.rd, 0);
        assert_eq!(d.rs1, 1);
    }

    #[test]
    fn disassemble_system_roundtrip() {
        let src = "caller w1\naddress w2\nblocknumber r3\ntimestamp r4\ngasremaining r5\nhalt\n";
        let code = assemble(src).unwrap();
        let text = disassemble(&code);
        assert!(text.contains("caller w1"));
        assert!(text.contains("address w2"));
        assert!(text.contains("blocknumber r3"));
        assert!(text.contains("timestamp r4"));
        assert!(text.contains("gasremaining r5"));
    }

    #[test]
    fn disassemble_wide_env_roundtrip() {
        let src = "callvalue w0\ngasprice w1\nbalance w2, r3\nhalt\n";
        let code = assemble(src).unwrap();
        let text = disassemble(&code);
        assert!(text.contains("callvalue w0"));
        assert!(text.contains("gasprice w1"));
        assert!(text.contains("balance w2, r3"));
    }

    // ========== Data directives ==========

    #[test]
    fn ascii_directive_embeds_bytes() {
        let src = r#"
            halt
        msg:
            .ascii "hello"
        "#;
        let code = assemble(src).unwrap();
        // halt = 4 bytes, then "hello" = 5 bytes
        assert_eq!(code.len(), 9);
        assert_eq!(&code[4..9], b"hello");
    }

    #[test]
    fn bytes_directive_with_values() {
        let src = "halt\ndata: .bytes 0x41, 0x42, 0x43";
        let code = assemble(src).unwrap();
        assert_eq!(code.len(), 7); // 4 + 3
        assert_eq!(&code[4..7], b"ABC");
    }

    #[test]
    fn ascii_with_escape_sequences() {
        let src = r#"halt
msg: .ascii "hi\n\0""#;
        let code = assemble(src).unwrap();
        assert_eq!(code.len(), 8); // 4 + 4 bytes ("hi" + \n + \0)
        assert_eq!(code[4], b'h');
        assert_eq!(code[5], b'i');
        assert_eq!(code[6], b'\n');
        assert_eq!(code[7], 0);
    }

    #[test]
    fn align_directive_pads_to_4() {
        let src = r#"
            halt
        data:
            .ascii "hi"
            .align
        next:
            halt
        "#;
        let code = assemble(src).unwrap();
        // halt(4) + "hi"(2) + align pad(2) + halt(4) = 12
        assert_eq!(code.len(), 12);
    }

    #[test]
    fn la_pseudo_loads_absolute_address() {
        let src = r#"
            la r1, msg
            halt
        msg:
            .ascii "test"
        "#;
        let code = assemble(src).unwrap();
        // la is at offset 0, msg is at offset 8 (after la + halt)
        // la should encode: addi r1, r0, CODE_START + 8
        let d = decode(Instruction(u32::from_le_bytes(code[0..4].try_into().unwrap())));
        assert_eq!(d.opcode, Opcode::Addi);
        assert_eq!(d.rd, 1);
        assert_eq!(d.rs1, 0);
        let expected_addr = crate::memory::CODE_START + 8;
        assert_eq!(sign_extend_18(d.rs2_or_imm), expected_addr as i32);
    }

    #[test]
    fn la_and_data_full_program() {
        // Load address of embedded data and use it with poseidon
        let src = r#"
            la r1, msg          ; r1 = address of "hello"
            addi r2, r0, 5      ; r2 = length
            halt
        msg:
            .ascii "hello"
        "#;
        let code = assemble(src).unwrap();

        let mut vm = crate::vm::Vm::new();
        vm.load(&code).unwrap();
        assert_eq!(vm.run().unwrap(), crate::vm::ExecResult::Halt);

        // r1 should point to the "hello" data in code section
        let addr = vm.cpu.read_gp(1) as u32;
        let mut loaded = Vec::new();
        for i in 0..5 {
            loaded.push(vm.memory.load8(addr + i).unwrap());
        }
        assert_eq!(&loaded, b"hello");
    }

    #[test]
    fn mixed_bytes_and_string() {
        let src = r#"halt
data: .bytes 0xFF, "AB", 0x00"#;
        let code = assemble(src).unwrap();
        assert_eq!(code.len(), 8); // 4 + 4 bytes
        assert_eq!(code[4], 0xFF);
        assert_eq!(code[5], b'A');
        assert_eq!(code[6], b'B');
        assert_eq!(code[7], 0x00);
    }
}
