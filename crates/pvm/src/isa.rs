//! PVM Instruction Set Architecture.
//!
//! 32-bit fixed-width instruction encoding:
//! ```text
//!   31      26 25    22 21    18 17                              0
//!   +─────────+────────+────────+──────────────────────────────────+
//!   │ opcode  │   rd   │  rs1   │          rs2 / immediate         │
//!   │ (6 bit) │ (4 bit)│ (4 bit)│            (18 bit)              │
//!   +─────────+────────+────────+──────────────────────────────────+
//! ```

/// All PVM opcodes. Values match the design specification (Chapter 3 PYDE BOOK).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    // --- 3.4.1 Arithmetic (64-bit GP registers) ---
    Add = 0x01, // rd = rs1 + rs2
    Sub = 0x02, // rd = rs1 - rs2
    Mul = 0x03, // rd = rs1 * rs2
    Div = 0x04, // rd = rs1 / rs2
    Mod = 0x05, // rd = rs1 % rs2
    And = 0x06, // rd = rs1 & rs2
    Or = 0x07,  // rd = rs1 | rs2
    Xor = 0x08, // rd = rs1 ^ rs2

    // --- 3.4.2 Wide Arithmetic (256-bit) ---
    Wadd = 0x09, // wd = ws1 + ws2
    Wsub = 0x0A, // wd = ws1 - ws2
    Wmul = 0x0B, // wd = ws1 * ws2
    Wdiv = 0x0C, // wd = ws1 / ws2
    Wmod = 0x0D, // wd = ws1 % ws2

    // --- Wide Logical (256-bit) ---
    Wand = 0x2D, // wd = ws1 & ws2
    Wor = 0x2E,  // wd = ws1 | ws2
    Wxor = 0x2F, // wd = ws1 ^ ws2
    Wnot = 0x1F, // wd = ~ws1
    /// Wide shift: wd = ws1 << amount (if imm&1==0) or ws1 >> amount (if imm&1==1).
    /// Shift amount from GP register indexed by imm bits [4:1].
    Wshift = 0x3A,

    // --- Extended Arithmetic (from gas table / roadmap) ---
    Addi = 0x0E, // rd = rs1 + sign_extend(imm)
    Not = 0x0F,  // rd = ~rs1
    Shl = 0x14,  // rd = rs1 << rs2
    Shr = 0x15,  // rd = rs1 >> rs2 (logical)
    Sar = 0x16,  // rd = rs1 >> rs2 (arithmetic)
    Lt = 0x17,   // rd = (rs1 < rs2) ? 1 : 0 (unsigned)
    Gt = 0x33,   // rd = (rs1 > rs2) ? 1 : 0 (unsigned)
    Eq = 0x34,   // rd = (rs1 == rs2) ? 1 : 0
    Slt = 0x35,  // rd = (rs1 < rs2) ? 1 : 0 (signed)
    Sgt = 0x36,  // rd = (rs1 > rs2) ? 1 : 0 (signed)

    // --- 3.4.3 Memory ---
    Load = 0x10,  // rd = memory[rs1 + imm]
    Store = 0x11, // memory[rs1 + imm] = rd
    Push = 0x12,  // SP -= 8; memory[SP] = rd
    Pop = 0x13,   // rd = memory[SP]; SP += 8

    // --- Wide Memory / Register Transfer ---
    Wload = 0x37,  // wd = memory256[rs1]
    Wstore = 0x3B, // memory256[rs1] = ws1
    Wmov = 0x3C,   // wd = ws1
    Narrow = 0x3D, // rd = lower64(ws1), trap if > u64::MAX
    Widen = 0x3E,  // wd = zero_extend(rs1)

    // --- 3.4.4 Control Flow ---
    Jmp = 0x18,  // PC = imm
    Beq = 0x19,  // if rs1 == rs2 then PC = imm
    Bne = 0x1A,  // if rs1 != rs2 then PC = imm
    Blt = 0x1B,  // if rs1 < rs2 then PC = imm
    Bge = 0x1C,  // if rs1 >= rs2 then PC = imm
    Call = 0x1D, // push PC+4 to RA; PC = imm
    Ret = 0x1E,  // PC = RA; restore frame

    // --- 3.4.5 Blockchain Syscalls ---
    Sload = 0x20,        // rd = storage[rs1]
    Sstore = 0x21,       // storage[rs1] = rd
    Sdelete = 0x22,      // delete storage[rs1]
    Caller = 0x23,       // rd = msg.sender
    Callvalue = 0x24,    // wd = msg.value (256-bit)
    Blockhash = 0x25,    // wd = hash(block at rs1)
    CallExt = 0x26,      // call external contract
    Delegate = 0x27,     // delegatecall
    Create = 0x28,       // deploy contract, rd = address
    Selfdestruct = 0x29, // destroy contract
    Log = 0x2A,          // emit event
    Revert = 0x2B,       // abort execution
    Halt = 0x2C,         // stop execution

    // --- 3.4.5 Crypto Syscalls ---
    Poseidon = 0x30,     // wd = poseidon_hash(memory[rs1..rs1+rs2])
    VerifySig = 0x31,    // rd = verify_signature(msg, sig, pk)
    MerkleVerify = 0x32, // rd = verify_merkle_path(root, leaf, path)

    // --- 3.4.6 Assertions + Memory ---
    Assert = 0x38,   // if rs1 == 0 then revert (assertion)
    Memcpy = 0x39,   // copy gp[imm&0xF] bytes from mem[gp[rs1]] to mem[gp[rd]]
    // 0x3A is now Wshift (wide shift); see definition above.
    // Until Phase 9, bulk writes use a WSTORE loop:
    //   for each 32-byte chunk: WSTORE to heap, advance pointer
    //   ~N/32 instructions for N bytes (not N instructions)

    // --- Wide Comparisons (result → GP register) ---
    Weq = 0x00, // rd = (ws1 == ws2) ? 1 : 0
    Wlt = 0x3F, // rd = (ws1 < ws2) ? 1 : 0

    // --- Invalid ---
    Invalid = 0xFF, // decoded from unrecognized opcode bits (not a real 6-bit slot)
}

impl Opcode {
    /// Decode a 6-bit opcode value into an Opcode variant.
    pub fn from_u8(val: u8) -> Self {
        match val {
            0x01 => Opcode::Add,
            0x02 => Opcode::Sub,
            0x03 => Opcode::Mul,
            0x04 => Opcode::Div,
            0x05 => Opcode::Mod,
            0x06 => Opcode::And,
            0x07 => Opcode::Or,
            0x08 => Opcode::Xor,
            0x09 => Opcode::Wadd,
            0x0A => Opcode::Wsub,
            0x0B => Opcode::Wmul,
            0x0C => Opcode::Wdiv,
            0x0D => Opcode::Wmod,
            0x0E => Opcode::Addi,
            0x0F => Opcode::Not,
            0x10 => Opcode::Load,
            0x11 => Opcode::Store,
            0x12 => Opcode::Push,
            0x13 => Opcode::Pop,
            0x14 => Opcode::Shl,
            0x15 => Opcode::Shr,
            0x16 => Opcode::Sar,
            0x17 => Opcode::Lt,
            0x18 => Opcode::Jmp,
            0x19 => Opcode::Beq,
            0x1A => Opcode::Bne,
            0x1B => Opcode::Blt,
            0x1C => Opcode::Bge,
            0x1D => Opcode::Call,
            0x1E => Opcode::Ret,
            0x1F => Opcode::Wnot,
            0x20 => Opcode::Sload,
            0x21 => Opcode::Sstore,
            0x22 => Opcode::Sdelete,
            0x23 => Opcode::Caller,
            0x24 => Opcode::Callvalue,
            0x25 => Opcode::Blockhash,
            0x26 => Opcode::CallExt,
            0x27 => Opcode::Delegate,
            0x28 => Opcode::Create,
            0x29 => Opcode::Selfdestruct,
            0x2A => Opcode::Log,
            0x2B => Opcode::Revert,
            0x2C => Opcode::Halt,
            0x2D => Opcode::Wand,
            0x2E => Opcode::Wor,
            0x2F => Opcode::Wxor,
            0x3A => Opcode::Wshift,
            0x30 => Opcode::Poseidon,
            0x31 => Opcode::VerifySig,
            0x32 => Opcode::MerkleVerify,
            0x33 => Opcode::Gt,
            0x34 => Opcode::Eq,
            0x35 => Opcode::Slt,
            0x36 => Opcode::Sgt,
            0x37 => Opcode::Wload,
            0x38 => Opcode::Assert,
            0x39 => Opcode::Memcpy,
            // 0x3A handled above (Wshift)
            0x3B => Opcode::Wstore,
            0x3C => Opcode::Wmov,
            0x3D => Opcode::Narrow,
            0x3E => Opcode::Widen,
            0x00 => Opcode::Weq,
            0x3F => Opcode::Wlt,
            _ => Opcode::Invalid,
        }
    }

    /// Encode this opcode as its 6-bit value.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Whether this opcode operates on the wide (256-bit) register file.
    pub fn is_wide(self) -> bool {
        matches!(
            self,
            Opcode::Wadd
                | Opcode::Wsub
                | Opcode::Wmul
                | Opcode::Wdiv
                | Opcode::Wmod
                | Opcode::Wand
                | Opcode::Wor
                | Opcode::Wxor
                | Opcode::Wnot
                | Opcode::Wshift
                | Opcode::Wload
                | Opcode::Wstore
                | Opcode::Wmov
                | Opcode::Widen
                | Opcode::Callvalue
                | Opcode::Blockhash
                | Opcode::Poseidon
        )
    }

    /// Whether this opcode uses the 18-bit field as a signed immediate.
    pub fn uses_immediate(self) -> bool {
        matches!(
            self,
            Opcode::Addi
                | Opcode::Load
                | Opcode::Store
                | Opcode::Jmp
                | Opcode::Beq
                | Opcode::Bne
                | Opcode::Blt
                | Opcode::Bge
                | Opcode::Call
        )
    }
}

/// List of all valid opcodes (excluding Invalid).
pub const ALL_OPCODES: &[Opcode] = &[
    Opcode::Add,
    Opcode::Sub,
    Opcode::Mul,
    Opcode::Div,
    Opcode::Mod,
    Opcode::And,
    Opcode::Or,
    Opcode::Xor,
    Opcode::Wadd,
    Opcode::Wsub,
    Opcode::Wmul,
    Opcode::Wdiv,
    Opcode::Wmod,
    Opcode::Wand,
    Opcode::Wor,
    Opcode::Wxor,
    Opcode::Wnot,
    Opcode::Wshift,
    Opcode::Addi,
    Opcode::Not,
    Opcode::Load,
    Opcode::Store,
    Opcode::Push,
    Opcode::Pop,
    Opcode::Shl,
    Opcode::Shr,
    Opcode::Sar,
    Opcode::Lt,
    Opcode::Jmp,
    Opcode::Beq,
    Opcode::Bne,
    Opcode::Blt,
    Opcode::Bge,
    Opcode::Call,
    Opcode::Ret,
    Opcode::Sload,
    Opcode::Sstore,
    Opcode::Sdelete,
    Opcode::Caller,
    Opcode::Callvalue,
    Opcode::Blockhash,
    Opcode::CallExt,
    Opcode::Delegate,
    Opcode::Create,
    Opcode::Selfdestruct,
    Opcode::Log,
    Opcode::Revert,
    Opcode::Halt,
    Opcode::Poseidon,
    Opcode::VerifySig,
    Opcode::MerkleVerify,
    Opcode::Gt,
    Opcode::Eq,
    Opcode::Slt,
    Opcode::Sgt,
    Opcode::Wload,
    Opcode::Assert,
    Opcode::Memcpy,
    Opcode::Wstore,
    Opcode::Wmov,
    Opcode::Narrow,
    Opcode::Widen,
    Opcode::Weq,
    Opcode::Wlt,
];

// --- Instruction encoding/decoding ---

/// A 32-bit PVM instruction word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instruction(pub u32);

/// Decoded instruction fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedInstruction {
    pub opcode: Opcode,
    /// Destination register (0-15 for GP, 0-7 for wide).
    pub rd: u8,
    /// First source register (0-15 for GP, 0-7 for wide).
    pub rs1: u8,
    /// Second source register or raw 18-bit immediate field.
    /// For register mode, only bits 0-3 are the register index.
    /// For immediate mode, this is the raw unsigned 18-bit value;
    /// use `sign_extend_18` to get the signed interpretation.
    pub rs2_or_imm: u32,
}

// Bit layout constants
const OPCODE_SHIFT: u32 = 26;
const OPCODE_MASK: u32 = 0x3F; // 6 bits
const RD_SHIFT: u32 = 22;
const RD_MASK: u32 = 0x0F; // 4 bits
const RS1_SHIFT: u32 = 18;
const RS1_MASK: u32 = 0x0F; // 4 bits
const RS2_IMM_MASK: u32 = 0x3FFFF; // 18 bits

/// Number of GP registers.
pub const GP_REG_COUNT: usize = 16;
/// Number of wide (256-bit) registers.
pub const WIDE_REG_COUNT: usize = 8;

/// Encode an instruction from its fields.
///
/// - `op`: opcode
/// - `rd`: destination register (4-bit, 0-15)
/// - `rs1`: first source register (4-bit, 0-15)
/// - `rs2_or_imm`: second source register (4-bit) or 18-bit immediate
pub fn encode(op: Opcode, rd: u8, rs1: u8, rs2_or_imm: u32) -> Instruction {
    debug_assert!(rd <= 0x0F, "rd out of 4-bit range");
    debug_assert!(rs1 <= 0x0F, "rs1 out of 4-bit range");
    debug_assert!(rs2_or_imm <= RS2_IMM_MASK, "rs2/imm out of 18-bit range");

    let word = ((op.to_u8() as u32 & OPCODE_MASK) << OPCODE_SHIFT)
        | ((rd as u32 & RD_MASK) << RD_SHIFT)
        | ((rs1 as u32 & RS1_MASK) << RS1_SHIFT)
        | (rs2_or_imm & RS2_IMM_MASK);
    Instruction(word)
}

/// Decode a 32-bit instruction word into its fields.
pub fn decode(instr: Instruction) -> DecodedInstruction {
    let w = instr.0;
    let opcode_bits = ((w >> OPCODE_SHIFT) & OPCODE_MASK) as u8;
    DecodedInstruction {
        opcode: Opcode::from_u8(opcode_bits),
        rd: ((w >> RD_SHIFT) & RD_MASK) as u8,
        rs1: ((w >> RS1_SHIFT) & RS1_MASK) as u8,
        rs2_or_imm: w & RS2_IMM_MASK,
    }
}

/// Sign-extend an 18-bit immediate value to i32.
/// The 18-bit field is treated as a two's complement signed integer
/// with range [-131072, 131071].
pub fn sign_extend_18(raw: u32) -> i32 {
    let raw = raw & RS2_IMM_MASK;
    if raw & (1 << 17) != 0 {
        // Sign bit set — extend with 1s
        (raw | !RS2_IMM_MASK) as i32
    } else {
        raw as i32
    }
}

/// Encode a signed immediate into the 18-bit field.
/// Returns None if the value is out of range [-131072, 131071].
pub fn encode_immediate(val: i32) -> Option<u32> {
    if !(-131072..=131071).contains(&val) {
        return None;
    }
    Some((val as u32) & RS2_IMM_MASK)
}

// --- Width-encoded memory access ---
// For LOAD/STORE, the 18-bit immediate is split:
//   [offset: 16 bits (signed)][width: 2 bits]
//   width: 00=8-bit, 01=16-bit, 10=32-bit, 11=64-bit

/// Memory access width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MemWidth {
    W8 = 0,
    W16 = 1,
    W32 = 2,
    W64 = 3,
}

/// Extract the width from the lower 2 bits of the 18-bit immediate.
pub fn decode_mem_width(raw: u32) -> MemWidth {
    match raw & 0x03 {
        0 => MemWidth::W8,
        1 => MemWidth::W16,
        2 => MemWidth::W32,
        3 => MemWidth::W64,
        _ => MemWidth::W8, // raw & 3 can only be 0-3, but default to W8 for safety
    }
}

/// Extract the 16-bit signed offset from bits [17:2] of the 18-bit immediate.
pub fn decode_mem_offset(raw: u32) -> i32 {
    let bits = (raw >> 2) & 0xFFFF;
    if bits & (1 << 15) != 0 {
        (bits | 0xFFFF_0000) as i32
    } else {
        bits as i32
    }
}

/// Encode a memory immediate: 16-bit signed offset + 2-bit width.
/// Returns None if offset is out of range [-32768, 32767].
pub fn encode_mem_immediate(offset: i32, width: MemWidth) -> Option<u32> {
    if !(-32768..=32767).contains(&offset) {
        return None;
    }
    let offset_bits = (offset as u32) & 0xFFFF;
    Some(((offset_bits << 2) | (width as u32)) & RS2_IMM_MASK)
}

// --- Gas Table ---

/// Gas cost for an opcode (single dimension).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GasCost(pub u32);

impl GasCost {
    pub const fn new(cost: u32) -> Self {
        Self(cost)
    }

    /// Returns the gas cost.
    pub const fn cost(&self) -> u32 {
        self.0
    }
}

/// Get the gas cost for an opcode.
pub fn gas_cost(op: Opcode) -> GasCost {
    match op {
        // Arithmetic (64-bit) — execution cost only
        Opcode::Add => GasCost::new(1),
        Opcode::Sub => GasCost::new(1),
        Opcode::Mul => GasCost::new(2),
        Opcode::Div => GasCost::new(4),
        Opcode::Mod => GasCost::new(4),
        Opcode::And => GasCost::new(1),
        Opcode::Or => GasCost::new(1),
        Opcode::Xor => GasCost::new(1),
        Opcode::Addi => GasCost::new(1),
        Opcode::Not => GasCost::new(1),
        Opcode::Shl => GasCost::new(1),
        Opcode::Shr => GasCost::new(1),
        Opcode::Sar => GasCost::new(1),
        Opcode::Lt => GasCost::new(1),
        Opcode::Gt => GasCost::new(1),
        Opcode::Eq => GasCost::new(1),
        Opcode::Slt => GasCost::new(1),
        Opcode::Sgt => GasCost::new(1),

        // Wide arithmetic (256-bit)
        Opcode::Wadd => GasCost::new(4),
        Opcode::Wsub => GasCost::new(4),
        Opcode::Wmul => GasCost::new(8),
        Opcode::Wdiv => GasCost::new(8),
        Opcode::Wmod => GasCost::new(8),
        Opcode::Wand => GasCost::new(2),
        Opcode::Wor => GasCost::new(2),
        Opcode::Wxor => GasCost::new(2),
        Opcode::Wnot => GasCost::new(2),
        Opcode::Wshift => GasCost::new(2),
        Opcode::Wmov => GasCost::new(1),
        Opcode::Narrow => GasCost::new(1),
        Opcode::Widen => GasCost::new(1),

        // Memory
        Opcode::Load => GasCost::new(3),
        Opcode::Store => GasCost::new(3),
        Opcode::Push => GasCost::new(3),
        Opcode::Pop => GasCost::new(3),
        Opcode::Wload => GasCost::new(4),
        Opcode::Wstore => GasCost::new(4),

        // Control flow
        Opcode::Jmp => GasCost::new(1),
        Opcode::Beq => GasCost::new(1),
        Opcode::Bne => GasCost::new(1),
        Opcode::Blt => GasCost::new(1),
        Opcode::Bge => GasCost::new(1),
        Opcode::Call => GasCost::new(500),
        Opcode::Ret => GasCost::new(1),

        // Blockchain syscalls
        Opcode::Sload => GasCost::new(200),
        Opcode::Sstore => GasCost::new(2_000),
        Opcode::Sdelete => GasCost::new(500),
        Opcode::Caller => GasCost::new(2),
        Opcode::Callvalue => GasCost::new(2),
        Opcode::Blockhash => GasCost::new(20),
        Opcode::CallExt => GasCost::new(500),
        Opcode::Delegate => GasCost::new(500),
        Opcode::Create => GasCost::new(16_000),
        Opcode::Selfdestruct => GasCost::new(2_500),
        Opcode::Log => GasCost::new(50),
        Opcode::Revert => GasCost::new(1),
        Opcode::Halt => GasCost::new(1),

        // Crypto syscalls
        Opcode::Poseidon => GasCost::new(50),
        Opcode::VerifySig => GasCost::new(5_000),
        Opcode::MerkleVerify => GasCost::new(100),

        // Assertions + memory
        Opcode::Assert => GasCost::new(1),
        Opcode::Memcpy => GasCost::new(3),  // base cost; + 3 per 8 bytes dynamic in handler

        // Wide comparisons
        Opcode::Weq => GasCost::new(2),
        Opcode::Wlt => GasCost::new(2),

        // Invalid
        Opcode::Invalid => GasCost::new(0),
    }
}

/// Precomputed gas lookup table indexed by 6-bit opcode value.
/// Avoids calling `gas_cost()` in the hot loop.
/// Use `TOTAL_GAS_TABLE[opcode as u8 as usize]` for O(1) lookup.
static TOTAL_GAS_TABLE: [u64; 64] = {
    let mut table = [0u64; 64];
    let mut i = 0u8;
    loop {
        let cost = match i {
            0x00 => Some(GasCost::new(2)),       // Weq
            0x01 => Some(GasCost::new(1)),       // Add
            0x02 => Some(GasCost::new(1)),       // Sub
            0x03 => Some(GasCost::new(2)),       // Mul
            0x04 => Some(GasCost::new(4)),       // Div
            0x05 => Some(GasCost::new(4)),       // Mod
            0x06 => Some(GasCost::new(1)),       // And
            0x07 => Some(GasCost::new(1)),       // Or
            0x08 => Some(GasCost::new(1)),       // Xor
            0x09 => Some(GasCost::new(4)),       // Wadd
            0x0A => Some(GasCost::new(4)),       // Wsub
            0x0B => Some(GasCost::new(8)),       // Wmul
            0x0C => Some(GasCost::new(8)),       // Wdiv
            0x0D => Some(GasCost::new(8)),       // Wmod
            0x0E => Some(GasCost::new(1)),       // Addi
            0x0F => Some(GasCost::new(1)),       // Not
            0x10 => Some(GasCost::new(3)),       // Load
            0x11 => Some(GasCost::new(3)),       // Store
            0x12 => Some(GasCost::new(3)),       // Push
            0x13 => Some(GasCost::new(3)),       // Pop
            0x14 => Some(GasCost::new(1)),       // Shl
            0x15 => Some(GasCost::new(1)),       // Shr
            0x16 => Some(GasCost::new(1)),       // Sar
            0x17 => Some(GasCost::new(1)),       // Lt
            0x18 => Some(GasCost::new(1)),       // Jmp
            0x19 => Some(GasCost::new(1)),       // Beq
            0x1A => Some(GasCost::new(1)),       // Bne
            0x1B => Some(GasCost::new(1)),       // Blt
            0x1C => Some(GasCost::new(1)),       // Bge
            0x1D => Some(GasCost::new(500)),     // Call
            0x1E => Some(GasCost::new(1)),       // Ret
            0x1F => Some(GasCost::new(2)),       // Wnot
            0x20 => Some(GasCost::new(200)),     // Sload
            0x21 => Some(GasCost::new(2_000)),   // Sstore
            0x22 => Some(GasCost::new(500)),     // Sdelete
            0x23 => Some(GasCost::new(2)),       // Caller
            0x24 => Some(GasCost::new(2)),       // Callvalue
            0x25 => Some(GasCost::new(20)),      // Blockhash
            0x26 => Some(GasCost::new(500)),     // CallExt
            0x27 => Some(GasCost::new(500)),     // Delegate
            0x28 => Some(GasCost::new(16_000)),  // Create
            0x29 => Some(GasCost::new(2_500)),   // Selfdestruct
            0x2A => Some(GasCost::new(50)),      // Log
            0x2B => Some(GasCost::new(1)),       // Revert
            0x2C => Some(GasCost::new(1)),       // Halt
            0x2D => Some(GasCost::new(2)),       // Wand
            0x2E => Some(GasCost::new(2)),       // Wor
            0x2F => Some(GasCost::new(2)),       // Wxor
            0x3A => Some(GasCost::new(2)),       // Wshift
            0x30 => Some(GasCost::new(50)),      // Poseidon
            0x31 => Some(GasCost::new(5_000)),   // VerifySig
            0x32 => Some(GasCost::new(100)),     // MerkleVerify
            0x33 => Some(GasCost::new(1)),       // Gt
            0x34 => Some(GasCost::new(1)),       // Eq
            0x35 => Some(GasCost::new(1)),       // Slt
            0x36 => Some(GasCost::new(1)),       // Sgt
            0x37 => Some(GasCost::new(4)),       // Wload
            0x38 => Some(GasCost::new(1)),       // Assert
            0x39 => Some(GasCost::new(3)),       // Memcpy
            0x3B => Some(GasCost::new(4)),       // Wstore
            0x3C => Some(GasCost::new(1)),       // Wmov
            0x3D => Some(GasCost::new(1)),       // Narrow
            0x3E => Some(GasCost::new(1)),       // Widen
            0x3F => Some(GasCost::new(2)),       // Wlt
            _ => None,
        };
        table[i as usize] = match cost {
            Some(c) => c.0 as u64,
            None => 0,
        };
        if i == 63 {
            break;
        }
        i += 1;
    }
    table
};

/// Fast total gas lookup by opcode value. O(1) table index.
#[inline]
pub fn total_gas(opcode_val: u8) -> u64 {
    TOTAL_GAS_TABLE[(opcode_val & 0x3F) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Task 0081: encode/decode roundtrip for every opcode ---

    #[test]
    fn encode_decode_roundtrip_all_opcodes() {
        for &op in ALL_OPCODES {
            let rd = 5u8;
            let rs1 = 10u8;
            let rs2 = 7u32;
            let instr = encode(op, rd, rs1, rs2);
            let dec = decode(instr);
            assert_eq!(dec.opcode, op, "opcode mismatch for {:?}", op);
            assert_eq!(dec.rd, rd, "rd mismatch for {:?}", op);
            assert_eq!(dec.rs1, rs1, "rs1 mismatch for {:?}", op);
            assert_eq!(dec.rs2_or_imm, rs2, "rs2/imm mismatch for {:?}", op);
        }
    }

    #[test]
    fn encode_decode_roundtrip_max_fields() {
        for &op in ALL_OPCODES {
            let rd = 15u8;
            let rs1 = 15u8;
            let rs2_or_imm = RS2_IMM_MASK; // all 18 bits set
            let instr = encode(op, rd, rs1, rs2_or_imm);
            let dec = decode(instr);
            assert_eq!(dec.opcode, op);
            assert_eq!(dec.rd, 15);
            assert_eq!(dec.rs1, 15);
            assert_eq!(dec.rs2_or_imm, RS2_IMM_MASK);
        }
    }

    #[test]
    fn encode_decode_roundtrip_zero_fields() {
        for &op in ALL_OPCODES {
            let instr = encode(op, 0, 0, 0);
            let dec = decode(instr);
            assert_eq!(dec.opcode, op);
            assert_eq!(dec.rd, 0);
            assert_eq!(dec.rs1, 0);
            assert_eq!(dec.rs2_or_imm, 0);
        }
    }

    // --- Task 0082: invalid opcode bits decode to Opcode::Invalid ---

    #[test]
    fn invalid_opcode_bits_decode_to_invalid() {
        // All 64 slots (0x00-0x3F) are now assigned.
        // Invalid only comes from values outside 6-bit range, which can't happen in practice.
        // Verify 0x00 = Weq, 0x3F = Wlt
        let instr = Instruction(0x00 << OPCODE_SHIFT);
        assert_eq!(decode(instr).opcode, Opcode::Weq);

        let instr = Instruction(0x3F << OPCODE_SHIFT);
        assert_eq!(decode(instr).opcode, Opcode::Wlt);
    }

    #[test]
    fn all_unassigned_opcode_slots_are_invalid() {
        // Test every possible 6-bit value
        for bits in 0..=0x3Fu8 {
            let op = Opcode::from_u8(bits);
            if op == Opcode::Invalid {
                // Confirm it's not in the ALL_OPCODES list
                assert!(!ALL_OPCODES.contains(&Opcode::Invalid));
            } else {
                // Confirm roundtrip
                assert_eq!(op.to_u8(), bits, "to_u8 mismatch for {:?}", op);
            }
        }
    }

    // --- Task 0083: immediate field sign extension (18-bit signed) ---

    #[test]
    fn sign_extend_positive() {
        // 0 -> 0
        assert_eq!(sign_extend_18(0), 0);
        // 1 -> 1
        assert_eq!(sign_extend_18(1), 1);
        // Max positive: 2^17 - 1 = 131071
        assert_eq!(sign_extend_18(0x1FFFF), 131071);
        // Some typical value
        assert_eq!(sign_extend_18(42), 42);
    }

    #[test]
    fn sign_extend_negative() {
        // -1 in 18-bit two's complement = 0x3FFFF
        assert_eq!(sign_extend_18(0x3FFFF), -1);
        // -2 = 0x3FFFE
        assert_eq!(sign_extend_18(0x3FFFE), -2);
        // Min negative: -2^17 = -131072, encoded as 0x20000
        assert_eq!(sign_extend_18(0x20000), -131072);
        // -42 in 18-bit = 0x3FFD6
        assert_eq!(sign_extend_18(encode_immediate(-42).unwrap()), -42);
    }

    #[test]
    fn sign_extend_roundtrip() {
        for val in [-131072, -1000, -1, 0, 1, 1000, 131071] {
            let encoded = encode_immediate(val).unwrap();
            let decoded = sign_extend_18(encoded);
            assert_eq!(decoded, val, "roundtrip failed for {}", val);
        }
    }

    #[test]
    fn sign_extend_boundary_values() {
        // Boundary between positive and negative: 0x1FFFF (131071) and 0x20000 (-131072)
        assert_eq!(sign_extend_18(0x1FFFF), 131071); // max positive
        assert_eq!(sign_extend_18(0x20000), -131072); // min negative
                                                      // One step apart
        assert_eq!(sign_extend_18(0x1FFFF) - sign_extend_18(0x20000), 262143);
    }

    #[test]
    fn encode_immediate_overflow() {
        assert!(encode_immediate(131072).is_none()); // max + 1
    }

    #[test]
    fn encode_immediate_underflow() {
        assert!(encode_immediate(-131073).is_none()); // min - 1
    }

    // --- Task 0084: register field bounds ---

    #[test]
    fn gp_register_range() {
        // GP registers: 0-15 (4 bits)
        for rd in 0..=15u8 {
            for rs1 in 0..=15u8 {
                let instr = encode(Opcode::Add, rd, rs1, 0);
                let dec = decode(instr);
                assert_eq!(dec.rd, rd);
                assert_eq!(dec.rs1, rs1);
            }
        }
    }

    #[test]
    fn wide_register_encoding() {
        // Wide ops use rd/rs1 fields for 0-7 (only lower 3 bits matter)
        for wd in 0..=7u8 {
            for ws1 in 0..=7u8 {
                let instr = encode(Opcode::Wadd, wd, ws1, 0);
                let dec = decode(instr);
                assert_eq!(dec.rd, wd);
                assert_eq!(dec.rs1, ws1);
            }
        }
    }

    #[test]
    fn rs2_register_in_lower_bits() {
        // For register-mode instructions, rs2 is in the lower 4 bits of the 18-bit field
        for rs2 in 0..=15u8 {
            let instr = encode(Opcode::Add, 1, 2, rs2 as u32);
            let dec = decode(instr);
            assert_eq!(dec.rs2_or_imm & 0x0F, rs2 as u32);
        }
    }

    // --- Gas table tests ---

    #[test]
    fn gas_costs_match_spec() {
        // Spot-check key values from the gas table
        assert_eq!(gas_cost(Opcode::Add).cost(), 1);
        assert_eq!(gas_cost(Opcode::Mul).cost(), 2);
        assert_eq!(gas_cost(Opcode::Div).cost(), 4);
        assert_eq!(gas_cost(Opcode::Wadd).cost(), 4);
        assert_eq!(gas_cost(Opcode::Wmul).cost(), 8);
        assert_eq!(gas_cost(Opcode::Load).cost(), 3);
        assert_eq!(gas_cost(Opcode::Store).cost(), 3);
        assert_eq!(gas_cost(Opcode::Sload).cost(), 200);
        assert_eq!(gas_cost(Opcode::Sstore).cost(), 2000);
        assert_eq!(gas_cost(Opcode::Poseidon).cost(), 50);
        assert_eq!(gas_cost(Opcode::VerifySig).cost(), 5000);
    }

    #[test]
    fn all_opcodes_have_nonzero_gas() {
        for &op in ALL_OPCODES {
            let cost = gas_cost(op);
            assert!(cost.cost() > 0, "{:?} has zero gas", op);
        }
    }

    #[test]
    fn invalid_opcode_has_zero_gas() {
        assert_eq!(gas_cost(Opcode::Invalid).cost(), 0);
    }

    // ========== Gas lookup table matches gas_cost ==========

    #[test]
    fn total_gas_table_matches_gas_cost() {
        for &op in ALL_OPCODES {
            let from_table = total_gas(op.to_u8());
            let from_func = gas_cost(op).cost() as u64;
            assert_eq!(
                from_table, from_func,
                "{:?} (0x{:02X}): table={} vs func={}",
                op,
                op.to_u8(),
                from_table,
                from_func
            );
        }
    }

    #[test]
    fn total_gas_unassigned_slots_are_zero() {
        // Check that opcode slots not assigned to any valid instruction return 0
        // All 64 slots (0x00-0x3F) are assigned in Pyde's ISA, so check
        // that the table covers the full range without panicking
        for i in 0..64u8 {
            let _ = total_gas(i); // should not panic
        }
    }

    // --- Instruction bit layout tests ---

    #[test]
    fn opcode_occupies_top_6_bits() {
        let instr = encode(Opcode::Add, 0, 0, 0); // Add = 0x01
        assert_eq!(instr.0 >> 26, 0x01);
    }

    #[test]
    fn rd_occupies_bits_25_22() {
        let instr = encode(Opcode::Add, 0xF, 0, 0);
        assert_eq!((instr.0 >> 22) & 0xF, 0xF);
    }

    #[test]
    fn rs1_occupies_bits_21_18() {
        let instr = encode(Opcode::Add, 0, 0xF, 0);
        assert_eq!((instr.0 >> 18) & 0xF, 0xF);
    }

    #[test]
    fn imm_occupies_bits_17_0() {
        let instr = encode(Opcode::Add, 0, 0, 0x3FFFF);
        assert_eq!(instr.0 & 0x3FFFF, 0x3FFFF);
    }

    #[test]
    fn fields_are_independent() {
        // Setting one field should not affect others
        let i1 = encode(Opcode::Add, 15, 0, 0);
        let i2 = encode(Opcode::Add, 0, 15, 0);
        let i3 = encode(Opcode::Add, 0, 0, 0x3FFFF);
        // The bits should not overlap
        assert_eq!(i1.0 & i2.0, encode(Opcode::Add, 0, 0, 0).0);
        assert_eq!(i1.0 & i3.0, encode(Opcode::Add, 0, 0, 0).0);
        assert_eq!(i2.0 & i3.0, encode(Opcode::Add, 0, 0, 0).0);
    }

    // --- Opcode categorization ---

    #[test]
    fn opcode_count() {
        // Design spec says ~45 core opcodes + extended instructions = ~58
        assert!(
            ALL_OPCODES.len() >= 45 && ALL_OPCODES.len() <= 64,
            "expected 45-64 opcodes (6-bit max), got {}",
            ALL_OPCODES.len()
        );
    }

    #[test]
    fn wide_opcodes_are_correct() {
        assert!(Opcode::Wadd.is_wide());
        assert!(Opcode::Wload.is_wide());
        assert!(Opcode::Widen.is_wide());
        assert!(!Opcode::Add.is_wide());
        assert!(!Opcode::Load.is_wide());
    }

    #[test]
    fn immediate_opcodes_are_correct() {
        assert!(Opcode::Addi.uses_immediate());
        assert!(Opcode::Load.uses_immediate());
        assert!(Opcode::Jmp.uses_immediate());
        assert!(Opcode::Beq.uses_immediate());
        assert!(Opcode::Call.uses_immediate());
        assert!(!Opcode::Add.uses_immediate());
        assert!(!Opcode::Ret.uses_immediate());
    }
}
