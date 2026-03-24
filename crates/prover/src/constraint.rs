//! PVM opcode constants and constraint documentation.
//!
//! The actual constraint evaluation lives in `air_adapter.rs` which implements
//! Plonky3's `Air<AB>` trait. This module provides the opcode constants shared
//! between the constraint evaluator, the recorder, and tests.
//!
//! ## Constraint Design
//!
//! PVM uses CHECKED arithmetic (traps on overflow), so Goldilocks field
//! arithmetic is exact for all valid execution traces. No limb decomposition
//! needed for GP registers.
//!
//! Bitwise operations (AND/OR/XOR/NOT) are verified via lookup tables (logup).
//! Wide arithmetic (WADD/WSUB/WMUL) uses carry propagation constraints.
//! Memory/storage consistency is verified via cross-table permutation arguments.

/// Opcode constants matching pyde-vm ISA.
/// Used by the AIR adapter, recorder, and tests.
pub mod opcodes {
    // GP Arithmetic
    pub const ADD: u64 = 0x01;
    pub const SUB: u64 = 0x02;
    pub const MUL: u64 = 0x03;
    pub const DIV: u64 = 0x04;
    pub const MOD: u64 = 0x05;
    pub const ADDI: u64 = 0x0E;

    // GP Bitwise
    pub const AND: u64 = 0x06;
    pub const OR: u64 = 0x07;
    pub const XOR: u64 = 0x08;
    pub const NOT: u64 = 0x0F;
    pub const SHL: u64 = 0x14;
    pub const SHR: u64 = 0x15;
    pub const SAR: u64 = 0x16;

    // Comparisons
    pub const LT: u64 = 0x17;
    pub const GT: u64 = 0x33;
    pub const EQ: u64 = 0x34;
    pub const SLT: u64 = 0x35;
    pub const SGT: u64 = 0x36;

    // Memory
    pub const LOAD: u64 = 0x10;
    pub const STORE: u64 = 0x11;
    pub const PUSH: u64 = 0x12;
    pub const POP: u64 = 0x13;

    // Control Flow
    pub const JMP: u64 = 0x18;
    pub const BEQ: u64 = 0x19;
    pub const BNE: u64 = 0x1A;
    pub const BLT: u64 = 0x1B;
    pub const BGE: u64 = 0x1C;
    pub const CALL: u64 = 0x1D;
    pub const RET: u64 = 0x1E;

    // Blockchain / Storage
    pub const SLOAD: u64 = 0x20;
    pub const SSTORE: u64 = 0x21;
    pub const SDELETE: u64 = 0x22;
    pub const CALLER: u64 = 0x23;
    pub const CALLVALUE: u64 = 0x24;
    pub const BLOCKHASH: u64 = 0x25;
    pub const CALLEXT: u64 = 0x26;
    pub const DELEGATE: u64 = 0x27;
    pub const CREATE: u64 = 0x28;
    pub const SELFDESTRUCT: u64 = 0x29;
    pub const LOG: u64 = 0x2A;
    pub const REVERT: u64 = 0x2B;
    pub const HALT: u64 = 0x2C;

    // Wide Arithmetic
    pub const WADD: u64 = 0x09;
    pub const WSUB: u64 = 0x0A;
    pub const WMUL: u64 = 0x0B;
    pub const WDIV: u64 = 0x0C;
    pub const WMOD: u64 = 0x0D;

    // Wide Bitwise
    pub const WAND: u64 = 0x2D;
    pub const WOR: u64 = 0x2E;
    pub const WXOR: u64 = 0x2F;
    pub const WNOT: u64 = 0x1F;

    // Wide Register Ops
    pub const WEQ: u64 = 0x00;
    pub const WLT: u64 = 0x3F;
    pub const WMOV: u64 = 0x3C;
    pub const NARROW: u64 = 0x3D;
    pub const WIDEN: u64 = 0x3E;
    pub const WLOAD: u64 = 0x37;
    pub const WSTORE: u64 = 0x3B;

    // Crypto / ZK-Native
    pub const POSEIDON: u64 = 0x30;
    pub const VERIFYSIG: u64 = 0x31;
    pub const MERKLEVERIFY: u64 = 0x32;
    pub const ASSERT: u64 = 0x38;
    pub const FIELDMUL: u64 = 0x39;
    pub const COMMIT: u64 = 0x3A;
}

/// Maximum constraint degree in the AIR.
/// opcode_selector = degree 6 (product of 6 bits)
/// × operand terms ≈ degree 2
/// = total ≈ 8
pub const MAX_CONSTRAINT_DEGREE: usize = 8;

#[cfg(test)]
mod tests {
    use super::opcodes;

    #[test]
    fn all_65_opcode_constants_match_isa() {
        use pyde_vm::isa::Opcode;

        // GP arithmetic (7)
        assert_eq!(opcodes::ADD, Opcode::Add as u64);
        assert_eq!(opcodes::SUB, Opcode::Sub as u64);
        assert_eq!(opcodes::MUL, Opcode::Mul as u64);
        assert_eq!(opcodes::DIV, Opcode::Div as u64);
        assert_eq!(opcodes::MOD, Opcode::Mod as u64);
        assert_eq!(opcodes::ADDI, Opcode::Addi as u64);
        assert_eq!(opcodes::FIELDMUL, Opcode::FieldMul as u64);

        // GP bitwise (7)
        assert_eq!(opcodes::AND, Opcode::And as u64);
        assert_eq!(opcodes::OR, Opcode::Or as u64);
        assert_eq!(opcodes::XOR, Opcode::Xor as u64);
        assert_eq!(opcodes::NOT, Opcode::Not as u64);
        assert_eq!(opcodes::SHL, Opcode::Shl as u64);
        assert_eq!(opcodes::SHR, Opcode::Shr as u64);
        assert_eq!(opcodes::SAR, Opcode::Sar as u64);

        // Comparisons (5)
        assert_eq!(opcodes::EQ, Opcode::Eq as u64);
        assert_eq!(opcodes::LT, Opcode::Lt as u64);
        assert_eq!(opcodes::GT, Opcode::Gt as u64);
        assert_eq!(opcodes::SLT, Opcode::Slt as u64);
        assert_eq!(opcodes::SGT, Opcode::Sgt as u64);

        // Memory (6)
        assert_eq!(opcodes::LOAD, Opcode::Load as u64);
        assert_eq!(opcodes::STORE, Opcode::Store as u64);
        assert_eq!(opcodes::PUSH, Opcode::Push as u64);
        assert_eq!(opcodes::POP, Opcode::Pop as u64);
        assert_eq!(opcodes::WLOAD, Opcode::Wload as u64);
        assert_eq!(opcodes::WSTORE, Opcode::Wstore as u64);

        // Control flow (7)
        assert_eq!(opcodes::JMP, Opcode::Jmp as u64);
        assert_eq!(opcodes::BEQ, Opcode::Beq as u64);
        assert_eq!(opcodes::BNE, Opcode::Bne as u64);
        assert_eq!(opcodes::BLT, Opcode::Blt as u64);
        assert_eq!(opcodes::BGE, Opcode::Bge as u64);
        assert_eq!(opcodes::CALL, Opcode::Call as u64);
        assert_eq!(opcodes::RET, Opcode::Ret as u64);

        // Termination (3)
        assert_eq!(opcodes::HALT, Opcode::Halt as u64);
        assert_eq!(opcodes::REVERT, Opcode::Revert as u64);
        assert_eq!(opcodes::SELFDESTRUCT, Opcode::Selfdestruct as u64);

        // Storage (3)
        assert_eq!(opcodes::SLOAD, Opcode::Sload as u64);
        assert_eq!(opcodes::SSTORE, Opcode::Sstore as u64);
        assert_eq!(opcodes::SDELETE, Opcode::Sdelete as u64);

        // Wide arithmetic (5)
        assert_eq!(opcodes::WADD, Opcode::Wadd as u64);
        assert_eq!(opcodes::WSUB, Opcode::Wsub as u64);
        assert_eq!(opcodes::WMUL, Opcode::Wmul as u64);
        assert_eq!(opcodes::WDIV, Opcode::Wdiv as u64);
        assert_eq!(opcodes::WMOD, Opcode::Wmod as u64);

        // Wide bitwise (4)
        assert_eq!(opcodes::WAND, Opcode::Wand as u64);
        assert_eq!(opcodes::WOR, Opcode::Wor as u64);
        assert_eq!(opcodes::WXOR, Opcode::Wxor as u64);
        assert_eq!(opcodes::WNOT, Opcode::Wnot as u64);

        // Wide register ops (5)
        assert_eq!(opcodes::WMOV, Opcode::Wmov as u64);
        assert_eq!(opcodes::NARROW, Opcode::Narrow as u64);
        assert_eq!(opcodes::WIDEN, Opcode::Widen as u64);
        assert_eq!(opcodes::WEQ, Opcode::Weq as u64);
        assert_eq!(opcodes::WLT, Opcode::Wlt as u64);

        // Syscalls (8)
        assert_eq!(opcodes::CALLER, Opcode::Caller as u64);
        assert_eq!(opcodes::CALLVALUE, Opcode::Callvalue as u64);
        assert_eq!(opcodes::BLOCKHASH, Opcode::Blockhash as u64);
        assert_eq!(opcodes::CALLEXT, Opcode::CallExt as u64);
        assert_eq!(opcodes::DELEGATE, Opcode::Delegate as u64);
        assert_eq!(opcodes::CREATE, Opcode::Create as u64);
        assert_eq!(opcodes::LOG, Opcode::Log as u64);
        assert_eq!(opcodes::ASSERT, Opcode::Assert as u64);

        // Crypto / ZK-native (4)
        assert_eq!(opcodes::POSEIDON, Opcode::Poseidon as u64);
        assert_eq!(opcodes::VERIFYSIG, Opcode::VerifySig as u64);
        assert_eq!(opcodes::MERKLEVERIFY, Opcode::MerkleVerify as u64);
        assert_eq!(opcodes::COMMIT, Opcode::Commit as u64);
    }

    #[test]
    fn opcode_count() {
        // 7 + 7 + 5 + 6 + 7 + 3 + 3 + 5 + 4 + 5 + 8 + 4 = 64 real opcodes + Invalid = 65
        // Verify we have constants for all 64 real opcodes
        let all = [
            opcodes::ADD, opcodes::SUB, opcodes::MUL, opcodes::DIV, opcodes::MOD,
            opcodes::ADDI, opcodes::FIELDMUL,
            opcodes::AND, opcodes::OR, opcodes::XOR, opcodes::NOT,
            opcodes::SHL, opcodes::SHR, opcodes::SAR,
            opcodes::EQ, opcodes::LT, opcodes::GT, opcodes::SLT, opcodes::SGT,
            opcodes::LOAD, opcodes::STORE, opcodes::PUSH, opcodes::POP,
            opcodes::WLOAD, opcodes::WSTORE,
            opcodes::JMP, opcodes::BEQ, opcodes::BNE, opcodes::BLT, opcodes::BGE,
            opcodes::CALL, opcodes::RET,
            opcodes::HALT, opcodes::REVERT, opcodes::SELFDESTRUCT,
            opcodes::SLOAD, opcodes::SSTORE, opcodes::SDELETE,
            opcodes::WADD, opcodes::WSUB, opcodes::WMUL, opcodes::WDIV, opcodes::WMOD,
            opcodes::WAND, opcodes::WOR, opcodes::WXOR, opcodes::WNOT,
            opcodes::WMOV, opcodes::NARROW, opcodes::WIDEN, opcodes::WEQ, opcodes::WLT,
            opcodes::CALLER, opcodes::CALLVALUE, opcodes::BLOCKHASH,
            opcodes::CALLEXT, opcodes::DELEGATE, opcodes::CREATE,
            opcodes::LOG, opcodes::ASSERT,
            opcodes::POSEIDON, opcodes::VERIFYSIG, opcodes::MERKLEVERIFY,
            opcodes::COMMIT,
        ];
        assert_eq!(all.len(), 64, "expected 64 real opcodes");

        // All values must be unique
        let mut sorted = all.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 64, "duplicate opcode values found");
    }
}
