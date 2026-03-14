//! PVM CPU: register file and instruction execution.

use crate::isa::{decode, sign_extend_18, Instruction, Opcode, GP_REG_COUNT, WIDE_REG_COUNT};
use crate::wide::{self, U256};
use thiserror::Error;

/// Execution error — the VM traps on these conditions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum Trap {
    #[error("arithmetic overflow")]
    Overflow,
    #[error("arithmetic underflow")]
    Underflow,
    #[error("division by zero")]
    DivisionByZero,
    #[error("invalid opcode")]
    InvalidOpcode,
    #[error("narrow: value exceeds 64 bits")]
    NarrowOverflow,
    #[error("memory fault")]
    MemoryFault,
    #[error("call stack overflow")]
    StackOverflow,
    #[error("call stack underflow")]
    StackUnderflow,
    #[error("out of gas")]
    OutOfGas,
}

/// The CPU register file and minimal execution state.
#[derive(Clone, Debug)]
pub struct Cpu {
    /// 16 general-purpose 64-bit registers.
    /// r0 is hardwired to zero.
    pub gp: [u64; GP_REG_COUNT],
    /// 8 wide 256-bit registers (w0-w7).
    pub wide: [U256; WIDE_REG_COUNT],
}

impl Cpu {
    pub fn new() -> Self {
        Self {
            gp: [0u64; GP_REG_COUNT],
            wide: [U256::ZERO; WIDE_REG_COUNT],
        }
    }

    /// Read a GP register. r0 always returns 0.
    pub fn read_gp(&self, reg: u8) -> u64 {
        if reg == 0 {
            0
        } else {
            self.gp[reg as usize]
        }
    }

    /// Write a GP register. Writes to r0 are silently discarded.
    pub fn write_gp(&mut self, reg: u8, val: u64) {
        if reg != 0 {
            self.gp[reg as usize] = val;
        }
    }

    /// Read a wide register (0-7).
    pub fn read_wide(&self, reg: u8) -> U256 {
        self.wide[(reg & 0x07) as usize]
    }

    /// Write a wide register (0-7).
    pub fn write_wide(&mut self, reg: u8, val: U256) {
        self.wide[(reg & 0x07) as usize] = val;
    }

    /// Execute a single arithmetic/logic instruction.
    /// Returns Ok(()) on success, Err(Trap) on fault.
    pub fn exec_alu(&mut self, instr: Instruction) -> Result<(), Trap> {
        let d = decode(instr);
        let rs1_val = self.read_gp(d.rs1);

        match d.opcode {
            Opcode::Add => {
                let rs2_val = self.read_gp(d.rs2_or_imm as u8 & 0x0F);
                let result = rs1_val.checked_add(rs2_val).ok_or(Trap::Overflow)?;
                self.write_gp(d.rd, result);
            }
            Opcode::Sub => {
                let rs2_val = self.read_gp(d.rs2_or_imm as u8 & 0x0F);
                let result = rs1_val.checked_sub(rs2_val).ok_or(Trap::Underflow)?;
                self.write_gp(d.rd, result);
            }
            Opcode::Mul => {
                let rs2_val = self.read_gp(d.rs2_or_imm as u8 & 0x0F);
                let result = rs1_val.checked_mul(rs2_val).ok_or(Trap::Overflow)?;
                self.write_gp(d.rd, result);
            }
            Opcode::Div => {
                let rs2_val = self.read_gp(d.rs2_or_imm as u8 & 0x0F);
                let result = rs1_val.checked_div(rs2_val).ok_or(Trap::DivisionByZero)?;
                self.write_gp(d.rd, result);
            }
            Opcode::Mod => {
                let rs2_val = self.read_gp(d.rs2_or_imm as u8 & 0x0F);
                if rs2_val == 0 {
                    return Err(Trap::DivisionByZero);
                }
                self.write_gp(d.rd, rs1_val % rs2_val);
            }
            Opcode::Addi => {
                let imm = sign_extend_18(d.rs2_or_imm) as i64;
                let result = (rs1_val as i64).checked_add(imm).ok_or(Trap::Overflow)?;
                self.write_gp(d.rd, result as u64);
            }
            Opcode::And => {
                let rs2_val = self.read_gp(d.rs2_or_imm as u8 & 0x0F);
                self.write_gp(d.rd, rs1_val & rs2_val);
            }
            Opcode::Or => {
                let rs2_val = self.read_gp(d.rs2_or_imm as u8 & 0x0F);
                self.write_gp(d.rd, rs1_val | rs2_val);
            }
            Opcode::Xor => {
                let rs2_val = self.read_gp(d.rs2_or_imm as u8 & 0x0F);
                self.write_gp(d.rd, rs1_val ^ rs2_val);
            }
            Opcode::Not => {
                self.write_gp(d.rd, !rs1_val);
            }
            Opcode::Shl => {
                let rs2_val = self.read_gp(d.rs2_or_imm as u8 & 0x0F);
                // Shift amount >= 64 produces 0
                let result = if rs2_val >= 64 { 0 } else { rs1_val << rs2_val };
                self.write_gp(d.rd, result);
            }
            Opcode::Shr => {
                let rs2_val = self.read_gp(d.rs2_or_imm as u8 & 0x0F);
                let result = if rs2_val >= 64 { 0 } else { rs1_val >> rs2_val };
                self.write_gp(d.rd, result);
            }
            Opcode::Sar => {
                let rs2_val = self.read_gp(d.rs2_or_imm as u8 & 0x0F);
                let signed = rs1_val as i64;
                // Arithmetic shift: shift >= 64 fills with sign bit
                let result = if rs2_val >= 64 {
                    if signed < 0 {
                        -1i64 as u64
                    } else {
                        0
                    }
                } else {
                    (signed >> rs2_val) as u64
                };
                self.write_gp(d.rd, result);
            }
            Opcode::Lt => {
                let rs2_val = self.read_gp(d.rs2_or_imm as u8 & 0x0F);
                self.write_gp(d.rd, if rs1_val < rs2_val { 1 } else { 0 });
            }
            Opcode::Gt => {
                let rs2_val = self.read_gp(d.rs2_or_imm as u8 & 0x0F);
                self.write_gp(d.rd, if rs1_val > rs2_val { 1 } else { 0 });
            }
            Opcode::Eq => {
                let rs2_val = self.read_gp(d.rs2_or_imm as u8 & 0x0F);
                self.write_gp(d.rd, if rs1_val == rs2_val { 1 } else { 0 });
            }
            Opcode::Slt => {
                let rs2_val = self.read_gp(d.rs2_or_imm as u8 & 0x0F);
                self.write_gp(
                    d.rd,
                    if (rs1_val as i64) < (rs2_val as i64) {
                        1
                    } else {
                        0
                    },
                );
            }
            Opcode::Sgt => {
                let rs2_val = self.read_gp(d.rs2_or_imm as u8 & 0x0F);
                self.write_gp(
                    d.rd,
                    if (rs1_val as i64) > (rs2_val as i64) {
                        1
                    } else {
                        0
                    },
                );
            }
            _ => return Err(Trap::InvalidOpcode),
        }

        Ok(())
    }

    /// Execute a single wide (256-bit) instruction.
    /// Returns Ok(()) on success, Err(Trap) on fault.
    pub fn exec_wide(&mut self, instr: Instruction) -> Result<(), Trap> {
        let d = decode(instr);

        match d.opcode {
            Opcode::Wadd => {
                let ws1 = self.read_wide(d.rs1);
                let ws2 = self.read_wide(d.rs2_or_imm as u8);
                let result = wide::wide_add(ws1, ws2)?;
                self.write_wide(d.rd, result);
            }
            Opcode::Wsub => {
                let ws1 = self.read_wide(d.rs1);
                let ws2 = self.read_wide(d.rs2_or_imm as u8);
                let result = wide::wide_sub(ws1, ws2)?;
                self.write_wide(d.rd, result);
            }
            Opcode::Wmul => {
                let ws1 = self.read_wide(d.rs1);
                let ws2 = self.read_wide(d.rs2_or_imm as u8);
                let result = wide::wide_mul(ws1, ws2)?;
                self.write_wide(d.rd, result);
            }
            Opcode::Wdiv => {
                let ws1 = self.read_wide(d.rs1);
                let ws2 = self.read_wide(d.rs2_or_imm as u8);
                let result = wide::wide_div(ws1, ws2)?;
                self.write_wide(d.rd, result);
            }
            Opcode::Wmod => {
                let ws1 = self.read_wide(d.rs1);
                let ws2 = self.read_wide(d.rs2_or_imm as u8);
                let result = wide::wide_mod(ws1, ws2)?;
                self.write_wide(d.rd, result);
            }
            Opcode::Wand => {
                let ws1 = self.read_wide(d.rs1);
                let ws2 = self.read_wide(d.rs2_or_imm as u8);
                self.write_wide(d.rd, ws1 & ws2);
            }
            Opcode::Wor => {
                let ws1 = self.read_wide(d.rs1);
                let ws2 = self.read_wide(d.rs2_or_imm as u8);
                self.write_wide(d.rd, ws1 | ws2);
            }
            Opcode::Wxor => {
                let ws1 = self.read_wide(d.rs1);
                let ws2 = self.read_wide(d.rs2_or_imm as u8);
                self.write_wide(d.rd, ws1 ^ ws2);
            }
            Opcode::Wnot => {
                let ws1 = self.read_wide(d.rs1);
                self.write_wide(d.rd, !ws1);
            }
            Opcode::Wmov => {
                let ws1 = self.read_wide(d.rs1);
                self.write_wide(d.rd, ws1);
            }
            Opcode::Narrow => {
                let ws1 = self.read_wide(d.rs1);
                let val = wide::narrow(ws1).ok_or(Trap::NarrowOverflow)?;
                self.write_gp(d.rd, val);
            }
            Opcode::Widen => {
                let val = self.read_gp(d.rs1);
                self.write_wide(d.rd, U256::from(val));
            }
            Opcode::Weq => {
                let ws1 = self.read_wide(d.rs1);
                let ws2 = self.read_wide(d.rs2_or_imm as u8);
                self.write_gp(d.rd, if ws1 == ws2 { 1 } else { 0 });
            }
            Opcode::Wlt => {
                let ws1 = self.read_wide(d.rs1);
                let ws2 = self.read_wide(d.rs2_or_imm as u8);
                self.write_gp(d.rd, if ws1 < ws2 { 1 } else { 0 });
            }
            _ => return Err(Trap::InvalidOpcode),
        }

        Ok(())
    }
}

impl Default for Cpu {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::Opcode;
    use crate::wide::U256;

    fn fresh() -> Cpu {
        Cpu::new()
    }

    /// Build a U256 from 4 u64 limbs (little-endian: l0 is lowest).
    fn u256(l0: u64, l1: u64, l2: u64, l3: u64) -> U256 {
        let lo = (l1 as u128) << 64 | l0 as u128;
        let hi = (l3 as u128) << 64 | l2 as u128;
        U256::from_words(hi, lo)
    }

    fn exec_rr(cpu: &mut Cpu, op: Opcode, rd: u8, rs1: u8, rs2: u8) -> Result<(), Trap> {
        use crate::isa::encode;
        cpu.exec_alu(encode(op, rd, rs1, rs2 as u32))
    }

    fn exec_ri(cpu: &mut Cpu, op: Opcode, rd: u8, rs1: u8, imm: i32) -> Result<(), Trap> {
        use crate::isa::{encode, encode_immediate};
        cpu.exec_alu(encode(op, rd, rs1, encode_immediate(imm)))
    }

    fn exec_wide_rr(
        cpu: &mut Cpu,
        op: Opcode,
        wd: u8,
        ws1: u8,
        ws2: u8,
    ) -> Result<(), Trap> {
        use crate::isa::encode;
        cpu.exec_wide(encode(op, wd, ws1, ws2 as u32))
    }

    // ========== Task 0108: WADD ==========

    #[test]
    fn wadd_basic() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::from(100u64));
        cpu.write_wide(2, U256::from(200u64));
        exec_wide_rr(&mut cpu, Opcode::Wadd, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_wide(3), U256::from(300u64));
    }

    #[test]
    fn wadd_cross_limb() {
        let mut cpu = fresh();
        cpu.write_wide(1, u256(u64::MAX, 0, 0, 0));
        cpu.write_wide(2, U256::from(1u64));
        exec_wide_rr(&mut cpu, Opcode::Wadd, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_wide(3), u256(0, 1, 0, 0));
    }

    #[test]
    fn wadd_overflow_traps() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::MAX);
        cpu.write_wide(2, U256::ONE);
        assert_eq!(
            exec_wide_rr(&mut cpu, Opcode::Wadd, 3, 1, 2),
            Err(Trap::Overflow)
        );
    }

    // ========== Task 0109: WSUB ==========

    #[test]
    fn wsub_basic() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::from(300u64));
        cpu.write_wide(2, U256::from(100u64));
        exec_wide_rr(&mut cpu, Opcode::Wsub, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_wide(3), U256::from(200u64));
    }

    #[test]
    fn wsub_underflow_traps() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::ZERO);
        cpu.write_wide(2, U256::ONE);
        assert_eq!(
            exec_wide_rr(&mut cpu, Opcode::Wsub, 3, 1, 2),
            Err(Trap::Underflow)
        );
    }

    // ========== Task 0110: WMUL ==========

    #[test]
    fn wmul_basic() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::from(7u64));
        cpu.write_wide(2, U256::from(6u64));
        exec_wide_rr(&mut cpu, Opcode::Wmul, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_wide(3), U256::from(42u64));
    }

    #[test]
    fn wmul_overflow_traps() {
        let mut cpu = fresh();
        cpu.write_wide(1, u256(0, 0, 1, 0)); // 2^128
        cpu.write_wide(2, u256(0, 0, 1, 0)); // 2^128
        assert_eq!(
            exec_wide_rr(&mut cpu, Opcode::Wmul, 3, 1, 2),
            Err(Trap::Overflow)
        );
    }

    // ========== Task 0111: WDIV ==========

    #[test]
    fn wdiv_basic() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::from(42u64));
        cpu.write_wide(2, U256::from(7u64));
        exec_wide_rr(&mut cpu, Opcode::Wdiv, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_wide(3), U256::from(6u64));
    }

    #[test]
    fn wdiv_by_zero_traps() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::from(42u64));
        cpu.write_wide(2, U256::ZERO);
        assert_eq!(
            exec_wide_rr(&mut cpu, Opcode::Wdiv, 3, 1, 2),
            Err(Trap::DivisionByZero)
        );
    }

    // ========== Task 0112: WMOD ==========

    #[test]
    fn wmod_basic() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::from(10u64));
        cpu.write_wide(2, U256::from(3u64));
        exec_wide_rr(&mut cpu, Opcode::Wmod, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_wide(3), U256::from(1u64));
    }

    #[test]
    fn wmod_by_zero_traps() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::from(10u64));
        cpu.write_wide(2, U256::ZERO);
        assert_eq!(
            exec_wide_rr(&mut cpu, Opcode::Wmod, 3, 1, 2),
            Err(Trap::DivisionByZero)
        );
    }

    // ========== Task 0113a: WAND ==========

    #[test]
    fn wand_basic() {
        let mut cpu = fresh();
        cpu.write_wide(1, u256(0xFF00, 0xFF00, 0xFF00, 0xFF00));
        cpu.write_wide(2, u256(0x0FF0, 0x0FF0, 0x0FF0, 0x0FF0));
        exec_wide_rr(&mut cpu, Opcode::Wand, 3, 1, 2).unwrap();
        assert_eq!(
            cpu.read_wide(3),
            u256(0x0F00, 0x0F00, 0x0F00, 0x0F00)
        );
    }

    // ========== Task 0113b: WOR ==========

    #[test]
    fn wor_basic() {
        let mut cpu = fresh();
        cpu.write_wide(1, u256(0xFF00, 0, 0, 0));
        cpu.write_wide(2, u256(0x00FF, 0, 0, 0));
        exec_wide_rr(&mut cpu, Opcode::Wor, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_wide(3), u256(0xFFFF, 0, 0, 0));
    }

    // ========== Task 0113c: WXOR ==========

    #[test]
    fn wxor_self_is_zero() {
        let mut cpu = fresh();
        cpu.write_wide(1, u256(0xDEAD, 0xBEEF, 0xCAFE, 0xBABE));
        exec_wide_rr(&mut cpu, Opcode::Wxor, 3, 1, 1).unwrap();
        assert_eq!(cpu.read_wide(3), U256::ZERO);
    }

    // ========== Task 0113d: WNOT ==========

    #[test]
    fn wnot_zero_is_max() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::ZERO);
        exec_wide_rr(&mut cpu, Opcode::Wnot, 3, 1, 0).unwrap();
        assert_eq!(cpu.read_wide(3), U256::MAX);
    }

    #[test]
    fn wnot_involution() {
        let mut cpu = fresh();
        let val = u256(0xDEAD, 0xBEEF, 0xCAFE, 0xBABE);
        cpu.write_wide(1, val);
        exec_wide_rr(&mut cpu, Opcode::Wnot, 2, 1, 0).unwrap();
        exec_wide_rr(&mut cpu, Opcode::Wnot, 3, 2, 0).unwrap();
        assert_eq!(cpu.read_wide(3), val);
    }

    // ========== Task 0113: WMOV ==========

    #[test]
    fn wmov_basic() {
        let mut cpu = fresh();
        let val = u256(1, 2, 3, 4);
        cpu.write_wide(1, val);
        exec_wide_rr(&mut cpu, Opcode::Wmov, 3, 1, 0).unwrap();
        assert_eq!(cpu.read_wide(3), val);
    }

    // ========== Task 0116: NARROW ==========

    #[test]
    fn narrow_basic() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::from(42u64));
        // NARROW rd=3 (GP), ws1=1 (wide)
        exec_wide_rr(&mut cpu, Opcode::Narrow, 3, 1, 0).unwrap();
        assert_eq!(cpu.read_gp(3), 42);
    }

    #[test]
    fn narrow_max_u64() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::from(u64::MAX));
        exec_wide_rr(&mut cpu, Opcode::Narrow, 3, 1, 0).unwrap();
        assert_eq!(cpu.read_gp(3), u64::MAX);
    }

    #[test]
    fn narrow_overflow_traps() {
        let mut cpu = fresh();
        cpu.write_wide(1, u256(0, 1, 0, 0)); // > u64::MAX
        assert_eq!(
            exec_wide_rr(&mut cpu, Opcode::Narrow, 3, 1, 0),
            Err(Trap::NarrowOverflow)
        );
    }

    // ========== Task 0117: WIDEN ==========

    #[test]
    fn widen_basic() {
        let mut cpu = fresh();
        cpu.write_gp(1, 42);
        // WIDEN wd=3 (wide), rs1=1 (GP)
        exec_wide_rr(&mut cpu, Opcode::Widen, 3, 1, 0).unwrap();
        assert_eq!(cpu.read_wide(3), U256::from(42u64));
    }

    #[test]
    fn widen_max_u64() {
        let mut cpu = fresh();
        cpu.write_gp(1, u64::MAX);
        exec_wide_rr(&mut cpu, Opcode::Widen, 3, 1, 0).unwrap();
        assert_eq!(cpu.read_wide(3), U256::from(u64::MAX));
        // Upper bits should be zero
        assert_eq!(*cpu.read_wide(3).high(), 0u128);
    }

    // ========== Task 0118: Large values > 2^128 ==========

    #[test]
    fn wadd_large_values() {
        let mut cpu = fresh();
        cpu.write_wide(1, u256(0, 0, u64::MAX, 0));
        cpu.write_wide(2, u256(0, 0, 1, 0));
        exec_wide_rr(&mut cpu, Opcode::Wadd, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_wide(3), u256(0, 0, 0, 1));
    }

    #[test]
    fn wmul_large_values() {
        let mut cpu = fresh();
        // 2^192 * 2 = 2^193
        cpu.write_wide(1, u256(0, 0, 0, 1));
        cpu.write_wide(2, U256::from(2u64));
        exec_wide_rr(&mut cpu, Opcode::Wmul, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_wide(3), u256(0, 0, 0, 2));
    }

    // ========== Task 0119: Overflow detection ==========

    #[test]
    fn wadd_max_overflow() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::MAX);
        cpu.write_wide(2, U256::ONE);
        assert_eq!(
            exec_wide_rr(&mut cpu, Opcode::Wadd, 3, 1, 2),
            Err(Trap::Overflow)
        );
    }

    #[test]
    fn wsub_zero_underflow() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::ZERO);
        cpu.write_wide(2, U256::ONE);
        assert_eq!(
            exec_wide_rr(&mut cpu, Opcode::Wsub, 3, 1, 2),
            Err(Trap::Underflow)
        );
    }

    // ========== Task 0120: NARROW panics on > 64 bits ==========

    #[test]
    fn narrow_panics_all_limbs_set() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::MAX);
        assert_eq!(
            exec_wide_rr(&mut cpu, Opcode::Narrow, 3, 1, 0),
            Err(Trap::NarrowOverflow)
        );
    }

    // ========== Task 0121: WIDEN zero-extends ==========

    #[test]
    fn widen_zero_extends() {
        let mut cpu = fresh();
        cpu.write_gp(1, 0xDEADBEEFCAFEBABE);
        exec_wide_rr(&mut cpu, Opcode::Widen, 3, 1, 0).unwrap();
        let w = cpu.read_wide(3);
        assert_eq!(*w.low(), 0xDEADBEEFCAFEBABEu128);
        assert_eq!(*w.high(), 0u128);
    }

    // ========== Wide invalid opcode ==========

    #[test]
    fn wide_invalid_opcode_traps() {
        let mut cpu = fresh();
        let instr = crate::isa::encode(Opcode::Add, 0, 0, 0); // not a wide op
        assert_eq!(cpu.exec_wide(instr), Err(Trap::InvalidOpcode));
    }

    // ========== Task 0085: ADD ==========

    #[test]
    fn add_basic() {
        let mut cpu: Cpu = fresh();
        cpu.write_gp(1, 10);
        cpu.write_gp(2, 20);
        cpu.write_gp(3, 5);
        exec_rr(&mut cpu, Opcode::Add, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 30);
    }

    #[test]
    fn add_zero() {
        let mut cpu = fresh();
        cpu.write_gp(1, 42);
        cpu.write_gp(2, 0);
        exec_rr(&mut cpu, Opcode::Add, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 42);
    }

    // ========== Task 0086: SUB ==========

    #[test]
    fn sub_basic() {
        let mut cpu = fresh();
        cpu.write_gp(1, 50);
        cpu.write_gp(2, 20);
        exec_rr(&mut cpu, Opcode::Sub, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 30);
    }

    #[test]
    fn sub_to_zero() {
        let mut cpu = fresh();
        cpu.write_gp(1, 100);
        cpu.write_gp(2, 100);
        exec_rr(&mut cpu, Opcode::Sub, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    // ========== Task 0087: MUL ==========

    #[test]
    fn mul_basic() {
        let mut cpu = fresh();
        cpu.write_gp(1, 7);
        cpu.write_gp(2, 6);
        exec_rr(&mut cpu, Opcode::Mul, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 42);
    }

    #[test]
    fn mul_by_zero() {
        let mut cpu = fresh();
        cpu.write_gp(1, u64::MAX);
        cpu.write_gp(2, 0);
        exec_rr(&mut cpu, Opcode::Mul, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    #[test]
    fn mul_by_one() {
        let mut cpu = fresh();
        cpu.write_gp(1, 999);
        cpu.write_gp(2, 1);
        exec_rr(&mut cpu, Opcode::Mul, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 999);
    }

    // ========== Task 0088: DIV ==========

    #[test]
    fn div_basic() {
        let mut cpu = fresh();
        cpu.write_gp(1, 42);
        cpu.write_gp(2, 7);
        exec_rr(&mut cpu, Opcode::Div, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 6);
    }

    #[test]
    fn div_truncates() {
        let mut cpu = fresh();
        cpu.write_gp(1, 10);
        cpu.write_gp(2, 3);
        exec_rr(&mut cpu, Opcode::Div, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 3);
    }

    // ========== Task 0089: MOD ==========

    #[test]
    fn mod_basic() {
        let mut cpu = fresh();
        cpu.write_gp(1, 10);
        cpu.write_gp(2, 3);
        exec_rr(&mut cpu, Opcode::Mod, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    #[test]
    fn mod_exact_divisor() {
        let mut cpu = fresh();
        cpu.write_gp(1, 42);
        cpu.write_gp(2, 7);
        exec_rr(&mut cpu, Opcode::Mod, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    // ========== Task 0090: ADDI ==========

    #[test]
    fn addi_positive() {
        let mut cpu = fresh();
        cpu.write_gp(1, 100);
        exec_ri(&mut cpu, Opcode::Addi, 3, 1, 50).unwrap();
        assert_eq!(cpu.read_gp(3), 150);
    }

    #[test]
    fn addi_negative() {
        let mut cpu = fresh();
        cpu.write_gp(1, 100);
        exec_ri(&mut cpu, Opcode::Addi, 3, 1, -30).unwrap();
        assert_eq!(cpu.read_gp(3), 70);
    }

    #[test]
    fn addi_max_immediate() {
        let mut cpu = fresh();
        cpu.write_gp(1, 0);
        exec_ri(&mut cpu, Opcode::Addi, 3, 1, 131071).unwrap();
        assert_eq!(cpu.read_gp(3), 131071);
    }

    #[test]
    fn addi_min_immediate() {
        let mut cpu = fresh();
        cpu.write_gp(1, 200000);
        exec_ri(&mut cpu, Opcode::Addi, 3, 1, -131072).unwrap();
        assert_eq!(cpu.read_gp(3), 200000 - 131072);
    }

    // ========== Task 0091: AND ==========

    #[test]
    fn and_basic() {
        let mut cpu = fresh();
        cpu.write_gp(1, 0xFF00);
        cpu.write_gp(2, 0x0FF0);
        exec_rr(&mut cpu, Opcode::And, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0x0F00);
    }

    // ========== Task 0092: OR ==========

    #[test]
    fn or_basic() {
        let mut cpu = fresh();
        cpu.write_gp(1, 0xFF00);
        cpu.write_gp(2, 0x00FF);
        exec_rr(&mut cpu, Opcode::Or, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0xFFFF);
    }

    // ========== Task 0093: XOR ==========

    #[test]
    fn xor_basic() {
        let mut cpu = fresh();
        cpu.write_gp(1, 0xAAAA);
        cpu.write_gp(2, 0xFFFF);
        exec_rr(&mut cpu, Opcode::Xor, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0x5555);
    }

    #[test]
    fn xor_self_is_zero() {
        let mut cpu = fresh();
        cpu.write_gp(1, 12345);
        exec_rr(&mut cpu, Opcode::Xor, 3, 1, 1).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    // ========== Task 0094: NOT ==========

    #[test]
    fn not_basic() {
        let mut cpu = fresh();
        cpu.write_gp(1, 0);
        exec_rr(&mut cpu, Opcode::Not, 3, 1, 0).unwrap();
        assert_eq!(cpu.read_gp(3), u64::MAX);
    }

    #[test]
    fn not_inverse() {
        let mut cpu = fresh();
        cpu.write_gp(1, 0xDEADBEEF);
        exec_rr(&mut cpu, Opcode::Not, 3, 1, 0).unwrap();
        assert_eq!(cpu.read_gp(3), !0xDEADBEEFu64);
    }

    // ========== Task 0095: SHL ==========

    #[test]
    fn shl_basic() {
        let mut cpu = fresh();
        cpu.write_gp(1, 1);
        cpu.write_gp(2, 10);
        exec_rr(&mut cpu, Opcode::Shl, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1024);
    }

    // ========== Task 0096: SHR ==========

    #[test]
    fn shr_basic() {
        let mut cpu = fresh();
        cpu.write_gp(1, 1024);
        cpu.write_gp(2, 10);
        exec_rr(&mut cpu, Opcode::Shr, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    #[test]
    fn shr_high_bit_not_extended() {
        let mut cpu = fresh();
        cpu.write_gp(1, u64::MAX); // all bits set
        cpu.write_gp(2, 32);
        exec_rr(&mut cpu, Opcode::Shr, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0xFFFFFFFF); // top 32 bits zeroed
    }

    // ========== Task 0097: SAR ==========

    #[test]
    fn sar_positive() {
        let mut cpu = fresh();
        cpu.write_gp(1, 1024);
        cpu.write_gp(2, 5);
        exec_rr(&mut cpu, Opcode::Sar, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 32);
    }

    #[test]
    fn sar_negative_extends_sign() {
        let mut cpu = fresh();
        cpu.write_gp(1, (-1024i64) as u64);
        cpu.write_gp(2, 5);
        exec_rr(&mut cpu, Opcode::Sar, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3) as i64, -32);
    }

    // ========== Task 0098: LT ==========

    #[test]
    fn lt_true() {
        let mut cpu = fresh();
        cpu.write_gp(1, 5);
        cpu.write_gp(2, 10);
        exec_rr(&mut cpu, Opcode::Lt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    #[test]
    fn lt_false() {
        let mut cpu = fresh();
        cpu.write_gp(1, 10);
        cpu.write_gp(2, 5);
        exec_rr(&mut cpu, Opcode::Lt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    #[test]
    fn lt_equal() {
        let mut cpu = fresh();
        cpu.write_gp(1, 5);
        cpu.write_gp(2, 5);
        exec_rr(&mut cpu, Opcode::Lt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    // ========== Task 0099: GT ==========

    #[test]
    fn gt_true() {
        let mut cpu = fresh();
        cpu.write_gp(1, 10);
        cpu.write_gp(2, 5);
        exec_rr(&mut cpu, Opcode::Gt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    #[test]
    fn gt_false() {
        let mut cpu = fresh();
        cpu.write_gp(1, 5);
        cpu.write_gp(2, 10);
        exec_rr(&mut cpu, Opcode::Gt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    // ========== Task 0100: EQ ==========

    #[test]
    fn eq_true() {
        let mut cpu = fresh();
        cpu.write_gp(1, 42);
        cpu.write_gp(2, 42);
        exec_rr(&mut cpu, Opcode::Eq, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    #[test]
    fn eq_false() {
        let mut cpu = fresh();
        cpu.write_gp(1, 42);
        cpu.write_gp(2, 43);
        exec_rr(&mut cpu, Opcode::Eq, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    // ========== Task 0101: SLT (signed less-than) ==========

    #[test]
    fn slt_negative_vs_positive() {
        let mut cpu = fresh();
        cpu.write_gp(1, (-5i64) as u64);
        cpu.write_gp(2, 5);
        exec_rr(&mut cpu, Opcode::Slt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    #[test]
    fn slt_positive_vs_negative() {
        let mut cpu = fresh();
        cpu.write_gp(1, 5);
        cpu.write_gp(2, (-5i64) as u64);
        exec_rr(&mut cpu, Opcode::Slt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    #[test]
    fn slt_both_negative() {
        let mut cpu = fresh();
        cpu.write_gp(1, (-10i64) as u64);
        cpu.write_gp(2, (-5i64) as u64);
        exec_rr(&mut cpu, Opcode::Slt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1); // -10 < -5
    }

    // ========== Task 0102: SGT (signed greater-than) ==========

    #[test]
    fn sgt_positive_vs_negative() {
        let mut cpu = fresh();
        cpu.write_gp(1, 5);
        cpu.write_gp(2, (-5i64) as u64);
        exec_rr(&mut cpu, Opcode::Sgt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    #[test]
    fn sgt_negative_vs_positive() {
        let mut cpu = fresh();
        cpu.write_gp(1, (-5i64) as u64);
        cpu.write_gp(2, 5);
        exec_rr(&mut cpu, Opcode::Sgt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    // ========== Task 0103: Boundary values ==========

    #[test]
    fn add_boundary_max_plus_zero() {
        let mut cpu = fresh();
        cpu.write_gp(1, u64::MAX);
        cpu.write_gp(2, 0);
        exec_rr(&mut cpu, Opcode::Add, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), u64::MAX);
    }

    #[test]
    fn add_boundary_max_minus_one_plus_one() {
        let mut cpu = fresh();
        cpu.write_gp(1, u64::MAX - 1);
        cpu.write_gp(2, 1);
        exec_rr(&mut cpu, Opcode::Add, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), u64::MAX);
    }

    #[test]
    fn sub_boundary_zero_minus_zero() {
        let mut cpu = fresh();
        cpu.write_gp(1, 0);
        cpu.write_gp(2, 0);
        exec_rr(&mut cpu, Opcode::Sub, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    #[test]
    fn mul_boundary_max_times_one() {
        let mut cpu = fresh();
        cpu.write_gp(1, u64::MAX);
        cpu.write_gp(2, 1);
        exec_rr(&mut cpu, Opcode::Mul, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), u64::MAX);
    }

    #[test]
    fn div_boundary_max_div_max() {
        let mut cpu = fresh();
        cpu.write_gp(1, u64::MAX);
        cpu.write_gp(2, u64::MAX);
        exec_rr(&mut cpu, Opcode::Div, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    #[test]
    fn lt_boundary_zero_vs_max() {
        let mut cpu = fresh();
        cpu.write_gp(1, 0);
        cpu.write_gp(2, u64::MAX);
        exec_rr(&mut cpu, Opcode::Lt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    #[test]
    fn eq_boundary_max_vs_max() {
        let mut cpu = fresh();
        cpu.write_gp(1, u64::MAX);
        cpu.write_gp(2, u64::MAX);
        exec_rr(&mut cpu, Opcode::Eq, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    // ========== Task 0104: Overflow detection ==========

    #[test]
    fn add_overflow_traps() {
        let mut cpu = fresh();
        cpu.write_gp(1, u64::MAX);
        cpu.write_gp(2, 1);
        assert_eq!(exec_rr(&mut cpu, Opcode::Add, 3, 1, 2), Err(Trap::Overflow));
    }

    #[test]
    fn sub_underflow_traps() {
        let mut cpu = fresh();
        cpu.write_gp(1, 0);
        cpu.write_gp(2, 1);
        assert_eq!(
            exec_rr(&mut cpu, Opcode::Sub, 3, 1, 2),
            Err(Trap::Underflow)
        );
    }

    #[test]
    fn mul_overflow_traps() {
        let mut cpu = fresh();
        cpu.write_gp(1, u64::MAX);
        cpu.write_gp(2, 2);
        assert_eq!(exec_rr(&mut cpu, Opcode::Mul, 3, 1, 2), Err(Trap::Overflow));
    }

    #[test]
    fn mul_large_overflow_traps() {
        let mut cpu = fresh();
        cpu.write_gp(1, 1u64 << 32);
        cpu.write_gp(2, 1u64 << 33);
        assert_eq!(exec_rr(&mut cpu, Opcode::Mul, 3, 1, 2), Err(Trap::Overflow));
    }

    // ========== Task 0105: Division by zero ==========

    #[test]
    fn div_by_zero_traps() {
        let mut cpu = fresh();
        cpu.write_gp(1, 42);
        cpu.write_gp(2, 0);
        assert_eq!(
            exec_rr(&mut cpu, Opcode::Div, 3, 1, 2),
            Err(Trap::DivisionByZero)
        );
    }

    #[test]
    fn mod_by_zero_traps() {
        let mut cpu = fresh();
        cpu.write_gp(1, 42);
        cpu.write_gp(2, 0);
        assert_eq!(
            exec_rr(&mut cpu, Opcode::Mod, 3, 1, 2),
            Err(Trap::DivisionByZero)
        );
    }

    // ========== Task 0106: Shift boundary values ==========

    #[test]
    fn shl_by_zero() {
        let mut cpu = fresh();
        cpu.write_gp(1, 0xABCD);
        cpu.write_gp(2, 0);
        exec_rr(&mut cpu, Opcode::Shl, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0xABCD);
    }

    #[test]
    fn shl_by_one() {
        let mut cpu = fresh();
        cpu.write_gp(1, 1);
        cpu.write_gp(2, 1);
        exec_rr(&mut cpu, Opcode::Shl, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 2);
    }

    #[test]
    fn shl_by_63() {
        let mut cpu = fresh();
        cpu.write_gp(1, 1);
        cpu.write_gp(2, 63);
        exec_rr(&mut cpu, Opcode::Shl, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1u64 << 63);
    }

    #[test]
    fn shl_by_64_is_zero() {
        let mut cpu = fresh();
        cpu.write_gp(1, u64::MAX);
        cpu.write_gp(2, 64);
        exec_rr(&mut cpu, Opcode::Shl, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    #[test]
    fn shr_by_zero() {
        let mut cpu = fresh();
        cpu.write_gp(1, 0xABCD);
        cpu.write_gp(2, 0);
        exec_rr(&mut cpu, Opcode::Shr, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0xABCD);
    }

    #[test]
    fn shr_by_63() {
        let mut cpu = fresh();
        cpu.write_gp(1, 1u64 << 63);
        cpu.write_gp(2, 63);
        exec_rr(&mut cpu, Opcode::Shr, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    #[test]
    fn shr_by_64_is_zero() {
        let mut cpu = fresh();
        cpu.write_gp(1, u64::MAX);
        cpu.write_gp(2, 64);
        exec_rr(&mut cpu, Opcode::Shr, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    #[test]
    fn sar_by_63_negative() {
        let mut cpu = fresh();
        cpu.write_gp(1, (-1i64) as u64); // all bits set
        cpu.write_gp(2, 63);
        exec_rr(&mut cpu, Opcode::Sar, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3) as i64, -1); // sign preserved
    }

    #[test]
    fn sar_by_64_negative() {
        let mut cpu = fresh();
        cpu.write_gp(1, (-100i64) as u64);
        cpu.write_gp(2, 64);
        exec_rr(&mut cpu, Opcode::Sar, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3) as i64, -1); // all sign bits
    }

    #[test]
    fn sar_by_64_positive() {
        let mut cpu = fresh();
        cpu.write_gp(1, 100);
        cpu.write_gp(2, 64);
        exec_rr(&mut cpu, Opcode::Sar, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    // ========== Task 0107: Signed comparison correctness ==========

    #[test]
    fn slt_min_vs_max() {
        let mut cpu = fresh();
        cpu.write_gp(1, i64::MIN as u64);
        cpu.write_gp(2, i64::MAX as u64);
        exec_rr(&mut cpu, Opcode::Slt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    #[test]
    fn sgt_max_vs_min() {
        let mut cpu = fresh();
        cpu.write_gp(1, i64::MAX as u64);
        cpu.write_gp(2, i64::MIN as u64);
        exec_rr(&mut cpu, Opcode::Sgt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    #[test]
    fn slt_unsigned_max_is_negative_one() {
        // u64::MAX is -1 in signed, so SLT(MAX, 0) should be true
        let mut cpu = fresh();
        cpu.write_gp(1, u64::MAX); // -1 as signed
        cpu.write_gp(2, 0);
        exec_rr(&mut cpu, Opcode::Slt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1); // -1 < 0
    }

    #[test]
    fn lt_unsigned_max_is_largest() {
        // Unsigned: MAX > 0
        let mut cpu = fresh();
        cpu.write_gp(1, u64::MAX);
        cpu.write_gp(2, 0);
        exec_rr(&mut cpu, Opcode::Lt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0); // MAX is not < 0 unsigned
    }

    #[test]
    fn signed_vs_unsigned_differ() {
        // u64::MAX is unsigned-largest but signed -1
        let mut cpu = fresh();
        cpu.write_gp(1, u64::MAX);
        cpu.write_gp(2, 1);

        // Unsigned: MAX > 1
        exec_rr(&mut cpu, Opcode::Gt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);

        // Signed: -1 < 1
        exec_rr(&mut cpu, Opcode::Slt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    // ========== r0 hardwired zero ==========

    #[test]
    fn r0_always_zero() {
        let mut cpu = fresh();
        cpu.write_gp(0, 9999); // write is discarded
        assert_eq!(cpu.read_gp(0), 0);
    }

    #[test]
    fn write_to_r0_discarded() {
        let mut cpu = fresh();
        cpu.write_gp(1, 10);
        cpu.write_gp(2, 20);
        // ADD r0, r1, r2 — result should be discarded
        exec_rr(&mut cpu, Opcode::Add, 0, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(0), 0);
    }

    // ========== Wide comparisons (WEQ, WLT) ==========

    #[test]
    fn weq_equal() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::from(42u64));
        cpu.write_wide(2, U256::from(42u64));
        exec_wide_rr(&mut cpu, Opcode::Weq, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    #[test]
    fn weq_not_equal() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::from(42u64));
        cpu.write_wide(2, U256::from(43u64));
        exec_wide_rr(&mut cpu, Opcode::Weq, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    #[test]
    fn weq_large_values() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::MAX);
        cpu.write_wide(2, U256::MAX);
        exec_wide_rr(&mut cpu, Opcode::Weq, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    #[test]
    fn wlt_true() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::from(100u64));
        cpu.write_wide(2, U256::from(200u64));
        exec_wide_rr(&mut cpu, Opcode::Wlt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    #[test]
    fn wlt_false() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::from(200u64));
        cpu.write_wide(2, U256::from(100u64));
        exec_wide_rr(&mut cpu, Opcode::Wlt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    #[test]
    fn wlt_equal_is_false() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::from(42u64));
        cpu.write_wide(2, U256::from(42u64));
        exec_wide_rr(&mut cpu, Opcode::Wlt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 0);
    }

    #[test]
    fn wlt_large_values() {
        let mut cpu = fresh();
        cpu.write_wide(1, U256::MAX - U256::ONE);
        cpu.write_wide(2, U256::MAX);
        exec_wide_rr(&mut cpu, Opcode::Wlt, 3, 1, 2).unwrap();
        assert_eq!(cpu.read_gp(3), 1);
    }

    // ========== Invalid opcode ==========

    #[test]
    fn invalid_opcode_traps() {
        let mut cpu = fresh();
        let instr = crate::isa::encode(Opcode::Halt, 0, 0, 0);
        assert_eq!(cpu.exec_alu(instr), Err(Trap::InvalidOpcode));
    }
}
