//! Memory conventions for codegen — re-exports PVM constants
//! and defines Otigen-specific layout conventions.

// Re-export PVM memory layout constants (single source of truth)
pub use pyde_vm::memory::{HEAP_START, STACK_TOP, CODE_START};

/// Size of a u64 value in bytes.
pub const WORD_SIZE: u32 = 8;
/// Size of a u256 value in bytes.
pub const WIDE_SIZE: u32 = 32;

/// Vec/String/bytes header layout in heap.
pub const VEC_LENGTH_OFFSET: u32 = 0;
pub const VEC_CAPACITY_OFFSET: u32 = 8;
pub const VEC_DATA_OFFSET: u32 = 16;

/// Reserved GP registers (codegen convention).
pub const REG_ZERO: u8 = 0;
pub const REG_RETURN: u8 = 1;
pub const REG_HEAP_PTR: u8 = 12;
pub const REG_SCRATCH_0: u8 = 14;
pub const REG_SCRATCH_1: u8 = 15;
