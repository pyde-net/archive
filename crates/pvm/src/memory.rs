//! PVM linear memory: 4 MB address space with lazy page allocation and gas metering.

use crate::cpu::Trap;
use thiserror::Error;

// --- Memory layout constants (Task 0122) ---

/// Total address space: 4 MB.
pub const MEMORY_SIZE: usize = 4 * 1024 * 1024; // 0x400000

/// Page size: 4 KB.
pub const PAGE_SIZE: usize = 4096;

/// Total number of pages.
pub const PAGE_COUNT: usize = MEMORY_SIZE / PAGE_SIZE; // 1024

/// Null page: 0x000000 - 0x000FFF (4 KB). Traps on any access.
pub const NULL_PAGE_END: u32 = 0x001000;

/// Code section: 0x001000 - 0x00FFFF (up to 64 KB). Read-only during execution.
pub const CODE_START: u32 = 0x001000;
pub const CODE_END: u32 = 0x010000;

/// Heap starts at 0x010000, grows upward.
pub const HEAP_START: u32 = 0x010000;

/// Stack starts at top of memory (0x3FFFFF), grows downward.
pub const STACK_TOP: u32 = MEMORY_SIZE as u32; // 0x400000 (exclusive)

/// Gas cost for first access to a new 4 KB page.
pub const PAGE_ALLOC_GAS: u64 = 200;

/// Memory access errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum MemoryError {
    #[error("null page access at 0x{0:06x}")]
    NullPageAccess(u32),
    #[error("out of bounds access at 0x{0:06x}")]
    OutOfBounds(u32),
    #[error("write to read-only code section at 0x{0:06x}")]
    CodeWriteProtected(u32),
    #[error("heap-stack collision")]
    HeapStackCollision,
}

impl From<MemoryError> for Trap {
    fn from(e: MemoryError) -> Self {
        match e {
            MemoryError::NullPageAccess(_) => Trap::MemoryFault,
            MemoryError::OutOfBounds(_) => Trap::MemoryFault,
            MemoryError::CodeWriteProtected(_) => Trap::MemoryFault,
            MemoryError::HeapStackCollision => Trap::MemoryFault,
        }
    }
}

/// A single 4 KB page, heap-allocated on first touch.
type Page = Box<[u8; PAGE_SIZE]>;

/// 4 MB linear memory with lazy page allocation and gas metering.
///
/// Pages are allocated on first touch instead of eagerly allocating 4 MB.
/// Reads from untouched pages return zero (same semantic as before).
pub struct Memory {
    /// Lazily-allocated pages. `None` = untouched (reads return zero).
    pages: Vec<Option<Page>>,
    /// Which pages have been accessed (for gas metering).
    pages_touched: [bool; PAGE_COUNT],
    /// Total gas charged for page allocations.
    pub page_gas_used: u64,
    /// Current heap top (grows upward from HEAP_START).
    pub heap_top: u32,
    /// Current stack pointer (grows downward from STACK_TOP).
    pub stack_pointer: u32,
    /// End of loaded code (within code section).
    pub code_end: u32,
}

impl Memory {
    pub fn new() -> Self {
        let mut pages = Vec::with_capacity(PAGE_COUNT);
        for _ in 0..PAGE_COUNT {
            pages.push(None);
        }
        Self {
            pages,
            pages_touched: [false; PAGE_COUNT],
            page_gas_used: 0,
            heap_top: HEAP_START,
            stack_pointer: STACK_TOP,
            code_end: CODE_START,
        }
    }

    /// Ensure a page is physically allocated. Returns a mutable reference to the page data.
    #[inline]
    fn ensure_page(&mut self, page_idx: usize) -> &mut [u8; PAGE_SIZE] {
        let page = self.pages[page_idx].get_or_insert_with(|| Box::new([0u8; PAGE_SIZE]));
        page
    }

    /// Read a byte from a page (returns 0 if page not materialized).
    #[inline]
    fn read_byte(&self, addr: u32) -> u8 {
        let page_idx = addr as usize / PAGE_SIZE;
        let offset = addr as usize % PAGE_SIZE;
        match &self.pages[page_idx] {
            Some(page) => page[offset],
            None => 0,
        }
    }

    /// Write a byte, materializing the page if needed.
    #[inline]
    fn write_byte(&mut self, addr: u32, val: u8) {
        let page_idx = addr as usize / PAGE_SIZE;
        let offset = addr as usize % PAGE_SIZE;
        let page = self.ensure_page(page_idx);
        page[offset] = val;
    }

    /// Read a contiguous slice of bytes into a buffer.
    fn read_bytes(&self, addr: u32, buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = self.read_byte(addr + i as u32);
        }
    }

    /// Write a contiguous slice of bytes, materializing pages as needed.
    fn write_bytes(&mut self, addr: u32, data: &[u8]) {
        for (i, &b) in data.iter().enumerate() {
            self.write_byte(addr + i as u32, b);
        }
    }

    /// Load bytecode into the code section.
    pub fn load_code(&mut self, bytecode: &[u8]) -> Result<(), MemoryError> {
        let end = CODE_START as usize + bytecode.len();
        if end > CODE_END as usize {
            return Err(MemoryError::OutOfBounds(end as u32));
        }
        // Materialize code pages and copy bytecode
        self.write_bytes(CODE_START, bytecode);
        self.code_end = end as u32;
        Ok(())
    }

    /// Check address validity and charge page gas if needed.
    fn check_access(&mut self, addr: u32, len: u32) -> Result<(), MemoryError> {
        // Null page trap
        if addr < NULL_PAGE_END {
            return Err(MemoryError::NullPageAccess(addr));
        }

        // Bounds check
        let end = addr
            .checked_add(len)
            .ok_or(MemoryError::OutOfBounds(addr))?;
        if end > MEMORY_SIZE as u32 {
            return Err(MemoryError::OutOfBounds(addr));
        }

        // Charge page gas for each new page touched
        let first_page = addr as usize / PAGE_SIZE;
        let last_page = (end as usize - 1) / PAGE_SIZE;
        for page in first_page..=last_page {
            if !self.pages_touched[page] {
                self.pages_touched[page] = true;
                self.page_gas_used += PAGE_ALLOC_GAS;
            }
        }

        Ok(())
    }

    /// Check that the address is not in the code section (for writes).
    fn check_writable(&self, addr: u32) -> Result<(), MemoryError> {
        if (CODE_START..CODE_END).contains(&addr) {
            return Err(MemoryError::CodeWriteProtected(addr));
        }
        Ok(())
    }

    /// Grow the heap by `bytes` bytes. Returns the old heap_top (start of allocation).
    pub fn heap_alloc(&mut self, bytes: u32) -> Result<u32, MemoryError> {
        let new_top = self
            .heap_top
            .checked_add(bytes)
            .ok_or(MemoryError::OutOfBounds(self.heap_top))?;
        if new_top > self.stack_pointer {
            return Err(MemoryError::HeapStackCollision);
        }
        let old_top = self.heap_top;
        self.heap_top = new_top;
        Ok(old_top)
    }

    /// Push to stack (decrement SP). Returns new SP.
    pub fn stack_alloc(&mut self, bytes: u32) -> Result<u32, MemoryError> {
        let new_sp = self
            .stack_pointer
            .checked_sub(bytes)
            .ok_or(MemoryError::HeapStackCollision)?;
        if new_sp < self.heap_top {
            return Err(MemoryError::HeapStackCollision);
        }
        self.stack_pointer = new_sp;
        Ok(new_sp)
    }

    /// Read a contiguous byte range from memory.
    pub fn load_bytes(&self, addr: usize, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| self.read_byte((addr + i) as u32))
            .collect()
    }

    // --- Byte-level load/store ---

    pub fn load8(&mut self, addr: u32) -> Result<u8, MemoryError> {
        self.check_access(addr, 1)?;
        Ok(self.read_byte(addr))
    }

    pub fn store8(&mut self, addr: u32, val: u8) -> Result<(), MemoryError> {
        self.check_access(addr, 1)?;
        self.check_writable(addr)?;
        self.write_byte(addr, val);
        Ok(())
    }

    // --- 16-bit load/store (little-endian) ---

    pub fn load16(&mut self, addr: u32) -> Result<u16, MemoryError> {
        self.check_access(addr, 2)?;
        let mut buf = [0u8; 2];
        self.read_bytes(addr, &mut buf);
        Ok(u16::from_le_bytes(buf))
    }

    pub fn store16(&mut self, addr: u32, val: u16) -> Result<(), MemoryError> {
        self.check_access(addr, 2)?;
        self.check_writable(addr)?;
        self.write_bytes(addr, &val.to_le_bytes());
        Ok(())
    }

    // --- 32-bit load/store (little-endian) ---

    pub fn load32(&mut self, addr: u32) -> Result<u32, MemoryError> {
        self.check_access(addr, 4)?;
        let mut buf = [0u8; 4];
        self.read_bytes(addr, &mut buf);
        Ok(u32::from_le_bytes(buf))
    }

    pub fn store32(&mut self, addr: u32, val: u32) -> Result<(), MemoryError> {
        self.check_access(addr, 4)?;
        self.check_writable(addr)?;
        self.write_bytes(addr, &val.to_le_bytes());
        Ok(())
    }

    // --- 64-bit load/store (little-endian) ---

    pub fn load64(&mut self, addr: u32) -> Result<u64, MemoryError> {
        self.check_access(addr, 8)?;
        let mut buf = [0u8; 8];
        self.read_bytes(addr, &mut buf);
        Ok(u64::from_le_bytes(buf))
    }

    pub fn store64(&mut self, addr: u32, val: u64) -> Result<(), MemoryError> {
        self.check_access(addr, 8)?;
        self.check_writable(addr)?;
        self.write_bytes(addr, &val.to_le_bytes());
        Ok(())
    }

    // --- 256-bit load/store (little-endian, for WLOAD/WSTORE) ---

    pub fn load256(&mut self, addr: u32) -> Result<[u8; 32], MemoryError> {
        self.check_access(addr, 32)?;
        let mut buf = [0u8; 32];
        self.read_bytes(addr, &mut buf);
        Ok(buf)
    }

    pub fn store256(&mut self, addr: u32, val: &[u8; 32]) -> Result<(), MemoryError> {
        self.check_access(addr, 32)?;
        self.check_writable(addr)?;
        self.write_bytes(addr, val);
        Ok(())
    }

    /// Immutable reference to a contiguous slice of memory.
    /// For ranges that span unmaterialized pages, this allocates a temporary buffer.
    pub fn read_slice(&self, addr: u32, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        self.read_bytes(addr, &mut buf);
        buf
    }

    /// Read a slice with access checking and gas metering (single check for the range).
    pub fn checked_read_slice(&mut self, addr: u32, len: usize) -> Result<Vec<u8>, MemoryError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        self.check_access(addr, len as u32)?;
        Ok(self.read_slice(addr, len))
    }

    /// Write a slice with access checking, writable check, and gas metering (single check).
    pub fn checked_write_slice(&mut self, addr: u32, data: &[u8]) -> Result<(), MemoryError> {
        if data.is_empty() {
            return Ok(());
        }
        self.check_access(addr, data.len() as u32)?;
        self.check_writable(addr)?;
        self.write_bytes(addr, data);
        Ok(())
    }

    /// Read a 32-bit instruction word from the code section (no gas charge).
    /// Code pages are always materialized by `load_code()`.
    #[inline]
    pub fn fetch_code_u32(&self, addr: u32) -> u32 {
        let mut buf = [0u8; 4];
        buf[0] = self.read_byte(addr);
        buf[1] = self.read_byte(addr + 1);
        buf[2] = self.read_byte(addr + 2);
        buf[3] = self.read_byte(addr + 3);
        u32::from_le_bytes(buf)
    }

    /// How many pages have been touched.
    pub fn pages_allocated(&self) -> usize {
        self.pages_touched.iter().filter(|&&t| t).count()
    }

    /// How many pages are physically materialized (have backing memory).
    pub fn pages_materialized(&self) -> usize {
        self.pages.iter().filter(|p| p.is_some()).count()
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Memory {
        Memory::new()
    }

    // ========== Task 0122: Layout constants ==========

    #[test]
    fn layout_constants() {
        assert_eq!(MEMORY_SIZE, 0x400000);
        assert_eq!(PAGE_SIZE, 4096);
        assert_eq!(PAGE_COUNT, 1024);
        assert_eq!(NULL_PAGE_END, 0x1000);
        assert_eq!(CODE_START, 0x1000);
        assert_eq!(CODE_END, 0x10000);
        assert_eq!(HEAP_START, 0x10000);
        assert_eq!(STACK_TOP, 0x400000);
    }

    // ========== Task 0123: Memory struct ==========

    #[test]
    fn new_memory_is_zeroed() {
        let m = mem();
        assert_eq!(m.heap_top, HEAP_START);
        assert_eq!(m.stack_pointer, STACK_TOP);
        assert_eq!(m.page_gas_used, 0);
    }

    // ========== Task 0124: Page tracking ==========

    #[test]
    fn first_access_charges_page_gas() {
        let mut m = mem();
        m.load64(HEAP_START).unwrap();
        assert_eq!(m.page_gas_used, PAGE_ALLOC_GAS);
    }

    #[test]
    fn second_access_same_page_no_extra_gas() {
        let mut m = mem();
        m.load64(HEAP_START).unwrap();
        m.load64(HEAP_START + 8).unwrap();
        assert_eq!(m.page_gas_used, PAGE_ALLOC_GAS); // still just one page
    }

    #[test]
    fn access_two_pages_charges_twice() {
        let mut m = mem();
        m.load64(HEAP_START).unwrap(); // page N
        m.load64(HEAP_START + PAGE_SIZE as u32).unwrap(); // page N+1
        assert_eq!(m.page_gas_used, PAGE_ALLOC_GAS * 2);
    }

    // ========== Task 0125-0128: LOAD 8/16/32/64 ==========

    #[test]
    fn load_store_8() {
        let mut m = mem();
        m.store8(HEAP_START, 0xAB).unwrap();
        assert_eq!(m.load8(HEAP_START).unwrap(), 0xAB);
    }

    #[test]
    fn load_store_16() {
        let mut m = mem();
        m.store16(HEAP_START, 0xBEEF).unwrap();
        assert_eq!(m.load16(HEAP_START).unwrap(), 0xBEEF);
    }

    #[test]
    fn load_store_32() {
        let mut m = mem();
        m.store32(HEAP_START, 0xDEADBEEF).unwrap();
        assert_eq!(m.load32(HEAP_START).unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn load_store_64() {
        let mut m = mem();
        m.store64(HEAP_START, 0xDEADBEEFCAFEBABE).unwrap();
        assert_eq!(m.load64(HEAP_START).unwrap(), 0xDEADBEEFCAFEBABE);
    }

    #[test]
    fn load_store_256() {
        let mut m = mem();
        let val = [0xABu8; 32];
        m.store256(HEAP_START, &val).unwrap();
        assert_eq!(m.load256(HEAP_START).unwrap(), val);
    }

    #[test]
    fn little_endian_byte_order() {
        let mut m = mem();
        m.store64(HEAP_START, 0x0102030405060708).unwrap();
        // Little-endian: lowest byte at lowest address
        assert_eq!(m.load8(HEAP_START).unwrap(), 0x08);
        assert_eq!(m.load8(HEAP_START + 7).unwrap(), 0x01);
    }

    // ========== Task 0133: Null page trap ==========

    #[test]
    fn null_page_read_traps() {
        let mut m = mem();
        assert_eq!(m.load8(0), Err(MemoryError::NullPageAccess(0)));
        assert_eq!(m.load64(0x800), Err(MemoryError::NullPageAccess(0x800)));
        assert_eq!(m.load8(0xFFF), Err(MemoryError::NullPageAccess(0xFFF)));
    }

    #[test]
    fn null_page_write_traps() {
        let mut m = mem();
        assert_eq!(m.store8(0, 42), Err(MemoryError::NullPageAccess(0)));
    }

    // ========== Task 0134: Code section read-only ==========

    #[test]
    fn code_section_read_ok() {
        let mut m = mem();
        m.load_code(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        assert_eq!(m.load8(CODE_START).unwrap(), 0x01);
        assert_eq!(m.load8(CODE_START + 3).unwrap(), 0x04);
    }

    #[test]
    fn code_section_write_traps() {
        let mut m = mem();
        assert_eq!(
            m.store8(CODE_START, 0xFF),
            Err(MemoryError::CodeWriteProtected(CODE_START))
        );
        assert_eq!(
            m.store64(CODE_START + 100, 0),
            Err(MemoryError::CodeWriteProtected(CODE_START + 100))
        );
    }

    #[test]
    fn load_code_too_large() {
        let mut m = mem();
        let big = vec![0u8; 65536]; // exactly 64 KB — should fail (code section is 60 KB)
                                    // CODE_START=0x1000, CODE_END=0x10000, so max code = 0xF000 = 61440
        assert!(m.load_code(&big).is_err());
    }

    // ========== Task 0135: Heap growth ==========

    #[test]
    fn heap_alloc_grows_upward() {
        let mut m = mem();
        assert_eq!(m.heap_top, HEAP_START);
        let ptr = m.heap_alloc(1024).unwrap();
        assert_eq!(ptr, HEAP_START);
        assert_eq!(m.heap_top, HEAP_START + 1024);
    }

    #[test]
    fn heap_alloc_sequential() {
        let mut m = mem();
        let p1 = m.heap_alloc(100).unwrap();
        let p2 = m.heap_alloc(200).unwrap();
        assert_eq!(p1, HEAP_START);
        assert_eq!(p2, HEAP_START + 100);
        assert_eq!(m.heap_top, HEAP_START + 300);
    }

    // ========== Task 0136: Stack growth ==========

    #[test]
    fn stack_alloc_grows_downward() {
        let mut m = mem();
        assert_eq!(m.stack_pointer, STACK_TOP);
        let sp = m.stack_alloc(64).unwrap();
        assert_eq!(sp, STACK_TOP - 64);
        assert_eq!(m.stack_pointer, STACK_TOP - 64);
    }

    // ========== Task 0137: Heap-stack collision ==========

    #[test]
    fn heap_stack_collision() {
        let mut m = mem();
        // Eat almost all memory from the heap side
        let available = STACK_TOP - HEAP_START;
        m.heap_alloc(available - 64).unwrap(); // leave 64 bytes for stack
        m.stack_alloc(64).unwrap(); // exactly fits

        // Now they've met — any more allocation should fail
        assert_eq!(m.heap_alloc(1), Err(MemoryError::HeapStackCollision));
        assert_eq!(m.stack_alloc(1), Err(MemoryError::HeapStackCollision));
    }

    // ========== Task 0138: Null page access traps ==========

    #[test]
    fn null_page_all_sizes_trap() {
        let mut m = mem();
        assert!(m.load8(0).is_err());
        assert!(m.load16(0).is_err());
        assert!(m.load32(0).is_err());
        assert!(m.load64(0).is_err());
        assert!(m.store8(0, 0).is_err());
        assert!(m.store16(0, 0).is_err());
        assert!(m.store32(0, 0).is_err());
        assert!(m.store64(0, 0).is_err());
    }

    // ========== Task 0139: Write to code section traps ==========

    #[test]
    fn code_write_all_sizes_trap() {
        let mut m = mem();
        let addr = CODE_START + 10;
        assert!(m.store8(addr, 0).is_err());
        assert!(m.store16(addr, 0).is_err());
        assert!(m.store32(addr, 0).is_err());
        assert!(m.store64(addr, 0).is_err());
    }

    // ========== Task 0140: Heap allocation and access ==========

    #[test]
    fn heap_write_and_read_back() {
        let mut m = mem();
        let ptr = m.heap_alloc(64).unwrap();
        m.store64(ptr, 0xCAFEBABE).unwrap();
        assert_eq!(m.load64(ptr).unwrap(), 0xCAFEBABE);
    }

    // ========== Task 0141: Stack push/pop ==========

    #[test]
    fn stack_push_pop_pattern() {
        let mut m = mem();
        // Push: decrement SP, write value
        let sp = m.stack_alloc(8).unwrap();
        m.store64(sp, 42).unwrap();

        // Pop: read value, increment SP
        let val = m.load64(sp).unwrap();
        assert_eq!(val, 42);
        m.stack_pointer += 8; // manual pop
        assert_eq!(m.stack_pointer, STACK_TOP);
    }

    // ========== Task 0142: Heap/stack collision detection ==========

    #[test]
    fn heap_into_stack_territory() {
        let mut m = mem();
        m.stack_alloc(1024).unwrap(); // reserve 1 KB for stack
        let max_heap = m.stack_pointer - HEAP_START;
        assert!(m.heap_alloc(max_heap + 1).is_err());
    }

    #[test]
    fn stack_into_heap_territory() {
        let mut m = mem();
        m.heap_alloc(1024).unwrap(); // reserve 1 KB on heap
        let max_stack = STACK_TOP - m.heap_top;
        assert!(m.stack_alloc(max_stack + 1).is_err());
    }

    // ========== Task 0143: Page gas metering ==========

    #[test]
    fn page_gas_metering() {
        let mut m = mem();
        assert_eq!(m.page_gas_used, 0);
        assert_eq!(m.pages_allocated(), 0);

        // Access first heap page
        m.store8(HEAP_START, 1).unwrap();
        assert_eq!(m.page_gas_used, 200);
        assert_eq!(m.pages_allocated(), 1);

        // Access 3 more pages
        m.store8(HEAP_START + PAGE_SIZE as u32, 1).unwrap();
        m.store8(HEAP_START + 2 * PAGE_SIZE as u32, 1).unwrap();
        m.store8(HEAP_START + 3 * PAGE_SIZE as u32, 1).unwrap();
        assert_eq!(m.page_gas_used, 800);
        assert_eq!(m.pages_allocated(), 4);
    }

    #[test]
    fn cross_page_access_charges_both() {
        let mut m = mem();
        // Store 8 bytes that cross a page boundary
        let boundary = HEAP_START + PAGE_SIZE as u32 - 4; // 4 bytes before page end
        m.store64(boundary, 0xDEADBEEF).unwrap();
        assert_eq!(m.page_gas_used, 400); // two pages touched
    }

    // ========== Task 0144: Out of bounds ==========

    #[test]
    fn out_of_bounds_traps() {
        let mut m = mem();
        assert!(m.load8(MEMORY_SIZE as u32).is_err());
        assert!(m.load64(MEMORY_SIZE as u32 - 4).is_err()); // partially OOB
    }

    // ========== Task 1168: Lazy page allocation ==========

    #[test]
    fn lazy_no_pages_materialized_on_new() {
        let m = mem();
        assert_eq!(m.pages_materialized(), 0);
    }

    #[test]
    fn lazy_read_untouched_returns_zero() {
        let mut m = mem();
        assert_eq!(m.load8(HEAP_START).unwrap(), 0);
        assert_eq!(m.load64(HEAP_START).unwrap(), 0);
        assert_eq!(m.load256(HEAP_START).unwrap(), [0u8; 32]);
    }

    #[test]
    fn lazy_write_materializes_page() {
        let mut m = mem();
        assert_eq!(m.pages_materialized(), 0);
        m.store8(HEAP_START, 42).unwrap();
        assert!(m.pages_materialized() >= 1);
        assert_eq!(m.load8(HEAP_START).unwrap(), 42);
    }

    #[test]
    fn lazy_code_load_materializes_code_pages_only() {
        let mut m = mem();
        let code = vec![0xAB; 100]; // 100 bytes, fits in 1 page
        m.load_code(&code).unwrap();
        // Only code page(s) should be materialized
        let materialized = m.pages_materialized();
        assert!(materialized <= 2); // code might span 1-2 pages
        assert!(materialized >= 1);
    }

    #[test]
    fn lazy_typical_transfer_touches_few_pages() {
        let mut m = mem();
        // Simulate a token transfer: load code, write a few values to heap
        let code = vec![0x00; 52]; // 13 instructions
        m.load_code(&code).unwrap();
        m.store64(HEAP_START, 1000).unwrap(); // sender balance
        m.store64(HEAP_START + 8, 500).unwrap(); // receiver balance
        m.store64(HEAP_START + 16, 50).unwrap(); // transfer amount

        // Should only have materialized code page(s) + 1 heap page
        let materialized = m.pages_materialized();
        assert!(materialized <= 3);
    }
}
