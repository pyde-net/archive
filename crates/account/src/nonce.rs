//! Nonce window management per Chapter 11, Section 11.5.
//!
//! Pyde uses a nonce window of size 16 instead of sequential nonces.
//! The account's `nonce` field stores the base (lowest unused nonce).
//! A 16-bit bitmap tracks which slots in `[base, base+15]` are used.
//! This allows up to 16 concurrent in-flight transactions per account.

/// Window size: 64 nonce slots (for high-throughput load testing).
pub const WINDOW_SIZE: u64 = 64;

/// Nonce state: base nonce + 64-bit usage bitmap.
/// Total: 16 bytes (u64 + u64).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceState {
    /// The base nonce (lowest in the window).
    pub base: u64,
    /// Bitmap of used nonces within the window (bit 0 = base, bit 63 = base+63).
    pub used: u64,
}

/// Nonce validation error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceError {
    /// Nonce is below the window (already consumed).
    BelowWindow,
    /// Nonce is above the window (too far ahead).
    AboveWindow,
    /// Nonce has already been used within the window.
    AlreadyUsed,
}

impl NonceState {
    /// Create a new nonce state starting at nonce 0.
    pub fn new() -> Self {
        Self { base: 0, used: 0 }
    }

    /// Create a nonce state with a specific base.
    pub fn with_base(base: u64) -> Self {
        Self { base, used: 0 }
    }

    /// Check if a nonce is valid (within window and not yet used).
    pub fn is_valid(&self, nonce: u64) -> bool {
        self.validate(nonce).is_ok()
    }

    /// Validate a nonce. Returns the bit index on success, or an error.
    pub fn validate(&self, nonce: u64) -> Result<u8, NonceError> {
        if nonce < self.base {
            return Err(NonceError::BelowWindow);
        }
        if nonce >= self.base + WINDOW_SIZE {
            return Err(NonceError::AboveWindow);
        }
        let bit = (nonce - self.base) as u8;
        if self.used & (1 << bit) != 0 {
            return Err(NonceError::AlreadyUsed);
        }
        Ok(bit)
    }

    /// Mark a nonce as used. Returns error if invalid.
    /// Automatically advances the window when leading nonces are consumed.
    pub fn use_nonce(&mut self, nonce: u64) -> Result<(), NonceError> {
        let bit = self.validate(nonce)?;
        self.used |= 1 << bit;
        self.advance();
        Ok(())
    }

    /// Advance the window: skip over consecutive used nonces at the base.
    /// E.g., if base=100 and bits 0,1,2 are set, advance to base=103.
    fn advance(&mut self) {
        while self.used & 1 == 1 {
            self.used >>= 1;
            self.base += 1;
        }
    }

    /// The highest valid nonce in the current window.
    pub fn max_nonce(&self) -> u64 {
        self.base + WINDOW_SIZE - 1
    }

    /// Number of available (unused) slots in the window.
    pub fn available_slots(&self) -> u32 {
        WINDOW_SIZE as u32 - self.used.count_ones()
    }

    /// Serialize to 16 bytes.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&self.base.to_le_bytes());
        buf[8..16].copy_from_slice(&self.used.to_le_bytes());
        buf
    }

    /// Deserialize from bytes (supports both 10-byte legacy and 16-byte new format).
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.len() >= 16 {
            let mut base_bytes = [0u8; 8];
            base_bytes.copy_from_slice(&data[0..8]);
            let mut used_bytes = [0u8; 8];
            used_bytes.copy_from_slice(&data[8..16]);
            Self {
                base: u64::from_le_bytes(base_bytes),
                used: u64::from_le_bytes(used_bytes),
            }
        } else if data.len() >= 10 {
            // Legacy 10-byte format (u16 bitmap)
            let mut base_bytes = [0u8; 8];
            base_bytes.copy_from_slice(&data[0..8]);
            let mut used_bytes = [0u8; 2];
            used_bytes.copy_from_slice(&data[8..10]);
            Self {
                base: u64::from_le_bytes(base_bytes),
                used: u16::from_le_bytes(used_bytes) as u64,
            }
        } else {
            Self::new()
        }
    }
}

impl Default for NonceState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Task 0362: Sequential nonce usage ==========

    #[test]
    fn sequential_nonces() {
        let mut ns = NonceState::new();
        assert_eq!(ns.base, 0);

        ns.use_nonce(0).unwrap();
        assert_eq!(ns.base, 1); // advanced past 0

        ns.use_nonce(1).unwrap();
        assert_eq!(ns.base, 2);

        ns.use_nonce(2).unwrap();
        assert_eq!(ns.base, 3);
    }

    #[test]
    fn sequential_from_nonzero_base() {
        let mut ns = NonceState::with_base(100);
        ns.use_nonce(100).unwrap();
        assert_eq!(ns.base, 101);
        ns.use_nonce(101).unwrap();
        assert_eq!(ns.base, 102);
    }

    // ========== Task 0363: Out-of-order nonce within window ==========

    #[test]
    fn out_of_order_usage() {
        let mut ns = NonceState::new();

        // Use nonce 5 first (out of order)
        ns.use_nonce(5).unwrap();
        assert_eq!(ns.base, 0); // base doesn't advance (0 not used yet)

        // Use nonce 3
        ns.use_nonce(3).unwrap();
        assert_eq!(ns.base, 0);

        // Use nonce 0 — now base advances past 0 (but 1,2 still unused)
        ns.use_nonce(0).unwrap();
        assert_eq!(ns.base, 1); // advanced past 0 only

        // Use 1, 2 — now advances past 1,2,3 (3 was already used), then 4 unused
        ns.use_nonce(1).unwrap();
        ns.use_nonce(2).unwrap();
        assert_eq!(ns.base, 4); // 0,1,2,3 all used, 4 is next

        // Use 4 — advances past 4, then 5 was already used, so advances to 6
        ns.use_nonce(4).unwrap();
        assert_eq!(ns.base, 6);
    }

    #[test]
    fn all_16_slots_out_of_order() {
        let mut ns = NonceState::new();

        // Use all 16 in reverse order
        for i in (0..16).rev() {
            ns.use_nonce(i).unwrap();
        }
        assert_eq!(ns.base, 16);
        assert_eq!(ns.used, 0); // all consumed, window shifted
    }

    // ========== Task 0364: Nonce outside window rejected ==========

    #[test]
    fn nonce_below_window_rejected() {
        let ns = NonceState::with_base(100);
        assert_eq!(ns.validate(99), Err(NonceError::BelowWindow));
        assert_eq!(ns.validate(50), Err(NonceError::BelowWindow));
    }

    #[test]
    fn nonce_above_window_rejected() {
        let ns = NonceState::with_base(100);
        assert_eq!(ns.validate(116), Err(NonceError::AboveWindow));
        assert_eq!(ns.validate(200), Err(NonceError::AboveWindow));
    }

    #[test]
    fn nonce_already_used_rejected() {
        let mut ns = NonceState::new();
        ns.use_nonce(5).unwrap();
        assert_eq!(ns.validate(5), Err(NonceError::AlreadyUsed));
    }

    #[test]
    fn nonce_at_window_boundaries() {
        let ns = NonceState::with_base(100);
        assert!(ns.is_valid(100)); // base
        assert!(ns.is_valid(115)); // base + 15
        assert!(!ns.is_valid(99)); // below
        assert!(!ns.is_valid(116)); // above
    }

    // ========== Task 0365: Window advancement after gap fill ==========

    #[test]
    fn window_advances_on_gap_fill() {
        let mut ns = NonceState::new();

        // Use 1, 2, 3 (skip 0)
        ns.use_nonce(1).unwrap();
        ns.use_nonce(2).unwrap();
        ns.use_nonce(3).unwrap();
        assert_eq!(ns.base, 0); // still 0, gap at 0

        // Fill the gap
        ns.use_nonce(0).unwrap();
        assert_eq!(ns.base, 4); // advances past 0,1,2,3
    }

    #[test]
    fn window_advances_partially() {
        let mut ns = NonceState::new();

        ns.use_nonce(0).unwrap();
        ns.use_nonce(1).unwrap();
        // Skip 2
        ns.use_nonce(3).unwrap();
        assert_eq!(ns.base, 2); // stopped at gap

        ns.use_nonce(2).unwrap();
        assert_eq!(ns.base, 4); // now advances past 2,3
    }

    // ========== Serialization ==========

    #[test]
    fn serialize_roundtrip() {
        let mut ns = NonceState::with_base(42);
        ns.use_nonce(43).unwrap();
        ns.use_nonce(45).unwrap();

        let bytes = ns.to_bytes();
        let restored = NonceState::from_bytes(&bytes);
        assert_eq!(ns, restored);
    }

    // ========== Helpers ==========

    #[test]
    fn available_slots() {
        let mut ns = NonceState::new();
        assert_eq!(ns.available_slots(), 16);

        ns.use_nonce(5).unwrap();
        assert_eq!(ns.available_slots(), 15);

        for i in 0..5 {
            ns.use_nonce(i).unwrap();
        }
        // 0-5 all used, window advanced to base=6, bitmap cleared
        // 16 fresh slots available again
        assert_eq!(ns.available_slots(), 16);
    }

    #[test]
    fn max_nonce() {
        let ns = NonceState::with_base(100);
        assert_eq!(ns.max_nonce(), 115);
    }
}
