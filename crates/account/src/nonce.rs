//! Nonce window management per Chapter 11, Section 11.5.
//!
//! Pyde uses a nonce window of size 16 instead of sequential nonces.
//! The account's `nonce` field stores the base (lowest unused nonce).
//! A 16-bit bitmap tracks which slots in `[base, base+15]` are used.
//! This allows up to 16 concurrent in-flight transactions per account.

/// Window size: 16 nonce slots.
pub const WINDOW_SIZE: u64 = 16;

/// Nonce state: base nonce + 16-bit usage bitmap.
/// Total: 10 bytes (u64 + u16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceState {
    /// The base nonce (lowest in the window).
    pub base: u64,
    /// Bitmap of used nonces within the window (bit 0 = base, bit 15 = base+15).
    pub used: u16,
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
        // Audit 386: `self.base + WINDOW_SIZE` overflows once `base` is
        // within `WINDOW_SIZE` of `u64::MAX`. In debug builds that's a
        // panic on a hot validation path; in release it wraps and the
        // resulting comparison rejects valid nonces while accepting
        // bogus ones near the wrap boundary. The right semantics:
        // when the window would extend past `u64::MAX`, all remaining
        // nonces in `[base, u64::MAX]` are still valid (there is no
        // nonce greater than `u64::MAX` to reject), so a `checked_add`
        // failure means "no upper-bound rejection."
        if let Some(window_end) = self.base.checked_add(WINDOW_SIZE) {
            if nonce >= window_end {
                return Err(NonceError::AboveWindow);
            }
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
        // Audit 386: `self.base += 1` panics when `base == u64::MAX`. In
        // practice this is unreachable (would require `u64::MAX` consumed
        // nonces on a single account), but a bounded loop keeps the
        // function total. Crucially we check the addition *before*
        // shifting the bit out — otherwise we'd consume the slot from
        // `used` without moving `base`, leaving the same nonce reusable.
        while self.used & 1 == 1 {
            match self.base.checked_add(1) {
                Some(b) => {
                    self.used >>= 1;
                    self.base = b;
                }
                None => break,
            }
        }
    }

    /// The highest valid nonce in the current window.
    pub fn max_nonce(&self) -> u64 {
        // Audit 386: `saturating_add` clamps the displayed upper bound
        // at `u64::MAX` when `base` is within `WINDOW_SIZE - 1` of it.
        // Used in the InvalidNonce error message rendered by
        // `validate_nonce`, so the wallet sees a meaningful bound
        // instead of a wrapped value.
        self.base.saturating_add(WINDOW_SIZE - 1)
    }

    /// Number of available (unused) slots in the window.
    pub fn available_slots(&self) -> u32 {
        WINDOW_SIZE as u32 - self.used.count_ones()
    }

    /// Serialize to 10 bytes.
    pub fn to_bytes(&self) -> [u8; 10] {
        let mut buf = [0u8; 10];
        buf[0..8].copy_from_slice(&self.base.to_le_bytes());
        buf[8..10].copy_from_slice(&self.used.to_le_bytes());
        buf
    }

    /// Deserialize from a 10-byte buffer.
    ///
    /// Audit 390: pre-fix the function silently returned
    /// `Self::new()` for inputs shorter than 10 bytes — meaning a
    /// truncated SMT read or a corrupted nonce-key value would
    /// roll the sender's nonce window back to `base = 0` rather
    /// than surface as a parse failure. Post-fix returns
    /// `Option<Self>`, so the truncation is observable; callers
    /// decide whether to default-on-missing (the EOA-with-no-prior-tx
    /// case) or treat as a hard error.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        let mut base_bytes = [0u8; 8];
        base_bytes.copy_from_slice(&data[0..8]);
        let mut used_bytes = [0u8; 2];
        used_bytes.copy_from_slice(&data[8..10]);
        Some(Self {
            base: u64::from_le_bytes(base_bytes),
            used: u16::from_le_bytes(used_bytes),
        })
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
        let restored = NonceState::from_bytes(&bytes).expect("10-byte buffer parses");
        assert_eq!(ns, restored);
    }

    /// Audit 390: short buffers must surface as `None` instead
    /// of silently rolling back to `Self::new()`. Pre-fix a
    /// truncated SMT read would have masqueraded as a fresh
    /// `base = 0` nonce window — letting an attacker who corrupted
    /// a nonce-key entry (or a node that crashed mid-write)
    /// silently replay every nonce up to the original base.
    #[test]
    fn audit_390_from_bytes_short_returns_none() {
        assert!(NonceState::from_bytes(&[]).is_none());
        assert!(NonceState::from_bytes(&[0u8; 9]).is_none());
        assert!(NonceState::from_bytes(&[1, 2, 3, 4]).is_none());
    }

    #[test]
    fn audit_390_from_bytes_at_or_above_10_succeeds() {
        // Exactly 10 bytes parses.
        assert!(NonceState::from_bytes(&[0u8; 10]).is_some());
        // Trailing bytes are ignored — keeps storage layouts that
        // append fields to the nonce-key value forward-compatible
        // with this parser.
        assert!(NonceState::from_bytes(&[0u8; 32]).is_some());
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

    // ========== Audit 386: u64::MAX overflow safety ==========

    #[test]
    fn validate_does_not_overflow_at_u64_max_base() {
        // Pre-fix: `self.base + WINDOW_SIZE` panics in debug and wraps
        // in release. Post-fix: `checked_add` returns `None`, the
        // upper-bound check is skipped, and every nonce in
        // `[base, u64::MAX]` is treated as in-window.
        let ns = NonceState::with_base(u64::MAX - 5);
        // Every nonce in [u64::MAX-5, u64::MAX] is valid (6 slots).
        for n in (u64::MAX - 5)..=u64::MAX {
            assert!(ns.is_valid(n), "nonce {} should be valid", n);
        }
        // Below-window still rejects.
        assert_eq!(ns.validate(u64::MAX - 6), Err(NonceError::BelowWindow));
    }

    #[test]
    fn validate_at_exact_u64_max_base() {
        // Edge case: base == u64::MAX. Only u64::MAX itself is in window.
        let ns = NonceState::with_base(u64::MAX);
        assert!(ns.is_valid(u64::MAX));
        assert_eq!(ns.validate(u64::MAX - 1), Err(NonceError::BelowWindow));
    }

    #[test]
    fn advance_does_not_overflow_at_u64_max() {
        // Pre-fix: `self.base += 1` panics when base reaches u64::MAX
        // mid-advance. Post-fix: the loop breaks instead.
        let mut ns = NonceState::with_base(u64::MAX);
        ns.use_nonce(u64::MAX).unwrap();
        // Base stays at u64::MAX (can't advance further), but the bit
        // is consumed.
        assert_eq!(ns.base, u64::MAX);
        // Re-using the same nonce is still rejected.
        assert_eq!(ns.validate(u64::MAX), Err(NonceError::AlreadyUsed));
    }

    #[test]
    fn max_nonce_saturates_at_u64_max() {
        // Pre-fix: `self.base + WINDOW_SIZE - 1` overflows.
        // Post-fix: saturates at u64::MAX.
        let ns = NonceState::with_base(u64::MAX - 5);
        assert_eq!(ns.max_nonce(), u64::MAX);

        let ns = NonceState::with_base(u64::MAX);
        assert_eq!(ns.max_nonce(), u64::MAX);
    }
}
