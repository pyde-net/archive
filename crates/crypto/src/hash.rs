use alloc::format;
use alloc::string::String;
use core::fmt;

/// A 256-bit (32-byte) hash output.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash256([u8; 32]);

impl Hash256 {
    pub const ZERO: Self = Self([0u8; 32]);

    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Construct a `Hash256` from a 32-byte slice.
    ///
    /// Audit 392: returns `None` for any other length. Pre-fix the
    /// function silently zero-padded short slices and silently
    /// truncated long ones — both behaviors hide programming bugs
    /// (a malformed 31-byte hash compared equal to a real
    /// `Hash256(...)` whose 32nd byte was zero, and a 33-byte
    /// payload had its trailing byte dropped on the floor without
    /// surfacing the size mismatch). Callers that genuinely need
    /// truncation/padding should do it explicitly at the call
    /// site.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        let bytes: [u8; 32] = slice.try_into().ok()?;
        Some(Self(bytes))
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256(0x{})", hex_encode(&self.0))
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex_encode(&self.0))
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<Hash256> for [u8; 32] {
    fn from(hash: Hash256) -> Self {
        hash.0
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_hash() {
        let h = Hash256::ZERO;
        assert_eq!(h.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn from_bytes_roundtrip() {
        let bytes = [42u8; 32];
        let h = Hash256::new(bytes);
        assert_eq!(h.to_bytes(), bytes);
    }

    #[test]
    fn from_slice_exact_length() {
        let bytes = [42u8; 32];
        let h = Hash256::from_slice(&bytes).expect("32-byte slice is accepted");
        assert_eq!(h.to_bytes(), bytes);
    }

    #[test]
    fn audit_392_from_slice_short_returns_none() {
        // Pre-fix this silently zero-padded; post-fix the size
        // mismatch surfaces as None so the caller decides what
        // to do.
        assert!(Hash256::from_slice(&[1, 2, 3]).is_none());
        assert!(Hash256::from_slice(&[]).is_none());
        assert!(Hash256::from_slice(&[0u8; 31]).is_none());
    }

    #[test]
    fn audit_392_from_slice_long_returns_none() {
        // Pre-fix this silently truncated; post-fix it returns
        // None so the trailing bytes can't be lost without the
        // caller noticing.
        assert!(Hash256::from_slice(&[7u8; 33]).is_none());
        assert!(Hash256::from_slice(&[7u8; 64]).is_none());
    }

    #[test]
    fn display_format() {
        let h = Hash256::ZERO;
        let s = format!("{}", h);
        assert!(s.starts_with("0x"));
        assert_eq!(s.len(), 66); // "0x" + 64 hex chars
    }

    #[test]
    fn debug_format() {
        let h = Hash256::ZERO;
        let s = format!("{:?}", h);
        assert!(s.starts_with("Hash256(0x"));
    }

    #[test]
    fn ordering() {
        let a = Hash256::new([0u8; 32]);
        let mut b_bytes = [0u8; 32];
        b_bytes[0] = 1;
        let b = Hash256::new(b_bytes);
        assert!(a < b);
    }

    #[test]
    fn equality() {
        let a = Hash256::new([7u8; 32]);
        let b = Hash256::new([7u8; 32]);
        let c = Hash256::new([8u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
