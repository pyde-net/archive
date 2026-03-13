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

    pub fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        let len = slice.len().min(32);
        bytes[..len].copy_from_slice(&slice[..len]);
        Self(bytes)
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
    fn from_slice_short() {
        let h = Hash256::from_slice(&[1, 2, 3]);
        let mut expected = [0u8; 32];
        expected[..3].copy_from_slice(&[1, 2, 3]);
        assert_eq!(h.to_bytes(), expected);
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
