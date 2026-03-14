//! 256-bit wide register support, backed by `ethnum::U256`.

pub use ethnum::U256;

use crate::cpu::Trap;

/// Checked 256-bit addition.
pub fn wide_add(a: U256, b: U256) -> Result<U256, Trap> {
    a.checked_add(b).ok_or(Trap::Overflow)
}

/// Checked 256-bit subtraction.
pub fn wide_sub(a: U256, b: U256) -> Result<U256, Trap> {
    a.checked_sub(b).ok_or(Trap::Underflow)
}

/// Checked 256-bit multiplication.
pub fn wide_mul(a: U256, b: U256) -> Result<U256, Trap> {
    a.checked_mul(b).ok_or(Trap::Overflow)
}

/// Checked 256-bit division.
pub fn wide_div(a: U256, b: U256) -> Result<U256, Trap> {
    a.checked_div(b).ok_or(Trap::DivisionByZero)
}

/// Checked 256-bit modulo.
pub fn wide_mod(a: U256, b: U256) -> Result<U256, Trap> {
    a.checked_rem(b).ok_or(Trap::DivisionByZero)
}

/// Convert U256 to u64, or None if it doesn't fit.
pub fn narrow(val: U256) -> Option<u64> {
    if val > U256::from(u64::MAX) {
        None
    } else {
        Some(val.as_u64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_basic() {
        assert_eq!(
            wide_add(U256::from(100u64), U256::from(200u64)).unwrap(),
            U256::from(300u64)
        );
    }

    #[test]
    fn add_overflow() {
        assert_eq!(wide_add(U256::MAX, U256::from(1u64)), Err(Trap::Overflow));
    }

    #[test]
    fn sub_basic() {
        assert_eq!(
            wide_sub(U256::from(300u64), U256::from(100u64)).unwrap(),
            U256::from(200u64)
        );
    }

    #[test]
    fn sub_underflow() {
        assert_eq!(wide_sub(U256::ZERO, U256::from(1u64)), Err(Trap::Underflow));
    }

    #[test]
    fn mul_basic() {
        assert_eq!(
            wide_mul(U256::from(7u64), U256::from(6u64)).unwrap(),
            U256::from(42u64)
        );
    }

    #[test]
    fn mul_overflow() {
        let big = U256::from(1u64) << 128;
        assert_eq!(wide_mul(big, big), Err(Trap::Overflow));
    }

    #[test]
    fn div_basic() {
        assert_eq!(
            wide_div(U256::from(42u64), U256::from(7u64)).unwrap(),
            U256::from(6u64)
        );
    }

    #[test]
    fn div_by_zero() {
        assert_eq!(
            wide_div(U256::from(42u64), U256::ZERO),
            Err(Trap::DivisionByZero)
        );
    }

    #[test]
    fn mod_basic() {
        assert_eq!(
            wide_mod(U256::from(10u64), U256::from(3u64)).unwrap(),
            U256::from(1u64)
        );
    }

    #[test]
    fn mod_by_zero() {
        assert_eq!(
            wide_mod(U256::from(10u64), U256::ZERO),
            Err(Trap::DivisionByZero)
        );
    }

    #[test]
    fn narrow_fits() {
        assert_eq!(narrow(U256::from(42u64)), Some(42));
    }

    #[test]
    fn narrow_max_u64() {
        assert_eq!(narrow(U256::from(u64::MAX)), Some(u64::MAX));
    }

    #[test]
    fn narrow_too_large() {
        assert_eq!(narrow(U256::from(u64::MAX) + U256::from(1u64)), None);
    }

    #[test]
    fn bitwise_ops() {
        let a = U256::from(0xFF00u64);
        let b = U256::from(0x0FF0u64);
        assert_eq!(a & b, U256::from(0x0F00u64));
        assert_eq!(a | b, U256::from(0xFFF0u64));
        assert_eq!(a ^ b, U256::from(0xF0F0u64));
        assert_eq!(!U256::ZERO, U256::MAX);
    }
}
