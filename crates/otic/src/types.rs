//! Type system for Otigen.
//!
//! Defines the concrete types used during type checking.
//! Separate from AST types — these are resolved and canonical.

use std::fmt;

/// A resolved, canonical type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Ty {
    // Unsigned integers
    U8, U16, U32, U64, U128, U256,
    // Signed integers
    I8, I16, I32, I64, I128, I256,
    // Other primitives
    Bool,
    Address,
    StringTy,
    Bytes,
    // Composite types
    Array(Box<Ty>, u64),       // [T; N]
    Vec(Box<Ty>),              // Vec<T>
    Map(Box<Ty>, Box<Ty>),     // Map<K, V>
    Tuple(Vec<Ty>),            // (T1, T2, ...)
    // Named types
    Struct(String),            // struct name
    Enum(String),              // enum name
    // Contract/interface handles (address + typed method dispatch)
    Contract(String),          // contract name — deploy!(Counter) returns this
    Interface(String),         // interface name — IERC20::at(addr) returns this
    // Special
    Unit,                      // void / no return
    /// Used for type inference when we don't know yet.
    Unknown,
    /// Used for error recovery — any type is compatible.
    Error,
}

impl Ty {
    /// Whether this is a numeric type (arithmetic operations allowed).
    pub fn is_numeric(&self) -> bool {
        matches!(self,
            Ty::U8 | Ty::U16 | Ty::U32 | Ty::U64 | Ty::U128 | Ty::U256
            | Ty::I8 | Ty::I16 | Ty::I32 | Ty::I64 | Ty::I128 | Ty::I256
        )
    }

    /// Whether this is an unsigned integer type.
    pub fn is_unsigned(&self) -> bool {
        matches!(self, Ty::U8 | Ty::U16 | Ty::U32 | Ty::U64 | Ty::U128 | Ty::U256)
    }

    /// Whether this is a signed integer type.
    pub fn is_signed(&self) -> bool {
        matches!(self, Ty::I8 | Ty::I16 | Ty::I32 | Ty::I64 | Ty::I128 | Ty::I256)
    }

    /// Whether this is an integer type (numeric, not bool).
    pub fn is_integer(&self) -> bool {
        self.is_numeric()
    }

    /// Bit width of integer types.
    pub fn bit_width(&self) -> Option<u32> {
        match self {
            Ty::U8 | Ty::I8 => Some(8),
            Ty::U16 | Ty::I16 => Some(16),
            Ty::U32 | Ty::I32 => Some(32),
            Ty::U64 | Ty::I64 => Some(64),
            Ty::U128 | Ty::I128 => Some(128),
            Ty::U256 | Ty::I256 => Some(256),
            _ => None,
        }
    }

    /// Whether a cast from self to target is a widening (always safe) cast.
    /// Allows: u8→u64, u64→u256, i32→i64, u32→i64, and any numeric→larger numeric.
    pub fn can_widen_to(&self, target: &Ty) -> bool {
        if self == target { return true; }
        match (self.bit_width(), target.bit_width()) {
            (Some(from), Some(to)) => {
                if from <= to {
                    // Same signedness — always ok
                    if self.is_unsigned() == target.is_unsigned() {
                        return true;
                    }
                    // Unsigned to signed of equal or wider size — ok
                    if self.is_unsigned() && target.is_signed() {
                        return true;
                    }
                    // Signed to unsigned of wider size — ok (with potential value check at runtime)
                    if self.is_signed() && target.is_unsigned() && from < to {
                        return true;
                    }
                }
                false
            }
            // Enum → numeric: enums are discriminant integers
            _ if matches!(self, Ty::Enum(_)) && target.is_numeric() => true,
            _ if self.is_numeric() && matches!(target, Ty::Enum(_)) => true,
            _ => false,
        }
    }

    /// Whether two types are compatible for comparison (==, !=, <, >, etc.).
    pub fn is_comparable_with(&self, other: &Ty) -> bool {
        if self == other { return true; }
        if matches!(self, Ty::Error) || matches!(other, Ty::Error) { return true; }
        if matches!(self, Ty::Unknown) || matches!(other, Ty::Unknown) { return true; }
        // Numeric types are comparable (implicit widening happens)
        if self.is_numeric() && other.is_numeric() { return true; }
        // Enums are comparable with numerics (discriminant comparison)
        if (matches!(self, Ty::Enum(_)) && other.is_numeric())
            || (self.is_numeric() && matches!(other, Ty::Enum(_))) { return true; }
        // Arrays of same size with compatible elements
        if let (Ty::Array(a, n1), Ty::Array(b, n2)) = (self, other) {
            return n1 == n2 && a.is_comparable_with(b);
        }
        false
    }

    /// Whether this is an enum type.
    pub fn is_enum(&self) -> bool {
        matches!(self, Ty::Enum(_))
    }

    /// Whether a type can be used as a map key.
    pub fn is_hashable(&self) -> bool {
        matches!(self,
            Ty::U8 | Ty::U16 | Ty::U32 | Ty::U64 | Ty::U128 | Ty::U256
            | Ty::I8 | Ty::I16 | Ty::I32 | Ty::I64 | Ty::I128 | Ty::I256
            | Ty::Bool | Ty::Address | Ty::StringTy | Ty::Bytes
        )
    }
}

impl fmt::Display for Ty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ty::U8 => write!(f, "u8"),
            Ty::U16 => write!(f, "u16"),
            Ty::U32 => write!(f, "u32"),
            Ty::U64 => write!(f, "u64"),
            Ty::U128 => write!(f, "u128"),
            Ty::U256 => write!(f, "u256"),
            Ty::I8 => write!(f, "i8"),
            Ty::I16 => write!(f, "i16"),
            Ty::I32 => write!(f, "i32"),
            Ty::I64 => write!(f, "i64"),
            Ty::I128 => write!(f, "i128"),
            Ty::I256 => write!(f, "i256"),
            Ty::Bool => write!(f, "bool"),
            Ty::Address => write!(f, "Address"),
            Ty::StringTy => write!(f, "String"),
            Ty::Bytes => write!(f, "bytes"),
            Ty::Array(elem, size) => write!(f, "[{}; {}]", elem, size),
            Ty::Vec(elem) => write!(f, "Vec<{}>", elem),
            Ty::Map(key, val) => write!(f, "Map<{}, {}>", key, val),
            Ty::Tuple(types) => {
                write!(f, "(")?;
                for (i, t) in types.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{}", t)?;
                }
                write!(f, ")")
            }
            Ty::Struct(name) => write!(f, "{}", name),
            Ty::Enum(name) => write!(f, "{}", name),
            Ty::Contract(name) => write!(f, "{}", name),
            Ty::Interface(name) => write!(f, "{}", name),
            Ty::Unit => write!(f, "()"),
            Ty::Unknown => write!(f, "?"),
            Ty::Error => write!(f, "<error>"),
        }
    }
}
