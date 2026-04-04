use crate::types::Address;

/// Compute FNV-1a function selector (same as Otigen codegen).
pub fn compute_selector(name: &str) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in name.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

/// Build calldata for a contract function call.
///
/// ```rust
/// use pyde_rust_sdk::contract::ContractCall;
///
/// let data = ContractCall::new("deposit")
///     .arg_u64(500)
///     .build();
/// ```
#[derive(Clone)]
pub struct ContractCall {
    method: String,
    selector: u32,
    args: Vec<u8>,
}

impl ContractCall {
    pub fn new(method: &str) -> Self {
        Self {
            method: method.to_string(),
            selector: compute_selector(method),
            args: Vec::new(),
        }
    }

    pub fn method_name(&self) -> &str {
        &self.method
    }

    pub fn arg_u64(mut self, val: u64) -> Self {
        self.args.extend_from_slice(&val.to_le_bytes());
        self
    }

    pub fn arg_bool(mut self, val: bool) -> Self {
        self.args.extend_from_slice(&(val as u64).to_le_bytes());
        self
    }

    pub fn arg_u256(mut self, val: ethnum::U256) -> Self {
        self.args.extend_from_slice(&val.to_le_bytes());
        self
    }

    pub fn arg_address(mut self, val: Address) -> Self {
        self.args.extend_from_slice(&val);
        self
    }

    pub fn arg_bytes(mut self, val: &[u8]) -> Self {
        self.args.extend_from_slice(val);
        self
    }

    /// Encode a String argument (length-prefixed, 8-byte aligned).
    pub fn arg_string(mut self, val: &str) -> Self {
        let bytes = val.as_bytes();
        self.args.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        self.args.extend_from_slice(bytes);
        // Pad to 8-byte alignment
        let padding = (8 - (bytes.len() % 8)) % 8;
        self.args.extend(std::iter::repeat(0u8).take(padding));
        self
    }

    /// Build the final calldata: [selector:4 BE][args].
    pub fn build(self) -> Vec<u8> {
        let mut data = self.selector.to_be_bytes().to_vec();
        data.extend_from_slice(&self.args);
        data
    }
}

/// Build deploy transaction data.
///
/// ```rust,ignore
/// let data = DeployData::new(constructor_bytes, runtime_bytes)
///     .arg_u64(1000)
///     .build();
/// ```
pub struct DeployData {
    constructor: Vec<u8>,
    runtime: Vec<u8>,
    args: Vec<u8>,
}

impl DeployData {
    pub fn new(constructor: Vec<u8>, runtime: Vec<u8>) -> Self {
        Self { constructor, runtime, args: Vec::new() }
    }

    pub fn arg_u64(mut self, val: u64) -> Self {
        self.args.extend_from_slice(&val.to_le_bytes());
        self
    }

    pub fn arg_bool(mut self, val: bool) -> Self {
        self.args.extend_from_slice(&(val as u64).to_le_bytes());
        self
    }

    pub fn arg_string(mut self, val: &str) -> Self {
        let bytes = val.as_bytes();
        self.args.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        self.args.extend_from_slice(bytes);
        let padding = (8 - (bytes.len() % 8)) % 8;
        self.args.extend(std::iter::repeat(0u8).take(padding));
        self
    }

    /// Build deploy data: [clen:4 LE][rlen:4 LE][constructor][runtime][args].
    pub fn build(self) -> Vec<u8> {
        let clen = self.constructor.len() as u32;
        let rlen = self.runtime.len() as u32;
        let mut data = Vec::with_capacity(8 + clen as usize + rlen as usize + self.args.len());
        data.extend_from_slice(&clen.to_le_bytes());
        data.extend_from_slice(&rlen.to_le_bytes());
        data.extend_from_slice(&self.constructor);
        data.extend_from_slice(&self.runtime);
        data.extend_from_slice(&self.args);
        data
    }
}

// ============================================================================
// Decode helpers
// ============================================================================

/// Decode a u64 from return bytes (first 8 bytes LE).
pub fn decode_u64(data: &[u8]) -> Option<u64> {
    if data.len() < 8 { return None; }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[..8]);
    Some(u64::from_le_bytes(buf))
}

/// Decode a u128 from return bytes.
pub fn decode_u128(data: &[u8]) -> Option<u128> {
    if data.len() < 16 { return None; }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&data[..16]);
    Some(u128::from_le_bytes(buf))
}

/// Decode a u256 from return bytes (32 bytes LE).
pub fn decode_u256(data: &[u8]) -> Option<ethnum::U256> {
    if data.len() < 32 { return None; }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[..32]);
    Some(ethnum::U256::from_le_bytes(buf))
}

/// Decode a bool from return bytes.
pub fn decode_bool(data: &[u8]) -> Option<bool> {
    decode_u64(data).map(|v| v != 0)
}

/// Decode an address from return bytes (32 bytes).
pub fn decode_address(data: &[u8]) -> Option<Address> {
    if data.len() < 32 { return None; }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&data[..32]);
    Some(addr)
}

/// Decode a length-prefixed string from return bytes.
pub fn decode_string(data: &[u8]) -> Option<String> {
    if data.len() < 8 { return None; }
    let mut len_buf = [0u8; 8];
    len_buf.copy_from_slice(&data[..8]);
    let len = u64::from_le_bytes(len_buf) as usize;
    if data.len() < 8 + len { return None; }
    String::from_utf8(data[8..8 + len].to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_fnv1a() {
        assert_eq!(compute_selector("get_count"), 0xd9e32bf7);
        assert_eq!(compute_selector("increment"), 0x3812e73e);
        assert_eq!(compute_selector("deposit"), 0x28a1b7b5);
    }

    #[test]
    fn contract_call_no_args() {
        let data = ContractCall::new("increment").build();
        assert_eq!(&data[..4], &compute_selector("increment").to_be_bytes());
        assert_eq!(data.len(), 4);
    }

    #[test]
    fn contract_call_with_u64() {
        let data = ContractCall::new("deposit").arg_u64(500).build();
        assert_eq!(data.len(), 12); // 4 selector + 8 arg
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[4..12]);
        assert_eq!(u64::from_le_bytes(buf), 500);
    }

    #[test]
    fn contract_call_with_string() {
        let data = ContractCall::new("set_name").arg_string("hello").build();
        // 4 selector + 8 len + 8 data (5 bytes + 3 padding) = 20
        assert_eq!(data.len(), 20);
    }

    #[test]
    fn deploy_data_with_args() {
        let d = DeployData::new(vec![1, 2, 3], vec![4, 5, 6, 7])
            .arg_u64(42)
            .build();
        // 4 clen + 4 rlen + 3 constructor + 4 runtime + 8 arg = 23
        assert_eq!(d.len(), 23);
        assert_eq!(u32::from_le_bytes(d[..4].try_into().unwrap()), 3); // clen
        assert_eq!(u32::from_le_bytes(d[4..8].try_into().unwrap()), 4); // rlen
    }

    #[test]
    fn decode_roundtrip() {
        assert_eq!(decode_u64(&42u64.to_le_bytes()), Some(42));
        assert_eq!(decode_bool(&1u64.to_le_bytes()), Some(true));
        assert_eq!(decode_bool(&0u64.to_le_bytes()), Some(false));

        let mut addr = [0xAA; 32];
        assert_eq!(decode_address(&addr), Some(addr));
    }

    #[test]
    fn decode_string_roundtrip() {
        let mut data = Vec::new();
        data.extend_from_slice(&5u64.to_le_bytes());
        data.extend_from_slice(b"hello");
        assert_eq!(decode_string(&data), Some("hello".to_string()));
    }
}
