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

    /// Unsigned 8-bit integer. Range: 0 to 255. Encoded as 8 bytes LE (zero-extended).
    /// ```rust,ignore
    /// ContractCall::new("set_level").arg_u8(100).build();
    /// ```
    pub fn arg_u8(self, val: u8) -> Self { self.arg_u64(val as u64) }

    /// Unsigned 16-bit integer. Range: 0 to 65,535. Encoded as 8 bytes LE.
    /// ```rust,ignore
    /// ContractCall::new("set_port").arg_u16(8080).build();
    /// ```
    pub fn arg_u16(self, val: u16) -> Self { self.arg_u64(val as u64) }

    /// Unsigned 32-bit integer. Range: 0 to 4,294,967,295. Encoded as 8 bytes LE.
    /// ```rust,ignore
    /// ContractCall::new("set_count").arg_u32(1_000_000).build();
    /// ```
    pub fn arg_u32(self, val: u32) -> Self { self.arg_u64(val as u64) }

    /// Unsigned 64-bit integer. Range: 0 to 18,446,744,073,709,551,615. Encoded as 8 bytes LE.
    /// ```rust,ignore
    /// ContractCall::new("deposit").arg_u64(500).build();
    /// ```
    pub fn arg_u64(mut self, val: u64) -> Self {
        self.args.extend_from_slice(&val.to_le_bytes());
        self
    }

    /// Signed 8-bit integer. Range: -128 to 127. Sign-extended to 8 bytes LE.
    /// ```rust,ignore
    /// ContractCall::new("set_offset").arg_i8(-1).build();
    /// ```
    pub fn arg_i8(self, val: i8) -> Self { self.arg_u64(val as i64 as u64) }

    /// Signed 16-bit integer. Range: -32,768 to 32,767. Sign-extended to 8 bytes LE.
    /// ```rust,ignore
    /// ContractCall::new("set_delta").arg_i16(-500).build();
    /// ```
    pub fn arg_i16(self, val: i16) -> Self { self.arg_u64(val as i64 as u64) }

    /// Signed 32-bit integer. Range: -2,147,483,648 to 2,147,483,647. Sign-extended to 8 bytes LE.
    /// ```rust,ignore
    /// ContractCall::new("set_balance").arg_i32(-1_000_000).build();
    /// ```
    pub fn arg_i32(self, val: i32) -> Self { self.arg_u64(val as i64 as u64) }

    /// Signed 64-bit integer. Range: -9,223,372,036,854,775,808 to 9,223,372,036,854,775,807.
    /// Encoded as 8 bytes LE (two's complement).
    /// ```rust,ignore
    /// ContractCall::new("set_reward").arg_i64(-42).build();
    /// ```
    pub fn arg_i64(self, val: i64) -> Self { self.arg_u64(val as u64) }

    /// Boolean. Encoded as u64: true = 1, false = 0.
    /// ```rust,ignore
    /// ContractCall::new("set_active").arg_bool(true).build();
    /// ```
    pub fn arg_bool(mut self, val: bool) -> Self {
        self.args.extend_from_slice(&(val as u64).to_le_bytes());
        self
    }

    /// Unsigned 128-bit integer. Range: 0 to 2^128 - 1. Encoded as 16 bytes LE.
    /// ```rust,ignore
    /// ContractCall::new("set_supply").arg_u128(1_000_000_000_000_000_000).build();
    /// ```
    pub fn arg_u128(mut self, val: u128) -> Self {
        self.args.extend_from_slice(&val.to_le_bytes());
        self
    }

    /// Signed 128-bit integer. Range: -2^127 to 2^127 - 1. Encoded as 16 bytes LE.
    /// ```rust,ignore
    /// ContractCall::new("set_delta").arg_i128(-500_000_000_000).build();
    /// ```
    pub fn arg_i128(mut self, val: i128) -> Self {
        self.args.extend_from_slice(&val.to_le_bytes());
        self
    }

    /// Unsigned 256-bit integer. Range: 0 to 2^256 - 1. Encoded as 32 bytes LE.
    /// ```rust,ignore
    /// ContractCall::new("set_amount").arg_u256(U256::from(99u64)).build();
    /// ```
    pub fn arg_u256(mut self, val: ethnum::U256) -> Self {
        self.args.extend_from_slice(&val.to_le_bytes());
        self
    }

    /// Signed 256-bit integer. Range: -2^255 to 2^255 - 1. Encoded as 32 bytes LE.
    /// ```rust,ignore
    /// ContractCall::new("set_price").arg_i256(I256::from(-1i64)).build();
    /// ```
    pub fn arg_i256(mut self, val: ethnum::I256) -> Self {
        self.args.extend_from_slice(&val.to_le_bytes());
        self
    }

    /// 32-byte address. Encoded as raw 32 bytes.
    /// ```rust,ignore
    /// ContractCall::new("set_owner").arg_address(addr).build();
    /// ```
    pub fn arg_address(mut self, val: Address) -> Self {
        self.args.extend_from_slice(&val);
        self
    }

    /// Raw bytes. Appended directly (no length prefix).
    /// For length-prefixed bytes, use `arg_string` or encode manually.
    /// ```rust,ignore
    /// ContractCall::new("set_data").arg_bytes(&[0xDE, 0xAD]).build();
    /// ```
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

    /// Encode a Vec<u64> argument: [byte_len:8][count:8][cap:8][elements...].
    pub fn arg_vec_u64(mut self, vals: &[u64]) -> Self {
        let data_len = 16 + vals.len() * 8; // count(8) + cap(8) + elements
        self.args.extend_from_slice(&(data_len as u64).to_le_bytes()); // byte_len
        self.args.extend_from_slice(&(vals.len() as u64).to_le_bytes()); // count
        self.args.extend_from_slice(&(vals.len() as u64).to_le_bytes()); // cap
        for v in vals {
            self.args.extend_from_slice(&v.to_le_bytes());
        }
        self
    }

    /// Encode a Vec<bool> argument.
    pub fn arg_vec_bool(self, vals: &[bool]) -> Self {
        let u64_vals: Vec<u64> = vals.iter().map(|b| *b as u64).collect();
        self.arg_vec_u64(&u64_vals)
    }

    /// Encode a Vec<Address> argument: [byte_len:8][count:8][cap:8][addr0:32][addr1:32]...
    pub fn arg_vec_address(mut self, vals: &[[u8; 32]]) -> Self {
        let data_len = 16 + vals.len() * 32;
        self.args.extend_from_slice(&(data_len as u64).to_le_bytes());
        self.args.extend_from_slice(&(vals.len() as u64).to_le_bytes());
        self.args.extend_from_slice(&(vals.len() as u64).to_le_bytes());
        for v in vals {
            self.args.extend_from_slice(v);
        }
        self
    }

    /// Encode a generic Vec: [byte_len:8][count:8][cap:8][elements...].
    /// The closure writes all element data using any arg_* methods.
    /// Works with any element type including strings, structs, nested vecs.
    ///
    /// ```rust,ignore
    /// // Vec of strings
    /// .arg_vec_of(2, |b| b.arg_string("alice").arg_string("bob"))
    ///
    /// // Vec of structs
    /// .arg_vec_of(2, |b| b
    ///     .arg_struct(|s| s.arg_string("alice").arg_u64(25))
    ///     .arg_struct(|s| s.arg_string("bob").arg_u64(30)))
    ///
    /// // Vec of vecs (nested)
    /// .arg_vec_of(2, |b| b
    ///     .arg_vec_u64(&[1, 2, 3])
    ///     .arg_vec_u64(&[4, 5]))
    /// ```
    pub fn arg_vec_of(mut self, count: usize, build_fn: impl FnOnce(ContractCall) -> ContractCall) -> Self {
        let inner = build_fn(ContractCall::new("_vec_"));
        let elements = &inner.args;
        let data_len = 16 + elements.len(); // count(8) + cap(8) + elements
        self.args.extend_from_slice(&(data_len as u64).to_le_bytes()); // byte_len
        self.args.extend_from_slice(&(count as u64).to_le_bytes());    // count
        self.args.extend_from_slice(&(count as u64).to_le_bytes());    // cap
        self.args.extend_from_slice(elements);
        self
    }

    /// Encode a struct argument: [byte_len:8][field0][field1]...
    /// Build the struct fields using a closure that writes to a nested ContractCall.
    pub fn arg_struct(mut self, build_fn: impl FnOnce(ContractCall) -> ContractCall) -> Self {
        let inner = build_fn(ContractCall::new("_struct_"));
        let fields = &inner.args;
        self.args.extend_from_slice(&(fields.len() as u64).to_le_bytes()); // byte_len
        self.args.extend_from_slice(fields);
        self
    }

    /// Encode a tuple: sequential fields with no length prefix.
    pub fn arg_tuple(mut self, build_fn: impl FnOnce(ContractCall) -> ContractCall) -> Self {
        let inner = build_fn(ContractCall::new("_tuple_"));
        self.args.extend_from_slice(&inner.args);
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
/// // From artifact with named constructor args (recommended)
/// let data = DeployData::from_artifact("out/Counter.json", &json!({
///     "initial_supply": 1000,
///     "name": "MyToken"
/// }))?.build();
///
/// // From raw bytecodes with manual args
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

    /// Load from artifact JSON file with ABI-validated constructor args.
    /// Pass empty json!({}) if the constructor takes no args.
    pub fn from_artifact(path: &str, args: &serde_json::Value) -> std::result::Result<Self, String> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| format!("read artifact: {}", e))?;
        Self::from_json(&json, args)
    }

    /// Load from artifact JSON string with ABI-validated constructor args.
    pub fn from_json(json: &str, args: &serde_json::Value) -> std::result::Result<Self, String> {
        let v: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| format!("parse artifact: {}", e))?;
        let constructor_hex = v.get("constructorBytecode")
            .and_then(|v| v.as_str())
            .ok_or("missing 'constructorBytecode' in artifact")?;
        let runtime_hex = v.get("deployedBytecode")
            .and_then(|v| v.as_str())
            .ok_or("missing 'deployedBytecode' in artifact")?;
        let constructor = hex::decode(constructor_hex.trim_start_matches("0x"))
            .map_err(|e| format!("bad constructor hex: {}", e))?;
        let runtime = hex::decode(runtime_hex.trim_start_matches("0x"))
            .map_err(|e| format!("bad runtime hex: {}", e))?;

        let mut deploy = Self::new(constructor, runtime);

        // Encode constructor args from ABI if available
        let abi = v.get("abi").unwrap_or(&v);
        if let Some(fns) = abi.get("functions").and_then(|v| v.as_array()) {
            if let Some(ctor) = fns.iter().find(|f| f.get("constructor").and_then(|v| v.as_bool()).unwrap_or(false)) {
                if let Some(params) = ctor.get("params").and_then(|v| v.as_array()) {
                    // Use a temporary Contract to leverage encode_value
                    let provider = crate::client::Provider::new("http://localhost:0");
                    let contract = crate::abi::Contract::from_json(json, [0u8; 32], &provider)
                        .map_err(|e| format!("parse ABI: {}", e))?;
                    for param in params {
                        let name = param.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let ty = param.get("type").and_then(|v| v.as_str()).unwrap_or("u64");
                        let val = args.get(name).ok_or_else(|| {
                            format!("constructor: missing arg '{}' ({})", name, ty)
                        })?;
                        contract.encode_value_public(&mut deploy.args, val, ty, &format!("constructor.{}", name))
                            .map_err(|e| format!("{}", e))?;
                    }
                }
            }
        }

        Ok(deploy)
    }

    // GP integers (8 bytes LE)
    pub fn arg_u8(self, val: u8) -> Self { self.arg_u64(val as u64) }
    pub fn arg_u16(self, val: u16) -> Self { self.arg_u64(val as u64) }
    pub fn arg_u32(self, val: u32) -> Self { self.arg_u64(val as u64) }
    pub fn arg_u64(mut self, val: u64) -> Self {
        self.args.extend_from_slice(&val.to_le_bytes());
        self
    }
    pub fn arg_i8(self, val: i8) -> Self { self.arg_u64(val as i64 as u64) }
    pub fn arg_i16(self, val: i16) -> Self { self.arg_u64(val as i64 as u64) }
    pub fn arg_i32(self, val: i32) -> Self { self.arg_u64(val as i64 as u64) }
    pub fn arg_i64(self, val: i64) -> Self { self.arg_u64(val as u64) }
    pub fn arg_bool(mut self, val: bool) -> Self {
        self.args.extend_from_slice(&(val as u64).to_le_bytes());
        self
    }
    // Wide integers
    pub fn arg_u128(mut self, val: u128) -> Self {
        self.args.extend_from_slice(&val.to_le_bytes());
        self
    }
    pub fn arg_i128(mut self, val: i128) -> Self {
        self.args.extend_from_slice(&val.to_le_bytes());
        self
    }
    pub fn arg_u256(mut self, val: ethnum::U256) -> Self {
        self.args.extend_from_slice(&val.to_le_bytes());
        self
    }
    pub fn arg_i256(mut self, val: ethnum::I256) -> Self {
        self.args.extend_from_slice(&val.to_le_bytes());
        self
    }
    // Address (32 bytes)
    pub fn arg_address(mut self, val: crate::types::Address) -> Self {
        self.args.extend_from_slice(&val);
        self
    }
    // String (length-prefixed, 8-byte aligned)
    pub fn arg_string(mut self, val: &str) -> Self {
        let bytes = val.as_bytes();
        self.args.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        self.args.extend_from_slice(bytes);
        let padding = (8 - (bytes.len() % 8)) % 8;
        self.args.extend(std::iter::repeat(0u8).take(padding));
        self
    }
    // Raw bytes
    pub fn arg_bytes(mut self, val: &[u8]) -> Self {
        self.args.extend_from_slice(val);
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

// Unsigned integers
pub fn decode_u64(data: &[u8]) -> Option<u64> {
    if data.len() < 8 { return None; }
    Some(u64::from_le_bytes(data[..8].try_into().ok()?))
}
pub fn decode_u128(data: &[u8]) -> Option<u128> {
    if data.len() < 16 { return None; }
    Some(u128::from_le_bytes(data[..16].try_into().ok()?))
}
pub fn decode_u256(data: &[u8]) -> Option<ethnum::U256> {
    if data.len() < 32 { return None; }
    Some(ethnum::U256::from_le_bytes(data[..32].try_into().ok()?))
}

// Signed integers
pub fn decode_i64(data: &[u8]) -> Option<i64> {
    if data.len() < 8 { return None; }
    Some(i64::from_le_bytes(data[..8].try_into().ok()?))
}
pub fn decode_i128(data: &[u8]) -> Option<i128> {
    if data.len() < 16 { return None; }
    Some(i128::from_le_bytes(data[..16].try_into().ok()?))
}
pub fn decode_i256(data: &[u8]) -> Option<ethnum::I256> {
    if data.len() < 32 { return None; }
    Some(ethnum::I256::from_le_bytes(data[..32].try_into().ok()?))
}

pub fn decode_bool(data: &[u8]) -> Option<bool> {
    decode_u64(data).map(|v| v != 0)
}

pub fn decode_address(data: &[u8]) -> Option<Address> {
    if data.len() < 32 { return None; }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&data[..32]);
    Some(addr)
}

/// Decode a length-prefixed string: [len:8 LE][utf8 bytes].
pub fn decode_string(data: &[u8]) -> Option<String> {
    let len = decode_u64(data)? as usize;
    let total = 8_usize.checked_add(len)?;
    if data.len() < total { return None; }
    String::from_utf8(data[8..total].to_vec()).ok()
}

/// Decode length-prefixed bytes: [len:8 LE][raw bytes].
pub fn decode_bytes(data: &[u8]) -> Option<Vec<u8>> {
    let len = decode_u64(data)? as usize;
    let total = 8_usize.checked_add(len)?;
    if data.len() < total { return None; }
    Some(data[8..total].to_vec())
}

/// Decode Vec<u64>: [byte_len:8][count:8][cap:8][elements...].
pub fn decode_vec_u64(data: &[u8]) -> Option<Vec<u64>> {
    if data.len() < 24 { return None; }
    let _byte_len = decode_u64(data)? as usize;
    let count = decode_u64(&data[8..])? as usize;
    // Clamp count against physically available data to prevent OOM/overflow
    let max_count = (data.len().saturating_sub(24)) / 8;
    if count > max_count { return None; }
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 24 + i * 8;
        result.push(u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?));
    }
    Some(result)
}

/// Decode Vec<bool>: same layout as Vec<u64>.
pub fn decode_vec_bool(data: &[u8]) -> Option<Vec<bool>> {
    decode_vec_u64(data).map(|v| v.into_iter().map(|x| x != 0).collect())
}

/// Decode Vec<Address>: [byte_len:8][count:8][cap:8][addr0:32][addr1:32]...
pub fn decode_vec_address(data: &[u8]) -> Option<Vec<Address>> {
    if data.len() < 24 { return None; }
    let _byte_len = decode_u64(data)? as usize;
    let count = decode_u64(&data[8..])? as usize;
    let max_count = (data.len().saturating_sub(24)) / 32;
    if count > max_count { return None; }
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 24 + i * 32;
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&data[offset..offset + 32]);
        result.push(addr);
    }
    Some(result)
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

        let addr = [0xAA; 32];
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
