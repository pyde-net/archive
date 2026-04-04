use crate::client::Provider;
use crate::contract::compute_selector;
use crate::error::{Result, SdkError};
use crate::types::{Address, Receipt};
use crate::wallet::Wallet;
use std::collections::HashMap;

// ============================================================================
// Value enum — dynamically typed return values
// ============================================================================

#[derive(Debug, Clone)]
pub enum Value {
    U64(u64),
    I64(i64),
    U128(u128),
    I128(i128),
    U256(ethnum::U256),
    Bool(bool),
    Address([u8; 32]),
    String(String),
    Bytes(Vec<u8>),
    Vec(Vec<Value>),
    Struct(HashMap<String, Value>),
    Enum(String),
    Unit,
}

impl Value {
    pub fn as_u64(&self) -> Option<u64> { if let Value::U64(v) = self { Some(*v) } else { None } }
    pub fn as_i64(&self) -> Option<i64> { if let Value::I64(v) = self { Some(*v) } else { None } }
    pub fn as_u128(&self) -> Option<u128> { if let Value::U128(v) = self { Some(*v) } else { None } }
    pub fn as_u256(&self) -> Option<ethnum::U256> { if let Value::U256(v) = self { Some(*v) } else { None } }
    pub fn as_bool(&self) -> Option<bool> { if let Value::Bool(v) = self { Some(*v) } else { None } }
    pub fn as_address(&self) -> Option<&[u8; 32]> { if let Value::Address(v) = self { Some(v) } else { None } }
    pub fn as_string(&self) -> Option<&str> { if let Value::String(v) = self { Some(v) } else { None } }
    pub fn as_bytes(&self) -> Option<&[u8]> { if let Value::Bytes(v) = self { Some(v) } else { None } }
    pub fn as_vec(&self) -> Option<&[Value]> { if let Value::Vec(v) = self { Some(v) } else { None } }
    pub fn as_struct(&self) -> Option<&HashMap<String, Value>> { if let Value::Struct(v) = self { Some(v) } else { None } }
    pub fn as_enum(&self) -> Option<&str> { if let Value::Enum(v) = self { Some(v) } else { None } }
    pub fn field(&self, name: &str) -> Option<&Value> { self.as_struct().and_then(|m| m.get(name)) }
    pub fn index(&self, i: usize) -> Option<&Value> { self.as_vec().and_then(|v| v.get(i)) }
}

// ============================================================================
// ABI types
// ============================================================================

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AbiFunction {
    pub name: String,
    #[serde(default)]
    pub params: Vec<AbiParam>,
    #[serde(default, alias = "returnType", alias = "returns")]
    pub returns: String,
    #[serde(default)]
    pub view: bool,
    #[serde(default)]
    pub constructor: bool,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AbiParam {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AbiStructDef {
    pub name: String,
    pub fields: Vec<AbiParam>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AbiEnumDef {
    pub name: String,
    pub variants: Vec<AbiEnumVariant>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AbiEnumVariant {
    pub name: String,
    pub discriminant: u32,
}

// ============================================================================
// Contract — ABI-aware interface
// ============================================================================

pub struct Contract<'a> {
    address: Address,
    provider: &'a Provider,
    wallet: Option<&'a Wallet>,
    functions: HashMap<String, AbiFunction>,
    structs: HashMap<String, AbiStructDef>,
    enums: HashMap<String, AbiEnumDef>,
}

impl<'a> Contract<'a> {
    /// Load from a build artifact JSON file.
    pub fn from_artifact(path: &str, address: Address, provider: &'a Provider) -> Result<Self> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| SdkError::InvalidResponse(format!("read artifact: {}", e)))?;
        Self::from_json(&json, address, provider)
    }

    /// Load from ABI JSON string.
    pub fn from_json(json: &str, address: Address, provider: &'a Provider) -> Result<Self> {
        let artifact: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| SdkError::InvalidResponse(format!("parse: {}", e)))?;

        let abi = artifact.get("abi").unwrap_or(&artifact);
        let mut functions = HashMap::new();
        let mut structs = HashMap::new();
        let mut enums = HashMap::new();

        if let Some(fns) = abi.get("functions").and_then(|v| v.as_array()) {
            for f in fns {
                if let Ok(func) = serde_json::from_value::<AbiFunction>(f.clone()) {
                    functions.insert(func.name.clone(), func);
                }
            }
        }
        if let Some(ss) = abi.get("structs").and_then(|v| v.as_array()) {
            for s in ss {
                if let Ok(def) = serde_json::from_value::<AbiStructDef>(s.clone()) {
                    structs.insert(def.name.clone(), def);
                }
            }
        }
        if let Some(es) = abi.get("enums").and_then(|v| v.as_array()) {
            for e in es {
                if let Ok(def) = serde_json::from_value::<AbiEnumDef>(e.clone()) {
                    enums.insert(def.name.clone(), def);
                }
            }
        }

        Ok(Self { address, provider, wallet: None, functions, structs, enums })
    }

    /// Create minimal contract (no ABI).
    pub fn new(address: Address, provider: &'a Provider) -> Self {
        Self { address, provider, wallet: None, functions: HashMap::new(), structs: HashMap::new(), enums: HashMap::new() }
    }

    /// Bind a wallet for write operations.
    pub fn connect(mut self, wallet: &'a Wallet) -> Self {
        self.wallet = Some(wallet);
        self
    }

    pub fn address(&self) -> &Address { &self.address }

    // ========================================================================
    // Read
    // ========================================================================

    /// Call a view function. Auto-encodes args, auto-decodes return.
    pub async fn read(&self, method: &str, args: &serde_json::Value) -> Result<Value> {
        let calldata = self.encode_call(method, args)?;
        let result = self.provider.call(&self.address, &calldata).await?;
        let fn_def = self.functions.get(method);
        let ret_type = fn_def.map(|f| f.returns.as_str()).unwrap_or("u64");
        Ok(self.decode_value(&result, ret_type, 0).0)
    }

    // ========================================================================
    // Write
    // ========================================================================

    /// Send a state-changing tx. Validates args, encodes, signs, sends, waits.
    pub async fn write(&self, method: &str, args: &serde_json::Value, gas_limit: u64) -> Result<Receipt> {
        let wallet = self.wallet.ok_or_else(|| SdkError::Signing(
            "No wallet connected. Use contract.connect(&wallet) first.".into()
        ))?;
        let calldata = self.encode_call(method, args)?;
        wallet.send_call(self.provider, &self.address, calldata, gas_limit).await
    }

    // ========================================================================
    // Encode — args to calldata with validation
    // ========================================================================

    /// Encode a function call with named args from JSON. Validates types.
    pub fn encode_call(&self, method: &str, args: &serde_json::Value) -> Result<Vec<u8>> {
        let fn_def = self.functions.get(method)
            .ok_or_else(|| SdkError::InvalidResponse(format!("Unknown function '{}'", method)))?;

        let selector = compute_selector(method);
        let mut buf = selector.to_be_bytes().to_vec();

        for param in &fn_def.params {
            let value = args.get(&param.name).ok_or_else(|| SdkError::InvalidResponse(
                format!("{}(): missing required param '{}' ({})", method, param.name, param.ty)
            ))?;
            self.encode_value(&mut buf, value, &param.ty, &format!("{}().{}", method, param.name))?;
        }

        Ok(buf)
    }

    fn encode_value(&self, buf: &mut Vec<u8>, value: &serde_json::Value, ty: &str, path: &str) -> Result<()> {
        match ty {
            "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" => {
                let n = value.as_i64().or_else(|| value.as_u64().map(|v| v as i64))
                    .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected {}, got {:?}", path, ty, value)))?;
                self.validate_int_range(n as i128, ty, path)?;
                if ty.starts_with('i') {
                    buf.extend_from_slice(&(n as u64).to_le_bytes());
                } else {
                    buf.extend_from_slice(&(n as u64).to_le_bytes());
                }
            }
            "u128" | "i128" => {
                let n = parse_json_u128(value)
                    .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected {}", path, ty)))?;
                buf.extend_from_slice(&n.to_le_bytes());
            }
            "u256" | "i256" => {
                let n = parse_json_u128(value).unwrap_or(0) as u128;
                let val = ethnum::U256::from(n);
                buf.extend_from_slice(&val.to_le_bytes());
            }
            "bool" => {
                let b = value.as_bool()
                    .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected bool", path)))?;
                buf.extend_from_slice(&(b as u64).to_le_bytes());
            }
            "Address" => {
                let s = value.as_str()
                    .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected Address hex", path)))?;
                let addr = crate::types::parse_address(s)?;
                buf.extend_from_slice(&addr);
            }
            "String" => {
                let s = value.as_str()
                    .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected String", path)))?;
                let bytes = s.as_bytes();
                buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                buf.extend_from_slice(bytes);
                let pad = (8 - (bytes.len() % 8)) % 8;
                buf.extend(std::iter::repeat(0u8).take(pad));
            }
            _ if ty.starts_with("Vec<") && ty.ends_with('>') => {
                let arr = value.as_array()
                    .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected array for {}", path, ty)))?;
                let elem_type = &ty[4..ty.len() - 1];
                let mut elem_buf = Vec::new();
                for (i, v) in arr.iter().enumerate() {
                    self.encode_value(&mut elem_buf, v, elem_type, &format!("{}[{}]", path, i))?;
                }
                let data_len = 16 + elem_buf.len();
                buf.extend_from_slice(&(data_len as u64).to_le_bytes());
                buf.extend_from_slice(&(arr.len() as u64).to_le_bytes());
                buf.extend_from_slice(&(arr.len() as u64).to_le_bytes());
                buf.extend_from_slice(&elem_buf);
            }
            _ => {
                // Check structs
                if let Some(def) = self.structs.get(ty) {
                    let obj = value.as_object()
                        .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected object for struct {}", path, ty)))?;
                    let mut field_buf = Vec::new();
                    for field in &def.fields {
                        let fv = obj.get(&field.name)
                            .ok_or_else(|| SdkError::InvalidResponse(format!("{}: missing field '{}' for struct {}", path, field.name, ty)))?;
                        self.encode_value(&mut field_buf, fv, &field.ty, &format!("{}.{}", path, field.name))?;
                    }
                    buf.extend_from_slice(&(field_buf.len() as u64).to_le_bytes());
                    buf.extend_from_slice(&field_buf);
                }
                // Check enums
                else if let Some(def) = self.enums.get(ty) {
                    let variant_name = value.as_str()
                        .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected variant name for enum {}", path, ty)))?;
                    let variant = def.variants.iter().find(|v| v.name == variant_name)
                        .ok_or_else(|| SdkError::InvalidResponse(format!(
                            "{}: unknown variant '{}' for enum {}. Valid: {}",
                            path, variant_name, ty,
                            def.variants.iter().map(|v| v.name.as_str()).collect::<Vec<_>>().join(", ")
                        )))?;
                    buf.extend_from_slice(&(variant.discriminant as u64).to_le_bytes());
                } else {
                    return Err(SdkError::InvalidResponse(format!("{}: unsupported type '{}'", path, ty)));
                }
            }
        }
        Ok(())
    }

    fn validate_int_range(&self, n: i128, ty: &str, path: &str) -> Result<()> {
        let (min, max): (i128, i128) = match ty {
            "u8" => (0, 255), "u16" => (0, 65535), "u32" => (0, 4294967295), "u64" => (0, i64::MAX as i128),
            "i8" => (-128, 127), "i16" => (-32768, 32767), "i32" => (-2147483648, 2147483647), "i64" => (i64::MIN as i128, i64::MAX as i128),
            _ => return Ok(()),
        };
        if n < min || n > max {
            return Err(SdkError::InvalidResponse(format!("{}: value {} out of range for {} ({} to {})", path, n, ty, min, max)));
        }
        Ok(())
    }

    // ========================================================================
    // Decode
    // ========================================================================

    fn decode_value(&self, data: &[u8], ty: &str, offset: usize) -> (Value, usize) {
        match ty {
            "u8" | "u16" | "u32" | "u64" => {
                if data.len() < offset + 8 { return (Value::U64(0), 8); }
                (Value::U64(u64::from_le_bytes(data[offset..offset+8].try_into().unwrap())), 8)
            }
            "i8" | "i16" | "i32" | "i64" => {
                if data.len() < offset + 8 { return (Value::I64(0), 8); }
                (Value::I64(i64::from_le_bytes(data[offset..offset+8].try_into().unwrap())), 8)
            }
            "u128" => {
                if data.len() < offset + 16 { return (Value::U128(0), 16); }
                (Value::U128(u128::from_le_bytes(data[offset..offset+16].try_into().unwrap())), 16)
            }
            "u256" | "i256" => {
                if data.len() < offset + 32 { return (Value::U256(ethnum::U256::ZERO), 32); }
                (Value::U256(ethnum::U256::from_le_bytes(data[offset..offset+32].try_into().unwrap())), 32)
            }
            "bool" => {
                if data.len() < offset + 8 { return (Value::Bool(false), 8); }
                (Value::Bool(u64::from_le_bytes(data[offset..offset+8].try_into().unwrap()) != 0), 8)
            }
            "Address" => {
                if data.len() < offset + 32 { return (Value::Address([0u8; 32]), 32); }
                let mut addr = [0u8; 32];
                addr.copy_from_slice(&data[offset..offset+32]);
                (Value::Address(addr), 32)
            }
            "String" => {
                if data.len() < offset + 8 { return (Value::String(String::new()), 8); }
                let len = u64::from_le_bytes(data[offset..offset+8].try_into().unwrap()) as usize;
                let s = if data.len() >= offset + 8 + len {
                    std::string::String::from_utf8_lossy(&data[offset+8..offset+8+len]).to_string()
                } else { String::new() };
                let aligned = 8 + len + ((8 - (len % 8)) % 8);
                (Value::String(s), aligned)
            }
            _ if ty.starts_with("Vec<") && ty.ends_with('>') => {
                let elem_type = &ty[4..ty.len()-1];
                if data.len() < offset + 24 { return (Value::Vec(vec![]), 24); }
                let byte_len = u64::from_le_bytes(data[offset..offset+8].try_into().unwrap()) as usize;
                let count = u64::from_le_bytes(data[offset+8..offset+16].try_into().unwrap()) as usize;
                let mut cursor = offset + 24;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    let (val, read) = self.decode_value(data, elem_type, cursor);
                    items.push(val);
                    cursor += read;
                }
                (Value::Vec(items), 8 + byte_len)
            }
            _ => {
                if let Some(def) = self.structs.get(ty) {
                    if data.len() < offset + 8 { return (Value::Struct(HashMap::new()), 8); }
                    let byte_len = u64::from_le_bytes(data[offset..offset+8].try_into().unwrap()) as usize;
                    let mut cursor = offset + 8;
                    let mut fields = HashMap::new();
                    for field in &def.fields {
                        let (val, read) = self.decode_value(data, &field.ty, cursor);
                        fields.insert(field.name.clone(), val);
                        cursor += read;
                    }
                    (Value::Struct(fields), 8 + byte_len)
                } else if let Some(def) = self.enums.get(ty) {
                    if data.len() < offset + 8 { return (Value::Enum("".into()), 8); }
                    let disc = u64::from_le_bytes(data[offset..offset+8].try_into().unwrap()) as u32;
                    let name = def.variants.iter().find(|v| v.discriminant == disc)
                        .map(|v| v.name.clone()).unwrap_or_else(|| disc.to_string());
                    (Value::Enum(name), 8)
                } else if ty == "()" || ty == "unit" {
                    (Value::Unit, 0)
                } else {
                    (Value::Bytes(data[offset..].to_vec()), data.len() - offset)
                }
            }
        }
    }
}

fn parse_json_u128(v: &serde_json::Value) -> Option<u128> {
    v.as_u64().map(|n| n as u128)
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_abi_json() -> String {
        serde_json::json!({
            "abi": {
                "functions": [
                    {"name":"get_count","params":[],"returns":"u64","view":true,"constructor":false},
                    {"name":"deposit","params":[{"name":"amount","type":"u64"}],"returns":"()","view":false,"constructor":false},
                    {"name":"set_user","params":[{"name":"user","type":"UserInfo"}],"returns":"()","view":false,"constructor":false},
                    {"name":"set_status","params":[{"name":"status","type":"Status"}],"returns":"()","view":false,"constructor":false},
                ],
                "structs": [{"name":"UserInfo","fields":[{"name":"name","type":"String"},{"name":"age","type":"u64"}]}],
                "enums": [{"name":"Status","variants":[{"name":"Active","discriminant":0},{"name":"Banned","discriminant":1}]}],
            }
        }).to_string()
    }

    fn dummy_provider() -> Provider { Provider::new("http://localhost:0") }

    #[test]
    fn encode_validates_missing_param() {
        let p = dummy_provider();
        let c = Contract::from_json(&test_abi_json(), [0; 32], &p).unwrap();
        let r = c.encode_call("deposit", &serde_json::json!({}));
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("missing required param"));
    }

    #[test]
    fn encode_validates_wrong_type() {
        let p = dummy_provider();
        let c = Contract::from_json(&test_abi_json(), [0; 32], &p).unwrap();
        let r = c.encode_call("deposit", &serde_json::json!({"amount": "not a number"}));
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("expected u64"));
    }

    #[test]
    fn encode_validates_int_range() {
        let p = dummy_provider();
        let c = Contract::from_json(&test_abi_json(), [0; 32], &p).unwrap();
        let r = c.encode_call("deposit", &serde_json::json!({"amount": -1}));
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("out of range"));
    }

    #[test]
    fn encode_u64_arg() {
        let p = dummy_provider();
        let c = Contract::from_json(&test_abi_json(), [0; 32], &p).unwrap();
        let data = c.encode_call("deposit", &serde_json::json!({"amount": 500})).unwrap();
        assert_eq!(data.len(), 12); // 4 selector + 8 u64
    }

    #[test]
    fn encode_struct_arg() {
        let p = dummy_provider();
        let c = Contract::from_json(&test_abi_json(), [0; 32], &p).unwrap();
        let data = c.encode_call("set_user", &serde_json::json!({"user": {"name": "alice", "age": 25}})).unwrap();
        assert!(data.len() > 12);
    }

    #[test]
    fn encode_validates_missing_struct_field() {
        let p = dummy_provider();
        let c = Contract::from_json(&test_abi_json(), [0; 32], &p).unwrap();
        let r = c.encode_call("set_user", &serde_json::json!({"user": {"name": "alice"}}));
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("missing field 'age'"));
    }

    #[test]
    fn encode_enum_by_name() {
        let p = dummy_provider();
        let c = Contract::from_json(&test_abi_json(), [0; 32], &p).unwrap();
        let data = c.encode_call("set_status", &serde_json::json!({"status": "Active"})).unwrap();
        assert_eq!(data.len(), 12);
    }

    #[test]
    fn encode_validates_unknown_enum_variant() {
        let p = dummy_provider();
        let c = Contract::from_json(&test_abi_json(), [0; 32], &p).unwrap();
        let r = c.encode_call("set_status", &serde_json::json!({"status": "Unknown"}));
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("unknown variant"));
    }

    #[test]
    fn decode_u64_value() {
        let p = dummy_provider();
        let c = Contract::new([0; 32], &p);
        let data = 42u64.to_le_bytes();
        let (v, _) = c.decode_value(&data, "u64", 0);
        assert_eq!(v.as_u64(), Some(42));
    }

    #[test]
    fn decode_string_value() {
        let p = dummy_provider();
        let c = Contract::new([0; 32], &p);
        let mut data = Vec::new();
        data.extend_from_slice(&5u64.to_le_bytes());
        data.extend_from_slice(b"hello\0\0\0");
        let (v, _) = c.decode_value(&data, "String", 0);
        assert_eq!(v.as_string(), Some("hello"));
    }

    #[test]
    fn decode_struct_value() {
        let p = dummy_provider();
        let json = test_abi_json();
        let c = Contract::from_json(&json, [0; 32], &p).unwrap();
        // Struct: [byte_len:8][name:String(8+5+3pad)][age:u64(8)]
        let mut data = Vec::new();
        let fields_len = 16 + 8; // string(16) + u64(8)
        data.extend_from_slice(&(fields_len as u64).to_le_bytes());
        data.extend_from_slice(&5u64.to_le_bytes()); // name len
        data.extend_from_slice(b"alice\0\0\0"); // name data (padded)
        data.extend_from_slice(&25u64.to_le_bytes()); // age
        let (v, _) = c.decode_value(&data, "UserInfo", 0);
        assert_eq!(v.field("name").and_then(|v| v.as_string()), Some("alice"));
        assert_eq!(v.field("age").and_then(|v| v.as_u64()), Some(25));
    }

    #[test]
    fn decode_enum_value() {
        let p = dummy_provider();
        let json = test_abi_json();
        let c = Contract::from_json(&json, [0; 32], &p).unwrap();
        let data = 1u64.to_le_bytes();
        let (v, _) = c.decode_value(&data, "Status", 0);
        assert_eq!(v.as_enum(), Some("Banned"));
    }
}
