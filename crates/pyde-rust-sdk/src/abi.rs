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
    I256(ethnum::I256),
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
    pub fn as_i128(&self) -> Option<i128> { if let Value::I128(v) = self { Some(*v) } else { None } }
    pub fn as_u256(&self) -> Option<ethnum::U256> { if let Value::U256(v) = self { Some(*v) } else { None } }
    pub fn as_i256(&self) -> Option<ethnum::I256> { if let Value::I256(v) = self { Some(*v) } else { None } }
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
    pub payable: bool,
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

    /// Encode a single value by ABI type. Used by DeployData for constructor args.
    pub fn encode_value_public(&self, buf: &mut Vec<u8>, value: &serde_json::Value, ty: &str, path: &str) -> Result<()> {
        self.encode_value(buf, value, ty, path)
    }

    // ========================================================================
    // Read
    // ========================================================================

    /// Call a view function. Auto-encodes args, auto-decodes return.
    /// Pass `None` for functions that take no arguments.
    pub async fn read(&self, method: &str, args: Option<&serde_json::Value>) -> Result<Value> {
        let empty = serde_json::json!({});
        let calldata = self.encode_call(method, args.unwrap_or(&empty))?;
        let result = self.provider.call(&self.address, &calldata).await?;
        let fn_def = self.functions.get(method);
        let ret_type = fn_def.map(|f| f.returns.as_str()).unwrap_or("u64");
        Ok(self.decode_value(&result, ret_type, 0).0)
    }

    /// Static-call ANY function (view or setter) without sending a tx.
    /// Simulates execution and returns the decoded return value.
    pub async fn simulate(&self, method: &str, args: Option<&serde_json::Value>) -> Result<Value> {
        self.read(method, args).await
    }

    /// Estimate gas for a contract call using the ABI.
    pub async fn estimate_gas(&self, method: &str, args: Option<&serde_json::Value>) -> Result<u64> {
        let empty = serde_json::json!({});
        let calldata = self.encode_call(method, args.unwrap_or(&empty))?;
        self.provider.estimate_gas(&self.address, &calldata).await
    }

    // ========================================================================
    // Write
    // ========================================================================

    /// Send a state-changing tx. Validates args, encodes, signs, sends, waits.
    /// Pass `None` for functions that take no arguments.
    pub async fn write(&self, method: &str, args: Option<&serde_json::Value>, gas_limit: u64) -> Result<Receipt> {
        self.write_with_value(method, args, 0, gas_limit).await
    }

    /// Send a state-changing tx with native token value. Validates payable.
    pub async fn write_with_value(
        &self, method: &str, args: Option<&serde_json::Value>, value: u128, gas_limit: u64,
    ) -> Result<Receipt> {
        let wallet = self.wallet.ok_or_else(|| SdkError::Signing(
            "No wallet connected. Use contract.connect(&wallet) first.".into()
        ))?;
        // Validate payable
        if value > 0 {
            if let Some(fn_def) = self.functions.get(method) {
                if !fn_def.payable {
                    return Err(SdkError::InvalidResponse(format!(
                        "{}() is not payable — cannot send value", method
                    )));
                }
            }
        }
        let empty = serde_json::json!({});
        let calldata = self.encode_call(method, args.unwrap_or(&empty))?;
        wallet.send_call_with_value(self.provider, &self.address, calldata, value, gas_limit).await
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
            "u8" | "u16" | "u32" | "u64" => {
                let n = value.as_u64()
                    .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected {}, got {:?}", path, ty, value)))?;
                self.validate_uint_range(n, ty, path)?;
                buf.extend_from_slice(&n.to_le_bytes());
            }
            "i8" | "i16" | "i32" | "i64" => {
                let n = value.as_i64()
                    .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected {}, got {:?}", path, ty, value)))?;
                self.validate_int_range(n, ty, path)?;
                buf.extend_from_slice(&n.to_le_bytes());
            }
            "u128" => {
                let n = parse_json_u128(value)
                    .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected u128", path)))?;
                buf.extend_from_slice(&n.to_le_bytes());
            }
            "i128" => {
                let n = parse_json_i128(value)
                    .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected i128", path)))?;
                buf.extend_from_slice(&n.to_le_bytes());
            }
            "u256" => {
                let n = parse_json_u256(value)
                    .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected u256", path)))?;
                buf.extend_from_slice(&n.to_le_bytes());
            }
            "i256" => {
                let n = parse_json_i256(value)
                    .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected i256", path)))?;
                buf.extend_from_slice(&n.to_le_bytes());
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
            "Bytes" | "bytes" => {
                let s = value.as_str()
                    .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected hex string for Bytes", path)))?;
                let hex = s.trim_start_matches("0x");
                let bytes = ::hex::decode(hex)
                    .map_err(|e| SdkError::InvalidResponse(format!("{}: bad hex for Bytes: {}", path, e)))?;
                buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                buf.extend_from_slice(&bytes);
                let pad = (8 - (bytes.len() % 8)) % 8;
                buf.extend(std::iter::repeat(0u8).take(pad));
            }
            // Tuple "(T1, T2, ...)" — sequential fields, no length prefix
            _ if ty.starts_with('(') && ty.ends_with(')') => {
                let inner = &ty[1..ty.len() - 1];
                if inner.is_empty() || inner == "()" {
                    // Unit tuple — no bytes
                } else {
                    let types = parse_tuple_types(inner);
                    let arr = value.as_array()
                        .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected array for tuple {}", path, ty)))?;
                    if arr.len() != types.len() {
                        return Err(SdkError::InvalidResponse(format!(
                            "{}: tuple {} expects {} elements, got {}", path, ty, types.len(), arr.len()
                        )));
                    }
                    for (i, (v, t)) in arr.iter().zip(types.iter()).enumerate() {
                        self.encode_value(buf, v, t, &format!("{}.{}", path, i))?;
                    }
                }
            }
            // Array "[T; N]" — N sequential elements, no length prefix
            _ if ty.starts_with('[') && ty.ends_with(']') => {
                let inner = &ty[1..ty.len() - 1];
                let (elem_type, count) = parse_array_type(inner)
                    .ok_or_else(|| SdkError::InvalidResponse(format!("{}: bad array type '{}'", path, ty)))?;
                let arr = value.as_array()
                    .ok_or_else(|| SdkError::InvalidResponse(format!("{}: expected array for {}", path, ty)))?;
                if arr.len() != count {
                    return Err(SdkError::InvalidResponse(format!(
                        "{}: array {} expects {} elements, got {}", path, ty, count, arr.len()
                    )));
                }
                for (i, v) in arr.iter().enumerate() {
                    self.encode_value(buf, v, elem_type, &format!("{}[{}]", path, i))?;
                }
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
                }
                // Unknown type name → treat as Address (Contract/Interface types are addresses)
                else if let Some(s) = value.as_str() {
                    let addr = crate::types::parse_address(s)
                        .map_err(|_| SdkError::InvalidResponse(format!(
                            "{}: unknown type '{}', tried as Address but got invalid hex", path, ty
                        )))?;
                    buf.extend_from_slice(&addr);
                } else {
                    return Err(SdkError::InvalidResponse(format!("{}: unsupported type '{}'", path, ty)));
                }
            }
        }
        Ok(())
    }

    fn validate_uint_range(&self, n: u64, ty: &str, path: &str) -> Result<()> {
        let max: u64 = match ty {
            "u8" => 255, "u16" => 65535, "u32" => 4294967295, "u64" => u64::MAX,
            _ => return Ok(()),
        };
        if n > max {
            return Err(SdkError::InvalidResponse(format!("{}: value {} out of range for {} (0 to {})", path, n, ty, max)));
        }
        Ok(())
    }

    fn validate_int_range(&self, n: i64, ty: &str, path: &str) -> Result<()> {
        let (min, max): (i64, i64) = match ty {
            "i8" => (-128, 127), "i16" => (-32768, 32767),
            "i32" => (-2147483648, 2147483647), "i64" => (i64::MIN, i64::MAX),
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
            "i128" => {
                if data.len() < offset + 16 { return (Value::I128(0), 16); }
                (Value::I128(i128::from_le_bytes(data[offset..offset+16].try_into().unwrap())), 16)
            }
            "u256" => {
                if data.len() < offset + 32 { return (Value::U256(ethnum::U256::ZERO), 32); }
                (Value::U256(ethnum::U256::from_le_bytes(data[offset..offset+32].try_into().unwrap())), 32)
            }
            "i256" => {
                if data.len() < offset + 32 { return (Value::I256(ethnum::I256::ZERO), 32); }
                (Value::I256(ethnum::I256::from_le_bytes(data[offset..offset+32].try_into().unwrap())), 32)
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
                let end = match (offset + 8).checked_add(len) {
                    Some(e) if e <= data.len() => e,
                    _ => return (Value::String(String::new()), 8),
                };
                let s = std::string::String::from_utf8_lossy(&data[offset+8..end]).to_string();
                let aligned = 8 + len + ((8 - (len % 8)) % 8);
                (Value::String(s), aligned)
            }
            "Bytes" | "bytes" => {
                if data.len() < offset + 8 { return (Value::Bytes(vec![]), 8); }
                let len = u64::from_le_bytes(data[offset..offset+8].try_into().unwrap()) as usize;
                let end = match (offset + 8).checked_add(len) {
                    Some(e) if e <= data.len() => e,
                    _ => return (Value::Bytes(vec![]), 8),
                };
                let bytes = data[offset+8..end].to_vec();
                let aligned = 8 + len + ((8 - (len % 8)) % 8);
                (Value::Bytes(bytes), aligned)
            }
            // Tuple "(T1, T2, ...)" — sequential decode
            _ if ty.starts_with('(') && ty.ends_with(')') => {
                let inner = &ty[1..ty.len()-1];
                if inner.is_empty() || inner == "()" {
                    (Value::Unit, 0)
                } else {
                    let types = parse_tuple_types(inner);
                    let mut cursor = offset;
                    let mut items = Vec::with_capacity(types.len());
                    for t in &types {
                        let (val, read) = self.decode_value(data, t, cursor);
                        items.push(val);
                        cursor += read;
                    }
                    (Value::Vec(items), cursor - offset)
                }
            }
            // Array "[T; N]" — N sequential elements
            _ if ty.starts_with('[') && ty.ends_with(']') => {
                let inner = &ty[1..ty.len()-1];
                if let Some((elem_type, count)) = parse_array_type(inner) {
                    let mut cursor = offset;
                    let mut items = Vec::with_capacity(count);
                    for _ in 0..count {
                        if cursor >= data.len() { break; }
                        let (val, read) = self.decode_value(data, elem_type, cursor);
                        items.push(val);
                        cursor += read;
                    }
                    (Value::Vec(items), cursor - offset)
                } else {
                    (Value::Bytes(data[offset..].to_vec()), data.len() - offset)
                }
            }
            _ if ty.starts_with("Vec<") && ty.ends_with('>') => {
                let elem_type = &ty[4..ty.len()-1];
                if data.len() < offset + 24 { return (Value::Vec(vec![]), 24); }
                let byte_len = u64::from_le_bytes(data[offset..offset+8].try_into().unwrap()) as usize;
                let count = u64::from_le_bytes(data[offset+8..offset+16].try_into().unwrap()) as usize;
                // Clamp count to prevent OOM from malformed data
                let max_elems = data.len().saturating_sub(offset + 24);
                let safe_count = count.min(max_elems);
                let mut cursor = offset + 24;
                let mut items = Vec::with_capacity(safe_count);
                for _ in 0..safe_count {
                    if cursor >= data.len() { break; }
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
                    // Unknown type (Contract/Interface) → decode as Address (32 bytes)
                    if data.len() >= offset + 32 {
                        let mut addr = [0u8; 32];
                        addr.copy_from_slice(&data[offset..offset+32]);
                        (Value::Address(addr), 32)
                    } else {
                        (Value::Bytes(data[offset..].to_vec()), data.len() - offset)
                    }
                }
            }
        }
    }
}

/// Parse comma-separated tuple types, handling nested generics.
/// e.g. "u64, Vec<String>, (u8, bool)" → ["u64", "Vec<String>", "(u8, bool)"]
fn parse_tuple_types(s: &str) -> Vec<&str> {
    let mut types = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                let t = s[start..i].trim();
                if !t.is_empty() { types.push(t); }
                start = i + 1;
            }
            _ => {}
        }
    }
    let t = s[start..].trim();
    if !t.is_empty() { types.push(t); }
    types
}

/// Parse "[T; N]" inner string → (element_type, count).
/// e.g. "u64; 3" → Some(("u64", 3))
fn parse_array_type(s: &str) -> Option<(&str, usize)> {
    let semi = s.rfind(';')?;
    let elem = s[..semi].trim();
    let count_str = s[semi + 1..].trim();
    let count = count_str.parse().ok()?;
    Some((elem, count))
}

fn parse_json_u128(v: &serde_json::Value) -> Option<u128> {
    v.as_u64().map(|n| n as u128)
        .or_else(|| v.as_str().and_then(|s| {
            if let Some(hex) = s.strip_prefix("0x") {
                u128::from_str_radix(hex, 16).ok()
            } else {
                s.parse().ok()
            }
        }))
}

fn parse_json_i128(v: &serde_json::Value) -> Option<i128> {
    v.as_i64().map(|n| n as i128)
        .or_else(|| v.as_u64().map(|n| n as i128))
        .or_else(|| v.as_str().and_then(|s| {
            if let Some(hex) = s.strip_prefix("0x") {
                u128::from_str_radix(hex, 16).ok().map(|n| n as i128)
            } else {
                s.parse().ok()
            }
        }))
}

fn parse_json_u256(v: &serde_json::Value) -> Option<ethnum::U256> {
    v.as_u64().map(|n| ethnum::U256::from(n))
        .or_else(|| v.as_str().and_then(|s| {
            if let Some(hex) = s.strip_prefix("0x") {
                ethnum::U256::from_str_radix(hex, 16).ok()
            } else {
                s.parse::<ethnum::U256>().ok()
            }
        }))
}

fn parse_json_i256(v: &serde_json::Value) -> Option<ethnum::I256> {
    v.as_i64().map(|n| ethnum::I256::from(n))
        .or_else(|| v.as_u64().map(|n| ethnum::I256::from(n as i128)))
        .or_else(|| v.as_str().and_then(|s| {
            if let Some(hex) = s.strip_prefix("0x") {
                ethnum::U256::from_str_radix(hex, 16).ok().map(|n| ethnum::I256::from_le_bytes(n.to_le_bytes()))
            } else {
                s.parse::<ethnum::I256>().ok()
            }
        }))
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
        // Negative value for u64 → rejected as not a valid u64
        let r = c.encode_call("deposit", &serde_json::json!({"amount": -1}));
        assert!(r.is_err());
        let err = r.unwrap_err().to_string();
        assert!(err.contains("expected u64") || err.contains("out of range"), "got: {}", err);
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

    #[test]
    fn encode_u64_full_range() {
        // u64::MAX should be accepted (was previously capped at i64::MAX)
        let p = dummy_provider();
        let json = test_abi_json();
        let c = Contract::from_json(&json, [0; 32], &p).unwrap();
        let r = c.encode_call("deposit", &serde_json::json!({"amount": u64::MAX}));
        assert!(r.is_ok());
        let data = r.unwrap();
        let val = u64::from_le_bytes(data[4..12].try_into().unwrap());
        assert_eq!(val, u64::MAX);
    }

    #[test]
    fn encode_decode_i128() {
        let p = dummy_provider();
        let json = serde_json::json!({
            "abi": {
                "functions": [{"name":"set","params":[{"name":"v","type":"i128"}],"returns":"i128","view":false}],
                "structs": [], "enums": [],
            }
        }).to_string();
        let c = Contract::from_json(&json, [0; 32], &p).unwrap();
        // Encode negative i128
        let data = c.encode_call("set", &serde_json::json!({"v": -500})).unwrap();
        // Decode it back
        let (val, _) = c.decode_value(&data[4..], "i128", 0);
        assert_eq!(val.as_i128(), Some(-500));
    }

    #[test]
    fn encode_decode_u256() {
        let p = dummy_provider();
        let json = serde_json::json!({
            "abi": {
                "functions": [{"name":"set","params":[{"name":"v","type":"u256"}],"returns":"u256","view":false}],
                "structs": [], "enums": [],
            }
        }).to_string();
        let c = Contract::from_json(&json, [0; 32], &p).unwrap();
        // u256 from hex string (above u128 range)
        let big = "340282366920938463463374607431768211456"; // 2^128
        let data = c.encode_call("set", &serde_json::json!({"v": big})).unwrap();
        let (val, _) = c.decode_value(&data[4..], "u256", 0);
        assert_eq!(val.as_u256(), Some(ethnum::U256::from(1u128) << 128));
    }

    #[test]
    fn encode_decode_i256_negative() {
        let p = dummy_provider();
        let json = serde_json::json!({
            "abi": {
                "functions": [{"name":"set","params":[{"name":"v","type":"i256"}],"returns":"i256","view":false}],
                "structs": [], "enums": [],
            }
        }).to_string();
        let c = Contract::from_json(&json, [0; 32], &p).unwrap();
        let data = c.encode_call("set", &serde_json::json!({"v": -1})).unwrap();
        let (val, _) = c.decode_value(&data[4..], "i256", 0);
        assert_eq!(val.as_i256(), Some(ethnum::I256::from(-1i64)));
    }

    #[test]
    fn u128_rejects_negative() {
        let p = dummy_provider();
        let json = serde_json::json!({
            "abi": {
                "functions": [{"name":"set","params":[{"name":"v","type":"u128"}],"returns":"()","view":false}],
                "structs": [], "enums": [],
            }
        }).to_string();
        let c = Contract::from_json(&json, [0; 32], &p).unwrap();
        let r = c.encode_call("set", &serde_json::json!({"v": -1}));
        assert!(r.is_err());
    }

    #[test]
    fn encode_tuple() {
        let p = dummy_provider();
        let json = serde_json::json!({
            "abi": {
                "functions": [{"name":"set","params":[{"name":"pair","type":"(u64, bool)"}],"returns":"()","view":false}],
                "structs": [], "enums": [],
            }
        }).to_string();
        let c = Contract::from_json(&json, [0; 32], &p).unwrap();
        let data = c.encode_call("set", &serde_json::json!({"pair": [42, true]})).unwrap();
        assert_eq!(data.len(), 4 + 8 + 8); // selector + u64 + bool
    }

    #[test]
    fn encode_decode_array() {
        let p = dummy_provider();
        let json = serde_json::json!({
            "abi": {
                "functions": [{"name":"set","params":[{"name":"arr","type":"[u64; 3]"}],"returns":"[u64; 3]","view":false}],
                "structs": [], "enums": [],
            }
        }).to_string();
        let c = Contract::from_json(&json, [0; 32], &p).unwrap();
        let data = c.encode_call("set", &serde_json::json!({"arr": [10, 20, 30]})).unwrap();
        assert_eq!(data.len(), 4 + 3 * 8); // selector + 3 u64s
        // Decode it back
        let (val, _) = c.decode_value(&data[4..], "[u64; 3]", 0);
        let items = val.as_vec().unwrap();
        assert_eq!(items[0].as_u64(), Some(10));
        assert_eq!(items[2].as_u64(), Some(30));
    }

    #[test]
    fn encode_array_wrong_length() {
        let p = dummy_provider();
        let json = serde_json::json!({
            "abi": {
                "functions": [{"name":"set","params":[{"name":"arr","type":"[u64; 3]"}],"returns":"()","view":false}],
                "structs": [], "enums": [],
            }
        }).to_string();
        let c = Contract::from_json(&json, [0; 32], &p).unwrap();
        let r = c.encode_call("set", &serde_json::json!({"arr": [10, 20]}));
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("expects 3 elements"));
    }

    #[test]
    fn encode_unknown_type_as_address() {
        let p = dummy_provider();
        let json = serde_json::json!({
            "abi": {
                "functions": [{"name":"set","params":[{"name":"c","type":"MyContract"}],"returns":"()","view":false}],
                "structs": [], "enums": [],
            }
        }).to_string();
        let c = Contract::from_json(&json, [0; 32], &p).unwrap();
        let addr = format!("0x{}", "cc".repeat(32));
        let data = c.encode_call("set", &serde_json::json!({"c": addr})).unwrap();
        assert_eq!(data.len(), 4 + 32); // selector + address
    }
}
