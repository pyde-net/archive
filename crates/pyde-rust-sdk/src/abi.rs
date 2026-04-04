use crate::client::Provider;
use crate::contract::{compute_selector, ContractCall};
use crate::error::{Result, SdkError};
use crate::types::Address;
use std::collections::HashMap;

/// Dynamically typed return value from a contract read.
#[derive(Debug, Clone)]
pub enum Value {
    U64(u64),
    U128(u128),
    U256(ethnum::U256),
    Bool(bool),
    Address([u8; 32]),
    String(String),
    Bytes(Vec<u8>),
    Vec(Vec<Value>),
    Struct(HashMap<String, Value>),
    Unit,
}

impl Value {
    pub fn as_u64(&self) -> Option<u64> {
        if let Value::U64(v) = self { Some(*v) } else { None }
    }
    pub fn as_u128(&self) -> Option<u128> {
        if let Value::U128(v) = self { Some(*v) } else { None }
    }
    pub fn as_u256(&self) -> Option<ethnum::U256> {
        if let Value::U256(v) = self { Some(*v) } else { None }
    }
    pub fn as_bool(&self) -> Option<bool> {
        if let Value::Bool(v) = self { Some(*v) } else { None }
    }
    pub fn as_address(&self) -> Option<&[u8; 32]> {
        if let Value::Address(v) = self { Some(v) } else { None }
    }
    pub fn as_string(&self) -> Option<&str> {
        if let Value::String(v) = self { Some(v) } else { None }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        if let Value::Bytes(v) = self { Some(v) } else { None }
    }
    pub fn as_vec(&self) -> Option<&[Value]> {
        if let Value::Vec(v) = self { Some(v) } else { None }
    }
    pub fn as_struct(&self) -> Option<&HashMap<String, Value>> {
        if let Value::Struct(v) = self { Some(v) } else { None }
    }

    /// Access struct field by name.
    pub fn field(&self, name: &str) -> Option<&Value> {
        self.as_struct().and_then(|m| m.get(name))
    }

    /// Access vec element by index.
    pub fn index(&self, i: usize) -> Option<&Value> {
        self.as_vec().and_then(|v| v.get(i))
    }
}

/// ABI function signature (from build artifact JSON).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AbiFunction {
    pub name: String,
    pub selector: u32,
    #[serde(default)]
    pub params: Vec<AbiParam>,
    #[serde(default, rename = "returnType")]
    pub return_type: String,
    #[serde(default)]
    pub view: bool,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AbiParam {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
}

/// ABI-aware contract interface.
/// Loads function signatures from a build artifact and provides
/// auto-decoded reads and writes.
pub struct Contract<'a> {
    address: Address,
    provider: &'a Provider,
    functions: HashMap<String, AbiFunction>,
}

impl<'a> Contract<'a> {
    /// Load contract from a build artifact JSON file.
    pub fn from_artifact(
        artifact_path: &str,
        address: Address,
        provider: &'a Provider,
    ) -> Result<Self> {
        let content = std::fs::read_to_string(artifact_path)
            .map_err(|e| SdkError::InvalidResponse(format!("read artifact: {}", e)))?;
        Self::from_json(&content, address, provider)
    }

    /// Load contract from ABI JSON string.
    pub fn from_json(
        json: &str,
        address: Address,
        provider: &'a Provider,
    ) -> Result<Self> {
        let artifact: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| SdkError::InvalidResponse(format!("parse artifact: {}", e)))?;

        let mut functions = HashMap::new();

        // Parse from our artifact format: { "abi": { "functions": [...] } }
        if let Some(abi) = artifact.get("abi") {
            if let Some(fns) = abi.get("functions").and_then(|v| v.as_array()) {
                for f in fns {
                    if let Ok(func) = serde_json::from_value::<AbiFunction>(f.clone()) {
                        functions.insert(func.name.clone(), func);
                    }
                }
            }
        }

        // Also try flat format: { "functions": [...] }
        if functions.is_empty() {
            if let Some(fns) = artifact.get("functions").and_then(|v| v.as_array()) {
                for f in fns {
                    if let Ok(func) = serde_json::from_value::<AbiFunction>(f.clone()) {
                        functions.insert(func.name.clone(), func);
                    }
                }
            }
        }

        Ok(Self { address, provider, functions })
    }

    /// Create with manually specified functions (no artifact file needed).
    pub fn new(address: Address, provider: &'a Provider) -> Self {
        Self { address, provider, functions: HashMap::new() }
    }

    /// Register a function manually.
    pub fn add_function(&mut self, name: &str, return_type: &str, view: bool) {
        self.functions.insert(name.to_string(), AbiFunction {
            name: name.to_string(),
            selector: compute_selector(name),
            params: vec![],
            return_type: return_type.to_string(),
            view,
        });
    }

    /// Read-only call — auto-decodes return value based on ABI return type.
    pub async fn read(&self, method: &str, args: &[u8]) -> Result<Value> {
        let mut calldata = compute_selector(method).to_be_bytes().to_vec();
        calldata.extend_from_slice(args);

        let result = self.provider.call(&self.address, &calldata).await?;

        // Look up return type from ABI
        let ret_type = self.functions.get(method)
            .map(|f| f.return_type.as_str())
            .unwrap_or("u64");

        Ok(decode_value(&result, ret_type))
    }

    /// Read with ContractCall builder for args.
    pub async fn read_call(&self, call: &ContractCall) -> Result<Value> {
        let data = call.clone().build();
        let method = &call.method_name();
        let result = self.provider.call(&self.address, &data).await?;

        let method_str: &str = method;
        let ret_type = self.functions.get(method_str)
            .map(|f| f.return_type.as_str())
            .unwrap_or("u64");

        Ok(decode_value(&result, ret_type))
    }

    pub fn address(&self) -> &Address { &self.address }
}

/// Decode raw bytes into a Value based on type string.
pub fn decode_value(data: &[u8], type_str: &str) -> Value {
    match type_str {
        "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" => {
            if data.len() >= 8 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[..8]);
                Value::U64(u64::from_le_bytes(buf))
            } else {
                Value::U64(0)
            }
        }
        "u128" | "i128" => {
            if data.len() >= 16 {
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&data[..16]);
                Value::U128(u128::from_le_bytes(buf))
            } else {
                Value::U128(0)
            }
        }
        "u256" | "i256" => {
            if data.len() >= 32 {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&data[..32]);
                Value::U256(ethnum::U256::from_le_bytes(buf))
            } else {
                Value::U256(ethnum::U256::ZERO)
            }
        }
        "bool" => {
            if data.len() >= 8 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[..8]);
                Value::Bool(u64::from_le_bytes(buf) != 0)
            } else {
                Value::Bool(false)
            }
        }
        "Address" => {
            if data.len() >= 32 {
                let mut addr = [0u8; 32];
                addr.copy_from_slice(&data[..32]);
                Value::Address(addr)
            } else {
                Value::Address([0u8; 32])
            }
        }
        "String" => {
            if data.len() >= 8 {
                let mut len_buf = [0u8; 8];
                len_buf.copy_from_slice(&data[..8]);
                let len = u64::from_le_bytes(len_buf) as usize;
                if data.len() >= 8 + len {
                    Value::String(
                        std::string::String::from_utf8_lossy(&data[8..8 + len]).to_string()
                    )
                } else {
                    Value::String(String::new())
                }
            } else {
                Value::String(String::new())
            }
        }
        "Bytes" => {
            if data.len() >= 8 {
                let mut len_buf = [0u8; 8];
                len_buf.copy_from_slice(&data[..8]);
                let len = u64::from_le_bytes(len_buf) as usize;
                if data.len() >= 8 + len {
                    Value::Bytes(data[8..8 + len].to_vec())
                } else {
                    Value::Bytes(vec![])
                }
            } else {
                Value::Bytes(vec![])
            }
        }
        "" | "unit" | "()" => Value::Unit,
        s if s.starts_with("Vec<") && s.ends_with('>') => {
            // Vec<T>: [byte_len:8][count:8][cap:8][elements...]
            if data.len() < 24 { return Value::Vec(vec![]); }
            let _byte_len = u64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8])) as usize;
            let count = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0; 8])) as usize;
            let elem_type = &s[4..s.len() - 1]; // extract T from Vec<T>
            let elem_size = match elem_type {
                "u64" | "i64" | "bool" => 8,
                "u128" | "i128" => 16,
                "u256" | "i256" | "Address" => 32,
                _ => 0, // variable-length elements not supported in auto-decode
            };
            if elem_size > 0 {
                let mut elements = Vec::with_capacity(count);
                for i in 0..count {
                    let offset = 24 + i * elem_size;
                    if offset + elem_size <= data.len() {
                        elements.push(decode_value(&data[offset..], elem_type));
                    }
                }
                Value::Vec(elements)
            } else {
                Value::Bytes(data.to_vec()) // fallback for variable-length elements
            }
        }
        _ => {
            // Unknown type — return raw bytes
            Value::Bytes(data.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_u64_value() {
        let data = 42u64.to_le_bytes();
        let v = decode_value(&data, "u64");
        assert_eq!(v.as_u64(), Some(42));
    }

    #[test]
    fn decode_bool_value() {
        let data = 1u64.to_le_bytes();
        assert_eq!(decode_value(&data, "bool").as_bool(), Some(true));
        let data = 0u64.to_le_bytes();
        assert_eq!(decode_value(&data, "bool").as_bool(), Some(false));
    }

    #[test]
    fn decode_string_value() {
        let mut data = Vec::new();
        data.extend_from_slice(&5u64.to_le_bytes());
        data.extend_from_slice(b"hello");
        let v = decode_value(&data, "String");
        assert_eq!(v.as_string(), Some("hello"));
    }

    #[test]
    fn decode_address_value() {
        let addr = [0xAA; 32];
        let v = decode_value(&addr, "Address");
        assert_eq!(v.as_address(), Some(&addr));
    }

    #[test]
    fn decode_u256_value() {
        let mut buf = [0u8; 32];
        buf[0] = 99;
        let v = decode_value(&buf, "u256");
        assert_eq!(v.as_u256(), Some(ethnum::U256::from(99u64)));
    }

    #[test]
    fn value_field_access() {
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), Value::String("alice".to_string()));
        fields.insert("age".to_string(), Value::U64(25));
        let v = Value::Struct(fields);

        assert_eq!(v.field("name").and_then(|v| v.as_string()), Some("alice"));
        assert_eq!(v.field("age").and_then(|v| v.as_u64()), Some(25));
        assert!(v.field("missing").is_none());
    }

    #[test]
    fn value_vec_access() {
        let v = Value::Vec(vec![Value::U64(10), Value::U64(20), Value::U64(30)]);
        assert_eq!(v.index(0).and_then(|v| v.as_u64()), Some(10));
        assert_eq!(v.index(2).and_then(|v| v.as_u64()), Some(30));
        assert!(v.index(5).is_none());
    }

    #[test]
    fn decode_unit() {
        let v = decode_value(&[], "unit");
        assert!(matches!(v, Value::Unit));
    }
}
