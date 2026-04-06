pub use pyde_account::address::{
    derive_create_address, derive_create2_address, derive_eoa_address,
};
pub use pyde_crypto::falcon::{FalconPublicKey, FalconSecretKey, FalconSignature};
pub use pyde_tx::types::{AccessEntry, FeePayer, Transaction, TransactionType};

/// 32-byte address.
pub type Address = [u8; 32];

/// Transaction receipt from the node.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub tx_hash: String,
    pub success: bool,
    pub gas_used: String,
    pub effective_gas: String,
    pub fee_paid: String,
    pub fee_burned: String,
    pub fee_validator: String,
    #[serde(default)]
    pub return_data: String,
    #[serde(default)]
    pub logs: Vec<Log>,
}

impl Receipt {
    /// Parse gas_used from hex string.
    pub fn gas(&self) -> u64 {
        u64::from_str_radix(self.gas_used.trim_start_matches("0x"), 16).unwrap_or(0)
    }

    /// Parse return_data as raw bytes.
    pub fn return_bytes(&self) -> Vec<u8> {
        let hex = self.return_data.trim_start_matches("0x");
        hex::decode(hex).unwrap_or_default()
    }

    /// For deploy receipts: extract the contract address from returnData.
    /// Returns None if returnData is not a valid 32-byte address.
    pub fn contract_address(&self) -> Option<Address> {
        let bytes = self.return_bytes();
        if bytes.len() == 32 {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&bytes);
            Some(addr)
        } else {
            None
        }
    }

    /// Decode return_data as a specific type using the decode helpers.
    /// Convenience for: `decode_u64(&receipt.return_bytes())`
    pub fn decode_u64(&self) -> Option<u64> {
        crate::contract::decode_u64(&self.return_bytes())
    }
    pub fn decode_i64(&self) -> Option<i64> {
        crate::contract::decode_i64(&self.return_bytes())
    }
    pub fn decode_u128(&self) -> Option<u128> {
        crate::contract::decode_u128(&self.return_bytes())
    }
    pub fn decode_i128(&self) -> Option<i128> {
        crate::contract::decode_i128(&self.return_bytes())
    }
    pub fn decode_u256(&self) -> Option<ethnum::U256> {
        crate::contract::decode_u256(&self.return_bytes())
    }
    pub fn decode_i256(&self) -> Option<ethnum::I256> {
        crate::contract::decode_i256(&self.return_bytes())
    }
    pub fn decode_bool(&self) -> Option<bool> {
        crate::contract::decode_bool(&self.return_bytes())
    }
    pub fn decode_address(&self) -> Option<Address> {
        crate::contract::decode_address(&self.return_bytes())
    }
    pub fn decode_string(&self) -> Option<String> {
        crate::contract::decode_string(&self.return_bytes())
    }
    pub fn decode_bytes(&self) -> Option<Vec<u8>> {
        crate::contract::decode_bytes(&self.return_bytes())
    }
}

/// Event log entry.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Log {
    pub address: String,
    #[serde(default)]
    pub topics: Vec<String>,
    #[serde(default)]
    pub data: String,
}

/// Log filter for querying events.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_block: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_block: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Topic filters. Each entry is None (match any) or a list of hex values (OR match).
    /// topics[0] = event signature hash, topics[1..3] = indexed params.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<Option<Vec<String>>>>,
}

/// Block header info.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    pub slot: String,
    pub timestamp: String,
    pub proposer: String,
    #[serde(default)]
    pub state_root: String,
    #[serde(default)]
    pub tx_count: String,
}

/// Override params for call/estimate_gas.
#[derive(Debug, Clone, Default)]
pub struct CallOverrides {
    pub from: Option<Address>,
    pub value: Option<u128>,
    pub gas_limit: Option<u64>,
}

/// Fee data from the network.
#[derive(Debug, Clone)]
pub struct FeeData {
    /// Current gas price (same as base fee in Pyde's EIP-1559 model, no tips).
    pub gas_price: u128,
    /// Current base fee per gas unit.
    pub base_fee: u128,
}

/// Parse a hex address string to [u8; 32].
pub fn parse_address(s: &str) -> Result<Address, crate::SdkError> {
    let hex = s.trim_start_matches("0x");
    if hex.len() != 64 {
        return Err(crate::SdkError::InvalidAddress(format!(
            "expected 64 hex chars, got {}",
            hex.len()
        )));
    }
    let bytes = hex::decode(hex)
        .map_err(|e| crate::SdkError::InvalidAddress(format!("bad hex: {}", e)))?;
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

/// Format an address as 0x-prefixed hex string.
pub fn format_address(addr: &Address) -> String {
    format!("0x{}", hex::encode(addr))
}

/// The zero address (32 zero bytes).
pub const ZERO_ADDRESS: Address = [0u8; 32];

/// Check if an address is the zero address.
pub fn is_zero_address(addr: &Address) -> bool {
    *addr == ZERO_ADDRESS
}

/// Validate a hex address string without parsing it.
pub fn is_valid_address(s: &str) -> bool {
    let hex = s.trim_start_matches("0x");
    hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// Check if two addresses are equal.
pub fn address_eq(a: &Address, b: &Address) -> bool {
    a == b
}

/// Validate a FALCON-512 private key hex (pk + sk combined, 2178 bytes).
pub fn is_valid_private_key(hex: &str) -> bool {
    let clean = hex.trim_start_matches("0x");
    clean.len() == (897 + 1281) * 2 && clean.chars().all(|c| c.is_ascii_hexdigit())
}

// ============================================================================
// Hex utilities
// ============================================================================

/// Check if a string is valid hex (with or without 0x prefix).
pub fn is_hex_string(value: &str) -> bool {
    let hex = value.trim_start_matches("0x");
    !hex.is_empty() && hex.len() % 2 == 0 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// Convert bytes to a 0x-prefixed hex string.
pub fn hexlify(data: &[u8]) -> String {
    format!("0x{}", hex::encode(data))
}

/// Convert a hex string to bytes.
pub fn get_bytes(value: &str) -> std::result::Result<Vec<u8>, String> {
    let hex_str = value.trim_start_matches("0x");
    hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))
}

/// Convert a u128 to a 0x-prefixed big-endian hex string.
pub fn to_be_hex(value: u128, width: Option<usize>) -> String {
    let hex = format!("{:x}", value);
    let padded = if let Some(w) = width {
        format!("{:0>width$}", hex, width = w * 2)
    } else if hex.len() % 2 != 0 {
        format!("0{}", hex)
    } else {
        hex
    };
    format!("0x{}", padded)
}

/// Concatenate multiple byte slices.
pub fn concat_bytes(values: &[&[u8]]) -> Vec<u8> {
    let total: usize = values.iter().map(|v| v.len()).sum();
    let mut result = Vec::with_capacity(total);
    for v in values { result.extend_from_slice(v); }
    result
}

/// Zero-pad bytes to a specific length (left-pad).
pub fn zero_pad_value(data: &[u8], length: usize) -> std::result::Result<Vec<u8>, String> {
    if data.len() > length { return Err(format!("Value {} bytes exceeds pad length {}", data.len(), length)); }
    let mut padded = vec![0u8; length];
    padded[length - data.len()..].copy_from_slice(data);
    Ok(padded)
}

/// Strip leading zero bytes.
pub fn strip_zeros(data: &[u8]) -> Vec<u8> {
    let start = data.iter().position(|&b| b != 0).unwrap_or(data.len());
    data[start..].to_vec()
}

/// Get byte length of a hex string.
pub fn data_length(hex: &str) -> usize {
    let h = hex.trim_start_matches("0x");
    h.len() / 2
}

// ============================================================================
// Unit formatting (1 PYDE = 10^9 quanta)
// ============================================================================

/// Default decimals for PYDE.
pub const PYDE_DECIMALS: u32 = 9;

/// Parse a human-readable amount to raw integer units.
///
/// ```rust,ignore
/// parse_units("1.5", 9)   // Ok(1_500_000_000)
/// parse_units("100", 18)  // Ok(100_000_000_000_000_000_000)
/// ```
pub fn parse_units(value: &str, decimals: u32) -> std::result::Result<u128, String> {
    if decimals > 38 { return Err(format!("decimals {} exceeds u128 precision (max 38)", decimals)); }
    let trimmed = value.trim();
    let negative = trimmed.starts_with('-');
    if negative {
        return Err("Negative values not supported for u128 units".into());
    }

    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() > 2 { return Err(format!("Invalid numeric string: {}", value)); }

    let whole = parts[0];
    let fraction = if parts.len() == 2 { parts[1] } else { "" };

    if fraction.len() > decimals as usize {
        return Err(format!(
            "Too many decimal places: \"{}\" has {} but only {} allowed",
            value, fraction.len(), decimals
        ));
    }

    // Validate chars
    if !whole.chars().all(|c| c.is_ascii_digit()) || (!fraction.is_empty() && !fraction.chars().all(|c| c.is_ascii_digit())) {
        return Err(format!("Invalid numeric string: {}", value));
    }

    let padded = format!("{:0<width$}", fraction, width = decimals as usize);
    let combined = format!("{}{}", whole, padded);
    combined.parse::<u128>().map_err(|e| format!("Overflow: {}", e))
}

/// Format raw integer units to a human-readable amount.
///
/// ```rust,ignore
/// format_units(1_500_000_000, 9)  // "1.5"
/// format_units(1_000_000, 9)      // "0.001"
/// ```
pub fn format_units(value: u128, decimals: u32) -> String {
    if decimals > 38 { return format!("{}", value); } // 10^39 overflows u128
    let divisor = 10u128.pow(decimals);
    let whole = value / divisor;
    let remainder = value % divisor;

    let frac_str = format!("{:0>width$}", remainder, width = decimals as usize);
    let trimmed = frac_str.trim_end_matches('0');
    let trimmed = if trimmed.is_empty() { "0" } else { trimmed };

    format!("{}.{}", whole, trimmed)
}

/// Parse PYDE to quanta (9 decimals). `parse_quanta("1.5")` → `Ok(1_500_000_000)`
pub fn parse_quanta(value: &str) -> std::result::Result<u128, String> {
    parse_units(value, PYDE_DECIMALS)
}

/// Format quanta to PYDE (9 decimals). `format_quanta(1_500_000_000)` → `"1.5"`
pub fn format_quanta(value: u128) -> String {
    format_units(value, PYDE_DECIMALS)
}
