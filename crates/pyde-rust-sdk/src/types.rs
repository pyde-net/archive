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

    pub fn decode_bool(&self) -> Option<bool> {
        crate::contract::decode_bool(&self.return_bytes())
    }

    pub fn decode_string(&self) -> Option<String> {
        crate::contract::decode_string(&self.return_bytes())
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
#[derive(Debug, Clone, serde::Serialize)]
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
