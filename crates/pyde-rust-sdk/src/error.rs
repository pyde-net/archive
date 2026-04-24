#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("connection error: {0}")]
    Connection(String),

    #[error("signing error: {0}")]
    Signing(String),

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("{}", format_revert(.gas_used, .data))]
    Reverted { gas_used: u64, data: Vec<u8> },

    #[error("insufficient balance: need {required}, have {available}")]
    InsufficientBalance { required: u128, available: u128 },

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("invalid response: {0}")]
    InvalidResponse(String),

    #[error("{0}")]
    Other(String),
}

impl SdkError {
    /// Check if this error has the given code string.
    pub fn code(&self) -> &'static str {
        match self {
            SdkError::Rpc(_) => "RPC_ERROR",
            SdkError::Connection(_) => "CONNECTION_ERROR",
            SdkError::Signing(_) => "SIGNING_ERROR",
            SdkError::Timeout(_) => "TIMEOUT",
            SdkError::Reverted { .. } => "CALL_EXCEPTION",
            SdkError::InsufficientBalance { .. } => "INSUFFICIENT_FUNDS",
            SdkError::InvalidAddress(_) => "INVALID_ARGUMENT",
            SdkError::InvalidArgument(_) => "INVALID_ARGUMENT",
            SdkError::InvalidResponse(_) => "INVALID_RESPONSE",
            SdkError::Other(_) => "OTHER",
        }
    }

    /// If this is a Reverted error, try to decode the revert reason string.
    pub fn revert_reason(&self) -> Option<String> {
        if let SdkError::Reverted { data, .. } = self {
            decode_revert_reason(data)
        } else {
            None
        }
    }

    /// Check if this is a revert (call exception).
    pub fn is_revert(&self) -> bool {
        matches!(self, SdkError::Reverted { .. })
    }
}

pub type Result<T> = std::result::Result<T, SdkError>;

/// Attempt to decode a revert reason from return data.
fn decode_revert_reason(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    // Try length-prefixed string: [len:8 LE][utf8 bytes]
    if data.len() >= 8 {
        let len = u64::from_le_bytes(data[..8].try_into().ok()?) as usize;
        if len > 0 && len <= data.len() - 8 {
            if let Ok(s) = std::str::from_utf8(&data[8..8 + len]) {
                if s.chars().all(|c| !c.is_control() || c == '\n') {
                    return Some(s.to_string());
                }
            }
        }
    }
    // Try raw UTF-8
    if let Ok(s) = std::str::from_utf8(data) {
        if s.len() <= 256 && s.chars().all(|c| !c.is_control() || c == '\n') {
            return Some(s.to_string());
        }
    }
    None
}

fn format_revert(gas_used: &u64, data: &[u8]) -> String {
    if let Some(reason) = decode_revert_reason(data) {
        format!("transaction reverted: {} (gas={})", reason, gas_used)
    } else {
        format!("transaction reverted (gas={})", gas_used)
    }
}
