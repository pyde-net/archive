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

    #[error("transaction reverted (gas={gas_used})")]
    Reverted { gas_used: u64, data: Vec<u8> },

    #[error("insufficient balance: need {required}, have {available}")]
    InsufficientBalance { required: u128, available: u128 },

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

pub type Result<T> = std::result::Result<T, SdkError>;
