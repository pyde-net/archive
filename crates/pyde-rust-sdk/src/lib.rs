//! # Pyde Rust SDK
//!
//! Client library for interacting with the Pyde blockchain from Rust.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use pyde_rust_sdk::{Provider, Wallet, ContractCall};
//!
//! #[tokio::main]
//! async fn main() {
//!     let provider = Provider::new("http://127.0.0.1:8545");
//!     let wallet = Wallet::generate().unwrap();
//!
//!     // Query
//!     let balance = provider.get_balance(wallet.address()).await.unwrap();
//!     let block = provider.get_block_number().await.unwrap();
//!
//!     // Transfer
//!     let receipt = wallet.transfer(&provider, &[0xBB; 32], 1000).await.unwrap();
//!
//!     // Contract call
//!     let data = ContractCall::new("increment").build();
//!     let receipt = wallet.send_call(&provider, &[0xCC; 32], data, 100_000).await.unwrap();
//! }
//! ```

pub mod abi;
pub mod client;
pub mod contract;
pub mod error;
pub mod signer;
pub mod types;
pub mod wallet;
pub mod ws;

// Top-level re-exports for convenience
pub use abi::{Contract, ContractReceipt, EventLog, Interface, Value};
pub use client::{Provider, ProviderOptions, TransactionResponse};
pub use contract::{compute_selector, ContractCall, DeployData};
pub use contract::{
    decode_address, decode_bool, decode_bytes, decode_i128, decode_i256, decode_i64, decode_string,
    decode_u128, decode_u256, decode_u64, decode_vec_address, decode_vec_bool, decode_vec_u64,
};
pub use error::{Result, SdkError};
pub use signer::Signer;
pub use types::{
    address_eq, concat_bytes, data_length, format_address, format_quanta, format_units, get_bytes,
    hexlify, is_hex_string, is_valid_address, is_valid_private_key, is_zero_address, parse_address,
    parse_quanta, parse_units, strip_zeros, to_be_hex, zero_pad_value, Address, BlockHeader,
    CallOverrides, FeeData, Log, LogFilter, Receipt, PYDE_DECIMALS, ZERO_ADDRESS,
};
pub use wallet::{Keystore, SignerProvider, Wallet};
pub use ws::WsProvider;
