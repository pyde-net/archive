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
pub mod types;
pub mod wallet;

// Top-level re-exports for convenience
pub use abi::{Contract, Value};
pub use client::Provider;
pub use contract::{compute_selector, ContractCall, DeployData};
pub use contract::{decode_address, decode_bool, decode_string, decode_u64, decode_u128, decode_u256};
pub use error::{Result, SdkError};
pub use types::{format_address, parse_address, Address, Receipt, Log, LogFilter};
pub use wallet::{Keystore, SignerProvider, Wallet};
