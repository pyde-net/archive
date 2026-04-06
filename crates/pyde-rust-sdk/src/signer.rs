use crate::error::Result;
use crate::types::Address;
use pyde_tx::types::Transaction;

/// Abstract signer trait. Wallet implements this.
/// Implement for hardware wallets, remote signers, or custodial signers.
pub trait Signer {
    /// The signer's address.
    fn address(&self) -> &Address;

    /// Sign a transaction in place (populates the signature field).
    fn sign_transaction(&self, tx: &mut Transaction) -> Result<()>;

    /// Sign an arbitrary 32-byte message. Returns signature bytes.
    fn sign(&self, message: &[u8; 32]) -> Result<Vec<u8>>;
}
