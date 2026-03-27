use pyde_mempool::encrypted::EncryptedTx;
use pyde_mempool::pool::Mempool;
use tracing::{debug, warn};

/// Transaction relay: receives encrypted txs from gossipsub, validates, stores in mempool.
pub struct TxRelay {
    mempool: Mempool,
}

impl TxRelay {
    pub fn new() -> Self {
        Self {
            mempool: Mempool::new(),
        }
    }

    pub fn with_capacity(max_size: usize) -> Self {
        Self {
            mempool: Mempool::with_capacity(max_size),
        }
    }

    /// Update the current block height (for expiry checks).
    pub fn set_current_block(&mut self, block: u64) {
        self.mempool.set_current_block(block);
    }

    /// Attempt to add a transaction received from the network.
    /// Returns true if accepted (new), false if rejected (duplicate, invalid, etc.).
    pub fn receive_tx(&mut self, tx: EncryptedTx) -> bool {
        match self.mempool.add(tx) {
            Ok(()) => {
                debug!("tx accepted into mempool");
                true
            }
            Err(e) => {
                debug!(?e, "tx rejected");
                false
            }
        }
    }

    /// Get current mempool size.
    pub fn mempool_size(&self) -> usize {
        self.mempool.len()
    }

    /// Get a reference to the mempool (for block building).
    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    /// Get a mutable reference to the mempool.
    pub fn mempool_mut(&mut self) -> &mut Mempool {
        &mut self.mempool
    }

    /// Remove transactions that were included in a finalized block.
    pub fn remove_included(&mut self, tx_hashes: &[[u8; 32]]) {
        self.mempool.remove_included(tx_hashes);
        debug!(removed = tx_hashes.len(), "pruned included txs from mempool");
    }

    /// Prune expired transactions.
    pub fn prune_expired(&mut self) {
        let before = self.mempool.len();
        self.mempool.prune_expired();
        let pruned = before - self.mempool.len();
        if pruned > 0 {
            debug!(pruned, "pruned expired txs from mempool");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::derive_eoa_address;
    use pyde_crypto::threshold;
    use pyde_mempool::encrypted::encrypt_transaction;
    use pyde_tx::types::AccessEntry;

    fn make_pk() -> threshold::ThresholdPublicKey {
        let (pk, _) = threshold::threshold_keygen(3, 2).unwrap();
        pk
    }

    fn dummy_access_list() -> Vec<AccessEntry> {
        vec![AccessEntry {
            address: derive_eoa_address(b"contract"),
            reads: vec![[0x01; 32]],
            writes: vec![],
        }]
    }

    fn make_enc_tx(pk: &threshold::ThresholdPublicKey, nonce: u64) -> EncryptedTx {
        let sender = derive_eoa_address(&nonce.to_le_bytes());
        let to = derive_eoa_address(b"to");
        encrypt_transaction(
            sender, nonce, 50_000, dummy_access_list(), None, 1,
            vec![0xAA; 666], &to, 0, b"", pk,
        ).unwrap()
    }

    #[test]
    fn receive_and_count() {
        let pk = make_pk();
        let mut relay = TxRelay::new();

        assert!(relay.receive_tx(make_enc_tx(&pk, 0)));
        assert!(relay.receive_tx(make_enc_tx(&pk, 1)));
        assert_eq!(relay.mempool_size(), 2);
    }

    #[test]
    fn reject_duplicate() {
        let pk = make_pk();
        let mut relay = TxRelay::new();

        let tx = make_enc_tx(&pk, 0);
        assert!(relay.receive_tx(tx.clone()));
        assert!(!relay.receive_tx(tx)); // duplicate
        assert_eq!(relay.mempool_size(), 1);
    }

    #[test]
    fn remove_included() {
        let pk = make_pk();
        let mut relay = TxRelay::new();

        let tx = make_enc_tx(&pk, 0);
        let hash = tx.hash();
        relay.receive_tx(tx);
        assert_eq!(relay.mempool_size(), 1);

        relay.remove_included(&[hash]);
        assert_eq!(relay.mempool_size(), 0);
    }
}
