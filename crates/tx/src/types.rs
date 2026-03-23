//! Transaction types per Chapter 11 spec.
//!
//! Every transaction has: from, to, value, data, gas_limit, nonce,
//! signature, fee_payer, access_list, deadline, chain_id, tx_type.

use pyde_account::address::Address;
use pyde_crypto::falcon::{falcon_verify, FalconPublicKey, FalconSignature};
use pyde_crypto::poseidon2::poseidon2_hash;

/// Transaction type tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TransactionType {
    /// Standard value transfer or contract call.
    Standard = 0,
    /// Contract deployment.
    Deploy = 1,
    /// Batch transaction (multiple operations).
    Batch = 2,
}

impl TransactionType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Standard),
            1 => Some(Self::Deploy),
            2 => Some(Self::Batch),
            _ => None,
        }
    }
}

/// Who pays the gas fee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeePayer {
    /// Sender pays from their own balance (default).
    Sender,
    /// A contract's gas tank pays.
    GasTank(Address),
    /// A third-party paymaster contract pays.
    Paymaster(Address),
}

impl FeePayer {
    pub fn tag(&self) -> u8 {
        match self {
            FeePayer::Sender => 0,
            FeePayer::GasTank(_) => 1,
            FeePayer::Paymaster(_) => 2,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            FeePayer::Sender => vec![0],
            FeePayer::GasTank(addr) => {
                let mut buf = vec![1];
                buf.extend_from_slice(addr);
                buf
            }
            FeePayer::Paymaster(addr) => {
                let mut buf = vec![2];
                buf.extend_from_slice(addr);
                buf
            }
        }
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        match data[0] {
            0 => Some(FeePayer::Sender),
            1 if data.len() >= 33 => {
                let addr: Address = data[1..33].try_into().ok()?;
                Some(FeePayer::GasTank(addr))
            }
            2 if data.len() >= 33 => {
                let addr: Address = data[1..33].try_into().ok()?;
                Some(FeePayer::Paymaster(addr))
            }
            _ => None,
        }
    }
}

/// An access list entry: contract address + read/write storage keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessEntry {
    pub address: Address,
    /// Storage keys that will only be read.
    pub reads: Vec<[u8; 32]>,
    /// Storage keys that will be written (may also be read).
    pub writes: Vec<[u8; 32]>,
}

/// The full transaction structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// Sender's address.
    pub from: Address,
    /// Recipient address (zero for contract deployment).
    pub to: Address,
    /// Value to transfer (in quanta).
    pub value: u128,
    /// Calldata (function call or init code for deploy).
    pub data: Vec<u8>,
    /// Maximum gas this transaction can consume.
    pub gas_limit: u64,
    /// Nonce (must be within sender's nonce window).
    pub nonce: u64,
    /// FALCON-512 signature bytes.
    pub signature: Vec<u8>,
    /// Who pays the gas fee.
    pub fee_payer: FeePayer,
    /// Access list: state keys this transaction will read/write.
    pub access_list: Vec<AccessEntry>,
    /// Expiry block height (None = no deadline).
    pub deadline: Option<u64>,
    /// Chain ID (replay protection across networks).
    pub chain_id: u64,
    /// Transaction type.
    pub tx_type: TransactionType,
}

impl Transaction {
    /// Compute the transaction hash (Poseidon2 of all fields except signature).
    ///
    /// ```text
    /// tx_hash = Poseidon2(
    ///     chain_id || from || to || value || Poseidon2(data) ||
    ///     gas_limit || nonce || fee_payer_tag ||
    ///     Poseidon2(access_list) || deadline || tx_type
    /// )
    /// ```
    pub fn hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&self.chain_id.to_le_bytes());
        buf.extend_from_slice(&self.from);
        buf.extend_from_slice(&self.to);
        buf.extend_from_slice(&self.value.to_le_bytes());
        buf.extend_from_slice(&poseidon2_hash(&self.data).to_bytes());
        buf.extend_from_slice(&self.gas_limit.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.push(self.fee_payer.tag());
        buf.extend_from_slice(&hash_access_list(&self.access_list));
        match self.deadline {
            Some(d) => {
                buf.push(1);
                buf.extend_from_slice(&d.to_le_bytes());
            }
            None => buf.push(0),
        }
        buf.push(self.tx_type as u8);
        poseidon2_hash(&buf).to_bytes()
    }

    /// Verify the transaction signature against a public key.
    pub fn verify_signature(&self, public_key: &[u8]) -> bool {
        let pk = match FalconPublicKey::from_bytes(public_key) {
            Some(pk) => pk,
            None => return false,
        };
        let sig = FalconSignature::from_bytes(&self.signature);
        let tx_hash = self.hash();
        falcon_verify(&pk, &tx_hash, &sig)
    }

    /// Serialize the full transaction to bytes (wire format).
    pub fn to_bytes(&self) -> Vec<u8> {
        let fee_bytes = self.fee_payer.to_bytes();
        let access_bytes = serialize_access_list(&self.access_list);

        let mut buf = Vec::new();
        buf.extend_from_slice(&self.from);                              // 32
        buf.extend_from_slice(&self.to);                                // 32
        buf.extend_from_slice(&self.value.to_le_bytes());               // 16
        buf.extend_from_slice(&(self.data.len() as u32).to_le_bytes()); // 4
        buf.extend_from_slice(&self.data);                              // var
        buf.extend_from_slice(&self.gas_limit.to_le_bytes());           // 8
        buf.extend_from_slice(&self.nonce.to_le_bytes());               // 8
        buf.extend_from_slice(&(self.signature.len() as u16).to_le_bytes()); // 2
        buf.extend_from_slice(&self.signature);                         // ~666
        buf.extend_from_slice(&(fee_bytes.len() as u8).to_le_bytes()); // 1
        buf.extend_from_slice(&fee_bytes);                              // 1-33
        buf.extend_from_slice(&(access_bytes.len() as u32).to_le_bytes()); // 4
        buf.extend_from_slice(&access_bytes);                           // var
        match self.deadline {
            Some(d) => {
                buf.push(1);
                buf.extend_from_slice(&d.to_le_bytes());
            }
            None => buf.push(0),
        }
        buf.extend_from_slice(&self.chain_id.to_le_bytes());           // 8
        buf.push(self.tx_type as u8);                                   // 1
        buf
    }

    /// Deserialize a transaction from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let mut offset = 0;

        let from: Address = data.get(offset..offset + 32)?.try_into().ok()?;
        offset += 32;
        let to: Address = data.get(offset..offset + 32)?.try_into().ok()?;
        offset += 32;
        let value = u128::from_le_bytes(data.get(offset..offset + 16)?.try_into().ok()?);
        offset += 16;
        let data_len = u32::from_le_bytes(data.get(offset..offset + 4)?.try_into().ok()?) as usize;
        offset += 4;
        let tx_data = data.get(offset..offset + data_len)?.to_vec();
        offset += data_len;
        let gas_limit = u64::from_le_bytes(data.get(offset..offset + 8)?.try_into().ok()?);
        offset += 8;
        let nonce = u64::from_le_bytes(data.get(offset..offset + 8)?.try_into().ok()?);
        offset += 8;
        let sig_len = u16::from_le_bytes(data.get(offset..offset + 2)?.try_into().ok()?) as usize;
        offset += 2;
        let signature = data.get(offset..offset + sig_len)?.to_vec();
        offset += sig_len;
        let fee_len = *data.get(offset)? as usize;
        offset += 1;
        let fee_payer = FeePayer::from_bytes(data.get(offset..offset + fee_len)?)?;
        offset += fee_len;
        let access_len =
            u32::from_le_bytes(data.get(offset..offset + 4)?.try_into().ok()?) as usize;
        offset += 4;
        let access_list = deserialize_access_list(data.get(offset..offset + access_len)?).ok()?;
        offset += access_len;
        let deadline_flag = *data.get(offset)?;
        offset += 1;
        let deadline = if deadline_flag == 1 {
            let d = u64::from_le_bytes(data.get(offset..offset + 8)?.try_into().ok()?);
            offset += 8;
            Some(d)
        } else {
            None
        };
        let chain_id = u64::from_le_bytes(data.get(offset..offset + 8)?.try_into().ok()?);
        offset += 8;
        let tx_type = TransactionType::from_u8(*data.get(offset)?)?;

        Some(Transaction {
            from,
            to,
            value,
            data: tx_data,
            gas_limit,
            nonce,
            signature,
            fee_payer,
            access_list,
            deadline,
            chain_id,
            tx_type,
        })
    }
}

/// Hash an access list for inclusion in the tx hash.
fn hash_access_list(access_list: &[AccessEntry]) -> [u8; 32] {
    let mut buf = Vec::new();
    for entry in access_list {
        buf.extend_from_slice(&entry.address);
        buf.extend_from_slice(&(entry.reads.len() as u32).to_le_bytes());
        for key in &entry.reads {
            buf.extend_from_slice(key);
        }
        buf.extend_from_slice(&(entry.writes.len() as u32).to_le_bytes());
        for key in &entry.writes {
            buf.extend_from_slice(key);
        }
    }
    poseidon2_hash(&buf).to_bytes()
}

fn serialize_access_list(access_list: &[AccessEntry]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(access_list.len() as u32).to_le_bytes());
    for entry in access_list {
        buf.extend_from_slice(&entry.address);
        buf.extend_from_slice(&(entry.reads.len() as u32).to_le_bytes());
        for key in &entry.reads {
            buf.extend_from_slice(key);
        }
        buf.extend_from_slice(&(entry.writes.len() as u32).to_le_bytes());
        for key in &entry.writes {
            buf.extend_from_slice(key);
        }
    }
    buf
}

fn deserialize_access_list(data: &[u8]) -> Result<Vec<AccessEntry>, &'static str> {
    if data.len() < 4 {
        return Err("access list too short: missing entry count");
    }
    let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut entries = Vec::with_capacity(count);
    let mut offset = 4;
    for _ in 0..count {
        if offset + 36 > data.len() {
            return Err("access list truncated: incomplete entry header");
        }
        let address: Address = data[offset..offset + 32].try_into().unwrap();
        offset += 32;
        // Reads
        let num_reads = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let mut reads = Vec::with_capacity(num_reads);
        for _ in 0..num_reads {
            if offset + 32 > data.len() {
                return Err("access list truncated: incomplete read key");
            }
            reads.push(data[offset..offset + 32].try_into().unwrap());
            offset += 32;
        }
        // Writes
        if offset + 4 > data.len() {
            return Err("access list truncated: missing write count");
        }
        let num_writes = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let mut writes = Vec::with_capacity(num_writes);
        for _ in 0..num_writes {
            if offset + 32 > data.len() {
                return Err("access list truncated: incomplete write key");
            }
            writes.push(data[offset..offset + 32].try_into().unwrap());
            offset += 32;
        }
        entries.push(AccessEntry { address, reads, writes });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::{derive_eoa_address, ZERO_ADDRESS};
    use pyde_crypto::falcon::{falcon_keygen, falcon_sign};

    fn make_test_tx() -> Transaction {
        Transaction {
            from: derive_eoa_address(&[0xAA; 897]),
            to: derive_eoa_address(&[0xBB; 897]),
            value: 1_000_000_000,
            data: b"transfer".to_vec(),
            gas_limit: 21_000,
            nonce: 0,
            signature: vec![],
            fee_payer: FeePayer::Sender,
            access_list: vec![],
            deadline: None,
            chain_id: 1,
            tx_type: TransactionType::Standard,
        }
    }

    // ========== Task 0382: Serialize/deserialize roundtrip ==========

    #[test]
    fn serialize_deserialize_roundtrip() {
        let tx = make_test_tx();
        let bytes = tx.to_bytes();
        let restored = Transaction::from_bytes(&bytes).unwrap();
        assert_eq!(tx, restored);
    }

    #[test]
    fn serialize_with_access_list() {
        let mut tx = make_test_tx();
        tx.access_list = vec![
            AccessEntry {
                address: [0x11; 32],
                reads: vec![[0x22; 32]],
                writes: vec![[0x33; 32]],
            },
            AccessEntry {
                address: [0x44; 32],
                reads: vec![],
                writes: vec![],
            },
        ];
        let bytes = tx.to_bytes();
        let restored = Transaction::from_bytes(&bytes).unwrap();
        assert_eq!(tx, restored);
    }

    #[test]
    fn serialize_with_deadline() {
        let mut tx = make_test_tx();
        tx.deadline = Some(100_000);
        let bytes = tx.to_bytes();
        let restored = Transaction::from_bytes(&bytes).unwrap();
        assert_eq!(tx.deadline, restored.deadline);
    }

    #[test]
    fn serialize_with_gas_tank() {
        let mut tx = make_test_tx();
        tx.fee_payer = FeePayer::GasTank([0xFF; 32]);
        let bytes = tx.to_bytes();
        let restored = Transaction::from_bytes(&bytes).unwrap();
        assert_eq!(tx.fee_payer, restored.fee_payer);
    }

    #[test]
    fn serialize_deploy_tx() {
        let mut tx = make_test_tx();
        tx.to = ZERO_ADDRESS;
        tx.tx_type = TransactionType::Deploy;
        tx.data = b"contract init code".to_vec();
        let bytes = tx.to_bytes();
        let restored = Transaction::from_bytes(&bytes).unwrap();
        assert_eq!(tx, restored);
    }

    // ========== Task 0383: Hash is deterministic ==========

    #[test]
    fn hash_deterministic() {
        let tx = make_test_tx();
        assert_eq!(tx.hash(), tx.hash());
    }

    #[test]
    fn different_tx_different_hash() {
        let tx1 = make_test_tx();
        let mut tx2 = make_test_tx();
        tx2.value = 999;
        assert_ne!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn hash_independent_of_signature() {
        let mut tx1 = make_test_tx();
        let mut tx2 = make_test_tx();
        tx1.signature = vec![0xAA; 100];
        tx2.signature = vec![0xBB; 200];
        // Hash doesn't include signature
        assert_eq!(tx1.hash(), tx2.hash());
    }

    // ========== Task 0384: Valid signature passes ==========

    #[test]
    fn valid_signature_passes() {
        let (pk, sk) = falcon_keygen();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut tx = make_test_tx();
        tx.from = derive_eoa_address(&pk_bytes);

        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).as_bytes().to_vec();

        assert!(tx.verify_signature(&pk_bytes));
    }

    // ========== Task 0385: Tampered transaction fails ==========

    #[test]
    fn tampered_value_fails_verification() {
        let (pk, sk) = falcon_keygen();
        let pk_bytes = pk.as_bytes().to_vec();
        let mut tx = make_test_tx();
        tx.from = derive_eoa_address(&pk_bytes);

        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk, &tx_hash).as_bytes().to_vec();

        // Tamper
        tx.value = 999_999;
        assert!(!tx.verify_signature(&pk_bytes));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (pk1, sk1) = falcon_keygen();
        let (pk2, _sk2) = falcon_keygen();
        let mut tx = make_test_tx();

        let tx_hash = tx.hash();
        tx.signature = falcon_sign(&sk1, &tx_hash).as_bytes().to_vec();

        // Verify with wrong key
        assert!(!tx.verify_signature(pk2.as_bytes()));
    }

    // ========== FeePayer ==========

    #[test]
    fn fee_payer_roundtrip() {
        for fp in [
            FeePayer::Sender,
            FeePayer::GasTank([0xAA; 32]),
            FeePayer::Paymaster([0xBB; 32]),
        ] {
            let bytes = fp.to_bytes();
            let restored = FeePayer::from_bytes(&bytes).unwrap();
            assert_eq!(fp, restored);
        }
    }

    // ========== Corrupt data ==========

    #[test]
    fn deserialize_empty_returns_none() {
        assert!(Transaction::from_bytes(&[]).is_none());
    }

    #[test]
    fn deserialize_truncated_returns_none() {
        assert!(Transaction::from_bytes(&[0; 50]).is_none());
    }
}
