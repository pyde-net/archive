//! Address derivation and formatting per Chapter 11 spec.
//!
//! - EOA:     Poseidon2(falcon_public_key)
//! - CREATE:  Poseidon2(deployer_address || nonce_bytes)
//! - CREATE2: Poseidon2(0xFF || deployer_address || salt || code_hash)

use pyde_crypto::poseidon2::poseidon2_hash;

/// 32-byte address (Poseidon2 hash of FALCON-512 public key).
pub type Address = [u8; 32];

/// Zero address constant.
pub const ZERO_ADDRESS: Address = [0u8; 32];

/// Derive an EOA address from a FALCON-512 public key.
///
/// `address = Poseidon2(falcon_public_key_bytes)`
pub fn derive_eoa_address(falcon_public_key: &[u8]) -> Address {
    poseidon2_hash(falcon_public_key).to_bytes()
}

/// Derive a contract address from CREATE.
///
/// `address = Poseidon2(deployer_address || nonce_bytes)`
pub fn derive_create_address(deployer: &Address, nonce: u64) -> Address {
    let mut input = Vec::with_capacity(40);
    input.extend_from_slice(deployer);
    input.extend_from_slice(&nonce.to_le_bytes());
    poseidon2_hash(&input).to_bytes()
}

/// Derive a contract address from CREATE2.
///
/// `address = Poseidon2(0xFF || deployer_address || salt || code_hash)`
pub fn derive_create2_address(deployer: &Address, salt: &[u8; 32], code: &[u8]) -> Address {
    let code_hash = poseidon2_hash(code).to_bytes();
    let mut input = Vec::with_capacity(97);
    input.push(0xFF);
    input.extend_from_slice(deployer);
    input.extend_from_slice(salt);
    input.extend_from_slice(&code_hash);
    poseidon2_hash(&input).to_bytes()
}

/// Well-known treasury address: Poseidon2("pyde-treasury").
/// Accumulates 10% of all transaction fees for future prover rewards.
pub fn treasury_address() -> Address {
    poseidon2_hash(b"pyde-treasury").to_bytes()
}

/// Well-known airdrop pool address: Poseidon2("pyde-airdrop-pool").
/// Genesis pre-mints the total claimable amount to this address;
/// `ClaimAirdrop` debits the pool and credits the claimer.
/// `SweepAirdrop` transfers any post-deadline residue to the treasury.
pub fn airdrop_pool_address() -> Address {
    poseidon2_hash(b"pyde-airdrop-pool").to_bytes()
}

/// Format an address as a hex string with "0x" prefix.
pub fn format_address(addr: &Address) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for byte in addr {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

/// Parse an address from a hex string (with or without "0x" prefix).
pub fn parse_address(s: &str) -> Option<Address> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.len() != 64 {
        return None;
    }
    let mut addr = ZERO_ADDRESS;
    for i in 0..32 {
        addr[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Task 0356: Address derivation is deterministic ==========

    #[test]
    fn eoa_address_deterministic() {
        let pk = [0xAB; 897];
        assert_eq!(derive_eoa_address(&pk), derive_eoa_address(&pk));
    }

    #[test]
    fn different_keys_different_addresses() {
        assert_ne!(derive_eoa_address(&[0xAB; 897]), derive_eoa_address(&[0xCD; 897]));
    }

    #[test]
    fn create_address_deterministic() {
        let deployer = derive_eoa_address(&[0xAB; 897]);
        assert_eq!(
            derive_create_address(&deployer, 0),
            derive_create_address(&deployer, 0)
        );
    }

    #[test]
    fn create_different_nonce_different_address() {
        let deployer = derive_eoa_address(&[0xAB; 897]);
        assert_ne!(
            derive_create_address(&deployer, 0),
            derive_create_address(&deployer, 1)
        );
    }

    // ========== Task 0357: CREATE2 same salt + code → same address ==========

    #[test]
    fn create2_deterministic() {
        let deployer = derive_eoa_address(&[0xAB; 897]);
        let salt = [0x42; 32];
        let code = b"contract bytecode";
        assert_eq!(
            derive_create2_address(&deployer, &salt, code),
            derive_create2_address(&deployer, &salt, code)
        );
    }

    // ========== Task 0358: CREATE2 different salt → different address ==========

    #[test]
    fn create2_different_salt_different_address() {
        let deployer = derive_eoa_address(&[0xAB; 897]);
        let code = b"contract bytecode";
        assert_ne!(
            derive_create2_address(&deployer, &[0x01; 32], code),
            derive_create2_address(&deployer, &[0x02; 32], code)
        );
    }

    #[test]
    fn create2_different_code_different_address() {
        let deployer = derive_eoa_address(&[0xAB; 897]);
        let salt = [0x42; 32];
        assert_ne!(
            derive_create2_address(&deployer, &salt, b"code_a"),
            derive_create2_address(&deployer, &salt, b"code_b")
        );
    }

    // ========== Display formatting ==========

    #[test]
    fn format_address_hex() {
        let addr = ZERO_ADDRESS;
        let s = format_address(&addr);
        assert_eq!(s, "0x0000000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(s.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn parse_address_roundtrip() {
        let addr = derive_eoa_address(&[0xAB; 897]);
        let s = format_address(&addr);
        let parsed = parse_address(&s).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn parse_address_no_prefix() {
        let addr = ZERO_ADDRESS;
        let s = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(parse_address(s), Some(addr));
    }

    #[test]
    fn parse_address_invalid() {
        assert_eq!(parse_address("0x123"), None); // too short
        assert_eq!(parse_address("not hex at all!"), None);
    }

    // ========== Zero address ==========

    #[test]
    fn zero_address_is_zero() {
        assert_eq!(ZERO_ADDRESS, [0u8; 32]);
    }

    #[test]
    fn derived_address_is_not_zero() {
        assert_ne!(derive_eoa_address(&[0xAB; 897]), ZERO_ADDRESS);
    }
}
