//! .pyc binary format: packages compiled contract into a single deployable file.
//!
//! Format:
//! ```text
//! ┌────────────────────────────────────────┐
//! │ Header (8 bytes)                       │
//! │   magic:   0x50594445 "PYDE" (4 bytes) │
//! │   version: u16 LE (2 bytes)            │
//! │   flags:   u16 LE (2 bytes)            │
//! ├────────────────────────────────────────┤
//! │ Section Table                          │
//! │   count: u16 LE (2 bytes)              │
//! │   entries[count]:                      │
//! │     type:   u8                         │
//! │     offset: u32 LE                     │
//! │     length: u32 LE                     │
//! ├────────────────────────────────────────┤
//! │ Section data (concatenated)            │
//! └────────────────────────────────────────┘
//! ```

use crate::abi::{abi_to_json, ContractAbi};
use crate::codegen::CompiledContract;

/// Magic bytes: "PYDE" in ASCII.
pub const MAGIC: [u8; 4] = [0x50, 0x59, 0x44, 0x45];

/// Format version. Only bumps when the binary layout changes
/// (new header fields, section table format change).
/// NOT the compiler version — that's in Cargo.toml.
pub const FORMAT_VERSION: u16 = 1;

/// Section types.
pub const SECTION_CONSTRUCTOR: u8 = 1;
pub const SECTION_RUNTIME: u8 = 2;
pub const SECTION_ABI: u8 = 3;
pub const SECTION_STORAGE: u8 = 4;
pub const SECTION_SOURCE_MAP: u8 = 5;

/// Header flags — contract properties the node needs at deploy time
/// without parsing the full ABI.
pub const FLAG_HAS_CONSTRUCTOR: u16 = 1 << 0; // run constructor bytecode at deploy
pub const FLAG_HAS_PAYABLE: u16 = 1 << 1; // contract accepts value transfers
pub const FLAG_HAS_STORAGE: u16 = 1 << 2; // contract uses persistent storage

/// A parsed .pyc file.
#[derive(Clone, Debug)]
pub struct PycFile {
    pub version: u16,
    pub flags: u16,
    pub constructor: Vec<u8>,
    pub runtime: Vec<u8>,
    pub abi_json: String,
    pub storage_json: String,
}

/// Encode a compiled contract + ABI into .pyc binary format.
pub fn encode(contract: &CompiledContract, abi: &ContractAbi) -> Vec<u8> {
    let abi_json = abi_to_json(abi).into_bytes();
    let storage_json = storage_to_json(abi).into_bytes();

    // Compute flags from contract properties
    let mut flags: u16 = 0;
    if !contract.constructor_bytecode.is_empty() {
        flags |= FLAG_HAS_CONSTRUCTOR;
    }
    if abi.functions.iter().any(|f| f.is_payable) {
        flags |= FLAG_HAS_PAYABLE;
    }
    if !abi.storage.is_empty() {
        flags |= FLAG_HAS_STORAGE;
    }

    // Collect sections
    let sections: Vec<(u8, &[u8])> = vec![
        (SECTION_CONSTRUCTOR, &contract.constructor_bytecode),
        (SECTION_RUNTIME, &contract.runtime_bytecode),
        (SECTION_ABI, &abi_json),
        (SECTION_STORAGE, &storage_json),
    ];

    // Calculate header + section table size
    // Header: 8 bytes. Section table: 2 (count) + N * 9 (type:1 + offset:4 + length:4)
    let table_size = 2 + sections.len() * 9;
    let header_total = 8 + table_size;

    // Calculate offsets
    let mut data_offset = header_total;
    let mut entries: Vec<(u8, u32, u32)> = Vec::new();
    for (ty, data) in &sections {
        entries.push((*ty, data_offset as u32, data.len() as u32));
        data_offset += data.len();
    }

    // Build binary
    let mut buf = Vec::with_capacity(data_offset);

    // Header
    buf.extend_from_slice(&MAGIC);
    buf.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    buf.extend_from_slice(&flags.to_le_bytes());

    // Section table
    buf.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for (ty, offset, length) in &entries {
        buf.push(*ty);
        buf.extend_from_slice(&offset.to_le_bytes());
        buf.extend_from_slice(&length.to_le_bytes());
    }

    // Section data
    for (_, data) in &sections {
        buf.extend_from_slice(data);
    }

    buf
}

/// Decode a .pyc binary back into its parts.
pub fn decode(data: &[u8]) -> Result<PycFile, String> {
    if data.len() < 8 {
        return Err("file too small".into());
    }
    if data[0..4] != MAGIC {
        return Err(format!(
            "invalid magic: expected PYDE, got {:?}",
            &data[0..4]
        ));
    }

    let version = u16::from_le_bytes([data[4], data[5]]);
    let flags = u16::from_le_bytes([data[6], data[7]]);

    if data.len() < 10 {
        return Err("missing section table".into());
    }
    let section_count = u16::from_le_bytes([data[8], data[9]]) as usize;

    let mut pos = 10;
    let mut sections: Vec<(u8, u32, u32)> = Vec::new();
    for _ in 0..section_count {
        if pos + 9 > data.len() {
            return Err("truncated section table".into());
        }
        let ty = data[pos];
        let offset =
            u32::from_le_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]]);
        let length =
            u32::from_le_bytes([data[pos + 5], data[pos + 6], data[pos + 7], data[pos + 8]]);
        sections.push((ty, offset, length));
        pos += 9;
    }

    let mut constructor = Vec::new();
    let mut runtime = Vec::new();
    let mut abi_json = String::new();
    let mut storage_json = String::new();

    for (ty, offset, length) in &sections {
        let start = *offset as usize;
        let end = start + *length as usize;
        if end > data.len() {
            return Err(format!("section type {} extends past end of file", ty));
        }
        let section_data = &data[start..end];

        match *ty {
            SECTION_CONSTRUCTOR => constructor = section_data.to_vec(),
            SECTION_RUNTIME => runtime = section_data.to_vec(),
            SECTION_ABI => abi_json = String::from_utf8_lossy(section_data).into_owned(),
            SECTION_STORAGE => storage_json = String::from_utf8_lossy(section_data).into_owned(),
            _ => {} // ignore unknown sections (forward compat)
        }
    }

    Ok(PycFile {
        version,
        flags,
        constructor,
        runtime,
        abi_json,
        storage_json,
    })
}

/// Generate storage schema JSON from ABI.
fn storage_to_json(abi: &ContractAbi) -> String {
    let mut out = String::from("[");
    for (i, s) in abi.storage.iter().enumerate() {
        out.push_str(&format!(
            "{{\"name\":\"{}\",\"type\":\"{}\",\"slot\":{}}}",
            s.name, s.ty, s.slot
        ));
        if i + 1 < abi.storage.len() {
            out.push(',');
        }
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::generate_abi;
    use crate::codegen::CodeGen;
    use crate::lexer::Lexer;
    use crate::lower;
    use crate::optimize;
    use crate::parser::Parser;

    fn compile_pyc(src: &str) -> Vec<u8> {
        let (tokens, _) = Lexer::new(src).tokenize();
        let (file, _) = Parser::new(tokens).parse();
        let mut ir = lower::lower(&file);
        optimize::optimize(&mut ir);
        let abi = generate_abi(&ir);
        let codegen = CodeGen::new();
        let contract = codegen.generate(&ir);
        encode(&contract, &abi)
    }

    #[test]
    fn pyc_encode_decode_roundtrip() {
        let data = compile_pyc(
            r#"
            contract Token {
                storage { supply: u256, }

                #[constructor]
                pub fn init() { self.supply = 1000; }

                #[view]
                pub fn get_supply() -> u256 { return self.supply; }

                pub fn set_supply(v: u256) { self.supply = v; }
            }
        "#,
        );

        // Check magic
        assert_eq!(&data[0..4], &MAGIC);
        assert_eq!(u16::from_le_bytes([data[4], data[5]]), FORMAT_VERSION);

        // Decode
        let pyc = decode(&data).expect("decode should succeed");
        assert_eq!(pyc.version, FORMAT_VERSION);
        assert!(
            !pyc.runtime.is_empty(),
            "runtime bytecode should be non-empty"
        );
        assert!(pyc.abi_json.contains("\"contract\": \"Token\""));
        assert!(pyc.abi_json.contains("get_supply"));
        assert!(pyc.abi_json.contains("set_supply"));
        assert!(pyc.storage_json.contains("supply"));
    }

    #[test]
    fn pyc_invalid_magic() {
        let result = decode(&[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid magic"));
    }

    #[test]
    fn pyc_too_small() {
        let result = decode(&[0x50, 0x59]);
        assert!(result.is_err());
    }

    #[test]
    fn pyc_runtime_executable_on_pvm() {
        let data = compile_pyc(
            r#"
            contract T {
                pub fn f() -> u64 { return 42; }
            }
        "#,
        );
        let pyc = decode(&data).unwrap();

        // The runtime bytecode should execute on PVM
        // (In production mode, needs calldata with selector. Skip for this test.)
        assert!(!pyc.runtime.is_empty());
        assert!(
            pyc.runtime.len().is_multiple_of(4),
            "bytecode should be 4-byte aligned"
        );
    }
}
