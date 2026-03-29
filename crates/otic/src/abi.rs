//! ABI generation: extract contract interface as JSON.
//!
//! Produces a JSON description of all public functions, events, errors,
//! and storage fields — everything a caller needs to interact with the contract.

use crate::codegen::{compute_selector, CompiledContract};
use crate::ir::IrProgram;
use crate::types::Ty;

/// A complete ABI description of a compiled contract.
#[derive(Clone, Debug)]
pub struct ContractAbi {
    pub contract_name: String,
    pub functions: Vec<AbiFn>,
    pub events: Vec<AbiEvent>,
    pub errors: Vec<AbiError>,
    pub storage: Vec<AbiStorageField>,
}

#[derive(Clone, Debug)]
pub struct AbiFn {
    pub name: String,
    pub selector: u32,
    pub params: Vec<AbiParam>,
    pub return_type: String,
    pub is_view: bool,
    pub is_payable: bool,
    pub is_constructor: bool,
    pub is_reentrant: bool,
    pub doc: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AbiParam {
    pub name: String,
    pub ty: String,
}

#[derive(Clone, Debug)]
pub struct AbiEvent {
    pub name: String,
    pub fields: Vec<AbiEventField>,
    pub doc: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AbiEventField {
    pub name: String,
    pub ty: String,
    pub indexed: bool,
}

#[derive(Clone, Debug)]
pub struct AbiError {
    pub name: String,
    pub fields: Vec<AbiParam>,
    pub doc: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AbiStorageField {
    pub name: String,
    pub ty: String,
    pub slot: u32,
}

/// Extract ABI from a compiled IR program.
pub fn generate_abi(program: &IrProgram) -> ContractAbi {
    let mut functions = Vec::new();
    let mut events = Vec::new();
    let mut errors = Vec::new();
    let mut storage = Vec::new();

    // Functions
    for func in &program.functions {
        if func.is_test {
            continue;
        }
        if func.is_pub || func.is_constructor {
            let selector = if func.is_constructor {
                0
            } else {
                compute_selector(&func.name)
            };
            functions.push(AbiFn {
                name: func.name.clone(),
                selector,
                params: func
                    .params
                    .iter()
                    .map(|(name, ty)| AbiParam {
                        name: name.clone(),
                        ty: ty_to_string(ty),
                    })
                    .collect(),
                return_type: ty_to_string(&func.return_ty),
                is_view: func.is_view,
                is_payable: func.is_payable,
                is_constructor: func.is_constructor,
                is_reentrant: func.is_reentrant,
                doc: func.doc.clone(),
            });
        }
    }

    // Events
    for event in &program.event_defs {
        events.push(AbiEvent {
            name: event.name.clone(),
            fields: event
                .fields
                .iter()
                .map(|f| AbiEventField {
                    name: f.name.clone(),
                    ty: ty_to_string(&f.ty),
                    indexed: f.indexed,
                })
                .collect(),
            doc: event.doc.clone(),
        });
    }

    // Errors
    for error in &program.error_defs {
        errors.push(AbiError {
            name: error.name.clone(),
            fields: error
                .fields
                .iter()
                .map(|(name, ty)| AbiParam {
                    name: name.clone(),
                    ty: ty_to_string(ty),
                })
                .collect(),
            doc: error.doc.clone(),
        });
    }

    // Storage
    for field in &program.storage_fields {
        storage.push(AbiStorageField {
            name: field.name.clone(),
            ty: ty_to_string(&field.ty),
            slot: field.slot,
        });
    }

    ContractAbi {
        contract_name: program.contract_name.clone(),
        functions,
        events,
        errors,
        storage,
    }
}

/// Serialize ABI to JSON string.
pub fn abi_to_json(abi: &ContractAbi) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"contract\": \"{}\",\n", abi.contract_name));

    // Functions
    out.push_str("  \"functions\": [\n");
    for (i, f) in abi.functions.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"name\": \"{}\",\n", f.name));
        out.push_str(&format!("      \"selector\": \"0x{:08x}\",\n", f.selector));

        out.push_str("      \"params\": [");
        for (j, p) in f.params.iter().enumerate() {
            out.push_str(&format!(
                "{{\"name\":\"{}\",\"type\":\"{}\"}}",
                p.name, p.ty
            ));
            if j + 1 < f.params.len() {
                out.push(',');
            }
        }
        out.push_str("],\n");

        out.push_str(&format!("      \"returns\": \"{}\",\n", f.return_type));
        out.push_str(&format!("      \"view\": {},\n", f.is_view));
        out.push_str(&format!("      \"payable\": {},\n", f.is_payable));
        out.push_str(&format!("      \"constructor\": {},\n", f.is_constructor));
        out.push_str(&format!("      \"reentrant\": {}", f.is_reentrant));
        if let Some(ref doc) = f.doc {
            out.push_str(&format!(
                ",\n      \"doc\": \"{}\"",
                doc.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "")
            ));
        }
        out.push('\n');
        out.push_str("    }");
        if i + 1 < abi.functions.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ],\n");

    // Events
    out.push_str("  \"events\": [\n");
    for (i, e) in abi.events.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"name\": \"{}\",\n", e.name));
        out.push_str("      \"fields\": [");
        for (j, f) in e.fields.iter().enumerate() {
            out.push_str(&format!(
                "{{\"name\":\"{}\",\"type\":\"{}\",\"indexed\":{}}}",
                f.name, f.ty, f.indexed
            ));
            if j + 1 < e.fields.len() {
                out.push(',');
            }
        }
        out.push(']');
        if let Some(ref doc) = e.doc {
            out.push_str(&format!(
                ",\n      \"doc\": \"{}\"",
                doc.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "")
            ));
        }
        out.push('\n');
        out.push_str("    }");
        if i + 1 < abi.events.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ],\n");

    // Errors
    out.push_str("  \"errors\": [\n");
    for (i, e) in abi.errors.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"name\": \"{}\",\n", e.name));
        out.push_str("      \"fields\": [");
        for (j, f) in e.fields.iter().enumerate() {
            out.push_str(&format!(
                "{{\"name\":\"{}\",\"type\":\"{}\"}}",
                f.name, f.ty
            ));
            if j + 1 < e.fields.len() {
                out.push(',');
            }
        }
        out.push(']');
        if let Some(ref doc) = e.doc {
            out.push_str(&format!(
                ",\n      \"doc\": \"{}\"",
                doc.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "")
            ));
        }
        out.push('\n');
        out.push_str("    }");
        if i + 1 < abi.errors.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ],\n");

    // Storage
    out.push_str("  \"storage\": [\n");
    for (i, s) in abi.storage.iter().enumerate() {
        out.push_str(&format!(
            "    {{\"name\":\"{}\",\"type\":\"{}\",\"slot\":{}}}",
            s.name, s.ty, s.slot
        ));
        if i + 1 < abi.storage.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]\n");

    out.push('}');
    out
}

/// Generate a full JSON build artifact (like Hardhat/Foundry).
/// Contains ABI, hex-encoded bytecode, storage layout, and compiler metadata.
pub fn artifact_to_json(abi: &ContractAbi, contract: &CompiledContract) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"contractName\": \"{}\",\n", abi.contract_name));
    out.push_str(&format!("  \"compiler\": \"otic {}\",\n", env!("CARGO_PKG_VERSION")));

    // Bytecode (hex-encoded)
    out.push_str("  \"bytecode\": \"0x");
    for b in &contract.bytecode {
        out.push_str(&format!("{:02x}", b));
    }
    out.push_str("\",\n");

    // Constructor bytecode
    out.push_str("  \"constructorBytecode\": \"0x");
    for b in &contract.constructor_bytecode {
        out.push_str(&format!("{:02x}", b));
    }
    out.push_str("\",\n");

    // Deployed/runtime bytecode
    out.push_str("  \"deployedBytecode\": \"0x");
    for b in &contract.runtime_bytecode {
        out.push_str(&format!("{:02x}", b));
    }
    out.push_str("\",\n");

    // Instruction count
    out.push_str(&format!("  \"instructionCount\": {},\n", contract.instruction_count));

    // Function selectors
    out.push_str("  \"selectors\": {");
    for (i, (sel, name, _)) in contract.selectors.iter().enumerate() {
        out.push_str(&format!("\"0x{:08x}\":\"{}\"", sel, name));
        if i + 1 < contract.selectors.len() { out.push(','); }
    }
    out.push_str("},\n");

    // Embed the full ABI
    out.push_str("  \"abi\": ");
    // Inline the ABI JSON (re-indent)
    let abi_json = abi_to_json(abi);
    for (i, line) in abi_json.lines().enumerate() {
        if i == 0 {
            out.push_str(line);
        } else {
            out.push_str("  ");
            out.push_str(line);
        }
        out.push('\n');
    }

    // Remove trailing newline, add comma
    if out.ends_with('\n') { out.pop(); }
    out.push_str(",\n");

    // Storage layout
    out.push_str("  \"storage\": [\n");
    for (i, s) in abi.storage.iter().enumerate() {
        out.push_str(&format!(
            "    {{\"name\": \"{}\", \"type\": \"{}\", \"slot\": {}}}",
            s.name, s.ty, s.slot
        ));
        if i + 1 < abi.storage.len() { out.push(','); }
        out.push('\n');
    }
    out.push_str("  ]\n");

    out.push('}');
    out
}

fn ty_to_string(ty: &Ty) -> String {
    match ty {
        Ty::U8 => "u8".into(),
        Ty::U16 => "u16".into(),
        Ty::U32 => "u32".into(),
        Ty::U64 => "u64".into(),
        Ty::U128 => "u128".into(),
        Ty::U256 => "u256".into(),
        Ty::I8 => "i8".into(),
        Ty::I16 => "i16".into(),
        Ty::I32 => "i32".into(),
        Ty::I64 => "i64".into(),
        Ty::I128 => "i128".into(),
        Ty::I256 => "i256".into(),
        Ty::Bool => "bool".into(),
        Ty::Address => "Address".into(),
        Ty::StringTy => "String".into(),
        Ty::Bytes => "bytes".into(),
        Ty::Array(inner, size) => format!("[{}; {}]", ty_to_string(inner), size),
        Ty::Vec(inner) => format!("Vec<{}>", ty_to_string(inner)),
        Ty::Map(k, v) => format!("Map<{}, {}>", ty_to_string(k), ty_to_string(v)),
        Ty::Tuple(items) => {
            let parts: Vec<String> = items.iter().map(|t| ty_to_string(t)).collect();
            format!("({})", parts.join(", "))
        }
        Ty::Struct(name) => name.clone(),
        Ty::Enum(name) => name.clone(),
        Ty::Unit => "()".into(),
        _ => "unknown".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;
    use crate::lower;
    use crate::parser::Parser;

    fn gen_abi(src: &str) -> ContractAbi {
        let (tokens, _) = Lexer::new(src).tokenize();
        let (file, _) = Parser::new(tokens).parse();
        let ir = lower::lower(&file);
        generate_abi(&ir)
    }

    #[test]
    fn abi_basic_contract() {
        let abi = gen_abi(
            r#"
            contract Token {
                storage { supply: u256, owner: Address, }

                event Transfer { from: Address, to: Address, amount: u256, }
                error InsufficientBalance { required: u256, available: u256, }

                #[constructor]
                pub fn init(initial_supply: u256) {
                    self.supply = initial_supply;
                }

                /// Get the total supply
                #[view]
                pub fn total_supply() -> u256 {
                    return self.supply;
                }

                #[payable]
                pub fn transfer(to: Address, amount: u256) {
                    self.supply = self.supply;
                }
            }
        "#,
        );

        assert_eq!(abi.contract_name, "Token");
        assert_eq!(abi.functions.len(), 3); // init, total_supply, transfer
        assert_eq!(abi.events.len(), 1);
        assert_eq!(abi.errors.len(), 1);
        assert_eq!(abi.storage.len(), 2);

        // Check constructor
        let init = abi.functions.iter().find(|f| f.name == "init").unwrap();
        assert!(init.is_constructor);
        assert_eq!(init.params.len(), 1);
        assert_eq!(init.params[0].name, "initial_supply");

        // Check view function
        let ts = abi
            .functions
            .iter()
            .find(|f| f.name == "total_supply")
            .unwrap();
        assert!(ts.is_view);
        assert_eq!(ts.return_type, "u256");
        assert!(ts.doc.is_some());

        // Check payable
        let transfer = abi.functions.iter().find(|f| f.name == "transfer").unwrap();
        assert!(transfer.is_payable);

        // Check event
        assert_eq!(abi.events[0].name, "Transfer");
        assert_eq!(abi.events[0].fields.len(), 3);

        // Check error
        assert_eq!(abi.errors[0].name, "InsufficientBalance");
        assert_eq!(abi.errors[0].fields.len(), 2);

        // Check storage
        assert_eq!(abi.storage[0].name, "supply");
        assert_eq!(abi.storage[0].ty, "u256");
        assert_eq!(abi.storage[1].name, "owner");
    }

    #[test]
    fn abi_to_json_valid() {
        let abi = gen_abi(
            r#"
            contract T {
                storage { count: u64, }
                pub fn inc() { self.count = self.count; }
                #[view]
                pub fn get() -> u64 { return self.count; }
            }
        "#,
        );

        let json = abi_to_json(&abi);
        assert!(json.contains("\"contract\": \"T\""));
        assert!(json.contains("\"name\": \"inc\""));
        assert!(json.contains("\"name\": \"get\""));
        assert!(json.contains("\"view\": true"));
        assert!(json.contains("\"count\""));
    }

    #[test]
    fn artifact_bytecode_runs_on_pvm() {
        // Full round-trip: compile → JSON artifact → extract bytecode → run on PVM
        let src = r#"
            contract T {
                pub fn add(a: u64, b: u64) -> u64 {
                    return a + b;
                }
            }
        "#;
        let (tokens, _) = Lexer::new(src).tokenize();
        let (file, _) = Parser::new(tokens).parse();
        let mut ir = lower::lower(&file);
        crate::optimize::optimize(&mut ir);
        let abi = generate_abi(&ir);
        let codegen = crate::codegen::CodeGen::new();
        let contract = codegen.generate(&ir);

        // Generate JSON artifact
        let json = artifact_to_json(&abi, &contract);

        // Verify JSON contains all bytecode sections
        assert!(json.contains("\"bytecode\": \"0x"));
        assert!(json.contains("\"deployedBytecode\": \"0x"));
        assert!(json.contains("\"constructorBytecode\": \"0x"));
        assert!(json.contains("\"selectors\":"));

        // Extract runtime bytecode from JSON and verify it matches the contract
        let marker = "\"deployedBytecode\": \"0x";
        let start = json.find(marker).unwrap() + marker.len();
        let end = json[start..].find('"').unwrap() + start;
        let hex = &json[start..end];
        let decoded: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i+2], 16).unwrap())
            .collect();
        assert_eq!(decoded, contract.runtime_bytecode, "decoded bytecode should match");

        // Run the runtime bytecode on PVM with calldata
        let selector = compute_selector("add");
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&selector.to_be_bytes()); // 4-byte selector (BE, like Ethereum)
        calldata.extend_from_slice(&10u64.to_le_bytes());
        calldata.extend_from_slice(&32u64.to_le_bytes());

        let mut vm = pyde_vm::vm::Vm::with_gas_limit(100_000);
        vm.calldata = calldata;
        vm.load(&decoded).unwrap();

        let mut steps = 0;
        loop {
            match vm.step() {
                Ok(Some(_)) => break,
                Ok(None) => { steps += 1; if steps > 1000 { break; } }
                Err(_) => break,
            }
        }

        assert_eq!(vm.cpu.read_gp(1), 42, "add(10, 32) from JSON artifact bytecode should be 42");
    }
}
