//! Otigen Compiler (otic): compiles .oti source files to PVM bytecode.
//!
//! Pipeline: source → lexer → parser → resolve → type check → safety → IR → optimize → codegen → .pyc

pub mod token;
pub mod lexer;
pub mod ast;
pub mod parser;
pub mod resolve;
pub mod types;
pub mod typecheck;
pub mod safety;
pub mod ir;
pub mod lower;
pub mod optimize;
pub mod memory;
pub mod codegen;
pub mod abi;
pub mod pyc;
pub mod diagnostic;

use std::collections::HashMap;

/// Compile all contracts in a source file. Returns a map of contract name → CompiledContract.
/// Contracts are compiled in declaration order. Later contracts can reference earlier ones
/// via `create!(ContractName, args)` — the compiler embeds the bytecode at compile time.
pub fn compile_all(src: &str) -> Vec<(String, codegen::CompiledContract)> {
    let (tokens, _) = lexer::Lexer::new(src).tokenize();
    let (file, _) = parser::Parser::new(tokens).parse();

    // Collect contract names
    let contract_items: Vec<&ast::ContractDef> = file.items.iter().filter_map(|item| {
        if let ast::Item::Contract(c) = item { Some(c) } else { None }
    }).collect();

    let mut results = Vec::new();
    let mut compiled_registry: HashMap<String, Vec<u8>> = HashMap::new();

    for contract in &contract_items {
        // Build a SourceFile with only this contract (plus top-level enums/structs/interfaces)
        let mut single_file = ast::SourceFile { items: Vec::new() };
        for item in &file.items {
            match item {
                ast::Item::Contract(c) if c.name.name == contract.name.name => {
                    single_file.items.push(item.clone());
                }
                ast::Item::Contract(_) => {} // skip other contracts
                _ => single_file.items.push(item.clone()), // keep enums, interfaces, etc.
            }
        }

        let mut ir = lower::lower_with_contracts(&single_file, &compiled_registry);
        optimize::optimize(&mut ir);
        let cg = codegen::CodeGen::new();
        let compiled = cg.generate(&ir);

        // Build deploy-format bytes for the registry:
        // [clen:4 LE][rlen:4 LE][constructor_bytes][runtime_bytes]
        let clen = compiled.constructor_bytecode.len() as u32;
        let rlen = compiled.runtime_bytecode.len() as u32;
        let mut deploy_bytes = Vec::with_capacity(8 + clen as usize + rlen as usize);
        deploy_bytes.extend_from_slice(&clen.to_le_bytes());
        deploy_bytes.extend_from_slice(&rlen.to_le_bytes());
        deploy_bytes.extend_from_slice(&compiled.constructor_bytecode);
        deploy_bytes.extend_from_slice(&compiled.runtime_bytecode);
        compiled_registry.insert(contract.name.name.clone(), deploy_bytes);

        results.push((contract.name.name.clone(), compiled));
    }

    results
}
