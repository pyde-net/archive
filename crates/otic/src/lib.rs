//! Otigen Compiler (otic): compiles .oti source files to PVM bytecode.
//!
//! Pipeline: source → lexer → parser → resolve → type check → safety → IR → optimize → codegen → .pyc

// Compiler + VM internals pass around nested generics (HashMap of
// Vec of tuples, etc.) where the shape IS the documentation; clippy
// flags these as `type_complexity`. Adding aliases would add names
// to learn without improving readability. Scoped allow at the
// module level; narrow to specific items if this grows.
#![allow(clippy::type_complexity)]

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
use types::Ty;

/// Resolve an AST type to an IR type. Standalone version for use outside the lowerer
/// (e.g. extracting contract signatures during compile_all).
fn resolve_ast_type(ty: &ast::Type) -> Ty {
    match ty {
        ast::Type::Primitive(p, _) => match p {
            ast::PrimitiveType::U8 => Ty::U8,
            ast::PrimitiveType::U16 => Ty::U16,
            ast::PrimitiveType::U32 => Ty::U32,
            ast::PrimitiveType::U64 => Ty::U64,
            ast::PrimitiveType::U128 => Ty::U128,
            ast::PrimitiveType::U256 => Ty::U256,
            ast::PrimitiveType::I8 => Ty::I8,
            ast::PrimitiveType::I16 => Ty::I16,
            ast::PrimitiveType::I32 => Ty::I32,
            ast::PrimitiveType::I64 => Ty::I64,
            ast::PrimitiveType::I128 => Ty::I128,
            ast::PrimitiveType::I256 => Ty::I256,
            ast::PrimitiveType::Bool => Ty::Bool,
            ast::PrimitiveType::Address => Ty::Address,
            ast::PrimitiveType::StringType => Ty::StringTy,
        },
        ast::Type::Bytes(_) => Ty::Bytes,
        ast::Type::Array(elem, size, _) => Ty::Array(Box::new(resolve_ast_type(elem)), *size),
        ast::Type::Vec(elem, _) => Ty::Vec(Box::new(resolve_ast_type(elem))),
        ast::Type::Map(key, val, _) => Ty::Map(Box::new(resolve_ast_type(key)), Box::new(resolve_ast_type(val))),
        ast::Type::Named(path) => {
            let name = path.last().map(|i| i.name.as_str()).unwrap_or("");
            match name {
                "u8" => Ty::U8, "u16" => Ty::U16, "u32" => Ty::U32, "u64" => Ty::U64,
                "u128" => Ty::U128, "u256" => Ty::U256,
                "i8" => Ty::I8, "i16" => Ty::I16, "i32" => Ty::I32, "i64" => Ty::I64,
                "i128" => Ty::I128, "i256" => Ty::I256,
                "bool" => Ty::Bool, "Address" => Ty::Address, "String" => Ty::StringTy,
                _ => Ty::Struct(name.to_string()),
            }
        }
        ast::Type::Tuple(types, _) => Ty::Tuple(types.iter().map(resolve_ast_type).collect()),
    }
}

/// Extract public function signatures and constructor signatures from all contracts
/// in the file. Used to enable cross-contract typed dispatch in compile_all.
fn extract_all_contract_signatures(
    file: &ast::SourceFile,
) -> (
    HashMap<String, Vec<(String, Vec<(String, Ty)>, Ty)>>,  // contract_functions
    HashMap<String, Vec<(String, Ty)>>,                       // contract_constructors
) {
    let mut contract_functions = HashMap::new();
    let mut contract_constructors = HashMap::new();

    for item in &file.items {
        if let ast::Item::Contract(c) = item {
            let mut pub_fns: Vec<(String, Vec<(String, Ty)>, Ty)> = Vec::new();
            for ci in &c.items {
                if let ast::ContractItem::Function(f) = ci {
                    if f.is_pub && !f.is_constructor() && !f.is_test() {
                        let params: Vec<(String, Ty)> = f.params.iter()
                            .map(|p| (p.name.name.clone(), resolve_ast_type(&p.ty)))
                            .collect();
                        let ret = f.return_type.as_ref()
                            .map(resolve_ast_type)
                            .unwrap_or(Ty::Unit);
                        pub_fns.push((f.name.name.clone(), params, ret));
                    }
                    if f.is_constructor() {
                        let params: Vec<(String, Ty)> = f.params.iter()
                            .map(|p| (p.name.name.clone(), resolve_ast_type(&p.ty)))
                            .collect();
                        contract_constructors.insert(c.name.name.clone(), params);
                    }
                }
            }
            if !pub_fns.is_empty() {
                contract_functions.insert(c.name.name.clone(), pub_fns);
            }
        }
    }

    (contract_functions, contract_constructors)
}

/// Compile all contracts in a source file. Returns a map of contract name → CompiledContract.
/// Contracts are compiled in declaration order. Later contracts can reference earlier ones
/// via `create!(ContractName, args)` — the compiler embeds the bytecode at compile time.
/// Cross-contract typed dispatch (Contract::at(addr).method()) works across all contracts
/// in the file.
pub fn compile_all(src: &str) -> Vec<(String, codegen::CompiledContract)> {
    let (tokens, _) = lexer::Lexer::new(src).tokenize();
    let (file, _) = parser::Parser::new(tokens).parse();

    // Extract function signatures from ALL contracts up front so typed dispatch
    // (Contract::at(addr).method()) works regardless of declaration order.
    let (all_contract_fns, all_contract_ctors) = extract_all_contract_signatures(&file);

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

        let mut ir = lower::lower_with_context(
            &single_file,
            &compiled_registry,
            &all_contract_fns,
            &all_contract_ctors,
        );
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
