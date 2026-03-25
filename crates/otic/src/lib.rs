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
