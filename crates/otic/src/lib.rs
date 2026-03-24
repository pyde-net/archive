//! Otigen Compiler (otic): compiles .oti source files to PVM bytecode.
//!
//! Pipeline: source → lexer → parser → resolve → type check → IR → optimize → codegen → .pyc

pub mod token;
pub mod lexer;
pub mod ast;
pub mod parser;
pub mod resolve;
pub mod types;
pub mod typecheck;
