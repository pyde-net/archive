//! Otigen Compiler (otic): compiles .oti source files to PVM bytecode.
//!
//! Pipeline: source → lexer → parser → type check → IR → optimize → codegen → .pyc

pub mod token;
pub mod lexer;
pub mod ast;
pub mod parser;
