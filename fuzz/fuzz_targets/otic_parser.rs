//! Fuzz target: full Otigen frontend on arbitrary input.
//!
//! Reachable from `pyde-dev build`, `pyde-dev script`, and `otic
//! build/check/test/abi/lex` whenever a developer compiles a
//! third-party `.oti` source. A panic in lex / parse / resolve /
//! typecheck / safety would crash the toolchain on a hostile
//! contract before any compile output is produced — not a
//! consensus-DoS like the wire targets, but a developer-tooling
//! denial-of-service that turns "this contract won't compile" into
//! "this contract crashes my IDE" or, in CI, into a flake that
//! blocks every PR until someone notices the input.
//!
//! The fuzz body mirrors `crates/otic/src/main.rs::run_frontend`'s
//! sequence and accepts any `Result` (Ok or Err diagnostics) as
//! valid — only panics / aborts fail the run. Non-UTF-8 inputs are
//! coerced via `from_utf8_lossy` so libfuzzer's mutator can keep
//! exercising the byte-level surface without first having to
//! discover well-formed UTF-8.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let src = std::str::from_utf8(data).map(str::to_owned).unwrap_or_else(|_| {
        String::from_utf8_lossy(data).into_owned()
    });

    // Lex + parse: the two stages every other front-end pass
    // depends on. A panic here would also blow up `otic test`,
    // `otic build`, `pyde-dev build`, and every developer
    // tool that reads a contract.
    let (tokens, _lex_errors) = otic::lexer::Lexer::new(&src).tokenize();
    let (file, _parse_errors) = otic::parser::Parser::new(tokens).parse();

    // Resolve / typecheck / safety run on a successfully-parsed
    // tree. They each accept arbitrary syntactically-valid
    // `SourceFile` shapes and return diagnostics, never panic.
    let _ = otic::resolve::Resolver::new().resolve(&file);
    let _ = otic::typecheck::TypeChecker::new().check(&file);
    let _ = otic::safety::SafetyChecker::new().check(&file);
});
