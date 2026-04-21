//! Integration tests for the lexer using .oti fixture files.

use otic::lexer::Lexer;
use otic::token::TokenKind;

#[test]
fn lex_erc20_contract() {
    let src = include_str!("fixtures/erc20.oti");
    let (tokens, errors) = Lexer::new(src).tokenize();
    assert!(errors.is_empty(), "lexer errors: {:?}", errors);

    // Should end with Eof
    assert_eq!(tokens.last().unwrap().kind, TokenKind::Eof);

    // Count key tokens to verify structure
    let contracts = tokens
        .iter()
        .filter(|t| t.kind == TokenKind::Contract)
        .count();
    let storages = tokens
        .iter()
        .filter(|t| t.kind == TokenKind::Storage)
        .count();
    let events = tokens.iter().filter(|t| t.kind == TokenKind::Event).count();
    let errors_kw = tokens.iter().filter(|t| t.kind == TokenKind::Error).count();
    let fns = tokens.iter().filter(|t| t.kind == TokenKind::Fn).count();
    let pubs = tokens.iter().filter(|t| t.kind == TokenKind::Pub).count();
    let emits = tokens.iter().filter(|t| t.kind == TokenKind::Emit).count();
    let returns = tokens
        .iter()
        .filter(|t| t.kind == TokenKind::Return)
        .count();
    let attrs: Vec<_> = tokens
        .iter()
        .filter(|t| matches!(&t.kind, TokenKind::Attribute(_)))
        .collect();

    assert_eq!(contracts, 1);
    assert_eq!(storages, 1);
    assert_eq!(events, 2); // Transfer, Approval
    assert_eq!(errors_kw, 3); // InsufficientBalance, InsufficientAllowance, TransferToZeroAddress
    assert_eq!(fns, 7); // init, transfer, approve, transfer_from, balance_of, allowance, get_total_supply
    assert_eq!(pubs, 7);
    assert_eq!(emits, 4); // Transfer emitted in init, transfer, transfer_from + Approval in approve
    assert_eq!(returns, 3); // balance_of, allowance, get_total_supply

    // Check attributes
    let attr_names: Vec<&str> = attrs
        .iter()
        .map(|t| {
            if let TokenKind::Attribute(s) = &t.kind {
                s.as_str()
            } else {
                ""
            }
        })
        .collect();
    assert!(attr_names.contains(&"constructor"));
    assert!(attr_names.contains(&"view"));
    assert!(attr_names.contains(&"indexed"));
}
