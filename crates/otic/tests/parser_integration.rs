//! Integration tests for the parser using .oti fixture files.

use otic::ast::*;
use otic::lexer::Lexer;
use otic::parser::Parser;

fn parse_file(src: &str) -> SourceFile {
    let (tokens, lex_errors) = Lexer::new(src).tokenize();
    assert!(lex_errors.is_empty(), "lex errors: {:?}", lex_errors);
    let (file, parse_errors) = Parser::new(tokens).parse();
    assert!(parse_errors.is_empty(), "parse errors: {:?}", parse_errors);
    file
}

#[test]
fn parse_erc20_contract() {
    let src = include_str!("fixtures/erc20.oti");
    let file = parse_file(src);

    assert_eq!(file.items.len(), 1);
    if let Item::Contract(c) = &file.items[0] {
        assert_eq!(c.name.name, "PydeToken");

        let mut storage_count = 0;
        let mut event_count = 0;
        let mut error_count = 0;
        let mut fn_count = 0;
        let mut pub_fn_count = 0;

        for item in &c.items {
            match item {
                ContractItem::Storage(s) => {
                    storage_count += 1;
                    // 6 fields: name, symbol, decimals, total_supply, balances, allowances
                    assert_eq!(s.fields.len(), 6);
                }
                ContractItem::Event(e) => {
                    event_count += 1;
                    match e.name.name.as_str() {
                        "Transfer" => {
                            assert_eq!(e.fields.len(), 3);
                            assert!(e.fields[0].indexed); // from
                            assert!(e.fields[1].indexed); // to
                            assert!(!e.fields[2].indexed); // amount
                        }
                        "Approval" => {
                            assert_eq!(e.fields.len(), 3);
                        }
                        _ => panic!("unexpected event: {}", e.name.name),
                    }
                }
                ContractItem::Error(_) => error_count += 1,
                ContractItem::Function(f) => {
                    fn_count += 1;
                    if f.is_pub {
                        pub_fn_count += 1;
                    }
                }
                _ => {}
            }
        }

        assert_eq!(storage_count, 1);
        assert_eq!(event_count, 2);
        assert_eq!(error_count, 3);
        assert_eq!(fn_count, 7);
        assert_eq!(pub_fn_count, 7);
    } else {
        panic!("expected contract");
    }
}

// Test a sample from each program category to ensure broad parsing coverage
macro_rules! parse_fixture {
    ($name:ident, $path:expr) => {
        #[test]
        fn $name() {
            let src = include_str!($path);
            let (tokens, lex_errors) = Lexer::new(src).tokenize();
            if !lex_errors.is_empty() {
                panic!("lex errors in {}: {:?}", stringify!($name), lex_errors);
            }
            let (file, parse_errors) = Parser::new(tokens).parse();
            if !parse_errors.is_empty() {
                panic!("parse errors in {}: {:?}", stringify!($name), parse_errors);
            }
            assert!(
                !file.items.is_empty(),
                "{} produced no items",
                stringify!($name)
            );
        }
    };
}

// === DeFi (15) ===
parse_fixture!(
    parse_erc20_advanced,
    "fixtures/programs/defi/erc20_advanced.oti"
);
parse_fixture!(parse_amm_pool, "fixtures/programs/defi/amm_pool.oti");
parse_fixture!(
    parse_lending_pool,
    "fixtures/programs/defi/lending_pool.oti"
);
parse_fixture!(parse_staking, "fixtures/programs/defi/staking.oti");
parse_fixture!(parse_vault, "fixtures/programs/defi/vault.oti");
parse_fixture!(parse_flash_loan, "fixtures/programs/defi/flash_loan.oti");
parse_fixture!(parse_order_book, "fixtures/programs/defi/order_book.oti");
parse_fixture!(parse_yield_farm, "fixtures/programs/defi/yield_farm.oti");
parse_fixture!(
    parse_wrapped_token,
    "fixtures/programs/defi/wrapped_token.oti"
);
parse_fixture!(
    parse_price_oracle,
    "fixtures/programs/defi/price_oracle.oti"
);
parse_fixture!(parse_stable_swap, "fixtures/programs/defi/stable_swap.oti");
parse_fixture!(
    parse_fee_distributor,
    "fixtures/programs/defi/fee_distributor.oti"
);
parse_fixture!(
    parse_liquidity_gauge,
    "fixtures/programs/defi/liquidity_gauge.oti"
);
parse_fixture!(parse_router, "fixtures/programs/defi/router.oti");
parse_fixture!(
    parse_token_vesting,
    "fixtures/programs/defi/token_vesting.oti"
);

// === NFT (7) ===
parse_fixture!(parse_basic_nft, "fixtures/programs/nft/basic_nft.oti");
parse_fixture!(
    parse_nft_marketplace,
    "fixtures/programs/nft/nft_marketplace.oti"
);
parse_fixture!(parse_nft_auction, "fixtures/programs/nft/nft_auction.oti");
parse_fixture!(
    parse_nft_collection,
    "fixtures/programs/nft/nft_collection.oti"
);
parse_fixture!(
    parse_soulbound_token,
    "fixtures/programs/nft/soulbound_token.oti"
);
parse_fixture!(
    parse_nft_royalties,
    "fixtures/programs/nft/nft_royalties.oti"
);
parse_fixture!(parse_nft_rental, "fixtures/programs/nft/nft_rental.oti");

// === Governance (8) ===
parse_fixture!(parse_dao, "fixtures/programs/governance/dao.oti");
parse_fixture!(parse_governor, "fixtures/programs/governance/governor.oti");
parse_fixture!(parse_multisig, "fixtures/programs/governance/multisig.oti");
parse_fixture!(parse_timelock, "fixtures/programs/governance/timelock.oti");
parse_fixture!(
    parse_voting_token,
    "fixtures/programs/governance/voting_token.oti"
);
parse_fixture!(parse_treasury, "fixtures/programs/governance/treasury.oti");
parse_fixture!(
    parse_reputation,
    "fixtures/programs/governance/reputation.oti"
);
parse_fixture!(
    parse_quadratic_voting,
    "fixtures/programs/governance/quadratic_voting.oti"
);

// === Games (7) ===
parse_fixture!(parse_lottery, "fixtures/programs/games/lottery.oti");
parse_fixture!(
    parse_prediction_market,
    "fixtures/programs/games/prediction_market.oti"
);
parse_fixture!(
    parse_rock_paper_scissors,
    "fixtures/programs/games/rock_paper_scissors.oti"
);
parse_fixture!(parse_coin_flip, "fixtures/programs/games/coin_flip.oti");
parse_fixture!(parse_chess_wager, "fixtures/programs/games/chess_wager.oti");
parse_fixture!(parse_nft_battle, "fixtures/programs/games/nft_battle.oti");
parse_fixture!(parse_raffle, "fixtures/programs/games/raffle.oti");

// === Finance (8) ===
parse_fixture!(parse_escrow, "fixtures/programs/finance/escrow.oti");
parse_fixture!(
    parse_payment_splitter,
    "fixtures/programs/finance/payment_splitter.oti"
);
parse_fixture!(
    parse_subscription,
    "fixtures/programs/finance/subscription.oti"
);
parse_fixture!(parse_invoice, "fixtures/programs/finance/invoice.oti");
parse_fixture!(parse_payroll, "fixtures/programs/finance/payroll.oti");
parse_fixture!(parse_crowdfund, "fixtures/programs/finance/crowdfund.oti");
parse_fixture!(parse_insurance, "fixtures/programs/finance/insurance.oti");
parse_fixture!(parse_bond, "fixtures/programs/finance/bond.oti");

// === Access Control (7) ===
parse_fixture!(parse_ownable, "fixtures/programs/access/ownable.oti");
parse_fixture!(
    parse_role_manager,
    "fixtures/programs/access/role_manager.oti"
);
parse_fixture!(
    parse_two_step_ownership,
    "fixtures/programs/access/two_step_ownership.oti"
);
parse_fixture!(parse_allowlist, "fixtures/programs/access/allowlist.oti");
parse_fixture!(
    parse_time_lock_admin,
    "fixtures/programs/access/time_lock_admin.oti"
);
parse_fixture!(parse_guardian, "fixtures/programs/access/guardian.oti");
parse_fixture!(
    parse_fee_manager,
    "fixtures/programs/access/fee_manager.oti"
);

// === Infrastructure (8) ===
parse_fixture!(
    parse_name_registry,
    "fixtures/programs/infra/name_registry.oti"
);
parse_fixture!(parse_proxy, "fixtures/programs/infra/proxy.oti");
parse_fixture!(parse_factory, "fixtures/programs/infra/factory.oti");
parse_fixture!(
    parse_access_control,
    "fixtures/programs/infra/access_control.oti"
);
parse_fixture!(
    parse_event_logger,
    "fixtures/programs/infra/event_logger.oti"
);
parse_fixture!(
    parse_rate_limiter,
    "fixtures/programs/infra/rate_limiter.oti"
);
parse_fixture!(
    parse_circuit_breaker,
    "fixtures/programs/infra/circuit_breaker.oti"
);
parse_fixture!(parse_whitelist, "fixtures/programs/infra/whitelist.oti");

// === Library (5) ===
parse_fixture!(parse_math_lib, "fixtures/programs/library/math_lib.oti");
parse_fixture!(
    parse_string_utils,
    "fixtures/programs/library/string_utils.oti"
);
parse_fixture!(
    parse_array_utils,
    "fixtures/programs/library/array_utils.oti"
);
parse_fixture!(
    parse_address_utils,
    "fixtures/programs/library/address_utils.oti"
);
parse_fixture!(parse_bitmap, "fixtures/programs/library/bitmap.oti");

// === Patterns (9) ===
parse_fixture!(
    parse_token_with_resource,
    "fixtures/programs/patterns/token_with_resource.oti"
);
parse_fixture!(
    parse_multi_contract,
    "fixtures/programs/patterns/multi_contract.oti"
);
parse_fixture!(
    parse_state_machine,
    "fixtures/programs/patterns/state_machine.oti"
);
parse_fixture!(
    parse_batch_operations,
    "fixtures/programs/patterns/batch_operations.oti"
);
parse_fixture!(
    parse_diamond_storage,
    "fixtures/programs/patterns/diamond_storage.oti"
);
parse_fixture!(
    parse_complex_structs,
    "fixtures/programs/patterns/complex_structs.oti"
);
parse_fixture!(
    parse_sponsored_functions,
    "fixtures/programs/patterns/sponsored_functions.oti"
);
parse_fixture!(
    parse_bytes_and_crypto,
    "fixtures/programs/patterns/bytes_and_crypto.oti"
);
parse_fixture!(
    parse_nested_types,
    "fixtures/programs/patterns/nested_types.oti"
);

// === Social (5) ===
parse_fixture!(
    parse_social_media,
    "fixtures/programs/social/social_media.oti"
);
parse_fixture!(parse_messaging, "fixtures/programs/social/messaging.oti");
parse_fixture!(parse_tipping, "fixtures/programs/social/tipping.oti");
parse_fixture!(
    parse_content_platform,
    "fixtures/programs/social/content_platform.oti"
);
parse_fixture!(
    parse_follow_system,
    "fixtures/programs/social/follow_system.oti"
);

// === Supply Chain (5) ===
parse_fixture!(parse_tracking, "fixtures/programs/supply/tracking.oti");
parse_fixture!(
    parse_certification,
    "fixtures/programs/supply/certification.oti"
);
parse_fixture!(parse_inventory, "fixtures/programs/supply/inventory.oti");
parse_fixture!(parse_shipping, "fixtures/programs/supply/shipping.oti");
parse_fixture!(parse_provenance, "fixtures/programs/supply/provenance.oti");

// === Real Estate (3) ===
parse_fixture!(
    parse_property_deed,
    "fixtures/programs/realestate/property_deed.oti"
);
parse_fixture!(
    parse_rental_agreement,
    "fixtures/programs/realestate/rental_agreement.oti"
);
parse_fixture!(
    parse_fractional_ownership,
    "fixtures/programs/realestate/fractional_ownership.oti"
);

// === Health (3) ===
parse_fixture!(
    parse_medical_records,
    "fixtures/programs/health/medical_records.oti"
);
parse_fixture!(
    parse_prescription,
    "fixtures/programs/health/prescription.oti"
);
parse_fixture!(
    parse_clinical_trial,
    "fixtures/programs/health/clinical_trial.oti"
);

// === Education (3) ===
parse_fixture!(
    parse_credential,
    "fixtures/programs/education/credential.oti"
);
parse_fixture!(
    parse_course_marketplace,
    "fixtures/programs/education/course_marketplace.oti"
);
parse_fixture!(
    parse_scholarship,
    "fixtures/programs/education/scholarship.oti"
);

// === Legal (3) ===
parse_fixture!(parse_will, "fixtures/programs/legal/will.oti");
parse_fixture!(
    parse_dispute_resolution,
    "fixtures/programs/legal/dispute_resolution.oti"
);
parse_fixture!(
    parse_smart_agreement,
    "fixtures/programs/legal/smart_agreement.oti"
);

// === Energy (3) ===
parse_fixture!(
    parse_carbon_credits,
    "fixtures/programs/energy/carbon_credits.oti"
);
parse_fixture!(
    parse_energy_trading,
    "fixtures/programs/energy/energy_trading.oti"
);
parse_fixture!(
    parse_renewable_certificates,
    "fixtures/programs/energy/renewable_certificates.oti"
);
