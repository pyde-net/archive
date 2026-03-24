//! Integration tests for the type checker using .oti fixture files.

use otic::lexer::Lexer;
use otic::parser::Parser;
use otic::typecheck::TypeChecker;

fn typecheck_file(src: &str) -> Vec<otic::typecheck::TypeError> {
    let (tokens, lex_errors) = Lexer::new(src).tokenize();
    assert!(lex_errors.is_empty(), "lex errors: {:?}", lex_errors);
    let (file, parse_errors) = Parser::new(tokens).parse();
    assert!(parse_errors.is_empty(), "parse errors: {:?}", parse_errors);
    TypeChecker::new().check(&file).errors
}

macro_rules! typecheck_fixture {
    ($name:ident, $path:expr) => {
        #[test]
        fn $name() {
            let src = include_str!($path);
            let errors = typecheck_file(src);
            if !errors.is_empty() {
                for e in &errors {
                    eprintln!("  {}", e);
                }
                panic!("{} had {} type errors", stringify!($name), errors.len());
            }
        }
    };
}

// === ERC20 ===
typecheck_fixture!(typecheck_erc20, "fixtures/erc20.oti");

// === DeFi ===
typecheck_fixture!(typecheck_erc20_advanced, "fixtures/programs/defi/erc20_advanced.oti");
typecheck_fixture!(typecheck_amm_pool, "fixtures/programs/defi/amm_pool.oti");
typecheck_fixture!(typecheck_lending_pool, "fixtures/programs/defi/lending_pool.oti");
typecheck_fixture!(typecheck_staking, "fixtures/programs/defi/staking.oti");
typecheck_fixture!(typecheck_vault, "fixtures/programs/defi/vault.oti");
typecheck_fixture!(typecheck_flash_loan, "fixtures/programs/defi/flash_loan.oti");
typecheck_fixture!(typecheck_order_book, "fixtures/programs/defi/order_book.oti");
typecheck_fixture!(typecheck_yield_farm, "fixtures/programs/defi/yield_farm.oti");
typecheck_fixture!(typecheck_wrapped_token, "fixtures/programs/defi/wrapped_token.oti");
typecheck_fixture!(typecheck_price_oracle, "fixtures/programs/defi/price_oracle.oti");
typecheck_fixture!(typecheck_stable_swap, "fixtures/programs/defi/stable_swap.oti");
typecheck_fixture!(typecheck_fee_distributor, "fixtures/programs/defi/fee_distributor.oti");
typecheck_fixture!(typecheck_liquidity_gauge, "fixtures/programs/defi/liquidity_gauge.oti");
typecheck_fixture!(typecheck_router, "fixtures/programs/defi/router.oti");
typecheck_fixture!(typecheck_token_vesting, "fixtures/programs/defi/token_vesting.oti");

// === NFT ===
typecheck_fixture!(typecheck_basic_nft, "fixtures/programs/nft/basic_nft.oti");
typecheck_fixture!(typecheck_nft_marketplace, "fixtures/programs/nft/nft_marketplace.oti");
typecheck_fixture!(typecheck_nft_auction, "fixtures/programs/nft/nft_auction.oti");
typecheck_fixture!(typecheck_nft_collection, "fixtures/programs/nft/nft_collection.oti");
typecheck_fixture!(typecheck_soulbound_token, "fixtures/programs/nft/soulbound_token.oti");
typecheck_fixture!(typecheck_nft_royalties, "fixtures/programs/nft/nft_royalties.oti");
typecheck_fixture!(typecheck_nft_rental, "fixtures/programs/nft/nft_rental.oti");

// === Governance ===
typecheck_fixture!(typecheck_dao, "fixtures/programs/governance/dao.oti");
typecheck_fixture!(typecheck_governor, "fixtures/programs/governance/governor.oti");
typecheck_fixture!(typecheck_multisig, "fixtures/programs/governance/multisig.oti");
typecheck_fixture!(typecheck_timelock, "fixtures/programs/governance/timelock.oti");
typecheck_fixture!(typecheck_voting_token, "fixtures/programs/governance/voting_token.oti");
typecheck_fixture!(typecheck_treasury, "fixtures/programs/governance/treasury.oti");
typecheck_fixture!(typecheck_reputation, "fixtures/programs/governance/reputation.oti");
typecheck_fixture!(typecheck_quadratic_voting, "fixtures/programs/governance/quadratic_voting.oti");

// === Games ===
typecheck_fixture!(typecheck_lottery, "fixtures/programs/games/lottery.oti");
typecheck_fixture!(typecheck_prediction_market, "fixtures/programs/games/prediction_market.oti");
typecheck_fixture!(typecheck_rock_paper_scissors, "fixtures/programs/games/rock_paper_scissors.oti");
typecheck_fixture!(typecheck_coin_flip, "fixtures/programs/games/coin_flip.oti");
typecheck_fixture!(typecheck_chess_wager, "fixtures/programs/games/chess_wager.oti");
typecheck_fixture!(typecheck_nft_battle, "fixtures/programs/games/nft_battle.oti");
typecheck_fixture!(typecheck_raffle, "fixtures/programs/games/raffle.oti");

// === Finance ===
typecheck_fixture!(typecheck_escrow, "fixtures/programs/finance/escrow.oti");
typecheck_fixture!(typecheck_payment_splitter, "fixtures/programs/finance/payment_splitter.oti");
typecheck_fixture!(typecheck_subscription, "fixtures/programs/finance/subscription.oti");
typecheck_fixture!(typecheck_invoice, "fixtures/programs/finance/invoice.oti");
typecheck_fixture!(typecheck_payroll, "fixtures/programs/finance/payroll.oti");
typecheck_fixture!(typecheck_crowdfund, "fixtures/programs/finance/crowdfund.oti");
typecheck_fixture!(typecheck_insurance, "fixtures/programs/finance/insurance.oti");
typecheck_fixture!(typecheck_bond, "fixtures/programs/finance/bond.oti");

// === Access Control ===
typecheck_fixture!(typecheck_ownable, "fixtures/programs/access/ownable.oti");
typecheck_fixture!(typecheck_role_manager, "fixtures/programs/access/role_manager.oti");
typecheck_fixture!(typecheck_two_step_ownership, "fixtures/programs/access/two_step_ownership.oti");
typecheck_fixture!(typecheck_allowlist, "fixtures/programs/access/allowlist.oti");
typecheck_fixture!(typecheck_time_lock_admin, "fixtures/programs/access/time_lock_admin.oti");
typecheck_fixture!(typecheck_guardian, "fixtures/programs/access/guardian.oti");
typecheck_fixture!(typecheck_fee_manager, "fixtures/programs/access/fee_manager.oti");

// === Infrastructure ===
typecheck_fixture!(typecheck_name_registry, "fixtures/programs/infra/name_registry.oti");
typecheck_fixture!(typecheck_proxy, "fixtures/programs/infra/proxy.oti");
typecheck_fixture!(typecheck_factory, "fixtures/programs/infra/factory.oti");
typecheck_fixture!(typecheck_access_control, "fixtures/programs/infra/access_control.oti");
typecheck_fixture!(typecheck_event_logger, "fixtures/programs/infra/event_logger.oti");
typecheck_fixture!(typecheck_rate_limiter, "fixtures/programs/infra/rate_limiter.oti");
typecheck_fixture!(typecheck_circuit_breaker, "fixtures/programs/infra/circuit_breaker.oti");
typecheck_fixture!(typecheck_whitelist, "fixtures/programs/infra/whitelist.oti");

// === Library ===
typecheck_fixture!(typecheck_math_lib, "fixtures/programs/library/math_lib.oti");
typecheck_fixture!(typecheck_string_utils, "fixtures/programs/library/string_utils.oti");
typecheck_fixture!(typecheck_array_utils, "fixtures/programs/library/array_utils.oti");
typecheck_fixture!(typecheck_address_utils, "fixtures/programs/library/address_utils.oti");
typecheck_fixture!(typecheck_bitmap, "fixtures/programs/library/bitmap.oti");

// === Patterns ===
typecheck_fixture!(typecheck_token_with_resource, "fixtures/programs/patterns/token_with_resource.oti");
typecheck_fixture!(typecheck_multi_contract, "fixtures/programs/patterns/multi_contract.oti");
typecheck_fixture!(typecheck_state_machine, "fixtures/programs/patterns/state_machine.oti");
typecheck_fixture!(typecheck_batch_operations, "fixtures/programs/patterns/batch_operations.oti");
typecheck_fixture!(typecheck_diamond_storage, "fixtures/programs/patterns/diamond_storage.oti");
typecheck_fixture!(typecheck_complex_structs, "fixtures/programs/patterns/complex_structs.oti");
typecheck_fixture!(typecheck_sponsored_functions, "fixtures/programs/patterns/sponsored_functions.oti");
typecheck_fixture!(typecheck_bytes_and_crypto, "fixtures/programs/patterns/bytes_and_crypto.oti");
typecheck_fixture!(typecheck_nested_types, "fixtures/programs/patterns/nested_types.oti");

// === Social ===
typecheck_fixture!(typecheck_social_media, "fixtures/programs/social/social_media.oti");
typecheck_fixture!(typecheck_messaging, "fixtures/programs/social/messaging.oti");
typecheck_fixture!(typecheck_tipping, "fixtures/programs/social/tipping.oti");
typecheck_fixture!(typecheck_content_platform, "fixtures/programs/social/content_platform.oti");
typecheck_fixture!(typecheck_follow_system, "fixtures/programs/social/follow_system.oti");

// === Supply Chain ===
typecheck_fixture!(typecheck_tracking, "fixtures/programs/supply/tracking.oti");
typecheck_fixture!(typecheck_certification, "fixtures/programs/supply/certification.oti");
typecheck_fixture!(typecheck_inventory, "fixtures/programs/supply/inventory.oti");
typecheck_fixture!(typecheck_shipping, "fixtures/programs/supply/shipping.oti");
typecheck_fixture!(typecheck_provenance, "fixtures/programs/supply/provenance.oti");

// === Real Estate ===
typecheck_fixture!(typecheck_property_deed, "fixtures/programs/realestate/property_deed.oti");
typecheck_fixture!(typecheck_rental_agreement, "fixtures/programs/realestate/rental_agreement.oti");
typecheck_fixture!(typecheck_fractional_ownership, "fixtures/programs/realestate/fractional_ownership.oti");

// === Health ===
typecheck_fixture!(typecheck_medical_records, "fixtures/programs/health/medical_records.oti");
typecheck_fixture!(typecheck_prescription, "fixtures/programs/health/prescription.oti");
typecheck_fixture!(typecheck_clinical_trial, "fixtures/programs/health/clinical_trial.oti");

// === Education ===
typecheck_fixture!(typecheck_credential, "fixtures/programs/education/credential.oti");
typecheck_fixture!(typecheck_course_marketplace, "fixtures/programs/education/course_marketplace.oti");
typecheck_fixture!(typecheck_scholarship, "fixtures/programs/education/scholarship.oti");

// === Legal ===
typecheck_fixture!(typecheck_will, "fixtures/programs/legal/will.oti");
typecheck_fixture!(typecheck_dispute_resolution, "fixtures/programs/legal/dispute_resolution.oti");
typecheck_fixture!(typecheck_smart_agreement, "fixtures/programs/legal/smart_agreement.oti");

// === Energy ===
typecheck_fixture!(typecheck_carbon_credits, "fixtures/programs/energy/carbon_credits.oti");
typecheck_fixture!(typecheck_energy_trading, "fixtures/programs/energy/energy_trading.oti");
typecheck_fixture!(typecheck_renewable_certificates, "fixtures/programs/energy/renewable_certificates.oti");
