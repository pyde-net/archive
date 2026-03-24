//! Integration tests for the safety checker using .oti fixture files.

use otic::lexer::Lexer;
use otic::parser::Parser;
use otic::safety::SafetyChecker;

fn safety_check_file(src: &str) -> Vec<otic::safety::SafetyError> {
    let (tokens, lex_errors) = Lexer::new(src).tokenize();
    assert!(lex_errors.is_empty(), "lex errors: {:?}", lex_errors);
    let (file, parse_errors) = Parser::new(tokens).parse();
    assert!(parse_errors.is_empty(), "parse errors: {:?}", parse_errors);
    SafetyChecker::new().check(&file).errors
}

macro_rules! safety_fixture {
    ($name:ident, $path:expr) => {
        #[test]
        fn $name() {
            let src = include_str!($path);
            let errors = safety_check_file(src);
            if !errors.is_empty() {
                for e in &errors {
                    eprintln!("  {}", e);
                }
                panic!("{} had {} safety errors", stringify!($name), errors.len());
            }
        }
    };
}

// === ERC20 ===
safety_fixture!(safety_erc20, "fixtures/erc20.oti");

// === DeFi ===
safety_fixture!(safety_erc20_advanced, "fixtures/programs/defi/erc20_advanced.oti");
safety_fixture!(safety_amm_pool, "fixtures/programs/defi/amm_pool.oti");
safety_fixture!(safety_lending_pool, "fixtures/programs/defi/lending_pool.oti");
safety_fixture!(safety_staking, "fixtures/programs/defi/staking.oti");
safety_fixture!(safety_vault, "fixtures/programs/defi/vault.oti");
safety_fixture!(safety_flash_loan, "fixtures/programs/defi/flash_loan.oti");
safety_fixture!(safety_order_book, "fixtures/programs/defi/order_book.oti");
safety_fixture!(safety_yield_farm, "fixtures/programs/defi/yield_farm.oti");
safety_fixture!(safety_wrapped_token, "fixtures/programs/defi/wrapped_token.oti");
safety_fixture!(safety_price_oracle, "fixtures/programs/defi/price_oracle.oti");
safety_fixture!(safety_stable_swap, "fixtures/programs/defi/stable_swap.oti");
safety_fixture!(safety_fee_distributor, "fixtures/programs/defi/fee_distributor.oti");
safety_fixture!(safety_liquidity_gauge, "fixtures/programs/defi/liquidity_gauge.oti");
safety_fixture!(safety_router, "fixtures/programs/defi/router.oti");
safety_fixture!(safety_token_vesting, "fixtures/programs/defi/token_vesting.oti");

// === NFT ===
safety_fixture!(safety_basic_nft, "fixtures/programs/nft/basic_nft.oti");
safety_fixture!(safety_nft_marketplace, "fixtures/programs/nft/nft_marketplace.oti");
safety_fixture!(safety_nft_auction, "fixtures/programs/nft/nft_auction.oti");
safety_fixture!(safety_nft_collection, "fixtures/programs/nft/nft_collection.oti");
safety_fixture!(safety_soulbound_token, "fixtures/programs/nft/soulbound_token.oti");
safety_fixture!(safety_nft_royalties, "fixtures/programs/nft/nft_royalties.oti");
safety_fixture!(safety_nft_rental, "fixtures/programs/nft/nft_rental.oti");

// === Governance ===
safety_fixture!(safety_dao, "fixtures/programs/governance/dao.oti");
safety_fixture!(safety_governor, "fixtures/programs/governance/governor.oti");
safety_fixture!(safety_multisig, "fixtures/programs/governance/multisig.oti");
safety_fixture!(safety_timelock, "fixtures/programs/governance/timelock.oti");
safety_fixture!(safety_voting_token, "fixtures/programs/governance/voting_token.oti");
safety_fixture!(safety_treasury, "fixtures/programs/governance/treasury.oti");
safety_fixture!(safety_reputation, "fixtures/programs/governance/reputation.oti");
safety_fixture!(safety_quadratic_voting, "fixtures/programs/governance/quadratic_voting.oti");

// === Games ===
safety_fixture!(safety_lottery, "fixtures/programs/games/lottery.oti");
safety_fixture!(safety_prediction_market, "fixtures/programs/games/prediction_market.oti");
safety_fixture!(safety_rock_paper_scissors, "fixtures/programs/games/rock_paper_scissors.oti");
safety_fixture!(safety_coin_flip, "fixtures/programs/games/coin_flip.oti");
safety_fixture!(safety_chess_wager, "fixtures/programs/games/chess_wager.oti");
safety_fixture!(safety_nft_battle, "fixtures/programs/games/nft_battle.oti");
safety_fixture!(safety_raffle, "fixtures/programs/games/raffle.oti");

// === Finance ===
safety_fixture!(safety_escrow, "fixtures/programs/finance/escrow.oti");
safety_fixture!(safety_payment_splitter, "fixtures/programs/finance/payment_splitter.oti");
safety_fixture!(safety_subscription, "fixtures/programs/finance/subscription.oti");
safety_fixture!(safety_invoice, "fixtures/programs/finance/invoice.oti");
safety_fixture!(safety_payroll, "fixtures/programs/finance/payroll.oti");
safety_fixture!(safety_crowdfund, "fixtures/programs/finance/crowdfund.oti");
safety_fixture!(safety_insurance, "fixtures/programs/finance/insurance.oti");
safety_fixture!(safety_bond, "fixtures/programs/finance/bond.oti");

// === Access ===
safety_fixture!(safety_ownable, "fixtures/programs/access/ownable.oti");
safety_fixture!(safety_role_manager, "fixtures/programs/access/role_manager.oti");
safety_fixture!(safety_two_step_ownership, "fixtures/programs/access/two_step_ownership.oti");
safety_fixture!(safety_allowlist, "fixtures/programs/access/allowlist.oti");
safety_fixture!(safety_time_lock_admin, "fixtures/programs/access/time_lock_admin.oti");
safety_fixture!(safety_guardian, "fixtures/programs/access/guardian.oti");
safety_fixture!(safety_fee_manager, "fixtures/programs/access/fee_manager.oti");

// === Infra ===
safety_fixture!(safety_name_registry, "fixtures/programs/infra/name_registry.oti");
safety_fixture!(safety_proxy, "fixtures/programs/infra/proxy.oti");
safety_fixture!(safety_factory, "fixtures/programs/infra/factory.oti");
safety_fixture!(safety_access_control, "fixtures/programs/infra/access_control.oti");
safety_fixture!(safety_event_logger, "fixtures/programs/infra/event_logger.oti");
safety_fixture!(safety_rate_limiter, "fixtures/programs/infra/rate_limiter.oti");
safety_fixture!(safety_circuit_breaker, "fixtures/programs/infra/circuit_breaker.oti");
safety_fixture!(safety_whitelist, "fixtures/programs/infra/whitelist.oti");

// === Library ===
safety_fixture!(safety_math_lib, "fixtures/programs/library/math_lib.oti");
safety_fixture!(safety_string_utils, "fixtures/programs/library/string_utils.oti");
safety_fixture!(safety_array_utils, "fixtures/programs/library/array_utils.oti");
safety_fixture!(safety_address_utils, "fixtures/programs/library/address_utils.oti");
safety_fixture!(safety_bitmap, "fixtures/programs/library/bitmap.oti");

// === Patterns ===
safety_fixture!(safety_token_with_resource, "fixtures/programs/patterns/token_with_resource.oti");
safety_fixture!(safety_multi_contract, "fixtures/programs/patterns/multi_contract.oti");
safety_fixture!(safety_state_machine, "fixtures/programs/patterns/state_machine.oti");
safety_fixture!(safety_batch_operations, "fixtures/programs/patterns/batch_operations.oti");
safety_fixture!(safety_diamond_storage, "fixtures/programs/patterns/diamond_storage.oti");
safety_fixture!(safety_complex_structs, "fixtures/programs/patterns/complex_structs.oti");
safety_fixture!(safety_sponsored_functions, "fixtures/programs/patterns/sponsored_functions.oti");
safety_fixture!(safety_bytes_and_crypto, "fixtures/programs/patterns/bytes_and_crypto.oti");
safety_fixture!(safety_nested_types, "fixtures/programs/patterns/nested_types.oti");

// === Social ===
safety_fixture!(safety_social_media, "fixtures/programs/social/social_media.oti");
safety_fixture!(safety_messaging, "fixtures/programs/social/messaging.oti");
safety_fixture!(safety_tipping, "fixtures/programs/social/tipping.oti");
safety_fixture!(safety_content_platform, "fixtures/programs/social/content_platform.oti");
safety_fixture!(safety_follow_system, "fixtures/programs/social/follow_system.oti");

// === Supply ===
safety_fixture!(safety_tracking, "fixtures/programs/supply/tracking.oti");
safety_fixture!(safety_certification, "fixtures/programs/supply/certification.oti");
safety_fixture!(safety_inventory, "fixtures/programs/supply/inventory.oti");
safety_fixture!(safety_shipping, "fixtures/programs/supply/shipping.oti");
safety_fixture!(safety_provenance, "fixtures/programs/supply/provenance.oti");

// === Real Estate ===
safety_fixture!(safety_property_deed, "fixtures/programs/realestate/property_deed.oti");
safety_fixture!(safety_rental_agreement, "fixtures/programs/realestate/rental_agreement.oti");
safety_fixture!(safety_fractional_ownership, "fixtures/programs/realestate/fractional_ownership.oti");

// === Health ===
safety_fixture!(safety_medical_records, "fixtures/programs/health/medical_records.oti");
safety_fixture!(safety_prescription, "fixtures/programs/health/prescription.oti");
safety_fixture!(safety_clinical_trial, "fixtures/programs/health/clinical_trial.oti");

// === Education ===
safety_fixture!(safety_credential, "fixtures/programs/education/credential.oti");
safety_fixture!(safety_course_marketplace, "fixtures/programs/education/course_marketplace.oti");
safety_fixture!(safety_scholarship, "fixtures/programs/education/scholarship.oti");

// === Legal ===
safety_fixture!(safety_will, "fixtures/programs/legal/will.oti");
safety_fixture!(safety_dispute_resolution, "fixtures/programs/legal/dispute_resolution.oti");
safety_fixture!(safety_smart_agreement, "fixtures/programs/legal/smart_agreement.oti");

// === Energy ===
safety_fixture!(safety_carbon_credits, "fixtures/programs/energy/carbon_credits.oti");
safety_fixture!(safety_energy_trading, "fixtures/programs/energy/energy_trading.oti");
safety_fixture!(safety_renewable_certificates, "fixtures/programs/energy/renewable_certificates.oti");
