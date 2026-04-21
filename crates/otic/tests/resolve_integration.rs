//! Integration tests for the name resolver using .oti fixture files.

use otic::lexer::Lexer;
use otic::parser::Parser;
use otic::resolve::Resolver;

fn resolve_file(src: &str) -> Vec<otic::resolve::ResolveError> {
    let (tokens, lex_errors) = Lexer::new(src).tokenize();
    assert!(lex_errors.is_empty(), "lex errors: {:?}", lex_errors);
    let (file, parse_errors) = Parser::new(tokens).parse();
    assert!(parse_errors.is_empty(), "parse errors: {:?}", parse_errors);
    Resolver::new().resolve(&file).errors
}

macro_rules! resolve_fixture {
    ($name:ident, $path:expr) => {
        #[test]
        fn $name() {
            let src = include_str!($path);
            let errors = resolve_file(src);
            if !errors.is_empty() {
                for e in &errors {
                    eprintln!("  {}", e);
                }
                panic!("{} had {} resolve errors", stringify!($name), errors.len());
            }
        }
    };
}

// === ERC20 ===
resolve_fixture!(resolve_erc20, "fixtures/erc20.oti");

// === DeFi ===
resolve_fixture!(
    resolve_erc20_advanced,
    "fixtures/programs/defi/erc20_advanced.oti"
);
resolve_fixture!(resolve_amm_pool, "fixtures/programs/defi/amm_pool.oti");
resolve_fixture!(
    resolve_lending_pool,
    "fixtures/programs/defi/lending_pool.oti"
);
resolve_fixture!(resolve_staking, "fixtures/programs/defi/staking.oti");
resolve_fixture!(resolve_vault, "fixtures/programs/defi/vault.oti");
resolve_fixture!(resolve_flash_loan, "fixtures/programs/defi/flash_loan.oti");
resolve_fixture!(resolve_order_book, "fixtures/programs/defi/order_book.oti");
resolve_fixture!(resolve_yield_farm, "fixtures/programs/defi/yield_farm.oti");
resolve_fixture!(
    resolve_wrapped_token,
    "fixtures/programs/defi/wrapped_token.oti"
);
resolve_fixture!(
    resolve_price_oracle,
    "fixtures/programs/defi/price_oracle.oti"
);
resolve_fixture!(
    resolve_stable_swap,
    "fixtures/programs/defi/stable_swap.oti"
);
resolve_fixture!(
    resolve_fee_distributor,
    "fixtures/programs/defi/fee_distributor.oti"
);
resolve_fixture!(
    resolve_liquidity_gauge,
    "fixtures/programs/defi/liquidity_gauge.oti"
);
resolve_fixture!(resolve_router, "fixtures/programs/defi/router.oti");
resolve_fixture!(
    resolve_token_vesting,
    "fixtures/programs/defi/token_vesting.oti"
);

// === NFT ===
resolve_fixture!(resolve_basic_nft, "fixtures/programs/nft/basic_nft.oti");
resolve_fixture!(
    resolve_nft_marketplace,
    "fixtures/programs/nft/nft_marketplace.oti"
);
resolve_fixture!(resolve_nft_auction, "fixtures/programs/nft/nft_auction.oti");
resolve_fixture!(
    resolve_nft_collection,
    "fixtures/programs/nft/nft_collection.oti"
);
resolve_fixture!(
    resolve_soulbound_token,
    "fixtures/programs/nft/soulbound_token.oti"
);
resolve_fixture!(
    resolve_nft_royalties,
    "fixtures/programs/nft/nft_royalties.oti"
);
resolve_fixture!(resolve_nft_rental, "fixtures/programs/nft/nft_rental.oti");

// === Governance ===
resolve_fixture!(resolve_dao, "fixtures/programs/governance/dao.oti");
resolve_fixture!(
    resolve_governor,
    "fixtures/programs/governance/governor.oti"
);
resolve_fixture!(
    resolve_multisig,
    "fixtures/programs/governance/multisig.oti"
);
resolve_fixture!(
    resolve_timelock,
    "fixtures/programs/governance/timelock.oti"
);
resolve_fixture!(
    resolve_voting_token,
    "fixtures/programs/governance/voting_token.oti"
);
resolve_fixture!(
    resolve_treasury,
    "fixtures/programs/governance/treasury.oti"
);
resolve_fixture!(
    resolve_reputation,
    "fixtures/programs/governance/reputation.oti"
);
resolve_fixture!(
    resolve_quadratic_voting,
    "fixtures/programs/governance/quadratic_voting.oti"
);

// === Games ===
resolve_fixture!(resolve_lottery, "fixtures/programs/games/lottery.oti");
resolve_fixture!(
    resolve_prediction_market,
    "fixtures/programs/games/prediction_market.oti"
);
resolve_fixture!(
    resolve_rock_paper_scissors,
    "fixtures/programs/games/rock_paper_scissors.oti"
);
resolve_fixture!(resolve_coin_flip, "fixtures/programs/games/coin_flip.oti");
resolve_fixture!(
    resolve_chess_wager,
    "fixtures/programs/games/chess_wager.oti"
);
resolve_fixture!(resolve_nft_battle, "fixtures/programs/games/nft_battle.oti");
resolve_fixture!(resolve_raffle, "fixtures/programs/games/raffle.oti");

// === Finance ===
resolve_fixture!(resolve_escrow, "fixtures/programs/finance/escrow.oti");
resolve_fixture!(
    resolve_payment_splitter,
    "fixtures/programs/finance/payment_splitter.oti"
);
resolve_fixture!(
    resolve_subscription,
    "fixtures/programs/finance/subscription.oti"
);
resolve_fixture!(resolve_invoice, "fixtures/programs/finance/invoice.oti");
resolve_fixture!(resolve_payroll, "fixtures/programs/finance/payroll.oti");
resolve_fixture!(resolve_crowdfund, "fixtures/programs/finance/crowdfund.oti");
resolve_fixture!(resolve_insurance, "fixtures/programs/finance/insurance.oti");
resolve_fixture!(resolve_bond, "fixtures/programs/finance/bond.oti");

// === Access Control ===
resolve_fixture!(resolve_ownable, "fixtures/programs/access/ownable.oti");
resolve_fixture!(
    resolve_role_manager,
    "fixtures/programs/access/role_manager.oti"
);
resolve_fixture!(
    resolve_two_step_ownership,
    "fixtures/programs/access/two_step_ownership.oti"
);
resolve_fixture!(resolve_allowlist, "fixtures/programs/access/allowlist.oti");
resolve_fixture!(
    resolve_time_lock_admin,
    "fixtures/programs/access/time_lock_admin.oti"
);
resolve_fixture!(resolve_guardian, "fixtures/programs/access/guardian.oti");
resolve_fixture!(
    resolve_fee_manager,
    "fixtures/programs/access/fee_manager.oti"
);

// === Infrastructure ===
resolve_fixture!(
    resolve_name_registry,
    "fixtures/programs/infra/name_registry.oti"
);
resolve_fixture!(resolve_proxy, "fixtures/programs/infra/proxy.oti");
resolve_fixture!(resolve_factory, "fixtures/programs/infra/factory.oti");
resolve_fixture!(
    resolve_access_control,
    "fixtures/programs/infra/access_control.oti"
);
resolve_fixture!(
    resolve_event_logger,
    "fixtures/programs/infra/event_logger.oti"
);
resolve_fixture!(
    resolve_rate_limiter,
    "fixtures/programs/infra/rate_limiter.oti"
);
resolve_fixture!(
    resolve_circuit_breaker,
    "fixtures/programs/infra/circuit_breaker.oti"
);
resolve_fixture!(resolve_whitelist, "fixtures/programs/infra/whitelist.oti");

// === Library ===
resolve_fixture!(resolve_math_lib, "fixtures/programs/library/math_lib.oti");
resolve_fixture!(
    resolve_string_utils,
    "fixtures/programs/library/string_utils.oti"
);
resolve_fixture!(
    resolve_array_utils,
    "fixtures/programs/library/array_utils.oti"
);
resolve_fixture!(
    resolve_address_utils,
    "fixtures/programs/library/address_utils.oti"
);
resolve_fixture!(resolve_bitmap, "fixtures/programs/library/bitmap.oti");

// === Patterns ===
resolve_fixture!(
    resolve_token_with_resource,
    "fixtures/programs/patterns/token_with_resource.oti"
);
resolve_fixture!(
    resolve_multi_contract,
    "fixtures/programs/patterns/multi_contract.oti"
);
resolve_fixture!(
    resolve_state_machine,
    "fixtures/programs/patterns/state_machine.oti"
);
resolve_fixture!(
    resolve_batch_operations,
    "fixtures/programs/patterns/batch_operations.oti"
);
resolve_fixture!(
    resolve_diamond_storage,
    "fixtures/programs/patterns/diamond_storage.oti"
);
resolve_fixture!(
    resolve_complex_structs,
    "fixtures/programs/patterns/complex_structs.oti"
);
resolve_fixture!(
    resolve_sponsored_functions,
    "fixtures/programs/patterns/sponsored_functions.oti"
);
resolve_fixture!(
    resolve_bytes_and_crypto,
    "fixtures/programs/patterns/bytes_and_crypto.oti"
);
resolve_fixture!(
    resolve_nested_types,
    "fixtures/programs/patterns/nested_types.oti"
);

// === Social ===
resolve_fixture!(
    resolve_social_media,
    "fixtures/programs/social/social_media.oti"
);
resolve_fixture!(resolve_messaging, "fixtures/programs/social/messaging.oti");
resolve_fixture!(resolve_tipping, "fixtures/programs/social/tipping.oti");
resolve_fixture!(
    resolve_content_platform,
    "fixtures/programs/social/content_platform.oti"
);
resolve_fixture!(
    resolve_follow_system,
    "fixtures/programs/social/follow_system.oti"
);

// === Supply Chain ===
resolve_fixture!(resolve_tracking, "fixtures/programs/supply/tracking.oti");
resolve_fixture!(
    resolve_certification,
    "fixtures/programs/supply/certification.oti"
);
resolve_fixture!(resolve_inventory, "fixtures/programs/supply/inventory.oti");
resolve_fixture!(resolve_shipping, "fixtures/programs/supply/shipping.oti");
resolve_fixture!(
    resolve_provenance,
    "fixtures/programs/supply/provenance.oti"
);

// === Real Estate ===
resolve_fixture!(
    resolve_property_deed,
    "fixtures/programs/realestate/property_deed.oti"
);
resolve_fixture!(
    resolve_rental_agreement,
    "fixtures/programs/realestate/rental_agreement.oti"
);
resolve_fixture!(
    resolve_fractional_ownership,
    "fixtures/programs/realestate/fractional_ownership.oti"
);

// === Health ===
resolve_fixture!(
    resolve_medical_records,
    "fixtures/programs/health/medical_records.oti"
);
resolve_fixture!(
    resolve_prescription,
    "fixtures/programs/health/prescription.oti"
);
resolve_fixture!(
    resolve_clinical_trial,
    "fixtures/programs/health/clinical_trial.oti"
);

// === Education ===
resolve_fixture!(
    resolve_credential,
    "fixtures/programs/education/credential.oti"
);
resolve_fixture!(
    resolve_course_marketplace,
    "fixtures/programs/education/course_marketplace.oti"
);
resolve_fixture!(
    resolve_scholarship,
    "fixtures/programs/education/scholarship.oti"
);

// === Legal ===
resolve_fixture!(resolve_will, "fixtures/programs/legal/will.oti");
resolve_fixture!(
    resolve_dispute_resolution,
    "fixtures/programs/legal/dispute_resolution.oti"
);
resolve_fixture!(
    resolve_smart_agreement,
    "fixtures/programs/legal/smart_agreement.oti"
);

// === Energy ===
resolve_fixture!(
    resolve_carbon_credits,
    "fixtures/programs/energy/carbon_credits.oti"
);
resolve_fixture!(
    resolve_energy_trading,
    "fixtures/programs/energy/energy_trading.oti"
);
resolve_fixture!(
    resolve_renewable_certificates,
    "fixtures/programs/energy/renewable_certificates.oti"
);
