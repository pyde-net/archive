//! Integration tests for IR lowering using .oti fixture files.

use otic::lexer::Lexer;
use otic::lower;
use otic::parser::Parser;

fn lower_file(src: &str) -> otic::ir::IrProgram {
    let (tokens, lex_errors) = Lexer::new(src).tokenize();
    assert!(lex_errors.is_empty(), "lex errors: {:?}", lex_errors);
    let (file, parse_errors) = Parser::new(tokens).parse();
    assert!(parse_errors.is_empty(), "parse errors: {:?}", parse_errors);
    let ir = lower::lower(&file);
    // Verify we got at least one function and the IR is valid
    assert!(!ir.functions.is_empty(), "no functions in IR");
    // Verify Display doesn't panic
    let _ = format!("{}", ir);
    ir
}

macro_rules! lower_fixture {
    ($name:ident, $path:expr) => {
        #[test]
        fn $name() {
            let src = include_str!($path);
            lower_file(src);
        }
    };
}

lower_fixture!(lower_erc20, "fixtures/erc20.oti");

// DeFi
lower_fixture!(
    lower_erc20_advanced,
    "fixtures/programs/defi/erc20_advanced.oti"
);
lower_fixture!(lower_amm_pool, "fixtures/programs/defi/amm_pool.oti");
lower_fixture!(
    lower_lending_pool,
    "fixtures/programs/defi/lending_pool.oti"
);
lower_fixture!(lower_staking, "fixtures/programs/defi/staking.oti");
lower_fixture!(lower_vault, "fixtures/programs/defi/vault.oti");
lower_fixture!(lower_flash_loan, "fixtures/programs/defi/flash_loan.oti");
lower_fixture!(lower_order_book, "fixtures/programs/defi/order_book.oti");
lower_fixture!(lower_yield_farm, "fixtures/programs/defi/yield_farm.oti");
lower_fixture!(
    lower_wrapped_token,
    "fixtures/programs/defi/wrapped_token.oti"
);
lower_fixture!(
    lower_price_oracle,
    "fixtures/programs/defi/price_oracle.oti"
);
lower_fixture!(lower_stable_swap, "fixtures/programs/defi/stable_swap.oti");
lower_fixture!(
    lower_fee_distributor,
    "fixtures/programs/defi/fee_distributor.oti"
);
lower_fixture!(
    lower_liquidity_gauge,
    "fixtures/programs/defi/liquidity_gauge.oti"
);
lower_fixture!(lower_router, "fixtures/programs/defi/router.oti");
lower_fixture!(
    lower_token_vesting,
    "fixtures/programs/defi/token_vesting.oti"
);

// NFT
lower_fixture!(lower_basic_nft, "fixtures/programs/nft/basic_nft.oti");
lower_fixture!(
    lower_nft_marketplace,
    "fixtures/programs/nft/nft_marketplace.oti"
);
lower_fixture!(lower_nft_auction, "fixtures/programs/nft/nft_auction.oti");
lower_fixture!(
    lower_nft_collection,
    "fixtures/programs/nft/nft_collection.oti"
);
lower_fixture!(
    lower_soulbound_token,
    "fixtures/programs/nft/soulbound_token.oti"
);
lower_fixture!(
    lower_nft_royalties,
    "fixtures/programs/nft/nft_royalties.oti"
);
lower_fixture!(lower_nft_rental, "fixtures/programs/nft/nft_rental.oti");

// Governance
lower_fixture!(lower_dao, "fixtures/programs/governance/dao.oti");
lower_fixture!(lower_governor, "fixtures/programs/governance/governor.oti");
lower_fixture!(lower_multisig, "fixtures/programs/governance/multisig.oti");
lower_fixture!(lower_timelock, "fixtures/programs/governance/timelock.oti");
lower_fixture!(
    lower_voting_token,
    "fixtures/programs/governance/voting_token.oti"
);
lower_fixture!(lower_treasury, "fixtures/programs/governance/treasury.oti");
lower_fixture!(
    lower_reputation,
    "fixtures/programs/governance/reputation.oti"
);
lower_fixture!(
    lower_quadratic_voting,
    "fixtures/programs/governance/quadratic_voting.oti"
);

// Games
lower_fixture!(lower_lottery, "fixtures/programs/games/lottery.oti");
lower_fixture!(
    lower_prediction_market,
    "fixtures/programs/games/prediction_market.oti"
);
lower_fixture!(
    lower_rock_paper_scissors,
    "fixtures/programs/games/rock_paper_scissors.oti"
);
lower_fixture!(lower_coin_flip, "fixtures/programs/games/coin_flip.oti");
lower_fixture!(lower_chess_wager, "fixtures/programs/games/chess_wager.oti");
lower_fixture!(lower_nft_battle, "fixtures/programs/games/nft_battle.oti");
lower_fixture!(lower_raffle, "fixtures/programs/games/raffle.oti");

// Finance
lower_fixture!(lower_escrow, "fixtures/programs/finance/escrow.oti");
lower_fixture!(
    lower_payment_splitter,
    "fixtures/programs/finance/payment_splitter.oti"
);
lower_fixture!(
    lower_subscription,
    "fixtures/programs/finance/subscription.oti"
);
lower_fixture!(lower_invoice, "fixtures/programs/finance/invoice.oti");
lower_fixture!(lower_payroll, "fixtures/programs/finance/payroll.oti");
lower_fixture!(lower_crowdfund, "fixtures/programs/finance/crowdfund.oti");
lower_fixture!(lower_insurance, "fixtures/programs/finance/insurance.oti");
lower_fixture!(lower_bond, "fixtures/programs/finance/bond.oti");

// Access
lower_fixture!(lower_ownable, "fixtures/programs/access/ownable.oti");
lower_fixture!(
    lower_role_manager,
    "fixtures/programs/access/role_manager.oti"
);
lower_fixture!(
    lower_two_step_ownership,
    "fixtures/programs/access/two_step_ownership.oti"
);
lower_fixture!(lower_allowlist, "fixtures/programs/access/allowlist.oti");
lower_fixture!(
    lower_time_lock_admin,
    "fixtures/programs/access/time_lock_admin.oti"
);
lower_fixture!(lower_guardian, "fixtures/programs/access/guardian.oti");
lower_fixture!(
    lower_fee_manager,
    "fixtures/programs/access/fee_manager.oti"
);

// Infra
lower_fixture!(
    lower_name_registry,
    "fixtures/programs/infra/name_registry.oti"
);
lower_fixture!(lower_proxy, "fixtures/programs/infra/proxy.oti");
lower_fixture!(lower_factory, "fixtures/programs/infra/factory.oti");
lower_fixture!(
    lower_access_control,
    "fixtures/programs/infra/access_control.oti"
);
lower_fixture!(
    lower_event_logger,
    "fixtures/programs/infra/event_logger.oti"
);
lower_fixture!(
    lower_rate_limiter,
    "fixtures/programs/infra/rate_limiter.oti"
);
lower_fixture!(
    lower_circuit_breaker,
    "fixtures/programs/infra/circuit_breaker.oti"
);
lower_fixture!(lower_whitelist, "fixtures/programs/infra/whitelist.oti");

// Library
lower_fixture!(lower_math_lib, "fixtures/programs/library/math_lib.oti");
lower_fixture!(
    lower_string_utils,
    "fixtures/programs/library/string_utils.oti"
);
lower_fixture!(
    lower_array_utils,
    "fixtures/programs/library/array_utils.oti"
);
lower_fixture!(
    lower_address_utils,
    "fixtures/programs/library/address_utils.oti"
);
lower_fixture!(lower_bitmap, "fixtures/programs/library/bitmap.oti");

// Patterns
lower_fixture!(
    lower_token_with_resource,
    "fixtures/programs/patterns/token_with_resource.oti"
);
lower_fixture!(
    lower_simple_factory,
    "fixtures/programs/patterns/simple_factory.oti"
);
lower_fixture!(
    lower_multi_contract,
    "fixtures/programs/patterns/multi_contract.oti"
);
lower_fixture!(
    lower_state_machine,
    "fixtures/programs/patterns/state_machine.oti"
);
lower_fixture!(
    lower_batch_operations,
    "fixtures/programs/patterns/batch_operations.oti"
);
lower_fixture!(
    lower_diamond_storage,
    "fixtures/programs/patterns/diamond_storage.oti"
);
lower_fixture!(
    lower_complex_structs,
    "fixtures/programs/patterns/complex_structs.oti"
);
lower_fixture!(
    lower_sponsored_functions,
    "fixtures/programs/patterns/sponsored_functions.oti"
);
lower_fixture!(
    lower_bytes_and_crypto,
    "fixtures/programs/patterns/bytes_and_crypto.oti"
);
lower_fixture!(
    lower_nested_types,
    "fixtures/programs/patterns/nested_types.oti"
);

// Social
lower_fixture!(
    lower_social_media,
    "fixtures/programs/social/social_media.oti"
);
lower_fixture!(lower_messaging, "fixtures/programs/social/messaging.oti");
lower_fixture!(lower_tipping, "fixtures/programs/social/tipping.oti");
lower_fixture!(
    lower_content_platform,
    "fixtures/programs/social/content_platform.oti"
);
lower_fixture!(
    lower_follow_system,
    "fixtures/programs/social/follow_system.oti"
);

// Supply
lower_fixture!(lower_tracking, "fixtures/programs/supply/tracking.oti");
lower_fixture!(
    lower_certification,
    "fixtures/programs/supply/certification.oti"
);
lower_fixture!(lower_inventory, "fixtures/programs/supply/inventory.oti");
lower_fixture!(lower_shipping, "fixtures/programs/supply/shipping.oti");
lower_fixture!(lower_provenance, "fixtures/programs/supply/provenance.oti");

// Real Estate
lower_fixture!(
    lower_property_deed,
    "fixtures/programs/realestate/property_deed.oti"
);
lower_fixture!(
    lower_rental_agreement,
    "fixtures/programs/realestate/rental_agreement.oti"
);
lower_fixture!(
    lower_fractional_ownership,
    "fixtures/programs/realestate/fractional_ownership.oti"
);

// Health
lower_fixture!(
    lower_medical_records,
    "fixtures/programs/health/medical_records.oti"
);
lower_fixture!(
    lower_prescription,
    "fixtures/programs/health/prescription.oti"
);
lower_fixture!(
    lower_clinical_trial,
    "fixtures/programs/health/clinical_trial.oti"
);

// Education
lower_fixture!(
    lower_credential,
    "fixtures/programs/education/credential.oti"
);
lower_fixture!(
    lower_course_marketplace,
    "fixtures/programs/education/course_marketplace.oti"
);
lower_fixture!(
    lower_scholarship,
    "fixtures/programs/education/scholarship.oti"
);

// Legal
lower_fixture!(lower_will, "fixtures/programs/legal/will.oti");
lower_fixture!(
    lower_dispute_resolution,
    "fixtures/programs/legal/dispute_resolution.oti"
);
lower_fixture!(
    lower_smart_agreement,
    "fixtures/programs/legal/smart_agreement.oti"
);

// Energy
lower_fixture!(
    lower_carbon_credits,
    "fixtures/programs/energy/carbon_credits.oti"
);
lower_fixture!(
    lower_energy_trading,
    "fixtures/programs/energy/energy_trading.oti"
);
lower_fixture!(
    lower_renewable_certificates,
    "fixtures/programs/energy/renewable_certificates.oti"
);
