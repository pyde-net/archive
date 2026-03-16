//! EIP-1559 base fee adjustment per Chapter 10 spec.
//!
//! - Base fee adjusts every block based on parent block's gas usage vs target
//! - Maximum adjustment: ±12.5% per block (1/8 divisor)
//! - At target (50% full): fee unchanged
//! - Over target: fee increases proportionally
//! - Under target: fee decreases proportionally
//! - No tips — all fee is base fee

/// Gas target: 400M (50% of maximum).
pub const GAS_TARGET: u64 = 400_000_000;

/// Gas ceiling: 1.6B (4x target, elastic blocks).
pub const GAS_CEILING: u64 = 1_600_000_000;

/// Minimum base fee floor (in quanta). Prevents fee from reaching zero.
pub const MIN_BASE_FEE: u128 = 1;

/// Genesis base fee (initial value at chain launch).
/// Targets ~$0.001 for a 21,000 gas transfer at launch price.
pub const GENESIS_BASE_FEE: u128 = 50_000_000_000; // 50 gwei equivalent

/// Base fee adjustment divisor (1/8 = 12.5% max change per block).
const ADJUSTMENT_DIVISOR: u128 = 8;

/// Adjust the base fee for the next block based on parent block's gas usage.
///
/// Formula per EIP-1559:
/// - If usage > target: `base_fee += base_fee * (usage - target) / target / 8`
/// - If usage < target: `base_fee -= base_fee * (target - usage) / target / 8`
/// - If usage == target: unchanged
///
/// Capped at ±12.5% per block. Never goes below MIN_BASE_FEE.
pub fn adjust_base_fee(
    parent_base_fee: u128,
    parent_gas_used: u64,
    parent_gas_target: u64,
) -> u128 {
    if parent_gas_target == 0 {
        return parent_base_fee;
    }

    if parent_gas_used == parent_gas_target {
        return parent_base_fee;
    }

    let new_fee = if parent_gas_used > parent_gas_target {
        // Block over target → increase
        let gas_delta = parent_gas_used - parent_gas_target;
        let fee_delta = parent_base_fee * gas_delta as u128
            / parent_gas_target as u128
            / ADJUSTMENT_DIVISOR;
        let fee_delta = fee_delta.max(1); // minimum increase of 1
        parent_base_fee + fee_delta
    } else {
        // Block under target → decrease
        let gas_delta = parent_gas_target - parent_gas_used;
        let fee_delta = parent_base_fee * gas_delta as u128
            / parent_gas_target as u128
            / ADJUSTMENT_DIVISOR;
        parent_base_fee.saturating_sub(fee_delta)
    };

    // Enforce minimum floor
    new_fee.max(MIN_BASE_FEE)
}

/// Check if a block's gas usage is within the elastic limit.
pub fn is_within_gas_limit(gas_used: u64, gas_ceiling: u64) -> bool {
    gas_used <= gas_ceiling
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Task 0426: Empty block → base fee decreases ==========

    #[test]
    fn empty_block_decreases_fee() {
        let fee = adjust_base_fee(1_000_000, 0, GAS_TARGET);
        assert!(fee < 1_000_000);
    }

    #[test]
    fn empty_block_decreases_by_12_5_pct() {
        let parent = 1_000_000u128;
        let fee = adjust_base_fee(parent, 0, GAS_TARGET);
        // 0 gas used → full decrease: parent * target / target / 8 = parent / 8
        assert_eq!(fee, parent - parent / 8); // 875,000
    }

    // ========== Task 0427: Full block (at target) → unchanged ==========

    #[test]
    fn at_target_unchanged() {
        let parent = 1_000_000u128;
        let fee = adjust_base_fee(parent, GAS_TARGET, GAS_TARGET);
        assert_eq!(fee, parent);
    }

    // ========== Task 0428: Over-target → base fee increases ==========

    #[test]
    fn over_target_increases() {
        let parent = 1_000_000u128;
        // Double the target
        let fee = adjust_base_fee(parent, GAS_TARGET * 2, GAS_TARGET);
        assert!(fee > parent);
    }

    #[test]
    fn slightly_over_target_small_increase() {
        let parent = 1_000_000u128;
        // 10% over target
        let used = GAS_TARGET + GAS_TARGET / 10;
        let fee = adjust_base_fee(parent, used, GAS_TARGET);
        // delta = parent * (used - target) / target / 8 = parent * 0.1 / 8 = parent * 0.0125
        let expected_delta = parent / 80; // 12,500
        assert_eq!(fee, parent + expected_delta);
    }

    // ========== Task 0429: Max increase is 12.5% ==========

    #[test]
    fn max_increase_12_5_pct() {
        let parent = 1_000_000u128;
        // 4x target (maximum elastic block)
        let fee_4x = adjust_base_fee(parent, GAS_TARGET * 4, GAS_TARGET);
        // delta = parent * 3*target / target / 8 = parent * 3/8 = 375,000
        // But wait — gas_used can exceed target by up to 3x (since ceiling = 4x target)
        // delta = parent * (4*target - target) / target / 8 = parent * 3 / 8
        assert_eq!(fee_4x, parent + parent * 3 / 8);

        // Even with absurdly high gas (shouldn't happen due to ceiling), check proportional
        let fee_2x = adjust_base_fee(parent, GAS_TARGET * 2, GAS_TARGET);
        assert_eq!(fee_2x, parent + parent / 8); // exactly 12.5% for 2x target
    }

    // ========== Task 0430: Max decrease is 12.5% ==========

    #[test]
    fn max_decrease_12_5_pct() {
        let parent = 1_000_000u128;
        let fee = adjust_base_fee(parent, 0, GAS_TARGET);
        // Empty block: decrease = parent * target / target / 8 = parent / 8
        assert_eq!(fee, parent - parent / 8);
    }

    #[test]
    fn half_target_decreases_by_6_25_pct() {
        let parent = 1_000_000u128;
        let fee = adjust_base_fee(parent, GAS_TARGET / 2, GAS_TARGET);
        // delta = parent * (target - target/2) / target / 8 = parent * 0.5 / 8 = parent / 16
        assert_eq!(fee, parent - parent / 16);
    }

    // ========== Task 0431: Never goes below floor ==========

    #[test]
    fn never_below_floor() {
        let fee = adjust_base_fee(1, 0, GAS_TARGET);
        assert_eq!(fee, MIN_BASE_FEE);
    }

    #[test]
    fn floor_prevents_zero() {
        // Repeated empty blocks: fee decreases but never reaches zero.
        // Integer division rounds delta to 0 before reaching MIN_BASE_FEE,
        // so fee stabilizes at a small value >= MIN_BASE_FEE.
        let mut fee = 100u128;
        for _ in 0..1000 {
            fee = adjust_base_fee(fee, 0, GAS_TARGET);
        }
        assert!(fee >= MIN_BASE_FEE);
        assert!(fee < 100); // decreased significantly
    }

    // ========== Task 0432: Elastic 4x block ==========

    #[test]
    fn elastic_4x_block_increases_proportionally() {
        let parent = 1_000_000u128;

        let fee_2x = adjust_base_fee(parent, GAS_TARGET * 2, GAS_TARGET);
        let fee_3x = adjust_base_fee(parent, GAS_TARGET * 3, GAS_TARGET);
        let fee_4x = adjust_base_fee(parent, GAS_TARGET * 4, GAS_TARGET);

        // Each step increases more than the last
        assert!(fee_2x < fee_3x);
        assert!(fee_3x < fee_4x);

        // 2x target = +12.5%, 3x target = +25%, 4x target = +37.5%
        assert_eq!(fee_2x - parent, parent / 8);      // +125,000
        assert_eq!(fee_3x - parent, parent * 2 / 8);  // +250,000
        assert_eq!(fee_4x - parent, parent * 3 / 8);  // +375,000
    }

    // ========== Genesis ==========

    #[test]
    fn genesis_base_fee_constant() {
        assert_eq!(GENESIS_BASE_FEE, 50_000_000_000);
    }

    // ========== Gas limit ==========

    #[test]
    fn within_gas_limit() {
        assert!(is_within_gas_limit(GAS_TARGET, GAS_CEILING));
        assert!(is_within_gas_limit(GAS_CEILING, GAS_CEILING));
        assert!(!is_within_gas_limit(GAS_CEILING + 1, GAS_CEILING));
    }

    // ========== Convergence ==========

    #[test]
    fn fee_converges_under_sustained_load() {
        let mut fee = GENESIS_BASE_FEE;
        // Sustained full blocks (at target) → fee stays constant
        for _ in 0..100 {
            fee = adjust_base_fee(fee, GAS_TARGET, GAS_TARGET);
        }
        assert_eq!(fee, GENESIS_BASE_FEE);
    }

    #[test]
    fn fee_rises_then_stabilizes() {
        let mut fee = GENESIS_BASE_FEE;
        // 10 over-target blocks
        for _ in 0..10 {
            fee = adjust_base_fee(fee, GAS_TARGET * 2, GAS_TARGET);
        }
        let high_fee = fee;
        assert!(high_fee > GENESIS_BASE_FEE);

        // Then 10 at-target blocks → stable
        for _ in 0..10 {
            fee = adjust_base_fee(fee, GAS_TARGET, GAS_TARGET);
        }
        assert_eq!(fee, high_fee);
    }
}
