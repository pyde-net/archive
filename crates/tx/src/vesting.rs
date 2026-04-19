//! Linear-with-cliff vesting for genesis allocations (Phase 4 slice 4.4).
//!
//! Schema-only: the allocation *buckets* (team / investors / treasury /
//! community / validator subsidy / liquidity) are recorded as config
//! metadata only. The protocol enforces one thing — the per-recipient
//! schedule. Send txs from a vested account are rejected if the amount
//! exceeds `balance - locked_remaining(current_slot)`.
//!
//! Shape: slot ranges + total amount.
//! - `start_slot`: when vesting begins (usually 0 = genesis).
//! - `cliff_slots`: slots after start during which nothing unlocks.
//! - `duration_slots`: total vesting duration. After
//!   `start + duration`, the full amount is unlocked.
//! - `total_amount`: initial allocation subject to vesting.
//!
//! Unlock curve:
//! - `slot < start + cliff` → unlocked = 0
//! - `slot >= start + duration` → unlocked = total_amount
//! - in between → linear: `total_amount * (slot - start) / duration`
//!
//! Note the cliff does NOT "catch up" to the linear curve at cliff-end.
//! Standard industry pattern: cliff = 0 unlocks, then at cliff the
//! curve jumps to `total * cliff / duration`, then continues linearly.

/// Vesting schedule attached to a genesis allocation. Stored at
/// `vesting_key(address)` in the state SMT; absent rows imply the
/// account has no vesting and can spend its full balance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VestingSchedule {
    pub start_slot: u64,
    pub cliff_slots: u64,
    pub duration_slots: u64,
    pub total_amount: u128,
}

impl VestingSchedule {
    /// Wire layout:
    ///   [start:8 LE][cliff:8 LE][duration:8 LE][total:16 LE] = 40 bytes.
    pub const ENCODED_LEN: usize = 8 + 8 + 8 + 16;

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::ENCODED_LEN);
        buf.extend_from_slice(&self.start_slot.to_le_bytes());
        buf.extend_from_slice(&self.cliff_slots.to_le_bytes());
        buf.extend_from_slice(&self.duration_slots.to_le_bytes());
        buf.extend_from_slice(&self.total_amount.to_le_bytes());
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::ENCODED_LEN {
            return None;
        }
        let start_slot = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let cliff_slots = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        let duration_slots = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
        let total_amount = u128::from_le_bytes(bytes[24..40].try_into().ok()?);
        Some(Self {
            start_slot,
            cliff_slots,
            duration_slots,
            total_amount,
        })
    }

    /// Compute the unlocked portion of `total_amount` at `current_slot`.
    /// Returns 0 before the cliff, `total_amount` after full vesting,
    /// linear interpolation in between.
    ///
    /// `duration_slots == 0` is treated as "fully vested at start"
    /// (instant unlock; no protocol-level vesting despite a record
    /// being present). This makes migration easier — entries created
    /// before vesting was meaningful won't accidentally lock balances.
    pub fn unlocked_at(&self, current_slot: u64) -> u128 {
        if self.duration_slots == 0 {
            return self.total_amount;
        }
        if current_slot < self.start_slot.saturating_add(self.cliff_slots) {
            return 0;
        }
        let end = self.start_slot.saturating_add(self.duration_slots);
        if current_slot >= end {
            return self.total_amount;
        }
        let elapsed = current_slot.saturating_sub(self.start_slot) as u128;
        let duration = self.duration_slots as u128;
        // Compute in u128 to avoid overflow on large totals.
        self.total_amount.saturating_mul(elapsed) / duration
    }

    /// Currently-locked amount = total - unlocked. Used by tx validation
    /// to derive the sender's spendable balance.
    pub fn locked_at(&self, current_slot: u64) -> u128 {
        self.total_amount.saturating_sub(self.unlocked_at(current_slot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sched(start: u64, cliff: u64, dur: u64, total: u128) -> VestingSchedule {
        VestingSchedule {
            start_slot: start,
            cliff_slots: cliff,
            duration_slots: dur,
            total_amount: total,
        }
    }

    #[test]
    fn unlocked_zero_before_cliff() {
        let s = sched(0, 100, 1000, 1_000_000);
        assert_eq!(s.unlocked_at(0), 0);
        assert_eq!(s.unlocked_at(50), 0);
        assert_eq!(s.unlocked_at(99), 0);
    }

    #[test]
    fn unlocked_jumps_at_cliff_to_linear_curve() {
        // At cliff = 100 of 1000 duration → 10% unlocks.
        let s = sched(0, 100, 1000, 1_000_000);
        assert_eq!(s.unlocked_at(100), 100_000);
    }

    #[test]
    fn unlocked_linear_between_cliff_and_end() {
        let s = sched(0, 100, 1000, 1_000_000);
        // 50% of duration elapsed → 50% unlocked
        assert_eq!(s.unlocked_at(500), 500_000);
        // 75% → 75%
        assert_eq!(s.unlocked_at(750), 750_000);
    }

    #[test]
    fn unlocked_full_at_end_and_after() {
        let s = sched(0, 100, 1000, 1_000_000);
        assert_eq!(s.unlocked_at(1000), 1_000_000);
        assert_eq!(s.unlocked_at(10_000), 1_000_000);
    }

    #[test]
    fn unlocked_respects_non_zero_start_slot() {
        let s = sched(500, 100, 1000, 1_000_000);
        assert_eq!(s.unlocked_at(499), 0, "pre-start");
        assert_eq!(s.unlocked_at(599), 0, "pre-cliff");
        assert_eq!(s.unlocked_at(600), 100_000, "at cliff");
        assert_eq!(s.unlocked_at(1500), 1_000_000, "at end");
    }

    #[test]
    fn zero_duration_means_instant_unlock() {
        let s = sched(0, 0, 0, 1_000_000);
        assert_eq!(s.unlocked_at(0), 1_000_000);
    }

    #[test]
    fn locked_and_unlocked_sum_to_total() {
        let s = sched(0, 100, 1000, 1_000_000);
        for slot in [0, 50, 100, 250, 500, 750, 1000, 2000] {
            assert_eq!(s.locked_at(slot) + s.unlocked_at(slot), 1_000_000);
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let s = sched(1_000, 86_400, 31_536_000, 150_000_000 * 1_000_000_000);
        let bytes = s.encode();
        assert_eq!(bytes.len(), VestingSchedule::ENCODED_LEN);
        let back = VestingSchedule::decode(&bytes).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn decode_rejects_truncated() {
        assert!(VestingSchedule::decode(&[0u8; 39]).is_none());
    }
}
