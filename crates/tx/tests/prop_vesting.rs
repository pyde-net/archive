//! Property tests for vesting schedule math (slice 4.4).

use proptest::prelude::*;
use pyde_tx::vesting::VestingSchedule;

fn any_schedule() -> impl Strategy<Value = VestingSchedule> {
    (
        0u64..=1_000_000_000,
        0u64..=1_000_000_000,
        1u64..=1_000_000_000,
        any::<u128>(),
    )
        .prop_map(
            |(start_slot, cliff_slots, duration_slots, total_amount)| VestingSchedule {
                start_slot,
                cliff_slots,
                duration_slots,
                total_amount,
            },
        )
}

proptest! {
    /// Encode→decode roundtrip must preserve every field. VestingSchedule
    /// has a fixed-size encoding (40 bytes) — if the encode/decode
    /// offsets ever drift, this catches it.
    #[test]
    fn schedule_encode_decode_roundtrip(sched in any_schedule()) {
        let bytes = sched.encode();
        prop_assert_eq!(bytes.len(), VestingSchedule::ENCODED_LEN);
        let decoded = VestingSchedule::decode(&bytes).unwrap();
        prop_assert_eq!(sched.start_slot, decoded.start_slot);
        prop_assert_eq!(sched.cliff_slots, decoded.cliff_slots);
        prop_assert_eq!(sched.duration_slots, decoded.duration_slots);
        prop_assert_eq!(sched.total_amount, decoded.total_amount);
    }

    /// Decoder must never panic on arbitrary bytes.
    #[test]
    fn schedule_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..=200)) {
        let _ = VestingSchedule::decode(&bytes);
    }

    /// Core invariant: unlocked + locked == total_amount for any slot.
    /// This is the fundamental accounting invariant. If unlocked_at()
    /// and locked_at() ever diverge, a bug lets a vesting holder
    /// spend more than they should OR less than vested unlocks.
    #[test]
    fn unlocked_plus_locked_equals_total(
        sched in any_schedule(),
        slot in 0u64..=u64::MAX,
    ) {
        let unlocked = sched.unlocked_at(slot);
        let locked = sched.locked_at(slot);
        prop_assert_eq!(
            unlocked.checked_add(locked),
            Some(sched.total_amount),
            "unlocked + locked must equal total (no overflow, no loss)"
        );
    }

    /// Monotonic unlock: unlocked_at is non-decreasing in slot. If it
    /// could ever go DOWN, tokens that were spendable in an earlier
    /// slot would become locked again — breaking expected semantics.
    #[test]
    fn unlocked_is_monotonic(
        sched in any_schedule(),
        slot_a in 0u64..=1_000_000_000,
        delta in 0u64..=1_000_000_000,
    ) {
        let slot_b = slot_a.saturating_add(delta);
        let u_a = sched.unlocked_at(slot_a);
        let u_b = sched.unlocked_at(slot_b);
        prop_assert!(u_b >= u_a, "unlocked decreased across slot boundary");
    }

    /// Before the cliff, nothing unlocks — but only for valid
    /// schedules where the cliff falls inside the vesting window.
    /// `cliff_slots > duration_slots` is ill-configured and rejected
    /// at genesis; runtime falls through to the end-of-vesting check
    /// which returns `total_amount` past `end_slot`.
    #[test]
    fn pre_cliff_unlocked_is_zero(sched in any_schedule()) {
        prop_assume!(sched.cliff_slots <= sched.duration_slots);
        let cliff_end = sched.start_slot.saturating_add(sched.cliff_slots);
        if cliff_end > 0 {
            let pre_cliff_slot = cliff_end.saturating_sub(1);
            if pre_cliff_slot >= sched.start_slot {
                let u = sched.unlocked_at(pre_cliff_slot);
                prop_assert_eq!(u, 0, "unlocked must be 0 strictly before cliff");
            }
        }
    }

    /// After the full duration, everything unlocks.
    #[test]
    fn post_duration_fully_unlocked(sched in any_schedule()) {
        let end_slot = sched.start_slot.saturating_add(sched.duration_slots);
        // Test at end_slot AND beyond.
        for future in [end_slot, end_slot.saturating_add(1_000_000), u64::MAX] {
            let u = sched.unlocked_at(future);
            prop_assert_eq!(
                u, sched.total_amount,
                "full amount must be unlocked at or after end_slot"
            );
        }
    }
}
