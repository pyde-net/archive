//! Slot clock: tracks the current slot based on wall clock time.
//!
//! Slot 0 starts at genesis timestamp. Each slot is 400ms.
//! The slot clock determines when to propose, vote, and advance.

use pyde_consensus::block::BLOCK_TIME_MS;
use std::time::{Duration, Instant};

/// Slot clock anchored to genesis time.
pub struct SlotClock {
    /// When the chain started (genesis timestamp or node start for devnet).
    genesis_instant: Instant,
    /// Genesis Unix timestamp in ms (for absolute time reference).
    genesis_timestamp_ms: u64,
    /// Slot duration.
    #[allow(dead_code)]
    slot_duration: Duration,
}

impl SlotClock {
    /// Create a new slot clock. If genesis_timestamp_ms is 0, use current time.
    pub fn new(genesis_timestamp_ms: u64) -> Self {
        let now_ms = current_time_ms();
        let genesis_instant = if genesis_timestamp_ms == 0 || genesis_timestamp_ms >= now_ms {
            // Genesis is now or in the future — start from current instant
            Instant::now()
        } else {
            // Genesis was in the past — compute how far back
            let elapsed_ms = now_ms - genesis_timestamp_ms;
            Instant::now() - Duration::from_millis(elapsed_ms)
        };

        Self {
            genesis_instant,
            genesis_timestamp_ms: if genesis_timestamp_ms == 0 { now_ms } else { genesis_timestamp_ms },
            slot_duration: Duration::from_millis(BLOCK_TIME_MS),
        }
    }

    /// Current slot number based on elapsed time since genesis.
    pub fn current_slot(&self) -> u64 {
        let elapsed = self.genesis_instant.elapsed();
        (elapsed.as_millis() as u64) / BLOCK_TIME_MS
    }

    /// Time remaining in the current slot.
    #[allow(dead_code)]
    pub fn time_remaining(&self) -> Duration {
        let elapsed = self.genesis_instant.elapsed();
        let elapsed_ms = elapsed.as_millis() as u64;
        let slot_end_ms = (self.current_slot() + 1) * BLOCK_TIME_MS;
        let remaining = slot_end_ms.saturating_sub(elapsed_ms);
        Duration::from_millis(remaining)
    }

    /// Duration until a specific slot starts.
    #[allow(dead_code)]
    pub fn duration_until_slot(&self, slot: u64) -> Duration {
        let slot_start_ms = slot * BLOCK_TIME_MS;
        let elapsed_ms = self.genesis_instant.elapsed().as_millis() as u64;
        if slot_start_ms > elapsed_ms {
            Duration::from_millis(slot_start_ms - elapsed_ms)
        } else {
            Duration::ZERO
        }
    }

    /// Timestamp (Unix ms) for a given slot.
    pub fn slot_timestamp(&self, slot: u64) -> u64 {
        self.genesis_timestamp_ms + slot * BLOCK_TIME_MS
    }

    /// Slot duration.
    #[allow(dead_code)]
    pub fn slot_duration(&self) -> Duration {
        self.slot_duration
    }

    /// Milliseconds elapsed within the current slot (0..400).
    pub fn ms_into_slot(&self) -> u64 {
        let elapsed_ms = self.genesis_instant.elapsed().as_millis() as u64;
        elapsed_ms % BLOCK_TIME_MS
    }
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_starts_at_zero() {
        let clock = SlotClock::new(0);
        // Just created — should be at slot 0 or very early
        assert!(clock.current_slot() <= 1);
    }

    #[test]
    fn slot_advances_with_time() {
        // Genesis was 2 seconds ago → should be at slot 5 (2000ms / 400ms)
        let now_ms = current_time_ms();
        let clock = SlotClock::new(now_ms - 2000);
        let slot = clock.current_slot();
        assert!(slot >= 4 && slot <= 6, "expected ~5, got {}", slot);
    }

    #[test]
    fn time_remaining_is_bounded() {
        let clock = SlotClock::new(0);
        let remaining = clock.time_remaining();
        assert!(remaining <= Duration::from_millis(BLOCK_TIME_MS));
    }

    #[test]
    fn slot_timestamp_consistent() {
        let genesis_ts = 1_000_000u64;
        let clock = SlotClock::new(genesis_ts);
        assert_eq!(clock.slot_timestamp(0), genesis_ts);
        assert_eq!(clock.slot_timestamp(10), genesis_ts + 10 * BLOCK_TIME_MS);
    }
}
