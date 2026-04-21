//! Slot clock: tracks the current slot based on wall clock time.
//!
//! Slot 0 starts at genesis timestamp. Each slot defaults to 400ms
//! but is configurable via `[consensus].block_time_ms` so tests can
//! cross large slot counts (epoch boundaries) quickly.
//! The slot clock determines when to propose, vote, and advance.

#[cfg(test)]
use pyde_consensus::block::BLOCK_TIME_MS;
use std::time::{Duration, Instant};

/// Slot clock anchored to genesis time.
pub struct SlotClock {
    /// When the chain started (genesis timestamp or node start for devnet).
    genesis_instant: Instant,
    /// Genesis Unix timestamp in ms (for absolute time reference).
    genesis_timestamp_ms: u64,
    /// Slot duration in ms — configurable via `[consensus].block_time_ms`.
    block_time_ms: u64,
}

impl SlotClock {
    /// Create a new slot clock at the default block time
    /// (`BLOCK_TIME_MS` = 400 ms). If `genesis_timestamp_ms` is 0,
    /// use the current wall clock. Kept for the in-module tests;
    /// production code goes through `with_block_time` so the config
    /// value actually takes effect.
    #[cfg(test)]
    pub fn new(genesis_timestamp_ms: u64) -> Self {
        Self::with_block_time(genesis_timestamp_ms, BLOCK_TIME_MS)
    }

    /// Create a new slot clock with a caller-supplied slot duration.
    /// Values outside 10..=10_000 are clamped to 10 ms / 10 s — sub-
    /// 10ms rates destabilize consensus on laptops and > 10s rates
    /// are clearly a config error.
    pub fn with_block_time(genesis_timestamp_ms: u64, block_time_ms: u64) -> Self {
        let block_time_ms = block_time_ms.clamp(10, 10_000);
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
            genesis_timestamp_ms: if genesis_timestamp_ms == 0 {
                now_ms
            } else {
                genesis_timestamp_ms
            },
            block_time_ms,
        }
    }

    /// Current slot number based on elapsed time since genesis.
    pub fn current_slot(&self) -> u64 {
        let elapsed = self.genesis_instant.elapsed();
        (elapsed.as_millis() as u64) / self.block_time_ms
    }

    /// Time remaining in the current slot.
    #[allow(dead_code)]
    pub fn time_remaining(&self) -> Duration {
        let elapsed = self.genesis_instant.elapsed();
        let elapsed_ms = elapsed.as_millis() as u64;
        let slot_end_ms = (self.current_slot() + 1) * self.block_time_ms;
        let remaining = slot_end_ms.saturating_sub(elapsed_ms);
        Duration::from_millis(remaining)
    }

    /// Duration until a specific slot starts.
    #[allow(dead_code)]
    pub fn duration_until_slot(&self, slot: u64) -> Duration {
        let slot_start_ms = slot * self.block_time_ms;
        let elapsed_ms = self.genesis_instant.elapsed().as_millis() as u64;
        if slot_start_ms > elapsed_ms {
            Duration::from_millis(slot_start_ms - elapsed_ms)
        } else {
            Duration::ZERO
        }
    }

    /// Timestamp (Unix ms) for a given slot.
    pub fn slot_timestamp(&self, slot: u64) -> u64 {
        self.genesis_timestamp_ms + slot * self.block_time_ms
    }

    /// Slot duration.
    #[allow(dead_code)]
    pub fn slot_duration(&self) -> Duration {
        Duration::from_millis(self.block_time_ms)
    }

    /// Milliseconds elapsed within the current slot (0..400).
    pub fn ms_into_slot(&self) -> u64 {
        let elapsed_ms = self.genesis_instant.elapsed().as_millis() as u64;
        elapsed_ms % self.block_time_ms
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
        assert!((4..=6).contains(&slot), "expected ~5, got {}", slot);
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
