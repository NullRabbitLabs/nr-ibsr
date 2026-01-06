//! Clock abstraction for IBSR.
//!
//! Provides a trait for getting the current time, with both real and mock implementations
//! to enable deterministic testing.

use std::time::{SystemTime, UNIX_EPOCH};

/// Trait for getting the current Unix timestamp.
pub trait Clock: Send + Sync {
    /// Returns the current time as Unix seconds since epoch.
    fn now_unix_sec(&self) -> u64;
}

/// Real system clock implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_sec(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_secs()
    }
}

/// Mock clock for testing with a fixed timestamp.
#[derive(Debug, Clone, Copy)]
pub struct MockClock {
    timestamp: u64,
}

impl MockClock {
    /// Create a mock clock with a fixed timestamp.
    pub fn new(timestamp: u64) -> Self {
        Self { timestamp }
    }
}

impl Clock for MockClock {
    fn now_unix_sec(&self) -> u64 {
        self.timestamp
    }
}

/// Mock clock that auto-advances time on each call.
///
/// Useful for testing time-sensitive loops where the clock needs to progress.
#[derive(Debug)]
pub struct AdvancingClock {
    timestamp: std::sync::atomic::AtomicU64,
    increment: u64,
}

impl AdvancingClock {
    /// Create an advancing clock starting at `timestamp` and incrementing by `increment` each call.
    pub fn new(timestamp: u64, increment: u64) -> Self {
        Self {
            timestamp: std::sync::atomic::AtomicU64::new(timestamp),
            increment,
        }
    }
}

impl Clock for AdvancingClock {
    fn now_unix_sec(&self) -> u64 {
        self.timestamp
            .fetch_add(self.increment, std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_clock_returns_fixed_timestamp() {
        let clock = MockClock::new(1234567890);
        assert_eq!(clock.now_unix_sec(), 1234567890);
    }

    #[test]
    fn test_mock_clock_zero_timestamp() {
        let clock = MockClock::new(0);
        assert_eq!(clock.now_unix_sec(), 0);
    }

    #[test]
    fn test_mock_clock_max_timestamp() {
        let clock = MockClock::new(u64::MAX);
        assert_eq!(clock.now_unix_sec(), u64::MAX);
    }

    #[test]
    fn test_system_clock_returns_reasonable_time() {
        let clock = SystemClock;
        let now = clock.now_unix_sec();

        // Should be after 2020-01-01 (1577836800)
        assert!(now > 1577836800);

        // Should be before 2100-01-01 (4102444800)
        assert!(now < 4102444800);
    }

    #[test]
    fn test_system_clock_is_monotonic() {
        let clock = SystemClock;
        let t1 = clock.now_unix_sec();
        let t2 = clock.now_unix_sec();

        // Second call should be >= first (at second granularity)
        assert!(t2 >= t1);
    }

    #[test]
    fn test_clock_trait_object() {
        // Test that Clock can be used as a trait object
        let mock: Box<dyn Clock> = Box::new(MockClock::new(1234567890));
        assert_eq!(mock.now_unix_sec(), 1234567890);

        let system: Box<dyn Clock> = Box::new(SystemClock);
        assert!(system.now_unix_sec() > 1577836800);
    }

    #[test]
    fn test_system_clock_default() {
        let clock = SystemClock::default();
        assert!(clock.now_unix_sec() > 1577836800);
    }

    #[test]
    fn test_advancing_clock_increments() {
        let clock = AdvancingClock::new(1000, 5);
        assert_eq!(clock.now_unix_sec(), 1000);
        assert_eq!(clock.now_unix_sec(), 1005);
        assert_eq!(clock.now_unix_sec(), 1010);
    }

    #[test]
    fn test_advancing_clock_zero_increment() {
        let clock = AdvancingClock::new(1000, 0);
        assert_eq!(clock.now_unix_sec(), 1000);
        assert_eq!(clock.now_unix_sec(), 1000);
    }

    #[test]
    fn test_advancing_clock_debug() {
        let clock = AdvancingClock::new(1000, 1);
        let debug = format!("{:?}", clock);
        assert!(debug.contains("AdvancingClock"));
    }
}
