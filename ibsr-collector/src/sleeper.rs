//! Sleep abstraction for testable collection loops.
//!
//! This module provides a `Sleeper` trait for abstracting sleep operations,
//! allowing collection loops to be tested without actual delays.

use std::time::Duration;

/// Trait for sleeping between collection cycles.
pub trait Sleeper: Send + Sync {
    /// Sleep for the specified number of seconds.
    fn sleep_sec(&self, seconds: u64);
}

/// Real sleeper that uses `std::thread::sleep`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealSleeper;

impl RealSleeper {
    /// Create a new real sleeper.
    pub fn new() -> Self {
        Self
    }
}

impl Sleeper for RealSleeper {
    fn sleep_sec(&self, seconds: u64) {
        std::thread::sleep(Duration::from_secs(seconds));
    }
}

/// Mock sleeper for testing - returns immediately.
#[derive(Debug, Default, Clone, Copy)]
pub struct MockSleeper;

impl MockSleeper {
    /// Create a new mock sleeper.
    pub fn new() -> Self {
        Self
    }
}

impl Sleeper for MockSleeper {
    fn sleep_sec(&self, _seconds: u64) {
        // Instant return for testing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_sleeper_returns_immediately() {
        let sleeper = MockSleeper::new();
        let start = std::time::Instant::now();
        sleeper.sleep_sec(100); // Would be 100 seconds if real
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 10); // Should be instant
    }

    #[test]
    fn test_mock_sleeper_default() {
        let sleeper = MockSleeper::default();
        sleeper.sleep_sec(1);
    }

    #[test]
    fn test_real_sleeper_new() {
        let sleeper = RealSleeper::new();
        let _ = format!("{:?}", sleeper);
    }

    #[test]
    fn test_real_sleeper_default() {
        let sleeper = RealSleeper::default();
        let _ = format!("{:?}", sleeper);
    }

    #[test]
    fn test_sleeper_trait_object() {
        let sleeper: Box<dyn Sleeper> = Box::new(MockSleeper::new());
        sleeper.sleep_sec(1);
    }

    #[test]
    fn test_mock_sleeper_debug() {
        let sleeper = MockSleeper::new();
        let debug = format!("{:?}", sleeper);
        assert!(debug.contains("MockSleeper"));
    }

    #[test]
    fn test_real_sleeper_debug() {
        let sleeper = RealSleeper::new();
        let debug = format!("{:?}", sleeper);
        assert!(debug.contains("RealSleeper"));
    }

    #[test]
    fn test_mock_sleeper_clone() {
        let sleeper = MockSleeper::new();
        let _cloned = sleeper;
    }

    #[test]
    fn test_real_sleeper_clone() {
        let sleeper = RealSleeper::new();
        let _cloned = sleeper;
    }
}
