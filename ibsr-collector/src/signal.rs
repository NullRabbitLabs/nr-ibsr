//! Signal handling for graceful shutdown.
//!
//! This module provides `ShutdownFlag` for handling SIGINT (Ctrl+C)
//! to enable graceful shutdown of collection loops.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Trait for checking shutdown status.
pub trait ShutdownCheck: Send + Sync {
    /// Returns true if shutdown has been requested.
    fn should_stop(&self) -> bool;
}

/// Flag that tracks whether shutdown has been requested.
///
/// When created with `new()`, registers a SIGINT handler that sets the flag.
/// The collection loop should periodically check `should_stop()`.
#[derive(Debug, Clone)]
pub struct ShutdownFlag {
    flag: Arc<AtomicBool>,
}

impl Default for ShutdownFlag {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownFlag {
    /// Create a new shutdown flag and register SIGINT handler.
    ///
    /// This sets up a Ctrl+C handler that will set the flag when triggered.
    /// If the handler cannot be registered (e.g., already registered), this
    /// will still return a valid flag that can be manually triggered.
    pub fn new() -> Self {
        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = flag.clone();

        // Attempt to set handler, ignore errors (may already be set)
        let _ = ctrlc::set_handler(move || {
            flag_clone.store(true, Ordering::SeqCst);
        });

        Self { flag }
    }

    /// Create a shutdown flag without registering a handler.
    ///
    /// Useful for testing when you want to manually control the flag.
    pub fn manual() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Manually trigger shutdown.
    ///
    /// Useful for testing or programmatic shutdown.
    pub fn trigger(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Reset the flag to not-shutdown state.
    ///
    /// Useful for testing.
    pub fn reset(&self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

impl ShutdownCheck for ShutdownFlag {
    fn should_stop(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

/// Mock shutdown checker for testing - never signals shutdown.
#[derive(Debug, Default, Clone)]
pub struct NeverShutdown;

impl NeverShutdown {
    /// Create a new mock that never signals shutdown.
    pub fn new() -> Self {
        Self
    }
}

impl ShutdownCheck for NeverShutdown {
    fn should_stop(&self) -> bool {
        false
    }
}

/// Mock shutdown checker that always signals shutdown.
#[derive(Debug, Default, Clone)]
pub struct AlwaysShutdown;

impl AlwaysShutdown {
    /// Create a new mock that always signals shutdown.
    pub fn new() -> Self {
        Self
    }
}

impl ShutdownCheck for AlwaysShutdown {
    fn should_stop(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown_flag_initially_false() {
        let flag = ShutdownFlag::manual();
        assert!(!flag.should_stop());
    }

    #[test]
    fn test_shutdown_flag_trigger() {
        let flag = ShutdownFlag::manual();
        assert!(!flag.should_stop());
        flag.trigger();
        assert!(flag.should_stop());
    }

    #[test]
    fn test_shutdown_flag_reset() {
        let flag = ShutdownFlag::manual();
        flag.trigger();
        assert!(flag.should_stop());
        flag.reset();
        assert!(!flag.should_stop());
    }

    #[test]
    fn test_shutdown_flag_clone_shares_state() {
        let flag1 = ShutdownFlag::manual();
        let flag2 = flag1.clone();
        assert!(!flag2.should_stop());
        flag1.trigger();
        assert!(flag2.should_stop());
    }

    #[test]
    fn test_shutdown_flag_debug() {
        let flag = ShutdownFlag::manual();
        let debug = format!("{:?}", flag);
        assert!(debug.contains("ShutdownFlag"));
    }

    #[test]
    fn test_shutdown_flag_default() {
        let flag = ShutdownFlag::default();
        assert!(!flag.should_stop());
    }

    #[test]
    fn test_never_shutdown() {
        let checker = NeverShutdown::new();
        assert!(!checker.should_stop());
        // Call multiple times - should always be false
        assert!(!checker.should_stop());
        assert!(!checker.should_stop());
    }

    #[test]
    fn test_never_shutdown_default() {
        let checker = NeverShutdown::default();
        assert!(!checker.should_stop());
    }

    #[test]
    fn test_never_shutdown_debug() {
        let checker = NeverShutdown::new();
        let debug = format!("{:?}", checker);
        assert!(debug.contains("NeverShutdown"));
    }

    #[test]
    fn test_always_shutdown() {
        let checker = AlwaysShutdown::new();
        assert!(checker.should_stop());
    }

    #[test]
    fn test_always_shutdown_default() {
        let checker = AlwaysShutdown::default();
        assert!(checker.should_stop());
    }

    #[test]
    fn test_always_shutdown_debug() {
        let checker = AlwaysShutdown::new();
        let debug = format!("{:?}", checker);
        assert!(debug.contains("AlwaysShutdown"));
    }

    #[test]
    fn test_shutdown_check_trait_object() {
        let checker: Box<dyn ShutdownCheck> = Box::new(NeverShutdown::new());
        assert!(!checker.should_stop());
    }

    #[test]
    fn test_shutdown_flag_new_does_not_panic() {
        // Should not panic even if ctrlc handler fails
        let flag = ShutdownFlag::new();
        assert!(!flag.should_stop());
    }
}
