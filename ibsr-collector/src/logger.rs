//! Logging abstraction for testable output.
//!
//! Provides a trait-based logging system that enables deterministic testing
//! of log output without depending on global state or external log crates.

use std::io::Write;
use std::sync::{Arc, RwLock};

/// Verbosity level for logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
    /// Normal output (always shown)
    Normal,
    /// Verbose output (-v flag)
    Verbose,
    /// Debug output (-vv flag)
    Debug,
}

impl Verbosity {
    /// Create verbosity from CLI flag count.
    pub fn from_count(count: u8) -> Self {
        match count {
            0 => Verbosity::Normal,
            1 => Verbosity::Verbose,
            _ => Verbosity::Debug,
        }
    }
}

/// Trait for logging output.
///
/// Implementations should be thread-safe as the collector may log from
/// multiple contexts (signal handlers, collection loop, etc.).
pub trait Logger: Send + Sync {
    /// Log a message at the given verbosity level.
    fn log(&self, level: Verbosity, message: &str);

    /// Log at normal level (always visible).
    fn info(&self, message: &str) {
        self.log(Verbosity::Normal, message);
    }

    /// Log at verbose level (requires -v).
    fn verbose(&self, message: &str) {
        self.log(Verbosity::Verbose, message);
    }

    /// Log at debug level (requires -vv).
    fn debug(&self, message: &str) {
        self.log(Verbosity::Debug, message);
    }
}

/// Logger that writes to stderr.
#[derive(Debug)]
pub struct StderrLogger {
    level: Verbosity,
}

impl StderrLogger {
    /// Create a new stderr logger with the given verbosity level.
    pub fn new(level: Verbosity) -> Self {
        Self { level }
    }

    /// Create a logger that only shows normal output.
    pub fn normal() -> Self {
        Self::new(Verbosity::Normal)
    }

    /// Create a logger that shows verbose output.
    pub fn verbose() -> Self {
        Self::new(Verbosity::Verbose)
    }

    /// Create a logger that shows debug output.
    pub fn debug() -> Self {
        Self::new(Verbosity::Debug)
    }
}

impl Logger for StderrLogger {
    fn log(&self, level: Verbosity, message: &str) {
        if level <= self.level {
            let _ = writeln!(std::io::stderr(), "{}", message);
        }
    }
}

/// Mock logger for testing that captures all messages.
#[derive(Debug, Clone)]
pub struct MockLogger {
    level: Verbosity,
    messages: Arc<RwLock<Vec<LogEntry>>>,
}

/// A captured log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub level: Verbosity,
    pub message: String,
}

impl MockLogger {
    /// Create a new mock logger with the given verbosity level.
    pub fn new(level: Verbosity) -> Self {
        Self {
            level,
            messages: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create a mock logger that captures all levels.
    pub fn capture_all() -> Self {
        Self::new(Verbosity::Debug)
    }

    /// Get all captured log entries.
    pub fn entries(&self) -> Vec<LogEntry> {
        self.messages.read().unwrap().clone()
    }

    /// Get all captured messages (just the text).
    pub fn messages(&self) -> Vec<String> {
        self.entries().iter().map(|e| e.message.clone()).collect()
    }

    /// Get messages at a specific level.
    pub fn messages_at_level(&self, level: Verbosity) -> Vec<String> {
        self.entries()
            .iter()
            .filter(|e| e.level == level)
            .map(|e| e.message.clone())
            .collect()
    }

    /// Check if any message contains the given substring.
    pub fn contains(&self, substring: &str) -> bool {
        self.messages().iter().any(|m| m.contains(substring))
    }

    /// Clear all captured messages.
    pub fn clear(&self) {
        self.messages.write().unwrap().clear();
    }

    /// Get count of captured messages.
    pub fn count(&self) -> usize {
        self.messages.read().unwrap().len()
    }
}

impl Logger for MockLogger {
    fn log(&self, level: Verbosity, message: &str) {
        // Always capture the message, regardless of level
        // This allows tests to verify what would be logged
        self.messages.write().unwrap().push(LogEntry {
            level,
            message: message.to_string(),
        });
    }
}

/// A no-op logger that discards all messages.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullLogger;

impl NullLogger {
    /// Create a new null logger.
    pub fn new() -> Self {
        Self
    }
}

impl Logger for NullLogger {
    fn log(&self, _level: Verbosity, _message: &str) {
        // Discard
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===========================================
    // Verbosity Tests
    // ===========================================

    #[test]
    fn test_verbosity_ordering() {
        assert!(Verbosity::Normal < Verbosity::Verbose);
        assert!(Verbosity::Verbose < Verbosity::Debug);
        assert!(Verbosity::Normal < Verbosity::Debug);
    }

    #[test]
    fn test_verbosity_from_count_zero() {
        assert_eq!(Verbosity::from_count(0), Verbosity::Normal);
    }

    #[test]
    fn test_verbosity_from_count_one() {
        assert_eq!(Verbosity::from_count(1), Verbosity::Verbose);
    }

    #[test]
    fn test_verbosity_from_count_two() {
        assert_eq!(Verbosity::from_count(2), Verbosity::Debug);
    }

    #[test]
    fn test_verbosity_from_count_higher() {
        // Any count >= 2 should be Debug
        assert_eq!(Verbosity::from_count(3), Verbosity::Debug);
        assert_eq!(Verbosity::from_count(255), Verbosity::Debug);
    }

    #[test]
    fn test_verbosity_clone() {
        let v = Verbosity::Verbose;
        let v2 = v;
        assert_eq!(v, v2);
    }

    #[test]
    fn test_verbosity_debug() {
        let debug_str = format!("{:?}", Verbosity::Normal);
        assert!(debug_str.contains("Normal"));
    }

    // ===========================================
    // MockLogger Tests
    // ===========================================

    #[test]
    fn test_mock_logger_captures_messages() {
        let logger = MockLogger::capture_all();
        logger.info("test message");

        let messages = logger.messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0], "test message");
    }

    #[test]
    fn test_mock_logger_captures_all_levels() {
        let logger = MockLogger::capture_all();
        logger.info("normal");
        logger.verbose("verbose");
        logger.debug("debug");

        let entries = logger.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].level, Verbosity::Normal);
        assert_eq!(entries[1].level, Verbosity::Verbose);
        assert_eq!(entries[2].level, Verbosity::Debug);
    }

    #[test]
    fn test_mock_logger_messages_at_level() {
        let logger = MockLogger::capture_all();
        logger.info("info1");
        logger.verbose("verbose1");
        logger.info("info2");

        let verbose_messages = logger.messages_at_level(Verbosity::Verbose);
        assert_eq!(verbose_messages.len(), 1);
        assert_eq!(verbose_messages[0], "verbose1");
    }

    #[test]
    fn test_mock_logger_contains() {
        let logger = MockLogger::capture_all();
        logger.info("hello world");

        assert!(logger.contains("hello"));
        assert!(logger.contains("world"));
        assert!(!logger.contains("goodbye"));
    }

    #[test]
    fn test_mock_logger_clear() {
        let logger = MockLogger::capture_all();
        logger.info("message");
        assert_eq!(logger.count(), 1);

        logger.clear();
        assert_eq!(logger.count(), 0);
    }

    #[test]
    fn test_mock_logger_count() {
        let logger = MockLogger::capture_all();
        assert_eq!(logger.count(), 0);

        logger.info("one");
        assert_eq!(logger.count(), 1);

        logger.info("two");
        assert_eq!(logger.count(), 2);
    }

    #[test]
    fn test_mock_logger_clone() {
        let logger = MockLogger::capture_all();
        logger.info("original");

        let logger2 = logger.clone();
        logger2.info("cloned");

        // Both should see the same messages (shared Arc)
        assert_eq!(logger.count(), 2);
        assert_eq!(logger2.count(), 2);
    }

    // ===========================================
    // StderrLogger Tests
    // ===========================================

    #[test]
    fn test_stderr_logger_new() {
        let logger = StderrLogger::new(Verbosity::Verbose);
        // Just verify it can be created
        assert_eq!(format!("{:?}", logger), "StderrLogger { level: Verbose }");
    }

    #[test]
    fn test_stderr_logger_constructors() {
        let normal = StderrLogger::normal();
        let verbose = StderrLogger::verbose();
        let debug = StderrLogger::debug();

        // Verify they were created with correct levels
        assert_eq!(format!("{:?}", normal), "StderrLogger { level: Normal }");
        assert_eq!(format!("{:?}", verbose), "StderrLogger { level: Verbose }");
        assert_eq!(format!("{:?}", debug), "StderrLogger { level: Debug }");
    }

    // ===========================================
    // NullLogger Tests
    // ===========================================

    #[test]
    fn test_null_logger_discards() {
        let logger = NullLogger::new();
        logger.info("discarded");
        logger.verbose("also discarded");
        logger.debug("all discarded");
        // No assertion needed - just verify it doesn't panic
    }

    #[test]
    fn test_null_logger_default() {
        let logger = NullLogger::default();
        logger.info("test");
    }

    #[test]
    fn test_null_logger_clone() {
        let logger = NullLogger::new();
        let logger2 = logger;
        logger2.info("test");
    }

    // ===========================================
    // LogEntry Tests
    // ===========================================

    #[test]
    fn test_log_entry_eq() {
        let e1 = LogEntry {
            level: Verbosity::Normal,
            message: "test".to_string(),
        };
        let e2 = LogEntry {
            level: Verbosity::Normal,
            message: "test".to_string(),
        };
        let e3 = LogEntry {
            level: Verbosity::Verbose,
            message: "test".to_string(),
        };

        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
    }

    #[test]
    fn test_log_entry_clone() {
        let e1 = LogEntry {
            level: Verbosity::Normal,
            message: "test".to_string(),
        };
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_log_entry_debug() {
        let entry = LogEntry {
            level: Verbosity::Normal,
            message: "test".to_string(),
        };
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("Normal"));
        assert!(debug_str.contains("test"));
    }
}
