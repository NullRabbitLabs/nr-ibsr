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

/// Format a Unix timestamp as a directory name string.
///
/// Returns a string in the format "YYYYMMDD-HHMMSSZ" (UTC time).
/// This is suitable for creating timestamped run directories.
///
/// # Example
/// ```
/// use ibsr_clock::format_timestamp_for_dirname;
/// let dirname = format_timestamp_for_dirname(1704067200); // 2024-01-01 00:00:00 UTC
/// assert_eq!(dirname, "20240101-000000Z");
/// ```
pub fn format_timestamp_for_dirname(timestamp: u64) -> String {
    // Convert to chrono DateTime for formatting
    // We use a simple manual approach to avoid adding chrono as a dependency
    let secs = timestamp;
    let days_since_epoch = secs / 86400;
    let secs_today = secs % 86400;

    let hours = secs_today / 3600;
    let minutes = (secs_today % 3600) / 60;
    let seconds = secs_today % 60;

    // Calculate year, month, day from days since epoch
    // Using a simplified algorithm (valid for 1970-2099)
    let (year, month, day) = days_to_ymd(days_since_epoch as i64);

    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    // Days since 1970-01-01
    let mut remaining_days = days;

    // Start from 1970
    let mut year = 1970i32;

    // Find year
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    // Find month and day
    let days_in_months: [i64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u32;
    for &days_in_month in &days_in_months {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    let day = (remaining_days + 1) as u32;

    (year, month, day)
}

/// Check if a year is a leap year.
fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
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

    #[test]
    fn test_format_timestamp_for_dirname_epoch() {
        // Unix epoch: 1970-01-01 00:00:00 UTC
        assert_eq!(format_timestamp_for_dirname(0), "19700101-000000Z");
    }

    #[test]
    fn test_format_timestamp_for_dirname_known_date() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        assert_eq!(format_timestamp_for_dirname(1704067200), "20240101-000000Z");
    }

    #[test]
    fn test_format_timestamp_for_dirname_with_time() {
        // 2024-06-15 13:30:45 UTC
        // Days from epoch to 2024-01-01: 19723
        // Days in 2024 to June 15: 31+29+31+30+31+14 = 166 (0-indexed)
        // Total days: 19723 + 166 = 19889
        // Timestamp: 19889 * 86400 + 13*3600 + 30*60 + 45 = 1718458245
        assert_eq!(format_timestamp_for_dirname(1718458245), "20240615-133045Z");
    }

    #[test]
    fn test_format_timestamp_for_dirname_leap_year() {
        // 2024-02-29 12:00:00 UTC (leap year)
        // Days from epoch to 2024-01-01: 19724
        // Days to Feb 29: 31 + 28 = 59
        // Timestamp: (19724 + 59) * 86400 + 12*3600 = 1709208000
        assert_eq!(format_timestamp_for_dirname(1709208000), "20240229-120000Z");
    }

    #[test]
    fn test_format_timestamp_for_dirname_end_of_year() {
        // 2023-12-31 23:59:59 UTC
        // Days from epoch to 2023-01-01: 19358
        // Days in 2023: 364 (Dec 31 is day 365, index 364)
        // Timestamp: (19358 + 364) * 86400 + 23*3600 + 59*60 + 59 = 1704067199
        assert_eq!(format_timestamp_for_dirname(1704067199), "20231231-235959Z");
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2000)); // Divisible by 400
        assert!(is_leap_year(2024)); // Divisible by 4, not by 100
        assert!(!is_leap_year(1900)); // Divisible by 100, not by 400
        assert!(!is_leap_year(2023)); // Not divisible by 4
    }

    #[test]
    fn test_days_to_ymd_epoch() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_known_dates() {
        // 2024-01-01 is 19723 days from epoch (1704067200 / 86400 = 19723)
        assert_eq!(days_to_ymd(19723), (2024, 1, 1));
        // 2000-01-01 is 10957 days from epoch
        assert_eq!(days_to_ymd(10957), (2000, 1, 1));
    }
}
