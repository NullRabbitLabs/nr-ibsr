//! Snapshot rotation logic for IBSR.
//!
//! Provides retention policies based on:
//! - Maximum number of files
//! - Maximum age of files

use std::path::Path;

use ibsr_clock::Clock;

use crate::writer::{Filesystem, FsError, SnapshotFile};

/// Configuration for snapshot rotation.
#[derive(Debug, Clone, Copy)]
pub struct RotationConfig {
    /// Maximum number of snapshot files to keep.
    /// Oldest files are removed first when exceeded.
    pub max_files: usize,

    /// Maximum age of snapshot files in seconds.
    /// Files older than this are removed.
    pub max_age_secs: u64,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            max_files: 3600,      // ~1 hour at 1/sec
            max_age_secs: 86400,  // 24 hours
        }
    }
}

impl RotationConfig {
    /// Create a new rotation config.
    pub fn new(max_files: usize, max_age_secs: u64) -> Self {
        Self { max_files, max_age_secs }
    }
}

/// Result of a rotation operation.
#[derive(Debug, Default)]
pub struct RotationResult {
    /// Number of files removed due to max_files limit.
    pub removed_by_count: usize,

    /// Number of files removed due to max_age limit.
    pub removed_by_age: usize,

    /// Paths of all removed files.
    pub removed_paths: Vec<std::path::PathBuf>,
}

impl RotationResult {
    /// Total number of files removed.
    pub fn total_removed(&self) -> usize {
        self.removed_by_count + self.removed_by_age
    }
}

/// Perform rotation on snapshot files in a directory.
///
/// Removes files that exceed the max_files count or are older than max_age_secs.
/// Files are processed in timestamp order (oldest first).
pub fn rotate_snapshots<F: Filesystem, C: Clock>(
    fs: &F,
    dir: &Path,
    config: &RotationConfig,
    clock: &C,
) -> Result<RotationResult, FsError> {
    let mut result = RotationResult::default();
    let now = clock.now_unix_sec();

    // Get all snapshot files, sorted by timestamp (oldest first)
    let mut files = fs.list_snapshots(dir)?;

    // First pass: remove files older than max_age
    let mut remaining_files: Vec<SnapshotFile> = Vec::new();
    for file in files {
        let age = now.saturating_sub(file.timestamp);
        if age > config.max_age_secs {
            fs.remove(&file.path)?;
            result.removed_by_age += 1;
            result.removed_paths.push(file.path);
        } else {
            remaining_files.push(file);
        }
    }

    // Second pass: remove oldest files if count exceeds max_files
    files = remaining_files;
    while files.len() > config.max_files {
        // Safe: while condition guarantees files is non-empty
        let oldest = &files[0];
        fs.remove(&oldest.path)?;
        result.removed_by_count += 1;
        result.removed_paths.push(oldest.path.clone());
        files.remove(0);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::MockFilesystem;
    use ibsr_clock::MockClock;
    use std::path::PathBuf;

    // ===========================================
    // Test Category D — Rotation Logic
    // ===========================================

    // --- RotationConfig ---

    #[test]
    fn test_rotation_config_default() {
        let config = RotationConfig::default();
        assert_eq!(config.max_files, 3600);
        assert_eq!(config.max_age_secs, 86400);
    }

    #[test]
    fn test_rotation_config_new() {
        let config = RotationConfig::new(100, 3600);
        assert_eq!(config.max_files, 100);
        assert_eq!(config.max_age_secs, 3600);
    }

    // --- Max files retention ---
    // Note: Tests use hourly filenames (snapshot_YYYYMMDDHH.jsonl)
    // Base timestamp: 2024-01-01 00:00:00 UTC = 1704067200
    // Each hour adds 3600 seconds

    #[test]
    fn test_rotate_no_files() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(1704067200); // 2024-01-01 00:00:00
        let config = RotationConfig::new(10, 86400);
        let dir = PathBuf::from("/tmp/snapshots");

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.total_removed(), 0);
        assert!(result.removed_paths.is_empty());
    }

    #[test]
    fn test_rotate_under_max_files() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(1704085200); // 2024-01-01 05:00:00
        let config = RotationConfig::new(10, 86400);
        let dir = PathBuf::from("/tmp/snapshots");

        // Add 5 hourly files (under the limit of 10)
        fs.add_file(dir.join("snapshot_2024010100.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010101.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010102.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010103.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010104.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.total_removed(), 0);
        assert_eq!(fs.list_snapshots(&dir).unwrap().len(), 5);
    }

    #[test]
    fn test_rotate_at_max_files() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(1704085200); // 2024-01-01 05:00:00
        let config = RotationConfig::new(5, 86400);
        let dir = PathBuf::from("/tmp/snapshots");

        // Add exactly 5 files (at the limit)
        fs.add_file(dir.join("snapshot_2024010100.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010101.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010102.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010103.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010104.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.total_removed(), 0);
        assert_eq!(fs.list_snapshots(&dir).unwrap().len(), 5);
    }

    #[test]
    fn test_rotate_over_max_files() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(1704085200); // 2024-01-01 05:00:00
        let config = RotationConfig::new(3, 86400);
        let dir = PathBuf::from("/tmp/snapshots");

        // Add 5 files (over the limit of 3)
        fs.add_file(dir.join("snapshot_2024010100.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010101.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010102.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010103.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010104.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_by_count, 2);
        assert_eq!(result.total_removed(), 2);

        let remaining = fs.list_snapshots(&dir).unwrap();
        assert_eq!(remaining.len(), 3);
        // Should keep the 3 newest files: 02, 03, 04
        assert_eq!(remaining[0].timestamp, 1704074400); // 02:00
        assert_eq!(remaining[1].timestamp, 1704078000); // 03:00
        assert_eq!(remaining[2].timestamp, 1704081600); // 04:00
    }

    #[test]
    fn test_rotate_removes_oldest_first() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(1704085200); // 2024-01-01 05:00:00
        let config = RotationConfig::new(2, 86400);
        let dir = PathBuf::from("/tmp/snapshots");

        fs.add_file(dir.join("snapshot_2024010100.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010103.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010101.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010104.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_by_count, 2);

        let remaining = fs.list_snapshots(&dir).unwrap();
        assert_eq!(remaining.len(), 2);
        // Should keep newest: 03 and 04
        assert_eq!(remaining[0].timestamp, 1704078000); // 03:00
        assert_eq!(remaining[1].timestamp, 1704081600); // 04:00
    }

    // --- Max age retention ---

    #[test]
    fn test_rotate_no_expired_files() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(1704078000); // 2024-01-01 03:00:00
        let config = RotationConfig::new(100, 14400); // 4 hours max age
        let dir = PathBuf::from("/tmp/snapshots");

        // All files are within max age (4 hours = 14400 sec)
        fs.add_file(dir.join("snapshot_2024010100.jsonl"), vec![]); // age = 3h
        fs.add_file(dir.join("snapshot_2024010101.jsonl"), vec![]); // age = 2h
        fs.add_file(dir.join("snapshot_2024010102.jsonl"), vec![]); // age = 1h

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_by_age, 0);
        assert_eq!(fs.list_snapshots(&dir).unwrap().len(), 3);
    }

    #[test]
    fn test_rotate_some_expired_files() {
        let fs = MockFilesystem::new();
        // Current time: 2024-01-01 10:00:00 = 1704103200
        let clock = MockClock::new(1704103200);
        let config = RotationConfig::new(100, 7200); // 2 hour max age
        let dir = PathBuf::from("/tmp/snapshots");

        // Files at different hours:
        // - 06:00 (1704088800): age = 4h > 2h, expired
        // - 07:00 (1704092400): age = 3h > 2h, expired
        // - 09:00 (1704099600): age = 1h < 2h, keep
        fs.add_file(dir.join("snapshot_2024010106.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010107.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010109.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_by_age, 2);

        let remaining = fs.list_snapshots(&dir).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].timestamp, 1704099600); // 09:00
    }

    #[test]
    fn test_rotate_all_expired_files() {
        let fs = MockFilesystem::new();
        // Current time: 2024-01-02 00:00:00 = 1704153600
        let clock = MockClock::new(1704153600);
        let config = RotationConfig::new(100, 7200); // 2 hour max age
        let dir = PathBuf::from("/tmp/snapshots");

        // All files are old (from previous day)
        fs.add_file(dir.join("snapshot_2024010100.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010101.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_by_age, 2);
        assert!(fs.list_snapshots(&dir).unwrap().is_empty());
    }

    #[test]
    fn test_rotate_exact_age_boundary() {
        let fs = MockFilesystem::new();
        // Current time: 2024-01-01 02:00:00 = 1704074400
        let clock = MockClock::new(1704074400);
        let config = RotationConfig::new(100, 7200); // 2 hour max age
        let dir = PathBuf::from("/tmp/snapshots");

        // File at 00:00 (1704067200), age = 2h exactly
        // age > max_age_secs means 7200 > 7200 is false, so not expired
        fs.add_file(dir.join("snapshot_2024010100.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_by_age, 0);
        assert_eq!(fs.list_snapshots(&dir).unwrap().len(), 1);
    }

    #[test]
    fn test_rotate_one_hour_over_age() {
        let fs = MockFilesystem::new();
        // Current time: 2024-01-01 03:00:00 = 1704078000
        let clock = MockClock::new(1704078000);
        let config = RotationConfig::new(100, 7200); // 2 hour max age
        let dir = PathBuf::from("/tmp/snapshots");

        // File at 00:00 (1704067200), age = 3h > 2h, expired
        fs.add_file(dir.join("snapshot_2024010100.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_by_age, 1);
        assert!(fs.list_snapshots(&dir).unwrap().is_empty());
    }

    // --- Combined max files + max age ---

    #[test]
    fn test_rotate_both_limits() {
        let fs = MockFilesystem::new();
        // Current time: 2024-01-01 10:00:00 = 1704103200
        let clock = MockClock::new(1704103200);
        let config = RotationConfig::new(2, 18000); // max 2 files, max age 5h
        let dir = PathBuf::from("/tmp/snapshots");

        // Files: 04:00 (age 6h, expired), 06:00 (age 4h, keep), 07:00, 08:00, 09:00
        // After age removal: 06:00, 07:00, 08:00, 09:00 (4 files)
        // After count removal: 08:00, 09:00 (2 files)
        fs.add_file(dir.join("snapshot_2024010104.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010106.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010107.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010108.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010109.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_by_age, 1);   // 04:00
        assert_eq!(result.removed_by_count, 2); // 06:00, 07:00
        assert_eq!(result.total_removed(), 3);

        let remaining = fs.list_snapshots(&dir).unwrap();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].timestamp, 1704096000); // 08:00
        assert_eq!(remaining[1].timestamp, 1704099600); // 09:00
    }

    // --- RotationResult ---

    #[test]
    fn test_rotation_result_total() {
        let result = RotationResult {
            removed_by_count: 3,
            removed_by_age: 2,
            removed_paths: vec![],
        };
        assert_eq!(result.total_removed(), 5);
    }

    #[test]
    fn test_rotation_result_paths() {
        let fs = MockFilesystem::new();
        // Current time: 2024-01-01 05:00:00
        let clock = MockClock::new(1704085200);
        let config = RotationConfig::new(1, 86400);
        let dir = PathBuf::from("/tmp/snapshots");

        fs.add_file(dir.join("snapshot_2024010100.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010101.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_paths.len(), 1);
        assert!(result.removed_paths[0].to_string_lossy().contains("2024010100"));
    }

    // --- Edge cases ---

    #[test]
    fn test_rotate_max_files_zero() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(1704085200); // 2024-01-01 05:00:00
        let config = RotationConfig::new(0, 86400);
        let dir = PathBuf::from("/tmp/snapshots");

        fs.add_file(dir.join("snapshot_2024010104.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        // All files should be removed when max_files is 0
        assert_eq!(result.removed_by_count, 1);
        assert!(fs.list_snapshots(&dir).unwrap().is_empty());
    }

    #[test]
    fn test_rotate_max_age_zero() {
        let fs = MockFilesystem::new();
        // Current time: exactly at hour 00:00 = 1704067200
        let clock = MockClock::new(1704067200);
        let config = RotationConfig::new(100, 0);
        let dir = PathBuf::from("/tmp/snapshots");

        // File at same time (age = 0, boundary)
        // age > 0 is false for age = 0
        fs.add_file(dir.join("snapshot_2024010100.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        // File at exact current time should be kept (age = 0, not > 0)
        assert_eq!(result.removed_by_age, 0);
        assert_eq!(fs.list_snapshots(&dir).unwrap().len(), 1);
    }

    #[test]
    fn test_rotate_timestamp_in_future() {
        let fs = MockFilesystem::new();
        // Current time: 2024-01-01 00:00 = 1704067200
        let clock = MockClock::new(1704067200);
        let config = RotationConfig::new(100, 3600);
        let dir = PathBuf::from("/tmp/snapshots");

        // File timestamp is in the "future" relative to clock
        // saturating_sub will make age = 0
        fs.add_file(dir.join("snapshot_2024010105.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        // Future file should be kept (age = 0)
        assert_eq!(result.removed_by_age, 0);
        assert_eq!(fs.list_snapshots(&dir).unwrap().len(), 1);
    }
}
