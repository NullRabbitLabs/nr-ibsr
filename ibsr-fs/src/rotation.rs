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

    #[test]
    fn test_rotate_no_files() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(1000);
        let config = RotationConfig::new(10, 3600);
        let dir = PathBuf::from("/tmp/snapshots");

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.total_removed(), 0);
        assert!(result.removed_paths.is_empty());
    }

    #[test]
    fn test_rotate_under_max_files() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(5000);
        let config = RotationConfig::new(10, 86400);
        let dir = PathBuf::from("/tmp/snapshots");

        // Add 5 files (under the limit of 10)
        for i in 1..=5 {
            fs.add_file(dir.join(format!("snapshot_{}.jsonl", i * 1000)), vec![]);
        }

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.total_removed(), 0);
        assert_eq!(fs.list_snapshots(&dir).unwrap().len(), 5);
    }

    #[test]
    fn test_rotate_at_max_files() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(10000);
        let config = RotationConfig::new(5, 86400);
        let dir = PathBuf::from("/tmp/snapshots");

        // Add exactly 5 files (at the limit)
        for i in 1..=5 {
            fs.add_file(dir.join(format!("snapshot_{}.jsonl", i * 1000)), vec![]);
        }

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.total_removed(), 0);
        assert_eq!(fs.list_snapshots(&dir).unwrap().len(), 5);
    }

    #[test]
    fn test_rotate_over_max_files() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(10000);
        let config = RotationConfig::new(3, 86400);
        let dir = PathBuf::from("/tmp/snapshots");

        // Add 5 files (over the limit of 3)
        for i in 1..=5 {
            fs.add_file(dir.join(format!("snapshot_{}.jsonl", i * 1000)), vec![]);
        }

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_by_count, 2);
        assert_eq!(result.total_removed(), 2);

        let remaining = fs.list_snapshots(&dir).unwrap();
        assert_eq!(remaining.len(), 3);
        // Should keep the 3 newest files
        assert_eq!(remaining[0].timestamp, 3000);
        assert_eq!(remaining[1].timestamp, 4000);
        assert_eq!(remaining[2].timestamp, 5000);
    }

    #[test]
    fn test_rotate_removes_oldest_first() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(10000);
        let config = RotationConfig::new(2, 86400);
        let dir = PathBuf::from("/tmp/snapshots");

        fs.add_file(dir.join("snapshot_1000.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_3000.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2000.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_4000.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_by_count, 2);

        let remaining = fs.list_snapshots(&dir).unwrap();
        assert_eq!(remaining.len(), 2);
        // Should keep newest: 3000 and 4000
        assert_eq!(remaining[0].timestamp, 3000);
        assert_eq!(remaining[1].timestamp, 4000);
    }

    // --- Max age retention ---

    #[test]
    fn test_rotate_no_expired_files() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(5000);
        let config = RotationConfig::new(100, 3600); // 1 hour max age
        let dir = PathBuf::from("/tmp/snapshots");

        // All files are within max age
        fs.add_file(dir.join("snapshot_4000.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_4500.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_4900.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_by_age, 0);
        assert_eq!(fs.list_snapshots(&dir).unwrap().len(), 3);
    }

    #[test]
    fn test_rotate_some_expired_files() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(10000);
        let config = RotationConfig::new(100, 3600); // 1 hour max age
        let dir = PathBuf::from("/tmp/snapshots");

        // Files at: 1000, 5000, 9000
        // At time 10000, max_age 3600:
        // - 1000: age = 9000 > 3600, expired
        // - 5000: age = 5000 > 3600, expired
        // - 9000: age = 1000 < 3600, keep
        fs.add_file(dir.join("snapshot_1000.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_5000.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_9000.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_by_age, 2);

        let remaining = fs.list_snapshots(&dir).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].timestamp, 9000);
    }

    #[test]
    fn test_rotate_all_expired_files() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(100000);
        let config = RotationConfig::new(100, 3600);
        let dir = PathBuf::from("/tmp/snapshots");

        // All files are old
        fs.add_file(dir.join("snapshot_1000.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2000.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_by_age, 2);
        assert!(fs.list_snapshots(&dir).unwrap().is_empty());
    }

    #[test]
    fn test_rotate_exact_age_boundary() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(5000);
        let config = RotationConfig::new(100, 1000); // 1000 sec max age
        let dir = PathBuf::from("/tmp/snapshots");

        // File at 4000, age = 1000, exactly at boundary
        // age > max_age_secs means 1000 > 1000 is false, so not expired
        fs.add_file(dir.join("snapshot_4000.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_by_age, 0);
        assert_eq!(fs.list_snapshots(&dir).unwrap().len(), 1);
    }

    #[test]
    fn test_rotate_one_second_over_age() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(5001);
        let config = RotationConfig::new(100, 1000);
        let dir = PathBuf::from("/tmp/snapshots");

        // File at 4000, age = 1001 > 1000, expired
        fs.add_file(dir.join("snapshot_4000.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_by_age, 1);
        assert!(fs.list_snapshots(&dir).unwrap().is_empty());
    }

    // --- Combined max files + max age ---

    #[test]
    fn test_rotate_both_limits() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(10000);
        let config = RotationConfig::new(2, 5000); // max 2 files, max age 5000 sec
        let dir = PathBuf::from("/tmp/snapshots");

        // Files: 1000 (age 9000, expired), 6000 (age 4000, keep), 7000, 8000, 9000
        // After age removal: 6000, 7000, 8000, 9000 (4 files)
        // After count removal: 8000, 9000 (2 files)
        fs.add_file(dir.join("snapshot_1000.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_6000.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_7000.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_8000.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_9000.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_by_age, 1);  // 1000
        assert_eq!(result.removed_by_count, 2); // 6000, 7000
        assert_eq!(result.total_removed(), 3);

        let remaining = fs.list_snapshots(&dir).unwrap();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].timestamp, 8000);
        assert_eq!(remaining[1].timestamp, 9000);
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
        let clock = MockClock::new(10000);
        let config = RotationConfig::new(1, 86400);
        let dir = PathBuf::from("/tmp/snapshots");

        fs.add_file(dir.join("snapshot_1000.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2000.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        assert_eq!(result.removed_paths.len(), 1);
        assert!(result.removed_paths[0].to_string_lossy().contains("1000"));
    }

    // --- Edge cases ---

    #[test]
    fn test_rotate_max_files_zero() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(10000);
        let config = RotationConfig::new(0, 86400);
        let dir = PathBuf::from("/tmp/snapshots");

        fs.add_file(dir.join("snapshot_9000.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        // All files should be removed when max_files is 0
        assert_eq!(result.removed_by_count, 1);
        assert!(fs.list_snapshots(&dir).unwrap().is_empty());
    }

    #[test]
    fn test_rotate_max_age_zero() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(10000);
        let config = RotationConfig::new(100, 0);
        let dir = PathBuf::from("/tmp/snapshots");

        // Files at 10000 (age = 0, boundary)
        // age > 0 is false for age = 0
        fs.add_file(dir.join("snapshot_10000.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        // File at exact current time should be kept (age = 0, not > 0)
        assert_eq!(result.removed_by_age, 0);
        assert_eq!(fs.list_snapshots(&dir).unwrap().len(), 1);
    }

    #[test]
    fn test_rotate_timestamp_in_future() {
        let fs = MockFilesystem::new();
        let clock = MockClock::new(1000);
        let config = RotationConfig::new(100, 500);
        let dir = PathBuf::from("/tmp/snapshots");

        // File timestamp is in the "future" relative to clock
        // saturating_sub will make age = 0
        fs.add_file(dir.join("snapshot_2000.jsonl"), vec![]);

        let result = rotate_snapshots(&fs, &dir, &config, &clock).expect("rotate");

        // Future file should be kept (age = 0)
        assert_eq!(result.removed_by_age, 0);
        assert_eq!(fs.list_snapshots(&dir).unwrap().len(), 1);
    }
}
