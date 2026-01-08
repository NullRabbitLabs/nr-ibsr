//! Snapshot writer abstraction for IBSR.
//!
//! Provides traits and implementations for writing snapshots to the filesystem
//! as hourly-chunked append-only JSONL files.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};

use ibsr_schema::Snapshot;
use thiserror::Error;

/// Errors from filesystem operations.
#[derive(Debug, Error)]
pub enum FsError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("path error: {0}")]
    Path(String),
}

/// Entry representing a snapshot file on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotFile {
    pub path: PathBuf,
    pub timestamp: u64,
}

/// Trait for filesystem operations.
/// Abstracted for testing with mock implementations.
pub trait Filesystem: Send + Sync {
    /// Write data atomically to a path (write to temp, then rename).
    fn write_atomic(&self, path: &Path, data: &[u8]) -> Result<(), FsError>;

    /// Append data to a file atomically.
    /// Creates the file if it doesn't exist.
    fn append_atomic(&self, path: &Path, data: &[u8]) -> Result<(), FsError>;

    /// Read file contents as a string.
    fn read_file(&self, path: &Path) -> Result<String, FsError>;

    /// List all snapshot files in a directory.
    fn list_snapshots(&self, dir: &Path) -> Result<Vec<SnapshotFile>, FsError>;

    /// Remove a file.
    fn remove(&self, path: &Path) -> Result<(), FsError>;

    /// Check if a path exists.
    fn exists(&self, path: &Path) -> bool;

    /// Create directory and parents if needed.
    fn create_dir_all(&self, path: &Path) -> Result<(), FsError>;
}

/// Real filesystem implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealFilesystem;

impl Filesystem for RealFilesystem {
    fn write_atomic(&self, path: &Path, data: &[u8]) -> Result<(), FsError> {
        // Create temp file path
        let temp_path = path.with_extension("tmp");

        // Write to temp file
        fs::write(&temp_path, data)?;

        // Rename to final path (atomic on most filesystems)
        fs::rename(&temp_path, path)?;

        Ok(())
    }

    fn append_atomic(&self, path: &Path, data: &[u8]) -> Result<(), FsError> {
        use std::fs::OpenOptions;
        use std::io::Write;

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Open file in append mode, creating if doesn't exist
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;

        file.write_all(data)?;
        // Use sync_data instead of sync_all - skips metadata sync, still durable for append-only
        file.sync_data()?;

        Ok(())
    }

    fn read_file(&self, path: &Path) -> Result<String, FsError> {
        Ok(fs::read_to_string(path)?)
    }

    fn list_snapshots(&self, dir: &Path) -> Result<Vec<SnapshotFile>, FsError> {
        let mut files = Vec::new();

        if !dir.exists() {
            return Ok(files);
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map_or(false, |e| e == "jsonl") {
                if let Some(ts) = parse_snapshot_filename(&path) {
                    files.push(SnapshotFile {
                        path,
                        timestamp: ts,
                    });
                }
            }
        }

        // Sort by timestamp (oldest first)
        files.sort_by_key(|f| f.timestamp);

        Ok(files)
    }

    fn remove(&self, path: &Path) -> Result<(), FsError> {
        fs::remove_file(path)?;
        Ok(())
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        fs::create_dir_all(path)?;
        Ok(())
    }
}

/// Mock filesystem for testing.
/// Cloning creates a new handle to the same underlying data.
#[derive(Debug, Clone, Default)]
pub struct MockFilesystem {
    files: std::sync::Arc<std::sync::RwLock<HashMap<PathBuf, Vec<u8>>>>,
    dirs: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<PathBuf>>>,
}

impl MockFilesystem {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get all files in the mock filesystem.
    pub fn files(&self) -> HashMap<PathBuf, Vec<u8>> {
        self.files.read().unwrap().clone()
    }

    /// Get content of a specific file.
    pub fn get_file(&self, path: &Path) -> Option<Vec<u8>> {
        self.files.read().unwrap().get(path).cloned()
    }

    /// Add a file directly (for test setup).
    pub fn add_file(&self, path: PathBuf, data: Vec<u8>) {
        self.files.write().unwrap().insert(path, data);
    }
}

impl Filesystem for MockFilesystem {
    fn write_atomic(&self, path: &Path, data: &[u8]) -> Result<(), FsError> {
        self.files.write().unwrap().insert(path.to_path_buf(), data.to_vec());
        Ok(())
    }

    fn append_atomic(&self, path: &Path, data: &[u8]) -> Result<(), FsError> {
        let mut files = self.files.write().unwrap();
        let entry = files.entry(path.to_path_buf()).or_insert_with(Vec::new);
        entry.extend_from_slice(data);
        Ok(())
    }

    fn read_file(&self, path: &Path) -> Result<String, FsError> {
        let files = self.files.read().unwrap();
        match files.get(path) {
            Some(data) => String::from_utf8(data.clone())
                .map_err(|e| FsError::Path(format!("invalid utf8: {}", e))),
            None => Err(FsError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("file not found: {}", path.display()),
            ))),
        }
    }

    fn list_snapshots(&self, dir: &Path) -> Result<Vec<SnapshotFile>, FsError> {
        let mut files = Vec::new();
        let dir_str = dir.to_string_lossy();

        for path in self.files.read().unwrap().keys() {
            let path_str = path.to_string_lossy();
            if path_str.starts_with(dir_str.as_ref())
                && path.extension().map_or(false, |e| e == "jsonl")
            {
                if let Some(ts) = parse_snapshot_filename(path) {
                    files.push(SnapshotFile {
                        path: path.clone(),
                        timestamp: ts,
                    });
                }
            }
        }

        files.sort_by_key(|f| f.timestamp);
        Ok(files)
    }

    fn remove(&self, path: &Path) -> Result<(), FsError> {
        self.files.write().unwrap().remove(path);
        Ok(())
    }

    fn exists(&self, path: &Path) -> bool {
        self.files.read().unwrap().contains_key(path)
            || self.dirs.read().unwrap().contains(path)
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        self.dirs.write().unwrap().insert(path.to_path_buf());
        Ok(())
    }
}

/// Parse hour timestamp from hourly snapshot filename.
/// Expected format: snapshot_YYYYMMDDHH.jsonl
/// Returns the Unix timestamp of the start of that hour.
pub fn parse_snapshot_filename(path: &Path) -> Option<u64> {
    let stem = path.file_stem()?.to_str()?;
    let parts: Vec<&str> = stem.split('_').collect();
    if parts.len() != 2 || parts[0] != "snapshot" {
        return None;
    }

    let hour_str = parts[1];
    // Expected format: YYYYMMDDHH (10 chars)
    if hour_str.len() != 10 {
        return None;
    }

    let year: i32 = hour_str[0..4].parse().ok()?;
    let month: u32 = hour_str[4..6].parse().ok()?;
    let day: u32 = hour_str[6..8].parse().ok()?;
    let hour: u32 = hour_str[8..10].parse().ok()?;

    // Create DateTime from parts
    Utc.with_ymd_and_hms(year, month, day, hour, 0, 0)
        .single()
        .map(|dt| dt.timestamp() as u64)
}

/// Generate hourly snapshot filename from timestamp.
/// Format: snapshot_YYYYMMDDHH.jsonl (one file per hour)
pub fn snapshot_filename(timestamp: u64) -> String {
    Utc.timestamp_opt(timestamp as i64, 0)
        .single()
        .map(|dt| format!("snapshot_{}.jsonl", dt.format("%Y%m%d%H")))
        .unwrap_or_else(|| format!("snapshot_{}.jsonl", timestamp))
}

/// Trait for writing snapshots.
pub trait SnapshotWriter: Send + Sync {
    /// Write a snapshot to disk.
    fn write(&self, snapshot: &Snapshot) -> Result<PathBuf, FsError>;
}

/// Standard snapshot writer implementation.
pub struct StandardSnapshotWriter<F: Filesystem> {
    fs: F,
    output_dir: PathBuf,
}

impl<F: Filesystem> StandardSnapshotWriter<F> {
    pub fn new(fs: F, output_dir: PathBuf) -> Self {
        Self { fs, output_dir }
    }

    /// Get the output directory.
    pub fn output_dir(&self) -> &Path {
        &self.output_dir
    }
}

impl<F: Filesystem> SnapshotWriter for StandardSnapshotWriter<F> {
    fn write(&self, snapshot: &Snapshot) -> Result<PathBuf, FsError> {
        // Ensure output directory exists
        self.fs.create_dir_all(&self.output_dir)?;

        // Generate hourly filename and path
        let filename = snapshot_filename(snapshot.ts_unix_sec);
        let path = self.output_dir.join(&filename);

        // Serialize as JSON line and append to hourly file
        let mut json = snapshot.to_json();
        json.push('\n');
        self.fs.append_atomic(&path, json.as_bytes())?;

        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibsr_schema::{BucketEntry, KeyType};
    use std::fs;
    use tempfile::tempdir;

    // ===========================================
    // Test Category D — Filesystem / Writer
    // ===========================================

    // --- Hourly naming scheme ---

    #[test]
    fn test_snapshot_filename_format() {
        // 1704067200 = 2024-01-01 00:00:00 UTC
        let filename = snapshot_filename(1704067200);
        assert_eq!(filename, "snapshot_2024010100.jsonl");
    }

    #[test]
    fn test_snapshot_filename_mid_hour() {
        // 1704069000 = 2024-01-01 00:30:00 UTC (same hour as above)
        let filename = snapshot_filename(1704069000);
        assert_eq!(filename, "snapshot_2024010100.jsonl");
    }

    #[test]
    fn test_snapshot_filename_next_hour() {
        // 1704070800 = 2024-01-01 01:00:00 UTC (next hour)
        let filename = snapshot_filename(1704070800);
        assert_eq!(filename, "snapshot_2024010101.jsonl");
    }

    #[test]
    fn test_snapshot_filename_zero() {
        // Epoch 0 = 1970-01-01 00:00:00 UTC
        let filename = snapshot_filename(0);
        assert_eq!(filename, "snapshot_1970010100.jsonl");
    }

    #[test]
    fn test_parse_snapshot_filename_valid() {
        // snapshot_2024010100.jsonl -> 2024-01-01 00:00:00 UTC = 1704067200
        let path = PathBuf::from("/tmp/snapshot_2024010100.jsonl");
        assert_eq!(parse_snapshot_filename(&path), Some(1704067200));
    }

    #[test]
    fn test_parse_snapshot_filename_zero_epoch() {
        let path = PathBuf::from("snapshot_1970010100.jsonl");
        assert_eq!(parse_snapshot_filename(&path), Some(0));
    }

    #[test]
    fn test_parse_snapshot_filename_invalid_prefix() {
        let path = PathBuf::from("data_2024010100.jsonl");
        assert_eq!(parse_snapshot_filename(&path), None);
    }

    #[test]
    fn test_parse_snapshot_filename_invalid_format() {
        let path = PathBuf::from("snapshot.jsonl");
        assert_eq!(parse_snapshot_filename(&path), None);
    }

    #[test]
    fn test_parse_snapshot_filename_old_unix_format() {
        // Old format snapshot_1234567890.jsonl should not parse (wrong length)
        let path = PathBuf::from("snapshot_1234567890.jsonl");
        assert_eq!(parse_snapshot_filename(&path), None);
    }

    #[test]
    fn test_parse_snapshot_filename_non_numeric() {
        let path = PathBuf::from("snapshot_abcdefghij.jsonl");
        assert_eq!(parse_snapshot_filename(&path), None);
    }

    #[test]
    fn test_parse_snapshot_filename_wrong_extension() {
        // parse_snapshot_filename doesn't check extension, that's done in list_snapshots
        let path = PathBuf::from("snapshot_2024010100.json");
        assert_eq!(parse_snapshot_filename(&path), Some(1704067200));
    }

    #[test]
    fn test_parse_snapshot_filename_invalid_date() {
        // Invalid month 13
        let path = PathBuf::from("snapshot_2024130100.jsonl");
        assert_eq!(parse_snapshot_filename(&path), None);
    }

    // --- Atomic write (temp + rename) ---

    #[test]
    fn test_mock_write_atomic() {
        let fs = MockFilesystem::new();
        let path = PathBuf::from("/tmp/test.jsonl");

        fs.write_atomic(&path, b"test data").expect("write");

        assert!(fs.exists(&path));
        assert_eq!(fs.get_file(&path), Some(b"test data".to_vec()));
    }

    #[test]
    fn test_mock_write_atomic_overwrites() {
        let fs = MockFilesystem::new();
        let path = PathBuf::from("/tmp/test.jsonl");

        fs.write_atomic(&path, b"first").expect("write");
        fs.write_atomic(&path, b"second").expect("write");

        assert_eq!(fs.get_file(&path), Some(b"second".to_vec()));
    }

    // --- Append atomic ---

    #[test]
    fn test_mock_append_atomic_creates_file() {
        let fs = MockFilesystem::new();
        let path = PathBuf::from("/tmp/status.jsonl");

        fs.append_atomic(&path, b"line1\n").expect("append");

        assert!(fs.exists(&path));
        assert_eq!(fs.get_file(&path), Some(b"line1\n".to_vec()));
    }

    #[test]
    fn test_mock_append_atomic_appends() {
        let fs = MockFilesystem::new();
        let path = PathBuf::from("/tmp/status.jsonl");

        fs.append_atomic(&path, b"line1\n").expect("append 1");
        fs.append_atomic(&path, b"line2\n").expect("append 2");
        fs.append_atomic(&path, b"line3\n").expect("append 3");

        assert_eq!(
            fs.get_file(&path),
            Some(b"line1\nline2\nline3\n".to_vec())
        );
    }

    #[test]
    fn test_mock_append_atomic_to_existing() {
        let fs = MockFilesystem::new();
        let path = PathBuf::from("/tmp/status.jsonl");

        // Pre-populate file
        fs.add_file(path.clone(), b"existing\n".to_vec());

        fs.append_atomic(&path, b"new\n").expect("append");

        assert_eq!(fs.get_file(&path), Some(b"existing\nnew\n".to_vec()));
    }

    // --- List snapshots ---

    #[test]
    fn test_mock_list_snapshots_empty() {
        let fs = MockFilesystem::new();
        let dir = PathBuf::from("/tmp/snapshots");

        let files = fs.list_snapshots(&dir).expect("list");

        assert!(files.is_empty());
    }

    #[test]
    fn test_mock_list_snapshots_with_files() {
        let fs = MockFilesystem::new();
        let dir = PathBuf::from("/tmp/snapshots");

        // 2024-01-01 00:00 = 1704067200, 01:00 = 1704070800, 02:00 = 1704074400
        fs.add_file(dir.join("snapshot_2024010100.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010102.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010101.jsonl"), vec![]);

        let files = fs.list_snapshots(&dir).expect("list");

        assert_eq!(files.len(), 3);
        // Should be sorted by timestamp
        assert_eq!(files[0].timestamp, 1704067200); // 00:00
        assert_eq!(files[1].timestamp, 1704070800); // 01:00
        assert_eq!(files[2].timestamp, 1704074400); // 02:00
    }

    #[test]
    fn test_mock_list_snapshots_ignores_non_jsonl() {
        let fs = MockFilesystem::new();
        let dir = PathBuf::from("/tmp/snapshots");

        fs.add_file(dir.join("snapshot_2024010100.jsonl"), vec![]);
        fs.add_file(dir.join("snapshot_2024010101.json"), vec![]);  // wrong extension
        fs.add_file(dir.join("other.txt"), vec![]);

        let files = fs.list_snapshots(&dir).expect("list");

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].timestamp, 1704067200);
    }

    #[test]
    fn test_mock_list_snapshots_ignores_invalid_names() {
        let fs = MockFilesystem::new();
        let dir = PathBuf::from("/tmp/snapshots");

        fs.add_file(dir.join("snapshot_2024010100.jsonl"), vec![]);
        fs.add_file(dir.join("data_2024010101.jsonl"), vec![]);  // wrong prefix
        fs.add_file(dir.join("snapshot_abcdefghij.jsonl"), vec![]);  // not numeric

        let files = fs.list_snapshots(&dir).expect("list");

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].timestamp, 1704067200);
    }

    // --- Remove ---

    #[test]
    fn test_mock_remove() {
        let fs = MockFilesystem::new();
        let path = PathBuf::from("/tmp/test.jsonl");

        fs.add_file(path.clone(), vec![]);
        assert!(fs.exists(&path));

        fs.remove(&path).expect("remove");
        assert!(!fs.exists(&path));
    }

    #[test]
    fn test_mock_remove_nonexistent() {
        let fs = MockFilesystem::new();
        let path = PathBuf::from("/tmp/nonexistent.jsonl");

        // Mock doesn't error on removing nonexistent files
        fs.remove(&path).expect("remove");
    }

    // --- Exists ---

    #[test]
    fn test_mock_exists() {
        let fs = MockFilesystem::new();
        let path = PathBuf::from("/tmp/test.jsonl");

        assert!(!fs.exists(&path));
        fs.add_file(path.clone(), vec![]);
        assert!(fs.exists(&path));
    }

    // --- Read file ---

    #[test]
    fn test_mock_read_file() {
        let fs = MockFilesystem::new();
        let path = PathBuf::from("/tmp/test.txt");

        fs.add_file(path.clone(), b"hello world".to_vec());

        let content = fs.read_file(&path).expect("read");
        assert_eq!(content, "hello world");
    }

    #[test]
    fn test_mock_read_file_not_found() {
        let fs = MockFilesystem::new();
        let path = PathBuf::from("/tmp/nonexistent.txt");

        let result = fs.read_file(&path);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, FsError::Io(_)));
    }

    #[test]
    fn test_mock_read_file_multiline() {
        let fs = MockFilesystem::new();
        let path = PathBuf::from("/tmp/multiline.txt");

        let content = "line1\nline2\nline3";
        fs.add_file(path.clone(), content.as_bytes().to_vec());

        let result = fs.read_file(&path).expect("read");
        assert_eq!(result, content);
    }

    #[test]
    fn test_mock_read_file_empty() {
        let fs = MockFilesystem::new();
        let path = PathBuf::from("/tmp/empty.txt");

        fs.add_file(path.clone(), vec![]);

        let content = fs.read_file(&path).expect("read");
        assert_eq!(content, "");
    }

    // --- SnapshotWriter ---

    #[test]
    fn test_snapshot_writer_creates_file() {
        let fs = MockFilesystem::new();
        let writer = StandardSnapshotWriter::new(fs, PathBuf::from("/tmp/snapshots"));

        // 1704067200 = 2024-01-01 00:00:00 UTC
        let snapshot = Snapshot::new(1704067200, &[8899], vec![], 60, 1704067200, 1704067200);
        let path = writer.write(&snapshot).expect("write");

        assert_eq!(path, PathBuf::from("/tmp/snapshots/snapshot_2024010100.jsonl"));
    }

    #[test]
    fn test_snapshot_writer_writes_json() {
        let fs = MockFilesystem::new();
        let writer = StandardSnapshotWriter::new(fs, PathBuf::from("/tmp/snapshots"));

        let bucket = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: 0x0A000001,
            dst_port: Some(8899),
            syn: 100,
            ack: 200,
            handshake_ack: 95,
            rst: 5,
            packets: 305,
            bytes: 45000,
        };
        // 1704067200 = 2024-01-01 00:00:00 UTC
        let snapshot = Snapshot::new(1704067200, &[8899], vec![bucket], 60, 1704067200, 1704067200);
        writer.write(&snapshot).expect("write");

        // Access the underlying filesystem to check content
        let path = PathBuf::from("/tmp/snapshots/snapshot_2024010100.jsonl");
        let fs_ref = &writer;
        let content = fs_ref.fs.get_file(&path).expect("file exists");
        let json = String::from_utf8(content).expect("valid utf8");

        // Content should end with newline (JSONL format)
        assert!(json.ends_with('\n'));

        // Verify it's valid JSON and matches (trim trailing newline)
        let restored = Snapshot::from_json(json.trim()).expect("valid snapshot");
        assert_eq!(restored, snapshot);
    }

    #[test]
    fn test_snapshot_writer_output_dir() {
        let fs = MockFilesystem::new();
        let writer = StandardSnapshotWriter::new(fs, PathBuf::from("/var/lib/ibsr/snapshots"));

        assert_eq!(writer.output_dir(), Path::new("/var/lib/ibsr/snapshots"));
    }

    #[test]
    fn test_snapshot_writer_multiple_writes_same_hour() {
        let fs = MockFilesystem::new();
        let writer = StandardSnapshotWriter::new(fs, PathBuf::from("/tmp/snapshots"));

        // All timestamps in 2024-01-01 00:xx:xx UTC (same hour)
        let snapshot1 = Snapshot::new(1704067200, &[8899], vec![], 60, 1704067200, 1704067200); // 00:00:00
        let snapshot2 = Snapshot::new(1704068000, &[8899], vec![], 60, 1704067200, 1704067200); // 00:13:20
        let snapshot3 = Snapshot::new(1704069000, &[8899], vec![], 60, 1704067200, 1704067200); // 00:30:00

        writer.write(&snapshot1).expect("write 1");
        writer.write(&snapshot2).expect("write 2");
        writer.write(&snapshot3).expect("write 3");

        // All should go to same hourly file (append behavior)
        let files = writer.fs.list_snapshots(writer.output_dir()).expect("list");
        assert_eq!(files.len(), 1);

        // Verify file contains 3 JSON lines
        let path = PathBuf::from("/tmp/snapshots/snapshot_2024010100.jsonl");
        let content = writer.fs.get_file(&path).expect("file");
        let content_str = String::from_utf8(content).expect("utf8");
        let lines: Vec<&str> = content_str.lines().collect();
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn test_snapshot_writer_multiple_writes_different_hours() {
        let fs = MockFilesystem::new();
        let writer = StandardSnapshotWriter::new(fs, PathBuf::from("/tmp/snapshots"));

        // Different hours
        let snapshot1 = Snapshot::new(1704067200, &[8899], vec![], 60, 1704067200, 1704067200); // 2024-01-01 00:00
        let snapshot2 = Snapshot::new(1704070800, &[8899], vec![], 60, 1704067200, 1704067200); // 2024-01-01 01:00
        let snapshot3 = Snapshot::new(1704074400, &[8899], vec![], 60, 1704067200, 1704067200); // 2024-01-01 02:00

        writer.write(&snapshot1).expect("write 1");
        writer.write(&snapshot2).expect("write 2");
        writer.write(&snapshot3).expect("write 3");

        // Should create 3 separate hourly files
        let files = writer.fs.list_snapshots(writer.output_dir()).expect("list");
        assert_eq!(files.len(), 3);
    }

    // --- MockFilesystem additional tests ---

    #[test]
    fn test_mock_filesystem_files() {
        let fs = MockFilesystem::new();
        fs.add_file(PathBuf::from("/a"), vec![1]);
        fs.add_file(PathBuf::from("/b"), vec![2]);

        let files = fs.files();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_mock_create_dir_all() {
        let fs = MockFilesystem::new();
        // Should succeed (no-op for mock)
        fs.create_dir_all(&PathBuf::from("/tmp/nested/dir")).expect("create");
    }

    // --- Filesystem trait object ---

    #[test]
    fn test_filesystem_trait_object() {
        let fs: Box<dyn Filesystem> = Box::new(MockFilesystem::new());
        let path = PathBuf::from("/tmp/test.jsonl");

        fs.write_atomic(&path, b"data").expect("write");
        assert!(fs.exists(&path));
    }

    // ===========================================
    // RealFilesystem Tests (using tempdir)
    // ===========================================

    #[test]
    fn test_real_fs_write_atomic() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;
        let path = dir.path().join("test.jsonl");

        fs.write_atomic(&path, b"test data").expect("write");

        assert!(path.exists());
        assert_eq!(fs::read(&path).unwrap(), b"test data");
    }

    #[test]
    fn test_real_fs_write_atomic_overwrites() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;
        let path = dir.path().join("test.jsonl");

        fs.write_atomic(&path, b"first").expect("write 1");
        fs.write_atomic(&path, b"second").expect("write 2");

        assert_eq!(fs::read(&path).unwrap(), b"second");
    }

    #[test]
    fn test_real_fs_append_atomic_creates_file() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;
        let path = dir.path().join("status.jsonl");

        fs.append_atomic(&path, b"line1\n").expect("append");

        assert!(path.exists());
        assert_eq!(fs::read(&path).unwrap(), b"line1\n");
    }

    #[test]
    fn test_real_fs_append_atomic_appends() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;
        let path = dir.path().join("status.jsonl");

        fs.append_atomic(&path, b"line1\n").expect("append 1");
        fs.append_atomic(&path, b"line2\n").expect("append 2");
        fs.append_atomic(&path, b"line3\n").expect("append 3");

        assert_eq!(fs::read(&path).unwrap(), b"line1\nline2\nline3\n");
    }

    #[test]
    fn test_real_fs_append_atomic_to_existing() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;
        let path = dir.path().join("status.jsonl");

        // Pre-populate file
        fs::write(&path, b"existing\n").expect("write");

        fs.append_atomic(&path, b"new\n").expect("append");

        assert_eq!(fs::read(&path).unwrap(), b"existing\nnew\n");
    }

    #[test]
    fn test_real_fs_append_atomic_creates_parent_dirs() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;
        let path = dir.path().join("nested").join("dir").join("status.jsonl");

        fs.append_atomic(&path, b"data\n").expect("append");

        assert!(path.exists());
        assert_eq!(fs::read(&path).unwrap(), b"data\n");
    }

    #[test]
    fn test_real_fs_exists() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;
        let path = dir.path().join("test.jsonl");

        assert!(!fs.exists(&path));
        fs::write(&path, b"").expect("create file");
        assert!(fs.exists(&path));
    }

    #[test]
    fn test_real_fs_remove() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;
        let path = dir.path().join("test.jsonl");

        fs::write(&path, b"data").expect("create file");
        assert!(path.exists());

        fs.remove(&path).expect("remove");
        assert!(!path.exists());
    }

    #[test]
    fn test_real_fs_create_dir_all() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;
        let nested = dir.path().join("a").join("b").join("c");

        assert!(!nested.exists());
        fs.create_dir_all(&nested).expect("create dirs");
        assert!(nested.exists());
    }

    #[test]
    fn test_real_fs_list_snapshots_empty_dir() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;

        let files = fs.list_snapshots(dir.path()).expect("list");
        assert!(files.is_empty());
    }

    #[test]
    fn test_real_fs_list_snapshots_nonexistent_dir() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;
        let nonexistent = dir.path().join("does_not_exist");

        let files = fs.list_snapshots(&nonexistent).expect("list");
        assert!(files.is_empty());
    }

    #[test]
    fn test_real_fs_list_snapshots_with_files() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;

        // 2024-01-01 00:00 = 1704067200, 01:00 = 1704070800, 02:00 = 1704074400
        fs::write(dir.path().join("snapshot_2024010100.jsonl"), b"").expect("write 1");
        fs::write(dir.path().join("snapshot_2024010102.jsonl"), b"").expect("write 2");
        fs::write(dir.path().join("snapshot_2024010101.jsonl"), b"").expect("write 3");

        let files = fs.list_snapshots(dir.path()).expect("list");

        assert_eq!(files.len(), 3);
        // Should be sorted by timestamp
        assert_eq!(files[0].timestamp, 1704067200); // 00:00
        assert_eq!(files[1].timestamp, 1704070800); // 01:00
        assert_eq!(files[2].timestamp, 1704074400); // 02:00
    }

    #[test]
    fn test_real_fs_list_snapshots_ignores_non_jsonl() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;

        fs::write(dir.path().join("snapshot_2024010100.jsonl"), b"").expect("write 1");
        fs::write(dir.path().join("snapshot_2024010101.json"), b"").expect("write 2");
        fs::write(dir.path().join("other.txt"), b"").expect("write 3");

        let files = fs.list_snapshots(dir.path()).expect("list");

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].timestamp, 1704067200);
    }

    #[test]
    fn test_real_fs_list_snapshots_ignores_invalid_names() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;

        fs::write(dir.path().join("snapshot_2024010100.jsonl"), b"").expect("write 1");
        fs::write(dir.path().join("data_2024010101.jsonl"), b"").expect("write 2");
        fs::write(dir.path().join("snapshot_abcdefghij.jsonl"), b"").expect("write 3");

        let files = fs.list_snapshots(dir.path()).expect("list");

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].timestamp, 1704067200);
    }

    #[test]
    fn test_real_fs_read_file() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;
        let path = dir.path().join("test.txt");

        fs::write(&path, b"hello world").expect("write");

        let content = fs.read_file(&path).expect("read");
        assert_eq!(content, "hello world");
    }

    #[test]
    fn test_real_fs_read_file_not_found() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;
        let path = dir.path().join("nonexistent.txt");

        let result = fs.read_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_real_fs_read_file_multiline() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;
        let path = dir.path().join("multiline.txt");

        let content = "line1\nline2\nline3";
        fs::write(&path, content).expect("write");

        let result = fs.read_file(&path).expect("read");
        assert_eq!(result, content);
    }

    #[test]
    fn test_real_snapshot_writer() {
        let dir = tempdir().expect("create temp dir");
        let fs = RealFilesystem;
        let writer = StandardSnapshotWriter::new(fs, dir.path().to_path_buf());

        let bucket = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: 0x0A000001,
            dst_port: Some(8899),
            syn: 100,
            ack: 200,
            handshake_ack: 95,
            rst: 5,
            packets: 305,
            bytes: 45000,
        };
        // 1704067200 = 2024-01-01 00:00:00 UTC
        let snapshot = Snapshot::new(1704067200, &[8899], vec![bucket], 60, 1704067200, 1704067200);
        let path = writer.write(&snapshot).expect("write");

        assert!(path.exists());
        let content = fs::read_to_string(&path).expect("read");
        // Content is JSONL format (ends with newline), trim for parsing
        let restored = Snapshot::from_json(content.trim()).expect("parse");
        assert_eq!(restored, snapshot);
    }

    #[test]
    fn test_real_snapshot_writer_creates_output_dir() {
        let dir = tempdir().expect("create temp dir");
        let output_dir = dir.path().join("nested").join("output");
        let fs = RealFilesystem;
        let writer = StandardSnapshotWriter::new(fs, output_dir.clone());

        assert!(!output_dir.exists());

        // 1704067200 = 2024-01-01 00:00:00 UTC
        let snapshot = Snapshot::new(1704067200, &[8899], vec![], 60, 1704067200, 1704067200);
        writer.write(&snapshot).expect("write");

        assert!(output_dir.exists());
    }
}
