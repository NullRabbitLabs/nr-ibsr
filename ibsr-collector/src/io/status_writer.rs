//! Status writer for append-only status.jsonl output.
//!
//! Writes periodic heartbeat lines to track collector progress:
//! - One JSON line per collection cycle
//! - Append-only (survives restarts)
//! - Machine-readable status for monitoring

use std::path::{Path, PathBuf};

use ibsr_fs::{Filesystem, FsError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from status writing.
#[derive(Debug, Error)]
pub enum StatusWriterError {
    #[error("failed to append status: {0}")]
    Append(#[source] FsError),
}

/// A single status line written per collection cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusLine {
    /// Unix epoch seconds when this cycle completed.
    pub timestamp: u64,

    /// Collection cycle number (1-indexed).
    pub cycle: u64,

    /// Unique IPs collected in this cycle.
    pub ips_collected: u64,

    /// Cumulative snapshots written so far.
    pub snapshots_written: u64,
}

impl StatusLine {
    /// Create a new status line.
    pub fn new(timestamp: u64, cycle: u64, ips_collected: u64, snapshots_written: u64) -> Self {
        Self {
            timestamp,
            cycle,
            ips_collected,
            snapshots_written,
        }
    }

    /// Serialize to JSON line (no trailing newline).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("StatusLine serialization should never fail")
    }

    /// Parse from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Writer for append-only status.jsonl file.
pub struct StatusWriter<F: Filesystem> {
    fs: F,
    path: PathBuf,
}

impl<F: Filesystem> StatusWriter<F> {
    /// Create a new status writer.
    pub fn new(fs: F, path: PathBuf) -> Self {
        Self { fs, path }
    }

    /// Get the path to the status file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a status line to the file.
    ///
    /// Each line is a JSON object followed by a newline.
    /// The file is created if it doesn't exist.
    pub fn append(&self, status: &StatusLine) -> Result<(), StatusWriterError> {
        let line = format!("{}\n", status.to_json());
        self.fs
            .append_atomic(&self.path, line.as_bytes())
            .map_err(StatusWriterError::Append)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibsr_fs::MockFilesystem;

    // =========================================
    // StatusLine Tests
    // =========================================

    #[test]
    fn test_status_line_new() {
        let line = StatusLine::new(1704067200, 1, 42, 1);
        assert_eq!(line.timestamp, 1704067200);
        assert_eq!(line.cycle, 1);
        assert_eq!(line.ips_collected, 42);
        assert_eq!(line.snapshots_written, 1);
    }

    #[test]
    fn test_status_line_to_json() {
        let line = StatusLine::new(1704067200, 1, 42, 1);
        let json = line.to_json();
        assert!(json.contains("\"timestamp\":1704067200"));
        assert!(json.contains("\"cycle\":1"));
        assert!(json.contains("\"ips_collected\":42"));
        assert!(json.contains("\"snapshots_written\":1"));
    }

    #[test]
    fn test_status_line_from_json() {
        let json = r#"{"timestamp":1704067200,"cycle":1,"ips_collected":42,"snapshots_written":1}"#;
        let line = StatusLine::from_json(json).expect("parse");
        assert_eq!(line.timestamp, 1704067200);
        assert_eq!(line.cycle, 1);
        assert_eq!(line.ips_collected, 42);
        assert_eq!(line.snapshots_written, 1);
    }

    #[test]
    fn test_status_line_roundtrip() {
        let original = StatusLine::new(1704067200, 5, 100, 10);
        let json = original.to_json();
        let parsed = StatusLine::from_json(&json).expect("parse");
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_status_line_invalid_json() {
        let result = StatusLine::from_json("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_status_line_missing_field() {
        let json = r#"{"timestamp":1000,"cycle":1}"#;
        let result = StatusLine::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_status_line_clone() {
        let line = StatusLine::new(1000, 1, 10, 1);
        let cloned = line.clone();
        assert_eq!(line, cloned);
    }

    #[test]
    fn test_status_line_debug() {
        let line = StatusLine::new(1000, 1, 10, 1);
        let debug = format!("{:?}", line);
        assert!(debug.contains("timestamp: 1000"));
        assert!(debug.contains("cycle: 1"));
    }

    #[test]
    fn test_status_line_zero_values() {
        let line = StatusLine::new(0, 0, 0, 0);
        let json = line.to_json();
        let parsed = StatusLine::from_json(&json).expect("parse");
        assert_eq!(parsed.timestamp, 0);
        assert_eq!(parsed.cycle, 0);
        assert_eq!(parsed.ips_collected, 0);
        assert_eq!(parsed.snapshots_written, 0);
    }

    #[test]
    fn test_status_line_large_values() {
        let line = StatusLine::new(u64::MAX, u64::MAX, u64::MAX, u64::MAX);
        let json = line.to_json();
        let parsed = StatusLine::from_json(&json).expect("parse");
        assert_eq!(parsed.timestamp, u64::MAX);
    }

    // =========================================
    // StatusWriter Tests (using MockFilesystem)
    // =========================================

    fn get_content(fs: &MockFilesystem, path: &Path) -> Option<String> {
        fs.get_file(path)
            .map(|data| String::from_utf8_lossy(&data).to_string())
    }

    #[test]
    fn test_status_writer_creates_file() {
        let fs = MockFilesystem::new();
        let path = PathBuf::from("/tmp/status.jsonl");
        let writer = StatusWriter::new(fs.clone(), path.clone());

        let status = StatusLine::new(1000, 1, 42, 1);
        writer.append(&status).expect("append");

        let content = get_content(&fs, &path);
        assert!(content.is_some());
        assert!(content.unwrap().contains("\"timestamp\":1000"));
    }

    #[test]
    fn test_status_writer_appends() {
        let fs = MockFilesystem::new();
        let path = PathBuf::from("/tmp/status.jsonl");
        let writer = StatusWriter::new(fs.clone(), path.clone());

        let status1 = StatusLine::new(1000, 1, 10, 1);
        let status2 = StatusLine::new(2000, 2, 20, 2);
        let status3 = StatusLine::new(3000, 3, 30, 3);

        writer.append(&status1).expect("append 1");
        writer.append(&status2).expect("append 2");
        writer.append(&status3).expect("append 3");

        let content = get_content(&fs, &path).expect("content");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);

        // Verify each line
        let line1 = StatusLine::from_json(lines[0]).expect("parse line 1");
        assert_eq!(line1.cycle, 1);

        let line2 = StatusLine::from_json(lines[1]).expect("parse line 2");
        assert_eq!(line2.cycle, 2);

        let line3 = StatusLine::from_json(lines[2]).expect("parse line 3");
        assert_eq!(line3.cycle, 3);
    }

    #[test]
    fn test_status_writer_path() {
        let fs = MockFilesystem::new();
        let path = PathBuf::from("/var/lib/ibsr/status.jsonl");
        let writer = StatusWriter::new(fs, path.clone());

        assert_eq!(writer.path(), path.as_path());
    }

    #[test]
    fn test_status_writer_survives_restart() {
        let fs = MockFilesystem::new();
        let path = PathBuf::from("/tmp/status.jsonl");

        // First "session" - write 2 lines
        {
            let writer = StatusWriter::new(fs.clone(), path.clone());
            writer
                .append(&StatusLine::new(1000, 1, 10, 1))
                .expect("append");
            writer
                .append(&StatusLine::new(2000, 2, 20, 2))
                .expect("append");
        }

        // Second "session" - write 2 more lines (simulating restart)
        {
            let writer = StatusWriter::new(fs.clone(), path.clone());
            writer
                .append(&StatusLine::new(3000, 3, 30, 3))
                .expect("append");
            writer
                .append(&StatusLine::new(4000, 4, 40, 4))
                .expect("append");
        }

        // Verify all 4 lines exist
        let content = get_content(&fs, &path).expect("content");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 4);

        let last_line = StatusLine::from_json(lines[3]).expect("parse");
        assert_eq!(last_line.cycle, 4);
    }

    #[test]
    fn test_status_writer_error_debug() {
        let err = StatusWriterError::Append(FsError::Path("test".to_string()));
        let debug = format!("{:?}", err);
        assert!(debug.contains("Append"));
    }

    #[test]
    fn test_status_line_format_matches_spec() {
        // Verify output matches the spec in the plan
        let line = StatusLine::new(1704067200, 1, 42, 1);
        let json = line.to_json();

        // Should be compact JSON (no extra whitespace)
        assert!(!json.contains('\n'));
        assert!(!json.contains("  "));

        // Should contain all required fields
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
    }
}
