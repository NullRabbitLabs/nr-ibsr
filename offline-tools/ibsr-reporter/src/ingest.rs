//! Snapshot ingestion and ordering.

use crate::types::WindowBounds;
use ibsr_schema::Snapshot;
use std::path::Path;

/// Errors from snapshot ingestion.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("no snapshots found")]
    NoSnapshots,
    #[error("failed to read file {path}: {source}")]
    ReadError {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse snapshot from {path}: {source}")]
    ParseError {
        path: String,
        #[source]
        source: ibsr_schema::SnapshotError,
    },
}

/// A stream of snapshots ordered by timestamp.
#[derive(Debug, Clone)]
pub struct SnapshotStream {
    snapshots: Vec<Snapshot>,
    bounds: WindowBounds,
}

impl SnapshotStream {
    /// Create a snapshot stream from an already-ordered list.
    /// Snapshots must be sorted by timestamp (ascending).
    pub fn from_ordered(snapshots: Vec<Snapshot>) -> Result<Self, IngestError> {
        if snapshots.is_empty() {
            return Err(IngestError::NoSnapshots);
        }

        let start_ts = snapshots.first().unwrap().ts_unix_sec;
        let end_ts = snapshots.last().unwrap().ts_unix_sec;
        let bounds = WindowBounds::new(start_ts, end_ts);

        Ok(Self { snapshots, bounds })
    }

    /// Create a snapshot stream from unordered snapshots (will sort by timestamp).
    pub fn from_unordered(mut snapshots: Vec<Snapshot>) -> Result<Self, IngestError> {
        if snapshots.is_empty() {
            return Err(IngestError::NoSnapshots);
        }

        // Sort by timestamp ascending
        snapshots.sort_by_key(|s| s.ts_unix_sec);

        Self::from_ordered(snapshots)
    }

    /// Get the window bounds (min/max timestamp).
    pub fn bounds(&self) -> WindowBounds {
        self.bounds
    }

    /// Get all snapshots in order.
    pub fn snapshots(&self) -> &[Snapshot] {
        &self.snapshots
    }

    /// Get number of snapshots.
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// Filter snapshots to those within a time window.
    /// Returns snapshots where `ts_unix_sec >= start && ts_unix_sec <= end`.
    pub fn filter_window(&self, start: u64, end: u64) -> Vec<&Snapshot> {
        self.snapshots
            .iter()
            .filter(|s| s.ts_unix_sec >= start && s.ts_unix_sec <= end)
            .collect()
    }

    /// Iterate over snapshots.
    pub fn iter(&self) -> impl Iterator<Item = &Snapshot> {
        self.snapshots.iter()
    }

    /// Infer destination ports from all snapshots.
    ///
    /// Returns the union of:
    /// - dst_ports from snapshot headers
    /// - dst_port values from bucket entries
    ///
    /// Result is sorted and deduplicated.
    pub fn inferred_dst_ports(&self) -> Vec<u16> {
        use std::collections::BTreeSet;

        let mut ports = BTreeSet::new();

        for snapshot in &self.snapshots {
            // Add ports from snapshot header
            for &port in &snapshot.dst_ports {
                ports.insert(port);
            }

            // Add ports from bucket entries
            for bucket in &snapshot.buckets {
                if let Some(port) = bucket.dst_port {
                    ports.insert(port);
                }
            }
        }

        ports.into_iter().collect()
    }

    /// Infer run_id from snapshots.
    ///
    /// Returns the run_id from the first snapshot, or None if no snapshots.
    pub fn inferred_run_id(&self) -> Option<u64> {
        self.snapshots.first().map(|s| s.run_id)
    }

    /// Get the schema version range (min, max) from all snapshots.
    pub fn schema_version_range(&self) -> (u32, u32) {
        if self.snapshots.is_empty() {
            return (0, 0);
        }

        let min = self.snapshots.iter().map(|s| s.version).min().unwrap_or(0);
        let max = self.snapshots.iter().map(|s| s.version).max().unwrap_or(0);

        (min, max)
    }
}

/// Parse a single snapshot from JSON string.
pub fn parse_snapshot(json: &str) -> Result<Snapshot, ibsr_schema::SnapshotError> {
    Snapshot::from_json(json)
}

/// Parse snapshots from a list of (filename, content) pairs.
/// Each file may contain multiple JSON lines (JSONL format).
/// Returns successfully parsed snapshots, skipping malformed lines.
/// If warn_fn is provided, it will be called for each skipped line.
pub fn parse_snapshots_lenient<F>(
    files: Vec<(String, String)>,
    mut warn_fn: Option<F>,
) -> Vec<Snapshot>
where
    F: FnMut(&str, &str),
{
    let mut snapshots = Vec::new();

    for (filename, content) in files {
        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match parse_snapshot(line) {
                Ok(snapshot) => snapshots.push(snapshot),
                Err(e) => {
                    if let Some(ref mut warn) = warn_fn {
                        let location = format!("{}:{}", filename, line_num + 1);
                        warn(&location, &e.to_string());
                    }
                }
            }
        }
    }

    snapshots
}

/// Derive window bounds from snapshots (min and max timestamp).
pub fn derive_window_bounds(snapshots: &[Snapshot]) -> Option<WindowBounds> {
    if snapshots.is_empty() {
        return None;
    }

    let min_ts = snapshots.iter().map(|s| s.ts_unix_sec).min().unwrap();
    let max_ts = snapshots.iter().map(|s| s.ts_unix_sec).max().unwrap();

    Some(WindowBounds::new(min_ts, max_ts))
}

/// Read snapshot files from a directory (using std::fs).
///
/// Returns list of (filename, content) pairs for successfully read files.
pub fn read_snapshot_files_from_dir(dir: &Path) -> Result<Vec<(String, String)>, IngestError> {
    use std::fs;

    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();

    let entries = fs::read_dir(dir).map_err(|e| IngestError::ReadError {
        path: dir.display().to_string(),
        source: e,
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| IngestError::ReadError {
            path: dir.display().to_string(),
            source: e,
        })?;

        let path = entry.path();
        if path.extension().map_or(false, |e| e == "jsonl") {
            let content = fs::read_to_string(&path).map_err(|e| IngestError::ReadError {
                path: path.display().to_string(),
                source: e,
            })?;
            files.push((path.display().to_string(), content));
        }
    }

    Ok(files)
}

/// Load and parse snapshots from a directory.
///
/// This is a convenience function that reads files and parses them.
/// Malformed files are skipped with warnings.
pub fn load_snapshots_from_dir<W>(
    dir: &Path,
    warn_fn: Option<W>,
) -> Result<SnapshotStream, IngestError>
where
    W: FnMut(&str, &str),
{
    let files = read_snapshot_files_from_dir(dir)?;
    let snapshots = parse_snapshots_lenient(files, warn_fn);
    SnapshotStream::from_unordered(snapshots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibsr_schema::{BucketEntry, KeyType};

    // ===========================================
    // Category A — Snapshot Ingestion Tests
    // ===========================================

    fn make_snapshot(ts: u64, dst_ports: &[u16], buckets: Vec<BucketEntry>) -> Snapshot {
        Snapshot::new(ts, dst_ports, buckets, 60, ts, ts)
    }

    fn make_bucket(key_value: u32, syn: u32, ack: u32) -> BucketEntry {
        BucketEntry {
            key_type: KeyType::SrcIp,
            key_value,
            dst_port: Some(8080),
            syn,
            ack,
            handshake_ack: ack, // Default to ack for legitimate traffic
            rst: 0,
            packets: syn + ack,
            bytes: (syn + ack) as u64 * 100,
        }
    }

    // -------------------------------------------
    // Parse single snapshot
    // -------------------------------------------

    #[test]
    fn test_parse_snapshot_valid_json() {
        let json = r#"{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1000,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#;
        let snapshot = parse_snapshot(json).unwrap();
        assert_eq!(snapshot.ts_unix_sec, 1000);
        assert_eq!(snapshot.dst_ports, vec![8080]);
        assert!(snapshot.buckets.is_empty());
    }

    #[test]
    fn test_parse_snapshot_with_buckets() {
        let json = r#"{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1000,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[{"key_type":"src_ip","src_ip":"10.0.0.1","dst_port":8080,"syn":100,"ack":50,"handshake_ack":50,"rst":5,"packets":155,"bytes":15500}]}"#;
        let snapshot = parse_snapshot(json).unwrap();
        assert_eq!(snapshot.buckets.len(), 1);
        assert_eq!(snapshot.buckets[0].syn, 100);
        assert_eq!(snapshot.buckets[0].ack, 50);
        assert_eq!(snapshot.buckets[0].handshake_ack, 50);
    }

    #[test]
    fn test_parse_snapshot_malformed_json() {
        let json = "not valid json";
        let result = parse_snapshot(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_snapshot_wrong_version() {
        let json = r#"{"version":999,"aggregation":"src_ip_dst_port","ts_unix_sec":1000,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#;
        let result = parse_snapshot(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_snapshot_missing_field() {
        let json = r#"{"version":5,"ts_unix_sec":1000}"#;
        let result = parse_snapshot(json);
        assert!(result.is_err());
    }

    // -------------------------------------------
    // Parse multiple snapshots in order
    // -------------------------------------------

    #[test]
    fn test_snapshot_stream_ordered() {
        let s1 = make_snapshot(1000, &[8080], vec![]);
        let s2 = make_snapshot(1001, &[8080], vec![]);
        let s3 = make_snapshot(1002, &[8080], vec![]);

        let stream = SnapshotStream::from_ordered(vec![s1, s2, s3]).unwrap();

        assert_eq!(stream.len(), 3);
        assert_eq!(stream.snapshots()[0].ts_unix_sec, 1000);
        assert_eq!(stream.snapshots()[2].ts_unix_sec, 1002);
    }

    #[test]
    fn test_snapshot_stream_unordered_sorts() {
        let s1 = make_snapshot(1002, &[8080], vec![]);
        let s2 = make_snapshot(1000, &[8080], vec![]);
        let s3 = make_snapshot(1001, &[8080], vec![]);

        let stream = SnapshotStream::from_unordered(vec![s1, s2, s3]).unwrap();

        // Should be sorted ascending
        assert_eq!(stream.snapshots()[0].ts_unix_sec, 1000);
        assert_eq!(stream.snapshots()[1].ts_unix_sec, 1001);
        assert_eq!(stream.snapshots()[2].ts_unix_sec, 1002);
    }

    #[test]
    fn test_snapshot_stream_ordering_stable() {
        // Same timestamps should maintain stable order (by insertion)
        let s1 = make_snapshot(1000, &[8080], vec![make_bucket(1, 10, 5)]);
        let s2 = make_snapshot(1000, &[8080], vec![make_bucket(2, 20, 10)]);

        let stream = SnapshotStream::from_ordered(vec![s1.clone(), s2.clone()]).unwrap();

        // Order preserved
        assert_eq!(stream.snapshots()[0].buckets[0].key_value, 1);
        assert_eq!(stream.snapshots()[1].buckets[0].key_value, 2);
    }

    // -------------------------------------------
    // Empty directory handling
    // -------------------------------------------

    #[test]
    fn test_snapshot_stream_empty_returns_error() {
        let result = SnapshotStream::from_ordered(vec![]);
        assert!(matches!(result, Err(IngestError::NoSnapshots)));
    }

    #[test]
    fn test_snapshot_stream_from_unordered_empty() {
        let result = SnapshotStream::from_unordered(vec![]);
        assert!(matches!(result, Err(IngestError::NoSnapshots)));
    }

    // -------------------------------------------
    // Malformed snapshot handling (skip with warning)
    // -------------------------------------------

    #[test]
    fn test_parse_snapshots_lenient_skips_malformed() {
        let files = vec![
            ("snap_1000.jsonl".to_string(), r#"{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1000,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#.to_string()),
            ("snap_1001.jsonl".to_string(), "invalid json".to_string()),
            ("snap_1002.jsonl".to_string(), r#"{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1002,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#.to_string()),
        ];

        let mut warnings = Vec::new();
        let snapshots = parse_snapshots_lenient(files, Some(|file: &str, err: &str| {
            warnings.push((file.to_string(), err.to_string()));
        }));

        // Should have 2 valid snapshots
        assert_eq!(snapshots.len(), 2);
        // Should have 1 warning
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].0.contains("snap_1001"));
    }

    #[test]
    fn test_parse_snapshots_lenient_no_warn_fn() {
        let files = vec![
            ("snap_1000.jsonl".to_string(), "invalid".to_string()),
            ("snap_1001.jsonl".to_string(), r#"{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1001,"interval_sec":60,"run_id":1001,"counter_mode":"cumulative","base_ts_unix_sec":1001,"dst_ports":[8080],"buckets":[]}"#.to_string()),
        ];

        let snapshots = parse_snapshots_lenient::<fn(&str, &str)>(files, None);
        assert_eq!(snapshots.len(), 1);
    }

    #[test]
    fn test_parse_snapshots_lenient_all_malformed() {
        let files = vec![
            ("snap_1.jsonl".to_string(), "bad".to_string()),
            ("snap_2.jsonl".to_string(), "also bad".to_string()),
        ];

        let snapshots = parse_snapshots_lenient::<fn(&str, &str)>(files, None);
        assert!(snapshots.is_empty());
    }

    #[test]
    fn test_parse_snapshots_lenient_multiline_jsonl() {
        // Simulate hourly file with multiple snapshots (as written by the collector)
        let multiline_content = r#"{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1000,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}
{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1001,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}
{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1002,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#;

        let files = vec![
            ("hourly_file.jsonl".to_string(), multiline_content.to_string()),
        ];

        let snapshots = parse_snapshots_lenient::<fn(&str, &str)>(files, None);

        assert_eq!(snapshots.len(), 3);
        assert_eq!(snapshots[0].ts_unix_sec, 1000);
        assert_eq!(snapshots[1].ts_unix_sec, 1001);
        assert_eq!(snapshots[2].ts_unix_sec, 1002);
    }

    #[test]
    fn test_parse_snapshots_lenient_multiline_with_empty_lines() {
        // File with empty lines interspersed
        let content = r#"{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1000,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}

{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1001,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}

{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1002,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#;

        let files = vec![("file.jsonl".to_string(), content.to_string())];
        let snapshots = parse_snapshots_lenient::<fn(&str, &str)>(files, None);

        assert_eq!(snapshots.len(), 3);
    }

    #[test]
    fn test_parse_snapshots_lenient_multiline_partial_failure() {
        // One valid line, one invalid line in same file
        let content = r#"{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1000,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}
invalid json line
{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1002,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#;

        let files = vec![("file.jsonl".to_string(), content.to_string())];
        let mut warnings = Vec::new();
        let snapshots = parse_snapshots_lenient(files, Some(|loc: &str, _err: &str| {
            warnings.push(loc.to_string());
        }));

        assert_eq!(snapshots.len(), 2);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains(":2")); // Line 2 failed
    }

    // -------------------------------------------
    // Window start/end derivation
    // -------------------------------------------

    #[test]
    fn test_derive_window_bounds_single() {
        let s = make_snapshot(1500, &[8080], vec![]);
        let bounds = derive_window_bounds(&[s]).unwrap();

        assert_eq!(bounds.start_ts, 1500);
        assert_eq!(bounds.end_ts, 1500);
        assert_eq!(bounds.duration_sec(), 0);
    }

    #[test]
    fn test_derive_window_bounds_multiple() {
        let s1 = make_snapshot(1000, &[8080], vec![]);
        let s2 = make_snapshot(1005, &[8080], vec![]);
        let s3 = make_snapshot(1010, &[8080], vec![]);

        let bounds = derive_window_bounds(&[s1, s2, s3]).unwrap();

        assert_eq!(bounds.start_ts, 1000);
        assert_eq!(bounds.end_ts, 1010);
        assert_eq!(bounds.duration_sec(), 10);
    }

    #[test]
    fn test_derive_window_bounds_unordered_input() {
        // derive_window_bounds should handle unordered input
        let s1 = make_snapshot(1010, &[8080], vec![]);
        let s2 = make_snapshot(1000, &[8080], vec![]);
        let s3 = make_snapshot(1005, &[8080], vec![]);

        let bounds = derive_window_bounds(&[s1, s2, s3]).unwrap();

        assert_eq!(bounds.start_ts, 1000);
        assert_eq!(bounds.end_ts, 1010);
    }

    #[test]
    fn test_derive_window_bounds_empty() {
        let bounds = derive_window_bounds(&[]);
        assert!(bounds.is_none());
    }

    // -------------------------------------------
    // SnapshotStream bounds and filtering
    // -------------------------------------------

    #[test]
    fn test_snapshot_stream_bounds() {
        let s1 = make_snapshot(1000, &[8080], vec![]);
        let s2 = make_snapshot(1010, &[8080], vec![]);

        let stream = SnapshotStream::from_ordered(vec![s1, s2]).unwrap();
        let bounds = stream.bounds();

        assert_eq!(bounds.start_ts, 1000);
        assert_eq!(bounds.end_ts, 1010);
    }

    #[test]
    fn test_snapshot_stream_filter_window() {
        let s1 = make_snapshot(1000, &[8080], vec![]);
        let s2 = make_snapshot(1005, &[8080], vec![]);
        let s3 = make_snapshot(1010, &[8080], vec![]);
        let s4 = make_snapshot(1015, &[8080], vec![]);

        let stream = SnapshotStream::from_ordered(vec![s1, s2, s3, s4]).unwrap();

        // Filter to 1005-1010 (inclusive)
        let filtered = stream.filter_window(1005, 1010);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].ts_unix_sec, 1005);
        assert_eq!(filtered[1].ts_unix_sec, 1010);
    }

    #[test]
    fn test_snapshot_stream_filter_window_none_match() {
        let s1 = make_snapshot(1000, &[8080], vec![]);
        let s2 = make_snapshot(1010, &[8080], vec![]);

        let stream = SnapshotStream::from_ordered(vec![s1, s2]).unwrap();

        let filtered = stream.filter_window(2000, 3000);
        assert!(filtered.is_empty());
    }

    // -------------------------------------------
    // Deterministic ordering
    // -------------------------------------------

    #[test]
    fn test_snapshot_stream_deterministic_from_same_input() {
        let make_snapshots = || {
            vec![
                make_snapshot(1002, &[8080], vec![]),
                make_snapshot(1000, &[8080], vec![]),
                make_snapshot(1001, &[8080], vec![]),
            ]
        };

        let stream1 = SnapshotStream::from_unordered(make_snapshots()).unwrap();
        let stream2 = SnapshotStream::from_unordered(make_snapshots()).unwrap();

        // Both should produce identical ordering
        for (s1, s2) in stream1.iter().zip(stream2.iter()) {
            assert_eq!(s1.ts_unix_sec, s2.ts_unix_sec);
        }
    }

    #[test]
    fn test_snapshot_stream_iter() {
        let s1 = make_snapshot(1000, &[8080], vec![]);
        let s2 = make_snapshot(1001, &[8080], vec![]);

        let stream = SnapshotStream::from_ordered(vec![s1, s2]).unwrap();

        let timestamps: Vec<u64> = stream.iter().map(|s| s.ts_unix_sec).collect();
        assert_eq!(timestamps, vec![1000, 1001]);
    }

    #[test]
    fn test_snapshot_stream_is_empty() {
        let s1 = make_snapshot(1000, &[8080], vec![]);
        let stream = SnapshotStream::from_ordered(vec![s1]).unwrap();
        assert!(!stream.is_empty());
    }

    // -------------------------------------------
    // Filesystem integration tests
    // -------------------------------------------

    #[test]
    fn test_read_snapshot_files_from_dir_empty() {
        let dir = tempfile::tempdir().unwrap();
        let result = read_snapshot_files_from_dir(dir.path()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_read_snapshot_files_from_dir_nonexistent() {
        let path = std::path::Path::new("/nonexistent/path/that/does/not/exist");
        let result = read_snapshot_files_from_dir(path).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_read_snapshot_files_from_dir_with_files() {
        let dir = tempfile::tempdir().unwrap();

        // Create test files
        std::fs::write(
            dir.path().join("snapshot_1000.jsonl"),
            r#"{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1000,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#,
        ).unwrap();
        std::fs::write(
            dir.path().join("snapshot_1001.jsonl"),
            r#"{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1001,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#,
        ).unwrap();
        // Non-jsonl file should be ignored
        std::fs::write(dir.path().join("readme.txt"), "ignored").unwrap();

        let result = read_snapshot_files_from_dir(dir.path()).unwrap();

        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_load_snapshots_from_dir_success() {
        let dir = tempfile::tempdir().unwrap();

        std::fs::write(
            dir.path().join("snapshot_1000.jsonl"),
            r#"{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1000,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#,
        ).unwrap();
        std::fs::write(
            dir.path().join("snapshot_1002.jsonl"),
            r#"{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1002,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#,
        ).unwrap();

        let stream = load_snapshots_from_dir::<fn(&str, &str)>(dir.path(), None).unwrap();

        assert_eq!(stream.len(), 2);
        // Should be sorted by timestamp
        assert_eq!(stream.snapshots()[0].ts_unix_sec, 1000);
        assert_eq!(stream.snapshots()[1].ts_unix_sec, 1002);
    }

    #[test]
    fn test_load_snapshots_from_dir_empty() {
        let dir = tempfile::tempdir().unwrap();

        let result = load_snapshots_from_dir::<fn(&str, &str)>(dir.path(), None);

        assert!(matches!(result, Err(IngestError::NoSnapshots)));
    }

    #[test]
    fn test_load_snapshots_from_dir_with_malformed() {
        let dir = tempfile::tempdir().unwrap();

        std::fs::write(
            dir.path().join("snapshot_1000.jsonl"),
            r#"{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1000,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#,
        ).unwrap();
        std::fs::write(
            dir.path().join("snapshot_1001.jsonl"),
            "invalid json",
        ).unwrap();

        let mut warnings = Vec::new();
        let stream = load_snapshots_from_dir(dir.path(), Some(|file: &str, _err: &str| {
            warnings.push(file.to_string());
        })).unwrap();

        assert_eq!(stream.len(), 1);
        assert_eq!(warnings.len(), 1);
    }

    // ===========================================
    // dst_ports inference tests
    // ===========================================

    #[test]
    fn test_infer_dst_ports_from_snapshots() {
        let s1 = make_snapshot(1000, &[8080, 443], vec![]);
        let s2 = make_snapshot(1001, &[8080, 443], vec![]);

        let stream = SnapshotStream::from_ordered(vec![s1, s2]).unwrap();
        let ports = stream.inferred_dst_ports();

        assert_eq!(ports, vec![443, 8080]); // Sorted
    }

    #[test]
    fn test_infer_dst_ports_union_across_snapshots() {
        // Different snapshots have different ports
        let s1 = make_snapshot(1000, &[8080], vec![]);
        let s2 = make_snapshot(1001, &[443], vec![]);
        let s3 = make_snapshot(1002, &[8080, 8443], vec![]);

        let stream = SnapshotStream::from_ordered(vec![s1, s2, s3]).unwrap();
        let ports = stream.inferred_dst_ports();

        // Union of all ports, sorted
        assert_eq!(ports, vec![443, 8080, 8443]);
    }

    #[test]
    fn test_infer_dst_ports_from_bucket_dst_ports() {
        // Even if snapshot header has no ports, infer from bucket dst_port values
        let s = Snapshot::new(
            1000,
            &[], // Empty in header
            vec![
                make_bucket(1, 100, 50), // dst_port = Some(8080) from make_bucket
            ],
            60,
            1000,
            1000,
        );

        let stream = SnapshotStream::from_ordered(vec![s]).unwrap();
        let ports = stream.inferred_dst_ports();

        assert_eq!(ports, vec![8080]);
    }

    #[test]
    fn test_infer_dst_ports_combines_header_and_buckets() {
        let s = Snapshot::new(
            1000,
            &[443], // Header has 443
            vec![
                BucketEntry {
                    key_type: KeyType::SrcIp,
                    key_value: 1,
                    dst_port: Some(8080), // Bucket has 8080
                    syn: 100,
                    ack: 50,
                    handshake_ack: 50,
                    rst: 0,
                    packets: 150,
                    bytes: 15000,
                },
            ],
            60,
            1000,
            1000,
        );

        let stream = SnapshotStream::from_ordered(vec![s]).unwrap();
        let ports = stream.inferred_dst_ports();

        assert_eq!(ports, vec![443, 8080]);
    }

    #[test]
    fn test_infer_run_id_from_snapshots() {
        let s1 = make_snapshot(1000, &[8080], vec![]);
        let s2 = make_snapshot(1001, &[8080], vec![]);

        let stream = SnapshotStream::from_ordered(vec![s1, s2]).unwrap();
        let run_id = stream.inferred_run_id();

        // run_id from make_snapshot uses ts as run_id
        assert_eq!(run_id, Some(1000));
    }

    #[test]
    fn test_infer_schema_version_range() {
        let s1 = make_snapshot(1000, &[8080], vec![]);
        let s2 = make_snapshot(1001, &[8080], vec![]);

        let stream = SnapshotStream::from_ordered(vec![s1, s2]).unwrap();
        let (min, max) = stream.schema_version_range();

        assert_eq!(min, 5);
        assert_eq!(max, 5);
    }
}
