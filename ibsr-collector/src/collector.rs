//! Collector loop orchestration.
//!
//! Provides the main collector loop that:
//! - Reads counters from BPF maps (via MapReader trait)
//! - Converts to snapshots with timestamps (via Clock trait)
//! - Writes snapshots to disk (via Filesystem/SnapshotWriter traits)
//! - Rotates old snapshots (via rotation logic)

use std::path::Path;

use ibsr_bpf::{counters_to_snapshot, MapReader, MapReaderError};
use ibsr_clock::Clock;
use ibsr_fs::{rotate_snapshots, Filesystem, FsError, RotationConfig, SnapshotWriter};
use thiserror::Error;

/// Errors from collector operations.
#[derive(Debug, Error)]
pub enum CollectorError {
    #[error("failed to read BPF map: {0}")]
    MapRead(#[from] MapReaderError),

    #[error("failed to write snapshot: {0}")]
    Write(#[from] FsError),
}

/// Result of a single collection cycle.
#[derive(Debug)]
pub struct CollectResult {
    /// Number of unique source IPs in the snapshot.
    pub bucket_count: usize,

    /// Timestamp of the snapshot.
    pub timestamp: u64,

    /// Number of files rotated out.
    pub rotated_count: usize,
}

/// Collector configuration.
#[derive(Debug, Clone)]
pub struct CollectorConfig {
    /// Destination ports being monitored (1-8 ports).
    pub dst_ports: Vec<u16>,

    /// Rotation settings.
    pub rotation: RotationConfig,
}

/// Perform a single collection cycle.
///
/// This is the core collector logic:
/// 1. Read counters from BPF map
/// 2. Convert to snapshot with current timestamp
/// 3. Write snapshot to disk
/// 4. Rotate old snapshots
pub fn collect_once<M, C, F, W>(
    map_reader: &M,
    clock: &C,
    writer: &W,
    fs: &F,
    output_dir: &Path,
    config: &CollectorConfig,
) -> Result<CollectResult, CollectorError>
where
    M: MapReader,
    C: Clock,
    F: Filesystem,
    W: SnapshotWriter,
{
    // Read counters from BPF map
    let counters = map_reader.read_counters()?;

    // Convert to snapshot
    let snapshot = counters_to_snapshot(&counters, clock, &config.dst_ports);
    let timestamp = snapshot.ts_unix_sec;
    let bucket_count = snapshot.buckets.len();

    // Write snapshot
    writer.write(&snapshot)?;

    // Rotate old snapshots
    let rotation_result = rotate_snapshots(fs, output_dir, &config.rotation, clock)?;

    Ok(CollectResult {
        bucket_count,
        timestamp,
        rotated_count: rotation_result.total_removed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibsr_bpf::{Counters, MapKey, MockMapReader};
    use ibsr_clock::MockClock;
    use ibsr_fs::{MockFilesystem, StandardSnapshotWriter};
    use std::path::PathBuf;
    use std::sync::Arc;

    // ===========================================
    // Integration Tests — Collector Loop
    // ===========================================

    // Hour-boundary timestamps for tests (hourly file format)
    const HOUR_0: u64 = 1704067200; // 2024-01-01 00:00:00 UTC
    const HOUR_1: u64 = 1704070800; // 2024-01-01 01:00:00 UTC
    const HOUR_2: u64 = 1704074400; // 2024-01-01 02:00:00 UTC
    const HOUR_3: u64 = 1704078000; // 2024-01-01 03:00:00 UTC

    #[test]
    fn test_collect_once_empty_map() {
        let map_reader = MockMapReader::new();
        let clock = MockClock::new(HOUR_0);
        let fs = Arc::new(MockFilesystem::new());
        let output_dir = PathBuf::from("/tmp/snapshots");
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir.clone());
        let config = CollectorConfig {
            dst_ports: vec![8899],
            rotation: RotationConfig::new(100, 86400),
        };

        let result = collect_once(&map_reader, &clock, &writer, &*fs, &output_dir, &config)
            .expect("collect");

        assert_eq!(result.bucket_count, 0);
        assert_eq!(result.timestamp, HOUR_0);
        assert_eq!(result.rotated_count, 0);

        // Verify snapshot was written
        let files = fs.list_snapshots(&output_dir).expect("list");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].timestamp, HOUR_0);
    }

    #[test]
    fn test_collect_once_with_counters() {
        let mut map_reader = MockMapReader::new();
        map_reader.add_counter(
            MapKey { src_ip: 0x0A000001, dst_port: 8899 }, // 10.0.0.1
            Counters {
                syn: 100,
                ack: 200,
                handshake_ack: 95,
                rst: 5,
                packets: 305,
                bytes: 45000,
            },
        );
        map_reader.add_counter(
            MapKey { src_ip: 0x0A000002, dst_port: 8899 }, // 10.0.0.2
            Counters {
                syn: 50,
                ack: 100,
                handshake_ack: 48,
                rst: 2,
                packets: 152,
                bytes: 20000,
            },
        );

        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let output_dir = PathBuf::from("/tmp/snapshots");
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir.clone());
        let config = CollectorConfig {
            dst_ports: vec![8899],
            rotation: RotationConfig::new(100, 86400),
        };

        let result = collect_once(&map_reader, &clock, &writer, &*fs, &output_dir, &config)
            .expect("collect");

        assert_eq!(result.bucket_count, 2);
        assert_eq!(result.timestamp, HOUR_1);
    }

    #[test]
    fn test_collect_once_triggers_rotation() {
        let map_reader = MockMapReader::new();
        let clock = MockClock::new(HOUR_3);
        let fs = Arc::new(MockFilesystem::new());
        let output_dir = PathBuf::from("/tmp/snapshots");

        // Pre-populate with old snapshots that should be rotated (hourly format)
        fs.add_file(output_dir.join("snapshot_2024010100.jsonl"), vec![]); // HOUR_0
        fs.add_file(output_dir.join("snapshot_2024010101.jsonl"), vec![]); // HOUR_1
        fs.add_file(output_dir.join("snapshot_2024010102.jsonl"), vec![]); // HOUR_2

        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir.clone());
        let config = CollectorConfig {
            dst_ports: vec![8899],
            rotation: RotationConfig::new(2, 86400), // Max 2 files
        };

        let result = collect_once(&map_reader, &clock, &writer, &*fs, &output_dir, &config)
            .expect("collect");

        // Should have rotated 2 files (keeping newest 2: HOUR_2 and HOUR_3)
        assert_eq!(result.rotated_count, 2);

        let files = fs.list_snapshots(&output_dir).expect("list");
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].timestamp, HOUR_2);
        assert_eq!(files[1].timestamp, HOUR_3);
    }

    #[test]
    fn test_collect_once_rotation_by_age() {
        let map_reader = MockMapReader::new();
        let clock = MockClock::new(HOUR_3);
        let fs = Arc::new(MockFilesystem::new());
        let output_dir = PathBuf::from("/tmp/snapshots");

        // Add old snapshot that should be rotated by age (HOUR_0 is 3 hours old)
        fs.add_file(output_dir.join("snapshot_2024010100.jsonl"), vec![]);

        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir.clone());
        let config = CollectorConfig {
            dst_ports: vec![8899],
            rotation: RotationConfig::new(100, 7200), // Max age 2 hours (7200 sec)
        };

        let result = collect_once(&map_reader, &clock, &writer, &*fs, &output_dir, &config)
            .expect("collect");

        // Old snapshot should be rotated
        assert_eq!(result.rotated_count, 1);

        let files = fs.list_snapshots(&output_dir).expect("list");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].timestamp, HOUR_3); // Only the new snapshot
    }

    #[test]
    fn test_collect_multiple_cycles() {
        let mut map_reader = MockMapReader::new();
        let fs = Arc::new(MockFilesystem::new());
        let output_dir = PathBuf::from("/tmp/snapshots");
        let config = CollectorConfig {
            dst_ports: vec![8899],
            rotation: RotationConfig::new(100, 86400),
        };

        // Cycle 1: HOUR_0
        let clock1 = MockClock::new(HOUR_0);
        let writer1 = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir.clone());
        map_reader.add_counter(MapKey { src_ip: 0x0A000001, dst_port: 8899 }, Counters {
            syn: 10, ack: 20, handshake_ack: 10, rst: 0, packets: 30, bytes: 1000,
        });
        collect_once(&map_reader, &clock1, &writer1, &*fs, &output_dir, &config).expect("cycle 1");

        // Cycle 2: HOUR_1
        let clock2 = MockClock::new(HOUR_1);
        let writer2 = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir.clone());
        map_reader.add_counter(MapKey { src_ip: 0x0A000002, dst_port: 8899 }, Counters {
            syn: 5, ack: 10, handshake_ack: 5, rst: 1, packets: 16, bytes: 500,
        });
        collect_once(&map_reader, &clock2, &writer2, &*fs, &output_dir, &config).expect("cycle 2");

        // Cycle 3: HOUR_2
        let clock3 = MockClock::new(HOUR_2);
        let writer3 = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir.clone());
        collect_once(&map_reader, &clock3, &writer3, &*fs, &output_dir, &config).expect("cycle 3");

        // Should have 3 snapshots (one per hour)
        let files = fs.list_snapshots(&output_dir).expect("list");
        assert_eq!(files.len(), 3);
        assert_eq!(files[0].timestamp, HOUR_0);
        assert_eq!(files[1].timestamp, HOUR_1);
        assert_eq!(files[2].timestamp, HOUR_2);
    }

    #[test]
    fn test_collect_preserves_dst_ports() {
        let map_reader = MockMapReader::new();
        let clock = MockClock::new(HOUR_0);
        let fs = Arc::new(MockFilesystem::new());
        let output_dir = PathBuf::from("/tmp/snapshots");
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir.clone());
        let config = CollectorConfig {
            dst_ports: vec![9000, 8080], // Multiple ports
            rotation: RotationConfig::new(100, 86400),
        };

        collect_once(&map_reader, &clock, &writer, &*fs, &output_dir, &config).expect("collect");

        // Read the snapshot and verify dst_ports (sorted)
        let path = output_dir.join("snapshot_2024010100.jsonl");
        let content = fs.get_file(&path).expect("file exists");
        let json = String::from_utf8(content).expect("valid utf8");

        let snapshot = ibsr_schema::Snapshot::from_json(&json).expect("parse");
        assert_eq!(snapshot.dst_ports, vec![8080, 9000]); // Sorted
    }

    #[test]
    fn test_collect_result_debug() {
        let result = CollectResult {
            bucket_count: 10,
            timestamp: 1000,
            rotated_count: 2,
        };
        let debug = format!("{:?}", result);
        assert!(debug.contains("bucket_count: 10"));
        assert!(debug.contains("timestamp: 1000"));
        assert!(debug.contains("rotated_count: 2"));
    }

    #[test]
    fn test_collector_config_clone() {
        let config = CollectorConfig {
            dst_ports: vec![8899, 8080],
            rotation: RotationConfig::new(100, 3600),
        };
        let cloned = config.clone();
        assert_eq!(cloned.dst_ports, vec![8899, 8080]);
    }

    #[test]
    fn test_collector_error_display() {
        let err = CollectorError::MapRead(MapReaderError::ReadError("test".to_string()));
        assert!(err.to_string().contains("failed to read BPF map"));
    }

    #[test]
    fn test_collector_error_write_display() {
        let err = CollectorError::Write(FsError::Path("test path".to_string()));
        assert!(err.to_string().contains("failed to write snapshot"));
    }

    #[test]
    fn test_collector_config_debug() {
        let config = CollectorConfig {
            dst_ports: vec![8899],
            rotation: RotationConfig::new(100, 3600),
        };
        let debug = format!("{:?}", config);
        assert!(debug.contains("dst_ports"));
        assert!(debug.contains("8899"));
        assert!(debug.contains("rotation"));
    }

    #[test]
    fn test_collect_once_map_read_error() {
        let map_reader = FailingMapReader;
        let clock = MockClock::new(1000);
        let fs = Arc::new(MockFilesystem::new());
        let output_dir = PathBuf::from("/tmp/snapshots");
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir.clone());
        let config = CollectorConfig {
            dst_ports: vec![8899],
            rotation: RotationConfig::new(100, 86400),
        };

        let result = collect_once(&map_reader, &clock, &writer, &*fs, &output_dir, &config);
        assert!(result.is_err());
        assert!(matches!(result, Err(CollectorError::MapRead(_))));
    }

    #[test]
    fn test_collect_once_write_error() {
        let map_reader = MockMapReader::new();
        let clock = MockClock::new(1000);
        let fs = Arc::new(MockFilesystem::new());
        let output_dir = PathBuf::from("/tmp/snapshots");
        let writer = FailingSnapshotWriter;
        let config = CollectorConfig {
            dst_ports: vec![8899],
            rotation: RotationConfig::new(100, 86400),
        };

        let result = collect_once(&map_reader, &clock, &writer, &*fs, &output_dir, &config);
        assert!(result.is_err());
        assert!(matches!(result, Err(CollectorError::Write(_))));
    }

    #[test]
    fn test_collect_once_rotation_error() {
        let map_reader = MockMapReader::new();
        let clock = MockClock::new(1000);
        let fs = FailingFilesystem;
        let output_dir = PathBuf::from("/tmp/snapshots");
        let writer = NoOpSnapshotWriter;
        let config = CollectorConfig {
            dst_ports: vec![8899],
            rotation: RotationConfig::new(100, 86400),
        };

        let result = collect_once(&map_reader, &clock, &writer, &fs, &output_dir, &config);
        assert!(result.is_err());
        assert!(matches!(result, Err(CollectorError::Write(_))));
    }

    // =========================================
    // Failing Mock Implementations for Testing
    // =========================================

    /// MapReader that always fails
    struct FailingMapReader;

    impl MapReader for FailingMapReader {
        fn read_counters(&self) -> Result<std::collections::HashMap<MapKey, Counters>, MapReaderError> {
            Err(MapReaderError::ReadError("simulated failure".to_string()))
        }
    }

    /// SnapshotWriter that always fails
    struct FailingSnapshotWriter;

    impl SnapshotWriter for FailingSnapshotWriter {
        fn write(&self, _snapshot: &ibsr_schema::Snapshot) -> Result<PathBuf, FsError> {
            Err(FsError::Path("simulated write failure".to_string()))
        }
    }

    /// SnapshotWriter that succeeds (for testing rotation errors)
    struct NoOpSnapshotWriter;

    impl SnapshotWriter for NoOpSnapshotWriter {
        fn write(&self, _snapshot: &ibsr_schema::Snapshot) -> Result<PathBuf, FsError> {
            Ok(PathBuf::from("/tmp/snapshot.jsonl"))
        }
    }

    /// Filesystem that always fails on list_snapshots (used by rotate)
    struct FailingFilesystem;

    impl Filesystem for FailingFilesystem {
        fn write_atomic(&self, _path: &Path, _data: &[u8]) -> Result<(), FsError> {
            Ok(())
        }

        fn append_atomic(&self, _path: &Path, _data: &[u8]) -> Result<(), FsError> {
            Ok(())
        }

        fn read_file(&self, _path: &Path) -> Result<String, FsError> {
            Err(FsError::Path("simulated read failure".to_string()))
        }

        fn list_snapshots(&self, _dir: &Path) -> Result<Vec<ibsr_fs::SnapshotFile>, FsError> {
            Err(FsError::Path("simulated list failure".to_string()))
        }

        fn remove(&self, _path: &Path) -> Result<(), FsError> {
            Ok(())
        }

        fn exists(&self, _path: &Path) -> bool {
            false
        }

        fn create_dir_all(&self, _path: &Path) -> Result<(), FsError> {
            Ok(())
        }
    }

    // Wrapper to implement Filesystem for Arc<MockFilesystem>
    struct ArcFs(Arc<MockFilesystem>);

    impl Filesystem for ArcFs {
        fn write_atomic(&self, path: &Path, data: &[u8]) -> Result<(), FsError> {
            self.0.write_atomic(path, data)
        }

        fn append_atomic(&self, path: &Path, data: &[u8]) -> Result<(), FsError> {
            self.0.append_atomic(path, data)
        }

        fn list_snapshots(&self, dir: &Path) -> Result<Vec<ibsr_fs::SnapshotFile>, FsError> {
            self.0.list_snapshots(dir)
        }

        fn remove(&self, path: &Path) -> Result<(), FsError> {
            self.0.remove(path)
        }

        fn exists(&self, path: &Path) -> bool {
            self.0.exists(path)
        }

        fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
            self.0.create_dir_all(path)
        }

        fn read_file(&self, path: &Path) -> Result<String, FsError> {
            self.0.read_file(path)
        }
    }

    // =========================================
    // Additional Tests for Mock Coverage
    // =========================================

    #[test]
    fn test_arc_fs_read_file() {
        let fs = Arc::new(MockFilesystem::new());
        let output_dir = PathBuf::from("/tmp/test");
        let file_path = output_dir.join("test.txt");
        fs.add_file(file_path.clone(), b"test content".to_vec());

        let arc_fs = ArcFs(fs);
        let content = arc_fs.read_file(&file_path).expect("read");
        assert_eq!(content, "test content");
    }

    #[test]
    fn test_arc_fs_read_file_not_found() {
        let fs = Arc::new(MockFilesystem::new());
        let arc_fs = ArcFs(fs);
        let result = arc_fs.read_file(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_arc_fs_exists() {
        let fs = Arc::new(MockFilesystem::new());
        let output_dir = PathBuf::from("/tmp/test");
        let file_path = output_dir.join("exists.txt");
        fs.add_file(file_path.clone(), vec![]);

        let arc_fs = ArcFs(fs);
        assert!(arc_fs.exists(&file_path));
        assert!(!arc_fs.exists(Path::new("/nonexistent")));
    }

    #[test]
    fn test_arc_fs_create_dir_all() {
        let fs = Arc::new(MockFilesystem::new());
        let arc_fs = ArcFs(fs);
        let result = arc_fs.create_dir_all(Path::new("/tmp/new/dir"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_failing_filesystem_write_atomic() {
        let fs = FailingFilesystem;
        let result = fs.write_atomic(Path::new("/tmp/test"), b"data");
        assert!(result.is_ok());
    }

    #[test]
    fn test_failing_filesystem_read_file() {
        let fs = FailingFilesystem;
        let result = fs.read_file(Path::new("/tmp/test"));
        assert!(result.is_err());
    }

    #[test]
    fn test_failing_filesystem_remove() {
        let fs = FailingFilesystem;
        let result = fs.remove(Path::new("/tmp/test"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_failing_filesystem_exists() {
        let fs = FailingFilesystem;
        assert!(!fs.exists(Path::new("/tmp/test")));
    }

    #[test]
    fn test_failing_filesystem_create_dir_all() {
        let fs = FailingFilesystem;
        let result = fs.create_dir_all(Path::new("/tmp/test"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_collector_error_debug() {
        let err = CollectorError::MapRead(MapReaderError::ReadError("test".to_string()));
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("MapRead"));
    }
}
