//! Collect command orchestration.
//!
//! Runs the XDP collector to gather traffic metrics.

use std::path::Path;

use chrono::{TimeZone, Utc};
use ibsr_bpf::MapReader;
use ibsr_clock::Clock;
use ibsr_fs::{Filesystem, RotationConfig, SnapshotWriter, StandardSnapshotWriter};

use crate::cli::CollectArgs;
use crate::collector::{collect_once, CollectorConfig};
use crate::io::{StatusLine, StatusWriter};
use crate::logger::Logger;
use crate::signal::ShutdownCheck;
use crate::sleeper::Sleeper;

use super::CommandResult;

/// Format run directory name from Unix timestamp.
/// Format: ibsr-YYYYMMDD-HHMMSSZ
fn format_run_dir_name(ts_unix: u64) -> String {
    Utc.timestamp_opt(ts_unix as i64, 0)
        .single()
        .map(|dt| dt.format("ibsr-%Y%m%d-%H%M%SZ").to_string())
        .unwrap_or_else(|| format!("ibsr-{}", ts_unix))
}

/// Result of collect command execution.
#[derive(Debug)]
pub struct CollectResult {
    /// Number of collection cycles completed.
    pub cycles: usize,
    /// Total unique IPs observed across all cycles.
    pub total_ips: usize,
    /// Total snapshots written.
    pub snapshots_written: usize,
    /// Total files rotated.
    pub files_rotated: usize,
}

/// Execute the collect command.
///
/// This is the main entry point for the collect subcommand.
/// For actual BPF operation, the map_reader should be a real BPF map reader.
/// For testing, it can be a mock.
pub fn execute_collect<M, C, F, S, H, L>(
    args: &CollectArgs,
    map_reader: &M,
    clock: &C,
    fs: &F,
    sleeper: &S,
    shutdown: &H,
    logger: &L,
) -> CommandResult<CollectResult>
where
    M: MapReader,
    C: Clock,
    F: Filesystem + Clone,
    S: Sleeper,
    H: ShutdownCheck,
    L: Logger,
{
    // Validate arguments
    args.validate()?;

    // Create timestamped run directory inside out_dir
    let run_ts = clock.now_unix_sec();
    let run_dir_name = format_run_dir_name(run_ts);
    let run_dir = args.out_dir.join(&run_dir_name);
    fs.create_dir_all(&run_dir)?;

    // Log startup configuration at verbose level
    let ports = args.get_all_ports();
    logger.verbose(&format!(
        "Starting collector: ports={:?}, out_dir={}, snapshot_interval={}s, status_interval={}s",
        ports,
        run_dir.display(),
        args.snapshot_interval_sec,
        args.status_interval_sec
    ));

    // Build collector config
    let config = CollectorConfig {
        dst_ports: args.get_all_ports(),
        rotation: RotationConfig::new(args.max_files, args.max_age),
        interval_sec: args.snapshot_interval_sec as u32,
        run_id: run_ts,
    };

    // Create snapshot writer pointing to run directory
    let writer = StandardSnapshotWriter::new(fs.clone(), run_dir.clone());

    // Create status writer for heartbeat output in run directory
    let status_path = run_dir.join("status.jsonl");
    let status_writer = StatusWriter::new(fs.clone(), status_path);

    // Run collection cycles
    let result = run_collection_loop(
        map_reader,
        clock,
        &writer,
        &status_writer,
        fs,
        &run_dir,
        &config,
        args.duration_sec,
        args.snapshot_interval_sec,
        args.status_interval_sec,
        sleeper,
        shutdown,
        logger,
    )?;

    Ok(result)
}

/// Run the collection loop.
///
/// If duration_sec is Some, runs for that duration.
/// If duration_sec is None, runs continuously until shutdown.
///
/// Internal counter reads happen every cycle (1 second), but snapshots
/// are only written at `snapshot_interval_sec` intervals.
#[allow(clippy::too_many_arguments)]
fn run_collection_loop<M, C, F, W, S, H, L>(
    map_reader: &M,
    clock: &C,
    writer: &W,
    status_writer: &StatusWriter<F>,
    fs: &F,
    output_dir: &Path,
    config: &CollectorConfig,
    duration_sec: Option<u64>,
    snapshot_interval_sec: u64,
    status_interval_sec: u64,
    sleeper: &S,
    shutdown: &H,
    logger: &L,
) -> CommandResult<CollectResult>
where
    M: MapReader,
    C: Clock,
    F: Filesystem,
    W: SnapshotWriter,
    S: Sleeper,
    H: ShutdownCheck,
    L: Logger,
{
    let mut cycles: u64 = 0;
    let mut total_ips: usize = 0;
    let mut interval_ips: usize = 0;  // IPs collected since last snapshot
    let mut snapshots_written: u64 = 0;
    let mut files_rotated = 0;

    let start_ts = clock.now_unix_sec();
    let end_ts = duration_sec.map(|d| start_ts + d);
    let mut last_snapshot_ts = start_ts;
    let mut last_status_ts = start_ts;

    // Track base timestamp for schema v5 - set on first snapshot, constant thereafter
    let mut base_ts_unix_sec: Option<u64> = None;

    loop {
        // Check if shutdown was requested
        if shutdown.should_stop() {
            break;
        }

        let current_ts = clock.now_unix_sec();

        // Check if it's time to write a snapshot
        let should_write_snapshot = current_ts >= last_snapshot_ts + snapshot_interval_sec;

        if should_write_snapshot {
            // For first snapshot, use run_id as base_ts; thereafter use stored value
            let snapshot_base_ts = base_ts_unix_sec.unwrap_or(config.run_id);

            // Run collection and write snapshot
            let result = collect_once(map_reader, clock, writer, fs, output_dir, config, snapshot_base_ts)?;

            // Store base_ts after first successful snapshot
            if base_ts_unix_sec.is_none() {
                base_ts_unix_sec = Some(config.run_id);
            }

            cycles += 1;
            interval_ips = result.bucket_count;
            total_ips += result.bucket_count;
            snapshots_written += 1;
            files_rotated += result.rotated_count;
            last_snapshot_ts = current_ts;

            // Write status line after snapshot
            let status = StatusLine::new(
                current_ts,
                cycles,
                result.bucket_count as u64,
                snapshots_written,
            );
            let _ = status_writer.append(&status);
        }

        // Log periodic status to stdout based on status_interval_sec
        if current_ts >= last_status_ts + status_interval_sec {
            logger.info(&format!(
                "cycle={} interval_ips={} total_ips={} snapshots={} snapshot_interval={}s",
                cycles, interval_ips, total_ips, snapshots_written, snapshot_interval_sec
            ));
            last_status_ts = current_ts;
        }

        // Check if duration has expired
        if let Some(end) = end_ts {
            if current_ts >= end {
                break;
            }
        }

        // Sleep for 1 second between cycles
        sleeper.sleep_sec(1);
    }

    Ok(CollectResult {
        cycles: cycles as usize,
        total_ips,
        snapshots_written: snapshots_written as usize,
        files_rotated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CommandError;
    use crate::logger::NullLogger;
    use crate::signal::NeverShutdown;
    use crate::sleeper::MockSleeper;
    use ibsr_bpf::{Counters, MapKey, MockMapReader};
    use ibsr_clock::{AdvancingClock, MockClock};
    use ibsr_fs::MockFilesystem;
    use std::path::PathBuf;
    use std::sync::Arc;

    // ===========================================
    // Test Category B — Collect Orchestration
    // ===========================================

    #[test]
    fn test_execute_collect_empty_map() {
        let map_reader = MockMapReader::new();
        // AdvancingClock: starts at 1704067200 (2024-01-01 00:00:00), increments by 5 each call
        let clock = AdvancingClock::new(1704067200, 5);
        let fs = MockFilesystem::new();
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();
        let logger = NullLogger;
        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: Some(10),
            iface: None,
            out_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            verbose: 0,
            status_interval_sec: 60,
            snapshot_interval_sec: 1, // Write snapshot immediately for test
        };

        let result =
            execute_collect(&args, &map_reader, &clock, &fs, &sleeper, &shutdown, &logger).expect("execute");

        // With duration=10, snapshot_interval=1, and clock advancing by 5 per call,
        // we get 2 cycles before the duration expires (collect_once also calls clock)
        assert_eq!(result.cycles, 2);
        assert_eq!(result.total_ips, 0);
        assert_eq!(result.snapshots_written, 2);
    }

    #[test]
    fn test_execute_collect_with_counters() {
        let mut map_reader = MockMapReader::new();
        map_reader.add_counter(
            MapKey { src_ip: 0x0A000001, dst_port: 8899 },
            Counters {
                syn: 100,
                ack: 50,
                handshake_ack: 50,
                rst: 5,
                packets: 200,
                bytes: 30000,
            },
        );
        map_reader.add_counter(
            MapKey { src_ip: 0x0A000002, dst_port: 8899 },
            Counters {
                syn: 50,
                ack: 25,
                handshake_ack: 25,
                rst: 2,
                packets: 100,
                bytes: 15000,
            },
        );

        let clock = AdvancingClock::new(1704067200, 5);
        let fs = MockFilesystem::new();
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();
        let logger = NullLogger;
        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: Some(10),
            iface: None,
            out_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            verbose: 0,
            status_interval_sec: 60,
            snapshot_interval_sec: 1,
        };

        let result =
            execute_collect(&args, &map_reader, &clock, &fs, &sleeper, &shutdown, &logger).expect("execute");

        // With duration=10, snapshot_interval=1, and clock advancing by 5 per call,
        // we get 2 cycles (collect_once also calls clock, accelerating time)
        assert_eq!(result.cycles, 2);
        assert_eq!(result.total_ips, 4); // 2 IPs x 2 cycles
        assert_eq!(result.snapshots_written, 2);
    }

    #[test]
    fn test_execute_collect_no_duration_runs_until_shutdown() {
        use crate::signal::CountingShutdown;

        let map_reader = MockMapReader::new();
        let clock = AdvancingClock::new(1704067200, 1);
        let fs = MockFilesystem::new();
        let sleeper = MockSleeper::new();
        // Allow exactly 1 cycle before shutdown
        let shutdown = CountingShutdown::new(1);
        let logger = NullLogger;
        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: None, // No duration = continuous until shutdown
            iface: None,
            out_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            verbose: 0,
            status_interval_sec: 60,
            snapshot_interval_sec: 1,
        };

        let result =
            execute_collect(&args, &map_reader, &clock, &fs, &sleeper, &shutdown, &logger).expect("execute");

        // With CountingShutdown(1), first check returns false, we run 1 cycle,
        // then second check returns true and we exit
        assert_eq!(result.cycles, 1);
    }

    #[test]
    fn test_execute_collect_invalid_port() {
        let map_reader = MockMapReader::new();
        let clock = MockClock::new(1704067200);
        let fs = MockFilesystem::new();
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();
        let logger = NullLogger;
        let args = CollectArgs {
            dst_port: vec![], // No ports specified - Invalid
            dst_ports: None,
            duration_sec: Some(10),
            iface: None,
            out_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            verbose: 0,
            status_interval_sec: 60,
            snapshot_interval_sec: 1,
        };

        let result = execute_collect(&args, &map_reader, &clock, &fs, &sleeper, &shutdown, &logger);
        assert!(result.is_err());
        assert!(matches!(result, Err(CommandError::InvalidArgument(_))));
    }

    #[test]
    fn test_execute_collect_invalid_max_files() {
        let map_reader = MockMapReader::new();
        let clock = MockClock::new(1704067200);
        let fs = MockFilesystem::new();
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();
        let logger = NullLogger;
        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: Some(10),
            iface: None,
            out_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 0, // Invalid
            max_age: 86400,
            verbose: 0,
            status_interval_sec: 60,
            snapshot_interval_sec: 1,
        };

        let result = execute_collect(&args, &map_reader, &clock, &fs, &sleeper, &shutdown, &logger);
        assert!(result.is_err());
        assert!(matches!(result, Err(CommandError::InvalidArgument(_))));
    }

    #[test]
    fn test_execute_collect_with_rotation_config() {
        // Tests that execute_collect respects rotation settings
        // Note: actual rotation is tested in collector.rs tests.
        // This test verifies the config is passed through correctly.
        let map_reader = MockMapReader::new();
        let clock = AdvancingClock::new(1704085200, 5);
        let fs = MockFilesystem::new();
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();
        let logger = NullLogger;
        let out_dir = PathBuf::from("/tmp/snapshots");

        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: Some(10),
            iface: None,
            out_dir,
            max_files: 2, // Rotation config is passed through
            max_age: 86400,
            verbose: 0,
            status_interval_sec: 60,
            snapshot_interval_sec: 1,
        };

        // Should complete without error
        let result =
            execute_collect(&args, &map_reader, &clock, &fs, &sleeper, &shutdown, &logger).expect("execute");

        // Verify collection completed
        assert!(result.cycles > 0);
        assert!(result.snapshots_written > 0);
    }

    #[test]
    fn test_collect_result_debug() {
        let result = CollectResult {
            cycles: 10,
            total_ips: 100,
            snapshots_written: 10,
            files_rotated: 5,
        };
        let debug = format!("{:?}", result);
        assert!(debug.contains("CollectResult"));
        assert!(debug.contains("cycles: 10"));
    }

    #[test]
    fn test_execute_collect_writes_snapshot() {
        let map_reader = MockMapReader::new();
        // 2024-01-01 00:00:00 UTC = 1704067200
        let clock = AdvancingClock::new(1704067200, 5);
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();
        let logger = NullLogger;
        let out_dir = PathBuf::from("/tmp/snapshots");

        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: Some(10),
            iface: None,
            out_dir: out_dir.clone(),
            max_files: 100,
            max_age: 86400,
            verbose: 0,
            status_interval_sec: 60,
            snapshot_interval_sec: 1,
        };

        execute_collect(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown, &logger).expect("execute");

        // Verify snapshot was written - files go to run directory, not out_dir directly
        // The run directory is named like ibsr-YYYYMMDD-HHMMSSZ
        // With hourly format, 2 cycles in same hour append to the same file
        let files = fs.files();
        let snapshot_files: Vec<_> = files.keys()
            .filter(|p| p.to_string_lossy().contains("snapshot_") && p.to_string_lossy().ends_with(".jsonl"))
            .collect();
        assert_eq!(snapshot_files.len(), 1); // Both cycles in same hour → 1 file
    }

    // ===========================================
    // Test Category I — Continuous Collection Mode
    // ===========================================

    #[test]
    fn test_execute_collect_continuous_until_shutdown() {
        use crate::signal::CountingShutdown;

        let map_reader = MockMapReader::new();
        let clock = AdvancingClock::new(1704067200, 1);
        let fs = MockFilesystem::new();
        let sleeper = MockSleeper::new();
        // Signal shutdown after 5 cycles
        let shutdown = CountingShutdown::new(5);
        let logger = NullLogger;

        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: None, // Continuous mode
            iface: None,
            out_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            verbose: 0,
            status_interval_sec: 60,
            snapshot_interval_sec: 1,
        };

        let result =
            execute_collect(&args, &map_reader, &clock, &fs, &sleeper, &shutdown, &logger).expect("execute");

        // Should have run 5 cycles before shutdown
        assert_eq!(result.cycles, 5);
    }

    // ===========================================
    // Test Category J — Status.jsonl Integration
    // ===========================================

    #[test]
    fn test_execute_collect_writes_status_file() {
        let map_reader = MockMapReader::new();
        let clock = AdvancingClock::new(1704067200, 5);
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();
        let logger = NullLogger;
        let out_dir = PathBuf::from("/tmp/snapshots");

        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: Some(10),
            iface: None,
            out_dir: out_dir.clone(),
            max_files: 100,
            max_age: 86400,
            verbose: 0,
            status_interval_sec: 60,
            snapshot_interval_sec: 1,
        };

        execute_collect(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown, &logger).expect("execute");

        // Verify status.jsonl was written - it goes in run directory
        let files = fs.files();
        let status_files: Vec<_> = files.keys()
            .filter(|p| p.to_string_lossy().ends_with("status.jsonl"))
            .collect();
        assert_eq!(status_files.len(), 1);

        let status_path = status_files[0];
        let content = fs.get_file(status_path).expect("status file should exist");
        let content_str = String::from_utf8_lossy(&content);

        // Should have two status lines (one per cycle)
        let lines: Vec<&str> = content_str.lines().collect();
        assert_eq!(lines.len(), 2);

        // Parse the last status line (final state)
        let status: StatusLine =
            serde_json::from_str(lines[1]).expect("should be valid JSON");
        assert_eq!(status.cycle, 2);
        assert_eq!(status.snapshots_written, 2);
    }

    #[test]
    fn test_execute_collect_status_appends_multiple_cycles() {
        use crate::signal::CountingShutdown;

        let map_reader = MockMapReader::new();
        let clock = AdvancingClock::new(1704067200, 1);
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = CountingShutdown::new(3);
        let logger = NullLogger;
        let out_dir = PathBuf::from("/tmp/snapshots");

        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: None, // Continuous until shutdown
            iface: None,
            out_dir: out_dir.clone(),
            max_files: 100,
            max_age: 86400,
            verbose: 0,
            status_interval_sec: 60,
            snapshot_interval_sec: 1,
        };

        let result =
            execute_collect(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown, &logger).expect("execute");
        assert_eq!(result.cycles, 3);

        // Verify status.jsonl has 3 lines
        let files = fs.files();
        let status_files: Vec<_> = files.keys()
            .filter(|p| p.to_string_lossy().ends_with("status.jsonl"))
            .collect();
        let status_path = status_files[0];
        let content = fs.get_file(status_path).expect("status file should exist");
        let content_str = String::from_utf8_lossy(&content);
        let lines: Vec<&str> = content_str.lines().collect();
        assert_eq!(lines.len(), 3);

        // Verify each line has correct cycle number
        for (i, line) in lines.iter().enumerate() {
            let status: StatusLine = serde_json::from_str(line).expect("valid JSON");
            assert_eq!(status.cycle, (i + 1) as u64);
            assert_eq!(status.snapshots_written, (i + 1) as u64);
        }
    }

    #[test]
    fn test_execute_collect_status_tracks_ips() {
        let mut map_reader = MockMapReader::new();
        map_reader.add_counter(
            MapKey { src_ip: 0x0A000001, dst_port: 8899 },
            Counters {
                syn: 100,
                ack: 50,
                handshake_ack: 50,
                rst: 5,
                packets: 200,
                bytes: 30000,
            },
        );
        map_reader.add_counter(
            MapKey { src_ip: 0x0A000002, dst_port: 8899 },
            Counters {
                syn: 50,
                ack: 25,
                handshake_ack: 25,
                rst: 2,
                packets: 100,
                bytes: 15000,
            },
        );

        let clock = AdvancingClock::new(1704067200, 5);
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();
        let logger = NullLogger;
        let out_dir = PathBuf::from("/tmp/snapshots");

        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: Some(10),
            iface: None,
            out_dir: out_dir.clone(),
            max_files: 100,
            max_age: 86400,
            verbose: 0,
            status_interval_sec: 60,
            snapshot_interval_sec: 1,
        };

        execute_collect(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown, &logger).expect("execute");

        // Verify status tracks IPs collected
        let files = fs.files();
        let status_files: Vec<_> = files.keys()
            .filter(|p| p.to_string_lossy().ends_with("status.jsonl"))
            .collect();
        let status_path = status_files[0];
        let content = fs.get_file(status_path).expect("status file should exist");
        let content_str = String::from_utf8_lossy(&content);
        let status: StatusLine =
            serde_json::from_str(content_str.lines().next().unwrap()).expect("valid JSON");
        assert_eq!(status.ips_collected, 2);
    }
}
