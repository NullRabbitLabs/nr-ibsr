//! Collect command orchestration.
//!
//! Runs the XDP collector to gather traffic metrics.

use std::path::{Path, PathBuf};

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

use super::{CommandError, CommandResult};

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
    fs.create_dir_all(&run_dir)
        .map_err(|e| CommandError::IoError(e.to_string()))?;

    // Log startup configuration at verbose level
    let ports = args.get_all_ports();
    logger.verbose(&format!(
        "Starting collector: ports={:?}, out_dir={}, report_interval={}s",
        ports,
        run_dir.display(),
        args.report_interval_sec
    ));

    // Build collector config
    let config = CollectorConfig {
        dst_ports: args.get_all_ports(),
        rotation: RotationConfig::new(args.max_files, args.max_age),
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
        args.report_interval_sec,
        sleeper,
        shutdown,
        logger,
    )?;

    Ok(result)
}

/// Run the collection loop.
///
/// If duration_sec is Some, runs for that duration.
/// If duration_sec is None, runs a single cycle (for testing) or until interrupted.
fn run_collection_loop<M, C, F, W, S, H, L>(
    map_reader: &M,
    clock: &C,
    writer: &W,
    status_writer: &StatusWriter<F>,
    fs: &F,
    output_dir: &Path,
    config: &CollectorConfig,
    duration_sec: Option<u64>,
    report_interval_sec: u64,
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
    let mut snapshots_written: u64 = 0;
    let mut files_rotated = 0;

    let start_ts = clock.now_unix_sec();
    let end_ts = duration_sec.map(|d| start_ts + d);
    let mut last_report_ts = start_ts;

    loop {
        // Check if shutdown was requested
        if shutdown.should_stop() {
            break;
        }

        // Run one collection cycle
        let result = collect_once(map_reader, clock, writer, fs, output_dir, config)?;

        cycles += 1;
        total_ips += result.bucket_count;
        snapshots_written += 1;
        files_rotated += result.rotated_count;

        // Write status line after each cycle
        let current_ts = clock.now_unix_sec();
        let status = StatusLine::new(
            current_ts,
            cycles,
            result.bucket_count as u64,
            snapshots_written,
        );
        // Ignore status write errors - don't fail collection if status write fails
        let _ = status_writer.append(&status);

        // Log periodic status to stdout based on report_interval_sec
        if current_ts >= last_report_ts + report_interval_sec {
            logger.info(&format!(
                "cycle={} ips={} snapshots={} rotated={}",
                cycles, result.bucket_count, snapshots_written, files_rotated
            ));
            last_report_ts = current_ts;
        }

        // Check if duration has expired (after completing cycle)
        // If duration_sec is None, we run continuously until shutdown
        if let Some(end) = end_ts {
            if clock.now_unix_sec() >= end {
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
    use crate::signal::NeverShutdown;
    use crate::sleeper::MockSleeper;
    use ibsr_bpf::{Counters, MockMapReader};
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
        // AdvancingClock: starts at 1000, increments by 5 each call
        // - Call 1 (start_ts): 1000, end_ts = 1010
        // - Call 2 (collect_once): 1005
        // - Call 3 (end check): 1010 >= 1010, exit
        let clock = AdvancingClock::new(1000, 5);
        let fs = MockFilesystem::new();
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();
        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: Some(10),
            iface: None,
            out_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            verbose: 0,
            report_interval_sec: 60,
        };

        let result =
            execute_collect(&args, &map_reader, &clock, &fs, &sleeper, &shutdown).expect("execute");

        assert_eq!(result.cycles, 1);
        assert_eq!(result.total_ips, 0);
        assert_eq!(result.snapshots_written, 1);
    }

    #[test]
    fn test_execute_collect_with_counters() {
        let mut map_reader = MockMapReader::new();
        map_reader.add_counter(
            0x0A000001,
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
            0x0A000002,
            Counters {
                syn: 50,
                ack: 25,
                handshake_ack: 25,
                rst: 2,
                packets: 100,
                bytes: 15000,
            },
        );

        let clock = AdvancingClock::new(1000, 5);
        let fs = MockFilesystem::new();
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();
        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: Some(10),
            iface: None,
            out_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            verbose: 0,
            report_interval_sec: 60,
        };

        let result =
            execute_collect(&args, &map_reader, &clock, &fs, &sleeper, &shutdown).expect("execute");

        assert_eq!(result.cycles, 1);
        assert_eq!(result.total_ips, 2);
        assert_eq!(result.snapshots_written, 1);
    }

    #[test]
    fn test_execute_collect_no_duration_runs_until_shutdown() {
        use crate::signal::CountingShutdown;

        let map_reader = MockMapReader::new();
        let clock = AdvancingClock::new(1000, 1);
        let fs = MockFilesystem::new();
        let sleeper = MockSleeper::new();
        // Allow exactly 1 cycle before shutdown
        let shutdown = CountingShutdown::new(1);
        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: None, // No duration = continuous until shutdown
            iface: None,
            out_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            verbose: 0,
            report_interval_sec: 60,
        };

        let result =
            execute_collect(&args, &map_reader, &clock, &fs, &sleeper, &shutdown).expect("execute");

        // With CountingShutdown(1), first check returns false, we run 1 cycle,
        // then second check returns true and we exit
        assert_eq!(result.cycles, 1);
    }

    #[test]
    fn test_execute_collect_invalid_port() {
        let map_reader = MockMapReader::new();
        // MockClock is fine here since we error before the loop runs
        let clock = MockClock::new(1000);
        let fs = MockFilesystem::new();
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();
        let args = CollectArgs {
            dst_port: vec![], // No ports specified - Invalid
            dst_ports: None,
            duration_sec: Some(10),
            iface: None,
            out_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            verbose: 0,
            report_interval_sec: 60,
        };

        let result = execute_collect(&args, &map_reader, &clock, &fs, &sleeper, &shutdown);
        assert!(result.is_err());
        assert!(matches!(result, Err(CommandError::InvalidArgument(_))));
    }

    #[test]
    fn test_execute_collect_invalid_max_files() {
        let map_reader = MockMapReader::new();
        // MockClock is fine here since we error before the loop runs
        let clock = MockClock::new(1000);
        let fs = MockFilesystem::new();
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();
        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: Some(10),
            iface: None,
            out_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 0, // Invalid
            max_age: 86400,
            map_size: 100000,
            verbose: 0,
            report_interval_sec: 60,
        };

        let result = execute_collect(&args, &map_reader, &clock, &fs, &sleeper, &shutdown);
        assert!(result.is_err());
        assert!(matches!(result, Err(CommandError::InvalidArgument(_))));
    }

    #[test]
    fn test_execute_collect_triggers_rotation() {
        let map_reader = MockMapReader::new();
        let clock = AdvancingClock::new(5000, 5);
        let fs = MockFilesystem::new();
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();
        let out_dir = PathBuf::from("/tmp/snapshots");

        // Pre-populate with old snapshots
        fs.add_file(out_dir.join("snapshot_1000.jsonl"), vec![]);
        fs.add_file(out_dir.join("snapshot_2000.jsonl"), vec![]);
        fs.add_file(out_dir.join("snapshot_3000.jsonl"), vec![]);

        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: Some(10),
            iface: None,
            out_dir,
            max_files: 2, // Only keep 2 files
            max_age: 86400,
            map_size: 100000,
            verbose: 0,
            report_interval_sec: 60,
        };

        let result =
            execute_collect(&args, &map_reader, &clock, &fs, &sleeper, &shutdown).expect("execute");

        // Should have rotated some files
        assert!(result.files_rotated > 0);
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
        // AdvancingClock starts at 1000, so snapshot timestamp is 1005 (second call)
        let clock = AdvancingClock::new(1000, 5);
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();
        let out_dir = PathBuf::from("/tmp/snapshots");

        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: Some(10),
            iface: None,
            out_dir: out_dir.clone(),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            verbose: 0,
            report_interval_sec: 60,
        };

        execute_collect(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown).expect("execute");

        // Verify snapshot was written
        let files = fs.list_snapshots(&out_dir).expect("list");
        assert_eq!(files.len(), 1);
        // Timestamp is from the second clock call (1005) since first is for start_ts
        assert_eq!(files[0].timestamp, 1005);
    }

    // ===========================================
    // Test Category I — Continuous Collection Mode
    // ===========================================

    #[test]
    fn test_execute_collect_continuous_until_shutdown() {
        use crate::signal::CountingShutdown;

        let map_reader = MockMapReader::new();
        let clock = AdvancingClock::new(1000, 1);
        let fs = MockFilesystem::new();
        let sleeper = MockSleeper::new();
        // Signal shutdown after 5 cycles
        let shutdown = CountingShutdown::new(5);

        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: None, // Continuous mode
            iface: None,
            out_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            verbose: 0,
            report_interval_sec: 60,
        };

        let result =
            execute_collect(&args, &map_reader, &clock, &fs, &sleeper, &shutdown).expect("execute");

        // Should have run 5 cycles before shutdown
        assert_eq!(result.cycles, 5);
    }

    // ===========================================
    // Test Category J — Status.jsonl Integration
    // ===========================================

    #[test]
    fn test_execute_collect_writes_status_file() {
        let map_reader = MockMapReader::new();
        let clock = AdvancingClock::new(1000, 5);
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();
        let out_dir = PathBuf::from("/tmp/snapshots");

        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: Some(10),
            iface: None,
            out_dir: out_dir.clone(),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            verbose: 0,
            report_interval_sec: 60,
        };

        execute_collect(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown).expect("execute");

        // Verify status.jsonl was written
        let status_path = out_dir.join("status.jsonl");
        let content = fs
            .get_file(&status_path)
            .expect("status file should exist");
        let content_str = String::from_utf8_lossy(&content);

        // Should have one status line
        let lines: Vec<&str> = content_str.lines().collect();
        assert_eq!(lines.len(), 1);

        // Parse the status line
        let status: StatusLine =
            serde_json::from_str(lines[0]).expect("should be valid JSON");
        assert_eq!(status.cycle, 1);
        assert_eq!(status.snapshots_written, 1);
    }

    #[test]
    fn test_execute_collect_status_appends_multiple_cycles() {
        use crate::signal::CountingShutdown;

        let map_reader = MockMapReader::new();
        let clock = AdvancingClock::new(1000, 1);
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = CountingShutdown::new(3);
        let out_dir = PathBuf::from("/tmp/snapshots");

        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: None, // Continuous until shutdown
            iface: None,
            out_dir: out_dir.clone(),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            verbose: 0,
            report_interval_sec: 60,
        };

        let result =
            execute_collect(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown).expect("execute");
        assert_eq!(result.cycles, 3);

        // Verify status.jsonl has 3 lines
        let status_path = out_dir.join("status.jsonl");
        let content = fs
            .get_file(&status_path)
            .expect("status file should exist");
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
            0x0A000001,
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
            0x0A000002,
            Counters {
                syn: 50,
                ack: 25,
                handshake_ack: 25,
                rst: 2,
                packets: 100,
                bytes: 15000,
            },
        );

        let clock = AdvancingClock::new(1000, 5);
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();
        let out_dir = PathBuf::from("/tmp/snapshots");

        let args = CollectArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: Some(10),
            iface: None,
            out_dir: out_dir.clone(),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            verbose: 0,
            report_interval_sec: 60,
        };

        execute_collect(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown).expect("execute");

        // Verify status tracks IPs collected
        let status_path = out_dir.join("status.jsonl");
        let content = fs
            .get_file(&status_path)
            .expect("status file should exist");
        let content_str = String::from_utf8_lossy(&content);
        let status: StatusLine =
            serde_json::from_str(content_str.lines().next().unwrap()).expect("valid JSON");
        assert_eq!(status.ips_collected, 2);
    }
}
