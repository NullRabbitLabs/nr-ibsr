//! Run command orchestration.
//!
//! Runs collection for a duration, then generates report.

use std::path::PathBuf;

use ibsr_bpf::MapReader;
use ibsr_clock::{format_timestamp_for_dirname, Clock};
use ibsr_fs::Filesystem;

use crate::cli::{CollectArgs, ReportArgs, RunArgs};
use crate::signal::ShutdownCheck;
use crate::sleeper::Sleeper;

use super::collect::{execute_collect, CollectResult};
use super::report::{execute_report, ReportResult};
use super::{CommandError, CommandResult};

/// Result of run command execution.
#[derive(Debug)]
pub struct RunResult {
    /// Path to the timestamped run directory.
    pub run_dir: PathBuf,
    /// Result from the collect phase.
    pub collect: CollectResult,
    /// Result from the report phase.
    pub report: ReportResult,
}

/// Execute the run command.
///
/// This runs the collect phase for the specified duration,
/// then runs the report phase to generate artifacts.
///
/// Creates a timestamped run directory under `out_dir`:
/// - `{out_dir}/ibsr-{timestamp}/` for all artifacts
/// - `{out_dir}/ibsr-{timestamp}/snapshots/` for snapshot files
pub fn execute_run<M, C, F, S, H>(
    args: &RunArgs,
    map_reader: &M,
    clock: &C,
    fs: &F,
    sleeper: &S,
    shutdown: &H,
) -> CommandResult<RunResult>
where
    M: MapReader,
    C: Clock,
    F: Filesystem + Clone,
    S: Sleeper,
    H: ShutdownCheck,
{
    // Validate arguments
    args.validate()?;

    // Create timestamped run directory
    let timestamp = clock.now_unix_sec();
    let dirname = format!("ibsr-{}", format_timestamp_for_dirname(timestamp));
    let run_dir = args.out_dir.join(&dirname);
    let snapshot_dir = run_dir.join("snapshots");

    // Create directories
    fs.create_dir_all(&run_dir)?;
    fs.create_dir_all(&snapshot_dir)?;

    // Build collect args with the timestamped snapshot directory
    let collect_args = CollectArgs {
        dst_port: args.dst_port.clone(),
        dst_ports: args.dst_ports.clone(),
        duration_sec: Some(args.duration_sec),
        iface: args.iface.clone(),
        out_dir: snapshot_dir.clone(),
        max_files: args.max_files,
        max_age: args.max_age,
        map_size: args.map_size,
        verbose: args.verbose,
        report_interval_sec: args.report_interval_sec,
    };
    let collect_result = execute_collect(&collect_args, map_reader, clock, fs, sleeper, shutdown)?;

    // Build report args with the timestamped directories
    let report_args = ReportArgs {
        input_dir: snapshot_dir,
        out_dir: run_dir.clone(),
        allowlist: args.allowlist.clone(),
        window_sec: args.window_sec,
        syn_rate_threshold: args.syn_rate_threshold,
        success_ratio_threshold: args.success_ratio_threshold,
        block_duration_sec: args.block_duration_sec,
    };
    let report_result = execute_report(&report_args, fs, clock)?;

    Ok(RunResult {
        run_dir,
        collect: collect_result,
        report: report_result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::DEFAULT_REPORT_INTERVAL_SEC;
    use crate::signal::NeverShutdown;
    use crate::sleeper::MockSleeper;
    use ibsr_bpf::{Counters, MockMapReader};
    use ibsr_clock::{AdvancingClock, MockClock};
    use ibsr_fs::MockFilesystem;
    use std::sync::Arc;

    // ===========================================
    // Test Category B — Run Orchestration
    // ===========================================

    #[test]
    fn test_execute_run_empty_collection() {
        let map_reader = MockMapReader::new();
        // AdvancingClock with increment 30 for 60-second duration (expires after 2 cycles)
        let clock = AdvancingClock::new(1000, 30);
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();

        let args = RunArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: 60,
            iface: None,
            snapshot_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            out_dir: PathBuf::from("/tmp/output"),
            allowlist: None,
            window_sec: 10,
            syn_rate_threshold: None,
            success_ratio_threshold: None,
            block_duration_sec: None,
            verbose: 0,
            report_interval_sec: DEFAULT_REPORT_INTERVAL_SEC,
        };

        let result =
            execute_run(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown).expect("execute");

        assert_eq!(result.collect.cycles, 1);
        assert_eq!(result.collect.snapshots_written, 1);
        assert_eq!(result.report.snapshot_count, 1);
    }

    #[test]
    fn test_execute_run_with_data() {
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

        let clock = AdvancingClock::new(1000, 30);
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();

        let args = RunArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: 60,
            iface: None,
            snapshot_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            out_dir: PathBuf::from("/tmp/output"),
            allowlist: None,
            window_sec: 10,
            syn_rate_threshold: None,
            success_ratio_threshold: None,
            block_duration_sec: None,
            verbose: 0,
            report_interval_sec: DEFAULT_REPORT_INTERVAL_SEC,
        };

        let result =
            execute_run(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown).expect("execute");

        assert_eq!(result.collect.total_ips, 1);
        assert!(fs.exists(&result.report.report_path));
        assert!(fs.exists(&result.report.rules_path));
        assert!(fs.exists(&result.report.evidence_path));
    }

    #[test]
    fn test_execute_run_with_offender() {
        let mut map_reader = MockMapReader::new();
        // Add an offender: high SYN, low ACK (low success ratio)
        map_reader.add_counter(
            0x0A000001,
            Counters {
                syn: 10000,
                ack: 10,
                handshake_ack: 10, // Low handshake_ack indicates SYN flood
                rst: 100,
                packets: 10110,
                bytes: 1500000,
            },
        );

        let clock = AdvancingClock::new(1000, 30);
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();

        let args = RunArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: 60,
            iface: None,
            snapshot_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            out_dir: PathBuf::from("/tmp/output"),
            allowlist: None,
            window_sec: 10,
            syn_rate_threshold: Some(100.0),
            success_ratio_threshold: Some(0.1),
            block_duration_sec: None,
            verbose: 0,
            report_interval_sec: DEFAULT_REPORT_INTERVAL_SEC,
        };

        let result =
            execute_run(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown).expect("execute");

        assert!(result.report.offender_count > 0);
    }

    #[test]
    fn test_execute_run_invalid_port() {
        let map_reader = MockMapReader::new();
        // MockClock is fine since we error before loop
        let clock = MockClock::new(1000);
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();

        let args = RunArgs {
            dst_port: vec![], // No ports specified - Invalid
            dst_ports: None,
            duration_sec: 60,
            iface: None,
            snapshot_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            out_dir: PathBuf::from("/tmp/output"),
            allowlist: None,
            window_sec: 10,
            syn_rate_threshold: None,
            success_ratio_threshold: None,
            block_duration_sec: None,
            verbose: 0,
            report_interval_sec: DEFAULT_REPORT_INTERVAL_SEC,
        };

        let result = execute_run(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown);
        assert!(result.is_err());
        assert!(matches!(result, Err(CommandError::InvalidArgument(_))));
    }

    #[test]
    fn test_execute_run_invalid_duration() {
        let map_reader = MockMapReader::new();
        // MockClock is fine since we error before loop
        let clock = MockClock::new(1000);
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();

        let args = RunArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: 0, // Invalid
            iface: None,
            snapshot_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            out_dir: PathBuf::from("/tmp/output"),
            allowlist: None,
            window_sec: 10,
            syn_rate_threshold: None,
            success_ratio_threshold: None,
            block_duration_sec: None,
            verbose: 0,
            report_interval_sec: DEFAULT_REPORT_INTERVAL_SEC,
        };

        let result = execute_run(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown);
        assert!(result.is_err());
        assert!(matches!(result, Err(CommandError::InvalidArgument(_))));
    }

    #[test]
    fn test_run_result_debug() {
        let result = RunResult {
            run_dir: PathBuf::from("/tmp/output/ibsr-20240101-120000Z"),
            collect: CollectResult {
                cycles: 10,
                total_ips: 100,
                snapshots_written: 10,
                files_rotated: 5,
            },
            report: ReportResult {
                report_path: PathBuf::from("/tmp/report.md"),
                rules_path: PathBuf::from("/tmp/rules.json"),
                evidence_path: PathBuf::from("/tmp/evidence.csv"),
                snapshot_count: 10,
                offender_count: 2,
                is_safe: true,
            },
        };
        let debug = format!("{:?}", result);
        assert!(debug.contains("RunResult"));
        assert!(debug.contains("run_dir"));
        assert!(debug.contains("collect"));
        assert!(debug.contains("report"));
    }

    // ===========================================
    // Test Category — Timestamped Run Directories
    // ===========================================

    #[test]
    fn test_run_creates_timestamped_directory() {
        let map_reader = MockMapReader::new();
        // Clock starts at 1704067200 = 2024-01-01 00:00:00 UTC
        let clock = AdvancingClock::new(1704067200, 30);
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();

        let args = RunArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: 60,
            iface: None,
            snapshot_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            out_dir: PathBuf::from("/tmp/output"),
            allowlist: None,
            window_sec: 10,
            syn_rate_threshold: None,
            success_ratio_threshold: None,
            block_duration_sec: None,
            verbose: 0,
            report_interval_sec: DEFAULT_REPORT_INTERVAL_SEC,
        };

        let result =
            execute_run(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown).expect("execute");

        // Verify run directory was created with timestamp format
        assert_eq!(
            result.run_dir,
            PathBuf::from("/tmp/output/ibsr-20240101-000000Z")
        );
        assert!(fs.exists(&result.run_dir));
    }

    #[test]
    fn test_run_snapshots_inside_run_directory() {
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

        // Clock starts at 1704067200 = 2024-01-01 00:00:00 UTC
        let clock = AdvancingClock::new(1704067200, 30);
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();

        let args = RunArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: 60,
            iface: None,
            snapshot_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            out_dir: PathBuf::from("/tmp/output"),
            allowlist: None,
            window_sec: 10,
            syn_rate_threshold: None,
            success_ratio_threshold: None,
            block_duration_sec: None,
            verbose: 0,
            report_interval_sec: DEFAULT_REPORT_INTERVAL_SEC,
        };

        let result =
            execute_run(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown).expect("execute");

        // Verify snapshots are inside run_dir/snapshots/
        let snapshot_dir = result.run_dir.join("snapshots");
        let snapshots = fs.list_snapshots(&snapshot_dir).expect("list");
        assert!(!snapshots.is_empty());
    }

    #[test]
    fn test_run_report_artifacts_in_run_directory() {
        let map_reader = MockMapReader::new();
        // Clock starts at 1704067200 = 2024-01-01 00:00:00 UTC
        let clock = AdvancingClock::new(1704067200, 30);
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();

        let args = RunArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: 60,
            iface: None,
            snapshot_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            out_dir: PathBuf::from("/tmp/output"),
            allowlist: None,
            window_sec: 10,
            syn_rate_threshold: None,
            success_ratio_threshold: None,
            block_duration_sec: None,
            verbose: 0,
            report_interval_sec: DEFAULT_REPORT_INTERVAL_SEC,
        };

        let result =
            execute_run(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown).expect("execute");

        // Verify report artifacts are directly in run_dir (not run_dir/output)
        assert!(result.report.report_path.starts_with(&result.run_dir));
        assert!(result.report.rules_path.starts_with(&result.run_dir));
        assert!(result.report.evidence_path.starts_with(&result.run_dir));

        // Verify they're not in a nested output directory
        assert!(!result
            .report
            .report_path
            .to_string_lossy()
            .contains("output/output"));
    }

    #[test]
    fn test_run_different_timestamps_create_different_directories() {
        let map_reader = MockMapReader::new();
        let fs = Arc::new(MockFilesystem::new());
        let sleeper = MockSleeper::new();
        let shutdown = NeverShutdown::new();

        let args = RunArgs {
            dst_port: vec![8899],
            dst_ports: None,
            duration_sec: 60,
            iface: None,
            snapshot_dir: PathBuf::from("/tmp/snapshots"),
            max_files: 100,
            max_age: 86400,
            map_size: 100000,
            out_dir: PathBuf::from("/tmp/output"),
            allowlist: None,
            window_sec: 10,
            syn_rate_threshold: None,
            success_ratio_threshold: None,
            block_duration_sec: None,
            verbose: 0,
            report_interval_sec: DEFAULT_REPORT_INTERVAL_SEC,
        };

        // First run at timestamp 1704067200 (2024-01-01 00:00:00)
        let clock1 = AdvancingClock::new(1704067200, 30);
        let result1 =
            execute_run(&args, &map_reader, &clock1, &*fs, &sleeper, &shutdown).expect("execute1");

        // Second run at timestamp 1704153600 (2024-01-02 00:00:00)
        let clock2 = AdvancingClock::new(1704153600, 30);
        let result2 =
            execute_run(&args, &map_reader, &clock2, &*fs, &sleeper, &shutdown).expect("execute2");

        // Verify different directories were created
        assert_ne!(result1.run_dir, result2.run_dir);
        assert!(fs.exists(&result1.run_dir));
        assert!(fs.exists(&result2.run_dir));
    }
}
