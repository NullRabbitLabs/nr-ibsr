//! Run command orchestration.
//!
//! Runs collection for a duration, then generates report.

use ibsr_bpf::MapReader;
use ibsr_clock::Clock;
use ibsr_fs::Filesystem;

use crate::cli::RunArgs;
use crate::signal::ShutdownCheck;
use crate::sleeper::Sleeper;

use super::collect::{execute_collect, CollectResult};
use super::report::{execute_report, ReportResult};
use super::{CommandError, CommandResult};

/// Result of run command execution.
#[derive(Debug)]
pub struct RunResult {
    /// Result from the collect phase.
    pub collect: CollectResult,
    /// Result from the report phase.
    pub report: ReportResult,
}

/// Execute the run command.
///
/// This runs the collect phase for the specified duration,
/// then runs the report phase to generate artifacts.
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

    // Convert to collect args and run collect phase
    let collect_args = args.to_collect_args();
    let collect_result = execute_collect(&collect_args, map_reader, clock, fs, sleeper, shutdown)?;

    // Convert to report args and run report phase
    let report_args = args.to_report_args();
    let report_result = execute_report(&report_args, fs, clock)?;

    Ok(RunResult {
        collect: collect_result,
        report: report_result,
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
            dst_port: 8899,
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
            dst_port: 8899,
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
            dst_port: 8899,
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
            dst_port: 0, // Invalid
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
            dst_port: 8899,
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
        };

        let result = execute_run(&args, &map_reader, &clock, &*fs, &sleeper, &shutdown);
        assert!(result.is_err());
        assert!(matches!(result, Err(CommandError::InvalidArgument(_))));
    }

    #[test]
    fn test_run_result_debug() {
        let result = RunResult {
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
        assert!(debug.contains("collect"));
        assert!(debug.contains("report"));
    }
}
