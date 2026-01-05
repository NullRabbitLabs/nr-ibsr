//! Report command orchestration.
//!
//! Generates report from collected snapshots.

use std::path::Path;

use ibsr_clock::Clock;
use ibsr_fs::Filesystem;
use ibsr_reporter::config::{Allowlist, ReporterConfig};
use ibsr_reporter::counterfactual;
use ibsr_reporter::decision::{evaluate_key, KeyDecision};
use ibsr_reporter::ingest::{parse_snapshot, SnapshotStream};
use ibsr_reporter::report::{self, Report};
use ibsr_reporter::rules::{self, EnforcementRules};
use ibsr_reporter::window;

use crate::cli::ReportArgs;
use crate::io::{load_allowlist, OutputWriter};

use super::{CommandError, CommandResult};

/// Result of report command execution.
#[derive(Debug)]
pub struct ReportResult {
    /// Path to the generated report.
    pub report_path: std::path::PathBuf,
    /// Path to the generated rules.
    pub rules_path: std::path::PathBuf,
    /// Path to the generated evidence CSV.
    pub evidence_path: std::path::PathBuf,
    /// Number of snapshots processed.
    pub snapshot_count: usize,
    /// Number of offenders detected.
    pub offender_count: usize,
    /// Whether the rules are safe for autonomous deployment.
    pub is_safe: bool,
}

/// Execute the report command.
///
/// This is the main entry point for the report subcommand.
pub fn execute_report<F, C>(
    args: &ReportArgs,
    fs: &F,
    clock: &C,
) -> CommandResult<ReportResult>
where
    F: Filesystem,
    C: Clock,
{
    // Validate arguments
    args.validate()?;

    // Build reporter config
    let config = build_config(args, fs)?;

    // Load snapshots from filesystem
    let snapshots = load_snapshots(fs, &args.input_dir)?;
    let snapshot_count = snapshots.len();

    if snapshot_count == 0 {
        return Err(CommandError::NoSnapshots(
            args.input_dir.display().to_string(),
        ));
    }

    // Run the reporter pipeline
    let (report, rules, decisions) = run_pipeline(&snapshots, &config, clock)?;

    // Write outputs
    let writer = OutputWriter::new(fs, &args.out_dir);
    let written = writer.write_all(&report, &rules, &decisions)?;

    Ok(ReportResult {
        report_path: written.report,
        rules_path: written.rules,
        evidence_path: written.evidence,
        snapshot_count,
        offender_count: rules.triggers.len(),
        is_safe: report.readiness.is_safe,
    })
}

/// Load snapshots from a directory using the Filesystem trait.
fn load_snapshots<F: Filesystem>(fs: &F, dir: &Path) -> CommandResult<SnapshotStream> {
    let snapshot_files = fs.list_snapshots(dir)?;

    let mut snapshots = Vec::new();
    for file in snapshot_files {
        let content = fs.read_file(&file.path)?;
        if let Ok(snapshot) = parse_snapshot(&content) {
            snapshots.push(snapshot);
        }
    }

    if snapshots.is_empty() {
        return Err(CommandError::NoSnapshots(dir.display().to_string()));
    }

    Ok(SnapshotStream::from_unordered(snapshots)?)
}

/// Build ReporterConfig from CLI args.
fn build_config<F: Filesystem>(args: &ReportArgs, fs: &F) -> CommandResult<ReporterConfig> {
    // Load allowlist if specified
    let allowlist = if let Some(ref path) = args.allowlist {
        load_allowlist(fs, path)?
    } else {
        Allowlist::empty()
    };

    // Build config with defaults, applying overrides
    let mut config = ReporterConfig::new(0) // dst_port will be extracted from snapshots
        .with_window_sec(args.window_sec)
        .with_allowlist(allowlist);

    // Apply threshold overrides if specified
    if let Some(threshold) = args.syn_rate_threshold {
        config = config.with_syn_rate_threshold(threshold);
    }
    if let Some(threshold) = args.success_ratio_threshold {
        config = config.with_success_ratio_threshold(threshold);
    }
    if let Some(duration) = args.block_duration_sec {
        config = config.with_block_duration_sec(duration);
    }

    Ok(config)
}

/// Run the reporter pipeline.
fn run_pipeline<C: Clock>(
    snapshots: &SnapshotStream,
    config: &ReporterConfig,
    clock: &C,
) -> CommandResult<(Report, EnforcementRules, Vec<KeyDecision>)> {
    // Get time window from snapshots
    let bounds = snapshots.bounds();

    // Extract dst_port from first snapshot
    let dst_port = snapshots
        .snapshots()
        .first()
        .map(|s| s.dst_port)
        .unwrap_or(0);

    // Create config with correct dst_port
    let mut config = config.clone();
    config.dst_port = dst_port;

    // Aggregate statistics
    let snapshot_refs: Vec<_> = snapshots.snapshots().iter().collect();
    let aggregated = window::aggregate_snapshots(&snapshot_refs, config.window_sec);
    let sorted = window::sorted_aggregated(&aggregated);

    // Evaluate decisions
    let current_ts = clock.now_unix_sec();
    let decisions: Vec<KeyDecision> = sorted
        .iter()
        .map(|(key, stats)| evaluate_key(*key, *stats, &config, current_ts))
        .collect();

    // Compute counterfactual
    let counterfactual = counterfactual::compute(&decisions, &config);

    // Generate rules and report
    let rules = rules::generate(&counterfactual.top_offenders, &config, current_ts);
    let report = report::generate(&bounds, &config, &counterfactual, &rules);

    Ok((report, rules, decisions))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibsr_clock::MockClock;
    use ibsr_fs::MockFilesystem;
    use ibsr_schema::{BucketEntry, KeyType, Snapshot};
    use std::path::PathBuf;
    use std::sync::Arc;

    fn create_test_snapshot(ts: u64, dst_port: u16, entries: Vec<BucketEntry>) -> Snapshot {
        Snapshot::new(ts, dst_port, entries)
    }

    fn write_snapshot(fs: &MockFilesystem, dir: &Path, snapshot: &Snapshot) {
        let filename = format!("snapshot_{}.jsonl", snapshot.ts_unix_sec);
        let path = dir.join(filename);
        let json = snapshot.to_json();
        fs.add_file(path, json.into_bytes());
    }

    // ===========================================
    // Test Category B — Report Orchestration
    // ===========================================

    #[test]
    fn test_execute_report_empty_dir() {
        let fs = Arc::new(MockFilesystem::new());
        let clock = MockClock::new(1000);
        let args = ReportArgs {
            input_dir: PathBuf::from("/tmp/snapshots"),
            out_dir: PathBuf::from("/tmp/output"),
            allowlist: None,
            window_sec: 10,
            syn_rate_threshold: None,
            success_ratio_threshold: None,
            block_duration_sec: None,
        };

        let result = execute_report(&args, &*fs, &clock);
        assert!(result.is_err());
        assert!(matches!(result, Err(CommandError::NoSnapshots(_))));
    }

    #[test]
    fn test_execute_report_single_snapshot() {
        let fs = Arc::new(MockFilesystem::new());
        let clock = MockClock::new(1000);
        let input_dir = PathBuf::from("/tmp/snapshots");
        let out_dir = PathBuf::from("/tmp/output");

        // Create a snapshot with some data
        let snapshot = create_test_snapshot(
            1000,
            8899,
            vec![BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0A000001, // 10.0.0.1
                syn: 100,
                ack: 50,
                rst: 5,
                packets: 200,
                bytes: 30000,
            }],
        );
        write_snapshot(&fs, &input_dir, &snapshot);

        let args = ReportArgs {
            input_dir,
            out_dir: out_dir.clone(),
            allowlist: None,
            window_sec: 10,
            syn_rate_threshold: None,
            success_ratio_threshold: None,
            block_duration_sec: None,
        };

        let result = execute_report(&args, &*fs, &clock).expect("execute");

        assert_eq!(result.snapshot_count, 1);
        assert!(fs.exists(&result.report_path));
        assert!(fs.exists(&result.rules_path));
        assert!(fs.exists(&result.evidence_path));
    }

    #[test]
    fn test_execute_report_with_offenders() {
        let fs = Arc::new(MockFilesystem::new());
        let clock = MockClock::new(1000);
        let input_dir = PathBuf::from("/tmp/snapshots");
        let out_dir = PathBuf::from("/tmp/output");

        // Create snapshot with high SYN rate, low success ratio (offender)
        let snapshot = create_test_snapshot(
            1000,
            8899,
            vec![BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0A000001,
                syn: 10000,  // High SYN
                ack: 10,     // Low ACK (low success ratio)
                rst: 100,
                packets: 10110,
                bytes: 1500000,
            }],
        );
        write_snapshot(&fs, &input_dir, &snapshot);

        let args = ReportArgs {
            input_dir,
            out_dir,
            allowlist: None,
            window_sec: 10,
            syn_rate_threshold: Some(100.0),
            success_ratio_threshold: Some(0.1),
            block_duration_sec: None,
        };

        let result = execute_report(&args, &*fs, &clock).expect("execute");

        assert_eq!(result.snapshot_count, 1);
        assert!(result.offender_count > 0);
    }

    #[test]
    fn test_execute_report_with_allowlist() {
        let fs = Arc::new(MockFilesystem::new());
        let clock = MockClock::new(1000);
        let input_dir = PathBuf::from("/tmp/snapshots");
        let out_dir = PathBuf::from("/tmp/output");
        let allowlist_path = PathBuf::from("/tmp/allowlist.txt");

        // Create allowlist that includes the offending IP
        fs.add_file(allowlist_path.clone(), b"10.0.0.1\n".to_vec());

        // Create snapshot with offending IP
        let snapshot = create_test_snapshot(
            1000,
            8899,
            vec![BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0A000001, // 10.0.0.1
                syn: 10000,
                ack: 10,
                rst: 100,
                packets: 10110,
                bytes: 1500000,
            }],
        );
        write_snapshot(&fs, &input_dir, &snapshot);

        let args = ReportArgs {
            input_dir,
            out_dir,
            allowlist: Some(allowlist_path),
            window_sec: 10,
            syn_rate_threshold: Some(100.0),
            success_ratio_threshold: Some(0.1),
            block_duration_sec: None,
        };

        let result = execute_report(&args, &*fs, &clock).expect("execute");

        // Allowlisted IP should not be an offender
        assert_eq!(result.offender_count, 0);
    }

    #[test]
    fn test_execute_report_multiple_snapshots() {
        let fs = Arc::new(MockFilesystem::new());
        let clock = MockClock::new(3000);
        let input_dir = PathBuf::from("/tmp/snapshots");
        let out_dir = PathBuf::from("/tmp/output");

        // Create multiple snapshots
        for ts in [1000, 2000, 3000] {
            let snapshot = create_test_snapshot(
                ts,
                8899,
                vec![BucketEntry {
                    key_type: KeyType::SrcIp,
                    key_value: 0x0A000001,
                    syn: 100,
                    ack: 50,
                    rst: 5,
                    packets: 200,
                    bytes: 30000,
                }],
            );
            write_snapshot(&fs, &input_dir, &snapshot);
        }

        let args = ReportArgs {
            input_dir,
            out_dir,
            allowlist: None,
            window_sec: 10,
            syn_rate_threshold: None,
            success_ratio_threshold: None,
            block_duration_sec: None,
        };

        let result = execute_report(&args, &*fs, &clock).expect("execute");

        assert_eq!(result.snapshot_count, 3);
    }

    #[test]
    fn test_execute_report_invalid_window_sec() {
        let fs = Arc::new(MockFilesystem::new());
        let clock = MockClock::new(1000);
        let args = ReportArgs {
            input_dir: PathBuf::from("/tmp/snapshots"),
            out_dir: PathBuf::from("/tmp/output"),
            allowlist: None,
            window_sec: 0, // Invalid
            syn_rate_threshold: None,
            success_ratio_threshold: None,
            block_duration_sec: None,
        };

        let result = execute_report(&args, &*fs, &clock);
        assert!(result.is_err());
        assert!(matches!(result, Err(CommandError::InvalidArgument(_))));
    }

    #[test]
    fn test_execute_report_invalid_allowlist() {
        let fs = Arc::new(MockFilesystem::new());
        let clock = MockClock::new(1000);
        let input_dir = PathBuf::from("/tmp/snapshots");

        // Create a snapshot so we get past the empty check
        let snapshot = create_test_snapshot(1000, 8899, vec![]);
        write_snapshot(&fs, &input_dir, &snapshot);

        let args = ReportArgs {
            input_dir,
            out_dir: PathBuf::from("/tmp/output"),
            allowlist: Some(PathBuf::from("/nonexistent/allowlist.txt")),
            window_sec: 10,
            syn_rate_threshold: None,
            success_ratio_threshold: None,
            block_duration_sec: None,
        };

        let result = execute_report(&args, &*fs, &clock);
        assert!(result.is_err());
        assert!(matches!(result, Err(CommandError::Allowlist(_))));
    }

    #[test]
    fn test_report_result_debug() {
        let result = ReportResult {
            report_path: PathBuf::from("/tmp/report.md"),
            rules_path: PathBuf::from("/tmp/rules.json"),
            evidence_path: PathBuf::from("/tmp/evidence.csv"),
            snapshot_count: 5,
            offender_count: 2,
            is_safe: true,
        };
        let debug = format!("{:?}", result);
        assert!(debug.contains("ReportResult"));
        assert!(debug.contains("snapshot_count: 5"));
    }

    #[test]
    fn test_build_config_with_overrides() {
        let fs = Arc::new(MockFilesystem::new());
        let args = ReportArgs {
            input_dir: PathBuf::from("/tmp/snapshots"),
            out_dir: PathBuf::from("/tmp/output"),
            allowlist: None,
            window_sec: 30,
            syn_rate_threshold: Some(200.0),
            success_ratio_threshold: Some(0.05),
            block_duration_sec: Some(600),
        };

        let config = build_config(&args, &*fs).expect("config");

        assert_eq!(config.window_sec, 30);
        assert_eq!(config.syn_rate_threshold, 200.0);
        assert_eq!(config.success_ratio_threshold, 0.05);
        assert_eq!(config.block_duration_sec, 600);
    }

    #[test]
    fn test_build_config_defaults() {
        let fs = Arc::new(MockFilesystem::new());
        let args = ReportArgs {
            input_dir: PathBuf::from("/tmp/snapshots"),
            out_dir: PathBuf::from("/tmp/output"),
            allowlist: None,
            window_sec: 10,
            syn_rate_threshold: None,
            success_ratio_threshold: None,
            block_duration_sec: None,
        };

        let config = build_config(&args, &*fs).expect("config");

        // Should use defaults from ReporterConfig
        assert_eq!(config.window_sec, 10);
    }
}
