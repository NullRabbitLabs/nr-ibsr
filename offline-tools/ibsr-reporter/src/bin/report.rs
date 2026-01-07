//! CLI for generating IBSR reports from collector snapshots.

use clap::Parser;
use ibsr_clock::{Clock, SystemClock};
use ibsr_reporter::config::{Allowlist, ReporterConfig};
use ibsr_reporter::counterfactual;
use ibsr_reporter::decision::{evaluate_key, Decision, KeyDecision};
use ibsr_reporter::ingest::{load_snapshots_from_dir, IngestError, SnapshotStream};
use ibsr_reporter::report::{self, Report};
use ibsr_reporter::rules::{self, EnforcementRules};
use ibsr_reporter::window;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "ibsr-report")]
#[command(version, about = "Generate IBSR reports from collector snapshots")]
struct Args {
    /// Input directory containing collector output (snapshot_*.jsonl files)
    #[arg(short = 'i', long = "in")]
    input_dir: PathBuf,

    /// Output directory for generated files (rules.json, report.md, evidence.csv)
    #[arg(short = 'o', long = "out")]
    output_dir: PathBuf,

    /// Destination TCP ports as comma-separated list (e.g., 8899,8900)
    #[arg(long = "dst-ports", value_delimiter = ',')]
    dst_ports: Vec<u16>,

    /// Path to allowlist file (one IP or CIDR per line)
    #[arg(long)]
    allowlist: Option<PathBuf>,

    /// Aggregation window size in seconds
    #[arg(long, default_value_t = 10)]
    window_sec: u64,

    /// SYN rate threshold (SYNs per second)
    #[arg(long, default_value_t = 100.0)]
    syn_rate_threshold: f64,

    /// Success ratio threshold (ACK/SYN)
    #[arg(long, default_value_t = 0.1)]
    success_ratio_threshold: f64,

    /// Block duration in seconds
    #[arg(long, default_value_t = 300)]
    block_duration_sec: u64,

    /// False positive safe ratio
    #[arg(long, default_value_t = 0.5)]
    fp_safe_ratio: f64,

    /// Minimum samples for FP calculation
    #[arg(long, default_value_t = 10)]
    min_samples_for_fp: usize,

    /// Increase verbosity (-v for warnings, -vv for debug)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Debug, thiserror::Error)]
enum ReportError {
    #[error("input directory does not exist: {0}")]
    InputNotFound(PathBuf),

    #[error("at least one destination port is required (use --dst-ports)")]
    NoPortsSpecified,

    #[error("failed to load snapshots: {0}")]
    Ingest(#[from] IngestError),

    #[error("failed to parse allowlist {path}: {reason}")]
    AllowlistParse { path: String, reason: String },

    #[error("failed to create output directory: {0}")]
    OutputDirCreate(std::io::Error),

    #[error("failed to write {file}: {source}")]
    WriteError {
        file: String,
        #[source]
        source: std::io::Error,
    },
}

fn main() -> ExitCode {
    let args = Args::parse();

    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(exit_code(&e))
        }
    }
}

fn exit_code(err: &ReportError) -> u8 {
    match err {
        ReportError::InputNotFound(_) | ReportError::NoPortsSpecified => 2,
        ReportError::AllowlistParse { .. } => 3,
        ReportError::Ingest(_) | ReportError::OutputDirCreate(_) | ReportError::WriteError { .. } => {
            1
        }
    }
}

fn run(args: Args) -> Result<(), ReportError> {
    // Validate inputs
    if !args.input_dir.exists() {
        return Err(ReportError::InputNotFound(args.input_dir));
    }
    if args.dst_ports.is_empty() {
        return Err(ReportError::NoPortsSpecified);
    }

    // Build config
    let config = build_config(&args)?;

    // Load snapshots
    let stream = if args.verbose > 0 {
        load_snapshots_from_dir(&args.input_dir, Some(|loc: &str, err: &str| {
            eprintln!("warning: {loc}: {err}");
        }))?
    } else {
        load_snapshots_from_dir::<fn(&str, &str)>(&args.input_dir, None)?
    };

    // Get current timestamp for rules generation
    let clock = SystemClock;
    let current_ts = clock.now_unix_sec();

    // Execute pipeline
    let (report, rules, decisions) = execute_pipeline(&stream, &config, current_ts);

    // Create output directory
    std::fs::create_dir_all(&args.output_dir).map_err(ReportError::OutputDirCreate)?;

    // Write outputs
    let rules_path = args.output_dir.join("rules.json");
    std::fs::write(&rules_path, rules.to_json()).map_err(|e| ReportError::WriteError {
        file: "rules.json".to_string(),
        source: e,
    })?;

    let report_path = args.output_dir.join("report.md");
    std::fs::write(&report_path, &report.content).map_err(|e| ReportError::WriteError {
        file: "report.md".to_string(),
        source: e,
    })?;

    let evidence_path = args.output_dir.join("evidence.csv");
    std::fs::write(&evidence_path, generate_evidence_csv(&decisions)).map_err(|e| {
        ReportError::WriteError {
            file: "evidence.csv".to_string(),
            source: e,
        }
    })?;

    // Print summary
    println!("Generated files in {}:", args.output_dir.display());
    println!("  - rules.json");
    println!("  - report.md");
    println!("  - evidence.csv");

    let blocked_count = decisions
        .iter()
        .filter(|d| matches!(d.decision, Decision::Block { .. }))
        .count();
    println!(
        "\nAnalyzed {} sources, {} would be blocked",
        decisions.len(),
        blocked_count
    );

    if report.readiness.is_safe {
        println!("\nReadiness: SAFE for autonomous enforcement");
    } else {
        println!("\nReadiness: NOT SAFE for autonomous enforcement");
        for reason in &report.readiness.reasons {
            println!("  - {reason}");
        }
    }

    Ok(())
}

fn build_config(args: &Args) -> Result<ReporterConfig, ReportError> {
    let mut config = ReporterConfig::new(args.dst_ports.clone())
        .with_window_sec(args.window_sec)
        .with_syn_rate_threshold(args.syn_rate_threshold)
        .with_success_ratio_threshold(args.success_ratio_threshold)
        .with_block_duration_sec(args.block_duration_sec)
        .with_fp_safe_ratio(args.fp_safe_ratio)
        .with_min_samples_for_fp(args.min_samples_for_fp);

    if let Some(allowlist_path) = &args.allowlist {
        let content = std::fs::read_to_string(allowlist_path).map_err(|e| {
            ReportError::AllowlistParse {
                path: allowlist_path.display().to_string(),
                reason: e.to_string(),
            }
        })?;
        let allowlist = parse_allowlist(&content, allowlist_path)?;
        config = config.with_allowlist(allowlist);
    }

    Ok(config)
}

fn parse_allowlist(content: &str, path: &PathBuf) -> Result<Allowlist, ReportError> {
    let mut allowlist = Allowlist::empty();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let result = if line.contains('/') {
            allowlist.add_cidr_str(line)
        } else {
            allowlist.add_ip_str(line)
        };

        if let Err(e) = result {
            return Err(ReportError::AllowlistParse {
                path: path.display().to_string(),
                reason: format!("line {}: {}", line_num + 1, e),
            });
        }
    }

    Ok(allowlist)
}

fn execute_pipeline(
    snapshots: &SnapshotStream,
    config: &ReporterConfig,
    current_ts: u64,
) -> (Report, EnforcementRules, Vec<KeyDecision>) {
    let bounds = snapshots.bounds();

    // Extract dst_ports from first snapshot if available, otherwise use config
    let dst_ports = snapshots
        .snapshots()
        .first()
        .map(|s| s.dst_ports.clone())
        .unwrap_or_else(|| config.dst_ports.clone());

    // Create config with correct dst_ports
    let mut config = config.clone();
    config.dst_ports = dst_ports;

    // Aggregate statistics
    let snapshot_refs: Vec<_> = snapshots.snapshots().iter().collect();
    let aggregated = window::aggregate_snapshots(&snapshot_refs, config.window_sec);
    let sorted = window::sorted_aggregated(&aggregated);

    // Evaluate decisions
    let decisions: Vec<KeyDecision> = sorted
        .iter()
        .map(|(key, stats)| evaluate_key(*key, *stats, &config, current_ts))
        .collect();

    // Compute counterfactual
    let counterfactual = counterfactual::compute(&decisions, &config);

    // Generate rules and report
    let rules = rules::generate(&counterfactual.top_offenders, &config, current_ts);
    let report = report::generate(&bounds, &config, &counterfactual, &rules);

    (report, rules, decisions)
}

fn generate_evidence_csv(decisions: &[KeyDecision]) -> String {
    let mut lines = Vec::with_capacity(decisions.len() + 1);

    // Header
    lines.push("source,syn_rate,success_ratio,decision,packets,bytes,syn".to_string());

    // Sort decisions for deterministic output
    let mut sorted: Vec<_> = decisions.iter().collect();
    sorted.sort_by_key(|d| d.key);

    // Data rows
    for d in sorted {
        let source = d.key.to_display_string();
        let decision_str = match d.decision {
            Decision::Allow => "allow",
            Decision::Block { .. } => "block",
        };

        lines.push(format!(
            "{},{:.2},{:.4},{},{},{},{}",
            source,
            d.stats.syn_rate,
            d.stats.success_ratio,
            decision_str,
            d.stats.total_packets,
            d.stats.total_bytes,
            d.stats.total_syn,
        ));
    }

    let mut result = lines.join("\n");
    result.push('\n');
    result
}
