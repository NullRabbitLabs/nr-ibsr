//! CLI for generating IBSR reports from collector snapshots.

use clap::Parser;
use ibsr_clock::{Clock, SystemClock};
use ibsr_reporter::config::{Allowlist, ReporterConfig};
use ibsr_reporter::counterfactual;
use ibsr_reporter::abuse::DetectionConfidence;
use ibsr_reporter::decision::{evaluate_key, Decision, KeyDecision};
use ibsr_reporter::episode::{self, EpisodeConfig, EpisodeType};
use ibsr_reporter::ingest::{load_snapshots_from_dir, IngestError, SnapshotStream};
use ibsr_reporter::report::{self, Report};
use ibsr_reporter::rules::{self, EnforcementRules};
use ibsr_reporter::summary::{EpisodeSummary, Summary, SummaryBuilder};
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

    /// Output directory for generated files (rules.json, report.md, evidence.csv, summary.json)
    #[arg(short = 'o', long = "out")]
    output_dir: PathBuf,

    /// Destination TCP ports as comma-separated list (optional filter, inferred from snapshots if omitted)
    #[arg(long = "dst-ports", value_delimiter = ',')]
    dst_ports: Vec<u16>,

    /// Path to allowlist file (one IP or CIDR per line)
    #[arg(long)]
    allowlist: Option<PathBuf>,

    /// Aggregation window size in seconds
    #[arg(long, default_value_t = 10)]
    window_sec: u64,

    /// SYN flood: SYN rate threshold (SYNs per second)
    #[arg(long, default_value_t = 100.0)]
    syn_rate_threshold: f64,

    /// SYN flood: Success ratio threshold (ACK/SYN)
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

    /// Volumetric abuse: SYN rate threshold (SYNs per second)
    #[arg(long, default_value_t = 500.0)]
    vol_syn_rate: f64,

    /// Volumetric abuse: Packet rate threshold (packets per second)
    #[arg(long, default_value_t = 1000.0)]
    vol_pkt_rate: f64,

    /// Volumetric abuse: Byte rate threshold (bytes per second)
    #[arg(long, default_value_t = 1_000_000.0)]
    vol_byte_rate: f64,

    /// Increase verbosity (-v for warnings, -vv for debug)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Debug, thiserror::Error)]
enum ReportError {
    #[error("input directory does not exist: {0}")]
    InputNotFound(PathBuf),

    #[error("no destination ports found in snapshots or specified via --dst-ports")]
    NoPortsFound,

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
        ReportError::InputNotFound(_) | ReportError::NoPortsFound => 2,
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

    // Load snapshots first (to infer ports if not specified)
    let stream = if args.verbose > 0 {
        load_snapshots_from_dir(&args.input_dir, Some(|loc: &str, err: &str| {
            eprintln!("warning: {loc}: {err}");
        }))?
    } else {
        load_snapshots_from_dir::<fn(&str, &str)>(&args.input_dir, None)?
    };

    // Determine dst_ports: use CLI if provided, otherwise infer from snapshots
    let dst_ports = if args.dst_ports.is_empty() {
        let inferred = stream.inferred_dst_ports();
        if inferred.is_empty() {
            return Err(ReportError::NoPortsFound);
        }
        if args.verbose > 0 {
            eprintln!("info: inferred dst_ports from snapshots: {:?}", inferred);
        }
        inferred
    } else {
        // CLI ports act as a filter
        args.dst_ports.clone()
    };

    // Build config with determined ports
    let config = build_config(&args, dst_ports)?;

    // Get current timestamp for rules generation
    let clock = SystemClock;
    let current_ts = clock.now_unix_sec();

    // Execute pipeline
    let (report, rules, decisions, summary) = execute_pipeline(&stream, &config, current_ts);

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

    let summary_path = args.output_dir.join("summary.json");
    std::fs::write(&summary_path, summary.to_json()).map_err(|e| ReportError::WriteError {
        file: "summary.json".to_string(),
        source: e,
    })?;

    // Print summary
    println!("Generated files in {}:", args.output_dir.display());
    println!("  - rules.json");
    println!("  - report.md");
    println!("  - evidence.csv");
    println!("  - summary.json");

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

fn build_config(args: &Args, dst_ports: Vec<u16>) -> Result<ReporterConfig, ReportError> {
    let mut config = ReporterConfig::new(dst_ports)
        .with_window_sec(args.window_sec)
        .with_syn_rate_threshold(args.syn_rate_threshold)
        .with_success_ratio_threshold(args.success_ratio_threshold)
        .with_block_duration_sec(args.block_duration_sec)
        .with_fp_safe_ratio(args.fp_safe_ratio)
        .with_min_samples_for_fp(args.min_samples_for_fp)
        .with_vol_syn_rate(args.vol_syn_rate)
        .with_vol_pkt_rate(args.vol_pkt_rate)
        .with_vol_byte_rate(args.vol_byte_rate);

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
) -> (Report, EnforcementRules, Vec<KeyDecision>, Summary) {
    let bounds = snapshots.bounds();

    // Get run_id and schema versions from snapshots
    let run_id = snapshots.inferred_run_id().unwrap_or(0);
    let (schema_min, schema_max) = snapshots.schema_version_range();

    // Get interval_sec from first snapshot (default 60)
    let interval_sec = snapshots
        .snapshots()
        .first()
        .map(|s| s.interval_sec as u32)
        .unwrap_or(60);

    // Aggregate statistics using v2 (correct delta computation)
    let snapshot_refs: Vec<_> = snapshots.snapshots().iter().collect();
    let aggregated = window::aggregate_snapshots_v2(&snapshot_refs, config.window_sec);
    let sorted = window::sorted_aggregated(&aggregated);

    // Evaluate decisions
    let decisions: Vec<KeyDecision> = sorted
        .iter()
        .map(|(key, stats)| evaluate_key(*key, *stats, config, current_ts))
        .collect();

    // Compute counterfactual
    let counterfactual = counterfactual::compute(&decisions, config);

    // Episode detection
    let episode_config = EpisodeConfig {
        syn_rate_threshold: config.syn_rate_threshold,
        vol_syn_rate: config.vol_syn_rate,
        vol_pkt_rate: config.vol_pkt_rate,
        vol_byte_rate: config.vol_byte_rate,
        success_ratio_threshold: config.success_ratio_threshold,
        min_episode_intervals: 1, // Allow single-window episodes
    };
    let interval_stats = window::extract_interval_stats(&snapshot_refs, interval_sec as u64, config.window_sec);
    let episodes = episode::detect_episodes(&interval_stats, &episode_config, interval_sec);

    // Generate rules from episodes (episodes are the single source of truth)
    let rules = rules::generate_from_episodes(&episodes, config, current_ts);
    let report = report::generate(&bounds, config, &counterfactual, &rules, &episodes);

    // Build summary with episodes
    let episode_summaries: Vec<EpisodeSummary> = episodes
        .iter()
        .map(|ep| EpisodeSummary {
            src_ip: ep.src_ip.clone(),
            dst_port: ep.dst_port,
            start_ts: ep.start_ts,
            end_ts: ep.end_ts,
            duration_sec: ep.duration_sec,
            interval_count: ep.interval_count,
            interval_sec: ep.interval_sec,
            episode_type: match ep.episode_type {
                EpisodeType::SingleWindow => "single_window".to_string(),
                EpisodeType::MultiWindow => "multi_window".to_string(),
            },
            max_syn_rate: ep.max_syn_rate,
            max_pkt_rate: ep.max_pkt_rate,
            max_byte_rate: ep.max_byte_rate,
            abuse_class: ep.abuse_class.map(|c| c.to_string()).unwrap_or_default(),
            trigger_reason: ep.trigger_reason.clone(),
        })
        .collect();

    let summary_builder = SummaryBuilder::new(run_id, bounds)
        .with_schema_versions(schema_min, schema_max)
        .with_ports(config.dst_ports.clone())
        .with_window_sec(config.window_sec)
        .with_syn_thresholds(config.syn_rate_threshold, config.success_ratio_threshold)
        .with_block_duration(config.block_duration_sec)
        .with_volumetric_thresholds(config.vol_syn_rate, config.vol_pkt_rate, config.vol_byte_rate)
        .with_counterfactual(counterfactual)
        .with_episodes(episode_summaries);

    // Gate enforcement: single-window episodes require manual review
    let has_single_window = episodes.iter().any(|ep| ep.episode_type == EpisodeType::SingleWindow);
    let mut enforcement_reasons = report.readiness.reasons.clone();
    let enforcement_safe = if has_single_window {
        enforcement_reasons.push("Single-window episode requires manual review".to_string());
        false
    } else {
        report.readiness.is_safe
    };
    let mut summary_builder = summary_builder.with_enforcement(enforcement_safe, enforcement_reasons);

    // Add triggers from episodes (episodes are the single source of truth for rates)
    for ep in &episodes {
        if let Some(abuse_class) = ep.abuse_class {
            summary_builder.add_trigger(
                abuse_class,
                ep.src_ip.clone(),
                ep.dst_port,
                ep.max_syn_rate,
                ep.max_pkt_rate,
                ep.max_byte_rate,
                ep.min_success_ratio,
                DetectionConfidence::High, // Episodes represent confirmed detection
            );
        }
    }

    let summary = summary_builder.build();

    (report, rules, decisions, summary)
}

fn generate_evidence_csv(decisions: &[KeyDecision]) -> String {
    let mut lines = Vec::with_capacity(decisions.len() + 1);

    // Header
    lines.push("source,abuse_class,syn_rate,success_ratio,decision,packets,bytes,syn".to_string());

    // Sort decisions for deterministic output
    let mut sorted: Vec<_> = decisions.iter().collect();
    sorted.sort_by_key(|d| d.key);

    // Data rows
    for d in sorted {
        let source = d.key.to_display_string();
        let abuse_class = d.abuse_class.map(|c| c.to_string()).unwrap_or_else(|| "".to_string());
        let decision_str = match d.decision {
            Decision::Allow => "allow",
            Decision::Block { .. } => "block",
        };

        lines.push(format!(
            "{},{},{:.2},{:.4},{},{},{},{}",
            source,
            abuse_class,
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
