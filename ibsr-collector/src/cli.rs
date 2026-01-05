//! CLI argument parsing for IBSR.
//!
//! Provides command-line interface for the unified ibsr binary with
//! collect, report, and run subcommands.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use thiserror::Error;

/// Default output directory for snapshots.
pub const DEFAULT_OUTPUT_DIR: &str = "/var/lib/ibsr/snapshots";

/// Default maximum number of snapshot files to retain.
pub const DEFAULT_MAX_FILES: usize = 3600;

/// Default maximum age of snapshots in seconds (24 hours).
pub const DEFAULT_MAX_AGE_SECS: u64 = 86400;

/// Default LRU map size for BPF counters.
pub const DEFAULT_MAP_SIZE: u32 = 100_000;

/// Default window size for report analysis in seconds.
pub const DEFAULT_WINDOW_SEC: u64 = 10;

/// Errors from CLI argument validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CliError {
    #[error("dst-port must be between 1 and 65535, got {0}")]
    InvalidPort(u32),

    #[error("max-files must be at least 1, got {0}")]
    InvalidMaxFiles(usize),

    #[error("max-age must be at least 1 second, got {0}")]
    InvalidMaxAge(u64),

    #[error("map-size must be at least 1, got {0}")]
    InvalidMapSize(u32),

    #[error("window-sec must be at least 1, got {0}")]
    InvalidWindowSec(u64),

    #[error("duration-sec must be at least 1 for run command, got {0}")]
    InvalidDurationSec(u64),
}

/// IBSR XDP Collector - Passive traffic metrics collection for Solana validators.
#[derive(Parser, Debug, Clone, PartialEq)]
#[command(name = "ibsr")]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Available commands.
#[derive(Subcommand, Debug, Clone, PartialEq)]
pub enum Command {
    /// Start collecting traffic metrics.
    Collect(CollectArgs),
    /// Generate report from collected snapshots.
    Report(ReportArgs),
    /// Run collection for a duration, then generate report.
    Run(RunArgs),
}

/// Arguments for the collect command.
#[derive(Parser, Debug, Clone, PartialEq, Eq)]
pub struct CollectArgs {
    /// Destination TCP port to monitor (required).
    /// This should be the port your Solana validator uses (e.g., 8899 for RPC).
    #[arg(short = 'p', long = "dst-port")]
    pub dst_port: u16,

    /// Duration to collect in seconds. If not specified, runs until SIGINT.
    #[arg(long)]
    pub duration_sec: Option<u64>,

    /// Network interface to attach XDP program to.
    /// If not specified, uses the interface with the default route.
    #[arg(short, long)]
    pub iface: Option<String>,

    /// Output directory for snapshot files.
    #[arg(short, long, default_value = DEFAULT_OUTPUT_DIR)]
    pub out_dir: PathBuf,

    /// Maximum number of snapshot files to retain.
    #[arg(long, default_value_t = DEFAULT_MAX_FILES)]
    pub max_files: usize,

    /// Maximum age of snapshot files in seconds.
    #[arg(long, default_value_t = DEFAULT_MAX_AGE_SECS)]
    pub max_age: u64,

    /// Size of the BPF LRU map for tracking source IPs.
    #[arg(long, default_value_t = DEFAULT_MAP_SIZE)]
    pub map_size: u32,
}

impl CollectArgs {
    /// Validate the arguments.
    pub fn validate(&self) -> Result<(), CliError> {
        if self.dst_port == 0 {
            return Err(CliError::InvalidPort(self.dst_port as u32));
        }
        if self.max_files == 0 {
            return Err(CliError::InvalidMaxFiles(self.max_files));
        }
        if self.max_age == 0 {
            return Err(CliError::InvalidMaxAge(self.max_age));
        }
        if self.map_size == 0 {
            return Err(CliError::InvalidMapSize(self.map_size));
        }
        Ok(())
    }
}

/// Arguments for the report command.
#[derive(Parser, Debug, Clone, PartialEq)]
pub struct ReportArgs {
    /// Input directory containing snapshot files (required).
    #[arg(long = "in")]
    pub input_dir: PathBuf,

    /// Output directory for report artifacts (required).
    #[arg(long = "out-dir")]
    pub out_dir: PathBuf,

    /// Path to allowlist file (one IP or CIDR per line).
    #[arg(long)]
    pub allowlist: Option<PathBuf>,

    /// Analysis window size in seconds.
    #[arg(long, default_value_t = DEFAULT_WINDOW_SEC)]
    pub window_sec: u64,

    /// Override SYN rate threshold (SYNs per second).
    #[arg(long)]
    pub syn_rate_threshold: Option<f64>,

    /// Override success ratio threshold (ACK/SYN ratio).
    #[arg(long)]
    pub success_ratio_threshold: Option<f64>,

    /// Override block duration in seconds.
    #[arg(long)]
    pub block_duration_sec: Option<u64>,
}

impl ReportArgs {
    /// Validate the arguments.
    pub fn validate(&self) -> Result<(), CliError> {
        if self.window_sec == 0 {
            return Err(CliError::InvalidWindowSec(self.window_sec));
        }
        Ok(())
    }
}

/// Arguments for the run command (collect then report).
#[derive(Parser, Debug, Clone, PartialEq)]
pub struct RunArgs {
    /// Destination TCP port to monitor (required).
    #[arg(short = 'p', long = "dst-port")]
    pub dst_port: u16,

    /// Duration to collect in seconds (required for run).
    #[arg(long)]
    pub duration_sec: u64,

    /// Network interface to attach XDP program to.
    #[arg(short, long)]
    pub iface: Option<String>,

    /// Directory for snapshot files.
    #[arg(long, default_value = DEFAULT_OUTPUT_DIR)]
    pub snapshot_dir: PathBuf,

    /// Maximum number of snapshot files to retain.
    #[arg(long, default_value_t = DEFAULT_MAX_FILES)]
    pub max_files: usize,

    /// Maximum age of snapshot files in seconds.
    #[arg(long, default_value_t = DEFAULT_MAX_AGE_SECS)]
    pub max_age: u64,

    /// Size of the BPF LRU map for tracking source IPs.
    #[arg(long, default_value_t = DEFAULT_MAP_SIZE)]
    pub map_size: u32,

    /// Output directory for report artifacts (required).
    #[arg(long = "out-dir")]
    pub out_dir: PathBuf,

    /// Path to allowlist file (one IP or CIDR per line).
    #[arg(long)]
    pub allowlist: Option<PathBuf>,

    /// Analysis window size in seconds.
    #[arg(long, default_value_t = DEFAULT_WINDOW_SEC)]
    pub window_sec: u64,

    /// Override SYN rate threshold (SYNs per second).
    #[arg(long)]
    pub syn_rate_threshold: Option<f64>,

    /// Override success ratio threshold (ACK/SYN ratio).
    #[arg(long)]
    pub success_ratio_threshold: Option<f64>,

    /// Override block duration in seconds.
    #[arg(long)]
    pub block_duration_sec: Option<u64>,
}

impl RunArgs {
    /// Validate the arguments.
    pub fn validate(&self) -> Result<(), CliError> {
        if self.dst_port == 0 {
            return Err(CliError::InvalidPort(self.dst_port as u32));
        }
        if self.duration_sec == 0 {
            return Err(CliError::InvalidDurationSec(self.duration_sec));
        }
        if self.max_files == 0 {
            return Err(CliError::InvalidMaxFiles(self.max_files));
        }
        if self.max_age == 0 {
            return Err(CliError::InvalidMaxAge(self.max_age));
        }
        if self.map_size == 0 {
            return Err(CliError::InvalidMapSize(self.map_size));
        }
        if self.window_sec == 0 {
            return Err(CliError::InvalidWindowSec(self.window_sec));
        }
        Ok(())
    }

    /// Convert to CollectArgs for the collect phase.
    pub fn to_collect_args(&self) -> CollectArgs {
        CollectArgs {
            dst_port: self.dst_port,
            duration_sec: Some(self.duration_sec),
            iface: self.iface.clone(),
            out_dir: self.snapshot_dir.clone(),
            max_files: self.max_files,
            max_age: self.max_age,
            map_size: self.map_size,
        }
    }

    /// Convert to ReportArgs for the report phase.
    pub fn to_report_args(&self) -> ReportArgs {
        ReportArgs {
            input_dir: self.snapshot_dir.clone(),
            out_dir: self.out_dir.clone(),
            allowlist: self.allowlist.clone(),
            window_sec: self.window_sec,
            syn_rate_threshold: self.syn_rate_threshold,
            success_ratio_threshold: self.success_ratio_threshold,
            block_duration_sec: self.block_duration_sec,
        }
    }
}

/// Parse CLI arguments from an iterator of strings.
/// Useful for testing.
pub fn parse_from<I, T>(iter: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    Cli::try_parse_from(iter)
}

/// Get the default network interface (the one with the default route).
/// Returns None if no default interface can be determined.
pub fn default_interface() -> Option<String> {
    // Read /proc/net/route to find default gateway interface
    let route_content = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_route_table(&route_content)
}

/// Parse /proc/net/route content to find the default interface.
/// Extracted for testability.
pub fn parse_route_table(content: &str) -> Option<String> {
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 2 {
            let destination = fields[1];
            // Default route has destination 00000000
            if destination == "00000000" {
                return Some(fields[0].to_string());
            }
        }
    }

    None
}

/// Resolve the interface to use: explicit argument or auto-detected default.
pub fn resolve_interface(explicit: Option<&str>) -> Option<String> {
    explicit.map(String::from).or_else(default_interface)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===========================================
    // Test Category E — CLI Argument Parsing
    // ===========================================

    // --- Required --dst-port flag ---

    #[test]
    fn test_collect_requires_dst_port() {
        let result = parse_from(["ibsr", "collect"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("--dst-port"));
    }

    #[test]
    fn test_collect_with_dst_port_short() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.dst_port, 8899);
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_with_dst_port_long() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.dst_port, 8899);
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_dst_port_max_value() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "65535"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.dst_port, 65535);
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_dst_port_min_value() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "1"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.dst_port, 1);
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_dst_port_zero_validation() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "0"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                let result = args.validate();
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), CliError::InvalidPort(0));
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_dst_port_overflow() {
        // Port > 65535 should fail parsing
        let result = parse_from(["ibsr", "collect", "--dst-port", "65536"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_collect_dst_port_negative() {
        let result = parse_from(["ibsr", "collect", "--dst-port", "-1"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_collect_dst_port_non_numeric() {
        let result = parse_from(["ibsr", "collect", "--dst-port", "abc"]);
        assert!(result.is_err());
    }

    // --- duration-sec optional ---

    #[test]
    fn test_collect_duration_sec_optional() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert!(args.duration_sec.is_none());
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_duration_sec_provided() {
        let cli =
            parse_from(["ibsr", "collect", "--dst-port", "8899", "--duration-sec", "60"])
                .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.duration_sec, Some(60));
            }
            _ => panic!("expected Collect"),
        }
    }

    // --- Optional flags with defaults ---

    #[test]
    fn test_collect_default_out_dir() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.out_dir, PathBuf::from(DEFAULT_OUTPUT_DIR));
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_custom_out_dir() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899", "--out-dir", "/tmp/snapshots"])
            .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.out_dir, PathBuf::from("/tmp/snapshots"));
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_out_dir_short() {
        let cli =
            parse_from(["ibsr", "collect", "-p", "8899", "-o", "/tmp/out"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.out_dir, PathBuf::from("/tmp/out"));
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_default_max_files() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.max_files, DEFAULT_MAX_FILES);
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_custom_max_files() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899", "--max-files", "100"])
            .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.max_files, 100);
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_max_files_zero_validation() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899", "--max-files", "0"])
            .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                let result = args.validate();
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), CliError::InvalidMaxFiles(0));
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_default_max_age() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.max_age, DEFAULT_MAX_AGE_SECS);
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_custom_max_age() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899", "--max-age", "7200"])
            .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.max_age, 7200);
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_max_age_zero_validation() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899", "--max-age", "0"])
            .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                let result = args.validate();
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), CliError::InvalidMaxAge(0));
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_default_map_size() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.map_size, DEFAULT_MAP_SIZE);
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_custom_map_size() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899", "--map-size", "50000"])
            .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.map_size, 50000);
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_map_size_zero_validation() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899", "--map-size", "0"])
            .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                let result = args.validate();
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), CliError::InvalidMapSize(0));
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_default_iface_is_none() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert!(args.iface.is_none());
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_custom_iface() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899", "--iface", "eth0"])
            .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.iface, Some("eth0".to_string()));
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_iface_short() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899", "-i", "enp0s3"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.iface, Some("enp0s3".to_string()));
            }
            _ => panic!("expected Collect"),
        }
    }

    // --- All arguments combined ---

    #[test]
    fn test_collect_all_args() {
        let cli = parse_from([
            "ibsr",
            "collect",
            "--dst-port",
            "8899",
            "--iface",
            "eth0",
            "--out-dir",
            "/data/snapshots",
            "--max-files",
            "1000",
            "--max-age",
            "3600",
            "--map-size",
            "200000",
        ])
        .expect("parse");

        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.dst_port, 8899);
                assert_eq!(args.iface, Some("eth0".to_string()));
                assert_eq!(args.out_dir, PathBuf::from("/data/snapshots"));
                assert_eq!(args.max_files, 1000);
                assert_eq!(args.max_age, 3600);
                assert_eq!(args.map_size, 200000);
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_valid_args_validate() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert!(args.validate().is_ok());
            }
            _ => panic!("expected Collect"),
        }
    }

    // --- Error messages ---

    #[test]
    fn test_error_display_invalid_port() {
        let err = CliError::InvalidPort(0);
        assert_eq!(err.to_string(), "dst-port must be between 1 and 65535, got 0");
    }

    #[test]
    fn test_error_display_invalid_window_sec() {
        let err = CliError::InvalidWindowSec(0);
        assert_eq!(err.to_string(), "window-sec must be at least 1, got 0");
    }

    #[test]
    fn test_error_display_invalid_duration_sec() {
        let err = CliError::InvalidDurationSec(0);
        assert_eq!(err.to_string(), "duration-sec must be at least 1 for run command, got 0");
    }

    #[test]
    fn test_error_display_invalid_max_files() {
        let err = CliError::InvalidMaxFiles(0);
        assert_eq!(err.to_string(), "max-files must be at least 1, got 0");
    }

    #[test]
    fn test_error_display_invalid_max_age() {
        let err = CliError::InvalidMaxAge(0);
        assert_eq!(err.to_string(), "max-age must be at least 1 second, got 0");
    }

    #[test]
    fn test_error_display_invalid_map_size() {
        let err = CliError::InvalidMapSize(0);
        assert_eq!(err.to_string(), "map-size must be at least 1, got 0");
    }

    // --- Interface auto-detection ---

    #[test]
    fn test_resolve_interface_explicit() {
        let result = resolve_interface(Some("eth0"));
        assert_eq!(result, Some("eth0".to_string()));
    }

    #[test]
    fn test_resolve_interface_none_falls_back() {
        // When explicit is None, falls back to default_interface()
        // Result depends on system state, but function should not panic
        let result = resolve_interface(None);
        // Can be Some or None depending on /proc/net/route
        // Just verify it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_default_interface_returns_option() {
        // This test verifies the function doesn't panic and returns valid result
        // The actual result depends on the system
        let result = default_interface();
        // On systems without /proc/net/route (like macOS), returns None
        // On Linux with networking, returns Some(interface_name)
        // Either None or Some with non-empty string is valid
        if let Some(iface) = result {
            assert!(!iface.is_empty());
        }
    }

    // --- Route table parsing ---

    #[test]
    fn test_parse_route_table_with_default_route() {
        let content = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\tFFFFFFFF\t0\t0\t0";
        let result = parse_route_table(content);
        assert_eq!(result, Some("eth0".to_string()));
    }

    #[test]
    fn test_parse_route_table_different_interface() {
        let content = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
enp0s3\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0";
        let result = parse_route_table(content);
        assert_eq!(result, Some("enp0s3".to_string()));
    }

    #[test]
    fn test_parse_route_table_no_default_route() {
        let content = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\tFFFFFFFF\t0\t0\t0";
        let result = parse_route_table(content);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_route_table_empty_content() {
        let result = parse_route_table("");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_route_table_header_only() {
        let content = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT";
        let result = parse_route_table(content);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_route_table_malformed_line_short() {
        // Line with only one field
        let content = "Iface\tDestination\tGateway
eth0";
        let result = parse_route_table(content);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_route_table_default_route_not_first() {
        let content = "Iface\tDestination\tGateway\tFlags
eth0\t0002A8C0\t00000000\t0001
wlan0\t00000000\t0102A8C0\t0003";
        let result = parse_route_table(content);
        assert_eq!(result, Some("wlan0".to_string()));
    }

    #[test]
    fn test_parse_route_table_whitespace_separated() {
        // Tabs or spaces should both work
        let content = "Iface Destination Gateway
eth0 00000000 0102A8C0";
        let result = parse_route_table(content);
        assert_eq!(result, Some("eth0".to_string()));
    }

    // --- Constants ---

    #[test]
    fn test_default_constants() {
        assert_eq!(DEFAULT_OUTPUT_DIR, "/var/lib/ibsr/snapshots");
        assert_eq!(DEFAULT_MAX_FILES, 3600);
        assert_eq!(DEFAULT_MAX_AGE_SECS, 86400);
        assert_eq!(DEFAULT_MAP_SIZE, 100_000);
        assert_eq!(DEFAULT_WINDOW_SEC, 10);
    }

    // --- Help and version ---

    #[test]
    fn test_help_flag() {
        let result = parse_from(["ibsr", "--help"]);
        assert!(result.is_err());
        // Help triggers an "error" exit but with DisplayHelp kind
        let err = result.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn test_version_flag() {
        let result = parse_from(["ibsr", "--version"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn test_collect_help() {
        let result = parse_from(["ibsr", "collect", "--help"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    // --- Unknown arguments ---

    #[test]
    fn test_unknown_flag() {
        let result = parse_from(["ibsr", "collect", "--dst-port", "8899", "--unknown"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_subcommand() {
        let result = parse_from(["ibsr", "unknown"]);
        assert!(result.is_err());
    }

    // --- Equality and Clone ---

    #[test]
    fn test_cli_equality() {
        let cli1 = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        let cli2 = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        assert_eq!(cli1, cli2);
    }

    #[test]
    fn test_cli_clone() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        let cloned = cli.clone();
        assert_eq!(cli, cloned);
    }

    #[test]
    fn test_collect_args_debug() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        let debug_str = format!("{:?}", cli);
        assert!(debug_str.contains("Collect"));
        assert!(debug_str.contains("8899"));
    }

    // ===========================================
    // Test Category F — Report Command
    // ===========================================

    #[test]
    fn test_report_requires_in() {
        let result = parse_from(["ibsr", "report", "--out-dir", "/tmp/out"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("--in"));
    }

    #[test]
    fn test_report_requires_out_dir() {
        let result = parse_from(["ibsr", "report", "--in", "/tmp/snapshots"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("--out-dir"));
    }

    #[test]
    fn test_report_with_required_args() {
        let cli = parse_from([
            "ibsr", "report", "--in", "/tmp/snapshots", "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Report(args) => {
                assert_eq!(args.input_dir, PathBuf::from("/tmp/snapshots"));
                assert_eq!(args.out_dir, PathBuf::from("/tmp/output"));
            }
            _ => panic!("expected Report"),
        }
    }

    #[test]
    fn test_report_default_window_sec() {
        let cli = parse_from([
            "ibsr", "report", "--in", "/tmp/snapshots", "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Report(args) => {
                assert_eq!(args.window_sec, DEFAULT_WINDOW_SEC);
            }
            _ => panic!("expected Report"),
        }
    }

    #[test]
    fn test_report_custom_window_sec() {
        let cli = parse_from([
            "ibsr", "report", "--in", "/tmp/snapshots", "--out-dir", "/tmp/output",
            "--window-sec", "30",
        ])
        .expect("parse");
        match cli.command {
            Command::Report(args) => {
                assert_eq!(args.window_sec, 30);
            }
            _ => panic!("expected Report"),
        }
    }

    #[test]
    fn test_report_window_sec_zero_validation() {
        let cli = parse_from([
            "ibsr", "report", "--in", "/tmp/snapshots", "--out-dir", "/tmp/output",
            "--window-sec", "0",
        ])
        .expect("parse");
        match cli.command {
            Command::Report(args) => {
                let result = args.validate();
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), CliError::InvalidWindowSec(0));
            }
            _ => panic!("expected Report"),
        }
    }

    #[test]
    fn test_report_allowlist_optional() {
        let cli = parse_from([
            "ibsr", "report", "--in", "/tmp/snapshots", "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Report(args) => {
                assert!(args.allowlist.is_none());
            }
            _ => panic!("expected Report"),
        }
    }

    #[test]
    fn test_report_allowlist_provided() {
        let cli = parse_from([
            "ibsr", "report", "--in", "/tmp/snapshots", "--out-dir", "/tmp/output",
            "--allowlist", "/tmp/allowlist.txt",
        ])
        .expect("parse");
        match cli.command {
            Command::Report(args) => {
                assert_eq!(args.allowlist, Some(PathBuf::from("/tmp/allowlist.txt")));
            }
            _ => panic!("expected Report"),
        }
    }

    #[test]
    fn test_report_threshold_overrides() {
        let cli = parse_from([
            "ibsr", "report", "--in", "/tmp/snapshots", "--out-dir", "/tmp/output",
            "--syn-rate-threshold", "200.0",
            "--success-ratio-threshold", "0.05",
            "--block-duration-sec", "600",
        ])
        .expect("parse");
        match cli.command {
            Command::Report(args) => {
                assert_eq!(args.syn_rate_threshold, Some(200.0));
                assert_eq!(args.success_ratio_threshold, Some(0.05));
                assert_eq!(args.block_duration_sec, Some(600));
            }
            _ => panic!("expected Report"),
        }
    }

    #[test]
    fn test_report_valid_args_validate() {
        let cli = parse_from([
            "ibsr", "report", "--in", "/tmp/snapshots", "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Report(args) => {
                assert!(args.validate().is_ok());
            }
            _ => panic!("expected Report"),
        }
    }

    #[test]
    fn test_report_help() {
        let result = parse_from(["ibsr", "report", "--help"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    // ===========================================
    // Test Category G — Run Command
    // ===========================================

    #[test]
    fn test_run_requires_dst_port() {
        let result = parse_from([
            "ibsr", "run", "--duration-sec", "60", "--out-dir", "/tmp/output",
        ]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("--dst-port"));
    }

    #[test]
    fn test_run_requires_duration_sec() {
        let result = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--out-dir", "/tmp/output",
        ]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("--duration-sec"));
    }

    #[test]
    fn test_run_requires_out_dir() {
        let result = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
        ]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("--out-dir"));
    }

    #[test]
    fn test_run_with_required_args() {
        let cli = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                assert_eq!(args.dst_port, 8899);
                assert_eq!(args.duration_sec, 60);
                assert_eq!(args.out_dir, PathBuf::from("/tmp/output"));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_run_dst_port_short() {
        let cli = parse_from([
            "ibsr", "run", "-p", "8899", "--duration-sec", "60", "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                assert_eq!(args.dst_port, 8899);
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_run_defaults() {
        let cli = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                assert_eq!(args.snapshot_dir, PathBuf::from(DEFAULT_OUTPUT_DIR));
                assert_eq!(args.max_files, DEFAULT_MAX_FILES);
                assert_eq!(args.max_age, DEFAULT_MAX_AGE_SECS);
                assert_eq!(args.map_size, DEFAULT_MAP_SIZE);
                assert_eq!(args.window_sec, DEFAULT_WINDOW_SEC);
                assert!(args.iface.is_none());
                assert!(args.allowlist.is_none());
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_run_all_args() {
        let cli = parse_from([
            "ibsr", "run",
            "--dst-port", "8899",
            "--duration-sec", "60",
            "--iface", "eth0",
            "--snapshot-dir", "/data/snapshots",
            "--max-files", "1000",
            "--max-age", "3600",
            "--map-size", "50000",
            "--out-dir", "/data/output",
            "--allowlist", "/data/allowlist.txt",
            "--window-sec", "30",
            "--syn-rate-threshold", "200.0",
            "--success-ratio-threshold", "0.05",
            "--block-duration-sec", "600",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                assert_eq!(args.dst_port, 8899);
                assert_eq!(args.duration_sec, 60);
                assert_eq!(args.iface, Some("eth0".to_string()));
                assert_eq!(args.snapshot_dir, PathBuf::from("/data/snapshots"));
                assert_eq!(args.max_files, 1000);
                assert_eq!(args.max_age, 3600);
                assert_eq!(args.map_size, 50000);
                assert_eq!(args.out_dir, PathBuf::from("/data/output"));
                assert_eq!(args.allowlist, Some(PathBuf::from("/data/allowlist.txt")));
                assert_eq!(args.window_sec, 30);
                assert_eq!(args.syn_rate_threshold, Some(200.0));
                assert_eq!(args.success_ratio_threshold, Some(0.05));
                assert_eq!(args.block_duration_sec, Some(600));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_run_dst_port_zero_validation() {
        let cli = parse_from([
            "ibsr", "run", "--dst-port", "0", "--duration-sec", "60",
            "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                let result = args.validate();
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), CliError::InvalidPort(0));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_run_duration_sec_zero_validation() {
        let cli = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "0",
            "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                let result = args.validate();
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), CliError::InvalidDurationSec(0));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_run_valid_args_validate() {
        let cli = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                assert!(args.validate().is_ok());
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_run_to_collect_args() {
        let cli = parse_from([
            "ibsr", "run",
            "--dst-port", "8899",
            "--duration-sec", "60",
            "--iface", "eth0",
            "--snapshot-dir", "/data/snapshots",
            "--max-files", "1000",
            "--max-age", "3600",
            "--map-size", "50000",
            "--out-dir", "/data/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                let collect_args = args.to_collect_args();
                assert_eq!(collect_args.dst_port, 8899);
                assert_eq!(collect_args.duration_sec, Some(60));
                assert_eq!(collect_args.iface, Some("eth0".to_string()));
                assert_eq!(collect_args.out_dir, PathBuf::from("/data/snapshots"));
                assert_eq!(collect_args.max_files, 1000);
                assert_eq!(collect_args.max_age, 3600);
                assert_eq!(collect_args.map_size, 50000);
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_run_to_report_args() {
        let cli = parse_from([
            "ibsr", "run",
            "--dst-port", "8899",
            "--duration-sec", "60",
            "--snapshot-dir", "/data/snapshots",
            "--out-dir", "/data/output",
            "--allowlist", "/data/allowlist.txt",
            "--window-sec", "30",
            "--syn-rate-threshold", "200.0",
            "--success-ratio-threshold", "0.05",
            "--block-duration-sec", "600",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                let report_args = args.to_report_args();
                assert_eq!(report_args.input_dir, PathBuf::from("/data/snapshots"));
                assert_eq!(report_args.out_dir, PathBuf::from("/data/output"));
                assert_eq!(report_args.allowlist, Some(PathBuf::from("/data/allowlist.txt")));
                assert_eq!(report_args.window_sec, 30);
                assert_eq!(report_args.syn_rate_threshold, Some(200.0));
                assert_eq!(report_args.success_ratio_threshold, Some(0.05));
                assert_eq!(report_args.block_duration_sec, Some(600));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_run_help() {
        let result = parse_from(["ibsr", "run", "--help"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn test_run_max_files_zero_validation() {
        let cli = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/output", "--max-files", "0",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                let result = args.validate();
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), CliError::InvalidMaxFiles(0));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_run_max_age_zero_validation() {
        let cli = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/output", "--max-age", "0",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                let result = args.validate();
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), CliError::InvalidMaxAge(0));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_run_map_size_zero_validation() {
        let cli = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/output", "--map-size", "0",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                let result = args.validate();
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), CliError::InvalidMapSize(0));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_run_window_sec_zero_validation() {
        let cli = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/output", "--window-sec", "0",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                let result = args.validate();
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), CliError::InvalidWindowSec(0));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_report_args_clone() {
        let cli = parse_from([
            "ibsr", "report", "--in", "/tmp/snapshots", "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Report(args) => {
                let cloned = args.clone();
                assert_eq!(args.input_dir, cloned.input_dir);
                assert_eq!(args.out_dir, cloned.out_dir);
            }
            _ => panic!("expected Report"),
        }
    }

    #[test]
    fn test_report_args_debug() {
        let cli = parse_from([
            "ibsr", "report", "--in", "/tmp/snapshots", "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Report(args) => {
                let debug_str = format!("{:?}", args);
                assert!(debug_str.contains("ReportArgs"));
                assert!(debug_str.contains("/tmp/snapshots"));
            }
            _ => panic!("expected Report"),
        }
    }

    #[test]
    fn test_run_args_clone() {
        let cli = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                let cloned = args.clone();
                assert_eq!(args.dst_port, cloned.dst_port);
                assert_eq!(args.duration_sec, cloned.duration_sec);
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_run_args_debug() {
        let cli = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                let debug_str = format!("{:?}", args);
                assert!(debug_str.contains("RunArgs"));
                assert!(debug_str.contains("8899"));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_command_report_equality() {
        let cli1 = parse_from([
            "ibsr", "report", "--in", "/tmp/snapshots", "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        let cli2 = parse_from([
            "ibsr", "report", "--in", "/tmp/snapshots", "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        assert_eq!(cli1, cli2);
    }

    #[test]
    fn test_command_run_equality() {
        let cli1 = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        let cli2 = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        assert_eq!(cli1, cli2);
    }

    #[test]
    fn test_to_collect_args_with_defaults() {
        let cli = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                let collect_args = args.to_collect_args();
                assert!(collect_args.iface.is_none());
                assert_eq!(collect_args.max_files, DEFAULT_MAX_FILES);
                assert_eq!(collect_args.max_age, DEFAULT_MAX_AGE_SECS);
                assert_eq!(collect_args.map_size, DEFAULT_MAP_SIZE);
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_to_report_args_with_defaults() {
        let cli = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                let report_args = args.to_report_args();
                assert!(report_args.allowlist.is_none());
                assert!(report_args.syn_rate_threshold.is_none());
                assert!(report_args.success_ratio_threshold.is_none());
                assert!(report_args.block_duration_sec.is_none());
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_report_thresholds_none_by_default() {
        let cli = parse_from([
            "ibsr", "report", "--in", "/tmp/snapshots", "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Report(args) => {
                assert!(args.syn_rate_threshold.is_none());
                assert!(args.success_ratio_threshold.is_none());
                assert!(args.block_duration_sec.is_none());
            }
            _ => panic!("expected Report"),
        }
    }

    #[test]
    fn test_run_iface_short() {
        let cli = parse_from([
            "ibsr", "run", "-p", "8899", "--duration-sec", "60", "-i", "eth0",
            "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match cli.command {
            Command::Run(args) => {
                assert_eq!(args.iface, Some("eth0".to_string()));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_cli_debug() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        let debug_str = format!("{:?}", cli);
        assert!(debug_str.contains("Cli"));
    }

    #[test]
    fn test_command_debug() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        let debug_str = format!("{:?}", cli.command);
        assert!(debug_str.contains("Collect"));
    }

    #[test]
    fn test_cli_error_equality() {
        let err1 = CliError::InvalidPort(0);
        let err2 = CliError::InvalidPort(0);
        assert_eq!(err1, err2);
    }

    #[test]
    fn test_cli_error_inequality() {
        let err1 = CliError::InvalidPort(0);
        let err2 = CliError::InvalidPort(1);
        assert_ne!(err1, err2);
    }

    #[test]
    fn test_collect_args_equality() {
        let cli1 = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        let cli2 = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match (cli1.command, cli2.command) {
            (Command::Collect(args1), Command::Collect(args2)) => {
                assert_eq!(args1, args2);
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_args_inequality() {
        let cli1 = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        let cli2 = parse_from(["ibsr", "collect", "--dst-port", "9000"]).expect("parse");
        match (cli1.command, cli2.command) {
            (Command::Collect(args1), Command::Collect(args2)) => {
                assert_ne!(args1, args2);
            }
            _ => panic!("expected Collect"),
        }
    }

    #[test]
    fn test_report_args_equality() {
        let cli1 = parse_from([
            "ibsr", "report", "--in", "/tmp/snapshots", "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        let cli2 = parse_from([
            "ibsr", "report", "--in", "/tmp/snapshots", "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match (cli1.command, cli2.command) {
            (Command::Report(args1), Command::Report(args2)) => {
                assert_eq!(args1, args2);
            }
            _ => panic!("expected Report"),
        }
    }

    #[test]
    fn test_run_args_equality() {
        let cli1 = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        let cli2 = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/output",
        ])
        .expect("parse");
        match (cli1.command, cli2.command) {
            (Command::Run(args1), Command::Run(args2)) => {
                assert_eq!(args1, args2);
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_cli_clone_deep() {
        let cli = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/output", "--allowlist", "/tmp/allow.txt",
        ])
        .expect("parse");
        let cloned = cli.clone();
        match (&cli.command, &cloned.command) {
            (Command::Run(args1), Command::Run(args2)) => {
                assert_eq!(args1.allowlist, args2.allowlist);
                assert_eq!(args1.dst_port, args2.dst_port);
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_report_with_all_threshold_overrides() {
        let cli = parse_from([
            "ibsr", "report",
            "--in", "/tmp/snapshots",
            "--out-dir", "/tmp/output",
            "--syn-rate-threshold", "50.5",
            "--success-ratio-threshold", "0.15",
            "--block-duration-sec", "900",
        ])
        .expect("parse");
        match cli.command {
            Command::Report(args) => {
                assert_eq!(args.syn_rate_threshold, Some(50.5));
                assert_eq!(args.success_ratio_threshold, Some(0.15));
                assert_eq!(args.block_duration_sec, Some(900));
            }
            _ => panic!("expected Report"),
        }
    }

    #[test]
    fn test_command_inequality_collect_vs_report() {
        let cli1 = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        let cli2 = parse_from([
            "ibsr", "report", "--in", "/tmp", "--out-dir", "/tmp/out",
        ])
        .expect("parse");
        assert_ne!(cli1, cli2);
    }

    #[test]
    fn test_command_inequality_collect_vs_run() {
        let cli1 = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        let cli2 = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60",
            "--out-dir", "/tmp/out",
        ])
        .expect("parse");
        assert_ne!(cli1, cli2);
    }

    #[test]
    fn test_cli_error_debug() {
        let err = CliError::InvalidPort(0);
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("InvalidPort"));
    }
}
