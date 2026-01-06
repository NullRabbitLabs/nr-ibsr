//! CLI argument parsing for IBSR.
//!
//! Provides command-line interface for the ibsr binary with the collect subcommand.

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
/// Kept for backwards compatibility with lib exports.
pub const DEFAULT_WINDOW_SEC: u64 = 10;

/// Maximum number of destination ports that can be monitored.
pub const MAX_DST_PORTS: usize = 8;

/// Errors from CLI argument validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CliError {
    #[error("dst-port must be between 1 and 65535, got {0}")]
    InvalidPort(u32),

    #[error("at least one destination port is required")]
    NoPortsSpecified,

    #[error("too many destination ports specified: {0} (max {MAX_DST_PORTS})")]
    TooManyPorts(usize),

    #[error("duplicate destination port: {0}")]
    DuplicatePort(u16),

    #[error("max-files must be at least 1, got {0}")]
    InvalidMaxFiles(usize),

    #[error("max-age must be at least 1 second, got {0}")]
    InvalidMaxAge(u64),

    #[error("map-size must be at least 1, got {0}")]
    InvalidMapSize(u32),
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
}

/// Default report interval in seconds.
pub const DEFAULT_REPORT_INTERVAL_SEC: u64 = 60;

/// Default snapshot interval in seconds.
pub const DEFAULT_SNAPSHOT_INTERVAL_SEC: u64 = 60;

/// Arguments for the collect command.
#[derive(Parser, Debug, Clone, PartialEq, Eq)]
pub struct CollectArgs {
    /// Destination TCP port(s) to monitor (repeatable, e.g., -p 8899 -p 8900).
    /// Maximum 8 ports. At least one port is required.
    #[arg(short = 'p', long = "dst-port", action = clap::ArgAction::Append)]
    pub dst_port: Vec<u16>,

    /// Destination TCP ports as comma-separated list (e.g., --dst-ports 8899,8900).
    /// Can be combined with -p flags. Maximum 8 ports total.
    #[arg(long = "dst-ports", value_delimiter = ',')]
    pub dst_ports: Option<Vec<u16>>,

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

    /// Increase verbosity (-v for verbose, -vv for debug).
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Interval for status reports in seconds.
    #[arg(long, default_value_t = DEFAULT_REPORT_INTERVAL_SEC)]
    pub report_interval_sec: u64,

    /// Interval for writing snapshots to disk in seconds.
    /// Internal counter reads still happen every second; this controls file emission.
    #[arg(long, default_value_t = DEFAULT_SNAPSHOT_INTERVAL_SEC)]
    pub snapshot_interval_sec: u64,
}

impl CollectArgs {
    /// Get all destination ports, merging -p and --dst-ports arguments.
    ///
    /// Returns a deduplicated, sorted list of ports.
    pub fn get_all_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self.dst_port.clone();
        if let Some(ref extra) = self.dst_ports {
            ports.extend(extra.iter().copied());
        }
        // Deduplicate and sort
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Validate the arguments.
    pub fn validate(&self) -> Result<(), CliError> {
        let ports = self.get_all_ports();

        // Check at least one port is specified
        if ports.is_empty() {
            return Err(CliError::NoPortsSpecified);
        }

        // Check not too many ports
        if ports.len() > MAX_DST_PORTS {
            return Err(CliError::TooManyPorts(ports.len()));
        }

        // Check all ports are valid (non-zero)
        for &port in &ports {
            if port == 0 {
                return Err(CliError::InvalidPort(0));
            }
        }

        // Check for duplicates (before dedup, to report the actual duplicate)
        let mut seen = std::collections::HashSet::new();
        for &port in &self.dst_port {
            if !seen.insert(port) {
                return Err(CliError::DuplicatePort(port));
            }
        }
        if let Some(ref extra) = self.dst_ports {
            for &port in extra {
                if !seen.insert(port) {
                    return Err(CliError::DuplicatePort(port));
                }
            }
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
    // Test Category E - CLI Argument Parsing
    // ===========================================

    // --- Required --dst-port flag ---

    #[test]
    fn test_collect_requires_dst_port() {
        let cli = parse_from(["ibsr", "collect"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                let result = args.validate();
                assert!(matches!(result, Err(CliError::NoPortsSpecified)));
            }
        }
    }

    #[test]
    fn test_collect_with_dst_port_short() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.dst_port, vec![8899]);
            }
        }
    }

    #[test]
    fn test_collect_with_dst_port_long() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.dst_port, vec![8899]);
            }
        }
    }

    #[test]
    fn test_collect_dst_port_max_value() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "65535"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.dst_port, vec![65535]);
            }
        }
    }

    #[test]
    fn test_collect_dst_port_min_value() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "1"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.dst_port, vec![1]);
            }
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
        }
    }

    #[test]
    fn test_collect_default_max_files() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.max_files, DEFAULT_MAX_FILES);
            }
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
        }
    }

    #[test]
    fn test_collect_default_max_age() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.max_age, DEFAULT_MAX_AGE_SECS);
            }
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
        }
    }

    #[test]
    fn test_collect_default_map_size() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.map_size, DEFAULT_MAP_SIZE);
            }
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
        }
    }

    #[test]
    fn test_collect_default_iface_is_none() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert!(args.iface.is_none());
            }
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
        }
    }

    #[test]
    fn test_collect_iface_short() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899", "-i", "enp0s3"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.iface, Some("enp0s3".to_string()));
            }
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
                assert_eq!(args.dst_port, vec![8899]);
                assert_eq!(args.iface, Some("eth0".to_string()));
                assert_eq!(args.out_dir, PathBuf::from("/data/snapshots"));
                assert_eq!(args.max_files, 1000);
                assert_eq!(args.max_age, 3600);
                assert_eq!(args.map_size, 200000);
            }
        }
    }

    #[test]
    fn test_collect_valid_args_validate() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert!(args.validate().is_ok());
            }
        }
    }

    // --- Error messages ---

    #[test]
    fn test_error_display_invalid_port() {
        let err = CliError::InvalidPort(0);
        assert_eq!(err.to_string(), "dst-port must be between 1 and 65535, got 0");
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

    // --- Verbose and Report Interval Flags ---

    #[test]
    fn test_collect_verbose_flag_none() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.verbose, 0);
            }
        }
    }

    #[test]
    fn test_collect_verbose_flag_single() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899", "-v"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.verbose, 1);
            }
        }
    }

    #[test]
    fn test_collect_verbose_flag_double() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899", "-vv"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.verbose, 2);
            }
        }
    }

    #[test]
    fn test_collect_verbose_flag_separate() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899", "-v", "-v"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.verbose, 2);
            }
        }
    }

    #[test]
    fn test_collect_report_interval_default() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.report_interval_sec, 60);
            }
        }
    }

    #[test]
    fn test_collect_report_interval_custom() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899", "--report-interval-sec", "30"])
            .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.report_interval_sec, 30);
            }
        }
    }

    // --- Multi-Port Validation Tests ---

    #[test]
    fn test_collect_too_many_ports() {
        // MAX_DST_PORTS is 8, so try 9 ports
        let cli = parse_from([
            "ibsr", "collect",
            "-p", "8001", "-p", "8002", "-p", "8003", "-p", "8004",
            "-p", "8005", "-p", "8006", "-p", "8007", "-p", "8008",
            "-p", "8009", // 9th port - exceeds MAX_DST_PORTS
        ])
        .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                let result = args.validate();
                assert!(result.is_err());
                assert!(matches!(result.unwrap_err(), CliError::TooManyPorts(9)));
            }
        }
    }

    #[test]
    fn test_collect_exactly_max_ports_allowed() {
        // MAX_DST_PORTS is 8, verify exactly 8 ports works
        let cli = parse_from([
            "ibsr", "collect",
            "-p", "8001", "-p", "8002", "-p", "8003", "-p", "8004",
            "-p", "8005", "-p", "8006", "-p", "8007", "-p", "8008",
        ])
        .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                let result = args.validate();
                assert!(result.is_ok()); // Should succeed with exactly 8 ports
            }
        }
    }

    #[test]
    fn test_collect_duplicate_port_in_dst_port() {
        let cli = parse_from([
            "ibsr", "collect",
            "-p", "8899",
            "-p", "8899", // duplicate
        ])
        .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                let result = args.validate();
                assert!(result.is_err());
                assert!(matches!(result.unwrap_err(), CliError::DuplicatePort(8899)));
            }
        }
    }

    #[test]
    fn test_collect_duplicate_port_in_dst_ports() {
        let cli = parse_from([
            "ibsr", "collect",
            "--dst-ports", "8899,9000,8899", // duplicate 8899
        ])
        .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                let result = args.validate();
                assert!(result.is_err());
                assert!(matches!(result.unwrap_err(), CliError::DuplicatePort(8899)));
            }
        }
    }

    #[test]
    fn test_collect_duplicate_port_across_flags() {
        let cli = parse_from([
            "ibsr", "collect",
            "-p", "8899",
            "--dst-ports", "9000,8899", // 8899 duplicates -p flag
        ])
        .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                let result = args.validate();
                assert!(result.is_err());
                assert!(matches!(result.unwrap_err(), CliError::DuplicatePort(8899)));
            }
        }
    }

    #[test]
    fn test_collect_get_all_ports_merges_both_flags() {
        let cli = parse_from([
            "ibsr", "collect",
            "-p", "8899",
            "-p", "8900",
            "--dst-ports", "9000,9001",
        ])
        .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                let ports = args.get_all_ports();
                assert_eq!(ports.len(), 4);
                assert!(ports.contains(&8899));
                assert!(ports.contains(&8900));
                assert!(ports.contains(&9000));
                assert!(ports.contains(&9001));
            }
        }
    }

    #[test]
    fn test_error_display_no_ports_specified() {
        let err = CliError::NoPortsSpecified;
        assert_eq!(err.to_string(), "at least one destination port is required");
    }

    #[test]
    fn test_error_display_too_many_ports() {
        let err = CliError::TooManyPorts(10);
        assert_eq!(err.to_string(), "too many destination ports specified: 10 (max 8)");
    }

    #[test]
    fn test_error_display_duplicate_port() {
        let err = CliError::DuplicatePort(8899);
        assert_eq!(err.to_string(), "duplicate destination port: 8899");
    }

    #[test]
    fn test_error_display_zero_port() {
        let err = CliError::InvalidPort(0);
        assert_eq!(err.to_string(), "dst-port must be between 1 and 65535, got 0");
    }

    // --- Report and Run commands no longer exist ---

    #[test]
    fn test_report_command_not_recognized() {
        let result = parse_from(["ibsr", "report", "--in", "/tmp", "--out-dir", "/tmp"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_run_command_not_recognized() {
        let result = parse_from([
            "ibsr", "run", "--dst-port", "8899", "--duration-sec", "60", "--out-dir", "/tmp",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_only_collect_command_exists() {
        // Verify that Collect is the only variant
        let cli = parse_from(["ibsr", "collect", "-p", "8899"]).expect("parse");
        // This will compile only if Collect is the only variant
        let Command::Collect(_) = cli.command;
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
        let Command::Collect(args1) = cli1.command;
        let Command::Collect(args2) = cli2.command;
        assert_eq!(args1, args2);
    }

    #[test]
    fn test_collect_args_inequality() {
        let cli1 = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        let cli2 = parse_from(["ibsr", "collect", "--dst-port", "9000"]).expect("parse");
        let Command::Collect(args1) = cli1.command;
        let Command::Collect(args2) = cli2.command;
        assert_ne!(args1, args2);
    }

    #[test]
    fn test_cli_error_debug() {
        let err = CliError::InvalidPort(0);
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("InvalidPort"));
    }
}
