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

    #[error("window-sec must be at least 1 second, got {0}")]
    InvalidWindowSec(u64),

    #[error("max-flows must be at least 1, got {0}")]
    InvalidMaxFlows(usize),

    #[error("sample-rate must be at least 1, got {0}")]
    InvalidSampleRate(u64),

    #[error("incident tag must be 1..=64 chars and match [a-zA-Z0-9_-], got {0:?}")]
    InvalidIncidentTag(String),
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
    /// Start collecting traffic metrics (StrictCounter mode — XDP counters).
    Collect(CollectArgs),
    /// Start collecting payload-aware response aggregates (ShadowPayload
    /// mode — TC ingress/egress + userspace HTTP parser). Used at
    /// operator-controlled boundaries (validator infra, edge proxies)
    /// for application-layer attack detection.
    CollectPayload(CollectPayloadArgs),
    /// Sampled packet capture for incident recording (CF-style "under
    /// attack mode"). TC ingress/egress program samples 1-in-N packets,
    /// userspace writes pcap files. Per
    /// docs/CF-INCIDENT-RECORDING-DESIGN-V1.md.
    RecordIncident(RecordIncidentArgs),
}

/// Default status interval in seconds (for status.jsonl updates).
pub const DEFAULT_STATUS_INTERVAL_SEC: u64 = 60;

/// Default snapshot interval in seconds.
pub const DEFAULT_SNAPSHOT_INTERVAL_SEC: u64 = 60;

/// Default output directory for ShadowPayload-mode snapshots. Distinct
/// from StrictCounter's path so the two modes can run on the same box
/// without overlapping output.
pub const DEFAULT_PAYLOAD_OUTPUT_DIR: &str = "/var/lib/ibsr/snapshots-payload";

/// Default flow-table cap for ShadowPayload-mode userspace handler.
/// Bounded memory: at full cap the handler LRU-evicts.
pub const DEFAULT_MAX_FLOWS: usize = 8192;

/// Default ringbuf size in bytes (16 MiB). Tunable at deployment time;
/// must match or be smaller than the compile-time `RINGBUFFER_BYTES`
/// in `tc_payload.bpf.c`.
pub const DEFAULT_RINGBUF_BYTES: usize = 16 * 1024 * 1024;

/// Default snapshot-emission window for ShadowPayload mode.
pub const DEFAULT_PAYLOAD_WINDOW_SEC: u64 = 60;

/// Default output directory for record-incident mode pcap files.
/// Distinct from the other modes so a multi-mode deployment doesn't
/// clobber.
pub const DEFAULT_RECORD_OUTPUT_DIR: &str = "/var/lib/ibsr/incidents";

/// Default sample rate — 1-in-1000 packets, the CF baseline. Operators
/// can drop to 1 (capture every packet) on trigger; a future Phase 2
/// runtime trigger will mutate this from outside the BPF program via
/// the config_map.
pub const DEFAULT_SAMPLE_RATE: u64 = 1000;

/// Default network interface for record-incident. Defaults to `lo`
/// for the same reason ShadowPayload does — post-term loopback is the
/// canonical recording vantage on hyperscaler-style boxes.
pub const DEFAULT_RECORD_IFACE: &str = "lo";

/// Default Unix socket path for the record-incident trigger socket.
/// Per docs/CF-INCIDENT-RECORDING-DESIGN-V1.md §"Trigger-socket auth",
/// access is gated by filesystem permissions.
pub const DEFAULT_TRIGGER_SOCKET_PATH: &str = "/var/run/ibsr.sock";

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

    /// Increase verbosity (-v for verbose, -vv for debug).
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Interval for status.jsonl updates in seconds.
    #[arg(long, default_value_t = DEFAULT_STATUS_INTERVAL_SEC)]
    pub status_interval_sec: u64,

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
        Ok(())
    }
}

/// Arguments for the `collect-payload` subcommand (ShadowPayload mode).
///
/// Mirrors `CollectArgs` for shared options (ports, output, rotation,
/// verbosity) and adds payload-mode-specific tunables: window size,
/// flow-table cap, ringbuf size.
#[derive(Parser, Debug, Clone, PartialEq, Eq)]
pub struct CollectPayloadArgs {
    /// Server-side TCP port(s) to monitor (repeatable, e.g., -p 8899).
    /// Filters both directions: dst_port==server (request) AND
    /// src_port==server (response). Maximum 8 ports.
    #[arg(short = 'p', long = "dst-port", action = clap::ArgAction::Append)]
    pub dst_port: Vec<u16>,

    /// Server-side TCP ports as comma-separated list. Combinable with -p.
    #[arg(long = "dst-ports", value_delimiter = ',')]
    pub dst_ports: Option<Vec<u16>>,

    /// Duration to collect in seconds. If not specified, runs until SIGINT.
    #[arg(long)]
    pub duration_sec: Option<u64>,

    /// Network interface for TC attach. Defaults to `lo` — the post-term
    /// loopback vantage where nginx-decrypted traffic flows toward the
    /// validator. Override only when the deployment topology differs.
    #[arg(short, long, default_value = "lo")]
    pub iface: String,

    /// Output directory for snapshot files (separate from StrictCounter
    /// path so both modes can coexist).
    #[arg(short, long, default_value = DEFAULT_PAYLOAD_OUTPUT_DIR)]
    pub out_dir: PathBuf,

    /// Maximum number of snapshot files to retain.
    #[arg(long, default_value_t = DEFAULT_MAX_FILES)]
    pub max_files: usize,

    /// Maximum age of snapshot files in seconds.
    #[arg(long, default_value_t = DEFAULT_MAX_AGE_SECS)]
    pub max_age: u64,

    /// Window for snapshot emission in seconds. Smaller windows give
    /// finer time resolution at the cost of higher write rate.
    #[arg(long, default_value_t = DEFAULT_PAYLOAD_WINDOW_SEC)]
    pub window_sec: u64,

    /// Userspace flow-table cap. At capacity the handler LRU-evicts;
    /// bounded memory.
    #[arg(long, default_value_t = DEFAULT_MAX_FLOWS)]
    pub max_flows: usize,

    /// BPF ringbuf size in bytes. Larger = more headroom on userspace
    /// stalls; smaller = lower memory cost. Lossy on overflow by design.
    #[arg(long, default_value_t = DEFAULT_RINGBUF_BYTES)]
    pub ringbuf_bytes: usize,

    /// Increase verbosity (-v for verbose, -vv for debug).
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Interval for status.jsonl updates in seconds.
    #[arg(long, default_value_t = DEFAULT_STATUS_INTERVAL_SEC)]
    pub status_interval_sec: u64,
}

impl CollectPayloadArgs {
    /// Get all server ports, merging -p and --dst-ports arguments.
    pub fn get_all_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self.dst_port.clone();
        if let Some(ref extra) = self.dst_ports {
            ports.extend(extra.iter().copied());
        }
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Validate the arguments. Same port + rotation rules as CollectArgs;
    /// adds window_sec > 0 and max_flows > 0 checks.
    pub fn validate(&self) -> Result<(), CliError> {
        let ports = self.get_all_ports();
        if ports.is_empty() {
            return Err(CliError::NoPortsSpecified);
        }
        if ports.len() > MAX_DST_PORTS {
            return Err(CliError::TooManyPorts(ports.len()));
        }
        for &port in &ports {
            if port == 0 {
                return Err(CliError::InvalidPort(0));
            }
        }
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
        if self.window_sec == 0 {
            return Err(CliError::InvalidWindowSec(self.window_sec));
        }
        if self.max_flows == 0 {
            return Err(CliError::InvalidMaxFlows(self.max_flows));
        }
        Ok(())
    }
}

/// Arguments for the `record-incident` subcommand (CF-style sampled
/// capture). Phase 1: static sample-rate from CLI. Phase 2 will add
/// a config_map subscription for runtime rate changes; the CLI value
/// becomes the initial setting.
#[derive(Parser, Debug, Clone, PartialEq, Eq)]
pub struct RecordIncidentArgs {
    /// Network interface for TC attach. Defaults to `lo` — same
    /// post-term-loopback vantage as collect-payload.
    #[arg(short, long, default_value = DEFAULT_RECORD_IFACE)]
    pub iface: String,

    /// Output directory for pcap files. Each invocation lands in a
    /// timestamped subdirectory; phase 4 will add per-trigger
    /// partitioning.
    #[arg(short = 'o', long, default_value = DEFAULT_RECORD_OUTPUT_DIR)]
    pub out_dir: PathBuf,

    /// Incident tag — short identifier baked into the output dir name.
    /// 1..=64 ASCII chars, [a-zA-Z0-9_-] only.
    #[arg(long, default_value = "ad-hoc")]
    pub tag: String,

    /// Sampling rate: 1-in-N packets are captured. `1` = every packet.
    /// Phase 1: static for the duration of the run.
    #[arg(long, default_value_t = DEFAULT_SAMPLE_RATE)]
    pub sample_rate: u64,

    /// Duration to capture in seconds. If not specified, runs until SIGINT.
    #[arg(long)]
    pub duration_sec: Option<u64>,

    /// Increase verbosity (-v, -vv).
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Interval for status.jsonl updates in seconds.
    #[arg(long, default_value_t = DEFAULT_STATUS_INTERVAL_SEC)]
    pub status_interval_sec: u64,

    /// Enable the trigger socket for runtime sample-rate / trigger /
    /// stop / status commands. Defaults off — when omitted, the
    /// recording runs at the static --sample-rate for the requested
    /// duration.
    #[arg(long)]
    pub trigger_socket: Option<PathBuf>,

    /// Per-customer salt for IPv4 hashing (16 hex chars). When set,
    /// every captured packet's src + dst IPv4 addresses are replaced
    /// with FNV-1a-64(salt || ip). Different salts produce
    /// uncorrelated hashed outputs across customers / runs.
    #[arg(long)]
    pub scrub_ip_salt: Option<String>,

    /// CIDR of an "internal" subnet (e.g., the operator's
    /// service-mesh range). Packets where BOTH src and dst are
    /// inside this subnet are dropped from the pcap output. Repeat
    /// the flag for multiple subnets.
    #[arg(long)]
    pub scrub_internal_subnet: Option<String>,

    /// Hot-tier per-pcap byte cap. When the current pcap exceeds this
    /// size, the sink rotates to a new file in the same out-dir with
    /// a freshly-stamped tag-ts directory. Operators bound disk
    /// usage with this + `--archive-after-sec`.
    #[arg(long)]
    pub max_pcap_bytes: Option<u64>,

    /// Archive directory: pcap files in `--out-dir` older than
    /// `--archive-after-sec` are gzipped into here. When `None`, no
    /// archiving happens (operator handles via cron / logrotate).
    #[arg(long)]
    pub archive_dir: Option<PathBuf>,

    /// Age threshold (seconds) before a pcap file is moved to the
    /// archive dir. Default 3600 (1 hour).
    #[arg(long, default_value_t = 3600)]
    pub archive_after_sec: u64,
}

impl RecordIncidentArgs {
    /// Validate the arguments. Sample-rate must be ≥ 1; tag must
    /// match the safe-on-disk character set so it can be used in the
    /// output directory name without escaping.
    pub fn validate(&self) -> Result<(), CliError> {
        if self.sample_rate < 1 {
            return Err(CliError::InvalidSampleRate(self.sample_rate));
        }
        if !is_valid_incident_tag(&self.tag) {
            return Err(CliError::InvalidIncidentTag(self.tag.clone()));
        }
        // Scrub flags are validated in execute_record_incident via
        // scrub::parse_ip_salt / parse_subnet to surface rich error
        // messages without coupling cli.rs to the scrub module.
        Ok(())
    }
}

/// Validates an incident tag: 1..=64 chars, [a-zA-Z0-9_-] only.
/// Pure function so tests can pin the exact charset.
pub fn is_valid_incident_tag(tag: &str) -> bool {
    let len = tag.chars().count();
    if !(1..=64).contains(&len) {
        return false;
    }
    tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
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
            _ => unreachable!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_with_dst_port_short() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.dst_port, vec![8899]);
            }
            _ => unreachable!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_with_dst_port_long() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.dst_port, vec![8899]);
            }
            _ => unreachable!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_dst_port_max_value() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "65535"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.dst_port, vec![65535]);
            }
            _ => unreachable!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_dst_port_min_value() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "1"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.dst_port, vec![1]);
            }
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_default_max_files() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.max_files, DEFAULT_MAX_FILES);
            }
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_default_max_age() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.max_age, DEFAULT_MAX_AGE_SECS);
            }
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_default_iface_is_none() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert!(args.iface.is_none());
            }
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_iface_short() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899", "-i", "enp0s3"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.iface, Some("enp0s3".to_string()));
            }
            _ => unreachable!("expected Collect"),
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
        ])
        .expect("parse");

        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.dst_port, vec![8899]);
                assert_eq!(args.iface, Some("eth0".to_string()));
                assert_eq!(args.out_dir, PathBuf::from("/data/snapshots"));
                assert_eq!(args.max_files, 1000);
                assert_eq!(args.max_age, 3600);
            }
            _ => unreachable!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_valid_args_validate() {
        let cli = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert!(args.validate().is_ok());
            }
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_verbose_flag_single() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899", "-v"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.verbose, 1);
            }
            _ => unreachable!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_verbose_flag_double() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899", "-vv"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.verbose, 2);
            }
            _ => unreachable!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_verbose_flag_separate() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899", "-v", "-v"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.verbose, 2);
            }
            _ => unreachable!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_status_interval_default() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899"]).expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.status_interval_sec, 60);
            }
            _ => unreachable!("expected Collect"),
        }
    }

    #[test]
    fn test_collect_status_interval_custom() {
        let cli = parse_from(["ibsr", "collect", "-p", "8899", "--status-interval-sec", "30"])
            .expect("parse");
        match cli.command {
            Command::Collect(args) => {
                assert_eq!(args.status_interval_sec, 30);
            }
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
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
            _ => unreachable!("expected Collect"),
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
        let Command::Collect(_) = cli.command else { panic!("expected Collect"); };
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
        let Command::Collect(args1) = cli1.command else { panic!("expected Collect"); };
        let Command::Collect(args2) = cli2.command else { panic!("expected Collect"); };
        assert_eq!(args1, args2);
    }

    #[test]
    fn test_collect_args_inequality() {
        let cli1 = parse_from(["ibsr", "collect", "--dst-port", "8899"]).expect("parse");
        let cli2 = parse_from(["ibsr", "collect", "--dst-port", "9000"]).expect("parse");
        let Command::Collect(args1) = cli1.command else { panic!("expected Collect"); };
        let Command::Collect(args2) = cli2.command else { panic!("expected Collect"); };
        assert_ne!(args1, args2);
    }

    #[test]
    fn test_cli_error_debug() {
        let err = CliError::InvalidPort(0);
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("InvalidPort"));
    }

    // ===========================================
    // Test Category F — collect-payload subcommand (ShadowPayload mode)
    // TDD: tests for argument parsing + validation written first;
    // implementation iterated until all pass.
    // ===========================================

    fn parse_payload(argv: &[&str]) -> CollectPayloadArgs {
        let cli = parse_from(argv).expect("parse");
        match cli.command {
            Command::CollectPayload(a) => a,
            _ => panic!("expected CollectPayload"),
        }
    }

    #[test]
    fn payload_subcommand_parses_minimal_args() {
        let args = parse_payload(&["ibsr", "collect-payload", "-p", "8899"]);
        assert_eq!(args.dst_port, vec![8899]);
        assert!(args.validate().is_ok());
    }

    #[test]
    fn payload_subcommand_iface_defaults_to_lo() {
        let args = parse_payload(&["ibsr", "collect-payload", "-p", "8899"]);
        assert_eq!(args.iface, "lo",
            "post-term loopback is the canonical vantage; default is lo");
    }

    #[test]
    fn payload_subcommand_iface_overridable() {
        let args = parse_payload(&["ibsr", "collect-payload", "-p", "8899", "-i", "eth0"]);
        assert_eq!(args.iface, "eth0");
    }

    #[test]
    fn payload_subcommand_window_sec_defaults_to_60() {
        let args = parse_payload(&["ibsr", "collect-payload", "-p", "8899"]);
        assert_eq!(args.window_sec, DEFAULT_PAYLOAD_WINDOW_SEC);
        assert_eq!(args.window_sec, 60);
    }

    #[test]
    fn payload_subcommand_max_flows_defaults_to_8192() {
        let args = parse_payload(&["ibsr", "collect-payload", "-p", "8899"]);
        assert_eq!(args.max_flows, DEFAULT_MAX_FLOWS);
        assert_eq!(args.max_flows, 8192);
    }

    #[test]
    fn payload_subcommand_ringbuf_bytes_defaults_to_16mib() {
        let args = parse_payload(&["ibsr", "collect-payload", "-p", "8899"]);
        assert_eq!(args.ringbuf_bytes, DEFAULT_RINGBUF_BYTES);
        assert_eq!(args.ringbuf_bytes, 16 * 1024 * 1024);
    }

    #[test]
    fn payload_subcommand_out_dir_distinct_from_collect() {
        // Prevent the two modes from clobbering each other on the same
        // box.
        let args = parse_payload(&["ibsr", "collect-payload", "-p", "8899"]);
        assert_eq!(args.out_dir.to_str(), Some(DEFAULT_PAYLOAD_OUTPUT_DIR));
        assert_ne!(
            args.out_dir.to_str(),
            Some(DEFAULT_OUTPUT_DIR),
            "ShadowPayload out-dir must differ from StrictCounter's by default",
        );
    }

    #[test]
    fn payload_subcommand_multiple_ports_repeated() {
        let args = parse_payload(&[
            "ibsr", "collect-payload", "-p", "8899", "-p", "9000",
        ]);
        assert_eq!(args.get_all_ports(), vec![8899, 9000]);
    }

    #[test]
    fn payload_subcommand_multiple_ports_via_dst_ports_csv() {
        let args = parse_payload(&[
            "ibsr", "collect-payload", "--dst-ports", "8899,9000,9001",
        ]);
        assert_eq!(args.get_all_ports(), vec![8899, 9000, 9001]);
    }

    #[test]
    fn payload_subcommand_validates_no_ports() {
        let args = parse_payload(&["ibsr", "collect-payload"]);
        assert_eq!(args.validate(), Err(CliError::NoPortsSpecified));
    }

    #[test]
    fn payload_subcommand_validates_too_many_ports() {
        let args = parse_payload(&[
            "ibsr", "collect-payload", "--dst-ports", "1,2,3,4,5,6,7,8,9",
        ]);
        match args.validate() {
            Err(CliError::TooManyPorts(9)) => {}
            other => panic!("expected TooManyPorts(9), got {:?}", other),
        }
    }

    #[test]
    fn payload_subcommand_validates_zero_port() {
        let args = parse_payload(&["ibsr", "collect-payload", "-p", "0"]);
        assert_eq!(args.validate(), Err(CliError::InvalidPort(0)));
    }

    #[test]
    fn payload_subcommand_validates_duplicate_port() {
        let args = parse_payload(&[
            "ibsr", "collect-payload", "-p", "8899", "-p", "8899",
        ]);
        assert_eq!(args.validate(), Err(CliError::DuplicatePort(8899)));
    }

    #[test]
    fn payload_subcommand_validates_zero_window() {
        let args = parse_payload(&[
            "ibsr", "collect-payload", "-p", "8899", "--window-sec", "0",
        ]);
        assert_eq!(args.validate(), Err(CliError::InvalidWindowSec(0)));
    }

    #[test]
    fn payload_subcommand_validates_zero_max_flows() {
        let args = parse_payload(&[
            "ibsr", "collect-payload", "-p", "8899", "--max-flows", "0",
        ]);
        assert_eq!(args.validate(), Err(CliError::InvalidMaxFlows(0)));
    }

    #[test]
    fn payload_subcommand_validates_zero_max_files() {
        let args = parse_payload(&[
            "ibsr", "collect-payload", "-p", "8899", "--max-files", "0",
        ]);
        assert_eq!(args.validate(), Err(CliError::InvalidMaxFiles(0)));
    }

    #[test]
    fn payload_subcommand_validates_zero_max_age() {
        let args = parse_payload(&[
            "ibsr", "collect-payload", "-p", "8899", "--max-age", "0",
        ]);
        assert_eq!(args.validate(), Err(CliError::InvalidMaxAge(0)));
    }

    #[test]
    fn payload_subcommand_get_all_ports_dedupes() {
        let args = parse_payload(&[
            "ibsr", "collect-payload",
            "-p", "8899", "-p", "9000",
            "--dst-ports", "8899,9001",
        ]);
        let ports = args.get_all_ports();
        // get_all_ports dedupes within itself; the validator catches the
        // duplicate cross-source.
        assert_eq!(ports, vec![8899, 9000, 9001]);
    }

    #[test]
    fn payload_subcommand_subcommand_distinct_from_collect() {
        // Pin: the two subcommands are routable independently.
        let cli_collect = parse_from(["ibsr", "collect", "-p", "8899"]).expect("parse");
        let cli_payload = parse_from(["ibsr", "collect-payload", "-p", "8899"]).expect("parse");
        assert!(matches!(cli_collect.command, Command::Collect(_)));
        assert!(matches!(cli_payload.command, Command::CollectPayload(_)));
    }

    #[test]
    fn payload_subcommand_max_8_ports_via_csv_passes() {
        let args = parse_payload(&[
            "ibsr", "collect-payload", "--dst-ports", "8899,9000,9001,9002,9003,9004,9005,9006",
        ]);
        assert!(args.validate().is_ok(), "8 ports is the limit, must pass");
    }

    #[test]
    fn payload_subcommand_window_sec_overridable() {
        let args = parse_payload(&[
            "ibsr", "collect-payload", "-p", "8899", "--window-sec", "10",
        ]);
        assert_eq!(args.window_sec, 10);
        assert!(args.validate().is_ok());
    }

    // ===========================================
    // Test Category G — record-incident subcommand
    // ===========================================

    fn parse_record(argv: &[&str]) -> RecordIncidentArgs {
        let cli = parse_from(argv).expect("parse");
        match cli.command {
            Command::RecordIncident(a) => a,
            _ => panic!("expected RecordIncident"),
        }
    }

    #[test]
    fn record_subcommand_parses_minimal_args() {
        let args = parse_record(&["ibsr", "record-incident"]);
        assert_eq!(args.iface, DEFAULT_RECORD_IFACE);
        assert_eq!(args.tag, "ad-hoc");
        assert_eq!(args.sample_rate, DEFAULT_SAMPLE_RATE);
        assert!(args.validate().is_ok());
    }

    #[test]
    fn record_subcommand_iface_defaults_to_lo() {
        let args = parse_record(&["ibsr", "record-incident"]);
        assert_eq!(args.iface, "lo");
    }

    #[test]
    fn record_subcommand_iface_overridable() {
        let args = parse_record(&["ibsr", "record-incident", "-i", "eth0"]);
        assert_eq!(args.iface, "eth0");
    }

    #[test]
    fn record_subcommand_tag_overridable() {
        let args = parse_record(&["ibsr", "record-incident", "--tag", "incident-abc"]);
        assert_eq!(args.tag, "incident-abc");
    }

    #[test]
    fn record_subcommand_default_out_dir() {
        let args = parse_record(&["ibsr", "record-incident"]);
        assert_eq!(args.out_dir, PathBuf::from(DEFAULT_RECORD_OUTPUT_DIR));
    }

    #[test]
    fn record_subcommand_default_sample_rate_is_1000() {
        let args = parse_record(&["ibsr", "record-incident"]);
        assert_eq!(args.sample_rate, 1000);
    }

    #[test]
    fn record_subcommand_custom_sample_rate() {
        let args = parse_record(&["ibsr", "record-incident", "--sample-rate", "1"]);
        assert_eq!(args.sample_rate, 1);
        assert!(args.validate().is_ok());
    }

    #[test]
    fn record_subcommand_validates_zero_sample_rate() {
        let args = parse_record(&["ibsr", "record-incident", "--sample-rate", "0"]);
        assert_eq!(args.validate(), Err(CliError::InvalidSampleRate(0)));
    }

    #[test]
    fn record_subcommand_validates_invalid_tag_with_slash() {
        let args = parse_record(&["ibsr", "record-incident", "--tag", "bad/slash"]);
        assert!(matches!(args.validate(), Err(CliError::InvalidIncidentTag(_))));
    }

    #[test]
    fn record_subcommand_validates_invalid_tag_with_dot_dot() {
        // Path-traversal attempt — must be rejected.
        let args = parse_record(&["ibsr", "record-incident", "--tag", "..abc"]);
        assert!(matches!(args.validate(), Err(CliError::InvalidIncidentTag(_))));
    }

    #[test]
    fn record_subcommand_validates_empty_tag() {
        let args = parse_record(&["ibsr", "record-incident", "--tag", ""]);
        assert!(matches!(args.validate(), Err(CliError::InvalidIncidentTag(_))));
    }

    #[test]
    fn record_subcommand_validates_too_long_tag() {
        let long = "x".repeat(65);
        let args = parse_record(&["ibsr", "record-incident", "--tag", &long]);
        assert!(matches!(args.validate(), Err(CliError::InvalidIncidentTag(_))));
    }

    #[test]
    fn record_subcommand_accepts_64_char_tag() {
        let max = "a".repeat(64);
        let args = parse_record(&["ibsr", "record-incident", "--tag", &max]);
        assert!(args.validate().is_ok(), "64 chars is the limit, must pass");
    }

    #[test]
    fn record_subcommand_accepts_alphanumeric_underscore_dash() {
        let args = parse_record(&[
            "ibsr", "record-incident", "--tag", "a-b_c-1234",
        ]);
        assert!(args.validate().is_ok());
    }

    #[test]
    fn record_subcommand_duration_sec_optional() {
        let args = parse_record(&["ibsr", "record-incident"]);
        assert!(args.duration_sec.is_none());
    }

    #[test]
    fn record_subcommand_duration_sec_provided() {
        let args = parse_record(&[
            "ibsr", "record-incident", "--duration-sec", "60",
        ]);
        assert_eq!(args.duration_sec, Some(60));
    }

    #[test]
    fn record_subcommand_trigger_socket_optional() {
        let args = parse_record(&["ibsr", "record-incident"]);
        assert!(args.trigger_socket.is_none());
    }

    #[test]
    fn record_subcommand_trigger_socket_path_parses() {
        let args = parse_record(&[
            "ibsr", "record-incident",
            "--trigger-socket", "/run/ibsr.sock",
        ]);
        assert_eq!(args.trigger_socket, Some(PathBuf::from("/run/ibsr.sock")));
    }

    #[test]
    fn record_subcommand_scrub_ip_salt_parses() {
        let args = parse_record(&[
            "ibsr", "record-incident",
            "--scrub-ip-salt", "DEADBEEFCAFEBABE",
        ]);
        assert_eq!(args.scrub_ip_salt, Some("DEADBEEFCAFEBABE".to_string()));
    }

    #[test]
    fn record_subcommand_scrub_internal_subnet_parses() {
        let args = parse_record(&[
            "ibsr", "record-incident",
            "--scrub-internal-subnet", "10.0.0.0/8",
        ]);
        assert_eq!(args.scrub_internal_subnet, Some("10.0.0.0/8".to_string()));
    }

    #[test]
    fn record_subcommand_max_pcap_bytes_optional() {
        let args = parse_record(&["ibsr", "record-incident"]);
        assert!(args.max_pcap_bytes.is_none());
    }

    #[test]
    fn record_subcommand_max_pcap_bytes_parses() {
        let args = parse_record(&[
            "ibsr", "record-incident", "--max-pcap-bytes", "10485760",
        ]);
        assert_eq!(args.max_pcap_bytes, Some(10_485_760));
    }

    #[test]
    fn record_subcommand_archive_dir_optional() {
        let args = parse_record(&["ibsr", "record-incident"]);
        assert!(args.archive_dir.is_none());
    }

    #[test]
    fn record_subcommand_archive_dir_parses() {
        let args = parse_record(&[
            "ibsr", "record-incident", "--archive-dir", "/srv/archive",
        ]);
        assert_eq!(args.archive_dir, Some(PathBuf::from("/srv/archive")));
    }

    #[test]
    fn record_subcommand_archive_after_sec_default_is_3600() {
        let args = parse_record(&["ibsr", "record-incident"]);
        assert_eq!(args.archive_after_sec, 3600);
    }

    #[test]
    fn record_subcommand_archive_after_sec_overridable() {
        let args = parse_record(&[
            "ibsr", "record-incident", "--archive-after-sec", "60",
        ]);
        assert_eq!(args.archive_after_sec, 60);
    }

    #[test]
    fn record_subcommand_distinct_from_collect_modes() {
        // Pin: the three subcommands route independently.
        let cli_record = parse_from(["ibsr", "record-incident"]).expect("parse");
        assert!(matches!(cli_record.command, Command::RecordIncident(_)));
    }

    #[test]
    fn record_subcommand_out_dir_default_distinct_from_other_modes() {
        let args = parse_record(&["ibsr", "record-incident"]);
        assert_ne!(args.out_dir, PathBuf::from(DEFAULT_OUTPUT_DIR));
        assert_ne!(args.out_dir, PathBuf::from(DEFAULT_PAYLOAD_OUTPUT_DIR));
    }

    #[test]
    fn record_subcommand_help() {
        let result = parse_from(["ibsr", "record-incident", "--help"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    // ===========================================
    // is_valid_incident_tag — direct tests
    // ===========================================

    #[test]
    fn valid_tag_minimal_one_char() {
        assert!(is_valid_incident_tag("a"));
    }

    #[test]
    fn valid_tag_max_64_chars() {
        let s = "a".repeat(64);
        assert!(is_valid_incident_tag(&s));
    }

    #[test]
    fn invalid_tag_65_chars() {
        let s = "a".repeat(65);
        assert!(!is_valid_incident_tag(&s));
    }

    #[test]
    fn invalid_tag_empty() {
        assert!(!is_valid_incident_tag(""));
    }

    #[test]
    fn invalid_tag_with_slash_disallowed() {
        assert!(!is_valid_incident_tag("a/b"));
    }

    #[test]
    fn invalid_tag_with_dot_disallowed() {
        // `.` is intentionally disallowed so `..` can't slip in.
        assert!(!is_valid_incident_tag("a.b"));
    }

    #[test]
    fn invalid_tag_with_space_disallowed() {
        assert!(!is_valid_incident_tag("a b"));
    }

    #[test]
    fn invalid_tag_with_unicode_disallowed() {
        assert!(!is_valid_incident_tag("café"));
    }

    #[test]
    fn valid_tag_alphanumeric_dash_underscore() {
        assert!(is_valid_incident_tag("incident-customer-A_42"));
    }
}
