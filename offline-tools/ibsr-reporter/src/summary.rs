//! Machine-readable summary output (summary.json).
//!
//! Provides versioned, deterministic output for comparisons across time.

use crate::abuse::{AbuseClass, DetectionConfidence};
use crate::counterfactual::{CounterfactualResult, FpBound};
use crate::types::WindowBounds;
use serde::{Deserialize, Serialize};

/// Current report schema version.
/// v3: Added episodes array for temporal episode detection.
/// v4: Added episode_type field (single_window or multi_window).
pub const REPORT_VERSION: u32 = 4;

/// Machine-readable summary for comparing reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    /// Report format version.
    pub report_version: u32,
    /// Run ID from the snapshots.
    pub run_id: u64,
    /// Minimum schema version of input snapshots.
    pub input_schema_version_min: u32,
    /// Maximum schema version of input snapshots.
    pub input_schema_version_max: u32,
    /// Time range analyzed.
    pub time_range: TimeRange,
    /// Ports analyzed.
    pub ports_analyzed: Vec<u16>,
    /// Analysis configuration.
    pub config: AnalysisConfig,
    /// List of triggered abuse detections.
    pub triggers: Vec<Trigger>,
    /// Detected abuse episodes (v3+).
    pub episodes: Vec<EpisodeSummary>,
    /// Blocked traffic estimates.
    pub blocked_traffic: BlockedTraffic,
    /// False positive bound.
    pub fp_bound: FpBoundSummary,
    /// Whether safe for autonomous enforcement.
    pub enforcement_safe: bool,
    /// Reasons if not safe.
    pub enforcement_reasons: Vec<String>,
}

/// Summary of a detected abuse episode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpisodeSummary {
    /// Source IP address.
    pub src_ip: String,
    /// Destination port.
    pub dst_port: Option<u16>,
    /// Start timestamp.
    pub start_ts: u64,
    /// End timestamp.
    pub end_ts: u64,
    /// Duration in seconds.
    pub duration_sec: u64,
    /// Number of intervals in the episode.
    pub interval_count: u32,
    /// Interval duration in seconds.
    pub interval_sec: u32,
    /// Episode type: "single_window" or "multi_window".
    pub episode_type: String,
    /// Peak SYN rate.
    pub max_syn_rate: f64,
    /// Peak packet rate.
    pub max_pkt_rate: f64,
    /// Peak byte rate.
    pub max_byte_rate: f64,
    /// Abuse classification.
    pub abuse_class: String,
    /// Human-readable trigger reason.
    pub trigger_reason: String,
}

/// Time range of analyzed data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start_ts: u64,
    pub end_ts: u64,
    pub duration_sec: u64,
}

impl From<&WindowBounds> for TimeRange {
    fn from(bounds: &WindowBounds) -> Self {
        Self {
            start_ts: bounds.start_ts,
            end_ts: bounds.end_ts,
            duration_sec: bounds.duration_sec(),
        }
    }
}

/// Analysis configuration for reproducibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub window_sec: u64,
    pub syn_rate_threshold: f64,
    pub success_ratio_threshold: f64,
    pub block_duration_sec: u64,
    pub vol_syn_rate: f64,
    pub vol_pkt_rate: f64,
    pub vol_byte_rate: f64,
}

/// A triggered abuse detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trigger {
    /// Abuse class that triggered.
    pub abuse_class: String,
    /// Source IP or CIDR.
    pub src: String,
    /// Destination port.
    pub dst_port: Option<u16>,
    /// Metrics that led to the trigger.
    pub rates: TriggerRates,
    /// Detection confidence.
    pub confidence: String,
}

/// Rates that led to a trigger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerRates {
    pub syn_rate: f64,
    pub pkt_rate: f64,
    pub byte_rate: f64,
    pub success_ratio: f64,
}

/// Blocked traffic estimates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedTraffic {
    pub packets_blocked_pct: f64,
    pub bytes_blocked_pct: f64,
    pub syn_blocked_pct: f64,
    pub packets_blocked_count: u64,
    pub bytes_blocked_count: u64,
    pub syn_blocked_count: u64,
}

/// False positive bound in summary format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpBoundSummary {
    pub computed: bool,
    pub value_pct: Option<f64>,
    pub reason: Option<String>,
}

impl From<&FpBound> for FpBoundSummary {
    fn from(fp: &FpBound) -> Self {
        match fp {
            FpBound::Computed(pct) => Self {
                computed: true,
                value_pct: Some(*pct),
                reason: None,
            },
            FpBound::Unknown { reason } => Self {
                computed: false,
                value_pct: None,
                reason: Some(reason.clone()),
            },
        }
    }
}

impl Summary {
    /// Serialize to JSON string (pretty-printed for readability).
    /// Output always ends with a newline for proper file termination.
    pub fn to_json(&self) -> String {
        let mut json = serde_json::to_string_pretty(self).expect("Summary serialization cannot fail");
        json.push('\n');
        json
    }

    /// Deserialize from JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Builder for creating Summary from reporter components.
pub struct SummaryBuilder {
    run_id: u64,
    input_schema_version_min: u32,
    input_schema_version_max: u32,
    bounds: WindowBounds,
    ports: Vec<u16>,
    window_sec: u64,
    syn_rate_threshold: f64,
    success_ratio_threshold: f64,
    block_duration_sec: u64,
    vol_syn_rate: f64,
    vol_pkt_rate: f64,
    vol_byte_rate: f64,
    triggers: Vec<Trigger>,
    episodes: Vec<EpisodeSummary>,
    counterfactual: Option<CounterfactualResult>,
    enforcement_safe: bool,
    enforcement_reasons: Vec<String>,
}

impl SummaryBuilder {
    pub fn new(run_id: u64, bounds: WindowBounds) -> Self {
        Self {
            run_id,
            input_schema_version_min: 5,
            input_schema_version_max: 5,
            bounds,
            ports: Vec::new(),
            window_sec: 10,
            syn_rate_threshold: 100.0,
            success_ratio_threshold: 0.1,
            block_duration_sec: 300,
            vol_syn_rate: 500.0,
            vol_pkt_rate: 1000.0,
            vol_byte_rate: 1_000_000.0,
            triggers: Vec::new(),
            episodes: Vec::new(),
            counterfactual: None,
            enforcement_safe: false,
            enforcement_reasons: Vec::new(),
        }
    }

    pub fn with_schema_versions(mut self, min: u32, max: u32) -> Self {
        self.input_schema_version_min = min;
        self.input_schema_version_max = max;
        self
    }

    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        self.ports = ports;
        self
    }

    pub fn with_window_sec(mut self, window_sec: u64) -> Self {
        self.window_sec = window_sec;
        self
    }

    pub fn with_syn_thresholds(mut self, syn_rate: f64, success_ratio: f64) -> Self {
        self.syn_rate_threshold = syn_rate;
        self.success_ratio_threshold = success_ratio;
        self
    }

    pub fn with_block_duration(mut self, duration: u64) -> Self {
        self.block_duration_sec = duration;
        self
    }

    pub fn with_volumetric_thresholds(mut self, syn: f64, pkt: f64, byte: f64) -> Self {
        self.vol_syn_rate = syn;
        self.vol_pkt_rate = pkt;
        self.vol_byte_rate = byte;
        self
    }

    pub fn add_trigger(
        &mut self,
        abuse_class: AbuseClass,
        src: String,
        dst_port: Option<u16>,
        syn_rate: f64,
        pkt_rate: f64,
        byte_rate: f64,
        success_ratio: f64,
        confidence: DetectionConfidence,
    ) {
        self.triggers.push(Trigger {
            abuse_class: abuse_class.to_string(),
            src,
            dst_port,
            rates: TriggerRates {
                syn_rate,
                pkt_rate,
                byte_rate,
                success_ratio,
            },
            confidence: confidence.to_string(),
        });
    }

    pub fn with_counterfactual(mut self, cf: CounterfactualResult) -> Self {
        self.counterfactual = Some(cf);
        self
    }

    pub fn with_episodes(mut self, episodes: Vec<EpisodeSummary>) -> Self {
        self.episodes = episodes;
        self
    }

    pub fn with_enforcement(mut self, safe: bool, reasons: Vec<String>) -> Self {
        self.enforcement_safe = safe;
        self.enforcement_reasons = reasons;
        self
    }

    pub fn build(self) -> Summary {
        let blocked_traffic = if let Some(ref cf) = self.counterfactual {
            BlockedTraffic {
                packets_blocked_pct: cf.percent_packets_blocked,
                bytes_blocked_pct: cf.percent_bytes_blocked,
                syn_blocked_pct: cf.percent_syn_blocked,
                packets_blocked_count: cf.blocked_packets,
                bytes_blocked_count: cf.blocked_bytes,
                syn_blocked_count: cf.blocked_syn,
            }
        } else {
            BlockedTraffic {
                packets_blocked_pct: 0.0,
                bytes_blocked_pct: 0.0,
                syn_blocked_pct: 0.0,
                packets_blocked_count: 0,
                bytes_blocked_count: 0,
                syn_blocked_count: 0,
            }
        };

        let fp_bound = if let Some(ref cf) = self.counterfactual {
            FpBoundSummary::from(&cf.fp_bound)
        } else {
            FpBoundSummary {
                computed: false,
                value_pct: None,
                reason: Some("No counterfactual data".to_string()),
            }
        };

        // Sort triggers for deterministic output
        let mut triggers = self.triggers;
        triggers.sort_by(|a, b| {
            a.abuse_class.cmp(&b.abuse_class)
                .then_with(|| a.src.cmp(&b.src))
                .then_with(|| a.dst_port.cmp(&b.dst_port))
        });

        // Sort ports for deterministic output
        let mut ports = self.ports;
        ports.sort();

        // Sort episodes for deterministic output (already sorted in detect_episodes,
        // but ensure consistency)
        let mut episodes = self.episodes;
        episodes.sort_by(|a, b| {
            a.start_ts
                .cmp(&b.start_ts)
                .then_with(|| a.src_ip.cmp(&b.src_ip))
                .then_with(|| a.dst_port.cmp(&b.dst_port))
        });

        Summary {
            report_version: REPORT_VERSION,
            run_id: self.run_id,
            input_schema_version_min: self.input_schema_version_min,
            input_schema_version_max: self.input_schema_version_max,
            time_range: TimeRange::from(&self.bounds),
            ports_analyzed: ports,
            config: AnalysisConfig {
                window_sec: self.window_sec,
                syn_rate_threshold: self.syn_rate_threshold,
                success_ratio_threshold: self.success_ratio_threshold,
                block_duration_sec: self.block_duration_sec,
                vol_syn_rate: self.vol_syn_rate,
                vol_pkt_rate: self.vol_pkt_rate,
                vol_byte_rate: self.vol_byte_rate,
            },
            triggers,
            episodes,
            blocked_traffic,
            fp_bound,
            enforcement_safe: self.enforcement_safe,
            enforcement_reasons: self.enforcement_reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abuse::{AbuseClass, DetectionConfidence};

    // ===========================================
    // Report Versioning Tests
    // ===========================================

    #[test]
    fn test_report_version_is_4() {
        assert_eq!(REPORT_VERSION, 4);
    }

    #[test]
    fn test_summary_contains_report_version() {
        let bounds = WindowBounds::new(1000, 1010);
        let summary = SummaryBuilder::new(12345, bounds)
            .with_ports(vec![8080])
            .build();

        assert_eq!(summary.report_version, 4);
    }

    #[test]
    fn test_summary_contains_run_id() {
        let bounds = WindowBounds::new(1000, 1010);
        let summary = SummaryBuilder::new(12345, bounds)
            .with_ports(vec![8080])
            .build();

        assert_eq!(summary.run_id, 12345);
    }

    #[test]
    fn test_summary_contains_schema_versions() {
        let bounds = WindowBounds::new(1000, 1010);
        let summary = SummaryBuilder::new(12345, bounds)
            .with_schema_versions(4, 5)
            .with_ports(vec![8080])
            .build();

        assert_eq!(summary.input_schema_version_min, 4);
        assert_eq!(summary.input_schema_version_max, 5);
    }

    // -------------------------------------------
    // Time range and ports
    // -------------------------------------------

    #[test]
    fn test_summary_time_range() {
        let bounds = WindowBounds::new(1000, 1060);
        let summary = SummaryBuilder::new(1, bounds)
            .with_ports(vec![8080])
            .build();

        assert_eq!(summary.time_range.start_ts, 1000);
        assert_eq!(summary.time_range.end_ts, 1060);
        assert_eq!(summary.time_range.duration_sec, 60);
    }

    #[test]
    fn test_summary_ports_analyzed_sorted() {
        let bounds = WindowBounds::new(1000, 1010);
        let summary = SummaryBuilder::new(1, bounds)
            .with_ports(vec![443, 80, 8080])
            .build();

        assert_eq!(summary.ports_analyzed, vec![80, 443, 8080]);
    }

    // -------------------------------------------
    // Triggers
    // -------------------------------------------

    #[test]
    fn test_summary_triggers_list() {
        let bounds = WindowBounds::new(1000, 1010);
        let mut builder = SummaryBuilder::new(1, bounds)
            .with_ports(vec![8080]);

        builder.add_trigger(
            AbuseClass::SynFloodLike,
            "10.0.0.1".to_string(),
            Some(8080),
            150.0,
            200.0,
            20000.0,
            0.05,
            DetectionConfidence::High,
        );

        let summary = builder.build();

        assert_eq!(summary.triggers.len(), 1);
        assert_eq!(summary.triggers[0].abuse_class, "SYN_FLOOD_LIKE");
        assert_eq!(summary.triggers[0].src, "10.0.0.1");
        assert_eq!(summary.triggers[0].dst_port, Some(8080));
        assert!((summary.triggers[0].rates.syn_rate - 150.0).abs() < 0.001);
        assert_eq!(summary.triggers[0].confidence, "high");
    }

    #[test]
    fn test_summary_triggers_sorted_deterministically() {
        let bounds = WindowBounds::new(1000, 1010);
        let mut builder = SummaryBuilder::new(1, bounds)
            .with_ports(vec![8080]);

        // Add in non-sorted order
        builder.add_trigger(
            AbuseClass::VolumetricTcpAbuse,
            "10.0.0.2".to_string(),
            Some(8080),
            600.0, 1500.0, 2_000_000.0, 0.9,
            DetectionConfidence::High,
        );
        builder.add_trigger(
            AbuseClass::SynFloodLike,
            "10.0.0.1".to_string(),
            Some(8080),
            150.0, 200.0, 20000.0, 0.05,
            DetectionConfidence::High,
        );

        let summary = builder.build();

        // Should be sorted by abuse_class then src
        assert_eq!(summary.triggers[0].abuse_class, "SYN_FLOOD_LIKE");
        assert_eq!(summary.triggers[1].abuse_class, "VOLUMETRIC_TCP_ABUSE");
    }

    // -------------------------------------------
    // Blocked traffic estimates
    // -------------------------------------------

    #[test]
    fn test_summary_blocked_traffic() {
        let bounds = WindowBounds::new(1000, 1010);
        let cf = CounterfactualResult {
            percent_packets_blocked: 50.0,
            percent_bytes_blocked: 45.0,
            percent_syn_blocked: 60.0,
            top_offenders: vec![],
            fp_bound: FpBound::Computed(2.5),
            total_packets: 1000,
            total_bytes: 100000,
            total_syn: 500,
            blocked_packets: 500,
            blocked_bytes: 45000,
            blocked_syn: 300,
        };

        let summary = SummaryBuilder::new(1, bounds)
            .with_ports(vec![8080])
            .with_counterfactual(cf)
            .build();

        assert!((summary.blocked_traffic.packets_blocked_pct - 50.0).abs() < 0.001);
        assert!((summary.blocked_traffic.bytes_blocked_pct - 45.0).abs() < 0.001);
        assert!((summary.blocked_traffic.syn_blocked_pct - 60.0).abs() < 0.001);
        assert_eq!(summary.blocked_traffic.packets_blocked_count, 500);
        assert_eq!(summary.blocked_traffic.bytes_blocked_count, 45000);
        assert_eq!(summary.blocked_traffic.syn_blocked_count, 300);
    }

    // -------------------------------------------
    // FP bound
    // -------------------------------------------

    #[test]
    fn test_summary_fp_bound_computed() {
        let bounds = WindowBounds::new(1000, 1010);
        let cf = CounterfactualResult {
            percent_packets_blocked: 50.0,
            percent_bytes_blocked: 45.0,
            percent_syn_blocked: 60.0,
            top_offenders: vec![],
            fp_bound: FpBound::Computed(2.5),
            total_packets: 1000,
            total_bytes: 100000,
            total_syn: 500,
            blocked_packets: 500,
            blocked_bytes: 45000,
            blocked_syn: 300,
        };

        let summary = SummaryBuilder::new(1, bounds)
            .with_ports(vec![8080])
            .with_counterfactual(cf)
            .build();

        assert!(summary.fp_bound.computed);
        assert_eq!(summary.fp_bound.value_pct, Some(2.5));
        assert!(summary.fp_bound.reason.is_none());
    }

    #[test]
    fn test_summary_fp_bound_unknown() {
        let bounds = WindowBounds::new(1000, 1010);
        let cf = CounterfactualResult {
            percent_packets_blocked: 0.0,
            percent_bytes_blocked: 0.0,
            percent_syn_blocked: 0.0,
            top_offenders: vec![],
            fp_bound: FpBound::Unknown { reason: "Insufficient data".to_string() },
            total_packets: 0,
            total_bytes: 0,
            total_syn: 0,
            blocked_packets: 0,
            blocked_bytes: 0,
            blocked_syn: 0,
        };

        let summary = SummaryBuilder::new(1, bounds)
            .with_ports(vec![8080])
            .with_counterfactual(cf)
            .build();

        assert!(!summary.fp_bound.computed);
        assert!(summary.fp_bound.value_pct.is_none());
        assert_eq!(summary.fp_bound.reason, Some("Insufficient data".to_string()));
    }

    // -------------------------------------------
    // Enforcement judgment
    // -------------------------------------------

    #[test]
    fn test_summary_enforcement_safe() {
        let bounds = WindowBounds::new(1000, 1010);
        let summary = SummaryBuilder::new(1, bounds)
            .with_ports(vec![8080])
            .with_enforcement(true, vec![])
            .build();

        assert!(summary.enforcement_safe);
        assert!(summary.enforcement_reasons.is_empty());
    }

    #[test]
    fn test_summary_enforcement_not_safe() {
        let bounds = WindowBounds::new(1000, 1010);
        let summary = SummaryBuilder::new(1, bounds)
            .with_ports(vec![8080])
            .with_enforcement(false, vec!["No abuse detected".to_string()])
            .build();

        assert!(!summary.enforcement_safe);
        assert_eq!(summary.enforcement_reasons, vec!["No abuse detected"]);
    }

    // -------------------------------------------
    // JSON serialization
    // -------------------------------------------

    #[test]
    fn test_summary_json_round_trip() {
        let bounds = WindowBounds::new(1000, 1010);
        let summary = SummaryBuilder::new(12345, bounds)
            .with_ports(vec![8080])
            .with_schema_versions(4, 5)
            .build();

        let json = summary.to_json();
        let parsed = Summary::from_json(&json).unwrap();

        assert_eq!(parsed.report_version, 4);
        assert_eq!(parsed.run_id, 12345);
        assert_eq!(parsed.input_schema_version_min, 4);
        assert_eq!(parsed.input_schema_version_max, 5);
    }

    #[test]
    fn test_summary_json_ends_with_newline() {
        let bounds = WindowBounds::new(1000, 1010);
        let summary = SummaryBuilder::new(1, bounds)
            .with_ports(vec![8080])
            .build();

        let json = summary.to_json();
        assert!(json.ends_with('\n'));
    }

    #[test]
    fn test_summary_json_deterministic() {
        let bounds = WindowBounds::new(1000, 1010);
        let summary1 = SummaryBuilder::new(12345, bounds)
            .with_ports(vec![8080, 443])
            .build();
        let summary2 = SummaryBuilder::new(12345, bounds)
            .with_ports(vec![443, 8080]) // Different order
            .build();

        // Should produce identical JSON (ports are sorted)
        assert_eq!(summary1.to_json(), summary2.to_json());
    }

    // -------------------------------------------
    // Config in summary
    // -------------------------------------------

    #[test]
    fn test_summary_config() {
        let bounds = WindowBounds::new(1000, 1010);
        let summary = SummaryBuilder::new(1, bounds)
            .with_ports(vec![8080])
            .with_window_sec(60)
            .with_syn_thresholds(200.0, 0.05)
            .with_block_duration(600)
            .with_volumetric_thresholds(400.0, 2000.0, 2_000_000.0)
            .build();

        assert_eq!(summary.config.window_sec, 60);
        assert!((summary.config.syn_rate_threshold - 200.0).abs() < 0.001);
        assert!((summary.config.success_ratio_threshold - 0.05).abs() < 0.001);
        assert_eq!(summary.config.block_duration_sec, 600);
        assert!((summary.config.vol_syn_rate - 400.0).abs() < 0.001);
        assert!((summary.config.vol_pkt_rate - 2000.0).abs() < 0.001);
        assert!((summary.config.vol_byte_rate - 2_000_000.0).abs() < 0.001);
    }
}
