//! Episode detection for temporal abuse analysis.
//!
//! Detects episodes (contiguous windows of suspicious traffic) to prevent
//! attacks from being averaged out over multi-hour runs.

use crate::abuse::AbuseClass;
use crate::types::AggregatedKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Episode type indicating the duration/confidence of the episode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeType {
    /// Single hot interval - requires manual review before autonomous enforcement.
    SingleWindow,
    /// Multiple consecutive hot intervals - eligible for autonomous enforcement.
    MultiWindow,
}

/// Per-interval statistics for a key.
#[derive(Debug, Clone)]
pub struct IntervalStats {
    /// Timestamp of this interval.
    pub ts: u64,
    /// SYN count in this interval.
    pub syn: u64,
    /// ACK count in this interval.
    pub ack: u64,
    /// Handshake ACK count in this interval.
    pub handshake_ack: u64,
    /// RST count in this interval.
    pub rst: u64,
    /// Packet count in this interval.
    pub packets: u64,
    /// Byte count in this interval.
    pub bytes: u64,
    /// SYN rate (syn / interval_sec).
    pub syn_rate: f64,
    /// Packet rate (packets / interval_sec).
    pub pkt_rate: f64,
    /// Byte rate (bytes / interval_sec).
    pub byte_rate: f64,
    /// Success ratio (handshake_ack / syn).
    pub success_ratio: f64,
}

/// Episode detection configuration.
#[derive(Debug, Clone)]
pub struct EpisodeConfig {
    /// SYN rate threshold for hot interval detection.
    pub syn_rate_threshold: f64,
    /// Volumetric SYN rate threshold.
    pub vol_syn_rate: f64,
    /// Volumetric packet rate threshold.
    pub vol_pkt_rate: f64,
    /// Volumetric byte rate threshold.
    pub vol_byte_rate: f64,
    /// Success ratio threshold for SYN_FLOOD_LIKE classification.
    pub success_ratio_threshold: f64,
    /// Minimum number of consecutive intervals for a valid episode.
    pub min_episode_intervals: u32,
}

impl Default for EpisodeConfig {
    fn default() -> Self {
        Self {
            syn_rate_threshold: 100.0,
            vol_syn_rate: 500.0,
            vol_pkt_rate: 1000.0,
            vol_byte_rate: 1_000_000.0,
            success_ratio_threshold: 0.1,
            min_episode_intervals: 1, // Allow single-window episodes
        }
    }
}

/// A detected abuse episode (consecutive hot intervals for a key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Episode {
    /// Source IP address (display string).
    pub src_ip: String,
    /// Destination port.
    pub dst_port: Option<u16>,
    /// Start timestamp of the episode.
    pub start_ts: u64,
    /// End timestamp of the episode.
    pub end_ts: u64,
    /// Duration in seconds.
    pub duration_sec: u64,
    /// Number of hot intervals in this episode.
    pub interval_count: u32,
    /// Snapshot interval in seconds.
    pub interval_sec: u32,
    /// Episode type (single_window or multi_window).
    pub episode_type: EpisodeType,
    /// Peak SYN rate across all intervals.
    pub max_syn_rate: f64,
    /// Peak packet rate across all intervals.
    pub max_pkt_rate: f64,
    /// Peak byte rate across all intervals.
    pub max_byte_rate: f64,
    /// Minimum success ratio across all intervals.
    pub min_success_ratio: f64,
    /// Total SYN count across the episode.
    pub total_syn: u64,
    /// Total packet count across the episode.
    pub total_packets: u64,
    /// Total byte count across the episode.
    pub total_bytes: u64,
    /// Abuse classification.
    pub abuse_class: Option<AbuseClass>,
    /// Human-readable trigger reason.
    pub trigger_reason: String,
}

/// Check if an interval is "hot" (meets episode detection preconditions).
///
/// An interval is hot if EITHER:
/// - SYN flood: syn_rate >= syn_rate_threshold AND success_ratio <= success_ratio_threshold
/// - VOLUMETRIC: 2+ of 3 vol_* thresholds exceeded
pub fn is_hot_interval(stats: &IntervalStats, config: &EpisodeConfig) -> bool {
    // SYN flood: requires both high rate AND low success ratio
    let syn_hot = stats.syn_rate >= config.syn_rate_threshold
        && stats.success_ratio <= config.success_ratio_threshold;

    // Volumetric precondition: 2+ of 3 thresholds exceeded
    let mut vol_count = 0u8;
    if stats.syn_rate >= config.vol_syn_rate {
        vol_count += 1;
    }
    if stats.pkt_rate >= config.vol_pkt_rate {
        vol_count += 1;
    }
    if stats.byte_rate >= config.vol_byte_rate {
        vol_count += 1;
    }
    let vol_hot = vol_count >= 2;

    syn_hot || vol_hot
}

/// Detect episodes from per-interval stats.
///
/// Groups consecutive hot intervals for each key into episodes,
/// filtering out episodes with fewer than min_episode_intervals.
pub fn detect_episodes(
    interval_stats: &HashMap<AggregatedKey, Vec<IntervalStats>>,
    config: &EpisodeConfig,
    interval_sec: u32,
) -> Vec<Episode> {
    let mut episodes = Vec::new();

    for (key, intervals) in interval_stats {
        // Skip if no intervals
        if intervals.is_empty() {
            continue;
        }

        // Find consecutive runs of hot intervals
        let mut current_run: Vec<&IntervalStats> = Vec::new();

        for interval in intervals {
            if is_hot_interval(interval, config) {
                current_run.push(interval);
            } else {
                // End of a hot run - check if it meets minimum length
                if current_run.len() >= config.min_episode_intervals as usize {
                    if let Some(ep) = build_episode(key, &current_run, config, interval_sec) {
                        episodes.push(ep);
                    }
                }
                current_run.clear();
            }
        }

        // Handle final run if it ends at the last interval
        if current_run.len() >= config.min_episode_intervals as usize {
            if let Some(ep) = build_episode(key, &current_run, config, interval_sec) {
                episodes.push(ep);
            }
        }
    }

    // Sort episodes by (start_ts, src_ip, dst_port) for determinism
    episodes.sort_by(|a, b| {
        a.start_ts
            .cmp(&b.start_ts)
            .then_with(|| a.src_ip.cmp(&b.src_ip))
            .then_with(|| a.dst_port.cmp(&b.dst_port))
    });

    episodes
}

/// Build an Episode from a run of consecutive hot intervals.
fn build_episode(
    key: &AggregatedKey,
    intervals: &[&IntervalStats],
    config: &EpisodeConfig,
    interval_sec: u32,
) -> Option<Episode> {
    if intervals.is_empty() {
        return None;
    }

    let start_ts = intervals.first()?.ts;
    let end_ts = intervals.last()?.ts;
    let duration_sec = end_ts.saturating_sub(start_ts) + interval_sec as u64;

    // Compute peak rates and aggregates
    let mut max_syn_rate = 0.0f64;
    let mut max_pkt_rate = 0.0f64;
    let mut max_byte_rate = 0.0f64;
    let mut min_success_ratio = f64::MAX;
    let mut total_syn = 0u64;
    let mut total_packets = 0u64;
    let mut total_bytes = 0u64;

    for interval in intervals {
        max_syn_rate = max_syn_rate.max(interval.syn_rate);
        max_pkt_rate = max_pkt_rate.max(interval.pkt_rate);
        max_byte_rate = max_byte_rate.max(interval.byte_rate);
        if interval.syn > 0 {
            min_success_ratio = min_success_ratio.min(interval.success_ratio);
        }
        total_syn += interval.syn;
        total_packets += interval.packets;
        total_bytes += interval.bytes;
    }

    // If no intervals had SYN traffic, use 0.0 for min_success_ratio
    if min_success_ratio == f64::MAX {
        min_success_ratio = 0.0;
    }

    let interval_count = intervals.len() as u32;
    let episode_type = if interval_count == 1 {
        EpisodeType::SingleWindow
    } else {
        EpisodeType::MultiWindow
    };

    let mut episode = Episode {
        src_ip: key_to_src_ip(key),
        dst_port: key.dst_port,
        start_ts,
        end_ts,
        duration_sec,
        interval_count,
        interval_sec,
        episode_type,
        max_syn_rate,
        max_pkt_rate,
        max_byte_rate,
        min_success_ratio,
        total_syn,
        total_packets,
        total_bytes,
        abuse_class: None,
        trigger_reason: String::new(),
    };

    // Classify the episode
    classify_episode(&mut episode, config);

    Some(episode)
}

/// Classify an episode using full abuse detection logic.
///
/// Classification rules:
/// - SYN_FLOOD_LIKE: max_syn_rate >= syn_rate_threshold AND min_success_ratio <= success_ratio_threshold
/// - VOLUMETRIC_TCP_ABUSE: 2+ of 3 max rates exceed volumetric thresholds
fn classify_episode(episode: &mut Episode, config: &EpisodeConfig) {
    // Check SYN flood condition (priority over volumetric)
    let syn_flood_triggered = episode.max_syn_rate >= config.syn_rate_threshold
        && episode.min_success_ratio <= config.success_ratio_threshold;

    // Count volumetric metrics exceeded
    let mut vol_count = 0u8;
    if episode.max_syn_rate >= config.vol_syn_rate {
        vol_count += 1;
    }
    if episode.max_pkt_rate >= config.vol_pkt_rate {
        vol_count += 1;
    }
    if episode.max_byte_rate >= config.vol_byte_rate {
        vol_count += 1;
    }
    let volumetric_triggered = vol_count >= 2;

    // Determine abuse class (SYN flood takes priority)
    if syn_flood_triggered {
        episode.abuse_class = Some(AbuseClass::SynFloodLike);
        episode.trigger_reason = format!(
            "syn_rate {:.1} >= {:.1} AND success_ratio {:.4} <= {:.4}",
            episode.max_syn_rate,
            config.syn_rate_threshold,
            episode.min_success_ratio,
            config.success_ratio_threshold
        );
    } else if volumetric_triggered {
        episode.abuse_class = Some(AbuseClass::VolumetricTcpAbuse);
        let mut reasons = Vec::new();
        if episode.max_syn_rate >= config.vol_syn_rate {
            reasons.push(format!("syn_rate {:.1} >= {:.1}", episode.max_syn_rate, config.vol_syn_rate));
        }
        if episode.max_pkt_rate >= config.vol_pkt_rate {
            reasons.push(format!("pkt_rate {:.1} >= {:.1}", episode.max_pkt_rate, config.vol_pkt_rate));
        }
        if episode.max_byte_rate >= config.vol_byte_rate {
            reasons.push(format!("byte_rate {:.1} >= {:.1}", episode.max_byte_rate, config.vol_byte_rate));
        }
        episode.trigger_reason = format!("{} of 3 volumetric: {}", vol_count, reasons.join(", "));
    }
}

/// Convert AggregatedKey to source IP string.
fn key_to_src_ip(key: &AggregatedKey) -> String {
    Ipv4Addr::from(key.key_value).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibsr_schema::KeyType;

    // ===========================================
    // Helper functions
    // ===========================================

    fn make_config() -> EpisodeConfig {
        EpisodeConfig::default()
    }

    fn make_interval_stats(
        ts: u64,
        syn_rate: f64,
        pkt_rate: f64,
        byte_rate: f64,
        success_ratio: f64,
    ) -> IntervalStats {
        IntervalStats {
            ts,
            syn: (syn_rate * 60.0) as u64, // Assuming 60-sec intervals
            ack: 0,
            handshake_ack: ((syn_rate * 60.0) * success_ratio) as u64,
            rst: 0,
            packets: (pkt_rate * 60.0) as u64,
            bytes: (byte_rate * 60.0) as u64,
            syn_rate,
            pkt_rate,
            byte_rate,
            success_ratio,
        }
    }

    fn make_key(ip: u32, port: u16) -> AggregatedKey {
        AggregatedKey::new(KeyType::SrcIp, ip, Some(port))
    }

    // ===========================================
    // is_hot_interval tests
    // ===========================================

    #[test]
    fn test_is_hot_interval_syn_flood() {
        let config = make_config();
        // syn_rate >= 100 AND success_ratio <= 0.1 should trigger SYN flood
        let stats = make_interval_stats(1000, 150.0, 200.0, 20000.0, 0.05);

        assert!(
            is_hot_interval(&stats, &config),
            "syn_rate 150 >= threshold 100 AND success_ratio 0.05 <= 0.1 should be hot"
        );
    }

    #[test]
    fn test_is_hot_interval_syn_flood_exact_threshold() {
        let config = make_config();
        // Exactly at both thresholds
        let stats = make_interval_stats(1000, 100.0, 200.0, 20000.0, 0.1);

        assert!(
            is_hot_interval(&stats, &config),
            "syn_rate exactly at threshold AND success_ratio exactly at threshold should be hot"
        );
    }

    #[test]
    fn test_is_hot_interval_high_syn_good_ratio_not_hot() {
        let config = make_config();
        // High syn_rate but good success_ratio - not a SYN flood
        let stats = make_interval_stats(1000, 150.0, 200.0, 20000.0, 0.5);

        assert!(
            !is_hot_interval(&stats, &config),
            "high syn_rate with good success_ratio should NOT be hot"
        );
    }

    #[test]
    fn test_is_hot_interval_syn_precondition_below_threshold() {
        let config = make_config();
        // Below threshold
        let stats = make_interval_stats(1000, 99.0, 200.0, 20000.0, 0.5);

        // Should NOT be hot from SYN alone (might still be hot from volumetric)
        // But with low pkt_rate and byte_rate, should not be hot
        assert!(
            !is_hot_interval(&stats, &config),
            "syn_rate 99 < threshold 100 and no volumetric should NOT be hot"
        );
    }

    #[test]
    fn test_is_hot_interval_volumetric_precondition_two_of_three() {
        let config = make_config();
        // High syn_rate (>=500) and high pkt_rate (>=1000), byte_rate below threshold
        // This is 2 of 3 volumetric metrics exceeded
        let stats = make_interval_stats(1000, 600.0, 1500.0, 500_000.0, 0.9);

        assert!(
            is_hot_interval(&stats, &config),
            "2 of 3 volumetric thresholds exceeded should be hot"
        );
    }

    #[test]
    fn test_is_hot_interval_volumetric_precondition_all_three() {
        let config = make_config();
        // All three volumetric metrics exceeded
        let stats = make_interval_stats(1000, 600.0, 1500.0, 2_000_000.0, 0.9);

        assert!(
            is_hot_interval(&stats, &config),
            "3 of 3 volumetric thresholds exceeded should be hot"
        );
    }

    #[test]
    fn test_is_hot_interval_volumetric_one_of_three_not_hot() {
        let config = make_config();
        // Only syn_rate exceeds volumetric threshold, but below SYN precondition
        // pkt_rate and byte_rate below thresholds
        let stats = make_interval_stats(1000, 99.0, 500.0, 500_000.0, 0.9);

        assert!(
            !is_hot_interval(&stats, &config),
            "Only 0-1 of 3 volumetric and syn_rate < 100 should NOT be hot"
        );
    }

    #[test]
    fn test_is_hot_interval_neither_precondition() {
        let config = make_config();
        // Low rates, legitimate traffic
        let stats = make_interval_stats(1000, 50.0, 100.0, 50_000.0, 0.95);

        assert!(
            !is_hot_interval(&stats, &config),
            "Low rates should NOT be hot"
        );
    }

    // ===========================================
    // Episode merging tests
    // ===========================================

    #[test]
    fn test_merge_consecutive_hot_intervals() {
        let config = make_config();
        let key = make_key(0x0A000001, 8080);

        // Three consecutive hot intervals
        let intervals = vec![
            make_interval_stats(1000, 150.0, 200.0, 20000.0, 0.05),
            make_interval_stats(1060, 160.0, 210.0, 21000.0, 0.04),
            make_interval_stats(1120, 140.0, 190.0, 19000.0, 0.06),
        ];

        let mut interval_map = HashMap::new();
        interval_map.insert(key, intervals);

        let episodes = detect_episodes(&interval_map, &config, 60);

        assert_eq!(
            episodes.len(),
            1,
            "Three consecutive hot intervals should merge into one episode"
        );

        let ep = &episodes[0];
        assert_eq!(ep.start_ts, 1000);
        assert_eq!(ep.end_ts, 1120);
        assert_eq!(ep.interval_count, 3);
    }

    #[test]
    fn test_non_consecutive_intervals_separate_episodes() {
        let config = make_config();
        let key = make_key(0x0A000001, 8080);

        // Hot, cold, hot - should create two separate single-window episodes
        let intervals = vec![
            make_interval_stats(1000, 150.0, 200.0, 20000.0, 0.05), // hot
            make_interval_stats(1060, 50.0, 100.0, 10000.0, 0.5),   // cold
            make_interval_stats(1120, 140.0, 190.0, 19000.0, 0.06), // hot
        ];

        let mut interval_map = HashMap::new();
        interval_map.insert(key, intervals);

        let episodes = detect_episodes(&interval_map, &config, 60);

        // Each isolated hot interval becomes a single-window episode
        assert_eq!(
            episodes.len(),
            2,
            "Each isolated hot interval should become a single-window episode"
        );
        assert!(episodes.iter().all(|e| e.episode_type == EpisodeType::SingleWindow));
    }

    #[test]
    fn test_single_interval_creates_single_window_episode() {
        let config = make_config();
        let key = make_key(0x0A000001, 8080);

        // Single hot interval now creates a single-window episode
        let intervals = vec![make_interval_stats(1000, 150.0, 200.0, 20000.0, 0.05)];

        let mut interval_map = HashMap::new();
        interval_map.insert(key, intervals);

        let episodes = detect_episodes(&interval_map, &config, 60);

        assert_eq!(
            episodes.len(),
            1,
            "Single hot interval should create a single-window episode"
        );
        assert_eq!(episodes[0].episode_type, EpisodeType::SingleWindow);
        assert_eq!(episodes[0].interval_count, 1);
    }

    #[test]
    fn test_exactly_two_intervals_meets_minimum() {
        let config = make_config();
        let key = make_key(0x0A000001, 8080);

        // Exactly two consecutive hot intervals
        let intervals = vec![
            make_interval_stats(1000, 150.0, 200.0, 20000.0, 0.05),
            make_interval_stats(1060, 160.0, 210.0, 21000.0, 0.04),
        ];

        let mut interval_map = HashMap::new();
        interval_map.insert(key, intervals);

        let episodes = detect_episodes(&interval_map, &config, 60);

        assert_eq!(
            episodes.len(),
            1,
            "Two consecutive hot intervals should create one episode"
        );
        assert_eq!(episodes[0].interval_count, 2);
    }

    // ===========================================
    // Episode classification tests
    // ===========================================

    #[test]
    fn test_classify_episode_syn_flood() {
        let config = make_config();
        let key = make_key(0x0A000001, 8080);

        // High SYN rate, low success ratio - SYN_FLOOD_LIKE
        let intervals = vec![
            make_interval_stats(1000, 150.0, 200.0, 20000.0, 0.05),
            make_interval_stats(1060, 160.0, 210.0, 21000.0, 0.04),
        ];

        let mut interval_map = HashMap::new();
        interval_map.insert(key, intervals);

        let episodes = detect_episodes(&interval_map, &config, 60);

        assert_eq!(episodes.len(), 1);
        assert_eq!(
            episodes[0].abuse_class,
            Some(AbuseClass::SynFloodLike),
            "High SYN rate with low success ratio should classify as SYN_FLOOD_LIKE"
        );
    }

    #[test]
    fn test_classify_episode_volumetric() {
        let config = make_config();
        let key = make_key(0x0A000001, 8080);

        // High volumetric rates, HIGH success ratio - VOLUMETRIC_TCP_ABUSE
        let intervals = vec![
            make_interval_stats(1000, 600.0, 1500.0, 2_000_000.0, 0.9),
            make_interval_stats(1060, 650.0, 1600.0, 2_100_000.0, 0.85),
        ];

        let mut interval_map = HashMap::new();
        interval_map.insert(key, intervals);

        let episodes = detect_episodes(&interval_map, &config, 60);

        assert_eq!(episodes.len(), 1);
        assert_eq!(
            episodes[0].abuse_class,
            Some(AbuseClass::VolumetricTcpAbuse),
            "High volumetric rates with high success ratio should classify as VOLUMETRIC_TCP_ABUSE"
        );
    }

    #[test]
    fn test_episode_peak_rates() {
        let config = make_config();
        let key = make_key(0x0A000001, 8080);

        let intervals = vec![
            make_interval_stats(1000, 150.0, 200.0, 20000.0, 0.05),
            make_interval_stats(1060, 200.0, 250.0, 25000.0, 0.03), // Higher rates
            make_interval_stats(1120, 160.0, 210.0, 21000.0, 0.04),
        ];

        let mut interval_map = HashMap::new();
        interval_map.insert(key, intervals);

        let episodes = detect_episodes(&interval_map, &config, 60);

        assert_eq!(episodes.len(), 1);
        let ep = &episodes[0];

        // Peak rates should be the max across all intervals
        assert!(
            (ep.max_syn_rate - 200.0).abs() < 0.001,
            "max_syn_rate should be 200.0"
        );
        assert!(
            (ep.max_pkt_rate - 250.0).abs() < 0.001,
            "max_pkt_rate should be 250.0"
        );
        assert!(
            (ep.max_byte_rate - 25000.0).abs() < 0.001,
            "max_byte_rate should be 25000.0"
        );
        // min_success_ratio should be the minimum
        assert!(
            (ep.min_success_ratio - 0.03).abs() < 0.001,
            "min_success_ratio should be 0.03"
        );
    }

    // ===========================================
    // Episode ordering tests (determinism)
    // ===========================================

    #[test]
    fn test_episodes_sorted_by_start_ts_then_src_ip_then_port() {
        let config = make_config();

        let key1 = make_key(0x0A000002, 8080); // 10.0.0.2
        let key2 = make_key(0x0A000001, 8080); // 10.0.0.1
        let key3 = make_key(0x0A000001, 443); // 10.0.0.1

        let mut interval_map = HashMap::new();

        // key1 starts at 1000
        interval_map.insert(
            key1,
            vec![
                make_interval_stats(1000, 150.0, 200.0, 20000.0, 0.05),
                make_interval_stats(1060, 160.0, 210.0, 21000.0, 0.04),
            ],
        );

        // key2 starts at 1000 (same time, but lower IP)
        interval_map.insert(
            key2,
            vec![
                make_interval_stats(1000, 150.0, 200.0, 20000.0, 0.05),
                make_interval_stats(1060, 160.0, 210.0, 21000.0, 0.04),
            ],
        );

        // key3 starts at 1000 (same time, same IP, lower port)
        interval_map.insert(
            key3,
            vec![
                make_interval_stats(1000, 150.0, 200.0, 20000.0, 0.05),
                make_interval_stats(1060, 160.0, 210.0, 21000.0, 0.04),
            ],
        );

        let episodes = detect_episodes(&interval_map, &config, 60);

        assert_eq!(episodes.len(), 3);

        // Should be sorted by: start_ts, then src_ip, then dst_port
        // All have same start_ts=1000
        // 10.0.0.1 < 10.0.0.2
        // For same IP: 443 < 8080
        assert_eq!(episodes[0].src_ip, "10.0.0.1");
        assert_eq!(episodes[0].dst_port, Some(443));

        assert_eq!(episodes[1].src_ip, "10.0.0.1");
        assert_eq!(episodes[1].dst_port, Some(8080));

        assert_eq!(episodes[2].src_ip, "10.0.0.2");
        assert_eq!(episodes[2].dst_port, Some(8080));
    }

    // ===========================================
    // EpisodeConfig tests
    // ===========================================

    #[test]
    fn test_episode_config_default() {
        let config = EpisodeConfig::default();

        assert!((config.syn_rate_threshold - 100.0).abs() < 0.001);
        assert!((config.vol_syn_rate - 500.0).abs() < 0.001);
        assert!((config.vol_pkt_rate - 1000.0).abs() < 0.001);
        assert!((config.vol_byte_rate - 1_000_000.0).abs() < 0.001);
        assert!((config.success_ratio_threshold - 0.1).abs() < 0.001);
        assert_eq!(config.min_episode_intervals, 1);
    }

    // ===========================================
    // Single-window episode tests
    // ===========================================

    #[test]
    fn test_single_interval_produces_episode() {
        let config = make_config();
        let key = make_key(0x0A000001, 8080);

        // Single hot interval should now produce an episode
        let intervals = vec![make_interval_stats(1000, 150.0, 200.0, 20000.0, 0.05)];

        let mut interval_map = HashMap::new();
        interval_map.insert(key, intervals);

        let episodes = detect_episodes(&interval_map, &config, 60);

        assert_eq!(
            episodes.len(),
            1,
            "Single hot interval should create one episode with single_window type"
        );
        assert_eq!(episodes[0].interval_count, 1);
        assert_eq!(episodes[0].episode_type, EpisodeType::SingleWindow);
    }

    #[test]
    fn test_multi_interval_produces_episode() {
        let config = make_config();
        let key = make_key(0x0A000001, 8080);

        // Multiple consecutive hot intervals
        let intervals = vec![
            make_interval_stats(1000, 150.0, 200.0, 20000.0, 0.05),
            make_interval_stats(1060, 160.0, 210.0, 21000.0, 0.04),
        ];

        let mut interval_map = HashMap::new();
        interval_map.insert(key, intervals);

        let episodes = detect_episodes(&interval_map, &config, 60);

        assert_eq!(episodes.len(), 1);
        assert_eq!(episodes[0].interval_count, 2);
        assert_eq!(episodes[0].episode_type, EpisodeType::MultiWindow);
    }

    #[test]
    fn test_episode_type_classification() {
        let config = make_config();
        let key1 = make_key(0x0A000001, 8080);
        let key2 = make_key(0x0A000002, 8080);

        let mut interval_map = HashMap::new();

        // Single-window episode
        interval_map.insert(
            key1,
            vec![make_interval_stats(1000, 150.0, 200.0, 20000.0, 0.05)],
        );

        // Multi-window episode (3 intervals)
        interval_map.insert(
            key2,
            vec![
                make_interval_stats(1000, 150.0, 200.0, 20000.0, 0.05),
                make_interval_stats(1060, 160.0, 210.0, 21000.0, 0.04),
                make_interval_stats(1120, 140.0, 190.0, 19000.0, 0.06),
            ],
        );

        let episodes = detect_episodes(&interval_map, &config, 60);

        assert_eq!(episodes.len(), 2);

        // Find the single-window episode (IP 10.0.0.1)
        let single = episodes.iter().find(|e| e.src_ip == "10.0.0.1").unwrap();
        assert_eq!(single.episode_type, EpisodeType::SingleWindow);
        assert_eq!(single.interval_count, 1);

        // Find the multi-window episode (IP 10.0.0.2)
        let multi = episodes.iter().find(|e| e.src_ip == "10.0.0.2").unwrap();
        assert_eq!(multi.episode_type, EpisodeType::MultiWindow);
        assert_eq!(multi.interval_count, 3);
    }
}
