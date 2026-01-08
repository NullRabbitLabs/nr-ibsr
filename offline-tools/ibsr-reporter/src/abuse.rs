//! Abuse class detection.
//!
//! Implements multiple abuse class triggers:
//! - SYN_FLOOD_LIKE: High SYN rate AND low success ratio
//! - VOLUMETRIC_TCP_ABUSE: High traffic volume (at least 2 of 3 metrics exceeded)

use crate::types::AggregatedStats;
use serde::{Deserialize, Serialize};

/// Abuse class that triggered the detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbuseClass {
    /// Classic SYN flood: high SYN rate AND low handshake success ratio.
    SynFloodLike,
    /// Volumetric TCP abuse: high traffic volume regardless of success ratio.
    /// Triggered when at least 2 of 3 metrics (syn_rate, pkt_rate, byte_rate) exceed thresholds.
    VolumetricTcpAbuse,
}

impl std::fmt::Display for AbuseClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AbuseClass::SynFloodLike => write!(f, "SYN_FLOOD_LIKE"),
            AbuseClass::VolumetricTcpAbuse => write!(f, "VOLUMETRIC_TCP_ABUSE"),
        }
    }
}

/// Result of abuse detection for a key.
#[derive(Debug, Clone)]
pub struct AbuseDetection {
    /// The abuse class that triggered, if any.
    pub abuse_class: Option<AbuseClass>,
    /// Number of volumetric metrics that exceeded thresholds.
    pub volumetric_metrics_exceeded: u8,
    /// Confidence/validity of the detection.
    pub confidence: DetectionConfidence,
}

/// Confidence level of the detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionConfidence {
    /// All metrics are reliable and detection is confident.
    High,
    /// Some metrics may be unreliable (e.g., success_ratio undefined).
    Medium,
    /// Detection is uncertain due to missing or unreliable data.
    Low,
}

impl std::fmt::Display for DetectionConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionConfidence::High => write!(f, "high"),
            DetectionConfidence::Medium => write!(f, "medium"),
            DetectionConfidence::Low => write!(f, "low"),
        }
    }
}

/// Extended stats including rates for volumetric detection.
#[derive(Debug, Clone, Copy)]
pub struct ExtendedStats {
    pub syn_rate: f64,
    pub pkt_rate: f64,
    pub byte_rate: f64,
    pub success_ratio: f64,
    /// Whether success_ratio is reliable (has enough SYN samples).
    pub success_ratio_reliable: bool,
}

impl ExtendedStats {
    /// Create from AggregatedStats and window duration.
    pub fn from_aggregated(stats: &AggregatedStats, window_sec: u64) -> Self {
        let window_f = window_sec as f64;
        let pkt_rate = if window_f > 0.0 { stats.total_packets as f64 / window_f } else { 0.0 };
        let byte_rate = if window_f > 0.0 { stats.total_bytes as f64 / window_f } else { 0.0 };

        // success_ratio is reliable if we have at least some SYN packets
        let success_ratio_reliable = stats.total_syn >= 10;

        Self {
            syn_rate: stats.syn_rate,
            pkt_rate,
            byte_rate,
            success_ratio: stats.success_ratio,
            success_ratio_reliable,
        }
    }
}

/// Volumetric abuse thresholds.
#[derive(Debug, Clone)]
pub struct VolumetricThresholds {
    pub syn_rate: f64,
    pub pkt_rate: f64,
    pub byte_rate: f64,
}

impl Default for VolumetricThresholds {
    fn default() -> Self {
        Self {
            syn_rate: 500.0,      // 500 SYN/sec
            pkt_rate: 1000.0,     // 1000 packets/sec
            byte_rate: 1_000_000.0, // 1 MB/sec
        }
    }
}

/// Detect abuse class for a key based on its extended stats.
///
/// Detection logic:
/// 1. SYN_FLOOD_LIKE: syn_rate >= threshold AND success_ratio <= threshold
///    - If success_ratio is unreliable, mark confidence as Medium
/// 2. VOLUMETRIC_TCP_ABUSE: at least 2 of 3 metrics exceed volumetric thresholds
///    - Does NOT require low success_ratio
pub fn detect_abuse(
    stats: &ExtendedStats,
    syn_rate_threshold: f64,
    success_ratio_threshold: f64,
    volumetric: &VolumetricThresholds,
) -> AbuseDetection {
    // Count volumetric metrics exceeded
    let mut vol_count = 0u8;
    if stats.syn_rate >= volumetric.syn_rate {
        vol_count += 1;
    }
    if stats.pkt_rate >= volumetric.pkt_rate {
        vol_count += 1;
    }
    if stats.byte_rate >= volumetric.byte_rate {
        vol_count += 1;
    }

    // Check SYN flood condition
    let syn_flood_triggered = stats.syn_rate >= syn_rate_threshold
        && stats.success_ratio <= success_ratio_threshold;

    // Check volumetric condition (2 of 3)
    let volumetric_triggered = vol_count >= 2;

    // Determine confidence
    let confidence = if stats.success_ratio_reliable {
        DetectionConfidence::High
    } else if syn_flood_triggered {
        // SYN flood triggered but success_ratio might be unreliable
        DetectionConfidence::Medium
    } else {
        DetectionConfidence::High
    };

    // Determine abuse class (SYN flood takes priority if both trigger)
    let abuse_class = if syn_flood_triggered && stats.success_ratio_reliable {
        Some(AbuseClass::SynFloodLike)
    } else if volumetric_triggered {
        Some(AbuseClass::VolumetricTcpAbuse)
    } else if syn_flood_triggered && !stats.success_ratio_reliable {
        // SYN flood condition met but success_ratio unreliable - still report as SYN flood
        // but with medium confidence
        Some(AbuseClass::SynFloodLike)
    } else {
        None
    };

    AbuseDetection {
        abuse_class,
        volumetric_metrics_exceeded: vol_count,
        confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===========================================
    // Abuse Class Detection Tests
    // ===========================================

    fn make_stats(syn_rate: f64, pkt_rate: f64, byte_rate: f64, success_ratio: f64, reliable: bool) -> ExtendedStats {
        ExtendedStats {
            syn_rate,
            pkt_rate,
            byte_rate,
            success_ratio,
            success_ratio_reliable: reliable,
        }
    }

    fn default_volumetric() -> VolumetricThresholds {
        VolumetricThresholds::default()
    }

    // -------------------------------------------
    // SYN_FLOOD_LIKE detection
    // -------------------------------------------

    #[test]
    fn test_syn_flood_triggers() {
        // High SYN rate AND low success ratio
        let stats = make_stats(150.0, 200.0, 20000.0, 0.05, true);
        let result = detect_abuse(&stats, 100.0, 0.1, &default_volumetric());

        assert_eq!(result.abuse_class, Some(AbuseClass::SynFloodLike));
        assert_eq!(result.confidence, DetectionConfidence::High);
    }

    #[test]
    fn test_syn_flood_exact_thresholds() {
        // Exactly at thresholds
        let stats = make_stats(100.0, 200.0, 20000.0, 0.1, true);
        let result = detect_abuse(&stats, 100.0, 0.1, &default_volumetric());

        assert_eq!(result.abuse_class, Some(AbuseClass::SynFloodLike));
    }

    #[test]
    fn test_syn_flood_not_triggered_high_success_ratio() {
        // High SYN rate but success ratio too high
        let stats = make_stats(150.0, 200.0, 20000.0, 0.5, true);
        let result = detect_abuse(&stats, 100.0, 0.1, &default_volumetric());

        // Should NOT trigger SYN flood (but might trigger volumetric if thresholds met)
        assert_ne!(result.abuse_class, Some(AbuseClass::SynFloodLike));
    }

    #[test]
    fn test_syn_flood_not_triggered_low_syn_rate() {
        // Low SYN rate even with low success ratio
        let stats = make_stats(50.0, 200.0, 20000.0, 0.05, true);
        let result = detect_abuse(&stats, 100.0, 0.1, &default_volumetric());

        assert_eq!(result.abuse_class, None);
    }

    #[test]
    fn test_syn_flood_unreliable_success_ratio() {
        // SYN flood conditions met but success_ratio unreliable
        let stats = make_stats(150.0, 200.0, 20000.0, 0.05, false); // unreliable
        let result = detect_abuse(&stats, 100.0, 0.1, &default_volumetric());

        // Should still trigger but with medium confidence
        assert_eq!(result.abuse_class, Some(AbuseClass::SynFloodLike));
        assert_eq!(result.confidence, DetectionConfidence::Medium);
    }

    // -------------------------------------------
    // VOLUMETRIC_TCP_ABUSE detection
    // -------------------------------------------

    #[test]
    fn test_volumetric_triggers_two_of_three() {
        // High syn_rate and pkt_rate (2 of 3), high success ratio (not SYN flood)
        let stats = make_stats(600.0, 1500.0, 500_000.0, 0.9, true);
        let vol = VolumetricThresholds {
            syn_rate: 500.0,
            pkt_rate: 1000.0,
            byte_rate: 1_000_000.0,
        };
        let result = detect_abuse(&stats, 100.0, 0.1, &vol);

        assert_eq!(result.abuse_class, Some(AbuseClass::VolumetricTcpAbuse));
        assert_eq!(result.volumetric_metrics_exceeded, 2);
    }

    #[test]
    fn test_volumetric_triggers_all_three() {
        // All three volumetric metrics exceeded
        let stats = make_stats(600.0, 1500.0, 2_000_000.0, 0.9, true);
        let vol = VolumetricThresholds {
            syn_rate: 500.0,
            pkt_rate: 1000.0,
            byte_rate: 1_000_000.0,
        };
        let result = detect_abuse(&stats, 100.0, 0.1, &vol);

        assert_eq!(result.abuse_class, Some(AbuseClass::VolumetricTcpAbuse));
        assert_eq!(result.volumetric_metrics_exceeded, 3);
    }

    #[test]
    fn test_volumetric_not_triggered_one_of_three() {
        // Only one volumetric metric exceeded
        let stats = make_stats(600.0, 500.0, 500_000.0, 0.9, true);
        let vol = VolumetricThresholds {
            syn_rate: 500.0,
            pkt_rate: 1000.0,
            byte_rate: 1_000_000.0,
        };
        let result = detect_abuse(&stats, 100.0, 0.1, &vol);

        assert_eq!(result.abuse_class, None);
        assert_eq!(result.volumetric_metrics_exceeded, 1);
    }

    #[test]
    fn test_volumetric_does_not_require_low_success_ratio() {
        // The key difference from SYN flood: doesn't need low success ratio
        let stats = make_stats(600.0, 1500.0, 2_000_000.0, 0.95, true); // Very high success ratio
        let vol = VolumetricThresholds {
            syn_rate: 500.0,
            pkt_rate: 1000.0,
            byte_rate: 1_000_000.0,
        };
        let result = detect_abuse(&stats, 100.0, 0.1, &vol);

        // Should trigger volumetric (not SYN flood due to high success ratio)
        assert_eq!(result.abuse_class, Some(AbuseClass::VolumetricTcpAbuse));
    }

    // -------------------------------------------
    // Priority: SYN flood over volumetric
    // -------------------------------------------

    #[test]
    fn test_syn_flood_takes_priority_over_volumetric() {
        // Both conditions met: SYN flood AND volumetric
        let stats = make_stats(600.0, 1500.0, 2_000_000.0, 0.05, true);
        let vol = VolumetricThresholds {
            syn_rate: 500.0,
            pkt_rate: 1000.0,
            byte_rate: 1_000_000.0,
        };
        let result = detect_abuse(&stats, 100.0, 0.1, &vol);

        // SYN flood should take priority
        assert_eq!(result.abuse_class, Some(AbuseClass::SynFloodLike));
        assert_eq!(result.volumetric_metrics_exceeded, 3);
    }

    // -------------------------------------------
    // No abuse detected
    // -------------------------------------------

    #[test]
    fn test_no_abuse_legit_traffic() {
        // Low rates, high success ratio - legitimate traffic
        let stats = make_stats(50.0, 100.0, 50_000.0, 0.95, true);
        let result = detect_abuse(&stats, 100.0, 0.1, &default_volumetric());

        assert_eq!(result.abuse_class, None);
        assert_eq!(result.volumetric_metrics_exceeded, 0);
        assert_eq!(result.confidence, DetectionConfidence::High);
    }

    // -------------------------------------------
    // Extended stats creation
    // -------------------------------------------

    #[test]
    fn test_extended_stats_from_aggregated() {
        let agg = AggregatedStats {
            total_syn: 100,
            total_ack: 90,
            total_rst: 5,
            total_packets: 200,
            total_bytes: 20000,
            syn_rate: 10.0,
            success_ratio: 0.9,
        };

        let ext = ExtendedStats::from_aggregated(&agg, 10);

        assert!((ext.syn_rate - 10.0).abs() < 0.001);
        assert!((ext.pkt_rate - 20.0).abs() < 0.001);  // 200 / 10
        assert!((ext.byte_rate - 2000.0).abs() < 0.001); // 20000 / 10
        assert!((ext.success_ratio - 0.9).abs() < 0.001);
        assert!(ext.success_ratio_reliable); // 100 >= 10
    }

    #[test]
    fn test_extended_stats_unreliable_with_few_syn() {
        let agg = AggregatedStats {
            total_syn: 5, // Less than 10
            total_ack: 5,
            total_rst: 0,
            total_packets: 10,
            total_bytes: 1000,
            syn_rate: 0.5,
            success_ratio: 1.0,
        };

        let ext = ExtendedStats::from_aggregated(&agg, 10);

        assert!(!ext.success_ratio_reliable); // 5 < 10
    }

    // -------------------------------------------
    // Abuse class display
    // -------------------------------------------

    #[test]
    fn test_abuse_class_display() {
        assert_eq!(format!("{}", AbuseClass::SynFloodLike), "SYN_FLOOD_LIKE");
        assert_eq!(format!("{}", AbuseClass::VolumetricTcpAbuse), "VOLUMETRIC_TCP_ABUSE");
    }

    #[test]
    fn test_confidence_display() {
        assert_eq!(format!("{}", DetectionConfidence::High), "high");
        assert_eq!(format!("{}", DetectionConfidence::Medium), "medium");
        assert_eq!(format!("{}", DetectionConfidence::Low), "low");
    }

    // -------------------------------------------
    // Port 80 attack pattern (from the original bug report)
    // -------------------------------------------

    #[test]
    fn test_port_80_attack_pattern_triggers_volumetric() {
        // This is the scenario from the bug report:
        // High traffic on port 80 with HIGH success ratio (> 1.0 due to handshake_ack accounting)
        // SYN flood detector fails because success_ratio > 0.10
        // Volumetric detector should catch this
        let stats = make_stats(
            500.0,       // High SYN rate
            2000.0,      // High packet rate
            500_000.0,   // Moderate byte rate
            1.2,         // Success ratio > 1.0 (unreliable on busy web ports)
            false,       // Marked unreliable
        );
        let vol = VolumetricThresholds {
            syn_rate: 400.0,
            pkt_rate: 1000.0,
            byte_rate: 1_000_000.0,
        };
        let result = detect_abuse(&stats, 100.0, 0.1, &vol);

        // Should trigger VOLUMETRIC, not SYN_FLOOD (success ratio too high)
        assert_eq!(result.abuse_class, Some(AbuseClass::VolumetricTcpAbuse));
        assert_eq!(result.volumetric_metrics_exceeded, 2); // syn_rate and pkt_rate
    }

    #[test]
    fn test_classic_syn_flood_still_triggers() {
        // Classic SYN flood: high SYN rate, very low success ratio
        let stats = make_stats(
            200.0,       // High SYN rate
            250.0,       // Moderate packet rate (mostly just SYNs)
            25_000.0,    // Low byte rate (small packets)
            0.01,        // Very low success ratio
            true,
        );
        let result = detect_abuse(&stats, 100.0, 0.1, &default_volumetric());

        assert_eq!(result.abuse_class, Some(AbuseClass::SynFloodLike));
        assert_eq!(result.confidence, DetectionConfidence::High);
    }
}
