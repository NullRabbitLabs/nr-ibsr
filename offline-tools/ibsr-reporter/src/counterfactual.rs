//! Counterfactual impact calculations.

use crate::config::ReporterConfig;
use crate::decision::{Decision, KeyDecision};
use crate::types::AggregatedKey;
use serde::{Deserialize, Serialize};

/// Result of counterfactual analysis.
#[derive(Debug, Clone)]
pub struct CounterfactualResult {
    pub percent_packets_blocked: f64,
    pub percent_bytes_blocked: f64,
    pub percent_syn_blocked: f64,
    pub top_offenders: Vec<Offender>,
    pub fp_bound: FpBound,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub total_syn: u64,
}

/// An offender entry for the top-N ranking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Offender {
    pub key: AggregatedKey,
    pub syn_rate: f64,
    pub success_ratio: f64,
    pub would_block_packets: u64,
    pub would_block_syn: u64,
    pub would_block_bytes: u64,
}

/// False positive bound.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FpBound {
    Computed(f64),
    Unknown { reason: String },
}

/// Compute counterfactual metrics from key decisions.
pub fn compute(decisions: &[KeyDecision], config: &ReporterConfig) -> CounterfactualResult {
    // Filter to non-allowlisted keys
    let non_allowlisted: Vec<_> = decisions.iter().filter(|d| !d.allowlisted).collect();

    // Calculate totals from non-allowlisted keys
    let total_packets: u64 = non_allowlisted.iter().map(|d| d.stats.total_packets).sum();
    let total_bytes: u64 = non_allowlisted.iter().map(|d| d.stats.total_bytes).sum();
    let total_syn: u64 = non_allowlisted.iter().map(|d| d.stats.total_syn).sum();

    // Calculate blocked totals (only from blocked, non-allowlisted keys)
    let blocked: Vec<_> = non_allowlisted
        .iter()
        .filter(|d| matches!(d.decision, Decision::Block { .. }))
        .collect();

    let blocked_packets: u64 = blocked.iter().map(|d| d.stats.total_packets).sum();
    let blocked_bytes: u64 = blocked.iter().map(|d| d.stats.total_bytes).sum();
    let blocked_syn: u64 = blocked.iter().map(|d| d.stats.total_syn).sum();

    // Calculate percentages (avoid div/0)
    let percent_packets_blocked = if total_packets > 0 {
        (blocked_packets as f64 / total_packets as f64) * 100.0
    } else {
        0.0
    };

    let percent_bytes_blocked = if total_bytes > 0 {
        (blocked_bytes as f64 / total_bytes as f64) * 100.0
    } else {
        0.0
    };

    let percent_syn_blocked = if total_syn > 0 {
        (blocked_syn as f64 / total_syn as f64) * 100.0
    } else {
        0.0
    };

    // Create offenders list from blocked keys
    let mut offenders: Vec<Offender> = blocked
        .iter()
        .map(|d| Offender {
            key: d.key,
            syn_rate: d.stats.syn_rate,
            success_ratio: d.stats.success_ratio,
            would_block_packets: d.stats.total_packets,
            would_block_syn: d.stats.total_syn,
            would_block_bytes: d.stats.total_bytes,
        })
        .collect();

    // Sort by would_block_syn descending (top offenders first)
    offenders.sort_by(|a, b| b.would_block_syn.cmp(&a.would_block_syn));

    // Limit to top N
    offenders.truncate(config.top_offenders_count);

    // Calculate FP bound
    let fp_bound = compute_fp_bound(&non_allowlisted, &blocked, config);

    CounterfactualResult {
        percent_packets_blocked,
        percent_bytes_blocked,
        percent_syn_blocked,
        top_offenders: offenders,
        fp_bound,
        total_packets,
        total_bytes,
        total_syn,
    }
}

/// Compute false-positive bound.
///
/// FP is the overlap between "would block" and "likely legitimate" keys.
/// A key is "likely legitimate" if success_ratio >= FP_SAFE_RATIO.
fn compute_fp_bound(
    all_keys: &[&KeyDecision],
    blocked_keys: &[&&KeyDecision],
    config: &ReporterConfig,
) -> FpBound {
    // Need minimum samples to compute FP
    if all_keys.len() < config.min_samples_for_fp {
        return FpBound::Unknown {
            reason: format!(
                "Insufficient data: {} keys, need at least {}",
                all_keys.len(),
                config.min_samples_for_fp
            ),
        };
    }

    // Find blocked keys that are "likely legitimate" (FP candidates)
    let fp_candidates: Vec<_> = blocked_keys
        .iter()
        .filter(|d| d.stats.success_ratio >= config.fp_safe_ratio)
        .collect();

    // Calculate FP as percentage of blocked traffic that's likely legitimate
    let total_blocked_packets: u64 = blocked_keys.iter().map(|d| d.stats.total_packets).sum();

    if total_blocked_packets == 0 {
        // No blocked traffic = 0% FP
        return FpBound::Computed(0.0);
    }

    let fp_packets: u64 = fp_candidates.iter().map(|d| d.stats.total_packets).sum();
    let fp_percent = (fp_packets as f64 / total_blocked_packets as f64) * 100.0;

    FpBound::Computed(fp_percent)
}

/// Get top N offenders sorted by impact.
pub fn top_offenders(offenders: &[Offender], n: usize) -> Vec<&Offender> {
    offenders.iter().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ReporterConfig;
    use crate::types::AggregatedStats;
    use ibsr_schema::KeyType;

    // ===========================================
    // Category D — Counterfactual Calculation Tests
    // ===========================================

    fn make_config() -> ReporterConfig {
        ReporterConfig::new(vec![8080])
            .with_syn_rate_threshold(100.0)
            .with_success_ratio_threshold(0.1)
    }

    fn make_key(ip: u32) -> AggregatedKey {
        AggregatedKey::new(KeyType::SrcIp, ip)
    }

    fn make_decision(
        ip: u32,
        packets: u64,
        bytes: u64,
        syn: u64,
        syn_rate: f64,
        success_ratio: f64,
        blocked: bool,
        allowlisted: bool,
    ) -> KeyDecision {
        KeyDecision {
            key: make_key(ip),
            stats: AggregatedStats {
                total_syn: syn,
                total_ack: (syn as f64 * success_ratio) as u64,
                total_rst: 0,
                total_packets: packets,
                total_bytes: bytes,
                syn_rate,
                success_ratio,
            },
            decision: if blocked {
                Decision::Block { until_ts: 1300 }
            } else {
                Decision::Allow
            },
            allowlisted,
        }
    }

    // -------------------------------------------
    // percent_packets_blocked calculation
    // -------------------------------------------

    #[test]
    fn test_percent_packets_blocked_basic() {
        let config = make_config();
        let decisions = vec![
            make_decision(1, 100, 10000, 50, 150.0, 0.05, true, false),  // blocked
            make_decision(2, 100, 10000, 50, 50.0, 0.5, false, false),   // allowed
        ];

        let result = compute(&decisions, &config);

        // 100 blocked / 200 total = 50%
        assert!((result.percent_packets_blocked - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_percent_packets_blocked_all_blocked() {
        let config = make_config();
        let decisions = vec![
            make_decision(1, 100, 10000, 50, 150.0, 0.05, true, false),
            make_decision(2, 100, 10000, 50, 150.0, 0.05, true, false),
        ];

        let result = compute(&decisions, &config);

        assert!((result.percent_packets_blocked - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_percent_packets_blocked_none_blocked() {
        let config = make_config();
        let decisions = vec![
            make_decision(1, 100, 10000, 50, 50.0, 0.5, false, false),
            make_decision(2, 100, 10000, 50, 50.0, 0.5, false, false),
        ];

        let result = compute(&decisions, &config);

        assert_eq!(result.percent_packets_blocked, 0.0);
    }

    // -------------------------------------------
    // percent_bytes_blocked calculation
    // -------------------------------------------

    #[test]
    fn test_percent_bytes_blocked() {
        let config = make_config();
        let decisions = vec![
            make_decision(1, 100, 30000, 50, 150.0, 0.05, true, false),  // blocked, 30k bytes
            make_decision(2, 100, 70000, 50, 50.0, 0.5, false, false),   // allowed, 70k bytes
        ];

        let result = compute(&decisions, &config);

        // 30000 blocked / 100000 total = 30%
        assert!((result.percent_bytes_blocked - 30.0).abs() < 0.001);
    }

    // -------------------------------------------
    // percent_syn_blocked calculation
    // -------------------------------------------

    #[test]
    fn test_percent_syn_blocked() {
        let config = make_config();
        let decisions = vec![
            make_decision(1, 100, 10000, 80, 150.0, 0.05, true, false),  // blocked, 80 syn
            make_decision(2, 100, 10000, 20, 50.0, 0.5, false, false),   // allowed, 20 syn
        ];

        let result = compute(&decisions, &config);

        // 80 blocked / 100 total = 80%
        assert!((result.percent_syn_blocked - 80.0).abs() < 0.001);
    }

    // -------------------------------------------
    // Handle zero totals (avoid div/0)
    // -------------------------------------------

    #[test]
    fn test_zero_totals_no_panic() {
        let config = make_config();
        let decisions = vec![
            make_decision(1, 0, 0, 0, 0.0, 0.0, true, false),
        ];

        let result = compute(&decisions, &config);

        assert_eq!(result.percent_packets_blocked, 0.0);
        assert_eq!(result.percent_bytes_blocked, 0.0);
        assert_eq!(result.percent_syn_blocked, 0.0);
    }

    #[test]
    fn test_empty_decisions() {
        let config = make_config();
        let result = compute(&[], &config);

        assert_eq!(result.percent_packets_blocked, 0.0);
        assert_eq!(result.percent_bytes_blocked, 0.0);
        assert_eq!(result.percent_syn_blocked, 0.0);
        assert!(result.top_offenders.is_empty());
    }

    // -------------------------------------------
    // Top offenders ranked by would_block_syn
    // -------------------------------------------

    #[test]
    fn test_top_offenders_ranked_by_syn() {
        let config = make_config();
        let decisions = vec![
            make_decision(1, 100, 10000, 50, 150.0, 0.05, true, false),   // 50 syn
            make_decision(2, 100, 10000, 200, 150.0, 0.05, true, false),  // 200 syn (highest)
            make_decision(3, 100, 10000, 100, 150.0, 0.05, true, false),  // 100 syn
        ];

        let result = compute(&decisions, &config);

        assert_eq!(result.top_offenders.len(), 3);
        // Should be sorted descending by would_block_syn
        assert_eq!(result.top_offenders[0].would_block_syn, 200);
        assert_eq!(result.top_offenders[1].would_block_syn, 100);
        assert_eq!(result.top_offenders[2].would_block_syn, 50);
    }

    #[test]
    fn test_top_offenders_limited_to_n() {
        let mut config = make_config();
        config.top_offenders_count = 2;

        let decisions = vec![
            make_decision(1, 100, 10000, 50, 150.0, 0.05, true, false),
            make_decision(2, 100, 10000, 200, 150.0, 0.05, true, false),
            make_decision(3, 100, 10000, 100, 150.0, 0.05, true, false),
        ];

        let result = compute(&decisions, &config);

        // Only top 2
        assert_eq!(result.top_offenders.len(), 2);
        assert_eq!(result.top_offenders[0].would_block_syn, 200);
        assert_eq!(result.top_offenders[1].would_block_syn, 100);
    }

    #[test]
    fn test_top_offenders_only_blocked() {
        let config = make_config();
        let decisions = vec![
            make_decision(1, 100, 10000, 50, 150.0, 0.05, true, false),   // blocked
            make_decision(2, 100, 10000, 200, 50.0, 0.5, false, false),   // allowed (not offender)
        ];

        let result = compute(&decisions, &config);

        // Only blocked key is an offender
        assert_eq!(result.top_offenders.len(), 1);
        assert_eq!(result.top_offenders[0].key.key_value, 1);
    }

    // -------------------------------------------
    // FP bound calculation
    // -------------------------------------------

    #[test]
    fn test_fp_bound_computed_no_fp() {
        let mut config = make_config();
        config.min_samples_for_fp = 2;
        config.fp_safe_ratio = 0.5;

        // All blocked keys have low success_ratio (< 0.5), so no FP
        let decisions = vec![
            make_decision(1, 100, 10000, 50, 150.0, 0.05, true, false),
            make_decision(2, 100, 10000, 50, 150.0, 0.08, true, false),
        ];

        let result = compute(&decisions, &config);

        assert_eq!(result.fp_bound, FpBound::Computed(0.0));
    }

    #[test]
    fn test_fp_bound_computed_with_fp() {
        let mut config = make_config();
        config.min_samples_for_fp = 2;
        config.fp_safe_ratio = 0.5;

        // One blocked key has high success_ratio (likely legitimate but still triggered)
        let decisions = vec![
            make_decision(1, 100, 10000, 50, 150.0, 0.05, true, false),  // bad actor
            make_decision(2, 100, 10000, 50, 150.0, 0.6, true, false),   // likely legitimate (FP)
        ];

        let result = compute(&decisions, &config);

        // 100 FP packets / 200 total blocked = 50%
        if let FpBound::Computed(fp) = result.fp_bound {
            assert!((fp - 50.0).abs() < 0.001);
        } else {
            panic!("Expected Computed FP bound");
        }
    }

    #[test]
    fn test_fp_bound_unknown_insufficient_data() {
        let mut config = make_config();
        config.min_samples_for_fp = 10;

        // Only 2 samples, need 10
        let decisions = vec![
            make_decision(1, 100, 10000, 50, 150.0, 0.05, true, false),
            make_decision(2, 100, 10000, 50, 150.0, 0.05, true, false),
        ];

        let result = compute(&decisions, &config);

        assert!(matches!(result.fp_bound, FpBound::Unknown { .. }));
        if let FpBound::Unknown { reason } = result.fp_bound {
            assert!(reason.contains("Insufficient data"));
        }
    }

    #[test]
    fn test_fp_bound_zero_when_no_blocked() {
        let mut config = make_config();
        config.min_samples_for_fp = 2;

        // All allowed, no blocked traffic
        let decisions = vec![
            make_decision(1, 100, 10000, 50, 50.0, 0.5, false, false),
            make_decision(2, 100, 10000, 50, 50.0, 0.5, false, false),
        ];

        let result = compute(&decisions, &config);

        // 0% FP when nothing blocked
        assert_eq!(result.fp_bound, FpBound::Computed(0.0));
    }

    // -------------------------------------------
    // Allowlisted keys excluded from all calculations
    // -------------------------------------------

    #[test]
    fn test_allowlisted_excluded_from_totals() {
        let config = make_config();
        let decisions = vec![
            make_decision(1, 100, 10000, 50, 150.0, 0.05, true, true),   // allowlisted
            make_decision(2, 100, 10000, 50, 150.0, 0.05, true, false),  // not allowlisted
        ];

        let result = compute(&decisions, &config);

        // Total should only include non-allowlisted
        assert_eq!(result.total_packets, 100);
        assert_eq!(result.total_bytes, 10000);
        assert_eq!(result.total_syn, 50);
    }

    #[test]
    fn test_allowlisted_excluded_from_offenders() {
        let config = make_config();
        let decisions = vec![
            make_decision(1, 100, 10000, 200, 150.0, 0.05, true, true),  // allowlisted, high syn
            make_decision(2, 100, 10000, 50, 150.0, 0.05, true, false),  // not allowlisted
        ];

        let result = compute(&decisions, &config);

        // Only non-allowlisted in offenders
        assert_eq!(result.top_offenders.len(), 1);
        assert_eq!(result.top_offenders[0].key.key_value, 2);
    }

    #[test]
    fn test_allowlisted_excluded_from_percentages() {
        let config = make_config();
        let decisions = vec![
            make_decision(1, 500, 50000, 250, 150.0, 0.05, true, true),  // allowlisted
            make_decision(2, 100, 10000, 50, 150.0, 0.05, true, false),  // blocked
            make_decision(3, 100, 10000, 50, 50.0, 0.5, false, false),   // allowed
        ];

        let result = compute(&decisions, &config);

        // Percentages based only on non-allowlisted (100 + 100 = 200 total)
        // 100 blocked / 200 total = 50%
        assert!((result.percent_packets_blocked - 50.0).abs() < 0.001);
    }

    // -------------------------------------------
    // Offender fields populated correctly
    // -------------------------------------------

    #[test]
    fn test_offender_fields() {
        let config = make_config();
        let decisions = vec![
            make_decision(0x0A000001, 150, 15000, 75, 120.0, 0.08, true, false),
        ];

        let result = compute(&decisions, &config);

        assert_eq!(result.top_offenders.len(), 1);
        let offender = &result.top_offenders[0];

        assert_eq!(offender.key.key_value, 0x0A000001);
        assert!((offender.syn_rate - 120.0).abs() < 0.001);
        assert!((offender.success_ratio - 0.08).abs() < 0.001);
        assert_eq!(offender.would_block_packets, 150);
        assert_eq!(offender.would_block_syn, 75);
        assert_eq!(offender.would_block_bytes, 15000);
    }

    // -------------------------------------------
    // top_offenders helper function
    // -------------------------------------------

    #[test]
    fn test_top_offenders_helper() {
        let offenders = vec![
            Offender {
                key: make_key(1),
                syn_rate: 100.0,
                success_ratio: 0.05,
                would_block_packets: 100,
                would_block_syn: 50,
                would_block_bytes: 10000,
            },
            Offender {
                key: make_key(2),
                syn_rate: 200.0,
                success_ratio: 0.05,
                would_block_packets: 200,
                would_block_syn: 100,
                would_block_bytes: 20000,
            },
        ];

        let top = top_offenders(&offenders, 1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].key.key_value, 1);
    }
}
