//! Decision engine - trigger logic and allowlist bypass.

use crate::config::ReporterConfig;
use crate::types::{AggregatedKey, AggregatedStats};
use serde::{Deserialize, Serialize};

/// Decision for a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Block { until_ts: u64 },
}

/// Result of evaluating a key.
#[derive(Debug, Clone)]
pub struct KeyDecision {
    pub key: AggregatedKey,
    pub stats: AggregatedStats,
    pub decision: Decision,
    pub allowlisted: bool,
}

/// Evaluate a single key against the trigger condition.
///
/// Trigger fires when:
/// - `syn_rate >= syn_rate_threshold`
/// - AND `success_ratio <= success_ratio_threshold`
///
/// If allowlisted, always returns Allow.
pub fn evaluate_key(
    key: AggregatedKey,
    stats: AggregatedStats,
    config: &ReporterConfig,
    current_ts: u64,
) -> KeyDecision {
    let allowlisted = config.allowlist.contains(key.key_value);

    let decision = if allowlisted {
        Decision::Allow
    } else if should_trigger(&stats, config) {
        Decision::Block {
            until_ts: current_ts + config.block_duration_sec,
        }
    } else {
        Decision::Allow
    };

    KeyDecision {
        key,
        stats,
        decision,
        allowlisted,
    }
}

/// Check if trigger condition is met.
fn should_trigger(stats: &AggregatedStats, config: &ReporterConfig) -> bool {
    stats.syn_rate >= config.syn_rate_threshold
        && stats.success_ratio <= config.success_ratio_threshold
}

/// Evaluate all keys and return decisions.
pub fn evaluate_all(
    aggregated: &[(AggregatedKey, AggregatedStats)],
    config: &ReporterConfig,
    current_ts: u64,
) -> Vec<KeyDecision> {
    aggregated
        .iter()
        .map(|(key, stats)| evaluate_key(*key, *stats, config, current_ts))
        .collect()
}

/// Filter to only blocked (non-allowlisted) keys.
pub fn blocked_keys(decisions: &[KeyDecision]) -> Vec<&KeyDecision> {
    decisions
        .iter()
        .filter(|d| matches!(d.decision, Decision::Block { .. }) && !d.allowlisted)
        .collect()
}

/// Filter to non-allowlisted keys (for offender ranking).
pub fn non_allowlisted_keys(decisions: &[KeyDecision]) -> Vec<&KeyDecision> {
    decisions.iter().filter(|d| !d.allowlisted).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Allowlist, ReporterConfig};
    use ibsr_schema::KeyType;

    // ===========================================
    // Category C — Decision Engine Tests
    // ===========================================

    fn make_config() -> ReporterConfig {
        ReporterConfig::new(vec![8080])
            .with_syn_rate_threshold(100.0)
            .with_success_ratio_threshold(0.1)
            .with_block_duration_sec(300)
    }

    fn make_key(ip: u32) -> AggregatedKey {
        AggregatedKey::new(KeyType::SrcIp, ip, Some(8080))
    }

    fn make_stats(syn_rate: f64, success_ratio: f64) -> AggregatedStats {
        AggregatedStats {
            total_syn: 1000,
            total_ack: (1000.0 * success_ratio) as u64,
            total_rst: 0,
            total_packets: 1000,
            total_bytes: 100000,
            syn_rate,
            success_ratio,
        }
    }

    // -------------------------------------------
    // Trigger fires when both conditions met
    // -------------------------------------------

    #[test]
    fn test_trigger_fires_both_conditions_met() {
        let config = make_config();
        let key = make_key(0x0A000001);
        // syn_rate = 150 >= 100, success_ratio = 0.05 <= 0.1
        let stats = make_stats(150.0, 0.05);

        let result = evaluate_key(key, stats, &config, 1000);

        assert!(matches!(result.decision, Decision::Block { until_ts: 1300 }));
        assert!(!result.allowlisted);
    }

    #[test]
    fn test_trigger_fires_exact_thresholds() {
        let config = make_config();
        let key = make_key(0x0A000001);
        // syn_rate = 100 (exactly threshold), success_ratio = 0.1 (exactly threshold)
        let stats = make_stats(100.0, 0.1);

        let result = evaluate_key(key, stats, &config, 1000);

        assert!(matches!(result.decision, Decision::Block { .. }));
    }

    // -------------------------------------------
    // No trigger when syn_rate below threshold
    // -------------------------------------------

    #[test]
    fn test_no_trigger_syn_rate_below() {
        let config = make_config();
        let key = make_key(0x0A000001);
        // syn_rate = 50 < 100, success_ratio = 0.05 <= 0.1
        let stats = make_stats(50.0, 0.05);

        let result = evaluate_key(key, stats, &config, 1000);

        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_no_trigger_syn_rate_just_below() {
        let config = make_config();
        let key = make_key(0x0A000001);
        // syn_rate = 99.9 < 100
        let stats = make_stats(99.9, 0.05);

        let result = evaluate_key(key, stats, &config, 1000);

        assert_eq!(result.decision, Decision::Allow);
    }

    // -------------------------------------------
    // No trigger when success_ratio above threshold
    // -------------------------------------------

    #[test]
    fn test_no_trigger_success_ratio_above() {
        let config = make_config();
        let key = make_key(0x0A000001);
        // syn_rate = 150 >= 100, success_ratio = 0.5 > 0.1
        let stats = make_stats(150.0, 0.5);

        let result = evaluate_key(key, stats, &config, 1000);

        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_no_trigger_success_ratio_just_above() {
        let config = make_config();
        let key = make_key(0x0A000001);
        // syn_rate = 150, success_ratio = 0.11 > 0.1
        let stats = make_stats(150.0, 0.11);

        let result = evaluate_key(key, stats, &config, 1000);

        assert_eq!(result.decision, Decision::Allow);
    }

    // -------------------------------------------
    // No trigger when neither condition met
    // -------------------------------------------

    #[test]
    fn test_no_trigger_neither_condition() {
        let config = make_config();
        let key = make_key(0x0A000001);
        // syn_rate = 50 < 100, success_ratio = 0.5 > 0.1
        let stats = make_stats(50.0, 0.5);

        let result = evaluate_key(key, stats, &config, 1000);

        assert_eq!(result.decision, Decision::Allow);
    }

    // -------------------------------------------
    // Block duration applied correctly
    // -------------------------------------------

    #[test]
    fn test_block_duration() {
        let config = make_config();
        let key = make_key(0x0A000001);
        let stats = make_stats(150.0, 0.05);

        let result = evaluate_key(key, stats, &config, 1000);

        if let Decision::Block { until_ts } = result.decision {
            // current_ts (1000) + block_duration (300) = 1300
            assert_eq!(until_ts, 1300);
        } else {
            panic!("Expected Block decision");
        }
    }

    #[test]
    fn test_block_duration_different_config() {
        let config = ReporterConfig::new(vec![8080])
            .with_syn_rate_threshold(100.0)
            .with_success_ratio_threshold(0.1)
            .with_block_duration_sec(600);

        let key = make_key(0x0A000001);
        let stats = make_stats(150.0, 0.05);

        let result = evaluate_key(key, stats, &config, 2000);

        if let Decision::Block { until_ts } = result.decision {
            assert_eq!(until_ts, 2600);
        } else {
            panic!("Expected Block decision");
        }
    }

    // -------------------------------------------
    // Allowlist IP always ALLOW
    // -------------------------------------------

    #[test]
    fn test_allowlist_ip_always_allow() {
        let mut allowlist = Allowlist::empty();
        allowlist.add_ip(0x0A000001);

        let config = ReporterConfig::new(vec![8080])
            .with_syn_rate_threshold(100.0)
            .with_success_ratio_threshold(0.1)
            .with_allowlist(allowlist);

        let key = make_key(0x0A000001);
        // Would trigger without allowlist
        let stats = make_stats(150.0, 0.05);

        let result = evaluate_key(key, stats, &config, 1000);

        assert_eq!(result.decision, Decision::Allow);
        assert!(result.allowlisted);
    }

    #[test]
    fn test_allowlist_ip_non_matching_still_blocks() {
        let mut allowlist = Allowlist::empty();
        allowlist.add_ip(0x0A000001);

        let config = ReporterConfig::new(vec![8080])
            .with_syn_rate_threshold(100.0)
            .with_success_ratio_threshold(0.1)
            .with_allowlist(allowlist);

        // Different IP
        let key = make_key(0x0A000002);
        let stats = make_stats(150.0, 0.05);

        let result = evaluate_key(key, stats, &config, 1000);

        assert!(matches!(result.decision, Decision::Block { .. }));
        assert!(!result.allowlisted);
    }

    // -------------------------------------------
    // Allowlist CIDR always ALLOW
    // -------------------------------------------

    #[test]
    fn test_allowlist_cidr_always_allow() {
        let mut allowlist = Allowlist::empty();
        allowlist.add_cidr(0x0A000000, 24); // 10.0.0.0/24

        let config = ReporterConfig::new(vec![8080])
            .with_syn_rate_threshold(100.0)
            .with_success_ratio_threshold(0.1)
            .with_allowlist(allowlist);

        // 10.0.0.1 is in 10.0.0.0/24
        let key = make_key(0x0A000001);
        let stats = make_stats(150.0, 0.05);

        let result = evaluate_key(key, stats, &config, 1000);

        assert_eq!(result.decision, Decision::Allow);
        assert!(result.allowlisted);
    }

    #[test]
    fn test_allowlist_cidr_out_of_range_blocks() {
        let mut allowlist = Allowlist::empty();
        allowlist.add_cidr(0x0A000000, 24); // 10.0.0.0/24

        let config = ReporterConfig::new(vec![8080])
            .with_syn_rate_threshold(100.0)
            .with_success_ratio_threshold(0.1)
            .with_allowlist(allowlist);

        // 10.0.1.1 is NOT in 10.0.0.0/24
        let key = make_key(0x0A000101);
        let stats = make_stats(150.0, 0.05);

        let result = evaluate_key(key, stats, &config, 1000);

        assert!(matches!(result.decision, Decision::Block { .. }));
        assert!(!result.allowlisted);
    }

    // -------------------------------------------
    // Allowlisted keys excluded from rankings
    // -------------------------------------------

    #[test]
    fn test_non_allowlisted_keys_filter() {
        let mut allowlist = Allowlist::empty();
        allowlist.add_ip(0x0A000001);

        let config = ReporterConfig::new(vec![8080])
            .with_syn_rate_threshold(100.0)
            .with_success_ratio_threshold(0.1)
            .with_allowlist(allowlist);

        let entries = vec![
            (make_key(0x0A000001), make_stats(150.0, 0.05)), // allowlisted
            (make_key(0x0A000002), make_stats(150.0, 0.05)), // not allowlisted
            (make_key(0x0A000003), make_stats(50.0, 0.5)),   // not allowlisted, not blocked
        ];

        let decisions = evaluate_all(&entries, &config, 1000);
        let non_allowlisted = non_allowlisted_keys(&decisions);

        // Should exclude allowlisted key
        assert_eq!(non_allowlisted.len(), 2);
        assert!(non_allowlisted.iter().all(|d| d.key.key_value != 0x0A000001));
    }

    #[test]
    fn test_blocked_keys_filter() {
        let config = make_config();

        let entries = vec![
            (make_key(0x0A000001), make_stats(150.0, 0.05)), // blocked
            (make_key(0x0A000002), make_stats(50.0, 0.5)),   // allowed
            (make_key(0x0A000003), make_stats(200.0, 0.01)), // blocked
        ];

        let decisions = evaluate_all(&entries, &config, 1000);
        let blocked = blocked_keys(&decisions);

        assert_eq!(blocked.len(), 2);
        assert!(blocked.iter().any(|d| d.key.key_value == 0x0A000001));
        assert!(blocked.iter().any(|d| d.key.key_value == 0x0A000003));
    }

    // -------------------------------------------
    // Empty allowlist (no bypasses)
    // -------------------------------------------

    #[test]
    fn test_empty_allowlist_no_bypasses() {
        let config = make_config(); // empty allowlist by default

        let key = make_key(0x0A000001);
        let stats = make_stats(150.0, 0.05);

        let result = evaluate_key(key, stats, &config, 1000);

        assert!(matches!(result.decision, Decision::Block { .. }));
        assert!(!result.allowlisted);
    }

    // -------------------------------------------
    // evaluate_all
    // -------------------------------------------

    #[test]
    fn test_evaluate_all_multiple_keys() {
        let config = make_config();

        let entries = vec![
            (make_key(0x0A000001), make_stats(150.0, 0.05)), // blocked
            (make_key(0x0A000002), make_stats(50.0, 0.5)),   // allowed
        ];

        let decisions = evaluate_all(&entries, &config, 1000);

        assert_eq!(decisions.len(), 2);
        assert!(matches!(decisions[0].decision, Decision::Block { .. }));
        assert_eq!(decisions[1].decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_all_empty() {
        let config = make_config();
        let decisions = evaluate_all(&[], &config, 1000);
        assert!(decisions.is_empty());
    }
}
