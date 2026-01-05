//! Rules generation for XDP-safe enforcement.

use crate::config::ReporterConfig;
use crate::counterfactual::Offender;
use crate::types::AggregatedKey;
use ibsr_schema::KeyType;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Enforcement rules output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementRules {
    pub version: u32,
    pub generated_at: u64,
    pub match_criteria: MatchCriteria,
    pub triggers: Vec<TriggerRule>,
    pub exceptions: Vec<Exception>,
}

/// Match criteria for the rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchCriteria {
    pub proto: String,
    pub dst_port: u16,
}

/// A single trigger rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerRule {
    pub key_type: String,
    pub key_value: String,
    pub window_sec: u64,
    pub syn_rate_threshold: f64,
    pub success_ratio_threshold: f64,
    pub action: Action,
}

/// Action to take when triggered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub action_type: String,
    pub duration_sec: u64,
}

/// An exception entry (allowlisted IP/CIDR).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exception {
    pub key_type: String,
    pub key_value: String,
}

/// Current rules schema version.
pub const RULES_VERSION: u32 = 1;

/// Generate enforcement rules from offenders.
pub fn generate(
    offenders: &[Offender],
    config: &ReporterConfig,
    generated_at: u64,
) -> EnforcementRules {
    let match_criteria = MatchCriteria {
        proto: "tcp".to_string(),
        dst_port: config.dst_port,
    };

    // Generate trigger rules from offenders, sorted for determinism
    let mut triggers: Vec<TriggerRule> = offenders
        .iter()
        .map(|o| TriggerRule {
            key_type: key_type_to_string(o.key.key_type),
            key_value: key_to_string(&o.key),
            window_sec: config.window_sec,
            syn_rate_threshold: config.syn_rate_threshold,
            success_ratio_threshold: config.success_ratio_threshold,
            action: Action {
                action_type: "drop".to_string(),
                duration_sec: config.block_duration_sec,
            },
        })
        .collect();

    // Sort for deterministic output (by key_type, then key_value)
    triggers.sort_by(|a, b| {
        a.key_type
            .cmp(&b.key_type)
            .then_with(|| a.key_value.cmp(&b.key_value))
    });

    // Generate exceptions from allowlist
    let mut exceptions = Vec::new();

    // Add individual IPs
    let mut ips: Vec<u32> = config.allowlist.ips().collect();
    ips.sort();
    for ip in ips {
        exceptions.push(Exception {
            key_type: "src_ip".to_string(),
            key_value: Ipv4Addr::from(ip).to_string(),
        });
    }

    // Add CIDRs
    let mut cidrs: Vec<(u32, u8)> = config.allowlist.cidrs().to_vec();
    cidrs.sort();
    for (network, prefix_len) in cidrs {
        exceptions.push(Exception {
            key_type: "src_cidr".to_string(),
            key_value: format!("{}/{}", Ipv4Addr::from(network), prefix_len),
        });
    }

    EnforcementRules {
        version: RULES_VERSION,
        generated_at,
        match_criteria,
        triggers,
        exceptions,
    }
}

/// Convert key type to string.
fn key_type_to_string(key_type: KeyType) -> String {
    match key_type {
        KeyType::SrcIp => "src_ip".to_string(),
        KeyType::SrcCidr24 => "src_cidr24".to_string(),
    }
}

/// Convert key to display string.
fn key_to_string(key: &AggregatedKey) -> String {
    let ip = Ipv4Addr::from(key.key_value);
    match key.key_type {
        KeyType::SrcIp => ip.to_string(),
        KeyType::SrcCidr24 => format!("{}/24", ip),
    }
}

impl EnforcementRules {
    /// Serialize to JSON string (pretty-printed for readability).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("Rules serialization cannot fail")
    }

    /// Serialize to compact JSON string (for embedding in report).
    pub fn to_json_compact(&self) -> String {
        serde_json::to_string(self).expect("Rules serialization cannot fail")
    }

    /// Deserialize from JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Allowlist, ReporterConfig};
    use ibsr_schema::KeyType;

    // ===========================================
    // Category E — Deterministic Outputs Tests (Rules)
    // ===========================================

    fn make_config() -> ReporterConfig {
        ReporterConfig::new(8080)
            .with_window_sec(10)
            .with_syn_rate_threshold(100.0)
            .with_success_ratio_threshold(0.1)
            .with_block_duration_sec(300)
    }

    fn make_offender(ip: u32, syn_rate: f64, key_type: KeyType) -> Offender {
        Offender {
            key: AggregatedKey::new(key_type, ip),
            syn_rate,
            success_ratio: 0.05,
            would_block_packets: 100,
            would_block_syn: 50,
            would_block_bytes: 10000,
        }
    }

    // -------------------------------------------
    // rules.json deterministic ordering
    // -------------------------------------------

    #[test]
    fn test_rules_triggers_sorted_by_key() {
        let config = make_config();
        let offenders = vec![
            make_offender(0x0A000003, 150.0, KeyType::SrcIp), // 10.0.0.3
            make_offender(0x0A000001, 150.0, KeyType::SrcIp), // 10.0.0.1
            make_offender(0x0A000002, 150.0, KeyType::SrcIp), // 10.0.0.2
        ];

        let rules = generate(&offenders, &config, 1000);

        // Should be sorted by key_value (IP address string)
        assert_eq!(rules.triggers.len(), 3);
        assert_eq!(rules.triggers[0].key_value, "10.0.0.1");
        assert_eq!(rules.triggers[1].key_value, "10.0.0.2");
        assert_eq!(rules.triggers[2].key_value, "10.0.0.3");
    }

    #[test]
    fn test_rules_triggers_sorted_by_key_type_then_value() {
        let config = make_config();
        let offenders = vec![
            make_offender(0x0A000000, 150.0, KeyType::SrcCidr24), // 10.0.0.0/24
            make_offender(0x0A000001, 150.0, KeyType::SrcIp),     // 10.0.0.1
        ];

        let rules = generate(&offenders, &config, 1000);

        // src_cidr24 < src_ip alphabetically
        assert_eq!(rules.triggers[0].key_type, "src_cidr24");
        assert_eq!(rules.triggers[1].key_type, "src_ip");
    }

    #[test]
    fn test_rules_deterministic_same_input() {
        let config = make_config();
        let offenders = vec![
            make_offender(0x0A000002, 150.0, KeyType::SrcIp),
            make_offender(0x0A000001, 150.0, KeyType::SrcIp),
        ];

        let rules1 = generate(&offenders, &config, 1000);
        let rules2 = generate(&offenders, &config, 1000);

        assert_eq!(rules1.to_json(), rules2.to_json());
    }

    // -------------------------------------------
    // rules.json valid JSON structure
    // -------------------------------------------

    #[test]
    fn test_rules_valid_json() {
        let config = make_config();
        let offenders = vec![make_offender(0x0A000001, 150.0, KeyType::SrcIp)];

        let rules = generate(&offenders, &config, 1000);
        let json = rules.to_json();

        // Should be valid JSON
        let parsed: EnforcementRules = EnforcementRules::from_json(&json).unwrap();
        assert_eq!(parsed.version, RULES_VERSION);
    }

    #[test]
    fn test_rules_round_trip() {
        let config = make_config();
        let offenders = vec![
            make_offender(0x0A000001, 150.0, KeyType::SrcIp),
            make_offender(0x0A000002, 200.0, KeyType::SrcIp),
        ];

        let rules = generate(&offenders, &config, 1000);
        let json = rules.to_json();
        let parsed = EnforcementRules::from_json(&json).unwrap();

        assert_eq!(parsed.triggers.len(), 2);
        assert_eq!(parsed.match_criteria.dst_port, 8080);
    }

    // -------------------------------------------
    // rules.json matches expected schema
    // -------------------------------------------

    #[test]
    fn test_rules_schema_fields() {
        let config = make_config();
        let offenders = vec![make_offender(0x0A000001, 150.0, KeyType::SrcIp)];

        let rules = generate(&offenders, &config, 1234567890);

        assert_eq!(rules.version, RULES_VERSION);
        assert_eq!(rules.generated_at, 1234567890);
        assert_eq!(rules.match_criteria.proto, "tcp");
        assert_eq!(rules.match_criteria.dst_port, 8080);
    }

    #[test]
    fn test_rules_trigger_fields() {
        let config = make_config();
        let offenders = vec![make_offender(0x0A000001, 150.0, KeyType::SrcIp)];

        let rules = generate(&offenders, &config, 1000);

        assert_eq!(rules.triggers.len(), 1);
        let trigger = &rules.triggers[0];

        assert_eq!(trigger.key_type, "src_ip");
        assert_eq!(trigger.key_value, "10.0.0.1");
        assert_eq!(trigger.window_sec, 10);
        assert!((trigger.syn_rate_threshold - 100.0).abs() < 0.001);
        assert!((trigger.success_ratio_threshold - 0.1).abs() < 0.001);
        assert_eq!(trigger.action.action_type, "drop");
        assert_eq!(trigger.action.duration_sec, 300);
    }

    #[test]
    fn test_rules_cidr_key_value_format() {
        let config = make_config();
        let offenders = vec![make_offender(0x0A000000, 150.0, KeyType::SrcCidr24)];

        let rules = generate(&offenders, &config, 1000);

        assert_eq!(rules.triggers[0].key_type, "src_cidr24");
        assert_eq!(rules.triggers[0].key_value, "10.0.0.0/24");
    }

    // -------------------------------------------
    // Exceptions from allowlist
    // -------------------------------------------

    #[test]
    fn test_rules_exceptions_from_allowlist_ip() {
        let mut allowlist = Allowlist::empty();
        allowlist.add_ip(0x0A000001); // 10.0.0.1

        let config = make_config().with_allowlist(allowlist);
        let rules = generate(&[], &config, 1000);

        assert_eq!(rules.exceptions.len(), 1);
        assert_eq!(rules.exceptions[0].key_type, "src_ip");
        assert_eq!(rules.exceptions[0].key_value, "10.0.0.1");
    }

    #[test]
    fn test_rules_exceptions_from_allowlist_cidr() {
        let mut allowlist = Allowlist::empty();
        allowlist.add_cidr(0xC0A80000, 24); // 192.168.0.0/24

        let config = make_config().with_allowlist(allowlist);
        let rules = generate(&[], &config, 1000);

        assert_eq!(rules.exceptions.len(), 1);
        assert_eq!(rules.exceptions[0].key_type, "src_cidr");
        assert_eq!(rules.exceptions[0].key_value, "192.168.0.0/24");
    }

    #[test]
    fn test_rules_exceptions_sorted() {
        let mut allowlist = Allowlist::empty();
        allowlist.add_ip(0x0A000003);
        allowlist.add_ip(0x0A000001);
        allowlist.add_ip(0x0A000002);

        let config = make_config().with_allowlist(allowlist);
        let rules = generate(&[], &config, 1000);

        // IPs should be sorted
        assert_eq!(rules.exceptions[0].key_value, "10.0.0.1");
        assert_eq!(rules.exceptions[1].key_value, "10.0.0.2");
        assert_eq!(rules.exceptions[2].key_value, "10.0.0.3");
    }

    #[test]
    fn test_rules_empty_exceptions_empty_allowlist() {
        let config = make_config();
        let rules = generate(&[], &config, 1000);

        assert!(rules.exceptions.is_empty());
    }

    // -------------------------------------------
    // Empty offenders
    // -------------------------------------------

    #[test]
    fn test_rules_empty_offenders() {
        let config = make_config();
        let rules = generate(&[], &config, 1000);

        assert!(rules.triggers.is_empty());
        assert_eq!(rules.match_criteria.dst_port, 8080);
    }

    // -------------------------------------------
    // JSON format
    // -------------------------------------------

    #[test]
    fn test_rules_to_json_compact() {
        let config = make_config();
        let offenders = vec![make_offender(0x0A000001, 150.0, KeyType::SrcIp)];

        let rules = generate(&offenders, &config, 1000);
        let compact = rules.to_json_compact();

        // Compact should have no newlines
        assert!(!compact.contains('\n'));
    }

    #[test]
    fn test_rules_to_json_pretty() {
        let config = make_config();
        let offenders = vec![make_offender(0x0A000001, 150.0, KeyType::SrcIp)];

        let rules = generate(&offenders, &config, 1000);
        let pretty = rules.to_json();

        // Pretty should have newlines
        assert!(pretty.contains('\n'));
    }
}
