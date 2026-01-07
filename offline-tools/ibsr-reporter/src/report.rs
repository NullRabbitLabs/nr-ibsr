//! Report generation (report.md).

use crate::config::ReporterConfig;
use crate::counterfactual::{CounterfactualResult, FpBound};
use crate::rules::EnforcementRules;
use crate::types::WindowBounds;
use serde::{Deserialize, Serialize};

/// Readiness judgment for autonomous enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessJudgment {
    pub is_safe: bool,
    pub reasons: Vec<String>,
}

/// Generated report.
#[derive(Debug, Clone)]
pub struct Report {
    pub content: String,
    pub readiness: ReadinessJudgment,
}

/// Generate the IBSR report.
pub fn generate(
    bounds: &WindowBounds,
    config: &ReporterConfig,
    counterfactual: &CounterfactualResult,
    rules: &EnforcementRules,
) -> Report {
    let readiness = compute_readiness(counterfactual, config);
    let content = build_report(bounds, config, counterfactual, rules, &readiness);

    Report { content, readiness }
}

/// Compute readiness judgment.
fn compute_readiness(result: &CounterfactualResult, _config: &ReporterConfig) -> ReadinessJudgment {
    let mut reasons = Vec::new();

    // Check FP bound
    match &result.fp_bound {
        FpBound::Unknown { reason } => {
            reasons.push(format!("False positive bound unknown: {}", reason));
        }
        FpBound::Computed(fp) if *fp > 5.0 => {
            reasons.push(format!("False positive bound too high: {:.1}%", fp));
        }
        _ => {}
    }

    // Check if any offenders found
    if result.top_offenders.is_empty() {
        reasons.push("No abuse pattern detected".to_string());
    }

    // Check impact is meaningful
    if result.percent_syn_blocked < 1.0 && !result.top_offenders.is_empty() {
        reasons.push("Minimal impact (<1% SYN blocked)".to_string());
    }

    // Check total traffic
    if result.total_packets == 0 {
        reasons.push("No traffic observed".to_string());
    }

    ReadinessJudgment {
        is_safe: reasons.is_empty(),
        reasons,
    }
}

/// Build the report markdown content.
fn build_report(
    bounds: &WindowBounds,
    config: &ReporterConfig,
    counterfactual: &CounterfactualResult,
    rules: &EnforcementRules,
    readiness: &ReadinessJudgment,
) -> String {
    let mut report = String::new();

    // Title
    report.push_str("# IBSR Report\n\n");

    // Section 1: Scope & Configuration
    report.push_str("## 1. Scope & Configuration\n\n");
    report.push_str(&format!("- **Time window start**: {}\n", bounds.start_ts));
    report.push_str(&format!("- **Time window end**: {}\n", bounds.end_ts));
    report.push_str(&format!("- **Duration**: {} seconds\n", bounds.duration_sec()));
    let ports_str = config.dst_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
    report.push_str(&format!("- **Destination ports**: {}\n", ports_str));
    report.push_str(&format!("- **Window size**: {} seconds\n", config.window_sec));
    report.push_str(&format!("- **SYN rate threshold**: {:.1} SYN/sec\n", config.syn_rate_threshold));
    report.push_str(&format!("- **Success ratio threshold**: {:.2}\n", config.success_ratio_threshold));
    report.push_str(&format!("- **Block duration**: {} seconds\n", config.block_duration_sec));

    // Allowlist summary
    let ip_count = config.allowlist.ip_count();
    let cidr_count = config.allowlist.cidr_count();
    if ip_count == 0 && cidr_count == 0 {
        report.push_str("- **Allowlist**: None configured\n");
    } else {
        report.push_str(&format!("- **Allowlist**: {} IPs, {} CIDRs\n", ip_count, cidr_count));
    }
    report.push('\n');

    // Section 2: Abuse Pattern Observed
    report.push_str("## 2. Abuse Pattern Observed\n\n");

    if counterfactual.top_offenders.is_empty() {
        report.push_str("No abuse pattern detected matching the trigger conditions.\n\n");
    } else {
        report.push_str(&format!(
            "Detected {} source(s) matching abuse pattern (TCP SYN churn).\n\n",
            counterfactual.top_offenders.len()
        ));

        report.push_str("### Top Offenders\n\n");
        report.push_str("| Source | SYN Rate | Success Ratio | Would Block Packets | Would Block SYN |\n");
        report.push_str("|--------|----------|---------------|---------------------|------------------|\n");

        for offender in &counterfactual.top_offenders {
            report.push_str(&format!(
                "| {} | {:.1}/sec | {:.2} | {} | {} |\n",
                offender.key.to_display_string(),
                offender.syn_rate,
                offender.success_ratio,
                offender.would_block_packets,
                offender.would_block_syn,
            ));
        }
        report.push('\n');
    }

    // Section 3: Counterfactual Enforcement Impact
    report.push_str("## 3. Counterfactual Enforcement Impact\n\n");

    report.push_str("### Blocked Traffic (if rules were enforced)\n\n");
    report.push_str(&format!("- **Packets blocked**: {:.1}%\n", counterfactual.percent_packets_blocked));
    report.push_str(&format!("- **Bytes blocked**: {:.1}%\n", counterfactual.percent_bytes_blocked));
    report.push_str(&format!("- **SYN blocked**: {:.1}%\n", counterfactual.percent_syn_blocked));
    report.push('\n');

    report.push_str("### False Positive Bound\n\n");
    match &counterfactual.fp_bound {
        FpBound::Computed(fp) => {
            report.push_str(&format!("- **FP bound**: {:.1}%\n", fp));
            if *fp == 0.0 {
                report.push_str("- No likely legitimate traffic would be blocked.\n");
            } else if *fp <= 5.0 {
                report.push_str("- FP bound is within acceptable range (<= 5%).\n");
            } else {
                report.push_str("- **WARNING**: FP bound exceeds acceptable threshold (> 5%).\n");
            }
        }
        FpBound::Unknown { reason } => {
            report.push_str(&format!("- **FP bound**: UNKNOWN\n"));
            report.push_str(&format!("- **Reason**: {}\n", reason));
            report.push_str("- Enforcement decision should be made with caution.\n");
        }
    }
    report.push('\n');

    report.push_str("### Uncertainty\n\n");
    if counterfactual.total_packets == 0 {
        report.push_str("- No traffic was observed during the analysis window.\n");
    } else {
        report.push_str(&format!(
            "- Analysis based on {} total packets, {} total SYN.\n",
            counterfactual.total_packets, counterfactual.total_syn
        ));
    }
    report.push('\n');

    // Section 4: Candidate Enforcement Rules
    report.push_str("## 4. Candidate Enforcement Rules\n\n");
    report.push_str("```json\n");
    report.push_str(&rules.to_json());
    report.push_str("```\n\n");

    // Section 5: Readiness Judgment
    report.push_str("## 5. Readiness Judgment\n\n");

    if readiness.is_safe {
        report.push_str("**This abuse class IS safe for autonomous enforcement.**\n\n");
        report.push_str("All safety criteria have been met:\n");
        report.push_str("- Abuse pattern clearly detected\n");
        report.push_str("- False positive bound within acceptable limits\n");
        report.push_str("- Meaningful impact on malicious traffic\n");
    } else {
        report.push_str("**This abuse class IS NOT safe for autonomous enforcement.**\n\n");
        report.push_str("Gating reasons:\n\n");
        for reason in &readiness.reasons {
            report.push_str(&format!("- {}\n", reason));
        }
    }
    report.push('\n');

    report
}

impl Report {
    /// Check if report contains a specific section header.
    pub fn has_section(&self, section_number: u8, title: &str) -> bool {
        let header = format!("## {}. {}", section_number, title);
        self.content.contains(&header)
    }

    /// Check if report contains text.
    pub fn contains(&self, text: &str) -> bool {
        self.content.contains(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ReporterConfig;
    use crate::counterfactual::Offender;
    use crate::rules::generate as generate_rules;
    use crate::types::AggregatedKey;
    use ibsr_schema::KeyType;

    // ===========================================
    // Category E — Deterministic Outputs Tests (Report)
    // ===========================================

    fn make_config() -> ReporterConfig {
        ReporterConfig::new(vec![8080])
            .with_window_sec(10)
            .with_syn_rate_threshold(100.0)
            .with_success_ratio_threshold(0.1)
            .with_block_duration_sec(300)
    }

    fn make_bounds() -> WindowBounds {
        WindowBounds::new(1000, 1010)
    }

    fn make_offender(ip: u32, syn_rate: f64) -> Offender {
        Offender {
            key: AggregatedKey::new(KeyType::SrcIp, ip, Some(8080)),
            syn_rate,
            success_ratio: 0.05,
            would_block_packets: 100,
            would_block_syn: 50,
            would_block_bytes: 10000,
        }
    }

    fn make_counterfactual_with_offenders() -> CounterfactualResult {
        CounterfactualResult {
            percent_packets_blocked: 50.0,
            percent_bytes_blocked: 45.0,
            percent_syn_blocked: 60.0,
            top_offenders: vec![
                make_offender(0x0A000001, 150.0),
                make_offender(0x0A000002, 120.0),
            ],
            fp_bound: FpBound::Computed(2.5),
            total_packets: 1000,
            total_bytes: 100000,
            total_syn: 500,
        }
    }

    fn make_counterfactual_no_offenders() -> CounterfactualResult {
        CounterfactualResult {
            percent_packets_blocked: 0.0,
            percent_bytes_blocked: 0.0,
            percent_syn_blocked: 0.0,
            top_offenders: vec![],
            fp_bound: FpBound::Computed(0.0),
            total_packets: 1000,
            total_bytes: 100000,
            total_syn: 500,
        }
    }

    // -------------------------------------------
    // report.md contains Section 1: Scope & configuration
    // -------------------------------------------

    #[test]
    fn test_report_section_1_exists() {
        let config = make_config();
        let bounds = make_bounds();
        let cf = make_counterfactual_with_offenders();
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(report.has_section(1, "Scope & Configuration"));
    }

    #[test]
    fn test_report_section_1_contains_time_window() {
        let config = make_config();
        let bounds = WindowBounds::new(1000, 1010);
        let cf = make_counterfactual_with_offenders();
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(report.contains("Time window start"));
        assert!(report.contains("1000"));
        assert!(report.contains("Time window end"));
        assert!(report.contains("1010"));
    }

    #[test]
    fn test_report_section_1_contains_dst_ports() {
        let config = make_config();
        let bounds = make_bounds();
        let cf = make_counterfactual_with_offenders();
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(report.contains("Destination ports"));
        assert!(report.contains("8080"));
    }

    #[test]
    fn test_report_section_1_contains_thresholds() {
        let config = make_config();
        let bounds = make_bounds();
        let cf = make_counterfactual_with_offenders();
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(report.contains("SYN rate threshold"));
        assert!(report.contains("100.0"));
        assert!(report.contains("Success ratio threshold"));
        assert!(report.contains("0.10"));
    }

    #[test]
    fn test_report_section_1_contains_allowlist_summary() {
        let config = make_config();
        let bounds = make_bounds();
        let cf = make_counterfactual_with_offenders();
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(report.contains("Allowlist"));
    }

    // -------------------------------------------
    // report.md contains Section 2: Abuse pattern observed
    // -------------------------------------------

    #[test]
    fn test_report_section_2_exists() {
        let config = make_config();
        let bounds = make_bounds();
        let cf = make_counterfactual_with_offenders();
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(report.has_section(2, "Abuse Pattern Observed"));
    }

    #[test]
    fn test_report_section_2_lists_top_offenders() {
        let config = make_config();
        let bounds = make_bounds();
        let cf = make_counterfactual_with_offenders();
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(report.contains("Top Offenders"));
        assert!(report.contains("10.0.0.1")); // First offender IP
        assert!(report.contains("10.0.0.2")); // Second offender IP
    }

    #[test]
    fn test_report_section_2_no_offenders() {
        let config = make_config();
        let bounds = make_bounds();
        let cf = make_counterfactual_no_offenders();
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(report.contains("No abuse pattern detected"));
    }

    // -------------------------------------------
    // report.md contains Section 3: Counterfactual impact
    // -------------------------------------------

    #[test]
    fn test_report_section_3_exists() {
        let config = make_config();
        let bounds = make_bounds();
        let cf = make_counterfactual_with_offenders();
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(report.has_section(3, "Counterfactual Enforcement Impact"));
    }

    #[test]
    fn test_report_section_3_contains_blocked_percentages() {
        let config = make_config();
        let bounds = make_bounds();
        let cf = make_counterfactual_with_offenders();
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(report.contains("Packets blocked"));
        assert!(report.contains("50.0%"));
        assert!(report.contains("Bytes blocked"));
        assert!(report.contains("SYN blocked"));
    }

    #[test]
    fn test_report_section_3_contains_fp_bound() {
        let config = make_config();
        let bounds = make_bounds();
        let cf = make_counterfactual_with_offenders();
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(report.contains("FP bound"));
        assert!(report.contains("2.5%"));
    }

    #[test]
    fn test_report_section_3_fp_unknown() {
        let config = make_config();
        let bounds = make_bounds();
        let mut cf = make_counterfactual_with_offenders();
        cf.fp_bound = FpBound::Unknown {
            reason: "Insufficient data".to_string(),
        };
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(report.contains("UNKNOWN"));
        assert!(report.contains("Insufficient data"));
    }

    // -------------------------------------------
    // report.md contains Section 4: Embedded rules.json
    // -------------------------------------------

    #[test]
    fn test_report_section_4_exists() {
        let config = make_config();
        let bounds = make_bounds();
        let cf = make_counterfactual_with_offenders();
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(report.has_section(4, "Candidate Enforcement Rules"));
    }

    #[test]
    fn test_report_section_4_contains_json_block() {
        let config = make_config();
        let bounds = make_bounds();
        let cf = make_counterfactual_with_offenders();
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(report.contains("```json"));
        assert!(report.contains("\"version\""));
        assert!(report.contains("\"triggers\""));
    }

    // -------------------------------------------
    // report.md contains Section 5: Readiness judgment
    // -------------------------------------------

    #[test]
    fn test_report_section_5_exists() {
        let config = make_config();
        let bounds = make_bounds();
        let cf = make_counterfactual_with_offenders();
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(report.has_section(5, "Readiness Judgment"));
    }

    #[test]
    fn test_report_section_5_is_safe() {
        let config = make_config();
        let bounds = make_bounds();
        let cf = make_counterfactual_with_offenders();
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(report.readiness.is_safe);
        assert!(report.contains("IS safe for autonomous enforcement"));
    }

    #[test]
    fn test_report_section_5_not_safe_no_offenders() {
        let config = make_config();
        let bounds = make_bounds();
        let cf = make_counterfactual_no_offenders();
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(!report.readiness.is_safe);
        assert!(report.contains("IS NOT safe for autonomous enforcement"));
        assert!(report.contains("No abuse pattern detected"));
    }

    #[test]
    fn test_report_section_5_not_safe_high_fp() {
        let config = make_config();
        let bounds = make_bounds();
        let mut cf = make_counterfactual_with_offenders();
        cf.fp_bound = FpBound::Computed(10.0); // High FP
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(!report.readiness.is_safe);
        assert!(report.contains("IS NOT safe"));
        assert!(report.readiness.reasons.iter().any(|r| r.contains("False positive bound too high")));
    }

    #[test]
    fn test_report_section_5_not_safe_fp_unknown() {
        let config = make_config();
        let bounds = make_bounds();
        let mut cf = make_counterfactual_with_offenders();
        cf.fp_bound = FpBound::Unknown {
            reason: "Test reason".to_string(),
        };
        let rules = generate_rules(&cf.top_offenders, &config, 1000);

        let report = generate(&bounds, &config, &cf, &rules);

        assert!(!report.readiness.is_safe);
        assert!(report.readiness.reasons.iter().any(|r| r.contains("False positive bound unknown")));
    }

    // -------------------------------------------
    // Readiness judgment logic
    // -------------------------------------------

    #[test]
    fn test_readiness_safe_conditions() {
        let mut config = make_config();
        config.min_samples_for_fp = 1; // Low threshold for testing

        let cf = CounterfactualResult {
            percent_packets_blocked: 50.0,
            percent_bytes_blocked: 50.0,
            percent_syn_blocked: 50.0,
            top_offenders: vec![make_offender(1, 150.0)],
            fp_bound: FpBound::Computed(2.0),
            total_packets: 1000,
            total_bytes: 100000,
            total_syn: 500,
        };

        let readiness = compute_readiness(&cf, &config);

        assert!(readiness.is_safe);
        assert!(readiness.reasons.is_empty());
    }

    #[test]
    fn test_readiness_minimal_impact() {
        let config = make_config();

        let cf = CounterfactualResult {
            percent_packets_blocked: 0.5,
            percent_bytes_blocked: 0.5,
            percent_syn_blocked: 0.5, // < 1%
            top_offenders: vec![make_offender(1, 150.0)],
            fp_bound: FpBound::Computed(0.0),
            total_packets: 1000,
            total_bytes: 100000,
            total_syn: 500,
        };

        let readiness = compute_readiness(&cf, &config);

        assert!(!readiness.is_safe);
        assert!(readiness.reasons.iter().any(|r| r.contains("Minimal impact")));
    }

    #[test]
    fn test_readiness_no_traffic() {
        let config = make_config();

        let cf = CounterfactualResult {
            percent_packets_blocked: 0.0,
            percent_bytes_blocked: 0.0,
            percent_syn_blocked: 0.0,
            top_offenders: vec![],
            fp_bound: FpBound::Computed(0.0),
            total_packets: 0,
            total_bytes: 0,
            total_syn: 0,
        };

        let readiness = compute_readiness(&cf, &config);

        assert!(!readiness.is_safe);
        assert!(readiness.reasons.iter().any(|r| r.contains("No traffic observed")));
    }

    // -------------------------------------------
    // Report helper methods
    // -------------------------------------------

    #[test]
    fn test_report_has_section_helper() {
        let report = Report {
            content: "## 1. Test Section\n\nContent here".to_string(),
            readiness: ReadinessJudgment {
                is_safe: true,
                reasons: vec![],
            },
        };

        assert!(report.has_section(1, "Test Section"));
        assert!(!report.has_section(2, "Test Section"));
        assert!(!report.has_section(1, "Other Section"));
    }

    #[test]
    fn test_report_contains_helper() {
        let report = Report {
            content: "This is some content with keywords".to_string(),
            readiness: ReadinessJudgment {
                is_safe: true,
                reasons: vec![],
            },
        };

        assert!(report.contains("keywords"));
        assert!(!report.contains("missing"));
    }
}
