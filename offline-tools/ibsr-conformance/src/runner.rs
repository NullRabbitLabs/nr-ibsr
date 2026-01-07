//! Conformance runner for executing fixtures and comparing outputs.

use crate::loader::{load_fixture, LoadError};
use crate::types::{ConformanceResult, FileDiff, Fixture, FixtureConfig};
use ibsr_clock::{Clock, MockClock};
use ibsr_reporter::config::{Allowlist, ReporterConfig};
use ibsr_reporter::counterfactual;
use ibsr_reporter::decision::{evaluate_key, Decision, KeyDecision};
use ibsr_reporter::ingest::SnapshotStream;
use ibsr_reporter::report::{self, Report};
use ibsr_reporter::rules::{self, EnforcementRules};
use ibsr_reporter::window;

/// Errors that can occur during conformance runs.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("failed to load fixture: {0}")]
    Load(#[from] LoadError),

    #[error("fixture has no snapshots")]
    NoSnapshots,

    #[error("failed to parse allowlist: {0}")]
    AllowlistParse(String),
}

/// Output from running the reporter pipeline.
#[derive(Debug, Clone)]
pub struct PipelineOutput {
    pub rules_json: String,
    pub report_md: String,
    pub evidence_csv: String,
}

/// Run a single fixture and return conformance result.
pub fn run_fixture(name: &str) -> Result<ConformanceResult, RunError> {
    let fixture = load_fixture(name)?;
    run_fixture_check(&fixture)
}

/// Run fixture check with loaded fixture data.
pub fn run_fixture_check(fixture: &Fixture) -> Result<ConformanceResult, RunError> {
    let output = run_pipeline(fixture)?;

    let mut diffs = Vec::new();

    if let Some(diff) = FileDiff::new("rules.json", &fixture.expected_rules, &output.rules_json) {
        diffs.push(diff);
    }

    if let Some(diff) = FileDiff::new("report.md", &fixture.expected_report, &output.report_md) {
        diffs.push(diff);
    }

    if let Some(diff) = FileDiff::new("evidence.csv", &fixture.expected_evidence, &output.evidence_csv) {
        diffs.push(diff);
    }

    if diffs.is_empty() {
        Ok(ConformanceResult::pass(&fixture.meta.name))
    } else {
        Ok(ConformanceResult::fail(&fixture.meta.name, diffs))
    }
}

/// Run the reporter pipeline on fixture data and return outputs.
pub fn run_pipeline(fixture: &Fixture) -> Result<PipelineOutput, RunError> {
    // Build config from fixture
    let config = build_config(&fixture.config, &fixture.allowlist)?;

    // Create snapshot stream
    let stream = SnapshotStream::from_unordered(fixture.snapshots.clone())
        .map_err(|_| RunError::NoSnapshots)?;

    // Use fixture's generated_at timestamp
    let clock = MockClock::new(fixture.meta.generated_at);

    // Run pipeline
    let (report, rules, decisions) = execute_pipeline(&stream, &config, &clock);

    // Generate outputs
    let rules_json = rules.to_json();
    let report_md = report.content.clone();
    let evidence_csv = generate_evidence_csv(&decisions);

    Ok(PipelineOutput {
        rules_json,
        report_md,
        evidence_csv,
    })
}

/// Build ReporterConfig from fixture config.
fn build_config(fixture_config: &FixtureConfig, allowlist_content: &Option<String>) -> Result<ReporterConfig, RunError> {
    let mut config = fixture_config.to_reporter_config();

    // Parse allowlist if present
    if let Some(content) = allowlist_content {
        let allowlist = parse_allowlist(content)?;
        config = config.with_allowlist(allowlist);
    }

    Ok(config)
}

/// Parse allowlist from file content.
fn parse_allowlist(content: &str) -> Result<Allowlist, RunError> {
    let mut allowlist = Allowlist::empty();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.contains('/') {
            allowlist.add_cidr_str(line)
                .map_err(|e| RunError::AllowlistParse(e.to_string()))?;
        } else {
            allowlist.add_ip_str(line)
                .map_err(|e| RunError::AllowlistParse(e.to_string()))?;
        }
    }

    Ok(allowlist)
}

/// Execute the reporter pipeline.
fn execute_pipeline(
    snapshots: &SnapshotStream,
    config: &ReporterConfig,
    clock: &MockClock,
) -> (Report, EnforcementRules, Vec<KeyDecision>) {
    let bounds = snapshots.bounds();

    // Extract dst_ports from first snapshot
    let dst_ports = snapshots
        .snapshots()
        .first()
        .map(|s| s.dst_ports.clone())
        .unwrap_or_else(|| config.dst_ports.clone());

    // Create config with correct dst_ports
    let mut config = config.clone();
    config.dst_ports = dst_ports;

    // Aggregate statistics
    let snapshot_refs: Vec<_> = snapshots.snapshots().iter().collect();
    let aggregated = window::aggregate_snapshots(&snapshot_refs, config.window_sec);
    let sorted = window::sorted_aggregated(&aggregated);

    // Evaluate decisions
    let current_ts = clock.now_unix_sec();
    let decisions: Vec<KeyDecision> = sorted
        .iter()
        .map(|(key, stats)| evaluate_key(*key, *stats, &config, current_ts))
        .collect();

    // Compute counterfactual
    let counterfactual = counterfactual::compute(&decisions, &config);

    // Generate rules and report
    let rules = rules::generate(&counterfactual.top_offenders, &config, current_ts);
    let report = report::generate(&bounds, &config, &counterfactual, &rules);

    (report, rules, decisions)
}

/// Generate expected outputs for a fixture and write to files.
///
/// This is useful for creating the expected/ directory contents for new fixtures.
pub fn generate_expected_outputs(fixture_path: &std::path::Path) -> Result<(), RunError> {
    use std::fs;

    let name = fixture_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let fixture = load_fixture(name)?;
    let output = run_pipeline(&fixture)?;

    // Create expected directory
    let expected_dir = fixture_path.join("expected");
    fs::create_dir_all(&expected_dir).map_err(|e| RunError::AllowlistParse(e.to_string()))?;

    // Write outputs
    fs::write(expected_dir.join("rules.json"), &output.rules_json)
        .map_err(|e| RunError::AllowlistParse(e.to_string()))?;
    fs::write(expected_dir.join("report.md"), &output.report_md)
        .map_err(|e| RunError::AllowlistParse(e.to_string()))?;
    fs::write(expected_dir.join("evidence.csv"), &output.evidence_csv)
        .map_err(|e| RunError::AllowlistParse(e.to_string()))?;

    Ok(())
}

/// Generate evidence CSV from decisions.
fn generate_evidence_csv(decisions: &[KeyDecision]) -> String {
    let mut lines = Vec::with_capacity(decisions.len() + 1);

    // Header
    lines.push("source,syn_rate,success_ratio,decision,packets,bytes,syn".to_string());

    // Sort decisions for deterministic output
    let mut sorted: Vec<_> = decisions.iter().collect();
    sorted.sort_by_key(|d| d.key);

    // Data rows
    for d in sorted {
        let source = d.key.to_display_string();
        let decision_str = match d.decision {
            Decision::Allow => "allow",
            Decision::Block { .. } => "block",
        };

        lines.push(format!(
            "{},{:.2},{:.4},{},{},{},{}",
            source,
            d.stats.syn_rate,
            d.stats.success_ratio,
            decision_str,
            d.stats.total_packets,
            d.stats.total_bytes,
            d.stats.total_syn,
        ));
    }

    let mut result = lines.join("\n");
    result.push('\n');
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibsr_reporter::types::AggregatedStats;
    use ibsr_schema::{BucketEntry, KeyType, Snapshot};

    // ===========================================
    // Category F3 — Conformance Runner Tests
    // ===========================================

    fn make_fixture_config() -> FixtureConfig {
        FixtureConfig {
            dst_ports: vec![8080],
            window_sec: 10,
            syn_rate_threshold: 100.0,
            success_ratio_threshold: 0.1,
            block_duration_sec: 300,
            fp_safe_ratio: 0.5,
            min_samples_for_fp: 1,
        }
    }

    fn make_snapshot_attacker() -> Snapshot {
        Snapshot::new(
            1000,
            &[8080],
            vec![BucketEntry {
                key_type: KeyType::SrcIp,
                // key_value uses MSB=first-octet representation (0x0A000001 = 10.0.0.1)
                key_value: 0x0A000001, // 10.0.0.1
                dst_port: Some(8080),
                syn: 5000,
                ack: 50,
                handshake_ack: 10,
                rst: 0,
                packets: 5050,
                bytes: 505000,
            }],
        )
    }

    fn make_snapshot_legitimate() -> Snapshot {
        Snapshot::new(
            1000,
            &[8080],
            vec![BucketEntry {
                key_type: KeyType::SrcIp,
                // key_value uses MSB=first-octet representation (0x0A000002 = 10.0.0.2)
                key_value: 0x0A000002, // 10.0.0.2
                dst_port: Some(8080),
                syn: 100,
                ack: 90,
                handshake_ack: 90,
                rst: 5,
                packets: 200,
                bytes: 20000,
            }],
        )
    }

    // -------------------------------------------
    // Pipeline execution
    // -------------------------------------------

    #[test]
    fn test_run_pipeline_attacker() {
        use crate::types::ScenarioMeta;

        let fixture = Fixture {
            meta: ScenarioMeta {
                name: "test".to_string(),
                description: "Test".to_string(),
                generated_at: 1000,
            },
            config: make_fixture_config(),
            allowlist: None,
            snapshots: vec![make_snapshot_attacker()],
            expected_rules: String::new(),
            expected_report: String::new(),
            expected_evidence: String::new(),
        };

        let output = run_pipeline(&fixture).unwrap();

        // Rules should contain the attacker
        assert!(output.rules_json.contains("10.0.0.1"));
        assert!(output.rules_json.contains("\"triggers\""));

        // Report should indicate abuse detected
        assert!(output.report_md.contains("IBSR Report"));
        assert!(output.report_md.contains("10.0.0.1"));

        // Evidence should show block decision
        assert!(output.evidence_csv.contains("10.0.0.1"));
        assert!(output.evidence_csv.contains("block"));
    }

    #[test]
    fn test_run_pipeline_legitimate() {
        use crate::types::ScenarioMeta;

        let fixture = Fixture {
            meta: ScenarioMeta {
                name: "test".to_string(),
                description: "Test".to_string(),
                generated_at: 1000,
            },
            config: make_fixture_config(),
            allowlist: None,
            snapshots: vec![make_snapshot_legitimate()],
            expected_rules: String::new(),
            expected_report: String::new(),
            expected_evidence: String::new(),
        };

        let output = run_pipeline(&fixture).unwrap();

        // No triggers (legitimate client)
        assert!(output.rules_json.contains("\"triggers\": []"));

        // Evidence should show allow decision
        assert!(output.evidence_csv.contains("10.0.0.2"));
        assert!(output.evidence_csv.contains("allow"));
    }

    // -------------------------------------------
    // Allowlist parsing
    // -------------------------------------------

    #[test]
    fn test_parse_allowlist_empty() {
        let allowlist = parse_allowlist("").unwrap();
        assert!(allowlist.is_empty());
    }

    #[test]
    fn test_parse_allowlist_single_ip() {
        let allowlist = parse_allowlist("10.0.0.1").unwrap();
        // All values use MSB=first-octet representation (0x0A000001 = 10.0.0.1)
        assert!(allowlist.contains(0x0A000001));
    }

    #[test]
    fn test_parse_allowlist_cidr() {
        let allowlist = parse_allowlist("192.168.0.0/24").unwrap();
        // 192.168.0.1 = 0xC0A80001 should be in 192.168.0.0/24
        assert!(allowlist.contains(0xC0A80001));
    }

    #[test]
    fn test_parse_allowlist_mixed() {
        let content = "10.0.0.1\n192.168.0.0/24\n# comment\n\n10.0.0.2";
        let allowlist = parse_allowlist(content).unwrap();
        // All values use MSB=first-octet representation
        assert!(allowlist.contains(0x0A000001)); // 10.0.0.1
        assert!(allowlist.contains(0x0A000002)); // 10.0.0.2
        assert!(allowlist.contains(0xC0A80001)); // 192.168.0.1 in 192.168.0.0/24
    }

    #[test]
    fn test_parse_allowlist_comments_and_empty() {
        let content = "# this is a comment\n\n  \n10.0.0.1";
        let allowlist = parse_allowlist(content).unwrap();
        assert_eq!(allowlist.ip_count(), 1);
    }

    #[test]
    fn test_parse_allowlist_invalid() {
        let result = parse_allowlist("not-an-ip");
        assert!(result.is_err());
    }

    // -------------------------------------------
    // Evidence CSV generation
    // -------------------------------------------

    #[test]
    fn test_generate_evidence_csv_empty() {
        let csv = generate_evidence_csv(&[]);
        assert_eq!(csv, "source,syn_rate,success_ratio,decision,packets,bytes,syn\n");
    }

    #[test]
    fn test_generate_evidence_csv_single() {
        use ibsr_reporter::types::AggregatedKey;

        let decisions = vec![KeyDecision {
            // key_value uses MSB=first-octet representation (0x0A000001 = 10.0.0.1)
            key: AggregatedKey::new(KeyType::SrcIp, 0x0A000001, Some(8080)),
            stats: AggregatedStats {
                total_syn: 100,
                total_ack: 10,
                total_rst: 5,
                total_packets: 200,
                total_bytes: 30000,
                syn_rate: 20.0,
                success_ratio: 0.1,
            },
            decision: Decision::Block { until_ts: 1000 },
            allowlisted: false,
        }];

        let csv = generate_evidence_csv(&decisions);
        let lines: Vec<_> = csv.lines().collect();

        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "source,syn_rate,success_ratio,decision,packets,bytes,syn");
        assert_eq!(lines[1], "10.0.0.1:8080,20.00,0.1000,block,200,30000,100");
    }

    // -------------------------------------------
    // Fixture check
    // -------------------------------------------

    #[test]
    fn test_run_fixture_check_pass() {
        use crate::types::ScenarioMeta;

        // Create a fixture and run pipeline to get expected outputs
        let mut fixture = Fixture {
            meta: ScenarioMeta {
                name: "test".to_string(),
                description: "Test".to_string(),
                generated_at: 1000,
            },
            config: make_fixture_config(),
            allowlist: None,
            snapshots: vec![make_snapshot_attacker()],
            expected_rules: String::new(),
            expected_report: String::new(),
            expected_evidence: String::new(),
        };

        // Generate expected outputs
        let output = run_pipeline(&fixture).unwrap();
        fixture.expected_rules = output.rules_json;
        fixture.expected_report = output.report_md;
        fixture.expected_evidence = output.evidence_csv;

        // Now check should pass
        let result = run_fixture_check(&fixture).unwrap();
        assert!(result.passed);
        assert!(result.diffs.is_empty());
    }

    #[test]
    fn test_run_fixture_check_fail() {
        use crate::types::ScenarioMeta;

        let fixture = Fixture {
            meta: ScenarioMeta {
                name: "test".to_string(),
                description: "Test".to_string(),
                generated_at: 1000,
            },
            config: make_fixture_config(),
            allowlist: None,
            snapshots: vec![make_snapshot_attacker()],
            expected_rules: "{}".to_string(), // Wrong expected
            expected_report: "# Wrong".to_string(),
            expected_evidence: "wrong".to_string(),
        };

        let result = run_fixture_check(&fixture).unwrap();
        assert!(!result.passed);
        assert!(!result.diffs.is_empty());
    }

    // -------------------------------------------
    // Error handling
    // -------------------------------------------

    #[test]
    fn test_run_error_display() {
        let err = RunError::NoSnapshots;
        assert!(err.to_string().contains("no snapshots"));

        let err = RunError::AllowlistParse("invalid".to_string());
        assert!(err.to_string().contains("allowlist"));
    }

    #[test]
    fn test_pipeline_output_debug() {
        let output = PipelineOutput {
            rules_json: "{}".to_string(),
            report_md: "# Report".to_string(),
            evidence_csv: "header".to_string(),
        };
        let debug = format!("{:?}", output);
        assert!(debug.contains("PipelineOutput"));
    }

    // -------------------------------------------
    // Integration: Generate outputs for fixtures
    // -------------------------------------------

    /// This test outputs expected content for all fixtures.
    /// Run with: cargo test -p ibsr-conformance print_fixture_outputs -- --ignored --nocapture
    #[test]
    #[ignore] // Only run manually
    fn print_fixture_outputs() {
        use crate::loader::list_fixtures;

        let fixtures = list_fixtures().expect("list fixtures");

        for name in &fixtures {
            let fixture = crate::loader::load_fixture(name).expect("load fixture");
            let output = run_pipeline(&fixture).expect("run pipeline");

            println!("\n\n========== FIXTURE: {} ==========", name);
            println!("\n--- rules.json ---");
            println!("{}", output.rules_json);
            println!("\n--- report.md ---");
            println!("{}", output.report_md);
            println!("\n--- evidence.csv ---");
            println!("{}", output.evidence_csv);
        }
    }

    // -------------------------------------------
    // Conformance tests for each fixture
    // -------------------------------------------

    #[test]
    fn test_conformance_syn_churn_attacker() {
        let result = run_fixture("syn_churn_attacker").expect("run fixture");
        assert!(result.passed, "Fixture syn_churn_attacker failed: {:?}", result.diffs);
    }

    #[test]
    fn test_conformance_legitimate_client() {
        let result = run_fixture("legitimate_client").expect("run fixture");
        assert!(result.passed, "Fixture legitimate_client failed: {:?}", result.diffs);
    }

    #[test]
    fn test_conformance_allowlisted_attacker() {
        let result = run_fixture("allowlisted_attacker").expect("run fixture");
        assert!(result.passed, "Fixture allowlisted_attacker failed: {:?}", result.diffs);
    }

    #[test]
    fn test_conformance_fp_unknown() {
        let result = run_fixture("fp_unknown").expect("run fixture");
        assert!(result.passed, "Fixture fp_unknown failed: {:?}", result.diffs);
    }

    #[test]
    fn test_conformance_boundary_conditions() {
        let result = run_fixture("boundary_conditions").expect("run fixture");
        assert!(result.passed, "Fixture boundary_conditions failed: {:?}", result.diffs);
    }

    // -------------------------------------------
    // Determinism tests
    // -------------------------------------------

    #[test]
    fn test_determinism_same_output_twice() {
        // Run the same fixture twice and verify identical outputs
        use crate::loader::load_fixture;

        let fixture = load_fixture("syn_churn_attacker").expect("load fixture");

        let output1 = run_pipeline(&fixture).expect("run pipeline 1");
        let output2 = run_pipeline(&fixture).expect("run pipeline 2");

        assert_eq!(output1.rules_json, output2.rules_json, "rules.json differs between runs");
        assert_eq!(output1.report_md, output2.report_md, "report.md differs between runs");
        assert_eq!(output1.evidence_csv, output2.evidence_csv, "evidence.csv differs between runs");
    }

    #[test]
    fn test_determinism_newlines_lf_only() {
        // Verify all outputs use LF only (no CRLF)
        use crate::loader::load_fixture;

        let fixture = load_fixture("syn_churn_attacker").expect("load fixture");
        let output = run_pipeline(&fixture).expect("run pipeline");

        assert!(!output.rules_json.contains('\r'), "rules.json contains CR");
        assert!(!output.report_md.contains('\r'), "report.md contains CR");
        assert!(!output.evidence_csv.contains('\r'), "evidence.csv contains CR");
    }

    #[test]
    fn test_determinism_no_wallclock_in_output() {
        // Verify the output doesn't contain current timestamp
        // (should only use fixture-provided timestamp)
        use crate::loader::load_fixture;

        let fixture = load_fixture("syn_churn_attacker").expect("load fixture");
        let output = run_pipeline(&fixture).expect("run pipeline");

        // Should contain the fixture timestamp (1000), not current wall clock
        assert!(output.rules_json.contains("\"generated_at\": 1000"));

        // Should not contain any timestamp that looks like a current epoch time
        // Current epoch is ~1700000000, fixture uses 1000
        let json_numbers: Vec<_> = output.rules_json
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| s.len() > 8) // Filter out small numbers
            .collect();

        for num in json_numbers {
            if let Ok(n) = num.parse::<u64>() {
                assert!(n < 1_000_000_000, "Found potential wall-clock timestamp: {}", n);
            }
        }
    }

    #[test]
    fn test_determinism_evidence_csv_sorted() {
        // Verify evidence CSV is sorted by source IP
        use crate::loader::load_fixture;

        let fixture = load_fixture("boundary_conditions").expect("load fixture");
        let output = run_pipeline(&fixture).expect("run pipeline");

        let lines: Vec<_> = output.evidence_csv.lines().skip(1).collect(); // Skip header
        assert!(lines.len() > 1, "Need multiple rows to test sorting");

        // Extract IPs and verify they're sorted
        let ips: Vec<_> = lines.iter()
            .map(|l| l.split(',').next().unwrap())
            .collect();

        let mut sorted_ips = ips.clone();
        sorted_ips.sort();

        assert_eq!(ips, sorted_ips, "Evidence CSV not sorted by source");
    }
}
