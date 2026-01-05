//! Conformance types.

use ibsr_reporter::config::ReporterConfig;
use ibsr_schema::Snapshot;
use serde::{Deserialize, Serialize};

/// Fixture scenario metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioMeta {
    pub name: String,
    pub description: String,
    /// Timestamp to use for generated_at in rules.json
    pub generated_at: u64,
}

/// Fixture configuration (serializable subset of ReporterConfig).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureConfig {
    pub dst_port: u16,
    pub window_sec: u64,
    pub syn_rate_threshold: f64,
    pub success_ratio_threshold: f64,
    pub block_duration_sec: u64,
    pub fp_safe_ratio: f64,
    pub min_samples_for_fp: usize,
}

impl FixtureConfig {
    /// Convert to ReporterConfig.
    pub fn to_reporter_config(&self) -> ReporterConfig {
        ReporterConfig::new(self.dst_port)
            .with_window_sec(self.window_sec)
            .with_syn_rate_threshold(self.syn_rate_threshold)
            .with_success_ratio_threshold(self.success_ratio_threshold)
            .with_block_duration_sec(self.block_duration_sec)
            .with_fp_safe_ratio(self.fp_safe_ratio)
            .with_min_samples_for_fp(self.min_samples_for_fp)
    }
}

/// A loaded fixture ready for execution.
#[derive(Debug, Clone)]
pub struct Fixture {
    pub meta: ScenarioMeta,
    pub config: FixtureConfig,
    pub allowlist: Option<String>,
    pub snapshots: Vec<Snapshot>,
    pub expected_rules: String,
    pub expected_report: String,
    pub expected_evidence: String,
}

/// Result of a conformance check.
#[derive(Debug, Clone)]
pub struct ConformanceResult {
    pub fixture_name: String,
    pub passed: bool,
    pub rules_match: bool,
    pub report_match: bool,
    pub evidence_match: bool,
    pub diffs: Vec<FileDiff>,
}

impl ConformanceResult {
    /// Create a passing result.
    pub fn pass(fixture_name: &str) -> Self {
        Self {
            fixture_name: fixture_name.to_string(),
            passed: true,
            rules_match: true,
            report_match: true,
            evidence_match: true,
            diffs: vec![],
        }
    }

    /// Create a failing result with diffs.
    pub fn fail(fixture_name: &str, diffs: Vec<FileDiff>) -> Self {
        let rules_match = !diffs.iter().any(|d| d.file == "rules.json");
        let report_match = !diffs.iter().any(|d| d.file == "report.md");
        let evidence_match = !diffs.iter().any(|d| d.file == "evidence.csv");

        Self {
            fixture_name: fixture_name.to_string(),
            passed: false,
            rules_match,
            report_match,
            evidence_match,
            diffs,
        }
    }
}

/// A diff between expected and actual content.
#[derive(Debug, Clone)]
pub struct FileDiff {
    pub file: String,
    pub expected_len: usize,
    pub actual_len: usize,
    pub first_diff_line: Option<usize>,
    pub expected_excerpt: Option<String>,
    pub actual_excerpt: Option<String>,
}

impl FileDiff {
    /// Create a new diff.
    pub fn new(file: &str, expected: &str, actual: &str) -> Option<Self> {
        if expected == actual {
            return None;
        }

        let expected_lines: Vec<&str> = expected.lines().collect();
        let actual_lines: Vec<&str> = actual.lines().collect();

        let mut first_diff_line = None;
        let mut expected_excerpt = None;
        let mut actual_excerpt = None;

        for (i, (e, a)) in expected_lines.iter().zip(actual_lines.iter()).enumerate() {
            if e != a {
                first_diff_line = Some(i + 1);
                expected_excerpt = Some(e.to_string());
                actual_excerpt = Some(a.to_string());
                break;
            }
        }

        // Handle length mismatch
        if first_diff_line.is_none() && expected_lines.len() != actual_lines.len() {
            let line = expected_lines.len().min(actual_lines.len()) + 1;
            first_diff_line = Some(line);
            expected_excerpt = expected_lines.get(line - 1).map(|s| s.to_string());
            actual_excerpt = actual_lines.get(line - 1).map(|s| s.to_string());
        }

        Some(Self {
            file: file.to_string(),
            expected_len: expected.len(),
            actual_len: actual.len(),
            first_diff_line,
            expected_excerpt,
            actual_excerpt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===========================================
    // Category F1 — Types Tests
    // ===========================================

    #[test]
    fn test_scenario_meta_deserialize() {
        let json = r#"{"name":"test","description":"Test scenario","generated_at":1000}"#;
        let meta: ScenarioMeta = serde_json::from_str(json).unwrap();
        assert_eq!(meta.name, "test");
        assert_eq!(meta.description, "Test scenario");
        assert_eq!(meta.generated_at, 1000);
    }

    #[test]
    fn test_fixture_config_deserialize() {
        let json = r#"{
            "dst_port": 8080,
            "window_sec": 10,
            "syn_rate_threshold": 100.0,
            "success_ratio_threshold": 0.1,
            "block_duration_sec": 300,
            "fp_safe_ratio": 0.5,
            "min_samples_for_fp": 10
        }"#;
        let config: FixtureConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.dst_port, 8080);
        assert_eq!(config.window_sec, 10);
    }

    #[test]
    fn test_fixture_config_to_reporter_config() {
        let config = FixtureConfig {
            dst_port: 8080,
            window_sec: 10,
            syn_rate_threshold: 100.0,
            success_ratio_threshold: 0.1,
            block_duration_sec: 300,
            fp_safe_ratio: 0.5,
            min_samples_for_fp: 10,
        };
        let reporter_config = config.to_reporter_config();
        assert_eq!(reporter_config.dst_port, 8080);
        assert_eq!(reporter_config.window_sec, 10);
        assert_eq!(reporter_config.syn_rate_threshold, 100.0);
    }

    #[test]
    fn test_conformance_result_pass() {
        let result = ConformanceResult::pass("test_fixture");
        assert!(result.passed);
        assert!(result.rules_match);
        assert!(result.report_match);
        assert!(result.evidence_match);
        assert!(result.diffs.is_empty());
    }

    #[test]
    fn test_conformance_result_fail() {
        let diffs = vec![FileDiff {
            file: "rules.json".to_string(),
            expected_len: 100,
            actual_len: 105,
            first_diff_line: Some(5),
            expected_excerpt: Some("expected".to_string()),
            actual_excerpt: Some("actual".to_string()),
        }];
        let result = ConformanceResult::fail("test_fixture", diffs);
        assert!(!result.passed);
        assert!(!result.rules_match);
        assert!(result.report_match);
        assert!(result.evidence_match);
    }

    #[test]
    fn test_file_diff_identical() {
        let diff = FileDiff::new("test.txt", "same content", "same content");
        assert!(diff.is_none());
    }

    #[test]
    fn test_file_diff_different_content() {
        let diff = FileDiff::new("test.txt", "line1\nline2\n", "line1\nline3\n").unwrap();
        assert_eq!(diff.file, "test.txt");
        assert_eq!(diff.first_diff_line, Some(2));
        assert_eq!(diff.expected_excerpt, Some("line2".to_string()));
        assert_eq!(diff.actual_excerpt, Some("line3".to_string()));
    }

    #[test]
    fn test_file_diff_different_length() {
        let diff = FileDiff::new("test.txt", "line1\nline2\n", "line1\n").unwrap();
        assert_eq!(diff.file, "test.txt");
        assert_eq!(diff.expected_len, 12);
        assert_eq!(diff.actual_len, 6);
    }

    #[test]
    fn test_file_diff_first_line_different() {
        let diff = FileDiff::new("test.txt", "foo\n", "bar\n").unwrap();
        assert_eq!(diff.first_diff_line, Some(1));
        assert_eq!(diff.expected_excerpt, Some("foo".to_string()));
        assert_eq!(diff.actual_excerpt, Some("bar".to_string()));
    }
}
