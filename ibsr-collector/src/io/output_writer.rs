//! Output writer for report artifacts.
//!
//! Writes three files to the output directory:
//! - report.md - The IBSR report
//! - rules.json - Deployable enforcement rules
//! - evidence.csv - Per-source decision evidence

use std::path::{Path, PathBuf};

use ibsr_fs::{Filesystem, FsError};
use ibsr_reporter::decision::{Decision, KeyDecision};
use ibsr_reporter::report::Report;
use ibsr_reporter::rules::EnforcementRules;
use thiserror::Error;

/// Errors from output writing.
#[derive(Debug, Error)]
pub enum OutputWriterError {
    #[error("failed to create output directory: {0}")]
    CreateDir(#[source] FsError),

    #[error("failed to write {file}: {source}")]
    Write {
        file: String,
        #[source]
        source: FsError,
    },
}

/// Output writer that writes artifacts to a directory.
pub struct OutputWriter<'a, F: Filesystem> {
    fs: &'a F,
    out_dir: &'a Path,
}

impl<'a, F: Filesystem> OutputWriter<'a, F> {
    /// Create a new output writer.
    pub fn new(fs: &'a F, out_dir: &'a Path) -> Self {
        Self { fs, out_dir }
    }

    /// Ensure the output directory exists.
    pub fn ensure_dir(&self) -> Result<(), OutputWriterError> {
        self.fs
            .create_dir_all(self.out_dir)
            .map_err(OutputWriterError::CreateDir)
    }

    /// Write all artifacts.
    pub fn write_all(
        &self,
        report: &Report,
        rules: &EnforcementRules,
        decisions: &[KeyDecision],
    ) -> Result<WrittenFiles, OutputWriterError> {
        self.ensure_dir()?;

        let report_path = self.write_report(report)?;
        let rules_path = self.write_rules(rules)?;
        let evidence_path = self.write_evidence(decisions)?;

        Ok(WrittenFiles {
            report: report_path,
            rules: rules_path,
            evidence: evidence_path,
        })
    }

    /// Write the report.md file.
    pub fn write_report(&self, report: &Report) -> Result<PathBuf, OutputWriterError> {
        let path = self.out_dir.join("report.md");
        self.fs
            .write_atomic(&path, report.content.as_bytes())
            .map_err(|e| OutputWriterError::Write {
                file: "report.md".to_string(),
                source: e,
            })?;
        Ok(path)
    }

    /// Write the rules.json file.
    pub fn write_rules(&self, rules: &EnforcementRules) -> Result<PathBuf, OutputWriterError> {
        let path = self.out_dir.join("rules.json");
        let json = rules.to_json();
        self.fs
            .write_atomic(&path, json.as_bytes())
            .map_err(|e| OutputWriterError::Write {
                file: "rules.json".to_string(),
                source: e,
            })?;
        Ok(path)
    }

    /// Write the evidence.csv file.
    pub fn write_evidence(&self, decisions: &[KeyDecision]) -> Result<PathBuf, OutputWriterError> {
        let path = self.out_dir.join("evidence.csv");
        let csv = generate_evidence_csv(decisions);
        self.fs
            .write_atomic(&path, csv.as_bytes())
            .map_err(|e| OutputWriterError::Write {
                file: "evidence.csv".to_string(),
                source: e,
            })?;
        Ok(path)
    }

    /// Get the path for report.md.
    pub fn report_path(&self) -> PathBuf {
        self.out_dir.join("report.md")
    }

    /// Get the path for rules.json.
    pub fn rules_path(&self) -> PathBuf {
        self.out_dir.join("rules.json")
    }

    /// Get the path for evidence.csv.
    pub fn evidence_path(&self) -> PathBuf {
        self.out_dir.join("evidence.csv")
    }
}

/// Paths to written files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenFiles {
    pub report: PathBuf,
    pub rules: PathBuf,
    pub evidence: PathBuf,
}

/// Generate evidence CSV content from decisions.
///
/// Format:
/// source,syn_rate,success_ratio,decision,packets,bytes,syn
pub fn generate_evidence_csv(decisions: &[KeyDecision]) -> String {
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

    lines.join("\n")
}

/// Convenience function to write the report.
pub fn write_report<F: Filesystem>(
    fs: &F,
    out_dir: &Path,
    report: &Report,
) -> Result<PathBuf, OutputWriterError> {
    let writer = OutputWriter::new(fs, out_dir);
    writer.ensure_dir()?;
    writer.write_report(report)
}

/// Convenience function to write the rules.
pub fn write_rules<F: Filesystem>(
    fs: &F,
    out_dir: &Path,
    rules: &EnforcementRules,
) -> Result<PathBuf, OutputWriterError> {
    let writer = OutputWriter::new(fs, out_dir);
    writer.ensure_dir()?;
    writer.write_rules(rules)
}

/// Convenience function to write evidence CSV.
pub fn write_evidence_csv<F: Filesystem>(
    fs: &F,
    out_dir: &Path,
    decisions: &[KeyDecision],
) -> Result<PathBuf, OutputWriterError> {
    let writer = OutputWriter::new(fs, out_dir);
    writer.ensure_dir()?;
    writer.write_evidence(decisions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibsr_fs::MockFilesystem;
    use ibsr_reporter::report::ReadinessJudgment;
    use ibsr_reporter::rules::{Action, MatchCriteria, TriggerRule, RULES_VERSION};
    use ibsr_reporter::types::{AggregatedKey, AggregatedStats};
    use ibsr_schema::KeyType;
    use std::sync::Arc;

    // ===========================================
    // Test Category C — Output Writing
    // ===========================================

    fn mock_report() -> Report {
        Report {
            content: "# Test Report\n\nContent here.".to_string(),
            readiness: ReadinessJudgment {
                is_safe: true,
                reasons: vec![],
            },
        }
    }

    fn mock_rules() -> EnforcementRules {
        EnforcementRules {
            version: RULES_VERSION,
            generated_at: 1000,
            match_criteria: MatchCriteria {
                proto: "tcp".to_string(),
                dst_port: 8899,
            },
            triggers: vec![TriggerRule {
                key_type: "src_ip".to_string(),
                key_value: "10.0.0.1".to_string(),
                window_sec: 10,
                syn_rate_threshold: 100.0,
                success_ratio_threshold: 0.1,
                action: Action {
                    action_type: "drop".to_string(),
                    duration_sec: 300,
                },
            }],
            exceptions: vec![],
        }
    }

    fn mock_decisions() -> Vec<KeyDecision> {
        vec![
            KeyDecision {
                key: AggregatedKey::new(KeyType::SrcIp, 0x0A000001), // 10.0.0.1
                stats: AggregatedStats {
                    total_syn: 750,
                    total_ack: 50,
                    total_rst: 10,
                    total_packets: 1000,
                    total_bytes: 150000,
                    syn_rate: 150.0,
                    success_ratio: 0.05,
                },
                decision: Decision::Block { until_ts: 1300 },
                allowlisted: false,
            },
            KeyDecision {
                key: AggregatedKey::new(KeyType::SrcIp, 0x0A000002), // 10.0.0.2
                stats: AggregatedStats {
                    total_syn: 250,
                    total_ack: 200,
                    total_rst: 5,
                    total_packets: 500,
                    total_bytes: 75000,
                    syn_rate: 50.0,
                    success_ratio: 0.8,
                },
                decision: Decision::Allow,
                allowlisted: false,
            },
        ]
    }

    // --- Output directory creation ---

    #[test]
    fn test_output_writer_ensure_dir() {
        let fs = Arc::new(MockFilesystem::new());
        let out_dir = PathBuf::from("/tmp/output");
        let writer = OutputWriter::new(&*fs, &out_dir);

        writer.ensure_dir().expect("ensure_dir");
        // MockFilesystem.create_dir_all always succeeds
    }

    #[test]
    fn test_output_writer_paths() {
        let fs = Arc::new(MockFilesystem::new());
        let out_dir = PathBuf::from("/tmp/output");
        let writer = OutputWriter::new(&*fs, &out_dir);

        assert_eq!(writer.report_path(), PathBuf::from("/tmp/output/report.md"));
        assert_eq!(writer.rules_path(), PathBuf::from("/tmp/output/rules.json"));
        assert_eq!(
            writer.evidence_path(),
            PathBuf::from("/tmp/output/evidence.csv")
        );
    }

    // --- Write report ---

    #[test]
    fn test_write_report() {
        let fs = Arc::new(MockFilesystem::new());
        let out_dir = PathBuf::from("/tmp/output");
        let report = mock_report();

        let path = write_report(&*fs, &out_dir, &report).expect("write");
        assert_eq!(path, PathBuf::from("/tmp/output/report.md"));

        let content = fs.get_file(&path).expect("read");
        let content_str = String::from_utf8(content).expect("utf8");
        assert!(content_str.contains("# Test Report"));
    }

    // --- Write rules ---

    #[test]
    fn test_write_rules() {
        let fs = Arc::new(MockFilesystem::new());
        let out_dir = PathBuf::from("/tmp/output");
        let rules = mock_rules();

        let path = write_rules(&*fs, &out_dir, &rules).expect("write");
        assert_eq!(path, PathBuf::from("/tmp/output/rules.json"));

        let content = fs.get_file(&path).expect("read");
        let content_str = String::from_utf8(content).expect("utf8");
        assert!(content_str.contains("\"version\""));
        assert!(content_str.contains("\"triggers\""));
    }

    // --- Write evidence CSV ---

    #[test]
    fn test_write_evidence_csv() {
        let fs = Arc::new(MockFilesystem::new());
        let out_dir = PathBuf::from("/tmp/output");
        let decisions = mock_decisions();

        let path = write_evidence_csv(&*fs, &out_dir, &decisions).expect("write");
        assert_eq!(path, PathBuf::from("/tmp/output/evidence.csv"));

        let content = fs.get_file(&path).expect("read");
        let content_str = String::from_utf8(content).expect("utf8");
        assert!(content_str.contains("source,syn_rate,success_ratio,decision,packets,bytes,syn"));
        assert!(content_str.contains("10.0.0.1"));
        assert!(content_str.contains("block"));
        assert!(content_str.contains("10.0.0.2"));
        assert!(content_str.contains("allow"));
    }

    // --- Write all ---

    #[test]
    fn test_write_all() {
        let fs = Arc::new(MockFilesystem::new());
        let out_dir = PathBuf::from("/tmp/output");
        let writer = OutputWriter::new(&*fs, &out_dir);

        let report = mock_report();
        let rules = mock_rules();
        let decisions = mock_decisions();

        let written = writer.write_all(&report, &rules, &decisions).expect("write_all");

        assert_eq!(written.report, PathBuf::from("/tmp/output/report.md"));
        assert_eq!(written.rules, PathBuf::from("/tmp/output/rules.json"));
        assert_eq!(written.evidence, PathBuf::from("/tmp/output/evidence.csv"));

        // Verify all files exist
        assert!(fs.exists(&written.report));
        assert!(fs.exists(&written.rules));
        assert!(fs.exists(&written.evidence));
    }

    // --- Evidence CSV generation ---

    #[test]
    fn test_generate_evidence_csv_empty() {
        let csv = generate_evidence_csv(&[]);
        assert_eq!(csv, "source,syn_rate,success_ratio,decision,packets,bytes,syn");
    }

    #[test]
    fn test_generate_evidence_csv_single() {
        let decisions = vec![KeyDecision {
            key: AggregatedKey::new(KeyType::SrcIp, 0x0A000001),
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
        assert_eq!(lines[1], "10.0.0.1,20.00,0.1000,block,200,30000,100");
    }

    #[test]
    fn test_generate_evidence_csv_sorted() {
        let decisions = vec![
            KeyDecision {
                key: AggregatedKey::new(KeyType::SrcIp, 0x0A000002), // 10.0.0.2
                stats: AggregatedStats::default(),
                decision: Decision::Allow,
                allowlisted: false,
            },
            KeyDecision {
                key: AggregatedKey::new(KeyType::SrcIp, 0x0A000001), // 10.0.0.1
                stats: AggregatedStats::default(),
                decision: Decision::Allow,
                allowlisted: false,
            },
        ];

        let csv = generate_evidence_csv(&decisions);
        let lines: Vec<_> = csv.lines().collect();

        // Should be sorted by key
        assert!(lines[1].starts_with("10.0.0.1"));
        assert!(lines[2].starts_with("10.0.0.2"));
    }

    #[test]
    fn test_generate_evidence_csv_cidr() {
        let decisions = vec![KeyDecision {
            key: AggregatedKey::new(KeyType::SrcCidr24, 0xC0A80100), // 192.168.1.0
            stats: AggregatedStats {
                total_syn: 500,
                total_ack: 10,
                total_rst: 5,
                total_packets: 1000,
                total_bytes: 100000,
                syn_rate: 100.0,
                success_ratio: 0.02,
            },
            decision: Decision::Block { until_ts: 1000 },
            allowlisted: false,
        }];

        let csv = generate_evidence_csv(&decisions);
        assert!(csv.contains("192.168.1.0/24"));
    }

    #[test]
    fn test_generate_evidence_csv_precision() {
        let decisions = vec![KeyDecision {
            key: AggregatedKey::new(KeyType::SrcIp, 0x0A000001),
            stats: AggregatedStats {
                total_syn: 100,
                total_ack: 10,
                total_rst: 5,
                total_packets: 200,
                total_bytes: 30000,
                syn_rate: 123.456789,
                success_ratio: 0.123456,
            },
            decision: Decision::Allow,
            allowlisted: false,
        }];

        let csv = generate_evidence_csv(&decisions);
        // syn_rate: 2 decimal places, success_ratio: 4 decimal places
        assert!(csv.contains("123.46"));
        assert!(csv.contains("0.1235"));
    }

    // --- Error handling ---

    #[test]
    fn test_output_writer_error_display_create_dir() {
        let err = OutputWriterError::CreateDir(FsError::Path("test".to_string()));
        assert!(err.to_string().contains("failed to create output directory"));
    }

    #[test]
    fn test_output_writer_error_display_write() {
        let err = OutputWriterError::Write {
            file: "report.md".to_string(),
            source: FsError::Path("test".to_string()),
        };
        let msg = err.to_string();
        assert!(msg.contains("failed to write report.md"));
    }

    #[test]
    fn test_output_writer_error_debug() {
        let err = OutputWriterError::CreateDir(FsError::Path("test".to_string()));
        let debug = format!("{:?}", err);
        assert!(debug.contains("CreateDir"));
    }

    #[test]
    fn test_written_files_debug() {
        let written = WrittenFiles {
            report: PathBuf::from("/tmp/report.md"),
            rules: PathBuf::from("/tmp/rules.json"),
            evidence: PathBuf::from("/tmp/evidence.csv"),
        };
        let debug = format!("{:?}", written);
        assert!(debug.contains("WrittenFiles"));
    }

    #[test]
    fn test_written_files_clone() {
        let written = WrittenFiles {
            report: PathBuf::from("/tmp/report.md"),
            rules: PathBuf::from("/tmp/rules.json"),
            evidence: PathBuf::from("/tmp/evidence.csv"),
        };
        let cloned = written.clone();
        assert_eq!(written, cloned);
    }
}
