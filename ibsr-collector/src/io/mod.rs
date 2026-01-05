//! IO helpers for CLI operations.
//!
//! Provides utilities for:
//! - Loading allowlist files
//! - Writing report artifacts (report.md, rules.json, evidence.csv)

pub mod allowlist_loader;
pub mod output_writer;

pub use allowlist_loader::{load_allowlist, AllowlistLoadError};
pub use output_writer::{write_evidence_csv, write_report, write_rules, OutputWriter, OutputWriterError};
