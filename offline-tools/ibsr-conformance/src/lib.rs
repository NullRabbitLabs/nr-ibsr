//! IBSR Conformance Harness
//!
//! This crate provides a conformance harness for validating IBSR reporter
//! implementations against golden fixtures.
//!
//! # Overview
//!
//! The conformance harness allows other implementations of IBSR to validate
//! their output against the reference Rust implementation by:
//!
//! 1. Loading synthetic snapshot fixtures
//! 2. Running the reporter pipeline
//! 3. Comparing output to expected golden files (byte-for-byte)
//!
//! # Fixtures
//!
//! Fixtures are stored in the `fixtures/` directory at the workspace root.
//! Each fixture is a directory containing:
//!
//! - `scenario.json` - Metadata (name, description, generated_at timestamp)
//! - `config.json` - Reporter configuration
//! - `allowlist.txt` - Optional allowlist file
//! - `snapshots/` - Input snapshot files (*.jsonl)
//! - `expected/` - Expected outputs
//!   - `rules.json`
//!   - `report.md`
//!   - `evidence.csv`

pub mod loader;
pub mod runner;
pub mod types;

pub use loader::{fixtures_dir, list_fixtures, load_fixture, LoadError};
pub use runner::{
    generate_expected_outputs, run_fixture, run_fixture_check, run_pipeline, PipelineOutput,
    RunError,
};
pub use types::{ConformanceResult, FileDiff, Fixture, FixtureConfig, ScenarioMeta};
