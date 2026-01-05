//! IBSR Reporter Core
//!
//! Consumes Phase 1 snapshots and produces:
//! - `rules.json` - Deployable XDP-safe enforcement rules
//! - `report.md` - IBSR artifact with 5 required sections
//!
//! Abuse class (v0): TCP SYN churn / connection exhaustion.

pub mod config;
pub mod counterfactual;
pub mod decision;
pub mod ingest;
pub mod report;
pub mod rules;
pub mod types;
pub mod window;

pub use config::{Allowlist, ReporterConfig};
pub use counterfactual::{CounterfactualResult, FpBound, Offender};
pub use decision::Decision;
pub use ingest::SnapshotStream;
pub use report::Report;
pub use rules::EnforcementRules;
pub use types::{AggregatedKey, AggregatedStats, WindowBounds};
