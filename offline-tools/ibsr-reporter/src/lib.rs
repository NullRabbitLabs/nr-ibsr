//! IBSR Reporter Core
//!
//! Consumes Phase 1 snapshots and produces:
//! - `rules.json` - Deployable XDP-safe enforcement rules
//! - `report.md` - IBSR artifact with 5 required sections
//! - `summary.json` - Machine-readable summary for comparisons
//!
//! Abuse classes:
//! - SYN_FLOOD_LIKE: TCP SYN churn / connection exhaustion
//! - VOLUMETRIC_TCP_ABUSE: High volume attacks (2-of-3 metrics)

pub mod abuse;
pub mod config;
pub mod counterfactual;
pub mod decision;
pub mod ingest;
pub mod report;
pub mod rules;
pub mod summary;
pub mod types;
pub mod window;

pub use config::{Allowlist, ReporterConfig};
pub use counterfactual::{CounterfactualResult, FpBound, Offender};
pub use decision::Decision;
pub use ingest::SnapshotStream;
pub use report::Report;
pub use rules::EnforcementRules;
pub use types::{AggregatedKey, AggregatedStats, WindowBounds};
