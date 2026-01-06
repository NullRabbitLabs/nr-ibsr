//! Command orchestration for CLI subcommands.
//!
//! Provides execute functions for:
//! - `collect` - Run the XDP collector
//! - `report` - Generate report from snapshots
//! - `run` - Collect then report

pub mod collect;
pub mod report;
pub mod run;

pub use collect::execute_collect;
pub use report::execute_report;
pub use run::execute_run;

use crate::cli::CliError;
use crate::io::{AllowlistLoadError, OutputWriterError};
use crate::CollectorError;
use ibsr_bpf::BpfError;
use ibsr_fs::FsError;
use ibsr_reporter::ingest::IngestError;
use thiserror::Error;

/// Errors from command execution.
#[derive(Debug, Error)]
pub enum CommandError {
    #[error("invalid argument: {0}")]
    InvalidArgument(#[from] CliError),

    #[error("filesystem error: {0}")]
    Filesystem(#[from] FsError),

    #[error("collector error: {0}")]
    Collector(#[from] CollectorError),

    #[error("ingest error: {0}")]
    Ingest(#[from] IngestError),

    #[error("allowlist error: {0}")]
    Allowlist(#[from] AllowlistLoadError),

    #[error("output error: {0}")]
    Output(#[from] OutputWriterError),

    #[error("BPF error: {0}")]
    Bpf(#[from] BpfError),

    #[error("no snapshots found in {0}")]
    NoSnapshots(String),

    #[error("no network interface found")]
    NoInterface,
}

/// Result of command execution.
pub type CommandResult<T> = Result<T, CommandError>;
