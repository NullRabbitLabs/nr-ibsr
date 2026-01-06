//! Command orchestration for CLI subcommands.
//!
//! Provides execute functions for:
//! - `collect` - Run the XDP collector

pub mod collect;

pub use collect::execute_collect;

use crate::cli::CliError;
use crate::CollectorError;
use ibsr_bpf::BpfError;
use ibsr_fs::FsError;
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

    #[error("BPF error: {0}")]
    Bpf(#[from] BpfError),

    #[error("no network interface found")]
    NoInterface,
}

/// Result of command execution.
pub type CommandResult<T> = Result<T, CommandError>;
