//! Command orchestration for CLI subcommands.
//!
//! Provides execute functions for:
//! - `collect` — StrictCounter mode (XDP counters).
//! - `collect-payload` — ShadowPayload mode (TC + ringbuf, HTTP parser).
//! - `record-incident` — CF-style sampled packet capture (TC + ringbuf,
//!   pcap writer).

pub mod collect;
pub mod collect_payload;
pub mod record_incident;

pub use collect::execute_collect;
pub use collect_payload::{
    execute_collect_payload, AttachError, CollectPayloadResult, TcPayloadAttacher,
};
pub use record_incident::{
    compute_boot_anchor_now, execute_record_incident, format_run_dir_name as record_run_dir_name,
    record_incident_loop, PacketEventSource, RecordIncidentAttacher, RecordIncidentLoopStats,
    RecordIncidentResult,
};

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

    #[error("{0}")]
    NotImplemented(String),
}

/// Result of command execution.
pub type CommandResult<T> = Result<T, CommandError>;
