//! IBSR Collector CLI.
//!
//! This crate provides the command-line interface and collector loop for the
//! IBSR XDP collector. It handles argument parsing, validation, configuration,
//! and orchestrates the snapshot collection cycle.

pub mod archive;
pub mod cli;
pub mod collector;
pub mod commands;
pub mod exit;
pub mod host_telemetry;
pub mod io;
pub mod logger;
pub mod payload;
pub mod payload_collector;
pub mod pcap;
pub mod scrub;
pub mod signal;
pub mod sleeper;
pub mod trigger_socket;

pub use cli::{
    default_interface, is_valid_incident_tag, parse_from, parse_route_table, resolve_interface,
    Cli, CliError, CollectArgs, CollectPayloadArgs, Command, RecordIncidentArgs,
    DEFAULT_MAX_AGE_SECS, DEFAULT_MAX_FILES, DEFAULT_MAX_FLOWS, DEFAULT_OUTPUT_DIR,
    DEFAULT_PAYLOAD_OUTPUT_DIR, DEFAULT_PAYLOAD_WINDOW_SEC, DEFAULT_RECORD_IFACE,
    DEFAULT_RECORD_OUTPUT_DIR, DEFAULT_RINGBUF_BYTES, DEFAULT_SAMPLE_RATE, DEFAULT_WINDOW_SEC,
    MAX_DST_PORTS,
};

pub use collector::{collect_once, CollectorConfig, CollectorError};

pub use commands::{execute_collect, CommandError, CommandResult};

pub use io::{StatusLine, StatusWriter, StatusWriterError};

pub use logger::{LogEntry, Logger, MockLogger, NullLogger, StderrLogger, Verbosity};
pub use signal::{AlwaysShutdown, CountingShutdown, NeverShutdown, ShutdownCheck, ShutdownFlag};
pub use sleeper::{MockSleeper, RealSleeper, Sleeper};
