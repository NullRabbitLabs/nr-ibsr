//! IBSR Collector CLI.
//!
//! This crate provides the command-line interface and collector loop for the
//! IBSR XDP collector. It handles argument parsing, validation, configuration,
//! and orchestrates the snapshot collection cycle.

pub mod cli;
pub mod collector;
pub mod commands;
pub mod exit;
pub mod io;
pub mod logger;
pub mod payload;
pub mod payload_collector;
pub mod signal;
pub mod sleeper;

pub use cli::{
    default_interface, parse_from, parse_route_table, resolve_interface, Cli, CliError,
    CollectArgs, CollectPayloadArgs, Command, DEFAULT_MAX_AGE_SECS, DEFAULT_MAX_FILES,
    DEFAULT_MAX_FLOWS, DEFAULT_OUTPUT_DIR, DEFAULT_PAYLOAD_OUTPUT_DIR,
    DEFAULT_PAYLOAD_WINDOW_SEC, DEFAULT_RINGBUF_BYTES, DEFAULT_WINDOW_SEC, MAX_DST_PORTS,
};

pub use collector::{collect_once, CollectorConfig, CollectorError};

pub use commands::{execute_collect, CommandError, CommandResult};

pub use io::{StatusLine, StatusWriter, StatusWriterError};

pub use logger::{LogEntry, Logger, MockLogger, NullLogger, StderrLogger, Verbosity};
pub use signal::{AlwaysShutdown, CountingShutdown, NeverShutdown, ShutdownCheck, ShutdownFlag};
pub use sleeper::{MockSleeper, RealSleeper, Sleeper};
