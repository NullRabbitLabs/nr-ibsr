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

pub use cli::{
    default_interface, parse_from, parse_route_table, resolve_interface, Cli, CliError,
    CollectArgs, Command, ReportArgs, RunArgs, DEFAULT_MAP_SIZE, DEFAULT_MAX_AGE_SECS,
    DEFAULT_MAX_FILES, DEFAULT_OUTPUT_DIR, DEFAULT_WINDOW_SEC,
};

pub use collector::{collect_once, CollectorConfig, CollectorError};

pub use commands::{
    execute_collect, execute_report, execute_run, CommandError, CommandResult,
};

pub use io::{
    load_allowlist, write_evidence_csv, write_report, write_rules, AllowlistLoadError,
    OutputWriter, OutputWriterError,
};
