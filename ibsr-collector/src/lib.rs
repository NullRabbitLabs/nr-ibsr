//! IBSR Collector CLI.
//!
//! This crate provides the command-line interface and collector loop for the
//! IBSR XDP collector. It handles argument parsing, validation, configuration,
//! and orchestrates the snapshot collection cycle.

pub mod cli;
pub mod collector;

pub use cli::{
    default_interface, parse_from, parse_route_table, resolve_interface, Cli, CliError,
    CollectArgs, Command, DEFAULT_MAP_SIZE, DEFAULT_MAX_AGE_SECS, DEFAULT_MAX_FILES,
    DEFAULT_OUTPUT_DIR,
};

pub use collector::{collect_once, CollectResult, CollectorConfig, CollectorError};
