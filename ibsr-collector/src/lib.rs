//! IBSR Collector CLI.
//!
//! This crate provides the command-line interface for the IBSR XDP collector.
//! It handles argument parsing, validation, and configuration.

pub mod cli;

pub use cli::{
    default_interface, parse_from, parse_route_table, resolve_interface, Cli, CliError,
    CollectArgs, Command, DEFAULT_MAP_SIZE, DEFAULT_MAX_AGE_SECS, DEFAULT_MAX_FILES,
    DEFAULT_OUTPUT_DIR,
};
