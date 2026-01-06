//! IO helpers for CLI operations.
//!
//! Provides utilities for:
//! - Writing status.jsonl for heartbeat/progress tracking

pub mod status_writer;

pub use status_writer::{StatusLine, StatusWriter, StatusWriterError};
