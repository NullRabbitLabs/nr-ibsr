//! IBSR Snapshot Schema
//!
//! Defines the versioned snapshot format for XDP collector output.

mod snapshot;

pub use snapshot::{BucketEntry, KeyType, Snapshot, SnapshotError, SCHEMA_VERSION};
