//! IBSR Snapshot Schema
//!
//! Defines the versioned snapshot format for XDP collector output.

mod snapshot;

pub use snapshot::{
    BucketEntry, KeyType, ResponseAggregates, Snapshot, SnapshotError, SCHEMA_VERSION,
    SUPPORTED_VERSIONS,
};
