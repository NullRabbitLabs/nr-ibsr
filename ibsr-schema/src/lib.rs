//! IBSR Snapshot Schema
//!
//! Defines the versioned snapshot format for XDP collector output.

mod snapshot;

pub use snapshot::{
    BucketEntry, KeyType, ResponseAggregates, RpcMetadata, Snapshot, SnapshotError, StatusCounts,
    SCHEMA_VERSION, SUPPORTED_VERSIONS,
};
