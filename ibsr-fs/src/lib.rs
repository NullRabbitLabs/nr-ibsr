//! Filesystem abstraction for IBSR.
//!
//! This crate provides:
//! - Filesystem trait for atomic writes and file operations
//! - SnapshotWriter for writing snapshots to disk
//! - Rotation logic for max files and max age retention

pub mod rotation;
pub mod writer;

pub use rotation::{rotate_snapshots, RotationConfig, RotationResult};
pub use writer::{
    parse_snapshot_filename, snapshot_filename, Filesystem, FsError, MockFilesystem,
    RealFilesystem, SnapshotFile, SnapshotWriter, StandardSnapshotWriter,
};
