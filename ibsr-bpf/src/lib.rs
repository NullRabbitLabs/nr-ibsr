//! IBSR XDP/BPF Support
//!
//! This crate provides:
//! - XDP program safety verification (source and ELF analysis)
//! - BPF map reader abstraction
//! - XDP program loader (future)

pub mod map_reader;
pub mod safety;

pub use map_reader::{counters_to_snapshot, Counters, MapReader, MapReaderError, MockMapReader};
pub use safety::{analyze_elf, analyze_source, SafetyError, SafetyReport};
