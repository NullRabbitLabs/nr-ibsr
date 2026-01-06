//! IBSR XDP/BPF Support
//!
//! This crate provides:
//! - XDP program safety verification (source and ELF analysis)
//! - BPF map reader abstraction
//! - XDP program loader (when `bpf` feature is enabled)

pub mod map_reader;
pub mod safety;

#[cfg(feature = "bpf")]
pub mod bpf_reader;

pub use map_reader::{
    counters_to_snapshot, BpfError, Counters, MapReader, MapReaderError, MockMapReader,
};
pub use safety::{analyze_elf, analyze_source, SafetyError, SafetyReport};

#[cfg(feature = "bpf")]
pub use bpf_reader::BpfMapReader;
