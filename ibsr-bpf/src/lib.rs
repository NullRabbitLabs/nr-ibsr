//! IBSR XDP/BPF Support
//!
//! This crate provides:
//! - XDP program safety verification (source and ELF analysis)
//! - BPF map reader abstraction
//! - XDP program loader

pub mod bpf_reader;
pub mod map_reader;
pub mod safety;

pub use bpf_reader::BpfMapReader;
pub use map_reader::{
    counters_to_snapshot, BpfError, Counters, MapReader, MapReaderError, MockMapReader,
};
pub use safety::{analyze_elf, analyze_source, SafetyError, SafetyReport};
