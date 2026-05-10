//! IBSR XDP/BPF Support
//!
//! This crate provides:
//! - BPF program safety verification (source and ELF analysis), with
//!   per-mode profiles for StrictCounter (XDP-only counters) and
//!   ShadowPayload (TC payload extraction with ringbuf events).
//! - BPF map reader abstraction
//! - XDP program loader
//! - TC payload-event decoder for ShadowPayload-mode ringbuf records.
//! - Record-incident TC packet recorder + decoder (CF-style sampled
//!   capture for the `record-incident` subcommand).

pub mod bpf_reader;
pub mod map_reader;
pub mod record_incident_event;
pub mod record_incident_loader;
pub mod safety;
pub mod tc_payload_event;
pub mod tc_payload_loader;

pub use bpf_reader::BpfMapReader;
pub use map_reader::{
    counters_to_snapshot, BpfError, Counters, MapKey, MapReader, MapReaderError, MockMapReader,
};
pub use record_incident_event::{
    decode_packet_event, record_direction, DecodedPacketEvent, RawPacketEvent, RecordDecodeError,
    EXPECTED_RAW_PACKET_EVENT_SIZE, RECORD_SNAPLEN_BYTES,
};
pub use record_incident_loader::{
    build_config_map_entries, build_sample_counter_init, fnv1a64, ConfigKey,
    LibbpfRecordIncidentCollector,
};
pub use safety::{
    analyze_elf, analyze_elf_with_profile, analyze_source, analyze_source_with_profile,
    SafetyError, SafetyProfile, SafetyReport,
};
pub use tc_payload_event::{
    decode_event, direction, DecodeError, DecodedEvent, RawFlowId, RawPayloadEvent,
    EXPECTED_RAW_EVENT_SIZE, PAYLOAD_SAMPLE_BYTES,
};
pub use tc_payload_loader::{
    build_port_filter_entries, InterfaceResolver, LibbpfPayloadCollector, MockInterfaceResolver,
    NixInterfaceResolver, PendingEvents, QueueBackedEventSource, TcPayloadLoaderError,
    MAX_PORT_FILTER_ENTRIES,
};
