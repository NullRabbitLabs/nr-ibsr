//! Production attacher for the `record-incident` subcommand.
//!
//! Loads `record_incident.bpf.c`'s skeleton via libbpf-rs, creates a
//! clsact qdisc on the configured interface, attaches the TC ingress
//! and egress programs, programs the per-CPU sampling counter and the
//! sample-rate config map, and starts a ringbuf consumer that pushes
//! events into a `PendingEvents` queue for the userspace pcap writer.
//!
//! Mirrors `tc_payload_loader.rs` shape — same Box::leak-for-'static
//! pattern, same explicit Drop impl that detaches both TC filters and
//! destroys the clsact qdisc, same SAFETY caveat about single-thread
//! use.

use std::mem::MaybeUninit;
use std::os::fd::AsFd;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{
    MapCore, OpenObject, RingBuffer, RingBufferBuilder, TcHook, TcHookBuilder, TC_EGRESS,
    TC_INGRESS,
};

use crate::tc_payload_loader::{
    InterfaceResolver, PendingEvents, TcPayloadLoaderError,
};

mod record_incident_skel {
    include!(concat!(env!("OUT_DIR"), "/record_incident.skel.rs"));
}

use record_incident_skel::*;

/// Config-map keys. Mirrors the `CFG_*` defines in
/// `record_incident.bpf.c`. The `u32` repr matches the BPF map's
/// key type.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigKey {
    SampleRate = 0,
    SamplingActive = 1,
    IncidentTagHash = 2,
    TriggerTimestamp = 3,
}

impl ConfigKey {
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    /// Encode the key as the byte form the kernel map expects.
    pub fn to_key_bytes(self) -> Vec<u8> {
        self.as_u32().to_ne_bytes().to_vec()
    }
}

/// FNV-1a 64-bit hash. Used to fingerprint incident tags into a
/// kernel-side u64 (CFG_INCIDENT_TAG_HASH) so the BPF program can
/// correlate per-trigger state without holding the variable-length
/// string. Pure function; fully testable.
pub fn fnv1a64(input: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in input {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Build the (key, values) pair for the per-CPU sample_counter map.
///
/// Layout: single slot (key=0u32). Each CPU's value is initialised to
/// `rate - 1` (so the rate-th packet on each CPU is the first sample),
/// or `0` when `rate <= 1` (sample every packet).
///
/// Returns `(key_bytes, values_vec)` where `values_vec.len() == n_cpus`
/// and each entry is the 8-byte native-byte-order `u64` representation
/// expected by the kernel.
///
/// Pure function — no I/O — fully testable.
pub fn build_sample_counter_init(
    rate: u64,
    n_cpus: usize,
) -> (Vec<u8>, Vec<Vec<u8>>) {
    let key = 0u32.to_ne_bytes().to_vec();
    let initial = if rate > 1 { rate - 1 } else { 0 };
    let value = initial.to_ne_bytes().to_vec();
    let values: Vec<Vec<u8>> = (0..n_cpus).map(|_| value.clone()).collect();
    (key, values)
}

/// Build the four (key, value) byte pairs for the config_map at
/// initial-attach time. The trigger socket later mutates individual
/// slots (Phase 3); Phase 2's loader writes all four at once.
///
/// Pure function — no I/O — fully testable.
pub fn build_config_map_entries(
    rate: u64,
    sampling_active: bool,
    incident_tag: &str,
    trigger_timestamp_unix_sec: u64,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (
            ConfigKey::SampleRate.to_key_bytes(),
            rate.to_ne_bytes().to_vec(),
        ),
        (
            ConfigKey::SamplingActive.to_key_bytes(),
            (sampling_active as u64).to_ne_bytes().to_vec(),
        ),
        (
            ConfigKey::IncidentTagHash.to_key_bytes(),
            fnv1a64(incident_tag.as_bytes()).to_ne_bytes().to_vec(),
        ),
        (
            ConfigKey::TriggerTimestamp.to_key_bytes(),
            trigger_timestamp_unix_sec.to_ne_bytes().to_vec(),
        ),
    ]
}

/// Production-ready record-incident attacher + event source.
///
/// Owns the skeleton, qdisc, hooks, and ringbuf. Drop is the cleanup
/// path: ringbuf drops first (releases its borrow on packet_rb map);
/// then the explicit cleanup `Drop` impl detaches both TC filters and
/// destroys the clsact qdisc; finally the skel itself drops.
pub struct LibbpfRecordIncidentCollector {
    // Field order = drop order (declared first = dropped first).
    ringbuf: RingBuffer<'static>,
    pending: PendingEvents,
    ingress_hook: Option<TcHook>,
    egress_hook: Option<TcHook>,
    qdisc: Option<TcHook>,
    // Skel must outlive the borrows above; declared last.
    _skel: RecordIncidentSkel<'static>,
    interface: String,
}

// SAFETY: same reasoning as `LibbpfPayloadCollector` — single-threaded
// use; libbpf-rs internals are not shared across threads concurrently.
unsafe impl Send for LibbpfRecordIncidentCollector {}
unsafe impl Sync for LibbpfRecordIncidentCollector {}

impl Drop for LibbpfRecordIncidentCollector {
    fn drop(&mut self) {
        if let Some(mut h) = self.ingress_hook.take() {
            if let Err(e) = h.detach() {
                eprintln!(
                    "ibsr record-incident: TC ingress detach on '{}' failed: {} \
                     (qdisc may need manual `tc qdisc del dev {} clsact`)",
                    self.interface, e, self.interface,
                );
            }
        }
        if let Some(mut h) = self.egress_hook.take() {
            if let Err(e) = h.detach() {
                eprintln!(
                    "ibsr record-incident: TC egress detach on '{}' failed: {}",
                    self.interface, e,
                );
            }
        }
        if let Some(mut h) = self.qdisc.take() {
            if let Err(e) = h.destroy() {
                eprintln!(
                    "ibsr record-incident: clsact qdisc destroy on '{}' failed: {} \
                     (recover with `tc qdisc del dev {} clsact`)",
                    self.interface, e, self.interface,
                );
            }
        }
    }
}

impl LibbpfRecordIncidentCollector {
    /// Get the interface name this collector is attached to.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Pump the ringbuf: ask libbpf to drain available events into the
    /// callback (which pushes into `PendingEvents`).
    pub fn pump(&mut self, timeout: std::time::Duration) -> Result<(), TcPayloadLoaderError> {
        self.ringbuf
            .poll(timeout)
            .map_err(|e| TcPayloadLoaderError::RingbufPoll(e.to_string()))
    }

    /// Reference to the pending-events queue (drain on each poll).
    pub fn pending(&self) -> &PendingEvents {
        &self.pending
    }

    /// Mutate one config_map slot at runtime. Used by Phase 3's
    /// trigger socket to flip CFG_SAMPLING_ACTIVE, change
    /// CFG_SAMPLE_RATE, etc.
    pub fn set_config(&self, key: ConfigKey, value: u64) -> Result<(), TcPayloadLoaderError> {
        let key_bytes = key.to_key_bytes();
        let value_bytes = value.to_ne_bytes().to_vec();
        self._skel
            .maps
            .config_map
            .update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY)
            .map_err(|e| TcPayloadLoaderError::MapProgram(format!("set_config: {}", e)))
    }

    /// Read one config_map slot. Returns `None` if the slot has never
    /// been written (shouldn't happen post-attach, but the BPF kernel
    /// API permits it). Used by Phase 3's `status` command.
    pub fn get_config(&self, key: ConfigKey) -> Result<Option<u64>, TcPayloadLoaderError> {
        let key_bytes = key.to_key_bytes();
        let raw = self
            ._skel
            .maps
            .config_map
            .lookup(&key_bytes, libbpf_rs::MapFlags::ANY)
            .map_err(|e| TcPayloadLoaderError::MapProgram(format!("get_config: {}", e)))?;
        Ok(raw.map(|bytes| {
            let mut arr = [0u8; 8];
            let n = bytes.len().min(8);
            arr[..n].copy_from_slice(&bytes[..n]);
            u64::from_ne_bytes(arr)
        }))
    }

    /// Open + load the skeleton, init per-CPU sample counter +
    /// config_map, create clsact qdisc, attach TC ingress + egress,
    /// set up the ringbuf consumer.
    ///
    /// `sample_rate` is the static rate value used to seed the per-CPU
    /// counter and `CFG_SAMPLE_RATE`. `incident_tag` and
    /// `trigger_timestamp_unix_sec` populate the kernel-side
    /// correlation fields. `sampling_active` initialises
    /// `CFG_SAMPLING_ACTIVE` — pass `true` for record-incident's
    /// "always-sample-the-configured-rate" Phase 1 / 2 mode; Phase 3
    /// will let the trigger socket flip this at runtime.
    pub fn attach(
        iface: &str,
        sample_rate: u64,
        resolver: &dyn InterfaceResolver,
    ) -> Result<Self, TcPayloadLoaderError> {
        Self::attach_with_config(
            iface,
            sample_rate,
            true, // sampling_active
            "ad-hoc",
            0,
            resolver,
        )
    }

    /// Full-control attach. Used by the production CLI command which
    /// passes the operator-supplied tag + timestamp; mirrors `attach`
    /// for the simple-default case.
    pub fn attach_with_config(
        iface: &str,
        sample_rate: u64,
        sampling_active: bool,
        incident_tag: &str,
        trigger_timestamp_unix_sec: u64,
        resolver: &dyn InterfaceResolver,
    ) -> Result<Self, TcPayloadLoaderError> {
        let ifindex = resolver.ifindex(iface)?;

        let open_object: &'static mut MaybeUninit<OpenObject> =
            Box::leak(Box::new(MaybeUninit::<OpenObject>::uninit()));

        let skel_builder = RecordIncidentSkelBuilder::default();
        let open_skel = skel_builder
            .open(open_object)
            .map_err(|e| TcPayloadLoaderError::BpfLoad(e.to_string()))?;

        let skel = open_skel
            .load()
            .map_err(|e| TcPayloadLoaderError::BpfLoad(e.to_string()))?;

        // Initialise the per-CPU sample counter — one slot, n_cpus
        // values, each set to (rate - 1) so the rate-th packet on each
        // CPU is the first sample.
        let n_cpus = libbpf_rs::num_possible_cpus()
            .map_err(|e| TcPayloadLoaderError::MapProgram(format!("num_possible_cpus: {}", e)))?;
        let (counter_key, counter_values) = build_sample_counter_init(sample_rate, n_cpus);
        skel.maps
            .sample_counter
            .update_percpu(&counter_key, &counter_values, libbpf_rs::MapFlags::ANY)
            .map_err(|e| {
                TcPayloadLoaderError::MapProgram(format!("sample_counter init: {}", e))
            })?;

        // Initialise the 4-entry config_map.
        let cfg_entries = build_config_map_entries(
            sample_rate,
            sampling_active,
            incident_tag,
            trigger_timestamp_unix_sec,
        );
        for (key, value) in &cfg_entries {
            skel.maps
                .config_map
                .update(key, value, libbpf_rs::MapFlags::ANY)
                .map_err(|e| {
                    TcPayloadLoaderError::MapProgram(format!("config_map update: {}", e))
                })?;
        }

        // Create clsact qdisc on the interface.
        let ingress_fd = skel.progs.tc_record_ingress.as_fd();
        let mut qdisc_builder = TcHookBuilder::new(ingress_fd);
        qdisc_builder.ifindex(ifindex as i32).replace(true);
        let qdisc = qdisc_builder
            .hook(TC_INGRESS | TC_EGRESS)
            .create()
            .map_err(|e| TcPayloadLoaderError::Qdisc {
                iface: iface.to_string(),
                reason: e.to_string(),
            })?;

        // Attach ingress filter.
        let mut ingress_builder = TcHookBuilder::new(ingress_fd);
        ingress_builder
            .ifindex(ifindex as i32)
            .replace(true)
            .handle(1)
            .priority(1);
        let mut ingress_hook = ingress_builder.hook(TC_INGRESS);
        let ingress_hook = ingress_hook
            .attach()
            .map_err(|e| TcPayloadLoaderError::Attach {
                direction: "ingress",
                reason: e.to_string(),
            })?;

        // Attach egress filter.
        let egress_fd = skel.progs.tc_record_egress.as_fd();
        let mut egress_builder = TcHookBuilder::new(egress_fd);
        egress_builder
            .ifindex(ifindex as i32)
            .replace(true)
            .handle(1)
            .priority(1);
        let mut egress_hook = egress_builder.hook(TC_EGRESS);
        let egress_hook = egress_hook
            .attach()
            .map_err(|e| TcPayloadLoaderError::Attach {
                direction: "egress",
                reason: e.to_string(),
            })?;

        // Set up the ringbuf consumer.
        let pending = PendingEvents::new();
        let pending_for_callback = pending.shared();
        let mut rb_builder = RingBufferBuilder::new();
        rb_builder
            .add(&skel.maps.packet_rb, move |bytes: &[u8]| {
                let mut guard = pending_for_callback
                    .lock()
                    .expect("ringbuf callback: pending mutex poisoned");
                guard.push(bytes.to_vec());
                0
            })
            .map_err(|e| TcPayloadLoaderError::Ringbuf(e.to_string()))?;
        let ringbuf = rb_builder
            .build()
            .map_err(|e| TcPayloadLoaderError::Ringbuf(e.to_string()))?;

        Ok(Self {
            ringbuf,
            pending,
            ingress_hook: Some(ingress_hook),
            egress_hook: Some(egress_hook),
            qdisc: Some(qdisc),
            _skel: skel,
            interface: iface.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_sample_counter_init_rate_one_yields_zero() {
        // rate=1 means "sample every packet" → counter starts at 0
        // so the first packet on every CPU triggers a sample.
        let (key, values) = build_sample_counter_init(1, 4);
        assert_eq!(key, 0u32.to_ne_bytes().to_vec());
        assert_eq!(values.len(), 4);
        for v in &values {
            assert_eq!(v, &0u64.to_ne_bytes().to_vec());
        }
    }

    #[test]
    fn build_sample_counter_init_rate_zero_treated_as_one() {
        // rate=0 is technically "disabled" but Phase 1 has no
        // sampling-active flag — the loader treats 0 the same as 1
        // (counter starts at 0).
        let (_, values) = build_sample_counter_init(0, 2);
        assert_eq!(values.len(), 2);
        for v in &values {
            assert_eq!(v, &0u64.to_ne_bytes().to_vec());
        }
    }

    #[test]
    fn build_sample_counter_init_rate_ten_yields_nine() {
        let (_, values) = build_sample_counter_init(10, 8);
        assert_eq!(values.len(), 8);
        for v in &values {
            assert_eq!(v, &9u64.to_ne_bytes().to_vec());
        }
    }

    #[test]
    fn build_sample_counter_init_zero_cpus_empty_values() {
        // Edge case — fanned-out tests should never see this on a real
        // box, but exercise the bound for safety.
        let (_, values) = build_sample_counter_init(100, 0);
        assert!(values.is_empty());
    }

    #[test]
    fn config_key_repr_matches_bpf_defines() {
        // Pin the kernel-side `CFG_*` defines.
        assert_eq!(ConfigKey::SampleRate.as_u32(), 0);
        assert_eq!(ConfigKey::SamplingActive.as_u32(), 1);
        assert_eq!(ConfigKey::IncidentTagHash.as_u32(), 2);
        assert_eq!(ConfigKey::TriggerTimestamp.as_u32(), 3);
    }

    #[test]
    fn config_key_to_key_bytes_uses_native_byte_order() {
        let bytes = ConfigKey::SampleRate.to_key_bytes();
        assert_eq!(bytes, 0u32.to_ne_bytes().to_vec());
        let bytes = ConfigKey::TriggerTimestamp.to_key_bytes();
        assert_eq!(bytes, 3u32.to_ne_bytes().to_vec());
    }

    #[test]
    fn fnv1a64_empty_string_yields_offset_basis() {
        assert_eq!(fnv1a64(b""), 0xcbf29ce484222325);
    }

    #[test]
    fn fnv1a64_hashes_known_input() {
        // Known FNV-1a 64 hash for "hello" — pin so future refactors
        // can't silently change the hash function.
        assert_eq!(fnv1a64(b"hello"), 0xa430d84680aabd0b);
    }

    #[test]
    fn fnv1a64_changes_on_one_byte_diff() {
        assert_ne!(fnv1a64(b"abc"), fnv1a64(b"abd"));
    }

    #[test]
    fn fnv1a64_consistent_for_same_input() {
        let a = fnv1a64(b"incident-2026-05-09");
        let b = fnv1a64(b"incident-2026-05-09");
        assert_eq!(a, b);
    }

    #[test]
    fn build_config_map_entries_returns_four_slots() {
        let entries = build_config_map_entries(1000, true, "tag", 1_700_000_000);
        assert_eq!(entries.len(), 4);
    }

    #[test]
    fn build_config_map_entries_rate_at_slot_0() {
        let entries = build_config_map_entries(1000, true, "x", 0);
        assert_eq!(entries[0].0, 0u32.to_ne_bytes().to_vec());
        assert_eq!(entries[0].1, 1000u64.to_ne_bytes().to_vec());
    }

    #[test]
    fn build_config_map_entries_active_bit_at_slot_1() {
        let entries = build_config_map_entries(1, false, "x", 0);
        assert_eq!(entries[1].0, 1u32.to_ne_bytes().to_vec());
        assert_eq!(entries[1].1, 0u64.to_ne_bytes().to_vec());

        let entries = build_config_map_entries(1, true, "x", 0);
        assert_eq!(entries[1].1, 1u64.to_ne_bytes().to_vec());
    }

    #[test]
    fn build_config_map_entries_tag_hash_at_slot_2() {
        let entries = build_config_map_entries(1, true, "tag", 0);
        let expected_hash = fnv1a64(b"tag");
        assert_eq!(entries[2].0, 2u32.to_ne_bytes().to_vec());
        assert_eq!(entries[2].1, expected_hash.to_ne_bytes().to_vec());
    }

    #[test]
    fn build_config_map_entries_timestamp_at_slot_3() {
        let entries = build_config_map_entries(1, true, "x", 1_700_000_000);
        assert_eq!(entries[3].0, 3u32.to_ne_bytes().to_vec());
        assert_eq!(entries[3].1, 1_700_000_000u64.to_ne_bytes().to_vec());
    }

    #[test]
    fn build_config_map_entries_zero_rate_round_trips() {
        // Loader accepts rate=0; the BPF-side decrement logic treats 0
        // as 1 (sample every packet) when the counter resets.
        let entries = build_config_map_entries(0, true, "x", 0);
        assert_eq!(entries[0].1, 0u64.to_ne_bytes().to_vec());
    }

    // Integration tests — require root + a real interface + BPF compile.
    // Run with: cargo test -- --ignored

    #[test]
    #[ignore]
    fn integration_attach_and_detach_on_lo() {
        todo!("Integration: requires root + lo interface + BPF compile")
    }

    #[test]
    #[ignore]
    fn integration_round_trip_one_event() {
        todo!("Integration: send a curl request, observe one ringbuf event")
    }
}
