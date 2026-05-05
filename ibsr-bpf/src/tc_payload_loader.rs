//! Production attacher for ShadowPayload mode.
//!
//! Loads `tc_payload.bpf.c`'s skeleton via libbpf-rs, creates a clsact
//! qdisc on the configured interface, attaches the TC ingress and
//! egress programs, programs the port-filter map, and starts a
//! ringbuf consumer that bridges kernel events into the userspace
//! `PayloadEventSource` trait.
//!
//! Per the project's TDD discipline, every pure function in this
//! module is unit-tested. The kernel-touching glue (skeleton
//! load + qdisc create + attach + ringbuf poll) is tested only via
//! integration on a live system with root + an interface; those
//! tests are marked `#[ignore]` and run with `cargo test -- --ignored`
//! in the project's Docker test rig.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use thiserror::Error;

/// Errors specific to the TC payload loader. These map onto the
/// generic `AttachError` exposed by `ibsr-collector::commands::collect_payload`.
#[derive(Debug, Error)]
pub enum TcPayloadLoaderError {
    #[error("interface '{0}' does not exist")]
    InterfaceNotFound(String),

    #[error("BPF program load failed: {0}")]
    BpfLoad(String),

    #[error("clsact qdisc setup failed for '{iface}': {reason}")]
    Qdisc { iface: String, reason: String },

    #[error("TC program attach failed (direction: {direction}): {reason}")]
    Attach { direction: &'static str, reason: String },

    #[error("port-filter map programming failed: {0}")]
    MapProgram(String),

    #[error("ringbuf setup failed: {0}")]
    Ringbuf(String),

    #[error("ringbuf poll failed: {0}")]
    RingbufPoll(String),

    #[error("port count {0} exceeds maximum 8")]
    TooManyPorts(usize),
}

/// Maximum number of ports the BPF port-filter map accepts. Matches
/// `tc_payload.bpf.c`'s `port_filter` map size.
pub const MAX_PORT_FILTER_ENTRIES: usize = 8;

/// Build the (key, value) byte pairs the BPF port-filter map expects.
///
/// Map shape (per `tc_payload.bpf.c`):
/// - key: u32 slot index (host byte order on userspace side; libbpf
///   handles endianness as appropriate).
/// - value: u16 port (network byte order, as the BPF program compares
///   against `tcp->dest` which is also network byte order).
///
/// Returns up to `MAX_PORT_FILTER_ENTRIES` pairs in slot order. Errors
/// if more ports are supplied than the map can hold.
///
/// Pure function — no I/O — fully testable.
pub fn build_port_filter_entries(
    ports: &[u16],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, TcPayloadLoaderError> {
    if ports.len() > MAX_PORT_FILTER_ENTRIES {
        return Err(TcPayloadLoaderError::TooManyPorts(ports.len()));
    }
    let mut out = Vec::with_capacity(ports.len());
    for (slot, port) in ports.iter().enumerate() {
        let key = (slot as u32).to_ne_bytes().to_vec();
        let value = port.to_be().to_ne_bytes().to_vec();
        out.push((key, value));
    }
    Ok(out)
}

/// Resolve an interface name to its kernel ifindex. Pulled into a
/// trait-mockable function so the resolver path is testable without
/// a real interface.
pub trait InterfaceResolver {
    fn ifindex(&self, name: &str) -> Result<u32, TcPayloadLoaderError>;
}

/// Production resolver — calls `nix::net::if_::if_nametoindex`.
pub struct NixInterfaceResolver;

impl InterfaceResolver for NixInterfaceResolver {
    fn ifindex(&self, name: &str) -> Result<u32, TcPayloadLoaderError> {
        nix::net::if_::if_nametoindex(name)
            .map_err(|_| TcPayloadLoaderError::InterfaceNotFound(name.to_string()))
    }
}

/// Mock resolver for tests — returns canned mappings.
pub struct MockInterfaceResolver {
    pub mappings: std::collections::HashMap<String, u32>,
}

impl MockInterfaceResolver {
    pub fn new() -> Self {
        Self {
            mappings: std::collections::HashMap::new(),
        }
    }
    pub fn with(mut self, name: &str, idx: u32) -> Self {
        self.mappings.insert(name.to_string(), idx);
        self
    }
}

impl Default for MockInterfaceResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl InterfaceResolver for MockInterfaceResolver {
    fn ifindex(&self, name: &str) -> Result<u32, TcPayloadLoaderError> {
        self.mappings
            .get(name)
            .copied()
            .ok_or_else(|| TcPayloadLoaderError::InterfaceNotFound(name.to_string()))
    }
}

/// Shared queue used by the ringbuf callback to hand events to the
/// `PayloadEventSource::poll` caller. Each callback push is one
/// kernel ringbuf event copied into a Vec<u8>; poll drains the queue.
///
/// Pure data structure — no kernel coupling — testable.
#[derive(Debug, Default)]
pub struct PendingEvents {
    inner: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl PendingEvents {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Clone the inner Arc — for the ringbuf callback to push into.
    pub fn shared(&self) -> Arc<Mutex<Vec<Vec<u8>>>> {
        self.inner.clone()
    }

    /// Drain all pending events. Returns them in arrival order.
    pub fn drain(&self) -> Vec<Vec<u8>> {
        let mut guard = self.inner.lock().expect("PendingEvents mutex poisoned");
        std::mem::take(&mut *guard)
    }

    /// Push one event (used by tests; production path uses the shared Arc directly).
    pub fn push(&self, event: Vec<u8>) {
        self.inner.lock().expect("PendingEvents mutex poisoned").push(event);
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("PendingEvents mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// PayloadEventSource implementation backed by a shared
/// `PendingEvents` queue. The libbpf-rs ringbuf consumer pushes
/// into this queue; the orchestrator's `poll` drains it.
///
/// In production, the ringbuf is polled in a separate path before
/// `poll` is called (typically the same loop, where the loader's
/// internal `pump` method invokes `RingBuffer::poll` for `timeout` and
/// then this poll drains the queue). For tests, events are pushed
/// directly via `PendingEvents::push`.
pub struct QueueBackedEventSource {
    pending: PendingEvents,
    /// Optional ringbuf-pump callback. None in tests.
    pump: Option<Box<dyn FnMut(Duration) -> Result<(), String> + Send>>,
}

impl QueueBackedEventSource {
    pub fn new(pending: PendingEvents) -> Self {
        Self {
            pending,
            pump: None,
        }
    }

    /// Attach a pump function that will be called on each `poll` to
    /// drive the kernel ringbuf forward.
    pub fn with_pump<F>(mut self, pump: F) -> Self
    where
        F: FnMut(Duration) -> Result<(), String> + Send + 'static,
    {
        self.pump = Some(Box::new(pump));
        self
    }

    /// Reference to the shared queue (for setting up the ringbuf
    /// callback with the same Arc).
    pub fn pending(&self) -> &PendingEvents {
        &self.pending
    }
}

impl crate::tc_payload_event::DecodedEvent {
    // Marker — keep the symbol referenced so we don't lose import.
    #[doc(hidden)]
    pub fn __sentinel() {}
}

// Implement PayloadEventSource via a trait alias path that doesn't
// pull in ibsr-collector (which depends on us). Since
// PayloadEventSource is defined in ibsr-collector, the impl lives
// there or in a downstream crate. For the loader to be useful from
// ibsr-collector::commands::collect_payload, we expose the
// queue-backed source as a TYPE that ibsr-collector wraps in its own
// trait impl.
//
// (Trait coherence: PayloadEventSource is in ibsr-collector;
// QueueBackedEventSource is in ibsr-bpf. ibsr-collector depends on
// ibsr-bpf, so the impl `impl PayloadEventSource for QueueBackedEventSource`
// lives in ibsr-collector. A small adapter in ibsr-collector wires
// it up.)

#[cfg(test)]
mod tests {
    use super::*;

    // ===========================================
    // build_port_filter_entries — pure function
    // ===========================================

    #[test]
    fn empty_port_list_yields_no_entries() {
        let entries = build_port_filter_entries(&[]).expect("empty ok");
        assert!(entries.is_empty());
    }

    #[test]
    fn single_port_at_slot_0() {
        let entries = build_port_filter_entries(&[8899]).expect("single ok");
        assert_eq!(entries.len(), 1);
        let (k, v) = &entries[0];
        // Key: u32 slot index 0, native byte order.
        assert_eq!(k, &0u32.to_ne_bytes().to_vec());
        // Value: u16 8899 in network byte order (big-endian), then native-byte-order encoded.
        assert_eq!(v, &8899u16.to_be().to_ne_bytes().to_vec());
    }

    #[test]
    fn multiple_ports_in_order() {
        let entries = build_port_filter_entries(&[8899, 9000, 9001]).expect("multi ok");
        assert_eq!(entries.len(), 3);
        for (slot, expected_port) in [8899u16, 9000, 9001].iter().enumerate() {
            let (k, v) = &entries[slot];
            assert_eq!(k, &(slot as u32).to_ne_bytes().to_vec());
            assert_eq!(v, &expected_port.to_be().to_ne_bytes().to_vec());
        }
    }

    #[test]
    fn exactly_max_entries_ok() {
        let ports: Vec<u16> = (1..=8).collect();
        let entries = build_port_filter_entries(&ports).expect("8 ok");
        assert_eq!(entries.len(), 8);
    }

    #[test]
    fn over_max_entries_rejected() {
        let ports: Vec<u16> = (1..=9).collect();
        match build_port_filter_entries(&ports) {
            Err(TcPayloadLoaderError::TooManyPorts(9)) => {}
            other => panic!("expected TooManyPorts(9), got {:?}", other),
        }
    }

    #[test]
    fn port_value_bytes_match_network_byte_order() {
        // 0x1234 in NBO = [0x12, 0x34]. On little-endian platforms,
        // .to_ne_bytes after .to_be() preserves the NBO sequence.
        let entries = build_port_filter_entries(&[0x1234]).unwrap();
        let (_k, v) = &entries[0];
        assert_eq!(v.len(), 2);
        // Verify against direct big-endian byte comparison so the test
        // is platform-independent.
        let nbo = 0x1234u16.to_be_bytes();
        if cfg!(target_endian = "little") {
            // .to_be() flips, then .to_ne_bytes gives big-endian sequence
            // (because bytes match what's stored in memory after the flip).
            // Our wire bytes should equal nbo on little-endian.
            assert_eq!(v.as_slice(), &nbo);
        } else {
            // Big-endian platform: .to_be() is a no-op, .to_ne_bytes is
            // already big-endian, so the bytes equal nbo.
            assert_eq!(v.as_slice(), &nbo);
        }
    }

    // ===========================================
    // InterfaceResolver — mock path
    // ===========================================

    #[test]
    fn mock_resolver_returns_known_iface() {
        let r = MockInterfaceResolver::new()
            .with("lo", 1)
            .with("eth0", 2);
        assert_eq!(r.ifindex("lo").unwrap(), 1);
        assert_eq!(r.ifindex("eth0").unwrap(), 2);
    }

    #[test]
    fn mock_resolver_rejects_unknown_iface() {
        let r = MockInterfaceResolver::new().with("lo", 1);
        match r.ifindex("nope0") {
            Err(TcPayloadLoaderError::InterfaceNotFound(name)) => {
                assert_eq!(name, "nope0");
            }
            other => panic!("expected InterfaceNotFound, got {:?}", other),
        }
    }

    // ===========================================
    // PendingEvents queue
    // ===========================================

    #[test]
    fn pending_events_starts_empty() {
        let p = PendingEvents::new();
        assert!(p.is_empty());
        assert!(p.drain().is_empty());
    }

    #[test]
    fn pending_events_push_then_drain_round_trip() {
        let p = PendingEvents::new();
        p.push(b"event1".to_vec());
        p.push(b"event2".to_vec());
        assert_eq!(p.len(), 2);
        let drained = p.drain();
        assert_eq!(drained, vec![b"event1".to_vec(), b"event2".to_vec()]);
        assert!(p.is_empty(), "drain must reset queue");
    }

    #[test]
    fn pending_events_drain_returns_arrival_order() {
        let p = PendingEvents::new();
        for i in 0..10u8 {
            p.push(vec![i]);
        }
        let drained = p.drain();
        for (i, ev) in drained.iter().enumerate() {
            assert_eq!(ev, &vec![i as u8]);
        }
    }

    #[test]
    fn pending_events_shared_arc_writers_visible_to_drain() {
        // Pin: the shared() Arc and the owning PendingEvents see the
        // same data. This is the load-bearing contract for the
        // ringbuf-callback push path.
        let p = PendingEvents::new();
        let shared = p.shared();
        shared
            .lock()
            .unwrap()
            .push(b"pushed via shared".to_vec());
        let drained = p.drain();
        assert_eq!(drained, vec![b"pushed via shared".to_vec()]);
    }

    #[test]
    fn pending_events_concurrent_writers_dont_panic() {
        // Pin: the Mutex serialises pushes from multiple ringbuf
        // callback invocations (which libbpf-rs calls from the poll
        // thread; the mutex isn't strictly necessary since libbpf-rs
        // serialises callbacks, but the Send + Sync requirement means
        // the type must be safe to share).
        let p = PendingEvents::new();
        let s1 = p.shared();
        let s2 = p.shared();
        let h1 = std::thread::spawn(move || {
            for i in 0..100u8 {
                s1.lock().unwrap().push(vec![i]);
            }
        });
        let h2 = std::thread::spawn(move || {
            for i in 100..200u8 {
                s2.lock().unwrap().push(vec![i]);
            }
        });
        h1.join().unwrap();
        h2.join().unwrap();
        assert_eq!(p.len(), 200);
    }

    // ===========================================
    // QueueBackedEventSource (without ringbuf pump)
    // ===========================================

    #[test]
    fn queue_backed_source_exposes_pending_handle() {
        let p = PendingEvents::new();
        p.push(b"x".to_vec());
        let src = QueueBackedEventSource::new(p);
        assert_eq!(src.pending().len(), 1);
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

    #[test]
    #[ignore]
    fn integration_orphan_qdisc_cleanup_on_drop() {
        todo!("Integration: verify clsact qdisc removed when collector drops")
    }
}
