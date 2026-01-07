//! BPF Map Reader abstraction for IBSR.
//!
//! This module provides:
//! - `MapKey` struct representing the composite map key (src_ip, dst_port)
//! - `Counters` struct representing raw counter data from BPF map
//! - `MapReader` trait for reading counters (with mock implementation for testing)
//! - Conversion from raw counters to `Snapshot`

use std::collections::HashMap;

use ibsr_clock::Clock;
use ibsr_schema::{BucketEntry, KeyType, Snapshot};
use thiserror::Error;

/// Composite map key for per-IP-per-port tracking.
/// Matches the BPF struct map_key layout: src_ip(4) + dst_port(2) + _pad(2) = 8 bytes
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct MapKey {
    pub src_ip: u32,
    pub dst_port: u16,
}

/// Raw counter data from BPF map.
/// This matches the structure stored in the LRU hash map.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub syn: u32,
    pub ack: u32,
    /// ACKs that complete the TCP handshake (ACK=1, SYN=0, RST=0, no payload).
    pub handshake_ack: u32,
    pub rst: u32,
    pub packets: u32,
    pub bytes: u64,
}

/// Errors from map reading operations.
#[derive(Debug, Error)]
pub enum MapReaderError {
    #[error("failed to read BPF map: {0}")]
    ReadError(String),
}

/// Errors specific to BPF program operations.
#[derive(Debug, Error)]
pub enum BpfError {
    #[error("failed to load BPF program: {0}")]
    Load(String),

    #[error("failed to attach XDP program to interface '{interface}': {reason}")]
    Attach { interface: String, reason: String },

    #[error("network interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("insufficient permissions (requires CAP_BPF, CAP_NET_ADMIN)")]
    InsufficientPermissions,

    #[error("BPF map operation failed: {0}")]
    MapError(String),
}

/// Trait for reading counters from a BPF map.
pub trait MapReader: Send + Sync {
    /// Read all counters from the map.
    /// Returns a map of (src_ip, dst_port) to counters.
    fn read_counters(&self) -> Result<HashMap<MapKey, Counters>, MapReaderError>;
}

/// Mock map reader for testing.
#[derive(Debug, Default)]
pub struct MockMapReader {
    counters: HashMap<MapKey, Counters>,
}

impl MockMapReader {
    /// Create a new empty mock map reader.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a mock map reader with predefined counters.
    pub fn with_counters(counters: HashMap<MapKey, Counters>) -> Self {
        Self { counters }
    }

    /// Add a counter entry for a specific (src_ip, dst_port) pair.
    pub fn add_counter(&mut self, key: MapKey, counters: Counters) {
        self.counters.insert(key, counters);
    }
}

impl MapReader for MockMapReader {
    fn read_counters(&self) -> Result<HashMap<MapKey, Counters>, MapReaderError> {
        Ok(self.counters.clone())
    }
}

/// Convert raw counters to a Snapshot.
///
/// # Arguments
/// * `counters` - Map of (src_ip, dst_port) to counter values
/// * `clock` - Clock implementation for timestamp
/// * `dst_ports` - The destination ports being monitored (for metadata)
pub fn counters_to_snapshot<C: Clock>(
    counters: &HashMap<MapKey, Counters>,
    clock: &C,
    dst_ports: &[u16],
) -> Snapshot {
    let buckets: Vec<BucketEntry> = counters
        .iter()
        .map(|(key, c)| BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: key.src_ip,
            dst_port: Some(key.dst_port),
            syn: c.syn,
            ack: c.ack,
            handshake_ack: c.handshake_ack,
            rst: c.rst,
            packets: c.packets,
            bytes: c.bytes,
        })
        .collect();

    Snapshot::new(clock.now_unix_sec(), dst_ports, buckets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibsr_clock::MockClock;

    // ===========================================
    // Test Category C — Map Reader / Snapshot Conversion
    // ===========================================

    // --- Counter mapping to BucketEntry ---

    #[test]
    fn test_single_counter_to_bucket_entry() {
        let mut counters = HashMap::new();
        counters.insert(
            MapKey { src_ip: 0x0A000001, dst_port: 8899 }, // 10.0.0.1:8899
            Counters {
                syn: 100,
                ack: 200,
                handshake_ack: 95,
                rst: 5,
                packets: 305,
                bytes: 45000,
            },
        );

        let clock = MockClock::new(1234567890);
        let snapshot = counters_to_snapshot(&counters, &clock, &[8899]);

        assert_eq!(snapshot.buckets.len(), 1);
        let bucket = &snapshot.buckets[0];
        assert_eq!(bucket.key_type, KeyType::SrcIp);
        assert_eq!(bucket.key_value, 0x0A000001);
        assert_eq!(bucket.dst_port, Some(8899));
        assert_eq!(bucket.syn, 100);
        assert_eq!(bucket.ack, 200);
        assert_eq!(bucket.handshake_ack, 95);
        assert_eq!(bucket.rst, 5);
        assert_eq!(bucket.packets, 305);
        assert_eq!(bucket.bytes, 45000);
    }

    #[test]
    fn test_multiple_counters_to_bucket_entries() {
        let mut counters = HashMap::new();
        counters.insert(
            MapKey { src_ip: 0x0A000001, dst_port: 8899 },
            Counters {
                syn: 10,
                ack: 20,
                handshake_ack: 10,
                rst: 1,
                packets: 31,
                bytes: 4500,
            },
        );
        counters.insert(
            MapKey { src_ip: 0x0A000002, dst_port: 8899 },
            Counters {
                syn: 50,
                ack: 100,
                handshake_ack: 50,
                rst: 0,
                packets: 150,
                bytes: 22000,
            },
        );

        let clock = MockClock::new(1234567890);
        let snapshot = counters_to_snapshot(&counters, &clock, &[8899]);

        assert_eq!(snapshot.buckets.len(), 2);
    }

    #[test]
    fn test_empty_counters_produces_empty_snapshot() {
        let counters: HashMap<MapKey, Counters> = HashMap::new();
        let clock = MockClock::new(1234567890);

        let snapshot = counters_to_snapshot(&counters, &clock, &[8899]);

        assert!(snapshot.buckets.is_empty());
    }

    // --- Timestamp alignment (mock clock) ---

    #[test]
    fn test_snapshot_uses_clock_timestamp() {
        let counters: HashMap<MapKey, Counters> = HashMap::new();
        let clock = MockClock::new(9999999999);

        let snapshot = counters_to_snapshot(&counters, &clock, &[8899]);

        assert_eq!(snapshot.ts_unix_sec, 9999999999);
    }

    #[test]
    fn test_snapshot_timestamp_zero() {
        let counters: HashMap<MapKey, Counters> = HashMap::new();
        let clock = MockClock::new(0);

        let snapshot = counters_to_snapshot(&counters, &clock, &[8899]);

        assert_eq!(snapshot.ts_unix_sec, 0);
    }

    #[test]
    fn test_snapshot_timestamp_max() {
        let counters: HashMap<MapKey, Counters> = HashMap::new();
        let clock = MockClock::new(u64::MAX);

        let snapshot = counters_to_snapshot(&counters, &clock, &[8899]);

        assert_eq!(snapshot.ts_unix_sec, u64::MAX);
    }

    // --- dst_port embedding ---

    #[test]
    fn test_snapshot_embeds_dst_port() {
        let counters: HashMap<MapKey, Counters> = HashMap::new();
        let clock = MockClock::new(1234567890);

        let snapshot = counters_to_snapshot(&counters, &clock, &[8899]);

        assert_eq!(snapshot.dst_ports, vec![8899]);
    }

    #[test]
    fn test_snapshot_embeds_different_dst_port() {
        let counters: HashMap<MapKey, Counters> = HashMap::new();
        let clock = MockClock::new(1234567890);

        let snapshot = counters_to_snapshot(&counters, &clock, &[443]);

        assert_eq!(snapshot.dst_ports, vec![443]);
    }

    #[test]
    fn test_snapshot_dst_port_max() {
        let counters: HashMap<MapKey, Counters> = HashMap::new();
        let clock = MockClock::new(1234567890);

        let snapshot = counters_to_snapshot(&counters, &clock, &[u16::MAX]);

        assert_eq!(snapshot.dst_ports, vec![u16::MAX]);
    }

    // --- Deterministic ordering ---

    #[test]
    fn test_snapshot_buckets_are_sorted_by_ip_then_port() {
        let mut counters = HashMap::new();
        // Insert in non-sorted order
        counters.insert(MapKey { src_ip: 0x0C000001, dst_port: 80 }, Counters::default());
        counters.insert(MapKey { src_ip: 0x0A000001, dst_port: 443 }, Counters::default());
        counters.insert(MapKey { src_ip: 0x0A000001, dst_port: 80 }, Counters::default());
        counters.insert(MapKey { src_ip: 0x0B000001, dst_port: 80 }, Counters::default());

        let clock = MockClock::new(1234567890);
        let snapshot = counters_to_snapshot(&counters, &clock, &[80, 443]);

        // Should be sorted by key_value (IP address), then by dst_port
        assert_eq!(snapshot.buckets[0].key_value, 0x0A000001);
        assert_eq!(snapshot.buckets[0].dst_port, Some(80));
        assert_eq!(snapshot.buckets[1].key_value, 0x0A000001);
        assert_eq!(snapshot.buckets[1].dst_port, Some(443));
        assert_eq!(snapshot.buckets[2].key_value, 0x0B000001);
        assert_eq!(snapshot.buckets[3].key_value, 0x0C000001);
    }

    #[test]
    fn test_snapshot_deterministic_json() {
        let mut counters1 = HashMap::new();
        counters1.insert(MapKey { src_ip: 0x0B000001, dst_port: 8899 }, Counters { syn: 1, ..Default::default() });
        counters1.insert(MapKey { src_ip: 0x0A000001, dst_port: 8899 }, Counters { syn: 2, ..Default::default() });

        let mut counters2 = HashMap::new();
        counters2.insert(MapKey { src_ip: 0x0A000001, dst_port: 8899 }, Counters { syn: 2, ..Default::default() });
        counters2.insert(MapKey { src_ip: 0x0B000001, dst_port: 8899 }, Counters { syn: 1, ..Default::default() });

        let clock = MockClock::new(1234567890);
        let snapshot1 = counters_to_snapshot(&counters1, &clock, &[8899]);
        let snapshot2 = counters_to_snapshot(&counters2, &clock, &[8899]);

        // Same data should produce identical JSON regardless of insertion order
        assert_eq!(snapshot1.to_json(), snapshot2.to_json());
    }

    // --- MockMapReader tests ---

    #[test]
    fn test_mock_map_reader_empty() {
        let reader = MockMapReader::new();
        let counters = reader.read_counters().expect("read counters");

        assert!(counters.is_empty());
    }

    #[test]
    fn test_mock_map_reader_with_counters() {
        let mut initial = HashMap::new();
        let key = MapKey { src_ip: 0x0A000001, dst_port: 8899 };
        initial.insert(key, Counters { syn: 10, ..Default::default() });

        let reader = MockMapReader::with_counters(initial);
        let counters = reader.read_counters().expect("read counters");

        assert_eq!(counters.len(), 1);
        assert_eq!(counters.get(&key).unwrap().syn, 10);
    }

    #[test]
    fn test_mock_map_reader_add_counter() {
        let mut reader = MockMapReader::new();
        let key1 = MapKey { src_ip: 0x0A000001, dst_port: 8899 };
        let key2 = MapKey { src_ip: 0x0A000002, dst_port: 8899 };
        reader.add_counter(key1, Counters { syn: 5, ..Default::default() });
        reader.add_counter(key2, Counters { syn: 10, ..Default::default() });

        let counters = reader.read_counters().expect("read counters");

        assert_eq!(counters.len(), 2);
        assert_eq!(counters.get(&key1).unwrap().syn, 5);
        assert_eq!(counters.get(&key2).unwrap().syn, 10);
    }

    #[test]
    fn test_mock_map_reader_overwrite_counter() {
        let mut reader = MockMapReader::new();
        let key = MapKey { src_ip: 0x0A000001, dst_port: 8899 };
        reader.add_counter(key, Counters { syn: 5, ..Default::default() });
        reader.add_counter(key, Counters { syn: 10, ..Default::default() });

        let counters = reader.read_counters().expect("read counters");

        assert_eq!(counters.len(), 1);
        assert_eq!(counters.get(&key).unwrap().syn, 10);
    }

    #[test]
    fn test_mock_map_reader_same_ip_different_ports() {
        let mut reader = MockMapReader::new();
        let key1 = MapKey { src_ip: 0x0A000001, dst_port: 80 };
        let key2 = MapKey { src_ip: 0x0A000001, dst_port: 443 };
        reader.add_counter(key1, Counters { syn: 5, ..Default::default() });
        reader.add_counter(key2, Counters { syn: 10, ..Default::default() });

        let counters = reader.read_counters().expect("read counters");

        // Same IP on different ports should be tracked separately
        assert_eq!(counters.len(), 2);
        assert_eq!(counters.get(&key1).unwrap().syn, 5);
        assert_eq!(counters.get(&key2).unwrap().syn, 10);
    }

    #[test]
    fn test_map_reader_trait_object() {
        let reader: Box<dyn MapReader> = Box::new(MockMapReader::new());
        let counters = reader.read_counters().expect("read counters");

        assert!(counters.is_empty());
    }

    // --- Counter boundary tests ---

    #[test]
    fn test_counter_max_values() {
        let mut counters = HashMap::new();
        counters.insert(
            MapKey { src_ip: u32::MAX, dst_port: u16::MAX },
            Counters {
                syn: u32::MAX,
                ack: u32::MAX,
                handshake_ack: u32::MAX,
                rst: u32::MAX,
                packets: u32::MAX,
                bytes: u64::MAX,
            },
        );

        let clock = MockClock::new(1234567890);
        let snapshot = counters_to_snapshot(&counters, &clock, &[8899]);

        let bucket = &snapshot.buckets[0];
        assert_eq!(bucket.key_value, u32::MAX);
        assert_eq!(bucket.dst_port, Some(u16::MAX));
        assert_eq!(bucket.syn, u32::MAX);
        assert_eq!(bucket.ack, u32::MAX);
        assert_eq!(bucket.handshake_ack, u32::MAX);
        assert_eq!(bucket.rst, u32::MAX);
        assert_eq!(bucket.packets, u32::MAX);
        assert_eq!(bucket.bytes, u64::MAX);
    }

    #[test]
    fn test_counter_zero_values() {
        let mut counters = HashMap::new();
        counters.insert(MapKey { src_ip: 0, dst_port: 0 }, Counters::default());

        let clock = MockClock::new(1234567890);
        let snapshot = counters_to_snapshot(&counters, &clock, &[8899]);

        let bucket = &snapshot.buckets[0];
        assert_eq!(bucket.key_value, 0);
        assert_eq!(bucket.dst_port, Some(0));
        assert_eq!(bucket.syn, 0);
        assert_eq!(bucket.ack, 0);
        assert_eq!(bucket.handshake_ack, 0);
        assert_eq!(bucket.rst, 0);
        assert_eq!(bucket.packets, 0);
        assert_eq!(bucket.bytes, 0);
    }

    // --- Integration: read and convert ---

    #[test]
    fn test_read_and_convert_workflow() {
        let mut reader = MockMapReader::new();
        reader.add_counter(
            MapKey { src_ip: 0x0A000001, dst_port: 8899 },
            Counters {
                syn: 100,
                ack: 200,
                handshake_ack: 95,
                rst: 5,
                packets: 305,
                bytes: 45000,
            },
        );

        let clock = MockClock::new(1234567890);

        // Read counters
        let counters = reader.read_counters().expect("read counters");

        // Convert to snapshot
        let snapshot = counters_to_snapshot(&counters, &clock, &[8899]);

        // Verify snapshot
        assert_eq!(snapshot.ts_unix_sec, 1234567890);
        assert_eq!(snapshot.dst_ports, vec![8899]);
        assert_eq!(snapshot.buckets.len(), 1);
        assert_eq!(snapshot.buckets[0].syn, 100);
        assert_eq!(snapshot.buckets[0].dst_port, Some(8899));
    }

    #[test]
    fn test_snapshot_roundtrip_through_json() {
        let mut counters = HashMap::new();
        counters.insert(
            MapKey { src_ip: 0x0A000001, dst_port: 8899 },
            Counters {
                syn: 100,
                ack: 200,
                handshake_ack: 95,
                rst: 5,
                packets: 305,
                bytes: 45000,
            },
        );

        let clock = MockClock::new(1234567890);
        let snapshot = counters_to_snapshot(&counters, &clock, &[8899]);

        // Serialize and deserialize
        let json = snapshot.to_json();
        let restored = Snapshot::from_json(&json).expect("deserialize");

        assert_eq!(snapshot, restored);
    }

    // --- BpfError tests ---

    #[test]
    fn test_bpf_error_load_display() {
        let err = BpfError::Load("failed to open object".to_string());
        assert_eq!(
            err.to_string(),
            "failed to load BPF program: failed to open object"
        );
    }

    #[test]
    fn test_bpf_error_attach_display() {
        let err = BpfError::Attach {
            interface: "eth0".to_string(),
            reason: "device busy".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "failed to attach XDP program to interface 'eth0': device busy"
        );
    }

    #[test]
    fn test_bpf_error_interface_not_found_display() {
        let err = BpfError::InterfaceNotFound("eth99".to_string());
        assert_eq!(err.to_string(), "network interface not found: eth99");
    }

    #[test]
    fn test_bpf_error_insufficient_permissions_display() {
        let err = BpfError::InsufficientPermissions;
        assert_eq!(
            err.to_string(),
            "insufficient permissions (requires CAP_BPF, CAP_NET_ADMIN)"
        );
    }

    #[test]
    fn test_bpf_error_map_error_display() {
        let err = BpfError::MapError("key not found".to_string());
        assert_eq!(err.to_string(), "BPF map operation failed: key not found");
    }

    #[test]
    fn test_bpf_error_debug() {
        let err = BpfError::Load("test".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("Load"));
        assert!(debug.contains("test"));
    }
}
