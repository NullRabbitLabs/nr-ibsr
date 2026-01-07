//! Snapshot and BucketEntry types for IBSR.

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::Ipv4Addr;

/// Current schema version.
/// Version 1: Added multi-port support (dst_port -> dst_ports)
/// Version 2: Added handshake_ack field for accurate SYN-flood detection
/// Version 3: Added per-port granularity (dst_port field in BucketEntry)
/// Version 4: Added aggregation field, changed key_value to src_ip string format
pub const SCHEMA_VERSION: u32 = 4;

/// Key type for bucket entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    SrcIp,
    SrcCidr24,
}

/// A single bucket entry representing counters for one source.
///
/// Note: Custom Serialize/Deserialize implementations emit `src_ip` as a
/// dotted-decimal string instead of `key_value` as u32, for human readability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketEntry {
    pub key_type: KeyType,
    /// The IP address as u32 (for internal use and sorting).
    /// Serialized as `src_ip` in dotted-decimal format.
    pub key_value: u32,
    /// Destination port this bucket tracks (for per-port granularity).
    pub dst_port: Option<u16>,
    pub syn: u32,
    pub ack: u32,
    /// ACKs that are part of handshake completion (ACK=1, SYN=0, RST=0, no payload).
    /// This is used for accurate SYN-flood detection, as established connection ACKs
    /// (with payload) should not count toward handshake success ratio.
    pub handshake_ack: u32,
    pub rst: u32,
    pub packets: u32,
    pub bytes: u64,
}

impl Serialize for BucketEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Count fields: key_type, src_ip, syn, ack, handshake_ack, rst, packets, bytes
        // + optionally dst_port
        let field_count = if self.dst_port.is_some() { 9 } else { 8 };
        let mut state = serializer.serialize_struct("BucketEntry", field_count)?;

        state.serialize_field("key_type", &self.key_type)?;
        state.serialize_field("src_ip", &ip_u32_to_string(self.key_value))?;

        if let Some(port) = self.dst_port {
            state.serialize_field("dst_port", &port)?;
        }

        state.serialize_field("syn", &self.syn)?;
        state.serialize_field("ack", &self.ack)?;
        state.serialize_field("handshake_ack", &self.handshake_ack)?;
        state.serialize_field("rst", &self.rst)?;
        state.serialize_field("packets", &self.packets)?;
        state.serialize_field("bytes", &self.bytes)?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for BucketEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            KeyType,
            SrcIp,
            DstPort,
            Syn,
            Ack,
            HandshakeAck,
            Rst,
            Packets,
            Bytes,
        }

        struct BucketEntryVisitor;

        impl<'de> Visitor<'de> for BucketEntryVisitor {
            type Value = BucketEntry;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct BucketEntry")
            }

            fn visit_map<V>(self, mut map: V) -> Result<BucketEntry, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut key_type = None;
                let mut src_ip: Option<String> = None;
                let mut dst_port = None;
                let mut syn = None;
                let mut ack = None;
                let mut handshake_ack = None;
                let mut rst = None;
                let mut packets = None;
                let mut bytes = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::KeyType => {
                            if key_type.is_some() {
                                return Err(de::Error::duplicate_field("key_type"));
                            }
                            key_type = Some(map.next_value()?);
                        }
                        Field::SrcIp => {
                            if src_ip.is_some() {
                                return Err(de::Error::duplicate_field("src_ip"));
                            }
                            src_ip = Some(map.next_value()?);
                        }
                        Field::DstPort => {
                            if dst_port.is_some() {
                                return Err(de::Error::duplicate_field("dst_port"));
                            }
                            dst_port = Some(map.next_value()?);
                        }
                        Field::Syn => {
                            if syn.is_some() {
                                return Err(de::Error::duplicate_field("syn"));
                            }
                            syn = Some(map.next_value()?);
                        }
                        Field::Ack => {
                            if ack.is_some() {
                                return Err(de::Error::duplicate_field("ack"));
                            }
                            ack = Some(map.next_value()?);
                        }
                        Field::HandshakeAck => {
                            if handshake_ack.is_some() {
                                return Err(de::Error::duplicate_field("handshake_ack"));
                            }
                            handshake_ack = Some(map.next_value()?);
                        }
                        Field::Rst => {
                            if rst.is_some() {
                                return Err(de::Error::duplicate_field("rst"));
                            }
                            rst = Some(map.next_value()?);
                        }
                        Field::Packets => {
                            if packets.is_some() {
                                return Err(de::Error::duplicate_field("packets"));
                            }
                            packets = Some(map.next_value()?);
                        }
                        Field::Bytes => {
                            if bytes.is_some() {
                                return Err(de::Error::duplicate_field("bytes"));
                            }
                            bytes = Some(map.next_value()?);
                        }
                    }
                }

                let key_type = key_type.ok_or_else(|| de::Error::missing_field("key_type"))?;
                let src_ip_str = src_ip.ok_or_else(|| de::Error::missing_field("src_ip"))?;
                // Parse IP - u32::from(Ipv4Addr) uses MSB=first-octet representation
                let key_value = u32::from(
                    src_ip_str
                        .parse::<Ipv4Addr>()
                        .map_err(|_| de::Error::custom(format!("invalid IP address: {}", src_ip_str)))?,
                );
                let syn = syn.ok_or_else(|| de::Error::missing_field("syn"))?;
                let ack = ack.ok_or_else(|| de::Error::missing_field("ack"))?;
                let handshake_ack =
                    handshake_ack.ok_or_else(|| de::Error::missing_field("handshake_ack"))?;
                let rst = rst.ok_or_else(|| de::Error::missing_field("rst"))?;
                let packets = packets.ok_or_else(|| de::Error::missing_field("packets"))?;
                let bytes = bytes.ok_or_else(|| de::Error::missing_field("bytes"))?;

                Ok(BucketEntry {
                    key_type,
                    key_value,
                    dst_port,
                    syn,
                    ack,
                    handshake_ack,
                    rst,
                    packets,
                    bytes,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "key_type",
            "src_ip",
            "dst_port",
            "syn",
            "ack",
            "handshake_ack",
            "rst",
            "packets",
            "bytes",
        ];
        deserializer.deserialize_struct("BucketEntry", FIELDS, BucketEntryVisitor)
    }
}

/// A snapshot of counters at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    /// Describes how metrics are aggregated: "src_ip_dst_port" means per source IP per destination port.
    pub aggregation: String,
    pub ts_unix_sec: u64,
    /// Destination ports being monitored (sorted for deterministic output).
    pub dst_ports: Vec<u16>,
    pub buckets: Vec<BucketEntry>,
}

impl Snapshot {
    /// Create a new snapshot with the current schema version.
    pub fn new(ts_unix_sec: u64, dst_ports: &[u16], mut buckets: Vec<BucketEntry>) -> Self {
        // Sort buckets for deterministic ordering: by key_type, then key_value, then dst_port
        buckets.sort_by(|a, b| {
            a.key_type
                .cmp(&b.key_type)
                .then_with(|| a.key_value.cmp(&b.key_value))
                .then_with(|| a.dst_port.cmp(&b.dst_port))
        });

        // Sort ports for deterministic output
        let mut sorted_ports = dst_ports.to_vec();
        sorted_ports.sort_unstable();

        Self {
            version: SCHEMA_VERSION,
            aggregation: "src_ip_dst_port".to_string(),
            ts_unix_sec,
            dst_ports: sorted_ports,
            buckets,
        }
    }

    /// Serialize snapshot to JSON string (single line for JSONL format).
    /// This cannot fail for our struct types.
    pub fn to_json(&self) -> String {
        // SAFETY: Our struct types are always serializable to JSON.
        // Snapshot contains only primitive types and Vec<BucketEntry>.
        serde_json::to_string(self).expect("Snapshot serialization cannot fail")
    }

    /// Deserialize snapshot from JSON string.
    pub fn from_json(json: &str) -> Result<Self, SnapshotError> {
        let snapshot: Snapshot = serde_json::from_str(json)?;
        if snapshot.version != SCHEMA_VERSION {
            return Err(SnapshotError::VersionMismatch {
                expected: SCHEMA_VERSION,
                found: snapshot.version,
            });
        }
        Ok(snapshot)
    }
}

/// Errors that can occur when working with snapshots.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("schema version mismatch: expected {expected}, found {found}")]
    VersionMismatch { expected: u32, found: u32 },

    #[error("invalid IP address: {0}")]
    InvalidIpAddress(String),
}

/// Convert a u32 IP address to dotted-decimal string.
/// Uses MSB=first-octet representation (same as Ipv4Addr).
pub fn ip_u32_to_string(ip: u32) -> String {
    Ipv4Addr::from(ip).to_string()
}

/// Parse a dotted-decimal IP string to u32.
/// Uses MSB=first-octet representation (same as Ipv4Addr).
pub fn string_to_ip_u32(s: &str) -> Result<u32, SnapshotError> {
    s.parse::<Ipv4Addr>()
        .map(u32::from)
        .map_err(|_| SnapshotError::InvalidIpAddress(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===========================================
    // Test Category A — Schema / Encoding
    // ===========================================

    #[test]
    fn test_roundtrip_empty_snapshot() {
        let snapshot = Snapshot::new(1234567890, &[8899], vec![]);

        let json = snapshot.to_json();
        let restored = Snapshot::from_json(&json).expect("deserialize");

        assert_eq!(snapshot, restored);
    }

    #[test]
    fn test_roundtrip_single_bucket() {
        let bucket = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: 0x0A000001, // 10.0.0.1
            dst_port: Some(8899),
            syn: 100,
            ack: 200,
            handshake_ack: 95,
            rst: 5,
            packets: 305,
            bytes: 45000,
        };
        let snapshot = Snapshot::new(1234567890, &[8899], vec![bucket]);

        let json = snapshot.to_json();
        let restored = Snapshot::from_json(&json).expect("deserialize");

        assert_eq!(snapshot, restored);
    }

    #[test]
    fn test_roundtrip_multiple_buckets() {
        let buckets = vec![
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0A000001,
                dst_port: Some(8000),
                syn: 10,
                ack: 20,
                handshake_ack: 10,
                rst: 1,
                packets: 31,
                bytes: 4500,
            },
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0A000002,
                dst_port: Some(8000),
                syn: 50,
                ack: 100,
                handshake_ack: 50,
                rst: 0,
                packets: 150,
                bytes: 22000,
            },
            BucketEntry {
                key_type: KeyType::SrcCidr24,
                key_value: 0x0A000000,
                dst_port: None,
                syn: 60,
                ack: 120,
                handshake_ack: 60,
                rst: 1,
                packets: 181,
                bytes: 26500,
            },
        ];
        let snapshot = Snapshot::new(1234567890, &[8000], buckets);

        let json = snapshot.to_json();
        let restored = Snapshot::from_json(&json).expect("deserialize");

        assert_eq!(snapshot, restored);
    }

    #[test]
    fn test_deterministic_bucket_ordering() {
        // Create buckets in random order
        let buckets_unordered = vec![
            BucketEntry {
                key_type: KeyType::SrcCidr24,
                key_value: 0x0A000000,
                dst_port: None,
                syn: 1,
                ack: 1,
                handshake_ack: 1,
                rst: 0,
                packets: 2,
                bytes: 100,
            },
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0B000001,
                dst_port: Some(8899),
                syn: 2,
                ack: 2,
                handshake_ack: 2,
                rst: 0,
                packets: 4,
                bytes: 200,
            },
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0A000001,
                dst_port: Some(8899),
                syn: 3,
                ack: 3,
                handshake_ack: 3,
                rst: 0,
                packets: 6,
                bytes: 300,
            },
        ];

        let snapshot = Snapshot::new(1234567890, &[8899], buckets_unordered);

        // Should be sorted: SrcIp entries first (by key_value), then SrcCidr24
        assert_eq!(snapshot.buckets.len(), 3);
        assert_eq!(snapshot.buckets[0].key_type, KeyType::SrcIp);
        assert_eq!(snapshot.buckets[0].key_value, 0x0A000001);
        assert_eq!(snapshot.buckets[1].key_type, KeyType::SrcIp);
        assert_eq!(snapshot.buckets[1].key_value, 0x0B000001);
        assert_eq!(snapshot.buckets[2].key_type, KeyType::SrcCidr24);
        assert_eq!(snapshot.buckets[2].key_value, 0x0A000000);
    }

    #[test]
    fn test_deterministic_ordering_produces_same_json() {
        let buckets1 = vec![
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0B000001,
                dst_port: Some(8899),
                syn: 1,
                ack: 1,
                handshake_ack: 1,
                rst: 0,
                packets: 2,
                bytes: 100,
            },
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0A000001,
                dst_port: Some(8899),
                syn: 2,
                ack: 2,
                handshake_ack: 2,
                rst: 0,
                packets: 4,
                bytes: 200,
            },
        ];

        let buckets2 = vec![
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0A000001,
                dst_port: Some(8899),
                syn: 2,
                ack: 2,
                handshake_ack: 2,
                rst: 0,
                packets: 4,
                bytes: 200,
            },
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0B000001,
                dst_port: Some(8899),
                syn: 1,
                ack: 1,
                handshake_ack: 1,
                rst: 0,
                packets: 2,
                bytes: 100,
            },
        ];

        let snapshot1 = Snapshot::new(1234567890, &[8899], buckets1);
        let snapshot2 = Snapshot::new(1234567890, &[8899], buckets2);

        let json1 = snapshot1.to_json();
        let json2 = snapshot2.to_json();

        assert_eq!(json1, json2);
    }

    #[test]
    fn test_sorting_within_same_key_type() {
        // Test that buckets with the same key_type are sorted by key_value
        // This exercises the then_with clause in the sort comparator
        let buckets = vec![
            BucketEntry {
                key_type: KeyType::SrcCidr24,
                key_value: 0x0C000000, // 12.0.0.0/24
                dst_port: None,
                syn: 1,
                ack: 1,
                handshake_ack: 1,
                rst: 0,
                packets: 2,
                bytes: 100,
            },
            BucketEntry {
                key_type: KeyType::SrcCidr24,
                key_value: 0x0A000000, // 10.0.0.0/24
                dst_port: None,
                syn: 2,
                ack: 2,
                handshake_ack: 2,
                rst: 0,
                packets: 4,
                bytes: 200,
            },
            BucketEntry {
                key_type: KeyType::SrcCidr24,
                key_value: 0x0B000000, // 11.0.0.0/24
                dst_port: None,
                syn: 3,
                ack: 3,
                handshake_ack: 3,
                rst: 0,
                packets: 6,
                bytes: 300,
            },
        ];

        let snapshot = Snapshot::new(1234567890, &[8899], buckets);

        // Should be sorted by key_value within SrcCidr24
        assert_eq!(snapshot.buckets.len(), 3);
        assert_eq!(snapshot.buckets[0].key_value, 0x0A000000);
        assert_eq!(snapshot.buckets[1].key_value, 0x0B000000);
        assert_eq!(snapshot.buckets[2].key_value, 0x0C000000);
    }

    #[test]
    fn test_empty_snapshot_handling() {
        let snapshot = Snapshot::new(0, &[], vec![]);

        assert_eq!(snapshot.version, SCHEMA_VERSION);
        assert_eq!(snapshot.ts_unix_sec, 0);
        assert!(snapshot.dst_ports.is_empty());
        assert!(snapshot.buckets.is_empty());

        let json = snapshot.to_json();
        let restored = Snapshot::from_json(&json).expect("deserialize");
        assert_eq!(snapshot, restored);
    }

    #[test]
    fn test_large_values_u32_max() {
        let bucket = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: u32::MAX,
            dst_port: Some(u16::MAX),
            syn: u32::MAX,
            ack: u32::MAX,
            handshake_ack: u32::MAX,
            rst: u32::MAX,
            packets: u32::MAX,
            bytes: u64::MAX,
        };
        let snapshot = Snapshot::new(u64::MAX, &[u16::MAX], vec![bucket]);

        let json = snapshot.to_json();
        let restored = Snapshot::from_json(&json).expect("deserialize");

        assert_eq!(snapshot, restored);
        assert_eq!(restored.buckets[0].syn, u32::MAX);
        assert_eq!(restored.buckets[0].bytes, u64::MAX);
        assert_eq!(restored.buckets[0].dst_port, Some(u16::MAX));
        assert_eq!(restored.ts_unix_sec, u64::MAX);
        assert_eq!(restored.dst_ports, vec![u16::MAX]);
    }

    #[test]
    fn test_version_mismatch_rejected() {
        // Manually craft JSON with wrong version
        let bad_json = r#"{"version":999,"aggregation":"src_ip_dst_port","ts_unix_sec":1234567890,"dst_ports":[8899],"buckets":[]}"#;

        let result = Snapshot::from_json(bad_json);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            SnapshotError::VersionMismatch {
                expected: 4,
                found: 999
            }
        ));
    }

    #[test]
    fn test_invalid_json_rejected() {
        let bad_json = "not valid json";

        let result = Snapshot::from_json(bad_json);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SnapshotError::Json(_)));
    }

    #[test]
    fn test_missing_field_rejected() {
        // JSON missing required field
        let bad_json = r#"{"version":1,"ts_unix_sec":1234567890,"buckets":[]}"#;

        let result = Snapshot::from_json(bad_json);

        assert!(result.is_err());
    }

    #[test]
    fn test_json_is_single_line() {
        let bucket = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: 0x0A000001,
            dst_port: Some(8899),
            syn: 100,
            ack: 200,
            handshake_ack: 95,
            rst: 5,
            packets: 305,
            bytes: 45000,
        };
        let snapshot = Snapshot::new(1234567890, &[8899], vec![bucket]);

        let json = snapshot.to_json();

        // JSONL format: no newlines in output
        assert!(!json.contains('\n'));
    }

    #[test]
    fn test_key_type_serialization() {
        let bucket_ip = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: 0x0A000001,
            dst_port: Some(80),
            syn: 1,
            ack: 1,
            handshake_ack: 1,
            rst: 0,
            packets: 2,
            bytes: 100,
        };
        let bucket_cidr = BucketEntry {
            key_type: KeyType::SrcCidr24,
            key_value: 0x0A000000,
            dst_port: None,
            syn: 1,
            ack: 1,
            handshake_ack: 1,
            rst: 0,
            packets: 2,
            bytes: 100,
        };

        let json_ip = serde_json::to_string(&bucket_ip).expect("serialize");
        let json_cidr = serde_json::to_string(&bucket_cidr).expect("serialize");

        assert!(json_ip.contains("\"src_ip\""));
        assert!(json_ip.contains("\"dst_port\":80"));
        assert!(json_cidr.contains("\"src_cidr24\""));
        // dst_port should be skipped when None
        assert!(!json_cidr.contains("dst_port"));
    }

    #[test]
    fn test_schema_version_constant() {
        assert_eq!(SCHEMA_VERSION, 4);
    }

    #[test]
    fn test_snapshot_new_sets_version() {
        let snapshot = Snapshot::new(1234567890, &[8899], vec![]);
        assert_eq!(snapshot.version, SCHEMA_VERSION);
    }

    // ===========================================
    // Test Category B — IP Conversion Utilities
    // ===========================================

    #[test]
    fn test_ip_u32_to_dotted_decimal() {
        // u32 values use MSB=first-octet representation (0x0A000001 = 10.0.0.1)
        assert_eq!(ip_u32_to_string(0x52_01_FE_7D), "82.1.254.125");
        assert_eq!(ip_u32_to_string(0x0A_00_00_01), "10.0.0.1");
        assert_eq!(ip_u32_to_string(0x0A_00_00_02), "10.0.0.2");
        assert_eq!(ip_u32_to_string(0xC0_A8_01_01), "192.168.1.1");

        // Edge cases
        assert_eq!(ip_u32_to_string(0), "0.0.0.0");
        assert_eq!(ip_u32_to_string(u32::MAX), "255.255.255.255");
    }

    #[test]
    fn test_dotted_decimal_to_ip_u32() {
        // string_to_ip_u32 returns MSB=first-octet representation
        assert_eq!(string_to_ip_u32("82.1.254.125").unwrap(), 0x52_01_FE_7D);
        assert_eq!(string_to_ip_u32("10.0.0.1").unwrap(), 0x0A_00_00_01);
        assert_eq!(string_to_ip_u32("192.168.1.1").unwrap(), 0xC0_A8_01_01);
        assert_eq!(string_to_ip_u32("0.0.0.0").unwrap(), 0);
        assert_eq!(string_to_ip_u32("255.255.255.255").unwrap(), u32::MAX);
    }

    #[test]
    fn test_ip_roundtrip_conversion() {
        // Roundtrip: string -> u32 (host order) -> string
        let test_ips = ["0.0.0.0", "10.0.0.1", "82.1.254.125", "192.168.1.1", "255.255.255.255"];
        for &ip_str in &test_ips {
            let host_order = string_to_ip_u32(ip_str).expect("parse");
            let back = ip_u32_to_string(host_order);
            assert_eq!(back, ip_str, "roundtrip failed for {}", ip_str);
        }
    }

    #[test]
    fn test_string_to_ip_invalid() {
        assert!(string_to_ip_u32("not an ip").is_err());
        assert!(string_to_ip_u32("256.0.0.1").is_err());
        assert!(string_to_ip_u32("").is_err());
        assert!(string_to_ip_u32("10.0.0").is_err());
    }

    // ===========================================
    // Test Category C — BucketEntry src_ip Serialization
    // ===========================================

    #[test]
    fn test_bucket_emits_src_ip_string_correctly() {
        let bucket = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: 0x0A000001, // 10.0.0.1
            dst_port: Some(8080),
            syn: 100,
            ack: 90,
            handshake_ack: 90,
            rst: 5,
            packets: 200,
            bytes: 20000,
        };

        let json = serde_json::to_string(&bucket).expect("serialize");

        // JSON should contain "src_ip":"10.0.0.1" NOT "key_value":167772161
        assert!(json.contains(r#""src_ip":"10.0.0.1""#), "JSON should contain src_ip string: {}", json);
        assert!(!json.contains(r#""key_value""#), "JSON should NOT contain key_value: {}", json);
    }

    #[test]
    fn test_bucket_roundtrip_with_src_ip() {
        let original = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: 0x5201FE7D, // 82.1.254.125
            dst_port: Some(22),
            syn: 50,
            ack: 45,
            handshake_ack: 40,
            rst: 2,
            packets: 100,
            bytes: 10000,
        };

        let json = serde_json::to_string(&original).expect("serialize");
        let restored: BucketEntry = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(original.key_value, restored.key_value);
        assert_eq!(original.key_type, restored.key_type);
        assert_eq!(original.dst_port, restored.dst_port);
        assert_eq!(original.syn, restored.syn);
        assert_eq!(original.ack, restored.ack);
        assert_eq!(original.handshake_ack, restored.handshake_ack);
        assert_eq!(original.rst, restored.rst);
        assert_eq!(original.packets, restored.packets);
        assert_eq!(original.bytes, restored.bytes);
    }

    #[test]
    fn test_bucket_roundtrip_edge_cases() {
        // Test with various IP addresses
        let ips = [0u32, 167772161, 1375862397, 3232235777, u32::MAX];

        for ip in ips {
            let original = BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: ip,
                dst_port: Some(80),
                syn: 1,
                ack: 1,
                handshake_ack: 1,
                rst: 0,
                packets: 2,
                bytes: 100,
            };

            let json = serde_json::to_string(&original).expect("serialize");
            let restored: BucketEntry = serde_json::from_str(&json).expect("deserialize");

            assert_eq!(original.key_value, restored.key_value,
                "roundtrip failed for IP {}: {}", ip, json);
        }
    }

    // ===========================================
    // Test Category D — Aggregation Field
    // ===========================================

    #[test]
    fn test_snapshot_includes_aggregation_header() {
        let snapshot = Snapshot::new(1000, &[8080], vec![]);
        let json = snapshot.to_json();

        // Verify aggregation field is present and has correct value
        assert!(json.contains(r#""aggregation":"src_ip_dst_port""#),
            "JSON should contain aggregation field: {}", json);

        // Verify roundtrip preserves aggregation
        let restored = Snapshot::from_json(&json).expect("deserialize");
        assert_eq!(restored.aggregation, "src_ip_dst_port");
    }

    #[test]
    fn test_snapshot_aggregation_in_output() {
        let bucket = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: 0x0A000002, // 10.0.0.2
            dst_port: Some(8080),
            syn: 100,
            ack: 90,
            handshake_ack: 90,
            rst: 5,
            packets: 200,
            bytes: 20000,
        };
        let snapshot = Snapshot::new(1000, &[8080], vec![bucket]);
        let json = snapshot.to_json();

        // Check the expected output format
        assert!(json.contains(r#""aggregation":"src_ip_dst_port""#));
        assert!(json.contains(r#""src_ip":"10.0.0.2""#));
    }
}
