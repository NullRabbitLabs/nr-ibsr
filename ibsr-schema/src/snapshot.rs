//! Snapshot and BucketEntry types for IBSR.

use serde::{Deserialize, Serialize};

/// Current schema version.
/// Version 1: Added multi-port support (dst_port -> dst_ports)
/// Version 2: Added handshake_ack field for accurate SYN-flood detection
pub const SCHEMA_VERSION: u32 = 2;

/// Key type for bucket entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    SrcIp,
    SrcCidr24,
}

/// A single bucket entry representing counters for one source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketEntry {
    pub key_type: KeyType,
    pub key_value: u32,
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

/// A snapshot of counters at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub ts_unix_sec: u64,
    /// Destination ports being monitored (sorted for deterministic output).
    pub dst_ports: Vec<u16>,
    pub buckets: Vec<BucketEntry>,
}

impl Snapshot {
    /// Create a new snapshot with the current schema version.
    pub fn new(ts_unix_sec: u64, dst_ports: &[u16], mut buckets: Vec<BucketEntry>) -> Self {
        // Sort buckets for deterministic ordering: by key_type, then key_value
        buckets.sort_by(|a, b| {
            a.key_type
                .cmp(&b.key_type)
                .then_with(|| a.key_value.cmp(&b.key_value))
        });

        // Sort ports for deterministic output
        let mut sorted_ports = dst_ports.to_vec();
        sorted_ports.sort_unstable();

        Self {
            version: SCHEMA_VERSION,
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
        assert_eq!(restored.ts_unix_sec, u64::MAX);
        assert_eq!(restored.dst_ports, vec![u16::MAX]);
    }

    #[test]
    fn test_version_mismatch_rejected() {
        // Manually craft JSON with wrong version
        let bad_json = r#"{"version":999,"ts_unix_sec":1234567890,"dst_ports":[8899],"buckets":[]}"#;

        let result = Snapshot::from_json(bad_json);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            SnapshotError::VersionMismatch {
                expected: 2,
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
        assert!(json_cidr.contains("\"src_cidr24\""));
    }

    #[test]
    fn test_schema_version_constant() {
        assert_eq!(SCHEMA_VERSION, 2);
    }

    #[test]
    fn test_snapshot_new_sets_version() {
        let snapshot = Snapshot::new(1234567890, &[8899], vec![]);
        assert_eq!(snapshot.version, SCHEMA_VERSION);
    }
}
