//! Sliding window aggregation.

use crate::types::{AggregatedKey, AggregatedStats};
use ibsr_schema::Snapshot;
use std::collections::HashMap;

/// Aggregate counters from multiple snapshots within a time window.
///
/// Returns a map of (key) -> aggregated stats.
pub fn aggregate_snapshots(
    snapshots: &[&Snapshot],
    window_sec: u64,
) -> HashMap<AggregatedKey, AggregatedStats> {
    let mut aggregated: HashMap<AggregatedKey, RawCounters> = HashMap::new();

    for snapshot in snapshots {
        for bucket in &snapshot.buckets {
            let key = AggregatedKey::new(bucket.key_type, bucket.key_value);
            let entry = aggregated.entry(key).or_default();
            entry.syn += bucket.syn as u64;
            entry.ack += bucket.ack as u64;
            entry.rst += bucket.rst as u64;
            entry.packets += bucket.packets as u64;
            entry.bytes += bucket.bytes;
        }
    }

    // Convert raw counters to stats with derived metrics
    aggregated
        .into_iter()
        .map(|(key, raw)| {
            let stats = AggregatedStats {
                total_syn: raw.syn,
                total_ack: raw.ack,
                total_rst: raw.rst,
                total_packets: raw.packets,
                total_bytes: raw.bytes,
                syn_rate: if window_sec > 0 {
                    raw.syn as f64 / window_sec as f64
                } else {
                    0.0
                },
                success_ratio: if raw.syn > 0 {
                    raw.ack as f64 / raw.syn as f64
                } else {
                    0.0
                },
            };
            (key, stats)
        })
        .collect()
}

/// Internal struct for accumulating raw counters.
#[derive(Debug, Default)]
struct RawCounters {
    syn: u64,
    ack: u64,
    rst: u64,
    packets: u64,
    bytes: u64,
}

/// Get sorted aggregated entries for deterministic output.
pub fn sorted_aggregated(
    aggregated: &HashMap<AggregatedKey, AggregatedStats>,
) -> Vec<(AggregatedKey, AggregatedStats)> {
    let mut entries: Vec<_> = aggregated.iter().map(|(k, v)| (*k, *v)).collect();
    entries.sort_by_key(|(k, _)| *k);
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibsr_schema::{BucketEntry, KeyType};

    // ===========================================
    // Category B — Windowing & Aggregation Tests
    // ===========================================

    fn make_snapshot(ts: u64, dst_port: u16, buckets: Vec<BucketEntry>) -> Snapshot {
        Snapshot::new(ts, dst_port, buckets)
    }

    fn make_bucket(key_value: u32, syn: u32, ack: u32, packets: u32, bytes: u64) -> BucketEntry {
        BucketEntry {
            key_type: KeyType::SrcIp,
            key_value,
            syn,
            ack,
            rst: 0,
            packets,
            bytes,
        }
    }

    // -------------------------------------------
    // Aggregate single snapshot
    // -------------------------------------------

    #[test]
    fn test_aggregate_single_snapshot_empty() {
        let s = make_snapshot(1000, 8080, vec![]);
        let result = aggregate_snapshots(&[&s], 10);
        assert!(result.is_empty());
    }

    #[test]
    fn test_aggregate_single_snapshot_one_bucket() {
        let s = make_snapshot(1000, 8080, vec![
            make_bucket(0x0A000001, 100, 50, 150, 15000),
        ]);

        let result = aggregate_snapshots(&[&s], 10);

        assert_eq!(result.len(), 1);
        let key = AggregatedKey::new(KeyType::SrcIp, 0x0A000001);
        let stats = result.get(&key).unwrap();

        assert_eq!(stats.total_syn, 100);
        assert_eq!(stats.total_ack, 50);
        assert_eq!(stats.total_packets, 150);
        assert_eq!(stats.total_bytes, 15000);
    }

    #[test]
    fn test_aggregate_single_snapshot_multiple_buckets() {
        let s = make_snapshot(1000, 8080, vec![
            make_bucket(0x0A000001, 100, 50, 150, 15000),
            make_bucket(0x0A000002, 200, 100, 300, 30000),
        ]);

        let result = aggregate_snapshots(&[&s], 10);

        assert_eq!(result.len(), 2);

        let key1 = AggregatedKey::new(KeyType::SrcIp, 0x0A000001);
        let key2 = AggregatedKey::new(KeyType::SrcIp, 0x0A000002);

        assert_eq!(result.get(&key1).unwrap().total_syn, 100);
        assert_eq!(result.get(&key2).unwrap().total_syn, 200);
    }

    // -------------------------------------------
    // Aggregate multiple snapshots (sum counters)
    // -------------------------------------------

    #[test]
    fn test_aggregate_multiple_snapshots_sums() {
        let s1 = make_snapshot(1000, 8080, vec![
            make_bucket(0x0A000001, 100, 50, 150, 15000),
        ]);
        let s2 = make_snapshot(1001, 8080, vec![
            make_bucket(0x0A000001, 200, 100, 300, 30000),
        ]);

        let result = aggregate_snapshots(&[&s1, &s2], 10);

        let key = AggregatedKey::new(KeyType::SrcIp, 0x0A000001);
        let stats = result.get(&key).unwrap();

        // Summed across both snapshots
        assert_eq!(stats.total_syn, 300);
        assert_eq!(stats.total_ack, 150);
        assert_eq!(stats.total_packets, 450);
        assert_eq!(stats.total_bytes, 45000);
    }

    #[test]
    fn test_aggregate_multiple_snapshots_different_keys() {
        let s1 = make_snapshot(1000, 8080, vec![
            make_bucket(0x0A000001, 100, 50, 150, 15000),
        ]);
        let s2 = make_snapshot(1001, 8080, vec![
            make_bucket(0x0A000002, 200, 100, 300, 30000),
        ]);

        let result = aggregate_snapshots(&[&s1, &s2], 10);

        // Both keys should be present
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_aggregate_three_snapshots() {
        let s1 = make_snapshot(1000, 8080, vec![make_bucket(1, 10, 5, 15, 1500)]);
        let s2 = make_snapshot(1001, 8080, vec![make_bucket(1, 20, 10, 30, 3000)]);
        let s3 = make_snapshot(1002, 8080, vec![make_bucket(1, 30, 15, 45, 4500)]);

        let result = aggregate_snapshots(&[&s1, &s2, &s3], 10);

        let key = AggregatedKey::new(KeyType::SrcIp, 1);
        let stats = result.get(&key).unwrap();

        assert_eq!(stats.total_syn, 60);
        assert_eq!(stats.total_ack, 30);
        assert_eq!(stats.total_packets, 90);
        assert_eq!(stats.total_bytes, 9000);
    }

    // -------------------------------------------
    // syn_rate calculation
    // -------------------------------------------

    #[test]
    fn test_syn_rate_calculation() {
        let s = make_snapshot(1000, 8080, vec![
            make_bucket(0x0A000001, 100, 50, 150, 15000),
        ]);

        // 100 SYNs over 10 seconds = 10 SYNs/sec
        let result = aggregate_snapshots(&[&s], 10);

        let key = AggregatedKey::new(KeyType::SrcIp, 0x0A000001);
        let stats = result.get(&key).unwrap();

        assert!((stats.syn_rate - 10.0).abs() < 0.001);
    }

    #[test]
    fn test_syn_rate_different_window() {
        let s = make_snapshot(1000, 8080, vec![
            make_bucket(0x0A000001, 100, 50, 150, 15000),
        ]);

        // 100 SYNs over 5 seconds = 20 SYNs/sec
        let result = aggregate_snapshots(&[&s], 5);

        let key = AggregatedKey::new(KeyType::SrcIp, 0x0A000001);
        let stats = result.get(&key).unwrap();

        assert!((stats.syn_rate - 20.0).abs() < 0.001);
    }

    #[test]
    fn test_syn_rate_zero_window() {
        let s = make_snapshot(1000, 8080, vec![
            make_bucket(0x0A000001, 100, 50, 150, 15000),
        ]);

        // Zero window should give 0 rate (avoid div/0)
        let result = aggregate_snapshots(&[&s], 0);

        let key = AggregatedKey::new(KeyType::SrcIp, 0x0A000001);
        let stats = result.get(&key).unwrap();

        assert_eq!(stats.syn_rate, 0.0);
    }

    // -------------------------------------------
    // success_ratio calculation
    // -------------------------------------------

    #[test]
    fn test_success_ratio_calculation() {
        let s = make_snapshot(1000, 8080, vec![
            make_bucket(0x0A000001, 100, 50, 150, 15000),
        ]);

        // 50 ACKs / 100 SYNs = 0.5
        let result = aggregate_snapshots(&[&s], 10);

        let key = AggregatedKey::new(KeyType::SrcIp, 0x0A000001);
        let stats = result.get(&key).unwrap();

        assert!((stats.success_ratio - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_success_ratio_perfect() {
        let s = make_snapshot(1000, 8080, vec![
            make_bucket(0x0A000001, 100, 100, 200, 20000),
        ]);

        // 100 ACKs / 100 SYNs = 1.0
        let result = aggregate_snapshots(&[&s], 10);

        let key = AggregatedKey::new(KeyType::SrcIp, 0x0A000001);
        let stats = result.get(&key).unwrap();

        assert!((stats.success_ratio - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_success_ratio_zero_syn() {
        let s = make_snapshot(1000, 8080, vec![
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0A000001,
                syn: 0,
                ack: 50,
                rst: 0,
                packets: 50,
                bytes: 5000,
            },
        ]);

        // 0 SYNs should give 0.0 ratio (avoid div/0)
        let result = aggregate_snapshots(&[&s], 10);

        let key = AggregatedKey::new(KeyType::SrcIp, 0x0A000001);
        let stats = result.get(&key).unwrap();

        assert_eq!(stats.success_ratio, 0.0);
    }

    #[test]
    fn test_success_ratio_low() {
        let s = make_snapshot(1000, 8080, vec![
            make_bucket(0x0A000001, 1000, 10, 1010, 101000),
        ]);

        // 10 ACKs / 1000 SYNs = 0.01
        let result = aggregate_snapshots(&[&s], 10);

        let key = AggregatedKey::new(KeyType::SrcIp, 0x0A000001);
        let stats = result.get(&key).unwrap();

        assert!((stats.success_ratio - 0.01).abs() < 0.001);
    }

    // -------------------------------------------
    // Deterministic aggregation
    // -------------------------------------------

    #[test]
    fn test_aggregate_deterministic() {
        let s1 = make_snapshot(1000, 8080, vec![
            make_bucket(2, 200, 100, 300, 30000),
            make_bucket(1, 100, 50, 150, 15000),
        ]);
        let s2 = make_snapshot(1001, 8080, vec![
            make_bucket(1, 50, 25, 75, 7500),
            make_bucket(2, 100, 50, 150, 15000),
        ]);

        let result1 = aggregate_snapshots(&[&s1, &s2], 10);
        let result2 = aggregate_snapshots(&[&s1, &s2], 10);

        // Same input -> same output
        assert_eq!(result1.len(), result2.len());
        for (k, v) in &result1 {
            assert_eq!(result2.get(k).unwrap(), v);
        }
    }

    #[test]
    fn test_sorted_aggregated_deterministic_order() {
        let s = make_snapshot(1000, 8080, vec![
            make_bucket(3, 300, 150, 450, 45000),
            make_bucket(1, 100, 50, 150, 15000),
            make_bucket(2, 200, 100, 300, 30000),
        ]);

        let result = aggregate_snapshots(&[&s], 10);
        let sorted = sorted_aggregated(&result);

        // Should be sorted by key (key_type, key_value)
        assert_eq!(sorted.len(), 3);
        assert_eq!(sorted[0].0.key_value, 1);
        assert_eq!(sorted[1].0.key_value, 2);
        assert_eq!(sorted[2].0.key_value, 3);
    }

    // -------------------------------------------
    // Edge case: all snapshots outside window
    // -------------------------------------------

    #[test]
    fn test_aggregate_empty_snapshot_list() {
        let result: HashMap<AggregatedKey, AggregatedStats> = aggregate_snapshots(&[], 10);
        assert!(result.is_empty());
    }

    // -------------------------------------------
    // CIDR key type
    // -------------------------------------------

    #[test]
    fn test_aggregate_cidr_key_type() {
        let s = make_snapshot(1000, 8080, vec![
            BucketEntry {
                key_type: KeyType::SrcCidr24,
                key_value: 0x0A000000,
                syn: 100,
                ack: 50,
                rst: 0,
                packets: 150,
                bytes: 15000,
            },
        ]);

        let result = aggregate_snapshots(&[&s], 10);

        let key = AggregatedKey::new(KeyType::SrcCidr24, 0x0A000000);
        assert!(result.contains_key(&key));
    }

    #[test]
    fn test_aggregate_mixed_key_types() {
        let s = make_snapshot(1000, 8080, vec![
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0A000001,
                syn: 100,
                ack: 50,
                rst: 0,
                packets: 150,
                bytes: 15000,
            },
            BucketEntry {
                key_type: KeyType::SrcCidr24,
                key_value: 0x0A000000,
                syn: 200,
                ack: 100,
                rst: 0,
                packets: 300,
                bytes: 30000,
            },
        ]);

        let result = aggregate_snapshots(&[&s], 10);

        // Both key types present and separate
        assert_eq!(result.len(), 2);

        let ip_key = AggregatedKey::new(KeyType::SrcIp, 0x0A000001);
        let cidr_key = AggregatedKey::new(KeyType::SrcCidr24, 0x0A000000);

        assert!(result.contains_key(&ip_key));
        assert!(result.contains_key(&cidr_key));
    }
}
