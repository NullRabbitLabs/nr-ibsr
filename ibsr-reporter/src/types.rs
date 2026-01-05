//! Shared internal types for the reporter.

use ibsr_schema::KeyType;
use serde::{Deserialize, Serialize};

/// Aggregated key identifying a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AggregatedKey {
    pub key_type: KeyType,
    pub key_value: u32,
}

impl AggregatedKey {
    /// Create a new aggregated key.
    pub fn new(key_type: KeyType, key_value: u32) -> Self {
        Self { key_type, key_value }
    }

    /// Format key as human-readable string (IP or CIDR notation).
    pub fn to_display_string(&self) -> String {
        let ip = std::net::Ipv4Addr::from(self.key_value);
        match self.key_type {
            KeyType::SrcIp => ip.to_string(),
            KeyType::SrcCidr24 => format!("{}/24", ip),
        }
    }
}

/// Aggregated statistics for a key over a time window.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct AggregatedStats {
    pub total_syn: u64,
    pub total_ack: u64,
    pub total_rst: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub syn_rate: f64,
    pub success_ratio: f64,
}

/// Time bounds derived from snapshot timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowBounds {
    pub start_ts: u64,
    pub end_ts: u64,
}

impl WindowBounds {
    /// Create new window bounds.
    pub fn new(start_ts: u64, end_ts: u64) -> Self {
        Self { start_ts, end_ts }
    }

    /// Duration of the window in seconds.
    pub fn duration_sec(&self) -> u64 {
        self.end_ts.saturating_sub(self.start_ts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===========================================
    // AggregatedKey Tests
    // ===========================================

    #[test]
    fn test_aggregated_key_new() {
        let key = AggregatedKey::new(KeyType::SrcIp, 0x0A000001);
        assert_eq!(key.key_type, KeyType::SrcIp);
        assert_eq!(key.key_value, 0x0A000001);
    }

    #[test]
    fn test_aggregated_key_display_src_ip() {
        let key = AggregatedKey::new(KeyType::SrcIp, 0x0A000001); // 10.0.0.1
        assert_eq!(key.to_display_string(), "10.0.0.1");
    }

    #[test]
    fn test_aggregated_key_display_cidr24() {
        let key = AggregatedKey::new(KeyType::SrcCidr24, 0x0A000000); // 10.0.0.0
        assert_eq!(key.to_display_string(), "10.0.0.0/24");
    }

    #[test]
    fn test_aggregated_key_ordering() {
        let key1 = AggregatedKey::new(KeyType::SrcIp, 100);
        let key2 = AggregatedKey::new(KeyType::SrcIp, 200);
        let key3 = AggregatedKey::new(KeyType::SrcCidr24, 100);

        // SrcIp < SrcCidr24 (enum ordering)
        assert!(key1 < key3);
        // Same type, lower value first
        assert!(key1 < key2);
    }

    #[test]
    fn test_aggregated_key_hash_eq() {
        use std::collections::HashSet;

        let key1 = AggregatedKey::new(KeyType::SrcIp, 100);
        let key2 = AggregatedKey::new(KeyType::SrcIp, 100);
        let key3 = AggregatedKey::new(KeyType::SrcIp, 200);

        let mut set = HashSet::new();
        set.insert(key1);
        assert!(set.contains(&key2));
        assert!(!set.contains(&key3));
    }

    // ===========================================
    // AggregatedStats Tests
    // ===========================================

    #[test]
    fn test_aggregated_stats_default() {
        let stats = AggregatedStats::default();
        assert_eq!(stats.total_syn, 0);
        assert_eq!(stats.total_ack, 0);
        assert_eq!(stats.total_rst, 0);
        assert_eq!(stats.total_packets, 0);
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.syn_rate, 0.0);
        assert_eq!(stats.success_ratio, 0.0);
    }

    // ===========================================
    // WindowBounds Tests
    // ===========================================

    #[test]
    fn test_window_bounds_new() {
        let bounds = WindowBounds::new(1000, 1010);
        assert_eq!(bounds.start_ts, 1000);
        assert_eq!(bounds.end_ts, 1010);
    }

    #[test]
    fn test_window_bounds_duration() {
        let bounds = WindowBounds::new(1000, 1010);
        assert_eq!(bounds.duration_sec(), 10);
    }

    #[test]
    fn test_window_bounds_duration_same_time() {
        let bounds = WindowBounds::new(1000, 1000);
        assert_eq!(bounds.duration_sec(), 0);
    }

    #[test]
    fn test_window_bounds_duration_saturating() {
        // Edge case: end < start (shouldn't happen but handle gracefully)
        let bounds = WindowBounds::new(1010, 1000);
        assert_eq!(bounds.duration_sec(), 0);
    }
}
