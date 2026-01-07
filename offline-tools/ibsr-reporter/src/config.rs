//! Reporter configuration and allowlist.

use std::collections::HashSet;
use std::net::Ipv4Addr;

/// Default window size in seconds.
pub const DEFAULT_WINDOW_SEC: u64 = 10;

/// Default SYN rate threshold (SYNs per second).
pub const DEFAULT_SYN_RATE_THRESHOLD: f64 = 100.0;

/// Default success ratio threshold (ACK/SYN).
pub const DEFAULT_SUCCESS_RATIO_THRESHOLD: f64 = 0.1;

/// Default block duration in seconds.
pub const DEFAULT_BLOCK_DURATION_SEC: u64 = 300;

/// Default false-positive safe ratio threshold.
pub const DEFAULT_FP_SAFE_RATIO: f64 = 0.5;

/// Default minimum samples for FP calculation.
pub const DEFAULT_MIN_SAMPLES_FOR_FP: usize = 10;

/// Default number of top offenders to report.
pub const DEFAULT_TOP_OFFENDERS_COUNT: usize = 10;

/// Reporter configuration.
#[derive(Debug, Clone)]
pub struct ReporterConfig {
    pub dst_ports: Vec<u16>,
    pub window_sec: u64,
    pub syn_rate_threshold: f64,
    pub success_ratio_threshold: f64,
    pub block_duration_sec: u64,
    pub fp_safe_ratio: f64,
    pub min_samples_for_fp: usize,
    pub top_offenders_count: usize,
    pub allowlist: Allowlist,
}

impl ReporterConfig {
    /// Create a new config with defaults and required dst_ports.
    pub fn new(dst_ports: Vec<u16>) -> Self {
        Self {
            dst_ports,
            window_sec: DEFAULT_WINDOW_SEC,
            syn_rate_threshold: DEFAULT_SYN_RATE_THRESHOLD,
            success_ratio_threshold: DEFAULT_SUCCESS_RATIO_THRESHOLD,
            block_duration_sec: DEFAULT_BLOCK_DURATION_SEC,
            fp_safe_ratio: DEFAULT_FP_SAFE_RATIO,
            min_samples_for_fp: DEFAULT_MIN_SAMPLES_FOR_FP,
            top_offenders_count: DEFAULT_TOP_OFFENDERS_COUNT,
            allowlist: Allowlist::empty(),
        }
    }

    /// Builder: set window_sec.
    pub fn with_window_sec(mut self, window_sec: u64) -> Self {
        self.window_sec = window_sec;
        self
    }

    /// Builder: set syn_rate_threshold.
    pub fn with_syn_rate_threshold(mut self, threshold: f64) -> Self {
        self.syn_rate_threshold = threshold;
        self
    }

    /// Builder: set success_ratio_threshold.
    pub fn with_success_ratio_threshold(mut self, threshold: f64) -> Self {
        self.success_ratio_threshold = threshold;
        self
    }

    /// Builder: set block_duration_sec.
    pub fn with_block_duration_sec(mut self, duration: u64) -> Self {
        self.block_duration_sec = duration;
        self
    }

    /// Builder: set allowlist.
    pub fn with_allowlist(mut self, allowlist: Allowlist) -> Self {
        self.allowlist = allowlist;
        self
    }

    /// Builder: set fp_safe_ratio.
    pub fn with_fp_safe_ratio(mut self, ratio: f64) -> Self {
        self.fp_safe_ratio = ratio;
        self
    }

    /// Builder: set min_samples_for_fp.
    pub fn with_min_samples_for_fp(mut self, min_samples: usize) -> Self {
        self.min_samples_for_fp = min_samples;
        self
    }
}

/// Allowlist of IPs and CIDRs that are always allowed.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    ips: HashSet<u32>,
    cidrs: Vec<(u32, u8)>, // (network address, prefix length)
}

impl Allowlist {
    /// Create an empty allowlist.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create an allowlist from IP addresses and CIDR blocks.
    pub fn new(ips: Vec<u32>, cidrs: Vec<(u32, u8)>) -> Self {
        Self {
            ips: ips.into_iter().collect(),
            cidrs,
        }
    }

    /// Add a single IP address (as u32).
    pub fn add_ip(&mut self, ip: u32) {
        self.ips.insert(ip);
    }

    /// Add a CIDR block (network address and prefix length).
    pub fn add_cidr(&mut self, network: u32, prefix_len: u8) {
        self.cidrs.push((network, prefix_len));
    }

    /// Parse and add an IP address from string.
    /// Stores MSB-first representation (same as Ipv4Addr and snapshot key_value).
    pub fn add_ip_str(&mut self, ip_str: &str) -> Result<(), AllowlistError> {
        let ip: Ipv4Addr = ip_str.parse().map_err(|_| AllowlistError::InvalidIp(ip_str.to_string()))?;
        self.ips.insert(u32::from(ip)); // MSB-first representation
        Ok(())
    }

    /// Parse and add a CIDR from string (e.g., "10.0.0.0/24").
    /// Stores MSB-first representation (same as Ipv4Addr and snapshot key_value).
    pub fn add_cidr_str(&mut self, cidr_str: &str) -> Result<(), AllowlistError> {
        let parts: Vec<&str> = cidr_str.split('/').collect();
        if parts.len() != 2 {
            return Err(AllowlistError::InvalidCidr(cidr_str.to_string()));
        }

        let ip: Ipv4Addr = parts[0].parse().map_err(|_| AllowlistError::InvalidCidr(cidr_str.to_string()))?;
        let prefix_len: u8 = parts[1].parse().map_err(|_| AllowlistError::InvalidCidr(cidr_str.to_string()))?;

        if prefix_len > 32 {
            return Err(AllowlistError::InvalidCidr(cidr_str.to_string()));
        }

        // MSB-first representation - mask works correctly with standard bit shifting
        let ip_u32 = u32::from(ip);
        let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
        let network = ip_u32 & mask;

        self.cidrs.push((network, prefix_len));
        Ok(())
    }

    /// Check if an IP address is in the allowlist.
    /// Input `ip` uses MSB=first-octet representation (same as snapshot key_value and Ipv4Addr).
    pub fn contains(&self, ip: u32) -> bool {
        // Check exact IP match
        if self.ips.contains(&ip) {
            return true;
        }

        // Check CIDR matches
        for &(network, prefix_len) in &self.cidrs {
            let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
            if (ip & mask) == network {
                return true;
            }
        }

        false
    }

    /// Check if the allowlist is empty.
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.cidrs.is_empty()
    }

    /// Get count of individual IPs.
    pub fn ip_count(&self) -> usize {
        self.ips.len()
    }

    /// Get count of CIDR blocks.
    pub fn cidr_count(&self) -> usize {
        self.cidrs.len()
    }

    /// Get all CIDRs for rules output.
    pub fn cidrs(&self) -> &[(u32, u8)] {
        &self.cidrs
    }

    /// Get all IPs for rules output.
    pub fn ips(&self) -> impl Iterator<Item = u32> + '_ {
        self.ips.iter().copied()
    }
}

/// Errors from allowlist parsing.
#[derive(Debug, thiserror::Error)]
pub enum AllowlistError {
    #[error("invalid IP address: {0}")]
    InvalidIp(String),
    #[error("invalid CIDR notation: {0}")]
    InvalidCidr(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===========================================
    // ReporterConfig Tests
    // ===========================================

    #[test]
    fn test_config_new_defaults() {
        let config = ReporterConfig::new(vec![8080]);
        assert_eq!(config.dst_ports, vec![8080]);
        assert_eq!(config.window_sec, DEFAULT_WINDOW_SEC);
        assert_eq!(config.syn_rate_threshold, DEFAULT_SYN_RATE_THRESHOLD);
        assert_eq!(config.success_ratio_threshold, DEFAULT_SUCCESS_RATIO_THRESHOLD);
        assert_eq!(config.block_duration_sec, DEFAULT_BLOCK_DURATION_SEC);
        assert!(config.allowlist.is_empty());
    }

    #[test]
    fn test_config_builder_window_sec() {
        let config = ReporterConfig::new(vec![8080]).with_window_sec(60);
        assert_eq!(config.window_sec, 60);
    }

    #[test]
    fn test_config_builder_syn_rate() {
        let config = ReporterConfig::new(vec![8080]).with_syn_rate_threshold(50.0);
        assert_eq!(config.syn_rate_threshold, 50.0);
    }

    #[test]
    fn test_config_builder_success_ratio() {
        let config = ReporterConfig::new(vec![8080]).with_success_ratio_threshold(0.2);
        assert_eq!(config.success_ratio_threshold, 0.2);
    }

    #[test]
    fn test_config_builder_chain() {
        let config = ReporterConfig::new(vec![443])
            .with_window_sec(30)
            .with_syn_rate_threshold(200.0)
            .with_success_ratio_threshold(0.05)
            .with_block_duration_sec(600);

        assert_eq!(config.dst_ports, vec![443]);
        assert_eq!(config.window_sec, 30);
        assert_eq!(config.syn_rate_threshold, 200.0);
        assert_eq!(config.success_ratio_threshold, 0.05);
        assert_eq!(config.block_duration_sec, 600);
    }

    // ===========================================
    // Allowlist Tests
    // ===========================================

    #[test]
    fn test_allowlist_empty() {
        let allowlist = Allowlist::empty();
        assert!(allowlist.is_empty());
        assert_eq!(allowlist.ip_count(), 0);
        assert_eq!(allowlist.cidr_count(), 0);
    }

    #[test]
    fn test_allowlist_add_ip() {
        let mut allowlist = Allowlist::empty();
        // All values use MSB=first-octet representation (0x0A000001 = 10.0.0.1)
        allowlist.add_ip(0x0A000001); // 10.0.0.1

        assert!(!allowlist.is_empty());
        assert_eq!(allowlist.ip_count(), 1);
        assert!(allowlist.contains(0x0A000001)); // 10.0.0.1
        assert!(!allowlist.contains(0x0A000002)); // 10.0.0.2
    }

    #[test]
    fn test_allowlist_add_ip_str() {
        let mut allowlist = Allowlist::empty();
        allowlist.add_ip_str("10.0.0.1").unwrap();

        assert!(allowlist.contains(0x0A000001)); // 10.0.0.1
    }

    #[test]
    fn test_allowlist_add_ip_str_invalid() {
        let mut allowlist = Allowlist::empty();
        let result = allowlist.add_ip_str("not-an-ip");
        assert!(result.is_err());
    }

    #[test]
    fn test_allowlist_add_cidr() {
        let mut allowlist = Allowlist::empty();
        // All values use MSB=first-octet representation
        allowlist.add_cidr(0x0A000000, 24); // 10.0.0.0/24

        assert_eq!(allowlist.cidr_count(), 1);
        assert!(allowlist.contains(0x0A000001)); // 10.0.0.1 should match
        assert!(allowlist.contains(0x0A0000FF)); // 10.0.0.255 should match
        assert!(!allowlist.contains(0x0A000100)); // 10.0.1.0 should NOT match
    }

    #[test]
    fn test_allowlist_add_cidr_str() {
        let mut allowlist = Allowlist::empty();
        allowlist.add_cidr_str("192.168.1.0/24").unwrap();

        // 192.168.1.100 = 0xC0A80164
        assert!(allowlist.contains(0xC0A80164));
        // 192.168.2.100 should NOT match
        assert!(!allowlist.contains(0xC0A80264));
    }

    #[test]
    fn test_allowlist_add_cidr_str_normalizes_network() {
        let mut allowlist = Allowlist::empty();
        // 10.0.0.5/24 should normalize to 10.0.0.0/24
        allowlist.add_cidr_str("10.0.0.5/24").unwrap();

        assert!(allowlist.contains(0x0A000001)); // 10.0.0.1 matches
    }

    #[test]
    fn test_allowlist_add_cidr_str_invalid_format() {
        let mut allowlist = Allowlist::empty();
        let result = allowlist.add_cidr_str("10.0.0.0");
        assert!(result.is_err());
    }

    #[test]
    fn test_allowlist_add_cidr_str_invalid_prefix() {
        let mut allowlist = Allowlist::empty();
        let result = allowlist.add_cidr_str("10.0.0.0/33");
        assert!(result.is_err());
    }

    #[test]
    fn test_allowlist_contains_ip_priority() {
        // IP match takes priority, but both should work
        let mut allowlist = Allowlist::empty();
        allowlist.add_ip(0x0A000001); // 10.0.0.1
        allowlist.add_cidr(0x0A000000, 24); // 10.0.0.0/24

        assert!(allowlist.contains(0x0A000001)); // 10.0.0.1 - matches IP
        assert!(allowlist.contains(0x0A000002)); // 10.0.0.2 - matches CIDR
    }

    #[test]
    fn test_allowlist_cidr_slash_8() {
        let mut allowlist = Allowlist::empty();
        allowlist.add_cidr_str("10.0.0.0/8").unwrap();

        assert!(allowlist.contains(0x0A000001)); // 10.0.0.1
        assert!(allowlist.contains(0x0AFFFFFF)); // 10.255.255.255
        assert!(!allowlist.contains(0x0B000001)); // 11.0.0.1
    }

    #[test]
    fn test_allowlist_cidr_slash_32() {
        let mut allowlist = Allowlist::empty();
        allowlist.add_cidr_str("10.0.0.1/32").unwrap();

        assert!(allowlist.contains(0x0A000001)); // 10.0.0.1
        assert!(!allowlist.contains(0x0A000002)); // 10.0.0.2
    }

    #[test]
    fn test_allowlist_cidr_slash_0() {
        let mut allowlist = Allowlist::empty();
        allowlist.add_cidr_str("0.0.0.0/0").unwrap();

        // /0 matches everything
        assert!(allowlist.contains(0x0A000001)); // 10.0.0.1
        assert!(allowlist.contains(0xFFFFFFFF)); // 255.255.255.255
    }

    #[test]
    fn test_allowlist_new_constructor() {
        // All values use MSB=first-octet representation
        let allowlist = Allowlist::new(
            vec![0x0A000001, 0x0A000002], // 10.0.0.1, 10.0.0.2
            vec![(0xC0A80000, 24)], // 192.168.0.0/24
        );

        assert_eq!(allowlist.ip_count(), 2);
        assert_eq!(allowlist.cidr_count(), 1);
        assert!(allowlist.contains(0x0A000001)); // 10.0.0.1
        assert!(allowlist.contains(0xC0A80064)); // 192.168.0.100
    }

    // ===========================================
    // Byte-Order Verification Tests
    // These tests ensure allowlist matching works correctly with MSB-first representation.
    // If bytes were accidentally swapped, these tests would fail.
    // ===========================================

    #[test]
    fn test_allowlist_string_parsing_uses_correct_byte_order() {
        let mut allowlist = Allowlist::empty();
        allowlist.add_ip_str("10.0.0.1").unwrap();

        // Must match 0x0A000001, NOT 0x0100000A
        assert!(
            allowlist.contains(0x0A000001),
            "Allowlist '10.0.0.1' must match key 0x0A000001"
        );
        assert!(
            !allowlist.contains(0x0100000A),
            "Allowlist '10.0.0.1' must NOT match swapped key 0x0100000A"
        );
    }

    #[test]
    fn test_allowlist_cidr_uses_correct_byte_order() {
        let mut allowlist = Allowlist::empty();
        allowlist.add_cidr_str("10.0.0.0/24").unwrap();

        // 10.0.0.1 (0x0A000001) must match
        assert!(
            allowlist.contains(0x0A000001),
            "CIDR 10.0.0.0/24 must match 0x0A000001 (10.0.0.1)"
        );

        // 10.0.0.255 (0x0A0000FF) must match
        assert!(
            allowlist.contains(0x0A0000FF),
            "CIDR 10.0.0.0/24 must match 0x0A0000FF (10.0.0.255)"
        );

        // Swapped values must NOT match
        assert!(
            !allowlist.contains(0x0100000A),
            "CIDR must NOT match swapped 0x0100000A"
        );
    }
}
