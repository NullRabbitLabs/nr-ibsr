//! Phase 5 — privacy / scrubbing pipeline for record-incident.
//!
//! Per docs/CF-INCIDENT-RECORDING-DESIGN-V1.md and the plan: BPF emits
//! raw packet bytes; userspace optionally:
//!   1. truncates payload (snaplen 256 — already done in BPF).
//!   2. hashes client-side IPv4 address with a per-customer salt.
//!   3. drops packets where both endpoints lie within a configured
//!      "internal" subnet (so service-mesh traffic between operator-
//!      controlled hosts isn't recorded).
//!
//! All scrubbing is **pure** — bytes-in, bytes-out (or "drop"). The
//! production loop applies it after decoding the BPF event but before
//! handing to the pcap sink.
//!
//! Limitations (v1):
//! - IPv4 only. IPv6 packets pass through unscrubbed.
//! - The IP-header and TCP/UDP checksums are NOT recomputed after
//!   src/dst rewrite. tcpdump / Wireshark will flag "checksum
//!   incorrect" on hashed IPs but otherwise parse fine. Operators
//!   running automated parsers should be aware.
//! - Hash function is FNV-1a-64 keyed with the salt — fast,
//!   deterministic, NOT cryptographic. Sufficient for "different
//!   customer / different salt → uncorrelatable IPs"; not sufficient
//!   for adversarial reversal (small input space; rainbow-table-able
//!   if the salt leaks).

use std::net::Ipv4Addr;

use ibsr_bpf::fnv1a64;
use thiserror::Error;

/// Operator-supplied scrubbing configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScrubConfig {
    /// Salt for IPv4 hashing. `None` = no IP hashing.
    pub ip_salt: Option<u64>,
    /// Internal subnet (network + prefix). When set, packets where
    /// BOTH src and dst lie inside the subnet are dropped from the
    /// pcap output.
    pub internal_subnet: Option<Ipv4Subnet>,
}

/// Parse error for the CLI flags.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScrubParseError {
    #[error("--scrub-ip-salt must be 16 hex chars (u64), got {0:?}")]
    InvalidIpSalt(String),

    #[error("--scrub-internal-subnet must be A.B.C.D/N, got {0:?}")]
    InvalidSubnet(String),

    #[error("subnet prefix must be 0..=32, got {0}")]
    InvalidPrefix(u8),
}

/// Parse a 16-hex-char salt into u64. Pure function.
pub fn parse_ip_salt(s: &str) -> Result<u64, ScrubParseError> {
    if s.len() != 16 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ScrubParseError::InvalidIpSalt(s.to_string()));
    }
    u64::from_str_radix(s, 16).map_err(|_| ScrubParseError::InvalidIpSalt(s.to_string()))
}

/// IPv4 subnet (network + prefix length 0..=32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Subnet {
    pub network: u32,
    pub prefix: u8,
}

impl Ipv4Subnet {
    /// Check if `ip` (network byte order = big-endian u32, host-form)
    /// is within the subnet. Pure function.
    pub fn contains(&self, ip: u32) -> bool {
        if self.prefix == 0 {
            return true;
        }
        if self.prefix >= 32 {
            return ip == self.network;
        }
        let mask: u32 = !0u32 << (32 - self.prefix);
        (ip & mask) == (self.network & mask)
    }
}

/// Parse an A.B.C.D/N CIDR string.
pub fn parse_subnet(s: &str) -> Result<Ipv4Subnet, ScrubParseError> {
    let (addr_part, prefix_part) = s
        .split_once('/')
        .ok_or_else(|| ScrubParseError::InvalidSubnet(s.to_string()))?;
    let addr: Ipv4Addr = addr_part
        .parse()
        .map_err(|_| ScrubParseError::InvalidSubnet(s.to_string()))?;
    let prefix: u8 = prefix_part
        .parse()
        .map_err(|_| ScrubParseError::InvalidSubnet(s.to_string()))?;
    if prefix > 32 {
        return Err(ScrubParseError::InvalidPrefix(prefix));
    }
    Ok(Ipv4Subnet {
        network: u32::from(addr),
        prefix,
    })
}

/// Hash an IPv4 address with the per-customer salt. Pure function.
///
/// Uses FNV-1a 64 over `salt || ip` and takes the lower 32 bits as
/// the hashed-IP. Same input → same output (so flow analysis still
/// works on hashed addresses); different salts produce uncorrelated
/// outputs.
pub fn hash_ipv4(ip: u32, salt: u64) -> u32 {
    let mut buf = [0u8; 12];
    buf[0..8].copy_from_slice(&salt.to_be_bytes());
    buf[8..12].copy_from_slice(&ip.to_be_bytes());
    fnv1a64(&buf) as u32
}

/// Result of `apply_scrub` — either the (possibly-modified) packet
/// bytes to write, or `Drop` if the packet should be excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScrubOutcome {
    /// Pass the packet through (possibly with src/dst IP hashed).
    Pass(Vec<u8>),
    /// Drop the packet — both endpoints lie within the internal
    /// subnet.
    Drop,
}

/// Apply scrubbing to a captured packet.
///
/// Layout assumption: snaplen-256 Ethernet frame. We sniff the
/// ethertype at offset 12; only IPv4 (0x0800) is scrubbed. Anything
/// else passes through unchanged.
///
/// Pure function — no I/O.
pub fn apply_scrub(pkt: &[u8], cfg: &ScrubConfig) -> ScrubOutcome {
    // Ethernet header is 14 bytes. Need at least L2 + L3 (20 bytes
    // for IPv4) to do anything meaningful.
    if pkt.len() < 14 + 20 {
        return ScrubOutcome::Pass(pkt.to_vec());
    }

    // Ethertype at offset 12..14.
    let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
    if ethertype != 0x0800 {
        return ScrubOutcome::Pass(pkt.to_vec());
    }

    // IPv4 src at 26..30, dst at 30..34. Both u32 in network byte
    // order; we read them as host-u32 (BE on the wire).
    let src_ip = u32::from_be_bytes([pkt[26], pkt[27], pkt[28], pkt[29]]);
    let dst_ip = u32::from_be_bytes([pkt[30], pkt[31], pkt[32], pkt[33]]);

    // Drop check: both endpoints inside the configured internal subnet.
    if let Some(subnet) = cfg.internal_subnet {
        if subnet.contains(src_ip) && subnet.contains(dst_ip) {
            return ScrubOutcome::Drop;
        }
    }

    // IP hashing.
    if let Some(salt) = cfg.ip_salt {
        let mut out = pkt.to_vec();
        let new_src = hash_ipv4(src_ip, salt);
        let new_dst = hash_ipv4(dst_ip, salt);
        out[26..30].copy_from_slice(&new_src.to_be_bytes());
        out[30..34].copy_from_slice(&new_dst.to_be_bytes());
        return ScrubOutcome::Pass(out);
    }

    ScrubOutcome::Pass(pkt.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ipv4_eth_pkt(src: u32, dst: u32) -> Vec<u8> {
        // 14-byte Ethernet header (zeroed dst+src MAC, ethertype 0x0800),
        // 20-byte IPv4 header (only src/dst IPs matter for the test).
        let mut pkt = vec![0u8; 14 + 20 + 20]; // L2 + IP + room for TCP
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        // IP header version=4, IHL=5 → byte 14 = 0x45.
        pkt[14] = 0x45;
        // src + dst at offsets 26..30 and 30..34.
        pkt[26..30].copy_from_slice(&src.to_be_bytes());
        pkt[30..34].copy_from_slice(&dst.to_be_bytes());
        pkt
    }

    // ===========================================
    // parse_ip_salt
    // ===========================================

    #[test]
    fn salt_parses_valid_16_hex_chars() {
        let salt = parse_ip_salt("DEADBEEFCAFEBABE").expect("ok");
        assert_eq!(salt, 0xDEADBEEFCAFEBABEu64);
    }

    #[test]
    fn salt_parses_lowercase_hex() {
        let salt = parse_ip_salt("deadbeefcafebabe").expect("ok");
        assert_eq!(salt, 0xDEADBEEFCAFEBABEu64);
    }

    #[test]
    fn salt_rejects_short_input() {
        assert!(matches!(parse_ip_salt("DEADBEEF"), Err(ScrubParseError::InvalidIpSalt(_))));
    }

    #[test]
    fn salt_rejects_long_input() {
        assert!(matches!(
            parse_ip_salt("DEADBEEFCAFEBABEDEAD"),
            Err(ScrubParseError::InvalidIpSalt(_)),
        ));
    }

    #[test]
    fn salt_rejects_non_hex() {
        assert!(matches!(
            parse_ip_salt("XEADBEEFCAFEBABE"),
            Err(ScrubParseError::InvalidIpSalt(_)),
        ));
    }

    // ===========================================
    // parse_subnet
    // ===========================================

    #[test]
    fn subnet_parses_basic_cidr() {
        let s = parse_subnet("10.0.0.0/8").expect("ok");
        assert_eq!(s.prefix, 8);
        assert_eq!(s.network, u32::from(Ipv4Addr::new(10, 0, 0, 0)));
    }

    #[test]
    fn subnet_parses_host_cidr() {
        let s = parse_subnet("192.168.1.1/32").expect("ok");
        assert_eq!(s.prefix, 32);
    }

    #[test]
    fn subnet_parses_zero_cidr() {
        let s = parse_subnet("0.0.0.0/0").expect("ok");
        assert_eq!(s.prefix, 0);
    }

    #[test]
    fn subnet_rejects_no_slash() {
        assert!(matches!(
            parse_subnet("10.0.0.0"),
            Err(ScrubParseError::InvalidSubnet(_)),
        ));
    }

    #[test]
    fn subnet_rejects_invalid_address() {
        assert!(matches!(
            parse_subnet("not.an.ip/24"),
            Err(ScrubParseError::InvalidSubnet(_)),
        ));
    }

    #[test]
    fn subnet_rejects_prefix_over_32() {
        assert!(matches!(parse_subnet("10.0.0.0/33"), Err(ScrubParseError::InvalidPrefix(33))));
    }

    // ===========================================
    // Ipv4Subnet::contains
    // ===========================================

    #[test]
    fn subnet_contains_inside_address() {
        let s = parse_subnet("10.0.0.0/8").unwrap();
        assert!(s.contains(u32::from(Ipv4Addr::new(10, 1, 2, 3))));
    }

    #[test]
    fn subnet_excludes_outside_address() {
        let s = parse_subnet("10.0.0.0/8").unwrap();
        assert!(!s.contains(u32::from(Ipv4Addr::new(11, 0, 0, 0))));
    }

    #[test]
    fn subnet_zero_prefix_matches_everything() {
        let s = parse_subnet("0.0.0.0/0").unwrap();
        assert!(s.contains(u32::from(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(s.contains(0));
        assert!(s.contains(u32::MAX));
    }

    #[test]
    fn subnet_host_prefix_matches_only_self() {
        let s = parse_subnet("192.168.1.5/32").unwrap();
        let host = u32::from(Ipv4Addr::new(192, 168, 1, 5));
        let neighbor = u32::from(Ipv4Addr::new(192, 168, 1, 6));
        assert!(s.contains(host));
        assert!(!s.contains(neighbor));
    }

    // ===========================================
    // hash_ipv4
    // ===========================================

    #[test]
    fn hash_ipv4_is_deterministic() {
        assert_eq!(hash_ipv4(0x0a000001, 0xDEAD), hash_ipv4(0x0a000001, 0xDEAD));
    }

    #[test]
    fn hash_ipv4_changes_with_salt() {
        assert_ne!(hash_ipv4(0x0a000001, 1), hash_ipv4(0x0a000001, 2));
    }

    #[test]
    fn hash_ipv4_changes_with_ip() {
        assert_ne!(hash_ipv4(0x0a000001, 0xDEAD), hash_ipv4(0x0a000002, 0xDEAD));
    }

    // ===========================================
    // apply_scrub
    // ===========================================

    #[test]
    fn scrub_passes_through_with_no_config() {
        let pkt = build_ipv4_eth_pkt(0x0a000001, 0x0a000002);
        let cfg = ScrubConfig::default();
        match apply_scrub(&pkt, &cfg) {
            ScrubOutcome::Pass(out) => assert_eq!(out, pkt),
            ScrubOutcome::Drop => panic!("default config must pass through"),
        }
    }

    #[test]
    fn scrub_passes_short_packet_unchanged() {
        // Less than L2+L3 — too short to inspect.
        let short = vec![0u8; 20];
        let cfg = ScrubConfig {
            ip_salt: Some(0xDEAD),
            internal_subnet: None,
        };
        match apply_scrub(&short, &cfg) {
            ScrubOutcome::Pass(out) => assert_eq!(out, short),
            ScrubOutcome::Drop => panic!("short packet must pass"),
        }
    }

    #[test]
    fn scrub_passes_non_ipv4_unchanged() {
        let mut pkt = build_ipv4_eth_pkt(0x0a000001, 0x0a000002);
        // Change ethertype to IPv6 (0x86DD) — must not be scrubbed.
        pkt[12] = 0x86;
        pkt[13] = 0xDD;
        let cfg = ScrubConfig {
            ip_salt: Some(0xDEAD),
            internal_subnet: None,
        };
        match apply_scrub(&pkt, &cfg) {
            ScrubOutcome::Pass(out) => {
                // Bytes at IP-position offsets must NOT be hashed.
                assert_eq!(&out[26..34], &pkt[26..34]);
            }
            ScrubOutcome::Drop => panic!("non-ipv4 must not drop"),
        }
    }

    #[test]
    fn scrub_hashes_src_and_dst_ip_when_salt_set() {
        let pkt = build_ipv4_eth_pkt(0x0a000001, 0x0a000002);
        let cfg = ScrubConfig {
            ip_salt: Some(0xDEAD),
            internal_subnet: None,
        };
        match apply_scrub(&pkt, &cfg) {
            ScrubOutcome::Pass(out) => {
                let new_src = u32::from_be_bytes([out[26], out[27], out[28], out[29]]);
                let new_dst = u32::from_be_bytes([out[30], out[31], out[32], out[33]]);
                assert_eq!(new_src, hash_ipv4(0x0a000001, 0xDEAD));
                assert_eq!(new_dst, hash_ipv4(0x0a000002, 0xDEAD));
                assert_ne!(new_src, 0x0a000001, "src must be transformed");
            }
            ScrubOutcome::Drop => panic!("hashing must not drop"),
        }
    }

    #[test]
    fn scrub_hashed_output_preserves_packet_length() {
        let pkt = build_ipv4_eth_pkt(0x0a000001, 0x0a000002);
        let cfg = ScrubConfig {
            ip_salt: Some(0xDEAD),
            internal_subnet: None,
        };
        match apply_scrub(&pkt, &cfg) {
            ScrubOutcome::Pass(out) => assert_eq!(out.len(), pkt.len()),
            ScrubOutcome::Drop => panic!("hashing must not drop"),
        }
    }

    #[test]
    fn scrub_drops_when_both_ips_inside_subnet() {
        let pkt = build_ipv4_eth_pkt(0x0a000001, 0x0a000002); // both 10.0.0.x
        let cfg = ScrubConfig {
            ip_salt: None,
            internal_subnet: Some(parse_subnet("10.0.0.0/8").unwrap()),
        };
        assert_eq!(apply_scrub(&pkt, &cfg), ScrubOutcome::Drop);
    }

    #[test]
    fn scrub_keeps_when_only_one_ip_inside_subnet() {
        // 10.0.0.1 -> 8.8.8.8: only one endpoint in the subnet.
        let pkt = build_ipv4_eth_pkt(0x0a000001, 0x08080808);
        let cfg = ScrubConfig {
            ip_salt: None,
            internal_subnet: Some(parse_subnet("10.0.0.0/8").unwrap()),
        };
        assert!(matches!(apply_scrub(&pkt, &cfg), ScrubOutcome::Pass(_)));
    }

    #[test]
    fn scrub_subnet_check_runs_before_hashing() {
        // Both inside subnet — should drop, not hash. Verifies the
        // ordering: if the subnet check came after hashing, we'd
        // never drop a real internal packet (the hash would put the
        // IPs outside the subnet).
        let pkt = build_ipv4_eth_pkt(0x0a000001, 0x0a000002);
        let cfg = ScrubConfig {
            ip_salt: Some(0xDEAD),
            internal_subnet: Some(parse_subnet("10.0.0.0/8").unwrap()),
        };
        assert_eq!(apply_scrub(&pkt, &cfg), ScrubOutcome::Drop);
    }
}
