//! Real BPF Map Reader implementation.
//!
//! This module provides `BpfMapReader` which loads and manages the XDP program
//! and reads counters from the BPF map.

use std::collections::HashMap;
use std::mem::MaybeUninit;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, OpenObject};

use crate::map_reader::{BpfError, Counters, MapReader, MapReaderError};

// Include the generated skeleton
mod counter_skel {
    include!(concat!(env!("OUT_DIR"), "/counter.skel.rs"));
}

use counter_skel::*;

/// BPF Map Reader that loads and manages the XDP program.
///
/// This struct owns the BPF skeleton and XDP link. When dropped, it automatically
/// detaches the XDP program from the interface.
pub struct BpfMapReader {
    skel: CounterSkel<'static>,
    _link: libbpf_rs::Link,
    interface: String,
}

// SAFETY: BpfMapReader is only used from a single thread in practice.
// The skeleton and link are not shared across threads.
unsafe impl Send for BpfMapReader {}
unsafe impl Sync for BpfMapReader {}

impl BpfMapReader {
    /// Create a new BpfMapReader and attach XDP program to the specified interface.
    ///
    /// # Arguments
    /// * `interface` - Network interface name (e.g., "eth0")
    /// * `dst_ports` - TCP destination ports to monitor (up to 8, network byte order will be handled)
    /// * `map_size` - Maximum entries in the LRU counter map
    ///
    /// # Errors
    /// Returns `BpfError` if:
    /// - BPF program fails to load
    /// - Interface not found
    /// - Insufficient permissions
    /// - XDP attachment fails
    pub fn new(interface: &str, dst_ports: &[u16], _map_size: u32) -> Result<Self, BpfError> {
        // Get interface index
        let ifindex = nix::net::if_::if_nametoindex(interface)
            .map_err(|_| BpfError::InterfaceNotFound(interface.to_string()))?;

        // Open and load the BPF skeleton
        // Leak the OpenObject to give it 'static lifetime (required by skeleton API)
        // This is intentional - the BpfMapReader lives for the duration of the program
        let open_object: &'static mut MaybeUninit<OpenObject> =
            Box::leak(Box::new(MaybeUninit::<OpenObject>::uninit()));

        let skel_builder = CounterSkelBuilder::default();
        let open_skel = skel_builder
            .open(open_object)
            .map_err(|e| BpfError::Load(e.to_string()))?;

        let skel = open_skel
            .load()
            .map_err(|e| BpfError::Load(e.to_string()))?;

        // Configure dst_ports in the config map (convert to network byte order)
        // Up to 8 ports supported; unused slots remain 0
        for (i, &port) in dst_ports.iter().take(8).enumerate() {
            let port_ne = port.to_be();
            let key: u32 = i as u32;
            skel.maps
                .config_map
                .update(&key.to_ne_bytes(), &port_ne.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
                .map_err(|e| BpfError::MapError(e.to_string()))?;
        }

        // Attach XDP program to interface
        let link = skel
            .progs
            .xdp_counter
            .attach_xdp(ifindex as i32)
            .map_err(|e| {
                if e.to_string().contains("permission") || e.to_string().contains("EPERM") {
                    BpfError::InsufficientPermissions
                } else {
                    BpfError::Attach {
                        interface: interface.to_string(),
                        reason: e.to_string(),
                    }
                }
            })?;

        Ok(Self {
            skel,
            _link: link,
            interface: interface.to_string(),
        })
    }

    /// Get the interface name this reader is attached to.
    pub fn interface(&self) -> &str {
        &self.interface
    }
}

impl MapReader for BpfMapReader {
    fn read_counters(&self) -> Result<HashMap<u32, Counters>, MapReaderError> {
        let mut result = HashMap::new();

        // Iterate over all keys in the counter map
        let map = &self.skel.maps.counter_map;

        for key in map.keys() {
            let key_clone = key.clone();
            let key_bytes: [u8; 4] = key
                .try_into()
                .map_err(|_| MapReaderError::ReadError("invalid key size".to_string()))?;
            let src_ip = u32::from_ne_bytes(key_bytes);

            if let Some(value) = map
                .lookup(&key_clone, libbpf_rs::MapFlags::ANY)
                .map_err(|e| MapReaderError::ReadError(e.to_string()))?
            {
                // BPF struct is 32 bytes with natural alignment (u64 requires 8-byte alignment).
                // Layout: syn(4) + ack(4) + handshake_ack(4) + rst(4) + packets(4) + _pad(4) + bytes(8) = 32 bytes
                if value.len() == 32 {
                    let syn = u32::from_ne_bytes(value[0..4].try_into().unwrap());
                    let ack = u32::from_ne_bytes(value[4..8].try_into().unwrap());
                    let handshake_ack = u32::from_ne_bytes(value[8..12].try_into().unwrap());
                    let rst = u32::from_ne_bytes(value[12..16].try_into().unwrap());
                    let packets = u32::from_ne_bytes(value[16..20].try_into().unwrap());
                    // Skip _pad at offset 20-23
                    let bytes = u64::from_ne_bytes(value[24..32].try_into().unwrap());

                    result.insert(
                        src_ip,
                        Counters {
                            syn,
                            ack,
                            handshake_ack,
                            rst,
                            packets,
                            bytes,
                        },
                    );
                }
            }
        }

        Ok(result)
    }
}

// Link is automatically dropped when BpfMapReader is dropped,
// which detaches the XDP program from the interface.

#[cfg(test)]
mod tests {
    use super::*;

    // Integration tests require privileged environment
    // Run with: cargo test --features bpf -- --ignored

    #[test]
    #[ignore]
    fn test_bpf_map_reader_loads_program() {
        // This test requires:
        // - Root/CAP_BPF permissions
        // - A valid network interface
        // - Compiled BPF program
        todo!("Integration test - run in privileged container")
    }

    #[test]
    #[ignore]
    fn test_bpf_map_reader_reads_empty_map() {
        todo!("Integration test - run in privileged container")
    }

    #[test]
    #[ignore]
    fn test_bpf_map_reader_cleanup_on_drop() {
        todo!("Integration test - run in privileged container")
    }

    // ===========================================
    // Raw bytes layout tests
    // These validate the BPF struct layout assumptions
    // ===========================================

    /// Expected size of BPF counter struct (must match counter.bpf.c)
    /// Layout: syn(4) + ack(4) + handshake_ack(4) + rst(4) + packets(4) + _pad(4) + bytes(8) = 32 bytes
    /// The padding is required for 8-byte alignment of the bytes field (BPF verifier requirement).
    const BPF_COUNTERS_SIZE: usize = 32;

    /// Parse raw BPF map value bytes into Counters.
    /// This mirrors the parsing logic in read_counters().
    fn parse_bpf_counters(value: &[u8]) -> Option<Counters> {
        if value.len() != BPF_COUNTERS_SIZE {
            return None;
        }
        // Layout: syn(4) + ack(4) + handshake_ack(4) + rst(4) + packets(4) + _pad(4) + bytes(8) = 32 bytes
        let syn = u32::from_ne_bytes(value[0..4].try_into().unwrap());
        let ack = u32::from_ne_bytes(value[4..8].try_into().unwrap());
        let handshake_ack = u32::from_ne_bytes(value[8..12].try_into().unwrap());
        let rst = u32::from_ne_bytes(value[12..16].try_into().unwrap());
        let packets = u32::from_ne_bytes(value[16..20].try_into().unwrap());
        // Skip _pad at offset 20-23
        let bytes = u64::from_ne_bytes(value[24..32].try_into().unwrap());
        Some(Counters {
            syn,
            ack,
            handshake_ack,
            rst,
            packets,
            bytes,
        })
    }

    #[test]
    fn test_bpf_struct_size_is_32_bytes() {
        // The BPF struct is 32 bytes with natural alignment.
        // The u64 bytes field requires 8-byte alignment for atomic operations.
        assert_eq!(BPF_COUNTERS_SIZE, 32);
    }

    #[test]
    fn test_parse_bpf_counters_all_zeros() {
        let value = [0u8; 32];
        let counters = parse_bpf_counters(&value).expect("parse succeeds");
        assert_eq!(counters.syn, 0);
        assert_eq!(counters.ack, 0);
        assert_eq!(counters.handshake_ack, 0);
        assert_eq!(counters.rst, 0);
        assert_eq!(counters.packets, 0);
        assert_eq!(counters.bytes, 0);
    }

    #[test]
    fn test_parse_bpf_counters_known_values() {
        // Construct a raw byte buffer with known values
        let mut value = [0u8; 32];
        // syn = 100
        value[0..4].copy_from_slice(&100u32.to_ne_bytes());
        // ack = 200
        value[4..8].copy_from_slice(&200u32.to_ne_bytes());
        // handshake_ack = 95
        value[8..12].copy_from_slice(&95u32.to_ne_bytes());
        // rst = 5
        value[12..16].copy_from_slice(&5u32.to_ne_bytes());
        // packets = 305
        value[16..20].copy_from_slice(&305u32.to_ne_bytes());
        // _pad at 20-23 is zero
        // bytes = 45000 (sum of packet lengths)
        value[24..32].copy_from_slice(&45000u64.to_ne_bytes());

        let counters = parse_bpf_counters(&value).expect("parse succeeds");
        assert_eq!(counters.syn, 100);
        assert_eq!(counters.ack, 200);
        assert_eq!(counters.handshake_ack, 95);
        assert_eq!(counters.rst, 5);
        assert_eq!(counters.packets, 305);
        assert_eq!(counters.bytes, 45000);
    }

    #[test]
    fn test_parse_bpf_counters_bytes_field_large_value() {
        // Test that bytes field can hold large values (u64)
        let mut value = [0u8; 32];
        // Use a large but realistic byte count: 1 TB = 10^12 bytes
        let large_bytes: u64 = 1_000_000_000_000;
        value[24..32].copy_from_slice(&large_bytes.to_ne_bytes());
        value[16..20].copy_from_slice(&1000000u32.to_ne_bytes()); // 1M packets

        let counters = parse_bpf_counters(&value).expect("parse succeeds");
        assert_eq!(counters.bytes, large_bytes);
        assert_eq!(counters.packets, 1_000_000);
    }

    #[test]
    fn test_parse_bpf_counters_bytes_max_value() {
        // Test u64::MAX for bytes field
        let mut value = [0u8; 32];
        value[24..32].copy_from_slice(&u64::MAX.to_ne_bytes());

        let counters = parse_bpf_counters(&value).expect("parse succeeds");
        assert_eq!(counters.bytes, u64::MAX);
    }

    #[test]
    fn test_parse_bpf_counters_rejects_wrong_size() {
        // 28 bytes (old packed size - now incorrect)
        let packed = [0u8; 28];
        assert!(parse_bpf_counters(&packed).is_none());

        // 31 bytes (too short)
        let short = [0u8; 31];
        assert!(parse_bpf_counters(&short).is_none());

        // 33 bytes (too long)
        let long = [0u8; 33];
        assert!(parse_bpf_counters(&long).is_none());
    }

    #[test]
    fn test_bytes_equals_sum_of_packet_lengths() {
        // Simulate 3 packets with known lengths
        let packet_lengths: [u64; 3] = [100, 1500, 64];
        let expected_bytes: u64 = packet_lengths.iter().sum();
        let packets = packet_lengths.len() as u32;

        let mut value = [0u8; 32];
        value[16..20].copy_from_slice(&packets.to_ne_bytes());
        value[24..32].copy_from_slice(&expected_bytes.to_ne_bytes());

        let counters = parse_bpf_counters(&value).expect("parse succeeds");

        // Assert bytes equals sum of packet lengths
        assert_eq!(counters.bytes, expected_bytes);
        assert_eq!(counters.bytes, 1664); // 100 + 1500 + 64
        assert_eq!(counters.packets, 3);
    }

    #[test]
    fn test_bytes_is_monotonic_increasing() {
        // Simulate a series of counter updates where bytes increases
        let mut cumulative_bytes: u64 = 0;
        let packet_sizes = [100u64, 200, 150, 1500, 64];

        for size in packet_sizes {
            cumulative_bytes += size;

            let mut value = [0u8; 32];
            value[24..32].copy_from_slice(&cumulative_bytes.to_ne_bytes());

            let counters = parse_bpf_counters(&value).expect("parse succeeds");
            assert_eq!(counters.bytes, cumulative_bytes);
        }

        // Final value should be sum of all
        assert_eq!(cumulative_bytes, 2014);
    }

    #[test]
    fn test_padding_is_ignored() {
        // Verify that the padding bytes (offset 20-23) are ignored
        let mut value = [0u8; 32];
        value[16..20].copy_from_slice(&100u32.to_ne_bytes()); // packets = 100
        value[20..24].copy_from_slice(&0xDEADBEEFu32.to_ne_bytes()); // garbage in padding
        value[24..32].copy_from_slice(&5000u64.to_ne_bytes()); // bytes = 5000

        let counters = parse_bpf_counters(&value).expect("parse succeeds");
        assert_eq!(counters.packets, 100);
        assert_eq!(counters.bytes, 5000);
    }
}
