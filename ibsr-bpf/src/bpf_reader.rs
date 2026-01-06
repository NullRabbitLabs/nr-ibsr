//! Real BPF Map Reader implementation.
//!
//! This module provides `BpfMapReader` which loads and manages the XDP program
//! and reads counters from the BPF map. Only available when the `bpf` feature is enabled.

#![cfg(feature = "bpf")]

use std::collections::HashMap;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::MapCore;

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
pub struct BpfMapReader<'a> {
    skel: CounterSkel<'a>,
    _link: libbpf_rs::Link,
    interface: String,
}

impl<'a> BpfMapReader<'a> {
    /// Create a new BpfMapReader and attach XDP program to the specified interface.
    ///
    /// # Arguments
    /// * `interface` - Network interface name (e.g., "eth0")
    /// * `dst_port` - TCP destination port to monitor (network byte order will be handled)
    /// * `map_size` - Maximum entries in the LRU counter map
    ///
    /// # Errors
    /// Returns `BpfError` if:
    /// - BPF program fails to load
    /// - Interface not found
    /// - Insufficient permissions
    /// - XDP attachment fails
    pub fn new(interface: &str, dst_port: u16, _map_size: u32) -> Result<Self, BpfError> {
        // Get interface index
        let ifindex = nix::net::if_::if_nametoindex(interface)
            .map_err(|_| BpfError::InterfaceNotFound(interface.to_string()))?;

        // Open and load the BPF skeleton
        let skel_builder = CounterSkelBuilder::default();
        let open_skel = skel_builder
            .open()
            .map_err(|e| BpfError::Load(e.to_string()))?;

        let mut skel = open_skel
            .load()
            .map_err(|e| BpfError::Load(e.to_string()))?;

        // Configure dst_port in the config map (convert to network byte order)
        let dst_port_ne = dst_port.to_be();
        let key: u32 = 0;
        skel.maps
            .config_map
            .update(&key.to_ne_bytes(), &dst_port_ne.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
            .map_err(|e| BpfError::MapError(e.to_string()))?;

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

impl MapReader for BpfMapReader<'_> {
    fn read_counters(&self) -> Result<HashMap<u32, Counters>, MapReaderError> {
        let mut result = HashMap::new();

        // Iterate over all keys in the counter map
        let map = &self.skel.maps.counter_map;

        for key in map.keys() {
            let key_bytes: [u8; 4] = key
                .try_into()
                .map_err(|_| MapReaderError::ReadError("invalid key size".to_string()))?;
            let src_ip = u32::from_ne_bytes(key_bytes);

            if let Some(value) = map
                .lookup(&key, libbpf_rs::MapFlags::ANY)
                .map_err(|e| MapReaderError::ReadError(e.to_string()))?
            {
                if value.len() >= 24 {
                    // Parse counter values from raw bytes
                    // Layout: syn(4) + ack(4) + rst(4) + packets(4) + bytes(8) = 24 bytes
                    let syn = u32::from_ne_bytes(value[0..4].try_into().unwrap());
                    let ack = u32::from_ne_bytes(value[4..8].try_into().unwrap());
                    let rst = u32::from_ne_bytes(value[8..12].try_into().unwrap());
                    let packets = u32::from_ne_bytes(value[12..16].try_into().unwrap());
                    let bytes = u64::from_ne_bytes(value[16..24].try_into().unwrap());

                    result.insert(
                        src_ip,
                        Counters {
                            syn,
                            ack,
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
}
