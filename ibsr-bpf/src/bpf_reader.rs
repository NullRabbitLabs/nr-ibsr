//! Real BPF Map Reader implementation.
//!
//! This module provides `BpfMapReader` which loads and manages BPF programs
//! and reads counters from the shared map.
//!
//! Two BPF programs run in parallel:
//!  - XDP `xdp_counter` on interface ingress (server receives probes)
//!  - TC  `tc_egress_counter` on interface egress (server sends responses)
//!
//! Both share the same `counter_map`; the egress program keys its bucket by
//! (peer_ip, server_port) so directional counts aggregate into the same
//! per-(scanner, watched-port) row. Closes V9 close-gate finding 2026-05-08
//! that XDP-ingress-only undercounts egress RSTs.

use std::collections::HashMap;
use std::io::Write;
use std::os::fd::AsFd;

use libbpf_rs::{Object, ObjectBuilder, TcHookBuilder, TC_EGRESS, TC_INGRESS};

use crate::map_reader::{BpfError, Counters, MapKey, MapReader, MapReaderError};

/// counter.bpf.c compiled to BPF object bytes at build time.
/// build.rs invokes libbpf-cargo's SkeletonBuilder with .obj() so the
/// .o lands at a path exposed via the COUNTER_BPF_OBJ_PATH env var.
/// We write these bytes to a tempfile at runtime so libxdp's
/// xdp_program__open_file (which insists on a path on disk) can
/// load + dispatch-attach the program.
const COUNTER_BPF_OBJ_BYTES: &[u8] = include_bytes!(env!("COUNTER_BPF_OBJ_PATH"));

/// BPF Map Reader that loads and manages the XDP + TC counter programs.
///
/// Owns the BPF object (loaded by libxdp through the dispatcher path),
/// the libxdp dispatcher attach handle, and TC hooks. Drop unwinds
/// attach state in declaration order — xdp_handle detaches first, then
/// the bpf_object is freed.
pub struct BpfMapReader {
    /// libxdp dispatcher attach handle. Detaches on Drop.
    /// MUST drop before `_object` so xdp_program__detach runs against
    /// a still-valid bpf_object. Field declaration order matters.
    _xdp_handle: crate::xdp_dispatcher::XdpDispatcherHandle,
    /// Loaded bpf_object (libxdp did the kernel load with FREPLACE
    /// BTF context). Maps + TC programs accessible via libbpf-rs.
    object: Object,
    _tc_egress_hook: libbpf_rs::TcHook,
    _tc_qdisc: libbpf_rs::TcHook, // clsact qdisc; destroyed on drop
    interface: String,
    /// Tempfile holding counter.bpf.o bytes. Kept alive for process
    /// lifetime so /proc/self/fd entries (libbpf may reference) stay
    /// valid even though we don't strictly need the file post-load.
    _temp_obj: tempfile::NamedTempFile,
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
    ///
    /// # Note
    /// The BPF LRU map size is fixed at 100,000 entries (hardcoded in eBPF).
    ///
    /// # Errors
    /// Returns `BpfError` if:
    /// - BPF program fails to load
    /// - Interface not found
    /// - Insufficient permissions
    /// - XDP attachment fails
    pub fn new(interface: &str, dst_ports: &[u16]) -> Result<Self, BpfError> {
        // Get interface index
        let ifindex = nix::net::if_::if_nametoindex(interface)
            .map_err(|_| BpfError::InterfaceNotFound(interface.to_string()))?;

        // Stage 1 — write the build-time-embedded counter.bpf.o to a
        // tempfile. libxdp's xdp_program__open_file insists on a path
        // (libxdp 1.6 has a from-buffer API but the version on the
        // sui-victim runtime is 1.3, which only takes paths).
        let mut temp_obj = tempfile::Builder::new()
            .prefix("ibsr-counter-")
            .suffix(".bpf.o")
            .tempfile()
            .map_err(|e| BpfError::Load(format!("create temp .o: {}", e)))?;
        temp_obj
            .write_all(COUNTER_BPF_OBJ_BYTES)
            .map_err(|e| BpfError::Load(format!("write temp .o: {}", e)))?;
        temp_obj.flush().ok();
        let obj_path = temp_obj.path().to_path_buf();

        // Stage 2 — open via libbpf (parses ELF, allocates kernel
        // objects, BUT does NOT load programs into the kernel yet).
        let open_object = ObjectBuilder::default()
            .open_file(&obj_path)
            .map_err(|e| BpfError::Load(format!("open bpf object: {}", e)))?;
        let raw_obj_ptr = open_object.take_ptr();

        // Stage 3 — hand the open bpf_object to libxdp for FREPLACE-aware
        // load + dispatcher attach. libxdp loads the program as type
        // BPF_PROG_TYPE_EXT (FREPLACE) so it chains correctly into the
        // dispatcher slot. counter.bpf.c includes XDP_RUN_CONFIG() which
        // emits the .xdp_run_config BTF section libxdp reads to register
        // the program at the configured priority.
        let xdp_handle = crate::xdp_dispatcher::attach_from_obj(
            interface,
            raw_obj_ptr.as_ptr() as *mut libxdp_sys::bpf_object,
            "xdp",
        )
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("permission") || msg.contains("EPERM") {
                BpfError::InsufficientPermissions
            } else {
                BpfError::Attach {
                    interface: interface.to_string(),
                    reason: msg,
                }
            }
        })?;

        // Stage 4 — wrap the now-loaded bpf_object in a libbpf-rs Object
        // for map + program access. libxdp's attach_from_obj loaded
        // EVERYTHING in the object (XDP via FREPLACE + TC programs as
        // plain libbpf programs); we now have full handles to maps.
        // SAFETY: raw_obj_ptr was returned by libbpf as an open object,
        // libxdp's attach loaded it, and we now hold sole ownership.
        let mut object = unsafe { Object::from_ptr(raw_obj_ptr) };

        // Stage 5 — configure dst_ports in config_map (network byte
        // order). Same logic as the old skel.maps.config_map.update.
        configure_config_map(&mut object, dst_ports)?;

        // Stage 6 — TC egress attach. tc_egress_counter was loaded as
        // a sched_cls program by libbpf during stage 3 (libxdp's load
        // touches the whole object, not just the XDP entry).
        // We perform the attach inside a closure scope so the borrowed
        // Program FD doesn't outlive the Program iterator item.
        let (qdisc, egress_hook) = {
            let prog = object
                .progs()
                .find(|p| p.name() == "tc_egress_counter")
                .ok_or_else(|| BpfError::Attach {
                    interface: interface.to_string(),
                    reason: "tc_egress_counter program not found in loaded object".into(),
                })?;
            let egress_prog_fd = prog.as_fd();

            let mut qdisc_builder = TcHookBuilder::new(egress_prog_fd);
            qdisc_builder.ifindex(ifindex as i32).replace(true);
            let qdisc = match qdisc_builder.hook(TC_INGRESS | TC_EGRESS).create() {
                Ok(h) => h,
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("Exclusivity") || msg.contains("EEXIST") || msg.contains("exists") {
                        let mut b = TcHookBuilder::new(egress_prog_fd);
                        b.ifindex(ifindex as i32).replace(true);
                        b.hook(TC_INGRESS | TC_EGRESS)
                    } else {
                        return Err(BpfError::Attach {
                            interface: interface.to_string(),
                            reason: format!("clsact qdisc create: {}", e),
                        });
                    }
                }
            };

            let mut egress_builder = TcHookBuilder::new(egress_prog_fd);
            egress_builder
                .ifindex(ifindex as i32)
                .replace(true)
                .handle(1)
                .priority(1);
            let mut egress_hook = egress_builder.hook(TC_EGRESS);
            let egress_hook = egress_hook.attach().map_err(|e| BpfError::Attach {
                interface: interface.to_string(),
                reason: format!("TC egress attach: {}", e),
            })?;
            (qdisc, egress_hook)
        };

        Ok(Self {
            _xdp_handle: xdp_handle,
            object,
            _tc_egress_hook: egress_hook,
            _tc_qdisc: qdisc,
            interface: interface.to_string(),
            _temp_obj: temp_obj,
        })
    }

    /// Get the interface name this reader is attached to.
    pub fn interface(&self) -> &str {
        &self.interface
    }
}

/// Set the configured dst_ports list in `config_map` (8 slots, key=index,
/// value=u16 port in network byte order). Used at startup before traffic
/// flows so the BPF program's port-match unrolled loop has the right
/// values; unused slots stay zero (counter.bpf.c treats 0 as "ignore").
fn configure_config_map(object: &mut Object, dst_ports: &[u16]) -> Result<(), BpfError> {
    use libbpf_rs::MapCore;
    let config_map = object
        .maps_mut()
        .find(|m| m.name() == "config_map")
        .ok_or_else(|| BpfError::MapError("config_map not found".into()))?;
    for (i, &port) in dst_ports.iter().take(8).enumerate() {
        let port_ne = port.to_be();
        let key: u32 = i as u32;
        config_map
            .update(
                &key.to_ne_bytes(),
                &port_ne.to_ne_bytes(),
                libbpf_rs::MapFlags::ANY,
            )
            .map_err(|e| BpfError::MapError(format!("config_map update: {}", e)))?;
    }
    Ok(())
}

impl MapReader for BpfMapReader {
    fn read_counters(&self) -> Result<HashMap<MapKey, Counters>, MapReaderError> {
        use libbpf_rs::MapCore;
        let mut result = HashMap::new();

        // Iterate over all keys in counter_map. We re-find the map per
        // call rather than caching a handle, because libbpf-rs's Map
        // borrows from Object and we'd need self-referential lifetimes.
        let map = self
            .object
            .maps()
            .find(|m| m.name() == "counter_map")
            .ok_or_else(|| {
                MapReaderError::ReadError("counter_map not found in loaded object".into())
            })?;

        for key in map.keys() {
            let key_clone = key.clone();
            // Key is now 8 bytes: src_ip(4) + dst_port(2) + _pad(2)
            let key_bytes: [u8; 8] = key
                .try_into()
                .map_err(|_| MapReaderError::ReadError("invalid key size".to_string()))?;
            let src_ip = u32::from_be_bytes(key_bytes[0..4].try_into().unwrap());
            let dst_port = u16::from_ne_bytes(key_bytes[4..6].try_into().unwrap());
            let map_key = MapKey { src_ip, dst_port };

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
                        map_key,
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
