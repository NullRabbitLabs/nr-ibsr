//! Userspace decoder for `record_incident.bpf.c`'s `struct
//! packet_event` ringbuf record.
//!
//! Layout is documented at the top of `src/bpf/record_incident.bpf.c`.
//! This module provides a `#[repr(C)]` Rust mirror plus a safe
//! decoder from the raw byte slice. The decoder validates length,
//! cap_len bound, and direction, and returns a `DecodedPacketEvent`
//! ready for the pcap writer.

use thiserror::Error;

/// BPF-side snaplen. Must match `SNAPLEN_BYTES` in
/// `record_incident.bpf.c`. Pinned by `compile_time_size_check` test.
pub const RECORD_SNAPLEN_BYTES: usize = 256;

/// Total size of the kernel-side `struct packet_event`. Pinned by
/// `compile_time_size_check` test against `RawPacketEvent`.
///
/// Layout (from record_incident.bpf.c):
///   0..8   ts_ns       u64
///   8..12  ifindex     u32
///  12..16  direction   u32
///  16..20  wire_len    u32
///  20..24  cap_len     u32
///  24..280 pkt[256]
pub const EXPECTED_RAW_PACKET_EVENT_SIZE: usize = 24 + RECORD_SNAPLEN_BYTES;

/// Direction marker as emitted by the record-incident BPF program.
pub mod record_direction {
    pub const INGRESS: u32 = 0;
    pub const EGRESS: u32 = 1;
}

/// Mirror of `struct packet_event` from record_incident.bpf.c. The
/// `repr(C)` layout matches exactly — any struct edit must be paired
/// with the offsets test below.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawPacketEvent {
    pub ts_ns: u64,
    pub ifindex: u32,
    pub direction: u32,
    pub wire_len: u32,
    pub cap_len: u32,
    pub pkt: [u8; RECORD_SNAPLEN_BYTES],
}

/// Decoder errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordDecodeError {
    #[error("ringbuf record wrong size: got {got} bytes, expected {expected}")]
    SizeMismatch { got: usize, expected: usize },

    #[error("cap_len {cap} exceeds snaplen {max}")]
    CapLenOverflow { cap: u32, max: usize },

    #[error("cap_len {cap} exceeds wire_len {wire}")]
    CapLenExceedsWire { cap: u32, wire: u32 },

    #[error("unknown direction value {0}")]
    UnknownDirection(u32),
}

/// Parsed event ready for handoff to the pcap writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPacketEvent {
    pub ts_ns: u64,
    pub ifindex: u32,
    pub direction: u32,
    pub wire_len: u32,
    pub cap_len: u32,
    /// `cap_len` bytes of packet header. Length is exactly `cap_len`.
    pub pkt: Vec<u8>,
}

/// Decode a ringbuf record into a `DecodedPacketEvent`.
pub fn decode_packet_event(raw: &[u8]) -> Result<DecodedPacketEvent, RecordDecodeError> {
    if raw.len() != EXPECTED_RAW_PACKET_EVENT_SIZE {
        return Err(RecordDecodeError::SizeMismatch {
            got: raw.len(),
            expected: EXPECTED_RAW_PACKET_EVENT_SIZE,
        });
    }

    // Safe: length is exactly EXPECTED_RAW_PACKET_EVENT_SIZE; layout is
    // repr(C) and matches the BPF-side struct by the pinned offset
    // table. `read_unaligned` handles any ringbuf alignment quirks.
    let raw_ptr = raw.as_ptr() as *const RawPacketEvent;
    let ev: RawPacketEvent = unsafe { std::ptr::read_unaligned(raw_ptr) };

    if (ev.cap_len as usize) > RECORD_SNAPLEN_BYTES {
        return Err(RecordDecodeError::CapLenOverflow {
            cap: ev.cap_len,
            max: RECORD_SNAPLEN_BYTES,
        });
    }
    if ev.cap_len > ev.wire_len {
        return Err(RecordDecodeError::CapLenExceedsWire {
            cap: ev.cap_len,
            wire: ev.wire_len,
        });
    }
    if ev.direction != record_direction::INGRESS && ev.direction != record_direction::EGRESS {
        return Err(RecordDecodeError::UnknownDirection(ev.direction));
    }

    let pkt = ev.pkt[..ev.cap_len as usize].to_vec();

    Ok(DecodedPacketEvent {
        ts_ns: ev.ts_ns,
        ifindex: ev.ifindex,
        direction: ev.direction,
        wire_len: ev.wire_len,
        cap_len: ev.cap_len,
        pkt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn raw_event_size_matches_pinned_value() {
        // Pin: any struct-layout edit on either side trips this before
        // the kernel→userspace decoder breaks at runtime.
        assert_eq!(
            size_of::<RawPacketEvent>(),
            EXPECTED_RAW_PACKET_EVENT_SIZE,
            "RawPacketEvent size drift — check field order vs record_incident.bpf.c",
        );
    }

    #[test]
    fn raw_packet_event_field_offsets_match_pinned_table() {
        let zero: *const RawPacketEvent = std::ptr::null();
        let zero_addr = zero as usize;
        unsafe {
            let off = |p: *const u8| (p as usize).wrapping_sub(zero_addr);
            assert_eq!(off(std::ptr::addr_of!((*zero).ts_ns).cast()), 0);
            assert_eq!(off(std::ptr::addr_of!((*zero).ifindex).cast()), 8);
            assert_eq!(off(std::ptr::addr_of!((*zero).direction).cast()), 12);
            assert_eq!(off(std::ptr::addr_of!((*zero).wire_len).cast()), 16);
            assert_eq!(off(std::ptr::addr_of!((*zero).cap_len).cast()), 20);
            assert_eq!(off(std::ptr::addr_of!((*zero).pkt).cast()), 24);
        }
    }

    fn build_raw(direction: u32, wire_len: u32, cap_len: u32, fill: u8) -> Vec<u8> {
        let mut ev = RawPacketEvent {
            ts_ns: 1_700_000_000_000_000_000,
            ifindex: 1,
            direction,
            wire_len,
            cap_len,
            pkt: [0u8; RECORD_SNAPLEN_BYTES],
        };
        for i in 0..(cap_len as usize).min(RECORD_SNAPLEN_BYTES) {
            ev.pkt[i] = fill;
        }
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&ev as *const RawPacketEvent) as *const u8,
                size_of::<RawPacketEvent>(),
            )
        };
        bytes.to_vec()
    }

    #[test]
    fn decode_round_trip_ingress() {
        let raw = build_raw(record_direction::INGRESS, 100, 50, 0xab);
        let ev = decode_packet_event(&raw).expect("decode");
        assert_eq!(ev.direction, record_direction::INGRESS);
        assert_eq!(ev.ts_ns, 1_700_000_000_000_000_000);
        assert_eq!(ev.ifindex, 1);
        assert_eq!(ev.wire_len, 100);
        assert_eq!(ev.cap_len, 50);
        assert_eq!(ev.pkt.len(), 50);
        assert!(ev.pkt.iter().all(|b| *b == 0xab));
    }

    #[test]
    fn decode_round_trip_egress() {
        let raw = build_raw(record_direction::EGRESS, 256, 256, 0xcd);
        let ev = decode_packet_event(&raw).expect("decode");
        assert_eq!(ev.direction, record_direction::EGRESS);
        assert_eq!(ev.cap_len, 256);
        assert_eq!(ev.pkt.len(), 256);
    }

    #[test]
    fn decode_zero_cap_len_ok() {
        // Zero-cap events shouldn't reach userspace (BPF skips empty),
        // but the decoder must handle them gracefully.
        let raw = build_raw(record_direction::INGRESS, 0, 0, 0);
        let ev = decode_packet_event(&raw).expect("decode");
        assert_eq!(ev.cap_len, 0);
        assert!(ev.pkt.is_empty());
    }

    #[test]
    fn decode_size_mismatch_rejects_short() {
        let raw = vec![0u8; 100];
        match decode_packet_event(&raw) {
            Err(RecordDecodeError::SizeMismatch { got: 100, expected }) => {
                assert_eq!(expected, EXPECTED_RAW_PACKET_EVENT_SIZE);
            }
            other => panic!("expected SizeMismatch, got {:?}", other),
        }
    }

    #[test]
    fn decode_size_mismatch_rejects_long() {
        let raw = vec![0u8; 1024];
        assert!(matches!(
            decode_packet_event(&raw),
            Err(RecordDecodeError::SizeMismatch { .. }),
        ));
    }

    #[test]
    fn decode_cap_overflow_rejects() {
        let mut raw = build_raw(record_direction::INGRESS, 1500, 100, 0);
        // Write cap_len = SNAPLEN+1 at offset 20.
        let bad: u32 = (RECORD_SNAPLEN_BYTES as u32) + 1;
        raw[20..24].copy_from_slice(&bad.to_le_bytes());
        // Wire_len needs to be >= cap_len for that check to pass first.
        let big_wire: u32 = bad + 100;
        raw[16..20].copy_from_slice(&big_wire.to_le_bytes());
        match decode_packet_event(&raw) {
            Err(RecordDecodeError::CapLenOverflow { cap, max }) => {
                assert_eq!(cap, bad);
                assert_eq!(max, RECORD_SNAPLEN_BYTES);
            }
            other => panic!("expected CapLenOverflow, got {:?}", other),
        }
    }

    #[test]
    fn decode_cap_exceeds_wire_rejects() {
        let mut raw = build_raw(record_direction::INGRESS, 50, 100, 0);
        // wire_len=50, cap_len=100 — invalid.
        raw[16..20].copy_from_slice(&50u32.to_le_bytes());
        raw[20..24].copy_from_slice(&100u32.to_le_bytes());
        match decode_packet_event(&raw) {
            Err(RecordDecodeError::CapLenExceedsWire { cap: 100, wire: 50 }) => {}
            other => panic!("expected CapLenExceedsWire, got {:?}", other),
        }
    }

    #[test]
    fn decode_unknown_direction_rejects() {
        let raw = build_raw(99, 100, 50, 0);
        match decode_packet_event(&raw) {
            Err(RecordDecodeError::UnknownDirection(99)) => {}
            other => panic!("expected UnknownDirection(99), got {:?}", other),
        }
    }
}
