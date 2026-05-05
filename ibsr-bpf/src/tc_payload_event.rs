//! Userspace decoder for `tc_payload.bpf.c`'s `struct payload_event`
//! ringbuf record.
//!
//! The kernel-side struct layout is documented at the top of
//! `src/bpf/tc_payload.bpf.c`. This module provides a `#[repr(C)]`
//! Rust mirror plus a safe decoder from a raw byte slice into the
//! userspace `payload::PayloadEvent` type used by the reassembler.

use thiserror::Error;

/// BPF-side payload-sample size. Must match `PAYLOAD_SAMPLE_BYTES` in
/// `tc_payload.bpf.c`. Pinned by `compile_time_size_check` test.
pub const PAYLOAD_SAMPLE_BYTES: usize = 1024;

/// Total size of the kernel-side `struct payload_event`. Pinned by
/// `compile_time_size_check` test against the Rust `RawPayloadEvent`.
pub const EXPECTED_RAW_EVENT_SIZE: usize = 1064;

/// BPF-side `struct flow_id` mirror. Network byte order for IPs +
/// ports (no conversion in BPF; userspace converts to display).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawFlowId {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

/// BPF-side `struct payload_event` mirror. Layout is exact:
/// `repr(C)` enforces field order, the explicit `_pad0` enforces
/// 8-byte alignment of `ts_ns` (matches the C struct's explicit
/// padding).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawPayloadEvent {
    pub flow: RawFlowId,
    pub direction: u32,
    pub tcp_seq: u32,
    pub _pad0: u32,
    pub ts_ns: u64,
    pub payload_len: u32,
    pub sample_len: u32,
    pub payload: [u8; PAYLOAD_SAMPLE_BYTES],
}

/// Direction marker as emitted by the BPF program. Mirrors the
/// `DIR_INGRESS` / `DIR_EGRESS` defines in `tc_payload.bpf.c`.
pub mod direction {
    pub const INGRESS: u32 = 0;
    pub const EGRESS: u32 = 1;
}

/// Decoder errors.
#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("ringbuf record too small: got {got} bytes, expected {expected}")]
    Truncated { got: usize, expected: usize },

    #[error("sample_len {sample} exceeds PAYLOAD_SAMPLE_BYTES {max}")]
    SampleLenOverflow { sample: u32, max: usize },

    #[error("unknown direction value {0}")]
    UnknownDirection(u32),
}

/// Parsed event ready for handoff to the userspace reassembler. Bytes
/// are converted to a `Vec<u8>` here (allocation per event); a
/// future zero-copy variant is possible if profiling shows allocator
/// pressure on the consumer side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedEvent {
    pub flow: RawFlowId,
    pub direction: u32,
    pub tcp_seq: u32,
    pub ts_ns: u64,
    pub payload_len: u32,
    pub sample_len: u32,
    pub payload: Vec<u8>,
}

/// Decode a ringbuf record. The slice must be exactly
/// `EXPECTED_RAW_EVENT_SIZE` bytes (the BPF program always reserves
/// `sizeof(struct payload_event)` per event).
pub fn decode_event(raw: &[u8]) -> Result<DecodedEvent, DecodeError> {
    if raw.len() != EXPECTED_RAW_EVENT_SIZE {
        return Err(DecodeError::Truncated {
            got: raw.len(),
            expected: EXPECTED_RAW_EVENT_SIZE,
        });
    }
    // Safe to interpret: we've checked the length is exactly
    // EXPECTED_RAW_EVENT_SIZE, the layout is repr(C) on both sides
    // and matches by the pinned offset table, and we read fields
    // through `read_unaligned` to handle any remaining alignment
    // sensitivity (the Vec<u8> inside the kernel ringbuf is not
    // guaranteed to be aligned to 8 bytes).
    let raw_ptr = raw.as_ptr() as *const RawPayloadEvent;
    let ev: RawPayloadEvent = unsafe { std::ptr::read_unaligned(raw_ptr) };

    if (ev.sample_len as usize) > PAYLOAD_SAMPLE_BYTES {
        return Err(DecodeError::SampleLenOverflow {
            sample: ev.sample_len,
            max: PAYLOAD_SAMPLE_BYTES,
        });
    }
    if ev.direction != direction::INGRESS && ev.direction != direction::EGRESS {
        return Err(DecodeError::UnknownDirection(ev.direction));
    }

    let payload = ev.payload[..ev.sample_len as usize].to_vec();

    Ok(DecodedEvent {
        flow: ev.flow,
        direction: ev.direction,
        tcp_seq: ev.tcp_seq,
        ts_ns: ev.ts_ns,
        payload_len: ev.payload_len,
        sample_len: ev.sample_len,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn raw_event_size_matches_bpf_pinned_value() {
        // Pin: Rust struct size must match the C struct size declared
        // at the top of tc_payload.bpf.c. If a future edit alters
        // either struct's layout (adding/removing/reordering fields,
        // changing the payload sample size), this test trips before
        // the kernel→userspace decoder breaks.
        assert_eq!(
            size_of::<RawPayloadEvent>(),
            EXPECTED_RAW_EVENT_SIZE,
            "RawPayloadEvent size drift — check pad/alignment vs tc_payload.bpf.c",
        );
    }

    #[test]
    fn flow_id_size_is_12_bytes() {
        assert_eq!(size_of::<RawFlowId>(), 12);
    }

    #[test]
    fn raw_payload_event_field_offsets_match_pinned_table() {
        // Pin the offsets named in tc_payload.bpf.c's offset table.
        // memoffset would simplify this but adding a dep for layout
        // pinning is overkill; manual checks via the Rust pointer
        // arithmetic are sufficient.
        let zero: *const RawPayloadEvent = std::ptr::null();
        let zero_addr = zero as usize;
        unsafe {
            let off = |p: *const u8| (p as usize).wrapping_sub(zero_addr);
            assert_eq!(off(std::ptr::addr_of!((*zero).flow.src_ip).cast()), 0);
            assert_eq!(off(std::ptr::addr_of!((*zero).flow.dst_ip).cast()), 4);
            assert_eq!(off(std::ptr::addr_of!((*zero).flow.src_port).cast()), 8);
            assert_eq!(off(std::ptr::addr_of!((*zero).flow.dst_port).cast()), 10);
            assert_eq!(off(std::ptr::addr_of!((*zero).direction).cast()), 12);
            assert_eq!(off(std::ptr::addr_of!((*zero).tcp_seq).cast()), 16);
            assert_eq!(off(std::ptr::addr_of!((*zero)._pad0).cast()), 20);
            assert_eq!(off(std::ptr::addr_of!((*zero).ts_ns).cast()), 24);
            assert_eq!(off(std::ptr::addr_of!((*zero).payload_len).cast()), 32);
            assert_eq!(off(std::ptr::addr_of!((*zero).sample_len).cast()), 36);
            assert_eq!(off(std::ptr::addr_of!((*zero).payload).cast()), 40);
        }
    }

    fn build_raw(direction: u32, sample_len: u32, payload_byte: u8) -> Vec<u8> {
        let mut ev = RawPayloadEvent {
            flow: RawFlowId {
                src_ip: 0x7f000001u32.to_be(),
                dst_ip: 0x7f000001u32.to_be(),
                src_port: 12345u16.to_be(),
                dst_port: 8899u16.to_be(),
            },
            direction,
            tcp_seq: 0xdeadbeef,
            _pad0: 0,
            ts_ns: 1_700_000_000_000_000_000,
            payload_len: sample_len,
            sample_len,
            payload: [0u8; PAYLOAD_SAMPLE_BYTES],
        };
        for i in 0..(sample_len as usize) {
            ev.payload[i] = payload_byte;
        }
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&ev as *const RawPayloadEvent) as *const u8,
                size_of::<RawPayloadEvent>(),
            )
        };
        bytes.to_vec()
    }

    #[test]
    fn decode_round_trip_basic() {
        let raw = build_raw(direction::INGRESS, 50, 0xab);
        let ev = decode_event(&raw).expect("decode");
        assert_eq!(ev.direction, direction::INGRESS);
        assert_eq!(ev.tcp_seq, 0xdeadbeef);
        assert_eq!(ev.ts_ns, 1_700_000_000_000_000_000);
        assert_eq!(ev.sample_len, 50);
        assert_eq!(ev.payload_len, 50);
        assert_eq!(ev.payload.len(), 50);
        assert!(ev.payload.iter().all(|b| *b == 0xab));
    }

    #[test]
    fn decode_round_trip_egress() {
        let raw = build_raw(direction::EGRESS, 10, 0xcd);
        let ev = decode_event(&raw).expect("decode");
        assert_eq!(ev.direction, direction::EGRESS);
        assert_eq!(ev.payload.len(), 10);
    }

    #[test]
    fn decode_truncated_rejects() {
        let raw = vec![0u8; 100];
        match decode_event(&raw) {
            Err(DecodeError::Truncated { got: 100, expected: 1064 }) => {}
            other => panic!("expected Truncated error, got {:?}", other),
        }
    }

    #[test]
    fn decode_oversize_rejects() {
        let raw = vec![0u8; 2048];
        assert!(matches!(
            decode_event(&raw),
            Err(DecodeError::Truncated { .. }),
        ));
    }

    #[test]
    fn decode_sample_overflow_rejects() {
        let mut raw = build_raw(direction::INGRESS, 50, 0);
        // Write sample_len = PAYLOAD_SAMPLE_BYTES + 1 (= 1025) at the
        // pinned offset (36).
        let bad: u32 = (PAYLOAD_SAMPLE_BYTES as u32) + 1;
        raw[36..40].copy_from_slice(&bad.to_le_bytes());
        match decode_event(&raw) {
            Err(DecodeError::SampleLenOverflow { sample, max }) => {
                assert_eq!(sample, bad);
                assert_eq!(max, PAYLOAD_SAMPLE_BYTES);
            }
            other => panic!("expected SampleLenOverflow, got {:?}", other),
        }
    }

    #[test]
    fn decode_unknown_direction_rejects() {
        let raw = build_raw(99, 10, 0);
        match decode_event(&raw) {
            Err(DecodeError::UnknownDirection(99)) => {}
            other => panic!("expected UnknownDirection(99), got {:?}", other),
        }
    }

    #[test]
    fn decode_zero_sample_len_ok() {
        // Zero-sample events are valid (payload was empty after header).
        // Doesn't happen in practice — BPF program skips empty payloads —
        // but the decoder must handle it gracefully.
        let raw = build_raw(direction::INGRESS, 0, 0);
        let ev = decode_event(&raw).expect("decode");
        assert_eq!(ev.sample_len, 0);
        assert!(ev.payload.is_empty());
    }
}
