//! ShadowPayload-mode userspace handler.
//!
//! This module turns kernel-side TC payload events (defined by
//! `ibsr-bpf/src/bpf/tc_payload.bpf.c`) into per-window response
//! aggregates that match the offline `nr_training/features/responses.py`
//! semantics exactly.
//!
//! Pipeline:
//!
//! ```text
//!   TC kernel program emits PayloadEvent records to a ringbuf
//!     ↓
//!   PayloadEvent (Rust)  — one per TCP packet's payload sample
//!     ↓
//!   FlowReassembler::feed(event)  — per-flow, per-direction
//!     buffer; httparse extracts complete HTTP messages + body sizes
//!     ↓
//!   RpcPair { request_bytes, response_bytes, status_code }  — emitted
//!     when matching request:response pair completes
//!     ↓
//!   WindowAggregator::record(pair)  — accumulates pairs in the
//!     current window
//!     ↓
//!   ResponseAggregates  — emitted on snapshot tick; matches
//!     `nr_training/features/responses.py` semantics exactly
//! ```
//!
//! Directionality: at the post-term loopback vantage, the configured
//! server port (e.g. Solana 8899, Sui 9000) is what nginx-decrypted
//! traffic flows toward. Packets with `dst_port == server_port` are
//! request-side (client→server); packets with `src_port == server_port`
//! are response-side (server→client). The same TCP connection is one
//! `flow_key` regardless of direction; per-direction state is tracked
//! independently inside the reassembler.
//!
//! HTTP body-size accounting matches the offline reproducer:
//! reproducers call `session.record_response(request_size_bytes=len(body),
//! response_size_bytes=len(body))` where `body` is the **HTTP body**
//! (JSON-RPC payload), not the full HTTP message. `httparse` parses the
//! HTTP head; the body length is then read from `Content-Length` (the
//! common case for JSON-RPC servers) or 0 if absent.
//!
//! Eviction: flows are evicted by LRU when the table reaches capacity,
//! and on idle timeout. Memory is bounded in userspace.

use ibsr_bpf::{direction as raw_dir, DecodedEvent};
use ibsr_schema::ResponseAggregates;
use std::collections::{HashMap, HashSet};

/// Maximum HTTP-head size we'll buffer per direction before giving up
/// and evicting the buffer (parser failure, malformed traffic, or
/// non-HTTP traffic on a configured port).
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Maximum HTTP-head fields httparse will accept. JSON-RPC servers
/// typically emit < 30 headers; 64 is generous.
pub const MAX_HTTP_HEADERS: usize = 64;

/// Maximum total bytes buffered per (flow, direction) before forced
/// eviction. Caps memory pressure when the TCP stream contains
/// non-HTTP traffic that never parses out.
pub const MAX_DIRECTION_BUFFER_BYTES: usize = 1 * 1024 * 1024;

/// Canonical 5-tuple-sans-protocol identifier for a TCP connection.
/// The same connection's two directions both map to the same `FlowKey`
/// (the (src_ip, src_port) and (dst_ip, dst_port) pair is sorted
/// lexicographically so both directions normalize to the same key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub low_addr: u128,
    pub high_addr: u128,
}

impl FlowKey {
    /// Build a canonical FlowKey from raw 4-tuple.
    pub fn from_tuple(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) -> Self {
        let a = ((src_ip as u128) << 16) | (src_port as u128);
        let b = ((dst_ip as u128) << 16) | (dst_port as u128);
        let (low_addr, high_addr) = if a <= b { (a, b) } else { (b, a) };
        FlowKey { low_addr, high_addr }
    }
}

/// Direction of a packet in a given flow. Determined by the userspace
/// caller from the configured server-port set: if the packet's
/// `dst_port` matches a configured server port, direction is
/// `ToServer` (request side); if `src_port` matches, direction is
/// `FromServer` (response side).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ToServer,
    FromServer,
}

/// One TCP-packet-sized payload event, post-decoding from the BPF
/// ringbuf record. The userspace reassembler consumes a stream of
/// these.
#[derive(Debug, Clone)]
pub struct PayloadEvent {
    pub flow: FlowKey,
    pub direction: Direction,
    pub tcp_seq: u32,
    pub ts_ns: u64,
    /// Total payload bytes in the original TCP packet (may exceed
    /// `payload.len()` if the packet was larger than the BPF sample
    /// size).
    pub payload_len: u32,
    /// Bytes actually sampled by BPF and copied to userspace.
    /// `payload.len() == sample_len`.
    pub payload: Vec<u8>,
}

impl PayloadEvent {
    /// Convert a kernel-decoded `DecodedEvent` into a userspace
    /// `PayloadEvent`, deriving `Direction` from the configured
    /// server-port set.
    ///
    /// Direction inference: the BPF program records direction relative
    /// to the network interface (ingress = inbound to host;
    /// egress = outbound from host). At the post-term loopback vantage,
    /// what matters is which side of the connection is the *server*.
    /// We use the server-port set as the disambiguator:
    ///
    /// - If `dst_port` is in `server_ports`, the packet is request-bound:
    ///   client → server → `Direction::ToServer`.
    /// - If `src_port` is in `server_ports`, the packet is response-bound:
    ///   server → client → `Direction::FromServer`.
    /// - Otherwise the packet doesn't belong to a server flow we care
    ///   about, and `None` is returned. (The BPF port filter normally
    ///   prevents this; this is a defensive check on the userspace
    ///   side.)
    pub fn from_decoded(
        ev: &DecodedEvent,
        server_ports: &HashSet<u16>,
    ) -> Option<Self> {
        // BPF emits ports in network byte order; convert to host byte
        // order for set lookup.
        let src_port = u16::from_be(ev.flow.src_port);
        let dst_port = u16::from_be(ev.flow.dst_port);
        let src_ip = u32::from_be(ev.flow.src_ip);
        let dst_ip = u32::from_be(ev.flow.dst_ip);

        let direction = if server_ports.contains(&dst_port) {
            Direction::ToServer
        } else if server_ports.contains(&src_port) {
            Direction::FromServer
        } else {
            return None;
        };

        let _ = ev.direction; // BPF-side ingress/egress flag is informational here.
        let _ = (raw_dir::INGRESS, raw_dir::EGRESS); // pin import.

        Some(PayloadEvent {
            flow: FlowKey::from_tuple(src_ip, src_port, dst_ip, dst_port),
            direction,
            tcp_seq: ev.tcp_seq,
            ts_ns: ev.ts_ns,
            payload_len: ev.payload_len,
            payload: ev.payload.clone(),
        })
    }
}

/// A complete request:response pair extracted from the stream. Emitted
/// by the reassembler when a request and its matching response both
/// complete on the same flow. Bytes counts match offline
/// `record_response(request_size_bytes=..., response_size_bytes=...)`
/// — i.e. **HTTP body length**, not full message length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcPair {
    pub flow: FlowKey,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub status_code: Option<u16>,
}

/// Result of `FlowReassembler::feed` — what to do with the consumed event.
#[derive(Debug, Clone, PartialEq)]
pub enum FeedOutcome {
    /// Buffered the bytes; no message complete yet.
    Buffered,
    /// Buffered + parsed a complete HTTP head; body still arriving.
    HeadComplete,
    /// Buffered + parsed a complete HTTP message (head + body); the
    /// reassembler has reset its direction state for the next message.
    /// May or may not have produced an `RpcPair`.
    MessageComplete(Option<RpcPair>),
    /// Buffer overflowed without parsing — direction reset (lossy).
    BufferOverflow,
}

/// Per-flow reassembler. Maintains independent buffers for the two
/// directions and pairs request:response when both complete.
#[derive(Debug, Default)]
pub struct FlowReassembler {
    to_server: DirectionState,
    from_server: DirectionState,
    /// Last-completed-but-unpaired request body size. Set when a
    /// to-server message completes; cleared when a from-server
    /// response completes and pairs with it.
    pending_request_bytes: Option<u64>,
}

/// State for one direction of a flow.
#[derive(Debug, Default)]
struct DirectionState {
    /// Reassembled bytes (in TCP-seq order — first-cut implementation
    /// assumes in-order delivery; reordering buffer can be added later).
    buf: Vec<u8>,
    /// Once head is parsed, this holds the body's length and how many
    /// body bytes we still need. None means we're still parsing the head.
    body_remaining: Option<usize>,
    /// Once head is parsed, this is the body length in bytes — the
    /// value we eventually emit as request_bytes / response_bytes.
    body_len_total: Option<u64>,
    /// Status code parsed from the response head (response direction
    /// only). None on request direction.
    status_code: Option<u16>,
}

impl DirectionState {
    /// Reset state for the next message on this direction (HTTP/1.1
    /// keep-alive: connections carry multiple back-to-back messages).
    fn reset(&mut self) {
        self.buf.clear();
        self.body_remaining = None;
        self.body_len_total = None;
        self.status_code = None;
    }
}

impl FlowReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a payload event into the appropriate direction. Returns a
    /// `FeedOutcome` describing what happened. When a complete
    /// request:response pair is produced, returns it inside
    /// `MessageComplete(Some(pair))`.
    pub fn feed(&mut self, ev: &PayloadEvent) -> FeedOutcome {
        let (state, is_response) = match ev.direction {
            Direction::ToServer => (&mut self.to_server, false),
            Direction::FromServer => (&mut self.from_server, true),
        };

        if state.buf.len() + ev.payload.len() > MAX_DIRECTION_BUFFER_BYTES {
            state.reset();
            return FeedOutcome::BufferOverflow;
        }
        state.buf.extend_from_slice(&ev.payload);

        // If we haven't parsed the head yet, try to.
        if state.body_remaining.is_none() {
            match try_parse_head(&state.buf, is_response) {
                ParseHead::Incomplete => return FeedOutcome::Buffered,
                ParseHead::Failed => {
                    state.reset();
                    return FeedOutcome::BufferOverflow;
                }
                ParseHead::Complete { head_bytes, body_len, status } => {
                    // Drop the head from the buffer; body bytes start fresh.
                    state.buf.drain(..head_bytes);
                    state.body_remaining = Some(body_len);
                    state.body_len_total = Some(body_len as u64);
                    state.status_code = status;
                    if state.body_remaining == Some(0) {
                        return self.complete_message(ev.flow, is_response);
                    }
                    // Fall through — body bytes may have arrived in this same event.
                }
            }
        }

        // Head is parsed; we're consuming body bytes.
        if let Some(remaining) = state.body_remaining.as_mut() {
            let consumed = std::cmp::min(*remaining, state.buf.len());
            *remaining -= consumed;
            state.buf.drain(..consumed);
            if *remaining == 0 {
                return self.complete_message(ev.flow, is_response);
            }
        }

        if state.body_remaining.is_some() {
            FeedOutcome::HeadComplete
        } else {
            FeedOutcome::Buffered
        }
    }

    fn complete_message(&mut self, flow: FlowKey, is_response: bool) -> FeedOutcome {
        // Snapshot direction state, then reset it for the next message
        // on this direction (HTTP/1.1 keep-alive).
        let body_len = if is_response {
            self.from_server.body_len_total.unwrap_or(0)
        } else {
            self.to_server.body_len_total.unwrap_or(0)
        };
        let status = self.from_server.status_code;

        if is_response {
            self.from_server.reset();
        } else {
            self.to_server.reset();
        }

        if !is_response {
            // Request completed — stash its body size, await response.
            self.pending_request_bytes = Some(body_len);
            return FeedOutcome::MessageComplete(None);
        }

        // Response completed — pair with the pending request.
        let request_bytes = self.pending_request_bytes.take();
        match request_bytes {
            Some(req_bytes) => FeedOutcome::MessageComplete(Some(RpcPair {
                flow,
                request_bytes: req_bytes,
                response_bytes: body_len,
                status_code: status,
            })),
            None => FeedOutcome::MessageComplete(None),
        }
    }
}

#[derive(Debug)]
enum ParseHead {
    Incomplete,
    Failed,
    Complete {
        head_bytes: usize,
        body_len: usize,
        status: Option<u16>,
    },
}

/// Try to parse an HTTP head from `buf`. Returns the number of bytes
/// the head occupies, the body length (from Content-Length), and the
/// status code (response direction only).
///
/// Body-length policy for first-cut: if Content-Length header is
/// present, use it. If absent, body_len = 0 (treats the message as
/// header-only — typical for empty 204 responses; under-counts for
/// chunked-transfer-encoded responses, which are rare for JSON-RPC
/// but should be added in a follow-up). This matches the offline
/// reproducer's `request_size_bytes = len(body)` for JSON-RPC bodies
/// where Content-Length always reflects the JSON payload size.
fn try_parse_head(buf: &[u8], is_response: bool) -> ParseHead {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
    if is_response {
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(buf) {
            Ok(httparse::Status::Complete(head_bytes)) => ParseHead::Complete {
                head_bytes,
                body_len: content_length(resp.headers),
                status: resp.code,
            },
            Ok(httparse::Status::Partial) => {
                if buf.len() > MAX_HEAD_BYTES {
                    ParseHead::Failed
                } else {
                    ParseHead::Incomplete
                }
            }
            Err(_) => ParseHead::Failed,
        }
    } else {
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(buf) {
            Ok(httparse::Status::Complete(head_bytes)) => ParseHead::Complete {
                head_bytes,
                body_len: content_length(req.headers),
                status: None,
            },
            Ok(httparse::Status::Partial) => {
                if buf.len() > MAX_HEAD_BYTES {
                    ParseHead::Failed
                } else {
                    ParseHead::Incomplete
                }
            }
            Err(_) => ParseHead::Failed,
        }
    }
}

fn content_length(headers: &[httparse::Header<'_>]) -> usize {
    for h in headers {
        if h.name.eq_ignore_ascii_case("Content-Length") {
            if let Ok(s) = std::str::from_utf8(h.value) {
                if let Ok(n) = s.trim().parse::<usize>() {
                    return n;
                }
            }
        }
    }
    0
}

/// Per-window aggregator. Accumulates RpcPair records for the active
/// window; on `take_window`, emits a `ResponseAggregates` matching the
/// offline `nr_training/features/responses.py` semantics exactly.
#[derive(Debug, Default)]
pub struct WindowAggregator {
    pairs: Vec<(u64, u64)>,
    /// Populated optionally for diagnostics.
    n_status_2xx: u64,
    n_status_4xx: u64,
    n_status_5xx: u64,
}

impl WindowAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, pair: &RpcPair) {
        self.pairs.push((pair.request_bytes, pair.response_bytes));
        if let Some(code) = pair.status_code {
            match code {
                200..=299 => self.n_status_2xx += 1,
                400..=499 => self.n_status_4xx += 1,
                500..=599 => self.n_status_5xx += 1,
                _ => {}
            }
        }
    }

    /// Emit aggregates for the current window and reset state.
    pub fn take_window(&mut self) -> ResponseAggregates {
        let agg = ResponseAggregates::from_pairs(&self.pairs);
        self.pairs.clear();
        self.n_status_2xx = 0;
        self.n_status_4xx = 0;
        self.n_status_5xx = 0;
        agg
    }

    pub fn n_pairs(&self) -> usize {
        self.pairs.len()
    }
}

/// Top-level handler — manages a flow table and routes events to the
/// right reassembler. Bounded memory: when the flow table reaches
/// `max_flows`, the least-recently-used flow is evicted.
#[derive(Debug)]
pub struct PayloadHandler {
    flows: HashMap<FlowKey, FlowReassembler>,
    aggregator: WindowAggregator,
    /// LRU ordering: oldest at the front.
    lru: std::collections::VecDeque<FlowKey>,
    max_flows: usize,
}

impl PayloadHandler {
    pub fn new(max_flows: usize) -> Self {
        Self {
            flows: HashMap::with_capacity(max_flows.min(4096)),
            aggregator: WindowAggregator::new(),
            lru: std::collections::VecDeque::new(),
            max_flows,
        }
    }

    /// Feed a payload event. Routes to per-flow reassembler; if a
    /// complete RpcPair emerges, records into the aggregator.
    pub fn feed(&mut self, ev: &PayloadEvent) -> FeedOutcome {
        // Touch flow in LRU.
        let is_new = !self.flows.contains_key(&ev.flow);
        if is_new && self.flows.len() >= self.max_flows {
            // Evict LRU.
            if let Some(victim) = self.lru.pop_front() {
                self.flows.remove(&victim);
            }
        }
        if is_new {
            self.flows.insert(ev.flow, FlowReassembler::new());
            self.lru.push_back(ev.flow);
        } else {
            // Move to back of LRU (most recently used). O(n) for now;
            // a doubly-linked-list LRU can land later if it becomes a
            // hot path.
            if let Some(idx) = self.lru.iter().position(|k| *k == ev.flow) {
                self.lru.remove(idx);
                self.lru.push_back(ev.flow);
            }
        }

        let outcome = self
            .flows
            .get_mut(&ev.flow)
            .expect("flow inserted above")
            .feed(ev);

        if let FeedOutcome::MessageComplete(Some(ref pair)) = outcome {
            self.aggregator.record(pair);
        }
        outcome
    }

    /// Take the current window's aggregates and reset.
    pub fn take_window(&mut self) -> ResponseAggregates {
        self.aggregator.take_window()
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow() -> FlowKey {
        FlowKey::from_tuple(0x7f000001, 12345, 0x7f000001, 8899)
    }

    fn ev(direction: Direction, payload: &[u8]) -> PayloadEvent {
        PayloadEvent {
            flow: flow(),
            direction,
            tcp_seq: 0,
            ts_ns: 0,
            payload_len: payload.len() as u32,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn flow_key_canonicalizes_directions_to_same_key() {
        let a = FlowKey::from_tuple(0x7f000001, 12345, 0x7f000001, 8899);
        let b = FlowKey::from_tuple(0x7f000001, 8899, 0x7f000001, 12345);
        assert_eq!(a, b);
    }

    #[test]
    fn parses_simple_request_and_response_pair() {
        let mut h = PayloadHandler::new(1024);

        let req = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 50\r\n\r\n";
        let req_body = vec![b'x'; 50];
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n";
        let resp_body = vec![b'y'; 200];

        h.feed(&ev(Direction::ToServer, req));
        let outcome = h.feed(&ev(Direction::ToServer, &req_body));
        assert!(matches!(outcome, FeedOutcome::MessageComplete(None)));

        h.feed(&ev(Direction::FromServer, resp));
        let outcome = h.feed(&ev(Direction::FromServer, &resp_body));
        match outcome {
            FeedOutcome::MessageComplete(Some(pair)) => {
                assert_eq!(pair.request_bytes, 50);
                assert_eq!(pair.response_bytes, 200);
                assert_eq!(pair.status_code, Some(200));
            }
            other => panic!("expected paired RpcPair, got {:?}", other),
        }
    }

    #[test]
    fn parses_message_split_across_events() {
        let mut h = PayloadHandler::new(1024);
        // Head: 48 bytes; body: 12 bytes; total: 60 bytes. Split into
        // chunks chosen so the head completes mid-stream and the body
        // tail arrives in the third chunk — exercises Buffered →
        // HeadComplete → MessageComplete progression.
        let req_full =
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\n\r\nhelloworldab";
        // Chunk boundaries: 30 / 20 / 10
        // Chunk 1 (0..30): partial head — httparse reports Partial → Buffered.
        // Chunk 2 (30..50): completes head at byte 48; body has 2 bytes
        //   so far; body_remaining = 10 → HeadComplete.
        // Chunk 3 (50..60): final 10 body bytes → MessageComplete.
        let (a, rest) = req_full.split_at(30);
        let (b, c) = rest.split_at(20);

        let o1 = h.feed(&ev(Direction::ToServer, a));
        let o2 = h.feed(&ev(Direction::ToServer, b));
        let o3 = h.feed(&ev(Direction::ToServer, c));

        assert!(matches!(o1, FeedOutcome::Buffered), "got {:?}", o1);
        assert!(matches!(o2, FeedOutcome::HeadComplete), "got {:?}", o2);
        assert!(matches!(o3, FeedOutcome::MessageComplete(None)), "got {:?}", o3);
    }

    #[test]
    fn keep_alive_two_request_response_pairs() {
        let mut h = PayloadHandler::new(1024);

        for i in 0..2 {
            let req = format!(
                "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
                10 + i,
            );
            let req_body = vec![b'x'; 10 + i];
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                100 + i,
            );
            let resp_body = vec![b'y'; 100 + i];

            h.feed(&ev(Direction::ToServer, req.as_bytes()));
            h.feed(&ev(Direction::ToServer, &req_body));
            h.feed(&ev(Direction::FromServer, resp.as_bytes()));
            let outcome = h.feed(&ev(Direction::FromServer, &resp_body));
            match outcome {
                FeedOutcome::MessageComplete(Some(pair)) => {
                    assert_eq!(pair.request_bytes, 10 + i as u64);
                    assert_eq!(pair.response_bytes, 100 + i as u64);
                }
                other => panic!("iter {} expected RpcPair, got {:?}", i, other),
            }
        }

        // Both pairs should be in the aggregator.
        let agg = h.take_window();
        assert_eq!(agg.count, 2);
        assert_eq!(agg.req_bytes_max, Some(11));
        assert_eq!(agg.resp_bytes_max, Some(101));
    }

    #[test]
    fn aggregator_matches_offline_semantics() {
        // Pin: same input pairs should yield the same ResponseAggregates
        // both via the WindowAggregator path AND via direct
        // ResponseAggregates::from_pairs. This is the contract that
        // bridges Stage B userspace to the Phase 1 close-gate.
        let mut h = PayloadHandler::new(1024);
        let cases = [
            (100u64, 200u64),
            (50, 250),
            (200, 600),
        ];
        for (req_n, resp_n) in cases.iter() {
            let req = format!(
                "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                req_n,
            );
            let req_body = vec![b'r'; *req_n as usize];
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                resp_n,
            );
            let resp_body = vec![b's'; *resp_n as usize];

            h.feed(&ev(Direction::ToServer, req.as_bytes()));
            h.feed(&ev(Direction::ToServer, &req_body));
            h.feed(&ev(Direction::FromServer, resp.as_bytes()));
            h.feed(&ev(Direction::FromServer, &resp_body));
        }
        let agg_via_handler = h.take_window();
        let agg_via_direct = ResponseAggregates::from_pairs(&[
            (100, 200), (50, 250), (200, 600),
        ]);
        assert_eq!(agg_via_handler, agg_via_direct);
    }

    #[test]
    fn flow_table_lru_eviction_caps_memory() {
        // max_flows=2; after 3 distinct flows, the oldest must evict.
        let mut h = PayloadHandler::new(2);
        for i in 0..3u32 {
            let f = FlowKey::from_tuple(0x7f000001, 1000 + i as u16, 0x7f000001, 8899);
            let e = PayloadEvent {
                flow: f,
                direction: Direction::ToServer,
                tcp_seq: 0,
                ts_ns: i as u64,
                payload_len: 5,
                payload: b"hello".to_vec(),
            };
            h.feed(&e);
        }
        assert_eq!(h.flow_count(), 2);
    }

    #[test]
    fn buffer_overflow_resets_direction() {
        let mut h = PayloadHandler::new(1024);
        // Inject ~1.1 MB of non-HTTP garbage on the request side; should
        // trip the per-direction cap.
        let chunk = vec![b'#'; 64 * 1024];
        let mut last_outcome = FeedOutcome::Buffered;
        for _ in 0..20 {
            last_outcome = h.feed(&ev(Direction::ToServer, &chunk));
            if matches!(last_outcome, FeedOutcome::BufferOverflow) {
                break;
            }
        }
        assert!(matches!(last_outcome, FeedOutcome::BufferOverflow));
    }

    #[test]
    fn malformed_http_resets_direction() {
        // Random bytes with multiple CRLF — httparse rejects as malformed.
        let mut h = PayloadHandler::new(1024);
        let trash = b"NOT_A_VALID_REQUEST\r\n\r\nbody";
        let outcome = h.feed(&ev(Direction::ToServer, trash));
        assert!(
            matches!(outcome, FeedOutcome::BufferOverflow),
            "expected BufferOverflow on malformed HTTP, got {:?}", outcome,
        );
    }

    #[test]
    fn response_without_paired_request_is_dropped() {
        // If we see a response without a prior request (mid-flow attach,
        // missed earlier traffic), don't emit a half-pair.
        let mut h = PayloadHandler::new(1024);
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let outcome = h.feed(&ev(Direction::FromServer, resp));
        match outcome {
            FeedOutcome::MessageComplete(None) => {}
            other => panic!("expected MessageComplete(None), got {:?}", other),
        }
        let agg = h.take_window();
        assert_eq!(agg.count, 0);
    }

    #[test]
    fn aggregator_zero_request_excluded_from_ratios() {
        // Pin: same offline rule — pairs with request_bytes=0 don't
        // contribute to amp_ratio_*.
        let mut agg = WindowAggregator::new();
        agg.record(&RpcPair {
            flow: flow(),
            request_bytes: 0,
            response_bytes: 100,
            status_code: Some(200),
        });
        agg.record(&RpcPair {
            flow: flow(),
            request_bytes: 50,
            response_bytes: 250,
            status_code: Some(200),
        });
        let r = agg.take_window();
        assert_eq!(r.count, 2);
        assert_eq!(r.amp_ratio_max, Some(5.0)); // only second pair contributes
        assert_eq!(r.amp_ratio_mean, Some(5.0));
    }

    #[test]
    fn empty_aggregator_yields_zero_count() {
        let mut agg = WindowAggregator::new();
        let r = agg.take_window();
        assert_eq!(r.count, 0);
        assert!(r.amp_ratio_mean.is_none());
        assert!(r.req_bytes_max.is_none());
    }

    #[test]
    fn aggregator_resets_after_take_window() {
        // Pin: take_window must reset state; consecutive windows are
        // independent.
        let mut h = PayloadHandler::new(1024);
        let req = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nresp123";
        h.feed(&ev(Direction::ToServer, req));
        h.feed(&ev(Direction::FromServer, resp));
        let r1 = h.take_window();
        assert_eq!(r1.count, 1);

        let r2 = h.take_window();
        assert_eq!(r2.count, 0, "second window should be empty after first take");
    }

    // ===========================================
    // Bridge from kernel-side DecodedEvent → userspace PayloadEvent
    // ===========================================

    fn decoded(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16, payload: &[u8])
        -> ibsr_bpf::DecodedEvent
    {
        ibsr_bpf::DecodedEvent {
            flow: ibsr_bpf::RawFlowId {
                src_ip: src_ip.to_be(),
                dst_ip: dst_ip.to_be(),
                src_port: src_port.to_be(),
                dst_port: dst_port.to_be(),
            },
            direction: ibsr_bpf::direction::INGRESS,
            tcp_seq: 0,
            ts_ns: 0,
            payload_len: payload.len() as u32,
            sample_len: payload.len() as u32,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn bridge_decoded_request_packet_maps_to_to_server() {
        let mut server_ports = HashSet::new();
        server_ports.insert(8899u16);
        // Client at 12345 → Server at 8899; dst_port matches server set.
        let d = decoded(0x7f000002, 12345, 0x7f000001, 8899, b"hello");
        let pe = PayloadEvent::from_decoded(&d, &server_ports).expect("bridge");
        assert_eq!(pe.direction, Direction::ToServer);
        assert_eq!(pe.payload, b"hello");
    }

    #[test]
    fn bridge_decoded_response_packet_maps_to_from_server() {
        let mut server_ports = HashSet::new();
        server_ports.insert(8899u16);
        // Server at 8899 → Client at 12345; src_port matches server set.
        let d = decoded(0x7f000001, 8899, 0x7f000002, 12345, b"resp");
        let pe = PayloadEvent::from_decoded(&d, &server_ports).expect("bridge");
        assert_eq!(pe.direction, Direction::FromServer);
        assert_eq!(pe.payload, b"resp");
    }

    #[test]
    fn bridge_unrelated_flow_returns_none() {
        // Neither port is in the server set — should be filtered out.
        let server_ports: HashSet<u16> = [8899u16].iter().copied().collect();
        let d = decoded(0x7f000001, 1000, 0x7f000002, 2000, b"x");
        assert!(PayloadEvent::from_decoded(&d, &server_ports).is_none());
    }

    #[test]
    fn bridge_canonicalises_flow_for_both_directions() {
        let server_ports: HashSet<u16> = [8899u16].iter().copied().collect();
        let req = decoded(0x7f000002, 12345, 0x7f000001, 8899, b"REQ");
        let resp = decoded(0x7f000001, 8899, 0x7f000002, 12345, b"RESP");
        let req_pe = PayloadEvent::from_decoded(&req, &server_ports).expect("req");
        let resp_pe = PayloadEvent::from_decoded(&resp, &server_ports).expect("resp");
        assert_eq!(req_pe.flow, resp_pe.flow,
            "request + response packets of same connection must map to same FlowKey");
    }

    #[test]
    fn bridge_end_to_end_decode_then_pair() {
        // Full bridge: build raw kernel events → decode → bridge to
        // PayloadEvent → feed PayloadHandler → produce ResponseAggregates.
        let server_ports: HashSet<u16> = [8899u16].iter().copied().collect();
        let req_full = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody";
        let resp_full = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npayload";

        let req_decoded = decoded(0x7f000002, 12345, 0x7f000001, 8899, req_full);
        let resp_decoded = decoded(0x7f000001, 8899, 0x7f000002, 12345, resp_full);

        let req_pe = PayloadEvent::from_decoded(&req_decoded, &server_ports).unwrap();
        let resp_pe = PayloadEvent::from_decoded(&resp_decoded, &server_ports).unwrap();

        let mut h = PayloadHandler::new(64);
        h.feed(&req_pe);
        let outcome = h.feed(&resp_pe);
        match outcome {
            FeedOutcome::MessageComplete(Some(pair)) => {
                assert_eq!(pair.request_bytes, 4, "body 'body' = 4 bytes");
                assert_eq!(pair.response_bytes, 7, "body 'payload' = 7 bytes");
                assert_eq!(pair.status_code, Some(200));
            }
            other => panic!("expected paired RpcPair, got {:?}", other),
        }
        let agg = h.take_window();
        assert_eq!(agg.count, 1);
        assert_eq!(agg.req_bytes_max, Some(4));
        assert_eq!(agg.resp_bytes_max, Some(7));
    }
}
