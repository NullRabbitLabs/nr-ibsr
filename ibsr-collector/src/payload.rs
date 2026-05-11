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
use ibsr_schema::{ResponseAggregates, RpcMetadata, StatusCounts};
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

/// Maximum response body bytes buffered per message for JSON-RPC envelope
/// parsing. JSON-RPC error envelopes are tiny (~100 bytes); this is well
/// above the practical envelope size while keeping per-flow memory
/// bounded. Bodies that exceed this cap mark the buffer as truncated and
/// the JSON-RPC parse is skipped — byte counting + timing still flow
/// through unaffected.
pub const RESP_BODY_BUFFER_CAP: usize = 8 * 1024;

/// Canonical 5-tuple-sans-protocol identifier for a TCP connection.
/// The same connection's two directions both map to the same `FlowKey`
/// (the (src_ip, src_port) and (dst_ip, dst_port) pair is sorted
/// lexicographically so both directions normalize to the same key).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// Original source port from the packet's TCP header (host byte
    /// order). Preserved alongside `flow` (which canonicalises
    /// directional ports for flow-table keying) so the
    /// `pcap.unique_src_ports` cardinality feature can track the
    /// original port-tuple distribution.
    pub src_port: u16,
    /// Original destination port (host byte order). Same purpose as
    /// `src_port` for `pcap.unique_dst_ports`.
    pub dst_port: u16,
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
            src_port,
            dst_port,
        })
    }
}

/// A complete request:response pair extracted from the stream. Emitted
/// by the reassembler when a request and its matching response both
/// complete on the same flow. Bytes counts match offline
/// `record_response(request_size_bytes=..., response_size_bytes=...)`
/// — i.e. **HTTP body length**, not full message length.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RpcPair {
    pub flow: FlowKey,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub status_code: Option<u16>,

    /// Timestamp (kernel `bpf_ktime_get_ns`) of the FIRST ToServer event
    /// observed for this request. Used downstream to compute response
    /// duration as `resp_completed_ns - req_started_ns`.
    pub req_started_ns: u64,

    /// Timestamp (kernel `bpf_ktime_get_ns`) of the FromServer event
    /// that drove `body_remaining` to 0 — i.e. the event at which the
    /// response message completed.
    pub resp_completed_ns: u64,

    /// True if the response body parsed cleanly as a JSON-RPC envelope.
    /// Used by the aggregator's `n_with_parsed_envelope` denominator
    /// (drives `rpc_error_frac` / `rpc_error_distinct_codes` from
    /// `None` to populated). False for non-JSON / truncated bodies.
    pub rpc_envelope_parsed: bool,

    /// JSON-RPC `error.code` value if the response carried a non-null
    /// `error` field. `None` if the envelope had no error or did not
    /// parse. Implies `rpc_envelope_parsed == true`.
    pub rpc_error_code: Option<i32>,
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
    /// Timestamp (kernel `bpf_ktime_get_ns`) captured at the FIRST
    /// ToServer event of the unpaired request. Stashed alongside
    /// `pending_request_bytes` so it threads through to the eventual
    /// `RpcPair.req_started_ns` when the matching response completes.
    pending_request_started_ns: Option<u64>,
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
    /// Cumulative network-actual payload bytes seen on this direction
    /// during head parsing (sum of prior events' `payload_len`). Used
    /// on head completion to compute how many body bytes have already
    /// arrived in the network (not just the sample). Reset alongside
    /// the rest of the per-message state.
    bytes_seen_pre_head: u64,
    /// Timestamp (kernel `bpf_ktime_get_ns`) of the first event observed
    /// for the current message on this direction. Captured at first
    /// event arrival, cleared on `reset`. Threads through to
    /// `RpcPair.req_started_ns` (ToServer) or unused (FromServer —
    /// `resp_completed_ns` instead comes from the completing event).
    first_event_ts_ns: Option<u64>,
    /// Bounded buffer of response body bytes for JSON-RPC envelope
    /// parsing. Populated only on the FromServer direction; capped at
    /// `RESP_BODY_BUFFER_CAP`. When the cap is hit mid-stream,
    /// `body_buf_truncated` is set and the JSON-RPC parse is skipped on
    /// message completion. Empty/unused on the ToServer direction.
    body_buf: Vec<u8>,
    /// True if the body buffer hit `RESP_BODY_BUFFER_CAP` before the
    /// message completed. Skips JSON-RPC envelope parse to avoid
    /// false-positive parses against truncated JSON.
    body_buf_truncated: bool,
}

impl DirectionState {
    /// Reset state for the next message on this direction (HTTP/1.1
    /// keep-alive: connections carry multiple back-to-back messages).
    fn reset(&mut self) {
        self.buf.clear();
        self.body_remaining = None;
        self.body_len_total = None;
        self.status_code = None;
        self.bytes_seen_pre_head = 0;
        self.first_event_ts_ns = None;
        self.body_buf.clear();
        self.body_buf_truncated = false;
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
    ///
    /// Body byte accounting: BPF samples up to `PAYLOAD_SAMPLE_BYTES`
    /// (1024) of each TCP packet's payload, but the event carries the
    /// **actual** segment payload size in `ev.payload_len`. For HTTP
    /// body byte counting we use `payload_len` (the real network
    /// progress), not the sampled bytes, so that responses larger than
    /// the sample size — common on `lo` where a single skb can carry
    /// 60+ KB without MTU-fragmentation — complete correctly.
    pub fn feed(&mut self, ev: &PayloadEvent) -> FeedOutcome {
        let (state, is_response) = match ev.direction {
            Direction::ToServer => (&mut self.to_server, false),
            Direction::FromServer => (&mut self.from_server, true),
        };

        // Capture the per-message start timestamp on the FIRST event of
        // each new message. Once set, subsequent body events do not
        // overwrite it — the caller wants the FIRST event's ts.
        if state.first_event_ts_ns.is_none() {
            state.first_event_ts_ns = Some(ev.ts_ns);
        }

        let head_was_parsed = state.body_remaining.is_some();

        if !head_was_parsed {
            // Head-parsing phase: buffer the sample bytes (so httparse
            // can find CRLF CRLF) and accumulate the network-actual
            // payload byte count so we know how many body bytes have
            // arrived by the time the head completes.
            if state.buf.len() + ev.payload.len() > MAX_DIRECTION_BUFFER_BYTES {
                state.reset();
                return FeedOutcome::BufferOverflow;
            }
            state.buf.extend_from_slice(&ev.payload);
            state.bytes_seen_pre_head =
                state.bytes_seen_pre_head.saturating_add(ev.payload_len as u64);

            match try_parse_head(&state.buf, is_response) {
                ParseHead::Incomplete => return FeedOutcome::Buffered,
                ParseHead::Failed => {
                    state.reset();
                    return FeedOutcome::BufferOverflow;
                }
                ParseHead::Complete { head_bytes, body_len, status } => {
                    state.body_len_total = Some(body_len as u64);
                    state.status_code = status;

                    // Body bytes already seen in the network = total
                    // payload bytes received during head parsing minus
                    // the head_bytes. Subsequent events count their
                    // ev.payload_len directly toward body completion.
                    //
                    // Why ev.payload_len rather than the sample buffer:
                    // BPF caps each event's sampled bytes at
                    // PAYLOAD_SAMPLE_BYTES (1024), but `payload_len`
                    // carries the true TCP-segment payload size. On
                    // `lo` a single skb can be 60+ KB without MTU-
                    // fragmentation; counting via sampled bytes would
                    // never reach a Content-Length of 1.4 MB.
                    let body_seen_so_far =
                        state.bytes_seen_pre_head.saturating_sub(head_bytes as u64);
                    let body_remaining_init =
                        (body_len as u64).saturating_sub(body_seen_so_far);
                    state.body_remaining = Some(body_remaining_init as usize);

                    // Capture body bytes after the head into the JSON-RPC
                    // body buffer (FromServer only). Bounded by
                    // RESP_BODY_BUFFER_CAP. The body bytes already in
                    // state.buf at this point are the chunk after head_bytes.
                    if is_response && head_bytes <= state.buf.len() {
                        append_capped(
                            &mut state.body_buf,
                            &mut state.body_buf_truncated,
                            &state.buf[head_bytes..],
                        );
                    }
                    state.buf.clear();

                    if body_remaining_init == 0 {
                        return self.complete_message(ev, is_response);
                    }
                    return FeedOutcome::HeadComplete;
                }
            }
        }

        // Head was already parsed in a previous event. This event is
        // pure body — count its full network payload toward body
        // completion. The sample buffer is unused for body bytes; body
        // accounting is by network-actual `payload_len` only.
        //
        // For FromServer, additionally append sampled bytes to body_buf
        // for JSON-RPC envelope parsing (bounded by cap).
        if is_response {
            append_capped(
                &mut state.body_buf,
                &mut state.body_buf_truncated,
                &ev.payload,
            );
        }

        if let Some(remaining) = state.body_remaining.as_mut() {
            let consumed = std::cmp::min(*remaining as u64, ev.payload_len as u64) as usize;
            *remaining -= consumed;
            if *remaining == 0 {
                return self.complete_message(ev, is_response);
            }
        }

        FeedOutcome::HeadComplete
    }

    fn complete_message(&mut self, ev: &PayloadEvent, is_response: bool) -> FeedOutcome {
        // Snapshot direction state, then reset it for the next message
        // on this direction (HTTP/1.1 keep-alive).
        let body_len = if is_response {
            self.from_server.body_len_total.unwrap_or(0)
        } else {
            self.to_server.body_len_total.unwrap_or(0)
        };
        let status = self.from_server.status_code;
        let direction_first_event_ts = if is_response {
            self.from_server.first_event_ts_ns.unwrap_or(0)
        } else {
            self.to_server.first_event_ts_ns.unwrap_or(0)
        };

        // Parse JSON-RPC envelope from the buffered response body if it
        // fit in the cap. Truncated bodies are not parsed.
        let (rpc_envelope_parsed, rpc_error_code) = if is_response
            && !self.from_server.body_buf_truncated
            && !self.from_server.body_buf.is_empty()
        {
            match parse_jsonrpc_envelope(&self.from_server.body_buf) {
                Some(error_code) => (true, error_code),
                None => (false, None),
            }
        } else {
            (false, None)
        };

        if is_response {
            self.from_server.reset();
        } else {
            self.to_server.reset();
        }

        if !is_response {
            // Request completed — stash its body size + start ts; await response.
            self.pending_request_bytes = Some(body_len);
            self.pending_request_started_ns = Some(direction_first_event_ts);
            return FeedOutcome::MessageComplete(None);
        }

        // Response completed — pair with the pending request.
        let request_bytes = self.pending_request_bytes.take();
        let req_started_ns = self.pending_request_started_ns.take().unwrap_or(0);
        match request_bytes {
            Some(req_bytes) => FeedOutcome::MessageComplete(Some(RpcPair {
                flow: ev.flow,
                request_bytes: req_bytes,
                response_bytes: body_len,
                status_code: status,
                req_started_ns,
                resp_completed_ns: ev.ts_ns,
                rpc_envelope_parsed,
                rpc_error_code,
            })),
            None => FeedOutcome::MessageComplete(None),
        }
    }
}

/// Append `bytes` to the response body buffer, capping at
/// `RESP_BODY_BUFFER_CAP`. Sets `truncated` if the cap was hit before
/// all input could be appended. Takes disjoint field references so it
/// can be called from sites that hold an immutable borrow of another
/// field on the same `DirectionState`.
fn append_capped(buf: &mut Vec<u8>, truncated: &mut bool, bytes: &[u8]) {
    if *truncated {
        return;
    }
    let space = RESP_BODY_BUFFER_CAP.saturating_sub(buf.len());
    if space == 0 {
        *truncated = true;
        return;
    }
    let take = space.min(bytes.len());
    buf.extend_from_slice(&bytes[..take]);
    if take < bytes.len() {
        *truncated = true;
    }
}

/// Try to parse `body` as a JSON-RPC envelope. Returns:
/// - `Some(Some(code))` if the body is valid JSON with a non-null
///   `error.code: i32` field.
/// - `Some(None)` if the body is valid JSON-RPC but with no error
///   (i.e. a result envelope, or an error field with null/missing code).
/// - `None` if the body did not parse as JSON.
fn parse_jsonrpc_envelope(body: &[u8]) -> Option<Option<i32>> {
    #[derive(serde::Deserialize)]
    struct Envelope {
        #[serde(default)]
        error: Option<RpcError>,
    }
    #[derive(serde::Deserialize)]
    struct RpcError {
        #[serde(default)]
        code: Option<i32>,
    }
    let env: Envelope = serde_json::from_slice(body).ok()?;
    Some(env.error.and_then(|e| e.code))
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
///
/// Also tracks distinct dst_port + src_port values observed across
/// EVERY payload event (not just paired RPCs) for the
/// `unique_dst_ports` / `unique_src_ports` features. Capped at 5 on
/// emit to match offline `summarise_pcap`'s `top_n=5` semantic.
#[derive(Debug, Default)]
pub struct WindowAggregator {
    /// Per-pair (request_bytes, response_bytes, duration_ns) triples.
    /// Duration is `Some` only when the pair carries non-zero req/resp
    /// timestamps (i.e. monotonic kernel ts capture succeeded).
    triples: Vec<(u64, u64, Option<u64>)>,

    // HTTP status counters (drive ResponseAggregates::status_*_frac via
    // StatusCounts). Denominator (`n_with_parsed_status`) excludes pairs
    // whose response did not parse a status line — see
    // `ResponseAggregates::from_triples_and_metadata` semantics.
    n_status_2xx: u64,
    n_status_4xx: u64,
    n_status_5xx: u64,
    n_with_parsed_status: u64,

    // JSON-RPC error metadata (drives ResponseAggregates::rpc_error_*).
    // `n_with_parsed_envelope` is the gate that flips both rpc fields
    // from None to populated.
    rpc_error_codes: Vec<i32>,
    rpc_error_count: u64,
    n_with_parsed_envelope: u64,

    /// All distinct dst_port values observed in any TC payload event
    /// during the current window. Used for `pcap.unique_dst_ports`.
    dst_ports_seen: std::collections::HashSet<u16>,
    /// All distinct src_port values observed in any TC payload event
    /// during the current window. Used for `pcap.unique_src_ports`.
    src_ports_seen: std::collections::HashSet<u16>,
}

impl WindowAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, pair: &RpcPair) {
        let duration_ns = if pair.resp_completed_ns > pair.req_started_ns {
            Some(pair.resp_completed_ns - pair.req_started_ns)
        } else {
            None
        };
        self.triples.push((pair.request_bytes, pair.response_bytes, duration_ns));

        if let Some(code) = pair.status_code {
            self.n_with_parsed_status += 1;
            match code {
                200..=299 => self.n_status_2xx += 1,
                400..=499 => self.n_status_4xx += 1,
                500..=599 => self.n_status_5xx += 1,
                _ => {}
            }
        }

        if pair.rpc_envelope_parsed {
            self.n_with_parsed_envelope += 1;
            if let Some(code) = pair.rpc_error_code {
                self.rpc_error_codes.push(code);
                self.rpc_error_count += 1;
            }
        }
    }

    /// Record port-tuple from one payload event (regardless of
    /// whether it ever produces an RpcPair). Called for every event
    /// fed to the handler so the distinct-port-cardinality features
    /// see all packets in the window, not just complete RPCs.
    pub fn observe_ports(&mut self, src_port: u16, dst_port: u16) {
        self.src_ports_seen.insert(src_port);
        self.dst_ports_seen.insert(dst_port);
    }

    /// Emit aggregates for the current window and reset state.
    /// Includes the port-cardinality features capped at 5.
    pub fn take_window(&mut self) -> ResponseAggregates {
        let status_counts = StatusCounts {
            n_2xx: self.n_status_2xx,
            n_4xx: self.n_status_4xx,
            n_5xx: self.n_status_5xx,
            n_with_parsed_status: self.n_with_parsed_status,
        };
        let rpc_metadata = RpcMetadata {
            error_codes: std::mem::take(&mut self.rpc_error_codes),
            error_count: self.rpc_error_count,
            n_with_parsed_envelope: self.n_with_parsed_envelope,
        };
        let dst_card = self.dst_ports_seen.len();
        let src_card = self.src_ports_seen.len();
        let agg = ResponseAggregates::from_triples_and_metadata(
            &self.triples,
            status_counts,
            rpc_metadata,
        )
        .with_port_cardinalities(dst_card, src_card);

        self.triples.clear();
        self.n_status_2xx = 0;
        self.n_status_4xx = 0;
        self.n_status_5xx = 0;
        self.n_with_parsed_status = 0;
        self.rpc_error_count = 0;
        self.n_with_parsed_envelope = 0;
        // rpc_error_codes already drained via std::mem::take above.
        self.dst_ports_seen.clear();
        self.src_ports_seen.clear();
        agg
    }

    pub fn n_pairs(&self) -> usize {
        self.triples.len()
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
    /// Also records the event's port-tuple in the aggregator so
    /// `pcap.unique_{dst,src}_ports` features see every packet, not
    /// just complete RPCs.
    pub fn feed(&mut self, ev: &PayloadEvent) -> FeedOutcome {
        // Record port-tuple BEFORE the reassembler call — every event
        // contributes to port-cardinality features regardless of
        // whether it ever completes an RPC pair (handshake-only
        // connections, partial captures, malformed traffic all
        // still inform the port-distribution view).
        self.aggregator.observe_ports(ev.src_port, ev.dst_port);

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
        // Test fixture src/dst ports — match the canonical flow tuple
        // built by `flow()`: src_port=12345, dst_port=8899.
        PayloadEvent {
            flow: flow(),
            direction,
            tcp_seq: 0,
            ts_ns: 0,
            payload_len: payload.len() as u32,
            payload: payload.to_vec(),
            src_port: 12345,
            dst_port: 8899,
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

    /// Test fixture for events whose actual TCP-segment payload is
    /// larger than the BPF sample. `payload_len` carries the network-
    /// actual size; `payload` (sample) is truncated. Mimics BPF on `lo`
    /// where a single skb can be 60+ KB but BPF samples only 1024 bytes.
    fn ev_truncated(direction: Direction, sample: &[u8], full_len: u32) -> PayloadEvent {
        PayloadEvent {
            flow: flow(),
            direction,
            tcp_seq: 0,
            ts_ns: 0,
            payload_len: full_len,
            payload: sample.to_vec(),
            src_port: 12345,
            dst_port: 8899,
        }
    }

    #[test]
    fn parses_large_body_with_truncated_samples() {
        // BPF emits at most PAYLOAD_SAMPLE_BYTES (1024) per event, but
        // ev.payload_len is the true segment size. A 1.5 MB response
        // typically arrives as a few 60+ KB skbs on `lo` (no MTU). The
        // parser must complete based on payload_len, not the truncated
        // sample buffer, otherwise body_remaining never reaches 0.
        let mut h = PayloadHandler::new(1024);

        // Tiny request that fits in one event.
        let req = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
        let outcome = h.feed(&ev(Direction::ToServer, req));
        assert!(
            matches!(outcome, FeedOutcome::MessageComplete(None)),
            "request should complete with body_len=0; got {:?}", outcome,
        );

        // Response: head + ~1.4 MB body, delivered as 24 events of 60 KB
        // each. BPF samples first 1024 bytes of each event; rest is
        // truncated. The parser must count via payload_len.
        let total_body: u32 = 1_400_000;
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            total_body,
        );
        let head_bytes_len = head.len();

        // Event 0: head + start of body. Sample carries the full head
        // plus a few body bytes (head_bytes_len + 100 bytes of body
        // sampled, but the segment is 60 KB).
        let segment_size: u32 = 60_000;
        let mut event_0_sample = head.as_bytes().to_vec();
        event_0_sample.extend_from_slice(&vec![b'y'; 100]); // body bytes in sample
        let outcome = h.feed(&ev_truncated(
            Direction::FromServer,
            &event_0_sample,
            segment_size,
        ));
        assert!(
            matches!(outcome, FeedOutcome::HeadComplete),
            "event 0 should complete head and not finish body; got {:?}", outcome,
        );

        // Subsequent events: pure body. Sample is 1024 bytes of 'y',
        // payload_len is the full 60_000-byte segment. After 23 more
        // events of 60 KB each, total body bytes seen =
        // (60_000 - head_bytes_len) + 23 * 60_000 = 24 * 60_000 - head_bytes_len.
        // For total_body = 1_400_000, that's 1_440_000 - head_len ≈ 1.44 MB,
        // so we need fewer events (23) for the body to complete.
        let mut event_count_needed = 23;
        let mut completed = false;
        let body_chunk_sample = vec![b'y'; 1024];
        for i in 0..30 {  // safety cap
            let outcome = h.feed(&ev_truncated(
                Direction::FromServer,
                &body_chunk_sample,
                segment_size,
            ));
            match outcome {
                FeedOutcome::HeadComplete => continue,
                FeedOutcome::MessageComplete(Some(pair)) => {
                    assert_eq!(pair.response_bytes, total_body as u64);
                    assert_eq!(pair.request_bytes, 0);
                    completed = true;
                    event_count_needed = i + 1;
                    break;
                }
                other => panic!("event {}: unexpected outcome {:?}", i + 1, other),
            }
        }
        assert!(completed, "1.4 MB body never completed across 30 large events");
        // Sanity: body should complete after ~23-24 events of 60 KB
        // (24 events * 60 KB = 1.44 MB > 1.4 MB body + ~80 byte head).
        assert!(
            event_count_needed >= 22 && event_count_needed <= 25,
            "expected completion at event 23±2, got {}", event_count_needed,
        );
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
        // Strip fields the handler populates from per-event metadata
        // (port tuples, HTTP status, JSON-RPC envelope, kernel timing)
        // before comparing — `from_pairs` knows only byte counts.
        // Compare on the byte-aggregate features that both paths compute.
        let mut agg_for_compare = agg_via_handler.clone();
        agg_for_compare.unique_dst_ports = None;
        agg_for_compare.unique_src_ports = None;
        agg_for_compare.status_2xx_frac = None;
        agg_for_compare.status_4xx_frac = None;
        agg_for_compare.status_5xx_frac = None;
        agg_for_compare.rpc_error_distinct_codes = None;
        agg_for_compare.rpc_error_frac = None;
        agg_for_compare.duration_ns_mean = None;
        agg_for_compare.duration_ns_max = None;
        let agg_via_direct = ResponseAggregates::from_pairs(&[
            (100, 200), (50, 250), (200, 600),
        ]);
        assert_eq!(agg_for_compare, agg_via_direct);
        // The handler path additionally populates port cardinalities;
        // pin those too to surface drift if the contract changes.
        assert_eq!(agg_via_handler.unique_dst_ports, Some(1),
            "all 3 RPCs target the same dst_port=8899 in this test");
        assert_eq!(agg_via_handler.unique_src_ports, Some(1),
            "all 3 RPCs use src_port=12345 (the test fixture's `flow()`)");
    }

    #[test]
    fn flow_table_lru_eviction_caps_memory() {
        // max_flows=2; after 3 distinct flows, the oldest must evict.
        let mut h = PayloadHandler::new(2);
        for i in 0..3u32 {
            let src_port = 1000 + i as u16;
            let f = FlowKey::from_tuple(0x7f000001, src_port, 0x7f000001, 8899);
            let e = PayloadEvent {
                flow: f,
                direction: Direction::ToServer,
                tcp_seq: 0,
                ts_ns: i as u64,
                payload_len: 5,
                payload: b"hello".to_vec(),
                src_port,
                dst_port: 8899,
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
    fn port_cardinality_tracked_per_window() {
        // Pin: distinct dst_port + src_port observed across events
        // are reported as cardinalities on the resulting
        // ResponseAggregates. Capped at 5 to match offline.
        let mut h = PayloadHandler::new(64);
        // 7 distinct src_ports, 1 dst_port (server) — cardinality
        // capped at 5 for src.
        for i in 0..7u16 {
            let src_port = 10000 + i;
            let f = FlowKey::from_tuple(0x7f000001, src_port, 0x7f000001, 8899);
            let e = PayloadEvent {
                flow: f,
                direction: Direction::ToServer,
                tcp_seq: 0,
                ts_ns: i as u64,
                payload_len: 5,
                payload: b"hello".to_vec(),
                src_port,
                dst_port: 8899,
            };
            h.feed(&e);
        }
        let agg = h.take_window();
        assert_eq!(agg.unique_src_ports, Some(5),
            "src_ports cardinality must be capped at 5");
        assert_eq!(agg.unique_dst_ports, Some(1),
            "dst_ports cardinality is the count of distinct dst_ports");
    }

    #[test]
    fn port_cardinality_resets_between_windows() {
        let mut h = PayloadHandler::new(64);
        let f = FlowKey::from_tuple(0x7f000001, 12345, 0x7f000001, 8899);
        let e = PayloadEvent {
            flow: f, direction: Direction::ToServer,
            tcp_seq: 0, ts_ns: 0, payload_len: 5,
            payload: b"hello".to_vec(),
            src_port: 12345, dst_port: 8899,
        };
        h.feed(&e);
        let r1 = h.take_window();
        assert_eq!(r1.unique_dst_ports, Some(1));
        assert_eq!(r1.unique_src_ports, Some(1));
        // Second window with no events: cardinalities are 0
        // (still emitted as Some, since we want explicit zero — not
        // None — to distinguish "v0.2-aware writer with empty
        // window" from "v0.1 writer that never emitted the field").
        let r2 = h.take_window();
        assert_eq!(r2.unique_dst_ports, Some(0));
        assert_eq!(r2.unique_src_ports, Some(0));
    }

    #[test]
    fn port_cardinality_observed_on_every_event_not_just_paired_rpcs() {
        // Pin: events that never produce an RpcPair (handshake-only,
        // partial captures, malformed traffic) STILL contribute to
        // port-cardinality. Test: feed 3 unparseable events, take
        // window. Expect cardinalities populated even though
        // n_pairs=0.
        let mut h = PayloadHandler::new(64);
        for i in 0..3u16 {
            let src_port = 20000 + i;
            let f = FlowKey::from_tuple(0x7f000001, src_port, 0x7f000001, 8899);
            let trash = b"not_http\r\n\r\n";
            let e = PayloadEvent {
                flow: f, direction: Direction::ToServer,
                tcp_seq: 0, ts_ns: 0, payload_len: trash.len() as u32,
                payload: trash.to_vec(),
                src_port, dst_port: 8899,
            };
            h.feed(&e);
        }
        let agg = h.take_window();
        assert_eq!(agg.count, 0, "no paired RPCs from malformed events");
        assert_eq!(agg.unique_src_ports, Some(3),
            "but port-cardinality features must still see all 3 src_ports");
        assert_eq!(agg.unique_dst_ports, Some(1));
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
            ..Default::default()
        });
        agg.record(&RpcPair {
            flow: flow(),
            request_bytes: 50,
            response_bytes: 250,
            status_code: Some(200),
            ..Default::default()
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
    fn aggregator_emits_status_fractions_with_parsed_denominator() {
        // 4 pairs all with parseable HTTP status: 2 × 2xx, 1 × 4xx, 1 × 5xx.
        // Fractions denominator = n_with_parsed_status (4).
        let mut agg = WindowAggregator::new();
        for code in [200u16, 200, 404, 503] {
            agg.record(&RpcPair {
                flow: flow(),
                request_bytes: 100,
                response_bytes: 100,
                status_code: Some(code),
                ..Default::default()
            });
        }
        let r = agg.take_window();
        assert_eq!(r.status_2xx_frac, Some(0.5));
        assert_eq!(r.status_4xx_frac, Some(0.25));
        assert_eq!(r.status_5xx_frac, Some(0.25));
    }

    #[test]
    fn aggregator_emits_status_fractions_skip_unparsed_responses() {
        // 2 of 3 pairs had parseable status (200, 500); 1 was non-HTTP.
        // Denominator = 2, not 3.
        let mut agg = WindowAggregator::new();
        agg.record(&RpcPair {
            flow: flow(),
            request_bytes: 100,
            response_bytes: 100,
            status_code: Some(200),
            ..Default::default()
        });
        agg.record(&RpcPair {
            flow: flow(),
            request_bytes: 100,
            response_bytes: 100,
            status_code: Some(500),
            ..Default::default()
        });
        agg.record(&RpcPair {
            flow: flow(),
            request_bytes: 100,
            response_bytes: 100,
            status_code: None, // non-HTTP / no status parsed
            ..Default::default()
        });
        let r = agg.take_window();
        // 1/2 = 0.5 (not 1/3)
        assert_eq!(r.status_2xx_frac, Some(0.5));
        assert_eq!(r.status_4xx_frac, Some(0.0));
        assert_eq!(r.status_5xx_frac, Some(0.5));
    }

    #[test]
    fn aggregator_emits_rpc_error_fields_when_envelopes_parsed() {
        // 4 pairs all with parsed JSON-RPC envelopes: 2 errors with codes
        // [-32602, -32601], 2 success.
        let mut agg = WindowAggregator::new();
        for (envelope_parsed, error_code) in [
            (true, Some(-32602)),
            (true, Some(-32601)),
            (true, None),
            (true, None),
        ] {
            agg.record(&RpcPair {
                flow: flow(),
                request_bytes: 100,
                response_bytes: 100,
                rpc_envelope_parsed: envelope_parsed,
                rpc_error_code: error_code,
                ..Default::default()
            });
        }
        let r = agg.take_window();
        // 2 distinct error codes
        assert_eq!(r.rpc_error_distinct_codes, Some(2));
        // 2 errors out of 4 pairs (denominator is `count`, not `n_with_parsed_envelope`)
        assert_eq!(r.rpc_error_frac, Some(0.5));
    }

    #[test]
    fn aggregator_emits_rpc_none_when_no_envelopes_parsed() {
        // No pair had rpc_envelope_parsed=true.
        let mut agg = WindowAggregator::new();
        agg.record(&RpcPair {
            flow: flow(),
            request_bytes: 100,
            response_bytes: 100,
            ..Default::default()
        });
        let r = agg.take_window();
        assert_eq!(r.rpc_error_distinct_codes, None);
        assert_eq!(r.rpc_error_frac, None);
    }

    #[test]
    fn aggregator_emits_duration_from_pair_timestamps() {
        // Pairs with req_started_ns + resp_completed_ns → durations.
        let mut agg = WindowAggregator::new();
        agg.record(&RpcPair {
            flow: flow(),
            request_bytes: 100,
            response_bytes: 100,
            req_started_ns: 1_000_000,
            resp_completed_ns: 3_000_000, // duration = 2_000_000
            ..Default::default()
        });
        agg.record(&RpcPair {
            flow: flow(),
            request_bytes: 100,
            response_bytes: 100,
            req_started_ns: 5_000_000,
            resp_completed_ns: 9_000_000, // duration = 4_000_000
            ..Default::default()
        });
        let r = agg.take_window();
        // mean = (2_000_000 + 4_000_000) / 2 = 3_000_000
        assert_eq!(r.duration_ns_mean, Some(3_000_000));
        // max = 4_000_000
        assert_eq!(r.duration_ns_max, Some(4_000_000));
    }

    #[test]
    fn aggregator_emits_duration_none_when_pairs_lack_timing() {
        // Pairs with req_started_ns == resp_completed_ns == 0 (default) →
        // no duration captured.
        let mut agg = WindowAggregator::new();
        agg.record(&RpcPair {
            flow: flow(),
            request_bytes: 100,
            response_bytes: 100,
            ..Default::default()
        });
        let r = agg.take_window();
        assert_eq!(r.duration_ns_mean, None);
        assert_eq!(r.duration_ns_max, None);
    }

    #[test]
    fn aggregator_resets_metadata_state_after_take_window() {
        // Pin: take_window resets ALL state, not just pairs/ports.
        let mut agg = WindowAggregator::new();
        agg.record(&RpcPair {
            flow: flow(),
            request_bytes: 100,
            response_bytes: 100,
            status_code: Some(200),
            req_started_ns: 1_000,
            resp_completed_ns: 5_000,
            rpc_envelope_parsed: true,
            rpc_error_code: Some(-32602),
            ..Default::default()
        });
        let _ = agg.take_window();
        let r2 = agg.take_window();
        assert_eq!(r2.count, 0);
        assert_eq!(r2.status_2xx_frac, None);
        assert_eq!(r2.duration_ns_mean, None);
        assert_eq!(r2.rpc_error_distinct_codes, None);
        assert_eq!(r2.rpc_error_frac, None);
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

    // ===========================================
    // Test Category — v7 timing + JSON-RPC error
    // (closes A.2 of PLAN-PRODUCTION-FEATURE-SURFACE)
    // ===========================================

    fn ev_ts(direction: Direction, payload: &[u8], ts_ns: u64) -> PayloadEvent {
        let mut e = ev(direction, payload);
        e.ts_ns = ts_ns;
        e
    }

    #[test]
    fn pair_carries_request_start_timestamp_from_first_to_server_event() {
        // Single-event request: req_started_ns = ts_ns of that event.
        let mut h = PayloadHandler::new(64);
        let req = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nBODY";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npayload";
        h.feed(&ev_ts(Direction::ToServer, req, 100_000));
        match h.feed(&ev_ts(Direction::FromServer, resp, 500_000)) {
            FeedOutcome::MessageComplete(Some(pair)) => {
                assert_eq!(pair.req_started_ns, 100_000);
            }
            other => panic!("expected paired RpcPair, got {:?}", other),
        }
    }

    #[test]
    fn pair_carries_response_complete_timestamp_from_completing_event() {
        // resp_completed_ns must be the ts_ns of the FromServer event that
        // drove `body_remaining` to 0 — not the first response event.
        let mut h = PayloadHandler::new(64);
        let req = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nBODY";
        // Response head + first 4 bytes of body in event 1, last 3 bytes in event 2.
        let resp_head = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npayl";
        let resp_tail = b"oad";
        h.feed(&ev_ts(Direction::ToServer, req, 100_000));
        let r1 = h.feed(&ev_ts(Direction::FromServer, resp_head, 500_000));
        assert!(matches!(r1, FeedOutcome::HeadComplete));
        match h.feed(&ev_ts(Direction::FromServer, resp_tail, 700_000)) {
            FeedOutcome::MessageComplete(Some(pair)) => {
                assert_eq!(pair.resp_completed_ns, 700_000,
                    "resp_completed_ns must come from the body-completing event, not the head event");
                assert_eq!(pair.req_started_ns, 100_000);
            }
            other => panic!("expected paired RpcPair, got {:?}", other),
        }
    }

    #[test]
    fn pair_carries_first_event_ts_for_multi_event_request() {
        // Multi-event request: req_started_ns = ts_ns of the FIRST ToServer
        // event for this request, not subsequent ones.
        let mut h = PayloadHandler::new(64);
        let req_head = b"POST / HTTP/1.1\r\nContent-Length: 7\r\n\r\npay";
        let req_tail = b"load";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nBODY";
        h.feed(&ev_ts(Direction::ToServer, req_head, 100_000));
        h.feed(&ev_ts(Direction::ToServer, req_tail, 200_000));
        match h.feed(&ev_ts(Direction::FromServer, resp, 500_000)) {
            FeedOutcome::MessageComplete(Some(pair)) => {
                assert_eq!(pair.req_started_ns, 100_000,
                    "req_started_ns must be the first ToServer event's ts, not the later one");
                assert_eq!(pair.resp_completed_ns, 500_000);
            }
            other => panic!("expected paired RpcPair, got {:?}", other),
        }
    }

    #[test]
    fn jsonrpc_error_envelope_populates_error_code() {
        // JSON-RPC error envelope in response body → rpc_envelope_parsed=true,
        // rpc_error_code=Some(-32602).
        let mut h = PayloadHandler::new(64);
        let req_body: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBlock\"}";
        let req_head = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            req_body.len(),
        );
        let mut req_full = req_head.as_bytes().to_vec();
        req_full.extend_from_slice(req_body);
        let body = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"Invalid params\"}}";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            body.len(),
        );
        let mut resp_full = resp.as_bytes().to_vec();
        resp_full.extend_from_slice(body);
        h.feed(&ev(Direction::ToServer, &req_full));
        match h.feed(&ev(Direction::FromServer, &resp_full)) {
            FeedOutcome::MessageComplete(Some(pair)) => {
                assert!(pair.rpc_envelope_parsed,
                    "JSON-RPC error envelope should mark rpc_envelope_parsed");
                assert_eq!(pair.rpc_error_code, Some(-32602));
            }
            other => panic!("expected paired RpcPair, got {:?}", other),
        }
    }

    #[test]
    fn jsonrpc_success_envelope_marks_parsed_with_no_error() {
        // JSON-RPC success envelope → rpc_envelope_parsed=true, rpc_error_code=None.
        let mut h = PayloadHandler::new(64);
        let req = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nBODY";
        let body = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":42}";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            body.len(),
        );
        let mut resp_full = resp.as_bytes().to_vec();
        resp_full.extend_from_slice(body);
        h.feed(&ev(Direction::ToServer, req));
        match h.feed(&ev(Direction::FromServer, &resp_full)) {
            FeedOutcome::MessageComplete(Some(pair)) => {
                assert!(pair.rpc_envelope_parsed,
                    "valid JSON-RPC success envelope should mark rpc_envelope_parsed");
                assert_eq!(pair.rpc_error_code, None);
            }
            other => panic!("expected paired RpcPair, got {:?}", other),
        }
    }

    #[test]
    fn non_jsonrpc_response_marks_envelope_unparsed() {
        // Non-JSON HTTP response → rpc_envelope_parsed=false, rpc_error_code=None.
        let mut h = PayloadHandler::new(64);
        let req = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nBODY";
        let body = b"<html>not json</html>";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            body.len(),
        );
        let mut resp_full = resp.as_bytes().to_vec();
        resp_full.extend_from_slice(body);
        h.feed(&ev(Direction::ToServer, req));
        match h.feed(&ev(Direction::FromServer, &resp_full)) {
            FeedOutcome::MessageComplete(Some(pair)) => {
                assert!(!pair.rpc_envelope_parsed,
                    "HTML body should NOT parse as JSON-RPC envelope");
                assert_eq!(pair.rpc_error_code, None);
            }
            other => panic!("expected paired RpcPair, got {:?}", other),
        }
    }

    #[test]
    fn oversize_response_body_skips_jsonrpc_parse() {
        // Body > RESP_BODY_BUFFER_CAP (8 KiB) → buffer truncates, parse skipped.
        // Pair must still be produced (timing/status/bytes all work), just
        // without JSON-RPC envelope info.
        let mut h = PayloadHandler::new(64);
        let req = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nBODY";
        let body_size: usize = 12 * 1024;
        let body = vec![b'x'; body_size];
        let resp_head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            body_size,
        );
        let mut resp_full = resp_head.as_bytes().to_vec();
        resp_full.extend_from_slice(&body);
        h.feed(&ev(Direction::ToServer, req));
        match h.feed(&ev(Direction::FromServer, &resp_full)) {
            FeedOutcome::MessageComplete(Some(pair)) => {
                assert!(!pair.rpc_envelope_parsed,
                    "truncated body should not be parsed as JSON-RPC");
                assert_eq!(pair.rpc_error_code, None);
                assert_eq!(pair.response_bytes, body_size as u64,
                    "byte counting still works regardless of buffer truncation");
            }
            other => panic!("expected paired RpcPair, got {:?}", other),
        }
    }
}
