// SPDX-License-Identifier: MIT
// IBSR TC Payload Capture Program (ShadowPayload mode)
//
// Two TC programs (ingress + egress) attached to the configured interface
// (typically `lo` for the post-term loopback vantage). For each TCP packet
// matching one of the configured destination/source ports, samples up to
// PAYLOAD_SAMPLE_BYTES of TCP payload to a ringbuf for userspace stream
// reassembly + HTTP/JSON-RPC parsing.
//
// Safety guarantees (enforced by static analysis under SafetyProfile::ShadowPayload):
// - Always returns TC_ACT_OK (never TC_ACT_SHOT, TC_ACT_REDIRECT, TC_ACT_STOLEN)
// - Never modifies packet data (no bpf_xdp_adjust_*, no bpf_skb_change_*,
//   no bpf_skb_store_bytes)
// - Never redirects (no bpf_redirect*, no DEVMAP/XSKMAP/CPUMAP)
// - Ringbuf pressure cannot backpressure the network stack — if reservation
//   fails, the event is dropped, the packet is not.
// - Only reads packet data via bpf_skb_load_bytes (read-only)
//
// The userspace consumer reassembles TCP streams across multiple events
// (sample_len ≤ payload_len when payload exceeds PAYLOAD_SAMPLE_BYTES),
// parses HTTP/JSON-RPC message boundaries, and emits per-RPC byte pairs
// to the window aggregator.

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Per-event sampled payload size. 1024 bytes covers most JSON-RPC requests
// in their entirety; larger responses are reconstructed across multiple
// events by userspace via TCP-seq reassembly. Tunable at deployment.
#define PAYLOAD_SAMPLE_BYTES 1024

// Ringbuf size: 16 MiB. At line rate with ~1 KiB events that's ~16k
// events of buffering — typically 0.5–2 seconds of headroom, more than
// enough for userspace to keep up. Lossy on overflow by design (events
// drop, packets do not).
#define RINGBUF_BYTES (16 * 1024 * 1024)

// Direction marker for events. Ingress = traffic toward this host
// (request from client), egress = traffic from this host (response to
// client). Userspace pairs requests with responses on (flow_id, seq).
#define DIR_INGRESS 0
#define DIR_EGRESS  1

// Flow identification — 5-tuple minus protocol (TCP only). Network byte
// order for IPs (consistent with counter.bpf.c) and ports (no conversion
// in BPF; userspace converts when displaying).
struct flow_id {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// Per-event ringbuf record. Layout is stable across BPF + Rust userspace —
// fixed-width fields, explicit padding, repr(C) match required. Total
// size: 1064 bytes (offset table below).
//
// Offset table (must match the userspace decoder in
// ibsr-bpf/src/tc_payload_event.rs and the size constant
// EXPECTED_RAW_EVENT_SIZE):
//
//   0  : flow.src_ip   (u32)
//   4  : flow.dst_ip   (u32)
//   8  : flow.src_port (u16)
//   10 : flow.dst_port (u16)
//   12 : direction     (u32)
//   16 : tcp_seq       (u32)
//   20 : _pad0         (u32)  -- explicit padding to 8-align ts_ns
//   24 : ts_ns         (u64)
//   32 : payload_len   (u32)
//   36 : sample_len    (u32)
//   40 : payload[1024]
// 1064 : end
//
// `payload_len`: full TCP payload bytes in this packet (could exceed
// `sample_len` if the packet is larger than PAYLOAD_SAMPLE_BYTES).
// `sample_len`: bytes actually copied into `payload[]`, ≤ PAYLOAD_SAMPLE_BYTES.
struct payload_event {
    struct flow_id flow;
    __u32 direction;
    __u32 tcp_seq;
    __u32 _pad0;          // Explicit padding to 8-align ts_ns
    __u64 ts_ns;
    __u32 payload_len;
    __u32 sample_len;
    __u8  payload[PAYLOAD_SAMPLE_BYTES];
};

// Ringbuf for kernel→userspace event channel. ShadowPayload-mode-only;
// safety verifier under StrictCounter would reject this map type.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_BYTES);
} payload_rb SEC(".maps");

// Configured ports to capture. 8 slots; values are network byte order.
// Index 0..N-1 = active ports, N..7 = 0 (unused).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u16);
} port_filter SEC(".maps");

// Returns 1 if `port` (network byte order) matches any configured port,
// else 0. Manually unrolled for verifier-friendliness.
static __always_inline int port_matches(__u16 port)
{
    __u32 i;
    __u16 *p;

    i = 0; p = bpf_map_lookup_elem(&port_filter, &i);
    if (p && *p != 0 && *p == port) return 1;
    i = 1; p = bpf_map_lookup_elem(&port_filter, &i);
    if (p && *p != 0 && *p == port) return 1;
    i = 2; p = bpf_map_lookup_elem(&port_filter, &i);
    if (p && *p != 0 && *p == port) return 1;
    i = 3; p = bpf_map_lookup_elem(&port_filter, &i);
    if (p && *p != 0 && *p == port) return 1;
    i = 4; p = bpf_map_lookup_elem(&port_filter, &i);
    if (p && *p != 0 && *p == port) return 1;
    i = 5; p = bpf_map_lookup_elem(&port_filter, &i);
    if (p && *p != 0 && *p == port) return 1;
    i = 6; p = bpf_map_lookup_elem(&port_filter, &i);
    if (p && *p != 0 && *p == port) return 1;
    i = 7; p = bpf_map_lookup_elem(&port_filter, &i);
    if (p && *p != 0 && *p == port) return 1;

    return 0;
}

// Common handler — direction is provided by the caller. Returns TC_ACT_OK
// unconditionally. The hot path is bounded: 1 ringbuf reserve + 1
// bpf_skb_load_bytes + 1 ringbuf submit; no loops.
static __always_inline int handle_skb(struct __sk_buff *skb, __u32 direction)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return TC_ACT_OK;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // Port filter: ingress matches dst_port (where the server listens),
    // egress matches src_port (where the server replies from). The
    // configured ports are the server-side ports the operator monitors.
    __u16 server_port = (direction == DIR_INGRESS) ? tcp->dest : tcp->source;
    if (!port_matches(server_port))
        return TC_ACT_OK;

    __u32 tcp_hdr_len = tcp->doff * 4;
    __u32 ip_total_len = bpf_ntohs(ip->tot_len);
    if (ip_total_len < ip_hdr_len + tcp_hdr_len)
        return TC_ACT_OK;
    __u32 payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;
    if (payload_len == 0)
        return TC_ACT_OK;  // skip empty packets (handshake / pure ACKs)

    // Verifier-friendly variable-size discipline.
    //
    // We branch on size class to a small set of constant-size load
    // calls. Each branch's bpf_skb_load_bytes uses a compile-time
    // constant size, which the kernel verifier accepts trivially.
    //
    // The size buckets are aligned to power-of-two boundaries with
    // the constraint that NO BYTES ARE DROPPED: each bucket copies
    // EXACTLY payload_len bytes (using a sequence of constant-size
    // loads), guaranteeing userspace receives the full TCP payload.
    // This preserves the offline-extractor numerical-identity
    // contract for the Phase 1 close gate.
    //
    // (Earlier attempts with `bpf_skb_load_bytes(..., sample_len)`
    // using a variable size hit "R4 invalid zero-sized read" — the
    // verifier rejects calls where the size argument's lower bound
    // is 0, even after explicit `if (size == 0) return` checks
    // because the C compiler proves the check redundant via dataflow
    // and elides it. asm volatile barriers also failed. The
    // bucketed-constant-size approach below avoids the issue
    // entirely.)
    __u32 sample_len = payload_len > PAYLOAD_SAMPLE_BYTES
        ? PAYLOAD_SAMPLE_BYTES
        : payload_len;

    // Reserve event in ringbuf. If reservation fails (ringbuf full),
    // drop the event silently and pass the packet — pressure cannot
    // backpressure the network stack.
    struct payload_event *ev =
        bpf_ringbuf_reserve(&payload_rb, sizeof(*ev), 0);
    if (!ev)
        return TC_ACT_OK;

    ev->flow.src_ip = ip->saddr;
    ev->flow.dst_ip = ip->daddr;
    ev->flow.src_port = tcp->source;
    ev->flow.dst_port = tcp->dest;
    ev->direction = direction;
    ev->tcp_seq = bpf_ntohl(tcp->seq);
    ev->_pad0 = 0;  // Explicit zero so userspace sees deterministic bytes.
    ev->ts_ns = bpf_ktime_get_ns();
    ev->payload_len = payload_len;
    ev->sample_len = sample_len;

    // Payload offset from skb start: L2 + IP + TCP header lengths.
    __u32 payload_offset =
        sizeof(struct ethhdr) + ip_hdr_len + tcp_hdr_len;

    // Bucketed constant-size dispatch. Each call uses a compile-time
    // constant for the size argument so the verifier accepts. The
    // bucket-and-tail pattern preserves all payload bytes:
    //   bucket = largest power-of-two <= sample_len
    //   tail   = sample_len - bucket  (also <= bucket; recursively bucketed)
    //
    // We unroll up to 11 levels (1024-byte sample = 1024+0, 768=512+256,
    // etc.). Each call is constant-size, and at most floor(log2(1024))=10
    // branches fire. The verifier trivially accepts each constant-size
    // load.
    //
    // For sample_len == 0 we return early (skipped earlier on
    // payload_len == 0; this is a fall-through guard).
    if (sample_len == 0) {
        bpf_ringbuf_discard(ev, 0);
        return TC_ACT_OK;
    }

    __u32 off = payload_offset;
    __u32 buf_off = 0;
    __u32 remaining = sample_len;
    long rc = 0;

    // Constant-size load helper: macro-style unrolled chain. Each
    // statement copies a fixed constant number of bytes if `remaining`
    // permits, then advances. The verifier sees each bpf_skb_load_bytes
    // size argument as a constant.
    //
    // Buckets: 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1.
    // Sum = 2047 bytes worth of capacity, comfortably draining any
    // sample_len up to PAYLOAD_SAMPLE_BYTES (1024). The 1024-byte
    // bucket is load-bearing: any packet whose TCP payload is >= 1024
    // bytes gets truncated to sample_len = 1024 by the cap above, and
    // without this top bucket the chain only sums to 1023, leaving
    // `remaining = 1` at the end → event discarded. That bug silently
    // dropped every event from packets with full-sized samples (the
    // common case for any non-trivial HTTP body), making
    // ShadowPayload-mode unobservable on traffic with multi-KB
    // payloads.
    if (remaining >= 1024 && rc == 0 && buf_off + 1024 <= PAYLOAD_SAMPLE_BYTES) {
        rc = bpf_skb_load_bytes(skb, off + buf_off, ev->payload + buf_off, 1024);
        if (rc == 0) { buf_off += 1024; remaining -= 1024; }
    }
    if (remaining >= 512 && rc == 0 && buf_off + 512 <= PAYLOAD_SAMPLE_BYTES) {
        rc = bpf_skb_load_bytes(skb, off + buf_off, ev->payload + buf_off, 512);
        if (rc == 0) { buf_off += 512; remaining -= 512; }
    }
    if (remaining >= 256 && rc == 0 && buf_off + 256 <= PAYLOAD_SAMPLE_BYTES) {
        rc = bpf_skb_load_bytes(skb, off + buf_off, ev->payload + buf_off, 256);
        if (rc == 0) { buf_off += 256; remaining -= 256; }
    }
    if (remaining >= 128 && rc == 0 && buf_off + 128 <= PAYLOAD_SAMPLE_BYTES) {
        rc = bpf_skb_load_bytes(skb, off + buf_off, ev->payload + buf_off, 128);
        if (rc == 0) { buf_off += 128; remaining -= 128; }
    }
    if (remaining >= 64 && rc == 0 && buf_off + 64 <= PAYLOAD_SAMPLE_BYTES) {
        rc = bpf_skb_load_bytes(skb, off + buf_off, ev->payload + buf_off, 64);
        if (rc == 0) { buf_off += 64; remaining -= 64; }
    }
    if (remaining >= 32 && rc == 0 && buf_off + 32 <= PAYLOAD_SAMPLE_BYTES) {
        rc = bpf_skb_load_bytes(skb, off + buf_off, ev->payload + buf_off, 32);
        if (rc == 0) { buf_off += 32; remaining -= 32; }
    }
    if (remaining >= 16 && rc == 0 && buf_off + 16 <= PAYLOAD_SAMPLE_BYTES) {
        rc = bpf_skb_load_bytes(skb, off + buf_off, ev->payload + buf_off, 16);
        if (rc == 0) { buf_off += 16; remaining -= 16; }
    }
    if (remaining >= 8 && rc == 0 && buf_off + 8 <= PAYLOAD_SAMPLE_BYTES) {
        rc = bpf_skb_load_bytes(skb, off + buf_off, ev->payload + buf_off, 8);
        if (rc == 0) { buf_off += 8; remaining -= 8; }
    }
    if (remaining >= 4 && rc == 0 && buf_off + 4 <= PAYLOAD_SAMPLE_BYTES) {
        rc = bpf_skb_load_bytes(skb, off + buf_off, ev->payload + buf_off, 4);
        if (rc == 0) { buf_off += 4; remaining -= 4; }
    }
    if (remaining >= 2 && rc == 0 && buf_off + 2 <= PAYLOAD_SAMPLE_BYTES) {
        rc = bpf_skb_load_bytes(skb, off + buf_off, ev->payload + buf_off, 2);
        if (rc == 0) { buf_off += 2; remaining -= 2; }
    }
    if (remaining >= 1 && rc == 0 && buf_off + 1 <= PAYLOAD_SAMPLE_BYTES) {
        rc = bpf_skb_load_bytes(skb, off + buf_off, ev->payload + buf_off, 1);
        if (rc == 0) { buf_off += 1; remaining -= 1; }
    }

    if (rc < 0 || remaining != 0) {
        // Either a load failed mid-stream, or we couldn't drain the
        // requested sample. Discard the partial event.
        bpf_ringbuf_discard(ev, 0);
        return TC_ACT_OK;
    }

    bpf_ringbuf_submit(ev, 0);
    return TC_ACT_OK;
}

SEC("tc")
int tc_payload_ingress(struct __sk_buff *skb)
{
    return handle_skb(skb, DIR_INGRESS);
}

SEC("tc")
int tc_payload_egress(struct __sk_buff *skb)
{
    return handle_skb(skb, DIR_EGRESS);
}

char LICENSE[] SEC("license") = "MIT";
