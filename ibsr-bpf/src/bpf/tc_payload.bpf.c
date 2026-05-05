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
// fixed-width fields, explicit padding, repr(C) match required.
//
// `payload_len`: full TCP payload bytes in this packet (could exceed
// `sample_len` if the packet is larger than PAYLOAD_SAMPLE_BYTES).
// `sample_len`: bytes actually copied into `payload[]`, ≤ PAYLOAD_SAMPLE_BYTES.
struct payload_event {
    struct flow_id flow;
    __u32 direction;
    __u32 tcp_seq;
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

    __u32 sample_len =
        payload_len > PAYLOAD_SAMPLE_BYTES ? PAYLOAD_SAMPLE_BYTES : payload_len;

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
    ev->ts_ns = bpf_ktime_get_ns();
    ev->payload_len = payload_len;
    ev->sample_len = sample_len;

    // Payload offset from skb start: L2 + IP + TCP header lengths.
    __u32 payload_offset =
        sizeof(struct ethhdr) + ip_hdr_len + tcp_hdr_len;

    long rc = bpf_skb_load_bytes(skb, payload_offset, ev->payload, sample_len);
    if (rc < 0) {
        // Couldn't read payload (shouldn't happen given we already checked
        // payload_len ≥ sample_len, but verifier requires the check).
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
