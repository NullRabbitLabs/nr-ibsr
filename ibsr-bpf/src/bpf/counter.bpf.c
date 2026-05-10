// SPDX-License-Identifier: MIT
// IBSR XDP Counter Program
//
// This XDP program performs passive traffic counting for TCP connections.
// It ONLY aggregates counters - it never drops, redirects, or modifies packets.
//
// Safety guarantees (enforced by static analysis):
// - Always returns XDP_PASS (never XDP_DROP, XDP_ABORTED, XDP_REDIRECT, XDP_TX)
// - Uses BPF_MAP_TYPE_LRU_HASH for bounded memory
// - No ringbuf/perf_event output (no per-packet events)
// - No redirect helpers
// - O(1) per-packet work

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// xdp_helpers.h ships with libxdp (xdp-tools). The XDP_RUN_CONFIG()
// macro emits the .xdp_run_config BTF section that libxdp's chained-
// program dispatcher reads to register a program for chaining. Without
// it, attach to a dispatcher fails with EOPNOTSUPP.
#include <xdp/xdp_helpers.h>

// Map key structure - 8 bytes total with explicit padding
// Layout: src_ip(4) + dst_port(2) + _pad(2) = 8 bytes
// This allows per-IP-per-port traffic tracking
struct map_key {
    __u32 src_ip;    // Source IPv4 address (network byte order / MSB-first)
    __u16 dst_port;  // Destination port (host byte order)
    __u16 _pad;      // Explicit padding for 8-byte alignment
};

// Counter structure - must match Rust parsing in bpf_reader.rs exactly
// Layout with natural alignment (u64 requires 8-byte alignment):
//   syn(4) + ack(4) + handshake_ack(4) + rst(4) + packets(4) + _pad(4) + bytes(8) = 32 bytes
// The padding is required because atomic operations on u64 (used by __sync_fetch_and_add)
// require 8-byte alignment, which the BPF verifier enforces.
struct counters {
    __u32 syn;
    __u32 ack;
    __u32 handshake_ack;  // ACKs with no SYN, no RST, and zero payload (handshake completion)
    __u32 rst;
    __u32 packets;
    __u32 _pad;           // Explicit padding for 8-byte alignment of bytes field
    __u64 bytes;
};

// Configuration map - holds destination ports to monitor (up to 8)
// Index 0-7 = dst_ports (network byte order, 0 = unused slot)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u16);
} config_map SEC(".maps");

// Counter map - LRU hash for bounded memory usage
// Key: (source IP, destination port) composite key
// Value: counter structure
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct map_key);
    __type(value, struct counters);
} counter_map SEC(".maps");

// Dispatcher chain registration.
//   priority=50 (default observation tier; nr-guard's enforcement runs
//                earlier, around 30, so banned IPs are dropped before
//                we waste cycles counting them — that's the production
//                ordering)
//   XDP_PASS=1 (chain continues to subsequent programs after we PASS;
//               we ALWAYS PASS so this is the only relevant action)
struct {
    __uint(priority, 50);
    __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_counter);

SEC("xdp")
int xdp_counter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Only process TCP packets
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Calculate IP header length (IHL is in 32-bit words)
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    // Parse TCP header
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Check if packet matches any configured destination port (manually unrolled)
    // Short-circuit after first match to avoid unnecessary map lookups
    __u16 matched_port = 0;
    __u32 cfg_key;
    __u16 *port_cfg;

    cfg_key = 0; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->dest == *port_cfg) { matched_port = bpf_ntohs(*port_cfg); goto port_matched; }

    cfg_key = 1; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->dest == *port_cfg) { matched_port = bpf_ntohs(*port_cfg); goto port_matched; }

    cfg_key = 2; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->dest == *port_cfg) { matched_port = bpf_ntohs(*port_cfg); goto port_matched; }

    cfg_key = 3; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->dest == *port_cfg) { matched_port = bpf_ntohs(*port_cfg); goto port_matched; }

    cfg_key = 4; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->dest == *port_cfg) { matched_port = bpf_ntohs(*port_cfg); goto port_matched; }

    cfg_key = 5; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->dest == *port_cfg) { matched_port = bpf_ntohs(*port_cfg); goto port_matched; }

    cfg_key = 6; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->dest == *port_cfg) { matched_port = bpf_ntohs(*port_cfg); goto port_matched; }

    cfg_key = 7; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->dest == *port_cfg) { matched_port = bpf_ntohs(*port_cfg); goto port_matched; }

    // No port matched
    return XDP_PASS;

port_matched:
    ; // Empty statement required before declaration in C
    // Extract source IP (keep network byte order / MSB-first for consistent representation)
    __u32 src_ip = ip->saddr;

    // Build composite map key (src_ip + dst_port)
    struct map_key mkey = {
        .src_ip = src_ip,
        .dst_port = matched_port,
        ._pad = 0,
    };

    // Calculate packet size (total Ethernet frame)
    __u64 pkt_len = data_end - data;

    // Calculate TCP header length and payload length for handshake ACK detection
    __u32 tcp_hdr_len = tcp->doff * 4;
    __u32 ip_total_len = bpf_ntohs(ip->tot_len);
    // Bounds check to prevent underflow
    __u32 tcp_payload_len = 0;
    if (ip_total_len > ip_hdr_len + tcp_hdr_len)
        tcp_payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;

    // Handshake ACK: ACK set, SYN not set, RST not set, no payload
    int is_handshake_ack = tcp->ack && !tcp->syn && !tcp->rst && (tcp_payload_len == 0);

    // Look up or initialize counters for this (src_ip, dst_port) pair
    struct counters *ctr = bpf_map_lookup_elem(&counter_map, &mkey);
    if (ctr) {
        // Update existing counters
        __sync_fetch_and_add(&ctr->packets, 1);
        __sync_fetch_and_add(&ctr->bytes, pkt_len);

        // Check TCP flags
        if (tcp->syn)
            __sync_fetch_and_add(&ctr->syn, 1);
        if (tcp->ack)
            __sync_fetch_and_add(&ctr->ack, 1);
        if (is_handshake_ack)
            __sync_fetch_and_add(&ctr->handshake_ack, 1);
        if (tcp->rst)
            __sync_fetch_and_add(&ctr->rst, 1);
    } else {
        // Initialize new counter entry (designated initializer zeros _pad)
        struct counters new_ctr = {
            .syn = tcp->syn ? 1 : 0,
            .ack = tcp->ack ? 1 : 0,
            .handshake_ack = is_handshake_ack ? 1 : 0,
            .rst = tcp->rst ? 1 : 0,
            .packets = 1,
            ._pad = 0,
            .bytes = pkt_len,
        };
        bpf_map_update_elem(&counter_map, &mkey, &new_ctr, BPF_ANY);
    }

    // Always pass the packet - we never drop or redirect
    return XDP_PASS;
}

// ─────────────────────────────────────────────────────────────────
// TC egress counter — observes packets leaving the interface (the
// server's responses). Mirrors xdp_counter's per-(src_ip, dst_port)
// aggregation but for the response direction:
//   - matches packets where tcp->source ∈ watched_ports (server is
//     replying from a watched server-side port)
//   - keys the counter map by (peer_ip = packet's dst_ip,
//     server_port = packet's src_port) — same shape as XDP ingress's
//     key (src_ip = scanner, dst_port = watched), so both directions
//     aggregate into the same bucket
//
// This closes the V9 close-gate finding (2026-05-08): pcap on the
// bridge captured 8 RSTs during a port scan; XDP-ingress-only
// counter saw 1. The missing 7 are the egress RSTs from closed-port
// responses, which only TC egress can observe.
//
// Safety: same as XDP — TC_ACT_OK (passes the packet), no drop / no
// modify; counters only.

#include <linux/pkt_cls.h>

SEC("classifier")
int tc_egress_counter(struct __sk_buff *skb)
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

    // Egress direction: match on tcp->source (the server's replying
    // port), not tcp->dest. Manually unrolled to mirror XDP's pattern.
    __u16 matched_port = 0;
    __u32 cfg_key;
    __u16 *port_cfg;

    cfg_key = 0; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->source == *port_cfg) { matched_port = bpf_ntohs(*port_cfg); goto egress_matched; }
    cfg_key = 1; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->source == *port_cfg) { matched_port = bpf_ntohs(*port_cfg); goto egress_matched; }
    cfg_key = 2; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->source == *port_cfg) { matched_port = bpf_ntohs(*port_cfg); goto egress_matched; }
    cfg_key = 3; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->source == *port_cfg) { matched_port = bpf_ntohs(*port_cfg); goto egress_matched; }
    cfg_key = 4; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->source == *port_cfg) { matched_port = bpf_ntohs(*port_cfg); goto egress_matched; }
    cfg_key = 5; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->source == *port_cfg) { matched_port = bpf_ntohs(*port_cfg); goto egress_matched; }
    cfg_key = 6; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->source == *port_cfg) { matched_port = bpf_ntohs(*port_cfg); goto egress_matched; }
    cfg_key = 7; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->source == *port_cfg) { matched_port = bpf_ntohs(*port_cfg); goto egress_matched; }

    return TC_ACT_OK;

egress_matched:
    ;
    // Key by (dst_ip, src_port) — the dst_ip on egress IS the
    // peer/scanner; the src_port IS the watched server port. Same
    // bucket-shape as ingress so directional counts aggregate.
    __u32 peer_ip = ip->daddr;
    struct map_key mkey = {
        .src_ip = peer_ip,
        .dst_port = matched_port,
        ._pad = 0,
    };

    __u64 pkt_len = data_end - data;

    __u32 tcp_hdr_len = tcp->doff * 4;
    __u32 ip_total_len = bpf_ntohs(ip->tot_len);
    __u32 tcp_payload_len = 0;
    if (ip_total_len > ip_hdr_len + tcp_hdr_len)
        tcp_payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;
    int is_handshake_ack = tcp->ack && !tcp->syn && !tcp->rst && (tcp_payload_len == 0);

    struct counters *ctr = bpf_map_lookup_elem(&counter_map, &mkey);
    if (ctr) {
        __sync_fetch_and_add(&ctr->packets, 1);
        __sync_fetch_and_add(&ctr->bytes, pkt_len);
        if (tcp->syn)
            __sync_fetch_and_add(&ctr->syn, 1);
        if (tcp->ack)
            __sync_fetch_and_add(&ctr->ack, 1);
        if (is_handshake_ack)
            __sync_fetch_and_add(&ctr->handshake_ack, 1);
        if (tcp->rst)
            __sync_fetch_and_add(&ctr->rst, 1);
    } else {
        struct counters new_ctr = {
            .syn = tcp->syn ? 1 : 0,
            .ack = tcp->ack ? 1 : 0,
            .handshake_ack = is_handshake_ack ? 1 : 0,
            .rst = tcp->rst ? 1 : 0,
            .packets = 1,
            ._pad = 0,
            .bytes = pkt_len,
        };
        bpf_map_update_elem(&counter_map, &mkey, &new_ctr, BPF_ANY);
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "MIT";
