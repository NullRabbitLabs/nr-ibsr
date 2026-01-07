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

// Map key structure - 8 bytes total with explicit padding
// Layout: src_ip(4) + dst_port(2) + _pad(2) = 8 bytes
// This allows per-IP-per-port traffic tracking
struct map_key {
    __u32 src_ip;    // Source IPv4 address (host byte order)
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
    // Capture the matched port in host byte order for use as map key
    __u16 matched_port = 0;
    __u32 cfg_key;
    __u16 *port_cfg;

    cfg_key = 0; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->dest == *port_cfg) matched_port = bpf_ntohs(*port_cfg);

    cfg_key = 1; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->dest == *port_cfg) matched_port = bpf_ntohs(*port_cfg);

    cfg_key = 2; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->dest == *port_cfg) matched_port = bpf_ntohs(*port_cfg);

    cfg_key = 3; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->dest == *port_cfg) matched_port = bpf_ntohs(*port_cfg);

    cfg_key = 4; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->dest == *port_cfg) matched_port = bpf_ntohs(*port_cfg);

    cfg_key = 5; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->dest == *port_cfg) matched_port = bpf_ntohs(*port_cfg);

    cfg_key = 6; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->dest == *port_cfg) matched_port = bpf_ntohs(*port_cfg);

    cfg_key = 7; port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (port_cfg && *port_cfg != 0 && tcp->dest == *port_cfg) matched_port = bpf_ntohs(*port_cfg);

    if (matched_port == 0)
        return XDP_PASS;

    // Extract source IP (convert to host byte order for consistent key)
    __u32 src_ip = bpf_ntohl(ip->saddr);

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

char LICENSE[] SEC("license") = "MIT";
