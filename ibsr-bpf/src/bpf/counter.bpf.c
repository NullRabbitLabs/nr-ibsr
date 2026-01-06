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

// Counter structure - must match Rust Counters struct exactly
// Layout: syn(4) + ack(4) + rst(4) + packets(4) + bytes(8) = 24 bytes
struct counters {
    __u32 syn;
    __u32 ack;
    __u32 rst;
    __u32 packets;
    __u64 bytes;
};

// Configuration map - holds the destination port to monitor
// Index 0 = dst_port (network byte order)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} config_map SEC(".maps");

// Counter map - LRU hash for bounded memory usage
// Key: source IPv4 address (host byte order)
// Value: counter structure
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
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

    // Get configured destination port
    __u32 cfg_key = 0;
    __u16 *dst_port_cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!dst_port_cfg)
        return XDP_PASS;

    // Check if packet matches our destination port
    if (tcp->dest != *dst_port_cfg)
        return XDP_PASS;

    // Extract source IP (convert to host byte order for consistent key)
    __u32 src_ip = bpf_ntohl(ip->saddr);

    // Calculate packet size
    __u64 pkt_len = data_end - data;

    // Look up or initialize counters for this source IP
    struct counters *ctr = bpf_map_lookup_elem(&counter_map, &src_ip);
    if (ctr) {
        // Update existing counters
        __sync_fetch_and_add(&ctr->packets, 1);
        __sync_fetch_and_add(&ctr->bytes, pkt_len);

        // Check TCP flags
        if (tcp->syn)
            __sync_fetch_and_add(&ctr->syn, 1);
        if (tcp->ack)
            __sync_fetch_and_add(&ctr->ack, 1);
        if (tcp->rst)
            __sync_fetch_and_add(&ctr->rst, 1);
    } else {
        // Initialize new counter entry
        struct counters new_ctr = {
            .syn = tcp->syn ? 1 : 0,
            .ack = tcp->ack ? 1 : 0,
            .rst = tcp->rst ? 1 : 0,
            .packets = 1,
            .bytes = pkt_len,
        };
        bpf_map_update_elem(&counter_map, &src_ip, &new_ctr, BPF_ANY);
    }

    // Always pass the packet - we never drop or redirect
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "MIT";
