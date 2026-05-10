// SPDX-License-Identifier: MIT
// IBSR TC Record-Incident Program (CF-style sampled packet capture)
//
// Two TC programs (ingress + egress) attached to the configured
// interface. For every packet, decrements a per-CPU sampling counter;
// when the counter reaches zero, samples up to SNAPLEN_BYTES of the
// packet header into a ringbuf and resets the counter to (sample_rate
// - 1). The userspace consumer turns ringbuf events into pcap records.
//
// Mode: re-uses SafetyProfile::ShadowPayload (TC + ringbuf, no drops).
// Safety guarantees (mechanically enforced by safety verifier):
// - Always returns TC_ACT_OK (never SHOT/REDIRECT/STOLEN/TRAP).
// - Never modifies packet data or headers.
// - Ringbuf pressure cannot backpressure the network stack — if
//   reservation fails, event is dropped, packet is TC_ACT_OK'd.
//
// Sampling design (pre-registered in
// docs/CF-INCIDENT-RECORDING-DESIGN-V1.md §1): per-CPU decrement
// counter. Non-uniform across asymmetric NIC queues by design — the
// trade-off bought us an uncontended hot path. Operators who need
// uniform sampling pick a different system; record-incident's
// contract is "approximately 1-in-N over the aggregate of all CPUs".

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Snaplen — 256 bytes captures Ethernet (14) + IPv4 (20) + TCP (20)
// + ~200 bytes of payload. Sufficient for incident triage; larger
// snaplens add storage cost without proportional analytical value at
// the recording tier.
#define SNAPLEN_BYTES 256

// Ringbuf size: 8 MiB. Smaller than tc_payload (16 MiB) because
// snaplen-256 events are ~4× smaller than the 1024-byte payload
// events tc_payload emits, so equivalent headroom in event count.
// Lossy on overflow by design.
#define RINGBUF_BYTES (8 * 1024 * 1024)

// Direction marker.
#define DIR_INGRESS 0
#define DIR_EGRESS  1

// Per-event ringbuf record. Layout is stable across BPF + Rust
// userspace — fixed-width fields, explicit padding, repr(C) match
// required.
//
// Offset table (must match userspace decoder + EXPECTED_RAW_EVENT_SIZE):
//
//   0  : ts_ns       (u64)
//   8  : ifindex     (u32)
//  12  : direction   (u32)
//  16  : wire_len    (u32)   -- original on-wire length
//  20  : cap_len     (u32)   -- bytes copied into pkt[]
//  24  : pkt[256]
// 280  : end
struct packet_event {
    __u64 ts_ns;
    __u32 ifindex;
    __u32 direction;
    __u32 wire_len;
    __u32 cap_len;
    __u8  pkt[SNAPLEN_BYTES];
};

// Ringbuf: kernel→userspace event channel.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_BYTES);
} packet_rb SEC(".maps");

// Per-CPU decrement counter. Single slot. Each CPU maintains its
// own count; when it reaches zero, the next packet on that CPU is
// sampled and the counter resets to (sample_rate - 1).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sample_counter SEC(".maps");

// Phase 2 config_map: 4 u64 slots indexed by `enum config_key`.
// Shared between the BPF program (reads SAMPLE_RATE on counter reset
// + SAMPLING_ACTIVE on every packet) and the userspace trigger
// socket (writes all 4 atomically per Phase 3 trigger commands).
//
// Layout:
//   key 0  CFG_SAMPLE_RATE        u64 (1..=N; 0 means "treat as 1")
//   key 1  CFG_SAMPLING_ACTIVE    u64 bool (0 = passthrough, 1 = active)
//   key 2  CFG_INCIDENT_TAG_HASH  u64 fnv1a-64 hash of tag string
//   key 3  CFG_TRIGGER_TIMESTAMP  u64 unix-seconds when current trigger fired
//
// Phase 1's `sample_rate_cfg` is folded into key 0 of this map.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} config_map SEC(".maps");

// Config-map keys. Kept in sync with the userspace `ConfigKey` enum.
#define CFG_SAMPLE_RATE        0
#define CFG_SAMPLING_ACTIVE    1
#define CFG_INCIDENT_TAG_HASH  2
#define CFG_TRIGGER_TIMESTAMP  3

// Common handler — direction is provided by the caller. Always
// returns TC_ACT_OK. Hot path is bounded: 1 per-CPU lookup, 1
// branch, and only 1-in-rate of: 1 array lookup + 1 ringbuf
// reserve + bucketed bpf_skb_load_bytes + 1 ringbuf submit.
static __always_inline int handle_skb(struct __sk_buff *skb, __u32 direction)
{
    // CFG_SAMPLING_ACTIVE gate. When 0 (the default for an
    // unconfigured map slot, and the explicit `stop` state from the
    // trigger socket), do nothing — full passthrough, no counter
    // decrement, no ringbuf reserve.
    __u32 active_key = CFG_SAMPLING_ACTIVE;
    __u64 *active = bpf_map_lookup_elem(&config_map, &active_key);
    if (!active || *active == 0)
        return TC_ACT_OK;

    __u32 zero = 0;
    __u64 *counter = bpf_map_lookup_elem(&sample_counter, &zero);
    if (!counter)
        return TC_ACT_OK;

    if (*counter > 0) {
        (*counter)--;
        return TC_ACT_OK;
    }

    // *counter == 0: sample this packet, then reset.
    __u32 rate_key = CFG_SAMPLE_RATE;
    __u64 *rate = bpf_map_lookup_elem(&config_map, &rate_key);
    __u64 r = rate ? *rate : 1;
    // Reset to rate-1 so the next (rate-1) packets are skipped and
    // the rate-th one is sampled. r<=1 keeps counter at 0 (sample
    // every packet).
    *counter = (r > 1) ? (r - 1) : 0;

    // Determine cap_len = min(skb->len, SNAPLEN_BYTES).
    __u32 wire_len = skb->len;
    __u32 cap_len = wire_len > SNAPLEN_BYTES ? SNAPLEN_BYTES : wire_len;
    if (cap_len == 0)
        return TC_ACT_OK;  // empty packet — nothing to record

    // Reserve event in ringbuf. If reservation fails (ringbuf full),
    // drop the event silently and pass the packet — pressure cannot
    // backpressure the network stack.
    struct packet_event *ev =
        bpf_ringbuf_reserve(&packet_rb, sizeof(*ev), 0);
    if (!ev)
        return TC_ACT_OK;

    ev->ts_ns = bpf_ktime_get_ns();
    ev->ifindex = skb->ifindex;
    ev->direction = direction;
    ev->wire_len = wire_len;
    ev->cap_len = cap_len;

    // Bucketed constant-size dispatch. Each bpf_skb_load_bytes call
    // uses a compile-time-constant size argument so the verifier
    // accepts trivially. The bucket-and-tail pattern preserves all
    // bytes up to cap_len. Same pattern as tc_payload.bpf.c (proven
    // verifier-friendly at production load).
    //
    // Buckets: 256, 128, 64, 32, 16, 8, 4, 2, 1.
    // Top bucket (256) is load-bearing — without it, the chain only
    // sums to 255 and a 256-byte capture would be lost (the
    // tc_payload bug we already burned on once).
    __u32 buf_off = 0;
    __u32 remaining = cap_len;
    long rc = 0;

    if (remaining >= 256 && rc == 0 && buf_off + 256 <= SNAPLEN_BYTES) {
        rc = bpf_skb_load_bytes(skb, buf_off, ev->pkt + buf_off, 256);
        if (rc == 0) { buf_off += 256; remaining -= 256; }
    }
    if (remaining >= 128 && rc == 0 && buf_off + 128 <= SNAPLEN_BYTES) {
        rc = bpf_skb_load_bytes(skb, buf_off, ev->pkt + buf_off, 128);
        if (rc == 0) { buf_off += 128; remaining -= 128; }
    }
    if (remaining >= 64 && rc == 0 && buf_off + 64 <= SNAPLEN_BYTES) {
        rc = bpf_skb_load_bytes(skb, buf_off, ev->pkt + buf_off, 64);
        if (rc == 0) { buf_off += 64; remaining -= 64; }
    }
    if (remaining >= 32 && rc == 0 && buf_off + 32 <= SNAPLEN_BYTES) {
        rc = bpf_skb_load_bytes(skb, buf_off, ev->pkt + buf_off, 32);
        if (rc == 0) { buf_off += 32; remaining -= 32; }
    }
    if (remaining >= 16 && rc == 0 && buf_off + 16 <= SNAPLEN_BYTES) {
        rc = bpf_skb_load_bytes(skb, buf_off, ev->pkt + buf_off, 16);
        if (rc == 0) { buf_off += 16; remaining -= 16; }
    }
    if (remaining >= 8 && rc == 0 && buf_off + 8 <= SNAPLEN_BYTES) {
        rc = bpf_skb_load_bytes(skb, buf_off, ev->pkt + buf_off, 8);
        if (rc == 0) { buf_off += 8; remaining -= 8; }
    }
    if (remaining >= 4 && rc == 0 && buf_off + 4 <= SNAPLEN_BYTES) {
        rc = bpf_skb_load_bytes(skb, buf_off, ev->pkt + buf_off, 4);
        if (rc == 0) { buf_off += 4; remaining -= 4; }
    }
    if (remaining >= 2 && rc == 0 && buf_off + 2 <= SNAPLEN_BYTES) {
        rc = bpf_skb_load_bytes(skb, buf_off, ev->pkt + buf_off, 2);
        if (rc == 0) { buf_off += 2; remaining -= 2; }
    }
    if (remaining >= 1 && rc == 0 && buf_off + 1 <= SNAPLEN_BYTES) {
        rc = bpf_skb_load_bytes(skb, buf_off, ev->pkt + buf_off, 1);
        if (rc == 0) { buf_off += 1; remaining -= 1; }
    }

    if (rc < 0 || remaining != 0) {
        // Either a load failed or we couldn't drain. Discard partial.
        bpf_ringbuf_discard(ev, 0);
        return TC_ACT_OK;
    }

    bpf_ringbuf_submit(ev, 0);
    return TC_ACT_OK;
}

SEC("tc")
int tc_record_ingress(struct __sk_buff *skb)
{
    return handle_skb(skb, DIR_INGRESS);
}

SEC("tc")
int tc_record_egress(struct __sk_buff *skb)
{
    return handle_skb(skb, DIR_EGRESS);
}

char LICENSE[] SEC("license") = "MIT";
