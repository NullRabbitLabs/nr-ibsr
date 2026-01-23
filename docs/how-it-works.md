---
title: How It Works
nav_order: 5
---

# How IBSR Works

Technical deep dive into IBSR's architecture and data model.

## Execution Model

### XDP Hook Point

IBSR attaches at the **XDP (eXpress Data Path)** hook, the earliest point a packet can be processed in the Linux network stack:

```
Network Interface
       │
       ▼
┌──────────────┐
│  XDP Hook    │ ◄── IBSR attaches here
│  (kernel)    │
└──────┬───────┘
       │ XDP_PASS (always)
       ▼
┌──────────────┐
│  tc ingress  │
└──────┬───────┘
       ▼
┌──────────────┐
│  netfilter   │
└──────┬───────┘
       ▼
   Application
```

XDP runs before:
- Traffic control (tc)
- Netfilter/iptables
- Socket layer
- Any userspace

### Per-Packet Processing

For each incoming TCP packet to a monitored port:

1. **Parse headers**: Ethernet → IP → TCP
2. **Check destination port**: Skip if not in monitored list
3. **Extract source IP**: 32-bit IPv4 address
4. **Update counters**: Increment appropriate metrics in BPF map
5. **Return `XDP_PASS`**: Packet continues to stack

All operations are O(1). No loops, no allocations, no blocking.

## BPF Map Structure

IBSR uses a single **LRU hash map** to track per-source-IP counters:

```
┌─────────────────────────────────────────────────────────┐
│                    BPF LRU Hash Map                     │
├─────────────────────────────────────────────────────────┤
│  Key: (src_ip: u32, dst_port: u16)                      │
│  Value: Counters { syn, ack, handshake_ack, rst,        │
│                    packets, bytes }                     │
├─────────────────────────────────────────────────────────┤
│  Max entries: --map-size (default 100,000)              │
│  Eviction: LRU (least recently updated)                 │
└─────────────────────────────────────────────────────────┘
```

### Counter Semantics

| Counter | Incremented When |
|---------|------------------|
| `syn` | TCP SYN flag set (connection initiation) |
| `ack` | TCP ACK flag set (includes data and handshake) |
| `handshake_ack` | ACK with no payload and seq > 0 (handshake completion) |
| `rst` | TCP RST flag set (connection reset) |
| `packets` | Every matched TCP packet |
| `bytes` | Every matched packet (IP total length) |

**Important**: Counters are **cumulative** within the map. They accumulate until the entry is evicted by LRU.

## Userspace Collector

The userspace `ibsr collect` process:

1. **Attaches XDP program** to network interface
2. **Polls BPF map** at configurable intervals
3. **Emits snapshots** with current counter values
4. **Writes status heartbeat** for monitoring
5. **Handles signals** for graceful shutdown

```
┌─────────────────────────────────────────┐
│          ibsr collect (userspace)       │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  Main Loop (every snapshot_sec)  │  │
│  │                                   │  │
│  │  1. Read BPF map entries         │  │
│  │  2. Build Snapshot struct        │  │
│  │  3. Serialize to JSONL           │  │
│  │  4. Append to hourly file        │  │
│  │  5. Update status.jsonl          │  │
│  │  6. Rotate old files if needed   │  │
│  └───────────────────────────────────┘  │
│                                         │
│  Signal Handler: SIGINT/SIGTERM         │
│  - Write final snapshot                 │
│  - Detach XDP program                   │
│  - Exit cleanly                         │
└─────────────────────────────────────────┘
```

## Snapshot Format

### Schema Version 3

Each snapshot is a single JSON line (JSONL format):

```json
{
  "version": 3,
  "ts_unix_sec": 1705312920,
  "dst_ports": [8899, 8900],
  "buckets": [
    {
      "key_type": "src_ip",
      "key_value": 3232235777,
      "dst_port": 8899,
      "syn": 42,
      "ack": 156,
      "handshake_ack": 40,
      "rst": 2,
      "packets": 200,
      "bytes": 45000
    }
  ]
}
```

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `version` | u32 | Schema version (currently 3) |
| `ts_unix_sec` | u64 | Unix timestamp (seconds since epoch) |
| `dst_ports` | [u16] | List of monitored ports |
| `buckets` | [Bucket] | Per-source counter entries |

### Bucket Entry

| Field | Type | Description |
|-------|------|-------------|
| `key_type` | string | Key type: `"src_ip"` |
| `key_value` | u32 | IPv4 address as 32-bit integer (MSB-first) |
| `dst_port` | u16 | Destination port this entry tracks |
| `syn` | u32 | SYN packets count |
| `ack` | u32 | ACK packets count |
| `handshake_ack` | u32 | Handshake-completing ACKs |
| `rst` | u32 | RST packets count |
| `packets` | u32 | Total packets count |
| `bytes` | u64 | Total bytes count |

### IP Address Encoding

The `key_value` field stores IPv4 addresses as 32-bit integers in network byte order (MSB-first):

```
IP: 192.168.1.1
Binary: 11000000.10101000.00000001.00000001
key_value: 3232235777 (decimal)
          0xC0A80101 (hex)
```

To convert back:

```python
ip = 3232235777
octets = [
    (ip >> 24) & 0xFF,  # 192
    (ip >> 16) & 0xFF,  # 168
    (ip >> 8) & 0xFF,   # 1
    ip & 0xFF           # 1
]
print(".".join(map(str, octets)))  # "192.168.1.1"
```

## Status File Format

The `status.jsonl` file records collection heartbeats:

```json
{"timestamp":1705312800,"cycle":1,"ips_collected":15,"snapshots_written":1}
{"timestamp":1705312860,"cycle":2,"ips_collected":23,"snapshots_written":2}
```

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | u64 | Unix timestamp when cycle completed |
| `cycle` | u64 | Collection cycle number (1-indexed) |
| `ips_collected` | u64 | Unique source IPs in this cycle |
| `snapshots_written` | u64 | Cumulative snapshots written |

## File Naming

### Snapshot Files

Pattern: `snapshot_YYYYMMDDHH.jsonl`

- `YYYY`: Year (4 digits)
- `MM`: Month (01-12)
- `DD`: Day (01-31)
- `HH`: Hour (00-23) in **UTC**

Example: `snapshot_2025011514.jsonl` = January 15, 2025, 14:00-14:59 UTC

Multiple snapshots append to the same hourly file.

### Deterministic Ordering

Within each snapshot, buckets are sorted by `(key_type, key_value, dst_port)` for:
- Reproducible output
- Stable diffs
- Easier testing

## Failure Modes

IBSR is designed to be fail-open:

| Failure | Behavior |
|---------|----------|
| XDP program fails to load | Error at startup, no traffic impact |
| BPF verifier rejection | Error at startup, no traffic impact |
| Collector process crash | XDP detaches, traffic continues normally |
| Disk full | Snapshot write fails, traffic continues |
| Map overflow | LRU evicts oldest entries, traffic continues |

### Graceful Shutdown

On SIGINT or SIGTERM:

1. Stop collection loop
2. Write final snapshot with current counters
3. Detach XDP program from interface
4. Exit with code 0

## Data Flow Summary

```
┌────────────┐     ┌─────────────┐     ┌──────────────┐
│ Network    │────▶│ XDP Program │────▶│ BPF LRU Map  │
│ Interface  │     │ (kernel)    │     │ (per-IP)     │
└────────────┘     └─────────────┘     └──────┬───────┘
                         │                     │
                   XDP_PASS               Map read
                   (always)             (userspace)
                         │                     │
                         ▼                     ▼
                   ┌─────────┐     ┌────────────────┐
                   │ Network │     │ ibsr collect   │
                   │ Stack   │     │ (serialize)    │
                   └─────────┘     └───────┬────────┘
                                           │
                                     JSONL write
                                           │
                                           ▼
                                   ┌───────────────┐
                                   │ Disk          │
                                   │ (snapshots)   │
                                   └───────────────┘
```

## Next Steps

- [Safety Model](safety.md) — Safety guarantees and verification
- [Reporting](reporting.md) — Offline analysis
- [FAQ](faq.md) — Common questions
