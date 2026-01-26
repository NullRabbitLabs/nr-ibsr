---
title: Safety
nav_order: 6
---

# Safety Model

IBSR is designed to be safe for deployment on production systems, including high-throughput validators and edge infrastructure.

We've tested on a 1Gbps pipe. We've simulated on a 10Gpbs one but haven't had the chance to actually run this because of the cost. If you have one we can use, that would be swell.

## Hard Guarantees

IBSR provides structural guarantees that cannot be violated:

| Guarantee | How It's Enforced |
|-----------|-------------------|
| **Cannot drop packets** | XDP program only returns `XDP_PASS`; no `XDP_DROP` or `XDP_ABORTED` code paths |
| **Cannot redirect traffic** | No `XDP_REDIRECT`, devmap, or AF_XDP support compiled in |
| **Cannot modify packets** | No packet data writes; read-only header inspection |
| **Cannot emit per-packet events** | No ringbuf, perf_event, or bpf_trace_printk; counters only |
| **Cannot consume unbounded memory** | Uses LRU hash map with configurable max entries |
| **Cannot block packet processing** | O(1) counter increment per packet; no loops |

## Safety Verification

IBSR uses belt-and-suspenders static analysis to verify safety invariants:

### 1. Source-Level Analysis

Before compilation, the BPF C source is parsed to detect:

- Any `return XDP_DROP` or `return XDP_ABORTED` statements
- Any `return XDP_REDIRECT` statements
- Use of forbidden BPF helpers (`bpf_redirect`, `bpf_xdp_adjust_*`, etc.)
- Use of forbidden map types (ringbuf, perf_event_array, devmap)

### 2. ELF Inspection

After compilation, the compiled BPF object file is scanned for:

- Forbidden symbols in the symbol table
- Forbidden map type declarations in BTF metadata
- Any relocation entries pointing to dangerous helpers

### 3. Continuous Testing

Both analyses run automatically:

- On every build via `docker compose run --rm test`
- In CI pipeline (if configured)
- Before release builds

If any safety check fails, the build fails.

## Performance Characteristics

IBSR is designed for minimal performance impact:

| Aspect | Characteristic |
|--------|----------------|
| Per-packet overhead | ~50-100 nanoseconds |
| CPU usage (userspace) | < 1% on most systems |
| Memory (userspace) | ~10-20 MB |
| Memory (BPF map) | Configurable via `--map-size` |
| Packet loss | None (XDP_PASS always) |
| Latency impact | Unmeasurable (nanosecond scale) |

### Per-Packet Operations

The XDP program performs:

1. Header boundary checks (constant time)
2. Protocol matching (constant time)
3. Port lookup in static array (constant time)
4. BPF map lookup/update (O(1) hash operation)
5. Return `XDP_PASS`

No loops, no dynamic allocation, no blocking.

## Memory Bounds

### BPF Map

The BPF LRU hash map is bounded by `--map-size`:

```
Memory = map_size * entry_size
       ~ map_size * 64 bytes

Default: 100,000 * 64 = 6.4 MB
Maximum: 1,000,000 * 64 = 64 MB (practical limit)
```

When the map is full, the kernel automatically evicts the least-recently-updated entries.

### Userspace Memory

The collector process uses:

- Fixed-size buffers for snapshot serialization
- No unbounded allocations
- Memory usage scales with snapshot size, not traffic volume

## Failure Modes

IBSR is fail-open by design:

### Program Load Failure

If the XDP program fails to load (verifier rejection, missing capabilities):
- Error message printed
- Process exits with non-zero code
- Traffic is unaffected (no XDP attached)

### Collector Crash

If the userspace collector crashes:
- Kernel automatically detaches XDP program
- Traffic continues to flow normally
- Systemd restarts the service (if configured)

### Disk Failure

If snapshot writes fail (disk full, permissions):
- Error logged
- Collection continues
- Traffic unaffected
- Alerts should trigger from missing status updates

### Map Overflow

If more unique IPs are seen than `--map-size`:
- LRU eviction removes oldest entries
- Some counters may be lost
- Traffic unaffected
- Consider increasing `--map-size`

## Risk Comparison

IBSR's risk profile is comparable to standard observability tools:

| Tool | Risk Profile |
|------|--------------|
| tcpdump | Packet capture, disk writes |
| bpftrace | Arbitrary BPF programs |
| XDP observability tools | Similar to IBSR |
| **IBSR** | Counter-only, no packet capture |

IBSR is **lower risk** than tcpdump because:
- No packet content is captured
- No ring buffer events
- Bounded memory usage
- Compile-time safety guarantees

## What IBSR Cannot Do

Explicitly excluded capabilities:

| Capability | Why Excluded |
|------------|--------------|
| Block traffic | Shadow-mode only; enforcement is a separate concern |
| Capture packets | Privacy and storage concerns |
| Real-time alerting | Offline analysis avoids false urgency |
| Threat intelligence | External feeds introduce bias |
| Autonomous action | Human review required |

## Operational Risk

### Adding IBSR

When deploying IBSR:
- Traffic continues to flow normally
- No configuration changes to applications
- No firewall rule changes
- Reversible by stopping the service

### Removing IBSR

When removing IBSR:
- Stop the service
- XDP program detaches automatically
- Traffic continues normally
- Optional: delete data files

### Worst Case

Even in the worst failure scenario:
- Traffic continues flowing (fail-open)
- System returns to baseline automatically
- No persistent state changes
- No data corruption

## Verification Commands

### Check XDP Attachment

```bash
# List XDP programs on interface
ip link show eth0 | grep xdp

# Detailed BPF program info
sudo bpftool prog list | grep xdp
```

### Check Safety Invariants

```bash
# Run test suite (includes safety analysis)
docker compose run --rm test

# Check for forbidden patterns in source
grep -r "XDP_DROP\|XDP_ABORTED\|XDP_REDIRECT" ibsr-bpf/src/
# Should return nothing
```

### Monitor Resource Usage

```bash
# BPF map size
sudo bpftool map list

# Process memory
ps aux | grep ibsr

# Disk usage
du -sh /var/lib/ibsr/snapshots/
```

## Next Steps

- [How It Works](how-it-works.md) - Technical architecture
- [Reporting](reporting.md) - Offline reporting workflow
- [FAQ](faq.md) - Common questions
