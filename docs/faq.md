---
title: FAQ
nav_order: 11
---

# Frequently Asked Questions

Common questions about IBSR deployment and operation.

## General

### Does IBSR block traffic?

**No.** IBSR always passes traffic (`XDP_PASS`). It is a shadow-mode observation system only. It collects metrics to inform *future* enforcement decisions but does not enforce anything itself.

### Can IBSR detect attacks?

IBSR collects metrics that reveal attack patterns:
- SYN floods (high SYN count, low ACK count)
- Port scanning (many IPs, few packets each)
- Volumetric attacks (high packet/byte rates)

In pilot deployments, the IBSR team analyzes these patterns and generates reports. You do not need to interpret the data yourself.

### Does IBSR integrate with threat intelligence feeds?

**No.** Threat intelligence is deliberately excluded to avoid:
- Bias from external classifications
- False confidence in blocklists
- Dependency on external services

IBSR generates evidence purely from observed traffic patterns.

### Is there a dashboard?

**No.** IBSR produces reports, not live UIs. This is intentional:
- Dashboards encourage reactive decisions
- Batch analysis allows careful review
- Reports are auditable artifacts

### Is IBSR safe to run on production systems?

IBSR is designed to be non-disruptive:
- Shadow-only (never drops packets)
- Fail-open by design
- Bounded memory usage
- Compile-time safety verification

However, IBSR is **early-stage software** currently used in controlled pilots and evaluation environments. It is not a mature, general-purpose security product. See [Safety Model](safety.md) for technical details.

## Installation & Requirements

### What kernel version do I need?

**Kernel 6.1 or higher.** This is available in:
- Debian 12 (Bookworm)
- Ubuntu 22.04+ with HWE kernel
- Most recent enterprise Linux distributions

Check with: `uname -r`

### What network interfaces are supported?

Most physical NICs support XDP. Check with:

```bash
ethtool -i eth0 | grep driver
```

**Supported drivers include**: ixgbe, i40e, ice, mlx5, virtio_net, veth

**Not supported**: Some virtual network devices, older drivers

### Can I use IBSR on containers/VMs?

**VMs**: Yes, if the virtual NIC supports XDP (virtio_net does).

**Containers**: Generally no. XDP requires access to the host network interface. You can run IBSR on the host to monitor container traffic.

### Do I need root access?

**Yes**, either:
- Run as root (simplest)
- Grant CAP_BPF, CAP_NET_ADMIN, CAP_SYS_ADMIN capabilities

See [Installation](install.md) for capability setup.

## Configuration

### How many ports can I monitor?

**Up to 8 ports** simultaneously. This limit exists to keep the BPF program simple and verifiable.

If you need more ports, run multiple IBSR instances with different configurations.

### What's the default output directory?

`/var/lib/ibsr/snapshots`

Change with `--out-dir`.

### How often are snapshots written?

**Every 60 seconds** by default.

Change with `--snapshot-interval-sec`.

### What happens when the map is full?

The **LRU (Least Recently Used)** algorithm evicts old entries. The oldest entries (by last update time) are removed to make room for new source IPs.

If you see many unique IPs, increase `--map-size`.

## Disk Space

### How much disk space do I need?

Depends on traffic volume:

| Unique IPs/Snapshot | Snapshot Size | Daily Usage (60s interval) |
|---------------------|---------------|---------------------------|
| 100 | ~5 KB | ~7 MB |
| 1,000 | ~50 KB | ~70 MB |
| 10,000 | ~500 KB | ~700 MB |
| 100,000 | ~5 MB | ~7 GB |

Default rotation (`--max-files 3600`, `--max-age 86400`) keeps ~24 hours of data.

### How do I estimate my needs?

Run IBSR for an hour, check file sizes:

```bash
du -sh /var/lib/ibsr/snapshots/
ls -la /var/lib/ibsr/snapshots/snapshot_*.jsonl | tail -5
```

### Can I compress snapshots?

Not natively. IBSR writes uncompressed JSONL.

You can compress archived snapshots:

```bash
gzip /archive/ibsr/snapshot_*.jsonl
```

## Performance

### What's the CPU overhead?

**Negligible.** The XDP program runs in nanoseconds per packet (O(1) operations).

Userspace CPU usage is typically < 1%.

### What's the memory usage?

- **Userspace process**: ~10-20 MB
- **BPF map**: `--map-size × 64 bytes` (default: ~6 MB)

Total: ~16-26 MB with defaults.

### Does IBSR add latency?

**No measurable latency.** XDP runs before the network stack, adding ~50-100 nanoseconds per packet.

### Will IBSR drop packets under load?

**No.** IBSR always returns `XDP_PASS`. Packets continue through the stack normally regardless of load.

## Troubleshooting

### Why am I seeing zero IPs collected?

Possible causes:
1. **No traffic to monitored ports**: Verify traffic with `tcpdump -i eth0 port 8899`
2. **Wrong interface**: Check `ip route get 8.8.8.8` for default interface
3. **Firewall dropping packets before XDP**: Unlikely but check iptables/nftables

### Why won't the XDP program attach?

Possible causes:
1. **Another XDP program already attached**: `ip link show eth0 | grep xdp`
2. **Driver doesn't support XDP**: Check driver compatibility
3. **Insufficient permissions**: Need root or CAP_BPF

### Why are snapshots not being written?

Check:
1. **Output directory exists**: `ls -la /var/lib/ibsr/`
2. **Write permissions**: Check ownership
3. **Disk space**: `df -h /var/lib/ibsr`
4. **Service logs**: `journalctl -u ibsr`

### How do I check if XDP is attached?

```bash
ip link show eth0 | grep xdp
# Output includes "xdp" if attached

sudo bpftool prog list | grep xdp
# Lists attached XDP programs
```

## Data & Reporting

### Do I need to run ibsr-report?

**No.** In pilot deployments, the IBSR team generates reports from your uploaded snapshots. You do not need to run `ibsr-report` or interpret raw data yourself.

The reporting tool is available for advanced users who want to self-serve, but this is optional.

### How do I get reports?

1. Run the IBSR collector on your infrastructure
2. Configure scheduled S3 uploads using `ibsr-export` (see [Reporting](reporting.md))
3. The IBSR team generates reports from uploaded data
4. You receive finished reports

There are no dashboards to watch and no logs to tail during normal operation.

### Why are counters cumulative?

BPF maps persist counters across snapshots. This means:
- Each snapshot shows *total* counts since the entry was created
- The reporter computes *deltas* between consecutive snapshots
- LRU eviction resets counters for evicted IPs

### How do I convert key_value to an IP address?

The `key_value` is an IPv4 address as a 32-bit integer:

```bash
# Using Python
python3 -c "import ipaddress; print(ipaddress.ip_address(3232235777))"
# Output: 192.168.1.1

# Using jq
echo '3232235777' | jq 'def ip: "\(. / 16777216 | floor).\((. / 65536) % 256 | floor).\((. / 256) % 256 | floor).\(. % 256)"; ip'
```

### Can I query snapshots with SQL?

Not directly. Options:
1. Import JSONL into a database
2. Use `jq` for ad-hoc queries
3. Use the `ibsr-report` tool

### How do I correlate with other logs?

Use the `ts_unix_sec` field to join with other time-series data:

```bash
# Find snapshot at specific time
grep '"ts_unix_sec":1705312920' /var/lib/ibsr/snapshots/*.jsonl
```

## Security

### What data does IBSR collect?

- Source IP addresses
- Destination ports (configured)
- TCP flag counts (SYN, ACK, RST)
- Packet and byte counts

**Not collected**:
- Packet contents/payloads
- Application-layer data
- Destination IP addresses

### Is collected data sensitive?

Source IP addresses may be considered PII depending on jurisdiction. Treat snapshots accordingly:
- Restrict access to output directory
- Consider data retention policies
- Encrypt if transferring over network

### Can IBSR be exploited?

IBSR's attack surface is minimal:
- No network listeners
- No incoming connections
- No packet content processing
- Compile-time verified BPF code

The primary risk is data exfiltration if an attacker gains access to snapshot files.

## Comparison

### How is IBSR different from tcpdump?

| Aspect | IBSR | tcpdump |
|--------|------|---------|
| Data captured | Counters only | Full packets |
| Storage | ~KB per snapshot | ~MB/GB for captures |
| Privacy | IPs only | Full payloads |
| Performance | Negligible | Can impact performance |
| Analysis | Offline reports | Manual inspection |

### How is IBSR different from Suricata/Snort?

| Aspect | IBSR | Suricata/Snort |
|--------|------|----------------|
| Mode | Shadow only | Active or passive |
| Signatures | None | Extensive rulesets |
| Output | Counters + reports | Alerts + logs |
| Complexity | Minimal | Significant |
| Purpose | Validate enforcement | Detect threats |

### How is IBSR different from a firewall?

IBSR does not enforce anything. It generates evidence about what *would* happen if enforcement were enabled.

## Next Steps

- [Installation](install.md) — Get started
- [Deployment](deployment.md) — Production deployment with S3 upload
- [Safety Model](safety.md) — Understand guarantees
- [Reporting](reporting.md) — S3 upload and pilot workflow
