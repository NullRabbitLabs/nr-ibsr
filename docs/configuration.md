# Configuration Reference

Complete reference for `ibsr collect` command options and tuning.

---

## Command Synopsis

```
ibsr collect [OPTIONS] --dst-port <PORT>...
ibsr collect [OPTIONS] --dst-ports <PORTS>
```

At least one destination port is required.

---

## CLI Options

### Required: Destination Ports

| Option | Description |
|--------|-------------|
| `-p, --dst-port <PORT>` | TCP destination port to monitor. Can be repeated up to 8 times. |
| `--dst-ports <PORTS>` | Comma-separated list of TCP ports (alternative to `-p`). |

```bash
# Using -p (repeatable)
ibsr collect -p 22 -p 80 -p 443

# Using --dst-ports
ibsr collect --dst-ports 22,80,443

# Mixed (not recommended, but works)
ibsr collect -p 22 --dst-ports 80,443
```

**Maximum**: 8 ports total across both options.

---

### Optional: Duration

| Option | Description | Default |
|--------|-------------|---------|
| `--duration-sec <SECS>` | Run for N seconds then exit gracefully. | Continuous (until SIGINT) |

```bash
# Run for 1 hour
ibsr collect -p 8899 --duration-sec 3600

# Run for 24 hours
ibsr collect -p 8899 --duration-sec 86400

# Run continuously (default)
ibsr collect -p 8899
# Press Ctrl+C to stop
```

---

### Optional: Network Interface

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --iface <IFACE>` | Network interface to attach XDP program. | Auto-detect default route interface |

```bash
# Explicit interface
ibsr collect -p 8899 -i eth0
ibsr collect -p 8899 -i ens192

# Auto-detect (default)
ibsr collect -p 8899
# Reads /proc/net/route to find default interface
```

**Auto-detection**: IBSR reads `/proc/net/route` and selects the interface with the default route (`0.0.0.0/0`).

---

### Optional: Output Directory

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --out-dir <DIR>` | Directory for snapshot and status files. | `/var/lib/ibsr/snapshots` |

```bash
# Custom output directory
ibsr collect -p 8899 --out-dir /data/ibsr/output

# Relative path (not recommended for services)
ibsr collect -p 8899 --out-dir ./output
```

The directory must exist before starting. IBSR does not create it.

---

### Optional: File Rotation

| Option | Description | Default |
|--------|-------------|---------|
| `--max-files <N>` | Maximum number of snapshot files to retain. | 3600 |
| `--max-age <SECS>` | Maximum age of snapshots in seconds. | 86400 (24 hours) |

Files are removed when **either** limit is exceeded.

```bash
# Keep up to 1000 files, max 12 hours old
ibsr collect -p 8899 --max-files 1000 --max-age 43200

# Aggressive rotation (testing)
ibsr collect -p 8899 --max-files 10 --max-age 600
```

**Calculation Example**:
- 1-minute snapshot interval = 60 snapshots/hour
- 24 hours retention = 1440 files
- Default `--max-files 3600` covers 60 hours at 1-minute intervals

---

### Optional: BPF Map Size

| Option | Description | Default |
|--------|-------------|---------|
| `--map-size <N>` | Maximum entries in BPF LRU hash map. | 100000 |

This controls memory usage and the maximum number of unique source IPs that can be tracked simultaneously.

```bash
# High-cardinality environment (many unique IPs)
ibsr collect -p 8899 --map-size 500000

# Memory-constrained environment
ibsr collect -p 8899 --map-size 50000
```

**Memory Estimation**:
- Each entry: ~64 bytes (key + counters)
- 100,000 entries: ~6.4 MB
- 500,000 entries: ~32 MB
- 1,000,000 entries: ~64 MB

When the map is full, the LRU algorithm evicts the least-recently-updated entries.

---

### Optional: Intervals

| Option | Description | Default |
|--------|-------------|---------|
| `--status-interval-sec <SECS>` | Interval for writing status.jsonl updates. | 60 |
| `--snapshot-interval-sec <SECS>` | Interval for emitting snapshots. | 60 |

```bash
# Faster snapshots (10-second intervals)
ibsr collect -p 8899 --snapshot-interval-sec 10

# Less frequent status updates
ibsr collect -p 8899 --status-interval-sec 300
```

**Note**: Snapshot and status intervals are independent. Each snapshot creates one JSONL line in the hourly snapshot file.

---

### Optional: Verbosity

| Option | Description | Default |
|--------|-------------|---------|
| `-v, --verbose` | Increase verbosity. Repeatable. | Quiet |

| Level | Flag | Output |
|-------|------|--------|
| 0 | (none) | Errors only |
| 1 | `-v` | Info messages |
| 2 | `-vv` | Debug messages |

```bash
# Info level
ibsr collect -p 8899 -v

# Debug level
ibsr collect -p 8899 -vv
```

---

## Example Configurations

### Single Port (Simple)

Monitor a single service:

```bash
sudo ibsr collect \
  -p 8899 \
  --out-dir /var/lib/ibsr/snapshots
```

### Multi-Port Validator

Monitor multiple RPC and gossip ports:

```bash
sudo ibsr collect \
  -p 8899 -p 8900 -p 8001 -p 8002 \
  --out-dir /var/lib/ibsr/snapshots \
  --max-files 2880 \
  --max-age 172800 \
  -v
```

### High-Traffic Environment

Tune for high cardinality and volume:

```bash
sudo ibsr collect \
  --dst-ports 80,443 \
  --out-dir /var/lib/ibsr/snapshots \
  --map-size 500000 \
  --snapshot-interval-sec 30 \
  --max-files 5760 \
  --max-age 86400
```

### Short Test Run

Quick validation:

```bash
sudo ibsr collect \
  -p 22 \
  --out-dir /tmp/ibsr-test \
  --duration-sec 60 \
  --snapshot-interval-sec 10 \
  -vv
```

---

## Output Directory Structure

After running, the output directory contains:

```
/var/lib/ibsr/snapshots/
├── snapshot_2025011500.jsonl   # Snapshots from hour 00:00-00:59
├── snapshot_2025011501.jsonl   # Snapshots from hour 01:00-01:59
├── snapshot_2025011502.jsonl   # ... and so on
└── status.jsonl                # Append-only heartbeat log
```

### Snapshot Files

- **Naming**: `snapshot_YYYYMMDDHH.jsonl` (UTC)
- **Format**: JSONL (one JSON object per line)
- **Content**: Cumulative counters at each snapshot interval

### Status File

- **Naming**: `status.jsonl`
- **Format**: JSONL (one JSON object per line)
- **Content**: Heartbeat with cycle count and IPs collected

---

## Environment Variables

IBSR does not read environment variables. All configuration is via CLI flags.

---

## Validation Rules

The CLI validates inputs before starting:

| Rule | Error Message |
|------|---------------|
| At least one port required | "At least one destination port is required" |
| Maximum 8 ports | "Too many destination ports (max 8)" |
| Port range 1-65535 | "Invalid port number" |
| Output directory exists | "Output directory does not exist" |
| Interface exists | "Interface not found" |

---

## Next Steps

- [Deployment](deployment.md) — Run as a systemd service
- [Operations](operations.md) — Monitoring and troubleshooting
- [How It Works](how-it-works.md) — Technical details
