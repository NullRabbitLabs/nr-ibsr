---
title: Quick Start
nav_order: 2
---

# Quick Start

Get IBSR collecting traffic in 5 minutes.

**Prerequisites**: IBSR installed (see [Installation](install.md)), root access.

## Step 1: Create Output Directory

```bash
sudo mkdir -p /var/lib/ibsr/snapshots
```

## Step 2: Start Collecting

Pick a TCP port to monitor (e.g., 22 for SSH, 80 for HTTP, 8899 for Solana RPC):

```bash
# Monitor port 8899, run for 3 minutes
sudo ibsr collect -p 8899 --out-dir /var/lib/ibsr/snapshots --duration-sec 180
```

You should see output like:

```
[INFO] Attached XDP program to eth0
[INFO] Monitoring TCP ports: [8899]
[INFO] Output directory: /var/lib/ibsr/snapshots
[INFO] Collection started. Press Ctrl+C to stop.
```

**Note**: If you don't specify `--duration-sec`, IBSR runs continuously until you press Ctrl+C.

## Step 3: Verify Output

While IBSR is running (or after it stops), check the output:

```bash
# List output files
ls -la /var/lib/ibsr/snapshots/

# Example output:
# -rw-r--r-- 1 root root 1234 Jan 15 10:00 snapshot_2025011510.jsonl
# -rw-r--r-- 1 root root  456 Jan 15 10:00 status.jsonl
```

### View Status Heartbeat

```bash
tail /var/lib/ibsr/snapshots/status.jsonl
```

```json
{"timestamp":1705312800,"cycle":1,"ips_collected":15,"snapshots_written":1}
{"timestamp":1705312860,"cycle":2,"ips_collected":23,"snapshots_written":2}
{"timestamp":1705312920,"cycle":3,"ips_collected":31,"snapshots_written":3}
```

### View Snapshot Data (Optional)

Local inspection is for diagnostics only. In pilot deployments, the IBSR team handles analysis.

```bash
# Pretty-print the last snapshot entry
tail -1 /var/lib/ibsr/snapshots/snapshot_*.jsonl | jq .
```

```json
{
  "version": 3,
  "ts_unix_sec": 1705312920,
  "dst_ports": [8899],
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

## Step 4: Upload to S3 (Pilots)

For pilot deployments, snapshots are uploaded to your S3 bucket on a schedule using `ibsr-export`.

The IBSR team generates reports from uploaded data — you don't need to analyze snapshots yourself.

See [Reporting](reporting.md) for upload configuration with `ibsr-export s3`.

## Step 5: Stop Collection

Press `Ctrl+C` to stop, or wait for `--duration-sec` to elapse.

```
[INFO] Received SIGINT, shutting down...
[INFO] Final snapshot written
[INFO] Collection complete: 3 cycles, 31 unique IPs
```

## Multi-Port Monitoring

Monitor multiple ports simultaneously:

```bash
# Using multiple -p flags
sudo ibsr collect -p 22 -p 80 -p 443 --out-dir /var/lib/ibsr/snapshots

# Using comma-separated list
sudo ibsr collect --dst-ports 22,80,443 --out-dir /var/lib/ibsr/snapshots
```

## Common Options

| Option | Description | Example |
|--------|-------------|---------|
| `-p, --dst-port` | Port to monitor (repeatable, max 8) | `-p 22 -p 80` |
| `--dst-ports` | Comma-separated ports | `--dst-ports 22,80,443` |
| `--duration-sec` | Run duration in seconds | `--duration-sec 3600` |
| `--out-dir` | Output directory | `--out-dir /var/lib/ibsr` |
| `-i, --iface` | Network interface | `-i eth0` |
| `-v` | Verbose output | `-v` or `-vv` |

See [Configuration](configuration.md) for the full reference.

## Next Steps

- [Deployment](deployment.md) — Run as a systemd service for continuous collection
- [Reporting](reporting.md) — Configure S3 uploads for pilot workflows
- [Configuration](configuration.md) — All CLI options and tuning
