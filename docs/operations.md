---
title: Operations
nav_order: 6
---

# Operations Guide

Monitoring, troubleshooting, and maintaining IBSR in production.

## Monitoring IBSR Health

### Status File Heartbeat

The primary health indicator is the `status.jsonl` file. Each line represents a completed collection cycle:

```bash
tail -1 /var/lib/ibsr/snapshots/status.jsonl
```

```json
{"timestamp":1705312920,"cycle":142,"ips_collected":523,"snapshots_written":142}
```

A healthy system shows:
- Recent `timestamp` (within last 2× status interval)
- Incrementing `cycle` numbers
- Non-zero `ips_collected` (if traffic is present)

### Staleness Check Script

Create `/usr/local/bin/check-ibsr-health`:

```bash
#!/bin/bash
# Check IBSR status file freshness

STATUS_FILE="/var/lib/ibsr/snapshots/status.jsonl"
MAX_AGE_SEC=180  # Alert if older than 3 minutes

if [ ! -f "$STATUS_FILE" ]; then
    echo "CRITICAL: Status file missing"
    exit 2
fi

LAST_TS=$(tail -1 "$STATUS_FILE" | jq -r '.timestamp')
NOW=$(date +%s)
AGE=$((NOW - LAST_TS))

if [ "$AGE" -gt "$MAX_AGE_SEC" ]; then
    echo "WARNING: Status file is ${AGE}s old (threshold: ${MAX_AGE_SEC}s)"
    exit 1
fi

echo "OK: Status updated ${AGE}s ago"
exit 0
```

Make it executable:

```bash
chmod +x /usr/local/bin/check-ibsr-health
```

### Cron-Based Alerting

Add to `/etc/cron.d/ibsr-monitor`:

```
# Check IBSR health every 5 minutes
*/5 * * * * root /usr/local/bin/check-ibsr-health || echo "IBSR health check failed" | mail -s "IBSR Alert" ops@example.com
```

## Disk Space Monitoring

### Check Snapshot Directory Size

```bash
du -sh /var/lib/ibsr/snapshots/
```

### Estimate Growth Rate

```bash
# Count files and sizes by hour
ls -la /var/lib/ibsr/snapshots/snapshot_*.jsonl | tail -10
```

### Set Up Disk Alerts

Add to health check script:

```bash
# Check disk usage
DISK_USAGE=$(df /var/lib/ibsr --output=pcent | tail -1 | tr -d ' %')
if [ "$DISK_USAGE" -gt 80 ]; then
    echo "WARNING: Disk usage at ${DISK_USAGE}%"
    exit 1
fi
```

## Troubleshooting

### Service Won't Start

**Symptom**: `systemctl start ibsr` fails

**Check logs**:
```bash
journalctl -u ibsr -n 50 --no-pager
```

**Common causes**:

| Error | Cause | Solution |
|-------|-------|----------|
| "Permission denied" | Missing root/CAP_BPF | Run as root or set capabilities |
| "Output directory does not exist" | Missing directory | `mkdir -p /var/lib/ibsr/snapshots` |
| "Interface not found" | Wrong interface name | Check `ip link show`, use `-i <iface>` |
| "Failed to attach XDP" | Interface doesn't support XDP | Use a different interface |

### XDP Attachment Failures

**Symptom**: "Failed to attach XDP program to interface"

**Check if another XDP program is attached**:
```bash
ip link show eth0 | grep xdp
```

**Remove conflicting program**:
```bash
sudo ip link set dev eth0 xdp off
```

**Check kernel support**:
```bash
uname -r  # Should be 6.1+
```

### No Snapshots Being Written

**Symptom**: Service running but no snapshot files

**Check status file**:
```bash
cat /var/lib/ibsr/snapshots/status.jsonl
```

If `ips_collected: 0`:
- No traffic to monitored ports
- Wrong interface selected
- Firewall blocking before XDP

**Verify interface**:
```bash
# Check which interface IBSR attached to
journalctl -u ibsr | grep "Attached XDP"

# Verify it's the right one
ip route get 8.8.8.8  # Shows default interface
```

### High CPU Usage

**Symptom**: `ibsr` process using unexpected CPU

This is rare. Possible causes:

1. **Very high traffic volume**: Normal, but consider tuning `--map-size`
2. **Small snapshot interval**: Increase `--snapshot-interval-sec`
3. **Disk I/O bottleneck**: Use faster storage

Check CPU:
```bash
top -p $(pgrep ibsr)
```

### Memory Issues

**Symptom**: Process killed by OOM

**Check map size**:
```bash
# Current setting in service file
grep map-size /etc/systemd/system/ibsr.service

# Memory estimate
# 100,000 entries × 64 bytes = ~6 MB
```

**Reduce if needed**:
```bash
# Edit service file
sudo systemctl edit ibsr --full

# Change --map-size to smaller value
# --map-size 50000
```

## Log Analysis

### View Recent Logs

```bash
# Last 100 lines
journalctl -u ibsr -n 100

# Follow live
journalctl -u ibsr -f

# Filter by priority
journalctl -u ibsr -p err  # Errors only
journalctl -u ibsr -p warning  # Warnings and above
```

### Search for Specific Events

```bash
# Startup events
journalctl -u ibsr | grep -i "attach\|start"

# Errors
journalctl -u ibsr | grep -i "error\|fail"

# Shutdown events
journalctl -u ibsr | grep -i "shutdown\|stop\|sigint"
```

### Export Logs

```bash
# Export to file
journalctl -u ibsr --since "1 hour ago" > ibsr-logs.txt

# Export as JSON
journalctl -u ibsr -o json --since "1 hour ago" > ibsr-logs.json
```

## Snapshot Management

### List Snapshots

```bash
ls -la /var/lib/ibsr/snapshots/snapshot_*.jsonl
```

### Count Snapshots

```bash
ls /var/lib/ibsr/snapshots/snapshot_*.jsonl | wc -l
```

### View Latest Snapshot

```bash
# Last entry in newest file
tail -1 "$(ls -t /var/lib/ibsr/snapshots/snapshot_*.jsonl | head -1)" | jq .
```

### Archive Old Snapshots

Before rotation removes them:

```bash
# Compress and archive
tar -czvf snapshots-$(date +%Y%m%d).tar.gz /var/lib/ibsr/snapshots/snapshot_*.jsonl

# Move to archive location
mv snapshots-*.tar.gz /archive/ibsr/
```

### Manual Cleanup

```bash
# Remove snapshots older than 7 days
find /var/lib/ibsr/snapshots -name "snapshot_*.jsonl" -mtime +7 -delete
```

## Data Upload

In pilot deployments, snapshots are uploaded to your S3 bucket using `ibsr-export`.

### Using ibsr-export (Pilots)

```bash
# Upload snapshots to S3
ibsr-export s3 \
  --input /var/lib/ibsr/snapshots \
  --bucket <your-bucket-name> \
  --prefix ibsr/<host-id>/snapshots
```

For scheduled uploads, see the systemd timer configuration in [Deployment](deployment.md#scheduled-s3-upload-required-for-pilots).

### Alternative: Manual Transfer

For non-pilot or offline scenarios, snapshots can be transferred manually:

```bash
# Rsync to another system
rsync -avz --progress \
  /var/lib/ibsr/snapshots/ \
  user@server:/data/ibsr/$(hostname)/
```

This is not the primary workflow for pilots.

## Performance Tuning

### For High-Traffic Environments

```bash
# Increase map size for more unique IPs
--map-size 500000

# Faster snapshots for finer granularity
--snapshot-interval-sec 30

# Keep more history
--max-files 5000
--max-age 172800  # 48 hours
```

### For Resource-Constrained Environments

```bash
# Smaller map size
--map-size 50000

# Less frequent snapshots
--snapshot-interval-sec 120

# Aggressive rotation
--max-files 500
--max-age 43200  # 12 hours
```

## Maintenance Tasks

### Daily

- Check health status script output
- Verify snapshots are being written
- Monitor disk space

### Weekly

- Review disk usage trends
- Archive old snapshots if needed
- Check logs for errors

### Monthly

- Review disk usage trends and adjust rotation settings if needed
- Verify S3 uploads are succeeding (check timer logs)
- Update IBSR if new version available

## Next Steps

- [Reporting](reporting.md) — S3 upload configuration for pilots
- [Upgrading](upgrading.md) — Version upgrades
- [FAQ](faq.md) — Common questions
