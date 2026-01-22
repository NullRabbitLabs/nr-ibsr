# Production Deployment

Deploy IBSR as a managed systemd service for continuous traffic collection.

---

## Prerequisites

- IBSR installed at `/usr/local/bin/ibsr` (see [Installation](install.md))
- Root access for systemd configuration
- Target network interface identified

---

## Systemd Service Setup

### 1. Create Output Directory

```bash
sudo mkdir -p /var/lib/ibsr/snapshots
sudo chmod 755 /var/lib/ibsr
```

### 2. Create Service File

Create `/etc/systemd/system/ibsr.service`:

```ini
[Unit]
Description=IBSR Traffic Collector
Documentation=https://github.com/nullrabbit/nr-ibsr
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ibsr collect \
    -p 8899 \
    --out-dir /var/lib/ibsr/snapshots \
    --max-files 3600 \
    --max-age 86400 \
    -v
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ibsr

# Security hardening
NoNewPrivileges=no
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/ibsr
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

**Customize**: Edit the `-p 8899` line to match your target ports.

### 3. Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable on boot
sudo systemctl enable ibsr

# Start now
sudo systemctl start ibsr

# Check status
sudo systemctl status ibsr
```

---

## Multi-Port Configuration

For monitoring multiple ports, edit the `ExecStart` line:

```ini
ExecStart=/usr/local/bin/ibsr collect \
    -p 22 -p 80 -p 443 -p 8899 \
    --out-dir /var/lib/ibsr/snapshots \
    --max-files 3600 \
    --max-age 86400 \
    -v
```

Or using comma-separated ports:

```ini
ExecStart=/usr/local/bin/ibsr collect \
    --dst-ports 22,80,443,8899 \
    --out-dir /var/lib/ibsr/snapshots
```

---

## Service Management

### Check Status

```bash
sudo systemctl status ibsr
```

### View Logs

```bash
# Recent logs
journalctl -u ibsr -n 50

# Follow logs
journalctl -u ibsr -f

# Logs since boot
journalctl -u ibsr -b
```

### Restart Service

```bash
sudo systemctl restart ibsr
```

### Stop Service

```bash
sudo systemctl stop ibsr
```

This gracefully detaches the XDP program and writes a final snapshot.

---

## Logrotate Configuration

The `status.jsonl` file grows continuously. Configure logrotate to manage it.

Create `/etc/logrotate.d/ibsr`:

```
/var/lib/ibsr/snapshots/status.jsonl {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

**Notes**:
- `copytruncate` avoids service restart during rotation
- Snapshot files (*.jsonl) are managed by IBSR's `--max-files` and `--max-age` options

---

## Directory Permissions

For production deployments:

```bash
# Standard permissions
sudo chown root:root /var/lib/ibsr
sudo chmod 755 /var/lib/ibsr
sudo chmod 755 /var/lib/ibsr/snapshots

# Restrict read access (optional)
sudo chmod 750 /var/lib/ibsr/snapshots
```

---

## Resource Usage

### CPU

- Negligible userspace CPU (< 1% on most systems)
- XDP program runs per-packet in kernel but does O(1) counter increment

### Memory

- Userspace process: ~10-20 MB
- BPF map: Configured via `--map-size` (default 100,000 entries = ~6 MB)

### Disk

Estimate disk usage based on traffic volume:

| Scenario | Snapshots/Hour | Size/Snapshot | Daily Usage |
|----------|----------------|---------------|-------------|
| Low traffic (< 1K IPs) | 60 | ~10 KB | ~15 MB |
| Medium traffic (10K IPs) | 60 | ~100 KB | ~150 MB |
| High traffic (100K IPs) | 60 | ~1 MB | ~1.5 GB |

---

## Multi-Interface Deployments

To monitor multiple interfaces, create separate service instances.

### Create Template Service

Create `/etc/systemd/system/ibsr@.service`:

```ini
[Unit]
Description=IBSR Traffic Collector (%i)
Documentation=https://github.com/nullrabbit/nr-ibsr
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ibsr collect \
    -p 8899 \
    -i %i \
    --out-dir /var/lib/ibsr/%i \
    -v
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ibsr-%i

NoNewPrivileges=no
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/ibsr
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

### Create Directories

```bash
sudo mkdir -p /var/lib/ibsr/eth0
sudo mkdir -p /var/lib/ibsr/eth1
```

### Start Per-Interface

```bash
sudo systemctl enable ibsr@eth0
sudo systemctl enable ibsr@eth1
sudo systemctl start ibsr@eth0
sudo systemctl start ibsr@eth1
```

---

## Verification Checklist

After deployment, verify:

```bash
# 1. Service is running
sudo systemctl is-active ibsr
# Expected: active

# 2. XDP attached (check interface)
ip link show eth0 | grep -i xdp
# Expected: xdp indicator in output

# 3. Snapshots being written
ls -la /var/lib/ibsr/snapshots/
# Expected: snapshot_*.jsonl files

# 4. Status heartbeat updating
tail -1 /var/lib/ibsr/snapshots/status.jsonl
# Expected: recent timestamp

# 5. No errors in logs
journalctl -u ibsr -p err -n 10
# Expected: no output
```

---

## Uninstalling the Service

```bash
# Stop and disable
sudo systemctl stop ibsr
sudo systemctl disable ibsr

# Remove service file
sudo rm /etc/systemd/system/ibsr.service
sudo systemctl daemon-reload

# Optionally remove data
sudo rm -rf /var/lib/ibsr
```

---

## Next Steps

- [Operations](operations.md) — Monitoring and troubleshooting
- [Upgrading](upgrading.md) — Version upgrades
- [Reporting](reporting.md) — Generate analysis reports
