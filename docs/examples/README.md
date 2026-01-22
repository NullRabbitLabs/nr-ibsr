# Example Configuration Files

This directory contains example configuration files for production IBSR deployments.

## Files

| File | Description | Install Location |
|------|-------------|------------------|
| `ibsr.service` | Systemd service unit | `/etc/systemd/system/ibsr.service` |
| `ibsr-logrotate` | Logrotate config for status.jsonl | `/etc/logrotate.d/ibsr` |

## Quick Setup

```bash
# Create output directory
sudo mkdir -p /var/lib/ibsr/snapshots

# Install systemd service
sudo cp ibsr.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ibsr
sudo systemctl start ibsr

# Install logrotate config
sudo cp ibsr-logrotate /etc/logrotate.d/ibsr
```

## Customization

### Systemd Service

Edit the `ExecStart` line to customize:

```ini
ExecStart=/usr/local/bin/ibsr collect \
    -p 22 -p 80 -p 443 \          # Ports to monitor
    --out-dir /var/lib/ibsr/snapshots \
    --max-files 3600 \             # Max snapshot files
    --max-age 86400 \              # Max age in seconds
    --map-size 100000 \            # BPF map size
    -v                             # Verbosity
```

### Logrotate

The default config rotates `status.jsonl` daily with 7-day retention. Adjust `rotate` and `daily`/`weekly` as needed.

## See Also

- [Deployment Guide](../deployment.md) — Full deployment instructions
- [Configuration Reference](../configuration.md) — All CLI options
- [Operations Guide](../operations.md) — Monitoring and maintenance
