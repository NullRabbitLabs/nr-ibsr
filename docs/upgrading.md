# Upgrading Guide

How to upgrade IBSR to a new version safely.

## Before Upgrading

### Check Current Version

```bash
ibsr --version
# ibsr 0.1.0
```

### Review Release Notes

Check the [GitHub Releases](https://github.com/nullrabbit/nr-ibsr/releases) page for:

- Breaking changes
- New features
- Schema version changes
- Required configuration updates

### Backup Current State

```bash
# Backup current binary (optional)
sudo cp /usr/local/bin/ibsr /usr/local/bin/ibsr.bak

# Backup recent snapshots (recommended)
tar -czvf ibsr-backup-$(date +%Y%m%d).tar.gz /var/lib/ibsr/snapshots/
```

## Upgrade Procedure

### Step 1: Download New Version

```bash
VERSION="v0.2.0"  # Set to target version
ARCH=$(uname -m)

case $ARCH in
  x86_64)  BINARY="ibsr-x86_64" ;;
  aarch64|arm64) BINARY="ibsr-arm64" ;;
esac

curl -LO "https://github.com/nullrabbit/nr-ibsr/releases/download/${VERSION}/${BINARY}"
curl -LO "https://github.com/nullrabbit/nr-ibsr/releases/download/${VERSION}/checksums.txt"
```

### Step 2: Verify Checksum

```bash
grep "${BINARY}" checksums.txt | sha256sum -c -
# ibsr-xxx: OK
```

### Step 3: Stop Service

```bash
sudo systemctl stop ibsr
```

This gracefully:
- Writes a final snapshot
- Detaches the XDP program
- Exits cleanly

### Step 4: Install New Binary

```bash
sudo install -m 755 "${BINARY}" /usr/local/bin/ibsr

# Verify new version
ibsr --version
```

### Step 5: Re-apply Capabilities (If Used)

If running with capabilities instead of root:

```bash
sudo setcap cap_bpf,cap_net_admin,cap_sys_admin+ep /usr/local/bin/ibsr
```

### Step 6: Start Service

```bash
sudo systemctl start ibsr
```

### Step 7: Verify Operation

```bash
# Check service status
sudo systemctl status ibsr

# Check logs for errors
journalctl -u ibsr -n 20

# Verify snapshots are being written
ls -la /var/lib/ibsr/snapshots/

# Check latest status
tail -1 /var/lib/ibsr/snapshots/status.jsonl
```

## Upgrade from Source

If building from source:

```bash
# Pull latest
cd nr-ibsr
git fetch origin
git checkout v0.2.0  # Or desired version

# Rebuild
./build.sh

# Stop service
sudo systemctl stop ibsr

# Install
sudo install -m 755 dist/ibsr-* /usr/local/bin/ibsr

# Start service
sudo systemctl start ibsr
```

## Schema Compatibility

### Snapshot Schema Versions

| IBSR Version | Snapshot Schema |
|--------------|-----------------|
| 0.1.x | v3 |

### Forward Compatibility

- Newer reporters can read older snapshots
- The reporter infers schema version from the `version` field
- Mixed-version snapshots in the same directory are supported

### Backward Compatibility

- Older reporters may not understand newer schema versions
- Always upgrade the reporter when upgrading the collector

## Rollback Procedure

If issues occur after upgrade:

### Step 1: Stop the Service

```bash
sudo systemctl stop ibsr
```

### Step 2: Restore Previous Binary

```bash
# If you backed up the binary
sudo cp /usr/local/bin/ibsr.bak /usr/local/bin/ibsr

# Or download the previous version
VERSION="v0.1.0"
# ... (same download steps as above)
```

### Step 3: Re-apply Capabilities

```bash
sudo setcap cap_bpf,cap_net_admin,cap_sys_admin+ep /usr/local/bin/ibsr
```

### Step 4: Start Service

```bash
sudo systemctl start ibsr
```

### Step 5: Verify Rollback

```bash
ibsr --version
sudo systemctl status ibsr
```

## Upgrading Multiple Hosts

For fleet upgrades:

### Sequential (Recommended)

1. Upgrade one host
2. Verify operation for 30+ minutes
3. Proceed to next host

### Parallel (With Caution)

```bash
# Example using parallel-ssh
pssh -h hosts.txt -i 'sudo systemctl stop ibsr && \
  curl -LO https://... && \
  sudo install -m 755 ibsr-* /usr/local/bin/ibsr && \
  sudo systemctl start ibsr'
```

## Post-Upgrade Checklist

- [ ] Service is running (`systemctl is-active ibsr`)
- [ ] No errors in logs (`journalctl -u ibsr -p err`)
- [ ] XDP attached to correct interface
- [ ] Snapshots being written
- [ ] Status file updating
- [ ] Correct version reported (`ibsr --version`)

## Troubleshooting Upgrades

### Service Won't Start After Upgrade

**Check logs**:
```bash
journalctl -u ibsr -n 50
```

**Common issues**:
- Missing capabilities (re-apply with `setcap`)
- Configuration incompatibility (check release notes)
- Permissions on output directory

### Snapshots Not Compatible

If the reporter complains about schema version:

1. Upgrade the reporter too
2. Or use the version of reporter matching snapshot schema

### XDP Attachment Fails

Kernel compatibility issue:

```bash
# Check kernel version
uname -r

# May need kernel upgrade for new XDP features
```

## Next Steps

- [Operations](operations.md) — Monitoring after upgrade
- [Installation](install.md) — Fresh install instructions
- [FAQ](faq.md) — Common questions
