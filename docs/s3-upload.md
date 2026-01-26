---
title: S3 Upload
nav_order: 3
---

# S3 Upload

`ibsr-export` uploads snapshot files to S3 or S3-compatible storage (MinIO, Cloudflare R2).

For pilots, uploading raw snapshot data to S3 is **recommended**.

**Prerequisite:** The IBSR collector must be running and producing snapshots. See [Installation](installation.md) for setup instructions.

If you want us to add support for other object stores, drop us a note.

## Installation 

### Pre-built Binary (Recommended)

Download from [GitHub Releases](https://github.com/NullRabbitLabs/nr-ibsr/releases):

```bash
# Download (adjust version and architecture as needed)
curl -LO https://github.com/NullRabbitLabs/nr-ibsr/releases/latest/download/ibsr-export-arm64

# Make executable and move to PATH
chmod +x ibsr-export-arm64
sudo mv ibsr-export-arm64 /usr/local/bin/ibsr-export
```

### Build from Source

Requires Docker:

```bash
git clone https://github.com/NullRabbitLabs/nr-ibsr.git
cd nr-ibsr
./build-export.sh --arch arm64  # or x86_64
sudo mv ./dist/ibsr-export-arm64 /usr/local/bin/ibsr-export
```

## Basic Usage

```bash
ibsr-export s3 \
  --input /var/lib/ibsr/snapshots \
  --bucket <customer-bucket-name> \
  --prefix ibsr/<host-id>/snapshots
```

This command:
- uploads snapshot `.jsonl` files
- preserves directory structure
- exits non-zero on failure

## Scheduled Uploads

Uploads are typically run on a schedule rather than manually.

### systemd (Recommended)

**Service unit** (`/etc/systemd/system/ibsr-upload.service`):

```ini
[Unit]
Description=IBSR snapshot upload
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/bin/ibsr-export s3 \
  --input /var/lib/ibsr/snapshots \
  --bucket <customer-bucket-name> \
  --prefix ibsr/<host-id>/snapshots
```

**Timer unit** (`/etc/systemd/system/ibsr-upload.timer`):

```ini
[Timer]
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
```

Enable:

```bash
systemctl daemon-reload
systemctl enable --now ibsr-upload.timer
```

### cron (Fallback)

```cron
0 * * * * /usr/local/bin/ibsr-export s3 --input /var/lib/ibsr/snapshots --bucket <customer-bucket-name> --prefix ibsr/<host-id>/snapshots >> /var/log/ibsr-upload.log 2>&1
```

## Authentication

`ibsr-export` uses the **standard AWS credential chain**.

In pilot deployments this is typically:
- an instance or workload role (preferred), or
- static access keys via environment variables

IBSR does not implement custom authentication or token management.

## Access Model

For pilots, data is uploaded to a **customer-owned S3 bucket**.

- The customer creates and owns the bucket
- The IBSR host is granted **write-only** access to a dedicated prefix
- The customer accesses data using existing AWS IAM permissions

IBSR does not require read access to the bucket.
