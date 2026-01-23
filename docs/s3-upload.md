---
title: S3 Upload
nav_order: 3
---

# S3 Uploads

S3 uploads are the **handoff mechanism** between the IBSR collector and report generation.

For pilots, uploading raw snapshot data to S3 is **required**.

## Pilot Default Workflow

1. Run the IBSR collector
2. Upload raw snapshot files to S3
3. IBSR team generates reports under agreement

## Upload Command

```bash
ibsr-export s3   --input /var/lib/ibsr/snapshots   --bucket <customer-bucket>   --prefix ibsr/<deployment-id>/snapshots
```

Uploads are typically scheduled (e.g. systemd timer or cron).

## Authentication

Uploads use the standard AWS credential chain available on the host.
No custom tokens or credential management are implemented by IBSR.

## Access

Buckets are customer-owned.
Customers access uploaded data using their existing AWS IAM permissions.
