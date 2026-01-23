---
title: Reporting
nav_order: 7

# Offline Reporting

IBSR generates **offline reports** from traffic snapshots collected on a target host.  
There is no live analysis, no dashboard, and no real-time decision-making.

## Status & Scope

IBSR reporting is **early-stage**.

It is currently intended for:
- controlled pilots
- evaluation and safety testing
- validating whether inline enforcement *could* be safe

The reporting pipeline and outputs may change as the system evolves.  
IBSR should not be relied on for protection.

## Overview

The reporting pipeline is intentionally **offline and unattended**:

1. `ibsr` runs on the target host and writes snapshots
2. `ibsr-report` processes snapshots and generates report artefacts
3. `ibsr-export` uploads artefacts for later review (e.g. to S3)

Humans interact **only with the final artefacts**, never with live output.

## Building `ibsr-report`

```bash
git clone https://github.com/NullRabbitLabs/nr-ibsr.git
cd nr-ibsr/offline-tools
cargo build --release
```

## Snapshot Handling

Snapshots are written as `.jsonl` files and may be processed locally or transferred to another host.

```bash
rsync -avz user@collector:/var/lib/ibsr/snapshots/ ./snapshots/
```

## Running `ibsr-report`

```bash
ibsr-report --in ./snapshots --out ./reports
```

## Report Outputs

```
reports/
├── report.md
├── summary.json
├── evidence.csv
└── rules.json
```

## Delivering Reports (Pilot Default)

For pilots, artefacts are uploaded to a **customer-owned S3 bucket** using `ibsr-export`.

The customer owns the bucket and reads artefacts using existing IAM access.

## Upload Authentication

`ibsr-export` uses the **standard AWS credential chain** on the host:
- instance/workload role (preferred)
- static access keys via environment variables

IBSR does not manage credentials or access control.

## Unattended Execution

IBSR is designed to run unattended. Reports are generated and uploaded on a schedule.

## What IBSR Does Not Require

- dashboards
- live monitoring
- alerting
- log tailing

Artefacts are the interface.
