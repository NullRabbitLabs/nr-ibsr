---
title: Home
nav_order: 1
---

# IBSR - Inline Block Simulation Report

IBSR is a **kernel-level shadow-mode security validation system** for network traffic.

It runs at the XDP/eBPF layer and observes live TCP traffic, collecting metrics that would inform inline enforcement decisions — **without enforcing anything**.

IBSR exists to generate **evidence** that inline enforcement could be safe *before* it is allowed to act.

## What IBSR Does

- Attaches an XDP/eBPF program to a network interface
- Observes TCP packets at the earliest possible point in the kernel
- Aggregates per-source-IP metrics (SYN, ACK, RST, packets, bytes)
- Writes structured snapshots to disk for offline analysis
- **Always passes traffic** (`XDP_PASS` only)

## What IBSR Is Not

| Not This | Why |
|----------|-----|
| Firewall | No packet drops, no enforcement |
| IPS | No signatures, no blocking |
| Real-time dashboard | Batch snapshots, offline analysis |
| Threat intelligence consumer | No external feeds, pure observation |

IBSR does not protect systems.
It validates whether protection *could* be safely applied.

## Why IBSR Exists

Inline enforcement is powerful but dangerous without proof.

Most security systems operate reactively and enforce policies without demonstrating mechanical correctness or measuring blast radius.

IBSR answers one question:

> "What would have happened if conservative inline rules were enforced?"

By running in shadow mode on production traffic, IBSR generates evidence for:

- **False positive surface** — legitimate traffic that would be blocked
- **Candidate block rules** — sources exhibiting abusive patterns
- **Counterfactual impact** — percentage of traffic affected

## Status & Maturity

IBSR is **early-stage software**.

It is currently used in:
- controlled pilots
- evaluation environments
- safety and feasibility testing

IBSR is intentionally limited in scope and functionality.  
Interfaces, outputs, and tooling may change as the system evolves.

It is **not** a general-purpose security product and should not be relied on for protection.

## Intended Use Cases

| Use Case | Description |
|----------|-------------|
| Pilot deployments | Observe traffic patterns before considering enforcement |
| Validator infrastructure | Collect RPC endpoint traffic data for analysis |
| Edge/ingress systems | Shadow-mode observation on load balancers |
| Baseline establishment | Generate evidence for future enforcement decisions |

## Pilot Workflow

In pilot deployments, the workflow is:

1. **Collect**: IBSR runs on your infrastructure, collecting traffic snapshots
2. **Upload**: Scheduled uploads send snapshots to your S3 bucket using `ibsr-export`
3. **Report**: The IBSR team generates reports from uploaded data
4. **Review**: You receive finished reports — no analysis required on your end

The collector runs unattended once configured. There are no dashboards to watch and no logs to tail.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Target Host                             │
│                                                                 │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │ Network     │───▶│ XDP/eBPF     │───▶│ ibsr collect     │   │
│  │ Interface   │    │ (XDP_PASS)   │    │ (userspace)      │   │
│  └─────────────┘    └──────────────┘    └────────┬─────────┘   │
│                            │                      │             │
│                     Counter updates          Snapshots          │
│                            │                      │             │
│                     ┌──────▼──────┐         ┌────▼────┐        │
│                     │ BPF LRU Map │         │ Disk    │        │
│                     │ (per-IP)    │         │ JSONL   │        │
│                     └─────────────┘         └────┬────┘        │
└──────────────────────────────────────────────────┼──────────────┘
                                                   │
                              ┌─────────────────────┘
                              ▼
                   ┌────────────────────┐
                   │ ibsr-export s3     │
                   │ (scheduled upload) │
                   └─────────┬──────────┘
                             │
                             ▼
                   ┌────────────────────┐
                   │ Customer S3 Bucket │
                   │ (snapshots)        │
                   └─────────┬──────────┘
                             │
                             ▼
                   ┌────────────────────┐
                   │ IBSR Team          │
                   │ (report generation)│
                   └─────────┬──────────┘
                             │
                             ▼
                   ┌────────────────────┐
                   │ Customer receives  │
                   │ final reports      │
                   └────────────────────┘
```

## Documentation

| Document | Description |
|----------|-------------|
| [Installation](install.md) | System requirements and installation methods |
| [Quick Start](quickstart.md) | Get running in 5 minutes |
| [Configuration](configuration.md) | CLI reference and tuning options |
| [Deployment](deployment.md) | Production deployment with systemd |
| [How It Works](how-it-works.md) | Technical deep dive |
| [Safety Model](safety.md) | Safety guarantees and risk profile |
| [Reporting](reporting.md) | S3 upload and report delivery |
| [Operations](operations.md) | Monitoring, troubleshooting, maintenance |
| [Upgrading](upgrading.md) | Version upgrades and rollback |
| [FAQ](faq.md) | Frequently asked questions |

## Design Principles

**Shadow-only**: IBSR never drops, redirects, or modifies packets. All packets return `XDP_PASS`.

**Fail-open**: If the collector crashes or the XDP program detaches, traffic continues unaffected.

**Bounded resources**: LRU map with configurable size ensures memory usage is predictable.

**Offline analysis**: All decision-making happens offline. No real-time enforcement logic.

**Conservative by default**: Thresholds and rules err on the side of false negatives over false positives.
