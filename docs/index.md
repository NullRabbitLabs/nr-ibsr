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

## Intended Use Cases

| Use Case | Description |
|----------|-------------|
| Pilot deployments | Validate enforcement rules before enabling |
| Validator infrastructure | Monitor RPC endpoints for abuse patterns |
| Edge/ingress systems | Pre-enforcement validation on load balancers |
| Safety case generation | Document enforcement impact for review |

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
│                     └─────────────┘         └─────────┘        │
└─────────────────────────────────────────────────────────────────┘
                                                    │
                              ┌─────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Offline Analysis Host                        │
│                                                                 │
│  ┌──────────────┐    ┌──────────────────────────────────────┐  │
│  │ Snapshots    │───▶│ ibsr-report                          │  │
│  │ (JSONL)      │    │                                      │  │
│  └──────────────┘    │  ├─ rules.json (enforcement rules)   │  │
│                      │  ├─ report.md  (human-readable)      │  │
│                      │  ├─ evidence.csv (per-source)        │  │
│                      │  └─ summary.json (machine-readable)  │  │
│                      └──────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
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
| [Reporting](reporting.md) | Offline analysis with ibsr-report |
| [Operations](operations.md) | Monitoring, troubleshooting, maintenance |
| [Upgrading](upgrading.md) | Version upgrades and rollback |
| [FAQ](faq.md) | Frequently asked questions |

## Design Principles

**Shadow-only**: IBSR never drops, redirects, or modifies packets. All packets return `XDP_PASS`.

**Fail-open**: If the collector crashes or the XDP program detaches, traffic continues unaffected.

**Bounded resources**: LRU map with configurable size ensures memory usage is predictable.

**Offline analysis**: All decision-making happens offline. No real-time enforcement logic.

**Conservative by default**: Thresholds and rules err on the side of false negatives over false positives.
