# IBSR — Inline Block Simulation Report

IBSR is a **kernel-level traffic collection and analysis tool** used to generate *Inline Block Simulation Reports*.

It runs in **shadow mode** at the XDP/eBPF layer, observing live network traffic and recording what *would* have been blocked under conservative security rules — **without enforcing anything**.

IBSR is designed to run **unattended** and produce **post-run reports**, not live alerts or dashboards.

## What This Repository Contains

| Component | Description |
|-----------|-------------|
| `ibsr` | XDP/eBPF-based traffic collector (shadow mode only) |
| `ibsr-report` | Offline report generator (in `offline-tools/`) |

The components are intentionally separated to keep the collector minimal and safe.

## What IBSR Does

- Attaches an XDP program to a network interface
- Aggregates per-source-IP connection metrics
- Writes bounded, rotated snapshot files
- Produces offline reports summarising simulated block decisions

**All packets are passed. IBSR never blocks traffic.**

## What IBSR Does Not Do

- It does not enforce security policy
- It does not modify or redirect traffic
- It does not generate live alerts
- It does not require human monitoring
- It is not a SIEM, firewall, or IPS

IBSR exists to validate whether inline enforcement *could* be safe — not to provide protection.

## Safety Model

- Shadow mode only (`XDP_PASS`)
- Fail-open by design
- No iptables or netfilter changes
- Bounded memory (LRU map)
- Minimal performance overhead
- Instant detach / removal

If IBSR fails or is removed, the system returns to baseline behaviour.

Safety invariants are verified through compile-time static analysis of both BPF source and compiled ELF.

## Usage Model

IBSR follows a simple, unattended workflow:

```
1. Collect    ibsr collect -p 8899 --out-dir /var/lib/ibsr/snapshots
2. Transfer   rsync snapshots to analysis host
3. Report     ibsr-report --in ./snapshots --out ./report
```

Humans interact only with the final report.

## Quick Start

```bash
# Install (from GitHub Releases)
curl -LO https://github.com/nullrabbit/nr-ibsr/releases/download/v0.1.0/ibsr-$(uname -m)
sudo install -m 755 ibsr-* /usr/local/bin/ibsr

# Run collector
sudo mkdir -p /var/lib/ibsr/snapshots
sudo ibsr collect -p 8899 --out-dir /var/lib/ibsr/snapshots

# Build reporter (from source)
cd offline-tools && cargo build --release

# Generate report
./target/release/ibsr-report --in /var/lib/ibsr/snapshots --out ./report
```

## Documentation

Full documentation lives in [`/docs`](docs/):

| Document | Description |
|----------|-------------|
| [Overview](docs/index.md) | What IBSR is and is not |
| [Installation](docs/install.md) | Download or build from source |
| [Quick Start](docs/quickstart.md) | Get running in 5 minutes |
| [Configuration](docs/configuration.md) | CLI reference and tuning |
| [Deployment](docs/deployment.md) | Production systemd setup |
| [Safety](docs/safety.md) | Safety guarantees and verification |
| [Reporting](docs/reporting.md) | Offline analysis with ibsr-report |
| [Operations](docs/operations.md) | Monitoring and troubleshooting |
| [FAQ](docs/faq.md) | Common questions |

## Requirements

- **OS**: Debian 12+ / Ubuntu 22.04+ (kernel 6.1+)
- **Arch**: arm64 or x86_64
- **Privileges**: root or CAP_BPF
- **NIC**: XDP-capable network interface

## Build from Source

```bash
# Run tests
docker compose run --rm test

# Build release binary
./build.sh

# Output: ./dist/ibsr-<arch>
```

## Status

IBSR is provided for controlled pilots and evaluation.

It is intentionally limited and conservative by design.

## License

MIT
