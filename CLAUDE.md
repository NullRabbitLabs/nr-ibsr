# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**nr-ibsr** is an open source greenfield project implementing an eBPF/XDP-based IP collector with snapshot persistence. The implementation follows a phased approach:

1. **XDP Collector + Snapshot Schema** - Data collection layer ✓ COMPLETE
2. **IBSR Reporter Core** - Core reporting functionality ✓ COMPLETE
3. **CLI + IO Boundaries** - Command-line interface and I/O handling ✓ COMPLETE
4. **Portability & Conformance** - Cross-platform support and testing harness ✓ COMPLETE

## Current State

All phases complete. The project now has:

- XDP/eBPF program for capturing unique source IPs on a target port
- Rust userspace collector using libbpf-rs
- JSON snapshot persistence with atomic writes
- LRU map for memory-bounded IP tracking
- **Reporter core** that consumes snapshots and produces:
  - `rules.json` - Deployable XDP-safe enforcement rules
  - `report.md` - IBSR artifact with 5 required sections
- Abuse detection for TCP SYN churn with configurable thresholds
- Counterfactual impact analysis with FP bounds
- **Unified CLI** with three subcommands: `collect`, `report`, `run`
- **Conformance harness** (`ibsr-conformance` crate) with:
  - Golden fixtures for 5 test scenarios
  - Deterministic output validation (byte-for-byte)
  - Fixture loader and runner for other implementations
- Comprehensive test coverage (97%+ lines)

## Deployment Target

- **OS**: Debian 12 (kernel 6.1+)
- **Runtime**: Systemd service (native binary)
- **Technology**: Rust with XDP/eBPF via libbpf-rs

## Build & Test Commands

```bash
# Run all tests with coverage enforcement (in Docker)
docker compose run --rm test

# Build release binary (in Docker, for deployment)
docker compose run --rm build
```

Development on macOS; all tests run in Docker (Linux container with BPF toolchain).

## CLI Synopsis

### `ibsr collect`

Collect traffic metrics using XDP/eBPF.

```bash
ibsr collect --dst-port <PORT> [OPTIONS]

Required:
  --dst-port, -p <PORT>   TCP destination port to monitor

Optional:
  --duration-sec <SECS>   Run for N seconds then stop (default: continuous until SIGINT)
  --iface, -i <IFACE>     Network interface (auto-detect if omitted)
  --out-dir, -o <DIR>     Snapshot output directory (default: ./snapshots)
  --max-files <N>         Max snapshot files to retain (default: 3600)
  --max-age <SECS>        Max age of snapshots in seconds (default: 86400)
  --map-size <N>          BPF LRU map size (default: 100000)
```

### `ibsr report`

Generate report from collected snapshots.

```bash
ibsr report --in <DIR> --out-dir <DIR> [OPTIONS]

Required:
  --in <DIR>              Input snapshot directory
  --out-dir <DIR>         Output directory for artifacts

Optional:
  --allowlist <FILE>      Path to allowlist file (one IP or CIDR per line)
  --window-sec <SECS>     Analysis window size (default: 10)
  --syn-rate-threshold <N>       Override SYN rate threshold
  --success-ratio-threshold <N>  Override success ratio threshold
  --block-duration-sec <N>       Override block duration

Outputs:
  report.md               IBSR report with 5 sections
  rules.json              Deployable XDP-safe rules
  evidence.csv            Per-source decision evidence
```

### `ibsr run`

Collect for a duration, then generate report.

```bash
ibsr run --dst-port <PORT> --duration-sec <SECS> --out-dir <DIR> [OPTIONS]

Required:
  --dst-port, -p <PORT>   TCP destination port to monitor
  --duration-sec <SECS>   Collection duration (required for run command)
  --out-dir <DIR>         Output directory for artifacts

Optional:
  --snapshot-dir <DIR>    Snapshot directory (default: ./snapshots)
  --iface, -i <IFACE>     Network interface (auto-detect if omitted)
  --max-files <N>         Max snapshot files to retain (default: 3600)
  --max-age <SECS>        Max age of snapshots in seconds (default: 86400)
  --map-size <N>          BPF LRU map size (default: 100000)
  --allowlist <FILE>      Path to allowlist file
  --window-sec <SECS>     Analysis window size (default: 10)
  --syn-rate-threshold <N>       Override SYN rate threshold
  --success-ratio-threshold <N>  Override success ratio threshold
  --block-duration-sec <N>       Override block duration
```

## Git Commit Policy

- Never mention Claude, AI, or any AI assistant in commit messages
- No `Co-Authored-By` lines referencing AI
- Commit messages should describe what changed and why

## Clean Code Standards

**Guard Clauses Over Nesting**
- Return early for error conditions and edge cases
- Avoid nested if/else statements
- Keep the happy path at the lowest indentation level

**Single Responsibility**
- Each function does one thing
- Each module has one reason to change
- If a function needs "and" in its description, split it

**Control Flow**
- No deeply nested conditionals (max 2 levels)
- Extract complex conditions into named boolean variables or functions
- Prefer switch/match statements over long if/else chains when appropriate
