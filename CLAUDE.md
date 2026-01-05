# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**nr-ibsr** is an open source greenfield project implementing an eBPF/XDP-based IP collector with snapshot persistence. The implementation follows a phased approach:

1. **XDP Collector + Snapshot Schema** - Data collection layer ✓ COMPLETE
2. **IBSR Reporter Core** - Core reporting functionality ✓ COMPLETE
3. **CLI + IO Boundaries** - Command-line interface and I/O handling
4. **Portability & Conformance** - Cross-platform support and testing harness

## Current State

Phase 2 is complete. The project now has:

- XDP/eBPF program for capturing unique source IPs on a target port
- Rust userspace collector using libbpf-rs
- JSON snapshot persistence with atomic writes
- LRU map for memory-bounded IP tracking
- **Reporter core** that consumes snapshots and produces:
  - `rules.json` - Deployable XDP-safe enforcement rules
  - `report.md` - IBSR artifact with 5 required sections
- Abuse detection for TCP SYN churn with configurable thresholds
- Counterfactual impact analysis with FP bounds
- Comprehensive test coverage (99%+ lines)

Next: Phase 3 (CLI + IO Boundaries)

## Deployment Target

- **OS**: Debian 12 (kernel 6.1+)
- **Runtime**: Systemd service (native binary)
- **Technology**: Rust with XDP/eBPF via libbpf-rs

## Build & Test Commands

```bash
# Run all tests with 100% coverage enforcement (in Docker)
docker compose run --rm test

# Build release binary (in Docker, for deployment)
docker compose run --rm build
```

Development on macOS; all tests run in Docker (Linux container with BPF toolchain).

## CLI Synopsis

```bash
ibsr collect --port <PORT> [OPTIONS]

Required:
  --port <PORT>         TCP destination port to monitor

Optional:
  --iface <IFACE>       Network interface (default: auto-detect from default route)
  --out-dir <DIR>       Snapshot output directory (default: ./snapshots)
  --max-files <N>       Max snapshot files to retain (default: 3600)
  --max-age <SECS>      Max age of snapshots in seconds (default: none)
  --map-size <N>        LRU map size for unique IPs (default: 100000)
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
