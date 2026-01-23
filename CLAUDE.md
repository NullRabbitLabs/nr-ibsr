# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**nr-ibsr** is an open source greenfield project implementing an eBPF/XDP-based IP collector with snapshot persistence. The on-box binary is a **strictly passive snapshot recorder** - it collects traffic metrics and writes snapshots to disk, but does NOT perform any analysis.

Analysis and report generation happen offline using tools in `offline-tools/`.

## Architecture

### On-Box Binary (`ibsr collect`)
- XDP/eBPF program for capturing unique source IPs on target ports
- Rust userspace collector using libbpf-rs
- JSON snapshot persistence with atomic writes
- LRU map for memory-bounded IP tracking
- Append-only `status.jsonl` heartbeat for monitoring
- Single subcommand: `collect`

### Offline Tools (`offline-tools/`)
- **ibsr-reporter**: Consumes snapshots and produces reports, rules, and evidence
- **ibsr-conformance**: Golden fixtures and conformance testing harness

### Export Tool (`ibsr-export/`)
- **ibsr-export**: Uploads report artefacts to S3 or S3-compatible storage (MinIO, R2)
- Standalone crate (excluded from main workspace to keep AWS deps separate)
- Features: concurrent uploads, retries, SSE encryption, presigned URLs

## Current State

- XDP/eBPF traffic collection is complete
- Snapshot persistence with rotation is complete
- Status heartbeat (`status.jsonl`) is implemented
- Reporter and conformance tooling moved to `offline-tools/`
- Comprehensive test coverage (99%+ lines)

## Deployment Target

- **OS**: Debian 12 (kernel 6.1+)
- **Runtime**: Systemd service (native binary)
- **Technology**: Rust with XDP/eBPF via libbpf-rs

## Build & Test Commands

```bash
# Run all tests with coverage enforcement (in Docker)
docker compose run --rm test

# Build release binary (in Docker, for deployment)
./build.sh

# Build ibsr-export (S3 uploader)
./build-export.sh
```

Development on macOS; all tests run in Docker (Linux container with BPF toolchain).

**IMPORTANT:** Always run both `test` AND `./build.sh` before considering a task complete. Tests passing does not guarantee the release build succeeds - always verify with `./build.sh` after tests pass.

Pre-built binaries for both `ibsr` and `ibsr-export` are available from [GitHub Releases](https://github.com/NullRabbitLabs/nr-ibsr/releases).

## CLI Synopsis

### `ibsr collect`

Collect traffic metrics using XDP/eBPF.

```bash
ibsr collect --dst-port <PORT> [OPTIONS]

Required:
  --dst-port, -p <PORT>   TCP destination port(s) to monitor (repeatable, max 8)
  --dst-ports <PORTS>     Comma-separated list of ports (alternative to -p)

Optional:
  --duration-sec <SECS>   Run for N seconds then stop (default: continuous until SIGINT)
  --iface, -i <IFACE>     Network interface (auto-detect if omitted)
  --out-dir, -o <DIR>     Snapshot output directory (default: /var/lib/ibsr/snapshots)
  --max-files <N>         Max snapshot files to retain (default: 3600)
  --max-age <SECS>        Max age of snapshots in seconds (default: 86400)
  --map-size <N>          BPF LRU map size (default: 100000)
  -v, --verbose           Increase verbosity (-v, -vv)
  --status-interval-sec   Interval for status.jsonl updates (default: 60)

Outputs:
  snapshot_<timestamp>.jsonl   Per-cycle traffic snapshot
  status.jsonl                 Append-only heartbeat/progress log
```

### Status File Format

The `status.jsonl` file is written to the output directory, one JSON line per collection cycle:

```json
{"timestamp":1704067200,"cycle":1,"ips_collected":42,"snapshots_written":1}
{"timestamp":1704067201,"cycle":2,"ips_collected":45,"snapshots_written":2}
```

Fields:
- `timestamp`: Unix epoch seconds when cycle completed
- `cycle`: Collection cycle number (1-indexed)
- `ips_collected`: Unique IPs in this cycle
- `snapshots_written`: Cumulative snapshots written

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

## Documentation Policy

**Always update documentation when:**
- Adding new features or tools
- Changing CLI interfaces or flags
- Modifying build/deployment processes
- Changing configuration options

**Documentation locations:**
- `docs/` - User-facing documentation (Jekyll site)
- `CLAUDE.md` - Developer guidance and architecture overview
- Code comments - Implementation details only

**When adding a new tool or feature:**
1. Update `CLAUDE.md` architecture section
2. Add/update relevant page in `docs/`
3. Update CLI synopsis if applicable
4. Ensure build commands are documented
