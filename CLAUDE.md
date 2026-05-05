# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**nr-ibsr** is an open source greenfield project implementing an eBPF/XDP-based IP collector with snapshot persistence. The on-box binary is a **strictly passive snapshot recorder** - it collects traffic metrics and writes snapshots to disk, but does NOT perform any analysis.

Analysis and report generation happen offline using tools in `offline-tools/`.

## Architecture

IBSR follows a hyperscaler/cloudflare-shaped operator-edge model: passive
observation at the network boundary with one load-bearing safety
guarantee — **shadow mode means no traffic is dropped, redirected, or
modified**. Two operating modes share that invariant; they differ in what
observation capability is permitted underneath. See `docs/safety.md` for
the full safety story.

### On-Box Binary

`ibsr` exposes two subcommands corresponding to the two safety profiles:

#### `ibsr collect` — StrictCounter mode (existing, default)
- XDP/eBPF program for capturing unique source IPs on target ports
- Counter-only — no per-packet events, no payload reads
- LRU map for memory-bounded IP tracking
- BPF source: `ibsr-bpf/src/bpf/counter.bpf.c`
- Snapshot schema v5 (or v6 with no `resp_aggregates`)
- Privacy posture: payload bytes never leave the kernel

#### `ibsr collect-payload` — ShadowPayload mode (in progress)
- TC ingress/egress eBPF programs that sample TCP payload to a ringbuf
- Userspace TCP-stream reassembler + httparse-based HTTP parser
- Per-window `ResponseAggregates` matching offline `nr_training/features/responses.py`
- BPF source: `ibsr-bpf/src/bpf/tc_payload.bpf.c`
- Snapshot schema v6 with `resp_aggregates` populated
- Mode-invariant rules still enforced: no drops/redirects/modifies; ringbuf pressure
  cannot backpressure the network stack (event drops, packet doesn't)
- Used for traffic-intelligence at operator-controlled boundaries (validator
  infrastructure, edge proxies, API gateways)
- Userspace handler in `ibsr-collector/src/payload.rs`

Both subcommands share JSON snapshot persistence with atomic writes, LRU /
window eviction discipline, and append-only `status.jsonl` heartbeats.

### Safety Verification (`ibsr-bpf/src/safety.rs`)

`SafetyProfile { StrictCounter | ShadowPayload }` selects which checks
apply. Mode-invariant checks (no drops, no redirects, no packet
modification, no DEVMAP/XSKMAP/CPUMAP) run for both. Mode-specific
checks: StrictCounter forbids ringbuf/perf_event helpers + map types
and requires `BPF_MAP_TYPE_LRU_HASH`; ShadowPayload permits ringbuf
and lifts the LRU requirement (bounded-memory discipline shifts to
userspace).

### Offline Tools (`offline-tools/`)
- **ibsr-reporter**: Consumes snapshots and produces reports, rules, and evidence
- **ibsr-conformance**: Golden fixtures and conformance testing harness

### Export Tool (`ibsr-export/`)
- **ibsr-export**: Uploads report artefacts to S3 or S3-compatible storage (MinIO, R2)
- Standalone crate (excluded from main workspace to keep AWS deps separate)
- Features: concurrent uploads, retries, SSE encryption, presigned URLs

## Current State

- StrictCounter (`ibsr collect`): complete, in production-equivalent state.
- ShadowPayload (`ibsr collect-payload`): in progress — BPF programs +
  safety verification + userspace HTTP parser + window aggregator + schema
  v6 are done; remaining work is the BPF loader / TC attach / ringbuf
  consumer wiring + the `collect-payload` subcommand CLI.
- Snapshot persistence with rotation: complete.
- Status heartbeat (`status.jsonl`): implemented.
- Reporter and conformance tooling: in `offline-tools/`.
- Comprehensive test coverage (99%+ lines).

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

### `ibsr collect` — StrictCounter mode

Collect traffic counters using XDP/eBPF. Counter-only; no payload reads.

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
  snapshot_<timestamp>.jsonl   Per-cycle traffic snapshot (schema v6 without
                                resp_aggregates — Strict-equivalent window)
  status.jsonl                 Append-only heartbeat/progress log
```

### `ibsr collect-payload` — ShadowPayload mode (in progress)

Collect per-window response-amplification aggregates via TC ingress/egress
eBPF + userspace HTTP-stream reassembly. Used at operator-controlled
boundaries where payload-aware traffic intelligence is the goal.

```bash
ibsr collect-payload --dst-port <PORT> [OPTIONS]

Required:
  --dst-port, -p <PORT>   Server-side TCP port(s) to monitor (repeatable, max 8)
                          Filters both directions: dst_port==server (request) +
                          src_port==server (response).

Optional:
  --iface, -i <IFACE>     Network interface for TC attach (default: lo, the
                          post-term loopback vantage)
  --out-dir, -o <DIR>     Snapshot output directory
  --max-flows <N>         Userspace flow-table cap (default: 8192)
  --window-sec <SECS>     Snapshot emission interval (default: 60)
  --ringbuf-bytes <N>     BPF ringbuf size (default: 16 MiB)
  -v, --verbose           Increase verbosity (-v, -vv)

Outputs:
  snapshot_<timestamp>.jsonl   Per-window snapshot (schema v6 with
                                resp_aggregates populated)
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
