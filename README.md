# IBSR - Inline Block Simulation Report

IBSR is an open-source XDP-based network traffic collector that aggregates TCP connection metrics for monitoring and analysis. It is designed to be **production-safe** for deployment on live systems, including high-throughput validators.

## What It Does

IBSR collects TCP traffic metrics for up to 8 destination ports using eBPF/XDP, aggregating per-source-IP counters:

- **SYN count** - TCP connection initiations
- **ACK count** - Acknowledgment packets
- **Handshake ACK count** - ACKs completing TCP handshake (no payload)
- **RST count** - Connection resets
- **Packet count** - Total packets
- **Byte count** - Total bytes

Metrics are periodically written to disk as versioned JSON snapshots for offline analysis or transfer to reporting systems. A status heartbeat file tracks collection progress.

## Safety Guarantees

IBSR is designed with strict safety constraints for production deployment:

### What IBSR Cannot Do

| Guarantee | Enforcement |
|-----------|-------------|
| **Cannot drop packets** | XDP program only returns `XDP_PASS`; no `XDP_DROP`/`XDP_ABORTED` code paths |
| **Cannot redirect traffic** | No `XDP_REDIRECT`, devmap, or AF_XDP support |
| **Cannot emit per-packet events** | No ringbuf or perf_event output; counters only |
| **Cannot consume unbounded memory** | Uses LRU hash map with configurable max entries |
| **Cannot block packet processing** | O(1) counter increment per packet |

### Safety Verification

Safety guarantees are enforced through belt-and-suspenders static analysis:

1. **Source-level analysis**: Parses the BPF C source to detect forbidden patterns before compilation
2. **ELF inspection**: Scans compiled object files for forbidden symbols and map types

Both analyses run as part of the test suite with every build.

## Quick Start

### Prerequisites

- Docker and Docker Compose
- macOS or Linux development host

### Build & Test

```bash
# Run all tests with coverage enforcement (in Docker)
docker compose run --rm test

# Build release binary for deployment (in Docker)
./build.sh

# Output binary will be at ./dist/ibsr-<arch>
```

### CLI Usage

```bash
# Single port monitoring
ibsr collect -p 8899 --out-dir /var/lib/ibsr

# Multiple ports (repeatable flag, max 8)
ibsr collect -p 22 -p 80 -p 443 --out-dir /var/lib/ibsr

# Multiple ports (comma-separated)
ibsr collect --dst-ports 22,80,443 --out-dir /var/lib/ibsr

# Run for specific duration (180 seconds)
ibsr collect -p 8899 --duration-sec 180 --out-dir ./output

# With custom rotation and verbosity
ibsr collect -p 8899 \
    --out-dir /var/lib/ibsr \
    --max-files 3600 \
    --max-age 86400 \
    --map-size 100000 \
    -vv

# Specify network interface explicitly
ibsr collect -p 8899 --iface eth0
```

### Command Reference

| Flag | Description | Default |
|------|-------------|---------|
| `--dst-port`, `-p` | Destination port to monitor (repeatable, max 8) | Required |
| `--dst-ports` | Comma-separated list of ports | - |
| `--duration-sec` | Run for N seconds then exit | Continuous |
| `--iface`, `-i` | Network interface | Auto-detect |
| `--out-dir`, `-o` | Snapshot output directory | `/var/lib/ibsr/snapshots` |
| `--max-files` | Maximum snapshot files to retain | 3600 |
| `--max-age` | Maximum snapshot age in seconds | 86400 |
| `--map-size` | BPF LRU map size (max source IPs) | 100000 |
| `--report-interval-sec` | Status heartbeat interval | 60 |
| `-v`, `--verbose` | Increase verbosity (-v, -vv) | Quiet |

## Snapshot Format

Snapshots are written as JSONL (one JSON object per line) in hourly files named `snapshot_YYYYMMDDHH.jsonl`:

```json
{"version":2,"ts_unix_sec":1704067200,"dst_ports":[22,80,443],"buckets":[{"key_type":"src_ip","key_value":167772161,"syn":100,"ack":200,"handshake_ack":95,"rst":5,"packets":305,"bytes":45000}]}
```

### Schema (v2)

```rust
Snapshot {
    version: u32,           // Schema version (currently 2)
    ts_unix_sec: u64,       // Unix timestamp
    dst_ports: Vec<u16>,    // Monitored ports
    buckets: Vec<BucketEntry>,
}

BucketEntry {
    key_type: KeyType,      // "src_ip"
    key_value: u32,         // IPv4 address as u32
    syn: u32,               // SYN packets
    ack: u32,               // ACK packets
    handshake_ack: u32,     // ACKs completing handshake (no payload)
    rst: u32,               // RST packets
    packets: u32,           // Total packets
    bytes: u64,             // Total bytes
}
```

Buckets are deterministically ordered by `(key_type, key_value)` for stable diffs and testing.

## Status File

A `status.jsonl` file is written to the output directory, tracking collection progress:

```json
{"timestamp":1704067200,"cycle":1,"ips_collected":42,"snapshots_written":1}
{"timestamp":1704067260,"cycle":2,"ips_collected":45,"snapshots_written":2}
```

| Field | Description |
|-------|-------------|
| `timestamp` | Unix epoch when cycle completed |
| `cycle` | Collection cycle number (1-indexed) |
| `ips_collected` | Unique source IPs in this cycle |
| `snapshots_written` | Cumulative snapshots written |

## Architecture

```
nr-ibsr/
├── ibsr-collector/     # Main binary + CLI
├── ibsr-schema/        # Snapshot schema + serialization
├── ibsr-bpf/           # XDP program + safety analysis
├── ibsr-fs/            # Filesystem abstraction + rotation
├── ibsr-clock/         # Clock abstraction for testing
├── offline-tools/      # Offline analysis tools
│   ├── ibsr-reporter/  # Snapshot ingestion + report generation
│   └── ibsr-conformance/  # Golden fixtures + conformance tests
├── build.sh            # Release build script
├── Dockerfile          # Test/build container
└── docker-compose.yml  # Test runner
```

### Output Files

When running `ibsr collect`, the output directory contains:

```
output/
├── snapshot_2024010112.jsonl  # Hourly snapshot file (YYYYMMDDHH)
├── snapshot_2024010113.jsonl  # Next hour's snapshots
└── status.jsonl               # Append-only heartbeat log
```

### Key Traits (for Testing)

All external boundaries are abstracted behind traits for mock-based testing:

```rust
trait Clock { fn now_unix_sec(&self) -> u64; }
trait MapReader { fn read_counters(&self) -> Result<HashMap<u32, Counters>>; }
trait SnapshotWriter { fn write(&self, snapshot: &Snapshot) -> Result<PathBuf>; }
trait Filesystem { fn write_atomic(&self, path, data); fn list(&self); fn remove(&self); }
```

## Offline Parsing

Snapshots can be parsed offline using the `offline-tools/ibsr-reporter` crate or any JSON parser.

### Using ibsr-reporter (Rust)

```rust
use ibsr_reporter::ingest::{load_snapshots_from_dir, parse_snapshot};
use std::path::Path;

// Load all snapshots from a directory
let stream = load_snapshots_from_dir(
    Path::new("./output"),
    Some(|file, err| eprintln!("Warning: {} - {}", file, err)),
)?;

println!("Loaded {} snapshots", stream.len());
for snapshot in stream.iter() {
    println!("ts={} ports={:?} ips={}",
        snapshot.ts_unix_sec,
        snapshot.dst_ports,
        snapshot.buckets.len());
}

// Parse a single line
let json = r#"{"version":2,"ts_unix_sec":1000,"dst_ports":[22],"buckets":[]}"#;
let snapshot = parse_snapshot(json)?;
```

### Using jq (Command Line)

```bash
# List all unique source IPs with their SYN counts
cat output/*.jsonl | jq -r '.buckets[] | "\(.key_value) \(.syn)"' | sort -u

# Convert IP addresses to dotted notation
cat output/*.jsonl | jq -r '.buckets[] |
  "\((.key_value / 16777216 | floor)).\(((.key_value / 65536) % 256) | floor).\(((.key_value / 256) % 256) | floor).\(.key_value % 256) syn=\(.syn) ack=\(.ack)"'

# Sum total bytes per hour file
for f in output/snapshot_*.jsonl; do
  echo -n "$f: "
  jq -s '[.[].buckets[].bytes] | add' "$f"
done
```

### Using Python

```python
import json
from pathlib import Path

def parse_snapshots(directory):
    for path in Path(directory).glob("snapshot_*.jsonl"):
        with open(path) as f:
            for line in f:
                snapshot = json.loads(line)
                yield snapshot

# Example usage
for snap in parse_snapshots("./output"):
    print(f"ts={snap['ts_unix_sec']} ports={snap['dst_ports']}")
    for bucket in snap["buckets"]:
        ip = bucket["key_value"]
        ip_str = f"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}"
        print(f"  {ip_str}: syn={bucket['syn']} ack={bucket['ack']}")
```

## Testing

### Coverage Requirements

The test suite enforces strict coverage thresholds:

- **99% line coverage** - Accounts for auto-generated derive macro code
- **95% function coverage** - Accounts for mock implementations and derive macros

### Test Categories

| Category | Description |
|----------|-------------|
| Schema/Encoding | Round-trip serialization, deterministic ordering, version handling |
| XDP Safety | Static analysis of BPF source and compiled ELF |
| Map Conversion | Counter-to-snapshot transformation with mocked clock |
| Filesystem | Rotation logic, atomic writes, naming conventions |
| CLI | Argument parsing, validation, error messages |
| Integration | End-to-end collector loop with mocked boundaries |

### Running Specific Tests

```bash
# Run tests for a specific crate
docker compose run --rm test cargo test -p ibsr-schema

# Run tests with output
docker compose run --rm test cargo test -- --nocapture

# Generate coverage report
docker compose run --rm test cargo llvm-cov --html
```

## Deployment

### Target Platform

- **OS**: Debian 12 (kernel 6.1+)
- **Runtime**: Systemd service
- **Requirements**: Root or CAP_BPF capability for XDP attachment

### Production Recommendations

1. Use `--map-size` to limit memory usage based on expected unique source IPs
2. Configure `--max-files` and `--max-age` based on disk space and retention needs
3. Monitor snapshot output directory for disk usage
4. Transfer snapshots to reporting systems before rotation removes them

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

1. Write tests first (TDD is mandatory)
2. Ensure `docker compose run --rm test` passes
3. Follow existing code patterns and conventions
4. Keep safety invariants intact
