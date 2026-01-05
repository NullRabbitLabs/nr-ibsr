# IBSR - Inline Block Simulation Report

IBSR is an open-source XDP-based network traffic collector that aggregates TCP connection metrics for monitoring and analysis. It is designed to be **production-safe** for deployment on live systems, including high-throughput validators.

## What It Does

IBSR collects TCP traffic metrics for a single destination port using eBPF/XDP, aggregating per-source-IP counters:

- **SYN count** - TCP connection initiations
- **ACK count** - Acknowledgment packets
- **RST count** - Connection resets
- **Packet count** - Total packets
- **Byte count** - Total bytes

Metrics are periodically written to disk as versioned JSON snapshots for offline analysis or transfer to reporting systems.

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

### Run Tests

```bash
# Run all tests with coverage enforcement
docker compose run --rm test

# Build release binary
docker compose run --rm build
```

### CLI Usage

```bash
# Collect traffic on port 8899, writing snapshots to /var/lib/ibsr
ibsr collect --port 8899 --out-dir /var/lib/ibsr

# With custom rotation settings
ibsr collect --port 8899 \
    --out-dir /var/lib/ibsr \
    --max-files 3600 \
    --max-age 86400 \
    --map-size 100000

# Auto-detect network interface or specify explicitly
ibsr collect --port 8899 --iface eth0
```

### Command Reference

| Flag | Description | Default |
|------|-------------|---------|
| `--port`, `-p` | Destination port to monitor (required) | - |
| `--iface`, `-i` | Network interface | Auto-detect from default route |
| `--out-dir`, `-o` | Snapshot output directory | `/var/lib/ibsr` |
| `--max-files` | Maximum snapshots to retain | 3600 |
| `--max-age` | Maximum snapshot age in seconds | 86400 |
| `--map-size` | BPF LRU map size (max source IPs) | 100000 |

## Snapshot Format

Snapshots are written as single-line JSON files with the naming convention `snapshot_<unix_timestamp>.jsonl`:

```json
{"version":0,"ts_unix_sec":1704067200,"dst_port":8899,"buckets":[{"key_type":"SrcIp","key_value":167772161,"syn":100,"ack":200,"rst":5,"packets":305,"bytes":45000}]}
```

### Schema (v0)

```rust
Snapshot {
    version: u32,       // Schema version (currently 0)
    ts_unix_sec: u64,   // Unix timestamp
    dst_port: u16,      // Monitored port
    buckets: Vec<BucketEntry>,
}

BucketEntry {
    key_type: KeyType,  // "SrcIp" or "SrcCidr24"
    key_value: u32,     // IPv4 address as u32
    syn: u32,
    ack: u32,
    rst: u32,
    packets: u32,
    bytes: u64,
}
```

Buckets are deterministically ordered by `(key_type, key_value)` for stable diffs and testing.

## Architecture

```
nr-ibsr/
├── ibsr-collector/     # Main binary + CLI
├── ibsr-schema/        # Snapshot schema + serialization
├── ibsr-bpf/           # XDP program + safety analysis
├── ibsr-fs/            # Filesystem abstraction + rotation
├── ibsr-clock/         # Clock abstraction for testing
├── Dockerfile          # Test/build container
└── docker-compose.yml  # Test runner
```

### Key Traits (for Testing)

All external boundaries are abstracted behind traits for mock-based testing:

```rust
trait Clock { fn now_unix_sec(&self) -> u64; }
trait MapReader { fn read_counters(&self) -> Result<HashMap<u32, Counters>>; }
trait SnapshotWriter { fn write(&self, snapshot: &Snapshot) -> Result<PathBuf>; }
trait Filesystem { fn write_atomic(&self, path, data); fn list(&self); fn remove(&self); }
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
