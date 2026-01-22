---
title: Reporting
nav_order: 7
---

# Offline Reporting

Generate analysis reports from IBSR snapshots using `ibsr-report`.

## Overview

The reporting pipeline is intentionally **offline**:

1. Collector runs on target host, writes snapshots
2. Snapshots are transferred to analysis host
3. `ibsr-report` processes snapshots and generates reports
4. Human reviews reports before any action

This separation ensures:
- No real-time decisions on production systems
- Reports can be regenerated with different parameters
- Analysis is reproducible and auditable

## Building ibsr-report

The reporter is built from source (not included in releases).

### Prerequisites

- Rust 1.70+ toolchain
- Git

### Build Steps

```bash
# Clone repository (if not already)
git clone https://github.com/NullRabbitLabs/nr-ibsr.git
cd nr-ibsr

# Build the reporter
cd offline-tools
cargo build --release

# Binary location
ls -la target/release/ibsr-report
```

### Install (Optional)

```bash
sudo install -m 755 target/release/ibsr-report /usr/local/bin/
```

## Transferring Snapshots

Copy snapshots from the collector host to the analysis host:

```bash
# Using rsync (recommended)
rsync -avz user@collector:/var/lib/ibsr/snapshots/ ./snapshots/

# Using scp
scp -r user@collector:/var/lib/ibsr/snapshots/ ./snapshots/
```

**Tip**: Only transfer what you need. The reporter processes all `.jsonl` files in the input directory.

## Running ibsr-report

### Basic Usage

```bash
ibsr-report \
  --in ./snapshots \
  --out ./reports
```

### With Port Specification

```bash
ibsr-report \
  --in ./snapshots \
  --out ./reports \
  --dst-ports 8899,8900
```

If `--dst-ports` is omitted, ports are inferred from the snapshot data.

### With Allowlist

```bash
ibsr-report \
  --in ./snapshots \
  --out ./reports \
  --allowlist ./known-good-ips.txt
```

## CLI Reference

```
ibsr-report [OPTIONS] --in <DIR> --out <DIR>
```

### Required Options

| Option | Description |
|--------|-------------|
| `--in, -i <DIR>` | Input directory containing snapshot_*.jsonl files |
| `--out, -o <DIR>` | Output directory for generated reports |

### Optional Options

| Option | Default | Description |
|--------|---------|-------------|
| `--dst-ports <PORTS>` | (inferred) | Comma-separated destination ports |
| `--allowlist <PATH>` | (none) | File with trusted IPs/CIDRs (one per line) |
| `--window-sec` | 10 | Aggregation window size in seconds |
| `--syn-rate-threshold` | 100.0 | SYN/sec threshold for abuse detection |
| `--success-ratio-threshold` | 0.1 | Minimum ACK/SYN ratio for legitimate traffic |
| `--block-duration-sec` | 300 | How long candidate rules would block |
| `--fp-safe-ratio` | 0.5 | Maximum acceptable false positive ratio |
| `--min-samples-for-fp` | 10 | Minimum samples for FP calculation |
| `--vol-syn-rate` | 500.0 | Volumetric SYN threshold (SYN/sec) |
| `--vol-pkt-rate` | 1000.0 | Volumetric packet threshold (pkt/sec) |
| `--vol-byte-rate` | 1000000.0 | Volumetric byte threshold (byte/sec) |
| `-v, --verbose` | (quiet) | Show warnings during parsing |

## Output Files

The reporter generates four files:

```
./reports/
├── rules.json      # Candidate enforcement rules
├── report.md       # Human-readable analysis
├── evidence.csv    # Per-source decision data
└── summary.json    # Machine-readable summary
```

### rules.json

XDP-safe enforcement rules that could be applied:

```json
{
  "version": 3,
  "generated_at": "2025-01-15T14:30:00Z",
  "match_criteria": {
    "proto": "tcp",
    "dst_ports": [8899]
  },
  "triggers": [
    {
      "key_type": "src_ip",
      "key_value": 3232235777,
      "dst_port": 8899,
      "abuse_class": "syn_flood_like",
      "window_sec": 10,
      "thresholds": {
        "syn_rate": 500.0,
        "success_ratio": 0.02
      },
      "action": "block"
    }
  ],
  "exceptions": []
}
```

### report.md

Human-readable report with five sections:

1. **Scope & Configuration** — Time range, ports, thresholds used
2. **Abuse Pattern Observed** — Detected episodes and classifications
3. **Counterfactual Enforcement Impact** — What percentage would be blocked
4. **Candidate Enforcement Rules** — Specific rules to consider
5. **Readiness Judgment** — Whether enforcement is recommended

### evidence.csv

Per-source evidence for auditing:

```csv
source,abuse_class,syn_rate,success_ratio,decision,packets,bytes,syn
192.168.1.100,syn_flood_like,523.40,0.02,block,15234,2345678,5234
10.0.0.5,none,12.30,0.89,allow,1234,123456,123
```

### summary.json

Machine-readable summary (schema v5):

```json
{
  "report_version": 5,
  "run_id": "ibsr-20250115-143000Z",
  "time_range": {
    "start_ts": 1705312800,
    "end_ts": 1705316400,
    "duration_sec": 3600
  },
  "ports_analyzed": [8899],
  "triggers": [...],
  "episodes": [...],
  "blocked_traffic": {
    "packets": 15234,
    "packets_percent": 12.5,
    "bytes": 2345678,
    "bytes_percent": 15.2,
    "syn": 5234,
    "syn_percent": 45.6
  },
  "fp_bound": {"computed": 0.02},
  "enforcement_safe": true,
  "enforcement_reasons": []
}
```

## Allowlist Format

Create a file with trusted IPs or CIDRs, one per line:

```
# known-good-ips.txt
# Trusted infrastructure
10.0.0.0/8
192.168.1.0/24

# Specific trusted sources
203.0.113.50
198.51.100.25
```

- Comments start with `#`
- Empty lines are ignored
- Supports both individual IPs and CIDR notation

Allowlisted sources are never flagged as abuse, regardless of their traffic pattern.

## Abuse Detection

### SYN Flood Detection

Triggered when:
- SYN rate > `--syn-rate-threshold` (default: 100/sec)
- Success ratio (ACK/SYN) < `--success-ratio-threshold` (default: 0.1)

This detects sources sending many connection attempts that don't complete.

### Volumetric Abuse Detection

Triggered when **2 or more** of these thresholds are exceeded:
- SYN rate > `--vol-syn-rate` (default: 500/sec)
- Packet rate > `--vol-pkt-rate` (default: 1000/sec)
- Byte rate > `--vol-byte-rate` (default: 1,000,000/sec)

This detects high-volume traffic that may exhaust resources.

## Episode Detection

The reporter identifies **episodes** — contiguous time windows where a source exhibits abusive patterns.

Episode types:
- **single_window**: Abuse detected in only one aggregation window
- **multi_window**: Abuse detected across multiple consecutive windows

**Important**: Single-window episodes require manual review before enforcement. The report marks `enforcement_safe: false` if only single-window episodes are detected.

## Interpreting Results

### Readiness Judgment

The report provides an `enforcement_safe` judgment based on:

1. **False positive bound** — Must be < 5%
2. **Offenders found** — At least one abusive source detected
3. **Impact threshold** — At least 1% of SYN traffic would be blocked
4. **Episode duration** — Multi-window episodes provide higher confidence

### When enforcement_safe = true

The report recommends that enforcement **could** be safely enabled, based on:
- Clear abuse patterns detected
- Low false positive risk
- Sufficient traffic to validate

### When enforcement_safe = false

Manual review required. Common reasons:
- Only single-window episodes (could be transient)
- Insufficient data (false positive bound unknown)
- Low impact (may not be worth the risk)

## Example Workflow

### 1. Collect Data

Run collector for sufficient duration (recommended: 1-24 hours):

```bash
sudo ibsr collect -p 8899 --out-dir /var/lib/ibsr/snapshots --duration-sec 86400
```

### 2. Transfer Data

```bash
rsync -avz server:/var/lib/ibsr/snapshots/ ./data/
```

### 3. Generate Report

```bash
ibsr-report \
  --in ./data \
  --out ./report \
  --dst-ports 8899 \
  --allowlist ./trusted-ips.txt \
  -v
```

### 4. Review Report

```bash
cat ./report/report.md
```

### 5. Examine Evidence

```bash
# Sort by SYN rate
sort -t, -k3 -rn ./report/evidence.csv | head -20
```

## Threshold Tuning

### Stricter Detection (More Alerts)

```bash
ibsr-report \
  --syn-rate-threshold 50 \
  --success-ratio-threshold 0.2 \
  --vol-syn-rate 200 \
  ...
```

### Looser Detection (Fewer False Positives)

```bash
ibsr-report \
  --syn-rate-threshold 200 \
  --success-ratio-threshold 0.05 \
  --vol-syn-rate 1000 \
  ...
```

### Tune for Your Environment

Start with defaults, then adjust based on:
- Normal traffic patterns in your environment
- False positive rate in reports
- Severity of abuse you want to detect

## Next Steps

- [Operations](operations.md) — Monitoring and troubleshooting
- [How It Works](how-it-works.md) — Technical details
- [FAQ](faq.md) — Common questions
