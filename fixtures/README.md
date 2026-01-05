# IBSR Conformance Fixtures

This directory contains golden fixtures for validating IBSR reporter implementations.

## Fixture Format

Each fixture is a directory with the following structure:

```
fixture-name/
├── scenario.json      # Metadata
├── config.json        # Reporter configuration
├── allowlist.txt      # (Optional) IP/CIDR allowlist
├── snapshots/         # Input snapshot files
│   └── *.jsonl        # One snapshot per file
└── expected/          # Expected outputs (golden files)
    ├── rules.json     # Enforcement rules
    ├── report.md      # IBSR report
    └── evidence.csv   # Per-source decision evidence
```

### scenario.json

```json
{
  "name": "fixture_name",
  "description": "Human-readable description",
  "generated_at": 1000
}
```

The `generated_at` timestamp is used as the clock time when generating outputs.
This ensures deterministic output regardless of when tests run.

### config.json

```json
{
  "dst_port": 8080,
  "window_sec": 10,
  "syn_rate_threshold": 100.0,
  "success_ratio_threshold": 0.1,
  "block_duration_sec": 300,
  "fp_safe_ratio": 0.5,
  "min_samples_for_fp": 1
}
```

### snapshots/*.jsonl

Each file contains a JSON snapshot in IBSR schema format:

```json
{"version":0,"ts_unix_sec":1000,"dst_port":8080,"buckets":[...]}
```

Files are named by timestamp (e.g., `1000.jsonl`).

## Available Fixtures

| Fixture | Description | Decision |
|---------|-------------|----------|
| `syn_churn_attacker` | Clear attacker with high SYN rate, low success ratio | BLOCK |
| `legitimate_client` | Normal client with low SYN rate, high success ratio | ALLOW |
| `allowlisted_attacker` | Attacker pattern but IP is allowlisted | ALLOW |
| `fp_unknown` | Insufficient data for FP bound calculation | BLOCK (not safe) |
| `boundary_conditions` | Tests exact threshold boundaries | Mixed |

## Running Conformance Tests

```bash
# Run all conformance tests
cargo test -p ibsr-conformance

# Run specific fixture
cargo test -p ibsr-conformance syn_churn_attacker
```

## Determinism Requirements

All outputs must be byte-for-byte reproducible. This requires:

1. **Timestamps**: Use `generated_at` from scenario.json, never wall-clock time
2. **Ordering**: All lists sorted deterministically (by key_type then key_value)
3. **Floating-point**: Fixed precision (2 decimals for rates, 4 for ratios)
4. **Line endings**: Always `\n` (LF), never `\r\n` (CRLF)
5. **Encoding**: UTF-8 throughout

## Adding New Fixtures

1. Create fixture directory:
   ```bash
   mkdir -p fixtures/my_fixture/{snapshots,expected}
   ```

2. Create `scenario.json` and `config.json`

3. Add snapshot files to `snapshots/`

4. Generate expected outputs:
   ```bash
   cargo test -p ibsr-conformance print_fixture_outputs -- --ignored --nocapture
   ```

5. Copy generated outputs to `expected/`

6. Add conformance test in `runner.rs`:
   ```rust
   #[test]
   fn test_conformance_my_fixture() {
       let result = run_fixture("my_fixture").expect("run fixture");
       assert!(result.passed, "Fixture my_fixture failed: {:?}", result.diffs);
   }
   ```

## Output Formats

### rules.json

XDP-safe enforcement rules with version, match criteria, triggers, and exceptions.

### report.md

IBSR report with 5 sections:
1. Scope & Configuration
2. Abuse Pattern Observed
3. Counterfactual Enforcement Impact
4. Candidate Enforcement Rules
5. Readiness Judgment

### evidence.csv

Per-source decision evidence:
```csv
source,syn_rate,success_ratio,decision,packets,bytes,syn
10.0.0.1,500.00,0.0100,block,5050,505000,5000
```
