# IBSR Report

## 1. Scope & Configuration

- **Time window start**: 1000
- **Time window end**: 1000
- **Duration**: 0 seconds
- **Destination ports**: 8080
- **Window size**: 10 seconds
- **SYN rate threshold**: 100.0 SYN/sec
- **Success ratio threshold**: 0.10
- **Block duration**: 300 seconds
- **Allowlist**: None configured

## 2. Abuse Pattern Observed

Detected 1 source(s) matching abuse pattern (TCP SYN churn).

### Top Offenders

| Source | SYN Rate | Success Ratio | Would Block Packets | Would Block SYN |
|--------|----------|---------------|---------------------|------------------|
| 10.0.0.1:8080 | 500.0/sec | 0.00 | 5050 | 5000 |

## 3. Counterfactual Enforcement Impact

### Blocked Traffic (if rules were enforced)

- **Packets blocked**: 100.0%
- **Bytes blocked**: 100.0%
- **SYN blocked**: 100.0%

### False Positive Bound

- **FP bound**: UNKNOWN
- **Reason**: Insufficient data: 1 keys, need at least 10
- Enforcement decision should be made with caution.

### Uncertainty

- Analysis based on 5050 total packets, 5000 total SYN.

## 4. Candidate Enforcement Rules

```json
{
  "version": 1,
  "generated_at": 1000,
  "match_criteria": {
    "proto": "tcp",
    "dst_ports": [
      8080
    ]
  },
  "triggers": [
    {
      "key_type": "src_ip",
      "key_value": "10.0.0.1",
      "window_sec": 10,
      "syn_rate_threshold": 100.0,
      "success_ratio_threshold": 0.1,
      "action": {
        "action_type": "drop",
        "duration_sec": 300
      }
    }
  ],
  "exceptions": []
}
```

## 5. Readiness Judgment

**This abuse class IS NOT safe for autonomous enforcement.**

Gating reasons:

- False positive bound unknown: Insufficient data: 1 keys, need at least 10

