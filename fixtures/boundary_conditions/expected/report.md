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
| 10.0.0.1 | 100.0/sec | 0.10 | 1100 | 1000 |

## 3. Counterfactual Enforcement Impact

### Blocked Traffic (if rules were enforced)

- **Packets blocked**: 28.8%
- **Bytes blocked**: 28.8%
- **SYN blocked**: 28.6%

### False Positive Bound

- **FP bound**: 0.0%
- No likely legitimate traffic would be blocked.

### Uncertainty

- Analysis based on 3814 total packets, 3499 total SYN.

## 4. Candidate Enforcement Rules

```json
{
  "version": 1,
  "generated_at": 1005,
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

**This abuse class IS safe for autonomous enforcement.**

All safety criteria have been met:
- Abuse pattern clearly detected
- False positive bound within acceptable limits
- Meaningful impact on malicious traffic

