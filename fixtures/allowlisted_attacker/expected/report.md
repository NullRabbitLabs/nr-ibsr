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
- **Allowlist**: 1 IPs, 0 CIDRs

## 2. Abuse Pattern Observed

No abuse pattern detected matching the trigger conditions.

## 3. Counterfactual Enforcement Impact

### Blocked Traffic (if rules were enforced)

- **Packets blocked**: 0.0%
- **Bytes blocked**: 0.0%
- **SYN blocked**: 0.0%

### False Positive Bound

- **FP bound**: UNKNOWN
- **Reason**: Insufficient data: 0 keys, need at least 1
- Enforcement decision should be made with caution.

### Uncertainty

- No traffic was observed during the analysis window.

## 4. Candidate Enforcement Rules

```json
{
  "version": 2,
  "generated_at": 1000,
  "match_criteria": {
    "proto": "tcp",
    "dst_ports": [
      8080
    ]
  },
  "triggers": [],
  "exceptions": [
    {
      "key_type": "src_ip",
      "key_value": "10.0.0.1"
    }
  ]
}
```

## 5. Readiness Judgment

**This abuse class IS NOT safe for autonomous enforcement.**

Gating reasons:

- False positive bound unknown: Insufficient data: 0 keys, need at least 1
- No abuse pattern detected
- No traffic observed

