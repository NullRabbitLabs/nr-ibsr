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

No abuse pattern detected matching the trigger conditions.

## 3. Counterfactual Enforcement Impact

### Blocked Traffic (if rules were enforced)

- **Packets blocked**: 0.0%
- **Bytes blocked**: 0.0%
- **SYN blocked**: 0.0%

### False Positive Bound

- **FP bound**: 0.0%
- No likely legitimate traffic would be blocked.

### Uncertainty

- Analysis based on 200 total packets, 100 total SYN.

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
  "triggers": [],
  "exceptions": []
}
```

## 5. Readiness Judgment

**This abuse class IS NOT safe for autonomous enforcement.**

Gating reasons:

- No abuse pattern detected

