# IBSR Sample Report

## 1. Scope & Configuration

- **Time window start**: 1767877804
- **Time window end**: 1767951184
- **Duration**: 73380 seconds
- **Destination ports**: 22, 80, 443, 8080, 8443, 9200
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

- Analysis based on 11556 total packets, 4985 total SYN.

## 4. Candidate Enforcement Rules

```json
{
  "version": 3,
  "generated_at": 1769175097,
  "match_criteria": {
    "proto": "tcp",
    "dst_ports": [
      22,
      80,
      443,
      8080,
      8443,
      9200
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

