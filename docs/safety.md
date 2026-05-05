---
title: Safety
nav_order: 6
---

# Safety Model

IBSR is designed to be safe for deployment on production systems, including high-throughput validators and edge infrastructure. We've tested on a 1Gbps pipe. We've simulated on a 10Gbps one but haven't had the chance to actually run this because of the cost. If you have one we can use, that would be swell.

IBSR follows the **hyperscaler / cloudflare-shaped operator-edge model**: passive observation at the network boundary, distributed across the operator's infrastructure, with a single load-bearing safety guarantee — **shadow mode means no traffic is dropped**. The mechanism by which observation happens (counter aggregation, payload sampling, application-layer parsing) is a deployment choice; the no-drop guarantee is invariant.

## The single hard guarantee — shadow mode

| Guarantee | How It's Enforced |
|-----------|-------------------|
| **Cannot drop packets** | BPF programs only return XDP_PASS (XDP) or TC_ACT_OK / TC_ACT_UNSPEC (TC); no drop / abort / shot code paths |
| **Cannot redirect traffic** | No XDP_REDIRECT, no bpf_redirect, no devmap / xskmap-based steering |
| **Cannot modify packets** | No packet data writes; read-only header + payload inspection |

Everything else — whether IBSR keeps counters in a kernel hash map, samples payloads to userspace via a ring buffer, parses HTTP/JSON-RPC at the application layer, or writes structured records to disk — is a per-mode operational choice that does not affect the load-bearing safety story. The hyperscalers and CDN operators that inspired this model (Cloudflare's edge, AWS Shield, Google's DoS-protection layer) all observe payloads at line rate without dropping; "no drops" is the invariant, payload-inspection is a routine capability.

## Two operating modes

IBSR exposes two safety profiles. Operators choose at deployment time per the threat model and the data-handling posture of their environment.

### StrictCounter mode (default — `ibsr collect`)

The original, conservative profile. Provides traffic-counter telemetry without per-packet event emission or payload reads.

- **BPF programs**: XDP only.
- **Permitted helpers**: bpf_map_lookup_elem, bpf_map_update_elem, bpf_ktime_get_ns, header-boundary checks.
- **Forbidden helpers**: bpf_ringbuf_*, bpf_perf_event_output, bpf_redirect*, bpf_xdp_adjust_*, bpf_clone_redirect.
- **Forbidden map types**: BPF_MAP_TYPE_RINGBUF, BPF_MAP_TYPE_PERF_EVENT_ARRAY, BPF_MAP_TYPE_DEVMAP*, BPF_MAP_TYPE_XSKMAP, BPF_MAP_TYPE_CPUMAP.
- **Required map type**: BPF_MAP_TYPE_LRU_HASH (bounded memory).
- **Per-packet output**: counter increments only — no kernel→userspace event stream.
- **Privacy posture**: payload bytes never leave the kernel.

This is the right profile for environments where payload-touching is a compliance / data-handling concern even at observation level — multi-tenant operator infrastructure, regulated payment paths, environments where the operator deliberately wants payload-blindness as a contractual property.

### ShadowPayload mode (opt-in — `ibsr collect-payload`)

The hyperscaler-style profile. Permits payload-aware traffic intelligence — application-layer parsing, request:response correlation, structured record emission — while preserving the no-drop / no-redirect / no-modify shadow-mode guarantee.

- **BPF programs**: XDP for steering + TC ingress/egress for payload reassembly. Both program types are constrained to PASS / OK return paths.
- **Permitted helpers**: counter-mode helpers + bpf_ringbuf_reserve / bpf_ringbuf_submit / bpf_ringbuf_output, bpf_skb_load_bytes, bpf_perf_event_output (for opt-in lossy emission).
- **Permitted map types**: counter-mode types + BPF_MAP_TYPE_RINGBUF, BPF_MAP_TYPE_PERF_EVENT_ARRAY.
- **Forbidden everywhere**: drops, redirects, packet modifications. The no-drop guarantee is mode-invariant.
- **Per-packet output**: opt-in. Userspace consumes ring-buffer events to reassemble TCP streams + parse HTTP / JSON-RPC / similar protocols. Sampling discipline is operator-configurable.
- **Privacy posture**: payload bytes are observable in userspace. Operators are responsible for whatever data-handling posture their deployment context requires (e.g. on-box-only, never-network-egressed, time-bounded retention).

This is the right profile for traffic-intelligence use cases where the operator controls the boundary the traffic crosses (own-validator infrastructure, own-edge proxy, own-API gateway) and wants application-layer signal — RPC amplification detection, anomalous-payload classification, request:response pairing analysis. It is **not** the right profile for environments where payload-blindness is a compliance property; use StrictCounter mode there.

## Choosing a mode

| If you want... | Use |
|---|---|
| Traffic counters + bounded memory + payload-blind operator-edge telemetry | StrictCounter |
| RPC-shape intelligence (request:response sizes, amplification ratios, JSON-RPC method distribution) | ShadowPayload |
| DDoS detection at packet-rate granularity | StrictCounter (counters carry the signal at this layer) |
| Application-layer attack classification (response-amplification primitives, anomaly detection) | ShadowPayload |
| To deploy on infrastructure you do not own | Reconsider — neither mode is a substitute for the operator's own consent |

## Safety Verification

Both modes share the load-bearing safety story (no drops / redirects / modifies); each mode has additional invariants that are mode-specific. Verification runs at build time and is mode-aware.

### Source-Level Analysis

Before compilation, BPF C source is parsed. Mode-invariant checks (run for both modes):

- Any `return XDP_DROP` / `XDP_ABORTED` / `XDP_REDIRECT` / `XDP_TX` statement.
- Any `return TC_ACT_SHOT` / `TC_ACT_REDIRECT` / `TC_ACT_STOLEN` statement.
- Use of redirect / mod helpers (`bpf_redirect*`, `bpf_xdp_adjust_*`, `bpf_clone_redirect`, `bpf_skb_change_*`).
- Use of redirect map types (DEVMAP, XSKMAP, CPUMAP).

Mode-specific checks:

- StrictCounter only: forbid `bpf_ringbuf_*`, `bpf_perf_event_output`, BPF_MAP_TYPE_RINGBUF, BPF_MAP_TYPE_PERF_EVENT_ARRAY. Require BPF_MAP_TYPE_LRU_HASH for bounded memory.
- ShadowPayload: ringbuf and perf_event are permitted; bounded-memory discipline shifts to userspace ring-buffer-consumer + sampling configuration.

### ELF Inspection

After compilation, the compiled BPF object file is scanned for the same forbidden symbols (mode-aware) plus relocation entries pointing to dangerous helpers.

### Continuous Testing

Both analyses run automatically:

- On every build via `docker compose run --rm test`.
- In CI pipeline (if configured).
- Before release builds.

If any mode-invariant or mode-specific safety check fails, the build fails.

## Performance Characteristics

### StrictCounter mode

| Aspect | Characteristic |
|--------|----------------|
| Per-packet overhead | ~50–100 nanoseconds |
| CPU usage (userspace) | < 1% on most systems |
| Memory (userspace) | ~10–20 MB |
| Memory (BPF map) | Configurable via `--map-size` |
| Packet loss | None (XDP_PASS always) |
| Latency impact | Unmeasurable (nanosecond scale) |

Per-packet operations: header boundary checks, protocol matching, port lookup, BPF map lookup/update, return XDP_PASS. No loops, no dynamic allocation, no blocking.

### ShadowPayload mode

| Aspect | Characteristic |
|--------|----------------|
| Per-packet overhead (XDP) | ~50–100 ns (steering + counter, same as StrictCounter) |
| Per-packet overhead (TC handling) | ~200–500 ns (payload-bytes load + ringbuf reserve+submit) |
| Userspace overhead | proportional to sampled payload volume + parser cost (httparse, JSON-RPC) |
| Ring-buffer pressure | sized at deployment time; events drop on pressure (lossy by design — IBSR's outcome is intelligence, not perfect capture) |
| Packet loss | None — pressure on the ring buffer never backpressures the network stack |
| Latency impact | Unmeasurable on the network path (network stack continues regardless of ring-buffer state) |

The cardinal rule: **ring-buffer pressure NEVER affects packet flow.** If userspace falls behind, ring-buffer events drop. The network path is unaffected. This is the load-bearing distinction from in-line packet inspectors (which can backpressure), and it preserves the no-drop guarantee mechanically.

## Memory Bounds

### StrictCounter

The BPF LRU hash map is bounded by `--map-size`:

```
Memory = map_size * entry_size
       ~ map_size * 64 bytes

Default: 100,000 * 64 = 6.4 MB
Maximum: 1,000,000 * 64 = 64 MB (practical limit)
```

When the map is full, the kernel automatically evicts the least-recently-updated entries.

### ShadowPayload

Counter map sized as in StrictCounter. Ring-buffer is sized at deployment (typical: 4 MiB – 16 MiB). Userspace TCP-flow reassembly maintains a bounded flow table (LRU-evicted on capacity); sampling discipline (per-flow rate cap, payload-bytes-per-flow cap) is configurable. Userspace memory bounds are an operator-tuned property of the deployment.

## Failure Modes

IBSR is fail-open by design in both modes.

### Program Load Failure

If the BPF program fails to load (verifier rejection, missing capabilities):

- Error message printed.
- Process exits with non-zero code.
- Traffic is unaffected (no BPF program attached).

### Collector Crash

If the userspace collector crashes:

- Kernel automatically detaches the BPF program(s).
- Traffic continues to flow normally.
- Systemd restarts the service (if configured).
- ShadowPayload mode: in-flight ring-buffer events are lost; no impact on the network path.

### Disk Failure

If snapshot writes fail (disk full, permissions):

- Error logged.
- Collection continues.
- Traffic unaffected.
- Alerts should trigger from missing status updates.

### Map / Ring-Buffer Overflow

StrictCounter — if more unique IPs are seen than `--map-size`:

- LRU eviction removes oldest entries.
- Some counters may be lost.
- Traffic unaffected.

ShadowPayload — if the ring buffer fills faster than userspace consumes:

- New events drop (lossy by design).
- Traffic unaffected (ring-buffer pressure cannot backpressure XDP / TC).
- Sampling intelligence remains representative if drops are uniform.

## Risk Comparison

| Tool | Risk Profile |
|------|--------------|
| tcpdump | Packet capture, disk writes, in-userspace, can backpressure if disk is slow |
| bpftrace | Arbitrary BPF programs |
| Cloudflare-edge / hyperscaler edge inspectors | Payload-aware observation, no drops, distributed |
| **IBSR StrictCounter** | Counter-only, no payload, no per-packet events |
| **IBSR ShadowPayload** | Payload-aware, lossy ring-buffer to userspace, no drops |

ShadowPayload mode's risk profile is **comparable to a hyperscaler-edge observer** — it sees payload at line rate, never drops or redirects, and the load-bearing failure mode (userspace can't keep up) is mechanically prevented from affecting the network path. StrictCounter mode's risk profile is **strictly lower than tcpdump's** because no payload bytes leave the kernel and the failure mode is bounded by LRU map size.

## What IBSR Cannot Do

Mode-invariant — cannot do in either mode:

| Capability | Why Excluded |
|------------|--------------|
| Block traffic | Shadow-mode invariant; enforcement is a separate concern |
| Modify traffic | Shadow-mode invariant; the operator's protection layer (WAF / firewall / rate-limiter) is the enforcement surface |
| Real-time alerting | Offline analysis avoids false urgency; alerting is a higher-layer responsibility |
| Threat intelligence (external feeds) | Not in scope; bias-introducing |
| Autonomous action | Human review required |

Mode-specific — StrictCounter cannot:

| Capability | Why Excluded (in StrictCounter) |
|------------|--------------|
| Capture payload | Privacy posture of this mode (use ShadowPayload if payload-aware intelligence is the goal) |
| Per-packet events | Privacy posture of this mode (use ShadowPayload if request-level events are the goal) |

## Operational Risk

### Adding IBSR

When deploying IBSR (either mode):

- Traffic continues to flow normally.
- No configuration changes to applications.
- No firewall rule changes.
- Reversible by stopping the service.

### Removing IBSR

When removing IBSR:

- Stop the service.
- BPF programs detach automatically.
- Traffic continues normally.
- Optional: delete data files.

### Worst Case

Even in the worst failure scenario:

- Traffic continues flowing (fail-open).
- System returns to baseline automatically.
- No persistent state changes.
- No data corruption.

## Verification Commands

### Check BPF Attachment

```bash
# List XDP programs on interface
ip link show eth0 | grep xdp

# List TC programs (ShadowPayload mode)
tc filter show dev eth0 ingress
tc filter show dev eth0 egress

# Detailed BPF program info
sudo bpftool prog list
```

### Check Safety Invariants

```bash
# Run test suite (includes mode-aware safety analysis)
docker compose run --rm test

# Check for forbidden patterns in source (mode-invariant)
grep -r "XDP_DROP\|XDP_ABORTED\|XDP_REDIRECT\|TC_ACT_SHOT\|TC_ACT_STOLEN" ibsr-bpf/src/
# Should return nothing
```

### Monitor Resource Usage

```bash
# BPF map size
sudo bpftool map list

# Process memory
ps aux | grep ibsr

# Disk usage
du -sh /var/lib/ibsr/snapshots/

# ShadowPayload mode: ring-buffer pressure / drop rate
sudo bpftool map dump name ibsr_payload_rb 2>/dev/null | head
```

## Next Steps

- [How It Works](how-it-works.md) — Technical architecture
- [Reporting](reporting.md) — Offline reporting workflow
- [FAQ](faq.md) — Common questions
