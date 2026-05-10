# CF-Style Incident Recording — Design v1 (pre-registered)

This document pre-registers the load-bearing design choices for IBSR's
third operating mode: `record-incident`. Per the project's principle 1
("pre-register the design BEFORE implementation"), it lands before any
phase-1 code.

The mode mirrors Cloudflare's "under attack" pattern: baseline sampling
at low rates, escalating to higher rates on operator/customer/auto-
detector signal, **always shadow mode** (the no-drop / no-redirect /
no-modify guarantee from `docs/safety.md` continues to hold), with
explicit privacy + retention controls.

The plan that this design implements is `PLAN-CF-INCIDENT-RECORDING-2026-05-09.md`.

## Architecture summary

Three new pieces alongside the existing `collect` (StrictCounter) and
`collect-payload` (ShadowPayload):

1. `record-incident` subcommand — TC ingress + egress program that
   sampled-emits packet headers (snaplen 256) to a ringbuf; userspace
   consumer writes pcap files.
2. `config_map` — 4-entry BPF array map (key=u32 enum, value=u64) shared
   inside the record-incident process between the BPF program and the
   userspace trigger socket. Holds sample-rate, sampling-active flag,
   incident-tag-hash, trigger-timestamp.
3. Trigger socket — Unix socket at `/var/run/ibsr.sock` that accepts
   one-line JSON commands updating the config_map. Three callers, one
   protocol: external API gateway, inference auto-trigger, operator CLI.

Safety profile: re-uses `SafetyProfile::ShadowPayload` for the BPF
verifier — same primitive set (TC + ringbuf), same shadow-mode invariants
(`TC_ACT_OK` only, no `bpf_redirect*`, no packet modification).

## Pre-registered decisions

### 1. Sampling-rate semantics — **per-CPU decrement counter**

When the BPF program processes a packet on the matched ports, it
decrements a per-CPU `BPF_MAP_TYPE_PERCPU_ARRAY` counter. When the
counter reaches zero, the packet is sampled (header copied to ringbuf)
and the counter resets to the configured `sample_rate`.

Rejected alternatives:
- **`bpf_get_prandom_u32() % rate`**: provides uniform sampling but
  costs an extra helper call per packet, and the verifier-friendly
  per-CPU counter pattern is well-trodden in Cilium / Cloudflare's
  public BPF code.
- **Single contended counter**: uniform across CPUs but the atomic
  contention at line rate kills throughput on multi-queue NICs.

Trade-off accepted: per-CPU sampling is **non-uniform across CPUs**
when the workload is asymmetric across NIC queues. This is documented
behavior, not a bug. Operators who need provably uniform sampling
should pick a different design — record-incident's contract is
"approximately 1-in-N over the aggregate of all CPUs".

### 2. Per-CPU vs single counter — **per-CPU** (see #1)

Locked together with #1. The counter is per-CPU. Userspace reads it
only for status/diagnostics, never for correctness.

### 3. Pcap format — **classic pcap with microsecond resolution**

File format: pcap classic (magic number `0xa1b2c3d4`), link-layer
type `LINKTYPE_ETHERNET` (1), snaplen 256, timestamp resolution
microseconds.

Rejected: pcap nanosecond format (magic `0xa1b23c4d`). Reasons:
- Microsecond is the universal default; every analysis tool reads it
  without fuss.
- Nanosecond resolution buys nothing for incident-recording use cases
  (HTTP RPC analysis is dominated by network jitter, not sub-µs
  ordering).
- Matches `tcpdump`'s default output so `tcpdump -r` works out of
  the box.

Note: `collect-payload` does not produce pcap (it produces
`ResponseAggregates` snapshots), so there is no precedent to match.

### 4. Trigger-socket auth — **filesystem permissions, v1**

The Unix socket at `/var/run/ibsr.sock` is created with mode `0660`,
owner `root:ibsr-trigger` (group must exist on the deployment host).
Anyone in `ibsr-trigger` can send any command. This is a deliberate
v1 choice, not a deferral.

Rationale:
- The three intended callers (external API gateway, inference
  container, operator CLI) all run on the same host as IBSR.
  Filesystem permissions are the lowest-friction enforcement.
- mTLS or token-based auth adds rotation/revocation surface that
  isn't worth the complexity for v1.
- Operators who want stronger isolation can put the socket behind a
  systemd socket-activated proxy or run record-incident in a
  per-tenant container.

Future: a `--trigger-socket-mode` flag could opt into mTLS by passing
the socket through stunnel, but that is out of v1 scope.

### 5. Storage encryption at rest — **out of scope, runbook responsibility**

IBSR writes pcap files in plaintext to the configured `--out-dir`. If
the operator needs encryption-at-rest, that is achieved via:
- Filesystem-level encryption (LUKS, dm-crypt, ZFS native encryption).
- Or by archiving to an encrypted destination via the existing
  `ibsr-export` tool (S3 SSE, etc.).

Rationale: per-process file encryption in v1 would duplicate
filesystem-level mechanisms the OS already provides better. The
runbook calls this out explicitly so operators don't deploy
record-incident on an unencrypted volume by accident.

## Configuration map schema

Pinned at `/sys/fs/bpf/ibsr/record_incident_config` (creation managed
by the loader; lifetime tied to the process — pin removed on Drop).

```c
enum config_key {
    CFG_SAMPLE_RATE        = 0,  // u64; 0 = sampling disabled
    CFG_SAMPLING_ACTIVE    = 1,  // u64 bool; 0 = passthrough, 1 = sampling on
    CFG_INCIDENT_TAG_HASH  = 2,  // u64 fnv1a-64 hash of tag string
    CFG_TRIGGER_TIMESTAMP  = 3,  // u64 unix-seconds when current trigger fired
};
```

The BPF program reads `CFG_SAMPLE_RATE` and `CFG_SAMPLING_ACTIVE` on
each matched packet (one map lookup; cheap). The userspace trigger
socket writes all four atomically.

## Trigger-socket protocol

Newline-delimited JSON, one command per line.

```
{"action": "set-sample-rate", "rate": 1000}
{"action": "trigger", "tag": "incident-customer-2026-05-09-1430Z", "rate": 10, "duration_sec": 600}
{"action": "stop"}
{"action": "status"}
```

Replies are also one-line JSON:

```
{"ok": true}
{"ok": false, "error": "rate must be >= 1"}
{"ok": true, "status": {"sampling_active": 1, "rate": 10, "tag": "...", "trigger_ts": 1715260200}}
```

Fields:
- `set-sample-rate.rate`: u64, `>= 1`. `0` is rejected (use `stop`
  to disable). The minimum 1 maps to "every packet" — the highest
  fidelity mode.
- `trigger.tag`: ASCII identifier, `[a-zA-Z0-9_-]{1,64}`. Used as
  the directory name component for partitioned output (Phase 4) and
  hashed for kernel-side correlation.
- `trigger.duration_sec`: u64, optional. `null` means "until stop".
  When present, the userspace listener auto-issues a `stop` at
  `trigger_ts + duration_sec`.

## Pcap output layout

```
{out-dir}/
  {tag}-{trigger_ts}/
    packets.pcap        # main pcap stream
    status.jsonl        # heartbeat (mirrors collect-payload format)
```

Phase 1 ships with one output dir per process invocation (no tag
partitioning); Phase 4 enables per-trigger partitioning where each
`trigger` command rotates to a new dir.

## Safety carryover

The record-incident BPF program is verified under
`SafetyProfile::ShadowPayload`:
- Mode-invariant: no `TC_ACT_SHOT` / `TC_ACT_REDIRECT` / `TC_ACT_STOLEN`,
  no `bpf_redirect*`, no `bpf_skb_*` mutating helpers, no
  DEVMAP/XSKMAP/CPUMAP.
- Mode-specific (ShadowPayload-permitted): ringbuf reserve/submit are
  allowed; per-CPU array map is allowed (it's neither
  DEVMAP/XSKMAP/CPUMAP nor a forbidden helper output).

**Ringbuf pressure invariant**: identical to `tc_payload.bpf.c` —
if `bpf_ringbuf_reserve` fails, the event is silently dropped, the
packet is `TC_ACT_OK`'d. Sampling does not backpressure the network
stack.

## Performance budget (pre-registration target)

At `--sample-rate 1000` (the default baseline), the per-packet hot
path adds:
- 1 per-CPU array lookup + decrement.
- 1 cmp-and-branch.
- ~1-in-1000 rate of: 1 ringbuf reserve (256 bytes) + 1 256-byte
  `bpf_skb_load_bytes` + 1 ringbuf submit.

Target: < 1% throughput overhead vs. unattached at baseline rate on
a 1 Gbps `lo` interface. Phase 6 acceptance test measures the
degradation curve.

## Phase 1 close gate

Phase 1 closes when:

1. `sudo ibsr record-incident -i lo --out-dir /tmp/x --tag test
   --duration-sec 5 --sample-rate 1` completes without error.
2. The output directory contains a `packets.pcap` readable by
   `tcpdump -r packets.pcap` showing sampled packets from the
   capture window.
3. `cargo test` (workspace) passes — including unit tests for the
   pcap writer and the config_map schema.
4. `./build.sh` (release) produces an `ibsr` binary with the new
   subcommand visible in `--help`.

## Out-of-scope for v1 (explicit non-goals)

- Active blocking / mitigation — that is `nr-guard`'s scope.
- Live alerting / inference — the inference container consumes IBSR
  snapshots and emits verdicts; record-incident is the recording
  layer it consumes.
- Per-customer encryption — see decision #5.
- Customer-facing API gateway — the trigger socket is the IBSR
  contract; the gateway sits above it.

## Methodology contributions banked

- **MC-13**: shadow-mode-default + adaptive-sampling-on-trigger as a
  privacy-by-default detection architecture.
- **MC-14**: the trigger socket as a small surface that explicitly
  separates auto-detection / customer-API / operator-CLI, instead of
  conflating them as most "incident recording" systems do.

## Cross-repo

- Substrate paper: see
  `/home/simon/Code/nullrabbit/nr-substrate/docs/STRATEGIC-NEXT-2026-05-09.md` §2.
- Demo (after Phase 3): `nr-substrate/demo/sui-victim/entrypoint.sh`
  optionally starts record-incident as a third sidecar.
- Auto-trigger (after Phase 3): `nr-substrate/scripts/inference_loop.py`
  can call into the trigger socket when a verdict crosses threshold.
