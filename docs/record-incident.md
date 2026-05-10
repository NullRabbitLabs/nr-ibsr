---
title: Record-Incident Mode
nav_order: 8
---

# Record-Incident Mode — CF-Style Sampled Packet Capture

`ibsr record-incident` is the third operating mode, alongside `collect`
(StrictCounter) and `collect-payload` (ShadowPayload). It records
sampled raw packets to pcap files for forensic analysis, with an
optional Unix socket to flip sampling rate, start/stop, and partition
output by tag at runtime.

The pattern mirrors Cloudflare's "under attack" architecture: low
baseline sampling rate (1-in-1000 by default), escalation on signal,
**always shadow-mode** (no traffic dropped, redirected, or modified),
with explicit privacy + retention controls.

For the design rationale and the five pre-registered decisions, see
[CF-INCIDENT-RECORDING-DESIGN-V1.md](CF-INCIDENT-RECORDING-DESIGN-V1.html).
For the safety story shared across all three modes, see
[Safety](safety.html).

## What you get

| Capability | Flag(s) |
| --- | --- |
| Sampled pcap capture | `--sample-rate` |
| Per-incident output partitioning | `--tag`, `--trigger-socket` |
| Runtime triggers (rate / start / stop / status) | `--trigger-socket` |
| Privacy: per-customer IP hashing | `--scrub-ip-salt` |
| Privacy: drop traffic between internal hosts | `--scrub-internal-subnet` |
| Hot-tier disk cap with auto-rotation | `--max-pcap-bytes` |
| Warm-tier gzip archive | `--archive-dir`, `--archive-after-sec` |

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│ ibsr record-incident                                               │
│                                                                    │
│  ┌─────────────────────┐         ┌──────────────────────────────┐  │
│  │ TC ingress + egress │         │  config_map                  │  │
│  │ BPF program         │ reads → │   CFG_SAMPLE_RATE            │  │
│  │                     │         │   CFG_SAMPLING_ACTIVE        │  │
│  │ per-CPU counter     │         │   CFG_INCIDENT_TAG_HASH      │  │
│  │ snaplen-256 ringbuf │         │   CFG_TRIGGER_TIMESTAMP      │  │
│  └──────────┬──────────┘         └────────────▲─────────────────┘  │
│             │ events                          │                    │
│             ▼                                 │ writes             │
│  ┌──────────────────────┐  ┌──────────────────┴───────────────┐    │
│  │ orchestrator loop    │  │ trigger socket                   │    │
│  │  - decode            │←─│   /var/run/ibsr.sock (mode 0660) │    │
│  │  - scrub             │  │   newline-delimited JSON         │    │
│  │  - write to sink     │  └──────────────────────────────────┘    │
│  │  - archive sweep     │                                          │
│  └──────────┬───────────┘                                          │
│             ▼                                                      │
│   {out-dir}/{tag-ts}/packets.pcap          status.jsonl            │
└────────────────────────────────────────────────────────────────────┘
```

## Quick start

### Static-rate capture

```bash
sudo ibsr record-incident \
  -i lo \
  --tag smoke-test \
  --duration-sec 5 \
  --sample-rate 1 \
  -o /tmp/ibsr-smoke
```

This captures every packet on `lo` for 5 seconds into
`/tmp/ibsr-smoke/smoke-test-<unix-ts>/packets.pcap`. Verify with
`tcpdump`:

```bash
tcpdump -r /tmp/ibsr-smoke/smoke-test-*/packets.pcap | head
```

### Baseline + on-demand triggers

```bash
sudo ibsr record-incident \
  -i lo \
  --sample-rate 1000 \
  --trigger-socket /var/run/ibsr.sock
```

This runs at the 1-in-1000 baseline rate. The trigger socket lets an
operator (or an auto-detector, or a customer-facing API gateway)
escalate to full capture on signal — see the next section.

## Trigger-socket protocol

When `--trigger-socket <path>` is set, `ibsr record-incident` opens a
Unix socket at that path with mode `0660`. Everything in the
`ibsr-trigger` group (or whatever group owns the socket file) can
send commands.

The protocol is one JSON command per connection, newline-terminated.
The server replies with one JSON line.

### `set-sample-rate`

Update the sampling rate without changing whether sampling is active.

```bash
echo '{"action":"set-sample-rate","rate":10}' | nc -U /var/run/ibsr.sock
# {"ok":true}
```

### `trigger`

The atomic escalation. Sets active=1, updates rate + tag-hash +
trigger timestamp. With `--trigger-socket` enabled, this also rotates
the pcap file to a new `{tag}-{trigger-ts}` subdirectory so each
incident lands in its own folder.

```bash
echo '{"action":"trigger","tag":"incident-2026-05-09-customer-X","rate":1,"duration_sec":600}' \
  | nc -U /var/run/ibsr.sock
# {"ok":true}
```

The optional `duration_sec` field auto-stops sampling at
`trigger_ts + duration_sec`.

Tag rules (enforced both at CLI and at trigger time):
- 1..=64 chars, `[a-zA-Z0-9_-]` only.
- No `/`, `.`, spaces, or non-ASCII — these would let a malicious
  trigger sneak path components into the partitioned output dir.

### `stop`

Disable sampling. The kernel-side counter keeps state but the
sampling-active flag flips to 0; subsequent `trigger` commands
resume from the new state.

```bash
echo '{"action":"stop"}' | nc -U /var/run/ibsr.sock
# {"ok":true}
```

### `status`

Read-only. Returns current state.

```bash
echo '{"action":"status"}' | nc -U /var/run/ibsr.sock
# {"ok":true,"status":{"sampling_active":1,"rate":10,"tag":"incident-...","trigger_ts":1715260200,"deadline_ts":1715260800}}
```

### Error replies

```bash
echo '{"action":"set-sample-rate","rate":0}' | nc -U /var/run/ibsr.sock
# {"ok":false,"error":"rate must be >= 1"}
```

Authentication: filesystem permissions only. See
[design decision #4](CF-INCIDENT-RECORDING-DESIGN-V1.html) for the
rationale and the future migration path to mTLS.

## Privacy / scrubbing

### Per-customer IP hashing

```bash
sudo ibsr record-incident \
  --scrub-ip-salt DEADBEEFCAFEBABE \
  ...
```

Every captured packet's IPv4 src + dst addresses are replaced with
`FNV-1a-64(salt || ip)` before the pcap write. Same input always
produces the same output (so flow analysis still works on hashed
addresses), but different salts produce uncorrelated hashed outputs
across customers / runs.

Caveats (also documented in `scrub.rs`):
- IPv4 only. IPv6 packets pass through unscrubbed.
- IP / TCP / UDP checksums are **not** recomputed. `tcpdump` and
  Wireshark will flag "checksum incorrect" but parse the packet
  fine. Automated parsers should be aware.
- The hash is **not cryptographic**. Sufficient for "different
  customer / different salt → uncorrelatable IPs"; not sufficient
  for adversarial reversal if the salt leaks.

### Internal-subnet drop

```bash
sudo ibsr record-incident \
  --scrub-internal-subnet 10.0.0.0/8 \
  ...
```

Packets where **both** src and dst lie within the configured CIDR
are dropped from the pcap output entirely. Use this to keep
service-mesh traffic between operator-controlled hosts out of the
recording.

The subnet check runs **before** hashing — pinned in
`scrub_subnet_check_runs_before_hashing`. If hashing came first,
the hashed IPs would land outside the subnet and we'd never drop
real internal traffic.

## Retention

### Hot-tier byte cap

```bash
sudo ibsr record-incident \
  --max-pcap-bytes $((10 * 1024 * 1024)) \
  ...
```

When the current pcap exceeds 10 MiB, the sink rotates to a new
file in the same out-dir with a freshly-stamped tag-ts directory.
This bounds the hot-tier footprint without depending on the
trigger socket.

### Warm-tier gzip archive

```bash
sudo ibsr record-incident \
  --archive-dir /srv/ibsr-archive \
  --archive-after-sec 3600 \
  ...
```

The orchestrator runs an archive sweep every 30 seconds. Pcap
files in `--out-dir` whose mtime is older than `--archive-after-sec`
are gzipped into `--archive-dir` (preserving the
`{tag-ts}/packets.pcap.gz` relative layout) and the originals are
removed.

Cold-tier (deletion / S3 upload / DR) is **out of scope** — the
operator's responsibility via cron / `ibsr-export` / S3 lifecycle
rules.

## Output layout

```
{out-dir}/
├── {tag}-{run-ts}/
│   ├── packets.pcap        # the capture (or first segment, if rotated)
│   └── status.jsonl        # heartbeat (one JSON line per status interval)
├── {tag}-{trigger1-ts}/    # phase-4 partition (one per `trigger` command)
│   └── packets.pcap
└── {tag}-{trigger2-ts}/
    └── packets.pcap
```

When the warm-tier sweeper runs, files migrate to:

```
{archive-dir}/
├── {tag}-{run-ts}/
│   └── packets.pcap.gz
└── ...
```

`status.jsonl` shape:

```json
{"timestamp":1715260200,"cycle":1,"events_written":42,"events_decode_errors":0,"events_write_errors":0,"events_scrubbed":0,"rotations":0,"size_driven_rotations":0,"poll_errors":0,"archived":0,"archive_errors":0}
```

## CLI reference

```text
ibsr record-incident [OPTIONS]

OPTIONS:
  -i, --iface <IFACE>
          Network interface for TC attach. Defaults to `lo`. [default: lo]
  -o, --out-dir <OUT_DIR>
          Output directory for pcap files. [default: /var/lib/ibsr/incidents]
      --tag <TAG>
          Incident tag. 1..=64 chars, [a-zA-Z0-9_-] only. [default: ad-hoc]
      --sample-rate <SAMPLE_RATE>
          1-in-N sampling rate. 1 = every packet. [default: 1000]
      --duration-sec <DURATION_SEC>
          Optional run length. Omit for SIGINT-bound execution.
      --trigger-socket <PATH>
          Enable runtime control socket. Mode 0660.
      --scrub-ip-salt <HEX64>
          Per-customer salt for IPv4 hashing (16 hex chars).
      --scrub-internal-subnet <CIDR>
          Drop packets where both endpoints lie in this CIDR.
      --max-pcap-bytes <BYTES>
          Hot-tier per-pcap byte cap. Triggers auto-rotation.
      --archive-dir <DIR>
          Warm-tier destination. Older pcaps gzipped into here.
      --archive-after-sec <SECS>
          Age threshold for warm-tier promotion. [default: 3600]
      --status-interval-sec <SECS>
          Heartbeat interval for status.jsonl. [default: 60]
  -v, --verbose...
          Increase verbosity (-v info, -vv debug).
```

## Operational notes

### Permissions

The trigger socket is created mode `0660` (owner + group RW). To let
non-root callers connect, put their user into the socket's owning
group. Production systemd unit example:

```ini
[Service]
ExecStart=/usr/local/bin/ibsr record-incident \
    --trigger-socket /var/run/ibsr.sock \
    --sample-rate 1000
User=root
Group=ibsr-trigger
UMask=0007
```

Then add the API gateway / inference container's user to
`ibsr-trigger`.

### Coexistence with `collect` / `collect-payload`

All three modes share the BPF infrastructure (clsact qdisc, port-
filter map). They can run simultaneously on the same interface
without conflict, with **distinct** default output directories so
they don't clobber each other:

| Mode | Default `--out-dir` |
| --- | --- |
| `collect` | `/var/lib/ibsr/snapshots` |
| `collect-payload` | `/var/lib/ibsr/snapshots-payload` |
| `record-incident` | `/var/lib/ibsr/incidents` |

### Performance budget

At `--sample-rate 1000` (the baseline), the BPF hot path adds:
- 1 per-CPU array lookup + decrement.
- 1 cmp-and-branch.
- ~1-in-1000 rate of: 1 ringbuf reserve + 1 256-byte
  `bpf_skb_load_bytes` + 1 ringbuf submit.

Target: < 1% throughput overhead vs. unattached at baseline rate on
a 1 Gbps interface. Higher rates trade throughput for fidelity
linearly.

### Encryption at rest

`ibsr record-incident` writes pcap files in plaintext. For
encryption-at-rest, use filesystem-level encryption (LUKS, dm-crypt,
ZFS native) on the volume backing `--out-dir` and `--archive-dir`,
or pipe the warm tier to an SSE-enabled S3 bucket via `ibsr-export`.

This is a deliberate v1 choice — see
[design decision #5](CF-INCIDENT-RECORDING-DESIGN-V1.html).

## Troubleshooting

### Empty `packets.pcap` (24 bytes)

The pcap contains only the global header. Causes:
- The interface saw no traffic during the capture window.
- Sample-rate too high for traffic volume (e.g. `--sample-rate 1000`
  and only ~50 packets passed).
- Filtering by `--scrub-internal-subnet` dropped everything (check
  `events_scrubbed` in `status.jsonl`).

### `attach failed: clsact qdisc setup failed`

Another tool already attached a clsact qdisc on the interface. Check
with `tc qdisc show dev <iface>`. Detach the conflict or use a
separate interface.

### Stuck socket file after a crash

`/var/run/ibsr.sock` lingers from a crashed run. The next
`ibsr record-incident --trigger-socket /var/run/ibsr.sock` removes
it before binding (best-effort cleanup), so this is usually self-
healing. If it isn't, `rm /var/run/ibsr.sock` manually.

### `tcpdump: bad dump file format`

You're reading a `.pcap.gz` from the warm tier without decompressing
first. Run `gunzip` or use `zcat`:

```bash
zcat /srv/ibsr-archive/incident-X-1715260200/packets.pcap.gz | tcpdump -r -
```

### "checksum incorrect" warnings under `--scrub-ip-salt`

Expected — scrubbing rewrites the IP src/dst without recomputing the
IP / TCP / UDP checksums. The packets parse fine; only the checksum
verification flags. Documented limitation, see `scrub.rs` header.

## See also

- [CF-INCIDENT-RECORDING-DESIGN-V1.md](CF-INCIDENT-RECORDING-DESIGN-V1.html)
  — pre-registered design choices.
- [Safety](safety.html) — the shadow-mode invariants that all three
  modes preserve.
- [How It Works](how-it-works.html) — IBSR architecture overview.
