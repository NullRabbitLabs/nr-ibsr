---
title: ShadowPayload mode — implementation status
nav_order: 7
---

# ShadowPayload mode — implementation status

This doc tracks the work breakdown for `ibsr collect-payload`
(ShadowPayload mode), the second operating mode introduced in
`docs/safety.md`. It exists for cross-conversation continuity and
should be deleted once the mode reaches feature-parity with `ibsr
collect`.

## Goal

Land the payload-aware traffic-intelligence path: TC ingress/egress
BPF programs that sample TCP payload to a ringbuf; userspace
TCP-stream reassembler that parses HTTP/JSON-RPC and pairs requests
with responses; per-window aggregator that emits
`ResponseAggregates` matching nr-substrate's offline
`nr_training/features/responses.py` semantics exactly. Used to
validate the Phase 1 close-gate criterion of the
`PRODUCTION-ARCHITECTURE-PLAN` (in nr-substrate) on a held-out
TLS-fronted lab bundle: production extractor produces numerically
identical feature values to the offline extractor for all 7
CIPHER_AGNOSTIC_V2 features.

## What's landed

### Framing

- `docs/safety.md`: rewritten for the hyperscaler/cloudflare model.
  Single load-bearing safety guarantee — no drops/redirects/modifies
  — with two operating modes (StrictCounter, ShadowPayload) that
  differ in observation capability underneath.

### Schema (`ibsr-schema`)

- `SCHEMA_VERSION` bumped to 6.
- `SUPPORTED_VERSIONS = [5, 6]` so existing v5 snapshots still
  round-trip.
- New `ResponseAggregates` struct with `count`, `resp_bytes_total`,
  `req_bytes_max`, `resp_bytes_max`, `amp_ratio_{mean,median,max}`.
  Field semantics match offline `responses.py` exactly.
- `ResponseAggregates::from_pairs(&[(req, resp)])` aggregator pinned
  by tests (offline rule: pairs with `request_bytes <= 0` excluded
  from ratios).
- `Snapshot::with_resp_aggregates()` builder for v6 emission;
  `resp_aggregates` field is `#[serde(skip_serializing_if = Option::is_none)]`
  so v6-without-aggregates is byte-shape-equivalent to v5.

### Safety verification (`ibsr-bpf::safety`)

- `SafetyProfile { StrictCounter, ShadowPayload }` enum.
- `analyze_source_with_profile` / `analyze_elf_with_profile` —
  per-mode-aware verifiers. Old `analyze_source` / `analyze_elf`
  preserved as thin StrictCounter wrappers (back-compat).
- Mode-invariant rules apply to both: no drops/redirects/modifies,
  no DEVMAP/XSKMAP/CPUMAP, no `bpf_xdp_adjust_*` /
  `bpf_skb_change_*` / `bpf_clone_redirect` / `bpf_skb_store_bytes`.
- Mode-specific (StrictCounter only): forbid `bpf_ringbuf_*`,
  `bpf_perf_event_output`, BPF_MAP_TYPE_RINGBUF,
  BPF_MAP_TYPE_PERF_EVENT_ARRAY; require BPF_MAP_TYPE_LRU_HASH.
- 16+ tests cover both profiles, mode-invariant, and mode-specific.

### TC payload BPF program (`ibsr-bpf/src/bpf/tc_payload.bpf.c`)

- Two TC programs (`tc_payload_ingress`, `tc_payload_egress`),
  attached at the configured interface (typically `lo` for post-term
  loopback vantage).
- Filters by configured server-port set.
- Samples up to `PAYLOAD_SAMPLE_BYTES` (1024) of TCP payload per
  packet to a ringbuf.
- Always returns `TC_ACT_OK` — no drops.
- Ringbuf reservation failure drops the *event*, never the packet.
- Pinned offset table in source comments; userspace decoder pins the
  same offsets via `tc_payload_event::tests::raw_payload_event_field_offsets_match_pinned_table`.
- Safety-verified: `analyze_source_with_profile(source, ShadowPayload)`
  passes; same source rejected under StrictCounter (pinned by test).
- Build wired in `ibsr-bpf/build.rs` — both BPF sources compile;
  skeleton generation produces `counter.skel.rs` + `tc_payload.skel.rs`.

### Userspace decoder + bridge (`ibsr-bpf::tc_payload_event`, `ibsr-collector::payload`)

- `RawPayloadEvent`: `#[repr(C)]` mirror of the BPF struct, exact
  layout match. `EXPECTED_RAW_EVENT_SIZE = 1064`.
- `decode_event(&[u8]) -> Result<DecodedEvent, DecodeError>`: safe
  bytes-to-struct decoder with length, sample-size, and direction
  validation.
- `PayloadEvent::from_decoded(&DecodedEvent, &server_ports)` bridge:
  translates network byte order, infers `Direction` from server-port
  set membership (dst_port in set → ToServer; src_port in set →
  FromServer), canonicalises FlowKey across both directions.

### Userspace handler (`ibsr-collector::payload`)

- `FlowKey` — directional canonicalisation.
- `FlowReassembler` — per-flow byte buffers + httparse-based head
  detection + Content-Length-based body-length accounting + HTTP/1.1
  keep-alive support.
- `RpcPair` — emitted when request + response complete on the same
  flow.
- `WindowAggregator` — accumulates pairs, emits `ResponseAggregates`
  on `take_window()`.
- `PayloadHandler` — top-level orchestrator with bounded flow table
  + LRU eviction.
- 17 tests (12 reassembler/aggregator + 5 bridge) cover the
  request/response pairing, message-split-across-events,
  HTTP/1.1 keep-alive, malformed input, buffer overflow, LRU
  eviction, end-to-end aggregator-vs-direct-from-pairs equivalence.

## What's remaining

### BPF loader + TC qdisc attach + ringbuf consumer

The kernel-attach Rust glue. Probably ~300-500 lines:

- `ibsr-bpf/src/tc_payload_loader.rs`:
  - `TcPayloadCollector::open(skel, iface, ports, max_flows)`
  - `clsact` qdisc creation on the configured interface
  - `bpf_tc_attach` for ingress + egress hooks
  - Port-filter map programming
  - Ringbuf consumer setup with a callback that decodes events,
    bridges to `PayloadEvent`, and feeds the `PayloadHandler`
- `ibsr-collector/src/commands/collect_payload.rs`:
  - Subcommand handler — parse args, validate, instantiate
    `TcPayloadCollector`, run window-snapshot loop, write v6
    snapshots with `resp_aggregates`.
- `ibsr-collector/src/cli.rs`:
  - Add `Command::CollectPayload(CollectPayloadArgs)` variant.

The libbpf-rs API surface is well-defined (`TcHookBuilder`,
`RingBufferBuilder`, `MapHandle::update`); the work is mechanical
but kernel-side, so unit tests cover only the orchestration; on-box
integration test confirms end-to-end behaviour.

### Phase 1 close-gate validation

Once `ibsr collect-payload` is operational:

1. Run a Sui F10 saturating reproducer with TLS-fronting against
   the local validator.
2. Concurrently run `ibsr collect-payload --iface lo
   --dst-port <validator_port>` to capture the bundle's traffic at
   the post-term loopback vantage.
3. Run `phase1_cross_validate.py` (in nr-substrate) comparing the
   IBSR-extracted feature dict against the offline `nr_training`
   extractor's reading of the bundle's `responses.parquet`.
4. Expected: 7/7 PASS within `PHASE_1_TOLERANCE` (cardinality +
   max-byte exact, amp_ratio ±1e-4 absolute).
5. `/methodology-review` at Stage B close-out — Phase 1 close-gate
   clears empirically on the live system.

## Test coverage so far

- `ibsr-bpf`: 97 tests (was 69 pre-Stage-B).
- `ibsr-schema`: 46 tests (was 35 pre-Stage-B).
- `ibsr-collector`: 199 tests (was 182 pre-Stage-B).
- Workspace total: 434/434 passing.

## Honest framing

ShadowPayload mode is a real safety-posture relaxation relative to
the original IBSR contract: under the new mode, payload bytes are
observable in userspace, where the original mode kept them inside
the kernel. The `docs/safety.md` rewrite makes this explicit and
points operators at the trade-off. The load-bearing no-drop /
no-redirect / no-modify guarantee is preserved mechanically across
both modes, but the privacy posture differs and operators are
responsible for whatever data-handling discipline their context
requires.
