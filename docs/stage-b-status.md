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

### Userspace orchestrator + CLI parser (TDD-COMPLETE)

Now landed:

- `ibsr-collector/src/cli.rs`: `Command::CollectPayload(CollectPayloadArgs)`
  variant with full CLI parser. Flags: `-p / --dst-port`,
  `--dst-ports`, `-i / --iface` (default `lo`), `--out-dir`,
  `--window-sec`, `--max-flows`, `--ringbuf-bytes`, `--max-files`,
  `--max-age`, `--duration-sec`, `-v`. 21 tests pin parsing +
  validation.
- `ibsr-collector/src/payload_collector.rs`:
  - `PayloadEventSource` trait + `MockPayloadEventSource` for tests.
  - `PayloadCollectorConfig` + `PayloadCollectorError` +
    `PayloadWindowResult` + `PayloadLoopResult`.
  - `build_payload_snapshot` — emits v6 with/without
    `resp_aggregates` based on window data.
  - `collect_payload_window` — single-window orchestrator with
    poll-then-deadline-check loop semantics.
  - `collect_payload_loop` — multi-window runner with the
    "IBSR runs without dying" contract: writer failures, source
    failures, decode failures all keep the loop going. Only shutdown
    terminates.
  - `args_to_config` / `args_to_server_ports` — wiring layer between
    validated CLI args and the orchestrator's runtime types.
  - 27 tests pin: empty/non-empty windows, paired RPC handling,
    malformed-event resilience, source-error resilience, shutdown
    short-circuit, writer-error propagation, multi-window
    aggregation, decode-error tallies, max-windows cap, end-to-end
    CLI-to-snapshot wiring.

### BPF loader + TC qdisc attach + ringbuf consumer (LANDED — integration-test-pending)

The kernel-attach Rust glue is now landed:

- `ibsr-bpf/src/tc_payload_loader.rs`:
  - Pure-function scaffolding (TDD-tested):
    - `build_port_filter_entries(ports) → Vec<(key, value)>`
    - `InterfaceResolver` trait + `NixInterfaceResolver` /
      `MockInterfaceResolver` impls
    - `PendingEvents` thread-safe queue
    - `QueueBackedEventSource` (production-shaped)
  - Production attacher (kernel-bound):
    - `LibbpfPayloadCollector::attach(iface, ports, resolver)`
    - Box::leak'd OpenObject for 'static skel lifetime (matches
      BpfMapReader pattern)
    - clsact qdisc creation via TcHookBuilder
    - TC ingress + egress filter attach
    - Port-filter map programming
    - RingBuffer consumer with callback pushing into `PendingEvents`
    - Drop order: ringbuf → hooks → qdisc → skel (graceful detach,
      no orphan state)

- `ibsr-collector/src/payload_collector.rs`:
  - `PayloadEventSource` impl for `LibbpfPayloadCollector`:
    pump → drain.
  - `PayloadEventSource` impl for `QueueBackedEventSource`: drain.
    (Both share the orchestrator's loop; the difference is whether a
    kernel pump runs before drain.)

- `ibsr-collector/src/commands/collect_payload.rs`:
  - `execute_collect_payload` (TDD-tested with mock attacher).
  - `TcPayloadAttacher` trait + `AttachError` variants.

- `ibsr-collector/src/main.rs`:
  - `LibbpfTcPayloadAttacher` — production attacher.
  - Wires `ibsr collect-payload` subcommand end-to-end.

Verified non-root: `ibsr collect-payload -p 8899 -i lo` loads the
BPF skeleton (libbpf reports the load attempt), fails cleanly with
EPERM, exits 1, prints "BPF program load failed: Operation not
permitted (os error 1)".

### Live integration tests (TO DO with root)

The 3 `#[ignore]`d tests in `ibsr-bpf::tc_payload_loader::tests`
document the operational verification scenarios:

1. `integration_attach_and_detach_on_lo`: bring up + tear down on
   loopback without leaving an orphan clsact qdisc
   (`tc qdisc show dev lo` clean before + after).
2. `integration_round_trip_one_event`: drive one HTTP request through
   localhost:8899, observe one payload event in the ringbuf.
3. `integration_orphan_qdisc_cleanup_on_drop`: kill the binary mid-run,
   verify Drop ran (qdisc removed).

To run these:
```
sudo cargo test -p ibsr-bpf --lib tc_payload_loader -- --ignored --nocapture
```

### Phase 1 close-gate validation (TO DO after live integration)

After the integration tests pass:

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

- `ibsr-bpf`: 111 tests (was 69 pre-Stage-B; +42; 6 marked
  `#[ignore]` for kernel integration).
- `ibsr-schema`: 46 tests (was 35 pre-Stage-B; +11).
- `ibsr-collector`: 257 tests (was 182 pre-Stage-B; +75).
- Workspace total: 506/506 passing.

All Stage-B-related changes are TDD-first: tests written before
implementation, and `cargo test` is run after every meaningful chunk.

### What runs without dying (operational robustness pinned by tests)

- Writer fails every iteration → loop continues; windows_failed
  accumulates; no panic.
  (`loop_continues_through_writer_failures`)
- Event source returns errors every poll → snapshot still emits;
  source_errors counts; no panic.
  (`loop_recovers_after_intermittent_source_errors`)
- Malformed event bytes → decode_errors increments; subsequent
  valid events still aggregate; no panic.
  (`malformed_event_increments_decode_errors_but_loop_continues`)
- Shutdown signal mid-window → events drained; final snapshot
  emitted; clean exit.
  (`shutdown_during_active_polling_emits_snapshot_before_exit`)
- 1000 unrelated events in one batch → events_filtered tallies; no
  pathological behavior.
  (`many_unrelated_events_in_one_batch_does_not_overflow`)
- HTTP/1.1 keep-alive / pipelined RPCs → multiple pairs aggregate
  correctly across the same flow.
  (`keep_alive_two_request_response_pairs`)
- Buffer overflow → direction state resets lossy; no panic.
  (`buffer_overflow_resets_direction`)
- Aggregator output matches `ResponseAggregates::from_pairs` exactly
  → bridge contract to the offline-extractor's semantics.
  (`aggregator_matches_offline_semantics`,
   `multiple_pairs_aggregate_per_offline_semantics`)

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
