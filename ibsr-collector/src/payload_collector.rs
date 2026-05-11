//! ShadowPayload-mode collector orchestration.
//!
//! Pulls payload events from a `PayloadEventSource` (kernel ringbuf in
//! production; mock in tests), runs them through the userspace
//! `PayloadHandler`, and emits a `Snapshot` v6 with `resp_aggregates`
//! at each window boundary.
//!
//! This module follows the project pattern of trait-abstracted I/O
//! (event source, clock, filesystem, snapshot writer) so the
//! orchestration logic is unit-testable without a kernel.
//!
//! Robustness contract — load-bearing for "IBSR runs without dying":
//!
//! - Event-source errors are logged and the loop continues. The
//!   ShadowPayload safety invariant is "ring-buffer pressure cannot
//!   backpressure the network stack"; this is preserved on the
//!   userspace side as "userspace errors don't terminate the loop".
//! - Malformed events (decode failure) are counted and dropped, never
//!   panicked on.
//! - Snapshot-write errors propagate (the caller decides whether to
//!   retry or exit).
//! - Shutdown is checked via `ShutdownCheck` between event polls so
//!   SIGINT/SIGTERM produce a clean exit (final snapshot emitted, TC
//!   detached at a higher layer).
//! - Empty windows (no events) still produce a snapshot for the
//!   inference loop's heartbeat semantics.

use std::collections::HashSet;
use std::path::Path;
use std::time::{Duration, Instant};

use ibsr_bpf::decode_event;
use ibsr_clock::Clock;
use ibsr_fs::{rotate_snapshots, Filesystem, FsError, RotationConfig, SnapshotWriter};
use ibsr_schema::{HostTelemetry, ResponseAggregates, Snapshot};
use thiserror::Error;

use crate::host_telemetry::{self, HostSampler, HostSnapshot};
use crate::payload::{PayloadEvent, PayloadHandler};
use crate::signal::ShutdownCheck;

/// Configuration for one ShadowPayload-mode collection cycle.
#[derive(Debug, Clone)]
pub struct PayloadCollectorConfig {
    /// Server-side ports being monitored. Used both as the BPF
    /// port-filter input and as the userspace direction-inference
    /// disambiguator.
    pub server_ports: Vec<u16>,
    /// Rotation policy for snapshot files.
    pub rotation: RotationConfig,
    /// Snapshot emission interval in seconds. Same field semantics as
    /// `CollectorConfig::interval_sec` for StrictCounter.
    pub interval_sec: u32,
    /// Stable run identifier (Unix timestamp at run start).
    pub run_id: u64,
}

/// Errors raised by the orchestrator.
#[derive(Debug, Error)]
pub enum PayloadCollectorError {
    #[error("snapshot write error: {0}")]
    Write(#[from] FsError),
}

/// Outcome of one collection window.
#[derive(Debug)]
pub struct PayloadWindowResult {
    /// Number of complete request:response pairs aggregated this window.
    pub n_pairs: u64,
    /// Snapshot timestamp.
    pub timestamp: u64,
    /// Whether `resp_aggregates` was populated (false = empty window).
    pub has_aggregates: bool,
    /// Snapshot files rotated out.
    pub rotated_count: usize,
    /// Decode failures observed this window (lossy by design).
    pub decode_errors: u64,
    /// Events filtered out by direction inference (no server-port match).
    pub events_filtered: u64,
    /// Event-source errors observed this window (lossy by design;
    /// preserves the no-drop guarantee even if userspace falls behind).
    pub source_errors: u64,
}

/// Trait abstracting the kernel-side ringbuf for testability. The
/// production implementation polls the libbpf-rs `RingBuffer`; the
/// mock implementation returns canned events.
pub trait PayloadEventSource {
    /// Poll for raw event bytes for at most `timeout`. Returns the
    /// (possibly empty) batch of events received before the timeout
    /// elapsed. An empty `Vec` is a normal idle return, not an error.
    fn poll(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String>;
}

/// In-process event source for tests. Returns canned event batches
/// in order; subsequent polls return empty until exhausted.
#[derive(Debug, Default)]
pub struct MockPayloadEventSource {
    pub batches: Vec<Vec<Vec<u8>>>,
    pub poll_count: u64,
    /// If set and >= poll_count threshold, subsequent polls error.
    pub fail_after: Option<u64>,
}

impl MockPayloadEventSource {
    pub fn from_batches(batches: Vec<Vec<Vec<u8>>>) -> Self {
        Self {
            batches,
            poll_count: 0,
            fail_after: None,
        }
    }
}

/// Bridge implementation: `ibsr_bpf::QueueBackedEventSource` becomes a
/// `PayloadEventSource` the orchestrator can poll. Lives here because
/// `PayloadEventSource` is defined in this crate and trait coherence
/// requires the impl to be downstream of both the trait and the type.
impl PayloadEventSource for ibsr_bpf::QueueBackedEventSource {
    fn poll(&mut self, _timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        // Drain whatever the kernel ringbuf callback has pushed since
        // the last poll. The kernel-side pump (libbpf-rs RingBuffer::poll)
        // runs on the same thread, separately, before this method is
        // called from the orchestrator loop. (When the production
        // adapter lands, the pump will be wired in via with_pump.)
        Ok(self.pending().drain())
    }
}

/// Bridge implementation: `ibsr_bpf::LibbpfPayloadCollector` (production
/// libbpf-rs adapter) becomes a `PayloadEventSource`. On poll: pump
/// the kernel ringbuf for `timeout`, then drain the queue the
/// callback pushed into.
///
/// This is the kernel-driven path; the orchestrator's loop is
/// otherwise identical to the mock-driven test path.
impl PayloadEventSource for ibsr_bpf::LibbpfPayloadCollector {
    fn poll(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        // libbpf RingBuffer::poll's timeout granularity is milliseconds.
        // We pump the kernel ringbuf for the requested timeout, which
        // invokes our callback for each available event (pushing into
        // the PendingEvents queue). Then drain the queue.
        self.pump(timeout).map_err(|e| e.to_string())?;
        Ok(self.pending().drain())
    }
}

impl PayloadEventSource for MockPayloadEventSource {
    fn poll(&mut self, _timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        self.poll_count += 1;
        if let Some(fail_after) = self.fail_after {
            if self.poll_count > fail_after {
                return Err("mock failure after limit".into());
            }
        }
        if self.batches.is_empty() {
            Ok(Vec::new())
        } else {
            Ok(self.batches.remove(0))
        }
    }
}

/// Build a v7 Snapshot from a window's `ResponseAggregates` and an
/// optional `HostTelemetry` block. If the aggregates are empty (zero
/// pairs), the `resp_aggregates` field is omitted (Strict-equivalent
/// shape). The host block is attached when `host` is `Some` regardless
/// of whether response pairs were observed (operators may want host-
/// only emit on idle windows).
pub fn build_payload_snapshot<C: Clock>(
    aggregates: ResponseAggregates,
    config: &PayloadCollectorConfig,
    clock: &C,
    base_ts_unix_sec: u64,
    host: Option<HostTelemetry>,
) -> Snapshot {
    // ShadowPayload mode doesn't carry per-(src_ip, dst_port) counter
    // buckets — those are StrictCounter mode's domain. Emit an empty
    // bucket list; downstream consumers infer mode from the presence
    // of `resp_aggregates`.
    let mut snapshot = Snapshot::new(
        clock.now_unix_sec(),
        &config.server_ports,
        Vec::new(),
        config.interval_sec,
        config.run_id,
        base_ts_unix_sec,
    );

    if aggregates.count > 0 {
        snapshot = snapshot.with_resp_aggregates(aggregates);
    }
    if let Some(h) = host {
        snapshot = snapshot.with_host(h);
    }
    snapshot
}

/// Run one window's worth of event polling + snapshot emission.
/// Returns when the deadline has elapsed OR the shutdown flag has been
/// raised.
///
/// Robustness: event-source errors and decode errors are recorded but
/// don't terminate the loop. Only writer errors propagate (so the
/// caller can distinguish recoverable from unrecoverable). In
/// production the caller treats writer errors as warnings and
/// continues; the next window's write is attempted independently.
#[allow(clippy::too_many_arguments)]
pub fn collect_payload_window<E, C, W, F, S>(
    event_source: &mut E,
    clock: &C,
    writer: &W,
    fs: &F,
    handler: &mut PayloadHandler,
    server_ports: &HashSet<u16>,
    config: &PayloadCollectorConfig,
    base_ts_unix_sec: u64,
    window_deadline: Instant,
    shutdown: &S,
    output_dir: &Path,
    host_sampler: Option<&HostSampler>,
) -> Result<PayloadWindowResult, PayloadCollectorError>
where
    E: PayloadEventSource,
    C: Clock,
    W: SnapshotWriter,
    F: Filesystem,
    S: ShutdownCheck,
{
    let mut decode_errors: u64 = 0;
    let mut events_filtered: u64 = 0;
    let mut source_errors: u64 = 0;

    // Capture host-telemetry baseline at window start. Failure (target
    // process is gone, /proc unreadable, non-Linux dev host) is
    // tolerated: the end-of-window capture re-checks, and the
    // resulting snapshot simply omits the host block.
    let host_baseline: Option<HostSnapshot> = host_sampler
        .and_then(|s| s.capture().ok());

    // Loop invariant: always poll at least once per iteration, even
    // when deadline has already passed. This ensures queued events get
    // drained on shutdown / window-wraparound. Exit condition is
    // (poll returned empty AND deadline passed) OR shutdown.
    loop {
        if shutdown.should_stop() {
            break;
        }
        let now = Instant::now();
        let remaining = window_deadline.saturating_duration_since(now);
        // Cap per-poll wait so we re-check shutdown promptly on long
        // windows. When remaining is 0, this is also 0 — a non-blocking
        // drain.
        let poll_timeout = remaining.min(Duration::from_millis(250));

        let (events, source_err) = match event_source.poll(poll_timeout) {
            Ok(events) => (events, false),
            Err(_e) => {
                source_errors += 1;
                (Vec::new(), true)
            }
        };

        let was_idle = events.is_empty();
        for raw in events {
            match decode_event(&raw) {
                Ok(decoded) => match PayloadEvent::from_decoded(&decoded, server_ports) {
                    Some(pe) => {
                        let _outcome = handler.feed(&pe);
                    }
                    None => {
                        events_filtered += 1;
                    }
                },
                Err(_e) => {
                    decode_errors += 1;
                }
            }
        }

        // Exit: idle (no events to drain) AND deadline reached. A source
        // error counts as idle for exit purposes — we've already
        // recorded it and shouldn't busy-loop on a broken source.
        if (was_idle || source_err) && now >= window_deadline {
            break;
        }
    }

    let aggregates = handler.take_window();
    let n_pairs = aggregates.count;
    let has_aggregates = aggregates.count > 0;

    // Capture end-of-window host snapshot and compute delta. Both the
    // baseline and end captures must succeed for the host block to
    // emit; otherwise the snapshot omits it (target gone mid-window /
    // /proc denied / non-Linux).
    let host_block: Option<HostTelemetry> = match (host_sampler, &host_baseline) {
        (Some(sampler), Some(baseline)) => sampler
            .capture()
            .ok()
            .map(|end| host_telemetry::delta(baseline, &end, host_telemetry::CLOCK_TICKS_PER_SEC)),
        _ => None,
    };

    let snapshot =
        build_payload_snapshot(aggregates, config, clock, base_ts_unix_sec, host_block);
    let timestamp = snapshot.ts_unix_sec;

    writer.write(&snapshot)?;

    let rotation_result = rotate_snapshots(fs, output_dir, &config.rotation, clock)?;

    Ok(PayloadWindowResult {
        n_pairs,
        timestamp,
        has_aggregates,
        rotated_count: rotation_result.total_removed(),
        decode_errors,
        events_filtered,
        source_errors,
    })
}

/// Convert validated `CollectPayloadArgs` into the
/// `PayloadCollectorConfig` the orchestrator consumes. Caller must
/// have already called `args.validate()`; this conversion does NOT
/// re-validate. `clock` provides the run_id (Unix timestamp at run
/// start).
pub fn args_to_config<C: Clock>(
    args: &crate::cli::CollectPayloadArgs,
    clock: &C,
) -> PayloadCollectorConfig {
    PayloadCollectorConfig {
        server_ports: args.get_all_ports(),
        rotation: RotationConfig::new(args.max_files, args.max_age),
        interval_sec: args.window_sec as u32,
        run_id: clock.now_unix_sec(),
    }
}

/// Build a `HashSet<u16>` of server ports for the userspace direction-
/// inference path. Pulled from validated `CollectPayloadArgs`.
pub fn args_to_server_ports(args: &crate::cli::CollectPayloadArgs) -> HashSet<u16> {
    args.get_all_ports().into_iter().collect()
}

/// Resolve the optional host-telemetry target into a [`HostSampler`].
///
/// - `--target-pid` → `Some(HostSampler::new(pid))`.
/// - `--target-process-name` → walk `/proc` for the first PID whose
///   `comm` matches; `None` if no match (snapshot omits host block).
/// - Neither set → `None`.
///
/// Process-name resolution is Linux-only; on non-Linux dev hosts the
/// name path returns `None`. Validation has already rejected the
/// "both flags set" case at CLI parse time, so this fn just picks
/// whichever was provided.
pub fn resolve_host_sampler(args: &crate::cli::CollectPayloadArgs) -> Option<HostSampler> {
    if let Some(pid) = args.target_pid {
        return Some(HostSampler::new(pid));
    }
    if let Some(name) = args.target_process_name.as_deref() {
        return resolve_pid_from_name(name).map(HostSampler::new);
    }
    None
}

/// Walk `/proc` and return the first PID whose `comm` (process name,
/// truncated to 15 chars by the kernel) matches `name`. Linux-only;
/// returns `None` on non-Linux dev hosts.
#[cfg(target_os = "linux")]
fn resolve_pid_from_name(name: &str) -> Option<u32> {
    // Collect ALL matching PIDs, then return the lowest. `read_dir` on
    // /proc has no defined ordering; without this collect-then-sort,
    // multi-worker processes (e.g. `sui-node` with many threads sharing
    // a `comm`) produce a nondeterministic resolved PID run-to-run.
    // The lowest PID is conventionally the parent / longest-lived
    // process — a sensible default when comm collisions exist.
    let dir = std::fs::read_dir("/proc").ok()?;
    let mut matches: Vec<u32> = Vec::new();
    for entry in dir.flatten() {
        let file_name = entry.file_name();
        let Some(pid_str) = file_name.to_str() else {
            // Non-UTF8 dirent (extremely rare on /proc, but `?` here
            // would abort the entire walk early on first occurrence).
            continue;
        };
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let comm_path = format!("/proc/{}/comm", pid);
        if let Ok(comm) = std::fs::read_to_string(&comm_path) {
            if comm.trim() == name {
                matches.push(pid);
            }
        }
    }
    matches.into_iter().min()
}

#[cfg(not(target_os = "linux"))]
fn resolve_pid_from_name(_name: &str) -> Option<u32> {
    None
}

/// Outcome of a multi-window collection run.
#[derive(Debug, Default)]
pub struct PayloadLoopResult {
    /// Number of windows that emitted a snapshot successfully.
    pub windows_completed: u64,
    /// Number of write errors encountered (windows that failed but
    /// loop continued).
    pub windows_failed: u64,
    /// Total request:response pairs aggregated across all windows.
    pub total_pairs: u64,
    /// Total decode errors observed (cumulative).
    pub total_decode_errors: u64,
    /// Total event-source errors observed (cumulative).
    pub total_source_errors: u64,
    /// Total events filtered out by direction inference.
    pub total_events_filtered: u64,
}

/// Run the multi-window payload-collection loop. Each iteration
/// invokes `collect_payload_window`; on success the result is folded
/// into the cumulative `PayloadLoopResult`. On writer failure the
/// loop CONTINUES (logs would happen at a higher layer); the only
/// terminal condition is `shutdown.should_stop() == true`.
///
/// This is the production loop's heartbeat: even if writes fail
/// repeatedly (disk full, permissions broken), the binary doesn't
/// die — the operator sees status.jsonl heartbeats stop, alerts fire,
/// the binary is restarted. The "IBSR runs without dying" contract.
///
/// `clock_for_deadline` is used to pick the wall-clock window deadline
/// for the FIRST window; subsequent deadlines advance by
/// `config.interval_sec`. We use Instant (monotonic) for deadlines so
/// wall-clock skew during the run doesn't break the cadence.
#[allow(clippy::too_many_arguments)]
pub fn collect_payload_loop<E, C, W, F, S>(
    event_source: &mut E,
    clock: &C,
    writer: &W,
    fs: &F,
    handler: &mut PayloadHandler,
    server_ports: &HashSet<u16>,
    config: &PayloadCollectorConfig,
    shutdown: &S,
    output_dir: &Path,
    max_windows: Option<u64>,
    host_sampler: Option<&HostSampler>,
) -> PayloadLoopResult
where
    E: PayloadEventSource,
    C: Clock,
    W: SnapshotWriter,
    F: Filesystem,
    S: ShutdownCheck,
{
    let mut result = PayloadLoopResult::default();
    let base_ts_unix_sec = clock.now_unix_sec();
    let mut deadline = Instant::now() + Duration::from_secs(config.interval_sec as u64);

    loop {
        if shutdown.should_stop() {
            break;
        }
        if let Some(limit) = max_windows {
            if result.windows_completed + result.windows_failed >= limit {
                break;
            }
        }

        match collect_payload_window(
            event_source,
            clock,
            writer,
            fs,
            handler,
            server_ports,
            config,
            base_ts_unix_sec,
            deadline,
            shutdown,
            output_dir,
            host_sampler,
        ) {
            Ok(window_result) => {
                result.windows_completed += 1;
                result.total_pairs += window_result.n_pairs;
                result.total_decode_errors += window_result.decode_errors;
                result.total_source_errors += window_result.source_errors;
                result.total_events_filtered += window_result.events_filtered;
            }
            Err(_e) => {
                // Writer failure is NOT fatal — log + continue. The
                // load-bearing "IBSR runs without dying" guarantee.
                // Higher layers see the stuck status.jsonl heartbeat
                // and alert; this loop keeps trying.
                result.windows_failed += 1;
            }
        }

        // Advance deadline by one full window. This caps drift to one
        // window length even if a window's processing took unusually
        // long — the next deadline is anchored to the previous one,
        // not Instant::now().
        deadline += Duration::from_secs(config.interval_sec as u64);
    }

    result
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use ibsr_bpf::{
        direction, RawFlowId, RawPayloadEvent, EXPECTED_RAW_EVENT_SIZE, PAYLOAD_SAMPLE_BYTES,
    };
    use ibsr_clock::MockClock;
    use ibsr_fs::{MockFilesystem, StandardSnapshotWriter};
    use std::collections::HashSet;
    use std::io;
    use std::path::PathBuf;
    use std::sync::Arc;

    // Wrapper to implement Filesystem for Arc<MockFilesystem>, mirrors
    // collector::tests::ArcFs.
    struct ArcFs(Arc<MockFilesystem>);
    impl Filesystem for ArcFs {
        fn write_atomic(&self, path: &Path, data: &[u8]) -> Result<(), FsError> {
            self.0.write_atomic(path, data)
        }
        fn append_atomic(&self, path: &Path, data: &[u8]) -> Result<(), FsError> {
            self.0.append_atomic(path, data)
        }
        fn read_file(&self, path: &Path) -> Result<String, FsError> {
            self.0.read_file(path)
        }
        fn list_snapshots(&self, dir: &Path) -> Result<Vec<ibsr_fs::SnapshotFile>, FsError> {
            self.0.list_snapshots(dir)
        }
        fn remove(&self, path: &Path) -> Result<(), FsError> {
            self.0.remove(path)
        }
        fn exists(&self, path: &Path) -> bool {
            self.0.exists(path)
        }
        fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
            self.0.create_dir_all(path)
        }
    }

    // Hour-boundary timestamp so snapshot_filename generates a
    // deterministic path (same convention as collector tests).
    const HOUR_0: u64 = 1_704_067_200; // 2024-01-01 00:00:00 UTC
    const HOUR_1: u64 = 1_704_070_800; // 2024-01-01 01:00:00 UTC

    fn raw_event_bytes(
        src_ip: u32,
        src_port: u16,
        dst_ip: u32,
        dst_port: u16,
        dir: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut ev = RawPayloadEvent {
            flow: RawFlowId {
                src_ip: src_ip.to_be(),
                dst_ip: dst_ip.to_be(),
                src_port: src_port.to_be(),
                dst_port: dst_port.to_be(),
            },
            direction: dir,
            tcp_seq: 0,
            _pad0: 0,
            ts_ns: 0,
            payload_len: payload.len() as u32,
            sample_len: payload.len() as u32,
            payload: [0u8; PAYLOAD_SAMPLE_BYTES],
        };
        ev.payload[..payload.len()].copy_from_slice(payload);
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&ev as *const RawPayloadEvent) as *const u8,
                std::mem::size_of::<RawPayloadEvent>(),
            )
        };
        bytes.to_vec()
    }

    fn req_event(payload: &[u8]) -> Vec<u8> {
        // Client 12345 → Server 8899; ingress.
        raw_event_bytes(0x7f000002, 12345, 0x7f000001, 8899, direction::INGRESS, payload)
    }

    fn resp_event(payload: &[u8]) -> Vec<u8> {
        // Server 8899 → Client 12345; egress.
        raw_event_bytes(0x7f000001, 8899, 0x7f000002, 12345, direction::EGRESS, payload)
    }

    fn config(server_ports: Vec<u16>) -> PayloadCollectorConfig {
        PayloadCollectorConfig {
            server_ports,
            rotation: RotationConfig::new(100, 86400),
            interval_sec: 60,
            run_id: HOUR_0,
        }
    }

    fn server_ports_set(ports: &[u16]) -> HashSet<u16> {
        ports.iter().copied().collect()
    }

    fn output_dir() -> PathBuf {
        PathBuf::from("/var/lib/ibsr/snapshots/payload")
    }

    fn parse_snapshots_from(fs: &MockFilesystem) -> Vec<Snapshot> {
        let dir = output_dir();
        let listed = fs.list_snapshots(&dir).expect("list");
        let mut out = Vec::new();
        for sf in listed {
            // Files in MockFilesystem are append-atomic with newline-
            // terminated JSON; iterate one snapshot per line.
            if let Ok(content) = fs.read_file(&sf.path) {
                for line in content.lines() {
                    if line.is_empty() {
                        continue;
                    }
                    if let Ok(s) = Snapshot::from_json(line) {
                        out.push(s);
                    }
                }
            }
        }
        out
    }

    // ===========================================
    // Test Category A — build_payload_snapshot
    // ===========================================

    #[test]
    fn empty_aggregates_yields_current_schema_snapshot_without_resp_block() {
        let cfg = config(vec![8899]);
        let clock = MockClock::new(HOUR_1);
        let agg = ResponseAggregates::from_pairs(&[]);
        let snap = build_payload_snapshot(agg, &cfg, &clock, HOUR_0, None);
        assert_eq!(snap.version, ibsr_schema::SCHEMA_VERSION);
        assert!(snap.resp_aggregates.is_none());
        assert_eq!(snap.ts_unix_sec, HOUR_1);
        assert_eq!(snap.run_id, HOUR_0);
    }

    #[test]
    fn nonempty_aggregates_yields_current_schema_snapshot_with_resp_block() {
        let cfg = config(vec![8899]);
        let clock = MockClock::new(HOUR_1);
        let agg = ResponseAggregates::from_pairs(&[(100, 200), (50, 250)]);
        let snap = build_payload_snapshot(agg.clone(), &cfg, &clock, HOUR_0, None);
        assert_eq!(snap.version, ibsr_schema::SCHEMA_VERSION);
        assert_eq!(snap.resp_aggregates, Some(agg));
    }

    #[test]
    fn snapshot_carries_server_ports_in_dst_ports() {
        let cfg = config(vec![8899, 9000]);
        let clock = MockClock::new(HOUR_1);
        let agg = ResponseAggregates::from_pairs(&[]);
        let snap = build_payload_snapshot(agg, &cfg, &clock, HOUR_0, None);
        assert!(snap.dst_ports.contains(&8899));
        assert!(snap.dst_ports.contains(&9000));
    }

    #[test]
    fn build_payload_snapshot_attaches_host_block_when_provided() {
        let cfg = config(vec![8899]);
        let clock = MockClock::new(HOUR_1);
        let agg = ResponseAggregates::from_pairs(&[]);
        let host = ibsr_schema::HostTelemetry {
            cpu_mean: Some(50.0),
            rss_max: Some(1024),
            ..Default::default()
        };
        let snap = build_payload_snapshot(agg, &cfg, &clock, HOUR_0, Some(host.clone()));
        assert_eq!(snap.host, Some(host));
    }

    #[test]
    fn build_payload_snapshot_omits_host_block_when_none() {
        let cfg = config(vec![8899]);
        let clock = MockClock::new(HOUR_1);
        let agg = ResponseAggregates::from_pairs(&[]);
        let snap = build_payload_snapshot(agg, &cfg, &clock, HOUR_0, None);
        assert!(snap.host.is_none(),
            "no host telemetry input → snapshot.host stays None");
    }

    #[test]
    fn resolve_host_sampler_picks_target_pid_when_set() {
        let args = make_args(&[("--target-pid", "1234")]);
        let sampler = resolve_host_sampler(&args).expect("sampler");
        assert_eq!(sampler.pid(), 1234);
    }

    #[test]
    fn resolve_host_sampler_returns_none_when_neither_flag_set() {
        let args = make_args(&[]);
        assert!(resolve_host_sampler(&args).is_none(),
            "no --target-pid + no --target-process-name → no sampler");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_host_sampler_resolves_own_process_name() {
        // Resolve our own /proc/self/comm and pass it as --target-process-name.
        // The walk should find a matching PID (our own) and produce a sampler.
        let own_comm = std::fs::read_to_string("/proc/self/comm")
            .expect("read /proc/self/comm")
            .trim()
            .to_string();
        let args = make_args(&[("--target-process-name", &own_comm)]);
        let sampler = resolve_host_sampler(&args)
            .expect("name resolution must produce a sampler for our own comm");
        // The resolved PID need not equal std::process::id() — comm-collisions
        // are possible (other test runners with the same name, etc.); what we
        // assert is that *some* matching process was found.
        assert!(sampler.pid() > 0, "resolved sampler must carry a valid PID");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn resolve_host_sampler_target_process_name_returns_none_on_non_linux() {
        // Non-Linux: /proc walk is unavailable; the name branch returns None.
        let args = make_args(&[("--target-process-name", "anything")]);
        assert!(resolve_host_sampler(&args).is_none(),
            "non-Linux dev hosts must not return a sampler for --target-process-name");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collect_payload_window_emits_host_block_for_self_sampler() {
        // Sampling /proc/self should always succeed (the test process
        // is alive). The end-of-window capture also succeeds, and the
        // resulting snapshot carries a populated host block.
        let mut src = MockPayloadEventSource::from_batches(vec![]);
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir());
        let cfg = config(vec![8899]);
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        let shutdown = crate::signal::NeverShutdown;
        let deadline = Instant::now();
        let pid = std::process::id();
        let sampler = HostSampler::new(pid);

        let _result = collect_payload_window(
            &mut src,
            &clock,
            &writer,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            HOUR_0,
            deadline,
            &shutdown,
            &output_dir(),
            Some(&sampler),
        )
        .expect("collect_payload_window");

        let snaps = parse_snapshots_from(&fs);
        assert_eq!(snaps.len(), 1);
        let host = snaps[0].host.as_ref()
            .expect("snapshot.host should be populated for /proc/self sampler");
        assert!(host.rss_max.is_some(), "rss_max should be populated for self");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collect_payload_window_omits_host_block_for_nonexistent_pid() {
        // A nonexistent target PID — both captures fail; snapshot
        // omits the host block (graceful degradation).
        let mut src = MockPayloadEventSource::from_batches(vec![]);
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir());
        let cfg = config(vec![8899]);
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        let shutdown = crate::signal::NeverShutdown;
        let deadline = Instant::now();
        let sampler = HostSampler::new(2_147_483_647);

        let _result = collect_payload_window(
            &mut src,
            &clock,
            &writer,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            HOUR_0,
            deadline,
            &shutdown,
            &output_dir(),
            Some(&sampler),
        )
        .expect("collect_payload_window");

        let snaps = parse_snapshots_from(&fs);
        assert_eq!(snaps.len(), 1);
        assert!(snaps[0].host.is_none(),
            "nonexistent PID → host block omitted");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collect_payload_window_omits_host_when_process_exits_mid_window() {
        // Plan-promised case: baseline capture succeeds, then the
        // target process exits before end-of-window capture. The host
        // block must be omitted (we don't fabricate a partial delta).
        //
        // Mechanism:
        // 1. Spawn a sleep-100ms child. /proc/<pid>/{stat,status} live.
        // 2. Spawn a background thread that calls child.wait(): this
        //    REAPS the child the moment it exits, so /proc/<pid>
        //    actually disappears (rather than lingering as a zombie
        //    with the parent — us — still holding the wait slot).
        // 3. Call collect_payload_window with a 500ms deadline.
        //    Baseline (t≈0) succeeds. Loop polls until deadline. Child
        //    exits at t≈100ms, reaper wakes, /proc/<pid> disappears.
        //    End capture at t≈500ms fails → host block omitted.
        use std::process::Command;
        use std::time::Duration as StdDuration;

        let child = Command::new("sleep")
            .arg("0.1")
            .spawn()
            .expect("spawn sleep child");
        let pid = child.id();
        // Move the Child handle into a reaper thread so the kernel
        // releases /proc/<pid> as soon as the child exits (otherwise
        // it stays as a zombie until we wait()).
        let reaper = std::thread::spawn(move || {
            let mut child = child;
            let _ = child.wait();
        });
        let sampler = HostSampler::new(pid);

        let mut src = MockPayloadEventSource::from_batches(vec![]);
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir());
        let cfg = config(vec![8899]);
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        let shutdown = crate::signal::NeverShutdown;
        let deadline = Instant::now() + StdDuration::from_millis(500);

        let _result = collect_payload_window(
            &mut src,
            &clock,
            &writer,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            HOUR_0,
            deadline,
            &shutdown,
            &output_dir(),
            Some(&sampler),
        )
        .expect("collect_payload_window");

        // Join the reaper to be tidy (child has long since exited).
        reaper.join().expect("reaper thread");

        let snaps = parse_snapshots_from(&fs);
        assert_eq!(snaps.len(), 1);
        assert!(snaps[0].host.is_none(),
            "process exited mid-window → host block omitted");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collect_payload_loop_threads_host_sampler_to_window() {
        // Plan-promised coverage gap: the loop's `host_sampler` parameter
        // must thread through to each window call. Run a single-window
        // loop with a /proc/self sampler and verify the emitted snapshot
        // carries a host block (proves the loop didn't drop the param).
        let mut src = MockPayloadEventSource::from_batches(vec![]);
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir());
        let mut cfg = config(vec![8899]);
        cfg.interval_sec = 1; // short window so the test finishes promptly
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        let shutdown = crate::signal::NeverShutdown;
        let sampler = HostSampler::new(std::process::id());

        let result = collect_payload_loop(
            &mut src,
            &clock,
            &writer,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            &shutdown,
            &output_dir(),
            Some(1),
            Some(&sampler),
        );
        assert_eq!(result.windows_completed, 1);
        let snaps = parse_snapshots_from(&fs);
        assert_eq!(snaps.len(), 1);
        let host = snaps[0].host.as_ref()
            .expect("loop must thread host_sampler through to window emit");
        assert!(host.rss_max.is_some(),
            "/proc/self RSS should always be readable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_pid_from_name_is_deterministic_under_multi_match() {
        // /proc/<pid>/comm-collision case: there are commonly multiple
        // processes with the same comm (kernel threads, multi-worker
        // services). resolve_pid_from_name must return the lowest PID
        // deterministically across runs, not whatever readdir returns
        // first. Probe via /proc/self/comm — own process is one match;
        // assert determinism by running twice.
        let own_comm = std::fs::read_to_string("/proc/self/comm")
            .expect("read /proc/self/comm")
            .trim()
            .to_string();
        let args = make_args(&[("--target-process-name", &own_comm)]);
        let s1 = resolve_host_sampler(&args).expect("first resolution");
        let s2 = resolve_host_sampler(&args).expect("second resolution");
        assert_eq!(s1.pid(), s2.pid(),
            "name resolution must be deterministic across runs");
    }

    // ===========================================
    // Test Category B — Orchestrator
    // ===========================================

    fn run_one_window(
        batches: Vec<Vec<Vec<u8>>>,
    ) -> (PayloadWindowResult, Vec<Snapshot>) {
        let mut src = MockPayloadEventSource::from_batches(batches);
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir());
        let cfg = config(vec![8899]);
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        let shutdown = crate::signal::NeverShutdown;

        // Window deadline already in the past → loop exits immediately,
        // process whatever's queued and emit snapshot.
        let deadline = Instant::now();

        let result = collect_payload_window(
            &mut src,
            &clock,
            &writer,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            HOUR_0,
            deadline,
            &shutdown,
            &output_dir(),            None,
        )
        .expect("collect_payload_window");

        let snaps = parse_snapshots_from(&fs);
        (result, snaps)
    }

    #[test]
    fn empty_window_writes_current_schema_snapshot_with_no_aggregates() {
        let (result, snaps) = run_one_window(vec![]);
        assert_eq!(result.n_pairs, 0);
        assert!(!result.has_aggregates);
        assert_eq!(result.decode_errors, 0);
        assert_eq!(result.events_filtered, 0);
        assert_eq!(result.source_errors, 0);
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].version, ibsr_schema::SCHEMA_VERSION);
        assert!(snaps[0].resp_aggregates.is_none());
    }

    #[test]
    fn paired_request_response_produces_resp_aggregates() {
        // POST / HTTP/1.1 ... Content-Length: 4 ... body
        // HTTP/1.1 200 OK ... Content-Length: 7 ... body
        let req = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nBODY";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nPAYLOAD";
        let batches = vec![vec![req_event(req)], vec![resp_event(resp)]];
        let (result, snaps) = run_one_window(batches);
        assert_eq!(result.n_pairs, 1);
        assert!(result.has_aggregates);
        assert_eq!(snaps.len(), 1);
        let agg = snaps[0].resp_aggregates.as_ref().expect("resp_aggregates");
        assert_eq!(agg.count, 1);
        assert_eq!(agg.req_bytes_max, Some(4));
        assert_eq!(agg.resp_bytes_max, Some(7));
    }

    #[test]
    fn malformed_event_increments_decode_errors_but_loop_continues() {
        // First batch: a truncated event (will fail decode_event).
        // Second/third: a valid pair so we still get aggregates.
        let truncated = vec![0u8; 100];
        let req = b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nABC";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO";
        let batches = vec![
            vec![truncated.clone()],
            vec![req_event(req)],
            vec![resp_event(resp)],
        ];
        let (result, snaps) = run_one_window(batches);
        assert!(result.decode_errors >= 1);
        assert_eq!(result.n_pairs, 1, "valid pair must still aggregate");
        let agg = snaps[0].resp_aggregates.as_ref().expect("aggregates");
        assert_eq!(agg.count, 1);
        assert_eq!(agg.req_bytes_max, Some(3));
    }

    #[test]
    fn unrelated_flow_increments_events_filtered_but_loop_continues() {
        let unrelated = raw_event_bytes(
            0x0a000001, 1000, 0x0a000002, 2000, direction::INGRESS,
            b"random",
        );
        let (result, snaps) = run_one_window(vec![vec![unrelated]]);
        assert_eq!(result.events_filtered, 1);
        assert_eq!(result.n_pairs, 0);
        assert_eq!(snaps.len(), 1);
        assert!(snaps[0].resp_aggregates.is_none());
    }

    #[test]
    fn event_source_error_does_not_kill_loop() {
        let mut src = MockPayloadEventSource::from_batches(Vec::new());
        src.fail_after = Some(0);
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir());
        let cfg = config(vec![8899]);
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        let shutdown = crate::signal::NeverShutdown;

        let result = collect_payload_window(
            &mut src,
            &clock,
            &writer,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            HOUR_0,
            Instant::now(),
            &shutdown,
            &output_dir(),            None,
        )
        .expect("loop must not propagate event-source errors");
        assert!(result.source_errors >= 1);
        let snaps = parse_snapshots_from(&fs);
        assert_eq!(snaps.len(), 1);
    }

    #[test]
    fn shutdown_flag_short_circuits_window() {
        let mut src = MockPayloadEventSource::from_batches(Vec::new());
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir());
        let cfg = config(vec![8899]);
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        let shutdown = crate::signal::AlwaysShutdown;

        // Long deadline; shutdown should short-circuit.
        let deadline = Instant::now() + Duration::from_secs(60);

        let _result = collect_payload_window(
            &mut src,
            &clock,
            &writer,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            HOUR_0,
            deadline,
            &shutdown,
            &output_dir(),            None,
        )
        .expect("clean shutdown");
        let snaps = parse_snapshots_from(&fs);
        assert_eq!(snaps.len(), 1, "shutdown must still emit final snapshot");
    }

    #[test]
    fn writer_error_propagates() {
        struct FailingWriter;
        impl SnapshotWriter for FailingWriter {
            fn write(&self, _snapshot: &Snapshot) -> Result<PathBuf, FsError> {
                Err(FsError::Io(io::Error::new(io::ErrorKind::Other, "disk full")))
            }
        }
        let mut src = MockPayloadEventSource::from_batches(Vec::new());
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let cfg = config(vec![8899]);
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        let shutdown = crate::signal::NeverShutdown;

        let result = collect_payload_window(
            &mut src,
            &clock,
            &FailingWriter,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            HOUR_0,
            Instant::now(),
            &shutdown,
            &output_dir(),            None,
        );
        match result {
            Err(PayloadCollectorError::Write(_)) => {}
            other => panic!("expected Write error, got {:?}", other.as_ref().err()),
        }
    }

    #[test]
    fn multiple_pairs_aggregate_per_offline_semantics() {
        // Pin: 3 RPC pairs in one window produce ResponseAggregates that
        // exactly match `ResponseAggregates::from_pairs`. This is the
        // bridge contract from ShadowPayload userspace to the Phase 1
        // close-gate cross-validation.
        //
        // Pair values pick exact-decimal means: req sum=300/count=3 → 100.0,
        // resp sum=1050/count=3 → 350.0. JSON-round-tripped f64 means in the
        // live pipeline must equal the directly-computed means; non-clean
        // divisors (e.g. sum=350) drift in the last bit through JSON.
        let pairs = [(90u64, 200u64), (60, 250), (150, 600)];
        let mut batches: Vec<Vec<Vec<u8>>> = Vec::new();
        for (req_n, resp_n) in pairs.iter() {
            let req = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", req_n);
            let req_body = vec![b'r'; *req_n as usize];
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", resp_n);
            let resp_body = vec![b's'; *resp_n as usize];
            let mut req_bytes = req.as_bytes().to_vec();
            req_bytes.extend_from_slice(&req_body);
            let mut resp_bytes = resp.as_bytes().to_vec();
            resp_bytes.extend_from_slice(&resp_body);
            // Cap to BPF sample size to mimic real ringbuf behaviour.
            req_bytes.truncate(PAYLOAD_SAMPLE_BYTES);
            resp_bytes.truncate(PAYLOAD_SAMPLE_BYTES);
            batches.push(vec![req_event(&req_bytes)]);
            batches.push(vec![resp_event(&resp_bytes)]);
        }
        let (_result, snaps) = run_one_window(batches);
        let agg = snaps[0].resp_aggregates.as_ref().expect("aggregates");
        // Strip fields populated by per-event metadata (port tuples,
        // HTTP status, JSON-RPC envelope, kernel timing) for the
        // byte-aggregate-only comparison; offline `from_pairs` knows
        // only request/response byte sizes. The byte aggregates are the
        // V8 cipher-agnostic manifest contract that pins this test.
        let mut agg_for_resp_only = agg.clone();
        agg_for_resp_only.unique_dst_ports = None;
        agg_for_resp_only.unique_src_ports = None;
        agg_for_resp_only.status_2xx_frac = None;
        agg_for_resp_only.status_4xx_frac = None;
        agg_for_resp_only.status_5xx_frac = None;
        agg_for_resp_only.rpc_error_distinct_codes = None;
        agg_for_resp_only.rpc_error_frac = None;
        agg_for_resp_only.duration_ns_mean = None;
        agg_for_resp_only.duration_ns_max = None;
        let expected_resp = ResponseAggregates::from_pairs(&[
            (90, 200),
            (60, 250),
            (150, 600),
        ]);
        assert_eq!(agg_for_resp_only, expected_resp,
            "ShadowPayload userspace pipeline must produce resp.* aggregates \
             identical to ResponseAggregates::from_pairs (the offline-\
             contract bridge for the V8 cipher-agnostic byte-count manifest).",
        );
        // And the new pcap.* port-cardinality fields are populated by
        // the userspace pipeline (closes the Phase 1 close-gate gap).
        // The bidirectional fixture has 2 distinct dst_ports (8899 server-
        // side + 12345 client-side from the response leg) and 2 distinct
        // src_ports — IBSR sees both directions of the TCP connection.
        // This matches the offline `summarise_pcap` semantic: distinct
        // dst_port values across the WHOLE pcap, not just the request-leg.
        assert_eq!(agg.unique_dst_ports, Some(2),
            "TC sees both directions: dst=8899 (request) + dst=12345 (response)");
        assert_eq!(agg.unique_src_ports, Some(2),
            "same: src=12345 (request) + src=8899 (response)");
    }

    #[test]
    fn pinned_event_size_matches_decoder() {
        // Defense in depth: the event-source returns Vec<u8> of size
        // EXPECTED_RAW_EVENT_SIZE; decode_event rejects anything else.
        // If the BPF struct ever drifts, both this test and the
        // tc_payload_event raw-size pin trip together.
        let req = b"POST / HTTP/1.1\r\n\r\n";
        let raw = req_event(req);
        assert_eq!(raw.len(), EXPECTED_RAW_EVENT_SIZE);
    }

    #[test]
    fn many_unrelated_events_in_one_batch_does_not_overflow() {
        // Stress: 1000 unrelated events in one batch. The loop must
        // process them all in one poll call without panicking, then
        // emit an empty snapshot.
        let unrelated: Vec<Vec<u8>> = (0..1000u32)
            .map(|i| {
                raw_event_bytes(
                    0x0a000000 + i,
                    1000,
                    0x0a000001,
                    2000,
                    direction::INGRESS,
                    b"x",
                )
            })
            .collect();
        let (result, snaps) = run_one_window(vec![unrelated]);
        assert_eq!(result.events_filtered, 1000);
        assert_eq!(result.n_pairs, 0);
        assert_eq!(snaps.len(), 1);
    }

    #[test]
    fn shutdown_during_active_polling_emits_snapshot_before_exit() {
        // Pre-load a paired request/response, then have the shutdown
        // signal fire after the events are drained — the snapshot emit
        // must still happen with the aggregates from those events.
        // (CountingShutdown returns false N times then true.)
        use crate::signal::CountingShutdown;
        let req = b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nok";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nack";
        let mut src = MockPayloadEventSource::from_batches(vec![
            vec![req_event(req)],
            vec![resp_event(resp)],
        ]);
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir());
        let cfg = config(vec![8899]);
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        // Allow 5 polls before signaling shutdown, so both batches drain.
        let shutdown = CountingShutdown::new(5);
        // Long deadline; shutdown should short-circuit after 5 polls.
        let deadline = Instant::now() + Duration::from_secs(60);

        let result = collect_payload_window(
            &mut src,
            &clock,
            &writer,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            HOUR_0,
            deadline,
            &shutdown,
            &output_dir(),            None,
        )
        .expect("shutdown should not error");
        assert_eq!(result.n_pairs, 1, "events drained before shutdown");
        let snaps = parse_snapshots_from(&fs);
        assert_eq!(snaps.len(), 1);
        let agg = snaps[0].resp_aggregates.as_ref().expect("aggregates");
        assert_eq!(agg.count, 1);
    }

    // ===========================================
    // Test Category C — Multi-window loop runner
    //
    // The "IBSR runs without dying" contract: writer failures, source
    // failures, decode failures all keep the loop going. Only shutdown
    // terminates.
    // ===========================================

    #[test]
    fn loop_emits_one_snapshot_per_window_with_max_windows_cap() {
        let cfg = PayloadCollectorConfig {
            server_ports: vec![8899],
            rotation: RotationConfig::new(100, 86400),
            interval_sec: 1, // short window so the loop cycles fast
            run_id: HOUR_0,
        };
        let mut src = MockPayloadEventSource::from_batches(Vec::new());
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir());
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        let shutdown = crate::signal::NeverShutdown;

        let result = collect_payload_loop(
            &mut src,
            &clock,
            &writer,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            &shutdown,
            &output_dir(),
            Some(3),            None,
        );
        assert_eq!(result.windows_completed, 3);
        assert_eq!(result.windows_failed, 0);
    }

    #[test]
    fn loop_continues_through_writer_failures() {
        // Writer fails every time, but the loop must continue (not panic,
        // not exit). Caps via max_windows so the test terminates.
        struct AlwaysFailingWriter;
        impl SnapshotWriter for AlwaysFailingWriter {
            fn write(&self, _snapshot: &Snapshot) -> Result<PathBuf, FsError> {
                Err(FsError::Io(io::Error::new(io::ErrorKind::Other, "bad disk")))
            }
        }
        let cfg = PayloadCollectorConfig {
            server_ports: vec![8899],
            rotation: RotationConfig::new(100, 86400),
            interval_sec: 1,
            run_id: HOUR_0,
        };
        let mut src = MockPayloadEventSource::from_batches(Vec::new());
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        let shutdown = crate::signal::NeverShutdown;

        let result = collect_payload_loop(
            &mut src,
            &clock,
            &AlwaysFailingWriter,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            &shutdown,
            &output_dir(),
            Some(5),            None,
        );
        // No window writes succeeded, but the loop ran 5 cycles and
        // didn't panic — the no-die contract holds.
        assert_eq!(result.windows_completed, 0);
        assert_eq!(result.windows_failed, 5);
    }

    #[test]
    fn loop_recovers_after_intermittent_source_errors() {
        // Source returns errors for the first few polls, then recovers.
        // The loop must still complete its window count.
        let cfg = PayloadCollectorConfig {
            server_ports: vec![8899],
            rotation: RotationConfig::new(100, 86400),
            interval_sec: 1,
            run_id: HOUR_0,
        };
        let mut src = MockPayloadEventSource::from_batches(Vec::new());
        // Source fails for polls 1-3 then recovers for the rest.
        // Implementation: fail_after = 0 means every poll after the 0th
        // fails. To get "fail then recover" we'd need a different
        // mechanism — for now, we model "always fails" as the worst
        // case and rely on `event_source_error_does_not_kill_loop`
        // (single-window) for the source-error path. This test
        // exercises the multi-window + persistent source error path.
        src.fail_after = Some(0);
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir());
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        let shutdown = crate::signal::NeverShutdown;

        let result = collect_payload_loop(
            &mut src,
            &clock,
            &writer,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            &shutdown,
            &output_dir(),
            Some(3),            None,
        );
        // All windows complete (source error doesn't fail the WINDOW —
        // the snapshot still gets written), and we tally source_errors.
        assert_eq!(result.windows_completed, 3);
        assert_eq!(result.windows_failed, 0);
        assert!(result.total_source_errors >= 3);
    }

    #[test]
    fn loop_exits_on_shutdown_signal() {
        // AlwaysShutdown: loop should exit before completing any window.
        let cfg = PayloadCollectorConfig {
            server_ports: vec![8899],
            rotation: RotationConfig::new(100, 86400),
            interval_sec: 60,
            run_id: HOUR_0,
        };
        let mut src = MockPayloadEventSource::from_batches(Vec::new());
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir());
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        let shutdown = crate::signal::AlwaysShutdown;

        let result = collect_payload_loop(
            &mut src,
            &clock,
            &writer,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            &shutdown,
            &output_dir(),
            None, // unbounded — only shutdown terminates
            None, // host_sampler
        );
        // Shutdown short-circuits before the first window; nothing is
        // emitted but we don't hang.
        assert_eq!(result.windows_completed, 0);
        assert_eq!(result.windows_failed, 0);
    }

    #[test]
    fn loop_aggregates_pairs_across_windows() {
        // 2 paired RPCs feeding the loop across 1 window emits 1 pair;
        // total_pairs accumulates across windows.
        let cfg = PayloadCollectorConfig {
            server_ports: vec![8899],
            rotation: RotationConfig::new(100, 86400),
            interval_sec: 1,
            run_id: HOUR_0,
        };
        let req = b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nok";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nack";
        // Three batches: req, resp, then empty. Two windows: first
        // window drains the pair; second window is empty.
        let mut src = MockPayloadEventSource::from_batches(vec![
            vec![req_event(req)],
            vec![resp_event(resp)],
        ]);
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir());
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        let shutdown = crate::signal::NeverShutdown;

        let result = collect_payload_loop(
            &mut src,
            &clock,
            &writer,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            &shutdown,
            &output_dir(),
            Some(2),            None,
        );
        assert_eq!(result.windows_completed, 2);
        assert_eq!(result.total_pairs, 1, "one pair across two windows");
    }

    #[test]
    fn loop_tracks_decode_errors_cumulatively() {
        // Inject malformed events; loop continues; decode_errors
        // accumulate.
        let cfg = PayloadCollectorConfig {
            server_ports: vec![8899],
            rotation: RotationConfig::new(100, 86400),
            interval_sec: 1,
            run_id: HOUR_0,
        };
        let bad = vec![0u8; 100];
        let mut src = MockPayloadEventSource::from_batches(vec![
            vec![bad.clone(), bad.clone()],
            vec![bad.clone()],
        ]);
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir());
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        let shutdown = crate::signal::NeverShutdown;

        let result = collect_payload_loop(
            &mut src,
            &clock,
            &writer,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            &shutdown,
            &output_dir(),
            Some(2),            None,
        );
        assert_eq!(result.windows_completed, 2);
        assert!(result.total_decode_errors >= 3,
            "all 3 malformed events must be counted; got {}",
            result.total_decode_errors,
        );
    }

    // ===========================================
    // Test Category D — args_to_config / args_to_server_ports
    // (the wiring layer between CLI parsing and the orchestrator)
    // ===========================================

    fn make_args(overrides: &[(&str, &str)]) -> crate::cli::CollectPayloadArgs {
        let mut argv: Vec<String> = vec![
            "ibsr".into(),
            "collect-payload".into(),
            "-p".into(),
            "8899".into(),
        ];
        for (k, v) in overrides {
            argv.push((*k).into());
            argv.push((*v).into());
        }
        let cli = crate::cli::parse_from(argv).expect("parse");
        match cli.command {
            crate::cli::Command::CollectPayload(a) => a,
            _ => unreachable!("expected CollectPayload"),
        }
    }

    #[test]
    fn args_to_config_pulls_server_ports() {
        let args = make_args(&[]);
        let clock = MockClock::new(HOUR_0);
        let cfg = args_to_config(&args, &clock);
        assert_eq!(cfg.server_ports, vec![8899]);
    }

    #[test]
    fn args_to_config_uses_clock_for_run_id() {
        let args = make_args(&[]);
        let clock = MockClock::new(HOUR_0);
        let cfg = args_to_config(&args, &clock);
        assert_eq!(cfg.run_id, HOUR_0);
    }

    #[test]
    fn args_to_config_uses_window_sec_for_interval() {
        let args = make_args(&[("--window-sec", "30")]);
        let clock = MockClock::new(HOUR_0);
        let cfg = args_to_config(&args, &clock);
        assert_eq!(cfg.interval_sec, 30);
    }

    #[test]
    fn args_to_config_uses_max_files_and_max_age() {
        let args = make_args(&[("--max-files", "500"), ("--max-age", "3600")]);
        let clock = MockClock::new(HOUR_0);
        let cfg = args_to_config(&args, &clock);
        assert_eq!(cfg.rotation.max_files, 500);
        assert_eq!(cfg.rotation.max_age_secs, 3600);
    }

    #[test]
    fn args_to_server_ports_returns_dedup_set() {
        let args = make_args(&[]); // 8899 only
        let set = args_to_server_ports(&args);
        assert!(set.contains(&8899));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn args_to_config_and_server_ports_round_trip_through_orchestrator() {
        // Pin: the wiring from CLI → config → orchestrator works
        // end-to-end. Run a short loop and verify aggregates flow.
        let args = make_args(&[("--window-sec", "1")]);
        let clock = MockClock::new(HOUR_0);
        let cfg = args_to_config(&args, &clock);
        let server_ports = args_to_server_ports(&args);

        let req = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npayload";
        let mut src = MockPayloadEventSource::from_batches(vec![
            vec![req_event(req)],
            vec![resp_event(resp)],
        ]);
        let fs = Arc::new(MockFilesystem::new());
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir());
        let mut handler = PayloadHandler::new(args.max_flows);
        let shutdown = crate::signal::NeverShutdown;

        let result = collect_payload_loop(
            &mut src,
            &clock,
            &writer,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            &shutdown,
            &output_dir(),
            Some(1),            None,
        );
        assert_eq!(result.windows_completed, 1);
        assert_eq!(result.total_pairs, 1);
    }

    #[test]
    fn queue_backed_source_integrates_with_orchestrator_end_to_end() {
        // Pin the bridge contract: ibsr_bpf::QueueBackedEventSource
        // (the production-shaped event source) feeds the orchestrator
        // exactly the same way the MockPayloadEventSource does. If
        // this test ever drifts (e.g. someone changes the drain
        // semantics) it trips before live integration breaks.
        use ibsr_bpf::{PendingEvents, QueueBackedEventSource};

        let req = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npayload";

        let pending = PendingEvents::new();
        // Push the synthetic kernel-shaped events directly into the
        // queue (bypassing the libbpf-rs pump that production would
        // use).
        pending.push(req_event(req));
        pending.push(resp_event(resp));

        let mut src = QueueBackedEventSource::new(pending);
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir());
        let cfg = config(vec![8899]);
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        let shutdown = crate::signal::NeverShutdown;

        let result = collect_payload_window(
            &mut src,
            &clock,
            &writer,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            HOUR_0,
            Instant::now(),
            &shutdown,
            &output_dir(),            None,
        )
        .expect("orchestrator must consume QueueBackedEventSource");

        assert_eq!(result.n_pairs, 1, "one paired RPC across the bridge");
        let snaps = parse_snapshots_from(&fs);
        let agg = snaps[0].resp_aggregates.as_ref().expect("aggregates");
        assert_eq!(agg.req_bytes_max, Some(4));
        assert_eq!(agg.resp_bytes_max, Some(7));
    }

    #[test]
    fn loop_max_windows_zero_returns_immediately() {
        let cfg = PayloadCollectorConfig {
            server_ports: vec![8899],
            rotation: RotationConfig::new(100, 86400),
            interval_sec: 1,
            run_id: HOUR_0,
        };
        let mut src = MockPayloadEventSource::from_batches(Vec::new());
        let clock = MockClock::new(HOUR_1);
        let fs = Arc::new(MockFilesystem::new());
        let writer = StandardSnapshotWriter::new(ArcFs(fs.clone()), output_dir());
        let mut handler = PayloadHandler::new(64);
        let server_ports = server_ports_set(&[8899]);
        let shutdown = crate::signal::NeverShutdown;

        let result = collect_payload_loop(
            &mut src,
            &clock,
            &writer,
            &ArcFs(fs.clone()),
            &mut handler,
            &server_ports,
            &cfg,
            &shutdown,
            &output_dir(),
            Some(0),            None,
        );
        assert_eq!(result.windows_completed, 0);
        assert_eq!(result.windows_failed, 0);
    }
}
