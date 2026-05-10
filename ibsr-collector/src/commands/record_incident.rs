//! Record-incident-mode command orchestration.
//!
//! Wires the validated `RecordIncidentArgs` through a
//! `RecordIncidentAttacher` (the BPF-loader / TC-attach abstraction)
//! into the inner `record_incident_loop` (ringbuf → decode → pcap-
//! write). The attacher trait + event-source trait are mocked in
//! tests so the full command path is exercisable without a kernel;
//! the production attacher (libbpf-rs adapter from
//! `ibsr_bpf::LibbpfRecordIncidentCollector`) lands as the only
//! kernel-bound piece.

use std::path::PathBuf;
use std::time::Duration;

use ibsr_bpf::decode_packet_event;
use ibsr_clock::Clock;
use ibsr_fs::Filesystem;

use crate::cli::RecordIncidentArgs;
use crate::logger::Logger;
use crate::pcap::{ts_ns_to_sec_usec, PacketSink};
use crate::scrub::{apply_scrub, ScrubConfig, ScrubOutcome};
use crate::signal::ShutdownCheck;
use crate::trigger_socket::{
    check_auto_stop, process_request, ConfigMutator, PendingRequest, TriggerState,
};

use super::{collect_payload::AttachError, CommandError, CommandResult};

/// Source of decoded packet events. The attacher returns a value
/// implementing this trait. Production's `LibbpfRecordIncidentCollector`
/// is wrapped by an adapter in `main.rs`; tests use
/// `MockPacketEventSource`.
pub trait PacketEventSource {
    /// Pump the underlying kernel ringbuf for at most `timeout`,
    /// pushing decoded ringbuf records into an internal buffer that
    /// `drain_events` returns.
    fn poll(&mut self, timeout: Duration) -> Result<(), String>;

    /// Drain all currently-buffered raw event bytes (one Vec<u8> per
    /// kernel ringbuf record).
    fn drain_events(&mut self) -> Vec<Vec<u8>>;
}

/// Initial attach-time configuration. Mirrors the four slots of the
/// kernel-side `config_map`. `sampling_active` is true for the
/// always-record Phase 2 mode; Phase 3's trigger socket flips it at
/// runtime.
#[derive(Debug, Clone)]
pub struct AttachConfig {
    pub iface: String,
    pub sample_rate: u64,
    pub sampling_active: bool,
    pub incident_tag: String,
    pub trigger_timestamp_unix_sec: u64,
}

/// Attacher for the record-incident BPF program.
pub trait RecordIncidentAttacher {
    /// Event source produced after a successful attach.
    type Source: PacketEventSource;

    /// Load the BPF program, attach TC ingress + egress on
    /// `cfg.iface`, program the per-CPU sampler at `cfg.sample_rate`,
    /// and write the four `config_map` slots from `cfg`. On failure,
    /// partial state is unwound before returning.
    fn attach(self, cfg: &AttachConfig) -> Result<Self::Source, AttachError>;
}

/// Outcome of `execute_record_incident`.
#[derive(Debug)]
pub struct RecordIncidentResult {
    pub run_dir: PathBuf,
    pub pcap_path: PathBuf,
    pub events_written: u64,
    pub events_decode_errors: u64,
    pub events_write_errors: u64,
    pub poll_errors: u64,
    pub rotations: u64,
    pub events_scrubbed: u64,
}

/// Default ringbuf-poll timeout. Short enough that shutdown signals
/// are responsive; long enough to amortise the syscall.
const POLL_TIMEOUT: Duration = Duration::from_millis(200);

/// Inner loop. Takes a writer (generic over `Write`) so unit tests
/// pin the exact pcap bytes a real run would have flushed.
///
/// `request_rx` is the orchestrator-side endpoint of the trigger
/// socket queue (Phase 3). When `None`, no trigger-socket dispatch
/// happens. `mutator` is the kernel config_map handle the orchestrator
/// uses to apply trigger commands and auto-stops; pass `None` when
/// `request_rx` is also `None` (Phase 1/2 static-rate mode).
///
/// `state` is the canonical session state — owned by the orchestrator
/// so the listener thread doesn't need a Mutex around it.
///
/// Returns counts of events written / decoded-with-error / write-
/// errors / poll-errors. Per the IBSR "runs without dying" contract,
/// runtime errors do not propagate — they're logged and counted.
/// Emitter for record-incident status.jsonl heartbeat lines.
/// Implementations append one JSON line per call. Mirrors the
/// pattern used by `collect` / `collect-payload`'s status writers but
/// with a record-incident-shaped payload (events_written / rotations
/// / scrubbed instead of ips_collected).
pub trait StatusEmitter {
    fn emit(&mut self, line: &str);
}

/// Build a status.jsonl line for record-incident. Pure function so
/// the JSON shape is testable.
pub fn build_status_line(
    ts_unix_sec: u64,
    cycle: u64,
    stats: &RecordIncidentLoopStats,
) -> String {
    format!(
        "{{\"timestamp\":{},\"cycle\":{},\"events_written\":{},\"events_decode_errors\":{},\
\"events_write_errors\":{},\"events_scrubbed\":{},\"rotations\":{},\
\"size_driven_rotations\":{},\"poll_errors\":{},\"archived\":{},\"archive_errors\":{}}}",
        ts_unix_sec,
        cycle,
        stats.events_written,
        stats.events_decode_errors,
        stats.events_write_errors,
        stats.events_scrubbed,
        stats.rotations,
        stats.size_driven_rotations,
        stats.poll_errors,
        stats.archived,
        stats.archive_errors,
    )
}

/// `StatusEmitter` backed by the `Filesystem::append_atomic` API. The
/// production wiring uses `RealFilesystem`; tests use
/// `MockFilesystem`.
pub struct FsStatusEmitter<F: Filesystem> {
    fs: F,
    path: PathBuf,
}

impl<F: Filesystem> FsStatusEmitter<F> {
    pub fn new(fs: F, path: PathBuf) -> Self {
        Self { fs, path }
    }
}

impl<F: Filesystem> StatusEmitter for FsStatusEmitter<F> {
    fn emit(&mut self, line: &str) {
        let mut buf = line.to_string();
        buf.push('\n');
        // Lossy-by-design: a status-write failure must not stall the
        // recording loop. Errors are dropped (the verbose log is the
        // operator's tap into pcap-write failures, status is just a
        // heartbeat).
        let _ = self.fs.append_atomic(&self.path, buf.as_bytes());
    }
}

/// Phase 6 retention configuration.
#[derive(Debug, Clone, Default)]
pub struct RetentionConfig {
    /// When set, the loop tracks bytes-per-current-pcap and rotates
    /// whenever it would exceed this cap.
    pub max_pcap_bytes: Option<u64>,
    /// Archive sweeper config. `None` = no archiving.
    pub archive: Option<ArchiveConfig>,
}

#[derive(Debug, Clone)]
pub struct ArchiveConfig {
    pub out_dir: PathBuf,
    pub archive_dir: PathBuf,
    /// Files older than this are archived.
    pub min_age_sec: u64,
    /// How often to run the sweep tick. Tests pass small values;
    /// production defaults to ≥ 60s.
    pub sweep_interval_sec: u64,
}

pub fn record_incident_loop<S, C, H, L>(
    source: &mut S,
    sink: &mut dyn PacketSink,
    clock: &C,
    shutdown: &H,
    logger: &L,
    deadline_sec: Option<u64>,
    boot_anchor_ns: i128,
    mut state: Option<&mut TriggerState>,
    request_rx: Option<&std::sync::mpsc::Receiver<PendingRequest>>,
    scrub: &ScrubConfig,
    retention: &RetentionConfig,
    status: Option<(&mut dyn StatusEmitter, u64)>,
) -> RecordIncidentLoopStats
where
    S: PacketEventSource + ConfigMutator,
    C: Clock,
    H: ShutdownCheck,
    L: Logger,
{
    let (mut status_emitter, status_interval_sec) = match status {
        Some((e, n)) if n > 0 => (Some(e), n),
        _ => (None, 0u64),
    };
    let mut last_status_sec: u64 = 0;
    let mut cycle: u64 = 0;
    let mut stats = RecordIncidentLoopStats::default();
    // Bytes written to the current pcap segment. Reset on every
    // rotation (size-driven OR trigger-driven).
    let mut current_bytes: u64 = 0;
    // Last archive sweep timestamp. The sweeper fires when
    // `now - last_archive_sec >= sweep_interval_sec`.
    let mut last_archive_sec: u64 = 0;

    loop {
        if shutdown.should_stop() {
            break;
        }
        if let Some(deadline) = deadline_sec {
            if clock.now_unix_sec() >= deadline {
                break;
            }
        }

        // status.jsonl heartbeat. Once per status_interval_sec ticks.
        // Lossy by design — emitter failures don't stall the loop.
        if let Some(emitter) = status_emitter.as_deref_mut() {
            let now = clock.now_unix_sec();
            if now.saturating_sub(last_status_sec) >= status_interval_sec {
                cycle += 1;
                let line = build_status_line(now, cycle, &stats);
                emitter.emit(&line);
                last_status_sec = now;
            }
        }

        // Phase 6: archive sweeper tick.
        if let Some(archive_cfg) = &retention.archive {
            let now = clock.now_unix_sec();
            if now.saturating_sub(last_archive_sec) >= archive_cfg.sweep_interval_sec {
                let pass = crate::archive::archive_pass(
                    &archive_cfg.out_dir,
                    &archive_cfg.archive_dir,
                    archive_cfg.min_age_sec,
                    now,
                );
                stats.archived += pass.archived;
                stats.archive_errors += pass.errors;
                if pass.archived > 0 || pass.errors > 0 {
                    logger.info(&format!(
                        "archive sweep: {} files moved to {}, {} errors",
                        pass.archived,
                        archive_cfg.archive_dir.display(),
                        pass.errors,
                    ));
                }
                last_archive_sec = now;
            }
        }

        // Drain trigger-socket commands first so a `stop` is honored
        // before more events are recorded. Both `state` and
        // `request_rx` must be present for any dispatch — the
        // orchestrator's `source` is also the `ConfigMutator` (the
        // libbpf collector implements both).
        if let (Some(rx), Some(state_ref)) = (request_rx, state.as_deref_mut()) {
            let now = clock.now_unix_sec();
            // Reborrow source immutably for the apply_command path
            // — only one immutable borrow lives at a time, and the
            // mutable borrow for `source.poll` resumes after this
            // block.
            while let Ok(req) = rx.try_recv() {
                // Snapshot pre-state so we can detect a Trigger
                // command's tag/ts change and rotate the pcap.
                let pre_tag = state_ref.incident_tag.clone();
                let pre_ts = state_ref.trigger_ts_unix_sec;
                process_request(req, state_ref, &*source, now);
                let rotated = pre_tag != state_ref.incident_tag
                    || pre_ts != state_ref.trigger_ts_unix_sec;
                if rotated {
                    let tag = state_ref.incident_tag.clone();
                    let ts = state_ref.trigger_ts_unix_sec;
                    match sink.rotate(&tag, ts) {
                        Ok(Some(new_path)) => {
                            stats.rotations += 1;
                            current_bytes = 0;
                            logger.info(&format!(
                                "rotated pcap to {} on trigger",
                                new_path.display(),
                            ));
                        }
                        Ok(None) => {} // sink doesn't rotate
                        Err(e) => {
                            stats.rotation_errors += 1;
                            logger.verbose(&format!(
                                "pcap rotation failed: {} (continuing on previous file)",
                                e,
                            ));
                        }
                    }
                }
            }
            check_auto_stop(state_ref, &*source, now);
        }

        if let Err(e) = source.poll(POLL_TIMEOUT) {
            stats.poll_errors += 1;
            logger.verbose(&format!("ringbuf poll error: {} (continuing)", e));
        }

        for raw in source.drain_events() {
            match decode_packet_event(&raw) {
                Ok(ev) => {
                    let (sec, usec) = ts_ns_to_sec_usec(ev.ts_ns, boot_anchor_ns);
                    let pkt_to_write = match apply_scrub(&ev.pkt, scrub) {
                        ScrubOutcome::Pass(bytes) => bytes,
                        ScrubOutcome::Drop => {
                            stats.events_scrubbed += 1;
                            continue;
                        }
                    };
                    match sink.write_packet(sec, usec, ev.wire_len, &pkt_to_write) {
                        Ok(()) => {
                            stats.events_written += 1;
                            // pcap record header (16) + packet bytes
                            current_bytes = current_bytes
                                .saturating_add(16 + pkt_to_write.len() as u64);

                            // Phase 6: size-driven rotation. Once the
                            // segment exceeds max_pcap_bytes, force a
                            // rotation. We re-use the current tag/ts
                            // (state_ref or fall back to clock-now).
                            if let Some(max) = retention.max_pcap_bytes {
                                if current_bytes >= max {
                                    let now = clock.now_unix_sec();
                                    let (tag, ts) = match &state {
                                        Some(s) => (s.incident_tag.clone(), now),
                                        None => ("rotation".to_string(), now),
                                    };
                                    match sink.rotate(&tag, ts) {
                                        Ok(Some(new_path)) => {
                                            stats.rotations += 1;
                                            stats.size_driven_rotations += 1;
                                            logger.info(&format!(
                                                "rotated pcap to {} after {} bytes (max={})",
                                                new_path.display(),
                                                current_bytes,
                                                max,
                                            ));
                                            current_bytes = 0;
                                        }
                                        Ok(None) => {
                                            // sink doesn't rotate — reset
                                            // counter so we don't log on
                                            // every subsequent write.
                                            current_bytes = 0;
                                        }
                                        Err(e) => {
                                            stats.rotation_errors += 1;
                                            logger.verbose(&format!(
                                                "size-driven rotation failed: {} (continuing)",
                                                e,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            stats.events_write_errors += 1;
                            logger.verbose(&format!("pcap write error: {} (continuing)", e));
                        }
                    }
                }
                Err(e) => {
                    stats.events_decode_errors += 1;
                    logger.verbose(&format!("decode error: {} (continuing)", e));
                }
            }
        }
    }

    stats
}

/// Loop-result counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RecordIncidentLoopStats {
    pub events_written: u64,
    pub events_decode_errors: u64,
    pub events_write_errors: u64,
    pub poll_errors: u64,
    pub rotations: u64,
    pub rotation_errors: u64,
    /// Phase 5: events scrubbed-and-dropped.
    pub events_scrubbed: u64,
    /// Phase 6: rotations driven by --max-pcap-bytes (subset of
    /// `rotations`).
    pub size_driven_rotations: u64,
    /// Phase 6: files moved to archive_dir.
    pub archived: u64,
    /// Phase 6: archive failures (per-file; aggregated).
    pub archive_errors: u64,
}

/// Format the per-run output directory name. `{tag}-{unix_ts}` —
/// chosen for readability + sortability + filesystem-safety. Pure
/// function so tests pin the exact name.
pub fn format_run_dir_name(tag: &str, ts_unix: u64) -> String {
    format!("{}-{}", tag, ts_unix)
}

/// Read the wall-clock and monotonic-clock simultaneously and compute
/// the boot anchor (`unix_ns - monotonic_ns`) used to convert kernel
/// `bpf_ktime_get_ns()` timestamps into pcap wall-clock timestamps.
///
/// Production-only; tests pass a canned anchor to `record_incident_loop`.
pub fn compute_boot_anchor_now() -> std::io::Result<i128> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let real = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let mono = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let unix_ns: u64 =
        real.as_secs() * 1_000_000_000 + (real.subsec_nanos() as u64);
    let mono_ns: u64 =
        (mono.tv_sec() as u64) * 1_000_000_000 + (mono.tv_nsec() as u64);
    Ok(crate::pcap::compute_boot_anchor_ns(unix_ns, mono_ns))
}

/// Optional Phase-3 trigger-socket inputs threaded through to the
/// record-incident loop. Passing `None` runs in static-rate mode
/// (Phase 1 / Phase 2 default).
pub struct TriggerInputs<'a> {
    pub state: &'a mut TriggerState,
    pub request_rx: &'a std::sync::mpsc::Receiver<PendingRequest>,
}

/// Execute the record-incident subcommand.
///
/// The caller pre-opens a `PacketSink` so this function is fully
/// testable; production wires `RotatingPcapSink` over real files
/// (see `main.rs::run_record_incident`).
///
/// `pcap_path` is the initial sink target — used purely for logging +
/// the `RecordIncidentResult` field. Phase 4's rotation is opaque to
/// this function; it watches via the loop's stats.
pub fn execute_record_incident<A, C, F, H, L>(
    args: &RecordIncidentArgs,
    attacher: A,
    clock: &C,
    fs: &F,
    shutdown: &H,
    logger: &L,
    sink: &mut dyn PacketSink,
    pcap_path: PathBuf,
    boot_anchor_ns: i128,
    triggers: Option<TriggerInputs<'_>>,
) -> CommandResult<RecordIncidentResult>
where
    A: RecordIncidentAttacher,
    A::Source: ConfigMutator,
    C: Clock,
    F: Filesystem + Clone,
    H: ShutdownCheck,
    L: Logger,
{
    args.validate()?;

    let scrub_cfg = build_scrub_config(args)
        .map_err(|e| CommandError::NotImplemented(format!("scrub config: {}", e)))?;
    let retention_cfg = build_retention_config(args);

    let run_ts = clock.now_unix_sec();
    let run_dir_name = format_run_dir_name(&args.tag, run_ts);
    let run_dir = args.out_dir.join(&run_dir_name);
    fs.create_dir_all(&run_dir)?;

    logger.verbose(&format!(
        "Starting record-incident: iface={}, sample_rate={}, tag={}, out={}",
        args.iface,
        args.sample_rate,
        args.tag,
        run_dir.display(),
    ));

    let cfg = AttachConfig {
        iface: args.iface.clone(),
        sample_rate: args.sample_rate,
        sampling_active: true, // Phase 2 default; Phase 3 trigger flips at runtime
        incident_tag: args.tag.clone(),
        trigger_timestamp_unix_sec: run_ts,
    };

    let mut source = attacher
        .attach(&cfg)
        .map_err(|e| CommandError::NotImplemented(format!("attach failed: {}", e)))?;

    logger.info(&format!(
        "record-incident attached: iface='{}', sample-rate=1-in-{}, output={}",
        args.iface,
        args.sample_rate,
        pcap_path.display(),
    ));

    let deadline_sec = args
        .duration_sec
        .map(|d| run_ts.saturating_add(d));

    let (state_opt, rx_opt) = match triggers {
        Some(t) => (Some(t.state), Some(t.request_rx)),
        None => (None, None),
    };

    // Status heartbeat. Writes to {run_dir}/status.jsonl every
    // args.status_interval_sec via the Filesystem trait — so unit
    // tests using MockFilesystem can inspect the heartbeat lines
    // alongside the run dir.
    let status_path = run_dir.join("status.jsonl");
    let mut status_emitter = FsStatusEmitter::new(fs.clone(), status_path);
    let status_input: Option<(&mut dyn StatusEmitter, u64)> =
        Some((&mut status_emitter, args.status_interval_sec));

    let stats = record_incident_loop(
        &mut source,
        sink,
        clock,
        shutdown,
        logger,
        deadline_sec,
        boot_anchor_ns,
        state_opt,
        rx_opt,
        &scrub_cfg,
        &retention_cfg,
        status_input,
    );

    if let Err(e) = sink.flush() {
        logger.verbose(&format!("final pcap flush failed: {} (Drop will retry)", e));
    }

    logger.info(&format!(
        "record-incident finished: {} events written, {} decode errors, {} write errors, {} poll errors, {} rotations",
        stats.events_written,
        stats.events_decode_errors,
        stats.events_write_errors,
        stats.poll_errors,
        stats.rotations,
    ));

    Ok(RecordIncidentResult {
        run_dir,
        pcap_path,
        events_written: stats.events_written,
        events_decode_errors: stats.events_decode_errors,
        events_write_errors: stats.events_write_errors,
        poll_errors: stats.poll_errors,
        rotations: stats.rotations,
        events_scrubbed: stats.events_scrubbed,
    })
}

/// Translate the CLI retention flags into a `RetentionConfig`. Pure
/// function — no I/O, all field shuffling.
pub fn build_retention_config(args: &RecordIncidentArgs) -> RetentionConfig {
    let archive = args.archive_dir.as_ref().map(|dir| ArchiveConfig {
        out_dir: args.out_dir.clone(),
        archive_dir: dir.clone(),
        min_age_sec: args.archive_after_sec,
        // Sweep at most every 30 seconds — fine-grained enough for
        // the 1-hour default min_age_sec.
        sweep_interval_sec: 30,
    });
    RetentionConfig {
        max_pcap_bytes: args.max_pcap_bytes,
        archive,
    }
}

/// Translate the CLI scrub flags into a `ScrubConfig`. Pure-ish — only
/// the parsing fns from `crate::scrub` plus string handling. Errors
/// surface as a single string suitable for `CommandError::NotImplemented`.
pub fn build_scrub_config(args: &RecordIncidentArgs) -> Result<ScrubConfig, String> {
    let ip_salt = match &args.scrub_ip_salt {
        Some(s) => Some(crate::scrub::parse_ip_salt(s).map_err(|e| e.to_string())?),
        None => None,
    };
    let internal_subnet = match &args.scrub_internal_subnet {
        Some(s) => Some(crate::scrub::parse_subnet(s).map_err(|e| e.to_string())?),
        None => None,
    };
    Ok(ScrubConfig {
        ip_salt,
        internal_subnet,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{parse_from, Command};
    use crate::logger::NullLogger;
    use crate::signal::{AlwaysShutdown, NeverShutdown};
    use crate::pcap::{PcapWriter, SimplePacketSink};
    use ibsr_bpf::{record_direction, RawPacketEvent, RECORD_SNAPLEN_BYTES};
    use ibsr_clock::MockClock;
    use std::collections::VecDeque;

    const HOUR_0: u64 = 1_704_067_200;

    fn parse_args(argv: &[&str]) -> RecordIncidentArgs {
        let cli = parse_from(argv).expect("parse");
        match cli.command {
            Command::RecordIncident(a) => a,
            _ => panic!("expected RecordIncident"),
        }
    }

    /// Build a raw ringbuf record (the same byte layout the kernel
    /// would produce). Mirrors the helper used in collect_payload's
    /// tests.
    fn raw_packet_event(
        direction: u32,
        wire_len: u32,
        cap_len: u32,
        ts_ns: u64,
        fill: u8,
    ) -> Vec<u8> {
        let mut ev = RawPacketEvent {
            ts_ns,
            ifindex: 1,
            direction,
            wire_len,
            cap_len,
            pkt: [0u8; RECORD_SNAPLEN_BYTES],
        };
        for i in 0..(cap_len as usize).min(RECORD_SNAPLEN_BYTES) {
            ev.pkt[i] = fill;
        }
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&ev as *const RawPacketEvent) as *const u8,
                std::mem::size_of::<RawPacketEvent>(),
            )
        };
        bytes.to_vec()
    }

    /// Mock event source: returns batches in order, then empty
    /// forever. Each `poll` call advances one batch.
    ///
    /// Also implements `ConfigMutator` (no-op by default; can be
    /// wired with a recording mutator via `with_mutator` for the
    /// trigger-socket integration tests).
    struct MockPacketEventSource {
        batches: VecDeque<Vec<Vec<u8>>>,
        current: Vec<Vec<u8>>,
        poll_failures: VecDeque<bool>,
        mutator: Option<RecordingMutator>,
    }

    impl MockPacketEventSource {
        fn from_batches(batches: Vec<Vec<Vec<u8>>>) -> Self {
            Self {
                batches: VecDeque::from(batches),
                current: Vec::new(),
                poll_failures: VecDeque::new(),
                mutator: None,
            }
        }

        fn with_poll_failures(mut self, fails: Vec<bool>) -> Self {
            self.poll_failures = VecDeque::from(fails);
            self
        }

        /// Wire a recording mutator. Subsequent `set_config` calls go
        /// through it; tests inspect via `mutator_calls`.
        fn with_mutator(mut self, mutator: RecordingMutator) -> Self {
            self.mutator = Some(mutator);
            self
        }

        /// Snapshot of the recording mutator's calls. Empty if no
        /// mutator was wired.
        fn mutator_calls(&self) -> Vec<(ibsr_bpf::ConfigKey, u64)> {
            self.mutator
                .as_ref()
                .map(|m| m.calls.lock().unwrap().clone())
                .unwrap_or_default()
        }
    }

    impl PacketEventSource for MockPacketEventSource {
        fn poll(&mut self, _timeout: Duration) -> Result<(), String> {
            // Advance one batch; queue any next batch's events into
            // `current` for drain_events to return.
            if let Some(b) = self.batches.pop_front() {
                self.current.extend(b);
            }
            if let Some(true) = self.poll_failures.pop_front() {
                return Err("simulated poll failure".to_string());
            }
            Ok(())
        }

        fn drain_events(&mut self) -> Vec<Vec<u8>> {
            std::mem::take(&mut self.current)
        }
    }

    impl ConfigMutator for MockPacketEventSource {
        fn set_config(
            &self,
            key: ibsr_bpf::ConfigKey,
            value: u64,
        ) -> Result<(), String> {
            if let Some(m) = &self.mutator {
                m.set_config(key, value)
            } else {
                // No-op when no mutator wired — non-trigger-socket
                // tests never invoke this path so this is unreached
                // in practice.
                Ok(())
            }
        }
    }

    /// Mock attacher that returns a pre-canned event source.
    struct CannedAttacher {
        source: MockPacketEventSource,
        last_cfg: std::sync::Arc<std::sync::Mutex<Option<AttachConfig>>>,
    }

    impl CannedAttacher {
        fn new(batches: Vec<Vec<Vec<u8>>>) -> Self {
            Self {
                source: MockPacketEventSource::from_batches(batches),
                last_cfg: std::sync::Arc::new(std::sync::Mutex::new(None)),
            }
        }
    }

    impl RecordIncidentAttacher for CannedAttacher {
        type Source = MockPacketEventSource;
        fn attach(self, cfg: &AttachConfig) -> Result<Self::Source, AttachError> {
            *self.last_cfg.lock().unwrap() = Some(cfg.clone());
            Ok(self.source)
        }
    }

    /// Mock attacher that always fails.
    struct FailingAttacher(AttachError);
    impl RecordIncidentAttacher for FailingAttacher {
        type Source = MockPacketEventSource;
        fn attach(self, _cfg: &AttachConfig) -> Result<Self::Source, AttachError> {
            Err(self.0)
        }
    }

    #[test]
    fn record_loop_writes_one_event() {
        let raw = raw_packet_event(record_direction::INGRESS, 100, 50, 1_000_000_000, 0xab);
        let mut source = MockPacketEventSource::from_batches(vec![vec![raw]]);
        let buf: Vec<u8> = Vec::new();
        let pcap_writer = PcapWriter::new(buf, RECORD_SNAPLEN_BYTES as u32).expect("pcap");
        let mut sink = SimplePacketSink::new(pcap_writer, None);
        let clock = MockClock::new(HOUR_0);
        // Shutdown after the first iteration: AlwaysShutdown returns
        // true on the very first check, but we still need one
        // iteration to drain the batch. CountingShutdown isn't
        // strictly needed — the loop checks shutdown FIRST so we'd
        // exit before draining. So set the shutdown to false for one
        // tick then true. Use CountingShutdown(1).
        let shutdown = crate::signal::CountingShutdown::new(2);
        let logger = NullLogger::new();

        // anchor=0 so ts_ns 1_000_000_000 → (1, 0).
        let stats = record_incident_loop(
            &mut source, &mut sink, &clock, &shutdown, &logger,
            None, 0, None, None,
            &ScrubConfig::default(), &RetentionConfig::default(),
            None,
        );

        assert_eq!(stats.events_written, 1);
        assert_eq!(stats.events_decode_errors, 0);
        assert_eq!(stats.events_write_errors, 0);

        let bytes = sink.into_inner();
        // Global header (24) + record header (16) + 50 packet bytes.
        assert_eq!(bytes.len(), 24 + 16 + 50);
        // Verify packet bytes are 0xab.
        assert!(bytes[40..].iter().all(|b| *b == 0xab));
        // Verify timestamp: ts_ns=1e9 + anchor 0 → ts_sec=1, ts_usec=0.
        assert_eq!(u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]), 1);
    }

    #[test]
    fn record_loop_skips_decode_errors_and_continues() {
        // Two events: one valid, one too short.
        let valid = raw_packet_event(record_direction::INGRESS, 100, 50, 0, 0xcd);
        let invalid = vec![0u8; 10];
        let mut source = MockPacketEventSource::from_batches(vec![vec![valid, invalid]]);
        let buf: Vec<u8> = Vec::new();
        let pcap_writer = PcapWriter::new(buf, RECORD_SNAPLEN_BYTES as u32).expect("pcap");
        let mut sink = SimplePacketSink::new(pcap_writer, None);
        let clock = MockClock::new(HOUR_0);
        let shutdown = crate::signal::CountingShutdown::new(2);
        let logger = NullLogger::new();

        let stats = record_incident_loop(
            &mut source, &mut sink, &clock, &shutdown, &logger,
            None, 0, None, None,
            &ScrubConfig::default(), &RetentionConfig::default(),
            None,
        );

        assert_eq!(stats.events_written, 1);
        assert_eq!(stats.events_decode_errors, 1);
    }

    #[test]
    fn record_loop_counts_poll_errors() {
        let mut source = MockPacketEventSource::from_batches(vec![vec![], vec![]])
            .with_poll_failures(vec![true, false]);
        let buf: Vec<u8> = Vec::new();
        let pcap_writer = PcapWriter::new(buf, RECORD_SNAPLEN_BYTES as u32).expect("pcap");
        let mut sink = SimplePacketSink::new(pcap_writer, None);
        let clock = MockClock::new(HOUR_0);
        let shutdown = crate::signal::CountingShutdown::new(3);
        let logger = NullLogger::new();

        let stats = record_incident_loop(
            &mut source, &mut sink, &clock, &shutdown, &logger,
            None, 0, None, None,
            &ScrubConfig::default(), &RetentionConfig::default(),
            None,
        );

        assert_eq!(stats.poll_errors, 1, "one simulated poll failure must be counted");
    }

    #[test]
    fn record_loop_respects_deadline() {
        // deadline = run_ts (already past) — should exit immediately
        // without draining any events.
        let raw = raw_packet_event(record_direction::INGRESS, 100, 50, 0, 0);
        let mut source = MockPacketEventSource::from_batches(vec![vec![raw]]);
        let buf: Vec<u8> = Vec::new();
        let pcap_writer = PcapWriter::new(buf, RECORD_SNAPLEN_BYTES as u32).expect("pcap");
        let mut sink = SimplePacketSink::new(pcap_writer, None);
        let clock = MockClock::new(HOUR_0);
        let shutdown = NeverShutdown;
        let logger = NullLogger::new();

        let stats = record_incident_loop(
            &mut source, &mut sink, &clock, &shutdown, &logger,
            Some(HOUR_0), // deadline = now → exit before processing
            0, None, None,
            &ScrubConfig::default(), &RetentionConfig::default(),
            None,
        );

        assert_eq!(stats.events_written, 0,
            "deadline must short-circuit before any events are drained");
    }

    /// Trivial mutator that records every set_config call. Used by
    /// the trigger-socket integration test below.
    #[derive(Default)]
    struct RecordingMutator {
        calls: std::sync::Mutex<Vec<(ibsr_bpf::ConfigKey, u64)>>,
    }
    impl ConfigMutator for RecordingMutator {
        fn set_config(
            &self,
            key: ibsr_bpf::ConfigKey,
            value: u64,
        ) -> Result<(), String> {
            self.calls.lock().unwrap().push((key, value));
            Ok(())
        }
    }

    #[test]
    fn record_loop_processes_pending_trigger_request() {
        // Drive a `set-sample-rate` request through the loop's
        // request_rx; verify mutator saw the corresponding write.
        let mut source = MockPacketEventSource::from_batches(vec![]);
        let buf: Vec<u8> = Vec::new();
        let pcap_writer = PcapWriter::new(buf, RECORD_SNAPLEN_BYTES as u32).expect("pcap");
        let mut sink = SimplePacketSink::new(pcap_writer, None);
        let clock = MockClock::new(HOUR_0);
        let shutdown = crate::signal::CountingShutdown::new(2);
        let logger = NullLogger::new();
        let mutator = RecordingMutator::default();
        let mut state = TriggerState::initial(1000, true, "ad-hoc", HOUR_0);

        let (req_tx, req_rx) = std::sync::mpsc::channel::<PendingRequest>();
        let (resp_tx, _resp_rx) = std::sync::mpsc::sync_channel(1);
        req_tx
            .send(PendingRequest {
                cmd: crate::trigger_socket::TriggerCommand::SetSampleRate { rate: 5 },
                response_tx: resp_tx,
            })
            .unwrap();

        // Wire mutator into source so the trigger-aware loop can call
        // set_config via the source.
        let mut source = MockPacketEventSource::with_mutator(source, mutator);

        record_incident_loop(
            &mut source, &mut sink, &clock, &shutdown, &logger,
            None, 0,
            Some(&mut state),
            Some(&req_rx),
            &ScrubConfig::default(), &RetentionConfig::default(),
            None,
        );

        assert_eq!(state.sample_rate, 5);
        assert_eq!(
            source.mutator_calls(),
            vec![(ibsr_bpf::ConfigKey::SampleRate, 5)],
            "loop must have applied the queued set-sample-rate command",
        );
    }

    /// Test sink that records every rotate(tag, ts) call. Used to
    /// verify the orchestrator triggers rotation on Trigger commands.
    struct RecordingSink {
        rotations: std::sync::Mutex<Vec<(String, u64)>>,
        events: u64,
    }
    impl RecordingSink {
        fn new() -> Self {
            Self {
                rotations: std::sync::Mutex::new(Vec::new()),
                events: 0,
            }
        }
    }
    impl crate::pcap::PacketSink for RecordingSink {
        fn write_packet(
            &mut self,
            _: u32, _: u32, _: u32, _: &[u8],
        ) -> std::io::Result<()> {
            self.events += 1;
            Ok(())
        }
        fn rotate(
            &mut self,
            tag: &str,
            ts: u64,
        ) -> std::io::Result<Option<std::path::PathBuf>> {
            self.rotations.lock().unwrap().push((tag.to_string(), ts));
            Ok(Some(std::path::PathBuf::from(format!("/x/{}-{}/packets.pcap", tag, ts))))
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        fn current_path(&self) -> Option<&std::path::Path> { None }
    }

    #[test]
    fn record_loop_scrub_drops_internal_subnet_traffic() {
        // Build a packet with src + dst inside 10.0.0.0/8.
        // Construct directly: the BPF event format wraps a 14-byte
        // Ethernet header + IPv4. Helper from record_incident_event
        // raw mode + the build_ipv4_eth_pkt is not exposed here, so
        // craft the cap_len bytes inline.
        let mut pkt = [0u8; RECORD_SNAPLEN_BYTES];
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        pkt[14] = 0x45;
        pkt[26..30].copy_from_slice(&0x0a000001u32.to_be_bytes());
        pkt[30..34].copy_from_slice(&0x0a000002u32.to_be_bytes());

        let mut ev = ibsr_bpf::RawPacketEvent {
            ts_ns: 0,
            ifindex: 1,
            direction: record_direction::INGRESS,
            wire_len: 64,
            cap_len: 64,
            pkt,
        };
        // Ensure cap_len bytes are filled (we set [0..34], which is
        // less than 64 — pad rest with the IP-header bytes already
        // there, valid pcap content).
        ev.cap_len = 60; // up to 60 bytes covers what we set above.

        let raw_bytes = unsafe {
            std::slice::from_raw_parts(
                (&ev as *const ibsr_bpf::RawPacketEvent) as *const u8,
                std::mem::size_of::<ibsr_bpf::RawPacketEvent>(),
            )
        }
        .to_vec();

        let mut source = MockPacketEventSource::from_batches(vec![vec![raw_bytes]]);
        let buf: Vec<u8> = Vec::new();
        let pcap_writer = PcapWriter::new(buf, RECORD_SNAPLEN_BYTES as u32).expect("pcap");
        let mut sink = SimplePacketSink::new(pcap_writer, None);
        let clock = MockClock::new(HOUR_0);
        let shutdown = crate::signal::CountingShutdown::new(2);
        let logger = NullLogger::new();

        let scrub = ScrubConfig {
            ip_salt: None,
            internal_subnet: Some(crate::scrub::parse_subnet("10.0.0.0/8").unwrap()),
        };

        let stats = record_incident_loop(
            &mut source, &mut sink, &clock, &shutdown, &logger,
            None, 0, None, None, &scrub, &RetentionConfig::default(),
            None,
        );

        assert_eq!(stats.events_scrubbed, 1,
            "internal-subnet packet must be scrubbed-and-dropped");
        assert_eq!(stats.events_written, 0,
            "scrubbed packet must NOT land in the pcap");
    }

    #[test]
    fn record_loop_rotates_pcap_on_trigger_command() {
        let mut source = MockPacketEventSource::from_batches(vec![]);
        let mutator = RecordingMutator::default();
        let mut source = MockPacketEventSource::with_mutator(source, mutator);
        let mut sink = RecordingSink::new();
        let clock = MockClock::new(HOUR_0);
        let shutdown = crate::signal::CountingShutdown::new(2);
        let logger = NullLogger::new();

        let mut state = TriggerState::initial(1000, false, "old-tag", 0);
        let (req_tx, req_rx) = std::sync::mpsc::channel::<PendingRequest>();
        let (resp_tx, _resp_rx) = std::sync::mpsc::sync_channel(1);
        req_tx.send(PendingRequest {
            cmd: crate::trigger_socket::TriggerCommand::Trigger {
                tag: "new-tag".into(),
                rate: 10,
                duration_sec: None,
            },
            response_tx: resp_tx,
        }).unwrap();

        let stats = record_incident_loop(
            &mut source, &mut sink, &clock, &shutdown, &logger,
            None, 0,
            Some(&mut state),
            Some(&req_rx),
            &ScrubConfig::default(), &RetentionConfig::default(),
            None,
        );

        let rotations = sink.rotations.lock().unwrap().clone();
        assert_eq!(rotations.len(), 1, "Trigger must rotate once");
        assert_eq!(rotations[0].0, "new-tag",
            "rotation tag must reflect the Trigger command");
        assert_eq!(rotations[0].1, HOUR_0,
            "rotation ts must be the orchestrator's clock-now");
        assert_eq!(stats.rotations, 1);
    }

    #[test]
    fn build_status_line_emits_record_incident_shape() {
        let mut stats = RecordIncidentLoopStats::default();
        stats.events_written = 5;
        stats.events_scrubbed = 2;
        stats.rotations = 1;
        let line = build_status_line(1_700_000_000, 3, &stats);
        assert!(line.contains("\"timestamp\":1700000000"));
        assert!(line.contains("\"cycle\":3"));
        assert!(line.contains("\"events_written\":5"));
        assert!(line.contains("\"events_scrubbed\":2"));
        assert!(line.contains("\"rotations\":1"));
        assert!(serde_json::from_str::<serde_json::Value>(&line).is_ok(),
            "status line must be valid JSON: {}", line);
    }

    #[test]
    fn fs_status_emitter_appends_one_line_per_emit() {
        let fs = ibsr_fs::MockFilesystem::new();
        let path = std::path::PathBuf::from("/tmp/status.jsonl");
        let mut emitter = FsStatusEmitter::new(fs.clone(), path.clone());
        emitter.emit(r#"{"a":1}"#);
        emitter.emit(r#"{"a":2}"#);
        let bytes = fs.get_file(&path).expect("status file written");
        let s = String::from_utf8(bytes).expect("utf8");
        assert_eq!(s, "{\"a\":1}\n{\"a\":2}\n",
            "each emit appends one newline-terminated JSON line");
    }

    /// Minimal recording emitter for loop-level integration test.
    #[derive(Default)]
    struct VecEmitter {
        lines: Vec<String>,
    }
    impl StatusEmitter for VecEmitter {
        fn emit(&mut self, line: &str) {
            self.lines.push(line.to_string());
        }
    }

    #[test]
    fn record_loop_emits_status_line_when_interval_elapses() {
        // status_interval_sec=0 → emit on every iteration. The
        // CountingShutdown(2) gives 2 iterations.
        let mut source = MockPacketEventSource::from_batches(vec![]);
        let mutator = RecordingMutator::default();
        let mut source = MockPacketEventSource::with_mutator(source, mutator);
        let buf: Vec<u8> = Vec::new();
        let pcap_writer = PcapWriter::new(buf, RECORD_SNAPLEN_BYTES as u32).expect("pcap");
        let mut sink = SimplePacketSink::new(pcap_writer, None);
        let clock = MockClock::new(HOUR_0);
        let shutdown = crate::signal::CountingShutdown::new(2);
        let logger = NullLogger::new();
        let mut emitter = VecEmitter::default();

        // status_interval_sec must be >0 (loop guards against 0).
        let status_interval = 1u64;
        let status: Option<(&mut dyn StatusEmitter, u64)> =
            Some((&mut emitter, status_interval));

        record_incident_loop(
            &mut source, &mut sink, &clock, &shutdown, &logger,
            None, 0, None, None,
            &ScrubConfig::default(), &RetentionConfig::default(),
            status,
        );

        assert!(!emitter.lines.is_empty(),
            "loop must emit at least one status line when interval elapses");
        // Each line must be valid JSON with the record-incident shape.
        for line in &emitter.lines {
            let v: serde_json::Value =
                serde_json::from_str(line).expect("line must be JSON");
            assert!(v.get("events_written").is_some());
            assert!(v.get("rotations").is_some());
        }
    }

    #[test]
    fn record_loop_size_driven_rotation_fires_when_max_pcap_bytes_hit() {
        // Two ~250-byte packets at max_pcap_bytes=300 should rotate
        // after the first.
        let raw1 = raw_packet_event(record_direction::INGRESS, 250, 250, 0, 0xaa);
        let raw2 = raw_packet_event(record_direction::INGRESS, 250, 250, 0, 0xbb);
        let mut source = MockPacketEventSource::from_batches(vec![vec![raw1, raw2]]);
        let mutator = RecordingMutator::default();
        let mut source = MockPacketEventSource::with_mutator(source, mutator);
        let mut sink = RecordingSink::new();
        let clock = MockClock::new(HOUR_0);
        let shutdown = crate::signal::CountingShutdown::new(2);
        let logger = NullLogger::new();

        let retention = RetentionConfig {
            max_pcap_bytes: Some(200),
            archive: None,
        };

        let mut state = TriggerState::initial(1, true, "x", HOUR_0);

        let stats = record_incident_loop(
            &mut source, &mut sink, &clock, &shutdown, &logger,
            None, 0,
            Some(&mut state),
            None, // no trigger socket
            &ScrubConfig::default(), &retention,
            None,
        );

        assert!(stats.size_driven_rotations >= 1,
            "max_pcap_bytes=200 with 250-byte packet must trigger size rotation");
        assert!(stats.events_written >= 2,
            "rotation must not skip writes: {:?}", stats);
    }

    #[test]
    fn record_loop_does_not_rotate_on_set_sample_rate() {
        // Rate-only updates don't change tag/ts → no rotation.
        let source = MockPacketEventSource::from_batches(vec![]);
        let mutator = RecordingMutator::default();
        let mut source = MockPacketEventSource::with_mutator(source, mutator);
        let mut sink = RecordingSink::new();
        let clock = MockClock::new(HOUR_0);
        let shutdown = crate::signal::CountingShutdown::new(2);
        let logger = NullLogger::new();

        let mut state = TriggerState::initial(1000, true, "x", HOUR_0);
        let (req_tx, req_rx) = std::sync::mpsc::channel::<PendingRequest>();
        let (resp_tx, _resp_rx) = std::sync::mpsc::sync_channel(1);
        req_tx.send(PendingRequest {
            cmd: crate::trigger_socket::TriggerCommand::SetSampleRate { rate: 5 },
            response_tx: resp_tx,
        }).unwrap();

        let stats = record_incident_loop(
            &mut source, &mut sink, &clock, &shutdown, &logger,
            None, 0,
            Some(&mut state),
            Some(&req_rx),
            &ScrubConfig::default(), &RetentionConfig::default(),
            None,
        );

        assert_eq!(sink.rotations.lock().unwrap().len(), 0,
            "set-sample-rate must NOT rotate the pcap");
        assert_eq!(stats.rotations, 0);
    }

    #[test]
    fn record_loop_auto_stops_at_deadline() {
        let mut source = MockPacketEventSource::from_batches(vec![]);
        let buf: Vec<u8> = Vec::new();
        let pcap_writer = PcapWriter::new(buf, RECORD_SNAPLEN_BYTES as u32).expect("pcap");
        let mut sink = SimplePacketSink::new(pcap_writer, None);
        let clock = MockClock::new(HOUR_0);
        // Allow 2 iterations.
        let shutdown = crate::signal::CountingShutdown::new(2);
        let logger = NullLogger::new();
        let mutator = RecordingMutator::default();

        // State already past deadline → first tick should auto-stop.
        let mut state = TriggerState::initial(1, true, "x", HOUR_0);
        state.trigger_deadline_unix_sec = Some(HOUR_0 - 1);

        let (_req_tx, req_rx) = std::sync::mpsc::channel::<PendingRequest>();

        let mut source = MockPacketEventSource::with_mutator(source, mutator);

        record_incident_loop(
            &mut source, &mut sink, &clock, &shutdown, &logger,
            None, 0,
            Some(&mut state),
            Some(&req_rx),
            &ScrubConfig::default(), &RetentionConfig::default(),
            None,
        );

        assert!(!state.sampling_active,
            "deadline-hit must clear sampling_active");
        assert!(
            source.mutator_calls()
                .iter()
                .any(|(k, v)| *k == ibsr_bpf::ConfigKey::SamplingActive && *v == 0),
            "auto-stop must write SamplingActive=0",
        );
    }

    #[test]
    fn record_loop_respects_shutdown_signal() {
        let raw = raw_packet_event(record_direction::INGRESS, 100, 50, 0, 0);
        let mut source = MockPacketEventSource::from_batches(vec![vec![raw]]);
        let buf: Vec<u8> = Vec::new();
        let pcap_writer = PcapWriter::new(buf, RECORD_SNAPLEN_BYTES as u32).expect("pcap");
        let mut sink = SimplePacketSink::new(pcap_writer, None);
        let clock = MockClock::new(HOUR_0);
        let shutdown = AlwaysShutdown;
        let logger = NullLogger::new();

        let stats = record_incident_loop(
            &mut source, &mut sink, &clock, &shutdown, &logger,
            None, 0, None, None,
            &ScrubConfig::default(), &RetentionConfig::default(),
            None,
        );

        assert_eq!(stats.events_written, 0,
            "shutdown must short-circuit before any events are drained");
    }

    #[test]
    fn format_run_dir_name_is_tag_then_timestamp() {
        assert_eq!(format_run_dir_name("ad-hoc", 1_704_067_200),
            "ad-hoc-1704067200");
        assert_eq!(format_run_dir_name("incident-customer-A", 42), "incident-customer-A-42");
    }

    fn make_sink() -> SimplePacketSink<Vec<u8>> {
        let writer = PcapWriter::new(Vec::new(), RECORD_SNAPLEN_BYTES as u32).expect("pcap");
        SimplePacketSink::new(writer, None)
    }

    #[test]
    fn execute_validates_args_first() {
        // sample_rate=0 → InvalidSampleRate.
        let args = RecordIncidentArgs {
            iface: "lo".into(),
            out_dir: PathBuf::from("/tmp/x"),
            tag: "test".into(),
            sample_rate: 0,
            duration_sec: Some(1),
            verbose: 0,
            status_interval_sec: 60,
            trigger_socket: None,
            scrub_ip_salt: None,
            scrub_internal_subnet: None,
            max_pcap_bytes: None,
            archive_dir: None,
            archive_after_sec: 3600,
        };
        let attacher = CannedAttacher::new(vec![]);
        let clock = MockClock::new(HOUR_0);
        let fs = ibsr_fs::MockFilesystem::new();
        let shutdown = NeverShutdown;
        let logger = NullLogger::new();
        let mut sink = make_sink();
        let result = execute_record_incident(
            &args, attacher, &clock, &fs, &shutdown, &logger,
            &mut sink, PathBuf::from("/tmp/x/test/packets.pcap"), 0,
            None,
        );
        assert!(matches!(result, Err(CommandError::InvalidArgument(_))));
    }

    #[test]
    fn execute_validates_invalid_tag() {
        let args = RecordIncidentArgs {
            iface: "lo".into(),
            out_dir: PathBuf::from("/tmp/x"),
            tag: "bad/slash".into(),
            sample_rate: 1,
            duration_sec: Some(1),
            verbose: 0,
            status_interval_sec: 60,
            trigger_socket: None,
            scrub_ip_salt: None,
            scrub_internal_subnet: None,
            max_pcap_bytes: None,
            archive_dir: None,
            archive_after_sec: 3600,
        };
        let attacher = CannedAttacher::new(vec![]);
        let clock = MockClock::new(HOUR_0);
        let fs = ibsr_fs::MockFilesystem::new();
        let shutdown = NeverShutdown;
        let logger = NullLogger::new();
        let mut sink = make_sink();
        let result = execute_record_incident(
            &args, attacher, &clock, &fs, &shutdown, &logger,
            &mut sink, PathBuf::from("/tmp/x/test/packets.pcap"), 0,
            None,
        );
        assert!(matches!(result, Err(CommandError::InvalidArgument(_))));
    }

    #[test]
    fn execute_attach_failure_propagates() {
        let args = parse_args(&[
            "ibsr", "record-incident", "-i", "lo",
            "--tag", "test", "--sample-rate", "10",
            "--duration-sec", "1",
            "-o", "/tmp/ibsr-record-test",
        ]);
        let attacher = FailingAttacher(AttachError::InterfaceNotFound("nope".into()));
        let clock = MockClock::new(HOUR_0);
        let fs = ibsr_fs::MockFilesystem::new();
        let shutdown = NeverShutdown;
        let logger = NullLogger::new();
        let mut sink = make_sink();
        let result = execute_record_incident(
            &args, attacher, &clock, &fs, &shutdown, &logger,
            &mut sink, PathBuf::from("/tmp/ibsr-record-test/test/packets.pcap"), 0,
            None,
        );
        match result {
            Err(CommandError::NotImplemented(msg)) => {
                assert!(msg.contains("nope"),
                    "error must include failing iface name: {}", msg);
            }
            other => panic!("expected NotImplemented(attach failed): {:?}", other),
        }
    }

    #[test]
    fn execute_happy_path_writes_pcap() {
        let raw = raw_packet_event(record_direction::INGRESS, 60, 60, 1_000_000_000, 0xfe);
        let args = parse_args(&[
            "ibsr", "record-incident", "-i", "lo",
            "--tag", "ok", "--sample-rate", "1",
            "--duration-sec", "1",
            "-o", "/tmp/ibsr-record-happy",
        ]);
        let attacher = CannedAttacher::new(vec![vec![raw]]);
        let clock = MockClock::new(HOUR_0);
        let fs = ibsr_fs::MockFilesystem::new();
        let shutdown = crate::signal::CountingShutdown::new(2);
        let logger = NullLogger::new();
        let mut sink = make_sink();
        let result = execute_record_incident(
            &args, attacher, &clock, &fs, &shutdown, &logger,
            &mut sink, PathBuf::from("/tmp/ibsr-record-happy/ok-1704067200/packets.pcap"),
            0,
            None,
        );
        let r = result.expect("ok");
        assert_eq!(r.events_written, 1);
        // Run dir created on the mock fs.
        assert!(fs.exists(&r.run_dir),
            "run_dir must be created on the (mock) filesystem");
        assert!(r.run_dir.ends_with("ok-1704067200"),
            "run_dir reflects the configured tag + clock: {:?}", r.run_dir);
    }
}
