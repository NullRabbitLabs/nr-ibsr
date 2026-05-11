//! ShadowPayload-mode collect-payload command orchestration.
//!
//! Wires the validated `CollectPayloadArgs` through the
//! `TcPayloadAttacher` (the BPF-loader / TC-attach abstraction) into
//! the `collect_payload_loop` (the multi-window orchestrator). The
//! attacher trait is mocked in tests so the full command path is
//! exercisable without a kernel; the production attacher (libbpf-rs
//! ringbuf adapter + clsact qdisc + TC ingress/egress hooks) lands as
//! the only kernel-bound piece.

use std::path::PathBuf;

use ibsr_clock::Clock;
use ibsr_fs::{Filesystem, StandardSnapshotWriter};

use crate::cli::CollectPayloadArgs;
use crate::logger::Logger;
use crate::payload::PayloadHandler;
use crate::payload_collector::{
    args_to_config, args_to_server_ports, collect_payload_loop, PayloadEventSource,
    PayloadLoopResult,
};
use crate::signal::ShutdownCheck;

use super::{CommandError, CommandResult};

/// Errors raised by the BPF / TC attacher.
#[derive(Debug, thiserror::Error)]
pub enum AttachError {
    #[error("BPF program load failed: {0}")]
    BpfLoad(String),

    #[error("TC qdisc setup failed for interface '{iface}': {reason}")]
    TcQdisc { iface: String, reason: String },

    #[error("TC program attach failed: {0}")]
    TcAttach(String),

    #[error("port-filter map programming failed: {0}")]
    MapProgram(String),

    #[error("ringbuf setup failed: {0}")]
    Ringbuf(String),

    #[error("interface '{0}' does not exist")]
    InterfaceNotFound(String),

    #[error("attach error: {0}")]
    Other(String),
}

/// One-shot attacher: load BPF program(s), create + attach TC qdisc,
/// program the port-filter map, set up the ringbuf consumer. Consumes
/// `self` because attaching is irreversible from the attacher's
/// perspective; the returned event source owns the handle and detaches
/// everything on Drop.
pub trait TcPayloadAttacher {
    /// The event source produced after attach. The caller polls this
    /// to receive raw ringbuf bytes.
    type Source: PayloadEventSource;

    /// Attach BPF programs + TC qdisc to `iface`, program port-filter
    /// with `ports`, set up ringbuf consumer. Returns the event source
    /// on success. On any failure the partial attach state is unwound
    /// before returning the error (no orphan qdisc / map / program).
    fn attach(self, iface: &str, ports: &[u16]) -> Result<Self::Source, AttachError>;
}

/// Outcome of `execute_collect_payload` — the user-facing summary the
/// CLI prints + the operator monitors via status.jsonl.
#[derive(Debug)]
pub struct CollectPayloadResult {
    /// Window cadence outcome from the orchestrator.
    pub loop_result: PayloadLoopResult,
    /// Output directory the snapshots landed in.
    pub run_dir: PathBuf,
}

/// Execute the collect-payload subcommand.
///
/// Trait-abstracted I/O so the full command path is unit-testable:
/// - `A`: TC payload attacher (real = libbpf-rs; mock = in-process).
/// - `C`: clock for timestamps.
/// - `F`: filesystem for atomic writes + rotation.
/// - `H`: shutdown signal source.
/// - `L`: logger for verbose / info / error messages.
///
/// Per the "IBSR runs without dying" contract: attach failures and
/// validation failures propagate as `CommandError`; runtime failures
/// (writer / source / decode) are logged and the loop continues.
pub fn execute_collect_payload<A, C, F, H, L>(
    args: &CollectPayloadArgs,
    attacher: A,
    clock: &C,
    fs: &F,
    shutdown: &H,
    logger: &L,
) -> CommandResult<CollectPayloadResult>
where
    A: TcPayloadAttacher,
    C: Clock,
    F: Filesystem + Clone,
    H: ShutdownCheck,
    L: Logger,
{
    args.validate()?;

    let run_ts = clock.now_unix_sec();
    let run_dir_name = format_run_dir_name(run_ts);
    let run_dir = args.out_dir.join(&run_dir_name);
    fs.create_dir_all(&run_dir)?;

    let ports = args.get_all_ports();
    logger.verbose(&format!(
        "Starting payload collector: ports={:?}, iface={}, out_dir={}, \
         window_sec={}, max_flows={}",
        ports,
        args.iface,
        run_dir.display(),
        args.window_sec,
        args.max_flows,
    ));

    let mut event_source = attacher
        .attach(&args.iface, &ports)
        .map_err(|e| CommandError::NotImplemented(format!("attach failed: {}", e)))?;

    logger.info(&format!(
        "TC payload programs attached to interface '{}' (ports {:?})",
        args.iface, ports,
    ));

    let cfg = args_to_config(args, clock);
    let server_ports = args_to_server_ports(args);
    let mut handler = PayloadHandler::new(args.max_flows);

    let writer = StandardSnapshotWriter::new(fs.clone(), run_dir.clone());

    // Optional duration cap → max_windows. Unit conversion: floor of
    // (duration / window) windows fit in the requested duration.
    let max_windows = args
        .duration_sec
        .map(|d| d.checked_div(args.window_sec).unwrap_or(1));

    // Resolve --target-pid (or --target-process-name) into an optional
    // HostSampler. The sampler is the wiring point for the v7 host
    // block; absent it, snapshots emit without `host`.
    let host_sampler = crate::payload_collector::resolve_host_sampler(args);

    let loop_result = collect_payload_loop(
        &mut event_source,
        clock,
        &writer,
        fs,
        &mut handler,
        &server_ports,
        &cfg,
        shutdown,
        &run_dir,
        max_windows,
        host_sampler.as_ref(),
    );

    logger.info(&format!(
        "payload collection finished: {} windows ok, {} windows failed, {} pairs total",
        loop_result.windows_completed, loop_result.windows_failed, loop_result.total_pairs,
    ));

    if loop_result.total_decode_errors > 0 {
        logger.verbose(&format!(
            "decode errors: {} (lossy by design)",
            loop_result.total_decode_errors,
        ));
    }
    if loop_result.total_source_errors > 0 {
        logger.verbose(&format!(
            "source errors: {} (lossy by design)",
            loop_result.total_source_errors,
        ));
    }

    Ok(CollectPayloadResult {
        loop_result,
        run_dir,
    })
}

/// Format run directory name from Unix timestamp. Mirrors the
/// `format_run_dir_name` in `commands::collect` for consistent on-disk
/// layout across modes.
fn format_run_dir_name(ts_unix: u64) -> String {
    use chrono::{TimeZone, Utc};
    Utc.timestamp_opt(ts_unix as i64, 0)
        .single()
        .map(|dt| dt.format("ibsr-payload-%Y%m%d-%H%M%SZ").to_string())
        .unwrap_or_else(|| format!("ibsr-payload-{}", ts_unix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{parse_from, Command};
    use crate::logger::NullLogger;
    use crate::payload_collector::MockPayloadEventSource;
    use crate::signal::{AlwaysShutdown, NeverShutdown};
    use ibsr_bpf::{
        direction, RawFlowId, RawPayloadEvent, PAYLOAD_SAMPLE_BYTES,
    };
    use ibsr_clock::MockClock;
    use ibsr_fs::MockFilesystem;
    use std::sync::Arc;

    const HOUR_0: u64 = 1_704_067_200;

    /// Test attacher that returns a pre-canned event source.
    struct CannedAttacher {
        source: MockPayloadEventSource,
        last_iface: Arc<std::sync::Mutex<Option<String>>>,
        last_ports: Arc<std::sync::Mutex<Option<Vec<u16>>>>,
    }
    impl CannedAttacher {
        fn new(batches: Vec<Vec<Vec<u8>>>) -> Self {
            Self {
                source: MockPayloadEventSource::from_batches(batches),
                last_iface: Arc::new(std::sync::Mutex::new(None)),
                last_ports: Arc::new(std::sync::Mutex::new(None)),
            }
        }
    }
    impl TcPayloadAttacher for CannedAttacher {
        type Source = MockPayloadEventSource;
        fn attach(self, iface: &str, ports: &[u16]) -> Result<Self::Source, AttachError> {
            *self.last_iface.lock().unwrap() = Some(iface.to_string());
            *self.last_ports.lock().unwrap() = Some(ports.to_vec());
            Ok(self.source)
        }
    }

    /// Test attacher that always fails to attach.
    struct FailingAttacher(AttachError);
    impl TcPayloadAttacher for FailingAttacher {
        type Source = MockPayloadEventSource;
        fn attach(self, _iface: &str, _ports: &[u16]) -> Result<Self::Source, AttachError> {
            Err(self.0)
        }
    }

    fn parse_payload_args(argv: &[&str]) -> CollectPayloadArgs {
        let cli = parse_from(argv).expect("parse");
        match cli.command {
            Command::CollectPayload(a) => a,
            _ => panic!("expected CollectPayload"),
        }
    }

    fn make_args(window_sec: u64, max_windows_via_duration: Option<u64>) -> CollectPayloadArgs {
        let mut argv: Vec<String> = vec![
            "ibsr".into(),
            "collect-payload".into(),
            "-p".into(),
            "8899".into(),
            "--window-sec".into(),
            window_sec.to_string(),
            "--out-dir".into(),
            "/tmp/test-payload".into(),
        ];
        if let Some(dur) = max_windows_via_duration {
            argv.push("--duration-sec".into());
            argv.push(dur.to_string());
        }
        let cli = parse_from(argv).expect("parse");
        match cli.command {
            Command::CollectPayload(a) => a,
            _ => panic!("expected CollectPayload"),
        }
    }

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
        raw_event_bytes(0x7f000002, 12345, 0x7f000001, 8899, direction::INGRESS, payload)
    }

    fn resp_event(payload: &[u8]) -> Vec<u8> {
        raw_event_bytes(0x7f000001, 8899, 0x7f000002, 12345, direction::EGRESS, payload)
    }

    // ===========================================
    // execute_collect_payload — happy path + failure modes
    // ===========================================

    #[test]
    fn execute_payload_with_valid_args_creates_run_dir() {
        let args = make_args(1, Some(1));
        let attacher = CannedAttacher::new(Vec::new());
        let clock = MockClock::new(HOUR_0);
        let fs = MockFilesystem::new();
        let shutdown = NeverShutdown;
        let logger = NullLogger::new();

        let result = execute_collect_payload(&args, attacher, &clock, &fs, &shutdown, &logger)
            .expect("execute");
        assert!(result.run_dir.starts_with("/tmp/test-payload/"),
            "run_dir should be inside out_dir: {:?}", result.run_dir);
        assert!(result.run_dir.to_string_lossy().contains("ibsr-payload-"),
            "run_dir should be timestamped: {:?}", result.run_dir);
        assert!(fs.exists(&result.run_dir),
            "run_dir should have been created on the filesystem");
    }

    #[test]
    fn execute_payload_passes_iface_to_attacher() {
        let mut argv = vec!["ibsr", "collect-payload", "-p", "8899", "-i", "eth1",
                            "--window-sec", "1", "--duration-sec", "1",
                            "--out-dir", "/tmp/test-payload"];
        let args = parse_payload_args(&argv);
        argv.clear();

        let attacher = CannedAttacher::new(Vec::new());
        let last_iface = attacher.last_iface.clone();
        let last_ports = attacher.last_ports.clone();
        let clock = MockClock::new(HOUR_0);
        let fs = MockFilesystem::new();
        let shutdown = NeverShutdown;
        let logger = NullLogger::new();

        execute_collect_payload(&args, attacher, &clock, &fs, &shutdown, &logger)
            .expect("execute");
        assert_eq!(last_iface.lock().unwrap().as_deref(), Some("eth1"));
        assert_eq!(last_ports.lock().unwrap().as_ref().unwrap(), &vec![8899]);
    }

    #[test]
    fn execute_payload_invalid_args_returns_error() {
        // No port set — validation fires before attacher is consulted.
        let args = parse_payload_args(&["ibsr", "collect-payload"]);
        let attacher = CannedAttacher::new(Vec::new());
        let clock = MockClock::new(HOUR_0);
        let fs = MockFilesystem::new();
        let shutdown = NeverShutdown;
        let logger = NullLogger::new();

        let result = execute_collect_payload(&args, attacher, &clock, &fs, &shutdown, &logger);
        assert!(matches!(result, Err(CommandError::InvalidArgument(_))));
    }

    #[test]
    fn execute_payload_attach_failure_propagates() {
        let args = make_args(1, Some(1));
        let attacher = FailingAttacher(AttachError::InterfaceNotFound("nope0".into()));
        let clock = MockClock::new(HOUR_0);
        let fs = MockFilesystem::new();
        let shutdown = NeverShutdown;
        let logger = NullLogger::new();

        let result = execute_collect_payload(&args, attacher, &clock, &fs, &shutdown, &logger);
        // Attach failure surfaces as CommandError::NotImplemented for now
        // (until a dedicated CommandError::Attach variant is added; the
        // user-facing message includes the original AttachError).
        match result {
            Err(CommandError::NotImplemented(msg)) => {
                assert!(msg.contains("nope0"),
                    "error must include the failing interface name: {}", msg);
            }
            other => panic!("expected NotImplemented(attach failed), got {:?}", other),
        }
    }

    #[test]
    fn execute_payload_runs_orchestrator_with_aggregated_pairs() {
        let args = make_args(1, Some(1));
        let req = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npayload";
        let attacher = CannedAttacher::new(vec![
            vec![req_event(req)],
            vec![resp_event(resp)],
        ]);
        let clock = MockClock::new(HOUR_0);
        let fs = MockFilesystem::new();
        let shutdown = NeverShutdown;
        let logger = NullLogger::new();

        let result = execute_collect_payload(&args, attacher, &clock, &fs, &shutdown, &logger)
            .expect("execute");
        assert_eq!(result.loop_result.windows_completed, 1);
        assert_eq!(result.loop_result.total_pairs, 1,
            "one paired RPC must surface as one pair in the loop result");
    }

    #[test]
    fn execute_payload_shutdown_short_circuits_cleanly() {
        let args = make_args(60, None);
        let attacher = CannedAttacher::new(Vec::new());
        let clock = MockClock::new(HOUR_0);
        let fs = MockFilesystem::new();
        let shutdown = AlwaysShutdown;
        let logger = NullLogger::new();

        let result = execute_collect_payload(&args, attacher, &clock, &fs, &shutdown, &logger)
            .expect("execute should succeed under shutdown");
        // Loop never enters a window because shutdown fires first.
        assert_eq!(result.loop_result.windows_completed, 0);
        assert_eq!(result.loop_result.windows_failed, 0);
    }

    #[test]
    fn execute_payload_duration_caps_window_count() {
        // window_sec=1, duration_sec=3 → max_windows=3.
        let args = make_args(1, Some(3));
        let attacher = CannedAttacher::new(Vec::new());
        let clock = MockClock::new(HOUR_0);
        let fs = MockFilesystem::new();
        let shutdown = NeverShutdown;
        let logger = NullLogger::new();

        let result = execute_collect_payload(&args, attacher, &clock, &fs, &shutdown, &logger)
            .expect("execute");
        assert_eq!(result.loop_result.windows_completed, 3,
            "duration 3s / 1s window = 3 windows");
    }

    #[test]
    fn execute_payload_run_dir_naming_includes_timestamp() {
        let args = make_args(1, Some(1));
        let attacher = CannedAttacher::new(Vec::new());
        let clock = MockClock::new(HOUR_0);
        let fs = MockFilesystem::new();
        let shutdown = NeverShutdown;
        let logger = NullLogger::new();

        let result = execute_collect_payload(&args, attacher, &clock, &fs, &shutdown, &logger)
            .expect("execute");
        assert!(result.run_dir.to_string_lossy().contains("ibsr-payload-"));
        // HOUR_0 = 2024-01-01 00:00:00 UTC
        assert!(
            result.run_dir.to_string_lossy().contains("20240101"),
            "run_dir should contain YYYYMMDD from clock: {:?}", result.run_dir,
        );
    }

    #[test]
    fn format_run_dir_name_format_is_stable() {
        // 1704067200 = 2024-01-01 00:00:00 UTC
        assert_eq!(format_run_dir_name(1704067200), "ibsr-payload-20240101-000000Z");
    }
}
