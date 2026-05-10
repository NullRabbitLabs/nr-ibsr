//! Trigger socket for record-incident.
//!
//! Per docs/CF-INCIDENT-RECORDING-DESIGN-V1.md §"Trigger-socket
//! protocol": a Unix socket that accepts newline-delimited JSON
//! commands updating the kernel-side `config_map`. Three intended
//! callers — operator CLI, customer-facing API gateway, inference
//! auto-trigger — all speak the same protocol.
//!
//! Pure pieces (`parse_command`, `apply_command`, `check_auto_stop`)
//! are unit-tested in isolation. The kernel-side `set_config` call is
//! abstracted via the `ConfigMutator` trait so tests pin the exact
//! sequence of `(key, value)` writes a real run would have made.
//!
//! The socket listener thread is wired in `commands/record_incident.rs`
//! when the operator passes `--trigger-socket`.

use std::sync::Arc;

use ibsr_bpf::ConfigKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Trigger socket protocol command. Newline-delimited JSON, one
/// command per line. The `serde(tag = "action")` derives the JSON
/// shape `{"action": "<name>", ...}` matching the design-doc spec.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum TriggerCommand {
    /// Update the sampling rate without changing the active flag.
    SetSampleRate { rate: u64 },
    /// Atomic trigger: flip active=1, set rate, set tag-hash, stamp
    /// timestamp. Optional duration auto-stops.
    Trigger {
        tag: String,
        rate: u64,
        #[serde(default)]
        duration_sec: Option<u64>,
    },
    /// Disable sampling. Counter and rate are preserved (the BPF
    /// program returns TC_ACT_OK before reading them); next `trigger`
    /// resumes from the new state.
    Stop,
    /// Report current state. Read-only.
    Status,
}

/// Response envelope for a command. Serialised as a single line of
/// JSON.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct CommandResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusReport>,
}

/// Status report — a snapshot of current state.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct StatusReport {
    pub sampling_active: u64,
    pub rate: u64,
    pub tag: String,
    pub trigger_ts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline_ts: Option<u64>,
}

impl CommandResponse {
    pub fn ok() -> Self {
        Self {
            ok: true,
            error: None,
            status: None,
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            status: None,
        }
    }

    pub fn with_status(report: StatusReport) -> Self {
        Self {
            ok: true,
            error: None,
            status: Some(report),
        }
    }
}

/// Canonical state of the recording session, mirrored from the
/// kernel-side `config_map` plus a userspace-only deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriggerState {
    pub sample_rate: u64,
    pub sampling_active: bool,
    pub incident_tag: String,
    pub trigger_ts_unix_sec: u64,
    /// Auto-stop deadline (unix seconds). `None` = no auto-stop.
    pub trigger_deadline_unix_sec: Option<u64>,
}

impl TriggerState {
    pub fn initial(rate: u64, sampling_active: bool, tag: impl Into<String>, ts: u64) -> Self {
        Self {
            sample_rate: rate,
            sampling_active,
            incident_tag: tag.into(),
            trigger_ts_unix_sec: ts,
            trigger_deadline_unix_sec: None,
        }
    }

    pub fn to_status_report(&self) -> StatusReport {
        StatusReport {
            sampling_active: self.sampling_active as u64,
            rate: self.sample_rate,
            tag: self.incident_tag.clone(),
            trigger_ts: self.trigger_ts_unix_sec,
            deadline_ts: self.trigger_deadline_unix_sec,
        }
    }
}

/// Errors when parsing a command line.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("empty input")]
    Empty,

    #[error("invalid JSON: {0}")]
    InvalidJson(String),
}

/// Parse a single command line. Returns `ParseError::Empty` for blank
/// input (so an idle socket connection's stray newlines don't
/// surface as "real" parse errors).
pub fn parse_command(line: &str) -> Result<TriggerCommand, ParseError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(ParseError::Empty);
    }
    serde_json::from_str(trimmed).map_err(|e| ParseError::InvalidJson(e.to_string()))
}

/// Trait for mutating the kernel-side `config_map`. Production
/// implementer is the libbpf-rs collector's `set_config`; tests use
/// `MockConfigMutator` which records call sequence.
pub trait ConfigMutator {
    fn set_config(&self, key: ConfigKey, value: u64) -> Result<(), String>;
}

/// Apply a parsed command. Updates `state` in place and writes the
/// matching values to `mutator`. Returns the response that the
/// caller serialises back over the socket.
///
/// Validation is deliberately strict: rate must be ≥ 1; tag must
/// pass the same charset rules as the CLI flag (so a malicious
/// trigger can't sneak path components into the tag-hashed
/// directory name in Phase 4).
pub fn apply_command<M: ConfigMutator>(
    cmd: &TriggerCommand,
    state: &mut TriggerState,
    mutator: &M,
    now_unix_sec: u64,
) -> CommandResponse {
    match cmd {
        TriggerCommand::SetSampleRate { rate } => {
            if *rate < 1 {
                return CommandResponse::err("rate must be >= 1");
            }
            if let Err(e) = mutator.set_config(ConfigKey::SampleRate, *rate) {
                return CommandResponse::err(format!("set sample-rate: {}", e));
            }
            state.sample_rate = *rate;
            CommandResponse::ok()
        }

        TriggerCommand::Trigger {
            tag,
            rate,
            duration_sec,
        } => {
            if *rate < 1 {
                return CommandResponse::err("rate must be >= 1");
            }
            if !crate::cli::is_valid_incident_tag(tag) {
                return CommandResponse::err(format!(
                    "tag must be 1..=64 chars [a-zA-Z0-9_-], got {:?}",
                    tag,
                ));
            }
            // Atomic-from-the-userspace-perspective: write rate, then
            // tag-hash, then trigger-ts, then active=1 last so the
            // BPF program never reads "active=1, rate=stale".
            let tag_hash = ibsr_bpf::fnv1a64(tag.as_bytes());
            if let Err(e) = mutator.set_config(ConfigKey::SampleRate, *rate) {
                return CommandResponse::err(format!("set rate: {}", e));
            }
            if let Err(e) = mutator.set_config(ConfigKey::IncidentTagHash, tag_hash) {
                return CommandResponse::err(format!("set tag-hash: {}", e));
            }
            if let Err(e) = mutator.set_config(ConfigKey::TriggerTimestamp, now_unix_sec) {
                return CommandResponse::err(format!("set trigger-ts: {}", e));
            }
            if let Err(e) = mutator.set_config(ConfigKey::SamplingActive, 1) {
                return CommandResponse::err(format!("set active: {}", e));
            }
            state.sample_rate = *rate;
            state.sampling_active = true;
            state.incident_tag = tag.clone();
            state.trigger_ts_unix_sec = now_unix_sec;
            state.trigger_deadline_unix_sec = duration_sec.map(|d| now_unix_sec.saturating_add(d));
            CommandResponse::ok()
        }

        TriggerCommand::Stop => {
            if let Err(e) = mutator.set_config(ConfigKey::SamplingActive, 0) {
                return CommandResponse::err(format!("set active=0: {}", e));
            }
            state.sampling_active = false;
            state.trigger_deadline_unix_sec = None;
            CommandResponse::ok()
        }

        TriggerCommand::Status => CommandResponse::with_status(state.to_status_report()),
    }
}

/// Check if the current state has hit its auto-stop deadline. If so,
/// issue an internal `stop` (writing active=0 to the kernel) and
/// return the response so callers can log it. Otherwise returns
/// `None` (and doesn't touch `state`).
///
/// Pure-of-side-effects-on-the-mutator function — no socket I/O.
/// Called by the record-incident loop on each iteration.
pub fn check_auto_stop<M: ConfigMutator>(
    state: &mut TriggerState,
    mutator: &M,
    now_unix_sec: u64,
) -> Option<CommandResponse> {
    let deadline = state.trigger_deadline_unix_sec?;
    if !state.sampling_active {
        return None;
    }
    if now_unix_sec < deadline {
        return None;
    }
    // Reuse Stop's semantics so deadline-hit and operator-stop look
    // identical from outside.
    let resp = apply_command(&TriggerCommand::Stop, state, mutator, now_unix_sec);
    Some(resp)
}

/// One pending request from the listener thread to the orchestrator.
/// The orchestrator receives, dispatches `apply_command`, and sends
/// the response back via `response_tx`. The listener writes the
/// response back to the client socket.
///
/// Carries an `oneshot` semantics via `mpsc::SyncSender` with capacity
/// 1; we don't pull in a oneshot crate for one channel.
pub struct PendingRequest {
    pub cmd: TriggerCommand,
    pub response_tx: std::sync::mpsc::SyncSender<CommandResponse>,
}

/// Process one pending request: lock state, apply, send response.
/// Pure-but-for-mutator: `mutator` is the orchestrator's collector
/// handle. Returns `false` if the response channel was closed (the
/// listener gave up); orchestrator can ignore or log.
pub fn process_request<M: ConfigMutator>(
    req: PendingRequest,
    state: &mut TriggerState,
    mutator: &M,
    now_unix_sec: u64,
) -> bool {
    let resp = apply_command(&req.cmd, state, mutator, now_unix_sec);
    req.response_tx.send(resp).is_ok()
}

/// Per-connection handler used by the listener thread. Reads one
/// line, parses, sends to the orchestrator queue, awaits response,
/// writes back. Pure I/O wrapper over `parse_command` + the
/// orchestrator-side `process_request`.
///
/// `request_tx` is the listener-side end of the queue.
/// `response_timeout` bounds how long we wait for the orchestrator
/// to dispatch — a stuck orchestrator (e.g. blocked in BPF I/O)
/// shouldn't pin connections forever.
pub fn handle_connection<R, W>(
    reader: R,
    mut writer: W,
    request_tx: &std::sync::mpsc::Sender<PendingRequest>,
    response_timeout: std::time::Duration,
) -> std::io::Result<()>
where
    R: std::io::BufRead,
    W: std::io::Write,
{
    let mut line = String::new();
    let mut buf = reader;
    buf.read_line(&mut line)?;

    let response = match parse_command(&line) {
        Ok(cmd) => {
            let (tx, rx) = std::sync::mpsc::sync_channel::<CommandResponse>(1);
            let req = PendingRequest {
                cmd,
                response_tx: tx,
            };
            if request_tx.send(req).is_err() {
                CommandResponse::err("orchestrator gone")
            } else {
                rx.recv_timeout(response_timeout)
                    .unwrap_or_else(|_| CommandResponse::err("response timeout"))
            }
        }
        Err(ParseError::Empty) => CommandResponse::err("empty input"),
        Err(ParseError::InvalidJson(msg)) => {
            CommandResponse::err(format!("parse error: {}", msg))
        }
    };

    let mut json = serde_json::to_string(&response)
        .unwrap_or_else(|_| r#"{"ok":false,"error":"serialize"}"#.into());
    json.push('\n');
    writer.write_all(json.as_bytes())?;
    writer.flush()?;
    Ok(())
}

/// Production socket-listener thread.
///
/// Owns the bound `UnixListener` + the listener-side `request_tx`.
/// Spawns a thread that accepts connections in a loop, dispatching
/// each to `handle_connection`. Connection-handling failures are
/// logged; only the listener-thread shutdown flag stops it.
///
/// Drop signals shutdown, joins the thread, removes the socket file.
pub struct TriggerSocketServer {
    socket_path: std::path::PathBuf,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TriggerSocketServer {
    /// Bind a socket at `path`, spawn the accept thread, return.
    /// `request_tx` is the orchestrator-side queue endpoint; the
    /// orchestrator drains the matching `Receiver` each loop tick
    /// and calls `process_request` on each.
    pub fn spawn(
        path: std::path::PathBuf,
        request_tx: std::sync::mpsc::Sender<PendingRequest>,
    ) -> std::io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        // Best-effort cleanup of any stale socket file from a prior
        // crashed run.
        let _ = std::fs::remove_file(&path);

        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;

        // Per docs/CF-INCIDENT-RECORDING-DESIGN-V1.md decision #4:
        // socket access is gated by filesystem permissions. 0660 =
        // owner + group RW, world none. The deployment must put the
        // intended caller (API gateway / inference / operator CLI)
        // into the owning group; without that, the socket is
        // root-only.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;

        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_thread = shutdown.clone();
        let path_for_thread = path.clone();

        let handle = std::thread::spawn(move || {
            use std::io::{BufReader, BufWriter};
            use std::sync::atomic::Ordering;

            while !shutdown_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(2)));
                        let cloned = match stream.try_clone() {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!(
                                    "trigger socket {:?}: stream clone failed: {}",
                                    path_for_thread, e,
                                );
                                continue;
                            }
                        };
                        let reader = BufReader::new(cloned);
                        let writer = BufWriter::new(stream);
                        if let Err(e) = handle_connection(
                            reader,
                            writer,
                            &request_tx,
                            std::time::Duration::from_secs(5),
                        ) {
                            eprintln!(
                                "trigger socket {:?}: connection error: {}",
                                path_for_thread, e,
                            );
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(e) => {
                        eprintln!(
                            "trigger socket {:?}: accept error: {} (continuing)",
                            path_for_thread, e,
                        );
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                }
            }
        });

        Ok(Self {
            socket_path: path,
            shutdown,
            handle: Some(handle),
        })
    }

    /// The socket file path. Useful for diagnostics + cleanup.
    pub fn path(&self) -> &std::path::Path {
        &self.socket_path
    }
}

impl Drop for TriggerSocketServer {
    fn drop(&mut self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Mock that records every `set_config` call.
    #[derive(Default)]
    struct MockConfigMutator {
        calls: std::sync::Mutex<Vec<(ConfigKey, u64)>>,
        fail_on: std::sync::Mutex<Option<ConfigKey>>,
    }

    impl MockConfigMutator {
        fn new() -> Self {
            Self::default()
        }

        fn fail_when(self, key: ConfigKey) -> Self {
            *self.fail_on.lock().unwrap() = Some(key);
            self
        }

        fn calls(&self) -> Vec<(ConfigKey, u64)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl ConfigMutator for MockConfigMutator {
        fn set_config(&self, key: ConfigKey, value: u64) -> Result<(), String> {
            if Some(key) == *self.fail_on.lock().unwrap() {
                return Err(format!("simulated failure on {:?}", key));
            }
            self.calls.lock().unwrap().push((key, value));
            Ok(())
        }
    }

    // ===========================================
    // parse_command
    // ===========================================

    #[test]
    fn parse_set_sample_rate() {
        let cmd = parse_command(r#"{"action": "set-sample-rate", "rate": 100}"#).unwrap();
        assert_eq!(cmd, TriggerCommand::SetSampleRate { rate: 100 });
    }

    #[test]
    fn parse_trigger_with_duration() {
        let cmd = parse_command(
            r#"{"action": "trigger", "tag": "abc", "rate": 10, "duration_sec": 600}"#,
        )
        .unwrap();
        assert_eq!(
            cmd,
            TriggerCommand::Trigger {
                tag: "abc".into(),
                rate: 10,
                duration_sec: Some(600),
            }
        );
    }

    #[test]
    fn parse_trigger_without_duration() {
        let cmd = parse_command(r#"{"action": "trigger", "tag": "x", "rate": 5}"#).unwrap();
        assert_eq!(
            cmd,
            TriggerCommand::Trigger {
                tag: "x".into(),
                rate: 5,
                duration_sec: None,
            }
        );
    }

    #[test]
    fn parse_stop() {
        let cmd = parse_command(r#"{"action": "stop"}"#).unwrap();
        assert_eq!(cmd, TriggerCommand::Stop);
    }

    #[test]
    fn parse_status() {
        let cmd = parse_command(r#"{"action": "status"}"#).unwrap();
        assert_eq!(cmd, TriggerCommand::Status);
    }

    #[test]
    fn parse_empty_line() {
        match parse_command("") {
            Err(ParseError::Empty) => {}
            other => panic!("expected Empty, got {:?}", other),
        }
        match parse_command("  \n  ") {
            Err(ParseError::Empty) => {}
            other => panic!("expected Empty, got {:?}", other),
        }
    }

    #[test]
    fn parse_invalid_json() {
        match parse_command("not json") {
            Err(ParseError::InvalidJson(_)) => {}
            other => panic!("expected InvalidJson, got {:?}", other),
        }
    }

    #[test]
    fn parse_unknown_action() {
        match parse_command(r#"{"action": "explode"}"#) {
            Err(ParseError::InvalidJson(_)) => {}
            other => panic!("expected InvalidJson for unknown action, got {:?}", other),
        }
    }

    #[test]
    fn parse_trims_whitespace_and_newlines() {
        let cmd = parse_command("  {\"action\": \"stop\"}  \n").unwrap();
        assert_eq!(cmd, TriggerCommand::Stop);
    }

    // ===========================================
    // apply_command — set-sample-rate
    // ===========================================

    #[test]
    fn apply_set_sample_rate_writes_rate_only() {
        let mut state = TriggerState::initial(1000, true, "ad-hoc", 0);
        let mutator = MockConfigMutator::new();
        let resp =
            apply_command(&TriggerCommand::SetSampleRate { rate: 50 }, &mut state, &mutator, 100);
        assert!(resp.ok);
        assert_eq!(mutator.calls(), vec![(ConfigKey::SampleRate, 50)]);
        assert_eq!(state.sample_rate, 50);
        assert!(state.sampling_active, "active flag must not change on rate-only update");
    }

    #[test]
    fn apply_set_sample_rate_zero_rejected() {
        let mut state = TriggerState::initial(1000, true, "ad-hoc", 0);
        let mutator = MockConfigMutator::new();
        let resp =
            apply_command(&TriggerCommand::SetSampleRate { rate: 0 }, &mut state, &mutator, 0);
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("rate must be >= 1"));
        assert!(mutator.calls().is_empty(), "rejected command must not write to the map");
    }

    // ===========================================
    // apply_command — trigger
    // ===========================================

    #[test]
    fn apply_trigger_writes_all_four_slots_in_order() {
        let mut state = TriggerState::initial(1000, false, "ad-hoc", 0);
        let mutator = MockConfigMutator::new();
        let resp = apply_command(
            &TriggerCommand::Trigger {
                tag: "incident-A".into(),
                rate: 10,
                duration_sec: Some(60),
            },
            &mut state,
            &mutator,
            1_700_000_000,
        );
        assert!(resp.ok);

        let calls = mutator.calls();
        let expected_hash = ibsr_bpf::fnv1a64(b"incident-A");
        assert_eq!(calls.len(), 4);
        // Order must be: rate → tag-hash → trigger-ts → active
        // (active flips last so BPF never reads active=1 with stale
        // rate/tag).
        assert_eq!(calls[0], (ConfigKey::SampleRate, 10));
        assert_eq!(calls[1], (ConfigKey::IncidentTagHash, expected_hash));
        assert_eq!(calls[2], (ConfigKey::TriggerTimestamp, 1_700_000_000));
        assert_eq!(calls[3], (ConfigKey::SamplingActive, 1));

        assert_eq!(state.sample_rate, 10);
        assert!(state.sampling_active);
        assert_eq!(state.incident_tag, "incident-A");
        assert_eq!(state.trigger_ts_unix_sec, 1_700_000_000);
        assert_eq!(state.trigger_deadline_unix_sec, Some(1_700_000_060));
    }

    #[test]
    fn apply_trigger_without_duration_leaves_deadline_none() {
        let mut state = TriggerState::initial(1, false, "x", 0);
        let mutator = MockConfigMutator::new();
        apply_command(
            &TriggerCommand::Trigger {
                tag: "x".into(),
                rate: 10,
                duration_sec: None,
            },
            &mut state,
            &mutator,
            42,
        );
        assert_eq!(state.trigger_deadline_unix_sec, None);
    }

    #[test]
    fn apply_trigger_zero_rate_rejected() {
        let mut state = TriggerState::initial(1000, false, "x", 0);
        let mutator = MockConfigMutator::new();
        let resp = apply_command(
            &TriggerCommand::Trigger {
                tag: "x".into(),
                rate: 0,
                duration_sec: None,
            },
            &mut state,
            &mutator,
            0,
        );
        assert!(!resp.ok);
        assert!(mutator.calls().is_empty());
        assert!(!state.sampling_active);
    }

    #[test]
    fn apply_trigger_invalid_tag_rejected() {
        let mut state = TriggerState::initial(1000, false, "x", 0);
        let mutator = MockConfigMutator::new();
        // Path traversal attempt — must be rejected.
        let resp = apply_command(
            &TriggerCommand::Trigger {
                tag: "../etc/passwd".into(),
                rate: 1,
                duration_sec: None,
            },
            &mut state,
            &mutator,
            0,
        );
        assert!(!resp.ok);
        assert!(mutator.calls().is_empty(),
            "rejected command must not write to the map");
    }

    #[test]
    fn apply_trigger_propagates_mutator_failure_on_active_flip() {
        let mut state = TriggerState::initial(1000, false, "x", 0);
        // Fail the active flip — a partial trigger must surface as ok=false.
        let mutator = MockConfigMutator::new().fail_when(ConfigKey::SamplingActive);
        let resp = apply_command(
            &TriggerCommand::Trigger {
                tag: "ok".into(),
                rate: 1,
                duration_sec: None,
            },
            &mut state,
            &mutator,
            0,
        );
        assert!(!resp.ok);
        // State must reflect that the partial write happened (rate
        // and tag are now divergent from the kernel — that's the
        // honest state). The Stop command can recover.
        assert_eq!(mutator.calls().len(), 3, "rate + tag-hash + ts written; active failed");
    }

    // ===========================================
    // apply_command — stop
    // ===========================================

    #[test]
    fn apply_stop_clears_active_and_deadline() {
        let mut state = TriggerState::initial(10, true, "incident", 0);
        state.trigger_deadline_unix_sec = Some(1000);
        let mutator = MockConfigMutator::new();
        let resp = apply_command(&TriggerCommand::Stop, &mut state, &mutator, 0);
        assert!(resp.ok);
        assert_eq!(mutator.calls(), vec![(ConfigKey::SamplingActive, 0)]);
        assert!(!state.sampling_active);
        assert_eq!(state.trigger_deadline_unix_sec, None);
    }

    #[test]
    fn apply_stop_idempotent_when_already_stopped() {
        let mut state = TriggerState::initial(1000, false, "x", 0);
        let mutator = MockConfigMutator::new();
        let resp = apply_command(&TriggerCommand::Stop, &mut state, &mutator, 0);
        assert!(resp.ok);
        // Still issues the kernel write — defense-in-depth, in case the
        // state and kernel diverged.
        assert_eq!(mutator.calls(), vec![(ConfigKey::SamplingActive, 0)]);
    }

    // ===========================================
    // apply_command — status
    // ===========================================

    #[test]
    fn apply_status_returns_current_state_no_write() {
        let mut state = TriggerState::initial(50, true, "tag-1", 1_700_000_000);
        state.trigger_deadline_unix_sec = Some(1_700_000_300);
        let mutator = MockConfigMutator::new();
        let resp = apply_command(&TriggerCommand::Status, &mut state, &mutator, 0);
        assert!(resp.ok);
        let report = resp.status.expect("status present");
        assert_eq!(report.sampling_active, 1);
        assert_eq!(report.rate, 50);
        assert_eq!(report.tag, "tag-1");
        assert_eq!(report.trigger_ts, 1_700_000_000);
        assert_eq!(report.deadline_ts, Some(1_700_000_300));
        assert!(mutator.calls().is_empty(), "status is read-only");
    }

    // ===========================================
    // check_auto_stop
    // ===========================================

    #[test]
    fn auto_stop_returns_none_before_deadline() {
        let mut state = TriggerState::initial(1, true, "x", 0);
        state.trigger_deadline_unix_sec = Some(1000);
        let mutator = MockConfigMutator::new();
        let resp = check_auto_stop(&mut state, &mutator, 999);
        assert!(resp.is_none());
        assert!(mutator.calls().is_empty());
        assert!(state.sampling_active);
    }

    #[test]
    fn auto_stop_fires_at_or_after_deadline() {
        let mut state = TriggerState::initial(1, true, "x", 0);
        state.trigger_deadline_unix_sec = Some(1000);
        let mutator = MockConfigMutator::new();
        let resp = check_auto_stop(&mut state, &mutator, 1000);
        let resp = resp.expect("auto-stop must fire");
        assert!(resp.ok);
        assert_eq!(mutator.calls(), vec![(ConfigKey::SamplingActive, 0)]);
        assert!(!state.sampling_active);
    }

    #[test]
    fn auto_stop_no_op_when_no_deadline() {
        let mut state = TriggerState::initial(1, true, "x", 0);
        // No deadline set.
        let mutator = MockConfigMutator::new();
        let resp = check_auto_stop(&mut state, &mutator, u64::MAX);
        assert!(resp.is_none());
        assert!(mutator.calls().is_empty());
    }

    #[test]
    fn auto_stop_no_op_when_already_inactive() {
        // Operator sent stop manually before deadline.
        let mut state = TriggerState::initial(1, false, "x", 0);
        state.trigger_deadline_unix_sec = Some(100);
        let mutator = MockConfigMutator::new();
        let resp = check_auto_stop(&mut state, &mutator, 200);
        assert!(resp.is_none());
        assert!(mutator.calls().is_empty(),
            "no double-stop write when already inactive");
    }

    // ===========================================
    // CommandResponse serialisation
    // ===========================================

    #[test]
    fn command_response_ok_serialises_compactly() {
        let r = CommandResponse::ok();
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#"{"ok":true}"#);
    }

    #[test]
    fn command_response_err_serialises_with_error_field() {
        let r = CommandResponse::err("boom");
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#"{"ok":false,"error":"boom"}"#);
    }

    #[test]
    fn command_response_status_serialises_with_status_block() {
        let r = CommandResponse::with_status(StatusReport {
            sampling_active: 1,
            rate: 10,
            tag: "ok".into(),
            trigger_ts: 1,
            deadline_ts: None,
        });
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""status""#));
        assert!(s.contains(r#""rate":10"#));
        assert!(!s.contains("deadline_ts"),
            "deadline_ts none is omitted by skip_serializing_if");
    }

    // ===========================================
    // process_request — orchestrator-side dispatch
    // ===========================================

    #[test]
    fn process_request_replies_with_apply_result() {
        let mutator = MockConfigMutator::new();
        let mut state = TriggerState::initial(1000, false, "x", 0);
        let (tx, rx) = std::sync::mpsc::sync_channel(1);

        let req = PendingRequest {
            cmd: TriggerCommand::SetSampleRate { rate: 10 },
            response_tx: tx,
        };
        let sent = process_request(req, &mut state, &mutator, 0);
        assert!(sent, "response channel still open → send must succeed");

        let resp = rx.try_recv().expect("response delivered");
        assert!(resp.ok);
        assert_eq!(state.sample_rate, 10);
    }

    #[test]
    fn process_request_returns_false_when_response_tx_dropped() {
        let mutator = MockConfigMutator::new();
        let mut state = TriggerState::initial(1000, false, "x", 0);
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        drop(rx); // listener gave up on the response
        let req = PendingRequest {
            cmd: TriggerCommand::Status,
            response_tx: tx,
        };
        let sent = process_request(req, &mut state, &mutator, 0);
        assert!(!sent, "closed response channel → send returns false");
    }

    // ===========================================
    // handle_connection — full protocol round-trip
    // ===========================================

    #[test]
    fn handle_connection_routes_command_via_queue() {
        // Listener thread: receive request via try_recv on its
        // (test-side) Receiver; respond via the carried sender. We
        // simulate the "orchestrator" inline.
        let (req_tx, req_rx) = std::sync::mpsc::channel::<PendingRequest>();
        let input = b"{\"action\":\"set-sample-rate\",\"rate\":42}\n";
        let reader = std::io::BufReader::new(&input[..]);
        let mut output = Vec::new();

        // Spawn a tiny inline "orchestrator" that processes one request
        // then exits.
        let h = std::thread::spawn(move || {
            let req = req_rx.recv().expect("request");
            let mut state = TriggerState::initial(1000, false, "x", 0);
            let mutator = MockConfigMutator::new();
            process_request(req, &mut state, &mutator, 0);
        });

        handle_connection(
            reader,
            &mut output,
            &req_tx,
            std::time::Duration::from_secs(1),
        )
        .expect("handle ok");
        h.join().unwrap();

        let out_str = std::str::from_utf8(&output).unwrap();
        assert!(out_str.contains(r#""ok":true"#),
            "successful command must yield ok=true response: {}", out_str);
        assert!(out_str.ends_with('\n'),
            "response must be newline-terminated: {:?}", out_str);
    }

    #[test]
    fn handle_connection_replies_err_on_invalid_json() {
        // Orchestrator is never consulted for parse errors.
        let (req_tx, _req_rx) = std::sync::mpsc::channel::<PendingRequest>();
        let input = b"not json at all\n";
        let reader = std::io::BufReader::new(&input[..]);
        let mut output = Vec::new();
        handle_connection(
            reader, &mut output, &req_tx,
            std::time::Duration::from_secs(1),
        ).expect("handle ok");

        let out_str = std::str::from_utf8(&output).unwrap();
        assert!(out_str.contains(r#""ok":false"#));
        assert!(out_str.contains("parse error"),
            "must surface parse-error in the response: {}", out_str);
    }

    #[test]
    fn handle_connection_replies_err_on_empty_line() {
        let (req_tx, _req_rx) = std::sync::mpsc::channel::<PendingRequest>();
        let input = b"\n";
        let reader = std::io::BufReader::new(&input[..]);
        let mut output = Vec::new();
        handle_connection(
            reader, &mut output, &req_tx,
            std::time::Duration::from_secs(1),
        ).expect("handle ok");
        let out_str = std::str::from_utf8(&output).unwrap();
        assert!(out_str.contains(r#""ok":false"#));
        assert!(out_str.contains("empty input"));
    }

    #[test]
    fn handle_connection_times_out_when_orchestrator_silent() {
        // Orchestrator receives but never processes the request.
        let (req_tx, req_rx) = std::sync::mpsc::channel::<PendingRequest>();
        let input = b"{\"action\":\"status\"}\n";
        let reader = std::io::BufReader::new(&input[..]);
        let mut output = Vec::new();
        let _keep_alive_rx = req_rx; // keep the channel open
        handle_connection(
            reader, &mut output, &req_tx,
            std::time::Duration::from_millis(50),
        ).expect("handle ok");
        let out_str = std::str::from_utf8(&output).unwrap();
        assert!(out_str.contains("response timeout"));
    }

    #[test]
    fn trigger_socket_server_binds_with_0660_perms() {
        // Pin the design-decision #4 invariant: the socket file must
        // be created with mode 0660 so non-group members can't
        // connect.
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "ibsr-trigger-perms-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let _ = std::fs::remove_file(&path);

        let (req_tx, _req_rx) = std::sync::mpsc::channel::<PendingRequest>();
        let server = TriggerSocketServer::spawn(path.clone(), req_tx).expect("spawn");
        // Read the file's mode after bind. The lower 9 bits should
        // be exactly 0o660 (rw-rw----) — set explicitly by spawn().
        let meta = std::fs::metadata(&path).expect("socket path exists");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o660,
            "trigger socket must be created mode 0660 per design decision #4 (got {:#o})",
            mode,
        );
        drop(server);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn handle_connection_replies_err_when_orchestrator_gone() {
        // Orchestrator-side receiver dropped before request arrives.
        let (req_tx, req_rx) = std::sync::mpsc::channel::<PendingRequest>();
        drop(req_rx);
        let input = b"{\"action\":\"status\"}\n";
        let reader = std::io::BufReader::new(&input[..]);
        let mut output = Vec::new();
        handle_connection(
            reader, &mut output, &req_tx,
            std::time::Duration::from_secs(1),
        ).expect("handle ok");
        let out_str = std::str::from_utf8(&output).unwrap();
        assert!(out_str.contains("orchestrator gone"));
    }
}
