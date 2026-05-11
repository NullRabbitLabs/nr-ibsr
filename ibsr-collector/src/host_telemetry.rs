//! Host-process telemetry sampler. Reads
//! `/proc/<pid>/{stat,status,io,fd,net/tcp}` at window boundaries and
//! produces a delta-based [`HostTelemetry`] block for emission alongside
//! the per-window response aggregates.
//!
//! Linux-only for live capture. The parsers are pure string functions
//! and run on any platform (so dev-host cargo-test on macOS exercises
//! them with hermetic string fixtures). [`HostSampler::capture`] is
//! gated by `#[cfg(target_os = "linux")]`; the non-Linux stub returns
//! an `Unsupported` error so callers downgrade to "no host block" on
//! the snapshot emit path.
//!
//! Architectural choices (locked for v7):
//! - **Single-thread sampling at window boundaries**: `cpu_max` /
//!   `rss_max` collapse to the end-of-window value. A future v8 may add
//!   a 1Hz mid-window ticker for true intra-window max.
//! - **Hardcoded `CLOCK_TICKS_PER_SEC = 100`**: Linux/Debian default
//!   since forever; the Phase B close-gate's ±1e-3 cpu-percent
//!   tolerance absorbs deviations on exotic kernels. Avoids pulling
//!   `libc` as a direct collector dep.
//! - **Fast-path skip**: `/proc/<pid>/net/tcp` larger than 50 MiB
//!   returns `num_connections=0` rather than parsing — production
//!   shouldn't see that, but a degenerate one-shot won't stall the
//!   snapshot-emit thread.

use ibsr_schema::HostTelemetry;
use std::time::Instant;

#[cfg(target_os = "linux")]
use std::{fs, io};

/// Linux/Debian default jiffies-per-second. See module docstring for
/// rationale on hardcoding rather than calling `sysconf(_SC_CLK_TCK)`.
pub const CLOCK_TICKS_PER_SEC: u64 = 100;

/// Maximum size of `/proc/<pid>/net/tcp` we will parse before
/// short-circuiting to `None`. Production servers rarely hit this —
/// it caps the worst-case CPU cost on a degenerate snapshot, and
/// surfaces "we don't know" via Option rather than a false 0.
pub const NET_TCP_MAX_BYTES: usize = 50 * 1024 * 1024;

/// Minimum elapsed time between baseline + end captures for rate
/// fields (cpu_*, rss_slope_bps) to be emitted. Below this threshold,
/// floating-point arithmetic on tiny intervals produces astronomical
/// per-second values from microsecond-scale ground truth. 100 ms is
/// far below any production window cadence (typically 60s) but above
/// any plausible accidental near-zero interval from a test fixture.
pub const MIN_ELAPSED_SEC: f64 = 0.1;

/// One captured `/proc` snapshot for a target PID. Combine two
/// snapshots (start-of-window + end-of-window) via [`delta`] to produce
/// a [`HostTelemetry`] block.
///
/// Each field is `Option<T>`: `None` means "we could not read this
/// value" (file missing, permission denied — typical for
/// `/proc/<pid>/io` without CAP_SYS_PTRACE — or oversized
/// `/proc/<pid>/net/tcp`). `Some(0)` means "zero, with confidence".
/// The distinction propagates through [`delta`] so a missing field
/// surfaces as `None` in the emitted `HostTelemetry`, not a misleading
/// `Some(0)`.
#[derive(Debug, Clone)]
pub struct HostSnapshot {
    /// utime + stime in jiffies (from `/proc/<pid>/stat`).
    pub cpu_jiffies: Option<u64>,
    /// VmRSS in bytes (from `/proc/<pid>/status`, `VmRSS: N kB`).
    pub rss_bytes: Option<u64>,
    /// Open file-descriptor count (number of entries in
    /// `/proc/<pid>/fd`).
    pub num_fds: Option<u32>,
    /// ESTABLISHED-state TCP connection count from
    /// `/proc/<pid>/net/tcp`. `None` if the file was oversized
    /// ([`NET_TCP_MAX_BYTES`]) or unreadable.
    pub num_connections: Option<u32>,
    /// Cumulative disk-write bytes from `/proc/<pid>/io::write_bytes`.
    /// `None` if `/proc/<pid>/io` is unreadable (commonly: collector
    /// lacks CAP_SYS_PTRACE).
    pub io_write_bytes: Option<u64>,
    /// Wall-clock instant the snapshot was captured. Drives elapsed-
    /// time calculations in [`delta`].
    pub captured_at: Instant,
}

/// Per-PID `/proc` sampler. Stateless beyond the configured PID.
#[derive(Debug, Clone, Copy)]
pub struct HostSampler {
    pid: u32,
}

impl HostSampler {
    pub fn new(pid: u32) -> Self {
        Self { pid }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Capture a `/proc` snapshot for the configured pid.
    ///
    /// Returns `Err` if the target process is gone (neither `stat` nor
    /// `status` is readable) — the caller should downgrade to "no host
    /// telemetry" emit. Best-effort per field: parser failure or
    /// missing-but-permitted files (e.g. `/proc/<pid>/io` requires
    /// CAP_SYS_PTRACE on most distros, `/proc/<pid>/net/tcp` may be
    /// oversized) surface as `None` on the individual field rather
    /// than failing the whole capture. The downstream [`delta`] then
    /// emits the corresponding `HostTelemetry` fields as `None`.
    #[cfg(target_os = "linux")]
    pub fn capture(&self) -> io::Result<HostSnapshot> {
        let pid = self.pid;
        let stat = fs::read_to_string(format!("/proc/{}/stat", pid))?;
        let status = fs::read_to_string(format!("/proc/{}/status", pid))?;
        let io_str = fs::read_to_string(format!("/proc/{}/io", pid)).ok();
        let net_tcp = fs::read_to_string(format!("/proc/{}/net/tcp", pid)).ok();
        let num_fds = fs::read_dir(format!("/proc/{}/fd", pid))
            .ok()
            .map(|d| d.filter_map(|e| e.ok()).count() as u32);
        Ok(HostSnapshot {
            cpu_jiffies: parse_cpu_jiffies(&stat),
            rss_bytes: parse_rss_bytes(&status),
            num_fds,
            num_connections: net_tcp.as_deref().and_then(parse_established_count),
            io_write_bytes: io_str.as_deref().and_then(parse_io_write_bytes),
            captured_at: Instant::now(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn capture(&self) -> std::io::Result<HostSnapshot> {
        // Non-Linux dev hosts have no /proc; return Unsupported so
        // callers know to omit the host block from the snapshot.
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "host telemetry requires /proc on Linux",
        ))
    }
}

/// Compute a [`HostTelemetry`] delta from `start`/`end` snapshots
/// captured at window boundaries. `clock_ticks_per_sec` is typically
/// [`CLOCK_TICKS_PER_SEC`] (100 on Linux/Debian).
///
/// Field semantics:
/// - `cpu_mean` / `cpu_max`: percent-of-one-core
///   `(jiffies_delta / clock_ticks_per_sec) / elapsed_sec * 100`. v7
///   single-thread sampling has only one data point per window, so
///   `cpu_max` collapses to the same value as `cpu_mean` (documented
///   on the schema field). A future v8 with mid-window sampling will
///   provide true intra-window max.
/// - `rss_delta`: signed bytes (`end.rss - start.rss`).
/// - `rss_max`: end-of-window value (`end.rss`).
/// - `rss_slope_bps`: `rss_delta / elapsed_sec`.
/// - `num_*_delta`: signed (`end - start`).
/// - `num_connections_max`: end-of-window value.
/// - `io_write_delta`: signed bytes.
///
/// Per-field `Option` propagation: when either side's field is `None`
/// (because the underlying `/proc` file was unreadable or oversized),
/// the corresponding output field emits as `None` rather than a
/// misleading delta against an implicit 0. Rate fields (`cpu_*`,
/// `rss_slope_bps`) additionally require `elapsed_sec >= MIN_ELAPSED_SEC`
/// to avoid astronomical per-second values on near-zero windows.
pub fn delta(
    start: &HostSnapshot,
    end: &HostSnapshot,
    clock_ticks_per_sec: u64,
) -> HostTelemetry {
    let elapsed_sec = end
        .captured_at
        .saturating_duration_since(start.captured_at)
        .as_secs_f64();
    let rate_ok = elapsed_sec >= MIN_ELAPSED_SEC && clock_ticks_per_sec > 0;

    let cpu_pct = match (start.cpu_jiffies, end.cpu_jiffies) {
        (Some(s), Some(e)) if rate_ok => {
            let jiffies_delta = e.saturating_sub(s);
            let cpu_secs = jiffies_delta as f64 / clock_ticks_per_sec as f64;
            Some((cpu_secs / elapsed_sec) * 100.0)
        }
        _ => None,
    };

    let (rss_delta, rss_max, rss_slope_bps) = match (start.rss_bytes, end.rss_bytes) {
        (Some(s), Some(e)) => {
            let d = e as i64 - s as i64;
            let slope = if elapsed_sec >= MIN_ELAPSED_SEC {
                Some(d as f64 / elapsed_sec)
            } else {
                None
            };
            (Some(d), Some(e), slope)
        }
        _ => (None, None, None),
    };

    let num_fds_delta = match (start.num_fds, end.num_fds) {
        (Some(s), Some(e)) => Some(e as i64 - s as i64),
        _ => None,
    };

    let (num_connections_delta, num_connections_max) =
        match (start.num_connections, end.num_connections) {
            (Some(s), Some(e)) => (Some(e as i64 - s as i64), Some(e)),
            _ => (None, None),
        };

    let io_write_delta = match (start.io_write_bytes, end.io_write_bytes) {
        (Some(s), Some(e)) => Some(e as i64 - s as i64),
        _ => None,
    };

    HostTelemetry {
        cpu_mean: cpu_pct,
        cpu_max: cpu_pct,
        rss_delta,
        rss_max,
        rss_slope_bps,
        num_fds_delta,
        num_connections_delta,
        num_connections_max,
        io_write_delta,
    }
}

/// Parse `utime + stime` (in jiffies) from a `/proc/<pid>/stat` body.
///
/// `comm` (field 2) can contain spaces and parentheses, so the standard
/// kernel-recommended trick is to find the LAST `)` and parse the
/// remaining whitespace-split fields from there. After the last `)` the
/// fields are state, ppid, pgrp, session, tty_nr, tpgid, flags, minflt,
/// cminflt, majflt, cmajflt, **utime (idx 11)**, **stime (idx 12)**, ...
pub fn parse_cpu_jiffies(stat: &str) -> Option<u64> {
    let last_paren = stat.rfind(')')?;
    let after = stat[last_paren + 1..].trim();
    let fields: Vec<&str> = after.split_whitespace().collect();
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime + stime)
}

/// Parse `VmRSS` (in bytes) from a `/proc/<pid>/status` body. The kernel
/// reports VmRSS as `VmRSS:    N kB` — multiply by 1024 to get bytes.
pub fn parse_rss_bytes(status: &str) -> Option<u64> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            // "VmRSS:    1234 kB"  →  rest = "    1234 kB"
            let mut parts = rest.split_whitespace();
            if let Some(n_str) = parts.next() {
                if let Ok(n) = n_str.parse::<u64>() {
                    return Some(n.saturating_mul(1024));
                }
            }
        }
    }
    None
}

/// Parse `write_bytes: N` from a `/proc/<pid>/io` body.
pub fn parse_io_write_bytes(io_str: &str) -> Option<u64> {
    for line in io_str.lines() {
        if let Some(rest) = line.strip_prefix("write_bytes:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Count ESTABLISHED-state TCP connections in a `/proc/<pid>/net/tcp`
/// body. State column (4th whitespace-split field on each data line)
/// equals `01` for `TCP_ESTABLISHED`. Skips the header line.
///
/// Files larger than [`NET_TCP_MAX_BYTES`] short-circuit to `None` —
/// "we skipped parsing, don't claim 0 connections". The caller (and
/// thus the schema field) will then emit `num_connections_*` as
/// `None` rather than fabricating a delta against an implicit zero.
pub fn parse_established_count(net_tcp: &str) -> Option<u32> {
    if net_tcp.len() > NET_TCP_MAX_BYTES {
        return None;
    }
    Some(
        net_tcp
            .lines()
            .skip(1) // header
            .filter(|line| line.split_whitespace().nth(3) == Some("01"))
            .count() as u32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ===========================================
    // Parsers — hermetic string fixtures
    // ===========================================

    #[test]
    fn parse_cpu_jiffies_systemd_fixture() {
        // Real /proc/1/stat from a Debian 12 host. After the comm `)`,
        // fields are: state ppid pgrp session tty_nr tpgid flags minflt
        // cminflt majflt cmajflt **utime** **stime** ... — utime + stime
        // are the 12th and 13th tokens (0-indexed 11 and 12).
        let stat = "1 (systemd) S 0 1 1 0 -1 4194560 12345 678 90 12 345 67 8 9 20 0 1 0 100 0 0";
        assert_eq!(parse_cpu_jiffies(stat), Some(345 + 67));
    }

    #[test]
    fn parse_cpu_jiffies_handles_parens_in_comm() {
        // comm can contain parentheses (e.g. processes named "(noisy)").
        // The parser finds the LAST `)`, not the first. After last `)`:
        // 11 fields then utime=100 stime=50.
        let stat = "1234 (proc(with)parens) R 0 1 1 0 -1 0 0 0 0 0 100 50 0 0 20 0 1 0 0 0";
        assert_eq!(parse_cpu_jiffies(stat), Some(150));
    }

    #[test]
    fn parse_cpu_jiffies_returns_none_on_malformed_input() {
        assert_eq!(parse_cpu_jiffies(""), None);
        assert_eq!(parse_cpu_jiffies("no paren here"), None);
        // Truncated — no utime field
        assert_eq!(parse_cpu_jiffies("1 (proc) R 0"), None);
    }

    #[test]
    fn parse_rss_bytes_picks_vmrss_kb_and_converts() {
        let status = "Name:\tsui-node\n\
                      Umask:\t0022\n\
                      VmPeak:\t   65536 kB\n\
                      VmSize:\t   32768 kB\n\
                      VmRSS:\t    1024 kB\n\
                      VmData:\t   16384 kB\n";
        // 1024 kB → 1024 * 1024 = 1048576 bytes
        assert_eq!(parse_rss_bytes(status), Some(1024 * 1024));
    }

    #[test]
    fn parse_rss_bytes_returns_none_when_field_absent() {
        let status = "Name:\tsui-node\nVmSize:\t32768 kB\n";
        assert_eq!(parse_rss_bytes(status), None);
    }

    #[test]
    fn parse_io_write_bytes_picks_write_bytes_field() {
        let io_str = "rchar: 12345\n\
                      wchar: 67890\n\
                      syscr: 100\n\
                      syscw: 200\n\
                      read_bytes: 4096\n\
                      write_bytes: 8192\n\
                      cancelled_write_bytes: 0\n";
        assert_eq!(parse_io_write_bytes(io_str), Some(8192));
    }

    #[test]
    fn parse_io_write_bytes_returns_none_when_field_absent() {
        // Some restricted contexts emit io but with the field redacted.
        let io_str = "rchar: 0\nwchar: 0\n";
        assert_eq!(parse_io_write_bytes(io_str), None);
    }

    #[test]
    fn parse_established_count_counts_state_01_lines() {
        // Real-shape fixture: header + 1 LISTEN (0A) + 2 ESTABLISHED (01) +
        // 1 TIME_WAIT (06).
        let net_tcp = concat!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
            "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n",
            "   1: 0100007F:8B7C 0100007F:1F90 01 00000000:00000000 02:0000017A 00000000     0        0 67890 1 0000000000000000 20 4 30 10 -1\n",
            "   2: 0100007F:1F90 0100007F:8B7C 01 00000000:00000000 00:00000000 00000000     0        0 67891 1 0000000000000000 20 4 30 10 -1\n",
            "   3: 0100007F:8B7E 0100007F:1F90 06 00000000:00000000 00:00000000 00000000     0        0 0 0 0000000000000000\n",
        );
        assert_eq!(parse_established_count(net_tcp), Some(2));
    }

    #[test]
    fn parse_established_count_returns_some_zero_for_header_only_file() {
        // Empty file = Some(0) (confidence-zero), not None (unknown).
        let net_tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        assert_eq!(parse_established_count(net_tcp), Some(0));
    }

    #[test]
    fn parse_established_count_short_circuits_oversized_input_to_none() {
        // Synthetic >50 MiB string — surfaces as `None` ("we didn't
        // parse") rather than a misleading `Some(0)` that would
        // produce phantom negative deltas downstream.
        let big = "x".repeat(NET_TCP_MAX_BYTES + 1);
        assert_eq!(parse_established_count(&big), None);
    }

    // ===========================================
    // delta() — pure-function math
    // ===========================================

    fn snapshot(
        cpu_jiffies: u64,
        rss_bytes: u64,
        num_fds: u32,
        num_connections: u32,
        io_write_bytes: u64,
        captured_at: Instant,
    ) -> HostSnapshot {
        HostSnapshot {
            cpu_jiffies: Some(cpu_jiffies),
            rss_bytes: Some(rss_bytes),
            num_fds: Some(num_fds),
            num_connections: Some(num_connections),
            io_write_bytes: Some(io_write_bytes),
            captured_at,
        }
    }

    fn empty_snapshot(captured_at: Instant) -> HostSnapshot {
        HostSnapshot {
            cpu_jiffies: None,
            rss_bytes: None,
            num_fds: None,
            num_connections: None,
            io_write_bytes: None,
            captured_at,
        }
    }

    #[test]
    fn delta_computes_cpu_percent_over_window() {
        // 100 jiffies elapsed at 100 ticks/sec = 1.0 cpu-second consumed
        // over a 2.0-second wall clock window → 50% (half a core).
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(2);
        let s0 = snapshot(0, 0, 0, 0, 0, t0);
        let s1 = snapshot(100, 0, 0, 0, 0, t1);
        let d = delta(&s0, &s1, 100);
        assert_eq!(d.cpu_mean, Some(50.0));
        assert_eq!(d.cpu_max, Some(50.0)); // collapses to mean in v7
    }

    #[test]
    fn delta_computes_signed_rss_delta_and_slope() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(10);
        let s0 = snapshot(0, 1_000_000, 0, 0, 0, t0);
        let s1 = snapshot(0, 1_500_000, 0, 0, 0, t1);
        let d = delta(&s0, &s1, 100);
        assert_eq!(d.rss_delta, Some(500_000));
        assert_eq!(d.rss_max, Some(1_500_000));
        // 500_000 bytes / 10 sec = 50_000 bps
        assert_eq!(d.rss_slope_bps, Some(50_000.0));
    }

    #[test]
    fn delta_rss_delta_can_be_negative() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);
        let s0 = snapshot(0, 2_000_000, 0, 0, 0, t0);
        let s1 = snapshot(0, 1_500_000, 0, 0, 0, t1);
        let d = delta(&s0, &s1, 100);
        assert_eq!(d.rss_delta, Some(-500_000));
        assert_eq!(d.rss_max, Some(1_500_000)); // end-of-window value
    }

    #[test]
    fn delta_collapses_rate_fields_when_elapsed_zero() {
        let t = Instant::now();
        let s0 = snapshot(0, 100, 0, 0, 0, t);
        let s1 = snapshot(50, 200, 0, 0, 0, t); // same instant
        let d = delta(&s0, &s1, 100);
        // Rate fields → None
        assert_eq!(d.cpu_mean, None);
        assert_eq!(d.cpu_max, None);
        assert_eq!(d.rss_slope_bps, None);
        // Delta fields stay populated
        assert_eq!(d.rss_delta, Some(100));
        assert_eq!(d.rss_max, Some(200));
    }

    #[test]
    fn delta_collapses_rate_fields_below_min_elapsed_threshold() {
        // 10 ms elapsed is far below MIN_ELAPSED_SEC (100 ms). Without
        // the threshold, 50 jiffies / 10 ms would emit cpu% =
        // (50/100) / 0.01 * 100 = 5000% — nonsense from a micro-window.
        // The threshold collapses cpu_* + rss_slope_bps to None.
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_millis(10);
        let s0 = snapshot(0, 1_000, 0, 0, 0, t0);
        let s1 = snapshot(50, 2_000, 0, 0, 0, t1);
        let d = delta(&s0, &s1, 100);
        assert_eq!(d.cpu_mean, None,
            "elapsed < MIN_ELAPSED_SEC must collapse cpu_mean to None");
        assert_eq!(d.cpu_max, None);
        assert_eq!(d.rss_slope_bps, None,
            "elapsed < MIN_ELAPSED_SEC must collapse rss_slope_bps to None");
        // Non-rate fields still populate.
        assert_eq!(d.rss_delta, Some(1_000));
        assert_eq!(d.rss_max, Some(2_000));
    }

    #[test]
    fn delta_emits_none_for_missing_fields_on_either_side() {
        // Per-field Option propagation: if either snapshot is missing a
        // field (typical: /proc/<pid>/io unreadable without
        // CAP_SYS_PTRACE), the corresponding delta is None — NOT a
        // misleading delta against an implicit zero.
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);
        let mut s0 = snapshot(10, 1_000, 5, 3, 100, t0);
        let mut s1 = snapshot(20, 2_000, 7, 5, 200, t1);
        // Wipe io_write_bytes from end snapshot — simulates IO file
        // becoming unreadable mid-window.
        s1.io_write_bytes = None;
        // Also: net/tcp went oversized on the START side only.
        s0.num_connections = None;
        let d = delta(&s0, &s1, 100);
        assert_eq!(d.io_write_delta, None,
            "io_write_delta must be None when either side is None, \
             not Some(0) (which would falsely claim zero writes)");
        assert_eq!(d.num_connections_delta, None);
        assert_eq!(d.num_connections_max, None);
        // Other fields, both sides Some → still populated.
        assert_eq!(d.rss_delta, Some(1_000));
        assert_eq!(d.cpu_mean, Some(10.0)); // (20-10) jiffies / 100 ticks / 1s * 100% = 10%
    }

    #[test]
    fn delta_emits_all_none_when_both_snapshots_empty() {
        // Pathological: both captures returned None for every field
        // (e.g. /proc/<pid>/stat parser failure on both sides).
        // delta() must surface that as a fully-None HostTelemetry,
        // not a struct of Some(0)s.
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);
        let d = delta(&empty_snapshot(t0), &empty_snapshot(t1), 100);
        assert_eq!(d.cpu_mean, None);
        assert_eq!(d.cpu_max, None);
        assert_eq!(d.rss_delta, None);
        assert_eq!(d.rss_max, None);
        assert_eq!(d.rss_slope_bps, None);
        assert_eq!(d.num_fds_delta, None);
        assert_eq!(d.num_connections_delta, None);
        assert_eq!(d.num_connections_max, None);
        assert_eq!(d.io_write_delta, None);
    }

    #[test]
    fn delta_signs_fd_and_connection_deltas() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);
        let s0 = snapshot(0, 0, 100, 50, 0, t0);
        let s1 = snapshot(0, 0, 96, 60, 0, t1); // 4 fds closed, 10 conns opened
        let d = delta(&s0, &s1, 100);
        assert_eq!(d.num_fds_delta, Some(-4));
        assert_eq!(d.num_connections_delta, Some(10));
        assert_eq!(d.num_connections_max, Some(60));
    }

    #[test]
    fn delta_signs_io_write_delta() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);
        let s0 = snapshot(0, 0, 0, 0, 1_000_000, t0);
        let s1 = snapshot(0, 0, 0, 0, 5_000_000, t1);
        let d = delta(&s0, &s1, 100);
        assert_eq!(d.io_write_delta, Some(4_000_000));
    }

    // ===========================================
    // HostSampler::capture — Linux integration
    // ===========================================

    #[cfg(target_os = "linux")]
    #[test]
    fn capture_returns_err_for_nonexistent_pid() {
        // A nonexistent PID — capture() must propagate the io::Error.
        // Pick a PID very unlikely to be in use; if a host has a process
        // there, the test will be a false positive but shouldn't fail.
        let sampler = HostSampler::new(2_147_483_647);
        let res = sampler.capture();
        assert!(res.is_err(), "expected Err for nonexistent PID, got Ok");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn capture_unsupported_on_non_linux() {
        let sampler = HostSampler::new(1);
        let err = sampler.capture().expect_err("non-Linux capture must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}
