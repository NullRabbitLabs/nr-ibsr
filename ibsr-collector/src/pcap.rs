//! Classic pcap-format writer for the `record-incident` subcommand.
//!
//! Per docs/CF-INCIDENT-RECORDING-DESIGN-V1.md §3, the pcap output is
//! classic format (magic `0xa1b2c3d4`, microsecond timestamp
//! resolution, link-layer type `LINKTYPE_ETHERNET`, snaplen 256). This
//! is the universal default — `tcpdump -r packets.pcap` and Wireshark
//! read it without flags.
//!
//! The writer is generic over `std::io::Write` so the encoding is
//! end-to-end testable against a `Vec<u8>` buffer; the production
//! orchestrator wraps a `BufWriter<File>`.

use std::io::{self, Write};

/// Classic pcap magic number — microsecond timestamp resolution,
/// native byte order. The kernel-side `bpf_ktime_get_ns` returns
/// monotonic-clock nanoseconds; userspace converts to (sec, usec)
/// before writing.
pub const PCAP_MAGIC: u32 = 0xa1b2c3d4;

/// Pcap version major.
pub const PCAP_VERSION_MAJOR: u16 = 2;
/// Pcap version minor.
pub const PCAP_VERSION_MINOR: u16 = 4;

/// Link-layer type — Ethernet (1). On `lo`, Linux's TC layer sees a
/// constructed Ethernet header so this is the correct linktype for
/// loopback captures.
pub const LINKTYPE_ETHERNET: u32 = 1;

/// Pcap global header size (24 bytes).
pub const PCAP_GLOBAL_HEADER_SIZE: usize = 24;

/// Pcap per-packet record header size (16 bytes: ts_sec, ts_usec,
/// incl_len, orig_len).
pub const PCAP_RECORD_HEADER_SIZE: usize = 16;

/// Build the 24-byte pcap global header. Pure function; fully testable.
///
/// Layout:
///   0..4   magic         u32 (PCAP_MAGIC)
///   4..6   version_major u16
///   6..8   version_minor u16
///   8..12  thiszone      i32 (0 = GMT)
///   12..16 sigfigs       u32 (0)
///   16..20 snaplen       u32
///   20..24 network       u32 (link-layer type)
pub fn build_global_header(snaplen: u32, linktype: u32) -> [u8; PCAP_GLOBAL_HEADER_SIZE] {
    let mut buf = [0u8; PCAP_GLOBAL_HEADER_SIZE];
    buf[0..4].copy_from_slice(&PCAP_MAGIC.to_le_bytes());
    buf[4..6].copy_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
    buf[6..8].copy_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
    buf[8..12].copy_from_slice(&0i32.to_le_bytes()); // thiszone
    buf[12..16].copy_from_slice(&0u32.to_le_bytes()); // sigfigs
    buf[16..20].copy_from_slice(&snaplen.to_le_bytes());
    buf[20..24].copy_from_slice(&linktype.to_le_bytes());
    buf
}

/// Build a 16-byte pcap record header. `ts_sec` and `ts_usec` are the
/// pcap timestamp; `incl_len` is captured length; `orig_len` is the
/// original on-wire length.
///
/// Pure function; fully testable.
pub fn build_record_header(
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
) -> [u8; PCAP_RECORD_HEADER_SIZE] {
    let mut buf = [0u8; PCAP_RECORD_HEADER_SIZE];
    buf[0..4].copy_from_slice(&ts_sec.to_le_bytes());
    buf[4..8].copy_from_slice(&ts_usec.to_le_bytes());
    buf[8..12].copy_from_slice(&incl_len.to_le_bytes());
    buf[12..16].copy_from_slice(&orig_len.to_le_bytes());
    buf
}

/// Convert a kernel monotonic timestamp `ts_ns` (from
/// `bpf_ktime_get_ns`) plus a userspace-resolved boot anchor into a
/// pcap (sec, usec) pair.
///
/// The anchor is computed once at program start as `(unix_now_ns -
/// monotonic_now_ns)` so subsequent events get a wall-clock timestamp
/// without per-event syscalls.
///
/// Pure function — no clock reads — fully testable.
pub fn ts_ns_to_sec_usec(ts_ns: u64, boot_anchor_ns: i128) -> (u32, u32) {
    let unix_ns = boot_anchor_ns + (ts_ns as i128);
    // Saturating to non-negative — pre-anchor events shouldn't happen
    // in practice (the BPF program uses ktime_get_ns which is positive
    // and grows; the anchor is set during attach), but if a clock
    // skew puts unix_ns negative, clamp to zero rather than wrap.
    let unix_ns = if unix_ns < 0 { 0 } else { unix_ns };
    let sec = (unix_ns / 1_000_000_000) as u32;
    let usec = ((unix_ns % 1_000_000_000) / 1_000) as u32;
    (sec, usec)
}

/// Compute a boot anchor: `unix_now_ns - monotonic_now_ns` in
/// nanoseconds. Production passes real clock reads; tests pin both.
///
/// Returned as `i128` to avoid overflow when subtracting two large
/// `u64` values where one can be larger than the other.
pub fn compute_boot_anchor_ns(unix_now_ns: u64, monotonic_now_ns: u64) -> i128 {
    (unix_now_ns as i128) - (monotonic_now_ns as i128)
}

/// Pcap writer.
///
/// Generic over `Write` so tests can wire a `Vec<u8>` and verify
/// the exact bytes the production path would have flushed to disk.
pub struct PcapWriter<W: Write> {
    inner: W,
    snaplen: u32,
    /// Number of packet records written (excludes the global header).
    written: u64,
}

impl<W: Write> PcapWriter<W> {
    /// Create a pcap writer; immediately writes the global header.
    pub fn new(mut inner: W, snaplen: u32) -> io::Result<Self> {
        let header = build_global_header(snaplen, LINKTYPE_ETHERNET);
        inner.write_all(&header)?;
        Ok(Self {
            inner,
            snaplen,
            written: 0,
        })
    }

    /// Write one packet record. `pkt` length must be ≤ snaplen and ≤
    /// `orig_len`; both invariants are enforced (returns
    /// `io::ErrorKind::InvalidInput` on violation).
    pub fn write_packet(
        &mut self,
        ts_sec: u32,
        ts_usec: u32,
        orig_len: u32,
        pkt: &[u8],
    ) -> io::Result<()> {
        if pkt.len() > self.snaplen as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("pkt len {} exceeds snaplen {}", pkt.len(), self.snaplen),
            ));
        }
        if (pkt.len() as u64) > (orig_len as u64) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "pkt len {} exceeds orig_len {}",
                    pkt.len(),
                    orig_len,
                ),
            ));
        }
        let hdr = build_record_header(ts_sec, ts_usec, pkt.len() as u32, orig_len);
        self.inner.write_all(&hdr)?;
        self.inner.write_all(pkt)?;
        self.written += 1;
        Ok(())
    }

    /// Number of packet records written so far.
    pub fn record_count(&self) -> u64 {
        self.written
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    /// Consume the writer and return the inner writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// Phase 4: rotation-aware packet sink. Implementations either ignore
/// rotation (Phase 1-3 single-pcap mode) or close + reopen at a new
/// tag-partitioned path.
pub trait PacketSink {
    /// Write one packet. Length and orig_len rules match `PcapWriter`.
    fn write_packet(
        &mut self,
        ts_sec: u32,
        ts_usec: u32,
        orig_len: u32,
        pkt: &[u8],
    ) -> std::io::Result<()>;

    /// Rotate to a new pcap target. Closes the current writer
    /// (flushing its buffer) and opens a new pcap at the path the
    /// implementation derives from `tag` + `trigger_ts_unix_sec`.
    /// No-op for sinks that don't support rotation.
    ///
    /// Returns the new target path on success, `None` if the sink
    /// doesn't rotate.
    fn rotate(
        &mut self,
        tag: &str,
        trigger_ts_unix_sec: u64,
    ) -> std::io::Result<Option<std::path::PathBuf>>;

    /// Flush the underlying writer.
    fn flush(&mut self) -> std::io::Result<()>;

    /// Path of the current target file, if known.
    fn current_path(&self) -> Option<&std::path::Path>;
}

/// Single-pcap sink — wraps a `PcapWriter<W>` with no rotation. Tests
/// use this with `Vec<u8>`; Phase 1/2 production wraps a
/// `BufWriter<File>`.
pub struct SimplePacketSink<W: std::io::Write> {
    writer: PcapWriter<W>,
    path: Option<std::path::PathBuf>,
}

impl<W: std::io::Write> SimplePacketSink<W> {
    pub fn new(writer: PcapWriter<W>, path: Option<std::path::PathBuf>) -> Self {
        Self { writer, path }
    }

    /// Borrow the inner writer (for tests that inspect bytes).
    pub fn writer(&self) -> &PcapWriter<W> {
        &self.writer
    }

    /// Mutably borrow the inner writer.
    pub fn writer_mut(&mut self) -> &mut PcapWriter<W> {
        &mut self.writer
    }

    /// Consume the sink and return the inner writer's writer (the
    /// `W` originally passed to `PcapWriter::new`). Used by tests
    /// that inspect the exact pcap bytes the loop produced.
    pub fn into_inner(self) -> W {
        self.writer.into_inner()
    }
}

impl<W: std::io::Write> PacketSink for SimplePacketSink<W> {
    fn write_packet(
        &mut self,
        ts_sec: u32,
        ts_usec: u32,
        orig_len: u32,
        pkt: &[u8],
    ) -> std::io::Result<()> {
        self.writer.write_packet(ts_sec, ts_usec, orig_len, pkt)
    }

    fn rotate(
        &mut self,
        _tag: &str,
        _trigger_ts_unix_sec: u64,
    ) -> std::io::Result<Option<std::path::PathBuf>> {
        // No rotation in Phase 1-3 mode. The loop's rotation attempt
        // is silently ignored; the existing pcap continues to grow.
        Ok(None)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    fn current_path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }
}

/// Compute the per-trigger sub-directory name. Pure function so the
/// rotation logic is testable without I/O.
///
/// Format: `{tag}-{trigger_ts}` — same scheme as the per-invocation
/// run dir in Phase 1, just with a per-trigger ts.
pub fn rotation_dir_name(tag: &str, trigger_ts_unix_sec: u64) -> String {
    format!("{}-{}", tag, trigger_ts_unix_sec)
}

/// Type alias for the writer-factory closure used by
/// `RotatingPcapSink`. Production wires this to "create dirs +
/// open File + wrap BufWriter"; tests use a closure that records
/// paths and produces Vec-backed writers shared via Arc<Mutex<...>>.
pub type WriterFactory =
    Box<dyn FnMut(&std::path::Path) -> std::io::Result<Box<dyn std::io::Write + Send>>>;

/// Rotation-aware pcap sink. On every `rotate(tag, ts)` call, flushes
/// the current pcap and opens a new one at
/// `{out_dir}/{tag}-{ts}/packets.pcap`. The actual file open is
/// delegated to an injectable `WriterFactory`.
///
/// Each rotation produces a complete, well-formed pcap (its own
/// global header) — `tcpdump -r` works on each segment independently.
pub struct RotatingPcapSink {
    out_dir: std::path::PathBuf,
    snaplen: u32,
    current: PcapWriter<Box<dyn std::io::Write + Send>>,
    current_path: std::path::PathBuf,
    factory: WriterFactory,
    rotation_count: u64,
}

impl RotatingPcapSink {
    /// Open the initial pcap and return the sink. `factory(path)` is
    /// called now for the initial file and again on every rotation.
    pub fn open(
        out_dir: std::path::PathBuf,
        initial_path: std::path::PathBuf,
        snaplen: u32,
        mut factory: WriterFactory,
    ) -> std::io::Result<Self> {
        let writer = factory(&initial_path)?;
        let current = PcapWriter::new(writer, snaplen)?;
        Ok(Self {
            out_dir,
            snaplen,
            current,
            current_path: initial_path,
            factory,
            rotation_count: 0,
        })
    }

    /// Total rotations performed since `open` (excluding the initial
    /// open).
    pub fn rotation_count(&self) -> u64 {
        self.rotation_count
    }
}

impl PacketSink for RotatingPcapSink {
    fn write_packet(
        &mut self,
        ts_sec: u32,
        ts_usec: u32,
        orig_len: u32,
        pkt: &[u8],
    ) -> std::io::Result<()> {
        self.current.write_packet(ts_sec, ts_usec, orig_len, pkt)
    }

    fn rotate(
        &mut self,
        tag: &str,
        trigger_ts_unix_sec: u64,
    ) -> std::io::Result<Option<std::path::PathBuf>> {
        // Best-effort flush of the outgoing pcap. The Drop on the
        // replaced PcapWriter will also flush via BufWriter::flush
        // semantics in production.
        self.current.flush().ok();

        let dir_name = rotation_dir_name(tag, trigger_ts_unix_sec);
        let new_path = self.out_dir.join(&dir_name).join("packets.pcap");

        let writer = (self.factory)(&new_path)?;
        let pcap = PcapWriter::new(writer, self.snaplen)?;
        self.current = pcap;
        self.current_path = new_path.clone();
        self.rotation_count += 1;
        Ok(Some(new_path))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.current.flush()
    }

    fn current_path(&self) -> Option<&std::path::Path> {
        Some(&self.current_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_header_magic_is_little_endian_microsecond() {
        let hdr = build_global_header(256, LINKTYPE_ETHERNET);
        // Magic on little-endian platforms is stored as d4 c3 b2 a1.
        assert_eq!(&hdr[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
    }

    #[test]
    fn global_header_versions_are_2_4() {
        let hdr = build_global_header(256, LINKTYPE_ETHERNET);
        assert_eq!(u16::from_le_bytes([hdr[4], hdr[5]]), 2);
        assert_eq!(u16::from_le_bytes([hdr[6], hdr[7]]), 4);
    }

    #[test]
    fn global_header_snaplen_field_position() {
        let hdr = build_global_header(256, LINKTYPE_ETHERNET);
        assert_eq!(u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]), 256);
    }

    #[test]
    fn global_header_linktype_field_position() {
        let hdr = build_global_header(256, LINKTYPE_ETHERNET);
        assert_eq!(u32::from_le_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]), 1);
    }

    #[test]
    fn global_header_size_is_24() {
        assert_eq!(PCAP_GLOBAL_HEADER_SIZE, 24);
        let hdr = build_global_header(256, LINKTYPE_ETHERNET);
        assert_eq!(hdr.len(), 24);
    }

    #[test]
    fn record_header_size_is_16() {
        assert_eq!(PCAP_RECORD_HEADER_SIZE, 16);
        let hdr = build_record_header(1, 2, 3, 4);
        assert_eq!(hdr.len(), 16);
    }

    #[test]
    fn record_header_ts_fields_round_trip() {
        let hdr = build_record_header(1_704_067_200, 123_456, 50, 100);
        assert_eq!(
            u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]),
            1_704_067_200,
        );
        assert_eq!(
            u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]),
            123_456,
        );
        assert_eq!(u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]), 50);
        assert_eq!(
            u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]),
            100,
        );
    }

    #[test]
    fn boot_anchor_compute_basic() {
        // unix=10s, monotonic=5s → anchor = 5s in ns
        let anchor = compute_boot_anchor_ns(10_000_000_000, 5_000_000_000);
        assert_eq!(anchor, 5_000_000_000_i128);
    }

    #[test]
    fn boot_anchor_handles_unix_smaller_than_monotonic() {
        // Pathological case (uninitialised wall clock) — must not panic.
        let anchor = compute_boot_anchor_ns(1, 5_000_000_000);
        assert_eq!(anchor, 1_i128 - 5_000_000_000_i128);
    }

    #[test]
    fn ts_ns_to_sec_usec_basic() {
        // unix=1_700_000_000s + 123_456_789ns
        // anchor = 1_700_000_000s in ns; ts_ns = 123_456_789
        let anchor = 1_700_000_000_i128 * 1_000_000_000;
        let (sec, usec) = ts_ns_to_sec_usec(123_456_789, anchor);
        assert_eq!(sec, 1_700_000_000);
        // 123_456_789 ns / 1000 = 123_456 us (truncates 789 ns)
        assert_eq!(usec, 123_456);
    }

    #[test]
    fn ts_ns_to_sec_usec_zero_anchor() {
        // ts_ns = 1.5s
        let (sec, usec) = ts_ns_to_sec_usec(1_500_000_000, 0);
        assert_eq!(sec, 1);
        assert_eq!(usec, 500_000);
    }

    #[test]
    fn ts_ns_to_sec_usec_clamps_negative_to_zero() {
        // anchor=-1s, ts_ns=0 → unix_ns=-1s → clamp → (0, 0)
        let (sec, usec) = ts_ns_to_sec_usec(0, -1_000_000_000_i128);
        assert_eq!(sec, 0);
        assert_eq!(usec, 0);
    }

    #[test]
    fn pcap_writer_emits_global_header_on_new() {
        let buf: Vec<u8> = Vec::new();
        let writer = PcapWriter::new(buf, 256).expect("new");
        let bytes = writer.into_inner();
        assert_eq!(bytes.len(), PCAP_GLOBAL_HEADER_SIZE);
        assert_eq!(&bytes[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(
            u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            256,
        );
    }

    #[test]
    fn pcap_writer_writes_one_packet_record() {
        let buf: Vec<u8> = Vec::new();
        let mut writer = PcapWriter::new(buf, 256).expect("new");
        let pkt = [0xab; 50];
        writer
            .write_packet(1_704_067_200, 500_000, 50, &pkt)
            .expect("write");
        assert_eq!(writer.record_count(), 1);
        let bytes = writer.into_inner();
        // global header + record header + 50 packet bytes
        assert_eq!(bytes.len(), 24 + 16 + 50);
        // Verify record header at offset 24.
        let rec = &bytes[24..40];
        assert_eq!(u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]), 1_704_067_200);
        assert_eq!(u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]), 500_000);
        assert_eq!(u32::from_le_bytes([rec[8], rec[9], rec[10], rec[11]]), 50);
        assert_eq!(u32::from_le_bytes([rec[12], rec[13], rec[14], rec[15]]), 50);
        // Packet bytes follow.
        assert!(bytes[40..].iter().all(|b| *b == 0xab));
    }

    #[test]
    fn pcap_writer_writes_truncated_record() {
        // wire_len 1500, captured 256 → record header should reflect
        // the asymmetry (incl_len=256, orig_len=1500).
        let buf: Vec<u8> = Vec::new();
        let mut writer = PcapWriter::new(buf, 256).expect("new");
        let pkt = [0xcd; 256];
        writer
            .write_packet(1_704_067_200, 0, 1500, &pkt)
            .expect("write");
        let bytes = writer.into_inner();
        let rec = &bytes[24..40];
        assert_eq!(u32::from_le_bytes([rec[8], rec[9], rec[10], rec[11]]), 256);
        assert_eq!(u32::from_le_bytes([rec[12], rec[13], rec[14], rec[15]]), 1500);
    }

    #[test]
    fn pcap_writer_writes_multiple_records_in_order() {
        let buf: Vec<u8> = Vec::new();
        let mut writer = PcapWriter::new(buf, 256).expect("new");
        for i in 0..5 {
            let pkt = vec![i as u8; 10];
            writer.write_packet(i as u32, 0, 10, &pkt).expect("write");
        }
        assert_eq!(writer.record_count(), 5);
        let bytes = writer.into_inner();
        assert_eq!(bytes.len(), 24 + 5 * (16 + 10));
        // Each record's first byte (after its 16-byte header) is the
        // record index: offset 24 + 16 = 40, then +26 per record.
        for i in 0..5 {
            let pkt_off = 24 + 16 + i * (16 + 10);
            assert_eq!(bytes[pkt_off], i as u8);
        }
    }

    #[test]
    fn pcap_writer_rejects_pkt_larger_than_snaplen() {
        let buf: Vec<u8> = Vec::new();
        let mut writer = PcapWriter::new(buf, 256).expect("new");
        let pkt = vec![0u8; 257];
        let err = writer.write_packet(0, 0, 1500, &pkt).expect_err("oversize");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(writer.record_count(), 0,
            "rejected write must not increment count");
    }

    #[test]
    fn pcap_writer_rejects_pkt_larger_than_orig_len() {
        let buf: Vec<u8> = Vec::new();
        let mut writer = PcapWriter::new(buf, 256).expect("new");
        let pkt = vec![0u8; 100];
        // orig_len smaller than captured — invalid.
        let err = writer.write_packet(0, 0, 50, &pkt).expect_err("invalid");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn pcap_writer_zero_length_pkt_ok() {
        // Edge: zero-length is valid (orig_len 0 too).
        let buf: Vec<u8> = Vec::new();
        let mut writer = PcapWriter::new(buf, 256).expect("new");
        writer.write_packet(0, 0, 0, &[]).expect("zero ok");
        assert_eq!(writer.record_count(), 1);
    }

    // ===========================================
    // Phase 4 — rotation
    // ===========================================

    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    /// Test-only registry: filters new file opens into a path → bytes
    /// shared map. Each rotation writes a fresh entry.
    fn make_test_factory() -> (
        WriterFactory,
        Arc<Mutex<HashMap<PathBuf, Arc<Mutex<Vec<u8>>>>>>,
    ) {
        let registry: Arc<Mutex<HashMap<PathBuf, Arc<Mutex<Vec<u8>>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let registry_for_factory = registry.clone();
        let factory: WriterFactory = Box::new(move |path: &std::path::Path| {
            let buf = Arc::new(Mutex::new(Vec::new()));
            registry_for_factory
                .lock()
                .unwrap()
                .insert(path.to_path_buf(), buf.clone());
            Ok(Box::new(SharedBufWriter(buf)) as Box<dyn std::io::Write + Send>)
        });
        (factory, registry)
    }

    /// Tiny adapter so a Vec inside Arc<Mutex<>> implements Write.
    struct SharedBufWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBufWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn rotation_dir_name_format_matches_run_dir_format() {
        assert_eq!(rotation_dir_name("tag-1", 100), "tag-1-100");
        assert_eq!(rotation_dir_name("incident-A", 1_704_067_200), "incident-A-1704067200");
    }

    #[test]
    fn simple_packet_sink_rotation_is_no_op() {
        let buf: Vec<u8> = Vec::new();
        let writer = PcapWriter::new(buf, 256).expect("new");
        let mut sink = SimplePacketSink::new(writer, None);
        let result = sink.rotate("any", 0).expect("rotate ok");
        assert!(result.is_none(), "simple sink doesn't rotate");
    }

    #[test]
    fn rotating_pcap_sink_writes_initial_pcap() {
        let (factory, registry) = make_test_factory();
        let initial = PathBuf::from("/x/initial-1/packets.pcap");
        let mut sink =
            RotatingPcapSink::open(PathBuf::from("/x"), initial.clone(), 256, factory).unwrap();
        sink.write_packet(0, 0, 4, &[0, 1, 2, 3]).expect("write");
        sink.flush().expect("flush");

        let map = registry.lock().unwrap();
        let entry = map.get(&initial).expect("initial path opened");
        let bytes = entry.lock().unwrap().clone();
        // 24 (global) + 16 (rec) + 4 (pkt) = 44.
        assert_eq!(bytes.len(), 44);
        // Verify magic.
        assert_eq!(&bytes[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
    }

    #[test]
    fn rotating_pcap_sink_creates_new_file_on_rotate() {
        let (factory, registry) = make_test_factory();
        let initial = PathBuf::from("/x/init-1/packets.pcap");
        let mut sink =
            RotatingPcapSink::open(PathBuf::from("/x"), initial.clone(), 256, factory).unwrap();

        let new_path = sink.rotate("incident-A", 1_704_067_200).expect("rotate ok").expect("path");
        assert_eq!(new_path, PathBuf::from("/x/incident-A-1704067200/packets.pcap"));
        assert_eq!(sink.rotation_count(), 1);

        let map = registry.lock().unwrap();
        assert!(map.contains_key(&initial), "initial opened");
        assert!(map.contains_key(&new_path), "post-rotate opened");
    }

    #[test]
    fn rotating_pcap_sink_writes_routed_to_current_file() {
        let (factory, registry) = make_test_factory();
        let initial = PathBuf::from("/x/init-1/packets.pcap");
        let mut sink =
            RotatingPcapSink::open(PathBuf::from("/x"), initial.clone(), 256, factory).unwrap();

        sink.write_packet(0, 0, 1, &[0xaa]).expect("init pkt");
        let new_path = sink.rotate("ev", 50).expect("rotate ok").unwrap();
        sink.write_packet(0, 0, 1, &[0xbb]).expect("post-rotate pkt");
        sink.flush().ok();

        let map = registry.lock().unwrap();
        let initial_bytes = map.get(&initial).unwrap().lock().unwrap().clone();
        let new_bytes = map.get(&new_path).unwrap().lock().unwrap().clone();

        // Initial: global hdr + 1 rec hdr + 1 pkt byte = 41.
        assert_eq!(initial_bytes.len(), 24 + 16 + 1);
        // Post-rotate: same shape, fresh global hdr.
        assert_eq!(new_bytes.len(), 24 + 16 + 1);
        // Post-rotate first packet byte must be 0xbb (not 0xaa) —
        // proves writes route to the new file after rotation.
        assert_eq!(new_bytes[40], 0xbb);
        // And the initial's payload byte stayed 0xaa.
        assert_eq!(initial_bytes[40], 0xaa);
    }

    #[test]
    fn rotating_pcap_sink_multiple_rotations_emit_distinct_dirs() {
        let (factory, registry) = make_test_factory();
        let initial = PathBuf::from("/x/init-1/packets.pcap");
        let mut sink =
            RotatingPcapSink::open(PathBuf::from("/x"), initial.clone(), 256, factory).unwrap();
        sink.rotate("A", 100).unwrap();
        sink.rotate("B", 200).unwrap();
        sink.rotate("C", 300).unwrap();

        let map = registry.lock().unwrap();
        assert!(map.contains_key(&initial));
        assert!(map.contains_key(&PathBuf::from("/x/A-100/packets.pcap")));
        assert!(map.contains_key(&PathBuf::from("/x/B-200/packets.pcap")));
        assert!(map.contains_key(&PathBuf::from("/x/C-300/packets.pcap")));
        assert_eq!(sink.rotation_count(), 3);
    }

    #[test]
    fn rotating_pcap_sink_current_path_updates_after_rotate() {
        let (factory, _registry) = make_test_factory();
        let initial = PathBuf::from("/x/init-1/packets.pcap");
        let mut sink = RotatingPcapSink::open(
            PathBuf::from("/x"),
            initial.clone(),
            256,
            factory,
        )
        .unwrap();
        assert_eq!(sink.current_path().unwrap(), initial.as_path());
        sink.rotate("after", 42).unwrap();
        assert_eq!(
            sink.current_path().unwrap(),
            std::path::Path::new("/x/after-42/packets.pcap"),
        );
    }

    #[test]
    fn pcap_output_is_tcpdump_compatible_layout() {
        // End-to-end pin: write a small pcap, verify byte-exact layout
        // matches the libpcap spec. Shields against accidental
        // reordering or magic flips.
        let buf: Vec<u8> = Vec::new();
        let mut writer = PcapWriter::new(buf, 256).expect("new");
        writer
            .write_packet(1_700_000_000, 1, 4, &[0xde, 0xad, 0xbe, 0xef])
            .expect("write");
        let bytes = writer.into_inner();

        // Total = 24 (global) + 16 (rec hdr) + 4 (pkt) = 44.
        assert_eq!(bytes.len(), 44);
        // Magic at 0..4 (little-endian on the wire).
        assert_eq!(&bytes[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        // Snaplen at 16..20.
        assert_eq!(&bytes[16..20], &256u32.to_le_bytes());
        // Linktype at 20..24.
        assert_eq!(&bytes[20..24], &1u32.to_le_bytes());
        // Record ts_sec at 24..28.
        assert_eq!(&bytes[24..28], &1_700_000_000u32.to_le_bytes());
        // Packet bytes at 40..44.
        assert_eq!(&bytes[40..44], &[0xde, 0xad, 0xbe, 0xef]);
    }
}
