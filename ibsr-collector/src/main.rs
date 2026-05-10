//! IBSR CLI binary.
//!
//! Entry point for the `ibsr` command-line tool.

use std::process::ExitCode;

/// Git commit hash captured at build time.
const GIT_HASH: &str = env!("GIT_HASH");
/// Build timestamp in ISO 8601 format.
const BUILD_TIME: &str = env!("BUILD_TIME");

use clap::Parser;
use ibsr_clock::SystemClock;
use ibsr_collector::commands::collect_payload::{
    execute_collect_payload, AttachError, TcPayloadAttacher,
};
use ibsr_collector::commands::record_incident::{
    compute_boot_anchor_now, execute_record_incident, AttachConfig, PacketEventSource,
    RecordIncidentAttacher,
};
use ibsr_collector::exit::{codes, exit_code};
use ibsr_collector::logger::{Logger, StderrLogger, Verbosity};
use ibsr_collector::pcap::{PacketSink, PcapWriter, RotatingPcapSink, SimplePacketSink, WriterFactory};
use ibsr_collector::{execute_collect, Cli, Command, CommandError, RealSleeper, ShutdownFlag};
use ibsr_fs::RealFilesystem;

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Set up shutdown handler for graceful termination on Ctrl+C
    let shutdown = ShutdownFlag::new();

    let result = match cli.command {
        Command::Collect(args) => run_collect(args, &shutdown),
        Command::CollectPayload(args) => run_collect_payload(args, &shutdown),
        Command::RecordIncident(args) => run_record_incident(args, &shutdown),
    };

    match result {
        Ok(()) => ExitCode::from(codes::SUCCESS as u8),
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::from(exit_code(&e) as u8)
        }
    }
}

/// Run the collect command.
fn run_collect(
    args: ibsr_collector::CollectArgs,
    shutdown: &ShutdownFlag,
) -> Result<(), CommandError> {
    let ports = args.get_all_ports();
    let interface = args.iface.as_deref().unwrap_or("eth0");
    let logger = StderrLogger::new(Verbosity::from_count(args.verbose));

    // Print version info with -vv
    logger.debug(&format!(
        "ibsr {} ({} built {})",
        env!("CARGO_PKG_VERSION"),
        GIT_HASH,
        BUILD_TIME
    ));

    let map_reader = ibsr_bpf::BpfMapReader::new(interface, &ports)?;

    // Log successful XDP attachment
    logger.info(&format!(
        "XDP program attached to interface '{}'",
        map_reader.interface()
    ));

    let clock = SystemClock;
    let fs = RealFilesystem;
    let sleeper = RealSleeper::new();

    let result = execute_collect(&args, &map_reader, &clock, &fs, &sleeper, shutdown, &logger)?;

    println!(
        "Collected {} IPs in {} cycles, wrote {} snapshots",
        result.total_ips, result.cycles, result.snapshots_written
    );

    Ok(())
}

/// Production TC payload attacher backed by libbpf-rs.
///
/// Loads the BPF skeleton, creates the clsact qdisc on the configured
/// interface, attaches the TC ingress + egress programs, programs the
/// port-filter map, sets up the ringbuf consumer. On any failure
/// during attach, partial state is unwound by Drop on the values
/// declared so far (qdisc destroy, hook detach, skel free).
struct LibbpfTcPayloadAttacher;

impl TcPayloadAttacher for LibbpfTcPayloadAttacher {
    type Source = ibsr_bpf::LibbpfPayloadCollector;

    fn attach(self, iface: &str, ports: &[u16]) -> Result<Self::Source, AttachError> {
        let resolver = ibsr_bpf::NixInterfaceResolver;
        ibsr_bpf::LibbpfPayloadCollector::attach(iface, ports, &resolver).map_err(|e| {
            // Map TcPayloadLoaderError variants to AttachError variants
            // so the user sees a kernel-failure-mode-specific message.
            use ibsr_bpf::TcPayloadLoaderError as E;
            match e {
                E::InterfaceNotFound(name) => AttachError::InterfaceNotFound(name),
                E::BpfLoad(reason) => AttachError::BpfLoad(reason),
                E::Qdisc { iface, reason } => AttachError::TcQdisc { iface, reason },
                E::Attach { direction, reason } => {
                    AttachError::TcAttach(format!("{}: {}", direction, reason))
                }
                E::MapProgram(reason) => AttachError::MapProgram(reason),
                E::Ringbuf(reason) => AttachError::Ringbuf(reason),
                E::RingbufPoll(reason) => AttachError::Other(format!("ringbuf poll: {}", reason)),
                E::TooManyPorts(n) => {
                    AttachError::Other(format!("too many ports ({}); max 8", n))
                }
            }
        })
    }
}

/// Run the collect-payload command (ShadowPayload mode).
fn run_collect_payload(
    args: ibsr_collector::CollectPayloadArgs,
    shutdown: &ShutdownFlag,
) -> Result<(), CommandError> {
    let logger = StderrLogger::new(Verbosity::from_count(args.verbose));

    logger.debug(&format!(
        "ibsr {} ({} built {})",
        env!("CARGO_PKG_VERSION"),
        GIT_HASH,
        BUILD_TIME
    ));

    let clock = SystemClock;
    let fs = RealFilesystem;
    let attacher = LibbpfTcPayloadAttacher;

    let result = execute_collect_payload(&args, attacher, &clock, &fs, shutdown, &logger)?;

    println!(
        "payload collection complete: {} windows ok, {} windows failed, \
         {} pairs total ({} decode errors, {} source errors, {} filtered)",
        result.loop_result.windows_completed,
        result.loop_result.windows_failed,
        result.loop_result.total_pairs,
        result.loop_result.total_decode_errors,
        result.loop_result.total_source_errors,
        result.loop_result.total_events_filtered,
    );
    println!("snapshots written to: {}", result.run_dir.display());

    Ok(())
}

/// Production wrapper around `LibbpfRecordIncidentCollector` that
/// adapts it to the `PacketEventSource` trait expected by the
/// orchestrator. Internal poll = ringbuf pump; drain = collector's
/// PendingEvents drain.
struct LibbpfRecordIncidentSource {
    inner: ibsr_bpf::LibbpfRecordIncidentCollector,
}

impl PacketEventSource for LibbpfRecordIncidentSource {
    fn poll(&mut self, timeout: std::time::Duration) -> Result<(), String> {
        self.inner.pump(timeout).map_err(|e| e.to_string())
    }

    fn drain_events(&mut self) -> Vec<Vec<u8>> {
        self.inner.pending().drain()
    }
}

impl ibsr_collector::trigger_socket::ConfigMutator for LibbpfRecordIncidentSource {
    fn set_config(
        &self,
        key: ibsr_bpf::ConfigKey,
        value: u64,
    ) -> Result<(), String> {
        self.inner.set_config(key, value).map_err(|e| e.to_string())
    }
}

/// Production attacher for the record-incident BPF program.
struct LibbpfRecordIncidentAttacher;

impl RecordIncidentAttacher for LibbpfRecordIncidentAttacher {
    type Source = LibbpfRecordIncidentSource;

    fn attach(self, cfg: &AttachConfig) -> Result<Self::Source, AttachError> {
        let resolver = ibsr_bpf::NixInterfaceResolver;
        ibsr_bpf::LibbpfRecordIncidentCollector::attach_with_config(
            &cfg.iface,
            cfg.sample_rate,
            cfg.sampling_active,
            &cfg.incident_tag,
            cfg.trigger_timestamp_unix_sec,
            &resolver,
        )
            .map(|inner| LibbpfRecordIncidentSource { inner })
            .map_err(|e| {
                use ibsr_bpf::TcPayloadLoaderError as E;
                match e {
                    E::InterfaceNotFound(name) => AttachError::InterfaceNotFound(name),
                    E::BpfLoad(reason) => AttachError::BpfLoad(reason),
                    E::Qdisc { iface, reason } => AttachError::TcQdisc { iface, reason },
                    E::Attach { direction, reason } => {
                        AttachError::TcAttach(format!("{}: {}", direction, reason))
                    }
                    E::MapProgram(reason) => AttachError::MapProgram(reason),
                    E::Ringbuf(reason) => AttachError::Ringbuf(reason),
                    E::RingbufPoll(reason) => AttachError::Other(format!("ringbuf poll: {}", reason)),
                    E::TooManyPorts(n) => AttachError::Other(format!("too many ports ({}); max 8", n)),
                }
            })
    }
}

/// Run the record-incident command (CF-style sampled capture).
fn run_record_incident(
    args: ibsr_collector::RecordIncidentArgs,
    shutdown: &ShutdownFlag,
) -> Result<(), CommandError> {
    use std::io::BufWriter;

    let logger = StderrLogger::new(Verbosity::from_count(args.verbose));

    logger.debug(&format!(
        "ibsr {} ({} built {})",
        env!("CARGO_PKG_VERSION"),
        GIT_HASH,
        BUILD_TIME
    ));

    let clock = SystemClock;
    let fs = RealFilesystem;

    args.validate()?;

    // Mirror the run-dir layout that execute_record_incident will
    // construct, but create the dir up-front so the file-open below
    // succeeds. `execute_record_incident` calls `fs.create_dir_all`
    // again — that's idempotent on RealFilesystem.
    use ibsr_clock::Clock;
    let run_ts = clock.now_unix_sec();
    let run_dir_name = format!("{}-{}", args.tag, run_ts);
    let run_dir = args.out_dir.join(&run_dir_name);
    std::fs::create_dir_all(&run_dir)
        .map_err(|e| CommandError::NotImplemented(format!("create out dir: {}", e)))?;

    let pcap_path = run_dir.join("packets.pcap");

    // Factory used both for the initial open and (in trigger-socket
    // mode) for subsequent rotations. Production: ensure parent dir
    // exists, open/truncate the file, wrap in BufWriter.
    let factory: WriterFactory = Box::new(|path: &std::path::Path| {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        Ok(Box::new(BufWriter::new(f)) as Box<dyn std::io::Write + Send>)
    });

    // Sink choice: RotatingPcapSink when --trigger-socket is enabled
    // (per-trigger partition); SimplePacketSink otherwise (single
    // pcap for the whole run).
    let mut sink: Box<dyn PacketSink> = if args.trigger_socket.is_some() {
        let s = RotatingPcapSink::open(
            args.out_dir.clone(),
            pcap_path.clone(),
            ibsr_bpf::RECORD_SNAPLEN_BYTES as u32,
            factory,
        )
        .map_err(|e| CommandError::NotImplemented(format!("open initial pcap: {}", e)))?;
        Box::new(s)
    } else {
        // Static-rate mode: open once via the factory.
        let mut f = factory;
        let writer = f(&pcap_path)
            .map_err(|e| CommandError::NotImplemented(format!("open pcap: {}", e)))?;
        let pcap = PcapWriter::new(writer, ibsr_bpf::RECORD_SNAPLEN_BYTES as u32)
            .map_err(|e| CommandError::NotImplemented(format!("pcap header: {}", e)))?;
        Box::new(SimplePacketSink::new(pcap, Some(pcap_path.clone())))
    };

    let boot_anchor_ns = compute_boot_anchor_now()
        .map_err(|e| CommandError::NotImplemented(format!("boot anchor: {}", e)))?;

    let attacher = LibbpfRecordIncidentAttacher;

    // Trigger-socket plumbing — only when --trigger-socket is set.
    // The listener thread sends parsed commands via the channel; the
    // orchestrator drains it each loop tick.
    use ibsr_collector::commands::record_incident::TriggerInputs;
    use ibsr_collector::trigger_socket::{
        PendingRequest, TriggerSocketServer, TriggerState,
    };
    let mut trigger_state = TriggerState::initial(args.sample_rate, true, &args.tag, run_ts);
    let (req_tx, req_rx) = std::sync::mpsc::channel::<PendingRequest>();
    let _socket_server = if let Some(socket_path) = args.trigger_socket.clone() {
        match TriggerSocketServer::spawn(socket_path.clone(), req_tx) {
            Ok(server) => {
                logger.info(&format!(
                    "trigger socket listening at {}",
                    socket_path.display(),
                ));
                Some(server)
            }
            Err(e) => {
                return Err(CommandError::NotImplemented(format!(
                    "trigger socket bind failed at {:?}: {}",
                    socket_path, e,
                )));
            }
        }
    } else {
        None
    };
    let triggers = if _socket_server.is_some() {
        Some(TriggerInputs {
            state: &mut trigger_state,
            request_rx: &req_rx,
        })
    } else {
        None
    };

    let result = execute_record_incident(
        &args,
        attacher,
        &clock,
        &fs,
        shutdown,
        &logger,
        sink.as_mut(),
        pcap_path,
        boot_anchor_ns,
        triggers,
    )?;

    println!(
        "record-incident complete: {} events written ({} decode errors, \
         {} write errors, {} poll errors, {} rotations, {} scrubbed)",
        result.events_written,
        result.events_decode_errors,
        result.events_write_errors,
        result.poll_errors,
        result.rotations,
        result.events_scrubbed,
    );
    println!("pcap written to: {}", result.pcap_path.display());

    Ok(())
}
