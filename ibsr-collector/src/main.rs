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
use ibsr_collector::exit::{codes, exit_code};
use ibsr_collector::logger::{Logger, StderrLogger, Verbosity};
use ibsr_collector::commands::collect_payload::{
    execute_collect_payload, AttachError, TcPayloadAttacher,
};
use ibsr_collector::{execute_collect, Cli, Command, CommandError, RealSleeper, ShutdownFlag};
use ibsr_fs::RealFilesystem;

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Set up shutdown handler for graceful termination on Ctrl+C
    let shutdown = ShutdownFlag::new();

    let result = match cli.command {
        Command::Collect(args) => run_collect(args, &shutdown),
        Command::CollectPayload(args) => run_collect_payload(args, &shutdown),
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
