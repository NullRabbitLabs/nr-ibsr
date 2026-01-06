//! IBSR CLI binary.
//!
//! Entry point for the `ibsr` command-line tool.

use std::process::ExitCode;

use clap::Parser;
use ibsr_clock::SystemClock;
use ibsr_collector::exit::{codes, exit_code};
use ibsr_collector::{execute_collect, Cli, Command, CommandError, RealSleeper, ShutdownFlag};
use ibsr_fs::RealFilesystem;

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Set up shutdown handler for graceful termination on Ctrl+C
    let shutdown = ShutdownFlag::new();

    let result = match cli.command {
        Command::Collect(args) => run_collect(args, &shutdown),
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
    // TODO: Multi-port BPF support - for now use first port
    let map_reader = ibsr_bpf::BpfMapReader::new(
        args.iface.as_deref().unwrap_or("eth0"),
        ports[0],
        args.map_size,
    )?;

    let clock = SystemClock;
    let fs = RealFilesystem;
    let sleeper = RealSleeper::new();

    let result = execute_collect(&args, &map_reader, &clock, &fs, &sleeper, shutdown)?;

    println!(
        "Collected {} IPs in {} cycles, wrote {} snapshots",
        result.total_ips, result.cycles, result.snapshots_written
    );

    Ok(())
}
