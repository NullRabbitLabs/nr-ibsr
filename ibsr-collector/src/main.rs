//! IBSR CLI binary.
//!
//! Entry point for the `ibsr` command-line tool.

use std::process::ExitCode;

use clap::Parser;
use ibsr_clock::SystemClock;
use ibsr_collector::exit::{codes, exit_code};
use ibsr_collector::{
    execute_collect, execute_report, execute_run, Cli, Command, CommandError, RealSleeper,
    ShutdownFlag,
};
use ibsr_fs::RealFilesystem;

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Set up shutdown handler for graceful termination on Ctrl+C
    let shutdown = ShutdownFlag::new();

    let result = match cli.command {
        Command::Collect(args) => run_collect(args, &shutdown),
        Command::Report(args) => run_report(args),
        Command::Run(args) => run_run(args, &shutdown),
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
    let map_reader = ibsr_bpf::BpfMapReader::new(
        args.iface.as_deref().unwrap_or("eth0"),
        args.dst_port,
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

/// Run the report command.
fn run_report(args: ibsr_collector::ReportArgs) -> Result<(), CommandError> {
    let clock = SystemClock;
    let fs = RealFilesystem;

    let result = execute_report(&args, &fs, &clock)?;

    println!("Report generated:");
    println!("  Snapshots processed: {}", result.snapshot_count);
    println!("  Offenders detected: {}", result.offender_count);
    println!("  Safe for deployment: {}", result.is_safe);
    println!();
    println!("Output files:");
    println!("  Report: {}", result.report_path.display());
    println!("  Rules: {}", result.rules_path.display());
    println!("  Evidence: {}", result.evidence_path.display());

    Ok(())
}

/// Run the run command (collect + report).
fn run_run(
    args: ibsr_collector::RunArgs,
    shutdown: &ShutdownFlag,
) -> Result<(), CommandError> {
    let map_reader = ibsr_bpf::BpfMapReader::new(
        args.iface.as_deref().unwrap_or("eth0"),
        args.dst_port,
        args.map_size,
    )?;

    let clock = SystemClock;
    let fs = RealFilesystem;
    let sleeper = RealSleeper::new();

    let result = execute_run(&args, &map_reader, &clock, &fs, &sleeper, shutdown)?;

    println!("Collection phase:");
    println!(
        "  Collected {} IPs in {} cycles",
        result.collect.total_ips, result.collect.cycles
    );
    println!();
    println!("Report phase:");
    println!("  Snapshots processed: {}", result.report.snapshot_count);
    println!("  Offenders detected: {}", result.report.offender_count);
    println!("  Safe for deployment: {}", result.report.is_safe);
    println!();
    println!("Output files:");
    println!("  Report: {}", result.report.report_path.display());
    println!("  Rules: {}", result.report.rules_path.display());
    println!("  Evidence: {}", result.report.evidence_path.display());

    Ok(())
}
