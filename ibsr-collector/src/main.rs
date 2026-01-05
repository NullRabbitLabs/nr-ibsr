//! IBSR CLI binary.
//!
//! Entry point for the `ibsr` command-line tool.

use std::process::ExitCode;

use clap::Parser;
use ibsr_clock::SystemClock;
use ibsr_collector::exit::{codes, exit_code};
use ibsr_collector::{
    execute_collect, execute_report, execute_run, Cli, Command, CommandError,
};
use ibsr_fs::RealFilesystem;

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Collect(args) => run_collect(args),
        Command::Report(args) => run_report(args),
        Command::Run(args) => run_run(args),
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
fn run_collect(args: ibsr_collector::CollectArgs) -> Result<(), CommandError> {
    // Note: In a real implementation, this would use a real BPF map reader.
    // For now, we use a stub that returns empty data.
    // The actual BPF integration will be implemented in Phase 4.
    let map_reader = ibsr_bpf::MockMapReader::new();
    let clock = SystemClock;
    let fs = RealFilesystem;

    let result = execute_collect(&args, &map_reader, &clock, &fs)?;

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
fn run_run(args: ibsr_collector::RunArgs) -> Result<(), CommandError> {
    // Note: In a real implementation, this would use a real BPF map reader.
    let map_reader = ibsr_bpf::MockMapReader::new();
    let clock = SystemClock;
    let fs = RealFilesystem;

    let result = execute_run(&args, &map_reader, &clock, &fs)?;

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
