//! Exit codes for the IBSR CLI.
//!
//! Following Unix conventions for exit codes.

use crate::commands::CommandError;

/// Exit code constants.
pub mod codes {
    /// Successful execution.
    pub const SUCCESS: i32 = 0;
    /// Invalid arguments.
    pub const INVALID_ARGS: i32 = 1;
    /// IO error.
    pub const IO_ERROR: i32 = 2;
    /// Collector error.
    pub const COLLECTOR_ERROR: i32 = 3;
    /// Reporter error.
    pub const REPORTER_ERROR: i32 = 4;
    /// No snapshots found.
    pub const NO_SNAPSHOTS: i32 = 5;
    /// Allowlist parse error.
    pub const ALLOWLIST_ERROR: i32 = 6;
    /// No network interface found.
    pub const NO_INTERFACE: i32 = 7;
    /// Interrupted by signal (128 + signal number).
    pub const SIGINT: i32 = 130;
}

/// Map a CommandError to an exit code.
pub fn exit_code(error: &CommandError) -> i32 {
    match error {
        CommandError::InvalidArgument(_) => codes::INVALID_ARGS,
        CommandError::Filesystem(_) => codes::IO_ERROR,
        CommandError::Collector(_) => codes::COLLECTOR_ERROR,
        CommandError::Ingest(_) => codes::REPORTER_ERROR,
        CommandError::Allowlist(_) => codes::ALLOWLIST_ERROR,
        CommandError::Output(_) => codes::IO_ERROR,
        CommandError::NoSnapshots(_) => codes::NO_SNAPSHOTS,
        CommandError::NoInterface => codes::NO_INTERFACE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::CliError;
    use crate::io::AllowlistLoadError;
    use crate::CollectorError;
    use ibsr_fs::FsError;
    use ibsr_reporter::ingest::IngestError;

    #[test]
    fn test_exit_code_invalid_argument() {
        let error = CommandError::InvalidArgument(CliError::InvalidPort(0));
        assert_eq!(exit_code(&error), codes::INVALID_ARGS);
    }

    #[test]
    fn test_exit_code_filesystem() {
        let error = CommandError::Filesystem(FsError::Path("test".to_string()));
        assert_eq!(exit_code(&error), codes::IO_ERROR);
    }

    #[test]
    fn test_exit_code_collector() {
        let error = CommandError::Collector(CollectorError::Write(FsError::Path("test".to_string())));
        assert_eq!(exit_code(&error), codes::COLLECTOR_ERROR);
    }

    #[test]
    fn test_exit_code_ingest() {
        let error = CommandError::Ingest(IngestError::NoSnapshots);
        assert_eq!(exit_code(&error), codes::REPORTER_ERROR);
    }

    #[test]
    fn test_exit_code_allowlist() {
        let error = CommandError::Allowlist(AllowlistLoadError::Read(FsError::Path("test".to_string())));
        assert_eq!(exit_code(&error), codes::ALLOWLIST_ERROR);
    }

    #[test]
    fn test_exit_code_no_snapshots() {
        let error = CommandError::NoSnapshots("/tmp".to_string());
        assert_eq!(exit_code(&error), codes::NO_SNAPSHOTS);
    }

    #[test]
    fn test_exit_code_no_interface() {
        let error = CommandError::NoInterface;
        assert_eq!(exit_code(&error), codes::NO_INTERFACE);
    }

    #[test]
    fn test_exit_codes_constants() {
        assert_eq!(codes::SUCCESS, 0);
        assert_eq!(codes::INVALID_ARGS, 1);
        assert_eq!(codes::IO_ERROR, 2);
        assert_eq!(codes::COLLECTOR_ERROR, 3);
        assert_eq!(codes::REPORTER_ERROR, 4);
        assert_eq!(codes::NO_SNAPSHOTS, 5);
        assert_eq!(codes::ALLOWLIST_ERROR, 6);
        assert_eq!(codes::NO_INTERFACE, 7);
        assert_eq!(codes::SIGINT, 130);
    }
}
