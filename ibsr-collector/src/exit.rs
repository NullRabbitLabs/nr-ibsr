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
    /// No network interface found.
    pub const NO_INTERFACE: i32 = 7;
    /// BPF error (load, attach, map operations).
    pub const BPF_ERROR: i32 = 8;
    /// Interrupted by signal (128 + signal number).
    pub const SIGINT: i32 = 130;
}

/// Map a CommandError to an exit code.
pub fn exit_code(error: &CommandError) -> i32 {
    match error {
        CommandError::InvalidArgument(_) => codes::INVALID_ARGS,
        CommandError::Filesystem(_) => codes::IO_ERROR,
        CommandError::Collector(_) => codes::COLLECTOR_ERROR,
        CommandError::NoInterface => codes::NO_INTERFACE,
        CommandError::Bpf(_) => codes::BPF_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::CliError;
    use crate::CollectorError;
    use ibsr_fs::FsError;

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
        let error =
            CommandError::Collector(CollectorError::Write(FsError::Path("test".to_string())));
        assert_eq!(exit_code(&error), codes::COLLECTOR_ERROR);
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
        assert_eq!(codes::NO_INTERFACE, 7);
        assert_eq!(codes::SIGINT, 130);
    }

    #[test]
    fn test_exit_code_bpf() {
        let error = CommandError::Bpf(ibsr_bpf::BpfError::InsufficientPermissions);
        assert_eq!(exit_code(&error), codes::BPF_ERROR);
    }
}
