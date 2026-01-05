//! Allowlist file loader.
//!
//! Parses allowlist files containing IP addresses and CIDR blocks.
//! Format:
//! - One entry per line
//! - Lines starting with # are comments
//! - Empty lines are ignored
//! - IP addresses: 10.0.0.1
//! - CIDR blocks: 192.168.0.0/24

use std::path::Path;

use ibsr_fs::{Filesystem, FsError};
use ibsr_reporter::config::{Allowlist, AllowlistError};
use thiserror::Error;

/// Errors from allowlist loading.
#[derive(Debug, Error)]
pub enum AllowlistLoadError {
    #[error("failed to read allowlist file: {0}")]
    Read(#[from] FsError),

    #[error("invalid entry on line {line}: {source}")]
    Parse {
        line: usize,
        #[source]
        source: AllowlistError,
    },
}

/// Load an allowlist from a file.
///
/// File format:
/// - Lines starting with # are comments
/// - Empty lines are ignored
/// - IP addresses: 10.0.0.1
/// - CIDR blocks: 192.168.0.0/24
pub fn load_allowlist<F: Filesystem>(
    fs: &F,
    path: &Path,
) -> Result<Allowlist, AllowlistLoadError> {
    let content = fs.read_file(path)?;
    parse_allowlist(&content)
}

/// Parse allowlist content from a string.
///
/// This is the core parsing logic, separated for testability.
pub fn parse_allowlist(content: &str) -> Result<Allowlist, AllowlistLoadError> {
    let mut allowlist = Allowlist::empty();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Determine if it's a CIDR or IP
        if trimmed.contains('/') {
            allowlist.add_cidr_str(trimmed).map_err(|e| AllowlistLoadError::Parse {
                line: line_num + 1,
                source: e,
            })?;
        } else {
            allowlist.add_ip_str(trimmed).map_err(|e| AllowlistLoadError::Parse {
                line: line_num + 1,
                source: e,
            })?;
        }
    }

    Ok(allowlist)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibsr_fs::MockFilesystem;
    use std::path::PathBuf;
    use std::sync::Arc;

    // ===========================================
    // Test Category C — Allowlist Loading
    // ===========================================

    #[test]
    fn test_parse_allowlist_empty() {
        let allowlist = parse_allowlist("").expect("parse");
        assert!(allowlist.is_empty());
    }

    #[test]
    fn test_parse_allowlist_comments_only() {
        let content = "# This is a comment\n# Another comment\n";
        let allowlist = parse_allowlist(content).expect("parse");
        assert!(allowlist.is_empty());
    }

    #[test]
    fn test_parse_allowlist_empty_lines() {
        let content = "\n\n\n";
        let allowlist = parse_allowlist(content).expect("parse");
        assert!(allowlist.is_empty());
    }

    #[test]
    fn test_parse_allowlist_single_ip() {
        let content = "10.0.0.1\n";
        let allowlist = parse_allowlist(content).expect("parse");
        assert_eq!(allowlist.ip_count(), 1);
        assert!(allowlist.contains(0x0A000001)); // 10.0.0.1
    }

    #[test]
    fn test_parse_allowlist_multiple_ips() {
        let content = "10.0.0.1\n10.0.0.2\n192.168.1.1\n";
        let allowlist = parse_allowlist(content).expect("parse");
        assert_eq!(allowlist.ip_count(), 3);
        assert!(allowlist.contains(0x0A000001));
        assert!(allowlist.contains(0x0A000002));
        assert!(allowlist.contains(0xC0A80101));
    }

    #[test]
    fn test_parse_allowlist_single_cidr() {
        let content = "192.168.0.0/24\n";
        let allowlist = parse_allowlist(content).expect("parse");
        assert_eq!(allowlist.cidr_count(), 1);
        assert!(allowlist.contains(0xC0A80001)); // 192.168.0.1
        assert!(allowlist.contains(0xC0A800FF)); // 192.168.0.255
    }

    #[test]
    fn test_parse_allowlist_multiple_cidrs() {
        let content = "10.0.0.0/8\n172.16.0.0/12\n";
        let allowlist = parse_allowlist(content).expect("parse");
        assert_eq!(allowlist.cidr_count(), 2);
    }

    #[test]
    fn test_parse_allowlist_mixed() {
        let content = "# Header comment\n10.0.0.1\n192.168.0.0/24\n# Mid comment\n10.0.0.2\n";
        let allowlist = parse_allowlist(content).expect("parse");
        assert_eq!(allowlist.ip_count(), 2);
        assert_eq!(allowlist.cidr_count(), 1);
    }

    #[test]
    fn test_parse_allowlist_whitespace_trimmed() {
        let content = "  10.0.0.1  \n\t192.168.0.0/24\t\n";
        let allowlist = parse_allowlist(content).expect("parse");
        assert_eq!(allowlist.ip_count(), 1);
        assert_eq!(allowlist.cidr_count(), 1);
    }

    #[test]
    fn test_parse_allowlist_comment_after_whitespace() {
        let content = "   # This is a comment\n";
        let allowlist = parse_allowlist(content).expect("parse");
        assert!(allowlist.is_empty());
    }

    #[test]
    fn test_parse_allowlist_invalid_ip() {
        let content = "not-an-ip\n";
        let result = parse_allowlist(content);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AllowlistLoadError::Parse { line: 1, .. }));
    }

    #[test]
    fn test_parse_allowlist_invalid_cidr() {
        let content = "10.0.0.0/33\n";
        let result = parse_allowlist(content);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AllowlistLoadError::Parse { line: 1, .. }));
    }

    #[test]
    fn test_parse_allowlist_invalid_on_line_3() {
        let content = "10.0.0.1\n192.168.0.0/24\ninvalid\n";
        let result = parse_allowlist(content);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AllowlistLoadError::Parse { line: 3, .. }));
    }

    #[test]
    fn test_load_allowlist_from_file() {
        let fs = Arc::new(MockFilesystem::new());
        let path = PathBuf::from("/tmp/allowlist.txt");
        fs.add_file(path.clone(), b"10.0.0.1\n192.168.0.0/24\n".to_vec());

        let allowlist = load_allowlist(&*fs, &path).expect("load");
        assert_eq!(allowlist.ip_count(), 1);
        assert_eq!(allowlist.cidr_count(), 1);
    }

    #[test]
    fn test_load_allowlist_file_not_found() {
        let fs = Arc::new(MockFilesystem::new());
        let path = PathBuf::from("/nonexistent/allowlist.txt");

        let result = load_allowlist(&*fs, &path);
        assert!(result.is_err());
        assert!(matches!(result, Err(AllowlistLoadError::Read(_))));
    }

    #[test]
    fn test_load_allowlist_empty_file() {
        let fs = Arc::new(MockFilesystem::new());
        let path = PathBuf::from("/tmp/empty.txt");
        fs.add_file(path.clone(), vec![]);

        let allowlist = load_allowlist(&*fs, &path).expect("load");
        assert!(allowlist.is_empty());
    }

    #[test]
    fn test_allowlist_load_error_display_read() {
        let err = AllowlistLoadError::Read(FsError::Path("test".to_string()));
        assert!(err.to_string().contains("failed to read allowlist file"));
    }

    #[test]
    fn test_allowlist_load_error_display_parse() {
        let err = AllowlistLoadError::Parse {
            line: 5,
            source: AllowlistError::InvalidIp("bad".to_string()),
        };
        let msg = err.to_string();
        assert!(msg.contains("line 5"));
    }

    #[test]
    fn test_allowlist_load_error_debug() {
        let err = AllowlistLoadError::Read(FsError::Path("test".to_string()));
        let debug = format!("{:?}", err);
        assert!(debug.contains("Read"));
    }

    #[test]
    fn test_parse_allowlist_realistic_file() {
        let content = r#"# IBSR Allowlist
# Trusted infrastructure IPs

# Load balancers
10.0.0.10
10.0.0.11

# Internal networks
192.168.0.0/24
172.16.0.0/16

# Monitoring servers
10.1.1.1
10.1.1.2
"#;
        let allowlist = parse_allowlist(content).expect("parse");
        assert_eq!(allowlist.ip_count(), 4);
        assert_eq!(allowlist.cidr_count(), 2);
    }
}
