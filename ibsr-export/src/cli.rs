//! CLI argument parsing for ibsr-export.

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Upload IBSR report artefacts to S3 or S3-compatible storage.
#[derive(Parser)]
#[command(name = "ibsr-export")]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Upload artefacts to S3 or S3-compatible storage
    S3(S3Args),
}

/// Arguments for the S3 upload command.
#[derive(Args, Debug)]
pub struct S3Args {
    // === Required ===
    /// Input directory containing artefacts from ibsr-report
    #[arg(long, required = true)]
    pub input: PathBuf,

    /// Target S3 bucket name
    #[arg(long, required = true)]
    pub bucket: String,

    // === Key layout ===
    /// Object key prefix (default: ibsr/<hostname>/<run-id>/)
    #[arg(long)]
    pub prefix: Option<String>,

    /// Override run ID (default: derived from input folder name or UTC timestamp)
    #[arg(long)]
    pub run_id: Option<String>,

    // === S3 target ===
    /// AWS region (default: from env/SDK)
    #[arg(long)]
    pub region: Option<String>,

    /// S3-compatible endpoint URL (for MinIO, R2, etc.)
    #[arg(long)]
    pub endpoint: Option<String>,

    /// Use path-style URLs (required for MinIO/R2)
    #[arg(long, default_value_t = false)]
    pub force_path_style: bool,

    // === Auth (credential chain only, no secrets via CLI) ===
    /// AWS profile name
    #[arg(long)]
    pub profile: Option<String>,

    /// ARN of role to assume
    #[arg(long)]
    pub assume_role_arn: Option<String>,

    /// Session name for assumed role
    #[arg(long, default_value = "ibsr-export")]
    pub assume_role_session_name: String,

    // === Upload selection ===
    /// Additional glob patterns to include (repeatable)
    #[arg(long, action = ArgAction::Append)]
    pub include: Vec<String>,

    /// Glob patterns to exclude (repeatable)
    #[arg(long, action = ArgAction::Append)]
    pub exclude: Vec<String>,

    // === Encryption ===
    /// Server-side encryption mode
    #[arg(long, value_enum)]
    pub sse: Option<SseMode>,

    /// KMS key ID or alias for SSE-KMS
    #[arg(long)]
    pub kms_key_id: Option<String>,

    /// KMS encryption context as JSON string
    #[arg(long)]
    pub kms_context: Option<String>,

    // === Presigned URLs ===
    /// Generate presigned GET URLs with this expiration (e.g., "1h", "7d")
    #[arg(long)]
    pub presign: Option<String>,

    // === Reliability ===
    /// Maximum concurrent uploads
    #[arg(long, default_value_t = 4)]
    pub concurrency: usize,

    /// Maximum retry attempts per upload
    #[arg(long, default_value_t = 8)]
    pub max_retries: u32,

    /// Per-request timeout in seconds
    #[arg(long, default_value_t = 60)]
    pub timeout_sec: u64,

    // === Output ===
    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub output: OutputFormat,

    // === Safety ===
    /// Print planned uploads without uploading
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,

    /// Allow overwriting existing objects
    #[arg(long, default_value_t = false)]
    pub overwrite: bool,
}

/// Server-side encryption mode.
#[derive(Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum SseMode {
    /// No server-side encryption
    None,
    /// SSE-S3 (AES-256)
    S3,
    /// SSE-KMS
    Kms,
}

/// Output format for results.
#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Human-readable text
    #[default]
    Text,
    /// JSON manifest
    Json,
}

impl S3Args {
    /// Derive the effective SSE mode.
    /// If --sse is provided, use it. Otherwise, use KMS if --kms-key-id is set, else S3.
    pub fn effective_sse(&self) -> SseMode {
        match &self.sse {
            Some(mode) => mode.clone(),
            None => {
                if self.kms_key_id.is_some() {
                    SseMode::Kms
                } else {
                    SseMode::S3
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effective_sse_default() {
        let args = S3Args {
            input: PathBuf::from("/tmp"),
            bucket: "test".into(),
            prefix: None,
            run_id: None,
            region: None,
            endpoint: None,
            force_path_style: false,
            profile: None,
            assume_role_arn: None,
            assume_role_session_name: "ibsr-export".into(),
            include: vec![],
            exclude: vec![],
            sse: None,
            kms_key_id: None,
            kms_context: None,
            presign: None,
            concurrency: 4,
            max_retries: 8,
            timeout_sec: 60,
            output: OutputFormat::Text,
            dry_run: false,
            overwrite: false,
        };
        assert_eq!(args.effective_sse(), SseMode::S3);
    }

    #[test]
    fn test_effective_sse_with_kms_key() {
        let args = S3Args {
            input: PathBuf::from("/tmp"),
            bucket: "test".into(),
            prefix: None,
            run_id: None,
            region: None,
            endpoint: None,
            force_path_style: false,
            profile: None,
            assume_role_arn: None,
            assume_role_session_name: "ibsr-export".into(),
            include: vec![],
            exclude: vec![],
            sse: None,
            kms_key_id: Some("alias/my-key".into()),
            kms_context: None,
            presign: None,
            concurrency: 4,
            max_retries: 8,
            timeout_sec: 60,
            output: OutputFormat::Text,
            dry_run: false,
            overwrite: false,
        };
        assert_eq!(args.effective_sse(), SseMode::Kms);
    }

    #[test]
    fn test_effective_sse_explicit_none() {
        let args = S3Args {
            input: PathBuf::from("/tmp"),
            bucket: "test".into(),
            prefix: None,
            run_id: None,
            region: None,
            endpoint: None,
            force_path_style: false,
            profile: None,
            assume_role_arn: None,
            assume_role_session_name: "ibsr-export".into(),
            include: vec![],
            exclude: vec![],
            sse: Some(SseMode::None),
            kms_key_id: Some("alias/my-key".into()), // ignored when sse is explicit
            kms_context: None,
            presign: None,
            concurrency: 4,
            max_retries: 8,
            timeout_sec: 60,
            output: OutputFormat::Text,
            dry_run: false,
            overwrite: false,
        };
        assert_eq!(args.effective_sse(), SseMode::None);
    }
}
