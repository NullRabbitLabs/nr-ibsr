//! Error types and exit codes for ibsr-export.

use std::path::PathBuf;

/// Exit codes for ibsr-export.
pub mod codes {
    pub const SUCCESS: u8 = 0;
    pub const INPUT_NOT_FOUND: u8 = 2;
    pub const REQUIRED_ARTEFACT_MISSING: u8 = 3;
    pub const UPLOAD_FAILED: u8 = 10;
    pub const OBJECT_EXISTS: u8 = 11;
    pub const CONFIG_ERROR: u8 = 1;
}

/// Errors that can occur during export operations.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("input directory not found: {0}")]
    InputNotFound(PathBuf),

    #[error("required artefact missing: {0}")]
    RequiredArtefactMissing(String),

    #[error("upload failed for {path}: {message}")]
    UploadFailed { path: String, message: String },

    #[error("object already exists: {0} (use --overwrite to replace)")]
    ObjectExists(String),

    #[error("partial upload failure: {succeeded} succeeded, {failed} failed")]
    PartialFailure { succeeded: usize, failed: usize },

    #[error("invalid presign duration: {0}")]
    InvalidPresignDuration(String),

    #[error("invalid glob pattern: {0}")]
    InvalidGlobPattern(String),

    #[error("AWS configuration error: {0}")]
    AwsConfig(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Map an error to its exit code.
pub fn exit_code(err: &ExportError) -> u8 {
    match err {
        ExportError::InputNotFound(_) => codes::INPUT_NOT_FOUND,
        ExportError::RequiredArtefactMissing(_) => codes::REQUIRED_ARTEFACT_MISSING,
        ExportError::UploadFailed { .. } => codes::UPLOAD_FAILED,
        ExportError::ObjectExists(_) => codes::OBJECT_EXISTS,
        ExportError::PartialFailure { .. } => codes::UPLOAD_FAILED,
        ExportError::InvalidPresignDuration(_) => codes::CONFIG_ERROR,
        ExportError::InvalidGlobPattern(_) => codes::CONFIG_ERROR,
        ExportError::AwsConfig(_) => codes::CONFIG_ERROR,
        ExportError::Io(_) => codes::CONFIG_ERROR,
        ExportError::Json(_) => codes::CONFIG_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_codes() {
        assert_eq!(
            exit_code(&ExportError::InputNotFound(PathBuf::from("/tmp"))),
            codes::INPUT_NOT_FOUND
        );
        assert_eq!(
            exit_code(&ExportError::RequiredArtefactMissing("report.md".into())),
            codes::REQUIRED_ARTEFACT_MISSING
        );
        assert_eq!(
            exit_code(&ExportError::ObjectExists("key".into())),
            codes::OBJECT_EXISTS
        );
        assert_eq!(
            exit_code(&ExportError::UploadFailed {
                path: "f".into(),
                message: "err".into()
            }),
            codes::UPLOAD_FAILED
        );
    }
}
