//! Presigned URL generation for S3 objects.

use crate::error::ExportError;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::Client;
use std::time::Duration;

/// Generate presigned GET URLs for S3 objects.
pub struct Presigner {
    client: Client,
    bucket: String,
}

impl Presigner {
    /// Create a new presigner.
    pub fn new(client: Client, bucket: &str) -> Self {
        Self {
            client,
            bucket: bucket.to_string(),
        }
    }

    /// Generate a presigned GET URL for an object.
    pub async fn presign_get(
        &self,
        key: &str,
        expires_in: Duration,
    ) -> Result<String, ExportError> {
        let presigning_config = PresigningConfig::expires_in(expires_in).map_err(|e| {
            ExportError::InvalidPresignDuration(format!("Invalid expiration: {}", e))
        })?;

        let presigned = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(presigning_config)
            .await
            .map_err(|e| {
                ExportError::AwsConfig(format!("Failed to generate presigned URL: {}", e))
            })?;

        Ok(presigned.uri().to_string())
    }
}

/// Parse a duration string like "7d", "24h", "1h", "30m".
pub fn parse_duration(s: &str) -> Result<Duration, ExportError> {
    humantime::parse_duration(s)
        .map_err(|_| ExportError::InvalidPresignDuration(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_days() {
        let d = parse_duration("7d").unwrap();
        assert_eq!(d, Duration::from_secs(7 * 24 * 60 * 60));
    }

    #[test]
    fn test_parse_duration_hours() {
        let d = parse_duration("24h").unwrap();
        assert_eq!(d, Duration::from_secs(24 * 60 * 60));
    }

    #[test]
    fn test_parse_duration_minutes() {
        let d = parse_duration("30m").unwrap();
        assert_eq!(d, Duration::from_secs(30 * 60));
    }

    #[test]
    fn test_parse_duration_seconds() {
        let d = parse_duration("3600s").unwrap();
        assert_eq!(d, Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_duration_combined() {
        let d = parse_duration("1h30m").unwrap();
        assert_eq!(d, Duration::from_secs(90 * 60));
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("invalid").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("7").is_err()); // missing unit
    }
}
