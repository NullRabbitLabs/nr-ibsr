//! S3 upload logic with concurrent uploads and retry handling.

use crate::cli::{S3Args, SseMode};
use crate::content_type::content_type_for_path;
use crate::error::ExportError;
use crate::metadata::MetadataBuilder;
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{ChecksumAlgorithm, ServerSideEncryption};
use aws_sdk_s3::Client;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::sleep;

/// Configuration for uploads.
pub struct UploadConfig {
    pub bucket: String,
    pub prefix: String,
    pub sse: SseMode,
    pub kms_key_id: Option<String>,
    pub kms_context: Option<String>,
    pub concurrency: usize,
    pub max_retries: u32,
    pub timeout: Duration,
    pub overwrite: bool,
    pub metadata: HashMap<String, String>,
}

/// Result of a single file upload.
pub struct UploadResult {
    pub path: String,
    pub key: String,
    pub etag: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub content_type: String,
}

/// S3 uploader with concurrent uploads and retry logic.
pub struct S3Uploader {
    client: Client,
    config: UploadConfig,
}

impl S3Uploader {
    /// Create a new S3 uploader from CLI arguments.
    pub async fn new(args: &S3Args, run_id: &str) -> Result<Self, ExportError> {
        let sdk_config = build_aws_config(args).await?;
        let mut s3_config_builder = aws_sdk_s3::config::Builder::from(&sdk_config);

        // Set endpoint if provided
        if let Some(endpoint) = &args.endpoint {
            s3_config_builder = s3_config_builder.endpoint_url(endpoint);
        }

        // Set path style if needed (for MinIO/R2)
        if args.force_path_style {
            s3_config_builder = s3_config_builder.force_path_style(true);
        }

        let s3_config = s3_config_builder.build();
        let client = Client::from_conf(s3_config);

        let metadata_builder = MetadataBuilder::new(run_id);
        let config = UploadConfig {
            bucket: args.bucket.clone(),
            prefix: args.prefix.clone().unwrap_or_default(),
            sse: args.effective_sse(),
            kms_key_id: args.kms_key_id.clone(),
            kms_context: args.kms_context.clone(),
            concurrency: args.concurrency,
            max_retries: args.max_retries,
            timeout: Duration::from_secs(args.timeout_sec),
            overwrite: args.overwrite,
            metadata: metadata_builder.build(),
        };

        Ok(Self { client, config })
    }

    /// Get the bucket name.
    pub fn bucket(&self) -> &str {
        &self.config.bucket
    }

    /// Check if an object exists in S3.
    pub async fn object_exists(&self, key: &str) -> Result<bool, ExportError> {
        match self
            .client
            .head_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(err) => {
                let service_err = err.into_service_error();
                if service_err.is_not_found() {
                    Ok(false)
                } else {
                    Err(ExportError::AwsConfig(format!(
                        "Failed to check object existence: {}",
                        service_err
                    )))
                }
            }
        }
    }

    /// Upload a single file with retries.
    pub async fn upload_file(
        &self,
        local_path: &Path,
        object_key: &str,
    ) -> Result<UploadResult, ExportError> {
        let file_name = local_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        // Read file and compute SHA256
        let content = tokio::fs::read(local_path).await?;
        let size_bytes = content.len() as u64;
        let sha256 = compute_sha256(&content);
        let content_type = content_type_for_path(local_path).to_string();

        // Retry loop with exponential backoff
        let mut attempt = 0;
        let mut last_error = None;

        while attempt < self.config.max_retries {
            attempt += 1;

            match self
                .upload_once(&content, object_key, &content_type)
                .await
            {
                Ok(etag) => {
                    return Ok(UploadResult {
                        path: file_name.to_string(),
                        key: object_key.to_string(),
                        etag,
                        sha256: sha256.clone(),
                        size_bytes,
                        content_type,
                    });
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.config.max_retries {
                        let delay = backoff_delay(attempt);
                        sleep(delay).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| ExportError::UploadFailed {
            path: file_name.to_string(),
            message: "Max retries exceeded".to_string(),
        }))
    }

    /// Single upload attempt.
    async fn upload_once(
        &self,
        content: &[u8],
        object_key: &str,
        content_type: &str,
    ) -> Result<String, ExportError> {
        let body = ByteStream::from(content.to_vec());

        let mut request = self
            .client
            .put_object()
            .bucket(&self.config.bucket)
            .key(object_key)
            .body(body)
            .content_type(content_type)
            .checksum_algorithm(ChecksumAlgorithm::Sha256);

        // Add metadata
        for (k, v) in &self.config.metadata {
            request = request.metadata(k, v);
        }

        // Set encryption
        match &self.config.sse {
            SseMode::None => {}
            SseMode::S3 => {
                request = request.server_side_encryption(ServerSideEncryption::Aes256);
            }
            SseMode::Kms => {
                request = request.server_side_encryption(ServerSideEncryption::AwsKms);
                if let Some(key_id) = &self.config.kms_key_id {
                    request = request.ssekms_key_id(key_id);
                }
                if let Some(context) = &self.config.kms_context {
                    request = request.ssekms_encryption_context(context);
                }
            }
        }

        let response = request.send().await.map_err(|e| ExportError::UploadFailed {
            path: object_key.to_string(),
            message: e.to_string(),
        })?;

        let etag = response.e_tag().unwrap_or("").to_string();
        Ok(etag)
    }

    /// Upload multiple files concurrently.
    pub async fn upload_files(
        &self,
        input_dir: &Path,
        files: Vec<(String, String)>, // (relative_path, object_key)
    ) -> Result<Vec<UploadResult>, ExportError> {
        let semaphore = Arc::new(Semaphore::new(self.config.concurrency));
        let mut handles = Vec::new();

        for (relative_path, object_key) in files {
            let local_path = input_dir.join(&relative_path);
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let uploader = self.clone_for_task();
            let key = object_key.clone();

            let handle = tokio::spawn(async move {
                let result = uploader.upload_file(&local_path, &key).await;
                drop(permit);
                result
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        let mut errors = Vec::new();

        for handle in handles {
            match handle.await {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(e)) => errors.push(e),
                Err(e) => errors.push(ExportError::UploadFailed {
                    path: "unknown".to_string(),
                    message: e.to_string(),
                }),
            }
        }

        if errors.is_empty() {
            Ok(results)
        } else if results.is_empty() {
            Err(errors.remove(0))
        } else {
            Err(ExportError::PartialFailure {
                succeeded: results.len(),
                failed: errors.len(),
            })
        }
    }

    /// Clone the uploader for use in a spawned task.
    fn clone_for_task(&self) -> Self {
        Self {
            client: self.client.clone(),
            config: UploadConfig {
                bucket: self.config.bucket.clone(),
                prefix: self.config.prefix.clone(),
                sse: self.config.sse.clone(),
                kms_key_id: self.config.kms_key_id.clone(),
                kms_context: self.config.kms_context.clone(),
                concurrency: self.config.concurrency,
                max_retries: self.config.max_retries,
                timeout: self.config.timeout,
                overwrite: self.config.overwrite,
                metadata: self.config.metadata.clone(),
            },
        }
    }
}

/// Build AWS SDK configuration from CLI arguments.
async fn build_aws_config(args: &S3Args) -> Result<aws_config::SdkConfig, ExportError> {
    let mut config_loader = aws_config::defaults(BehaviorVersion::latest());

    // Set region if provided
    if let Some(region) = &args.region {
        config_loader = config_loader.region(Region::new(region.clone()));
    }

    // Set profile if provided
    if let Some(profile) = &args.profile {
        config_loader = config_loader.profile_name(profile);
    }

    let config = config_loader.load().await;

    // Handle assume role if specified
    // Note: For full assume role support, we'd need aws-sdk-sts
    // Users should configure an AWS profile with role_arn for assume role
    if let Some(role_arn) = &args.assume_role_arn {
        return Err(ExportError::AwsConfig(format!(
            "AssumeRole via --assume-role-arn is not yet implemented. \
             Please configure an AWS profile with role_arn instead: {}",
            role_arn
        )));
    }

    Ok(config)
}

/// Compute SHA256 hash of data, returning hex string.
fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Calculate backoff delay with jitter.
fn backoff_delay(attempt: u32) -> Duration {
    let base_ms = 100u64;
    let max_ms = 30_000u64;

    // Exponential backoff: 100ms, 200ms, 400ms, 800ms, ...
    let delay_ms = base_ms.saturating_mul(2u64.saturating_pow(attempt - 1));
    let delay_ms = delay_ms.min(max_ms);

    // Add jitter (0-50% of delay)
    let jitter_ms = (delay_ms as f64 * rand_jitter()) as u64;
    Duration::from_millis(delay_ms + jitter_ms)
}

/// Generate random jitter factor between 0.0 and 0.5.
fn rand_jitter() -> f64 {
    // Simple deterministic "jitter" based on current time
    // For production, consider using rand crate
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    (nanos as f64 / u32::MAX as f64) * 0.5
}

/// Convert bytes to hex string.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_sha256() {
        let data = b"hello world";
        let hash = compute_sha256(data);
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex::encode(&[0x00, 0xff, 0x10]), "00ff10");
    }

    #[test]
    fn test_backoff_delay() {
        let d1 = backoff_delay(1);
        let d2 = backoff_delay(2);
        let d3 = backoff_delay(3);

        // Base delays should increase exponentially
        assert!(d1.as_millis() >= 100);
        assert!(d1.as_millis() <= 150); // 100 + up to 50% jitter
        assert!(d2.as_millis() >= 200);
        assert!(d3.as_millis() >= 400);
    }

    #[test]
    fn test_backoff_max() {
        let d = backoff_delay(20); // Very high attempt
        assert!(d.as_millis() <= 45_000); // 30s + 50% jitter max
    }
}
