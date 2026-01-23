//! Upload manifest generation and serialization.

use crate::cli::SseMode;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Version of the manifest schema.
pub const MANIFEST_VERSION: u32 = 1;

/// Upload manifest containing metadata about uploaded objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadManifest {
    pub version: u32,
    pub tool: String,
    pub run_id: String,
    pub hostname: String,
    pub generated_at: String,
    pub target: TargetInfo,
    pub objects: Vec<ObjectInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub failures: Vec<FailureInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Information about the upload target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    #[serde(rename = "type")]
    pub target_type: String,
    pub bucket: String,
    pub prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub sse: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_key_id: Option<String>,
}

/// Information about a successfully uploaded object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectInfo {
    pub path: String,
    pub key: String,
    pub etag: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub content_type: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presigned_get_url: Option<String>,
}

/// Information about a failed upload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureInfo {
    pub path: String,
    pub key: String,
    pub error: String,
}

impl UploadManifest {
    /// Create a new upload manifest.
    pub fn new(
        run_id: &str,
        hostname: &str,
        bucket: &str,
        prefix: &str,
        region: Option<&str>,
        endpoint: Option<&str>,
        sse: &SseMode,
        kms_key_id: Option<&str>,
    ) -> Self {
        let sse_str = match sse {
            SseMode::None => "none",
            SseMode::S3 => "s3",
            SseMode::Kms => "kms",
        };

        Self {
            version: MANIFEST_VERSION,
            tool: "ibsr-export".to_string(),
            run_id: run_id.to_string(),
            hostname: hostname.to_string(),
            generated_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            target: TargetInfo {
                target_type: "s3".to_string(),
                bucket: bucket.to_string(),
                prefix: prefix.to_string(),
                region: region.map(|s| s.to_string()),
                endpoint: endpoint.map(|s| s.to_string()),
                sse: sse_str.to_string(),
                kms_key_id: kms_key_id.map(|s| s.to_string()),
            },
            objects: Vec::new(),
            failures: Vec::new(),
            status: None,
        }
    }

    /// Add a successfully uploaded object.
    pub fn add_object(&mut self, object: ObjectInfo) {
        self.objects.push(object);
    }

    /// Add a failed upload.
    pub fn add_failure(&mut self, failure: FailureInfo) {
        self.failures.push(failure);
    }

    /// Set the status (e.g., "partial" for partial failures).
    pub fn set_status(&mut self, status: &str) {
        self.status = Some(status.to_string());
    }

    /// Sort objects by path for deterministic output.
    pub fn sort_objects(&mut self) {
        self.objects.sort_by(|a, b| a.path.cmp(&b.path));
        self.failures.sort_by(|a, b| a.path.cmp(&b.path));
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Write manifest to a file.
    pub fn write_to(&self, path: &Path) -> Result<(), std::io::Error> {
        let json = self.to_json().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        std::fs::write(path, json)
    }
}

impl ObjectInfo {
    /// Create a new object info.
    pub fn new(
        path: &str,
        key: &str,
        etag: &str,
        sha256: &str,
        size_bytes: u64,
        content_type: &str,
        bucket: &str,
    ) -> Self {
        Self {
            path: path.to_string(),
            key: key.to_string(),
            etag: etag.to_string(),
            sha256: sha256.to_string(),
            size_bytes,
            content_type: content_type.to_string(),
            url: format!("s3://{}/{}", bucket, key),
            presigned_get_url: None,
        }
    }

    /// Set the presigned GET URL.
    pub fn with_presigned_url(mut self, url: String) -> Self {
        self.presigned_get_url = Some(url);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_creation() {
        let manifest = UploadManifest::new(
            "2026-01-22T10:15:00Z",
            "host-y",
            "nr-ibsr-pilot-reports",
            "customer-x/host-y/2026-01-22T1015Z",
            Some("eu-west-1"),
            None,
            &SseMode::Kms,
            Some("alias/nr-ibsr"),
        );

        assert_eq!(manifest.version, MANIFEST_VERSION);
        assert_eq!(manifest.tool, "ibsr-export");
        assert_eq!(manifest.run_id, "2026-01-22T10:15:00Z");
        assert_eq!(manifest.target.bucket, "nr-ibsr-pilot-reports");
        assert_eq!(manifest.target.sse, "kms");
    }

    #[test]
    fn test_add_object() {
        let mut manifest = UploadManifest::new(
            "test",
            "host",
            "bucket",
            "prefix",
            None,
            None,
            &SseMode::S3,
            None,
        );

        manifest.add_object(ObjectInfo::new(
            "report.md",
            "prefix/report.md",
            "\"etag\"",
            "abc123",
            1024,
            "text/markdown; charset=utf-8",
            "bucket",
        ));

        assert_eq!(manifest.objects.len(), 1);
        assert_eq!(manifest.objects[0].path, "report.md");
        assert_eq!(manifest.objects[0].url, "s3://bucket/prefix/report.md");
    }

    #[test]
    fn test_json_serialization() {
        let manifest = UploadManifest::new(
            "test",
            "host",
            "bucket",
            "prefix",
            None,
            None,
            &SseMode::S3,
            None,
        );

        let json = manifest.to_json().unwrap();
        assert!(json.contains("\"version\": 1"));
        assert!(json.contains("\"tool\": \"ibsr-export\""));
    }

    #[test]
    fn test_sort_objects() {
        let mut manifest = UploadManifest::new(
            "test",
            "host",
            "bucket",
            "prefix",
            None,
            None,
            &SseMode::S3,
            None,
        );

        manifest.add_object(ObjectInfo::new(
            "z_file.md", "prefix/z_file.md", "\"e1\"", "h1", 100, "text/markdown; charset=utf-8", "bucket"
        ));
        manifest.add_object(ObjectInfo::new(
            "a_file.md", "prefix/a_file.md", "\"e2\"", "h2", 200, "text/markdown; charset=utf-8", "bucket"
        ));

        manifest.sort_objects();

        assert_eq!(manifest.objects[0].path, "a_file.md");
        assert_eq!(manifest.objects[1].path, "z_file.md");
    }

    #[test]
    fn test_failures_not_serialized_when_empty() {
        let manifest = UploadManifest::new(
            "test",
            "host",
            "bucket",
            "prefix",
            None,
            None,
            &SseMode::S3,
            None,
        );

        let json = manifest.to_json().unwrap();
        assert!(!json.contains("\"failures\""));
    }
}
