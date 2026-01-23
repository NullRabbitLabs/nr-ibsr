//! S3 object metadata generation.

use std::collections::HashMap;

/// Builder for x-ibsr-* metadata headers.
pub struct MetadataBuilder {
    run_id: String,
    hostname: String,
    version: String,
}

impl MetadataBuilder {
    /// Create a new metadata builder with the given run ID.
    pub fn new(run_id: &str) -> Self {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string());

        let version = env!("CARGO_PKG_VERSION").to_string();

        Self {
            run_id: run_id.to_string(),
            hostname,
            version,
        }
    }

    /// Build the metadata map for S3 object headers.
    ///
    /// Returns headers without the `x-amz-meta-` prefix (AWS SDK adds it automatically).
    pub fn build(&self) -> HashMap<String, String> {
        let mut meta = HashMap::new();
        meta.insert("ibsr-run-id".to_string(), self.run_id.clone());
        meta.insert("ibsr-hostname".to_string(), self.hostname.clone());
        meta.insert("ibsr-version".to_string(), self.version.clone());
        meta
    }

    /// Get the hostname.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_builder() {
        let builder = MetadataBuilder::new("2026-01-22T10:15:00Z");
        let meta = builder.build();

        assert_eq!(meta.get("ibsr-run-id"), Some(&"2026-01-22T10:15:00Z".to_string()));
        assert!(meta.contains_key("ibsr-hostname"));
        assert!(meta.contains_key("ibsr-version"));
    }

    #[test]
    fn test_hostname() {
        let builder = MetadataBuilder::new("test");
        // Hostname should be non-empty
        assert!(!builder.hostname().is_empty());
    }
}
