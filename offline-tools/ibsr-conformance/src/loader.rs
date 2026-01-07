//! Fixture loading utilities.

use crate::types::{Fixture, FixtureConfig, ScenarioMeta};
use ibsr_schema::Snapshot;
use std::path::{Path, PathBuf};

/// Errors that can occur when loading fixtures.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("fixture not found: {0}")]
    NotFound(String),

    #[error("missing file in fixture: {0}")]
    MissingFile(String),

    #[error("failed to read file {path}: {source}")]
    ReadError {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse JSON in {path}: {source}")]
    JsonError {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to parse snapshot: {0}")]
    SnapshotError(String),

    #[error("no snapshots found in fixture: {0}")]
    NoSnapshots(String),
}

/// Get the fixtures directory path.
///
/// By default, looks for `fixtures/` relative to the workspace root.
pub fn fixtures_dir() -> PathBuf {
    // Navigate from the crate to workspace root
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let path = Path::new(&manifest_dir);

    // If we're in ibsr-conformance crate, go up two levels to workspace root
    if path.ends_with("ibsr-conformance") {
        path.parent() // offline-tools
            .and_then(|p| p.parent()) // workspace root
            .unwrap_or(path)
            .join("fixtures")
    } else {
        path.join("fixtures")
    }
}

/// List all available fixture names.
pub fn list_fixtures() -> Result<Vec<String>, LoadError> {
    let dir = fixtures_dir();
    if !dir.exists() {
        return Ok(vec![]);
    }

    let mut fixtures = Vec::new();
    let entries = std::fs::read_dir(&dir).map_err(|e| LoadError::ReadError {
        path: dir.display().to_string(),
        source: e,
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| LoadError::ReadError {
            path: dir.display().to_string(),
            source: e,
        })?;

        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name() {
                fixtures.push(name.to_string_lossy().to_string());
            }
        }
    }

    fixtures.sort();
    Ok(fixtures)
}

/// Load a fixture by name.
pub fn load_fixture(name: &str) -> Result<Fixture, LoadError> {
    let fixture_dir = fixtures_dir().join(name);
    if !fixture_dir.exists() {
        return Err(LoadError::NotFound(name.to_string()));
    }

    // Load metadata
    let meta = load_scenario_meta(&fixture_dir)?;

    // Load config
    let config = load_fixture_config(&fixture_dir)?;

    // Load optional allowlist
    let allowlist = load_allowlist(&fixture_dir)?;

    // Load snapshots
    let snapshots = load_snapshots(&fixture_dir, name)?;

    // Load expected outputs
    let expected_rules = load_expected_file(&fixture_dir, "rules.json")?;
    let expected_report = load_expected_file(&fixture_dir, "report.md")?;
    let expected_evidence = load_expected_file(&fixture_dir, "evidence.csv")?;

    Ok(Fixture {
        meta,
        config,
        allowlist,
        snapshots,
        expected_rules,
        expected_report,
        expected_evidence,
    })
}

/// Load scenario metadata.
fn load_scenario_meta(fixture_dir: &Path) -> Result<ScenarioMeta, LoadError> {
    let path = fixture_dir.join("scenario.json");
    let content = read_file(&path)?;
    serde_json::from_str(&content).map_err(|e| LoadError::JsonError {
        path: path.display().to_string(),
        source: e,
    })
}

/// Load fixture configuration.
fn load_fixture_config(fixture_dir: &Path) -> Result<FixtureConfig, LoadError> {
    let path = fixture_dir.join("config.json");
    let content = read_file(&path)?;
    serde_json::from_str(&content).map_err(|e| LoadError::JsonError {
        path: path.display().to_string(),
        source: e,
    })
}

/// Load optional allowlist.
fn load_allowlist(fixture_dir: &Path) -> Result<Option<String>, LoadError> {
    let path = fixture_dir.join("allowlist.txt");
    if !path.exists() {
        return Ok(None);
    }
    read_file(&path).map(Some)
}

/// Load snapshots from the fixture's snapshots directory.
fn load_snapshots(fixture_dir: &Path, fixture_name: &str) -> Result<Vec<Snapshot>, LoadError> {
    let snapshots_dir = fixture_dir.join("snapshots");
    if !snapshots_dir.exists() {
        return Err(LoadError::MissingFile(format!(
            "{}/snapshots/",
            fixture_name
        )));
    }

    let entries = std::fs::read_dir(&snapshots_dir).map_err(|e| LoadError::ReadError {
        path: snapshots_dir.display().to_string(),
        source: e,
    })?;

    let mut snapshots = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| LoadError::ReadError {
            path: snapshots_dir.display().to_string(),
            source: e,
        })?;

        let path = entry.path();
        if path.extension().map_or(false, |e| e == "jsonl") {
            let content = read_file(&path)?;
            let snapshot = Snapshot::from_json(&content)
                .map_err(|e| LoadError::SnapshotError(e.to_string()))?;
            snapshots.push(snapshot);
        }
    }

    if snapshots.is_empty() {
        return Err(LoadError::NoSnapshots(fixture_name.to_string()));
    }

    // Sort by timestamp for determinism
    snapshots.sort_by_key(|s| s.ts_unix_sec);

    Ok(snapshots)
}

/// Load an expected output file.
fn load_expected_file(fixture_dir: &Path, filename: &str) -> Result<String, LoadError> {
    let path = fixture_dir.join("expected").join(filename);
    if !path.exists() {
        return Err(LoadError::MissingFile(format!("expected/{}", filename)));
    }
    read_file(&path)
}

/// Read a file to string.
fn read_file(path: &Path) -> Result<String, LoadError> {
    std::fs::read_to_string(path).map_err(|e| LoadError::ReadError {
        path: path.display().to_string(),
        source: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ===========================================
    // Category F1 — Fixture Loader Tests
    // ===========================================

    // -------------------------------------------
    // Load fixture from fixtures directory by name
    // -------------------------------------------

    #[test]
    fn test_load_fixture_not_found() {
        let result = load_fixture("nonexistent_fixture_name");
        assert!(matches!(result, Err(LoadError::NotFound(_))));
    }

    // -------------------------------------------
    // Parse fixture metadata
    // -------------------------------------------

    #[test]
    fn test_load_scenario_meta_valid() {
        let temp = TempDir::new().unwrap();
        let fixture_dir = temp.path();

        fs::write(
            fixture_dir.join("scenario.json"),
            r#"{"name":"test_scenario","description":"A test","generated_at":12345}"#,
        )
        .unwrap();

        let meta = load_scenario_meta(fixture_dir).unwrap();
        assert_eq!(meta.name, "test_scenario");
        assert_eq!(meta.description, "A test");
        assert_eq!(meta.generated_at, 12345);
    }

    #[test]
    fn test_load_scenario_meta_missing() {
        let temp = TempDir::new().unwrap();
        let result = load_scenario_meta(temp.path());
        assert!(matches!(result, Err(LoadError::ReadError { .. })));
    }

    #[test]
    fn test_load_scenario_meta_invalid_json() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("scenario.json"), "not valid json").unwrap();

        let result = load_scenario_meta(temp.path());
        assert!(matches!(result, Err(LoadError::JsonError { .. })));
    }

    // -------------------------------------------
    // Load input snapshots from fixture
    // -------------------------------------------

    #[test]
    fn test_load_snapshots_single() {
        let temp = TempDir::new().unwrap();
        let fixture_dir = temp.path();
        fs::create_dir_all(fixture_dir.join("snapshots")).unwrap();

        let snapshot = Snapshot::new(1000, &[8080], vec![]);
        fs::write(
            fixture_dir.join("snapshots/1000.jsonl"),
            snapshot.to_json(),
        )
        .unwrap();

        let snapshots = load_snapshots(fixture_dir, "test").unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].ts_unix_sec, 1000);
    }

    #[test]
    fn test_load_snapshots_multiple_sorted() {
        let temp = TempDir::new().unwrap();
        let fixture_dir = temp.path();
        fs::create_dir_all(fixture_dir.join("snapshots")).unwrap();

        // Write in reverse order
        for ts in [1002, 1001, 1000] {
            let snapshot = Snapshot::new(ts, &[8080], vec![]);
            fs::write(
                fixture_dir.join(format!("snapshots/{}.jsonl", ts)),
                snapshot.to_json(),
            )
            .unwrap();
        }

        let snapshots = load_snapshots(fixture_dir, "test").unwrap();
        assert_eq!(snapshots.len(), 3);
        // Should be sorted by timestamp
        assert_eq!(snapshots[0].ts_unix_sec, 1000);
        assert_eq!(snapshots[1].ts_unix_sec, 1001);
        assert_eq!(snapshots[2].ts_unix_sec, 1002);
    }

    #[test]
    fn test_load_snapshots_missing_directory() {
        let temp = TempDir::new().unwrap();
        let result = load_snapshots(temp.path(), "test");
        assert!(matches!(result, Err(LoadError::MissingFile(_))));
    }

    #[test]
    fn test_load_snapshots_empty_directory() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("snapshots")).unwrap();

        let result = load_snapshots(temp.path(), "test");
        assert!(matches!(result, Err(LoadError::NoSnapshots(_))));
    }

    #[test]
    fn test_load_snapshots_ignores_non_jsonl() {
        let temp = TempDir::new().unwrap();
        let fixture_dir = temp.path();
        fs::create_dir_all(fixture_dir.join("snapshots")).unwrap();

        // Write a valid snapshot
        let snapshot = Snapshot::new(1000, &[8080], vec![]);
        fs::write(
            fixture_dir.join("snapshots/1000.jsonl"),
            snapshot.to_json(),
        )
        .unwrap();
        // Write a non-jsonl file
        fs::write(fixture_dir.join("snapshots/readme.txt"), "ignored").unwrap();

        let snapshots = load_snapshots(fixture_dir, "test").unwrap();
        assert_eq!(snapshots.len(), 1);
    }

    // -------------------------------------------
    // Load expected outputs
    // -------------------------------------------

    #[test]
    fn test_load_expected_file_exists() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("expected")).unwrap();
        fs::write(temp.path().join("expected/rules.json"), r#"{"test":true}"#).unwrap();

        let content = load_expected_file(temp.path(), "rules.json").unwrap();
        assert_eq!(content, r#"{"test":true}"#);
    }

    #[test]
    fn test_load_expected_file_missing() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("expected")).unwrap();

        let result = load_expected_file(temp.path(), "missing.json");
        assert!(matches!(result, Err(LoadError::MissingFile(_))));
    }

    // -------------------------------------------
    // Handle missing fixture gracefully
    // -------------------------------------------

    #[test]
    fn test_fixtures_dir_returns_valid_path() {
        let dir = fixtures_dir();
        // Should return a path ending in "fixtures"
        assert!(dir.ends_with("fixtures"));
    }

    // -------------------------------------------
    // Handle malformed fixture gracefully
    // -------------------------------------------

    #[test]
    fn test_load_snapshots_malformed_json() {
        let temp = TempDir::new().unwrap();
        let fixture_dir = temp.path();
        fs::create_dir_all(fixture_dir.join("snapshots")).unwrap();

        fs::write(fixture_dir.join("snapshots/bad.jsonl"), "not json").unwrap();

        let result = load_snapshots(fixture_dir, "test");
        assert!(matches!(result, Err(LoadError::SnapshotError(_))));
    }

    // -------------------------------------------
    // Load allowlist
    // -------------------------------------------

    #[test]
    fn test_load_allowlist_present() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("allowlist.txt"), "10.0.0.1\n192.168.0.0/24\n").unwrap();

        let allowlist = load_allowlist(temp.path()).unwrap();
        assert!(allowlist.is_some());
        assert!(allowlist.unwrap().contains("10.0.0.1"));
    }

    #[test]
    fn test_load_allowlist_absent() {
        let temp = TempDir::new().unwrap();
        let allowlist = load_allowlist(temp.path()).unwrap();
        assert!(allowlist.is_none());
    }

    // -------------------------------------------
    // Full fixture load (using real fixtures)
    // -------------------------------------------

    #[test]
    fn test_load_real_fixture() {
        // Test loading a real fixture that exists
        let result = load_fixture("syn_churn_attacker");
        match result {
            Ok(fixture) => {
                assert_eq!(fixture.meta.name, "syn_churn_attacker");
                assert_eq!(fixture.config.dst_ports, vec![8080]);
                assert!(!fixture.snapshots.is_empty());
            }
            Err(LoadError::NotFound(_)) => {
                // Fixtures may not exist in all test environments
                // This is acceptable for unit tests
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_list_real_fixtures() {
        // List real fixtures if they exist
        let fixtures = list_fixtures().unwrap();
        // In the CI environment, fixtures should exist
        // If they don't, the list will just be empty
        for name in fixtures {
            // Each name should be non-empty
            assert!(!name.is_empty());
        }
    }
}
