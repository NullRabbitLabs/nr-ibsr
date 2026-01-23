//! Integration tests for ibsr-export using MinIO.
//!
//! These tests require a running MinIO instance. Run with:
//!
//! ```bash
//! # Start MinIO
//! docker compose up -d minio
//!
//! # Create test bucket
//! docker compose exec minio mc alias set local http://localhost:9000 minioadmin minioadmin
//! docker compose exec minio mc mb local/test-bucket
//!
//! # Run integration tests
//! AWS_ACCESS_KEY_ID=minioadmin \
//! AWS_SECRET_ACCESS_KEY=minioadmin \
//! MINIO_ENDPOINT=http://localhost:9000 \
//! cargo test --features integration -- --ignored
//! ```

#![cfg(feature = "integration")]

use std::env;
use std::fs::File;
use std::io::Write;
use std::process::Command;
use tempfile::TempDir;

fn minio_endpoint() -> String {
    env::var("MINIO_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".to_string())
}

fn test_bucket() -> String {
    env::var("TEST_BUCKET").unwrap_or_else(|_| "test-bucket".to_string())
}

/// Create a test input directory with artefacts.
fn create_test_input() -> TempDir {
    let dir = TempDir::new().expect("Failed to create temp dir");

    let mut report = File::create(dir.path().join("report.md")).unwrap();
    writeln!(report, "# Test Report\n\nThis is a test report.").unwrap();

    let mut summary = File::create(dir.path().join("summary.json")).unwrap();
    writeln!(summary, r#"{{"test": "data", "count": 42}}"#).unwrap();

    let mut evidence = File::create(dir.path().join("evidence.csv")).unwrap();
    writeln!(evidence, "ip,count\n10.0.0.1,100\n10.0.0.2,50").unwrap();

    dir
}

/// Run ibsr-export with the given arguments.
fn run_export(args: &[&str]) -> std::process::Output {
    let binary = env!("CARGO_BIN_EXE_ibsr-export");

    Command::new(binary)
        .args(args)
        .env("AWS_ACCESS_KEY_ID", "minioadmin")
        .env("AWS_SECRET_ACCESS_KEY", "minioadmin")
        .output()
        .expect("Failed to execute ibsr-export")
}

#[test]
#[ignore = "requires running MinIO"]
fn test_dry_run() {
    let input = create_test_input();
    let endpoint = minio_endpoint();
    let bucket = test_bucket();

    let output = run_export(&[
        "s3",
        "--input",
        input.path().to_str().unwrap(),
        "--bucket",
        &bucket,
        "--endpoint",
        &endpoint,
        "--force-path-style",
        "--dry-run",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    assert!(output.status.success(), "Expected success exit code");
    assert!(stdout.contains("Dry run"), "Expected dry run output");
    assert!(stdout.contains("report.md"), "Expected report.md in output");
    assert!(stdout.contains("summary.json"), "Expected summary.json in output");
}

#[test]
#[ignore = "requires running MinIO"]
fn test_upload_to_minio() {
    let input = create_test_input();
    let endpoint = minio_endpoint();
    let bucket = test_bucket();

    // Generate unique prefix to avoid collisions
    let prefix = format!("test-{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis());

    let output = run_export(&[
        "s3",
        "--input",
        input.path().to_str().unwrap(),
        "--bucket",
        &bucket,
        "--prefix",
        &prefix,
        "--endpoint",
        &endpoint,
        "--force-path-style",
        "--sse",
        "none", // MinIO doesn't support SSE-S3 by default
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    assert!(output.status.success(), "Expected success exit code");
    assert!(stdout.contains("Uploaded:"), "Expected upload summary");
    assert!(stdout.contains("3 ok"), "Expected 3 files uploaded");

    // Verify manifest was written
    let manifest_path = input.path().join("upload-manifest.json");
    assert!(manifest_path.exists(), "Expected upload-manifest.json to be written");

    let manifest_content = std::fs::read_to_string(&manifest_path).unwrap();
    assert!(manifest_content.contains(&bucket), "Manifest should contain bucket");
    assert!(manifest_content.contains(&prefix), "Manifest should contain prefix");
    assert!(manifest_content.contains("report.md"), "Manifest should contain report.md");
}

#[test]
#[ignore = "requires running MinIO"]
fn test_json_output() {
    let input = create_test_input();
    let endpoint = minio_endpoint();
    let bucket = test_bucket();

    let prefix = format!("test-json-{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis());

    let output = run_export(&[
        "s3",
        "--input",
        input.path().to_str().unwrap(),
        "--bucket",
        &bucket,
        "--prefix",
        &prefix,
        "--endpoint",
        &endpoint,
        "--force-path-style",
        "--sse",
        "none",
        "--output",
        "json",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "Expected success exit code");

    // Verify JSON output is valid
    let manifest: serde_json::Value = serde_json::from_str(&stdout)
        .expect("Expected valid JSON output");

    assert_eq!(manifest["version"], 1);
    assert_eq!(manifest["tool"], "ibsr-export");
    assert!(manifest["objects"].is_array());
}

#[test]
#[ignore = "requires running MinIO"]
fn test_missing_input_directory() {
    let endpoint = minio_endpoint();
    let bucket = test_bucket();

    let output = run_export(&[
        "s3",
        "--input",
        "/nonexistent/path",
        "--bucket",
        &bucket,
        "--endpoint",
        &endpoint,
        "--force-path-style",
    ]);

    assert!(!output.status.success(), "Expected failure exit code");
    assert_eq!(output.status.code(), Some(2), "Expected exit code 2");
}

#[test]
#[ignore = "requires running MinIO"]
fn test_missing_required_artefacts() {
    let dir = TempDir::new().unwrap();
    // Create only report.md, missing summary.json
    File::create(dir.path().join("report.md")).unwrap();

    let endpoint = minio_endpoint();
    let bucket = test_bucket();

    let output = run_export(&[
        "s3",
        "--input",
        dir.path().to_str().unwrap(),
        "--bucket",
        &bucket,
        "--endpoint",
        &endpoint,
        "--force-path-style",
    ]);

    assert!(!output.status.success(), "Expected failure exit code");
    assert_eq!(output.status.code(), Some(3), "Expected exit code 3");
}
