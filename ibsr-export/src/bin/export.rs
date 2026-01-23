//! ibsr-export CLI binary.
//!
//! Upload IBSR report artefacts to S3 or S3-compatible storage.

use clap::Parser;
use ibsr_export::{
    exit_code, parse_duration, Cli, Command, ExportError, FileSelector, ObjectInfo, OutputFormat,
    Presigner, S3Uploader, UploadManifest,
};
use std::process::ExitCode;
use std::time::Instant;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli).await {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(exit_code(&e))
        }
    }
}

async fn run(cli: Cli) -> Result<(), ExportError> {
    match cli.command {
        Command::S3(args) => run_s3(args).await,
    }
}

async fn run_s3(args: ibsr_export::S3Args) -> Result<(), ExportError> {
    // 1. Validate input directory exists
    if !args.input.exists() {
        return Err(ExportError::InputNotFound(args.input.clone()));
    }

    if !args.input.is_dir() {
        return Err(ExportError::InputNotFound(args.input.clone()));
    }

    // 2. Select files to upload
    let selector = FileSelector::new(&args.include, &args.exclude)?;
    selector.validate_required(&args.input)?;
    let files = selector.select_files(&args.input)?;

    if files.is_empty() {
        eprintln!("warning: no files to upload");
        return Ok(());
    }

    // 3. Determine run ID and prefix
    let run_id = resolve_run_id(&args);
    let prefix = resolve_prefix(&args, &run_id);

    // 4. Build (relative_path, object_key) pairs
    let uploads: Vec<(String, String)> = files
        .iter()
        .map(|p| {
            let rel_path = p.to_string_lossy().to_string();
            let key = if prefix.is_empty() {
                rel_path.clone()
            } else {
                format!("{}/{}", prefix, rel_path)
            };
            (rel_path, key)
        })
        .collect();

    // 5. Dry run: print and exit
    if args.dry_run {
        println!("Dry run - would upload {} file(s):", uploads.len());
        for (path, key) in &uploads {
            println!("  {} -> s3://{}/{}", path, args.bucket, key);
        }
        return Ok(());
    }

    // 6. Create uploader
    let uploader = S3Uploader::new(&args, &run_id).await?;

    // 7. Check for existing objects if --overwrite not set
    if !args.overwrite {
        for (_, key) in &uploads {
            if uploader.object_exists(key).await? {
                return Err(ExportError::ObjectExists(key.clone()));
            }
        }
    }

    // 8. Upload files
    let start = Instant::now();
    let results = uploader.upload_files(&args.input, uploads.clone()).await?;
    let duration = start.elapsed();

    // 9. Generate presigned URLs if requested
    let presigned_urls = if let Some(ref presign_dur) = args.presign {
        let dur = parse_duration(presign_dur)?;
        let presigner = Presigner::new(
            aws_sdk_s3::Client::new(&aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await),
            &args.bucket,
        );

        let mut urls = Vec::new();
        for result in &results {
            let url = presigner.presign_get(&result.key, dur).await?;
            urls.push((result.key.clone(), url));
        }
        Some(urls)
    } else {
        None
    };

    // 10. Build manifest
    let hostname = ibsr_export::MetadataBuilder::new(&run_id).hostname().to_string();
    let mut manifest = UploadManifest::new(
        &run_id,
        &hostname,
        &args.bucket,
        &prefix,
        args.region.as_deref(),
        args.endpoint.as_deref(),
        &args.effective_sse(),
        args.kms_key_id.as_deref(),
    );

    for result in &results {
        let presigned_url = presigned_urls
            .as_ref()
            .and_then(|urls| urls.iter().find(|(k, _)| k == &result.key))
            .map(|(_, url)| url.clone());

        let object_info = ObjectInfo::new(
            &result.path,
            &result.key,
            &result.etag,
            &result.sha256,
            result.size_bytes,
            &result.content_type,
            &args.bucket,
        );

        let object_info = if let Some(url) = presigned_url {
            object_info.with_presigned_url(url)
        } else {
            object_info
        };

        manifest.add_object(object_info);
    }

    manifest.sort_objects();

    // 11. Write manifest
    let manifest_path = args.input.join("upload-manifest.json");
    manifest.write_to(&manifest_path)?;

    // 12. Output
    match args.output {
        OutputFormat::Text => {
            println!(
                "Uploaded: {} ok, 0 failed, Duration: {:.1}s",
                results.len(),
                duration.as_secs_f64()
            );
            println!("Manifest written to: {}", manifest_path.display());

            if presigned_urls.is_some() {
                println!("\nPresigned URLs:");
                for obj in &manifest.objects {
                    if let Some(url) = &obj.presigned_get_url {
                        println!("  {}: {}", obj.path, url);
                    }
                }
            }
        }
        OutputFormat::Json => {
            println!("{}", manifest.to_json()?);
        }
    }

    Ok(())
}

/// Resolve the run ID from args or input directory name.
fn resolve_run_id(args: &ibsr_export::S3Args) -> String {
    if let Some(id) = &args.run_id {
        return id.clone();
    }

    // Try to extract from input directory name (e.g., "run-2026-01-22T1015Z")
    if let Some(name) = args.input.file_name().and_then(|n| n.to_str()) {
        if name.starts_with("run-") || name.contains("T") {
            return name.to_string();
        }
    }

    // Default to current UTC timestamp
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Resolve the prefix from args or generate default.
fn resolve_prefix(args: &ibsr_export::S3Args, run_id: &str) -> String {
    if let Some(prefix) = &args.prefix {
        return prefix.clone();
    }

    // Default: ibsr/<hostname>/<run-id>
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());

    format!("ibsr/{}/{}", hostname, run_id)
}
