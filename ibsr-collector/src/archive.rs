//! Phase 6 — warm-tier archiving for record-incident.
//!
//! Periodically scans the recording out-dir for `packets.pcap` files
//! older than `archive_after_sec`, gzips them into the archive dir,
//! and deletes the originals. Operates as a stateless sweeper that
//! the orchestrator invokes at `archive_check_interval` ticks.
//!
//! The sweep logic is split into pure (`should_archive`,
//! `archive_target_path`) and side-effectful (`archive_file`)
//! pieces so the unit tests pin behaviour without real filesystem
//! ops; integration tests cover the gzip+rename plumbing.

use std::path::{Path, PathBuf};

use flate2::write::GzEncoder;
use flate2::Compression;

/// Decide whether a file's mtime makes it eligible for archive.
/// Pure function. `now_unix_sec` and `mtime_unix_sec` are in seconds;
/// `min_age_sec` is the threshold.
pub fn should_archive(
    mtime_unix_sec: u64,
    now_unix_sec: u64,
    min_age_sec: u64,
) -> bool {
    now_unix_sec.saturating_sub(mtime_unix_sec) >= min_age_sec
}

/// Map a source pcap file path under `out_dir` to its archive path
/// under `archive_dir` (relative path preserved + `.gz` suffix). Pure
/// function so tests pin the mapping.
///
/// If `src` is not under `out_dir`, falls back to using just the
/// file's basename — this is a safety check, not the happy path.
pub fn archive_target_path(
    src: &Path,
    out_dir: &Path,
    archive_dir: &Path,
) -> PathBuf {
    let rel = src.strip_prefix(out_dir).unwrap_or_else(|_| {
        // Use just the file name as fallback.
        Path::new(src.file_name().unwrap_or_else(|| src.as_os_str()))
    });
    let mut target = archive_dir.join(rel);
    let new_name = match target.file_name() {
        Some(name) => {
            let mut s = name.to_os_string();
            s.push(".gz");
            s
        }
        None => "archive.pcap.gz".into(),
    };
    target.set_file_name(new_name);
    target
}

/// Gzip-compress one file from `src` into `dst`, then delete `src`.
/// `dst`'s parent directory is created if missing. The src is
/// deleted only after the gzip completes successfully — partial
/// archive failures leave the source intact for the next sweep.
///
/// I/O wrapper; tested via integration. Pure-shape for unit-test
/// mocking is the caller's responsibility (see `archive_files_in`
/// + `Filesystem`-style abstraction below).
pub fn archive_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let input = std::fs::File::open(src)?;
    let output = std::fs::File::create(dst)?;
    let mut encoder = GzEncoder::new(output, Compression::default());
    let mut reader = std::io::BufReader::new(input);
    std::io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?;
    // Only remove source after successful gzip.
    std::fs::remove_file(src)?;
    Ok(())
}

/// One pass over `out_dir`: find every `*.pcap` whose mtime is older
/// than `min_age_sec`, archive it to `archive_dir`. Returns the
/// number of files archived. Failures on individual files are
/// logged-via-the-caller (we just count them in `errors`).
///
/// Used by the orchestrator's periodic sweep tick.
pub fn archive_pass(
    out_dir: &Path,
    archive_dir: &Path,
    min_age_sec: u64,
    now_unix_sec: u64,
) -> ArchivePassResult {
    let mut result = ArchivePassResult::default();
    let entries = match std::fs::read_dir(out_dir) {
        Ok(e) => e,
        Err(_) => return result, // out_dir missing → nothing to archive
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Recurse one level to handle phase-4 tag-partitioned
            // sub-directories. We don't recurse arbitrarily deep —
            // the layout is at most {out-dir}/{tag-ts}/packets.pcap.
            if let Ok(inner) = std::fs::read_dir(&path) {
                for sub in inner.flatten() {
                    let sub_path = sub.path();
                    process_one(&sub_path, out_dir, archive_dir, min_age_sec, now_unix_sec, &mut result);
                }
            }
            continue;
        }
        process_one(&path, out_dir, archive_dir, min_age_sec, now_unix_sec, &mut result);
    }
    result
}

fn process_one(
    path: &Path,
    out_dir: &Path,
    archive_dir: &Path,
    min_age_sec: u64,
    now_unix_sec: u64,
    result: &mut ArchivePassResult,
) {
    if path.extension().and_then(|s| s.to_str()) != Some("pcap") {
        return;
    }
    let mtime_sec = match path
        .metadata()
        .and_then(|m| m.modified())
        .and_then(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "pre-epoch mtime"))
        })
    {
        Ok(d) => d.as_secs(),
        Err(_) => return,
    };
    if !should_archive(mtime_sec, now_unix_sec, min_age_sec) {
        return;
    }
    let dst = archive_target_path(path, out_dir, archive_dir);
    match archive_file(path, &dst) {
        Ok(()) => result.archived += 1,
        Err(_) => result.errors += 1,
    }
}

/// Result of one sweep pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ArchivePassResult {
    pub archived: u64,
    pub errors: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_archive_returns_true_when_age_exceeds_threshold() {
        // mtime = 1000, now = 5000, min_age = 3000 → diff 4000 >= 3000.
        assert!(should_archive(1000, 5000, 3000));
    }

    #[test]
    fn should_archive_returns_true_at_exact_threshold() {
        assert!(should_archive(1000, 4000, 3000));
    }

    #[test]
    fn should_archive_returns_false_below_threshold() {
        assert!(!should_archive(1000, 3500, 3000));
    }

    #[test]
    fn should_archive_handles_zero_age() {
        // min_age=0 — any age qualifies, including same-second.
        assert!(should_archive(100, 100, 0));
    }

    #[test]
    fn should_archive_saturates_on_negative_diff() {
        // mtime in the future (clock skew) — diff saturates to 0.
        assert!(!should_archive(5000, 1000, 1));
        assert!(should_archive(5000, 1000, 0));
    }

    #[test]
    fn archive_target_path_preserves_relative_layout() {
        let src = PathBuf::from("/var/lib/ibsr/incidents/A-100/packets.pcap");
        let out = PathBuf::from("/var/lib/ibsr/incidents");
        let arc = PathBuf::from("/srv/archive");
        let target = archive_target_path(&src, &out, &arc);
        assert_eq!(
            target,
            PathBuf::from("/srv/archive/A-100/packets.pcap.gz"),
        );
    }

    #[test]
    fn archive_target_path_falls_back_to_basename_when_out_doesnt_match() {
        let src = PathBuf::from("/elsewhere/x.pcap");
        let out = PathBuf::from("/var/lib/ibsr/incidents");
        let arc = PathBuf::from("/srv/archive");
        let target = archive_target_path(&src, &out, &arc);
        assert_eq!(target, PathBuf::from("/srv/archive/x.pcap.gz"));
    }

    #[test]
    fn archive_target_path_appends_gz_suffix() {
        let src = PathBuf::from("/o/d/packets.pcap");
        let out = PathBuf::from("/o");
        let arc = PathBuf::from("/a");
        let target = archive_target_path(&src, &out, &arc);
        assert!(target.to_string_lossy().ends_with(".pcap.gz"));
    }

    #[test]
    fn archive_pass_skips_missing_out_dir() {
        // Pointing at a non-existent dir shouldn't panic or error;
        // the function returns ArchivePassResult { 0, 0 }.
        let result = archive_pass(
            Path::new("/no/such/path/ibsr/incidents"),
            Path::new("/no/such/archive"),
            3600,
            1_700_000_000,
        );
        assert_eq!(result.archived, 0);
        assert_eq!(result.errors, 0);
    }

    #[test]
    fn archive_pass_handles_real_files() {
        // Integration-style test using tempdir. Creates an aged
        // pcap, sweeps, verifies it lands in the archive as .pcap.gz
        // and the source is removed.
        let out_dir = std::env::temp_dir().join(format!(
            "ibsr-archive-test-out-{}",
            std::process::id(),
        ));
        let arc_dir = std::env::temp_dir().join(format!(
            "ibsr-archive-test-arc-{}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&out_dir);
        let _ = std::fs::remove_dir_all(&arc_dir);
        std::fs::create_dir_all(&out_dir).unwrap();
        std::fs::create_dir_all(out_dir.join("A-100")).unwrap();
        let src = out_dir.join("A-100").join("packets.pcap");
        std::fs::write(&src, b"some pcap bytes").unwrap();

        // Set mtime to far in the past so it qualifies as old.
        // We don't have utimes via std; rely on now_unix_sec being
        // far in the future to make any current file qualify.
        let now = u64::MAX / 2;

        let result = archive_pass(&out_dir, &arc_dir, 1, now);
        assert!(result.archived >= 1, "expected at least one archive: {:?}", result);
        assert!(!src.exists(), "source pcap must be removed after archive");
        let archived = arc_dir.join("A-100").join("packets.pcap.gz");
        assert!(archived.exists(), "archive must exist: {:?}", archived);
        // Cleanup.
        let _ = std::fs::remove_dir_all(&out_dir);
        let _ = std::fs::remove_dir_all(&arc_dir);
    }

    #[test]
    fn archive_file_creates_parent_dir() {
        let dir = std::env::temp_dir().join(format!(
            "ibsr-archive-mkdir-{}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let src = dir.join("src.pcap");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&src, b"hello").unwrap();
        let dst = dir.join("nested/deep/dst.pcap.gz");
        archive_file(&src, &dst).expect("archive ok");
        assert!(dst.exists(),
            "archive_file must create the parent directory chain");
        assert!(!src.exists(), "source must be removed");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
