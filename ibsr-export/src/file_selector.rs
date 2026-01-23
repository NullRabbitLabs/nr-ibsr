//! File selection logic for upload.

use crate::error::ExportError;
use glob::Pattern;
use std::path::{Path, PathBuf};

/// Default files to upload (if they exist).
const DEFAULT_FILES: &[&str] = &["report.md", "summary.json", "evidence.csv", "manifest.json"];

/// Required files that must exist.
const REQUIRED_FILES: &[&str] = &["report.md", "summary.json"];

/// Selects files for upload based on defaults and include/exclude patterns.
pub struct FileSelector {
    include_patterns: Vec<Pattern>,
    exclude_patterns: Vec<Pattern>,
}

impl FileSelector {
    /// Create a new file selector with the given include/exclude patterns.
    pub fn new(includes: &[String], excludes: &[String]) -> Result<Self, ExportError> {
        let include_patterns = includes
            .iter()
            .map(|p| {
                Pattern::new(p).map_err(|_| ExportError::InvalidGlobPattern(p.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let exclude_patterns = excludes
            .iter()
            .map(|p| {
                Pattern::new(p).map_err(|_| ExportError::InvalidGlobPattern(p.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            include_patterns,
            exclude_patterns,
        })
    }

    /// Validate that required files exist in the input directory.
    pub fn validate_required(&self, input_dir: &Path) -> Result<(), ExportError> {
        for file in REQUIRED_FILES {
            let path = input_dir.join(file);
            if !path.exists() {
                return Err(ExportError::RequiredArtefactMissing(file.to_string()));
            }
        }
        Ok(())
    }

    /// Select files to upload from the input directory.
    ///
    /// Returns paths relative to the input directory.
    pub fn select_files(&self, input_dir: &Path) -> Result<Vec<PathBuf>, ExportError> {
        let mut files = Vec::new();

        // Add default files if they exist
        for file in DEFAULT_FILES {
            let path = input_dir.join(file);
            if path.exists() && path.is_file() {
                files.push(PathBuf::from(*file));
            }
        }

        // Add files matching include patterns
        if !self.include_patterns.is_empty() {
            for entry in std::fs::read_dir(input_dir)? {
                let entry = entry?;
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                // Check if matches any include pattern
                let matches_include = self
                    .include_patterns
                    .iter()
                    .any(|p| p.matches(file_name));

                if matches_include {
                    let relative = PathBuf::from(file_name);
                    if !files.contains(&relative) {
                        files.push(relative);
                    }
                }
            }
        }

        // Remove files matching exclude patterns
        files.retain(|f| {
            let file_name = f.file_name().and_then(|n| n.to_str()).unwrap_or("");
            !self.exclude_patterns.iter().any(|p| p.matches(file_name))
        });

        // Sort for deterministic ordering
        files.sort();

        Ok(files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::TempDir;

    fn create_test_dir() -> TempDir {
        let dir = TempDir::new().unwrap();
        File::create(dir.path().join("report.md")).unwrap();
        File::create(dir.path().join("summary.json")).unwrap();
        File::create(dir.path().join("evidence.csv")).unwrap();
        File::create(dir.path().join("extra.pdf")).unwrap();
        File::create(dir.path().join("debug.log")).unwrap();
        dir
    }

    #[test]
    fn test_default_files() {
        let dir = create_test_dir();
        let selector = FileSelector::new(&[], &[]).unwrap();

        let files = selector.select_files(dir.path()).unwrap();

        assert!(files.contains(&PathBuf::from("report.md")));
        assert!(files.contains(&PathBuf::from("summary.json")));
        assert!(files.contains(&PathBuf::from("evidence.csv")));
        assert!(!files.contains(&PathBuf::from("extra.pdf")));
        assert!(!files.contains(&PathBuf::from("debug.log")));
    }

    #[test]
    fn test_include_pattern() {
        let dir = create_test_dir();
        let selector = FileSelector::new(&["*.pdf".to_string()], &[]).unwrap();

        let files = selector.select_files(dir.path()).unwrap();

        assert!(files.contains(&PathBuf::from("extra.pdf")));
    }

    #[test]
    fn test_exclude_pattern() {
        let dir = create_test_dir();
        let selector = FileSelector::new(&[], &["evidence.csv".to_string()]).unwrap();

        let files = selector.select_files(dir.path()).unwrap();

        assert!(files.contains(&PathBuf::from("report.md")));
        assert!(files.contains(&PathBuf::from("summary.json")));
        assert!(!files.contains(&PathBuf::from("evidence.csv")));
    }

    #[test]
    fn test_validate_required_success() {
        let dir = create_test_dir();
        let selector = FileSelector::new(&[], &[]).unwrap();

        assert!(selector.validate_required(dir.path()).is_ok());
    }

    #[test]
    fn test_validate_required_missing() {
        let dir = TempDir::new().unwrap();
        File::create(dir.path().join("report.md")).unwrap();
        // summary.json is missing

        let selector = FileSelector::new(&[], &[]).unwrap();
        let result = selector.validate_required(dir.path());

        assert!(matches!(
            result,
            Err(ExportError::RequiredArtefactMissing(f)) if f == "summary.json"
        ));
    }

    #[test]
    fn test_invalid_glob() {
        let result = FileSelector::new(&["[invalid".to_string()], &[]);
        assert!(matches!(result, Err(ExportError::InvalidGlobPattern(_))));
    }

    #[test]
    fn test_files_sorted() {
        let dir = create_test_dir();
        let selector = FileSelector::new(&["*.pdf".to_string(), "*.log".to_string()], &[]).unwrap();

        let files = selector.select_files(dir.path()).unwrap();

        // Verify sorted order
        let sorted: Vec<_> = files.iter().cloned().collect();
        let mut expected = sorted.clone();
        expected.sort();
        assert_eq!(sorted, expected);
    }
}
