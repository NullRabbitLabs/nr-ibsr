//! Content-type mapping for file extensions.

/// Returns the content type for a given file extension.
///
/// Mappings:
/// - `.md` -> `text/markdown; charset=utf-8`
/// - `.json` -> `application/json; charset=utf-8`
/// - `.csv` -> `text/csv; charset=utf-8`
/// - `.pdf` -> `application/pdf`
/// - default -> `application/octet-stream`
pub fn content_type_for_extension(ext: &str) -> &'static str {
    match ext.to_lowercase().as_str() {
        "md" => "text/markdown; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "pdf" => "application/pdf",
        "txt" => "text/plain; charset=utf-8",
        "html" | "htm" => "text/html; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "yaml" | "yml" => "text/yaml; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Returns the content type for a file path based on its extension.
pub fn content_type_for_path(path: &std::path::Path) -> &'static str {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(content_type_for_extension)
        .unwrap_or("application/octet-stream")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_markdown() {
        assert_eq!(content_type_for_extension("md"), "text/markdown; charset=utf-8");
        assert_eq!(content_type_for_extension("MD"), "text/markdown; charset=utf-8");
    }

    #[test]
    fn test_json() {
        assert_eq!(
            content_type_for_extension("json"),
            "application/json; charset=utf-8"
        );
    }

    #[test]
    fn test_csv() {
        assert_eq!(content_type_for_extension("csv"), "text/csv; charset=utf-8");
    }

    #[test]
    fn test_pdf() {
        assert_eq!(content_type_for_extension("pdf"), "application/pdf");
    }

    #[test]
    fn test_unknown() {
        assert_eq!(content_type_for_extension("xyz"), "application/octet-stream");
        assert_eq!(content_type_for_extension(""), "application/octet-stream");
    }

    #[test]
    fn test_content_type_for_path() {
        assert_eq!(
            content_type_for_path(Path::new("report.md")),
            "text/markdown; charset=utf-8"
        );
        assert_eq!(
            content_type_for_path(Path::new("/path/to/summary.json")),
            "application/json; charset=utf-8"
        );
        assert_eq!(
            content_type_for_path(Path::new("no_extension")),
            "application/octet-stream"
        );
    }
}
