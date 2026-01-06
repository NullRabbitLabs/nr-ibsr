//! XDP Safety Invariant Verification
//!
//! This module provides both source-level and ELF-level analysis to verify
//! that the XDP program cannot drop, redirect, or emit per-packet events.

use regex::Regex;
use std::collections::HashSet;
use thiserror::Error;

/// Forbidden XDP return actions that could affect packet flow.
const FORBIDDEN_XDP_ACTIONS: &[&str] = &[
    "XDP_DROP",
    "XDP_ABORTED",
    "XDP_REDIRECT",
    "XDP_TX",
];

/// Forbidden BPF helper functions that could emit events or redirect.
const FORBIDDEN_BPF_HELPERS: &[&str] = &[
    "bpf_redirect",
    "bpf_redirect_map",
    "bpf_xdp_redirect_map",
    "bpf_perf_event_output",
    "bpf_ringbuf_output",
    "bpf_ringbuf_reserve",
    "bpf_ringbuf_submit",
];

/// Forbidden map types that could be used for redirection.
const FORBIDDEN_MAP_TYPES: &[&str] = &[
    "BPF_MAP_TYPE_DEVMAP",
    "BPF_MAP_TYPE_DEVMAP_HASH",
    "BPF_MAP_TYPE_XSKMAP",
    "BPF_MAP_TYPE_CPUMAP",
    "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
    "BPF_MAP_TYPE_RINGBUF",
];

/// Required map type for bounded memory.
const REQUIRED_MAP_TYPE: &str = "BPF_MAP_TYPE_LRU_HASH";

/// Errors from safety verification.
#[derive(Debug, Error)]
pub enum SafetyError {
    #[error("forbidden XDP action found: {0}")]
    ForbiddenAction(String),

    #[error("forbidden BPF helper found: {0}")]
    ForbiddenHelper(String),

    #[error("forbidden map type found: {0}")]
    ForbiddenMapType(String),

    #[error("required LRU map type not found")]
    MissingLruMap,

    #[error("ELF parsing error: {0}")]
    ElfError(String),

    #[error("source analysis error: {0}")]
    SourceError(String),
}

/// Result of safety verification.
#[derive(Debug, Default)]
pub struct SafetyReport {
    pub forbidden_actions: Vec<String>,
    pub forbidden_helpers: Vec<String>,
    pub forbidden_map_types: Vec<String>,
    pub has_lru_map: bool,
    pub is_safe: bool,
}

impl SafetyReport {
    /// Check if the program passes all safety requirements.
    pub fn validate(&self) -> Result<(), SafetyError> {
        if let Some(action) = self.forbidden_actions.first() {
            return Err(SafetyError::ForbiddenAction(action.clone()));
        }
        if let Some(helper) = self.forbidden_helpers.first() {
            return Err(SafetyError::ForbiddenHelper(helper.clone()));
        }
        if let Some(map_type) = self.forbidden_map_types.first() {
            return Err(SafetyError::ForbiddenMapType(map_type.clone()));
        }
        if !self.has_lru_map {
            return Err(SafetyError::MissingLruMap);
        }
        Ok(())
    }
}

/// Analyze C source code for forbidden patterns.
pub fn analyze_source(source: &str) -> SafetyReport {
    let mut report = SafetyReport::default();

    // Check for forbidden XDP actions (as return values)
    for action in FORBIDDEN_XDP_ACTIONS {
        // Match "return XDP_DROP" or similar patterns
        let pattern = format!(r"\breturn\s+{}\b", regex::escape(action));
        // Pattern is always valid since action is alphanumeric
        let re = Regex::new(&pattern).expect("valid regex pattern");
        if re.is_match(source) {
            report.forbidden_actions.push(action.to_string());
        }
    }

    // Check for forbidden BPF helpers
    for helper in FORBIDDEN_BPF_HELPERS {
        let pattern = format!(r"\b{}\s*\(", regex::escape(helper));
        // Pattern is always valid since helper is alphanumeric
        let re = Regex::new(&pattern).expect("valid regex pattern");
        if re.is_match(source) {
            report.forbidden_helpers.push(helper.to_string());
        }
    }

    // Check for forbidden map types
    for map_type in FORBIDDEN_MAP_TYPES {
        if source.contains(map_type) {
            report.forbidden_map_types.push(map_type.to_string());
        }
    }

    // Check for required LRU map
    report.has_lru_map = source.contains(REQUIRED_MAP_TYPE);

    // Determine overall safety
    report.is_safe = report.forbidden_actions.is_empty()
        && report.forbidden_helpers.is_empty()
        && report.forbidden_map_types.is_empty()
        && report.has_lru_map;

    report
}

/// Analyze compiled ELF for forbidden symbols.
pub fn analyze_elf(elf_bytes: &[u8]) -> Result<SafetyReport, SafetyError> {
    use object::{Object, ObjectSection, ObjectSymbol};

    let file = object::File::parse(elf_bytes)
        .map_err(|e| SafetyError::ElfError(e.to_string()))?;

    let mut report = SafetyReport::default();
    let mut found_symbols: HashSet<String> = HashSet::new();

    // Collect all symbol names
    for symbol in file.symbols() {
        if let Ok(name) = symbol.name() {
            found_symbols.insert(name.to_string());
        }
    }

    // Check for forbidden helpers in symbols
    for helper in FORBIDDEN_BPF_HELPERS {
        if found_symbols.contains(*helper) {
            report.forbidden_helpers.push(helper.to_string());
        }
    }

    // For ELF analysis, we check section names for map definitions
    // and look for specific patterns in the data
    for section in file.sections() {
        let name = match section.name() {
            Ok(n) => n,
            Err(_) => continue,
        };

        // Check if this is a maps section
        if !name.contains("maps") && !name.contains(".rodata") {
            continue;
        }

        let data = match section.data() {
            Ok(d) => d,
            Err(_) => continue,
        };

        let data_str = String::from_utf8_lossy(data);

        // Check for forbidden map types in section data
        for map_type in FORBIDDEN_MAP_TYPES {
            if data_str.contains(map_type) {
                report.forbidden_map_types.push(map_type.to_string());
            }
        }

        // Check for LRU map
        if data_str.contains(REQUIRED_MAP_TYPE) {
            report.has_lru_map = true;
        }
    }

    // Note: XDP actions are compile-time constants, so we can't easily detect them
    // in the ELF without disassembling. Source analysis handles this.
    // For ELF, we focus on helper calls and map types.

    report.is_safe = report.forbidden_actions.is_empty()
        && report.forbidden_helpers.is_empty()
        && report.forbidden_map_types.is_empty();

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===========================================
    // Test Category B — XDP Safety Invariants
    // ===========================================

    // --- Source Analysis Tests ---

    #[test]
    fn test_source_detects_xdp_drop() {
        let source = r#"
            int xdp_prog(struct xdp_md *ctx) {
                return XDP_DROP;
            }
        "#;

        let report = analyze_source(source);

        assert!(!report.is_safe);
        assert!(report.forbidden_actions.contains(&"XDP_DROP".to_string()));
    }

    #[test]
    fn test_source_detects_xdp_aborted() {
        let source = r#"
            int xdp_prog(struct xdp_md *ctx) {
                return XDP_ABORTED;
            }
        "#;

        let report = analyze_source(source);

        assert!(!report.is_safe);
        assert!(report.forbidden_actions.contains(&"XDP_ABORTED".to_string()));
    }

    #[test]
    fn test_source_detects_xdp_redirect() {
        let source = r#"
            int xdp_prog(struct xdp_md *ctx) {
                return XDP_REDIRECT;
            }
        "#;

        let report = analyze_source(source);

        assert!(!report.is_safe);
        assert!(report.forbidden_actions.contains(&"XDP_REDIRECT".to_string()));
    }

    #[test]
    fn test_source_detects_xdp_tx() {
        let source = r#"
            int xdp_prog(struct xdp_md *ctx) {
                return XDP_TX;
            }
        "#;

        let report = analyze_source(source);

        assert!(!report.is_safe);
        assert!(report.forbidden_actions.contains(&"XDP_TX".to_string()));
    }

    #[test]
    fn test_source_detects_bpf_redirect() {
        let source = r#"
            int xdp_prog(struct xdp_md *ctx) {
                bpf_redirect(1, 0);
                return XDP_PASS;
            }
        "#;

        let report = analyze_source(source);

        assert!(!report.is_safe);
        assert!(report.forbidden_helpers.contains(&"bpf_redirect".to_string()));
    }

    #[test]
    fn test_source_detects_ringbuf_output() {
        let source = r#"
            int xdp_prog(struct xdp_md *ctx) {
                bpf_ringbuf_output(&rb, &event, sizeof(event), 0);
                return XDP_PASS;
            }
        "#;

        let report = analyze_source(source);

        assert!(!report.is_safe);
        assert!(report.forbidden_helpers.contains(&"bpf_ringbuf_output".to_string()));
    }

    #[test]
    fn test_source_detects_perf_event_output() {
        let source = r#"
            int xdp_prog(struct xdp_md *ctx) {
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
                return XDP_PASS;
            }
        "#;

        let report = analyze_source(source);

        assert!(!report.is_safe);
        assert!(report.forbidden_helpers.contains(&"bpf_perf_event_output".to_string()));
    }

    #[test]
    fn test_source_detects_devmap() {
        let source = r#"
            struct {
                __uint(type, BPF_MAP_TYPE_DEVMAP);
                __uint(max_entries, 256);
            } devmap SEC(".maps");
        "#;

        let report = analyze_source(source);

        assert!(!report.is_safe);
        assert!(report.forbidden_map_types.contains(&"BPF_MAP_TYPE_DEVMAP".to_string()));
    }

    #[test]
    fn test_source_detects_ringbuf_map() {
        let source = r#"
            struct {
                __uint(type, BPF_MAP_TYPE_RINGBUF);
                __uint(max_entries, 256 * 1024);
            } ringbuf SEC(".maps");
        "#;

        let report = analyze_source(source);

        assert!(!report.is_safe);
        assert!(report.forbidden_map_types.contains(&"BPF_MAP_TYPE_RINGBUF".to_string()));
    }

    #[test]
    fn test_source_requires_lru_map() {
        let source = r#"
            int xdp_prog(struct xdp_md *ctx) {
                return XDP_PASS;
            }
        "#;

        let report = analyze_source(source);

        assert!(!report.is_safe);
        assert!(!report.has_lru_map);
    }

    #[test]
    fn test_source_accepts_lru_hash_map() {
        let source = r#"
            struct {
                __uint(type, BPF_MAP_TYPE_LRU_HASH);
                __uint(max_entries, 100000);
            } counters SEC(".maps");

            int xdp_prog(struct xdp_md *ctx) {
                return XDP_PASS;
            }
        "#;

        let report = analyze_source(source);

        assert!(report.has_lru_map);
        assert!(report.forbidden_actions.is_empty());
        assert!(report.forbidden_helpers.is_empty());
        assert!(report.forbidden_map_types.is_empty());
        assert!(report.is_safe);
    }

    #[test]
    fn test_source_allows_xdp_pass() {
        let source = r#"
            struct {
                __uint(type, BPF_MAP_TYPE_LRU_HASH);
                __uint(max_entries, 100000);
            } counters SEC(".maps");

            int xdp_prog(struct xdp_md *ctx) {
                return XDP_PASS;
            }
        "#;

        let report = analyze_source(source);

        assert!(report.is_safe);
        assert!(!report.forbidden_actions.contains(&"XDP_PASS".to_string()));
    }

    #[test]
    fn test_source_multiple_violations() {
        let source = r#"
            struct {
                __uint(type, BPF_MAP_TYPE_RINGBUF);
            } ringbuf SEC(".maps");

            int xdp_prog(struct xdp_md *ctx) {
                bpf_ringbuf_output(&ringbuf, &event, sizeof(event), 0);
                return XDP_DROP;
            }
        "#;

        let report = analyze_source(source);

        assert!(!report.is_safe);
        assert!(report.forbidden_actions.contains(&"XDP_DROP".to_string()));
        assert!(report.forbidden_helpers.contains(&"bpf_ringbuf_output".to_string()));
        assert!(report.forbidden_map_types.contains(&"BPF_MAP_TYPE_RINGBUF".to_string()));
    }

    #[test]
    fn test_source_safe_counter_program() {
        // This represents what our actual XDP program should look like
        let source = r#"
            #include <linux/bpf.h>
            #include <bpf/bpf_helpers.h>

            struct counters {
                __u32 syn;
                __u32 ack;
                __u32 rst;
                __u32 packets;
                __u64 bytes;
            };

            struct {
                __uint(type, BPF_MAP_TYPE_LRU_HASH);
                __type(key, __u32);
                __type(value, struct counters);
                __uint(max_entries, 100000);
            } counter_map SEC(".maps");

            SEC("xdp")
            int xdp_counter(struct xdp_md *ctx) {
                // ... packet parsing and counter updates ...
                return XDP_PASS;
            }

            char LICENSE[] SEC("license") = "MIT";
        "#;

        let report = analyze_source(source);

        assert!(report.is_safe);
        assert!(report.has_lru_map);
        assert!(report.forbidden_actions.is_empty());
        assert!(report.forbidden_helpers.is_empty());
        assert!(report.forbidden_map_types.is_empty());
    }

    // --- Safety Report Validation Tests ---

    #[test]
    fn test_report_validate_safe() {
        let report = SafetyReport {
            forbidden_actions: vec![],
            forbidden_helpers: vec![],
            forbidden_map_types: vec![],
            has_lru_map: true,
            is_safe: true,
        };

        assert!(report.validate().is_ok());
    }

    #[test]
    fn test_report_validate_forbidden_action() {
        let report = SafetyReport {
            forbidden_actions: vec!["XDP_DROP".to_string()],
            forbidden_helpers: vec![],
            forbidden_map_types: vec![],
            has_lru_map: true,
            is_safe: false,
        };

        let err = report.validate().unwrap_err();
        assert!(matches!(err, SafetyError::ForbiddenAction(_)));
    }

    #[test]
    fn test_report_validate_forbidden_helper() {
        let report = SafetyReport {
            forbidden_actions: vec![],
            forbidden_helpers: vec!["bpf_redirect".to_string()],
            forbidden_map_types: vec![],
            has_lru_map: true,
            is_safe: false,
        };

        let err = report.validate().unwrap_err();
        assert!(matches!(err, SafetyError::ForbiddenHelper(_)));
    }

    #[test]
    fn test_report_validate_forbidden_map_type() {
        let report = SafetyReport {
            forbidden_actions: vec![],
            forbidden_helpers: vec![],
            forbidden_map_types: vec!["BPF_MAP_TYPE_RINGBUF".to_string()],
            has_lru_map: true,
            is_safe: false,
        };

        let err = report.validate().unwrap_err();
        assert!(matches!(err, SafetyError::ForbiddenMapType(_)));
    }

    #[test]
    fn test_report_validate_missing_lru() {
        let report = SafetyReport {
            forbidden_actions: vec![],
            forbidden_helpers: vec![],
            forbidden_map_types: vec![],
            has_lru_map: false,
            is_safe: false,
        };

        let err = report.validate().unwrap_err();
        assert!(matches!(err, SafetyError::MissingLruMap));
    }

    // --- XDP Action Edge Cases ---

    #[test]
    fn test_source_only_detects_return_statements() {
        // This test verifies we only match actual return statements,
        // not just any mention of XDP_DROP
        let source = r#"
            struct {
                __uint(type, BPF_MAP_TYPE_LRU_HASH);
                __uint(max_entries, 100000);
            } counters SEC(".maps");

            // Note: we never drop packets for safety reasons
            /* XDP_DROP is forbidden */
            #define FORBIDDEN_ACTION XDP_DROP

            int xdp_prog(struct xdp_md *ctx) {
                return XDP_PASS;
            }
        "#;

        let report = analyze_source(source);

        // We only match "return XDP_DROP", not just "XDP_DROP" anywhere
        assert!(report.forbidden_actions.is_empty());
        assert!(report.is_safe);
    }

    #[test]
    fn test_source_detects_conditional_drop() {
        let source = r#"
            struct {
                __uint(type, BPF_MAP_TYPE_LRU_HASH);
                __uint(max_entries, 100000);
            } counters SEC(".maps");

            int xdp_prog(struct xdp_md *ctx) {
                if (should_drop)
                    return XDP_DROP;
                return XDP_PASS;
            }
        "#;

        let report = analyze_source(source);

        assert!(!report.is_safe);
        assert!(report.forbidden_actions.contains(&"XDP_DROP".to_string()));
    }

    // --- ELF Analysis Tests ---

    #[test]
    fn test_elf_invalid_bytes() {
        let invalid_elf = b"not a valid elf file";

        let result = analyze_elf(invalid_elf);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SafetyError::ElfError(_)));
    }

    #[test]
    fn test_elf_empty_file() {
        let empty: &[u8] = &[];

        let result = analyze_elf(empty);

        assert!(result.is_err());
    }

    #[test]
    fn test_elf_truncated_header() {
        // ELF magic but truncated header
        let truncated: &[u8] = &[0x7f, b'E', b'L', b'F', 2, 1, 1, 0];

        let result = analyze_elf(truncated);

        assert!(result.is_err());
    }

    #[test]
    fn test_elf_valid_empty_bpf() {
        use object::write::{Object, Symbol, SymbolSection};
        use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

        // Create a minimal valid BPF ELF using object crate
        let mut obj = Object::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);

        // Add a harmless symbol
        obj.add_symbol(Symbol {
            name: b"xdp_counter".to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Text,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Undefined,
            flags: SymbolFlags::None,
        });

        let elf_bytes = obj.write().expect("failed to write ELF");
        let result = analyze_elf(&elf_bytes);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.forbidden_helpers.is_empty());
        assert!(report.forbidden_map_types.is_empty());
    }

    #[test]
    fn test_elf_detects_forbidden_helper_symbol() {
        use object::write::{Object, Symbol, SymbolSection};
        use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

        let mut obj = Object::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);

        // Add a forbidden helper symbol
        obj.add_symbol(Symbol {
            name: b"bpf_redirect".to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Undefined,
            flags: SymbolFlags::None,
        });

        let elf_bytes = obj.write().expect("failed to write ELF");
        let result = analyze_elf(&elf_bytes);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.forbidden_helpers.contains(&"bpf_redirect".to_string()));
        assert!(!report.is_safe);
    }

    #[test]
    fn test_elf_detects_ringbuf_helper() {
        use object::write::{Object, Symbol, SymbolSection};
        use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

        let mut obj = Object::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);

        obj.add_symbol(Symbol {
            name: b"bpf_ringbuf_output".to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Undefined,
            flags: SymbolFlags::None,
        });

        let elf_bytes = obj.write().expect("failed to write ELF");
        let result = analyze_elf(&elf_bytes);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.forbidden_helpers.contains(&"bpf_ringbuf_output".to_string()));
    }

    #[test]
    fn test_elf_with_maps_section() {
        use object::write::{Object, Symbol, SymbolSection};
        use object::{Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope};

        let mut obj = Object::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);

        // Add a maps section with some data containing map type info
        let section_id = obj.add_section(
            vec![],
            b".maps".to_vec(),
            SectionKind::ReadOnlyData,
        );
        obj.set_section_data(section_id, b"BPF_MAP_TYPE_LRU_HASH", 1);

        obj.add_symbol(Symbol {
            name: b"counter_map".to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Data,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(section_id),
            flags: SymbolFlags::None,
        });

        let elf_bytes = obj.write().expect("failed to write ELF");
        let result = analyze_elf(&elf_bytes);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.has_lru_map);
    }

    #[test]
    fn test_elf_detects_forbidden_map_in_section() {
        use object::write::{Object, Symbol, SymbolSection};
        use object::{Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope};

        let mut obj = Object::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);

        // Add a maps section with forbidden map type
        let section_id = obj.add_section(
            vec![],
            b".maps".to_vec(),
            SectionKind::ReadOnlyData,
        );
        obj.set_section_data(section_id, b"BPF_MAP_TYPE_RINGBUF data here", 1);

        obj.add_symbol(Symbol {
            name: b"ringbuf".to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Data,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(section_id),
            flags: SymbolFlags::None,
        });

        let elf_bytes = obj.write().expect("failed to write ELF");
        let result = analyze_elf(&elf_bytes);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.forbidden_map_types.contains(&"BPF_MAP_TYPE_RINGBUF".to_string()));
    }

    #[test]
    fn test_elf_rodata_section_scanned() {
        use object::write::{Object, Symbol, SymbolSection};
        use object::{Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope};

        let mut obj = Object::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);

        // Add a .rodata section
        let section_id = obj.add_section(
            vec![],
            b".rodata".to_vec(),
            SectionKind::ReadOnlyData,
        );
        obj.set_section_data(section_id, b"BPF_MAP_TYPE_DEVMAP config", 1);

        obj.add_symbol(Symbol {
            name: b"config".to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Data,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(section_id),
            flags: SymbolFlags::None,
        });

        let elf_bytes = obj.write().expect("failed to write ELF");
        let result = analyze_elf(&elf_bytes);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.forbidden_map_types.contains(&"BPF_MAP_TYPE_DEVMAP".to_string()));
    }

    #[test]
    fn test_elf_with_section_name_error() {
        // Create a minimal ELF64 for BPF with a section that has an invalid name offset
        // This tests the Err(_) => continue branch for section.name()
        let mut elf = vec![
            // ELF header (64 bytes)
            0x7f, b'E', b'L', b'F',  // Magic
            2,    // 64-bit
            1,    // Little endian
            1,    // ELF version
            0,    // OS/ABI
            0, 0, 0, 0, 0, 0, 0, 0,  // Padding
            1, 0,  // Type: relocatable
            0xf7, 0x00,  // Machine: BPF
            1, 0, 0, 0,  // Version
            0, 0, 0, 0, 0, 0, 0, 0,  // Entry point
            0, 0, 0, 0, 0, 0, 0, 0,  // Program header offset
            64, 0, 0, 0, 0, 0, 0, 0,  // Section header offset (right after header)
            0, 0, 0, 0,  // Flags
            64, 0,  // ELF header size
            0, 0,   // Program header entry size
            0, 0,   // Program header count
            64, 0,  // Section header entry size
            3, 0,   // Section header count (null + strtab + bad section)
            1, 0,   // Section name string table index
        ];
        // ELF header is exactly 64 bytes, no padding needed

        // Section header 0 (null section) - 64 bytes
        for _ in 0..64 {
            elf.push(0);
        }

        // Section header 1 (string table) - 64 bytes
        let strtab_offset = elf.len() + 128;  // After all section headers
        let strtab: Vec<u8> = vec![
            0,  // null
            b'.', b's', b't', b'r', b't', b'a', b'b', 0,  // .strtab
        ];
        elf.extend_from_slice(&[
            1, 0, 0, 0,  // sh_name = 1 (pointing to ".strtab")
            3, 0, 0, 0,  // sh_type = SHT_STRTAB
            0, 0, 0, 0, 0, 0, 0, 0,  // sh_flags
            0, 0, 0, 0, 0, 0, 0, 0,  // sh_addr
        ]);
        // sh_offset (8 bytes)
        elf.extend_from_slice(&(strtab_offset as u64).to_le_bytes());
        // sh_size (8 bytes)
        elf.extend_from_slice(&(strtab.len() as u64).to_le_bytes());
        elf.extend_from_slice(&[
            0, 0, 0, 0,  // sh_link
            0, 0, 0, 0,  // sh_info
            1, 0, 0, 0, 0, 0, 0, 0,  // sh_addralign
            0, 0, 0, 0, 0, 0, 0, 0,  // sh_entsize
        ]);

        // Section header 2 (section with invalid name offset) - 64 bytes
        elf.extend_from_slice(&[
            255, 255, 0, 0,  // sh_name = 65535 (way past string table)
            1, 0, 0, 0,  // sh_type = SHT_PROGBITS
            0, 0, 0, 0, 0, 0, 0, 0,  // sh_flags
            0, 0, 0, 0, 0, 0, 0, 0,  // sh_addr
            0, 0, 0, 0, 0, 0, 0, 0,  // sh_offset
            0, 0, 0, 0, 0, 0, 0, 0,  // sh_size
            0, 0, 0, 0,  // sh_link
            0, 0, 0, 0,  // sh_info
            1, 0, 0, 0, 0, 0, 0, 0,  // sh_addralign
            0, 0, 0, 0, 0, 0, 0, 0,  // sh_entsize
        ]);

        // Append string table data
        elf.extend_from_slice(&strtab);

        let result = analyze_elf(&elf);
        // Should succeed - the bad section is just skipped
        assert!(result.is_ok());
    }

    #[test]
    fn test_elf_with_section_data_error() {
        // Create a minimal ELF64 for BPF with a .maps section that has invalid data range
        // This tests the Err(_) => continue branch for section.data()
        let mut elf = vec![
            // ELF header (64 bytes)
            0x7f, b'E', b'L', b'F',  // Magic
            2,    // 64-bit
            1,    // Little endian
            1,    // ELF version
            0,    // OS/ABI
            0, 0, 0, 0, 0, 0, 0, 0,  // Padding
            1, 0,  // Type: relocatable
            0xf7, 0x00,  // Machine: BPF
            1, 0, 0, 0,  // Version
            0, 0, 0, 0, 0, 0, 0, 0,  // Entry point
            0, 0, 0, 0, 0, 0, 0, 0,  // Program header offset
            64, 0, 0, 0, 0, 0, 0, 0,  // Section header offset
            0, 0, 0, 0,  // Flags
            64, 0,  // ELF header size
            0, 0,   // Program header entry size
            0, 0,   // Program header count
            64, 0,  // Section header entry size
            3, 0,   // Section header count
            1, 0,   // Section name string table index
        ];
        // ELF header is exactly 64 bytes, no padding needed

        // Section header 0 (null section)
        for _ in 0..64 {
            elf.push(0);
        }

        // String table content
        let strtab: Vec<u8> = vec![
            0,  // null
            b'.', b's', b't', b'r', b't', b'a', b'b', 0,  // .strtab at offset 1
            b'.', b'm', b'a', b'p', b's', 0,  // .maps at offset 9
        ];
        let strtab_offset = elf.len() + 128;  // After section headers

        // Section header 1 (string table)
        elf.extend_from_slice(&[
            1, 0, 0, 0,  // sh_name = 1
            3, 0, 0, 0,  // sh_type = SHT_STRTAB
            0, 0, 0, 0, 0, 0, 0, 0,  // sh_flags
            0, 0, 0, 0, 0, 0, 0, 0,  // sh_addr
        ]);
        elf.extend_from_slice(&(strtab_offset as u64).to_le_bytes());
        elf.extend_from_slice(&(strtab.len() as u64).to_le_bytes());
        elf.extend_from_slice(&[
            0, 0, 0, 0,  // sh_link
            0, 0, 0, 0,  // sh_info
            1, 0, 0, 0, 0, 0, 0, 0,  // sh_addralign
            0, 0, 0, 0, 0, 0, 0, 0,  // sh_entsize
        ]);

        // Section header 2 (.maps with invalid data offset - points way past file)
        elf.extend_from_slice(&[
            9, 0, 0, 0,  // sh_name = 9 (pointing to ".maps")
            1, 0, 0, 0,  // sh_type = SHT_PROGBITS
            0, 0, 0, 0, 0, 0, 0, 0,  // sh_flags
            0, 0, 0, 0, 0, 0, 0, 0,  // sh_addr
        ]);
        // sh_offset pointing way past file end
        elf.extend_from_slice(&[0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0]);
        // sh_size
        elf.extend_from_slice(&[100, 0, 0, 0, 0, 0, 0, 0]);
        elf.extend_from_slice(&[
            0, 0, 0, 0,  // sh_link
            0, 0, 0, 0,  // sh_info
            1, 0, 0, 0, 0, 0, 0, 0,  // sh_addralign
            0, 0, 0, 0, 0, 0, 0, 0,  // sh_entsize
        ]);

        // Append string table
        elf.extend_from_slice(&strtab);

        let result = analyze_elf(&elf);
        // Should succeed - the .maps section with bad data is just skipped
        assert!(result.is_ok());
    }

    // --- Actual XDP Source Verification ---

    #[test]
    fn test_actual_xdp_source_passes_safety() {
        let source = include_str!("bpf/counter.bpf.c");
        let report = analyze_source(source);
        assert!(
            report.is_safe,
            "XDP source failed safety verification: {:?}",
            report
        );
        assert!(report.has_lru_map, "XDP source must use LRU hash map");
        assert!(
            report.forbidden_actions.is_empty(),
            "XDP source contains forbidden actions: {:?}",
            report.forbidden_actions
        );
        assert!(
            report.forbidden_helpers.is_empty(),
            "XDP source contains forbidden helpers: {:?}",
            report.forbidden_helpers
        );
        assert!(
            report.forbidden_map_types.is_empty(),
            "XDP source contains forbidden map types: {:?}",
            report.forbidden_map_types
        );
    }
}
