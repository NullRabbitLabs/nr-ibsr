//! BPF Safety Invariant Verification
//!
//! This module provides source-level and ELF-level analysis to verify safety
//! invariants on IBSR's BPF programs. IBSR follows the hyperscaler/cloudflare
//! shadow-mode model: a single load-bearing safety guarantee — **no traffic
//! is dropped, redirected, or modified** — with two operating modes that
//! differ in what observation capabilities are permitted underneath.
//!
//! - [`SafetyProfile::StrictCounter`] (default): the original conservative
//!   profile. XDP-only, counter-only, no per-packet events, no payload reads.
//!   Privacy posture: payload bytes never leave the kernel.
//!
//! - [`SafetyProfile::ShadowPayload`] (opt-in): permits XDP for steering plus
//!   TC ingress/egress for payload reassembly + ringbuf / perf_event output
//!   to userspace. Application-layer parsing happens in userspace. The no-drop
//!   guarantee is mechanically preserved: ring-buffer pressure cannot
//!   backpressure the network stack.
//!
//! See `docs/safety.md` for the user-facing model description.

use regex::Regex;
use std::collections::HashSet;
use thiserror::Error;

/// Operating mode for safety verification. Selects which checks apply.
///
/// The mode-invariant rules (no drops / redirects / modifies, no DEVMAP /
/// XSKMAP / CPUMAP) apply to both modes — they encode the load-bearing
/// shadow-mode guarantee. Mode-specific rules differ:
///
/// - StrictCounter: forbid ringbuf / perf_event helpers + map types; require
///   `BPF_MAP_TYPE_LRU_HASH` for bounded kernel memory.
/// - ShadowPayload: ringbuf / perf_event permitted; `BPF_MAP_TYPE_LRU_HASH`
///   is no longer required (bounded-memory discipline shifts to the userspace
///   ring-buffer consumer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SafetyProfile {
    /// XDP-only, counter-only, no per-packet events. Existing `ibsr collect`
    /// subcommand. The default — strictest profile.
    #[default]
    StrictCounter,
    /// XDP for steering + TC ingress/egress for payload reassembly +
    /// ringbuf / perf_event for userspace handoff. New `ibsr collect-payload`
    /// subcommand. Used when payload-aware traffic intelligence is the goal.
    ShadowPayload,
}

/// Mode-invariant XDP actions that violate the no-drop / no-redirect / no-modify
/// shadow guarantee. Forbidden in BOTH modes.
const FORBIDDEN_XDP_ACTIONS: &[&str] = &[
    "XDP_DROP",
    "XDP_ABORTED",
    "XDP_REDIRECT",
    "XDP_TX",
];

/// Mode-invariant TC actions that violate the no-drop / no-redirect / no-modify
/// shadow guarantee. Forbidden in BOTH modes. (Only meaningful when ShadowPayload
/// mode introduces TC programs; harmless to check for in StrictCounter source.)
const FORBIDDEN_TC_ACTIONS: &[&str] = &[
    "TC_ACT_SHOT",
    "TC_ACT_REDIRECT",
    "TC_ACT_STOLEN",
    "TC_ACT_TRAP",
];

/// Mode-invariant BPF helpers that redirect or modify packets. Forbidden in
/// BOTH modes. (`bpf_xdp_adjust_*` mutates packet data; `bpf_clone_redirect`
/// would tee traffic out-of-path; `bpf_skb_change_*` rewrites headers.)
const FORBIDDEN_BPF_HELPERS_INVARIANT: &[&str] = &[
    "bpf_redirect",
    "bpf_redirect_map",
    "bpf_xdp_redirect_map",
    "bpf_xdp_adjust_head",
    "bpf_xdp_adjust_tail",
    "bpf_xdp_adjust_meta",
    "bpf_clone_redirect",
    "bpf_skb_change_head",
    "bpf_skb_change_tail",
    "bpf_skb_change_proto",
    "bpf_skb_change_type",
    "bpf_skb_store_bytes",
];

/// StrictCounter-only forbidden helpers. These are *permitted* under
/// ShadowPayload (it needs ringbuf to ship events to userspace) but forbidden
/// under StrictCounter (where payload bytes must not leave the kernel).
const FORBIDDEN_BPF_HELPERS_STRICT_ONLY: &[&str] = &[
    "bpf_perf_event_output",
    "bpf_ringbuf_output",
    "bpf_ringbuf_reserve",
    "bpf_ringbuf_submit",
];

/// Mode-invariant forbidden map types — used for traffic redirection. Forbidden
/// in BOTH modes regardless of profile.
const FORBIDDEN_MAP_TYPES_INVARIANT: &[&str] = &[
    "BPF_MAP_TYPE_DEVMAP",
    "BPF_MAP_TYPE_DEVMAP_HASH",
    "BPF_MAP_TYPE_XSKMAP",
    "BPF_MAP_TYPE_CPUMAP",
];

/// StrictCounter-only forbidden map types. Permitted under ShadowPayload
/// (kernel→userspace event channel), forbidden under StrictCounter.
const FORBIDDEN_MAP_TYPES_STRICT_ONLY: &[&str] = &[
    "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
    "BPF_MAP_TYPE_RINGBUF",
];

/// Required map type for bounded kernel memory in StrictCounter mode.
/// In ShadowPayload mode, kernel maps may include flow-keyed hash maps but
/// are not required to be LRU; the bounded-memory discipline lives in
/// userspace (the ring-buffer consumer's flow table).
const REQUIRED_MAP_TYPE: &str = "BPF_MAP_TYPE_LRU_HASH";

impl SafetyProfile {
    /// Helpers forbidden in this profile.
    fn forbidden_helpers(self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = FORBIDDEN_BPF_HELPERS_INVARIANT.to_vec();
        if matches!(self, SafetyProfile::StrictCounter) {
            out.extend_from_slice(FORBIDDEN_BPF_HELPERS_STRICT_ONLY);
        }
        out
    }

    /// Map types forbidden in this profile.
    fn forbidden_map_types(self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = FORBIDDEN_MAP_TYPES_INVARIANT.to_vec();
        if matches!(self, SafetyProfile::StrictCounter) {
            out.extend_from_slice(FORBIDDEN_MAP_TYPES_STRICT_ONLY);
        }
        out
    }

    /// Whether this profile requires `BPF_MAP_TYPE_LRU_HASH` for bounded
    /// kernel memory. Only StrictCounter does — ShadowPayload's bounded-memory
    /// discipline lives in userspace.
    fn requires_lru_map(self) -> bool {
        matches!(self, SafetyProfile::StrictCounter)
    }

    /// Forbidden return actions for this profile. Mode-invariant: includes
    /// both XDP and TC drop/redirect/steal actions.
    fn forbidden_actions(self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = FORBIDDEN_XDP_ACTIONS.to_vec();
        out.extend_from_slice(FORBIDDEN_TC_ACTIONS);
        out
    }
}

/// Errors from safety verification.
#[derive(Debug, Error)]
pub enum SafetyError {
    #[error("forbidden BPF action found: {0}")]
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

/// Result of safety verification. The `profile` field records which profile
/// the report was produced under so downstream consumers can interpret the
/// `has_lru_map` flag correctly (required for StrictCounter, optional for
/// ShadowPayload).
#[derive(Debug, Default)]
pub struct SafetyReport {
    pub forbidden_actions: Vec<String>,
    pub forbidden_helpers: Vec<String>,
    pub forbidden_map_types: Vec<String>,
    pub has_lru_map: bool,
    pub is_safe: bool,
    pub profile: SafetyProfile,
}

impl SafetyReport {
    /// Check if the program passes all safety requirements for its profile.
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
        if self.profile.requires_lru_map() && !self.has_lru_map {
            return Err(SafetyError::MissingLruMap);
        }
        Ok(())
    }
}

/// Analyze C source code for forbidden patterns under [`SafetyProfile::StrictCounter`].
/// Thin compatibility wrapper around [`analyze_source_with_profile`].
pub fn analyze_source(source: &str) -> SafetyReport {
    analyze_source_with_profile(source, SafetyProfile::StrictCounter)
}

/// Analyze C source code for forbidden patterns under the given safety profile.
/// Returns a `SafetyReport` recording all violations found and the profile used.
///
/// Mode-invariant rules (no drops / redirects / modifies, no DEVMAP /
/// XSKMAP / CPUMAP) apply to both modes. Mode-specific rules — ringbuf and
/// perf_event helper / map-type forbiddenness, and the LRU-map requirement —
/// apply only under StrictCounter.
pub fn analyze_source_with_profile(source: &str, profile: SafetyProfile) -> SafetyReport {
    let mut report = SafetyReport {
        profile,
        ..SafetyReport::default()
    };

    // Check for forbidden return actions (XDP + TC).
    for action in profile.forbidden_actions() {
        // Match "return XDP_DROP" / "return TC_ACT_SHOT" or similar patterns.
        let pattern = format!(r"\breturn\s+{}\b", regex::escape(action));
        // Pattern is always valid since action is alphanumeric.
        let re = Regex::new(&pattern).expect("valid regex pattern");
        if re.is_match(source) {
            report.forbidden_actions.push(action.to_string());
        }
    }

    // Check for forbidden BPF helpers (mode-aware).
    for helper in profile.forbidden_helpers() {
        let pattern = format!(r"\b{}\s*\(", regex::escape(helper));
        // Pattern is always valid since helper is alphanumeric.
        let re = Regex::new(&pattern).expect("valid regex pattern");
        if re.is_match(source) {
            report.forbidden_helpers.push(helper.to_string());
        }
    }

    // Check for forbidden map types (mode-aware).
    for map_type in profile.forbidden_map_types() {
        if source.contains(map_type) {
            report.forbidden_map_types.push(map_type.to_string());
        }
    }

    // Check for required LRU map (StrictCounter only).
    report.has_lru_map = source.contains(REQUIRED_MAP_TYPE);

    // Determine overall safety. Profile-aware: ShadowPayload doesn't require
    // an LRU map.
    let lru_ok = !profile.requires_lru_map() || report.has_lru_map;
    report.is_safe = report.forbidden_actions.is_empty()
        && report.forbidden_helpers.is_empty()
        && report.forbidden_map_types.is_empty()
        && lru_ok;

    report
}

/// Analyze compiled ELF for forbidden symbols under [`SafetyProfile::StrictCounter`].
/// Thin compatibility wrapper around [`analyze_elf_with_profile`].
pub fn analyze_elf(elf_bytes: &[u8]) -> Result<SafetyReport, SafetyError> {
    analyze_elf_with_profile(elf_bytes, SafetyProfile::StrictCounter)
}

/// Analyze compiled ELF for forbidden symbols under the given safety profile.
pub fn analyze_elf_with_profile(
    elf_bytes: &[u8],
    profile: SafetyProfile,
) -> Result<SafetyReport, SafetyError> {
    use object::{Object, ObjectSection, ObjectSymbol};

    let file = object::File::parse(elf_bytes)
        .map_err(|e| SafetyError::ElfError(e.to_string()))?;

    let mut report = SafetyReport {
        profile,
        ..SafetyReport::default()
    };
    let mut found_symbols: HashSet<String> = HashSet::new();

    // Collect all symbol names.
    for symbol in file.symbols() {
        if let Ok(name) = symbol.name() {
            found_symbols.insert(name.to_string());
        }
    }

    // Check for forbidden helpers in symbols (mode-aware).
    for helper in profile.forbidden_helpers() {
        if found_symbols.contains(helper) {
            report.forbidden_helpers.push(helper.to_string());
        }
    }

    // For ELF analysis, we check section names for map definitions
    // and look for specific patterns in the data.
    for section in file.sections() {
        let name = match section.name() {
            Ok(n) => n,
            Err(_) => continue,
        };

        // Check if this is a maps section.
        if !name.contains("maps") && !name.contains(".rodata") {
            continue;
        }

        let data = match section.data() {
            Ok(d) => d,
            Err(_) => continue,
        };

        let data_str = String::from_utf8_lossy(data);

        // Check for forbidden map types in section data (mode-aware).
        for map_type in profile.forbidden_map_types() {
            if data_str.contains(map_type) {
                report.forbidden_map_types.push(map_type.to_string());
            }
        }

        // Check for LRU map.
        if data_str.contains(REQUIRED_MAP_TYPE) {
            report.has_lru_map = true;
        }
    }

    // Note: XDP/TC actions are compile-time constants, so we can't easily
    // detect them in the ELF without disassembling. Source analysis handles
    // this. For ELF, we focus on helper calls and map types.

    let lru_ok = !profile.requires_lru_map() || report.has_lru_map;
    report.is_safe = report.forbidden_actions.is_empty()
        && report.forbidden_helpers.is_empty()
        && report.forbidden_map_types.is_empty()
        && lru_ok;

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
            profile: SafetyProfile::StrictCounter,
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
            profile: SafetyProfile::StrictCounter,
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
            profile: SafetyProfile::StrictCounter,
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
            profile: SafetyProfile::StrictCounter,
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
            profile: SafetyProfile::StrictCounter,
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
        assert_eq!(
            report.profile,
            SafetyProfile::StrictCounter,
            "default profile must be StrictCounter (back-compat)"
        );
    }

    // ===========================================
    // Test Category C — Per-Mode Safety Profile (ShadowPayload)
    // ===========================================

    #[test]
    fn test_default_profile_is_strict_counter() {
        let p: SafetyProfile = Default::default();
        assert_eq!(p, SafetyProfile::StrictCounter);
    }

    #[test]
    fn test_shadow_payload_permits_ringbuf_helper() {
        let source = r#"
            struct {
                __uint(type, BPF_MAP_TYPE_RINGBUF);
                __uint(max_entries, 4 * 1024 * 1024);
            } payload_rb SEC(".maps");

            SEC("tc/ingress")
            int tc_payload(struct __sk_buff *skb) {
                struct payload_event *ev = bpf_ringbuf_reserve(&payload_rb, sizeof(*ev), 0);
                if (!ev) return TC_ACT_OK;
                bpf_ringbuf_submit(ev, 0);
                return TC_ACT_OK;
            }
        "#;
        let report = analyze_source_with_profile(source, SafetyProfile::ShadowPayload);
        assert!(
            report.is_safe,
            "ShadowPayload should accept ringbuf usage: {:?}", report,
        );
        assert!(report.forbidden_helpers.is_empty());
        assert!(report.forbidden_map_types.is_empty());
        assert_eq!(report.profile, SafetyProfile::ShadowPayload);
    }

    #[test]
    fn test_shadow_payload_permits_perf_event_output() {
        let source = r#"
            struct {
                __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
            } events SEC(".maps");

            SEC("tc/egress")
            int tc_handle(struct __sk_buff *skb) {
                bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
                return TC_ACT_OK;
            }
        "#;
        let report = analyze_source_with_profile(source, SafetyProfile::ShadowPayload);
        assert!(report.is_safe, "ShadowPayload should accept perf_event_output: {:?}", report);
    }

    #[test]
    fn test_shadow_payload_does_not_require_lru_map() {
        // ShadowPayload programs may use a HASH (not LRU) map for flow state;
        // the bounded-memory discipline lives in the userspace ring-buffer
        // consumer.
        let source = r#"
            struct {
                __uint(type, BPF_MAP_TYPE_RINGBUF);
                __uint(max_entries, 1024 * 1024);
            } rb SEC(".maps");

            SEC("tc/ingress")
            int p(struct __sk_buff *skb) {
                return TC_ACT_OK;
            }
        "#;
        let report = analyze_source_with_profile(source, SafetyProfile::ShadowPayload);
        assert!(report.is_safe, "ShadowPayload should not require LRU map");
        assert!(!report.has_lru_map);
        assert!(report.validate().is_ok());
    }

    #[test]
    fn test_shadow_payload_still_forbids_drops() {
        let source = r#"
            SEC("tc/ingress")
            int p(struct __sk_buff *skb) {
                return TC_ACT_SHOT;
            }
        "#;
        let report = analyze_source_with_profile(source, SafetyProfile::ShadowPayload);
        assert!(!report.is_safe, "ShadowPayload must still forbid TC_ACT_SHOT");
        assert!(report.forbidden_actions.contains(&"TC_ACT_SHOT".to_string()));
    }

    #[test]
    fn test_shadow_payload_still_forbids_redirects() {
        let source = r#"
            SEC("tc/egress")
            int p(struct __sk_buff *skb) {
                bpf_redirect(1, 0);
                return TC_ACT_OK;
            }
        "#;
        let report = analyze_source_with_profile(source, SafetyProfile::ShadowPayload);
        assert!(!report.is_safe);
        assert!(report.forbidden_helpers.contains(&"bpf_redirect".to_string()));
    }

    #[test]
    fn test_shadow_payload_still_forbids_xdp_drop() {
        let source = r#"
            SEC("xdp")
            int p(struct xdp_md *ctx) {
                return XDP_DROP;
            }
        "#;
        let report = analyze_source_with_profile(source, SafetyProfile::ShadowPayload);
        assert!(!report.is_safe);
        assert!(report.forbidden_actions.contains(&"XDP_DROP".to_string()));
    }

    #[test]
    fn test_shadow_payload_still_forbids_xdp_redirect() {
        let source = r#"
            SEC("xdp")
            int p(struct xdp_md *ctx) {
                return XDP_REDIRECT;
            }
        "#;
        let report = analyze_source_with_profile(source, SafetyProfile::ShadowPayload);
        assert!(!report.is_safe);
        assert!(report.forbidden_actions.contains(&"XDP_REDIRECT".to_string()));
    }

    #[test]
    fn test_shadow_payload_still_forbids_devmap() {
        let source = r#"
            struct {
                __uint(type, BPF_MAP_TYPE_DEVMAP);
            } devmap SEC(".maps");
        "#;
        let report = analyze_source_with_profile(source, SafetyProfile::ShadowPayload);
        assert!(!report.is_safe);
        assert!(report.forbidden_map_types.contains(&"BPF_MAP_TYPE_DEVMAP".to_string()));
    }

    #[test]
    fn test_shadow_payload_still_forbids_xdp_adjust_head() {
        // bpf_xdp_adjust_head modifies packet data; mode-invariant forbidden.
        let source = r#"
            SEC("xdp")
            int p(struct xdp_md *ctx) {
                bpf_xdp_adjust_head(ctx, 16);
                return XDP_PASS;
            }
        "#;
        let report = analyze_source_with_profile(source, SafetyProfile::ShadowPayload);
        assert!(!report.is_safe);
        assert!(report.forbidden_helpers.contains(&"bpf_xdp_adjust_head".to_string()));
    }

    #[test]
    fn test_strict_counter_still_forbids_ringbuf() {
        // Regression: existing StrictCounter behavior must be preserved.
        let source = r#"
            struct {
                __uint(type, BPF_MAP_TYPE_RINGBUF);
            } rb SEC(".maps");
        "#;
        let report = analyze_source_with_profile(source, SafetyProfile::StrictCounter);
        assert!(!report.is_safe);
        assert!(report.forbidden_map_types.contains(&"BPF_MAP_TYPE_RINGBUF".to_string()));
    }

    #[test]
    fn test_strict_counter_still_forbids_perf_event_output() {
        // Regression: existing StrictCounter behavior must be preserved.
        let source = r#"
            int xdp_prog(struct xdp_md *ctx) {
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
                return XDP_PASS;
            }
        "#;
        let report = analyze_source_with_profile(source, SafetyProfile::StrictCounter);
        assert!(!report.is_safe);
        assert!(report.forbidden_helpers.contains(&"bpf_perf_event_output".to_string()));
    }

    #[test]
    fn test_tc_actions_forbidden_in_strict_counter_too() {
        // Even though StrictCounter doesn't introduce TC programs, the
        // mode-invariant rules still apply — a stray TC_ACT_SHOT in source
        // analysed under StrictCounter must still trip.
        let source = r#"
            int p(struct __sk_buff *skb) {
                return TC_ACT_SHOT;
            }
        "#;
        let report = analyze_source_with_profile(source, SafetyProfile::StrictCounter);
        assert!(!report.is_safe);
        assert!(report.forbidden_actions.contains(&"TC_ACT_SHOT".to_string()));
    }

    #[test]
    fn test_shadow_payload_validate_ok_without_lru() {
        let report = SafetyReport {
            forbidden_actions: vec![],
            forbidden_helpers: vec![],
            forbidden_map_types: vec![],
            has_lru_map: false,
            is_safe: true,
            profile: SafetyProfile::ShadowPayload,
        };
        // ShadowPayload doesn't require LRU; validate must pass.
        assert!(report.validate().is_ok());
    }

    #[test]
    fn test_strict_counter_validate_fails_without_lru() {
        let report = SafetyReport {
            forbidden_actions: vec![],
            forbidden_helpers: vec![],
            forbidden_map_types: vec![],
            has_lru_map: false,
            is_safe: false,
            profile: SafetyProfile::StrictCounter,
        };
        // StrictCounter requires LRU; validate must reject.
        assert!(matches!(
            report.validate().unwrap_err(),
            SafetyError::MissingLruMap
        ));
    }

    #[test]
    fn test_invariant_helpers_forbidden_in_both_modes() {
        // bpf_clone_redirect tees traffic out-of-path — never permitted.
        for profile in [SafetyProfile::StrictCounter, SafetyProfile::ShadowPayload] {
            let source = r#"
                int p(struct __sk_buff *skb) {
                    bpf_clone_redirect(skb, 1, 0);
                    return TC_ACT_OK;
                }
            "#;
            let report = analyze_source_with_profile(source, profile);
            assert!(
                !report.is_safe,
                "bpf_clone_redirect must be forbidden in {:?}", profile,
            );
            assert!(report.forbidden_helpers.contains(&"bpf_clone_redirect".to_string()));
        }
    }

    #[test]
    fn test_actual_tc_payload_source_passes_shadow_payload_safety() {
        // Pin: the real tc_payload.bpf.c source must pass ShadowPayload-mode
        // safety verification. If a future edit introduces a forbidden
        // helper / map type / return action, this test trips before the BPF
        // code can land.
        let source = include_str!("bpf/tc_payload.bpf.c");
        let report = analyze_source_with_profile(source, SafetyProfile::ShadowPayload);
        assert!(
            report.is_safe,
            "tc_payload.bpf.c failed ShadowPayload safety verification: {:?}",
            report,
        );
        assert_eq!(report.profile, SafetyProfile::ShadowPayload);
        assert!(
            report.forbidden_actions.is_empty(),
            "tc_payload contains forbidden actions: {:?}", report.forbidden_actions,
        );
        assert!(
            report.forbidden_helpers.is_empty(),
            "tc_payload contains forbidden helpers: {:?}", report.forbidden_helpers,
        );
        assert!(
            report.forbidden_map_types.is_empty(),
            "tc_payload contains forbidden map types: {:?}", report.forbidden_map_types,
        );
    }

    #[test]
    fn test_actual_tc_payload_source_rejected_under_strict_counter() {
        // Pin: tc_payload.bpf.c must NOT pass StrictCounter safety
        // verification — it uses ringbuf which is StrictCounter-forbidden.
        // This test documents that the per-mode profile distinction is
        // load-bearing: payload-aware programs require explicit opt-in.
        let source = include_str!("bpf/tc_payload.bpf.c");
        let report = analyze_source_with_profile(source, SafetyProfile::StrictCounter);
        assert!(
            !report.is_safe,
            "tc_payload.bpf.c must not pass StrictCounter — it uses ringbuf",
        );
        // Specifically: the ringbuf map type and ringbuf helpers should trip.
        assert!(
            report.forbidden_map_types.contains(&"BPF_MAP_TYPE_RINGBUF".to_string()),
            "expected BPF_MAP_TYPE_RINGBUF to trip under StrictCounter",
        );
    }
}
