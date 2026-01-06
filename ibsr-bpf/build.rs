//! Build script for ibsr-bpf
//!
//! Compiles the XDP BPF program when the `bpf` feature is enabled.
//! Without the feature, compilation is skipped (for unit tests).

fn main() {
    // Always rerun if the BPF source changes
    println!("cargo:rerun-if-changed=src/bpf/counter.bpf.c");
    println!("cargo:rerun-if-changed=build.rs");

    // BPF compilation is only attempted when the bpf feature is enabled
    // Without the feature, only safety analysis via include_str! is available
}
