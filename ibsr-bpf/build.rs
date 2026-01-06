//! Build script for ibsr-bpf
//!
//! Compiles the XDP BPF program and generates the Rust skeleton.

use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const BPF_SOURCE: &str = "src/bpf/counter.bpf.c";

fn main() {
    println!("cargo:rerun-if-changed={}", BPF_SOURCE);
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let skel_path = out_dir.join("counter.skel.rs");

    SkeletonBuilder::new()
        .source(BPF_SOURCE)
        .build_and_generate(&skel_path)
        .expect("Failed to build and generate BPF skeleton");
}
