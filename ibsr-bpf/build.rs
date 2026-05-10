//! Build script for ibsr-bpf
//!
//! Compiles BPF programs and generates Rust skeletons:
//! - `counter.bpf.c`: XDP counter program (StrictCounter mode).
//! - `tc_payload.bpf.c`: TC ingress/egress payload sampler (ShadowPayload
//!   mode). Emits payload samples to a ringbuf for userspace stream
//!   reassembly.
//! - `record_incident.bpf.c`: TC ingress/egress sampled packet recorder
//!   (CF-style incident recording mode). Emits snaplen-256 packet
//!   headers to a ringbuf for userspace pcap writing.

use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const COUNTER_SOURCE: &str = "src/bpf/counter.bpf.c";
const TC_PAYLOAD_SOURCE: &str = "src/bpf/tc_payload.bpf.c";
const RECORD_INCIDENT_SOURCE: &str = "src/bpf/record_incident.bpf.c";

fn main() {
    println!("cargo:rerun-if-changed={}", COUNTER_SOURCE);
    println!("cargo:rerun-if-changed={}", TC_PAYLOAD_SOURCE);
    println!("cargo:rerun-if-changed={}", RECORD_INCIDENT_SOURCE);
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    SkeletonBuilder::new()
        .source(COUNTER_SOURCE)
        .build_and_generate(out_dir.join("counter.skel.rs"))
        .expect("Failed to build and generate counter BPF skeleton");

    SkeletonBuilder::new()
        .source(TC_PAYLOAD_SOURCE)
        .build_and_generate(out_dir.join("tc_payload.skel.rs"))
        .expect("Failed to build and generate tc_payload BPF skeleton");

    SkeletonBuilder::new()
        .source(RECORD_INCIDENT_SOURCE)
        .build_and_generate(out_dir.join("record_incident.skel.rs"))
        .expect("Failed to build and generate record_incident BPF skeleton");
}
