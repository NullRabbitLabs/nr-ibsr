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

    // counter.bpf.c needs BOTH:
    //   - the generated Rust skeleton (for libbpf-rs Object/Map handles
    //     against the loaded bpf_object — used in bpf_reader.rs for
    //     counter_map iteration + config_map writes)
    //   - the raw .o file on disk (for libxdp's xdp_program__open_file
    //     to load with the right BTF context for FREPLACE/dispatcher
    //     chaining — D5a fix)
    // SkeletonBuilder writes to .obj() target; we then expose the path
    // via cargo:rustc-env so bpf_reader.rs can pass it to libxdp at
    // runtime.
    let counter_obj_path = out_dir.join("counter.bpf.o");
    SkeletonBuilder::new()
        .source(COUNTER_SOURCE)
        .obj(&counter_obj_path)
        .build_and_generate(out_dir.join("counter.skel.rs"))
        .expect("Failed to build and generate counter BPF skeleton");
    println!(
        "cargo:rustc-env=COUNTER_BPF_OBJ_PATH={}",
        counter_obj_path.display()
    );

    SkeletonBuilder::new()
        .source(TC_PAYLOAD_SOURCE)
        .build_and_generate(out_dir.join("tc_payload.skel.rs"))
        .expect("Failed to build and generate tc_payload BPF skeleton");

    SkeletonBuilder::new()
        .source(RECORD_INCIDENT_SOURCE)
        .build_and_generate(out_dir.join("record_incident.skel.rs"))
        .expect("Failed to build and generate record_incident BPF skeleton");
}
