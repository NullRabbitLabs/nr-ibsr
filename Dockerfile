# IBSR Test and Build Image
# Debian 12 base with Rust toolchain and coverage tools
# syntax=docker/dockerfile:1

FROM rust:1.87-bookworm AS base

# Install dependencies for coverage and BPF toolchain
RUN apt-get update && apt-get install -y \
    llvm \
    clang \
    libbpf-dev \
    libelf-dev \
    pkg-config \
    linux-libc-dev \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm

# Install Rust components for coverage and BPF skeleton generation
RUN rustup component add llvm-tools-preview rustfmt

# Install cargo-llvm-cov for coverage
RUN cargo install cargo-llvm-cov

# Set working directory
WORKDIR /app

# Test stage - runs tests with coverage during build (uses cache mounts)
# Use ./test.sh to run, or docker compose run test for backwards compatibility
FROM base AS test
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo llvm-cov --workspace \
    --fail-under-lines 97 \
    --fail-under-functions 94 \
    --ignore-filename-regex "main\.rs|build\.rs|bpf_reader\.rs"

# Builder stage - used by build.sh with cache mounts
FROM base AS builder
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp /app/target/release/ibsr /ibsr

# Export stage - minimal output
FROM scratch AS export
COPY --from=builder /ibsr /ibsr
