# ibsr-export Build Image
# Builds the S3 export tool without BPF dependencies
# syntax=docker/dockerfile:1

FROM rust:1.88-bookworm AS base

# Install minimal dependencies (cmake needed for aws-lc-sys)
RUN apt-get update && apt-get install -y \
    cmake \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Builder stage
FROM base AS builder
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp /app/target/release/ibsr-export /ibsr-export

# Export stage - minimal output
FROM scratch AS export
COPY --from=builder /ibsr-export /ibsr-export
