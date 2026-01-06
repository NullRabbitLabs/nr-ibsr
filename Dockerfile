# IBSR Test and Build Image
# Debian 12 base with Rust toolchain and coverage tools

FROM rust:1.87-bookworm

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

# Copy workspace
COPY . .

# Default command: run tests with coverage
# Coverage thresholds allow for auto-generated derive macro code
# Coverage thresholds:
# - 99% lines: accounts for auto-generated derive macro code
# - 95% functions: accounts for mock implementations with multiple trait methods
CMD ["cargo", "llvm-cov", "--all-features", "--workspace", \
     "--fail-under-lines", "99", \
     "--fail-under-functions", "95"]
