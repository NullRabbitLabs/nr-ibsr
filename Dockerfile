# IBSR Test and Build Image
# Debian 12 base with Rust toolchain and coverage tools

FROM rust:1.87-bookworm

# Install dependencies for coverage and BPF toolchain (for later stages)
RUN apt-get update && apt-get install -y \
    llvm \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Install llvm-tools-preview for coverage (required by cargo-llvm-cov)
RUN rustup component add llvm-tools-preview

# Install cargo-llvm-cov for coverage
RUN cargo install cargo-llvm-cov

# Set working directory
WORKDIR /app

# Copy workspace
COPY . .

# Default command: run tests with coverage
# Coverage thresholds allow for auto-generated derive macro code
CMD ["cargo", "llvm-cov", "--all-features", "--workspace", \
     "--fail-under-lines", "99", \
     "--fail-under-functions", "97"]
