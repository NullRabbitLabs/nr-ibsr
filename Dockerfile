# IBSR Test and Build Image
# Debian 12 base with Rust toolchain and coverage tools

FROM rust:1.87-bookworm

# Install dependencies for coverage and BPF toolchain (for later stages)
RUN apt-get update && apt-get install -y \
    llvm \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-llvm-cov for coverage
RUN cargo install cargo-llvm-cov

# Set working directory
WORKDIR /app

# Copy workspace
COPY . .

# Default command: run tests with coverage
CMD ["cargo", "llvm-cov", "--all-features", "--workspace", \
     "--fail-under-lines", "100", \
     "--fail-under-functions", "100"]
