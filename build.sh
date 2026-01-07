#!/usr/bin/env bash
set -euo pipefail

# Build IBSR for target architecture using Docker
# Usage: ./build.sh [--arch arm64|x86_64]
#
# Default: arm64 (for Debian on macOS UTM)
# Output: ./dist/ibsr-<arch>

ARCH="arm64"

while [[ $# -gt 0 ]]; do
    case $1 in
        --arch)
            ARCH="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: ./build.sh [--arch arm64|x86_64]"
            echo ""
            echo "Options:"
            echo "  --arch    Target architecture: arm64 (default) or x86_64"
            echo ""
            echo "Output: ./dist/ibsr-<arch>"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

case "$ARCH" in
    arm64)
        PLATFORM="linux/arm64"
        ;;
    x86_64)
        PLATFORM="linux/amd64"
        ;;
    *)
        echo "Error: Invalid architecture '$ARCH'. Use arm64 or x86_64."
        exit 1
        ;;
esac

echo "Building IBSR for $ARCH ($PLATFORM)..."

# Create dist directory
mkdir -p dist

# Build using BuildKit with cache mounts for cargo registry and target
# - Base image (toolchain) is cached
# - Cargo registry is cached between builds
# - Target directory is cached for incremental compilation
# - Source code is always fresh (COPY happens after cache setup)
DOCKER_BUILDKIT=1 docker build \
    --platform "$PLATFORM" \
    --target export \
    --output "type=local,dest=./dist" \
    -t ibsr-build .

# Rename the output binary
mv "./dist/ibsr" "./dist/ibsr-$ARCH"

# Get build info (same values embedded in binary)
GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo ""
echo "Build complete: ./dist/ibsr-$ARCH"
echo "Build: $GIT_HASH ($BUILD_TIME)"
