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

# Build the image with all source files
docker build --platform "$PLATFORM" -t ibsr-build .

# Run cargo build inside container (no volume mount to avoid target dir conflicts)
CONTAINER_ID=$(docker create --platform "$PLATFORM" ibsr-build cargo build --release)
docker start -a "$CONTAINER_ID"

# Extract the binary from the container
mkdir -p dist
docker cp "$CONTAINER_ID:/app/target/release/ibsr" "./dist/ibsr-$ARCH"

# Clean up the container
docker rm "$CONTAINER_ID" > /dev/null

echo ""
echo "Build complete: ./dist/ibsr-$ARCH"
