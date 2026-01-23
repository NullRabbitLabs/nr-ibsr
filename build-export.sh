#!/usr/bin/env bash
set -euo pipefail

# Build ibsr-export for target architecture using Docker
# Usage: ./build-export.sh [--arch arm64|x86_64]
#
# Default: arm64 (for Debian on macOS UTM)
# Output: ./dist/ibsr-export-<arch>

ARCH="arm64"

while [[ $# -gt 0 ]]; do
    case $1 in
        --arch)
            ARCH="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: ./build-export.sh [--arch arm64|x86_64]"
            echo ""
            echo "Options:"
            echo "  --arch    Target architecture: arm64 (default) or x86_64"
            echo ""
            echo "Output: ./dist/ibsr-export-<arch>"
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

echo "Building ibsr-export for $ARCH ($PLATFORM)..."

# Create dist directory
mkdir -p dist

# Build using BuildKit with cache mounts
DOCKER_BUILDKIT=1 docker build \
    --platform "$PLATFORM" \
    --target export \
    --output "type=local,dest=./dist" \
    -f ibsr-export/Dockerfile \
    -t ibsr-export-build \
    ./ibsr-export

# Rename the output binary
mv "./dist/ibsr-export" "./dist/ibsr-export-$ARCH"

# Get build info
GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo ""
echo "Build complete: ./dist/ibsr-export-$ARCH"
echo "Build: $GIT_HASH ($BUILD_TIME)"
