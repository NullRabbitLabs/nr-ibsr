#!/usr/bin/env bash
set -euo pipefail

# Deploy IBSR binary to remote machine via SSH
# Usage: ./deploy.sh --arch <arm64|x86_64> <user@host>
#
# Example: ./deploy.sh --arch arm64 root@192.168.64.2

ARCH=""
TARGET=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --arch)
            ARCH="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: ./deploy.sh --arch <arm64|x86_64> <user@host>"
            echo ""
            echo "Options:"
            echo "  --arch    Target architecture: arm64 or x86_64"
            echo ""
            echo "Example: ./deploy.sh --arch arm64 root@192.168.64.2"
            exit 0
            ;;
        *)
            TARGET="$1"
            shift
            ;;
    esac
done

if [[ -z "$ARCH" ]]; then
    echo "Error: --arch is required"
    echo "Usage: ./deploy.sh --arch <arm64|x86_64> <user@host>"
    exit 1
fi

if [[ -z "$TARGET" ]]; then
    echo "Error: target host is required"
    echo "Usage: ./deploy.sh --arch <arm64|x86_64> <user@host>"
    exit 1
fi

BINARY="./dist/ibsr-$ARCH"

if [[ ! -f "$BINARY" ]]; then
    echo "Error: Binary not found at $BINARY"
    echo "Run ./build.sh --arch $ARCH first"
    exit 1
fi

echo "Deploying IBSR ($ARCH) to $TARGET..."

scp "$BINARY" "$TARGET:/usr/local/bin/ibsr"

echo "Done. Binary installed at /usr/local/bin/ibsr"
