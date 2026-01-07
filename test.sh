#!/usr/bin/env bash
set -euo pipefail

# Run tests with BuildKit caching
# Usage: ./test.sh
#
# This uses the same caching strategy as build.sh:
# - Cargo registry cached between runs
# - Target directory cached for incremental compilation
#
# First run: Full compilation (~2 minutes)
# Subsequent runs: Incremental (~10-30 seconds for small changes)

echo "Running tests with coverage..."

DOCKER_BUILDKIT=1 docker build \
    --target test \
    --progress=plain \
    -t ibsr-test .

echo ""
echo "Tests passed!"
