---
title: Installation
nav_order: 2
---

# Installation

This guide covers installing IBSR on a Linux host.

## System Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Operating System | Debian 12+ | Ubuntu 22.04+ also supported |
| Kernel | 6.1+ | For XDP and BTF support |
| Architecture | arm64 or x86_64 | Pre-built binaries available for both |
| Privileges | root or CAP_BPF | Required for XDP attachment |
| Network | XDP-capable NIC | Most physical NICs support XDP |
| Disk Space | 1 GB+ | For snapshot storage |

### Verify Kernel Version

```bash
uname -r
# Should show 6.1.x or higher
```

### Verify XDP Support

```bash
# Check if XDP is available
ip link show | grep xdp
# No output is normal - XDP programs attach on demand
```

## Option 1: Pre-built Binary (Recommended)

Download the appropriate binary from [GitHub Releases](https://github.com/NullRabbitLabs/nr-ibsr/releases).

### Detect Architecture

```bash
ARCH=$(uname -m)
case $ARCH in
  x86_64)  BINARY="ibsr-x86_64" ;;
  aarch64) BINARY="ibsr-arm64" ;;
  arm64)   BINARY="ibsr-arm64" ;;
  *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac
echo "Will download: $BINARY"
```

### Download and Install

```bash
# Set the version you want to install
VERSION="v0.1.0"

# Download binary and checksums
curl -LO "https://github.com/NullRabbitLabs/nr-ibsr/releases/download/${VERSION}/${BINARY}"
curl -LO "https://github.com/NullRabbitLabs/nr-ibsr/releases/download/${VERSION}/checksums.txt"

# Verify checksum
grep "${BINARY}" checksums.txt | sha256sum -c -
# Should output: ibsr-xxx: OK

# Install to /usr/local/bin
sudo install -m 755 "${BINARY}" /usr/local/bin/ibsr

# Verify installation
ibsr --version
```

### One-liner Install Script

For convenience, you can use this combined script:

```bash
#!/bin/bash
set -e

VERSION="${1:-v0.1.0}"
ARCH=$(uname -m)

case $ARCH in
  x86_64)  BINARY="ibsr-x86_64" ;;
  aarch64|arm64) BINARY="ibsr-arm64" ;;
  *) echo "Unsupported: $ARCH"; exit 1 ;;
esac

BASE_URL="https://github.com/NullRabbitLabs/nr-ibsr/releases/download/${VERSION}"

curl -LO "${BASE_URL}/${BINARY}"
curl -LO "${BASE_URL}/checksums.txt"
grep "${BINARY}" checksums.txt | sha256sum -c -
sudo install -m 755 "${BINARY}" /usr/local/bin/ibsr
rm -f "${BINARY}" checksums.txt

echo "Installed ibsr ${VERSION}"
ibsr --version
```

## Option 2: Build from Source

Building from source requires Docker with BuildKit support.

### Prerequisites

- Docker 20.10+ with BuildKit
- Git
- 2 GB free disk space for build cache

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/NullRabbitLabs/nr-ibsr.git
cd nr-ibsr

# Build for the target architecture
# Default: arm64 (for Debian on macOS UTM)
./build.sh

# Or specify architecture explicitly
./build.sh --arch x86_64
./build.sh --arch arm64

# Output binary location
ls -la dist/
# dist/ibsr-arm64 or dist/ibsr-x86_64
```

### Install Built Binary

```bash
sudo install -m 755 dist/ibsr-* /usr/local/bin/ibsr
ibsr --version
```

### Build Details

The build script:
- Uses Docker BuildKit for cross-compilation
- Compiles in a Debian 12 container with LLVM/Clang toolchain
- Produces a statically-linked binary with embedded BPF bytecode
- Embeds git commit hash and build timestamp

## Post-Installation Verification

### Check Binary

```bash
# Version and help
ibsr --version
ibsr --help
ibsr collect --help
```

### Verify XDP Attachment (dry run)

```bash
# Create test output directory
mkdir -p /tmp/ibsr-test

# Start collecting on port 22 for 5 seconds
# This will attach the XDP program and verify it works
sudo ibsr collect -p 22 --out-dir /tmp/ibsr-test --duration-sec 5

# Check output
ls /tmp/ibsr-test/
# Should show: snapshot_*.jsonl and status.jsonl

# View status
cat /tmp/ibsr-test/status.jsonl
```

### Cleanup Test Files

```bash
rm -rf /tmp/ibsr-test
```

## Permissions

IBSR requires elevated privileges to attach XDP programs.

### Option A: Run as Root (Simple)

```bash
sudo ibsr collect -p 8899 --out-dir /var/lib/ibsr/snapshots
```

### Option B: CAP_BPF Capability (More Secure)

Grant the binary BPF capabilities without full root:

```bash
# Set capabilities on the binary
sudo setcap cap_bpf,cap_net_admin,cap_sys_admin+ep /usr/local/bin/ibsr

# Verify capabilities
getcap /usr/local/bin/ibsr
# Should show: /usr/local/bin/ibsr = cap_bpf,cap_net_admin,cap_sys_admin+ep

# Now can run without sudo
ibsr collect -p 8899 --out-dir /var/lib/ibsr/snapshots
```

**Note**: After reinstalling or upgrading the binary, capabilities must be re-applied.

## Output Directory Setup

Create the default output directory:

```bash
# Create directory
sudo mkdir -p /var/lib/ibsr/snapshots

# If running as non-root with capabilities, set ownership
sudo chown $(whoami):$(whoami) /var/lib/ibsr/snapshots
```

## Uninstallation

### Remove Binary

```bash
sudo rm /usr/local/bin/ibsr
```

### Remove Data (Optional)

```bash
# Remove snapshots (destructive)
sudo rm -rf /var/lib/ibsr
```

### Remove Systemd Service (If Installed)

See [Deployment](deployment.md) for systemd uninstall instructions.

## Next Steps

- [Quick Start](quickstart.md) — Get running in 5 minutes
- [Configuration](configuration.md) — CLI options and tuning
- [Deployment](deployment.md) — Production deployment with systemd
