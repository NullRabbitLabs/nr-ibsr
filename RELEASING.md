# Releasing IBSR

This document describes the CI/CD workflows and release process for IBSR.

## Continuous Integration

The CI workflow (`.github/workflows/ci.yml`) runs automatically on:
- Push to `main` or `master` branches
- Pull requests targeting `main` or `master`

### CI Pipeline

1. **Test** - Runs the test suite with coverage enforcement
   ```bash
   docker compose run --rm test
   ```
   Coverage thresholds: 97% line coverage, 94% function coverage

2. **Build** - Compiles the x86_64 release binary (runs after tests pass)

## Creating Releases

Releases are built automatically by the release workflow (`.github/workflows/release.yml`).

### Release Artifacts

Each release produces two binaries:
- `ibsr-arm64` - For ARM64 Linux systems (e.g., Debian on Apple Silicon)
- `ibsr-x86_64` - For x86_64 Linux systems

### Option 1: Tag-based Release

Push a version tag to trigger an automatic release:

```bash
# Create and push a tag
git tag v1.0.0
git push origin v1.0.0
```

The workflow will:
1. Build binaries for both architectures in parallel
2. Create a GitHub Release with auto-generated release notes
3. Attach both binaries to the release

### Option 2: Manual Release

1. Go to **Actions** > **Release** workflow on GitHub
2. Click **Run workflow**
3. Enter the release tag (e.g., `v1.0.0`)
4. Click **Run workflow**

### Version Tagging Convention

- Release versions: `v1.0.0`, `v1.2.3`
- Pre-release versions: `v1.0.0-rc1`, `v2.0.0-beta.1`

Tags containing `-` are automatically marked as pre-releases on GitHub.

## Build Process

The release workflow uses Docker BuildKit with QEMU for cross-platform builds:

```bash
# Build for ARM64
./build.sh --arch arm64

# Build for x86_64
./build.sh --arch x86_64
```

Build metadata (git hash and timestamp) is embedded in the binary at compile time.

## Deployment

After downloading a release binary:

```bash
# Make executable
chmod +x ibsr-arm64

# Verify build info
./ibsr-arm64 --version

# Deploy to target system
scp ibsr-arm64 user@server:/usr/local/bin/ibsr
```
